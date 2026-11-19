#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Deterministic contents, controlled mutations, full-byte restore verification. */
static volatile sig_atomic_t mutate_requested, verify_requested, exit_requested;
static size_t pages, dirty_run, clean_gap;
static unsigned int generation;
static unsigned char *memory;
static const char *state_path;
static const char *layout = "dense";
static size_t excluded_page = SIZE_MAX;

static void handler(int sig)
{
    if (sig == SIGUSR1) mutate_requested = 1;
    else if (sig == SIGUSR2) verify_requested = 1;
    else exit_requested = 1;
}

static int dirty_page(size_t page)
{
    return dirty_run && page % (dirty_run + clean_gap) < dirty_run;
}

static unsigned char pattern(size_t page, size_t offset, unsigned int gen)
{
    uint64_t value = (page + 1) * UINT64_C(0x9e3779b97f4a7c15) +
                     offset * UINT64_C(0xd1b54a32d192ed03) + gen * UINT64_C(0x94d049bb133111eb);
    value ^= value >> 33;
    value *= UINT64_C(0xff51afd7ed558ccd);
    return (unsigned char)(value >> 32);
}

static void state(const char *kind, uint64_t errors)
{
    FILE *stream = fopen(state_path, "w");
    if (!stream) { perror("state"); exit(2); }
    fprintf(stream, "{\"kind\":\"%s\",\"pid\":%ld,\"pages\":%zu,\"generation\":%u,"
                    "\"dirty_run\":%zu,\"clean_gap\":%zu,\"base\":%" PRIuPTR ",\"errors\":%" PRIu64 ","
                    "\"layout\":\"%s\",\"excluded_page\":%zu}\n",
                    kind, (long)getpid(), pages, generation, dirty_run, clean_gap, (uintptr_t)memory, errors,
                    layout, excluded_page);
    if (fclose(stream)) { perror("close state"); exit(2); }
}

int main(int argc, char **argv)
{
    struct sigaction action = { .sa_handler = handler };
    sigset_t block, oldmask;
    if (argc != 5 && argc != 6) return 2;
    pages = strtoull(argv[1], NULL, 10);
    dirty_run = strtoull(argv[2], NULL, 10);
    clean_gap = strtoull(argv[3], NULL, 10);
    state_path = argv[4];
    if (argc == 6) layout = argv[5];
    if (strcmp(layout,"dense") && strcmp(layout,"unmapped") && strcmp(layout,"protected")) return 2;
    if (!pages || pages > 524288 || dirty_run + clean_gap > pages ||
        (!dirty_run && !clean_gap)) return 2;
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1); sigaddset(&block, SIGUSR2); sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, &oldmask);
    memory = mmap(NULL, pages*4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) { perror("mmap"); return 2; }
    madvise(memory, pages*4096, MADV_NOHUGEPAGE);
    for (size_t page = 0; page < pages; page++)
        for (size_t offset = 0; offset < 4096; offset++)
            memory[page*4096+offset] = pattern(page, offset, 0);
    if (strcmp(layout,"dense")) {
        excluded_page = pages/2;
        int result = !strcmp(layout,"unmapped") ? munmap(memory+excluded_page*4096,4096) :
            mprotect(memory+excluded_page*4096,4096,PROT_NONE);
        if (result) { perror("layout"); return 2; }
    }
    state("READY", 0);
    while (!exit_requested) {
        while (!mutate_requested && !verify_requested && !exit_requested)
            sigsuspend(&oldmask);
        if (mutate_requested) {
            mutate_requested = 0;
            generation++;
            for (size_t page = 0; page < pages; page++)
                if (page != excluded_page && dirty_page(page))
                    for (size_t offset = 0; offset < 4096; offset++)
                        memory[page*4096+offset] = pattern(page, offset, generation);
            state("MUTATED", 0);
        }
        if (verify_requested) {
            uint64_t errors = 0;
            verify_requested = 0;
            if (!strcmp(layout,"protected") && mprotect(memory+excluded_page*4096,4096,PROT_READ)) {
                perror("verify mprotect"); return 2;
            }
            for (size_t page = 0; page < pages; page++) {
                if (page == excluded_page && !strcmp(layout,"unmapped")) continue;
                unsigned int expected = page != excluded_page && dirty_page(page) ? generation : 0;
                for (size_t offset = 0; offset < 4096; offset++)
                    errors += memory[page*4096+offset] != pattern(page, offset, expected);
            }
            if (!strcmp(layout,"protected") && mprotect(memory+excluded_page*4096,4096,PROT_NONE)) {
                perror("restore mprotect"); return 2;
            }
            state("VERIFIED", errors);
        }
    }
    return 0;
}
