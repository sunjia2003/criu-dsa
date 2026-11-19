#!/usr/bin/env python3
"""Exercise the production smaps reader with real files, without privileges."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]

HEADERS = {
    "log.h": r"""
#include <stdio.h>
#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(...) fprintf(stderr, __VA_ARGS__)
#define pr_perror(...) fprintf(stderr, __VA_ARGS__)
""",
    "page.h": "#define PAGE_SIZE 4096\n",
    "pstree.h": r"""
#include <sys/types.h>
#define TASK_DEAD 2
struct fixture_pid { pid_t real; int state; };
struct pstree_item { struct fixture_pid *pid; struct pstree_item *next; };
extern struct pstree_item *fixture_root;
#define for_each_pstree_item(item) \
    for ((item) = fixture_root; (item); (item) = (item)->next)
""",
    "util.h": "#include <sys/types.h>\nint open_proc(pid_t, const char *);\n",
}

HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "pstree.h"

struct pstree_item *fixture_root;
static struct fixture_pid pids[3];
static struct pstree_item tasks[3];
static const char *paths[3];
static int opened_fds[3];
static int open_calls, reject_open_pid, reject_thread_create, reject_thread_join;

int open_proc(pid_t pid, const char *name)
{
    size_t i;
    assert(!strcmp(name, "smaps"));
    open_calls++;
    if (pid == reject_open_pid) {
        errno = EACCES;
        return -1;
    }
    for (i = 0; i < 3; i++)
        if (pids[i].real == pid && paths[i]) {
            opened_fds[i] = open(paths[i], O_RDONLY | O_CLOEXEC);
            return opened_fds[i];
        }
    errno = ENOENT;
    return -1;
}

static int create_reader(pthread_t *thread, const pthread_attr_t *attr,
                         void *(*entry)(void *), void *argument)
{
    if (reject_thread_create)
        return EAGAIN;
    return pthread_create(thread, attr, entry, argument);
}

static int join_reader(pthread_t thread, void **result)
{
    if (reject_thread_join)
        return reject_thread_join;
    return pthread_join(thread, result);
}

#define pthread_create create_reader
#define pthread_join join_reader
#include "@SOURCE@"
#undef pthread_join
#undef pthread_create

static int descriptor_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int count = 0;
    assert(directory);
    while ((entry = readdir(directory)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            count++;
    assert(!closedir(directory));
    return count;
}

static void prepare(int count, const char *first, const char *second)
{
    int i;
    fixture_root = count ? &tasks[0] : NULL;
    for (i = 0; i < count; i++) {
        pids[i].real = 41001 + i;
        pids[i].state = 0;
        tasks[i].pid = &pids[i];
        tasks[i].next = i + 1 < count ? &tasks[i + 1] : NULL;
    }
    paths[0] = first;
    paths[1] = second;
    setenv("CRIU_DSA_SMAPS_PREFETCH", "1", 1);
    setenv("CRIU_DSA_DUMP", "1", 1);
    unsetenv("CRIU_DSA_SMAPS_PREFETCH_TRACE");
    unsetenv("CRIU_DSA_PROFILE");
}

static void compare_input(pid_t pid, const char *path)
{
    char *actual = NULL, *expected;
    size_t length = 0, copied = 0;
    struct stat status;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && !fstat(fd, &status));
    expected = malloc((size_t)status.st_size + 1);
    assert(expected);
    while (copied < (size_t)status.st_size) {
        ssize_t amount = read(fd, expected + copied, (size_t)status.st_size - copied);
        assert(amount > 0);
        copied += (size_t)amount;
    }
    assert(!close(fd));
    assert(smaps_prefetch_take(pid, &actual, &length) == 1);
    assert(length == copied && actual);
    assert(!memcmp(actual, expected, copied));
    assert(actual[length] == '\0');
    free(actual);
    free(expected);
}

int main(int argc, char **argv)
{
    int baseline, i;
    char *text = (char *)1;
    size_t length = 123;
    assert(argc == 4);
    prepare(1, argv[2], argv[3]);
    baseline = descriptor_count();
    if (!strcmp(argv[1], "input")) {
        assert(!smaps_prefetch_start());
        smaps_prefetch_network_done();
        compare_input(pids[0].real, argv[2]);
        assert(open_calls == 1);
        assert(smaps_prefetch_take(pids[0].real, &text, &length) == -1);
        assert(!text && !length);
    } else if (!strcmp(argv[1], "multiple")) {
        prepare(2, argv[2], argv[3]);
        assert(!smaps_prefetch_start());
        compare_input(pids[1].real, argv[3]);
        compare_input(pids[0].real, argv[2]);
        assert(open_calls == 2);
    } else if (!strcmp(argv[1], "disabled")) {
        for (i = 0; i < 3; i++) {
            if (i == 0) unsetenv("CRIU_DSA_SMAPS_PREFETCH");
            if (i == 1) setenv("CRIU_DSA_SMAPS_PREFETCH", "0", 1);
            if (i == 2) {
                setenv("CRIU_DSA_SMAPS_PREFETCH", "1", 1);
                setenv("CRIU_DSA_DUMP", "0", 1);
            }
            assert(!smaps_prefetch_start());
            assert(!smaps_prefetch_take(pids[0].real, &text, &length));
            assert(!text && !length && !open_calls);
            assert(!smaps_prefetch_cleanup());
        }
    } else if (!strcmp(argv[1], "invalid")) {
        setenv("CRIU_DSA_SMAPS_PREFETCH", "unexpected", 1);
        assert(smaps_prefetch_start() == -1 && !open_calls);
    } else if (!strcmp(argv[1], "open-error")) {
        prepare(2, argv[2], argv[3]);
        reject_open_pid = pids[1].real;
        assert(smaps_prefetch_start() == -1);
        assert(open_calls == 2);
    } else if (!strcmp(argv[1], "read-error")) {
        assert(!smaps_prefetch_start());
        errno = 0;
        assert(smaps_prefetch_take(pids[0].real, &text, &length) == -1);
        assert(errno == EISDIR && !text && !length);
        assert(open_calls == 1);
    } else if (!strcmp(argv[1], "create-error")) {
        prepare(2, argv[2], argv[3]);
        reject_thread_create = 1;
        assert(smaps_prefetch_start() == -1);
        assert(open_calls == 2);
    } else if (!strcmp(argv[1], "join-einval") || !strcmp(argv[1], "join-ebusy")) {
        prepare(2, argv[2], argv[3]);
        assert(!smaps_prefetch_start());
        reject_thread_join = !strcmp(argv[1], "join-einval") ? EINVAL : EBUSY;
        assert(smaps_prefetch_cleanup() == -1);
        assert(descriptor_count() == baseline + 2);
        assert(fcntl(opened_fds[0], F_GETFD) >= 0);
        assert(fcntl(opened_fds[1], F_GETFD) >= 0);
        /* A failed cleanup must not pretend the task was released. */
        assert(smaps_prefetch_start() == -1 && open_calls == 2);
        reject_thread_join = 0;
        assert(!smaps_prefetch_cleanup());
        assert(descriptor_count() == baseline);
        errno = 0;
        assert(fcntl(opened_fds[0], F_GETFD) == -1 && errno == EBADF);
        errno = 0;
        assert(fcntl(opened_fds[1], F_GETFD) == -1 && errno == EBADF);
        /* After a real join and cleanup, a fresh task remains usable. */
        assert(!smaps_prefetch_start());
        compare_input(pids[0].real, argv[2]);
        compare_input(pids[1].real, argv[3]);
    } else if (!strcmp(argv[1], "dead")) {
        prepare(2, argv[2], argv[3]);
        pids[1].state = TASK_DEAD;
        assert(!smaps_prefetch_start());
        compare_input(pids[0].real, argv[2]);
        assert(!smaps_prefetch_take(pids[1].real, &text, &length));
        assert(!text && !length && open_calls == 1);
    } else if (!strcmp(argv[1], "cleanup")) {
        for (i = 0; i < 20; i++) {
            assert(!smaps_prefetch_start());
            assert(!smaps_prefetch_cleanup());
            assert(!smaps_prefetch_cleanup());
            assert(descriptor_count() == baseline);
        }
    } else {
        assert(!"unknown scenario");
    }
    assert(!smaps_prefetch_cleanup());
    assert(!smaps_prefetch_cleanup());
    assert(descriptor_count() == baseline);
    return 0;
}
"""


class SmapsPrefetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="smaps-prefetch-test-")
        cls.addClassCleanup(cls.build.cleanup)
        directory = Path(cls.build.name)
        for name, content in HEADERS.items():
            (directory / name).write_text(content)
        (directory / "smaps-prefetch.h").write_bytes(
            (ROOT / "criu/include/smaps-prefetch.h").read_bytes())
        # Included twice (harness and production); the fixture header needs a guard.
        header = directory / "pstree.h"
        header.write_text("#ifndef TEST_PSTREE_H\n#define TEST_PSTREE_H\n" +
                          header.read_text() + "\n#endif\n")
        source = directory / "harness.c"
        source.write_text(HARNESS.replace("@SOURCE@", str(ROOT / "criu/smaps-prefetch.c")))
        cls.executable = directory / "harness"
        command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall", "-Wextra",
                   "-Werror", "-pthread", "-I", str(directory), str(source),
                   "-o", str(cls.executable)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError("Production helper fixture did not compile:\n" +
                               result.stdout + result.stderr)

    def exercise(self, scenario, first=b"mapping\nVmFlags: rd wr\n", second=b"different mapping"):
        with tempfile.TemporaryDirectory(prefix="smaps-prefetch-input-") as temporary:
            directory = Path(temporary)
            left, right = directory / "left", directory / "right"
            if first is None:
                left.mkdir()  # open succeeds; real read fails with EISDIR.
            else:
                left.write_bytes(first)
            right.write_bytes(second)
            result = subprocess.run([str(self.executable), scenario, str(left), str(right)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_input_growth_and_no_trailing_newline(self):
        record = b"1000-2000 rw-p 00000000 00:00 0\nVmFlags: rd wr mr mw me ac sd\n"
        self.exercise("input", (record * 5000)[:-1])

    def test_empty_and_page_boundary_inputs(self):
        for size in (0, 4095, 4096, 4097, 65536):
            with self.subTest(size=size):
                self.exercise("input", b"x" * size)

    def test_multiple_pids_keep_distinct_results(self):
        self.exercise("multiple", b"first PID" * 17000, b"second PID" * 19000)

    def test_disabled_and_native_paths_do_not_open_inputs(self):
        self.exercise("disabled")

    def test_invalid_selector_is_rejected(self):
        self.exercise("invalid")

    def test_partial_open_failure_reclaims_descriptors(self):
        self.exercise("open-error")

    def test_read_error_is_reported_without_reopening(self):
        self.exercise("read-error", None)

    def test_thread_creation_failure_reclaims_inputs(self):
        self.exercise("create-error")

    def test_join_failure_preserves_inputs_until_successful_cleanup(self):
        for scenario in ("join-einval", "join-ebusy"):
            with self.subTest(scenario=scenario):
                self.exercise(scenario, b"large input\n" * 20000, b"second input\n" * 20000)

    def test_dead_tasks_are_skipped(self):
        self.exercise("dead")

    def test_early_and_repeated_cleanup_has_no_fd_leaks(self):
        self.exercise("cleanup", b"large input\n" * 20000)


if __name__ == "__main__":
    unittest.main()
