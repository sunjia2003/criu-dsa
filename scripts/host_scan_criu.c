#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Preserve every inherited arena/control FD; only constrain this CRIU exec. */
int main(int argc, char **argv)
{
    const char *executable = getenv("CDP_HOST_SCAN_EXECUTABLE");
    const char *roots[] = {
        "/home/lbr/workspace/result-processed/20261015-host-scan-builds/",
        "/home/lbr/workspace/result-processed/20261016-host-scan-builds/"
    };
    const char *name = NULL;
    cpu_set_t cpus;
    (void)argc;
    if (executable)
        for (unsigned i = 0; i < sizeof(roots)/sizeof(roots[0]); i++)
            if (!strncmp(executable, roots[i], strlen(roots[i])))
                name = executable+strlen(roots[i]);
    if (!name || (strcmp(name, "baseline.criu") && strcmp(name, "candidate-v3.criu") &&
                 strcmp(name, "candidate-v4.criu") && strcmp(name, "candidate-v5.criu") &&
                 strcmp(name, "candidate-v6.criu") && strcmp(name, "candidate-v7.criu") &&
                 strcmp(name, "candidate-v8.criu") && strcmp(name, "candidate-v9.criu"))) {
        fputs("Unregistered experimental CRIU executable\n", stderr);
        return 2;
    }
    CPU_ZERO(&cpus);
    CPU_SET(18, &cpus); CPU_SET(19, &cpus); CPU_SET(20, &cpus);
    const char *main_cpu = getenv("CRIU_DSA_HOST_SCAN_MAIN_CPU");
    if (main_cpu && *main_cpu) {
        char *end;
        long cpu = strtol(main_cpu, &end, 10);
        if (*end || cpu < 18 || cpu > 20) {
            fputs("Main CPU must be in the registered Host set 18-20\n", stderr);
            return 2;
        }
        CPU_ZERO(&cpus);
        CPU_SET(cpu, &cpus);
    }
    if (sched_setaffinity(0, sizeof(cpus), &cpus)) {
        perror("CRIU affinity");
        return 2;
    }
    argv[0] = (char *)executable;
    execv(executable, argv);
    perror("exec CRIU");
    return 127;
}
