[![CI](https://github.com/checkpoint-restore/criu/actions/workflows/ci.yml/badge.svg)](
    https://github.com/checkpoint-restore/criu/actions/workflows/ci.yml)
[![CircleCI](https://circleci.com/gh/checkpoint-restore/criu.svg?style=svg)](
    https://circleci.com/gh/checkpoint-restore/criu)

<p align="center"><img src="Documentation/logo.svg" width="256px"/></p>

## CRIU -- A project to implement checkpoint/restore functionality for Linux

CRIU (stands for Checkpoint and Restore in Userspace) is a utility to checkpoint/restore Linux tasks.

Using this tool, you can freeze a running application (or part of it) and checkpoint
it to a hard drive as a collection of files. You can then use the files to restore and run the
application from the point it was frozen at. The distinctive feature of the CRIU
project is that it is mainly implemented in user space. There are some more projects
doing C/R for Linux, and so far CRIU [appears to be](https://criu.org/Comparison_to_other_CR_projects)
the most feature-rich and up-to-date with the kernel.

CRIU project is (almost) the never-ending story, because we have to always keep up with the
Linux kernel supporting checkpoint and restore for all the features it provides. Thus we're
looking for contributors of all kinds -- feedback, bug reports, testing, coding, writing, etc.
Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) if you would like to get involved.

The project [started](https://criu.org/History) as the way to do live migration for OpenVZ
Linux containers, but later grew to more sophisticated and flexible tool. It is currently
used by (integrated into) OpenVZ, LXC/LXD, Docker, and other software, project gets tremendous
help from the community, and its packages are included into many Linux distributions.

The project home is at http://criu.org. This wiki contains all the knowledge base for CRIU we have.
Pages worth starting with are:
- [Installation instructions](http://criu.org/Installation)
- [A simple example of usage](http://criu.org/Simple_loop)
- [Examples of more advanced usage](https://criu.org/Category:HOWTO)
- Troubleshooting can be hard, some help can be found [here](https://criu.org/When_C/R_fails), [here](https://criu.org/What_cannot_be_checkpointed) and [here](https://criu.org/index.php?title=FAQ)

### Checkpoint and restore of simple loop process
<p align="center"><a href="https://asciinema.org/a/232445"><img src="https://asciinema.org/a/232445.png" width="572px" height="412px"/></a></p>

## Advanced features

As main usage for CRIU is live migration, there's a library for it called P.Haul. Also the
project exposes two cool core features as standalone libraries. These are libcompel for parasite code
injection and libsoccr for TCP connections checkpoint-restore.

### Live migration

True [live migration](https://criu.org/Live_migration) using CRIU is possible, but doing
all the steps by hands might be complicated. The [phaul sub-project](https://criu.org/P.Haul)
provides a Go library that encapsulates most of the complexity. This library and the Go bindings
for CRIU are stored in the [go-criu](https://github.com/checkpoint-restore/go-criu) repository.


### Parasite code injection

In order to get state of the running process CRIU needs to make this process execute
some code, that would fetch the required information. To make this happen without
killing the application itself, CRIU uses the [parasite code injection](https://criu.org/Parasite_code)
technique, which is also available as a standalone library called [libcompel](https://criu.org/Compel).

### TCP sockets checkpoint-restore

One of the CRIU features is the ability to save and restore state of a TCP socket
without breaking the connection. This functionality is considered to be useful by
itself, and we have it available as the [libsoccr library](https://criu.org/Libsoccr).

## Workspace Snapshot Integration (This Branch)

This branch adds an optional dump-time btrfs workspace snapshot path.

New dump options:
- `--workspace-snapshot`
- `--workspace-root <path>`
- `--workspace-snapshot-parent <path>`
- `--workspace-snapshot-dir <name>` (default: `snaps`)
- `--workspace-snapshot-meta-dir <name>` (default: `meta`)
- `--workspace-snapshot-strict` (enabled by default)

Behavior summary:
- Snapshot work runs in a dedicated worker thread during dump.
- Dump fails if snapshot is unfinished or failed at the pre-unfreeze gate.
- In strict mode, nested subvolumes under `--workspace-root` cause dump failure.

Required directory topology:
- `--workspace-snapshot-parent` must be outside `--workspace-root`.
- Both paths must be on the same btrfs filesystem.

Troubleshooting:
- `source workspace contains nested subvolumes`: remove nested subvolumes from
    source, or disable strict mode via `--no-workspace-snapshot-strict`.
- `Snapshot parent ... must be outside source workspace ...`: move snapshot
    parent to a sibling path outside source.

Test launch wrapper (no root overlay):
- `test/zdtm/workspace-wrap.sh` uses mount namespace + writable path
    redirection only.
- `criu-test.sh` enables wrapper launch by default for target workload.
- `test/zdtm.py` can enable the same wrapper with:
    `--workspace-wrap --workspace-wrap-root <path>`.

## External Workload Harness (This Branch)

This branch also includes an external workload harness under
`test/workloads/` for compatibility verification with long-running services
and simulators.

Included adapters:
- `redis-ycsb`
- `mysql-sysbench`
- `lammps-bd`
- `verilator-linux`

Entry point:
- `test/workloads/run-matrix.sh`

Useful commands:
- `test/workloads/run-matrix.sh --list`
- `sudo test/workloads/run-matrix.sh --workload all --mode all --profile small`

MySQL safety constraints:
- test instance never uses ports `3306`/`33060`
- all runtime paths must stay under run root
- stop/cleanup is instance-scoped (pidfile + cmdline fingerprint)
- broad process kill patterns are forbidden

See `test/workloads/README.md` for detailed usage and troubleshooting.

## Licence

The project is licensed under GPLv2 (though files sitting in the lib/ directory are LGPLv2.1).

All files in the images/ directory are licensed under the Expat license (so-called MIT).
See the images/LICENSE file.
