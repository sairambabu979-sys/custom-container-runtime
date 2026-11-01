# Learning track

Five chapters, in the order the code runs. Each chapter has three parts:

1. **The idea**: what the kernel offers and why a container runtime needs it.
2. **Read the code**: where hull does it, and which decisions are subtle.
3. **Exercises**: shell experiments first, then changes to hull that a test will judge.

| # | Chapter | You will understand |
|---|---|---|
| 1 | [What a container is](01-what-is-a-container.md) | Why "a container" is just a process with a different view of the system |
| 2 | [Namespaces](02-namespaces.md) | `clone3`, user-namespace ID maps, why PID 1 ignores your Ctrl-C |
| 3 | [The root filesystem](03-root-filesystem.md) | Mount propagation, the fd-based mount API, symlink attacks, `pivot_root` |
| 4 | [The process](04-the-process.md) | The parent/child protocol, the order of privilege drops, the signal and fd traps |
| 5 | [Testing a runtime](05-testing-a-runtime.md) | Differential testing against runc, and the bugs it found in this code |

## How to use this

Don't read hull's code before you have tried the experiments. Each chapter's shell exercises take
five minutes and make the code obvious afterwards.

The "change hull" exercises are the real learning. Most of them are a few lines. A test tells you
whether you got it right, and `scripts/test-integration.sh <test name>` runs one test.

You need a Linux machine (a VM is fine) where you can be root, with kernel 5.14 or newer.
`uname -r` tells you which kernel you have.
