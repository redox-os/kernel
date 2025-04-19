# Kernel

Redox OS Microkernel

[![docs](https://img.shields.io/badge/docs-master-blue.svg)](https://docs.rs/redox_syscall/latest/syscall/)
[![SLOCs counter](https://tokei.rs/b1/github/redox-os/kernel?category=code)](https://github.com/XAMPPRocky/tokei)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

## Requirements

* [`nasm`](https://nasm.us/) needs to be available on the PATH at build time.

## Building The Documentation

Use this command:

```sh
cargo doc --open --target x86_64-unknown-none
```

## Debugging

### QEMU

Running [QEMU](https://www.qemu.org) with the `-s` flag will set up QEMU to listen on port `1234` for a GDB client to connect to it. To debug the redox kernel run.

```sh
make qemu gdb=yes
```

This will start a virtual machine with and listen on port `1234` for a GDB or LLDB client.

### GDB

If you are going to use [GDB](https://www.gnu.org/software/gdb/), run these commands to load debug symbols and connect to your running kernel:

```
(gdb) symbol-file build/kernel.sym
(gdb) target remote localhost:1234
```

### LLDB

If you are going to use [LLDB](https://lldb.llvm.org/), run these commands to start debugging:

```
(lldb) target create -s build/kernel.sym build/kernel
(lldb) gdb-remote localhost:1234
```

After connecting to your kernel you can set some interesting breakpoints and `continue`
the process. See your debuggers man page for more information on useful commands to run.

## Notes

- Always use `foo.get(n)` instead of `foo[n]` and try to cover for the possibility of `Option::None`. Doing the regular way may work fine for applications, but never in the kernel. No possible panics should ever exist in kernel space, because then the whole OS would just stop working.

- If you receive a kernel panic in QEMU, use `pkill qemu-system` to kill the frozen QEMU process.

## How To Contribute

To learn how to contribute to this system component you need to read the following document:

- [CONTRIBUTING.md](https://gitlab.redox-os.org/redox-os/redox/-/blob/master/CONTRIBUTING.md)

## Development

To learn how to do development with this system component inside the Redox build system you need to read the [Build System](https://doc.redox-os.org/book/build-system-reference.html) and [Coding and Building](https://doc.redox-os.org/book/coding-and-building.html) pages.

### How To Build

To build this system component you need to download the Redox build system, you can learn how to do it on the [Building Redox](https://doc.redox-os.org/book/podman-build.html) page.

This is necessary because they only work with cross-compilation to a Redox virtual machine, but you can do some testing from Linux.

## Funding - _Unix-style Signals and Process Management_

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/RedoxOS-Signals).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)
