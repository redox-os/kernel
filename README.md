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
cargo doc --open --target x86_64-unknown-none`.
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
