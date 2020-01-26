# kernel

Redox OS Microkernel

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![docs](https://img.shields.io/badge/docs-master-blue.svg)](https://doc.redox-os.org/kernel/kernel/)
[![](https://tokei.rs/b1/github/redox-os/kernel?category=code)](https://github.com/Aaronepower/tokei)

## Debugging the redox kernel

Running [qemu] with the `-s` flag will set up [qemu] to listen on port 1234 for
a [gdb] client to connect to it. To debug the redox kernel run.

```
make qemu gdb=yes
```

This will start a VM with and listen on port 1234 for a [gdb] or [lldb] client.

## [gdb]

If you are going to use [gdb], run the following to load debug symbols and connect
to your running kernel.

```
(gdb) symbol-file build/kernel.sym
(gdb) target remote localhost:1234
```

## [lldb]

If you are going to use [lldb], run the following to start debugging.

```
(lldb) target create -s build/kernel.sym build/kernel
(lldb) gdb-remote localhost:1234
```

## Debugging

After connecting to your kernel you can set some interesting breakpoints and `continue`
the process. See your debuggers man page for more information on useful commands to run.

[qemu]: https://www.qemu.org
[gdb]: https://www.gnu.org/software/gdb/
[lldb]: https://lldb.llvm.org/
