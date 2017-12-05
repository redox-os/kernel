# kernel

Redox OS Microkernel

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![docs](https://img.shields.io/badge/docs-master-blue.svg)](https://doc.redox-os.org/kernel/kernel/)
[![](https://tokei.rs/b1/github/redox-os/kernel?category=code)](https://github.com/Aaronepower/tokei)

## Debugging the redox kernel

Running [qemu] with the `-s` flag will set up [qemu] to listen on port 1234 for
a [gdb] client to connect to it. To debug the redox kernel run.

```
make qemu debug=yes
```

This will start a VM with and listen on port 1234 for a [gdb] client. Run the following
to connect to it.

```
(gdb) target remote localhost:1234
```

This is great, but without debug info debugging can be quite difficult. The
redox build process strips the kernel of debug info and copies the debug info
to a separate file `kernel.sym`. You can import these symbols in [gdb] with
the following

```
(gdb) symbol-file build/kernel.sym
```

Now you can set some interesting breakpoints and `continue` the process.

[qemu]: https://www.qemu.org
[gdb]: https://www.gnu.org/software/gdb/
