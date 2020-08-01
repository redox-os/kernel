#[cfg(feature = "acpi")]
use crate::acpi;
use crate::syscall::io::{Io, Pio};

#[no_mangle]
pub unsafe extern fn kreset() -> ! {
    println!("kreset");

    // 8042 reset
    {
        println!("Reset with 8042");
        let mut port = Pio::<u8>::new(0x64);
        while port.readf(2) {}
        port.write(0xFE);
    }

    // Use triple fault to guarantee reset
    asm!("cli");
    asm!("lidt cs:0");
    asm!("int $3");

    unreachable!();
}

#[no_mangle]
pub unsafe extern fn kstop() -> ! {
    println!("kstop");

    #[cfg(feature = "acpi")]
    acpi::set_global_s_state(5);

    // Magic shutdown code for bochs and qemu (older versions).
    for c in "Shutdown".bytes() {
        let port = 0x8900;
        println!("Shutdown with outb(0x{:X}, '{}')", port, c as char);
        Pio::<u8>::new(port).write(c);
    }

    // Magic shutdown using qemu default ACPI method
    {
        let port = 0x604;
        let data = 0x2000;
        println!("Shutdown with outb(0x{:X}, 0x{:X})", port, data);
        Pio::<u16>::new(port).write(data);
    }

    // Magic code for VMWare. Also a hard lock.
    println!("Shutdown with cli hlt");
    loop {
        asm!("cli; hlt");
    }
}
