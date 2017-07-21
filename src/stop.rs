use acpi;
use syscall::io::{Io, Pio};

#[no_mangle]
pub unsafe extern fn kstop() -> ! {
    println!("kstop");
    acpi::set_global_s_state(5);
    
    // Magic shutdown code for bochs and qemu (older versions).
    for c in "Shutdown".bytes() {
        let port = 0x8900;
        println!("Shutdown with outb(0x{:X}, '{}')", port, c as char);
        Pio::<u8>::new(port).write(c);
    }

    // Magic code for VMWare. Also a hard lock.
    println!("Shutdown with cli hlt");
    asm!("cli; hlt" : : : : "intel", "volatile");

    unreachable!();
}
