use acpi;
use syscall::io::{Io, Pio};

#[no_mangle]
pub unsafe extern fn kstop() -> ! {
    println!("kstop");

    // ACPI shutdown
    {
        let acpi = acpi::ACPI_TABLE.lock();
        if let Some(ref fadt) = acpi.fadt {
            let port = fadt.pm1a_control_block as u16;
            let mut val = 1 << 13;
            if let Some(ref dsdt) = acpi.dsdt {
                if let Some((a, b)) = dsdt.slp_typ() {
                    println!("Shutdown SLP_TYPa {:X}, SLP_TYPb {:X}", a, b);
                    val |= a;
                }
            }
            println!("Shutdown with ACPI outw(0x{:X}, 0x{:X})", port, val);
            Pio::<u16>::new(port).write(val);
        }
    }

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
