#[cfg(feature = "acpi")]
use crate::{
    context,
    scheme::acpi,
    time,
};

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
    core::arch::asm!("
        cli
        lidt cs:0
        int $3
    ");

    unreachable!();
}

#[cfg(feature = "acpi")]
fn userspace_acpi_shutdown() {
    log::info!("Notifying any potential ACPI driver");
    // Tell whatever driver that handles ACPI, that it should enter the S5 state (i.e.
    // shutdown).
    if ! acpi::register_kstop() {
        // There was no context to switch to.
        log::info!("No ACPI driver was alive to handle shutdown.");
        return;
    }
    log::info!("Waiting one second for ACPI driver to run the shutdown sequence.");
    let (initial_s, initial_ns) = time::monotonic();

    // Since this driver is a userspace process, and we do not use any magic like directly
    // context switching, we have to wait for the userspace driver to complete, with a timeout.
    //
    // We switch context, and wait for one second.
    loop {
        // TODO: Switch directly to whichever process is handling the kstop pipe. We would add an
        // event flag like EVENT_DIRECT, which has already been suggested for IRQs.
        // TODO: Waitpid with timeout? Because, what if the ACPI driver would crash?
        let _ = unsafe { context::switch() };
        let (current_s, current_ns) = time::monotonic();

        let diff_s = current_s - initial_s;
        let diff_part_ns = current_ns - initial_ns;
        let diff_ns = diff_s * 1_000_000_000 + diff_part_ns;

        if diff_ns > 1_000_000_000 {
            log::info!("Timeout reached, thus falling back to other shutdown methods.");
            return;
        }
    }
}

#[no_mangle]
pub unsafe extern fn kstop() -> ! {
    log::info!("Running kstop()");

    #[cfg(feature = "acpi")]
    userspace_acpi_shutdown();

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
        core::arch::asm!("cli; hlt");
    }
}
