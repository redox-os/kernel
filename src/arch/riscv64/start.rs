

#[naked]
pub unsafe fn usermode(ip: usize, sp: usize, arg: usize, _singlestep: u32) -> ! {
    asm!(
        "csrw sepc, {}",
        "sret",
        in(reg) ip
    );

    unreachable!();
}
