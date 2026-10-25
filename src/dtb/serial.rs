use fdt::properties::{values::StringList, PHandle};
use spin::Mutex;
use syscall::MmioPtr;

use crate::{
    devices::{serial::SerialKind, uart_16550, uart_meson, uart_pl011},
    dtb::{diag_uart_params, diag_uart_range, Fdt, FdtNode},
    memory::{RmmA, RmmArch},
};

pub static COM1: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);

const MESON_UART_REGISTER_SIZE: usize = 0x18;
const MESON_XTAL_HZ: u32 = 24_000_000;

fn stdout_baud(dtb: &Fdt<'_>) -> Option<u32> {
    let params = diag_uart_params(dtb)?;
    let digits = params
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    params.get(..digits)?.parse().ok()
}

fn named_clock_rate(dtb: &Fdt<'_>, node: FdtNode<'_>, name: &str) -> Option<u32> {
    // Initial Meson support only handles clocks whose provider exposes a
    // fixed rate directly through clock-frequency. It does not evaluate
    // outputs from programmable clock controllers.
    let names = node
        .raw_property("clock-names")?
        .as_value::<StringList>()
        .ok()?;
    let clocks = node.raw_property("clocks")?;
    let mut cells = clocks
        .value
        .as_chunks::<4>()
        .0
        .iter()
        .map(|cell| u32::from_be_bytes(*cell));

    for clock_name in names {
        let provider = dtb.root().resolve_phandle(PHandle::new(cells.next()?))?;
        let argument_cells = provider
            .raw_property("#clock-cells")
            .and_then(|property| property.as_value::<u32>().ok())?;

        if clock_name == name {
            return provider
                .raw_property("clock-frequency")
                .and_then(|property| property.as_value::<u32>().ok());
        }

        for _ in 0..argument_cells {
            cells.next()?;
        }
    }

    None
}

#[cfg_attr(not(dtb), expect(dead_code))]
pub unsafe fn init_early(dtb: &Fdt<'_>) {
    unsafe {
        if !matches!(*COM1.lock(), SerialKind::NotPresent) {
            // Hardcoded UART
            return;
        }

        if let Some((phys, size, skip_init, cts, compatible)) = diag_uart_range(dtb) {
            let virt = RmmA::phys_to_virt(phys).data();
            let serial_opt = if compatible.compatible_with("arm,pl011") {
                let mut serial_port = uart_pl011::SerialPort::new(virt, cts);
                if !skip_init {
                    serial_port.init(false);
                }
                Some(SerialKind::Pl011(serial_port))
            } else if compatible.compatible_with("ns16550a") {
                if cfg!(target_arch = "riscv64") {
                    //TODO: get actual register size from device tree
                    let mut serial_port = uart_16550::SerialPort::<MmioPtr<u8>>::new(virt);
                    if !skip_init {
                        let _ = serial_port.init();
                    }
                    Some(SerialKind::Ns16550u8(serial_port))
                } else {
                    //TODO: get actual register size from device tree
                    let mut serial_port = uart_16550::SerialPort::<MmioPtr<u32>>::new(virt);
                    if !skip_init {
                        let _ = serial_port.init();
                    }
                    Some(SerialKind::Ns16550u32(serial_port))
                }
            } else if compatible.compatible_with("snps,dw-apb-uart") {
                //TODO: get actual register size from device tree
                let mut serial_port = uart_16550::SerialPort::<MmioPtr<u32>>::new(virt);
                if !skip_init {
                    let _ = serial_port.init();
                }
                Some(SerialKind::Ns16550u32(serial_port))
            } else if uart_meson::is_compatible(compatible) {
                if size < MESON_UART_REGISTER_SIZE || !virt.is_multiple_of(size_of::<u32>()) {
                    warn!(
                        "invalid Meson UART MMIO range at {:#X}, size {:#X}",
                        virt, size
                    );
                    return;
                }

                let Some(node) = crate::dtb::diag_uart_node(dtb) else {
                    warn!("diagnostic UART disappeared while parsing DTB");
                    return;
                };
                let fifo_size = node
                    .raw_property("fifosize")
                    .or_else(|| node.raw_property("fifo-size"))
                    .and_then(|property| property.as_value::<u32>().ok())
                    .filter(|&value| (1..=256).contains(&value))
                    .unwrap_or(64);
                let baud_rate = stdout_baud(dtb)
                    .filter(|&value| value != 0)
                    .unwrap_or(115_200);
                let Some(variant) = uart_meson::ClockVariant::from_compatible(compatible) else {
                    warn!("unsupported Meson UART compatible {:?}", compatible);
                    return;
                };
                let clock_name = if uart_meson::uses_vendor_clock_binding(compatible) {
                    "clk_uart"
                } else {
                    "baud"
                };
                let Some(clock_rate) = named_clock_rate(dtb, node, clock_name) else {
                    warn!(
                        "Meson UART {:?} requires a {:?} clock",
                        compatible, clock_name
                    );
                    return;
                };
                if clock_rate != MESON_XTAL_HZ {
                    warn!(
                        "Meson UART {:?} clock is {} Hz, expected {} Hz",
                        compatible, clock_rate, MESON_XTAL_HZ
                    );
                    return;
                }
                // SAFETY: diag_uart_range translated and validated the DT MMIO
                // range, and this branch only accepts Meson UART compatibles.
                let mut serial_port =
                    uart_meson::SerialPort::new(virt, baud_rate, variant, fifo_size, skip_init);
                if !skip_init {
                    serial_port.init_early();
                }
                Some(SerialKind::Meson(serial_port))
            } else {
                None
            };
            match serial_opt {
                Some(serial) => {
                    *COM1.lock() = serial;
                    info!("UART {:?} at {:#X} size {:#X}", compatible, virt, size);
                }
                None => {
                    warn!(
                        "UART {:?} at {:#X} size {:#X}: no driver found",
                        compatible, virt, size
                    );
                }
            }
        }
    }
}
