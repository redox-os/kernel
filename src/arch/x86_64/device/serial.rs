use crate::devices::uart_16550::SerialPort;
use crate::syscall::io::Pio;
use spin::Mutex;

pub static COM1: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x3F8));
pub static COM2: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x2F8));
pub static COM3: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x3E8));
pub static COM4: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x2E8));

pub unsafe fn init() {
    COM1.lock().init();
    COM2.lock().init();
    COM3.lock().init();
    COM4.lock().init();
}
