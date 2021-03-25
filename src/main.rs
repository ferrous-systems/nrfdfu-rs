use std::{path::Path, time::Duration};
use serialport::available_ports;
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USB_VID: u16 = 0x1915;
const USB_PID: u16 = 0x521f;

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run() -> Result<()> {
    let matching_ports: Vec<_> = available_ports()?.into_iter().filter(|port| {
        match &port.port_type {
            serialport::SerialPortType::UsbPort(usb) => {
                usb.vid == USB_VID && usb.pid == USB_PID
            }
            _ => false,
        }
    }).collect();

    let mut port = match matching_ports.len() {
        0 => return Err(format!("no matching USB serial device found").into()),
        1 => serialport::new(&matching_ports[0].port_name, 115200)
                            .timeout(Duration::from_millis(1000))
                            .open()?,
        _ => return Err(format!("multiple matching USB serial devices found").into()),
    };

    let mut slip_enc = slip_codec::Encoder::new();
    let mut slip_dec = slip_codec::Decoder::new();

    slip_enc.encode(&[0x00], &mut port)?;

    let mut response = vec![];
    slip_dec.decode(&mut port, &mut response).map_err(|e| format!("{:?}", e))?;

    println!("{:?}", response);

    Ok(())
}
