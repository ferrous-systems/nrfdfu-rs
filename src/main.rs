use num_traits::FromPrimitive;
use serialport::{available_ports, SerialPort};
use std::error::Error;
use std::time::Duration;
use std::fs::File;
use std::io::Read;

mod messages;
mod slip;

use messages::*;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USB_VID: u16 = 0x1915;
const USB_PID: u16 = 0x521f;

/// Bootloader protocol version we support.
const PROTOCOL_VERSION: u8 = 1;

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
    let matching_ports: Vec<_> = available_ports()?
        .into_iter()
        .filter(|port| match &port.port_type {
            serialport::SerialPortType::UsbPort(usb) => usb.vid == USB_VID && usb.pid == USB_PID,
            _ => false,
        })
        .collect();

    let port = match matching_ports.len() {
        0 => return Err(format!("no matching USB serial device found").into()),
        1 => serialport::new(&matching_ports[0].port_name, 115200)
            .timeout(Duration::from_millis(1000))
            .open()?,
        _ => return Err(format!("multiple matching USB serial devices found").into()),
    };

    let mut conn = BootloaderConnection::new(port)?;
    let proto_version = conn.fetch_protocol_version()?;
    if proto_version != PROTOCOL_VERSION {
        return Err(format!(
            "device reports protocol version {}, we only support {}",
            proto_version, PROTOCOL_VERSION
        )
        .into());
    }

    // Disable receipt notification. USB is a reliable transport.
    conn.set_receipt_notification(0)?;

    let mtu = conn.fetch_mtu()?;
    println!("MTU = {} Bytes", mtu);

    if false {
        // Needs support for sending init packets first.
        conn.create_data_object(8)?;
    }

    let obj_select = conn.select_object_command();
    println!("select object response: {:?}", obj_select);

    let version = conn.fetch_protocol_version()?;
    println!("protocol version: {}", version);

    let hw_version = conn.fetch_hardware_version()?;
    println!("hardware version: {:?}", hw_version);

    conn.send_init_packet()?;

    Ok(())
}

struct BootloaderConnection {
    serial: Box<dyn SerialPort>,
    buf: Vec<u8>,
}

impl BootloaderConnection {
    fn new(serial: Box<dyn SerialPort>) -> Result<Self> {
        Ok(Self {
            serial,
            buf: Vec::new(),
        })
    }

    fn request<R: Request>(&mut self, req: R) -> Result<R::Response> {
        let mut buf = vec![R::OPCODE as u8];
        req.write_payload(&mut buf)?;
        eprintln!("--> {:?}", buf);

        // Go through an intermediate buffer to avoid writing every byte individually.
        self.buf.clear();
        slip::encode_frame(&buf, &mut self.buf)?;
        self.serial.write_all(&self.buf)?;

        self.buf.clear();
        slip::decode_frame(&mut self.serial, &mut self.buf)?;
        eprintln!("<-- {:?}", self.buf);

        // Response format:
        // - Fixed byte 0x60
        // - Request opcode
        // - Response result code
        // - Response payload
        if self.buf.len() < 3 {
            return Err(format!(
                "truncated response (expected at least 3 bytes, got {})",
                self.buf.len()
            )
            .into());
        }

        if self.buf[0] != OpCode::Response as u8 {
            return Err(format!(
                "malformed response (expected nrf DFU response preamble 0x60, got 0x{:02x})",
                self.buf[0]
            )
            .into());
        }

        if self.buf[1] != R::OPCODE as u8 {
            return Err(format!(
                "malformed response (expected echoed opcode {:?} (0x{:02x}), got 0x{:02x})",
                R::OPCODE,
                R::OPCODE as u8,
                self.buf[1]
            )
            .into());
        }

        let result: NrfDfuResultCode = NrfDfuResultCode::from_u8(self.buf[2]).ok_or_else(|| {
            format!(
                "malformed response (invalid result code 0x{:02x})",
                self.buf[2]
            )
        })?;

        match result {
            NrfDfuResultCode::Success => {}
            NrfDfuResultCode::ExtError => match self.buf.get(3) {
                Some(byte) => {
                    let ext_error: ExtError = ExtError::from_u8(*byte).ok_or_else(|| {
                        format!(
                            "malformed response (unknown extended error code 0x{:02x})",
                            byte
                        )
                    })?;

                    return Err(DfuError {
                        code: NrfDfuResultCode::ExtError,
                        ext_error: Some(ext_error),
                    }
                    .into());
                }
                None => {
                    return Err(format!("malformed response (missing extended error byte)").into());
                }
            },
            code => {
                return Err(DfuError {
                    code,
                    ext_error: None,
                }
                .into())
            }
        }

        let mut response_bytes = &self.buf[3..];
        let response = R::Response::read_payload(&mut response_bytes)?;

        if !response_bytes.is_empty() {
            return Err(format!("trailing bytes in response").into());
        }

        Ok(response)
    }

    fn fetch_protocol_version(&mut self) -> Result<u8> {
        let response = self.request(ProtocolVersionRequest);
        match response {
            Ok(version_response) => Ok(version_response.version),
            Err(e) => Err(e),
        }
    }

    fn fetch_hardware_version(&mut self) -> Result<HardwareVersionResponse> {
        self.request(HardwareVersionRequest)
    }

    /// WIP: fill this in as we figure out how the protocol works.
    /// This sends the `.dat` file that's zipped into our firmware DFU .zip(?)
    /// modeled after `pc-nrfutil`s `dfu_transport_serial::send_init_packet()`
    fn send_init_packet(&mut self) -> Result<()> {
        println!("Sending init packet...");
        let select_response =  self.select_object_command()?;
        println!("Object selected: {:?}", select_response);

        // TODO pass file path into fn
        let mut dat_file = File::open("loopback.dat").expect("no file found");
        let mut data = Vec::new();
        dat_file.read_to_end(&mut data)?;
        let data_size = data.len() as u32;

        // e.g. self.__create_command(len(init_packet))
        println!("Creating Command...");
        self.create_command_object(data_size)?;
        println!("Command created");

        // e.g. self.__stream_data(data=init_packet)
        println!("Streaming Data: len: {}", data_size);
        let write_response = self.send_write_request(data)?;
        // TODO: calculate crc and send crc packet
        println!("Write response: {:?}", write_response);

        Ok(())
    }

    /// "Init packet"
    fn select_object_command(&mut self) -> Result<SelectResponse> {
        self.request(SelectRequest(NrfDfuObjectType::Command))
    }

    fn create_command_object(&mut self, size: u32) -> Result<()> {
        self.request(CreateObjectRequest {
            obj_type: NrfDfuObjectType::Command,
            size,
        })?;
        Ok(())
    }

    fn create_data_object(&mut self, size: u32) -> Result<()> {
        // Note: Data objects cannot be created if no init packet has been sent. This results in an
        // `OperationNotPermitted` error.
        self.request(CreateObjectRequest {
            obj_type: NrfDfuObjectType::Data,
            size,
        })?;
        Ok(())
    }

    fn set_receipt_notification(&mut self, every_n_packets: u16) -> Result<()> {
        self.request(SetPrnRequest(every_n_packets))?;
        Ok(())
    }

    fn fetch_mtu(&mut self) -> Result<u16> {
        Ok(self.request(GetMtuRequest)?.0)
    }

    fn send_write_request(&mut self, data: Vec<u8>) -> Result<WriteResponse> {
        self.request(WriteRequest{
            request_payload: data,
        })
    }
}
