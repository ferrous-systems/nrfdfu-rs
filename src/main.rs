use num_traits::FromPrimitive;
use serialport::{available_ports, SerialPort};
use std::time::Duration;
use std::{error::Error, fs};

mod elf;
mod init_packet;
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
    let elf_path = std::env::args_os().skip(1).next();
    let image = match elf_path {
        Some(path) => {
            let elf = fs::read(&path)?;
            Some(elf::read_elf_image(&elf)?)
        }
        None => None,
    };

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

    // Disable receipt notification. USB is a reliable transport.
    conn.set_receipt_notification(0)?;

    let obj_select = conn.select_object_command();
    println!("select object response: {:?}", obj_select);

    let version = conn.fetch_protocol_version()?;
    println!("protocol version: {}", version);

    let hw_version = conn.fetch_hardware_version()?;
    println!("hardware version: {:?}", hw_version);

    let image = image.unwrap_or_else(|| vec![1, 2, 3]);

    let init_packet = init_packet::build_init_packet(&image);
    conn.send_init_packet(&init_packet)?;
    conn.create_data_object(image.len() as u32)?;

    Ok(())
}

struct BootloaderConnection {
    serial: Box<dyn SerialPort>,
    buf: Vec<u8>,
    mtu: u16,
}

impl BootloaderConnection {
    fn new(serial: Box<dyn SerialPort>) -> Result<Self> {
        let mut this = Self {
            serial,
            buf: Vec::new(),
            mtu: 0,
        };

        // We must check the protocol version before doing anything else, since any other command
        // might change if the version changes.
        let proto_version = this.fetch_protocol_version()?;
        if proto_version != PROTOCOL_VERSION {
            return Err(format!(
                "device reports protocol version {}, we only support {}",
                proto_version, PROTOCOL_VERSION
            )
            .into());
        }

        let mtu = this.fetch_mtu()?;
        println!("MTU = {} Bytes", mtu);
        this.mtu = mtu;
        Ok(this)
    }

    /// send `req` and do not fetch any response
    fn request<R: Request>(&mut self, req: R) -> Result<()> {
        let mut buf = vec![R::OPCODE as u8];
        req.write_payload(&mut buf)?;
        eprintln!("--> {:?}", buf);

        // Go through an intermediate buffer to avoid writing every byte individually.
        self.buf.clear();
        slip::encode_frame(&buf, &mut self.buf)?;
        self.serial.write_all(&self.buf)?;

        Ok(())
    }

    /// send `req` and expect a response.
    /// aborts if no response is received within timeout window.
    fn request_response<R: Request>(&mut self, req: R) -> Result<R::Response> {
        self.request(req)?;

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

        let result: ResultCode = ResultCode::from_u8(self.buf[2]).ok_or_else(|| {
            format!(
                "malformed response (invalid result code 0x{:02x})",
                self.buf[2]
            )
        })?;

        match result {
            ResultCode::Success => {}
            ResultCode::ExtError => match self.buf.get(3) {
                Some(byte) => {
                    let ext_error: ExtError = ExtError::from_u8(*byte).ok_or_else(|| {
                        format!(
                            "malformed response (unknown extended error code 0x{:02x})",
                            byte
                        )
                    })?;

                    return Err(DfuError {
                        code: ResultCode::ExtError,
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
        let response = self.request_response(ProtocolVersionRequest);
        match response {
            Ok(version_response) => Ok(version_response.version),
            Err(e) => Err(e),
        }
    }

    fn fetch_hardware_version(&mut self) -> Result<HardwareVersionResponse> {
        self.request_response(HardwareVersionRequest)
    }

    /// This sends the `.dat` file that's zipped into our firmware DFU .zip(?)
    /// modeled after `pc-nrfutil`s `dfu_transport_serial::send_init_packet()`
    fn send_init_packet(&mut self, data: &[u8]) -> Result<()> {
        println!("Sending init packet...");
        let select_response = self.select_object_command()?;
        println!("Object selected: {:?}", select_response);

        let data_size = data.len() as u32;

        // e.g. self.__create_command(len(init_packet))
        println!("Creating Command...");
        self.create_command_object(data_size)?;
        println!("Command created");

        // e.g. self.__stream_data(data=init_packet)
        println!("Streaming Data: len: {}", data_size);
        let write_response = self.write_object_data(data)?;
        // TODO: calculate crc and check against what we received
        let target_crc = self.get_crc()?;
        println!(
            "Write response: {:?} | crc: {:?}",
            write_response, target_crc
        );

        self.execute()?;

        Ok(())
    }

    /// Sends a
    /// Request Type: `Select`
    /// Parameters:   `Object type = Command`
    fn select_object_command(&mut self) -> Result<SelectResponse> {
        self.request_response(SelectRequest(ObjectType::Command))
    }

    /// Sends a
    /// Request Type: `Create`
    /// Parameters:   `Object type = Command`
    ///               `size`
    fn create_command_object(&mut self, size: u32) -> Result<()> {
        self.request_response(CreateObjectRequest {
            obj_type: ObjectType::Command,
            size,
        })?;
        Ok(())
    }

    /// Sends a
    /// Request Type: `Create`
    /// Parameters:   `Object type = Data`
    ///               `size`
    fn create_data_object(&mut self, size: u32) -> Result<()> {
        // Note: Data objects cannot be created if no init packet has been sent. This results in an
        // `OperationNotPermitted` error.
        self.request_response(CreateObjectRequest {
            obj_type: ObjectType::Data,
            size,
        })?;
        Ok(())
    }

    fn set_receipt_notification(&mut self, every_n_packets: u16) -> Result<()> {
        self.request_response(SetPrnRequest(every_n_packets))?;
        Ok(())
    }

    fn fetch_mtu(&mut self) -> Result<u16> {
        Ok(self.request_response(GetMtuRequest)?.0)
    }

    fn write_object_data(&mut self, data: &[u8]) -> Result<()> {
        // On the wire, the write request contains the opcode byte, and is then SLIP-encoded,
        // potentially doubling the size, so the chunk size has to be smaller than the MTU.
        let max_chunk_size = usize::from(self.mtu / 2 - 1);
        for chunk in data.chunks(max_chunk_size) {
            // TODO: this also needs to take into account the receipt response. In our case we turn
            // it off, so there's nothing to do here.
            self.request(WriteRequest {
                request_payload: chunk,
            })?;
        }

        Ok(())
    }

    fn get_crc(&mut self) -> Result<CrcResponse> {
        self.request_response(CrcRequest)
    }

    // tell the target to execute whatever request setup we sent them before
    fn execute(&mut self) -> Result<ExecuteResponse> {
        self.request_response(ExecuteRequest)
    }
}
