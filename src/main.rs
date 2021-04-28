use num_traits::FromPrimitive;
use serialport::{available_ports, SerialPort};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

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

    println!("==================================================");
    println!(" FLASHING FIRMWARE");
    println!("==================================================");
    let dat_path = Path::new("loopback.dat");
    let bin_path = Path::new("loopback.bin");
    conn.send_init_packet(dat_path, mtu)?;
    conn.send_firmware(bin_path, mtu)?;

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
    fn send_init_packet(&mut self, dat_path: &Path, mtu: u16) -> Result<()> {
        let mut dat_file = File::open(dat_path).expect(".dat file not found");
        let mut data = Vec::new();
        dat_file.read_to_end(&mut data)?;
        let data_size = data.len() as u32;

        println!("Sending init packet...");
        let select_response = self.select_object_command()?;
        println!("Object selected: {:?}", select_response);

        // e.g. self.__create_command(len(init_packet))
        println!("Creating Command...");
        self.create_command_object(data_size)?;
        println!("Command created");

        // e.g. self.__stream_data(data=init_packet)
        println!("Streaming Data: len: {}", data_size);
        self.stream_data(data, mtu)?;
        // TODO: calculate crc and check against what we received
        let _target_crc = self.get_crc()?;

        // e.g. self.__execute()
        self.execute()?;

        Ok(())
    }

    /// WIP: fill this in as we figure out how the protocol works.
    /// `mtu`: Maxmimum Transmission unit; The maximum number of bytes to be sent in one packet
    fn send_firmware(&mut self, bin_path: &Path, mtu: u16) -> Result<()> {
        // TODO deduplicate with send_init_packet code
        let mut bin_file = File::open(bin_path).expect("firmware file not found");
        let mut data = Vec::new();
        bin_file.read_to_end(&mut data)?;
        let data_size = data.len() as u32;

        println!("Sending firmware file...");

        // TODO: use actual firmware img
        let data_size = 42;

        // e.g. self.__create_data(len(data))
        self.create_data_object(data_size);

        // e.g. self.__stream_data(data=data, crc=response['crc'], offset=i)
        self.stream_data(data, mtu)?;
        // TODO: calculate crc and check against what we received
        let _target_crc = self.get_crc()?;

        // e.g. self.__execute()
        self.execute()?;

        Ok(())
    }

    /// Sends a
    /// Request Type: `Select`
    /// Parameters:   `Object type = Command`
    fn select_object_command(&mut self) -> Result<SelectResponse> {
        self.request_response(SelectRequest(NrfDfuObjectType::Command))
    }

    /// Sends a
    /// Request Type: `Create`
    /// Parameters:   `Object type = Command`
    ///               `size`
    fn create_command_object(&mut self, size: u32) -> Result<()> {
        self.request_response(CreateObjectRequest {
            obj_type: NrfDfuObjectType::Command,
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
            obj_type: NrfDfuObjectType::Data,
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

    // TODO pass data by reference
    fn stream_data(&mut self, mut data: Vec<u8>, mtu: u16) -> Result<()> {

        let max_payload = ((mtu-1)/2 - 1) as usize; // stolen from `dfu_transport_serial::__stream_data()`
        let mut bytes_left = data.len();

        println!("Streaming {} bytes in chunks of <={}...", data.len(), max_payload);

        // Q: how do I do this more idiomatically?
        while bytes_left > 0 {
            let chunk_size = match bytes_left < max_payload {
                true => bytes_left,
                false => max_payload,
            };

            bytes_left -= chunk_size;

            let chunk: Vec<u8> = data.drain(0..chunk_size).collect();
            // firmware doesn't return WriteResponse in our use case; ignore for now
            self.request(WriteRequest {
                request_payload: chunk,
            });
            println!("\n\n");
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
