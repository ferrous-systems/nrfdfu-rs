use num_traits::FromPrimitive;
use serialport::{available_ports, ClearBuffer, SerialPort};
use std::error::Error;
use std::time::Duration;

mod messages;

use messages::{
    DfuError, ExtError, NrfDfuOpCode, HardwareVersionRequest, HardwareVersionResponse,
    NrfDfuResultCode,
    ProtocolVersionRequest, Request, Response,
};

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

    let version = conn.fetch_protocol_version()?;
    println!("protocol version: {}", version);

    // TODO: ⚡️ this yields the protocol version response again
    let hw_version = conn.fetch_hardware_version()?;
    println!("hardware version: {:?}", hw_version);

    Ok(())
}

struct BootloaderConnection {
    slip_enc: slip_codec::Encoder,
    slip_dec: slip_codec::Decoder,
    serial: Box<dyn SerialPort>,
}

impl BootloaderConnection {
    fn new(serial: Box<dyn SerialPort>) -> Result<Self> {
        serial.clear(ClearBuffer::All)?;
        Ok(Self {
            slip_enc: slip_codec::Encoder::new(),
            slip_dec: slip_codec::Decoder::new(),
            serial,
        })
    }

    fn request<R: Request>(&mut self, req: R) -> Result<R::Response> {
        let mut buf = vec![R::OPCODE as u8];
        req.write_payload(&mut buf)?;
        eprintln!("req: {:x?}", buf);
        self.slip_enc.encode(&buf, &mut self.serial)?;

        let mut response_bytes = vec![];
        self.slip_dec
            .decode(&mut self.serial, &mut response_bytes)
            .map_err(|e| format!("{:?}", e))?;
        eprintln!("resp: {:x?}", response_bytes);

        // Response format:
        // - Fixed byte 0x60
        // - Request opcode
        // - Response result code
        // - Response payload
        if response_bytes.len() < 3 {
            return Err(format!(
                "truncated response (expected at least 3 bytes, got {})",
                response_bytes.len()
            )
            .into());
        }

        if response_bytes[0] != NrfDfuOpCode::Response as u8 {
            return Err(format!(
                "malformed response (expected nrf DFU response preamble 0x60, got 0x{:02x})",
                response_bytes[0]
            )
            .into());
        }

        if response_bytes[1] != R::OPCODE as u8 {
            return Err(format!(
                "malformed response (expected echoed opcode {:?} (0x{:02x}), got 0x{:02x})",
                R::OPCODE,
                R::OPCODE as u8,
                response_bytes[1]
            )
            .into());
        }

        let result: NrfDfuResultCode =
            NrfDfuResultCode::from_u8(response_bytes[2]).ok_or_else(|| {
                format!(
                    "malformed response (invalid result code 0x{:02x})",
                    response_bytes[2]
                )
            })?;

        match result {
            NrfDfuResultCode::Success => {}
            NrfDfuResultCode::ExtError => match response_bytes.get(3) {
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

        let mut response_bytes = &response_bytes[3..];
        let response = R::Response::read_payload(&mut response_bytes)?;

        if !response_bytes.is_empty() {
            return Err(format!("trailing bytes in response").into());
        }

        Ok(response)
    }

    fn fetch_protocol_version(&mut self) -> Result<u8> {
        let response = self.request(ProtocolVersionRequest);
        match response{
            Ok(version_response) => Ok(version_response.version),
            Err(e) => Err(e)
        }
    }

    fn fetch_hardware_version(&mut self) -> Result<HardwareVersionResponse> {
        self.request(HardwareVersionRequest)
    }
}
