use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use num_derive::{FromPrimitive};


// opcodes
// note: incomplete; only contains opcodes that we currently use
#[derive(FromPrimitive, Debug)]
pub enum NrfDfuOpCode {
    ProtocolVersion = 0x0,
    Select = 0x06,
    Ping = 0x09,
    HardwareVersionGet = 0x0A,
    Response = 0x60, // marks the start of a response message
}

#[derive(FromPrimitive, Debug)]
pub enum NrfDfuResultCode {
    Invalid = 0x00,               // Invalid opcode.
    Success = 0x01,               // Operation successful.
    OpCodeNotSupported = 0x02,    // Opcode not supported.
    InvalidParameter = 0x03,      // Missing or invalid parameter value.
    InsufficientResources = 0x04, // Not enough memory for the data object.
    InvalidObject = 0x05, // Data object does not match the firmware and hardware requirements,
    // the signature is wrong, or parsing the command failed.
    UnsupoortedType = 0x07, // Not a valid object type for a Create request.
    OperationNotPermitted = 0x08, // The state of the DFU process does not allow this operation.
    OperationFailed = 0x0A, // Operation failed.
    ExtError = 0x0B, // Extended error. The next byte of the response contains the error code of
                     // the extended error (see @ref nrf_dfu_ext_error_code_t.
}

#[derive(Debug)]
pub struct DfuError {
    pub code: NrfDfuResultCode,
    pub ext_error: Option<ExtError>,
}

#[derive(FromPrimitive, Debug)]
pub enum ExtError {
    NoError = 0x00,
    InvalidErrorCode = 0x01,
    WrongCommandFormat = 0x02,
    UnknownCommand = 0x03,
    InitCommandInvalid = 0x04,
    FwVersionFailure = 0x05,
    HwVersionFailure = 0x06,
    SdVersionFailure = 0x07,
    SignatureMissing = 0x08,
    WrongHashType = 0x09,
    HashFailed = 0x0A,
    WrongSignatureType = 0x0B,
    VerificationFailed = 0x0C,
    InsufficientSpace = 0x0D,
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum NrfDfuObjectType {
    Invalid = 0x00,
    Command = 0x01,
    Data = 0x02,
}

impl fmt::Display for DfuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DFU error code: {:?}", self.code)?;
        if self.ext_error.is_some() {
            write!(f, "| extended error code: {:?}", self.ext_error)?;
        }
        Ok(())
    }
}

impl Error for DfuError {}

pub trait Request {
    const OPCODE: NrfDfuOpCode;
    type Response: Response;

    fn write_payload<W: Write>(&self, writer: W) -> io::Result<()>;
}

pub trait Response: Sized {
    fn read_payload<R: Read>(reader: R) -> io::Result<Self>;
}

pub struct ProtocolVersionRequest;

impl Request for ProtocolVersionRequest {
    const OPCODE: NrfDfuOpCode = NrfDfuOpCode::ProtocolVersion;

    type Response = ProtocolVersionResponse;

    fn write_payload<W: Write>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

pub struct ProtocolVersionResponse {
    pub version: u8,
}

impl Response for ProtocolVersionResponse {
    fn read_payload<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            version: reader.read_u8()?,
        })
    }
}

pub struct HardwareVersionRequest;

impl Request for HardwareVersionRequest {
    const OPCODE: NrfDfuOpCode = NrfDfuOpCode::HardwareVersionGet;

    type Response = HardwareVersionResponse;

    fn write_payload<W: Write>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct HardwareVersionResponse {
    // See FICR register docs
    part: u32,
    variant: u32,
    rom_size: u32,
    ram_size: u32,
    rom_page_size: u32,
}

impl Response for HardwareVersionResponse {
    fn read_payload<R: Read>(mut response_bytes: R) -> io::Result<Self> {
        // TODO: is this the wrong way round? should it be rom_page_size first?
        Ok(Self {
            part: response_bytes.read_u32::<LE>()?,
            variant: response_bytes.read_u32::<LE>()?,
            rom_size: response_bytes.read_u32::<LE>()?,
            ram_size: response_bytes.read_u32::<LE>()?,
            rom_page_size: response_bytes.read_u32::<LE>()?,
        })
    }
}

pub struct PingRequest(pub u8);

impl Request for PingRequest {
    const OPCODE: NrfDfuOpCode = NrfDfuOpCode::Ping;

    type Response = PingResponse;

    fn write_payload<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.0)
    }
}

#[derive(Debug)]
pub struct PingResponse(pub u8);

impl Response for PingResponse {
    fn read_payload<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self(reader.read_u8()?))
    }
}

pub struct SelectRequest(pub NrfDfuObjectType);

impl Request for SelectRequest {
    const OPCODE: NrfDfuOpCode = NrfDfuOpCode::Select;

    type Response = SelectResponse;

    fn write_payload<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // TOOD should I cast this more nicely?
        writer.write_u8(self.0 as u8)
    }
}

#[derive(Debug)]
pub struct SelectResponse {
    max_size: u32,
    offset: u32,
    crc: u32,
}

impl Response for SelectResponse {
    fn read_payload<R: Read>(mut response_bytes: R) -> io::Result<Self> {
        // NOTE: The parameter order is *not* in accordance with to the parameter order from the docs
        // (https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v15.0.0%2Flib_dfu_transport.html)
        // but rather follows the order from the firmware implementation:
        // https://github.com/tmael/nRF5_SDK/blob/master/components/libraries/bootloader/serial_dfu/nrf_dfu_serial.c#L106
        Ok(Self {
            max_size: response_bytes.read_u32::<LE>()?,
            offset: response_bytes.read_u32::<LE>()?,
            crc: response_bytes.read_u32::<LE>()?,
        })
    }
}
