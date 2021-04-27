use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use num_derive::FromPrimitive;

// opcodes
// note: incomplete; only contains opcodes that we currently use
#[derive(FromPrimitive, Debug)]
pub enum OpCode {
    ProtocolVersion = 0x00,
    CreateObject = 0x01,
    ReceiptNotifSet = 0x02,
    Crc = 0x03,
    Select = 0x06,
    MtuGet = 0x07,
    Write = 0x08,
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
        // TODO add error code names + descriptions
        write!(f, "DFU error code: {:?}", self.code)?;
        if self.ext_error.is_some() {
            write!(f, "| extended error code: {:?}", self.ext_error)?;
        }
        Ok(())
    }
}

impl Error for DfuError {}

pub trait Request {
    const OPCODE: OpCode;
    type Response: Response;

    fn write_payload<W: Write>(&self, writer: W) -> io::Result<()>;
}

pub trait Response: Sized {
    fn read_payload<R: Read>(reader: R) -> io::Result<Self>;
}

pub struct ProtocolVersionRequest;

impl Request for ProtocolVersionRequest {
    const OPCODE: OpCode = OpCode::ProtocolVersion;

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
    const OPCODE: OpCode = OpCode::HardwareVersionGet;

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
    const OPCODE: OpCode = OpCode::Ping;

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
    const OPCODE: OpCode = OpCode::Select;

    type Response = SelectResponse;

    fn write_payload<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // TODO should I cast this more nicely?
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

pub struct CreateObjectRequest {
    pub obj_type: NrfDfuObjectType,
    pub size: u32,
}

impl Request for CreateObjectRequest {
    const OPCODE: OpCode = OpCode::CreateObject;

    type Response = CreateObjectResponse;

    fn write_payload<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // note:
        // https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v15.0.0%2Flib_dfu_transport.html
        // suggests that `object_type` should be a uint_32t, but message sent by `pc-nrfutil`
        // seems to hold this as a `u8`?
        // TODO dive deeper into `pc-nrfutil` & firmware and verify
        writer.write_u8(self.obj_type as u8)?;
        writer.write_u32::<LE>(self.size)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CreateObjectResponse;

impl Response for CreateObjectResponse {
    fn read_payload<R: Read>(_reader: R) -> io::Result<Self> {
        Ok(Self)
    }
}

pub struct SetPrnRequest(pub u16);

impl Request for SetPrnRequest {
    const OPCODE: OpCode = OpCode::ReceiptNotifSet;

    type Response = SetPrnResponse;

    fn write_payload<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.0)
    }
}

pub struct SetPrnResponse;

impl Response for SetPrnResponse {
    fn read_payload<R: Read>(_reader: R) -> io::Result<Self> {
        Ok(Self)
    }
}

pub struct GetMtuRequest;

impl Request for GetMtuRequest {
    const OPCODE: OpCode = OpCode::MtuGet;

    type Response = GetMtuResponse;

    fn write_payload<W: Write>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

pub struct GetMtuResponse(pub u16);

impl Response for GetMtuResponse {
    fn read_payload<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self(reader.read_u16::<LE>()?))
    }
}

pub struct WriteRequest {
    pub request_payload: Vec<u8>,
}

impl Request for WriteRequest {
    const OPCODE: OpCode = OpCode::Write;

    type Response = WriteResponse;

    // TODO: note that this currently does not take into account the MTU –
    // we'll need to split this up into several requests for any data that exceeds the MTU
    // reported by the target device
    fn write_payload<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write(&self.request_payload[..]);
        Ok(())
    }
}

#[derive(Debug)]
// MAY contain a crc
pub struct WriteResponse(pub Option<u32>);

impl Response for WriteResponse {
    fn read_payload<R: Read>(mut _reader: R) -> io::Result<Self> {
        // firmware doesn't return WriteResponse in our use case; ignore for now
        todo!();
    }
}

pub struct CrcRequest;

impl Request for CrcRequest {
    const OPCODE: OpCode = OpCode::Crc;

    type Response = CrcResponse;

    fn write_payload<W: Write>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct CrcResponse{
    pub offset: u32,
    pub crc: u32,
}

impl Response for CrcResponse {
    fn read_payload<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self{
            offset: reader.read_u32::<LE>()?,
            crc: reader.read_u32::<LE>()?,
        })
    }
}