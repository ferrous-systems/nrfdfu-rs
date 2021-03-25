
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

pub const NRF_DFU_PREAMBLE: u8 = 0x60;

// opcodes
// note: incomplete; only contains opcodes that we currently use
#[derive(FromPrimitive, Debug)]
pub enum NrfDfuOpCode {
    ProtocolVersion = 0x0,
}
#[derive(FromPrimitive, Debug)]
pub enum NrfDfuResultCode {
    Invalid                 = 0x00,    // Invalid opcode.
    Success                 = 0x01,    // Operation successful.
    OpCodeNotSupported      = 0x02,    // Opcode not supported.
    InvalidParameter        = 0x03,    // Missing or invalid parameter value.
    InsufficientResources    = 0x04,    // Not enough memory for the data object.
    InvalidObject           = 0x05,    // Data object does not match the firmware and hardware requirements, the signature is wrong, or parsing the command failed.
    UnsupoortedType         = 0x07,    // Not a valid object type for a Create request.
    OperationNotPermitted   = 0x08,    // The state of the DFU process does not allow this operation.
    OperationFailed         = 0x0A,    // Operation failed.
    ExtError                = 0x0B,    // Extended error. The next byte of the response contains the error code of the extended error (see @ref nrf_dfu_ext_error_code_t.
}

#[derive(Debug)]
pub enum NrfDfuResponseDetails {
    ProtocolVersion(u8),               // Protocol version response
}

#[derive(Debug)]
pub struct NrfDfuResponse {
    /// should always be NRF_DFU_PREAMBLE
    preamble: u8,
    /// the opcode of the request we're responding to
    request: NrfDfuOpCode,
    /// Result of the operation. (e.g. error code)
    result: NrfDfuResultCode,
    // response (e.g. the thing you asked for)
    response_details: NrfDfuResponseDetails
}

impl NrfDfuResponse {
    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        // All responses start with `0x60`
        let preamble = bytes[0];
        assert_eq!(preamble, NRF_DFU_PREAMBLE);

        let request = FromPrimitive::from_u8(bytes[1]).unwrap();

        // TODO split off into separate handler functions depending on `request` once this get more complex
        let (result, response_details) = match request {
            NrfDfuOpCode::ProtocolVersion => {
                let result = FromPrimitive::from_u8(bytes[2]).unwrap();
                let protocol_version = bytes[3];
                (result, NrfDfuResponseDetails::ProtocolVersion(protocol_version))
            }
        };

        NrfDfuResponse {
            preamble,
            request,
            result,
            response_details,
        }
    }
}