//! Bounded exact-output decoding for one complete PBZX XZ chunk.

use std::fmt;

use crate::ffi;

pub const MAX_XZ_CHUNK_SIZE: u64 = 1 << 30;
pub const MAX_XZ_MEMORY_LIMIT: u64 = 1 << 30;

/// Static failure from bounded XZ decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XzError {
    InvalidArgument,
    InputLimit,
    OutputLimit,
    MemoryLimit,
    AllocationFailed,
    Malformed,
    Truncated,
    TrailingData,
    Unsupported,
    Library,
    OutputSizeMismatch,
}

impl fmt::Display for XzError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid XZ decoder argument",
            Self::InputLimit => "XZ input limit exceeded",
            Self::OutputLimit => "XZ output limit exceeded",
            Self::MemoryLimit => "XZ memory limit exceeded",
            Self::AllocationFailed => "XZ decoder allocation failed",
            Self::Malformed => "malformed XZ stream",
            Self::Truncated => "truncated XZ stream",
            Self::TrailingData => "trailing data after XZ stream",
            Self::Unsupported => "unsupported XZ stream",
            Self::Library => "XZ decoder failed",
            Self::OutputSizeMismatch => "XZ output size differs from its declaration",
        })
    }
}

impl std::error::Error for XzError {}

/// Decodes exactly one complete XZ stream into an exact-size caller buffer.
///
/// Both buffers and `memory_limit` are independently capped by the native
/// boundary. Any error clears bytes written to `output`. A successful stream
/// that produces fewer bytes than the declared output buffer is also rejected
/// and cleared.
///
/// # Errors
///
/// Returns a static error for invalid limits, allocation failure, malformed,
/// truncated, concatenated, trailing, unsupported, oversized, or incorrectly
/// sized input.
pub fn decode_exact(input: &[u8], output: &mut [u8], memory_limit: u64) -> Result<(), XzError> {
    let (status, output_size) = ffi::decode_xz(input, output, memory_limit);
    if let Err(error) = check(status) {
        output.fill(0);
        return Err(error);
    }
    if output_size != output.len() {
        output.fill(0);
        return Err(XzError::OutputSizeMismatch);
    }
    Ok(())
}

fn check(status: i32) -> Result<(), XzError> {
    match status {
        0 => Ok(()),
        1 => Err(XzError::InvalidArgument),
        2 => Err(XzError::InputLimit),
        3 => Err(XzError::OutputLimit),
        4 => Err(XzError::MemoryLimit),
        5 => Err(XzError::AllocationFailed),
        6 => Err(XzError::Malformed),
        7 => Err(XzError::Truncated),
        8 => Err(XzError::TrailingData),
        9 => Err(XzError::Unsupported),
        _ => Err(XzError::Library),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_native_status() {
        let expected = [
            Ok(()),
            Err(XzError::InvalidArgument),
            Err(XzError::InputLimit),
            Err(XzError::OutputLimit),
            Err(XzError::MemoryLimit),
            Err(XzError::AllocationFailed),
            Err(XzError::Malformed),
            Err(XzError::Truncated),
            Err(XzError::TrailingData),
            Err(XzError::Unsupported),
            Err(XzError::Library),
        ];
        for (status, expected) in (0_i32..).zip(expected) {
            assert_eq!(check(status), expected);
        }
        assert_eq!(check(999), Err(XzError::Library));
    }

    #[test]
    fn malformed_input_is_redacted_and_clears_output() {
        let mut output = [0xa5; 32];
        let error = decode_exact(b"synthetic malformed XZ", &mut output, 1 << 20).unwrap_err();
        assert_eq!(error, XzError::Malformed);
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(!format!("{error:?} {error}").contains("synthetic"));
    }

    #[test]
    fn rejects_a_successful_stream_with_the_wrong_declared_output_size() {
        const EMPTY_XZ: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x00, 0x00,
            0x00, 0x00, 0x1c, 0xdf, 0x44, 0x21, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x59, 0x5a,
        ];
        let mut output = [0xa5; 1];
        assert_eq!(
            decode_exact(EMPTY_XZ, &mut output, 1 << 20),
            Err(XzError::OutputSizeMismatch)
        );
        assert_eq!(output, [0]);
    }
}
