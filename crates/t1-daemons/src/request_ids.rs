//! Linux request identifiers sourced from kernel randomness.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use t1_bridge::control::RequestIdSource;
use t1_bridge::rpc::RequestId;

const REQUEST_ID_RANDOM_BYTES: usize = 16;
const KERNEL_RANDOM_DEVICE: &str = "/dev/urandom";

// Linux UAPI value. `OpenOptionsExt::custom_flags` is the safe standard-library
// route for applying close-on-exec atomically during open.
const O_CLOEXEC: i32 = 0o20_00000;

/// A redaction-safe request-ID entropy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestIdError {
    /// The kernel random device could not be opened safely.
    RandomDeviceUnavailable,
    /// A complete fresh request identifier could not be read.
    EntropyUnavailable,
}

impl fmt::Display for RequestIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomDeviceUnavailable => {
                formatter.write_str("kernel request-ID entropy source is unavailable")
            }
            Self::EntropyUnavailable => {
                formatter.write_str("fresh request-ID entropy is unavailable")
            }
        }
    }
}

impl std::error::Error for RequestIdError {}

/// An owned, fail-closed source of random `BridgeXPC` request identifiers.
///
/// Any read failure permanently exhausts the source. Bytes consumed by a
/// partial failed read are discarded and the underlying reader is never
/// consulted again.
pub struct LinuxRequestIdSource<R> {
    reader: R,
    failure: Option<RequestIdError>,
}

impl<R> LinuxRequestIdSource<R> {
    /// Takes ownership of a caller-supplied entropy reader.
    ///
    /// Production callers should use [`LinuxRequestIdSource::open`]. This
    /// constructor exists so deterministic readers can be injected by tests
    /// and higher-level adapters.
    pub const fn new(reader: R) -> Self {
        Self {
            reader,
            failure: None,
        }
    }

    /// Reports the source's sticky redaction-safe failure, if any.
    #[must_use]
    pub const fn failure(&self) -> Option<RequestIdError> {
        self.failure
    }

    /// Returns ownership of the underlying reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl LinuxRequestIdSource<File> {
    /// Opens the Linux kernel random device with close-on-exec set atomically.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if the device cannot be opened.
    pub fn open() -> Result<Self, RequestIdError> {
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(O_CLOEXEC)
            .open(KERNEL_RANDOM_DEVICE)
            .map_err(|_| RequestIdError::RandomDeviceUnavailable)?;
        Ok(Self::new(reader))
    }
}

impl<R: Read> RequestIdSource for LinuxRequestIdSource<R> {
    fn next_request_id(&mut self) -> Option<RequestId> {
        if self.failure.is_some() {
            return None;
        }

        let mut bytes = [0_u8; REQUEST_ID_RANDOM_BYTES];
        if self.reader.read_exact(&mut bytes).is_err() {
            bytes.fill(0);
            self.failure = Some(RequestIdError::EntropyUnavailable);
            return None;
        }
        Some(RequestId::from_uuid_v4_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{self, Cursor};
    use std::rc::Rc;

    struct ScriptedReader {
        steps: Vec<ReadStep>,
        next_step: usize,
        calls: Rc<Cell<usize>>,
    }

    enum ReadStep {
        Bytes(Vec<u8>),
        Interrupted,
        Error(io::ErrorKind),
        SensitiveError,
        Eof,
    }

    impl ScriptedReader {
        fn new(steps: impl IntoIterator<Item = ReadStep>, calls: Rc<Cell<usize>>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                next_step: 0,
                calls,
            }
        }
    }

    impl Read for ScriptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.calls.set(self.calls.get() + 1);
            let step = self.steps.get(self.next_step).expect("scripted read step");
            self.next_step += 1;
            match step {
                ReadStep::Bytes(bytes) => {
                    assert!(bytes.len() <= buffer.len(), "scripted chunk fits buffer");
                    buffer[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                }
                ReadStep::Interrupted => Err(io::Error::from(io::ErrorKind::Interrupted)),
                ReadStep::Error(kind) => Err(io::Error::from(*kind)),
                ReadStep::SensitiveError => Err(io::Error::other(
                    "private entropy-source detail and consumed bytes",
                )),
                ReadStep::Eof => Ok(0),
            }
        }
    }

    fn bytes(start: u8, count: usize) -> Vec<u8> {
        (0..count)
            .map(|offset| start.wrapping_add(u8::try_from(offset).unwrap()))
            .collect()
    }

    #[test]
    fn reads_exactly_sixteen_fresh_bytes_per_identifier() {
        let entropy = bytes(0, 32);
        let mut source = LinuxRequestIdSource::new(Cursor::new(entropy));

        let first = source.next_request_id().unwrap();
        let second = source.next_request_id().unwrap();

        assert_eq!(first.as_str(), "00010203-0405-4607-8809-0A0B0C0D0E0F");
        assert_eq!(second.as_str(), "10111213-1415-4617-9819-1A1B1C1D1E1F");
        assert_ne!(first, second);
        assert_eq!(source.into_inner().position(), 32);
    }

    #[test]
    fn interrupted_reads_retry_without_losing_or_reusing_bytes() {
        let calls = Rc::new(Cell::new(0));
        let reader = ScriptedReader::new(
            [
                ReadStep::Interrupted,
                ReadStep::Bytes(bytes(0x20, 5)),
                ReadStep::Interrupted,
                ReadStep::Bytes(bytes(0x25, 11)),
            ],
            Rc::clone(&calls),
        );
        let mut source = LinuxRequestIdSource::new(reader);

        let request_id = source.next_request_id().unwrap();

        assert_eq!(request_id.as_str(), "20212223-2425-4627-A829-2A2B2C2D2E2F");
        assert_eq!(calls.get(), 4);
        assert_eq!(source.failure(), None);
    }

    #[test]
    fn short_entropy_is_a_sticky_failure() {
        let calls = Rc::new(Cell::new(0));
        let reader = ScriptedReader::new(
            [ReadStep::Bytes(bytes(0x30, 15)), ReadStep::Eof],
            Rc::clone(&calls),
        );
        let mut source = LinuxRequestIdSource::new(reader);

        assert!(source.next_request_id().is_none());
        assert_eq!(source.failure(), Some(RequestIdError::EntropyUnavailable));
        let failed_calls = calls.get();
        assert!(source.next_request_id().is_none());
        assert!(source.next_request_id().is_none());
        assert_eq!(calls.get(), failed_calls);
    }

    #[test]
    fn reader_error_discards_partial_bytes_and_permanently_exhausts_source() {
        let calls = Rc::new(Cell::new(0));
        let reader = ScriptedReader::new(
            [
                ReadStep::Bytes(bytes(0x40, 8)),
                ReadStep::Error(io::ErrorKind::Other),
                ReadStep::Bytes(bytes(0x48, 8)),
            ],
            Rc::clone(&calls),
        );
        let mut source = LinuxRequestIdSource::new(reader);

        assert!(source.next_request_id().is_none());
        assert_eq!(source.failure(), Some(RequestIdError::EntropyUnavailable));
        assert_eq!(calls.get(), 2);
        assert!(source.next_request_id().is_none());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn uuid_version_variant_and_canonical_format_are_forced() {
        for entropy in [[0_u8; 16], [u8::MAX; 16]] {
            let mut source = LinuxRequestIdSource::new(Cursor::new(entropy));
            let request_id = source.next_request_id().unwrap();
            let value = request_id.as_str().as_bytes();

            assert_eq!(value.len(), 36);
            assert_eq!(value[14], b'4');
            assert!(matches!(value[19], b'8' | b'9' | b'A' | b'B'));
            assert_eq!(&value[8..9], b"-");
            assert_eq!(&value[13..14], b"-");
            assert_eq!(&value[18..19], b"-");
            assert_eq!(&value[23..24], b"-");
        }
    }

    #[test]
    fn diagnostics_do_not_expose_io_details_or_entropy() {
        let calls = Rc::new(Cell::new(0));
        let reader = ScriptedReader::new([ReadStep::SensitiveError], calls);
        let mut source = LinuxRequestIdSource::new(reader);

        assert!(source.next_request_id().is_none());
        let error = source.failure().unwrap();
        let rendered = format!("{error} {error:?}");

        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("consumed bytes"));
        assert!(!rendered.contains("/dev/"));
        assert!(std::error::Error::source(&error).is_none());
    }
}
