//! Bounded streaming parsers for archive formats used by Apple installer payloads.

use std::fmt;
use std::io::{self, Read};

const XZ_MAGIC: &[u8; 6] = b"\xfd7zXZ\0";
const MAX_PBZX_CHUNK_SIZE: u64 = 1 << 30;
const MAX_ARCHIVE_PATH_SIZE: usize = 1 << 20;

/// An archive parsing or streaming failure.
#[derive(Debug)]
pub enum Error {
    /// The underlying reader failed.
    Io(io::Error),
    /// A fixed-size value ended before all of its bytes were available.
    Truncated {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The input does not satisfy the named archive contract.
    Invalid(&'static str),
    /// A declared size is outside the parser's fixed safety bound.
    LimitExceeded {
        context: &'static str,
        size: u64,
        limit: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "archive input error: {error}"),
            Self::Truncated {
                context,
                expected,
                actual,
            } => write!(
                formatter,
                "truncated {context}: expected {expected} bytes, received {actual}"
            ),
            Self::Invalid(context) => write!(formatter, "invalid {context}"),
            Self::LimitExceeded {
                context,
                size,
                limit,
            } => write!(formatter, "{context} size {size} exceeds limit {limit}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Truncated { .. } | Self::Invalid(_) | Self::LimitExceeded { .. } => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn read_exact<R: Read + ?Sized>(
    reader: &mut R,
    target: &mut [u8],
    context: &'static str,
) -> Result<(), Error> {
    let mut offset = 0;
    while offset < target.len() {
        match reader.read(&mut target[offset..]) {
            Ok(0) => {
                return Err(Error::Truncated {
                    context,
                    expected: target.len(),
                    actual: offset,
                });
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(())
}

fn read_optional_exact<R: Read + ?Sized>(
    reader: &mut R,
    target: &mut [u8],
    context: &'static str,
) -> Result<bool, Error> {
    if target.is_empty() {
        return Ok(true);
    }

    let mut first = [0_u8; 1];
    loop {
        match reader.read(&mut first) {
            Ok(0) => return Ok(false),
            Ok(1) => break,
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    target[0] = first[0];
    read_exact(reader, &mut target[1..], context).map_err(|error| match error {
        Error::Truncated { actual, .. } => Error::Truncated {
            context,
            expected: target.len(),
            actual: actual + 1,
        },
        other => other,
    })?;
    Ok(true)
}

fn read_be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("validated fixed-width slice"))
}

fn read_le_integer(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .enumerate()
        .fold(0_u64, |value, (shift, byte)| {
            value | (u64::from(*byte) << (shift * 8))
        })
}

/// PBZX stream metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PbzxHeader {
    pub max_chunk_size: u64,
}

/// The encoding used by one PBZX chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PbzxEncoding {
    Raw,
    Xz,
}

/// Sizes and encoding declared by one PBZX chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PbzxChunkHeader {
    pub expanded_size: u64,
    pub archived_size: u64,
    pub encoding: PbzxEncoding,
}

/// A forward-only PBZX parser.
pub struct PbzxReader<R> {
    source: R,
    header: PbzxHeader,
    unread_payload: u64,
    chunk_open: bool,
}

impl<R: Read> PbzxReader<R> {
    /// Parse a PBZX stream header.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is truncated, has the wrong magic, or
    /// declares a zero or unreasonably large maximum chunk.
    pub fn new(mut source: R) -> Result<Self, Error> {
        let mut bytes = [0_u8; 12];
        read_exact(&mut source, &mut bytes, "PBZX header")?;
        if &bytes[..4] != b"pbzx" {
            return Err(Error::Invalid("PBZX magic"));
        }
        let max_chunk_size = read_be_u64(&bytes[4..]);
        if max_chunk_size == 0 || max_chunk_size > MAX_PBZX_CHUNK_SIZE {
            return Err(Error::LimitExceeded {
                context: "PBZX maximum chunk",
                size: max_chunk_size,
                limit: MAX_PBZX_CHUNK_SIZE,
            });
        }
        Ok(Self {
            source,
            header: PbzxHeader { max_chunk_size },
            unread_payload: 0,
            chunk_open: false,
        })
    }

    /// Return stream metadata.
    #[must_use]
    pub const fn header(&self) -> PbzxHeader {
        self.header
    }

    /// Begin the next chunk, or return `None` at a clean stream boundary.
    ///
    /// The previous chunk must be consumed or drained before calling this.
    ///
    /// # Errors
    ///
    /// Returns an error for an unconsumed prior chunk, a truncated or invalid
    /// header or payload prefix, an unsupported compression kind, or a size
    /// outside the declared and fixed safety bounds.
    pub fn next_chunk(&mut self) -> Result<Option<PbzxChunk<'_, R>>, Error> {
        if self.chunk_open {
            return Err(Error::Invalid("unconsumed PBZX chunk"));
        }

        let mut bytes = [0_u8; 16];
        if !read_optional_exact(&mut self.source, &mut bytes, "PBZX chunk header")? {
            return Ok(None);
        }
        let expanded_size = read_be_u64(&bytes[..8]);
        let archived_size = read_be_u64(&bytes[8..]);
        if expanded_size > self.header.max_chunk_size {
            return Err(Error::LimitExceeded {
                context: "PBZX expanded chunk",
                size: expanded_size,
                limit: self.header.max_chunk_size,
            });
        }
        if archived_size > MAX_PBZX_CHUNK_SIZE {
            return Err(Error::LimitExceeded {
                context: "PBZX archived chunk",
                size: archived_size,
                limit: MAX_PBZX_CHUNK_SIZE,
            });
        }

        let prefix_length = usize::try_from(archived_size.min(XZ_MAGIC.len() as u64))
            .map_err(|_| Error::Invalid("PBZX chunk prefix size"))?;
        let mut prefix = [0_u8; 6];
        read_exact(
            &mut self.source,
            &mut prefix[..prefix_length],
            "PBZX chunk payload",
        )?;
        self.unread_payload = archived_size - prefix_length as u64;
        self.chunk_open = archived_size != 0;

        let encoding = if prefix_length == XZ_MAGIC.len() && &prefix == XZ_MAGIC {
            PbzxEncoding::Xz
        } else if archived_size == expanded_size {
            PbzxEncoding::Raw
        } else {
            return Err(Error::Invalid("PBZX chunk compression"));
        };
        let header = PbzxChunkHeader {
            expanded_size,
            archived_size,
            encoding,
        };
        Ok(Some(PbzxChunk {
            parent: self,
            header,
            prefix,
            prefix_length,
            prefix_position: 0,
        }))
    }
}

/// A bounded reader over one PBZX chunk's archived bytes.
pub struct PbzxChunk<'a, R> {
    parent: &'a mut PbzxReader<R>,
    header: PbzxChunkHeader,
    prefix: [u8; 6],
    prefix_length: usize,
    prefix_position: usize,
}

impl<R> PbzxChunk<'_, R> {
    /// Return this chunk's parsed metadata.
    #[must_use]
    pub const fn header(&self) -> PbzxChunkHeader {
        self.header
    }

    /// Return the number of archived bytes still exposed by this reader.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        (self.prefix_length - self.prefix_position) as u64 + self.parent.unread_payload
    }
}

impl<R: Read> PbzxChunk<'_, R> {
    /// Consume and discard all remaining archived bytes in this chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying payload is truncated or cannot be read.
    pub fn drain(mut self) -> Result<(), Error> {
        let mut scratch = [0_u8; 8192];
        while self.remaining() != 0 {
            let count = self.read(&mut scratch).map_err(Error::Io)?;
            if count == 0 {
                return Err(Error::Truncated {
                    context: "PBZX chunk payload",
                    expected: usize::try_from(self.remaining()).unwrap_or(usize::MAX),
                    actual: 0,
                });
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for PbzxChunk<'_, R> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        if self.prefix_position < self.prefix_length {
            let count = target.len().min(self.prefix_length - self.prefix_position);
            target[..count]
                .copy_from_slice(&self.prefix[self.prefix_position..self.prefix_position + count]);
            self.prefix_position += count;
            if self.remaining() == 0 {
                self.parent.chunk_open = false;
            }
            return Ok(count);
        }
        if self.parent.unread_payload == 0 {
            return Ok(0);
        }
        let limit = usize::try_from(self.parent.unread_payload)
            .unwrap_or(usize::MAX)
            .min(target.len());
        let count = self.parent.source.read(&mut target[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated PBZX chunk payload",
            ));
        }
        self.parent.unread_payload -= count as u64;
        if self.remaining() == 0 {
            self.parent.chunk_open = false;
        }
        Ok(count)
    }
}

/// Apple Archive entry magic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppleArchiveMagic {
    Yaa1,
    Aa01,
}

/// The value encoded by an Apple Archive header field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppleArchiveValue {
    Flag,
    Unsigned(u64),
    Bytes(Vec<u8>),
    Blob(u64),
}

/// One Apple Archive header field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleArchiveField {
    pub key: [u8; 3],
    pub value: AppleArchiveValue,
}

/// One parsed Apple Archive entry header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleArchiveEntry {
    pub magic: AppleArchiveMagic,
    pub fields: Vec<AppleArchiveField>,
}

impl AppleArchiveEntry {
    /// Find the last field with `key`, matching the reference parser's map behavior.
    #[must_use]
    pub fn field(&self, key: &[u8; 3]) -> Option<&AppleArchiveValue> {
        self.fields
            .iter()
            .rev()
            .find(|field| &field.key == key)
            .map(|field| &field.value)
    }

    /// Iterate over blob fields in payload order.
    pub fn blobs(&self) -> impl Iterator<Item = (&[u8; 3], u64)> {
        self.fields.iter().filter_map(|field| match field.value {
            AppleArchiveValue::Blob(size) => Some((&field.key, size)),
            _ => None,
        })
    }
}

/// Parse one YAA1/AA01 entry header, or return `None` at a clean boundary.
///
/// Blob payloads immediately following the header remain unread for the caller.
///
/// # Errors
///
/// Returns an error when the header is truncated, has invalid magic or size,
/// or contains a malformed or unsupported field.
pub fn read_apple_archive_entry<R: Read + ?Sized>(
    reader: &mut R,
) -> Result<Option<AppleArchiveEntry>, Error> {
    let mut prefix = [0_u8; 6];
    if !read_optional_exact(reader, &mut prefix, "Apple Archive header")? {
        return Ok(None);
    }
    let magic = match &prefix[..4] {
        b"YAA1" => AppleArchiveMagic::Yaa1,
        b"AA01" => AppleArchiveMagic::Aa01,
        _ => return Err(Error::Invalid("Apple Archive magic")),
    };
    let header_size = usize::from(u16::from_le_bytes([prefix[4], prefix[5]]));
    if header_size < prefix.len() {
        return Err(Error::Invalid("Apple Archive header size"));
    }
    let mut header = vec![0_u8; header_size];
    header[..prefix.len()].copy_from_slice(&prefix);
    read_exact(reader, &mut header[prefix.len()..], "Apple Archive header")?;

    let mut fields = Vec::new();
    let mut position = prefix.len();
    while position < header.len() {
        let field_header = take(&header, &mut position, 4, "Apple Archive field header")?;
        if !field_header[..3].is_ascii() {
            return Err(Error::Invalid("Apple Archive field key"));
        }
        let key = [field_header[0], field_header[1], field_header[2]];
        let subtype = field_header[3];
        let value = match subtype {
            b'*' => AppleArchiveValue::Flag,
            b'1' => AppleArchiveValue::Unsigned(read_le_integer(take(
                &header,
                &mut position,
                1,
                "Apple Archive integer field",
            )?)),
            b'2' => AppleArchiveValue::Unsigned(read_le_integer(take(
                &header,
                &mut position,
                2,
                "Apple Archive integer field",
            )?)),
            b'4' => AppleArchiveValue::Unsigned(read_le_integer(take(
                &header,
                &mut position,
                4,
                "Apple Archive integer field",
            )?)),
            b'8' => AppleArchiveValue::Unsigned(read_le_integer(take(
                &header,
                &mut position,
                8,
                "Apple Archive integer field",
            )?)),
            b'A' => AppleArchiveValue::Blob(read_le_integer(take(
                &header,
                &mut position,
                2,
                "Apple Archive blob field",
            )?)),
            b'B' => AppleArchiveValue::Blob(read_le_integer(take(
                &header,
                &mut position,
                4,
                "Apple Archive blob field",
            )?)),
            b'C' => AppleArchiveValue::Blob(read_le_integer(take(
                &header,
                &mut position,
                8,
                "Apple Archive blob field",
            )?)),
            b'P' => {
                let size_bytes = take(&header, &mut position, 2, "Apple Archive string length")?;
                let size = usize::from(u16::from_le_bytes([size_bytes[0], size_bytes[1]]));
                AppleArchiveValue::Bytes(
                    take(&header, &mut position, size, "Apple Archive string field")?.to_vec(),
                )
            }
            b'F' => fixed_bytes(&header, &mut position, 4)?,
            b'G' => fixed_bytes(&header, &mut position, 20)?,
            b'H' => fixed_bytes(&header, &mut position, 32)?,
            b'I' => fixed_bytes(&header, &mut position, 48)?,
            b'J' => fixed_bytes(&header, &mut position, 64)?,
            b'S' => fixed_bytes(&header, &mut position, 8)?,
            b'T' => fixed_bytes(&header, &mut position, 12)?,
            _ => return Err(Error::Invalid("Apple Archive field subtype")),
        };
        fields.push(AppleArchiveField { key, value });
    }

    Ok(Some(AppleArchiveEntry { magic, fields }))
}

fn take<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    length: usize,
    context: &'static str,
) -> Result<&'a [u8], Error> {
    let end = position
        .checked_add(length)
        .ok_or(Error::Invalid("Apple Archive field length overflow"))?;
    let value = bytes.get(*position..end).ok_or(Error::Truncated {
        context,
        expected: length,
        actual: bytes.len().saturating_sub(*position),
    })?;
    *position = end;
    Ok(value)
}

fn fixed_bytes(
    header: &[u8],
    position: &mut usize,
    length: usize,
) -> Result<AppleArchiveValue, Error> {
    Ok(AppleArchiveValue::Bytes(
        take(header, position, length, "Apple Archive fixed field")?.to_vec(),
    ))
}

/// CPIO wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpioFormat {
    Newc,
    Crc,
    Odc,
}

/// Metadata for one CPIO archive entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpioEntryHeader {
    pub format: CpioFormat,
    pub path: Vec<u8>,
    pub mode: u32,
    pub file_size: u64,
    pub checksum: Option<u32>,
}

impl CpioEntryHeader {
    /// Return whether this entry is the archive trailer.
    #[must_use]
    pub fn is_trailer(&self) -> bool {
        self.path == b"TRAILER!!!"
    }

    /// Return whether the mode identifies a regular file.
    #[must_use]
    pub const fn is_regular_file(&self) -> bool {
        self.mode & 0o170_000 == 0o100_000
    }
}

/// A forward-only parser for one CPIO stream.
pub struct CpioReader<R> {
    source: R,
    format: CpioFormat,
    pending_magic: Option<[u8; 6]>,
    unread_data: u64,
    padding: u64,
    expected_checksum: Option<u32>,
    observed_checksum: u32,
    finished: bool,
}

impl<R: Read> CpioReader<R> {
    /// Detect the CPIO format from the first header and create a parser.
    ///
    /// # Errors
    ///
    /// Returns an error when the magic is truncated or does not identify a
    /// supported newc, CRC, or odc stream.
    pub fn new(mut source: R) -> Result<Self, Error> {
        let mut magic = [0_u8; 6];
        read_exact(&mut source, &mut magic, "CPIO magic")?;
        let format = match &magic {
            b"070701" => CpioFormat::Newc,
            b"070702" => CpioFormat::Crc,
            b"070707" => CpioFormat::Odc,
            _ => return Err(Error::Invalid("CPIO magic")),
        };
        Ok(Self {
            source,
            format,
            pending_magic: Some(magic),
            unread_data: 0,
            padding: 0,
            expected_checksum: None,
            observed_checksum: 0,
            finished: false,
        })
    }
}

impl<R: Read> CpioReader<R> {
    /// Return the detected wire format.
    #[must_use]
    pub const fn format(&self) -> CpioFormat {
        self.format
    }

    /// Begin the next entry, or return `None` after `TRAILER!!!`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unconsumed prior entry, failed CRC validation,
    /// truncation, malformed fields, or an oversized filename.
    pub fn next_entry(&mut self) -> Result<Option<CpioEntry<'_, R>>, Error> {
        self.finish_previous()?;
        if self.finished {
            return Ok(None);
        }

        let header = match self.format {
            CpioFormat::Newc | CpioFormat::Crc => self.read_newc_header()?,
            CpioFormat::Odc => self.read_odc_header()?,
        };
        self.unread_data = header.file_size;
        self.expected_checksum = header.checksum;
        self.observed_checksum = 0;
        self.finished = header.is_trailer();
        Ok(Some(CpioEntry {
            parent: self,
            header,
        }))
    }

    fn read_newc_header(&mut self) -> Result<CpioEntryHeader, Error> {
        let mut header = [0_u8; 110];
        if let Some(magic) = self.pending_magic.take() {
            header[..6].copy_from_slice(&magic);
            read_exact(&mut self.source, &mut header[6..], "newc CPIO header")?;
        } else {
            read_exact(&mut self.source, &mut header, "newc CPIO header")?;
        }
        let format = match &header[..6] {
            b"070701" => CpioFormat::Newc,
            b"070702" => CpioFormat::Crc,
            _ => return Err(Error::Invalid("newc CPIO magic")),
        };
        if format != self.format {
            return Err(Error::Invalid("mixed CPIO formats"));
        }
        let mut values = [0_u32; 13];
        for (index, value) in values.iter_mut().enumerate() {
            let start = 6 + index * 8;
            *value = parse_ascii_u32(&header[start..start + 8], 16, "newc CPIO integer")?;
        }
        let mode = values[1];
        let file_size = u64::from(values[6]);
        let name_size =
            usize::try_from(values[11]).map_err(|_| Error::Invalid("newc CPIO name size"))?;
        let path = read_cpio_path(&mut self.source, name_size, "newc CPIO filename")?;
        let name_padding = padding_4(
            110_usize
                .checked_add(name_size)
                .ok_or(Error::Invalid("newc CPIO header length overflow"))?,
        );
        skip_exact(
            &mut self.source,
            name_padding as u64,
            "newc CPIO name padding",
        )?;
        self.padding = padding_4_u64(file_size);
        let checksum = (format == CpioFormat::Crc).then_some(values[12]);
        Ok(CpioEntryHeader {
            format,
            path,
            mode,
            file_size,
            checksum,
        })
    }

    fn read_odc_header(&mut self) -> Result<CpioEntryHeader, Error> {
        let mut header = [0_u8; 76];
        if let Some(magic) = self.pending_magic.take() {
            header[..6].copy_from_slice(&magic);
            read_exact(&mut self.source, &mut header[6..], "odc CPIO header")?;
        } else {
            read_exact(&mut self.source, &mut header, "odc CPIO header")?;
        }
        if &header[..6] != b"070707" {
            return Err(Error::Invalid("odc CPIO magic"));
        }
        let mode = parse_ascii_u32(&header[18..24], 8, "odc CPIO mode")?;
        let name_size = usize::try_from(parse_ascii_u32(&header[59..65], 8, "odc CPIO name size")?)
            .map_err(|_| Error::Invalid("odc CPIO name size"))?;
        let file_size = parse_ascii_u64(&header[65..76], 8, "odc CPIO file size")?;
        let path = read_cpio_path(&mut self.source, name_size, "odc CPIO filename")?;
        self.padding = 0;
        Ok(CpioEntryHeader {
            format: CpioFormat::Odc,
            path,
            mode,
            file_size,
            checksum: None,
        })
    }

    fn finish_previous(&mut self) -> Result<(), Error> {
        if self.unread_data != 0 {
            return Err(Error::Invalid("unconsumed CPIO entry"));
        }
        if let Some(expected) = self.expected_checksum.take()
            && expected != self.observed_checksum
        {
            return Err(Error::Invalid("CRC CPIO checksum"));
        }
        if self.padding != 0 {
            skip_exact(&mut self.source, self.padding, "newc CPIO data padding")?;
            self.padding = 0;
        }
        Ok(())
    }
}

/// A bounded reader over one CPIO entry's data.
pub struct CpioEntry<'a, R> {
    parent: &'a mut CpioReader<R>,
    header: CpioEntryHeader,
}

impl<R> CpioEntry<'_, R> {
    /// Return this entry's parsed metadata.
    #[must_use]
    pub const fn header(&self) -> &CpioEntryHeader {
        &self.header
    }

    /// Return the number of unread data bytes.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.parent.unread_data
    }
}

impl<R: Read> CpioEntry<'_, R> {
    /// Consume the rest of the entry, validate its checksum, and skip its padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is truncated, cannot be read, or has a
    /// checksum that does not match its CRC header.
    pub fn drain(mut self) -> Result<(), Error> {
        let mut scratch = [0_u8; 8192];
        while self.remaining() != 0 {
            let count = self.read(&mut scratch).map_err(Error::Io)?;
            if count == 0 {
                return Err(Error::Truncated {
                    context: "CPIO entry data",
                    expected: usize::try_from(self.remaining()).unwrap_or(usize::MAX),
                    actual: 0,
                });
            }
        }
        self.parent.finish_previous()
    }
}

impl<R: Read> Read for CpioEntry<'_, R> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() || self.parent.unread_data == 0 {
            return Ok(0);
        }
        let limit = usize::try_from(self.parent.unread_data)
            .unwrap_or(usize::MAX)
            .min(target.len());
        let count = self.parent.source.read(&mut target[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated CPIO entry data",
            ));
        }
        self.parent.unread_data -= count as u64;
        if self.parent.expected_checksum.is_some() {
            self.parent.observed_checksum = target[..count]
                .iter()
                .fold(self.parent.observed_checksum, |sum, byte| {
                    sum.wrapping_add(u32::from(*byte))
                });
        }
        Ok(count)
    }
}

fn read_cpio_path<R: Read + ?Sized>(
    reader: &mut R,
    size: usize,
    context: &'static str,
) -> Result<Vec<u8>, Error> {
    if size == 0 {
        return Err(Error::Invalid("CPIO filename size"));
    }
    if size > MAX_ARCHIVE_PATH_SIZE {
        return Err(Error::LimitExceeded {
            context: "CPIO filename",
            size: size as u64,
            limit: MAX_ARCHIVE_PATH_SIZE as u64,
        });
    }
    let mut path = vec![0_u8; size];
    read_exact(reader, &mut path, context)?;
    if path.pop() != Some(0) || path.contains(&0) {
        return Err(Error::Invalid("NUL-terminated CPIO filename"));
    }
    Ok(path)
}

fn parse_ascii_u32(bytes: &[u8], radix: u32, context: &'static str) -> Result<u32, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid(context))?;
    u32::from_str_radix(text, radix).map_err(|_| Error::Invalid(context))
}

fn parse_ascii_u64(bytes: &[u8], radix: u32, context: &'static str) -> Result<u64, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid(context))?;
    u64::from_str_radix(text, radix).map_err(|_| Error::Invalid(context))
}

const fn padding_4(size: usize) -> usize {
    size.wrapping_neg() & 3
}

const fn padding_4_u64(size: u64) -> u64 {
    size.wrapping_neg() & 3
}

fn skip_exact<R: Read + ?Sized>(
    reader: &mut R,
    mut size: u64,
    context: &'static str,
) -> Result<(), Error> {
    let mut scratch = [0_u8; 8192];
    while size != 0 {
        let count = usize::try_from(size)
            .unwrap_or(usize::MAX)
            .min(scratch.len());
        read_exact(reader, &mut scratch[..count], context)?;
        size -= count as u64;
    }
    Ok(())
}

/// Validate that an archive path is a non-empty relative POSIX path.
///
/// `.` components are accepted because CPIO archives commonly use `./name`.
/// Absolute paths, parent traversal, NUL bytes, and paths resolving only to `.`
/// are rejected. Filesystem extraction must additionally avoid following
/// attacker-controlled symlinks below its selected output directory.
///
/// # Errors
///
/// Returns an error when `path` is empty, absolute, contains a NUL or parent
/// traversal component, or resolves only to current-directory components.
pub fn validate_relative_output_path(path: &[u8]) -> Result<(), Error> {
    if path.is_empty() || path[0] == b'/' || path.contains(&0) {
        return Err(Error::Invalid("archive output path"));
    }
    let mut useful_component = false;
    for component in path.split(|byte| *byte == b'/') {
        if component == b".." {
            return Err(Error::Invalid("archive parent traversal"));
        }
        if !component.is_empty() && component != b"." {
            useful_component = true;
        }
    }
    if !useful_component {
        return Err(Error::Invalid("archive output path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    fn pbzx(chunks: &[(u64, &[u8])]) -> Vec<u8> {
        let mut bytes = b"pbzx".to_vec();
        bytes.extend_from_slice(&64_u64.to_be_bytes());
        for (expanded, archived) in chunks {
            bytes.extend_from_slice(&expanded.to_be_bytes());
            bytes.extend_from_slice(&(archived.len() as u64).to_be_bytes());
            bytes.extend_from_slice(archived);
        }
        bytes
    }

    fn apple_header(magic: &[u8], fields: &[u8]) -> Vec<u8> {
        let size = u16::try_from(6 + fields.len()).expect("test header fits");
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(fields);
        bytes
    }

    fn newc_entry(format: CpioFormat, path: &[u8], mode: u32, data: &[u8]) -> Vec<u8> {
        let magic = match format {
            CpioFormat::Newc => b"070701".as_slice(),
            CpioFormat::Crc => b"070702".as_slice(),
            CpioFormat::Odc => panic!("wrong test builder"),
        };
        let checksum = data
            .iter()
            .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        let values = [
            1,
            mode,
            0,
            0,
            1,
            0,
            u32::try_from(data.len()).expect("test data fits"),
            0,
            0,
            0,
            0,
            u32::try_from(path.len() + 1).expect("test path fits"),
            if format == CpioFormat::Crc {
                checksum
            } else {
                0
            },
        ];
        let mut bytes = magic.to_vec();
        for value in values {
            bytes.extend_from_slice(format!("{value:08x}").as_bytes());
        }
        bytes.extend_from_slice(path);
        bytes.push(0);
        bytes.resize(bytes.len() + padding_4(bytes.len()), 0);
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len() + padding_4(data.len()), 0);
        bytes
    }

    fn odc_entry(path: &[u8], mode: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = format!(
            "070707{:06o}{:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            path.len() + 1,
            data.len()
        )
        .into_bytes();
        assert_eq!(bytes.len(), 76);
        bytes.extend_from_slice(path);
        bytes.push(0);
        bytes.extend_from_slice(data);
        bytes
    }

    #[test]
    fn pbzx_streams_raw_chunks_without_overread() {
        let bytes = pbzx(&[(3, b"one"), (3, b"two")]);
        let mut reader = PbzxReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.header().max_chunk_size, 64);

        let mut first = reader.next_chunk().unwrap().unwrap();
        assert_eq!(first.header().encoding, PbzxEncoding::Raw);
        let mut output = Vec::new();
        first.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"one");
        let second = reader.next_chunk().unwrap().unwrap();
        assert_eq!(second.header().archived_size, 3);
        second.drain().unwrap();
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn pbzx_classifies_xz_without_decompressing_it() {
        let mut archived = XZ_MAGIC.to_vec();
        archived.extend_from_slice(b"opaque compressed bytes");
        let bytes = pbzx(&[(63, &archived)]);
        let mut reader = PbzxReader::new(Cursor::new(bytes)).unwrap();
        let mut chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk.header().encoding, PbzxEncoding::Xz);
        let mut output = Vec::new();
        chunk.read_to_end(&mut output).unwrap();
        assert_eq!(output, archived);
    }

    #[test]
    fn pbzx_rejects_truncation_unknown_compression_and_size_overflow() {
        let error = PbzxReader::new(Cursor::new(b"pbzx\0".as_slice()))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Truncated { .. }));

        let bytes = pbzx(&[(20, b"short")]);
        let mut reader = PbzxReader::new(Cursor::new(bytes)).unwrap();
        assert!(matches!(
            reader.next_chunk(),
            Err(Error::Invalid("PBZX chunk compression"))
        ));

        let mut oversized = b"pbzx".to_vec();
        oversized.extend_from_slice(&(MAX_PBZX_CHUNK_SIZE + 1).to_be_bytes());
        assert!(matches!(
            PbzxReader::new(Cursor::new(oversized)),
            Err(Error::LimitExceeded { .. })
        ));

        let mut truncated_payload = pbzx(&[(8, b"12345678")]);
        truncated_payload.pop();
        let mut reader = PbzxReader::new(Cursor::new(truncated_payload)).unwrap();
        let error = reader.next_chunk().unwrap().unwrap().drain().unwrap_err();
        assert!(matches!(
            error,
            Error::Io(ref source) if source.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn apple_archive_parses_reference_field_layouts() {
        let mut fields = Vec::new();
        fields.extend_from_slice(b"PATP");
        fields.extend_from_slice(&9_u16.to_le_bytes());
        fields.extend_from_slice(b"usr/share");
        fields.extend_from_slice(b"TYP1M");
        fields.extend_from_slice(b"DATB");
        fields.extend_from_slice(&4_u32.to_le_bytes());
        fields.extend_from_slice(b"FLG*");
        fields.extend_from_slice(b"IDX8");
        fields.extend_from_slice(&42_u64.to_le_bytes());
        fields.extend_from_slice(b"HSHF");
        fields.extend_from_slice(b"hash");
        let bytes = apple_header(b"YAA1", &fields);

        let entry = read_apple_archive_entry(&mut Cursor::new(bytes))
            .unwrap()
            .unwrap();
        assert_eq!(entry.magic, AppleArchiveMagic::Yaa1);
        assert_eq!(
            entry.field(b"PAT"),
            Some(&AppleArchiveValue::Bytes(b"usr/share".to_vec()))
        );
        assert_eq!(entry.field(b"TYP"), Some(&AppleArchiveValue::Unsigned(77)));
        assert_eq!(entry.blobs().collect::<Vec<_>>(), vec![(b"DAT", 4)]);
        assert_eq!(entry.field(b"FLG"), Some(&AppleArchiveValue::Flag));
        assert_eq!(entry.field(b"IDX"), Some(&AppleArchiveValue::Unsigned(42)));
    }

    #[test]
    fn apple_archive_accepts_aa01_and_rejects_malformed_headers() {
        let bytes = apple_header(b"AA01", b"");
        let entry = read_apple_archive_entry(&mut Cursor::new(bytes))
            .unwrap()
            .unwrap();
        assert_eq!(entry.magic, AppleArchiveMagic::Aa01);

        let bad_size = [b'Y', b'A', b'A', b'1', 5, 0];
        assert!(matches!(
            read_apple_archive_entry(&mut Cursor::new(bad_size)),
            Err(Error::Invalid("Apple Archive header size"))
        ));

        let truncated_field = apple_header(b"YAA1", b"PATP\x04\0x");
        assert!(matches!(
            read_apple_archive_entry(&mut Cursor::new(truncated_field)),
            Err(Error::Truncated { .. })
        ));
        let unknown = apple_header(b"YAA1", b"BADZ");
        assert!(matches!(
            read_apple_archive_entry(&mut Cursor::new(unknown)),
            Err(Error::Invalid("Apple Archive field subtype"))
        ));
    }

    #[test]
    fn newc_streams_entries_and_observes_padding() {
        let mut bytes = newc_entry(CpioFormat::Newc, b"./etc/item", 0o100_644, b"abc");
        bytes.extend_from_slice(&newc_entry(CpioFormat::Newc, b"TRAILER!!!", 0, b""));
        let mut reader = CpioReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.format(), CpioFormat::Newc);
        let mut entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.header().path, b"./etc/item");
        assert!(entry.header().is_regular_file());
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"abc");
        drop(entry);
        let trailer = reader.next_entry().unwrap().unwrap();
        assert!(trailer.header().is_trailer());
        trailer.drain().unwrap();
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn crc_cpio_validates_checksum_after_streaming() {
        let mut bytes = newc_entry(CpioFormat::Crc, b"record", 0o100_600, b"value");
        bytes.extend_from_slice(&newc_entry(CpioFormat::Crc, b"TRAILER!!!", 0, b""));
        let mut reader = CpioReader::new(Cursor::new(bytes.clone())).unwrap();
        reader.next_entry().unwrap().unwrap().drain().unwrap();
        assert!(reader.next_entry().is_ok());

        let data_offset = bytes.windows(5).position(|part| part == b"value").unwrap();
        bytes[data_offset] ^= 1;
        let mut reader = CpioReader::new(Cursor::new(bytes)).unwrap();
        let error = reader.next_entry().unwrap().unwrap().drain().unwrap_err();
        assert!(matches!(error, Error::Invalid("CRC CPIO checksum")));
    }

    #[test]
    fn odc_parses_reference_layout_without_alignment_padding() {
        let mut bytes = odc_entry(b"directory/file", 0o100_644, b"payload");
        bytes.extend_from_slice(&odc_entry(b"TRAILER!!!", 0, b""));
        let mut reader = CpioReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.format(), CpioFormat::Odc);
        let mut entry = reader.next_entry().unwrap().unwrap();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        assert_eq!(entry.header().path, b"directory/file");
        assert_eq!(data, b"payload");
        drop(entry);
        assert!(reader.next_entry().unwrap().unwrap().header().is_trailer());
    }

    #[test]
    fn cpio_rejects_truncation_bad_numbers_and_oversized_names() {
        assert!(matches!(
            CpioReader::new(Cursor::new(b"0707".as_slice())),
            Err(Error::Truncated { .. })
        ));

        let mut bad = newc_entry(CpioFormat::Newc, b"name", 0o100_644, b"");
        bad[6] = b'g';
        let mut reader = CpioReader::new(Cursor::new(bad)).unwrap();
        assert!(matches!(
            reader.next_entry(),
            Err(Error::Invalid("newc CPIO integer"))
        ));

        let mut huge = newc_entry(CpioFormat::Newc, b"name", 0o100_644, b"");
        huge[94..102].copy_from_slice(b"00100001");
        let mut reader = CpioReader::new(Cursor::new(huge)).unwrap();
        assert!(matches!(
            reader.next_entry(),
            Err(Error::LimitExceeded { .. })
        ));

        let mut truncated_data = newc_entry(CpioFormat::Newc, b"name", 0o100_644, b"data");
        truncated_data.truncate(truncated_data.len() - 3);
        let mut reader = CpioReader::new(Cursor::new(truncated_data)).unwrap();
        let error = reader.next_entry().unwrap().unwrap().drain().unwrap_err();
        assert!(matches!(
            error,
            Error::Io(ref source) if source.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn safe_relative_paths_reject_archive_traversal() {
        for safe in [b"file".as_slice(), b"./dir/file", b"dir//file"] {
            assert!(validate_relative_output_path(safe).is_ok(), "{safe:?}");
        }
        for unsafe_path in [
            b"".as_slice(),
            b"/absolute",
            b"../escape",
            b"dir/../../escape",
            b".",
            b"./",
            b"nul\0byte",
        ] {
            assert!(
                validate_relative_output_path(unsafe_path).is_err(),
                "{unsafe_path:?}"
            );
        }
    }

    #[test]
    fn readers_refuse_to_advance_past_unconsumed_payloads() {
        let bytes = pbzx(&[(3, b"one"), (3, b"two")]);
        let mut reader = PbzxReader::new(Cursor::new(bytes)).unwrap();
        {
            let _chunk = reader.next_chunk().unwrap().unwrap();
        }
        assert!(matches!(
            reader.next_chunk(),
            Err(Error::Invalid("unconsumed PBZX chunk"))
        ));

        let bytes = newc_entry(CpioFormat::Newc, b"file", 0o100_644, b"data");
        let mut reader = CpioReader::new(Cursor::new(bytes)).unwrap();
        let entry = reader.next_entry().unwrap().unwrap();
        drop(entry);
        assert!(matches!(
            reader.next_entry(),
            Err(Error::Invalid("unconsumed CPIO entry"))
        ));
    }
}
