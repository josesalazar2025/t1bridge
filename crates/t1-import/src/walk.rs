//! Bounded, read-only walking of reference-proven Apple payload containers.

use std::cell::Cell;
use std::fmt;
use std::io::{self, Read};

use t1_platform::xz::{self, MAX_XZ_MEMORY_LIMIT};

use crate::archive::{
    self, AppleArchiveValue, CpioReader, PbzxEncoding, PbzxReader, read_apple_archive_entry,
    validate_relative_output_path,
};
use crate::discovery::{MAX_FDR_DATA_SIZE, MAX_SOURCE_SIZE};

/// Maximum nested Apple Archive metadata depth.
pub const MAX_NESTING_DEPTH: usize = 8;
/// Maximum archive entries visited across one walk.
pub const MAX_WALK_ENTRIES: usize = 131_072;
/// Maximum Apple Archive fields visited across one walk.
pub const MAX_WALK_FIELDS: usize = 1_048_576;
/// Maximum raw PBZX chunks accepted in one PBZX stream.
pub const MAX_PBZX_CHUNKS: usize = 4_096;
/// Maximum raw PBZX chunk buffered while adapting chunks to a byte stream.
pub const MAX_BUFFERED_PBZX_CHUNK_SIZE: u64 = MAX_FDR_DATA_SIZE;

const PAT: &[u8; 3] = b"PAT";
const TYP: &[u8; 3] = b"TYP";
const YOP: &[u8; 3] = b"YOP";
const DAT: &[u8; 3] = b"DAT";
const METADATA_TYPE: u64 = b'M' as u64;
const EMBED_OPERATION: u64 = b'E' as u64;
const OVERLAY_OPERATION: u64 = b'O' as u64;

/// A payload-redacted container walk failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkError {
    /// Caller-supplied source size is empty or above the importer ceiling.
    InvalidSourceSize,
    /// The already-open reader failed; only its error kind is retained.
    Reader(io::ErrorKind),
    /// A supported container was structurally malformed.
    MalformedContainer,
    /// The top-level stream was neither PBZX nor Apple Archive.
    UnsupportedTopLevel,
    /// An Apple Archive metadata blob used an unproven nested format.
    UnsupportedNestedContainer,
    /// One bounded XZ PBZX chunk failed exact decompression.
    XzDecompression,
    /// A PBZX chunk or the cumulative expansion exceeded the walker's bounds.
    PbzxChunkLimit,
    /// Too many PBZX chunks were present in one stream.
    PbzxChunkCountLimit,
    /// Nested Apple Archive metadata exceeded the supported depth.
    NestingLimit,
    /// The global archive-entry budget was exhausted.
    EntryLimit,
    /// The global Apple Archive field budget was exhausted.
    FieldLimit,
    /// An archive entry path was absent, malformed, absolute, or traversing.
    UnsafePath,
    /// A selected CPIO entry was not a regular file.
    SelectedObjectNotRegular,
    /// A selected object exceeded the FDR object size ceiling.
    SelectedObjectTooLarge,
    /// A selected object allocation could not be reserved.
    AllocationFailed,
    /// More than one object matched the caller's selector.
    DuplicateSelectedObject,
    /// No data object matched the caller's selector.
    MissingSelectedObject,
    /// A child or top-level container stopped before consuming its exact input.
    UnreadPayload,
}

impl fmt::Display for WalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSourceSize => "import source size is invalid",
            Self::Reader(_) => "import source reader failed",
            Self::MalformedContainer => "import container is malformed",
            Self::UnsupportedTopLevel => "unsupported top-level import container",
            Self::UnsupportedNestedContainer => "unsupported nested import container",
            Self::XzDecompression => "PBZX XZ decompression failed",
            Self::PbzxChunkLimit => "PBZX chunk exceeds the walk buffer limit",
            Self::PbzxChunkCountLimit => "PBZX stream contains too many chunks",
            Self::NestingLimit => "import container nesting limit exceeded",
            Self::EntryLimit => "import archive entry limit exceeded",
            Self::FieldLimit => "Apple Archive field limit exceeded",
            Self::UnsafePath => "import archive contains an unsafe path",
            Self::SelectedObjectNotRegular => "selected CPIO object is not a regular file",
            Self::SelectedObjectTooLarge => "selected FDR object exceeds the size limit",
            Self::AllocationFailed => "selected FDR object allocation failed",
            Self::DuplicateSelectedObject => "multiple import objects matched the selection",
            Self::MissingSelectedObject => "selected import object was not found",
            Self::UnreadPayload => "import container left unread payload data",
        })
    }
}

impl std::error::Error for WalkError {}

/// Streams every safe AA/CPIO path through `selector` and returns one match.
///
/// `source_size` is the exact, already-validated size of the caller-owned
/// stream. The selector receives borrowed path bytes and decides matching; it
/// may implement exact, case-insensitive, or another caller-owned policy. The
/// walker never interprets a path as a regular expression.
///
/// Supported orders exactly mirror the private reference: top-level AA, PBZX
/// to AA or CPIO, nested AA to AA, and nested AA to PBZX to AA. PBZX chunks may
/// be raw or bounded XZ; nested CPIO is rejected without fallback.
///
/// # Errors
///
/// Returns a redaction-safe error for malformed or unsupported containers,
/// unsafe paths, exhausted bounds, duplicate/missing matches, reader failure,
/// or any child that does not consume its exact declared payload.
pub fn collect_fdr_object<R, S>(
    source: R,
    source_size: u64,
    mut selector: S,
) -> Result<Vec<u8>, WalkError>
where
    R: Read,
    S: FnMut(&[u8]) -> bool,
{
    collect_with_limits(source, source_size, &mut selector, Limits::production())
}

#[derive(Clone, Copy)]
struct Limits {
    source_bytes: u64,
    output_bytes: u64,
    nesting: usize,
    entries: usize,
    fields: usize,
    pbzx_chunks: usize,
    pbzx_chunk_bytes: u64,
    pbzx_expanded_bytes: u64,
}

impl Limits {
    const fn production() -> Self {
        Self {
            source_bytes: MAX_SOURCE_SIZE,
            output_bytes: MAX_FDR_DATA_SIZE,
            nesting: MAX_NESTING_DEPTH,
            entries: MAX_WALK_ENTRIES,
            fields: MAX_WALK_FIELDS,
            pbzx_chunks: MAX_PBZX_CHUNKS,
            pbzx_chunk_bytes: MAX_BUFFERED_PBZX_CHUNK_SIZE,
            pbzx_expanded_bytes: MAX_SOURCE_SIZE,
        }
    }
}

struct Budget {
    entries: Cell<usize>,
    fields: Cell<usize>,
    pbzx_expanded_bytes: Cell<u64>,
    limits: Limits,
}

impl Budget {
    const fn new(limits: Limits) -> Self {
        Self {
            entries: Cell::new(0),
            fields: Cell::new(0),
            pbzx_expanded_bytes: Cell::new(0),
            limits,
        }
    }

    fn entry(&self) -> Result<(), WalkError> {
        let entries = self
            .entries
            .get()
            .checked_add(1)
            .ok_or(WalkError::EntryLimit)?;
        if entries > self.limits.entries {
            return Err(WalkError::EntryLimit);
        }
        self.entries.set(entries);
        Ok(())
    }

    fn fields(&self, count: usize) -> Result<(), WalkError> {
        let fields = self
            .fields
            .get()
            .checked_add(count)
            .ok_or(WalkError::FieldLimit)?;
        if fields > self.limits.fields {
            return Err(WalkError::FieldLimit);
        }
        self.fields.set(fields);
        Ok(())
    }

    fn pbzx_expanded(&self, count: u64) -> Result<(), PbzxReadError> {
        let expanded = self
            .pbzx_expanded_bytes
            .get()
            .checked_add(count)
            .ok_or(PbzxReadError::ChunkLimit)?;
        if expanded > self.limits.pbzx_expanded_bytes {
            return Err(PbzxReadError::ChunkLimit);
        }
        self.pbzx_expanded_bytes.set(expanded);
        Ok(())
    }
}

struct Selection(Option<Vec<u8>>);

impl Selection {
    const fn new() -> Self {
        Self(None)
    }

    fn store(&mut self, mut bytes: Vec<u8>) -> Result<(), WalkError> {
        if self.0.is_some() {
            wipe_bytes(&mut bytes);
            return Err(WalkError::DuplicateSelectedObject);
        }
        self.0 = Some(bytes);
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, WalkError> {
        self.0.take().ok_or(WalkError::MissingSelectedObject)
    }
}

impl Drop for Selection {
    fn drop(&mut self) {
        if let Some(bytes) = self.0.as_mut() {
            wipe_bytes(bytes);
        }
    }
}

fn wipe_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
}

fn collect_with_limits<R, S>(
    source: R,
    source_size: u64,
    selector: &mut S,
    limits: Limits,
) -> Result<Vec<u8>, WalkError>
where
    R: Read,
    S: FnMut(&[u8]) -> bool,
{
    if source_size == 0 || source_size > limits.source_bytes {
        return Err(WalkError::InvalidSourceSize);
    }

    let mut source = ExactReader::new(source, source_size);
    let budget = Budget::new(limits);
    let mut selection = Selection::new();
    walk_top(&mut source, selector, &mut selection, &budget)?;
    if source.remaining() != 0 {
        return Err(WalkError::UnreadPayload);
    }
    selection.finish()
}

fn walk_top<S: FnMut(&[u8]) -> bool>(
    source: &mut dyn Read,
    selector: &mut S,
    selection: &mut Selection,
    budget: &Budget,
) -> Result<(), WalkError> {
    let prefix = read_prefix(source)?;
    let mut stream = PrefixedReader::new(prefix, source);
    match stream.prefix_magic() {
        b"pbzx" => walk_pbzx_top(&mut stream, selector, selection, budget),
        b"YAA1" | b"AA01" => walk_aa(&mut stream, 0, selector, selection, budget),
        _ => Err(WalkError::UnsupportedTopLevel),
    }
}

fn walk_pbzx_top<S: FnMut(&[u8]) -> bool>(
    source: &mut dyn Read,
    selector: &mut S,
    selection: &mut Selection,
    budget: &Budget,
) -> Result<(), WalkError> {
    let mut pbzx = RawPbzxReader::new(source, budget)?;
    let prefix = read_prefix(&mut pbzx)?;
    {
        let mut expanded = PrefixedReader::new(prefix, &mut pbzx);
        match expanded.prefix_magic() {
            b"YAA1" | b"AA01" => walk_aa(&mut expanded, 0, selector, selection, budget)?,
            magic if is_cpio_magic(*magic, expanded.prefix()) => {
                walk_cpio(&mut expanded, selector, selection, budget)?;
            }
            _ => return Err(WalkError::UnsupportedTopLevel),
        }
        ensure_eof(&mut expanded)?;
    }
    ensure_eof(&mut pbzx)
}

fn walk_aa<S: FnMut(&[u8]) -> bool>(
    source: &mut dyn Read,
    depth: usize,
    selector: &mut S,
    selection: &mut Selection,
    budget: &Budget,
) -> Result<(), WalkError> {
    loop {
        let Some(entry) = read_apple_archive_entry(source).map_err(map_archive_error)? else {
            return Ok(());
        };
        budget.entry()?;
        budget.fields(entry.fields.len())?;

        let path = match entry.field(PAT) {
            Some(AppleArchiveValue::Bytes(path)) => path.as_slice(),
            _ => return Err(WalkError::UnsafePath),
        };
        validate_relative_output_path(path).map_err(|_| WalkError::UnsafePath)?;
        let selected = selector(path);
        let nested = matches!(
            entry.field(TYP),
            Some(AppleArchiveValue::Unsigned(METADATA_TYPE))
        ) && matches!(
            entry.field(YOP),
            Some(AppleArchiveValue::Unsigned(
                EMBED_OPERATION | OVERLAY_OPERATION
            ))
        );

        for (key, size) in entry.blobs() {
            let mut blob = LimitedReader::new(source, size);
            if key == DAT && nested {
                if depth >= budget.limits.nesting {
                    return Err(WalkError::NestingLimit);
                }
                walk_nested(&mut blob, depth + 1, selector, selection, budget)?;
            } else if key == DAT && selected {
                let bytes = read_selected(&mut blob, size, budget.limits.output_bytes)?;
                selection.store(bytes)?;
            } else {
                drain(&mut blob)?;
            }
            if blob.remaining() != 0 {
                return Err(WalkError::UnreadPayload);
            }
        }
    }
}

fn walk_nested<S: FnMut(&[u8]) -> bool>(
    source: &mut dyn Read,
    depth: usize,
    selector: &mut S,
    selection: &mut Selection,
    budget: &Budget,
) -> Result<(), WalkError> {
    let prefix = read_prefix(source)?;
    let mut nested = PrefixedReader::new(prefix, source);
    match nested.prefix_magic() {
        b"YAA1" | b"AA01" => walk_aa(&mut nested, depth, selector, selection, budget)?,
        b"pbzx" => {
            let mut pbzx = RawPbzxReader::new(&mut nested, budget)?;
            let prefix = read_prefix(&mut pbzx)?;
            {
                let mut expanded = PrefixedReader::new(prefix, &mut pbzx);
                if !matches!(expanded.prefix_magic(), b"YAA1" | b"AA01") {
                    return Err(WalkError::UnsupportedNestedContainer);
                }
                walk_aa(&mut expanded, depth, selector, selection, budget)?;
                ensure_eof(&mut expanded)?;
            }
            ensure_eof(&mut pbzx)?;
        }
        _ => return Err(WalkError::UnsupportedNestedContainer),
    }
    ensure_eof(&mut nested)
}

fn walk_cpio<S: FnMut(&[u8]) -> bool>(
    source: &mut dyn Read,
    selector: &mut S,
    selection: &mut Selection,
    budget: &Budget,
) -> Result<(), WalkError> {
    {
        let mut cpio = CpioReader::new(&mut *source).map_err(map_archive_error)?;
        while let Some(mut entry) = cpio.next_entry().map_err(map_archive_error)? {
            budget.entry()?;
            if entry.header().is_trailer() {
                entry.drain().map_err(map_archive_error)?;
                continue;
            }
            validate_relative_output_path(&entry.header().path)
                .map_err(|_| WalkError::UnsafePath)?;
            let selected = selector(&entry.header().path);
            if selected && !entry.header().is_regular_file() {
                return Err(WalkError::SelectedObjectNotRegular);
            }
            if selected {
                let size = entry.header().file_size;
                let bytes = read_selected(&mut entry, size, budget.limits.output_bytes)?;
                selection.store(bytes)?;
                entry.drain().map_err(map_archive_error)?;
            } else {
                entry.drain().map_err(map_archive_error)?;
            }
        }
    }
    ensure_eof(source)
}

fn read_selected(reader: &mut dyn Read, size: u64, maximum: u64) -> Result<Vec<u8>, WalkError> {
    if size == 0 || size > maximum {
        return Err(WalkError::SelectedObjectTooLarge);
    }
    let size = usize::try_from(size).map_err(|_| WalkError::SelectedObjectTooLarge)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| WalkError::AllocationFailed)?;
    bytes.resize(size, 0);
    if let Err(error) = reader.read_exact(&mut bytes) {
        bytes.fill(0);
        return Err(map_io_error(error));
    }
    Ok(bytes)
}

fn drain(reader: &mut dyn Read) -> Result<(), WalkError> {
    let mut scratch = [0_u8; 8192];
    loop {
        match reader.read(&mut scratch) {
            Ok(0) => {
                scratch.fill(0);
                return Ok(());
            }
            Ok(_) => {}
            Err(error) => {
                scratch.fill(0);
                return Err(map_io_error(error));
            }
        }
    }
}

fn ensure_eof(reader: &mut dyn Read) -> Result<(), WalkError> {
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(WalkError::UnreadPayload),
        Err(error) => Err(map_io_error(error)),
    }
}

fn read_prefix(reader: &mut dyn Read) -> Result<Prefix, WalkError> {
    let mut bytes = [0_u8; 6];
    let mut len = 0;
    while len < bytes.len() {
        match reader.read(&mut bytes[len..]) {
            Ok(0) => break,
            Ok(count) => len += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(map_io_error(error)),
        }
    }
    if len < 4 {
        return Err(WalkError::MalformedContainer);
    }
    Ok(Prefix { bytes, len })
}

fn is_cpio_magic(magic: [u8; 4], prefix: &Prefix) -> bool {
    magic == *b"0707"
        && prefix.len == 6
        && matches!(&prefix.bytes, b"070701" | b"070702" | b"070707")
}

fn map_archive_error(error: archive::Error) -> WalkError {
    match error {
        archive::Error::Io(error) => map_io_error(error),
        archive::Error::Truncated { .. }
        | archive::Error::Invalid(_)
        | archive::Error::LimitExceeded { .. } => WalkError::MalformedContainer,
    }
}

fn map_io_error(error: io::Error) -> WalkError {
    if let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<PbzxReadError>())
    {
        return match error {
            PbzxReadError::Malformed => WalkError::MalformedContainer,
            PbzxReadError::Xz => WalkError::XzDecompression,
            PbzxReadError::ChunkLimit => WalkError::PbzxChunkLimit,
            PbzxReadError::ChunkCountLimit => WalkError::PbzxChunkCountLimit,
        };
    }
    let kind = error.kind();
    drop(error);
    WalkError::Reader(kind)
}

struct ExactReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> ExactReader<R> {
    const fn new(inner: R, remaining: u64) -> Self {
        Self { inner, remaining }
    }

    const fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl<R: Read> Read for ExactReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || bytes.is_empty() {
            return Ok(0);
        }
        let limit = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let count = self.inner.read(&mut bytes[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[derive(Clone, Copy)]
struct Prefix {
    bytes: [u8; 6],
    len: usize,
}

struct PrefixedReader<'a> {
    prefix: Prefix,
    position: usize,
    inner: &'a mut dyn Read,
}

impl<'a> PrefixedReader<'a> {
    const fn new(prefix: Prefix, inner: &'a mut dyn Read) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }

    fn prefix_magic(&self) -> &[u8; 4] {
        self.prefix.bytes[..4]
            .try_into()
            .expect("prefix always has four bytes")
    }

    const fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}

impl Read for PrefixedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.position < self.prefix.len {
            let count = bytes.len().min(self.prefix.len - self.position);
            bytes[..count]
                .copy_from_slice(&self.prefix.bytes[self.position..self.position + count]);
            self.position += count;
            return Ok(count);
        }
        self.inner.read(bytes)
    }
}

struct LimitedReader<'a> {
    inner: &'a mut dyn Read,
    remaining: u64,
}

impl<'a> LimitedReader<'a> {
    const fn new(inner: &'a mut dyn Read, remaining: u64) -> Self {
        Self { inner, remaining }
    }

    const fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl Read for LimitedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || bytes.is_empty() {
            return Ok(0);
        }
        let limit = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let count = self.inner.read(&mut bytes[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated embedded archive",
            ));
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[derive(Debug)]
enum PbzxReadError {
    Malformed,
    Xz,
    ChunkLimit,
    ChunkCountLimit,
}

impl fmt::Display for PbzxReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PBZX stream adapter failed")
    }
}

impl std::error::Error for PbzxReadError {}

struct RawPbzxReader<'source, 'budget> {
    reader: PbzxReader<&'source mut dyn Read>,
    buffer: Vec<u8>,
    position: usize,
    chunks: usize,
    limits: Limits,
    budget: &'budget Budget,
    finished: bool,
}

impl<'source, 'budget> RawPbzxReader<'source, 'budget> {
    fn new(source: &'source mut dyn Read, budget: &'budget Budget) -> Result<Self, WalkError> {
        let reader = PbzxReader::new(source).map_err(map_archive_error)?;
        Ok(Self {
            reader,
            buffer: Vec::new(),
            position: 0,
            chunks: 0,
            limits: budget.limits,
            budget,
            finished: false,
        })
    }

    fn next_buffer(&mut self) -> io::Result<bool> {
        self.buffer.fill(0);
        self.buffer.clear();
        self.position = 0;
        loop {
            let Some(mut chunk) = self.reader.next_chunk().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, PbzxReadError::Malformed)
            })?
            else {
                self.finished = true;
                return Ok(false);
            };
            self.chunks = self.chunks.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, PbzxReadError::ChunkCountLimit)
            })?;
            if self.chunks > self.limits.pbzx_chunks {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    PbzxReadError::ChunkCountLimit,
                ));
            }
            let header = chunk.header();
            if header.archived_size > self.limits.pbzx_chunk_bytes
                || header.expanded_size > self.limits.pbzx_chunk_bytes
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    PbzxReadError::ChunkLimit,
                ));
            }
            self.budget
                .pbzx_expanded(header.expanded_size)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let expanded_size = usize::try_from(header.expanded_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, PbzxReadError::ChunkLimit)
            })?;
            resize_buffer(&mut self.buffer, expanded_size)?;
            match header.encoding {
                PbzxEncoding::Raw => chunk.read_exact(&mut self.buffer)?,
                PbzxEncoding::Xz => {
                    let archived_size = usize::try_from(header.archived_size).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, PbzxReadError::ChunkLimit)
                    })?;
                    let mut archived = TemporaryChunk::with_size(archived_size)?;
                    chunk.read_exact(archived.as_mut_slice())?;
                    xz::decode_exact(archived.as_slice(), &mut self.buffer, MAX_XZ_MEMORY_LIMIT)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, PbzxReadError::Xz)
                        })?;
                }
            }
            if !self.buffer.is_empty() {
                return Ok(true);
            }
        }
    }
}

fn resize_buffer(buffer: &mut Vec<u8>, size: usize) -> io::Result<()> {
    let additional = size.saturating_sub(buffer.len());
    buffer
        .try_reserve_exact(additional)
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, PbzxReadError::ChunkLimit))?;
    buffer.resize(size, 0);
    Ok(())
}

struct TemporaryChunk(Vec<u8>);

impl TemporaryChunk {
    fn with_size(size: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        resize_buffer(&mut bytes, size)?;
        Ok(Self(bytes))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for TemporaryChunk {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl Read for RawPbzxReader<'_, '_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        while self.position == self.buffer.len() {
            if self.finished || !self.next_buffer()? {
                return Ok(0);
            }
        }
        let count = bytes.len().min(self.buffer.len() - self.position);
        bytes[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl Drop for RawPbzxReader<'_, '_> {
    fn drop(&mut self) {
        self.buffer.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TARGET: &[u8] = b"usr/share/t1bridge/FDRData";
    const OBJECT: &[u8] = b"bplist00synthetic-fdr-object";

    fn aa_field_bytes(key: [u8; 3], value: &[u8]) -> Vec<u8> {
        let mut field = key.to_vec();
        field.push(b'P');
        field.extend_from_slice(
            &u16::try_from(value.len())
                .expect("synthetic AA value fits u16")
                .to_le_bytes(),
        );
        field.extend_from_slice(value);
        field
    }

    fn aa_field_u8(key: [u8; 3], value: u8) -> Vec<u8> {
        let mut field = key.to_vec();
        field.push(b'1');
        field.push(value);
        field
    }

    fn aa_entry(path: &[u8], data: &[u8], nested: bool) -> Vec<u8> {
        aa_entry_with_operation(path, data, nested.then_some(b'E'))
    }

    fn aa_entry_with_operation(path: &[u8], data: &[u8], operation: Option<u8>) -> Vec<u8> {
        let mut fields = aa_field_bytes(*PAT, path);
        fields.extend_from_slice(&aa_field_u8(
            *TYP,
            if operation.is_some() { b'M' } else { b'F' },
        ));
        if let Some(operation) = operation {
            fields.extend_from_slice(&aa_field_u8(*YOP, operation));
        }
        fields.extend_from_slice(DAT);
        fields.push(b'B');
        fields.extend_from_slice(
            &u32::try_from(data.len())
                .expect("synthetic AA data fits u32")
                .to_le_bytes(),
        );
        let mut entry = b"YAA1".to_vec();
        entry.extend_from_slice(
            &u16::try_from(6 + fields.len())
                .expect("synthetic AA header fits u16")
                .to_le_bytes(),
        );
        entry.extend_from_slice(&fields);
        entry.extend_from_slice(data);
        entry
    }

    fn pbzx(chunks: &[&[u8]]) -> Vec<u8> {
        let maximum = chunks.iter().map(|chunk| chunk.len()).max().unwrap_or(1) as u64;
        let mut bytes = b"pbzx".to_vec();
        bytes.extend_from_slice(&maximum.to_be_bytes());
        for chunk in chunks {
            bytes.extend_from_slice(&(chunk.len() as u64).to_be_bytes());
            bytes.extend_from_slice(&(chunk.len() as u64).to_be_bytes());
            bytes.extend_from_slice(chunk);
        }
        bytes
    }

    fn pbzx_xz(expanded_size: u64, archived: &[u8]) -> Vec<u8> {
        let mut bytes = b"pbzx".to_vec();
        bytes.extend_from_slice(&expanded_size.to_be_bytes());
        bytes.extend_from_slice(&expanded_size.to_be_bytes());
        bytes.extend_from_slice(&(archived.len() as u64).to_be_bytes());
        bytes.extend_from_slice(archived);
        bytes
    }

    fn newc_entry(path: &[u8], mode: u32, data: &[u8]) -> Vec<u8> {
        let values = [
            1,
            mode,
            0,
            0,
            1,
            0,
            u32::try_from(data.len()).expect("synthetic CPIO data fits u32"),
            0,
            0,
            0,
            0,
            u32::try_from(path.len() + 1).expect("synthetic CPIO path fits u32"),
            0,
        ];
        let mut bytes = b"070701".to_vec();
        for value in values {
            bytes.extend_from_slice(format!("{value:08x}").as_bytes());
        }
        bytes.extend_from_slice(path);
        bytes.push(0);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes.extend_from_slice(data);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn cpio(path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut bytes = newc_entry(path, 0o100_600, data);
        bytes.extend_from_slice(&newc_entry(b"TRAILER!!!", 0, b""));
        bytes
    }

    fn collect(bytes: Vec<u8>) -> Result<Vec<u8>, WalkError> {
        let size = bytes.len() as u64;
        collect_fdr_object(Cursor::new(bytes), size, |path| path == TARGET)
    }

    #[test]
    fn walks_every_reference_proven_container_order() {
        let cpio_payload = cpio(TARGET, OBJECT);
        let aa_payload = aa_entry(TARGET, OBJECT, false);
        let nested_aa = aa_entry(b"metadata", &aa_payload, true);
        let nested_pbzx = aa_entry(b"metadata", &pbzx(&[&aa_payload]), true);
        let overlay_aa = aa_entry_with_operation(b"overlay", &aa_payload, Some(b'O'));

        for payload in [
            pbzx(&[&cpio_payload]),
            pbzx(&[&aa_payload[..7], &aa_payload[7..]]),
            nested_aa,
            nested_pbzx,
            overlay_aa,
        ] {
            assert_eq!(collect(payload).unwrap(), OBJECT);
        }
    }

    #[test]
    fn rejects_unproven_aa_to_cpio_nesting() {
        let payload = aa_entry(b"metadata", &cpio(TARGET, OBJECT), true);
        assert_eq!(collect(payload), Err(WalkError::UnsupportedNestedContainer));
    }

    #[test]
    fn caller_controls_case_insensitive_selection() {
        let payload = aa_entry(b"USR/SHARE/T1BRIDGE/fdrdata", OBJECT, false);
        let size = payload.len() as u64;
        let selected = collect_fdr_object(Cursor::new(payload), size, |path| {
            path.eq_ignore_ascii_case(TARGET)
        })
        .unwrap();
        assert_eq!(selected, OBJECT);
    }

    #[test]
    fn duplicate_and_missing_selection_are_distinct() {
        let mut duplicate = aa_entry(TARGET, OBJECT, false);
        duplicate.extend_from_slice(&aa_entry(TARGET, b"second object", false));
        assert_eq!(collect(duplicate), Err(WalkError::DuplicateSelectedObject));

        let missing = aa_entry(b"different/path", OBJECT, false);
        assert_eq!(collect(missing), Err(WalkError::MissingSelectedObject));
    }

    #[test]
    fn selected_payload_wipe_clears_every_byte() {
        let mut bytes = [0xa5; 32];
        wipe_bytes(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_traversal_before_selection() {
        let unsafe_entry = aa_entry(b"../private/FDRData", OBJECT, false);
        assert_eq!(collect(unsafe_entry), Err(WalkError::UnsafePath));

        let cpio = pbzx(&[&cpio(b"safe/../../private", OBJECT)]);
        assert_eq!(collect(cpio), Err(WalkError::UnsafePath));
    }

    #[test]
    fn expands_one_exact_bounded_xz_chunk() {
        const EXPANDED: &[u8] = b"synthetic expanded PBZX chunk";
        const XZ: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0,
            0x21, 0x1d, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe6, 0x6a, 0x1c, 0x77, 0x01, 0x00, 0x1c, 0x73, 0x79, 0x6e, 0x74, 0x68, 0x65, 0x74,
            0x69, 0x63, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x65, 0x64, 0x20, 0x50, 0x42,
            0x5a, 0x58, 0x20, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x98,
            0xa7, 0xf8, 0x55, 0xbb, 0x60, 0x6d, 0x00, 0x01, 0x3d, 0x1d, 0x4c, 0x91, 0x68, 0x29,
            0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
        ];
        let encoded = pbzx_xz(EXPANDED.len() as u64, XZ);
        let mut source = Cursor::new(encoded);
        let limits = Limits::production();
        let budget = Budget::new(limits);
        let mut reader = RawPbzxReader::new(&mut source, &budget).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, EXPANDED);
    }

    #[test]
    fn rejects_invalid_xz_without_disclosing_compressed_bytes() {
        let archived = b"\xfd7zXZ\0opaque-private-compressed-data";
        let payload = pbzx_xz(64, archived);
        let error = collect(payload).unwrap_err();
        assert_eq!(error, WalkError::XzDecompression);
        assert!(!format!("{error:?} {error}").contains("opaque"));
    }

    #[test]
    fn rejects_unread_child_and_top_level_payloads() {
        let mut child = aa_entry(TARGET, OBJECT, false);
        child.extend_from_slice(b"trailing");
        let payload = aa_entry(b"metadata", &child, true);
        assert_eq!(collect(payload), Err(WalkError::MalformedContainer));

        let mut cpio_payload = cpio(TARGET, OBJECT);
        cpio_payload.push(0xaa);
        assert_eq!(
            collect(pbzx(&[&cpio_payload])),
            Err(WalkError::UnreadPayload)
        );
    }

    #[test]
    fn enforces_entry_field_output_source_and_chunk_bounds() {
        let payload = aa_entry(TARGET, OBJECT, false);
        let mut limits = Limits::production();
        limits.entries = 0;
        assert_eq!(
            collect_with_limits(
                Cursor::new(payload.clone()),
                payload.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::EntryLimit)
        );

        let mut limits = Limits::production();
        limits.fields = 1;
        assert_eq!(
            collect_with_limits(
                Cursor::new(payload.clone()),
                payload.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::FieldLimit)
        );

        let mut limits = Limits::production();
        limits.output_bytes = 4;
        assert_eq!(
            collect_with_limits(
                Cursor::new(payload.clone()),
                payload.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::SelectedObjectTooLarge)
        );

        let mut limits = Limits::production();
        limits.source_bytes = (payload.len() - 1) as u64;
        assert_eq!(
            collect_with_limits(
                Cursor::new(payload.clone()),
                payload.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::InvalidSourceSize)
        );

        let wrapped = pbzx(&[&payload]);
        let mut limits = Limits::production();
        limits.pbzx_chunk_bytes = 4;
        assert_eq!(
            collect_with_limits(
                Cursor::new(wrapped.clone()),
                wrapped.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::PbzxChunkLimit)
        );
    }

    #[test]
    fn enforces_nesting_and_pbzx_chunk_count_bounds() {
        let leaf = aa_entry(TARGET, OBJECT, false);
        let nested = aa_entry(b"outer", &aa_entry(b"inner", &leaf, true), true);
        let mut limits = Limits::production();
        limits.nesting = 1;
        assert_eq!(
            collect_with_limits(
                Cursor::new(nested.clone()),
                nested.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::NestingLimit)
        );

        let wrapped = pbzx(&[b"".as_slice(), &leaf]);
        let mut limits = Limits::production();
        limits.pbzx_chunks = 1;
        assert_eq!(
            collect_with_limits(
                Cursor::new(wrapped.clone()),
                wrapped.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::PbzxChunkCountLimit)
        );
    }

    #[test]
    fn enforces_one_expansion_budget_across_nested_pbzx_streams() {
        let leaf = aa_entry(TARGET, OBJECT, false);
        let nested_pbzx = pbzx(&[&leaf]);
        let outer_aa = aa_entry(b"metadata", &nested_pbzx, true);
        let wrapped = pbzx(&[&outer_aa]);
        let exact_budget = u64::try_from(outer_aa.len() + leaf.len()).unwrap();

        let mut limits = Limits::production();
        limits.pbzx_expanded_bytes = exact_budget;
        assert_eq!(
            collect_with_limits(
                Cursor::new(wrapped.clone()),
                wrapped.len() as u64,
                &mut |path| path == TARGET,
                limits,
            )
            .unwrap(),
            OBJECT
        );

        limits.pbzx_expanded_bytes = exact_budget - 1;
        assert_eq!(
            collect_with_limits(
                Cursor::new(wrapped.clone()),
                wrapped.len() as u64,
                &mut |path| path == TARGET,
                limits,
            ),
            Err(WalkError::PbzxChunkLimit)
        );
    }

    #[test]
    fn rejects_crossing_chunk_before_allocation_or_xz_decode() {
        let mut raw = b"pbzx".to_vec();
        raw.extend_from_slice(&1024_u64.to_be_bytes());
        raw.extend_from_slice(&1024_u64.to_be_bytes());
        raw.extend_from_slice(&1024_u64.to_be_bytes());
        raw.extend_from_slice(b"prefix");
        let mut limits = Limits::production();
        limits.pbzx_expanded_bytes = 1023;
        assert_eq!(
            collect_with_limits(
                Cursor::new(raw.clone()),
                raw.len() as u64,
                &mut |_| false,
                limits,
            ),
            Err(WalkError::PbzxChunkLimit)
        );

        let malformed_xz = pbzx_xz(64, b"\xfd7zXZ\0invalid");
        limits.pbzx_expanded_bytes = 63;
        assert_eq!(
            collect_with_limits(
                Cursor::new(malformed_xz.clone()),
                malformed_xz.len() as u64,
                &mut |_| false,
                limits,
            ),
            Err(WalkError::PbzxChunkLimit)
        );
    }

    #[test]
    fn rejects_expansion_accounting_overflow_without_changing_usage() {
        let mut limits = Limits::production();
        limits.pbzx_expanded_bytes = u64::MAX;
        let budget = Budget::new(limits);
        budget.pbzx_expanded_bytes.set(u64::MAX);

        assert!(matches!(
            budget.pbzx_expanded(1),
            Err(PbzxReadError::ChunkLimit)
        ));
        assert_eq!(budget.pbzx_expanded_bytes.get(), u64::MAX);
    }

    #[test]
    fn errors_redact_paths_payloads_and_reader_details() {
        struct SensitiveReader;

        impl Read for SensitiveReader {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private path and payload marker"))
            }
        }

        let error = collect_fdr_object(SensitiveReader, 16, |_| false).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("payload marker"));

        let error = collect(aa_entry(b"../private-path", b"secret-payload", false)).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private-path"));
        assert!(!rendered.contains("secret-payload"));
    }
}
