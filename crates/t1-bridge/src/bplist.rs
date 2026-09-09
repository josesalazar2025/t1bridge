//! Bounded binary-property-list codec for the `BridgeXPC` wire subset.

use std::collections::BTreeMap;
use std::error;
use std::fmt;

const HEADER: &[u8; 8] = b"bplist00";
const TRAILER_SIZE: usize = 32;

/// The `BridgeXPC` frame limit is also the maximum accepted or produced plist.
pub const MAX_PLIST_SIZE: usize = 16 * 1024 * 1024;

const MAX_OBJECTS: usize = 262_144;
const MAX_REFERENCES: usize = 1_048_576;
const MAX_DEPTH: usize = 64;
const MAX_DECODED_NODES: usize = 1_048_576;
const MAX_VALUE_BYTES: usize = MAX_PLIST_SIZE;

/// A value in the property-list subset used by `BridgeXPC`.
///
/// Integers cover the exact wire domain needed by the protocol: signed 64-bit
/// status values and unsigned 64-bit values carried by wrapper dictionaries.
#[derive(Clone, Eq, PartialEq)]
pub enum Value {
    Null,
    Boolean(bool),
    Integer(i128),
    Data(Vec<u8>),
    String(String),
    Array(Vec<Self>),
    Dictionary(BTreeMap<String, Self>),
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("Null"),
            Self::Boolean(value) => formatter.debug_tuple("Boolean").field(value).finish(),
            Self::Integer(value) => formatter.debug_tuple("Integer").field(value).finish(),
            Self::Data(value) => formatter
                .debug_struct("Data")
                .field("len", &value.len())
                .finish(),
            Self::String(value) => formatter.debug_tuple("String").field(value).finish(),
            Self::Array(values) => formatter.debug_tuple("Array").field(values).finish(),
            Self::Dictionary(values) => formatter.debug_tuple("Dictionary").field(values).finish(),
        }
    }
}

/// A payload-redacted binary-property-list error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InputTooLarge,
    OutputTooLarge,
    InvalidHeader,
    InvalidTrailer,
    LimitExceeded,
    Malformed,
    Unsupported,
    IntegerOutOfRange,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InputTooLarge => "binary plist exceeds the input limit",
            Self::OutputTooLarge => "binary plist exceeds the output limit",
            Self::InvalidHeader => "invalid binary plist header",
            Self::InvalidTrailer => "invalid binary plist trailer",
            Self::LimitExceeded => "binary plist complexity limit exceeded",
            Self::Malformed => "malformed binary plist",
            Self::Unsupported => "unsupported binary plist value",
            Self::IntegerOutOfRange => "binary plist integer is out of range",
        };
        formatter.write_str(message)
    }
}

impl error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectKind {
    Null,
    Boolean,
    Integer,
    Data,
    String,
    Array,
    Dictionary,
}

#[derive(Debug)]
struct ScannedObject {
    kind: ObjectKind,
    children: Vec<usize>,
    dictionary_key_count: usize,
}

/// Decode one complete `bplist00` document.
///
/// # Errors
///
/// Returns an error when the document is oversized, malformed, cyclic, over
/// the complexity limits, or contains a value outside the supported subset.
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    if input.len() > MAX_PLIST_SIZE {
        return Err(Error::InputTooLarge);
    }
    if input.len() < HEADER.len() + TRAILER_SIZE {
        return Err(Error::Malformed);
    }
    if input.get(..HEADER.len()) != Some(HEADER) {
        return Err(Error::InvalidHeader);
    }

    let trailer_start = input.len() - TRAILER_SIZE;
    let trailer = &input[trailer_start..];
    if trailer[..6] != [0; 6] {
        return Err(Error::InvalidTrailer);
    }

    let offset_size = usize::from(trailer[6]);
    let reference_size = usize::from(trailer[7]);
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&reference_size) {
        return Err(Error::InvalidTrailer);
    }

    let object_count = usize_from_u64(read_be_u64(&trailer[8..16])?)?;
    let top_object = usize_from_u64(read_be_u64(&trailer[16..24])?)?;
    let offset_table_start = usize_from_u64(read_be_u64(&trailer[24..32])?)?;
    if object_count == 0 || object_count > MAX_OBJECTS || top_object >= object_count {
        return Err(Error::InvalidTrailer);
    }
    if offset_table_start < HEADER.len() || offset_table_start > trailer_start {
        return Err(Error::InvalidTrailer);
    }

    let offset_table_size = object_count
        .checked_mul(offset_size)
        .ok_or(Error::LimitExceeded)?;
    if offset_table_start
        .checked_add(offset_table_size)
        .ok_or(Error::LimitExceeded)?
        != trailer_start
    {
        return Err(Error::InvalidTrailer);
    }

    let mut offsets = Vec::with_capacity(object_count);
    for index in 0..object_count {
        let start = offset_table_start + index * offset_size;
        let offset = usize_from_u64(read_be_u64(&input[start..start + offset_size])?)?;
        if !(HEADER.len()..offset_table_start).contains(&offset) {
            return Err(Error::Malformed);
        }
        offsets.push(offset);
    }

    let mut ordered_offsets = offsets.clone();
    ordered_offsets.sort_unstable();
    if ordered_offsets.first() != Some(&HEADER.len())
        || ordered_offsets.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(Error::Malformed);
    }

    let mut ends_by_offset = BTreeMap::new();
    for (position, &offset) in ordered_offsets.iter().enumerate() {
        let end = ordered_offsets
            .get(position + 1)
            .copied()
            .unwrap_or(offset_table_start);
        ends_by_offset.insert(offset, end);
    }

    let mut scanned = Vec::with_capacity(object_count);
    let mut total_references = 0usize;
    for &offset in &offsets {
        let end = *ends_by_offset.get(&offset).ok_or(Error::Malformed)?;
        let object = scan_object(input, offset, end, reference_size, object_count)?;
        total_references = total_references
            .checked_add(object.children.len())
            .ok_or(Error::LimitExceeded)?;
        if total_references > MAX_REFERENCES {
            return Err(Error::LimitExceeded);
        }
        scanned.push(object);
    }

    for object in &scanned {
        for &key_reference in &object.children[..object.dictionary_key_count] {
            if scanned[key_reference].kind != ObjectKind::String {
                return Err(Error::Malformed);
            }
        }
    }

    let mut colors = vec![0u8; object_count];
    for index in 0..object_count {
        validate_acyclic(index, &scanned, &mut colors, 0)?;
    }

    let mut budget = DecodeBudget {
        nodes: 0,
        value_bytes: 0,
    };
    decode_object(
        input,
        &offsets,
        &ends_by_offset,
        &scanned,
        top_object,
        0,
        &mut budget,
    )
}

fn scan_object(
    input: &[u8],
    start: usize,
    end: usize,
    reference_size: usize,
    object_count: usize,
) -> Result<ScannedObject, Error> {
    let mut cursor = start;
    let marker = read_byte(input, &mut cursor, end)?;
    let high = marker & 0xf0;
    let low = marker & 0x0f;

    let (kind, children, dictionary_key_count) = match marker {
        0x00 => (ObjectKind::Null, Vec::new(), 0),
        0x08 | 0x09 => (ObjectKind::Boolean, Vec::new(), 0),
        _ if high == 0x10 => {
            let width = integer_width(low)?;
            let bytes = take(input, &mut cursor, end, width)?;
            decode_integer(bytes)?;
            (ObjectKind::Integer, Vec::new(), 0)
        }
        _ if high == 0x40 => {
            let length = read_length(input, &mut cursor, end, low)?;
            take(input, &mut cursor, end, length)?;
            (ObjectKind::Data, Vec::new(), 0)
        }
        _ if high == 0x50 => {
            let length = read_length(input, &mut cursor, end, low)?;
            let bytes = take(input, &mut cursor, end, length)?;
            if !bytes.is_ascii() {
                return Err(Error::Malformed);
            }
            (ObjectKind::String, Vec::new(), 0)
        }
        _ if high == 0x60 => {
            let units = read_length(input, &mut cursor, end, low)?;
            let length = units.checked_mul(2).ok_or(Error::LimitExceeded)?;
            let bytes = take(input, &mut cursor, end, length)?;
            validate_utf16(bytes)?;
            (ObjectKind::String, Vec::new(), 0)
        }
        _ if high == 0xa0 => {
            let count = read_length(input, &mut cursor, end, low)?;
            let children =
                read_references(input, &mut cursor, end, count, reference_size, object_count)?;
            (ObjectKind::Array, children, 0)
        }
        _ if high == 0xd0 => {
            let count = read_length(input, &mut cursor, end, low)?;
            let reference_count = count.checked_mul(2).ok_or(Error::LimitExceeded)?;
            let children = read_references(
                input,
                &mut cursor,
                end,
                reference_count,
                reference_size,
                object_count,
            )?;
            (ObjectKind::Dictionary, children, count)
        }
        _ => return Err(Error::Unsupported),
    };

    if cursor != end {
        return Err(Error::Malformed);
    }
    Ok(ScannedObject {
        kind,
        children,
        dictionary_key_count,
    })
}

fn read_references(
    input: &[u8],
    cursor: &mut usize,
    end: usize,
    count: usize,
    reference_size: usize,
    object_count: usize,
) -> Result<Vec<usize>, Error> {
    if count > MAX_REFERENCES {
        return Err(Error::LimitExceeded);
    }
    let byte_count = count
        .checked_mul(reference_size)
        .ok_or(Error::LimitExceeded)?;
    let bytes = take(input, cursor, end, byte_count)?;
    let mut references = Vec::with_capacity(count);
    for raw in bytes.chunks_exact(reference_size) {
        let reference = usize_from_u64(read_be_u64(raw)?)?;
        if reference >= object_count {
            return Err(Error::Malformed);
        }
        references.push(reference);
    }
    Ok(references)
}

fn validate_acyclic(
    index: usize,
    objects: &[ScannedObject],
    colors: &mut [u8],
    depth: usize,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::LimitExceeded);
    }
    match colors[index] {
        1 => return Err(Error::Malformed),
        2 => return Ok(()),
        _ => {}
    }
    colors[index] = 1;
    for &child in &objects[index].children {
        validate_acyclic(child, objects, colors, depth + 1)?;
    }
    colors[index] = 2;
    Ok(())
}

struct DecodeBudget {
    nodes: usize,
    value_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
fn decode_object(
    input: &[u8],
    offsets: &[usize],
    ends_by_offset: &BTreeMap<usize, usize>,
    scanned: &[ScannedObject],
    index: usize,
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<Value, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::LimitExceeded);
    }
    budget.nodes = budget.nodes.checked_add(1).ok_or(Error::LimitExceeded)?;
    if budget.nodes > MAX_DECODED_NODES {
        return Err(Error::LimitExceeded);
    }

    let start = offsets[index];
    let end = *ends_by_offset.get(&start).ok_or(Error::Malformed)?;
    let mut cursor = start;
    let marker = read_byte(input, &mut cursor, end)?;
    let high = marker & 0xf0;
    let low = marker & 0x0f;
    match scanned[index].kind {
        ObjectKind::Null => Ok(Value::Null),
        ObjectKind::Boolean => Ok(Value::Boolean(marker == 0x09)),
        ObjectKind::Integer => {
            let bytes = take(input, &mut cursor, end, integer_width(low)?)?;
            Ok(Value::Integer(decode_integer(bytes)?))
        }
        ObjectKind::Data => {
            let length = read_length(input, &mut cursor, end, low)?;
            charge_bytes(budget, length)?;
            Ok(Value::Data(take(input, &mut cursor, end, length)?.to_vec()))
        }
        ObjectKind::String if high == 0x50 => {
            let length = read_length(input, &mut cursor, end, low)?;
            charge_bytes(budget, length)?;
            let bytes = take(input, &mut cursor, end, length)?;
            let text = std::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
            Ok(Value::String(text.to_owned()))
        }
        ObjectKind::String => {
            let units = read_length(input, &mut cursor, end, low)?;
            let length = units.checked_mul(2).ok_or(Error::LimitExceeded)?;
            charge_bytes(budget, length)?;
            let bytes = take(input, &mut cursor, end, length)?;
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            let text = String::from_utf16(&units).map_err(|_| Error::Malformed)?;
            Ok(Value::String(text))
        }
        ObjectKind::Array => {
            let mut values = Vec::with_capacity(scanned[index].children.len());
            for &child in &scanned[index].children {
                values.push(decode_object(
                    input,
                    offsets,
                    ends_by_offset,
                    scanned,
                    child,
                    depth + 1,
                    budget,
                )?);
            }
            Ok(Value::Array(values))
        }
        ObjectKind::Dictionary => {
            let count = scanned[index].dictionary_key_count;
            let (keys, values) = scanned[index].children.split_at(count);
            let mut dictionary = BTreeMap::new();
            for (&key, &value) in keys.iter().zip(values) {
                let Value::String(key) = decode_object(
                    input,
                    offsets,
                    ends_by_offset,
                    scanned,
                    key,
                    depth + 1,
                    budget,
                )?
                else {
                    return Err(Error::Malformed);
                };
                let value = decode_object(
                    input,
                    offsets,
                    ends_by_offset,
                    scanned,
                    value,
                    depth + 1,
                    budget,
                )?;
                if dictionary.insert(key, value).is_some() {
                    return Err(Error::Malformed);
                }
            }
            Ok(Value::Dictionary(dictionary))
        }
    }
}

fn charge_bytes(budget: &mut DecodeBudget, amount: usize) -> Result<(), Error> {
    budget.value_bytes = budget
        .value_bytes
        .checked_add(amount)
        .ok_or(Error::LimitExceeded)?;
    if budget.value_bytes > MAX_VALUE_BYTES {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}

fn read_length(input: &[u8], cursor: &mut usize, end: usize, low: u8) -> Result<usize, Error> {
    if low < 0x0f {
        return Ok(usize::from(low));
    }
    let marker = read_byte(input, cursor, end)?;
    if marker & 0xf0 != 0x10 {
        return Err(Error::Malformed);
    }
    let width = integer_width(marker & 0x0f)?;
    if width > 8 {
        return Err(Error::LimitExceeded);
    }
    let length = usize_from_u64(read_be_u64(take(input, cursor, end, width)?)?)?;
    if length > MAX_REFERENCES.max(MAX_PLIST_SIZE) {
        return Err(Error::LimitExceeded);
    }
    Ok(length)
}

fn integer_width(low: u8) -> Result<usize, Error> {
    match low {
        0..=4 => Ok(1usize << low),
        _ => Err(Error::Unsupported),
    }
}

fn decode_integer(bytes: &[u8]) -> Result<i128, Error> {
    match bytes.len() {
        1 | 2 | 4 => Ok(i128::from(read_be_u64(bytes)?)),
        8 => {
            let raw: [u8; 8] = bytes.try_into().map_err(|_| Error::Malformed)?;
            Ok(i128::from(i64::from_be_bytes(raw)))
        }
        16 => {
            let raw: [u8; 16] = bytes.try_into().map_err(|_| Error::Malformed)?;
            let value = i128::from_be_bytes(raw);
            if value < i128::from(i64::MIN) || value > i128::from(u64::MAX) {
                return Err(Error::IntegerOutOfRange);
            }
            Ok(value)
        }
        _ => Err(Error::Unsupported),
    }
}

fn validate_utf16(bytes: &[u8]) -> Result<(), Error> {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
    for character in char::decode_utf16(units) {
        character.map_err(|_| Error::Malformed)?;
    }
    Ok(())
}

fn read_byte(input: &[u8], cursor: &mut usize, end: usize) -> Result<u8, Error> {
    let byte = *input
        .get(*cursor)
        .filter(|_| *cursor < end)
        .ok_or(Error::Malformed)?;
    *cursor += 1;
    Ok(byte)
}

fn take<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    end: usize,
    length: usize,
) -> Result<&'a [u8], Error> {
    let next = cursor.checked_add(length).ok_or(Error::LimitExceeded)?;
    if next > end {
        return Err(Error::Malformed);
    }
    let result = input.get(*cursor..next).ok_or(Error::Malformed)?;
    *cursor = next;
    Ok(result)
}

fn read_be_u64(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(Error::Malformed);
    }
    Ok(bytes
        .iter()
        .fold(0u64, |value, &byte| (value << 8) | u64::from(byte)))
}

fn usize_from_u64(value: u64) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::LimitExceeded)
}

enum EncodedObject {
    Null,
    Boolean(bool),
    Integer(i128),
    Data(Vec<u8>),
    String(String),
    Array(Vec<usize>),
    Dictionary {
        keys: Vec<usize>,
        values: Vec<usize>,
    },
}

struct Encoder {
    objects: Vec<EncodedObject>,
    references: usize,
    value_bytes: usize,
}

/// Encode one deterministic `bplist00` document.
///
/// # Errors
///
/// Returns an error when the value is too large or deeply nested, has too many
/// objects or references, or contains an integer outside the supported range.
pub fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut encoder = Encoder {
        objects: Vec::new(),
        references: 0,
        value_bytes: 0,
    };
    let top_object = encoder.add(value, 0)?;
    let largest_reference = u64::try_from(encoder.objects.len().saturating_sub(1))
        .map_err(|_| Error::OutputTooLarge)?;
    let reference_size = integer_storage_width(largest_reference);

    let mut output = Vec::new();
    append(&mut output, HEADER)?;
    let mut offsets = Vec::with_capacity(encoder.objects.len());
    for object in &encoder.objects {
        offsets.push(output.len());
        encode_object(object, reference_size, &mut output)?;
    }

    let offset_table_start = output.len();
    let offset_size = integer_storage_width(
        u64::try_from(offset_table_start).map_err(|_| Error::OutputTooLarge)?,
    );
    for offset in offsets {
        append_be(
            &mut output,
            u64::try_from(offset).map_err(|_| Error::OutputTooLarge)?,
            offset_size,
        )?;
    }

    append(&mut output, &[0; 6])?;
    push(
        &mut output,
        u8::try_from(offset_size).map_err(|_| Error::OutputTooLarge)?,
    )?;
    push(
        &mut output,
        u8::try_from(reference_size).map_err(|_| Error::OutputTooLarge)?,
    )?;
    append_be(
        &mut output,
        u64::try_from(encoder.objects.len()).map_err(|_| Error::OutputTooLarge)?,
        8,
    )?;
    append_be(
        &mut output,
        u64::try_from(top_object).map_err(|_| Error::OutputTooLarge)?,
        8,
    )?;
    append_be(
        &mut output,
        u64::try_from(offset_table_start).map_err(|_| Error::OutputTooLarge)?,
        8,
    )?;
    Ok(output)
}

impl Encoder {
    fn add(&mut self, value: &Value, depth: usize) -> Result<usize, Error> {
        if depth > MAX_DEPTH || self.objects.len() >= MAX_OBJECTS {
            return Err(Error::LimitExceeded);
        }
        let index = self.objects.len();
        self.objects.push(EncodedObject::Null);
        let object = match value {
            Value::Null => EncodedObject::Null,
            Value::Boolean(value) => EncodedObject::Boolean(*value),
            Value::Integer(value) => {
                if *value < i128::from(i64::MIN) || *value > i128::from(u64::MAX) {
                    return Err(Error::IntegerOutOfRange);
                }
                EncodedObject::Integer(*value)
            }
            Value::Data(value) => {
                self.charge_bytes(value.len())?;
                EncodedObject::Data(value.clone())
            }
            Value::String(value) => {
                self.charge_bytes(value.len())?;
                EncodedObject::String(value.clone())
            }
            Value::Array(values) => {
                self.charge_references(values.len())?;
                let mut children = Vec::with_capacity(values.len());
                for value in values {
                    children.push(self.add(value, depth + 1)?);
                }
                EncodedObject::Array(children)
            }
            Value::Dictionary(values) => {
                self.charge_references(values.len().checked_mul(2).ok_or(Error::LimitExceeded)?)?;
                let mut keys = Vec::with_capacity(values.len());
                let mut children = Vec::with_capacity(values.len());
                for (key, value) in values {
                    self.charge_bytes(key.len())?;
                    let key_index = self.objects.len();
                    if key_index >= MAX_OBJECTS {
                        return Err(Error::LimitExceeded);
                    }
                    self.objects.push(EncodedObject::String(key.clone()));
                    keys.push(key_index);
                    children.push(self.add(value, depth + 1)?);
                }
                EncodedObject::Dictionary {
                    keys,
                    values: children,
                }
            }
        };
        self.objects[index] = object;
        Ok(index)
    }

    fn charge_references(&mut self, count: usize) -> Result<(), Error> {
        self.references = self
            .references
            .checked_add(count)
            .ok_or(Error::LimitExceeded)?;
        if self.references > MAX_REFERENCES {
            return Err(Error::LimitExceeded);
        }
        Ok(())
    }

    fn charge_bytes(&mut self, count: usize) -> Result<(), Error> {
        self.value_bytes = self
            .value_bytes
            .checked_add(count)
            .ok_or(Error::LimitExceeded)?;
        if self.value_bytes > MAX_VALUE_BYTES {
            return Err(Error::LimitExceeded);
        }
        Ok(())
    }
}

fn encode_object(
    object: &EncodedObject,
    reference_size: usize,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    match object {
        EncodedObject::Null => push(output, 0x00),
        EncodedObject::Boolean(false) => push(output, 0x08),
        EncodedObject::Boolean(true) => push(output, 0x09),
        EncodedObject::Integer(value) => encode_integer(*value, output),
        EncodedObject::Data(value) => {
            encode_length(0x40, value.len(), output)?;
            append(output, value)
        }
        EncodedObject::String(value) if value.is_ascii() => {
            encode_length(0x50, value.len(), output)?;
            append(output, value.as_bytes())
        }
        EncodedObject::String(value) => {
            let units = value.encode_utf16().collect::<Vec<_>>();
            encode_length(0x60, units.len(), output)?;
            for unit in units {
                append(output, &unit.to_be_bytes())?;
            }
            Ok(())
        }
        EncodedObject::Array(references) => {
            encode_length(0xa0, references.len(), output)?;
            for &reference in references {
                append_be(
                    output,
                    u64::try_from(reference).map_err(|_| Error::OutputTooLarge)?,
                    reference_size,
                )?;
            }
            Ok(())
        }
        EncodedObject::Dictionary { keys, values } => {
            encode_length(0xd0, keys.len(), output)?;
            for &reference in keys.iter().chain(values) {
                append_be(
                    output,
                    u64::try_from(reference).map_err(|_| Error::OutputTooLarge)?,
                    reference_size,
                )?;
            }
            Ok(())
        }
    }
}

fn encode_integer(value: i128, output: &mut Vec<u8>) -> Result<(), Error> {
    if value < 0 {
        push(output, 0x13)?;
        let value = i64::try_from(value).map_err(|_| Error::IntegerOutOfRange)?;
        return append(output, &value.to_be_bytes());
    }
    let value = u64::try_from(value).map_err(|_| Error::IntegerOutOfRange)?;
    match integer_storage_width(value) {
        width @ (1 | 2 | 4) => {
            let exponent = u8::try_from(width.trailing_zeros()).map_err(|_| Error::Malformed)?;
            push(output, 0x10 | exponent)?;
            append_be(output, value, width)
        }
        8 if value < (1u64 << 63) => {
            push(output, 0x13)?;
            append_be(output, value, 8)
        }
        8 => {
            push(output, 0x14)?;
            append(output, &[0; 8])?;
            append_be(output, value, 8)
        }
        _ => Err(Error::IntegerOutOfRange),
    }
}

fn encode_length(marker: u8, length: usize, output: &mut Vec<u8>) -> Result<(), Error> {
    if length < 15 {
        let inline_length = u8::try_from(length).map_err(|_| Error::OutputTooLarge)?;
        return push(output, marker | inline_length);
    }
    push(output, marker | 0x0f)?;
    let wire_length = u64::try_from(length).map_err(|_| Error::OutputTooLarge)?;
    let width = integer_storage_width(wire_length);
    let exponent = u8::try_from(width.trailing_zeros()).map_err(|_| Error::Malformed)?;
    push(output, 0x10 | exponent)?;
    append_be(output, wire_length, width)
}

fn integer_storage_width(value: u64) -> usize {
    if u8::try_from(value).is_ok() {
        1
    } else if u16::try_from(value).is_ok() {
        2
    } else if u32::try_from(value).is_ok() {
        4
    } else {
        8
    }
}

fn push(output: &mut Vec<u8>, byte: u8) -> Result<(), Error> {
    if output.len() >= MAX_PLIST_SIZE {
        return Err(Error::OutputTooLarge);
    }
    output.push(byte);
    Ok(())
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::OutputTooLarge)?;
    if next > MAX_PLIST_SIZE {
        return Err(Error::OutputTooLarge);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_be(output: &mut Vec<u8>, value: u64, width: usize) -> Result<(), Error> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(Error::OutputTooLarge);
    }
    let bytes = value.to_be_bytes();
    append(output, &bytes[bytes.len() - width..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLISTLIB_NEGATIVE: &[u8] = &[
        0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xa4, 0x01, 0x02, 0x03, 0x04, 0x10, 0x01,
        0x08, 0x5f, 0x10, 0x11, 0x53, 0x59, 0x4e, 0x54, 0x48, 0x45, 0x54, 0x49, 0x43, 0x2d, 0x52,
        0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0xa4, 0x05, 0x06, 0x07, 0x08, 0x10, 0x03, 0x10, 0x00,
        0x42, 0x01, 0x02, 0x13, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x02, 0xd6, 0x08, 0x0d, 0x0f,
        0x10, 0x24, 0x29, 0x2b, 0x2d, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39,
    ];

    const PLISTLIB_COMPLEX: &[u8] = &[
        0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd5, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x0a, 0x0b, 0x0c, 0x5f, 0x10, 0x10, 0x78, 0x61, 0x72, 0x74, 0x2d, 0x6d, 0x73, 0x67,
        0x2e, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x10, 0x10, 0x78, 0x61, 0x72, 0x74,
        0x2d, 0x6d, 0x73, 0x67, 0x2e, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x55, 0x6c, 0x61,
        0x62, 0x65, 0x6c, 0x55, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x55, 0x69, 0x74, 0x65, 0x6d, 0x73,
        0x09, 0xd1, 0x08, 0x09, 0x5f, 0x10, 0x1c, 0x5f, 0x5f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70,
        0x70, 0x6c, 0x65, 0x2e, 0x42, 0x72, 0x69, 0x64, 0x67, 0x65, 0x58, 0x50, 0x43, 0x2e, 0x75,
        0x69, 0x6e, 0x74, 0x36, 0x34, 0x10, 0x01, 0x64, 0x00, 0x63, 0x00, 0x61, 0x00, 0x66, 0x00,
        0xe9, 0x00, 0xa3, 0x0d, 0x0e, 0x0f, 0x40, 0x12, 0x00, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x13, 0x26, 0x39, 0x3f, 0x45, 0x4b, 0x4c, 0x4f, 0x6e, 0x70, 0x79, 0x7a, 0x7e, 0x7f, 0x84,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x95,
    ];

    fn integer(value: i128) -> Value {
        Value::Integer(value)
    }

    #[test]
    fn decodes_plistlib_negative_status_fixture() {
        assert_eq!(
            decode(PLISTLIB_NEGATIVE).unwrap(),
            Value::Array(vec![
                integer(1),
                Value::Boolean(false),
                Value::String("SYNTHETIC-REQUEST".into()),
                Value::Array(vec![
                    integer(3),
                    integer(0),
                    Value::Data(vec![1, 2]),
                    integer(-536_870_186),
                ]),
            ])
        );
    }

    #[test]
    fn decodes_plistlib_wrapper_unicode_null_and_u64_fixture() {
        let Value::Dictionary(root) = decode(PLISTLIB_COMPLEX).unwrap() else {
            panic!("expected dictionary");
        };
        assert_eq!(root["xart-msg.success"], Value::Boolean(true));
        assert_eq!(root["label"], Value::String("café".into()));
        assert_eq!(root["empty"], Value::Null);
        assert_eq!(
            root["items"],
            Value::Array(vec![
                Value::Data(Vec::new()),
                integer(65_536),
                integer(1i128 << 63),
            ])
        );
        let Value::Dictionary(wrapper) = &root["xart-msg.version"] else {
            panic!("expected wrapper dictionary");
        };
        assert_eq!(wrapper["__com.apple.BridgeXPC.uint64"], integer(1));
    }

    #[test]
    fn round_trips_each_supported_value() {
        let mut nested = BTreeMap::new();
        nested.insert("array".into(), Value::Array(vec![Value::Null, integer(-1)]));
        nested.insert("bool".into(), Value::Boolean(true));
        nested.insert("data".into(), Value::Data(vec![0, 1, 2, 255]));
        nested.insert("integer".into(), integer(i128::from(u64::MAX)));
        nested.insert("text".into(), Value::String("雪".into()));
        let value = Value::Dictionary(nested);
        let encoded = encode(&value).unwrap();
        assert_eq!(decode(&encoded).unwrap(), value);
    }

    #[test]
    fn encoding_is_deterministic_and_dictionary_sorted() {
        let mut dictionary = BTreeMap::new();
        dictionary.insert("z".into(), integer(2));
        dictionary.insert("a".into(), integer(1));
        let value = Value::Dictionary(dictionary);
        assert_eq!(encode(&value).unwrap(), encode(&value).unwrap());
        assert_eq!(decode(&encode(&value).unwrap()).unwrap(), value);
    }

    #[test]
    fn integer_boundaries_round_trip() {
        for value in [
            i128::from(i64::MIN),
            -1,
            0,
            255,
            256,
            65_535,
            65_536,
            i128::from(u32::MAX) + 1,
            i128::from(i64::MAX),
            i128::from(i64::MAX) + 1,
            i128::from(u64::MAX),
        ] {
            let encoded = encode(&integer(value)).unwrap();
            assert_eq!(decode(&encoded).unwrap(), integer(value));
        }
    }

    #[test]
    fn round_trips_extended_lengths_and_two_byte_references() {
        let value = Value::Array((0..300).map(integer).collect());
        let encoded = encode(&value).unwrap();
        assert_eq!(encoded[HEADER.len()], 0xaf);
        assert_eq!(encoded[encoded.len() - TRAILER_SIZE + 7], 2);
        assert_eq!(decode(&encoded).unwrap(), value);
    }

    #[test]
    fn round_trips_four_byte_offsets() {
        let value = Value::Array(vec![Value::Data(vec![0x5a; 70_000]), Value::Null]);
        let encoded = encode(&value).unwrap();
        assert_eq!(encoded[encoded.len() - TRAILER_SIZE + 6], 4);
        assert_eq!(decode(&encoded).unwrap(), value);
    }

    #[test]
    fn decodes_three_byte_offsets_as_written_by_corefoundation() {
        // CoreFoundation writes the narrowest offset width that fits, so real
        // FDRData files use widths such as 3; the format allows 1..=8 bytes.
        let value = Value::Data(vec![0x5a; 300]);
        let encoded = encode(&value).unwrap();
        let trailer_start = encoded.len() - TRAILER_SIZE;
        let trailer = &encoded[trailer_start..];
        assert_eq!(trailer[6], 2);
        let object_count = usize::try_from(read_be_u64(&trailer[8..16]).unwrap()).unwrap();
        let table_start = usize::try_from(read_be_u64(&trailer[24..32]).unwrap()).unwrap();
        let mut widened = encoded[..table_start].to_vec();
        for index in 0..object_count {
            let start = table_start + index * 2;
            let offset = read_be_u64(&encoded[start..start + 2]).unwrap();
            widened.extend_from_slice(&offset.to_be_bytes()[5..]);
        }
        let mut new_trailer = trailer.to_vec();
        new_trailer[6] = 3;
        widened.extend_from_slice(&new_trailer);
        assert_eq!(decode(&widened).unwrap(), value);
    }

    #[test]
    fn offset_width_covers_the_complete_object_table() {
        let value = Value::Data(vec![0x5a; 300]);
        let encoded = encode(&value).unwrap();
        assert_eq!(encoded[encoded.len() - TRAILER_SIZE + 6], 2);
        assert_eq!(decode(&encoded).unwrap(), value);
    }

    #[test]
    fn debug_redacts_data_recursively() {
        let mut dictionary = BTreeMap::new();
        dictionary.insert("opaque".into(), Value::Data(vec![0xde, 0xad, 0xbe, 0xef]));
        let debug = format!("{:?}", Value::Dictionary(dictionary));
        assert!(debug.contains("len: 4"));
        assert!(!debug.contains("222"));
        assert!(!debug.contains("173"));
    }

    #[test]
    fn rejects_integer_outside_protocol_domain() {
        assert_eq!(
            encode(&integer(i128::from(i64::MIN) - 1)),
            Err(Error::IntegerOutOfRange)
        );
        assert_eq!(
            encode(&integer(i128::from(u64::MAX) + 1)),
            Err(Error::IntegerOutOfRange)
        );
    }

    #[test]
    fn rejects_wrong_header_and_trailing_data() {
        let encoded = encode(&integer(1)).unwrap();
        let mut wrong_header = encoded.clone();
        wrong_header[0] = b'x';
        assert_eq!(decode(&wrong_header), Err(Error::InvalidHeader));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn rejects_unsupported_marker() {
        let mut encoded = encode(&Value::Null).unwrap();
        encoded[HEADER.len()] = 0x23;
        assert_eq!(decode(&encoded), Err(Error::Unsupported));
    }

    #[test]
    fn rejects_bad_reference() {
        let mut encoded = encode(&Value::Array(vec![integer(1)])).unwrap();
        let array_reference = HEADER.len() + 1;
        encoded[array_reference] = 2;
        assert_eq!(decode(&encoded), Err(Error::Malformed));
    }

    #[test]
    fn rejects_non_string_dictionary_key() {
        let mut dictionary = BTreeMap::new();
        dictionary.insert("key".into(), integer(1));
        let mut encoded = encode(&Value::Dictionary(dictionary)).unwrap();
        let key_offset = HEADER.len() + 3;
        encoded[key_offset] = 0x10;
        assert_eq!(decode(&encoded), Err(Error::Malformed));
    }

    #[test]
    fn rejects_cyclic_graph() {
        let mut encoded = encode(&Value::Array(vec![integer(1)])).unwrap();
        let array_reference = HEADER.len() + 1;
        encoded[array_reference] = 0;
        assert_eq!(decode(&encoded), Err(Error::Malformed));
    }

    #[test]
    fn rejects_excessive_nesting_on_encode() {
        let mut value = Value::Null;
        for _ in 0..=MAX_DEPTH {
            value = Value::Array(vec![value]);
        }
        assert_eq!(encode(&value), Err(Error::LimitExceeded));
    }

    #[test]
    fn errors_never_include_payload_content() {
        let error = decode(b"private biometric bytes").unwrap_err();
        assert!(!error.to_string().contains("private"));
    }
}
