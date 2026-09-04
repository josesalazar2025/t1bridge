//! Strict, bounded reader for Apple's XML `FDRData` dictionary form.

use std::fmt;

const XML_DECLARATION: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const APPLE_PLIST_DOCTYPE: &[u8] = b"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">";
const PLIST_OPEN: &[u8] = b"<plist version=\"1.0\">";
const PLIST_CLOSE: &[u8] = b"</plist>";
const DICT_OPEN: &[u8] = b"<dict>";
const DICT_CLOSE: &[u8] = b"</dict>";
const KEY_OPEN: &[u8] = b"<key>";
const KEY_CLOSE: &[u8] = b"</key>";
const DATA_OPEN: &[u8] = b"<data>";
const DATA_CLOSE: &[u8] = b"</data>";
const MAX_KEY_SIZE: usize = 256;

/// Payload-redacted XML `FDRData` parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The document is not Apple's canonical XML-plist dictionary form.
    Malformed,
    /// A dictionary key is outside the small ASCII subset used by `FDRData`.
    InvalidKey,
    /// A data value is not canonical padded base64.
    InvalidBase64,
    /// The requested dictionary key occurs more than once.
    DuplicateKey,
    /// Decoded storage could not be bounded or allocated.
    LimitExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed Apple XML property list",
            Self::InvalidKey => "invalid Apple XML property-list key",
            Self::InvalidBase64 => "invalid Apple XML property-list data",
            Self::DuplicateKey => "duplicate Apple XML property-list key",
            Self::LimitExceeded => "Apple XML property-list data exceeds its limit",
        })
    }
}

impl std::error::Error for Error {}

/// Returns the decoded data value for one exact key in a canonical Apple XML
/// plist dictionary.
///
/// Every dictionary entry is structurally and base64 validated even when its
/// key does not match. XML entities, nested containers, alternate doctypes,
/// and non-data values are deliberately rejected: none are needed by Apple's
/// `FDRData` format, and rejecting them keeps this parser non-expanding and
/// dependency-free.
pub fn select_data(input: &[u8], key: &[u8], maximum: usize) -> Result<Option<Vec<u8>>, Error> {
    let mut parser = Parser::new(input);
    parser.take(XML_DECLARATION)?;
    parser.whitespace();
    parser.take(APPLE_PLIST_DOCTYPE)?;
    parser.whitespace();
    parser.take(PLIST_OPEN)?;
    parser.whitespace();
    parser.take(DICT_OPEN)?;

    let mut selected = None;
    loop {
        parser.whitespace();
        if parser.try_take(DICT_CLOSE) {
            break;
        }

        parser.take(KEY_OPEN)?;
        let entry_key = parser.until(KEY_CLOSE)?;
        validate_key(entry_key)?;
        parser.take(KEY_CLOSE)?;
        parser.whitespace();
        parser.take(DATA_OPEN)?;
        let encoded = parser.until(DATA_CLOSE)?;
        let matches = entry_key == key;
        let decoded = decode_base64(encoded, maximum, matches)?;
        if matches && selected.replace(decoded.ok_or(Error::Malformed)?).is_some() {
            return Err(Error::DuplicateKey);
        }
        parser.take(DATA_CLOSE)?;
    }

    parser.whitespace();
    parser.take(PLIST_CLOSE)?;
    parser.whitespace();
    if !parser.remaining().is_empty() {
        return Err(Error::Malformed);
    }
    Ok(selected)
}

fn validate_key(key: &[u8]) -> Result<(), Error> {
    if key.is_empty()
        || key.len() > MAX_KEY_SIZE
        || !key
            .iter()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'<' | b'>' | b'&'))
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn decode_base64(encoded: &[u8], maximum: usize, retain: bool) -> Result<Option<Vec<u8>>, Error> {
    let symbol_count = encoded
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    if symbol_count == 0 || symbol_count % 4 != 0 {
        return Err(Error::InvalidBase64);
    }
    let maximum_encoded = maximum
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(Error::LimitExceeded)?;
    if symbol_count > maximum_encoded {
        return Err(Error::LimitExceeded);
    }

    let capacity = symbol_count / 4 * 3;
    let mut output = if retain {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity.min(maximum))
            .map_err(|_| Error::LimitExceeded)?;
        Some(bytes)
    } else {
        None
    };
    let mut quartet = [0_u8; 4];
    let mut quartet_len = 0_usize;
    let mut finished = false;

    for &byte in encoded {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if finished {
            return Err(Error::InvalidBase64);
        }
        quartet[quartet_len] = byte;
        quartet_len += 1;
        if quartet_len == quartet.len() {
            let (decoded, count, padded) = decode_quartet(quartet)?;
            if let Some(bytes) = &mut output {
                if bytes
                    .len()
                    .checked_add(count)
                    .is_none_or(|len| len > maximum)
                {
                    return Err(Error::LimitExceeded);
                }
                bytes.extend_from_slice(&decoded[..count]);
            }
            finished = padded;
            quartet_len = 0;
        }
    }
    if quartet_len != 0 {
        return Err(Error::InvalidBase64);
    }
    Ok(output)
}

fn decode_quartet(encoded: [u8; 4]) -> Result<([u8; 3], usize, bool), Error> {
    let first = base64_value(encoded[0]).ok_or(Error::InvalidBase64)?;
    let second = base64_value(encoded[1]).ok_or(Error::InvalidBase64)?;
    let third = base64_value(encoded[2]);
    let fourth = base64_value(encoded[3]);

    match (encoded[2], encoded[3], third, fourth) {
        (b'=', b'=', None, None) if second.trailing_zeros() >= 4 => {
            Ok(([first << 2 | second >> 4, 0, 0], 1, true))
        }
        (_, b'=', Some(third), None) if third.trailing_zeros() >= 2 => Ok((
            [first << 2 | second >> 4, second << 4 | third >> 2, 0],
            2,
            true,
        )),
        (_, _, Some(third), Some(fourth)) => Ok((
            [
                first << 2 | second >> 4,
                second << 4 | third >> 2,
                third << 6 | fourth,
            ],
            3,
            false,
        )),
        _ => Err(Error::InvalidBase64),
    }
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn whitespace(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn take(&mut self, expected: &[u8]) -> Result<(), Error> {
        if self.try_take(expected) {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn try_take(&mut self, expected: &[u8]) -> bool {
        let Some(end) = self.offset.checked_add(expected.len()) else {
            return false;
        };
        if self.input.get(self.offset..end) == Some(expected) {
            self.offset = end;
            true
        } else {
            false
        }
    }

    fn until(&mut self, delimiter: &[u8]) -> Result<&'a [u8], Error> {
        let tail = self.remaining();
        let relative = tail
            .windows(delimiter.len())
            .position(|window| window == delimiter)
            .ok_or(Error::Malformed)?;
        let value = &tail[..relative];
        self.offset += relative;
        Ok(value)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn selects_one_data_value_and_validates_other_entries() {
        let input = xml(&[("OTHER", "AA=="), ("FSCl-SYNTHETICMODULE001", "AQID\nBA==")]);
        assert_eq!(
            select_data(&input, b"FSCl-SYNTHETICMODULE001", 16),
            Ok(Some(vec![1, 2, 3, 4]))
        );
        assert_eq!(select_data(&input, b"MISSING", 16), Ok(None));
    }

    #[test]
    fn rejects_noncanonical_or_ambiguous_documents() {
        let duplicate = xml(&[
            ("FSCl-SYNTHETICMODULE001", "AA=="),
            ("FSCl-SYNTHETICMODULE001", "AQ=="),
        ]);
        assert_eq!(
            select_data(&duplicate, b"FSCl-SYNTHETICMODULE001", 16),
            Err(Error::DuplicateKey)
        );

        for input in [
            b"not xml".to_vec(),
            xml(&[("BAD&KEY", "AA==")]),
            xml(&[("KEY", "A===")]),
            xml(&[("KEY", "AB==")]),
            xml(&[("KEY", "AAAA====")]),
        ] {
            assert!(select_data(&input, b"KEY", 16).is_err());
        }
    }

    #[test]
    fn enforces_decoded_size_without_retaining_unrelated_data() {
        let input = xml(&[("OTHER", "AAAA"), ("KEY", "AQIDBA==")]);
        assert_eq!(select_data(&input, b"KEY", 3), Err(Error::LimitExceeded));
    }

    fn xml(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut document = format!(
            "{}\n{}\n{}\n<dict>\n",
            std::str::from_utf8(XML_DECLARATION).unwrap(),
            std::str::from_utf8(APPLE_PLIST_DOCTYPE).unwrap(),
            std::str::from_utf8(PLIST_OPEN).unwrap()
        );
        for (key, data) in entries {
            write!(document, "<key>{key}</key>\n<data>{data}</data>\n").unwrap();
        }
        document.push_str("</dict>\n</plist>\n");
        document.into_bytes()
    }
}
