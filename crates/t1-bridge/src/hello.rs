//! Bounded `BridgeXPC` HELLO body encoding and validation.

use core::fmt;

pub const MAX_HELLO_BODY_LEN: usize = 64 * 1024;
pub const MAX_PROCESS_NAME_LEN: usize = 255;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_KEY_LEN: usize = 512;
const PROTOCOL_VERSION_KEY: &str = "MaxSupportedProtocolVersion";

/// Encodes the Linux side of a `BridgeXPC` HELLO exchange.
///
/// # Errors
///
/// Returns [`HelloError::InvalidProcessName`] for an empty name or one longer
/// than [`MAX_PROCESS_NAME_LEN`] bytes.
pub fn encode_hello(process_name: &str) -> Result<Vec<u8>, HelloError> {
    if process_name.is_empty() || process_name.len() > MAX_PROCESS_NAME_LEN {
        return Err(HelloError::InvalidProcessName);
    }

    let mut body = Vec::with_capacity(96 + process_name.len());
    body.extend_from_slice(br#"{"OSBuild":"Linux","BridgeXPCVersion":1.35,"ProcessName":""#);
    escape_json_string(process_name, &mut body);
    body.extend_from_slice(br#"","MaxSupportedProtocolVersion":1}"#);
    Ok(body)
}

/// Validates a peer `BridgeXPC` HELLO body.
///
/// Unknown fields are accepted when their values are valid bounded JSON. The
/// protocol-version field must occur exactly once and contain a JSON number
/// greater than or equal to one.
///
/// # Errors
///
/// Returns a payload-redacted error when the body exceeds the defensive size
/// limit, is not valid bounded JSON, or does not advertise a supported
/// protocol version.
pub fn validate_peer_hello(body: &[u8]) -> Result<(), HelloError> {
    if body.len() > MAX_HELLO_BODY_LEN {
        return Err(HelloError::BodyTooLarge);
    }
    let input = core::str::from_utf8(body).map_err(|_| HelloError::MalformedJson)?;
    Parser::new(input).parse_hello()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloError {
    InvalidProcessName,
    BodyTooLarge,
    MalformedJson,
    NestingTooDeep,
    JsonKeyTooLong,
    MissingProtocolVersion,
    DuplicateProtocolVersion,
    UnsupportedProtocolVersion,
}

impl fmt::Display for HelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidProcessName => "BridgeXPC process name is invalid",
            Self::BodyTooLarge => "BridgeXPC HELLO body is too large",
            Self::MalformedJson => "BridgeXPC HELLO contains malformed JSON",
            Self::NestingTooDeep => "BridgeXPC HELLO JSON is nested too deeply",
            Self::JsonKeyTooLong => "BridgeXPC HELLO JSON key is too long",
            Self::MissingProtocolVersion => {
                "BridgeXPC HELLO is missing its maximum protocol version"
            }
            Self::DuplicateProtocolVersion => {
                "BridgeXPC HELLO repeats its maximum protocol version"
            }
            Self::UnsupportedProtocolVersion => {
                "BridgeXPC peer does not support protocol version 1"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HelloError {}

fn escape_json_string(value: &str, output: &mut Vec<u8>) {
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br"\\"),
            '\u{08}' => output.extend_from_slice(br"\b"),
            '\u{0c}' => output.extend_from_slice(br"\f"),
            '\n' => output.extend_from_slice(br"\n"),
            '\r' => output.extend_from_slice(br"\r"),
            '\t' => output.extend_from_slice(br"\t"),
            '\0'..='\u{1f}' | '\u{80}'..='\u{ffff}' => {
                append_unicode_escape(
                    u16::try_from(u32::from(character)).expect("matched BMP scalar"),
                    output,
                );
            }
            '\u{10000}'.. => {
                let scalar = u32::from(character) - 0x1_0000;
                append_unicode_escape(
                    u16::try_from(0xd800 + (scalar >> 10)).expect("valid high surrogate"),
                    output,
                );
                append_unicode_escape(
                    u16::try_from(0xdc00 + (scalar & 0x3ff)).expect("valid low surrogate"),
                    output,
                );
            }
            _ => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
}

fn append_unicode_escape(value: u16, output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.extend_from_slice(br"\u");
    output.push(HEX[usize::from((value >> 12) & 0x0f)]);
    output.push(HEX[usize::from((value >> 8) & 0x0f)]);
    output.push(HEX[usize::from((value >> 4) & 0x0f)]);
    output.push(HEX[usize::from(value & 0x0f)]);
}

struct Parser<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input, position: 0 }
    }

    fn parse_hello(mut self) -> Result<(), HelloError> {
        self.skip_whitespace();
        if self.peek() != Some(b'{') {
            return Err(HelloError::MalformedJson);
        }
        self.position += 1;
        self.skip_whitespace();

        let mut protocol_version = None;
        if self.take(b'}') {
            self.finish()?;
            return Err(HelloError::MissingProtocolVersion);
        }

        loop {
            let key = self.parse_key()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();

            if key == PROTOCOL_VERSION_KEY {
                if protocol_version.is_some() {
                    return Err(HelloError::DuplicateProtocolVersion);
                }
                protocol_version = Some(self.parse_protocol_version()?);
            } else {
                self.parse_value(1)?;
            }

            self.skip_whitespace();
            if self.take(b'}') {
                break;
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }

        self.finish()?;
        match protocol_version {
            Some(true) => Ok(()),
            Some(false) => Err(HelloError::UnsupportedProtocolVersion),
            None => Err(HelloError::MissingProtocolVersion),
        }
    }

    fn parse_protocol_version(&mut self) -> Result<bool, HelloError> {
        if !matches!(self.peek(), Some(b'-' | b'0'..=b'9')) {
            self.parse_value(1)?;
            return Ok(false);
        }
        let number = self.parse_number()?;
        let value = number
            .parse::<f64>()
            .map_err(|_| HelloError::MalformedJson)?;
        Ok(value >= 1.0)
    }

    fn parse_value(&mut self, depth: usize) -> Result<(), HelloError> {
        if depth > MAX_JSON_DEPTH {
            return Err(HelloError::NestingTooDeep);
        }
        match self.peek() {
            Some(b'"') => self.parse_string(None),
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b't') => self.parse_literal("true"),
            Some(b'f') => self.parse_literal("false"),
            Some(b'n') => self.parse_literal("null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(|_| ()),
            _ => Err(HelloError::MalformedJson),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), HelloError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.take(b'}') {
            return Ok(());
        }
        loop {
            self.parse_string(None)?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            self.parse_value(depth + 1)?;
            self.skip_whitespace();
            if self.take(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), HelloError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.take(b']') {
            return Ok(());
        }
        loop {
            self.parse_value(depth + 1)?;
            self.skip_whitespace();
            if self.take(b']') {
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_key(&mut self) -> Result<String, HelloError> {
        let mut key = String::new();
        self.parse_string(Some(&mut key))?;
        Ok(key)
    }

    fn parse_string(&mut self, mut output: Option<&mut String>) -> Result<(), HelloError> {
        self.expect(b'"')?;
        loop {
            let character = match self.next_character() {
                Some('"') => return Ok(()),
                Some('\\') => self.parse_escape()?,
                Some(character) if character <= '\u{1f}' => {
                    return Err(HelloError::MalformedJson);
                }
                Some(character) => character,
                None => return Err(HelloError::MalformedJson),
            };

            if let Some(value) = output.as_deref_mut() {
                if value.len() + character.len_utf8() > MAX_JSON_KEY_LEN {
                    return Err(HelloError::JsonKeyTooLong);
                }
                value.push(character);
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, HelloError> {
        match self.next_byte() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{08}'),
            Some(b'f') => Ok('\u{0c}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => self.parse_unicode_escape(),
            _ => Err(HelloError::MalformedJson),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, HelloError> {
        let first = self.parse_hex_quad()?;
        let scalar = match first {
            0xd800..=0xdbff => {
                if self.next_byte() != Some(b'\\') || self.next_byte() != Some(b'u') {
                    return Err(HelloError::MalformedJson);
                }
                let second = self.parse_hex_quad()?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(HelloError::MalformedJson);
                }
                0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(HelloError::MalformedJson),
            _ => u32::from(first),
        };
        char::from_u32(scalar).ok_or(HelloError::MalformedJson)
    }

    fn parse_hex_quad(&mut self) -> Result<u16, HelloError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self.next_byte().ok_or(HelloError::MalformedJson)?;
            let digit = match digit {
                b'0'..=b'9' => u16::from(digit - b'0'),
                b'a'..=b'f' => u16::from(digit - b'a' + 10),
                b'A'..=b'F' => u16::from(digit - b'A' + 10),
                _ => return Err(HelloError::MalformedJson),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<&'a str, HelloError> {
        let start = self.position;
        self.take(b'-');

        match self.next_byte() {
            Some(b'0') if matches!(self.peek(), Some(b'0'..=b'9')) => {
                return Err(HelloError::MalformedJson);
            }
            Some(b'0'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(HelloError::MalformedJson),
        }

        if self.take(b'.') {
            self.take_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            self.take_digits()?;
        }
        Ok(&self.input[start..self.position])
    }

    fn take_digits(&mut self) -> Result<(), HelloError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(HelloError::MalformedJson);
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        Ok(())
    }

    fn parse_literal(&mut self, literal: &str) -> Result<(), HelloError> {
        if self.input[self.position..].starts_with(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            Err(HelloError::MalformedJson)
        }
    }

    fn finish(&mut self) -> Result<(), HelloError> {
        self.skip_whitespace();
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(HelloError::MalformedJson)
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), HelloError> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(HelloError::MalformedJson)
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn next_character(&mut self) -> Option<char> {
        let character = self.input[self.position..].chars().next()?;
        self.position += character.len_utf8();
        Some(character)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HelloError, MAX_HELLO_BODY_LEN, MAX_PROCESS_NAME_LEN, encode_hello, validate_peer_hello,
    };

    #[test]
    fn encodes_exact_compact_client_hello() {
        assert_eq!(
            encode_hello("t1-touchid").unwrap(),
            br#"{"OSBuild":"Linux","BridgeXPCVersion":1.35,"ProcessName":"t1-touchid","MaxSupportedProtocolVersion":1}"#
        );
    }

    #[test]
    fn encodes_exact_compact_server_hello() {
        assert_eq!(
            encode_hello("xartstorageremoted").unwrap(),
            br#"{"OSBuild":"Linux","BridgeXPCVersion":1.35,"ProcessName":"xartstorageremoted","MaxSupportedProtocolVersion":1}"#
        );
    }

    #[test]
    fn escapes_process_name_as_json() {
        assert_eq!(
            encode_hello("synthetic\"\\\n\u{1f}é🚀").unwrap(),
            br#"{"OSBuild":"Linux","BridgeXPCVersion":1.35,"ProcessName":"synthetic\"\\\n\u001f\u00e9\ud83d\ude80","MaxSupportedProtocolVersion":1}"#
        );
    }

    #[test]
    fn validates_minimal_peer_hello() {
        validate_peer_hello(br#"{"MaxSupportedProtocolVersion":1}"#).unwrap();
    }

    #[test]
    fn accepts_unknown_nested_fields_and_json_types() {
        validate_peer_hello(
            br#"{"OSBuild":"Synthetic","unknown":{"array":[true,false,null,-2.5e+3,"\ud83d\ude80"]},"MaxSupportedProtocolVersion":1.5}"#,
        )
        .unwrap();
    }

    #[test]
    fn protocol_field_order_does_not_matter() {
        for body in [
            br#"{"MaxSupportedProtocolVersion":1,"other":0}"#.as_slice(),
            br#"{"other":0,"MaxSupportedProtocolVersion":1,"last":[]}"#.as_slice(),
            br#"{"other":0,"MaxSupportedProtocolVersion":1}"#.as_slice(),
        ] {
            validate_peer_hello(body).unwrap();
        }
    }

    #[test]
    fn recognizes_escaped_protocol_field_name() {
        validate_peer_hello(br#"{"Max\u0053upportedProtocolVersion":1}"#).unwrap();
    }

    #[test]
    fn rejects_missing_duplicate_or_unsupported_protocol_version() {
        assert_eq!(
            validate_peer_hello(br#"{"other":1}"#),
            Err(HelloError::MissingProtocolVersion)
        );
        assert_eq!(
            validate_peer_hello(
                br#"{"MaxSupportedProtocolVersion":1,"MaxSupportedProtocolVersion":2}"#
            ),
            Err(HelloError::DuplicateProtocolVersion)
        );
        for body in [
            br#"{"MaxSupportedProtocolVersion":0}"#.as_slice(),
            br#"{"MaxSupportedProtocolVersion":-1}"#.as_slice(),
            br#"{"MaxSupportedProtocolVersion":"1"}"#.as_slice(),
            br#"{"MaxSupportedProtocolVersion":true}"#.as_slice(),
        ] {
            assert_eq!(
                validate_peer_hello(body),
                Err(HelloError::UnsupportedProtocolVersion)
            );
        }
        validate_peer_hello(br#"{"MaxSupportedProtocolVersion":1e999}"#).unwrap();
    }

    #[test]
    fn rejects_non_object_malformed_and_trailing_input() {
        for body in [
            br"[]".as_slice(),
            br#"{"MaxSupportedProtocolVersion":01}"#.as_slice(),
            br#"{"MaxSupportedProtocolVersion":1,}"#.as_slice(),
            br#"{"MaxSupportedProtocolVersion":1} trailing"#.as_slice(),
            br#"{"MaxSupportedProtocolVersion":1,"bad":"\ud800"}"#.as_slice(),
            &[0xff],
        ] {
            assert_eq!(validate_peer_hello(body), Err(HelloError::MalformedJson));
        }
    }

    #[test]
    fn enforces_body_depth_key_and_process_name_bounds() {
        assert_eq!(
            validate_peer_hello(&vec![b' '; MAX_HELLO_BODY_LEN + 1]),
            Err(HelloError::BodyTooLarge)
        );

        let deep = format!(
            "{{\"MaxSupportedProtocolVersion\":1,\"nested\":{}0{}}}",
            "[".repeat(33),
            "]".repeat(33)
        );
        assert_eq!(
            validate_peer_hello(deep.as_bytes()),
            Err(HelloError::NestingTooDeep)
        );

        let long_key = format!(
            "{{\"{}\":0,\"MaxSupportedProtocolVersion\":1}}",
            "k".repeat(513)
        );
        assert_eq!(
            validate_peer_hello(long_key.as_bytes()),
            Err(HelloError::JsonKeyTooLong)
        );

        assert_eq!(encode_hello(""), Err(HelloError::InvalidProcessName));
        assert_eq!(
            encode_hello(&"p".repeat(MAX_PROCESS_NAME_LEN + 1)),
            Err(HelloError::InvalidProcessName)
        );
    }

    #[test]
    fn errors_do_not_include_payload_content() {
        let marker = "SYNTHETIC_SECRET_MARKER";
        let error = validate_peer_hello(format!("{{\"{marker}\":").as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(marker));
    }
}
