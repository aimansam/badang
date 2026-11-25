// Badang — Payload Converter
// Parses shellcode from common formats into raw bytes.

/// Supported input formats for shellcode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadFormat {
    /// Raw hex bytes: "fc 48 83 e4 f0" or "fc4883e4f0"
    Hex,
    /// C-style array: {0xfc, 0x48, 0x83} or "\xfc\x48\x83"
    CArray,
    /// Python bytes: b'\xfc\x48' or b"\xfc\x48"
    PythonBytes,
    /// Rust byte array: [0xfc, 0x48, 0x83]
    RustArray,
    /// Comma-separated decimal: 252, 72, 131
    Decimal,
}

impl PayloadFormat {
    pub fn name(&self) -> &str {
        match self {
            Self::Hex => "Hex",
            Self::CArray => "C Array",
            Self::PythonBytes => "Python Bytes",
            Self::RustArray => "Rust Array",
            Self::Decimal => "Decimal",
        }
    }

    pub fn all() -> &'static [PayloadFormat] {
        &[
            Self::Hex,
            Self::CArray,
            Self::PythonBytes,
            Self::RustArray,
            Self::Decimal,
        ]
    }

    pub fn placeholder(&self) -> &str {
        match self {
            Self::Hex => "fc 48 83 e4 f0 e8 cc 00 00 00 ...",
            Self::CArray => "\\xfc\\x48\\x83\\xe4  or  {0xfc, 0x48, 0x83}",
            Self::PythonBytes => "b'\\xfc\\x48\\x83\\xe4\\xf0'",
            Self::RustArray => "[0xfc, 0x48, 0x83, 0xe4, 0xf0]",
            Self::Decimal => "252, 72, 131, 228, 240",
        }
    }
}

/// Auto-detect the format from the input text.
pub fn detect_format(input: &str) -> PayloadFormat {
    let trimmed = input.trim();
    if trimmed.starts_with("b'") || trimmed.starts_with("b\"") {
        return PayloadFormat::PythonBytes;
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        if trimmed.contains("0x") || trimmed.contains("0X") {
            return PayloadFormat::RustArray;
        }
        return PayloadFormat::Decimal;
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return PayloadFormat::CArray;
    }
    if trimmed.contains("\\x") {
        return PayloadFormat::CArray;
    }
    if trimmed.contains(',') {
        let has_hex_prefix = trimmed.contains("0x") || trimmed.contains("0X");
        if has_hex_prefix {
            return PayloadFormat::CArray;
        }
        return PayloadFormat::Decimal;
    }
    PayloadFormat::Hex
}

/// Parse shellcode from text in the given format.
pub fn parse(input: &str, format: PayloadFormat) -> Result<Vec<u8>, String> {
    let result = match format {
        PayloadFormat::Hex => parse_hex(input),
        PayloadFormat::CArray => parse_c_array(input),
        PayloadFormat::PythonBytes => parse_python_bytes(input),
        PayloadFormat::RustArray => parse_rust_array(input),
        PayloadFormat::Decimal => parse_decimal(input),
    }?;
    if result.is_empty() {
        return Err("no bytes parsed from input".to_string());
    }
    Ok(result)
}

/// Auto-detect format and parse.
pub fn auto_parse(input: &str) -> Result<(Vec<u8>, PayloadFormat), String> {
    let format = detect_format(input);
    let bytes = parse(input, format)?;
    Ok((bytes, format))
}

/// Format bytes as a hex dump (16 bytes per line with ASCII sidebar).
pub fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        out.push_str(&format!("{:08x}  ", offset));

        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                out.push(' ');
            }
        }
        // Pad if less than 16 bytes
        let pad = 16 - chunk.len();
        for j in 0..pad {
            out.push_str("   ");
            if chunk.len() + j == 7 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

/// Format bytes as a C array string.
pub fn to_c_array(bytes: &[u8]) -> String {
    let mut out = String::from("unsigned char buf[] = {\n");
    for (i, chunk) in bytes.chunks(12).enumerate() {
        out.push_str("    ");
        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("0x{:02x}", byte));
            if i * 12 + j < bytes.len() - 1 {
                out.push_str(", ");
            }
        }
        out.push('\n');
    }
    out.push_str("};\n");
    out
}

/// Format bytes as a Python byte string.
pub fn to_python_bytes(bytes: &[u8]) -> String {
    let mut out = String::from("buf = b'");
    for byte in bytes {
        out.push_str(&format!("\\x{:02x}", byte));
    }
    out.push('\'');
    out
}

/// Format bytes as a Rust byte array.
pub fn to_rust_array(bytes: &[u8]) -> String {
    let mut out = format!("let buf: [u8; {}] = [\n", bytes.len());
    for chunk in bytes.chunks(12) {
        out.push_str("    ");
        for byte in chunk {
            out.push_str(&format!("0x{:02x}, ", byte));
        }
        out.push('\n');
    }
    out.push_str("];\n");
    out
}

// --- Parsers ---

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
        .collect();
    let hex_str: String = cleaned.split_whitespace().collect();
    if !hex_str.len().is_multiple_of(2) {
        return Err("hex string has odd number of characters".to_string());
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {}: {}", i / 2, e))
        })
        .collect()
}

fn parse_c_array(input: &str) -> Result<Vec<u8>, String> {
    let cleaned = input
        .trim()
        .trim_start_matches(['{', '"'])
        .trim_end_matches(['}', '"', ';']);

    if cleaned.contains("\\x") {
        return parse_escape_hex(cleaned);
    }

    cleaned
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let s = s.trim().trim_end_matches(|c: char| !c.is_ascii_hexdigit());
            let hex = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u8::from_str_radix(hex, 16).map_err(|e| format!("invalid byte '{}': {}", s, e))
        })
        .collect()
}

fn parse_python_bytes(input: &str) -> Result<Vec<u8>, String> {
    let cleaned = input
        .trim()
        .trim_start_matches("b'")
        .trim_start_matches("b\"")
        .trim_end_matches('\'')
        .trim_end_matches('"');
    parse_escape_hex(cleaned)
}

fn parse_escape_hex(input: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') | Some('X') => {
                    let hi = chars.next().ok_or("unexpected end after \\x")?;
                    let lo = chars.next().ok_or("unexpected end after \\x")?;
                    let hex = format!("{}{}", hi, lo);
                    let byte = u8::from_str_radix(&hex, 16)
                        .map_err(|e| format!("invalid \\x escape '{}': {}", hex, e))?;
                    bytes.push(byte);
                }
                Some('0') => bytes.push(0),
                Some('n') => bytes.push(b'\n'),
                Some('r') => bytes.push(b'\r'),
                Some('t') => bytes.push(b'\t'),
                Some(other) => {
                    return Err(format!("unknown escape '\\{}'", other));
                }
                None => return Err("unexpected end after backslash".to_string()),
            }
        }
        // Skip whitespace, commas, quotes, and other formatting
    }
    Ok(bytes)
}

fn parse_rust_array(input: &str) -> Result<Vec<u8>, String> {
    let cleaned = input.trim().trim_start_matches('[').trim_end_matches(']');
    cleaned
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let hex = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u8::from_str_radix(hex, 16).map_err(|e| format!("invalid byte '{}': {}", s, e))
        })
        .collect()
}

fn parse_decimal(input: &str) -> Result<Vec<u8>, String> {
    let cleaned = input.trim().trim_start_matches('[').trim_end_matches(']');
    cleaned
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.trim()
                .parse::<u8>()
                .map_err(|e| format!("invalid decimal byte '{}': {}", s, e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_spaced() {
        let bytes = parse("fc 48 83 e4 f0", PayloadFormat::Hex).unwrap();
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83, 0xe4, 0xf0]);
    }

    #[test]
    fn test_parse_hex_compact() {
        let bytes = parse("fc4883e4f0", PayloadFormat::Hex).unwrap();
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83, 0xe4, 0xf0]);
    }

    #[test]
    fn test_parse_c_array_braces() {
        let bytes = parse("{0xfc, 0x48, 0x83}", PayloadFormat::CArray).unwrap();
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83]);
    }

    #[test]
    fn test_parse_c_array_escape() {
        let bytes = parse("\\xfc\\x48\\x83\\xe4", PayloadFormat::CArray).unwrap();
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83, 0xe4]);
    }

    #[test]
    fn test_parse_python_bytes() {
        let bytes = parse("b'\\xfc\\x48\\x83'", PayloadFormat::PythonBytes).unwrap();
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83]);
    }

    #[test]
    fn test_parse_rust_array() {
        let bytes = parse("[0xfc, 0x48, 0x83]", PayloadFormat::RustArray).unwrap();
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83]);
    }

    #[test]
    fn test_parse_decimal() {
        let bytes = parse("252, 72, 131", PayloadFormat::Decimal).unwrap();
        assert_eq!(bytes, vec![252, 72, 131]);
    }

    #[test]
    fn test_auto_detect_hex() {
        let (bytes, fmt) = auto_parse("fc 48 83 e4 f0").unwrap();
        assert_eq!(fmt, PayloadFormat::Hex);
        assert_eq!(bytes, vec![0xfc, 0x48, 0x83, 0xe4, 0xf0]);
    }

    #[test]
    fn test_auto_detect_python() {
        let (bytes, fmt) = auto_parse("b'\\xfc\\x48'").unwrap();
        assert_eq!(fmt, PayloadFormat::PythonBytes);
        assert_eq!(bytes, vec![0xfc, 0x48]);
    }

    #[test]
    fn test_auto_detect_c_array() {
        let (bytes, fmt) = auto_parse("{0xfc, 0x48}").unwrap();
        assert_eq!(fmt, PayloadFormat::CArray);
        assert_eq!(bytes, vec![0xfc, 0x48]);
    }

    #[test]
    fn test_auto_detect_decimal() {
        let (bytes, fmt) = auto_parse("252, 72, 131").unwrap();
        assert_eq!(fmt, PayloadFormat::Decimal);
        assert_eq!(bytes, vec![252, 72, 131]);
    }

    #[test]
    fn test_hex_dump_format() {
        let dump = hex_dump(&[0xfc, 0x48, 0x83, 0xe4]);
        assert!(dump.contains("fc 48 83 e4"));
        assert!(dump.contains("00000000"));
    }

    #[test]
    fn test_to_c_array() {
        let out = to_c_array(&[0xfc, 0x48]);
        assert!(out.contains("0xfc"));
        assert!(out.contains("0x48"));
    }

    #[test]
    fn test_to_python_bytes() {
        let out = to_python_bytes(&[0xfc, 0x48]);
        assert_eq!(out, "buf = b'\\xfc\\x48'");
    }

    #[test]
    fn test_empty_input() {
        assert!(parse("", PayloadFormat::Hex).is_err());
    }

    #[test]
    fn test_odd_hex() {
        assert!(parse("fc4", PayloadFormat::Hex).is_err());
    }
}
