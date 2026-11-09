//! Shared tooling for the reference binaries: a minimal JSON reader and writer and the network
//! options object of conformance/PROTOCOL.md. Not specification; standard library only.

use bcs::*;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------------------------
// Minimal JSON

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] as char).is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn parse(&mut self) -> Result<Json, String> {
        self.ws();
        if self.i >= self.s.len() {
            return Err("unexpected end".into());
        }
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut map = BTreeMap::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(map));
                }
                loop {
                    self.ws();
                    let key = match self.parse()? {
                        Json::Str(k) => k,
                        _ => return Err("object key must be a string".into()),
                    };
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return Err("expected ':'".into());
                    }
                    self.i += 1;
                    let value = self.parse()?;
                    map.insert(key, value);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(map));
                        }
                        _ => return Err("expected ',' or '}'".into()),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.parse()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err("expected ',' or ']'".into()),
                    }
                }
            }
            b'"' => {
                self.i += 1;
                let mut out = String::new();
                loop {
                    let c = *self.s.get(self.i).ok_or("unterminated string")?;
                    self.i += 1;
                    match c {
                        b'"' => return Ok(Json::Str(out)),
                        b'\\' => {
                            let e = *self.s.get(self.i).ok_or("bad escape")?;
                            self.i += 1;
                            match e {
                                b'"' => out.push('"'),
                                b'\\' => out.push('\\'),
                                b'/' => out.push('/'),
                                b'n' => out.push('\n'),
                                b't' => out.push('\t'),
                                b'r' => out.push('\r'),
                                b'b' => out.push('\u{8}'),
                                b'f' => out.push('\u{c}'),
                                b'u' => {
                                    let hex = std::str::from_utf8(self.s.get(self.i..self.i + 4).ok_or("bad \\u")?)
                                        .map_err(|_| "bad \\u")?;
                                    let code = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u")?;
                                    self.i += 4;
                                    out.push(char::from_u32(code).unwrap_or('?'));
                                }
                                _ => return Err("bad escape".into()),
                            }
                        }
                        _ => {
                            let start = self.i - 1;
                            let mut end = self.i;
                            while end < self.s.len() && (self.s[end] & 0xc0) == 0x80 {
                                end += 1;
                            }
                            out.push_str(std::str::from_utf8(&self.s[start..end]).map_err(|_| "bad utf8")?);
                            self.i = end;
                        }
                    }
                }
            }
            b't' if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Json::Bool(true))
            }
            b'f' if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Json::Bool(false))
            }
            b'n' if self.s[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(Json::Null)
            }
            _ => {
                let start = self.i;
                while self.i < self.s.len() && b"+-0123456789.eE".contains(&self.s[self.i]) {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| "bad number")?;
                if text.is_empty() {
                    return Err(format!("unexpected character at {}", start));
                }
                if let Ok(v) = text.parse::<i128>() {
                    Ok(Json::Int(v))
                } else {
                    text.parse::<f64>().map(Json::Float).map_err(|_| format!("bad number {text}"))
                }
            }
        }
    }
}

pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    let v = p.parse()?;
    p.ws();
    if p.i != p.s.len() {
        return Err("trailing characters".into());
    }
    Ok(v)
}

pub fn write_json(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::Float(f) => out.push_str(&f.to_string()),
        Json::Str(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Json::Arr(items) => {
            out.push('[');
            for (k, item) in items.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Json::Obj(map) => {
            out.push('{');
            for (k, (key, value)) in map.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                write_json(&Json::Str(key.clone()), out);
                out.push(':');
                write_json(value, out);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Network options (PROTOCOL.md section 4.8 `options`, section 5 `{options}`)

pub fn parse_network(name: &str) -> Result<Network, String> {
    match name {
        "main" => Ok(Network::Main),
        "testnet3" => Ok(Network::Testnet3),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unknown network {other}")),
    }
}

pub fn parse_network_options(value: Option<&Json>) -> Result<NetworkOptions, String> {
    let mut options = NetworkOptions::default();
    let opts = match value {
        None | Some(Json::Null) => return Ok(options),
        Some(Json::Obj(opts)) => opts,
        Some(_) => return Err("options must be an object".into()),
    };
    for (key, value) in opts {
        match (key.as_str(), value) {
            ("testactivationheight", Json::Obj(heights)) => {
                for (name, height) in heights {
                    match height {
                        Json::Int(h) if *h >= 0 && *h <= i32::MAX as i128 => options.activation_heights.push((name.clone(), *h as i32)),
                        _ => return Err("activation height must be a non-negative integer".into()),
                    }
                }
            }
            ("test", Json::Arr(tests)) => {
                for test in tests {
                    match test {
                        Json::Str(name) if name == "bip94" => options.enforce_bip94 = true,
                        _ => return Err(format!("unknown test option {test:?}")),
                    }
                }
            }
            ("signetchallenge", Json::Str(challenge)) => {
                let bytes = hex_decode(challenge).filter(|_| !challenge.bytes().any(|c| c.is_ascii_uppercase()));
                options.signet_challenge = Some(bytes.ok_or("signetchallenge must be lowercase hex")?);
            }
            _ => return Err(format!("unknown or malformed option {key}")),
        }
    }
    Ok(options)
}
