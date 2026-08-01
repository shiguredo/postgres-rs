// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 値の変換処理。
//!
//! PostgreSQL のテキスト形式 (クエリ結果・パラメータ) を
//! `Value` に変換する。バイナリ形式のサポートはまだない。
//!
//! INTERVAL / INET / CIDR / MACADDR / MONEY / 複合型 / enum / range は
//! テキストとして扱い、`Value::Text` にフォールバックする。
//! 将来のバージョンで個別の型として追加される可能性がある。

use crate::constants::oid;
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};

/// データベース上で扱う値の型。
///
/// 変換に失敗した場合は型安全性を優先して `Value::Text` にフォールバックする
/// (mysql-rs と同じ方針)。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int2(i16),
    Int4(i32),
    Int8(i64),
    Float4(f32),
    Float8(f64),
    /// 任意精度数値。PostgreSQL の `NUMERIC` は 2 進浮動小数点数で
    /// 表現できないため、テキストのまま保持する。
    Numeric(String),
    /// OID (オブジェクト識別子)。pg_type 等のカタログの型 OID に使う。
    Oid(u32),
    Text(String),
    Bytes(Vec<u8>),
    /// UUID。128 ビットの値として保持する。
    Uuid(u128),
    /// JSON / JSONB。テキスト表現のまま保持する。
    Json(String),
    /// 配列。要素型 OID と要素のリストを持つ。
    ///
    /// 要素型 OID はデコード時に使う。エンコード時は
    /// クエリ文脈から型が決まるため使わない。
    Array {
        element_type: u32,
        values: Vec<Value>,
    },
    Date(NaiveDate),
    Time(NaiveTime),
    Timestamp(NaiveDateTime),
    Timestamptz(DateTime<Utc>),
}

impl Value {
    /// クエリパラメータとして送信するバイト列 (テキスト形式) に変換する。
    ///
    /// `None` は SQL NULL を表す。
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Value::Null => None,
            Value::Bool(b) => Some(if *b { b"t" } else { b"f" }.to_vec()),
            Value::Int2(v) => Some(v.to_string().into_bytes()),
            Value::Int4(v) => Some(v.to_string().into_bytes()),
            Value::Int8(v) => Some(v.to_string().into_bytes()),
            Value::Float4(v) => Some(float_to_text(*v as f64).into_bytes()),
            Value::Float8(v) => Some(float_to_text(*v).into_bytes()),
            Value::Numeric(s) => Some(s.as_bytes().to_vec()),
            Value::Oid(v) => Some(v.to_string().into_bytes()),
            Value::Text(s) => Some(s.as_bytes().to_vec()),
            Value::Bytes(b) => Some(escape_bytea(b).into_bytes()),
            Value::Uuid(v) => Some(uuid_to_text(*v).into_bytes()),
            Value::Json(s) => Some(s.as_bytes().to_vec()),
            Value::Array { values, .. } => Some(encode_array(values).into_bytes()),
            Value::Date(d) => Some(d.format("%Y-%m-%d").to_string().into_bytes()),
            Value::Time(t) => Some(t.format("%H:%M:%S%.6f").to_string().into_bytes()),
            Value::Timestamp(dt) => {
                Some(dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string().into_bytes())
            }
            Value::Timestamptz(dt) => Some(
                dt.format("%Y-%m-%d %H:%M:%S%.6f%:z")
                    .to_string()
                    .into_bytes(),
            ),
        }
    }
}

/// 型変換関数の型エイリアス。
pub type Converter = fn(&str) -> Value;

/// テキスト形式の float を PostgreSQL の表記に変換する。
///
/// Rust の `{:?}` 表記は `inf` / `-inf` / `NaN` になるが、
/// PostgreSQL は `Infinity` / `-Infinity` / `NaN` を受け付ける。
fn float_to_text(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        if value > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        }
    } else {
        value.to_string()
    }
}

/// バイト列を bytea のテキスト形式 (\\x 16 進) に変換する。
fn escape_bytea(value: &[u8]) -> String {
    let mut out = String::from("\\x");
    for b in value {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// フィールド型 (OID) に対応するデコーダーを取得する。
pub fn decoder_for(type_oid: u32) -> Converter {
    match type_oid {
        oid::BOOL => convert_bool,
        oid::INT2 => convert_int2,
        oid::INT4 => convert_int4,
        oid::INT8 => convert_int8,
        oid::FLOAT4 => convert_float4,
        oid::FLOAT8 => convert_float8,
        oid::BYTEA => convert_bytea,
        oid::OID => convert_oid,
        oid::NUMERIC => convert_numeric,
        oid::UUID => convert_uuid,
        oid::JSON | oid::JSONB => convert_json,
        oid::DATE => convert_date,
        oid::TIME => convert_time,
        oid::TIMESTAMP => convert_timestamp,
        oid::TIMESTAMPTZ => convert_timestamptz,
        // 配列型。要素型 OID を固定した薄いラッパーで変換する。
        oid::array::BOOL => convert_bool_array,
        oid::array::BYTEA => convert_bytea_array,
        oid::array::INT2 => convert_int2_array,
        oid::array::INT4 => convert_int4_array,
        oid::array::INT8 => convert_int8_array,
        oid::array::FLOAT4 => convert_float4_array,
        oid::array::FLOAT8 => convert_float8_array,
        oid::array::NUMERIC => convert_numeric_array,
        oid::array::UUID => convert_uuid_array,
        oid::array::JSON => convert_json_array,
        oid::array::JSONB => convert_jsonb_array,
        oid::array::DATE => convert_date_array,
        oid::array::TIME => convert_time_array,
        oid::array::TIMESTAMP => convert_timestamp_array,
        oid::array::TIMESTAMPTZ => convert_timestamptz_array,
        // TEXT / VARCHAR / BPCHAR / NAME / CHAR / OID / JSON / JSONB /
        // 未知の型はテキストとして扱う。
        _ => convert_text,
    }
}

fn convert_text(s: &str) -> Value {
    Value::Text(s.to_string())
}

/// OID を u32 として保持する。
fn convert_oid(s: &str) -> Value {
    match s.parse() {
        Ok(v) => Value::Oid(v),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_bool(s: &str) -> Value {
    match s {
        "t" | "true" | "1" | "y" | "yes" | "on" => Value::Bool(true),
        "f" | "false" | "0" | "n" | "no" | "off" => Value::Bool(false),
        _ => Value::Text(s.to_string()),
    }
}

fn convert_int2(s: &str) -> Value {
    match s.parse() {
        Ok(v) => Value::Int2(v),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_int4(s: &str) -> Value {
    match s.parse() {
        Ok(v) => Value::Int4(v),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_int8(s: &str) -> Value {
    match s.parse() {
        Ok(v) => Value::Int8(v),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_float4(s: &str) -> Value {
    match parse_float(s) {
        Some(v) => Value::Float4(v as f32),
        None => Value::Text(s.to_string()),
    }
}

fn convert_float8(s: &str) -> Value {
    match parse_float(s) {
        Some(v) => Value::Float8(v),
        None => Value::Text(s.to_string()),
    }
}

/// PostgreSQL の float 表記をパースする。
fn parse_float(s: &str) -> Option<f64> {
    match s {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => s.parse().ok(),
    }
}

/// NUMERIC をテキストのまま保持する。
///
/// 数値として成立するか軽く検証し、成立しない場合は Text にフォールバックする。
fn convert_numeric(s: &str) -> Value {
    if is_numeric_text(s) {
        Value::Numeric(s.to_string())
    } else {
        Value::Text(s.to_string())
    }
}

/// NUMERIC のテキスト表記として成立するかどうかを検証する。
///
/// `[+-]? 数字 (.[数字]*)? ([eE][+-]?数字+)?` に加えて、
/// `NaN` / `Infinity` / `-Infinity` を受け付ける。
fn is_numeric_text(s: &str) -> bool {
    if matches!(s, "NaN" | "Infinity" | "-Infinity") {
        return true;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    let mut has_digit = false;
    let mut has_dot = false;
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' => {
                has_digit = true;
                i += 1;
            }
            b'.' if !has_dot => {
                has_dot = true;
                i += 1;
            }
            b'e' | b'E' => {
                // 指数表記は末尾にしか現れない。
                if !has_digit {
                    return false;
                }
                i += 1;
                if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                    i += 1;
                }
                if i >= bytes.len() || !bytes[i].is_ascii_digit() {
                    return false;
                }
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                return i == bytes.len();
            }
            _ => return false,
        }
    }
    has_digit
}

/// UUID を 128 ビットの値として保持する。
fn convert_uuid(s: &str) -> Value {
    // 8-4-4-4-12 の 36 文字形式をハイフンなしの 32 桁の 16 進数としてパースする。
    if s.len() != 36 {
        return Value::Text(s.to_string());
    }
    let mut bytes = [0u8; 16];
    let mut nibble_index = 0;
    for c in s.chars() {
        if c == '-' {
            continue;
        }
        let Some(v) = hex_val(c as u8) else {
            return Value::Text(s.to_string());
        };
        bytes[nibble_index / 2] |= if nibble_index % 2 == 0 { v << 4 } else { v };
        nibble_index += 1;
    }
    if nibble_index != 32 {
        return Value::Text(s.to_string());
    }
    Value::Uuid(u128::from_be_bytes(bytes))
}

/// 128 ビットの UUID 値を 8-4-4-4-12 形式の文字列に変換する。
fn uuid_to_text(value: u128) -> String {
    let bytes = value.to_be_bytes();
    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// JSON / JSONB をテキストのまま保持する。
fn convert_json(s: &str) -> Value {
    Value::Json(s.to_string())
}

fn convert_bytea(s: &str) -> Value {
    let Some(hex) = s.strip_prefix("\\x") else {
        return Value::Text(s.to_string());
    };
    if hex.len() % 2 != 0 {
        return Value::Text(s.to_string());
    }
    let mut bytes = Vec::new();
    let mut iter = hex.bytes();
    while let Some(hi) = iter.next() {
        // 長さは偶数と確認済みのため lo は必ず存在する。
        let lo = iter.next().expect("hex length is even as validated above");
        let (Some(hi), Some(lo)) = (hex_val(hi), hex_val(lo)) else {
            return Value::Text(s.to_string());
        };
        bytes.push((hi << 4) | lo);
    }
    Value::Bytes(bytes)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn convert_date(s: &str) -> Value {
    match NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        Ok(d) => Value::Date(d),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_time(s: &str) -> Value {
    match NaiveTime::parse_from_str(s, "%H:%M:%S%.f") {
        Ok(t) => Value::Time(t),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_timestamp(s: &str) -> Value {
    match NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        Ok(dt) => Value::Timestamp(dt),
        Err(_) => Value::Text(s.to_string()),
    }
}

fn convert_timestamptz(s: &str) -> Value {
    // オフセットは +09:00 / +0900 の両方が送られ得るため、
    // コロンを除いた形式に正規化してからパースする。
    let normalized = normalize_offset(s);
    match DateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S%.f%z") {
        Ok(dt) => Value::Timestamptz(dt.with_timezone(&Utc)),
        Err(_) => Value::Text(s.to_string()),
    }
}

/// 末尾のタイムゾーンオフセットを chrono がパースできる形式に正規化する。
///
/// PostgreSQL は `+09` / `+0900` / `+09:00` のいずれでも送るため、
/// コロンを除去して `±HH` は `±HH00` に補う。
/// `2024-01-01 12:00:00+09:00` を `2024-01-01 12:00:00+0900` にする。
/// 日付・時刻は空白区切りで、オフセットは時刻部分の直後に付く。
/// `BC` 付きの日付 (オフセットなし) はそのまま返す。
fn normalize_offset(s: &str) -> String {
    let Some(space) = s.rfind(' ') else {
        return s.to_string();
    };
    let (head, tail) = s.split_at(space + 1);
    match tail.find(['+', '-']) {
        Some(pos) => {
            let (time, offset) = tail.split_at(pos);
            let offset = offset.replace(':', "");
            // オフセットは ±HH (3 文字) または ±HHMM (5 文字) の形式。
            // ±HH は ±HH00 に補う。それ以外の形式はパースできないため、
            // そのまま返す (呼び出し側で Text にフォールバックする)。
            let normalized = match offset.len() {
                3 => format!("{}00", offset),
                5 => offset,
                _ => return s.to_string(),
            };
            format!("{}{}{}", head, time, normalized)
        }
        None => s.to_string(),
    }
}

/// テキスト形式の配列を `Value::Array` に変換する。
///
/// `element_oid` は要素型の OID で、各要素のデコードに使う。
/// 要素がさらに配列の場合 (多次元配列) は、
/// `decoder_for` の配列デコーダで再帰的に変換する。
fn convert_array(s: &str, element_oid: u32) -> Value {
    let Some(inner) = array_inner(s) else {
        return Value::Text(s.to_string());
    };
    let Some(elements) = split_array_elements(inner) else {
        return Value::Text(s.to_string());
    };
    let element_decoder = decoder_for(element_oid);
    let mut values = Vec::new();
    for element in elements {
        match element {
            None => values.push(Value::Null),
            Some(raw) => values.push(element_decoder(&raw)),
        }
    }
    Value::Array {
        element_type: element_oid,
        values,
    }
}

/// 配列リテラルの外側の波括弧を除去する。
///
/// 先頭が `{` で始まり末尾が `}` で終わらない場合は `None` を返す。
fn array_inner(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    // 空配列 `{}` は空の要素リストとして扱う。
    Some(inner)
}

/// 配列リテラルの内側をトップレベルの要素に分割する。
///
/// 要素の `None` は SQL NULL (引用符なしの `NULL`) を表す。
/// 引用符で囲まれた要素は引用符を除去し、エスケープを解決する。
/// 引用符の対応や波括弧の対応が不正な場合は `None` を返す。
fn split_array_elements(inner: &str) -> Option<Vec<Option<String>>> {
    // PostgreSQL は空配列 `{}` と空白だけの `{ }` を空の要素リストとして扱う。
    // `src/backend/utils/adt/arrayfuncs.c` の `ReadArrayStr` を参照。
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut elements = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut depth = 0usize;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_quote => {
                in_quote = true;
                current.push(c);
            }
            '"' if in_quote => {
                // 引用符内のエスケープされた引用符 \" を解決する。
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quote = false;
                    current.push(c);
                }
            }
            '\\' if in_quote => {
                // 引用符内のバックスラッシュは次の文字をエスケープする。
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '{' if !in_quote => {
                depth += 1;
                current.push(c);
            }
            '}' if !in_quote => {
                // 入れ子の波括弧が不正に閉じられた場合は失敗扱いにする。
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                current.push(c);
            }
            ',' if !in_quote && depth == 0 => {
                elements.push(normalize_array_element(&current));
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    // 引用符が閉じられていない場合は失敗扱いにする。
    if in_quote || depth != 0 {
        return None;
    }
    elements.push(normalize_array_element(&current));
    Some(elements)
}

/// 配列要素の生テキストを正規化する。
///
/// 引用符なしの `NULL` は SQL NULL を表すため `None` を返す。
/// 引用符で囲まれた要素は引用符を除去し、エスケープを解決する。
fn normalize_array_element(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("null") {
        return None;
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                // バックスラッシュは次の文字をエスケープする。
                if let Some(next) = chars.next() {
                    out.push(next);
                } else {
                    return Some(raw.to_string());
                }
            } else {
                out.push(c);
            }
        }
        return Some(out);
    }
    Some(raw.to_string())
}

/// 要素のリストをテキスト形式の配列リテラルにエンコードする。
///
/// 要素の `Value::Null` は引用符なしの `NULL` としてエンコードする。
/// 空白・カンマ・波括弧・引用符・バックスラッシュを含む要素は
/// 二重引用符で囲み、引用符とバックスラッシュをエスケープする。
fn encode_array(values: &[Value]) -> String {
    let mut out = String::from("{");
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&encode_array_element(value));
    }
    out.push('}');
    out
}

fn encode_array_element(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_string(),
        other => {
            let Some(bytes) = other.to_bytes() else {
                return "NULL".to_string();
            };
            let s = String::from_utf8_lossy(&bytes).into_owned();
            if s.is_empty()
                || s.eq_ignore_ascii_case("null")
                || s.chars()
                    .any(|c| matches!(c, '{' | '}' | ',' | '"' | '\\' | ' ' | '\t' | '\n' | '\r'))
            {
                let mut quoted = String::with_capacity(s.len() + 2);
                quoted.push('"');
                for c in s.chars() {
                    if c == '"' || c == '\\' {
                        quoted.push('\\');
                    }
                    quoted.push(c);
                }
                quoted.push('"');
                quoted
            } else {
                s
            }
        }
    }
}

// 以下は要素型 OID ごとの薄いラッパー。
//
// `Converter` が fn ポインタのため要素 OID をキャプチャできないことから、
// 配列型 OID ごとにラッパーを用意している。
fn convert_bool_array(s: &str) -> Value {
    convert_array(s, oid::BOOL)
}
fn convert_bytea_array(s: &str) -> Value {
    convert_array(s, oid::BYTEA)
}
fn convert_int2_array(s: &str) -> Value {
    convert_array(s, oid::INT2)
}
fn convert_int4_array(s: &str) -> Value {
    convert_array(s, oid::INT4)
}
fn convert_int8_array(s: &str) -> Value {
    convert_array(s, oid::INT8)
}
fn convert_float4_array(s: &str) -> Value {
    convert_array(s, oid::FLOAT4)
}
fn convert_float8_array(s: &str) -> Value {
    convert_array(s, oid::FLOAT8)
}
fn convert_numeric_array(s: &str) -> Value {
    convert_array(s, oid::NUMERIC)
}
fn convert_uuid_array(s: &str) -> Value {
    convert_array(s, oid::UUID)
}
fn convert_json_array(s: &str) -> Value {
    convert_array(s, oid::JSON)
}
fn convert_jsonb_array(s: &str) -> Value {
    convert_array(s, oid::JSONB)
}
fn convert_date_array(s: &str) -> Value {
    convert_array(s, oid::DATE)
}
fn convert_time_array(s: &str) -> Value {
    convert_array(s, oid::TIME)
}
fn convert_timestamp_array(s: &str) -> Value {
    convert_array(s, oid::TIMESTAMP)
}
fn convert_timestamptz_array(s: &str) -> Value {
    convert_array(s, oid::TIMESTAMPTZ)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes() {
        assert_eq!(Value::Null.to_bytes(), None);
        assert_eq!(Value::Bool(true).to_bytes(), Some(b"t".to_vec()));
        assert_eq!(Value::Int8(-42).to_bytes(), Some(b"-42".to_vec()));
        assert_eq!(
            Value::Text("hello".to_string()).to_bytes(),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            Value::Bytes(vec![0x00, 0xff]).to_bytes(),
            Some(b"\\x00ff".to_vec())
        );
    }

    #[test]
    fn test_float_to_text_special_values() {
        assert_eq!(float_to_text(f64::NAN), "NaN");
        assert_eq!(float_to_text(f64::INFINITY), "Infinity");
        assert_eq!(float_to_text(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(float_to_text(1.5), "1.5");
    }

    #[test]
    fn test_decoder_for_unknown_oid_falls_back_to_text() {
        assert_eq!(
            decoder_for(999_999)("anything"),
            Value::Text("anything".to_string())
        );
    }

    #[test]
    fn test_normalize_offset() {
        assert_eq!(
            normalize_offset("2024-01-01 12:00:00+09:00"),
            "2024-01-01 12:00:00+0900"
        );
        assert_eq!(
            normalize_offset("2024-01-01 12:00:00+0900"),
            "2024-01-01 12:00:00+0900"
        );
    }

    #[test]
    fn test_convert_numeric() {
        assert_eq!(
            convert_numeric("123.45"),
            Value::Numeric("123.45".to_string())
        );
        assert_eq!(
            convert_numeric("-0.001"),
            Value::Numeric("-0.001".to_string())
        );
        assert_eq!(
            convert_numeric("1e+05"),
            Value::Numeric("1e+05".to_string())
        );
        assert_eq!(convert_numeric("NaN"), Value::Numeric("NaN".to_string()));
        assert_eq!(
            convert_numeric("Infinity"),
            Value::Numeric("Infinity".to_string())
        );
        // 数値として成立しない場合は Text にフォールバックする。
        assert_eq!(convert_numeric("12a34"), Value::Text("12a34".to_string()));
    }

    #[test]
    fn test_convert_uuid() {
        let value = convert_uuid("123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(value, Value::Uuid(0x123e4567e89b12d3a456426614174000));
        // UUID をエンコードし直すと元の文字列に戻る。
        assert_eq!(
            uuid_to_text(0x123e4567e89b12d3a456426614174000),
            "123e4567-e89b-12d3-a456-426614174000"
        );
        // 形式が不正な場合は Text にフォールバックする。
        assert_eq!(
            convert_uuid("not-a-uuid"),
            Value::Text("not-a-uuid".to_string())
        );
        assert_eq!(
            convert_uuid("123e4567e89b12d3a45642661417400"),
            Value::Text("123e4567e89b12d3a45642661417400".to_string())
        );
    }

    #[test]
    fn test_convert_json() {
        assert_eq!(
            convert_json("{\"a\": 1}"),
            Value::Json("{\"a\": 1}".to_string())
        );
    }

    #[test]
    fn test_convert_array_int4() {
        let value = convert_int4_array("{1,2,3}");
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::INT4,
                values: vec![Value::Int4(1), Value::Int4(2), Value::Int4(3)],
            }
        );
    }

    #[test]
    fn test_convert_array_text_with_quotes() {
        let value = convert_array("{\"a b\",\"c,d\",\"e\\\"f\"}", oid::TEXT);
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::TEXT,
                values: vec![
                    Value::Text("a b".to_string()),
                    Value::Text("c,d".to_string()),
                    Value::Text("e\"f".to_string()),
                ],
            }
        );
    }

    #[test]
    fn test_convert_array_with_null() {
        let value = convert_int4_array("{1,NULL,3}");
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::INT4,
                values: vec![Value::Int4(1), Value::Null, Value::Int4(3)],
            }
        );
        // 引用符付きの "NULL" は文字列として扱う。
        let value = convert_array("{NULL,\"NULL\"}", oid::TEXT);
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::TEXT,
                values: vec![Value::Null, Value::Text("NULL".to_string())],
            }
        );
    }

    #[test]
    fn test_convert_array_invalid() {
        // 波括弧で囲まれていない場合は Text にフォールバックする。
        assert_eq!(
            convert_int4_array("1,2,3"),
            Value::Text("1,2,3".to_string())
        );
        // 引用符が閉じられていない場合は Text にフォールバックする。
        assert_eq!(
            convert_int4_array("{\"a}"),
            Value::Text("{\"a}".to_string())
        );
    }

    #[test]
    fn test_convert_array_empty() {
        // PostgreSQL の空配列 `{}` は空の要素リストとして扱う。
        assert_eq!(
            convert_int4_array("{}"),
            Value::Array {
                element_type: oid::INT4,
                values: Vec::new(),
            }
        );
        // 空白だけの `{ }` も空の要素リストとして扱う。
        assert_eq!(
            convert_int4_array("{ }"),
            Value::Array {
                element_type: oid::INT4,
                values: Vec::new(),
            }
        );
        // 引用符付きの空文字列 `{""}` は空文字列 1 要素の配列として扱う。
        assert_eq!(
            convert_int4_array("{\"\"}"),
            Value::Array {
                element_type: oid::INT4,
                values: vec![Value::Text(String::new())],
            }
        );
    }

    #[test]
    fn test_encode_array() {
        assert_eq!(
            encode_array(&[Value::Int4(1), Value::Int4(2), Value::Int4(3)]),
            "{1,2,3}"
        );
        assert_eq!(
            encode_array(&[Value::Null, Value::Text("a b".to_string())]),
            "{NULL,\"a b\"}"
        );
        assert_eq!(
            encode_array(&[Value::Text("NULL".to_string())]),
            "{\"NULL\"}"
        );
        assert_eq!(
            encode_array(&[Value::Text("a\"b".to_string())]),
            "{\"a\\\"b\"}"
        );
    }

    #[test]
    fn test_array_round_trip() {
        // エンコードした配列をデコードすると同じ値になる。
        let original = Value::Array {
            element_type: oid::INT4,
            values: vec![Value::Int4(1), Value::Null, Value::Int4(-3)],
        };
        let bytes = original.to_bytes().expect("配列のエンコードに成功しました");
        let text = String::from_utf8(bytes).expect("UTF-8 です");
        assert_eq!(convert_int4_array(&text), original);
    }
}
