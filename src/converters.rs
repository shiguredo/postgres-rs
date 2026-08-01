// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 値の変換処理。
//!
//! PostgreSQL のテキスト形式 (クエリ結果・パラメータ) を
//! `Value` に変換する。バイナリ形式のサポートはまだない。

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
    Text(String),
    Bytes(Vec<u8>),
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
            Value::Text(s) => Some(s.as_bytes().to_vec()),
            Value::Bytes(b) => Some(escape_bytea(b).into_bytes()),
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
        oid::DATE => convert_date,
        oid::TIME => convert_time,
        oid::TIMESTAMP => convert_timestamp,
        oid::TIMESTAMPTZ => convert_timestamptz,
        // TEXT / VARCHAR / BPCHAR / NAME / JSON / JSONB / NUMERIC / UUID /
        // 未知の型はテキストとして扱う。
        _ => convert_text,
    }
}

fn convert_text(s: &str) -> Value {
    Value::Text(s.to_string())
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
}
