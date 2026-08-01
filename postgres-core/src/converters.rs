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
use crate::error::{Error, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};

/// データベース上で扱う値の型。
///
/// 変換に失敗した場合は型安全性を優先して `Value::Text` にフォールバックする
/// (mysql-rs と同じ方針)。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// SQL の NULL を表す。
    Null,
    /// PostgreSQL の `BOOLEAN` の値を保持する。
    Bool(bool),
    /// PostgreSQL の `SMALLINT` (16 ビット整数) の値を保持する。
    Int2(i16),
    /// PostgreSQL の `INTEGER` (32 ビット整数) の値を保持する。
    Int4(i32),
    /// PostgreSQL の `BIGINT` (64 ビット整数) の値を保持する。
    Int8(i64),
    /// PostgreSQL の `REAL` (32 ビット浮動小数点数) の値を保持する。
    Float4(f32),
    /// PostgreSQL の `DOUBLE PRECISION` (64 ビット浮動小数点数) の値を保持する。
    Float8(f64),
    /// 任意精度数値。PostgreSQL の `NUMERIC` は 2 進浮動小数点数で
    /// 表現できないため、テキストのまま保持する。
    Numeric(String),
    /// OID (オブジェクト識別子)。pg_type 等のカタログの型 OID に使う。
    Oid(u32),
    /// PostgreSQL のテキスト型 (`TEXT` / `VARCHAR` 等) の文字列を保持する。
    Text(String),
    /// PostgreSQL の `BYTEA` のバイト列を保持する。
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
        /// 要素型の OID。
        element_type: u32,
        /// 要素のリスト。SQL NULL は `Value::Null` で表す。
        values: Vec<Value>,
    },
    /// PostgreSQL の `DATE` (日付) を保持する。
    Date(NaiveDate),
    /// PostgreSQL の `TIME` (時刻) を保持する。
    Time(NaiveTime),
    /// PostgreSQL の `TIMESTAMP` (タイムゾーンなしの日時) を保持する。
    Timestamp(NaiveDateTime),
    /// PostgreSQL の `TIMESTAMPTZ` (UTC に正規化したタイムゾーン付き日時) を保持する。
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
        oid::array::CHAR => convert_char_array,
        oid::array::NAME => convert_name_array,
        oid::array::INT2 => convert_int2_array,
        oid::array::INT4 => convert_int4_array,
        oid::array::TEXT => convert_text_array,
        oid::array::BPCHAR => convert_bpchar_array,
        oid::array::VARCHAR => convert_varchar_array,
        oid::array::INT8 => convert_int8_array,
        oid::array::FLOAT4 => convert_float4_array,
        oid::array::FLOAT8 => convert_float8_array,
        oid::array::OID => convert_oid_array,
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
    // 8-4-4-4-12 の 36 文字形式だけを UUID として扱う。
    // ハイフンの位置と 16 進数字であることを先に検証し、
    // 不正な入力でインデックス外アクセスを起こさない。
    if s.len() != 36 {
        return Value::Text(s.to_string());
    }
    let hyphen_positions = [8, 13, 18, 23];
    let mut digits = String::new();
    for (index, byte) in s.bytes().enumerate() {
        if hyphen_positions.contains(&index) {
            if byte != b'-' {
                return Value::Text(s.to_string());
            }
        } else if byte.is_ascii_hexdigit() {
            digits.push(byte as char);
        } else {
            return Value::Text(s.to_string());
        }
    }
    match u128::from_str_radix(&digits, 16) {
        Ok(value) => Value::Uuid(value),
        Err(_) => Value::Text(s.to_string()),
    }
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
    // 16 進形式 (`\x...`) とエスケープ形式 (`\ooo` や `\\`) の両方を扱う。
    // bytea_output はデフォルトで hex だが、escape に設定することもできる。
    if let Some(hex) = s.strip_prefix("\\x") {
        if hex.len() % 2 != 0 {
            return Value::Text(s.to_string());
        }
        let mut bytes = Vec::new();
        let mut iter = hex.bytes();
        while let Some(hi) = iter.next() {
            let Some(lo) = iter.next() else {
                return Value::Text(s.to_string());
            };
            let (Some(hi), Some(lo)) = (hex_val(hi), hex_val(lo)) else {
                return Value::Text(s.to_string());
            };
            bytes.push((hi << 4) | lo);
        }
        return Value::Bytes(bytes);
    }

    let mut bytes = Vec::new();
    let mut iter = s.bytes();
    while let Some(byte) = iter.next() {
        match byte {
            b'\\' => match iter.next() {
                Some(b'\\') => bytes.push(b'\\'),
                Some(first @ b'0'..=b'7') => {
                    let Some(second @ b'0'..=b'7') = iter.next() else {
                        return Value::Text(s.to_string());
                    };
                    let Some(third @ b'0'..=b'7') = iter.next() else {
                        return Value::Text(s.to_string());
                    };
                    // 8 ビットに収まるのは 0o377 まで。
                    if first > b'3' {
                        return Value::Text(s.to_string());
                    }
                    let value = ((first - b'0') << 6) | ((second - b'0') << 3) | (third - b'0');
                    bytes.push(value);
                }
                _ => return Value::Text(s.to_string()),
            },
            byte => bytes.push(byte),
        }
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

/// 配列の最大次元数。PostgreSQL の `MAXDIM` と同じ値。
const MAX_ARRAY_DEPTH: usize = 6;

/// 配列リテラルの要素。
enum ArrayElement {
    /// SQL NULL。
    Null,
    /// 要素のテキスト表現。
    Value(String),
    /// 多次元配列の入れ子。
    Nested(Vec<ArrayElement>),
}

/// テキスト形式の配列を `Value::Array` に変換する。
///
/// `element_oid` は要素型の OID で、各要素のデコードに使う。
/// 多次元配列は入れ子の `Value::Array` に変換する。
fn convert_array(s: &str, element_oid: u32) -> Value {
    let Some(elements) = parse_array_literal(s) else {
        return Value::Text(s.to_string());
    };
    Value::Array {
        element_type: element_oid,
        values: convert_array_elements(elements, element_oid),
    }
}

/// 解析済みの配列要素を `Value` に変換する。
fn convert_array_elements(elements: Vec<ArrayElement>, element_oid: u32) -> Vec<Value> {
    let mut values = Vec::new();
    for element in elements {
        match element {
            ArrayElement::Null => values.push(Value::Null),
            ArrayElement::Value(raw) => values.push(decoder_for(element_oid)(&raw)),
            ArrayElement::Nested(children) => values.push(Value::Array {
                element_type: element_oid,
                values: convert_array_elements(children, element_oid),
            }),
        }
    }
    values
}

/// 配列リテラルを解析する。
///
/// PostgreSQL の配列入力形式のうち、サーバーが出力する形式
/// (`{...}`、二重引用符、バックスラッシュエスケープ) を扱う。
/// 次元を指定する `[1:2]={...}` 形式には対応しない。
fn parse_array_literal(s: &str) -> Option<Vec<ArrayElement>> {
    let chars: Vec<char> = s.chars().collect();
    let mut index = 0;
    skip_array_whitespace(&chars, &mut index);
    let elements = parse_array_level(&chars, &mut index, 0)?;
    skip_array_whitespace(&chars, &mut index);
    if index != chars.len() {
        return None;
    }
    Some(elements)
}

/// 1 段階の波括弧を解析する。
fn parse_array_level(chars: &[char], index: &mut usize, depth: usize) -> Option<Vec<ArrayElement>> {
    if depth >= MAX_ARRAY_DEPTH {
        return None;
    }
    if chars.get(*index) != Some(&'{') {
        return None;
    }
    *index += 1;
    skip_array_whitespace(chars, index);

    let mut elements = Vec::new();
    if chars.get(*index) == Some(&'}') {
        *index += 1;
        return Some(elements);
    }

    loop {
        elements.push(parse_array_element(chars, index, depth)?);
        skip_array_whitespace(chars, index);
        match chars.get(*index) {
            Some(',') => {
                *index += 1;
                skip_array_whitespace(chars, index);
                // 末尾のカンマは受け付けない。
                if chars.get(*index) == Some(&'}') {
                    return None;
                }
            }
            Some('}') => {
                *index += 1;
                return Some(elements);
            }
            _ => return None,
        }
    }
}

/// 配列の 1 要素を解析する。
fn parse_array_element(chars: &[char], index: &mut usize, depth: usize) -> Option<ArrayElement> {
    match chars.get(*index)? {
        '"' => parse_quoted_array_element(chars, index).map(ArrayElement::Value),
        '{' => parse_array_level(chars, index, depth + 1).map(ArrayElement::Nested),
        _ => parse_unquoted_array_element(chars, index),
    }
}

/// 二重引用符で囲まれた要素を解析する。
///
/// 引用符内のバックスラッシュは次の文字をエスケープする。
fn parse_quoted_array_element(chars: &[char], index: &mut usize) -> Option<String> {
    *index += 1;
    let mut value = String::new();
    loop {
        let c = *chars.get(*index)?;
        *index += 1;
        match c {
            '\\' => {
                let escaped = *chars.get(*index)?;
                *index += 1;
                value.push(escaped);
            }
            '"' => break,
            _ => value.push(c),
        }
    }
    skip_array_whitespace(chars, index);
    Some(value)
}

/// 引用符なしの要素を解析する。
///
/// バックスラッシュは次の文字をエスケープする。
/// エスケープがある要素は `NULL` とみなさない。
fn parse_unquoted_array_element(chars: &[char], index: &mut usize) -> Option<ArrayElement> {
    let mut raw = Vec::new();
    // エスケープされた空白は要素の一部として扱うため、
    // 末尾の空白を削るときは最後の非空白文字の位置を別に覚えておく。
    let mut value_len = 0;
    let mut escaped = false;
    while let Some(c) = chars.get(*index) {
        match c {
            ',' | '}' => break,
            '{' | '"' => return None,
            '\\' => {
                *index += 1;
                let escaped_char = *chars.get(*index)?;
                raw.push(escaped_char);
                *index += 1;
                value_len = raw.len();
                escaped = true;
            }
            c if c.is_whitespace() => {
                raw.push(*c);
                *index += 1;
            }
            c => {
                raw.push(*c);
                *index += 1;
                value_len = raw.len();
            }
        }
    }
    if value_len == 0 {
        return None;
    }
    let value: String = raw[..value_len].iter().collect();
    if !escaped && value.eq_ignore_ascii_case("null") {
        Some(ArrayElement::Null)
    } else {
        Some(ArrayElement::Value(value))
    }
}

/// 配列の解析中に空白を読み飛ばす。
fn skip_array_whitespace(chars: &[char], index: &mut usize) {
    while chars.get(*index).is_some_and(|c| c.is_whitespace()) {
        *index += 1;
    }
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
        // 多次元配列は入れ子の波括弧としてエンコードする。
        Value::Array { values, .. } => encode_array(values),
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
fn convert_char_array(s: &str) -> Value {
    convert_array(s, oid::CHAR)
}
fn convert_name_array(s: &str) -> Value {
    convert_array(s, oid::NAME)
}
fn convert_text_array(s: &str) -> Value {
    convert_array(s, oid::TEXT)
}
fn convert_bpchar_array(s: &str) -> Value {
    convert_array(s, oid::BPCHAR)
}
fn convert_varchar_array(s: &str) -> Value {
    convert_array(s, oid::VARCHAR)
}
fn convert_oid_array(s: &str) -> Value {
    convert_array(s, oid::OID)
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

/// 型が一致しない値の変換エラーを生成する。
fn type_mismatch(expected: &str) -> Error {
    Error::interface(format!(
        "Cannot read a column of another type as {expected}"
    ))
}

/// 整数型の値を `i64` に拡張する。
fn as_i64(value: &Value) -> Result<i64> {
    match value {
        Value::Int2(v) => Ok(i64::from(*v)),
        Value::Int4(v) => Ok(i64::from(*v)),
        Value::Int8(v) => Ok(*v),
        _ => Err(type_mismatch("an integer")),
    }
}

impl TryFrom<&Value> for i16 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Int2(v) => Ok(*v),
            _ => Err(type_mismatch("SMALLINT")),
        }
    }
}

impl TryFrom<&Value> for i32 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Int2(v) => Ok(i32::from(*v)),
            Value::Int4(v) => Ok(*v),
            _ => Err(type_mismatch("INTEGER")),
        }
    }
}

impl TryFrom<&Value> for i64 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        as_i64(value)
    }
}

impl TryFrom<&Value> for u32 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Oid(v) => Ok(*v),
            _ => Err(type_mismatch("OID")),
        }
    }
}

impl TryFrom<&Value> for bool {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Bool(v) => Ok(*v),
            _ => Err(type_mismatch("BOOLEAN")),
        }
    }
}

impl TryFrom<&Value> for f32 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Float4(v) => Ok(*v),
            _ => Err(type_mismatch("REAL")),
        }
    }
}

impl TryFrom<&Value> for f64 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Float4(v) => Ok(f64::from(*v)),
            Value::Float8(v) => Ok(*v),
            _ => Err(type_mismatch("DOUBLE PRECISION")),
        }
    }
}

impl TryFrom<&Value> for String {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Text(v) | Value::Numeric(v) | Value::Json(v) => Ok(v.clone()),
            _ => Err(type_mismatch("TEXT")),
        }
    }
}

impl TryFrom<&Value> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Bytes(v) => Ok(v.clone()),
            _ => Err(type_mismatch("BYTEA")),
        }
    }
}

impl TryFrom<&Value> for u128 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Uuid(v) => Ok(*v),
            _ => Err(type_mismatch("UUID")),
        }
    }
}

impl TryFrom<&Value> for NaiveDate {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Date(v) => Ok(*v),
            _ => Err(type_mismatch("DATE")),
        }
    }
}

impl TryFrom<&Value> for NaiveTime {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Time(v) => Ok(*v),
            _ => Err(type_mismatch("TIME")),
        }
    }
}

impl TryFrom<&Value> for NaiveDateTime {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Timestamp(v) => Ok(*v),
            _ => Err(type_mismatch("TIMESTAMP")),
        }
    }
}

impl TryFrom<&Value> for DateTime<Utc> {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Timestamptz(v) => Ok(*v),
            _ => Err(type_mismatch("TIMESTAMPTZ")),
        }
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

        // 36 文字すべてが 16 進数字でも panic せず Text にフォールバックする。
        let malformed = "0".repeat(36);
        assert_eq!(convert_uuid(&malformed), Value::Text(malformed));

        // ハイフンの位置が不正な場合も Text にフォールバックする。
        let malformed = format!("0-{}", "0".repeat(34));
        assert_eq!(convert_uuid(&malformed), Value::Text(malformed));

        // 大文字の 16 進数字も受け付ける。
        assert_eq!(
            convert_uuid("123E4567-E89B-12D3-A456-426614174000"),
            Value::Uuid(0x123e4567e89b12d3a456426614174000)
        );
    }

    #[test]
    fn test_convert_bytea() {
        // 16 進形式。
        assert_eq!(convert_bytea("\\x00ff"), Value::Bytes(vec![0x00, 0xff]));
        // エスケープ形式 (bytea_output = escape)。
        assert_eq!(
            convert_bytea("abc\\000def"),
            Value::Bytes(b"abc\0def".to_vec())
        );
        assert_eq!(
            convert_bytea("abc\\\\def"),
            Value::Bytes(b"abc\\def".to_vec())
        );
        // 不正な形式は Text にフォールバックする。
        assert_eq!(convert_bytea("\\x0"), Value::Text("\\x0".to_string()));
    }

    #[test]
    fn test_decoder_for_text_array_family() {
        for (array_oid, element_oid) in [
            (oid::array::CHAR, oid::CHAR),
            (oid::array::NAME, oid::NAME),
            (oid::array::TEXT, oid::TEXT),
            (oid::array::BPCHAR, oid::BPCHAR),
            (oid::array::VARCHAR, oid::VARCHAR),
        ] {
            assert_eq!(
                decoder_for(array_oid)("{a,b}"),
                Value::Array {
                    element_type: element_oid,
                    values: vec![Value::Text("a".to_string()), Value::Text("b".to_string())],
                }
            );
        }
        assert_eq!(
            decoder_for(oid::array::OID)("{1,2}"),
            Value::Array {
                element_type: oid::OID,
                values: vec![Value::Oid(1), Value::Oid(2)],
            }
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
    fn test_convert_array_backslash_escapes() {
        // 引用符の外のバックスラッシュも次の文字をエスケープする。
        let value = convert_array("{a\\,b}", oid::TEXT);
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::TEXT,
                values: vec![Value::Text("a,b".to_string())],
            }
        );

        // エスケープされた空白は要素の一部として保持する。
        let value = convert_array("{a\\ }", oid::TEXT);
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::TEXT,
                values: vec![Value::Text("a ".to_string())],
            }
        );

        // エスケープを含む要素は NULL とみなさない。
        let value = convert_array("{N\\ULL,\"NULL\"}", oid::TEXT);
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::TEXT,
                values: vec![
                    Value::Text("NULL".to_string()),
                    Value::Text("NULL".to_string())
                ],
            }
        );
    }

    #[test]
    fn test_convert_nested_array() {
        let value = convert_int4_array("{{1,2},{3,4}}");
        assert_eq!(
            value,
            Value::Array {
                element_type: oid::INT4,
                values: vec![
                    Value::Array {
                        element_type: oid::INT4,
                        values: vec![Value::Int4(1), Value::Int4(2)],
                    },
                    Value::Array {
                        element_type: oid::INT4,
                        values: vec![Value::Int4(3), Value::Int4(4)],
                    },
                ],
            }
        );
        assert_eq!(value.to_bytes(), Some(b"{{1,2},{3,4}}".to_vec()));
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
