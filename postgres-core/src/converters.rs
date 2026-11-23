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
use crate::datetime::{Date, Time, Timestamp, Timestamptz};
use crate::error::{Error, Result};

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
    /// PostgreSQL 19 で追加された `oid8` (64 ビットのオブジェクト識別子) の値を保持する。
    Oid8(u64),
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
    Date(Date),
    /// PostgreSQL の `TIME` (時刻) を保持する。
    Time(Time),
    /// PostgreSQL の `TIMESTAMP` (タイムゾーンなしの日時) を保持する。
    Timestamp(Timestamp),
    /// PostgreSQL の `TIMESTAMPTZ` (UTC に正規化したタイムゾーン付き日時) を保持する。
    Timestamptz(Timestamptz),
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
            Value::Oid8(v) => Some(v.to_string().into_bytes()),
            Value::Text(s) => Some(s.as_bytes().to_vec()),
            Value::Bytes(b) => Some(escape_bytea(b).into_bytes()),
            Value::Uuid(v) => Some(uuid_to_text(*v).into_bytes()),
            Value::Json(s) => Some(s.as_bytes().to_vec()),
            Value::Array { values, .. } => Some(encode_array(values).into_bytes()),
            Value::Date(d) => Some(d.to_iso().into_bytes()),
            Value::Time(t) => Some(t.to_iso().into_bytes()),
            Value::Timestamp(dt) => Some(dt.to_iso().into_bytes()),
            Value::Timestamptz(dt) => Some(dt.to_iso().into_bytes()),
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

/// 16 進 1 桁の文字。小文字で出力する。
const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// 1 バイトを 16 進 2 桁のバイト列にする表。
const HEX_PAIRS: [[u8; 2]; 256] = {
    let mut table = [[0_u8; 2]; 256];
    let mut i = 0;
    while i < 256 {
        table[i][0] = HEX_DIGITS[i >> 4];
        table[i][1] = HEX_DIGITS[i & 0xf];
        i += 1;
    }
    table
};

/// バイト列を bytea のテキスト形式 (\\x 16 進) に変換する。
///
/// `format!` をバイトごとに呼ぶと遅いため、表を使ってバイト列に書き込む。
fn escape_bytea(value: &[u8]) -> String {
    let mut out = Vec::with_capacity(2 + value.len() * 2);
    out.extend_from_slice(b"\\x");
    for b in value {
        out.extend_from_slice(&HEX_PAIRS[usize::from(*b)]);
    }
    // 書き込むのは ASCII だけのため UTF-8 として必ず妥当になる。
    String::from_utf8(out).expect("Hex output contains only ASCII bytes")
}

/// フィールド型 (OID) に対応するデコーダーを取得する。
///
/// bool、整数、浮動小数点数、numeric、oid / oid8、bytea、uuid、json / jsonb、
/// date / time / timestamp / timestamptz とそれらの配列は、対応する [`Value`] に変換する。
/// interval や inet などそれ以外の型は [`Value::Text`] とし、[`oid::array`] に挙げた
/// 組み込み型の配列は要素を `Value::Text` にした [`Value::Array`] とする。
/// 独自の変換が必要な型は、接続の `register_converter` で登録する。
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
        oid::OID8 => convert_oid8,
        oid::NUMERIC => convert_numeric,
        oid::UUID => convert_uuid,
        oid::JSON | oid::JSONB => convert_json,
        oid::DATE => convert_date,
        oid::TIME => convert_time,
        oid::TIMESTAMP => convert_timestamp,
        oid::TIMESTAMPTZ => convert_timestamptz,
        // 配列型。要素型 OID を const ジェネリクスで固定した関数で変換する。
        oid::array::BOOL => convert_array_of::<{ oid::BOOL }>,
        oid::array::BYTEA => convert_array_of::<{ oid::BYTEA }>,
        oid::array::CHAR => convert_array_of::<{ oid::CHAR }>,
        oid::array::NAME => convert_array_of::<{ oid::NAME }>,
        oid::array::INT2 => convert_array_of::<{ oid::INT2 }>,
        oid::array::INT4 => convert_array_of::<{ oid::INT4 }>,
        oid::array::TEXT => convert_array_of::<{ oid::TEXT }>,
        oid::array::BPCHAR => convert_array_of::<{ oid::BPCHAR }>,
        oid::array::VARCHAR => convert_array_of::<{ oid::VARCHAR }>,
        oid::array::INT8 => convert_array_of::<{ oid::INT8 }>,
        oid::array::FLOAT4 => convert_array_of::<{ oid::FLOAT4 }>,
        oid::array::FLOAT8 => convert_array_of::<{ oid::FLOAT8 }>,
        oid::array::OID => convert_array_of::<{ oid::OID }>,
        oid::array::OID8 => convert_array_of::<{ oid::OID8 }>,
        oid::array::NUMERIC => convert_array_of::<{ oid::NUMERIC }>,
        oid::array::UUID => convert_array_of::<{ oid::UUID }>,
        oid::array::JSON => convert_array_of::<{ oid::JSON }>,
        oid::array::JSONB => convert_array_of::<{ oid::JSONB }>,
        oid::array::DATE => convert_array_of::<{ oid::DATE }>,
        oid::array::TIME => convert_array_of::<{ oid::TIME }>,
        oid::array::TIMESTAMP => convert_array_of::<{ oid::TIMESTAMP }>,
        oid::array::TIMESTAMPTZ => convert_array_of::<{ oid::TIMESTAMPTZ }>,
        // 変換せずテキストとして扱う組み込み型の配列。要素は `Value::Text` になる。
        // box の配列は要素の区切りが `;` (pg_type.dat の typdelim) で、この配列の解析と
        // 形式が異なるため含めない。
        oid::array::INTERVAL => convert_array_of::<{ oid::INTERVAL }>,
        oid::array::TIMETZ => convert_array_of::<{ oid::TIMETZ }>,
        oid::array::INET => convert_array_of::<{ oid::INET }>,
        oid::array::CIDR => convert_array_of::<{ oid::CIDR }>,
        oid::array::MACADDR => convert_array_of::<{ oid::MACADDR }>,
        oid::array::MACADDR8 => convert_array_of::<{ oid::MACADDR8 }>,
        oid::array::MONEY => convert_array_of::<{ oid::MONEY }>,
        oid::array::BIT => convert_array_of::<{ oid::BIT }>,
        oid::array::VARBIT => convert_array_of::<{ oid::VARBIT }>,
        oid::array::XML => convert_array_of::<{ oid::XML }>,
        oid::array::POINT => convert_array_of::<{ oid::POINT }>,
        oid::array::LINE => convert_array_of::<{ oid::LINE }>,
        oid::array::LSEG => convert_array_of::<{ oid::LSEG }>,
        oid::array::PATH => convert_array_of::<{ oid::PATH }>,
        oid::array::POLYGON => convert_array_of::<{ oid::POLYGON }>,
        oid::array::CIRCLE => convert_array_of::<{ oid::CIRCLE }>,
        oid::array::TSVECTOR => convert_array_of::<{ oid::TSVECTOR }>,
        oid::array::TSQUERY => convert_array_of::<{ oid::TSQUERY }>,
        oid::array::JSONPATH => convert_array_of::<{ oid::JSONPATH }>,
        oid::array::PG_LSN => convert_array_of::<{ oid::PG_LSN }>,
        oid::array::XID8 => convert_array_of::<{ oid::XID8 }>,
        oid::array::INT4RANGE => convert_array_of::<{ oid::INT4RANGE }>,
        oid::array::INT8RANGE => convert_array_of::<{ oid::INT8RANGE }>,
        oid::array::NUMRANGE => convert_array_of::<{ oid::NUMRANGE }>,
        oid::array::TSRANGE => convert_array_of::<{ oid::TSRANGE }>,
        oid::array::TSTZRANGE => convert_array_of::<{ oid::TSTZRANGE }>,
        oid::array::DATERANGE => convert_array_of::<{ oid::DATERANGE }>,
        oid::array::INT4MULTIRANGE => convert_array_of::<{ oid::INT4MULTIRANGE }>,
        oid::array::INT8MULTIRANGE => convert_array_of::<{ oid::INT8MULTIRANGE }>,
        oid::array::NUMMULTIRANGE => convert_array_of::<{ oid::NUMMULTIRANGE }>,
        oid::array::TSMULTIRANGE => convert_array_of::<{ oid::TSMULTIRANGE }>,
        oid::array::TSTZMULTIRANGE => convert_array_of::<{ oid::TSTZMULTIRANGE }>,
        oid::array::DATEMULTIRANGE => convert_array_of::<{ oid::DATEMULTIRANGE }>,
        // TEXT / VARCHAR / BPCHAR / NAME / CHAR、上の配列に挙げた要素型、
        // 独自型を含む未知の型はテキストとして扱う。
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

/// oid8 を u64 として保持する。
///
/// PostgreSQL 19 の src/backend/utils/adt/oid8.c の oid8out は、値を符号なしの
/// 10 進数で出力する。将来の版で出力形式が変わった場合はここを見直す。
fn convert_oid8(s: &str) -> Value {
    match s.parse() {
        Ok(v) => Value::Oid8(v),
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
    // 桁を集めずに直接 128 ビットへ組み立てる。
    let mut value: u128 = 0;
    for (index, byte) in s.bytes().enumerate() {
        if hyphen_positions.contains(&index) {
            if byte != b'-' {
                return Value::Text(s.to_string());
            }
        } else {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Value::Text(s.to_string()),
            };
            value = (value << 4) | u128::from(digit);
        }
    }
    Value::Uuid(value)
}

/// 128 ビットの UUID 値を 8-4-4-4-12 形式の文字列に変換する。
///
/// `format!` をバイトごとに呼ぶと遅いため、表を使ってバイト列に書き込む。
fn uuid_to_text(value: u128) -> String {
    let bytes = value.to_be_bytes();
    let mut out = Vec::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push(b'-');
        }
        out.extend_from_slice(&HEX_PAIRS[usize::from(*byte)]);
    }
    // 書き込むのは ASCII だけのため UTF-8 として必ず妥当になる。
    String::from_utf8(out).expect("Hex output contains only ASCII bytes")
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
    match Date::parse_iso(s) {
        Some(date) => Value::Date(date),
        None => Value::Text(s.to_string()),
    }
}

fn convert_time(s: &str) -> Value {
    match Time::parse_iso(s) {
        Some(time) => Value::Time(time),
        None => Value::Text(s.to_string()),
    }
}

fn convert_timestamp(s: &str) -> Value {
    match Timestamp::parse_iso(s) {
        Some(timestamp) => Value::Timestamp(timestamp),
        None => Value::Text(s.to_string()),
    }
}

fn convert_timestamptz(s: &str) -> Value {
    match Timestamptz::parse_iso(s) {
        Some(timestamp) => Value::Timestamptz(timestamp),
        None => Value::Text(s.to_string()),
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
///
/// 解析はバイト列に対して行う。構造文字 (`{` `}` `,` `"` `\` と区切りの空白) は
/// すべて ASCII で、UTF-8 の連続バイト (0x80 以上) と衝突しないため、
/// 文字列を `Vec<char>` に展開せずに走査できる。
/// バックスラッシュのエスケープは次の 1 文字 (UTF-8 では 1〜4 バイト) である。
fn parse_array_literal(s: &str) -> Option<Vec<ArrayElement>> {
    let bytes = s.as_bytes();
    let mut index = 0;
    skip_array_whitespace(bytes, &mut index);
    let elements = parse_array_level(bytes, &mut index, 0)?;
    skip_array_whitespace(bytes, &mut index);
    if index != bytes.len() {
        return None;
    }
    Some(elements)
}

/// 1 段階の波括弧を解析する。
fn parse_array_level(bytes: &[u8], index: &mut usize, depth: usize) -> Option<Vec<ArrayElement>> {
    if depth >= MAX_ARRAY_DEPTH {
        return None;
    }
    if bytes.get(*index) != Some(&b'{') {
        return None;
    }
    *index += 1;
    skip_array_whitespace(bytes, index);

    let mut elements = Vec::new();
    if bytes.get(*index) == Some(&b'}') {
        *index += 1;
        return Some(elements);
    }

    loop {
        elements.push(parse_array_element(bytes, index, depth)?);
        skip_array_whitespace(bytes, index);
        match bytes.get(*index) {
            Some(b',') => {
                *index += 1;
                skip_array_whitespace(bytes, index);
                // 末尾のカンマは受け付けない。
                if bytes.get(*index) == Some(&b'}') {
                    return None;
                }
            }
            Some(b'}') => {
                *index += 1;
                return Some(elements);
            }
            _ => return None,
        }
    }
}

/// 配列の 1 要素を解析する。
fn parse_array_element(bytes: &[u8], index: &mut usize, depth: usize) -> Option<ArrayElement> {
    match bytes.get(*index)? {
        b'"' => parse_quoted_array_element(bytes, index).map(ArrayElement::Value),
        b'{' => parse_array_level(bytes, index, depth + 1).map(ArrayElement::Nested),
        _ => parse_unquoted_array_element(bytes, index),
    }
}

/// 二重引用符で囲まれた要素を解析する。
///
/// 引用符内のバックスラッシュは次の文字 (UTF-8 では 1〜4 バイト) をエスケープする。
fn parse_quoted_array_element(bytes: &[u8], index: &mut usize) -> Option<String> {
    *index += 1;
    let mut value = Vec::new();
    loop {
        let b = *bytes.get(*index)?;
        *index += 1;
        match b {
            b'\\' => {
                // エスケープの直後の 1 文字をそのまま写す。
                let char_len = utf8_char_len(*bytes.get(*index)?)?;
                value.extend_from_slice(bytes.get(*index..*index + char_len)?);
                *index += char_len;
            }
            b'"' => break,
            // 引用符の内側のそれ以外のバイトはそのまま写す。
            other => value.push(other),
        }
    }
    skip_array_whitespace(bytes, index);
    // 写したのは入力の UTF-8 部分列のため妥当な UTF-8 になる。
    Some(String::from_utf8(value).expect("A substring of UTF-8 input is valid UTF-8"))
}

/// 引用符なしの要素を解析する。
///
/// バックスラッシュは次の文字をエスケープする。
/// エスケープがある要素は `NULL` とみなさない。
fn parse_unquoted_array_element(bytes: &[u8], index: &mut usize) -> Option<ArrayElement> {
    let mut raw = Vec::new();
    // エスケープされた空白は要素の一部として扱うため、
    // 末尾の空白を削るときは最後の非空白文字の位置を別に覚えておく。
    let mut value_len = 0;
    let mut escaped = false;
    while let Some(b) = bytes.get(*index) {
        match b {
            b',' | b'}' => break,
            b'{' | b'"' => return None,
            b'\\' => {
                *index += 1;
                // エスケープの直後の 1 文字 (UTF-8 では 1〜4 バイト) をそのまま写す。
                let char_len = utf8_char_len(*bytes.get(*index)?)?;
                raw.extend_from_slice(bytes.get(*index..*index + char_len)?);
                *index += char_len;
                value_len = raw.len();
                escaped = true;
            }
            b if is_array_whitespace(*b) => {
                raw.push(*b);
                *index += 1;
            }
            other => {
                raw.push(*other);
                *index += 1;
                value_len = raw.len();
            }
        }
    }
    if value_len == 0 {
        return None;
    }
    // 区切りの空白は ASCII だけのため、有効長は文字の境界に一致する。
    raw.truncate(value_len);
    let value = String::from_utf8(raw).expect("A substring of UTF-8 input is valid UTF-8");
    if !escaped && value.eq_ignore_ascii_case("null") {
        Some(ArrayElement::Null)
    } else {
        Some(ArrayElement::Value(value))
    }
}

/// UTF-8 の先頭バイトから 1 文字のバイト長を得る。
///
/// 連続バイト (0x80 以上 0xC0 未満) が先頭に来た場合は不正として失敗する。
/// 4 バイトを超える長さは UTF-8 に存在しないため失敗する。
fn utf8_char_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC0..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF7 => Some(4),
        _ => None,
    }
}

/// 配列のテキスト形式で区切りとして扱う空白。
///
/// PostgreSQL の `scanner_isspace` と同じ 6 種類に限定する。
/// NBSP などの Unicode の空白は要素の一部として扱うため、ここには含めない。
fn is_array_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// 配列の解析中に空白を読み飛ばす。
fn skip_array_whitespace(bytes: &[u8], index: &mut usize) {
    while bytes.get(*index).is_some_and(|b| is_array_whitespace(*b)) {
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
            // 引用符で囲む文字は構造文字と区切りの空白 (scanner_isspace の 6 種類)。
            if s.is_empty()
                || s.eq_ignore_ascii_case("null")
                || s.chars().any(|c| {
                    matches!(
                        c,
                        '{' | '}'
                            | ','
                            | '"'
                            | '\\'
                            | ' '
                            | '\t'
                            | '\n'
                            | '\r'
                            | '\u{0B}'
                            | '\u{0C}'
                    )
                })
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

/// 要素型 OID を固定して配列を変換する。
///
/// `Converter` は fn ポインタで要素型 OID をキャプチャできないため、要素型 OID を
/// const ジェネリクスで受け取り、配列型ごとに別の関数として実体化する。
fn convert_array_of<const ELEMENT_OID: u32>(s: &str) -> Value {
    convert_array(s, ELEMENT_OID)
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

impl TryFrom<&Value> for u64 {
    type Error = Error;

    /// `oid8` の値を取り出す。`oid` の値も値を失わずに広げられるため受け付ける。
    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Oid8(v) => Ok(*v),
            Value::Oid(v) => Ok(u64::from(*v)),
            _ => Err(type_mismatch("OID8")),
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

/// 配列を `Vec<T>` として取り出す。
///
/// 要素はそれぞれ `T` の変換規則で取り出し、多次元配列は `Vec<Vec<T>>` のように
/// 入れ子の `Vec` で取り出す。NULL の要素を含む配列はエラーになるため、
/// `Vec<Option<T>>` で取り出す。`bytea` の値そのものは `Vec<u8>` で取り出す。
impl<'a, T> TryFrom<&'a Value> for Vec<T>
where
    T: TryFrom<&'a Value, Error = Error>,
{
    type Error = Error;

    fn try_from(value: &'a Value) -> Result<Self> {
        let Value::Array { values, .. } = value else {
            return Err(type_mismatch("an array"));
        };
        let mut out = Vec::new();
        for (index, element) in values.iter().enumerate() {
            if matches!(element, Value::Null) {
                return Err(Error::interface(format!(
                    "Array element {index} is NULL; read the array as Vec<Option<T>>"
                )));
            }
            out.push(T::try_from(element).map_err(|error| array_element_error(index, error))?);
        }
        Ok(out)
    }
}

/// NULL の要素を `None` として、配列を `Vec<Option<T>>` として取り出す。
///
/// NULL 以外の要素は `T` の変換規則で取り出す。
impl<'a, T> TryFrom<&'a Value> for Vec<Option<T>>
where
    T: TryFrom<&'a Value, Error = Error>,
{
    type Error = Error;

    fn try_from(value: &'a Value) -> Result<Self> {
        let Value::Array { values, .. } = value else {
            return Err(type_mismatch("an array"));
        };
        let mut out = Vec::new();
        for (index, element) in values.iter().enumerate() {
            out.push(match element {
                Value::Null => None,
                element => {
                    Some(T::try_from(element).map_err(|error| array_element_error(index, error))?)
                }
            });
        }
        Ok(out)
    }
}

/// 配列要素の変換エラーに要素の位置を加える。
fn array_element_error(index: usize, error: Error) -> Error {
    Error::interface(format!("Array element {index}: {}", error.message()))
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

impl TryFrom<&Value> for Date {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Date(v) => Ok(*v),
            _ => Err(type_mismatch("DATE")),
        }
    }
}

impl TryFrom<&Value> for Time {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Time(v) => Ok(*v),
            _ => Err(type_mismatch("TIME")),
        }
    }
}

impl TryFrom<&Value> for Timestamp {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Timestamp(v) => Ok(*v),
            _ => Err(type_mismatch("TIMESTAMP")),
        }
    }
}

impl TryFrom<&Value> for Timestamptz {
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

    fn date(year: i32, month: u32, day: u32) -> Date {
        Date::from_ymd(year, month, day).expect("日付は有効です")
    }

    fn time(hour: u32, minute: u32, second: u32, micro: u32) -> Time {
        Time::from_hms_micro(hour, minute, second, micro).expect("時刻は有効です")
    }

    fn timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Timestamp {
        Timestamp::from_ymd_hms_micro(year, month, day, hour, minute, second, micro)
            .expect("タイムスタンプは有効です")
    }

    fn timestamptz(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Timestamptz {
        Timestamptz::from_utc_ymd_hms_micro(year, month, day, hour, minute, second, 0)
            .expect("タイムスタンプは有効です")
    }

    #[test]
    fn test_convert_date_extended_years() {
        // PostgreSQL は年を 4 桁以上にゼロ埋めする。DATE の上限は 5874897-12-31。
        assert_eq!(convert_date("10000-01-01"), Value::Date(date(10000, 1, 1)));
        assert_eq!(
            convert_date("5874897-12-31"),
            Value::Date(date(5874897, 12, 31))
        );
        // 上限の翌日は範囲外。
        assert_eq!(
            convert_date("5874898-01-01"),
            Value::Text("5874898-01-01".to_string())
        );
        // 下限は 4714-11-24 BC (内部年 -4713)。
        assert_eq!(
            convert_date("4714-11-24 BC"),
            Value::Date(date(-4713, 11, 24))
        );
        assert_eq!(
            convert_date("4714-11-23 BC"),
            Value::Text("4714-11-23 BC".to_string())
        );
        // 8 桁の年はサーバーが出力しないため読まない。
        assert_eq!(
            convert_date("10000000-01-01"),
            Value::Text("10000000-01-01".to_string())
        );
        // 4 桁に満たない年もサーバーが出力しないため読まない。
        assert_eq!(
            convert_date("999-01-01"),
            Value::Text("999-01-01".to_string())
        );
        // 3 桁以下の年を 4 桁として誤読しない。
        assert_eq!(
            convert_date("2026-1-1"),
            Value::Text("2026-1-1".to_string())
        );
    }

    #[test]
    fn test_convert_date_bc() {
        // PostgreSQL は BC の日付を「YYYY-MM-DD BC」の形で出力する。
        // 内部表現では 1 BC が年 0 に対応する。
        assert_eq!(convert_date("0044-03-15 BC"), Value::Date(date(-43, 3, 15)));
        assert_eq!(convert_date("0001-01-01 BC"), Value::Date(date(0, 1, 1)));
        let bc = date(-43, 3, 15);
        assert_eq!(bc.to_iso(), "0044-03-15 BC");
        // AD と BC の表示年に年 0 は存在しないため拒否する。
        assert_eq!(
            convert_date("0000-01-01"),
            Value::Text("0000-01-01".to_string())
        );
        assert_eq!(
            convert_date("0000-01-01 BC"),
            Value::Text("0000-01-01 BC".to_string())
        );
        // 小文字の紀元や余分な空白はサーバーが出力しないため拒否する。
        assert_eq!(
            convert_date("0044-03-15 bc"),
            Value::Text("0044-03-15 bc".to_string())
        );
    }

    #[test]
    fn test_convert_date_leap_years() {
        // うるう年の判定はグレゴリオ暦の規則そのもの (isleap と同じ)。
        assert_eq!(convert_date("2024-02-29"), Value::Date(date(2024, 2, 29)));
        assert_eq!(convert_date("2000-02-29"), Value::Date(date(2000, 2, 29)));
        assert_eq!(
            convert_date("1900-02-29"),
            Value::Text("1900-02-29".to_string())
        );
        assert_eq!(
            convert_date("1500-02-29"),
            Value::Text("1500-02-29".to_string())
        );
        assert_eq!(
            convert_date("2023-02-29"),
            Value::Text("2023-02-29".to_string())
        );
        // BC の年も同じ規則で判定する。1 BC は内部年 0 で、400 で割り切れるためうるう年。
        assert_eq!(convert_date("0001-02-29 BC"), Value::Date(date(0, 2, 29)));
        // 5 BC は内部年 -4 で、4 で割り切れるためうるう年。
        assert_eq!(convert_date("0005-02-29 BC"), Value::Date(date(-4, 2, 29)));
        // 4 BC は内部年 -3 で、4 で割り切れない。
        assert_eq!(
            convert_date("0004-02-29 BC"),
            Value::Text("0004-02-29 BC".to_string())
        );
        // 月ごとの日数。4 月 31 日は存在しない。
        assert_eq!(
            convert_date("2026-04-31"),
            Value::Text("2026-04-31".to_string())
        );
        // 月 0 と日 0 は拒否する。
        assert_eq!(
            convert_date("2026-00-01"),
            Value::Text("2026-00-01".to_string())
        );
        assert_eq!(
            convert_date("2026-01-00"),
            Value::Text("2026-01-00".to_string())
        );
    }

    #[test]
    fn test_convert_time_strict_forms() {
        // 小数は 1〜6 桁。末尾の 0 はサーバーが切り詰めるが、ここでは受理する。
        assert_eq!(
            convert_time("12:34:56.5"),
            Value::Time(time(12, 34, 56, 500_000))
        );
        assert_eq!(
            convert_time("12:34:56.123456"),
            Value::Time(time(12, 34, 56, 123_456))
        );
        // 7 桁以上の小数はサーバーが出力しないため拒否する。
        assert_eq!(
            convert_time("12:34:56.1234567"),
            Value::Text("12:34:56.1234567".to_string())
        );
        // ドットだけでは小数にならない。
        assert_eq!(
            convert_time("12:34:56."),
            Value::Text("12:34:56.".to_string())
        );
        // 24:00:00 と、同じマイクロ秒になる 23:59:60 を受理する。出力は 24:00:00。
        let end = time(24, 0, 0, 0);
        assert_eq!(convert_time("24:00:00"), Value::Time(end));
        assert_eq!(convert_time("23:59:60"), Value::Time(end));
        assert_eq!(end.to_iso(), "24:00:00");
        assert_eq!(
            convert_time("23:59:60.1"),
            Value::Text("23:59:60.1".to_string())
        );
        // 2 桁に満たない時分秒はサーバーが出力しないため拒否する。
        assert_eq!(convert_time("1:23:45"), Value::Text("1:23:45".to_string()));
    }

    #[test]
    fn test_convert_timestamp_forms() {
        assert_eq!(
            convert_timestamp("2026-11-22 12:34:56"),
            Value::Timestamp(timestamp(2026, 11, 22, 12, 34, 56, 0))
        );
        assert_eq!(
            convert_timestamp("2026-11-22 12:34:56.789012"),
            Value::Timestamp(timestamp(2026, 11, 22, 12, 34, 56, 789_012))
        );
        // BC は文字列全体の末尾に付く。
        let expected = timestamp(-43, 3, 15, 12, 0, 0, 0);
        assert_eq!(
            convert_timestamp("0044-03-15 12:00:00 BC"),
            Value::Timestamp(expected)
        );
        assert_eq!(expected.to_iso(), "0044-03-15 12:00:00 BC");
        // 24:00:00 は翌日 00:00:00 になる。
        assert_eq!(
            convert_timestamp("2024-01-31 24:00:00"),
            Value::Timestamp(timestamp(2024, 2, 1, 0, 0, 0, 0))
        );
        // 紀元の位置が違うものは拒否する。
        assert_eq!(
            convert_timestamp("0044-03-15 BC 12:00:00"),
            Value::Text("0044-03-15 BC 12:00:00".to_string())
        );
        assert_eq!(
            convert_timestamp("infinity"),
            Value::Timestamp(Timestamp::Infinity)
        );
        assert_eq!(
            convert_timestamp("-infinity"),
            Value::Timestamp(Timestamp::NegInfinity)
        );
        assert_eq!(convert_date("infinity"), Value::Date(Date::Infinity));
        assert_eq!(convert_date("-infinity"), Value::Date(Date::NegInfinity));
    }

    #[test]
    fn test_convert_timestamptz_offset_forms() {
        // EncodeTimezone は ±HH / ±HH:MM / ±HH:MM:SS の 3 形式を出力する。
        // 時だけのオフセット。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56+09"),
            Value::Timestamptz(timestamptz(2026, 11, 22, 3, 34, 56))
        );
        // 分付きのオフセット。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56+09:30"),
            Value::Timestamptz(timestamptz(2026, 11, 22, 3, 4, 56))
        );
        // 秒付きのオフセット。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56+09:30:15"),
            Value::Timestamptz(timestamptz(2026, 11, 22, 3, 4, 41))
        );
        // 負のオフセット。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56-05"),
            Value::Timestamptz(timestamptz(2026, 11, 22, 17, 34, 56))
        );
        // 日付の境界を跨ぐ換算 (現地 00:30 は UTC では前日)。
        assert_eq!(
            convert_timestamptz("2026-11-22 00:30:00+09"),
            Value::Timestamptz(timestamptz(2026, 11, 21, 15, 30, 0))
        );
        // BC のタイムスタンプ付きタイムゾーン。紀元はオフセットの後ろに付く。
        assert_eq!(
            convert_timestamptz("0044-03-15 12:00:00+09 BC"),
            Value::Timestamptz(timestamptz(-43, 3, 15, 3, 0, 0))
        );
        // 分も秒も 0 でないオフセットの上限は 15:59:59。
        assert!(matches!(
            convert_timestamptz("2026-11-22 12:34:56+15:59:59"),
            Value::Timestamptz(_)
        ));
        // 時 16 は PostgreSQL の MAX_TZDISP_HOUR を超えるため拒否する。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56+16"),
            Value::Text("2026-11-22 12:34:56+16".to_string())
        );
        // コロンなしの ±HHMM はサーバーが出力しないため拒否する。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56+0900"),
            Value::Text("2026-11-22 12:34:56+0900".to_string())
        );
        // オフセットがない場合も拒否する。
        assert_eq!(
            convert_timestamptz("2026-11-22 12:34:56"),
            Value::Text("2026-11-22 12:34:56".to_string())
        );
        assert_eq!(
            convert_timestamptz("infinity"),
            Value::Timestamptz(Timestamptz::Infinity)
        );
    }

    #[test]
    fn test_datetime_round_trip() {
        // 整形して解析すると同じ値に戻る。
        let cases = [
            date(2026, 11, 22),
            date(10000, 1, 1),
            date(44, 3, 15),
            date(-43, 3, 15),
            date(0, 1, 1),
            date(-4713, 11, 24),
            date(5874897, 12, 31),
            Date::Infinity,
            Date::NegInfinity,
        ];
        for date in cases {
            let text = date.to_iso();
            assert_eq!(
                Date::parse_iso(&text),
                Some(date),
                "日付の往復で値が変化しました: {text}"
            );
        }
        let times = [
            time(12, 34, 56, 500_000),
            time(23, 59, 59, 999_999),
            time(0, 0, 0, 0),
            time(24, 0, 0, 0),
        ];
        for time in times {
            let text = time.to_iso();
            assert_eq!(
                Time::parse_iso(&text),
                Some(time),
                "時刻の往復で値が変化しました: {text}"
            );
        }
        // UTC のタイムスタンプ付きタイムゾーンの往復。
        let datetime = Timestamptz::from_utc_ymd_hms_micro(10000, 1, 1, 12, 34, 56, 789_012)
            .expect("タイムスタンプは有効です");
        let text = datetime.to_iso();
        assert_eq!(text, "10000-01-01 12:34:56.789012+00");
        assert_eq!(Timestamptz::parse_iso(&text), Some(datetime));
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
        let value = decoder_for(oid::array::INT4)("{1,2,3}");
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
        let value = decoder_for(oid::array::INT4)("{{1,2},{3,4}}");
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
        let value = decoder_for(oid::array::INT4)("{1,NULL,3}");
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
            decoder_for(oid::array::INT4)("1,2,3"),
            Value::Text("1,2,3".to_string())
        );
        // 引用符が閉じられていない場合は Text にフォールバックする。
        assert_eq!(
            decoder_for(oid::array::INT4)("{\"a}"),
            Value::Text("{\"a}".to_string())
        );
    }

    #[test]
    fn test_convert_array_empty() {
        // PostgreSQL の空配列 `{}` は空の要素リストとして扱う。
        assert_eq!(
            decoder_for(oid::array::INT4)("{}"),
            Value::Array {
                element_type: oid::INT4,
                values: Vec::new(),
            }
        );
        // 空白だけの `{ }` も空の要素リストとして扱う。
        assert_eq!(
            decoder_for(oid::array::INT4)("{ }"),
            Value::Array {
                element_type: oid::INT4,
                values: Vec::new(),
            }
        );
        // 引用符付きの空文字列 `{""}` は空文字列 1 要素の配列として扱う。
        assert_eq!(
            decoder_for(oid::array::INT4)("{\"\"}"),
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
        assert_eq!(decoder_for(oid::array::INT4)(&text), original);
    }

    #[test]
    fn test_array_round_trip_with_non_ascii_whitespace() {
        // PostgreSQL の配列の空白は ASCII の 6 種類だけ。NBSP などの Unicode の空白は
        // 要素の一部として扱うため、符号化しても失わない。
        for text in [
            "\u{00A0}",
            "\u{00A0}a",
            "a\u{00A0}",
            "a\u{00A0}b",
            "a\u{000B}",
            "\u{000C}",
        ] {
            let original = Value::Array {
                element_type: oid::TEXT,
                values: vec![Value::Text(text.to_string())],
            };
            let bytes = original.to_bytes().expect("配列のエンコードに成功しました");
            let encoded = String::from_utf8(bytes).expect("UTF-8 です");
            assert_eq!(
                decoder_for(oid::array::TEXT)(&encoded),
                original,
                "配列の往復で値が変わりました: {text:?}"
            );
        }
    }

    #[test]
    fn test_array_quotes_all_ascii_whitespace() {
        // PostgreSQL が区切りとして扱う空白は引用符で囲む。
        for text in ["a\u{000B}", "a\u{000C}", "a b", "a\tb"] {
            let encoded = encode_array(&[Value::Text(text.to_string())]);
            assert_eq!(
                encoded,
                format!("{{\"{text}\"}}"),
                "空白を含む要素が引用符で囲まれません: {text:?}"
            );
        }
    }

    #[test]
    fn test_array_keeps_non_ascii_whitespace_unquoted() {
        // サーバーは NBSP を区切りとして扱わないため、引用符なしで出力する。
        assert_eq!(
            decoder_for(oid::array::TEXT)("{\u{00A0}}"),
            Value::Array {
                element_type: oid::TEXT,
                values: vec![Value::Text("\u{00A0}".to_string())],
            }
        );
        assert_eq!(
            decoder_for(oid::array::TEXT)("{a\u{00A0}}"),
            Value::Array {
                element_type: oid::TEXT,
                values: vec![Value::Text("a\u{00A0}".to_string())],
            }
        );
    }

    /// 配列として取り出せない値と要素は、理由と位置が分かるエラーにする。
    #[test]
    fn test_array_into_vec_errors() {
        let ints = |values: Vec<Value>| Value::Array {
            element_type: oid::INT4,
            values,
        };
        let error = Vec::<i32>::try_from(&Value::Int4(1))
            .expect_err("配列でない値を Vec として取り出せました");
        assert_eq!(
            error.message(),
            "Cannot read a column of another type as an array"
        );
        let error = Vec::<Option<i32>>::try_from(&Value::Text("{1}".to_string()))
            .expect_err("配列でない値を Vec<Option<T>> として取り出せました");
        assert_eq!(
            error.message(),
            "Cannot read a column of another type as an array"
        );

        // NULL の要素は Vec<T> では取り出せず、Vec<Option<T>> を使うよう案内する。
        let with_null = ints(vec![Value::Int4(1), Value::Null]);
        let error =
            Vec::<i32>::try_from(&with_null).expect_err("NULL の要素を Vec<T> で取り出せました");
        assert_eq!(
            error.message(),
            "Array element 1 is NULL; read the array as Vec<Option<T>>"
        );

        // 要素の型が合わない場合は、要素の位置と要素の変換エラーを示す。
        let mixed = ints(vec![Value::Int4(1), Value::Text("x".to_string())]);
        for error in [
            Vec::<i32>::try_from(&mixed).expect_err("型の異なる要素を取り出せました"),
            Vec::<Option<i32>>::try_from(&mixed).expect_err("型の異なる要素を取り出せました"),
        ] {
            assert_eq!(
                error.message(),
                "Array element 1: Cannot read a column of another type as INTEGER"
            );
        }

        // 多次元配列を 1 次元として取り出すと、入れ子の要素の位置でエラーになる。
        let nested = ints(vec![ints(vec![Value::Int4(1)])]);
        let error = Vec::<i32>::try_from(&nested).expect_err("2 次元配列を 1 次元で取り出せました");
        assert_eq!(
            error.message(),
            "Array element 0: Cannot read a column of another type as INTEGER"
        );

        // bytea の値は従来どおり Vec<u8> で取り出し、bytea[] は Vec<Vec<u8>> で取り出す。
        assert_eq!(
            Vec::<u8>::try_from(&Value::Bytes(vec![1, 2])).expect("bytea を取り出せません"),
            vec![1, 2]
        );
        let byteas = Value::Array {
            element_type: oid::BYTEA,
            values: vec![Value::Bytes(vec![1]), Value::Bytes(Vec::new())],
        };
        assert_eq!(
            Vec::<Vec<u8>>::try_from(&byteas).expect("bytea[] を取り出せません"),
            vec![vec![1], Vec::new()]
        );
    }
}
