// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! converters モジュールの Property-Based Testing。
//!
//! エンコード (to_bytes) とデコード (decoder_for) の往復が
//! 元の値を保持することを検証する。日付・時刻型は PostgreSQL が
//! マイクロ秒精度しか持たないため、ナノ秒以下は切り捨てて比較する。

use chrono::{DateTime, NaiveDate, NaiveTime, Timelike, Utc};
use proptest::prelude::*;
use shiguredo_postgres_core::constants::oid;
use shiguredo_postgres_core::converters::{Value, decoder_for};

/// 有限の f64 を生成する戦略。
fn finite_f64() -> impl Strategy<Value = f64> + Clone {
    any::<f64>().prop_filter("有限の f64 です", |f| f.is_finite())
}

/// 有限の f32 を生成する戦略。
fn finite_f32() -> impl Strategy<Value = f32> + Clone {
    any::<f32>().prop_filter("有限の f32 です", |f| f.is_finite())
}

/// エンコード・デコードで往復が成立するスカラー値を生成する戦略。
///
/// NaN を含む float と特殊値を含む float は専用のテストで扱う。
fn scalar_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i16>().prop_map(Value::Int2),
        any::<i32>().prop_map(Value::Int4),
        any::<i64>().prop_map(Value::Int8),
        any::<i64>().prop_map(|i| Value::Numeric(i.to_string())),
        any::<u32>().prop_map(Value::Oid),
        any::<String>().prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..=256).prop_map(Value::Bytes),
        any::<u128>().prop_map(Value::Uuid),
        any::<String>().prop_map(Value::Json),
    ]
}

/// NaN と無限大を含む f64 を生成する戦略。
fn any_f64() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>(),
        Just(f64::NAN),
        Just(f64::INFINITY),
        Just(f64::NEG_INFINITY),
    ]
}

/// 有効な日付の Value を生成する戦略。
fn date_strategy() -> impl Strategy<Value = Value> {
    (1i32..=9999, 1u32..=12, 1u32..=31).prop_filter_map("有効な日付です", |(y, m, d)| {
        NaiveDate::from_ymd_opt(y, m, d).map(Value::Date)
    })
}

/// 有効な時刻の Value を生成する戦略。
///
/// ナノ秒を含むため、マイクロ秒以下が失われるケースを検証できる。
fn time_strategy() -> impl Strategy<Value = Value> {
    (0u32..=23, 0u32..=59, 0u32..=59, 0u32..=999_999_999)
        .prop_filter_map("有効な時刻です", |(h, m, s, ns)| {
            NaiveTime::from_hms_nano_opt(h, m, s, ns).map(Value::Time)
        })
}

/// 有効なタイムスタンプの Value を生成する戦略。
fn timestamp_strategy() -> impl Strategy<Value = Value> {
    (
        1i32..=9999,
        1u32..=12,
        1u32..=31,
        0u32..=23,
        0u32..=59,
        0u32..=59,
        0u32..=999_999_999,
    )
        .prop_filter_map(
            "有効なタイムスタンプです",
            |(y, mo, d, h, mi, s, ns)| {
                NaiveDate::from_ymd_opt(y, mo, d)
                    .and_then(|date| date.and_hms_nano_opt(h, mi, s, ns))
                    .map(Value::Timestamp)
            },
        )
}

/// 有効なタイムスタンプ (UTC) の Value を生成する戦略。
fn timestamptz_strategy() -> impl Strategy<Value = Value> {
    (
        1i32..=9999,
        1u32..=12,
        1u32..=31,
        0u32..=23,
        0u32..=59,
        0u32..=59,
        0u32..=999_999_999,
    )
        .prop_filter_map(
            "有効なタイムスタンプ (UTC) です",
            |(y, mo, d, h, mi, s, ns)| {
                NaiveDate::from_ymd_opt(y, mo, d)
                    .and_then(|date| date.and_hms_nano_opt(h, mi, s, ns))
                    .map(|dt| {
                        Value::Timestamptz(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
                    })
            },
        )
}

/// 要素型ごとの配列の Value を生成する戦略。
///
/// 要素はその配列型 OID のデコーダーで往復できるスカラー値だけを使う。
/// 複合要素 (ネスト配列) はサポート対象外のため含めない。
fn array_strategy() -> impl Strategy<Value = Value> {
    fn array_of(
        element_type: u32,
        elements: impl Strategy<Value = Value> + Clone,
    ) -> impl Strategy<Value = Value> {
        proptest::collection::vec(elements, 0..=8).prop_map(move |values| Value::Array {
            element_type,
            values,
        })
    }

    prop_oneof![
        array_of(oid::BOOL, any::<bool>().prop_map(Value::Bool)),
        array_of(oid::INT2, any::<i16>().prop_map(Value::Int2)),
        array_of(oid::INT4, any::<i32>().prop_map(Value::Int4)),
        array_of(oid::INT8, any::<i64>().prop_map(Value::Int8)),
        array_of(oid::FLOAT4, finite_f32().prop_map(Value::Float4)),
        array_of(oid::FLOAT8, finite_f64().prop_map(Value::Float8)),
        array_of(
            oid::NUMERIC,
            any::<i64>().prop_map(|i| Value::Numeric(i.to_string()))
        ),
        array_of(
            oid::BYTEA,
            proptest::collection::vec(any::<u8>(), 0..=64).prop_map(Value::Bytes)
        ),
        array_of(oid::UUID, any::<u128>().prop_map(Value::Uuid)),
    ]
}

/// 値をエンコードしてからテキスト形式でデコードする。
fn encode_decode(value: &Value, type_oid: u32) -> Value {
    let bytes = value
        .to_bytes()
        .expect("テキスト形式のエンコードに成功しました");
    let s = std::str::from_utf8(&bytes).expect("テキスト形式は UTF-8 です");
    decoder_for(type_oid)(s)
}

/// スカラー値に対応するデコーダーの OID を返す。
fn scalar_decoder_oid(value: &Value) -> u32 {
    match value {
        Value::Bool(_) => oid::BOOL,
        Value::Int2(_) => oid::INT2,
        Value::Int4(_) => oid::INT4,
        Value::Int8(_) => oid::INT8,
        Value::Float4(_) => oid::FLOAT4,
        Value::Float8(_) => oid::FLOAT8,
        Value::Numeric(_) => oid::NUMERIC,
        Value::Oid(_) => oid::OID,
        Value::Text(_) => oid::TEXT,
        Value::Bytes(_) => oid::BYTEA,
        Value::Uuid(_) => oid::UUID,
        Value::Json(_) => oid::JSON,
        _ => unreachable!("スカラー以外の値が渡されました"),
    }
}

/// 要素型 OID に対応する配列型 OID を返す。
///
/// `Value::Array` が保持するのは要素型 OID のため、
/// 配列のデコードには対応する配列型 OID が必要になる。
fn array_oid_for(element_type: u32) -> u32 {
    match element_type {
        oid::BOOL => oid::array::BOOL,
        oid::INT2 => oid::array::INT2,
        oid::INT4 => oid::array::INT4,
        oid::INT8 => oid::array::INT8,
        oid::FLOAT4 => oid::array::FLOAT4,
        oid::FLOAT8 => oid::array::FLOAT8,
        oid::NUMERIC => oid::array::NUMERIC,
        oid::BYTEA => oid::array::BYTEA,
        oid::UUID => oid::array::UUID,
        _ => unreachable!("対応する配列型 OID がありません"),
    }
}

/// ナノ秒をマイクロ秒精度に切り捨てる。
fn truncate_to_micros(ns: u32) -> u32 {
    ns - ns % 1000
}

proptest! {
    /// スカラー値はエンコード・デコードの往復で元の値を保つ。
    #[test]
    fn prop_scalar_roundtrip(value in scalar_strategy()) {
        let decoded = encode_decode(&value, scalar_decoder_oid(&value));
        prop_assert_eq!(decoded, value);
    }

    /// float は特殊値を含めてエンコード・デコードの往復で元の値を保つ。
    ///
    /// NaN は等価比較できないため、NaN 同士であることを個別に検証する。
    #[test]
    fn prop_float_roundtrip(
        f8 in any_f64(),
        f4 in prop_oneof![finite_f32(), Just(f32::NAN), Just(f32::INFINITY), Just(f32::NEG_INFINITY)],
    ) {
        let decoded = encode_decode(&Value::Float8(f8), oid::FLOAT8);
        match decoded {
            Value::Float8(decoded_f8) => {
                if f8.is_nan() {
                    prop_assert!(decoded_f8.is_nan());
                } else {
                    prop_assert_eq!(decoded_f8, f8);
                }
            }
            other => prop_assert!(false, "FLOAT8 のデコードに失敗しました: {:?}", other),
        }

        let decoded = encode_decode(&Value::Float4(f4), oid::FLOAT4);
        match decoded {
            Value::Float4(decoded_f4) => {
                if f4.is_nan() {
                    prop_assert!(decoded_f4.is_nan());
                } else {
                    prop_assert_eq!(decoded_f4, f4);
                }
            }
            other => prop_assert!(false, "FLOAT4 のデコードに失敗しました: {:?}", other),
        }
    }

    /// 日付はエンコード・デコードの往復で元の値を保つ。
    #[test]
    fn prop_date_roundtrip(value in date_strategy()) {
        let decoded = encode_decode(&value, oid::DATE);
        prop_assert_eq!(decoded, value);
    }

    /// 時刻はマイクロ秒精度まで往復で元の値を保つ。
    ///
    /// PostgreSQL はマイクロ秒精度しか持たないため、
    /// ナノ秒以下は切り捨てて比較する。
    #[test]
    fn prop_time_roundtrip(value in time_strategy()) {
        let Value::Time(original) = &value else {
            unreachable!("time_strategy は Time だけを生成します");
        };
        let decoded = encode_decode(&value, oid::TIME);
        let Value::Time(decoded_time) = decoded else {
            prop_assert!(false, "TIME のデコードに失敗しました: {:?}", decoded);
            unreachable!()
        };
        let expected = NaiveTime::from_hms_nano_opt(
            original.hour(),
            original.minute(),
            original.second(),
            truncate_to_micros(original.nanosecond()),
        )
        .expect("マイクロ秒切り捨て後も有効な時刻です");
        prop_assert_eq!(decoded_time, expected);
    }

    /// タイムスタンプはマイクロ秒精度まで往復で元の値を保つ。
    #[test]
    fn prop_timestamp_roundtrip(value in timestamp_strategy()) {
        let Value::Timestamp(original) = &value else {
            unreachable!("timestamp_strategy は Timestamp だけを生成します");
        };
        let decoded = encode_decode(&value, oid::TIMESTAMP);
        let Value::Timestamp(decoded_ts) = decoded else {
            prop_assert!(false, "TIMESTAMP のデコードに失敗しました: {:?}", decoded);
            unreachable!()
        };
        let expected = original
            .with_nanosecond(truncate_to_micros(original.nanosecond()))
            .expect("マイクロ秒切り捨て後も有効なタイムスタンプです");
        prop_assert_eq!(decoded_ts, expected);
    }

    /// タイムスタンプ (UTC) はマイクロ秒精度まで往復で元の値を保つ。
    #[test]
    fn prop_timestamptz_roundtrip(value in timestamptz_strategy()) {
        let Value::Timestamptz(original) = &value else {
            unreachable!("timestamptz_strategy は Timestamptz だけを生成します");
        };
        let decoded = encode_decode(&value, oid::TIMESTAMPTZ);
        let Value::Timestamptz(decoded_tstz) = decoded else {
            prop_assert!(false, "TIMESTAMPTZ のデコードに失敗しました: {:?}", decoded);
            unreachable!()
        };
        let naive = original
            .naive_utc()
            .with_nanosecond(truncate_to_micros(original.nanosecond()))
            .expect("マイクロ秒切り捨て後も有効なタイムスタンプです");
        let expected = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        prop_assert_eq!(decoded_tstz, expected);
    }

    /// フラットな配列はエンコード・デコードの往復で元の値を保つ。
    #[test]
    fn prop_array_roundtrip(value in array_strategy()) {
        let Value::Array { element_type, .. } = &value else {
            unreachable!("array_strategy は Array だけを生成します");
        };
        // デコードには配列型 OID が必要。Value が持つのは要素型 OID のため、
        // 対応する配列型 OID に変換する。
        let decoded = encode_decode(&value, array_oid_for(*element_type));
        prop_assert_eq!(decoded, value);
    }

    /// NUMERIC の変換は成功時に Numeric、失敗時に Text を返し、
    /// いずれの場合も入力文字列を保持する。
    #[test]
    fn prop_numeric_fallback(s in "\\PC*") {
        let decoded = decoder_for(oid::NUMERIC)(&s);
        let preserved = match decoded {
            Value::Numeric(ref d) | Value::Text(ref d) => d == &s,
            _ => false,
        };
        prop_assert!(
            preserved,
            "NUMERIC の変換は入力文字列を保持する必要があります。入力: {:?}, 結果: {:?}",
            s,
            decoded
        );
    }

    /// DATE の変換は成功時に Date、失敗時に Text を返し、
    /// いずれの場合も入力文字列を保持する。
    #[test]
    fn prop_date_fallback(s in "\\PC*") {
        let decoded = decoder_for(oid::DATE)(&s);
        let preserved = match decoded {
            Value::Date(_) => true,
            Value::Text(ref d) => d == &s,
            _ => false,
        };
        prop_assert!(
            preserved,
            "DATE の変換は Date か Text のいずれかでなければなりません。入力: {:?}, 結果: {:?}",
            s,
            decoded
        );
    }

    /// UUID の変換は成功時に Uuid、失敗時に Text を返し、
    /// いずれの場合も入力文字列を保持する。
    #[test]
    fn prop_uuid_fallback(s in "\\PC*") {
        let decoded = decoder_for(oid::UUID)(&s);
        let preserved = match decoded {
            Value::Uuid(_) => true,
            Value::Text(ref d) => d == &s,
            _ => false,
        };
        prop_assert!(
            preserved,
            "UUID の変換は Uuid か Text のいずれかでなければなりません。入力: {:?}, 結果: {:?}",
            s,
            decoded
        );
    }

    /// 配列の変換は成功時に Array、失敗時に Text を返し、
    /// いずれの場合も入力文字列を保持する。
    #[test]
    fn prop_array_fallback(s in "\\PC*") {
        let decoded = decoder_for(oid::array::INT4)(&s);
        let preserved = match decoded {
            Value::Array { .. } => true,
            Value::Text(ref d) => d == &s,
            _ => false,
        };
        prop_assert!(
            preserved,
            "配列の変換は Array か Text のいずれかでなければなりません。入力: {:?}, 結果: {:?}",
            s,
            decoded
        );
    }
}
