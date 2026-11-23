// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! converters モジュールの Property-Based Testing。
//!
//! エンコード (to_bytes) とデコード (decoder_for) の往復が
//! 元の値を保持することを検証する。

use shiguredo_postgres_core::constants::oid;
use shiguredo_postgres_core::converters::{Value, decoder_for};
use shiguredo_postgres_core::datetime::{Date, Time, Timestamp, Timestamptz};
use std::cell::Cell;

/// 長さをサンプリングする。
///
/// 空・単一・最大の境界値に意味のある確率 (1/2) を与え、
/// 残りは区間内を一様に引く。
fn sample_len(ctx: &mut noprop::TestCaseContext, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    if max == 1 {
        return noprop::sample_usize_in(ctx, 0..=1);
    }
    noprop::sample_with_boundaries(ctx, &[0, 1, max], noprop::Ratio::one_nth(2), |ctx| {
        noprop::sample_usize_in(ctx, 0..=max)
    })
}

/// NUL を含まない文字列をサンプリングする。
///
/// フォールバック系のテストは NUL を含まない文字列を使うため、
///
/// 生成後に NUL を置き換える。
fn sample_cstring(ctx: &mut noprop::TestCaseContext, max_len: usize) -> String {
    let len = sample_len(ctx, max_len);
    let s = noprop::sample_string(ctx, len);
    // NUL は C 文字列の終端と衝突するため置き換える。
    s.replace('\0', "a")
}

/// 任意のテキストをサンプリングする。
///
/// Text / Json は NUL を含めてもエンコード・デコードで保持されるため、
/// 置き換えは行わない。
fn sample_text(ctx: &mut noprop::TestCaseContext, max_len: usize) -> String {
    let len = sample_len(ctx, max_len);
    noprop::sample_string(ctx, len)
}

/// 長さ 0..=max のバイト列をサンプリングする。
fn sample_bytes_capped(ctx: &mut noprop::TestCaseContext, max: usize) -> Vec<u8> {
    let len = sample_len(ctx, max);
    noprop::sample_bytes_vec(ctx, len)
}

/// NaN と無限大を含む f64 をサンプリングする。
///
/// 有限値を 4/7、NaN・正の無限大・負の無限大を各 1/7 で生成する。
/// 256 ケースで特定の特殊値を見逃す確率は (6/7)^256 ≒ 1e-17 で無視できる。
fn sample_f64_arbitrary(ctx: &mut noprop::TestCaseContext) -> f64 {
    match noprop::sample_weighted_index(ctx, &[4, 1, 1, 1]) {
        0 => noprop::sample_f64(ctx),
        1 => f64::NAN,
        2 => f64::INFINITY,
        _ => f64::NEG_INFINITY,
    }
}

/// NaN と無限大を含む f32 をサンプリングする。
///
/// 分布は f64 と同じく有限値を 4/7、特殊値を各 1/7 とする。
fn sample_f32_arbitrary(ctx: &mut noprop::TestCaseContext) -> f32 {
    match noprop::sample_weighted_index(ctx, &[4, 1, 1, 1]) {
        0 => noprop::sample_f32(ctx),
        1 => f32::NAN,
        2 => f32::INFINITY,
        _ => f32::NEG_INFINITY,
    }
}

/// エンコード・デコードで往復が成立するスカラー値をサンプリングする。
///
/// 戻り値の添え字は呼び出し側のカバレッジ記録用で、10 種類の variant を
/// 均等な重みで選ぶ。NaN を含む float と特殊値を含む float は専用のテストで扱う。
fn sample_scalar(ctx: &mut noprop::TestCaseContext) -> (usize, Value) {
    // 11 variant を均等に選ぶ。256 ケースで特定 variant を見逃す確率は
    // (10/11)^256 ≒ 3e-11 で無視できる。
    let index = noprop::sample_weighted_index(ctx, &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    let value = match index {
        0 => Value::Bool(noprop::sample_bool(ctx)),
        1 => Value::Int2(noprop::sample_i16(ctx)),
        2 => Value::Int4(noprop::sample_i32(ctx)),
        3 => Value::Int8(noprop::sample_i64(ctx)),
        4 => Value::Numeric(noprop::sample_i64(ctx).to_string()),
        5 => Value::Oid(noprop::sample_u32(ctx)),
        6 => Value::Text(sample_text(ctx, 64)),
        7 => Value::Bytes(sample_bytes_capped(ctx, 256)),
        8 => Value::Uuid(noprop::sample_u128(ctx)),
        9 => Value::Oid8(noprop::sample_u64(ctx)),
        _ => Value::Json(sample_text(ctx, 64)),
    };
    (index, value)
}

/// 閉区間の年を一様に引く。幅は `u32` に収まる。
fn sample_year_in(ctx: &mut noprop::TestCaseContext, low: i32, high: i32) -> i32 {
    let span = u32::try_from(i64::from(high) - i64::from(low)).expect("年の幅は u32 に収まります");
    let offset = noprop::sample_usize_in(
        ctx,
        0..=usize::try_from(span).expect("年の幅は usize に収まります"),
    );
    low + i32::try_from(offset).expect("引いた年のオフセットは i32 に収まります")
}

/// 時分秒とマイクロ秒を、1 日の中の通常の時刻として引く。
fn sample_hms_micro(ctx: &mut noprop::TestCaseContext) -> (u32, u32, u32, u32) {
    (
        noprop::sample_usize_in(ctx, 0..=23) as u32,
        noprop::sample_usize_in(ctx, 0..=59) as u32,
        noprop::sample_usize_in(ctx, 0..=59) as u32,
        noprop::sample_usize_in(ctx, 0..=999_999) as u32,
    )
}

/// 有効な日付の Value をサンプリングする。
///
/// 年は 4713 BC から 5874897 年まで。存在しない日付は捨てる。
/// 端の日と無限大は境界値として混ぜる。
fn sample_date(ctx: &mut noprop::TestCaseContext) -> Value {
    let edges = [
        Date::from_ymd(-4713, 11, 24).expect("DATE の下限は有効です"),
        Date::from_ymd(5874897, 12, 31).expect("DATE の上限は有効です"),
        Date::from_ymd(0, 2, 29).expect("1 BC の 2 月 29 日は有効です"),
        Date::Infinity,
        Date::NegInfinity,
    ];
    let date = noprop::sample_with_boundaries(ctx, &edges, noprop::Ratio::one_nth(4), |ctx| {
        noprop::sample_with_rejection(ctx, 10, |ctx| {
            // -4712 年以降は各月が存在するので、無効になるのは主に 2 月 29 日以外の日数超過。
            let year = sample_year_in(ctx, -4712, 5_874_897);
            let month = noprop::sample_usize_in(ctx, 1..=12) as u32;
            let day = noprop::sample_usize_in(ctx, 1..=31) as u32;
            Date::from_ymd(year, month, day)
        })
    });
    Value::Date(date)
}

/// 有効な時刻の Value をサンプリングする。
///
/// マイクロ秒精度。`24:00:00` は境界値として混ぜる。
fn sample_time(ctx: &mut noprop::TestCaseContext) -> Value {
    let end = Time::from_hms_micro(24, 0, 0, 0).expect("24:00:00 は有効です");
    let time = noprop::sample_with_boundaries(ctx, &[end], noprop::Ratio::one_nth(8), |ctx| {
        let (hour, minute, second, micro) = sample_hms_micro(ctx);
        Time::from_hms_micro(hour, minute, second, micro).expect("通常の時刻は有効です")
    });
    Value::Time(time)
}

/// 有効なタイムスタンプの Value をサンプリングする。
///
/// 年は TIMESTAMP の範囲 (4713 BC から 294276 年) から引く。
fn sample_timestamp(ctx: &mut noprop::TestCaseContext) -> Value {
    let edges = [
        Timestamp::from_ymd_hms_micro(-4713, 11, 24, 0, 0, 0, 0)
            .expect("TIMESTAMP の下限は有効です"),
        Timestamp::from_ymd_hms_micro(294276, 12, 31, 23, 59, 59, 999_999)
            .expect("TIMESTAMP の上限は有効です"),
        Timestamp::Infinity,
        Timestamp::NegInfinity,
    ];
    let timestamp = noprop::sample_with_boundaries(ctx, &edges, noprop::Ratio::one_nth(4), |ctx| {
        noprop::sample_with_rejection(ctx, 10, |ctx| {
            let year = sample_year_in(ctx, -4712, 294_276);
            let month = noprop::sample_usize_in(ctx, 1..=12) as u32;
            let day = noprop::sample_usize_in(ctx, 1..=31) as u32;
            let (hour, minute, second, micro) = sample_hms_micro(ctx);
            Timestamp::from_ymd_hms_micro(year, month, day, hour, minute, second, micro)
        })
    });
    Value::Timestamp(timestamp)
}

/// 有効なタイムスタンプ (UTC) の Value をサンプリングする。
fn sample_timestamptz(ctx: &mut noprop::TestCaseContext) -> Value {
    let edges = [
        Timestamptz::from_utc_ymd_hms_micro(-4713, 11, 24, 0, 0, 0, 0)
            .expect("TIMESTAMPTZ の下限は有効です"),
        Timestamptz::from_utc_ymd_hms_micro(294276, 12, 31, 23, 59, 59, 999_999)
            .expect("TIMESTAMPTZ の上限は有効です"),
        Timestamptz::Infinity,
        Timestamptz::NegInfinity,
    ];
    let timestamp = noprop::sample_with_boundaries(ctx, &edges, noprop::Ratio::one_nth(4), |ctx| {
        noprop::sample_with_rejection(ctx, 10, |ctx| {
            let year = sample_year_in(ctx, -4712, 294_276);
            let month = noprop::sample_usize_in(ctx, 1..=12) as u32;
            let day = noprop::sample_usize_in(ctx, 1..=31) as u32;
            let (hour, minute, second, micro) = sample_hms_micro(ctx);
            Timestamptz::from_utc_ymd_hms_micro(year, month, day, hour, minute, second, micro)
        })
    });
    Value::Timestamptz(timestamp)
}

/// 要素型ごとの配列の Value をサンプリングする。
///
/// 要素はその配列型 OID のデコーダーで往復できるスカラー値だけを使う。
/// 複合要素 (ネスト配列) はサポート対象外のため含めない。
/// 戻り値の添え字は呼び出し側のカバレッジ記録用である。
fn sample_array(ctx: &mut noprop::TestCaseContext) -> (usize, Value) {
    // 10 種類の要素型を均等に選ぶ。256 ケースで特定型を見逃す確率は
    // (9/10)^256 ≒ 2e-12 で無視できる。
    let index = noprop::sample_weighted_index(ctx, &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    let count = sample_len(ctx, 8);
    let value = match index {
        0 => Value::Array {
            element_type: oid::BOOL,
            values: (0..count)
                .map(|_| Value::Bool(noprop::sample_bool(ctx)))
                .collect(),
        },
        1 => Value::Array {
            element_type: oid::INT2,
            values: (0..count)
                .map(|_| Value::Int2(noprop::sample_i16(ctx)))
                .collect(),
        },
        2 => Value::Array {
            element_type: oid::INT4,
            values: (0..count)
                .map(|_| Value::Int4(noprop::sample_i32(ctx)))
                .collect(),
        },
        3 => Value::Array {
            element_type: oid::INT8,
            values: (0..count)
                .map(|_| Value::Int8(noprop::sample_i64(ctx)))
                .collect(),
        },
        4 => Value::Array {
            element_type: oid::FLOAT4,
            values: (0..count)
                .map(|_| Value::Float4(noprop::sample_f32(ctx)))
                .collect(),
        },
        5 => Value::Array {
            element_type: oid::FLOAT8,
            values: (0..count)
                .map(|_| Value::Float8(noprop::sample_f64(ctx)))
                .collect(),
        },
        6 => Value::Array {
            element_type: oid::NUMERIC,
            values: (0..count)
                .map(|_| Value::Numeric(noprop::sample_i64(ctx).to_string()))
                .collect(),
        },
        7 => Value::Array {
            element_type: oid::BYTEA,
            values: (0..count)
                .map(|_| Value::Bytes(sample_bytes_capped(ctx, 64)))
                .collect(),
        },
        8 => Value::Array {
            element_type: oid::OID8,
            values: (0..count)
                .map(|_| Value::Oid8(noprop::sample_u64(ctx)))
                .collect(),
        },
        _ => Value::Array {
            element_type: oid::UUID,
            values: (0..count)
                .map(|_| Value::Uuid(noprop::sample_u128(ctx)))
                .collect(),
        },
    };
    (index, value)
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
        Value::Oid8(_) => oid::OID8,
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
        oid::OID8 => oid::array::OID8,
        _ => unreachable!("対応する配列型 OID がありません"),
    }
}

/// スカラー値はエンコード・デコードの往復で元の値を保つ。
#[test]
fn prop_scalar_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // 11 variant のうち 1 つでも欠けると検証が偏るため、ビットマスクで記録する。
    let seen = Cell::new(0u16);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let (index, value) = sample_scalar(ctx);
        let decoded = encode_decode(&value, scalar_decoder_oid(&value));
        assert_eq!(decoded, value, "スカラー値の往復で値が変化しました");
        // 検証に成功した variant だけを記録する。失敗したケースで
        // ゲートを満たしてはならない。
        seen.set(seen.get() | (1 << index));
        Ok(())
    })?;
    assert_eq!(
        seen.get(),
        0x7ff,
        "すべてのスカラー型が検証されませんでした: {:#013b}\n{runner}",
        seen.get()
    );
    Ok(())
}

/// float は特殊値を含めてエンコード・デコードの往復で元の値を保つ。
///
/// NaN は等価比較できないため、NaN 同士であることを個別に検証する。
#[test]
fn prop_float_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // 特殊値が一度も出ないと分岐の検証が空虚になるため数える。
    let f8_nan = Cell::new(0usize);
    let f8_inf = Cell::new(0usize);
    let f4_nan = Cell::new(0usize);
    let f4_inf = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let f8 = sample_f64_arbitrary(ctx);
        let f4 = sample_f32_arbitrary(ctx);

        let decoded = encode_decode(&Value::Float8(f8), oid::FLOAT8);
        match decoded {
            Value::Float8(decoded_f8) => {
                if f8.is_nan() {
                    assert!(decoded_f8.is_nan(), "FLOAT8 の NaN が保持されませんでした");
                } else {
                    assert_eq!(decoded_f8, f8, "FLOAT8 の往復で値が変化しました");
                }
            }
            other => panic!("FLOAT8 のデコードに失敗しました: {:?}", other),
        }

        let decoded = encode_decode(&Value::Float4(f4), oid::FLOAT4);
        match decoded {
            Value::Float4(decoded_f4) => {
                if f4.is_nan() {
                    assert!(decoded_f4.is_nan(), "FLOAT4 の NaN が保持されませんでした");
                } else {
                    assert_eq!(decoded_f4, f4, "FLOAT4 の往復で値が変化しました");
                }
            }
            other => panic!("FLOAT4 のデコードに失敗しました: {:?}", other),
        }

        if f8.is_nan() {
            f8_nan.set(f8_nan.get() + 1);
        }
        if f8.is_infinite() {
            f8_inf.set(f8_inf.get() + 1);
        }
        if f4.is_nan() {
            f4_nan.set(f4_nan.get() + 1);
        }
        if f4.is_infinite() {
            f4_inf.set(f4_inf.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        f8_nan.get() > 0,
        "FLOAT8 の NaN が一度も検証されませんでした\n{runner}"
    );
    assert!(
        f8_inf.get() > 0,
        "FLOAT8 の無限大が一度も検証されませんでした\n{runner}"
    );
    assert!(
        f4_nan.get() > 0,
        "FLOAT4 の NaN が一度も検証されませんでした\n{runner}"
    );
    assert!(
        f4_inf.get() > 0,
        "FLOAT4 の無限大が一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// 日付はエンコード・デコードの往復で元の値を保つ。
#[test]
fn prop_date_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let value = sample_date(ctx);
        let decoded = encode_decode(&value, oid::DATE);
        assert_eq!(decoded, value, "日付の往復で値が変化しました");
        Ok(())
    })?;
    Ok(())
}

/// 時刻はエンコード・デコードの往復で元の値を保つ。
#[test]
fn prop_time_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let value = sample_time(ctx);
        let decoded = encode_decode(&value, oid::TIME);
        assert_eq!(decoded, value, "時刻の往復で値が変化しました");
        Ok(())
    })?;
    Ok(())
}

/// タイムスタンプはエンコード・デコードの往復で元の値を保つ。
#[test]
fn prop_timestamp_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let value = sample_timestamp(ctx);
        let decoded = encode_decode(&value, oid::TIMESTAMP);
        assert_eq!(decoded, value, "タイムスタンプの往復で値が変化しました");
        Ok(())
    })?;
    Ok(())
}

/// タイムスタンプ (UTC) はエンコード・デコードの往復で元の値を保つ。
#[test]
fn prop_timestamptz_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let value = sample_timestamptz(ctx);
        let decoded = encode_decode(&value, oid::TIMESTAMPTZ);
        assert_eq!(
            decoded, value,
            "タイムスタンプ (UTC) の往復で値が変化しました"
        );
        Ok(())
    })?;
    Ok(())
}

/// フラットな配列はエンコード・デコードの往復で元の値を保つ。
#[test]
fn prop_array_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // 10 種類の要素型のうち 1 つでも欠けると検証が偏るため記録する。
    let seen = Cell::new(0u16);
    let non_empty = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let (index, value) = sample_array(ctx);
        let Value::Array { element_type, .. } = &value else {
            unreachable!("配列だけを生成します");
        };
        // デコードには配列型 OID が必要。Value が持つのは要素型 OID のため、
        // 対応する配列型 OID に変換する。
        let decoded = encode_decode(&value, array_oid_for(*element_type));
        assert_eq!(decoded, value, "配列の往復で値が変化しました");
        seen.set(seen.get() | (1 << index));
        let Value::Array { values, .. } = &value else {
            unreachable!("配列だけを生成します");
        };
        if !values.is_empty() {
            non_empty.set(non_empty.get() + 1);
        }
        Ok(())
    })?;
    assert_eq!(
        seen.get(),
        0x3ff,
        "すべての配列要素型が検証されませんでした: {:#012b}\n{runner}",
        seen.get()
    );
    assert!(
        non_empty.get() > 0,
        "非空の配列が一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// NUMERIC の変換は成功時に Numeric、失敗時に Text を返し、
/// いずれの場合も入力文字列を保持する。
#[test]
fn prop_numeric_fallback() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let s = sample_cstring(ctx, 32);
        let decoded = decoder_for(oid::NUMERIC)(&s);
        let preserved = match &decoded {
            Value::Numeric(d) | Value::Text(d) => d == &s,
            _ => false,
        };
        assert!(
            preserved,
            "NUMERIC の変換は入力文字列を保持する必要があります。入力: {:?}, 結果: {:?}",
            s, decoded
        );
        Ok(())
    })?;
    Ok(())
}

/// DATE の変換は成功時に Date、失敗時に Text を返し、
/// いずれの場合も入力文字列を保持する。
#[test]
fn prop_date_fallback() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let s = sample_cstring(ctx, 32);
        let decoded = decoder_for(oid::DATE)(&s);
        let preserved = match &decoded {
            Value::Date(_) => true,
            Value::Text(d) => d == &s,
            _ => false,
        };
        assert!(
            preserved,
            "DATE の変換は Date か Text のいずれかでなければなりません。入力: {:?}, 結果: {:?}",
            s, decoded
        );
        Ok(())
    })?;
    Ok(())
}

/// UUID の変換は成功時に Uuid、失敗時に Text を返し、
/// いずれの場合も入力文字列を保持する。
#[test]
fn prop_uuid_fallback() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let s = sample_cstring(ctx, 32);
        let decoded = decoder_for(oid::UUID)(&s);
        let preserved = match &decoded {
            Value::Uuid(_) => true,
            Value::Text(d) => d == &s,
            _ => false,
        };
        assert!(
            preserved,
            "UUID の変換は Uuid か Text のいずれかでなければなりません。入力: {:?}, 結果: {:?}",
            s, decoded
        );
        Ok(())
    })?;
    Ok(())
}

/// 配列の変換は成功時に Array、失敗時に Text を返し、
/// いずれの場合も入力文字列を保持する。
#[test]
fn prop_array_fallback() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let s = sample_cstring(ctx, 32);
        let decoded = decoder_for(oid::array::INT4)(&s);
        let preserved = match &decoded {
            Value::Array { .. } => true,
            Value::Text(d) => d == &s,
            _ => false,
        };
        assert!(
            preserved,
            "配列の変換は Array か Text のいずれかでなければなりません。入力: {:?}, 結果: {:?}",
            s, decoded
        );
        Ok(())
    })?;
    Ok(())
}

/// NULL を `None` として要素をサンプリングする。NULL は 1/4 の確率で出す。
fn sample_nullable<T>(
    ctx: &mut noprop::TestCaseContext,
    mut sample: impl FnMut(&mut noprop::TestCaseContext) -> T,
) -> Option<T> {
    match noprop::sample_weighted_index(ctx, &[3, 1]) {
        0 => Some(sample(ctx)),
        _ => None,
    }
}

/// `Option` の要素を配列の要素に変換する。`None` は SQL NULL にする。
fn nullable_values<T>(elements: &[Option<T>], to_value: impl Fn(&T) -> Value) -> Vec<Value> {
    elements
        .iter()
        .map(|element| element.as_ref().map_or(Value::Null, &to_value))
        .collect()
}

/// 配列はエンコード・デコードの往復の後、`Vec<Option<T>>` として元の要素を取り出せる。
///
/// NULL を含まない配列だけが `Vec<T>` としても取り出せ、NULL を含む配列はエラーになる。
/// 1 次元の integer[] と text[]、2 次元の integer[] を検証する。
#[test]
fn prop_array_into_vec() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // NULL の有無と 2 次元配列のどれかが一度も出ないと検証が空虚になるため数える。
    let with_null = Cell::new(0usize);
    let without_null = Cell::new(0usize);
    let nested = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        // integer[]
        let len = sample_len(ctx, 8);
        let ints: Vec<Option<i32>> = (0..len)
            .map(|_| sample_nullable(ctx, noprop::sample_i32))
            .collect();
        let value = Value::Array {
            element_type: oid::INT4,
            values: nullable_values(&ints, |v| Value::Int4(*v)),
        };
        let decoded = encode_decode(&value, oid::array::INT4);
        assert_eq!(
            Vec::<Option<i32>>::try_from(&decoded).expect("integer[] を取り出せません"),
            ints,
            "integer[] の要素が変化しました"
        );
        if ints.iter().all(Option::is_some) {
            let expected: Vec<i32> = ints.iter().flatten().copied().collect();
            assert_eq!(
                Vec::<i32>::try_from(&decoded).expect("NULL のない integer[] を取り出せません"),
                expected,
                "NULL のない integer[] の要素が変化しました"
            );
            without_null.set(without_null.get() + 1);
        } else {
            assert!(
                Vec::<i32>::try_from(&decoded).is_err(),
                "NULL を含む integer[] を Vec<i32> で取り出せました"
            );
            with_null.set(with_null.get() + 1);
        }

        // text[]。引用符が必要な文字や "NULL" という文字列も要素として保持する。
        let len = sample_len(ctx, 8);
        let texts: Vec<Option<String>> = (0..len)
            .map(|_| sample_nullable(ctx, |ctx| sample_cstring(ctx, 8)))
            .collect();
        let value = Value::Array {
            element_type: oid::TEXT,
            values: nullable_values(&texts, |v| Value::Text(v.clone())),
        };
        let decoded = encode_decode(&value, oid::array::TEXT);
        assert_eq!(
            Vec::<Option<String>>::try_from(&decoded).expect("text[] を取り出せません"),
            texts,
            "text[] の要素が変化しました"
        );

        // 2 次元の integer[]。PostgreSQL の多次元配列と同じく、行の長さをそろえる。
        let rows = noprop::sample_usize_in(ctx, 1..=3);
        let columns = noprop::sample_usize_in(ctx, 1..=3);
        let matrix: Vec<Vec<Option<i32>>> = (0..rows)
            .map(|_| {
                (0..columns)
                    .map(|_| sample_nullable(ctx, noprop::sample_i32))
                    .collect()
            })
            .collect();
        let value = Value::Array {
            element_type: oid::INT4,
            values: matrix
                .iter()
                .map(|row| Value::Array {
                    element_type: oid::INT4,
                    values: nullable_values(row, |v| Value::Int4(*v)),
                })
                .collect(),
        };
        let decoded = encode_decode(&value, oid::array::INT4);
        assert_eq!(
            Vec::<Vec<Option<i32>>>::try_from(&decoded)
                .expect("2 次元の integer[] を取り出せません"),
            matrix,
            "2 次元の integer[] の要素が変化しました"
        );
        nested.set(nested.get() + 1);
        Ok(())
    })?;
    assert!(
        with_null.get() > 0 && without_null.get() > 0 && nested.get() > 0,
        "NULL の有無または 2 次元配列が検証されませんでした\n{runner}"
    );
    Ok(())
}
