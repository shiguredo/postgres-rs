// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_postgres_core::constants::oid;
use shiguredo_postgres_core::converters::{Value, decoder_for};

fuzz_target!(|data: &[u8]| {
    // データから導出した OID のデコーダーを任意の文字列で実行する。
    // 未知の OID は Text にフォールバックする。
    let derived_oid = data.iter().fold(0u32, |acc, &b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    });

    // データから導出した OID と文字列でデコーダーを実行する。
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decoder_for(derived_oid)(s);

        // 主要なスカラー型と配列型のデコーダーをすべて実行する。
        let type_oids = [
            oid::BOOL, oid::BYTEA, oid::INT2, oid::INT4, oid::INT8, oid::FLOAT4, oid::FLOAT8,
            oid::NUMERIC, oid::OID, oid::UUID, oid::JSON, oid::JSONB, oid::DATE, oid::TIME,
            oid::TIMESTAMP, oid::TIMESTAMPTZ, oid::array::BOOL, oid::array::BYTEA,
            oid::array::INT2, oid::array::INT4, oid::array::INT8, oid::array::FLOAT4,
            oid::array::FLOAT8, oid::array::NUMERIC, oid::array::UUID, oid::array::JSON,
            oid::array::JSONB, oid::array::DATE, oid::array::TIME, oid::array::TIMESTAMP,
            oid::array::TIMESTAMPTZ,
        ];
        for type_oid in type_oids {
            let _ = decoder_for(type_oid)(s);
        }
    }

    // 任意のバイト列を Text / Bytes としてエンコードしてからデコードしても
    // パニックしないことを検証する。
    let text = String::from_utf8_lossy(data);
    let text_value = Value::Text(text.into_owned());
    let encoded = text_value.to_bytes().expect("Text のエンコードは成功します");
    let encoded_str = std::str::from_utf8(&encoded).expect("テキスト形式は UTF-8 です");
    let _ = decoder_for(oid::TEXT)(encoded_str);

    let bytes_value = Value::Bytes(data.to_vec());
    let encoded = bytes_value.to_bytes().expect("Bytes のエンコードは成功します");
    let encoded_str = std::str::from_utf8(&encoded).expect("テキスト形式は UTF-8 です");
    let _ = decoder_for(oid::BYTEA)(encoded_str);
});
