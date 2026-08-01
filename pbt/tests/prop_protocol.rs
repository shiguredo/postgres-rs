// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! protocol モジュールの Property-Based Testing。
//!
//! フロントエンドメッセージの組み立てがフレーム構造を満たすこと、
//! バックエンドメッセージの組み立てと解析の往復が元の値を保持することを
//! 検証する。

use proptest::prelude::*;
use shiguredo_postgres_core::constants::{backend, frontend};
use shiguredo_postgres_core::protocol::{
    BackendKeyData, CommandComplete, CopyResponse, DataRow, ErrorResponse, NotificationResponse,
    ParameterDescription, PostgresPacket, RowDescription, bind_message, cancel_request_message,
    close_message, copy_data_message, copy_done_message, copy_fail_message, describe_message,
    execute_message, flush_message, parse_message, password_message, query_message,
    sasl_initial_response, sasl_response, startup_message, sync_message, terminate_message,
};

/// NUL 終端文字列をペイロードに追加する。
fn push_cstring(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// フロントエンドメッセージのフレーム構造を検証する。
///
/// 形式は「1 バイトタイプ + 4 バイト長さ (自身を含む) + ペイロード」。
/// 長さフィールドはタイプバイトを除いたバイト数を表すため、
/// メッセージ全体の長さより 1 小さい。
fn check_frame(message: &[u8], expected_type: u8) -> Result<(), String> {
    if message.len() < 5 {
        return Err(format!("メッセージが短すぎます: {} バイト", message.len()));
    }
    if message[0] != expected_type {
        return Err(format!(
            "メッセージタイプが一致しません: 期待 '{}' 実測 '{}'",
            expected_type as char, message[0] as char
        ));
    }
    let length = u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize;
    if length != message.len() - 1 {
        return Err(format!(
            "長さフィールドが一致しません: 期待 {} 実測 {}",
            length,
            message.len() - 1
        ));
    }
    Ok(())
}

proptest! {
    /// すべてのフロントエンドメッセージは正しいフレーム構造を持つ。
    #[test]
    fn prop_frontend_frame(
        sql in "\\PC*",
        password in proptest::collection::vec(any::<u8>(), 0..=256),
        mechanism in "\\PC*",
        initial_response in proptest::collection::vec(any::<u8>(), 0..=256),
        sasl_data in proptest::collection::vec(any::<u8>(), 0..=256),
        kind in any::<u8>(),
        name in "\\PC*",
        copy_data in proptest::collection::vec(any::<u8>(), 0..=256),
        fail_message in "\\PC*",
        statement in "\\PC*",
        query in "\\PC*",
        parameter_types in proptest::collection::vec(any::<u32>(), 0..=16),
        portal in "\\PC*",
        parameters in proptest::collection::vec(
            proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=256)),
            0..=16,
        ),
        max_rows in any::<u32>(),
    ) {
        prop_assert!(check_frame(&query_message(&sql), frontend::QUERY).is_ok());
        prop_assert!(check_frame(&password_message(&password), frontend::PASSWORD).is_ok());
        prop_assert!(
            check_frame(&sasl_initial_response(&mechanism, &initial_response), frontend::PASSWORD).is_ok()
        );
        prop_assert!(check_frame(&sasl_response(&sasl_data), frontend::PASSWORD).is_ok());
        prop_assert!(check_frame(&terminate_message(), frontend::TERMINATE).is_ok());
        prop_assert!(check_frame(&close_message(kind, &name), frontend::CLOSE).is_ok());
        prop_assert!(check_frame(&flush_message(), frontend::FLUSH).is_ok());
        prop_assert!(check_frame(&copy_data_message(&copy_data), frontend::COPY_DATA).is_ok());
        prop_assert!(check_frame(&copy_done_message(), frontend::COPY_DONE).is_ok());
        prop_assert!(check_frame(&copy_fail_message(&fail_message), frontend::COPY_FAIL).is_ok());
        prop_assert!(
            check_frame(&parse_message(&statement, &query, &parameter_types), frontend::PARSE).is_ok()
        );
        let params: Vec<Option<&[u8]>> = parameters.iter().map(|p| p.as_deref()).collect();
        prop_assert!(
            check_frame(&bind_message(&portal, &statement, &params), frontend::BIND).is_ok()
        );
        prop_assert!(check_frame(&describe_message(kind, &name), frontend::DESCRIBE).is_ok());
        prop_assert!(check_frame(&execute_message(&portal, max_rows), frontend::EXECUTE).is_ok());
        prop_assert!(check_frame(&sync_message(), frontend::SYNC).is_ok());
    }

    /// スタートアップメッセージは長さ・バージョン・終端 NUL の構造を持つ。
    #[test]
    fn prop_startup_message_frame(parameters in proptest::collection::vec(("\\PC*", "\\PC*"), 0..=8)) {
        let refs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let message = startup_message(&refs);
        let length = u32::from_be_bytes([message[0], message[1], message[2], message[3]]) as usize;
        prop_assert_eq!(length, message.len());
        let version = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
        prop_assert_eq!(version, shiguredo_postgres_core::constants::PROTOCOL_VERSION);
        // 末尾はパラメータリストの終端 NUL。
        prop_assert_eq!(message[message.len() - 1], 0);
    }

    /// キャンセル要求メッセージは固定長 16 バイトの構造を持つ。
    #[test]
    fn prop_cancel_request_frame(process_id in any::<u32>(), secret_key in any::<u32>()) {
        let message = cancel_request_message(process_id, secret_key);
        prop_assert_eq!(message.len(), 16);
        let length = u32::from_be_bytes([message[0], message[1], message[2], message[3]]) as usize;
        prop_assert_eq!(length, 16);
        let code = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
        prop_assert_eq!(code, shiguredo_postgres_core::constants::CANCEL_REQUEST_CODE);
        let parsed_pid = u32::from_be_bytes([message[8], message[9], message[10], message[11]]);
        prop_assert_eq!(parsed_pid, process_id);
        let parsed_key = u32::from_be_bytes([message[12], message[13], message[14], message[15]]);
        prop_assert_eq!(parsed_key, secret_key);
    }

    /// DataRow は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_data_row_roundtrip(
        values in proptest::collection::vec(
            proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=256)),
            0..=16,
        ),
    ) {
        let mut payload = (values.len() as u16).to_be_bytes().to_vec();
        for value in &values {
            match value {
                None => payload.extend_from_slice(&(-1_i32).to_be_bytes()),
                Some(bytes) => {
                    payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    payload.extend_from_slice(bytes);
                }
            }
        }
        let packet = PostgresPacket {
            message_type: backend::DATA_ROW,
            data: payload,
        };
        let row = DataRow::parse(&packet).expect("組み立てた DataRow はパースできます");
        prop_assert_eq!(row.values, values);
    }

    /// RowDescription は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_row_description_roundtrip(
        fields in proptest::collection::vec(
            ("\\PC*", any::<u32>(), any::<i16>(), any::<u32>(), any::<i16>(), any::<i32>(), any::<i16>()),
            0..=16,
        ),
    ) {
        let mut payload = (fields.len() as u16).to_be_bytes().to_vec();
        for (name, table_oid, column_attr, type_oid, type_size, type_modifier, format) in &fields {
            push_cstring(&mut payload, name);
            payload.extend_from_slice(&table_oid.to_be_bytes());
            payload.extend_from_slice(&column_attr.to_be_bytes());
            payload.extend_from_slice(&type_oid.to_be_bytes());
            payload.extend_from_slice(&type_size.to_be_bytes());
            payload.extend_from_slice(&type_modifier.to_be_bytes());
            payload.extend_from_slice(&format.to_be_bytes());
        }
        let packet = PostgresPacket {
            message_type: backend::ROW_DESCRIPTION,
            data: payload,
        };
        let parsed = RowDescription::parse(&packet).expect("組み立てた RowDescription はパースできます");
        let roundtripped: Vec<(String, u32, i16, u32, i16, i32, i16)> = parsed
            .fields
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    f.table_oid,
                    f.column_attr,
                    f.type_oid,
                    f.type_size,
                    f.type_modifier,
                    f.format,
                )
            })
            .collect();
        prop_assert_eq!(roundtripped, fields);
    }

    /// ParameterDescription は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_parameter_description_roundtrip(type_oids in proptest::collection::vec(any::<u32>(), 0..=16)) {
        let mut payload = (type_oids.len() as u16).to_be_bytes().to_vec();
        for type_oid in &type_oids {
            payload.extend_from_slice(&type_oid.to_be_bytes());
        }
        let packet = PostgresPacket {
            message_type: backend::PARAMETER_DESCRIPTION,
            data: payload,
        };
        let parsed =
            ParameterDescription::parse(&packet).expect("組み立てた ParameterDescription はパースできます");
        prop_assert_eq!(parsed.type_oids, type_oids);
    }

    /// BackendKeyData は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_backend_key_data_roundtrip(process_id in any::<u32>(), secret_key in any::<u32>()) {
        let mut payload = process_id.to_be_bytes().to_vec();
        payload.extend_from_slice(&secret_key.to_be_bytes());
        let packet = PostgresPacket {
            message_type: backend::BACKEND_KEY_DATA,
            data: payload,
        };
        let parsed = BackendKeyData::parse(&packet).expect("組み立てた BackendKeyData はパースできます");
        prop_assert_eq!(parsed.process_id, process_id);
        prop_assert_eq!(parsed.secret_key, secret_key);
    }

    /// NotificationResponse は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_notification_roundtrip(
        process_id in any::<u32>(),
        channel in "\\PC*",
        payload in "\\PC*",
    ) {
        let mut data = process_id.to_be_bytes().to_vec();
        push_cstring(&mut data, &channel);
        push_cstring(&mut data, &payload);
        let packet = PostgresPacket {
            message_type: backend::NOTIFICATION_RESPONSE,
            data,
        };
        let parsed =
            NotificationResponse::parse(&packet).expect("組み立てた NotificationResponse はパースできます");
        prop_assert_eq!(parsed.process_id, process_id);
        prop_assert_eq!(parsed.channel, channel);
        prop_assert_eq!(parsed.payload, payload);
    }

    /// CommandComplete は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_command_complete_roundtrip(tag in "\\PC*") {
        let mut payload = tag.as_bytes().to_vec();
        payload.push(0);
        let packet = PostgresPacket {
            message_type: backend::COMMAND_COMPLETE,
            data: payload,
        };
        let parsed = CommandComplete::parse(&packet).expect("組み立てた CommandComplete はパースできます");
        prop_assert_eq!(parsed.tag, tag);
    }

    /// CopyResponse は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_copy_response_roundtrip(
        overall_format in any::<u8>(),
        column_formats in proptest::collection::vec(any::<u16>(), 0..=16),
    ) {
        let mut payload = vec![overall_format];
        payload.extend_from_slice(&(column_formats.len() as u16).to_be_bytes());
        for format in &column_formats {
            payload.extend_from_slice(&format.to_be_bytes());
        }
        let packet = PostgresPacket {
            message_type: backend::COPY_IN_RESPONSE,
            data: payload,
        };
        let parsed = CopyResponse::parse_in(&packet).expect("組み立てた CopyResponse はパースできます");
        prop_assert_eq!(parsed.overall_format, overall_format);
        prop_assert_eq!(parsed.column_formats, column_formats);
    }

    /// ErrorResponse は組み立てと解析の往復で元の値を保つ。
    #[test]
    fn prop_error_response_roundtrip(
        severity in "\\PC*",
        severity_nonlocalized in "\\PC*",
        code in "\\PC*",
        message in "\\PC*",
        detail in "\\PC*",
        hint in "\\PC*",
        position in "\\PC*",
        internal_position in "\\PC*",
        internal_query in "\\PC*",
        context in "\\PC*",
        schema in "\\PC*",
        table in "\\PC*",
        column in "\\PC*",
        data_type in "\\PC*",
        constraint in "\\PC*",
        file in "\\PC*",
        line in "\\PC*",
        routine in "\\PC*",
    ) {
        let mut payload = Vec::new();
        push_field(&mut payload, b'S', &severity);
        push_field(&mut payload, b'V', &severity_nonlocalized);
        push_field(&mut payload, b'C', &code);
        push_field(&mut payload, b'M', &message);
        push_field(&mut payload, b'D', &detail);
        push_field(&mut payload, b'H', &hint);
        push_field(&mut payload, b'P', &position);
        push_field(&mut payload, b'p', &internal_position);
        push_field(&mut payload, b'q', &internal_query);
        push_field(&mut payload, b'W', &context);
        push_field(&mut payload, b's', &schema);
        push_field(&mut payload, b't', &table);
        push_field(&mut payload, b'c', &column);
        push_field(&mut payload, b'd', &data_type);
        push_field(&mut payload, b'n', &constraint);
        push_field(&mut payload, b'F', &file);
        push_field(&mut payload, b'L', &line);
        push_field(&mut payload, b'R', &routine);
        payload.push(0);
        let packet = PostgresPacket {
            message_type: backend::ERROR_RESPONSE,
            data: payload,
        };
        let parsed = ErrorResponse::parse(&packet).expect("組み立てた ErrorResponse はパースできます");
        prop_assert_eq!(parsed.severity, severity);
        prop_assert_eq!(parsed.severity_nonlocalized, severity_nonlocalized);
        prop_assert_eq!(parsed.code, code);
        prop_assert_eq!(parsed.message, message);
        prop_assert_eq!(parsed.detail, Some(detail));
        prop_assert_eq!(parsed.hint, Some(hint));
        prop_assert_eq!(parsed.position, Some(position));
        prop_assert_eq!(parsed.internal_position, Some(internal_position));
        prop_assert_eq!(parsed.internal_query, Some(internal_query));
        prop_assert_eq!(parsed.context, Some(context));
        prop_assert_eq!(parsed.schema, Some(schema));
        prop_assert_eq!(parsed.table, Some(table));
        prop_assert_eq!(parsed.column, Some(column));
        prop_assert_eq!(parsed.data_type, Some(data_type));
        prop_assert_eq!(parsed.constraint, Some(constraint));
        prop_assert_eq!(parsed.file, Some(file));
        prop_assert_eq!(parsed.line, Some(line));
        prop_assert_eq!(parsed.routine, Some(routine));
    }
}

/// エラー応答のフィールド (タイプ 1 バイト + NUL 終端文字列) をペイロードに追加する。
fn push_field(out: &mut Vec<u8>, field_type: u8, value: &str) {
    out.push(field_type);
    push_cstring(out, value);
}
