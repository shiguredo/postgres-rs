// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! メッセージのエンコード・デコードのテスト。

// このテストバイナリでは一部のヘルパーだけを使うため、
// 残りのヘルパーが未使用になることを想定する。
#[expect(dead_code)]
#[path = "helpers/helpers.rs"]
mod helpers;

use helpers::parse_client_message;
use shiguredo_postgres_core::constants::{auth, backend, frontend, oid};
use shiguredo_postgres_core::error::Error;
use shiguredo_postgres_core::protocol::{
    AuthenticationRequest, BackendKeyData, CommandComplete, CopyResponse, DataRow, ErrorResponse,
    NoticeResponse, NotificationResponse, ParameterDescription, ParameterStatus, PostgresPacket,
    ReadyForQuery, RowDescription, bind_message, describe_message, execute_message, parse_message,
    query_message, sasl_initial_response, sasl_response, startup_message, sync_message,
    terminate_message,
};

#[test]
fn structured_messages_consume_the_complete_body() {
    type Parse = fn(&PostgresPacket) -> shiguredo_postgres_core::error::Result<()>;
    let cases: &[(u8, &[u8], Parse)] = &[
        (backend::PARAMETER_STATUS, b"TimeZone\0UTC\0", |p| {
            ParameterStatus::parse(p).map(drop)
        }),
        (backend::BACKEND_KEY_DATA, &[0; 8], |p| {
            BackendKeyData::parse(p).map(drop)
        }),
        (backend::PARAMETER_DESCRIPTION, &[0, 0], |p| {
            ParameterDescription::parse(p).map(drop)
        }),
        (backend::ROW_DESCRIPTION, &[0, 0], |p| {
            RowDescription::parse(p).map(drop)
        }),
        (backend::DATA_ROW, &[0, 0], |p| DataRow::parse(p).map(drop)),
        (backend::COMMAND_COMPLETE, b"SELECT 0\0", |p| {
            CommandComplete::parse(p).map(drop)
        }),
        (
            backend::NOTIFICATION_RESPONSE,
            b"\0\0\0\x01events\0\0",
            |p| NotificationResponse::parse(p).map(drop),
        ),
        (backend::COPY_OUT_RESPONSE, &[0, 0, 1, 0, 0], |p| {
            CopyResponse::parse_out(p).map(drop)
        }),
        (
            backend::ERROR_RESPONSE,
            b"SERROR\0C22000\0Mexample\0\0",
            |p| ErrorResponse::parse(p).map(drop),
        ),
        (backend::NOTICE_RESPONSE, b"SNOTICE\0Mexample\0\0", |p| {
            NoticeResponse::parse(p).map(drop)
        }),
    ];
    for &(message_type, data, parse) in cases {
        let mut packet = PostgresPacket {
            message_type,
            data: data.to_vec(),
        };
        parse(&packet).expect("正しい本文を受理できません");
        packet.data.push(0);
        assert!(
            matches!(parse(&packet), Err(Error::InternalError(_))),
            "本文末尾の余剰バイトを受理しました: {message_type}"
        );
    }
}

#[test]
fn diagnostic_fields_require_a_separate_message_terminator() {
    let mut packet = PostgresPacket {
        message_type: backend::ERROR_RESPONSE,
        data: b"C22000\0Mexample\0".to_vec(),
    };
    // 最後の文字列を閉じる NUL はフィールド一覧の終端を兼ねない。
    assert!(matches!(
        ErrorResponse::parse(&packet),
        Err(Error::InternalError(_))
    ));
    // 将来追加されるフィールドは、その長さと終端が正しければ無視できる。
    packet.data.extend_from_slice(b"?extension\0\0");
    let response = ErrorResponse::parse(&packet).expect("終端付きの未知フィールドを処理できません");
    assert_eq!(response.code, "22000");
    assert_eq!(response.message, "example");
}

#[test]
fn test_startup_message() {
    let message = startup_message(&[("user", "postgres"), ("database", "mydb")]);
    // タイプバイトはない。先頭 4 バイトは長さ。
    let length = u32::from_be_bytes([message[0], message[1], message[2], message[3]]) as usize;
    assert_eq!(length, message.len());
    // 次の 4 バイトはプロトコルバージョン 3.0。
    let version = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    assert_eq!(version, 196_608);
    // パラメータが NUL 終端で並ぶ。
    let params = &message[8..message.len() - 1];
    assert!(params.starts_with(b"user\0postgres\0database\0mydb\0"));
    assert_eq!(message[message.len() - 1], 0);
}

#[test]
fn test_query_message() {
    let message = query_message("SELECT 1");
    let (message_type, payload) = parse_client_message(&message);
    assert_eq!(message_type, frontend::QUERY);
    assert_eq!(payload, b"SELECT 1\0");
}

#[test]
fn test_sasl_initial_response() {
    let message = sasl_initial_response("SCRAM-SHA-256", b"n,,n=,r=abc");
    let (message_type, payload) = parse_client_message(&message);
    assert_eq!(message_type, frontend::PASSWORD);
    // メカニズム名 (NUL 終端) + 初期応答の長さ + 初期応答。
    assert_eq!(&payload[..14], b"SCRAM-SHA-256\0");
    let length = i32::from_be_bytes([payload[14], payload[15], payload[16], payload[17]]);
    assert_eq!(length as usize, payload.len() - 18);
    assert_eq!(&payload[18..], b"n,,n=,r=abc");
}

#[test]
fn test_sasl_response() {
    let message = sasl_response(b"c=biws,r=abc,p=xyz");
    let (message_type, payload) = parse_client_message(&message);
    assert_eq!(message_type, frontend::PASSWORD);
    // ペイロードは追加データそのもの (長さフィールドなし)。
    assert_eq!(payload, b"c=biws,r=abc,p=xyz");
}

#[test]
fn test_parse_messages() {
    // AuthenticationRequest: コード + 追加データ。
    let packet = PostgresPacket {
        message_type: backend::AUTHENTICATION_REQUEST,
        data: 5_u32
            .to_be_bytes()
            .iter()
            .chain([1, 2, 3, 4].iter())
            .copied()
            .collect(),
    };
    let auth_request =
        AuthenticationRequest::parse(&packet).expect("AuthenticationRequest の解析に成功しました");
    assert_eq!(auth_request.code(), auth::MD5_PASSWORD);
    assert_eq!(auth_request.data, vec![1, 2, 3, 4]);

    // SASL のメカニズムリスト。
    let mut sasl_data = 10_u32.to_be_bytes().to_vec();
    sasl_data.extend_from_slice(b"SCRAM-SHA-256\0SCRAM-SHA-256-PLUS\0\0");
    let sasl = AuthenticationRequest::parse(&PostgresPacket {
        message_type: backend::AUTHENTICATION_REQUEST,
        data: sasl_data,
    })
    .expect("AuthenticationRequest の解析に成功しました");
    assert_eq!(sasl.code(), auth::SASL);
    assert_eq!(
        sasl.mechanisms(),
        vec![
            "SCRAM-SHA-256".to_string(),
            "SCRAM-SHA-256-PLUS".to_string()
        ]
    );

    // ParameterStatus。
    let packet = PostgresPacket {
        message_type: backend::PARAMETER_STATUS,
        data: b"server_version\0"
            .iter()
            .chain(b"17.0\0".iter())
            .copied()
            .collect(),
    };
    let status = ParameterStatus::parse(&packet).expect("ParameterStatus の解析に成功しました");
    assert_eq!(status.name, "server_version");
    assert_eq!(status.value, "17.0");

    // BackendKeyData。
    let packet = PostgresPacket {
        message_type: backend::BACKEND_KEY_DATA,
        data: 123_u32
            .to_be_bytes()
            .iter()
            .chain(456_u32.to_be_bytes().iter())
            .copied()
            .collect(),
    };
    let key_data = BackendKeyData::parse(&packet).expect("BackendKeyData の解析に成功しました");
    assert_eq!(key_data.process_id, 123);
    assert_eq!(key_data.secret_key, 456);

    // ReadyForQuery。
    let packet = PostgresPacket {
        message_type: backend::READY_FOR_QUERY,
        data: vec![b'I'],
    };
    let ready = ReadyForQuery::parse(&packet).expect("ReadyForQuery の解析に成功しました");
    assert_eq!(ready.transaction_status, b'I');
}

#[test]
fn test_parse_authentication_wrong_type() {
    let packet = PostgresPacket {
        message_type: backend::READY_FOR_QUERY,
        data: vec![b'I'],
    };
    assert!(matches!(
        AuthenticationRequest::parse(&packet),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_parse_row_description() {
    // フィールド: (name, table_oid, column_attr, type_oid, type_size, type_modifier, format)。
    let mut payload = 1_i16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"id\0");
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload.extend_from_slice(&0_i16.to_be_bytes());
    payload.extend_from_slice(&oid::INT4.to_be_bytes());
    payload.extend_from_slice(&4_i16.to_be_bytes());
    payload.extend_from_slice(&(-1_i32).to_be_bytes());
    payload.extend_from_slice(&0_i16.to_be_bytes());

    let packet = PostgresPacket {
        message_type: backend::ROW_DESCRIPTION,
        data: payload,
    };
    let description = RowDescription::parse(&packet).expect("RowDescription の解析に成功しました");
    assert_eq!(description.fields.len(), 1);
    assert_eq!(description.fields[0].name, "id");
    assert_eq!(description.fields[0].type_oid, oid::INT4);
    assert_eq!(description.fields[0].type_size, 4);
}

#[test]
fn test_parse_data_row() {
    // 3 カラム: 値, NULL, 空文字列。
    let mut payload = 3_i16.to_be_bytes().to_vec();
    payload.extend_from_slice(&3_i32.to_be_bytes());
    payload.extend_from_slice(b"abc");
    payload.extend_from_slice(&(-1_i32).to_be_bytes());
    payload.extend_from_slice(&0_i32.to_be_bytes());

    let packet = PostgresPacket {
        message_type: backend::DATA_ROW,
        data: payload,
    };
    let row = DataRow::parse(&packet).expect("DataRow の解析に成功しました");
    assert_eq!(row.values.len(), 3);
    assert_eq!(row.values[0], Some(b"abc".to_vec()));
    assert_eq!(row.values[1], None);
    assert_eq!(row.values[2], Some(Vec::new()));
}

#[test]
fn test_parse_data_row_truncated() {
    // 長さ 10 を宣言したのに 3 バイトしかない。
    let mut payload = 1_i16.to_be_bytes().to_vec();
    payload.extend_from_slice(&10_i32.to_be_bytes());
    payload.extend_from_slice(b"abc");
    let packet = PostgresPacket {
        message_type: backend::DATA_ROW,
        data: payload,
    };
    assert!(matches!(
        DataRow::parse(&packet),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_parse_command_complete() {
    let packet = PostgresPacket {
        message_type: backend::COMMAND_COMPLETE,
        data: b"INSERT 0 5\0".to_vec(),
    };
    let command = CommandComplete::parse(&packet).expect("CommandComplete の解析に成功しました");
    assert_eq!(command.tag, "INSERT 0 5");
}

#[test]
fn test_parse_error_response() {
    let packet = PostgresPacket {
        message_type: backend::ERROR_RESPONSE,
        data: helpers::error_response_payload("42P01", "relation \"foo\" does not exist"),
    };
    let response = ErrorResponse::parse(&packet).expect("ErrorResponse の解析に成功しました");
    assert_eq!(response.severity, "ERROR");
    assert_eq!(response.code, "42P01");
    assert_eq!(response.message, "relation \"foo\" does not exist");
}

#[test]
fn test_parse_parameter_description() {
    let mut payload = 2_i16.to_be_bytes().to_vec();
    payload.extend_from_slice(&oid::TEXT.to_be_bytes());
    payload.extend_from_slice(&oid::INT4.to_be_bytes());
    let packet = PostgresPacket {
        message_type: backend::PARAMETER_DESCRIPTION,
        data: payload,
    };
    let description =
        ParameterDescription::parse(&packet).expect("ParameterDescription の解析に成功しました");
    assert_eq!(description.type_oids, vec![oid::TEXT, oid::INT4]);
}

#[test]
fn test_parse_invalid_utf8() {
    // パラメータ名が不正な UTF-8。
    let packet = PostgresPacket {
        message_type: backend::PARAMETER_STATUS,
        data: vec![0xff, 0xfe, 0],
    };
    assert!(matches!(
        ParameterStatus::parse(&packet),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_parse_ready_for_query_invalid_length() {
    let packet = PostgresPacket {
        message_type: backend::READY_FOR_QUERY,
        data: vec![b'I', b'T'],
    };
    assert!(matches!(
        ReadyForQuery::parse(&packet),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_parse_messages_roundtrip() {
    // 拡張クエリプロトコルのフロントエンドメッセージを組み立てて、
    // 中身を検証する。
    let parse = parse_message("", "SELECT $1::int", &[]);
    let (message_type, payload) = parse_client_message(&parse);
    assert_eq!(message_type, frontend::PARSE);
    assert_eq!(payload, b"\0SELECT $1::int\0\0\0");

    let bind = bind_message("", "", &[Some(b"42")]);
    let (message_type, payload) = parse_client_message(&bind);
    assert_eq!(message_type, frontend::BIND);
    // portal\0 statement\0 形式コード数 0 パラメータ数 1 長さ 2 "42" 結果形式コード数 0。
    let mut expected = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 2];
    expected.extend_from_slice(b"42");
    expected.extend_from_slice(&[0, 0]);
    assert_eq!(payload, expected);

    let describe = describe_message(b'P', "");
    let (message_type, payload) = parse_client_message(&describe);
    assert_eq!(message_type, frontend::DESCRIBE);
    assert_eq!(payload, b"P\0");

    let execute = execute_message("", 0);
    let (message_type, payload) = parse_client_message(&execute);
    assert_eq!(message_type, frontend::EXECUTE);
    assert_eq!(payload, b"\0\0\0\0\0");

    let sync = sync_message();
    let (message_type, payload) = parse_client_message(&sync);
    assert_eq!(message_type, frontend::SYNC);
    assert!(payload.is_empty());

    let terminate = terminate_message();
    let (message_type, payload) = parse_client_message(&terminate);
    assert_eq!(message_type, frontend::TERMINATE);
    assert!(payload.is_empty());
}

#[test]
fn test_ssl_request_message() {
    let message = shiguredo_postgres_core::protocol::ssl_request_message();
    assert_eq!(message.len(), 8);
    let length = u32::from_be_bytes([message[0], message[1], message[2], message[3]]);
    assert_eq!(length, 8);
    let code = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    assert_eq!(code, 80_877_103);
}
