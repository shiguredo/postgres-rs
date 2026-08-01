// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sans I/O な接続状態機械のテスト。
//!
//! サーバーが送信するはずのワイヤプロトコルのバイト列を
//! ヘルパーで組み立てて `feed_bytes` で供給し、
//! クライアントの状態遷移と送信メッセージを検証する。

mod helpers;

use helpers::{
    ScramServer, authentication_cleartext, authentication_md5, authentication_ok,
    authentication_sasl, authentication_sasl_continue, authentication_sasl_final, backend_key_data,
    bind_complete, build_message, command_complete, data_row, error_response,
    parameter_description, parameter_status, parse_client_message, parse_complete, ready_for_query,
    row_description,
};
use shiguredo_postgres_core::connection::{AuthState, ConnectOptions, Connection, SslMode};
use shiguredo_postgres_core::constants::{frontend, oid, transaction_status};
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres_core::error::Error;

fn options() -> ConnectOptions {
    ConnectOptions {
        host: "localhost".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("mydb".to_string()),
        ssl_mode: SslMode::Disabled,
        ..Default::default()
    }
}

/// 送信キューからメッセージを取り出して分解する。
fn pop_client_message(conn: &mut Connection) -> (u8, Vec<u8>) {
    let raw = conn.pop_send_queue().unwrap();
    let (message_type, payload) = parse_client_message(&raw);
    (message_type, payload.to_vec())
}

/// 認証済みの接続を作成する。
fn connect_authenticated() -> Connection {
    let mut conn = Connection::connect(options()).unwrap();
    assert_eq!(
        conn.request_authentication_start().unwrap(),
        AuthState::Send
    );
    let startup = conn.pop_send_queue().unwrap();
    // スタートアップメッセージに user と database が含まれる。
    assert!(startup.windows(5).any(|w| w == b"user\0"));
    assert!(startup.windows(9).any(|w| w == b"database\0"));

    let mut server_data = Vec::new();
    server_data.extend_from_slice(&authentication_ok());
    server_data.extend_from_slice(&parameter_status("server_version", "17.0"));
    server_data.extend_from_slice(&parameter_status("client_encoding", "UTF8"));
    server_data.extend_from_slice(&backend_key_data(12345, 67890));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    while conn.request_authentication_continue().unwrap() != AuthState::Success {}
    assert!(conn.is_open());
    assert_eq!(conn.server_version(), Some("17.0"));
    assert_eq!(conn.backend_process_id(), 12345);
    assert_eq!(conn.backend_secret_key(), 67890);
    assert_eq!(conn.transaction_status(), transaction_status::IDLE);
    conn
}

#[test]
fn test_connect_options_validation() {
    // ポート 0 はエラー。
    let bad = ConnectOptions {
        port: 0,
        ..options()
    };
    assert!(matches!(
        Connection::connect(bad),
        Err(Error::InterfaceError { .. })
    ));

    // タイムアウト 0 はエラー。
    let bad = ConnectOptions {
        connect_timeout: std::time::Duration::ZERO,
        ..options()
    };
    assert!(matches!(
        Connection::connect(bad),
        Err(Error::InterfaceError { .. })
    ));

    // 最大メッセージサイズ 0 はエラー。
    let bad = ConnectOptions {
        max_message_size: 0,
        ..options()
    };
    assert!(matches!(
        Connection::connect(bad),
        Err(Error::InterfaceError { .. })
    ));
}

#[test]
fn test_authentication_success() {
    connect_authenticated();
}

#[test]
fn test_authentication_empty_user() {
    let options = ConnectOptions {
        user: String::new(),
        ..options()
    };
    let mut conn = Connection::connect(options).unwrap();
    assert!(matches!(
        conn.request_authentication_start(),
        Err(Error::InterfaceError { .. })
    ));
}

#[test]
fn test_authentication_md5() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // サーバーが MD5 認証を要求する。
    conn.feed_bytes(&authentication_md5(&[1, 2, 3, 4])).unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );

    // パスワードメッセージの形式を検証する。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    let password = &payload[..payload.len() - 1];
    assert_eq!(password.len(), 35);
    assert!(password.starts_with(b"md5"));

    // 認証完了。
    conn.feed_bytes(&authentication_ok()).unwrap();
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Success
    );
}

#[test]
fn test_authentication_cleartext() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_cleartext()).unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );

    // 平文パスワードが NUL 終端で送られる。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    assert_eq!(payload, b"password\0");

    conn.feed_bytes(&authentication_ok()).unwrap();
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Success
    );
}

#[test]
fn test_authentication_scram() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // サーバーが SCRAM-SHA-256 を要求する。
    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256"]))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );

    // SASL 初期応答を検証する。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    let mechanism_end = payload.iter().position(|&b| b == 0).unwrap();
    assert_eq!(&payload[..mechanism_end], b"SCRAM-SHA-256");
    let response_len = i32::from_be_bytes([
        payload[mechanism_end + 1],
        payload[mechanism_end + 2],
        payload[mechanism_end + 3],
        payload[mechanism_end + 4],
    ]) as usize;
    let client_first =
        std::str::from_utf8(&payload[mechanism_end + 5..mechanism_end + 5 + response_len]).unwrap();
    assert!(client_first.starts_with("n,,n=,r="));

    // サーバー最初のメッセージを送る。
    let server = ScramServer::new();
    let server_first = server.server_first(client_first);
    conn.feed_bytes(&authentication_sasl_continue(server_first.as_bytes()))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );

    // SASL 応答 (クライアント最終メッセージ) を検証する。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    // SASL 応答は長さフィールドなしのペイロードそのもの。
    let client_final = std::str::from_utf8(&payload).unwrap();
    assert!(client_final.starts_with("c=biws,r="));
    assert!(client_final.contains(",p="));

    // サーバー最終メッセージを送る。
    let client_first_bare = client_first.strip_prefix("n,,").unwrap();
    let server_final = server
        .server_final(client_final, b"password", client_first_bare, &server_first)
        .expect("client proof must be valid");
    conn.feed_bytes(&authentication_sasl_final(server_final.as_bytes()))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::NeedRead
    );

    // AuthenticationOk と ReadyForQuery で認証完了。
    conn.feed_bytes(&authentication_ok()).unwrap();
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Success
    );
}

#[test]
fn test_authentication_scram_wrong_password() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256"]))
        .unwrap();
    conn.request_authentication_continue().unwrap();
    let (_, payload) = pop_client_message(&mut conn);
    let mechanism_end = payload.iter().position(|&b| b == 0).unwrap();
    let response_len = i32::from_be_bytes([
        payload[mechanism_end + 1],
        payload[mechanism_end + 2],
        payload[mechanism_end + 3],
        payload[mechanism_end + 4],
    ]) as usize;
    let client_first =
        std::str::from_utf8(&payload[mechanism_end + 5..mechanism_end + 5 + response_len]).unwrap();

    let server = ScramServer::new();
    let server_first = server.server_first(client_first);
    conn.feed_bytes(&authentication_sasl_continue(server_first.as_bytes()))
        .unwrap();
    conn.request_authentication_continue().unwrap();
    let (_, payload) = pop_client_message(&mut conn);
    // SASL 応答は長さフィールドなしのペイロードそのもの。
    std::str::from_utf8(&payload).unwrap();

    // サーバーが認証失敗としてエラー応答を返す。
    conn.feed_bytes(&error_response(
        "28P01",
        "password authentication failed for user \"postgres\"",
    ))
    .unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(e) if e.code() == Some("28P01")
    ));
}

#[test]
fn test_authentication_unsupported_method() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // 未対応の認証方式 (GSSAPI = 7)。
    let mut payload = 7_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"test-data");
    conn.feed_bytes(&build_message(b'R', &payload)).unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NotSupportedError { .. })
    ));
}

#[test]
fn test_authentication_sasl_unsupported_mechanism() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // SCRAM-SHA-256 を含まないメカニズムリスト。
    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-1", "PLAIN"]))
        .unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NotSupportedError { .. })
    ));
}

#[test]
fn test_authentication_oauth() {
    // OAuth トークンを設定した接続は OAUTHBEARER で認証する。
    let mut conn = Connection::connect(ConnectOptions {
        oauth_token: Some("test-token".to_string()),
        ..options()
    })
    .unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // サーバーが OAUTHBEARER メカニズムを提供する。
    conn.feed_bytes(&authentication_sasl(&["OAUTHBEARER"]))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );

    // SASL 初期応答の形式を検証する。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    let mechanism_end = payload.iter().position(|&b| b == 0).unwrap();
    assert_eq!(&payload[..mechanism_end], b"OAUTHBEARER");
    let response_len = i32::from_be_bytes([
        payload[mechanism_end + 1],
        payload[mechanism_end + 2],
        payload[mechanism_end + 3],
        payload[mechanism_end + 4],
    ]) as usize;
    // RFC 7628 の初期応答: GS2 ヘッダー + kvsep + auth=Bearer <token> + kvsep。
    // libpq と同じく host / port は含めない。
    let initial =
        std::str::from_utf8(&payload[mechanism_end + 5..mechanism_end + 5 + response_len]).unwrap();
    assert_eq!(initial, "n,,\x01auth=Bearer test-token\x01\x01");

    // サーバーは検証成功時に最終メッセージを送らず、
    // 直接 AuthenticationOk と ReadyForQuery を送る。
    conn.feed_bytes(&authentication_ok()).unwrap();
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Success
    );
}

#[test]
fn test_authentication_oauth_prefers_oauthbearer() {
    // サーバーが SCRAM-SHA-256 と OAUTHBEARER の両方を提供し、
    // OAuth トークンが設定されている場合は OAUTHBEARER を選ぶ (libpq と同じ)。
    let mut conn = Connection::connect(ConnectOptions {
        oauth_token: Some("test-token".to_string()),
        ..options()
    })
    .unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256", "OAUTHBEARER"]))
        .unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );
    let (_, payload) = pop_client_message(&mut conn);
    let mechanism_end = payload.iter().position(|&b| b == 0).unwrap();
    assert_eq!(&payload[..mechanism_end], b"OAUTHBEARER");
}

#[test]
fn test_authentication_oauth_token_rejected() {
    let mut conn = Connection::connect(ConnectOptions {
        oauth_token: Some("invalid-token".to_string()),
        ..options()
    })
    .unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_sasl(&["OAUTHBEARER"]))
        .unwrap();
    conn.request_authentication_continue().unwrap();
    pop_client_message(&mut conn);

    // サーバーがトークン拒否を SASL 継続 (RFC 7628 の JSON エラー応答) で通知する。
    let error_json = r#"{ "status": "invalid_token", "openid-configuration": "https://issuer.example.com/.well-known/openid-configuration", "scope": "openid" }"#;
    conn.feed_bytes(&authentication_sasl_continue(error_json.as_bytes()))
        .unwrap();
    // 新しいトークンが必要なことを示す制御信号が返る。
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NeedOAuthToken)
    ));
}

#[test]
fn test_authentication_oauth_without_token() {
    // トークンなしでサーバーが OAUTHBEARER のみ提供する場合は失敗する。
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_sasl(&["OAUTHBEARER"]))
        .unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NotSupportedError { .. })
    ));
}

#[test]
fn test_query_select() {
    let mut conn = connect_authenticated();

    // サーバー応答を先に供給しておく。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("?column?", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    let affected = conn.query("SELECT 1", false).unwrap();
    assert_eq!(affected, 1);

    let result = conn.result().unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0], Value::Int4(1));
    assert_eq!(result.tag.as_deref(), Some("SELECT 1"));
    assert!(result.is_done());
}

#[test]
fn test_query_with_null_and_empty() {
    let mut conn = connect_authenticated();

    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[
        ("a", oid::TEXT),
        ("b", oid::INT8),
        ("c", oid::BOOL),
    ]));
    server_data.extend_from_slice(&data_row(&[None, Some(b"42"), Some(b"t")]));
    server_data.extend_from_slice(&data_row(&[Some(b""), None, Some(b"f")]));
    server_data.extend_from_slice(&command_complete("SELECT 2"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    conn.query("SELECT a, b, c FROM t", false).unwrap();
    let result = conn.result().unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0][0], Value::Null);
    assert_eq!(result.rows[0][1], Value::Int8(42));
    assert_eq!(result.rows[0][2], Value::Bool(true));
    assert_eq!(result.rows[1][0], Value::Text(String::new()));
    assert_eq!(result.rows[1][1], Value::Null);
    assert_eq!(result.rows[1][2], Value::Bool(false));
}

#[test]
fn test_query_need_more_data_resume() {
    let mut conn = connect_authenticated();

    // サーバー応答がまだ届いていない状態では NeedMoreData。
    assert!(matches!(
        conn.query("SELECT 1", false),
        Err(Error::NeedMoreData)
    ));

    // 応答を供給してから再開する。クエリは送信済みなので再送しない。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("?column?", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    let affected = conn.read_query_result(false).unwrap();
    assert_eq!(affected, 1);
}

#[test]
fn test_query_insert() {
    let mut conn = connect_authenticated();

    let mut server_data = Vec::new();
    server_data.extend_from_slice(&command_complete("INSERT 0 5"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    let affected = conn.query("INSERT INTO t VALUES (1)", false).unwrap();
    assert_eq!(affected, 5);
    assert!(conn.result().unwrap().rows.is_empty());
}

#[test]
fn test_query_empty_query() {
    let mut conn = connect_authenticated();

    conn.feed_bytes(&build_empty_query_response()).unwrap();
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();

    let affected = conn.query("", false).unwrap();
    assert_eq!(affected, 0);
}

#[test]
fn test_query_server_error() {
    let mut conn = connect_authenticated();

    // エラー応答を先に供給する。
    conn.feed_bytes(&error_response("42P01", "relation \"foo\" does not exist"))
        .unwrap();
    // エラー後の ReadyForQuery も供給する。
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();

    assert!(matches!(
        conn.query("SELECT * FROM foo", false),
        Err(e) if e.code() == Some("42P01")
    ));

    // エラー後も次のクエリを実行できる (ReadyForQuery は読み飛ばされる)。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("?column?", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"2")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    let affected = conn.query("SELECT 2", false).unwrap();
    assert_eq!(affected, 1);
}

#[test]
fn test_query_resume_after_error_cleanup() {
    let mut conn = connect_authenticated();

    // エラー応答だけが届いた状態。
    conn.feed_bytes(&error_response("42P01", "relation \"foo\" does not exist"))
        .unwrap();
    assert!(matches!(
        conn.query("SELECT * FROM foo", false),
        Err(e) if e.code() == Some("42P01")
    ));

    // ReadyForQuery がまだ届いていない状態で次のクエリを実行すると
    // 読み残しの回収が NeedMoreData で中断する。クエリは送信されない。
    assert!(matches!(
        conn.query("SELECT 1", false),
        Err(Error::NeedMoreData)
    ));

    // ReadyForQuery が届いたら読み残しの回収を再開でき、クエリも実行できる。
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("?column?", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    let affected = conn.query("SELECT 1", false).unwrap();
    assert_eq!(affected, 1);
}

#[test]
fn test_execute_with_parameters() {
    let mut conn = connect_authenticated();

    // サーバー応答を先に供給しておく。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&parse_complete());
    server_data.extend_from_slice(&bind_complete());
    server_data.extend_from_slice(&parameter_description(&[oid::TEXT]));
    server_data.extend_from_slice(&row_description(&[("name", oid::TEXT)]));
    server_data.extend_from_slice(&data_row(&[Some(b"hello")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    let affected = conn
        .execute(
            "SELECT $1::text",
            &[Value::Text("hello".to_string())],
            false,
        )
        .unwrap();
    assert_eq!(affected, 1);
    assert_eq!(
        conn.result().unwrap().rows[0][0],
        Value::Text("hello".to_string())
    );

    // 送信メッセージの順序: Parse, Bind, Describe, Execute, Sync。
    let messages: Vec<(u8, Vec<u8>)> = (0..5)
        .map(|_| {
            let raw = conn.pop_send_queue().unwrap();
            let (message_type, payload) = parse_client_message(&raw);
            (message_type, payload.to_vec())
        })
        .collect();
    assert_eq!(messages[0].0, frontend::PARSE);
    assert_eq!(messages[1].0, frontend::BIND);
    assert_eq!(messages[2].0, frontend::DESCRIBE);
    assert_eq!(messages[3].0, frontend::EXECUTE);
    assert_eq!(messages[4].0, frontend::SYNC);
    // Parse メッセージにクエリが含まれる。
    assert!(messages[0].1.windows(16).any(|w| w == b"SELECT $1::text\0"));
    // Bind メッセージにパラメータが含まれる。
    assert!(messages[1].1.windows(5).any(|w| w == b"hello"));
}

#[test]
fn test_execute_with_null_parameter() {
    let mut conn = connect_authenticated();

    conn.feed_bytes(&command_complete("INSERT 0 1")).unwrap();
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .unwrap();

    let affected = conn
        .execute("INSERT INTO t VALUES ($1)", &[Value::Null], false)
        .unwrap();
    assert_eq!(affected, 1);

    // NULL パラメータは長さ -1 で送られる。
    let messages: Vec<u8> = (0..5)
        .flat_map(|_| {
            let raw = conn.pop_send_queue().unwrap();
            let (message_type, payload) = parse_client_message(&raw);
            let mut out = vec![message_type];
            out.extend_from_slice(payload);
            out
        })
        .collect();
    assert!(messages.windows(4).any(|w| w == [0xff, 0xff, 0xff, 0xff]));
}

#[test]
fn test_unbuffered_query() {
    let mut conn = connect_authenticated();

    // サーバー応答を先に供給しておく。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("num", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&data_row(&[Some(b"2")]));
    server_data.extend_from_slice(&command_complete("SELECT 2"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();

    // アンバッファードモードでは行記述までで返る。
    let affected = conn.query("SELECT 1 UNION SELECT 2", true).unwrap();
    assert_eq!(affected, 0);
    assert_eq!(conn.result().unwrap().rows.len(), 0);

    // 1 行ずつ読み込む。
    let packet = conn.read_packet().unwrap();
    let row = conn
        .result_mut()
        .unwrap()
        .read_rowdata_packet_unbuffered(packet)
        .unwrap()
        .unwrap();
    assert_eq!(row[0], Value::Int4(1));

    let packet = conn.read_packet().unwrap();
    let row = conn
        .result_mut()
        .unwrap()
        .read_rowdata_packet_unbuffered(packet)
        .unwrap()
        .unwrap();
    assert_eq!(row[0], Value::Int4(2));

    // コマンド完了で結果セットが終了する。
    let packet = conn.read_packet().unwrap();
    let row = conn
        .result_mut()
        .unwrap()
        .read_rowdata_packet_unbuffered(packet)
        .unwrap();
    assert!(row.is_none());

    let packet = conn.read_packet().unwrap();
    let row = conn
        .result_mut()
        .unwrap()
        .read_rowdata_packet_unbuffered(packet)
        .unwrap();
    assert!(row.is_none());
    assert!(conn.result().unwrap().is_done());
    assert_eq!(conn.result().unwrap().affected_rows, 2);
}

#[test]
fn test_unbuffered_finish_on_next_query() {
    let mut conn = connect_authenticated();

    // アンバッファードクエリを開始する。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("num", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();
    conn.query("SELECT 1", true).unwrap();

    // 読み残しを次のクエリで読み飛ばす。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data).unwrap();
    conn.query("SELECT 2", false).unwrap();
}

#[test]
fn test_tls_preferred_supported() {
    let mut conn = Connection::connect(ConnectOptions {
        ssl_mode: SslMode::Preferred,
        ..options()
    })
    .unwrap();
    let state = conn.request_authentication_start().unwrap();
    assert_eq!(state, AuthState::Send);

    // SSL 要求メッセージを検証する。
    let ssl_request = conn.pop_send_queue().unwrap();
    assert_eq!(ssl_request.len(), 8);
    let code = u32::from_be_bytes([
        ssl_request[4],
        ssl_request[5],
        ssl_request[6],
        ssl_request[7],
    ]);
    assert_eq!(code, 80_877_103);

    // サーバーが 'S' で応答する。
    conn.feed_bytes(b"S").unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );
    assert!(conn.needs_tls_upgrade());
    assert!(!conn.is_secure());

    // TLS アップグレード後にスタートアップメッセージを送信する。
    conn.set_secure(true);
    assert_eq!(
        conn.request_authentication_send_startup().unwrap(),
        AuthState::Send
    );
    assert!(!conn.needs_tls_upgrade());
    let startup = conn.pop_send_queue().unwrap();
    let version = u32::from_be_bytes([startup[4], startup[5], startup[6], startup[7]]);
    assert_eq!(version, 196_608);
}

#[test]
fn test_tls_preferred_not_supported() {
    let mut conn = Connection::connect(ConnectOptions {
        ssl_mode: SslMode::Preferred,
        ..options()
    })
    .unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // サーバーが 'N' で応答する。平文で続行する。
    conn.feed_bytes(b"N").unwrap();
    assert_eq!(
        conn.request_authentication_continue().unwrap(),
        AuthState::Send
    );
    assert!(!conn.needs_tls_upgrade());
    let startup = conn.pop_send_queue().unwrap();
    let version = u32::from_be_bytes([startup[4], startup[5], startup[6], startup[7]]);
    assert_eq!(version, 196_608);
}

#[test]
fn test_tls_required_not_supported() {
    let mut conn = Connection::connect(ConnectOptions {
        ssl_mode: SslMode::Required,
        ..options()
    })
    .unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // サーバーが 'N' で応答するとエラーになる。
    conn.feed_bytes(b"N").unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::OperationalError { .. })
    ));
}

#[test]
fn test_tls_invalid_response() {
    let mut conn = Connection::connect(ConnectOptions {
        ssl_mode: SslMode::Preferred,
        ..options()
    })
    .unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    // 'S' / 'N' 以外の応答はエラー。
    conn.feed_bytes(b"X").unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_authentication_error_response() {
    let mut conn = Connection::connect(options()).unwrap();
    conn.request_authentication_start().unwrap();
    conn.pop_send_queue();

    conn.feed_bytes(&error_response("28P01", "password authentication failed"))
        .unwrap();
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(e) if e.code() == Some("28P01")
    ));
}

#[test]
fn test_close() {
    let mut conn = connect_authenticated();
    conn.close().unwrap();
    assert!(!conn.is_open());
    let (message_type, _) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::TERMINATE);
    // 二重 close は無害。
    conn.close().unwrap();
    // クローズ後のクエリはエラー。
    assert!(matches!(
        conn.query("SELECT 1", false),
        Err(Error::InterfaceError { .. })
    ));
}

#[test]
fn test_force_close() {
    let mut conn = connect_authenticated();
    conn.query("SELECT 1", false).unwrap_err();
    conn.force_close();
    assert!(!conn.is_open());
    assert!(conn.pop_send_queue().is_none());
}

/// 空クエリ応答メッセージを組み立てる。
fn build_empty_query_response() -> Vec<u8> {
    build_message(b'I', &[])
}
