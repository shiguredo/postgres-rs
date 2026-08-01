// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sans I/O な接続状態機械のテスト。
//!
//! サーバーが送信するはずのワイヤプロトコルのバイト列を
//! ヘルパーで組み立てて `feed_bytes` で供給し、
//! クライアントの状態遷移と送信メッセージを検証する。

#[path = "helpers/helpers.rs"]
mod helpers;
#[path = "test_connection/lifecycle.rs"]
mod lifecycle;

use helpers::{
    ScramServer, authentication_cleartext, authentication_md5, authentication_ok,
    authentication_sasl, authentication_sasl_continue, authentication_sasl_final, backend_key_data,
    bind_complete, build_message, command_complete, data_row, error_response, notice_response,
    parameter_description, parameter_status, parse_client_message, parse_complete, ready_for_query,
    row_description, row_description_with_format,
};
use shiguredo_postgres_core::connection::result::QueryResult;
use shiguredo_postgres_core::connection::{AuthState, ConnectOptions, Connection, SslMode};
use shiguredo_postgres_core::constants::{auth, backend, frontend, oid, transaction_status};
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres_core::error::Error;
use shiguredo_postgres_core::protocol::PostgresPacket;

fn options() -> ConnectOptions {
    ConnectOptions {
        host: "127.0.0.1".to_string(),
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
    let raw = conn
        .pop_send_queue()
        .expect("送信キューの取り出しに成功しました");
    let (message_type, payload) = parse_client_message(&raw);
    (message_type, payload.to_vec())
}

/// 認証済みの接続を作成する。
fn connect_authenticated() -> Connection {
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    assert_eq!(
        conn.request_authentication_start()
            .expect("認証開始に成功しました"),
        AuthState::Send
    );
    let startup = conn
        .pop_send_queue()
        .expect("送信キューの取り出しに成功しました");
    // スタートアップメッセージに user と database が含まれる。
    assert!(startup.windows(5).any(|w| w == b"user\0"));
    assert!(startup.windows(9).any(|w| w == b"database\0"));

    let mut server_data = Vec::new();
    server_data.extend_from_slice(&authentication_ok());
    server_data.extend_from_slice(&parameter_status("server_version", "17.0"));
    server_data.extend_from_slice(&parameter_status("client_encoding", "UTF8"));
    server_data.extend_from_slice(&backend_key_data(12345, 67890));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    while conn
        .request_authentication_continue()
        .expect("認証の継続に成功しました")
        != AuthState::Success
    {}
    assert!(conn.is_open());
    assert_eq!(conn.server_version(), Some("17.0"));
    assert_eq!(conn.backend_process_id(), 12345);
    assert_eq!(conn.backend_secret_key(), 67890);
    assert_eq!(conn.transaction_status(), transaction_status::IDLE);
    assert_eq!(conn.ready_sequence(), 1);
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

    // 予約済みの起動パラメーターは、サーバーへ接続する前に拒否する。
    let bad = ConnectOptions {
        runtime_params: vec![("DateStyle".to_string(), "German".to_string())],
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
    let mut conn = Connection::connect(options).expect("接続の作成に成功しました");
    assert!(matches!(
        conn.request_authentication_start(),
        Err(Error::InterfaceError { .. })
    ));
}

/// SSLRequest に対する応答と、I/O 層からの TLS 検証完了イベントを処理する。
fn start_verified_tls(mut options: ConnectOptions) -> Connection {
    options.ssl_mode = SslMode::VerifyFull;
    let mut conn = Connection::connect(options).expect("接続の作成に成功しました");
    assert_eq!(
        conn.request_authentication_start()
            .expect("認証を開始できませんでした"),
        AuthState::Send
    );
    conn.pop_send_queue().expect("SSLRequest がありません");
    conn.feed_bytes(b"S")
        .expect("TLS 応答を供給できませんでした");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("TLS 応答を処理できませんでした"),
        AuthState::Send
    );
    conn.set_secure(true);
    assert_eq!(
        conn.request_authentication_send_startup()
            .expect("StartupMessage を構築できませんでした"),
        AuthState::Send
    );
    conn.pop_send_queue().expect("StartupMessage がありません");
    conn
}

#[test]
fn test_authentication_rejects_md5() {
    // TLS の有無に関係なく、MD5 の応答は送信しない。
    for mut conn in [start_plain_authentication(), start_verified_tls(options())] {
        conn.feed_bytes(&authentication_md5(&[1, 2, 3, 4]))
            .expect("サーバー応答を供給できませんでした");
        assert!(matches!(
            conn.request_authentication_continue(),
            Err(e @ Error::NotSupportedError { .. }) if e.message().contains("MD5")
        ));
        assert!(
            conn.pop_send_queue().is_none(),
            "MD5 の応答を送信しようとしました"
        );
        assert!(!conn.is_open());
    }
}

#[test]
fn test_authentication_allows_cleartext_only_for_local_development() {
    // 外部ホストの平文接続を明示的に許可しても、そのサーバーへパスワードは送らない。
    let remote = start_plain_authentication_with(ConnectOptions {
        host: "container.example".to_string(),
        allow_insecure_remote: true,
        ..options()
    });
    for mut conn in [start_verified_tls(options()), remote] {
        conn.feed_bytes(&authentication_cleartext())
            .expect("平文パスワード要求を供給できませんでした");
        assert!(matches!(
            conn.request_authentication_continue(),
            Err(e @ Error::NotSupportedError { .. }) if e.message().contains("Cleartext")
        ));
        assert!(
            conn.pop_send_queue().is_none(),
            "パスワードを送信しようとしました"
        );
        assert!(!conn.is_open());
    }

    // 明示的な sslmode=disable によるループバックと Unix 接続は従来どおり認証できる。
    for host in ["127.0.0.1", "localhost", "::1", "/"] {
        let mut conn = start_plain_authentication_with(ConnectOptions {
            host: host.to_string(),
            ..options()
        });
        send_cleartext_password(&mut conn);
        conn.feed_bytes(&authentication_ok())
            .expect("認証成功を供給できませんでした");
        assert_eq!(
            conn.request_authentication_continue()
                .expect("認証成功を処理できませんでした"),
            AuthState::NeedRead
        );
        conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
            .expect("ReadyForQuery を供給できませんでした");
        assert_eq!(
            conn.request_authentication_continue()
                .expect("起動を完了できませんでした"),
            AuthState::Success
        );
    }
}

/// ローカル開発用の平文認証応答を処理し、パスワードメッセージを送信キューから取り出す。
fn send_cleartext_password(conn: &mut Connection) {
    conn.feed_bytes(&authentication_cleartext())
        .expect("平文パスワード要求を供給できませんでした");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("ローカルの平文認証が拒否されました"),
        AuthState::Send
    );
    let (message_type, payload) = pop_client_message(conn);
    assert_eq!(message_type, frontend::PASSWORD);
    assert_eq!(payload, b"password\0");
}

#[test]
fn test_authentication_validates_cleartext_phase_and_protects_password() {
    // AuthenticationCleartextPassword には方式コード以外のデータはない。
    let mut conn = start_plain_authentication();
    let mut malformed = auth::CLEARTEXT_PASSWORD.to_be_bytes().to_vec();
    malformed.push(0);
    assert_startup_rejected(
        &mut conn,
        &build_message(backend::AUTHENTICATION_REQUEST, &malformed),
    );

    // SCRAM 開始後に別方式へ変更する要求を拒否する。
    let (mut conn, _) = start_scram_authentication();
    assert_startup_rejected(&mut conn, &authentication_cleartext());

    // 認証中の重複要求で、二度目の送信を行ってはいけない。
    let mut conn = start_plain_authentication();
    send_cleartext_password(&mut conn);
    assert_startup_rejected(&mut conn, &authentication_cleartext());

    // サーバーがエラーに資格情報を含めてもその内容はエラーに残らない。
    let mut conn = start_plain_authentication();
    send_cleartext_password(&mut conn);
    conn.feed_bytes(&error_response("28P01", "password"))
        .expect("エラー応答を供給できませんでした");
    let error = conn
        .request_authentication_continue()
        .expect_err("エラー応答後に認証を続行しました");
    assert!(matches!(error, Error::OperationalError { .. }));
    assert!(!format!("{error:?}").contains("password"));
}

fn start_plain_authentication() -> Connection {
    start_plain_authentication_with(options())
}

fn start_plain_authentication_with(options: ConnectOptions) -> Connection {
    let mut conn = Connection::connect(options).expect("接続の作成に成功しました");
    assert_eq!(
        conn.request_authentication_start()
            .expect("認証を開始できませんでした"),
        AuthState::Send
    );
    conn.pop_send_queue().expect("StartupMessage がありません");
    conn
}

/// 不正な起動応答で接続が破棄され、同期境界や送信キューが変わらないことを確認する。
fn assert_startup_rejected(conn: &mut Connection, frame: &[u8]) {
    let before = conn.ready_sequence();
    conn.feed_bytes(frame)
        .expect("起動応答を供給できませんでした");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::InternalError { .. })
    ));
    assert_eq!(conn.ready_sequence(), before);
    assert!(!conn.is_open());
    assert!(conn.pop_send_queue().is_none());
}

#[test]
fn test_authentication_requires_valid_ok_and_ready() {
    let mut conn = start_plain_authentication();
    // ReadyForQuery は AuthenticationOk に代わる成功通知ではない。
    assert_startup_rejected(&mut conn, &ready_for_query(transaction_status::IDLE));

    let mut conn = start_plain_authentication();
    let mut malformed_ok = 0_u32.to_be_bytes().to_vec();
    malformed_ok.push(0);
    assert_startup_rejected(&mut conn, &build_message(b'R', &malformed_ok));

    for frame in [
        authentication_ok(),
        ready_for_query(transaction_status::IN_TRANSACTION),
        build_message(b'Z', b"II"),
    ] {
        let mut conn = start_plain_authentication();
        conn.feed_bytes(&authentication_ok())
            .expect("認証成功を供給できませんでした");
        assert_eq!(
            conn.request_authentication_continue()
                .expect("認証成功を処理できませんでした"),
            AuthState::NeedRead
        );
        // 起動途中の重複 AuthenticationOk と、idle でない/形式不正の Ready を拒否する。
        assert_startup_rejected(&mut conn, &frame);
    }
}

#[test]
fn test_authentication_rejects_parameter_status_breaking_decoding() {
    // 起動時に送った client_encoding=UTF8 と DateStyle=ISO を、サーバーが別の値で
    // 報告した場合は、行を正しく復号できないため認証を終えずに接続を閉じる。
    for (name, value) in [
        ("client_encoding", "SQL_ASCII"),
        ("DateStyle", "Postgres, MDY"),
    ] {
        let mut conn = start_plain_authentication();
        conn.feed_bytes(&authentication_ok())
            .expect("認証成功を供給できませんでした");
        assert_eq!(
            conn.request_authentication_continue()
                .expect("認証成功を処理できませんでした"),
            AuthState::NeedRead
        );
        conn.feed_bytes(&parameter_status(name, value))
            .expect("ParameterStatus を供給できませんでした");
        let error = conn
            .request_authentication_continue()
            .expect_err("復号の前提を崩す起動時の値を受理しました");
        assert!(
            matches!(error, Error::NotSupportedError(_)),
            "未サポートエラーではありません: {error:?}"
        );
        assert!(!conn.is_open());
    }

    // pgbouncer などの接続プーラーは、起動時に送った値を正規化せずにそのまま報告する。
    // PostgreSQL と同じ規則で解釈し、出力形式が ISO の `ISO` は受理する。
    let mut conn = start_plain_authentication();
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&authentication_ok());
    server_data.extend_from_slice(&parameter_status("client_encoding", "UTF8"));
    server_data.extend_from_slice(&parameter_status("DateStyle", "ISO"));
    server_data.extend_from_slice(&backend_key_data(12345, 67890));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");
    while conn
        .request_authentication_continue()
        .expect("接続プーラーが報告した起動時の値を拒否しました")
        != AuthState::Success
    {}
    assert!(conn.is_open());
}

/// 実際のクライアントの初期応答を使い、対応する SCRAM server-first を構築する。
fn start_scram_authentication() -> (Connection, String) {
    let mut conn = start_plain_authentication();
    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256"]))
        .expect("認証要求を供給できませんでした");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("SCRAM を開始できませんでした"),
        AuthState::Send
    );
    let (_, payload) = pop_client_message(&mut conn);
    let payload = payload
        .strip_prefix(b"SCRAM-SHA-256\0")
        .expect("SCRAM の初期応答ではありません");
    let client_first =
        std::str::from_utf8(&payload[4..]).expect("SCRAM の初期応答が UTF-8 ではありません");
    let server_first = ScramServer::new().server_first(client_first);
    (conn, server_first)
}

#[test]
fn test_authentication_enforces_scram_order() {
    for frame in [
        authentication_ok(),
        authentication_sasl(&["SCRAM-SHA-256"]),
        authentication_sasl_final(b""),
    ] {
        let (mut conn, _) = start_scram_authentication();
        assert_startup_rejected(&mut conn, &frame);
    }

    for continue_again in [false, true] {
        let (mut conn, server_first) = start_scram_authentication();
        let challenge = authentication_sasl_continue(server_first.as_bytes());
        conn.feed_bytes(&challenge)
            .expect("SCRAM の最初の応答を供給できませんでした");
        assert_eq!(
            conn.request_authentication_continue()
                .expect("SCRAM の最初の応答を処理できませんでした"),
            AuthState::Send
        );
        pop_client_message(&mut conn);
        // 証明待ちの状態では AuthenticationOk も、PBKDF2 の再実行要求も拒否する。
        let invalid = if continue_again {
            challenge
        } else {
            authentication_ok()
        };
        assert_startup_rejected(&mut conn, &invalid);
    }
}

#[test]
fn test_authentication_rejects_malformed_sasl_list() {
    for mechanisms in [b"SCRAM-SHA-256\0".as_slice(), b"OTHER\0\0SCRAM-SHA-256\0\0"] {
        let mut conn = start_plain_authentication();
        let mut payload = 10_u32.to_be_bytes().to_vec();
        payload.extend_from_slice(mechanisms);
        // リストの正しい終端を確認するまでは認証方式を選ばない。
        assert_startup_rejected(&mut conn, &build_message(b'R', &payload));
    }
}

#[test]
fn test_authentication_scram() {
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    // サーバーが SCRAM-SHA-256 を要求する。
    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256"]))
        .expect("サーバー応答の供給に成功しました");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::Send
    );

    // SASL 初期応答を検証する。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    let mechanism_end = payload
        .iter()
        .position(|&b| b == 0)
        .expect("NUL 終端が見つかりました");
    assert_eq!(&payload[..mechanism_end], b"SCRAM-SHA-256");
    let response_len = i32::from_be_bytes([
        payload[mechanism_end + 1],
        payload[mechanism_end + 2],
        payload[mechanism_end + 3],
        payload[mechanism_end + 4],
    ]) as usize;
    let client_first =
        std::str::from_utf8(&payload[mechanism_end + 5..mechanism_end + 5 + response_len])
            .expect("クライアント最初のメッセージを UTF-8 として解釈できました");
    assert!(client_first.starts_with("n,,n=,r="));

    // サーバー最初のメッセージを送る。
    let server = ScramServer::new();
    let server_first = server.server_first(client_first);
    conn.feed_bytes(&authentication_sasl_continue(server_first.as_bytes()))
        .expect("サーバー応答の供給に成功しました");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::Send
    );

    // SASL 応答 (クライアント最終メッセージ) を検証する。
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    // SASL 応答は長さフィールドなしのペイロードそのもの。
    let client_final = std::str::from_utf8(&payload)
        .expect("クライアント最終メッセージを UTF-8 として解釈できました");
    assert!(client_final.starts_with("c=biws,r="));
    assert!(client_final.contains(",p="));

    // サーバー最終メッセージを送る。
    let client_first_bare = client_first
        .strip_prefix("n,,")
        .expect("GS2 ヘッダーの除去に成功しました");
    let server_final = server
        .server_final(client_final, b"password", client_first_bare, &server_first)
        .expect("クライアント証明の検証に成功しました");
    conn.feed_bytes(&authentication_sasl_final(server_final.as_bytes()))
        .expect("サーバー応答の供給に成功しました");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::NeedRead
    );

    // AuthenticationOk と ReadyForQuery で認証完了。
    conn.feed_bytes(&authentication_ok())
        .expect("サーバー応答の供給に成功しました");
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("サーバー応答の供給に成功しました");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::Success
    );
}

#[test]
fn test_authentication_scram_wrong_password() {
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256"]))
        .expect("サーバー応答の供給に成功しました");
    conn.request_authentication_continue()
        .expect("認証の継続に成功しました");
    let (_, payload) = pop_client_message(&mut conn);
    let mechanism_end = payload
        .iter()
        .position(|&b| b == 0)
        .expect("NUL 終端が見つかりました");
    let response_len = i32::from_be_bytes([
        payload[mechanism_end + 1],
        payload[mechanism_end + 2],
        payload[mechanism_end + 3],
        payload[mechanism_end + 4],
    ]) as usize;
    let client_first =
        std::str::from_utf8(&payload[mechanism_end + 5..mechanism_end + 5 + response_len])
            .expect("クライアント最初のメッセージを UTF-8 として解釈できました");

    let server = ScramServer::new();
    let server_first = server.server_first(client_first);
    conn.feed_bytes(&authentication_sasl_continue(server_first.as_bytes()))
        .expect("サーバー応答の供給に成功しました");
    conn.request_authentication_continue()
        .expect("認証の継続に成功しました");
    let (_, payload) = pop_client_message(&mut conn);
    // SASL 応答は長さフィールドなしのペイロードそのもの。
    std::str::from_utf8(&payload).expect("クライアント最終メッセージを UTF-8 として解釈できました");

    // サーバーが認証失敗としてエラー応答を返す。
    conn.feed_bytes(&error_response(
        "28P01",
        "password authentication failed for user \"postgres\"",
    ))
    .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(e) if e.code() == Some("28P01")
    ));
}

#[test]
fn test_authentication_unsupported_method() {
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    // 未対応の認証方式 (GSSAPI = 7)。
    let mut payload = 7_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"test-data");
    conn.feed_bytes(&build_message(b'R', &payload))
        .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NotSupportedError { .. })
    ));
}

#[test]
fn test_authentication_sasl_unsupported_mechanism() {
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    // SCRAM-SHA-256 を含まないメカニズムリスト。
    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-1", "PLAIN"]))
        .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NotSupportedError { .. })
    ));
}

fn start_oauth_authentication() -> Connection {
    let mut conn = start_verified_tls(ConnectOptions {
        oauth_token: Some("token-placeholder".to_string()),
        ..options()
    });
    // 外部トークンが設定されている場合、検証済み TLS では OAUTHBEARER を選ぶ。
    conn.feed_bytes(&authentication_sasl(&["SCRAM-SHA-256", "OAUTHBEARER"]))
        .expect("サーバー応答の供給に成功しました");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("OAuth 認証を開始できませんでした"),
        AuthState::Send
    );
    conn
}

#[test]
fn test_authentication_oauth() {
    let mut conn = start_oauth_authentication();
    let (message_type, payload) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::PASSWORD);
    let initial = payload
        .strip_prefix(b"OAUTHBEARER\0")
        .expect("選ばれた認証方式が OAUTHBEARER ではありません");
    let (length, response) = initial.split_at(4);
    let len = u32::from_be_bytes(length.try_into().expect("長さが 4 バイトではありません"));
    assert_eq!(len as usize, response.len());
    // RFC 7628 の初期応答。libpq と同じく host / port は含めない。
    assert_eq!(response, b"n,,\x01auth=Bearer token-placeholder\x01\x01");

    // PostgreSQL の OAuth 成功時は SASLFinal がなく、直接 AuthenticationOk を受信する。
    conn.feed_bytes(&authentication_ok())
        .expect("認証成功を供給できませんでした");
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("ReadyForQuery を供給できませんでした");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証成功を処理できませんでした"),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue()
            .expect("起動を完了できませんでした"),
        AuthState::Success
    );
}

#[test]
fn test_authentication_oauth_requires_verified_tls() {
    // TLS が必須でも名前を検証しないモードでは OAuth トークンを設定できない。
    for (host, ssl_mode) in [
        ("127.0.0.1", SslMode::Disabled),
        ("/", SslMode::Disabled),
        ("127.0.0.1", SslMode::Required),
        ("127.0.0.1", SslMode::VerifyCa),
    ] {
        assert!(
            Connection::connect(ConnectOptions {
                host: host.to_string(),
                oauth_token: Some("token-placeholder".to_string()),
                ssl_mode,
                ..options()
            })
            .is_err()
        );
    }
}

#[test]
fn test_authentication_oauth_does_not_send_invalid_tokens() {
    // 空・空白を含む値・サーバーの受信上限を超える値は、TLS でも送信しない。
    let oversized = "a".repeat(65_535);
    for token in ["", "token placeholder", &oversized] {
        let mut conn = start_verified_tls(ConnectOptions {
            oauth_token: Some(token.to_string()),
            ..options()
        });
        conn.feed_bytes(&authentication_sasl(&["OAUTHBEARER"]))
            .expect("サーバー応答を供給できませんでした");
        assert!(matches!(
            conn.request_authentication_continue(),
            Err(Error::InterfaceError { .. })
        ));
        assert!(conn.pop_send_queue().is_none());
    }
}

#[test]
fn test_authentication_oauth_token_rejected() {
    let mut conn = start_oauth_authentication();
    pop_client_message(&mut conn);

    // RFC 7628 のエラー応答後は既存接続で資格情報を送らず、新しい接続を要求する。
    conn.feed_bytes(&authentication_sasl_continue(
        br#"{ "status": "invalid_token" }"#,
    ))
    .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::NeedOAuthToken)
    ));
    assert!(!conn.is_open());
    assert!(conn.pop_send_queue().is_none());
}

#[test]
fn test_authentication_oauth_rejects_sasl_final() {
    let mut conn = start_oauth_authentication();
    pop_client_message(&mut conn);

    // OAUTHBEARER の成功に SASLFinal は使わない。
    assert_startup_rejected(&mut conn, &authentication_sasl_final(b""));
}

#[test]
fn test_authentication_oauth_does_not_expose_server_error_fields() {
    for authenticated in [false, true] {
        let mut conn = start_oauth_authentication();
        pop_client_message(&mut conn);
        if authenticated {
            conn.feed_bytes(&authentication_ok())
                .expect("認証成功を供給できませんでした");
            assert_eq!(
                conn.request_authentication_continue()
                    .expect("認証成功を処理できませんでした"),
                AuthState::NeedRead
            );
        }
        // エラーに認証情報を反映するサーバーでも呼び出し側へ返すエラーは固定。
        conn.feed_bytes(&error_response("28P01", "token-placeholder"))
            .expect("サーバー応答を供給できませんでした");
        let error = conn
            .request_authentication_continue()
            .expect_err("エラー応答後に認証を続行しました");
        assert!(matches!(error, Error::OperationalError { .. }));
        assert!(!format!("{error:?}").contains("token-placeholder"));
    }
}

#[test]
fn test_authentication_notice_is_queued() {
    // 認証中に届いた NOTICE も利用者が確認できるようにキューへ積まれる。
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_ok())
        .expect("サーバー応答の供給に成功しました");
    conn.feed_bytes(&notice_response("01000", "startup notice"))
        .expect("サーバー応答の供給に成功しました");
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("サーバー応答の供給に成功しました");
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::NeedRead
    );
    assert_eq!(
        conn.request_authentication_continue()
            .expect("認証の継続に成功しました"),
        AuthState::Success
    );

    let notice = conn
        .pop_notice()
        .expect("認証中の NOTICE がキューに積まれていません");
    assert_eq!(notice.code, "01000", "SQLSTATE が一致しません");
    assert_eq!(
        notice.message, "startup notice",
        "NOTICE のメッセージが一致しません"
    );
}

#[test]
fn test_authentication_oauth_without_token() {
    // トークンなしでサーバーが OAUTHBEARER のみ提供する場合は失敗する。
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    conn.feed_bytes(&authentication_sasl(&["OAUTHBEARER"]))
        .expect("サーバー応答の供給に成功しました");
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
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .query("SELECT 1", false)
        .expect("クエリの実行に成功しました");
    assert_eq!(affected, 1);

    let result = conn.result().expect("クエリ結果の取得に成功しました");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0], Value::Int4(1));
    assert_eq!(result.tag.as_deref(), Some("SELECT 1"));
    assert!(result.is_done());
}

#[test]
fn test_query_rejects_binary_result_format() {
    // 拡張クエリの Bind で結果形式コードを 0 件 (すべてテキスト) で要求しているため、
    // サーバーがバイナリ形式を返した場合は復号せずに拒否する。
    let mut conn = connect_authenticated();

    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description_with_format(&[("?column?", oid::INT4)], 1));
    // バイナリの INT4 1 は NUL を 3 個含むが、UTF-8 としては不正ではない。
    server_data.extend_from_slice(&data_row(&[Some(&[0, 0, 0, 1])]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let error = conn
        .query("SELECT 1", false)
        .expect_err("バイナリ形式の結果は拒否されます");
    assert!(
        matches!(error, Error::InternalError(_)),
        "内部エラーではありません: {error:?}"
    );
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
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    conn.query("SELECT a, b, c FROM t", false)
        .expect("クエリの実行に成功しました");
    let result = conn.result().expect("クエリ結果の取得に成功しました");
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0][0], Value::Null);
    assert_eq!(result.rows[0][1], Value::Int8(42));
    assert_eq!(result.rows[0][2], Value::Bool(true));
    assert_eq!(result.rows[1][0], Value::Text(String::new()));
    assert_eq!(result.rows[1][1], Value::Null);
    assert_eq!(result.rows[1][2], Value::Bool(false));
}

#[test]
fn test_query_rejects_data_row_with_wrong_field_count() {
    // libpq の getAnotherTuple は、行の列数が RowDescription のフィールド数と
    // 一致しないメッセージを "unexpected field count in D message" として拒否する。
    // 列数が少ないまま受理すると、列名から引く値の位置がずれてパニックしうる。
    // 列数が多いまま受理すると、宣言されたフィールドに対応しない値が混ざる。
    let cases: [&[Option<&[u8]>]; 2] = [&[Some(b"1")], &[Some(b"1"), Some(b"2"), Some(b"3")]];
    for values in cases {
        let mut conn = connect_authenticated();

        let mut server_data = Vec::new();
        server_data.extend_from_slice(&row_description(&[("a", oid::INT4), ("b", oid::INT4)]));
        server_data.extend_from_slice(&data_row(values));
        server_data.extend_from_slice(&command_complete("SELECT 1"));
        server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
        conn.feed_bytes(&server_data)
            .expect("サーバー応答の供給に成功しました");

        let error = conn
            .query("SELECT a, b FROM t", false)
            .expect_err("列数の異なる行を受理しました");
        assert!(
            matches!(error, Error::InternalError(_)),
            "列数の不一致がプロトコルエラーになりません: {error}"
        );
    }
}

#[test]
fn test_query_after_force_close_reports_closed_connection() {
    // 読み込み途中の結果を持ったまま接続を閉じても、次の操作は閉じていることを返す。
    // 途中の結果を回収しようとして NeedMoreData を返すと、Sans I/O の呼び出し側は
    // 受け付けられないデータを待ち続けてしまう。
    let mut conn = connect_authenticated();

    // 行記述と行だけを届け、結果を読み込み途中にする。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("a", oid::TEXT)]));
    server_data.extend_from_slice(&data_row(&[Some(b"x")]));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.query("SELECT a FROM t", false),
        Err(Error::NeedMoreData)
    ));

    // 長さが 4 未満のフレームは同期を失ったものとして接続を閉じる。
    assert!(
        conn.feed_bytes(&[backend::DATA_ROW, 0, 0, 0, 3]).is_err(),
        "不正な長さのフレームを受理しました"
    );
    assert!(!conn.is_open());
    // 途中まで読んだ行は残さない。
    assert!(conn.result().is_none());
    for error in [
        conn.query("SELECT 1", false)
            .expect_err("閉じた接続でクエリを実行できました"),
        conn.read_packet()
            .expect_err("閉じた接続から受信メッセージを読めました"),
    ] {
        assert!(
            matches!(&error, Error::InterfaceError { message } if message == "Connection is closed"),
            "閉じた接続のエラーではありません: {error:?}"
        );
    }
}

#[test]
fn test_query_rejects_parameter_status_breaking_decoding() {
    // 行は UTF-8、日付・時刻は ISO 形式として復号する。PostgreSQL は SET による変更を
    // ReadyForQuery の直前の ParameterStatus で通知するため、同じ応答サイクルの行も
    // すでに変更後の設定で届いている。前提を崩す通知を受けたら、サイクルを失敗にして閉じる。
    // GUC 名は大文字と小文字を区別しない。
    for (name, value) in [
        ("client_encoding", "LATIN1"),
        ("DateStyle", "German, DMY"),
        ("datestyle", "SQL, MDY"),
    ] {
        let mut conn = connect_authenticated();

        let mut server_data = Vec::new();
        server_data.extend_from_slice(&command_complete("SET"));
        server_data.extend_from_slice(&row_description(&[("a", oid::TEXT)]));
        // LATIN1 の "Ã©" は UTF-8 の "é" と同じバイト列で、UTF-8 としても妥当になる。
        server_data.extend_from_slice(&data_row(&[Some("é".as_bytes())]));
        server_data.extend_from_slice(&command_complete("SELECT 1"));
        server_data.extend_from_slice(&parameter_status(name, value));
        server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
        conn.feed_bytes(&server_data)
            .expect("サーバー応答の供給に成功しました");

        let error = conn
            .query("SET ...; SELECT a FROM t", false)
            .expect_err("復号の前提を崩す変更を受理しました");
        assert!(
            matches!(error, Error::NotSupportedError(_)),
            "未サポートエラーではありません: {error:?}"
        );
        assert!(!conn.is_open());
        // 誤った前提で復号した行は残さない。
        assert!(conn.result().is_none());
    }

    // ISO のままの日付順序の変更と、PostgreSQL が正規化しない UNICODE (UTF8 の別名) は受理する。
    for (name, value) in [("DateStyle", "ISO, DMY"), ("client_encoding", "UNICODE")] {
        let mut conn = connect_authenticated();

        let mut server_data = Vec::new();
        server_data.extend_from_slice(&command_complete("SET"));
        server_data.extend_from_slice(&parameter_status(name, value));
        server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
        conn.feed_bytes(&server_data)
            .expect("サーバー応答の供給に成功しました");

        conn.query("SET ...", false)
            .expect("復号の前提を保つ変更を拒否しました");
        assert!(conn.is_open());
        assert_eq!(
            conn.server_parameters().get(name).map(String::as_str),
            Some(value)
        );
    }

    // 接続を経由せず結果に直接供給した場合も拒否する。
    let packet = PostgresPacket {
        message_type: backend::PARAMETER_STATUS,
        data: b"client_encoding\0LATIN1\0".to_vec(),
    };
    assert!(
        QueryResult::new().feed_packet(packet).is_err(),
        "結果に直接供給した前提を崩す通知を受理しました"
    );
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
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .read_query_result(false)
        .expect("クエリ結果の読み取りに成功しました");
    assert_eq!(affected, 1);
}

#[test]
fn test_query_insert() {
    let mut conn = connect_authenticated();

    let mut server_data = Vec::new();
    server_data.extend_from_slice(&command_complete("INSERT 0 5"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .query("INSERT INTO t VALUES (1)", false)
        .expect("クエリの実行に成功しました");
    assert_eq!(affected, 5);
    assert!(
        conn.result()
            .expect("クエリ結果の取得に成功しました")
            .rows
            .is_empty()
    );
}

#[test]
fn test_query_empty_query() {
    let mut conn = connect_authenticated();

    conn.feed_bytes(&build_empty_query_response())
        .expect("サーバー応答の供給に成功しました");
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("サーバー応答の供給に成功しました");

    let affected = conn.query("", false).expect("クエリの実行に成功しました");
    assert_eq!(affected, 0);
}

#[test]
fn test_query_server_error() {
    let mut conn = connect_authenticated();

    // エラー応答を先に供給する。
    conn.feed_bytes(&error_response("42P01", "relation \"foo\" does not exist"))
        .expect("サーバー応答の供給に成功しました");
    // エラー後の ReadyForQuery も供給する。
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("サーバー応答の供給に成功しました");

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
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .query("SELECT 2", false)
        .expect("クエリの実行に成功しました");
    assert_eq!(affected, 1);
}

#[test]
fn test_query_resume_after_error_cleanup() {
    let mut conn = connect_authenticated();

    // エラー応答だけが届いた状態。
    conn.feed_bytes(&error_response("42P01", "relation \"foo\" does not exist"))
        .expect("サーバー応答の供給に成功しました");
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
        .expect("サーバー応答の供給に成功しました");
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("?column?", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&ready_for_query(transaction_status::IDLE));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .query("SELECT 1", false)
        .expect("クエリの実行に成功しました");
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
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .execute(
            "SELECT $1::text",
            &[Value::Text("hello".to_string())],
            false,
        )
        .expect("パラメータ付きクエリの実行に成功しました");
    assert_eq!(affected, 1);
    assert_eq!(
        conn.result().expect("クエリ結果の取得に成功しました").rows[0][0],
        Value::Text("hello".to_string())
    );

    // 送信メッセージの順序: Parse, Bind, Describe, Execute, Sync。
    let messages: Vec<(u8, Vec<u8>)> = (0..5)
        .map(|_| {
            let raw = conn
                .pop_send_queue()
                .expect("送信キューの取り出しに成功しました");
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

    conn.feed_bytes(&command_complete("INSERT 0 1"))
        .expect("サーバー応答の供給に成功しました");
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("サーバー応答の供給に成功しました");

    let affected = conn
        .execute("INSERT INTO t VALUES ($1)", &[Value::Null], false)
        .expect("パラメータ付きクエリの実行に成功しました");
    assert_eq!(affected, 1);

    // NULL パラメータは長さ -1 で送られる。
    let messages: Vec<u8> = (0..5)
        .flat_map(|_| {
            let raw = conn
                .pop_send_queue()
                .expect("送信キューの取り出しに成功しました");
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
    conn.feed_bytes(&server_data)
        .expect("サーバー応答の供給に成功しました");

    // アンバッファードモードでは行記述までで返る。
    let affected = conn
        .query("SELECT 1 UNION SELECT 2", true)
        .expect("クエリの実行に成功しました");
    assert_eq!(affected, 0);
    assert_eq!(
        conn.result()
            .expect("クエリ結果の取得に成功しました")
            .rows
            .len(),
        0
    );

    // 1 行ずつ読み込む。
    let packet = conn
        .read_packet()
        .expect("パケットの読み取りに成功しました");
    let row = conn
        .result_mut()
        .expect("クエリ結果の取得に成功しました")
        .read_rowdata_packet_unbuffered(packet)
        .expect("行データの読み取りに成功しました")
        .expect("行データが返りました");
    assert_eq!(row[0], Value::Int4(1));

    let packet = conn
        .read_packet()
        .expect("パケットの読み取りに成功しました");
    let row = conn
        .result_mut()
        .expect("クエリ結果の取得に成功しました")
        .read_rowdata_packet_unbuffered(packet)
        .expect("行データの読み取りに成功しました")
        .expect("行データが返りました");
    assert_eq!(row[0], Value::Int4(2));

    // コマンド完了で結果セットが終了する。
    let packet = conn
        .read_packet()
        .expect("パケットの読み取りに成功しました");
    let row = conn
        .result_mut()
        .expect("クエリ結果の取得に成功しました")
        .read_rowdata_packet_unbuffered(packet)
        .expect("行データの読み取りに成功しました");
    assert!(row.is_none());

    let packet = conn
        .read_packet()
        .expect("パケットの読み取りに成功しました");
    let row = conn
        .result_mut()
        .expect("クエリ結果の取得に成功しました")
        .read_rowdata_packet_unbuffered(packet)
        .expect("行データの読み取りに成功しました");
    assert!(row.is_none());
    assert!(
        conn.result()
            .expect("クエリ結果の取得に成功しました")
            .is_done()
    );
    assert_eq!(
        conn.result()
            .expect("クエリ結果の取得に成功しました")
            .affected_rows,
        2
    );
}

#[test]
fn test_unbuffered_finish_on_next_query() {
    let mut conn = connect_authenticated();

    // アンバッファードクエリを開始する。
    let mut server_data = Vec::new();
    server_data.extend_from_slice(&row_description(&[("num", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"1")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    server_data.extend_from_slice(&row_description(&[("num", oid::INT4)]));
    server_data.extend_from_slice(&data_row(&[Some(b"2")]));
    server_data.extend_from_slice(&command_complete("SELECT 1"));
    conn.feed_bytes(&server_data)
        .expect("サーバー応答を供給できる");
    conn.query("SELECT 1; SELECT 2", true)
        .expect("アンバッファードクエリを開始できる");
    assert_eq!(pop_client_message(&mut conn).0, frontend::QUERY);
    let ready_before = conn.ready_sequence();

    // 複文の読み残しを捨てても、最後の ReadyForQuery を受信するまでは送信しない。
    assert!(matches!(
        conn.send_query("SELECT 3"),
        Err(Error::NeedMoreData)
    ));
    assert_eq!(conn.ready_sequence(), ready_before);
    assert!(conn.pop_send_queue().is_none());
    assert!(conn.is_busy());
    assert!(
        !conn
            .result()
            .expect("前の結果が残っている")
            .has_next_rowset()
    );

    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("前のクエリの同期応答を供給できる");
    conn.send_query("SELECT 3").expect("次のクエリを送信できる");
    assert_eq!(pop_client_message(&mut conn).0, frontend::QUERY);
    assert_eq!(conn.ready_sequence(), ready_before + 1);
}

#[test]
fn test_tls_modes_require_handshake_before_startup() {
    for ssl_mode in [SslMode::VerifyFull, SslMode::Required, SslMode::VerifyCa] {
        let mut conn = Connection::connect(ConnectOptions {
            ssl_mode,
            ..options()
        })
        .expect("接続の作成に成功しました");
        let state = conn
            .request_authentication_start()
            .expect("認証開始に成功しました");
        assert_eq!(state, AuthState::Send);

        // SSL 要求メッセージを検証する。
        let ssl_request = conn
            .pop_send_queue()
            .expect("送信キューの取り出しに成功しました");
        assert_eq!(ssl_request.len(), 8);
        let code = u32::from_be_bytes([
            ssl_request[4],
            ssl_request[5],
            ssl_request[6],
            ssl_request[7],
        ]);
        assert_eq!(code, 80_877_103);

        // 読み込み不足で再開しても、TLS 応答を PostgreSQL メッセージと誤解釈しない。
        assert!(matches!(
            conn.request_authentication_continue(),
            Err(Error::NeedMoreData)
        ));
        // サーバーが 'S' で応答する。
        conn.feed_bytes(b"S")
            .expect("サーバー応答の供給に成功しました");
        assert_eq!(
            conn.request_authentication_continue()
                .expect("認証の継続に成功しました"),
            AuthState::Send
        );
        assert!(conn.needs_tls_upgrade());
        assert!(!conn.is_secure());

        // 'S' だけでは TLS は成立していないため、StartupMessage を許可しない。
        assert!(matches!(
            conn.request_authentication_send_startup(),
            Err(Error::InterfaceError { .. })
        ));
        assert!(conn.pop_send_queue().is_none());
        // I/O 層が TLS 検証完了を通知した場合だけ StartupMessage を送信する。
        conn.set_secure(true);
        assert_eq!(
            conn.request_authentication_send_startup()
                .expect("スタートアップメッセージの送信に成功しました"),
            AuthState::Send
        );
        assert!(!conn.needs_tls_upgrade());
        let startup = conn
            .pop_send_queue()
            .expect("送信キューの取り出しに成功しました");
        let version = u32::from_be_bytes([startup[4], startup[5], startup[6], startup[7]]);
        assert_eq!(version, 196_608);
    }
}

#[test]
fn test_tls_modes_reject_plaintext_fallback() {
    for ssl_mode in [SslMode::VerifyFull, SslMode::Required, SslMode::VerifyCa] {
        let mut conn = Connection::connect(ConnectOptions {
            ssl_mode,
            ..options()
        })
        .expect("接続の作成に成功しました");
        conn.request_authentication_start()
            .expect("認証開始に成功しました");
        conn.pop_send_queue();

        // サーバーが 'N' で応答するとエラーになる。
        conn.feed_bytes(b"N")
            .expect("サーバー応答の供給に成功しました");
        assert!(matches!(
            conn.request_authentication_continue(),
            Err(Error::OperationalError { .. })
        ));
        assert!(
            conn.pop_send_queue().is_none(),
            "平文の起動メッセージを送信しようとしました"
        );
        assert!(!conn.is_open());
    }
}

#[test]
fn test_tls_invalid_response() {
    let mut conn = Connection::connect(ConnectOptions {
        ssl_mode: SslMode::VerifyFull,
        ..options()
    })
    .expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    // 'S' / 'N' 以外の応答はエラー。
    conn.feed_bytes(b"X")
        .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_authentication_error_response() {
    let mut conn = Connection::connect(options()).expect("接続の作成に成功しました");
    conn.request_authentication_start()
        .expect("認証開始に成功しました");
    conn.pop_send_queue();

    conn.feed_bytes(&error_response("28P01", "password authentication failed"))
        .expect("サーバー応答の供給に成功しました");
    assert!(matches!(
        conn.request_authentication_continue(),
        Err(e) if e.code() == Some("28P01")
    ));
}

#[test]
fn test_close() {
    let mut conn = connect_authenticated();
    conn.close().expect("接続のクローズに成功しました");
    assert!(!conn.is_open());
    let (message_type, _) = pop_client_message(&mut conn);
    assert_eq!(message_type, frontend::TERMINATE);
    // 二重 close は無害。
    conn.close().expect("接続のクローズに成功しました");
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
