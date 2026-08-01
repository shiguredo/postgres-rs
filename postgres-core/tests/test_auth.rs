// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 認証処理の公開 API のテスト。
//!
//! RFC 7677 のテストベクタは実装内の単体テストで検証している。
//! ここでは ScramClient の公開 API の動作を検証する。

// このテストバイナリでは ScramServer だけを使うため、
// 他のヘルパーが未使用になることを想定する。
#[expect(dead_code)]
#[path = "helpers/helpers.rs"]
mod helpers;

use helpers::ScramServer;
use shiguredo_postgres_core::auth::ScramClient;
use shiguredo_postgres_core::error::Error;

#[test]
fn test_client_first_message_format() {
    let scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    let message = scram.client_first_message();
    // PostgreSQL はユーザー名をスタートアップメッセージで送るため、
    // SCRAM ではユーザー名を送らない (n=)。
    assert!(message.starts_with("n,,n=,r="));
    let nonce = message
        .strip_prefix("n,,n=,r=")
        .expect("クライアント最初のメッセージからの nonce の取り出しに成功しました");
    // nonce は 18 バイトの乱数を base64 エンコードした 24 文字。
    assert_eq!(nonce.len(), 24);
}

#[test]
fn test_scram_full_flow() {
    let mut scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    let client_first = scram.client_first_message();

    let server = ScramServer::new();
    let server_first = server.server_first(&client_first);

    let client_final = scram
        .handle_server_first(&server_first, b"password")
        .expect("サーバー最初のメッセージの処理に成功しました");
    // クライアント最終メッセージの形式を検証する。
    assert!(client_final.starts_with("c=biws,r="));
    let attributes: Vec<&str> = client_final.split(',').collect();
    assert_eq!(attributes.len(), 3);
    assert!(attributes[0].starts_with("c="));
    assert!(attributes[1].starts_with("r="));
    assert!(attributes[2].starts_with("p="));

    // サーバー最終メッセージの署名を検証する。
    let client_first_bare = client_first
        .strip_prefix("n,,")
        .expect("クライアント最初のメッセージからのプレフィックスの除去に成功しました");
    let server_final = server
        .server_final(&client_final, b"password", client_first_bare, &server_first)
        .expect("サーバー最終メッセージの生成に成功しました");
    scram
        .handle_server_final(&server_final)
        .expect("サーバー最終メッセージの検証に成功しました");
}

#[test]
fn test_scram_wrong_password_rejected() {
    let mut scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    let client_first = scram.client_first_message();

    let server = ScramServer::new();
    let server_first = server.server_first(&client_first);

    // 間違ったパスワードでクライアント最終メッセージを作る。
    let client_final = scram
        .handle_server_first(&server_first, b"wrong-password")
        .expect("サーバー最初のメッセージの処理に成功しました");
    let client_first_bare = client_first
        .strip_prefix("n,,")
        .expect("クライアント最初のメッセージからのプレフィックスの除去に成功しました");
    // サーバーは正しいパスワードで検証するため、クライアントの証明が一致しない。
    let server_final =
        server.server_final(&client_final, b"password", client_first_bare, &server_first);
    assert!(server_final.is_none());
}

#[test]
fn test_scram_server_signature_mismatch() {
    let mut scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    let client_first = scram.client_first_message();

    let server = ScramServer::new();
    let server_first = server.server_first(&client_first);
    let client_final = scram
        .handle_server_first(&server_first, b"password")
        .expect("サーバー最初のメッセージの処理に成功しました");
    let client_first_bare = client_first
        .strip_prefix("n,,")
        .expect("クライアント最初のメッセージからのプレフィックスの除去に成功しました");
    let server_final = server
        .server_final(&client_final, b"password", client_first_bare, &server_first)
        .expect("サーバー最終メッセージの生成に成功しました");

    // 署名を壊すと検証が失敗する。
    let tampered = format!("v=AAAA{}", &server_final[2..]);
    assert!(matches!(
        scram.handle_server_final(&tampered),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_scram_server_nonce_does_not_match() {
    let mut scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    // クライアント nonce と無関係な nonce をサーバーが返す。
    let server_first = "r=attacker-nonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    assert!(matches!(
        scram.handle_server_first(server_first, b"password"),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_scram_invalid_server_first() {
    let mut scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    // 属性が欠けている。
    assert!(scram.handle_server_first("r=abc123", b"password").is_err());
    // salt の base64 が不正。
    assert!(
        scram
            .handle_server_first("r=abc123,s=!!!,i=4096", b"password")
            .is_err()
    );
    // イテレーション数が大きすぎる。
    assert!(
        scram
            .handle_server_first(
                "r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=999999999",
                b"password"
            )
            .is_err()
    );
}

#[test]
fn test_scram_invalid_server_final() {
    let mut scram = ScramClient::new().expect("SCRAM クライアントの生成に成功しました");
    // server-first の前にはいかなる署名も検証してはいけない。
    assert!(matches!(
        scram.handle_server_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        Err(Error::InterfaceError { .. })
    ));

    let server_first = ScramServer::new().server_first(&scram.client_first_message());
    scram
        .handle_server_first(&server_first, b"password")
        .expect("サーバー最初のメッセージの処理に成功しました");
    // server-first の後も形式や署名長が不正な最終応答は拒否する。
    for final_message in ["e=invalid-proof", "v=!!!", "v=c2hvcnQ="] {
        assert!(matches!(
            scram.handle_server_final(final_message),
            Err(Error::InternalError { .. })
        ));
    }
}
