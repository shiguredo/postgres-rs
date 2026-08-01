// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 認証処理の公開 API のテスト。
//!
//! RFC 7677 のテストベクタは実装内の単体テストで検証している。
//! ここでは ScramClient の公開 API の動作を検証する。

mod helpers;

use helpers::ScramServer;
use shiguredo_postgres::auth::ScramClient;
use shiguredo_postgres::error::Error;

#[test]
fn test_client_first_message_format() {
    let scram = ScramClient::new().unwrap();
    let message = scram.client_first_message();
    // PostgreSQL はユーザー名をスタートアップメッセージで送るため、
    // SCRAM ではユーザー名を送らない (n=)。
    assert!(message.starts_with("n,,n=,r="));
    let nonce = message.strip_prefix("n,,n=,r=").unwrap();
    // nonce は 18 バイトの乱数を base64 エンコードした 24 文字。
    assert_eq!(nonce.len(), 24);
}

#[test]
fn test_scram_full_flow() {
    let mut scram = ScramClient::new().unwrap();
    let client_first = scram.client_first_message();

    let server = ScramServer::new();
    let server_first = server.server_first(&client_first);

    let client_final = scram
        .handle_server_first(&server_first, b"password")
        .unwrap();
    // クライアント最終メッセージの形式を検証する。
    assert!(client_final.starts_with("c=biws,r="));
    let attributes: Vec<&str> = client_final.split(',').collect();
    assert_eq!(attributes.len(), 3);
    assert!(attributes[0].starts_with("c="));
    assert!(attributes[1].starts_with("r="));
    assert!(attributes[2].starts_with("p="));

    // サーバー最終メッセージの署名を検証する。
    let client_first_bare = client_first.strip_prefix("n,,").unwrap();
    let server_final = server
        .server_final(&client_final, b"password", client_first_bare, &server_first)
        .unwrap();
    scram.handle_server_final(&server_final).unwrap();
}

#[test]
fn test_scram_wrong_password_rejected() {
    let mut scram = ScramClient::new().unwrap();
    let client_first = scram.client_first_message();

    let server = ScramServer::new();
    let server_first = server.server_first(&client_first);

    // 間違ったパスワードでクライアント最終メッセージを作る。
    let client_final = scram
        .handle_server_first(&server_first, b"wrong-password")
        .unwrap();
    let client_first_bare = client_first.strip_prefix("n,,").unwrap();
    // サーバーは正しいパスワードで検証するため、クライアントの証明が一致しない。
    let server_final =
        server.server_final(&client_final, b"password", client_first_bare, &server_first);
    assert!(server_final.is_none());
}

#[test]
fn test_scram_server_signature_mismatch() {
    let mut scram = ScramClient::new().unwrap();
    let client_first = scram.client_first_message();

    let server = ScramServer::new();
    let server_first = server.server_first(&client_first);
    let client_final = scram
        .handle_server_first(&server_first, b"password")
        .unwrap();
    let client_first_bare = client_first.strip_prefix("n,,").unwrap();
    let server_final = server
        .server_final(&client_final, b"password", client_first_bare, &server_first)
        .unwrap();

    // 署名を壊すと検証が失敗する。
    let tampered = format!("v=AAAA{}", &server_final[2..]);
    assert!(matches!(
        scram.handle_server_final(&tampered),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_scram_server_nonce_does_not_match() {
    let mut scram = ScramClient::new().unwrap();
    // クライアント nonce と無関係な nonce をサーバーが返す。
    let server_first = "r=attacker-nonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    assert!(matches!(
        scram.handle_server_first(server_first, b"password"),
        Err(Error::InternalError { .. })
    ));
}

#[test]
fn test_scram_invalid_server_first() {
    let mut scram = ScramClient::new().unwrap();
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
    let scram = ScramClient::new().unwrap();
    // v= 属性がない。
    assert!(scram.handle_server_final("e=invalid-proof").is_err());
    // base64 が不正。
    assert!(scram.handle_server_final("v=!!!").is_err());
    // 署名の長さが 32 バイトでない。
    assert!(scram.handle_server_final("v=c2hvcnQ=").is_err());
}

#[test]
fn test_md5_password_hash_format() {
    let hash = shiguredo_postgres::auth::md5_password_hash("postgres", b"password", &[1, 2, 3, 4]);
    // "md5" + 32 桁の 16 進数。
    assert_eq!(hash.len(), 35);
    assert!(hash.starts_with("md5"));
    assert!(hash[3..].chars().all(|c| c.is_ascii_hexdigit()));
    // 同一入力は同一ハッシュになる。
    let hash2 = shiguredo_postgres::auth::md5_password_hash("postgres", b"password", &[1, 2, 3, 4]);
    assert_eq!(hash, hash2);
    // ソルトが異なればハッシュも異なる。
    let hash3 = shiguredo_postgres::auth::md5_password_hash("postgres", b"password", &[5, 6, 7, 8]);
    assert_ne!(hash, hash3);
}
