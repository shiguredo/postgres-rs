// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! auth モジュールの Property-Based Testing。
//!
//! SCRAM ハンドシェイク全体がランダムなパスワード・ソルト・
//! イテレーション数に対して成功することと、
//! 改ざんされたサーバー最終メッセージが検証に失敗することを検証する。
//! サーバー側の計算は RFC 5802 のアルゴリズムをそのまま実装する。

use aws_lc_rs::{hmac, pbkdf2};
use base64ct::{Base64, Encoding};
use proptest::prelude::*;
use shiguredo_postgres_core::auth::{ScramClient, md5_password_hash};
use std::num::NonZeroU32;

/// サーバー側の SCRAM 署名を計算してサーバー最終メッセージを組み立てる。
///
/// RFC 5802 のサーバー側処理をそのまま実装する。
/// `handle_server_final` の成功パスを検証するために使う。
fn compute_server_final(
    client_final: &str,
    client_nonce: &str,
    salt: &[u8],
    iterations: u32,
    password: &[u8],
    server_first: &str,
) -> String {
    // `c=biws,r=<nonce>,p=<proof>` からクライアント最終メッセージの nonce を抽出する。
    let nonce = client_final
        .split(',')
        .find_map(|attr| attr.strip_prefix("r="))
        .expect("クライアント最終メッセージに nonce が含まれています");

    // PostgreSQL は SCRAM でユーザー名を送らないため、
    // クライアント最初のメッセージは `n=,r=<nonce>` の形式になる。
    let client_first_bare = format!("n=,r={}", client_nonce);
    let client_final_without_proof = format!("c=biws,r={}", nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );

    let salted_password = derive_salted_password(password, salt, iterations);
    let server_key = hmac_sha256(&salted_password, b"Server Key");
    let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
    format!("v={}", Base64::encode_string(&server_signature))
}

/// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations, 32) を計算する。
fn derive_salted_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let iterations = NonZeroU32::new(iterations).expect("イテレーション数は 1 以上です");
    let mut salted_password = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut salted_password,
    );
    salted_password
}

/// HMAC-SHA-256 を計算する。
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

proptest! {
    /// MD5 パスワードハッシュは PostgreSQL の形式 (md5 + 32 桁 16 進) を満たし、
    /// 同じ入力に対して決定的に動作する。
    #[test]
    fn prop_md5_password_hash(
        user in "\\PC{0,64}",
        password in proptest::collection::vec(any::<u8>(), 0..=64),
        salt in proptest::collection::vec(any::<u8>(), 4),
    ) {
        let hash = md5_password_hash(&user, &password, &salt);
        prop_assert!(hash.starts_with("md5"));
        prop_assert_eq!(hash.len(), 35);
        // 同じ入力に対しては同じハッシュを返す。
        let again = md5_password_hash(&user, &password, &salt);
        prop_assert_eq!(hash.clone(), again);
        // ソルトが異なればハッシュも異なる。
        let mut other_salt = salt.clone();
        other_salt[0] ^= 0xff;
        let other = md5_password_hash(&user, &password, &other_salt);
        prop_assert_ne!(hash, other);
    }

    /// SCRAM ハンドシェイクはランダムなパスワード・ソルト・イテレーション数で
    /// 成功し、改ざんされたサーバー最終メッセージは検証に失敗する。
    #[test]
    fn prop_scram_handshake(
        password in proptest::collection::vec(any::<u8>(), 0..=64),
        server_extra in "[A-Za-z0-9]{1,16}",
        salt in proptest::collection::vec(any::<u8>(), 1..=32),
        iterations in 1u32..=100,
    ) {
        let mut client = ScramClient::new().expect("nonce の生成に成功しました");
        let client_first = client.client_first_message();
        let client_nonce = client_first
            .strip_prefix("n,,n=,r=")
            .expect("クライアント最初のメッセージの形式が想定と異なります");

        // サーバー最初のメッセージはクライアント nonce を先頭に含む必要がある。
        let server_first = format!(
            "r={}{},s={},i={}",
            client_nonce,
            server_extra,
            Base64::encode_string(&salt),
            iterations
        );
        let client_final = client
            .handle_server_first(&server_first, &password)
            .expect("サーバー最初のメッセージの処理に成功しました");
        prop_assert!(
            client_final.starts_with("c=biws,r="),
            "クライアント最終メッセージの形式が不正です: {}",
            client_final
        );
        prop_assert!(
            client_final.contains(",p="),
            "クライアント最終メッセージに proof が含まれていません: {}",
            client_final
        );

        // 正しいサーバー最終メッセージは検証に成功する。
        let server_final = compute_server_final(
            &client_final,
            client_nonce,
            &salt,
            iterations,
            &password,
            &server_first,
        );
        prop_assert!(
            client.handle_server_final(&server_final).is_ok(),
            "正しいサーバー最終メッセージの検証に失敗しました"
        );

        // 別のパスワードから計算したサーバー最終メッセージは検証に失敗する。
        let mut wrong_password = password.clone();
        if wrong_password.is_empty() {
            wrong_password.push(0x01);
        } else {
            wrong_password[0] ^= 0xff;
        }
        let wrong_final = compute_server_final(
            &client_final,
            client_nonce,
            &salt,
            iterations,
            &wrong_password,
            &server_first,
        );
        if server_final != wrong_final {
            prop_assert!(
                client.handle_server_final(&wrong_final).is_err(),
                "改ざんされたサーバー最終メッセージの検証に失敗しませんでした"
            );
        }
    }

    /// サーバー最初のメッセージの nonce がクライアント nonce で始まらない場合は
    /// エラーになる。
    #[test]
    fn prop_scram_nonce_mismatch(_dummy in any::<u8>()) {
        let mut client = ScramClient::new().expect("nonce の生成に成功しました");
        let client_first = client.client_first_message();
        let client_nonce = client_first
            .strip_prefix("n,,n=,r=")
            .expect("クライアント最初のメッセージの形式が想定と異なります");

        // 先頭文字を必ず変えた nonce はクライアント nonce で始まらない。
        let mut bytes = client_nonce.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let mismatched_nonce = String::from_utf8(bytes).expect("base64 は ASCII です");
        let server_first = format!("r={},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10", mismatched_nonce);
        prop_assert!(
            client.handle_server_first(&server_first, b"password").is_err(),
            "nonce が一致しないサーバー最初のメッセージが受け入れられました"
        );
    }
}
