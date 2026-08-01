// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 認証で使用する暗号処理。
//!
//! 仕様は RFC 5802 (SCRAM) / RFC 7677 (SCRAM-SHA-256) と、
//! PostgreSQL の SASL 認証実装に基づく。
//! PostgreSQL の SCRAM 実装はクライアントがユーザー名を送らない
//! (スタートアップメッセージで送信済みのため) ため、
//! クライアント最初のメッセージは `n,,n=,r=<nonce>` の形式となる。
//!
//! PostgreSQL の実装は以下のファイルを参照:
//! - `src/interfaces/libpq/fe-auth-scram.c`
//! - `src/backend/libpq/auth-scram.c`

use crate::error::{Error, Result};
use aws_lc_rs::constant_time;
use aws_lc_rs::digest;
use aws_lc_rs::hmac;
use aws_lc_rs::pbkdf2;
use aws_lc_rs::rand;
use base64ct::{Base64, Encoding};
use std::num::NonZeroU32;

/// 認証 1 回で同期的に実行する PBKDF2 の反復上限。
///
/// PostgreSQL 18 の libpq は正値を要求するが、計算量を制限する上限はない。
/// 既定値の 4,096 より十分に高い上限を設け、サーバー指定の計算量を制限する。
/// この上限を超えるベリファイアを設定したサーバーとは認証できない。
const MAX_SCRAM_ITERATIONS: u32 = 600_000;

/// SCRAM のクライアントキー・サーバーキーの HMAC ラベル。
const SCRAM_CLIENT_KEY_LABEL: &[u8] = b"Client Key";
const SCRAM_SERVER_KEY_LABEL: &[u8] = b"Server Key";

/// SCRAM-SHA-256 クライアントの状態。
#[derive(Clone)]
pub struct ScramClient {
    client_nonce: String,
    client_first_bare: String,
    server_signature: Option<[u8; 32]>,
}

impl std::fmt::Debug for ScramClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // パスワード由来のサーバー署名を Debug 出力に含めない。
        formatter
            .debug_struct("ScramClient")
            .finish_non_exhaustive()
    }
}

impl ScramClient {
    /// クライアント nonce を生成して新しい SCRAM クライアントを作成する。
    ///
    /// nonce は PostgreSQL の libpq と同じく 18 バイトの乱数を
    /// base64 エンコードしたものを使う。
    pub fn new() -> Result<Self> {
        let mut raw_nonce = [0u8; 18];
        rand::fill(&mut raw_nonce)
            .map_err(|_| Error::internal("Failed to generate SCRAM client nonce".to_string()))?;
        let client_nonce = Base64::encode_string(&raw_nonce);
        let client_first_bare = format!("n=,r={}", client_nonce);
        Ok(Self {
            client_nonce,
            client_first_bare,
            server_signature: None,
        })
    }

    /// クライアント最初のメッセージを返す。
    ///
    /// SASL 初期応答として送信する。
    pub fn client_first_message(&self) -> String {
        format!("n,,{}", self.client_first_bare)
    }

    /// サーバー最初のメッセージを処理して、クライアント最終メッセージを返す。
    ///
    /// サーバー最初のメッセージは
    /// `r=<nonce>,s=<base64 salt>,i=<iterations>` の形式。
    /// クライアント最終メッセージは SASL 応答として送信する。
    /// 反復数が 600,000 を超える場合や、既にクライアント最終メッセージを生成した場合は
    /// エラーを返す。
    pub fn handle_server_first(&mut self, server_first: &str, password: &[u8]) -> Result<String> {
        if self.server_signature.is_some() {
            return Err(Error::interface(
                "SCRAM server-first message was already processed",
            ));
        }
        let (nonce, salt, iterations) = parse_server_first(server_first)?;

        // RFC 5802 §5.1 ではクライアントの nonce にサーバー自身の nonce を追加する。
        // SCRAM の仕様が将来変更されたときはこの比較も見直す。
        if nonce.len() <= self.client_nonce.len() || !nonce.starts_with(&self.client_nonce) {
            return Err(Error::internal(
                "SCRAM server nonce must extend the client nonce",
            ));
        }

        let prepared_password = prepare_password(password);
        let salted_password = derive_salted_password(&prepared_password, &salt, iterations);

        let client_key = hmac_sha256(&salted_password, SCRAM_CLIENT_KEY_LABEL);
        let stored_key = sha256(&client_key);

        let client_final_without_proof = format!("c=biws,r={}", nonce);
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );

        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let client_proof = xor(&client_key, &client_signature);

        let server_key = hmac_sha256(&salted_password, SCRAM_SERVER_KEY_LABEL);
        self.server_signature = Some(hmac_sha256(&server_key, auth_message.as_bytes()));

        Ok(format!(
            "{},p={}",
            client_final_without_proof,
            Base64::encode_string(&client_proof)
        ))
    }

    /// サーバー最終メッセージの署名を検証する。
    ///
    /// サーバー最終メッセージは `v=<base64 server signature>` の形式。
    /// `handle_server_first` が成功する前や、署名が一致しない場合はエラーを返す。
    pub fn handle_server_final(&self, server_final: &str) -> Result<()> {
        let Some(expected) = &self.server_signature else {
            return Err(Error::interface(
                "SCRAM server-final received before server-first",
            ));
        };
        let server_signature = parse_server_final(server_final)?;
        constant_time::verify_slices_are_equal(&server_signature, expected)
            .map_err(|_| Error::internal("SCRAM server signature mismatch"))
    }
}

/// サーバー最初のメッセージを解析して (nonce, salt, iterations) を返す。
///
/// 形式: `r=<nonce>,s=<base64 salt>,i=<iterations>`
fn parse_server_first(server_first: &str) -> Result<(&str, Vec<u8>, NonZeroU32)> {
    let mut attributes = server_first.split(',');
    let nonce = attributes
        .next()
        .and_then(|attribute| attribute.strip_prefix("r="))
        .filter(|nonce| !nonce.is_empty() && nonce.bytes().all(|b| matches!(b, 0x21..=0x7e)))
        .ok_or_else(|| Error::internal("Invalid or missing SCRAM server nonce"))?;
    let salt = attributes
        .next()
        .and_then(|attribute| attribute.strip_prefix("s="))
        .ok_or_else(|| Error::internal("Missing SCRAM salt"))?;
    let count = attributes
        .next()
        .and_then(|attribute| attribute.strip_prefix("i="))
        .and_then(|count| count.parse::<NonZeroU32>().ok())
        .ok_or_else(|| Error::internal("Invalid or missing SCRAM iteration count"))?;
    if count.get() > MAX_SCRAM_ITERATIONS {
        return Err(Error::internal(format!(
            "SCRAM iteration count exceeds the maximum of {MAX_SCRAM_ITERATIONS}"
        )));
    }
    if attributes.next().is_some() {
        return Err(Error::internal(
            "Unexpected additional SCRAM server-first attributes",
        ));
    }
    let salt =
        Base64::decode_vec(salt).map_err(|_| Error::internal("Invalid SCRAM salt base64"))?;
    Ok((nonce, salt, count))
}

/// サーバー最終メッセージを解析して署名を返す。
///
/// 形式: `v=<base64 server signature>`
fn parse_server_final(server_final: &str) -> Result<[u8; 32]> {
    let encoded = server_final
        .strip_prefix("v=")
        .ok_or_else(|| Error::internal("Missing SCRAM server signature"))?;
    let mut signature = [0; 32];
    let decoded = Base64::decode(encoded, &mut signature)
        .map_err(|_| Error::internal("Invalid SCRAM server signature base64 or length"))?;
    if decoded.len() != 32 {
        return Err(Error::internal("Invalid SCRAM server signature length"));
    }
    Ok(signature)
}

/// SCRAM のパスワードに SASLprep (RFC 4013) を適用する。
///
/// PostgreSQL は UTF-8 として有効で禁止文字を含まないパスワードに
/// SASLprep を適用し、それ以外は生のバイト列を使う。
fn prepare_password(password: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(password) {
        Ok(value) => match stringprep::saslprep(value) {
            Ok(prepared) => prepared.into_owned().into_bytes(),
            Err(_) => password.to_vec(),
        },
        Err(_) => password.to_vec(),
    }
}

/// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations, 32) を計算する。
///
/// RFC 5802 3. の Hi() 関数に相当する。
fn derive_salted_password(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> [u8; 32] {
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

/// SHA-256 を計算する。
fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// HMAC-SHA-256 を計算する。
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// 32 バイトの排他的論理和を計算する。
fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 の SCRAM-SHA-256 テストベクタで検証する。
    #[test]
    fn test_scram_rfc7677_vector() {
        let client_nonce = "rOprNGfwEbeRWgbNEkqO";
        let client_first_bare = format!("n=user,r={}", client_nonce);
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let expected_client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
        let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

        let mut scram = ScramClient {
            client_nonce: client_nonce.to_string(),
            client_first_bare,
            server_signature: None,
        };
        let client_final = scram
            .handle_server_first(server_first, b"pencil")
            .expect("RFC 7677 のサーバー初期応答を受理できませんでした");
        assert_eq!(client_final, expected_client_final);
        scram
            .handle_server_final(server_final)
            .expect("RFC 7677 のサーバー署名を検証できませんでした");
    }

    /// サーバー最初のメッセージの解析を検証する。
    #[test]
    fn test_parse_server_first() {
        let (nonce, salt, iterations) =
            parse_server_first("r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
                .expect("サーバー最初のメッセージの解析に成功しました");
        assert_eq!(nonce, "abc123");
        assert_eq!(
            salt,
            Base64::decode_vec("W22ZaJ0SNY7soEsUEjb6gQ==")
                .expect("base64 のデコードに成功しました")
        );
        assert_eq!(iterations.get(), 4096);
    }

    /// 不正なサーバー最初のメッセージでエラーになることを検証する。
    #[test]
    fn test_parse_server_first_invalid() {
        // 属性名が欠けている。
        assert!(parse_server_first("r=abc123").is_err());
        // salt の base64 が不正。
        assert!(parse_server_first("r=abc123,s=!!!,i=4096").is_err());
        // イテレーション数が 0。
        assert!(parse_server_first("r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0").is_err());
        // 未知の属性。
        assert!(parse_server_first("r=abc123,x=1").is_err());
    }

    /// SCRAM のパスワードに SASLprep が適用されることを検証する。
    #[test]
    fn test_prepare_password() {
        assert_eq!(prepare_password(b"pencil"), b"pencil");
        // U+00AD (SOFT HYPHEN) は SASLprep で削除される。
        assert_eq!(prepare_password("I\u{00AD}X".as_bytes()), b"IX");
        // 禁止文字を含む場合は生のバイト列を使う。
        assert_eq!(prepare_password(b"\0"), b"\0");
        // UTF-8 として不正な場合も生のバイト列を使う。
        assert_eq!(prepare_password(&[0xff, 0xfe]), vec![0xff, 0xfe]);
    }

    /// 反復回数の上限を PBKDF2 を実行せず解析段階で検証する。
    #[test]
    fn test_scram_iteration_limit() {
        let prefix = "r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=";
        let exact_limit = format!("{prefix}600000");
        assert_eq!(
            parse_server_first(&exact_limit)
                .expect("上限ちょうどの反復数を受理できませんでした")
                .2
                .get(),
            600_000
        );
        assert!(parse_server_first(&format!("{prefix}600001")).is_err());
        assert!(parse_server_first(&format!("{prefix}4294967296")).is_err());
    }
}
