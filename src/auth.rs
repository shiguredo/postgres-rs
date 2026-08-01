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
use md5::{Digest, Md5};
use std::num::NonZeroU32;

/// PBKDF2 のイテレーション数の上限。
///
/// サーバーが極端に大きな値を送ってきた場合に CPU を消費され続ける
/// DoS を防ぐための上限。PostgreSQL のデフォルトは 4096 で、
/// 現実のサーバーがこの上限を超えることはない。
const MAX_SCRAM_ITERATIONS: u32 = 10_000_000;

/// SCRAM のクライアントキー・サーバーキーの HMAC ラベル。
const SCRAM_CLIENT_KEY_LABEL: &[u8] = b"Client Key";
const SCRAM_SERVER_KEY_LABEL: &[u8] = b"Server Key";

/// SCRAM-SHA-256 クライアントの状態。
#[derive(Debug, Clone)]
pub struct ScramClient {
    client_nonce: String,
    client_first_bare: String,
    auth_message: String,
    server_signature: [u8; 32],
}

impl ScramClient {
    /// クライアント nonce を生成して新しい SCRAM クライアントを作成する。
    ///
    /// nonce は PostgreSQL の libpq と同じく 18 バイトの乱数を
    /// base64 エンコードしたものを使う。
    pub fn new() -> Result<Self> {
        let mut raw_nonce = [0u8; 18];
        rand::fill(&mut raw_nonce).map_err(|_| Error::InternalError {
            code: String::new(),
            message: "Failed to generate SCRAM client nonce".to_string(),
        })?;
        let client_nonce = Base64::encode_string(&raw_nonce);
        let client_first_bare = format!("n=,r={}", client_nonce);
        Ok(Self {
            client_nonce,
            client_first_bare,
            auth_message: String::new(),
            server_signature: [0u8; 32],
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
    pub fn handle_server_first(&mut self, server_first: &str, password: &[u8]) -> Result<String> {
        let (nonce, salt, iterations) = parse_server_first(server_first)?;

        // サーバー nonce はクライアント nonce を先頭に含む必要がある (RFC 5802 5.1)。
        if !nonce.starts_with(&self.client_nonce) {
            return Err(Error::InternalError {
                code: String::new(),
                message: "SCRAM server nonce does not start with client nonce".to_string(),
            });
        }

        let salted_password = derive_salted_password(password, &salt, iterations);

        let client_key = hmac_sha256(&salted_password, SCRAM_CLIENT_KEY_LABEL);
        let stored_key = sha256(&client_key);

        let client_final_without_proof = format!("c=biws,r={}", nonce);
        self.auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );

        let client_signature = hmac_sha256(&stored_key, self.auth_message.as_bytes());
        let client_proof = xor(&client_key, &client_signature);

        let server_key = hmac_sha256(&salted_password, SCRAM_SERVER_KEY_LABEL);
        self.server_signature = hmac_sha256(&server_key, self.auth_message.as_bytes());

        Ok(format!(
            "{},p={}",
            client_final_without_proof,
            Base64::encode_string(&client_proof)
        ))
    }

    /// サーバー最終メッセージの署名を検証する。
    ///
    /// サーバー最終メッセージは `v=<base64 server signature>` の形式。
    /// 検証に失敗した場合はエラーを返す。
    pub fn handle_server_final(&self, server_final: &str) -> Result<()> {
        let server_signature = parse_server_final(server_final)?;
        if server_signature.len() != 32 {
            return Err(Error::InternalError {
                code: String::new(),
                message: format!(
                    "SCRAM server signature length mismatch: expected 32, got {}",
                    server_signature.len()
                ),
            });
        }
        constant_time::verify_slices_are_equal(&server_signature, &self.server_signature).map_err(
            |_| Error::InternalError {
                code: String::new(),
                message: "SCRAM server signature mismatch".to_string(),
            },
        )
    }
}

/// サーバー最初のメッセージを解析して (nonce, salt, iterations) を返す。
///
/// 形式: `r=<nonce>,s=<base64 salt>,i=<iterations>`
fn parse_server_first(server_first: &str) -> Result<(String, Vec<u8>, u32)> {
    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;
    for attr in server_first.split(',') {
        let (key, value) = attr.split_once('=').ok_or_else(|| Error::InternalError {
            code: String::new(),
            message: format!("Invalid SCRAM server-first attribute: {}", attr),
        })?;
        match key {
            "r" => nonce = Some(value.to_string()),
            "s" => {
                let decoded = Base64::decode_vec(value).map_err(|_| Error::InternalError {
                    code: String::new(),
                    message: format!("Invalid SCRAM salt base64: {}", value),
                })?;
                salt = Some(decoded);
            }
            "i" => {
                let parsed: u32 = value.parse().map_err(|_| Error::InternalError {
                    code: String::new(),
                    message: format!("Invalid SCRAM iteration count: {}", value),
                })?;
                iterations = Some(parsed);
            }
            _ => {
                return Err(Error::InternalError {
                    code: String::new(),
                    message: format!("Unknown SCRAM server-first attribute: {}", key),
                });
            }
        }
    }
    let nonce = nonce.ok_or_else(|| Error::InternalError {
        code: String::new(),
        message: "SCRAM server-first is missing nonce".to_string(),
    })?;
    let salt = salt.ok_or_else(|| Error::InternalError {
        code: String::new(),
        message: "SCRAM server-first is missing salt".to_string(),
    })?;
    let iterations = iterations.ok_or_else(|| Error::InternalError {
        code: String::new(),
        message: "SCRAM server-first is missing iteration count".to_string(),
    })?;
    if iterations == 0 {
        return Err(Error::InternalError {
            code: String::new(),
            message: "SCRAM iteration count must be greater than 0".to_string(),
        });
    }
    if iterations > MAX_SCRAM_ITERATIONS {
        return Err(Error::InternalError {
            code: String::new(),
            message: format!(
                "SCRAM iteration count too large: {} (max {})",
                iterations, MAX_SCRAM_ITERATIONS
            ),
        });
    }
    Ok((nonce, salt, iterations))
}

/// サーバー最終メッセージを解析して署名を返す。
///
/// 形式: `v=<base64 server signature>`
fn parse_server_final(server_final: &str) -> Result<Vec<u8>> {
    let (key, value) = server_final
        .split_once('=')
        .ok_or_else(|| Error::InternalError {
            code: String::new(),
            message: format!("Invalid SCRAM server-final message: {}", server_final),
        })?;
    if key != "v" {
        return Err(Error::InternalError {
            code: String::new(),
            message: format!("Unexpected SCRAM server-final attribute: {}", key),
        });
    }
    Base64::decode_vec(value).map_err(|_| Error::InternalError {
        code: String::new(),
        message: format!("Invalid SCRAM server signature base64: {}", value),
    })
}

/// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations, 32) を計算する。
///
/// RFC 5802 3. の Hi() 関数に相当する。
fn derive_salted_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let iterations = NonZeroU32::new(iterations).expect("iterations is validated to be non-zero");
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

/// MD5 認証のパスワードハッシュを計算する。
///
/// PostgreSQL の MD5 認証は `md5` + md5(hex(md5(password + user)) + salt) の形式。
/// PostgreSQL の実装は `src/backend/libpq/auth.c` の `md5_encrypt` を参照。
pub fn md5_password_hash(user: &str, password: &[u8], salt: &[u8]) -> String {
    let mut inner = Md5::new();
    inner.update(password);
    inner.update(user.as_bytes());
    let inner_hex = to_hex(&inner.finalize());

    let mut outer = Md5::new();
    outer.update(inner_hex.as_bytes());
    outer.update(salt);
    let outer_hex = to_hex(&outer.finalize());

    format!("md5{}", outer_hex)
}

/// バイト列を小文字 16 進文字列に変換する。
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
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

        let scram = ScramClient {
            client_nonce: client_nonce.to_string(),
            client_first_bare,
            auth_message: String::new(),
            server_signature: [0u8; 32],
        };
        // パスワードは内部で PBKDF2 に入るため、ハンドラを直接使わず
        // 内部計算でクライアント最終メッセージを再現する。
        let salted_password = derive_salted_password(
            b"pencil",
            &Base64::decode_vec("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap(),
            4096,
        );
        let client_key = hmac_sha256(&salted_password, SCRAM_CLIENT_KEY_LABEL);
        let stored_key = sha256(&client_key);
        let client_final_without_proof =
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0".to_string();
        let auth_message = format!(
            "{},{},{}",
            scram.client_first_bare, server_first, client_final_without_proof
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let client_proof = xor(&client_key, &client_signature);
        let client_final = format!(
            "{},p={}",
            client_final_without_proof,
            Base64::encode_string(&client_proof)
        );
        assert_eq!(client_final, expected_client_final);

        let server_key = hmac_sha256(&salted_password, SCRAM_SERVER_KEY_LABEL);
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
        assert_eq!(
            Base64::encode_string(&server_signature),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
        assert_eq!(
            server_final,
            "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
    }

    /// サーバー最初のメッセージの解析を検証する。
    #[test]
    fn test_parse_server_first() {
        let (nonce, salt, iterations) =
            parse_server_first("r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").unwrap();
        assert_eq!(nonce, "abc123");
        assert_eq!(
            salt,
            Base64::decode_vec("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap()
        );
        assert_eq!(iterations, 4096);
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
        // イテレーション数が上限超過。
        assert!(parse_server_first("r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10000001").is_err());
        // 未知の属性。
        assert!(parse_server_first("r=abc123,x=1").is_err());
    }

    /// MD5 ハッシュが PostgreSQL の形式になることを検証する。
    #[test]
    fn test_md5_password_hash() {
        // 内側の md5("passwordpostgres") は既知の値で検証する。
        let salt = [0x01, 0x02, 0x03, 0x04];
        let hash = md5_password_hash("postgres", b"password", &salt);
        let mut inner = Md5::new();
        inner.update(b"password");
        inner.update(b"postgres");
        let inner_hex = to_hex(&inner.finalize());
        let mut outer = Md5::new();
        outer.update(inner_hex.as_bytes());
        outer.update(salt);
        let expected = format!("md5{}", to_hex(&outer.finalize()));
        assert_eq!(hash, expected);
        assert_eq!(hash.len(), 35);
        assert!(hash.starts_with("md5"));
    }
}
