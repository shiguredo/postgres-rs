// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! テスト用のヘルパー関数。
//!
//! モックやスタブは使わず、サーバーが送信するはずの
//! ワイヤプロトコルのバイト列を組み立てて供給する。

// ヘルパーは各テストバイナリ (test_auth / test_connection / test_protocol) が
// 使用する関数の一部だけを参照するため、使用されない関数が発生する。
// テストバイナリごとに警告が出るのを防ぐ。
#![allow(dead_code)]

use aws_lc_rs::digest;
use aws_lc_rs::hmac;
use aws_lc_rs::pbkdf2;
use base64ct::{Base64, Encoding};
use std::num::NonZeroU32;

/// バックエンドメッセージをフレーム化する。
pub fn build_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(message_type);
    message.extend_from_slice(&((payload.len() as u32 + 4).to_be_bytes()));
    message.extend_from_slice(payload);
    message
}

/// フレーム化されたクライアントメッセージを分解する。
///
/// 戻り値は (メッセージタイプ, ペイロード)。
pub fn parse_client_message(message: &[u8]) -> (u8, &[u8]) {
    let message_type = message[0];
    let length = u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize;
    (message_type, &message[5..5 + length - 4])
}

/// AuthenticationOk メッセージを組み立てる。
pub fn authentication_ok() -> Vec<u8> {
    build_message(b'R', &0_u32.to_be_bytes())
}

/// AuthenticationCleartextPassword メッセージを組み立てる。
pub fn authentication_cleartext() -> Vec<u8> {
    build_message(b'R', &3_u32.to_be_bytes())
}

/// AuthenticationMD5Password メッセージを組み立てる。
pub fn authentication_md5(salt: &[u8; 4]) -> Vec<u8> {
    let mut payload = 5_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(salt);
    build_message(b'R', &payload)
}

/// AuthenticationSASL メッセージを組み立てる。
pub fn authentication_sasl(mechanisms: &[&str]) -> Vec<u8> {
    let mut payload = 10_u32.to_be_bytes().to_vec();
    for mechanism in mechanisms {
        payload.extend_from_slice(mechanism.as_bytes());
        payload.push(0);
    }
    payload.push(0);
    build_message(b'R', &payload)
}

/// AuthenticationSASLContinue メッセージを組み立てる。
pub fn authentication_sasl_continue(server_first: &[u8]) -> Vec<u8> {
    let mut payload = 11_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(server_first);
    build_message(b'R', &payload)
}

/// AuthenticationSASLFinal メッセージを組み立てる。
pub fn authentication_sasl_final(server_final: &[u8]) -> Vec<u8> {
    let mut payload = 12_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(server_final);
    build_message(b'R', &payload)
}

/// ParameterStatus メッセージを組み立てる。
pub fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    build_message(b'S', &payload)
}

/// BackendKeyData メッセージを組み立てる。
pub fn backend_key_data(process_id: u32, secret_key: u32) -> Vec<u8> {
    let mut payload = process_id.to_be_bytes().to_vec();
    payload.extend_from_slice(&secret_key.to_be_bytes());
    build_message(b'K', &payload)
}

/// ReadyForQuery メッセージを組み立てる。
pub fn ready_for_query(transaction_status: u8) -> Vec<u8> {
    build_message(b'Z', &[transaction_status])
}

/// ErrorResponse メッセージを組み立てる。
///
/// フィールドは S (severity), C (SQLSTATE), M (message) のみ。
pub fn error_response(code: &str, message: &str) -> Vec<u8> {
    build_message(b'E', &error_response_payload(code, message))
}

/// ErrorResponse のペイロード (フレームヘッダーなし) を組み立てる。
pub fn error_response_payload(code: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(b'S');
    payload.extend_from_slice(b"ERROR\0");
    payload.push(b'C');
    payload.extend_from_slice(code.as_bytes());
    payload.push(0);
    payload.push(b'M');
    payload.extend_from_slice(message.as_bytes());
    payload.push(0);
    payload.push(0);
    payload
}

/// RowDescription メッセージを組み立てる。
///
/// フィールドは (名前, 型 OID) のリスト。
pub fn row_description(fields: &[(&str, u32)]) -> Vec<u8> {
    let mut payload = (fields.len() as i16).to_be_bytes().to_vec();
    for (name, type_oid) in fields {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0_u32.to_be_bytes());
        payload.extend_from_slice(&0_i16.to_be_bytes());
        payload.extend_from_slice(&type_oid.to_be_bytes());
        payload.extend_from_slice(&(-1_i16).to_be_bytes());
        payload.extend_from_slice(&(-1_i32).to_be_bytes());
        payload.extend_from_slice(&0_i16.to_be_bytes());
    }
    build_message(b'T', &payload)
}

/// DataRow メッセージを組み立てる。
pub fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut payload = (values.len() as i16).to_be_bytes().to_vec();
    for value in values {
        match value {
            None => payload.extend_from_slice(&(-1_i32).to_be_bytes()),
            Some(bytes) => {
                payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                payload.extend_from_slice(bytes);
            }
        }
    }
    build_message(b'D', &payload)
}

/// CommandComplete メッセージを組み立てる。
pub fn command_complete(tag: &str) -> Vec<u8> {
    let mut payload = tag.as_bytes().to_vec();
    payload.push(0);
    build_message(b'C', &payload)
}

/// ParseComplete メッセージを組み立てる。
pub fn parse_complete() -> Vec<u8> {
    build_message(b'1', &[])
}

/// BindComplete メッセージを組み立てる。
pub fn bind_complete() -> Vec<u8> {
    build_message(b'2', &[])
}

/// ParameterDescription メッセージを組み立てる。
pub fn parameter_description(type_oids: &[u32]) -> Vec<u8> {
    let mut payload = (type_oids.len() as i16).to_be_bytes().to_vec();
    for oid in type_oids {
        payload.extend_from_slice(&oid.to_be_bytes());
    }
    build_message(b't', &payload)
}

/// テスト用の SCRAM-SHA-256 サーバー。
///
/// クライアントの証明を検証し、サーバー署名を計算する。
/// RFC 5802 / RFC 7677 のサーバー側の処理をそのまま実装している。
pub struct ScramServer {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub server_nonce: String,
}

impl ScramServer {
    /// 新しい SCRAM サーバーを作成する。
    pub fn new() -> Self {
        Self {
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            iterations: 4096,
            server_nonce: "TestServerNonce".to_string(),
        }
    }

    /// クライアント最初のメッセージから nonce を抽出してサーバー最初のメッセージを返す。
    pub fn server_first(&self, client_first: &str) -> String {
        let client_first_bare = client_first.strip_prefix("n,,").unwrap_or(client_first);
        let client_nonce = client_first_bare.rsplit("r=").next().unwrap_or_default();
        format!(
            "r={}{},s={},i={}",
            client_nonce,
            self.server_nonce,
            Base64::encode_string(&self.salt),
            self.iterations
        )
    }

    /// クライアント最終メッセージを検証してサーバー最終メッセージを返す。
    ///
    /// クライアントの証明が正しくない場合は `None` を返す。
    pub fn server_final(
        &self,
        client_final: &str,
        password: &[u8],
        client_first_bare: &str,
        server_first: &str,
    ) -> Option<String> {
        let mut nonce = None;
        let mut proof = None;
        for attr in client_final.split(',') {
            let (key, value) = attr.split_once('=')?;
            match key {
                "r" => nonce = Some(value),
                "p" => proof = Some(value),
                _ => {}
            }
        }
        let nonce = nonce?;
        let proof = proof?;
        if !nonce.ends_with(&self.server_nonce) {
            return None;
        }

        let client_final_without_proof = format!("c=biws,r={}", nonce);
        let auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );

        let iterations = NonZeroU32::new(self.iterations).expect("iterations is non-zero");
        let mut salted_password = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &self.salt,
            password,
            &mut salted_password,
        );

        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key = sha256(&client_key);
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let expected_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let received_proof = Base64::decode_vec(proof).ok()?;
        if received_proof != expected_proof {
            return None;
        }

        let server_key = hmac_sha256(&salted_password, b"Server Key");
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
        Some(format!("v={}", Base64::encode_string(&server_signature)))
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}
