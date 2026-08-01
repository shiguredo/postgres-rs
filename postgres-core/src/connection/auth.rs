// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 認証状態機械。

use crate::auth::{ScramClient, md5_password_hash};
use crate::connection::{AuthState, ConnectOptions, Connection, SslMode};
use crate::constants::{auth, backend};
use crate::error::{Error, Result};
use crate::protocol::{
    AuthenticationRequest, ErrorResponse, ParameterStatus, PostgresPacket, ReadyForQuery,
};

/// SASL 認証で使用するメカニズム名。
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// OAuth 認証で使用するメカニズム名。
///
/// PostgreSQL の OAuth 認証 (pg_hba.conf の `oauth` メソッド) は
/// SASL OAUTHBEARER メカニズム (RFC 7628) を使う。
/// サーバー実装は PostgreSQL の `src/backend/libpq/auth-oauth.c` を参照。
const OAUTHBEARER: &str = "OAUTHBEARER";

/// 認証処理の段階。
///
/// SASL 認証は複数往復するため、認証方式の進行状況を保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPhase {
    /// 初期段階。認証要求の応答待ち。
    Initial,
    /// SCRAM-SHA-256 認証中。
    Scram,
    /// MD5 認証中。
    Md5,
    /// 平文パスワード認証中。
    Cleartext,
    /// OAuth (OAUTHBEARER) 認証中。
    Oauth,
}

impl Connection {
    /// 認証要求の第一段階。
    ///
    /// SSL 要求 (必要な場合) またはスタートアップメッセージを
    /// send_queue に追加する。
    ///
    /// SSL 要求を送信した場合は `AuthState::Send` を返す。
    /// この場合、サーバーからの SSL 応答 (1 バイト) を読み込んで
    /// `request_authentication_continue` を呼ぶと、
    /// 'S' 応答時は `needs_tls_upgrade()` が true になる。
    pub fn request_authentication_start(&mut self) -> Result<AuthState> {
        if self.options.user.is_empty() {
            return Err(Error::InterfaceError {
                message: "Did not specify a username".to_string(),
            });
        }

        let do_ssl = !matches!(self.options.ssl_mode, SslMode::Disabled);

        if do_ssl {
            let message = crate::protocol::ssl_request_message();
            self.packet_stream.write_message(&message);
            self.packet_stream.expect_tls_response();
            self.tls_requested = true;
            self.auth_phase = AuthPhase::Initial;
            return Ok(AuthState::Send);
        }

        self.write_startup_message()?;
        self.auth_phase = AuthPhase::Initial;
        Ok(AuthState::Send)
    }

    /// TLS アップグレード後にスタートアップメッセージを送信する。
    ///
    /// `needs_tls_upgrade()` が true の状態で、呼び出し側が
    /// TLS 接続を確立して `set_secure(true)` を呼んだ後に使う。
    pub fn request_authentication_send_startup(&mut self) -> Result<AuthState> {
        if !self.needs_tls_upgrade {
            return Err(Error::InterfaceError {
                message: "TLS upgrade is not pending".to_string(),
            });
        }
        self.write_startup_message()?;
        self.needs_tls_upgrade = false;
        self.auth_phase = AuthPhase::Initial;
        Ok(AuthState::Send)
    }

    /// スタートアップメッセージを組み立てて送信キューに追加する。
    fn write_startup_message(&mut self) -> Result<()> {
        let mut parameters: Vec<(&str, String)> = Vec::new();
        parameters.push(("user", self.options.user.clone()));
        if let Some(database) = &self.options.database {
            parameters.push(("database", database.clone()));
        }
        if let Some(application_name) = &self.options.application_name {
            parameters.push(("application_name", application_name.clone()));
        }
        // クライアントエンコーディングは UTF-8 に固定する。
        // すべてのメッセージを UTF-8 としてデコードする前提のため。
        parameters.push(("client_encoding", "UTF8".to_string()));
        parameters.push(("DateStyle", "ISO".to_string()));

        let refs: Vec<(&str, &str)> = parameters.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let message = crate::protocol::startup_message(&refs);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// 認証応答を処理し、次の状態を返す。
    ///
    /// 追加の送信が必要な場合は send_queue にデータを追加して
    /// `AuthState::Send` を返す。
    /// `ReadyForQuery` を受信した時点で `AuthState::Success` を返す。
    pub fn request_authentication_continue(&mut self) -> Result<AuthState> {
        if self.tls_requested {
            self.tls_requested = false;
            let packet = self.read_packet()?;
            return self.process_tls_response(packet);
        }

        let packet = self.read_packet()?;
        match packet.message_type {
            backend::AUTHENTICATION_REQUEST => self.process_authentication(packet),
            backend::PARAMETER_STATUS => {
                let status = ParameterStatus::parse(&packet)?;
                tracing::debug!(name = %status.name, value = %status.value, "Parameter status");
                self.server_parameters.insert(status.name, status.value);
                Ok(AuthState::NeedRead)
            }
            backend::BACKEND_KEY_DATA => {
                let key_data = crate::protocol::BackendKeyData::parse(&packet)?;
                self.backend_process_id = key_data.process_id;
                self.backend_secret_key = key_data.secret_key;
                Ok(AuthState::NeedRead)
            }
            backend::NOTICE_RESPONSE => {
                let notice = crate::protocol::NoticeResponse::parse(&packet)?;
                tracing::debug!(
                    severity = %notice.severity,
                    code = %notice.code,
                    message = %notice.message,
                    "Notice"
                );
                Ok(AuthState::NeedRead)
            }
            backend::ERROR_RESPONSE => {
                let response = ErrorResponse::parse(&packet)?;
                Err(crate::error::from_error_response(&response))
            }
            backend::READY_FOR_QUERY => {
                let ready = ReadyForQuery::parse(&packet)?;
                self.transaction_status = ready.transaction_status;
                let status = match ready.transaction_status {
                    crate::constants::transaction_status::IDLE => "idle",
                    crate::constants::transaction_status::IN_TRANSACTION => "in transaction",
                    crate::constants::transaction_status::FAILED => "failed transaction",
                    _ => "unknown",
                };
                tracing::debug!(transaction_status = status, "Authentication complete");
                Ok(AuthState::Success)
            }
            _ => Err(Error::internal(format!(
                "Unexpected message during authentication: '{}' (0x{:02x})",
                packet.message_type as char, packet.message_type
            ))),
        }
    }

    /// SSL 要求への応答 (1 バイトのみ) を処理する。
    fn process_tls_response(&mut self, packet: PostgresPacket) -> Result<AuthState> {
        if !packet.data.is_empty() {
            return Err(Error::internal(format!(
                "Invalid TLS response: expected 1 byte, got {} bytes",
                packet.data.len()
            )));
        }
        match packet.message_type {
            // 'S' は ParameterStatus のタイプと同一だが、
            // SSL 要求の直後では TLS 応答を意味する。
            b'S' => {
                self.needs_tls_upgrade = true;
                Ok(AuthState::Send)
            }
            b'N' => {
                // Required / VerifyCa / VerifyFull はサーバーが SSL に
                // 対応していない場合にエラーにする。
                // Allow / Preferred は平文にフォールバックする。
                let ssl_required =
                    !matches!(self.options.ssl_mode, SslMode::Allow | SslMode::Preferred);
                if ssl_required {
                    return Err(Error::operational(
                        "SSL is required but the server doesn't support it",
                    ));
                }
                tracing::debug!("Server does not support SSL, continuing without it");
                self.write_startup_message()?;
                Ok(AuthState::Send)
            }
            _ => Err(Error::internal(format!(
                "Invalid TLS response: got '{}' (0x{:02x}), expected 'S' or 'N'",
                packet.message_type as char, packet.message_type
            ))),
        }
    }

    /// 認証要求メッセージを処理する。
    fn process_authentication(&mut self, packet: PostgresPacket) -> Result<AuthState> {
        let auth_request = AuthenticationRequest::parse(&packet)?;
        match auth_request.code {
            auth::OK => {
                tracing::debug!("Authentication OK");
                Ok(AuthState::NeedRead)
            }
            auth::CLEARTEXT_PASSWORD => {
                let message = crate::protocol::password_message(&self.options.password);
                self.packet_stream.write_message(&message);
                self.auth_phase = AuthPhase::Cleartext;
                Ok(AuthState::Send)
            }
            auth::MD5_PASSWORD => {
                if auth_request.data.len() != 4 {
                    return Err(Error::internal(format!(
                        "Invalid MD5 salt length: expected 4, got {}",
                        auth_request.data.len()
                    )));
                }
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&auth_request.data);
                let hash = md5_password_hash(&self.options.user, &self.options.password, &salt);
                let message = crate::protocol::password_message(hash.as_bytes());
                self.packet_stream.write_message(&message);
                self.auth_phase = AuthPhase::Md5;
                Ok(AuthState::Send)
            }
            auth::SASL => {
                let mechanisms = auth_request.mechanisms();
                tracing::debug!(mechanisms = ?mechanisms, "SASL mechanisms offered");
                // OAuth トークンが設定されていてサーバーが OAUTHBEARER を
                // 提供している場合は OAuth 認証を選ぶ (libpq と同じ挙動)。
                if self.options.oauth_token.is_some() && mechanisms.iter().any(|m| m == OAUTHBEARER)
                {
                    let initial = oauth_initial_response(&self.options)?;
                    let message =
                        crate::protocol::sasl_initial_response(OAUTHBEARER, initial.as_bytes());
                    self.packet_stream.write_message(&message);
                    self.auth_phase = AuthPhase::Oauth;
                    return Ok(AuthState::Send);
                }
                if !mechanisms.iter().any(|m| m == SCRAM_SHA_256) {
                    return Err(Error::not_supported(format!(
                        "SCRAM-SHA-256 is not supported by the server: {:?}",
                        mechanisms
                    )));
                }
                let scram = ScramClient::new()?;
                let client_first = scram.client_first_message();
                let message =
                    crate::protocol::sasl_initial_response(SCRAM_SHA_256, client_first.as_bytes());
                self.packet_stream.write_message(&message);
                self.scram = Some(scram);
                self.auth_phase = AuthPhase::Scram;
                Ok(AuthState::Send)
            }
            auth::SASL_CONTINUE => {
                if self.auth_phase == AuthPhase::Oauth {
                    // サーバーがトークンを拒否した (RFC 7628 のエラー応答)。
                    // 新しいトークンで接続をやり直す必要がある。
                    // 同一接続で再認証を試みてもサーバーは kvsep 応答のみ
                    // 受け付けるため、接続の張り直しは呼び出し側が行う。
                    return Err(Error::NeedOAuthToken);
                }
                if self.auth_phase != AuthPhase::Scram {
                    return Err(Error::internal(
                        "Received SASL continue without starting SASL".to_string(),
                    ));
                }
                let scram = self.scram.as_mut().ok_or_else(|| {
                    Error::internal("SASL continue without SCRAM client state".to_string())
                })?;
                let server_first = auth_request.as_str()?;
                let client_final =
                    scram.handle_server_first(server_first, &self.options.password)?;
                let message = crate::protocol::sasl_response(client_final.as_bytes());
                self.packet_stream.write_message(&message);
                Ok(AuthState::Send)
            }
            auth::SASL_FINAL => {
                if self.auth_phase == AuthPhase::Oauth {
                    // OAuth ではサーバーは検証成功時に最終メッセージを送らず、
                    // 直接 AuthenticationOK を送る。防御的にここでは
                    // 認証完了として AuthenticationOK を待つ。
                    return Ok(AuthState::NeedRead);
                }
                if self.auth_phase != AuthPhase::Scram {
                    return Err(Error::internal(
                        "Received SASL final without starting SASL".to_string(),
                    ));
                }
                let scram = self.scram.as_ref().ok_or_else(|| {
                    Error::internal("SASL final without SCRAM client state".to_string())
                })?;
                let server_final = auth_request.as_str()?;
                scram.handle_server_final(server_final)?;
                tracing::debug!("SCRAM server signature verified");
                Ok(AuthState::NeedRead)
            }
            code => Err(Error::not_supported(format!(
                "Authentication method {} is not supported",
                code
            ))),
        }
    }
}

/// OAUTHBEARER の初期応答を組み立てる。
///
/// RFC 7628 Sec. 3.1 の形式で、GS2 ヘッダー (`n,,`) の後に
/// kvsep 区切りの key-value ペアを続ける。
/// libpq と同じく `auth=Bearer <token>` のみを送り、
/// host / port は含めない。
fn oauth_initial_response(options: &ConnectOptions) -> Result<String> {
    let token = options.oauth_token.as_ref().ok_or_else(|| {
        Error::not_supported(
            "The server requires OAuth authentication but no OAuth token is configured",
        )
    })?;
    Ok(format!("n,,\x01auth=Bearer {}\x01\x01", token))
}
