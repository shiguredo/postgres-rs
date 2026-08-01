// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 認証状態機械。

use crate::auth::{ScramClient, md5_password_hash};
use crate::connection::{AuthState, Connection, SslMode};
use crate::constants::{auth, backend};
use crate::error::{Error, Result};
use crate::protocol::{
    AuthenticationRequest, ErrorResponse, ParameterStatus, PostgresPacket, ReadyForQuery,
};

/// SASL 認証で使用するメカニズム名。
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

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

        let do_ssl = match self.options.ssl_mode {
            SslMode::Disabled => false,
            SslMode::Preferred | SslMode::Required => true,
        };

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
            _ => Err(Error::InternalError {
                code: String::new(),
                message: format!(
                    "Unexpected message during authentication: '{}' (0x{:02x})",
                    packet.message_type as char, packet.message_type
                ),
            }),
        }
    }

    /// SSL 要求への応答 (1 バイトのみ) を処理する。
    fn process_tls_response(&mut self, packet: PostgresPacket) -> Result<AuthState> {
        if !packet.data.is_empty() {
            return Err(Error::InternalError {
                code: String::new(),
                message: format!(
                    "Invalid TLS response: expected 1 byte, got {} bytes",
                    packet.data.len()
                ),
            });
        }
        match packet.message_type {
            // 'S' は ParameterStatus のタイプと同一だが、
            // SSL 要求の直後では TLS 応答を意味する。
            b'S' => {
                self.needs_tls_upgrade = true;
                Ok(AuthState::Send)
            }
            b'N' => {
                if self.options.ssl_mode == SslMode::Required {
                    return Err(Error::OperationalError {
                        code: String::new(),
                        message: "SSL is required but the server doesn't support it".to_string(),
                    });
                }
                tracing::debug!("Server does not support SSL, continuing without it");
                self.write_startup_message()?;
                Ok(AuthState::Send)
            }
            _ => Err(Error::InternalError {
                code: String::new(),
                message: format!(
                    "Invalid TLS response: got '{}' (0x{:02x}), expected 'S' or 'N'",
                    packet.message_type as char, packet.message_type
                ),
            }),
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
                    return Err(Error::InternalError {
                        code: String::new(),
                        message: format!(
                            "Invalid MD5 salt length: expected 4, got {}",
                            auth_request.data.len()
                        ),
                    });
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
                if !mechanisms.iter().any(|m| m == SCRAM_SHA_256) {
                    return Err(Error::NotSupportedError {
                        code: String::new(),
                        message: format!(
                            "SCRAM-SHA-256 is not supported by the server: {:?}",
                            mechanisms
                        ),
                    });
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
                if self.auth_phase != AuthPhase::Scram {
                    return Err(Error::InternalError {
                        code: String::new(),
                        message: "Received SASL continue without starting SASL".to_string(),
                    });
                }
                let scram = self.scram.as_mut().ok_or_else(|| Error::InternalError {
                    code: String::new(),
                    message: "SASL continue without SCRAM client state".to_string(),
                })?;
                let server_first = auth_request.as_str()?;
                let client_final =
                    scram.handle_server_first(server_first, &self.options.password)?;
                let message = crate::protocol::sasl_response(client_final.as_bytes());
                self.packet_stream.write_message(&message);
                Ok(AuthState::Send)
            }
            auth::SASL_FINAL => {
                if self.auth_phase != AuthPhase::Scram {
                    return Err(Error::InternalError {
                        code: String::new(),
                        message: "Received SASL final without starting SASL".to_string(),
                    });
                }
                let scram = self.scram.as_ref().ok_or_else(|| Error::InternalError {
                    code: String::new(),
                    message: "SASL final without SCRAM client state".to_string(),
                })?;
                let server_final = auth_request.as_str()?;
                scram.handle_server_final(server_final)?;
                tracing::debug!("SCRAM server signature verified");
                Ok(AuthState::NeedRead)
            }
            code => Err(Error::NotSupportedError {
                code: String::new(),
                message: format!("Authentication method {} is not supported", code),
            }),
        }
    }
}
