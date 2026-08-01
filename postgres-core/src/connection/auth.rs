// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 認証状態機械。

use crate::auth::ScramClient;
use crate::connection::{AuthState, Connection, SslMode};
use crate::constants::{auth, backend, transaction_status};
use crate::error::{Error, Result};
use crate::protocol::{
    AuthenticationRequest, ErrorResponse, ParameterStatus, PostgresPacket, ReadyForQuery,
};

/// SASL 認証で使用するメカニズム名。
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// OAuth 認証で使用する SASL メカニズム名 (RFC 7628)。
const OAUTHBEARER: &str = "OAUTHBEARER";

/// 認証処理の段階。
///
/// 初期の AuthenticationOk は trust 等に対応するが、SCRAM の開始後は
/// サーバー証明の検証を済ませない限り AuthenticationOk を受け付けない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthPhase {
    /// 認証開始前または TLS 交渉中。
    NotStarted,
    /// スタートアップメッセージを送信して認証要求を待つ。
    Initial,
    /// ローカル接続で平文パスワードを送信し結果を待つ。
    CleartextSent,
    /// SCRAM の最初のサーバーメッセージを待つ。
    ScramContinue,
    /// SCRAM の最後のサーバーメッセージを待つ。
    ScramFinal,
    /// SCRAM のサーバー証明を検証済みで AuthenticationOk を待つ。
    ScramVerified,
    /// OAuth トークンを送信して結果を待つ。
    Oauth,
    /// AuthenticationOk を受信して ReadyForQuery を待つ。
    Authenticated { secret_sent: bool },
    /// 認証と起動が完了した。
    Complete,
    /// 認証エラーが発生した。この接続で再開できない。
    Failed,
}

impl Connection {
    /// 認証要求の第一段階。
    ///
    /// SSL 要求 (必要な場合) またはスタートアップメッセージを送信キューに追加する。
    /// SSL 要求への 'S' 応答後は `needs_tls_upgrade()` が true になる。
    pub fn request_authentication_start(&mut self) -> Result<AuthState> {
        if self.closed
            || self.auth_phase != AuthPhase::NotStarted
            || self.tls_requested
            || self.needs_tls_upgrade
        {
            return Err(Error::interface("Authentication cannot be started again"));
        }
        if self.options.user.is_empty() {
            return Err(Error::interface("Did not specify a username"));
        }

        if self.options.ssl_mode != SslMode::Disabled {
            let message = crate::protocol::ssl_request_message();
            self.packet_stream.write_message(&message);
            self.packet_stream.expect_tls_response();
            self.tls_requested = true;
        } else {
            self.write_startup_message()?;
            self.auth_phase = AuthPhase::Initial;
        }
        Ok(AuthState::Send)
    }

    /// TLS アップグレード後にスタートアップメッセージを送信する。
    ///
    /// `needs_tls_upgrade()` が true の状態で、呼び出し側が指定された `SslMode` の
    /// 条件を満たす TLS 接続を確立して `set_secure(true)` を呼んだ後に使う。
    pub fn request_authentication_send_startup(&mut self) -> Result<AuthState> {
        if self.closed || !self.needs_tls_upgrade || !self.secure {
            return Err(Error::interface(
                "A TLS connection is required before startup",
            ));
        }
        self.write_startup_message()?;
        self.needs_tls_upgrade = false;
        self.auth_phase = AuthPhase::Initial;
        Ok(AuthState::Send)
    }

    /// スタートアップメッセージを組み立てて送信キューに追加する。
    fn write_startup_message(&mut self) -> Result<()> {
        // 起動パラメーターは Connection::connect で検査済みで、接続後には変更できない。
        let mut parameters = vec![("user", self.options.user.as_str())];
        if let Some(database) = &self.options.database {
            parameters.push(("database", database.as_str()));
        }
        if let Some(application_name) = &self.options.application_name {
            parameters.push(("application_name", application_name.as_str()));
        }
        // 追加の GUC は固定値より前に置き、同名の指定を検証で弾いておく。
        for (name, value) in &self.options.runtime_params {
            parameters.push((name.as_str(), value.as_str()));
        }
        // すべてのメッセージを UTF-8 としてデコードする前提のため固定する。
        parameters.push(("client_encoding", "UTF8"));
        parameters.push(("DateStyle", "ISO"));

        crate::protocol::validate_startup(&parameters)?;
        let message = crate::protocol::startup_message(&parameters);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// 認証応答を処理し、次の状態を返す。
    ///
    /// 追加の送信が必要な場合は送信キューにデータを追加し `AuthState::Send` を返す。
    /// 正しい順序の AuthenticationOk と ReadyForQuery を受信してから成功を返す。
    /// 受信データが不足する場合を除き、応答の処理中にエラーが起きた接続は破棄する。
    pub fn request_authentication_continue(&mut self) -> Result<AuthState> {
        if self.closed
            || matches!(self.auth_phase, AuthPhase::Complete | AuthPhase::Failed)
            || (self.auth_phase == AuthPhase::NotStarted && !self.tls_requested)
        {
            return Err(Error::interface(
                "Authentication is not awaiting a response",
            ));
        }

        let packet = self.packet_stream.read_packet()?;
        let result = if self.tls_requested {
            self.tls_requested = false;
            self.process_tls_response(packet)
        } else {
            self.process_startup_response(packet)
        };
        if result.is_err() {
            // 失敗した段階を読み飛ばして、後続のメッセージから認証を続けてはいけない。
            self.auth_phase = AuthPhase::Failed;
            self.scram = None;
            self.force_close();
        }
        result
    }

    /// スタートアップ中に受信したメッセージを処理する。
    fn process_startup_response(&mut self, packet: PostgresPacket) -> Result<AuthState> {
        // PostgreSQL 18 公式文書 §54.2.1 の Startup に従い、AuthenticationOk の後に
        // ParameterStatus、BackendKeyData、ReadyForQuery を受け付ける。
        // 将来のプロトコルで順序が変わった場合はここも更新する。
        match packet.message_type {
            backend::AUTHENTICATION_REQUEST => self.process_authentication(packet),
            backend::PARAMETER_STATUS
                if matches!(self.auth_phase, AuthPhase::Authenticated { .. }) =>
            {
                let status = ParameterStatus::parse(&packet)?;
                // 起動時に送った値をサーバーが報告する。前提を崩す値なら認証を終えない。
                super::check_session_parameter(&status)?;
                self.server_parameters.insert(status.name, status.value);
                Ok(AuthState::NeedRead)
            }
            backend::BACKEND_KEY_DATA
                if matches!(self.auth_phase, AuthPhase::Authenticated { .. }) =>
            {
                let key_data = crate::protocol::BackendKeyData::parse(&packet)?;
                self.backend_process_id = key_data.process_id;
                self.backend_secret_key = key_data.secret_key;
                Ok(AuthState::NeedRead)
            }
            backend::NOTICE_RESPONSE => {
                // サーバーのペイロードをログに出さず、利用者が明示的に取得できるようにする。
                let notice = crate::protocol::NoticeResponse::parse(&packet)?;
                self.notices.push_back(notice);
                Ok(AuthState::NeedRead)
            }
            backend::ERROR_RESPONSE => {
                if matches!(
                    self.auth_phase,
                    AuthPhase::CleartextSent
                        | AuthPhase::Oauth
                        | AuthPhase::Authenticated { secret_sent: true }
                ) {
                    // サーバーが受け取った資格情報をエラーに含めても呼び出し側に伝播させない。
                    return Err(Error::operational(
                        "Server rejected startup after credentials were sent",
                    ));
                }
                let response = ErrorResponse::parse(&packet)?;
                Err(crate::error::from_error_response(&response))
            }
            backend::READY_FOR_QUERY
                if matches!(self.auth_phase, AuthPhase::Authenticated { .. }) =>
            {
                let ready = ReadyForQuery::parse(&packet)?;
                if ready.transaction_status != transaction_status::IDLE {
                    return Err(Error::internal(
                        "Expected an idle ReadyForQuery during startup",
                    ));
                }
                self.transaction_status = ready.transaction_status;
                self.ready_sequence = self.ready_sequence.wrapping_add(1);
                self.auth_phase = AuthPhase::Complete;
                tracing::debug!("Authentication complete");
                Ok(AuthState::Success)
            }
            _ => Err(Error::internal(format!(
                "Unexpected message during startup: 0x{:02x}",
                packet.message_type
            ))),
        }
    }

    /// SSL 要求への応答 (1 バイトのみ) を処理する。
    fn process_tls_response(&mut self, packet: PostgresPacket) -> Result<AuthState> {
        if !packet.data.is_empty() || !self.is_recv_queue_empty() {
            return Err(Error::internal(
                "Invalid TLS response: expected a single byte",
            ));
        }
        match packet.message_type {
            b'S' => {
                self.needs_tls_upgrade = true;
                Ok(AuthState::Send)
            }
            b'N' => Err(Error::operational(
                "TLS is required but the server does not support it",
            )),
            _ => Err(Error::internal("Invalid TLS response: expected 'S' or 'N'")),
        }
    }

    /// 認証要求メッセージを処理する。
    fn process_authentication(&mut self, packet: PostgresPacket) -> Result<AuthState> {
        let request = AuthenticationRequest::parse(&packet)?;
        // PostgreSQL 18 公式文書 §54.3 の SASL 交換順序を検証する。
        // 将来のメカニズムを追加するときは、成功に必要な段階もここへ追加する。
        match (request.code, self.auth_phase) {
            (auth::CLEARTEXT_PASSWORD, AuthPhase::Initial)
                if self.options.ssl_mode == SslMode::Disabled
                    && !self.secure
                    && self.options.is_local_endpoint() =>
            {
                // PostgreSQL 18 公式文書 §54.7 の AuthenticationCleartextPassword には
                // 方式コード以外のペイロードがない。将来の仕様変更時はこの検査を見直す。
                if !request.data.is_empty() {
                    return Err(Error::internal(
                        "Unexpected payload in cleartext authentication request",
                    ));
                }
                // この例外は明示的に TLS を無効化したローカル開発用の接続だけに適用する。
                let message = crate::protocol::password_message(&self.options.password)?;
                self.packet_stream.write_message(&message);
                self.auth_phase = AuthPhase::CleartextSent;
                Ok(AuthState::Send)
            }
            (auth::CLEARTEXT_PASSWORD, AuthPhase::Initial) => Err(Error::not_supported(
                "Cleartext password authentication requires a local connection with sslmode=disable; configure SCRAM-SHA-256",
            )),
            (auth::MD5_PASSWORD, _) => Err(Error::not_supported(
                "MD5 password authentication is disabled; configure SCRAM-SHA-256",
            )),
            (
                auth::OK,
                phase @ (AuthPhase::Initial
                | AuthPhase::CleartextSent
                | AuthPhase::Oauth
                | AuthPhase::ScramVerified),
            ) => {
                if !request.data.is_empty() {
                    return Err(Error::internal("Unexpected payload in AuthenticationOk"));
                }
                self.auth_phase = AuthPhase::Authenticated {
                    secret_sent: matches!(phase, AuthPhase::CleartextSent | AuthPhase::Oauth),
                };
                Ok(AuthState::NeedRead)
            }
            (auth::SASL, AuthPhase::Initial) => self.start_sasl(&request.data),
            (auth::SASL_CONTINUE, AuthPhase::Oauth) => {
                // RFC 7628 §3.2.3 のエラー応答を受けた接続では認証を続けない。
                // サーバー提供の発見情報は使わず、利用者のプロバイダから取得し直す。
                Err(Error::NeedOAuthToken)
            }
            (auth::SASL_CONTINUE, AuthPhase::ScramContinue) => {
                let scram = self
                    .scram
                    .as_mut()
                    .ok_or_else(|| Error::internal("SASL continue without SCRAM client state"))?;
                let client_final =
                    scram.handle_server_first(request.as_str()?, &self.options.password)?;
                let message = crate::protocol::sasl_response(client_final.as_bytes());
                self.packet_stream.write_message(&message);
                self.auth_phase = AuthPhase::ScramFinal;
                Ok(AuthState::Send)
            }
            (auth::SASL_FINAL, AuthPhase::ScramFinal) => {
                let scram = self
                    .scram
                    .take()
                    .ok_or_else(|| Error::internal("SASL final without SCRAM client state"))?;
                scram.handle_server_final(request.as_str()?)?;
                self.auth_phase = AuthPhase::ScramVerified;
                Ok(AuthState::NeedRead)
            }
            (
                auth::OK
                | auth::CLEARTEXT_PASSWORD
                | auth::SASL
                | auth::SASL_CONTINUE
                | auth::SASL_FINAL,
                _,
            ) => {
                // OAUTHBEARER には成功時の追加データがない (RFC 7628 §3.2)。
                Err(Error::internal(format!(
                    "Unexpected authentication request in current phase: {}",
                    request.code
                )))
            }
            (code, _) => Err(Error::not_supported(format!(
                "Authentication method {code} is not supported"
            ))),
        }
    }

    /// サーバーの SASL リストからメカニズムを選択し初期応答を送る。
    fn start_sasl(&mut self, data: &[u8]) -> Result<AuthState> {
        let (scram_offered, oauth_offered) = parse_sasl_mechanisms(data)?;
        if let Some(token) = &self.options.oauth_token
            && oauth_offered
        {
            // RFC 7628 §3 は OAUTHBEARER のトークン送信に TLS を要求する。
            // Sans I/O 層では I/O 側の TLS 検証完了通知を信頼し、平文へ降格しない。
            if !self.secure || self.options.ssl_mode != SslMode::VerifyFull {
                return Err(Error::not_supported(
                    "OAUTHBEARER authentication requires a verified TLS connection",
                ));
            }
            let initial = oauth_initial_response(token)?;
            let message = crate::protocol::sasl_initial_response(OAUTHBEARER, initial.as_bytes());
            self.packet_stream.write_message(&message);
            self.auth_phase = AuthPhase::Oauth;
        } else if scram_offered {
            let scram = ScramClient::new()?;
            let client_first = scram.client_first_message();
            let message =
                crate::protocol::sasl_initial_response(SCRAM_SHA_256, client_first.as_bytes());
            self.packet_stream.write_message(&message);
            self.scram = Some(scram);
            self.auth_phase = AuthPhase::ScramContinue;
        } else if oauth_offered {
            return Err(Error::not_supported(
                "The server requires OAuth authentication but no OAuth token is configured",
            ));
        } else {
            return Err(Error::not_supported(
                "No supported SASL mechanism offered by the server",
            ));
        }
        Ok(AuthState::Send)
    }
}

/// PostgreSQL 18 §54.7 の AuthenticationSASL に従い、空文字列終端まで検証する。
///
/// SASL メカニズム名の文字は RFC 4422 §3.1 に従う。将来の拡張は有効な名前なら無視する。
fn parse_sasl_mechanisms(data: &[u8]) -> Result<(bool, bool)> {
    let Some(data) = data.strip_suffix(b"\0\0") else {
        return Err(Error::internal("Invalid SASL mechanism list terminator"));
    };
    let mut scram = false;
    let mut oauth = false;
    for mechanism in data.split(|&byte| byte == 0) {
        if !(1..=20).contains(&mechanism.len())
            || !mechanism.iter().all(|&byte| {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(Error::internal("Invalid SASL mechanism name"));
        }
        scram |= mechanism == SCRAM_SHA_256.as_bytes();
        oauth |= mechanism == OAUTHBEARER.as_bytes();
    }
    Ok((scram, oauth))
}

/// RFC 7628 §3.1 に沿って OAUTHBEARER の初期応答を組み立てる。
fn oauth_initial_response(token: &str) -> Result<String> {
    const PREFIX: &str = "n,,\x01auth=Bearer ";
    const SUFFIX: &str = "\x01\x01";
    // PostgreSQL 18 の PG_MAX_AUTH_TOKEN_LENGTH は長さフィールドを含む。
    // 制限が将来変更された場合はここも見直す。
    const MAX_TOKEN_LENGTH: usize =
        65_535 - 4 - (OAUTHBEARER.len() + 1) - 4 - PREFIX.len() - SUFFIX.len();
    if token.len() > MAX_TOKEN_LENGTH {
        return Err(Error::interface("OAuth token is too long"));
    }
    // RFC 6750 §2.1 の b64token に従い、SASL の区切り文字や空白の混入も防ぐ。
    let value = token.trim_end_matches('=');
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
    {
        return Err(Error::interface("Invalid OAuth bearer token format"));
    }
    Ok(format!("{PREFIX}{token}{SUFFIX}"))
}
