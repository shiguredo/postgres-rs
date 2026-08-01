// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 接続を管理するモジュール。

pub mod auth;
pub mod packet;
pub mod result;

use crate::auth::ScramClient;
use crate::connection::auth::AuthPhase;
use crate::connection::packet::PacketStream;
pub use crate::connection::result::{FeedResult, QueryResult};
use crate::error::{Error, Result};
use crate::protocol::PostgresPacket;
use std::collections::HashMap;
use std::time::Duration;

/// デフォルトポート。
pub const DEFAULT_PORT: u16 = 5432;

/// デフォルトの最大メッセージサイズ。
///
/// サーバーが送信できるメッセージサイズを制限して DoS を防ぐ。
/// PostgreSQL の単一メッセージの理論上の上限は 1 GB だが、
/// 現実的な利用ではこのサイズで十分。
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// 接続オプション。
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Vec<u8>,
    pub database: Option<String>,
    pub application_name: Option<String>,
    pub connect_timeout: Duration,
    pub ssl_mode: SslMode,
    pub max_message_size: usize,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: DEFAULT_PORT,
            user: String::new(),
            password: Vec::new(),
            database: None,
            application_name: None,
            connect_timeout: Duration::from_secs(10),
            ssl_mode: SslMode::Preferred,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

/// SSL モード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// SSL を使用しない。
    Disabled,
    /// サーバーが対応していれば SSL、しなければ平文。
    Preferred,
    /// SSL が必須。
    Required,
}

/// 認証状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// サーバーからの応答を待つ。
    NeedRead,
    /// 送信すべきデータが send_queue に追加された。
    Send,
    /// 認証成功。
    Success,
}

/// PostgreSQL 接続 (sans I/O)。
///
/// 実際の TCP/TLS 入出力は呼び出し側が担当し、
/// 本構造体はプロトコル状態と送受信キューの管理のみを行う。
pub struct Connection {
    options: ConnectOptions,
    packet_stream: PacketStream,
    auth_phase: AuthPhase,
    scram: Option<ScramClient>,
    server_parameters: HashMap<String, String>,
    backend_process_id: u32,
    backend_secret_key: u32,
    transaction_status: u8,
    secure: bool,
    needs_tls_upgrade: bool,
    tls_requested: bool,
    result: Option<QueryResult>,
    affected_rows: i64,
    closed: bool,
}

impl Connection {
    /// 新規接続のための内部状態を構築する。
    ///
    /// 実際の TCP/TLS 接続および認証は呼び出し側が行う。
    pub fn connect(options: ConnectOptions) -> Result<Self> {
        if options.port == 0 {
            return Err(Error::InterfaceError {
                message: "port must be greater than 0".to_string(),
            });
        }
        if options.max_message_size == 0 {
            return Err(Error::InterfaceError {
                message: "max_message_size must be greater than 0".to_string(),
            });
        }
        let one_year = Duration::from_secs(365 * 24 * 60 * 60);
        if options.connect_timeout.is_zero() || options.connect_timeout >= one_year {
            return Err(Error::InterfaceError {
                message: "connect_timeout must be greater than 0 and less than one year"
                    .to_string(),
            });
        }

        Ok(Self {
            packet_stream: PacketStream::new(options.max_message_size),
            options,
            auth_phase: AuthPhase::Initial,
            scram: None,
            server_parameters: HashMap::new(),
            backend_process_id: 0,
            backend_secret_key: 0,
            transaction_status: 0,
            secure: false,
            needs_tls_upgrade: false,
            tls_requested: false,
            result: None,
            affected_rows: 0,
            closed: false,
        })
    }

    /// TLS アップグレードが必要かどうかを返す。
    ///
    /// サーバーが SSL 要求に 'S' で応答した場合に true になる。
    /// 呼び出し側は TLS 接続を確立して `set_secure(true)` を呼び、
    /// `request_authentication_send_startup` で認証を再開する。
    pub fn needs_tls_upgrade(&self) -> bool {
        self.needs_tls_upgrade
    }

    /// TLS 状態を設定する。
    pub fn set_secure(&mut self, secure: bool) {
        self.secure = secure;
    }

    /// TLS 接続が確立されているかどうか。
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// 接続オプションを取得する。
    pub fn options(&self) -> &ConnectOptions {
        &self.options
    }

    /// 接続が開いているかどうか。
    pub fn is_open(&self) -> bool {
        !self.closed
    }

    /// 接続を閉じる。
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let message = crate::protocol::terminate_message();
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// 強制的に接続を閉じる。
    pub fn force_close(&mut self) {
        self.packet_stream.force_close();
        self.closed = true;
    }

    /// 送信キューから先頭のメッセージを取り出す。
    pub fn pop_send_queue(&mut self) -> Option<Vec<u8>> {
        self.packet_stream.send_queue.pop_front()
    }

    /// 受信した生バイト列を消費してメッセージを組み立て、recv_queue に追加する。
    pub fn feed_bytes(&mut self, data: &[u8]) -> Result<usize> {
        self.packet_stream.feed_bytes(data)
    }

    /// 受信済みメッセージキューから一つ取り出す。
    pub fn read_packet(&mut self) -> Result<PostgresPacket> {
        self.packet_stream.read_packet()
    }

    /// 受信キューが空かどうかを返す。
    pub fn is_recv_queue_empty(&self) -> bool {
        self.packet_stream.recv_queue.is_empty()
    }

    /// サーバーパラメータを取得する。
    pub fn server_parameters(&self) -> &HashMap<String, String> {
        &self.server_parameters
    }

    /// バックエンドプロセス ID を取得する。
    pub fn backend_process_id(&self) -> u32 {
        self.backend_process_id
    }

    /// バックエンドのシークレットキーを取得する。
    pub fn backend_secret_key(&self) -> u32 {
        self.backend_secret_key
    }

    /// 現在のトランザクション状態を取得する。
    pub fn transaction_status(&self) -> u8 {
        self.transaction_status
    }

    /// サーバーバージョンを取得する。
    pub fn server_version(&self) -> Option<&str> {
        self.server_parameters
            .get("server_version")
            .map(String::as_str)
    }

    /// クエリを実行する (単純クエリプロトコル)。
    ///
    /// 影響を受けた行数を返す。
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    pub fn query(&mut self, sql: &str, unbuffered: bool) -> Result<i64> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::InterfaceError {
                message: "Connection is closed".to_string(),
            });
        }
        tracing::debug!(sql = %sql, unbuffered, "Executing query");
        let message = crate::protocol::query_message(sql);
        self.packet_stream.write_message(&message);
        let affected_rows = self.read_query_result(unbuffered)?;
        tracing::debug!(affected_rows, "Query executed");
        Ok(affected_rows)
    }

    /// パラメータ付きクエリを実行する (拡張クエリプロトコル)。
    ///
    /// パラメータはテキスト形式で送信される。
    /// 影響を受けた行数を返す。
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    pub fn execute(
        &mut self,
        sql: &str,
        parameters: &[crate::converters::Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::InterfaceError {
                message: "Connection is closed".to_string(),
            });
        }
        tracing::debug!(sql = %sql, parameter_count = parameters.len(), unbuffered, "Executing statement");
        let encoded: Vec<Option<Vec<u8>>> = parameters.iter().map(|v| v.to_bytes()).collect();
        let refs: Vec<Option<&[u8]>> = encoded.iter().map(|p| p.as_deref()).collect();

        // 名前なしステートメント・名前なしポータルを使用し、
        // パース・バインド・記述・実行・同期を一括で送信する。
        let parse = crate::protocol::parse_message("", sql, &[]);
        let bind = crate::protocol::bind_message("", "", &refs);
        let describe = crate::protocol::describe_message(crate::constants::describe::PORTAL, "");
        let execute = crate::protocol::execute_message("", 0);
        let sync = crate::protocol::sync_message();
        for message in [parse, bind, describe, execute, sync] {
            self.packet_stream.write_message(&message);
        }

        let affected_rows = self.read_query_result(unbuffered)?;
        tracing::debug!(affected_rows, "Statement executed");
        Ok(affected_rows)
    }

    /// 結果セットを読み込む。
    ///
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    /// 呼び出し側はさらにデータを供給してから再度呼び出すことで読み込みを再開できる。
    pub fn read_query_result(&mut self, unbuffered: bool) -> Result<i64> {
        let mut result = self
            .result
            .take()
            .filter(|r| !r.is_done())
            .unwrap_or_default();
        if result.is_initial() {
            result.unbuffered_active = unbuffered;
        }
        loop {
            let packet = self.read_packet()?;
            match result.feed_packet(packet) {
                Ok(FeedResult::NeedMore) => continue,
                Ok(FeedResult::Done | FeedResult::UnbufferedReady) => {
                    let affected_rows = result.affected_rows;
                    self.transaction_status =
                        result.transaction_status.unwrap_or(self.transaction_status);
                    self.result = Some(result);
                    return Ok(affected_rows);
                }
                Err(e) => {
                    // エラー応答で中断した場合は、次のクエリ実行時に
                    // ReadyForQuery まで読み飛ばすために結果を保持する。
                    self.result = Some(result);
                    return Err(e);
                }
            }
        }
    }

    /// 結果セットを設定する。
    pub fn set_result(&mut self, result: QueryResult) {
        self.transaction_status = result.transaction_status.unwrap_or(self.transaction_status);
        self.result = Some(result);
    }

    /// 前回の結果セットの読み残しを読み飛ばす。
    ///
    /// 新しいクエリを実行する前に呼び出す。
    /// エラー応答で中断した結果やアンバッファード結果を回収する。
    ///
    /// `Error::NeedMoreData` で中断した場合は結果を保持したままエラーを返す。
    /// 呼び出し側はデータを供給してから再度呼び出すことで再開できる。
    pub(crate) fn finish_previous_result(&mut self) -> Result<()> {
        if let Some(mut result) = self.result.take() {
            let finish = (|| {
                if result.unbuffered_active {
                    result.finish_unbuffered(self)?;
                }
                while !result.is_done() {
                    let packet = self.read_packet()?;
                    match result.feed_packet(packet)? {
                        FeedResult::NeedMore => continue,
                        FeedResult::Done | FeedResult::UnbufferedReady => break,
                    }
                }
                Ok(())
            })();
            if finish.is_err() {
                // 受信キューにデータが足りない等で中断した場合は、
                // 結果を保持して再開できるようにする。
                self.result = Some(result);
                return finish;
            }
            self.transaction_status = result.transaction_status.unwrap_or(self.transaction_status);
        }
        Ok(())
    }

    /// 影響を受けた行数を取得する。
    pub fn affected_rows(&self) -> i64 {
        self.affected_rows
    }

    /// 現在の結果セットを取得する。
    pub fn result(&self) -> Option<&QueryResult> {
        self.result.as_ref()
    }

    /// 現在の結果セットを可変で取得する。
    ///
    /// アンバッファードクエリで行を 1 行ずつ読み込むために使う。
    pub fn result_mut(&mut self) -> Option<&mut QueryResult> {
        self.result.as_mut()
    }
}
