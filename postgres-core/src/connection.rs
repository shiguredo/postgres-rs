// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 接続を管理するモジュール。

pub mod auth;
pub mod packet;
pub mod result;

use crate::auth::ScramClient;
use crate::connection::auth::AuthPhase;
use crate::connection::packet::PacketStream;
pub use crate::connection::result::{FeedResult, QueryResult, RowSet};
use crate::constants::backend;
use crate::converters::Converter;
use crate::error::{Error, Result};
use crate::protocol::{
    CopyResponse, ErrorResponse, FieldDescription, NoticeResponse, NotificationResponse,
    ParameterStatus, PostgresPacket, ReadyForQuery,
};
use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
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
    /// CA 証明書のファイルパス。指定がない場合は OS 標準の証明書ストアを使う。
    pub ssl_ca: Option<String>,
    /// クライアント証明書のファイルパス。
    pub ssl_cert: Option<String>,
    /// クライアント秘密鍵のファイルパス。
    pub ssl_key: Option<String>,
    /// OAuth のアクセストークン。
    ///
    /// サーバーが OAUTHBEARER メカニズムを提供している場合に使う。
    /// `Connection::connect_with_oauth` を使うと、トークンが拒否された
    /// ときにトークンプロバイダから新しいトークンを取得して再接続する。
    pub oauth_token: Option<String>,
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
            ssl_ca: None,
            ssl_cert: None,
            ssl_key: None,
            oauth_token: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

impl ConnectOptions {
    /// libpq 形式の接続文字列から接続オプションを構築する。
    ///
    /// 形式は `key=value` のペアを空白区切りで並べたもの。
    /// 値は単一引用符で囲むことができ、引用符内では
    /// バックスラッシュによるエスケープと `''` による引用符の表現が使える。
    ///
    /// 対応するキー:
    /// `host` / `port` / `dbname` / `database` / `user` / `password` /
    /// `application_name` / `connect_timeout` (秒) / `sslmode` /
    /// `sslrootcert` / `sslcert` / `sslkey`。
    /// 未知のキーは無視する (libpq と同じ挙動)。
    pub fn from_conninfo(conninfo: &str) -> Result<Self> {
        let mut options = Self::default();
        for (key, value) in parse_conninfo(conninfo)? {
            match key.as_str() {
                "host" => options.host = value,
                "port" => {
                    options.port = value.parse().map_err(|_| {
                        Error::interface(format!("Invalid port in connection string: {}", value))
                    })?
                }
                "dbname" | "database" => options.database = Some(value),
                "user" => options.user = value,
                "password" => options.password = value.into_bytes(),
                "application_name" => options.application_name = Some(value),
                "connect_timeout" => {
                    let seconds: u64 = value.parse().map_err(|_| {
                        Error::interface(format!(
                            "Invalid connect_timeout in connection string: {}",
                            value
                        ))
                    })?;
                    options.connect_timeout = Duration::from_secs(seconds);
                }
                "sslmode" => options.ssl_mode = SslMode::from_str(&value)?,
                "sslrootcert" => options.ssl_ca = Some(value),
                "sslcert" => options.ssl_cert = Some(value),
                "sslkey" => options.ssl_key = Some(value),
                _ => {
                    tracing::debug!(key = %key, "Ignoring unknown connection parameter");
                }
            }
        }
        Ok(options)
    }

    /// `postgres://` または `postgresql://` 形式の URL から接続オプションを構築する。
    ///
    /// 形式は `postgres://[user[:password]@][host][:port][/dbname][?query]`。
    /// クエリ文字列には conninfo と同じキー (`sslmode` 等) を指定できる。
    /// `?host=/path` で Unix ドメインソケットのディレクトリを指定できる。
    ///
    /// libpq の接続文字列の仕様に基づく。
    /// <https://www.postgresql.org/docs/current/libpq-connect.html>
    pub fn from_url(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
            .ok_or_else(|| Error::interface(format!("Invalid PostgreSQL URL: {}", url)))?;

        let (userinfo, rest) = match rest.split_once('@') {
            Some((userinfo, rest)) => (Some(userinfo), rest),
            None => (None, rest),
        };
        let (authority, path_and_query) = match rest.split_once('/') {
            Some((authority, path_and_query)) => (authority, path_and_query),
            None => (rest, ""),
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };

        let mut options = Self::default();
        if let Some(userinfo) = userinfo {
            let (user, password) = match userinfo.split_once(':') {
                Some((user, password)) => (user, Some(password)),
                None => (userinfo, None),
            };
            options.user = percent_decode(user, false)?;
            if let Some(password) = password {
                options.password = percent_decode(password, false)?.into_bytes();
            }
        }
        if !authority.is_empty() {
            let (host, port) = parse_url_authority(authority)?;
            if let Some(host) = host {
                options.host = host;
            }
            if let Some(port) = port {
                options.port = port;
            }
        }
        if !path.is_empty() {
            options.database = Some(percent_decode(path, false)?);
        }
        if let Some(query) = query {
            for (key, value) in parse_url_query(query) {
                match key.as_str() {
                    "host" => options.host = value,
                    "port" => {
                        options.port = value.parse().map_err(|_| {
                            Error::interface(format!("Invalid port in URL: {}", value))
                        })?
                    }
                    "sslmode" => options.ssl_mode = SslMode::from_str(&value)?,
                    "application_name" => options.application_name = Some(value),
                    "connect_timeout" => {
                        let seconds: u64 = value.parse().map_err(|_| {
                            Error::interface(format!("Invalid connect_timeout in URL: {}", value))
                        })?;
                        options.connect_timeout = Duration::from_secs(seconds);
                    }
                    "sslrootcert" => options.ssl_ca = Some(value),
                    "sslcert" => options.ssl_cert = Some(value),
                    "sslkey" => options.ssl_key = Some(value),
                    _ => {
                        tracing::debug!(key = %key, "Ignoring unknown URL query parameter");
                    }
                }
            }
        }
        Ok(options)
    }
}

/// libpq 形式の接続文字列を `(キー, 値)` のペアのリストに分解する。
///
/// 値は単一引用符で囲むことができ、引用符内ではバックスラッシュによる
/// エスケープと `''` による引用符の表現が使える (libpq と同じ規則)。
fn parse_conninfo(conninfo: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    let chars: Vec<char> = conninfo.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // 空白をスキップする。
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        // キーは空白または = までの文字列。
        let key_start = i;
        while i < chars.len() && chars[i] != '=' && !chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            return Err(Error::interface(format!(
                "Invalid connection string: {}",
                conninfo
            )));
        }
        let key: String = chars[key_start..i].iter().collect();
        i += 1;
        // 値は単一引用符付きまたは単一引用符なし。
        let value = if i < chars.len() && chars[i] == '\'' {
            i += 1;
            let mut value = String::new();
            let mut closed = false;
            while i < chars.len() {
                match chars[i] {
                    '\'' => {
                        if i + 1 < chars.len() && chars[i + 1] == '\'' {
                            value.push('\'');
                            i += 2;
                        } else {
                            i += 1;
                            closed = true;
                            break;
                        }
                    }
                    '\\' if i + 1 < chars.len() => {
                        value.push(chars[i + 1]);
                        i += 2;
                    }
                    c => {
                        value.push(c);
                        i += 1;
                    }
                }
            }
            if !closed {
                return Err(Error::interface(format!(
                    "Invalid connection string: {}",
                    conninfo
                )));
            }
            value
        } else {
            let value_start = i;
            while i < chars.len() && !chars[i].is_whitespace() {
                i += 1;
            }
            chars[value_start..i].iter().collect()
        };
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// URL の authority 部分 (`host[:port]` または `[IPv6]:port`) を分解する。
fn parse_url_authority(authority: &str) -> Result<(Option<String>, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 アドレスは [::1]:5432 の形式で書かれる。
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| Error::interface(format!("Invalid host in URL: {}", authority)))?;
        let port = match after.strip_prefix(':') {
            Some(port) => Some(
                port.parse()
                    .map_err(|_| Error::interface(format!("Invalid port in URL: {}", authority)))?,
            ),
            None => None,
        };
        return Ok((Some(host.to_string()), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| Error::interface(format!("Invalid port in URL: {}", authority)))?;
            Ok((Some(host.to_string()), Some(port)))
        }
        None => Ok((Some(authority.to_string()), None)),
    }
}

/// URL のクエリ文字列を `(キー, 値)` のペアのリストに分解する。
///
/// `+` は空白を意味する (フォームエンコーディングと同じ規則)。
fn parse_url_query(query: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let key = percent_decode(key, true).unwrap_or_else(|_| key.to_string());
        let value = percent_decode(value, true).unwrap_or_else(|_| value.to_string());
        pairs.push((key, value));
    }
    pairs
}

/// パーセントエンコードされた文字列をデコードする。
///
/// `plus_as_space` が true の場合は `+` を空白に変換する (クエリ文字列用)。
fn percent_decode(s: &str, plus_as_space: bool) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(Error::interface(format!("Invalid percent encoding: {}", s)));
                }
                let hi = hex_value(bytes[i + 1])
                    .ok_or_else(|| Error::interface(format!("Invalid percent encoding: {}", s)))?;
                let lo = hex_value(bytes[i + 2])
                    .ok_or_else(|| Error::interface(format!("Invalid percent encoding: {}", s)))?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| Error::interface(format!("Invalid UTF-8: {}", e)))
}

/// 16 進文字の値を返す。16 進文字でない場合は `None`。
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// SSL モード。
///
/// libpq の `sslmode` と同じ意味を持つ。
/// <https://www.postgresql.org/docs/current/libpq-ssl.html>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// SSL を使用しない。
    Disabled,
    /// まず SSL を試し、サーバーが対応していないか
    /// 接続の失敗時に平文へフォールバックする。
    Allow,
    /// サーバーが対応していれば SSL、しなければ平文。
    ///
    /// デフォルト。SSL を使用する場合は CA 検証を行い、
    /// ホスト名の検証は行わない。
    Preferred,
    /// SSL が必須。CA 検証を行い、ホスト名の検証は行わない。
    Required,
    /// SSL が必須。CA 検証のみ行い、ホスト名の検証は行わない。
    VerifyCa,
    /// SSL が必須。CA 検証とホスト名の検証の両方を行う。
    VerifyFull,
}

impl FromStr for SslMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "disable" => Ok(SslMode::Disabled),
            "allow" => Ok(SslMode::Allow),
            "prefer" => Ok(SslMode::Preferred),
            "require" => Ok(SslMode::Required),
            "verify-ca" => Ok(SslMode::VerifyCa),
            "verify-full" => Ok(SslMode::VerifyFull),
            _ => Err(Error::interface(format!("Invalid sslmode: {}", s))),
        }
    }
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

/// 非同期通知。
///
/// LISTEN 中のチャネルに NOTIFY が送られたときに受信する。
#[derive(Debug, Clone)]
pub struct Notification {
    /// 通知を送ったバックエンドのプロセス ID。
    pub process_id: u32,
    /// チャネル名。
    pub channel: String,
    /// ペイロード。
    pub payload: String,
}

/// COPY プロトコルの進行状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyPhase {
    None,
    In,
    Out,
}

/// バッチクエリの結果読み込みの進行状態。
///
/// `NeedMoreData` で中断したときに保持され、再開に使う。
#[derive(Debug)]
enum BatchReadProgress {
    /// まだ読み終わっていない結果のリスト。
    Reading(Vec<Result<i64>>),
    /// エラー応答後の読み飛ばしが中断した状態。
    ///
    /// `remaining` はエラーで実行されなかったステートメントの残り数。
    AfterError {
        results: Vec<Result<i64>>,
        remaining: usize,
    },
}

/// プリペアドステートメント。
#[derive(Debug, Clone)]
pub struct PreparedStatement {
    /// サーバー上のステートメント名。
    pub name: String,
    /// ステートメントの SQL テキスト。
    pub sql: String,
    /// パラメータの型 OID。準備時にサーバーが決定する。
    pub parameter_oids: Vec<u32>,
    /// 結果のフィールド情報。行を返さないステートメントでは空。
    pub fields: Vec<FieldDescription>,
}

/// エラー後に実行されなかったバッチステートメントの結果を埋める。
fn finish_batch_after_error(mut results: Vec<Result<i64>>, remaining: usize) -> Vec<Result<i64>> {
    for _ in 0..remaining {
        results.push(Err(Error::internal(
            "Batch statement was not executed because a previous statement failed",
        )));
    }
    results
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
    /// 受信した非同期通知のキュー。
    notifications: VecDeque<Notification>,
    /// 受信した NOTICE のキュー。
    notices: VecDeque<NoticeResponse>,
    /// ユーザーが登録した型 OID ごとのデコーダ。
    custom_decoders: HashMap<u32, Converter>,
    /// COPY プロトコルの進行状態。
    copy_phase: CopyPhase,
    /// 準備中のステートメントの名前と SQL。
    pending_prepare: Option<(String, String)>,
    /// 次に生成するステートメント名の番号。
    next_statement_id: u64,
    /// バッチクエリの結果読み込みの進行状態。
    pending_batch: Option<BatchReadProgress>,
}

impl Connection {
    /// 新規接続のための内部状態を構築する。
    ///
    /// 実際の TCP/TLS 接続および認証は呼び出し側が行う。
    pub fn connect(options: ConnectOptions) -> Result<Self> {
        if options.port == 0 {
            return Err(Error::interface("port must be greater than 0"));
        }
        if options.max_message_size == 0 {
            return Err(Error::interface("max_message_size must be greater than 0"));
        }
        let one_year = Duration::from_secs(365 * 24 * 60 * 60);
        if options.connect_timeout.is_zero() || options.connect_timeout >= one_year {
            return Err(Error::interface(
                "connect_timeout must be greater than 0 and less than one year",
            ));
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
            notifications: VecDeque::new(),
            notices: VecDeque::new(),
            custom_decoders: HashMap::new(),
            copy_phase: CopyPhase::None,
            pending_prepare: None,
            next_statement_id: 0,
            pending_batch: None,
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

    /// クエリ結果読み込み用に 1 メッセージを取得する。
    ///
    /// 非同期メッセージ (通知・NOTICE・パラメータステータス) は
    /// キューに積んで `None` を返し、それ以外は `Some(packet)` を返す。
    /// 受信キューにメッセージがない場合は `Error::NeedMoreData` を返す。
    pub fn read_query_packet(&mut self) -> Result<Option<PostgresPacket>> {
        let packet = self.read_packet()?;
        match packet.message_type {
            backend::NOTIFICATION_RESPONSE
            | backend::NOTICE_RESPONSE
            | backend::PARAMETER_STATUS => {
                self.handle_async_message(packet)?;
                Ok(None)
            }
            _ => Ok(Some(packet)),
        }
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

    /// 受信した非同期通知を一つ取り出す。
    ///
    /// 通知はクエリ実行中の任意のタイミングで受信されるため、
    /// クエリの実行・結果読み込み後に確認する。
    pub fn pop_notification(&mut self) -> Option<Notification> {
        self.notifications.pop_front()
    }

    /// 受信した非同期通知をすべて取り出す。
    pub fn drain_notifications(&mut self) -> Vec<Notification> {
        self.notifications.drain(..).collect()
    }

    /// 受信した NOTICE を一つ取り出す。
    pub fn pop_notice(&mut self) -> Option<NoticeResponse> {
        self.notices.pop_front()
    }

    /// 型 OID に対応するデコーダを登録する。
    ///
    /// 登録したデコーダは組み込みのデコーダより優先される。
    /// 複合型・enum・独自型の配列等をテキスト形式で変換する場合に使う。
    pub fn register_converter(&mut self, type_oid: u32, converter: Converter) {
        self.custom_decoders.insert(type_oid, converter);
    }

    /// クエリを実行する (単純クエリプロトコル)。
    ///
    /// 影響を受けた行数を返す。
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    pub fn query(&mut self, sql: &str, unbuffered: bool) -> Result<i64> {
        self.send_query(sql)?;
        self.read_query_result(unbuffered)
    }

    /// クエリメッセージを送信キューに追加する (単純クエリプロトコル)。
    ///
    /// 前回の結果の読み残しを回収してから送信する。
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す
    /// (読み残しの回収中の場合)。
    pub fn send_query(&mut self, sql: &str) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        tracing::debug!(sql = %sql, "Sending query");
        let message = crate::protocol::query_message(sql);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// パラメータ付きクエリを実行する (拡張クエリプロトコル)。
    ///
    /// パラメータはテキスト形式で送信される。
    /// 無名ステートメントを使うため、毎回サーバー側でパースされる。
    /// 影響を受けた行数を返す。
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    pub fn execute(
        &mut self,
        sql: &str,
        parameters: &[crate::converters::Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.send_execute(sql, parameters)?;
        self.read_query_result(unbuffered)
    }

    /// パラメータ付きクエリのメッセージ群を送信キューに追加する (拡張クエリプロトコル)。
    ///
    /// 前回の結果の読み残しを回収してから送信する。
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す
    /// (読み残しの回収中の場合)。
    pub fn send_execute(
        &mut self,
        sql: &str,
        parameters: &[crate::converters::Value],
    ) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        tracing::debug!(
            sql = %sql,
            parameter_count = parameters.len(),
            "Sending statement"
        );
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
        Ok(())
    }

    /// プリペアドステートメントを準備するためのメッセージ群を送信キューに追加する。
    ///
    /// パース・記述・同期を送信する。ステートメント名はクライアント側で生成し、
    /// 準備完了は `read_prepare_result` で受け取る。
    /// 前回の結果の読み残しを回収してから送信する。
    pub fn send_prepare(&mut self, sql: &str) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        self.next_statement_id += 1;
        let name = format!("stmt_{}", self.next_statement_id);
        tracing::debug!(statement_name = %name, sql = %sql, "Preparing statement");
        let parse = crate::protocol::parse_message(&name, sql, &[]);
        let describe =
            crate::protocol::describe_message(crate::constants::describe::STATEMENT, &name);
        let sync = crate::protocol::sync_message();
        for message in [parse, describe, sync] {
            self.packet_stream.write_message(&message);
        }
        self.pending_prepare = Some((name, sql.to_string()));
        Ok(())
    }

    /// 準備したステートメントの結果を読み込む。
    ///
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    /// 呼び出し側はさらにデータを供給してから再度呼び出すことで読み込みを再開できる。
    pub fn read_prepare_result(&mut self) -> Result<PreparedStatement> {
        let mut result = self
            .result
            .take()
            .filter(|r| !r.is_done())
            .unwrap_or_default();
        loop {
            let packet = match self.read_query_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) => continue,
                Err(e) => {
                    self.result = Some(result);
                    return Err(e);
                }
            };
            match result.feed_packet(packet) {
                Ok(FeedResult::NeedMore | FeedResult::UnbufferedReady) => continue,
                Ok(FeedResult::Done) => {
                    let (name, sql) = self.pending_prepare.take().ok_or_else(|| {
                        Error::internal("read_prepare_result called without send_prepare")
                    })?;
                    self.transaction_status =
                        result.transaction_status.unwrap_or(self.transaction_status);
                    let statement = PreparedStatement {
                        name,
                        sql,
                        parameter_oids: result.parameter_oids.clone(),
                        fields: result.fields.clone(),
                    };
                    tracing::debug!(
                        statement_name = %statement.name,
                        parameter_count = statement.parameter_oids.len(),
                        "Statement prepared"
                    );
                    return Ok(statement);
                }
                Err(e) => {
                    // エラー応答で中断した場合は、次の操作時に
                    // ReadyForQuery まで読み飛ばすために結果を保持する。
                    self.result = Some(result);
                    return Err(e);
                }
            }
        }
    }

    /// プリペアドステートメントを実行するためのメッセージ群を送信キューに追加する。
    ///
    /// 前回の結果の読み残しを回収してから送信する。
    /// 結果の読み込みは `read_query_result` で行う。
    pub fn send_execute_prepared(
        &mut self,
        statement: &PreparedStatement,
        parameters: &[crate::converters::Value],
    ) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        if parameters.len() != statement.parameter_oids.len() {
            return Err(Error::interface(format!(
                "Parameter count mismatch: expected {}, got {}",
                statement.parameter_oids.len(),
                parameters.len()
            )));
        }
        tracing::debug!(
            statement_name = %statement.name,
            parameter_count = parameters.len(),
            "Executing prepared statement"
        );
        let encoded: Vec<Option<Vec<u8>>> = parameters.iter().map(|v| v.to_bytes()).collect();
        let refs: Vec<Option<&[u8]>> = encoded.iter().map(|p| p.as_deref()).collect();

        let bind = crate::protocol::bind_message("", &statement.name, &refs);
        let describe = crate::protocol::describe_message(crate::constants::describe::PORTAL, "");
        let execute = crate::protocol::execute_message("", 0);
        let sync = crate::protocol::sync_message();
        for message in [bind, describe, execute, sync] {
            self.packet_stream.write_message(&message);
        }
        Ok(())
    }

    /// バッチクエリのメッセージ群を送信キューに追加する (拡張クエリプロトコル)。
    ///
    /// 複数のステートメントを 1 往復で送信する。各ステートメントは
    /// 無名ステートメントでパース・バインド・記述・実行し、
    /// 最後に 1 回だけ同期する。
    /// 結果の読み込みは `read_batch_results` で行う。
    pub fn send_batch(
        &mut self,
        statements: &[(String, Vec<crate::converters::Value>)],
    ) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        tracing::debug!(statement_count = statements.len(), "Sending batch");
        for (sql, parameters) in statements {
            let encoded: Vec<Option<Vec<u8>>> = parameters.iter().map(|v| v.to_bytes()).collect();
            let refs: Vec<Option<&[u8]>> = encoded.iter().map(|p| p.as_deref()).collect();
            let parse = crate::protocol::parse_message("", sql, &[]);
            let bind = crate::protocol::bind_message("", "", &refs);
            let describe =
                crate::protocol::describe_message(crate::constants::describe::PORTAL, "");
            let execute = crate::protocol::execute_message("", 0);
            for message in [parse, bind, describe, execute] {
                self.packet_stream.write_message(&message);
            }
        }
        let sync = crate::protocol::sync_message();
        self.packet_stream.write_message(&sync);
        Ok(())
    }

    /// バッチクエリの結果をすべて読み込む。
    ///
    /// 戻り値の長さは送信したステートメント数と同じで、
    /// ステートメントごとの影響行数またはエラーを持つ。
    /// 途中のステートメントでエラーが起きた場合、後続のステートメントは
    /// サーバーで実行されず、未実行を表すエラーが入る。
    ///
    /// `Error::NeedMoreData` で中断した場合は進行状態を保持するため、
    /// 呼び出し側がデータを供給してから再度呼び出すことで再開できる。
    pub fn read_batch_results(&mut self, count: usize) -> Result<Vec<Result<i64>>> {
        // 中断状態から再開する。
        match self.pending_batch.take() {
            Some(BatchReadProgress::Reading(results)) => {
                self.read_batch_results_inner(count, results)
            }
            Some(BatchReadProgress::AfterError { results, remaining }) => {
                // エラー応答後の読み飛ばしを再開する。
                match self.finish_previous_result() {
                    Ok(()) => Ok(finish_batch_after_error(results, remaining)),
                    Err(Error::NeedMoreData) => {
                        self.pending_batch =
                            Some(BatchReadProgress::AfterError { results, remaining });
                        Err(Error::NeedMoreData)
                    }
                    Err(e) => Err(e),
                }
            }
            None => self.read_batch_results_inner(count, Vec::new()),
        }
    }

    /// バッチクエリの結果読み込みの本体。
    fn read_batch_results_inner(
        &mut self,
        count: usize,
        mut results: Vec<Result<i64>>,
    ) -> Result<Vec<Result<i64>>> {
        while results.len() < count {
            // 最後のステートメントは ReadyForQuery まで読み、
            // 途中のステートメントはコマンド完了で完了とする。
            let is_last = results.len() + 1 == count;
            match self.read_query_result_inner(false, !is_last) {
                Ok(affected) => results.push(Ok(affected)),
                Err(Error::NeedMoreData) => {
                    self.pending_batch = Some(BatchReadProgress::Reading(results));
                    return Err(Error::NeedMoreData);
                }
                Err(e) => {
                    results.push(Err(e));
                    let remaining = count - results.len();
                    // エラー後は後続のステートメントはサーバーで実行されない。
                    // ReadyForQuery まで読み飛ばす。
                    match self.finish_previous_result() {
                        Ok(()) => return Ok(finish_batch_after_error(results, remaining)),
                        Err(Error::NeedMoreData) => {
                            self.pending_batch =
                                Some(BatchReadProgress::AfterError { results, remaining });
                            return Err(Error::NeedMoreData);
                        }
                        Err(e2) => return Err(e2),
                    }
                }
            }
        }
        Ok(results)
    }

    /// 結果セットを読み込む。
    ///
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    /// 呼び出し側はさらにデータを供給してから再度呼び出すことで読み込みを再開できる。
    pub fn read_query_result(&mut self, unbuffered: bool) -> Result<i64> {
        self.read_query_result_inner(unbuffered, false)
    }

    /// 結果セットを読み込む。
    ///
    /// `stop_at_command_complete` が true の場合はコマンド完了で完了し、
    /// ReadyForQuery は待たない。バッチクエリの途中のステートメントで使う。
    fn read_query_result_inner(
        &mut self,
        unbuffered: bool,
        stop_at_command_complete: bool,
    ) -> Result<i64> {
        let mut result = self
            .result
            .take()
            .filter(|r| !r.is_done())
            .unwrap_or_default();
        if result.is_initial() {
            result.unbuffered_active = unbuffered;
            result.stop_at_command_complete = stop_at_command_complete;
            result.custom_decoders = self.custom_decoders.clone();
        }
        loop {
            let packet = match self.read_query_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) => continue,
                Err(e) => {
                    self.result = Some(result);
                    return Err(e);
                }
            };
            match result.feed_packet(packet) {
                Ok(FeedResult::NeedMore) => continue,
                Ok(FeedResult::Done) => {
                    // 複数結果セットの場合は最初の結果セットを現在に戻す。
                    result.rewind_to_first_rowset();
                    let affected_rows = result.affected_rows;
                    self.transaction_status =
                        result.transaction_status.unwrap_or(self.transaction_status);
                    self.result = Some(result);
                    return Ok(affected_rows);
                }
                Ok(FeedResult::UnbufferedReady) => {
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
    pub fn finish_previous_result(&mut self) -> Result<()> {
        if let Some(mut result) = self.result.take() {
            let finish = (|| {
                if result.unbuffered_active {
                    result.finish_unbuffered(self)?;
                }
                while !result.is_done() {
                    let packet = match self.read_query_packet()? {
                        Some(packet) => packet,
                        None => continue,
                    };
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

    /// クエリ処理中の非同期メッセージ (通知・NOTICE・パラメータステータス) を処理する。
    fn handle_async_message(&mut self, packet: PostgresPacket) -> Result<()> {
        match packet.message_type {
            backend::NOTIFICATION_RESPONSE => {
                let notification = NotificationResponse::parse(&packet)?;
                tracing::debug!(
                    channel = %notification.channel,
                    payload = %notification.payload,
                    "Notification received"
                );
                self.notifications.push_back(Notification {
                    process_id: notification.process_id,
                    channel: notification.channel,
                    payload: notification.payload,
                });
            }
            backend::NOTICE_RESPONSE => {
                let notice = NoticeResponse::parse(&packet)?;
                tracing::debug!(
                    severity = %notice.severity,
                    code = %notice.code,
                    message = %notice.message,
                    "Notice received"
                );
                self.notices.push_back(notice);
            }
            backend::PARAMETER_STATUS => {
                let status = ParameterStatus::parse(&packet)?;
                self.server_parameters.insert(status.name, status.value);
            }
            _ => {
                return Err(Error::internal(format!(
                    "Unexpected message type in handle_async_message: {}",
                    packet.message_type as char
                )));
            }
        }
        Ok(())
    }

    /// サーバーへの疎通を確認する。
    ///
    /// 空のクエリを送信してサーバーの応答を確認する。
    pub fn ping(&mut self) -> Result<i64> {
        self.query("", false)
    }

    /// CopyIn を開始するためのクエリを送信キューに追加する。
    ///
    /// `COPY ... FROM STDIN` 形式の SQL を送信する。
    /// サーバーの応答は `read_copy_in_response` で受け取る。
    pub fn send_copy_in(&mut self, sql: &str) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        tracing::debug!(sql = %sql, "Sending CopyIn query");
        let message = crate::protocol::query_message(sql);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// CopyIn の開始応答を読み込む。
    ///
    /// サーバーが CopyIn を受け付けた場合は `CopyResponse` を返し、
    /// それ以外の応答 (エラー等) の場合はエラーを返す。
    pub fn read_copy_in_response(&mut self) -> Result<CopyResponse> {
        loop {
            let packet = self.read_packet()?;
            match packet.message_type {
                backend::COPY_IN_RESPONSE => {
                    let response = CopyResponse::parse_in(&packet)?;
                    self.copy_phase = CopyPhase::In;
                    tracing::debug!(overall_format = response.overall_format, "CopyIn started");
                    return Ok(response);
                }
                backend::ERROR_RESPONSE => {
                    let response = ErrorResponse::parse(&packet)?;
                    return Err(crate::error::from_error_response(&response));
                }
                backend::NOTIFICATION_RESPONSE
                | backend::NOTICE_RESPONSE
                | backend::PARAMETER_STATUS => {
                    self.handle_async_message(packet)?;
                    continue;
                }
                // COPY 文ではないクエリの場合はコマンド完了後に
                // ReadyForQuery が送られる。
                backend::COMMAND_COMPLETE => continue,
                backend::READY_FOR_QUERY => {
                    let ready = ReadyForQuery::parse(&packet)?;
                    self.transaction_status = ready.transaction_status;
                    return Err(Error::interface("CopyIn was not started by the server"));
                }
                _ => {
                    return Err(Error::internal(format!(
                        "Unexpected message during CopyIn response: '{}' (0x{:02x})",
                        packet.message_type as char, packet.message_type
                    )));
                }
            }
        }
    }

    /// CopyIn 中のデータを送信キューに追加する。
    ///
    /// データは COPY の行データで、改行区切りのテキストまたは
    /// バイナリ形式の行を含む。
    pub fn send_copy_data(&mut self, data: &[u8]) -> Result<()> {
        if self.copy_phase != CopyPhase::In {
            return Err(Error::interface("CopyData can only be sent during CopyIn"));
        }
        let message = crate::protocol::copy_data_message(data);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// CopyIn の完了を送信キューに追加する。
    ///
    /// データの送信が完了したら呼び出す。その後、
    /// `finish_copy_in` で結果を読み込む。
    pub fn send_copy_done(&mut self) -> Result<()> {
        if self.copy_phase != CopyPhase::In {
            return Err(Error::interface("CopyDone can only be sent during CopyIn"));
        }
        let message = crate::protocol::copy_done_message();
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// CopyIn の失敗を送信キューに追加する。
    ///
    /// エラーで COPY を中断する場合に呼び出す。サーバーは
    /// エラー応答を返し、接続は正常な状態に戻る。
    pub fn send_copy_fail(&mut self, message: &str) -> Result<()> {
        if self.copy_phase != CopyPhase::In {
            return Err(Error::interface("CopyFail can only be sent during CopyIn"));
        }
        let message = crate::protocol::copy_fail_message(message);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// CopyIn の結果を読み込む。
    ///
    /// `send_copy_done` の後に呼び出す。影響を受けた行数を返す。
    /// データのエラーで COPY が中断された場合はエラーを返す。
    pub fn finish_copy_in(&mut self) -> Result<i64> {
        self.copy_phase = CopyPhase::None;
        self.read_query_result(false)
    }

    /// CopyOut を開始するためのクエリを送信キューに追加する。
    ///
    /// `COPY ... TO STDOUT` 形式の SQL を送信する。
    /// サーバーの応答は `read_copy_out_response` で受け取る。
    pub fn send_copy_out(&mut self, sql: &str) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        tracing::debug!(sql = %sql, "Sending CopyOut query");
        let message = crate::protocol::query_message(sql);
        self.packet_stream.write_message(&message);
        Ok(())
    }

    /// CopyOut の開始応答を読み込む。
    ///
    /// サーバーが CopyOut を受け付けた場合は `CopyResponse` を返し、
    /// それ以外の応答 (エラー等) の場合はエラーを返す。
    pub fn read_copy_out_response(&mut self) -> Result<CopyResponse> {
        loop {
            let packet = self.read_packet()?;
            match packet.message_type {
                backend::COPY_OUT_RESPONSE => {
                    let response = CopyResponse::parse_out(&packet)?;
                    self.copy_phase = CopyPhase::Out;
                    tracing::debug!(overall_format = response.overall_format, "CopyOut started");
                    return Ok(response);
                }
                backend::ERROR_RESPONSE => {
                    let response = ErrorResponse::parse(&packet)?;
                    return Err(crate::error::from_error_response(&response));
                }
                backend::NOTIFICATION_RESPONSE
                | backend::NOTICE_RESPONSE
                | backend::PARAMETER_STATUS => {
                    self.handle_async_message(packet)?;
                    continue;
                }
                backend::COMMAND_COMPLETE => continue,
                backend::READY_FOR_QUERY => {
                    let ready = ReadyForQuery::parse(&packet)?;
                    self.transaction_status = ready.transaction_status;
                    return Err(Error::interface("CopyOut was not started by the server"));
                }
                _ => {
                    return Err(Error::internal(format!(
                        "Unexpected message during CopyOut response: '{}' (0x{:02x})",
                        packet.message_type as char, packet.message_type
                    )));
                }
            }
        }
    }

    /// CopyOut 中のデータを一つ読み込む。
    ///
    /// データが 1 つ届くたびに `Some(data)` を返し、
    /// CopyOut の終了時に `None` を返す。
    pub fn read_copy_out_data(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let packet = self.read_packet()?;
            match packet.message_type {
                backend::COPY_DATA => {
                    return Ok(Some(packet.data));
                }
                backend::COPY_DONE => {
                    tracing::debug!("CopyOut finished");
                    return Ok(None);
                }
                backend::ERROR_RESPONSE => {
                    let response = ErrorResponse::parse(&packet)?;
                    return Err(crate::error::from_error_response(&response));
                }
                backend::NOTIFICATION_RESPONSE
                | backend::NOTICE_RESPONSE
                | backend::PARAMETER_STATUS => {
                    self.handle_async_message(packet)?;
                    continue;
                }
                _ => {
                    return Err(Error::internal(format!(
                        "Unexpected message during CopyOut data: '{}' (0x{:02x})",
                        packet.message_type as char, packet.message_type
                    )));
                }
            }
        }
    }

    /// CopyOut の結果を読み込む。
    ///
    /// `read_copy_out_data` が `None` を返した後に呼び出す。
    /// 影響を受けた行数を返す。
    pub fn finish_copy_out(&mut self) -> Result<i64> {
        self.copy_phase = CopyPhase::None;
        self.read_query_result(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// conninfo 形式の接続文字列のパースを検証する。
    #[test]
    fn test_from_conninfo() {
        let options = ConnectOptions::from_conninfo(
            "host=db.example.com port=5433 dbname=mydb user=alice password='pa ss' sslmode=require connect_timeout=30 application_name='my app'",
        )
        .expect("パースに成功しました");
        assert_eq!(options.host, "db.example.com");
        assert_eq!(options.port, 5433);
        assert_eq!(options.database.as_deref(), Some("mydb"));
        assert_eq!(options.user, "alice");
        assert_eq!(options.password, b"pa ss");
        assert_eq!(options.ssl_mode, SslMode::Required);
        assert_eq!(options.connect_timeout, Duration::from_secs(30));
        assert_eq!(options.application_name.as_deref(), Some("my app"));
    }

    /// conninfo 形式の引用符のエスケープを検証する。
    #[test]
    fn test_from_conninfo_quotes() {
        // バックスラッシュエスケープと '' による引用符の表現。
        // libpq と同じく、引用符内のバックスラッシュは次の文字を
        // エスケープするため、Windows のパスはそのままでは使えない。
        let options = ConnectOptions::from_conninfo(
            "user=alice password='it''s ok' sslrootcert='/etc/ssl/certs/ca.pem'",
        )
        .expect("パースに成功しました");
        assert_eq!(options.password, b"it's ok");
        assert_eq!(options.ssl_ca.as_deref(), Some("/etc/ssl/certs/ca.pem"));
    }

    /// conninfo 形式で sslmode の全バリアントを検証する。
    #[test]
    fn test_from_conninfo_sslmode() {
        for (mode, expected) in [
            ("disable", SslMode::Disabled),
            ("allow", SslMode::Allow),
            ("prefer", SslMode::Preferred),
            ("require", SslMode::Required),
            ("verify-ca", SslMode::VerifyCa),
            ("verify-full", SslMode::VerifyFull),
        ] {
            let options = ConnectOptions::from_conninfo(&format!("sslmode={}", mode))
                .expect("パースに成功しました");
            assert_eq!(
                options.ssl_mode, expected,
                "sslmode={} が一致しません",
                mode
            );
        }
    }

    /// conninfo 形式で不正な入力がエラーになることを検証する。
    #[test]
    fn test_from_conninfo_invalid() {
        // 引用符が閉じられていない。
        assert!(ConnectOptions::from_conninfo("password='abc").is_err());
        // キーに対応する = がない。
        assert!(ConnectOptions::from_conninfo("host").is_err());
        // ポートが数値でない。
        assert!(ConnectOptions::from_conninfo("port=abc").is_err());
        // sslmode が不正。
        assert!(ConnectOptions::from_conninfo("sslmode=unknown").is_err());
    }

    /// postgres:// URL のパースを検証する。
    #[test]
    fn test_from_url() {
        let options = ConnectOptions::from_url(
            "postgres://alice:secret@db.example.com:5433/mydb?sslmode=verify-full&application_name=myapp",
        )
        .expect("パースに成功しました");
        assert_eq!(options.user, "alice");
        assert_eq!(options.password, b"secret");
        assert_eq!(options.host, "db.example.com");
        assert_eq!(options.port, 5433);
        assert_eq!(options.database.as_deref(), Some("mydb"));
        assert_eq!(options.ssl_mode, SslMode::VerifyFull);
        assert_eq!(options.application_name.as_deref(), Some("myapp"));
    }

    /// postgres:// URL の省略形と IPv6 を検証する。
    #[test]
    fn test_from_url_short_forms() {
        // パスワードなし・ポートなし・データベースなし。
        let options = ConnectOptions::from_url("postgres://alice@db.example.com")
            .expect("パースに成功しました");
        assert_eq!(options.user, "alice");
        assert_eq!(options.host, "db.example.com");
        assert_eq!(options.port, DEFAULT_PORT);
        assert_eq!(options.database, None);

        // IPv6 アドレスは [::1]:5432 の形式。
        let options = ConnectOptions::from_url("postgres://alice@[::1]:5432/db")
            .expect("パースに成功しました");
        assert_eq!(options.host, "::1");
        assert_eq!(options.port, 5432);
        assert_eq!(options.database.as_deref(), Some("db"));

        // postgresql:// 接頭辞も使える。
        let options = ConnectOptions::from_url("postgresql://alice@db.example.com")
            .expect("パースに成功しました");
        assert_eq!(options.host, "db.example.com");
    }

    /// postgres:// URL のパーセントエンコーディングを検証する。
    #[test]
    fn test_from_url_percent_encoding() {
        let options = ConnectOptions::from_url(
            "postgres://a%40b:p%40ss@db.example.com/my%20db?application_name=my%20app",
        )
        .expect("パースに成功しました");
        assert_eq!(options.user, "a@b");
        assert_eq!(options.password, b"p@ss");
        assert_eq!(options.database.as_deref(), Some("my db"));
        assert_eq!(options.application_name.as_deref(), Some("my app"));
    }

    /// postgres:// URL で Unix ドメインソケットのディレクトリを指定できることを検証する。
    #[test]
    fn test_from_url_unix_socket() {
        let options = ConnectOptions::from_url("postgres:///mydb?host=/var/run/postgresql")
            .expect("パースに成功しました");
        assert_eq!(options.host, "/var/run/postgresql");
        assert_eq!(options.database.as_deref(), Some("mydb"));
    }

    /// postgres:// URL の不正な入力を検証する。
    #[test]
    fn test_from_url_invalid() {
        // postgres:// で始まらない。
        assert!(ConnectOptions::from_url("http://example.com").is_err());
        // ポートが数値でない。
        assert!(ConnectOptions::from_url("postgres://host:abc/db").is_err());
        // 不正なパーセントエンコーディング。
        assert!(ConnectOptions::from_url("postgres://%zz@host/db").is_err());
    }
}
