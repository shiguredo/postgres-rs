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
use crate::constants::{backend, transaction_status};
use crate::converters::{Converter, Value};
use crate::error::{Error, Result};
use crate::protocol::{
    CopyResponse, ErrorResponse, FieldDescription, NoticeResponse, NotificationResponse,
    ParameterStatus, PostgresPacket, ReadyForQuery,
};
use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
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
#[derive(Clone)]
pub struct ConnectOptions {
    /// 接続先のホスト名または Unix ドメインソケットのディレクトリパス。
    pub host: String,
    /// 接続先のポート番号。
    pub port: u16,
    /// 認証に使うユーザー名。
    pub user: String,
    /// 認証に使うパスワードのバイト列。
    pub password: Vec<u8>,
    /// 接続するデータベース名。`None` の場合はユーザー名と同じ名前のデータベースを使う。
    pub database: Option<String>,
    /// 接続時にサーバーへ通知するアプリケーション名。
    pub application_name: Option<String>,
    /// 接続確立のタイムアウト。
    pub connect_timeout: Duration,
    /// SSL 接続モード。
    pub ssl_mode: SslMode,
    /// TCP キープアライブを使うかどうか。既定は `true`。
    ///
    /// Unix ドメインソケットの接続には関係しない。`false` の場合は
    /// `keepalives_idle`、`keepalives_interval`、`keepalives_count` を指定できない。
    pub keepalives: bool,
    /// 無通信の状態が続いてからキープアライブを送り始めるまでの時間。
    ///
    /// `None` の場合は OS の既定値を使う。1 秒以上の秒単位で指定する。
    /// Unix ドメインソケットの接続では指定できない。
    pub keepalives_idle: Option<Duration>,
    /// 応答のないキープアライブを再送するまでの間隔。
    ///
    /// `None` の場合は OS の既定値を使う。1 秒以上の秒単位で指定する。
    /// Unix ドメインソケットの接続では指定できない。
    pub keepalives_interval: Option<Duration>,
    /// 接続が切れたと判断するまでに失ってよいキープアライブの数。
    ///
    /// `None` の場合は OS の既定値を使う。1 以上を指定する。
    /// Unix ドメインソケットの接続では指定できない。
    pub keepalives_count: Option<u32>,
    /// 送信したデータの確認応答を待つ時間の上限 (`TCP_USER_TIMEOUT`)。
    ///
    /// 超えると接続を閉じる。`None` の場合は OS の既定値を使う。
    /// 1 ミリ秒以上のミリ秒単位で指定する。Linux と Android でだけ使え、
    /// ほかの OS や Unix ドメインソケットの接続では接続時にエラーになる。
    pub tcp_user_timeout: Option<Duration>,
    /// 開発用。`sslmode=disable` でローカル以外の TCP 接続を明示的に許可する。
    ///
    /// 通信は保護されない。平文パスワードと OAuth トークンはこの経路では送信しない。
    pub allow_insecure_remote: bool,
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
    /// 起動時にサーバーへ送るコマンドラインオプション (libpq の `options`)。
    ///
    /// `-c search_path=app -c statement_timeout=5s` のように、サーバーの設定を
    /// `-c 名前=値` の形で並べる。値はそのままサーバーへ送り、空文字列は送らない。
    /// サーバーはこの値を [`ConnectOptions::runtime_params`] より先に処理するため、
    /// 同じ設定を両方で指定した場合は `runtime_params` の値が残る。
    /// `client_encoding` と `DateStyle` は固定値を送るため、ここで変えても反映されない。
    pub options: Option<String>,
    /// 起動時にサーバーへ送る追加のパラメーター。
    ///
    /// `search_path`、`statement_timeout`、`TimeZone` などの設定を
    /// 接続確立時に指定する。`user`、`database`、`application_name`、
    /// `client_encoding`、`DateStyle`、`options`、`replication` は
    /// 専用の設定か固定値があるため指定できない。
    /// `_pq_.` で始まる名前はプロトコル拡張のために予約されているため指定できない。
    /// 名前は重複を許さず、大文字と小文字を区別しない。
    pub runtime_params: Vec<(String, String)>,
    /// 受信を許可する 1 メッセージの最大サイズ (バイト)。
    pub max_message_size: usize,
    /// 上位の接続が保持するプリペアドステートメントキャッシュの上限。
    ///
    /// `0` の場合はキャッシュを使わず、無名ステートメントで実行する。
    pub statement_cache_capacity: usize,
}

impl std::fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 設定にはパスワードと OAuth トークンが含まれるため、ログに出せる項目を限定する。
        f.debug_struct("ConnectOptions")
            .field("port", &self.port)
            .field("connect_timeout", &self.connect_timeout)
            .field("ssl_mode", &self.ssl_mode)
            .field("allow_insecure_remote", &self.allow_insecure_remote)
            .field("keepalives", &self.keepalives)
            .field("keepalives_idle", &self.keepalives_idle)
            .field("keepalives_interval", &self.keepalives_interval)
            .field("keepalives_count", &self.keepalives_count)
            .field("tcp_user_timeout", &self.tcp_user_timeout)
            .field("max_message_size", &self.max_message_size)
            .field("statement_cache_capacity", &self.statement_cache_capacity)
            .field("runtime_param_count", &self.runtime_params.len())
            .finish_non_exhaustive()
    }
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
            options: None,
            connect_timeout: Duration::from_secs(10),
            ssl_mode: SslMode::VerifyFull,
            keepalives: true,
            keepalives_idle: None,
            keepalives_interval: None,
            keepalives_count: None,
            tcp_user_timeout: None,
            allow_insecure_remote: false,
            ssl_ca: None,
            ssl_cert: None,
            ssl_key: None,
            oauth_token: None,
            runtime_params: Vec::new(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            statement_cache_capacity: 128,
        }
    }
}

impl ConnectOptions {
    /// DNS やネットワークを経由しない開発接続かどうか。
    fn is_local_endpoint(&self) -> bool {
        self.host.starts_with('/')
            || self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// TCP キープアライブと `tcp_user_timeout` の設定を検証する。
    ///
    /// libpq は Unix ドメインソケットや `keepalives=0` のときに調整値を黙って無視するが、
    /// 指定が効かない組み合わせは誤りとしてエラーにする。値はソケットオプションに
    /// 渡す単位 (秒またはミリ秒) の整数で、C の `int` に収まる範囲に限る。
    fn validate_tcp_settings(&self) -> Result<()> {
        let tuned = self.keepalives_idle.is_some()
            || self.keepalives_interval.is_some()
            || self.keepalives_count.is_some();
        if self.host.starts_with('/') && (tuned || self.tcp_user_timeout.is_some()) {
            return Err(Error::interface(
                "TCP keepalive and tcp_user_timeout settings cannot be used with Unix domain sockets",
            ));
        }
        if !self.keepalives && tuned {
            return Err(Error::interface(
                "keepalives_idle, keepalives_interval and keepalives_count require keepalives",
            ));
        }
        let max = u64::from(i32::MAX.unsigned_abs());
        for (name, value) in [
            ("keepalives_idle", self.keepalives_idle),
            ("keepalives_interval", self.keepalives_interval),
        ] {
            if let Some(value) = value
                && (value.subsec_nanos() != 0 || value.as_secs() == 0 || value.as_secs() > max)
            {
                return Err(Error::interface(format!(
                    "{name} must be a whole number of seconds between 1 and {max}"
                )));
            }
        }
        if let Some(count) = self.keepalives_count
            && (count == 0 || u64::from(count) > max)
        {
            return Err(Error::interface(format!(
                "keepalives_count must be between 1 and {max}"
            )));
        }
        if let Some(timeout) = self.tcp_user_timeout
            && (timeout.subsec_nanos() % 1_000_000 != 0
                || timeout.as_millis() == 0
                || timeout.as_millis() > u128::from(max))
        {
            return Err(Error::interface(format!(
                "tcp_user_timeout must be a whole number of milliseconds between 1 and {max}"
            )));
        }
        Ok(())
    }

    /// 起動時に送る追加パラメーターを検証する。
    ///
    /// 名前は空でなく、専用の設定や固定値を持つキーと重複してはならない。
    /// プロトコル拡張のために予約された `_pq_.` で始まる名前も受け付けない。
    /// 同じ名前が複数回指定された場合もエラーにする。
    fn validate_runtime_params(&self) -> Result<()> {
        const RESERVED: [&str; 7] = [
            "user",
            "database",
            "application_name",
            "client_encoding",
            "datestyle",
            "options",
            "replication",
        ];
        let mut seen = std::collections::HashSet::new();
        for (name, _) in &self.runtime_params {
            if name.is_empty() {
                return Err(Error::interface("Runtime parameter name must not be empty"));
            }
            // PostgreSQL 19 公式文書 §53.1.5 Protocol Extensions のとおり、`_pq_.` で始まる
            // 名前は起動パラメーターではなくプロトコル拡張の要求になる。サーバーは未対応の拡張を
            // NegotiateProtocolVersion で拒否するが、この実装は拡張を要求しないため、その応答を
            // 受け付けない。判定は src/backend/tcop/backend_startup.c の ProcessStartupPacket と
            // 同じく、大文字と小文字を区別する前方一致にする。
            // 将来の版で拡張が定義された場合は、ここを見直す。
            if name.starts_with("_pq_.") {
                return Err(Error::interface(format!(
                    "Runtime parameter `{}` is reserved for protocol extensions",
                    name
                )));
            }
            let normalized = name.to_ascii_lowercase();
            if RESERVED.contains(&normalized.as_str()) {
                return Err(Error::interface(format!(
                    "Runtime parameter `{}` is reserved",
                    name
                )));
            }
            if !seen.insert(normalized) {
                return Err(Error::interface(format!(
                    "Runtime parameter `{}` is specified more than once",
                    name
                )));
            }
        }
        Ok(())
    }

    /// libpq 形式の接続文字列から接続オプションを構築する。
    ///
    /// 形式は `key=value` のペアを空白区切りで並べたもの。
    /// 値は単一引用符で囲むことができ、引用符内では
    /// バックスラッシュによるエスケープと `''` による引用符の表現が使える。
    ///
    /// 対応するキー:
    /// `host` / `port` / `dbname` / `database` / `user` / `password` /
    /// `application_name` / `connect_timeout` (秒) / `sslmode` /
    /// `sslrootcert` / `sslcert` / `sslkey` / `allow_insecure_remote` (`true` または `false`) /
    /// `keepalives` (0 は無効、それ以外は有効) / `keepalives_idle` (秒) /
    /// `keepalives_interval` (秒) / `keepalives_count` / `tcp_user_timeout` (ミリ秒)。
    /// キープアライブの調整値と `tcp_user_timeout` の 0 は OS の既定値を表す。
    /// 未対応のキーは黙って無視せずエラーにする。
    /// `options` (起動時のコマンドラインオプション) も指定できる。
    /// 追加の起動パラメーター ([`ConnectOptions::runtime_params`]) は
    /// 接続文字列では指定できない。API から設定するか、`options` に `-c` で指定する。
    pub fn from_conninfo(conninfo: &str) -> Result<Self> {
        let mut options = Self::default();
        for (key, value) in parse_conninfo(conninfo)? {
            options.set_option(&key, value, OptionSource::ConnInfo)?;
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
            .ok_or_else(|| Error::interface("Invalid PostgreSQL URL scheme"))?;

        // ユーザー情報の区切りは authority の中だけで解釈する。
        let (authority, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
        let (userinfo, authority) = match authority.split_once('@') {
            Some((userinfo, authority)) => (Some(userinfo), authority),
            None => (None, authority),
        };
        let tail = tail.strip_prefix('/').unwrap_or(tail);
        let (path, query) = match tail.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (tail, None),
        };

        let mut options = Self::default();
        if let Some(userinfo) = userinfo {
            let (user, password) = match userinfo.split_once(':') {
                Some((user, password)) => (user, Some(password)),
                None => (userinfo, None),
            };
            options.user = percent_decode(user)?;
            if let Some(password) = password {
                options.password = percent_decode(password)?.into_bytes();
            }
        }
        if !authority.is_empty() {
            let (host, port) = parse_url_authority(authority)?;
            if let Some(host) = host {
                options.host = percent_decode(&host)?;
            }
            if let Some(port) = port {
                options.port = port;
            }
        }
        if !path.is_empty() {
            options.database = Some(percent_decode(path)?);
        }
        if let Some(query) = query {
            for (key, value) in parse_url_query(query)? {
                options.set_option(&key, value, OptionSource::Url)?;
            }
        }
        Ok(options)
    }

    /// 接続文字列または URL のクエリ文字列で指定された 1 つのキーを設定する。
    ///
    /// 2 つの形式で受け付けるキーと値の解釈をそろえるため、ここにまとめる。
    /// 未対応のキーは黙って無視せずエラーにする。
    fn set_option(&mut self, key: &str, value: String, source: OptionSource) -> Result<()> {
        match key {
            "host" => self.host = value,
            "port" => {
                self.port = value
                    .parse()
                    .map_err(|_| Error::interface(format!("Invalid port in {}", source.name())))?
            }
            "dbname" | "database" => self.database = Some(value),
            "user" => self.user = value,
            "password" => self.password = value.into_bytes(),
            "application_name" => self.application_name = Some(value),
            "options" => self.options = Some(value),
            "connect_timeout" => {
                let seconds: u64 = value.parse().map_err(|_| {
                    Error::interface(format!("Invalid connect_timeout in {}", source.name()))
                })?;
                self.connect_timeout = Duration::from_secs(seconds);
            }
            "sslmode" => self.ssl_mode = SslMode::from_str(&value)?,
            "allow_insecure_remote" => {
                self.allow_insecure_remote = value
                    .parse()
                    .map_err(|_| Error::interface("allow_insecure_remote must be true or false"))?
            }
            "sslrootcert" => self.ssl_ca = Some(value),
            "sslcert" => self.ssl_cert = Some(value),
            "sslkey" => self.ssl_key = Some(value),
            // PostgreSQL 19 文書 §31.1.2 Parameter Key Words のとおり、keepalives は整数で
            // 0 以外を有効とし、ほかの 4 つは 0 を OS の既定値として扱う。単位は
            // keepalives_idle と keepalives_interval が秒、tcp_user_timeout がミリ秒。
            // libpq は負の値を 0 と同じに扱うが、ここでは指定の誤りとしてエラーにする。
            // 将来 libpq の解釈が変わった場合はここを見直す。
            "keepalives" => {
                let value: i32 = value.parse().map_err(|_| {
                    Error::interface(format!("Invalid keepalives in {}", source.name()))
                })?;
                self.keepalives = value != 0;
            }
            "keepalives_idle" => {
                self.keepalives_idle = parse_tcp_setting(key, &value, source)?
                    .map(|seconds| Duration::from_secs(u64::from(seconds)))
            }
            "keepalives_interval" => {
                self.keepalives_interval = parse_tcp_setting(key, &value, source)?
                    .map(|seconds| Duration::from_secs(u64::from(seconds)))
            }
            "keepalives_count" => self.keepalives_count = parse_tcp_setting(key, &value, source)?,
            "tcp_user_timeout" => {
                self.tcp_user_timeout = parse_tcp_setting(key, &value, source)?
                    .map(|millis| Duration::from_millis(u64::from(millis)))
            }
            _ => return Err(Error::interface(source.unsupported_message())),
        }
        Ok(())
    }
}

/// TCP の設定値 (0 以上の整数) を解釈する。0 は OS の既定値を表す `None` にする。
///
/// 値の範囲は libpq と同じく C の `int` に収まる範囲とする。
fn parse_tcp_setting(key: &str, value: &str, source: OptionSource) -> Result<Option<u32>> {
    let value: i32 = value
        .parse()
        .ok()
        .filter(|value| *value >= 0)
        .ok_or_else(|| Error::interface(format!("Invalid {key} in {}", source.name())))?;
    Ok((value > 0).then(|| value.unsigned_abs()))
}

/// 接続オプションを指定した文字列の形式。エラーメッセージの表記を分けるために使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionSource {
    /// libpq 形式の接続文字列。
    ConnInfo,
    /// `postgres://` 形式の URL。
    Url,
}

impl OptionSource {
    /// エラーメッセージで使う形式の名前を返す。
    fn name(self) -> &'static str {
        match self {
            Self::ConnInfo => "connection string",
            Self::Url => "URL",
        }
    }

    /// 未対応のキーを指定されたときのエラーメッセージを返す。
    fn unsupported_message(self) -> &'static str {
        match self {
            Self::ConnInfo => "Unsupported connection option",
            Self::Url => "Unsupported URL connection option",
        }
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
        let key_end = i;
        // `=` の前後の空白は省略できる (libpq と同じ)。
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' || key_end == key_start {
            return Err(Error::interface("Invalid connection string"));
        }
        let key: String = chars[key_start..key_end].iter().collect();
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
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
                return Err(Error::interface("Invalid connection string"));
            }
            value
        } else {
            // 引用符なしの値でもバックスラッシュは次の文字をエスケープする。
            let mut value = String::new();
            while i < chars.len() {
                match chars[i] {
                    '\\' if i + 1 < chars.len() => {
                        value.push(chars[i + 1]);
                        i += 2;
                    }
                    '\\' => {
                        return Err(Error::interface("Invalid connection string"));
                    }
                    c if c.is_whitespace() => break,
                    c => {
                        value.push(c);
                        i += 1;
                    }
                }
            }
            value
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
            .ok_or_else(|| Error::interface("Invalid host in URL"))?;
        if !after.is_empty() && !after.starts_with(':') {
            return Err(Error::interface("Invalid host in URL"));
        }
        let port = match after.strip_prefix(':') {
            Some(port) => Some(
                port.parse()
                    .map_err(|_| Error::interface("Invalid port in URL"))?,
            ),
            None => None,
        };
        return Ok((Some(host.to_string()), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| Error::interface("Invalid port in URL"))?;
            Ok((Some(host.to_string()), Some(port)))
        }
        None => Ok((Some(authority.to_string()), None)),
    }
}

/// URL のクエリ文字列を `(キー, 値)` のペアのリストに分解する。
///
/// クエリ文字列をパーセントデコードする。
///
/// URI では `+` は空白ではなくリテラルのプラス記号として扱う。
fn parse_url_query(query: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| Error::interface("Invalid URL connection option"))?;
        pairs.push((percent_decode(key)?, percent_decode(value)?));
    }
    Ok(pairs)
}

/// パーセントエンコードされた文字列をデコードする。
fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(Error::interface("Invalid percent encoding"));
                }
                let hi = hex_value(bytes[i + 1])
                    .ok_or_else(|| Error::interface("Invalid percent encoding"))?;
                let lo = hex_value(bytes[i + 2])
                    .ok_or_else(|| Error::interface("Invalid percent encoding"))?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::interface("Invalid UTF-8 in URL"))
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

/// TLS 接続ポリシー。
///
/// TLS を使うモードでは、接続に失敗しても平文には切り替えない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// TLS を使用しない。通常は Unix ドメインソケット、`localhost` またはループバック IP に限る。
    /// ローカル以外の開発環境では `ConnectOptions::allow_insecure_remote` も明示する。
    Disabled,
    /// TLS を必須とする。CA を明示した場合は信頼チェーンを検証する。接続先の名前は検証しない。
    Required,
    /// TLS を必須とし、証明書の信頼チェーンを検証する。接続先の名前は検証しない。
    VerifyCa,
    /// 既定。TLS を必須とし、証明書の信頼チェーンと接続先のホスト名または IP アドレスを検証する。
    VerifyFull,
}

impl FromStr for SslMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "disable" => Ok(SslMode::Disabled),
            "require" => Ok(SslMode::Required),
            "verify-ca" => Ok(SslMode::VerifyCa),
            "verify-full" => Ok(SslMode::VerifyFull),
            _ => Err(Error::interface(
                "Unsupported sslmode; use disable, require, verify-ca, or verify-full",
            )),
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

/// バッチクエリの行取得の進行状態。
enum BatchRowProgress {
    /// まだ読み終わっていない結果のリスト。
    Reading(Vec<Result<QueryResult>>),
    /// エラー応答後の読み飛ばしが中断した状態。
    ///
    /// `remaining` はエラーで実行されなかったステートメントの残り数。
    AfterError {
        results: Vec<Result<QueryResult>>,
        remaining: usize,
    },
}

/// プリペアドステートメント。準備した接続でのみ実行できる。
#[derive(Debug, Clone)]
pub struct PreparedStatement {
    name: String,
    sql: String,
    parameter_oids: Vec<u32>,
    fields: Vec<FieldDescription>,
    owner: Arc<()>,
}

impl PreparedStatement {
    /// サーバー上のステートメント名を返す。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// ステートメントの SQL テキストを返す。
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// 準備時にサーバーが決めたパラメータの型 OID を返す。
    pub fn parameter_oids(&self) -> &[u32] {
        &self.parameter_oids
    }

    /// 結果のフィールド情報を返す。行を返さないステートメントでは空。
    pub fn fields(&self) -> &[FieldDescription] {
        &self.fields
    }
}

/// Close と Sync に対する応答の読み込み状態。
enum DeallocateReadProgress {
    WaitingForClose,
    WaitingForReady(Result<()>),
}

/// バッチ中の文の位置。途中の文はコマンド完了まで、最終文は同期まで読み取る。
#[derive(Debug, Clone, Copy)]
enum BatchPosition {
    Intermediate,
    Last,
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

/// エラー後に実行されなかったバッチステートメントの結果 (行付き) を埋める。
fn finish_batch_rows_after_error(remaining: usize) -> Vec<Result<QueryResult>> {
    (0..remaining)
        .map(|_| {
            Err(Error::internal(
                "Batch statement was not executed because a previous statement failed",
            ))
        })
        .collect()
}

/// 行の復号の前提を崩す ParameterStatus を拒否する。
///
/// 行の値は UTF-8、日付・時刻は ISO 形式として復号する。そのため、
/// `client_encoding` は UTF8 を、`DateStyle` は ISO の出力形式を示す値だけを受け付ける。
/// どちらも起動時に固定しているが、`SET` で接続後に変更できる。
/// 値は PostgreSQL と同じ規則で解釈する。サーバーは正規形を報告するが、
/// 接続プーラーはクライアントが起動時に送った値をそのまま報告することがある。
/// それ以外のパラメータは検査しない。
fn check_session_parameter(status: &ParameterStatus) -> Result<()> {
    // GUC 名は大文字と小文字を区別しない。
    if status.name.eq_ignore_ascii_case("client_encoding")
        && !client_encoding_is_utf8(&status.value)
    {
        return Err(Error::not_supported(format!(
            "Unsupported client_encoding reported by the server: {:?} (only UTF8 is supported)",
            status.value
        )));
    }
    if status.name.eq_ignore_ascii_case("DateStyle") && !date_style_keeps_iso(&status.value) {
        return Err(Error::not_supported(format!(
            "Unsupported DateStyle reported by the server: {:?} (only ISO output is supported)",
            status.value
        )));
    }
    Ok(())
}

/// `client_encoding` の値が UTF8 を指すか。
///
/// PostgreSQL 18 の src/common/encnames.c の pg_char_to_encoding と同じく、
/// 英数字以外を除いて小文字にした名前を別名表で引く。UTF8 になる別名は `utf8` と `unicode` だけ。
/// 将来の PostgreSQL で別名表が変わった場合は、ここを見直す。
fn client_encoding_is_utf8(value: &str) -> bool {
    // 空の名前と NAMEDATALEN (64) バイト以上の名前は解決しない。
    // ASCII 以外を含む名前は、英数字の判定がサーバーのロケールに依存するため受け付けない。
    if value.is_empty() || value.len() >= 64 || !value.is_ascii() {
        return false;
    }
    let cleaned: Vec<u8> = value
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    matches!(cleaned.as_slice(), b"utf8" | b"unicode")
}

/// `DateStyle` の出力形式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateOutputStyle {
    Iso,
    Sql,
    Postgres,
    German,
}

/// `DateStyle` の日付順序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateFieldOrder {
    Ymd,
    Dmy,
    Mdy,
}

/// `DateStyle` の値を構成する語。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateStyleWord {
    Style(DateOutputStyle),
    Order(DateFieldOrder),
}

/// `DateStyle` の値で、出力形式が ISO のまま保たれるか。
///
/// PostgreSQL 18 の src/backend/commands/variable.c の check_datestyle と同じく解釈する。
/// 出力形式の語がない値は現在の形式を保つ。ISO 以外の形式を報告された接続は閉じるため、
/// 現在の形式は ISO である。ISO 形式の出力は日付順序に依存しない
/// (src/backend/utils/adt/datetime.c の EncodeDateOnly)。
/// 語の矛盾や未知の語など PostgreSQL が拒否する値は受け付けない。
/// 引用符付きの名前と、サーバーの既定値に依存する `DEFAULT` も受け付けない。
/// 将来の PostgreSQL で語や解釈が変わった場合は、ここを見直す。
fn date_style_keeps_iso(value: &str) -> bool {
    let Some(words) = split_unquoted_list(value) else {
        return false;
    };
    let mut style = None;
    let mut order = None;
    for word in words {
        match date_style_word(word) {
            Some(DateStyleWord::Style(next)) => {
                if style.is_some_and(|current| current != next) {
                    return false;
                }
                style = Some(next);
            }
            Some(DateStyleWord::Order(next)) => {
                if order.is_some_and(|current| current != next) {
                    return false;
                }
                order = Some(next);
            }
            None => return false,
        }
    }
    style.is_none_or(|style| style == DateOutputStyle::Iso)
}

/// check_datestyle の語を判定する。比較は大文字と小文字を区別しない。
///
/// `POSTGRES`、`EURO`、`NONEURO` は前方一致で判定する。
fn date_style_word(word: &str) -> Option<DateStyleWord> {
    let starts_with = |prefix: &str| {
        word.as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    };
    let word = if word.eq_ignore_ascii_case("ISO") {
        DateStyleWord::Style(DateOutputStyle::Iso)
    } else if word.eq_ignore_ascii_case("SQL") {
        DateStyleWord::Style(DateOutputStyle::Sql)
    } else if starts_with("POSTGRES") {
        DateStyleWord::Style(DateOutputStyle::Postgres)
    } else if word.eq_ignore_ascii_case("GERMAN") {
        DateStyleWord::Style(DateOutputStyle::German)
    } else if word.eq_ignore_ascii_case("YMD") {
        DateStyleWord::Order(DateFieldOrder::Ymd)
    } else if word.eq_ignore_ascii_case("DMY") || starts_with("EURO") {
        DateStyleWord::Order(DateFieldOrder::Dmy)
    } else if word.eq_ignore_ascii_case("MDY")
        || word.eq_ignore_ascii_case("US")
        || starts_with("NONEURO")
    {
        DateStyleWord::Order(DateFieldOrder::Mdy)
    } else {
        return None;
    };
    Some(word)
}

/// カンマ区切りの名前の並びを分ける。引用符付きの名前を含む場合は `None` を返す。
///
/// PostgreSQL 18 の src/backend/utils/adt/varlena.c の SplitIdentifierString のうち、
/// 引用符のない名前の規則に従う。区切りの前後の空白は scanner_isspace の 6 種類で、
/// 空の値は名前のない並びになる。空の名前や、名前の後のカンマ以外の文字は不正とする。
/// PostgreSQL は名前を小文字にし、63 バイトに切り詰めるが、語の判定は大文字と小文字を
/// 区別せず、判定する語はいずれも 63 バイトより短いため、結果は変わらない。
fn split_unquoted_list(value: &str) -> Option<Vec<&str>> {
    let bytes = value.as_bytes();
    let is_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
    let skip_spaces = |mut index: usize| {
        while bytes.get(index).copied().is_some_and(is_space) {
            index += 1;
        }
        index
    };
    let mut words = Vec::new();
    let mut index = skip_spaces(0);
    if index == bytes.len() {
        return Some(words);
    }
    loop {
        if bytes[index] == b'"' {
            return None;
        }
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|&byte| byte != b',' && !is_space(byte))
        {
            index += 1;
        }
        if start == index {
            return None;
        }
        // 区切りは ASCII のため、切り出す位置は文字の境界になる。
        words.push(&value[start..index]);
        index = skip_spaces(index);
        match bytes.get(index) {
            None => return Some(words),
            Some(b',') => {
                index = skip_spaces(index + 1);
                if index == bytes.len() {
                    // カンマの後には名前が続く必要がある。
                    return None;
                }
            }
            Some(_) => return None,
        }
    }
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
    ready_sequence: u64,
    bind_complete_seen: bool,
    parse_complete_seen: bool,
    cancellation_error_seen: bool,
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
    /// COPY の開始要求を送信して応答を待っている状態かどうか。
    copy_pending: bool,
    /// 準備中のステートメントの名前と SQL。
    pending_prepare: Option<(String, String)>,
    /// 接続の破棄後も、残っているハンドルと新しい接続を区別する識別子。
    statement_owner: Arc<()>,
    /// 次に生成するステートメント名の番号。
    next_statement_id: u64,
    /// 破棄中のステートメントの応答状態。
    pending_deallocation: Option<DeallocateReadProgress>,
    /// 送信済みで同期を待つバッチの文数。0 は未送信または空のバッチを示す。
    batch_count: usize,
    /// バッチクエリの結果読み込みの進行状態。
    pending_batch: Option<BatchReadProgress>,
    /// 送信済みで、行付きの結果を待つバッチの文数。
    batch_row_count: usize,
    /// 行付きバッチ結果の読み込みの進行状態。
    pending_batch_rows: Option<BatchRowProgress>,
}

impl Connection {
    /// 新規接続のための内部状態を構築する。
    ///
    /// 実際の TCP/TLS 接続および認証は呼び出し側が行う。
    /// 設定の組み合わせや起動パラメーターが不正な場合は、接続する前に
    /// `Error::InterfaceError` を返す。
    pub fn connect(options: ConnectOptions) -> Result<Self> {
        for value in [
            Some(options.host.as_str()),
            Some(options.user.as_str()),
            options.database.as_deref(),
            options.application_name.as_deref(),
            options.options.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.as_bytes().contains(&0) {
                return Err(Error::interface(
                    "Connection settings must not contain NUL bytes",
                ));
            }
        }
        let unix = options.host.starts_with('/');
        if unix && options.ssl_mode != SslMode::Disabled {
            return Err(Error::interface(
                "Unix domain sockets require sslmode=disable",
            ));
        }
        if options.ssl_mode == SslMode::Disabled {
            if !options.is_local_endpoint() && !options.allow_insecure_remote {
                return Err(Error::interface(
                    "Unencrypted remote TCP requires allow_insecure_remote=true",
                ));
            }
            if options.ssl_ca.is_some() || options.ssl_cert.is_some() || options.ssl_key.is_some() {
                return Err(Error::interface(
                    "TLS certificate settings cannot be used with sslmode=disable",
                ));
            }
        } else if options.allow_insecure_remote {
            return Err(Error::interface(
                "allow_insecure_remote requires sslmode=disable",
            ));
        }
        options.validate_tcp_settings()?;
        if options.oauth_token.is_some() && options.ssl_mode != SslMode::VerifyFull {
            return Err(Error::interface("OAuth requires sslmode=verify-full"));
        }
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
        // 予約済みや重複した起動パラメーターは、サーバーへ接続する前に拒否する。
        options.validate_runtime_params()?;

        Ok(Self {
            packet_stream: PacketStream::new(options.max_message_size),
            options,
            auth_phase: AuthPhase::NotStarted,
            scram: None,
            server_parameters: HashMap::new(),
            backend_process_id: 0,
            backend_secret_key: 0,
            transaction_status: 0,
            ready_sequence: 0,
            bind_complete_seen: false,
            parse_complete_seen: false,
            cancellation_error_seen: false,
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
            copy_pending: false,
            pending_prepare: None,
            statement_owner: Arc::new(()),
            next_statement_id: 0,
            pending_deallocation: None,
            batch_count: 0,
            pending_batch: None,
            batch_row_count: 0,
            pending_batch_rows: None,
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

    /// 入出力層が設定した `SslMode` の検証条件を満たす TLS 接続を確立したことを通知する。
    ///
    /// Sans I/O 層は実際のソケットを検証できない。`VerifyFull` を指定した場合は、
    /// 信頼チェーンと接続先の名前の両方を検証した後にのみ `true` を渡す。
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

    /// 接続をそのまま再利用できない状態かどうか。
    ///
    /// アンバッファード結果の読み取り中、COPY の処理中、バッチの実行中、
    /// プリペアドステートメントの準備または破棄中に true を返す。
    pub fn is_busy(&self) -> bool {
        self.copy_phase != CopyPhase::None
            || self.copy_pending
            || self.batch_count != 0
            || self.pending_prepare.is_some()
            || self.pending_deallocation.is_some()
            || self
                .result
                .as_ref()
                .is_some_and(|result| result.unbuffered_active)
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
    ///
    /// 読み込み途中の結果も破棄する。閉じた接続では応答を読み飛ばして回収できず、
    /// 途中まで読んだ行の正しさも保証できないため。
    pub fn force_close(&mut self) {
        self.packet_stream.force_close();
        self.batch_count = 0;
        self.pending_batch = None;
        self.result = None;
        self.closed = true;
    }

    /// 送信キューから先頭のメッセージを取り出す。
    pub fn pop_send_queue(&mut self) -> Option<Vec<u8>> {
        self.packet_stream.send_queue.pop_front()
    }

    /// 受信した生バイト列を消費してメッセージを組み立て、recv_queue に追加する。
    pub fn feed_bytes(&mut self, data: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        // SSL 応答の後で TLS の検証済み Startup を送るまでは、通常フレームを受け付けない。
        // 同じ読み取りに混ざったデータは PacketStream が拒否する。ここでは別々の読み取りも拒否する。
        if !data.is_empty()
            && (self.needs_tls_upgrade
                || (self.tls_requested && !self.packet_stream.is_tls_response_pending()))
        {
            self.force_close();
            return Err(Error::internal("Unexpected data before TLS startup"));
        }
        match self.packet_stream.feed_bytes(data) {
            Ok(added) => Ok(added),
            Err(error) => {
                self.force_close();
                Err(error)
            }
        }
    }

    /// 受信済みメッセージキューから一つ取り出す。
    ///
    /// ReadyForQuery の形式が不正な場合はエラーを返し、同期済みとはみなさない。
    /// 閉じた接続ではデータを供給できないため、`Error::NeedMoreData` ではなく
    /// `Error::InterfaceError` を返す。
    pub fn read_packet(&mut self) -> Result<PostgresPacket> {
        let packet = self.read_open_packet()?;
        self.record_packet(packet)
    }

    /// 開いている接続の受信キューから一つ取り出す。
    fn read_open_packet(&mut self) -> Result<PostgresPacket> {
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        self.packet_stream.read_packet()
    }

    /// 受信したフレームの形式を確認し、同期と文の進行を記録する。
    fn record_packet(&mut self, packet: PostgresPacket) -> Result<PostgresPacket> {
        match packet.message_type {
            backend::READY_FOR_QUERY => {
                // PostgreSQL 18 公式文書 §54.7 の状態だけを受け付ける。
                // 将来プロトコルに状態が追加された場合はここで対応する。
                let ready = ReadyForQuery::parse(&packet)?;
                match ready.transaction_status {
                    transaction_status::IDLE
                    | transaction_status::IN_TRANSACTION
                    | transaction_status::FAILED => {}
                    status => {
                        return Err(Error::internal(format!(
                            "Invalid ReadyForQuery transaction status: 0x{status:02x}"
                        )));
                    }
                }
                self.transaction_status = ready.transaction_status;
                self.ready_sequence = self.ready_sequence.wrapping_add(1);
            }
            backend::BIND_COMPLETE => {
                if !packet.data.is_empty() {
                    return Err(Error::internal("Invalid BindComplete payload"));
                }
                self.bind_complete_seen = true;
            }
            backend::PARSE_COMPLETE => {
                if !packet.data.is_empty() {
                    return Err(Error::internal("Invalid ParseComplete payload"));
                }
                self.parse_complete_seen = true;
            }
            backend::CLOSE_COMPLETE
            | backend::NO_DATA
            | backend::EMPTY_QUERY_RESPONSE
            | backend::COPY_DONE
                if !packet.data.is_empty() =>
            {
                return Err(Error::internal(
                    "Unexpected payload in an empty backend message",
                ));
            }
            _ => {}
        }
        Ok(packet)
    }

    /// クエリ結果読み込み用に 1 メッセージを取得する。
    ///
    /// 非同期メッセージ (通知・NOTICE・パラメータステータス) は
    /// キューに積んで `None` を返し、それ以外は `Some(packet)` を返す。
    /// 受信キューにメッセージがない場合は `Error::NeedMoreData` を返す。
    pub fn read_query_packet(&mut self) -> Result<Option<PostgresPacket>> {
        let packet = self.read_packet()?;
        self.handle_query_packet(packet)
    }

    fn handle_query_packet(&mut self, packet: PostgresPacket) -> Result<Option<PostgresPacket>> {
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

    /// 認証を含め、正常な ReadyForQuery を消費するたびに増える通し番号を返す。
    ///
    /// 初期値は `0`。受信キューに追加しただけでは増えない。
    /// オーバーフロー時は `0` に戻るため、新しい境界は値の不一致で判定する。
    pub fn ready_sequence(&self) -> u64 {
        self.ready_sequence
    }

    /// 最後の `send_execute_prepared` 以降に BindComplete を消費したかを返す。
    ///
    /// 同期のために応答を読み飛ばしても保持され、次の準備済み実行の送信時に初期化される。
    pub fn bind_complete_seen(&self) -> bool {
        self.bind_complete_seen
    }

    /// 最後の `send_prepare` 以降に ParseComplete を消費したかを返す。
    ///
    /// 同期のために応答を読み飛ばしても保持され、次のステートメント準備の送信時に初期化される。
    pub fn parse_complete_seen(&self) -> bool {
        self.parse_complete_seen
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
        crate::protocol::validate_query(sql)?;
        tracing::debug!("Sending query");
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
        self.send_execute_typed(sql, &[], parameters)
    }

    /// パラメーターの型 OID を明示してクエリのメッセージ群を送信キューに追加する。
    ///
    /// 型 OID が空の場合は PostgreSQL が SQL の文脈から型を推論する。
    /// `parameter_oids` の要素数は `parameters` の要素数と一致する必要がある。
    pub fn send_execute_typed(
        &mut self,
        sql: &str,
        parameter_oids: &[u32],
        parameters: &[crate::converters::Value],
    ) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        crate::protocol::validate_parse("", sql, parameter_oids)?;
        crate::protocol::validate_bind_parameter_count(parameters.len())?;
        if !parameter_oids.is_empty() && parameter_oids.len() != parameters.len() {
            return Err(Error::interface(format!(
                "Parameter type count mismatch: expected {}, got {}",
                parameters.len(),
                parameter_oids.len()
            )));
        }
        tracing::debug!(parameter_count = parameters.len(), "Sending statement");
        let encoded: Vec<Option<Vec<u8>>> = parameters.iter().map(|v| v.to_bytes()).collect();
        let refs: Vec<Option<&[u8]>> = encoded.iter().map(|p| p.as_deref()).collect();

        crate::protocol::validate_bind("", "", &refs)?;

        // 名前なしステートメント・名前なしポータルを使用し、
        // パース・バインド・記述・実行・同期を一括で送信する。
        let parse = crate::protocol::parse_message("", sql, parameter_oids);
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
        self.send_prepare_typed(sql, &[])
    }

    /// パラメーターの型 OID を明示してプリペアドステートメントのメッセージ群を送信する。
    ///
    /// 型 OID が空の場合は PostgreSQL が SQL の文脈から型を推論する。
    /// 型 OID を指定すると、サーバーはその型でパラメーターを解釈する。
    pub fn send_prepare_typed(&mut self, sql: &str, parameter_oids: &[u32]) -> Result<()> {
        self.finish_previous_result()?;
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        let next_statement_id = self
            .next_statement_id
            .checked_add(1)
            .ok_or_else(|| Error::internal("Prepared statement identifier exhausted"))?;
        let name = format!("stmt_{next_statement_id}");
        crate::protocol::validate_parse(&name, sql, parameter_oids)?;
        self.next_statement_id = next_statement_id;
        tracing::debug!(statement_name = %name, "Preparing statement");
        let parse = crate::protocol::parse_message(&name, sql, parameter_oids);
        let describe =
            crate::protocol::describe_message(crate::constants::describe::STATEMENT, &name);
        let sync = crate::protocol::sync_message();
        for message in [parse, describe, sync] {
            self.packet_stream.write_message(&message);
        }
        self.pending_prepare = Some((name, sql.to_string()));
        self.parse_complete_seen = false;
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
                    self.keep_result(result);
                    return Err(e);
                }
            };
            match result.feed_packet(packet) {
                Ok(FeedResult::NeedMore | FeedResult::UnbufferedReady) => continue,
                Ok(FeedResult::Done) => {
                    let (name, sql) = self.pending_prepare.take().ok_or_else(|| {
                        Error::internal("read_prepare_result called without send_prepare")
                    })?;
                    let statement = PreparedStatement {
                        name,
                        sql,
                        parameter_oids: result.parameter_oids,
                        fields: result.fields,
                        owner: Arc::clone(&self.statement_owner),
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
                    // 準備中の状態は解除し、接続を再利用できるようにする。
                    self.pending_prepare = None;
                    self.keep_result(result);
                    return Err(e);
                }
            }
        }
    }

    /// この接続自身が準備したステートメントかどうかを返す。
    ///
    /// サーバーに現在も存在するかどうかは検査しない。
    pub fn owns_statement(&self, statement: &PreparedStatement) -> bool {
        Arc::ptr_eq(&self.statement_owner, &statement.owner)
    }

    /// プリペアドステートメントを実行するためのメッセージ群を送信キューに追加する。
    ///
    /// 別の接続で準備したステートメントやパラメータ数が違う場合はエラーを返す。
    /// 検査後、前回の結果の読み残しを回収してから送信する。
    /// 結果の読み込みは `read_query_result` で行う。
    pub fn send_execute_prepared(
        &mut self,
        statement: &PreparedStatement,
        parameters: &[Value],
    ) -> Result<()> {
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        if !self.owns_statement(statement) {
            return Err(Error::interface(
                "Prepared statement belongs to another connection",
            ));
        }
        if parameters.len() != statement.parameter_oids.len() {
            return Err(Error::interface(format!(
                "Parameter count mismatch: expected {}, got {}",
                statement.parameter_oids.len(),
                parameters.len()
            )));
        }
        self.finish_previous_result()?;
        tracing::debug!(
            statement_name = %statement.name,
            parameter_count = parameters.len(),
            "Executing prepared statement"
        );
        let encoded: Vec<Option<Vec<u8>>> = parameters.iter().map(|v| v.to_bytes()).collect();
        let refs: Vec<Option<&[u8]>> = encoded.iter().map(|p| p.as_deref()).collect();

        crate::protocol::validate_bind("", &statement.name, &refs)?;
        let bind = crate::protocol::bind_message("", &statement.name, &refs);
        let describe = crate::protocol::describe_message(crate::constants::describe::PORTAL, "");
        let execute = crate::protocol::execute_message("", 0);
        let sync = crate::protocol::sync_message();
        for message in [bind, describe, execute, sync] {
            self.packet_stream.write_message(&message);
        }
        self.bind_complete_seen = false;
        Ok(())
    }

    /// 名前付きプリペアドステートメントの破棄を送信キューに追加する。
    ///
    /// 前回の結果の読み残しを回収してから Close と Sync を送信する。
    /// ステートメント名は空文字列や NUL を含む文字列を指定できない。
    /// 応答は `read_deallocate_result` で読み込む。
    pub fn send_deallocate(&mut self, name: &str) -> Result<()> {
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        if name.is_empty() {
            return Err(Error::interface("Invalid prepared statement name"));
        }
        crate::protocol::validate_close(name)?;
        self.finish_previous_result()?;
        if self.is_busy() {
            return Err(Error::interface("Connection is busy"));
        }

        // PostgreSQL 18 公式文書 §54.2.3 の Close と Sync に従う。
        // サーバーの応答仕様が将来変更された場合は読み込み側にも反映する。
        let close = crate::protocol::close_message(crate::constants::describe::STATEMENT, name);
        let sync = crate::protocol::sync_message();
        self.packet_stream.write_message(&close);
        self.packet_stream.write_message(&sync);
        self.pending_deallocation = Some(DeallocateReadProgress::WaitingForClose);
        Ok(())
    }

    /// `send_deallocate` の応答を読み込む。
    ///
    /// CloseComplete に続く ReadyForQuery まで読み込んで成功を返す。
    /// サーバーのエラー応答も、ReadyForQuery を読み込んでから返す。
    /// `Error::NeedMoreData` の場合は進行状態を保持し、データ供給後に再開できる。
    pub fn read_deallocate_result(&mut self) -> Result<()> {
        if self.pending_deallocation.is_none() {
            return Err(Error::interface(
                "No prepared statement deallocation is pending",
            ));
        }
        loop {
            let Some(packet) = self.read_query_packet()? else {
                continue;
            };
            match (packet.message_type, &self.pending_deallocation) {
                (backend::CLOSE_COMPLETE, Some(DeallocateReadProgress::WaitingForClose))
                    if packet.data.is_empty() =>
                {
                    self.pending_deallocation =
                        Some(DeallocateReadProgress::WaitingForReady(Ok(())));
                }
                (backend::ERROR_RESPONSE, _) => {
                    let response = ErrorResponse::parse(&packet)?;
                    let error = crate::error::from_error_response(&response);
                    if !matches!(
                        self.pending_deallocation,
                        Some(DeallocateReadProgress::WaitingForReady(Err(_)))
                    ) {
                        // CloseComplete の後でも、Sync の処理中にエラーが起こりうる。
                        self.pending_deallocation =
                            Some(DeallocateReadProgress::WaitingForReady(Err(error)));
                    }
                }
                (backend::READY_FOR_QUERY, _) => {
                    return match self.pending_deallocation.take() {
                        Some(DeallocateReadProgress::WaitingForReady(result)) => result,
                        _ => Err(Error::internal(
                            "Missing CloseComplete before ReadyForQuery",
                        )),
                    };
                }
                _ => {
                    return Err(Error::internal(format!(
                        "Unexpected message during statement deallocation: '{}' (0x{:02x})",
                        packet.message_type as char, packet.message_type
                    )));
                }
            }
        }
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
        if statements.is_empty() {
            // 読み込み件数が 0 の場合、対応する同期応答を発生させない。
            return Ok(());
        }
        tracing::debug!(statement_count = statements.len(), "Sending batch");
        // 後続の文が不正な場合も一件も送信しない。全件のフレームを組み立ててから移す。
        let mut messages = Vec::new();
        for (sql, parameters) in statements {
            crate::protocol::validate_parse("", sql, &[])?;
            crate::protocol::validate_bind_parameter_count(parameters.len())?;
            let encoded: Vec<Option<Vec<u8>>> = parameters.iter().map(|v| v.to_bytes()).collect();
            let refs: Vec<Option<&[u8]>> = encoded.iter().map(|p| p.as_deref()).collect();
            crate::protocol::validate_bind("", "", &refs)?;
            messages.extend([
                crate::protocol::parse_message("", sql, &[]),
                crate::protocol::bind_message("", "", &refs),
                crate::protocol::describe_message(crate::constants::describe::PORTAL, ""),
                crate::protocol::execute_message("", 0),
            ]);
        }
        messages.push(crate::protocol::sync_message());
        self.packet_stream.send_queue.extend(messages);
        self.batch_count = statements.len();
        self.batch_row_count = statements.len();
        self.pending_batch_rows = None;
        Ok(())
    }

    /// バッチクエリの結果をすべて読み込む。
    ///
    /// 戻り値の長さは送信したステートメント数と同じで、
    /// ステートメントごとの影響行数またはエラーを持つ。
    /// 途中のステートメントでエラーが起きた場合、後続のステートメントは
    /// サーバーで実行されず、未実行を表すエラーが入る。
    ///
    /// `count` は `send_batch` で送信した文数と一致する必要がある。
    /// `Error::NeedMoreData` で中断した場合は進行状態を保持するため、
    /// データを供給して同じ `count` で呼び出すと再開できる。
    pub fn read_batch_results(&mut self, count: usize) -> Result<Vec<Result<i64>>> {
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        if count != self.batch_count {
            return Err(Error::interface(
                "Batch result count does not match the submitted batch",
            ));
        }
        // 中断状態から再開する。
        let result = match self.pending_batch.take() {
            Some(BatchReadProgress::Reading(results)) => {
                self.read_batch_results_inner(count, results)
            }
            Some(BatchReadProgress::AfterError { results, remaining }) => {
                // エラー応答後の読み飛ばしを再開する。
                match self.drain_to_ready() {
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
        };
        // 文のエラーは結果ベクトルに含める。外側のエラーで再試行できるのは入力不足だけ。
        match &result {
            Ok(_) => {
                self.batch_count = 0;
                // 行付きの読み込みに切り替えないよう、使わなかった状態も消す。
                self.batch_row_count = 0;
                self.pending_batch_rows = None;
            }
            Err(Error::NeedMoreData) => {}
            Err(_) => {
                self.force_close();
                self.result = None;
            }
        }
        result
    }

    /// バッチクエリの結果を、ステートメントごとの結果セットとして読み込む。
    ///
    /// 戻り値の長さは送信したステートメント数と同じで、
    /// ステートメントごとのフィールドと行、またはエラーを持つ。
    /// 途中のステートメントでエラーが起きた場合、後続のステートメントは
    /// サーバーで実行されず、未実行を表すエラーが入る。
    ///
    /// `Error::NeedMoreData` で中断した場合は進行状態を保持するため、
    /// データを供給して再度呼び出すと再開できる。
    pub fn read_batch_row_results(&mut self) -> Result<Vec<Result<QueryResult>>> {
        if self.closed {
            return Err(Error::interface("Connection is closed"));
        }
        let count = self.batch_row_count;
        if count == 0 {
            return Ok(Vec::new());
        }
        let (mut results, pending_skip) = match self.pending_batch_rows.take() {
            Some(BatchRowProgress::Reading(results)) => (results, None),
            Some(BatchRowProgress::AfterError { results, remaining }) => (results, Some(remaining)),
            None => (Vec::new(), None),
        };
        if let Some(remaining) = pending_skip {
            match self.drain_to_ready() {
                Ok(()) => {
                    results.extend(finish_batch_rows_after_error(remaining));
                    return Ok(results);
                }
                Err(Error::NeedMoreData) => {
                    self.pending_batch_rows =
                        Some(BatchRowProgress::AfterError { results, remaining });
                    return Err(Error::NeedMoreData);
                }
                Err(error) => {
                    self.force_close();
                    self.result = None;
                    return Err(error);
                }
            }
        }
        while results.len() < count {
            let position = if results.len() + 1 == count {
                BatchPosition::Last
            } else {
                BatchPosition::Intermediate
            };
            match self.read_query_result_inner(false, Some(position)) {
                Ok(_) => {
                    let result = self
                        .result
                        .take()
                        .ok_or_else(|| Error::internal("Batch statement produced no result"))?;
                    results.push(Ok(result));
                }
                Err(Error::NeedMoreData) => {
                    self.pending_batch_rows = Some(BatchRowProgress::Reading(results));
                    return Err(Error::NeedMoreData);
                }
                Err(error) if error.code().is_some_and(|code| !code.is_empty()) => {
                    results.push(Err(error));
                    let remaining = count - results.len();
                    match self.drain_to_ready() {
                        Ok(()) => {
                            results.extend(finish_batch_rows_after_error(remaining));
                            return Ok(results);
                        }
                        Err(Error::NeedMoreData) => {
                            self.pending_batch_rows =
                                Some(BatchRowProgress::AfterError { results, remaining });
                            return Err(Error::NeedMoreData);
                        }
                        Err(error) => {
                            self.force_close();
                            self.result = None;
                            return Err(error);
                        }
                    }
                }
                Err(error) => {
                    self.force_close();
                    self.result = None;
                    return Err(error);
                }
            }
        }
        self.batch_count = 0;
        self.batch_row_count = 0;
        Ok(results)
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
            let position = if results.len() + 1 == count {
                BatchPosition::Last
            } else {
                BatchPosition::Intermediate
            };
            match self.read_query_result_inner(false, Some(position)) {
                Ok(affected) => results.push(Ok(affected)),
                Err(Error::NeedMoreData) => {
                    self.pending_batch = Some(BatchReadProgress::Reading(results));
                    return Err(Error::NeedMoreData);
                }
                Err(e) if e.code().is_some_and(|code| !code.is_empty()) => {
                    results.push(Err(e));
                    let remaining = count - results.len();
                    // エラー後は後続のステートメントはサーバーで実行されない。
                    // ReadyForQuery まで読み飛ばす。
                    match self.drain_to_ready() {
                        Ok(()) => return Ok(finish_batch_after_error(results, remaining)),
                        Err(Error::NeedMoreData) => {
                            self.pending_batch =
                                Some(BatchReadProgress::AfterError { results, remaining });
                            return Err(Error::NeedMoreData);
                        }
                        Err(e2) => return Err(e2),
                    }
                }
                // フォーマット不正などは文のエラーではない。
                Err(e) => return Err(e),
            }
        }
        Ok(results)
    }

    /// 結果セットを読み込む。
    ///
    /// 受信キューに十分なメッセージがない場合は `Error::NeedMoreData` を返す。
    /// 呼び出し側はさらにデータを供給してから再度呼び出すことで読み込みを再開できる。
    pub fn read_query_result(&mut self, unbuffered: bool) -> Result<i64> {
        self.read_query_result_inner(unbuffered, None)
    }

    /// 結果セットを読み込む。バッチの途中ではコマンド完了で中断し、
    /// 最後ではコマンド完了と Sync に対応する ReadyForQuery を確認する。
    fn read_query_result_inner(
        &mut self,
        unbuffered: bool,
        batch_position: Option<BatchPosition>,
    ) -> Result<i64> {
        let mut result = self
            .result
            .take()
            .filter(|r| !r.is_done())
            .unwrap_or_default();
        if result.is_initial() {
            result.unbuffered_active = unbuffered;
            result.stop_at_command_complete =
                matches!(batch_position, Some(BatchPosition::Intermediate));
            result.custom_decoders = self.custom_decoders.clone();
        }
        loop {
            let input = match batch_position {
                Some(position) => self.read_batch_packet(position, result.command_completed()),
                None => self.read_query_packet(),
            };
            let packet = match input {
                Ok(Some(packet)) => packet,
                Ok(None) => continue,
                Err(e) => {
                    self.keep_result(result);
                    return Err(e);
                }
            };
            match result.feed_packet(packet) {
                Ok(FeedResult::NeedMore) => continue,
                Ok(FeedResult::Done) => {
                    // 複数結果セットの場合は最初の結果セットを現在に戻す。
                    result.rewind_to_first_rowset();
                    let affected_rows = result.affected_rows;
                    self.result = Some(result);
                    return Ok(affected_rows);
                }
                Ok(FeedResult::UnbufferedReady) => {
                    let affected_rows = result.affected_rows;
                    self.result = Some(result);
                    return Ok(affected_rows);
                }
                Err(e) => {
                    // エラー応答で中断した場合は、次のクエリ実行時に
                    // ReadyForQuery まで読み飛ばすために結果を保持する。
                    self.keep_result(result);
                    return Err(e);
                }
            }
        }
    }

    /// バッチの同期境界を確定してから、受信フレームを記録する。
    fn read_batch_packet(
        &mut self,
        position: BatchPosition,
        command_completed: bool,
    ) -> Result<Option<PostgresPacket>> {
        let packet = self.read_open_packet()?;
        // PostgreSQL 18 §54.2.3: Execute は CommandComplete または EmptyQueryResponse で完了し、
        // Sync が ReadyForQuery を返す。将来、完了応答が増える場合はこの検査を見直す。
        // Sync のトランザクション完了が失敗した場合は、最終文の完了後でも ErrorResponse が来る。
        let valid = match packet.message_type {
            backend::READY_FOR_QUERY => {
                matches!(position, BatchPosition::Last) && command_completed
            }
            backend::ERROR_RESPONSE
            | backend::PARAMETER_STATUS
            | backend::NOTICE_RESPONSE
            | backend::NOTIFICATION_RESPONSE => true,
            _ => !command_completed,
        };
        if !valid {
            // 無効な同期を記録せず、呼び出し元で接続を閉じる。
            return Err(Error::internal(
                "Unexpected message at batch synchronization boundary",
            ));
        }
        let packet = self.record_packet(packet)?;
        self.handle_query_packet(packet)
    }

    /// アンバッファードクエリから、最初の行を返す結果セットの次の行を取得する。
    ///
    /// 行は接続に複製せず、読み込みのたびに所有権を呼び出し側に渡す。
    /// その結果セットの末尾に達した場合、後続の結果セットは保存せず読み飛ばし、
    /// ReadyForQuery の消費後に `None` を返す。読めるアンバッファード結果がなければ
    /// 即座に `None` を返す。
    /// `Error::NeedMoreData` の場合はデータを供給してから読み込みを再開できる。
    pub fn read_next_row(&mut self) -> Result<Option<Vec<Value>>> {
        let Some(mut result) = self.result.take() else {
            return Ok(None);
        };
        let row = result.read_next_unbuffered(self);
        self.keep_result(result);
        row
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
        if self.batch_count != 0 {
            return Err(Error::interface(
                "A batch is still awaiting synchronization",
            ));
        }
        if self.pending_deallocation.is_some() {
            return Err(Error::interface(
                "Prepared statement deallocation is pending",
            ));
        }
        if let Some(mut result) = self.result.take() {
            let finish = (|| {
                if result.unbuffered_active {
                    return result.finish_unbuffered(self);
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
                self.keep_result(result);
                return finish;
            }
        }
        Ok(())
    }

    /// 応答の内容を捨てて次の ReadyForQuery まで同期する。
    ///
    /// サーバーエラーやキャンセルからの回復に使う。応答が保留中の場合にだけ呼ぶ。
    /// 通知・NOTICE・パラメータ状態は通常どおり処理するが、行やサーバーエラーは破棄する。
    /// `Error::NeedMoreData` の場合はデータを供給して再度呼び出す。
    /// 入力を要求する COPY など、受信だけで回復できない応答ではエラーを返す。
    pub fn drain_to_ready(&mut self) -> Result<()> {
        self.drain_until_ready(false).map(|_| ())
    }

    /// キャンセルした操作の応答を読み飛ばし、同期までに SQLSTATE 57014 を受け取ったかを返す。
    ///
    /// `Error::NeedMoreData` で中断しても検出状態を保持する。
    /// この SQLSTATE はクエリのキャンセルを示すが、キャンセル要求以外の原因でも返りうる。
    /// 残りの契約は `drain_to_ready` と同じ。
    pub fn drain_canceled_request(&mut self) -> Result<bool> {
        self.drain_until_ready(true)
    }

    fn drain_until_ready(&mut self, observe_cancellation: bool) -> Result<bool> {
        loop {
            let Some(packet) = self.read_query_packet()? else {
                continue;
            };
            match packet.message_type {
                backend::READY_FOR_QUERY => break,
                backend::ERROR_RESPONSE
                    if observe_cancellation && !self.cancellation_error_seen =>
                {
                    self.cancellation_error_seen = ErrorResponse::parse(&packet)?.code == "57014";
                }
                backend::ERROR_RESPONSE
                | backend::DATA_ROW
                | backend::ROW_DESCRIPTION
                | backend::COMMAND_COMPLETE
                | backend::EMPTY_QUERY_RESPONSE
                | backend::COPY_OUT_RESPONSE
                | backend::COPY_DATA
                | backend::COPY_DONE
                | backend::PARSE_COMPLETE
                | backend::BIND_COMPLETE
                | backend::PARAMETER_DESCRIPTION
                | backend::NO_DATA
                | backend::CLOSE_COMPLETE => {}
                _ => {
                    return Err(Error::internal(format!(
                        "Cannot drain backend message 0x{:02x} safely",
                        packet.message_type
                    )));
                }
            }
        }
        self.result = None;
        self.pending_prepare = None;
        self.batch_count = 0;
        self.pending_batch = None;
        self.batch_row_count = 0;
        self.pending_batch_rows = None;
        self.copy_phase = CopyPhase::None;
        self.copy_pending = false;
        self.pending_deallocation = None;
        Ok(std::mem::take(&mut self.cancellation_error_seen))
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
                if let Err(error) = check_session_parameter(&status) {
                    // 変更の通知は応答サイクルの最後に届くため、同じサイクルの行も
                    // すでに誤った前提で届いている。この接続は再利用しない。
                    self.force_close();
                    return Err(error);
                }
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
        crate::protocol::validate_query(sql)?;
        tracing::debug!("Sending CopyIn query");
        let message = crate::protocol::query_message(sql);
        self.packet_stream.write_message(&message);
        self.copy_pending = true;
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
                    self.copy_pending = false;
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
                    self.copy_pending = false;
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
        crate::protocol::validate_copy_data(data.len())?;
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
        crate::protocol::validate_copy_fail(message)?;
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
        self.copy_pending = false;
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
        crate::protocol::validate_query(sql)?;
        tracing::debug!("Sending CopyOut query");
        let message = crate::protocol::query_message(sql);
        self.packet_stream.write_message(&message);
        self.copy_pending = true;
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
                    self.copy_pending = false;
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
                    self.copy_pending = false;
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
        self.copy_pending = false;
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

    /// 現在の結果セットを取り出す。
    ///
    /// 呼び出し後は `result()` が `None` を返す。
    /// 行を複製せずに呼び出し側へ渡したい場合に使う。
    pub fn take_result(&mut self) -> Option<QueryResult> {
        self.result.take()
    }

    /// 中断した結果を、読み込みの再開や読み飛ばしのために保持する。
    ///
    /// 処理中に接続を閉じた場合は保持しない。[`Connection::force_close`] と同じ理由による。
    fn keep_result(&mut self, result: QueryResult) {
        if !self.closed {
            self.result = Some(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// conninfo 形式の接続文字列のパースを検証する。
    #[test]
    fn test_from_conninfo() {
        let options = ConnectOptions::from_conninfo(
            "host=db.example.com port=5433 dbname=mydb user=alice password='pa ss' sslmode=verify-full connect_timeout=30 application_name='my app'",
        )
        .expect("パースに成功しました");
        assert_eq!(options.host, "db.example.com");
        assert_eq!(options.port, 5433);
        assert_eq!(options.database.as_deref(), Some("mydb"));
        assert_eq!(options.user, "alice");
        assert_eq!(options.password, b"pa ss");
        assert_eq!(options.ssl_mode, SslMode::VerifyFull);
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

    /// conninfo 形式の `=` 前後の空白と引用符なしのエスケープを検証する。
    #[test]
    fn test_from_conninfo_whitespace_and_unquoted_escapes() {
        let options = ConnectOptions::from_conninfo(
            "host = localhost port= 5432 user = alice password=a\\ b",
        )
        .expect("パースに成功しました");
        assert_eq!(options.host, "localhost");
        assert_eq!(options.port, 5432);
        assert_eq!(options.user, "alice");
        assert_eq!(options.password, b"a b");

        // 末尾のバックスラッシュは不正。
        assert!(ConnectOptions::from_conninfo("password=a\\").is_err());
        // キーが空の場合は不正。
        assert!(ConnectOptions::from_conninfo("=value").is_err());
    }

    /// conninfo 形式で sslmode の全バリアントを検証する。
    #[test]
    fn test_from_conninfo_sslmode() {
        for (mode, expected) in [
            ("disable", SslMode::Disabled),
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

    /// TLS の無効化は明示したローカル接続でのみ利用できる。
    #[test]
    fn test_local_only_transport_policy() {
        assert_eq!(ConnectOptions::default().ssl_mode, SslMode::VerifyFull);
        for host in ["localhost", "LOCALHOST", "127.0.0.1", "::1", "/tmp"] {
            let options = ConnectOptions {
                host: host.into(),
                ssl_mode: SslMode::Disabled,
                ..ConnectOptions::default()
            };
            assert!(
                Connection::connect(options).is_ok(),
                "明示したローカル接続が拒否されました"
            );
        }
        for host in ["db.example.com", "192.0.2.1"] {
            let options = ConnectOptions {
                host: host.into(),
                ssl_mode: SslMode::Disabled,
                ..ConnectOptions::default()
            };
            assert!(
                Connection::connect(options).is_err(),
                "許可されない平文接続を受理しました"
            );
        }
        assert!(
            Connection::connect(ConnectOptions {
                host: "/tmp".into(),
                ..ConnectOptions::default()
            })
            .is_err(),
            "明示していない Unix ソケット接続を受理しました"
        );
        let remote = ConnectOptions::from_conninfo(
            "host=192.0.2.1 sslmode=disable allow_insecure_remote=true",
        )
        .expect("リモート開発接続の設定を読めません");
        assert!(
            Connection::connect(remote).is_ok(),
            "明示したリモート開発接続が拒否されました"
        );
        let conflicting = ConnectOptions::from_url("postgres://host?allow_insecure_remote=true")
            .expect("URL の開発用フラグを読めません");
        assert!(
            Connection::connect(conflicting).is_err(),
            "既定の TLS と互換性のない開発用フラグを受理しました"
        );
        for value in ["allow", "prefer"] {
            assert!(
                value.parse::<SslMode>().is_err(),
                "弱い TLS モードを受理しました"
            );
        }
    }

    /// 接続設定が資格情報を出力せず、未対応の設定を黙って無視しないことを確認する。
    #[test]
    fn test_connection_configuration_is_not_leaked() {
        let options = ConnectOptions {
            password: "synthetic-password".into(),
            oauth_token: Some("synthetic-bearer".into()),
            ..ConnectOptions::default()
        };
        let debug = format!("{options:?}");
        assert!(
            !debug.contains("password") && !debug.contains("bearer"),
            "資格情報を出力しました"
        );
        let error = ConnectOptions::from_conninfo("password='synthetic-password")
            .expect_err("閉じていないパスワードを受理しました");
        assert!(!error.to_string().contains("synthetic-password"));
        assert!(ConnectOptions::from_conninfo("channel_binding=require").is_err());
        assert!(ConnectOptions::from_url("postgres://host?require_auth=scram-sha-256").is_err());
        assert!(ConnectOptions::from_url("postgres://host?password=%x0").is_err());
    }

    /// TLS 応答と直後の未検証データが別々に届いても接続を閉じる。
    #[test]
    fn test_data_between_tls_acceptance_and_verified_startup() {
        for consume_response in [false, true] {
            let mut conn = Connection::connect(ConnectOptions {
                user: "tester".into(),
                ..ConnectOptions::default()
            })
            .expect("接続状態を作成できません");
            conn.request_authentication_start()
                .expect("TLS 要求を作成できません");
            conn.feed_bytes(b"S")
                .expect("単独の TLS 応答を受信できません");
            if consume_response {
                conn.request_authentication_continue()
                    .expect("TLS 応答を読めません");
            }
            conn.feed_bytes(b"Z")
                .expect_err("TLS 検証前の追加データを受理しました");
            assert!(
                !conn.is_open(),
                "TLS 検証前の追加データで接続が閉じませんでした"
            );
            assert!(
                conn.pop_send_queue().is_none(),
                "送信待ちのデータが残っています"
            );
        }
    }

    /// 不正な入力が混じったバッチは先頭の文も送信しない。
    #[test]
    fn test_invalid_batch_does_not_enqueue_messages() {
        let mut conn =
            Connection::connect(ConnectOptions::default()).expect("接続状態を作成できません");
        let commands = [
            ("SELECT 1".into(), vec![]),
            ("SELECT $1::text".into(), vec![Value::Text("a\0b".into())]),
        ];
        conn.send_batch(&commands)
            .expect_err("NUL を含むテキストパラメーターを受理しました");
        assert!(
            conn.pop_send_queue().is_none(),
            "先行する文の一部が残っています"
        );
    }

    /// 起動時の追加パラメーターが予約名と重複を拒否することを検証する。
    #[test]
    fn test_validate_runtime_params() {
        let valid = ConnectOptions {
            runtime_params: vec![
                ("search_path".to_string(), "app,public".to_string()),
                ("statement_timeout".to_string(), "5s".to_string()),
            ],
            ..Default::default()
        };
        assert!(
            valid.validate_runtime_params().is_ok(),
            "正しいパラメーターが拒否されました"
        );

        let empty_name = ConnectOptions {
            runtime_params: vec![(String::new(), "x".to_string())],
            ..Default::default()
        };
        assert!(
            empty_name.validate_runtime_params().is_err(),
            "空の名前が受理されました"
        );

        let reserved = ConnectOptions {
            runtime_params: vec![("USER".to_string(), "x".to_string())],
            ..Default::default()
        };
        assert!(
            reserved.validate_runtime_params().is_err(),
            "予約名が受理されました"
        );

        // `_pq_.` で始まる名前はプロトコル拡張の要求になるため拒否する。
        let protocol_extension = ConnectOptions {
            runtime_params: vec![(
                "_pq_.test_protocol_negotiation".to_string(),
                "x".to_string(),
            )],
            ..Default::default()
        };
        let error = protocol_extension
            .validate_runtime_params()
            .expect_err("プロトコル拡張の名前が受理されました");
        assert_eq!(
            error.message(),
            "Runtime parameter `_pq_.test_protocol_negotiation` is reserved for protocol extensions",
            "プロトコル拡張を拒否したエラーが返りませんでした"
        );
        // サーバーと同じく大文字と小文字を区別するため、`_PQ_.` は通常の設定として送る。
        let uppercase_prefix = ConnectOptions {
            runtime_params: vec![("_PQ_.custom".to_string(), "x".to_string())],
            ..Default::default()
        };
        assert!(
            uppercase_prefix.validate_runtime_params().is_ok(),
            "プロトコル拡張ではない名前が拒否されました"
        );

        let duplicate = ConnectOptions {
            runtime_params: vec![
                ("search_path".to_string(), "a".to_string()),
                ("SEARCH_PATH".to_string(), "b".to_string()),
            ],
            ..Default::default()
        };
        assert!(
            duplicate.validate_runtime_params().is_err(),
            "重複した名前が受理されました"
        );
    }

    /// 型 OID の数が引数の数と一致しない実行を拒否することを検証する。
    #[test]
    fn test_send_execute_typed_rejects_mismatched_types() {
        let mut conn =
            Connection::connect(ConnectOptions::default()).expect("接続状態を作成できません");
        let error = conn
            .send_execute_typed("SELECT $1", &[23], &[])
            .expect_err("型 OID の数が引数と一致しない実行が成功しました");
        assert_eq!(
            error.message(),
            "Parameter type count mismatch: expected 0, got 1",
            "エラーメッセージが一致しません"
        );
        assert!(
            conn.pop_send_queue().is_none(),
            "拒否した実行のメッセージが送信キューに残っています"
        );
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

    /// postgres:// URL のホストのパーセントエンコーディングと名前付きパラメータを検証する。
    #[test]
    fn test_from_url_encoded_host_and_named_parameters() {
        let options = ConnectOptions::from_url("postgres://%2Fvar%2Flib%2Fpostgresql/dbname")
            .expect("パースに成功しました");
        assert_eq!(options.host, "/var/lib/postgresql");
        assert_eq!(options.database.as_deref(), Some("dbname"));

        let options = ConnectOptions::from_url(
            "postgres://host/pathdb?user=alice&password=p%40ss&dbname=querydb",
        )
        .expect("パースに成功しました");
        assert_eq!(options.user, "alice");
        assert_eq!(options.password, b"p@ss");
        assert_eq!(options.database.as_deref(), Some("querydb"));

        // URI の `+` は空白ではなくリテラルのプラス記号。
        let options = ConnectOptions::from_url("postgres://host/db?application_name=a+b")
            .expect("パースに成功しました");
        assert_eq!(options.application_name.as_deref(), Some("a+b"));
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

    /// options を接続文字列と URL から読めることを確認する。
    #[test]
    fn test_options_from_connection_string() {
        let conninfo =
            ConnectOptions::from_conninfo("host=db options='-c search_path=app -c geqo=off'")
                .expect("options を含む接続文字列を読めません");
        let url = ConnectOptions::from_url(
            "postgres://db?options=-c%20search_path%3Dapp%20-c%20geqo%3Doff",
        )
        .expect("options を含む URL を読めません");
        for options in [conninfo, url] {
            assert_eq!(
                options.options.as_deref(),
                Some("-c search_path=app -c geqo=off")
            );
        }
        assert_eq!(ConnectOptions::default().options, None);
    }

    /// キープアライブと tcp_user_timeout のキーを libpq と同じ単位で解釈することを確認する。
    #[test]
    fn test_tcp_settings_from_connection_string() {
        let default = ConnectOptions::default();
        assert!(
            default.keepalives,
            "キープアライブが既定で有効になっていません"
        );
        assert_eq!(default.keepalives_idle, None);
        assert_eq!(default.tcp_user_timeout, None);

        // 秒、秒、回数、ミリ秒の順に解釈する。接続文字列と URL で結果は同じになる。
        let conninfo = ConnectOptions::from_conninfo(
            "host=db.example.com keepalives=1 keepalives_idle=30 keepalives_interval=5 keepalives_count=3 tcp_user_timeout=1500",
        )
        .expect("TCP の設定を含む接続文字列を読めません");
        let url = ConnectOptions::from_url(
            "postgres://db.example.com?keepalives=1&keepalives_idle=30&keepalives_interval=5&keepalives_count=3&tcp_user_timeout=1500",
        )
        .expect("TCP の設定を含む URL を読めません");
        for options in [conninfo, url] {
            assert!(options.keepalives);
            assert_eq!(options.keepalives_idle, Some(Duration::from_secs(30)));
            assert_eq!(options.keepalives_interval, Some(Duration::from_secs(5)));
            assert_eq!(options.keepalives_count, Some(3));
            assert_eq!(options.tcp_user_timeout, Some(Duration::from_millis(1500)));
        }

        // keepalives は 0 以外を有効とする。調整値の 0 は OS の既定値を表す。
        let options = ConnectOptions::from_conninfo(
            "keepalives=0 keepalives_idle=0 keepalives_interval=0 keepalives_count=0 tcp_user_timeout=0",
        )
        .expect("0 を指定した接続文字列を読めません");
        assert!(!options.keepalives, "keepalives=0 で無効になりません");
        assert_eq!(options.keepalives_idle, None);
        assert_eq!(options.keepalives_interval, None);
        assert_eq!(options.keepalives_count, None);
        assert_eq!(options.tcp_user_timeout, None);
        assert!(
            ConnectOptions::from_conninfo("keepalives=2")
                .expect("keepalives=2 を読めません")
                .keepalives,
            "0 以外の keepalives で有効になりません"
        );

        // 負の値、整数でない値、int に収まらない値はエラーにする。
        for (conninfo, expected) in [
            ("keepalives=on", "Invalid keepalives in connection string"),
            (
                "keepalives_idle=-1",
                "Invalid keepalives_idle in connection string",
            ),
            (
                "keepalives_interval=1.5",
                "Invalid keepalives_interval in connection string",
            ),
            (
                "keepalives_count=2147483648",
                "Invalid keepalives_count in connection string",
            ),
            (
                "tcp_user_timeout=abc",
                "Invalid tcp_user_timeout in connection string",
            ),
        ] {
            let error = ConnectOptions::from_conninfo(conninfo)
                .expect_err("不正な TCP の設定を受理しました");
            assert_eq!(error.message(), expected, "{conninfo} のエラーが異なります");
        }
        let error = ConnectOptions::from_url("postgres://host?keepalives_idle=-1")
            .expect_err("URL の不正な TCP の設定を受理しました");
        assert_eq!(error.message(), "Invalid keepalives_idle in URL");
    }

    /// 効かない組み合わせや範囲外の TCP の設定を、接続前にエラーにすることを確認する。
    #[test]
    fn test_tcp_settings_validation() {
        let tcp = || ConnectOptions {
            host: "db.example.com".into(),
            ..ConnectOptions::default()
        };
        assert!(
            Connection::connect(ConnectOptions {
                keepalives_idle: Some(Duration::from_secs(30)),
                keepalives_interval: Some(Duration::from_secs(5)),
                keepalives_count: Some(3),
                tcp_user_timeout: Some(Duration::from_millis(1500)),
                ..tcp()
            })
            .is_ok(),
            "正しい TCP の設定が拒否されました"
        );
        let cases = [
            (
                ConnectOptions {
                    host: "/tmp".into(),
                    ssl_mode: SslMode::Disabled,
                    keepalives_idle: Some(Duration::from_secs(30)),
                    ..ConnectOptions::default()
                },
                "TCP keepalive and tcp_user_timeout settings cannot be used with Unix domain sockets",
            ),
            (
                ConnectOptions {
                    host: "/tmp".into(),
                    ssl_mode: SslMode::Disabled,
                    tcp_user_timeout: Some(Duration::from_millis(1500)),
                    ..ConnectOptions::default()
                },
                "TCP keepalive and tcp_user_timeout settings cannot be used with Unix domain sockets",
            ),
            (
                ConnectOptions {
                    keepalives: false,
                    keepalives_count: Some(3),
                    ..tcp()
                },
                "keepalives_idle, keepalives_interval and keepalives_count require keepalives",
            ),
            (
                ConnectOptions {
                    keepalives_idle: Some(Duration::ZERO),
                    ..tcp()
                },
                "keepalives_idle must be a whole number of seconds between 1 and 2147483647",
            ),
            (
                ConnectOptions {
                    keepalives_interval: Some(Duration::from_millis(1500)),
                    ..tcp()
                },
                "keepalives_interval must be a whole number of seconds between 1 and 2147483647",
            ),
            (
                ConnectOptions {
                    keepalives_idle: Some(Duration::from_secs(1 << 31)),
                    ..tcp()
                },
                "keepalives_idle must be a whole number of seconds between 1 and 2147483647",
            ),
            (
                ConnectOptions {
                    keepalives_count: Some(0),
                    ..tcp()
                },
                "keepalives_count must be between 1 and 2147483647",
            ),
            (
                ConnectOptions {
                    keepalives_count: Some(1 << 31),
                    ..tcp()
                },
                "keepalives_count must be between 1 and 2147483647",
            ),
            (
                ConnectOptions {
                    tcp_user_timeout: Some(Duration::from_micros(1500)),
                    ..tcp()
                },
                "tcp_user_timeout must be a whole number of milliseconds between 1 and 2147483647",
            ),
            (
                ConnectOptions {
                    tcp_user_timeout: Some(Duration::ZERO),
                    ..tcp()
                },
                "tcp_user_timeout must be a whole number of milliseconds between 1 and 2147483647",
            ),
        ];
        for (options, expected) in cases {
            let error = Connection::connect(options)
                .err()
                .expect("不正な TCP の設定を受理しました");
            assert_eq!(error.message(), expected);
        }
        // keepalives=false だけなら、Unix ドメインソケットでも受け付ける。
        assert!(
            Connection::connect(ConnectOptions {
                host: "/tmp".into(),
                ssl_mode: SslMode::Disabled,
                keepalives: false,
                ..ConnectOptions::default()
            })
            .is_ok(),
            "Unix ドメインソケットで keepalives=false が拒否されました"
        );
    }
}
