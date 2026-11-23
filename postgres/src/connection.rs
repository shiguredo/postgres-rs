// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 接続の tokio I/O 実装。
//!
//! sans I/O な状態機械 (内部実装) に対し、TCP/TLS/Unix ドメインソケット
//! 接続、タイムアウト、読み書きを行う。

mod tls;

use crate::batch::Batch;
use crate::converters::Value;
use crate::error::{Error, Result};
use shiguredo_postgres_core::connection::{AuthState, Connection as InnerConnection};

// 以下は sans I/O 実装 (shiguredo_postgres_core) から再エクスポートした型。
// 利用者は shiguredo_postgres クレートだけに依存すればよい。
// ドキュメントは sans I/O 実装側のものが引き継がれる。
pub use shiguredo_postgres_core::connection::{
    ConnectOptions, Notification, PreparedStatement, QueryResult, SslMode,
};
use std::collections::HashMap;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// キャンセル要求後の後始末に許す時間。
const CANCEL_RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// 送信メッセージを 1 回の write にまとめる上限。
///
/// これを超えるメッセージ (COPY データなど) はコピーせず直接書き込む。
const WRITE_COALESCE_LIMIT: usize = 64 * 1024;

/// 1 回の read で受け取る最大バイト数。
///
/// shiguredo/lean の postgres-rs/Framing.lean にある chunkInvariant は、
/// 任意の分割で読み取った場合も連結したバイト列を一括で走査した場合と
/// 同じフレーム列になることを示す。
/// つまりこの値はプロトコルの正しさに影響せず、性能だけのパラメータである。
const READ_BUFFER_SIZE: usize = 4 * 1024;

/// 最後に同期が確認された後のワイヤー状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WirePhase {
    Idle,
    Writing,
    Reading,
    Recovering,
    Rows,
    CopyIn,
    CopyInFinished,
    CopyOut,
    CopyOutFinished,
}

/// キャッシュする文と最終使用順。
struct CachedStatement {
    statement: PreparedStatement,
    last_used: u64,
}

/// 自動準備した文を特定するキー。
///
/// 同じ SQL でもパラメーターの型 OID が異なれば別の文になる。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StatementKey {
    sql: String,
    parameter_oids: Vec<u32>,
}

impl StatementKey {
    fn new(sql: &str, parameter_oids: &[u32]) -> Self {
        Self {
            sql: sql.to_string(),
            parameter_oids: parameter_oids.to_vec(),
        }
    }
}

/// 接続の状態を表すストリーム。
enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Unix(UnixStream),
}

/// キャンセル要求の接続先。
#[derive(Debug, Clone, Copy)]
enum CancelTarget {
    /// TCP 接続。TLS を使うかどうかも保持する。
    Tcp {
        /// 元の接続が確立したピアのアドレス。
        addr: std::net::SocketAddr,
        /// 元の接続が TLS を使っていたかどうか。
        tls: bool,
    },
    /// Unix ドメインソケット。接続先は [`ConnectOptions`] から求める。
    Unix,
}

/// 実行中のクエリをキャンセルするためのトークン。
///
/// 元の接続から独立して保持でき、別のタスクから実行中のクエリをキャンセルできる。
/// キャンセル要求は新しい接続で送るため、元の接続を借りたままでも使える。
/// 対象のクエリは元の接続側でエラーになる。
///
/// トークンは [`Connection::cancel_token`] で作る。
/// 接続が閉じた後にキャンセルしても、サーバーは対象のバックエンドを
/// 見つけられないため何も起きない。
#[derive(Clone, Debug)]
pub struct CancelToken {
    options: ConnectOptions,
    target: CancelTarget,
    process_id: u32,
    secret_key: u32,
}

impl CancelToken {
    /// キャンセル要求を送信する。
    ///
    /// 元の接続と同じピアへ接続し、同じ TLS の設定でハンドシェイクする。
    /// 平文への降格は行わない。
    /// サーバーが接続を閉じるまで待ち、応答本文が届いた場合はエラーを返す。
    pub async fn cancel(&self) -> Result<()> {
        fn io_error(error: io::Error) -> Error {
            Error::operational(format!("Cancel request transport failed: {error}"))
        }
        // DNS を引き直さず、元の接続と同じピアへ接続する。
        let mut stream = match self.target {
            CancelTarget::Tcp { addr, tls } => {
                let mut plain = TcpStream::connect(addr).await.map_err(io_error)?;
                // libpq と同じく、キャンセル要求の接続にも同じ TCP の設定を使う。
                configure_tcp(&plain, &self.options)?;
                if tls {
                    plain
                        .write_all(&crate::protocol::ssl_request_message())
                        .await
                        .map_err(io_error)?;
                    if plain.read_u8().await.map_err(io_error)? != b'S' {
                        return Err(Error::operational(
                            "Server rejected TLS for the cancel request",
                        ));
                    }
                    establish_tls(plain, &self.options).await?
                } else {
                    ConnectionStream::Plain(plain)
                }
            }
            CancelTarget::Unix => connect_stream(&self.options).await?,
        };
        let message = crate::protocol::cancel_request_message(self.process_id, self.secret_key);
        stream.write_all(&message).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        // キャンセル専用接続に応答の本文はない。EOF は処理済みを表すが、
        // 対象クエリにキャンセルが効いたかまでは分からない。
        if stream.read(&mut [0]).await.map_err(io_error)? != 0 {
            return Err(Error::operational(
                "Unexpected response to the cancel request",
            ));
        }
        Ok(())
    }
}

/// OAuth トークンプロバイダ。
///
/// 認証フロー中にトークンが拒否されたときに新しいトークンを返す。
/// プール内で接続が別タスクに渡されるため `Send` である必要がある。
type OAuthTokenProvider = Box<
    dyn FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send>>
        + Send,
>;

impl ConnectionStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf).await,
            Self::Tls(s) => s.read(buf).await,
            Self::Unix(s) => s.read(buf).await,
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.write_all(data).await,
            Self::Tls(s) => s.write_all(data).await,
            Self::Unix(s) => s.write_all(data).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush().await,
            Self::Tls(s) => s.flush().await,
            Self::Unix(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.shutdown().await,
            Self::Tls(s) => s.shutdown().await,
            Self::Unix(s) => s.shutdown().await,
        }
    }
}

/// PostgreSQL 接続。
pub struct Connection {
    inner: InnerConnection,
    stream: Option<ConnectionStream>,
    /// 受信ごとのヒープ確保を避けるため、接続内で使い回す。
    read_buffer: Box<[u8; READ_BUFFER_SIZE]>,
    /// 送信キューをまとめて書き込むためのバッファ。接続内で使い回す。
    write_buffer: Vec<u8>,
    /// 自動準備した文のみをキャッシュする。明示的に準備した文は利用者が管理する。
    statement_cache: HashMap<StatementKey, CachedStatement>,
    statement_clock: u64,
    phase: WirePhase,
    /// 現在の要求を送信する直前に観測した同期応答の番号。
    request_ready_sequence: u64,
    /// ワイヤー同期だけで安全に復帰できる要求か。文の準備・解放と COPY は復帰させない。
    request_can_cancel: bool,
    /// トランザクションが commit / rollback されずに破棄されたかどうか。
    ///
    /// 次の `begin()` でロールバックしてから開始する。
    transaction_dirty: bool,
}

impl Connection {
    /// 新規接続を確立する。
    ///
    /// TCP または Unix ドメインソケット接続、TLS ネゴシエーション (必要な場合)、
    /// 認証、ReadyForQuery の受信までを行う。
    ///
    /// `host` が `/` で始まる場合は Unix ドメインソケットとして扱う。
    /// ソケットファイルは libpq と同じく `<host>/.s.PGSQL.<port>` になる。
    /// Unix ドメインソケットは `SslMode::Disabled` を明示して使う。
    /// TCP の既定は証明書と接続先の名前を検証する TLS で、平文には切り替えない。
    pub async fn connect(options: ConnectOptions) -> Result<Self> {
        Self::connect_with_oauth(options, || async {
            Err(Error::interface("OAuth token provider is not configured"))
        })
        .await
    }

    /// 新規接続を確立する (OAuth トークンプロバイダ付き)。
    ///
    /// サーバーが OAuth 認証 (OAUTHBEARER) を要求し、トークンが拒否された
    /// 場合に `token_provider` から新しいトークンを取得して
    /// 接続をやり直す。トークンの再取得は最大 3 回まで。
    ///
    /// `token_provider` は呼び出されるたびに新しいトークンを返す。
    /// 初回のトークンは `ConnectOptions::oauth_token` に設定する。
    pub async fn connect_with_oauth<F, Fut>(
        options: ConnectOptions,
        mut token_provider: F,
    ) -> Result<Self>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String>> + Send + 'static,
    {
        // 認証フローで使い回せるように Box 化する。
        let mut provider: OAuthTokenProvider = Box::new(move || Box::pin(token_provider()));
        let inner = InnerConnection::connect(options)?;
        let stream = connect_stream(inner.options()).await?;
        let mut conn = Self {
            inner,
            stream: Some(stream),
            read_buffer: Box::new([0; READ_BUFFER_SIZE]),
            write_buffer: Vec::new(),
            statement_cache: HashMap::new(),
            statement_clock: 0,
            phase: WirePhase::Idle,
            request_ready_sequence: 0,
            request_can_cancel: false,
            transaction_dirty: false,
        };

        conn.authenticate(Some(&mut provider)).await?;

        tracing::info!(
            port = conn.inner.options().port,
            server_version = conn.inner.server_version().unwrap_or("unknown"),
            backend_pid = conn.inner.backend_process_id(),
            "Connected to PostgreSQL server"
        );
        Ok(conn)
    }

    /// 認証フローを実行する。
    ///
    /// sans I/O の状態機械と連携して、
    /// SSL 要求 → TLS アップグレード → スタートアップ →
    /// 認証 → ReadyForQuery まで進める。
    ///
    /// 認証フェーズ全体に `connect_timeout` のタイムアウトを適用する。
    /// サーバーが応答を返さない場合 (起動直後の一時サーバーへの接続等) に
    /// 永久にブロックするのを防ぐ。libpq の `connect_timeout` と同じ挙動。
    ///
    /// OAuth 認証でトークンが拒否された場合は `token_provider` から
    /// 新しいトークンを取得して接続をやり直す。
    async fn authenticate(
        &mut self,
        token_provider: Option<&mut OAuthTokenProvider>,
    ) -> Result<()> {
        let timeout_duration = self.inner.options().connect_timeout;
        tokio::time::timeout(timeout_duration, self.authenticate_inner(token_provider))
            .await
            .map_err(|_| {
                Error::operational(format!(
                    "Authentication timeout after {:?}",
                    timeout_duration
                ))
            })?
    }

    /// OAuth トークンの再取得の上限回数。
    const MAX_OAUTH_RETRIES: u32 = 3;

    /// 認証の試行結果。
    async fn authenticate_inner(
        &mut self,
        mut token_provider: Option<&mut OAuthTokenProvider>,
    ) -> Result<()> {
        let mut oauth_retries = 0;
        loop {
            match self.authenticate_attempt().await {
                Ok(()) => return Ok(()),
                Err(Error::NeedOAuthToken) => {
                    oauth_retries += 1;
                    if oauth_retries > Self::MAX_OAUTH_RETRIES {
                        return Err(Error::operational(format!(
                            "OAuth authentication failed after {} attempts",
                            Self::MAX_OAUTH_RETRIES
                        )));
                    }
                    let provider = token_provider.as_deref_mut().ok_or_else(|| {
                        Error::interface(
                            "The server rejected the OAuth token but no token provider is configured",
                        )
                    })?;
                    let token = provider()
                        .await
                        .map_err(|_| Error::operational("Failed to obtain an OAuth token"))?;
                    tracing::debug!(
                        attempt = oauth_retries,
                        "OAuth token rejected, retrying with a new token"
                    );
                    // サーバーは同一接続での再認証を受け付けないため
                    // (RFC 7628 では kvsep 応答のみ)、接続を張り直す。
                    let mut options = self.inner.options().clone();
                    options.oauth_token = Some(token);
                    let inner = InnerConnection::connect(options.clone())?;
                    let stream = connect_stream(&options).await?;
                    self.inner = inner;
                    self.stream = Some(stream);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 認証を 1 回試行する。
    async fn authenticate_attempt(&mut self) -> Result<()> {
        let mut state = self.inner.request_authentication_start()?;
        let mut ssl_response = self.inner.options().ssl_mode != SslMode::Disabled;
        loop {
            match state {
                AuthState::NeedRead => {
                    // 1 回の read で複数メッセージが届いた場合に備え、
                    // 受信キューが空のときだけ読み込む。
                    if self.inner.is_recv_queue_empty() {
                        if ssl_response {
                            // PostgreSQL 18 §54.2.10 (将来変更される可能性がある)。
                            // TLS ハンドシェイク前の平文を認証応答に混ぜない。
                            self.pump_read_limited(1).await?;
                        } else {
                            self.pump_read().await?;
                        }
                    }
                    ssl_response = false;
                    state = self.inner.request_authentication_continue()?;
                }
                AuthState::Send => {
                    self.pump_write().await?;
                    state = AuthState::NeedRead;
                }
                AuthState::Success => return Ok(()),
            }
            if self.inner.needs_tls_upgrade() {
                self.upgrade_to_tls().await?;
                self.inner.set_secure(true);
                state = self.inner.request_authentication_send_startup()?;
            }
        }
    }

    /// 平文ストリームを TLS ストリームにアップグレードする。
    async fn upgrade_to_tls(&mut self) -> Result<()> {
        let stream = self
            .stream
            .take()
            .ok_or_else(|| Error::interface("No stream to upgrade"))?;
        let plain = match stream {
            ConnectionStream::Plain(s) => s,
            ConnectionStream::Tls(_) => {
                return Err(Error::interface("Already TLS"));
            }
            ConnectionStream::Unix(_) => {
                return Err(Error::interface(
                    "TLS upgrade is not supported on Unix domain sockets",
                ));
            }
        };

        self.stream = Some(establish_tls(plain, self.inner.options()).await?);
        Ok(())
    }

    /// 送信キューの内容をすべて書き込む。
    ///
    /// 拡張クエリでは Bind / Describe / Execute / Sync を別メッセージとして
    /// 積むため、そのまま書くと 1 クエリで 4 回の write が発生する。
    /// 小さなメッセージは 1 回の write にまとめ、システムコールを減らす。
    /// フレームの境界はバイト列に埋め込まれているため、書き込みの分割・結合は
    /// 受信側の走査結果を変えない (shiguredo/lean の Framing.lean の chunkInvariant)。
    async fn pump_write(&mut self) -> Result<()> {
        let Some(first) = self.inner.pop_send_queue() else {
            self.flush().await?;
            return Ok(());
        };
        let Some(second) = self.inner.pop_send_queue() else {
            // メッセージが 1 つだけならコピーせずにそのまま書く。
            self.write_all(&first).await?;
            self.flush().await?;
            return Ok(());
        };

        self.write_buffer.clear();
        if first.len() >= WRITE_COALESCE_LIMIT {
            self.write_all(&first).await?;
        } else {
            self.write_buffer.extend_from_slice(&first);
        }
        if second.len() >= WRITE_COALESCE_LIMIT {
            self.flush_write_buffer().await?;
            self.write_all(&second).await?;
        } else {
            if self.write_buffer.len() + second.len() > WRITE_COALESCE_LIMIT {
                self.flush_write_buffer().await?;
            }
            self.write_buffer.extend_from_slice(&second);
        }

        while let Some(data) = self.inner.pop_send_queue() {
            // 大きなメッセージはコピーせず、そのまま書く。
            if data.len() >= WRITE_COALESCE_LIMIT {
                self.flush_write_buffer().await?;
                self.write_all(&data).await?;
                continue;
            }
            if self.write_buffer.len() + data.len() > WRITE_COALESCE_LIMIT {
                self.flush_write_buffer().await?;
            }
            self.write_buffer.extend_from_slice(&data);
        }
        self.flush_write_buffer().await?;
        self.flush().await?;
        Ok(())
    }

    /// まとめた送信バッファを書き出す。
    async fn flush_write_buffer(&mut self) -> Result<()> {
        if self.write_buffer.is_empty() {
            return Ok(());
        }
        // self を可変借用したままバッファを渡せないため、一度取り出して戻す。
        // 容量はそのまま残るので、次の要求で確保し直さない。
        let mut buffer = std::mem::take(&mut self.write_buffer);
        let result = self.write_all(&buffer).await;
        buffer.clear();
        self.write_buffer = buffer;
        result
    }

    /// サーバーからデータを読み込み、内部の受信バッファに供給する。
    ///
    /// 受信バッファに完全なメッセージが蓄積されるまで繰り返し読み込む。
    async fn pump_read(&mut self) -> Result<()> {
        self.pump_read_limited(self.read_buffer.len()).await
    }

    async fn pump_read_limited(&mut self, limit: usize) -> Result<()> {
        loop {
            let read = match self.stream.as_mut() {
                Some(stream) => stream.read(&mut self.read_buffer[..limit]).await,
                None => return Err(Error::interface("No stream available")),
            };
            let n = match read {
                Ok(0) => {
                    self.force_close();
                    return Err(Error::operational(
                        "Lost connection to PostgreSQL server during query",
                    ));
                }
                Ok(n) => n,
                Err(e) => {
                    self.force_close();
                    return Err(Error::operational(format!(
                        "Lost connection to PostgreSQL server during query ({})",
                        e
                    )));
                }
            };
            tracing::debug!(n, "pump_read received");
            let added = match self.inner.feed_bytes(&self.read_buffer[..n]) {
                Ok(added) => added,
                Err(error) => {
                    self.force_close();
                    return Err(error);
                }
            };
            if added > 0 {
                break;
            }
        }
        Ok(())
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self.stream.as_mut() {
            Some(stream) => stream.write_all(data).await,
            None => {
                return Err(Error::interface("No stream available"));
            }
        }
        .map_err(|e| {
            self.force_close();
            Error::operational(format!("Failed to write to PostgreSQL server ({})", e))
        })
    }

    async fn flush(&mut self) -> Result<()> {
        match self.stream.as_mut() {
            Some(stream) => stream.flush().await,
            None => {
                return Err(Error::interface("No stream available"));
            }
        }
        .map_err(|e| {
            self.force_close();
            Error::operational(format!("Failed to flush to PostgreSQL server ({})", e))
        })
    }

    /// 新しい要求を始める。ストリーム行の読み残しだけは安全に回収できる。
    async fn ensure_idle(&mut self) -> Result<()> {
        if !self.is_open() {
            return Err(Error::interface("Connection is closed"));
        }
        match self.phase {
            WirePhase::Idle => Ok(()),
            WirePhase::Rows => self.finish_rows().await,
            WirePhase::CopyIn
            | WirePhase::CopyInFinished
            | WirePhase::CopyOut
            | WirePhase::CopyOutFinished => Err(Error::interface("COPY is still in progress")),
            WirePhase::Writing | WirePhase::Reading | WirePhase::Recovering => {
                self.force_close();
                Err(Error::interface(
                    "Connection was interrupted before synchronization",
                ))
            }
        }
    }

    /// 要求をキューに積んでから、最初の await より先に書き込み中と記録する。
    async fn start_request<F>(&mut self, can_cancel: bool, send: F) -> Result<()>
    where
        F: FnOnce(&mut InnerConnection) -> Result<()>,
    {
        self.ensure_idle().await?;
        send(&mut self.inner)?;
        self.write_request(can_cancel).await
    }

    /// 新しい要求の同期番号を記録して送信する。
    async fn write_request(&mut self, can_cancel: bool) -> Result<()> {
        self.request_ready_sequence = self.inner.ready_sequence();
        self.request_can_cancel = can_cancel;
        self.write_pending().await
    }

    /// 新しい要求または継続中の COPY フレームを書き切る。
    async fn write_pending(&mut self) -> Result<()> {
        self.phase = WirePhase::Writing;
        self.pump_write().await?;
        self.phase = WirePhase::Reading;
        Ok(())
    }

    fn saw_ready(&self) -> bool {
        self.request_ready_sequence != self.inner.ready_sequence()
    }

    /// 未読の応答を捨て、現在の要求に対応する ReadyForQuery を確認する。
    async fn recover_ready(&mut self) -> Result<()> {
        self.phase = WirePhase::Recovering;
        if !self.saw_ready() {
            self.read_until(InnerConnection::drain_to_ready).await?;
        }
        if !self.saw_ready() {
            return Err(Error::internal("Missing ReadyForQuery during recovery"));
        }
        self.phase = WirePhase::Idle;
        Ok(())
    }

    /// 結果を公開する前に、同期済みか明示的に継続可能な段階かを確定する。
    async fn finish_response<T>(
        &mut self,
        result: Result<T>,
        continuation: WirePhase,
    ) -> Result<T> {
        if self.saw_ready() {
            self.phase = WirePhase::Idle;
            return result;
        }
        match result {
            Ok(value) if continuation != WirePhase::Idle => {
                self.phase = continuation;
                Ok(value)
            }
            Ok(_) => {
                self.force_close();
                Err(Error::internal("Missing ReadyForQuery after response"))
            }
            Err(error) => {
                // 正常なサーバーエラーには同期応答が続く。ローカルエラーでは
                // プロトコル上の位置を確定できないため、この接続を閉じる。
                if error.code().is_none_or(str::is_empty) || self.recover_ready().await.is_err() {
                    self.force_close();
                }
                Err(error)
            }
        }
    }

    fn require_phase(&self, expected: WirePhase) -> Result<()> {
        if !self.is_open() {
            return Err(Error::interface("Connection is closed"));
        }
        if self.phase != expected {
            return Err(Error::interface(
                "Operation is not valid in the current connection state",
            ));
        }
        Ok(())
    }

    /// 読み込みが `NeedMoreData` で中断した場合は受信してから再試行する。
    async fn read_until<T, F>(&mut self, read: F) -> Result<T>
    where
        F: Fn(&mut InnerConnection) -> Result<T>,
    {
        loop {
            match read(&mut self.inner) {
                Ok(value) => return Ok(value),
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
    }

    /// 結果セットを読み込む。
    async fn read_query_result(&mut self, unbuffered: bool) -> Result<i64> {
        loop {
            match self.inner.read_query_result(unbuffered) {
                Ok(affected) => return Ok(affected),
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
    }

    /// クエリを実行する (単純クエリプロトコル)。
    pub async fn query(&mut self, sql: &str, unbuffered: bool) -> Result<i64> {
        tracing::debug!(unbuffered, "Executing query");
        self.start_request(true, |inner| inner.send_query(sql))
            .await?;
        self.finish_query(unbuffered).await
    }

    /// バッファード結果の完了、または最初の行セットの読み出し開始を確定する。
    async fn finish_query(&mut self, unbuffered: bool) -> Result<i64> {
        let result = self.read_query_result(unbuffered).await;
        let continuation = if unbuffered {
            WirePhase::Rows
        } else {
            WirePhase::Idle
        };
        self.finish_response(result, continuation).await
    }

    /// パラメーター付きクエリを実行する (拡張クエリプロトコル)。
    ///
    /// 自動準備する文は `statement_cache_capacity` 件まで保持する。
    /// 容量が 0 の場合は `execute_uncached` と同じ動作になる。
    /// キャッシュ済みの文が Bind 完了前に失効し、接続が同期済みかつ
    /// トランザクション外であれば、一度だけ再準備して実行する。
    pub async fn execute(&mut self, sql: &str, args: &[Value], unbuffered: bool) -> Result<i64> {
        self.execute_with_types(sql, &[], args, unbuffered).await
    }

    /// パラメーターの型 OID を明示してクエリを実行する (拡張クエリプロトコル)。
    ///
    /// `$1` の型が SQL の文脈だけでは決まらない場合に使う。
    /// `parameter_oids` の要素数は `args` の要素数と一致する必要がある。
    /// 同じ SQL でも型 OID が異なる場合は別の文としてキャッシュする。
    pub async fn execute_typed(
        &mut self,
        sql: &str,
        parameter_oids: &[u32],
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.execute_with_types(sql, parameter_oids, args, unbuffered)
            .await
    }

    /// 型 OID の指定を伴う実行の本体。
    async fn execute_with_types(
        &mut self,
        sql: &str,
        parameter_oids: &[u32],
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        if !parameter_oids.is_empty() && parameter_oids.len() != args.len() {
            return Err(Error::interface(format!(
                "Parameter type count mismatch: expected {}, got {}",
                args.len(),
                parameter_oids.len()
            )));
        }
        if self.inner.options().statement_cache_capacity == 0 {
            if parameter_oids.is_empty() {
                return self.execute_uncached(sql, args, unbuffered).await;
            }
            return self
                .execute_uncached_typed(sql, parameter_oids, args, unbuffered)
                .await;
        }
        let key = StatementKey::new(sql, parameter_oids);
        self.ensure_idle().await?;
        self.cache_statement(&key, args.len()).await?;
        let result = self.execute_cached(&key, args, unbuffered).await;
        let invalidated_before_execution = result.as_ref().err().is_some_and(|error| {
            matches!(error.code(), Some("26000" | "0A000")) && !self.inner.bind_complete_seen()
        });
        if invalidated_before_execution
            && self.is_open()
            && self.phase == WirePhase::Idle
            && self.transaction_status() == crate::constants::transaction_status::IDLE
        {
            // Close は存在しなくなった文名に対しても安全に完了する。
            self.evict_statement(&key).await?;
            self.cache_statement(&key, args.len()).await?;
            return self.execute_cached(&key, args, unbuffered).await;
        }
        result
    }

    /// 名前付きステートメントを作らず、パースから実行までを 1 往復で送信する。
    ///
    /// 既存のキャッシュを参照せず、実行結果もキャッシュに追加しない。
    pub async fn execute_uncached(
        &mut self,
        sql: &str,
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.start_request(true, |inner| inner.send_execute(sql, args))
            .await?;
        self.finish_query(unbuffered).await
    }

    /// パラメーターの型 OID を明示し、キャッシュを使わずに実行する。
    pub async fn execute_uncached_typed(
        &mut self,
        sql: &str,
        parameter_oids: &[u32],
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.start_request(true, |inner| {
            inner.send_execute_typed(sql, parameter_oids, args)
        })
        .await?;
        self.finish_query(unbuffered).await
    }

    /// クエリを実行し、ちょうど 1 行を取得する。
    ///
    /// 0 行または 2 行以上を返した場合はエラーになる。
    /// 0 行を許す場合は [`Connection::query_opt`] を使う。
    pub async fn query_one(&mut self, sql: &str, args: &[Value]) -> Result<crate::row::Row> {
        self.execute(sql, args, false).await?;
        let (fields, rows) = self.take_result_rows()?;
        let count = rows.len();
        match count {
            1 => Ok(crate::row::Row::new(
                fields,
                rows.into_iter()
                    .next()
                    .expect("Rows has exactly one element as checked above"),
            )),
            0 => Err(Error::interface("Query returned no rows")),
            _ => Err(Error::interface(format!(
                "Query returned {count} rows but exactly one was expected"
            ))),
        }
    }

    /// クエリを実行し、0 行または 1 行を取得する。
    ///
    /// 2 行以上を返した場合はエラーになる。
    pub async fn query_opt(
        &mut self,
        sql: &str,
        args: &[Value],
    ) -> Result<Option<crate::row::Row>> {
        self.execute(sql, args, false).await?;
        let (fields, rows) = self.take_result_rows()?;
        let count = rows.len();
        match count {
            0 => Ok(None),
            1 => Ok(Some(crate::row::Row::new(
                fields,
                rows.into_iter()
                    .next()
                    .expect("Rows has exactly one element as checked above"),
            ))),
            _ => Err(Error::interface(format!(
                "Query returned {count} rows but at most one was expected"
            ))),
        }
    }

    /// 実行済みの結果セットを取り出し、フィールドと行に分ける。
    fn take_result_rows(
        &mut self,
    ) -> Result<(Vec<crate::protocol::FieldDescription>, Vec<Vec<Value>>)> {
        let result = self
            .inner
            .take_result()
            .ok_or_else(|| Error::internal("Query result is not available"))?;
        Ok((result.fields, result.rows))
    }

    /// 利用者が管理するステートメントを準備する。
    ///
    /// 文は作成元の接続に属する。不要になった文は `deallocate` で解放する。
    pub async fn prepare(&mut self, sql: &str) -> Result<PreparedStatement> {
        self.start_request(false, |inner| inner.send_prepare(sql))
            .await?;
        let result = self.read_until(InnerConnection::read_prepare_result).await;
        if result.is_err() && self.inner.parse_complete_seen() {
            // Parse が成功していても、メタデータを確定できなかった文は管理できない。
            self.force_close();
            return result;
        }
        self.finish_response(result, WirePhase::Idle).await
    }

    /// パラメーターの型 OID を明示してステートメントを準備する。
    ///
    /// サーバーが返した型 OID が指定と異なる場合はエラーになる。
    pub async fn prepare_typed(
        &mut self,
        sql: &str,
        parameter_oids: &[u32],
    ) -> Result<PreparedStatement> {
        self.start_request(false, |inner| inner.send_prepare_typed(sql, parameter_oids))
            .await?;
        let result = self.read_until(InnerConnection::read_prepare_result).await;
        let result = match result {
            // 型を指定した場合だけ、サーバーが返した型と一致するか確認する。
            // 指定がない場合はサーバーが推論した型をそのまま使う。
            Ok(statement)
                if !parameter_oids.is_empty() && statement.parameter_oids() != parameter_oids =>
            {
                // 指定と異なる型で準備された文は、呼び出し側の期待と一致しない。
                let error = Error::interface(format!(
                    "Prepared statement parameter types differ from the requested types: requested {:?}, got {:?}",
                    parameter_oids,
                    statement.parameter_oids()
                ));
                self.force_close();
                Err(error)
            }
            other => other,
        };
        if result.is_err() && self.inner.parse_complete_seen() {
            // Parse が成功していても、メタデータを確定できなかった文は管理できない。
            self.force_close();
            return result;
        }
        self.finish_response(result, WirePhase::Idle).await
    }

    /// 同じ接続で準備したステートメントを実行する。
    ///
    /// 明示的に準備した文は自動で再準備しない。失効時には準備し直す。
    pub async fn execute_prepared(
        &mut self,
        statement: &PreparedStatement,
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.check_statement_owner(statement)?;
        self.start_request(true, |inner| inner.send_execute_prepared(statement, args))
            .await?;
        self.finish_query(unbuffered).await
    }

    /// 同じ接続で明示的に準備した文をサーバー側で解放する。
    pub async fn deallocate(&mut self, statement: &PreparedStatement) -> Result<()> {
        self.check_statement_owner(statement)?;
        self.deallocate_name(statement.name()).await
    }

    fn check_statement_owner(&self, statement: &PreparedStatement) -> Result<()> {
        if self.inner.owns_statement(statement) {
            Ok(())
        } else {
            Err(Error::interface(
                "Prepared statement belongs to another connection",
            ))
        }
    }

    async fn deallocate_name(&mut self, name: &str) -> Result<()> {
        self.start_request(false, |inner| inner.send_deallocate(name))
            .await?;
        let result = self
            .read_until(InnerConnection::read_deallocate_result)
            .await;
        self.finish_response(result, WirePhase::Idle).await
    }

    async fn cache_statement(&mut self, key: &StatementKey, argument_count: usize) -> Result<()> {
        if self.statement_cache.contains_key(key) {
            return Ok(());
        }
        // 先に追い出すので、キャッシュとサーバー上の自動準備文の両方を上限内に保つ。
        if self.statement_cache.len() >= self.inner.options().statement_cache_capacity {
            let oldest = self
                .statement_cache
                .iter()
                .max_by_key(|(_, entry)| self.statement_clock.wrapping_sub(entry.last_used))
                .map(|(key, _)| key.clone())
                .ok_or_else(|| Error::internal("Statement cache is unexpectedly empty"))?;
            self.evict_statement(&oldest).await?;
        }
        let statement = self.prepare_typed(&key.sql, &key.parameter_oids).await?;
        if statement.parameter_oids().len() != argument_count {
            let expected = statement.parameter_oids().len();
            self.deallocate_name(statement.name()).await?;
            return Err(Error::interface(format!(
                "Parameter count mismatch: expected {expected}, got {argument_count}"
            )));
        }
        self.statement_cache.insert(
            key.clone(),
            CachedStatement {
                statement,
                last_used: self.statement_clock,
            },
        );
        Ok(())
    }

    async fn evict_statement(&mut self, key: &StatementKey) -> Result<()> {
        if let Some(entry) = self.statement_cache.remove(key)
            && let Err(error) = self.deallocate_name(entry.statement.name()).await
        {
            // 解放を確認できない文をサーバーに蓄積させない。
            self.force_close();
            return Err(error);
        }
        Ok(())
    }

    async fn execute_cached(
        &mut self,
        key: &StatementKey,
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        let entry = self
            .statement_cache
            .get_mut(key)
            .ok_or_else(|| Error::internal("Cached statement not found"))?;
        self.statement_clock = self.statement_clock.wrapping_add(1);
        entry.last_used = self.statement_clock;
        self.inner.send_execute_prepared(&entry.statement, args)?;
        self.write_request(true).await?;
        self.finish_query(unbuffered).await
    }

    /// バッチクエリを実行する。
    ///
    /// 複数のステートメントを 1 往復で送信する。
    /// 戻り値の長さはバッチ内のステートメント数と同じで、
    /// ステートメントごとの影響行数またはエラーを持つ。
    /// 途中のステートメントでエラーが起きた場合、後続のステートメントは
    /// サーバーで実行されず、未実行を表すエラーが入る。
    pub async fn batch_execute(&mut self, batch: Batch) -> Result<Vec<Result<i64>>> {
        let statements = batch.into_statements();
        let count = statements.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        tracing::debug!(statement_count = count, "Executing batch");
        self.start_request(false, |inner| inner.send_batch(&statements))
            .await?;
        let result = self
            .read_until(|inner| inner.read_batch_results(count))
            .await;
        self.finish_response(result, WirePhase::Idle).await
    }

    /// バッチクエリを実行し、ステートメントごとの結果セットを返す。
    ///
    /// 複数の `SELECT` や `RETURNING` の行をステートメントごとに取得できる。
    /// 1 往復で送信するが、結果はすべて読み込んでから返す。
    /// 途中のステートメントでエラーが起きた場合、後続のステートメントは
    /// サーバーで実行されず、未実行を表すエラーが入る。
    pub async fn batch_execute_rows(&mut self, batch: Batch) -> Result<Vec<Result<QueryResult>>> {
        let statements = batch.into_statements();
        let count = statements.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        tracing::debug!(statement_count = count, "Executing batch with rows");
        self.start_request(false, |inner| inner.send_batch(&statements))
            .await?;
        let result = self
            .read_until(|inner| inner.read_batch_row_results())
            .await;
        self.finish_response(result, WirePhase::Idle).await
    }

    /// CopyIn を実行する。
    ///
    /// `sql` は `COPY ... FROM STDIN` 形式の SQL で、`data` は COPY の
    /// 行データ (テキストまたはバイナリ形式) 全体を渡す。
    /// 影響を受けた行数を返す。
    ///
    /// 大きなデータを扱う場合は `copy_in_begin` / `send_copy_data` /
    /// `send_copy_done` / `finish_copy_in` で分割送信する。
    pub async fn copy_in(&mut self, sql: &str, data: &[u8]) -> Result<i64> {
        self.copy_in_begin(sql).await?;
        self.send_copy_data(data).await?;
        self.send_copy_done().await?;
        self.finish_copy_in().await
    }

    /// CopyIn を開始する。
    ///
    /// サーバーが CopyIn を受け付けるまで待つ。
    /// その後 `send_copy_data` でデータを送り、
    /// `send_copy_done` の後に `finish_copy_in` で結果を読み込む。
    pub async fn copy_in_begin(&mut self, sql: &str) -> Result<()> {
        self.start_request(false, |inner| inner.send_copy_in(sql))
            .await?;
        let response = self
            .read_until(InnerConnection::read_copy_in_response)
            .await;
        self.finish_response(response, WirePhase::CopyIn).await?;
        Ok(())
    }

    /// CopyIn 中のデータを送信する。
    pub async fn send_copy_data(&mut self, data: &[u8]) -> Result<()> {
        self.require_phase(WirePhase::CopyIn)?;
        self.inner.send_copy_data(data)?;
        self.write_pending().await?;
        self.phase = WirePhase::CopyIn;
        Ok(())
    }

    /// CopyIn の完了を送信する。
    pub async fn send_copy_done(&mut self) -> Result<()> {
        self.require_phase(WirePhase::CopyIn)?;
        self.inner.send_copy_done()?;
        self.write_pending().await?;
        self.phase = WirePhase::CopyInFinished;
        Ok(())
    }

    /// CopyIn の失敗を送信する。
    ///
    /// `finish_copy_in` でエラー応答と同期応答を回収するまで、接続は再利用できない。
    pub async fn send_copy_fail(&mut self, message: &str) -> Result<()> {
        self.require_phase(WirePhase::CopyIn)?;
        self.inner.send_copy_fail(message)?;
        self.write_pending().await?;
        self.phase = WirePhase::CopyInFinished;
        Ok(())
    }

    /// CopyIn の結果と同期応答を読み込む。
    pub async fn finish_copy_in(&mut self) -> Result<i64> {
        self.require_phase(WirePhase::CopyInFinished)?;
        self.phase = WirePhase::Reading;
        let result = self.read_until(InnerConnection::finish_copy_in).await;
        self.finish_response(result, WirePhase::Idle).await
    }

    /// CopyOut を実行してすべてのデータを取得する。
    ///
    /// `sql` は `COPY ... TO STDOUT` 形式の SQL。
    /// 大きなデータを扱う場合は `copy_out_begin` / `read_copy_out_data` で
    /// 分割読み込みする。
    pub async fn copy_out(&mut self, sql: &str) -> Result<Vec<u8>> {
        self.copy_out_begin(sql).await?;
        let mut all = Vec::new();
        while let Some(data) = self.read_copy_out_data().await? {
            all.extend_from_slice(&data);
        }
        self.finish_copy_out().await?;
        Ok(all)
    }

    /// CopyOut を開始する。
    ///
    /// サーバーが CopyOut を受け付けるまで待つ。
    /// その後 `read_copy_out_data` でデータを読み、
    /// `None` が返ったら `finish_copy_out` で結果を読み込む。
    pub async fn copy_out_begin(&mut self, sql: &str) -> Result<()> {
        self.start_request(false, |inner| inner.send_copy_out(sql))
            .await?;
        let response = self
            .read_until(InnerConnection::read_copy_out_response)
            .await;
        self.finish_response(response, WirePhase::CopyOut).await?;
        Ok(())
    }

    /// CopyOut 中のデータを一つ読み込む。
    ///
    /// データが 1 つ届くたびに `Some(data)` を返し、
    /// CopyOut の終了時に `None` を返す。
    pub async fn read_copy_out_data(&mut self) -> Result<Option<Vec<u8>>> {
        self.require_phase(WirePhase::CopyOut)?;
        self.phase = WirePhase::Reading;
        let result = self.read_until(InnerConnection::read_copy_out_data).await;
        let continuation = if matches!(result, Ok(None)) {
            WirePhase::CopyOutFinished
        } else {
            WirePhase::CopyOut
        };
        self.finish_response(result, continuation).await
    }

    /// CopyOut の結果と同期応答を読み込む。
    pub async fn finish_copy_out(&mut self) -> Result<i64> {
        self.require_phase(WirePhase::CopyOutFinished)?;
        self.phase = WirePhase::Reading;
        let result = self.read_until(InnerConnection::finish_copy_out).await;
        self.finish_response(result, WirePhase::Idle).await
    }

    /// `unbuffered = true` で開始したクエリの最初の結果セットから次の行を取得する。
    ///
    /// 最初の結果セットを読み切ったときは残りの結果セットをバッファせずに
    /// 同期応答まで処理し、`None` を返す。サーバーエラーはその時点で返す。
    /// 読み取りを途中でやめる場合は `finish_rows` で読み残しを破棄できる。
    pub async fn next_row(&mut self) -> Result<Option<Vec<Value>>> {
        if self.is_open() && self.phase == WirePhase::Idle {
            return Ok(None);
        }
        self.require_phase(WirePhase::Rows)?;
        self.phase = WirePhase::Reading;
        let result = self.read_until(InnerConnection::read_next_row).await;
        let continuation = if matches!(result, Ok(None)) {
            WirePhase::Idle
        } else {
            WirePhase::Rows
        };
        self.finish_response(result, continuation).await
    }

    /// 未読のストリーム行と後続結果セットを破棄し、接続を同期する。
    ///
    /// ポータルを中断する操作ではない。サーバーが処理を終えるまで待機する。
    /// 未読のクエリエラーは破棄し、プロトコルや通信のエラーは呼び出し元に返す。
    pub async fn finish_rows(&mut self) -> Result<()> {
        if self.is_open() && self.phase == WirePhase::Idle {
            return Ok(());
        }
        self.require_phase(WirePhase::Rows)?;
        let result = self.recover_ready().await;
        if result.is_err() {
            self.force_close();
        }
        result
    }

    /// サーバーへの疎通を確認する。
    ///
    /// 空のクエリを送信してサーバーの応答を確認する。
    pub async fn ping(&mut self) -> Result<()> {
        self.query("", false).await?;
        Ok(())
    }

    /// トランザクションを開始する。
    ///
    /// 既にトランザクション内の場合はエラーを返す。
    /// トランザクションを閉じるときは `Transaction::commit` または
    /// `Transaction::rollback` を呼ぶ。
    /// どちらも呼ばずに破棄した場合は、次の `begin()` 時に
    /// ロールバックされてから開始される。
    pub async fn begin(&mut self) -> Result<crate::transaction::Transaction<'_>> {
        crate::transaction::Transaction::begin(self).await
    }

    /// トランザクションを開始する (オプション指定)。
    pub async fn begin_with(
        &mut self,
        options: crate::transaction::TxOptions,
    ) -> Result<crate::transaction::Transaction<'_>> {
        crate::transaction::Transaction::begin_with(self, options).await
    }

    /// 次の非同期通知を待つ。
    ///
    /// 事前に `LISTEN` クエリを実行しておくこと。
    /// クエリ実行中でないアイドル状態で呼び出すこと。
    /// クエリ結果の読み残しがある状態では動作しない。
    pub async fn next_notification(&mut self) -> Result<Notification> {
        self.require_phase(WirePhase::Idle)?;
        loop {
            if let Some(notification) = self.inner.pop_notification() {
                return Ok(notification);
            }
            // 受信キューにメッセージがあれば処理し、なければ読み込む。
            if self.inner.is_recv_queue_empty() {
                self.pump_read().await?;
            }
            match self.inner.read_query_packet() {
                Ok(Some(_)) => {
                    self.force_close();
                    return Err(Error::internal(
                        "Unexpected message while waiting for notification",
                    ));
                }
                Ok(None) | Err(Error::NeedMoreData) => continue,
                Err(error) => {
                    self.force_close();
                    return Err(error);
                }
            }
        }
    }

    /// 受信済みの非同期通知をすべて取り出す。
    pub fn drain_notifications(&mut self) -> Vec<Notification> {
        self.inner.drain_notifications()
    }

    /// 受信した NOTICE を一つ取り出す。
    ///
    /// クエリ実行中にサーバーが送ってきた NOTICE (警告等) を取得する。
    pub fn pop_notice(&mut self) -> Option<crate::protocol::NoticeResponse> {
        self.inner.pop_notice()
    }

    /// クエリをタイムアウト付きで実行する (単純クエリプロトコル)。
    ///
    /// タイムアウトはエラーを返す。要求を送り終えた場合はキャンセルを試み、
    /// 同期を確認できない場合は接続を閉じる。サーバー側の実行結果は保証しない。
    pub async fn query_with_timeout(
        &mut self,
        sql: &str,
        unbuffered: bool,
        timeout_duration: Duration,
    ) -> Result<i64> {
        match timeout(timeout_duration, self.query(sql, unbuffered)).await {
            Ok(result) => result,
            Err(_) => Err(self.handle_query_timeout(timeout_duration).await),
        }
    }

    /// パラメータ付きクエリをタイムアウト付きで実行する (拡張クエリプロトコル)。
    ///
    /// タイムアウトはエラーを返す。要求を送り終えた場合はキャンセルを試み、
    /// 同期を確認できない場合は接続を閉じる。サーバー側の実行結果は保証しない。
    pub async fn execute_with_timeout(
        &mut self,
        sql: &str,
        args: &[Value],
        unbuffered: bool,
        timeout_duration: Duration,
    ) -> Result<i64> {
        match timeout(timeout_duration, self.execute(sql, args, unbuffered)).await {
            Ok(result) => result,
            Err(_) => Err(self.handle_query_timeout(timeout_duration).await),
        }
    }

    async fn handle_query_timeout(&mut self, duration: Duration) -> Error {
        if self.phase != WirePhase::Idle
            && self.is_open()
            && let Err(error) = self.cancel_request().await
        {
            tracing::debug!(%error, "Closing interrupted PostgreSQL connection");
        }
        Error::operational(format!("Query timed out after {duration:?}"))
    }

    /// 応答待ちで中断されたクエリ、または読み取り中の行ストリームをキャンセルする。
    ///
    /// クエリの Future が接続を借りたまま並行して呼ぶことはできない。
    /// 書き込みの完了が不明、準備済み文の管理中、COPY 中の場合は接続を閉じる。
    /// アイドル状態ではキャンセルを送信しない。
    pub async fn cancel_request(&mut self) -> Result<()> {
        if !self.is_open() || self.phase == WirePhase::Idle {
            return Err(Error::interface(
                "No interruptible query on this connection",
            ));
        }
        if !self.request_can_cancel || !matches!(self.phase, WirePhase::Reading | WirePhase::Rows) {
            self.force_close();
            return Err(Error::interface(
                "Interrupted connection cannot be recovered safely",
            ));
        }
        self.phase = WirePhase::Recovering;
        let recovery = async {
            self.send_cancel_request().await?;
            let canceled = self
                .read_until(InnerConnection::drain_canceled_request)
                .await?;
            if !canceled || !self.saw_ready() {
                return Err(Error::operational("Query cancellation was not confirmed"));
            }
            Ok(())
        };
        let result = match timeout(CANCEL_RECOVERY_TIMEOUT, recovery).await {
            Ok(result) => result,
            Err(_) => Err(Error::operational(
                "Timed out recovering after cancel request",
            )),
        };
        if result.is_ok() {
            self.phase = WirePhase::Idle;
        } else {
            self.force_close();
        }
        result
    }

    /// 別接続で CancelRequest を送信し、サーバーがその接続を閉じるまで待つ。
    async fn send_cancel_request(&mut self) -> Result<()> {
        self.cancel_token()?.cancel().await
    }

    /// 実行中のクエリを別タスクからキャンセルするためのトークンを作る。
    ///
    /// トークンは元の接続の接続先、TLS の設定、バックエンドのキーを保持する。
    /// トークンを作った時点の接続が閉じた後でも作れるが、対象のクエリは
    /// 既に終わっている可能性がある。
    pub fn cancel_token(&self) -> Result<CancelToken> {
        fn io_error(error: io::Error) -> Error {
            Error::operational(format!("Cancel request transport failed: {error}"))
        }
        let process_id = self.inner.backend_process_id();
        if process_id == 0 {
            return Err(Error::operational(
                "No backend cancellation key was supplied",
            ));
        }
        // PostgreSQL 18 §54.2.8 / §54.2.10。将来、プロトコル仕様が変わる可能性がある。
        // 接続先は確立済みストリームのピアから取り、キャンセル時に DNS を引き直さない。
        let target = match self.stream.as_ref() {
            Some(ConnectionStream::Plain(plain)) => CancelTarget::Tcp {
                addr: plain.peer_addr().map_err(io_error)?,
                tls: false,
            },
            Some(ConnectionStream::Tls(original)) => CancelTarget::Tcp {
                addr: original.get_ref().0.peer_addr().map_err(io_error)?,
                tls: true,
            },
            Some(ConnectionStream::Unix(_)) => CancelTarget::Unix,
            None => return Err(Error::interface("No stream to cancel")),
        };
        Ok(CancelToken {
            options: self.inner.options().clone(),
            target,
            process_id,
            secret_key: self.inner.backend_secret_key(),
        })
    }

    /// カーソルを作成する。
    pub fn cursor(&mut self) -> crate::cursor::Cursor<'_> {
        crate::cursor::Cursor::new(self)
    }

    /// 接続を閉じる。未同期の場合は追加のプロトコルメッセージを送らず破棄する。
    pub async fn close(&mut self) -> Result<()> {
        if !self.is_open() || self.is_busy() {
            self.force_close();
            return Ok(());
        }
        self.inner.close()?;
        let result = self.pump_write().await;
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        self.statement_cache.clear();
        result
    }

    /// 強制的に接続を閉じる。
    ///
    /// Terminate の送信やストリームの graceful shutdown を行わず、
    /// 即座に接続を破棄する。
    pub fn force_close(&mut self) {
        self.inner.force_close();
        self.stream.take();
        self.statement_cache.clear();
    }

    /// 自動準備した文のキャッシュを空にする。
    ///
    /// サーバー側のプリペアドステートメントを破棄した後 (`DISCARD ALL` 等) に呼ぶ。
    pub(crate) fn clear_statement_cache(&mut self) {
        self.statement_cache.clear();
    }

    /// 接続が開いているかどうか。
    pub fn is_open(&self) -> bool {
        self.inner.is_open() && self.stream.is_some()
    }

    /// 要求の送信開始から同期応答の受信まで、または回復中であるかどうか。
    pub fn is_busy(&self) -> bool {
        self.phase != WirePhase::Idle
    }

    /// サーバーバージョンを取得する。
    pub fn server_version(&self) -> Option<&str> {
        self.inner.server_version()
    }

    /// バックエンドプロセス ID を取得する。
    pub fn backend_process_id(&self) -> u32 {
        self.inner.backend_process_id()
    }

    /// 現在のトランザクション状態を取得する。
    pub fn transaction_status(&self) -> u8 {
        self.inner.transaction_status()
    }

    /// 現在の結果セットを取得する。
    pub fn result(&self) -> Option<&QueryResult> {
        self.inner.result()
    }

    /// 現在の結果セットを可変で取得する。
    ///
    /// 逐次取得する場合は `next_row` を使う。このメソッドでは通信しない。
    pub fn result_mut(&mut self) -> Option<&mut QueryResult> {
        self.inner.result_mut()
    }

    /// 型 OID に対応するデコーダを登録する。
    ///
    /// 登録したデコーダは組み込みのデコーダより優先される。
    pub fn register_converter(&mut self, type_oid: u32, converter: crate::converters::Converter) {
        self.inner.register_converter(type_oid, converter);
    }

    /// トランザクションの破棄を記録する。
    ///
    /// `Transaction` が commit / rollback されずに破棄されたときに呼ばれる。
    pub(crate) fn mark_transaction_dirty(&mut self) {
        self.transaction_dirty = true;
    }

    /// 破棄されたトランザクションをロールバックする。
    ///
    /// 次のトランザクション開始前に呼ぶ。
    pub(crate) async fn rollback_dirty_transaction(&mut self) -> Result<()> {
        // 結果の読み残しがあるときは、同期前のトランザクション状態で判断しない。
        self.ensure_idle().await?;
        if !self.transaction_dirty {
            return Ok(());
        }
        if self.transaction_status() != crate::constants::transaction_status::IDLE {
            self.query("ROLLBACK", false).await?;
            if self.transaction_status() != crate::constants::transaction_status::IDLE {
                self.force_close();
                return Err(Error::internal("Connection is not idle after rollback"));
            }
        }
        self.transaction_dirty = false;
        Ok(())
    }
}

/// 接続先のストリームを確立する。
async fn connect_stream(options: &ConnectOptions) -> Result<ConnectionStream> {
    if options.host.starts_with('/') {
        // Unix ドメインソケット。libpq と同じく
        // ソケットファイルは `<host>/.s.PGSQL.<port>` にある。
        let host = options.host.trim_end_matches('/');
        let path = format!("{}/.s.PGSQL.{}", host, options.port);
        let stream = timeout(options.connect_timeout, UnixStream::connect(&path))
            .await
            .map_err(|e| {
                Error::operational(format!(
                    "Connection timeout to Unix domain socket {} ({})",
                    path, e
                ))
            })?
            .map_err(|e| {
                Error::operational(format!(
                    "Can't connect to PostgreSQL server on Unix domain socket {} ({})",
                    path, e
                ))
            })?;
        return Ok(ConnectionStream::Unix(stream));
    }
    let addr = match std::net::IpAddr::from_str(&options.host) {
        Ok(ip) if ip.is_ipv6() => format!("[{}]:{}", options.host, options.port),
        _ => format!("{}:{}", options.host, options.port),
    };
    let connect = async {
        if options.ssl_mode == SslMode::Disabled && options.host.eq_ignore_ascii_case("localhost") {
            // ローカル開発用の名前だけは DNS や hosts ファイルを参照せず、ループバックに固定する。
            let loopback = [
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, options.port)),
                std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, options.port)),
            ];
            TcpStream::connect(loopback.as_slice()).await
        } else {
            TcpStream::connect(&addr).await
        }
    };
    let stream = timeout(options.connect_timeout, connect)
        .await
        .map_err(|e| {
            Error::operational(format!(
                "Connection timeout to PostgreSQL server on {:?} ({})",
                addr, e
            ))
        })?
        .map_err(|e| {
            Error::operational(format!(
                "Can't connect to PostgreSQL server on {:?} ({})",
                addr, e
            ))
        })?;
    configure_tcp(&stream, options)?;
    Ok(ConnectionStream::Plain(stream))
}

/// TCP ソケットに接続設定の TCP オプションを適用する。
///
/// 通常の接続とキャンセル要求の接続の両方で使う。値の組み合わせと範囲は
/// `Connection::connect` で検証済みのため、ここでは OS が対応しているかだけを見る。
fn configure_tcp(stream: &TcpStream, options: &ConnectOptions) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|e| Error::operational(format!("Failed to set TCP_NODELAY: {}", e)))?;
    let socket = socket2::SockRef::from(stream);
    // PostgreSQL 19 文書 §31.1.2 Parameter Key Words のとおり、キープアライブは既定で有効にし
    // (src/interfaces/libpq/fe-connect.c の useKeepalives)、指定のない調整値は OS の既定値のままにする。
    // libpq は対応していない OS では調整値を黙って無視するが、ここでは指定が効かないことをエラーにする。
    // 将来 libpq の既定値や解釈が変わった場合はここを見直す。
    if options.keepalives {
        let tuned = options.keepalives_idle.is_some()
            || options.keepalives_interval.is_some()
            || options.keepalives_count.is_some();
        if tuned {
            socket
                .set_tcp_keepalive(&tcp_keepalive(options)?)
                .map_err(|e| Error::operational(format!("Failed to set TCP keepalive: {e}")))?;
        } else {
            socket
                .set_keepalive(true)
                .map_err(|e| Error::operational(format!("Failed to set SO_KEEPALIVE: {e}")))?;
        }
    }
    if let Some(timeout) = options.tcp_user_timeout {
        set_tcp_user_timeout(&socket, timeout)?;
    }
    Ok(())
}

/// キープアライブの調整値を組み立てる。
fn tcp_keepalive(options: &ConnectOptions) -> Result<socket2::TcpKeepalive> {
    let mut keepalive = socket2::TcpKeepalive::new();
    // Windows は無通信時間と再送間隔を SIO_KEEPALIVE_VALS でまとめて設定するため、
    // 片方だけを指定した場合はもう片方を libpq の pqSetKeepalivesWin32 と同じ既定値
    // (2 時間と 1 秒) で補う。
    #[cfg(windows)]
    let (idle, interval) = (
        Some(
            options
                .keepalives_idle
                .unwrap_or(Duration::from_secs(2 * 60 * 60)),
        ),
        Some(
            options
                .keepalives_interval
                .unwrap_or(Duration::from_secs(1)),
        ),
    );
    #[cfg(not(windows))]
    let (idle, interval) = (options.keepalives_idle, options.keepalives_interval);
    if let Some(idle) = idle {
        keepalive = with_keepalive_time(keepalive, idle)?;
    }
    if let Some(interval) = interval {
        keepalive = with_keepalive_interval(keepalive, interval)?;
    }
    if let Some(count) = options.keepalives_count {
        keepalive = with_keepalive_retries(keepalive, count)?;
    }
    Ok(keepalive)
}

/// 無通信時間を設定する (`TCP_KEEPIDLE` またはそれに相当するオプション)。
#[cfg(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    windows
))]
fn with_keepalive_time(
    keepalive: socket2::TcpKeepalive,
    idle: Duration,
) -> Result<socket2::TcpKeepalive> {
    Ok(keepalive.with_time(idle))
}

/// 無通信時間を設定できない OS ではエラーにする。
#[cfg(not(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    windows
)))]
fn with_keepalive_time(
    _keepalive: socket2::TcpKeepalive,
    _idle: Duration,
) -> Result<socket2::TcpKeepalive> {
    Err(Error::not_supported(
        "keepalives_idle is not supported on this platform",
    ))
}

/// 再送間隔を設定する (`TCP_KEEPINTVL` またはそれに相当するオプション)。
#[cfg(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    windows
))]
fn with_keepalive_interval(
    keepalive: socket2::TcpKeepalive,
    interval: Duration,
) -> Result<socket2::TcpKeepalive> {
    Ok(keepalive.with_interval(interval))
}

/// 再送間隔を設定できない OS ではエラーにする。
#[cfg(not(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    windows
)))]
fn with_keepalive_interval(
    _keepalive: socket2::TcpKeepalive,
    _interval: Duration,
) -> Result<socket2::TcpKeepalive> {
    Err(Error::not_supported(
        "keepalives_interval is not supported on this platform",
    ))
}

/// 切断と判断するまでの回数を設定する (`TCP_KEEPCNT`)。
#[cfg(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    windows
))]
fn with_keepalive_retries(
    keepalive: socket2::TcpKeepalive,
    count: u32,
) -> Result<socket2::TcpKeepalive> {
    Ok(keepalive.with_retries(count))
}

/// 切断と判断するまでの回数を設定できない OS ではエラーにする。
#[cfg(not(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    windows
)))]
fn with_keepalive_retries(
    _keepalive: socket2::TcpKeepalive,
    _count: u32,
) -> Result<socket2::TcpKeepalive> {
    Err(Error::not_supported(
        "keepalives_count is not supported on this platform",
    ))
}

/// 確認応答を待つ時間の上限を設定する (`TCP_USER_TIMEOUT`)。
#[cfg(any(target_os = "android", target_os = "linux"))]
fn set_tcp_user_timeout(socket: &socket2::SockRef<'_>, timeout: Duration) -> Result<()> {
    socket
        .set_tcp_user_timeout(Some(timeout))
        .map_err(|e| Error::operational(format!("Failed to set TCP_USER_TIMEOUT: {e}")))
}

/// `TCP_USER_TIMEOUT` がない OS ではエラーにする。
#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn set_tcp_user_timeout(_socket: &socket2::SockRef<'_>, _timeout: Duration) -> Result<()> {
    Err(Error::not_supported(
        "tcp_user_timeout is not supported on this platform",
    ))
}

/// PostgreSQL サーバーと TLS ハンドシェイクを行う。
async fn establish_tls(plain: TcpStream, options: &ConnectOptions) -> Result<ConnectionStream> {
    let config = tls::build_tls_config(options).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = tls::server_name_from_host(&options.host)?;
    let tls = connector
        .connect(server_name, plain)
        .await
        .map_err(|error| Error::operational(format!("TLS handshake failed: {error}")))?;
    Ok(ConnectionStream::Tls(Box::new(tls)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 実際の TCP 接続を作り、ソケットに設定されたオプションを読み戻す。
    async fn connected_socket(
        listener: &tokio::net::TcpListener,
        options: ConnectOptions,
    ) -> TcpStream {
        let port = listener
            .local_addr()
            .expect("待ち受けアドレスを取得できません")
            .port();
        let options = ConnectOptions { port, ..options };
        match connect_stream(&options)
            .await
            .expect("ローカルの待ち受けに接続できません")
        {
            ConnectionStream::Plain(stream) => stream,
            _ => panic!("TCP 接続のはずが別の種類の接続になりました"),
        }
    }

    /// キープアライブと TCP_USER_TIMEOUT の設定が、実際のソケットに反映されることを確認する。
    #[tokio::test]
    async fn test_connect_stream_applies_tcp_settings() {
        // 接続はカーネルの待ち行列で確立するため、accept しなくてよい。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ローカルで待ち受けできません");
        let base = ConnectOptions {
            host: "127.0.0.1".into(),
            ssl_mode: SslMode::Disabled,
            ..ConnectOptions::default()
        };

        // 既定ではキープアライブを有効にし、調整値は OS の既定値のままにする。
        let stream = connected_socket(&listener, base.clone()).await;
        let socket = socket2::SockRef::from(&stream);
        assert!(
            socket.keepalive().expect("SO_KEEPALIVE を読めません"),
            "既定でキープアライブが有効になっていません"
        );
        assert!(
            socket.tcp_nodelay().expect("TCP_NODELAY を読めません"),
            "TCP_NODELAY が有効になっていません"
        );

        // keepalives=false ではキープアライブを有効にしない。
        let stream = connected_socket(
            &listener,
            ConnectOptions {
                keepalives: false,
                ..base.clone()
            },
        )
        .await;
        assert!(
            !socket2::SockRef::from(&stream)
                .keepalive()
                .expect("SO_KEEPALIVE を読めません"),
            "keepalives=false なのにキープアライブが有効です"
        );

        // 調整値はそれぞれのソケットオプションに秒と回数で設定する。
        let stream = connected_socket(
            &listener,
            ConnectOptions {
                keepalives_idle: Some(Duration::from_secs(37)),
                keepalives_interval: Some(Duration::from_secs(7)),
                keepalives_count: Some(4),
                ..base.clone()
            },
        )
        .await;
        let socket = socket2::SockRef::from(&stream);
        assert!(socket.keepalive().expect("SO_KEEPALIVE を読めません"));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(
                socket
                    .tcp_keepalive_time()
                    .expect("キープアライブの無通信時間を読めません"),
                Duration::from_secs(37)
            );
            assert_eq!(
                socket
                    .tcp_keepalive_interval()
                    .expect("キープアライブの再送間隔を読めません"),
                Duration::from_secs(7)
            );
            assert_eq!(
                socket
                    .tcp_keepalive_retries()
                    .expect("キープアライブの回数を読めません"),
                4
            );
        }

        // TCP_USER_TIMEOUT は Linux と Android でだけ設定でき、ほかの OS ではエラーにする。
        let options = ConnectOptions {
            port: listener
                .local_addr()
                .expect("待ち受けアドレスを取得できません")
                .port(),
            tcp_user_timeout: Some(Duration::from_millis(1500)),
            ..base
        };
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let ConnectionStream::Plain(stream) = connect_stream(&options)
                .await
                .expect("tcp_user_timeout を指定した接続に失敗しました")
            else {
                panic!("TCP 接続のはずが別の種類の接続になりました");
            };
            assert_eq!(
                socket2::SockRef::from(&stream)
                    .tcp_user_timeout()
                    .expect("TCP_USER_TIMEOUT を読めません"),
                Some(Duration::from_millis(1500))
            );
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let error = match connect_stream(&options).await {
                Ok(_) => panic!("対応していない OS で tcp_user_timeout を受け付けました"),
                Err(error) => error,
            };
            assert_eq!(
                error.message(),
                "tcp_user_timeout is not supported on this platform"
            );
        }
    }
}
