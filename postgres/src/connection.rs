// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 接続の tokio I/O 実装。
//!
//! sans I/O な状態機械 (内部実装) に対し、TCP/TLS/Unix ドメインソケット
//! 接続、タイムアウト、読み書きを行う。

use crate::batch::Batch;
use crate::converters::Value;
use crate::error::{Error, Result};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{DigitallySignedStruct, Error as RustlsError};
use rustls_platform_verifier::{BuilderVerifierExt, Verifier};
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

/// 接続の状態を表すストリーム。
enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Unix(UnixStream),
}

/// 認証の試行結果。
enum AuthenticateOutcome {
    Success,
    /// TLS ハンドシェイクに失敗した。
    TlsFailed,
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
    /// 自動準備したステートメントのキャッシュ (SQL をキーとする)。
    ///
    /// 同じ SQL を繰り返し実行するときにサーバー側の再パースを避ける。
    /// 動的な SQL を大量に実行する場合はキャッシュが無制限に
    /// 増えるため、利用側で SQL を正規化すること。
    statement_cache: HashMap<String, PreparedStatement>,
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
    /// Unix ドメインソケットでは SSL は使用しない (libpq と同じ挙動)。
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
        let is_unix_socket = options.host.starts_with('/');
        let mut options = options;
        if is_unix_socket {
            options.ssl_mode = SslMode::Disabled;
        }
        let inner = InnerConnection::connect(options.clone())?;
        let stream = connect_stream(&options).await?;
        let mut conn = Self {
            inner,
            stream: Some(stream),
            statement_cache: HashMap::new(),
            transaction_dirty: false,
        };

        conn.authenticate(Some(&mut provider)).await?;

        tracing::info!(
            host = %options.host,
            port = options.port,
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
                Ok(AuthenticateOutcome::Success) => return Ok(()),
                Ok(AuthenticateOutcome::TlsFailed) => {
                    // Allow モードは TLS ハンドシェイクに失敗した場合に
                    // 平文で接続し直す (libpq と同じ挙動)。
                    // sslmode を Disabled に変更して再試行するため、
                    // このループは最大 2 回で終了する。
                    if self.inner.options().ssl_mode != SslMode::Allow {
                        return Err(Error::operational(
                            "TLS handshake failed and the sslmode does not allow fallback",
                        ));
                    }
                    tracing::debug!("TLS handshake failed, retrying without SSL");
                    let mut options = self.inner.options().clone();
                    options.ssl_mode = SslMode::Disabled;
                    let inner = InnerConnection::connect(options.clone())?;
                    let stream = connect_stream(&options).await?;
                    self.inner = inner;
                    self.stream = Some(stream);
                }
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
                    let token = provider().await.map_err(|e| {
                        Error::operational(format!("Failed to obtain an OAuth token: {}", e))
                    })?;
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
    async fn authenticate_attempt(&mut self) -> Result<AuthenticateOutcome> {
        let mut state = self.inner.request_authentication_start()?;
        loop {
            match state {
                AuthState::NeedRead => {
                    // 1 回の read で複数メッセージが届いた場合に備え、
                    // 受信キューが空のときだけ読み込む。
                    if self.inner.is_recv_queue_empty() {
                        self.pump_read().await?;
                    }
                    state = self.inner.request_authentication_continue()?;
                }
                AuthState::Send => {
                    self.pump_write().await?;
                    state = AuthState::NeedRead;
                }
                AuthState::Success => return Ok(AuthenticateOutcome::Success),
            }
            if self.inner.needs_tls_upgrade() {
                if self.upgrade_to_tls().await.is_err() {
                    return Ok(AuthenticateOutcome::TlsFailed);
                }
                self.inner.set_secure(true);
                state = self.inner.request_authentication_send_startup()?;
            }
        }
    }

    /// 平文ストリームを TLS ストリームにアップグレードする。
    async fn upgrade_to_tls(&mut self) -> Result<()> {
        let config = build_tls_config(self.inner.options()).await?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = server_name_from_host(&self.inner.options().host)?;

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

        let tls_stream = connector
            .connect(server_name, plain)
            .await
            .map_err(|e| Error::operational(format!("TLS handshake failed: {}", e)))?;
        self.stream = Some(ConnectionStream::Tls(Box::new(tls_stream)));
        Ok(())
    }

    /// 送信キューの内容をすべて書き込む。
    async fn pump_write(&mut self) -> Result<()> {
        while let Some(data) = self.inner.pop_send_queue() {
            self.write_all(&data).await?;
        }
        self.flush().await?;
        Ok(())
    }

    /// サーバーからデータを読み込み、内部の受信バッファに供給する。
    ///
    /// 受信バッファに完全なメッセージが蓄積されるまで繰り返し読み込む。
    async fn pump_read(&mut self) -> Result<()> {
        loop {
            let mut buf = vec![0u8; 4096];
            let n = match self.read(&mut buf).await {
                Ok(0) => {
                    self.inner.force_close();
                    self.stream.take();
                    return Err(Error::operational(
                        "Lost connection to PostgreSQL server during query",
                    ));
                }
                Ok(n) => n,
                Err(e) => {
                    self.inner.force_close();
                    self.stream.take();
                    return Err(Error::operational(format!(
                        "Lost connection to PostgreSQL server during query ({})",
                        e
                    )));
                }
            };
            tracing::debug!(n, "pump_read received");
            let added = self.inner.feed_bytes(&buf[..n])?;
            if added > 0 {
                break;
            }
        }
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.stream.as_mut() {
            Some(stream) => stream.read(buf).await,
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No stream available",
            )),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self.stream.as_mut() {
            Some(stream) => stream.write_all(data).await,
            None => {
                return Err(Error::interface("No stream available"));
            }
        }
        .map_err(|e| {
            self.inner.force_close();
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
            self.inner.force_close();
            Error::operational(format!("Failed to flush to PostgreSQL server ({})", e))
        })
    }

    /// 送信処理を実行し、読み残しの回収が `NeedMoreData` で中断した場合は
    /// 受信してから再試行する。
    async fn pump_write_after<F>(&mut self, send: F) -> Result<()>
    where
        F: Fn(&mut InnerConnection) -> Result<()>,
    {
        loop {
            match send(&mut self.inner) {
                Ok(()) => {
                    self.pump_write().await?;
                    return Ok(());
                }
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
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
        tracing::debug!(sql = %sql, unbuffered, "Executing query");
        self.pump_write_after(|inner| inner.send_query(sql)).await?;
        let affected = self.read_query_result(unbuffered).await?;
        tracing::debug!(affected_rows = affected, "Query executed");
        Ok(affected)
    }

    /// パラメータ付きクエリを実行する (拡張クエリプロトコル)。
    ///
    /// 同じ SQL を 2 回目以降に実行する場合は、前回準備した
    /// プリペアドステートメントを再利用する (ステートメントキャッシュ)。
    /// サーバー再起動等でステートメントが失効した場合は
    /// 自動的に再準備して 1 回だけリトライする。
    pub async fn execute(&mut self, sql: &str, args: &[Value], unbuffered: bool) -> Result<i64> {
        tracing::debug!(sql = %sql, parameter_count = args.len(), unbuffered, "Executing statement");
        if let Some(statement) = self.statement_cache.get(sql).cloned() {
            return self
                .execute_prepared_inner(&statement, args, unbuffered)
                .await;
        }
        let statement = self.prepare(sql).await?;
        self.statement_cache
            .insert(sql.to_string(), statement.clone());
        self.execute_prepared_inner(&statement, args, unbuffered)
            .await
    }

    /// ステートメントを準備する。
    ///
    /// 返された `PreparedStatement` は `execute_prepared` で実行できる。
    pub async fn prepare(&mut self, sql: &str) -> Result<PreparedStatement> {
        self.pump_write_after(|inner| inner.send_prepare(sql))
            .await?;
        self.read_until(|inner| inner.read_prepare_result()).await
    }

    /// 準備済みステートメントを実行する。
    ///
    /// ステートメントがサーバー側で失効している場合 (サーバー再起動等) は
    /// 自動的に再準備して 1 回だけリトライする。
    pub async fn execute_prepared(
        &mut self,
        statement: &PreparedStatement,
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.execute_prepared_inner(statement, args, unbuffered)
            .await
    }

    /// プリペアドステートメントの実行本体。
    ///
    /// ステートメントがサーバー側で失効した場合に再準備して
    /// 1 回だけリトライする。
    /// 対象は 26000 (undefined statement: サーバー再起動等) と
    /// 0A000 (cached plan must not change result type: DDL で型が変わった場合)。
    /// 0A000 の場合は古いステートメントがサーバーに残るため、
    /// 接続のライフサイクル中に何度も型が変わると蓄積する。
    async fn execute_prepared_inner(
        &mut self,
        statement: &PreparedStatement,
        args: &[Value],
        unbuffered: bool,
    ) -> Result<i64> {
        self.pump_write_after(|inner| inner.send_execute_prepared(statement, args))
            .await?;
        match self.read_query_result(unbuffered).await {
            Err(e) if matches!(e.code(), Some("26000") | Some("0A000")) => {
                tracing::debug!(
                    statement_name = %statement.name,
                    sqlstate = e.code().unwrap_or_default(),
                    "Statement was invalidated on the server, re-preparing"
                );
                let re_prepared = self.prepare(&statement.sql).await?;
                self.statement_cache
                    .insert(statement.sql.clone(), re_prepared.clone());
                self.pump_write_after(|inner| inner.send_execute_prepared(&re_prepared, args))
                    .await?;
                self.read_query_result(unbuffered).await
            }
            result => result,
        }
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
        self.pump_write_after(|inner| inner.send_batch(&statements))
            .await?;
        loop {
            match self.inner.read_batch_results(count) {
                Ok(results) => return Ok(results),
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
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
        self.pump_write_after(|inner| inner.send_copy_in(sql))
            .await?;
        self.read_until(|inner| inner.read_copy_in_response())
            .await?;
        self.pump_write_after(|inner| inner.send_copy_data(data))
            .await?;
        self.pump_write_after(|inner| inner.send_copy_done())
            .await?;
        self.read_until(|inner| inner.finish_copy_in()).await
    }

    /// CopyIn を開始する。
    ///
    /// サーバーが CopyIn を受け付けるまで待つ。
    /// その後 `send_copy_data` でデータを送り、
    /// `send_copy_done` の後に `finish_copy_in` で結果を読み込む。
    pub async fn copy_in_begin(&mut self, sql: &str) -> Result<()> {
        self.pump_write_after(|inner| inner.send_copy_in(sql))
            .await?;
        self.read_until(|inner| inner.read_copy_in_response())
            .await?;
        Ok(())
    }

    /// CopyIn 中のデータを送信する。
    pub async fn send_copy_data(&mut self, data: &[u8]) -> Result<()> {
        self.pump_write_after(|inner| inner.send_copy_data(data))
            .await
    }

    /// CopyIn の完了を送信する。
    pub async fn send_copy_done(&mut self) -> Result<()> {
        self.pump_write_after(|inner| inner.send_copy_done()).await
    }

    /// CopyIn の失敗を送信する。
    ///
    /// サーバーはエラー応答を返し、接続は正常な状態に戻る。
    pub async fn send_copy_fail(&mut self, message: &str) -> Result<()> {
        self.pump_write_after(|inner| inner.send_copy_fail(message))
            .await
    }

    /// CopyIn の結果を読み込む。
    pub async fn finish_copy_in(&mut self) -> Result<i64> {
        self.read_until(|inner| inner.finish_copy_in()).await
    }

    /// CopyOut を実行してすべてのデータを取得する。
    ///
    /// `sql` は `COPY ... TO STDOUT` 形式の SQL。
    /// 大きなデータを扱う場合は `copy_out_begin` / `read_copy_out_data` で
    /// 分割読み込みする。
    pub async fn copy_out(&mut self, sql: &str) -> Result<Vec<u8>> {
        self.pump_write_after(|inner| inner.send_copy_out(sql))
            .await?;
        self.read_until(|inner| inner.read_copy_out_response())
            .await?;
        let mut all = Vec::new();
        loop {
            match self.inner.read_copy_out_data() {
                Ok(Some(data)) => all.extend_from_slice(&data),
                Ok(None) => break,
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
        self.read_until(|inner| inner.finish_copy_out()).await?;
        Ok(all)
    }

    /// CopyOut を開始する。
    ///
    /// サーバーが CopyOut を受け付けるまで待つ。
    /// その後 `read_copy_out_data` でデータを読み、
    /// `None` が返ったら `finish_copy_out` で結果を読み込む。
    pub async fn copy_out_begin(&mut self, sql: &str) -> Result<()> {
        self.pump_write_after(|inner| inner.send_copy_out(sql))
            .await?;
        self.read_until(|inner| inner.read_copy_out_response())
            .await?;
        Ok(())
    }

    /// CopyOut 中のデータを一つ読み込む。
    ///
    /// データが 1 つ届くたびに `Some(data)` を返し、
    /// CopyOut の終了時に `None` を返す。
    pub async fn read_copy_out_data(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            match self.inner.read_copy_out_data() {
                Ok(value) => return Ok(value),
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
    }

    /// CopyOut の結果を読み込む。
    pub async fn finish_copy_out(&mut self) -> Result<i64> {
        self.read_until(|inner| inner.finish_copy_out()).await
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
                    return Err(Error::internal(
                        "Unexpected message while waiting for notification",
                    ));
                }
                Ok(None) => continue,
                Err(Error::NeedMoreData) => continue,
                Err(e) => return Err(e),
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
    /// タイムアウトした場合はサーバーにキャンセル要求を送り、
    /// 接続を正常な状態に戻した上でエラーを返す。
    pub async fn query_with_timeout(
        &mut self,
        sql: &str,
        unbuffered: bool,
        timeout_duration: Duration,
    ) -> Result<i64> {
        match timeout(timeout_duration, self.query(sql, unbuffered)).await {
            Ok(result) => result,
            Err(_) => {
                // キャンセルに失敗した場合は接続は使用できないため、
                // タイムアウトエラーではなくキャンセルエラーを返す。
                self.cancel_and_recover(unbuffered, timeout_duration)
                    .await?;
                Err(Error::operational(format!(
                    "Query timed out after {:?}",
                    timeout_duration
                )))
            }
        }
    }

    /// パラメータ付きクエリをタイムアウト付きで実行する (拡張クエリプロトコル)。
    ///
    /// タイムアウトした場合はサーバーにキャンセル要求を送り、
    /// 接続を正常な状態に戻した上でエラーを返す。
    pub async fn execute_with_timeout(
        &mut self,
        sql: &str,
        args: &[Value],
        unbuffered: bool,
        timeout_duration: Duration,
    ) -> Result<i64> {
        match timeout(timeout_duration, self.execute(sql, args, unbuffered)).await {
            Ok(result) => result,
            Err(_) => {
                // キャンセルに失敗した場合は接続は使用できないため、
                // タイムアウトエラーではなくキャンセルエラーを返す。
                self.cancel_and_recover(unbuffered, timeout_duration)
                    .await?;
                Err(Error::operational(format!(
                    "Query timed out after {:?}",
                    timeout_duration
                )))
            }
        }
    }

    /// タイムアウトしたクエリをキャンセルして接続を回復する。
    ///
    /// 別の接続からキャンセル要求を送信し、サーバーが
    /// エラー応答 (57014) と ReadyForQuery を返すまで読み切る。
    /// キャンセル要求の送信自体に失敗した場合は接続は使用できないため、
    /// エラーを返す。
    async fn cancel_and_recover(
        &mut self,
        unbuffered: bool,
        timeout_duration: Duration,
    ) -> Result<()> {
        tracing::debug!("Query timed out, canceling");
        if let Err(e) = self.send_cancel_request().await {
            tracing::error!(error = %e, "Failed to send cancel request");
            return Err(e);
        }
        // キャンセル応答 (エラー応答 57014) を受信するまで読み続ける。
        loop {
            match self.inner.read_query_result(unbuffered) {
                Ok(_) => break,
                Err(Error::NeedMoreData) => self.pump_read().await?,
                // キャンセルによるエラー応答。
                Err(_) => break,
            }
        }
        // 読み残し (ReadyForQuery) を回収して接続を正常な状態に戻す。
        loop {
            match self.inner.finish_previous_result() {
                Ok(()) => break,
                Err(Error::NeedMoreData) => self.pump_read().await?,
                Err(e) => return Err(e),
            }
        }
        tracing::debug!(timeout = ?timeout_duration, "Query canceled after timeout");
        Ok(())
    }

    /// 進行中のクエリをキャンセルする。
    ///
    /// 別の TCP 接続から CancelRequest を送信する。
    /// クエリ実行中は接続が読み取り中でブロックしているため、
    /// 別タスクからこのメソッドを呼ぶ必要がある。
    pub async fn cancel_request(&mut self) -> Result<()> {
        self.send_cancel_request().await
    }

    /// 別接続でキャンセル要求を送信する。
    async fn send_cancel_request(&mut self) -> Result<()> {
        let options = self.inner.options().clone();
        let message = crate::protocol::cancel_request_message(
            self.inner.backend_process_id(),
            self.inner.backend_secret_key(),
        );
        let mut stream = connect_stream(&options).await?;
        stream
            .write_all(&message)
            .await
            .map_err(|e| Error::operational(format!("Failed to send cancel request ({})", e)))?;
        let _ = stream.shutdown().await;
        Ok(())
    }

    /// カーソルを作成する。
    pub fn cursor(&mut self) -> crate::cursor::Cursor<'_> {
        crate::cursor::Cursor::new(self)
    }

    /// 接続を閉じる。
    pub async fn close(&mut self) -> Result<()> {
        self.inner.close()?;
        self.pump_write().await?;
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        Ok(())
    }

    /// 強制的に接続を閉じる。
    ///
    /// Terminate の送信やストリームの graceful shutdown を行わず、
    /// 即座に接続を破棄する。
    pub fn force_close(&mut self) {
        self.inner.force_close();
        self.stream.take();
    }

    /// 接続が開いているかどうか。
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
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
    /// アンバッファードクエリで行を 1 行ずつ読み込むために使う。
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
    /// 接続がプールに返却される直前や、次のトランザクション開始時に呼ぶ。
    pub(crate) async fn rollback_dirty_transaction(&mut self) -> Result<()> {
        if !self.transaction_dirty {
            return Ok(());
        }
        self.query("ROLLBACK", false).await?;
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
    let stream = timeout(options.connect_timeout, TcpStream::connect(&addr))
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
    stream
        .set_nodelay(true)
        .map_err(|e| Error::operational(format!("Failed to set TCP_NODELAY: {}", e)))?;
    Ok(ConnectionStream::Plain(stream))
}

/// ホスト名または IP アドレスから TLS の ServerName を生成する。
fn server_name_from_host(host: &str) -> Result<ServerName<'static>> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = std::net::IpAddr::from_str(host) {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|_| Error::operational("Invalid server hostname for TLS"))
}

/// ホスト名検証のみをスキップする verifier。
///
/// 内部の verifier で証明書チェーン・署名検証は行い、
/// ホスト名不一致に起因するエラーのみを成功として変換する。
#[derive(Debug)]
struct NoHostnameVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl NoHostnameVerifier {
    fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for NoHostnameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(assertion) => Ok(assertion),
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// TLS 設定を構築する。
///
/// sslmode による検証の違い:
/// - `VerifyFull` は CA 検証とホスト名検証の両方を行う。
/// - それ以外の SSL モードは CA 検証のみ行い、ホスト名検証は行わない。
async fn build_tls_config(options: &ConnectOptions) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            Error::operational(format!("Failed to configure TLS protocol versions: {}", e))
        })?;

    let verify_hostname = matches!(options.ssl_mode, SslMode::VerifyFull);

    let config = if verify_hostname {
        if let Some(ca_path) = &options.ssl_ca {
            let mut root_store = rustls::RootCertStore::empty();
            let cert_file = tokio::fs::read(ca_path)
                .await
                .map_err(|e| Error::operational(format!("Failed to read CA file: {}", e)))?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::operational(format!("Failed to parse CA file: {}", e)))?;
            root_store.add_parsable_certificates(certs);
            builder.with_root_certificates(root_store)
        } else {
            builder.with_platform_verifier().map_err(|e| {
                Error::operational(format!("Failed to configure platform verifier: {}", e))
            })?
        }
    } else {
        let verifier: Arc<dyn ServerCertVerifier> = if let Some(ca_path) = &options.ssl_ca {
            let mut root_store = rustls::RootCertStore::empty();
            let cert_file = tokio::fs::read(ca_path)
                .await
                .map_err(|e| Error::operational(format!("Failed to read CA file: {}", e)))?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::operational(format!("Failed to parse CA file: {}", e)))?;
            root_store.add_parsable_certificates(certs);
            let inner =
                WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
                    .build()
                    .map_err(|e| {
                        Error::operational(format!("Failed to build webpki verifier: {}", e))
                    })?;
            Arc::new(NoHostnameVerifier::new(inner))
        } else {
            let inner = Verifier::new(provider).map_err(|e| {
                Error::operational(format!("Failed to create platform verifier: {}", e))
            })?;
            Arc::new(NoHostnameVerifier::new(Arc::new(inner)))
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
    };

    if (options.ssl_cert.is_some()) != (options.ssl_key.is_some()) {
        return Err(Error::operational(
            "ssl_cert and ssl_key must be specified together",
        ));
    }

    let config = if let (Some(cert_path), Some(key_path)) = (&options.ssl_cert, &options.ssl_key) {
        let cert_file = tokio::fs::read(cert_path)
            .await
            .map_err(|e| Error::operational(format!("Failed to read client cert file: {}", e)))?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::operational(format!("Failed to parse client cert file: {}", e)))?;

        let key_file = tokio::fs::read(key_path)
            .await
            .map_err(|e| Error::operational(format!("Failed to read client key file: {}", e)))?;
        let keys: Vec<PrivatePkcs8KeyDer<'static>> = PrivatePkcs8KeyDer::pem_slice_iter(&key_file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::operational(format!("Failed to parse client key file: {}", e)))?;
        if keys.is_empty() {
            return Err(Error::operational("No PKCS8 private key found"));
        }
        config.with_client_auth_cert(
            certs,
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                keys.into_iter()
                    .next()
                    .expect("at least one PKCS8 private key was verified above"),
            ),
        )
    } else {
        Ok(config.with_no_client_auth())
    };

    config.map_err(|e| Error::operational(format!("Failed to build TLS config: {}", e)))
}
