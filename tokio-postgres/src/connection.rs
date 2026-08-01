// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 接続の tokio I/O 実装。
//!
//! `shiguredo_postgres::Connection` の sans I/O な状態機械に対し、
//! TCP/TLS 接続、タイムアウト、読み書きを行う。

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{DigitallySignedStruct, Error as RustlsError};
use rustls_platform_verifier::{BuilderVerifierExt, Verifier};
use shiguredo_postgres::connection::{
    AuthState, ConnectOptions, Connection as InnerConnection, QueryResult,
};
use shiguredo_postgres::converters::Value;
use shiguredo_postgres::error::{Error, Result};
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// PostgreSQL 接続。
pub struct Connection {
    inner: InnerConnection,
    stream: Option<ConnectionStream>,
}

enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl ConnectionStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf).await,
            Self::Tls(s) => s.read(buf).await,
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.write_all(data).await,
            Self::Tls(s) => s.write_all(data).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush().await,
            Self::Tls(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.shutdown().await,
            Self::Tls(s) => s.shutdown().await,
        }
    }
}

impl Connection {
    /// 新規接続を確立する。
    ///
    /// TCP 接続、TLS ネゴシエーション (必要な場合)、
    /// 認証、ReadyForQuery の受信までを行う。
    pub async fn connect(options: ConnectOptions) -> Result<Self> {
        let inner = InnerConnection::connect(options.clone())?;
        let addr = match std::net::IpAddr::from_str(&options.host) {
            Ok(ip) if ip.is_ipv6() => format!("[{}]:{}", options.host, options.port),
            _ => format!("{}:{}", options.host, options.port),
        };
        let stream = timeout(options.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Connection timeout: {}", e),
            })?
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Can't connect to PostgreSQL server on {:?} ({})", addr, e),
            })?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Failed to set TCP_NODELAY: {}", e),
            })?;

        let mut conn = Self {
            inner,
            stream: Some(ConnectionStream::Plain(stream)),
        };

        conn.authenticate().await?;

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
    async fn authenticate(&mut self) -> Result<()> {
        let timeout_duration = self.inner.options().connect_timeout;
        tokio::time::timeout(timeout_duration, self.authenticate_inner())
            .await
            .map_err(|_| Error::OperationalError {
                code: String::new(),
                message: format!("Authentication timeout after {:?}", timeout_duration),
            })?
    }

    async fn authenticate_inner(&mut self) -> Result<()> {
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
                AuthState::Success => break,
            }
            if self.inner.needs_tls_upgrade() {
                self.upgrade_to_tls().await?;
                self.inner.set_secure(true);
                state = self.inner.request_authentication_send_startup()?;
            }
        }
        Ok(())
    }

    /// 平文ストリームを TLS ストリームにアップグレードする。
    async fn upgrade_to_tls(&mut self) -> Result<()> {
        let config = build_tls_config(self.inner.options()).await?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = server_name_from_host(&self.inner.options().host)?;

        let stream = self.stream.take().ok_or_else(|| Error::InterfaceError {
            message: "No stream to upgrade".to_string(),
        })?;
        let plain = match stream {
            ConnectionStream::Plain(s) => s,
            ConnectionStream::Tls(_) => {
                return Err(Error::InterfaceError {
                    message: "Already TLS".to_string(),
                });
            }
        };

        let tls_stream =
            connector
                .connect(server_name, plain)
                .await
                .map_err(|e| Error::OperationalError {
                    code: String::new(),
                    message: format!("TLS handshake failed: {}", e),
                })?;
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
                    return Err(Error::OperationalError {
                        code: String::new(),
                        message: "Lost connection to PostgreSQL server during query".to_string(),
                    });
                }
                Ok(n) => n,
                Err(e) => {
                    self.inner.force_close();
                    self.stream.take();
                    return Err(Error::OperationalError {
                        code: String::new(),
                        message: format!(
                            "Lost connection to PostgreSQL server during query ({})",
                            e
                        ),
                    });
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
                return Err(Error::InterfaceError {
                    message: "No stream available".to_string(),
                });
            }
        }
        .map_err(|e| {
            self.inner.force_close();
            Error::OperationalError {
                code: String::new(),
                message: format!("Failed to write to PostgreSQL server ({})", e),
            }
        })
    }

    async fn flush(&mut self) -> Result<()> {
        match self.stream.as_mut() {
            Some(stream) => stream.flush().await,
            None => {
                return Err(Error::InterfaceError {
                    message: "No stream available".to_string(),
                });
            }
        }
        .map_err(|e| {
            self.inner.force_close();
            Error::OperationalError {
                code: String::new(),
                message: format!("Failed to flush to PostgreSQL server ({})", e),
            }
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
    pub async fn execute(&mut self, sql: &str, args: &[Value], unbuffered: bool) -> Result<i64> {
        tracing::debug!(sql = %sql, parameter_count = args.len(), unbuffered, "Executing statement");
        self.pump_write_after(|inner| inner.send_execute(sql, args))
            .await?;
        let affected = self.read_query_result(unbuffered).await?;
        tracing::debug!(affected_rows = affected, "Statement executed");
        Ok(affected)
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
    pub fn result_mut(&mut self) -> Option<&mut QueryResult> {
        self.inner.result_mut()
    }
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
    ServerName::try_from(host.to_string()).map_err(|_| Error::OperationalError {
        code: String::new(),
        message: "Invalid server hostname for TLS".to_string(),
    })
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
async fn build_tls_config(options: &ConnectOptions) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::OperationalError {
            code: String::new(),
            message: format!("Failed to configure TLS protocol versions: {}", e),
        })?;

    let config = if options.ssl_verify_identity {
        if let Some(ca_path) = &options.ssl_ca {
            let mut root_store = rustls::RootCertStore::empty();
            let cert_file =
                tokio::fs::read(ca_path)
                    .await
                    .map_err(|e| Error::OperationalError {
                        code: String::new(),
                        message: format!("Failed to read CA file: {}", e),
                    })?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::OperationalError {
                    code: String::new(),
                    message: format!("Failed to parse CA file: {}", e),
                })?;
            root_store.add_parsable_certificates(certs);
            builder.with_root_certificates(root_store)
        } else {
            builder
                .with_platform_verifier()
                .map_err(|e| Error::OperationalError {
                    code: String::new(),
                    message: format!("Failed to configure platform verifier: {}", e),
                })?
        }
    } else {
        let verifier: Arc<dyn ServerCertVerifier> = if let Some(ca_path) = &options.ssl_ca {
            let mut root_store = rustls::RootCertStore::empty();
            let cert_file =
                tokio::fs::read(ca_path)
                    .await
                    .map_err(|e| Error::OperationalError {
                        code: String::new(),
                        message: format!("Failed to read CA file: {}", e),
                    })?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::OperationalError {
                    code: String::new(),
                    message: format!("Failed to parse CA file: {}", e),
                })?;
            root_store.add_parsable_certificates(certs);
            let inner =
                WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
                    .build()
                    .map_err(|e| Error::OperationalError {
                        code: String::new(),
                        message: format!("Failed to build webpki verifier: {}", e),
                    })?;
            Arc::new(NoHostnameVerifier::new(inner))
        } else {
            let inner = Verifier::new(provider).map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Failed to create platform verifier: {}", e),
            })?;
            Arc::new(NoHostnameVerifier::new(Arc::new(inner)))
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
    };

    if (options.ssl_cert.is_some()) != (options.ssl_key.is_some()) {
        return Err(Error::OperationalError {
            code: String::new(),
            message: "ssl_cert and ssl_key must be specified together".to_string(),
        });
    }

    let config = if let (Some(cert_path), Some(key_path)) = (&options.ssl_cert, &options.ssl_key) {
        let cert_file = tokio::fs::read(cert_path)
            .await
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Failed to read client cert file: {}", e),
            })?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Failed to parse client cert file: {}", e),
            })?;

        let key_file = tokio::fs::read(key_path)
            .await
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Failed to read client key file: {}", e),
            })?;
        let keys: Vec<PrivatePkcs8KeyDer<'static>> = PrivatePkcs8KeyDer::pem_slice_iter(&key_file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::OperationalError {
                code: String::new(),
                message: format!("Failed to parse client key file: {}", e),
            })?;
        if keys.is_empty() {
            return Err(Error::OperationalError {
                code: String::new(),
                message: "No PKCS8 private key found".to_string(),
            });
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

    config.map_err(|e| Error::OperationalError {
        code: String::new(),
        message: format!("Failed to build TLS config: {}", e),
    })
}
