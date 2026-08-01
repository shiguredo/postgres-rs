// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 統合テスト用のヘルパー。
#![allow(dead_code)]

use shiguredo_container::core::IntoContainerPort;
use shiguredo_container::{
    AsyncRunner, ContainerAsync, ContainerRequest, GenericImage, ImageExt, WaitFor,
};
use shiguredo_postgres::connection::{ConnectOptions, SslMode};
use shiguredo_tokio_postgres::connection::Connection;
use shiguredo_tokio_postgres::pool::{Pool, PoolConfig};
use std::time::Duration;

/// tracing subscriber を一度だけ初期化する。
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// PostgreSQL コンテナのイメージを組み立てる。
fn postgres_image() -> ContainerRequest<GenericImage> {
    GenericImage::new("postgres", "17")
        .with_exposed_port(5432.tcp())
        .with_ready_conditions(vec![WaitFor::message_on_stdout(
            "database system is ready to accept connections",
        )])
}

/// コンテナ起動後の PostgreSQL に接続するための接続オプションを組み立てる。
pub async fn build_postgres_options() -> (ConnectOptions, ContainerAsync<GenericImage>) {
    let node = postgres_image()
        .with_env_var("POSTGRES_PASSWORD", "password")
        .with_env_var("POSTGRES_DB", "test")
        // Apple Container はイメージの ENV を継承しないため、
        // データディレクトリと PATH を明示的に指定する。
        .with_env_var("PGDATA", "/var/lib/postgresql/data")
        .with_env_var(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin",
        )
        .start()
        .await
        .expect("PostgreSQL コンテナの起動に失敗しました");

    // macOS (Apple Container) ではコンテナの IP に直接接続する。
    // ポートフォワードは initdb の一時サーバーから本番サーバーへの
    // 切り替え時に接続が不安定になるため使わない。
    // Linux (Docker) ではポートフォワードを使う。
    #[cfg(target_os = "macos")]
    let (host, port) = {
        let ip = node
            .get_bridge_ip_address()
            .await
            .expect("コンテナの IP アドレス取得に失敗しました");
        (ip.to_string(), 5432)
    };
    #[cfg(not(target_os = "macos"))]
    let (host, port) = {
        let host = node
            .get_host()
            .await
            .expect("コンテナのホスト取得に失敗しました")
            .to_string();
        let port = node
            .get_host_port_ipv4(5432)
            .await
            .expect("コンテナのポート取得に失敗しました");
        (host, port)
    };

    let options = ConnectOptions {
        host,
        port,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("test".to_string()),
        // コンテナ起動直後は initdb の一時サーバーに接続してしまうことがある。
        // 認証タイムアウトを短くして、リトライで本番サーバーに接続し直す。
        connect_timeout: Duration::from_secs(5),
        ssl_mode: SslMode::Disabled,
        ..Default::default()
    };
    (options, node)
}

/// PostgreSQL に接続する。
///
/// コンテナの readiness ログ (initdb の一時サーバー) で
/// 接続可能と誤判定されることがあるため、接続できるまでリトライする。
pub async fn connect(options: &ConnectOptions) -> Connection {
    tracing::debug!(host = %options.host, port = options.port, "Connecting to PostgreSQL");
    let mut last_error = None;
    for attempt in 0..60 {
        match Connection::connect(options.clone()).await {
            Ok(conn) => return conn,
            Err(e) => {
                tracing::debug!(attempt, error = %e, "Connection attempt failed");
                last_error = Some(e);
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }
    panic!(
        "PostgreSQL への接続に失敗しました: {:?}",
        last_error.map(|e| e.to_string())
    );
}

/// プールを起動する。
///
/// コンテナ起動直後の一時サーバー問題で接続に失敗することがあるため、
/// 起動できるまでリトライする。
pub async fn start_pool(options: &ConnectOptions, config: PoolConfig) -> Pool {
    let mut last_error = None;
    for _ in 0..60 {
        match Pool::start(options.clone(), config.clone()).await {
            Ok(pool) => return pool,
            Err(e) => {
                last_error = Some(e);
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }
    panic!(
        "プールの起動に失敗しました: {:?}",
        last_error.map(|e| e.to_string())
    );
}

/// テーブルを作成する。
pub async fn create_test_table(conn: &mut Connection) {
    conn.query("DROP TABLE IF EXISTS test_items", false)
        .await
        .expect("DROP TABLE の実行に失敗しました");
    conn.query(
        "CREATE TABLE test_items (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0
        )",
        false,
    )
    .await
    .expect("CREATE TABLE の実行に失敗しました");
}
