// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 統合テスト用のヘルパー。

use shiguredo_container::core::IntoContainerPort;
use shiguredo_container::core::wait::LogWaitStrategy;
use shiguredo_container::{
    AsyncRunner, ContainerAsync, ContainerRequest, GenericImage, ImageExt, WaitFor,
};
use shiguredo_postgres::connection::{ConnectOptions, Connection, SslMode};
use shiguredo_postgres::pool::{Pool, PoolConfig};
use std::time::Duration;

/// tracing subscriber を一度だけ初期化する。
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// テスト対象の PostgreSQL バージョン。
///
/// 環境変数 `POSTGRES_VERSION` で指定する (デフォルトは 17)。
/// CI では matrix で 19 / 18 / 17 / 16 を切り替えて実行する。
pub fn postgres_version() -> String {
    std::env::var("POSTGRES_VERSION").unwrap_or_else(|_| "17".to_string())
}

/// PostgreSQL のメジャーバージョン番号を取り出す。
///
/// `19` や `19.0` のようなタグから先頭の数字だけを取り出す。
/// イメージ内のディレクトリ名 (`/usr/lib/postgresql/<major>/bin`) に使う。
fn postgres_major(version: &str) -> String {
    version.chars().take_while(|c| c.is_ascii_digit()).collect()
}

/// PostgreSQL コンテナのイメージを組み立てる。
fn postgres_image(version: &str) -> ContainerRequest<GenericImage> {
    GenericImage::new("postgres", version)
        .with_exposed_port(5432.tcp())
        // 同じ行を initdb の一時サーバーと本番サーバーの両方が出力する。
        // 一時サーバーは TCP で待ち受けないため、本番サーバーの 2 回目まで待つ。
        // どちらのストリームに出るかはコンテナランタイムによって異なるため、
        // stdout と stderr を合わせて数える。
        .with_ready_conditions(vec![WaitFor::log(
            LogWaitStrategy::stdout_or_stderr("database system is ready to accept connections")
                .with_times(2),
        )])
        // Apple Container はイメージの ENV を継承しないため、
        // データディレクトリと PATH を明示的に指定する。
        .with_env_var("PGDATA", "/var/lib/postgresql/data")
        .with_env_var(
            "PATH",
            format!(
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/{}/bin",
                postgres_major(version)
            ),
        )
}

/// コンテナ起動後の PostgreSQL に接続するための接続オプションを組み立てる。
pub async fn build_postgres_options() -> (ConnectOptions, ContainerAsync<GenericImage>) {
    let version = postgres_version();
    let node = postgres_image(&version)
        .with_env_var("POSTGRES_PASSWORD", "password")
        .with_env_var("POSTGRES_DB", "test")
        .start()
        .await
        .unwrap_or_else(|e| panic!("PostgreSQL {} コンテナの起動に失敗しました: {}", version, e));

    // ローカルのポート転送だけを使う。リモートのコンテナ環境には平文で接続しない。
    let host = node
        .get_host()
        .await
        .expect("コンテナのホストを取得できません")
        .to_string();
    assert!(
        matches!(host.as_str(), "localhost" | "127.0.0.1"),
        "テストにはローカルのポート転送が必要です"
    );
    let port = node
        .get_host_port_ipv4(5432)
        .await
        .expect("転送ポートを取得できません");

    let options = ConnectOptions {
        host,
        port,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("test".to_string()),
        // 応答しない接続でテストが長く止まらないよう、認証タイムアウトを短くする。
        connect_timeout: Duration::from_secs(5),
        ssl_mode: SslMode::Disabled,
        ..Default::default()
    };
    (options, node)
}

/// PostgreSQL に接続する。
///
/// コンテナは本番サーバーの起動まで待ってから返るため、リトライしない。
pub async fn connect(options: &ConnectOptions) -> Connection {
    Connection::connect(options.clone())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "PostgreSQL ({}:{}) への接続に失敗しました: {e}",
                options.host, options.port
            )
        })
}

/// プールを起動する。
///
/// コンテナは本番サーバーの起動まで待ってから返るため、リトライしない。
pub async fn start_pool(options: &ConnectOptions, config: PoolConfig) -> Pool {
    Pool::start(options.clone(), config)
        .await
        .unwrap_or_else(|e| panic!("プールの起動に失敗しました: {e}"))
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
