// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! pgbouncer を経由した接続の統合テスト。
//!
//! コンテナ上で PostgreSQL と pgbouncer を起動し、pgbouncer に接続して動作を確認する。
//! pgbouncer は起動時のパラメーターを正規化せずに保存し、接続の確立時にそのまま
//! ParameterStatus で返す (src/varcache.c の varcache_set と src/proto.c の welcome_client)。
//! transaction モードでは、サーバーを切り替えるたびにクライアントの設定を SET で送り直す。

// このテストバイナリでは一部のヘルパーだけを使うため、
// 残りのヘルパーが未使用になることを想定する。
#[expect(dead_code)]
#[path = "helpers/helpers.rs"]
mod helpers;

use shiguredo_container::core::IntoContainerPort;
use shiguredo_container::{AsyncRunner, ContainerAsync, GenericImage, ImageExt, WaitFor};
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::Value;
use shiguredo_postgres::error::Error;

/// pgbouncer のイメージ。CloudNativePG が PGDG の pgbouncer パッケージから作っている。
const PGBOUNCER_IMAGE: &str = "ghcr.io/cloudnative-pg/pgbouncer";

/// pgbouncer のバージョン。
const PGBOUNCER_TAG: &str = "1.26.1";

/// pgbouncer が待ち受けるポート。
const PGBOUNCER_PORT: u16 = 6432;

/// pgbouncer のプールモード。
#[derive(Debug, Clone, Copy)]
enum PoolMode {
    /// クライアントの接続の間、同じサーバー接続を使う。
    Session,
    /// トランザクションごとにサーバー接続を割り当てる。
    Transaction,
}

impl PoolMode {
    /// pgbouncer.ini の `pool_mode` の値。
    fn name(self) -> &'static str {
        match self {
            PoolMode::Session => "session",
            PoolMode::Transaction => "transaction",
        }
    }
}

/// PostgreSQL の前に pgbouncer を起動し、pgbouncer への接続オプションを返す。
///
/// コンテナは戻り値が破棄されるまで動かし続ける。
async fn start_pgbouncer(
    mode: PoolMode,
) -> (
    ConnectOptions,
    ContainerAsync<GenericImage>,
    ContainerAsync<GenericImage>,
) {
    let (postgres_options, postgres) = helpers::build_postgres_options().await;

    // pgbouncer はコンテナの IP で PostgreSQL に接続する。
    let postgres_ip = postgres
        .get_bridge_ip_address()
        .await
        .expect("PostgreSQL コンテナの IP アドレス取得に失敗しました");
    // 認証は SCRAM-SHA-256 とし、pgbouncer は平文のパスワードでサーバーにも SCRAM で接続する。
    // 名前付きのプリペアドステートメントを transaction モードでも使えるよう、
    // max_prepared_statements でプロトコルレベルの対応を有効にする。
    let config = format!(
        "[databases]\n\
         test = host={postgres_ip} port=5432 dbname=test\n\
         \n\
         [pgbouncer]\n\
         listen_addr = 0.0.0.0\n\
         listen_port = {PGBOUNCER_PORT}\n\
         unix_socket_dir =\n\
         auth_type = scram-sha-256\n\
         auth_file = /tmp/userlist.txt\n\
         pool_mode = {}\n\
         max_prepared_statements = 100\n\
         server_tls_sslmode = disable\n",
        mode.name()
    );
    // 設定はコンテナ内のシェルでファイルに書いてから pgbouncer を起動する。
    // Apple Container ではファイルのコピーがプロセスの起動後になり、
    // pgbouncer がイメージ既定の設定で起動して終了してしまうため、コピーは使わない。
    let pgbouncer = GenericImage::new(PGBOUNCER_IMAGE, PGBOUNCER_TAG)
        .with_entrypoint("/bin/sh")
        .with_exposed_port(PGBOUNCER_PORT.tcp())
        .with_ready_conditions(vec![WaitFor::message_on_either_std("process up")])
        .with_env_var("PGBOUNCER_INI", config)
        .with_env_var("PGBOUNCER_USERLIST", "\"postgres\" \"password\"\n")
        // pgbouncer は root では起動しない。イメージの設定を引き継がない環境に備えて明示する。
        .with_user("pgbouncer")
        .with_cmd([
            "-c",
            "printf '%s' \"$PGBOUNCER_INI\" > /tmp/pgbouncer.ini && \
             printf '%s' \"$PGBOUNCER_USERLIST\" > /tmp/userlist.txt && \
             exec /usr/bin/pgbouncer /tmp/pgbouncer.ini",
        ])
        .start()
        .await
        .unwrap_or_else(|e| panic!("pgbouncer コンテナの起動に失敗しました: {e}"));

    // PostgreSQL への接続と同じく、ローカルのポート転送で pgbouncer に接続する。
    let port = pgbouncer
        .get_host_port_ipv4(PGBOUNCER_PORT)
        .await
        .expect("pgbouncer の転送ポートを取得できません");
    let options = ConnectOptions {
        port,
        ..postgres_options
    };
    (options, pgbouncer, postgres)
}

/// pgbouncer を経由して、起動、単純クエリ、拡張クエリ、プリペアドステートメントを確かめる。
async fn check_queries(conn: &mut Connection) {
    // DATE は ISO 形式として復号でき、非 ASCII の文字列は UTF-8 のまま往復する。
    conn.query("SELECT DATE '2026-11-23', 'あ'::text", false)
        .await
        .expect("単純クエリの実行に失敗しました");
    let rows = &conn.result().expect("結果がありません").rows;
    assert!(
        matches!(rows[0][0], Value::Date(_)),
        "日付として復号されていません: {:?}",
        rows[0][0]
    );
    assert_eq!(
        rows[0][1],
        Value::Text("あ".to_string()),
        "文字列が一致しません"
    );

    conn.execute("SELECT $1::int + 1", &[Value::Int4(41)], false)
        .await
        .expect("拡張クエリの実行に失敗しました");
    let rows = &conn.result().expect("結果がありません").rows;
    assert_eq!(
        rows[0][0],
        Value::Int4(42),
        "拡張クエリの結果が一致しません"
    );

    let statement = conn
        .prepare("SELECT $1::text || '!'")
        .await
        .expect("プリペアドステートメントの準備に失敗しました");
    for value in ["a", "b"] {
        conn.execute_prepared(&statement, &[Value::Text(value.to_string())], false)
            .await
            .expect("プリペアドステートメントの実行に失敗しました");
        let rows = &conn.result().expect("結果がありません").rows;
        assert_eq!(
            rows[0][0],
            Value::Text(format!("{value}!")),
            "プリペアドステートメントの結果が一致しません"
        );
    }

    // ISO のままの日付順序の変更は受理し、後続のトランザクションでも日付を復号できる。
    conn.query("SET DateStyle = 'ISO, DMY'", false)
        .await
        .expect("日付順序の変更に失敗しました");
    conn.query("SELECT DATE '2026-11-23'", false)
        .await
        .expect("日付順序の変更後のクエリの実行に失敗しました");
    let rows = &conn.result().expect("結果がありません").rows;
    assert!(
        matches!(rows[0][0], Value::Date(_)),
        "日付順序の変更後に日付として復号されていません: {:?}",
        rows[0][0]
    );
}

/// 復号の前提を崩す変更は、pgbouncer を経由しても通知され、接続を閉じる。
async fn check_breaking_parameter_change(options: &ConnectOptions) {
    let mut conn = helpers::connect(options).await;
    let error = conn
        .query("SET client_encoding = 'LATIN1'; SELECT 'x'", false)
        .await
        .expect_err("復号の前提を崩す変更を受理しました");
    assert!(
        matches!(error, Error::NotSupportedError(_)),
        "未サポートエラーではありません: {error:?}"
    );
    assert!(!conn.is_open(), "接続が閉じていません");
}

#[tokio::test]
async fn test_pgbouncer_session_mode() {
    helpers::init_tracing();
    let (options, _pgbouncer, _postgres) = start_pgbouncer(PoolMode::Session).await;

    // pgbouncer は起動時に送った DateStyle=ISO をそのまま返すが、出力形式は ISO なので接続できる。
    let mut conn = helpers::connect(&options).await;
    check_queries(&mut conn).await;
    check_breaking_parameter_change(&options).await;
}

#[tokio::test]
async fn test_pgbouncer_transaction_mode() {
    helpers::init_tracing();
    let (options, _pgbouncer, _postgres) = start_pgbouncer(PoolMode::Transaction).await;

    let mut conn = helpers::connect(&options).await;
    check_queries(&mut conn).await;
    check_breaking_parameter_change(&options).await;
}
