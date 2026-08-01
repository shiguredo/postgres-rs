// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! connection モジュールの統合テスト。
//!
//! コンテナ上の PostgreSQL に対して、起動パラメーター、型指定付きクエリ、
//! バッチの結果セット取得、別タスクからのキャンセルを検証する。

// このテストバイナリでは一部のヘルパーだけを使うため、
// 残りのヘルパーが未使用になることを想定する。
#[expect(dead_code)]
#[path = "helpers/helpers.rs"]
mod helpers;

use shiguredo_postgres::batch::Batch;
use shiguredo_postgres::connection::Connection;
use shiguredo_postgres::constants::oid;
use shiguredo_postgres::converters::Value;
use std::time::{Duration, Instant};

/// 起動パラメーターがスタートアップメッセージで送られることを確認する。
#[tokio::test]
async fn test_runtime_params_are_sent_in_startup() {
    helpers::init_tracing();
    let (mut options, _node) = helpers::build_postgres_options().await;
    options.runtime_params = vec![
        ("search_path".to_string(), "pg_catalog".to_string()),
        ("statement_timeout".to_string(), "1234ms".to_string()),
    ];
    let mut conn = helpers::connect(&options).await;

    let row = conn
        .query_one(
            "SELECT current_setting('search_path'), current_setting('statement_timeout')",
            &[],
        )
        .await
        .expect("設定値の取得に失敗しました");
    assert_eq!(
        row.get::<String>(0).expect("search_path を取得できません"),
        "pg_catalog",
        "search_path が起動パラメーターの値と一致しません"
    );
    assert_eq!(
        row.get::<String>(1)
            .expect("statement_timeout を取得できません"),
        "1234ms",
        "statement_timeout が起動パラメーターの値と一致しません"
    );
}

/// 予約済みの起動パラメーターが接続の確立前に拒否されることを確認する。
#[tokio::test]
async fn test_reserved_runtime_param_is_rejected() {
    helpers::init_tracing();
    let (mut options, _node) = helpers::build_postgres_options().await;
    options.runtime_params = vec![("user".to_string(), "other".to_string())];

    let error = Connection::connect(options)
        .await
        .err()
        .expect("予約済みの起動パラメーターが受理されました");
    assert_eq!(
        error.message(),
        "Runtime parameter `user` is reserved",
        "エラーメッセージが一致しません"
    );
}

/// 型 OID を明示して準備した文を実行できることを確認する。
#[tokio::test]
async fn test_prepare_typed_and_execute_prepared() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let statement = conn
        .prepare_typed("SELECT $1", &[oid::INT4])
        .await
        .expect("型指定付きの準備に失敗しました");
    assert_eq!(
        statement.parameter_oids(),
        &[oid::INT4],
        "サーバーが返したパラメーターの型が一致しません"
    );

    conn.execute_prepared(&statement, &[Value::Int4(7)], false)
        .await
        .expect("準備済み文の実行に失敗しました");
    let result = conn.result().expect("結果がありません");
    assert_eq!(result.rows[0][0], Value::Int4(7), "実行結果が一致しません");

    conn.deallocate(&statement)
        .await
        .expect("文の解放に失敗しました");
}

/// 型 OID の明示が結果の型に反映されることを確認する。
#[tokio::test]
async fn test_execute_typed_applies_the_requested_type() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // 整数として解釈させる。
    conn.execute_typed("SELECT $1", &[oid::INT4], &[Value::Int4(9)], false)
        .await
        .expect("INTEGER 指定の実行に失敗しました");
    let result = conn.result().expect("結果がありません");
    assert_eq!(result.rows[0][0], Value::Int4(9), "実行結果が一致しません");

    // 同じ SQL でも型 OID が違えば別の文として扱われる。
    conn.execute_typed(
        "SELECT $1",
        &[oid::TEXT],
        &[Value::Text("hello".to_string())],
        false,
    )
    .await
    .expect("TEXT 指定の実行に失敗しました");
    let result = conn.result().expect("結果がありません");
    assert_eq!(
        result.rows[0][0],
        Value::Text("hello".to_string()),
        "実行結果が一致しません"
    );
}

/// バッチの各ステートメントの行を取得できることを確認する。
#[tokio::test]
async fn test_batch_execute_rows_returns_each_result_set() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut batch = Batch::new();
    batch.append("SELECT 1::int4 AS a", &[]);
    batch.append("SELECT $1::int4 AS b", &[Value::Int4(2)]);
    batch.append("CREATE TEMP TABLE batch_rows_tmp (value int4)", &[]);
    batch.append("SELECT 'x'::text AS c", &[]);

    let results = conn
        .batch_execute_rows(batch)
        .await
        .expect("行付きバッチの実行に失敗しました");
    assert_eq!(results.len(), 4, "結果の数が一致しません");

    let first = results[0].as_ref().expect("1 件目の結果");
    assert_eq!(first.fields[0].name, "a", "列名が一致しません");
    assert_eq!(first.rows[0][0], Value::Int4(1), "1 件目の行が一致しません");

    let second = results[1].as_ref().expect("2 件目の結果");
    assert_eq!(
        second.rows[0][0],
        Value::Int4(2),
        "2 件目の行が一致しません"
    );

    let third = results[2].as_ref().expect("3 件目の結果");
    assert!(third.rows.is_empty(), "行を返さない文に行があります");
    assert_eq!(
        third.tag.as_deref(),
        Some("CREATE TABLE"),
        "3 件目のコマンドタグが一致しません"
    );

    let fourth = results[3].as_ref().expect("4 件目の結果");
    assert_eq!(
        fourth.rows[0][0],
        Value::Text("x".to_string()),
        "4 件目の行が一致しません"
    );

    // バッチの後も接続を再利用できる。
    conn.ping().await.expect("バッチ後の ping に失敗しました");
}

/// 途中でエラーになったバッチの後続が未実行として返ることを確認する。
#[tokio::test]
async fn test_batch_execute_rows_reports_unexecuted_statements() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut batch = Batch::new();
    batch.append("SELECT 1::int4 AS a", &[]);
    batch.append("SELECT * FROM no_such_table", &[]);
    batch.append("SELECT 3::int4 AS c", &[]);

    let results = conn
        .batch_execute_rows(batch)
        .await
        .expect("行付きバッチの実行に失敗しました");
    assert_eq!(results.len(), 3, "結果の数が一致しません");
    assert!(results[0].is_ok(), "1 件目は成功するはずです");
    assert!(
        matches!(&results[1], Err(error) if error.code() == Some("42P01")),
        "2 件目は SQLSTATE 42P01 が期待されます"
    );
    assert!(
        results[2].is_err(),
        "3 件目はエラー後に実行されないためエラーになるはずです"
    );

    conn.ping()
        .await
        .expect("バッチエラー後の ping に失敗しました");
}

/// 別タスクから実行中のクエリをキャンセルできることを確認する。
#[tokio::test]
async fn test_cancel_token_cancels_a_running_query() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let token = conn
        .cancel_token()
        .expect("キャンセルトークンの作成に失敗しました");
    let pid = i32::try_from(conn.backend_process_id()).expect("バックエンド PID が範囲外です");
    let mut monitor = helpers::connect(&options).await;
    let cancel = tokio::spawn(async move {
        // サーバーはコマンドを待っている間に受け取ったキャンセルを無視するため、
        // クエリが実行中になったことを pg_stat_activity で確かめてから送る。
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let row = monitor
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                     WHERE pid = $1 AND state = 'active' AND query = 'SELECT pg_sleep(10)')",
                    &[Value::Int4(pid)],
                )
                .await
                .expect("pg_stat_activity の参照に失敗しました");
            if row.get::<bool>(0).expect("実行状態を取得できません") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "クエリが実行中になりませんでした"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        token.cancel().await
    });

    let error = conn
        .query("SELECT pg_sleep(10)", false)
        .await
        .expect_err("キャンセルしたクエリが成功しました");
    // 57014 は query_canceled。ほかの理由で失敗した場合と区別する。
    assert_eq!(
        error.code(),
        Some("57014"),
        "キャンセルによるエラーが返りませんでした: {error}"
    );
    cancel
        .await
        .expect("キャンセルタスクが失敗しました")
        .expect("キャンセル要求の送信に失敗しました");

    // キャンセル後も接続を再利用できる。
    conn.ping()
        .await
        .expect("キャンセル後の ping に失敗しました");
}
