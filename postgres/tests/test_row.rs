// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! row モジュールの統合テスト。
//!
//! コンテナ上の PostgreSQL に対して、行数の検査付き取得と
//! 列番号・列名からの型付き取得を検証する。

// このテストバイナリでは一部のヘルパーだけを使うため、
// 残りのヘルパーが未使用になることを想定する。
#[expect(dead_code)]
#[path = "helpers/helpers.rs"]
mod helpers;

#[tokio::test]
async fn test_query_one_reads_typed_values() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let row = conn
        .query_one(
            "SELECT 42::int4 AS id, 'postgres'::text AS name, NULL::text AS note, true AS active",
            &[],
        )
        .await
        .expect("1 行の取得に失敗しました");

    assert_eq!(row.len(), 4, "列数が一致しません");
    assert_eq!(
        row.get::<i32>(0).expect("整数を取得できません"),
        42,
        "列番号からの取得結果が一致しません"
    );
    assert_eq!(
        row.get_by_name::<String>("name")
            .expect("文字列を取得できません"),
        "postgres",
        "列名からの取得結果が一致しません"
    );
    assert!(
        row.get_opt::<String>(2)
            .expect("NULL を取得できません")
            .is_none(),
        "NULL が None になりません"
    );
    assert!(
        row.get::<String>(2).is_err(),
        "NULL を型付きで取得できてしまいました"
    );
    assert!(
        row.get_by_name::<bool>("active")
            .expect("真偽値を取得できません"),
        "真偽値の取得結果が一致しません"
    );
    assert_eq!(
        row.column_names().collect::<Vec<_>>(),
        vec!["id", "name", "note", "active"],
        "列名の並びが一致しません"
    );
}

#[tokio::test]
async fn test_query_one_rejects_unexpected_row_counts() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    assert!(
        conn.query_one("SELECT 1 WHERE false", &[]).await.is_err(),
        "0 行のクエリが成功しました"
    );
    assert!(
        conn.query_one("SELECT generate_series(1, 2)", &[])
            .await
            .is_err(),
        "2 行のクエリが成功しました"
    );

    // 行数検査に失敗しても接続は再利用できる。
    conn.ping().await.expect("行数検査後の ping に失敗しました");
}

#[tokio::test]
async fn test_query_opt_accepts_zero_or_one_row() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    assert!(
        conn.query_opt("SELECT 1 WHERE false", &[])
            .await
            .expect("0 行の取得に失敗しました")
            .is_none(),
        "0 行が None になりません"
    );

    let row = conn
        .query_opt("SELECT 7::int4 AS value", &[])
        .await
        .expect("1 行の取得に失敗しました")
        .expect("1 行が None になりました");
    assert_eq!(
        row.get_by_name::<i32>("value")
            .expect("整数を取得できません"),
        7,
        "取得結果が一致しません"
    );

    assert!(
        conn.query_opt("SELECT generate_series(1, 2)", &[])
            .await
            .is_err(),
        "2 行のクエリが成功しました"
    );
}

/// 複数行の結果をすべて Row として取得し、列名から型付きで読めることを確認する。
#[tokio::test]
async fn test_query_all_reads_every_row() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let rows = conn
        .query_all(
            "SELECT n AS id, 'row ' || n AS label FROM generate_series(1, $1::int4) AS n ORDER BY n",
            &[shiguredo_postgres::converters::Value::Int4(3)],
        )
        .await
        .expect("複数行の取得に失敗しました");
    let read: Vec<(i32, String)> = rows
        .iter()
        .map(|row| {
            (
                row.get_by_name::<i32>("id").expect("id を取得できません"),
                row.get_by_name::<String>("label")
                    .expect("label を取得できません"),
            )
        })
        .collect();
    assert_eq!(
        read,
        vec![
            (1, "row 1".to_string()),
            (2, "row 2".to_string()),
            (3, "row 3".to_string())
        ],
        "取得した行が一致しません"
    );

    // 0 行の結果は空の一覧になり、続けて同じ接続を使える。
    assert!(
        conn.query_all("SELECT 1 WHERE false", &[])
            .await
            .expect("0 行の取得に失敗しました")
            .is_empty(),
        "0 行の結果が空になりません"
    );
    conn.ping().await.expect("取得後の ping に失敗しました");
}

#[tokio::test]
async fn test_row_type_mismatch_is_an_error() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let row = conn
        .query_one("SELECT 1::int4 AS value", &[])
        .await
        .expect("1 行の取得に失敗しました");
    assert!(row.get::<bool>(0).is_err(), "型の異なる変換が成功しました");
    assert!(row.get::<i16>(0).is_err(), "整数の縮小変換が成功しました");
    assert!(
        row.get_by_name::<i32>("missing").is_err(),
        "存在しない列名が受理されました"
    );
}
