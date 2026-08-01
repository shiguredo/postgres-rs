// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! shiguredo_container を使った PostgreSQL 接続統合テスト。
//!
//! コンテナ上で PostgreSQL コンテナを起動し、tokio_postgres クレートから
//! 実際に接続・クエリ実行・結果取得ができることを確認する。
//! デフォルト設定では scram-sha-256 認証になるため、
//! SCRAM 認証フローも併せて検証される。

mod helpers;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use shiguredo_postgres::converters::Value;
use shiguredo_postgres::error::Error;
use shiguredo_tokio_postgres::cursor::{Cursor, DictCursor};
use shiguredo_tokio_postgres::pool::PoolConfig;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::test]
async fn test_select_one_plus_one() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("SELECT 1 + 1")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows.len(), 1, "行数が一致しません");
    assert_eq!(rows[0][0], Value::Int4(2), "計算結果が一致しません");
}

#[tokio::test]
async fn test_create_insert_and_select() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    helpers::create_test_table(&mut conn).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .execute(
            "INSERT INTO test_items (name, quantity) VALUES ($1, $2)",
            &[Value::Text("apple".to_string()), Value::Int4(5)],
        )
        .await
        .expect("INSERT の実行に失敗しました");
    cursor
        .execute(
            "INSERT INTO test_items (name, quantity) VALUES ($1, $2)",
            &[Value::Text("banana".to_string()), Value::Int4(3)],
        )
        .await
        .expect("INSERT の実行に失敗しました");

    cursor
        .query("SELECT id, name, quantity FROM test_items ORDER BY id")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows.len(), 2, "行数が一致しません");
    assert_eq!(rows[0][0], Value::Int4(1), "id が一致しません");
    assert_eq!(
        rows[0][1],
        Value::Text("apple".to_string()),
        "name が一致しません"
    );
    assert_eq!(rows[0][2], Value::Int4(5), "quantity が一致しません");
    assert_eq!(rows[1][1], Value::Text("banana".to_string()));

    // 削除と件数確認。
    cursor
        .execute(
            "DELETE FROM test_items WHERE name = $1",
            &[Value::Text("apple".to_string())],
        )
        .await
        .expect("DELETE の実行に失敗しました");
    cursor
        .query("SELECT COUNT(*) FROM test_items")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int8(1), "件数が一致しません");
}

#[tokio::test]
async fn test_dict_cursor() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    helpers::create_test_table(&mut conn).await;

    let mut cursor = DictCursor::new(Cursor::new(&mut conn));
    cursor
        .execute(
            "INSERT INTO test_items (name, quantity) VALUES ($1, $2)",
            &[Value::Text("cherry".to_string()), Value::Int4(7)],
        )
        .await
        .expect("INSERT の実行に失敗しました");
    cursor
        .query("SELECT id, name, quantity FROM test_items")
        .await
        .expect("SELECT の実行に失敗しました");

    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows.len(), 1, "行数が一致しません");
    let row: &HashMap<String, Value> = &rows[0];
    assert_eq!(row.get("id"), Some(&Value::Int4(1)), "id が一致しません");
    assert_eq!(
        row.get("name"),
        Some(&Value::Text("cherry".to_string())),
        "name が一致しません"
    );
    assert_eq!(
        row.get("quantity"),
        Some(&Value::Int4(7)),
        "quantity が一致しません"
    );
}

#[tokio::test]
async fn test_prepared_statement() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .execute(
            "SELECT $1::int + $2::int",
            &[Value::Int4(10), Value::Int4(32)],
        )
        .await
        .expect("パラメータ付き SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int4(42), "計算結果が一致しません");

    // テキストパラメータ。
    cursor
        .execute("SELECT $1::text", &[Value::Text("hello".to_string())])
        .await
        .expect("テキストパラメータの実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Text("hello".to_string()),
        "テキストが一致しません"
    );

    // 複数回実行しても同じ結果になる (ステートメントの再利用)。
    for _ in 0..3 {
        cursor
            .execute("SELECT $1::int", &[Value::Int4(7)])
            .await
            .expect("繰り返し実行に失敗しました");
        let rows = cursor.fetch_all().expect("結果取得に失敗しました");
        assert_eq!(rows[0][0], Value::Int4(7), "値が一致しません");
    }
}

#[tokio::test]
async fn test_null_values() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS null_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE null_test (a TEXT, b INTEGER)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");
    cursor
        .execute(
            "INSERT INTO null_test VALUES ($1, $2)",
            &[Value::Null, Value::Null],
        )
        .await
        .expect("INSERT の実行に失敗しました");
    cursor
        .query("SELECT a, b FROM null_test")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows.len(), 1, "行数が一致しません");
    assert_eq!(rows[0][0], Value::Null, "a が NULL になりません");
    assert_eq!(rows[0][1], Value::Null, "b が NULL になりません");

    // NOT NULL 制約違反のエラー (SQLSTATE 23502、クラス 23: 整合性制約違反)。
    cursor
        .query("DROP TABLE IF EXISTS not_null_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE not_null_test (a TEXT NOT NULL)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");
    let result = cursor
        .execute("INSERT INTO not_null_test VALUES ($1)", &[Value::Null])
        .await;
    assert!(
        matches!(result, Err(Error::IntegrityError { ref code, .. }) if code == "23502"),
        "SQLSTATE 23502 が期待されるが {:?} が返った",
        result
    );
}

#[tokio::test]
async fn test_type_conversions() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS type_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query(
            "CREATE TABLE type_test (
                b BOOLEAN,
                s SMALLINT,
                i INTEGER,
                bi BIGINT,
                r REAL,
                d DOUBLE PRECISION,
                t TEXT,
                bt BYTEA,
                dt DATE,
                tm TIME,
                ts TIMESTAMP,
                tstz TIMESTAMPTZ
            )",
        )
        .await
        .expect("CREATE TABLE の実行に失敗しました");

    let date = NaiveDate::from_ymd_opt(2024, 1, 15).expect("有効な日付です");
    let time = NaiveTime::from_hms_micro_opt(12, 34, 56, 123_456).expect("有効な時刻です");
    let timestamp = NaiveDateTime::new(
        date,
        NaiveTime::from_hms_micro_opt(12, 34, 56, 123_456).expect("有効な時刻です"),
    );
    let timestamptz = Utc
        .with_ymd_and_hms(2024, 1, 15, 12, 34, 56)
        .single()
        .expect("有効な日時です")
        + chrono::Duration::microseconds(123_456);

    cursor
        .execute(
            "INSERT INTO type_test VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                Value::Bool(true),
                Value::Int2(-32768),
                Value::Int4(2147483647),
                Value::Int8(-9223372036854775808),
                Value::Float4(1.5),
                Value::Float8(std::f64::consts::PI),
                Value::Text("日本語テキスト".to_string()),
                Value::Bytes(vec![0x00, 0x01, 0xff, 0xfe]),
                Value::Date(date),
                Value::Time(time),
                Value::Timestamp(timestamp),
                Value::Timestamptz(timestamptz),
            ],
        )
        .await
        .expect("INSERT の実行に失敗しました");

    cursor
        .query("SELECT * FROM type_test")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows.len(), 1, "行数が一致しません");
    let row = &rows[0];
    assert_eq!(row[0], Value::Bool(true), "boolean が一致しません");
    assert_eq!(row[1], Value::Int2(-32768), "smallint が一致しません");
    assert_eq!(row[2], Value::Int4(2147483647), "integer が一致しません");
    assert_eq!(
        row[3],
        Value::Int8(-9223372036854775808),
        "bigint が一致しません"
    );
    assert_eq!(row[4], Value::Float4(1.5), "real が一致しません");
    assert_eq!(
        row[5],
        Value::Float8(std::f64::consts::PI),
        "double precision が一致しません"
    );
    assert_eq!(
        row[6],
        Value::Text("日本語テキスト".to_string()),
        "text が一致しません"
    );
    assert_eq!(
        row[7],
        Value::Bytes(vec![0x00, 0x01, 0xff, 0xfe]),
        "bytea が一致しません"
    );
    assert_eq!(row[8], Value::Date(date), "date が一致しません");
    assert_eq!(row[9], Value::Time(time), "time が一致しません");
    assert_eq!(
        row[10],
        Value::Timestamp(timestamp),
        "timestamp が一致しません"
    );
    assert_eq!(
        row[11],
        Value::Timestamptz(timestamptz),
        "timestamptz が一致しません"
    );
}

#[tokio::test]
async fn test_transaction_rollback() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS tx_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE tx_test (v INTEGER)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");

    cursor
        .query("BEGIN")
        .await
        .expect("BEGIN の実行に失敗しました");
    cursor
        .execute("INSERT INTO tx_test VALUES ($1)", &[Value::Int4(1)])
        .await
        .expect("INSERT の実行に失敗しました");
    cursor
        .query("ROLLBACK")
        .await
        .expect("ROLLBACK の実行に失敗しました");

    cursor
        .query("SELECT COUNT(*) FROM tx_test")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int8(0), "ROLLBACK が効いていません");

    // COMMIT の場合は残る。
    cursor
        .query("BEGIN")
        .await
        .expect("BEGIN の実行に失敗しました");
    cursor
        .execute("INSERT INTO tx_test VALUES ($1)", &[Value::Int4(2)])
        .await
        .expect("INSERT の実行に失敗しました");
    cursor
        .query("COMMIT")
        .await
        .expect("COMMIT の実行に失敗しました");
    cursor
        .query("SELECT COUNT(*) FROM tx_test")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int8(1), "COMMIT が効いていません");
}

#[tokio::test]
async fn test_server_error() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    // 存在しないテーブルへのクエリ。
    let result = cursor.query("SELECT * FROM no_such_table").await;
    assert!(
        matches!(result, Err(Error::ProgrammingError { ref code, .. }) if code == "42P01"),
        "SQLSTATE 42P01 が期待されるが {:?} が返った",
        result
    );

    // 構文エラー。
    let result = cursor.query("SELECT FROM").await;
    assert!(
        matches!(result, Err(Error::ProgrammingError { ref code, .. }) if code == "42601"),
        "SQLSTATE 42601 が期待されるが {:?} が返った",
        result
    );

    // エラー後も正常にクエリを実行できる。
    cursor
        .query("SELECT 1")
        .await
        .expect("エラー後のクエリに失敗しました");
}

#[tokio::test]
async fn test_integrity_error() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS unique_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE unique_test (v INTEGER UNIQUE)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");
    cursor
        .execute("INSERT INTO unique_test VALUES ($1)", &[Value::Int4(1)])
        .await
        .expect("INSERT の実行に失敗しました");

    // 一意制約違反。
    let result = cursor
        .execute("INSERT INTO unique_test VALUES ($1)", &[Value::Int4(1)])
        .await;
    assert!(
        matches!(result, Err(Error::IntegrityError { ref code, .. }) if code == "23505"),
        "SQLSTATE 23505 が期待されるが {:?} が返った",
        result
    );

    // エラー後も正常にクエリを実行できる。
    cursor
        .query("SELECT 1")
        .await
        .expect("エラー後のクエリに失敗しました");
}

#[tokio::test]
async fn test_float_special_values() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .execute(
            "SELECT $1::double precision, $2::double precision, $3::double precision",
            &[
                Value::Float8(f64::NAN),
                Value::Float8(f64::INFINITY),
                Value::Float8(f64::NEG_INFINITY),
            ],
        )
        .await
        .expect("特殊値の SELECT に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert!(
        matches!(rows[0][0], Value::Float8(v) if v.is_nan()),
        "NaN が一致しません"
    );
    assert_eq!(
        rows[0][1],
        Value::Float8(f64::INFINITY),
        "Infinity が一致しません"
    );
    assert_eq!(
        rows[0][2],
        Value::Float8(f64::NEG_INFINITY),
        "-Infinity が一致しません"
    );
}

#[tokio::test]
async fn test_parallel_queries() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;

    // 複数の接続を並列に確立してクエリを実行する。
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let options = options.clone();
            tokio::spawn(async move {
                let mut conn = helpers::connect(&options).await;
                let mut cursor = Cursor::new(&mut conn);
                cursor
                    .query(&format!("SELECT {} * 2", i))
                    .await
                    .expect("SELECT の実行に失敗しました");
                let rows = cursor.fetch_all().expect("結果取得に失敗しました");
                rows[0][0].clone()
            })
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let value = handle.await.expect("並列タスクがパニックしました");
        assert_eq!(value, Value::Int4((i as i32) * 2), "並列結果が一致しません");
    }
}

#[tokio::test]
async fn test_pool() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;

    let config = PoolConfig {
        max_size: 4,
        min_idle: 1,
        acquire_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    // 複数タスクからプールを共有する。
    let mut handles = Vec::new();
    for i in 0..8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
            let mut cursor = Cursor::new(pooled.connection_mut());
            cursor
                .query(&format!("SELECT {}", i))
                .await
                .expect("SELECT の実行に失敗しました");
            let rows = cursor.fetch_all().expect("結果取得に失敗しました");
            rows[0][0].clone()
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let value = handle.await.expect("プールタスクがパニックしました");
        assert_eq!(value, Value::Int4(i as i32), "プール結果が一致しません");
    }

    pool.close().await.expect("プールの停止に失敗しました");
}

#[tokio::test]
async fn test_discard_connection() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;

    let config = PoolConfig {
        max_size: 2,
        min_idle: 1,
        acquire_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    // 破棄された接続はプールに返却されない。
    {
        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        pooled.discard();
    }

    // 破棄後も新しい接続を取得できる。
    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    let mut cursor = Cursor::new(pooled.connection_mut());
    cursor
        .query("SELECT 1")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int4(1), "結果が一致しません");

    pool.close().await.expect("プールの停止に失敗しました");
}

#[tokio::test]
async fn test_transaction_status() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    use shiguredo_postgres::constants::transaction_status;
    assert_eq!(
        conn.transaction_status(),
        transaction_status::IDLE,
        "初期状態はアイドル"
    );

    conn.query("BEGIN", false)
        .await
        .expect("BEGIN の実行に失敗しました");
    assert_eq!(
        conn.transaction_status(),
        transaction_status::IN_TRANSACTION,
        "トランザクション中"
    );

    conn.query("COMMIT", false)
        .await
        .expect("COMMIT の実行に失敗しました");
    assert_eq!(
        conn.transaction_status(),
        transaction_status::IDLE,
        "コミット後はアイドル"
    );
}

#[tokio::test]
async fn test_invalid_utf8_error() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // PostgreSQL はクライアントから受信した text パラメータのエンコーディングを
    // 検証しないため、サーバー側で convert_from に検証させる。
    let mut cursor = Cursor::new(&mut conn);
    let result = cursor
        .execute(
            "SELECT convert_from($1::bytea, 'UTF8')",
            &[Value::Bytes(vec![0xff, 0xfe, 0xfd])],
        )
        .await;
    assert!(
        matches!(result, Err(Error::DataError { ref code, .. }) if code == "22021"),
        "SQLSTATE 22021 が期待されるが {:?} が返った",
        result
    );

    // エラー後も正常にクエリを実行できる。
    cursor
        .query("SELECT 1")
        .await
        .expect("エラー後のクエリに失敗しました");
}

#[tokio::test]
async fn test_close_connection() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    conn.query("SELECT 1", false)
        .await
        .expect("SELECT の実行に失敗しました");
    conn.close().await.expect("接続のクローズに失敗しました");
    assert!(!conn.is_open(), "接続が閉じられていません");

    // クローズ後のクエリはエラーになる。
    let result = conn.query("SELECT 1", false).await;
    assert!(result.is_err(), "クローズ後のクエリはエラーになるはず");
}

#[tokio::test]
async fn test_connection_close_terminates_server_side() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let pid = conn.backend_process_id();
    assert!(pid > 0, "バックエンドプロセス ID が取得できません");

    conn.close().await.expect("接続のクローズに失敗しました");

    // サーバー側でバックエンドプロセスが終了していることを確認する。
    // 直接確認する手段がないため、別接続で pg_stat_activity を確認する。
    let mut check = helpers::connect(&options).await;
    let mut cursor = Cursor::new(&mut check);
    cursor
        .execute(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE pid = $1",
            &[Value::Int4(pid as i32)],
        )
        .await
        .expect("pg_stat_activity の参照に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Int8(0),
        "バックエンドプロセスが残っています"
    );
}

#[tokio::test]
async fn test_timestamptz_timezone() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .execute(
            "SELECT $1::timestamptz",
            &[Value::Timestamptz(
                Utc.with_ymd_and_hms(2024, 1, 15, 12, 34, 56)
                    .single()
                    .expect("有効な日時です"),
            )],
        )
        .await
        .expect("timestamptz の SELECT に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Timestamptz(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 34, 56)
                .single()
                .expect("有効な日時です")
        ),
        "timestamptz が一致しません"
    );

    // サーバーのタイムゾーンを変更しても同じ時刻になる。
    cursor
        .query("SET TIME ZONE 'Asia/Tokyo'")
        .await
        .expect("SET TIME ZONE の実行に失敗しました");
    cursor
        .execute(
            "SELECT $1::timestamptz",
            &[Value::Timestamptz(
                Utc.with_ymd_and_hms(2024, 1, 15, 12, 34, 56)
                    .single()
                    .expect("有効な日時です"),
            )],
        )
        .await
        .expect("timestamptz の SELECT に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Timestamptz(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 34, 56)
                .single()
                .expect("有効な日時です")
        ),
        "タイムゾーン変更後も timestamptz が一致しません"
    );
}
