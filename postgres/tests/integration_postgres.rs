// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! shiguredo_container を使った PostgreSQL 接続統合テスト。
//!
//! コンテナ上で PostgreSQL コンテナを起動し、tokio_postgres クレートから
//! 実際に接続・クエリ実行・結果取得ができることを確認する。
//! デフォルト設定では scram-sha-256 認証になるため、
//! SCRAM 認証フローも併せて検証される。

#[path = "helpers/helpers.rs"]
mod helpers;

use shiguredo_postgres::constants::oid;
use shiguredo_postgres::converters::{IpNetwork, Value};
use shiguredo_postgres::cursor::{Cursor, DictCursor};
use shiguredo_postgres::datetime::{Date, FiniteInterval, Interval, Time, Timestamp, Timestamptz};
use shiguredo_postgres::error::Error;
use shiguredo_postgres::pool::PoolConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// テスト対象のイメージが要求したバージョンで起動していることを確認する。
///
/// CI の matrix で指定したバージョンと実際に起動したサーバーの
/// バージョンがずれていないことを検証する。
#[tokio::test]
async fn test_server_version_matches_requested() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let conn = helpers::connect(&options).await;

    let actual = conn
        .server_version()
        .expect("サーバーバージョンが取得できません")
        .to_string();
    let expected = helpers::postgres_version();
    assert!(
        actual.starts_with(&expected),
        "サーバーバージョンが一致しません: expected={} actual={}",
        expected,
        actual
    );
}

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
        matches!(&result, Err(Error::IntegrityError(info)) if info.code == "23502"),
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

    let date = Date::from_ymd(2024, 1, 15).expect("有効な日付です");
    let time = Time::from_hms_micro(12, 34, 56, 123_456).expect("有効な時刻です");
    let timestamp =
        Timestamp::from_ymd_hms_micro(2024, 1, 15, 12, 34, 56, 123_456).expect("有効な日時です");
    let timestamptz = Timestamptz::from_utc_ymd_hms_micro(2024, 1, 15, 12, 34, 56, 123_456)
        .expect("有効な日時です");

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

/// PostgreSQL 19 で追加された oid8 をサーバーとの往復で u64 として扱えることを確認する。
///
/// 19 より前のサーバーには oid8 型がないため、型がないことだけを確かめる。
#[tokio::test]
async fn test_oid8_conversion() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let row = conn
        .query_one(
            "SELECT current_setting('server_version_num')::int, to_regtype('oid8') IS NOT NULL",
            &[],
        )
        .await
        .expect("サーバーの版と型の有無を取得できません");
    let version_num = row.get::<i32>(0).expect("版の番号を取得できません");
    let has_oid8 = row.get::<bool>(1).expect("型の有無を取得できません");
    assert_eq!(
        has_oid8,
        version_num >= 190000,
        "oid8 型の有無がサーバーの版と一致しません: {version_num}"
    );
    if !has_oid8 {
        return;
    }

    // 最大値は i64 に収まらず、符号なしの 10 進数で往復する。
    let array = Value::Array {
        element_type: oid::OID8,
        values: vec![Value::Oid8(0), Value::Null, Value::Oid8(u64::MAX)],
    };
    let row = conn
        .query_one(
            "SELECT $1::oid8, $2::oid8[]",
            &[Value::Oid8(u64::MAX), array.clone()],
        )
        .await
        .expect("oid8 の往復に失敗しました");
    assert_eq!(
        row.value(0),
        Some(&Value::Oid8(u64::MAX)),
        "oid8 が一致しません"
    );
    assert_eq!(
        row.get::<u64>(0).expect("oid8 を u64 として取得できません"),
        u64::MAX,
        "u64 として取得した oid8 が一致しません"
    );
    assert_eq!(row.value(1), Some(&array), "oid8 の配列が一致しません");
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
async fn test_transaction_commit_reports_server_rollback() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    conn.query("CREATE TEMP TABLE tx_commit_test (v integer)", false)
        .await
        .expect("一時テーブルの作成に失敗しました");

    let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
    tx.query("INSERT INTO tx_commit_test VALUES (1)", false)
        .await
        .expect("INSERT の実行に失敗しました");
    let error = tx
        .query("SELECT 1 / 0", false)
        .await
        .expect_err("ゼロ除算はトランザクションを失敗させるはずです");
    assert_eq!(error.code(), Some("22012"), "SQLSTATE が一致しません");

    // 失敗済みのトランザクションに対する COMMIT は ErrorResponse ではなく、
    // ROLLBACK タグを返す。クエリが完了してもコミット成功ではない。
    tx.commit()
        .await
        .expect_err("サーバーのロールバックをコミット成功として返しました");
    assert_eq!(
        conn.result().and_then(|result| result.tag.as_deref()),
        Some("ROLLBACK"),
        "サーバーは ROLLBACK タグを返すはずです"
    );

    // 終了済みの接続を再利用でき、失敗したトランザクションの変更は残らない。
    let mut tx = conn.begin().await.expect("エラー後の BEGIN に失敗しました");
    let rows = tx
        .query("SELECT v FROM tx_commit_test", false)
        .await
        .expect("ロールバック後の SELECT に失敗しました");
    assert_eq!(rows, 0, "ロールバック済みの変更が残っています");
    tx.rollback().await.expect("ROLLBACK に失敗しました");
}

#[tokio::test]
async fn test_cancelled_commit_is_not_reusable() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    let mut blocker = helpers::connect(&options).await;

    // 遅延制約トリガーを使い、INSERT ではなく COMMIT の時点で別接続の
    // アドバイザリロックを待たせる。固定時間の待機に成功判定を依存させない。
    blocker
        .query("SELECT pg_advisory_lock(1)", false)
        .await
        .expect("アドバイザリロックの取得に失敗しました");
    conn.query(
        "CREATE TEMP TABLE tx_wait_test (v integer);
         CREATE FUNCTION pg_temp.tx_wait_on_commit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             PERFORM pg_advisory_xact_lock(1);
             RETURN NULL;
         END;
         $$;
         CREATE CONSTRAINT TRIGGER tx_wait_on_commit
         AFTER INSERT ON tx_wait_test DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW EXECUTE FUNCTION pg_temp.tx_wait_on_commit()",
        false,
    )
    .await
    .expect("遅延制約トリガーの作成に失敗しました");

    let pid = i32::try_from(conn.backend_process_id()).expect("バックエンド PID が範囲外です");
    let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
    tx.query("INSERT INTO tx_wait_test VALUES (1)", false)
        .await
        .expect("INSERT の時点ではトリガーが実行されないはずです");

    let wait_for_blocked_commit = async {
        loop {
            blocker
                .execute(
                    "SELECT cardinality(pg_blocking_pids($1)) > 0",
                    &[Value::Int4(pid)],
                    false,
                )
                .await
                .expect("COMMIT のロック待ちを確認できませんでした");
            let result = blocker.result().expect("ロック待ちの結果がありません");
            if result.rows[0][0] == Value::Bool(true) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    // サーバーが COMMIT を受け取ったことを確認してから Future を破棄する。
    tokio::select! {
        result = tx.commit() => panic!("ロック中に COMMIT が完了しました: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(10), wait_for_blocked_commit) => {
            result.expect("COMMIT が時間内にロック待ちになりませんでした");
        }
    }
    assert!(
        !conn.is_open() || conn.is_busy(),
        "中断した COMMIT の応答を待たずに接続が再利用可能になりました"
    );
    // テスト終了時にロックを解放する前に、未同期の接続を破棄する。
    conn.force_close();
}

#[tokio::test]
async fn test_transaction_rollback_failure_preserves_dirty_state() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    conn.query("CREATE TEMP TABLE tx_copy_test (v integer)", false)
        .await
        .expect("一時テーブルの作成に失敗しました");

    let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
    tx.conn()
        .copy_in_begin("COPY tx_copy_test FROM STDIN")
        .await
        .expect("COPY の開始に失敗しました");
    tx.conn()
        .send_copy_data(b"1\n")
        .await
        .expect("COPY のデータ送信に失敗しました");

    // COPY の途中では ROLLBACK クエリが送れない。失敗して所有権を
    // 手放したあとも、未ロールバックのトランザクションを記録しておく。
    tx.rollback()
        .await
        .expect_err("COPY の途中で ROLLBACK が成功しました");
    conn.send_copy_done()
        .await
        .expect("CopyDone の送信に失敗しました");
    let inserted = conn
        .finish_copy_in()
        .await
        .expect("COPY 結果の取得に失敗しました");
    assert_eq!(inserted, 1, "COPY で挿入した件数が一致しません");

    // COPY を終えても元のトランザクションは開いたままなので、次の
    // begin がこれをロールバックしてから新しいトランザクションを始める。
    let mut tx = conn.begin().await.expect("失敗後の BEGIN に失敗しました");
    let rows = tx
        .query("SELECT v FROM tx_copy_test", false)
        .await
        .expect("ロールバック後の SELECT に失敗しました");
    assert_eq!(rows, 0, "破棄されたトランザクションの変更が残っています");
    tx.rollback().await.expect("ROLLBACK に失敗しました");
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
        matches!(&result, Err(Error::ProgrammingError(info)) if info.code == "42P01"),
        "SQLSTATE 42P01 が期待されるが {:?} が返った",
        result
    );

    // 構文エラー。
    let result = cursor.query("SELECT FROM").await;
    assert!(
        matches!(&result, Err(Error::ProgrammingError(info)) if info.code == "42601"),
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
        matches!(&result, Err(Error::IntegrityError(info)) if info.code == "23505"),
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
        matches!(&result, Err(Error::DataError(info)) if info.code == "22021"),
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
                Timestamptz::from_utc_ymd_hms_micro(2024, 1, 15, 12, 34, 56, 0)
                    .expect("有効な日時です"),
            )],
        )
        .await
        .expect("timestamptz の SELECT に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Timestamptz(
            Timestamptz::from_utc_ymd_hms_micro(2024, 1, 15, 12, 34, 56, 0)
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
                Timestamptz::from_utc_ymd_hms_micro(2024, 1, 15, 12, 34, 56, 0)
                    .expect("有効な日時です"),
            )],
        )
        .await
        .expect("timestamptz の SELECT に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Timestamptz(
            Timestamptz::from_utc_ymd_hms_micro(2024, 1, 15, 12, 34, 56, 0)
                .expect("有効な日時です")
        ),
        "タイムゾーン変更後も timestamptz が一致しません"
    );
}

/// 配列を `Value::Array` で返す組み込み型の OID 定数がサーバーのカタログと一致し、
/// テキストとして扱う型の配列を要素がテキストの配列として取り出せることを確認する。
#[tokio::test]
async fn test_text_type_arrays() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // (型名, 要素型 OID, 配列型 OID)。サーバーの pg_type と突き合わせて定数の誤りを検出する。
    let expected = [
        ("interval", oid::INTERVAL, oid::array::INTERVAL),
        ("timetz", oid::TIMETZ, oid::array::TIMETZ),
        ("inet", oid::INET, oid::array::INET),
        ("cidr", oid::CIDR, oid::array::CIDR),
        ("macaddr", oid::MACADDR, oid::array::MACADDR),
        ("macaddr8", oid::MACADDR8, oid::array::MACADDR8),
        ("money", oid::MONEY, oid::array::MONEY),
        ("bit", oid::BIT, oid::array::BIT),
        ("varbit", oid::VARBIT, oid::array::VARBIT),
        ("xml", oid::XML, oid::array::XML),
        ("point", oid::POINT, oid::array::POINT),
        ("line", oid::LINE, oid::array::LINE),
        ("lseg", oid::LSEG, oid::array::LSEG),
        ("path", oid::PATH, oid::array::PATH),
        ("polygon", oid::POLYGON, oid::array::POLYGON),
        ("circle", oid::CIRCLE, oid::array::CIRCLE),
        ("tsvector", oid::TSVECTOR, oid::array::TSVECTOR),
        ("tsquery", oid::TSQUERY, oid::array::TSQUERY),
        ("jsonpath", oid::JSONPATH, oid::array::JSONPATH),
        ("pg_lsn", oid::PG_LSN, oid::array::PG_LSN),
        ("xid8", oid::XID8, oid::array::XID8),
        ("int4range", oid::INT4RANGE, oid::array::INT4RANGE),
        ("int8range", oid::INT8RANGE, oid::array::INT8RANGE),
        ("numrange", oid::NUMRANGE, oid::array::NUMRANGE),
        ("tsrange", oid::TSRANGE, oid::array::TSRANGE),
        ("tstzrange", oid::TSTZRANGE, oid::array::TSTZRANGE),
        ("daterange", oid::DATERANGE, oid::array::DATERANGE),
        (
            "int4multirange",
            oid::INT4MULTIRANGE,
            oid::array::INT4MULTIRANGE,
        ),
        (
            "int8multirange",
            oid::INT8MULTIRANGE,
            oid::array::INT8MULTIRANGE,
        ),
        (
            "nummultirange",
            oid::NUMMULTIRANGE,
            oid::array::NUMMULTIRANGE,
        ),
        ("tsmultirange", oid::TSMULTIRANGE, oid::array::TSMULTIRANGE),
        (
            "tstzmultirange",
            oid::TSTZMULTIRANGE,
            oid::array::TSTZMULTIRANGE,
        ),
        (
            "datemultirange",
            oid::DATEMULTIRANGE,
            oid::array::DATEMULTIRANGE,
        ),
    ];
    let names = Value::Array {
        element_type: oid::TEXT,
        values: expected
            .iter()
            .map(|(name, _, _)| Value::Text((*name).to_string()))
            .collect(),
    };
    let rows = conn
        .query_all(
            "SELECT typname::text, oid::int8, typarray::int8, typdelim::text FROM pg_type \
             WHERE typname = ANY($1::text[]) AND typnamespace = 'pg_catalog'::regnamespace",
            &[names],
        )
        .await
        .expect("pg_type の取得に失敗しました");
    assert_eq!(rows.len(), expected.len(), "カタログにない型があります");
    for row in &rows {
        let name = row.get::<String>(0).expect("型名を取得できません");
        let (_, element, array) = expected
            .iter()
            .find(|(expected_name, _, _)| *expected_name == name)
            .expect("問い合わせていない型が返りました");
        assert_eq!(
            row.get::<i64>(1).expect("型の OID を取得できません"),
            i64::from(*element),
            "{name} の OID が定数と一致しません"
        );
        assert_eq!(
            row.get::<i64>(2).expect("配列型の OID を取得できません"),
            i64::from(*array),
            "{name} の配列型の OID が定数と一致しません"
        );
        // 配列の解析は区切り文字が `,` の型だけを扱う。
        assert_eq!(
            row.get::<String>(3).expect("区切り文字を取得できません"),
            ",",
            "{name} の配列の区切り文字が `,` ではありません"
        );
    }

    // 代表的な型の配列を、NULL を含めて要素がテキストの配列として取り出す。
    let row = conn
        .query_one(
            "SELECT ARRAY['04:05:06+09', NULL]::timetz[], ARRAY['16/B374D848']::pg_lsn[], \
             ARRAY['[1,3)']::int4range[], ARRAY[point(1, 2)]",
            &[],
        )
        .await
        .expect("配列の取得に失敗しました");
    for (index, element, values) in [
        (0, oid::TIMETZ, vec![Some("04:05:06+09"), None]),
        (1, oid::PG_LSN, vec![Some("16/B374D848")]),
        (2, oid::INT4RANGE, vec![Some("[1,3)")]),
        (3, oid::POINT, vec![Some("(1,2)")]),
    ] {
        assert!(
            matches!(
                row.value(index),
                Some(Value::Array { element_type, .. }) if *element_type == element
            ),
            "列 {index} が要素型 {element} の配列になりません: {:?}",
            row.value(index)
        );
        let expected: Vec<Option<String>> = values
            .into_iter()
            .map(|value| value.map(str::to_string))
            .collect();
        assert_eq!(
            row.get::<Vec<Option<String>>>(index)
                .expect("配列を取得できません"),
            expected,
            "列 {index} の要素が一致しません"
        );
    }
}

/// interval、inet / cidr、macaddr / macaddr8 を型付きの値として読み書きできることを確認する。
#[tokio::test]
async fn test_interval_network_and_mac_conversion() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    let finite = |months, days, microseconds| {
        Interval::Finite(
            FiniteInterval::new(months, days, microseconds).expect("有限の値を作れません"),
        )
    };
    let network = |address: &str, prefix_len| IpNetwork {
        address: address.parse().expect("アドレスを解析できません"),
        prefix_len,
    };

    // サーバーの出力 (IntervalStyle=postgres) を型付きの値として読む。
    let row = conn
        .query_one(
            "SELECT '1 year 2 mons 3 days 04:05:06.789'::interval, '-1 days +02:03:00'::interval, \
             '192.168.0.1'::inet, '2001:db8::1/64'::inet, '10.0.0.0/8'::cidr, \
             '08:00:2b:01:02:03'::macaddr, '08:00:2b:01:02:03:04:05'::macaddr8, \
             ARRAY['1 day', NULL]::interval[], ARRAY['10.0.0.1', '::1/128']::inet[]",
            &[],
        )
        .await
        .expect("値の取得に失敗しました");
    assert_eq!(
        row.get::<Interval>(0).expect("interval を取得できません"),
        finite(14, 3, 14_706_789_000)
    );
    assert_eq!(
        row.get::<Interval>(1).expect("interval を取得できません"),
        finite(0, -1, 7_380_000_000)
    );
    assert_eq!(
        row.get::<IpAddr>(2)
            .expect("ホストアドレスを取得できません"),
        "192.168.0.1"
            .parse::<IpAddr>()
            .expect("アドレスを解析できません")
    );
    assert_eq!(
        row.get::<IpNetwork>(3).expect("inet を取得できません"),
        network("2001:db8::1", 64)
    );
    assert_eq!(
        row.get::<IpNetwork>(4).expect("cidr を取得できません"),
        network("10.0.0.0", 8)
    );
    assert_eq!(
        row.get::<[u8; 6]>(5).expect("macaddr を取得できません"),
        [0x08, 0x00, 0x2b, 0x01, 0x02, 0x03]
    );
    assert_eq!(
        row.get::<[u8; 8]>(6).expect("macaddr8 を取得できません"),
        [0x08, 0x00, 0x2b, 0x01, 0x02, 0x03, 0x04, 0x05]
    );
    assert_eq!(
        row.get::<Vec<Option<Interval>>>(7)
            .expect("interval[] を取得できません"),
        vec![Some(finite(0, 1, 0)), None]
    );
    assert_eq!(
        row.get::<Vec<IpNetwork>>(8)
            .expect("inet[] を取得できません"),
        vec![network("10.0.0.1", 32), network("::1", 128)]
    );

    // パラメーターとして送った値を、サーバーが同じ値として解釈して返す。
    let values = [
        Value::Interval(finite(-14, -3, -1)),
        Value::Interval(finite(1_234_567, -98_765, -123_456_789_012_345)),
        Value::Inet(network("2001:db8::abcd", 48)),
        Value::Cidr(network("192.168.0.0", 16)),
        Value::MacAddr([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]),
        Value::MacAddr8([1, 2, 3, 4, 5, 6, 7, 8]),
    ];
    let row = conn
        .query_one(
            "SELECT $1::interval, $2::interval, $3::inet, $4::cidr, $5::macaddr, $6::macaddr8",
            &values,
        )
        .await
        .expect("パラメーターの往復に失敗しました");
    assert_eq!(row.into_values(), values.to_vec(), "往復で値が変わりました");

    // ほかの IntervalStyle の出力は型付きの値にせず、テキストのまま返す。
    conn.query("SET IntervalStyle = 'iso_8601'", false)
        .await
        .expect("IntervalStyle を変更できません");
    let row = conn
        .query_one("SELECT '1 day'::interval", &[])
        .await
        .expect("interval の取得に失敗しました");
    assert_eq!(row.value(0), Some(&Value::Text("P1D".to_string())));

    // sql_standard では符号のないフィールドに先頭の符号が及ぶが、postgres 形式の値は
    // 負のフィールドの後ろに符号を明示するため、同じ値として入力される。
    conn.query(
        "SET IntervalStyle = 'sql_standard'; CREATE TEMPORARY TABLE intervals (v interval)",
        false,
    )
    .await
    .expect("sql_standard の準備に失敗しました");
    let mixed = [
        finite(0, -1, 7_380_000_000),
        finite(-14, 3, -1),
        finite(-12, 0, 1),
    ];
    for interval in mixed {
        conn.execute(
            "INSERT INTO intervals VALUES ($1)",
            &[Value::Interval(interval)],
            false,
        )
        .await
        .expect("sql_standard で interval を挿入できません");
    }
    conn.query("RESET IntervalStyle", false)
        .await
        .expect("IntervalStyle を戻せません");
    let stored: Vec<Interval> = conn
        .query_all("SELECT v FROM intervals ORDER BY ctid", &[])
        .await
        .expect("挿入した interval を取得できません")
        .iter()
        .map(|row| row.get::<Interval>(0).expect("interval を取得できません"))
        .collect();
    assert_eq!(stored, mixed.to_vec(), "sql_standard で値が変わりました");

    // 無限大の interval は PostgreSQL 17 以降で使える。
    let version_num = conn
        .query_one("SELECT current_setting('server_version_num')::int", &[])
        .await
        .expect("サーバーの版を取得できません")
        .get::<i32>(0)
        .expect("版の番号を取得できません");
    if version_num >= 170000 {
        let row = conn
            .query_one(
                "SELECT 'infinity'::interval, $1::interval",
                &[Value::Interval(Interval::NegInfinity)],
            )
            .await
            .expect("無限大の interval の取得に失敗しました");
        assert_eq!(
            row.get::<Interval>(0).expect("infinity を取得できません"),
            Interval::Infinity
        );
        assert_eq!(
            row.get::<Interval>(1).expect("-infinity を取得できません"),
            Interval::NegInfinity
        );
    }
}
