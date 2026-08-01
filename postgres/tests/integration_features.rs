// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 追加機能 (プリペアドステートメント・バッチ・COPY・通知・トランザクション・
//! タイムアウト・拡張型・エラー詳細等) の統合テスト。
//!
//! コンテナ上で PostgreSQL を起動し、実際のサーバーに対して動作を確認する。

mod helpers;

use chrono::NaiveDate;
use shiguredo_postgres::batch::Batch;
use shiguredo_postgres::connection::Connection;
use shiguredo_postgres::cursor::Cursor;
use shiguredo_postgres::pool::PoolConfig;
use shiguredo_postgres::transaction::{IsolationLevel, TxOptions};
use shiguredo_postgres_core::constants::oid;
use shiguredo_postgres_core::converters::Value;
use std::time::Duration;

/// サーバー上のプリペアドステートメントの数を確認する。
async fn count_prepared_statements(conn: &mut Connection) -> i64 {
    let mut cursor = Cursor::new(conn);
    cursor
        .query("SELECT COUNT(*) FROM pg_prepared_statements")
        .await
        .expect("pg_prepared_statements の参照に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    match rows[0][0] {
        Value::Int8(count) => count,
        ref other => panic!("プリペアドステートメント数の型が想定外です: {:?}", other),
    }
}

#[tokio::test]
async fn test_explicit_prepared_statement() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let statement = conn
        .prepare("SELECT $1::int + $2::int")
        .await
        .expect("プリペアドステートメントの準備に失敗しました");
    assert_eq!(
        statement.parameter_oids,
        vec![oid::INT4, oid::INT4],
        "パラメータ型 OID が一致しません"
    );

    let affected = conn
        .execute_prepared(&statement, &[Value::Int4(10), Value::Int4(32)], false)
        .await
        .expect("プリペアドステートメントの実行に失敗しました");
    assert_eq!(affected, 1, "SELECT の影響行数が一致しません");

    let rows = conn.result().expect("結果がありません").rows.clone();
    assert_eq!(rows[0][0], Value::Int4(42), "計算結果が一致しません");

    // パラメータ数を間違えるとエラーになる。
    let result = conn
        .execute_prepared(&statement, &[Value::Int4(1)], false)
        .await;
    assert!(
        result.is_err(),
        "パラメータ数の不一致はエラーになるはずです"
    );

    // プリペアドステートメントは pg_prepared_statements に残る。
    assert!(
        count_prepared_statements(&mut conn).await >= 1,
        "プリペアドステートメントがサーバーに残っていません"
    );
}

#[tokio::test]
async fn test_statement_cache_reuse() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // 同じ SQL を繰り返し実行してもプリペアドステートメントは増えない。
    for _ in 0..5 {
        conn.execute("SELECT $1::int", &[Value::Int4(7)], false)
            .await
            .expect("クエリの実行に失敗しました");
    }
    assert_eq!(
        count_prepared_statements(&mut conn).await,
        1,
        "ステートメントキャッシュが機能していません"
    );

    // 異なる SQL は別のステートメントとして準備される。
    conn.execute("SELECT $1::text", &[Value::Text("a".to_string())], false)
        .await
        .expect("クエリの実行に失敗しました");
    assert_eq!(
        count_prepared_statements(&mut conn).await,
        2,
        "異なる SQL がキャッシュされていません"
    );
}

#[tokio::test]
async fn test_batch_execute() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    helpers::create_test_table(&mut conn).await;

    let mut batch = Batch::new();
    batch.append("SELECT $1::int + 1", &[Value::Int4(1)]);
    batch.append(
        "INSERT INTO test_items (name, quantity) VALUES ($1, $2)",
        &[Value::Text("apple".to_string()), Value::Int4(5)],
    );
    batch.append(
        "INSERT INTO test_items (name, quantity) VALUES ($1, $2)",
        &[Value::Text("banana".to_string()), Value::Int4(3)],
    );
    batch.append("SELECT 42", &[]);

    let results = conn
        .batch_execute(batch)
        .await
        .expect("バッチの実行に失敗しました");
    assert_eq!(results.len(), 4, "結果の数が一致しません");
    assert_eq!(*results[0].as_ref().expect("1 件目の結果"), 1);
    assert_eq!(*results[1].as_ref().expect("2 件目の結果"), 1);
    assert_eq!(*results[2].as_ref().expect("3 件目の結果"), 1);
    assert_eq!(*results[3].as_ref().expect("4 件目の結果"), 1);

    // バッチ後の接続は正常に使える。
    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("SELECT COUNT(*) FROM test_items")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int8(2), "件数が一致しません");
}

#[tokio::test]
async fn test_batch_error_midway() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    helpers::create_test_table(&mut conn).await;

    let mut batch = Batch::new();
    batch.append("SELECT 1", &[]);
    // 存在しないテーブルへの INSERT はエラーになる。
    batch.append("INSERT INTO no_such_table VALUES (1)", &[]);
    batch.append("SELECT 3", &[]);

    let results = conn
        .batch_execute(batch)
        .await
        .expect("バッチの実行に失敗しました");
    assert_eq!(results.len(), 3, "結果の数が一致しません");
    assert!(results[0].is_ok(), "1 件目は成功するはずです");
    assert!(
        matches!(&results[1], Err(e) if e.code() == Some("42P01")),
        "2 件目は SQLSTATE 42P01 が期待されるが {:?}",
        results[1]
    );
    assert!(
        results[2].is_err(),
        "3 件目はエラー後に実行されないためエラーになるはずです"
    );

    // エラー後も接続は正常に使える。
    conn.ping()
        .await
        .expect("バッチエラー後の ping に失敗しました");
}

#[tokio::test]
async fn test_multiple_result_sets() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // 単純クエリプロトコルで複数ステートメントを送ると複数の結果セットが返る。
    conn.query("SELECT 1 AS a; SELECT 2 AS b", false)
        .await
        .expect("複数ステートメントの実行に失敗しました");

    let result = conn.result().expect("結果がありません");
    assert_eq!(
        result.rows[0][0],
        Value::Int4(1),
        "1 つ目の結果セットが一致しません"
    );
    assert!(result.has_next_rowset(), "2 つ目の結果セットがありません");

    // 次の結果セットに切り替える。
    let mut result = result.clone();
    assert!(
        result.next_rowset(),
        "2 つ目の結果セットへの移動に失敗しました"
    );
    assert_eq!(
        result.rows[0][0],
        Value::Int4(2),
        "2 つ目の結果セットが一致しません"
    );
    assert!(!result.has_next_rowset(), "3 つ目の結果セットはありません");
}

#[tokio::test]
async fn test_copy_in_and_out() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    helpers::create_test_table(&mut conn).await;

    let affected = conn
        .copy_in(
            "COPY test_items (name, quantity) FROM STDIN",
            b"apple\t5\nbanana\t3\ncherry\t7\n",
        )
        .await
        .expect("CopyIn に失敗しました");
    assert_eq!(affected, 3, "CopyIn の影響行数が一致しません");

    // COPY で挿入したデータを通常のクエリで確認する。
    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("SELECT COUNT(*) FROM test_items")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(rows[0][0], Value::Int8(3), "件数が一致しません");

    // CopyOut でデータを取り出す。
    let data = conn
        .copy_out("COPY test_items (name, quantity) TO STDOUT")
        .await
        .expect("CopyOut に失敗しました");
    assert_eq!(
        data, b"apple\t5\nbanana\t3\ncherry\t7\n",
        "CopyOut のデータが一致しません"
    );
}

#[tokio::test]
async fn test_copy_in_chunked() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;
    helpers::create_test_table(&mut conn).await;

    conn.copy_in_begin("COPY test_items (name, quantity) FROM STDIN")
        .await
        .expect("CopyIn の開始に失敗しました");
    conn.send_copy_data(b"apple\t5\n")
        .await
        .expect("CopyData の送信に失敗しました");
    conn.send_copy_data(b"banana\t3\n")
        .await
        .expect("CopyData の送信に失敗しました");
    conn.send_copy_done()
        .await
        .expect("CopyDone の送信に失敗しました");
    let affected = conn
        .finish_copy_in()
        .await
        .expect("CopyIn の完了に失敗しました");
    assert_eq!(affected, 2, "CopyIn の影響行数が一致しません");
}

#[tokio::test]
async fn test_listen_notify() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut listener = helpers::connect(&options).await;
    let mut notifier = helpers::connect(&options).await;

    listener
        .query("LISTEN test_channel", false)
        .await
        .expect("LISTEN の実行に失敗しました");

    notifier
        .query("NOTIFY test_channel, 'hello payload'", false)
        .await
        .expect("NOTIFY の実行に失敗しました");

    let notification = tokio::time::timeout(Duration::from_secs(5), listener.next_notification())
        .await
        .expect("通知の受信がタイムアウトしました")
        .expect("通知の受信に失敗しました");
    assert_eq!(
        notification.channel, "test_channel",
        "チャネル名が一致しません"
    );
    assert_eq!(
        notification.payload, "hello payload",
        "ペイロードが一致しません"
    );
}

#[tokio::test]
async fn test_transaction_commit_and_rollback() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS tx_api_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE tx_api_test (v INTEGER)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");

    // ロールバックした変更は残らない。
    {
        let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
        tx.execute("INSERT INTO tx_api_test VALUES ($1)", &[Value::Int4(1)])
            .await
            .expect("INSERT の実行に失敗しました");
        tx.rollback().await.expect("ROLLBACK に失敗しました");
    }

    // コミットした変更は残る。
    {
        let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
        tx.execute("INSERT INTO tx_api_test VALUES ($1)", &[Value::Int4(2)])
            .await
            .expect("INSERT の実行に失敗しました");
        tx.commit().await.expect("COMMIT に失敗しました");
    }

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("SELECT COUNT(*) FROM tx_api_test")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Int8(1),
        "コミット・ロールバックが正しくありません"
    );
}

#[tokio::test]
async fn test_transaction_auto_rollback_on_drop() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS tx_drop_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE tx_drop_test (v INTEGER)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");

    // commit / rollback せずにトランザクションを破棄する。
    {
        let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
        tx.execute("INSERT INTO tx_drop_test VALUES ($1)", &[Value::Int4(1)])
            .await
            .expect("INSERT の実行に失敗しました");
        // drop で tx が破棄される。
    }

    // 次の begin() で自動的にロールバックされてから開始される。
    let mut tx = conn.begin().await.expect("破棄後の BEGIN に失敗しました");
    let rows = {
        let mut cursor = Cursor::new(tx.conn());
        cursor
            .query("SELECT COUNT(*) FROM tx_drop_test")
            .await
            .expect("SELECT の実行に失敗しました");
        cursor
            .fetch_all()
            .expect("結果取得に失敗しました")
            .iter()
            .map(|row| row.to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        rows[0][0],
        Value::Int8(0),
        "破棄されたトランザクションの変更が残っています"
    );
    tx.rollback().await.expect("ROLLBACK に失敗しました");
}

#[tokio::test]
async fn test_transaction_savepoint() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS tx_savepoint_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE tx_savepoint_test (v INTEGER)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");

    let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
    tx.execute(
        "INSERT INTO tx_savepoint_test VALUES ($1)",
        &[Value::Int4(1)],
    )
    .await
    .expect("INSERT の実行に失敗しました");

    // セーブポイント以降の変更をロールバックする。
    tx.savepoint("sp1").await.expect("SAVEPOINT に失敗しました");
    tx.execute(
        "INSERT INTO tx_savepoint_test VALUES ($1)",
        &[Value::Int4(2)],
    )
    .await
    .expect("INSERT の実行に失敗しました");
    tx.rollback_to_savepoint("sp1")
        .await
        .expect("ROLLBACK TO SAVEPOINT に失敗しました");

    // セーブポイント以降の変更を破棄する。
    tx.savepoint("sp2").await.expect("SAVEPOINT に失敗しました");
    tx.execute(
        "INSERT INTO tx_savepoint_test VALUES ($1)",
        &[Value::Int4(3)],
    )
    .await
    .expect("INSERT の実行に失敗しました");
    tx.release_savepoint("sp2")
        .await
        .expect("RELEASE SAVEPOINT に失敗しました");

    tx.commit().await.expect("COMMIT に失敗しました");

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("SELECT v FROM tx_savepoint_test ORDER BY v")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    let values: Vec<_> = rows.iter().map(|row| row[0].clone()).collect();
    assert_eq!(
        values,
        vec![Value::Int4(1), Value::Int4(3)],
        "セーブポイントのロールバックが正しくありません"
    );
}

#[tokio::test]
async fn test_transaction_options() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // 読み取り専用トランザクションでは書き込みができない。
    let mut tx = conn
        .begin_with(TxOptions {
            read_only: true,
            ..Default::default()
        })
        .await
        .expect("BEGIN に失敗しました");
    let result = tx
        .query("CREATE TABLE should_fail (v INTEGER)", false)
        .await;
    assert!(
        result.is_err(),
        "読み取り専用トランザクションでの書き込みは失敗するはずです"
    );
    // エラー後のトランザクションをロールバックして閉じる。
    tx.rollback().await.expect("ROLLBACK に失敗しました");

    // 分離レベル付きのトランザクションも開始できる。
    let tx = conn
        .begin_with(TxOptions {
            isolation_level: Some(IsolationLevel::Serializable),
            ..Default::default()
        })
        .await
        .expect("BEGIN に失敗しました");
    tx.rollback().await.expect("ROLLBACK に失敗しました");

    // トランザクション中の BEGIN はサーバーが NOTICE を送るだけで
    // エラーにはならない (ネストしたトランザクションは作成されない)。
    let mut tx = conn.begin().await.expect("BEGIN に失敗しました");
    let result = tx.query("BEGIN", false).await;
    assert!(
        result.is_ok(),
        "トランザクション中の BEGIN はエラーにならないはずです"
    );
    let notice = tx
        .conn()
        .pop_notice()
        .expect("トランザクション中の BEGIN で NOTICE が届くはずです");
    assert!(
        notice.message.contains("already a transaction in progress"),
        "NOTICE のメッセージが一致しません: {}",
        notice.message
    );
    tx.rollback().await.expect("ROLLBACK に失敗しました");
}

#[tokio::test]
async fn test_query_timeout_cancel() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    // 5 秒かかるクエリを 500ms でタイムアウトさせる。
    let started = std::time::Instant::now();
    let result = conn
        .query_with_timeout("SELECT pg_sleep(5)", false, Duration::from_millis(500))
        .await;
    assert!(result.is_err(), "タイムアウトはエラーになるはずです");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "タイムアウトが効いていません ({}ms)",
        started.elapsed().as_millis()
    );

    // キャンセル後も接続は正常に使える。
    conn.ping()
        .await
        .expect("キャンセル後の接続が正常ではありません");

    // 拡張クエリプロトコルでも同様にタイムアウトする。
    let result = conn
        .execute_with_timeout("SELECT pg_sleep(5)", &[], false, Duration::from_millis(500))
        .await;
    assert!(result.is_err(), "execute のタイムアウトが効いていません");
    conn.ping()
        .await
        .expect("execute キャンセル後の接続が正常ではありません");
}

#[tokio::test]
async fn test_ping() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    conn.ping().await.expect("ping に失敗しました");
}

#[tokio::test]
async fn test_extended_types() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS extended_type_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query(
            "CREATE TABLE extended_type_test (
                n NUMERIC,
                u UUID,
                j JSONB,
                ia INTEGER[]
            )",
        )
        .await
        .expect("CREATE TABLE の実行に失敗しました");

    let uuid = 0x123e4567e89b12d3a456426614174000_u128;
    cursor
        .execute(
            "INSERT INTO extended_type_test VALUES ($1, $2, $3, $4)",
            &[
                Value::Numeric("12345678901234567890.12345".to_string()),
                Value::Uuid(uuid),
                Value::Json("{\"key\": \"value\"}".to_string()),
                Value::Array {
                    element_type: oid::INT4,
                    values: vec![Value::Int4(1), Value::Null, Value::Int4(-3)],
                },
            ],
        )
        .await
        .expect("INSERT の実行に失敗しました");

    cursor
        .query("SELECT n, u, j, ia FROM extended_type_test")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    let row = &rows[0];
    assert_eq!(
        row[0],
        Value::Numeric("12345678901234567890.12345".to_string()),
        "NUMERIC が一致しません"
    );
    assert_eq!(row[1], Value::Uuid(uuid), "UUID が一致しません");
    assert_eq!(
        row[2],
        Value::Json("{\"key\": \"value\"}".to_string()),
        "JSONB が一致しません"
    );
    assert_eq!(
        row[3],
        Value::Array {
            element_type: oid::INT4,
            values: vec![Value::Int4(1), Value::Null, Value::Int4(-3)],
        },
        "配列が一致しません"
    );
}

#[tokio::test]
async fn test_numeric_array_and_date_array() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .execute(
            "SELECT ARRAY['1.5', '2.25']::numeric[], ARRAY['2024-01-15']::date[]",
            &[],
        )
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Array {
            element_type: oid::NUMERIC,
            values: vec![
                Value::Numeric("1.5".to_string()),
                Value::Numeric("2.25".to_string()),
            ],
        },
        "numeric 配列が一致しません"
    );
    let date = NaiveDate::from_ymd_opt(2024, 1, 15).expect("有効な日付です");
    assert_eq!(
        rows[0][1],
        Value::Array {
            element_type: oid::DATE,
            values: vec![Value::Date(date)],
        },
        "date 配列が一致しません"
    );
}

#[tokio::test]
async fn test_error_details() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TABLE IF EXISTS error_detail_test")
        .await
        .expect("DROP TABLE の実行に失敗しました");
    cursor
        .query("CREATE TABLE error_detail_test (v INTEGER UNIQUE)")
        .await
        .expect("CREATE TABLE の実行に失敗しました");
    cursor
        .execute(
            "INSERT INTO error_detail_test VALUES ($1)",
            &[Value::Int4(1)],
        )
        .await
        .expect("INSERT の実行に失敗しました");

    // 一意制約違反では制約名と詳細が取得できる。
    let result = cursor
        .execute(
            "INSERT INTO error_detail_test VALUES ($1)",
            &[Value::Int4(1)],
        )
        .await;
    match result {
        Err(e) => {
            assert_eq!(e.code(), Some("23505"), "SQLSTATE が一致しません");
            assert_eq!(
                e.constraint(),
                Some("error_detail_test_v_key"),
                "制約名が一致しません"
            );
            assert!(e.detail().is_some(), "エラー詳細が取得できません: {:?}", e);
            assert!(
                e.message().contains("duplicate key"),
                "メッセージが一致しません"
            );
        }
        Ok(_) => panic!("一意制約違反がエラーになりません"),
    }

    // 構文エラーでは位置が取得できる。
    let result = cursor.query("SELECT FROM").await;
    match result {
        Err(e) => {
            assert_eq!(e.code(), Some("42601"), "SQLSTATE が一致しません");
            assert!(
                e.position().is_some(),
                "エラー位置が取得できません: {:?}",
                e
            );
        }
        Ok(_) => panic!("構文エラーがエラーになりません"),
    }
}

#[tokio::test]
async fn test_notice_queue() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    conn.query("DO $$ BEGIN RAISE NOTICE 'hello notice'; END $$", false)
        .await
        .expect("RAISE NOTICE の実行に失敗しました");

    let notice = conn.pop_notice().expect("NOTICE が受信できません");
    assert_eq!(
        notice.message, "hello notice",
        "NOTICE のメッセージが一致しません"
    );
}

#[tokio::test]
async fn test_custom_converter() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("DROP TYPE IF EXISTS custom_mood CASCADE")
        .await
        .expect("DROP TYPE の実行に失敗しました");
    cursor
        .query("CREATE TYPE custom_mood AS ENUM ('happy', 'sad')")
        .await
        .expect("CREATE TYPE の実行に失敗しました");

    // enum 型の OID を取得する。
    cursor
        .execute(
            "SELECT oid FROM pg_type WHERE typname = $1",
            &[Value::Text("custom_mood".to_string())],
        )
        .await
        .expect("pg_type の参照に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    let Value::Oid(type_oid) = rows[0][0] else {
        panic!("型 OID が取得できません: {:?}", rows[0][0]);
    };

    // 独自デコーダを登録する。値の先頭に接頭辞を付ける。
    conn.register_converter(type_oid, |s| Value::Text(format!("mood:{}", s)));

    let mut cursor = Cursor::new(&mut conn);
    cursor
        .query("SELECT 'happy'::custom_mood")
        .await
        .expect("SELECT の実行に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    assert_eq!(
        rows[0][0],
        Value::Text("mood:happy".to_string()),
        "独自デコーダが適用されていません"
    );
}

#[tokio::test]
async fn test_statement_invalidation_on_ddl() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let mut conn = helpers::connect(&options).await;

    {
        let mut cursor = Cursor::new(&mut conn);
        cursor
            .query("DROP TABLE IF EXISTS inval_test")
            .await
            .expect("DROP TABLE の実行に失敗しました");
        cursor
            .query("CREATE TABLE inval_test (v INTEGER)")
            .await
            .expect("CREATE TABLE の実行に失敗しました");
    }

    // ステートメントキャッシュに SELECT を登録する。
    conn.execute("SELECT v FROM inval_test", &[], false)
        .await
        .expect("SELECT の実行に失敗しました");

    // DDL で列の型を変更するとキャッシュされたプランが無効になる
    // (0A000: cached plan must not change result type)。
    conn.query("ALTER TABLE inval_test ALTER COLUMN v TYPE BIGINT", false)
        .await
        .expect("ALTER TABLE の実行に失敗しました");

    // 自動再準備されて再実行できる。
    conn.execute("SELECT v FROM inval_test", &[], false)
        .await
        .expect("DDL 後の SELECT の自動再準備に失敗しました");
}

#[tokio::test]
async fn test_pool_min_idle_replenish() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;

    let config = PoolConfig {
        max_size: 4,
        min_idle: 2,
        acquire_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    // プール起動時に min_idle 分の接続が確立されている。
    let mut check = helpers::connect(&options).await;
    assert!(
        count_backends(&mut check).await >= 2,
        "min_idle 分の接続が確立されていません"
    );

    // 接続を取得して破棄すると、アイドル接続が減る。
    {
        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        pooled.discard();
        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        pooled.discard();
    }

    // 破棄後の返却 (次回 acquire) で min_idle まで補充される。
    // マネージャタスクの処理を待つためリトライする。
    let mut check = helpers::connect(&options).await;
    let mut connected = false;
    for _ in 0..10 {
        let backends = count_backends(&mut check).await;
        if backends >= 2 {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(connected, "min_idle まで補充されていません");

    pool.close().await.expect("プールの停止に失敗しました");
}

/// サーバー上のバックエンド数を確認する。
///
/// 自分自身のバックエンドは除く。
async fn count_backends(conn: &mut Connection) -> i64 {
    let mut cursor = Cursor::new(conn);
    cursor
        .query("SELECT COUNT(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid()")
        .await
        .expect("pg_stat_activity の参照に失敗しました");
    let rows = cursor.fetch_all().expect("結果取得に失敗しました");
    match rows[0][0] {
        Value::Int8(count) => count,
        ref other => panic!("バックエンド数の型が想定外です: {:?}", other),
    }
}
