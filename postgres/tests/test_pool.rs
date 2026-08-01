// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! pool モジュールの統合テスト。
//!
//! コンテナ上の PostgreSQL に対して、接続の破棄・クローズ・寿命・
//! トランザクションの後始末・タイムアウトを検証する。

// このテストバイナリでは一部のヘルパーだけを使うため、
// 残りのヘルパーが未使用になることを想定する。
#[expect(dead_code)]
#[path = "helpers/helpers.rs"]
mod helpers;

use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::constants::transaction_status;
use shiguredo_postgres::converters::Value;
use shiguredo_postgres::cursor::Cursor;
use shiguredo_postgres::pool::PoolConfig;
use std::time::Duration;

/// 破棄した接続の枠が解放されることを確認する。
#[tokio::test]
async fn test_discard_releases_capacity() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    pooled.discard();

    // 破棄後も同じ枠で取得できること。
    let mut pooled = pool
        .acquire()
        .await
        .expect("破棄後の接続の取得に失敗しました");
    {
        let mut cursor = Cursor::new(pooled.connection_mut());
        cursor
            .query("SELECT 1")
            .await
            .expect("SELECT の実行に失敗しました");
        let rows = cursor.fetch_all().expect("結果取得に失敗しました");
        assert_eq!(rows[0][0], Value::Int4(1), "結果が一致しません");
    }
    drop(pooled);
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.discarded.explicit, 1,
        "明示的な破棄の集計が一致しません"
    );
    assert_eq!(stat.closed_total, 1, "破棄された接続が重複計上されました");
    pool.close().await.expect("プールの停止に失敗しました");
}

/// 利用者が接続を閉じた場合も枠が解放されることを確認する。
#[tokio::test]
async fn test_closed_connection_releases_capacity() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    pooled
        .connection_mut()
        .close()
        .await
        .expect("接続のクローズに失敗しました");
    drop(pooled);

    // 閉じた接続は再利用されず、新しい接続が取得できること。
    let pooled = pool
        .acquire()
        .await
        .expect("クローズ後の接続の取得に失敗しました");
    assert!(pooled.connection().is_open(), "接続が開いていません");
    drop(pooled);
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.discarded.already_closed, 1,
        "閉じていた接続の集計が一致しません"
    );
    assert_eq!(stat.closed_total, 1, "破棄された接続が重複計上されました");
    pool.close().await.expect("プールの停止に失敗しました");
}

/// 取得待ちがタイムアウトし、その後に枠が回復することを確認する。
#[tokio::test]
async fn test_acquire_timeout() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let held = pool.acquire().await.expect("接続の取得に失敗しました");
    let result = pool.acquire_with_timeout(Duration::from_millis(500)).await;
    assert!(result.is_err(), "取得がタイムアウトしませんでした");

    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.acquire_timeout_total, 1,
        "取得タイムアウト数が一致しません"
    );
    assert!(
        stat.acquire_duration_total > Duration::ZERO,
        "取得時間の合計が記録されていません"
    );
    assert_eq!(stat.waiting, 0, "タイムアウト済みの取得試行が残っています");
    assert_eq!(stat.capacity_wait_total, 1, "枠待ちの回数が一致しません");
    assert!(
        stat.capacity_wait_duration_total > Duration::ZERO,
        "タイムアウトした試行の枠待ち時間が記録されていません"
    );

    drop(held);

    // タイムアウトした要求が枠を占有したままにならないこと。
    let pooled = pool
        .acquire()
        .await
        .expect("タイムアウト後の接続の取得に失敗しました");
    drop(pooled);

    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert!(
        stat.acquired_total >= 2,
        "貸出数の合計が統計に反映されていません"
    );
    assert!(
        stat.created_total >= 1,
        "確立した接続数が統計に反映されていません"
    );
    pool.close().await.expect("プールの停止に失敗しました");
}

/// 最大生存時間を超えた接続が再利用されないことを確認する。
#[tokio::test]
async fn test_max_lifetime_replaces_connection() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        max_lifetime: Duration::from_millis(300),
        max_idle_time: Duration::from_secs(60),
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let started = tokio::time::Instant::now();
    let mut first_pid = None;
    let mut replaced = false;
    while started.elapsed() < Duration::from_secs(3) {
        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        let pid = pooled.connection().backend_process_id();
        match first_pid {
            None => first_pid = Some(pid),
            Some(first) if pid != first => {
                replaced = true;
                break;
            }
            _ => {}
        }
        drop(pooled);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(replaced, "最大生存時間を超えた接続が再利用されました");
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.discarded.lifetime_expired, 1,
        "寿命切れで破棄した接続の集計が一致しません"
    );
    pool.close().await.expect("プールの停止に失敗しました");
}

/// トランザクションが残った接続がロールバックされてから再利用されることを確認する。
#[tokio::test]
async fn test_open_transaction_is_rolled_back_on_release() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    let backend_pid = pooled.connection().backend_process_id();
    {
        let mut cursor = Cursor::new(pooled.connection_mut());
        cursor
            .query("BEGIN")
            .await
            .expect("BEGIN の実行に失敗しました");
    }
    drop(pooled);

    let pooled = pool
        .acquire()
        .await
        .expect("ロールバック後の接続の取得に失敗しました");
    assert_eq!(
        pooled.connection().transaction_status(),
        transaction_status::IDLE,
        "トランザクションが残ったまま接続が再利用されました"
    );
    assert_eq!(
        pooled.connection().backend_process_id(),
        backend_pid,
        "ロールバック後に同じ接続が再利用されませんでした"
    );
    drop(pooled);
    pool.close().await.expect("プールの停止に失敗しました");
}

/// プールを閉じた後に接続を取得できないことを確認する。
#[tokio::test]
async fn test_acquire_after_close_fails() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    pool.close().await.expect("プールの停止に失敗しました");
    let result = pool.acquire().await;
    assert!(result.is_err(), "閉じたプールから接続を取得できました");
}

/// 途中まで読み取ったアンバッファードクエリの接続が再利用されないことを確認する。
#[tokio::test]
async fn test_unbuffered_query_is_not_reused() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    pooled
        .connection_mut()
        .query("SELECT 1", true)
        .await
        .expect("アンバッファードクエリの実行に失敗しました");
    // 結果を読み切らずに返却する。
    drop(pooled);

    // 途中状態の接続は破棄され、新しい接続でクエリを実行できること。
    let mut pooled = pool.acquire().await.expect("再接続の取得に失敗しました");
    {
        let mut cursor = Cursor::new(pooled.connection_mut());
        cursor
            .query("SELECT 2")
            .await
            .expect("SELECT の実行に失敗しました");
        let rows = cursor.fetch_all().expect("結果取得に失敗しました");
        assert_eq!(rows[0][0], Value::Int4(2), "結果が一致しません");
    }
    drop(pooled);
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.discarded.unsynchronized, 1,
        "プロトコルの同期を確認できない接続の集計が一致しません"
    );
    assert_eq!(stat.closed_total, 1, "破棄された接続が重複計上されました");
    pool.close().await.expect("プールの停止に失敗しました");
}

/// プリペアに失敗した接続が破棄されず、再利用されることを確認する。
#[tokio::test]
async fn test_failed_prepare_keeps_connection_reusable() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    let pid = pooled.connection().backend_process_id();
    let result = pooled.connection_mut().prepare("SELECT FROM").await;
    assert!(result.is_err(), "不正な SQL の prepare が成功しました");
    assert!(
        !pooled.connection().is_busy(),
        "prepare 失敗後に接続が busy と判定されました"
    );
    drop(pooled);

    // 同じ接続が再利用されること。
    let mut pooled = pool
        .acquire()
        .await
        .expect("prepare 失敗後の接続の取得に失敗しました");
    assert_eq!(
        pooled.connection().backend_process_id(),
        pid,
        "prepare 失敗後に接続が張り直されました"
    );
    {
        let mut cursor = Cursor::new(pooled.connection_mut());
        cursor
            .query("SELECT 1")
            .await
            .expect("SELECT の実行に失敗しました");
        let rows = cursor.fetch_all().expect("結果取得に失敗しました");
        assert_eq!(rows[0][0], Value::Int4(1), "結果が一致しません");
    }
    drop(pooled);
    pool.close().await.expect("プールの停止に失敗しました");
}

/// 空きがない場合に try_acquire が None を返すことを確認する。
#[tokio::test]
async fn test_try_acquire_returns_none_when_full() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    assert!(
        pool.try_acquire()
            .await
            .expect("即時取得に失敗しました")
            .is_none(),
        "接続がないのに即時取得できました"
    );

    let lease = pool.acquire().await.expect("接続の取得に失敗しました");
    assert!(
        pool.try_acquire()
            .await
            .expect("即時取得に失敗しました")
            .is_none(),
        "貸出中の接続があるのに即時取得できました"
    );
    drop(lease);

    let lease = pool
        .try_acquire()
        .await
        .expect("即時取得に失敗しました")
        .expect("空きがあるのに即時取得できませんでした");
    drop(lease);
    pool.close().await.expect("プールの停止に失敗しました");
}

/// close_with_timeout が貸出中の接続の返却を待つことを確認する。
#[tokio::test]
async fn test_close_with_timeout_waits_for_leased_connection() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let lease = pool.acquire().await.expect("接続の取得に失敗しました");
    let result = pool.close_with_timeout(Duration::from_millis(100)).await;
    assert!(result.is_err(), "貸出中の接続があるのに停止できました");

    drop(lease);
    pool.close_with_timeout(Duration::from_secs(5))
        .await
        .expect("接続の返却後の停止に失敗しました");
}

/// min_size を維持し、確立した接続数が統計に反映されることを確認する。
#[tokio::test]
async fn test_min_size_is_maintained() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 3,
        min_idle: 0,
        min_size: 2,
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let mut created = 0;
    for _ in 0..50 {
        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        // total は確立中の接続も含むため、確立が完了するまで待つ。
        created = stat.created_total;
        if created >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(created >= 2, "min_size まで接続が確立されませんでした");
    pool.close().await.expect("プールの停止に失敗しました");
}

/// 起動時に確立した接続が統計に反映されることを確認する。
#[tokio::test]
async fn test_startup_connections_are_counted() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 2,
        min_idle: 1,
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(stat.idle, 1, "起動時のアイドル接続数が一致しません");
    assert!(
        stat.created_total >= 1,
        "起動時の接続数が統計に反映されていません"
    );
    pool.close().await.expect("プールの停止に失敗しました");
}

/// リセット後に貸出中の接続が破棄され、新しい接続が使われることを確認する。
#[tokio::test]
async fn test_reset_replaces_leased_connections() {
    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;
    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        acquire_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let pool = helpers::start_pool(&options, config).await;

    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    let old_pid = pooled.connection().backend_process_id();
    pool.reset().await.expect("リセットに失敗しました");

    // 貸出中の接続はリセット直後も使い続けられる。
    assert!(
        pooled.connection().is_open(),
        "貸出中の接続がリセットで閉じられました"
    );
    {
        let mut cursor = Cursor::new(pooled.connection_mut());
        cursor
            .query("SELECT 1")
            .await
            .expect("SELECT の実行に失敗しました");
        let rows = cursor.fetch_all().expect("結果取得に失敗しました");
        assert_eq!(rows[0][0], Value::Int4(1), "結果が一致しません");
    }
    drop(pooled);

    // 返却時に破棄され、新しい接続でクエリを実行できること。
    let mut pooled = pool
        .acquire()
        .await
        .expect("リセット後の接続の取得に失敗しました");
    assert_ne!(
        pooled.connection().backend_process_id(),
        old_pid,
        "リセット後も同じ接続が使われました"
    );
    {
        let mut cursor = Cursor::new(pooled.connection_mut());
        cursor
            .query("SELECT 2")
            .await
            .expect("SELECT の実行に失敗しました");
        let rows = cursor.fetch_all().expect("結果取得に失敗しました");
        assert_eq!(rows[0][0], Value::Int4(2), "結果が一致しません");
    }
    drop(pooled);
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.discarded.reset, 1,
        "リセットで破棄した接続の集計が一致しません"
    );
    pool.close().await.expect("プールの停止に失敗しました");
}

/// 接続ライフサイクルのフックが呼ばれることを確認する。
#[tokio::test]
async fn test_lifecycle_hooks_are_called() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    helpers::init_tracing();
    let (options, _node) = helpers::build_postgres_options().await;

    let before_connect = Arc::new(AtomicUsize::new(0));
    let after_connect = Arc::new(AtomicUsize::new(0));
    let after_release = Arc::new(AtomicUsize::new(0));
    let before_close = Arc::new(AtomicUsize::new(0));
    let on_acquire = Arc::new(AtomicUsize::new(0));
    let on_release = Arc::new(AtomicUsize::new(0));

    let config = PoolConfig {
        max_size: 1,
        min_idle: 0,
        before_connect: Some({
            let counter = before_connect.clone();
            Arc::new(move |_options: &mut ConnectOptions| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
        }),
        before_close: Some({
            let counter = before_close.clone();
            Arc::new(move |_conn: &mut Connection| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
        }),
        on_release: Some({
            let counter = on_release.clone();
            Arc::new(move |_conn: &Connection| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
        }),
        ..Default::default()
    }
    .with_after_connect({
        let counter = after_connect.clone();
        move |_conn| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    })
    .with_after_release({
        let counter = after_release.clone();
        move |_conn| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    })
    .with_on_acquire({
        let counter = on_acquire.clone();
        move |_conn| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    });

    let pool = helpers::start_pool(&options, config).await;
    let lease = pool.acquire().await.expect("接続の取得に失敗しました");
    drop(lease);
    // 返却は非同期に処理されるため、フックが呼ばれるまで待つ。
    for _ in 0..500 {
        if before_connect.load(Ordering::SeqCst) >= 1
            && after_connect.load(Ordering::SeqCst) >= 1
            && on_acquire.load(Ordering::SeqCst) >= 1
            && on_release.load(Ordering::SeqCst) >= 1
            && after_release.load(Ordering::SeqCst) >= 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    pool.close().await.expect("プールの停止に失敗しました");

    assert!(
        before_connect.load(Ordering::SeqCst) >= 1,
        "before_connect が呼ばれませんでした"
    );
    assert!(
        after_connect.load(Ordering::SeqCst) >= 1,
        "after_connect が呼ばれませんでした"
    );
    assert!(
        on_acquire.load(Ordering::SeqCst) >= 1,
        "on_acquire が呼ばれませんでした"
    );
    assert!(
        on_release.load(Ordering::SeqCst) >= 1,
        "on_release が呼ばれませんでした"
    );
    assert!(
        after_release.load(Ordering::SeqCst) >= 1,
        "after_release が呼ばれませんでした"
    );
    assert!(
        before_close.load(Ordering::SeqCst) >= 1,
        "before_close が呼ばれませんでした"
    );
}

/// 枠を待った試行だけを数え、取得キャンセルと通常の引き渡しの両方を集計する。
#[tokio::test]
async fn test_capacity_wait_counts_only_queued_acquisitions() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let (options, _node) = helpers::build_postgres_options().await;
    let pool = helpers::start_pool(
        &options,
        PoolConfig {
            max_size: 1,
            min_idle: 0,
            ..Default::default()
        },
    )
    .await;
    let held = pool.acquire().await.expect("接続の取得に失敗しました");
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(
        stat.capacity_wait_total, 0,
        "空き枠があった取得が枠待ちに数えられました"
    );
    assert_eq!(
        stat.capacity_wait_duration_total,
        Duration::ZERO,
        "接続確立の時間が枠待ちに加算されました"
    );

    // 即時取得は枠がない場合にも待機しない。
    assert!(
        pool.try_acquire()
            .await
            .expect("即時取得に失敗しました")
            .is_none()
    );

    let mut canceled = Box::pin(pool.acquire());
    let mut waiting = Box::pin(pool.acquire());
    // Future を同じタスクから poll し、統計要求より前に取得要求を送る。
    poll_fn(|cx| {
        assert!(
            canceled.as_mut().poll(cx).is_pending(),
            "枠がないのに接続を取得できました"
        );
        assert!(
            waiting.as_mut().poll(cx).is_pending(),
            "枠がないのに接続を取得できました"
        );
        Poll::Ready(())
    })
    .await;
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(stat.waiting, 2, "待機中の取得試行数が一致しません");
    assert_eq!(stat.capacity_wait_total, 2, "枠待ちの回数が一致しません");
    assert_eq!(
        stat.capacity_wait_duration_total,
        Duration::ZERO,
        "終了していない試行の枠待ち時間が加算されました"
    );

    drop(canceled);
    let stat = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(stat.waiting, 1, "キャンセル済みの取得試行が残っています");
    assert!(
        stat.capacity_wait_duration_total > Duration::ZERO,
        "キャンセルした試行の枠待ち時間が記録されていません"
    );

    drop(held);
    let next = waiting.await.expect("空き枠を確保できませんでした");
    let finished = pool.stat().await.expect("統計の取得に失敗しました");
    assert_eq!(finished.waiting, 0, "取得済みの試行がキューに残っています");
    assert_eq!(
        finished.capacity_wait_total, 2,
        "枠待ちの回数が重複計上されました"
    );
    assert_eq!(
        finished.acquire_timeout_total, 0,
        "取得キャンセルがタイムアウトに数えられました"
    );
    assert!(
        finished.capacity_wait_duration_total > stat.capacity_wait_duration_total,
        "待機を経て成功した試行が集計されませんでした"
    );
    drop(next);
    pool.close().await.expect("プールの停止に失敗しました");
}

mod reuse_safety {
    use super::*;
    use shiguredo_postgres::pool::Pool;
    use std::sync::Arc;

    /// アイドルに戻してから時間切れになった接続を即時取得でも貸し出さない。
    #[tokio::test]
    async fn test_try_acquire_evicts_idle_expired_connection() {
        let (options, _node) = helpers::build_postgres_options().await;
        let pool = helpers::start_pool(
            &options,
            PoolConfig {
                max_size: 1,
                min_idle: 0,
                max_idle_time: Duration::ZERO,
                ..Default::default()
            },
        )
        .await;
        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        drop(pooled);

        // アイドル時間が 0 なので、返却後にアイドルキューからは貸し出せない。
        assert!(
            pool.try_acquire()
                .await
                .expect("即時取得に失敗しました")
                .is_none(),
            "アイドル時間切れの接続が再利用されました"
        );
        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert_eq!(
            stat.discarded.idle_expired, 1,
            "アイドル時間切れで破棄した接続の集計が一致しません"
        );
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 確立後フックが閉じた接続でプールの準備や貸出を成功扱いにしない。
    #[tokio::test]
    async fn test_after_connect_cannot_lend_closed_connection() {
        let (options, _node) = helpers::build_postgres_options().await;
        let mut config = PoolConfig {
            max_size: 1,
            min_idle: 1,
            ..Default::default()
        }
        .with_after_connect(|conn| {
            Box::pin(async move {
                conn.force_close();
                Ok(())
            })
        });
        assert!(
            Pool::start(options.clone(), config.clone()).await.is_err(),
            "閉じた接続で初期化に成功しました"
        );

        config.min_idle = 0;
        let pool = helpers::start_pool(&options, config).await;
        assert!(
            pool.acquire().await.is_err(),
            "確立後フックが閉じた接続を取得できました"
        );
        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert_eq!(stat.created_total, 1, "確立した接続の集計が一致しません");
        assert_eq!(
            stat.acquired_total, 0,
            "貸し出していない接続が計上されました"
        );
        assert_eq!(
            stat.discarded.already_closed, 1,
            "閉じていた接続の集計が一致しません"
        );
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// ロールバック後の返却フックが接続を閉じても、閉じた接続は貸し出さない。
    #[tokio::test]
    async fn test_after_release_cannot_reuse_closed_connection_after_rollback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (options, _node) = helpers::build_postgres_options().await;
        let count = Arc::new(AtomicUsize::new(0));
        let pool = helpers::start_pool(
            &options,
            PoolConfig {
                max_size: 1,
                min_idle: 0,
                ..Default::default()
            }
            .with_after_release({
                let count = count.clone();
                move |conn| {
                    let count = count.clone();
                    Box::pin(async move {
                        assert_eq!(
                            conn.transaction_status(),
                            transaction_status::IDLE,
                            "ロールバック前に返却フックが呼ばれました"
                        );
                        if count.fetch_add(1, Ordering::Relaxed) == 0 {
                            conn.force_close();
                        }
                        Ok(())
                    })
                }
            }),
        )
        .await;
        let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        pooled
            .connection_mut()
            .query("BEGIN", false)
            .await
            .expect("BEGIN の実行に失敗しました");
        let original_pid = pooled.connection().backend_process_id();
        drop(pooled);

        let pooled = pool.acquire().await.expect("接続の再取得に失敗しました");
        assert_ne!(
            pooled.connection().backend_process_id(),
            original_pid,
            "返却フックが閉じた接続が再利用されました"
        );
        drop(pooled);

        // 2 回目の返却フックは接続を閉じない。フックは非同期に走るため、
        // 呼び出しが終わるまで待ってから集計を確認する。
        for _ in 0..500 {
            if count.load(Ordering::Relaxed) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert_eq!(
            count.load(Ordering::Relaxed),
            2,
            "返却フックの呼び出し回数が一致しません"
        );
        assert_eq!(
            stat.discarded.already_closed, 1,
            "閉じていた接続の集計が一致しません"
        );
        assert_eq!(
            stat.discarded.rejected_by_hook, 0,
            "フックが拒んだ接続の集計が一致しません"
        );
        assert_eq!(
            stat.closed_total + stat.closing as u64,
            1,
            "破棄された接続が重複計上されました"
        );
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 応答待ちの Future がキャンセルされると、IDLE が残っていても接続を再利用しない。
    #[tokio::test]
    async fn test_canceled_query_is_not_reused() {
        let (options, _node) = helpers::build_postgres_options().await;
        let pool = helpers::start_pool(
            &options,
            PoolConfig {
                max_size: 1,
                min_idle: 0,
                ..Default::default()
            },
        )
        .await;
        let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        let original_pid = pooled.connection().backend_process_id();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            pooled.connection_mut().query("SELECT pg_sleep(30)", false),
        )
        .await;
        assert!(
            result.is_err(),
            "実行中のクエリがタイムアウトしませんでした"
        );
        drop(pooled);

        let pooled = pool.acquire().await.expect("接続の再取得に失敗しました");
        assert_ne!(
            pooled.connection().backend_process_id(),
            original_pid,
            "実行を中断した接続が再利用されました"
        );
        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert_eq!(
            stat.discarded.unsynchronized, 1,
            "プロトコルの同期を確認できない接続の集計が一致しません"
        );
        drop(pooled);
        pool.close().await.expect("プールの停止に失敗しました");
    }
}

mod async_hooks {
    use super::*;
    use shiguredo_postgres::error::Error;
    use shiguredo_postgres::pool::Pool;

    /// 確立後フックで初期化 SQL を実行できることを確認する。
    #[tokio::test]
    async fn test_after_connect_runs_initialization_sql() {
        let (options, _node) = helpers::build_postgres_options().await;
        let config = PoolConfig {
            max_size: 1,
            min_idle: 0,
            ..Default::default()
        }
        .with_after_connect(|conn| {
            Box::pin(async move {
                conn.execute("SET application_name = 'pool-init'", &[], false)
                    .await?;
                Ok(())
            })
        });
        let pool = helpers::start_pool(&options, config).await;

        // Deref 経由でプールの接続を直接使う。
        let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        let row = pooled
            .query_one("SHOW application_name", &[])
            .await
            .expect("設定値の取得に失敗しました");
        assert_eq!(
            row.get::<String>(0)
                .expect("application_name を取得できません"),
            "pool-init",
            "after_connect の設定が反映されていません"
        );
        drop(pooled);
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 確立後フックのエラーで接続の確立が失敗することを確認する。
    #[tokio::test]
    async fn test_after_connect_error_rejects_the_connection() {
        let (options, _node) = helpers::build_postgres_options().await;
        let config = PoolConfig {
            max_size: 1,
            min_idle: 1,
            ..Default::default()
        }
        .with_after_connect(|_conn| {
            Box::pin(async { Err(Error::interface("initialization failed")) })
        });

        assert!(
            Pool::start(options, config).await.is_err(),
            "確立後フックのエラーでプールの起動が失敗しませんでした"
        );
    }

    /// 貸出フックが拒否した接続を貸し出さないことを確認する。
    #[tokio::test]
    async fn test_on_acquire_can_reject_a_connection() {
        let (options, _node) = helpers::build_postgres_options().await;
        let config = PoolConfig {
            max_size: 1,
            min_idle: 0,
            acquire_timeout: Duration::from_secs(10),
            ..Default::default()
        }
        .with_on_acquire(|_conn| Box::pin(async { Err(Error::interface("rejected")) }));
        let pool = helpers::start_pool(&options, config).await;

        let error = pool
            .acquire()
            .await
            .err()
            .expect("拒否した接続が貸し出されました");
        assert_eq!(
            error.message(),
            "rejected",
            "貸出フックのエラーが返りませんでした"
        );
        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert!(
            stat.discarded.rejected_by_hook >= 1,
            "貸出フックで破棄した接続の集計が一致しません"
        );
        pool.close().await.expect("プールの停止に失敗しました");
    }
}

mod recycling {
    use super::*;
    use shiguredo_postgres::pool::{ConnectionHook, RecyclingMethod};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Clean がセッション状態を破棄することを確認する。
    #[tokio::test]
    async fn test_clean_recycling_discards_session_state() {
        let (options, _node) = helpers::build_postgres_options().await;
        let config = PoolConfig {
            max_size: 1,
            min_idle: 0,
            recycling: RecyclingMethod::Clean,
            ..Default::default()
        };
        let pool = helpers::start_pool(&options, config).await;

        {
            let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
            pooled
                .execute("SET myapp.tenant = 'leaked'", &[], false)
                .await
                .expect("SET の実行に失敗しました");
            let row = pooled
                .query_one("SELECT current_setting('myapp.tenant', true)", &[])
                .await
                .expect("設定値の取得に失敗しました");
            assert_eq!(
                row.get_opt::<String>(0)
                    .expect("設定値を取得できません")
                    .as_deref(),
                Some("leaked"),
                "貸出中の設定値が一致しません"
            );
        }

        // max_size が 1 なので、後始末中の接続がアイドルに戻るまで待つ。
        let mut pooled = pool.acquire().await.expect("接続の再取得に失敗しました");
        let row = pooled
            .query_one("SELECT current_setting('myapp.tenant', true)", &[])
            .await
            .expect("設定値の取得に失敗しました");
        assert_ne!(
            row.get_opt::<String>(0)
                .expect("設定値を取得できません")
                .as_deref(),
            Some("leaked"),
            "DISCARD ALL の後にセッション設定が残っています"
        );
        drop(pooled);
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// Custom の後始末フックが返却時に実行されることを確認する。
    #[tokio::test]
    async fn test_custom_recycling_runs_the_hook() {
        let (options, _node) = helpers::build_postgres_options().await;
        let count = Arc::new(AtomicUsize::new(0));
        let hook: ConnectionHook = Arc::new({
            let count = count.clone();
            move |conn| {
                let count = count.clone();
                Box::pin(async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    conn.execute("SET myapp.recycled = 'yes'", &[], false)
                        .await?;
                    Ok(())
                })
            }
        });
        let config = PoolConfig {
            max_size: 1,
            min_idle: 0,
            ..Default::default()
        }
        .with_recycling(RecyclingMethod::Custom(hook));
        let pool = helpers::start_pool(&options, config).await;

        drop(pool.acquire().await.expect("接続の取得に失敗しました"));
        let mut pooled = pool.acquire().await.expect("接続の再取得に失敗しました");
        let row = pooled
            .query_one("SELECT current_setting('myapp.recycled', true)", &[])
            .await
            .expect("設定値の取得に失敗しました");
        assert_eq!(
            row.get_opt::<String>(0)
                .expect("設定値を取得できません")
                .as_deref(),
            Some("yes"),
            "Custom の後始末が実行されていません"
        );
        assert!(
            count.load(Ordering::Relaxed) >= 1,
            "Custom の後始末フックが呼ばれていません"
        );
        drop(pooled);
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 接続生成の差し替えが使われることを確認する。
    #[tokio::test]
    async fn test_connector_is_used_to_establish_connections() {
        let (options, _node) = helpers::build_postgres_options().await;
        let count = Arc::new(AtomicUsize::new(0));
        let config = PoolConfig {
            max_size: 1,
            min_idle: 0,
            ..Default::default()
        }
        .with_connector({
            let count = count.clone();
            move |options: ConnectOptions| {
                count.fetch_add(1, Ordering::Relaxed);
                Connection::connect(options)
            }
        });
        let pool = helpers::start_pool(&options, config).await;

        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        assert!(
            count.load(Ordering::Relaxed) >= 1,
            "差し替えた接続生成処理が呼ばれていません"
        );
        drop(pooled);
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 返却された接続のソケットが close_with_timeout の完了までに閉じることを確認する。
    #[tokio::test]
    async fn test_close_with_timeout_closes_returned_connections() {
        use std::time::Instant;

        let (options, _node) = helpers::build_postgres_options().await;
        let pool = helpers::start_pool(
            &options,
            PoolConfig {
                max_size: 1,
                min_idle: 0,
                ..Default::default()
            },
        )
        .await;
        let pooled = pool.acquire().await.expect("接続の取得に失敗しました");
        let pid = pooled.backend_process_id();

        let closer = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.close_with_timeout(Duration::from_secs(5)).await })
        };
        // 停止が貸出の返却を待っている間に返却する。
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(pooled);
        closer
            .await
            .expect("停止タスクが失敗しました")
            .expect("プールの停止に失敗しました");

        let mut conn = helpers::connect(&options).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let row = conn
                .query_one(
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE pid = $1",
                    &[Value::Int4(pid as i32)],
                )
                .await
                .expect("pg_stat_activity の参照に失敗しました");
            if row.get::<i64>(0).expect("件数を取得できません") == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "返却された接続のバックエンドが残っています"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
