// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! コネクションプール。
//!
//! マネージャタスクが接続の所有権を一元管理し、
//! mpsc チャネル経由で貸出・返却を行う。
//! Mutex / RwLock は使用しない。

use crate::connection::Connection;
use shiguredo_postgres_core::connection::ConnectOptions;
use shiguredo_postgres_core::error::{Error, Result};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// プール設定。
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// 最大接続数。
    pub max_size: usize,
    /// 最小アイドル接続数。プール起動時にこの数だけ接続を確立する。
    pub min_idle: usize,
    /// アイドル接続の最大生存時間。超過した接続は破棄される。
    pub max_idle_time: Duration,
    /// 接続の最大生存時間。超過した接続は再利用されない。
    pub max_lifetime: Duration,
    /// 接続取得のタイムアウト。
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10,
            min_idle: 1,
            max_idle_time: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
            acquire_timeout: Duration::from_secs(30),
        }
    }
}

/// マネージャタスクへの要求。
enum PoolRequest {
    /// 接続を 1 つ取得する。
    Acquire {
        reply: mpsc::Sender<Result<Connection>>,
    },
    /// 接続を返却する。
    Return {
        conn: Box<Connection>,
        created_at: Instant,
    },
    /// プールを閉じる。
    Close,
}

/// コネクションプール。
///
/// 内部的にマネージャタスクを起動し、接続のライフサイクルを管理する。
/// `Clone` して複数タスクから共有できる。
pub struct Pool {
    request_tx: mpsc::Sender<PoolRequest>,
    config: PoolConfig,
}

impl Clone for Pool {
    fn clone(&self) -> Self {
        Self {
            request_tx: self.request_tx.clone(),
            config: self.config.clone(),
        }
    }
}

impl Pool {
    /// プールを生成し、マネージャタスクを起動する。
    pub async fn start(options: ConnectOptions, config: PoolConfig) -> Result<Self> {
        if config.max_size == 0 {
            return Err(Error::InterfaceError {
                message: "max_size must be greater than 0".to_string(),
            });
        }
        if config.min_idle > config.max_size {
            return Err(Error::InterfaceError {
                message: "min_idle must not exceed max_size".to_string(),
            });
        }

        let (request_tx, request_rx) = mpsc::channel::<PoolRequest>(config.max_size * 2);

        // min_idle 分の接続を事前に確立する。
        let mut idle: Vec<IdleConnection> = Vec::new();
        for _ in 0..config.min_idle {
            let conn = Connection::connect(options.clone()).await?;
            idle.push(IdleConnection {
                conn,
                created_at: Instant::now(),
                idle_since: Instant::now(),
            });
        }

        let manager = PoolManager {
            options,
            config: config.clone(),
            idle,
            active_count: 0,
            request_rx,
            waiting: std::collections::VecDeque::new(),
        };
        tokio::spawn(manager.run());

        tracing::info!(
            max_size = config.max_size,
            min_idle = config.min_idle,
            "Connection pool started"
        );

        Ok(Self { request_tx, config })
    }

    /// プールから接続を 1 つ取得する。
    ///
    /// アイドル接続があればそれを返し、なければ新規接続を生成する。
    /// 最大接続数に達している場合は、空きが出るまで待機する。
    pub async fn acquire(&self) -> Result<PooledConnection> {
        let (reply_tx, mut reply_rx) = mpsc::channel::<Result<Connection>>(1);

        self.request_tx
            .send(PoolRequest::Acquire { reply: reply_tx })
            .await
            .map_err(|_| Error::InterfaceError {
                message: "Connection pool manager is gone".to_string(),
            })?;

        let conn = tokio::time::timeout(self.config.acquire_timeout, reply_rx.recv())
            .await
            .map_err(|_| Error::InterfaceError {
                message: "Timed out waiting for a connection from the pool".to_string(),
            })?
            .ok_or_else(|| Error::InterfaceError {
                message: "Connection pool manager is gone".to_string(),
            })??;

        Ok(PooledConnection {
            conn: Some(conn),
            created_at: Instant::now(),
            pool: self.clone(),
        })
    }

    /// プールを閉じる。
    ///
    /// マネージャタスクに停止を通知する。
    /// 既に貸出中の接続は、返却時に破棄される。
    pub async fn close(&self) -> Result<()> {
        self.request_tx
            .send(PoolRequest::Close)
            .await
            .map_err(|_| Error::InterfaceError {
                message: "Connection pool manager is already gone".to_string(),
            })
    }
}

/// プールから貸し出された接続。
///
/// `Drop` 時に自動的にプールへ返却される。
/// 明示的に破棄したい場合は `discard()` を呼ぶ。
pub struct PooledConnection {
    conn: Option<Connection>,
    created_at: Instant,
    pool: Pool,
}

impl PooledConnection {
    /// 内部の接続への参照を取得する。
    pub fn connection(&self) -> &Connection {
        self.conn
            .as_ref()
            .expect("PooledConnection is already consumed")
    }

    /// 内部の接続への可変参照を取得する。
    pub fn connection_mut(&mut self) -> &mut Connection {
        self.conn
            .as_mut()
            .expect("PooledConnection is already consumed")
    }

    /// 接続をプールに返却せず破棄する。
    pub fn discard(mut self) {
        if let Some(mut conn) = self.conn.take() {
            conn.force_close();
        }
        // pool への返却は行わない。Drop 実装側で conn が None なら何もしない。
        tracing::debug!("Connection discarded from pool");
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take()
            && conn.is_open()
        {
            let request_tx = self.pool.request_tx.clone();
            let created_at = self.created_at;
            // 非同期コンテキスト外から返却するため、try_send で試みる。
            // チャネルが満杯の場合は接続を破棄する。
            if request_tx
                .try_send(PoolRequest::Return {
                    conn: Box::new(conn),
                    created_at,
                })
                .is_err()
            {
                tracing::debug!("Failed to return connection to pool, dropping it");
            }
        }
    }
}

/// アイドル接続の管理情報。
struct IdleConnection {
    conn: Connection,
    created_at: Instant,
    idle_since: Instant,
}

/// マネージャタスクの本体。
///
/// 全接続の所有権を持ち、貸出・返却・寿命管理を行う。
/// 最大接続数に達した acquire 要求は待機キューに積み、
/// 接続が返却されたら渡す。
struct PoolManager {
    options: ConnectOptions,
    config: PoolConfig,
    idle: Vec<IdleConnection>,
    active_count: usize,
    request_rx: mpsc::Receiver<PoolRequest>,
    waiting: std::collections::VecDeque<mpsc::Sender<Result<Connection>>>,
}

impl PoolManager {
    async fn run(mut self) {
        // アイドル接続の掃除用インターバル。
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(request) = self.request_rx.recv() => {
                    match request {
                        PoolRequest::Acquire { reply } => {
                            self.handle_acquire(reply).await;
                        }
                        PoolRequest::Return { conn, created_at } => {
                            self.handle_return(conn, created_at).await;
                        }
                        PoolRequest::Close => {
                            tracing::info!("Connection pool closing");
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    self.evict_expired();
                    // 破棄で min_idle を下回った場合は補充する。
                    self.replenish_idle().await;
                }
            }
        }

        // 残りのアイドル接続をすべて閉じる。
        for mut idle_conn in self.idle.drain(..) {
            let _ = idle_conn.conn.close().await;
        }
        tracing::info!("Connection pool closed");
    }

    /// 接続の取得要求を処理する。
    async fn handle_acquire(&mut self, reply: mpsc::Sender<Result<Connection>>) {
        // アイドル接続から有効なものを探す。
        while let Some(idle_conn) = self.idle.pop() {
            if self.is_healthy(&idle_conn) {
                self.active_count += 1;
                let _ = reply.send(Ok(idle_conn.conn)).await;
                return;
            }
            // 不正な接続は破棄する。
            tracing::debug!("Evicting unhealthy idle connection");
        }

        // アイドルがなければ新規接続を生成する。
        if self.active_count < self.config.max_size {
            self.active_count += 1;
            let result = Connection::connect(self.options.clone()).await;
            if result.is_err() {
                // 接続の生成に失敗した場合は数を戻して再試行できるようにする。
                self.active_count -= 1;
            }
            let _ = reply.send(result).await;
            return;
        }

        // 最大接続数に達している場合は、空きが出るまで待機する。
        // 要求側は acquire_timeout で打ち切るため、ここで待機しても
        // タイムアウト処理は要求側に任される。
        self.waiting.push_back(reply);
    }

    /// 接続の返却を処理する。
    async fn handle_return(&mut self, mut conn: Box<Connection>, created_at: Instant) {
        self.active_count = self.active_count.saturating_sub(1);

        if !conn.is_open() {
            return;
        }

        // commit / rollback されずに破棄されたトランザクションがあれば
        // ロールバックしてからアイドルに戻す。
        // ロールバックに失敗した場合は接続を破棄する。
        if let Err(e) = conn.rollback_dirty_transaction().await {
            tracing::debug!(error = %e, "Failed to roll back dirty transaction, dropping connection");
            return;
        }

        // 最大生存時間を超過していれば破棄する。
        if created_at.elapsed() >= self.config.max_lifetime {
            tracing::debug!("Connection exceeded max_lifetime, dropping");
            return;
        }

        // 待機中の要求があれば、その要求に接続を渡す。
        // 要求側がタイムアウト等で drop 済みの場合は次の要求を試す。
        let mut conn = *conn;
        while let Some(reply) = self.waiting.pop_front() {
            match reply.try_send(Ok(conn)) {
                Ok(()) => {
                    self.active_count += 1;
                    self.replenish_idle().await;
                    return;
                }
                Err(err) => {
                    // 送信失敗時は TrySendError からメッセージを取り戻せる。
                    let message = match err {
                        mpsc::error::TrySendError::Full(m)
                        | mpsc::error::TrySendError::Closed(m) => m,
                    };
                    conn = message.expect("connection result is always contained in the message");
                    tracing::debug!("Waiting acquire request was cancelled");
                }
            }
        }

        self.idle.push(IdleConnection {
            conn,
            created_at,
            idle_since: Instant::now(),
        });
        // アイドル数が min_idle を下回っている場合は補充する。
        self.replenish_idle().await;
    }

    /// アイドル接続が min_idle を下回っている場合に補充する。
    ///
    /// 接続数の上限 (max_size) を超えない範囲で、min_idle まで
    /// 新規接続を確立してアイドルに追加する。
    /// 接続の確立に失敗した場合は中断する (次の機会に再試行する)。
    async fn replenish_idle(&mut self) {
        while self.idle.len() < self.config.min_idle
            && self.active_count + self.idle.len() < self.config.max_size
        {
            match Connection::connect(self.options.clone()).await {
                Ok(conn) => {
                    self.idle.push(IdleConnection {
                        conn,
                        created_at: Instant::now(),
                        idle_since: Instant::now(),
                    });
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to replenish idle connection");
                    break;
                }
            }
        }
    }

    /// 期限切れのアイドル接続を破棄する。
    fn evict_expired(&mut self) {
        let before = self.idle.len();
        self.idle.retain(|idle_conn| {
            let idle_expired = idle_conn.idle_since.elapsed() >= self.config.max_idle_time;
            let lifetime_expired = idle_conn.created_at.elapsed() >= self.config.max_lifetime;
            !idle_expired && !lifetime_expired
        });
        let evicted = before - self.idle.len();
        if evicted > 0 {
            tracing::debug!(evicted, "Evicted expired idle connections");
        }
    }

    /// 接続が再利用可能かどうかを判定する。
    fn is_healthy(&self, idle_conn: &IdleConnection) -> bool {
        if !idle_conn.conn.is_open() {
            return false;
        }
        if idle_conn.created_at.elapsed() >= self.config.max_lifetime {
            return false;
        }
        if idle_conn.idle_since.elapsed() >= self.config.max_idle_time {
            return false;
        }
        true
    }
}
