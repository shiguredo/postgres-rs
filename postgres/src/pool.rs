// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! コネクションプール。
//!
//! マネージャタスクが接続のライフサイクルを管理する。
//! アイドル接続の受け渡しだけは短い Mutex で保護し、貸出・返却の
//! 高速経路はチャネル往復を避けて直接アイドルキューを操作する。
//! 待機者がある場合や、フック・ロールバックが必要な場合は
//! これまでどおりマネージャへ要求を送る。
//!
//! 接続の確立、ロールバック、クローズは `JoinSet` で管理する別タスクが
//! 担当する。マネージャはこれらの完了を待たないため、接続の確立中でも
//! 返却や他の取得要求を処理できる。タスクが panic した場合も `JoinSet`
//! が完了として返すため、接続数の会計が失われない。
//!
//! 接続数は「貸出中 + アイドル + 確立中 + 後始末中 + 破棄中」の合計が
//! `max_size` を超えないように管理する。

use crate::connection::{ConnectOptions, Connection};
use crate::constants::transaction_status;
use crate::error::{Error, Result};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;

/// 接続を使用する前に生存確認を行うアイドル時間。
const PING_AFTER_IDLE: Duration = Duration::from_secs(1);

/// トランザクションの後始末 (ロールバック) に許す時間。
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// プール停止時に接続を閉じるのに許す時間。
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// 接続を可変で借りて非同期処理を行うフックの戻り値。
///
/// 接続の借用期間をフックの実行期間に閉じ込めるため、ライフタイムを引数に持つ。
pub type HookFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// 接続を可変で受け取り、結果を返す非同期フック。
///
/// 接続の初期化や後始末に SQL を実行できる。エラーを返すと接続は破棄される。
/// フックは `Arc` で共有するため、同じフックが複数のタスクから同時に呼ばれる。
pub type ConnectionHook = Arc<dyn for<'a> Fn(&'a mut Connection) -> HookFuture<'a> + Send + Sync>;

/// 接続を確立する処理。
///
/// [`PoolConfig::connector`] に設定すると、プールは接続の確立をこの処理に委ねる。
/// OAuth のトークン更新を含む接続など、[`Connection::connect`] 以外の経路を使う場合に使う。
pub type Connector = Arc<
    dyn Fn(ConnectOptions) -> Pin<Box<dyn Future<Output = Result<Connection>> + Send>>
        + Send
        + Sync,
>;

/// 接続確立前に呼ばれるフック。
type BeforeConnectHook = Arc<dyn Fn(&mut ConnectOptions) + Send + Sync>;

/// 接続クローズ前に呼ばれるフック。
type BeforeCloseHook = Arc<dyn Fn(&mut Connection) + Send + Sync>;

/// 接続の貸出・返却を観測するフック。
type ConnectionObserver = Arc<dyn Fn(&Connection) + Send + Sync>;

/// 接続をプールに戻すときのセッション状態の扱い。
#[derive(Clone, Default)]
pub enum RecyclingMethod {
    /// トランザクションをロールバックするだけで、セッション状態は残す。
    ///
    /// `SET`、一時テーブル、`LISTEN`、セッション単位のアドバイザリロックなどは
    /// 次の利用者に持ち越される。状態を残したくない場合は [`RecyclingMethod::Clean`] か
    /// [`RecyclingMethod::Custom`] を使う。
    #[default]
    Fast,
    /// トランザクションをロールバックし、`DISCARD ALL` でセッションを初期化する。
    ///
    /// `DISCARD ALL` はサーバー側のプリペアドステートメントも破棄するため、
    /// この接続の文キャッシュと、利用者が保持する [`crate::connection::PreparedStatement`] は
    /// 無効になる。取得し直した接続で古い文を実行するとエラーになる。
    Clean,
    /// 利用者が指定した非同期フックでセッションを後始末する。
    ///
    /// フックはトランザクションのロールバック後に呼ばれる。
    /// エラーを返した接続は破棄する。
    Custom(ConnectionHook),
}

impl fmt::Debug for RecyclingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fast => f.write_str("Fast"),
            Self::Clean => f.write_str("Clean"),
            Self::Custom(_) => f.write_str("Custom"),
        }
    }
}

/// プール設定。
#[derive(Clone)]
pub struct PoolConfig {
    /// 最大接続数。
    ///
    /// 貸出中・アイドル・確立中・後始末中・破棄中の接続の合計の上限。
    pub max_size: usize,
    /// 最小アイドル接続数。
    ///
    /// プール起動時にこの数だけ接続を確立する。
    /// 起動後はこの数を下回らないよう随時補充する。
    pub min_idle: usize,
    /// 最小接続数。
    ///
    /// 貸出中・アイドル・確立中・後始末中の合計の下限。
    /// 貸出中の接続が多い場合でも、この数までは接続を維持する。
    pub min_size: usize,
    /// アイドル接続の最大生存時間。超過した接続は破棄される。
    pub max_idle_time: Duration,
    /// 接続の最大生存時間。超過した接続は再利用されない。
    pub max_lifetime: Duration,
    /// 接続の最大生存時間に加えるジッターの最大値。
    ///
    /// 接続ごとに 0 からこの値までの範囲で寿命をばらつかせ、
    /// 同時に作られた接続が一斉に失効するのを防ぐ。
    pub max_lifetime_jitter: Duration,
    /// 接続取得のタイムアウト。
    pub acquire_timeout: Duration,
    /// アイドル接続の点検と最小アイドル接続の補充を行う間隔。
    pub health_check_interval: Duration,
    /// アイドル接続の生存確認 (Ping) のタイムアウト。
    ///
    /// 0 の場合はタイムアウトしない。
    pub ping_timeout: Duration,
    /// 接続を確立する前に呼ばれるフック。
    ///
    /// 接続オプションを書き換えるために使う。
    /// マネージャとは別のタスクで同期的に呼ばれるため、重い処理を書かないこと。
    pub before_connect: Option<BeforeConnectHook>,
    /// 接続を確立する処理。
    ///
    /// `None` の場合は [`Connection::connect`] を使う。
    /// OAuth のトークン更新を含む接続など、別の経路を使う場合に設定する。
    pub connector: Option<Connector>,
    /// 接続を確立した後に呼ばれる非同期フック。
    ///
    /// 初期化 SQL (`search_path` や `statement_timeout` の設定など) を実行できる。
    /// エラーを返した接続は破棄し、接続の確立は失敗する。
    /// このフックで設定した状態は [`RecyclingMethod::Clean`] の `DISCARD ALL` で
    /// 初期化される。接続ごとに固定したい設定は
    /// [`ConnectOptions::runtime_params`] を使う。
    pub after_connect: Option<ConnectionHook>,
    /// 接続をアイドルに戻す直前に呼ばれる非同期フック。
    ///
    /// トランザクションのロールバックと [`PoolConfig::recycling`] の処理の後に呼ばれる。
    /// エラーを返した接続は破棄する。
    pub after_release: Option<ConnectionHook>,
    /// 接続を閉じる直前に呼ばれるフック。
    ///
    /// マネージャとは別のタスクで同期的に呼ばれる。`discard()` では呼び出し元で同期的に
    /// 実行される。重い処理を書かないこと。
    pub before_close: Option<BeforeCloseHook>,
    /// 接続を貸し出す直前に呼ばれる非同期フック。
    ///
    /// エラーを返した接続は破棄し、別の接続で取得をやり直す。
    /// 取得のタイムアウトはこのやり直しを含めて判定する。
    pub on_acquire: Option<ConnectionHook>,
    /// 接続を返却したときに呼ばれるフック。
    ///
    /// 通常はマネージャタスク内で同期的に呼ばれる。`discard()` では呼び出し元で同期的に
    /// 実行される。重い処理を書かないこと。
    pub on_release: Option<ConnectionObserver>,
    /// 接続をプールに戻すときのセッション状態の扱い。
    ///
    /// 既定は [`RecyclingMethod::Fast`] で、トランザクションのロールバックだけを行う。
    pub recycling: RecyclingMethod,
}

impl fmt::Debug for PoolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolConfig")
            .field("max_size", &self.max_size)
            .field("min_idle", &self.min_idle)
            .field("min_size", &self.min_size)
            .field("max_idle_time", &self.max_idle_time)
            .field("max_lifetime", &self.max_lifetime)
            .field("max_lifetime_jitter", &self.max_lifetime_jitter)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("health_check_interval", &self.health_check_interval)
            .field("ping_timeout", &self.ping_timeout)
            .field("before_connect", &self.before_connect.is_some())
            .field("connector", &self.connector.is_some())
            .field("after_connect", &self.after_connect.is_some())
            .field("after_release", &self.after_release.is_some())
            .field("before_close", &self.before_close.is_some())
            .field("on_acquire", &self.on_acquire.is_some())
            .field("on_release", &self.on_release.is_some())
            .field("recycling", &self.recycling)
            .finish()
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10,
            min_idle: 1,
            min_size: 0,
            max_idle_time: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
            max_lifetime_jitter: Duration::ZERO,
            acquire_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(5),
            before_connect: None,
            connector: None,
            after_connect: None,
            after_release: None,
            before_close: None,
            on_acquire: None,
            on_release: None,
            recycling: RecyclingMethod::Fast,
        }
    }
}

impl PoolConfig {
    /// 接続を確立する処理を設定する。
    ///
    /// 設定した処理は接続を確立するたびに呼ばれる。
    #[must_use]
    pub fn with_connector<F, Fut>(mut self, connector: F) -> Self
    where
        F: Fn(ConnectOptions) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Connection>> + Send + 'static,
    {
        self.connector = Some(Arc::new(move |options| Box::pin(connector(options))));
        self
    }

    /// 接続確立後に実行する非同期フックを設定する。
    #[must_use]
    pub fn with_after_connect<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a mut Connection) -> HookFuture<'a> + Send + Sync + 'static,
    {
        self.after_connect = Some(Arc::new(hook));
        self
    }

    /// 接続をアイドルに戻す直前に実行する非同期フックを設定する。
    #[must_use]
    pub fn with_after_release<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a mut Connection) -> HookFuture<'a> + Send + Sync + 'static,
    {
        self.after_release = Some(Arc::new(hook));
        self
    }

    /// 接続を貸し出す直前に実行する非同期フックを設定する。
    ///
    /// フックがエラーを返した接続は破棄され、取得は別の接続でやり直される。
    #[must_use]
    pub fn with_on_acquire<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a mut Connection) -> HookFuture<'a> + Send + Sync + 'static,
    {
        self.on_acquire = Some(Arc::new(hook));
        self
    }

    /// 接続をプールに戻すときのセッション状態の扱いを設定する。
    #[must_use]
    pub fn with_recycling(mut self, recycling: RecyclingMethod) -> Self {
        self.recycling = recycling;
        self
    }
}

/// アイドル接続と待機者数。取得・返却の高速経路とマネージャで共有する。
struct IdleState {
    connections: VecDeque<ManagedConnection>,
    /// マネージャの待機キューにいる取得要求の数。
    ///
    /// 高速経路は待機者を追い越さないため、この値が 0 のときだけ使う。
    waiting: usize,
}

impl IdleState {
    fn new(connections: VecDeque<ManagedConnection>) -> Self {
        Self {
            connections,
            waiting: 0,
        }
    }
}

/// マネージャと高速経路で共有するプール状態。
struct PoolShared {
    idle: Mutex<IdleState>,
    /// 貸出中の接続数。
    active: AtomicUsize,
}

impl PoolShared {
    fn lock_idle(&self) -> MutexGuard<'_, IdleState> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// プールの内部状態。
struct PoolInner {
    request_tx: mpsc::UnboundedSender<PoolRequest>,
    /// アイドル接続と貸出数。高速経路と共有する。
    shared: Arc<PoolShared>,
    config: PoolConfig,
    /// プールが閉じられたかどうか。
    closed: AtomicBool,
    /// マネージャの外で生存確認した接続もリセット前の世代なら貸し出さない。
    generation: AtomicU64,
    /// 貸し出しに成功した延べ数。
    acquired_total: AtomicU64,
    /// 取得がタイムアウトした延べ数。
    acquire_timeout_total: AtomicU64,
    /// 取得に要した時間の合計 (ナノ秒)。
    acquire_duration_total_nanos: AtomicU64,
    /// 現在貸し出している接続数。
    lease_count: AtomicUsize,
    /// 貸出数が 0 になったことを待機者へ知らせる。
    lease_zero: Notify,
}

impl PoolInner {
    fn lease_acquired(&self) {
        self.lease_count.fetch_add(1, Ordering::Relaxed);
    }

    fn lease_released(&self) {
        let previous = self
            .lease_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            })
            .unwrap_or(0);
        if previous == 1 {
            self.lease_zero.notify_waiters();
        }
    }
}

/// マネージャタスクへの要求。
enum PoolRequest {
    /// 接続を 1 つ取得する。
    Acquire { waiter: Waiter },
    /// 空きがあれば接続を 1 つ取得する。
    TryAcquire {
        reply: oneshot::Sender<Option<PooledConnection>>,
    },
    /// 接続を返却する。理由が指定された接続は再利用しない。
    Release {
        conn: ManagedConnection,
        discard: Option<DiscardReason>,
    },
    /// 高速取得の検査で使えなかったアイドル接続を破棄する。
    ///
    /// 貸出前の接続なので `on_release` フックは呼ばない。
    DiscardIdle {
        conn: ManagedConnection,
        reason: DiscardReason,
    },
    /// 高速取得でアイドル接続が尽きたときに、補充を促す。
    Wake,
    /// 呼び出し元で接続を破棄し、貸出枠を 1 つ解放する。
    Discard { reason: DiscardReason },
    /// プールの状態を取得する。
    Stat { reply: oneshot::Sender<PoolStat> },
    /// すべての接続を破棄し、プールを開いたままにする。
    Reset { ack: oneshot::Sender<()> },
    /// プールを閉じる。
    Close { ack: oneshot::Sender<()> },
}

/// プールの状態のスナップショット。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStat {
    /// 最大接続数。
    pub max_size: usize,
    /// 現在の接続数 (貸出中・アイドル・確立中・後始末中・破棄中の合計)。
    pub total: usize,
    /// 貸出中の接続数。
    pub active: usize,
    /// アイドル接続数。
    pub idle: usize,
    /// 確立中の接続数。
    pub creating: usize,
    /// 後始末中の接続数。
    pub cleaning: usize,
    /// 破棄中の接続数。
    pub closing: usize,
    /// 最大接続数に達しているため、空き枠を待っている取得試行の数。
    pub waiting: usize,
    /// これまでに貸し出した接続の延べ数。`try_acquire` の成功を含む。
    pub acquired_total: u64,
    /// `acquire` と `acquire_with_timeout` がタイムアウトした延べ数。
    pub acquire_timeout_total: u64,
    /// 成功した `acquire` と `acquire_with_timeout` の処理時間の合計。
    ///
    /// 接続の確立・生存確認・試行のやり直しを含む。`try_acquire` は含まない。
    pub acquire_duration_total: Duration,
    /// 最大接続数に達し、再利用できるアイドル接続もなく、キューに入った取得試行の延べ数。
    ///
    /// `try_acquire` は計上しない。再試行などで同じ呼び出しが再び待った場合はその都度数える。
    pub capacity_wait_total: u64,
    /// 枠待ちを終えた取得試行の待ち時間の合計。
    ///
    /// キューに入ってから再利用できる接続または新規接続用の枠を確保する時点までを計上する。
    /// その前にタイムアウトやキャンセルで終了した場合は、その時点までを計上する。
    /// 接続を確保した後の貸出フック、接続の確立、生存確認の時間は含まない。
    pub capacity_wait_duration_total: Duration,
    /// これまでに確立した接続の延べ数。確立後の検査で破棄された接続も含む。
    pub created_total: u64,
    /// これまでに破棄が完了した接続の延べ数。現在クローズ処理中の接続は含まない。
    pub closed_total: u64,
    /// 確立済みの接続を破棄すると決めた理由ごとの延べ数。
    ///
    /// 接続 1 件につき最初に確定した理由を 1 件だけ計上する。クローズ処理中の接続も
    /// 含む。接続の確立自体に失敗した場合は含まない。
    pub discarded: PoolDiscardStat,
}

/// 確立済みの接続を破棄すると決めた理由ごとの統計。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolDiscardStat {
    /// 利用者が `discard()` を呼んだ接続の数。
    pub explicit: u64,
    /// 検査時点で既に閉じていた接続の数。
    pub already_closed: u64,
    /// 最大生存時間に達した接続の数。
    pub lifetime_expired: u64,
    /// 最大アイドル時間に達した接続の数。
    pub idle_expired: u64,
    /// リセット前の世代に属する接続の数。
    pub reset: u64,
    /// 処理の途中など、プロトコルの同期を確認できなかった接続の数。
    pub unsynchronized: u64,
    /// ロールバック後や貸出前の検査でトランザクションが残っていた接続の数。
    pub transaction_not_idle: u64,
    /// `after_release` または `on_acquire` がエラーを返した接続の数。
    pub rejected_by_hook: u64,
    /// 接続の後始末 (`DISCARD ALL` やカスタムの後始末) に失敗した接続の数。
    pub recycle_failed: u64,
    /// 生存確認の失敗・タイムアウト・実行中の取得キャンセルで破棄した接続の数。
    pub ping_failed: u64,
    /// ロールバックを実行できなかった接続の数。
    pub rollback_failed: u64,
    /// プールの停止に伴って破棄した接続の数。
    pub shutdown: u64,
}

#[derive(Debug, Clone, Copy)]
enum DiscardReason {
    Explicit,
    AlreadyClosed,
    LifetimeExpired,
    IdleExpired,
    Reset,
    Unsynchronized,
    TransactionNotIdle,
    RejectedByHook,
    RecycleFailed,
    PingFailed,
    RollbackFailed,
    Shutdown,
}

impl PoolDiscardStat {
    fn record(&mut self, reason: DiscardReason) {
        let counter = match reason {
            DiscardReason::Explicit => &mut self.explicit,
            DiscardReason::AlreadyClosed => &mut self.already_closed,
            DiscardReason::LifetimeExpired => &mut self.lifetime_expired,
            DiscardReason::IdleExpired => &mut self.idle_expired,
            DiscardReason::Reset => &mut self.reset,
            DiscardReason::Unsynchronized => &mut self.unsynchronized,
            DiscardReason::TransactionNotIdle => &mut self.transaction_not_idle,
            DiscardReason::RejectedByHook => &mut self.rejected_by_hook,
            DiscardReason::RecycleFailed => &mut self.recycle_failed,
            DiscardReason::PingFailed => &mut self.ping_failed,
            DiscardReason::RollbackFailed => &mut self.rollback_failed,
            DiscardReason::Shutdown => &mut self.shutdown,
        };
        *counter += 1;
    }
}

/// プールがライフサイクルを管理する接続。
struct ManagedConnection {
    conn: Box<Connection>,
    /// 接続を確立した時刻。
    created_at: Instant,
    /// この接続に適用する最大生存時間 (ジッター込み)。
    lifetime: Duration,
    /// 接続を確立したときのプールの世代。
    generation: u64,
    /// アイドルキューに入った時刻。直ちに貸し出す場合は `None`。
    idle_since: Option<Instant>,
}

impl ManagedConnection {
    /// 接続の返却・点検・引き渡しで共通の安全条件を確認する。
    fn check(&self, generation: u64) -> std::result::Result<(), DiscardReason> {
        if self.generation != generation {
            return Err(DiscardReason::Reset);
        }
        if !self.conn.is_open() {
            return Err(DiscardReason::AlreadyClosed);
        }
        if self.created_at.elapsed() >= self.lifetime {
            return Err(DiscardReason::LifetimeExpired);
        }
        if self.conn.is_busy() {
            return Err(DiscardReason::Unsynchronized);
        }
        match self.conn.transaction_status() {
            transaction_status::IDLE => Ok(()),
            transaction_status::IN_TRANSACTION | transaction_status::FAILED => {
                Err(DiscardReason::TransactionNotIdle)
            }
            _ => Err(DiscardReason::Unsynchronized),
        }
    }

    /// アイドルキューから出すときはアイドル時間も確認する。
    fn check_idle(
        &self,
        generation: u64,
        max_idle_time: Duration,
    ) -> std::result::Result<(), DiscardReason> {
        self.check(generation)?;
        if self
            .idle_since
            .is_some_and(|since| since.elapsed() >= max_idle_time)
        {
            return Err(DiscardReason::IdleExpired);
        }
        Ok(())
    }
}

/// 取得試行の応答先と、枠待ちを計測するための情報。
struct Waiter {
    reply: oneshot::Sender<Result<PooledConnection>>,
    canceled_at: oneshot::Receiver<Instant>,
    queued_at: Option<Instant>,
}

/// 取得 Future が破棄された時刻をマネージャに残す。
struct AcquireCancellation(Option<oneshot::Sender<Instant>>);

impl Drop for AcquireCancellation {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(Instant::now());
        }
    }
}

/// 接続確立タスクの結果と、その接続を使う取得要求。
struct ConnectorOutcome {
    result: Result<ManagedConnection>,
    waiter: Option<Waiter>,
}

/// コネクションプール。
///
/// 内部的にマネージャタスクを起動し、接続のライフサイクルを管理する。
/// `Clone` して複数タスクから共有できる。
///
/// 返却時の自動ロールバックは未完了のトランザクションだけを対象とする。
/// [`PoolConfig::recycling`] が [`RecyclingMethod::Fast`] の場合、コミット済みの
/// セッション設定 (`SET`)、一時テーブル、`LISTEN`、セッション単位の
/// アドバイザリロックなどは次の利用者に持ち越される。
/// [`RecyclingMethod::Clean`] なら `DISCARD ALL` で初期化し、
/// [`RecyclingMethod::Custom`] なら任意の後始末を実行できる。
#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

impl Pool {
    /// プールを生成し、マネージャタスクを起動する。
    ///
    /// `min_idle` 分の接続を確立してから戻る。
    /// いずれかの接続の確立に失敗した場合は、確立済みの接続を閉じてエラーを返す。
    pub async fn start(options: ConnectOptions, config: PoolConfig) -> Result<Self> {
        Self::start_inner(options, config, true).await
    }

    /// 接続を確立せずにプールを生成し、マネージャタスクを起動する。
    ///
    /// `min_idle` と `min_size` の接続はバックグラウンドで確立する。
    /// データベースがまだ起動していない場合でもプールを生成できる。
    pub async fn start_lazy(options: ConnectOptions, config: PoolConfig) -> Result<Self> {
        Self::start_inner(options, config, false).await
    }

    async fn start_inner(
        options: ConnectOptions,
        config: PoolConfig,
        establish_min_idle: bool,
    ) -> Result<Self> {
        validate_config(&config)?;

        let mut idle: VecDeque<ManagedConnection> = VecDeque::new();
        if establish_min_idle && config.min_idle > 0 {
            // 起動時の接続確立も並列に行う。
            let mut connectors = JoinSet::new();
            for index in 0..config.min_idle {
                let options = options.clone();
                let lifetime = connection_lifetime(&config, index as u64);
                let before_connect = config.before_connect.clone();
                let connector = config.connector.clone();
                let after_connect = config.after_connect.clone();
                connectors.spawn(establish_connection(
                    options,
                    connector,
                    before_connect,
                    after_connect,
                    lifetime,
                    0,
                ));
            }

            let mut first_error = None;
            while let Some(result) = connectors.join_next().await {
                match result {
                    Ok(Ok(mut conn)) => match conn.check(0) {
                        Ok(()) => {
                            conn.idle_since = Some(Instant::now());
                            idle.push_back(conn);
                        }
                        Err(reason) => {
                            if conn.conn.is_open() {
                                close_connection(conn.conn, config.before_close.clone()).await;
                            }
                            first_error = Some(unusable_connection_error(reason));
                        }
                    },
                    Ok(Err(error)) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                    Err(join_error) => {
                        tracing::error!(
                            error = %join_error,
                            "Connection establishment task failed during startup"
                        );
                        if first_error.is_none() {
                            first_error =
                                Some(Error::interface("Connection establishment task failed"));
                        }
                    }
                }

                if first_error.is_some() {
                    connectors.shutdown().await;
                    break;
                }
            }

            if let Some(error) = first_error {
                close_idle_connections(idle, config.before_close.clone()).await;
                return Err(error);
            }
        }

        let startup_connections = idle.len() as u64;
        let shared = Arc::new(PoolShared {
            idle: Mutex::new(IdleState::new(idle)),
            active: AtomicUsize::new(0),
        });
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(PoolInner {
            request_tx,
            shared: Arc::clone(&shared),
            config: config.clone(),
            closed: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            acquired_total: AtomicU64::new(0),
            acquire_timeout_total: AtomicU64::new(0),
            acquire_duration_total_nanos: AtomicU64::new(0),
            lease_count: AtomicUsize::new(0),
            lease_zero: Notify::new(),
        });
        let manager = PoolManager {
            options,
            config,
            inner: Arc::downgrade(&inner),
            shared,
            creating: 0,
            replenishing: 0,
            replenishment_paused: false,
            cleaning: 0,
            closing: 0,
            created_total: startup_connections,
            closed_total: 0,
            discarded: PoolDiscardStat::default(),
            capacity_wait_total: 0,
            capacity_wait_duration_total: Duration::ZERO,
            lifetime_counter: startup_connections,
            generation: 0,
            waiting: VecDeque::new(),
            request_rx,
            connectors: JoinSet::new(),
            replenishers: JoinSet::new(),
            cleanups: JoinSet::new(),
            closers: JoinSet::new(),
        };
        tokio::spawn(manager.run());

        tracing::info!(
            max_size = inner.config.max_size,
            min_idle = inner.config.min_idle,
            "Connection pool started"
        );

        Ok(Self { inner })
    }

    /// プールから接続を 1 つ取得する。
    ///
    /// アイドル接続があればそれを返し、なければ新規接続を生成する。
    /// 最大接続数に達している場合は、空きが出るまで待機する。
    /// アイドル状態が長い接続は、使用前に生存確認を行う。
    pub async fn acquire(&self) -> Result<PooledConnection> {
        self.acquire_with_timeout(self.inner.config.acquire_timeout)
            .await
    }

    /// 指定したタイムアウトで接続を 1 つ取得する。
    ///
    /// 待ち時間が指定したタイムアウトを超えた場合はエラーを返す。
    pub async fn acquire_with_timeout(
        &self,
        acquire_timeout: Duration,
    ) -> Result<PooledConnection> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::interface("Connection pool is closed"));
        }

        match tokio::time::timeout(acquire_timeout, self.acquire_with_retry()).await {
            Ok(result) => result,
            Err(_) => {
                self.inner
                    .acquire_timeout_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(Error::interface(
                    "Timed out waiting for a connection from the pool",
                ))
            }
        }
    }

    /// 空きがあれば接続を 1 つ取得する。
    ///
    /// アイドル接続がない場合は待機せずに `None` を返す。
    /// 新規接続の確立も行わない。
    pub async fn try_acquire(&self) -> Result<Option<PooledConnection>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::interface("Connection pool is closed"));
        }

        let lease = match self.try_fast_acquire() {
            Some(lease) => Some(lease),
            None => {
                let (reply_tx, reply_rx) = oneshot::channel();
                self.inner
                    .request_tx
                    .send(PoolRequest::TryAcquire { reply: reply_tx })
                    .map_err(|_| Error::interface("Connection pool manager is gone"))?;
                reply_rx
                    .await
                    .map_err(|_| Error::interface("Connection pool manager is gone"))?
            }
        };
        let Some(mut lease) = lease else {
            return Ok(None);
        };
        match self.check_lease(&lease) {
            Ok(()) => {}
            Err(DiscardReason::Shutdown) => {
                lease.discard_on_drop = Some(DiscardReason::Shutdown);
                return Err(Error::interface("Connection pool is closed"));
            }
            Err(reason) => {
                lease.discard_on_drop = Some(reason);
                return Ok(None);
            }
        }
        // 貸出フックは取得側タスクで実行する。
        if let Some(hook) = &self.inner.config.on_acquire {
            if let Err(error) = hook(lease.connection_mut()).await {
                tracing::debug!(error = %error, "on_acquire hook rejected a pooled connection");
                lease.discard_on_drop = Some(DiscardReason::RejectedByHook);
                return Ok(None);
            }
            // フックの実行中に寿命が尽きたり、接続が使えなくなったりする。
            if let Err(reason) = self.check_lease(&lease) {
                lease.discard_on_drop = Some(reason);
                return Ok(None);
            }
        }
        self.inner.acquired_total.fetch_add(1, Ordering::Relaxed);
        Ok(Some(lease))
    }

    /// 取得と生存確認を繰り返す。
    async fn acquire_with_retry(&self) -> Result<PooledConnection> {
        let started = Instant::now();
        // 貸出フックが拒否した接続のエラー。すべて拒否された場合はこれを返す。
        let mut rejected = None;
        // 生存確認の前後に貸出条件が崩れた接続を捨てながら取得を試みる。
        // 試行回数は最大接続数に 1 を加えた数に制限する。
        for _ in 0..=self.inner.config.max_size {
            let mut lease = match self.try_fast_acquire() {
                Some(lease) => lease,
                None => self.request_connection().await?,
            };
            if let Err(reason) = self.check_lease(&lease) {
                lease.discard_on_drop = Some(reason);
                if matches!(reason, DiscardReason::Shutdown) {
                    return Err(Error::interface("Connection pool is closed"));
                }
                continue;
            }

            // アイドル状態が長い接続だけ生存確認を行う。
            if lease
                .managed()
                .idle_since
                .is_some_and(|since| since.elapsed() >= PING_AFTER_IDLE)
            {
                // 生存確認が途中でキャンセルされた場合は接続を再利用しない。
                lease.discard_on_drop = Some(DiscardReason::PingFailed);
                if !self.is_alive(&mut lease).await {
                    lease.discard_with_reason(DiscardReason::PingFailed);
                    continue;
                }
                lease.discard_on_drop = None;
                if let Err(reason) = self.check_lease(&lease) {
                    lease.discard_on_drop = Some(reason);
                    if matches!(reason, DiscardReason::Shutdown) {
                        return Err(Error::interface("Connection pool is closed"));
                    }
                    continue;
                }
            }

            // 貸出フックは取得側タスクで実行する。マネージャで実行すると、
            // フックの待ち時間が他の取得・返却を塞ぐ。
            if let Some(hook) = &self.inner.config.on_acquire {
                if let Err(error) = hook(lease.connection_mut()).await {
                    tracing::debug!(error = %error, "on_acquire hook rejected a pooled connection");
                    lease.discard_on_drop = Some(DiscardReason::RejectedByHook);
                    rejected = Some(error);
                    continue;
                }
                // フックの実行中に寿命が尽きたり、接続が使えなくなったりする。
                if let Err(reason) = self.check_lease(&lease) {
                    lease.discard_on_drop = Some(reason);
                    if matches!(reason, DiscardReason::Shutdown) {
                        return Err(Error::interface("Connection pool is closed"));
                    }
                    continue;
                }
            }

            self.inner.acquired_total.fetch_add(1, Ordering::Relaxed);
            let elapsed = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            self.inner
                .acquire_duration_total_nanos
                .fetch_add(elapsed, Ordering::Relaxed);
            return Ok(lease);
        }

        Err(rejected.unwrap_or_else(|| {
            Error::interface("Failed to acquire a healthy connection from the pool")
        }))
    }

    /// アイドル接続をマネージャを介さずに取得する。
    ///
    /// 待機者がいる場合、接続が寿命切れ・未同期・トランザクション中の場合、
    /// フック後の検査に失敗した場合は `None` を返し、呼び出し側が
    /// マネージャ経由の取得へフォールバックする。
    fn try_fast_acquire(&self) -> Option<PooledConnection> {
        if self.inner.closed.load(Ordering::Acquire) {
            return None;
        }
        let (conn, replenish) = {
            let mut idle = self.inner.shared.lock_idle();
            // 待機者がいる場合は順番を守るため高速経路を使わない。
            if idle.waiting > 0 {
                return None;
            }
            let conn = idle.connections.pop_front()?;
            // 検査に失敗しても DiscardIdle で戻せるよう、先に貸出中へ移す。
            self.inner.shared.active.fetch_add(1, Ordering::AcqRel);
            // アイドルが尽き、まだ最大接続数に余裕がある場合だけ補充を促す。
            // max_size に達している場合に起こすと、無駄な起床が増える。
            let replenish = idle.connections.is_empty()
                && self.inner.config.min_idle > 0
                && self.inner.shared.active.load(Ordering::Acquire) < self.inner.config.max_size;
            (conn, replenish)
        };
        if replenish {
            let _ = self.inner.request_tx.send(PoolRequest::Wake);
        }
        match self.make_fast_lease(conn) {
            Ok(lease) => Some(lease),
            Err((conn, reason)) => {
                let request = PoolRequest::DiscardIdle { conn, reason };
                if let Err(error) = self.inner.request_tx.send(request) {
                    let _ = self.inner.shared.active.try_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |count| Some(count.saturating_sub(1)),
                    );
                    drop(error.0);
                }
                None
            }
        }
    }

    /// 高速経路用の貸出検査。マネージャの `make_lease` と同じ条件を使う。
    fn make_fast_lease(
        &self,
        conn: ManagedConnection,
    ) -> std::result::Result<PooledConnection, (ManagedConnection, DiscardReason)> {
        let generation = self.inner.generation.load(Ordering::Acquire);
        let check = |conn: &ManagedConnection| {
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(DiscardReason::Shutdown);
            }
            conn.check_idle(generation, self.inner.config.max_idle_time)
        };
        if let Err(reason) = check(&conn) {
            return Err((conn, reason));
        }
        // 貸出フックは接続を渡した後の取得側タスクで実行する。
        // ここで実行すると、フックの待ち時間がマネージャや高速経路を塞ぐ。
        self.inner.lease_acquired();
        Ok(PooledConnection {
            conn: Some(conn),
            inner: Arc::clone(&self.inner),
            released: false,
            discard_on_drop: None,
        })
    }

    /// マネージャに接続を 1 つ要求する。
    async fn request_connection(&self) -> Result<PooledConnection> {
        let (reply, mut reply_rx) = oneshot::channel();
        let (cancel_tx, canceled_at) = oneshot::channel();
        // `reply_rx` より先に Drop されるように宣言する。マネージャが応答先の
        // 閉鎖を検出した時点で、キャンセルされた時刻を取得できる。
        let mut cancellation = AcquireCancellation(Some(cancel_tx));
        self.inner
            .request_tx
            .send(PoolRequest::Acquire {
                waiter: Waiter {
                    reply,
                    canceled_at,
                    queued_at: None,
                },
            })
            .map_err(|_| Error::interface("Connection pool manager is gone"))?;
        let result = (&mut reply_rx).await;
        cancellation.0 = None;
        result.map_err(|_| Error::interface("Connection pool manager is gone"))?
    }

    /// マネージャから受け取った後や、生存確認後の接続を再確認する。
    fn check_lease(&self, lease: &PooledConnection) -> std::result::Result<(), DiscardReason> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(DiscardReason::Shutdown);
        }
        lease
            .managed()
            .check(self.inner.generation.load(Ordering::Acquire))
    }

    /// 接続の生存確認を行う。
    async fn is_alive(&self, lease: &mut PooledConnection) -> bool {
        let ping = lease.connection_mut().ping();
        if self.inner.config.ping_timeout.is_zero() {
            ping.await.is_ok()
        } else {
            tokio::time::timeout(self.inner.config.ping_timeout, ping)
                .await
                .is_ok_and(|result| result.is_ok())
        }
    }

    /// プールの状態を取得する。
    ///
    /// マネージャタスクに問い合わせるため、非同期関数になっている。
    pub async fn stat(&self) -> Result<PoolStat> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .request_tx
            .send(PoolRequest::Stat { reply: reply_tx })
            .map_err(|_| Error::interface("Connection pool manager is gone"))?;
        reply_rx
            .await
            .map_err(|_| Error::interface("Connection pool manager is gone"))
    }

    /// プールの設定を取得する。
    pub fn config(&self) -> PoolConfig {
        self.inner.config.clone()
    }

    /// すべての接続を破棄し、プールを開いたままにする。
    ///
    /// 貸出中の接続は返却時に破棄される。
    /// ネットワーク障害やサーバー再起動の後に接続を作り直すときに使う。
    pub async fn reset(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::interface("Connection pool is closed"));
        }

        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .request_tx
            .send(PoolRequest::Reset { ack: ack_tx })
            .map_err(|_| Error::interface("Connection pool manager is gone"))?;
        ack_rx
            .await
            .map_err(|_| Error::interface("Connection pool manager is gone"))
    }

    /// プールを閉じる。
    ///
    /// マネージャタスクに停止を通知し、アイドル接続を閉じる。
    /// 貸出中の接続は、返却時に破棄される。
    /// 2 回目以降の呼び出しは何もせず `Ok(())` を返す。
    pub async fn close(&self) -> Result<()> {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .request_tx
            .send(PoolRequest::Close { ack: ack_tx })
            .map_err(|_| Error::interface("Connection pool manager is already gone"))?;
        ack_rx
            .await
            .map_err(|_| Error::interface("Connection pool manager is already gone"))
    }

    /// プールを閉じ、貸出中の接続がすべて返却されるまで待つ。
    ///
    /// 返却された接続は、貸出数の解放前にソケットを閉じる。
    /// そのため、この関数が成功した時点でプールが管理していた接続の
    /// 物理クローズも完了している。
    /// 指定したタイムアウトを超えても返却されない場合はエラーを返す。
    /// タイムアウトした場合もプール自体は閉じられている。
    pub async fn close_with_timeout(&self, timeout: Duration) -> Result<()> {
        self.close().await?;

        let wait_for_leases = async {
            loop {
                // カウント確認前に待機登録し、0 への遷移を取りこぼさない。
                let notified = self.inner.lease_zero.notified();
                tokio::pin!(notified);
                let _ = notified.as_mut().enable();
                if self.inner.lease_count.load(Ordering::Acquire) == 0 {
                    break;
                }
                notified.await;
            }
            Ok::<(), Error>(())
        };
        tokio::time::timeout(timeout, wait_for_leases)
            .await
            .map_err(|_| {
                Error::interface("Timed out waiting for leased connections to be released")
            })??;
        Ok(())
    }
}

/// プールから貸し出された接続。
///
/// `Drop` 時に自動的にプールへ返却される。
/// 明示的に破棄したい場合は `discard()` を呼ぶ。
pub struct PooledConnection {
    conn: Option<ManagedConnection>,
    inner: Arc<PoolInner>,
    released: bool,
    /// 生存確認中に取得 Future が破棄されても、不完全な接続を再利用しない。
    discard_on_drop: Option<DiscardReason>,
}

impl PooledConnection {
    fn managed(&self) -> &ManagedConnection {
        self.conn
            .as_ref()
            .expect("Pooled connection is already consumed")
    }

    /// 内部の接続への参照を取得する。
    pub fn connection(&self) -> &Connection {
        &self.managed().conn
    }

    /// 内部の接続への可変参照を取得する。
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self
            .conn
            .as_mut()
            .expect("Pooled connection is already consumed")
            .conn
    }

    /// 接続をプールに返却せず破棄する。
    pub fn discard(self) {
        self.discard_with_reason(DiscardReason::Explicit);
    }

    fn discard_with_reason(mut self, reason: DiscardReason) {
        self.discard_on_drop = Some(reason);
        if let Some(mut conn) = self.conn.take() {
            if let Some(hook) = &self.inner.config.on_release {
                hook(&conn.conn);
            }
            if let Some(hook) = &self.inner.config.before_close {
                hook(&mut conn.conn);
            }
            conn.conn.force_close();
        }
        self.release(PoolRequest::Discard { reason });
        tracing::debug!(?reason, "Connection discarded from pool");
    }

    /// フックもロールバックも不要な接続を、マネージャを介さずに返却する。
    ///
    /// 待機者がいる場合、接続が未同期・トランザクション中・寿命切れの場合、
    /// フックが設定されている場合は `false` を返し、マネージャ経由の返却へ
    /// フォールバックする。
    fn try_fast_release(&mut self) -> bool {
        if self.discard_on_drop.is_some()
            || self.inner.closed.load(Ordering::Acquire)
            || self.inner.config.on_release.is_some()
            || self.inner.config.after_release.is_some()
            || !matches!(self.inner.config.recycling, RecyclingMethod::Fast)
        {
            return false;
        }
        let Some(mut conn) = self.conn.take() else {
            return false;
        };
        let mut idle = self.inner.shared.lock_idle();
        // close と reset は idle ロックの外で closed を立て、内側で世代を進める。
        // 判定はロック取得後に行い、停止・リセットとの競合を避ける。
        if self.inner.closed.load(Ordering::Acquire) || idle.waiting > 0 {
            drop(idle);
            self.conn = Some(conn);
            return false;
        }
        let generation = self.inner.generation.load(Ordering::Acquire);
        if conn.check(generation).is_err() {
            drop(idle);
            self.conn = Some(conn);
            return false;
        }
        conn.idle_since = Some(Instant::now());
        idle.connections.push_back(conn);
        let _ = self
            .inner
            .shared
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
        self.inner.lease_released();
        drop(idle);
        self.released = true;
        true
    }

    /// 接続をプールに返却する。
    fn release(&mut self, request: PoolRequest) {
        // 停止と返却が競合した場合も、貸出数の解放前にソケットを閉じる。
        // close_with_timeout が貸出数の 0 を観測した時点で、
        // 返却された接続の物理クローズも完了していることを保証するため。
        let request = match request {
            PoolRequest::Release { mut conn, discard }
                if self.inner.closed.load(Ordering::Acquire) =>
            {
                conn.conn.force_close();
                PoolRequest::Discard {
                    reason: discard.unwrap_or(DiscardReason::Shutdown),
                }
            }
            other => other,
        };
        self.released = true;
        self.inner.lease_released();
        // 非同期コンテキスト外から返却するため、送信は同期で行う。
        // チャネルは無制限なので、ここで失敗するのはプールが閉じた場合だけ。
        if self.inner.request_tx.send(request).is_err() {
            tracing::debug!("Failed to return a connection to the pool");
        }
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection()
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection_mut()
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // プールが閉じている場合は、貸出数の解放前にソケットを閉じる。
        // close_with_timeout が貸出数の 0 を観測した時点で、返却された接続の
        // 物理クローズも完了していることを保証するため。
        if self.inner.closed.load(Ordering::Acquire) {
            if let Some(mut conn) = self.conn.take() {
                conn.conn.force_close();
            }
            self.release(PoolRequest::Discard {
                reason: self.discard_on_drop.unwrap_or(DiscardReason::Shutdown),
            });
            return;
        }
        if self.try_fast_release() {
            return;
        }
        let request = match self.conn.take() {
            Some(conn) => PoolRequest::Release {
                conn,
                discard: self.discard_on_drop,
            },
            None => {
                // 明示的な破棄中にフックが panic した場合にも貸出枠を戻す。
                PoolRequest::Discard {
                    reason: self
                        .discard_on_drop
                        .expect("Missing pooled connection discard reason"),
                }
            }
        };
        self.release(request);
    }
}

/// 設定を検証する。
fn validate_config(config: &PoolConfig) -> Result<()> {
    if config.max_size == 0 {
        return Err(Error::interface("max_size must be greater than 0"));
    }
    if config.min_idle > config.max_size {
        return Err(Error::interface("min_idle must not exceed max_size"));
    }
    if config.min_size > config.max_size {
        return Err(Error::interface("min_size must not exceed max_size"));
    }
    if config.health_check_interval.is_zero() {
        return Err(Error::interface(
            "health_check_interval must be greater than 0",
        ));
    }
    Ok(())
}

/// 接続の寿命をジッター込みで計算する。
fn connection_lifetime(config: &PoolConfig, index: u64) -> Duration {
    if config.max_lifetime_jitter.is_zero() {
        return config.max_lifetime;
    }

    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(index);
    let span = config
        .max_lifetime_jitter
        .as_nanos()
        .saturating_add(1)
        .min(u128::from(u64::MAX)) as u64;
    let jitter = hasher.finish() % span;
    config.max_lifetime + Duration::from_nanos(jitter)
}

/// マネージャタスクの本体。
///
/// 接続のライフサイクルを管理する。アイドル接続は共有キューに置き、
/// 高速経路と受け渡す。接続の確立やロールバックは `JoinSet` のタスクに
/// 任せ、ここでは待たない。
struct PoolManager {
    options: ConnectOptions,
    config: PoolConfig,
    inner: Weak<PoolInner>,
    /// アイドル接続と貸出数。高速経路と共有する。
    shared: Arc<PoolShared>,
    /// 確立中の接続数。
    creating: usize,
    /// アイドル補充のために確立中の接続数。
    replenishing: usize,
    /// 補充に失敗した場合は次のヘルスチェックまで再試行しない。
    replenishment_paused: bool,
    /// 後始末中の接続数。
    cleaning: usize,
    /// 破棄中の接続数。
    closing: usize,
    /// 確立した接続の延べ数。
    created_total: u64,
    /// 破棄した接続の延べ数。
    closed_total: u64,
    discarded: PoolDiscardStat,
    capacity_wait_total: u64,
    capacity_wait_duration_total: Duration,
    /// 次に作る接続のジッター計算に使う番号。
    lifetime_counter: u64,
    /// 接続の世代。リセットするたびに増える。
    generation: u64,
    waiting: VecDeque<Waiter>,
    request_rx: mpsc::UnboundedReceiver<PoolRequest>,
    /// 接続確立タスク (取得要求付き)。
    connectors: JoinSet<ConnectorOutcome>,
    /// 接続確立タスク (アイドル補充用)。
    replenishers: JoinSet<ConnectorOutcome>,
    /// トランザクション後始末タスク。
    cleanups: JoinSet<std::result::Result<ManagedConnection, DiscardReason>>,
    /// 接続破棄タスク。
    closers: JoinSet<()>,
}

impl PoolManager {
    async fn run(mut self) {
        let mut interval = tokio::time::interval(self.config.health_check_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                request = self.request_rx.recv() => {
                    match request {
                        Some(PoolRequest::Acquire { waiter }) => {
                            self.handle_acquire(waiter);
                            self.maybe_replenish();
                        }
                        Some(PoolRequest::TryAcquire { reply }) => {
                            self.handle_try_acquire(reply);
                        }
                        Some(PoolRequest::Release { conn, discard }) => {
                            self.handle_release(conn, discard);
                        }
                        Some(PoolRequest::DiscardIdle { conn, reason }) => {
                            self.release_active();
                            self.discard_connection(conn, reason);
                            self.try_serve_waiters();
                            self.maybe_replenish();
                        }
                        Some(PoolRequest::Wake) => {
                            self.maybe_replenish();
                        }
                        Some(PoolRequest::Discard { reason }) => {
                            self.release_active();
                            self.record_closed(reason);
                            self.try_serve_waiters();
                            self.maybe_replenish();
                        }
                        Some(PoolRequest::Stat { reply }) => {
                            self.prune_canceled_waiters();
                            let _ = reply.send(self.snapshot());
                        }
                        Some(PoolRequest::Reset { ack }) => {
                            self.reset();
                            let _ = ack.send(());
                        }
                        Some(PoolRequest::Close { ack }) => {
                            self.shutdown().await;
                            let _ = ack.send(());
                            break;
                        }
                        None => {
                            self.shutdown().await;
                            break;
                        }
                    }
                }
                Some(result) = self.connectors.join_next() => {
                    self.handle_connector_result(result);
                }
                Some(result) = self.replenishers.join_next() => {
                    self.handle_replenisher_result(result);
                }
                Some(result) = self.cleanups.join_next() => {
                    self.handle_cleanup_result(result);
                }
                Some(result) = self.closers.join_next() => {
                    self.handle_closer_result(result);
                }
                _ = interval.tick() => {
                    self.prune_canceled_waiters();
                    self.replenishment_paused = false;
                    self.evict_idle();
                    self.try_serve_waiters();
                    self.maybe_replenish();
                }
            }
        }

        tracing::info!("Connection pool closed");
    }

    /// 現在の接続数 (貸出中・アイドル・確立中・後始末中・破棄中) を返す。
    fn total(&self) -> usize {
        let idle = self.shared.lock_idle();
        self.total_locked(&idle)
    }

    fn total_locked(&self, idle: &IdleState) -> usize {
        idle.connections.len() + self.active() + self.creating + self.cleaning + self.closing
    }

    fn active(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }

    fn release_active(&self) {
        let _ = self
            .shared
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
    }

    fn push_waiting_back(&mut self, waiter: Waiter) {
        let mut idle = self.shared.lock_idle();
        self.waiting.push_back(waiter);
        idle.waiting = self.waiting.len();
    }

    fn push_waiting_front(&mut self, waiter: Waiter) {
        let mut idle = self.shared.lock_idle();
        self.waiting.push_front(waiter);
        idle.waiting = self.waiting.len();
    }

    /// 現在の状態を取得する。
    fn snapshot(&self) -> PoolStat {
        let (acquired_total, acquire_timeout_total, acquire_duration_total_nanos) =
            match self.inner.upgrade() {
                Some(inner) => (
                    inner.acquired_total.load(Ordering::Relaxed),
                    inner.acquire_timeout_total.load(Ordering::Relaxed),
                    inner.acquire_duration_total_nanos.load(Ordering::Relaxed),
                ),
                None => (0, 0, 0),
            };
        let idle = self.shared.lock_idle();
        PoolStat {
            max_size: self.config.max_size,
            total: self.total_locked(&idle),
            active: self.active(),
            idle: idle.connections.len(),
            creating: self.creating,
            cleaning: self.cleaning,
            closing: self.closing,
            waiting: idle.waiting,
            acquired_total,
            acquire_timeout_total,
            acquire_duration_total: Duration::from_nanos(acquire_duration_total_nanos),
            capacity_wait_total: self.capacity_wait_total,
            capacity_wait_duration_total: self.capacity_wait_duration_total,
            created_total: self.created_total,
            closed_total: self.closed_total,
            discarded: self.discarded,
        }
    }

    /// 空きがあれば新規接続を作らずに渡す。
    fn handle_try_acquire(&mut self, reply: oneshot::Sender<Option<PooledConnection>>) {
        self.prune_canceled_waiters();
        // 待機中の要求がある場合は、順番を守るため割り込まない。
        if !self.waiting.is_empty() || reply.is_closed() {
            let _ = reply.send(None);
            return;
        }

        let lease = self.take_idle_lease().map(|(lease, _)| lease);
        let took_idle = lease.is_some();
        let _ = reply.send(lease);
        if took_idle {
            self.maybe_replenish();
        }
    }

    /// 接続を返却する。
    fn handle_release(&mut self, conn: ManagedConnection, discard: Option<DiscardReason>) {
        self.release_active();

        if let Some(hook) = &self.config.on_release {
            hook(&conn.conn);
        }

        match discard.map_or_else(|| conn.check(self.generation), Err) {
            Ok(()) if self.needs_release_cleanup() => {
                // 非同期フックやセッションの初期化が必要な場合は、
                // マネージャを塞がないよう別タスクで実行する。
                self.spawn_cleanup(conn, false);
            }
            Ok(()) => self.offer(conn),
            Err(DiscardReason::TransactionNotIdle) if discard.is_none() => {
                // プロトコルが同期済みで、開いたトランザクションがあるときだけ
                // マネージャとは別のタスクでロールバックする。
                self.spawn_cleanup(conn, true);
            }
            Err(reason) => self.discard_connection(conn, reason),
        }

        self.try_serve_waiters();
        self.maybe_replenish();
    }

    /// 返却時に非同期の後始末が必要かどうか。
    fn needs_release_cleanup(&self) -> bool {
        self.config.after_release.is_some()
            || !matches!(self.config.recycling, RecyclingMethod::Fast)
    }

    /// 接続を待機中の要求に渡すか、アイドルに追加する。
    fn offer(&mut self, mut conn: ManagedConnection) {
        // 後始末から戻った接続は、再検査してからアイドルキューへ入れる。
        if let Err(reason) = conn.check(self.generation) {
            self.discard_connection(conn, reason);
            return;
        }

        if let Some(mut waiter) = self.pop_waiter() {
            if let Some((lease, available_at)) = self.make_lease(conn) {
                self.finish_wait(&mut waiter, available_at);
                // 受信側が既に破棄されている場合、接続は Drop 経由で返却される。
                let _ = waiter.reply.send(Ok(lease));
            } else {
                self.push_waiting_front(waiter);
            }
        } else {
            conn.idle_since = Some(Instant::now());
            let mut idle = self.shared.lock_idle();
            idle.connections.push_back(conn);
        }
    }

    /// 検査を通過した接続だけを貸し出す。
    fn make_lease(&mut self, conn: ManagedConnection) -> Option<(PooledConnection, Instant)> {
        let inner = self.inner.upgrade()?;
        if inner.closed.load(Ordering::Acquire) {
            self.discard_connection(conn, DiscardReason::Shutdown);
            return None;
        }
        if let Err(reason) = conn.check_idle(self.generation, self.config.max_idle_time) {
            self.discard_connection(conn, reason);
            return None;
        }
        let available_at = Instant::now();

        self.shared.active.fetch_add(1, Ordering::AcqRel);
        inner.lease_acquired();
        Some((
            PooledConnection {
                conn: Some(conn),
                inner,
                released: false,
                discard_on_drop: None,
            },
            available_at,
        ))
    }

    /// 枠待ちを終了させ、実際の待ち時間を合計に加える。
    fn finish_wait(&mut self, waiter: &mut Waiter, end: Instant) {
        record_capacity_wait(waiter, end, &mut self.capacity_wait_duration_total);
    }

    /// キャンセル済みの要求を除き、待ち時間を確定させる。
    fn prune_canceled_waiters(&mut self) {
        let mut idle = self.shared.lock_idle();
        self.waiting.retain_mut(|waiter| {
            if waiter.reply.is_closed() {
                record_capacity_wait(
                    waiter,
                    Instant::now(),
                    &mut self.capacity_wait_duration_total,
                );
                false
            } else {
                true
            }
        });
        idle.waiting = self.waiting.len();
    }

    /// 待機中の要求を取り出す。既に破棄された要求は読み飛ばす。
    fn pop_waiter(&mut self) -> Option<Waiter> {
        let mut idle = self.shared.lock_idle();
        loop {
            let mut waiter = self.waiting.pop_front()?;
            idle.waiting = self.waiting.len();
            if !waiter.reply.is_closed() {
                return Some(waiter);
            }
            drop(idle);
            self.finish_wait(&mut waiter, Instant::now());
            idle = self.shared.lock_idle();
        }
    }

    /// 新しい取得要求を処理し、枯渇時だけ枠待ちを開始する。
    fn handle_acquire(&mut self, waiter: Waiter) {
        self.try_serve_waiters();
        if waiter.reply.is_closed() {
            return;
        }
        if let Err(mut waiter) = self.try_dispatch(waiter) {
            waiter.queued_at = Some(Instant::now());
            self.capacity_wait_total += 1;
            self.push_waiting_back(waiter);
            // 高速返却が同時にアイドルを増やした可能性があるため、
            // 待機キューへ入れた直後にもう一度処理する。
            self.try_serve_waiters();
        }
    }

    /// 待機中の要求を処理する。
    fn try_serve_waiters(&mut self) {
        while let Some(waiter) = self.pop_waiter() {
            if let Err(waiter) = self.try_dispatch(waiter) {
                self.push_waiting_front(waiter);
                break;
            }
        }
    }

    /// 接続を貸し出すか、接続の確立に必要な枠を確保する。
    fn try_dispatch(&mut self, mut waiter: Waiter) -> std::result::Result<(), Waiter> {
        if let Some((lease, available_at)) = self.take_idle_lease() {
            self.finish_wait(&mut waiter, available_at);
            let _ = waiter.reply.send(Ok(lease));
        } else if self.total() < self.config.max_size {
            self.finish_wait(&mut waiter, Instant::now());
            self.spawn_connector(waiter);
        } else {
            return Err(waiter);
        }
        Ok(())
    }

    /// 再利用可能なアイドル接続を取り出す。
    fn take_idle_lease(&mut self) -> Option<(PooledConnection, Instant)> {
        loop {
            let conn = {
                let mut idle = self.shared.lock_idle();
                idle.connections.pop_front()
            };
            let conn = conn?;
            if let Some(lease) = self.make_lease(conn) {
                return Some(lease);
            }
        }
    }

    /// アイドル接続の点検を行う。
    fn evict_idle(&mut self) {
        let connections = {
            let mut idle = self.shared.lock_idle();
            std::mem::take(&mut idle.connections)
        };
        let mut kept = VecDeque::with_capacity(connections.len());
        for conn in connections {
            match conn.check_idle(self.generation, self.config.max_idle_time) {
                Ok(()) => kept.push_back(conn),
                Err(reason) => self.discard_connection(conn, reason),
            }
        }
        // 点検中に高速経路が追加した新しい接続より前に、古い接続を戻す。
        let mut idle = self.shared.lock_idle();
        for conn in kept.into_iter().rev() {
            idle.connections.push_front(conn);
        }
    }

    /// アイドル接続と接続数の下限を維持する。
    fn maybe_replenish(&mut self) {
        if self.replenishment_paused {
            return;
        }
        loop {
            let (idle_len, total) = {
                let idle = self.shared.lock_idle();
                (idle.connections.len(), self.total_locked(&idle))
            };
            let idle_needed = idle_len + self.replenishing < self.config.min_idle;
            let total_needed = total < self.config.min_size;
            if (!idle_needed && !total_needed) || total >= self.config.max_size {
                break;
            }
            self.spawn_replenisher();
        }
    }

    /// 次の接続に適用する寿命を返す。
    fn next_lifetime(&mut self) -> Duration {
        let lifetime = connection_lifetime(&self.config, self.lifetime_counter);
        self.lifetime_counter += 1;
        lifetime
    }

    /// 取得要求に紐づく接続確立タスクを起動する。
    fn spawn_connector(&mut self, waiter: Waiter) {
        self.spawn_connection(Some(waiter));
    }

    /// アイドル補充用の接続確立タスクを起動する。
    fn spawn_replenisher(&mut self) {
        self.spawn_connection(None);
    }

    fn spawn_connection(&mut self, waiter: Option<Waiter>) {
        self.creating += 1;
        let connection = establish_connection(
            self.options.clone(),
            self.config.connector.clone(),
            self.config.before_connect.clone(),
            self.config.after_connect.clone(),
            self.next_lifetime(),
            self.generation,
        );
        let tasks = if waiter.is_none() {
            self.replenishing += 1;
            &mut self.replenishers
        } else {
            &mut self.connectors
        };
        tasks.spawn(async move {
            ConnectorOutcome {
                result: connection.await,
                waiter,
            }
        });
    }

    /// 返却された接続の後始末を行うタスクを起動する。
    ///
    /// `rollback` が `true` の場合はトランザクションをロールバックしてから、
    /// セッションの初期化と返却フックを実行する。
    /// マネージャを塞がないよう、すべての待ち合わせをこのタスクで行う。
    fn spawn_cleanup(&mut self, mut conn: ManagedConnection, rollback: bool) {
        self.cleaning += 1;
        let recycling = self.config.recycling.clone();
        let after_release = self.config.after_release.clone();
        self.cleanups.spawn(async move {
            if rollback {
                match tokio::time::timeout(CLEANUP_TIMEOUT, conn.conn.query("ROLLBACK", false))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(error = %error, "Failed to roll back a pooled connection");
                        conn.conn.force_close();
                        return Err(DiscardReason::RollbackFailed);
                    }
                    Err(_) => {
                        tracing::debug!("Timed out rolling back a pooled connection");
                        conn.conn.force_close();
                        return Err(DiscardReason::RollbackFailed);
                    }
                }
            }
            // ロールバック後もトランザクションが残っていれば再利用しない。
            if conn.conn.transaction_status() != transaction_status::IDLE {
                conn.conn.force_close();
                return Err(DiscardReason::RollbackFailed);
            }
            if let Err(error) = reset_connection_session(&mut conn.conn, &recycling).await {
                tracing::debug!(error = %error, "Failed to reset a pooled connection");
                conn.conn.force_close();
                return Err(DiscardReason::RecycleFailed);
            }
            if let Some(hook) = after_release {
                match tokio::time::timeout(CLEANUP_TIMEOUT, hook(&mut conn.conn)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(
                            error = %error,
                            "after_release hook rejected a pooled connection"
                        );
                        conn.conn.force_close();
                        return Err(DiscardReason::RejectedByHook);
                    }
                    Err(_) => {
                        tracing::debug!("Timed out running the after_release hook");
                        conn.conn.force_close();
                        return Err(DiscardReason::RejectedByHook);
                    }
                }
            }
            Ok(conn)
        });
    }

    /// 理由を一度だけ計上し、別タスクで接続を閉じる。
    fn discard_connection(&mut self, conn: ManagedConnection, reason: DiscardReason) {
        if !conn.conn.is_open() {
            self.record_closed(reason);
            return;
        }
        self.discarded.record(reason);
        self.closing += 1;
        let before_close = self.config.before_close.clone();
        self.closers
            .spawn(close_connection(conn.conn, before_close));
    }

    /// 既に閉じた接続の破棄を計上する。
    fn record_closed(&mut self, reason: DiscardReason) {
        self.discarded.record(reason);
        self.closed_total += 1;
    }

    /// 接続確立タスクの完了を処理する。
    fn handle_connector_result(
        &mut self,
        result: std::result::Result<ConnectorOutcome, JoinError>,
    ) {
        self.creating = self.creating.saturating_sub(1);

        match result {
            Ok(ConnectorOutcome {
                result: Ok(conn),
                waiter,
            }) => {
                self.created_total += 1;
                match conn.check(self.generation) {
                    Ok(()) => match waiter {
                        Some(waiter) if !waiter.reply.is_closed() => {
                            let response = self
                                .make_lease(conn)
                                .map(|(lease, _)| lease)
                                .ok_or_else(|| {
                                    Error::interface(
                                        "New pooled connection became unusable before checkout",
                                    )
                                });
                            let _ = waiter.reply.send(response);
                        }
                        _ => self.offer(conn),
                    },
                    Err(reason) => {
                        self.discard_connection(conn, reason);
                        if let Some(waiter) = waiter {
                            if matches!(reason, DiscardReason::Reset) {
                                self.handle_acquire(waiter);
                            } else {
                                let _ = waiter.reply.send(Err(unusable_connection_error(reason)));
                            }
                        }
                    }
                }
                self.try_serve_waiters();
                self.maybe_replenish();
            }
            Ok(ConnectorOutcome {
                result: Err(error),
                waiter,
            }) => {
                if let Some(waiter) = waiter {
                    let _ = waiter.reply.send(Err(error));
                }
                self.try_serve_waiters();
            }
            Err(join_error) => {
                tracing::error!(error = %join_error, "Connection establishment task failed");
                self.try_serve_waiters();
            }
        }
    }

    /// アイドル補充タスクの完了を処理する。
    fn handle_replenisher_result(
        &mut self,
        result: std::result::Result<ConnectorOutcome, JoinError>,
    ) {
        self.creating = self.creating.saturating_sub(1);
        self.replenishing = self.replenishing.saturating_sub(1);

        match result {
            Ok(ConnectorOutcome {
                result: Ok(conn), ..
            }) => {
                self.created_total += 1;
                match conn.check(self.generation) {
                    Ok(()) => self.offer(conn),
                    Err(reason) => {
                        if !matches!(reason, DiscardReason::Reset) {
                            self.replenishment_paused = true;
                        }
                        self.discard_connection(conn, reason);
                    }
                }
                self.try_serve_waiters();
                self.maybe_replenish();
            }
            Ok(ConnectorOutcome {
                result: Err(error), ..
            }) => {
                self.replenishment_paused = true;
                tracing::warn!(error = %error, "Failed to replenish an idle connection");
                self.try_serve_waiters();
            }
            Err(join_error) => {
                self.replenishment_paused = true;
                tracing::error!(error = %join_error, "Connection replenishment task failed");
                self.try_serve_waiters();
            }
        }
    }

    /// トランザクション後始末タスクの完了を処理する。
    fn handle_cleanup_result(
        &mut self,
        result: std::result::Result<
            std::result::Result<ManagedConnection, DiscardReason>,
            JoinError,
        >,
    ) {
        self.cleaning = self.cleaning.saturating_sub(1);

        match result {
            Ok(Ok(conn)) => match conn.check(self.generation) {
                Ok(()) => self.offer(conn),
                Err(reason) => self.discard_connection(conn, reason),
            },
            Ok(Err(reason)) => self.record_closed(reason),
            Err(join_error) => {
                tracing::error!(error = %join_error, "Connection cleanup task failed");
                self.record_closed(DiscardReason::RollbackFailed);
            }
        }

        self.try_serve_waiters();
        self.maybe_replenish();
    }

    /// 接続破棄タスクの完了を処理する。
    fn handle_closer_result(&mut self, result: std::result::Result<(), JoinError>) {
        self.closing = self.closing.saturating_sub(1);
        self.closed_total += 1;
        if let Err(join_error) = result {
            tracing::error!(error = %join_error, "Connection close task failed");
        }
        self.try_serve_waiters();
        self.maybe_replenish();
    }

    /// 接続をすべて破棄し、プールを開いたままにする。
    fn reset(&mut self) {
        let connections = {
            let mut idle = self.shared.lock_idle();
            self.generation += 1;
            if let Some(inner) = self.inner.upgrade() {
                inner.generation.store(self.generation, Ordering::Release);
            }
            std::mem::take(&mut idle.connections)
        };
        self.replenishment_paused = false;
        for conn in connections {
            self.discard_connection(conn, DiscardReason::Reset);
        }
        self.try_serve_waiters();
        self.maybe_replenish();
        tracing::debug!("Connection pool reset");
    }

    /// プールを停止する。
    async fn shutdown(&mut self) {
        let waiters = {
            let mut idle = self.shared.lock_idle();
            let waiters = self.waiting.drain(..).collect::<Vec<_>>();
            idle.waiting = 0;
            waiters
        };
        for mut waiter in waiters {
            self.finish_wait(&mut waiter, Instant::now());
            let _ = waiter
                .reply
                .send(Err(Error::interface("Connection pool is closed")));
        }

        let connections = {
            let mut idle = self.shared.lock_idle();
            idle.connections.drain(..).collect::<Vec<_>>()
        };
        for conn in connections {
            self.discard_connection(conn, DiscardReason::Shutdown);
        }
        while self.closers.join_next().await.is_some() {
            self.closing = self.closing.saturating_sub(1);
            self.closed_total += 1;
        }

        // 進行中の接続確立・後始末を中止して待つ。
        self.connectors.shutdown().await;
        self.replenishers.shutdown().await;
        self.cleanups.shutdown().await;

        tracing::info!("Connection pool shutting down");
    }
}

/// タイムアウトやキャンセルの時刻は、マネージャがそれを検知した時刻とは異なる。
fn record_capacity_wait(waiter: &mut Waiter, end: Instant, total: &mut Duration) {
    if let Some(start) = waiter.queued_at.take() {
        let end = waiter.canceled_at.try_recv().map_or(end, |at| at.min(end));
        *total = total.saturating_add(end.saturating_duration_since(start));
    }
}

/// 接続を確立し、確立直後のフックまで実行する。
///
/// フックは接続の確立元タスクで実行する。ここでエラーになった接続は
/// プールに戻さず、初期化に失敗した接続として破棄する。
async fn establish_connection(
    mut options: ConnectOptions,
    connector: Option<Connector>,
    before_connect: Option<BeforeConnectHook>,
    after_connect: Option<ConnectionHook>,
    lifetime: Duration,
    generation: u64,
) -> Result<ManagedConnection> {
    if let Some(hook) = before_connect {
        hook(&mut options);
    }
    let mut conn = match connector {
        Some(connector) => connector(options).await?,
        None => Connection::connect(options).await?,
    };
    let created_at = Instant::now();
    if let Some(hook) = after_connect
        && let Err(error) = hook(&mut conn).await
    {
        tracing::debug!(error = %error, "after_connect hook rejected a new pooled connection");
        conn.force_close();
        return Err(error);
    }
    Ok(ManagedConnection {
        conn: Box::new(conn),
        created_at,
        lifetime,
        generation,
        idle_since: None,
    })
}

/// 返却された接続のセッション状態を初期化する。
///
/// `DISCARD ALL` はプリペアドステートメントも破棄するため、
/// サーバー側の状態を消した後でクライアント側の文キャッシュも消す。
async fn reset_connection_session(
    conn: &mut Connection,
    recycling: &RecyclingMethod,
) -> Result<()> {
    match recycling {
        RecyclingMethod::Fast => Ok(()),
        RecyclingMethod::Clean => {
            // PostgreSQL 18 公式文書の DISCARD にあるとおり、DISCARD ALL は
            // トランザクションブロック内では実行できない。呼び出し前に
            // トランザクションをロールバックしておく。
            match tokio::time::timeout(CLEANUP_TIMEOUT, conn.query("DISCARD ALL", false)).await {
                Ok(Ok(_)) => {
                    conn.clear_statement_cache();
                    Ok(())
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(Error::operational("Timed out discarding the session state")),
            }
        }
        RecyclingMethod::Custom(hook) => {
            match tokio::time::timeout(CLEANUP_TIMEOUT, hook(conn)).await {
                Ok(result) => result,
                Err(_) => Err(Error::operational("Timed out resetting the session state")),
            }
        }
    }
}

fn unusable_connection_error(reason: DiscardReason) -> Error {
    Error::interface(format!("New pooled connection is not usable ({reason:?})"))
}

/// アイドル接続をまとめて閉じる。
async fn close_idle_connections(
    idle: VecDeque<ManagedConnection>,
    before_close: Option<BeforeCloseHook>,
) {
    let mut closers = JoinSet::new();
    for idle_conn in idle {
        closers.spawn(close_connection(idle_conn.conn, before_close.clone()));
    }
    while closers.join_next().await.is_some() {}
}

/// 接続を閉じる。
async fn close_connection(mut conn: Box<Connection>, before_close: Option<BeforeCloseHook>) {
    if let Some(hook) = before_close {
        hook(&mut conn);
    }
    if conn.is_busy()
        || !matches!(
            conn.transaction_status(),
            transaction_status::IDLE
                | transaction_status::IN_TRANSACTION
                | transaction_status::FAILED
        )
    {
        // 未完了の通信に Terminate を足さず、ソケットをそのまま閉じる。
        conn.force_close();
        return;
    }
    match tokio::time::timeout(CLOSE_TIMEOUT, conn.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(error = %error, "Failed to close a pooled connection"),
        Err(_) => tracing::debug!("Timed out closing a pooled connection"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 統計の確定が遅れても、枠待ちにキャンセル後の時間を加えない。
    #[test]
    fn test_capacity_wait_uses_cancellation_instant() {
        let (reply, _rx) = oneshot::channel();
        let (cancel, canceled_at) = oneshot::channel();
        let started = Instant::now();
        let mut waiter = Waiter {
            reply,
            canceled_at,
            queued_at: Some(started),
        };
        let elapsed = Duration::from_millis(25);
        cancel
            .send(started + elapsed)
            .expect("キャンセル時刻を送信できませんでした");
        let mut total = Duration::ZERO;
        let detected_at = started + Duration::from_secs(1);

        record_capacity_wait(&mut waiter, detected_at, &mut total);
        assert_eq!(
            total, elapsed,
            "キャンセルの検出遅れが枠待ち時間に加算されました"
        );
        record_capacity_wait(&mut waiter, detected_at, &mut total);
        assert_eq!(total, elapsed, "同じ枠待ち時間が重複計上されました");
    }

    /// 設定の検証が不正な値を拒否することを確認する。
    #[test]
    fn test_validate_config_rejects_invalid_values() {
        let max_size_zero = PoolConfig {
            max_size: 0,
            ..Default::default()
        };
        assert!(
            validate_config(&max_size_zero).is_err(),
            "max_size が 0 の設定が受け入れられました"
        );

        let min_idle_too_large = PoolConfig {
            max_size: 2,
            min_idle: 3,
            ..Default::default()
        };
        assert!(
            validate_config(&min_idle_too_large).is_err(),
            "min_idle が max_size を超える設定が受け入れられました"
        );

        let min_size_too_large = PoolConfig {
            max_size: 2,
            min_size: 3,
            ..Default::default()
        };
        assert!(
            validate_config(&min_size_too_large).is_err(),
            "min_size が max_size を超える設定が受け入れられました"
        );

        let health_check_zero = PoolConfig {
            health_check_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(
            validate_config(&health_check_zero).is_err(),
            "health_check_interval が 0 の設定が受け入れられました"
        );
    }

    /// 寿命のジッターが設定範囲に収まることを確認する。
    #[test]
    fn test_connection_lifetime_applies_jitter() {
        let config = PoolConfig {
            max_lifetime: Duration::from_secs(10),
            max_lifetime_jitter: Duration::from_secs(2),
            ..Default::default()
        };
        for index in 0..32 {
            let lifetime = connection_lifetime(&config, index);
            assert!(
                lifetime >= config.max_lifetime,
                "寿命が最大生存時間を下回りました"
            );
            assert!(
                lifetime <= config.max_lifetime + config.max_lifetime_jitter,
                "寿命が最大生存時間とジッターの合計を超えました"
            );
        }

        let no_jitter = PoolConfig {
            max_lifetime: Duration::from_secs(10),
            ..Default::default()
        };
        assert_eq!(
            connection_lifetime(&no_jitter, 0),
            Duration::from_secs(10),
            "ジッターなしの寿命が最大生存時間と一致しません"
        );
    }

    /// 接続を作らない設定でも統計の取得と停止ができることを確認する。
    #[tokio::test]
    async fn test_stat_and_close_without_connections() {
        let config = PoolConfig {
            max_size: 4,
            min_idle: 0,
            min_size: 0,
            ..Default::default()
        };
        let pool = Pool::start(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert_eq!(stat.max_size, 4, "最大接続数が一致しません");
        assert_eq!(stat.total, 0, "接続数が一致しません");
        assert_eq!(stat.idle, 0, "アイドル接続数が一致しません");
        assert_eq!(stat.active, 0, "貸出中の接続数が一致しません");
        assert_eq!(stat.waiting, 0, "待機中の要求数が一致しません");
        assert_eq!(stat.acquired_total, 0, "貸出数の合計が一致しません");
        assert_eq!(
            stat.acquire_timeout_total, 0,
            "取得タイムアウト数が一致しません"
        );
        assert_eq!(
            stat.acquire_duration_total,
            Duration::ZERO,
            "取得時間の合計が一致しません"
        );
        assert_eq!(stat.created_total, 0, "確立した接続数が一致しません");
        assert_eq!(stat.closed_total, 0, "破棄した接続数が一致しません");

        pool.close().await.expect("プールの停止に失敗しました");

        // 停止後は新しい接続を取得できないこと。
        let result = pool.acquire().await;
        assert!(result.is_err(), "停止したプールから接続を取得できました");
    }

    /// 停止が冪等であることを確認する。
    #[tokio::test]
    async fn test_close_is_idempotent() {
        let config = PoolConfig {
            max_size: 2,
            min_idle: 0,
            ..Default::default()
        };
        let pool = Pool::start(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        pool.close().await.expect("1 回目の停止に失敗しました");
        pool.close()
            .await
            .expect("2 回目の停止でエラーになりました");
    }

    /// 設定を取得できることを確認する。
    #[tokio::test]
    async fn test_config_is_available() {
        let config = PoolConfig {
            max_size: 3,
            min_idle: 0,
            ..Default::default()
        };
        let pool = Pool::start(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        let config = pool.config();
        assert_eq!(config.max_size, 3, "最大接続数が一致しません");
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 接続を確立しない遅延起動ができることを確認する。
    #[tokio::test]
    async fn test_start_lazy_without_connections() {
        let config = PoolConfig {
            max_size: 2,
            min_idle: 0,
            ..Default::default()
        };
        let pool = Pool::start_lazy(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        let stat = pool.stat().await.expect("統計の取得に失敗しました");
        assert_eq!(stat.total, 0, "接続数が一致しません");
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 接続がない場合に try_acquire が None を返すことを確認する。
    #[tokio::test]
    async fn test_try_acquire_without_connections() {
        let config = PoolConfig {
            max_size: 2,
            min_idle: 0,
            ..Default::default()
        };
        let pool = Pool::start(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        let lease = pool.try_acquire().await.expect("即時取得に失敗しました");
        assert!(lease.is_none(), "接続がないのに即時取得できました");
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 接続がない状態でもリセットできることを確認する。
    #[tokio::test]
    async fn test_reset_without_connections() {
        let config = PoolConfig {
            max_size: 2,
            min_idle: 0,
            ..Default::default()
        };
        let pool = Pool::start(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        pool.reset().await.expect("リセットに失敗しました");
        pool.close().await.expect("プールの停止に失敗しました");
    }

    /// 貸出中の接続がない場合、close_with_timeout が待たずに完了することを確認する。
    #[tokio::test]
    async fn test_close_with_timeout_without_leases() {
        let config = PoolConfig {
            max_size: 2,
            min_idle: 0,
            ..Default::default()
        };
        let pool = Pool::start(ConnectOptions::default(), config)
            .await
            .expect("プールの生成に失敗しました");

        pool.close_with_timeout(Duration::from_secs(1))
            .await
            .expect("プールの停止に失敗しました");
    }
}
