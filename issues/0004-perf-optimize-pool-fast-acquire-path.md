# プール高速取得経路の時刻取得・重複検査・フォールバックを削減する

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/refactor-pool-fast-acquire
- Polished: {YYYY-MM-DD}

## 目的

アイドル接続が存在する最速の取得・返却パスにおいて、不要な時刻取得、重複する健全性検査、タイマー構造体の生成、および単一の期限切れ接続によるスローパスへのフォールバックを削減し、ホットパスのレイテンシを短縮する。

## 現状

`postgres/src/pool.rs` の高速取得・返却パス（`Pool::acquire_with_timeout` → `Pool::acquire_with_retry` → `Pool::try_fast_acquire` → `Pool::make_fast_lease` および `PooledConnection::try_fast_release`）では、1 往復の間に以下の無駄が発生している。

- `tokio::time::timeout` の期限計算、`Pool::acquire_with_retry` の `started` 計測、`ManagedConnection::check` / `ManagedConnection::check_idle` の `elapsed()`、直後の重複した `Pool::check_lease`、`PING_AFTER_IDLE` 判定、経過時間加算、`PooledConnection::try_fast_release` の検査と `idle_since` 記録により、1 往復で最大 9 回の `Instant::now` / `elapsed` が呼ばれる
- `Pool::make_fast_lease` で `ManagedConnection::check_idle` を通過した直後に、`Pool::acquire_with_retry` が `await` を挟まず `Pool::check_lease` を再実行している
- `Pool::try_fast_acquire` はキューから取り出した 1 本が期限切れだっただけで `PoolRequest::DiscardIdle` を送って即 `None` を返すため、他に健全なアイドル接続が残っていても `Pool::request_connection` や `PoolRequest::TryAcquire` のスローパスへフォールバックする
- `PING_AFTER_IDLE` 未満かつ `on_acquire` 未設定で同期的に取得できる場合でも、毎回 `tokio::time::timeout` を構築している

## 設計方針

- `ManagedConnection` に接続作成時に計算した `expires_at: Instant` を保持し、`ManagedConnection::check` と `ManagedConnection::check_idle` が呼び出し元から単一の `now: Instant` を受け取るように変更する
- 高速経路で直前に `ManagedConnection::check_idle` を通過した直後の重複 `Pool::check_lease` を省略する（マネージャ経由の取得や `ping` / `on_acquire` 実行後の再検査は維持する）
- `Pool::try_fast_acquire` 内で期限切れや無効なアイドル接続を `PoolRequest::DiscardIdle` に回しつつ、次の健全なアイドル接続が見つかるまでループする
- `acquire_timeout` が 0 でない場合に、同期的に完了できる高速取得（`ping` 不要かつ `on_acquire` 未設定）は `tokio::time::timeout` の生成前に完了できるようにする

## 完了条件

- 高速取得・返却 1 往復あたりの時刻取得回数と重複検査が削減され、期限切れ接続の後ろに健全なアイドル接続がある場合にマネージャへフォールバックしないこと
- ベンチマークで高速経路のレイテンシ改善を確認できること
- 寿命切れ・アイドル期限切れ・リセット・停止・タイムアウトに関する既存および新規テストがすべて通ること
