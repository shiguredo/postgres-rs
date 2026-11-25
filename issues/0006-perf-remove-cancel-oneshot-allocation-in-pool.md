# プール待機要求のキャンセル通知用 oneshot 割り当てを削減する

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/refactor-pool-cancel-tracking
- Polished: {YYYY-MM-DD}

## 目的

プール取得がスローパスに入った際のヒープ割り当てを削減し、キャンセルされていない大多数の待機要求でのオーバーヘッドを抑える。

## 現状

`postgres/src/pool.rs` の `Pool::request_connection` は、マネージャからの応答を受け取る `reply` に加え、`AcquireCancellation` が取得 Future の破棄時刻を `record_capacity_wait` へ伝えるためだけに 2 本目の `oneshot::channel()` (`canceled_at`) を毎回確保している。

取得がキャンセルされるのは例外的なケースであるにもかかわらず、スローパスを通るすべての取得試行で追加の `oneshot::channel` の確保・解放が発生している。

## 設計方針

- `canceled_at` 用の `oneshot::channel()` を廃止し、枠待ちの開始時刻と確定状態（未登録・待機中・計上済み）を完了側とキャンセル側で共有する軽量な状態（または `PoolInner` 側の `AtomicU64` への加算）へ置き換える
- 完了側と `AcquireCancellation::drop` が競合しても、先着 1 回だけが `capacity_wait_duration_total` に加算し、二重計上も計上漏れも起きないことを保証する

## 完了条件

- `Pool::request_connection` が `canceled_at` 用の `oneshot::channel()` を確保しなくなること
- `test_capacity_wait_uses_cancellation_instant` や `test_capacity_wait_counts_only_queued_acquisitions` を含む枠待ち計測テストがすべて通ること
