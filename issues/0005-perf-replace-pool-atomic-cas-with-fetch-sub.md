# プールの active / lease_count デクリメントを CAS ループから fetch_sub に置き換える

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/refactor-pool-atomic-fetch-sub
- Polished: {YYYY-MM-DD}

## 目的

高競合時の `PoolShared::active` および `PoolInner::lease_count` の更新における CAS リトライをなくし、単一のアトミック命令で貸出・返却の会計を更新できるようにする。

## 現状

`postgres/src/pool.rs` では、アンダーフロー防止のために以下の 4 箇所で `AtomicUsize::try_update` による CAS ループを使用している。

- `PoolInner::lease_released`
- `PooledConnection::try_fast_release`
- `Pool::try_fast_acquire` 内の `PoolRequest::DiscardIdle` 送信失敗時のロールバック
- `PoolManager::release_active`

マルチスレッドで取得・返却が競合すると CAS ループがリトライを繰り返し、単一命令の `fetch_sub(1, Ordering::AcqRel)` と比べてオーバーヘッドが大きくなる。また `Pool::try_fast_acquire` では `self.inner.shared.active.fetch_add(1, Ordering::AcqRel)` の戻り値を使わず、直後に再度 `self.inner.shared.active.load(Ordering::Acquire)` を呼び出している。

## 設計方針

- `PoolShared::active` が常に「未解放の `PooledConnection` 数 (`lease_count`) + 未処理の `PoolRequest::DiscardIdle` 数 + 未処理の `PoolRequest::Release` / `PoolRequest::Discard` 数」と一致する会計不変条件を維持した上で、4 箇所の `try_update` を `fetch_sub(1, Ordering::AcqRel)` に置き換える
- 異常時の防御としてデバッグビルド用の不変条件アサーション（`debug_assert!(previous > 0)`）を添える
- `Pool::try_fast_acquire` の重複する `active.load` を削除し、`fetch_add` の戻り値から `active` を算出する

## 完了条件

- `postgres/src/pool.rs` から `active` / `lease_count` に対する `try_update` CAS ループと `try_fast_acquire` の重複 `active.load` が除去されていること
- 高並行取得・返却・破棄・停止競合を含む全テストが通り、ベンチマークで競合時の性能劣化がない（または改善する）こと
