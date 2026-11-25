# プール飽和時のロック回数削減と待機者への直接受け渡しを導入する

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/refactor-pool-saturation-handoff
- Polished: {YYYY-MM-DD}

## 目的

コネクションプールが `max_size` に達して待機者が存在する飽和時のスループットとレイテンシを改善する。

## 現状

`postgres/src/pool.rs` の飽和時（`waiting > 0`、`idle == 0`、`total == max_size`）の処理では、`PoolShared::lock_idle` の取得・解放が過剰に分割されている。

- `PoolManager::handle_acquire` は `PoolManager::try_serve_waiters`、`PoolManager::try_dispatch`（内部で `PoolManager::take_idle_lease` と `PoolManager::total` を個別にロック）、`PoolManager::push_waiting_back`、再度の `PoolManager::try_serve_waiters`、さらに呼び出し元の `PoolManager::run` における `PoolManager::maybe_replenish` まで含め、1 件の `PoolRequest::Acquire` 処理で多数回ロックを繰り返す
- `PoolManager::handle_release` でも、`PoolManager::offer` で待機者へ接続を渡した後に空の `PoolManager::try_serve_waiters` と `PoolManager::maybe_replenish` で再度ロックを取得する
- `PoolManager::maybe_replenish` はループの各反復ごとに `PoolShared::lock_idle` を取り直している
- `waiting > 0` の間は `PooledConnection::try_fast_release` が常にマネージャ経由の `PoolRequest::Release` にフォールバックするため、返却タスク → マネージャタスク → 待機タスクの 2 回のコンテキストスイッチが発生し、単一のマネージャタスクがホットパスのボトルネックになる

## 設計方針

- `PoolManager::try_dispatch`・`PoolManager::try_serve_waiters`・`PoolManager::maybe_replenish` の分割ロックを統合し、必要な本数やディスパッチ可否を最小限のロック回数で判定する
- 待機者キューを `IdleState` の保護下へ移し、`PooledConnection::try_fast_release` が健全な接続（フック・後始末が不要かつ `RecyclingMethod::Fast`）を返却するとき、生きている先頭待機者の `oneshot::Sender` へマネージャタスクを経由せず直接受け渡し（Direct Handoff）できるようにする
- 直接受け渡しの送信直前に待機者がキャンセルされて `send` が失敗した場合は、次の生きている待機者へ引き継ぐか、待機者がいなければアイドルキューへの返却または停止時の破棄を行い、接続数会計 (`total <= max_size`) と `Pool::close_with_timeout` の物理クローズ保証を崩さない

## 完了条件

- 飽和時 1 往復あたりの `PoolShared::lock_idle` 呼び出し回数とコンテキストスイッチ回数が削減されること
- 飽和時の取得・返却を計測するベンチマークでスループットおよびレイテンシの改善を確認できること
- `Pool::close_with_timeout`・`Pool::reset`・キャンセル競合を含む全テストが通ること
