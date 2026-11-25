# PoolManager の pop_waiter で待機者の追い越し・横取りが起きるウィンドウを修正する

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/fix-pool-waiter-overtaking
- Polished: {YYYY-MM-DD}

## 目的

コネクションプールの待機キューにおける FIFO の取得順序保証を回復し、先頭待機者が後続タスクや高速経路によって追い越される並行性バグを修正する。

## 現状

`postgres/src/pool.rs` の `PoolManager::pop_waiter` は、`PoolShared::lock_idle` のロック下で `self.waiting.pop_front()` を実行し、`idle.waiting = self.waiting.len()` を更新してからロックを解放している。その後 `PoolManager::try_serve_waiters` が `PoolManager::try_dispatch` に失敗して `PoolManager::push_waiting_front` で待機者を先頭へ戻すまでの間に、`idle.waiting` が一時的に `0` になるウィンドウが存在する。

このウィンドウ中に別タスクで `PooledConnection::try_fast_release` や `Pool::try_fast_acquire` が実行されると、`idle.waiting == 0` と誤認して高速経路が走り、待機者が存在しているにもかかわらず後続タスクが接続を横取りできる。

さらに `PoolManager::handle_acquire` は、`PoolManager::try_serve_waiters` が先頭待機者をディスパッチできずに `self.waiting` が非空のまま戻った直後にも、新規の `waiter` に対して `PoolManager::try_dispatch` を呼び出しており、先頭待機者を追い越す経路が残っている。

## 設計方針

- `PoolManager::try_serve_waiters` で待機者をロック外へ一時退避させず、単一ロック下で先頭待機者を確認しながらアイドル接続または新規接続枠の有無を判定し、ディスパッチが確定したときだけ先頭待機者を消費する
- `PoolManager::pop_waiter` 内のキャンセル済み待機者の読み飛ばしも同一ロック内で完了させ、途中で `idle.waiting` を不整合にしない
- `PoolManager::handle_acquire` で `self.waiting` が非空のときは新規 `waiter` への `PoolManager::try_dispatch` を行わず、末尾へ追加する

## 完了条件

- 待機者が存在する状態で `PooledConnection::try_fast_release`・`Pool::try_fast_acquire`・後続 `PoolRequest::Acquire` が先頭待機者を追い越さないこと
- 既存の `postgres/tests/test_pool.rs` およびユニットテストがすべて通ること
- 待機者存在時の FIFO 順序と競合時の挙動を検証するテストが追加され通ること
