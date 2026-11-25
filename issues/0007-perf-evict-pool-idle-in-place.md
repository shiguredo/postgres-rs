# PoolManager::evict_idle をインプレース選別に変更する

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/refactor-pool-evict-idle-in-place
- Polished: {YYYY-MM-DD}

## 目的

定期ヘルスチェック時の不要なヒープ割り当てと時刻取得を削減し、点検中に健全なアイドル接続が一時的にキューから消失して高速取得がミスする問題を解消する。

## 現状

`postgres/src/pool.rs` の `PoolManager::evict_idle` は `health_check_interval` ごとに以下の処理を行っている。

- `std::mem::take(&mut idle.connections)` でアイドル接続をすべて抜き出してロックを解放するため、点検が終わるまで `idle.connections` が一時的に空になり、その間の `Pool::try_fast_acquire` が健全な接続があるにもかかわらずスローパスへフォールバックする
- 毎回 `VecDeque::with_capacity(connections.len())` を新規確保して全要素を移し替え、さらに逆順で `push_front` し直している
- ループ内の各接続で `ManagedConnection::check_idle` を通じて `created_at.elapsed()` と `idle_since.elapsed()` を毎回呼び出している

## 設計方針

- 点検開始時に 1 回だけ `now = Instant::now()` を取得する
- `PoolShared::lock_idle` のロック下で `idle.connections` をインプレース選別し、破棄対象の接続だけをローカルの `Vec::new()` へ移す（破棄対象がない通常時はヒープ割り当てゼロ）
- ロックを解放した後、破棄対象の接続に対して `PoolManager::discard_connection` を呼ぶ
- 健全な接続の順序をそのまま維持する

## 完了条件

- `PoolManager::evict_idle` がアイドル接続をキューから一時的に全撤去せず、破棄対象がない場合にヒープ割り当てを行わないこと
- 時刻取得が 1 回の点検につき 1 回になること
- 寿命切れ・アイドル期限切れ・点検時の既存および新規テストがすべて通ること
