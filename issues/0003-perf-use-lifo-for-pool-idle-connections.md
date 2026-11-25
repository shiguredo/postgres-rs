# プールのアイドル接続取得を FIFO から LIFO に変更する

- Created: 2026-11-25
- Completed: {YYYY-MM-DD}
- Branch: feature/change-pool-idle-lifo
- Polished: {YYYY-MM-DD}

## 目的

アイドル接続の再利用効率を高め、不要な生存確認 (`Connection::ping`) の発生を抑えるとともに、プリペアドステートメントキャッシュのヒット率向上と余剰アイドル接続の自然な縮退を実現する。

## 現状

`postgres/src/pool.rs` では `PooledConnection::try_fast_release` と `PoolManager::offer` が `idle.connections.push_back` で末尾へ返却し、`Pool::try_fast_acquire` と `PoolManager::take_idle_lease` が `idle.connections.pop_front` で先頭から取り出す FIFO 構造になっている。

アイドル接続が複数存在する低〜中負荷のワークロードでは、毎回最も古くアイドル状態だった接続が選ばれるため、以下の性能劣化が起きる。

- 1 本の接続が巡回するまでの経過時間が `PING_AFTER_IDLE` を超えやすくなり、不要なネットワーク 1 RTT の `Connection::ping` が繰り返し発生する
- クエリが全接続へ薄く分散するため、`Connection` ごとの自動プリペアドステートメントキャッシュやサーバー側のキャッシュ効率が低下する
- 負荷が低下しても全接続の `idle_since` が更新され続けるため、`PoolConfig::max_idle_time` による余剰アイドル接続の縮退が機能しにくい

## 設計方針

- `Pool::try_fast_acquire` と `PoolManager::take_idle_lease` の取り出しを `idle.connections.pop_back` に変更し、直近まで使われていた接続を優先再利用する LIFO 方式にする
- `PoolManager::evict_idle` で残存接続を戻す際も、末尾側ほど `idle_since` が新しい順序を保つようにする

## 完了条件

- アイドル接続の取得が LIFO で動作し、定常負荷で不要な `Connection::ping` が抑えられること
- 負荷低下時に余剰のアイドル接続の `idle_since` が更新されず、`PoolConfig::max_idle_time` 経過後に破棄されることをテストで確認できること
- 既存のプールテストがすべて通ること
