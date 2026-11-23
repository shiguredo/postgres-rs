# postgres-rs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

> [!WARNING]
> このライブラリは開発中であり、仕様が積極的に変更される場合があります。

## 概要

`postgres-rs` は PostgreSQL クライアントの Rust 実装です。

- `shiguredo_postgres` - tokio 上で動作する非同期 PostgreSQL クライアント
- `shiguredo_postgres_core` - Sans I/O な PostgreSQL プロトコル実装

PostgreSQL 16 / 17 / 18 / 19 で動作を確認しています。

## 主な機能

- 単純クエリプロトコル
- 拡張クエリプロトコル
  - パラメーター付きクエリ
  - パラメーターの型 OID の明示
- 接続に紐付くプリペアドステートメント
  - 容量制限付きキャッシュ
  - 実行前の失効時の自動再準備
- 名前付きステートメントを作らない 1 往復のパラメーター付きクエリ
- 行の取得
  - 行の逐次取得
  - 行数の検査付き取得 (`query_one` / `query_opt`)
  - すべての行の取得 (`query_all`)
  - 列番号・列名からの型付き取得 (`Row`)
  - 配列の `Vec<T>` / `Vec<Option<T>>` での取得 (多次元は入れ子の `Vec`)
- バッチクエリ
  - 複数ステートメントを 1 往復で送信
  - ステートメントごとの結果セット取得
- 複数結果セット
  - 単純クエリでの複数ステートメント
- COPY プロトコル
  - CopyIn
  - CopyOut
- LISTEN / NOTIFY
- トランザクション
  - セーブポイント
  - 自動ロールバック
- コネクションプール
  - Ping による生存確認
  - 最小接続の維持
  - 統計取得
  - リセット
  - セッションの初期化 (`DISCARD ALL`)
  - 接続生成処理の差し替え
- 接続ライフサイクルのフック
  - 確立前
  - 確立後 (非同期)
  - 貸出前 (非同期、拒否可能)
  - 返却後 (非同期)
  - 解放時
  - クローズ前
- クエリタイムアウト
  - サーバー側キャンセル
  - 別タスクからのキャンセル (`CancelToken`)
- 接続設定
  - 起動パラメーター (`search_path` 等)
  - 起動時のコマンドラインオプション (`options`。接続文字列と URL でも指定できる)
  - TCP キープアライブ (既定で有効) と `tcp_user_timeout`
- 認証
  - SCRAM-SHA-256
  - サーバー側で認証要求を省略する方式
  - ローカル開発用の平文パスワード
  - OAuth
    - OAUTHBEARER
    - PostgreSQL 18 以降
    - 検証済み TLS が必須
- TLS
  - 既定は `sslmode=verify-full`
  - 開発用の平文接続は明示指定
- Unix ドメインソケット
- 接続文字列
  - libpq 形式
  - `postgres://` URL
- 型変換: 数値 / 浮動小数 / 日付時刻 / NUMERIC / UUID / JSON / JSONB / 配列 / bytea / oid8 (PostgreSQL 19 以降) 等

対応しない機能とその理由は [意図的に実装しない機能](docs/unsupported-features.md) を参照してください。

## 使い方

### 単一接続

以下はローカル開発向けの例です。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection, SslMode};
use shiguredo_postgres::converters::Value;
use shiguredo_postgres::cursor::Cursor;

#[tokio::main]
async fn main() {
    let options = ConnectOptions {
        host: "127.0.0.1".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("mydb".to_string()),
        ssl_mode: SslMode::Disabled,
        ..Default::default()
    };

    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");
    let mut cursor = Cursor::new(&mut conn);

    // パラメーター付きクエリ
    cursor
        .execute(
            "SELECT id, name FROM users WHERE age > $1",
            &[Value::Int4(20)],
        )
        .await
        .expect("クエリの実行に失敗しました");

    for row in cursor.fetch_all().expect("結果の取得に失敗しました") {
        println!("{:?}", row);
    }

    conn.close().await.expect("接続のクローズに失敗しました");
}
```

接続文字列 (libpq 形式) や URL から接続することもできます。

```rust
let options = ConnectOptions::from_conninfo(
    "host=127.0.0.1 port=5432 user=postgres password=password dbname=mydb sslmode=disable",
)
.expect("接続文字列の解析に失敗しました");

let options = ConnectOptions::from_url(
    "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
)
.expect("接続文字列の解析に失敗しました");
```

### プリペアドステートメント

`execute` は同じ SQL の文をキャッシュします。一度だけの SQL には `execute_uncached` を使います。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::Value;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    // ステートメントキャッシュ: 同じ SQL は 2 回目以降に再パースされない
    conn.execute("SELECT $1::int", &[Value::Int4(1)], false)
        .await
        .expect("クエリの実行に失敗しました");

    // 明示的な準備と実行
    let statement = conn.prepare("SELECT $1::int + $2::int").await.expect("プリペアドステートメントの準備に失敗しました");
    conn.execute_prepared(&statement, &[Value::Int4(1), Value::Int4(2)], false)
        .await
        .expect("クエリの実行に失敗しました");
    conn.deallocate(&statement).await.expect("準備済みの文を解放できません");
}
```

### 行の逐次取得

`unbuffered = true` を渡すと `next_row` で 1 行ずつ取得できます。

```rust
conn.execute_uncached("SELECT generate_series(1, $1::int)", &[Value::Int4(100_000)], true)
    .await?;
while let Some(row) = conn.next_row().await? {
    println!("{row:?}");
}
```

### トランザクション

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::Value;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    let mut tx = conn.begin().await.expect("トランザクションの開始に失敗しました");
    tx.execute(
        "INSERT INTO users (name) VALUES ($1)",
        &[Value::Text("alice".to_string())],
    )
    .await
    .expect("クエリの実行に失敗しました");
    // エラー時は tx.rollback()、または commit / rollback せずに
    // 破棄すると次の begin() で自動的にロールバックされる
    tx.commit().await.expect("コミットに失敗しました");

    // セーブポイント
    let mut tx = conn.begin().await.expect("トランザクションの開始に失敗しました");
    tx.execute("UPDATE users SET name = 'bob'", &[]).await.expect("クエリの実行に失敗しました");
    tx.savepoint("sp1").await.expect("セーブポイントの作成に失敗しました");
    tx.execute("DELETE FROM users", &[]).await.expect("クエリの実行に失敗しました");
    tx.rollback_to_savepoint("sp1").await.expect("セーブポイントへのロールバックに失敗しました");
    tx.commit().await.expect("コミットに失敗しました");
}
```

### バッチクエリ

複数のステートメントを 1 往復で送信します。

```rust
use shiguredo_postgres::batch::Batch;
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::Value;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    let mut batch = Batch::new();
    batch.append("INSERT INTO users (name) VALUES ($1)", &[Value::Text("a".to_string())]);
    batch.append("INSERT INTO users (name) VALUES ($1)", &[Value::Text("b".to_string())]);
    batch.append("SELECT COUNT(*) FROM users", &[]);

    // ステートメントごとの結果 (影響行数またはエラー) が返る
    let results = conn.batch_execute(batch).await.expect("バッチの実行に失敗しました");
}
```

### COPY

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    // CopyIn
    conn.copy_in(
        "COPY users (name) FROM STDIN",
        b"alice\nbob\ncherry\n",
    )
    .await
    .expect("COPY の実行に失敗しました");

    // CopyOut
    let data = conn
        .copy_out("COPY users (name) TO STDOUT")
        .await
        .expect("COPY の実行に失敗しました");
}
```

### LISTEN / NOTIFY

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    conn.query("LISTEN channel_name", false).await.expect("クエリの実行に失敗しました");

    // 通知を待つ (事前に別の接続から NOTIFY を送っておく)
    let notification = conn.next_notification().await.expect("通知の取得に失敗しました");
    println!("channel={} payload={}", notification.channel, notification.payload);
}
```

### クエリタイムアウト

タイムアウトするとサーバーにキャンセル要求を送ります。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::Value;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    let result = conn
        .query_with_timeout("SELECT pg_sleep(10)", false, Duration::from_secs(1))
        .await;
    assert!(result.is_err());

    // 回復できた接続だけを再利用する。
    if conn.is_open() && !conn.is_busy() {
        conn.ping().await.expect("Ping に失敗しました");
    }
}
```

### OAuth 認証

PostgreSQL 18 以降の OAuth 認証に対応しています。トークンの取得は利用者が行います。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};

#[tokio::main]
async fn main() {
    // 静的なトークンで接続する場合。
    let options = ConnectOptions {
        oauth_token: Some("access-token".to_string()),
        ..ConnectOptions::from_url("postgres://user@db.example.com/mydb?sslmode=verify-full")
            .expect("接続文字列の解析に失敗しました")
    };
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    // トークンプロバイダ付きで接続する場合。
    // トークンが拒否されたときに新しいトークンを取得して再接続する。
    let options = ConnectOptions {
        oauth_token: Some("initial-token".to_string()),
        ..ConnectOptions::from_url("postgres://user@db.example.com/mydb?sslmode=verify-full")
            .expect("接続文字列の解析に失敗しました")
    };
    let mut conn = Connection::connect_with_oauth(options, || {
        // ここで OAuth 2.0 / OIDC フロー (リフレッシュ等) を行い、
        // 新しいアクセストークンを返す。
        async { Ok("new-access-token".to_string()) }
    })
    .await
    .expect("OAuth 接続に失敗しました");
}
```

### 非同期並列クエリ

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection, SslMode};
use shiguredo_postgres::cursor::Cursor;

#[tokio::main]
async fn main() {
    let options = ConnectOptions {
        host: "127.0.0.1".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("mydb".to_string()),
        ssl_mode: SslMode::Disabled,
        ..Default::default()
    };

    // 複数の接続を並列に確立してクエリを実行する
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let opts = options.clone();
            tokio::spawn(async move {
                let mut conn = Connection::connect(opts).await.expect("接続に失敗しました");
                let mut cursor = Cursor::new(&mut conn);
                cursor
                    .query(&format!("SELECT {} AS num", i))
                    .await
                    .expect("クエリの実行に失敗しました");
                let rows = cursor.fetch_all().expect("結果の取得に失敗しました");
                rows[0][0].clone()
            })
        })
        .collect();

    for handle in handles {
        println!("{:?}", handle.await.expect("タスクの実行に失敗しました"));
    }
}
```

### コネクションプール

既定の `RecyclingMethod::Fast` は未完了のトランザクションをロールバックするだけで、
`SET`、一時テーブル、`LISTEN` などのセッション状態は次の利用者に持ち越されます。
状態を残したくない場合は `RecyclingMethod::Clean` を指定してください。
`Clean` は `DISCARD ALL` を実行するため、プリペアドステートメントは無効になります。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection, SslMode};
use shiguredo_postgres::cursor::Cursor;
use shiguredo_postgres::pool::{Pool, PoolConfig, RecyclingMethod};

#[tokio::main]
async fn main() {
    let options = ConnectOptions {
        host: "127.0.0.1".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("mydb".to_string()),
        ssl_mode: SslMode::Disabled,
        ..Default::default()
    };

    let config = PoolConfig {
        max_size: 10,
        min_idle: 2,
        recycling: RecyclingMethod::Clean,
        ..Default::default()
    };

    let pool = Pool::start(options, config)
        .await
        .expect("プールの生成に失敗しました");

    // 複数タスクからプールを共有する
    let mut handles = Vec::new();
    for i in 0..8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            // acquire で接続を借りる。drop で自動的に返却される
            let mut pooled = pool
                .acquire()
                .await
                .expect("接続の取得に失敗しました");
            let mut cursor = Cursor::new(pooled.connection_mut());
            cursor
                .query(&format!("SELECT {} AS task_id", i))
                .await
                .expect("SELECT の実行に失敗しました");
            let rows = cursor.fetch_all().expect("結果取得に失敗しました");
            rows[0][0].clone()
        }));
    }

    for handle in handles {
        println!("{:?}", handle.await.expect("タスクの実行に失敗しました"));
    }

    pool.close().await.expect("プールの停止に失敗しました");
}
```

接続確立後に初期化 SQL を実行する場合は `with_after_connect` を使います。
フックは非同期関数で、エラーを返した接続は破棄されます。

```rust
use shiguredo_postgres::pool::PoolConfig;

let config = PoolConfig::default().with_after_connect(|conn| {
    Box::pin(async move {
        conn.execute("SET search_path = app, public", &[], false)
            .await?;
        Ok(())
    })
});
```

`with_on_acquire` は貸出前の検証に使い、エラーを返すと接続を破棄して取得をやり直します。
`with_after_release` は返却後の後始末に使います。
`RecyclingMethod::Custom` を指定すると、任意の非同期処理でセッションを初期化できます。

## ライセンス

Apache License 2.0

```text
Copyright 2026 Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
