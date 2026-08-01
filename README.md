# postgres-rs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

> [!WARNING]
> このリポジトリはお試し実装です。正式リリースは行いません。

## 概要

`postgres-rs` は PostgreSQL クライアントの Rust 実装です。

- `shiguredo_postgres` - tokio 上で動作する非同期 PostgreSQL クライアント
- `shiguredo_postgres_core` - Sans I/O な PostgreSQL プロトコル実装

主な機能:

- 単純クエリプロトコル / 拡張クエリプロトコル (パラメータ付きクエリ)
- プリペアドステートメント (ステートメントキャッシュと自動再準備)
- バッチクエリ (複数ステートメントを 1 往復で送信)
- 複数結果セット (単純クエリでの複数ステートメント)
- COPY プロトコル (CopyIn / CopyOut)
- LISTEN / NOTIFY
- トランザクション (セーブポイント、自動ロールバック)
- コネクションプール (min_idle 補充、最大生存時間)
- クエリタイムアウト (サーバー側キャンセル付き)
- 認証: SCRAM-SHA-256 / MD5 / 平文 / trust / OAuth (OAUTHBEARER, PostgreSQL 18 以降)
- TLS (sslmode: disable / allow / prefer / require / verify-ca / verify-full)
- Unix ドメインソケット
- 接続文字列 (libpq 形式) と `postgres://` URL
- 型変換: 数値 / 浮動小数 / 日付時刻 / NUMERIC / UUID / JSON / JSONB / 配列 / bytea 等

## 使い方

### 単一接続

```rust
use shiguredo_postgres_core::connection::{ConnectOptions, SslMode};
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres::connection::Connection;
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

    let mut conn = Connection::connect(options).await.unwrap();
    let mut cursor = Cursor::new(&mut conn);

    // パラメータ付きクエリ
    cursor
        .execute(
            "SELECT id, name FROM users WHERE age > $1",
            &[Value::Int4(20)],
        )
        .await
        .unwrap();

    for row in cursor.fetch_all().unwrap() {
        println!("{:?}", row);
    }

    conn.close().await.unwrap();
}
```

接続文字列 (libpq 形式) や URL から接続することもできます。

```rust
let options = ConnectOptions::from_conninfo(
    "host=127.0.0.1 port=5432 user=postgres password=password dbname=mydb sslmode=disable",
)
.unwrap();

let options = ConnectOptions::from_url(
    "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
)
.unwrap();
```

### プリペアドステートメント

同じ SQL を繰り返し実行する場合は、ステートメントキャッシュが有効です。
明示的に準備して実行することもできます。

```rust
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres::connection::Connection;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .unwrap();
    let mut conn = Connection::connect(options).await.unwrap();

    // ステートメントキャッシュ: 同じ SQL は 2 回目以降に再パースされない
    conn.execute("SELECT $1::int", &[Value::Int4(1)], false)
        .await
        .unwrap();

    // 明示的な準備と実行
    let statement = conn.prepare("SELECT $1::int + $2::int").await.unwrap();
    conn.execute_prepared(&statement, &[Value::Int4(1), Value::Int4(2)], false)
        .await
        .unwrap();
}
```

### トランザクション

```rust
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres::connection::Connection;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .unwrap();
    let mut conn = Connection::connect(options).await.unwrap();

    let mut tx = conn.begin().await.unwrap();
    tx.execute(
        "INSERT INTO users (name) VALUES ($1)",
        &[Value::Text("alice".to_string())],
    )
    .await
    .unwrap();
    // エラー時は tx.rollback()、または commit / rollback せずに
    // 破棄すると次の begin() で自動的にロールバックされる
    tx.commit().await.unwrap();

    // セーブポイント
    let mut tx = conn.begin().await.unwrap();
    tx.execute("UPDATE users SET name = 'bob'", &[]).await.unwrap();
    tx.savepoint("sp1").await.unwrap();
    tx.execute("DELETE FROM users", &[]).await.unwrap();
    tx.rollback_to_savepoint("sp1").await.unwrap();
    tx.commit().await.unwrap();
}
```

### バッチクエリ

複数のステートメントを 1 往復で送信します。

```rust
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres::batch::Batch;
use shiguredo_postgres::connection::Connection;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .unwrap();
    let mut conn = Connection::connect(options).await.unwrap();

    let mut batch = Batch::new();
    batch.append("INSERT INTO users (name) VALUES ($1)", &[Value::Text("a".to_string())]);
    batch.append("INSERT INTO users (name) VALUES ($1)", &[Value::Text("b".to_string())]);
    batch.append("SELECT COUNT(*) FROM users", &[]);

    // ステートメントごとの結果 (影響行数またはエラー) が返る
    let results = conn.batch_execute(batch).await.unwrap();
}
```

### COPY

```rust
use shiguredo_postgres::connection::Connection;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .unwrap();
    let mut conn = Connection::connect(options).await.unwrap();

    // CopyIn
    conn.copy_in(
        "COPY users (name) FROM STDIN",
        b"alice\nbob\ncherry\n",
    )
    .await
    .unwrap();

    // CopyOut
    let data = conn
        .copy_out("COPY users (name) TO STDOUT")
        .await
        .unwrap();
}
```

### LISTEN / NOTIFY

```rust
use shiguredo_postgres::connection::Connection;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .unwrap();
    let mut conn = Connection::connect(options).await.unwrap();

    conn.query("LISTEN channel_name", false).await.unwrap();

    // 通知を待つ (事前に別の接続から NOTIFY を送っておく)
    let notification = conn.next_notification().await.unwrap();
    println!("channel={} payload={}", notification.channel, notification.payload);
}
```

### クエリタイムアウト

タイムアウトした場合はサーバーにキャンセル要求を送り、
接続を正常な状態に戻した上でエラーを返します。

```rust
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres::connection::Connection;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .unwrap();
    let mut conn = Connection::connect(options).await.unwrap();

    let result = conn
        .query_with_timeout("SELECT pg_sleep(10)", false, Duration::from_secs(1))
        .await;
    assert!(result.is_err());

    // キャンセル後も接続は正常に使える
    conn.ping().await.unwrap();
}
```

### OAuth 認証

PostgreSQL 18 以降の OAuth 認証 (pg_hba.conf の `oauth` メソッド) に対応しています。
`ConnectOptions::oauth_token` にアクセストークンを設定するか、
`connect_with_oauth` でトークンプロバイダを渡します。
トークンがサーバーに拒否された場合は、プロバイダから新しいトークンを
取得して接続をやり直します (最大 3 回)。

```rust
use shiguredo_postgres_core::connection::ConnectOptions;
use shiguredo_postgres::connection::Connection;

#[tokio::main]
async fn main() {
    // 静的なトークンで接続する場合。
    let options = ConnectOptions {
        oauth_token: Some("access-token".to_string()),
        ..ConnectOptions::from_url("postgres://user@db.example.com/mydb?sslmode=require").unwrap()
    };
    let mut conn = Connection::connect(options).await.unwrap();

    // トークンプロバイダ付きで接続する場合。
    // トークンが拒否されたときに新しいトークンを取得して再接続する。
    let options = ConnectOptions {
        oauth_token: Some("initial-token".to_string()),
        ..ConnectOptions::from_url("postgres://user@db.example.com/mydb?sslmode=require").unwrap()
    };
    let mut conn = Connection::connect_with_oauth(options, || {
        // ここで OAuth 2.0 / OIDC フロー (リフレッシュ等) を行い、
        // 新しいアクセストークンを返す。
        async { Ok("new-access-token".to_string()) }
    })
    .await
    .unwrap();
}
```

トークンの取得 (OAuth 2.0 / OIDC フロー) 自体は利用者の責任です。
libpq の libpq-oauth のようなトークン取得フローは実装していません。

### 非同期並列クエリ

```rust
use shiguredo_postgres_core::connection::ConnectOptions;
use shiguredo_postgres::connection::Connection;
use shiguredo_postgres::cursor::Cursor;

#[tokio::main]
async fn main() {
    let options = ConnectOptions {
        host: "127.0.0.1".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("mydb".to_string()),
        ..Default::default()
    };

    // 複数の接続を並列に確立してクエリを実行する
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let opts = options.clone();
            tokio::spawn(async move {
                let mut conn = Connection::connect(opts).await.unwrap();
                let mut cursor = Cursor::new(&mut conn);
                cursor
                    .query(&format!("SELECT {} AS num", i))
                    .await
                    .unwrap();
                let rows = cursor.fetch_all().unwrap();
                rows[0][0].clone()
            })
        })
        .collect();

    for handle in handles {
        println!("{:?}", handle.await.unwrap());
    }
}
```

### コネクションプール

```rust
use shiguredo_postgres_core::connection::ConnectOptions;
use shiguredo_postgres::connection::Connection;
use shiguredo_postgres::cursor::Cursor;
use shiguredo_postgres::pool::{Pool, PoolConfig};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let options = ConnectOptions {
        host: "127.0.0.1".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: b"password".to_vec(),
        database: Some("mydb".to_string()),
        ..Default::default()
    };

    let config = PoolConfig {
        max_size: 10,
        min_idle: 2,
        max_idle_time: Duration::from_secs(600),
        max_lifetime: Duration::from_secs(1800),
        acquire_timeout: Duration::from_secs(30),
    };

    let pool = Pool::start(options, config).await.unwrap();

    // 複数タスクからプールを共有する
    let mut handles = Vec::new();
    for i in 0..8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            // acquire で接続を借りる。drop で自動的に返却される
            let mut pooled = pool.acquire().await.unwrap();
            let mut cursor = Cursor::new(pooled.connection_mut());
            cursor
                .query(&format!("SELECT {} AS task_id", i))
                .await
                .unwrap();
            let rows = cursor.fetch_all().unwrap();
            rows[0][0].clone()
        }));
    }

    for handle in handles {
        println!("{:?}", handle.await.unwrap());
    }

    pool.close().await.unwrap();
}
```

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
