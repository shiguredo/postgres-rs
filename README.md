# postgres-rs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

> [!WARNING]
> このリポジトリはお試し実装です。正式リリースは行いません。

## 概要

`postgres-rs` は PostgreSQL クライアントの Rust 実装です。

- `shiguredo_postgres` - Sans I/O な PostgreSQL プロトコル実装
- `shiguredo_tokio_postgres` - tokio 上で動作する非同期 PostgreSQL クライアント

## 使い方

### 単一接続

```rust
use shiguredo_postgres::connection::{ConnectOptions, SslMode};
use shiguredo_postgres::converters::Value;
use shiguredo_tokio_postgres::connection::Connection;
use shiguredo_tokio_postgres::cursor::Cursor;

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

### 非同期並列クエリ

```rust
use shiguredo_postgres::connection::ConnectOptions;
use shiguredo_tokio_postgres::connection::Connection;
use shiguredo_tokio_postgres::cursor::Cursor;

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
use shiguredo_postgres::connection::ConnectOptions;
use shiguredo_tokio_postgres::connection::Connection;
use shiguredo_tokio_postgres::cursor::Cursor;
use shiguredo_tokio_postgres::pool::{Pool, PoolConfig};
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
