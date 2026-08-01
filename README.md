# postgres-rs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

> [!WARNING]
> このリポジトリはお試し実装です。正式リリースは行いません。

## 概要

`postgres-rs` は PostgreSQL クライアントの Rust 実装です。

- `shiguredo_postgres` - Sans I/O な PostgreSQL プロトコル実装
- `shiguredo_tokio_postgres` - tokio 上で動作する非同期 PostgreSQL クライアント (開発中)

## 使い方

### 単一接続 (開発中)

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};

let options = ConnectOptions {
    host: "127.0.0.1".to_string(),
    port: 5432,
    user: "postgres".to_string(),
    password: b"password".to_vec(),
    database: Some("mydb".to_string()),
    ..Default::default()
};

let mut conn = Connection::connect(options).unwrap();
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
