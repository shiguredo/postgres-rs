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
  - TLS 1.2 / 1.3 の範囲指定 (`ssl_min_protocol_version` / `ssl_max_protocol_version`)
  - SNI の無効化 (`sslsni=0`)
  - クライアント証明書 (秘密鍵は PKCS#8 / PKCS#1 / SEC1)
- Unix ドメインソケット
- 接続文字列
  - libpq 形式
  - `postgres://` URL
- 型変換
  - bool / 整数 / 浮動小数 / NUMERIC / oid / oid8 (PostgreSQL 19 以降) / bytea / UUID / JSON / JSONB / date / time / timestamp / timestamptz / interval / inet / cidr / macaddr / macaddr8 と、それらの配列
  - interval は `IntervalStyle` が既定の `postgres` のときに変換し、ほかの形式はテキストとして返す
  - timetz / 範囲型などそれ以外の型はテキストとして返す
  - 範囲型など主な組み込み型の配列は、要素がテキストの配列として返す (対象は `constants::oid::array` に挙げた型、`box` の配列は含まない)
  - 独自の変換の登録 (`register_converter`)

対応しない機能とその理由は [意図的に実装しない機能](docs/unsupported-features.md) を参照してください。

## インストール

crates.io には公開していません。GitHub のリポジトリを git 依存で指定し、`tag` には [Releases](https://github.com/shiguredo/postgres-rs/releases) のタグを指定してください。

```toml
[dependencies]
shiguredo_postgres = { git = "https://github.com/shiguredo/postgres-rs", tag = "<リリースのタグ>" }
tokio = { version = "1.54", features = ["macros", "rt-multi-thread"] }
```

- Rust 1.95 以降が必要です
- 以下の例の `#[tokio::main]` は、tokio の `macros` と `rt-multi-thread` を使います
- TLS と暗号処理には rustls と aws-lc-rs を使うため、OpenSSL は不要です

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

### 接続文字列

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

URL ではクエリ文字列に同じキーを指定します。未対応のキーは無視せずエラーにします。

| キー | 内容 |
| --- | --- |
| `host` | ホスト名、IP アドレス、または Unix ドメインソケットのディレクトリ (`/` で始まる) |
| `port` | ポート番号。既定は 5432 |
| `dbname` / `database` | データベース名 |
| `user` / `password` | ユーザー名とパスワード |
| `application_name` | サーバーに通知するアプリケーション名 |
| `options` | 起動時のコマンドラインオプション (`-c search_path=app` など) |
| `connect_timeout` | 接続確立のタイムアウト (秒)。既定は 10 |
| `sslmode` | `verify-full` (既定) / `verify-ca` / `require` / `disable` |
| `sslrootcert` / `sslcert` / `sslkey` | CA 証明書、クライアント証明書、クライアント秘密鍵のファイルパス |
| `sslsni` | SNI を送るか (`1` は送る、`0` は送らない)。既定は `1` |
| `ssl_min_protocol_version` / `ssl_max_protocol_version` | `TLSv1.2` / `TLSv1.3`。既定の最小は `TLSv1.2` |
| `keepalives` | TCP キープアライブを使うか (`0` は使わない)。既定は使う |
| `keepalives_idle` / `keepalives_interval` | キープアライブの無通信時間と再送間隔 (秒)。`0` は OS の既定値 |
| `keepalives_count` | 切断と判断するまでに失ってよいキープアライブの数。`0` は OS の既定値 |
| `tcp_user_timeout` | 送信データの確認応答を待つ上限 (ミリ秒)。`0` は OS の既定値。Linux と Android のみ |
| `allow_insecure_remote` | 開発用。`sslmode=disable` でローカル以外への平文接続を許す (`true` / `false`) |

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

`unbuffered = true` を渡すと `next_row` で 1 行ずつ `Row` として取得できます。

```rust
conn.execute_uncached("SELECT n FROM generate_series(1, $1::int) AS n", &[Value::Int4(100_000)], true)
    .await?;
while let Some(row) = conn.next_row().await? {
    let n: i32 = row.get_by_name("n")?;
    println!("{n}");
}
```

読み取りを途中でやめる場合は、次のクエリの前に `finish_rows` で読み残しを破棄します。

### 行と型付きの値

`query_all` はすべての行を `Row` として返します。`Row` からは列番号か列名で、Rust の型に変換して取り出せます。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::{IpNetwork, Value};
use shiguredo_postgres::datetime::{Interval, Timestamptz};

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    let rows = conn
        .query_all(
            "SELECT id, name, nickname, tags, client_addr, session_timeout, created_at \
             FROM users WHERE age > $1",
            &[Value::Int4(20)],
        )
        .await
        .expect("クエリの実行に失敗しました");
    for row in &rows {
        let id: i32 = row.get_by_name("id").expect("id を取得できません");
        let name: String = row.get_by_name("name").expect("name を取得できません");
        // NULL を許す列は get_opt / get_opt_by_name で Option として取り出す
        let nickname: Option<String> = row
            .get_opt_by_name("nickname")
            .expect("nickname を取得できません");
        // 配列は Vec<T>、NULL を含みうる配列は Vec<Option<T>> で取り出す
        let tags: Vec<Option<String>> = row.get_by_name("tags").expect("tags を取得できません");
        let client_addr: IpNetwork = row
            .get_by_name("client_addr")
            .expect("client_addr を取得できません");
        let session_timeout: Interval = row
            .get_by_name("session_timeout")
            .expect("session_timeout を取得できません");
        let created_at: Timestamptz = row
            .get_by_name("created_at")
            .expect("created_at を取得できません");
        println!(
            "{id} {name} {nickname:?} {tags:?} {client_addr:?} {session_timeout:?} {created_at:?}"
        );
    }
}
```

列の値は `Value` に変換され、`Row::get` などで次の Rust の型として取り出せます。
変換できない値は `Value::Text` のまま返ります。
パラメーターも `Value` で渡します。パラメーターはテキスト形式で送るため、型はクエリの文脈 (`$1::int4` など) で決まります。

| PostgreSQL の型 | `Value` | 取り出せる Rust の型 |
| --- | --- | --- |
| `boolean` | `Bool` | `bool` |
| `smallint` | `Int2` | `i16` / `i32` / `i64` |
| `integer` | `Int4` | `i32` / `i64` |
| `bigint` | `Int8` | `i64` |
| `real` | `Float4` | `f32` / `f64` |
| `double precision` | `Float8` | `f64` |
| `numeric` | `Numeric` (文字列) | `String` |
| `text` / `varchar` / `char` / `name` | `Text` | `String` |
| `bytea` | `Bytes` | `Vec<u8>` |
| `oid` | `Oid` | `u32` / `u64` |
| `oid8` (PostgreSQL 19 以降) | `Oid8` | `u64` |
| `uuid` | `Uuid` | `u128` |
| `json` / `jsonb` | `Json` (文字列) | `String` |
| `date` / `time` / `timestamp` / `timestamptz` | `Date` / `Time` / `Timestamp` / `Timestamptz` | `datetime` モジュールの同名の型 |
| `interval` | `Interval` | `datetime::Interval` |
| `inet` | `Inet` | `converters::IpNetwork`、ホストアドレスは `IpAddr` でも取り出せる |
| `cidr` | `Cidr` | `converters::IpNetwork` |
| `macaddr` / `macaddr8` | `MacAddr` / `MacAddr8` | `[u8; 6]` / `[u8; 8]` |
| 配列 | `Array` | `Vec<T>` / `Vec<Option<T>>` (多次元は入れ子の `Vec`) |
| それ以外 | `Text` | `String` |

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

### TLS とクライアント証明書

既定の `sslmode=verify-full` は、OS の証明書ストアで証明書の信頼チェーンと接続先の名前を検証します。
`sslrootcert` を指定した場合は、OS の証明書ストアの代わりにその CA で検証します。
クライアント証明書は `sslcert` と `sslkey` で指定します。

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_conninfo(
        "host=db.example.com dbname=mydb user=app \
         sslrootcert=/etc/postgres/ca.pem sslcert=/etc/postgres/client.pem sslkey=/etc/postgres/client.key",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");
    conn.ping().await.expect("Ping に失敗しました");
}
```

| `sslmode` | 検証の内容 |
| --- | --- |
| `verify-full` (既定) | 証明書の信頼チェーンと接続先の名前を検証する |
| `verify-ca` | 信頼チェーンだけを検証する。`sslrootcert` がなければ OS の証明書ストアを使う |
| `require` | TLS を必須とする。`sslrootcert` を指定した場合だけ信頼チェーンを検証する |
| `disable` | 平文で接続する。`localhost`、ループバック IP、Unix ドメインソケットに限る |

- TLS の接続に失敗しても、平文には切り替えません
- 秘密鍵は PEM または DER の PKCS#8、PKCS#1 (RSA)、SEC1 (EC) を受け付けます。暗号化された鍵には対応しません

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

## Agent Skills

[Agent Skills](https://agentskills.io/) 形式のスキルを同梱しています。`gh skill install` コマンドで対応する AI エージェント (Claude Code、Cursor、GitHub Copilot、Gemini CLI など) にインストールでき、エージェントがこのライブラリの API と使い方を理解した上で支援できるようになります。

```bash
gh skill install shiguredo/postgres-rs shiguredo-postgres
```

スキルの内容は [`skills/shiguredo-postgres/SKILL.md`](skills/shiguredo-postgres/SKILL.md) を参照してください。

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
