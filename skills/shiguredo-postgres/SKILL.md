---
name: shiguredo-postgres
description: 時雨堂の PostgreSQL クライアントライブラリ shiguredo_postgres の機能・API リファレンス。tokio 上の接続 (TLS / SCRAM-SHA-256 / OAuth / Unix ドメインソケット)、接続文字列と URL、クエリとプリペアドステートメント、Row による型付きの取得、Value の型変換、トランザクション、バッチ、COPY、LISTEN / NOTIFY、タイムアウトとキャンセル、コネクションプールに関する質問時に使用。
---

# shiguredo_postgres

tokio 上で動作する PostgreSQL クライアント。プロトコルは Sans I/O の `shiguredo_postgres_core` で実装し、TCP / TLS / Unix ドメインソケットの入出力を `shiguredo_postgres` が担う。利用者は `shiguredo_postgres` だけに依存すればよい。

## 特徴

- **安全側の既定**: 既定は `sslmode=verify-full`。TLS に失敗しても平文に切り替えない。平文接続は `localhost`、ループバック IP、Unix ドメインソケットに限る
- **黙って無視しない**: 未対応の接続キー、効かない設定の組み合わせ、対応しない OS での TCP の設定は、接続前にエラーにする
- **テキスト形式**: プロトコル 3.0 で、パラメーターと結果はすべてテキスト形式でやり取りする
- **行の復号の前提を守る**: `client_encoding=UTF8` と `DateStyle=ISO` を起動時に固定し、変更を通知された接続はエラーにして閉じる
- **MD5 認証には対応しない**: SCRAM-SHA-256、OAUTHBEARER、ローカル開発接続での平文パスワード、認証の省略に応じる

## バージョン情報

- crate 名: `shiguredo_postgres`
- バージョン: 2026.0.0
- Rust Edition: 2024
- 最小 Rust バージョン: 1.95
- ライセンス: Apache-2.0
- 動作を確認している PostgreSQL: 16 / 17 / 18 / 19
- 配布: crates.io には公開していない。git 依存で使う

```toml
[dependencies]
shiguredo_postgres = { git = "https://github.com/shiguredo/postgres-rs", tag = "<リリースのタグ>" }
tokio = { version = "1.54", features = ["macros", "rt-multi-thread"] }
```

## 依存

- `shiguredo_postgres_core`: Sans I/O なプロトコル実装 (同じリポジトリ)
- `tokio`: 非同期ランタイムと TCP / Unix ドメインソケット
- `rustls` / `tokio-rustls`: TLS (暗号は aws-lc-rs、TLS 1.2 / 1.3)
- `rustls-platform-verifier` / `rustls-native-certs`: OS の証明書検証と信頼アンカー
- `socket2`: TCP キープアライブと `TCP_USER_TIMEOUT`
- `aws-lc-rs` / `base64ct`: SCRAM-SHA-256 (core が使う)
- `tracing`: ログ

## モジュール

| モジュール | 主な型 |
| --- | --- |
| `connection` | `Connection`, `ConnectOptions`, `SslMode`, `TlsVersion`, `CancelToken`, `PreparedStatement`, `Notification`, `QueryResult` |
| `row` | `Row` |
| `cursor` | `Cursor`, `DictCursor` |
| `transaction` | `Transaction`, `TxOptions`, `IsolationLevel` |
| `batch` | `Batch` |
| `pool` | `Pool`, `PoolConfig`, `PooledConnection`, `RecyclingMethod`, `PoolStat`, `PoolDiscardStat`, `ConnectionHook`, `HookFuture`, `Connector` |
| `converters` | `Value`, `IpNetwork`, `Converter`, `decoder_for` |
| `datetime` | `Date`, `Time`, `Timestamp`, `Timestamptz`, `Interval` と有限値の `FiniteDate` / `FiniteTimestamp` / `FiniteTimestamptz` / `FiniteInterval` |
| `constants` | 型 OID (`oid::INT4` など) と配列型 OID (`oid::array::INT4` など)、プロトコル定数 |
| `error` | `Error`, `Result`, `ServerErrorInfo` |
| `protocol` | `FieldDescription`, `NoticeResponse` などプロトコルのメッセージ |

## 接続設定 (`ConnectOptions`)

`ConnectOptions::default()`、`ConnectOptions::from_conninfo(&str)` (libpq 形式)、`ConnectOptions::from_url(&str)` (`postgres://` / `postgresql://`) で作る。

| フィールド | 既定値 | 説明 |
| --- | --- | --- |
| `host` | `"localhost"` | ホスト名、IP アドレス、または `/` で始まる Unix ドメインソケットのディレクトリ |
| `port` | `5432` | ポート番号 |
| `user` / `password` | 空 | ユーザー名とパスワード (`Vec<u8>`) |
| `database` | `None` | `None` はユーザー名と同じ名前のデータベース |
| `application_name` | `None` | サーバーに通知するアプリケーション名 |
| `options` | `None` | 起動時のコマンドラインオプション (`-c search_path=app` など)。そのまま送る |
| `runtime_params` | 空 | 起動時に送る追加の設定 (`search_path` など)。`options` より後に処理される |
| `connect_timeout` | 10 秒 | 接続確立のタイムアウト |
| `ssl_mode` | `SslMode::VerifyFull` | `Disabled` / `Required` / `VerifyCa` / `VerifyFull` |
| `ssl_ca` / `ssl_cert` / `ssl_key` | `None` | CA 証明書、クライアント証明書、クライアント秘密鍵のファイルパス |
| `ssl_min_protocol_version` | `TlsVersion::Tls12` | TLS の最小バージョン |
| `ssl_max_protocol_version` | `None` | TLS の最大バージョン |
| `ssl_sni` | `true` | SNI で接続先のホスト名を送るか (IP アドレスの場合は送らない) |
| `keepalives` | `true` | TCP キープアライブを使うか |
| `keepalives_idle` / `keepalives_interval` | `None` | キープアライブの無通信時間と再送間隔 (1 秒以上の秒単位)。`None` は OS の既定値 |
| `keepalives_count` | `None` | 切断と判断するまでの回数。`None` は OS の既定値 |
| `tcp_user_timeout` | `None` | 送信データの確認応答を待つ上限 (1 ミリ秒以上)。Linux と Android のみ |
| `allow_insecure_remote` | `false` | 開発用。`sslmode=disable` でローカル以外への平文接続を許す |
| `oauth_token` | `None` | OAUTHBEARER で送るアクセストークン。`verify-full` でのみ使える |
| `max_message_size` | 64 MiB | 受信を許す 1 メッセージの最大サイズ |
| `statement_cache_capacity` | `128` | 自動準備する文のキャッシュの上限。`0` はキャッシュしない |

接続文字列と URL のクエリ文字列で使えるキー: `host` / `port` / `dbname` / `database` / `user` / `password` / `application_name` / `options` / `connect_timeout` (秒) / `sslmode` / `sslrootcert` / `sslcert` / `sslkey` / `sslsni` (`0` / `1`) / `ssl_min_protocol_version` / `ssl_max_protocol_version` (`TLSv1.2` / `TLSv1.3`) / `keepalives` (`0` は無効) / `keepalives_idle` (秒) / `keepalives_interval` (秒) / `keepalives_count` / `tcp_user_timeout` (ミリ秒) / `allow_insecure_remote` (`true` / `false`)。キープアライブの調整値と `tcp_user_timeout` の `0` は OS の既定値を表す。ほかのキー (`channel_binding`、`target_session_attrs`、`hostaddr` など) はエラーになる。

`Connection::connect` が接続前に拒否する主な組み合わせ:

- Unix ドメインソケットで `sslmode=disable` 以外を指定する
- `sslmode=disable` でローカル以外に接続する (`allow_insecure_remote=true` がない場合)
- `sslmode=disable` と TLS の証明書の設定を一緒に指定する
- `oauth_token` を `verify-full` 以外で使う
- `keepalives=false` とキープアライブの調整値を一緒に指定する、Unix ドメインソケットで TCP の設定を指定する
- `ssl_min_protocol_version` が `ssl_max_protocol_version` を超える
- `runtime_params` に専用の設定や固定値を持つ名前 (`user`、`client_encoding`、`DateStyle`、`options` など) や `_pq_.` で始まる名前を使う

## 接続 (`Connection`)

| メソッド | 説明 |
| --- | --- |
| `connect(options)` | 接続を確立する |
| `connect_with_oauth(options, provider)` | トークンが拒否されたときに `provider` から新しいトークンを取得して接続し直す |
| `query(sql, unbuffered)` | 単純クエリプロトコルで実行する。複数の文を `;` で並べられる。影響行数を返す |
| `execute(sql, args, unbuffered)` | パラメーター付きで実行する。同じ SQL の文をキャッシュする |
| `execute_typed(sql, oids, args, unbuffered)` | パラメーターの型 OID を明示して実行する |
| `execute_uncached(sql, args, unbuffered)` | 名前付きの文を作らず 1 往復で実行する。一度だけの SQL に使う |
| `query_one(sql, args)` | ちょうど 1 行を `Row` で返す。0 行と 2 行以上はエラー |
| `query_opt(sql, args)` | 0 行か 1 行を `Option<Row>` で返す |
| `query_all(sql, args)` | すべての行を `Vec<Row>` で返す |
| `prepare(sql)` / `prepare_typed(sql, oids)` | 文を準備して `PreparedStatement` を返す |
| `execute_prepared(&stmt, args, unbuffered)` / `deallocate(&stmt)` | 準備した文を実行・解放する |
| `next_row()` | `unbuffered = true` で始めたクエリの次の行を `Option<Row>` で返す |
| `finish_rows()` | 読み残しの行を破棄して接続を同期する |
| `result()` / `result_mut()` | 直前のクエリの結果 (`QueryResult`: `fields`、`rows`、`affected_rows`、`tag`) |
| `begin()` / `begin_with(TxOptions)` | トランザクションを開始する |
| `batch_execute(batch)` / `batch_execute_rows(batch)` | 複数の文を 1 往復で送る。文ごとの影響行数か結果セットを返す |
| `copy_in(sql, data)` / `copy_out(sql)` | `COPY FROM STDIN` / `COPY TO STDOUT` を一度に実行する |
| `copy_in_begin` / `send_copy_data` / `send_copy_done` / `send_copy_fail` / `finish_copy_in` | CopyIn を少しずつ送る |
| `copy_out_begin` / `read_copy_out_data` / `finish_copy_out` | CopyOut を少しずつ受け取る |
| `next_notification()` / `drain_notifications()` | `LISTEN` の通知を待つ・受信済みの通知を取り出す |
| `pop_notice()` | 受信した NOTICE を 1 つ取り出す |
| `query_with_timeout(sql, unbuffered, d)` / `execute_with_timeout(sql, args, unbuffered, d)` | タイムアウト付きで実行し、超えたらサーバーにキャンセルを送る |
| `cancel_token()` | 別のタスクからキャンセルするための `CancelToken` を作る (`token.cancel().await`) |
| `cancel_request()` | 応答待ちで中断したクエリや読み取り中の行をキャンセルする |
| `ping()` | 空のクエリで疎通を確かめる |
| `register_converter(oid, converter)` | 型 OID に独自のデコーダー (`fn(&str) -> Value`) を登録する |
| `cursor()` | `Cursor` を作る。`execute` / `query` の後に `fetch_one` / `fetch_many` / `fetch_all` で行 (`&Vec<Value>`) を取り出す。`DictCursor::new(cursor)` は列名をキーにした `HashMap` で返す |
| `server_version()` / `backend_process_id()` / `transaction_status()` | 接続の情報 |
| `is_open()` / `is_busy()` / `close()` / `force_close()` | 接続の状態と終了 |

## 行 (`Row`)

| メソッド | 説明 |
| --- | --- |
| `get::<T>(index)` / `get_by_name::<T>(name)` | 値を `T` に変換して取り出す。NULL、型の不一致、存在しない列はエラー |
| `get_opt::<T>(index)` / `get_opt_by_name::<T>(name)` | NULL を `None` として取り出す |
| `value(index)` / `value_by_name(name)` | `&Value` をそのまま参照する |
| `len()` / `is_empty()` / `column_names()` / `column_index(name)` / `column_name(index)` | 列の情報。列名は大文字と小文字を区別する |
| `into_values()` | 行の値をすべて `Vec<Value>` で取り出す |

## 型変換 (`Value`)

| PostgreSQL の型 | `Value` | `Row::get` で取り出せる型 |
| --- | --- | --- |
| `boolean` | `Bool(bool)` | `bool` |
| `smallint` / `integer` / `bigint` | `Int2` / `Int4` / `Int8` | `i16` / `i32` / `i64` (値を失わない広げ方も可) |
| `real` / `double precision` | `Float4` / `Float8` | `f32` / `f64` |
| `numeric` | `Numeric(String)` | `String` |
| `text` / `varchar` / `char` / `name` など | `Text(String)` | `String` |
| `bytea` | `Bytes(Vec<u8>)` | `Vec<u8>` |
| `oid` / `oid8` (PostgreSQL 19 以降) | `Oid(u32)` / `Oid8(u64)` | `u32` / `u64` |
| `uuid` | `Uuid(u128)` | `u128` |
| `json` / `jsonb` | `Json(String)` | `String` |
| `date` / `time` / `timestamp` / `timestamptz` | `Date` / `Time` / `Timestamp` / `Timestamptz` | 同名の `datetime` の型 (`date` / `timestamp` / `timestamptz` は `infinity` / `-infinity` も表す) |
| `interval` | `Interval(Interval)` | `datetime::Interval` (月数・日数・マイクロ秒) |
| `inet` / `cidr` | `Inet(IpNetwork)` / `Cidr(IpNetwork)` | `IpNetwork` (`address` と `prefix_len`)。ホストアドレスの `inet` は `IpAddr` でも可 |
| `macaddr` / `macaddr8` | `MacAddr([u8; 6])` / `MacAddr8([u8; 8])` | `[u8; 6]` / `[u8; 8]` |
| 配列 | `Array { element_type, values }` | `Vec<T>` / `Vec<Option<T>>` (多次元は入れ子の `Vec`) |
| それ以外 | `Text(String)` | `String` |

- 変換に失敗した値は `Value::Text` のまま返る
- `interval` は `IntervalStyle` が既定の `postgres` のときだけ変換する。ほかの形式で出力された値は `Value::Text` になる
- `timetz`、範囲型、幾何型などは変換しない。`constants::oid::array` に挙げた組み込み型の配列は、要素が `Value::Text` の `Value::Array` になる。`box` の配列は区切りが `;` のため 1 つの `Value::Text` になる
- NULL を含む配列を `Vec<T>` で取り出すとエラーになる。`Vec<Option<T>>` を使う
- パラメーターは `Value` で渡し、テキスト形式で送る。型はクエリの文脈で決まるため、必要なら `$1::int4` のように型を書くか `execute_typed` を使う。SQL NULL は `Value::Null`

## トランザクション、バッチ

- `conn.begin().await?` で `Transaction` を作り、`execute` / `query` / `savepoint` / `rollback_to_savepoint` / `release_savepoint` / `commit` / `rollback` を使う。ほかのメソッドは `tx.conn()` から呼ぶ
- `commit` も `rollback` もせずに破棄したトランザクションは、次の `begin()` でロールバックしてから開始する
- `TxOptions { isolation_level, read_only, deferrable }` を `begin_with` に渡す。`IsolationLevel` は `ReadCommitted` / `RepeatableRead` / `Serializable`
- `Batch::new()` に `append(sql, args)` で文を足し、`batch_execute` で送る。文ごとに `Result` が返る

## コネクションプール (`Pool`)

`Pool::start(options, config)` は `min_idle` 個の接続を確立してから戻る。`Pool::start_lazy` は接続をバックグラウンドで確立する。`Pool` は `Clone` でき、複数のタスクで共有する。

| メソッド | 説明 |
| --- | --- |
| `acquire()` / `acquire_with_timeout(d)` | 接続を借りる (`PooledConnection`)。`drop` で返却する |
| `try_acquire()` | アイドル接続があれば借りる。待たず、新しい接続も作らない |
| `stat()` | `PoolStat` (接続数の内訳、取得の待ち時間、破棄の理由の内訳など) |
| `reset()` | すべての接続を破棄して作り直す。貸出中の接続は返却時に破棄する |
| `close()` / `close_with_timeout(d)` | プールを止める。後者は貸出中の接続の返却まで待つ |

`PooledConnection` は `connection()` / `connection_mut()` で `Connection` を参照し、`discard()` で返却せずに破棄する。

| `PoolConfig` のフィールド | 既定値 | 説明 |
| --- | --- | --- |
| `max_size` | `10` | 接続数の上限 |
| `min_idle` | `1` | 維持するアイドル接続の数 |
| `min_size` | `0` | 維持する接続数の下限 |
| `max_idle_time` | 600 秒 | アイドル接続の最大生存時間 |
| `max_lifetime` / `max_lifetime_jitter` | 1800 秒 / 0 | 接続の最大生存時間とそのばらつき |
| `acquire_timeout` | 30 秒 | `acquire` のタイムアウト |
| `health_check_interval` | 30 秒 | アイドル接続の点検と補充の間隔 |
| `ping_timeout` | 5 秒 | 生存確認のタイムアウト。`0` は無制限 |
| `recycling` | `RecyclingMethod::Fast` | 返却時の後始末 |
| `before_connect` / `connector` / `after_connect` / `on_acquire` / `after_release` / `on_release` / `before_close` | `None` | 接続のライフサイクルのフック |

- `RecyclingMethod::Fast` はトランザクションをロールバックするだけで、`SET`、一時テーブル、`LISTEN` などのセッション状態は次の利用者に残る。`Clean` は `DISCARD ALL` を実行し、プリペアドステートメントも無効にする。`Custom(hook)` は独自の後始末を行う
- 非同期フックは `with_after_connect` / `with_on_acquire` / `with_after_release` / `with_connector` で設定する。フックがエラーを返した接続は破棄する。`on_acquire` がエラーを返すと別の接続で取得をやり直す

```rust
use shiguredo_postgres::connection::ConnectOptions;
use shiguredo_postgres::pool::{Pool, PoolConfig, RecyclingMethod};

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_url(
        "postgres://postgres:password@127.0.0.1:5432/mydb?sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let config = PoolConfig {
        max_size: 10,
        recycling: RecyclingMethod::Clean,
        ..Default::default()
    }
    .with_after_connect(|conn| {
        Box::pin(async move {
            conn.execute("SET statement_timeout = '5s'", &[], false).await?;
            Ok(())
        })
    });
    let pool = Pool::start(options, config).await.expect("プールの起動に失敗しました");

    let mut pooled = pool.acquire().await.expect("接続の取得に失敗しました");
    let row = pooled
        .connection_mut()
        .query_one("SELECT 1::int4 AS one", &[])
        .await
        .expect("クエリの実行に失敗しました");
    assert_eq!(row.get_by_name::<i32>("one").expect("値を取得できません"), 1);
    drop(pooled);

    pool.close().await.expect("プールの停止に失敗しました");
}
```

## エラー (`Error`)

| variant | 内容 |
| --- | --- |
| `DatabaseError` / `DataError` / `OperationalError` / `IntegrityError` / `InternalError` / `ProgrammingError` / `NotSupportedError` | サーバーのエラー応答。SQLSTATE のクラスで分ける (`23` は `IntegrityError` など) |
| `OperationalError` / `InternalError` / `NotSupportedError` | クライアント側でも使う。接続や TLS の失敗は `OperationalError`、対応しない指定 (`TLSv1.1` など) は `NotSupportedError` になる |
| `InterfaceError { message }` | 引数や設定の誤り、プロトコルの誤用など、呼び出し側に原因があるクライアント側のエラー |

`code()` (SQLSTATE)、`message()`、`detail()`、`hint()`、`position()`、`constraint()` でエラーの内容を取り出せる。クライアント側のエラーでは `code()` は `None` になる。例えばクエリのキャンセルは `code() == Some("57014")` になる。

## 例

```rust
use shiguredo_postgres::connection::{ConnectOptions, Connection};
use shiguredo_postgres::converters::Value;

#[tokio::main]
async fn main() {
    let options = ConnectOptions::from_conninfo(
        "host=127.0.0.1 user=postgres password=password dbname=mydb sslmode=disable",
    )
    .expect("接続文字列の解析に失敗しました");
    let mut conn = Connection::connect(options).await.expect("接続に失敗しました");

    let mut tx = conn.begin().await.expect("トランザクションの開始に失敗しました");
    tx.execute(
        "INSERT INTO users (name, tags) VALUES ($1, $2)",
        &[
            Value::Text("alice".to_string()),
            Value::Array {
                element_type: shiguredo_postgres::constants::oid::TEXT,
                values: vec![Value::Text("admin".to_string()), Value::Null],
            },
        ],
    )
    .await
    .expect("挿入に失敗しました");
    tx.commit().await.expect("コミットに失敗しました");

    for row in conn
        .query_all("SELECT name, tags FROM users ORDER BY name", &[])
        .await
        .expect("クエリの実行に失敗しました")
    {
        let name: String = row.get_by_name("name").expect("name を取得できません");
        let tags: Vec<Option<String>> = row.get_by_name("tags").expect("tags を取得できません");
        println!("{name} {tags:?}");
    }

    conn.close().await.expect("接続のクローズに失敗しました");
}
```

## 注意点

- `unbuffered = true` で始めたクエリの読み残しは、次の要求の前に自動で読み捨てる。途中でやめたことを明示する場合は `finish_rows` を呼ぶ
- クエリの Future を途中で破棄すると (`tokio::time::timeout` で包んだ場合など)、同期を確認できない接続は次の要求で閉じる。タイムアウトには `query_with_timeout` / `execute_with_timeout` を使い、その後は `is_open() && !is_busy()` を確かめてから再利用する
- `SET client_encoding` や `SET DateStyle` で行の復号の前提を変えると、その応答はエラーになり接続を閉じる。別の形式が必要な場合は `convert_to` や `to_char` でクエリの中で変換する
- `execute` がキャッシュした文がスキーマの変更で無効になった場合、接続が同期済みでトランザクションの外であれば一度だけ準備し直す
- `PreparedStatement` は準備した接続でだけ実行できる。プールの `Clean` では返却時に無効になる
- フックは `Arc` で共有され、複数のタスクから同時に呼ばれる

## 対応しない機能

MD5 認証、`sslmode=allow` / `prefer`、チャネルバインディング (SCRAM-SHA-256-PLUS)、Kerberos / GSSAPI / SSPI、OAuth のトークン取得、`.pgpass` / サービスファイル / libpq の環境変数、複数ホストとフェイルオーバー、`sslnegotiation=direct`、レプリケーション接続と `COPY BOTH`、任意の Sync / Flush を使うパイプライン、ラージオブジェクト専用 API、プロトコル 3.2、バイナリ形式、Function Call、`hostaddr`、`require_auth`、失効リスト (`sslcrl`)、暗号化された秘密鍵 (`sslpassword`)、`sslcertmode`、TLS 1.2 より前のバージョン。理由はリポジトリの `docs/unsupported-features.md` にある。
