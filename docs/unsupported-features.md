# 意図的に実装しない機能

`postgres-rs` は PostgreSQL の汎用クライアントです。libpq や他のドライバーの完全互換は目指しません。既定ではサーバーの身元と資格情報を保護し、開発や既存環境のために検証を緩める場合は明示指定を求めます。用途が限られる機能は必要性と運用上の負担を見極めてから検討します。

## 安全性のために提供しない機能

| 機能 | 方針と代替手段 |
| --- | --- |
| MD5 パスワード認証 | 削除しました。PostgreSQL 本家でも非推奨です。ロールのパスワードを SCRAM-SHA-256 で設定し直し、`pg_hba.conf` を `scram-sha-256` に切り替えてください。設定名が `md5` でもサーバーが SCRAM を要求する場合は、実際に要求された方式で判定します。 |
| ローカル開発接続以外での平文パスワード要求 | `AuthenticationCleartextPassword` への応答は、`sslmode=disable` を明示したローカル開発接続に限ります。TLS 接続や別ホストへの平文接続では拒否します。PAM / LDAP / RADIUS など同じプロトコル要求を使う方式は、この条件の外では利用できません。 |
| TLS と平文の自動切り替え | `allow` と `prefer` は受け付けません。既定の `verify-full` と明示指定の `require`、`verify-ca` はすべて TLS が必須です。拒否や検証失敗から平文へ切り替えません。 |
| 別ホストへの無条件の平文接続 | `sslmode=disable` だけで利用できるのは `localhost`、ループバック IP、Unix ドメインソケットです。`localhost` は名前解決を行わずループバックに接続します。別ホストの開発用コンテナーなどに接続する場合は `allow_insecure_remote=true` も明示します。通信は暗号化されず相手の身元も検証しないため、信頼できる開発ネットワークと開発専用のデータ・資格情報に限って使ってください。 |
| 接続先の名前を検証しない経路での OAuth Bearer トークン送信 | OAuth は `verify-full` でのみ利用できます。`verify-ca` や `require`、ローカルの平文接続では送信しません。 |
| 上限を超える SCRAM の反復回数 | サーバー指定の計算負荷を制限するため、PBKDF2 は 600,000 回までとします。これを超える設定で作成された SCRAM ベリファイアは利用できません。 |
| 接続後の `client_encoding` と `DateStyle` の変更 | 行の値は UTF-8、日付・時刻は ISO 形式として復号します。`client_encoding` を UTF8 以外に、`DateStyle` を ISO 以外の出力形式に変えたことを `ParameterStatus` で通知された接続は、その応答をエラーにして閉じます。値は PostgreSQL と同じ規則で解釈するため、接続プーラーが起動時の値 (`DateStyle=ISO` など) をそのまま返しても受け付けます。PostgreSQL は変更を応答の最後に通知するため、同じ応答の行も返しません。行を逐次取得している場合は、それまでに返した行も変更後の設定で届いている可能性があります。同じ応答の中で変更して元に戻した場合は通知されず、検出できません。別の文字コードや形式が必要な場合は、`convert_to` や `to_char` でクエリの中で変換してください。 |
| 未対応の接続オプションの黙認 | 接続文字列の未対応キーはエラーになります。例えば `channel_binding=require` を指定しても、SCRAM-SHA-256-PLUS を実装していないため受け付けません。チャネルバインディングが必須の環境では、対応するクライアントを使ってください。 |

## 用途を絞るために実装しない機能

| 機能 | 対象外とする理由 |
| --- | --- |
| Kerberos / GSSAPI / SSPI、GSS 暗号化 | 外部の認証基盤とプラットフォームごとの設定を必要とします。汎用クライアントとしては、SCRAM-SHA-256 と検証済み TLS を優先します。 |
| OAuth トークンの取得・対話フロー | OAuth のトークン取得、対話的なログイン、プロバイダーの設定はアプリケーションに委ねます。取得済みトークンの OAUTHBEARER 送信は対応します。 |
| `.pgpass`、サービスファイル、libpq 用環境変数の自動読み込み | プロセス環境や暗黙の設定ファイルで接続先・資格情報が変わらないよう、アプリケーションから明示的に渡す設定に限定します。 |
| 複数ホストの自動フェイルオーバー、`target_session_attrs` | 可用性と接続先の選択は運用構成に依存します。現時点では単一の接続先を設定します。 |
| `sslnegotiation=direct` | TLS は PostgreSQL 16 以降で使える `SSLRequest` による方式を維持します。直接ネゴシエーションを必須にしません。 |
| レプリケーション接続と `COPY BOTH` | WAL や変更配信は一般の SQL 接続とは別の用途です。通常の `COPY FROM STDIN` / `COPY TO STDOUT` は対応します。 |
| 任意の Sync / Flush を公開する汎用パイプライン | 公開 API の同期境界を明確に保つためです。複数文をまとめて送るバッチと、無名の 1 往復実行は対応します。 |
| ラージオブジェクト専用 API | 通常の SQL や COPY によるデータ処理を優先します。 |

## 照合に使った一次資料

比較基準は PostgreSQL 18.7 です。

- [本家の認証選択と状態検査](https://github.com/postgres/postgres/blob/REL_18_7/src/interfaces/libpq/fe-auth.c)
- [本家の接続文字列と TLS 設定](https://github.com/postgres/postgres/blob/REL_18_7/src/interfaces/libpq/fe-connect.c)
- [本家の MD5 パスワード非推奨の扱い](https://github.com/postgres/postgres/blob/REL_18_7/src/backend/libpq/crypt.c)
- [本家の日付・時刻の出力形式](https://github.com/postgres/postgres/blob/REL_18_7/src/backend/utils/adt/datetime.c)
- [本家の `client_encoding` と `DateStyle` の正規化](https://github.com/postgres/postgres/blob/REL_18_7/src/backend/commands/variable.c)
- [本家の `ParameterStatus` の通知](https://github.com/postgres/postgres/blob/REL_18_7/src/backend/utils/misc/guc.c)
- [PostgreSQL 18 のプロトコルフロー](https://www.postgresql.org/docs/18/protocol-flow.html)
