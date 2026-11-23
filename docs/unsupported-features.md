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
| TLS 1.2 より前のバージョン | `ssl_min_protocol_version` と `ssl_max_protocol_version` は `TLSv1.2` と `TLSv1.3` だけを受け付け、`TLSv1` と `TLSv1.1` はエラーにします。libpq の既定の最小も `TLSv1.2` です。 |
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
| プロトコル 3.2、`min_protocol_version` と `max_protocol_version` | 常にプロトコル 3.0 で接続します。3.2 は PostgreSQL 18 以降でキャンセル要求の秘密鍵を長くした版です。PostgreSQL 19 の libpq も、版の交渉に対応しないサーバーや中継との互換のため、既定では 3.0 を使います (PostgreSQL 19 文書 §53.1.4 Protocol Versions)。 |
| パラメーターと結果のバイナリ形式 | すべてテキスト形式 (PostgreSQL 19 文書 §53.1.3 Formats and Format Codes) でやり取りし、PostgreSQL のテキスト出力を解釈します。 |
| Function Call (fast-path) | PostgreSQL 19 文書 §53.2.5 Function Call は、新しいコードでは避け、`SELECT function($1, ...)` を準備した文で置き換えることを勧めています。関数は SQL から呼んでください。 |
| `hostaddr` | ホスト名と接続先の IP アドレスを別々に持つと、`sslmode=disable` で許すローカル接続の判定と、TLS で名前を検証する対象が分かれます。接続先は `host` だけで指定します。IP アドレスで接続する場合は `host` に IP アドレスを書きます。 |
| `require_auth` | 認証方式の制限は認証の状態遷移に関わるため、現時点では実装しません。この実装が応じる方式は、SCRAM-SHA-256、`verify-full` での OAUTHBEARER、ローカル開発接続での平文パスワード、サーバーによる認証の省略に限ります。 |
| 証明書失効リスト (`sslcrl` / `sslcrldir`) | 既定の `verify-full` は OS の証明書検証を使い、そこには失効リストを渡せません。`sslrootcert` を明示した場合と検証の内容がずれるため、どちらでも失効リストは受け付けません。 |
| 暗号化されたクライアント秘密鍵と `sslpassword` | 鍵のパスワードを接続設定に持たせません。暗号化していない鍵を、アクセス権を絞ったファイルに置いてください。鍵は PEM または DER の PKCS#8、PKCS#1 (RSA)、SEC1 (EC) を受け付けます。 |
| `sslcertmode` | `sslcert` と `sslkey` を指定した場合は、サーバーが要求したときにクライアント証明書を送ります (libpq の `allow` と同じ)。送らない `disable` と、サーバーが要求しなければ失敗する `require` は実装しません。 |

## 照合に使った一次資料

比較基準は PostgreSQL 19.0 です。

- [本家の認証選択と状態検査](https://github.com/postgres/postgres/blob/REL_19_0/src/interfaces/libpq/fe-auth.c)
- [本家の接続文字列と TLS 設定](https://github.com/postgres/postgres/blob/REL_19_0/src/interfaces/libpq/fe-connect.c)
- [本家の MD5 パスワード非推奨の扱い](https://github.com/postgres/postgres/blob/REL_19_0/src/backend/libpq/crypt.c)
- [本家の日付・時刻の出力形式](https://github.com/postgres/postgres/blob/REL_19_0/src/backend/utils/adt/datetime.c)
- [本家の `client_encoding` と `DateStyle` の正規化](https://github.com/postgres/postgres/blob/REL_19_0/src/backend/commands/variable.c)
- [本家の `ParameterStatus` の通知](https://github.com/postgres/postgres/blob/REL_19_0/src/backend/utils/misc/guc.c)
- [PostgreSQL 19 のプロトコルの概要 (版と形式コード)](https://www.postgresql.org/docs/19/protocol-overview.html)
- [PostgreSQL 19 のプロトコルフロー (Function Call を含む)](https://www.postgresql.org/docs/19/protocol-flow.html)
- [PostgreSQL 19 の libpq の接続パラメーター](https://www.postgresql.org/docs/19/libpq-connect.html#LIBPQ-PARAMKEYWORDS)
