// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL ワイヤプロトコルの定数。

/// プロトコルバージョン 3.0。
///
/// スタートアップメッセージの先頭 4 バイトにビッグエンディアンで格納される。
pub const PROTOCOL_VERSION: u32 = 196_608;

/// SSL 要求コード。
///
/// スタートアップメッセージの代わりに送信される 8 バイトのメッセージに格納される。
pub const SSL_REQUEST_CODE: u32 = 80_877_103;

/// GSSAPI 暗号化要求コード。
pub const GSSENC_REQUEST_CODE: u32 = 80_877_104;

/// キャンセル要求コード。
///
/// 進行中のクエリをキャンセルするために、別の接続から
/// バックエンドプロセス ID とシークレットキーとともに送信する。
pub const CANCEL_REQUEST_CODE: u32 = 80_877_102;

/// バックエンド (サーバー) から送信されるメッセージタイプ。
pub mod backend {
    /// 認証要求。
    pub const AUTHENTICATION_REQUEST: u8 = b'R';
    /// パラメータステータス。
    pub const PARAMETER_STATUS: u8 = b'S';
    /// バックエンドキーデータ。
    pub const BACKEND_KEY_DATA: u8 = b'K';
    /// クエリ処理可能。
    pub const READY_FOR_QUERY: u8 = b'Z';
    /// 行記述。
    pub const ROW_DESCRIPTION: u8 = b'T';
    /// データ行。
    pub const DATA_ROW: u8 = b'D';
    /// コマンド完了。
    pub const COMMAND_COMPLETE: u8 = b'C';
    /// 空クエリ応答。
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    /// エラー応答。
    pub const ERROR_RESPONSE: u8 = b'E';
    /// 通知応答。
    pub const NOTICE_RESPONSE: u8 = b'N';
    /// 非同期通知。
    pub const NOTIFICATION_RESPONSE: u8 = b'A';
    /// パラメータ記述。
    pub const PARAMETER_DESCRIPTION: u8 = b't';
    /// データなし。
    pub const NO_DATA: u8 = b'n';
    /// パース完了。
    pub const PARSE_COMPLETE: u8 = b'1';
    /// バインド完了。
    pub const BIND_COMPLETE: u8 = b'2';
    /// クローズ完了。
    pub const CLOSE_COMPLETE: u8 = b'3';
    /// ポータル一時停止。
    pub const PORTAL_SUSPENDED: u8 = b's';
    /// CopyIn 応答。
    pub const COPY_IN_RESPONSE: u8 = b'G';
    /// CopyOut 応答。
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    /// CopyBoth 応答。
    pub const COPY_BOTH_RESPONSE: u8 = b'W';
    /// Copy データ。
    pub const COPY_DATA: u8 = b'd';
    /// Copy 完了。
    pub const COPY_DONE: u8 = b'c';
    /// プロトコルバージョン交渉。
    pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
}

/// フロントエンド (クライアント) から送信されるメッセージタイプ。
pub mod frontend {
    /// クエリ (単純クエリプロトコル)。
    pub const QUERY: u8 = b'Q';
    /// パース。
    pub const PARSE: u8 = b'P';
    /// バインド。
    pub const BIND: u8 = b'B';
    /// 記述。
    pub const DESCRIBE: u8 = b'D';
    /// 実行。
    pub const EXECUTE: u8 = b'E';
    /// 同期。
    pub const SYNC: u8 = b'S';
    /// フラッシュ。
    pub const FLUSH: u8 = b'H';
    /// パスワードメッセージ。
    pub const PASSWORD: u8 = b'p';
    /// 終了。
    pub const TERMINATE: u8 = b'X';
    /// クローズ。
    pub const CLOSE: u8 = b'C';
    /// Copy データ。
    pub const COPY_DATA: u8 = b'd';
    /// Copy 完了。
    pub const COPY_DONE: u8 = b'c';
    /// Copy 失敗。
    pub const COPY_FAIL: u8 = b'F';
}

/// 認証要求の種類。
pub mod auth {
    /// 認証成功。
    pub const OK: u32 = 0;
    /// Kerberos V5。
    pub const KERBEROS_V5: u32 = 2;
    /// 平文パスワード。
    pub const CLEARTEXT_PASSWORD: u32 = 3;
    /// MD5 パスワード。
    pub const MD5_PASSWORD: u32 = 5;
    /// SCM 資格情報。
    pub const SCM_CREDENTIAL: u32 = 6;
    /// GSSAPI。
    pub const GSS: u32 = 7;
    /// GSSAPI 継続。
    pub const GSS_CONTINUE: u32 = 8;
    /// SSPI。
    pub const SSPI: u32 = 9;
    /// SASL。
    pub const SASL: u32 = 10;
    /// SASL 継続。
    pub const SASL_CONTINUE: u32 = 11;
    /// SASL 最終。
    pub const SASL_FINAL: u32 = 12;
}

/// ReadyForQuery メッセージのトランザクション状態。
pub mod transaction_status {
    /// アイドル状態。
    pub const IDLE: u8 = b'I';
    /// トランザクション内。
    pub const IN_TRANSACTION: u8 = b'T';
    /// 失敗したトランザクション内。
    pub const FAILED: u8 = b'E';
}

/// Describe メッセージの対象。
pub mod describe {
    /// ステートメント。
    pub const STATEMENT: u8 = b'S';
    /// ポータル。
    pub const PORTAL: u8 = b'P';
}

/// データ型の OID。
///
/// PostgreSQL の pg_type システムカタログに定義されている標準型の OID。
/// 配列型の OID は要素型ごとに固定されており、将来のバージョンで
/// 変更される可能性は低いが、独自型の配列はここに含まれない。
pub mod oid {
    /// bool 型 (真偽値)。
    pub const BOOL: u32 = 16;
    /// bytea 型 (バイト列)。
    pub const BYTEA: u32 = 17;
    /// char 型 (1 バイトの内部文字型)。
    pub const CHAR: u32 = 18;
    /// name 型 (識別子などに使う 63 バイトまでの文字列型)。
    pub const NAME: u32 = 19;
    /// bigint (int8) 型。
    pub const INT8: u32 = 20;
    /// smallint (int2) 型。
    pub const INT2: u32 = 21;
    /// integer (int4) 型。
    pub const INT4: u32 = 23;
    /// oid 型 (オブジェクト識別子)。
    pub const OID: u32 = 26;
    /// oid8 型 (64 ビットのオブジェクト識別子)。
    ///
    /// PostgreSQL 19 の src/include/catalog/pg_type.dat で追加された。
    /// 19 より前のサーバーにはこの型がない。
    pub const OID8: u32 = 6437;
    /// text 型 (可変長文字列)。
    pub const TEXT: u32 = 25;
    /// json 型 (テキスト形式の JSON)。
    pub const JSON: u32 = 114;
    /// jsonb 型 (バイナリ形式の JSON)。
    pub const JSONB: u32 = 3802;
    /// real (float4) 型。
    pub const FLOAT4: u32 = 700;
    /// double precision (float8) 型。
    pub const FLOAT8: u32 = 701;
    /// numeric 型 (任意精度の数値)。
    pub const NUMERIC: u32 = 1700;
    /// char(n) 型 (空白で埋めた固定長文字列)。
    pub const BPCHAR: u32 = 1042;
    /// varchar(n) 型 (可変長文字列)。
    pub const VARCHAR: u32 = 1043;
    /// date 型 (日付)。
    pub const DATE: u32 = 1082;
    /// time 型 (時刻)。
    pub const TIME: u32 = 1083;
    /// timestamp 型 (タイムゾーンなしの日時)。
    pub const TIMESTAMP: u32 = 1114;
    /// timestamptz 型 (タイムゾーン付きの日時)。
    pub const TIMESTAMPTZ: u32 = 1184;
    /// uuid 型 (汎用一意識別子)。
    pub const UUID: u32 = 2950;

    // 以下は変換せず `Value::Text` として扱う組み込み型。配列は要素を `Value::Text` にした
    // `Value::Array` として返すため、要素型と配列型の OID を持つ。
    // OID は PostgreSQL 19 の src/include/catalog/pg_type.dat の oid と array_type_oid による。
    /// interval 型 (時間間隔)。
    pub const INTERVAL: u32 = 1186;
    /// timetz 型 (タイムゾーン付きの時刻)。
    pub const TIMETZ: u32 = 1266;
    /// inet 型 (IP アドレスとネットワーク)。
    pub const INET: u32 = 869;
    /// cidr 型 (IP ネットワーク)。
    pub const CIDR: u32 = 650;
    /// macaddr 型 (6 バイトの MAC アドレス)。
    pub const MACADDR: u32 = 829;
    /// macaddr8 型 (8 バイトの MAC アドレス)。
    pub const MACADDR8: u32 = 774;
    /// money 型 (通貨)。
    pub const MONEY: u32 = 790;
    /// bit 型 (固定長のビット列)。
    pub const BIT: u32 = 1560;
    /// varbit 型 (可変長のビット列)。
    pub const VARBIT: u32 = 1562;
    /// xml 型 (XML)。
    pub const XML: u32 = 142;
    /// point 型 (平面上の点)。
    pub const POINT: u32 = 600;
    /// line 型 (無限の直線)。
    pub const LINE: u32 = 628;
    /// lseg 型 (線分)。
    pub const LSEG: u32 = 601;
    /// path 型 (経路)。
    pub const PATH: u32 = 602;
    /// polygon 型 (多角形)。
    pub const POLYGON: u32 = 604;
    /// circle 型 (円)。
    pub const CIRCLE: u32 = 718;
    /// tsvector 型 (全文検索の文書)。
    pub const TSVECTOR: u32 = 3614;
    /// tsquery 型 (全文検索の問い合わせ)。
    pub const TSQUERY: u32 = 3615;
    /// jsonpath 型 (SQL/JSON パス式)。
    pub const JSONPATH: u32 = 4072;
    /// pg_lsn 型 (WAL の位置)。
    pub const PG_LSN: u32 = 3220;
    /// xid8 型 (64 ビットのトランザクション ID)。
    pub const XID8: u32 = 5069;
    /// int4range 型 (integer の範囲)。
    pub const INT4RANGE: u32 = 3904;
    /// int8range 型 (bigint の範囲)。
    pub const INT8RANGE: u32 = 3926;
    /// numrange 型 (numeric の範囲)。
    pub const NUMRANGE: u32 = 3906;
    /// tsrange 型 (timestamp の範囲)。
    pub const TSRANGE: u32 = 3908;
    /// tstzrange 型 (timestamptz の範囲)。
    pub const TSTZRANGE: u32 = 3910;
    /// daterange 型 (date の範囲)。
    pub const DATERANGE: u32 = 3912;
    /// int4multirange 型 (integer の範囲の集合)。
    pub const INT4MULTIRANGE: u32 = 4451;
    /// int8multirange 型 (bigint の範囲の集合)。
    pub const INT8MULTIRANGE: u32 = 4536;
    /// nummultirange 型 (numeric の範囲の集合)。
    pub const NUMMULTIRANGE: u32 = 4532;
    /// tsmultirange 型 (timestamp の範囲の集合)。
    pub const TSMULTIRANGE: u32 = 4533;
    /// tstzmultirange 型 (timestamptz の範囲の集合)。
    pub const TSTZMULTIRANGE: u32 = 4534;
    /// datemultirange 型 (date の範囲の集合)。
    pub const DATEMULTIRANGE: u32 = 4535;

    /// 組み込み型の配列型 OID。
    ///
    /// サーバーは配列の要素型をクライアントに直接送らないため、
    /// 配列型 OID から要素型 OID への対応をクライアント側で持つ。
    /// ここにない配列型 (独自型・複合型の配列) はテキストとして扱う。
    pub mod array {
        /// bool 型の配列型の OID。
        pub const BOOL: u32 = 1000;
        /// bytea 型の配列型の OID。
        pub const BYTEA: u32 = 1001;
        /// char 型の配列型の OID。
        pub const CHAR: u32 = 1002;
        /// name 型の配列型の OID。
        pub const NAME: u32 = 1003;
        /// smallint (int2) 型の配列型の OID。
        pub const INT2: u32 = 1005;
        /// integer (int4) 型の配列型の OID。
        pub const INT4: u32 = 1007;
        /// text 型の配列型の OID。
        pub const TEXT: u32 = 1009;
        /// char(n) 型の配列型の OID。
        pub const BPCHAR: u32 = 1014;
        /// varchar(n) 型の配列型の OID。
        pub const VARCHAR: u32 = 1015;
        /// bigint (int8) 型の配列型の OID。
        pub const INT8: u32 = 1016;
        /// real (float4) 型の配列型の OID。
        pub const FLOAT4: u32 = 1021;
        /// double precision (float8) 型の配列型の OID。
        pub const FLOAT8: u32 = 1022;
        /// oid 型の配列型の OID。
        pub const OID: u32 = 1028;
        /// oid8 型の配列型の OID。PostgreSQL 19 で追加された。
        pub const OID8: u32 = 6442;
        /// date 型の配列型の OID。
        pub const DATE: u32 = 1182;
        /// time 型の配列型の OID。
        pub const TIME: u32 = 1183;
        /// timestamp 型の配列型の OID。
        pub const TIMESTAMP: u32 = 1115;
        /// timestamptz 型の配列型の OID。
        pub const TIMESTAMPTZ: u32 = 1185;
        /// numeric 型の配列型の OID。
        pub const NUMERIC: u32 = 1231;
        /// json 型の配列型の OID。
        pub const JSON: u32 = 199;
        /// jsonb 型の配列型の OID。
        pub const JSONB: u32 = 3807;
        /// uuid 型の配列型の OID。
        pub const UUID: u32 = 2951;
        /// interval 型の配列型の OID。
        pub const INTERVAL: u32 = 1187;
        /// timetz 型の配列型の OID。
        pub const TIMETZ: u32 = 1270;
        /// inet 型の配列型の OID。
        pub const INET: u32 = 1041;
        /// cidr 型の配列型の OID。
        pub const CIDR: u32 = 651;
        /// macaddr 型の配列型の OID。
        pub const MACADDR: u32 = 1040;
        /// macaddr8 型の配列型の OID。
        pub const MACADDR8: u32 = 775;
        /// money 型の配列型の OID。
        pub const MONEY: u32 = 791;
        /// bit 型の配列型の OID。
        pub const BIT: u32 = 1561;
        /// varbit 型の配列型の OID。
        pub const VARBIT: u32 = 1563;
        /// xml 型の配列型の OID。
        pub const XML: u32 = 143;
        /// point 型の配列型の OID。
        pub const POINT: u32 = 1017;
        /// line 型の配列型の OID。
        pub const LINE: u32 = 629;
        /// lseg 型の配列型の OID。
        pub const LSEG: u32 = 1018;
        /// path 型の配列型の OID。
        pub const PATH: u32 = 1019;
        /// polygon 型の配列型の OID。
        pub const POLYGON: u32 = 1027;
        /// circle 型の配列型の OID。
        pub const CIRCLE: u32 = 719;
        /// tsvector 型の配列型の OID。
        pub const TSVECTOR: u32 = 3643;
        /// tsquery 型の配列型の OID。
        pub const TSQUERY: u32 = 3645;
        /// jsonpath 型の配列型の OID。
        pub const JSONPATH: u32 = 4073;
        /// pg_lsn 型の配列型の OID。
        pub const PG_LSN: u32 = 3221;
        /// xid8 型の配列型の OID。
        pub const XID8: u32 = 271;
        /// int4range 型の配列型の OID。
        pub const INT4RANGE: u32 = 3905;
        /// int8range 型の配列型の OID。
        pub const INT8RANGE: u32 = 3927;
        /// numrange 型の配列型の OID。
        pub const NUMRANGE: u32 = 3907;
        /// tsrange 型の配列型の OID。
        pub const TSRANGE: u32 = 3909;
        /// tstzrange 型の配列型の OID。
        pub const TSTZRANGE: u32 = 3911;
        /// daterange 型の配列型の OID。
        pub const DATERANGE: u32 = 3913;
        /// int4multirange 型の配列型の OID。
        pub const INT4MULTIRANGE: u32 = 6150;
        /// int8multirange 型の配列型の OID。
        pub const INT8MULTIRANGE: u32 = 6157;
        /// nummultirange 型の配列型の OID。
        pub const NUMMULTIRANGE: u32 = 6151;
        /// tsmultirange 型の配列型の OID。
        pub const TSMULTIRANGE: u32 = 6152;
        /// tstzmultirange 型の配列型の OID。
        pub const TSTZMULTIRANGE: u32 = 6153;
        /// datemultirange 型の配列型の OID。
        pub const DATEMULTIRANGE: u32 = 6155;
    }
}
