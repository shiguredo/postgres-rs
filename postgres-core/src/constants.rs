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
    pub const BOOL: u32 = 16;
    pub const BYTEA: u32 = 17;
    pub const CHAR: u32 = 18;
    pub const NAME: u32 = 19;
    pub const INT8: u32 = 20;
    pub const INT2: u32 = 21;
    pub const INT4: u32 = 23;
    pub const OID: u32 = 26;
    pub const TEXT: u32 = 25;
    pub const JSON: u32 = 114;
    pub const JSONB: u32 = 3802;
    pub const FLOAT4: u32 = 700;
    pub const FLOAT8: u32 = 701;
    pub const NUMERIC: u32 = 1700;
    pub const BPCHAR: u32 = 1042;
    pub const VARCHAR: u32 = 1043;
    pub const DATE: u32 = 1082;
    pub const TIME: u32 = 1083;
    pub const TIMESTAMP: u32 = 1114;
    pub const TIMESTAMPTZ: u32 = 1184;
    pub const UUID: u32 = 2950;

    /// 組み込み型の配列型 OID。
    ///
    /// サーバーは配列の要素型をクライアントに直接送らないため、
    /// 配列型 OID から要素型 OID への対応をクライアント側で持つ。
    /// ここにない配列型 (独自型・複合型の配列) はテキストとして扱う。
    pub mod array {
        pub const BOOL: u32 = 1000;
        pub const BYTEA: u32 = 1001;
        pub const CHAR: u32 = 1002;
        pub const NAME: u32 = 1003;
        pub const INT2: u32 = 1005;
        pub const INT4: u32 = 1007;
        pub const TEXT: u32 = 1009;
        pub const BPCHAR: u32 = 1014;
        pub const VARCHAR: u32 = 1015;
        pub const INT8: u32 = 1016;
        pub const FLOAT4: u32 = 1021;
        pub const FLOAT8: u32 = 1022;
        pub const OID: u32 = 1028;
        pub const DATE: u32 = 1182;
        pub const TIME: u32 = 1183;
        pub const TIMESTAMP: u32 = 1115;
        pub const TIMESTAMPTZ: u32 = 1185;
        pub const NUMERIC: u32 = 1231;
        pub const JSON: u32 = 199;
        pub const JSONB: u32 = 3807;
        pub const UUID: u32 = 2951;
    }
}
