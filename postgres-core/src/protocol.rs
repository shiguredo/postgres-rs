// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL ワイヤプロトコルのメッセージ実装。
//!
//! 仕様は PostgreSQL 18 公式ドキュメントの「Frontend/Backend Protocol」に基づく。
//! <https://www.postgresql.org/docs/18/protocol.html>
//! スタートアップ時はプロトコルバージョン 3.0 を指定する。
//! 将来のバージョンではメッセージが追加・変更される可能性がある。
//!
//! フレーム形式:
//! - スタートアップフェーズ: 4 バイト長さ (自身を含む) + ペイロード
//! - 通常メッセージ: 1 バイトタイプ + 4 バイト長さ (自身を含む) + ペイロード
//! - SSL 要求への応答: タイプ 1 バイトのみ (長さヘッダーなし)
//!
//! 数値はすべてビッグエンディアンで、長さは自身を含むバイト数を表す。
//!
//! 公開のメッセージ組み立て関数は低レベル API で、入力は検査しない。
//! 終端の扱いやサーバーの受信上限を含む送信前の検査は
//! [`Connection`](crate::connection::Connection) が行う。

use crate::constants::backend;
use crate::error::{Error, Result};
use std::str;

// PostgreSQL 18 公式文書 §54.4 と §54.5 のメッセージ形式に従う。
// 長さフィールドは Int32 であり、自身を含むがメッセージタイプは含まない。
const LENGTH_FIELD_SIZE: usize = 4;

// PostgreSQL 実装はワイヤ形式の表現上限より小さい受信上限を持つ。
// src/include/libpq/libpq.h の PQ_LARGE_MESSAGE_LIMIT (MaxAllocSize - 1) と
// PQ_SMALL_MESSAGE_LIMIT、および src/include/libpq/pqcomm.h の MAX_STARTUP_PACKET_LENGTH に基づく。
// 将来の PostgreSQL では、実装上限や各メッセージへの割り当てが変わる可能性がある。
const LARGE_MESSAGE_LIMIT: usize = (1 << 30) - 2;
const SMALL_MESSAGE_LIMIT: usize = 10_000;
// StartupMessage だけは長さフィールドを除いて上限を適用する。
const STARTUP_MESSAGE_LIMIT: usize = 10_000 + LENGTH_FIELD_SIZE;

/// フレームの各部分を加算し、Int32 の表現上限とサーバー実装の上限を確認する。
fn checked_frontend_length(
    message: &str,
    server_limit: usize,
    parts: impl IntoIterator<Item = usize>,
) -> Result<usize> {
    let limit = server_limit.min(i32::MAX as usize);
    parts
        .into_iter()
        .try_fold(0_usize, |sum, part| {
            sum.checked_add(part).filter(|&len| len <= limit)
        })
        .ok_or_else(|| Error::interface(format!("{message} message exceeds {limit} bytes")))
}

/// NUL 終端で送る文字列や、テキスト形式の Bind パラメータを確認する。
fn validate_no_nul(field: &str, value: &[u8]) -> Result<()> {
    if value.contains(&0) {
        return Err(Error::interface(format!("{field} must not contain NUL")));
    }
    Ok(())
}

/// StartupMessage のパラメータ名・値と送信長を検査する。
///
/// 空の名前、埋め込み NUL、または長さの上限超過は `Error::InterfaceError` を返す。
pub(crate) fn validate_startup(parameters: &[(&str, &str)]) -> Result<()> {
    // プロトコルバージョン 4 バイトと、パラメータ一覧の終端 NUL を含む。
    let mut len = LENGTH_FIELD_SIZE + 4 + 1;
    for (name, value) in parameters {
        if name.is_empty() {
            return Err(Error::interface("Startup parameter name must not be empty"));
        }
        len = checked_frontend_length(
            "StartupMessage",
            STARTUP_MESSAGE_LIMIT,
            [len, name.len(), 1, value.len(), 1],
        )?;
        validate_no_nul("Startup parameter name", name.as_bytes())?;
        validate_no_nul("Startup parameter value", value.as_bytes())?;
    }
    Ok(())
}

/// Query の SQL と送信長を検査する。
///
/// SQL に埋め込み NUL があるか長さの上限を超える場合は `Error::InterfaceError` を返す。
pub(crate) fn validate_query(sql: &str) -> Result<()> {
    checked_frontend_length(
        "Query",
        LARGE_MESSAGE_LIMIT,
        [LENGTH_FIELD_SIZE, sql.len(), 1],
    )?;
    validate_no_nul("Query SQL", sql.as_bytes())
}

/// Parse の名前、SQL、パラメータ型数と送信長を検査する。
///
/// 埋め込み NUL、または個数・長さの上限超過は `Error::InterfaceError` を返す。
pub(crate) fn validate_parse(statement: &str, sql: &str, parameter_types: &[u32]) -> Result<()> {
    let count = checked_parameter_count("Parse", parameter_types.len())?;
    // 型の個数は Int16、OID はそれぞれ Int32 に格納される。
    checked_frontend_length(
        "Parse",
        LARGE_MESSAGE_LIMIT,
        [
            LENGTH_FIELD_SIZE,
            statement.len(),
            1,
            sql.len(),
            1,
            2,
            count * 4,
        ],
    )?;
    validate_no_nul("Parse statement name", statement.as_bytes())?;
    validate_no_nul("Parse SQL", sql.as_bytes())
}

/// Bind のパラメータ数を、それらをエンコードする前に検査する。
///
/// 65,535 個を超える場合は `Error::InterfaceError` を返す。
pub(crate) fn validate_bind_parameter_count(count: usize) -> Result<()> {
    checked_parameter_count("Bind", count).map(|_| ())
}

/// サーバーの Parse / Bind は Int16 の個数フィールドを符号なしとして読む。
fn checked_parameter_count(message: &str, count: usize) -> Result<usize> {
    // src/backend/libpq/pqformat.c の pq_getmsgint および
    // src/interfaces/libpq/libpq-fe.h の PQ_QUERY_PARAM_MAX_LIMIT を参照。
    if count > usize::from(u16::MAX) {
        return Err(Error::interface(format!(
            "{message} parameter count exceeds {}",
            u16::MAX
        )));
    }
    Ok(count)
}

/// Bind の名前、テキストパラメータと送信長を検査する。
///
/// 埋め込み NUL、またはパラメータの個数・バイト数やフレーム長の上限超過は
/// `Error::InterfaceError` を返す。
pub(crate) fn validate_bind(
    portal: &str,
    statement: &str,
    parameters: &[Option<&[u8]>],
) -> Result<()> {
    validate_bind_parameter_count(parameters.len())?;
    // 2 つの名前の終端 NUL に加え、パラメータ形式数、値の数、結果形式数に各 2 バイト。
    let mut len = checked_frontend_length(
        "Bind",
        LARGE_MESSAGE_LIMIT,
        [
            LENGTH_FIELD_SIZE,
            portal.len(),
            1,
            statement.len(),
            1,
            2,
            2,
            2,
        ],
    )?;
    for parameter in parameters {
        // NULL も値の長さフィールドに -1 を格納するため 4 バイト必要。
        len = checked_bind_parameter_length(len, parameter.map_or(0, <[u8]>::len))?;
    }
    validate_no_nul("Bind portal name", portal.as_bytes())?;
    validate_no_nul("Bind statement name", statement.as_bytes())?;
    for value in parameters.iter().flatten() {
        // 値には長さが付くが、本エンコーダーはテキスト形式で送信する。
        // src/backend/tcop/postgres.c の exec_bind_message はテキストを文字コード変換し、型入力関数へ渡す。
        validate_no_nul("Bind text parameter", value)?;
    }
    Ok(())
}

/// Bind のパラメータ 1 個の長さと、長さフィールド込みの合計を検査する。
fn checked_bind_parameter_length(frame_len: usize, value_len: usize) -> Result<usize> {
    if value_len > i32::MAX as usize {
        return Err(Error::interface("Bind parameter length exceeds i32::MAX"));
    }
    checked_frontend_length("Bind", LARGE_MESSAGE_LIMIT, [frame_len, 4, value_len])
}

/// Close のステートメント名またはポータル名と送信長を検査する。
///
/// 埋め込み NUL や長さの上限超過は `Error::InterfaceError` を返す。
pub(crate) fn validate_close(name: &str) -> Result<()> {
    checked_frontend_length(
        "Close",
        SMALL_MESSAGE_LIMIT,
        [LENGTH_FIELD_SIZE, 1, name.len(), 1],
    )?;
    validate_no_nul("Close name", name.as_bytes())
}

/// CopyData のデータ長を検査する。データに含まれる NUL は検査対象外とする。
///
/// 上限超過は `Error::InterfaceError` を返す。大きなデータは複数のフレームに分けて送信できる。
pub(crate) fn validate_copy_data(len: usize) -> Result<()> {
    checked_frontend_length("CopyData", LARGE_MESSAGE_LIMIT, [LENGTH_FIELD_SIZE, len]).map(|_| ())
}

/// CopyFail の理由文字列と送信長を検査する。
///
/// 埋め込み NUL や長さの上限超過は `Error::InterfaceError` を返す。
pub(crate) fn validate_copy_fail(reason: &str) -> Result<()> {
    checked_frontend_length(
        "CopyFail",
        SMALL_MESSAGE_LIMIT,
        [LENGTH_FIELD_SIZE, reason.len(), 1],
    )?;
    validate_no_nul("CopyFail reason", reason.as_bytes())
}

/// 受信したメッセージを表現する構造体。
#[derive(Debug, Clone)]
pub struct PostgresPacket {
    /// メッセージタイプを表す 1 バイトの文字。
    pub message_type: u8,
    /// メッセージのペイロード (タイプバイトと長さフィールドを除く)。
    pub data: Vec<u8>,
}

/// スタートアップメッセージを組み立てる。
///
/// スタートアップメッセージのみタイプバイトを持たない。
/// パラメータは `(名前, 値)` のリストとして与える。
pub fn startup_message(parameters: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&crate::constants::PROTOCOL_VERSION.to_be_bytes());
    for (name, value) in parameters {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }
    payload.push(0);

    let mut message = Vec::new();
    let length = payload.len() as u32 + 4;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&payload);
    message
}

/// SSL 要求メッセージを組み立てる。
///
/// スタートアップメッセージと同様にタイプバイトを持たない。
/// サーバーは 'S' (SSL 対応) または 'N' (非対応) の 1 バイトで応答する。
pub fn ssl_request_message() -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&8_u32.to_be_bytes());
    message.extend_from_slice(&crate::constants::SSL_REQUEST_CODE.to_be_bytes());
    message
}

/// クエリメッセージを組み立てる (単純クエリプロトコル)。
pub fn query_message(sql: &str) -> Vec<u8> {
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    frontend_message(crate::constants::frontend::QUERY, &payload)
}

/// 明示したローカル開発接続にだけ使う平文パスワード応答を組み立てる。
pub(crate) fn password_message(password: &[u8]) -> Result<Vec<u8>> {
    // PostgreSQL 18 の recv_password_packet は PG_MAX_AUTH_TOKEN_LENGTH を適用し、空を拒否する。
    // サーバー側の上限や形式が将来変わったときはここも見直す。
    const MAX_AUTH_TOKEN_LENGTH: usize = 65_535;
    if password.is_empty() {
        return Err(Error::interface(
            "No password supplied for local authentication",
        ));
    }
    checked_frontend_length(
        "PasswordMessage",
        MAX_AUTH_TOKEN_LENGTH,
        [LENGTH_FIELD_SIZE, password.len(), 1],
    )?;
    validate_no_nul("PasswordMessage password", password)?;
    let mut payload = Vec::new();
    payload.extend_from_slice(password);
    payload.push(0);
    Ok(frontend_message(
        crate::constants::frontend::PASSWORD,
        &payload,
    ))
}

/// SASL 初期応答メッセージを組み立てる。
///
/// ペイロードはメカニズム名 (NUL 終端) + 初期応答の長さ + 初期応答本体。
pub fn sasl_initial_response(mechanism: &str, initial_response: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(mechanism.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&(initial_response.len() as i32).to_be_bytes());
    payload.extend_from_slice(initial_response);
    frontend_message(crate::constants::frontend::PASSWORD, &payload)
}

/// SASL 応答メッセージを組み立てる。
///
/// ペイロードは追加データそのもの (長さフィールドなし)。
/// PostgreSQL のサーバーは SASLInitialResponse 以降の 'p' メッセージを
/// ペイロード全体をそのまま SCRAM メッセージとして扱う
/// (`src/backend/libpq/auth-sasl.c` の `CheckSASLAuth` を参照)。
pub fn sasl_response(data: &[u8]) -> Vec<u8> {
    frontend_message(crate::constants::frontend::PASSWORD, data)
}

/// 終了メッセージを組み立てる。
pub fn terminate_message() -> Vec<u8> {
    frontend_message(crate::constants::frontend::TERMINATE, &[])
}

/// キャンセル要求メッセージを組み立てる。
///
/// スタートアップメッセージと同様にタイプバイトを持たない。
/// 進行中のクエリをキャンセルするために、別の TCP 接続から送信する。
/// `process_id` と `secret_key` は BackendKeyData メッセージで受信した値を使う。
pub fn cancel_request_message(process_id: u32, secret_key: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&crate::constants::CANCEL_REQUEST_CODE.to_be_bytes());
    payload.extend_from_slice(&process_id.to_be_bytes());
    payload.extend_from_slice(&secret_key.to_be_bytes());
    let mut message = Vec::new();
    let length = payload.len() as u32 + 4;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&payload);
    message
}

/// クローズメッセージを組み立てる (拡張クエリプロトコル)。
///
/// `kind` はステートメント ('S') またはポータル ('P')。
/// 名前付きステートメントの破棄に使う。
pub fn close_message(kind: u8, name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(kind);
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    frontend_message(crate::constants::frontend::CLOSE, &payload)
}

/// フラッシュメッセージを組み立てる (拡張クエリプロトコル)。
///
/// サーバーに送信済みメッセージの処理を強制させる。
pub fn flush_message() -> Vec<u8> {
    frontend_message(crate::constants::frontend::FLUSH, &[])
}

/// Copy データメッセージを組み立てる (COPY プロトコル)。
///
/// CopyIn 中にサーバーへデータを送信するために使う。
pub fn copy_data_message(data: &[u8]) -> Vec<u8> {
    frontend_message(crate::constants::frontend::COPY_DATA, data)
}

/// Copy 完了メッセージを組み立てる (COPY プロトコル)。
///
/// CopyIn のデータ送信完了をサーバーに通知する。
pub fn copy_done_message() -> Vec<u8> {
    frontend_message(crate::constants::frontend::COPY_DONE, &[])
}

/// Copy 失敗メッセージを組み立てる (COPY プロトコル)。
///
/// CopyIn をエラーで中断するために使う。エラーメッセージは NUL 終端文字列。
pub fn copy_fail_message(message: &str) -> Vec<u8> {
    let mut payload = message.as_bytes().to_vec();
    payload.push(0);
    frontend_message(crate::constants::frontend::COPY_FAIL, &payload)
}

/// パースメッセージを組み立てる (拡張クエリプロトコル)。
///
/// `parameter_types` が空の場合はサーバーに型推論を任せる。
/// 名前付きステートメントが必要ない場合は空文字列を渡す。
pub fn parse_message(statement: &str, query: &str, parameter_types: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(statement.as_bytes());
    payload.push(0);
    payload.extend_from_slice(query.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&(parameter_types.len() as u16).to_be_bytes());
    for oid in parameter_types {
        payload.extend_from_slice(&oid.to_be_bytes());
    }
    frontend_message(crate::constants::frontend::PARSE, &payload)
}

/// バインドメッセージを組み立てる (拡張クエリプロトコル)。
///
/// パラメータはテキスト形式で送信する。
/// `parameters` の `None` は SQL NULL を表す。
pub fn bind_message(portal: &str, statement: &str, parameters: &[Option<&[u8]>]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(portal.as_bytes());
    payload.push(0);
    payload.extend_from_slice(statement.as_bytes());
    payload.push(0);

    // パラメータ形式コード: 0 件 = すべてテキスト形式。
    payload.extend_from_slice(&0_i16.to_be_bytes());

    payload.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
    for parameter in parameters {
        match parameter {
            None => payload.extend_from_slice(&(-1_i32).to_be_bytes()),
            Some(value) => {
                payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
                payload.extend_from_slice(value);
            }
        }
    }

    // 結果形式コード: 0 件 = すべてテキスト形式。
    payload.extend_from_slice(&0_i16.to_be_bytes());

    frontend_message(crate::constants::frontend::BIND, &payload)
}

/// 記述メッセージを組み立てる (拡張クエリプロトコル)。
///
/// `kind` はステートメント ('S') またはポータル ('P')。
pub fn describe_message(kind: u8, name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(kind);
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    frontend_message(crate::constants::frontend::DESCRIBE, &payload)
}

/// 実行メッセージを組み立てる (拡張クエリプロトコル)。
///
/// `max_rows` が 0 の場合は全行を返す。
pub fn execute_message(portal: &str, max_rows: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(portal.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&max_rows.to_be_bytes());
    frontend_message(crate::constants::frontend::EXECUTE, &payload)
}

/// 同期メッセージを組み立てる (拡張クエリプロトコル)。
pub fn sync_message() -> Vec<u8> {
    frontend_message(crate::constants::frontend::SYNC, &[])
}

/// フロントエンドメッセージにフレームヘッダーを付与する。
fn frontend_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(message_type);
    let length = payload.len() as u32 + 4;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(payload);
    message
}

/// 認証要求メッセージ。
///
/// 認証方式コードに応じてデータが異なる。
/// - MD5 パスワード: 4 バイトのソルト
/// - SASL: サポートするメカニズム名のリスト (NUL 区切り、末尾に NUL)
/// - SASL 継続: サーバー最初のメッセージ
/// - SASL 最終: サーバー最終メッセージ
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    /// 認証方式コード (`constants::auth` の定数を参照)。
    pub code: u32,
    /// 認証方式に応じた付加データ。
    pub data: Vec<u8>,
}

impl AuthenticationRequest {
    /// 認証要求メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::AUTHENTICATION_REQUEST)?;
        let mut reader = Reader::new(&packet.data);
        let code = reader.read_u32()?;
        let data = reader.read_all().to_vec();
        Ok(Self { code, data })
    }

    /// 認証方式コードを返す。
    pub fn code(&self) -> u32 {
        self.code
    }

    /// SASL のメカニズム名のリストを返す。
    ///
    /// 認証方式コードが SASL でない場合は空リストを返す。
    pub fn mechanisms(&self) -> Vec<String> {
        self.data
            .split(|&b| b == 0)
            .filter(|m| !m.is_empty())
            .filter_map(|m| str::from_utf8(m).ok())
            .map(str::to_string)
            .collect()
    }

    /// ペイロード全体を UTF-8 文字列として返す。
    ///
    /// SASL 継続・最終メッセージは UTF-8 文字列として送信される。
    pub fn as_str(&self) -> Result<&str> {
        str::from_utf8(&self.data).map_err(|e| malformed(format!("Invalid UTF-8: {}", e)))
    }
}

/// パラメータステータスメッセージ。
#[derive(Debug, Clone)]
pub struct ParameterStatus {
    /// パラメータ名。
    pub name: String,
    /// パラメータ値。
    pub value: String,
}

impl ParameterStatus {
    /// パラメータステータスメッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::PARAMETER_STATUS)?;
        let mut reader = Reader::new(&packet.data);
        let name = reader.read_cstring()?;
        let value = reader.read_cstring()?;
        reader.finish()?;
        Ok(Self { name, value })
    }
}

/// バックエンドキーデータメッセージ。
#[derive(Debug, Clone)]
pub struct BackendKeyData {
    /// バックエンドプロセスの ID。
    pub process_id: u32,
    /// キャンセル要求で使う秘密キー。
    pub secret_key: u32,
}

impl BackendKeyData {
    /// バックエンドキーデータメッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::BACKEND_KEY_DATA)?;
        let mut reader = Reader::new(&packet.data);
        let process_id = reader.read_u32()?;
        let secret_key = reader.read_u32()?;
        // PostgreSQL 18 はプロトコル 3.0 ではキャンセルキーを 4 バイトで送る。
        // 3.2 以降に対応する場合は、ネゴシエーションと一緒にこの固定長を見直す。
        reader.finish()?;
        Ok(Self {
            process_id,
            secret_key,
        })
    }
}

/// クエリ処理可能メッセージ。
#[derive(Debug, Clone)]
pub struct ReadyForQuery {
    /// トランザクション状態 (`constants::transaction_status` の定数を参照)。
    pub transaction_status: u8,
}

impl ReadyForQuery {
    /// クエリ処理可能メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::READY_FOR_QUERY)?;
        if packet.data.len() != 1 {
            return Err(malformed(format!(
                "Invalid ReadyForQuery length: {}",
                packet.data.len()
            )));
        }
        Ok(Self {
            transaction_status: packet.data[0],
        })
    }
}

/// フィールド記述。
#[derive(Debug, Clone)]
pub struct FieldDescription {
    /// フィールド (カラム) 名。
    pub name: String,
    /// フィールドを持つテーブルの OID。
    pub table_oid: u32,
    /// テーブル内のカラム番号 (0 は式や計算結果)。
    pub column_attr: i16,
    /// フィールドのデータ型の OID。
    pub type_oid: u32,
    /// データ型のサイズ (バイト)。
    pub type_size: i16,
    /// データ型の型修飾子 (varchar の長さなど)。
    pub type_modifier: i32,
    /// 値の形式コード (0 はテキスト、1 はバイナリ)。
    pub format: i16,
}

/// 行記述メッセージ。
#[derive(Debug, Clone)]
pub struct RowDescription {
    /// フィールドごとの記述のリスト。
    pub fields: Vec<FieldDescription>,
}

impl RowDescription {
    /// 行記述メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::ROW_DESCRIPTION)?;
        let mut reader = Reader::new(&packet.data);
        let field_count = reader.read_u16()?;
        let mut fields = Vec::new();
        for _ in 0..field_count {
            let name = reader.read_cstring()?;
            let table_oid = reader.read_u32()?;
            let column_attr = reader.read_i16()?;
            let type_oid = reader.read_u32()?;
            let type_size = reader.read_i16()?;
            let type_modifier = reader.read_i32()?;
            let format = reader.read_i16()?;
            fields.push(FieldDescription {
                name,
                table_oid,
                column_attr,
                type_oid,
                type_size,
                type_modifier,
                format,
            });
        }
        reader.finish()?;
        Ok(Self { fields })
    }
}

/// データ行メッセージ。
#[derive(Debug, Clone)]
pub struct DataRow {
    /// カラムごとの値 (None は SQL NULL)。
    pub values: Vec<Option<Vec<u8>>>,
}

/// データ行メッセージの借用ビュー。
///
/// 行の復号では値を `Value` に変換するため、本文から直接借用して
/// 値ごとのコピーを 1 回に減らす。[`DataRow::parse`] はこの借用ビューに
/// 所有するコピーを重ねた形で、解析条件は同一である。
#[derive(Debug)]
pub struct DataRowRef<'a> {
    /// カラムごとの値 (None は SQL NULL)。
    pub values: Vec<Option<&'a [u8]>>,
}

impl<'a> DataRowRef<'a> {
    /// データ行メッセージを本文への借用として解析する。
    ///
    /// 値の長さが -1 の場合は SQL NULL を表す。
    /// 借用はパケット本文の生存期間に束ねられる。
    pub fn parse_ref(packet: &'a PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::DATA_ROW)?;
        let mut reader = Reader::new(&packet.data);
        let column_count = reader.read_u16()?;
        // 列数は受信した値のため、本文の長さを確かめる前に確保しない。
        let mut values = Vec::new();
        for _ in 0..column_count {
            let length = reader.read_i32()?;
            if length < 0 {
                values.push(None);
            } else {
                values.push(Some(reader.read_bytes(length as usize)?));
            }
        }
        reader.finish()?;
        Ok(Self { values })
    }
}

impl DataRow {
    /// データ行メッセージを解析する。
    ///
    /// 値の長さが -1 の場合は SQL NULL を表す。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        let referenced = DataRowRef::parse_ref(packet)?;
        Ok(Self {
            values: referenced
                .values
                .into_iter()
                .map(|value| value.map(<[u8]>::to_vec))
                .collect(),
        })
    }
}

/// コマンド完了メッセージ。
#[derive(Debug, Clone)]
pub struct CommandComplete {
    /// 実行されたコマンドを示す完了タグ (`INSERT 0 1` など)。
    pub tag: String,
}

impl CommandComplete {
    /// コマンド完了メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::COMMAND_COMPLETE)?;
        let mut reader = Reader::new(&packet.data);
        let tag = reader.read_cstring()?;
        reader.finish()?;
        Ok(Self { tag })
    }
}

/// パラメータ記述メッセージ。
#[derive(Debug, Clone)]
pub struct ParameterDescription {
    /// パラメータのデータ型 OID のリスト。
    pub type_oids: Vec<u32>,
}

impl ParameterDescription {
    /// パラメータ記述メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::PARAMETER_DESCRIPTION)?;
        let mut reader = Reader::new(&packet.data);
        let parameter_count = reader.read_u16()?;
        let mut type_oids = Vec::new();
        for _ in 0..parameter_count {
            type_oids.push(reader.read_u32()?);
        }
        reader.finish()?;
        Ok(Self { type_oids })
    }
}

/// エラー応答メッセージ。
///
/// フィールドの詳細は PostgreSQL ドキュメントの
/// 「Error and Notice Message Fields」を参照。
/// <https://www.postgresql.org/docs/current/protocol-error-fields.html>
#[derive(Debug, Clone, Default)]
pub struct ErrorResponse {
    /// エラーの重要度 (ERROR や FATAL など)。
    pub severity: String,
    /// ロケールに依存しない重要度。
    pub severity_nonlocalized: String,
    /// SQLSTATE コード。
    pub code: String,
    /// エラーメッセージ。
    pub message: String,
    /// エラーの詳細情報。
    pub detail: Option<String>,
    /// エラー解決のヒント。
    pub hint: Option<String>,
    /// クエリ文字列内のエラー位置。
    pub position: Option<String>,
    /// 内部クエリ内のエラー位置。
    pub internal_position: Option<String>,
    /// エラーの原因となった内部クエリ。
    pub internal_query: Option<String>,
    /// エラー発生時のコンテキスト。
    pub context: Option<String>,
    /// 関連するスキーマ名。
    pub schema: Option<String>,
    /// 関連するテーブル名。
    pub table: Option<String>,
    /// 関連するカラム名。
    pub column: Option<String>,
    /// 関連するデータ型名。
    pub data_type: Option<String>,
    /// 関連する制約名。
    pub constraint: Option<String>,
    /// エラーを報告したサーバー側ソースファイル名。
    pub file: Option<String>,
    /// エラーを報告したソースファイル内の行番号。
    pub line: Option<String>,
    /// エラーを報告したサーバー側ルーチン名。
    pub routine: Option<String>,
}

impl ErrorResponse {
    /// エラー応答メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::ERROR_RESPONSE)?;
        parse_field_response(&packet.data)
    }
}

/// 通知応答メッセージ。
///
/// エラー応答と同じフィールド形式を持つ。
#[derive(Debug, Clone, Default)]
pub struct NoticeResponse {
    /// 通知の重要度 (NOTICE や WARNING など)。
    pub severity: String,
    /// ロケールに依存しない重要度。
    pub severity_nonlocalized: String,
    /// SQLSTATE コード。
    pub code: String,
    /// 通知メッセージ。
    pub message: String,
    /// 通知の詳細情報。
    pub detail: Option<String>,
    /// 通知に関するヒント。
    pub hint: Option<String>,
    /// 通知発生時のコンテキスト。
    pub context: Option<String>,
}

impl NoticeResponse {
    /// 通知応答メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::NOTICE_RESPONSE)?;
        let response = parse_field_response(&packet.data)?;
        Ok(Self {
            severity: response.severity,
            severity_nonlocalized: response.severity_nonlocalized,
            code: response.code,
            message: response.message,
            detail: response.detail,
            hint: response.hint,
            context: response.context,
        })
    }
}

/// 非同期通知メッセージ。
///
/// LISTEN 中のチャネルに NOTIFY が送られたときに受信する。
#[derive(Debug, Clone)]
pub struct NotificationResponse {
    /// 通知を送信したバックエンドプロセスの ID。
    pub process_id: u32,
    /// 通知チャネル名。
    pub channel: String,
    /// 通知のペイロード。
    pub payload: String,
}

impl NotificationResponse {
    /// 非同期通知メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::NOTIFICATION_RESPONSE)?;
        let mut reader = Reader::new(&packet.data);
        let process_id = reader.read_u32()?;
        let channel = reader.read_cstring()?;
        let payload = reader.read_cstring()?;
        reader.finish()?;
        Ok(Self {
            process_id,
            channel,
            payload,
        })
    }
}

/// Copy 応答メッセージ (CopyIn / CopyOut / CopyBoth 共通の形式)。
///
/// COPY プロトコルの開始をサーバーが受け付けたときに送られる。
/// 全体の形式コード (0 はテキスト、1 はバイナリ) と、
/// カラムごとの形式コードを持つ。
#[derive(Debug, Clone)]
pub struct CopyResponse {
    /// 全体の形式コード (0 はテキスト、1 はバイナリ)。
    pub overall_format: u8,
    /// カラムごとの形式コード。
    pub column_formats: Vec<u16>,
}

impl CopyResponse {
    /// CopyIn 応答メッセージを解析する。
    pub fn parse_in(packet: &PostgresPacket) -> Result<Self> {
        Self::parse_common(packet, backend::COPY_IN_RESPONSE)
    }

    /// CopyOut 応答メッセージを解析する。
    pub fn parse_out(packet: &PostgresPacket) -> Result<Self> {
        Self::parse_common(packet, backend::COPY_OUT_RESPONSE)
    }

    /// CopyBoth 応答メッセージを解析する。
    pub fn parse_both(packet: &PostgresPacket) -> Result<Self> {
        Self::parse_common(packet, backend::COPY_BOTH_RESPONSE)
    }

    /// Copy 応答メッセージの共通解析処理。
    fn parse_common(packet: &PostgresPacket, expected: u8) -> Result<Self> {
        check_message_type(packet, expected)?;
        let mut reader = Reader::new(&packet.data);
        let overall_format = reader.read_u8()?;
        let column_count = reader.read_u16()?;
        let mut column_formats = Vec::new();
        for _ in 0..column_count {
            column_formats.push(reader.read_u16()?);
        }
        reader.finish()?;
        Ok(Self {
            overall_format,
            column_formats,
        })
    }
}

/// エラー応答・通知応答の共通フィールド解析。
///
/// フィールドは (タイプ 1 バイト, 内容 NUL 終端文字列) の繰り返しで、
/// 終端の 0 バイトで終わる。
fn parse_field_response(data: &[u8]) -> Result<ErrorResponse> {
    let mut reader = Reader::new(data);
    let mut response = ErrorResponse::default();
    loop {
        // PostgreSQL 18 §54.7 の応答では、最後のフィールドとは別に終端の 0 が必要。
        // フィールドの拡張は許すが、本文形式が変わった場合は終端条件も見直す。
        let field_type = reader.read_u8()?;
        if field_type == 0 {
            break;
        }
        let content = reader.read_cstring()?;
        match field_type {
            b'S' => response.severity = content,
            b'V' => response.severity_nonlocalized = content,
            b'C' => response.code = content,
            b'M' => response.message = content,
            b'D' => response.detail = Some(content),
            b'H' => response.hint = Some(content),
            b'P' => response.position = Some(content),
            b'p' => response.internal_position = Some(content),
            b'q' => response.internal_query = Some(content),
            b'W' => response.context = Some(content),
            b's' => response.schema = Some(content),
            b't' => response.table = Some(content),
            b'c' => response.column = Some(content),
            b'd' => response.data_type = Some(content),
            b'n' => response.constraint = Some(content),
            b'F' => response.file = Some(content),
            b'L' => response.line = Some(content),
            b'R' => response.routine = Some(content),
            _ => {}
        }
    }
    reader.finish()?;
    Ok(response)
}

/// メッセージタイプが期待通りか確認する。
fn check_message_type(packet: &PostgresPacket, expected: u8) -> Result<()> {
    if packet.message_type != expected {
        return Err(Error::internal(format!(
            "Unexpected message type: got '{}' (0x{:02x}), expected '{}'",
            packet.message_type as char, packet.message_type, expected as char
        )));
    }
    Ok(())
}

/// 不正なプロトコルデータを表すエラーを生成する。
fn malformed(message: impl Into<String>) -> Error {
    Error::internal(message.into())
}

/// バイト列を読み進めるためのリーダー。
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_i16(&mut self) -> Result<i16> {
        let bytes = self.read_bytes(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_bytes(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(size).ok_or_else(|| {
            malformed(format!(
                "Read size overflow: Position={}, Size={}",
                self.position, size
            ))
        })?;
        if end > self.data.len() {
            return Err(malformed(format!(
                "Insufficient data: Expected={}, Actual={}, Position={}, Data Length={}",
                size,
                self.data.len().saturating_sub(self.position),
                self.position,
                self.data.len()
            )));
        }
        let result = &self.data[self.position..end];
        self.position = end;
        Ok(result)
    }

    /// NUL 終端文字列を読み込む。
    ///
    /// NUL が見つからない場合はエラーを返す。
    fn read_cstring(&mut self) -> Result<String> {
        let end = self.data[self.position..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| {
                malformed(format!(
                    "Missing NUL terminator: Position={}",
                    self.position
                ))
            })?;
        let bytes = &self.data[self.position..self.position + end];
        self.position += end + 1;
        let s = str::from_utf8(bytes).map_err(|e| malformed(format!("Invalid UTF-8: {}", e)))?;
        Ok(s.to_string())
    }

    /// 構造化メッセージの本文を最後まで消費したことを確認する。
    fn finish(self) -> Result<()> {
        // PostgreSQL 18 の libpq は pqParseInput3 でカーソルと宣言長の一致を確認する。
        // 将来のプロトコルで本文が拡張された場合は、対応する解析処理も更新する。
        if self.position != self.data.len() {
            return Err(malformed("Unexpected trailing bytes in message body"));
        }
        Ok(())
    }

    /// 残りのデータをすべて読み込む。
    fn read_all(&mut self) -> &'a [u8] {
        let result = &self.data[self.position..];
        self.position = self.data.len();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_embedded_nul_in_text_fields() {
        // NUL 終端フィールドだけでなく、長さを持つテキスト形式の Bind 値も拒否する。
        let invalid = "a\0b";
        for result in [
            validate_startup(&[(invalid, "value")]),
            validate_startup(&[("name", invalid)]),
            validate_query(invalid),
            validate_parse(invalid, "", &[]),
            validate_parse("", invalid, &[]),
            validate_bind(invalid, "", &[]),
            validate_bind("", invalid, &[]),
            validate_bind("", "", &[Some(invalid.as_bytes())]),
            validate_close(invalid),
            validate_copy_fail(invalid),
        ] {
            assert!(
                matches!(result, Err(Error::InterfaceError { .. })),
                "埋め込み NUL はインターフェイスエラーになります: {result:?}"
            );
        }
    }

    #[test]
    fn checks_parameter_count_at_unsigned_16_bit_boundary() {
        // 32,767 ではなく 65,535 まで許可する。SQL NULL も 1 個に数える。
        let limit = usize::from(u16::MAX);
        let types = vec![0_u32; limit + 1];
        let parameters = vec![None; limit + 1];
        validate_parse("", "", &types[..limit]).expect("Parse の最大個数は許可されます");
        validate_bind("", "", &parameters[..limit]).expect("Bind の最大個数は許可されます");
        assert!(matches!(
            validate_parse("", "", &types),
            Err(Error::InterfaceError { .. })
        ));
        assert!(matches!(
            validate_bind("", "", &parameters),
            Err(Error::InterfaceError { .. })
        ));
    }

    #[test]
    fn checks_bind_parameter_length_and_accumulated_frame_length() {
        // 巨大なバッファーを確保せず、個別の Int32 上限とフレーム合計を別々に確認する。
        let error = checked_bind_parameter_length(12, i32::MAX as usize + 1)
            .expect_err("値の長さが Int32 に収まらない場合は拒否されます");
        assert_eq!(error.message(), "Bind parameter length exceeds i32::MAX");

        // 2 個の長さフィールドを加えるとちょうど上限となる長さを選ぶ。
        let limit = (1 << 30) - 2;
        let value_len = (limit - 12 - 8) / 2;
        let len = checked_bind_parameter_length(12, value_len).expect("1 個目の長さは有効です");
        assert_eq!(
            checked_bind_parameter_length(len, value_len).expect("合計が上限なら有効です"),
            limit
        );
        assert!(matches!(
            checked_bind_parameter_length(len, value_len + 1),
            Err(Error::InterfaceError { .. })
        ));
    }

    #[test]
    fn checks_server_message_size_boundaries_in_bytes() {
        // 3 バイトの文字を使い、文字数ではなくバイト数を制限することを確認する。
        let reason = "あ".repeat(3_331) + "ab";
        validate_copy_fail(&reason).expect("CopyFail の 9,995 バイトの理由は許可されます");
        assert!(matches!(
            validate_copy_fail(&(reason + "c")),
            Err(Error::InterfaceError { .. })
        ));
        validate_close(&"a".repeat(9_994)).expect("Close の名前が最大長の場合は許可されます");
        assert!(matches!(
            validate_close(&"a".repeat(9_995)),
            Err(Error::InterfaceError { .. })
        ));

        // Startup は 4 バイトの長さフィールドを除いた 10,000 バイトで制限される。
        // バージョン、終端 NUL 3 個、3 バイトの名前 'key' を値の長さから差し引く。
        let value = "a".repeat(9_990);
        validate_startup(&[("key", &value)]).expect("Startup の最大長は許可されます");
        assert!(matches!(
            validate_startup(&[("key", &(value + "b"))]),
            Err(Error::InterfaceError { .. })
        ));
        assert!(matches!(
            validate_startup(&[("", "value")]),
            Err(Error::InterfaceError { .. })
        ));

        // CopyData のデータ長に型バイトは足さず、長さフィールドの 4 バイトは足す。
        let data_limit = (1 << 30) - 2 - 4;
        validate_copy_data(data_limit).expect("CopyData の最大データ長は許可されます");
        for len in [data_limit + 1, usize::MAX] {
            assert!(matches!(
                validate_copy_data(len),
                Err(Error::InterfaceError { .. })
            ));
        }
    }
}
