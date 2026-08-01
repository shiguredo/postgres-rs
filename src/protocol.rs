// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL ワイヤプロトコルのメッセージ実装。
//!
//! 仕様は PostgreSQL 公式ドキュメントの「Frontend/Backend Protocol」に基づく。
//! <https://www.postgresql.org/docs/current/protocol.html>
//! プロトコルは PostgreSQL 16 時点の内容であり、将来のバージョンで
//! メッセージが追加・変更される可能性がある。
//!
//! フレーム形式:
//! - スタートアップフェーズ: 4 バイト長さ (自身を含む) + ペイロード
//! - 通常メッセージ: 1 バイトタイプ + 4 バイト長さ (自身を含む) + ペイロード
//! - SSL 要求への応答: タイプ 1 バイトのみ (長さヘッダーなし)
//!
//! 数値はすべてビッグエンディアンで、長さは自身を含むバイト数を表す。

use crate::constants::backend;
use crate::error::{Error, Result};
use std::str;

/// 受信したメッセージを表現する構造体。
#[derive(Debug, Clone)]
pub struct PostgresPacket {
    pub message_type: u8,
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

/// パスワードメッセージを組み立てる。
pub fn password_message(password: &[u8]) -> Vec<u8> {
    let mut payload = password.to_vec();
    payload.push(0);
    frontend_message(crate::constants::frontend::PASSWORD, &payload)
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
    payload.extend_from_slice(&(parameter_types.len() as i16).to_be_bytes());
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

    payload.extend_from_slice(&(parameters.len() as i16).to_be_bytes());
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
    pub code: u32,
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
    pub name: String,
    pub value: String,
}

impl ParameterStatus {
    /// パラメータステータスメッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::PARAMETER_STATUS)?;
        let mut reader = Reader::new(&packet.data);
        let name = reader.read_cstring()?;
        let value = reader.read_cstring()?;
        Ok(Self { name, value })
    }
}

/// バックエンドキーデータメッセージ。
#[derive(Debug, Clone)]
pub struct BackendKeyData {
    pub process_id: u32,
    pub secret_key: u32,
}

impl BackendKeyData {
    /// バックエンドキーデータメッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::BACKEND_KEY_DATA)?;
        let mut reader = Reader::new(&packet.data);
        let process_id = reader.read_u32()?;
        let secret_key = reader.read_u32()?;
        Ok(Self {
            process_id,
            secret_key,
        })
    }
}

/// クエリ処理可能メッセージ。
#[derive(Debug, Clone)]
pub struct ReadyForQuery {
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
    pub name: String,
    pub table_oid: u32,
    pub column_attr: i16,
    pub type_oid: u32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: i16,
}

/// 行記述メッセージ。
#[derive(Debug, Clone)]
pub struct RowDescription {
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
        Ok(Self { fields })
    }
}

/// データ行メッセージ。
#[derive(Debug, Clone)]
pub struct DataRow {
    pub values: Vec<Option<Vec<u8>>>,
}

impl DataRow {
    /// データ行メッセージを解析する。
    ///
    /// 値の長さが -1 の場合は SQL NULL を表す。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::DATA_ROW)?;
        let mut reader = Reader::new(&packet.data);
        let column_count = reader.read_u16()?;
        let mut values = Vec::new();
        for _ in 0..column_count {
            let length = reader.read_i32()?;
            if length < 0 {
                values.push(None);
            } else {
                let value = reader.read_bytes(length as usize)?.to_vec();
                values.push(Some(value));
            }
        }
        Ok(Self { values })
    }
}

/// コマンド完了メッセージ。
#[derive(Debug, Clone)]
pub struct CommandComplete {
    pub tag: String,
}

impl CommandComplete {
    /// コマンド完了メッセージを解析する。
    pub fn parse(packet: &PostgresPacket) -> Result<Self> {
        check_message_type(packet, backend::COMMAND_COMPLETE)?;
        let mut reader = Reader::new(&packet.data);
        let tag = reader.read_cstring()?;
        Ok(Self { tag })
    }
}

/// パラメータ記述メッセージ。
#[derive(Debug, Clone)]
pub struct ParameterDescription {
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
        Ok(Self { type_oids })
    }
}

/// エラー応答メッセージ。
///
/// フィールドの詳細は PostgreSQL ドキュメントの
/// 「Error and Notice Message Fields」を参照。
#[derive(Debug, Clone, Default)]
pub struct ErrorResponse {
    pub severity: String,
    pub severity_nonlocalized: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub constraint: Option<String>,
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
    pub severity: String,
    pub severity_nonlocalized: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
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
    while let Ok(field_type) = reader.read_u8() {
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
            b's' => response.schema = Some(content),
            b't' => response.table = Some(content),
            b'c' => response.column = Some(content),
            b'n' => response.constraint = Some(content),
            _ => {}
        }
    }
    Ok(response)
}

/// メッセージタイプが期待通りか確認する。
fn check_message_type(packet: &PostgresPacket, expected: u8) -> Result<()> {
    if packet.message_type != expected {
        return Err(Error::InternalError {
            code: String::new(),
            message: format!(
                "Unexpected message type: got '{}' (0x{:02x}), expected '{}'",
                packet.message_type as char, packet.message_type, expected as char
            ),
        });
    }
    Ok(())
}

/// 不正なプロトコルデータを表すエラーを生成する。
fn malformed(message: impl Into<String>) -> Error {
    Error::InternalError {
        code: String::new(),
        message: message.into(),
    }
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

    /// 残りのデータをすべて読み込む。
    fn read_all(&mut self) -> &'a [u8] {
        let result = &self.data[self.position..];
        self.position = self.data.len();
        result
    }
}
