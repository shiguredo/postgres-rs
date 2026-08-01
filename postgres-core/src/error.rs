// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 関連のエラー型。

use crate::protocol::ErrorResponse;
use std::fmt;

/// 結果型のエイリアス。
pub type Result<T> = std::result::Result<T, Error>;

/// サーバーから送られたエラーの詳細情報。
///
/// `code` はサーバーから返された SQLSTATE コードである。
/// `detail` / `hint` / `position` / `constraint` 等は
/// サーバーがエラー応答で送ってきた詳細情報である。
///
/// エラーのサイズを小さく保つため `Box` で包む。
#[derive(Debug, Clone)]
pub struct ServerErrorInfo {
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<String>,
    pub constraint: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
}

impl ServerErrorInfo {
    /// クライアント側エラーのための空の詳細情報を生成する。
    fn client_side(message: String) -> Self {
        Self {
            code: String::new(),
            message,
            detail: None,
            hint: None,
            position: None,
            constraint: None,
            schema: None,
            table: None,
            column: None,
        }
    }
}

/// PostgreSQL 関連の全エラーを表す列挙型。
#[derive(Debug)]
pub enum Error {
    /// 汎用データベースエラー。
    DatabaseError(Box<ServerErrorInfo>),

    /// データ関連エラー (クラス 22: データ例外)。
    DataError(Box<ServerErrorInfo>),

    /// 運用エラー (クラス 08: 接続例外など)。
    OperationalError(Box<ServerErrorInfo>),

    /// 整合性エラー (クラス 23: 整合性制約違反)。
    IntegrityError(Box<ServerErrorInfo>),

    /// 内部エラー (クラス XX: 内部エラー)。
    InternalError(Box<ServerErrorInfo>),

    /// プログラミングエラー (クラス 42: 構文エラーまたはアクセスルール違反など)。
    ProgrammingError(Box<ServerErrorInfo>),

    /// 未サポートエラー (クラス 0A: 機能がサポートされていない)。
    NotSupportedError(Box<ServerErrorInfo>),

    /// インターフェイス関連エラー (クライアント側)。
    InterfaceError { message: String },

    /// さらにデータが必要 (Sans I/O 層の状態信号)。
    ///
    /// 受信キューに完全なメッセージが蓄積されるまで呼び出し側が
    /// バイト列を供給してから再度処理を再開する。
    NeedMoreData,

    /// OAuth 認証で新しいトークンが必要 (Sans I/O 層の状態信号)。
    ///
    /// サーバーがトークンを拒否した。呼び出し側は新しいトークンを取得し、
    /// 接続を張り直して認証を再開する。
    NeedOAuthToken,
}

impl Error {
    /// クライアント側のインターフェイスエラーを生成する。
    ///
    /// 引数の不正・プロトコルの誤用等、呼び出し側に原因があるエラーに使う。
    pub fn interface(message: impl Into<String>) -> Self {
        Error::InterfaceError {
            message: message.into(),
        }
    }

    /// クライアント側の内部エラーを生成する。
    ///
    /// サーバー由来の詳細情報は存在しないため、すべて `None` になる。
    pub fn internal(message: impl Into<String>) -> Self {
        Error::InternalError(Box::new(ServerErrorInfo::client_side(message.into())))
    }

    /// クライアント側の運用エラーを生成する。
    ///
    /// 接続が確立できない等、サーバー由来でないエラーに使う。
    pub fn operational(message: impl Into<String>) -> Self {
        Error::OperationalError(Box::new(ServerErrorInfo::client_side(message.into())))
    }

    /// クライアント側の未サポートエラーを生成する。
    pub fn not_supported(message: impl Into<String>) -> Self {
        Error::NotSupportedError(Box::new(ServerErrorInfo::client_side(message.into())))
    }

    /// SQLSTATE コードを取得する。
    ///
    /// クライアント側で発生したエラーの場合は `None` を返す。
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => Some(&info.code),
            Error::InterfaceError { .. } | Error::NeedMoreData | Error::NeedOAuthToken => None,
        }
    }

    /// エラーメッセージを取得する。
    pub fn message(&self) -> &str {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => &info.message,
            Error::InterfaceError { message } => message,
            Error::NeedMoreData => "Need more data",
            Error::NeedOAuthToken => "Need OAuth token",
        }
    }

    /// サーバーから送られたエラーの詳細情報を取得する。
    pub fn detail(&self) -> Option<&str> {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => info.detail.as_deref(),
            Error::InterfaceError { .. } | Error::NeedMoreData | Error::NeedOAuthToken => None,
        }
    }

    /// サーバーから送られたヒントを取得する。
    pub fn hint(&self) -> Option<&str> {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => info.hint.as_deref(),
            Error::InterfaceError { .. } | Error::NeedMoreData | Error::NeedOAuthToken => None,
        }
    }

    /// エラーが発生したクエリ内の位置 (1 から始まる文字位置) を取得する。
    pub fn position(&self) -> Option<&str> {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => info.position.as_deref(),
            Error::InterfaceError { .. } | Error::NeedMoreData | Error::NeedOAuthToken => None,
        }
    }

    /// 違反した制約名を取得する。
    pub fn constraint(&self) -> Option<&str> {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => info.constraint.as_deref(),
            Error::InterfaceError { .. } | Error::NeedMoreData | Error::NeedOAuthToken => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DatabaseError(info)
            | Error::DataError(info)
            | Error::OperationalError(info)
            | Error::IntegrityError(info)
            | Error::InternalError(info)
            | Error::ProgrammingError(info)
            | Error::NotSupportedError(info) => write!(f, "{}: {}", info.code, info.message),
            Error::InterfaceError { message } => write!(f, "{}", message),
            Error::NeedMoreData => write!(f, "Need more data"),
            Error::NeedOAuthToken => write!(f, "Need OAuth token"),
        }
    }
}

impl std::error::Error for Error {}

/// サーバーからのエラー応答を適切なエラーに変換する。
///
/// SQLSTATE コードのクラス (先頭 2 文字) に基づいてエラー種別を分類する。
/// 分類は PostgreSQL ドキュメント付録 A のエラーコード表と、
/// psycopg2 のエラー分類に従う。
/// この分類は将来の PostgreSQL バージョンで新しいクラスが追加された場合に
/// 変わる可能性がある。
pub fn from_error_response(response: &ErrorResponse) -> Error {
    let info = Box::new(ServerErrorInfo {
        code: response.code.clone(),
        message: response.message.clone(),
        detail: response.detail.clone(),
        hint: response.hint.clone(),
        position: response.position.clone(),
        constraint: response.constraint.clone(),
        schema: response.schema.clone(),
        table: response.table.clone(),
        column: response.column.clone(),
    });
    let class: String = info.code.chars().take(2).collect();
    match class.as_str() {
        // クラス 08: 接続例外
        "08" => Error::OperationalError(info),
        // クラス 0A: 機能がサポートされていない
        "0A" => Error::NotSupportedError(info),
        // クラス 22: データ例外
        "22" => Error::DataError(info),
        // クラス 23: 整合性制約違反
        "23" => Error::IntegrityError(info),
        // クラス 42: 構文エラーまたはアクセスルール違反
        "42" => Error::ProgrammingError(info),
        // クラス XX: 内部エラー
        "XX" => Error::InternalError(info),
        // クラス 20-44 の構文・プログラミング系エラー
        "20" | "21" | "24" | "25" | "26" | "27" | "28" | "2B" | "2D" | "2F" | "34" | "38"
        | "39" | "3B" | "3D" | "3F" | "40" | "44" => Error::ProgrammingError(info),
        // クラス 53-58, F0 の運用系エラー
        "53" | "54" | "55" | "57" | "58" | "F0" => Error::OperationalError(info),
        _ => Error::DatabaseError(info),
    }
}
