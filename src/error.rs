// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL 関連のエラー型。

use crate::protocol::ErrorResponse;
use std::fmt;

/// 結果型のエイリアス。
pub type Result<T> = std::result::Result<T, Error>;

/// PostgreSQL 関連の全エラーを表す列挙型。
///
/// `code` はサーバーから返された SQLSTATE コードである。
/// クライアント側で発生したエラーの場合は空文字列となる。
#[derive(Debug)]
pub enum Error {
    /// 汎用データベースエラー。
    DatabaseError { code: String, message: String },

    /// データ関連エラー (クラス 22: データ例外)。
    DataError { code: String, message: String },

    /// 運用エラー (クラス 08: 接続例外など)。
    OperationalError { code: String, message: String },

    /// 整合性エラー (クラス 23: 整合性制約違反)。
    IntegrityError { code: String, message: String },

    /// 内部エラー (クラス XX: 内部エラー)。
    InternalError { code: String, message: String },

    /// プログラミングエラー (クラス 42: 構文エラーまたはアクセスルール違反など)。
    ProgrammingError { code: String, message: String },

    /// 未サポートエラー (クラス 0A: 機能がサポートされていない)。
    NotSupportedError { code: String, message: String },

    /// インターフェイス関連エラー (クライアント側)。
    InterfaceError { message: String },

    /// さらにデータが必要 (Sans I/O 層の状態信号)。
    ///
    /// 受信キューに完全なメッセージが蓄積されるまで呼び出し側が
    /// バイト列を供給してから再度処理を再開する。
    NeedMoreData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DatabaseError { code, message }
            | Error::DataError { code, message }
            | Error::OperationalError { code, message }
            | Error::IntegrityError { code, message }
            | Error::InternalError { code, message }
            | Error::ProgrammingError { code, message }
            | Error::NotSupportedError { code, message } => write!(f, "{}: {}", code, message),
            Error::InterfaceError { message } => write!(f, "{}", message),
            Error::NeedMoreData => write!(f, "Need more data"),
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
    let code = response.code.clone();
    let message = response.message.clone();
    let class: String = code.chars().take(2).collect();
    match class.as_str() {
        // クラス 08: 接続例外
        "08" => Error::OperationalError { code, message },
        // クラス 0A: 機能がサポートされていない
        "0A" => Error::NotSupportedError { code, message },
        // クラス 22: データ例外
        "22" => Error::DataError { code, message },
        // クラス 23: 整合性制約違反
        "23" => Error::IntegrityError { code, message },
        // クラス 42: 構文エラーまたはアクセスルール違反
        "42" => Error::ProgrammingError { code, message },
        // クラス XX: 内部エラー
        "XX" => Error::InternalError { code, message },
        // クラス 20-44 の構文・プログラミング系エラー
        "20" | "21" | "24" | "25" | "26" | "27" | "28" | "2B" | "2D" | "2F" | "34" | "38"
        | "39" | "3B" | "3D" | "3F" | "40" | "44" => Error::ProgrammingError { code, message },
        // クラス 53-58, F0 の運用系エラー
        "53" | "54" | "55" | "57" | "58" | "F0" => Error::OperationalError { code, message },
        _ => Error::DatabaseError { code, message },
    }
}
