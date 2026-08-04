// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tokio 上で動作する PostgreSQL クライアント。
//!
//! sans I/O なプロトコル実装 (`shiguredo_postgres_core`) は内部実装であり、
//! 利用者は本クレートだけに依存すればよい。プロトコル実装の公開 API は
//! 以下のモジュールとして再エクスポートされる。
//!
//! - [`constants`] - プロトコル定数 (メッセージ種別・型 OID 等)
//! - [`converters`] - 値の変換 (`Value` 等)
//! - [`error`] - エラー型
//! - [`protocol`] - ワイヤプロトコルのメッセージとレスポンス型
//!
//! TCP/TLS 接続および入出力は本クレートが担当する。

pub use shiguredo_postgres_core::constants;
pub use shiguredo_postgres_core::converters;
pub use shiguredo_postgres_core::error;
pub use shiguredo_postgres_core::protocol;

pub mod batch;
pub mod connection;
pub mod cursor;
pub mod pool;
pub mod transaction;
