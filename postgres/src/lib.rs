// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! tokio 上で動作する PostgreSQL クライアント。
//!
//! `shiguredo_postgres` の sans I/O なプロトコル実装に対し、
//! TCP/TLS 接続および入出力を担当する。

pub mod batch;
pub mod connection;
pub mod cursor;
pub mod pool;
pub mod transaction;
