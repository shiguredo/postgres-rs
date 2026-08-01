// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sans I/O な PostgreSQL プロトコル実装。
//!
//! 実際の TCP/TLS 入出力は呼び出し側が担当する。

pub mod auth;
pub mod connection;
pub mod constants;
pub mod converters;
pub mod error;
pub mod protocol;
