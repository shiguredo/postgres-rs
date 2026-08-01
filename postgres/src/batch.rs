// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! バッチクエリ。
//!
//! 複数のステートメントをまとめて 1 往復で送信するために使う。
//! 実行は `Connection::batch_execute` で行う。

use shiguredo_postgres_core::converters::Value;

/// バッチクエリ。
#[derive(Debug, Clone, Default)]
pub struct Batch {
    statements: Vec<(String, Vec<Value>)>,
}

impl Batch {
    /// 空のバッチを作成する。
    pub fn new() -> Self {
        Self::default()
    }

    /// ステートメントを追加する。
    ///
    /// `sql` は `$1` 形式のパラメータを含むことができる。
    pub fn append(&mut self, sql: &str, parameters: &[Value]) {
        self.statements.push((sql.to_string(), parameters.to_vec()));
    }

    /// バッチ内のステートメント数を返す。
    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// バッチが空かどうかを返す。
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// バッチ内のステートメントのリストを消費して返す。
    pub(crate) fn into_statements(self) -> Vec<(String, Vec<Value>)> {
        self.statements
    }
}
