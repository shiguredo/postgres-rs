// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! カーソル実装。

use crate::connection::Connection;
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres_core::error::{Error, Result};
use shiguredo_postgres_core::protocol::FieldDescription;
use std::collections::HashMap;

/// 標準カーソル。
pub struct Cursor<'a> {
    connection: &'a mut Connection,
    fields: Vec<FieldDescription>,
    rows: Vec<Vec<Value>>,
    row_number: usize,
    row_count: i64,
    executed: bool,
    closed: bool,
}

impl<'a> Cursor<'a> {
    /// 新規カーソルを作成する。
    pub fn new(connection: &'a mut Connection) -> Self {
        Self {
            connection,
            fields: Vec::new(),
            rows: Vec::new(),
            row_number: 0,
            row_count: -1,
            executed: false,
            closed: false,
        }
    }

    /// カーソルを閉じる。
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        // 結果はバッファードで読み込み済みのため、読み残しの回収は不要。
        self.closed = true;
        Ok(())
    }

    fn check_closed(&self) -> Result<()> {
        if self.closed {
            Err(Error::InterfaceError {
                message: "Cursor closed".to_string(),
            })
        } else {
            Ok(())
        }
    }

    fn check_executed(&self) -> Result<()> {
        if !self.executed {
            Err(Error::InterfaceError {
                message: "execute() first".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// パラメータ付きクエリを実行する (拡張クエリプロトコル)。
    pub async fn execute(&mut self, query: &str, args: &[Value]) -> Result<i64> {
        self.check_closed()?;
        let affected = self.connection.execute(query, args, false).await?;
        self.refresh_result();
        self.executed = true;
        Ok(affected)
    }

    /// クエリを実行する (単純クエリプロトコル)。
    pub async fn query(&mut self, query: &str) -> Result<i64> {
        self.check_closed()?;
        let affected = self.connection.query(query, false).await?;
        self.refresh_result();
        self.executed = true;
        Ok(affected)
    }

    fn refresh_result(&mut self) {
        let result = self.connection.result().cloned();
        if let Some(result) = result {
            self.row_count = result.affected_rows;
            self.fields = result.fields.clone();
            self.rows = result.rows.clone();
            self.row_number = 0;
        }
    }

    /// 結果セットのフィールド情報を取得する。
    pub fn description(&self) -> &[FieldDescription] {
        &self.fields
    }

    /// 影響を受けた行数を取得する。
    pub fn row_count(&self) -> i64 {
        self.row_count
    }

    /// 次の行を取得する。
    pub fn fetch_one(&mut self) -> Result<Option<&Vec<Value>>> {
        self.check_executed()?;
        if self.row_number >= self.rows.len() {
            Ok(None)
        } else {
            let row = &self.rows[self.row_number];
            self.row_number += 1;
            Ok(Some(row))
        }
    }

    /// 指定行数だけ取得する。
    pub fn fetch_many(&mut self, size: usize) -> Result<Vec<&Vec<Value>>> {
        self.check_executed()?;
        let end = (self.row_number + size).min(self.rows.len());
        let result: Vec<_> = self.rows[self.row_number..end].iter().collect();
        self.row_number = end;
        Ok(result)
    }

    /// 全行を取得する。
    pub fn fetch_all(&mut self) -> Result<Vec<&Vec<Value>>> {
        self.check_executed()?;
        let result: Vec<_> = self.rows[self.row_number..].iter().collect();
        self.row_number = self.rows.len();
        Ok(result)
    }
}

/// 辞書形式で結果を返すカーソル。
pub struct DictCursor<'a> {
    inner: Cursor<'a>,
    fields: Vec<String>,
    fields_dirty: bool,
}

impl<'a> DictCursor<'a> {
    pub fn new(cursor: Cursor<'a>) -> Self {
        Self {
            inner: cursor,
            fields: Vec::new(),
            fields_dirty: true,
        }
    }

    fn build_fields(&mut self) {
        self.fields = self
            .inner
            .description()
            .iter()
            .map(|d| d.name.clone())
            .collect();
    }

    fn ensure_fields(&mut self) {
        if self.fields_dirty {
            self.build_fields();
            self.fields_dirty = false;
        }
    }

    /// パラメータ付きクエリを実行する (拡張クエリプロトコル)。
    pub async fn execute(&mut self, query: &str, args: &[Value]) -> Result<i64> {
        let affected = self.inner.execute(query, args).await?;
        self.fields_dirty = true;
        Ok(affected)
    }

    /// クエリを実行する (単純クエリプロトコル)。
    pub async fn query(&mut self, query: &str) -> Result<i64> {
        let affected = self.inner.query(query).await?;
        self.fields_dirty = true;
        Ok(affected)
    }

    /// カーソルを閉じる。
    pub async fn close(&mut self) -> Result<()> {
        self.inner.close().await
    }

    /// 次の行を辞書形式で取得する。
    pub fn fetch_one(&mut self) -> Result<Option<HashMap<String, Value>>> {
        self.ensure_fields();
        match self.inner.fetch_one()? {
            None => Ok(None),
            Some(row) => {
                let mut dict = HashMap::new();
                for (field, value) in self.fields.iter().zip(row.iter()) {
                    dict.insert(field.clone(), value.clone());
                }
                Ok(Some(dict))
            }
        }
    }

    /// 指定行数だけ辞書形式で取得する。
    pub fn fetch_many(&mut self, size: usize) -> Result<Vec<HashMap<String, Value>>> {
        let mut result = Vec::new();
        for _ in 0..size {
            match self.fetch_one()? {
                Some(row) => result.push(row),
                None => break,
            }
        }
        Ok(result)
    }

    /// 全行を辞書形式で取得する。
    pub fn fetch_all(&mut self) -> Result<Vec<HashMap<String, Value>>> {
        let mut result = Vec::new();
        while let Some(row) = self.fetch_one()? {
            result.push(row);
        }
        Ok(result)
    }
}
