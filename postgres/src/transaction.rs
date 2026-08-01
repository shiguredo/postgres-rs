// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! トランザクション。
//!
//! `Connection::begin` で開始し、`commit` / `rollback` で終了する。
//! セーブポイントは `savepoint` / `rollback_to_savepoint` /
//! `release_savepoint` で扱う。
//!
//! `commit` / `rollback` のどちらも呼ばずに `Transaction` を破棄した場合は、
//! 次の `begin()` 時またはプールへの返却時にロールバックされる。

use crate::connection::Connection;
use shiguredo_postgres_core::constants::transaction_status;
use shiguredo_postgres_core::converters::Value;
use shiguredo_postgres_core::error::{Error, Result};

/// トランザクションの分離レベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl IsolationLevel {
    fn as_sql(self) -> &'static str {
        match self {
            IsolationLevel::ReadCommitted => "READ COMMITTED",
            IsolationLevel::RepeatableRead => "REPEATABLE READ",
            IsolationLevel::Serializable => "SERIALIZABLE",
        }
    }
}

/// トランザクションの開始オプション。
#[derive(Debug, Clone, Copy, Default)]
pub struct TxOptions {
    /// 分離レベル。`None` の場合はサーバーのデフォルトを使う。
    pub isolation_level: Option<IsolationLevel>,
    /// 読み取り専用トランザクションにするかどうか。
    pub read_only: bool,
    /// 遅延可能トランザクションにするかどうか。
    ///
    /// 分離レベルが SERIALIZABLE かつ読み取り専用のときだけ有効。
    pub deferrable: bool,
}

/// トランザクション。
pub struct Transaction<'a> {
    conn: &'a mut Connection,
    finished: bool,
}

impl<'a> Transaction<'a> {
    /// トランザクションを開始する。
    ///
    /// 既にトランザクション内の場合はエラーを返す。
    pub(crate) async fn begin(conn: &'a mut Connection) -> Result<Self> {
        Self::begin_with(conn, TxOptions::default()).await
    }

    /// オプションを指定してトランザクションを開始する。
    pub(crate) async fn begin_with(conn: &'a mut Connection, options: TxOptions) -> Result<Self> {
        // 破棄されたトランザクションを先にロールバックする。
        conn.rollback_dirty_transaction().await?;
        if conn.transaction_status() != transaction_status::IDLE {
            return Err(Error::interface(
                "Cannot begin a transaction while already in one",
            ));
        }
        let mut sql = String::from("BEGIN");
        let mut clauses = Vec::new();
        if let Some(level) = options.isolation_level {
            clauses.push(format!("ISOLATION LEVEL {}", level.as_sql()));
        }
        if options.read_only {
            clauses.push("READ ONLY".to_string());
        }
        if options.deferrable {
            clauses.push("DEFERRABLE".to_string());
        }
        if !clauses.is_empty() {
            sql.push(' ');
            sql.push_str(&clauses.join(" "));
        }
        conn.query(&sql, false).await?;
        Ok(Self {
            conn,
            finished: false,
        })
    }

    /// トランザクションをコミットする。
    pub async fn commit(mut self) -> Result<()> {
        self.finished = true;
        self.conn.query("COMMIT", false).await?;
        tracing::debug!("Transaction committed");
        Ok(())
    }

    /// トランザクションをロールバックする。
    pub async fn rollback(mut self) -> Result<()> {
        self.finished = true;
        self.conn.query("ROLLBACK", false).await?;
        tracing::debug!("Transaction rolled back");
        Ok(())
    }

    /// トランザクション内でパラメータ付きクエリを実行する (拡張クエリプロトコル)。
    pub async fn execute(&mut self, sql: &str, args: &[Value]) -> Result<i64> {
        self.conn.execute(sql, args, false).await
    }

    /// トランザクション内でクエリを実行する (単純クエリプロトコル)。
    pub async fn query(&mut self, sql: &str, unbuffered: bool) -> Result<i64> {
        self.conn.query(sql, unbuffered).await
    }

    /// セーブポイントを作成する。
    ///
    /// `name` は SQL 識別子としてそのまま埋め込まれるため、
    /// 識別子として有効な名前を渡すこと。
    /// `rollback_to_savepoint` でセーブポイントまで戻り、
    /// `release_savepoint` でセーブポイントを破棄する。
    pub async fn savepoint(&mut self, name: &str) -> Result<()> {
        let sql = format!("SAVEPOINT {}", name);
        self.conn.query(&sql, false).await.map(|_| ())
    }

    /// セーブポイントまでロールバックする。
    ///
    /// セーブポイント作成後の変更は破棄されるが、
    /// トランザクション自体は継続する。
    pub async fn rollback_to_savepoint(&mut self, name: &str) -> Result<()> {
        let sql = format!("ROLLBACK TO SAVEPOINT {}", name);
        self.conn.query(&sql, false).await.map(|_| ())
    }

    /// セーブポイントを破棄する。
    pub async fn release_savepoint(&mut self, name: &str) -> Result<()> {
        let sql = format!("RELEASE SAVEPOINT {}", name);
        self.conn.query(&sql, false).await.map(|_| ())
    }

    /// 内部の接続への可変参照を取得する。
    ///
    /// トランザクション内でカーソル等を使用する場合に使う。
    pub fn conn(&mut self) -> &mut Connection {
        self.conn
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // 非同期コンテキスト外のためここではロールバックできない。
            // 次の begin() またはプールへの返却時にロールバックされる。
            tracing::warn!("Transaction dropped without commit or rollback");
            self.conn.mark_transaction_dirty();
        }
    }
}
