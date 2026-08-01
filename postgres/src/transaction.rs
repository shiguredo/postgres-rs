// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! トランザクション。
//!
//! `Connection::begin` で開始し、`commit` / `rollback` で終了する。
//! セーブポイントは `savepoint` / `rollback_to_savepoint` /
//! `release_savepoint` で扱う。
//!
//! 終了が確認されないまま `Transaction` を破棄した場合は、
//! 次の `begin()` 時またはプールへの返却時に必要に応じてロールバックされる。
//! 終了処理の中断などでプロトコルが未同期の接続は再利用できない場合がある。

use crate::connection::Connection;
use crate::constants::transaction_status;
use crate::converters::Value;
use crate::error::{Error, Result};

/// トランザクションの分離レベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// `READ COMMITTED`。各文の開始時点のスナップショットを見る。
    ReadCommitted,
    /// `REPEATABLE READ`。トランザクション内の最初の文の時点のスナップショットを見る。
    RepeatableRead,
    /// `SERIALIZABLE`。直列実行した場合と同じ結果になることを保証する。
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
    ///
    /// 先行する文のエラーなどによりサーバーが代わりにロールバックした場合は、
    /// コミットが行われなかったことをエラーとして返す。
    /// この Future を中断した場合は、サーバー側でコミット済みの可能性がある。
    pub async fn commit(mut self) -> Result<()> {
        self.finish("COMMIT").await?;
        tracing::debug!("Transaction committed");
        Ok(())
    }

    /// トランザクションをロールバックする。
    ///
    /// ロールバックの完了を確認できない場合はエラーを返す。
    pub async fn rollback(mut self) -> Result<()> {
        self.finish("ROLLBACK").await?;
        tracing::debug!("Transaction rolled back");
        Ok(())
    }

    /// 終了コマンドを送り、コマンドタグと接続の同期状態を確認する。
    async fn finish(&mut self, command: &str) -> Result<()> {
        self.conn.query(command, false).await?;

        // PostgreSQL 18 文書 54.7 節の CommandComplete と ReadyForQuery を確認する。
        // サーバー実装 utility.c の standard_ProcessUtility は、失敗済みの
        // トランザクションに対する COMMIT に ROLLBACK タグを返す。
        // このタグの扱いは将来の PostgreSQL で変わる可能性がある。
        let tag = self.conn.result().and_then(|result| result.tag.as_deref());
        if command == "COMMIT" && tag == Some("ROLLBACK") {
            return Err(Error::operational(
                "PostgreSQL rolled back the transaction instead of committing it",
            ));
        }
        if tag != Some(command) {
            return Err(Error::internal(format!(
                "Unexpected command tag for {command}: {tag:?}"
            )));
        }
        if !self.conn.is_open()
            || self.conn.is_busy()
            || self.conn.transaction_status() != transaction_status::IDLE
        {
            return Err(Error::internal(format!(
                "Connection did not become idle after {command}"
            )));
        }

        // 終了を確認する前に失敗・中断した場合は、Drop で dirty を記録する。
        self.finished = true;
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
    /// `name` は引用符を付けずに渡す。大文字・小文字は区別し、空の名前と NUL は拒否する。
    /// `rollback_to_savepoint` でセーブポイントまで戻り、
    /// `release_savepoint` でセーブポイントを破棄する。
    pub async fn savepoint(&mut self, name: &str) -> Result<()> {
        let sql = savepoint_sql("SAVEPOINT", name)?;
        self.conn.query(&sql, false).await.map(|_| ())
    }

    /// セーブポイントまでロールバックする。
    ///
    /// セーブポイント作成後の変更は破棄されるが、
    /// トランザクション自体は継続する。
    pub async fn rollback_to_savepoint(&mut self, name: &str) -> Result<()> {
        let sql = savepoint_sql("ROLLBACK TO SAVEPOINT", name)?;
        self.conn.query(&sql, false).await.map(|_| ())
    }

    /// セーブポイントを破棄する。
    pub async fn release_savepoint(&mut self, name: &str) -> Result<()> {
        let sql = savepoint_sql("RELEASE SAVEPOINT", name)?;
        self.conn.query(&sql, false).await.map(|_| ())
    }

    /// 内部の接続への可変参照を取得する。
    ///
    /// トランザクション内でカーソル等を使用する場合に使う。
    pub fn conn(&mut self) -> &mut Connection {
        self.conn
    }
}

/// 操作名は呼び出し側の固定文字列、利用者入力は単一の引用済み識別子にする。
fn savepoint_sql(command: &str, name: &str) -> Result<String> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(Error::interface(
            "Savepoint name must be non-empty and contain no NUL bytes",
        ));
    }
    // PostgreSQL 18 §4.1.1 の引用規則に従う。将来、識別子の構文が変わる可能性がある。
    let quoted = name.replace('"', "\"\"");
    Ok(format!("{command} \"{quoted}\""))
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Drop からは非同期処理を待てないため、次の begin() または
            // プールへの返却時の処理に委ねる。
            self.conn.mark_transaction_dirty();
            tracing::warn!("Transaction dropped without confirmed completion");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::savepoint_sql;

    #[test]
    fn test_savepoint_identifier() {
        // 識別子内の二重引用符は重ね、両端を引用符で囲む。
        let sql = savepoint_sql("SAVEPOINT", "Phase \"One\"").expect("識別子を引用できません");
        assert_eq!(sql, "SAVEPOINT \"Phase \"\"One\"\"\"");
        for name in ["", "name\0suffix"] {
            assert!(
                savepoint_sql("SAVEPOINT", name).is_err(),
                "不正な識別子を受理しました"
            );
        }
    }
}
