// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL クエリ結果読み込み。

use crate::constants::backend;
use crate::converters::{Value, decoder_for};
use crate::error::{Error, Result};
use crate::protocol::{
    CommandComplete, DataRowRef, ErrorResponse, FieldDescription, ParameterDescription,
    ParameterStatus, PostgresPacket, ReadyForQuery, RowDescription,
};
use std::collections::{HashMap, VecDeque};

/// 結果セット読み込みの内部状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ReadState {
    /// 最初のメッセージを待っている。
    #[default]
    Initial,
    /// 行データを読み込み中。
    Rows,
    /// コマンド完了後、次の結果セットまたは ReadyForQuery を待っている。
    ///
    /// 単純クエリプロトコルで複数ステートメントを送った場合に、
    /// ここで次の結果セットの開始を検出する。
    CommandComplete,
    /// 行記述を受信済みで、アンバッファードの行を読み込める。
    UnbufferedReady,
    /// 読み込み完了。
    Done,
}

/// 1 メッセージを処理した後の結果読み込み状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedResult {
    /// さらにメッセージが必要。
    NeedMore,
    /// 結果セットの読み込みが完了。
    Done,
    /// アンバッファードクエリの 1 行読み込みが完了。
    UnbufferedReady,
}

/// 1 つの結果セット (フィールド + 行)。
///
/// 単純クエリプロトコルで複数ステートメントを送った場合、
/// `QueryResult` が複数の結果セットを持つことがある。
#[derive(Debug, Clone)]
pub struct RowSet {
    /// 結果セットのフィールド情報。
    pub fields: Vec<FieldDescription>,
    /// 結果セットの行データ。各行はフィールド順の値を持つ。
    pub rows: Vec<Vec<Value>>,
    /// 結果セットで影響を受けた行数。
    pub affected_rows: i64,
    /// コマンド完了タグ (`SELECT 5` 等)。
    pub tag: Option<String>,
}

/// クエリ結果を表現する構造体。
///
/// `fields` / `rows` / `affected_rows` / `tag` は現在の結果セットを指す。
/// 追加の結果セットがある場合は `next_rowset()` で順に切り替える。
#[derive(Debug, Default, Clone)]
pub struct QueryResult {
    /// 現在の結果セットで影響を受けた行数。
    pub affected_rows: i64,
    /// サーバーのトランザクション状態。`ReadyForQuery` の受信時に設定される。
    pub transaction_status: Option<u8>,
    /// 現在の結果セットのフィールド情報。
    pub fields: Vec<FieldDescription>,
    /// 現在の結果セットの行データ。各行はフィールド順の値を持つ。
    pub rows: Vec<Vec<Value>>,
    /// 現在の結果セットのコマンド完了タグ (`SELECT 5` 等)。
    pub tag: Option<String>,
    /// アンバッファードクエリの実行中かどうか。
    pub unbuffered_active: bool,
    /// プリペアドステートメントのパラメータ型 OID。
    ///
    /// パラメータ記述メッセージを受信したときに設定される。
    /// 通常のクエリ実行では使われない。
    pub parameter_oids: Vec<u32>,
    /// ユーザーが登録した型 OID ごとのデコーダ。
    ///
    /// 接続からコピーされ、組み込みのデコーダより優先される。
    pub(crate) custom_decoders: HashMap<u32, crate::converters::Converter>,
    /// 追加の結果セット。`next_rowset()` で現在の結果セットと入れ替える。
    rowsets: VecDeque<RowSet>,
    read_state: ReadState,
    /// コマンド完了で結果セットの読み込みを完了するかどうか。
    ///
    /// バッチクエリの途中のステートメントで使う。通常のクエリでは
    /// ReadyForQuery まで待つため false。
    pub(crate) stop_at_command_complete: bool,
}

impl QueryResult {
    /// 新規の結果セットを作成する。
    pub fn new() -> Self {
        Self::default()
    }

    /// 結果セットの読み込みが完了しているかどうか。
    pub fn is_done(&self) -> bool {
        self.read_state == ReadState::Done
    }

    /// 最初のメッセージを待っている状態かどうか。
    pub(crate) fn is_initial(&self) -> bool {
        self.read_state == ReadState::Initial
    }

    /// 追加の結果セットが存在するかどうか。
    pub fn has_next_rowset(&self) -> bool {
        !self.rowsets.is_empty()
    }

    /// 現在の結果セットを追加の結果セットに切り替える。
    ///
    /// 追加の結果セットが存在する場合は現在の結果セットを置き換えて
    /// `true` を返し、存在しない場合は `false` を返す。
    pub fn next_rowset(&mut self) -> bool {
        let Some(rowset) = self.rowsets.pop_front() else {
            return false;
        };
        self.fields = rowset.fields;
        self.rows = rowset.rows;
        self.affected_rows = rowset.affected_rows;
        self.tag = rowset.tag;
        true
    }

    /// 読み込み完了後、最初の結果セットを現在の結果セットに戻す。
    ///
    /// 複数結果セットの読み込みが完了した時点では最後の結果セットが
    /// 現在の結果セットになっているため、最初の結果セットに戻す。
    /// 呼び出し側は `next_rowset()` で順に次の結果セットへ進める。
    pub(crate) fn rewind_to_first_rowset(&mut self) {
        if self.rowsets.is_empty() {
            return;
        }
        self.rowsets.push_back(RowSet {
            fields: std::mem::take(&mut self.fields),
            rows: std::mem::take(&mut self.rows),
            affected_rows: self.affected_rows,
            tag: self.tag.take(),
        });
        let first = self
            .rowsets
            .pop_front()
            .expect("rowsets is not empty as checked above");
        self.fields = first.fields;
        self.rows = first.rows;
        self.affected_rows = first.affected_rows;
        self.tag = first.tag;
    }

    /// 1 メッセージを消費して結果セットを組み立てる。
    ///
    /// 追加のメッセージが必要な場合は `FeedResult::NeedMore` を返す。
    pub fn feed_packet(&mut self, packet: PostgresPacket) -> Result<FeedResult> {
        match self.read_state {
            ReadState::Initial => self.feed_initial(packet),
            ReadState::Rows => self.feed_row(packet),
            ReadState::CommandComplete => self.feed_command_complete(packet),
            ReadState::UnbufferedReady => self.feed_row(packet),
            ReadState::Done => Ok(FeedResult::Done),
        }
    }

    fn feed_initial(&mut self, packet: PostgresPacket) -> Result<FeedResult> {
        match packet.message_type {
            // 行記述。SELECT 等の行を返すクエリで送られる。
            backend::ROW_DESCRIPTION => {
                let description = RowDescription::parse(&packet)?;
                self.fields = description.fields;
                if self.unbuffered_active {
                    self.read_state = ReadState::UnbufferedReady;
                    Ok(FeedResult::UnbufferedReady)
                } else {
                    self.read_state = ReadState::Rows;
                    Ok(FeedResult::NeedMore)
                }
            }
            // コマンド完了。行を返さないクエリ (INSERT 等) で送られる。
            backend::COMMAND_COMPLETE => {
                self.finish_command(packet)?;
                self.after_command_complete()
            }
            // 空クエリ応答。空文字列のクエリで送られる。
            backend::EMPTY_QUERY_RESPONSE => self.after_command_complete(),
            // 拡張クエリプロトコルの前段メッセージはスキップする。
            backend::PARSE_COMPLETE | backend::BIND_COMPLETE | backend::NO_DATA => {
                Ok(FeedResult::NeedMore)
            }
            // パラメータ記述。プリペアドステートメントの準備時に送られる。
            backend::PARAMETER_DESCRIPTION => {
                let description = ParameterDescription::parse(&packet)?;
                self.parameter_oids = description.type_oids;
                Ok(FeedResult::NeedMore)
            }
            // 通知応答・非同期通知はクエリの結果とは無関係なのでスキップする。
            // 例: DROP TABLE は NOTICE を送る場合がある。
            backend::NOTICE_RESPONSE | backend::NOTIFICATION_RESPONSE => Ok(FeedResult::NeedMore),
            backend::PARAMETER_STATUS => {
                check_parameter_status(&packet)?;
                Ok(FeedResult::NeedMore)
            }
            // クエリ処理可能。コマンドの区切りを示し、これで完了する。
            backend::READY_FOR_QUERY => {
                self.finish_ready(&packet)?;
                Ok(FeedResult::Done)
            }
            backend::ERROR_RESPONSE => {
                let response = ErrorResponse::parse(&packet)?;
                Err(crate::error::from_error_response(&response))
            }
            _ => Err(protocol_error(&packet)),
        }
    }

    fn feed_row(&mut self, packet: PostgresPacket) -> Result<FeedResult> {
        match packet.message_type {
            backend::DATA_ROW => {
                let row = self.read_row(packet)?;
                if self.unbuffered_active {
                    self.rows = vec![row];
                    self.read_state = ReadState::UnbufferedReady;
                    Ok(FeedResult::UnbufferedReady)
                } else {
                    self.rows.push(row);
                    Ok(FeedResult::NeedMore)
                }
            }
            // コマンド完了。この後も ReadyForQuery が送られるため、
            // ここでは完了せずに ReadyForQuery を待つ。
            backend::COMMAND_COMPLETE => {
                self.finish_command(packet)?;
                self.after_command_complete()
            }
            backend::READY_FOR_QUERY => {
                self.finish_ready(&packet)?;
                Ok(FeedResult::Done)
            }
            backend::ERROR_RESPONSE => {
                let response = ErrorResponse::parse(&packet)?;
                Err(crate::error::from_error_response(&response))
            }
            // 通知応答・非同期通知はクエリの結果とは無関係なのでスキップする。
            backend::NOTICE_RESPONSE | backend::NOTIFICATION_RESPONSE => Ok(FeedResult::NeedMore),
            backend::PARAMETER_STATUS => {
                check_parameter_status(&packet)?;
                Ok(FeedResult::NeedMore)
            }
            _ => Err(protocol_error(&packet)),
        }
    }

    /// コマンド完了後のメッセージを処理する。
    ///
    /// 単純クエリプロトコルで複数ステートメントを送った場合は、
    /// 次のステートメントの開始 (行記述・コマンド完了・空クエリ応答) で
    /// 現在の結果セットを追加の結果セットに退避する。
    fn feed_command_complete(&mut self, packet: PostgresPacket) -> Result<FeedResult> {
        match packet.message_type {
            backend::ROW_DESCRIPTION => {
                self.push_rowset();
                let description = RowDescription::parse(&packet)?;
                self.fields = description.fields;
                if self.unbuffered_active {
                    self.read_state = ReadState::UnbufferedReady;
                    Ok(FeedResult::UnbufferedReady)
                } else {
                    self.read_state = ReadState::Rows;
                    Ok(FeedResult::NeedMore)
                }
            }
            // 行を返さないステートメント (INSERT 等) が続く場合。
            backend::COMMAND_COMPLETE => {
                self.push_rowset();
                self.finish_command(packet)?;
                self.after_command_complete()
            }
            backend::EMPTY_QUERY_RESPONSE => {
                self.push_rowset();
                self.after_command_complete()
            }
            backend::READY_FOR_QUERY => {
                self.finish_ready(&packet)?;
                Ok(FeedResult::Done)
            }
            backend::ERROR_RESPONSE => {
                let response = ErrorResponse::parse(&packet)?;
                Err(crate::error::from_error_response(&response))
            }
            backend::NOTICE_RESPONSE | backend::NOTIFICATION_RESPONSE => Ok(FeedResult::NeedMore),
            backend::PARAMETER_STATUS => {
                check_parameter_status(&packet)?;
                Ok(FeedResult::NeedMore)
            }
            _ => Err(protocol_error(&packet)),
        }
    }

    /// 実行が完了し、最後の Sync の応答を待っているかどうかを返す。
    pub(super) fn command_completed(&self) -> bool {
        self.read_state == ReadState::CommandComplete
    }

    /// ReadyForQuery を受け取り、結果セットの読み込みを完了する。
    fn finish_ready(&mut self, packet: &PostgresPacket) -> Result<()> {
        let ready = ReadyForQuery::parse(packet)?;
        self.transaction_status = Some(ready.transaction_status);
        self.read_state = ReadState::Done;
        self.unbuffered_active = false;
        Ok(())
    }

    /// コマンド完了後の共通処理。
    ///
    /// バッチクエリの途中のステートメントはここで完了し、
    /// それ以外は次の結果セットまたは ReadyForQuery を待つ。
    fn after_command_complete(&mut self) -> Result<FeedResult> {
        if self.stop_at_command_complete {
            self.read_state = ReadState::Done;
            Ok(FeedResult::Done)
        } else {
            self.read_state = ReadState::CommandComplete;
            Ok(FeedResult::NeedMore)
        }
    }

    /// 現在の結果セットを追加の結果セットとして退避して初期化する。
    fn push_rowset(&mut self) {
        self.rowsets.push_back(RowSet {
            fields: std::mem::take(&mut self.fields),
            rows: std::mem::take(&mut self.rows),
            affected_rows: self.affected_rows,
            tag: self.tag.take(),
        });
        self.affected_rows = 0;
    }

    /// コマンド完了メッセージを処理する。
    ///
    /// 影響を受けた行数とタグを記録する。完了状態には遷移しない。
    /// 完了は ReadyForQuery メッセージで通知される。
    fn finish_command(&mut self, packet: PostgresPacket) -> Result<()> {
        let command = CommandComplete::parse(&packet)?;
        // 行数の解析を先に済ませてからタグを移動する。クローンしない。
        self.affected_rows = parse_affected_rows(&command.tag);
        self.tag = Some(command.tag);
        Ok(())
    }

    /// データ行メッセージから行を読み取る。
    fn read_row(&self, packet: PostgresPacket) -> Result<Vec<Value>> {
        // 本文への借用として値を読む。行の復号では値を Value に変換するため、
        // 所有する解析を挟むと値ごとにコピーが 2 回になる。
        let row = DataRowRef::parse_ref(&packet)?;
        // libpq の getAnotherTuple は、行の列数が RowDescription のフィールド数と
        // 一致しないメッセージを "unexpected field count in D message" として拒否する。
        // 一致しないまま復号すると、列名から引く値とフィールドの対応が崩れるか、
        // 存在しない列へのアクセスでパニックしうるため、同じ条件で拒否する。
        if row.values.len() != self.fields.len() {
            return Err(Error::internal(format!(
                "Unexpected field count in DataRow message: got {}, expected {}",
                row.values.len(),
                self.fields.len()
            )));
        }
        // クエリ実行時は結果形式コードを 0 件 (すべてテキスト) で要求している。
        // サーバーがバイナリ形式を返した場合、テキストとして復号すると値が壊れるか、
        // NUL を含む文字列として黙って通るため、復号の前に拒否する。
        if let Some(field) = self.fields.iter().find(|field| field.format != 0) {
            return Err(Error::internal(format!(
                "Unexpected result format: got {}, expected 0 (text) for type OID {}",
                field.format, field.type_oid
            )));
        }
        let mut values = Vec::new();
        // 列数は一致しているため、フィールドと値の対応はそのまま先頭から順に取れる。
        for (field, value) in self.fields.iter().zip(row.values.iter()) {
            // ユーザーが登録したデコーダを組み込みのデコーダより優先する。
            let decoder = self
                .custom_decoders
                .get(&field.type_oid)
                .copied()
                .unwrap_or_else(|| decoder_for(field.type_oid));
            match value {
                None => values.push(Value::Null),
                Some(bytes) => {
                    let s = std::str::from_utf8(bytes).map_err(|e| {
                        Error::internal(format!("Invalid UTF-8 in data row: {}", e))
                    })?;
                    values.push(decoder(s));
                }
            }
        }
        Ok(values)
    }

    /// アンバッファードクエリで次の行を読み込む。
    ///
    /// 戻り値は読み込んだ行で、結果セットの末尾 (コマンド完了) の場合は `None`。
    /// 最後に読み込んだ行は互換性のため `rows` にも保持する。
    pub fn read_rowdata_packet_unbuffered(
        &mut self,
        packet: PostgresPacket,
    ) -> Result<Option<Vec<Value>>> {
        let row = self.read_unbuffered_packet(packet)?;
        if let Some(row) = &row {
            self.rows = vec![row.clone()];
        }
        Ok(row)
    }

    fn read_unbuffered_packet(&mut self, packet: PostgresPacket) -> Result<Option<Vec<Value>>> {
        match packet.message_type {
            backend::DATA_ROW => self.read_row(packet).map(Some),
            // コマンド完了の後も ReadyForQuery までは接続が使用中である。
            backend::COMMAND_COMPLETE => {
                self.finish_command(packet)?;
                self.read_state = ReadState::CommandComplete;
                Ok(None)
            }
            backend::READY_FOR_QUERY => {
                self.finish_ready(&packet)?;
                Ok(None)
            }
            backend::NOTICE_RESPONSE | backend::NOTIFICATION_RESPONSE => Ok(None),
            backend::PARAMETER_STATUS => {
                check_parameter_status(&packet)?;
                Ok(None)
            }
            backend::ERROR_RESPONSE => {
                let response = ErrorResponse::parse(&packet)?;
                Err(crate::error::from_error_response(&response))
            }
            _ => Err(protocol_error(&packet)),
        }
    }

    /// 接続から行を 1 行読み、行セットの末尾では同期まで進める。
    pub(crate) fn read_next_unbuffered(
        &mut self,
        conn: &mut crate::connection::Connection,
    ) -> Result<Option<Vec<Value>>> {
        if !self.unbuffered_active {
            return Ok(None);
        }
        while self.read_state == ReadState::UnbufferedReady {
            if let Some(packet) = conn.read_query_packet()?
                && let Some(row) = self.read_unbuffered_packet(packet)?
            {
                return Ok(Some(row));
            }
        }
        self.finish_unbuffered(conn)?;
        Ok(None)
    }

    /// アンバッファードクエリを終了し、残りの行を読み飛ばす。
    ///
    /// 後続の結果セットもデコードせずに捨て、ReadyForQuery まで読み込む。
    /// サーバーのエラーや `Error::NeedMoreData` で中断した場合は再開できる。
    pub fn finish_unbuffered(&mut self, conn: &mut crate::connection::Connection) -> Result<()> {
        // PostgreSQL 18 公式文書 §54.2.2 と §54.2.6 のとおり、単純クエリは
        // ひとつの ReadyForQuery まで複数の結果や COPY OUT を返しうる。
        // 将来のプロトコルで応答が増えた場合は、捨ててよいものか見直す。
        while !self.is_done() {
            let Some(packet) = conn.read_query_packet()? else {
                continue;
            };
            match packet.message_type {
                backend::COMMAND_COMPLETE if self.read_state != ReadState::CommandComplete => {
                    // 最初の結果セットのコマンドタグと影響行数だけを残す。
                    self.finish_command(packet)?;
                    self.read_state = ReadState::CommandComplete;
                }
                backend::READY_FOR_QUERY => self.finish_ready(&packet)?,
                backend::ERROR_RESPONSE => {
                    let response = ErrorResponse::parse(&packet)?;
                    return Err(crate::error::from_error_response(&response));
                }
                backend::DATA_ROW
                | backend::ROW_DESCRIPTION
                | backend::COMMAND_COMPLETE
                | backend::EMPTY_QUERY_RESPONSE
                | backend::COPY_OUT_RESPONSE
                | backend::COPY_DATA
                | backend::COPY_DONE => {}
                _ => return Err(protocol_error(&packet)),
            }
        }
        Ok(())
    }
}

/// コマンドタグから影響を受けた行数を取り出す。
///
/// タグの形式は `SELECT 5` / `INSERT 0 5` / `UPDATE 3` のように
/// 最後の空白区切りの要素が行数になる。
/// 行数を含まないタグ (`CREATE TABLE` 等) は 0 を返す。
fn parse_affected_rows(tag: &str) -> i64 {
    tag.rsplit(' ')
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

/// 結果に直接供給された ParameterStatus を検査する。
///
/// [`Connection`](crate::connection::Connection) を経由する読み込みでは、接続が先に
/// ParameterStatus を処理するため、ここには届かない。結果に直接供給された場合も、
/// 行の復号の前提を崩す値を拒否する。
fn check_parameter_status(packet: &PostgresPacket) -> Result<()> {
    super::check_session_parameter(&ParameterStatus::parse(packet)?)
}

/// 予期しないメッセージのプロトコルエラーを生成する。
fn protocol_error(packet: &PostgresPacket) -> Error {
    Error::internal(format!(
        "Unexpected message during query result: '{}' (0x{:02x})",
        packet.message_type as char, packet.message_type
    ))
}
