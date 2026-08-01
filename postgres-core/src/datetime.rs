// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL の日付・時刻型。
//!
//! `DATE` / `TIME` / `TIMESTAMP` / `TIMESTAMPTZ` を、PostgreSQL 18 の内部表現で保持する。
//! 有限の日付は 2000-01-01 からの日数、有限の時刻は深夜からのマイクロ秒、
//! 有限のタイムスタンプは 2000-01-01 00:00:00 からのマイクロ秒である。
//! 暦はプロレプティック・グレゴリオ暦で、閏秒の挿入表は持たない。1 日は常に 86400 秒。
//! 時計もタイムゾーンデータベースも読まない。入出力は呼び出し側のバイト列だけである。
//!
//! 定数と算法は `src/include/datatype/timestamp.h`、`src/include/utils/date.h`、
//! `src/backend/utils/adt/datetime.c`、`date.c`、`timestamp.c` に合わせている。
//! 将来の版で変わる可能性がある。

mod date;
mod julian;
mod text;
mod time;
mod timestamp;

pub use date::{Date, FiniteDate};
pub use time::Time;
pub use timestamp::{FiniteTimestamp, FiniteTimestamptz, Timestamp, Timestamptz};
