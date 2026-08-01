// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL の `DATE`。
//!
//! 有限値は 2000-01-01 からの日数 (`DateADT`)。
//! 無限大は `DATEVAL_NOBEGIN` / `DATEVAL_NOEND` で、有限の範囲の外にある。

use super::julian::{self, DATE_INFINITY, DATE_NEG_INFINITY, POSTGRES_EPOCH_JDATE};
use super::text;

/// 有限の `DATE`。
///
/// 範囲は 4714-11-24 BC から 5874897-12-31 まで。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FiniteDate {
    /// 2000-01-01 からの日数。`IS_VALID_DATE` を満たす。
    days: i32,
}

impl FiniteDate {
    /// 2000-01-01 からの日数から作る。範囲外は `None`。
    pub fn from_postgres_days(days: i32) -> Option<Self> {
        if julian::is_valid_date(days) {
            Some(Self { days })
        } else {
            None
        }
    }

    /// 天文年の年月日から作る。
    ///
    /// 年 0 は 1 BC。存在しない日と `DATE` の範囲外は `None`。
    pub fn from_ymd(year: i32, month: u32, day: u32) -> Option<Self> {
        if !julian::is_valid_ymd(year, month, day) {
            return None;
        }
        let days = julian::date2j(year, month as i32, day as i32) - i64::from(POSTGRES_EPOCH_JDATE);
        let days = i32::try_from(days).ok()?;
        Self::from_postgres_days(days)
    }

    /// 2000-01-01 からの日数。
    pub fn postgres_days(self) -> i32 {
        self.days
    }

    /// ユリウス日。
    pub fn julian_day(self) -> i32 {
        self.days + POSTGRES_EPOCH_JDATE
    }

    /// 天文年。
    pub fn year(self) -> i32 {
        self.ymd().0
    }

    /// 月。1 から 12。
    pub fn month(self) -> u32 {
        self.ymd().1
    }

    /// 日。
    pub fn day(self) -> u32 {
        self.ymd().2
    }

    /// 天文年・月・日。
    pub fn ymd(self) -> (i32, u32, u32) {
        julian::j2date(self.julian_day()).expect("finite DATE has a non-negative Julian day")
    }
}

/// PostgreSQL の `DATE`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Date {
    /// `-infinity`。
    NegInfinity,
    /// 有限の日付。
    Finite(FiniteDate),
    /// `infinity`。
    Infinity,
}

impl Date {
    /// 天文年の年月日から有限の日付を作る。
    pub fn from_ymd(year: i32, month: u32, day: u32) -> Option<Self> {
        FiniteDate::from_ymd(year, month, day).map(Self::Finite)
    }

    /// `DateADT` の 32 ビット値から作る。
    ///
    /// 最小値は `-infinity`、最大値は `infinity`、有限の範囲は日付、
    /// それ以外は壊れた値として `None`。
    pub fn from_postgres(days: i32) -> Option<Self> {
        if days == DATE_NEG_INFINITY {
            Some(Self::NegInfinity)
        } else if days == DATE_INFINITY {
            Some(Self::Infinity)
        } else {
            FiniteDate::from_postgres_days(days).map(Self::Finite)
        }
    }

    /// `DateADT` の 32 ビット値。
    pub fn to_postgres(self) -> i32 {
        match self {
            Self::NegInfinity => DATE_NEG_INFINITY,
            Self::Finite(date) => date.postgres_days(),
            Self::Infinity => DATE_INFINITY,
        }
    }

    /// 有限ならその日付。
    pub fn finite(self) -> Option<FiniteDate> {
        match self {
            Self::Finite(date) => Some(date),
            Self::NegInfinity | Self::Infinity => None,
        }
    }

    /// `-infinity` か。
    pub fn is_neg_infinity(self) -> bool {
        matches!(self, Self::NegInfinity)
    }

    /// `infinity` か。
    pub fn is_infinity(self) -> bool {
        matches!(self, Self::Infinity)
    }

    /// `DateStyle=ISO` の文字列を解析する。
    ///
    /// サーバーが出力する `YYYY-MM-DD`、末尾の ` BC`、`infinity` / `-infinity` を受け付ける。
    pub fn parse_iso(text: &str) -> Option<Self> {
        text::parse_date(text)
    }

    /// `DateStyle=ISO` の文字列にする。
    pub fn to_iso(self) -> String {
        text::format_date(self)
    }
}
