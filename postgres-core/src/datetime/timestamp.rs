// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL の `TIMESTAMP` と `TIMESTAMPTZ`。
//!
//! どちらも 2000-01-01 00:00:00 からのマイクロ秒。
//! `TIMESTAMP` は壁時計の日時、`TIMESTAMPTZ` は UTC の瞬間。
//! 範囲は 4714-11-24 00:00:00 BC から 294276-12-31 23:59:59.999999 まで。
//! 無限大は `i64` の両端で、有限の範囲の外にある。
//!
//! 時刻がちょうど `24:00:00` のときは `tm2timestamp` と同じく翌日 00:00:00 にする。
//! オフセットの適用は `dt2local` と同じく、表示上のオフセット秒を引いて UTC にする。

use super::date::FiniteDate;
use super::julian::{
    self, POSTGRES_EPOCH_JDATE, TIMESTAMP_INFINITY, TIMESTAMP_NEG_INFINITY, USECS_PER_DAY,
    USECS_PER_SEC,
};
use super::text;
use super::time::Time;

/// 有限の `TIMESTAMP` または `TIMESTAMPTZ` の共通の瞬間。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Instant {
    /// 2000-01-01 00:00:00 からのマイクロ秒。`IS_VALID_TIMESTAMP` を満たす。
    usecs: i64,
}

impl Instant {
    fn from_postgres_usecs(usecs: i64) -> Option<Self> {
        if julian::is_valid_timestamp(usecs) {
            Some(Self { usecs })
        } else {
            None
        }
    }

    fn from_date_time(date: FiniteDate, time: Time) -> Option<Self> {
        let mut days = i64::from(date.postgres_days());
        let mut time_usecs = time.postgres_usecs();
        if time_usecs == USECS_PER_DAY {
            days = days.checked_add(1)?;
            time_usecs = 0;
        }
        let usecs = days.checked_mul(USECS_PER_DAY)?.checked_add(time_usecs)?;
        Self::from_postgres_usecs(usecs)
    }

    fn from_ymd_hms_micro(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Option<Self> {
        let date = FiniteDate::from_ymd(year, month, day)?;
        let time = Time::from_hms_micro(hour, minute, second, micro)?;
        Self::from_date_time(date, time)
    }

    fn postgres_usecs(self) -> i64 {
        self.usecs
    }

    fn parts(self) -> (i32, u32, u32, u32, u32, u32, u32) {
        let mut days = self.usecs / USECS_PER_DAY;
        let mut time_usecs = self.usecs % USECS_PER_DAY;
        // 切捨て除算では負の時刻が残る。`timestamp2tm` と同じく 1 日繰り下げる。
        if time_usecs < 0 {
            time_usecs += USECS_PER_DAY;
            days -= 1;
        }
        let days = i32::try_from(days).expect("finite timestamp day count fits in i32");
        let julian = days + POSTGRES_EPOCH_JDATE;
        let (year, month, day) =
            julian::j2date(julian).expect("finite timestamp has a non-negative Julian day");
        let time =
            Time::from_postgres_usecs(time_usecs).expect("timestamp time of day is within one day");
        (
            year,
            month,
            day,
            time.hour(),
            time.minute(),
            time.second(),
            time.microsecond(),
        )
    }
}

/// 有限の `TIMESTAMP`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FiniteTimestamp {
    instant: Instant,
}

impl FiniteTimestamp {
    /// 2000-01-01 00:00:00 からのマイクロ秒から作る。範囲外は `None`。
    pub fn from_postgres_usecs(usecs: i64) -> Option<Self> {
        Instant::from_postgres_usecs(usecs).map(|instant| Self { instant })
    }

    /// 日付と時刻から作る。`24:00:00` は翌日 00:00:00 になる。
    pub fn from_date_time(date: FiniteDate, time: Time) -> Option<Self> {
        Instant::from_date_time(date, time).map(|instant| Self { instant })
    }

    /// 天文年の年月日時分秒とマイクロ秒から作る。
    pub fn from_ymd_hms_micro(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Option<Self> {
        Instant::from_ymd_hms_micro(year, month, day, hour, minute, second, micro)
            .map(|instant| Self { instant })
    }

    /// 2000-01-01 00:00:00 からのマイクロ秒。
    pub fn postgres_usecs(self) -> i64 {
        self.instant.postgres_usecs()
    }

    /// 天文年・月・日・時・分・秒・マイクロ秒。
    pub fn parts(self) -> (i32, u32, u32, u32, u32, u32, u32) {
        self.instant.parts()
    }
}

/// PostgreSQL の `TIMESTAMP`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Timestamp {
    /// `-infinity`。
    NegInfinity,
    /// 有限のタイムスタンプ。
    Finite(FiniteTimestamp),
    /// `infinity`。
    Infinity,
}

impl Timestamp {
    /// 天文年の年月日時分秒から有限のタイムスタンプを作る。
    pub fn from_ymd_hms_micro(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Option<Self> {
        FiniteTimestamp::from_ymd_hms_micro(year, month, day, hour, minute, second, micro)
            .map(Self::Finite)
    }

    /// `Timestamp` の 64 ビット値から作る。
    ///
    /// 両端は無限大、有限の範囲はタイムスタンプ、それ以外は `None`。
    pub fn from_postgres(usecs: i64) -> Option<Self> {
        if usecs == TIMESTAMP_NEG_INFINITY {
            Some(Self::NegInfinity)
        } else if usecs == TIMESTAMP_INFINITY {
            Some(Self::Infinity)
        } else {
            FiniteTimestamp::from_postgres_usecs(usecs).map(Self::Finite)
        }
    }

    /// `Timestamp` の 64 ビット値。
    pub fn to_postgres(self) -> i64 {
        match self {
            Self::NegInfinity => TIMESTAMP_NEG_INFINITY,
            Self::Finite(timestamp) => timestamp.postgres_usecs(),
            Self::Infinity => TIMESTAMP_INFINITY,
        }
    }

    /// 有限ならそのタイムスタンプ。
    pub fn finite(self) -> Option<FiniteTimestamp> {
        match self {
            Self::Finite(timestamp) => Some(timestamp),
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

    /// `DateStyle=ISO` のタイムスタンプを解析する。
    pub fn parse_iso(text: &str) -> Option<Self> {
        text::parse_timestamp(text)
    }

    /// `DateStyle=ISO` のタイムスタンプにする。
    pub fn to_iso(self) -> String {
        text::format_timestamp(self)
    }
}

/// 有限の `TIMESTAMPTZ`。保持するのは UTC。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FiniteTimestamptz {
    instant: Instant,
}

impl FiniteTimestamptz {
    /// UTC のマイクロ秒から作る。範囲外は `None`。
    pub fn from_postgres_usecs(usecs: i64) -> Option<Self> {
        Instant::from_postgres_usecs(usecs).map(|instant| Self { instant })
    }

    /// UTC の年月日時分秒から作る。
    pub fn from_utc_ymd_hms_micro(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Option<Self> {
        Instant::from_ymd_hms_micro(year, month, day, hour, minute, second, micro)
            .map(|instant| Self { instant })
    }

    /// 現地時刻から表示上のオフセット秒を引いて UTC にする。
    ///
    /// `+09` は `+32400`。結果が範囲外なら `None`。
    pub fn from_local(local: FiniteTimestamp, offset_seconds: i32) -> Option<Self> {
        let delta = i64::from(offset_seconds).checked_mul(USECS_PER_SEC)?;
        let utc = local.postgres_usecs().checked_sub(delta)?;
        Self::from_postgres_usecs(utc)
    }

    /// UTC のマイクロ秒。
    pub fn postgres_usecs(self) -> i64 {
        self.instant.postgres_usecs()
    }

    /// UTC の天文年・月・日・時・分・秒・マイクロ秒。
    pub fn parts(self) -> (i32, u32, u32, u32, u32, u32, u32) {
        self.instant.parts()
    }
}

/// PostgreSQL の `TIMESTAMPTZ`。有限値は UTC。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Timestamptz {
    /// `-infinity`。
    NegInfinity,
    /// UTC の有限値。
    Finite(FiniteTimestamptz),
    /// `infinity`。
    Infinity,
}

impl Timestamptz {
    /// UTC の年月日時分秒から有限値を作る。
    pub fn from_utc_ymd_hms_micro(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Option<Self> {
        FiniteTimestamptz::from_utc_ymd_hms_micro(year, month, day, hour, minute, second, micro)
            .map(Self::Finite)
    }

    /// `TimestampTz` の 64 ビット値から作る。
    pub fn from_postgres(usecs: i64) -> Option<Self> {
        if usecs == TIMESTAMP_NEG_INFINITY {
            Some(Self::NegInfinity)
        } else if usecs == TIMESTAMP_INFINITY {
            Some(Self::Infinity)
        } else {
            FiniteTimestamptz::from_postgres_usecs(usecs).map(Self::Finite)
        }
    }

    /// `TimestampTz` の 64 ビット値。
    pub fn to_postgres(self) -> i64 {
        match self {
            Self::NegInfinity => TIMESTAMP_NEG_INFINITY,
            Self::Finite(timestamp) => timestamp.postgres_usecs(),
            Self::Infinity => TIMESTAMP_INFINITY,
        }
    }

    /// 有限ならその UTC 値。
    pub fn finite(self) -> Option<FiniteTimestamptz> {
        match self {
            Self::Finite(timestamp) => Some(timestamp),
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

    /// `DateStyle=ISO` のタイムスタンプ付きタイムゾーンを解析して UTC にする。
    pub fn parse_iso(text: &str) -> Option<Self> {
        text::parse_timestamptz(text)
    }

    /// UTC を `DateStyle=ISO` で `+00` 付きにする。
    pub fn to_iso(self) -> String {
        text::format_timestamptz(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_of_day_rolls_to_next_date() {
        let timestamp = Timestamp::from_ymd_hms_micro(2024, 1, 31, 24, 0, 0, 0)
            .expect("24:00:00 は翌日になります");
        let Timestamp::Finite(timestamp) = timestamp else {
            panic!("有限のタイムスタンプです");
        };
        assert_eq!(timestamp.parts(), (2024, 2, 1, 0, 0, 0, 0));
    }

    #[test]
    fn test_offset_crosses_midnight() {
        let local = FiniteTimestamp::from_ymd_hms_micro(2026, 11, 22, 0, 30, 0, 0)
            .expect("現地時刻は有効です");
        let utc = FiniteTimestamptz::from_local(local, 9 * 3600).expect("UTC は範囲内です");
        assert_eq!(utc.parts(), (2026, 11, 21, 15, 30, 0, 0));
    }

    #[test]
    fn test_timestamp_upper_bound() {
        assert!(Timestamp::from_ymd_hms_micro(294276, 12, 31, 23, 59, 59, 999_999).is_some());
        assert!(Timestamp::from_ymd_hms_micro(294276, 12, 31, 24, 0, 0, 0).is_none());
        assert!(Timestamp::from_ymd_hms_micro(294277, 1, 1, 0, 0, 0, 0).is_none());
        assert!(FiniteDate::from_ymd(5874897, 12, 31).is_some());
    }
}
