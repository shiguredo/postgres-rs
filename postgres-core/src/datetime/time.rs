// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL の `TIME`。
//!
//! 深夜 0 時からのマイクロ秒。範囲は 0 以上 `24:00:00` ちょうど以下。
//! 閏秒の挿入表は持たない。秒 60 は `tm2time` と同じくマイクロ秒へ畳む。
//! `23:59:60` は `24:00:00` と同じ値になり、出力は `time2tm` の時分秒になる。

use super::julian::{USECS_PER_DAY, USECS_PER_HOUR, USECS_PER_MINUTE, USECS_PER_SEC};
use super::text;

/// PostgreSQL の `TIME`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    /// 深夜からのマイクロ秒。0 以上 `USECS_PER_DAY` 以下。
    usecs: i64,
}

impl Time {
    /// 深夜からのマイクロ秒から作る。範囲外は `None`。
    pub fn from_postgres_usecs(usecs: i64) -> Option<Self> {
        if (0..=USECS_PER_DAY).contains(&usecs) {
            Some(Self { usecs })
        } else {
            None
        }
    }

    /// 時分秒とマイクロ秒から作る。
    ///
    /// `time_overflows` と同じく、時 24 と秒 60 を個別には許し、
    /// 合計が `24:00:00` を超えたら `None`。マイクロ秒は 0 から 999999。
    pub fn from_hms_micro(hour: u32, minute: u32, second: u32, micro: u32) -> Option<Self> {
        if hour > 24 || minute >= 60 || second > 60 || micro >= 1_000_000 {
            return None;
        }
        let seconds = (i64::from(hour) * 60 + i64::from(minute)) * 60 + i64::from(second);
        let usecs = seconds
            .checked_mul(USECS_PER_SEC)?
            .checked_add(i64::from(micro))?;
        Self::from_postgres_usecs(usecs)
    }

    /// 深夜からのマイクロ秒。
    pub fn postgres_usecs(self) -> i64 {
        self.usecs
    }

    /// `time2tm` の時。`24:00:00` では 24。
    pub fn hour(self) -> u32 {
        u32::try_from(self.usecs / USECS_PER_HOUR).expect("TIME hour is between 0 and 24")
    }

    /// `time2tm` の分。
    pub fn minute(self) -> u32 {
        let rest = self.usecs % USECS_PER_HOUR;
        u32::try_from(rest / USECS_PER_MINUTE).expect("TIME minute is between 0 and 59")
    }

    /// `time2tm` の秒。正規化後は 0 から 59。
    pub fn second(self) -> u32 {
        let rest = self.usecs % USECS_PER_MINUTE;
        u32::try_from(rest / USECS_PER_SEC).expect("normalized TIME second is between 0 and 59")
    }

    /// `time2tm` のマイクロ秒。
    pub fn microsecond(self) -> u32 {
        u32::try_from(self.usecs % USECS_PER_SEC).expect("TIME microsecond is between 0 and 999999")
    }

    /// `DateStyle=ISO` の時刻を解析する。
    pub fn parse_iso(text: &str) -> Option<Self> {
        text::parse_time(text)
    }

    /// `DateStyle=ISO` の時刻にする。
    pub fn to_iso(self) -> String {
        text::format_time(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_of_day_and_leap_second_spelling() {
        let end = Time::from_hms_micro(24, 0, 0, 0).expect("24:00:00 は有効です");
        let spelled =
            Time::from_hms_micro(23, 59, 60, 0).expect("23:59:60 は 24:00:00 に畳まれます");
        assert_eq!(end, spelled);
        assert_eq!(end.postgres_usecs(), USECS_PER_DAY);
        assert_eq!(end.hour(), 24);
        assert_eq!(end.to_iso(), "24:00:00");
        assert_eq!(Time::parse_iso("23:59:60"), Some(end));
        assert_eq!(Time::parse_iso("24:00:00"), Some(end));
        assert!(Time::from_hms_micro(23, 59, 60, 1).is_none());
        assert!(Time::from_hms_micro(24, 0, 0, 1).is_none());
        let rolled = Time::from_hms_micro(12, 0, 60, 0).expect("12:00:60 は 12:01:00 です");
        assert_eq!(rolled.to_iso(), "12:01:00");
    }
}
