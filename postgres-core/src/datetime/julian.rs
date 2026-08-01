// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL のユリウス日と値域。
//!
//! 算法と定数は PostgreSQL 18 の次の定義に合わせている。
//! 将来の版で変わる可能性がある。
//!
//! - `src/include/datatype/timestamp.h` の `IS_VALID_DATE` / `IS_VALID_TIMESTAMP` /
//!   `POSTGRES_EPOCH_JDATE` / `DATE_END_JULIAN` / `MIN_TIMESTAMP` / `END_TIMESTAMP`
//! - `src/include/utils/datetime.h` の `isleap`
//! - `src/backend/utils/adt/datetime.c` の `date2j` / `j2date` / `day_tab`
//! - `src/include/utils/date.h` の `DATEVAL_NOBEGIN` / `DATEVAL_NOEND`

/// 2000-01-01 のユリウス日。`date2j(2000, 1, 1)`。
pub const POSTGRES_EPOCH_JDATE: i32 = 2_451_545;

/// 1970-01-01 のユリウス日。`date2j(1970, 1, 1)`。
///
/// PostgreSQL 元期との差は 10957 日で、2000-01-01 は 1970 年から数えて
/// うるう日 7 日を含む。
pub const UNIX_EPOCH_JDATE: i32 = 2_440_588;

/// 日付として許す最初のユリウス日。4714-11-24 BC。
pub const DATETIME_MIN_JULIAN: i32 = 0;

/// 日付として許さない最初のユリウス日。`date2j(5874898, 1, 1)`。
pub const DATE_END_JULIAN: i32 = 2_147_483_494;

/// タイムスタンプとして許さない最初のユリウス日。`date2j(294277, 1, 1)`。
pub const TIMESTAMP_END_JULIAN: i32 = 109_203_528;

/// 2000-01-01 からの日数の下限。`DATETIME_MIN_JULIAN - POSTGRES_EPOCH_JDATE`。
pub const MIN_DATE_DAYS: i32 = DATETIME_MIN_JULIAN - POSTGRES_EPOCH_JDATE;

/// 2000-01-01 からの日数の上限。`DATE_END_JULIAN` の前日。
pub const MAX_DATE_DAYS: i32 = DATE_END_JULIAN - POSTGRES_EPOCH_JDATE - 1;

/// 1 日のマイクロ秒。閏秒は足さない。
pub const USECS_PER_DAY: i64 = 86_400_000_000;

/// 1 時間のマイクロ秒。
pub const USECS_PER_HOUR: i64 = 3_600_000_000;

/// 1 分のマイクロ秒。
pub const USECS_PER_MINUTE: i64 = 60_000_000;

/// 1 秒のマイクロ秒。
pub const USECS_PER_SEC: i64 = 1_000_000;

/// 有限なタイムスタンプの下限 (含む)。
pub const MIN_TIMESTAMP: i64 = -211_813_488_000_000_000;

/// 有限なタイムスタンプの上限 (含まない)。
pub const END_TIMESTAMP: i64 = 9_223_371_331_200_000_000;

/// `DATE` の `-infinity`。`DateADT` の最小値。
pub const DATE_NEG_INFINITY: i32 = i32::MIN;

/// `DATE` の `infinity`。`DateADT` の最大値。
pub const DATE_INFINITY: i32 = i32::MAX;

/// `TIMESTAMP` / `TIMESTAMPTZ` の `-infinity`。
pub const TIMESTAMP_NEG_INFINITY: i64 = i64::MIN;

/// `TIMESTAMP` / `TIMESTAMPTZ` の `infinity`。
pub const TIMESTAMP_INFINITY: i64 = i64::MAX;

/// 数値オフセットの時の上限。`MAX_TZDISP_HOUR`。
pub const MAX_TZDISP_HOUR: i32 = 15;

const _: () = assert!(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE == 10_957);
const _: () = assert!(
    (TIMESTAMP_END_JULIAN as i64 - POSTGRES_EPOCH_JDATE as i64) * USECS_PER_DAY == END_TIMESTAMP
);
const _: () = assert!(
    (DATETIME_MIN_JULIAN as i64 - POSTGRES_EPOCH_JDATE as i64) * USECS_PER_DAY == MIN_TIMESTAMP
);

/// グレゴリオ暦のうるう年。`isleap` と同じ。
///
/// 1582 年より前も同じ式を使う。年は天文年で、1 BC は 0、2 BC は -1。
/// 剰余が 0 であることと整除は、切捨て除算でも一致する。
pub fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// 月の日数。`day_tab[isleap(year)][month - 1]` と同じ。
///
/// 月が 1 から 12 の外なら `None`。
pub fn days_in_month(year: i32, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return None,
    })
}

/// `date2j`。中間計算は 64 ビットで行い、C の `int` 除算と同じく 0 方向へ切捨てる。
///
/// 有効な日付では、月を動かしたあとの年は正になり、結果は `i32` に収まる。
pub fn date2j(year: i32, month: i32, day: i32) -> i64 {
    let mut year = i64::from(year);
    let mut month = i64::from(month);
    if month > 2 {
        month += 1;
        year += 4800;
    } else {
        month += 13;
        year += 4799;
    }
    let century = year / 100;
    year * 365 - 32167 + year / 4 - century + century / 4 + (7834 * month) / 256 + i64::from(day)
}

/// `j2date`。
///
/// 非負のユリウス日だけを受け付ける。PostgreSQL は負のユリウス日を
/// `j2date` に渡さない。
pub fn j2date(julian_day: i32) -> Option<(i32, u32, u32)> {
    if julian_day < 0 {
        return None;
    }
    let mut julian = u64::from(julian_day as u32);
    julian += 32044;
    let mut quad = julian / 146097;
    let extra = (julian - quad * 146097) * 4 + 3;
    julian += 60 + quad * 3 + extra / 146097;
    quad = julian / 1461;
    julian -= quad * 1461;
    let mut year = julian * 4 / 1461;
    julian = if year != 0 {
        (julian + 305) % 365
    } else {
        (julian + 306) % 366
    } + 123;
    year += quad * 4;
    let year = i64::try_from(year).ok()? - 4800;
    let year = i32::try_from(year).ok()?;
    quad = julian * 2141 / 65536;
    let day = julian - 7834 * quad / 256;
    let month = (quad + 10) % 12 + 1;
    let month = u32::try_from(month).ok()?;
    let day = u32::try_from(day).ok()?;
    Some((year, month, day))
}

/// `IS_VALID_DATE`。日数は 2000-01-01 からの日数。
pub fn is_valid_date(days: i32) -> bool {
    (MIN_DATE_DAYS..=MAX_DATE_DAYS).contains(&days)
}

/// `IS_VALID_TIMESTAMP`。マイクロ秒は 2000-01-01 00:00:00 から。
pub fn is_valid_timestamp(usecs: i64) -> bool {
    (MIN_TIMESTAMP..END_TIMESTAMP).contains(&usecs)
}

/// 年月日がグレゴリオ暦の実在する日で、`DATE` の範囲に入るか。
pub fn is_valid_ymd(year: i32, month: u32, day: u32) -> bool {
    let Some(limit) = days_in_month(year, month) else {
        return false;
    };
    if day == 0 || day > limit {
        return false;
    }
    // ここまで来た月日は 1..=12 と 1..=31 なので i32 に収まる。
    let julian = date2j(year, month as i32, day as i32);
    let Some(days) = julian.checked_sub(i64::from(POSTGRES_EPOCH_JDATE)) else {
        return false;
    };
    let Ok(days) = i32::try_from(days) else {
        return false;
    };
    is_valid_date(days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_and_origin() {
        assert_eq!(date2j(2000, 1, 1), i64::from(POSTGRES_EPOCH_JDATE));
        assert_eq!(date2j(1970, 1, 1), i64::from(UNIX_EPOCH_JDATE));
        assert_eq!(date2j(-4713, 11, 24), 0);
        assert_eq!(j2date(POSTGRES_EPOCH_JDATE), Some((2000, 1, 1)));
        assert_eq!(j2date(0), Some((-4713, 11, 24)));
    }

    #[test]
    fn test_leap_years() {
        assert!(is_leap_year(2024));
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(1500));
        assert!(is_leap_year(0));
        assert!(is_leap_year(-4));
        assert!(!is_leap_year(-3));
        assert_eq!(days_in_month(1500, 2), Some(28));
        assert_eq!(days_in_month(0, 2), Some(29));
    }

    #[test]
    fn test_date_bounds() {
        assert!(is_valid_ymd(-4713, 11, 24));
        assert!(!is_valid_ymd(-4713, 11, 23));
        assert!(is_valid_ymd(5874897, 12, 31));
        assert!(!is_valid_ymd(5874898, 1, 1));
        assert!(!is_valid_ymd(2023, 2, 29));
        assert!(is_valid_ymd(2024, 2, 29));
    }

    #[test]
    fn test_roundtrip_across_gregorian_cycles() {
        // 400 年周期の両側と、DATE / TIMESTAMP の端の年を全部の日で往復する。
        for year in [-400, -1, 0, 1, 400, 1582, 1900, 2000, 294276, 5874897] {
            for month in 1..=12 {
                let Some(limit) = days_in_month(year, month) else {
                    panic!("月は 1 から 12 です");
                };
                for day in 1..=limit {
                    if !is_valid_ymd(year, month, day) {
                        continue;
                    }
                    let julian = date2j(year, month as i32, day as i32);
                    let julian =
                        i32::try_from(julian).expect("有効なユリウス日は i32 に収まります");
                    assert_eq!(
                        j2date(julian),
                        Some((year, month, day)),
                        "ユリウス日の往復に失敗しました: {year}-{month}-{day}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_consecutive_days_differ_by_one() {
        let mut previous: Option<i64> = None;
        for month in 1..=12 {
            let limit = days_in_month(2024, month).expect("月は有効です");
            for day in 1..=limit {
                let julian = date2j(2024, month as i32, day as i32);
                if let Some(previous) = previous {
                    assert_eq!(julian, previous + 1);
                }
                previous = Some(julian);
            }
        }
        assert_eq!(
            date2j(2025, 1, 1),
            previous.expect("前年の末日があります") + 1
        );
        // 1 BC (年 0) の 2 月 29 日の翌日は 3 月 1 日。
        assert_eq!(date2j(0, 3, 1), date2j(0, 2, 29) + 1);
        assert_eq!(date2j(-4713, 11, 25), date2j(-4713, 11, 24) + 1);
    }
}
