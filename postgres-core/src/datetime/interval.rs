// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL の `INTERVAL`。
//!
//! 有限値は PostgreSQL の内部表現と同じく、月数、日数、マイクロ秒の 3 つを別々に持つ。
//! 1 か月や 1 日の長さは文脈で変わるため、3 つを互いに換算しない。
//! 無限大は PostgreSQL 17 以降の `INTERVAL_NOBEGIN` / `INTERVAL_NOEND` で、
//! 3 つの値がそれぞれ最小値または最大値になる。

/// 有限の `INTERVAL`。
///
/// 月数、日数、マイクロ秒はそれぞれ独立した符号を持てる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiniteInterval {
    /// 月数。
    months: i32,
    /// 日数。
    days: i32,
    /// マイクロ秒。
    microseconds: i64,
}

impl FiniteInterval {
    /// 月数、日数、マイクロ秒から作る。
    ///
    /// 3 つの値がすべて最小値またはすべて最大値の組み合わせは、PostgreSQL では無限大を表すため
    /// `None` を返す。無限大は [`Interval::NegInfinity`] と [`Interval::Infinity`] で表す。
    pub fn new(months: i32, days: i32, microseconds: i64) -> Option<Self> {
        // PostgreSQL 19 の src/include/datatype/timestamp.h の INTERVAL_NOT_FINITE と同じ判定。
        // 将来の版で無限大の表現が変わった場合はここを見直す。
        let is_neg_infinity = months == i32::MIN && days == i32::MIN && microseconds == i64::MIN;
        let is_infinity = months == i32::MAX && days == i32::MAX && microseconds == i64::MAX;
        if is_neg_infinity || is_infinity {
            return None;
        }
        Some(Self {
            months,
            days,
            microseconds,
        })
    }

    /// 月数。
    pub fn months(self) -> i32 {
        self.months
    }

    /// 日数。
    pub fn days(self) -> i32 {
        self.days
    }

    /// マイクロ秒。
    pub fn microseconds(self) -> i64 {
        self.microseconds
    }

    /// `IntervalStyle=postgres` の文字列にする。
    fn to_postgres_style(self) -> String {
        // PostgreSQL 19 の src/backend/utils/adt/timestamp.c の interval2itm で分解し、
        // datetime.c の EncodeInterval (INTSTYLE_POSTGRES)、AddPostgresIntPart、AppendSeconds と
        // 同じ規則で書く。将来の版で出力の規則が変わった場合はここを見直す。
        const MICROSECONDS_PER_HOUR: i64 = 3_600_000_000;
        const MICROSECONDS_PER_MINUTE: i64 = 60_000_000;
        const MICROSECONDS_PER_SECOND: i64 = 1_000_000;
        let year = i64::from(self.months / 12);
        let month = i64::from(self.months % 12);
        let day = i64::from(self.days);
        // 除算は 0 方向への切り捨てのため、時・分・秒・マイクロ秒の符号はそろう。
        let hour = self.microseconds / MICROSECONDS_PER_HOUR;
        let rest = self.microseconds - hour * MICROSECONDS_PER_HOUR;
        let minute = rest / MICROSECONDS_PER_MINUTE;
        let rest = rest - minute * MICROSECONDS_PER_MINUTE;
        let second = rest / MICROSECONDS_PER_SECOND;
        let fraction = rest - second * MICROSECONDS_PER_SECOND;

        let mut out = String::new();
        let mut is_zero = true;
        let mut is_before = false;
        for (value, unit) in [(year, "year"), (month, "mon"), (day, "day")] {
            if value == 0 {
                continue;
            }
            if !is_zero {
                out.push(' ');
            }
            // 直前の 0 でないフィールドが負の場合だけ、正の値に `+` を付ける。
            if is_before && value > 0 {
                out.push('+');
            }
            out.push_str(&value.to_string());
            out.push(' ');
            out.push_str(unit);
            if value != 1 {
                out.push('s');
            }
            is_before = value < 0;
            is_zero = false;
        }
        if is_zero || hour != 0 || minute != 0 || second != 0 || fraction != 0 {
            if !is_zero {
                out.push(' ');
            }
            if hour < 0 || minute < 0 || second < 0 || fraction < 0 {
                out.push('-');
            } else if is_before {
                out.push('+');
            }
            out.push_str(&format!(
                "{:02}:{:02}:{:02}",
                hour.unsigned_abs(),
                minute.unsigned_abs(),
                second.unsigned_abs()
            ));
            if fraction != 0 {
                // 小数部は 6 桁で、末尾の 0 を書かない。
                let digits = format!("{:06}", fraction.unsigned_abs());
                out.push('.');
                out.push_str(digits.trim_end_matches('0'));
            }
        }
        out
    }

    /// `IntervalStyle=postgres` の文字列を解析する。
    ///
    /// 解析した値を [`FiniteInterval::to_postgres_style`] で書き戻し、元の文字列と一致する場合だけ
    /// 値を返す。ほかの `IntervalStyle` の出力や、サーバーが出力しない書き方は `None` になる。
    fn parse_postgres_style(text: &str) -> Option<Self> {
        let mut months: i64 = 0;
        let mut days: i64 = 0;
        let mut microseconds: i64 = 0;
        // 年、月、日、時刻の順に、それぞれ 1 回まで現れる。
        let mut next_field = 0;
        let mut tokens = text.split(' ');
        while let Some(token) = tokens.next() {
            if token.contains(':') {
                if next_field > 3 {
                    return None;
                }
                microseconds = parse_time(token)?;
                next_field = 4;
                continue;
            }
            let value: i64 = parse_signed(token)?;
            let (field, months_per_unit) = match tokens.next()? {
                "year" | "years" => (0, 12),
                "mon" | "mons" => (1, 1),
                "day" | "days" => (2, 0),
                _ => return None,
            };
            if field < next_field {
                return None;
            }
            next_field = field + 1;
            if field == 2 {
                days = value;
            } else {
                months = months.checked_add(value.checked_mul(months_per_unit)?)?;
            }
        }
        let interval = Self::new(
            i32::try_from(months).ok()?,
            i32::try_from(days).ok()?,
            microseconds,
        )?;
        (interval.to_postgres_style() == text).then_some(interval)
    }
}

/// 符号付きの 10 進整数を解析する。`+` も受け付ける。
fn parse_signed(token: &str) -> Option<i64> {
    let digits = token.strip_prefix('+').unwrap_or(token);
    let unsigned = digits.strip_prefix('-').unwrap_or(digits);
    if unsigned.is_empty() || !unsigned.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `[+-]時:分:秒[.小数]` をマイクロ秒にする。
fn parse_time(token: &str) -> Option<i64> {
    let (negative, body) = match token.as_bytes().first()? {
        b'-' => (true, &token[1..]),
        b'+' => (false, &token[1..]),
        _ => (false, token),
    };
    let mut parts = body.split(':');
    let hours = parts.next()?;
    let minutes = parts.next()?;
    let seconds = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let (seconds, fraction) = match seconds.split_once('.') {
        Some((seconds, fraction)) => (seconds, fraction),
        None => (seconds, ""),
    };
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(hours)
        || !all_digits(minutes)
        || !all_digits(seconds)
        || (!fraction.is_empty() && !all_digits(fraction))
        || fraction.len() > 6
    {
        return None;
    }
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    let seconds: i64 = seconds.parse().ok()?;
    let fraction: i64 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<6}").parse().ok()?
    };
    // i64::MIN のマイクロ秒も表せるよう、負の値として積み上げる。
    let magnitude = hours
        .checked_mul(-3_600_000_000)?
        .checked_sub(minutes.checked_mul(60_000_000)?)?
        .checked_sub(seconds.checked_mul(1_000_000)?)?
        .checked_sub(fraction)?;
    if negative {
        Some(magnitude)
    } else {
        magnitude.checked_neg()
    }
}

/// PostgreSQL の `INTERVAL`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interval {
    /// `-infinity`。PostgreSQL 17 以降で使える。
    NegInfinity,
    /// 有限の時間間隔。
    Finite(FiniteInterval),
    /// `infinity`。PostgreSQL 17 以降で使える。
    Infinity,
}

impl Interval {
    /// 月数、日数、マイクロ秒から作る。
    ///
    /// PostgreSQL の無限大の表現 (3 つがすべて最小値、またはすべて最大値) はそれぞれ
    /// [`Interval::NegInfinity`] と [`Interval::Infinity`] になる。
    pub fn from_postgres(months: i32, days: i32, microseconds: i64) -> Self {
        match FiniteInterval::new(months, days, microseconds) {
            Some(interval) => Self::Finite(interval),
            None if months == i32::MIN => Self::NegInfinity,
            None => Self::Infinity,
        }
    }

    /// 有限ならその値。
    pub fn finite(self) -> Option<FiniteInterval> {
        match self {
            Self::Finite(interval) => Some(interval),
            Self::NegInfinity | Self::Infinity => None,
        }
    }

    /// `IntervalStyle=postgres` (既定) の文字列を解析する。
    ///
    /// サーバーがこの形式で出力する文字列と、`infinity` / `-infinity` を受け付ける。
    /// `postgres_verbose`、`sql_standard`、`iso_8601` の出力は `None` になる。
    pub fn parse_postgres_style(text: &str) -> Option<Self> {
        // PostgreSQL 19 の src/backend/utils/adt/timestamp.c の EncodeSpecialInterval は、
        // IntervalStyle によらず無限大を `-infinity` / `infinity` と書く。
        match text {
            "-infinity" => Some(Self::NegInfinity),
            "infinity" => Some(Self::Infinity),
            _ => FiniteInterval::parse_postgres_style(text).map(Self::Finite),
        }
    }

    /// `IntervalStyle=postgres` の文字列にする。
    ///
    /// この形式は、負のフィールドの後ろのフィールドすべてに符号を明示する。そのため
    /// サーバーの `IntervalStyle` が `sql_standard` でも、同じ値として入力される。
    pub fn to_postgres_style(self) -> String {
        // PostgreSQL 19 の src/backend/utils/adt/datetime.c の DecodeInterval は、ほかに符号の
        // 明示がない場合に限り、sql_standard で先頭の符号をすべてのフィールドに適用する。
        // postgres 形式の出力はこの条件に当たらない (同関数のコメント)。
        // 将来この入力の規則が変わった場合はここを見直す。
        match self {
            Self::NegInfinity => "-infinity".to_string(),
            Self::Finite(interval) => interval.to_postgres_style(),
            Self::Infinity => "infinity".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// サーバーが出力する形式を、符号の付け方を含めて読み書きできることを確認する。
    #[test]
    fn test_postgres_style_examples() {
        // (文字列, 月数, 日数, マイクロ秒)。PostgreSQL の interval_out の出力と同じ文字列。
        let cases = [
            ("00:00:00", 0, 0, 0),
            ("1 year 2 mons 3 days 04:05:06.789", 14, 3, 14_706_789_000),
            ("1 mon", 1, 0, 0),
            ("-1 years -2 mons", -14, 0, 0),
            ("-1 days +02:03:00", 0, -1, 7_380_000_000),
            ("1 day -00:00:01", 0, 1, -1_000_000),
            ("-1 years +3 days", -12, 3, 0),
            ("-00:00:00.000001", 0, 0, -1),
            ("2562047788:00:54.775807", 0, 0, i64::MAX),
            ("-2562047788:00:54.775808", 0, 0, i64::MIN),
            ("-178956970 years -8 mons", i32::MIN, 0, 0),
        ];
        for (text, months, days, microseconds) in cases {
            let interval = Interval::Finite(
                FiniteInterval::new(months, days, microseconds).expect("有限の値を作れません"),
            );
            assert_eq!(interval.to_postgres_style(), text, "{text} を書けません");
            assert_eq!(
                Interval::parse_postgres_style(text),
                Some(interval),
                "{text} を読めません"
            );
        }
        assert_eq!(
            Interval::from_postgres(i32::MIN, i32::MIN, i64::MIN),
            Interval::NegInfinity
        );
        assert_eq!(
            Interval::from_postgres(i32::MAX, i32::MAX, i64::MAX),
            Interval::Infinity
        );
        assert_eq!(
            Interval::parse_postgres_style("infinity"),
            Some(Interval::Infinity)
        );
    }

    /// ほかの IntervalStyle の出力とサーバーが出力しない書き方は、値として読まない。
    #[test]
    fn test_other_styles_are_not_parsed() {
        for text in [
            // postgres_verbose
            "@ 1 year 2 mons 3 days 4 hours 5 mins 6.789 secs",
            // sql_standard
            "+1-2 +3 +4:05:06.789",
            "1 0:00:00",
            "4:05:06",
            // iso_8601
            "P1Y2M3DT4H5M6.789S",
            // 正規の形ではない書き方
            "13 mons",
            "1 days",
            "2 day",
            "1 day 1 year",
            "04:05:06.7890",
            "04:05:06.1234567",
            "",
            " 1 day",
            "1 day ",
            "-0 days",
            "1 day 1 day",
            "1 day 04:05:06 1 year",
            "178956971 years",
        ] {
            assert_eq!(
                Interval::parse_postgres_style(text),
                None,
                "{text:?} を値として読みました"
            );
        }
    }
}
