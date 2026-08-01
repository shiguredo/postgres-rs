// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! `DateStyle=ISO` の解析と整形。
//!
//! 接続時に `DateStyle=ISO` を固定しているため、サーバーは
//! `EncodeDateOnly` / `EncodeTimeOnly` / `EncodeDateTime` /
//! `EncodeTimezone` / `AppendSeconds` の出力だけを送る。
//! この形式と、`infinity` / `-infinity` だけを受理する。
//! 算法は PostgreSQL 18 の `src/backend/utils/adt/datetime.c` に合わせている。
//! 将来の版で変わる可能性がある。

use super::date::Date;
use super::julian::MAX_TZDISP_HOUR;
use super::time::Time;
use super::timestamp::{FiniteTimestamp, FiniteTimestamptz, Timestamp, Timestamptz};

const INFINITY: &str = "infinity";
const NEG_INFINITY: &str = "-infinity";

fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        _ => None,
    }
}

fn parse_two_digits(bytes: &[u8], index: &mut usize) -> Option<u32> {
    let hi = digit_value(*bytes.get(*index)?)?;
    let lo = digit_value(*bytes.get(*index + 1)?)?;
    *index += 2;
    Some(hi * 10 + lo)
}

/// 末尾の「 BC」を切り離す。
fn strip_era(text: &str) -> Option<(&str, bool)> {
    if let Some(body) = text.strip_suffix(" BC") {
        Some((body, true))
    } else {
        Some((text, false))
    }
}

fn parse_year(bytes: &[u8], index: &mut usize) -> Option<i32> {
    let start = *index;
    while *index < bytes.len() && *index - start < 7 && bytes[*index].is_ascii_digit() {
        *index += 1;
    }
    let digits = &bytes[start..*index];
    if digits.len() < 4 {
        return None;
    }
    let mut year: i32 = 0;
    for &byte in digits {
        year = year.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    if year <= 0 {
        return None;
    }
    Some(year)
}

fn astronomical_year(display_year: i32, bc: bool) -> Option<i32> {
    if bc {
        display_year.checked_sub(1).map(|year| -year)
    } else {
        Some(display_year)
    }
}

/// ISO の日付本文 (`YYYY-MM-DD`) を解析する。
fn parse_date_body(text: &str, bc: bool) -> Option<(i32, u32, u32)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let display_year = parse_year(bytes, &mut index)?;
    if bytes.get(index) != Some(&b'-') {
        return None;
    }
    index += 1;
    let month = parse_two_digits(bytes, &mut index)?;
    if bytes.get(index) != Some(&b'-') {
        return None;
    }
    index += 1;
    let day = parse_two_digits(bytes, &mut index)?;
    if index != bytes.len() {
        return None;
    }
    let year = astronomical_year(display_year, bc)?;
    Some((year, month, day))
}

fn parse_time_parts(text: &str) -> Option<(u32, u32, u32, u32)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let hour = parse_two_digits(bytes, &mut index)?;
    if bytes.get(index) != Some(&b':') {
        return None;
    }
    index += 1;
    let minute = parse_two_digits(bytes, &mut index)?;
    if bytes.get(index) != Some(&b':') {
        return None;
    }
    index += 1;
    let second = parse_two_digits(bytes, &mut index)?;
    let mut micros = 0_u32;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let length = index - start;
        if length == 0 || length > 6 {
            return None;
        }
        for &byte in &bytes[start..index] {
            micros = micros * 10 + digit_value(byte)?;
        }
        for _ in length..6 {
            micros *= 10;
        }
    }
    if index != bytes.len() {
        return None;
    }
    Some((hour, minute, second, micros))
}

fn parse_offset(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let (&sign, rest) = bytes.split_first()?;
    let sign: i64 = match sign {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let mut index = 0;
    let hour = parse_two_digits(rest, &mut index)?;
    if hour > u32::try_from(MAX_TZDISP_HOUR).expect("MAX_TZDISP_HOUR fits in u32") {
        return None;
    }
    let mut seconds = i64::from(hour) * 3600;
    if rest.get(index) == Some(&b':') {
        index += 1;
        let minute = parse_two_digits(rest, &mut index)?;
        if minute > 59 {
            return None;
        }
        seconds += i64::from(minute) * 60;
        if rest.get(index) == Some(&b':') {
            index += 1;
            let second = parse_two_digits(rest, &mut index)?;
            if second > 59 {
                return None;
            }
            seconds += i64::from(second);
        }
    }
    if index != rest.len() {
        return None;
    }
    Some(sign * seconds)
}

pub(crate) fn parse_date(text: &str) -> Option<Date> {
    if text == INFINITY {
        return Some(Date::Infinity);
    }
    if text == NEG_INFINITY {
        return Some(Date::NegInfinity);
    }
    let (body, bc) = strip_era(text)?;
    let (year, month, day) = parse_date_body(body, bc)?;
    Date::from_ymd(year, month, day)
}

pub(crate) fn parse_time(text: &str) -> Option<Time> {
    let (hour, minute, second, micros) = parse_time_parts(text)?;
    Time::from_hms_micro(hour, minute, second, micros)
}

pub(crate) fn parse_timestamp(text: &str) -> Option<Timestamp> {
    if text == INFINITY {
        return Some(Timestamp::Infinity);
    }
    if text == NEG_INFINITY {
        return Some(Timestamp::NegInfinity);
    }
    let (body, bc) = strip_era(text)?;
    let (date, time) = body.split_once(' ')?;
    let (year, month, day) = parse_date_body(date, bc)?;
    let (hour, minute, second, micros) = parse_time_parts(time)?;
    Timestamp::from_ymd_hms_micro(year, month, day, hour, minute, second, micros)
}

pub(crate) fn parse_timestamptz(text: &str) -> Option<Timestamptz> {
    if text == INFINITY {
        return Some(Timestamptz::Infinity);
    }
    if text == NEG_INFINITY {
        return Some(Timestamptz::NegInfinity);
    }
    let (body, bc) = strip_era(text)?;
    let (date, rest) = body.split_once(' ')?;
    let offset_at = rest.find(['+', '-'])?;
    let (time, offset) = rest.split_at(offset_at);
    let (year, month, day) = parse_date_body(date, bc)?;
    let (hour, minute, second, micros) = parse_time_parts(time)?;
    let offset = parse_offset(offset)?;
    let offset = i32::try_from(offset).ok()?;
    let local =
        FiniteTimestamp::from_ymd_hms_micro(year, month, day, hour, minute, second, micros)?;
    FiniteTimestamptz::from_local(local, offset).map(Timestamptz::Finite)
}

fn push_zero_padded(out: &mut String, value: u32, min_digits: usize) {
    let mut buffer = [0_u8; 10];
    let mut length = 0;
    let mut rest = value;
    loop {
        buffer[length] = b'0' + (rest % 10) as u8;
        length += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for _ in length..min_digits {
        out.push('0');
    }
    for &byte in buffer[..length].iter().rev() {
        out.push(byte as char);
    }
}

fn push_year(out: &mut String, year: i32) {
    let display = if year > 0 { year } else { 1 - year };
    push_zero_padded(out, display.unsigned_abs(), 4);
}

fn push_date_body(out: &mut String, year: i32, month: u32, day: u32) {
    push_year(out, year);
    out.push('-');
    push_zero_padded(out, month, 2);
    out.push('-');
    push_zero_padded(out, day, 2);
}

fn push_time(out: &mut String, time: Time) {
    push_zero_padded(out, time.hour(), 2);
    out.push(':');
    push_zero_padded(out, time.minute(), 2);
    out.push(':');
    push_zero_padded(out, time.second(), 2);
    let micros = time.microsecond();
    if micros != 0 {
        let mut fraction = micros;
        let mut length = 6;
        while fraction.is_multiple_of(10) {
            fraction /= 10;
            length -= 1;
        }
        let mut buffer = [b'0'; 6];
        for slot in buffer[..length].iter_mut().rev() {
            *slot = b'0' + (fraction % 10) as u8;
            fraction /= 10;
        }
        out.push('.');
        for &byte in &buffer[..length] {
            out.push(byte as char);
        }
    }
}

fn push_era(out: &mut String, year: i32) {
    if year <= 0 {
        out.push_str(" BC");
    }
}

pub(crate) fn format_date(date: Date) -> String {
    match date {
        Date::NegInfinity => NEG_INFINITY.to_string(),
        Date::Infinity => INFINITY.to_string(),
        Date::Finite(date) => {
            let (year, month, day) = date.ymd();
            let mut out = String::with_capacity(16);
            push_date_body(&mut out, year, month, day);
            push_era(&mut out, year);
            out
        }
    }
}

pub(crate) fn format_time(time: Time) -> String {
    let mut out = String::with_capacity(15);
    push_time(&mut out, time);
    out
}

fn format_timestamp_parts(parts: (i32, u32, u32, u32, u32, u32, u32)) -> String {
    let (year, month, day, hour, minute, second, micro) = parts;
    let time = Time::from_hms_micro(hour, minute, second, micro)
        .expect("timestamp parts form a time within a day");
    let mut out = String::with_capacity(32);
    push_date_body(&mut out, year, month, day);
    out.push(' ');
    push_time(&mut out, time);
    push_era(&mut out, year);
    out
}

pub(crate) fn format_timestamp(timestamp: Timestamp) -> String {
    match timestamp {
        Timestamp::NegInfinity => NEG_INFINITY.to_string(),
        Timestamp::Infinity => INFINITY.to_string(),
        Timestamp::Finite(timestamp) => format_timestamp_parts(timestamp.parts()),
    }
}

pub(crate) fn format_timestamptz(timestamp: Timestamptz) -> String {
    match timestamp {
        Timestamptz::NegInfinity => NEG_INFINITY.to_string(),
        Timestamptz::Infinity => INFINITY.to_string(),
        Timestamptz::Finite(timestamp) => {
            let (year, month, day, hour, minute, second, micro) = timestamp.parts();
            let time = Time::from_hms_micro(hour, minute, second, micro)
                .expect("timestamptz parts form a time within a day");
            let mut out = String::with_capacity(36);
            push_date_body(&mut out, year, month, day);
            out.push(' ');
            push_time(&mut out, time);
            // 分も秒も 0 の UTC オフセットは `EncodeTimezone` と同じく時だけ。
            out.push_str("+00");
            push_era(&mut out, year);
            out
        }
    }
}
