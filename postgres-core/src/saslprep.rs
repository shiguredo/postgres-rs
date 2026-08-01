// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! SASLprep (RFC 4013)。
//!
//! SCRAM のパスワードに適用する。失敗したパスワードは呼び出し側が
//! 生のバイト列のまま使う。PostgreSQL の `pg_saslprep` と同じく、
//! 写像の結果が空なら失敗である。
//! 禁止文字と双方向文字の検査は NFKC のあとに行う (RFC 4013 の 2.3 から 2.5)。
//! 文字クラスは RFC 3454 (Unicode 3.2) の表で、NFKC の分解は Unicode 17.0 である。
//! 将来の版で変わる可能性がある。

mod classes;
mod nfkc;

use std::cmp::Ordering;

/// 符号位置が両端を含む範囲表にあるか。範囲は重ならず昇順である。
fn in_ranges(code: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .binary_search_by(|(start, end)| {
            if code > *end {
                Ordering::Less
            } else if code < *start {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

fn map_code(code: u32) -> Option<u32> {
    if in_ranges(code, classes::NON_ASCII_SPACE) {
        Some(0x20)
    } else if in_ranges(code, classes::MAPPED_TO_NOTHING) {
        None
    } else {
        Some(code)
    }
}

fn prohibited(code: u32) -> bool {
    in_ranges(code, classes::PROHIBITED) || in_ranges(code, classes::UNASSIGNED)
}

fn bidirectional_violation(codes: &[u32]) -> bool {
    if !codes.iter().any(|code| in_ranges(*code, classes::RANDAL)) {
        return false;
    }
    if codes.iter().any(|code| in_ranges(*code, classes::LCAT)) {
        return true;
    }
    let first = codes[0];
    let last = codes[codes.len() - 1];
    !in_ranges(first, classes::RANDAL) || !in_ranges(last, classes::RANDAL)
}

/// `input` に SASLprep を適用する。禁止なら `None`。
pub fn saslprep(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    // 印字可能な ASCII は写像も NFKC も恒等で、禁止文字を含まない。
    if input.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
        return Some(input.to_string());
    }
    let mut mapped = Vec::new();
    for ch in input.chars() {
        if let Some(code) = map_code(ch as u32) {
            mapped.push(code);
        }
    }
    if mapped.is_empty() {
        return None;
    }
    let normalized = nfkc::nfkc(&mapped);
    if normalized.iter().any(|code| prohibited(*code)) || bidirectional_violation(&normalized) {
        return None;
    }
    Some(
        normalized
            .into_iter()
            .map(|code| char::from_u32(code).expect("SASLprep output is a scalar value"))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4013_examples() {
        // RFC 4013 3. の例。
        assert_eq!(saslprep("I\u{00AD}X").as_deref(), Some("IX"));
        assert_eq!(saslprep("user").as_deref(), Some("user"));
        assert_eq!(saslprep("USER").as_deref(), Some("USER"));
        assert_eq!(saslprep("\u{00AA}").as_deref(), Some("a"));
        assert_eq!(saslprep("\u{2168}").as_deref(), Some("IX"));
        assert_eq!(saslprep("\u{0007}"), None);
        // アラビア文字のあとに ASCII 数字。RandAL と L が混在する。
        assert_eq!(saslprep("\u{0627}1"), None);
    }

    #[test]
    fn test_space_mapping_and_empty_mapping() {
        assert_eq!(saslprep("x\u{00A0}y").as_deref(), Some("x y"));
        assert_eq!(saslprep("\u{00AD}"), None);
        assert_eq!(saslprep(""), None);
        assert_eq!(saslprep("\u{FEFF}a").as_deref(), Some("a"));
    }
}
