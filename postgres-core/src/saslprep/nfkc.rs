// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! NFKC。Unicode Standard Annex #15 の分解、正規順序、再合成。
//!
//! 分解表は PostgreSQL 18 が使う Unicode 17.0 と同じである。
//! 将来の版で変わる可能性がある。

mod decomp;
mod table;

/// 1 文字の分解。
#[derive(Clone, Copy)]
pub(super) struct Decomp {
    /// 符号位置。
    pub cp: u32,
    /// 正規結合クラス。
    pub class: u8,
    /// 下位 5 ビットが分解長。互換分解・インライン・再合成禁止のフラグを含む。
    pub flags: u8,
    /// インラインなら分解先、否則 `CODEPOINTS` の添字。
    pub index: u16,
}

const COMPAT: u8 = 0x20;
const INLINE: u8 = 0x40;
const NO_COMPOSE_BIT: u8 = 0x80;

const SBASE: u32 = 0xAC00;
const LBASE: u32 = 0x1100;
const VBASE: u32 = 0x1161;
const TBASE: u32 = 0x11A7;
const LCOUNT: u32 = 19;
const VCOUNT: u32 = 21;
const TCOUNT: u32 = 28;
const SCOUNT: u32 = LCOUNT * VCOUNT * TCOUNT;

fn size(entry: &Decomp) -> usize {
    usize::from(entry.flags & 0x1F)
}

fn is_inline(entry: &Decomp) -> bool {
    entry.flags & INLINE != 0
}

fn no_compose(entry: &Decomp) -> bool {
    entry.flags & (NO_COMPOSE_BIT | COMPAT) != 0
}

fn lookup(code: u32) -> Option<&'static Decomp> {
    let index = decomp::DECOMP
        .binary_search_by_key(&code, |entry| entry.cp)
        .ok()?;
    Some(&decomp::DECOMP[index])
}

fn class_of(code: u32) -> u8 {
    lookup(code).map(|entry| entry.class).unwrap_or(0)
}

fn decompose_into(code: u32, out: &mut Vec<u32>) {
    if (SBASE..SBASE + SCOUNT).contains(&code) {
        let sindex = code - SBASE;
        let lead = LBASE + sindex / (VCOUNT * TCOUNT);
        let vowel = VBASE + (sindex % (VCOUNT * TCOUNT)) / TCOUNT;
        let trail = sindex % TCOUNT;
        out.push(lead);
        out.push(vowel);
        if trail != 0 {
            out.push(TBASE + trail);
        }
        return;
    }
    let Some(entry) = lookup(code) else {
        out.push(code);
        return;
    };
    if size(entry) == 0 {
        out.push(code);
        return;
    }
    if is_inline(entry) {
        decompose_into(u32::from(entry.index), out);
        return;
    }
    let start = usize::from(entry.index);
    let parts: Vec<u32> = table::CODEPOINTS[start..start + size(entry)].to_vec();
    for part in parts {
        decompose_into(part, out);
    }
}

fn canonical_order(codes: &mut [u32]) {
    let mut index = 1;
    while index < codes.len() {
        let previous_class = class_of(codes[index - 1]);
        let next_class = class_of(codes[index]);
        if previous_class == 0 || next_class == 0 || previous_class <= next_class {
            index += 1;
            continue;
        }
        codes.swap(index - 1, index);
        if index > 1 {
            index -= 1;
        } else {
            index += 1;
        }
    }
}

fn recompose(start: u32, code: u32) -> Option<u32> {
    if (LBASE..LBASE + LCOUNT).contains(&start) && (VBASE..VBASE + VCOUNT).contains(&code) {
        let lindex = start - LBASE;
        let vindex = code - VBASE;
        return Some(SBASE + (lindex * VCOUNT + vindex) * TCOUNT);
    }
    if (SBASE..SBASE + SCOUNT).contains(&start)
        && (start - SBASE).is_multiple_of(TCOUNT)
        && code > TBASE
        && code < TBASE + TCOUNT
    {
        return Some(start + (code - TBASE));
    }
    for entry in decomp::DECOMP {
        if size(entry) != 2 || no_compose(entry) {
            continue;
        }
        let index = usize::from(entry.index);
        if table::CODEPOINTS[index] == start && table::CODEPOINTS[index + 1] == code {
            return Some(entry.cp);
        }
    }
    None
}

/// `codes` を NFKC にする。
pub(super) fn nfkc(codes: &[u32]) -> Vec<u32> {
    let mut decomposed = Vec::new();
    for &code in codes {
        decompose_into(code, &mut decomposed);
    }
    canonical_order(&mut decomposed);
    if decomposed.is_empty() {
        return decomposed;
    }
    let mut composed = Vec::with_capacity(decomposed.len());
    composed.push(decomposed[0]);
    let mut starter_at = 0;
    let mut starter = decomposed[0];
    let mut last_class: i16 = -1;
    for &ch in &decomposed[1..] {
        let ch_class = i16::from(class_of(ch));
        if last_class < ch_class
            && let Some(composite) = recompose(starter, ch)
        {
            composed[starter_at] = composite;
            starter = composite;
        } else if ch_class == 0 {
            starter_at = composed.len();
            starter = ch;
            last_class = -1;
            composed.push(ch);
        } else {
            last_class = ch_class;
            composed.push(ch);
        }
    }
    composed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nfkc_str(text: &str) -> String {
        let codes: Vec<u32> = text.chars().map(|ch| ch as u32).collect();
        nfkc(&codes)
            .into_iter()
            .map(|code| char::from_u32(code).expect("NFKC output is a scalar value"))
            .collect()
    }

    #[test]
    fn test_nfkc_examples() {
        assert_eq!(nfkc_str("a\u{0301}"), "á");
        assert_eq!(nfkc_str("\u{00AA}"), "a");
        assert_eq!(nfkc_str("\u{2168}"), "IX");
        assert_eq!(nfkc_str("\u{FB01}"), "fi");
        assert_eq!(nfkc_str("\u{FF21}"), "A");
        assert_eq!(nfkc_str("\u{AC00}"), "\u{AC00}");
    }
}
