// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! auth モジュールの Property-Based Testing。
//!
//! SCRAM ハンドシェイク全体がランダムなパスワード・ソルト・
//! イテレーション数に対して成功することと、
//! 改ざんされたサーバー最終メッセージが検証に失敗することを検証する。
//! サーバー側の計算は RFC 5802 のアルゴリズムをそのまま実装する。

use aws_lc_rs::{hmac, pbkdf2};
use base64ct::{Base64, Encoding};
use shiguredo_postgres_core::auth::ScramClient;
use std::cell::Cell;
use std::num::NonZeroU32;

/// 長さをサンプリングする。
///
/// 空・単一・最大の境界値に意味のある確率 (1/2) を与え、
/// 残りは区間内を一様に引く。
fn sample_len(ctx: &mut noprop::TestCaseContext, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    if max == 1 {
        return noprop::sample_usize_in(ctx, 0..=1);
    }
    noprop::sample_with_boundaries(ctx, &[0, 1, max], noprop::Ratio::one_nth(2), |ctx| {
        noprop::sample_usize_in(ctx, 0..=max)
    })
}

/// 下限付きの長さをサンプリングする。
///
/// 最小値と最大値に意味のある確率 (1/2) を与え、残りは区間内を一様に引く。
fn sample_len_range(ctx: &mut noprop::TestCaseContext, min: usize, max: usize) -> usize {
    assert!(min <= max, "長さの範囲が不正です");
    if min == max {
        return min;
    }
    noprop::sample_with_boundaries(ctx, &[min, max], noprop::Ratio::one_nth(2), |ctx| {
        noprop::sample_usize_in(ctx, min..=max)
    })
}

/// 長さ 0..=max のバイト列をサンプリングする。
fn sample_bytes_capped(ctx: &mut noprop::TestCaseContext, max: usize) -> Vec<u8> {
    let len = sample_len(ctx, max);
    noprop::sample_bytes_vec(ctx, len)
}

/// 英数字の文字列をサンプリングする。
///
/// SCRAM のサーバー追加 nonce は `[A-Za-z0-9]` で構成される。
/// 長さは 1..=16 で、両端の境界値に意味のある確率を与える。
fn sample_alphanum(ctx: &mut noprop::TestCaseContext, min: usize, max: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let len = sample_len_range(ctx, min, max);
    (0..len)
        .map(|_| noprop::sample_choice(ctx, CHARSET) as char)
        .collect()
}

/// 入力と、仕様から独立に決めた SASLprep 後の期待バイト列をサンプリングする。
fn sample_password(ctx: &mut noprop::TestCaseContext) -> (Vec<u8>, Vec<u8>) {
    match noprop::sample_usize_in(ctx, 0..=2) {
        0 => {
            let mut ascii = sample_bytes_capped(ctx, 64);
            for byte in &mut ascii {
                *byte = b'!' + *byte % 94;
            }
            (ascii.clone(), ascii)
        }
        1 => {
            // PostgreSQL 18 の fe-auth-scram.c は SASLprep 失敗時に元の値を使う。
            // 対応する入力の扱いが将来変われば、この検証も見直す。
            let mut raw = sample_bytes_capped(ctx, 63);
            raw.push(0xff); // どの接頭辞でも UTF-8 として不正になる。
            (raw.clone(), raw)
        }
        _ => {
            // RFC 4013 §2.1 / §2.2 の空白写像、削除、互換正規化を固定の期待値で確認する。
            // 実装と同じ正規化関数は使わない。将来仕様が変わればこの対応表を見直す。
            let (input, expected) = noprop::sample_choice(
                ctx,
                &[("x\u{a0}y", "x y"), ("x\u{ad}y", "xy"), ("Al\u{b5}", "Alμ")],
            );
            (input.as_bytes().to_vec(), expected.as_bytes().to_vec())
        }
    }
}

/// サーバー側の SCRAM 署名を計算してサーバー最終メッセージを組み立てる。
///
/// RFC 5802 のサーバー側処理をそのまま実装する。
/// `handle_server_final` の成功パスを検証するために使う。
fn compute_server_final(
    client_final: &str,
    client_nonce: &str,
    salt: &[u8],
    iterations: u32,
    password: &[u8],
    server_first: &str,
) -> String {
    // `c=biws,r=<nonce>,p=<proof>` からクライアント最終メッセージの nonce を抽出する。
    let nonce = client_final
        .split(',')
        .find_map(|attr| attr.strip_prefix("r="))
        .expect("クライアント最終メッセージに nonce が含まれています");

    // PostgreSQL は SCRAM でユーザー名を送らないため、
    // クライアント最初のメッセージは `n=,r=<nonce>` の形式になる。
    let client_first_bare = format!("n=,r={}", client_nonce);
    let client_final_without_proof = format!("c=biws,r={}", nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );

    let salted_password = derive_salted_password(password, salt, iterations);
    let server_key = hmac_sha256(&salted_password, b"Server Key");
    let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
    format!("v={}", Base64::encode_string(&server_signature))
}

/// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations, 32) を計算する。
fn derive_salted_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let iterations = NonZeroU32::new(iterations).expect("イテレーション数は 1 以上です");
    let mut salted_password = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut salted_password,
    );
    salted_password
}

/// HMAC-SHA-256 を計算する。
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// SCRAM ハンドシェイクはランダムなパスワード・ソルト・イテレーション数で
/// 成功し、改ざんされたサーバー最終メッセージは検証に失敗する。
#[test]
fn prop_scram_handshake() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // 空パスワードと改ざん検証が一度も起きないと検証が空虚になるため数える。
    let empty_password = Cell::new(0usize);
    let normalized_password = Cell::new(0usize);
    let raw_password = Cell::new(0usize);
    let tampered = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let (password, prepared) = sample_password(ctx);
        let server_extra = sample_alphanum(ctx, 1, 16);
        let salt_len = sample_len_range(ctx, 1, 32);
        let salt = noprop::sample_bytes_vec(ctx, salt_len);
        let iterations = sample_len_range(ctx, 1, 100) as u32;

        let mut client = ScramClient::new().expect("nonce の生成に成功しました");
        let client_first = client.client_first_message();
        let client_nonce = client_first
            .strip_prefix("n,,n=,r=")
            .expect("クライアント最初のメッセージの形式が想定と異なります");

        // サーバー最初のメッセージはクライアント nonce を先頭に含む必要がある。
        let server_first = format!(
            "r={}{},s={},i={}",
            client_nonce,
            server_extra,
            Base64::encode_string(&salt),
            iterations
        );
        let client_final = client
            .handle_server_first(&server_first, &password)
            .expect("サーバー最初のメッセージの処理に成功しました");
        assert!(
            client_final.starts_with("c=biws,r="),
            "クライアント最終メッセージの形式が不正です: {}",
            client_final
        );
        assert!(
            client_final.contains(",p="),
            "クライアント最終メッセージに proof が含まれていません: {}",
            client_final
        );

        // 正しいサーバー最終メッセージは検証に成功する。
        let server_final = compute_server_final(
            &client_final,
            client_nonce,
            &salt,
            iterations,
            &prepared,
            &server_first,
        );
        assert!(
            client.handle_server_final(&server_final).is_ok(),
            "正しいサーバー最終メッセージの検証に失敗しました"
        );

        // 別のパスワードから計算したサーバー最終メッセージは検証に失敗する。
        let mut wrong_password = prepared.clone();
        if wrong_password.is_empty() {
            wrong_password.push(0x01);
        } else {
            wrong_password[0] ^= 0xff;
        }
        let wrong_final = compute_server_final(
            &client_final,
            client_nonce,
            &salt,
            iterations,
            &wrong_password,
            &server_first,
        );
        if server_final != wrong_final {
            assert!(
                client.handle_server_final(&wrong_final).is_err(),
                "改ざんされたサーバー最終メッセージの検証に失敗しませんでした"
            );
            tampered.set(tampered.get() + 1);
        }

        if password.is_empty() {
            empty_password.set(empty_password.get() + 1);
        }
        if password != prepared {
            normalized_password.set(normalized_password.get() + 1);
        }
        if std::str::from_utf8(&password).is_err() {
            raw_password.set(raw_password.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        empty_password.get() > 0,
        "空パスワードが一度も検証されませんでした\n{runner}"
    );
    assert!(
        normalized_password.get() > 0 && raw_password.get() > 0,
        "SASLprep の変換または元のバイト列への復帰が検証されませんでした\n{runner}"
    );
    assert!(
        tampered.get() > 0,
        "改ざん検証が一度も実行されませんでした\n{runner}"
    );
    Ok(())
}

/// サーバー最初のメッセージの nonce がクライアント nonce で始まらない場合は
/// エラーになる。
#[test]
fn prop_scram_nonce_mismatch() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        // ケースごとに RNG を消費し、実行を区別する。値は検証に使わない。
        let _dummy = noprop::sample_u8(ctx);
        let mut client = ScramClient::new().expect("nonce の生成に成功しました");
        let client_first = client.client_first_message();
        let client_nonce = client_first
            .strip_prefix("n,,n=,r=")
            .expect("クライアント最初のメッセージの形式が想定と異なります");

        // 先頭文字を必ず変えた nonce はクライアント nonce で始まらない。
        let mut bytes = client_nonce.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let mismatched_nonce = String::from_utf8(bytes).expect("base64 は ASCII です");
        let server_first = format!("r={},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10", mismatched_nonce);
        assert!(
            client
                .handle_server_first(&server_first, b"password")
                .is_err(),
            "nonce が一致しないサーバー最初のメッセージが受け入れられました"
        );
        Ok(())
    })?;
    Ok(())
}
