// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_postgres_core::auth::ScramClient;

fuzz_target!(|data: &[u8]| {
    // 任意の入力に対して SCRAM のサーバー最初・最終メッセージの処理が
    // パニックしないことを検証する。
    if let Ok(s) = std::str::from_utf8(data) {
        // サーバー最終メッセージの検証。
        let client = ScramClient::new().expect("nonce の生成に成功しました");
        let _ = client.handle_server_final(s);

        // サーバー最初のメッセージの処理。
        // 任意入力の nonce がクライアント nonce で始まることはないため、
        // 高コストな PBKDF2 (イテレーション数上限 10,000,000) は実行されない。
        let mut client = ScramClient::new().expect("nonce の生成に成功しました");
        let _ = client.handle_server_first(s, data);
    }
});
