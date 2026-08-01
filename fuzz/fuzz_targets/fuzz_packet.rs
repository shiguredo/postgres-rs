// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_postgres_core::connection::packet::PacketStream;

fuzz_target!(|data: &[u8]| {
    // 一度に全バイトを供給するパス。
    let mut stream = PacketStream::new(1024);
    let _ = stream.feed_bytes(data);
    while let Ok(_packet) = stream.read_packet() {}

    // 1 バイトずつ供給するパス。部分メッセージの蓄積を検証する。
    let mut stream = PacketStream::new(1024);
    for b in data {
        let _ = stream.feed_bytes(&[*b]);
    }
    while let Ok(_packet) = stream.read_packet() {}
});
