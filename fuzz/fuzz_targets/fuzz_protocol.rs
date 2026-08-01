// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_postgres_core::constants::backend;
use shiguredo_postgres_core::protocol::{
    AuthenticationRequest, BackendKeyData, CommandComplete, CopyResponse, DataRow,
    ErrorResponse, NoticeResponse, NotificationResponse, ParameterDescription, ParameterStatus,
    PostgresPacket, ReadyForQuery, RowDescription,
};

fuzz_target!(|data: &[u8]| {
    // 先頭バイトをメッセージタイプとして使い、残りをペイロードとして
    // すべてのバックエンドメッセージパーサーを実行する。
    let (message_type, payload) = match data.split_first() {
        Some((&message_type, payload)) => (message_type, payload),
        None => (backend::READY_FOR_QUERY, &[][..]),
    };
    let packet = PostgresPacket {
        message_type,
        data: payload.to_vec(),
    };
    let _ = AuthenticationRequest::parse(&packet);
    let _ = ParameterStatus::parse(&packet);
    let _ = BackendKeyData::parse(&packet);
    let _ = ReadyForQuery::parse(&packet);
    let _ = RowDescription::parse(&packet);
    let _ = DataRow::parse(&packet);
    let _ = CommandComplete::parse(&packet);
    let _ = ParameterDescription::parse(&packet);
    let _ = ErrorResponse::parse(&packet);
    let _ = NoticeResponse::parse(&packet);
    let _ = NotificationResponse::parse(&packet);
    let _ = CopyResponse::parse_in(&packet);
    let _ = CopyResponse::parse_out(&packet);
    let _ = CopyResponse::parse_both(&packet);
});
