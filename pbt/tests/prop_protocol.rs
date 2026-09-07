// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! protocol モジュールの Property-Based Testing。
//!
//! フロントエンドメッセージの組み立てがフレーム構造を満たすこと、
//! バックエンドメッセージの組み立てと解析の往復が元の値を保持することを
//! 検証する。

use shiguredo_postgres_core::constants::{backend, frontend};
use shiguredo_postgres_core::protocol::{
    BackendKeyData, CommandComplete, CopyResponse, DataRow, ErrorResponse, NotificationResponse,
    ParameterDescription, PostgresPacket, RowDescription, bind_message, cancel_request_message,
    close_message, copy_data_message, copy_done_message, copy_fail_message, describe_message,
    execute_message, flush_message, parse_message, password_message, query_message,
    sasl_initial_response, sasl_response, startup_message, sync_message, terminate_message,
};
use std::cell::Cell;

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

/// NUL を含まない文字列をサンプリングする。
///
/// PostgreSQL のプロトコルは C 文字列 (NUL 終端) を使うため、
/// ペイロードに NUL を含められない。Unicode 文字列を生成した後に
/// NUL を置き換えて有効な入力だけを作る。
fn sample_cstring(ctx: &mut noprop::TestCaseContext, max_len: usize) -> String {
    let len = sample_len(ctx, max_len);
    let s = noprop::sample_string(ctx, len);
    // NUL は終端文字と衝突するため置き換える。Unicode 全体から見れば
    // 出現確率は無視できるほど小さいため、分布への影響は誤差程度である。
    s.replace('\0', "a")
}

/// 長さ 0..=max のバイト列をサンプリングする。
fn sample_bytes_capped(ctx: &mut noprop::TestCaseContext, max: usize) -> Vec<u8> {
    let len = sample_len(ctx, max);
    noprop::sample_bytes_vec(ctx, len)
}

/// NULL になり得るバイト列をサンプリングする。
///
/// None と Some を 1/2 ずつ生成する。
fn sample_option_bytes(ctx: &mut noprop::TestCaseContext, max: usize) -> Option<Vec<u8>> {
    if noprop::sample_bool(ctx) {
        None
    } else {
        Some(sample_bytes_capped(ctx, max))
    }
}

/// NUL 終端文字列をペイロードに追加する。
fn push_cstring(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// フロントエンドメッセージのフレーム構造を検証する。
///
/// 形式は「1 バイトタイプ + 4 バイト長さ (自身を含む) + ペイロード」。
/// 長さフィールドはタイプバイトを除いたバイト数を表すため、
/// メッセージ全体の長さより 1 小さい。
fn check_frame(message: &[u8], expected_type: u8) -> Result<(), String> {
    if message.len() < 5 {
        return Err(format!("メッセージが短すぎます: {} バイト", message.len()));
    }
    if message[0] != expected_type {
        return Err(format!(
            "メッセージタイプが一致しません: 期待 '{}' 実測 '{}'",
            expected_type as char, message[0] as char
        ));
    }
    let length = u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize;
    if length != message.len() - 1 {
        return Err(format!(
            "長さフィールドが一致しません: 期待 {} 実測 {}",
            length,
            message.len() - 1
        ));
    }
    Ok(())
}

/// すべてのフロントエンドメッセージは正しいフレーム構造を持つ。
#[test]
fn prop_frontend_frame() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let sql = sample_cstring(ctx, 64);
        let password = sample_bytes_capped(ctx, 256);
        let mechanism = sample_cstring(ctx, 32);
        let initial_response = sample_bytes_capped(ctx, 256);
        let sasl_data = sample_bytes_capped(ctx, 256);
        let kind = noprop::sample_u8(ctx);
        let name = sample_cstring(ctx, 32);
        let copy_data = sample_bytes_capped(ctx, 256);
        let fail_message = sample_cstring(ctx, 32);
        let statement = sample_cstring(ctx, 32);
        let query = sample_cstring(ctx, 64);
        let parameter_count = sample_len(ctx, 16);
        let parameter_types: Vec<u32> = (0..parameter_count)
            .map(|_| noprop::sample_u32(ctx))
            .collect();
        let portal = sample_cstring(ctx, 32);
        let params_count = sample_len(ctx, 16);
        let parameters: Vec<Option<Vec<u8>>> = (0..params_count)
            .map(|_| sample_option_bytes(ctx, 256))
            .collect();
        let max_rows = noprop::sample_u32(ctx);

        assert!(
            check_frame(&query_message(&sql), frontend::QUERY).is_ok(),
            "クエリメッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&password_message(&password), frontend::PASSWORD).is_ok(),
            "パスワードメッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(
                &sasl_initial_response(&mechanism, &initial_response),
                frontend::PASSWORD
            )
            .is_ok(),
            "SASL 初期応答のフレーム構造が不正です"
        );
        assert!(
            check_frame(&sasl_response(&sasl_data), frontend::PASSWORD).is_ok(),
            "SASL 応答のフレーム構造が不正です"
        );
        assert!(
            check_frame(&terminate_message(), frontend::TERMINATE).is_ok(),
            "終了メッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&close_message(kind, &name), frontend::CLOSE).is_ok(),
            "クローズメッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&flush_message(), frontend::FLUSH).is_ok(),
            "フラッシュメッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&copy_data_message(&copy_data), frontend::COPY_DATA).is_ok(),
            "コピーデータメッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&copy_done_message(), frontend::COPY_DONE).is_ok(),
            "コピー完了メッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&copy_fail_message(&fail_message), frontend::COPY_FAIL).is_ok(),
            "コピー失敗メッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(
                &parse_message(&statement, &query, &parameter_types),
                frontend::PARSE
            )
            .is_ok(),
            "パースメッセージのフレーム構造が不正です"
        );
        let params: Vec<Option<&[u8]>> = parameters.iter().map(|p| p.as_deref()).collect();
        assert!(
            check_frame(&bind_message(&portal, &statement, &params), frontend::BIND).is_ok(),
            "バインドメッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&describe_message(kind, &name), frontend::DESCRIBE).is_ok(),
            "記述メッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&execute_message(&portal, max_rows), frontend::EXECUTE).is_ok(),
            "実行メッセージのフレーム構造が不正です"
        );
        assert!(
            check_frame(&sync_message(), frontend::SYNC).is_ok(),
            "同期メッセージのフレーム構造が不正です"
        );
        Ok(())
    })?;
    Ok(())
}

/// スタートアップメッセージは長さ・バージョン・終端 NUL の構造を持つ。
#[test]
fn prop_startup_message_frame() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // 空のパラメータだけでは検証が空虚になるため、非空を数える。
    let non_empty = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let count = sample_len(ctx, 8);
        let mut parameters = Vec::new();
        for _ in 0..count {
            parameters.push((sample_cstring(ctx, 32), sample_cstring(ctx, 32)));
        }
        let refs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let message = startup_message(&refs);
        let length = u32::from_be_bytes([message[0], message[1], message[2], message[3]]) as usize;
        assert_eq!(length, message.len(), "長さフィールドが不正です");
        let version = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
        assert_eq!(
            version,
            shiguredo_postgres_core::constants::PROTOCOL_VERSION,
            "プロトコルバージョンが不正です"
        );
        // 末尾はパラメータリストの終端 NUL。
        assert_eq!(message[message.len() - 1], 0, "末尾の終端 NUL がありません");
        if !parameters.is_empty() {
            non_empty.set(non_empty.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        non_empty.get() > 0,
        "非空のパラメータが一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// キャンセル要求メッセージは固定長 16 バイトの構造を持つ。
#[test]
fn prop_cancel_request_frame() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let process_id = noprop::sample_u32(ctx);
        let secret_key = noprop::sample_u32(ctx);
        let message = cancel_request_message(process_id, secret_key);
        assert_eq!(message.len(), 16, "メッセージ長が不正です");
        let length = u32::from_be_bytes([message[0], message[1], message[2], message[3]]) as usize;
        assert_eq!(length, 16, "長さフィールドが不正です");
        let code = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
        assert_eq!(
            code,
            shiguredo_postgres_core::constants::CANCEL_REQUEST_CODE,
            "要求コードが不正です"
        );
        let parsed_pid = u32::from_be_bytes([message[8], message[9], message[10], message[11]]);
        assert_eq!(parsed_pid, process_id, "プロセス ID が一致しません");
        let parsed_key = u32::from_be_bytes([message[12], message[13], message[14], message[15]]);
        assert_eq!(parsed_key, secret_key, "シークレットキーが一致しません");
        Ok(())
    })?;
    Ok(())
}

/// DataRow は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_data_row_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    // 空だけ・NULL なし・NULL ありのいずれかに偏ると検証が空虚になるため数える。
    // 長さ 0..=16 を境界付きで引くため、非空の確率は 1 - (1/3 + (2/3)*(1/17)) ≒ 0.63、
    // 256 ケースで見逃す確率は無視できるほど小さい。
    let non_empty = Cell::new(0usize);
    let has_none = Cell::new(0usize);
    let has_some = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let count = sample_len(ctx, 16);
        let mut values = Vec::new();
        for _ in 0..count {
            values.push(sample_option_bytes(ctx, 256));
        }
        let mut payload = (values.len() as u16).to_be_bytes().to_vec();
        for value in &values {
            match value {
                None => payload.extend_from_slice(&(-1_i32).to_be_bytes()),
                Some(bytes) => {
                    payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    payload.extend_from_slice(bytes);
                }
            }
        }
        let packet = PostgresPacket {
            message_type: backend::DATA_ROW,
            data: payload,
        };
        let row = DataRow::parse(&packet).expect("組み立てた DataRow はパースできます");
        assert_eq!(row.values, values, "DataRow の往復で値が変化しました");
        if !values.is_empty() {
            non_empty.set(non_empty.get() + 1);
        }
        if values.iter().any(|v| v.is_none()) {
            has_none.set(has_none.get() + 1);
        }
        if values.iter().any(|v| v.is_some()) {
            has_some.set(has_some.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        non_empty.get() > 0,
        "非空の DataRow が一度も検証されませんでした\n{runner}"
    );
    assert!(
        has_none.get() > 0,
        "NULL を含む DataRow が一度も検証されませんでした\n{runner}"
    );
    assert!(
        has_some.get() > 0,
        "非 NULL を含む DataRow が一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// RowDescription は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_row_description_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let non_empty = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let count = sample_len(ctx, 16);
        let mut fields = Vec::new();
        for _ in 0..count {
            fields.push((
                sample_cstring(ctx, 32),
                noprop::sample_u32(ctx),
                noprop::sample_i16(ctx),
                noprop::sample_u32(ctx),
                noprop::sample_i16(ctx),
                noprop::sample_i32(ctx),
                noprop::sample_i16(ctx),
            ));
        }
        let mut payload = (fields.len() as u16).to_be_bytes().to_vec();
        for (name, table_oid, column_attr, type_oid, type_size, type_modifier, format) in &fields {
            push_cstring(&mut payload, name);
            payload.extend_from_slice(&table_oid.to_be_bytes());
            payload.extend_from_slice(&column_attr.to_be_bytes());
            payload.extend_from_slice(&type_oid.to_be_bytes());
            payload.extend_from_slice(&type_size.to_be_bytes());
            payload.extend_from_slice(&type_modifier.to_be_bytes());
            payload.extend_from_slice(&format.to_be_bytes());
        }
        let packet = PostgresPacket {
            message_type: backend::ROW_DESCRIPTION,
            data: payload,
        };
        let parsed =
            RowDescription::parse(&packet).expect("組み立てた RowDescription はパースできます");
        let roundtripped: Vec<(String, u32, i16, u32, i16, i32, i16)> = parsed
            .fields
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    f.table_oid,
                    f.column_attr,
                    f.type_oid,
                    f.type_size,
                    f.type_modifier,
                    f.format,
                )
            })
            .collect();
        assert_eq!(
            roundtripped, fields,
            "RowDescription の往復で値が変化しました"
        );
        if !fields.is_empty() {
            non_empty.set(non_empty.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        non_empty.get() > 0,
        "非空の RowDescription が一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// ParameterDescription は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_parameter_description_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let non_empty = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let count = sample_len(ctx, 16);
        let type_oids: Vec<u32> = (0..count).map(|_| noprop::sample_u32(ctx)).collect();
        let mut payload = (type_oids.len() as u16).to_be_bytes().to_vec();
        for type_oid in &type_oids {
            payload.extend_from_slice(&type_oid.to_be_bytes());
        }
        let packet = PostgresPacket {
            message_type: backend::PARAMETER_DESCRIPTION,
            data: payload,
        };
        let parsed = ParameterDescription::parse(&packet)
            .expect("組み立てた ParameterDescription はパースできます");
        assert_eq!(
            parsed.type_oids, type_oids,
            "ParameterDescription の往復で値が変化しました"
        );
        if !type_oids.is_empty() {
            non_empty.set(non_empty.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        non_empty.get() > 0,
        "非空の ParameterDescription が一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// BackendKeyData は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_backend_key_data_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let process_id = noprop::sample_u32(ctx);
        let secret_key = noprop::sample_u32(ctx);
        let mut payload = process_id.to_be_bytes().to_vec();
        payload.extend_from_slice(&secret_key.to_be_bytes());
        let packet = PostgresPacket {
            message_type: backend::BACKEND_KEY_DATA,
            data: payload,
        };
        let parsed =
            BackendKeyData::parse(&packet).expect("組み立てた BackendKeyData はパースできます");
        assert_eq!(parsed.process_id, process_id, "プロセス ID が一致しません");
        assert_eq!(
            parsed.secret_key, secret_key,
            "シークレットキーが一致しません"
        );
        Ok(())
    })?;
    Ok(())
}

/// NotificationResponse は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_notification_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let process_id = noprop::sample_u32(ctx);
        let channel = sample_cstring(ctx, 32);
        let payload = sample_cstring(ctx, 32);
        let mut data = process_id.to_be_bytes().to_vec();
        push_cstring(&mut data, &channel);
        push_cstring(&mut data, &payload);
        let packet = PostgresPacket {
            message_type: backend::NOTIFICATION_RESPONSE,
            data,
        };
        let parsed = NotificationResponse::parse(&packet)
            .expect("組み立てた NotificationResponse はパースできます");
        assert_eq!(parsed.process_id, process_id, "プロセス ID が一致しません");
        assert_eq!(parsed.channel, channel, "チャネル名が一致しません");
        assert_eq!(parsed.payload, payload, "ペイロードが一致しません");
        Ok(())
    })?;
    Ok(())
}

/// CommandComplete は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_command_complete_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let tag = sample_cstring(ctx, 32);
        let mut payload = tag.as_bytes().to_vec();
        payload.push(0);
        let packet = PostgresPacket {
            message_type: backend::COMMAND_COMPLETE,
            data: payload,
        };
        let parsed =
            CommandComplete::parse(&packet).expect("組み立てた CommandComplete はパースできます");
        assert_eq!(parsed.tag, tag, "コマンドタグが一致しません");
        Ok(())
    })?;
    Ok(())
}

/// CopyResponse は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_copy_response_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let non_empty = Cell::new(0usize);
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let overall_format = noprop::sample_u8(ctx);
        let count = sample_len(ctx, 16);
        let column_formats: Vec<u16> = (0..count).map(|_| noprop::sample_u16(ctx)).collect();
        let mut payload = vec![overall_format];
        payload.extend_from_slice(&(column_formats.len() as u16).to_be_bytes());
        for format in &column_formats {
            payload.extend_from_slice(&format.to_be_bytes());
        }
        let packet = PostgresPacket {
            message_type: backend::COPY_IN_RESPONSE,
            data: payload,
        };
        let parsed =
            CopyResponse::parse_in(&packet).expect("組み立てた CopyResponse はパースできます");
        assert_eq!(
            parsed.overall_format, overall_format,
            "全体形式が一致しません"
        );
        assert_eq!(
            parsed.column_formats, column_formats,
            "カラム形式が一致しません"
        );
        if !column_formats.is_empty() {
            non_empty.set(non_empty.get() + 1);
        }
        Ok(())
    })?;
    assert!(
        non_empty.get() > 0,
        "非空の CopyResponse が一度も検証されませんでした\n{runner}"
    );
    Ok(())
}

/// ErrorResponse は組み立てと解析の往復で元の値を保つ。
#[test]
fn prop_error_response_roundtrip() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("POSTGRES_RS_SEED")?;
    let mut runner = noprop::Runner::new(seed);
    runner.run(256, |ctx| {
        let severity = sample_cstring(ctx, 32);
        let severity_nonlocalized = sample_cstring(ctx, 32);
        let code = sample_cstring(ctx, 32);
        let message = sample_cstring(ctx, 32);
        let detail = sample_cstring(ctx, 32);
        let hint = sample_cstring(ctx, 32);
        let position = sample_cstring(ctx, 32);
        let internal_position = sample_cstring(ctx, 32);
        let internal_query = sample_cstring(ctx, 32);
        let context = sample_cstring(ctx, 32);
        let schema = sample_cstring(ctx, 32);
        let table = sample_cstring(ctx, 32);
        let column = sample_cstring(ctx, 32);
        let data_type = sample_cstring(ctx, 32);
        let constraint = sample_cstring(ctx, 32);
        let file = sample_cstring(ctx, 32);
        let line = sample_cstring(ctx, 32);
        let routine = sample_cstring(ctx, 32);
        let mut payload = Vec::new();
        push_field(&mut payload, b'S', &severity);
        push_field(&mut payload, b'V', &severity_nonlocalized);
        push_field(&mut payload, b'C', &code);
        push_field(&mut payload, b'M', &message);
        push_field(&mut payload, b'D', &detail);
        push_field(&mut payload, b'H', &hint);
        push_field(&mut payload, b'P', &position);
        push_field(&mut payload, b'p', &internal_position);
        push_field(&mut payload, b'q', &internal_query);
        push_field(&mut payload, b'W', &context);
        push_field(&mut payload, b's', &schema);
        push_field(&mut payload, b't', &table);
        push_field(&mut payload, b'c', &column);
        push_field(&mut payload, b'd', &data_type);
        push_field(&mut payload, b'n', &constraint);
        push_field(&mut payload, b'F', &file);
        push_field(&mut payload, b'L', &line);
        push_field(&mut payload, b'R', &routine);
        payload.push(0);
        let packet = PostgresPacket {
            message_type: backend::ERROR_RESPONSE,
            data: payload,
        };
        let parsed =
            ErrorResponse::parse(&packet).expect("組み立てた ErrorResponse はパースできます");
        assert_eq!(parsed.severity, severity, "重要度が一致しません");
        assert_eq!(
            parsed.severity_nonlocalized, severity_nonlocalized,
            "非ローカライズ重要度が一致しません"
        );
        assert_eq!(parsed.code, code, "コードが一致しません");
        assert_eq!(parsed.message, message, "メッセージが一致しません");
        assert_eq!(parsed.detail, Some(detail), "詳細が一致しません");
        assert_eq!(parsed.hint, Some(hint), "ヒントが一致しません");
        assert_eq!(parsed.position, Some(position), "位置が一致しません");
        assert_eq!(
            parsed.internal_position,
            Some(internal_position),
            "内部位置が一致しません"
        );
        assert_eq!(
            parsed.internal_query,
            Some(internal_query),
            "内部クエリが一致しません"
        );
        assert_eq!(parsed.context, Some(context), "文脈が一致しません");
        assert_eq!(parsed.schema, Some(schema), "スキーマが一致しません");
        assert_eq!(parsed.table, Some(table), "テーブルが一致しません");
        assert_eq!(parsed.column, Some(column), "カラムが一致しません");
        assert_eq!(parsed.data_type, Some(data_type), "データ型が一致しません");
        assert_eq!(parsed.constraint, Some(constraint), "制約が一致しません");
        assert_eq!(parsed.file, Some(file), "ファイルが一致しません");
        assert_eq!(parsed.line, Some(line), "行番号が一致しません");
        assert_eq!(parsed.routine, Some(routine), "ルーチンが一致しません");
        Ok(())
    })?;
    Ok(())
}

/// エラー応答のフィールド (タイプ 1 バイト + NUL 終端文字列) をペイロードに追加する。
fn push_field(out: &mut Vec<u8>, field_type: u8, value: &str) {
    out.push(field_type);
    push_cstring(out, value);
}
