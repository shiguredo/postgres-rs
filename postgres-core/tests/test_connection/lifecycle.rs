// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! ReadyForQuery を境界とする同期と、準備済み文・行ストリームの進行を検証する。

use super::*;
use shiguredo_postgres_core::constants::{backend, describe};

#[test]
fn malformed_ready_does_not_advance_the_sequence() {
    let mut conn = connect_authenticated();
    let before = conn.ready_sequence();

    // 長さが不正な場合と、長さは正しくてもトランザクション状態が不正な場合を確認する。
    for payload in [&b""[..], b"IT", b"?"] {
        conn.feed_bytes(&build_message(backend::READY_FOR_QUERY, payload))
            .expect("不正な応答フレームを供給できる");
        assert!(matches!(conn.read_packet(), Err(Error::InternalError(_))));
        assert_eq!(conn.ready_sequence(), before);
        assert_eq!(conn.transaction_status(), transaction_status::IDLE);
    }

    // フレームを受信キューに追加した時点ではなく、読んだ時点で状態を更新する。
    conn.feed_bytes(&ready_for_query(transaction_status::IN_TRANSACTION))
        .expect("正常な同期応答を供給できる");
    assert_eq!(conn.ready_sequence(), before);
    assert_eq!(
        conn.read_packet().expect("同期応答を読める").message_type,
        backend::READY_FOR_QUERY
    );
    assert_eq!(conn.ready_sequence(), before + 1);
    assert_eq!(
        conn.transaction_status(),
        transaction_status::IN_TRANSACTION
    );
}

#[test]
fn input_copy_cannot_be_recovered_by_draining() {
    let mut conn = connect_authenticated();
    let before = conn.ready_sequence();
    // 後続の COPY が入力を待つ場合、受信だけの回復では同期まで到達できない。
    conn.feed_bytes(&build_message(backend::COPY_IN_RESPONSE, &[0, 0, 0]))
        .expect("COPY 開始応答を供給できる");
    conn.drain_to_ready()
        .expect_err("入力待ちの COPY ではドレインを拒否する");
    assert_eq!(conn.ready_sequence(), before);
}

#[test]
fn deallocation_waits_for_ready_after_close_and_sync_error() {
    let mut conn = connect_authenticated();
    let before = conn.ready_sequence();
    assert!(matches!(
        conn.send_deallocate("stmt_1\0suffix"),
        Err(Error::InterfaceError { .. })
    ));
    assert!(conn.pop_send_queue().is_none());

    conn.send_deallocate("stmt_1").expect("破棄を送信できる");
    assert_eq!(
        pop_client_message(&mut conn),
        (
            frontend::CLOSE,
            [vec![describe::STATEMENT], b"stmt_1\0".to_vec()].concat()
        )
    );
    assert_eq!(pop_client_message(&mut conn), (frontend::SYNC, vec![]));
    conn.feed_bytes(&build_message(backend::CLOSE_COMPLETE, &[]))
        .expect("破棄完了応答を供給できる");
    assert!(matches!(
        conn.read_deallocate_result(),
        Err(Error::NeedMoreData)
    ));
    assert!(conn.is_busy());
    assert_eq!(conn.ready_sequence(), before);

    // Close が完了していても、Sync でサーバーエラーになれば同期後にそれを返す。
    conn.feed_bytes(&error_response("23514", "constraint violation during sync"))
        .expect("同期中のエラーを供給できる");
    assert!(matches!(
        conn.read_deallocate_result(),
        Err(Error::NeedMoreData)
    ));
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("同期応答を供給できる");
    let error = conn
        .read_deallocate_result()
        .expect_err("同期中のエラーが返る");
    assert_eq!(error.code(), Some("23514"));
    assert_eq!(conn.ready_sequence(), before + 1);
    assert!(!conn.is_busy());

    // 同期済みの接続で別の破棄操作を始められる。分割されても正常完了の進捗を保持する。
    conn.send_deallocate("stmt_2")
        .expect("別の文の破棄を送信できる");
    conn.feed_bytes(&build_message(backend::CLOSE_COMPLETE, &[]))
        .expect("破棄完了応答を供給できる");
    assert!(matches!(
        conn.read_deallocate_result(),
        Err(Error::NeedMoreData)
    ));
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("同期応答を供給できる");
    conn.read_deallocate_result().expect("破棄と同期が完了する");
    assert_eq!(conn.ready_sequence(), before + 2);
    assert!(!conn.is_busy());
}

#[test]
fn prepared_statement_is_connection_owned_and_execution_progress_survives_recovery() {
    let mut conn = connect_authenticated();
    let before = conn.ready_sequence();
    conn.send_prepare("SELECT $1::int4")
        .expect("文の準備を送信できる");
    assert!(!conn.parse_complete_seen());
    conn.feed_bytes(
        &[
            parse_complete(),
            parameter_description(&[oid::INT4]),
            row_description(&[("n", oid::INT4)]),
        ]
        .concat(),
    )
    .expect("文の準備の応答を供給できる");
    assert!(matches!(
        conn.read_prepare_result(),
        Err(Error::NeedMoreData)
    ));
    assert!(conn.parse_complete_seen());
    assert_eq!(conn.ready_sequence(), before);
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("同期応答を供給できる");
    let statement = conn.read_prepare_result().expect("準備済み文を取得できる");
    assert_eq!(conn.ready_sequence(), before + 1);
    assert_eq!(statement.sql(), "SELECT $1::int4");
    assert_eq!(statement.parameter_oids(), &[oid::INT4]);
    assert_eq!(statement.fields()[0].name, "n");

    // ハンドルを複製しても所有者は変わらない。他の接続では何も送信しない。
    let statement = statement.clone();
    let mut other = connect_authenticated();
    assert!(conn.owns_statement(&statement));
    assert!(!other.owns_statement(&statement));
    assert!(matches!(
        other.send_execute_prepared(&statement, &[Value::Int4(1)]),
        Err(Error::InterfaceError { .. })
    ));
    assert!(other.pop_send_queue().is_none());

    conn.send_execute_prepared(&statement, &[Value::Int4(1)])
        .expect("準備した接続で実行できる");
    assert!(!conn.bind_complete_seen());
    conn.feed_bytes(
        &[
            bind_complete(),
            error_response("0A000", "error after binding"),
        ]
        .concat(),
    )
    .expect("バインド後のエラー応答を供給できる");
    let error = conn.read_query_result(false).expect_err("実行エラーが返る");
    assert_eq!(error.code(), Some("0A000"));
    assert!(conn.bind_complete_seen());
    assert!(matches!(conn.drain_to_ready(), Err(Error::NeedMoreData)));
    assert_eq!(conn.ready_sequence(), before + 1);
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("エラー後の同期応答を供給できる");
    conn.drain_to_ready().expect("実行のエラー後に同期できる");
    assert!(conn.bind_complete_seen());
    assert_eq!(conn.ready_sequence(), before + 2);
    assert!(conn.result().is_none());

    // 送信に成功しなければ検出状態は変わらず、次の実行を実際に送信してから初期化する。
    assert!(conn.send_execute_prepared(&statement, &[]).is_err());
    assert!(conn.bind_complete_seen());
    conn.send_execute_prepared(&statement, &[Value::Int4(2)])
        .expect("同期後に別の実行を送信できる");
    assert!(!conn.bind_complete_seen());
}

#[test]
fn next_row_moves_first_result_rows_and_drains_later_results() {
    let mut conn = connect_authenticated();
    let before = conn.ready_sequence();
    conn.send_query("SELECT 1; SELECT 2")
        .expect("クエリを送信できる");
    conn.feed_bytes(&row_description(&[("n", oid::INT4)]))
        .expect("最初の結果の行記述を供給できる");
    conn.read_query_result(true).expect("行を読み始められる");
    assert!(matches!(conn.read_next_row(), Err(Error::NeedMoreData)));

    conn.feed_bytes(&[data_row(&[Some(b"1")]), command_complete("SELECT 1")].concat())
        .expect("最初の結果の行データを供給できる");
    assert_eq!(
        conn.read_next_row().expect("行を取得できる"),
        Some(vec![Value::Int4(1)])
    );
    assert!(conn.result().expect("結果がある").rows.is_empty());
    assert!(matches!(conn.read_next_row(), Err(Error::NeedMoreData)));

    // 2 番目の結果の行にデコードできない値を入れ、デコードせず破棄することを確認する。
    conn.feed_bytes(
        &[
            row_description(&[("s", oid::TEXT)]),
            data_row(&[Some(b"\xff")]),
            command_complete("SELECT 1"),
            parameter_status("TimeZone", "UTC"),
        ]
        .concat(),
    )
    .expect("後続結果の応答を供給できる");
    assert!(matches!(conn.read_next_row(), Err(Error::NeedMoreData)));
    assert_eq!(conn.ready_sequence(), before);
    assert_eq!(
        conn.server_parameters().get("TimeZone").map(String::as_str),
        Some("UTC")
    );
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("同期応答を供給できる");
    assert_eq!(conn.read_next_row().expect("最後の同期が完了する"), None);
    assert_eq!(conn.ready_sequence(), before + 1);
    assert!(!conn.is_busy());
    let result = conn.result().expect("最初の結果が残っている");
    assert_eq!(result.fields[0].name, "n");
    assert_eq!(result.affected_rows, 1);
    assert!(!result.has_next_rowset());
}

#[test]
fn batch_protocol_error_is_not_treated_as_a_statement_error() {
    for (completed, status) in [
        (0, transaction_status::IDLE),
        (1, transaction_status::IDLE),
        (2, b'?'),
    ] {
        let mut conn = connect_authenticated();
        let before = conn.ready_sequence();
        conn.send_batch(&[
            ("SELECT 1".to_owned(), vec![]),
            ("SELECT 2".to_owned(), vec![]),
        ])
        .expect("複数文のバッチを送信できる");

        for _ in 0..completed {
            conn.feed_bytes(&command_complete("SELECT 1"))
                .expect("完了応答フレームを供給できる");
            assert!(matches!(
                conn.read_batch_results(2),
                Err(Error::NeedMoreData)
            ));
        }
        // 途中・最後の文が未完、または状態値が不正なら、同期番号を進めず接続を閉じる。
        conn.feed_bytes(&ready_for_query(status))
            .expect("同期応答フレームを供給できる");
        assert!(matches!(
            conn.read_batch_results(2),
            Err(Error::InternalError(_))
        ));
        assert_eq!(conn.ready_sequence(), before);
        assert!(!conn.is_open(), "同期を確認できない接続は再利用しない");
    }
}

#[test]
fn ready_sequence_is_shared_by_no_row_queries_batches_and_copy() {
    let mut conn = connect_authenticated();
    let before = conn.ready_sequence();

    // 行のないアンバッファードクエリは同期を終えてから戻り、使用中にしない。
    conn.feed_bytes(
        &[
            command_complete("UPDATE 2"),
            ready_for_query(transaction_status::IDLE),
        ]
        .concat(),
    )
    .expect("行を返さないクエリの応答を供給できる");
    assert_eq!(
        conn.query("UPDATE t SET x = 1", true)
            .expect("クエリを実行できる"),
        2
    );
    assert!(!conn.is_busy());
    assert_eq!(conn.ready_sequence(), before + 1);
    assert_eq!(pop_client_message(&mut conn).0, frontend::QUERY);

    // 空のバッチは Sync を送らないため、次のクエリに余分な ReadyForQuery が残らない。
    conn.send_batch(&[]).expect("空のバッチを処理できる");
    assert!(
        conn.read_batch_results(0)
            .expect("空の結果を取得できる")
            .is_empty()
    );
    assert!(conn.pop_send_queue().is_none());

    // 途中の CommandComplete は同期境界ではない。
    conn.send_batch(&[
        ("UPDATE t SET x = 2".to_string(), vec![]),
        (String::new(), vec![]),
    ])
    .expect("バッチを送信できる");
    assert!(
        conn.is_busy(),
        "最初の応答を読む前もバッチは同期を待っている"
    );
    assert!(matches!(
        conn.send_query("SELECT 1"),
        Err(Error::InterfaceError { .. })
    ));
    // 最後の空文では EmptyQueryResponse が Execute の完了を示す。
    for response in [
        command_complete("UPDATE 2"),
        build_message(backend::EMPTY_QUERY_RESPONSE, &[]),
    ] {
        conn.feed_bytes(&response)
            .expect("コマンド完了応答を供給できる");
        assert!(matches!(
            conn.read_batch_results(2),
            Err(Error::NeedMoreData)
        ));
        assert_eq!(conn.ready_sequence(), before + 1);
    }
    // 再試行時に文数を変えても進行は失われず、正しい文数で結果を回収できる。
    for count in [0, 1, 3] {
        assert!(matches!(
            conn.read_batch_results(count),
            Err(Error::InterfaceError { .. })
        ));
        assert_eq!(conn.ready_sequence(), before + 1);
    }
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("バッチの同期応答を供給できる");
    assert_eq!(
        conn.read_batch_results(2)
            .expect("バッチを同期できる")
            .len(),
        2
    );
    assert_eq!(conn.ready_sequence(), before + 2);

    // COPY 開始後にエラーが起き、汎用ドレインで同期すると COPY 状態が解除される。
    conn.send_copy_out("COPY t TO STDOUT")
        .expect("COPY を送信できる");
    conn.feed_bytes(&build_message(backend::COPY_OUT_RESPONSE, &[0, 0, 1, 0, 0]))
        .expect("COPY の開始応答を供給できる");
    conn.read_copy_out_response()
        .expect("COPY の開始応答を読める");
    conn.feed_bytes(&error_response(
        "57014",
        "canceling statement due to user request",
    ))
    .expect("キャンセルの応答を供給できる");
    assert!(matches!(
        conn.drain_canceled_request(),
        Err(Error::NeedMoreData)
    ));
    assert!(conn.is_busy());
    conn.feed_bytes(&ready_for_query(transaction_status::IDLE))
        .expect("COPY の同期応答を供給できる");
    assert!(
        conn.drain_canceled_request()
            .expect("COPY のキャンセル後に同期できる")
    );
    assert_eq!(conn.ready_sequence(), before + 3);
    assert!(!conn.is_busy());

    // キャンセルエラー未受信の次の操作も同期できるが、前の検出状態を引き継がない。
    conn.send_query("UPDATE t SET x = 4")
        .expect("クエリを送信できる");
    conn.feed_bytes(
        &[
            command_complete("UPDATE 2"),
            ready_for_query(transaction_status::IDLE),
        ]
        .concat(),
    )
    .expect("正常終了の応答を供給できる");
    assert!(
        !conn
            .drain_canceled_request()
            .expect("キャンセルを確認せずに同期できる")
    );
    assert_eq!(conn.ready_sequence(), before + 4);
}
