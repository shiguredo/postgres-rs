// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL メッセージストリーム。
//!
//! 受信した生バイト列をフレーム単位に分解し、送信メッセージをキューに積む。
//! フレーム形式は「1 バイトタイプ + 4 バイト長さ (自身を含む) + ペイロード」。
//!
//! 例外として、SSL 要求への応答はタイプ 1 バイトのみで
//! 長さヘッダーを持たないため、専用の状態で処理する。

use crate::constants::backend;
use crate::error::{Error, Result};
use crate::protocol::PostgresPacket;
use std::collections::VecDeque;

/// 長いメッセージを取りうる型以外で許す宣言長の上限。
///
/// libpq の `pqParseInput3` は、宣言長 (長さフィールド自身を含む) が 30000 を
/// 超えるメッセージを、長い型以外では同期喪失として扱う。
const SHORT_MESSAGE_LIMIT: usize = 30_000;

/// 30000 バイトを超えてよいバックエンドメッセージ型か。
///
/// `src/interfaces/libpq/fe-protocol3.c` の `VALID_LONG_MESSAGE_TYPE` と同じ集合。
/// `V` (FunctionCallResponse) はクライアントが使わないが、判定を揃えておく。
const fn is_long_message_type(message_type: u8) -> bool {
    matches!(
        message_type,
        backend::COPY_DATA
            | backend::DATA_ROW
            | backend::ERROR_RESPONSE
            | b'V'
            | backend::NOTICE_RESPONSE
            | backend::NOTIFICATION_RESPONSE
            | backend::ROW_DESCRIPTION
            | backend::PARAMETER_DESCRIPTION
    )
}

/// メッセージストリーム。
pub struct PacketStream {
    /// 送信すべきメッセージのキュー。
    pub send_queue: VecDeque<Vec<u8>>,
    /// 受信中の生バイト列。先頭の `consumed` バイトは解析済み。
    recv_buffer: Vec<u8>,
    /// 受信バッファの解析済みバイト数。
    ///
    /// フレームを切り出すたびにバッファの先頭を詰めると、1 回の読み取りに
    /// 多数のフレームが含まれるときに移動量がフレーム数の 2 乗に膨らむ。
    /// そのため消費位置を記録し、1 回の供給につき最後に 1 回だけ詰める。
    consumed: usize,
    /// 受信済みメッセージのキュー。
    pub recv_queue: VecDeque<PostgresPacket>,
    /// 許容する最大メッセージサイズ。
    max_message_size: usize,
    /// 次の受信が SSL 要求への応答 (1 バイトのみ) かどうか。
    tls_response_pending: bool,
}

impl PacketStream {
    /// 新規のメッセージストリームを作成する。
    pub fn new(max_message_size: usize) -> Self {
        Self {
            send_queue: VecDeque::new(),
            recv_buffer: Vec::new(),
            consumed: 0,
            recv_queue: VecDeque::new(),
            max_message_size,
            tls_response_pending: false,
        }
    }

    /// 組み立て済みメッセージを送信キューに追加する。
    pub fn write_message(&mut self, message: &[u8]) {
        self.send_queue.push_back(message.to_vec());
    }

    /// 次の受信を SSL 要求への応答として扱う。
    ///
    /// SSL 要求を送信した後に呼び出す。
    /// SSL 応答は 'S' または 'N' の 1 バイトのみで長さヘッダーを持たない。
    pub fn expect_tls_response(&mut self) {
        self.tls_response_pending = true;
    }

    /// SSL 要求への応答待ちかどうか。
    pub fn is_tls_response_pending(&self) -> bool {
        self.tls_response_pending
    }

    /// 受信した生バイト列を消費してメッセージを組み立て、recv_queue に追加する。
    ///
    /// 戻り値は追加されたメッセージ数。
    /// SSL 要求への応答を待っている間に 1 バイトを超える入力を受けた場合は、
    /// 受送信キューを破棄してエラーを返す。
    pub fn feed_bytes(&mut self, data: &[u8]) -> Result<usize> {
        if self.tls_response_pending {
            // PostgreSQL 18 公式文書 §54.2.10 の SSL Session Encryption に従い、
            // 交渉応答に続くデータを通常フレームとして扱わない。仕様が変わればここも見直す。
            let message_type = match (self.recv_buffer.as_slice(), data) {
                ([], []) => return Ok(0),
                ([], [byte]) => *byte,
                _ => {
                    self.force_close();
                    return Err(Error::internal(
                        "Invalid TLS response: expected a single byte",
                    ));
                }
            };
            self.tls_response_pending = false;
            self.recv_queue.push_back(PostgresPacket {
                message_type,
                data: Vec::new(),
            });
            return Ok(1);
        }

        self.recv_buffer.extend_from_slice(data);
        let mut packets_added = 0;
        loop {
            let remaining = self.recv_buffer.len() - self.consumed;
            if remaining < 5 {
                break;
            }
            let message_type = self.recv_buffer[self.consumed];
            let length = u32::from_be_bytes([
                self.recv_buffer[self.consumed + 1],
                self.recv_buffer[self.consumed + 2],
                self.recv_buffer[self.consumed + 3],
                self.recv_buffer[self.consumed + 4],
            ]) as usize;
            if length < 4 {
                self.force_close();
                return Err(Error::internal(format!(
                    "Invalid message length: {} (must be at least 4)",
                    length
                )));
            }
            // libpq と同じく、長いメッセージを取りうる型以外では
            // 宣言長が 30000 を超えるフレームを同期喪失として拒否する。
            // 受信バッファを確保する前に判定するため、長さだけを送られても消費しない。
            if length > SHORT_MESSAGE_LIMIT && !is_long_message_type(message_type) {
                self.force_close();
                return Err(Error::internal(format!(
                    "Got message longer than the libpq limit for message type {} ({} > {})",
                    message_type, length, SHORT_MESSAGE_LIMIT
                )));
            }
            let payload_len = length - 4;
            if payload_len > self.max_message_size {
                self.force_close();
                return Err(Error::internal(format!(
                    "Got message larger than max_message_size bytes ({} > {})",
                    payload_len, self.max_message_size
                )));
            }
            let Some(total_len) = 5usize.checked_add(payload_len) else {
                self.force_close();
                return Err(Error::internal("Message length overflow"));
            };
            if remaining < total_len {
                break;
            }
            let payload = self.recv_buffer[self.consumed + 5..self.consumed + total_len].to_vec();
            self.consumed += total_len;
            self.recv_queue.push_back(PostgresPacket {
                message_type,
                data: payload,
            });
            packets_added += 1;
        }
        // 解析済みの先頭を 1 回だけ詰める。バッファを消費し切ったときは
        // 容量を保ったまま長さを 0 に戻し、次の読み取りの確保を避ける。
        if self.consumed > 0 {
            if self.consumed == self.recv_buffer.len() {
                self.recv_buffer.clear();
            } else {
                self.recv_buffer.copy_within(self.consumed.., 0);
                self.recv_buffer
                    .truncate(self.recv_buffer.len() - self.consumed);
            }
            self.consumed = 0;
        }

        Ok(packets_added)
    }

    /// 受信済みメッセージキューから一つ取り出す。
    pub fn read_packet(&mut self) -> Result<PostgresPacket> {
        self.recv_queue.pop_front().ok_or(Error::NeedMoreData)
    }

    /// 強制的にキューをクリアする。
    pub fn force_close(&mut self) {
        self.send_queue.clear();
        self.recv_queue.clear();
        self.recv_buffer.clear();
        self.consumed = 0;
        self.tls_response_pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::backend;

    /// メッセージタイプとペイロードからフレーム化されたバイト列を組み立てる。
    pub(crate) fn build_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.push(message_type);
        message.extend_from_slice(&((payload.len() as u32 + 4).to_be_bytes()));
        message.extend_from_slice(payload);
        message
    }

    #[test]
    fn test_feed_bytes_multiple_messages() {
        let mut stream = PacketStream::new(1024);
        let mut payload = b"server_version\0".to_vec();
        payload.extend_from_slice(b"17.0\0");
        let mut data = build_message(backend::PARAMETER_STATUS, &payload);
        data.extend_from_slice(&build_message(backend::READY_FOR_QUERY, b"I"));
        let added = stream
            .feed_bytes(&data)
            .expect("複数メッセージの受信処理に成功しました");
        assert_eq!(added, 2);
        let packet = stream
            .read_packet()
            .expect("1 つ目のメッセージの取り出しに成功しました");
        assert_eq!(packet.message_type, backend::PARAMETER_STATUS);
        let packet = stream
            .read_packet()
            .expect("2 つ目のメッセージの取り出しに成功しました");
        assert_eq!(packet.message_type, backend::READY_FOR_QUERY);
    }

    #[test]
    fn test_feed_bytes_partial_message() {
        let mut stream = PacketStream::new(1024);
        let data = build_message(backend::READY_FOR_QUERY, b"I");
        // 1 バイトずつ供給しても最終的に 1 メッセージになる。
        for i in 0..data.len() {
            let added = stream
                .feed_bytes(&data[i..i + 1])
                .expect("1 バイトずつの受信処理に成功しました");
            if i + 1 < data.len() {
                assert_eq!(added, 0);
            }
        }
        let packet = stream
            .read_packet()
            .expect("メッセージの取り出しに成功しました");
        assert_eq!(packet.message_type, backend::READY_FOR_QUERY);
        assert!(matches!(stream.read_packet(), Err(Error::NeedMoreData)));
    }

    #[test]
    fn test_feed_bytes_invalid_length() {
        let mut stream = PacketStream::new(1024);
        // 長さ 3 は不正 (自身を含めて 4 以上必要)。
        let data = vec![backend::READY_FOR_QUERY, 0, 0, 0, 3, b'I'];
        let result = stream.feed_bytes(&data);
        assert!(result.is_err());
    }

    /// 宣言長だけのヘッダーを組み立てる。本文は付けない。
    fn build_header(message_type: u8, length: u32) -> Vec<u8> {
        let mut header = vec![message_type];
        header.extend_from_slice(&length.to_be_bytes());
        header
    }

    #[test]
    fn test_short_message_type_limit() {
        // 短い型は libpq と同じく 30000 バイトまでを受理する。
        let mut stream = PacketStream::new(1024 * 1024);
        stream
            .feed_bytes(&build_header(backend::READY_FOR_QUERY, 30_000))
            .expect("30000 バイトの短い型は受理されます");
        // 30001 バイトは長い型でだけ許される。
        let mut stream = PacketStream::new(1024 * 1024);
        assert!(matches!(
            stream.feed_bytes(&build_header(backend::READY_FOR_QUERY, 30_001)),
            Err(Error::InternalError(_))
        ));
        let mut stream = PacketStream::new(1024 * 1024);
        stream
            .feed_bytes(&build_header(backend::DATA_ROW, 30_001))
            .expect("長い型は 30001 バイトでも受理されます");
        // 長さ 3 は型に関係なく拒否する。
        let mut stream = PacketStream::new(1024 * 1024);
        assert!(matches!(
            stream.feed_bytes(&build_header(backend::DATA_ROW, 3)),
            Err(Error::InternalError(_))
        ));
    }

    #[test]
    fn test_feed_bytes_over_max_message_size() {
        let mut stream = PacketStream::new(1024);
        let payload = vec![0u8; 1025];
        let data = build_message(backend::DATA_ROW, &payload);
        let result = stream.feed_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_response() {
        let mut stream = PacketStream::new(1024);
        stream.expect_tls_response();
        // 空の入力は待機を維持し、1 バイトの応答だけを取り出せる。
        assert_eq!(stream.feed_bytes(&[]).expect("空の入力を許可します"), 0);
        assert!(stream.is_tls_response_pending());
        let added = stream
            .feed_bytes(b"S")
            .expect("TLS 応答の受信処理に成功しました");
        assert_eq!(added, 1);
        assert!(!stream.is_tls_response_pending());
        let packet = stream
            .read_packet()
            .expect("TLS 応答の取り出しに成功しました");
        assert_eq!(packet.message_type, b'S');
        assert!(packet.data.is_empty());
        assert!(matches!(stream.read_packet(), Err(Error::NeedMoreData)));
    }

    #[test]
    fn test_tls_response_with_extra_bytes() {
        // 交渉結果や後続データのフレーム完全性によらず、余分な 1 バイトで拒否する。
        for response in [b'S', b'N', b'E'] {
            let mut stream = PacketStream::new(1024);
            stream.write_message(&crate::protocol::ssl_request_message());
            stream.expect_tls_response();
            assert!(matches!(
                stream.feed_bytes(&[response, b' ']),
                Err(Error::InternalError(_))
            ));
            assert!(!stream.is_tls_response_pending());
            assert!(stream.send_queue.is_empty());
            assert!(stream.recv_buffer.is_empty());
            assert!(matches!(stream.read_packet(), Err(Error::NeedMoreData)));
        }
    }

    #[test]
    fn test_force_close() {
        let mut stream = PacketStream::new(1024);
        stream.write_message(&build_message(backend::READY_FOR_QUERY, b"I"));
        let data = build_message(backend::READY_FOR_QUERY, b"I");
        stream
            .feed_bytes(&data)
            .expect("強制クローズ前のメッセージ受信に成功しました");
        stream.force_close();
        assert!(stream.send_queue.is_empty());
        assert!(stream.recv_queue.is_empty());
        assert!(matches!(stream.read_packet(), Err(Error::NeedMoreData)));
    }
}
