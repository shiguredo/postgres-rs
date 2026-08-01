// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL メッセージストリーム。
//!
//! 受信した生バイト列をフレーム単位に分解し、送信メッセージをキューに積む。
//! フレーム形式は「1 バイトタイプ + 4 バイト長さ (自身を含む) + ペイロード」。
//!
//! 例外として、SSL 要求への応答はタイプ 1 バイトのみで
//! 長さヘッダーを持たないため、専用の状態で処理する。

use crate::error::{Error, Result};
use crate::protocol::PostgresPacket;
use std::collections::VecDeque;

/// メッセージストリーム。
pub struct PacketStream {
    /// 送信すべきメッセージのキュー。
    pub send_queue: VecDeque<Vec<u8>>,
    /// 受信中の生バイト列。
    recv_buffer: Vec<u8>,
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
    pub fn feed_bytes(&mut self, data: &[u8]) -> Result<usize> {
        self.recv_buffer.extend_from_slice(data);
        let mut packets_added = 0;

        if self.tls_response_pending {
            if self.recv_buffer.is_empty() {
                return Ok(0);
            }
            let message_type = self.recv_buffer[0];
            self.recv_buffer.drain(..1);
            self.tls_response_pending = false;
            self.recv_queue.push_back(PostgresPacket {
                message_type,
                data: Vec::new(),
            });
            packets_added += 1;
        }

        loop {
            if self.recv_buffer.len() < 5 {
                break;
            }
            let message_type = self.recv_buffer[0];
            let length = u32::from_be_bytes([
                self.recv_buffer[1],
                self.recv_buffer[2],
                self.recv_buffer[3],
                self.recv_buffer[4],
            ]) as usize;
            if length < 4 {
                self.force_close();
                return Err(Error::InternalError {
                    code: String::new(),
                    message: format!("Invalid message length: {} (must be at least 4)", length),
                });
            }
            let payload_len = length - 4;
            if payload_len > self.max_message_size {
                self.force_close();
                return Err(Error::InternalError {
                    code: String::new(),
                    message: format!(
                        "Got message larger than max_message_size bytes ({} > {})",
                        payload_len, self.max_message_size
                    ),
                });
            }
            let total_len = 5 + payload_len;
            if self.recv_buffer.len() < total_len {
                break;
            }
            let payload = self.recv_buffer[5..total_len].to_vec();
            self.recv_buffer.drain(..total_len);
            self.recv_queue.push_back(PostgresPacket {
                message_type,
                data: payload,
            });
            packets_added += 1;
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
        let added = stream.feed_bytes(&data).unwrap();
        assert_eq!(added, 2);
        let packet = stream.read_packet().unwrap();
        assert_eq!(packet.message_type, backend::PARAMETER_STATUS);
        let packet = stream.read_packet().unwrap();
        assert_eq!(packet.message_type, backend::READY_FOR_QUERY);
    }

    #[test]
    fn test_feed_bytes_partial_message() {
        let mut stream = PacketStream::new(1024);
        let data = build_message(backend::READY_FOR_QUERY, b"I");
        // 1 バイトずつ供給しても最終的に 1 メッセージになる。
        for i in 0..data.len() {
            let added = stream.feed_bytes(&data[i..i + 1]).unwrap();
            if i + 1 < data.len() {
                assert_eq!(added, 0);
            }
        }
        let packet = stream.read_packet().unwrap();
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
        // TLS 応答は 1 バイトのみ。続けて通常メッセージも流れる。
        let mut data = vec![b'S'];
        data.extend_from_slice(&build_message(backend::READY_FOR_QUERY, b"I"));
        let added = stream.feed_bytes(&data).unwrap();
        assert_eq!(added, 2);
        let packet = stream.read_packet().unwrap();
        assert_eq!(packet.message_type, b'S');
        assert!(packet.data.is_empty());
        let packet = stream.read_packet().unwrap();
        assert_eq!(packet.message_type, backend::READY_FOR_QUERY);
    }

    #[test]
    fn test_force_close() {
        let mut stream = PacketStream::new(1024);
        stream.write_message(&build_message(backend::READY_FOR_QUERY, b"I"));
        let data = build_message(backend::READY_FOR_QUERY, b"I");
        stream.feed_bytes(&data).unwrap();
        stream.force_close();
        assert!(stream.send_queue.is_empty());
        assert!(stream.recv_queue.is_empty());
        assert!(matches!(stream.read_packet(), Err(Error::NeedMoreData)));
    }
}
