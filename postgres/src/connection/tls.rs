// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 接続設定に応じて TLS のサーバー証明書検証とクライアント認証を構成する。

use super::{ConnectOptions, SslMode};
use crate::error::{Error, Result};
use rustls::client::WantsClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::server::ParsedCertificate;
use rustls::{ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use std::net::IpAddr;
use std::sync::Arc;

/// ホスト名または IP アドレスから TLS の ServerName を生成する。
pub(super) fn server_name_from_host(host: &str) -> Result<ServerName<'static>> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|_| Error::operational("Invalid server hostname for TLS"))
}

/// 接続モードで指定された検証とクライアント認証を構成する。
pub(super) async fn build_tls_config(options: &ConnectOptions) -> Result<ClientConfig> {
    let roots = if let Some(ca_path) = &options.ssl_ca {
        let mut root_store = RootCertStore::empty();
        let cert_file = tokio::fs::read(ca_path)
            .await
            .map_err(|error| Error::operational(format!("Failed to read CA file: {error}")))?;
        for cert in CertificateDer::pem_slice_iter(&cert_file) {
            let cert = cert
                .map_err(|error| Error::operational(format!("Failed to parse CA file: {error}")))?;
            root_store
                .add(cert)
                .map_err(|error| Error::operational(format!("Invalid CA certificate: {error}")))?;
        }
        if root_store.is_empty() {
            return Err(Error::operational("No trust anchors found in CA file"));
        }
        Some(root_store)
    } else if options.ssl_mode == SslMode::VerifyCa {
        let certs = tokio::task::spawn_blocking(rustls_native_certs::load_native_certs)
            .await
            .map_err(|error| {
                Error::operational(format!("Failed to load system certificates: {error}"))
            })?;
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(certs.certs);
        Some(root_store)
    } else {
        None
    };
    let config = configure_verifier(options.ssl_mode, roots)?;

    if (options.ssl_cert.is_some()) != (options.ssl_key.is_some()) {
        return Err(Error::operational(
            "ssl_cert and ssl_key must be specified together",
        ));
    }

    let config = if let (Some(cert_path), Some(key_path)) = (&options.ssl_cert, &options.ssl_key) {
        let cert_file = tokio::fs::read(cert_path)
            .await
            .map_err(|e| Error::operational(format!("Failed to read client cert file: {}", e)))?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::operational(format!("Failed to parse client cert file: {}", e)))?;

        let key_file = tokio::fs::read(key_path)
            .await
            .map_err(|e| Error::operational(format!("Failed to read client key file: {}", e)))?;
        config.with_client_auth_cert(certs, client_private_key(&key_file)?)
    } else {
        Ok(config.with_no_client_auth())
    };

    config.map_err(|e| Error::operational(format!("Failed to build TLS config: {}", e)))
}

/// クライアント秘密鍵を読み込む。
///
/// PEM のラベルが `PRIVATE KEY` の PKCS#8、`RSA PRIVATE KEY` の PKCS#1 (RSA 鍵)、
/// `EC PRIVATE KEY` の SEC1 (EC 鍵) を受け付け、ファイルの中で最初に見つかった鍵を使う。
/// 証明書など鍵以外の PEM セクションは読み飛ばす。PEM の鍵が見つからない場合は、
/// ファイル全体を同じ 3 形式の DER として読む。
/// 暗号化された鍵 (ラベルが `ENCRYPTED PRIVATE KEY` のものなど) には対応しない。
fn client_private_key(data: &[u8]) -> Result<PrivateKeyDer<'static>> {
    // PostgreSQL 19 の src/interfaces/libpq/fe-secure-openssl.c (initialize_SSL) は sslkey を
    // SSL_use_PrivateKey_file で PEM として読み、失敗した場合は DER (SSL_FILETYPE_ASN1) として
    // 読み直す。OpenSSL が読める鍵形式のうち、暗号化されていない 3 形式を同じ順で受け付ける。
    // 将来 libpq が鍵の読み込み方法を変えた場合はここを見直す。
    match PrivateKeyDer::from_pem_slice(data) {
        Ok(key) => Ok(key),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => PrivateKeyDer::try_from(data)
            .map(|key| key.clone_key())
            .map_err(|_| {
                Error::operational(
                    "No unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC private key found in client key file",
                )
            }),
        Err(error) => Err(Error::operational(format!(
            "Failed to parse client key file: {error}"
        ))),
    }
}

/// モード別の検証を構成する。名前を照合しない場合も、ハンドシェイク署名は必須とする。
fn configure_verifier(
    mode: SslMode,
    roots: Option<RootCertStore>,
) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            Error::operational(format!(
                "Failed to configure TLS protocol versions: {error}"
            ))
        })?;

    // PostgreSQL 18 libpq-ssl §32.19.1 では require に CA があれば verify-ca 相当になる。
    // 本実装は暗黙のファイルを探さず、明示された sslrootcert だけをこの互換規則に使う。
    // 将来 libpq の互換規則が変わった場合にはこの分岐を見直す。
    match (mode, roots) {
        (SslMode::VerifyFull, Some(roots)) => Ok(builder.with_root_certificates(roots)),
        (SslMode::VerifyFull, None) => builder.with_platform_verifier().map_err(|error| {
            Error::operational(format!("Failed to configure platform verifier: {error}"))
        }),
        (SslMode::VerifyCa, Some(roots)) | (SslMode::Required, Some(roots))
            if !roots.is_empty() =>
        {
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoNameVerifier {
                    roots: Some(roots),
                    algorithms,
                })))
        }
        (SslMode::Required, None) => {
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoNameVerifier {
                    roots: None,
                    algorithms,
                })))
        }
        (SslMode::VerifyCa | SslMode::Required, _) => {
            Err(Error::operational("No TLS trust anchors available"))
        }
        (SslMode::Disabled, _) => Err(Error::internal("TLS is disabled")),
    }
}

/// 明示されたモードに限り接続先の名前照合を省略する。信頼アンカーありなら信頼チェーンを検証する。
#[derive(Debug)]
struct NoNameVerifier {
    roots: Option<RootCertStore>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        if let Some(roots) = &self.roots {
            // RFC 5280 §6 のパス検証は rustls に委ねる。名前照合や失効確認はしない。
            // 将来 rustls の検証契約が変わった場合はこの呼び出しを見直す。
            verify_server_cert_signed_by_trust_anchor(
                &cert,
                roots,
                intermediates,
                now,
                self.algorithms.all,
            )?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    #[tokio::test]
    async fn test_certificate_verification_by_ssl_mode() {
        // プロセス内で生成した CA とサーバー証明書で、実際の TLS ハンドシェイクを検査する。
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let ca_key = rcgen::KeyPair::generate().expect("検証用 CA の鍵を生成できません");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("検証用 CA を作成できません");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().expect("検証用サーバーの鍵を生成できません");
        let leaf = rcgen::CertificateParams::new(vec!["db.example.invalid".to_owned()])
            .expect("検証用サーバー名を設定できません")
            .signed_by(&key, &issuer)
            .expect("検証用サーバー証明書を署名できません");
        let other_ca = rcgen::generate_simple_self_signed(vec!["other.example.invalid".to_owned()])
            .expect("信頼チェーンの不一致を検査する証明書を生成できません");
        let mut trusted = RootCertStore::empty();
        trusted
            .add(ca.der().clone())
            .expect("検証用 CA を登録できません");
        let mut untrusted = RootCertStore::empty();
        untrusted
            .add(other_ca.cert.der().clone())
            .expect("比較用の証明書を登録できません");

        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let server = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[version])
                .expect("検証対象の TLS バージョンを設定できません")
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone()],
                    PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .expect("サーバー証明書と鍵を設定できません");
            let server = tokio_rustls::TlsAcceptor::from(Arc::new(server));

            // 名前不一致と信頼チェーン不一致を別々に確認する。require は明示 CA があれば検証する。
            for (mode, roots, host, expected) in [
                (
                    SslMode::VerifyFull,
                    Some(&trusted),
                    "db.example.invalid",
                    true,
                ),
                (
                    SslMode::VerifyFull,
                    Some(&trusted),
                    "wrong.example.invalid",
                    false,
                ),
                (
                    SslMode::VerifyCa,
                    Some(&trusted),
                    "wrong.example.invalid",
                    true,
                ),
                (
                    SslMode::VerifyCa,
                    Some(&untrusted),
                    "db.example.invalid",
                    false,
                ),
                (
                    SslMode::Required,
                    Some(&trusted),
                    "wrong.example.invalid",
                    true,
                ),
                (
                    SslMode::Required,
                    Some(&untrusted),
                    "db.example.invalid",
                    false,
                ),
                (SslMode::Required, None, "wrong.example.invalid", true),
            ] {
                let config = configure_verifier(mode, roots.cloned())
                    .expect("検証対象のクライアントを設定できません")
                    .with_no_client_auth();
                let client = tokio_rustls::TlsConnector::from(Arc::new(config));
                let name = server_name_from_host(host).expect("検証対象の名前を設定できません");
                let (client_io, server_io) = tokio::io::duplex(16 * 1024);
                let (client_result, server_result) =
                    tokio::join!(client.connect(name, client_io), server.accept(server_io));
                assert_eq!(
                    client_result.is_ok(),
                    expected,
                    "{mode:?} / {version:?} / {host} の検証結果が異なります: {:?}",
                    client_result.err()
                );
                if expected {
                    assert!(
                        server_result.is_ok(),
                        "サーバー側で TLS の確立に失敗しました: {:?}",
                        server_result.err()
                    );
                }
            }
        }
    }

    /// DER の TLV を 1 つ読み、指定したタグであることを確かめて (中身, 残り) を返す。
    ///
    /// 試験で生成した鍵の構造だけを読むため、長さは 2 バイトまでの形式に限る。
    fn der_tlv(input: &[u8], tag: u8) -> (&[u8], &[u8]) {
        assert_eq!(input[0], tag, "DER のタグが想定と異なります");
        let (length, header) = match input[1] {
            n if n < 0x80 => (usize::from(n), 2),
            0x81 => (usize::from(input[2]), 3),
            0x82 => ((usize::from(input[2]) << 8) | usize::from(input[3]), 4),
            other => panic!("想定していない DER の長さ形式です: {other:#04x}"),
        };
        (&input[header..header + length], &input[header + length..])
    }

    /// PKCS#8 の PrivateKeyInfo から privateKey の中身を取り出す。
    ///
    /// RFC 5958 §2 の PrivateKeyInfo は version、privateKeyAlgorithm、privateKey の順に並ぶ。
    /// RSA 鍵では privateKey の中身が RFC 8017 付録 A.1.2 の RSAPrivateKey (PKCS#1) になる。
    fn pkcs8_private_key(der: &[u8]) -> &[u8] {
        let (body, _) = der_tlv(der, 0x30);
        let (_, rest) = der_tlv(body, 0x02);
        let (_, rest) = der_tlv(rest, 0x30);
        let (private_key, _) = der_tlv(rest, 0x04);
        private_key
    }

    /// DER を PEM に変換する。
    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        use base64ct::Encoding;
        let body = base64ct::Base64::encode_string(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 の出力は ASCII です"));
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out.into_bytes()
    }

    #[tokio::test]
    async fn test_client_key_formats() {
        use aws_lc_rs::encoding::AsDer;

        // クライアント証明書を必須にしたサーバーと実際にハンドシェイクし、
        // 読み込んだ鍵で CertificateVerify の署名が通ることまで確かめる。
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let ca_key = rcgen::KeyPair::generate().expect("検証用 CA の鍵を生成できません");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("検証用 CA を作成できません");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let server_key = rcgen::KeyPair::generate().expect("検証用サーバーの鍵を生成できません");
        let server_cert = rcgen::CertificateParams::new(vec!["db.example.invalid".to_owned()])
            .expect("検証用サーバー名を設定できません")
            .signed_by(&server_key, &issuer)
            .expect("検証用サーバー証明書を署名できません");
        let mut roots = RootCertStore::empty();
        roots
            .add(ca.der().clone())
            .expect("検証用 CA を登録できません");

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            provider.clone(),
        )
        .build()
        .expect("クライアント証明書の検証を設定できません");
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS バージョンを設定できません")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .expect("サーバー証明書と鍵を設定できません");
        let server = tokio_rustls::TlsAcceptor::from(Arc::new(server));

        let ec_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("EC のクライアント鍵を生成できません");
        let rsa_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .expect("RSA のクライアント鍵を生成できません");
        let client_params =
            rcgen::CertificateParams::new(vec!["client.example.invalid".to_owned()])
                .expect("クライアント名を設定できません");
        let ec_cert = client_params
            .clone()
            .signed_by(&ec_key, &issuer)
            .expect("EC のクライアント証明書を署名できません");
        let rsa_cert = client_params
            .signed_by(&rsa_key, &issuer)
            .expect("RSA のクライアント証明書を署名できません");

        let ec_pkcs8 = ec_key.serialize_der();
        // openssl ec の出力と同じく、曲線の指定 (parameters) を含む SEC1 の鍵を書き出す。
        let ec_sec1 = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ec_pkcs8,
        )
        .expect("EC 鍵を読み込めません")
        .private_key()
        .as_der()
        .expect("SEC1 形式の EC 鍵を書き出せません")
        .as_ref()
        .to_vec();
        // RFC 5915 §3 の ECPrivateKey は version、privateKey、parameters [0] の順に並ぶ。
        let (body, _) = der_tlv(&ec_sec1, 0x30);
        let (_, rest) = der_tlv(body, 0x02);
        let (_, rest) = der_tlv(rest, 0x04);
        assert_eq!(rest[0], 0xa0, "SEC1 の鍵に曲線の指定が含まれていません");
        let rsa_pkcs8 = rsa_key.serialize_der();
        let rsa_pkcs1 = pkcs8_private_key(&rsa_pkcs8).to_vec();

        // 証明書の後ろに鍵を置いたファイルでも、証明書を読み飛ばして鍵を見つける。
        let mut cert_then_key = pem("CERTIFICATE", ec_cert.der());
        cert_then_key.extend_from_slice(&pem("EC PRIVATE KEY", &ec_sec1));

        for (label, data, cert, expected) in [
            (
                "PEM の PKCS#8 (EC)",
                pem("PRIVATE KEY", &ec_pkcs8),
                &ec_cert,
                "pkcs8",
            ),
            (
                "PEM の SEC1",
                pem("EC PRIVATE KEY", &ec_sec1),
                &ec_cert,
                "sec1",
            ),
            ("証明書の後ろの SEC1", cert_then_key, &ec_cert, "sec1"),
            (
                "PEM の PKCS#8 (RSA)",
                pem("PRIVATE KEY", &rsa_pkcs8),
                &rsa_cert,
                "pkcs8",
            ),
            (
                "PEM の PKCS#1",
                pem("RSA PRIVATE KEY", &rsa_pkcs1),
                &rsa_cert,
                "pkcs1",
            ),
            ("DER の SEC1", ec_sec1.clone(), &ec_cert, "sec1"),
            ("DER の PKCS#1", rsa_pkcs1.clone(), &rsa_cert, "pkcs1"),
        ] {
            let key = client_private_key(&data)
                .unwrap_or_else(|error| panic!("{label} の鍵を読み込めません: {error}"));
            let kind = match &key {
                PrivateKeyDer::Pkcs1(_) => "pkcs1",
                PrivateKeyDer::Sec1(_) => "sec1",
                PrivateKeyDer::Pkcs8(_) => "pkcs8",
                _ => "other",
            };
            assert_eq!(kind, expected, "{label} の鍵の形式が異なります");

            let config = configure_verifier(SslMode::VerifyFull, Some(roots.clone()))
                .expect("検証対象のクライアントを設定できません")
                .with_client_auth_cert(vec![cert.der().clone()], key)
                .unwrap_or_else(|error| {
                    panic!("{label} の鍵をクライアント認証に設定できません: {error}")
                });
            let client = tokio_rustls::TlsConnector::from(Arc::new(config));
            let name = server_name_from_host("db.example.invalid")
                .expect("検証対象の名前を設定できません");
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let (client_result, server_result) =
                tokio::join!(client.connect(name, client_io), server.accept(server_io));
            assert!(
                client_result.is_ok(),
                "{label} の鍵で TLS を確立できません: {:?}",
                client_result.err()
            );
            let server_stream = server_result.unwrap_or_else(|error| {
                panic!("{label} の鍵でサーバーが TLS を確立できません: {error}")
            });
            assert!(
                server_stream.get_ref().1.peer_certificates().is_some(),
                "{label} の鍵でクライアント証明書が届いていません"
            );
        }
    }

    #[test]
    fn test_client_key_without_usable_key() {
        // 暗号化された鍵と鍵を含まないファイルは、読めない理由が分かるエラーにする。
        let expected =
            "No unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC private key found in client key file";
        for (label, data) in [
            (
                "暗号化された鍵",
                pem("ENCRYPTED PRIVATE KEY", &[0x30, 0x00]),
            ),
            ("証明書だけのファイル", pem("CERTIFICATE", &[0x30, 0x00])),
            ("空のファイル", Vec::new()),
        ] {
            let error =
                client_private_key(&data).expect_err("使える鍵がないのに読み込みに成功しました");
            assert_eq!(error.message(), expected, "{label} のエラーが異なります");
        }
    }
}
