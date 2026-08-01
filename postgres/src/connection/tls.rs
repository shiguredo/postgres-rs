// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 接続設定に応じて TLS のサーバー証明書検証とクライアント認証を構成する。

use super::{ConnectOptions, SslMode};
use crate::error::{Error, Result};
use rustls::client::WantsClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject};
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
        let keys: Vec<PrivatePkcs8KeyDer<'static>> = PrivatePkcs8KeyDer::pem_slice_iter(&key_file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::operational(format!("Failed to parse client key file: {}", e)))?;
        if keys.is_empty() {
            return Err(Error::operational("No PKCS8 private key found"));
        }
        config.with_client_auth_cert(
            certs,
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                keys.into_iter()
                    .next()
                    .expect("at least one PKCS8 private key was verified above"),
            ),
        )
    } else {
        Ok(config.with_no_client_auth())
    };

    config.map_err(|e| Error::operational(format!("Failed to build TLS config: {}", e)))
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
}
