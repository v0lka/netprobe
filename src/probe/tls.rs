//! TLS handshake prober

use crate::probe::ProbeError;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, pki_types::ServerName};
use x509_parser::prelude::*;

/// TLS connection status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsStatus {
    Ok,
    #[allow(dead_code)]
    Error,
}

/// TLS information extracted from the handshake
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub handshake_ms: f64,
    pub version: String,
    pub cipher: String,
    pub cert_subject: String,
    pub cert_issuer: String,
    pub cert_san: Vec<String>,
    pub cert_expiry: chrono::DateTime<chrono::Utc>,
    pub cert_days_remaining: i64,
    #[allow(dead_code)]
    pub status: TlsStatus,
}

/// Perform a TLS handshake with precise timing
/// Uses tokio-rustls for async TLS handshake and x509-parser for certificate parsing
pub async fn tls_handshake(
    tokio_stream: TokioTcpStream,
    hostname: &str,
    timeout_duration: Duration,
) -> Result<(TlsStream<TokioTcpStream>, TlsInfo), ProbeError> {
    let start = Instant::now();

    // Build TLS client config with webpki roots
    let config = build_tls_config()?;
    let connector = TlsConnector::from(Arc::new(config));

    // Parse server name
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|_| ProbeError::Other("Invalid hostname".to_string()))?;

    // Perform async TLS handshake with timeout
    let tls_stream = timeout(
        timeout_duration,
        connector.connect(server_name, tokio_stream),
    )
    .await
    .map_err(|_| ProbeError::Timeout)?
    .map_err(|e| ProbeError::Other(format!("TLS handshake failed: {}", e)))?;

    let elapsed = start.elapsed();
    let handshake_ms = elapsed.as_secs_f64() * 1000.0;

    // Extract TLS information from the established connection
    let info = extract_tls_info(&tls_stream, handshake_ms)?;

    Ok((tls_stream, info))
}

/// Build TLS client configuration
fn build_tls_config() -> Result<ClientConfig, ProbeError> {
    // Use ring as the crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();

    // Add webpki roots (Mozilla root certificates)
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

/// Extract TLS information from the established connection
fn extract_tls_info<S>(stream: &TlsStream<S>, handshake_ms: f64) -> Result<TlsInfo, ProbeError> {
    // Get the connection info from the TLS stream
    let (_, conn) = stream.get_ref();

    // Get TLS version
    let version = match conn.protocol_version() {
        Some(v) => format!("{:?}", v).replace("TLSv1_", "TLSv1."),
        None => "Unknown".to_string(),
    };

    // Get cipher suite
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_else(|| "Unknown".to_string());

    // Get peer certificates
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| ProbeError::Other("No peer certificates available".to_string()))?;

    if certs.is_empty() {
        return Err(ProbeError::Other("Empty certificate chain".to_string()));
    }

    // Parse the leaf certificate (first in chain)
    let leaf_cert = &certs[0];
    let (_, cert) = X509Certificate::from_der(leaf_cert.as_ref())
        .map_err(|e| ProbeError::ParseError(format!("Failed to parse certificate: {}", e)))?;

    // Extract subject
    let cert_subject = cert.subject().to_string();

    // Extract issuer
    let cert_issuer = cert.issuer().to_string();

    // Extract SAN (Subject Alternative Names)
    let cert_san = extract_san(&cert);

    // Extract validity
    let validity = cert.validity();
    let not_after = validity.not_after;

    // Convert to chrono DateTime
    let cert_expiry =
        chrono::DateTime::from_timestamp(not_after.timestamp(), 0).unwrap_or_else(chrono::Utc::now);

    // Calculate days remaining
    let now = chrono::Utc::now();
    let cert_days_remaining = (cert_expiry - now).num_days();

    Ok(TlsInfo {
        handshake_ms,
        version,
        cipher,
        cert_subject,
        cert_issuer,
        cert_san,
        cert_expiry,
        cert_days_remaining,
        status: TlsStatus::Ok,
    })
}

/// Extract Subject Alternative Names from certificate
fn extract_san(cert: &X509Certificate) -> Vec<String> {
    let mut san_list = Vec::new();

    for extension in cert.extensions() {
        // The extension is already parsed in x509-parser 0.18
        // We access parsed_extension directly
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => san_list.push(dns.to_string()),
                    GeneralName::IPAddress(ip) => {
                        let ip_str = match ip.len() {
                            4 => {
                                let octets: [u8; 4] = ip[..4].try_into().unwrap_or([0, 0, 0, 0]);
                                std::net::Ipv4Addr::from(octets).to_string()
                            }
                            16 => {
                                let octets: [u8; 16] = ip[..16].try_into().unwrap_or([0; 16]);
                                std::net::Ipv6Addr::from(octets).to_string()
                            }
                            _ => continue,
                        };
                        san_list.push(ip_str);
                    }
                    _ => {}
                }
            }
        }
    }

    san_list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_status_enum() {
        assert_eq!(TlsStatus::Ok, TlsStatus::Ok);
        assert_ne!(TlsStatus::Ok, TlsStatus::Error);
    }

    #[test]
    fn test_tls_info_structure() {
        let info = TlsInfo {
            handshake_ms: 42.3,
            version: "TLSv1.3".to_string(),
            cipher: "TLS_AES_256_GCM_SHA384".to_string(),
            cert_subject: "CN=example.com".to_string(),
            cert_issuer: "CN=Test CA".to_string(),
            cert_san: vec!["example.com".to_string(), "www.example.com".to_string()],
            cert_expiry: chrono::Utc::now() + chrono::Duration::days(90),
            cert_days_remaining: 90,
            status: TlsStatus::Ok,
        };

        assert_eq!(info.handshake_ms, 42.3);
        assert_eq!(info.version, "TLSv1.3");
        assert_eq!(info.cert_days_remaining, 90);
    }
}
