//! WARP-flavoured TLS for MASQUE endpoints.
//!
//! Cloudflare's MASQUE endpoints are not ordinary HTTPS servers, so the usual
//! "verify the certificate against the SNI" rule cannot be applied:
//!
//! * **the SNI is a decoy.** Clients reach the edge with an unrelated name
//!   (`www.microsoft.com` in the wild, `consumer-masque.cloudflareclient.com`
//!   by default), so hostname verification would always fail.
//! * **the device authenticates with a client certificate** whose key is the
//!   registered ECDSA P-256 private key. Presenting it is what identifies the
//!   device; skipping it means the edge has nothing to recognise.
//! * **the endpoint is authenticated by pinning its public key** instead of
//!   walking a CA chain.
//!
//! ALPN then selects the carrier: `h2` for HTTP/2, `h3` for HTTP/3.
//!
//! Reference behaviour: `usque` (`api.PrepareTlsConfig`) and mihomo
//! (`transport/masque.PrepareTlsConfig`), which agree field for field.

use base64::Engine as _;
use boring::asn1::{Asn1Integer, Asn1Time};
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private, Public};
use boring::ssl::{SslAlert, SslConnector, SslMethod, SslRef, SslVerifyError, SslVerifyMode};
use boring::x509::{X509, X509Builder, X509NameBuilder};
use honk_config::node::Node;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// SNI Cloudflare's consumer WARP endpoints are registered under. A node may
/// override it to masquerade as unrelated HTTPS traffic.
pub(super) const DEFAULT_SNI: &str = "consumer-masque.cloudflareclient.com";

/// How long the generated self-signed device certificate stays valid. The edge
/// only reads its public key, so this is a formality.
const CERT_VALID_DAYS: u32 = 3650;

/// A MASQUE node's TLS identity: a connector carrying the device certificate
/// and, when configured, the endpoint pin.
pub struct WarpIdentity {
    connector: SslConnector,
    server_name: String,
}

impl WarpIdentity {
    /// Build the node's TLS identity from its key material.
    pub fn build(node: &Node) -> anyhow::Result<Self> {
        let config = node
            .masque()
            .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
        let private_key = config.private_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "masque node {} has no private-key; WARP endpoints authenticate the device \
                 with a client certificate",
                node.name
            )
        })?;
        let device = PKey::private_key_from_der(&decode_base64(private_key, "private-key")?)?;
        let certificate = self_signed(&device)?;

        let pinned = match config.endpoint_public_key.as_deref() {
            Some(key) => Some(PKey::public_key_from_der(&decode_base64(
                key,
                "public-key",
            )?)?),
            None => None,
        };

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
        // The SNI is a decoy, so PKI verification is replaced by the pin below.
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_certificate(&certificate)?;
        builder.set_private_key(&device)?;
        match pinned {
            Some(pinned) => {
                builder.set_custom_verify_callback(SslVerifyMode::PEER, pin_endpoint_key(pinned));
            }
            None => {
                tracing::warn!(
                    "masque node {}: no public-key, so the endpoint is not pinned",
                    node.name
                );
            }
        }
        // The carrier is chosen per node; HTTP/2 nodes must not offer h3.
        builder.set_alpn_protos(ALPN_H2_WIRE)?;

        Ok(Self {
            connector: builder.build(),
            server_name: config
                .tls
                .sni
                .clone()
                .unwrap_or_else(|| DEFAULT_SNI.to_string()),
        })
    }

    /// The name presented as the decoy SNI.
    pub fn sni(&self) -> &str {
        &self.server_name
    }

    /// Run the TLS handshake. `server_name` reaches the edge as the decoy SNI.
    pub async fn connect<S>(
        &self,
        stream: S,
        timeout: Duration,
    ) -> anyhow::Result<tokio_boring::SslStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let configuration = self.connector.configure()?;
        let handshake = tokio_boring::connect(configuration, &self.server_name, stream);
        tokio::time::timeout(timeout, handshake)
            .await
            .map_err(|_| anyhow::anyhow!("masque TLS handshake timed out after {timeout:?}"))?
            .map_err(|error| anyhow::anyhow!("masque TLS handshake failed: {error}"))
    }
}

/// ALPN wire format for a single `h2` protocol.
const ALPN_H2_WIRE: &[u8] = b"\x02h2";

/// Accept the peer only when its leaf certificate carries the pinned key.
fn pin_endpoint_key(
    pinned: PKey<Public>,
) -> impl Fn(&mut SslRef) -> Result<(), SslVerifyError> + Send + Sync + 'static {
    move |ssl| {
        let matches = ssl
            .peer_certificate()
            .and_then(|certificate| certificate.public_key().ok())
            .is_some_and(|key| key.public_eq(&pinned));
        if matches {
            Ok(())
        } else {
            Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
        }
    }
}

/// A minimal self-signed certificate over the device key. Only the public key
/// matters to the edge; every other field is filler.
///
/// Shared with the HTTP/3 carrier: the same device identity has to be offered
/// on the QUIC handshake as on the TCP one.
pub(super) fn self_signed(device: &PKey<Private>) -> anyhow::Result<X509> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "honk-masque")?;
    let name = name.build();
    let serial_number = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_number)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(CERT_VALID_DAYS)?;
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(device)?;
    builder.sign(device, MessageDigest::sha256())?;
    Ok(builder.build())
}

/// Decode base64 key material, tolerating PEM armour and whitespace.
pub(super) fn decode_base64(value: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    let mut flattened = String::with_capacity(value.len());
    for line in value.lines() {
        let line = line.trim();
        if line.starts_with("-----") {
            continue;
        }
        flattened.push_str(line);
    }
    base64::engine::general_purpose::STANDARD
        .decode(flattened)
        .map_err(|error| anyhow::anyhow!("masque {field} is not valid base64: {error}"))
}
