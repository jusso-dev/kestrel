//! rustls configuration and the acceptor that copies the client certificate
//! onto each request. axum-server does not expose the peer certificate itself.

use crate::ServerError;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Once};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower_service::Service;

static CRYPTO: Once = Once::new();

#[derive(Clone, Debug)]
pub struct PeerCert {
    pub der: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PeerAcceptor<A = axum_server::accept::DefaultAcceptor> {
    inner: RustlsAcceptor<A>,
}

impl PeerAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S, A> Accept<I, S> for PeerAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
    A::Future: Send + 'static,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<A::Stream>;
    type Service = PeerCertService<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (tls_stream, inner_service) = inner.accept(stream, service).await?;
            let (_, connection) = tls_stream.get_ref();
            let der = connection
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| cert.as_ref().to_vec());
            let peer = der.map(|der| PeerCert { der });
            Ok((tls_stream, PeerCertService::new(inner_service, peer)))
        })
    }
}

#[derive(Clone, Debug)]
pub struct PeerCertService<S> {
    inner: S,
    peer: Option<PeerCert>,
}

impl<S> PeerCertService<S> {
    fn new(inner: S, peer: Option<PeerCert>) -> Self {
        Self { inner, peer }
    }
}

impl<S, B> Service<http::Request<B>> for PeerCertService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if let Some(peer) = self.peer.clone() {
            request.extensions_mut().insert(peer);
        }
        self.inner.call(request)
    }
}

pub fn rustls_config(
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
    require_client: bool,
) -> Result<RustlsConfig, ServerError> {
    install_ring();
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_reader = ca_pem.as_bytes();
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert = cert.map_err(|err| ServerError::new(err.to_string()))?;
        roots
            .add(cert)
            .map_err(|err| ServerError::new(err.to_string()))?;
    }
    let mut verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
    if !require_client {
        verifier = verifier.allow_unauthenticated();
    }
    let verifier = verifier
        .build()
        .map_err(|err| ServerError::new(err.to_string()))?;

    let mut cert_reader = cert_pem.as_bytes();
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ServerError::new(err.to_string()))?;
    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|err| ServerError::new(err.to_string()))?
        .ok_or_else(|| ServerError::new("server private key is missing"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| ServerError::new(err.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| ServerError::new(err.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn install_ring() {
    CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
