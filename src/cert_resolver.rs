use std::sync::Arc;

pub struct ResolvesServerCertUsingSni {
    pub(crate) fallback: String,
    pub(crate) key: Arc<dyn wtransport::tls::rustls::sign::SigningKey>,
}

impl ResolvesServerCertUsingSni {
    pub fn new(fallback: String) -> Self {
        let key = wtransport::tls::rustls::sign::any_supported_type(
            &wtransport::tls::rustls::PrivateKey(cert::HARDCODED_NOT_SO_SECRET_KEY_DER.to_vec()),
        )
        .unwrap();
        Self { fallback, key }
    }
}

impl wtransport::tls::rustls::server::ResolvesServerCert for ResolvesServerCertUsingSni {
    fn resolve(
        &self,
        client_hello: wtransport::tls::rustls::server::ClientHello,
    ) -> Option<Arc<wtransport::tls::rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name().unwrap_or(self.fallback.as_str());
        let cert = cert::self_signed(
            name.into(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        Some(Arc::new(wtransport::tls::rustls::sign::CertifiedKey::new(
            vec![wtransport::tls::rustls::Certificate(cert)],
            self.key.clone(),
        )))
    }
}
