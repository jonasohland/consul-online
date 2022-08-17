use rustls::client::HandshakeSignatureValid;
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::client::WantsClientCert;
use rustls::client::WantsTransparencyPolicyOrClientCert;
use rustls::Certificate;
use rustls::ClientConfig;
use rustls::ConfigBuilder;
use rustls::OwnedTrustAnchor;
use rustls::PrivateKey;
use rustls::RootCertStore;
use rustls::WantsVerifier;
use std::fmt::Display;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use ureq::Agent;
use ureq::Request;

#[derive(Debug)]
pub enum Error {
    General(String),
    UnixSocketUnsupported,
    InvalidBool(String),
    ReadCaCert(std::io::Error),
    ParseCaCert(pem::PemError),
    AddCaCert(webpki::Error),
    AddClientCert(rustls::Error),
    MissingClientKey,
    MissingClientCert,
    ReadClientKey(std::io::Error),
    ParseClientKey(pem::PemError),
    ReadClientCert(std::io::Error),
    ParseClientCert(pem::PemError),
    ReadTokenFile(std::io::Error),
    Request(ureq::Error),
    Timeout(Duration),
}

impl Display for Error {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::General(err) => write!(f, "error: {}", err),
            Error::UnixSocketUnsupported => write!(f, "unix sockets are not supported at the moment"),
            Error::InvalidBool(v) => write!(f, "environment variable could not be parsed as boolean: {}", v),
            Error::ReadCaCert(e) => write!(f, "could not read the ca certificate: {}", e),
            Error::ParseCaCert(e) => write!(f, "could not parse the provided ca certificate: {}", e),
            Error::AddCaCert(e) => write!(f, "invalid ca certificate: {}", e),
            Error::AddClientCert(e) => write!(f, "invalid client certificate: {}", e),
            Error::MissingClientKey => write!(f, "missing client key option"),
            Error::MissingClientCert => write!(f, "missing client cert option"),
            Error::ReadClientKey(e) => write!(f, "failed to read client key: {}", e),
            Error::ParseClientKey(e) => write!(f, "failed to parse client key: {}", e),
            Error::ReadClientCert(e) => write!(f, "failed to read client cert: {}", e),
            Error::ParseClientCert(e) => write!(f, "failed to parse client cert: {}", e),
            Error::ReadTokenFile(e) => write!(f, "failed to read token file: {}", e),
            Error::Request(e) => write!(f, "request failed: {}", e),
            Error::Timeout(d) => write!(f, "timed out after {} seconds", d.as_secs()),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Config {
    pub http_addr: String,
    pub http_ssl: bool,
    pub timeout: Option<u64>,
    pub interval: Option<u64>,
    pub reconnect: bool,
    pub skip_verify: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub http_token: Option<String>,
    pub http_token_file: Option<String>,
}

struct SkippingVerifier();

impl ServerCertVerifier for SkippingVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,
        _: &[Certificate],
        _: &rustls::ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        log::info!("skipping verification (unsafe!)");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &Certificate,
        _: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        log::info!("assume is signature ok (unsafe!)");
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &Certificate,
        _: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        log::info!("assume is signature ok (unsafe!)");
        Ok(HandshakeSignatureValid::assertion())
    }
}

fn load_client_cert(path: &str) -> Result<Certificate> {
    Ok(Certificate(
        pem::parse(&fs::read_to_string(PathBuf::from(path)).map_err(Error::ReadClientCert)?)
            .map_err(Error::ParseClientCert)?
            .contents,
    ))
}

fn load_client_key(path: &str) -> Result<PrivateKey> {
    Ok(PrivateKey(
        pem::parse(&fs::read_to_string(PathBuf::from(path)).map_err(Error::ReadClientKey)?)
            .map_err(Error::ParseClientKey)?
            .contents,
    ))
}

fn add_client_cert(
    config: &Config,
    builder: ConfigBuilder<ClientConfig, WantsClientCert>,
) -> Result<ClientConfig> {
    match &config.client_cert {
        Some(cert) => match &config.client_key {
            Some(key) => Ok(builder
                .with_single_cert(
                    vec![load_client_cert(cert.as_str())?],
                    load_client_key(key.as_str())?,
                )
                .map_err(Error::AddClientCert)?),
            None => Err(Error::MissingClientKey),
        },
        None => match config.client_key {
            Some(_) => Err(Error::MissingClientCert),
            None => Ok(builder.with_no_client_auth()),
        },
    }
}

fn add_client_cert2(
    config: &Config,
    builder: ConfigBuilder<ClientConfig, WantsTransparencyPolicyOrClientCert>,
) -> Result<ClientConfig> {
    match &config.client_cert {
        Some(cert) => match &config.client_key {
            Some(key) => Ok(builder
                .with_single_cert(
                    vec![load_client_cert(cert.as_str())?],
                    load_client_key(key.as_str())?,
                )
                .map_err(Error::AddClientCert)?),
            None => Err(Error::MissingClientKey),
        },
        None => match config.client_key {
            Some(_) => Err(Error::MissingClientCert),
            None => Ok(builder.with_no_client_auth()),
        },
    }
}

fn add_verifier(
    config: &Config,
    builder: ConfigBuilder<ClientConfig, WantsVerifier>,
) -> Result<ClientConfig> {
    if config.skip_verify {
        log::info!("add custom verifier");
        add_client_cert(
            config,
            builder.with_custom_certificate_verifier(Arc::new(SkippingVerifier())),
        )
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |anchor| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    anchor.subject,
                    anchor.spki,
                    anchor.name_constraints,
                )
            },
        ));
        if let Some(ca) = &config.ca_cert {
            log::info!("read ca cert from: {}", ca);
            root_store
                .add(
                    &fs::read_to_string(PathBuf::from(ca.as_str()))
                        .map_err(Error::ReadCaCert)
                        .and_then(|s| pem::parse(&s).map_err(Error::ParseCaCert))
                        .map(|pem| Certificate(pem.contents))?,
                )
                .map_err(Error::AddCaCert)?;
        }
        add_client_cert2(config, builder.with_root_certificates(root_store))
    }
}

fn build_tls_config(config: &Config) -> Result<rustls::ClientConfig> {
    add_verifier(
        config,
        rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .unwrap(),
    )
}

fn url_base(config: &Config) -> Result<(String, bool)> {
    if config.http_addr.starts_with("http://") {
        if config.http_ssl {
            log::warn!("address ({}) indicates http transport, but CONSUL_HTTP_SSL=true, using ssl transport", config.http_addr);
            Ok((
                format!("https://{}", config.http_addr.split_at(6).1.to_owned()),
                true,
            ))
        } else {
            Ok((config.http_addr.clone(), false))
        }
    } else if config.http_addr.starts_with("https://") {
        Ok((config.http_addr.clone(), true))
    } else if config.http_addr.starts_with("unix:/") {
        Err(Error::UnixSocketUnsupported)
    } else if config.http_ssl {
        Ok((format!("https://{}", config.http_addr), true))
    } else {
        Ok((format!("http://{}", config.http_addr), false))
    }
}

fn agent_and_url(config: &Config) -> Result<(ureq::Agent, String)> {
    url_base(config).and_then(|(url, ssl)| {
        if ssl {
            Ok(ureq::builder()
                .https_only(true)
                .tls_config(Arc::new(build_tls_config(config)?))
                .build())
        } else {
            Ok(ureq::builder().build())
        }
        .map(|agent| (agent, format!("{}/v1/operator/raft/configuration", url)))
    })
}

struct HeaderAdder(Option<(&'static str, String)>);

impl HeaderAdder {
    fn try_new(config: &Config) -> Result<Self> {
        match &config.http_token {
            Some(token) => Ok(Self(Some(("X-Consul-Token", token.to_owned())))),
            None => match &config.http_token_file {
                Some(f) => Ok(Self(Some((
                    "X-Consul-Token",
                    fs::read_to_string(PathBuf::from(f))
                        .map_err(Error::ReadTokenFile)?
                        .trim()
                        .to_owned(),
                )))),
                None => Ok(Self(None)),
            },
        }
    }

    fn with_header(&self, r: Request) -> Request {
        match &self.0 {
            Some((h, v)) => r.set(h, v.as_str()),
            None => r,
        }
    }
}

fn do_request(
    agent: &Agent,
    url: &str,
    timeout: Duration,
    header_adder: &HeaderAdder,
) -> Result<u16> {
    header_adder
        .with_header(agent.get(url))
        .timeout(timeout)
        .call()
        .map_err(Error::Request)
        .map(|r| r.status())
}

pub fn wait(config: Config) -> Result<()> {
    let (agent, url) = agent_and_url(&config)?;
    let header_adder = HeaderAdder::try_new(&config)?;
    let start_time = std::time::SystemTime::now();
    let interval = Duration::from_secs(config.interval.unwrap_or(10));
    loop {
        log::debug!("request...");
        let timeout = std::cmp::max(
            config
                .timeout
                .map(|global_timeout| {
                    std::cmp::min(
                        Duration::from_secs(global_timeout)
                            .checked_sub(SystemTime::now().duration_since(start_time).unwrap())
                            .unwrap_or(Duration::from_secs(0)),
                        interval,
                    )
                })
                .unwrap_or(interval),
            if config.reconnect {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(10)
            },
        );
        let req_start = SystemTime::now();
        log::info!("will timeout after {} millis", timeout.as_millis());
        match do_request(&agent, url.as_str(), timeout, &header_adder) {
            Ok(code) => match code {
                200 => break Ok(()),
                _ => {
                    log::info!("code: {}", code);
                }
            },
            Err(err) => match err {
                Error::Request(ureq::Error::Status(s, r)) => {
                    if s == 500 {
                        log::info!("not ready yet: {}/{}", r.status_text(), s);
                    } else if !config.reconnect {
                        break Err(Error::Request(ureq::Error::Status(s, r)));
                    } else {
                        log::info!("request failed: {}", s);
                    }
                }
                rest => {
                    if !config.reconnect {
                        break Err(rest);
                    } else {
                        log::info!("request failed: {}", rest);
                    }
                }
            },
        }
        if let Some(timeout) = config.timeout {
            let now = SystemTime::now();
            if start_time + std::time::Duration::from_secs(timeout) < now {
                break Err(Error::Timeout(now.duration_since(start_time).unwrap()));
            }
        }
        if let Some(d) = timeout.checked_sub(SystemTime::now().duration_since(req_start).unwrap()) {
            log::debug!("sleep {} millis", d.as_millis());
            std::thread::sleep(d)
        }
    }
}
