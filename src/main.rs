use std::{fmt::Display, str::FromStr};

use clap::Parser;
use consul_online::{wait, Config, Error};
use log::LevelFilter;

type Result<T> = std::result::Result<T, consul_online::Error>;

/// Is consul online?
#[derive(clap::Parser)]
struct CommandLine {
    /// Address of the consul agent Examples: "127.0.0.1:8500" "http://127.0.0.1:8500" "https://localhost:8501" "http://my-domain.fail".
    /// Can also be set with the CONSUL_HTTP_ADDR environment variable [default: localhost:8500]
    address: Option<String>,

    /// Application log level
    #[clap(long, short, rename_all = "lower", default_value_t = LevelFilter::Warn)]
    log_level: LevelFilter,

    /// Force TLS connection. Can also enabled by setting CONSUL_HTTP_SSL=true in the environment
    #[clap(long)]
    tls: bool,

    /// Global timeout in seconds. Will stop trying to wait for consul to come online for at least this amount of time. Might wait longer, especially if the --reconnect option is not specified
    /// Can also be set via the CONSUL_ONLINE_TIMEOUT environment variable     
    #[clap(short, long)]
    timeout: Option<u64>,

    /// Polling interval in seconds. Can also be set via the CONSUL_ONLINE_INTERVAL environment variable
    #[clap(short, long)]
    interval: Option<u64>,

    /// Do not treat connection failures as exit conditions. Can also be set via the CONSUL_ONLINE_RECONNECT environment variable
    #[clap(short, long)]
    reconnect: bool,

    /// Skip server certificate validation. This is is dangerous and should be avoided! It might be better to simply provide
    /// the consul ca certificate with the --ca-cert option. This option can also set by specifying CONSUL_HTTP_SSL_VERIFY=false
    /// in the environment
    #[clap(long)]
    skip_verify: bool,

    /// Consul ca certificate, can also be set via the CONSUL_CACERT environment variable
    #[clap(long)]
    ca_cert: Option<String>,

    /// Consul client certificate, can also be set via the CONSUL_CLIENT_CERT environment variable
    #[clap(long)]
    client_cert: Option<String>,

    /// Consul client key, can also be set via the CONSUL_CLIENT_KEY environment variable
    #[clap(long)]
    client_key: Option<String>,

    /// Consul access token, must have operator:read permissions.
    /// Can also be set with the CONSUL_HTTP_TOKEN environment variable
    #[clap(long)]
    http_token: Option<String>,

    /// File from which to read a consul access token, must have operator:read permissions.
    /// Can also be set with the CONSUL_HTTP_TOKEN_FILE environment variable
    #[clap(long)]
    http_token_file: Option<String>,
}

fn bool_env_var(name: &'static str, default: bool) -> Result<bool> {
    std::env::var(name)
        .ok()
        .map(|v| match v.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(Error::InvalidBool(v)),
        })
        .unwrap_or(Ok(default))
}

fn from_env<T>(name: &'static str) -> Result<Option<T>>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    std::env::var(name)
        .ok()
        .map(|v| {
            FromStr::from_str(v.as_str()).map_err(|e| {
                Error::General(format!(
                    "failed to convert env var {} to destination type: {}",
                    name, e
                ))
            })
        })
        .transpose()
}

impl TryFrom<CommandLine> for Config {
    type Error = Error;
    fn try_from(c: CommandLine) -> Result<Config> {
        Ok(Config {
            http_addr: c
                .address
                .or_else(|| std::env::var("CONSUL_HTTP_ADDR").ok())
                .unwrap_or_else(|| "localhost:8500".to_owned()),
            http_ssl: c.tls || bool_env_var("CONSUL_HTTP_SSL", false)?,
            timeout: c.timeout.or(from_env("CONSUL_ONLINE_TIMEOUT")?),
            interval: c.interval.or(from_env("CONSUL_ONLINE_INTERVAL")?),
            reconnect: c.reconnect || bool_env_var("CONSUL_ONLINE_RECONNECT", false)?,
            skip_verify: c.skip_verify || !bool_env_var("CONSUL_HTTP_SSL_VERIFY", true)?,
            ca_cert: c.ca_cert.or_else(|| std::env::var("CONSUL_CACERT").ok()),
            client_cert: c
                .client_cert
                .or_else(|| std::env::var("CONSUL_CLIENT_CERT").ok()),
            client_key: c
                .client_key
                .or_else(|| std::env::var("CONSUL_CLIENT_KEY").ok()),
            http_token: c
                .http_token
                .or_else(|| std::env::var("CONSUL_HTTP_TOKEN").ok()),
            http_token_file: c
                .http_token_file
                .or_else(|| std::env::var("CONSUL_HTTP_TOKEN_FILE").ok()),
        })
    }
}

fn main() {
    let command_line = CommandLine::parse();
    env_logger::builder()
        .parse_env("CONSUL_ONLINE_LOG")
        .filter_level(command_line.log_level)
        .init();

    std::process::exit(match Config::try_from(command_line).and_then(wait) {
        Err(Error::Request(e)) => {
            log::error!("failed: {}", e);
            3
        }
        Err(Error::Timeout(t)) => {
            log::error!("timed out after {} seconds", t.as_secs());
            2
        }
        Err(rest) => {
            log::error!("initialization failed: {}", rest);
            1
        }
        Ok(_) => {
            log::info!("consul is online!");
            0
        }
    });
}
