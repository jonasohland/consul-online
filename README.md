# consul-online

## What
A small program that checks if a consul agent is online, meaning it is running and has established a connection to a cluster with an elected leader.

## Usage
```
consul-online 
Is consul online?

USAGE:
    consul-online [OPTIONS] [ADDRESS]

ARGS:
    <ADDRESS>    Address of the consul agent Examples: "127.0.0.1:8500" "http://127.0.0.1:8500"
                 "https://localhost:8501" "http://my-domain.fail". Can also be set with the
                 CONSUL_HTTP_ADDR environment variable [default: localhost:8500]

OPTIONS:
        --ca-cert <CA_CERT>
            Consul ca certificate, can also be set via the CONSUL_CACERT environment variable

        --client-cert <CLIENT_CERT>
            Consul client certificate, can also be set via the CONSUL_CLIENT_CERT environment
            variable

        --client-key <CLIENT_KEY>
            Consul client key, can also be set via the CONSUL_CLIENT_KEY environment variable

    -h, --help
            Print help information

        --http-token <HTTP_TOKEN>
            Consul access token, must have operator:read permissions. Can also be set with the
            CONSUL_HTTP_TOKEN environment variable

        --http-token-file <HTTP_TOKEN_FILE>
            File from which to read a consul access token, must have operator:read permissions. Can
            also be set with the CONSUL_HTTP_TOKEN_FILE environment variable

    -i, --interval <INTERVAL>
            Polling interval in seconds. Can also be set via the CONSUL_ONLINE_INTERVAL environment
            variable

    -l, --log-level <LOG_LEVEL>
            Application log level [default: WARN]

    -r, --reconnect
            Do not treat connection failures as exit conditions. Can also be set via the
            CONSUL_ONLINE_RECONNECT environment variable

        --skip-verify
            Skip server certificate validation. This is is dangerous and should be avoided! It might
            be better to simply provide the consul ca certificate with the --ca-cert option. This
            option can also set by specifying CONSUL_HTTP_SSL_VERIFY=false in the environment

    -t, --timeout <TIMEOUT>
            Global timeout in seconds. Will stop trying to wait for consul to come online for at
            least this amount of time. Might wait longer, especially if the --reconnect option is
            not specified Can also be set via the CONSUL_ONLINE_TIMEOUT environment variable

        --tls
            Force TLS connection. Can also enabled by setting CONSUL_HTTP_SSL=true in the
            environment


```

## Exit codes

|Code|Meaning|
|---|---|
|0|Consul is online! |
|1|Initialization failed do to an error in the provided command-line arguments or environment vars. (file could not be read or parsed, argument missing)
|2|Timed out while waiting for consul to come online. Only occurs when the `--timeout` argument is provided|
|3|Connection to consul was not successful. Does not occur when the `--reconnect` is specified|


## Known limitations
`consul-online` uses rustls for TLS connections and is therefore not able to verify the validity of server certificates when connecting to an ip-address. If you for example wish to connect to consul using bound to localhost, you should either use the localhost dns name (preferred) or skip certificate verification using the `--skip-verify` option.