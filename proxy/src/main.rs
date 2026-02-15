mod zone_editor;

/// host is the natural unique identifier for a hosting device
#[derive(Debug)]
struct HostId(String);

/// consumer is the natural unique identifier for a consumer (an email or phone number)
enum ConsumerId {
    TODO,
    Sms(phonenumber::PhoneNumber),
    Email(email_address::EmailAddress),
}

struct TunnelNonce(String);

trait TotpChallengeSender {
    type Error;

    fn challenge(&self, otp: i32) -> Result<Self::Error, ()>;
}

impl TotpChallengeSender for phonenumber::PhoneNumber {
    type Error = ();

    fn challenge(&self, _otp: i32) -> Result<Self::Error, ()> {
        // sns?
        Ok(())
    }
}

impl TotpChallengeSender for email_address::EmailAddress {
    type Error = ();

    fn challenge(&self, _otp: i32) -> Result<Self::Error, ()> {
        // ses?
        Ok(())
    }
}

trait PushNotifier {
    type Identifier;
    type Error;

    fn notify(id: &Self::Identifier, inverter_url: &url::Url) -> Result<Self::Error, ()>;
}

struct ApplePushNotificationServiceDeviceToken;

struct ApplePushNotificationService;

impl PushNotifier for ApplePushNotificationService {
    type Identifier = ApplePushNotificationServiceDeviceToken;
    type Error = ();

    fn notify(_id: &Self::Identifier, _inverter_url: &url::Url) -> Result<Self::Error, ()> {
        // apns
        Ok(())
    }
}

fn register_host(
    _host: &HostId,
    _push_notifier_identifier: ApplePushNotificationServiceDeviceToken,
) -> Result<(), std::io::Error> {
    // validation: host is unique, dns-friendly
    // persist to postgres
    Ok(())
}

fn handle_pseudo_push_notification(
    _host: &HostId,
    _websocket: tungstenite::protocol::WebSocket<
        rustls::Stream<rustls::ServerConnection, std::net::TcpStream>,
    >,
) -> Result<(), std::io::Error> {
    loop {}
}

fn register_consumer(
    _host: &HostId,
    _consumer: &ConsumerId,
    _secret: &otp::Secret,
) -> Result<(), std::io::Error> {
    // persist to postgres **encrypted**
    Ok(())
}

fn handle_proxy_auth(
    _host: &HostId,
    _consumer_stream: rustls::Stream<rustls::ServerConnection, std::net::TcpStream>,
) -> Result<(), std::io::Error> {
    // fetch totp secret for (HostId, ConsumerId) (or 404)
    // missing or invalid basic auth header:
    //   send one-time code on appropriate channel
    //   return 401
    // Set-Cookie: a jwt auth token
    // redirect to the equivalent "handle_proxy"
    Ok(())
}

fn handle_proxy(
    _host: &HostId,
    _client_hello: rustls::server::ClientHello,
    _consumer_stream: std::net::TcpStream,
) -> Result<(), std::io::Error> {
    // send push notification on best channel to host
    // park
    Ok(())
}

fn handle_tunnel(
    _host: &HostId,
    _tunnel_nonce: &TunnelNonce,
    _websocket: tungstenite::protocol::WebSocket<
        rustls::Stream<rustls::ServerConnection, std::net::TcpStream>,
    >,
) -> Result<(), std::io::Error> {
    // connect host_stream to consumer_stream
    Ok(())
}

fn handle_one_tcp_connection(
    domain: &String,
    mut tcp_stream: std::net::TcpStream,
) -> Result<(), std::io::Error> {
    // Read TLS packets until we've consumed a full client hello and are ready to accept a connection.
    let accepted = {
        let mut acceptor = rustls::server::Acceptor::default();

        loop {
            acceptor.read_tls(&mut tcp_stream)?;

            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    let _ = alert.write_all(&mut tcp_stream);
                    return Err(std::io::Error::other(e));
                }
            }
        }
    };

    let client_hello = accepted.client_hello();

    let Some(servername) = client_hello.server_name() else {
        return Err(std::io::Error::other("missing sni server name"));
    };

    match servername
        .ends_with(domain)
        .then(|| {
            servername[..(servername.len() - domain.len())]
                .split_terminator('.')
                .collect::<Vec<&str>>()
        })
        .as_deref()
    {
        Some([]) => {
            println!("mode: hostless");

            // TODO configure the correct cert
            let config = std::sync::Arc::new(
                rustls::server::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![],
                        rustls_pki_types::PrivatePkcs8KeyDer::from(vec![]).into(),
                    )
                    .map_err(std::io::Error::other)?,
            );

            let mut ssl_connection =
                accepted.into_connection(config).map_err(|(e, mut alert)| {
                    let _ = alert.write_all(&mut tcp_stream);
                    std::io::Error::other(e)
                })?;
            let ssl_stream = rustls::Stream::new(&mut ssl_connection, &mut tcp_stream);

            handle_hostless(domain, ssl_stream)
        }
        Some([verb, host_string]) if *verb == "2fa" => {
            let host = HostId(host_string.to_string());
            println!("mode: proxy_auth for {host:?}");

            // TODO configure the correct cert
            let config = std::sync::Arc::new(
                rustls::server::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![],
                        rustls_pki_types::PrivatePkcs8KeyDer::from(vec![]).into(),
                    )
                    .map_err(std::io::Error::other)?,
            );

            let mut ssl_connection =
                accepted.into_connection(config).map_err(|(e, mut alert)| {
                    let _ = alert.write_all(&mut tcp_stream);
                    std::io::Error::other(e)
                })?;
            let ssl_stream = rustls::Stream::new(&mut ssl_connection, &mut tcp_stream);

            handle_proxy_auth(&host, ssl_stream)
        }
        Some([host_string]) => {
            let host = HostId(host_string.to_string());
            println!("mode: proxy for {host:?}");
            handle_proxy(&host, client_hello, tcp_stream)
        }
        _ => Err(std::io::Error::other(format!(
            "unexpected sni server name: {servername}"
        ))),
    }
}

fn handle_hostless(
    domain: &String,
    mut ssl_stream: rustls::Stream<rustls::ServerConnection, std::net::TcpStream>,
) -> Result<(), std::io::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);

    let mut buffer = [0; 8192];
    use std::io::Read;
    let n = ssl_stream.read(&mut buffer)?;
    if n == 0 {
        // TODO eof???
        return Err(std::io::Error::other("eof"));
    }
    let result = request.parse(&buffer[..n]).map_err(std::io::Error::other)?;
    if result.is_partial() {
        // TODO request didn't fit in the buffer. probably need to handle this, not
        // error?
        return Err(std::io::Error::other(
            "request is still partial after one read()",
        ));
    }
    let partially_read_part = buffer[result.unwrap()..n].to_vec();

    let http_host_header = request
        .headers
        .iter()
        .find_map(|h| {
            if h.name == "Host" {
                Some(h.value)
            } else {
                None
            }
        })
        .ok_or_else(|| std::io::Error::other("missing host header"))?;

    if http_host_header != domain.as_bytes() {
        // TODO emit 404
        return Ok(());
    }

    if request.path == Some("/{{HOST}}") {
        let host = HostId("TODO".into());
        let push_notification_identifier = ApplePushNotificationServiceDeviceToken;

        return register_host(&host, push_notification_identifier);
    }
    if request.path == Some("/{{HOST}}/consumer/{{CONSUMER}}") {
        let host = HostId("TODO".into());
        let consumer = ConsumerId::TODO;
        let otp_secret = otp::Secret::from_bytes("TODO".as_bytes());
        return register_consumer(&host, &consumer, &otp_secret);
    }
    if request.path == Some("/{{HOST}}/pseudo-push-notification") {
        let host = HostId("TODO".into());

        // TODO check and send upgrade headers
        let websocket = tungstenite::protocol::WebSocket::from_partially_read(
            ssl_stream,
            partially_read_part,
            tungstenite::protocol::Role::Server,
            None,
        );
        return handle_pseudo_push_notification(&host, websocket);
    }
    if request.path == Some("/{{HOST}}/tunnel/{{NONCE}}") {
        let host = HostId("TODO".into());
        let tunnel_nonce = TunnelNonce("TODO".into());

        // TODO check and send upgrade headers
        let websocket = tungstenite::protocol::WebSocket::from_partially_read(
            ssl_stream,
            partially_read_part,
            tungstenite::protocol::Role::Server,
            None,
        );
        return handle_tunnel(&host, &tunnel_nonce, websocket);
    }
    // TODO emit 404
    Ok(())
}

fn main() -> std::io::Result<()> {
    let domain = std::env::var("DOMAIN").map_err(std::io::Error::other)?;

    let _zone_editor = crate::zone_editor::ZoneEditor::new(
        &domain,
        &std::fs::read_to_string("/secrets/cloudflare_dns_api")?,
    )?;

    let listener = std::net::TcpListener::bind("0.0.0.0:443")?;

    println!("starting main loop");
    std::thread::scope(|scope| {
        for maybe_tcp_stream in listener.incoming() {
            let Ok(tcp_stream) = maybe_tcp_stream else {
                println!("problem accepting: {maybe_tcp_stream:?}");
                break;
            };

            println!("accepted: {tcp_stream:?}");
            scope.spawn(|| {
                let _ = dbg!(handle_one_tcp_connection(&domain, tcp_stream));
                println!("done");
            });
        }
    });
    println!("exiting main loop");

    Ok(())
}
