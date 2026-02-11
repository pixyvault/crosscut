/// host is the natural unique identifier for a hosting device
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

///

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

///

fn register_host(
    _host: &HostId,
    _push_notifier_identifier: ApplePushNotificationServiceDeviceToken,
) -> Result<(), std::io::Error> {
    // validation: server is unique, dns-friendly
    // persist to postgres
    Ok(())
}

fn handle_pseudo_push_notification(
    _host: &HostId,
    _websocket: tungstenite::protocol::WebSocket<openssl::ssl::SslStream<std::net::TcpStream>>,
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
    _consumer: &ConsumerId,
    _consumer_stream: openssl::ssl::SslStream<std::net::TcpStream>,
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
    _consumer_stream: openssl::ssl::MidHandshakeSslStream<std::net::TcpStream>,
) -> Result<(), std::io::Error> {
    // send push notification on best channel to host
    // park
    Ok(())
}

fn handle_tunnel(
    _host: &HostId,
    _tunnel_nonce: &TunnelNonce,
    _websocket: tungstenite::protocol::WebSocket<openssl::ssl::SslStream<std::net::TcpStream>>,
) -> Result<(), std::io::Error> {
    // connect host_stream to consumer_stream
    Ok(())
}

fn handle_one_tcp_connection(
    ssl_acceptor: openssl::ssl::SslAcceptor,
    tcp_stream: std::net::TcpStream,
) -> Result<(), std::io::Error> {
    match ssl_acceptor.accept(tcp_stream) {
        Ok(mut ssl_stream) => {
            use std::io::Read;

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut request = httparse::Request::new(&mut headers);

            let mut buffer = [0; 8192];
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

            let host_header = request
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

            if host_header == "2fa.{{HOST}}.{{DOMAIN}}".as_bytes() {
                let host = HostId("TODO".into());
                let consumer = ConsumerId::TODO;
                return handle_proxy_auth(&host, &consumer, ssl_stream);
            }
            if host_header == "{{DOMAIN}}".as_bytes() {
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
                return Ok(());
            }
            // TODO emit 404
            Ok(())
        }
        Err(openssl::ssl::HandshakeError::Failure(mid_handshake_stream))
            if THIS_IS_A_PROXY_REQUEST.get() =>
        {
            let host = HostId("TODO".into());

            handle_proxy(&host, mid_handshake_stream)
        }
        _ => {
            // TODO error accepting SSL
            Ok(())
        }
    }
}

thread_local! {
    static THIS_IS_A_PROXY_REQUEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

////////

fn main() -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:443")?;

    let ssl_acceptor = {
        let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate_v5(
            openssl::ssl::SslMethod::tls_server(),
        )?;
        builder.set_client_hello_callback(
            |ssl_ref: &mut openssl::ssl::SslRef,
             _ssl_alert: &mut openssl::ssl::SslAlert|
             -> Result<openssl::ssl::ClientHelloResponse, openssl::error::ErrorStack> {
                let sni = ssl_ref
                    .servername(openssl::ssl::NameType::HOST_NAME)
                    .ok_or_else(openssl::error::ErrorStack::get)?;
                if sni == "{{HOST}}.{{DOMAIN}}" {
                    THIS_IS_A_PROXY_REQUEST.set(true);
                    // TODO there might be more to this...?
                    return Ok(openssl::ssl::ClientHelloResponse::RETRY);
                }
                if sni == "2fa.{{HOST}}.{{DOMAIN}}" {
                    // TODO configure the correct cert
                    return Ok(openssl::ssl::ClientHelloResponse::SUCCESS);
                }
                if sni == "{{DOMAIN}}" {
                    // TODO configure the correct cert
                    return Ok(openssl::ssl::ClientHelloResponse::SUCCESS);
                }
                Err(openssl::error::ErrorStack::get())
            },
        );
        builder.build()
    };

    std::thread::scope(|scope| {
        for maybe_tcp_stream in listener.incoming() {
            let Ok(tcp_stream) = maybe_tcp_stream else {
                // TODO problem accepting
                break;
            };

            scope.spawn(|| {
                let _ = handle_one_tcp_connection(ssl_acceptor.clone(), tcp_stream);
            });
        }
    });

    Ok(())
}
