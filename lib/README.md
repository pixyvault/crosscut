lib
===

The basic shape of this library should conform to single-threaded C, suitable for *either* multiplexing *or* threading.

The implementation is therefore *extremely* C-inflected Rust. In particular: no `async`, no tokio,
no threads.

Every IO action presents an interface something like:

 * \*\_getfd() -> int
   returns something that we can ask the kernel to `poll` for readiness
 * \*\_getpollevent() -> 
   we *probably* need a way to differentiate "poll for reading" from "poll for writing"?
 * \*\_advance() ->
   performs blocking IO, but guaranteed to be non-blocking exactly once after the kernel tells us the thing returned from getfd is "ready" for the kind of io returned by getpollevent.

To multiplex, then:
 * loop { poll(getfd, getpollevent); advance() }

And to multithread:
 * spawn { loop { advance() } }

... and then use callbacks at various state points, I think?

So then what are the actions?

 * init()
   - generate and locally save an ssl cert
   - send oob to the proxy:
     - the ACME DNS challenge for the new cert
     - our push-notification identifier (e.g. APNS device token)
   - sign the new ssl cert

 * share(file, recipient)
   - if this is the first time we're sharing with this recipient:
      - generate a TOTP secret for this recipient
      - save it locally
   - send the TOTP secret oob to the proxy
   - generate and return a URL

 * serve()
   - to be called when app is actively running
   - create a long-lived backchannel to the proxy for pseudo-push-notifications
     - reconnect on error
   - manage zero or more serve\_one machines transparently

 * serve\_one()
   - to be called on receipt of a push notification
   - create a transient connection to the given proxy "inverter" endpoint
   - authenticate using TOTP secret
   - request/response loop
