# gjallar

![rust](https://img.shields.io/badge/rust-2024-orange?logo=rust)
![crates.io](https://img.shields.io/crates/v/gjallar)
![license](https://img.shields.io/badge/license-MIT-blue)

web push notifications from a rust server, encrypted, signed and classified.

gjallar takes the subscription a browser hands your page, a message and your VAPID key,
and gives back the exact `POST` a push service accepts: apple's, google's, mozilla's or
microsoft's. when the push service answers, it tells you what the answer means for the
subscription. the core has no http client, so it fits any server, async or not. the
`client` feature adds a blocking one on `ureq`.

named after gjallarhorn, the horn heimdall blows to tell every god at once that
something happened. this one mostly tells phones.

## why

sending a web push takes three rfcs and a w3c draft. the payload is encrypted for one
browser with a one-time key (rfc 8291), the request is signed with a token for one push
service (rfc 8292), and the headers say how long to keep it and what it replaces
(rfc 8030). get one byte of the encryption wrong and the push service still answers
`201`, then the browser drops the message without a word.

the push services also disagree with each other on the details. apple wants a contact
in every token and no more than one new token an hour. it answers an expired
subscription with `410`, where the rfc says `404`, and explains refusals in json under
`reason`. mozilla's json says it under `message`, next to an error number. gjallar folds all of that into a few types, and
checks its encryption byte for byte against the rfc's own test vector.

## how a push goes out

1. **you make a VAPID key once.** the private half is a secret. the public half goes to
   your page, which passes it to `pushManager.subscribe()` as `applicationServerKey`.
   the browser binds the subscription to it.
2. **the page subscribes** inside a click handler (safari asks for permission only
   during a user gesture) and posts `subscription.toJSON()` to your server.
3. **`Subscription` parses that json** and checks it: the endpoint is an absolute
   `https` url, `p256dh` is a point on P-256, and `auth` is 16 bytes. anything else is
   an `Error`, never a panic. other members, like a device name you stored beside it,
   are ignored.
4. **`WebPush::request` builds the request.** it signs an ES256 token whose `aud` is
   the endpoint's origin and whose `exp` is 12 hours ahead, and keeps it for that
   origin until an hour before it expires. then it makes a one-time P-256 key and a
   16-byte salt, derives the AES-128-GCM key from ECDH with `p256dh` and HKDF with
   `auth`, and seals the payload as one 4096-byte record. that caps a payload at 3993
   bytes. the request carries `TTL`, `Urgency` and `Topic` when you set them,
   `Content-Encoding: aes128gcm` and `Authorization: vapid t=…, k=…`.
5. **you send it**, with the `client` feature or with whatever http client you already
   have.
6. **`Outcome::classify` reads the answer:**

| answer | outcome | what to do |
| ------ | ------- | ---------- |
| 2xx | `Delivered` | nothing. the push service holds it until the browser comes online |
| 404, 410 | `Gone` | delete the subscription. the user unsubscribed or it expired |
| 408, 429, 5xx | `RetryLater { after }` | send again later, after `Retry-After` when there is one |
| anything else | `Refused { reason }` | fix something. `reason` is apple's `reason`, mozilla's `message` or the start of a plain-text body |

## declarative web push

`Message::declarative` writes the w3c's declarative format,
`{"web_push": 8030, "notification": {…}}`. safari 18.4 on iphone and ipad and safari
18.5 on the mac show it by themselves and open `navigate` on a tap, without running any
service worker code. so the notification still shows when the service worker is stale
or gone, and safari never catches the site sending a push it didn't show. other
browsers hand the same json to the service worker's `push` event:

```js
// service-worker.js, for the browsers that don't read web_push themselves
self.addEventListener("push", (event) => {
  const { notification } = event.data.json();
  event.waitUntil(
    self.registration.showNotification(notification.title, {
      body: notification.body,
      tag: notification.tag,
      data: { navigate: notification.navigate },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data.navigate));
});
```

`Message::new` takes any bytes instead, for a service worker that reads its own format.

## using it

```toml
# Cargo.toml. leave out the feature to bring your own http client
gjallar = { version = "0.1", features = ["client"] }
serde_json = "1"
```

```rust
use gjallar::{Client, Message, Notification, Outcome, Subscription, VapidKey, WebPush};

// once, at startup. keep one client: it reuses tokens and connections
let key: VapidKey = std::env::var("VAPID_KEY")?.parse()?;
let client = Client::new(WebPush::new(key, "mailto:ops@example.com")?);

// per message
let subscription: Subscription = serde_json::from_str(&stored_json)?;
let message = Message::declarative(
    Notification::new("Your order shipped", "https://shop.example.com/orders/1042")
        .body("It should arrive on Thursday."),
)?;
match client.send(&subscription, &message)? {
    Outcome::Gone { .. } => delete(&subscription),
    outcome => println!("{outcome:?}"),
}
```

`client.send_all(&subscriptions, &message)` sends to many at once and returns one result
per subscription, in the same order. without the client, `push.request(&subscription,
&message)` returns an `http::Request<Vec<u8>>`. the crate docs show it going out through
`reqwest`.

### the client

the `client` feature sends over `ureq` with rustls and webpki roots, so there's still
no openssl anywhere. `send_all` keeps up to 8 requests in flight, one thread each. every
request gets 10 seconds, the whole call gets 30, and a `429`, `408`, `5xx` or failed
connection is retried once. the retry waits for the `Retry-After` the service gave, or
a second without one. a retry that would end past the deadline isn't made, and a
subscription the deadline never reached comes back as `Error::Deadline`. all four
numbers have setters. redirects are never followed, since following one would send the
message somewhere the subscription never named.

## commands

```bash
# make a VAPID key: the private half to the file, the public half to the screen
cargo run --example keygen > vapid.key

# push one notification to the subscriptions in a json file (one object or an array)
GJALLAR_VAPID_KEY=$(cat vapid.key) cargo run --example send --features client -- \
    mailto:you@example.com subscriptions.json "Hello" https://example.com/
```

```text
public key (applicationServerKey): BNnENATvnSHpQicB6U73Ikr6YfOG3PvEvwc7QLZpCJozHu_qAVdIB7dK0r6htfzkDQ48QShBEb9zXGX8iQ0XEvo
https://web.push.apple.com: refused (400 Bad Request): BadWebPushToken
```

that second line is apple's answer to a subscription made up for this readme. a real
one says `delivered`.

the key file holds the base64url of the 32-byte private scalar, the same form the
`web-push` npm package prints, so keys from it load as they are. `VapidKey::from_pem`
reads an `openssl ecparam -genkey -name prime256v1` key too.

## sharp edges

- **gjallar stores nothing.** a `Gone` subscription stays in your database until you
  delete it, and every send to it costs a request.
- **a new VAPID key orphans every subscription.** browsers bind each subscription to the
  key it was made with. apple answers the old ones with `403 VapidPkHashMismatch`, and
  the pages have to subscribe again.
- **safari revokes permission over a push it didn't show.** a declarative message
  always shows. with `Message::new` or `Message::empty`, the service worker has to show a
  notification for every push.
- **apple refuses a `TTL` of zero** with `400 BadTtl`. the default is four weeks, the
  longest google keeps a message.
- **the client blocks.** from async code, call it on `spawn_blocking`, or use
  `WebPush::request` with your own async client.
- **an endpoint is a password.** anyone holding it, plus the keys, can push to that
  browser. `Subscription`'s `Debug` prints only the origin, so keep it that way in your
  logs.
- **plain `http` endpoints only work on loopback**, for a fake push service in tests.
  real ones are all `https`.

## file structure

```text
.
├── .github/            # checks on every pull request, releases to crates.io
├── flake.nix           # the package, the checks and a dev shell
├── nix/package.nix     # the crane build, with tests, clippy, rustdoc and rustfmt as checks
├── examples/
│   ├── keygen.rs       # make a VAPID key
│   └── send.rs         # push to subscriptions from a json file
├── src/
│   ├── lib.rs          # the crate docs and the public api
│   ├── subscription.rs # PushSubscription.toJSON(), parsed and checked
│   ├── vapid.rs        # the key, and the token cache keyed by origin
│   ├── ece.rs          # rfc 8291 aes128gcm, both ways
│   ├── message.rs      # the payload, TTL, Urgency and Topic
│   ├── declarative.rs  # the declarative web push json
│   ├── push.rs         # the signed, encrypted http::Request
│   ├── outcome.rs      # the push service's answer, classified
│   ├── client.rs       # the blocking ureq client, behind `client`
│   └── receiver.rs     # the browser's side, for tests
└── tests/
    ├── request.rs      # the core end to end, no network
    └── client.rs       # the client against a fake push service on loopback
```

## releases

every pull request runs `nix flake check` on x86_64-linux and aarch64-darwin: the tests
with and without `client`, clippy, rustdoc and rustfmt, all with warnings as errors.
its commits have to follow conventional commits. the version lives in `Cargo.toml`, and
a pull request has to raise it unless it's labeled `no-release`.

once a new version lands on `main`, ci checks it again, publishes it to crates.io, and
tags the release.

## hacking on it

```bash
nix develop                    # the toolchain
cargo test                     # the core
cargo test --features client   # plus the client, against a fake push service
nix flake check                # all of the above, clippy, rustdoc and rustfmt
```

the tests never talk to a real push service. `Receiver` plays the browser: it makes a
subscription for any endpoint and decrypts what arrives there. the fake push service in
`tests/client.rs` decrypts every message with its subscription's keys and verifies the
VAPID token's signature, then answers `201`, `410`, `429` and then `201`, or `403`.

---

heimdall waits for ragnarök to blow his horn. you only need something to happen.
