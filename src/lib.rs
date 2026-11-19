//! Web Push for servers: encrypts and signs push messages for browsers, and reads
//! what the push service answers.
//!
//! It covers the server's half of the standards a browser's `PushManager` speaks:
//!
//! - **RFC 8291** message encryption (`aes128gcm`, with RFC 8188's header), pinned to
//!   the RFC's own test vector.
//! - **RFC 8292** VAPID: ES256 tokens for the push service's origin, reused per
//!   origin until an hour before they expire.
//! - **RFC 8030** delivery options: `TTL`, `Urgency` and `Topic`.
//! - **Declarative Web Push** payloads, which Safari shows with no service worker code.
//!
//! The core builds an [`http::Request`] and classifies an answer into an [`Outcome`],
//! so it works with any HTTP client, async or not. The `client` feature adds a
//! blocking [`Client`] on `ureq` that sends to many subscriptions at once within a time
//! budget. The cryptography is pure Rust (RustCrypto), with no OpenSSL.
//!
//! # Sending a notification
//!
//! **Once:** make a VAPID key and keep its private half with your other secrets.
//!
//! ```
//! let key = gjallar::VapidKey::generate()?;
//! let secret = key.to_base64url(); // to your secret store
//! let public = key.public_key(); // to the page, as applicationServerKey
//! # Ok::<(), gjallar::Error>(())
//! ```
//!
//! **In the page:** subscribe with the public key, from a click handler (Safari only
//! asks for permission during a user gesture), and send the subscription to your
//! server:
//!
//! ```js
//! const registration = await navigator.serviceWorker.ready;
//! const subscription = await registration.pushManager.subscribe({
//!   userVisibleOnly: true,
//!   applicationServerKey: "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
//! });
//! await fetch("/push/subscriptions", { method: "POST", body: JSON.stringify(subscription) });
//! ```
//!
//! **On the server:** parse what the page sent, and push to it.
//!
#![cfg_attr(feature = "client", doc = "```no_run")]
#![cfg_attr(not(feature = "client"), doc = "```ignore")]
//! use gjallar::{Client, Message, Notification, Outcome, Subscription, VapidKey, WebPush};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let secret = gjallar::VapidKey::generate()?.to_base64url();
//! # let body = r#"{"endpoint":"https://fcm.googleapis.com/fcm/send/x","keys":{"p256dh":"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4","auth":"BTBZMqHH6r4Tts7J_aSIgg"}}"#;
//! let key: VapidKey = secret.parse()?;
//! let subscription: Subscription = serde_json::from_str(body)?;
//!
//! // keep one client for the life of the process: it reuses VAPID tokens and connections
//! let client = Client::new(WebPush::new(key, "mailto:ops@example.com")?);
//! let message = Message::declarative(
//!     Notification::new("Your order shipped", "https://shop.example.com/orders/1042")
//!         .body("It should arrive on Thursday."),
//! )?;
//!
//! match client.send(&subscription, &message)? {
//!     Outcome::Delivered => {}
//!     Outcome::Gone { .. } => { /* delete the subscription */ }
//!     Outcome::Refused { status, reason } => eprintln!("refused: {status} {reason:?}"),
//!     Outcome::RetryLater { after, .. } => eprintln!("busy, retry after {after:?}"),
//!     _ => {}
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`Client::send_all`] sends one message to many subscriptions in parallel and returns
//! one result per subscription, in order, within one overall deadline.
//!
//! # With another HTTP client
//!
//! [`WebPush::request`] returns a complete `http::Request<Vec<u8>>`: method, URL,
//! headers and encrypted body. Send it with any client and hand the answer to
//! [`Outcome::classify`]. With `reqwest`, for example:
//!
//! ```ignore
//! async fn send(
//!     http: &reqwest::Client,
//!     push: &gjallar::WebPush,
//!     subscription: &gjallar::Subscription,
//!     message: &gjallar::Message,
//! ) -> Result<gjallar::Outcome, Box<dyn std::error::Error>> {
//!     let request = reqwest::Request::try_from(push.request(subscription, message)?)?;
//!     let response = http.execute(request).await?;
//!     let (status, headers) = (response.status(), response.headers().clone());
//!     let body = response.bytes().await?;
//!     Ok(gjallar::Outcome::classify(status, &headers, &body))
//! }
//! ```
//!
//! Building a request signs and encrypts on the calling thread, which takes well under
//! a millisecond.
//!
//! # Limits
//!
//! A payload holds at most [`MAX_PAYLOAD`] (3993) bytes, what one 4096-byte encrypted
//! record carries. A `Topic` is at most 32 base64url characters; [`Topic::digest`]
//! turns any text into one. Push services keep a message for at most about four weeks
//! whatever its `TTL`.
//!
//! # Testing
//!
//! [`Receiver`] plays the browser: it makes a subscription for any endpoint, including
//! `http://127.0.0.1` for a fake push service, and decrypts what was sent to it.
//!
#![cfg_attr(feature = "client", doc = "[`Client`]: crate::Client")]
#![cfg_attr(
    feature = "client",
    doc = "[`Client::send_all`]: crate::Client::send_all"
)]
#![cfg_attr(
    not(feature = "client"),
    doc = "[`Client`]: https://docs.rs/gjallar/latest/gjallar/struct.Client.html"
)]
#![cfg_attr(
    not(feature = "client"),
    doc = "[`Client::send_all`]: https://docs.rs/gjallar/latest/gjallar/struct.Client.html#method.send_all"
)]
#![warn(missing_docs)]

mod base64url;
#[cfg(feature = "client")]
mod client;
mod declarative;
mod ece;
mod error;
mod message;
mod outcome;
mod push;
mod receiver;
mod subscription;
mod vapid;

#[cfg(feature = "client")]
pub use client::Client;
pub use declarative::{Action, Declarative, Dir, Notification};
pub use ece::MAX_PAYLOAD;
pub use error::Error;
pub use http;
pub use message::{Message, Topic, Urgency};
pub use outcome::Outcome;
pub use push::WebPush;
pub use receiver::Receiver;
pub use subscription::Subscription;
pub use vapid::VapidKey;
