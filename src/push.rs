use std::time::{Duration, SystemTime};

use http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Method, Request};

use crate::vapid::Signer;
use crate::{Error, Message, Subscription, VapidKey, ece};

/// Turns a subscription and a message into a signed, encrypted HTTP request, ready for
/// any HTTP client to send.
///
/// It holds the VAPID key, the subject, and one VAPID token per push service, which it
/// reuses until an hour before the token expires. A long-lived sender should keep one
/// `WebPush` (it is `Send + Sync`) rather than build one per message: Apple asks for no
/// more than one new token an hour.
///
/// ```
/// use gjallar::{Message, Subscription, VapidKey, WebPush};
///
/// let push = WebPush::new(VapidKey::generate()?, "mailto:ops@example.com")?;
/// # let subscription = gjallar::Receiver::generate()?.subscription("https://push.example.com/abc")?;
/// let request = push.request(&subscription, &Message::new("hello")?)?;
/// assert_eq!(request.method(), "POST");
/// assert_eq!(request.headers()["content-encoding"], "aes128gcm");
/// // hand `request` to the HTTP client of your choice, then classify its answer
/// # Ok::<(), gjallar::Error>(())
/// ```
pub struct WebPush {
    signer: Signer,
}

impl WebPush {
    /// A sender signing with `key`, naming `subject` as its contact in every VAPID
    /// token: a `mailto:` address or an `https:` URL. Push services may use it to reach
    /// you about your traffic, and Apple rejects a token without one.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSubject`] if `subject` is neither a `mailto:` address nor an
    /// `https:` URL, or contains whitespace.
    pub fn new(key: VapidKey, subject: &str) -> Result<Self, Error> {
        Ok(Self {
            signer: Signer::new(key, subject)?,
        })
    }

    /// How far ahead each VAPID token's `exp` lies. 12 hours unless set; RFC 8292
    /// allows at most 24, and the margin covers a clock that runs ahead of the push
    /// service's. A token is replaced an hour before it expires, or halfway through a
    /// validity shorter than two hours.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidValidity`] for zero or more than 24 hours.
    pub fn token_validity(mut self, validity: Duration) -> Result<Self, Error> {
        self.signer.set_validity(validity)?;
        Ok(self)
    }

    /// The VAPID key this sender signs with.
    pub fn key(&self) -> &VapidKey {
        self.signer.key()
    }

    /// The `POST` request that delivers `message` to `subscription`: the endpoint as its
    /// URL, the RFC 8030 headers (`TTL`, and `Urgency` and `Topic` when set), the VAPID
    /// `Authorization`, and the payload encrypted for the browser with `aes128gcm`.
    /// A message with no payload goes without a body or encryption headers.
    ///
    /// Each call encrypts with a fresh one-time key and salt.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] if the system's random number generator fails.
    pub fn request(
        &self,
        subscription: &Subscription,
        message: &Message,
    ) -> Result<Request<Vec<u8>>, Error> {
        self.request_at(subscription, message, SystemTime::now())
    }

    pub(crate) fn request_at(
        &self,
        subscription: &Subscription,
        message: &Message,
        now: SystemTime,
    ) -> Result<Request<Vec<u8>>, Error> {
        let authorization = self.signer.authorization(subscription.origin(), now);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(subscription.endpoint())
            .header("ttl", message.ttl)
            .header(AUTHORIZATION, header(authorization)?);
        if let Some(urgency) = message.urgency {
            request = request.header("urgency", urgency.as_str());
        }
        if let Some(topic) = &message.topic {
            request = request.header("topic", header(topic.as_str().to_owned())?);
        }
        let body = if message.payload.is_empty() {
            Vec::new()
        } else {
            request = request
                .header(CONTENT_ENCODING, "aes128gcm")
                .header(CONTENT_TYPE, "application/octet-stream");
            ece::encrypt(
                &message.payload,
                subscription.public_key(),
                subscription.auth(),
            )?
        };
        request
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .map_err(|_| Error::InvalidEndpoint("not a URL"))
    }
}

impl std::fmt::Debug for WebPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebPush")
            .field("key", self.key())
            .finish_non_exhaustive()
    }
}

fn header(value: String) -> Result<HeaderValue, Error> {
    // Every value here is base64url, digits or a fixed word, so this cannot fail.
    HeaderValue::try_from(value).map_err(|_| Error::InvalidKey("header"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Topic, Urgency};

    fn push() -> WebPush {
        WebPush::new(VapidKey::generate().unwrap(), "mailto:ops@example.com").unwrap()
    }

    #[test]
    fn builds_an_encrypted_request() {
        let receiver = Receiver::generate().unwrap();
        let subscription = receiver
            .subscription("https://push.example.com:8443/send/abc?x=1")
            .unwrap();
        let message = Message::new("hello")
            .unwrap()
            .ttl(Duration::from_secs(60))
            .urgency(Urgency::High)
            .topic(Topic::new("greeting").unwrap());
        let request = push().request(&subscription, &message).unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), "https://push.example.com:8443/send/abc?x=1");
        let headers = request.headers();
        assert_eq!(headers["ttl"], "60");
        assert_eq!(headers["urgency"], "high");
        assert_eq!(headers["topic"], "greeting");
        assert_eq!(headers["content-encoding"], "aes128gcm");
        assert_eq!(headers["content-type"], "application/octet-stream");
        assert_eq!(
            headers["content-length"],
            request.body().len().to_string().as_str()
        );
        assert!(
            headers["authorization"]
                .to_str()
                .unwrap()
                .starts_with("vapid t=")
        );
        assert_eq!(receiver.decrypt(request.body()).unwrap(), b"hello");
    }

    #[test]
    fn sends_an_empty_message_without_a_body() {
        let subscription = Receiver::generate()
            .unwrap()
            .subscription("https://push.example.com/a")
            .unwrap();
        let request = push().request(&subscription, &Message::empty()).unwrap();
        assert!(request.body().is_empty());
        assert_eq!(request.headers()["content-length"], "0");
        assert!(!request.headers().contains_key("content-encoding"));
        assert!(!request.headers().contains_key("urgency"));
        assert!(!request.headers().contains_key("topic"));
    }

    #[test]
    fn signs_for_the_endpoint_origin() {
        let subscription = Receiver::generate()
            .unwrap()
            .subscription("https://Web.Push.Apple.com/QGx")
            .unwrap();
        let push = push();
        let request = push.request(&subscription, &Message::empty()).unwrap();
        let authorization = request.headers()["authorization"].to_str().unwrap();
        let jwt = authorization
            .strip_prefix("vapid t=")
            .unwrap()
            .split(',')
            .next()
            .unwrap();
        let claims = jwt.split('.').nth(1).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&crate::base64url::decode(claims).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://web.push.apple.com");
        assert!(authorization.ends_with(&format!(", k={}", push.key().public_key())));
    }
}
