use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::declarative::Declarative;
use crate::{Error, MAX_PAYLOAD, base64url};

/// One push message: its payload and the RFC 8030 options the push service acts on.
///
/// ```
/// use std::time::Duration;
/// use gjallar::{Message, Notification, Topic, Urgency};
///
/// let message = Message::declarative(
///     Notification::new("Build finished", "https://ci.example.com/builds/42").body("all green"),
/// )?
/// .ttl(Duration::from_secs(3600))
/// .urgency(Urgency::High)
/// .topic(Topic::digest("build/42"));
/// # Ok::<(), gjallar::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub(crate) payload: Vec<u8>,
    pub(crate) ttl: u64,
    pub(crate) urgency: Option<Urgency>,
    pub(crate) topic: Option<Topic>,
}

/// Four weeks: the longest Firebase Cloud Messaging keeps a message, and less than
/// the 30 days Apple and Mozilla allow.
const DEFAULT_TTL: u64 = 28 * 24 * 3600;

impl Message {
    /// A message with an opaque payload, which the service worker's `push` event reads
    /// with `event.data`.
    ///
    /// # Errors
    ///
    /// [`Error::PayloadTooLarge`] for a payload over [`MAX_PAYLOAD`] bytes, the most
    /// that one encrypted 4096-byte record holds.
    pub fn new(payload: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge {
                size: payload.len(),
            });
        }
        Ok(Self {
            payload,
            ttl: DEFAULT_TTL,
            urgency: None,
            topic: None,
        })
    }

    /// A message with no payload. It is sent without a body or encryption, and the
    /// service worker's `push` event sees `event.data` as `null`.
    ///
    /// Safari revokes the permission of a site whose push shows no notification, so a
    /// service worker that receives this must still show one.
    pub fn empty() -> Self {
        Self {
            payload: Vec::new(),
            ttl: DEFAULT_TTL,
            urgency: None,
            topic: None,
        }
    }

    /// A Declarative Web Push message, which a browser that supports it (Safari 18.4
    /// and later) shows by itself, with no service worker code. Other browsers deliver
    /// the same JSON to the service worker's `push` event.
    ///
    /// # Errors
    ///
    /// [`Error::PayloadTooLarge`] when the JSON is over [`MAX_PAYLOAD`] bytes.
    pub fn declarative(message: impl Into<Declarative>) -> Result<Self, Error> {
        Self::new(message.into().to_json())
    }

    /// How long the push service keeps the message for a browser that is offline,
    /// sent as the `TTL` header in whole seconds. Four weeks unless set.
    ///
    /// Zero asks for delivery only to a browser that is connected right now. Apple
    /// answers a `TTL` of zero with 400 `BadTtl`, and push services cap long ones at
    /// their own limit (four weeks at Firebase, 30 days at Apple and Mozilla).
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl.as_secs();
        self
    }

    /// How soon the browser's device should wake for the message, sent as the
    /// `Urgency` header. Without it push services assume [`Urgency::Normal`].
    #[must_use]
    pub fn urgency(mut self, urgency: Urgency) -> Self {
        self.urgency = Some(urgency);
        self
    }

    /// A name for the message, sent as the `Topic` header. A push service still
    /// holding an undelivered message with the same topic for the same subscription
    /// replaces it with this one.
    #[must_use]
    pub fn topic(mut self, topic: Topic) -> Self {
        self.topic = Some(topic);
        self
    }

    /// The plaintext payload, before encryption.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// The RFC 8030 `Urgency` of a message: how much battery the device may spend to
/// receive it promptly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Urgency {
    /// `very-low`: delivered when the device is on power and Wi-Fi, say.
    VeryLow,
    /// `low`: delivered when the device is on power or Wi-Fi.
    Low,
    /// `normal`: delivered unless the device is low on battery. The default.
    Normal,
    /// `high`: delivered right away, even on low battery.
    High,
}

impl Urgency {
    /// The header value: `very-low`, `low`, `normal` or `high`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VeryLow => "very-low",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Urgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RFC 8030 `Topic`: 1 to 32 characters of the base64url alphabet
/// (`A-Z a-z 0-9 - _`).
///
/// [`Topic::new`] checks a name you choose, and [`Topic::digest`] makes a valid one
/// from any text, so a tag like `deploy/web-1/3f2a9c` can name its message as is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Topic(String);

impl Topic {
    /// The most characters a topic may have.
    pub const MAX_LEN: usize = 32;

    /// Checks a topic.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTopic`] if it is empty, longer than 32 characters, or uses a
    /// character outside the base64url alphabet.
    pub fn new(topic: &str) -> Result<Self, Error> {
        let valid = (1..=Self::MAX_LEN).contains(&topic.len())
            && topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if valid {
            Ok(Self(topic.to_owned()))
        } else {
            Err(Error::InvalidTopic)
        }
    }

    /// The first 32 characters of the base64url SHA-256 of `text`. It is always a
    /// valid topic, and equal texts give equal topics.
    pub fn digest(text: impl AsRef<[u8]>) -> Self {
        let mut digest = base64url::encode(Sha256::digest(text.as_ref()));
        digest.truncate(Self::MAX_LEN);
        Self(digest)
    }

    /// The header value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Topic {
    type Err = Error;

    fn from_str(topic: &str) -> Result<Self, Error> {
        Self::new(topic)
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_topics() {
        for good in ["a", "deploy-1_2", &"x".repeat(32), "AZaz09-_"] {
            assert_eq!(Topic::new(good).unwrap().as_str(), good);
        }
        for bad in ["", &"x".repeat(33), "has space", "a/b", "a=b", "a.b", "é"] {
            assert!(
                matches!(Topic::new(bad), Err(Error::InvalidTopic)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn digests_any_text_into_a_topic() {
        let topic = Topic::digest("deploy/switch/3f2a9c1d0e4b");
        assert_eq!(topic.as_str().len(), 32);
        assert_eq!(Topic::new(topic.as_str()).unwrap(), topic);
        assert_eq!(topic, Topic::digest("deploy/switch/3f2a9c1d0e4b"));
        assert_ne!(topic, Topic::digest("deploy/switch/3f2a9c1d0e4c"));
        // base64url(sha256("")) = 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU
        assert_eq!(
            Topic::digest("").as_str(),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NM"
        );
    }

    #[test]
    fn bounds_the_payload() {
        assert!(Message::new(vec![0; MAX_PAYLOAD]).is_ok());
        assert!(matches!(
            Message::new(vec![0; MAX_PAYLOAD + 1]),
            Err(Error::PayloadTooLarge { size }) if size == MAX_PAYLOAD + 1
        ));
        assert_eq!(MAX_PAYLOAD, 3993);
    }

    #[test]
    fn keeps_the_options() {
        let message = Message::new("hi")
            .unwrap()
            .ttl(Duration::from_millis(90_500))
            .urgency(Urgency::VeryLow)
            .topic(Topic::new("t").unwrap());
        assert_eq!(message.ttl, 90);
        assert_eq!(message.urgency, Some(Urgency::VeryLow));
        assert_eq!(message.topic.unwrap().as_str(), "t");
        assert_eq!(Message::empty().ttl, 28 * 24 * 3600);
    }
}
