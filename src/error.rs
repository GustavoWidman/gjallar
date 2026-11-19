use std::fmt;

/// Everything that can go wrong while preparing, sending or decrypting a push message.
///
/// Bad input from a browser or a push service (a malformed subscription, a key that is
/// not a curve point, a body that does not decrypt) always ends up here and never in a
/// panic.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The subscription's endpoint is not an absolute `https` URL, or not one a push
    /// service could serve. The string says what is wrong with it.
    InvalidEndpoint(&'static str),
    /// A key is malformed: bad base64url, the wrong length, or not a point on P-256.
    /// The string names the key (`p256dh`, `auth`, `VAPID key`).
    InvalidKey(&'static str),
    /// The VAPID subject is neither a `mailto:` nor an `https:` URI.
    InvalidSubject,
    /// A `Topic` is empty, longer than 32 characters, or uses a character outside the
    /// base64url alphabet.
    InvalidTopic,
    /// A VAPID token validity of zero or of more than 24 hours.
    InvalidValidity,
    /// The plaintext does not fit in one 4096-byte record. `size` is its length and
    /// [`MAX_PAYLOAD`](crate::MAX_PAYLOAD) the limit.
    PayloadTooLarge {
        /// The length of the rejected plaintext, in bytes.
        size: usize,
    },
    /// The operating system's random number generator failed.
    Random,
    /// An encrypted body is malformed or does not decrypt with the given keys.
    Decrypt,
    /// The client gave up before sending this request, because the time budget of the
    /// whole send ran out.
    Deadline,
    /// The request could not be sent, or its response not read: DNS, TLS, a refused
    /// connection or a timeout.
    #[cfg(feature = "client")]
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(why) => write!(f, "invalid push endpoint: {why}"),
            Self::InvalidKey(which) => write!(f, "invalid {which}"),
            Self::InvalidSubject => {
                f.write_str("invalid VAPID subject: it must be a mailto: or https: URI")
            }
            Self::InvalidTopic => f.write_str(
                "invalid topic: it must be 1 to 32 characters of the base64url alphabet",
            ),
            Self::InvalidValidity => f.write_str(
                "invalid VAPID token validity: it must be more than 0 and at most 24 hours",
            ),
            Self::PayloadTooLarge { size } => write!(
                f,
                "payload of {size} bytes is over the {} bytes one push message holds",
                crate::MAX_PAYLOAD
            ),
            Self::Random => f.write_str("the system's random number generator failed"),
            Self::Decrypt => f.write_str("the push message does not decrypt"),
            Self::Deadline => f.write_str("the send's time budget ran out before this request"),
            #[cfg(feature = "client")]
            Self::Transport(error) => write!(f, "could not reach the push service: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "client")]
            Self::Transport(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
