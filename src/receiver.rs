use std::fmt;

use p256::SecretKey;
use p256::elliptic_curve::Generate;

use crate::{Error, Subscription, ece};

/// The browser's side of a subscription: a P-256 key pair and an auth secret, which
/// decrypt what a push service delivers.
///
/// Its use is testing a sender end to end without a browser: make a subscription for
/// a fake push service, send to it, and decrypt what arrived.
///
/// ```
/// use gjallar::{Message, Receiver, VapidKey, WebPush};
///
/// let receiver = Receiver::generate()?;
/// let subscription = receiver.subscription("http://127.0.0.1:8080/push/1")?;
/// let push = WebPush::new(VapidKey::generate()?, "mailto:test@example.com")?;
/// let request = push.request(&subscription, &Message::new("ping")?)?;
/// assert_eq!(receiver.decrypt(request.body())?, b"ping");
/// # Ok::<(), gjallar::Error>(())
/// ```
#[derive(Clone)]
pub struct Receiver {
    secret: SecretKey,
    auth: [u8; 16],
}

impl Receiver {
    /// A fresh key pair and auth secret.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] if the system's random number generator fails.
    pub fn generate() -> Result<Self, Error> {
        let secret = SecretKey::try_generate().map_err(|_| Error::Random)?;
        let mut auth = [0; 16];
        getrandom::fill(&mut auth).map_err(|_| Error::Random)?;
        Ok(Self { secret, auth })
    }

    /// The subscription a browser holding these keys would report for `endpoint`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEndpoint`] if `endpoint` is not an `https` URL or an `http` one
    /// to a loopback address.
    pub fn subscription(&self, endpoint: &str) -> Result<Subscription, Error> {
        let p256dh = self.secret.public_key().to_sec1_bytes();
        let p256dh = p256dh
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidKey("p256dh"))?;
        Subscription::from_parts(endpoint, p256dh, self.auth)
    }

    /// Decrypts an `aes128gcm` push message body (RFC 8291) sent to this receiver's
    /// subscription.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] if the body is malformed, was encrypted for other keys, or
    /// was tampered with.
    pub fn decrypt(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        ece::decrypt(body, &self.secret, &self.auth)
    }
}

impl fmt::Debug for Receiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}
