use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::SecretKey;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;

use crate::{Error, base64url};

/// The application server's VAPID key pair (RFC 8292), a P-256 key that identifies
/// the server to push services.
///
/// The browser binds each subscription to the public half: pass
/// [`public_key`](Self::public_key) to `pushManager.subscribe()` as its
/// `applicationServerKey`. Every push then has to be signed with the private half, so
/// changing the key orphans every subscription made with the old one (Apple answers
/// them with 403 `VapidPkHashMismatch`).
///
/// The private half is stored as the base64url of its 32-byte scalar, one line that
/// fits in any secret store. It is the same form the `web-push` npm package and most
/// other libraries print, so their keys load here too:
///
/// ```
/// use gjallar::VapidKey;
///
/// let key = VapidKey::generate()?;
/// let stored = key.to_base64url(); // keep this secret
/// let loaded: VapidKey = stored.parse()?;
/// assert_eq!(loaded.public_key(), key.public_key());
/// # Ok::<(), gjallar::Error>(())
/// ```
///
/// Its [`Debug`] output never shows the private half.
#[derive(Clone)]
pub struct VapidKey {
    signing: SigningKey,
    public: [u8; 65],
}

impl VapidKey {
    /// Generates a new key from the operating system's random number generator.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] if the random number generator fails.
    pub fn generate() -> Result<Self, Error> {
        let secret = SecretKey::try_generate().map_err(|_| Error::Random)?;
        Ok(Self::from_secret(&secret))
    }

    /// Loads a private key from the base64url of its 32-byte scalar, the form
    /// [`to_base64url`](Self::to_base64url) writes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the text is not 32 bytes of base64url or not a valid
    /// P-256 scalar.
    pub fn from_base64url(text: &str) -> Result<Self, Error> {
        let bytes: [u8; 32] =
            base64url::decode_array(text).ok_or(Error::InvalidKey("VAPID key"))?;
        let secret = SecretKey::from_slice(&bytes).map_err(|_| Error::InvalidKey("VAPID key"))?;
        Ok(Self::from_secret(&secret))
    }

    /// Loads a private key from PEM, either SEC1 (`BEGIN EC PRIVATE KEY`, what
    /// `openssl ecparam -genkey -name prime256v1` writes) or PKCS#8
    /// (`BEGIN PRIVATE KEY`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the text is neither, or holds a key on another curve.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let secret = SecretKey::from_sec1_pem(pem)
            .or_else(|_| SecretKey::from_pkcs8_pem(pem))
            .map_err(|_| Error::InvalidKey("VAPID key"))?;
        Ok(Self::from_secret(&secret))
    }

    /// The private key as the base64url of its 32-byte scalar. This is the secret:
    /// store it where other secrets go.
    pub fn to_base64url(&self) -> String {
        base64url::encode(self.signing.to_bytes())
    }

    /// The public key as base64url of its uncompressed point, the
    /// `applicationServerKey` the page passes to `pushManager.subscribe()`. It is not
    /// secret: every push carries it.
    pub fn public_key(&self) -> String {
        base64url::encode(self.public)
    }

    /// The public key as its 65 uncompressed bytes (`0x04 ‖ x ‖ y`).
    pub fn public_key_bytes(&self) -> [u8; 65] {
        self.public
    }

    fn from_secret(secret: &SecretKey) -> Self {
        let public = secret.public_key().to_sec1_bytes();
        let public: [u8; 65] = public
            .as_ref()
            .try_into()
            .expect("an uncompressed P-256 point is 65 bytes");
        Self {
            signing: SigningKey::from(secret),
            public,
        }
    }
}

impl FromStr for VapidKey {
    type Err = Error;

    /// Parses either form [`VapidKey`] reads: PEM when the text starts with
    /// `-----BEGIN`, base64url otherwise.
    fn from_str(text: &str) -> Result<Self, Error> {
        if text.trim_start().starts_with("-----BEGIN") {
            Self::from_pem(text)
        } else {
            Self::from_base64url(text)
        }
    }
}

impl fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VapidKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl PartialEq for VapidKey {
    fn eq(&self, other: &Self) -> bool {
        self.signing == other.signing
    }
}

impl Eq for VapidKey {}

/// Signs VAPID tokens and keeps one per audience until it nears its expiry.
pub(crate) struct Signer {
    key: VapidKey,
    subject: String,
    validity: Duration,
    tokens: Mutex<HashMap<String, Token>>,
}

#[derive(Clone)]
struct Token {
    authorization: String,
    expires: u64,
}

#[derive(Serialize)]
struct Claims<'a> {
    aud: &'a str,
    exp: u64,
    sub: &'a str,
}

/// RFC 8292 §2 caps `exp` at 24 hours ahead. 12 hours leaves room for a sender whose
/// clock runs ahead of the push service's.
pub(crate) const DEFAULT_VALIDITY: Duration = Duration::from_secs(12 * 3600);
const MAX_VALIDITY: Duration = Duration::from_secs(24 * 3600);
/// Apple asks for no more than one new token an hour, so a token is replaced an hour
/// before it expires, or halfway through a validity shorter than two hours.
const RENEW_BEFORE: Duration = Duration::from_secs(3600);

impl Signer {
    pub(crate) fn new(key: VapidKey, subject: &str) -> Result<Self, Error> {
        check_subject(subject)?;
        Ok(Self {
            key,
            subject: subject.to_owned(),
            validity: DEFAULT_VALIDITY,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn set_validity(&mut self, validity: Duration) -> Result<(), Error> {
        if validity.is_zero() || validity > MAX_VALIDITY {
            return Err(Error::InvalidValidity);
        }
        self.validity = validity;
        self.tokens
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Ok(())
    }

    pub(crate) fn key(&self) -> &VapidKey {
        &self.key
    }

    /// The `Authorization` header value for a push service origin, `vapid t=…, k=…`.
    pub(crate) fn authorization(&self, audience: &str, now: SystemTime) -> String {
        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let renew_before = RENEW_BEFORE.min(self.validity / 2).as_secs();
        // A poisoned lock only means another thread panicked mid-insert; the map
        // itself is still a valid cache.
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = tokens.get(audience)
            && now + renew_before < token.expires
        {
            return token.authorization.clone();
        }
        let expires = now + self.validity.as_secs();
        let token = Token {
            authorization: format!(
                "vapid t={}, k={}",
                self.sign(audience, expires),
                self.key.public_key()
            ),
            expires,
        };
        tokens.retain(|_, token| token.expires > now);
        tokens.insert(audience.to_owned(), token.clone());
        token.authorization
    }

    fn sign(&self, audience: &str, expires: u64) -> String {
        // {"typ":"JWT","alg":"ES256"}
        const HEADER: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
        let claims = Claims {
            aud: audience,
            exp: expires,
            sub: &self.subject,
        };
        let claims = serde_json::to_vec(&claims).expect("the claims are plain strings and numbers");
        let input = format!("{HEADER}.{}", base64url::encode(claims));
        let signature: Signature = self.key.signing.sign(input.as_bytes());
        format!("{input}.{}", base64url::encode(signature.to_bytes()))
    }
}

fn check_subject(subject: &str) -> Result<(), Error> {
    if subject.chars().any(char::is_whitespace) {
        return Err(Error::InvalidSubject);
    }
    let lower = subject.to_ascii_lowercase();
    if let Some(address) = lower.strip_prefix("mailto:") {
        return match address.split_once('@') {
            Some((user, host)) if !user.is_empty() && !host.is_empty() => Ok(()),
            _ => Err(Error::InvalidSubject),
        };
    }
    if lower.starts_with("https://") {
        let uri: http::Uri = subject.parse().map_err(|_| Error::InvalidSubject)?;
        if uri.host().is_some_and(|host| !host.is_empty()) {
            return Ok(());
        }
    }
    Err(Error::InvalidSubject)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    fn decode_json(part: &str) -> serde_json::Value {
        serde_json::from_slice(&base64url::decode(part).unwrap()).unwrap()
    }

    /// Splits `vapid t=<jwt>, k=<key>` and verifies the token's ES256 signature with `k`.
    fn verify(authorization: &str) -> (serde_json::Value, serde_json::Value, String) {
        let rest = authorization.strip_prefix("vapid t=").unwrap();
        let (jwt, key) = rest.split_once(", k=").unwrap();
        let (input, signature) = jwt.rsplit_once('.').unwrap();
        let (header, claims) = input.split_once('.').unwrap();
        let verifying = VerifyingKey::from_sec1_bytes(&base64url::decode(key).unwrap()).unwrap();
        let signature = Signature::from_slice(&base64url::decode(signature).unwrap()).unwrap();
        verifying.verify(input.as_bytes(), &signature).unwrap();
        (decode_json(header), decode_json(claims), key.to_owned())
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn signs_an_es256_token_with_the_claims() {
        let key = VapidKey::generate().unwrap();
        let signer = Signer::new(key.clone(), "mailto:ops@example.com").unwrap();
        let (header, claims, k) =
            verify(&signer.authorization("https://push.example.com", at(1_000)));
        assert_eq!(header, serde_json::json!({"typ": "JWT", "alg": "ES256"}));
        assert_eq!(
            claims,
            serde_json::json!({"aud": "https://push.example.com", "exp": 1_000 + 12 * 3600, "sub": "mailto:ops@example.com"})
        );
        assert_eq!(k, key.public_key());
    }

    #[test]
    fn reuses_a_token_per_audience_until_an_hour_before_it_expires() {
        let signer = Signer::new(VapidKey::generate().unwrap(), "https://example.com").unwrap();
        let apple = "https://web.push.apple.com";
        let first = signer.authorization(apple, at(0));
        assert_eq!(signer.authorization(apple, at(11 * 3600 - 1)), first);
        assert_ne!(
            signer.authorization("https://fcm.googleapis.com", at(1)),
            first
        );
        let renewed = signer.authorization(apple, at(11 * 3600));
        assert_ne!(renewed, first);
        let (_, claims, _) = verify(&renewed);
        assert_eq!(claims["exp"], 23 * 3600);
    }

    #[test]
    fn renews_halfway_through_a_short_validity() {
        let mut signer = Signer::new(VapidKey::generate().unwrap(), "https://example.com").unwrap();
        signer.set_validity(Duration::from_secs(1800)).unwrap();
        let first = signer.authorization("https://a.example", at(0));
        assert_eq!(signer.authorization("https://a.example", at(899)), first);
        assert_ne!(signer.authorization("https://a.example", at(900)), first);
    }

    #[test]
    fn bounds_the_validity() {
        let mut signer = Signer::new(VapidKey::generate().unwrap(), "https://example.com").unwrap();
        assert!(signer.set_validity(Duration::ZERO).is_err());
        assert!(
            signer
                .set_validity(Duration::from_secs(24 * 3600 + 1))
                .is_err()
        );
        signer.set_validity(Duration::from_secs(24 * 3600)).unwrap();
        let (_, claims, _) = verify(&signer.authorization("https://a.example", at(5)));
        assert_eq!(claims["exp"], 5 + 24 * 3600);
    }

    #[test]
    fn checks_the_subject() {
        for good in [
            "mailto:ops@example.com",
            "MAILTO:a@b",
            "https://example.com",
            "https://example.com/contact",
        ] {
            assert!(check_subject(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "ops@example.com",
            "mailto:",
            "mailto:nobody",
            "mailto: ops@example.com",
            "http://example.com",
            "https://",
            "example.com",
        ] {
            assert!(check_subject(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn round_trips_the_key() {
        let key = VapidKey::generate().unwrap();
        let loaded = VapidKey::from_base64url(&key.to_base64url()).unwrap();
        assert_eq!(loaded, key);
        assert_eq!(key.public_key_bytes()[0], 4);
        assert!(!format!("{key:?}").contains(&key.to_base64url()));
    }

    #[test]
    fn loads_the_rfc_8291_application_server_key() {
        let key: VapidKey = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
            .parse()
            .unwrap();
        assert_eq!(
            key.public_key(),
            "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
        );
    }

    #[test]
    fn loads_pem() {
        let key = VapidKey::generate().unwrap();
        let secret = SecretKey::from_slice(&key.signing.to_bytes()).unwrap();
        let sec1 = secret.to_sec1_pem(Default::default()).unwrap();
        assert_eq!(sec1.parse::<VapidKey>().unwrap(), key);
        use p256::pkcs8::EncodePrivateKey;
        let pkcs8 = secret.to_pkcs8_pem(Default::default()).unwrap();
        assert_eq!(VapidKey::from_pem(&pkcs8).unwrap(), key);
    }

    #[test]
    fn rejects_bad_keys() {
        for bad in [
            "",
            "short",
            &base64url::encode([0u8; 32]),
            &base64url::encode([0xffu8; 32]),
            "-----BEGIN junk",
        ] {
            assert!(
                matches!(bad.parse::<VapidKey>(), Err(Error::InvalidKey(_))),
                "{bad}"
            );
        }
    }
}
