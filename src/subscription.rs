use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{Error, base64url};

/// Where one browser receives pushes, and the keys to encrypt them for it.
///
/// It deserializes the JSON of the browser's `PushSubscription.toJSON()`, the object a
/// page sends to its server after `pushManager.subscribe()`:
///
/// ```
/// let subscription: gjallar::Subscription = serde_json::from_str(r#"{
///     "endpoint": "https://web.push.apple.com/QGx2Y1N0aGlzIGlzIG5vdCBhIHJlYWwgdG9rZW4",
///     "expirationTime": null,
///     "keys": {
///         "p256dh": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
///         "auth": "BTBZMqHH6r4Tts7J_aSIgg"
///     }
/// }"#)?;
/// assert_eq!(subscription.origin(), "https://web.push.apple.com");
/// # Ok::<(), serde_json::Error>(())
/// ```
///
/// Members other than these are ignored, so a subscription stored beside a name or a
/// user id still parses, and `#[serde(flatten)]` puts it inside a larger record. It
/// serializes back to the same shape.
///
/// Every field is checked while parsing: the endpoint is an absolute `https` URL (or
/// `http` to a loopback address, for a push service under test), `p256dh` is a point on
/// P-256 in uncompressed form, and `auth` is 16 bytes. The endpoint is a capability URL
/// that anyone holding it can push to, so [`Debug`] prints only its origin.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "Json", into = "Json")]
pub struct Subscription {
    endpoint: String,
    origin: String,
    p256dh: [u8; 65],
    public_key: PublicKey,
    auth: [u8; 16],
    expiration_time: Option<u64>,
}

impl Subscription {
    /// Builds a subscription from its endpoint and its two base64url keys, as
    /// `PushSubscription.toJSON()` spells them.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEndpoint`] for an endpoint that is not an absolute `https` URL,
    /// and [`Error::InvalidKey`] for keys that do not decode to a P-256 point and a
    /// 16-byte secret.
    pub fn new(endpoint: &str, p256dh: &str, auth: &str) -> Result<Self, Error> {
        let origin = origin(endpoint)?;
        let p256dh: [u8; 65] =
            base64url::decode_array(p256dh).ok_or(Error::InvalidKey("p256dh"))?;
        let public_key = user_agent_key(&p256dh)?;
        let auth = base64url::decode_array(auth).ok_or(Error::InvalidKey("auth"))?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            origin,
            p256dh,
            public_key,
            auth,
            expiration_time: None,
        })
    }

    pub(crate) fn from_parts(
        endpoint: &str,
        p256dh: [u8; 65],
        auth: [u8; 16],
    ) -> Result<Self, Error> {
        Ok(Self {
            endpoint: endpoint.to_owned(),
            origin: origin(endpoint)?,
            public_key: user_agent_key(&p256dh)?,
            p256dh,
            auth,
            expiration_time: None,
        })
    }

    /// The push service URL that messages for this browser are posted to.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The endpoint's origin (`https://fcm.googleapis.com`), which is also the VAPID
    /// token's audience.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The browser's P-256 public key, uncompressed (`0x04 ‖ x ‖ y`).
    pub fn p256dh(&self) -> &[u8; 65] {
        &self.p256dh
    }

    /// The browser's 16-byte authentication secret.
    pub fn auth(&self) -> &[u8; 16] {
        &self.auth
    }

    /// When the browser said the subscription expires, if it said so. Most browsers
    /// send `null`.
    pub fn expiration_time(&self) -> Option<SystemTime> {
        self.expiration_time
            .map(|ms| UNIX_EPOCH + Duration::from_millis(ms))
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

fn user_agent_key(p256dh: &[u8; 65]) -> Result<PublicKey, Error> {
    // RFC 8291 requires the uncompressed form, which the length already pins down; the
    // parse rejects anything that is not on the curve.
    PublicKey::from_sec1_bytes(p256dh).map_err(|_| Error::InvalidKey("p256dh"))
}

/// The origin of a push endpoint, as RFC 6454 serializes it: lowercase scheme and host,
/// and the port only when it is not the scheme's default.
pub(crate) fn origin(endpoint: &str) -> Result<String, Error> {
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| Error::InvalidEndpoint("not a URL"))?;
    let scheme = uri
        .scheme_str()
        .ok_or(Error::InvalidEndpoint("not an absolute URL"))?
        .to_ascii_lowercase();
    let authority = uri
        .authority()
        .ok_or(Error::InvalidEndpoint("not an absolute URL"))?;
    if authority.as_str().contains('@') {
        return Err(Error::InvalidEndpoint("carries credentials"));
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err(Error::InvalidEndpoint("has no host"));
    }
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" if is_loopback(&host) => 80,
        _ => return Err(Error::InvalidEndpoint("is not https")),
    };
    Ok(match authority.port_u16() {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Json {
    endpoint: String,
    #[serde(default)]
    expiration_time: Option<f64>,
    keys: Keys,
}

#[derive(Deserialize, Serialize)]
struct Keys {
    p256dh: String,
    auth: String,
}

impl TryFrom<Json> for Subscription {
    type Error = Error;

    fn try_from(json: Json) -> Result<Self, Error> {
        let mut subscription =
            Subscription::new(&json.endpoint, &json.keys.p256dh, &json.keys.auth)?;
        // A DOMHighResTimeStamp: milliseconds since the epoch, possibly fractional.
        subscription.expiration_time = json
            .expiration_time
            .filter(|ms| ms.is_finite() && *ms >= 0.0)
            .map(|ms| ms as u64);
        Ok(subscription)
    }
}

impl From<Subscription> for Json {
    fn from(subscription: Subscription) -> Self {
        Json {
            keys: Keys {
                p256dh: base64url::encode(subscription.p256dh),
                auth: base64url::encode(subscription.auth),
            },
            expiration_time: subscription.expiration_time.map(|ms| ms as f64),
            endpoint: subscription.endpoint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256DH: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";

    fn json(endpoint: &str, p256dh: &str, auth: &str, expiration: &str) -> String {
        format!(
            r#"{{"endpoint":"{endpoint}","expirationTime":{expiration},"keys":{{"p256dh":"{p256dh}","auth":"{auth}"}}}}"#
        )
    }

    #[test]
    fn parses_a_browser_subscription() {
        let text = json(
            "https://fcm.googleapis.com/fcm/send/abc:def",
            P256DH,
            AUTH,
            "null",
        );
        let subscription: Subscription = serde_json::from_str(&text).unwrap();
        assert_eq!(
            subscription.endpoint(),
            "https://fcm.googleapis.com/fcm/send/abc:def"
        );
        assert_eq!(subscription.origin(), "https://fcm.googleapis.com");
        assert_eq!(subscription.auth().len(), 16);
        assert_eq!(subscription.expiration_time(), None);
        assert_eq!(serde_json::to_string(&subscription).unwrap(), text);
    }

    #[test]
    fn keeps_the_expiration_time() {
        let text = json("https://example.com/push", P256DH, AUTH, "1700000000000.5");
        let subscription: Subscription = serde_json::from_str(&text).unwrap();
        assert_eq!(
            subscription.expiration_time(),
            Some(UNIX_EPOCH + Duration::from_millis(1_700_000_000_000))
        );
    }

    #[test]
    fn ignores_other_members() {
        let text = r#"{"name":"phone","endpoint":"https://example.com/p","keys":{"p256dh":"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4","auth":"BTBZMqHH6r4Tts7J_aSIgg"}}"#;
        assert!(serde_json::from_str::<Subscription>(text).is_ok());
    }

    #[test]
    fn rejects_bad_keys() {
        let off_curve = format!("BA{}", &P256DH[2..]);
        let compressed = "AyVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx";
        for (p256dh, auth) in [
            (off_curve.as_str(), AUTH),
            (compressed, AUTH),
            ("not base64!", AUTH),
            (P256DH, "BTBZMqHH6r4Tts7J_aSI"),
            (P256DH, ""),
        ] {
            let error = Subscription::new("https://example.com/p", p256dh, auth).unwrap_err();
            assert!(
                matches!(error, Error::InvalidKey(_)),
                "{p256dh} {auth}: {error}"
            );
        }
    }

    #[test]
    fn computes_origins() {
        for (endpoint, expected) in [
            ("https://Push.Example.com/a/b?c", "https://push.example.com"),
            ("https://push.example.com:443/a", "https://push.example.com"),
            (
                "https://push.example.com:8443/a",
                "https://push.example.com:8443",
            ),
            ("http://127.0.0.1:4000/a", "http://127.0.0.1:4000"),
            ("http://localhost/a", "http://localhost"),
            ("http://[::1]:80/a", "http://[::1]"),
        ] {
            assert_eq!(origin(endpoint).unwrap(), expected, "{endpoint}");
        }
    }

    #[test]
    fn rejects_bad_endpoints() {
        for endpoint in [
            "",
            "/relative",
            "push.example.com/a",
            "http://push.example.com/a",
            "http://10.0.0.1/a",
            "ftp://push.example.com/a",
            "https://user:secret@push.example.com/a",
            "https:///a",
        ] {
            let error = Subscription::new(endpoint, P256DH, AUTH).unwrap_err();
            assert!(
                matches!(error, Error::InvalidEndpoint(_)),
                "{endpoint}: {error}"
            );
        }
    }

    #[test]
    fn debug_hides_the_endpoint() {
        let subscription =
            Subscription::new("https://example.com/secret-token", P256DH, AUTH).unwrap();
        let printed = format!("{subscription:?}");
        assert!(!printed.contains("secret-token"), "{printed}");
        assert!(printed.contains("https://example.com"), "{printed}");
    }
}
