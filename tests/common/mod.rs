#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

/// Checks an `Authorization: vapid t=<jwt>, k=<key>` header the way a push service
/// does: `k` is the sender's key, the JWT's ES256 signature verifies with it, `aud` is
/// the push service's origin, `exp` lies in the next 24 hours and `sub` is a contact.
/// Returns the claims.
pub fn check_vapid(header: &str, audience: &str, public_key: &str) -> serde_json::Value {
    let rest = header
        .strip_prefix("vapid t=")
        .expect("a vapid authorization");
    let (jwt, key) = rest.split_once(", k=").expect("t and k parameters");
    assert_eq!(key, public_key);

    let (input, signature) = jwt.rsplit_once('.').expect("a signed JWT");
    let (header, claims) = input.split_once('.').expect("a JWT header and claims");
    let verifying = VerifyingKey::from_sec1_bytes(&decode(key)).expect("an uncompressed P-256 key");
    let signature = Signature::from_slice(&decode(signature)).expect("a 64-byte ES256 signature");
    verifying
        .verify(input.as_bytes(), &signature)
        .expect("the signature verifies with k");

    let header: serde_json::Value = serde_json::from_slice(&decode(header)).unwrap();
    assert_eq!(header["alg"], "ES256");
    let claims: serde_json::Value = serde_json::from_slice(&decode(claims)).unwrap();
    assert_eq!(claims["aud"], audience);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = claims["exp"].as_u64().expect("a numeric exp");
    assert!(
        exp > now && exp <= now + 24 * 3600,
        "exp {exp} is not within a day of {now}"
    );
    let sub = claims["sub"].as_str().expect("a sub claim");
    assert!(
        sub.starts_with("mailto:") || sub.starts_with("https://"),
        "{sub}"
    );
    claims
}

pub fn decode(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).expect("base64url")
}
