//! RFC 8291 message encryption: the `aes128gcm` content coding of RFC 8188, keyed by
//! ECDH between a one-time sender key and the browser's `p256dh`, mixed with its
//! `auth` secret.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::Generate;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;

use crate::Error;

/// The record size written into every header. One record of this size holds the
/// whole message, which is all RFC 8291 §4 allows.
const RECORD_SIZE: u32 = 4096;
/// salt (16) ‖ rs (4) ‖ idlen (1) ‖ keyid, the sender's public key (65).
pub(crate) const HEADER_SIZE: usize = 16 + 4 + 1 + 65;
const TAG_SIZE: usize = 16;
/// The largest plaintext one 4096-byte record carries: the record minus the header,
/// the padding delimiter and the AEAD tag (RFC 8291 §4).
pub const MAX_PAYLOAD: usize = RECORD_SIZE as usize - HEADER_SIZE - 1 - TAG_SIZE;

/// Encrypts with a fresh sender key and salt.
pub(crate) fn encrypt(
    plaintext: &[u8],
    ua_public: &PublicKey,
    auth: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let sender = SecretKey::try_generate().map_err(|_| Error::Random)?;
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
    encrypt_with(plaintext, ua_public, auth, &sender, salt)
}

/// Encrypts with the given sender key and salt. Both must be fresh for every message:
/// reusing them reuses the AES-GCM key and nonce.
pub(crate) fn encrypt_with(
    plaintext: &[u8],
    ua_public: &PublicKey,
    auth: &[u8; 16],
    sender: &SecretKey,
    salt: [u8; 16],
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge {
            size: plaintext.len(),
        });
    }
    let as_public = sec1(&sender.public_key());
    let shared = p256::ecdh::diffie_hellman(sender.to_nonzero_scalar(), ua_public.as_affine());
    let (cek, nonce) = derive(
        shared.raw_secret_bytes(),
        auth,
        &sec1(ua_public),
        &as_public,
        &salt,
    );

    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    record.push(2); // the last (and only) record's padding delimiter
    let ciphertext = Aes128Gcm::new(&cek.into())
        .encrypt(&Nonce::from(nonce), record.as_slice())
        .map_err(|_| Error::PayloadTooLarge {
            size: plaintext.len(),
        })?;

    let mut body = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// Decrypts an `aes128gcm` body addressed to `ua_secret`, records and padding included.
pub(crate) fn decrypt(
    body: &[u8],
    ua_secret: &SecretKey,
    auth: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let (salt, rest) = body.split_first_chunk::<16>().ok_or(Error::Decrypt)?;
    let (rs, rest) = rest.split_first_chunk::<4>().ok_or(Error::Decrypt)?;
    let (&idlen, rest) = rest.split_first().ok_or(Error::Decrypt)?;
    let rs = u32::from_be_bytes(*rs) as usize;
    if rs < 18 || idlen != 65 || rest.len() < 65 {
        return Err(Error::Decrypt);
    }
    let (keyid, records) = rest.split_at(65);
    let as_public = PublicKey::from_sec1_bytes(keyid).map_err(|_| Error::Decrypt)?;
    let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_public.as_affine());
    let (cek, base_nonce) = derive(
        shared.raw_secret_bytes(),
        auth,
        &sec1(&ua_secret.public_key()),
        keyid,
        salt,
    );
    let cipher = Aes128Gcm::new(&cek.into());

    if records.is_empty() {
        return Err(Error::Decrypt);
    }
    let count = records.len().div_ceil(rs);
    let mut plaintext = Vec::new();
    for (seq, record) in records.chunks(rs).enumerate() {
        let mut nonce = base_nonce;
        for (byte, seq) in nonce[4..].iter_mut().zip((seq as u64).to_be_bytes()) {
            *byte ^= seq;
        }
        let mut opened = cipher
            .decrypt(&Nonce::from(nonce), record)
            .map_err(|_| Error::Decrypt)?;
        let delimiter = opened.iter().rposition(|&b| b != 0).ok_or(Error::Decrypt)?;
        let last = seq + 1 == count;
        if opened[delimiter] != if last { 2 } else { 1 } {
            return Err(Error::Decrypt);
        }
        opened.truncate(delimiter);
        plaintext.extend_from_slice(&opened);
    }
    Ok(plaintext)
}

/// The content encryption key and nonce of RFC 8291 §3.4.
fn derive(
    ecdh: &[u8],
    auth: &[u8; 16],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8],
) -> ([u8; 16], [u8; 12]) {
    let mut key_info = Vec::with_capacity(14 + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = [0; 32];
    Hkdf::<Sha256>::new(Some(auth), ecdh)
        .expand(&key_info, &mut ikm)
        .expect("32 bytes is a valid HKDF-SHA-256 length");

    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0; 16];
    let mut nonce = [0; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .expect("16 bytes is a valid HKDF-SHA-256 length");
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .expect("12 bytes is a valid HKDF-SHA-256 length");
    (cek, nonce)
}

fn sec1(key: &PublicKey) -> Vec<u8> {
    key.to_sec1_bytes().into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64url::decode;

    /// RFC 8291 Appendix A.
    const PLAINTEXT: &str = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const HEADER: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const CIPHERTEXT: &str =
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

    fn secret(text: &str) -> SecretKey {
        SecretKey::from_slice(&decode(text).unwrap()).unwrap()
    }

    fn auth() -> [u8; 16] {
        decode(AUTH).unwrap().try_into().unwrap()
    }

    fn expected_body() -> Vec<u8> {
        [decode(HEADER).unwrap(), decode(CIPHERTEXT).unwrap()].concat()
    }

    #[test]
    fn matches_rfc_8291_appendix_a() {
        let ua_public = PublicKey::from_sec1_bytes(&decode(UA_PUBLIC).unwrap()).unwrap();
        let salt = decode(SALT).unwrap().try_into().unwrap();
        let plaintext = decode(PLAINTEXT).unwrap();
        assert_eq!(plaintext, b"When I grow up, I want to be a watermelon");
        let body =
            encrypt_with(&plaintext, &ua_public, &auth(), &secret(AS_PRIVATE), salt).unwrap();
        assert_eq!(body, expected_body());
    }

    #[test]
    fn decrypts_rfc_8291_appendix_a() {
        let plaintext = decrypt(&expected_body(), &secret(UA_PRIVATE), &auth()).unwrap();
        assert_eq!(plaintext, b"When I grow up, I want to be a watermelon");
    }

    #[test]
    fn round_trips_with_fresh_keys() {
        let ua = SecretKey::try_generate().unwrap();
        let auth = [7; 16];
        for size in [0, 1, 100, MAX_PAYLOAD] {
            let plaintext = vec![0xab; size];
            let body = encrypt(&plaintext, &ua.public_key(), &auth).unwrap();
            assert_eq!(body.len(), HEADER_SIZE + size + 1 + TAG_SIZE);
            assert_eq!(decrypt(&body, &ua, &auth).unwrap(), plaintext);
        }
        let largest = encrypt(&[0; MAX_PAYLOAD], &ua.public_key(), &auth).unwrap();
        assert_eq!(largest.len(), RECORD_SIZE as usize);
    }

    #[test]
    fn refuses_a_payload_over_one_record() {
        let ua = SecretKey::try_generate().unwrap();
        let error = encrypt(&[0; MAX_PAYLOAD + 1], &ua.public_key(), &[0; 16]).unwrap_err();
        assert!(matches!(error, Error::PayloadTooLarge { size } if size == MAX_PAYLOAD + 1));
    }

    #[test]
    fn rejects_tampered_or_truncated_bodies() {
        let ua = secret(UA_PRIVATE);
        let body = expected_body();
        for cut in [0, 15, 20, 21, 85, 86, 100, body.len() - 1] {
            assert!(decrypt(&body[..cut], &ua, &auth()).is_err(), "cut at {cut}");
        }
        let mut flipped = body.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(decrypt(&flipped, &ua, &auth()).is_err());
        assert!(decrypt(&body, &ua, &[0; 16]).is_err());
        assert!(decrypt(&body, &SecretKey::try_generate().unwrap(), &auth()).is_err());
    }
}
