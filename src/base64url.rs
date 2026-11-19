use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url, with or without padding. The standard alphabet's `+` and `/` are
/// accepted too, since some subscription stores re-encode the browser's keys that way.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=');
    let text: String = text
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(text).ok()
}

pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode(text)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_every_spelling() {
        let bytes = [0xfb, 0xff, 0xbf];
        assert_eq!(encode(bytes), "-_-_");
        for text in ["-_-_", "+/+/", " -_-_\n"] {
            assert_eq!(decode(text).as_deref(), Some(&bytes[..]), "{text:?}");
        }
        assert_eq!(decode("AQ==").as_deref(), Some(&[1][..]));
        assert_eq!(decode("AQ").as_deref(), Some(&[1][..]));
        assert_eq!(decode("!!"), None);
        assert_eq!(decode_array::<2>("AQ"), None);
    }
}
