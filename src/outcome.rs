use std::time::{Duration, SystemTime};

use http::header::RETRY_AFTER;
use http::{HeaderMap, Response, StatusCode};

/// What a push service's answer means for the message and the subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Accepted (201, or any other 2xx). The push service holds the message until the
    /// browser comes online or the `TTL` runs out; it says nothing about display.
    Delivered,
    /// The subscription no longer exists (404 or 410): the user unsubscribed, the
    /// browser dropped it, or it expired. Delete it, and never send to it again.
    Gone {
        /// 404 or 410.
        status: StatusCode,
    },
    /// The push service refused this request (400, 401, 403, 413 and any other
    /// answer not listed here). Sending it again unchanged gets the same answer: it is
    /// a bug, a bad key, or a subscription made under another VAPID key.
    Refused {
        /// The status code.
        status: StatusCode,
        /// The service's own reason, when its body gives one: Apple's `reason`
        /// (`BadJwtToken`, `VapidPkHashMismatch`, `PayloadTooLarge`, …), Mozilla's
        /// `message`, or the start of a plain-text body.
        reason: Option<String>,
    },
    /// The push service is overloaded or failing (429, 408 or 5xx). Send again later,
    /// no sooner than `after` when the service said.
    RetryLater {
        /// The status code.
        status: StatusCode,
        /// The wait the `Retry-After` header asked for, in seconds or as a date.
        after: Option<Duration>,
    },
}

/// The longest refusal reason kept from a plain-text body.
const MAX_REASON: usize = 200;

impl Outcome {
    /// Classifies a push service's answer from its status, headers and body. The body
    /// is only read for a refusal's reason; pass an empty slice when it was not read.
    ///
    /// ```
    /// use gjallar::Outcome;
    /// use http::{HeaderMap, StatusCode};
    ///
    /// let outcome = Outcome::classify(StatusCode::FORBIDDEN, &HeaderMap::new(), br#"{"reason":"VapidPkHashMismatch"}"#);
    /// assert_eq!(outcome, Outcome::Refused {
    ///     status: StatusCode::FORBIDDEN,
    ///     reason: Some("VapidPkHashMismatch".into()),
    /// });
    /// ```
    pub fn classify(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Self {
        Self::classify_at(status, headers, body, SystemTime::now())
    }

    /// Classifies a whole response whose body has been read into memory.
    pub fn from_response<B: AsRef<[u8]>>(response: &Response<B>) -> Self {
        Self::classify(
            response.status(),
            response.headers(),
            response.body().as_ref(),
        )
    }

    pub(crate) fn classify_at(
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
        now: SystemTime,
    ) -> Self {
        match status.as_u16() {
            200..=299 => Self::Delivered,
            404 | 410 => Self::Gone { status },
            408 | 429 | 500..=599 => Self::RetryLater {
                status,
                after: retry_after(headers, now),
            },
            _ => Self::Refused {
                status,
                reason: reason(body),
            },
        }
    }

    /// Whether the push service accepted the message.
    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered)
    }

    /// Whether the subscription is gone for good and should be deleted.
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Gone { .. })
    }
}

fn retry_after(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(now).unwrap_or_default())
}

fn reason(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
        // Apple: {"reason": "..."}. Mozilla: {"code", "errno", "error", "message"}.
        // Google APIs: {"error": {"message": "..."}}.
        let found = [
            &json["reason"],
            &json["message"],
            &json["error"]["message"],
            &json["error"],
        ]
        .into_iter()
        .find_map(|value| value.as_str());
        if let Some(found) = found {
            return Some(found.to_owned());
        }
    }
    Some(match text.char_indices().nth(MAX_REASON) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use http::HeaderValue;

    use super::*;

    fn classify(status: u16, retry: Option<&str>, body: &str) -> Outcome {
        let mut headers = HeaderMap::new();
        if let Some(retry) = retry {
            headers.insert(RETRY_AFTER, HeaderValue::from_str(retry).unwrap());
        }
        let now = UNIX_EPOCH + Duration::from_secs(1_445_412_480); // Wed, 21 Oct 2015 07:28:00 GMT
        Outcome::classify_at(
            StatusCode::from_u16(status).unwrap(),
            &headers,
            body.as_bytes(),
            now,
        )
    }

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    #[test]
    fn delivered_for_every_success() {
        for code in [200, 201, 202, 204] {
            assert_eq!(classify(code, None, ""), Outcome::Delivered, "{code}");
        }
    }

    #[test]
    fn gone_for_404_and_410() {
        for code in [404, 410] {
            let outcome = classify(code, None, r#"{"reason":"Unregistered"}"#);
            assert_eq!(
                outcome,
                Outcome::Gone {
                    status: status(code)
                }
            );
            assert!(outcome.is_gone());
        }
    }

    #[test]
    fn retry_later_for_overload_and_server_errors() {
        for code in [408, 429, 500, 502, 503, 504] {
            assert_eq!(
                classify(code, None, ""),
                Outcome::RetryLater {
                    status: status(code),
                    after: None
                },
                "{code}"
            );
        }
        assert_eq!(
            classify(429, Some("120"), ""),
            Outcome::RetryLater {
                status: status(429),
                after: Some(Duration::from_secs(120))
            }
        );
        assert_eq!(
            classify(503, Some("Wed, 21 Oct 2015 07:30:00 GMT"), ""),
            Outcome::RetryLater {
                status: status(503),
                after: Some(Duration::from_secs(120))
            }
        );
        assert_eq!(
            classify(503, Some("Wed, 21 Oct 2015 07:00:00 GMT"), ""),
            Outcome::RetryLater {
                status: status(503),
                after: Some(Duration::ZERO)
            }
        );
        assert_eq!(
            classify(429, Some("soon"), ""),
            Outcome::RetryLater {
                status: status(429),
                after: None
            }
        );
    }

    #[test]
    fn refused_with_the_service_reason() {
        let cases = [
            (403, r#"{"reason":"BadJwtToken"}"#, Some("BadJwtToken")),
            (
                413,
                r#"{"reason":"PayloadTooLarge"}"#,
                Some("PayloadTooLarge"),
            ),
            (
                400,
                r#"{"code":400,"errno":110,"error":"Bad Request","message":"Missing TTL header"}"#,
                Some("Missing TTL header"),
            ),
            (
                400,
                r#"{"error":{"code":400,"message":"Invalid TTL"}}"#,
                Some("Invalid TTL"),
            ),
            (401, r#"{"error":"Unauthorized"}"#, Some("Unauthorized")),
            (
                403,
                "the key in the authorization header does not correspond to the sender ID\n",
                Some("the key in the authorization header does not correspond to the sender ID"),
            ),
            (400, "[1, 2]", Some("[1, 2]")),
            (400, "", None),
            (400, "  \n", None),
            (301, "", None),
        ];
        for (code, body, reason) in cases {
            assert_eq!(
                classify(code, None, body),
                Outcome::Refused {
                    status: status(code),
                    reason: reason.map(str::to_owned)
                },
                "{code} {body}"
            );
        }
    }

    #[test]
    fn trims_long_reasons_and_ignores_binary_bodies() {
        let long = "é".repeat(500);
        let Outcome::Refused {
            reason: Some(reason),
            ..
        } = classify(400, None, &long)
        else {
            panic!("expected a refusal with a reason");
        };
        assert_eq!(reason.chars().count(), MAX_REASON + 1);
        let binary = Outcome::classify(StatusCode::BAD_REQUEST, &HeaderMap::new(), &[0xff, 0xfe]);
        assert_eq!(
            binary,
            Outcome::Refused {
                status: StatusCode::BAD_REQUEST,
                reason: None
            }
        );
    }

    #[test]
    fn classifies_a_response() {
        let response = Response::builder()
            .status(201)
            .body(Vec::<u8>::new())
            .unwrap();
        assert!(Outcome::from_response(&response).is_delivered());
    }
}
