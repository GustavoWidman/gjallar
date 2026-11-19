//! The HTTP-client-free core, end to end: the browser's subscription JSON in, a
//! request a push service accepts out.

mod common;

use std::time::Duration;

use gjallar::{
    Message, Notification, Outcome, Receiver, Subscription, Topic, Urgency, VapidKey, WebPush,
};

#[test]
fn a_browser_subscription_gets_a_request_it_can_decrypt() {
    let receiver = Receiver::generate().unwrap();
    // round-trip through JSON, as a subscription stored by the server would
    let stored = serde_json::to_string(
        &receiver
            .subscription("https://updates.push.services.mozilla.com/wpush/v2/gAAAA")
            .unwrap(),
    )
    .unwrap();
    let subscription: Subscription = serde_json::from_str(&stored).unwrap();

    let key = VapidKey::generate().unwrap();
    let push = WebPush::new(key.clone(), "mailto:ops@example.com").unwrap();
    let message = Message::declarative(
        Notification::new("Build 42 failed", "https://ci.example.com/builds/42")
            .body("3 tests failed"),
    )
    .unwrap()
    .ttl(Duration::from_secs(600))
    .urgency(Urgency::High)
    .topic(Topic::digest("build/42"));
    let request = push.request(&subscription, &message).unwrap();

    assert_eq!(
        request.uri(),
        "https://updates.push.services.mozilla.com/wpush/v2/gAAAA"
    );
    let headers = request.headers();
    assert_eq!(headers["ttl"], "600");
    assert_eq!(headers["urgency"], "high");
    assert_eq!(headers["topic"], Topic::digest("build/42").as_str());
    assert_eq!(headers["content-encoding"], "aes128gcm");
    let claims = common::check_vapid(
        headers["authorization"].to_str().unwrap(),
        "https://updates.push.services.mozilla.com",
        &key.public_key(),
    );
    assert_eq!(claims["sub"], "mailto:ops@example.com");

    let payload: serde_json::Value =
        serde_json::from_slice(&receiver.decrypt(request.body()).unwrap()).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({
            "web_push": 8030,
            "notification": {"title": "Build 42 failed", "navigate": "https://ci.example.com/builds/42", "body": "3 tests failed"}
        })
    );
}

#[test]
fn one_token_serves_every_request_to_a_push_service() {
    let push = WebPush::new(VapidKey::generate().unwrap(), "https://example.com").unwrap();
    let authorization = |endpoint: &str| {
        let subscription = Receiver::generate()
            .unwrap()
            .subscription(endpoint)
            .unwrap();
        let request = push.request(&subscription, &Message::empty()).unwrap();
        request.headers()["authorization"].clone()
    };
    let first = authorization("https://web.push.apple.com/a");
    assert_eq!(authorization("https://web.push.apple.com/b"), first);
    assert_ne!(
        authorization("https://fcm.googleapis.com/fcm/send/c"),
        first
    );
}

#[test]
fn an_answer_classifies_from_the_response() {
    let response = gjallar::http::Response::builder()
        .status(410)
        .body(b"push subscription has unsubscribed or expired.".to_vec())
        .unwrap();
    assert!(Outcome::from_response(&response).is_gone());
}
