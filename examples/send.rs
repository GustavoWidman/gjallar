//! Sends one notification to the subscriptions in a JSON file, then reports what each
//! push service said.
//!
//! ```text
//! GJALLAR_VAPID_KEY=$(cat vapid.key) cargo run --example send --features client -- \
//!     mailto:you@example.com subscriptions.json "Hello" https://example.com/
//! ```
//!
//! The file holds one `PushSubscription.toJSON()` object, or an array of them.

use std::error::Error;
use std::time::Duration;

use gjallar::{Client, Message, Notification, Outcome, Subscription, Urgency, VapidKey, WebPush};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [subject, file, title, navigate] = args.as_slice() else {
        return Err("usage: send <subject> <subscriptions.json> <title> <url>".into());
    };
    let key: VapidKey = std::env::var("GJALLAR_VAPID_KEY")
        .map_err(|_| "set GJALLAR_VAPID_KEY to the private key keygen printed")?
        .parse()?;

    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
    let subscriptions: Vec<Subscription> = match json {
        serde_json::Value::Array(_) => serde_json::from_value(json)?,
        single => vec![serde_json::from_value(single)?],
    };

    let client = Client::new(WebPush::new(key, subject)?);
    let message = Message::declarative(Notification::new(title.as_str(), navigate.as_str()))?
        .ttl(Duration::from_secs(24 * 3600))
        .urgency(Urgency::Normal);

    for (subscription, result) in subscriptions
        .iter()
        .zip(client.send_all(&subscriptions, &message))
    {
        let origin = subscription.origin();
        match result {
            Ok(Outcome::Delivered) => println!("{origin}: delivered"),
            Ok(Outcome::Gone { status }) => println!("{origin}: gone ({status}), remove it"),
            Ok(Outcome::Refused { status, reason }) => {
                println!(
                    "{origin}: refused ({status}): {}",
                    reason.as_deref().unwrap_or("no reason given")
                )
            }
            Ok(Outcome::RetryLater { status, after }) => {
                println!("{origin}: busy ({status}), retry after {after:?}")
            }
            Ok(other) => println!("{origin}: {other:?}"),
            Err(error) => println!("{origin}: {error}"),
        }
    }
    Ok(())
}
