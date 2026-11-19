use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// A Declarative Web Push message, as the W3C Push API defines it:
/// `{"web_push": 8030, "notification": {…}}`.
///
/// A browser that supports it (Safari 18.4 and later on iOS and iPadOS, 18.5 on macOS)
/// shows the notification itself and opens its `navigate` URL on a tap, with no
/// service worker code, so the notification still shows when the service worker is
/// stale or gone. Other browsers hand the same JSON to the service worker's `push`
/// event, which shows it with `showNotification`.
///
/// Most messages need only a [`Notification`], which converts into this; build a
/// `Declarative` directly to set [`mutable`](Self::mutable).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Declarative {
    web_push: u16,
    notification: Notification,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    mutable: bool,
}

impl Declarative {
    /// Wraps a notification.
    pub fn new(notification: Notification) -> Self {
        Self {
            web_push: 8030,
            notification,
            mutable: false,
        }
    }

    /// Lets the service worker change the notification before it shows: the browser
    /// fires the `push` event first, and shows this notification only if the worker
    /// does not show one of its own.
    #[must_use]
    pub fn mutable(mut self, mutable: bool) -> Self {
        self.mutable = mutable;
        self
    }

    /// The JSON payload.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a declarative message is plain JSON")
    }
}

impl From<Notification> for Declarative {
    fn from(notification: Notification) -> Self {
        Self::new(notification)
    }
}

/// The notification a [`Declarative`] message shows. Its members are those of the
/// Notifications API's `NotificationOptions`, plus `navigate`, the URL a tap opens.
///
/// ```
/// use gjallar::{Action, Notification};
///
/// let notification = Notification::new("New reply", "https://forum.example.com/t/42#reply-7")
///     .body("ana: that fixed it, thanks")
///     .tag("thread-42")
///     .icon("https://forum.example.com/icon-192.png")
///     .action(Action::new("mute", "Mute thread", "https://forum.example.com/t/42/mute"));
/// ```
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    title: String,
    navigate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dir: Option<Dir>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    badge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    renotify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    silent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    require_interaction: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actions: Vec<Action>,
}

impl Notification {
    /// A notification with its two required members: the title, and the URL a tap
    /// opens. Browsers resolve `navigate` as a URL, so make it absolute.
    pub fn new(title: impl Into<String>, navigate: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            navigate: navigate.into(),
            body: None,
            tag: None,
            lang: None,
            dir: None,
            icon: None,
            image: None,
            badge: None,
            timestamp: None,
            renotify: None,
            silent: None,
            require_interaction: None,
            data: None,
            actions: Vec::new(),
        }
    }

    /// The text under the title.
    #[must_use]
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// A name that makes this notification replace an earlier one with the same tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// The language of the title and body, as a BCP 47 tag such as `en` or `pt-BR`.
    #[must_use]
    pub fn lang(mut self, lang: impl Into<String>) -> Self {
        self.lang = Some(lang.into());
        self
    }

    /// The direction of the title and body.
    #[must_use]
    pub fn dir(mut self, dir: Dir) -> Self {
        self.dir = Some(dir);
        self
    }

    /// The URL of an icon shown beside the text.
    #[must_use]
    pub fn icon(mut self, url: impl Into<String>) -> Self {
        self.icon = Some(url.into());
        self
    }

    /// The URL of a larger image shown in the notification.
    #[must_use]
    pub fn image(mut self, url: impl Into<String>) -> Self {
        self.image = Some(url.into());
        self
    }

    /// The URL of a small monochrome icon for the status bar.
    #[must_use]
    pub fn badge(mut self, url: impl Into<String>) -> Self {
        self.badge = Some(url.into());
        self
    }

    /// When the event the notification is about happened. Times before 1970 are sent
    /// as 0.
    #[must_use]
    pub fn timestamp(mut self, at: SystemTime) -> Self {
        let millis = at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        self.timestamp = Some(u64::try_from(millis).unwrap_or(u64::MAX));
        self
    }

    /// Alerts again when this notification replaces one with the same tag. Browsers
    /// ignore it on a notification without a tag.
    #[must_use]
    pub fn renotify(mut self, renotify: bool) -> Self {
        self.renotify = Some(renotify);
        self
    }

    /// Shows the notification without sound or vibration.
    #[must_use]
    pub fn silent(mut self, silent: bool) -> Self {
        self.silent = Some(silent);
        self
    }

    /// Keeps the notification on screen until the user acts on it, where the platform
    /// allows that.
    #[must_use]
    pub fn require_interaction(mut self, require: bool) -> Self {
        self.require_interaction = Some(require);
        self
    }

    /// Any JSON, readable as `notification.data` in the service worker.
    #[must_use]
    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Adds a button. Browsers show only as many as they support
    /// (`Notification.maxActions`).
    #[must_use]
    pub fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }
}

/// A button on a [`Notification`] that opens its own URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Action {
    action: String,
    title: String,
    navigate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
}

impl Action {
    /// A button with its identifier, its label, and the URL it opens.
    pub fn new(
        action: impl Into<String>,
        title: impl Into<String>,
        navigate: impl Into<String>,
    ) -> Self {
        Self {
            action: action.into(),
            title: title.into(),
            navigate: navigate.into(),
            icon: None,
        }
    }

    /// The URL of an icon for the button.
    #[must_use]
    pub fn icon(mut self, url: impl Into<String>) -> Self {
        self.icon = Some(url.into());
        self
    }
}

/// The text direction of a [`Notification`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    /// Follow the platform's direction.
    Auto,
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn json_of(message: impl Into<Declarative>) -> serde_json::Value {
        serde_json::from_slice(&message.into().to_json()).unwrap()
    }

    #[test]
    fn writes_only_the_required_members_by_default() {
        assert_eq!(
            json_of(Notification::new("Hi", "https://example.com/")),
            json!({"web_push": 8030, "notification": {"title": "Hi", "navigate": "https://example.com/"}})
        );
    }

    #[test]
    fn writes_every_member_with_its_spec_name() {
        let notification = Notification::new("Deployed", "https://example.com/d/1")
            .body("4 of 6")
            .tag("deploy/1")
            .lang("en")
            .dir(Dir::Ltr)
            .icon("https://example.com/i.png")
            .image("https://example.com/big.png")
            .badge("https://example.com/b.png")
            .timestamp(UNIX_EPOCH + Duration::from_millis(1_795_038_000_000))
            .renotify(true)
            .silent(false)
            .require_interaction(true)
            .data(json!({"id": 1}))
            .action(
                Action::new("open", "Open", "https://example.com/d/1")
                    .icon("https://example.com/o.png"),
            );
        assert_eq!(
            json_of(Declarative::new(notification).mutable(true)),
            json!({
                "web_push": 8030,
                "mutable": true,
                "notification": {
                    "title": "Deployed",
                    "navigate": "https://example.com/d/1",
                    "body": "4 of 6",
                    "tag": "deploy/1",
                    "lang": "en",
                    "dir": "ltr",
                    "icon": "https://example.com/i.png",
                    "image": "https://example.com/big.png",
                    "badge": "https://example.com/b.png",
                    "timestamp": 1_795_038_000_000u64,
                    "renotify": true,
                    "silent": false,
                    "requireInteraction": true,
                    "data": {"id": 1},
                    "actions": [{"action": "open", "title": "Open", "navigate": "https://example.com/d/1", "icon": "https://example.com/o.png"}]
                }
            })
        );
    }
}
