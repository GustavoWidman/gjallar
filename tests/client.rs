//! The blocking client against a fake push service on loopback, which decrypts every
//! message with its subscription's keys and checks its VAPID header the way a real
//! one would.

#![cfg(feature = "client")]

mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gjallar::http::StatusCode;
use gjallar::{Client, Error, Message, Outcome, Receiver, Subscription, VapidKey, WebPush};

struct Received {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// A push service that answers by path: `/ok` 201, `/gone` 410, `/busy` 429 the first
/// time and 201 after, `/refused` 403 with Apple's reason, `/slow` never in time.
struct FakePushService {
    origin: String,
    received: Arc<Mutex<Vec<Received>>>,
}

impl FakePushService {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&received);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let log = Arc::clone(&log);
                thread::spawn(move || answer(stream.unwrap(), &log));
            }
        });
        Self { origin, received }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    fn received(&self, path: &str) -> Vec<Received> {
        let mut log = self.received.lock().unwrap();
        let (matching, rest) = log.drain(..).partition(|r: &Received| r.path == path);
        *log = rest;
        matching
    }
}

fn answer(stream: TcpStream, log: &Mutex<Vec<Received>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let path = line.split_whitespace().nth(1).unwrap().to_owned();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .map_or(0, |l| l.parse().unwrap());
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();

    let seen_before = log.lock().unwrap().iter().any(|r| r.path == path);
    log.lock().unwrap().push(Received {
        path: path.clone(),
        headers,
        body,
    });
    let (status, extra, body) = match path.as_str() {
        "/ok" => ("201 Created", "", ""),
        "/gone" => ("410 Gone", "", ""),
        "/busy" if !seen_before => ("429 Too Many Requests", "Retry-After: 1\r\n", ""),
        "/busy" => ("201 Created", "", ""),
        "/refused" => (
            "403 Forbidden",
            "Content-Type: application/json\r\n",
            r#"{"reason":"VapidPkHashMismatch"}"#,
        ),
        "/slow" => {
            thread::sleep(Duration::from_secs(5));
            ("201 Created", "", "")
        }
        _ => ("404 Not Found", "", ""),
    };
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

struct Browser {
    receiver: Receiver,
    subscription: Subscription,
}

fn browser(service: &FakePushService, path: &str) -> Browser {
    let receiver = Receiver::generate().unwrap();
    let subscription = receiver.subscription(&service.endpoint(path)).unwrap();
    Browser {
        receiver,
        subscription,
    }
}

/// What a push service checks on arrival: the VAPID header and the encryption.
fn check(
    service: &FakePushService,
    key: &VapidKey,
    browser: &Browser,
    request: &Received,
    payload: &[u8],
) {
    common::check_vapid(
        &request.headers["authorization"],
        &service.origin,
        &key.public_key(),
    );
    assert_eq!(request.headers["ttl"], "3600");
    assert_eq!(request.headers["content-encoding"], "aes128gcm");
    assert!(request.headers["user-agent"].starts_with("gjallar/"));
    assert_eq!(browser.receiver.decrypt(&request.body).unwrap(), payload);
}

#[test]
fn sends_to_every_subscription_and_classifies_each_answer() {
    let service = FakePushService::start();
    let key = VapidKey::generate().unwrap();
    let client = Client::new(WebPush::new(key.clone(), "mailto:ops@example.com").unwrap());
    let browsers: Vec<Browser> = ["/ok", "/gone", "/busy", "/refused"]
        .into_iter()
        .map(|path| browser(&service, path))
        .collect();
    let payload =
        br#"{"web_push":8030,"notification":{"title":"hi","navigate":"https://example.com/"}}"#;
    let message = Message::new(payload.as_slice())
        .unwrap()
        .ttl(Duration::from_secs(3600));

    let results = client.send_all(browsers.iter().map(|b| &b.subscription), &message);

    let outcomes: Vec<Outcome> = results.into_iter().map(Result::unwrap).collect();
    assert_eq!(
        outcomes,
        [
            Outcome::Delivered,
            Outcome::Gone {
                status: StatusCode::GONE
            },
            Outcome::Delivered,
            Outcome::Refused {
                status: StatusCode::FORBIDDEN,
                reason: Some("VapidPkHashMismatch".to_owned()),
            },
        ]
    );
    for (browser, path, attempts) in [
        (&browsers[0], "/ok", 1),
        (&browsers[1], "/gone", 1),
        (&browsers[2], "/busy", 2),
        (&browsers[3], "/refused", 1),
    ] {
        let received = service.received(path);
        assert_eq!(received.len(), attempts, "{path}");
        for request in &received {
            check(&service, &key, browser, request, payload);
        }
    }
}

#[test]
fn reports_retry_later_when_retries_run_out() {
    let service = FakePushService::start();
    let client =
        Client::new(WebPush::new(VapidKey::generate().unwrap(), "https://example.com").unwrap())
            .retries(0);
    let busy = browser(&service, "/busy");
    let outcome = client
        .send(&busy.subscription, &Message::new("x").unwrap())
        .unwrap();
    assert_eq!(
        outcome,
        Outcome::RetryLater {
            status: StatusCode::TOO_MANY_REQUESTS,
            after: Some(Duration::from_secs(1)),
        }
    );
}

#[test]
fn keeps_to_the_deadline() {
    let service = FakePushService::start();
    let client =
        Client::new(WebPush::new(VapidKey::generate().unwrap(), "https://example.com").unwrap())
            .timeout(Duration::from_millis(300))
            .deadline(Duration::from_millis(800));
    let slow = browser(&service, "/slow");
    let ok = browser(&service, "/ok");

    let started = Instant::now();
    let results = client.send_all(
        [&slow.subscription, &ok.subscription],
        &Message::new("x").unwrap(),
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    assert!(
        matches!(results[0], Err(Error::Transport(_))),
        "{:?}",
        results[0]
    );
    assert_eq!(*results[1].as_ref().unwrap(), Outcome::Delivered);
}

#[test]
fn reports_an_unreachable_push_service() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let subscription = Receiver::generate()
        .unwrap()
        .subscription(&format!("http://127.0.0.1:{port}/nobody"))
        .unwrap();
    let client =
        Client::new(WebPush::new(VapidKey::generate().unwrap(), "https://example.com").unwrap())
            .retries(0);
    let error = client.send(&subscription, &Message::empty()).unwrap_err();
    assert!(matches!(error, Error::Transport(_)), "{error}");
}
