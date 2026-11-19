use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::{Error, Message, Outcome, Subscription, WebPush};

/// A blocking client that sends push messages with `ureq` over rustls, retries what the
/// push service asks to have retried, and keeps every send inside a time budget.
///
/// It owns a [`WebPush`] and a connection pool; keep one for the life of the process.
/// It is `Send + Sync`, so threads can share it. From async code, call it on a
/// blocking thread (`tokio::task::spawn_blocking`), or use [`WebPush::request`] with
/// your async client instead.
///
/// ```no_run
/// use std::time::Duration;
/// use gjallar::{Client, Message, Subscription, VapidKey, WebPush};
///
/// # fn main() -> Result<(), gjallar::Error> {
/// # let (key, subscriptions): (VapidKey, Vec<Subscription>) = (VapidKey::generate()?, vec![]);
/// let client = Client::new(WebPush::new(key, "https://example.com")?)
///     .deadline(Duration::from_secs(10));
/// let message = Message::new("{\"kind\":\"sync\"}")?;
/// for (subscription, result) in subscriptions.iter().zip(client.send_all(&subscriptions, &message)) {
///     match result {
///         Ok(outcome) if outcome.is_gone() => { /* delete `subscription` */ }
///         Ok(outcome) => println!("{}: {outcome:?}", subscription.origin()),
///         Err(error) => eprintln!("{}: {error}", subscription.origin()),
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct Client {
    push: WebPush,
    agent: ureq::Agent,
    timeout: Duration,
    deadline: Duration,
    retries: u32,
    concurrency: usize,
}

/// The wait before retrying a request that failed without saying when to retry.
const RETRY_WAIT: Duration = Duration::from_secs(1);
/// The most of an answer's body read, for a refusal's reason.
const MAX_BODY: u64 = 64 * 1024;

impl Client {
    /// A client with the defaults: 10 seconds per request, 30 for a whole send, one
    /// retry, and up to 8 requests in flight.
    pub fn new(push: WebPush) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // a push endpoint answers itself; following a redirect would resend the
            // message somewhere the subscription never named
            .max_redirects(0)
            .max_redirects_will_error(false)
            .user_agent(concat!("gjallar/", env!("CARGO_PKG_VERSION")))
            .build()
            .new_agent();
        Self {
            push,
            agent,
            timeout: Duration::from_secs(10),
            deadline: Duration::from_secs(30),
            retries: 1,
            concurrency: 8,
        }
    }

    /// The longest one request may take, connecting and reading the answer included.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The longest a [`send`](Self::send) or [`send_all`](Self::send_all) call may take,
    /// retries and waits included. A request that would start after it is reported as
    /// [`Error::Deadline`], and a retry that would end after it is not made.
    #[must_use]
    pub fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// How many times to send again after a 429, 408 or 5xx answer, or a failed
    /// connection. Each retry waits for the `Retry-After` the service gave, or a second
    /// without one. One unless set.
    #[must_use]
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// The most requests [`send_all`](Self::send_all) keeps in flight at once, each on
    /// its own thread. At least 1.
    #[must_use]
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// The [`WebPush`] that signs and encrypts for this client.
    pub fn push(&self) -> &WebPush {
        &self.push
    }

    /// Sends one message to one subscription.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the push service could not be reached, even after
    /// retries, and [`Error::Deadline`] when the time budget ran out first. An answer
    /// from the push service, a refusal included, is an [`Outcome`], not an error.
    pub fn send(&self, subscription: &Subscription, message: &Message) -> Result<Outcome, Error> {
        self.deliver(subscription, message, Instant::now() + self.deadline)
    }

    /// Sends one message to every subscription, several at a time, and returns one
    /// result per subscription in the same order. The whole call takes at most the
    /// [`deadline`](Self::deadline).
    pub fn send_all<'a>(
        &self,
        subscriptions: impl IntoIterator<Item = &'a Subscription>,
        message: &Message,
    ) -> Vec<Result<Outcome, Error>> {
        let deadline = Instant::now() + self.deadline;
        let subscriptions: Vec<&Subscription> = subscriptions.into_iter().collect();
        let workers = self.concurrency.min(subscriptions.len());
        if workers <= 1 {
            return subscriptions
                .into_iter()
                .map(|subscription| self.deliver(subscription, message, deadline))
                .collect();
        }

        let next = AtomicUsize::new(0);
        let results: Vec<Mutex<Option<Result<Outcome, Error>>>> =
            subscriptions.iter().map(|_| Mutex::new(None)).collect();
        thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(subscription) = subscriptions.get(index) else {
                            break;
                        };
                        let result = self.deliver(subscription, message, deadline);
                        *results[index].lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
                    }
                });
            }
        });
        results
            .into_iter()
            .map(|slot| {
                slot.into_inner()
                    .unwrap_or_else(|e| e.into_inner())
                    .unwrap_or(Err(Error::Deadline))
            })
            .collect()
    }

    fn deliver(
        &self,
        subscription: &Subscription,
        message: &Message,
        deadline: Instant,
    ) -> Result<Outcome, Error> {
        let mut last = Err(Error::Deadline);
        for attempt in 0..=self.retries {
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
            else {
                break;
            };
            let result = self.attempt(subscription, message, remaining.min(self.timeout));
            let wait = match &result {
                Ok(Outcome::RetryLater { after, .. }) => after.unwrap_or(RETRY_WAIT),
                Err(Error::Transport(_)) => RETRY_WAIT,
                _ => return result,
            };
            last = result;
            if attempt == self.retries || Instant::now() + wait >= deadline {
                break;
            }
            thread::sleep(wait);
        }
        last
    }

    fn attempt(
        &self,
        subscription: &Subscription,
        message: &Message,
        timeout: Duration,
    ) -> Result<Outcome, Error> {
        let request = self.push.request(subscription, message)?;
        let request = self
            .agent
            .configure_request(request)
            .timeout_global(Some(timeout))
            .build();
        let mut response = self
            .agent
            .run(request)
            .map_err(|error| Error::Transport(Box::new(error)))?;
        // The body only matters for a refusal's reason, so one that fails to arrive is
        // classified as empty rather than turning an answer into an error.
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .unwrap_or_default();
        Ok(Outcome::classify(
            response.status(),
            response.headers(),
            &body,
        ))
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("push", &self.push)
            .field("timeout", &self.timeout)
            .field("deadline", &self.deadline)
            .field("retries", &self.retries)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}
