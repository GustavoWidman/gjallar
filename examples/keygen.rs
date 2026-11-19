//! Makes a VAPID key pair. The private key goes to stdout, so it can be piped straight
//! into a secret store without landing on the screen; the public key, which the page
//! passes to `pushManager.subscribe()`, goes to stderr.
//!
//! ```text
//! cargo run --example keygen > vapid.key
//! ```

fn main() -> Result<(), gjallar::Error> {
    let key = gjallar::VapidKey::generate()?;
    println!("{}", key.to_base64url());
    eprintln!("public key (applicationServerKey): {}", key.public_key());
    Ok(())
}
