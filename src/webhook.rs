//! Settlement webhooks: `POST <callback_url>` with the [`PaymentStatus`] JSON body and
//! `X-Buyback-Signature: sha256=<hex hmac of body>`. Failed deliveries are retried every 30 s.

use crate::state::PaymentStatus;
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub struct Webhook {
    secret: Zeroizing<Vec<u8>>,
    http: reqwest::Client,
}

impl Webhook {
    pub fn new(secret: Vec<u8>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        Self {
            secret: Zeroizing::new(secret),
            http,
        }
    }

    /// `sha256=<hex>` signature of `body`.
    pub fn sign(&self, body: &[u8]) -> String {
        sign(&self.secret, body)
    }

    pub async fn post(&self, url: &str, status: &PaymentStatus) -> Result<()> {
        let body = serde_json::to_vec(status).map_err(|e| Error::Config(e.to_string()))?;
        let resp = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("x-buyback-signature", self.sign(&body))
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Chain(format!("webhook: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Chain(format!("webhook returned {}", resp.status())));
        }
        Ok(())
    }
}

/// `sha256=<hex hmac-sha256(secret, body)>`. Receivers recompute and compare in constant time.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc4231_case_2() {
        assert_eq!(
            super::sign(b"Jefe", b"what do ya want for nothing?"),
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
