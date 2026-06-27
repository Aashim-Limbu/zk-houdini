use crate::x402::{SettleResponse, VerifyResponse};
use anyhow::{anyhow, Result};

pub struct Facilitator {
    base: String,
    api_key: String,
    http: reqwest::Client,
}

impl Facilitator {
    pub fn new(base: String, api_key: String) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), api_key, http: reqwest::Client::new() }
    }

    fn body(payload: &serde_json::Value, requirements: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "x402Version": 2,
            "paymentPayload": payload,
            "paymentRequirements": requirements,
        })
    }

    pub async fn verify(&self, payload: &serde_json::Value, requirements: &serde_json::Value) -> Result<VerifyResponse> {
        let res = self.http
            .post(format!("{}/verify", self.base))
            .bearer_auth(&self.api_key)
            .json(&Self::body(payload, requirements))
            .send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("facilitator /verify HTTP {}: {}", res.status(), res.text().await.unwrap_or_default()));
        }
        Ok(res.json::<VerifyResponse>().await?)
    }

    pub async fn settle(&self, payload: &serde_json::Value, requirements: &serde_json::Value) -> Result<SettleResponse> {
        let res = self.http
            .post(format!("{}/settle", self.base))
            .bearer_auth(&self.api_key)
            .json(&Self::body(payload, requirements))
            .send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("facilitator /settle HTTP {}: {}", res.status(), res.text().await.unwrap_or_default()));
        }
        Ok(res.json::<SettleResponse>().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn verify_posts_bearer_and_parses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .and(header("authorization", "Bearer testkey"))
            .and(body_partial_json(serde_json::json!({ "x402Version": 2 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "isValid": true, "payer": "GBUYER"
            })))
            .mount(&server)
            .await;

        let fac = Facilitator::new(server.uri(), "testkey".into());
        let payload = serde_json::json!({"x402Version":2,"payload":{"transaction":"AAAA"}});
        let reqs = serde_json::json!({"scheme":"exact"});
        let v = fac.verify(&payload, &reqs).await.unwrap();
        assert!(v.is_valid);
        assert_eq!(v.payer.as_deref(), Some("GBUYER"));
    }

    #[tokio::test]
    async fn settle_parses_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "transaction": "abc123", "network": "stellar:testnet", "payer": "GBUYER"
            })))
            .mount(&server)
            .await;
        let fac = Facilitator::new(server.uri(), "k".into());
        let s = fac.settle(&serde_json::json!({}), &serde_json::json!({})).await.unwrap();
        assert!(s.success);
        assert_eq!(s.transaction, "abc123");
    }
}
