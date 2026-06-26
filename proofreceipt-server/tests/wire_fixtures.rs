//! Round-trip tests: real x402 v2 wire bytes (captured by `proofreceipt-buyer/scripts/capture.mjs`)
//! deserialize correctly into the Rust structs used by the audit server.
//!
//! Fixtures live in tests/fixtures/ and are committed alongside this file.
//! Run with: `cargo test --test wire_fixtures`

use proofreceipt_server::x402::{PaymentPayload, VerifyResponse};

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {name}: {e}"))
}

/// Real PAYMENT-SIGNATURE payload produced by `@x402/stellar` ExactStellarScheme.
/// Verifies that the top-level x402Version, accepted (PaymentRequirements), and
/// payload (scheme-specific data) fields all deserialize without data loss.
#[test]
fn payment_payload_deserializes() {
    let json = fixture("payment_payload.json");
    let p: PaymentPayload = serde_json::from_str(&json)
        .expect("PaymentPayload should deserialize from real x402 v2 wire bytes");

    assert_eq!(p.x402_version, 2, "x402Version must be 2 (x402 v2 wire)");

    // `accepted` carries the PaymentRequirements object
    assert!(p.accepted.is_object(), "accepted must be a JSON object");
    assert_eq!(
        p.accepted["scheme"], "exact",
        "accepted.scheme must be 'exact' (the Stellar exact scheme)"
    );
    assert_eq!(
        p.accepted["network"], "stellar:testnet",
        "accepted.network must identify the Stellar testnet"
    );

    // `payload` carries scheme-specific data (Stellar XDR transaction)
    assert!(p.payload.is_object(), "payload must be a JSON object");
    assert!(
        p.payload["transaction"].is_string(),
        "payload.transaction must be a base64-encoded Stellar XDR string"
    );
    let xdr = p.payload["transaction"].as_str().unwrap();
    assert!(!xdr.is_empty(), "payload.transaction must not be empty");
}

/// Real `/verify` response from the OZ Channels facilitator for an intentionally
/// malformed transaction XDR. Verifies that the `isValid`/`invalidReason`/`payer`
/// fields deserialize with correct Rust field names and Option handling.
#[test]
fn verify_invalid_deserializes() {
    let json = fixture("verify_invalid.json");
    let v: VerifyResponse = serde_json::from_str(&json)
        .expect("VerifyResponse should deserialize from real /verify response");

    assert!(!v.is_valid, "isValid must be false for an intentionally invalid payment");
    assert!(
        v.invalid_reason.is_some(),
        "invalidReason must be present when isValid=false"
    );
    let reason = v.invalid_reason.as_deref().unwrap();
    assert!(!reason.is_empty(), "invalidReason must not be empty");
    // payer is absent in the invalid response — Option<String> must be None
    assert!(
        v.payer.is_none(),
        "payer must be None (absent) when the payment is invalid"
    );
}
