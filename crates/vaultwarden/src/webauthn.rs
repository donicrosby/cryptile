// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! CTAP2 hardware security-key leg for the provider-7 two-factor challenge.
//!
//! Wire contract pinned by `tests/fixtures/CAPTURES.md` and the live-verified
//! `integration/webauthn_gauntlet.py` (harness VW 1.37.2): the assertion blob
//! mimics the web vault connector exactly — lowercase response keys
//! (`authenticatorData` / `clientDataJson` / `signature`), unpadded
//! base64url, no `userHandle`, `id == rawId == b64url(credential id)`, empty
//! `extensions`. The upstream crate's serde spelling (`clientDataJSON`,
//! mixed padding) does not match, so the token JSON is assembled by hand
//! from the CTAP2 result.
//!
//! No soft tokens by policy (openspec add-two-factor-login): `usb` + `nfc`
//! transport features only — a hardware root of trust is the whole point.
//! Device I/O is exercised by the manual runbook, not CI; everything below
//! the ceremony is pure and unit-tested.

use secrecy::SecretString;
use webauthn_authenticator_rs::prelude::{RequestChallengeResponse, Url};
use webauthn_authenticator_rs::transport::Transport;
use webauthn_authenticator_rs::WebauthnAuthenticator;

/// Timeout handed to the device ceremony. The crate clamps above 60s.
const CEREMONY_TIMEOUT_MS: u32 = 60_000;

/// Decoded provider-7 challenge inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnChallenge {
    /// Base64url challenge string as served by the server.
    pub challenge_b64: String,
    /// RP ID the credential must have been registered under.
    pub rp_id: String,
    /// Allowed credential ids (base64url strings as served).
    pub allow_credential_ids: Vec<String>,
}

/// Errors from challenge decoding and the device ceremony. All map onto the
/// AUTH class (exit 3) upstream.
#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("no USB/NFC security key found; connect a CTAP2 hardware key and retry")]
    NoDevice,
    #[error("security key ceremony failed or timed out: {0}")]
    Device(String),
    #[error("webauthn challenge malformed: {0}")]
    Challenge(String),
}

/// Decode the provider-7 entry out of a full two-factor challenge body
/// (`TwoFactorProviders2`, either key casing). Missing fields fail typed,
/// never panic (spec: malformed challenge fails with a remediation hint).
pub(crate) fn challenge_from_body(body: &str) -> Result<WebauthnChallenge, WebauthnError> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| WebauthnError::Challenge(format!("body is not JSON: {e}")))?;
    let providers2 = ["TwoFactorProviders2", "twoFactorProviders2"]
        .iter()
        .find_map(|k| v.get(k))
        .ok_or_else(|| WebauthnError::Challenge("body lacks TwoFactorProviders2".into()))?;
    let entry = providers2.get("7").ok_or_else(|| {
        WebauthnError::Challenge("server challenge offers no provider-7 (webauthn) entry".into())
    })?;
    let get_str = |k: &str| entry.get(k).and_then(|x| x.as_str()).map(String::from);
    let challenge_b64 = get_str("challenge")
        .ok_or_else(|| WebauthnError::Challenge("provider-7 entry lacks 'challenge'".into()))?;
    let rp_id = get_str("rpId")
        .ok_or_else(|| WebauthnError::Challenge("provider-7 entry lacks 'rpId'".into()))?;
    let allow_credential_ids: Vec<String> = entry
        .get("allowCredentials")
        .and_then(|x| x.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|c| c.get("id").and_then(|i| i.as_str()).map(String::from))
                .collect()
        })
        .ok_or_else(|| {
            WebauthnError::Challenge("provider-7 entry lacks 'allowCredentials'".into())
        })?;
    if allow_credential_ids.is_empty() {
        return Err(WebauthnError::Challenge(
            "provider-7 allowCredentials is empty; no credential can answer".into(),
        ));
    }
    Ok(WebauthnChallenge {
        challenge_b64,
        rp_id,
        allow_credential_ids,
    })
}

/// Derive the browser origin the credential was registered under from the
/// RP ID: `https://<rp-id>`, except loopback/dev hosts where the harness
/// registers keys under plain http (CAPTURES.md: origin must match the RP).
pub(crate) fn origin_for_rp_id(rp_id: &str) -> Option<String> {
    let host = rp_id.trim();
    if host.is_empty() || host.contains('/') {
        return None;
    }
    let loopback = host == "localhost"
        || host.starts_with("127.")
        || host.starts_with("[::1]")
        || host == "::1";
    let scheme = if loopback { "http" } else { "https" };
    Some(format!("{scheme}://{host}"))
}

fn b64url_nopad(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, tolerating `=` padding (VW serves padded challenge and
/// credential ids; the gauntlet had to add padding before decoding).
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    let unpadded = s.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(unpadded)
}

/// Assemble the web-vault-connector token JSON from a CTAP2 assertion,
/// per the live-verified shape in `integration/webauthn_gauntlet.py`:
/// lowercase response keys, unpadded base64url, no `userHandle`,
/// `id == rawId == b64url(credential id)`.
pub(crate) fn fido2_response_json(
    cred: &webauthn_authenticator_rs::prelude::PublicKeyCredential,
) -> Result<String, WebauthnError> {
    let id = b64url_nopad(cred.raw_id.as_ref());
    serde_json::to_string(&serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": b64url_nopad(cred.response.authenticator_data.as_ref()),
            "clientDataJson": b64url_nopad(cred.response.client_data_json.as_ref()),
            "signature": b64url_nopad(cred.response.signature.as_ref()),
        },
    }))
    .map_err(|e| WebauthnError::Challenge(format!("assertion serialization: {e}")))
}

/// Build the crate's request options from the decoded challenge. Routed
/// through `serde_json` because [`RequestChallengeResponse`] is exactly the
/// struct the ceremony consumes and the wire shape is the documented one.
fn request_options(ch: &WebauthnChallenge) -> Result<RequestChallengeResponse, WebauthnError> {
    let challenge_bytes = b64url_decode(&ch.challenge_b64)
        .map_err(|e| WebauthnError::Challenge(format!("challenge is not base64url: {e}")))?;
    let allow: Vec<serde_json::Value> = ch
        .allow_credential_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "type": "public-key",
                "id": id,
            })
        })
        .collect();
    let opts = serde_json::json!({
        "publicKey": {
            "challenge": b64url_nopad(&challenge_bytes),
            "rpId": ch.rp_id,
            "timeout": CEREMONY_TIMEOUT_MS,
            "userVerification": "discouraged",
            "allowCredentials": allow,
        }
    });
    serde_json::from_value(opts).map_err(|e| {
        WebauthnError::Challenge(format!(
            "challenge does not fit the CTAP2 request shape: {e}"
        ))
    })
}

/// Run the CTAP2 getAssertion ceremony over USB (and NFC where a reader is
/// present) and return the `twoFactorToken` blob. Blocking device I/O:
/// callers invoke via `spawn_blocking`. Inside, a dedicated single-thread
/// runtime hosts the async transports — this function runs on a blocking
/// pool thread with no ambient tokio context.
pub fn perform_assertion(ch: &WebauthnChallenge) -> Result<SecretString, WebauthnError> {
    let origin = Url::parse(
        &origin_for_rp_id(&ch.rp_id)
            .ok_or_else(|| WebauthnError::Challenge(format!("unusable rpId '{}'", ch.rp_id)))?,
    )
    .map_err(|e| WebauthnError::Challenge(format!("origin for rpId: {e}")))?;
    let options = request_options(ch)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| WebauthnError::Device(format!("device runtime: {e}")))?;
    let cred = rt.block_on(async {
        let ui = webauthn_authenticator_rs::ui::Cli {};
        let transport = webauthn_authenticator_rs::transport::AnyTransport::new()
            .await
            .map_err(|e| WebauthnError::Device(format!("no transport: {e}")))?;
        let tokens = transport
            .tokens()
            .await
            .map_err(|e| WebauthnError::Device(format!("device enumeration: {e}")))?;
        for token in tokens {
            if let Some(auth) =
                webauthn_authenticator_rs::ctap2::CtapAuthenticator::new(token, &ui).await
            {
                let mut wan = WebauthnAuthenticator::new(auth);
                return wan
                    .do_authentication(origin, options)
                    .map_err(|e| WebauthnError::Device(format!("{e:?}")));
            }
        }
        Err(WebauthnError::NoDevice)
    })?;
    Ok(SecretString::from(fido2_response_json(&cred)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shape observed live on harness VW 1.37.2 (webauthn_gauntlet.py login leg).
    const CHALLENGE_BODY: &str = r#"{
        "error": "invalid_grant",
        "error_description": "Two factor required.",
        "TwoFactorProviders": ["7"],
        "TwoFactorProviders2": {
            "7": {
                "challenge": "Rk9PQmFy",
                "rpId": "localhost",
                "allowCredentials": [{"id": "Y3JlZC1pZA", "type": "public-key"}],
                "timeout": 60000,
                "userVerification": "discouraged"
            }
        }
    }"#;

    #[test]
    fn challenge_decodes_from_body() {
        let ch = challenge_from_body(CHALLENGE_BODY).expect("decodes");
        assert_eq!(ch.challenge_b64, "Rk9PQmFy");
        assert_eq!(ch.rp_id, "localhost");
        assert_eq!(ch.allow_credential_ids, vec!["Y3JlZC1pZA".to_string()]);
    }

    #[test]
    fn challenge_lower_casing_decodes() {
        let body = CHALLENGE_BODY.replace("TwoFactorProviders2", "twoFactorProviders2");
        assert!(challenge_from_body(&body).is_ok());
    }

    #[test]
    fn malformed_challenges_fail_typed() {
        // No provider-7 entry.
        assert!(matches!(
            challenge_from_body(r#"{"TwoFactorProviders2":{"0":null}}"#),
            Err(WebauthnError::Challenge(_))
        ));
        // Missing challenge field.
        let no_chal =
            r#"{"TwoFactorProviders2":{"7":{"rpId":"x","allowCredentials":[{"id":"a"}]}}}"#;
        assert!(matches!(
            challenge_from_body(no_chal),
            Err(WebauthnError::Challenge(_))
        ));
        // Empty allowCredentials.
        let no_allow =
            r#"{"TwoFactorProviders2":{"7":{"challenge":"a","rpId":"x","allowCredentials":[]}}}"#;
        assert!(matches!(
            challenge_from_body(no_allow),
            Err(WebauthnError::Challenge(_))
        ));
        // Not JSON at all.
        assert!(matches!(
            challenge_from_body("nope"),
            Err(WebauthnError::Challenge(_))
        ));
    }

    #[test]
    fn origin_matches_harness_rp_ids() {
        assert_eq!(
            origin_for_rp_id("localhost").as_deref(),
            Some("http://localhost")
        );
        assert_eq!(
            origin_for_rp_id("127.0.0.1").as_deref(),
            Some("http://127.0.0.1")
        );
        assert_eq!(
            origin_for_rp_id("bw.jeansburger.net").as_deref(),
            Some("https://bw.jeansburger.net")
        );
        assert_eq!(origin_for_rp_id(""), None);
        assert_eq!(origin_for_rp_id("bad/host"), None);
    }

    #[test]
    fn fido2_response_matches_gauntlet_shape() {
        // A PublicKeyCredential as the crate itself would produce, fed back
        // through serde so the test does not depend on type constructors.
        let cred: webauthn_authenticator_rs::prelude::PublicKeyCredential =
            serde_json::from_value(serde_json::json!({
                "id": "Y3JlZC1pZA",
                "rawId": "Y3JlZC1pZA",
                "type": "public-key",
                "extensions": {},
                "response": {
                    "authenticatorData": "YXV0aERhdGE",
                    "clientDataJSON": "Y2xpZW50RGF0YQ",
                    "signature": "c2ln",
                    "userHandle": null
                }
            }))
            .expect("credential decodes");
        let tok = fido2_response_json(&cred).expect("serializes");
        let v: serde_json::Value = serde_json::from_str(&tok).expect("json");
        assert_eq!(v["id"], v["rawId"]);
        assert_eq!(v["id"], "Y3JlZC1pZA");
        assert_eq!(v["type"], "public-key");
        assert_eq!(v["extensions"], serde_json::json!({}));
        // Lowercase-J wire keys, unpadded b64url — NOT the crate serde spelling.
        assert!(v["response"]["clientDataJson"].is_string());
        assert!(v["response"]["clientDataJSON"].is_null());
        assert_eq!(v["response"]["authenticatorData"], "YXV0aERhdGE");
        assert_eq!(v["response"]["signature"], "c2ln");
        assert!(v.get("userHandle").is_none());
        let tok_str = v["response"]["clientDataJson"].as_str().unwrap();
        assert!(!tok_str.contains('='));
    }

    #[test]
    fn request_options_fit_the_ceremony_input() {
        let ch = challenge_from_body(CHALLENGE_BODY).expect("decodes");
        let rcr = request_options(&ch).expect("fits");
        assert_eq!(rcr.public_key.rp_id, "localhost");
        assert_eq!(rcr.public_key.allow_credentials.len(), 1);
        assert_eq!(rcr.public_key.challenge.as_slice(), b"FOOBar");
        // `discouraged` is the CTAP2-authentication default; assert via serde
        // spelling rather than the DO_NOT_USE variant name.
        let uv = serde_json::to_value(rcr.public_key.user_verification).unwrap();
        assert_eq!(uv, serde_json::json!("discouraged"));
    }

    #[test]
    fn b64url_decode_tolerates_padding() {
        assert_eq!(b64url_decode("Y3JlZC1pZA==").unwrap(), b"cred-id");
        assert_eq!(b64url_decode("Y3JlZC1pZA").unwrap(), b"cred-id");
        assert_eq!(b64url_decode("Rk9PQmFy").unwrap(), b"FOOBar");
    }
}
