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
//! No soft tokens by policy (openspec add-two-factor-login,
//! add-fidoh-ceremony-provider): hardware transports only — a hardware root
//! of trust is the whole point. Device I/O is exercised by the manual
//! runbook, not CI; everything below the ceremony is pure and unit-tested.
//!
//! Two ceremony backends live behind this one wire contract:
//!
//! - `feature = "webauthn"`: the legacy `webauthn-authenticator-rs` path,
//!   byte-identical in stage 1.
//! - `feature = "fidoh"` (stage 1 of add-fidoh-ceremony-provider): the
//!   fidoh-backed path — cryptile keeps challenge decode, RP ID/origin
//!   derivation, clientDataJSON assembly, and VW wire assembly; fidoh owns
//!   device selection, transport, keepalives, and touch, inside ONE
//!   caller-supplied budget (its single-Deadline model — no hop can wait
//!   past it, so the ceremony cannot hang; there is no outer timeout wrap
//!   because none is needed). When both features are on, the fidoh path is
//!   authoritative.

#[cfg(any(feature = "webauthn", feature = "fidoh"))]
mod shared {
    /// Decoded provider-7 challenge inputs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WebauthnChallenge {
        /// Base64url challenge string as served by the server.
        pub challenge_b64: String,
        /// RP ID the credential must have been registered under.
        pub rp_id: String,
        /// Allowed credential ids (base64url strings as served).
        pub allow_credential_ids: Vec<String>,
        /// Server-requested user-verification posture
        /// (`userVerification` on the provider-7 entry; absent →
        /// [`UvPosture::Discouraged`]). Consumed by the fidoh path; the
        /// legacy path keeps its hardcoded posture until stage 2.
        pub uv: UvPosture,
    }

    /// Server-requested user-verification posture from the provider-7
    /// challenge entry (add-fidoh-uv-passthrough). The wire value is one
    /// of `discouraged` | `preferred` | `required` (WebAuthn L3
    /// §5.4.6); `required` and `preferred` both mean "ask the key to
    /// verify the user" at the CTAP2 getAssertion layer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UvPosture {
        /// Omitted or `"discouraged"`: do not ask the key to verify.
        Discouraged,
        /// `"preferred"` or `"required"`: ask the key to verify. fidoh
        /// degrades gracefully to the discouraged wire shape when the
        /// plugged key advertises no `uv` capability (its getInfo-probe
        /// contract, reported in the ceremony outcome); the full PIN
        /// flow arrives with fidoh beta.1's clientPIN work, not here.
        Preferred,
    }

    impl UvPosture {
        /// Wire spelling → posture. Case-insensitive: the value is a
        /// DOM string the server echoes, casing not contractual.
        /// Unknown spellings return None so the challenge decode can
        /// fail typed instead of inventing a policy the server did not
        /// ask for.
        pub fn from_wire(spelling: &str) -> Option<Self> {
            match spelling.to_ascii_lowercase().as_str() {
                "discouraged" => Some(Self::Discouraged),
                "preferred" | "required" => Some(Self::Preferred),
                _ => None,
            }
        }
    }

    /// Errors from challenge decoding and the device ceremony. The legacy
    /// path maps every variant onto the AUTH class (exit 3) upstream; the
    /// fidoh path carries the transport/server split itself (see
    /// [`FidohCeremonyError`]) and flattens onto the typed variants here.
    #[derive(Debug, thiserror::Error)]
    pub enum WebauthnError {
        /// No authenticator answered enumeration. The legacy path maps this
        /// to AUTH (historical behavior, unified in stage 2); the fidoh path
        /// maps no-device to Transport (design.md: a missing key is not a
        /// credentials problem).
        #[cfg(feature = "webauthn")]
        #[error("no USB/NFC security key found; connect a CTAP2 hardware key and retry")]
        NoDevice,
        #[error("security key ceremony failed or timed out: {0}")]
        Device(String),
        #[error("webauthn challenge malformed: {0}")]
        Challenge(String),
        /// fidoh-path device/transport failure: TRANSPORT class (exit 4),
        /// not AUTH — a missing, dead, or wedged key is not a credentials
        /// problem (add-fidoh-ceremony-provider design.md §error mapping).
        #[cfg(feature = "fidoh")]
        #[error("security key transport failed: {0}")]
        FidohTransport(String),
        /// fidoh-path internal (assembly) failure: SERVER class (exit 4).
        #[cfg(feature = "fidoh")]
        #[error("security key assertion failed internally: {0}")]
        FidohServer(String),
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
            WebauthnError::Challenge(
                "server challenge offers no provider-7 (webauthn) entry".into(),
            )
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
        // Server-requested user-verification posture (add-fidoh-uv-
        // passthrough): absent → discouraged; case-insensitive per the
        // wire spelling; unknown spellings fail typed. Only the fidoh
        // path consumes this today — the legacy path keeps its hardcoded
        // `discouraged` until stage 2 flips the default.
        let uv = match entry.get("userVerification").map(serde_json::Value::as_str) {
            Some(Some(spelling)) => UvPosture::from_wire(spelling).ok_or_else(|| {
                WebauthnError::Challenge(format!(
                    "provider-7 userVerification '{spelling}' is not one of \
                     discouraged|preferred|required"
                ))
            })?,
            Some(None) => {
                return Err(WebauthnError::Challenge(
                    "provider-7 userVerification is not a string".into(),
                ))
            }
            None => UvPosture::Discouraged,
        };
        Ok(WebauthnChallenge {
            challenge_b64,
            rp_id,
            allow_credential_ids,
            uv,
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

    pub(crate) fn b64url_nopad(bytes: &[u8]) -> String {
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
        raw_id: &[u8],
        auth_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<String, WebauthnError> {
        let id = b64url_nopad(raw_id);
        serde_json::to_string(&serde_json::json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": b64url_nopad(auth_data),
                "clientDataJson": b64url_nopad(client_data_json),
                "signature": b64url_nopad(signature),
            },
        }))
        .map_err(|e| WebauthnError::Challenge(format!("assertion serialization: {e}")))
    }
}

#[cfg(any(feature = "webauthn", feature = "fidoh"))]
#[cfg(test)]
use shared::{b64url_decode, fido2_response_json};
#[cfg(any(feature = "webauthn", feature = "fidoh"))]
pub(crate) use shared::{challenge_from_body, origin_for_rp_id};
#[cfg(any(feature = "webauthn", feature = "fidoh"))]
pub use shared::{UvPosture, WebauthnChallenge, WebauthnError};

// ------------------------------------------------------------------------
// The fidoh-backed ceremony (feature = "fidoh", stage 1 of
// add-fidoh-ceremony-provider). fidoh owns device selection, transport,
// keepalives, and touch; cryptile owns the WebAuthn context (clientDataJSON
// and its hash), the wire shape, and the ONE ceremony budget.
// ------------------------------------------------------------------------
#[cfg(feature = "fidoh")]
mod fidoh_backend {
    use std::time::Duration;

    use fidoh_core::device::{ChannelId, CtapCommand, Device, DeviceEvent};
    use fidoh_core::error::{CeremonyError, DiscoveryDiagnostic, Error};
    use fidoh_core::get_assertion::{CredentialType, PublicKeyCredentialDescriptor};
    use fidoh_core::pin::{PinProviderHandle, PinSourceError};
    use fidoh_core::sleep::SleepHandle;
    use fidoh_core::time::Deadline;
    use fidoh_core::transport::{
        apply_selection, CandidateDescriptor, DeviceInfo, SelectionPolicy, Transport,
    };
    use fidoh_core::{Ceremony, GetAssertionExchange, UvPolicy};
    use fidoh_tokio::TokioSleep;
    use fidoh_transport_hid::HidTransport;
    use fidoh_transport_pcsc::{library::PcscLibrary, PcscTransport};
    use secrecy::SecretString;
    use sha2::{Digest, Sha256};

    use super::shared::{
        b64url_decode, b64url_nopad, fido2_response_json, UvPosture, WebauthnChallenge,
        WebauthnError,
    };

    /// The ceremony budget handed to fidoh (its single ceremony Deadline:
    /// discovery, selection, connect, the getInfo probe, the §6.2 exchange,
    /// and every touch wait consume its remainder — no hop may wait past it,
    /// so total ceremony time is bounded by construction, not by an outer
    /// timeout wrap). 60 s mirrors the legacy path's `CEREMONY_TIMEOUT_MS`.
    pub(crate) const FIDOH_CEREMONY_BUDGET: Duration = Duration::from_secs(60);

    /// The budget in force, readable at the provider boundary: the same
    /// finite value bounds the ceremony thread's wait (a wedged ceremony
    /// surfaces typed Transport, never an indefinite join). Default is
    /// [`FIDOH_CEREMONY_BUDGET`]; tests may shrink it (debug builds only) to
    /// drive expiry quickly.
    pub(crate) fn ceremony_budget() -> Duration {
        #[cfg(debug_assertions)]
        {
            let ms = TEST_BUDGET_MILLIS.load(std::sync::atomic::Ordering::Relaxed);
            if ms != 0 {
                return Duration::from_millis(ms);
            }
        }
        FIDOH_CEREMONY_BUDGET
    }

    /// Test-only budget override (0 = the default budget). Debug builds
    /// only; never compiled into release. Public like the
    /// `with_assertion_hook` seam it composes with: the wiremock e2e suite
    /// (tests/, a separate crate) uses it to drive budget expiry.
    #[cfg(debug_assertions)]
    pub fn set_ceremony_budget_for_tests(budget: Duration) {
        TEST_BUDGET_MILLIS.store(
            u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    #[cfg(debug_assertions)]
    static TEST_BUDGET_MILLIS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// The UP_NEEDED keepalive status byte (CTAP2.1 §11.2.9.1.7): the
    /// authenticator is waiting for user presence.
    const UP_NEEDED: u8 = 0x02;

    /// Errors the fidoh path reports. The split is load-bearing: `Auth`
    /// variants surface as exit 3 (credentials or consent were wrong),
    /// `Transport` variants as exit 4 (device or transport), `Server` as
    /// exit 4 (internal failure). Pinned by design.md §error mapping; total
    /// over fidoh's typed ceremony errors.
    #[derive(Debug, thiserror::Error)]
    pub enum FidohCeremonyError {
        /// User declined, UP was rejected, or the PIN/UV consent failed.
        /// AUTH class: consent was refused on the key.
        #[error("security-key ceremony was declined on the device: {0}")]
        Declined(String),
        /// The plugged key holds no credential matching the server's
        /// allow-list. AUTH class: wrong key for this account.
        #[error("plugged key holds no credential this account registered (allow-list mismatch)")]
        WrongCredential,
        /// No device found on any transport. TRANSPORT class: nothing to
        /// talk to (design.md diverges from the legacy Auth mapping here).
        #[error("no USB/CCID security key found; connect a CTAP2 hardware key and retry: {0}")]
        NoDevice(String),
        /// Transport open/enumeration/I-O failure. TRANSPORT class.
        #[error("security key transport failed: {0}")]
        Transport(String),
        /// The single ceremony budget expired (wedged device, touch never
        /// given). TRANSPORT class, typed within the budget — never an
        /// indefinite hang.
        #[error(
            "security key ceremony budget expired during the {phase} phase; give the key a \
             fresh budget (at least {budget}s) and touch it when it blinks"
        )]
        BudgetExpired {
            /// The fidoh phase that was waiting when the budget ran out.
            phase: &'static str,
            /// The budget that was in force, in whole seconds.
            budget: u64,
        },
        /// Challenge/RP-ID/request-shape or wire-assembly failure inside
        /// cryptile. SERVER class: credentials and device state were not at
        /// fault.
        #[error("security key assertion failed internally: {0}")]
        Assembly(String),
    }

    impl FidohCeremonyError {
        /// Which exit-code class this error belongs to (`auth` | `transport`
        /// | `server`). Total over the variant set — no fidoh error can
        /// surface unclassified.
        pub fn exit_class(&self) -> &'static str {
            match self {
                Self::Declined(_) | Self::WrongCredential => "auth",
                Self::NoDevice(_) | Self::Transport(_) | Self::BudgetExpired { .. } => "transport",
                Self::Assembly(_) => "server",
            }
        }
    }

    impl From<FidohCeremonyError> for WebauthnError {
        fn from(e: FidohCeremonyError) -> Self {
            match e.exit_class() {
                "auth" => WebauthnError::Device(e.to_string()),
                "transport" => WebauthnError::FidohTransport(e.to_string()),
                _ => WebauthnError::FidohServer(e.to_string()),
            }
        }
    }

    /// Map fidoh's typed ceremony outcomes onto cryptile's classes. Total
    /// over `CeremonyError` — exhaustively matched so a new fidoh variant is
    /// a compile error here, not an unclassified string at runtime.
    pub(crate) fn map_ceremony_error(e: CeremonyError) -> FidohCeremonyError {
        match e {
            CeremonyError::NoDevice(diags) => FidohCeremonyError::NoDevice(render_diags(&diags)),
            CeremonyError::AmbiguousDevice(candidates) => FidohCeremonyError::Transport(format!(
                "several security keys are present ({candidates:?}); remove all but one and retry"
            )),
            CeremonyError::UserActionTimeout | CeremonyError::UpRejected => {
                FidohCeremonyError::Declined(e.to_string())
            }
            CeremonyError::UserCancelled => FidohCeremonyError::Declined(e.to_string()),
            CeremonyError::NoCredentials => FidohCeremonyError::WrongCredential,
            CeremonyError::Timeout(phase) => FidohCeremonyError::BudgetExpired {
                phase: phase.name(),
                budget: FIDOH_CEREMONY_BUDGET.as_secs(),
            },
            CeremonyError::Transport(te) => FidohCeremonyError::Transport(te.to_string()),
            CeremonyError::Ctap(status) => {
                let msg = status.to_string();
                match status {
                    fidoh_core::StatusCode::NoCredentials
                    | fidoh_core::StatusCode::InvalidCredential => {
                        FidohCeremonyError::WrongCredential
                    }
                    fidoh_core::StatusCode::UserActionTimeout
                    | fidoh_core::StatusCode::OperationDenied
                    | fidoh_core::StatusCode::UpRequired
                    | fidoh_core::StatusCode::PinAuthInvalid
                    | fidoh_core::StatusCode::PinAuthBlocked
                    | fidoh_core::StatusCode::PuatRequired
                    | fidoh_core::StatusCode::PinPolicyViolation
                    | fidoh_core::StatusCode::UvBlocked => FidohCeremonyError::Declined(msg),
                    other => FidohCeremonyError::Transport(format!(
                        "device rejected the request: {other}"
                    )),
                }
            }
            CeremonyError::CredentialMismatch { .. } => FidohCeremonyError::WrongCredential,
            // fidoh beta.1 clientPIN outcomes (add-fidoh-pin-provider):
            // user-side credential/consent state is AUTH, caller-side I/O
            // (the PIN source itself) is TRANSPORT.
            CeremonyError::PinRequired => FidohCeremonyError::Declined("the key requires its PIN to verify (PinRequired): set a key PIN or run interactively".to_string()),
            CeremonyError::PinNotSet => FidohCeremonyError::Declined("verification requires a PIN but the key has none set (PinNotSet): set a PIN on the key".to_string()),
            CeremonyError::PinTooLong => FidohCeremonyError::Declined("the provided PIN exceeds the authenticator's limit (PinTooLong)".to_string()),
            CeremonyError::IncorrectPin { remaining_retries } => {
                FidohCeremonyError::Declined(match remaining_retries {
                    Some(n) => format!("wrong key PIN: {n} attempt(s) remaining"),
                    None => format!("wrong key PIN: {e}"),
                })
            }
            CeremonyError::PinBlocked => FidohCeremonyError::Declined("key PIN retry counter exhausted (PinBlocked): unplug and replug the key to reset, then use the correct PIN".to_string()),
            CeremonyError::PinAuthBlocked => FidohCeremonyError::Declined("authenticator PIN is locked after repeated failures (PinAuthBlocked): reset the key before retrying".to_string()),
            CeremonyError::PinProviderFailed => FidohCeremonyError::Transport("the PIN source failed before the key could be asked (PinProviderFailed)".to_string()),
        }
    }

    fn render_diags(diags: &[DiscoveryDiagnostic]) -> String {
        if diags.is_empty() {
            String::from("no authenticator answered on any transport")
        } else {
            diags
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        }
    }

    /// Decode the challenge into fidoh's getAssertion request inputs:
    /// the raw challenge bytes and the allow-list descriptors. Fails typed
    /// (SERVER class upstream: the inputs came from the server wire, and
    /// wrong-bytes-here is an assembly problem, not a credentials one) on
    /// base64url garbage.
    pub(super) fn assertion_request(
        ch: &WebauthnChallenge,
    ) -> Result<(Vec<u8>, Vec<PublicKeyCredentialDescriptor>), FidohCeremonyError> {
        let challenge_bytes = b64url_decode(&ch.challenge_b64).map_err(|e| {
            FidohCeremonyError::Assembly(format!("challenge is not base64url: {e}"))
        })?;
        let allow: Vec<PublicKeyCredentialDescriptor> = ch
            .allow_credential_ids
            .iter()
            .map(|id| {
                Ok(PublicKeyCredentialDescriptor {
                    type_field: CredentialType::PublicKey,
                    id: b64url_decode(id).map_err(|e| {
                        FidohCeremonyError::Assembly(format!(
                            "allow-list credential id is not base64url: {e}"
                        ))
                    })?,
                    transports: None,
                })
            })
            .collect::<Result<_, FidohCeremonyError>>()?;
        Ok((challenge_bytes, allow))
    }

    /// Assemble the clientDataJSON the web-vault connector would send
    /// (byte-parity with the legacy path's `webauthn-authenticator-rs`
    /// serialization: this exact key order with `tokenBinding: null`), and
    /// hash it. fidoh receives ONLY the hash — clientDataJSON assembly stays
    /// cryptile's job (design.md §seam).
    pub(super) fn client_data_json(origin: &str, challenge_b64: &str) -> (Vec<u8>, Vec<u8>) {
        let json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_b64}\",\"origin\":\"{origin}\",\"tokenBinding\":null}}"
        );
        let hash = Sha256::digest(json.as_bytes()).to_vec();
        (hash, json.into_bytes())
    }

    /// The §6.2 exchange. `allow_credentials: None` would mean resident-key
    /// discovery; the server always pins the allow-list. The
    /// user-verification posture is the server's request
    /// (add-fidoh-uv-passthrough): discouraged → omit `options.uv`;
    /// preferred/required → `UvPolicy::Preferred`, which fidoh degrades
    /// to the discouraged wire shape when the plugged key advertises no
    /// `uv` capability (its getInfo-probe contract, reported in the
    /// ceremony outcome). No PIN acquisition here — that is fidoh
    /// beta.1's clientPIN work.
    fn exchange(
        rp_id: &str,
        client_data_hash: Vec<u8>,
        allow: Vec<PublicKeyCredentialDescriptor>,
        uv: UvPosture,
        pin_provider: Option<PinProviderHandle>,
    ) -> GetAssertionExchange {
        GetAssertionExchange {
            rp_id: rp_id.to_string(),
            client_data_hash,
            allow_credentials: Some(allow),
            user_verification: match uv {
                UvPosture::Discouraged => UvPolicy::Discouraged,
                UvPosture::Preferred => UvPolicy::Preferred,
            },
            pin_uv_auth: None,
            drain: None,
            entropy: None,
            pin_provider,
            pin_uv_auth_protocol: None,
        }
    }

    /// Keepalive UX: forwards everything unchanged, prints a touch prompt on
    /// the FIRST UP_NEEDED only (display-level dedup, the pattern fidoh's
    /// own CLI documents as the keepalive UX seam).
    struct TouchPrompt<D> {
        inner: D,
        prompted: bool,
    }

    impl<D: Device + Send + 'static> Device for TouchPrompt<D> {
        async fn send(
            &mut self,
            cmd: &CtapCommand,
            deadline: &Deadline,
            sleep: SleepHandle<'_>,
        ) -> Result<DeviceEvent, Error> {
            let event = self.inner.send(cmd, deadline, sleep).await;
            if let Ok(DeviceEvent::Keepalive { status }) = &event {
                if *status == UP_NEEDED && !self.prompted {
                    self.prompted = true;
                    eprintln!("touch your security key to approve the sign-in…");
                }
            }
            event
        }

        async fn open_channel(
            &mut self,
            deadline: &Deadline,
            sleep: SleepHandle<'_>,
        ) -> Result<ChannelId, Error> {
            self.inner.open_channel(deadline, sleep).await
        }

        async fn close(self) -> Result<(), Error> {
            self.inner.close().await
        }
    }

    /// Probe → §6.2 exchange over an already-connected device, inside the
    /// shared budget. Generic over the connected device: each transport arm
    /// instantiates it with its concrete type (fidoh's `Device` trait is not
    /// dyn-safe by design; its own CLI dispatches the same way).
    async fn run_ceremony<D: Device + Send + 'static>(
        device: D,
        xch: GetAssertionExchange,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<fidoh_core::GetAssertionOutcome, CeremonyError> {
        xch.run(
            TouchPrompt {
                inner: device,
                prompted: false,
            },
            deadline,
            sleep,
        )
        .await
    }

    /// Enumerate both hardware transports. A failing transport is a
    /// diagnostic (D2: collect, never short-circuit); pcscd being down must
    /// not hide a USB key.
    async fn discover(
        hid: &HidTransport,
        pcsc: Option<&PcscTransport<PcscLibrary>>,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> (Vec<DeviceInfo>, Vec<DiscoveryDiagnostic>) {
        let mut candidates = Vec::new();
        let mut diagnostics = Vec::new();
        match hid.enumerate(deadline, sleep).await {
            Ok(found) => candidates.extend(found),
            Err(e) => diagnostics.push(DiscoveryDiagnostic::new(
                fidoh_core::transport::TransportKind::Hid,
                e,
            )),
        }
        match pcsc {
            Some(t) => match t.enumerate(deadline, sleep).await {
                Ok(found) => candidates.extend(found),
                Err(e) => diagnostics.push(DiscoveryDiagnostic::new(
                    fidoh_core::transport::TransportKind::Pcsc,
                    e,
                )),
            },
            None => diagnostics.push(DiscoveryDiagnostic::new(
                fidoh_core::transport::TransportKind::Pcsc,
                Error::Transport(fidoh_core::TransportError::new(
                    "pcsc",
                    String::from("PC/SC context unavailable (is pcscd running?)"),
                )),
            )),
        }
        (candidates, diagnostics)
    }

    /// The typed fidoh-backed ceremony entry: keeps fidoh's outcome split
    /// (auth/transport/server) so the provider can surface the right
    /// exit-code class without string matching. Blocking device I/O: the
    /// provider invokes it on a dedicated thread, bounded by
    /// [`ceremony_budget`].
    pub fn fidoh_perform_assertion(
        ch: &WebauthnChallenge,
        pin_source: Option<cryptile_core::provider::PinSource>,
    ) -> Result<SecretString, FidohCeremonyError> {
        let origin = super::origin_for_rp_id(&ch.rp_id)
            .ok_or_else(|| FidohCeremonyError::Assembly(format!("unusable rpId '{}'", ch.rp_id)))?;
        let (challenge_bytes, allow) = assertion_request(ch)?;
        let (client_data_hash, client_data_json_bytes) =
            client_data_json(&origin, &b64url_nopad(&challenge_bytes));
        // Backend-neutral closure → fidoh's provider handle (the wrap is
        // the feature boundary: this is the only place the two shapes
        // meet). The closure is lazy — fidoh invokes it only when
        // clientPIN acquisition demands a PIN.
        let pin_provider = pin_source.map(|mut src| {
            PinProviderHandle::from_closure(move || {
                src().map_err(|()| PinSourceError { _context: () })
            })
        });
        let xch = exchange(&ch.rp_id, client_data_hash, allow, ch.uv, pin_provider);

        // One budget for the whole ceremony (fidoh's single-Deadline model):
        // discovery, selection, connect, the probe, and the §6.2 exchange
        // each consume the remainder; no hop may wait longer than what
        // remains.
        let deadline = Deadline::new(ceremony_budget());
        let sleep = TokioSleep;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| FidohCeremonyError::Transport(format!("device runtime: {e}")))?;

        let first = rt
            .block_on(async {
                // The real PC/SC context, or None when pcscd is down (diagnostic,
                // never a mask for the USB transport).
                let pcsc = PcscLibrary::establish().ok().map(PcscTransport::new);

                // Discovery → explicit deterministic selection. `First` is the
                // deliberate opt-in: a headless agent should not hard-fail
                // because two keys are plugged in; the server's allow-list makes
                // the wrong key answer `NoCredentials` (typed AUTH), never a
                // silent success.
                let (candidates, diagnostics) = discover(
                    &HidTransport::new(),
                    pcsc.as_ref(),
                    &deadline,
                    sleep.handle(),
                )
                .await;
                let descriptors: Vec<CandidateDescriptor> =
                    candidates.iter().map(|info| info.descriptor()).collect();
                let selected = apply_selection(&SelectionPolicy::First, &descriptors)
                    .map_err(CeremonyError::from_core)
                    .and_then(|s| s.ok_or(CeremonyError::NoDevice(Vec::new())))
                    .map_err(|e| match e {
                        // Enrich the no-device error with the per-transport
                        // diagnostics (why pcsc/hid found nothing).
                        CeremonyError::NoDevice(_) => CeremonyError::NoDevice(diagnostics.clone()),
                        other => other,
                    })?;

                // fidoh has no kind accessor on `DeviceId`; its own CLI
                // discriminates by the HID id prefix ("/dev/hidrawN").
                if selected.id.as_str().starts_with("/dev/") {
                    let hid = HidTransport::new();
                    let dev = hid
                        .connect(&selected.id, &deadline, sleep.handle())
                        .await
                        .map_err(CeremonyError::from_core)?;
                    run_ceremony(
                        TouchPrompt {
                            inner: dev,
                            prompted: false,
                        },
                        xch,
                        &deadline,
                        sleep.handle(),
                    )
                    .await
                } else {
                    let Some(t) = pcsc else {
                        return Err(CeremonyError::NoDevice(diagnostics));
                    };
                    let dev = t
                        .connect(&selected.id, &deadline, sleep.handle())
                        .await
                        .map_err(CeremonyError::from_core)?;
                    run_ceremony(
                        TouchPrompt {
                            inner: dev,
                            prompted: false,
                        },
                        xch,
                        &deadline,
                        sleep.handle(),
                    )
                    .await
                }
            })
            .map_err(map_ceremony_error)?;

        let assertion = first.first();
        let blob = fido2_response_json(
            &assertion.credential.id,
            &assertion.auth_data,
            &client_data_json_bytes,
            &assertion.signature,
        )
        .map_err(|e| FidohCeremonyError::Assembly(e.to_string()))?;
        Ok(SecretString::from(blob))
    }
}

#[cfg(feature = "fidoh")]
pub(crate) use fidoh_backend::ceremony_budget;
#[cfg(all(feature = "fidoh", debug_assertions))]
pub use fidoh_backend::set_ceremony_budget_for_tests;
#[cfg(feature = "fidoh")]
pub use fidoh_backend::{fidoh_perform_assertion, FidohCeremonyError};

#[cfg(feature = "webauthn")]
pub use legacy::perform_assertion;

// ------------------------------------------------------------------------
// The legacy ceremony (feature = "webauthn"): byte-identical in stage 1.
// ------------------------------------------------------------------------
#[cfg(feature = "webauthn")]
mod legacy {
    use secrecy::SecretString;
    use webauthn_authenticator_rs::prelude::{RequestChallengeResponse, Url};
    use webauthn_authenticator_rs::transport::Transport;
    use webauthn_authenticator_rs::WebauthnAuthenticator;

    use super::shared::{
        b64url_decode, b64url_nopad, fido2_response_json, WebauthnChallenge, WebauthnError,
    };

    /// Timeout handed to the device ceremony. The crate clamps above 60s.
    pub(crate) const CEREMONY_TIMEOUT_MS: u32 = 60_000;

    /// Build the crate's request options from the decoded challenge. Routed
    /// through `serde_json` because [`RequestChallengeResponse`] is exactly the
    /// struct the ceremony consumes and the wire shape is the documented one.
    pub(super) fn request_options(
        ch: &WebauthnChallenge,
    ) -> Result<RequestChallengeResponse, WebauthnError> {
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
        let origin =
            Url::parse(&super::origin_for_rp_id(&ch.rp_id).ok_or_else(|| {
                WebauthnError::Challenge(format!("unusable rpId '{}'", ch.rp_id))
            })?)
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
        Ok(SecretString::from(fido2_response_json(
            cred.raw_id.as_ref(),
            cred.response.authenticator_data.as_ref(),
            cred.response.client_data_json.as_ref(),
            cred.response.signature.as_ref(),
        )?))
    }
}

#[cfg(any(feature = "webauthn", feature = "fidoh"))]
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
        // The exact components a CTAP2 assertion carries, fed through the
        // assembler both ceremony paths share.
        let tok = fido2_response_json(b"cred-id", b"authData", b"clientData", b"sig")
            .expect("serializes");
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
    fn b64url_decode_tolerates_padding() {
        assert_eq!(b64url_decode("Y3JlZC1pZA==").unwrap(), b"cred-id");
        assert_eq!(b64url_decode("Y3JlZC1pZA").unwrap(), b"cred-id");
        assert_eq!(b64url_decode("Rk9PQmFy").unwrap(), b"FOOBar");
    }

    // add-fidoh-uv-passthrough: the provider-7 entry's userVerification
    // rides on the decoded challenge (consumed by the fidoh exchange).

    #[test]
    fn challenge_uv_preferred_and_required_decode_to_preferred() {
        for spelling in ["preferred", "required", "PREFERRED", "Required"] {
            let body = format!(
                r#"{{"TwoFactorProviders2":{{"7":{{"challenge":"Rk9PQmFy","rpId":"localhost","allowCredentials":[{{"id":"Y3JlZC1pZA"}}],"userVerification":"{spelling}"}}}}}}"#
            );
            let ch = challenge_from_body(&body).expect("decodes");
            assert_eq!(ch.uv, UvPosture::Preferred, "spelling {spelling:?}");
        }
    }

    #[test]
    fn challenge_uv_absent_and_discouraged_decode_to_discouraged() {
        // Absent: the pre-change default.
        let absent = challenge_from_body(
            r#"{"TwoFactorProviders2":{"7":{"challenge":"Rk9PQmFy","rpId":"localhost","allowCredentials":[{"id":"Y3JlZC1pZA"}]}}}"#,
        )
        .expect("decodes");
        assert_eq!(absent.uv, UvPosture::Discouraged);
        // Explicit discouraged + the live-capture shape (CHALLENGE_BODY).
        let explicit = challenge_from_body(
            r#"{"TwoFactorProviders2":{"7":{"challenge":"Rk9PQmFy","rpId":"localhost","allowCredentials":[{"id":"Y3JlZC1pZA"}],"userVerification":"discouraged"}}}"#,
        )
        .expect("decodes");
        assert_eq!(explicit.uv, UvPosture::Discouraged);
        let captured = challenge_from_body(CHALLENGE_BODY).expect("decodes");
        assert_eq!(captured.uv, UvPosture::Discouraged);
    }

    #[test]
    fn challenge_uv_unknown_or_non_string_fails_typed() {
        let unknown = r#"{"TwoFactorProviders2":{"7":{"challenge":"a","rpId":"x","allowCredentials":[{"id":"a"}],"userVerification":"maybe"}}}"#;
        assert!(matches!(
            challenge_from_body(unknown),
            Err(WebauthnError::Challenge(_))
        ));
        let non_string = r#"{"TwoFactorProviders2":{"7":{"challenge":"a","rpId":"x","allowCredentials":[{"id":"a"}],"userVerification":1}}}"#;
        assert!(matches!(
            challenge_from_body(non_string),
            Err(WebauthnError::Challenge(_))
        ));
    }

    #[test]
    fn uv_posture_wire_mapping() {
        assert_eq!(
            UvPosture::from_wire("discouraged"),
            Some(UvPosture::Discouraged)
        );
        assert_eq!(
            UvPosture::from_wire("preferred"),
            Some(UvPosture::Preferred)
        );
        assert_eq!(UvPosture::from_wire("required"), Some(UvPosture::Preferred));
        assert_eq!(
            UvPosture::from_wire("Discouraged"),
            Some(UvPosture::Discouraged)
        );
        assert_eq!(UvPosture::from_wire(""), None);
        assert_eq!(UvPosture::from_wire("always"), None);
    }
}

#[cfg(feature = "webauthn")]
#[cfg(test)]
mod legacy_tests {
    use super::*;

    #[test]
    fn request_options_fit_the_ceremony_input() {
        let ch = challenge_from_body(
            r#"{"TwoFactorProviders2":{"7":{"challenge":"Rk9PQmFy","rpId":"localhost","allowCredentials":[{"id":"Y3JlZC1pZA","type":"public-key"}]}}}"#,
        )
        .expect("decodes");
        let rcr = legacy::request_options(&ch).expect("fits");
        assert_eq!(rcr.public_key.rp_id, "localhost");
        assert_eq!(rcr.public_key.allow_credentials.len(), 1);
        assert_eq!(rcr.public_key.challenge.as_slice(), b"FOOBar");
        // `discouraged` is the CTAP2-authentication default; assert via serde
        // spelling rather than the DO_NOT_USE variant name.
        let uv = serde_json::to_value(rcr.public_key.user_verification).unwrap();
        assert_eq!(uv, serde_json::json!("discouraged"));
    }
}

#[cfg(feature = "fidoh")]
#[cfg(test)]
mod fidoh_tests {
    use super::*;

    #[test]
    fn error_mapping_is_total_and_classed() {
        use fidoh_backend::FidohCeremonyError as E;
        // Auth class.
        assert_eq!(E::Declined("x".into()).exit_class(), "auth");
        assert_eq!(E::WrongCredential.exit_class(), "auth");
        // Transport class.
        assert_eq!(E::NoDevice("x".into()).exit_class(), "transport");
        assert_eq!(E::Transport("x".into()).exit_class(), "transport");
        assert_eq!(
            E::BudgetExpired {
                phase: "user-presence",
                budget: 60
            }
            .exit_class(),
            "transport"
        );
        // Server class.
        assert_eq!(E::Assembly("x".into()).exit_class(), "server");
        // fidoh beta.1 clientPIN outcomes (add-fidoh-pin-provider): the
        // user-side PIN state is AUTH, the caller-side PIN source is
        // TRANSPORT. Class-level lock on every new variant.
        assert_eq!(E::Declined("PinRequired".into()).exit_class(), "auth");
        assert_eq!(
            E::Declined("PinNotSet: set a PIN on the key".into()).exit_class(),
            "auth"
        );
        assert_eq!(
            E::Transport("PinProviderFailed".into()).exit_class(),
            "transport"
        );
    }

    /// The full beta.1 PIN-class mapping, asserted over the real fidoh
    /// `CeremonyError` variants through `map_ceremony_error` — the
    /// totality lock add-fidoh-pin-provider pins in spec.
    #[test]
    fn pin_error_mapping_classes() {
        use fidoh_core::error::CeremonyError as CE;
        let class_of = |e: CE| {
            crate::webauthn::fidoh_backend::map_ceremony_error(e)
                .exit_class()
                .to_string()
        };
        // User-side credential/consent state → AUTH.
        assert_eq!(class_of(CE::PinRequired), "auth");
        assert_eq!(class_of(CE::PinNotSet), "auth");
        assert_eq!(class_of(CE::PinTooLong), "auth");
        assert_eq!(
            class_of(CE::IncorrectPin {
                remaining_retries: Some(2)
            }),
            "auth"
        );
        assert_eq!(class_of(CE::PinBlocked), "auth");
        assert_eq!(class_of(CE::PinAuthBlocked), "auth");
        // Caller-side I/O (the PIN source itself) → TRANSPORT.
        assert_eq!(class_of(CE::PinProviderFailed), "transport");
    }

    #[test]
    fn fidoh_errors_flatten_with_their_class_intact() {
        use fidoh_backend::FidohCeremonyError as E;
        // Decline flattens onto the AUTH-class Device variant.
        assert!(matches!(
            WebauthnError::from(E::Declined("no".into())),
            WebauthnError::Device(_)
        ));
        // Budget expiry flattons onto the typed TRANSPORT variant.
        assert!(matches!(
            WebauthnError::from(E::BudgetExpired {
                phase: "user-presence",
                budget: 60
            }),
            WebauthnError::FidohTransport(_)
        ));
        // Assembly failure flattens onto the typed SERVER variant.
        assert!(matches!(
            WebauthnError::from(E::Assembly("bad".into())),
            WebauthnError::FidohServer(_)
        ));
    }

    #[test]
    fn client_data_json_is_byte_parity_with_the_legacy_crate() {
        use fidoh_backend::{client_data_json as fidoh_cdj, FIDOH_CEREMONY_BUDGET};
        // The legacy path's clientDataJSON, reconstructed byte-for-byte from
        // webauthn-authenticator-rs 0.5.5 (webauthn_rs_proto
        // CollectedClientData serde: type, challenge, origin, tokenBinding
        // always null; crossOrigin skipped). The challenge is the server's
        // b64url string as served.
        let (hash, json) = fidoh_cdj("http://localhost", "Rk9PQmFy");
        let s = String::from_utf8(json).unwrap();
        assert_eq!(
            s,
            r#"{"type":"webauthn.get","challenge":"Rk9PQmFy","origin":"http://localhost","tokenBinding":null}"#
        );
        // The hash is what fidoh signs over: SHA-256 of exactly those bytes.
        use sha2::{Digest, Sha256};
        let expect: Vec<u8> = Sha256::digest(s.as_bytes()).to_vec();
        assert_eq!(hash, expect);
        // The budget is finite and mirrors the legacy timeout.
        assert_eq!(FIDOH_CEREMONY_BUDGET.as_secs(), 60);
    }

    #[test]
    fn assertion_request_decodes_the_challenge_and_allow_list() {
        let ch = challenge_from_body(
            r#"{"TwoFactorProviders2":{"7":{"challenge":"Rk9PQmFy","rpId":"localhost","allowCredentials":[{"id":"Y3JlZC1pZA","type":"public-key"}]}}}"#,
        )
        .expect("decodes");
        let (challenge_bytes, allow) = fidoh_backend::assertion_request(&ch).expect("decodes");
        assert_eq!(challenge_bytes, b"FOOBar".to_vec());
        assert_eq!(allow.len(), 1);
        assert_eq!(allow[0].id, b"cred-id".to_vec());
        assert_eq!(
            allow[0].type_field,
            fidoh_core::get_assertion::CredentialType::PublicKey
        );
    }
}
