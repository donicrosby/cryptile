//! Provider ops with 4.5 refresh semantics: on AuthExpired, refresh once
//! via the session's refresh token and retry once. No loops, one hint.

use cryptile_core::provider::Provider;
use cryptile_core::{ExposeSecret, Namespace, Ref, Secret, SecretMeta, Session};

fn refresh_hint() -> String {
    "session expired and refresh failed; run `cryptile login` to re-establish".into()
}

fn map_retry(e: cryptile_core::ProviderError) -> String {
    if matches!(e, cryptile_core::ProviderError::AuthExpired) {
        refresh_hint()
    } else {
        e.to_string()
    }
}

/// Refresh margin: if the access token dies inside this window, rotate it
/// before issuing backend requests instead of eating a 401 round-trip.
const REFRESH_MARGIN_SECS: u64 = 300;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Proactive half of token lifecycle: if the backend reports an expiry
/// within the margin, rotate once up front. Failure here is non-fatal —
/// the reactive AuthExpired path in each op stays the single authority
/// for surfacing auth errors and the re-login remediation hint.
async fn ensure_fresh(provider: &dyn Provider, session: &Session) -> Session {
    let stale = provider
        .session_expiry(session)
        .is_some_and(|exp| now_unix().saturating_add(REFRESH_MARGIN_SECS) >= exp);
    if !stale {
        return session.clone();
    }
    match provider.refresh_session(session).await {
        Ok(fresh) => fresh,
        Err(_) => session.clone(),
    }
}

/// `cryptile export --namespace N`: all values in a namespace. Returns the
/// (possibly rotated) session alongside the secrets.
pub async fn export(
    provider: &dyn Provider,
    session: Session,
    namespace: &str,
) -> Result<(Session, Vec<Secret>), String> {
    async fn export_once(
        p: &dyn Provider,
        s: Session,
        namespace: &str,
    ) -> Result<(Session, Vec<Secret>), cryptile_core::ProviderError> {
        let names = p.list_namespaces(&s).await?;
        let target = names
            .into_iter()
            .find(|n| n.name.eq_ignore_ascii_case(namespace))
            .ok_or_else(|| {
                cryptile_core::ProviderError::NotFound(format!("namespace {namespace}"))
            })?;
        let secrets = p.get_namespace_secrets(&s, &target).await?;
        Ok((s, secrets))
    }
    let (session, secrets) =
        match export_once(provider, ensure_fresh(provider, &session).await, namespace).await {
            Ok(v) => v,
            Err(cryptile_core::ProviderError::AuthExpired) => {
                let fresh = provider
                    .refresh_session(&session)
                    .await
                    .map_err(|_| refresh_hint())?;
                export_once(provider, fresh, namespace)
                    .await
                    .map_err(map_retry)?
            }
            Err(e) => return Err(e.to_string()),
        };
    Ok((session, secrets))
}

async fn get_once(
    p: &dyn Provider,
    s: Session,
    r: &Ref,
) -> Result<(Session, Secret), cryptile_core::ProviderError> {
    let secret = p.get_secret(&s, r).await?;
    Ok((s, secret))
}

async fn list_ns_once(
    p: &dyn Provider,
    s: Session,
) -> Result<(Session, Vec<Namespace>), cryptile_core::ProviderError> {
    let ns = p.list_namespaces(&s).await?;
    Ok((s, ns))
}

async fn list_items_once(
    p: &dyn Provider,
    s: Session,
    ns: &str,
) -> Result<(Session, Vec<SecretMeta>), cryptile_core::ProviderError> {
    let list = p.list_namespaces(&s).await?;
    let target = list
        .iter()
        .find(|n| n.name.eq_ignore_ascii_case(ns))
        .cloned()
        .ok_or_else(|| cryptile_core::ProviderError::NotFound(format!("namespace {ns}")))?;
    let metas = p.list_secrets(&s, &target).await?;
    Ok((s, metas))
}

/// `cryptile get <ref>`: one field value. Returns the (possibly rotated)
/// session alongside so the caller can re-seal it.
pub async fn get(
    provider: &dyn Provider,
    session: Session,
    r: &Ref,
) -> Result<(Session, String), String> {
    let (session, secret) =
        match get_once(provider, ensure_fresh(provider, &session).await, r).await {
            Ok(v) => v,
            Err(cryptile_core::ProviderError::AuthExpired) => {
                let fresh = provider
                    .refresh_session(&session)
                    .await
                    .map_err(|_| refresh_hint())?;
                get_once(provider, fresh, r).await.map_err(map_retry)?
            }
            Err(e) => return Err(e.to_string()),
        };
    let field = secret
        .field(&r.field)
        .ok_or_else(|| format!("field '{}' not present on {}", r.field, r.locus))?;
    Ok((session, field.expose_secret().to_string()))
}

/// `cryptile list [namespace]`: namespace names, or item names in one.
pub async fn list(
    provider: &dyn Provider,
    session: Session,
    namespace: Option<String>,
) -> Result<(Session, Vec<String>), String> {
    let Some(ns) = namespace else {
        let (session, names) =
            match list_ns_once(provider, ensure_fresh(provider, &session).await).await {
                Ok(v) => v,
                Err(cryptile_core::ProviderError::AuthExpired) => {
                    let fresh = provider
                        .refresh_session(&session)
                        .await
                        .map_err(|_| refresh_hint())?;
                    list_ns_once(provider, fresh).await.map_err(map_retry)?
                }
                Err(e) => return Err(e.to_string()),
            };
        return Ok((session, names.into_iter().map(|n| n.name).collect()));
    };

    let (session, metas) =
        match list_items_once(provider, ensure_fresh(provider, &session).await, &ns).await {
            Ok(v) => v,
            Err(cryptile_core::ProviderError::AuthExpired) => {
                let fresh = provider
                    .refresh_session(&session)
                    .await
                    .map_err(|_| refresh_hint())?;
                list_items_once(provider, fresh, &ns)
                    .await
                    .map_err(map_retry)?
            }
            Err(e) => return Err(e.to_string()),
        };
    Ok((session, metas.into_iter().map(|m| m.name).collect()))
}
