use crate::error::AegisError;
use crate::policy::{PolicyTier, SandboxPolicy};
use reqwest::Method;
use serde::Serialize;
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub body: String,
    pub bytes: usize,
    pub final_url: String,
}

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => {
            if let Some(v4_mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(v4_mapped));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub async fn validate_target_url(policy: &SandboxPolicy, raw_url: &str) -> Result<Url, AegisError> {
    if policy.tier != PolicyTier::AllowlistedNet {
        return Err(AegisError::PolicyViolation(
            "Outbound network access requires allowlisted_net tier".into(),
        ));
    }

    let parsed = Url::parse(raw_url)
        .map_err(|e| AegisError::PolicyViolation(format!("Invalid URL '{raw_url}': {e}")))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| AegisError::PolicyViolation("Missing URL hostname".into()))?
        .to_lowercase();

    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return Err(AegisError::SsrfBlocked(format!(
            "SSRF guard blocked local hostname '{host}'"
        )));
    }

    let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_unbracketed.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(AegisError::SsrfBlocked(format!(
                "SSRF guard blocked private/loopback/metadata IP '{ip}'"
            )));
        }
        return Err(AegisError::PolicyViolation(format!(
            "Direct IP host '{ip}' is not on the allowlisted_net domain allowlist"
        )));
    }

    let scheme = parsed.scheme();
    if scheme != "https" && !(policy.allow_http_plaintext && scheme == "http") {
        return Err(AegisError::PolicyViolation(format!(
            "Only https:// scheme permitted by Tier 3 proxy (got '{scheme}')"
        )));
    }

    let domain_allowed = policy.allowed_domains.iter().any(|allowed| {
        let d = allowed.trim().to_lowercase();
        !d.is_empty() && (host == d || host.ends_with(&format!(".{d}")))
    });
    if !domain_allowed {
        return Err(AegisError::PolicyViolation(format!(
            "Domain '{host}' is not on the Tier 3 allowlist"
        )));
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| AegisError::SsrfBlocked(format!("DNS lookup failed for '{host}': {e}")))?;

    let mut count = 0usize;
    for addr in resolved {
        count += 1;
        if is_blocked_ip(addr.ip()) {
            return Err(AegisError::SsrfBlocked(format!(
                "SSRF guard blocked resolved private/loopback/metadata IP {}",
                addr.ip()
            )));
        }
    }
    if count == 0 {
        return Err(AegisError::SsrfBlocked(format!(
            "DNS returned zero addresses for '{host}'"
        )));
    }

    Ok(parsed)
}

pub async fn validate_and_fetch(
    url_str: &str,
    method: &str,
    body: Option<String>,
    policy: &SandboxPolicy,
) -> Result<ProxyResponse, AegisError> {
    let parsed = validate_target_url(policy, url_str).await?;
    let http_method = Method::from_bytes(method.trim().to_uppercase().as_bytes())
        .map_err(|e| AegisError::PolicyViolation(format!("Invalid HTTP method '{method}': {e}")))?;

    if !matches!(http_method, Method::GET | Method::HEAD | Method::POST) {
        return Err(AegisError::PolicyViolation(format!(
            "HTTP method '{http_method}' is not permitted by Tier 3 proxy"
        )));
    }

    let timeout_ms = policy.request_timeout_ms.max(100);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| AegisError::EngineError(format!("HTTP client build failed: {e}")))?;

    let mut req = client.request(http_method, parsed.clone());
    if let Some(payload) = body {
        req = req.body(payload);
    }

    let response = req
        .send()
        .await
        .map_err(|e| AegisError::GuestRuntimeError(format!("Tier 3 proxy request failed: {e}")))?;

    let status = response.status().as_u16();
    if let Some(len) = response.content_length()
        && len as usize > policy.max_response_bytes
    {
        return Err(AegisError::PolicyViolation(format!(
            "Response size ({len} bytes) exceeds Tier 3 cap ({} bytes)",
            policy.max_response_bytes
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AegisError::GuestRuntimeError(format!("Failed reading HTTP body: {e}")))?;
    if bytes.len() > policy.max_response_bytes {
        return Err(AegisError::PolicyViolation(format!(
            "Response body ({} bytes) exceeded Tier 3 cap ({} bytes)",
            bytes.len(),
            policy.max_response_bytes
        )));
    }

    Ok(ProxyResponse {
        status,
        bytes: bytes.len(),
        body: String::from_utf8_lossy(&bytes).into_owned(),
        final_url: parsed.to_string(),
    })
}
