use crate::error::AegisError;
use crate::policy::{PolicyTier, SandboxPolicy};
use std::net::IpAddr;
use url::Url;

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
        return Err(AegisError::CapabilityDenied(
            "Outbound network access requires allowlisted_net tier".into(),
        ));
    }

    let parsed = Url::parse(raw_url)
        .map_err(|e| AegisError::CapabilityDenied(format!("Invalid URL '{raw_url}': {e}")))?;

    if policy.https_only && parsed.scheme() != "https" {
        return Err(AegisError::CapabilityDenied(format!(
            "Only https:// scheme permitted by Tier 3 proxy (got '{}')",
            parsed.scheme()
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AegisError::CapabilityDenied("Missing URL hostname".into()))?
        .to_lowercase();

    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return Err(AegisError::CapabilityDenied(format!(
            "SSRF guard blocked local hostname '{host}'"
        )));
    }

    let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_unbracketed.parse::<IpAddr>()
        && is_blocked_ip(ip)
    {
        return Err(AegisError::CapabilityDenied(format!(
            "SSRF guard blocked private/loopback/metadata IP '{ip}'"
        )));
    }

    let domain_allowed = policy.allowed_domains.iter().any(|allowed| {
        let d = allowed.to_lowercase();
        host == d || host.ends_with(&format!(".{d}"))
    });
    if !domain_allowed {
        return Err(AegisError::CapabilityDenied(format!(
            "Domain '{host}' is not on the Tier 3 allowlist"
        )));
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| AegisError::CapabilityDenied(format!("DNS lookup failed for '{host}': {e}")))?;

    let mut count = 0usize;
    for addr in resolved {
        count += 1;
        if is_blocked_ip(addr.ip()) {
            return Err(AegisError::CapabilityDenied(format!(
                "SSRF guard blocked resolved private/metadata IP {}",
                addr.ip()
            )));
        }
    }
    if count == 0 {
        return Err(AegisError::CapabilityDenied(format!(
            "DNS returned zero addresses for '{host}'"
        )));
    }

    Ok(parsed)
}

pub async fn fetch_allowlisted_get(
    policy: &SandboxPolicy,
    raw_url: &str,
) -> Result<String, AegisError> {
    let parsed = validate_target_url(policy, raw_url).await?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| AegisError::GuestRuntime(format!("HTTP client build failed: {e}")))?;

    let response = client
        .get(parsed)
        .send()
        .await
        .map_err(|e| AegisError::GuestRuntime(format!("HTTP GET failed: {e}")))?;

    if let Some(len) = response.content_length()
        && len as usize > policy.max_response_bytes
    {
        return Err(AegisError::CapabilityDenied(format!(
            "Response size ({len} bytes) exceeds Tier 3 cap ({} bytes)",
            policy.max_response_bytes
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| AegisError::GuestRuntime(format!("Failed reading HTTP body: {e}")))?;
    if body.len() > policy.max_response_bytes {
        return Err(AegisError::CapabilityDenied(format!(
            "Response body ({} bytes) exceeded Tier 3 cap ({} bytes)",
            body.len(),
            policy.max_response_bytes
        )));
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}
