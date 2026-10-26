//! Target grammar and the operator's allow/deny policy, checked before any proof work so
//! lexical garbage and disallowed destinations cost nothing (`gateway.mjs` `validTarget`,
//! `makeEgressPolicy`).

use serde_json::Value;

pub(crate) const REASON_BAD_TARGET: &str = "bad-target";
pub(crate) const REASON_BAD_TARGET_POLICY: &str = "bad-target-policy";

enum HostPattern {
    Any,
    Suffix(String),
    Exact(String),
}

struct Pattern {
    host: HostPattern,
    port: Option<u16>,
}

impl Pattern {
    fn parse(spec: &str) -> Option<Self> {
        let (host, port) = spec.rsplit_once(':')?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        let host = host.to_ascii_lowercase();
        let host = if host == "*" {
            HostPattern::Any
        } else if let Some(suffix) = host.strip_prefix('*') {
            if suffix.starts_with('.') {
                HostPattern::Suffix(suffix.to_string())
            } else {
                HostPattern::Exact(host)
            }
        } else {
            HostPattern::Exact(host)
        };
        let port = if port == "*" {
            None
        } else {
            Some(parse_port(port)?)
        };
        Some(Self { host, port })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        match &self.host {
            HostPattern::Any => true,
            HostPattern::Suffix(suffix) => host.ends_with(suffix.as_str()),
            HostPattern::Exact(exact) => exact == host,
        }
    }
}

pub(crate) struct Policy {
    allows: Vec<Pattern>,
    denies: Vec<Pattern>,
}

impl Policy {
    /// Comma-separated `host:port` patterns; malformed entries are dropped.
    pub(crate) fn parse(allow: &str, deny: &str) -> Self {
        let list = |spec: &str| {
            spec.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(Pattern::parse)
                .collect()
        };
        Self {
            allows: list(allow),
            denies: list(deny),
        }
    }

    fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        if host.is_empty() || host.starts_with('.') || host.contains("..") {
            return false;
        }
        if self.denies.iter().any(|p| p.matches(host, port)) {
            return false;
        }
        self.allows.iter().any(|p| p.matches(host, port))
    }

    /// Check an envelope's `target` field: the `host:port` grammar first, then this policy.
    pub(crate) fn check_target(
        &self,
        target: Option<&Value>,
    ) -> Result<(String, u16), &'static str> {
        let target = target.and_then(Value::as_str).ok_or(REASON_BAD_TARGET)?;
        let (host, port) = target.rsplit_once(':').ok_or(REASON_BAD_TARGET)?;
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if !host_ok {
            return Err(REASON_BAD_TARGET);
        }
        let port = parse_port(port).ok_or(REASON_BAD_TARGET)?;
        if !self.allows(host, port) {
            return Err(REASON_BAD_TARGET_POLICY);
        }
        Ok((host.to_string(), port))
    }
}

fn parse_port(digits: &str) -> Option<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits
        .parse::<u32>()
        .ok()
        .filter(|p| (1..=65535).contains(p))
        .and_then(|p| u16::try_from(p).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(policy: &Policy, target: &str) -> Result<(String, u16), &'static str> {
        policy.check_target(Some(&Value::String(target.into())))
    }

    #[test]
    fn the_default_policy_allows_only_port_443() {
        let policy = Policy::parse("*:443", "");
        assert_eq!(
            check(&policy, "example.com:443"),
            Ok(("example.com".into(), 443))
        );
        assert_eq!(
            check(&policy, "example.com:80"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "EXAMPLE.com.:0443"),
            Ok(("EXAMPLE.com.".into(), 443))
        );
    }

    #[test]
    fn target_grammar_is_host_colon_port() {
        let policy = Policy::parse("*:*", "");
        for bad in [
            "example.com",
            ":443",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:443443",
            "[::1]:443",
            "exa mple.com:443",
            "example.com:44a",
        ] {
            assert_eq!(check(&policy, bad), Err(REASON_BAD_TARGET), "{bad}");
        }
        assert_eq!(policy.check_target(None), Err(REASON_BAD_TARGET));
        assert_eq!(
            policy.check_target(Some(&Value::Number(443.into()))),
            Err(REASON_BAD_TARGET)
        );
    }

    #[test]
    fn deny_wins_and_suffixes_exclude_the_apex() {
        let policy = Policy::parse("*.example.com:443, api.other.org:*", "evil.example.com:443");
        assert!(check(&policy, "a.example.com:443").is_ok());
        assert_eq!(
            check(&policy, "example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "evil.example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "evil.example.com.:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert!(check(&policy, "api.other.org:8443").is_ok());
        assert_eq!(
            check(&policy, "..example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
    }

    #[test]
    fn malformed_patterns_are_dropped() {
        let policy = Policy::parse("nocolon, :443, host:, host:99999, host:x, *:443", "");
        assert!(check(&policy, "host:443").is_ok());
        assert_eq!(check(&policy, "host:80"), Err(REASON_BAD_TARGET_POLICY));
        let empty = Policy::parse("", "");
        assert_eq!(check(&empty, "host:443"), Err(REASON_BAD_TARGET_POLICY));
    }
}
