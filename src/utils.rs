use axum::http::{HeaderValue, Uri};

pub(crate) fn get_host_port<'a>(host: Option<&'a HeaderValue>, uri: &'a Uri) -> (&'a str, u16) {
    let default_port = match uri.scheme() {
        Some(scheme) if scheme.as_str() == "https" => 443,
        _ => 80,
    };
    match host {
        Some(host) => split_host_port(host.to_str().unwrap_or_default(), default_port),
        None => (
            uri.host().unwrap_or_default(),
            uri.port_u16().unwrap_or(default_port),
        ),
    }
}

fn split_host_port(host: &str, default_port: u16) -> (&str, u16) {
    // Handle IPv6 format [::1]:8080
    if let Some(end) = host.find(']') {
        if host.starts_with('[') {
            let host_part = &host[1..end];
            let port_part = host.get(end + 1..).and_then(|s| s.strip_prefix(':'));
            return (
                host_part,
                port_part
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(default_port),
            );
        }
    }

    // Existing IPv4 handling
    let mut parts = host.split(':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next().and_then(|s| s.parse().ok());
    (host, port.unwrap_or(default_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_host_port_ipv4() {
        assert_eq!(split_host_port("localhost:8080", 80), ("localhost", 8080));
        assert_eq!(split_host_port("127.0.0.1:3000", 80), ("127.0.0.1", 3000));
        assert_eq!(split_host_port("example.com", 443), ("example.com", 443));
    }

    #[test]
    fn test_split_host_port_ipv6() {
        assert_eq!(split_host_port("[::1]:8080", 80), ("::1", 8080));
        assert_eq!(split_host_port("[2001:db8::1]", 443), ("2001:db8::1", 443));
        assert_eq!(split_host_port("[v6.addr]:invalid", 80), ("v6.addr", 80)); // Test invalid port
    }

    #[test]
    fn test_get_host_port_with_header() {
        let uri = Uri::from_static("http://example.com/foo");
        let host_header = HeaderValue::from_static("real-host:9090");
        assert_eq!(get_host_port(Some(&host_header), &uri), ("real-host", 9090));
    }

    #[test]
    fn test_get_host_port_without_header() {
        let uri = Uri::from_static("https://example.com:8443/bar");
        assert_eq!(get_host_port(None, &uri), ("example.com", 8443));
    }

    #[test]
    fn test_get_host_port_default_port() {
        let uri = Uri::from_static("https://example.com/bar");
        assert_eq!(get_host_port(None, &uri), ("example.com", 443));

        let uri = Uri::from_static("http://example.com/bar");
        assert_eq!(get_host_port(None, &uri), ("example.com", 80));
    }
}
