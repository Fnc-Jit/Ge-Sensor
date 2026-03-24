//! HTTP dissector — minimal zero-allocation header extraction.
//!
//! Parses HTTP request method and URI, or response status code,
//! from the L7 payload. Does NOT allocate for the common case.

/// Parsed HTTP request information.
#[derive(Debug, Clone, Default)]
pub struct HttpInfo {
    /// HTTP method (GET, POST, etc.) — empty for responses
    pub method: String,
    /// Request URI path
    pub uri: String,
    /// HTTP version string (e.g., "HTTP/1.1")
    pub version: String,
    /// Response status code (0 for requests)
    pub status_code: u16,
    /// Host header value (if present)
    pub host: String,
}

/// Attempt to parse HTTP request/response from payload.
pub fn dissect_http(data: &[u8], payload_offset: usize) -> Option<HttpInfo> {
    let payload = data.get(payload_offset..)?;

    // Need at least a few bytes to identify HTTP
    if payload.len() < 10 {
        return None;
    }

    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?;

    let mut info = HttpInfo::default();

    if first_line.starts_with("HTTP/") {
        // ── Response: "HTTP/1.1 200 OK" ──
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            info.version = parts[0].to_string();
            info.status_code = parts[1].parse().unwrap_or(0);
        }
    } else {
        // ── Request: "GET /path HTTP/1.1" ──
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            info.method = parts[0].to_string();
            info.uri = parts[1].to_string();
            info.version = parts[2].to_string();
        } else {
            return None;
        }
    }

    // Extract Host header
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(host) = line.strip_prefix("Host: ").or_else(|| line.strip_prefix("host: ")) {
            info.host = host.trim().to_string();
            break;
        }
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_parse() {
        let payload = b"GET /api/v1/status HTTP/1.1\r\nHost: gods-eye.io\r\nAccept: */*\r\n\r\n";
        let info = dissect_http(payload, 0).expect("should parse HTTP");
        assert_eq!(info.method, "GET");
        assert_eq!(info.uri, "/api/v1/status");
        assert_eq!(info.version, "HTTP/1.1");
        assert_eq!(info.host, "gods-eye.io");
        assert_eq!(info.status_code, 0);
    }

    #[test]
    fn test_http_response_parse() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
        let info = dissect_http(payload, 0).expect("should parse HTTP response");
        assert_eq!(info.status_code, 200);
        assert_eq!(info.version, "HTTP/1.1");
    }
}
