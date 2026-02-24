use std::collections::HashSet;

use http::header::HeaderName;
use http::HeaderMap;

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub(crate) fn rewrite_request_headers_for_upstream(headers: &HeaderMap) -> HeaderMap {
    rewrite_hop_by_hop_headers(headers)
}

pub(crate) fn rewrite_response_headers_for_downstream(headers: &HeaderMap) -> HeaderMap {
    rewrite_hop_by_hop_headers(headers)
}

fn rewrite_hop_by_hop_headers(headers: &HeaderMap) -> HeaderMap {
    let mut blocked = blocked_header_names(headers);
    blocked.insert(HeaderName::from_static("proxy-connection"));

    let mut rewritten = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if blocked.contains(name) {
            continue;
        }
        rewritten.append(name.clone(), value.clone());
    }
    rewritten
}

fn blocked_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    let mut blocked = HashSet::with_capacity(HOP_BY_HOP_HEADERS.len() + 4);
    for header in HOP_BY_HOP_HEADERS {
        blocked.insert(HeaderName::from_static(header));
    }

    for token in parse_connection_tokens(headers) {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            blocked.insert(name);
        }
    }
    blocked
}

fn parse_connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut tokens = Vec::new();
    for value in headers.get_all(HeaderName::from_static("connection")) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for token in raw.split(',') {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                tokens.push(trimmed.to_ascii_lowercase());
            }
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::{rewrite_request_headers_for_upstream, rewrite_response_headers_for_downstream};

    #[test]
    fn header_preservation_and_strip_matrix() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert("host", HeaderValue::from_static("api.example.com"));
        request_headers.insert("user-agent", HeaderValue::from_static("curl/8.7.1"));
        request_headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-internal-hop"),
        );
        request_headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        request_headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        request_headers.insert("x-internal-hop", HeaderValue::from_static("remove-me"));
        request_headers.insert("x-request-id", HeaderValue::from_static("req-1"));

        let rewritten_request = rewrite_request_headers_for_upstream(&request_headers);
        assert_eq!(
            rewritten_request.get("host").and_then(|v| v.to_str().ok()),
            Some("api.example.com")
        );
        assert_eq!(
            rewritten_request
                .get("user-agent")
                .and_then(|v| v.to_str().ok()),
            Some("curl/8.7.1")
        );
        assert_eq!(
            rewritten_request
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some("req-1")
        );
        assert!(rewritten_request.get("connection").is_none());
        assert!(rewritten_request.get("keep-alive").is_none());
        assert!(rewritten_request.get("proxy-connection").is_none());
        assert!(rewritten_request.get("x-internal-hop").is_none());

        let mut response_headers = HeaderMap::new();
        response_headers.insert("content-type", HeaderValue::from_static("application/json"));
        response_headers.insert("content-length", HeaderValue::from_static("12"));
        response_headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        response_headers.insert("upgrade", HeaderValue::from_static("websocket"));
        response_headers.insert("te", HeaderValue::from_static("trailers"));

        let rewritten_response = rewrite_response_headers_for_downstream(&response_headers);
        assert_eq!(
            rewritten_response
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            rewritten_response
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("12")
        );
        assert!(rewritten_response.get("transfer-encoding").is_none());
        assert!(rewritten_response.get("upgrade").is_none());
        assert!(rewritten_response.get("te").is_none());
    }
}
