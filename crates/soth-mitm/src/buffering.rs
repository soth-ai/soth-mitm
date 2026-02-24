use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::HeaderMap;

use crate::types::{HttpVersion, InterceptedRequest, InterceptedResponse};

pub(crate) fn build_intercepted_request(
    method: String,
    path: String,
    version: HttpVersion,
    headers: HeaderMap,
    body: Bytes,
    max_size_bytes: usize,
) -> InterceptedRequest {
    let declared_content_length = parse_declared_content_length(&headers);
    let (body, body_truncated, body_original_size) =
        truncate_request_body(body, max_size_bytes, declared_content_length);

    InterceptedRequest {
        method,
        path,
        version,
        headers,
        body,
        body_truncated,
        body_original_size,
    }
}

pub(crate) fn build_intercepted_response(
    status: u16,
    headers: HeaderMap,
    body: Bytes,
    is_streaming: bool,
) -> InterceptedResponse {
    InterceptedResponse {
        status,
        headers,
        body,
        is_streaming,
    }
}

fn truncate_request_body(
    body: Bytes,
    max_size_bytes: usize,
    declared_content_length: Option<usize>,
) -> (Bytes, bool, Option<usize>) {
    if max_size_bytes == 0 || body.len() <= max_size_bytes {
        return (body, false, None);
    }

    let truncated = body.slice(0..max_size_bytes);
    (truncated, true, declared_content_length)
}

fn parse_declared_content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{header::CONTENT_LENGTH, HeaderMap, HeaderValue};

    use super::{build_intercepted_request, build_intercepted_response};
    use crate::types::HttpVersion;

    #[test]
    fn request_body_complete_or_truncated_contract() {
        let request = build_intercepted_request(
            "POST".to_string(),
            "/v1/records".to_string(),
            HttpVersion::Http11,
            HeaderMap::new(),
            Bytes::from_static(b"{\"kind\":\"x\"}"),
            1024,
        );
        assert!(!request.body_truncated);
        assert_eq!(request.body_original_size, None);
        assert_eq!(request.body, Bytes::from_static(b"{\"kind\":\"x\"}"));

        let truncated = build_intercepted_request(
            "POST".to_string(),
            "/upload".to_string(),
            HttpVersion::Http11,
            HeaderMap::new(),
            Bytes::from(vec![b'a'; 64]),
            16,
        );
        assert!(truncated.body_truncated);
        assert_eq!(truncated.body.len(), 16);
    }

    #[test]
    fn body_original_size_contract() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("200"));

        let request = build_intercepted_request(
            "POST".to_string(),
            "/upload".to_string(),
            HttpVersion::Http11,
            headers,
            Bytes::from(vec![b'a'; 64]),
            16,
        );
        assert!(request.body_truncated);
        assert_eq!(request.body.len(), 16);
        assert_eq!(request.body_original_size, Some(200));
    }

    #[test]
    fn response_builder_preserves_streaming_flag() {
        let response = build_intercepted_response(
            200,
            HeaderMap::new(),
            Bytes::from_static(b"data: token\\n\\n"),
            true,
        );
        assert_eq!(response.status, 200);
        assert!(response.is_streaming);
    }
}
