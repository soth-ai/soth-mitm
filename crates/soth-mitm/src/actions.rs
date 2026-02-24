use bytes::Bytes;
use http::HeaderMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerAction {
    Forward,
    ForwardModified {
        body: Bytes,
    },
    Block {
        status: u16,
        headers: HeaderMap,
        body: Bytes,
    },
    Reroute {
        host: String,
        port: u16,
        path_override: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    Forward,
    ForwardModified { body: Bytes },
}
