use bytes::Bytes;

/// Decision returned by [`InterceptHandler::on_request`](crate::InterceptHandler::on_request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerDecision {
    Allow,
    Block { status: u16, body: Bytes },
}
