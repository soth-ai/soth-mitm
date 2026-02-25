use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerDecision {
    Allow,
    Block { status: u16, body: Bytes },
}
