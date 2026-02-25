use uuid::Uuid;

pub(crate) fn connection_id_for_flow_id(flow_id: u64) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&flow_id.to_be_bytes());
    let mixed = flow_id.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    bytes[8..].copy_from_slice(&mixed.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
