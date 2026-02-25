use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use uuid::Uuid;

pub(crate) fn connection_id_for_flow_id(flow_id: u64) -> Uuid {
    let mut hasher = DefaultHasher::new();
    flow_id.hash(&mut hasher);
    let hash = hasher.finish();

    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&flow_id.to_be_bytes());
    bytes[8..].copy_from_slice(&hash.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
