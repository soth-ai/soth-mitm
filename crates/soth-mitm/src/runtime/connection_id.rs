use uuid::Uuid;

use crate::types::FlowId;

pub(crate) fn connection_id_for_flow_id(flow_id: FlowId) -> Uuid {
    // Mix the flow_id bits across all 16 bytes so even small sequential
    // values produce full-looking UUIDs instead of 00000000-0000-4xxx-...
    let seeded = flow_id.as_u64().wrapping_add(1);
    let a = seeded.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
    let b = seeded.wrapping_mul(0x517C_C1B7_2722_0A95_u64).wrapping_add(0x6C62_272E_07BB_0142_u64);

    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&a.to_be_bytes());
    bytes[8..].copy_from_slice(&b.to_be_bytes());
    // Set UUID v4 version and RFC 4122 variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
