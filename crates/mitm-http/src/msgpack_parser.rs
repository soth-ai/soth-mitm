use crate::msgpack::{MsgPackDecodeFailure, MsgPackDecodeLimits, MsgPackFailureCode};

pub(crate) fn decode_msgpack_structure_impl(
    input: &[u8],
    limits: MsgPackDecodeLimits,
) -> Result<(), MsgPackDecodeFailure> {
    if input.len() > limits.max_input_bytes {
        return Err(MsgPackDecodeFailure {
            code: MsgPackFailureCode::InputTooLarge,
            detail: format!(
                "input length {} exceeds max {}",
                input.len(),
                limits.max_input_bytes
            ),
        });
    }

    let mut cursor = MsgPackCursor {
        input,
        offset: 0,
        limits,
    };
    cursor.parse_value(0)?;

    if cursor.offset != input.len() {
        return Err(MsgPackDecodeFailure {
            code: MsgPackFailureCode::TrailingBytes,
            detail: format!("consumed {} bytes out of {}", cursor.offset, input.len()),
        });
    }

    Ok(())
}

struct MsgPackCursor<'a> {
    input: &'a [u8],
    offset: usize,
    limits: MsgPackDecodeLimits,
}

impl MsgPackCursor<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<(), MsgPackDecodeFailure> {
        if depth > self.limits.max_depth {
            return Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::DepthExceeded,
                detail: format!("depth {} exceeds max {}", depth, self.limits.max_depth),
            });
        }

        let marker = self.take_u8()?;
        match marker {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Ok(()),
            0xcc => self.skip(1),
            0xcd => self.skip(2),
            0xce => self.skip(4),
            0xcf => self.skip(8),
            0xd0 => self.skip(1),
            0xd1 => self.skip(2),
            0xd2 => self.skip(4),
            0xd3 => self.skip(8),
            0xca => self.skip(4),
            0xcb => self.skip(8),
            0xa0..=0xbf => self.parse_text((marker & 0x1f) as usize),
            0xd9 => {
                let len = self.take_u8()? as usize;
                self.parse_text(len)
            }
            0xda => {
                let len = self.take_u16()? as usize;
                self.parse_text(len)
            }
            0xdb => {
                let len = self.take_u32()? as usize;
                self.parse_text(len)
            }
            0xc4 => {
                let len = self.take_u8()? as usize;
                self.parse_binary(len)
            }
            0xc5 => {
                let len = self.take_u16()? as usize;
                self.parse_binary(len)
            }
            0xc6 => {
                let len = self.take_u32()? as usize;
                self.parse_binary(len)
            }
            0x90..=0x9f => self.parse_array((marker & 0x0f) as usize, depth + 1),
            0xdc => {
                let len = self.take_u16()? as usize;
                self.parse_array(len, depth + 1)
            }
            0xdd => {
                let len = self.take_u32()? as usize;
                self.parse_array(len, depth + 1)
            }
            0x80..=0x8f => self.parse_map((marker & 0x0f) as usize, depth + 1),
            0xde => {
                let len = self.take_u16()? as usize;
                self.parse_map(len, depth + 1)
            }
            0xdf => {
                let len = self.take_u32()? as usize;
                self.parse_map(len, depth + 1)
            }
            0xd4 => self.parse_extension(1),
            0xd5 => self.parse_extension(2),
            0xd6 => self.parse_extension(4),
            0xd7 => self.parse_extension(8),
            0xd8 => self.parse_extension(16),
            0xc7 => {
                let len = self.take_u8()? as usize;
                self.parse_extension(len)
            }
            0xc8 => {
                let len = self.take_u16()? as usize;
                self.parse_extension(len)
            }
            0xc9 => {
                let len = self.take_u32()? as usize;
                self.parse_extension(len)
            }
            _ => Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::InvalidMarker,
                detail: format!("invalid marker 0x{marker:02x} at {}", self.offset - 1),
            }),
        }
    }

    fn parse_text(&mut self, len: usize) -> Result<(), MsgPackDecodeFailure> {
        if len > self.limits.max_text_bytes {
            return Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::TextTooLarge,
                detail: format!(
                    "text length {len} exceeds max {}",
                    self.limits.max_text_bytes
                ),
            });
        }
        self.skip(len)
    }

    fn parse_binary(&mut self, len: usize) -> Result<(), MsgPackDecodeFailure> {
        if len > self.limits.max_binary_bytes {
            return Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::BinaryTooLarge,
                detail: format!(
                    "binary length {len} exceeds max {}",
                    self.limits.max_binary_bytes
                ),
            });
        }
        self.skip(len)
    }

    fn parse_array(&mut self, len: usize, depth: usize) -> Result<(), MsgPackDecodeFailure> {
        if len > self.limits.max_container_len {
            return Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::ContainerTooLarge,
                detail: format!(
                    "array length {len} exceeds max {}",
                    self.limits.max_container_len
                ),
            });
        }
        for _ in 0..len {
            self.parse_value(depth)?;
        }
        Ok(())
    }

    fn parse_map(&mut self, len: usize, depth: usize) -> Result<(), MsgPackDecodeFailure> {
        if len > self.limits.max_container_len {
            return Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::ContainerTooLarge,
                detail: format!(
                    "map length {len} exceeds max {}",
                    self.limits.max_container_len
                ),
            });
        }
        for _ in 0..len {
            self.parse_value(depth)?;
            self.parse_value(depth)?;
        }
        Ok(())
    }

    fn parse_extension(&mut self, len: usize) -> Result<(), MsgPackDecodeFailure> {
        if len > self.limits.max_extension_bytes {
            return Err(MsgPackDecodeFailure {
                code: MsgPackFailureCode::ExtensionTooLarge,
                detail: format!(
                    "extension length {len} exceeds max {}",
                    self.limits.max_extension_bytes
                ),
            });
        }
        self.skip(1)?;
        self.skip(len)
    }

    fn take_u8(&mut self) -> Result<u8, MsgPackDecodeFailure> {
        let byte = self
            .input
            .get(self.offset)
            .copied()
            .ok_or(MsgPackDecodeFailure {
                code: MsgPackFailureCode::Truncated,
                detail: format!("unexpected end of input at {}", self.offset),
            })?;
        self.offset += 1;
        Ok(byte)
    }

    fn take_u16(&mut self) -> Result<u16, MsgPackDecodeFailure> {
        let bytes = self.take_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, MsgPackDecodeFailure> {
        let bytes = self.take_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_exact(&mut self, len: usize) -> Result<&[u8], MsgPackDecodeFailure> {
        let end = self.offset.saturating_add(len);
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(MsgPackDecodeFailure {
                code: MsgPackFailureCode::Truncated,
                detail: format!("expected {len} bytes at {}", self.offset),
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) -> Result<(), MsgPackDecodeFailure> {
        self.take_exact(len).map(|_| ())
    }
}
