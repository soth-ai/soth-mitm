use std::io::{self, Write};

pub(crate) enum StreamingContentDecoder {
    Gzip(Box<flate2::write::GzDecoder<CappedDecoderOutput>>),
    Brotli(Box<brotli::DecompressorWriter<CappedDecoderOutput>>),
    Zstd(Box<zstd::stream::write::Decoder<'static, CappedDecoderOutput>>),
}

impl StreamingContentDecoder {
    pub(crate) fn from_header_value(
        value: &str,
        max_buffered_output_bytes: usize,
    ) -> io::Result<Option<Self>> {
        let Some(encoding) = single_content_encoding(value) else {
            return Ok(None);
        };
        let output = || CappedDecoderOutput::new(max_buffered_output_bytes);
        let encoding = encoding.to_ascii_lowercase();
        match encoding.as_str() {
            "gzip" => Ok(Some(Self::Gzip(Box::new(flate2::write::GzDecoder::new(
                output(),
            ))))),
            "br" => Ok(Some(Self::Brotli(Box::new(
                brotli::DecompressorWriter::new(output(), 4096),
            )))),
            "zstd" => {
                let decoder = zstd::stream::write::Decoder::new(output())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                Ok(Some(Self::Zstd(Box::new(decoder))))
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn decode_chunk(&mut self, chunk: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip(decoder) => {
                decoder.write_all(chunk)?;
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
            Self::Brotli(decoder) => {
                decoder.write_all(chunk)?;
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
            Self::Zstd(decoder) => {
                decoder.write_all(chunk)?;
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
        }
    }

    pub(crate) fn finish(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip(decoder) => {
                decoder.try_finish()?;
                Ok(decoder.get_mut().take())
            }
            Self::Brotli(decoder) => {
                decoder.close()?;
                Ok(decoder.get_mut().take())
            }
            Self::Zstd(decoder) => {
                decoder.flush()?;
                Ok(decoder.get_mut().take())
            }
        }
    }
}

fn single_content_encoding(value: &str) -> Option<&str> {
    let mut parts = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    let encoding = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(encoding)
}

pub(crate) struct CappedDecoderOutput {
    bytes: Vec<u8>,
    max_len: usize,
}

impl CappedDecoderOutput {
    fn new(max_len: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_len,
        }
    }

    fn take(&mut self) -> Vec<u8> {
        if self.bytes.is_empty() {
            Vec::new()
        } else {
            std::mem::take(&mut self.bytes)
        }
    }
}

impl Write for CappedDecoderOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > self.max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "decoded content exceeded decoder output budget (len={}, incoming={}, limit={})",
                    self.bytes.len(),
                    buf.len(),
                    self.max_len
                ),
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::StreamingContentDecoder;
    use std::io::Write;

    #[test]
    fn decodes_gzip_chunks() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"data: {\"type\":\"ping\"}\n\n").unwrap();
        let encoded = encoder.finish().unwrap();

        let mut decoder = StreamingContentDecoder::from_header_value("gzip", 1024)
            .unwrap()
            .unwrap();
        let midpoint = encoded.len() / 2;
        let mut decoded = decoder.decode_chunk(&encoded[..midpoint]).unwrap();
        decoded.extend(decoder.decode_chunk(&encoded[midpoint..]).unwrap());
        decoded.extend(decoder.finish().unwrap());

        assert_eq!(decoded, b"data: {\"type\":\"ping\"}\n\n");
    }

    #[test]
    fn decodes_zstd_chunks() {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.write_all(b"data: {\"type\":\"ping\"}\n\n").unwrap();
        let encoded = encoder.finish().unwrap();

        let mut decoder = StreamingContentDecoder::from_header_value("zstd", 1024)
            .unwrap()
            .unwrap();
        let midpoint = encoded.len() / 2;
        let mut decoded = decoder.decode_chunk(&encoded[..midpoint]).unwrap();
        decoded.extend(decoder.decode_chunk(&encoded[midpoint..]).unwrap());
        decoded.extend(decoder.finish().unwrap());

        assert_eq!(decoded, b"data: {\"type\":\"ping\"}\n\n");
    }

    #[test]
    fn decodes_brotli_chunks() {
        let mut encoded = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut encoded, 4096, 1, 22);
            encoder.write_all(b"data: {\"type\":\"ping\"}\n\n").unwrap();
        }

        let mut decoder = StreamingContentDecoder::from_header_value("br", 1024)
            .unwrap()
            .unwrap();
        let midpoint = encoded.len() / 2;
        let mut decoded = decoder.decode_chunk(&encoded[..midpoint]).unwrap();
        decoded.extend(decoder.decode_chunk(&encoded[midpoint..]).unwrap());
        decoded.extend(decoder.finish().unwrap());

        assert_eq!(decoded, b"data: {\"type\":\"ping\"}\n\n");
    }

    #[test]
    fn content_encoding_is_case_insensitive() {
        assert!(StreamingContentDecoder::from_header_value("GZip", 1024)
            .unwrap()
            .is_some());
        assert!(StreamingContentDecoder::from_header_value("BR", 1024)
            .unwrap()
            .is_some());
        assert!(StreamingContentDecoder::from_header_value("Zstd", 1024)
            .unwrap()
            .is_some());
    }

    #[test]
    fn enforces_decoded_output_budget() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"data: too-large\n\n").unwrap();
        let encoded = encoder.finish().unwrap();

        let mut decoder = StreamingContentDecoder::from_header_value("gzip", 4)
            .unwrap()
            .unwrap();

        let error = decoder.decode_chunk(&encoded).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
