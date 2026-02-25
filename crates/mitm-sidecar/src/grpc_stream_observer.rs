struct GrpcStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    context: FlowContext,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    pending: Vec<u8>,
    max_message_bytes: usize,
    next_sequence_no: u64,
    stream_ended: bool,
    _marker: std::marker::PhantomData<(P, S)>,
}

impl<P, S> GrpcStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn new(
        context: FlowContext,
        runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
        flow_hooks: Arc<dyn FlowHooks>,
        max_message_bytes: usize,
    ) -> Self {
        Self {
            context,
            runtime_governor,
            flow_hooks,
            pending: Vec::new(),
            max_message_bytes,
            next_sequence_no: 0,
            stream_ended: false,
            _marker: std::marker::PhantomData,
        }
    }

    async fn emit_payload(&mut self, payload: Vec<u8>) -> io::Result<()> {
        if payload.len() > self.max_message_bytes {
            self.runtime_governor.mark_decoder_failure();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "gRPC message exceeded decoder budget (len={}, limit={})",
                    payload.len(),
                    self.max_message_bytes
                ),
            ));
        }
        let sequence = self.next_sequence_no;
        self.next_sequence_no += 1;
        self.flow_hooks
            .on_stream_chunk(
                self.context.clone(),
                StreamChunk {
                    payload: bytes::Bytes::from(payload),
                    sequence,
                    frame_kind: StreamFrameKind::GrpcMessage,
                },
            )
            .await;
        Ok(())
    }

    async fn parse_available_frames(&mut self) -> io::Result<()> {
        loop {
            if self.pending.len() < 5 {
                return Ok(());
            }
            let frame_len = u32::from_be_bytes([
                self.pending[1],
                self.pending[2],
                self.pending[3],
                self.pending[4],
            ]) as usize;
            if self.pending.len() < 5 + frame_len {
                return Ok(());
            }

            let _compression_flag = self.pending[0];
            let payload = self.pending[5..5 + frame_len].to_vec();
            self.pending.drain(..5 + frame_len);
            self.emit_payload(payload).await?;
        }
    }
}

impl<P, S> HttpBodyObserver for GrpcStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn on_chunk<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.pending.extend_from_slice(chunk);
            self.parse_available_frames().await
        })
    }

    fn on_complete<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if !self.pending.is_empty() {
                self.pending.clear();
            }
            if !self.stream_ended {
                self.flow_hooks.on_stream_end(self.context.clone()).await;
                self.stream_ended = true;
            }
            Ok(())
        })
    }
}
