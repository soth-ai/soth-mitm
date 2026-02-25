struct NdjsonStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    context: FlowContext,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    pending: Vec<u8>,
    max_line_bytes: usize,
    next_sequence_no: u64,
    stream_ended: bool,
    _marker: std::marker::PhantomData<(P, S)>,
}

impl<P, S> NdjsonStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn new(
        context: FlowContext,
        runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
        flow_hooks: Arc<dyn FlowHooks>,
        max_line_bytes: usize,
    ) -> Self {
        Self {
            context,
            runtime_governor,
            flow_hooks,
            pending: Vec::new(),
            max_line_bytes,
            next_sequence_no: 0,
            stream_ended: false,
            _marker: std::marker::PhantomData,
        }
    }

    fn emit_line(&mut self, mut line: Vec<u8>) -> io::Result<()> {
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() > self.max_line_bytes {
            self.runtime_governor.mark_decoder_failure();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "NDJSON line exceeded decoder budget (len={}, limit={})",
                    line.len(),
                    self.max_line_bytes
                ),
            ));
        }
        let sequence = self.next_sequence_no;
        self.next_sequence_no += 1;
        let flow_hooks = Arc::clone(&self.flow_hooks);
        let hook_context = self.context.clone();
        tokio::spawn(async move {
            flow_hooks
                .on_stream_chunk(
                    hook_context,
                    StreamChunk {
                        payload: bytes::Bytes::from(line),
                        sequence,
                        frame_kind: StreamFrameKind::NdjsonLine,
                    },
                )
                .await;
        });
        Ok(())
    }
}

impl<P, S> HttpBodyObserver for NdjsonStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn on_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.pending.extend_from_slice(chunk);
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending.drain(..=index).collect::<Vec<u8>>();
            line.pop();
            self.emit_line(line)?;
        }
        Ok(())
    }

    fn on_complete(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.emit_line(line)?;
        }
        if !self.stream_ended {
            let flow_hooks = Arc::clone(&self.flow_hooks);
            let hook_context = self.context.clone();
            tokio::spawn(async move {
                flow_hooks.on_stream_end(hook_context).await;
            });
            self.stream_ended = true;
        }
        Ok(())
    }
}
