struct SseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    parser: mitm_http::SseParser,
    max_event_bytes: usize,
    next_sequence_no: u64,
    stream_ended: bool,
}

impl<P, S> SseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn new(
        engine: Arc<MitmEngine<P, S>>,
        context: FlowContext,
        runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
        flow_hooks: Arc<dyn FlowHooks>,
        max_event_bytes: usize,
    ) -> Self {
        Self {
            engine,
            context,
            runtime_governor,
            flow_hooks,
            parser: mitm_http::SseParser::new(),
            max_event_bytes,
            next_sequence_no: 1,
            stream_ended: false,
        }
    }

    fn emit_parsed_event(&mut self, event: mitm_http::SseEvent) -> io::Result<()> {
        if event.data.len() > self.max_event_bytes {
            self.runtime_governor.mark_decoder_failure();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SSE event exceeded decoder budget (len={}, limit={})",
                    event.data.len(),
                    self.max_event_bytes
                ),
            ));
        }
        let sequence_no = self.next_sequence_no;
        self.next_sequence_no += 1;
        emit_sse_event(&self.engine, self.context.clone(), sequence_no, &event);
        let is_done = event.data == "[DONE]";
        let flow_hooks = Arc::clone(&self.flow_hooks);
        let hook_context = self.context.clone();
        let hook_chunk = StreamChunk {
            payload: bytes::Bytes::from(event.data),
            sequence: sequence_no,
            frame_kind: StreamFrameKind::SseData,
        };
        tokio::spawn(async move {
            flow_hooks.on_stream_chunk(hook_context, hook_chunk).await;
        });
        if is_done && !self.stream_ended {
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

impl<P, S> HttpBodyObserver for SseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn on_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        if chunk.len() > self.max_event_bytes {
            self.runtime_governor.mark_decoder_failure();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SSE chunk exceeded decoder budget (len={}, limit={})",
                    chunk.len(),
                    self.max_event_bytes
                ),
            ));
        }
        for event in self.parser.push_bytes(chunk) {
            self.emit_parsed_event(event)?;
        }
        Ok(())
    }

    fn on_complete(&mut self) -> io::Result<()> {
        if let Some(event) = self.parser.finish() {
            self.emit_parsed_event(event)?;
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
