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

    async fn emit_parsed_event(&mut self, event: mitm_http::SseEvent) -> io::Result<()> {
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
        self.flow_hooks
            .on_stream_chunk(
                self.context.clone(),
                StreamChunk {
                    payload: bytes::Bytes::from(event.data),
                    sequence: sequence_no,
                    frame_kind: StreamFrameKind::SseData,
                },
            )
            .await;
        if is_done && !self.stream_ended {
            self.flow_hooks.on_stream_end(self.context.clone()).await;
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
    fn on_chunk<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
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
                self.emit_parsed_event(event).await?;
            }
            Ok(())
        })
    }

    fn on_complete<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(event) = self.parser.finish() {
                self.emit_parsed_event(event).await?;
            }
            if !self.stream_ended {
                self.flow_hooks.on_stream_end(self.context.clone()).await;
                self.stream_ended = true;
            }
            Ok(())
        })
    }
}
