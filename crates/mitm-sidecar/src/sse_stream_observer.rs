struct SseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    parser: mitm_http::SseParser,
    next_sequence_no: u64,
}

impl<P, S> SseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    fn new(engine: Arc<MitmEngine<P, S>>, context: FlowContext) -> Self {
        Self {
            engine,
            context,
            parser: mitm_http::SseParser::new(),
            next_sequence_no: 1,
        }
    }

    fn emit_parsed_event(&mut self, event: mitm_http::SseEvent) {
        let sequence_no = self.next_sequence_no;
        self.next_sequence_no += 1;
        emit_sse_event(&self.engine, self.context.clone(), sequence_no, &event);
    }
}

impl<P, S> HttpBodyObserver for SseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    fn on_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        for event in self.parser.push_bytes(chunk) {
            self.emit_parsed_event(event);
        }
        Ok(())
    }

    fn on_complete(&mut self) -> io::Result<()> {
        if let Some(event) = self.parser.finish() {
            self.emit_parsed_event(event);
        }
        Ok(())
    }
}
