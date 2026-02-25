impl<P, S> SidecarServer<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    pub async fn run_until_shutdown(
        self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> io::Result<()> {
        if *shutdown_rx.borrow() {
            return Ok(());
        }

        tokio::select! {
            result = self.run() => result,
            changed = shutdown_rx.changed() => {
                match changed {
                    Ok(_) => Ok(()),
                    Err(_) => Ok(()),
                }
            }
        }
    }
}
