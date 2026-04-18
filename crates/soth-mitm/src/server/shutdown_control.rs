use super::SidecarServer;
use crate::observe::EventConsumer;
use crate::policy::PolicyEngine;
use std::io;

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

    pub async fn run_until_shutdown_with_listener(
        self,
        listener: tokio::net::TcpListener,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> io::Result<()> {
        if *shutdown_rx.borrow() {
            return Ok(());
        }
        tokio::select! {
            result = self.run_with_external_listener(listener) => result,
            changed = shutdown_rx.changed() => {
                match changed {
                    Ok(_) => Ok(()),
                    Err(_) => Ok(()),
                }
            }
        }
    }
}
