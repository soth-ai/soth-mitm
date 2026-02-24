use std::future::Future;

use bytes::Bytes;

use crate::{
    ConnectionInfo, ConnectionStats, HandlerAction, InterceptedRequest, InterceptedResponse,
    ResponseAction,
};

pub trait InterceptHandler: Send + Sync + 'static {
    fn on_request(
        &self,
        request: &InterceptedRequest,
        connection: &ConnectionInfo,
    ) -> impl Future<Output = HandlerAction> + Send;

    fn on_response(
        &self,
        _response: &InterceptedResponse,
        _connection: &ConnectionInfo,
    ) -> impl Future<Output = ResponseAction> + Send {
        async { ResponseAction::Forward }
    }

    fn on_stream_chunk(
        &self,
        chunk: &Bytes,
        _connection: &ConnectionInfo,
    ) -> impl Future<Output = Bytes> + Send {
        let cloned = chunk.clone();
        async move { cloned }
    }

    fn on_connection_open(&self, _connection: &ConnectionInfo) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn on_connection_close(
        &self,
        _connection: &ConnectionInfo,
        _stats: &ConnectionStats,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}
