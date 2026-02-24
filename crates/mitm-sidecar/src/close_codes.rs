#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReasonCode {
    Blocked,
    ConnectParseFailed,
    TlsHandshakeFailed,
    RoutePlannerFailed,
    UpstreamConnectFailed,
    RelayEof,
    RelayError,
    IdleWatchdogTimeout,
    StreamStageTimeout,
    MitmHttpCompleted,
    MitmHttpError,
    WebSocketCompleted,
    WebSocketError,
}

impl CloseReasonCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::ConnectParseFailed => "connect_parse_failed",
            Self::TlsHandshakeFailed => "tls_handshake_failed",
            Self::RoutePlannerFailed => "route_planner_failed",
            Self::UpstreamConnectFailed => "upstream_connect_failed",
            Self::RelayEof => "relay_eof",
            Self::RelayError => "relay_error",
            Self::IdleWatchdogTimeout => "idle_watchdog_timeout",
            Self::StreamStageTimeout => "stream_stage_timeout",
            Self::MitmHttpCompleted => "mitm_http_completed",
            Self::MitmHttpError => "mitm_http_error",
            Self::WebSocketCompleted => "websocket_completed",
            Self::WebSocketError => "websocket_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseFailureCode {
    IncompleteHeaders,
    HeaderTooLarge,
    ReadError,
    Parser(ConnectParseError),
}

impl ParseFailureCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::IncompleteHeaders => "incomplete_headers",
            Self::HeaderTooLarge => "header_too_large",
            Self::ReadError => "read_error",
            Self::Parser(code) => code.code(),
        }
    }
}
