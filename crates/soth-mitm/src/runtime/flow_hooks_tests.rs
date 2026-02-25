use super::{
    parse_unix_client_addr_meta, process_info_from_unix_client_addr,
    socket_family_from_flow_context,
};
use mitm_http::ApplicationProtocol;
use mitm_observe::FlowContext;
use std::path::PathBuf;

#[test]
fn parses_unix_client_addr_metadata() {
    let parsed = parse_unix_client_addr_meta("unix:pid=4242,path=/tmp/soth-mitm.sock")
        .expect("unix metadata should parse");
    assert_eq!(parsed.pid, Some(4242));
    assert_eq!(parsed.path, Some(PathBuf::from("/tmp/soth-mitm.sock")));
}

#[test]
fn unix_client_addr_maps_socket_family_and_process_info() {
    let context = FlowContext {
        flow_id: 9,
        client_addr: "unix:pid=1234,path=/tmp/soth.sock".to_string(),
        server_host: "127.0.0.1".to_string(),
        server_port: 11434,
        protocol: ApplicationProtocol::Http1,
    };
    let socket_family = socket_family_from_flow_context(&context);
    assert!(matches!(
        socket_family,
        crate::types::SocketFamily::UnixDomain { .. }
    ));
    let process = process_info_from_unix_client_addr(&context.client_addr)
        .expect("pid metadata should map to process info");
    assert_eq!(process.pid, 1234);
}
