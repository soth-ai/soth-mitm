fn parse_http3_passthrough_hint(connect_head: &[u8]) -> Option<&'static str> {
    let head = std::str::from_utf8(connect_head).ok()?;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(parts) => parts,
            None => continue,
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-proxy-protocol") && value.eq_ignore_ascii_case("h3") {
            return Some("x-proxy-protocol");
        }
        if name.eq_ignore_ascii_case("x-http3-passthrough")
            && (value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes"))
        {
            return Some("x-http3-passthrough");
        }
    }
    None
}

fn flow_action_label(action: FlowAction) -> &'static str {
    match action {
        FlowAction::Intercept => "intercept",
        FlowAction::Tunnel => "tunnel",
        FlowAction::Block => "block",
    }
}
