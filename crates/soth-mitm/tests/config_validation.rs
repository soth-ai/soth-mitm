use soth_mitm::{MitmConfig, MitmError};

#[test]
fn reject_empty_interception_destinations() {
    let config = MitmConfig::default();
    let error = config
        .validate()
        .expect_err("destinations must be required");
    match error {
        MitmError::InvalidConfig(detail) => {
            assert!(detail.contains("interception.destinations"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn reject_invalid_destination_port() {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:notaport".to_string());

    let error = config.validate().expect_err("invalid port must fail");
    match error {
        MitmError::InvalidConfig(detail) => {
            assert!(detail.contains("invalid interception destination port"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn accept_minimal_valid_configuration() {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:443".to_string());

    config.validate().expect("minimal config should validate");
}

#[test]
fn reject_zero_body_size_limit() {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:443".to_string());
    config.body.max_size_bytes = 0;

    let error = config
        .validate()
        .expect_err("zero body size limit must fail");
    match error {
        MitmError::InvalidConfig(detail) => {
            assert!(detail.contains("body.max_size_bytes"));
        }
        other => panic!("unexpected error: {other}"),
    }
}
