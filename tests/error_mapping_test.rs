//! `AxiamError::from_http_status`/`from_grpc_code` (`src/error.rs`)
//! CONTRACT.md §2 status-table branch coverage, plus the best-effort
//! `action`/`resource_id` extraction on the `Authz` variant. These are pure
//! functions with no transport dependency, so they are exercised directly
//! rather than through a mock HTTP/gRPC server (already covered end-to-end
//! by `tests/login_mfa_flow_test.rs` and `tests/grpc_check_access_test.rs`
//! for the handful of codes those flows naturally produce; this file fills
//! in the remaining table entries).

use axiam_sdk::AxiamError;

#[test]
fn http_400_maps_to_network() {
    assert!(matches!(
        AxiamError::from_http_status(400, "bad request"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn http_401_maps_to_auth() {
    assert!(matches!(
        AxiamError::from_http_status(401, "unauthorized"),
        AxiamError::Auth { .. }
    ));
}

#[test]
fn http_403_maps_to_authz() {
    assert!(matches!(
        AxiamError::from_http_status(403, "forbidden"),
        AxiamError::Authz { .. }
    ));
}

#[test]
fn http_408_maps_to_network() {
    assert!(matches!(
        AxiamError::from_http_status(408, "request timeout"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn http_409_maps_to_authz() {
    assert!(matches!(
        AxiamError::from_http_status(409, "conflict"),
        AxiamError::Authz { .. }
    ));
}

#[test]
fn http_429_maps_to_network() {
    assert!(matches!(
        AxiamError::from_http_status(429, "rate limited"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn http_5xx_maps_to_network() {
    for status in [500, 502, 503, 504] {
        assert!(
            matches!(
                AxiamError::from_http_status(status, "server error"),
                AxiamError::Network { .. }
            ),
            "status {status} must map to Network"
        );
    }
}

#[test]
fn http_unrecognized_status_defaults_to_network() {
    assert!(matches!(
        AxiamError::from_http_status(418, "i'm a teapot"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn authz_body_fields_are_extracted_from_structured_403_body() {
    let body = r#"{"error":"authorization_denied","message":"nope","action":"users:delete","resource_id":"11111111-1111-1111-1111-111111111111"}"#;
    match AxiamError::from_http_status(403, body) {
        AxiamError::Authz {
            action,
            resource_id,
            ..
        } => {
            assert_eq!(action.as_deref(), Some("users:delete"));
            assert_eq!(
                resource_id.as_deref(),
                Some("11111111-1111-1111-1111-111111111111")
            );
        }
        other => panic!("expected Authz, got {other:?}"),
    }
}

#[test]
fn authz_body_fields_are_none_for_a_non_json_body() {
    match AxiamError::from_http_status(403, "plain text, not JSON") {
        AxiamError::Authz {
            action,
            resource_id,
            message,
        } => {
            assert!(action.is_none());
            assert!(resource_id.is_none());
            assert_eq!(message, "plain text, not JSON");
        }
        other => panic!("expected Authz, got {other:?}"),
    }
}

#[test]
fn authz_body_fields_are_none_when_json_omits_them() {
    let body = r#"{"error":"authorization_denied","message":"nope"}"#;
    match AxiamError::from_http_status(409, body) {
        AxiamError::Authz {
            action,
            resource_id,
            ..
        } => {
            assert!(action.is_none());
            assert!(resource_id.is_none());
        }
        other => panic!("expected Authz, got {other:?}"),
    }
}

#[test]
fn grpc_unauthenticated_maps_to_auth() {
    assert!(matches!(
        AxiamError::from_grpc_code(16, "no valid auth"),
        AxiamError::Auth { .. }
    ));
}

#[test]
fn grpc_permission_denied_maps_to_authz_with_no_structured_fields() {
    match AxiamError::from_grpc_code(7, "denied") {
        AxiamError::Authz {
            action,
            resource_id,
            ..
        } => {
            assert!(
                action.is_none() && resource_id.is_none(),
                "gRPC PERMISSION_DENIED carries no structured error body"
            );
        }
        other => panic!("expected Authz, got {other:?}"),
    }
}

#[test]
fn grpc_unavailable_maps_to_network() {
    assert!(matches!(
        AxiamError::from_grpc_code(14, "unavailable"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn grpc_deadline_exceeded_maps_to_network() {
    assert!(matches!(
        AxiamError::from_grpc_code(4, "deadline exceeded"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn grpc_internal_maps_to_network() {
    assert!(matches!(
        AxiamError::from_grpc_code(13, "internal"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn grpc_resource_exhausted_maps_to_network() {
    assert!(matches!(
        AxiamError::from_grpc_code(8, "rate limited"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn grpc_unrecognized_code_defaults_to_network() {
    assert!(matches!(
        AxiamError::from_grpc_code(2, "unknown"),
        AxiamError::Network { .. }
    ));
}

#[test]
fn display_impls_render_the_message_for_each_variant() {
    let auth = AxiamError::Auth {
        message: "auth msg".into(),
    };
    assert!(format!("{auth}").contains("auth msg"));

    let authz = AxiamError::Authz {
        message: "authz msg".into(),
        action: None,
        resource_id: None,
    };
    assert!(format!("{authz}").contains("authz msg"));

    let network = AxiamError::Network {
        message: "network msg".into(),
        source: None,
    };
    assert!(format!("{network}").contains("network msg"));
}
