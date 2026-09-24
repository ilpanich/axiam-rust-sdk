//! CONTRACT.md §1.1.1 and §10.3 (contract 1.51) — `validate_token` and
//! `introspect_token` over gRPC, against an in-process `TokenService`.
//!
//! What these pin, in §10.3's words: a `cnf`-bearing response is not treated
//! as a bearer token; an empty `CnfClaim` is refused; and — the positive
//! regression — an unbound response still validates. Around them, §1.1.1's
//! own rules: every field is modelled, the inspected token is not the
//! caller's, boundness comes from `cnf` and never from `token_type`, another
//! tenant's token is `valid: false` rather than an error, and no caller token
//! means no wire call.

#![cfg(feature = "grpc")]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axiam_sdk::grpc::r#gen::token_service_server::{TokenService, TokenServiceServer};
use axiam_sdk::grpc::r#gen::{
    CnfClaim as WireCnfClaim, IntrospectTokenRequest, IntrospectTokenResponse,
    RptPermission as WireRptPermission, ValidateTokenRequest, ValidateTokenResponse,
};
use axiam_sdk::grpc::{GrpcChannelConfig, TokenGrpcClient, TokenStatus, build_channel};
use axiam_sdk::token::refresh_guard::RefreshedTokens;
use axiam_sdk::token::{PresentedProofs, TokenManager};
use axiam_sdk::{AxiamError, Sensitive};
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status};
use uuid::Uuid;

const THUMBPRINT: &str = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";
const OTHER_THUMBPRINT: &str = "SdNmN7ixdrq3uSR8dPxHiRdrpuuTj0Hjwp9-SQ7wWbw";
const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
const CALLER_TOKEN: &str = "caller-access-token";
const INSPECTED_TOKEN: &str = "inspected-device-token";

/// What the stub answers, and what it saw.
#[derive(Clone, Default)]
struct Script {
    valid: bool,
    cnf: Option<WireCnfClaim>,
    token_type: String,
    unauthenticated_once: Arc<AtomicBool>,
    fire_unauthenticated: bool,
    calls: Arc<AtomicUsize>,
    /// (authorization metadata, request.access_token) per call.
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

struct Stub(Script);

impl Stub {
    fn record<T>(&self, request: &Request<T>, inspected: &str) -> Result<(), Status> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        let auth = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        self.0
            .seen
            .lock()
            .unwrap()
            .push((auth, inspected.to_string()));
        if self.0.fire_unauthenticated && !self.0.unauthenticated_once.swap(true, Ordering::SeqCst)
        {
            return Err(Status::unauthenticated("caller token expired"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl TokenService for Stub {
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let inspected = request.get_ref().access_token.clone();
        self.record(&request, &inspected)?;
        let s = &self.0;
        Ok(Response::new(if s.valid {
            ValidateTokenResponse {
                valid: true,
                subject_id: "sub-1".into(),
                tenant_id: "tenant-1".into(),
                org_id: "org-1".into(),
                exp: 1_900_000_000,
                cnf: s.cnf.clone(),
                token_type: s.token_type.clone(),
            }
        } else {
            // What the server answers for a token of another tenant (§1.1.1
            // rule 6): not an error — inactive, empty, no `cnf`.
            ValidateTokenResponse::default()
        }))
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        let inspected = request.get_ref().access_token.clone();
        self.record(&request, &inspected)?;
        let s = &self.0;
        Ok(Response::new(IntrospectTokenResponse {
            active: s.valid,
            sub: "sub-1".into(),
            tenant_id: "tenant-1".into(),
            org_id: "org-1".into(),
            iss: "https://iam.example.com".into(),
            iat: 1_899_999_100,
            exp: 1_900_000_000,
            jti: "jti-1".into(),
            scope: "read write".into(),
            client_id: String::new(),
            token_type: s.token_type.clone(),
            cnf: s.cnf.clone(),
            permissions: vec![WireRptPermission {
                resource_id: "res-1".into(),
                resource_scopes: vec!["view".into()],
                exp: 1_900_000_000,
            }],
            ext_exchange_iss: "https://partner.example".into(),
        }))
    }
}

async fn serve(script: Script) -> SocketAddr {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    let addr = incoming.local_addr().expect("local_addr");
    tokio::spawn(async move {
        Server::builder()
            .add_service(TokenServiceServer::new(Stub(script)))
            .serve_with_incoming(incoming)
            .await
            .expect("stub TokenService");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

fn refresh_counter(counter: Arc<AtomicUsize>) -> axiam_sdk::grpc::RefreshFn {
    Arc::new(move |_refresh: String| {
        let counter = Arc::clone(&counter);
        let fut: Pin<Box<dyn Future<Output = Result<RefreshedTokens, AxiamError>> + Send>> =
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(RefreshedTokens {
                    access: Sensitive::new("rotated-caller-token".to_string()),
                    refresh: Some(Sensitive::new("rotated-refresh".to_string())),
                    exp: Some(9_999_999_999),
                    tenant_id: None,
                })
            });
        fut
    })
}

async fn client(addr: SocketAddr, logged_in: bool, refreshes: Arc<AtomicUsize>) -> TokenGrpcClient {
    let manager = Arc::new(TokenManager::new());
    if logged_in {
        manager
            .set_tokens(
                Sensitive::new(CALLER_TOKEN.to_string()),
                Some(Sensitive::new("refresh".to_string())),
                Some(9_999_999_999),
                None,
            )
            .await;
    }
    let channel =
        build_channel(&format!("http://{addr}"), &GrpcChannelConfig::default()).expect("channel");
    TokenGrpcClient::new(channel, manager, Uuid::new_v4(), refresh_counter(refreshes))
}

fn inspected() -> Sensitive<String> {
    Sensitive::new(INSPECTED_TOKEN.to_string())
}

fn bound_to(x5t: &str, jkt: &str) -> Option<WireCnfClaim> {
    Some(WireCnfClaim {
        x5t_s256: x5t.into(),
        jkt: jkt.into(),
    })
}

// ---------------------------------------------------------------------------

/// The positive regression §10.3 names: an unbound response still validates,
/// with or without proofs — rule 9 must not become "every caller presents a
/// proof".
#[tokio::test]
async fn an_unbound_token_still_validates() {
    let script = Script {
        valid: true,
        token_type: "Bearer".into(),
        ..Script::default()
    };
    let addr = serve(script).await;
    let c = client(addr, true, Arc::default()).await;

    let v = c.validate_token(&inspected()).await.expect("validate");

    assert!(v.valid);
    assert_eq!(v.cnf, None, "absent stays absent");
    assert_eq!(v.status(), TokenStatus::Bearer);
    v.verify_possession(PresentedProofs::default())
        .expect("unbound: no proof needed");
    v.verify_possession(PresentedProofs {
        certificate_thumbprint: Some(THUMBPRINT),
        dpop_thumbprint: None,
    })
    .expect("unbound: a proof is not required, and not held against it");
}

/// Rules 4 and 5: a certificate-bound token is reported `"Bearer"` by the
/// server, and `valid: true` — and is still not usable by a presenter without
/// the certificate. Boundness is read from `cnf`, never from `token_type`.
#[tokio::test]
async fn a_certificate_bound_token_is_not_a_bearer_token() {
    let script = Script {
        valid: true,
        token_type: "Bearer".into(),
        cnf: bound_to(THUMBPRINT, ""),
        ..Script::default()
    };
    let addr = serve(script).await;
    let c = client(addr, true, Arc::default()).await;

    let v = c.validate_token(&inspected()).await.expect("validate");

    assert!(v.valid);
    assert_eq!(v.token_type, "Bearer", "the server says Bearer…");
    assert_eq!(
        v.status(),
        TokenStatus::SenderConstrained,
        "…and the SDK still reads the token as bound"
    );
    assert_eq!(
        v.cnf.as_ref().and_then(|c| c.x5t_s256.as_deref()),
        Some(THUMBPRINT)
    );
    assert_eq!(
        v.cnf.as_ref().and_then(|c| c.jkt.clone()),
        None,
        "an empty proto3 member is an absent member"
    );

    let none = PresentedProofs::default();
    let wrong = PresentedProofs {
        certificate_thumbprint: Some(OTHER_THUMBPRINT),
        dpop_thumbprint: None,
    };
    let right = PresentedProofs {
        certificate_thumbprint: Some(THUMBPRINT),
        dpop_thumbprint: None,
    };
    assert!(matches!(
        v.verify_possession(none),
        Err(AxiamError::Auth { .. })
    ));
    assert!(matches!(
        v.verify_possession(wrong),
        Err(AxiamError::Auth { .. })
    ));
    v.verify_possession(right)
        .expect("the certificate it names");
}

/// §10.3 rule 3: a `CnfClaim` with both members empty is refused, not read as
/// unbound. Present-but-empty is distinct from absent.
#[tokio::test]
async fn an_empty_cnf_claim_is_refused() {
    let script = Script {
        valid: true,
        token_type: "Bearer".into(),
        cnf: bound_to("", ""),
        ..Script::default()
    };
    let addr = serve(script).await;
    let c = client(addr, true, Arc::default()).await;

    let v = c.validate_token(&inspected()).await.expect("validate");

    assert!(v.cnf.is_some(), "present, not absent");
    assert_eq!(v.status(), TokenStatus::Unverifiable);
    for proofs in [
        PresentedProofs::default(),
        PresentedProofs {
            certificate_thumbprint: Some(THUMBPRINT),
            dpop_thumbprint: Some(JKT),
        },
    ] {
        assert!(
            v.verify_possession(proofs).is_err(),
            "nothing satisfies an empty confirmation"
        );
    }
}

/// Rule 6: a token of another tenant comes back `valid: false`, and that is an
/// answer, not an error.
#[tokio::test]
async fn another_tenants_token_is_invalid_not_an_error() {
    let addr = serve(Script::default()).await;
    let c = client(addr, true, Arc::default()).await;

    let v = c
        .validate_token(&inspected())
        .await
        .expect("an inactive token is not a failed call");

    assert!(!v.valid);
    assert_eq!(v.cnf, None);
    assert_eq!(v.status(), TokenStatus::Inactive);
    assert!(v.verify_possession(PresentedProofs::default()).is_err());
}

/// Rule 1: two tokens, kept apart. The caller's authenticates the call; the
/// inspected one travels in the message. Neither stands in for the other.
#[tokio::test]
async fn the_inspected_token_is_not_the_callers() {
    let script = Script {
        valid: true,
        token_type: "Bearer".into(),
        ..Script::default()
    };
    let seen = Arc::clone(&script.seen);
    let addr = serve(script).await;
    let c = client(addr, true, Arc::default()).await;

    c.validate_token(&inspected()).await.unwrap();
    c.introspect_token(&inspected()).await.unwrap();

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    for (authorization, message_token) in seen {
        assert_eq!(authorization, format!("Bearer {CALLER_TOKEN}"));
        assert_eq!(message_token, INSPECTED_TOKEN);
    }
}

/// Rule 2: no caller token, no wire call — `AuthError`, and the server never
/// hears of it.
#[tokio::test]
async fn without_a_caller_token_there_is_no_wire_call() {
    let script = Script::default();
    let calls = Arc::clone(&script.calls);
    let addr = serve(script).await;
    let refreshes = Arc::new(AtomicUsize::new(0));
    let c = client(addr, false, Arc::clone(&refreshes)).await;

    for err in [
        c.validate_token(&inspected())
            .await
            .map(|_| ())
            .unwrap_err(),
        c.introspect_token(&inspected())
            .await
            .map(|_| ())
            .unwrap_err(),
    ] {
        assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
}

/// Rule 3 for `introspect_token`: every RFC 7662 field, with a `jkt` binding —
/// which only a verified DPoP proof satisfies.
#[tokio::test]
async fn introspection_models_every_field_and_reads_jkt() {
    let script = Script {
        valid: true,
        token_type: "DPoP".into(),
        cnf: bound_to("", JKT),
        ..Script::default()
    };
    let addr = serve(script).await;
    let c = client(addr, true, Arc::default()).await;

    let i = c.introspect_token(&inspected()).await.expect("introspect");

    assert!(i.active);
    assert_eq!(
        (i.sub.as_str(), i.tenant_id.as_str(), i.org_id.as_str()),
        ("sub-1", "tenant-1", "org-1")
    );
    assert_eq!(i.iss, "https://iam.example.com");
    assert_eq!((i.iat, i.exp), (1_899_999_100, 1_900_000_000));
    assert_eq!(i.jti, "jti-1");
    assert_eq!(i.scope.as_deref(), Some("read write"));
    assert_eq!(i.client_id, None, "an empty proto3 string is absent");
    assert_eq!(
        i.ext_exchange_iss.as_deref(),
        Some("https://partner.example")
    );
    assert_eq!(i.permissions.len(), 1);
    assert_eq!(i.permissions[0].resource_id, "res-1");
    assert_eq!(i.permissions[0].resource_scopes, vec!["view".to_string()]);
    assert_eq!(i.status(), TokenStatus::SenderConstrained);

    assert!(
        i.verify_possession(PresentedProofs {
            certificate_thumbprint: Some(THUMBPRINT),
            dpop_thumbprint: None,
        })
        .is_err(),
        "a certificate does not satisfy a DPoP binding"
    );
    i.verify_possession(PresentedProofs {
        certificate_thumbprint: None,
        dpop_thumbprint: Some(JKT),
    })
    .expect("the verified proof's key");
}

/// §9 applies to the **caller's** token: `UNAUTHENTICATED` refreshes it once
/// and retries once. The inspected token is untouched by the refresh.
#[tokio::test]
async fn unauthenticated_refreshes_the_callers_token_and_retries_once() {
    let script = Script {
        valid: true,
        token_type: "Bearer".into(),
        fire_unauthenticated: true,
        ..Script::default()
    };
    let (calls, seen) = (Arc::clone(&script.calls), Arc::clone(&script.seen));
    let addr = serve(script).await;
    let refreshes = Arc::new(AtomicUsize::new(0));
    let c = client(addr, true, Arc::clone(&refreshes)).await;

    let v = c.validate_token(&inspected()).await.expect("after refresh");

    assert!(v.valid);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen[1].0, "Bearer rotated-caller-token");
    assert_eq!(seen[1].1, INSPECTED_TOKEN);
}
