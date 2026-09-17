//! CONTRACT.md §28.9 required tests 1 and 2 — the two that need no Actix
//! app: the document's shape and its validation negatives, and the
//! challenge's quoting and its refusals.
//!
//! §28.9 asks for the same five assertions, on the same fixtures, in every
//! SDK repository, so that a divergence shows up as a different expected
//! value rather than as a different test. This file and
//! `tests/mcp_actix_test.rs` are that suite for Rust, ported from the
//! TypeScript reference implementation's `test/middleware/mcp.contract.test.ts`
//! / `test/middleware/mcp.express.test.ts` (T21.9b):
//!
//! 1. document shape + validation negatives .......... here
//! 2. challenge quoting + refusals ..................... here
//! 3. 401 with the challenge ........................... mcp_actix_test.rs
//! 4. 403 insufficient_scope ........................... mcp_actix_test.rs
//! 5. a token whose `aud` is not the resource .......... mcp_actix_test.rs
//! + the regression that matters more than all five ..... mcp_actix_test.rs
//!
//! A few of the TypeScript port's sub-assertions have no Rust counterpart
//! because Rust's type system makes the scenario unrepresentable rather
//! than merely invalid at runtime — noted inline where they are skipped:
//! `authorization_servers` cannot carry a non-string entry (it is `Vec<String>`),
//! and `bearer_challenge`'s `error` cannot be an OAuth code RFC 6750 §3.1 does
//! not define (`BearerChallengeError` is a closed three-variant enum).

#![cfg(feature = "actix")]

use axiam_sdk::management::ValidationError;
use axiam_sdk::middleware::{
    BearerChallengeError, BearerChallengeOptions, ProtectedResourceMetadataOptions,
    bearer_challenge, protected_resource_metadata,
};

/// §28.9's configuration, as its table spells it.
fn fixture() -> ProtectedResourceMetadataOptions {
    ProtectedResourceMetadataOptions::new(
        "https://mcp.example.com/mcp",
        vec!["https://axiam.example.com".to_string()],
    )
    .scopes_supported(vec!["mcp:read".to_string(), "mcp:tools".to_string()])
    .resource_documentation("https://mcp.example.com/docs")
}

const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const METADATA_URL: &str = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

fn no_credential_vector() -> String {
    format!("Bearer resource_metadata=\"{METADATA_URL}\"")
}
fn invalid_token_vector() -> String {
    format!("Bearer error=\"invalid_token\", resource_metadata=\"{METADATA_URL}\"")
}
fn insufficient_scope_vector() -> String {
    format!(
        "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"{METADATA_URL}\""
    )
}
fn all_four_vector() -> String {
    format!(
        "Bearer error=\"invalid_request\", error_description=\"The access token is malformed\", scope=\"mcp:read mcp:tools\", resource_metadata=\"{METADATA_URL}\""
    )
}

/// Assert that `options` is refused as a `ValidationError` (CONTRACT.md §2 —
/// §28 adds no new error type).
fn assert_refuses(options: ProtectedResourceMetadataOptions) -> ValidationError {
    let err = protected_resource_metadata(options).expect_err("the configuration must be refused");
    err.validation()
        .expect("a §28 refusal must carry a ValidationError")
        .clone()
}

// ---------------------------------------------------------------------------
// §28.9 test 1 — document shape, and the validation negatives
// ---------------------------------------------------------------------------

#[test]
fn produces_the_exact_json_of_28_2_from_the_fixture() {
    let metadata = protected_resource_metadata(fixture()).expect("fixture is valid");

    // §28.2: member order in JSON is not semantically significant, so this
    // compares parsed values first...
    let value = serde_json::to_value(&metadata.document).expect("serializable");
    assert_eq!(
        value,
        serde_json::json!({
            "resource": "https://mcp.example.com/mcp",
            "authorization_servers": ["https://axiam.example.com"],
            "scopes_supported": ["mcp:read", "mcp:tools"],
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://mcp.example.com/docs",
        }),
    );
    // ...but the order is still fixed in the emitted bytes, so that an
    // implementation has one obvious answer.
    let keys: Vec<&String> = value.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        vec![
            "resource",
            "authorization_servers",
            "scopes_supported",
            "bearer_methods_supported",
            "resource_documentation",
        ]
    );
    assert_eq!(metadata.metadata_path, METADATA_PATH);
    assert_eq!(metadata.metadata_url, METADATA_URL);
}

#[test]
fn derives_every_metadata_path_in_28_3s_table() {
    // A trailing slash is carried through rather than trimmed: it is part of
    // the resource identifier the client will compare, and two resources
    // that differ only by it are two resources.
    let cases = [
        (
            "https://mcp.example.com",
            "/.well-known/oauth-protected-resource",
        ),
        (
            "https://mcp.example.com/",
            "/.well-known/oauth-protected-resource",
        ),
        (
            "https://mcp.example.com/mcp",
            "/.well-known/oauth-protected-resource/mcp",
        ),
        (
            "https://mcp.example.com/mcp/",
            "/.well-known/oauth-protected-resource/mcp/",
        ),
        (
            "https://mcp.example.com/a/b",
            "/.well-known/oauth-protected-resource/a/b",
        ),
    ];
    for (resource, metadata_path) in cases {
        let options = ProtectedResourceMetadataOptions {
            resource: resource.to_string(),
            ..fixture()
        };
        let metadata = protected_resource_metadata(options).unwrap_or_else(|e| {
            panic!("{resource} must be accepted: {e}");
        });
        assert_eq!(metadata.metadata_path, metadata_path, "{resource}");
        assert_eq!(
            metadata.metadata_url,
            format!("https://mcp.example.com{metadata_path}"),
            "{resource}"
        );
        // The document keeps the resource exactly as written — nothing is
        // normalised, and the trailing slash of the fourth row survives.
        assert_eq!(metadata.document.resource, resource, "{resource}");
    }
}

#[test]
fn refuses_a_resource_that_is_relative_or_carries_a_fragment_or_a_query() {
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "/mcp".to_string(),
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "mcp.example.com/mcp".to_string(),
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "https://mcp.example.com/mcp#tools".to_string(),
        ..fixture()
    });
    // §28.3 derives the document's own URL from this value and a query makes
    // that derivation ambiguous — so §28 forbids what RFC 8707 permits.
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "https://mcp.example.com/mcp?tenant_id=acme".to_string(),
        ..fixture()
    });
}

#[test]
fn refuses_http_on_a_routable_host_and_accepts_it_on_loopback() {
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "http://mcp.example.com/mcp".to_string(),
        ..fixture()
    });

    let loopback = protected_resource_metadata(ProtectedResourceMetadataOptions {
        resource: "http://127.0.0.1:8080/mcp".to_string(),
        authorization_servers: vec!["http://localhost:9000".to_string()],
        ..fixture()
    })
    .expect("loopback http is accepted");
    assert_eq!(loopback.document.resource, "http://127.0.0.1:8080/mcp");
    assert_eq!(
        loopback.metadata_url,
        "http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp"
    );

    // The carve-out is the host, not a substring of it: an authority whose
    // userinfo merely reads `localhost` resolves to a routable host.
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "http://localhost@evil.example.com/mcp".to_string(),
        ..fixture()
    });

    // §28.2 rule 2 names three hosts; `[::1]` is the third, and the brackets
    // are part of the host rather than punctuation around it.
    let v6 = protected_resource_metadata(ProtectedResourceMetadataOptions {
        resource: "http://[::1]:8080/mcp".to_string(),
        authorization_servers: vec!["http://[::1]:9000".to_string()],
        ..fixture()
    })
    .expect("[::1] is a loopback host");
    assert_eq!(
        v6.metadata_url,
        "http://[::1]:8080/.well-known/oauth-protected-resource/mcp"
    );
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: "http://[2001:db8::1]:8080/mcp".to_string(),
        ..fixture()
    });

    // An empty value is a refusal, not an empty document. (A non-string
    // entry is not representable at all — `authorization_servers` is
    // `Vec<String>` — where the TypeScript port needed a runtime check,
    // Rust's type system rules the case out entirely.)
    assert_refuses(ProtectedResourceMetadataOptions {
        resource: String::new(),
        ..fixture()
    });
}

#[test]
fn refuses_an_empty_authorization_servers_and_an_entry_with_a_query_a_fragment_or_a_duplicate() {
    // A document that names no authorization server answers none of the
    // question the client asked.
    assert_refuses(ProtectedResourceMetadataOptions {
        authorization_servers: vec![],
        ..fixture()
    });
    // §28.2 rule 4: the tenant travels as `?tenant_id=` on the individual
    // endpoint URLs and never on the issuer. An entry with one is not an
    // issuer, and no token's `iss` would ever equal it.
    assert_refuses(ProtectedResourceMetadataOptions {
        authorization_servers: vec!["https://axiam.example.com?tenant_id=a".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        authorization_servers: vec!["https://axiam.example.com#frag".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        authorization_servers: vec![
            "https://axiam.example.com".to_string(),
            "https://axiam.example.com".to_string(),
        ],
        ..fixture()
    });
}

#[test]
fn refuses_a_duplicate_scope_and_a_scope_token_outside_nqchar_and_preserves_order() {
    assert_refuses(ProtectedResourceMetadataOptions {
        scopes_supported: vec!["mcp:read".to_string(), "mcp:read".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        scopes_supported: vec!["mcp read".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        scopes_supported: vec!["mcp:\"read\"".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        scopes_supported: vec![String::new()],
        ..fixture()
    });

    // The order is the caller's, never sorted: `scopes_supported` is what
    // the operator chose to publish, in the form they chose to publish it.
    let reordered = protected_resource_metadata(ProtectedResourceMetadataOptions {
        scopes_supported: vec!["mcp:tools".to_string(), "mcp:read".to_string()],
        ..fixture()
    })
    .expect("valid scopes");
    assert_eq!(
        reordered.document.scopes_supported,
        vec!["mcp:tools".to_string(), "mcp:read".to_string()]
    );
}

#[test]
fn refuses_any_bearer_methods_supported_that_is_not_exactly_header() {
    // §10's guard reads a bearer credential from the `Authorization` header
    // alone, so `body` or `query` would describe behaviour no conformant SDK
    // has.
    assert_refuses(ProtectedResourceMetadataOptions {
        bearer_methods_supported: vec!["query".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        bearer_methods_supported: vec!["header".to_string(), "body".to_string()],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        bearer_methods_supported: vec![],
        ..fixture()
    });
    assert_refuses(ProtectedResourceMetadataOptions {
        bearer_methods_supported: vec!["header".to_string(), "header".to_string()],
        ..fixture()
    });

    // The default (unset in `ProtectedResourceMetadataOptions::new`) is the
    // only accepted value.
    let defaulted = protected_resource_metadata(ProtectedResourceMetadataOptions::new(
        fixture().resource,
        fixture().authorization_servers,
    ))
    .expect("default bearer_methods_supported is accepted");
    assert_eq!(
        defaulted.document.bearer_methods_supported,
        vec!["header".to_string()]
    );
}

#[test]
fn omits_scopes_supported_when_empty_and_resource_documentation_when_absent_never_null() {
    let bare = protected_resource_metadata(ProtectedResourceMetadataOptions::new(
        fixture().resource,
        fixture().authorization_servers,
    ))
    .expect("bare fixture is valid");

    let json = serde_json::to_value(&bare.document).expect("serializable");
    assert_eq!(
        json,
        serde_json::json!({
            "resource": "https://mcp.example.com/mcp",
            "authorization_servers": ["https://axiam.example.com"],
            "bearer_methods_supported": ["header"],
        }),
    );
    // An empty `scopes_supported` would assert that this resource server
    // understands no scopes — a different and almost always false claim.
    // And an explicit `null` is not an omission.
    assert!(json.get("scopes_supported").is_none());
    assert!(json.get("resource_documentation").is_none());
    let raw = serde_json::to_string(&bare.document).expect("serializable");
    assert!(!raw.contains("null"));
}

#[test]
fn accepts_a_resource_documentation_with_a_query_and_a_fragment() {
    // It is a page, not an identifier.
    let metadata = protected_resource_metadata(ProtectedResourceMetadataOptions {
        resource_documentation: Some("https://mcp.example.com/docs?v=2#tools".to_string()),
        ..fixture()
    })
    .expect("query + fragment permitted");
    assert_eq!(
        metadata.document.resource_documentation.as_deref(),
        Some("https://mcp.example.com/docs?v=2#tools")
    );
    assert_refuses(ProtectedResourceMetadataOptions {
        resource_documentation: Some("http://docs.example.com/mcp".to_string()),
        ..fixture()
    });
}

// ---------------------------------------------------------------------------
// §28.9 test 2 — challenge quoting
// ---------------------------------------------------------------------------

#[test]
fn produces_28_4s_four_vectors_as_exact_strings() {
    assert_eq!(
        bearer_challenge(BearerChallengeOptions::new(METADATA_URL)).unwrap(),
        no_credential_vector()
    );

    assert_eq!(
        bearer_challenge(
            BearerChallengeOptions::new(METADATA_URL).error(BearerChallengeError::InvalidToken)
        )
        .unwrap(),
        invalid_token_vector()
    );

    assert_eq!(
        bearer_challenge(
            BearerChallengeOptions::new(METADATA_URL)
                .error(BearerChallengeError::InsufficientScope)
                .scope("mcp:tools")
        )
        .unwrap(),
        insufficient_scope_vector()
    );

    // The parameter order is fixed — error, error_description, scope,
    // resource_metadata — and the separator is exactly one comma and one
    // space, so that these are exact strings rather than a set a test has to
    // re-parse.
    assert_eq!(
        bearer_challenge(
            BearerChallengeOptions::new(METADATA_URL)
                .error(BearerChallengeError::InvalidRequest)
                .error_description("The access token is malformed")
                .scope("mcp:read mcp:tools")
        )
        .unwrap(),
        all_four_vector()
    );
}

// `refuses an error code RFC 6750 §3.1 does not define` has no Rust
// counterpart: `BearerChallengeError` is a closed three-variant enum, so a
// fourth value (e.g. the token-endpoint-only `invalid_grant`) cannot be
// constructed at all — a stricter guarantee than the TypeScript port's
// runtime refusal of it.

#[test]
fn refuses_rather_than_escapes_an_error_description_outside_nqschar() {
    // RFC 6750 §3 restricts each parameter to a character set that cannot
    // contain `"` or `\`, so a value needing an escape is a value that does
    // not belong in a challenge.
    for error_description in [
        "he said \"no\"",
        "a back\\slash",
        "two\nlines",
        "a control\u{7}",
        "non-ASCII: café",
        "",
    ] {
        let err = bearer_challenge(
            BearerChallengeOptions::new(METADATA_URL)
                .error(BearerChallengeError::InvalidRequest)
                .error_description(error_description),
        )
        .expect_err(error_description);
        // No escaping occurred: the refusal is an error, never a challenge
        // carrying `\"`.
        assert!(!err.to_string().contains("\\\""), "{error_description}");
    }
}

#[test]
fn refuses_a_scope_with_a_leading_trailing_or_doubled_space_or_an_empty_one() {
    for scope in [
        " mcp:read",
        "mcp:read ",
        "mcp:read  mcp:tools",
        "",
        " ",
        "mcp:\"read\"",
    ] {
        bearer_challenge(
            BearerChallengeOptions::new(METADATA_URL)
                .error(BearerChallengeError::InsufficientScope)
                .scope(scope),
        )
        .expect_err(scope);
    }
}

#[test]
fn refuses_a_resource_metadata_that_is_not_an_encoded_absolute_url() {
    // A correctly encoded URL cannot contain a space, a quote or a
    // backslash, so one that does has not been encoded.
    for resource_metadata_url in [
        "https://mcp.example.com/.well-known/oauth protected resource",
        "https://mcp.example.com/\"quoted\"",
        "https://mcp.example.com/back\\slash",
        "/.well-known/oauth-protected-resource/mcp",
        "http://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    ] {
        bearer_challenge(BearerChallengeOptions::new(resource_metadata_url))
            .expect_err(resource_metadata_url);
    }

    // It MAY carry a query and a fragment, unlike the resource identifier.
    let url = format!("{METADATA_URL}?v=2#x");
    assert_eq!(
        bearer_challenge(BearerChallengeOptions::new(&url)).unwrap(),
        format!("Bearer resource_metadata=\"{url}\"")
    );
}
