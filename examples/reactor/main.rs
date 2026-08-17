//! A runnable reactor — CONTRACT.md §22.
//!
//! Three hooks in one process:
//!
//! * `token.pre_issue` — enrich the token with `ext.` claims (mutable).
//! * `login.post_auth` — veto a sign-in from an embargoed region, or demand
//!   step-up MFA (veto-only).
//! * `grant.pre_assign` — four-eyes: refuse a self-granted admin role
//!   (veto-only).
//!
//! ```bash
//! export AXIAM_AMQP_URL='amqps://reactor:secret@broker.example.com:5671/%2f'
//! export AXIAM_TENANT_ID='11111111-1111-1111-1111-111111111111'
//! export AXIAM_REACTOR_ID='99999999-9999-9999-9999-999999999999'
//! export AXIAM_AMQP_SIGNING_KEY_HEX='…64 hex chars…'
//! cargo run --example reactor --features amqp
//! ```
//!
//! # Before this runs, register the reactor (§22.9)
//!
//! ```bash
//! curl -X POST https://axiam.example.com/api/v1/reactors \
//!   -H "Authorization: Bearer $ADMIN_TOKEN" \
//!   -H 'Content-Type: application/json' \
//!   -d '{
//!         "name": "example-reactor",
//!         "events": ["token.pre_issue", "login.post_auth", "grant.pre_assign"],
//!         "mode": "intercept",
//!         "priority": 10,
//!         "timeout_ms": 500
//!       }'
//! ```
//!
//! The response carries the `id` this process needs as `AXIAM_REACTOR_ID`, and
//! the server declares the queue. **This process declares nothing** (§22.1).
//!
//! Note what the registration deliberately omits: `failure_policy`. Two of the
//! three events default to `fail_closed`, and §22.8 says the strictest default
//! wins — so this reactor being unreachable **denies** logins and grants,
//! while token enrichment keeps flowing. That is the right shape, and it is
//! why naming the policy explicitly is usually a mistake.
//!
//! # What this example does not do
//!
//! It does not hook `authz.check`, `authz.check_batch` or `token.introspect`,
//! because §22.7 makes them un-hookable: a reactor round-trip is milliseconds
//! and the check path's budget is microseconds. External input on an
//! authorization decision belongs in a **deny grant**, which the engine
//! evaluates at hot-path cost.

use std::collections::BTreeMap;

use axiam_sdk::Sensitive;
use axiam_sdk::amqp::reactor::{
    FailurePolicy, ReactorConfig, ReactorDecision, ReactorEvent, ReactorRouter, ReactorShutdown,
    default_failure_policy_for, event_spec, events, reactor_serve,
};
use axiam_sdk::reactor_handler;
use axiam_sdk::telemetry::TelemetryEvent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let amqp_url = env("AXIAM_AMQP_URL")?;
    let tenant_id = env("AXIAM_TENANT_ID")?.parse()?;
    let reactor_id = env("AXIAM_REACTOR_ID")?.parse()?;

    // The tenant's HKDF-derived AMQP subkey (§8 v2), fetched from the
    // management API and held in `Sensitive` so it cannot be printed, logged
    // or serialized by accident (§22.12). NEVER hard-code one.
    let signing_key = Sensitive::new(decode_hex(&env("AXIAM_AMQP_SIGNING_KEY_HEX")?)?);

    // The strictest default among the events we registered for (§22.8). Shown
    // here because it is worth knowing before you go live, not because the SDK
    // needs it: the server derives it from the registration.
    // One handler per event (§22.14) instead of a `match` whose `_ =>` arm
    // answers on behalf of code that never ran. Each name was validated at
    // COMPILE time by `#[reactor_handler]`; an event nobody bound abstains, so
    // the registration's failure_policy decides rather than this file.
    let router = ReactorRouter::new()
        .on::<enrich_token>()
        .on::<screen_login>()
        .on::<four_eyes>();

    // The strictest default among the events actually bound (§22.8), derived
    // from the router rather than from a restatement of the registration — so
    // the two cannot drift apart. Shown here because it is worth knowing before
    // you go live, not because the SDK needs it: the server derives it from the
    // registration.
    let policy = default_failure_policy_for(router.events().iter().copied());
    assert_eq!(policy, FailurePolicy::FailClosed);
    println!("failure policy when this reactor is unreachable: {policy}");

    let shutdown = ReactorShutdown::new();
    let on_signal = shutdown.clone();
    tokio::spawn(async move {
        // Ctrl-C drains the in-flight event and returns (§18) — it does not
        // abandon a dispatch the server is still waiting on.
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("shutting down; draining the in-flight event");
            on_signal.trigger();
        }
    });

    let config = ReactorConfig::builder()
        .amqp_url(amqp_url)
        .tenant_id(tenant_id)
        .reactor_id(reactor_id)
        .signing_key(signing_key)
        .shutdown(shutdown)
        .telemetry_hook(|event: &TelemetryEvent| {
            if let TelemetryEvent::RequestEnd {
                path_template,
                duration,
                outcome,
                ..
            } = event
            {
                // `path_template` is the registry event name — a bounded
                // label set, never a correlation id (§19).
                println!("reactor {path_template} finished in {duration:?}: {outcome:?}");
            }
        })
        .build()?;

    println!("consuming {} (declared by the server)", config.queue());
    reactor_serve(config, router.build()?).await?;
    Ok(())
}

/// `token.pre_issue` is the one mutable event here, and its allow-list is the
/// `ext.` namespace and nothing else — `sub`, `aud`, `exp` and every other
/// standard claim are unreachable, because none of them begins with `ext.`.
#[reactor_handler("token.pre_issue")]
async fn enrich_token(event: ReactorEvent) -> ReactorDecision {
    let Some(sub) = event.payload.get("sub").and_then(|v| v.as_str()) else {
        return ReactorDecision::allow();
    };

    let mut patch = BTreeMap::new();
    patch.insert("ext.cost_center".to_string(), cost_center_for(sub));
    patch.insert("ext.department".to_string(), "engineering".to_string());

    // A chained event carries what an earlier reactor already decided, so you
    // can decide against the state that will actually commit. It is read-only
    // context — do NOT copy it into your own patch; the server merges (§22.6).
    let already_set = event
        .chained_patch()
        .is_some_and(|prior| prior.get("ext.department").is_some());
    if already_set {
        // A higher-priority reactor will overwrite ours anyway, so do not
        // contest the key.
        patch.remove("ext.department");
    }

    // Optional self-check. The runtime will NOT prune a forbidden key for you
    // (§22.4 rule 1): one bad key rejects the whole patch server-side, and
    // silently dropping it would leave you believing a field was set.
    if let Some(spec) = event_spec(events::TOKEN_PRE_ISSUE) {
        for key in patch.keys() {
            debug_assert!(
                spec.patch_field_allowed(key),
                "{key} is outside the allow-list"
            );
        }
    }

    ReactorDecision::mutate(patch)
}

/// `login.post_auth` fires on password sign-in, on SAML ACS and on the OIDC
/// callback — after the credentials verify and before any session or token is
/// issued (§22.5).
#[reactor_handler("login.post_auth")]
async fn screen_login(event: ReactorEvent) -> ReactorDecision {
    let ip = event
        .payload
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if is_embargoed(ip) {
        // A deny with no reason still denies; the reason is for the audit
        // trail.
        return ReactorDecision::deny("embargoed region");
    }

    if is_unfamiliar(ip) {
        // `require_mfa` rides on `allow` and is valid on this event only.
        //
        // Caveat worth knowing: the federated paths (SAML ACS, OIDC callback)
        // have no step-up branch, so a `require_mfa` answer there FAILS the
        // sign-in rather than being dropped. A reactor that needs step-up on a
        // federated login answers `deny` and drives enrolment out of band.
        return ReactorDecision::require_step_up();
    }

    ReactorDecision::allow()
}

/// `grant.pre_assign` is veto-only: it can refuse a role assignment, and it
/// cannot rewrite one.
#[reactor_handler("grant.pre_assign")]
async fn four_eyes(event: ReactorEvent) -> ReactorDecision {
    let actor = event.payload.get("actor_id").and_then(|v| v.as_str());
    let subject = event.payload.get("subject_id").and_then(|v| v.as_str());
    let role = event
        .payload
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if role == "admin" && actor.is_some() && actor == subject {
        return ReactorDecision::deny("admin cannot be self-granted; needs a second approver");
    }
    ReactorDecision::allow()
}

fn cost_center_for(sub: &str) -> String {
    // Stand-in for a real lookup.
    format!("cc-{}", sub.len())
}

fn is_embargoed(ip: &str) -> bool {
    ip.starts_with("198.51.100.")
}

fn is_unfamiliar(ip: &str) -> bool {
    ip.starts_with("203.0.113.")
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be set"))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err("signing key hex must have an even length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
