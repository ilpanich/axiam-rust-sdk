//! RFC 7592 client configuration — CONTRACT.md §28.12 (contract 1.53).
//!
//! A client that registered itself through `POST /oauth2/register` (RFC 7591)
//! receives, once, a `registration_client_uri` and a
//! `registration_access_token`. With those two it can read, replace and delete
//! **its own** registration. Three operations on [`AxiamClient`]:
//! [`AxiamClient::read_client_registration`],
//! [`AxiamClient::update_client_registration`] and
//! [`AxiamClient::delete_client_registration`].
//!
//! Four rules shape all three (§28.12.2):
//!
//! 1. **The URI is used verbatim, and only at the configured AXIAM.** A URI
//!    whose scheme, host or port differs from the client's base URL — or an
//!    `http` URI when the base URL is not `http` on a loopback host — is
//!    refused locally, before any request: the token is a bearer, and a helper
//!    that followed a URI to another origin would hand it to whoever wrote the
//!    URI.
//! 2. **The token travels in `Authorization: Bearer` only** — never in the
//!    query, never in a body.
//! 3. **It is not the SDK's session.** These requests go out on a transport
//!    with no cookie jar and no redirect following, carry no SDK access token,
//!    and a `401` from them never reaches the §9 refresh guard.
//! 4. **Neither write is retried.** An update that reached the server and lost
//!    its response has already rotated the token; a delete whose `204` was lost
//!    would read `401` on a retry. Only the read follows §16.

use serde_json::{Map, Value};

use super::exchange::oauth2_error_or_fallback;
use crate::client::AxiamClient;
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

/// The members `update_client_registration` never sends (§28.12.2 rule 4).
///
/// The first four the server refuses with `400 invalid_request` when present;
/// `client_secret` it never accepts back.
const SERVER_STATED_MEMBERS: [&str; 5] = [
    "registration_access_token",
    "registration_client_uri",
    "client_secret_expires_at",
    "client_id_issued_at",
    "client_secret",
];

/// An RFC 7591 §3.2.1 / RFC 7592 §3 client information response.
///
/// `registration_access_token` and `client_secret` are [`Sensitive`]
/// (§28.12.4): `Debug` redacts both, and the type implements neither
/// `Serialize` nor `Display`, so no serializer or format string reaches them.
///
/// Every member the server sent that this type does not name is kept in
/// [`Self::extra`] — RFC 7591 §3.2.1 lets a server add members, and because an
/// update is a **full replacement**, a member a read returned and an update
/// left out is a member the server deletes. Passing a read's result straight
/// to [`AxiamClient::update_client_registration`] therefore sends it back
/// intact, including `jwks` / `jwks_uri` and the CIBA members.
#[derive(Debug, Clone, Default)]
pub struct ClientRegistration {
    /// The client's `client_id`.
    pub client_id: String,
    /// When the client id was issued (seconds since the epoch). Never sent on
    /// an update.
    pub client_id_issued_at: Option<i64>,
    /// The registered display name.
    pub client_name: Option<String>,
    /// The registered redirect URIs. `None` when the response did not carry
    /// the member as a list of strings — then an update does not send it,
    /// rather than sending `[]` (§28.12.2 rule 4); a member of another shape
    /// is kept in [`Self::extra`] and sent back as read.
    pub redirect_uris: Option<Vec<String>>,
    /// The registered grant types; `None` as for [`Self::redirect_uris`].
    pub grant_types: Option<Vec<String>>,
    /// The registered response types; `None` as for [`Self::redirect_uris`].
    pub response_types: Option<Vec<String>>,
    /// How the client authenticates at the token endpoint. The server refuses
    /// an update that changes it.
    pub token_endpoint_auth_method: Option<String>,
    /// The registered scope, space-separated.
    pub scope: Option<String>,
    /// Where this registration is read, replaced and deleted. Never sent on an
    /// update.
    pub registration_client_uri: Option<String>,
    /// When the client secret expires (`0` = never). Never sent on an update.
    pub client_secret_expires_at: Option<i64>,
    /// The client's JWK Set, for a `private_key_jwt` client.
    pub jwks: Option<Value>,
    /// Where the client's JWK Set is published.
    pub jwks_uri: Option<String>,
    /// The client secret — present only on the registration response itself,
    /// never on a read or an update. Never sent back.
    pub client_secret: Option<Sensitive<String>>,
    /// The registration access token — present on the registration response
    /// and, **rotated**, on every update response; absent on a read. Never
    /// sent in a body.
    pub registration_access_token: Option<Sensitive<String>>,
    /// Every other member of the response, verbatim.
    pub extra: Map<String, Value>,
}

impl ClientRegistration {
    /// Decode a client information response, tolerating unknown members.
    pub fn from_json(value: Value) -> Result<Self, AxiamError> {
        let Value::Object(mut map) = value else {
            return Err(AxiamError::network(
                "client registration response is not a JSON object",
            ));
        };
        fn take_str(map: &mut Map<String, Value>, key: &str) -> Option<String> {
            match map.remove(key) {
                Some(Value::String(s)) => Some(s),
                Some(other) if !other.is_null() => {
                    // Keep a member of an unexpected type rather than drop it:
                    // a replacement must not lose what the server holds.
                    map.insert(key.to_string(), other);
                    None
                }
                _ => None,
            }
        }
        fn take_i64(map: &mut Map<String, Value>, key: &str) -> Option<i64> {
            match map.remove(key) {
                Some(Value::Number(n)) => n.as_i64(),
                Some(other) if !other.is_null() => {
                    map.insert(key.to_string(), other);
                    None
                }
                _ => None,
            }
        }
        fn take_list(map: &mut Map<String, Value>, key: &str) -> Option<Vec<String>> {
            match map.remove(key) {
                Some(Value::Array(items)) if items.iter().all(Value::is_string) => Some(
                    items
                        .into_iter()
                        .filter_map(|v| match v {
                            Value::String(s) => Some(s),
                            _ => None,
                        })
                        .collect(),
                ),
                Some(other) if !other.is_null() => {
                    // A list with an item of another type, or not a list at
                    // all: kept as read, never trimmed or dropped
                    // (§28.12.2 rule 4, contract 1.59 P12.4).
                    map.insert(key.to_string(), other);
                    None
                }
                _ => None,
            }
        }

        let client_id = take_str(&mut map, "client_id").ok_or_else(|| {
            AxiamError::network("client registration response carries no client_id")
        })?;
        let jwks = match map.remove("jwks") {
            Some(Value::Null) | None => None,
            Some(v) => Some(v),
        };
        Ok(Self {
            client_id,
            client_id_issued_at: take_i64(&mut map, "client_id_issued_at"),
            client_name: take_str(&mut map, "client_name"),
            redirect_uris: take_list(&mut map, "redirect_uris"),
            grant_types: take_list(&mut map, "grant_types"),
            response_types: take_list(&mut map, "response_types"),
            token_endpoint_auth_method: take_str(&mut map, "token_endpoint_auth_method"),
            scope: take_str(&mut map, "scope"),
            registration_client_uri: take_str(&mut map, "registration_client_uri"),
            client_secret_expires_at: take_i64(&mut map, "client_secret_expires_at"),
            jwks,
            jwks_uri: take_str(&mut map, "jwks_uri"),
            client_secret: take_str(&mut map, "client_secret").map(Sensitive::new),
            registration_access_token: take_str(&mut map, "registration_access_token")
                .map(Sensitive::new),
            extra: map,
        })
    }

    /// The RFC 7592 §2.2 replacement body: every member but the five the
    /// server states (§28.12.2 rule 4), with `client_id` set to this
    /// registration's own. Built from what the read carried: a list it lacked
    /// is not sent, never as `[]` (contract 1.59 P12.4).
    fn update_body(&self) -> Value {
        let mut body = self.extra.clone();
        for key in SERVER_STATED_MEMBERS {
            body.remove(key);
        }
        body.insert("client_id".into(), Value::String(self.client_id.clone()));
        let mut put = |key: &str, value: Option<Value>| {
            if let Some(v) = value {
                body.insert(key.into(), v);
            }
        };
        put("client_name", self.client_name.clone().map(Value::String));
        put("redirect_uris", self.redirect_uris.as_deref().map(string_list));
        put("grant_types", self.grant_types.as_deref().map(string_list));
        put(
            "response_types",
            self.response_types.as_deref().map(string_list),
        );
        put(
            "token_endpoint_auth_method",
            self.token_endpoint_auth_method.clone().map(Value::String),
        );
        put("scope", self.scope.clone().map(Value::String));
        put("jwks", self.jwks.clone());
        put("jwks_uri", self.jwks_uri.clone().map(Value::String));
        Value::Object(body)
    }
}

fn string_list(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

/// The host as compared for "same origin": lower-cased, IPv6 unbracketed.
fn origin_of(url: &url::Url) -> (String, Option<String>, Option<u16>) {
    (
        url.scheme().to_ascii_lowercase(),
        url.host_str().map(|h| h.to_ascii_lowercase()),
        url.port_or_known_default(),
    )
}

/// §28.12.2 rule 1: accept `uri` only at the configured AXIAM origin.
///
/// The refusal names no part of the URI beyond its scheme: it is caller input,
/// and an error message is the one most often logged.
pub(crate) fn check_registration_uri(
    base: &url::Url,
    uri: &str,
    operation: &'static str,
) -> Result<url::Url, AxiamError> {
    let refuse = |why: &str| {
        crate::management::error::local_refusal(
            operation,
            "registration_client_uri",
            format!("{why} (CONTRACT.md §28.12.2 rule 1)"),
        )
    };
    let parsed = url::Url::parse(uri).map_err(|_| refuse("not an absolute URL"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(refuse("must be an https URL"));
    }
    if origin_of(&parsed) != origin_of(base) {
        return Err(refuse(
            "not at the configured AXIAM origin (scheme, host and port must match the client's base URL)",
        ));
    }
    if scheme == "http"
        && !base
            .host_str()
            .is_some_and(crate::url_guard::is_loopback_host)
    {
        return Err(refuse(
            "must be https unless the base URL is http on a loopback host",
        ));
    }
    Ok(parsed)
}

impl AxiamClient {
    /// `GET registration_client_uri` (RFC 7592 §2.1, CONTRACT.md §28.12) —
    /// read this client's registration.
    ///
    /// The result carries neither the token nor the client secret: the server
    /// never returns them on a read. It does carry every member an update
    /// needs, so the usual update is "read, change a field, update".
    ///
    /// Retried per §16 on a transport failure or `5xx` (a read is safe to
    /// repeat). A `401 invalid_token` — an unknown client, a wrong or
    /// rotated-away token, another tenant's client, a client with no token:
    /// the server never says which — is an [`AxiamError::Auth`] carrying the
    /// [`crate::OAuthProtocolError`], and never refreshes the SDK's session.
    ///
    /// # Errors
    /// The §28.12.2 rule 1 refusal (an `AxiamError::Network` whose
    /// [`AxiamError::validation`] is set) is raised before any request.
    pub async fn read_client_registration(
        &self,
        registration_client_uri: &str,
        registration_access_token: &Sensitive<String>,
    ) -> Result<ClientRegistration, AxiamError> {
        self.ensure_open()?;
        let url = check_registration_uri(
            self.base_url(),
            registration_client_uri,
            "read_client_registration",
        )?;
        let runner = crate::retry::RetryRunner {
            enabled: self.retry_enabled(),
            operation: "read_client_registration",
            telemetry: self.telemetry(),
            jitter: &crate::retry::ThreadRngJitter,
            sleeper: &crate::retry::TokioSleeper,
        };
        let url = &url;
        runner
            .run(|_| async move {
                let response = self
                    .http_bare()
                    .get(url.clone())
                    .bearer_auth(registration_access_token.expose())
                    .header("Accept", "application/json")
                    .send()
                    .await
                    .map_err(|e| {
                        crate::retry::Attempt::bare(AxiamError::network(format!(
                            "read_client_registration request failed: {e}"
                        )))
                    })?;
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(crate::retry::parse_retry_after);
                let status = response.status().as_u16();
                let result = decode_registration(response, "read_client_registration").await;
                match result {
                    Err(err) if crate::retry::status_is_retryable(status) => {
                        Err(crate::retry::Attempt { err, retry_after })
                    }
                    other => Ok(other),
                }
            })
            .await?
    }

    /// `PUT registration_client_uri` (RFC 7592 §2.2, CONTRACT.md §28.12) —
    /// **replace** this client's registration, and receive a **rotated**
    /// token.
    ///
    /// `metadata` is the **whole** registration: a member it omits is a member
    /// the server deletes. Start from [`Self::read_client_registration`]'s
    /// result, which carries every member (`jwks` / `jwks_uri` included), and
    /// change what you mean to change. The SDK sets `client_id` to
    /// `metadata.client_id` and never sends `registration_access_token`,
    /// `registration_client_uri`, `client_secret_expires_at`,
    /// `client_id_issued_at` or `client_secret`.
    ///
    /// **Persist the returned `registration_access_token` before doing
    /// anything else.** From the moment the server answers, it is the only
    /// valid token: the one you presented is dead for every operation.
    ///
    /// **Never retried** — not on a transport error, not on a `5xx`. An update
    /// that reached the server and lost its response has already rotated the
    /// token; repeating it with the old one is a `401` that locks you out of
    /// your own registration. On a lost answer, read the registration with the
    /// token you hold: a `401` means the update landed.
    pub async fn update_client_registration(
        &self,
        registration_client_uri: &str,
        registration_access_token: &Sensitive<String>,
        metadata: &ClientRegistration,
    ) -> Result<ClientRegistration, AxiamError> {
        self.ensure_open()?;
        let url = check_registration_uri(
            self.base_url(),
            registration_client_uri,
            "update_client_registration",
        )?;
        let response = self
            .http_bare()
            .put(url)
            .bearer_auth(registration_access_token.expose())
            .header("Accept", "application/json")
            .json(&metadata.update_body())
            .send()
            .await
            .map_err(|e| {
                AxiamError::network(format!("update_client_registration request failed: {e}"))
            })?;
        decode_registration(response, "update_client_registration").await
    }

    /// `DELETE registration_client_uri` (RFC 7592 §2.3, CONTRACT.md §28.12) —
    /// delete this client's registration. `204` returns `Ok(())`.
    ///
    /// **Never retried**: a retry after a lost `204` would read `401` and
    /// report a successful deletion as a failure.
    pub async fn delete_client_registration(
        &self,
        registration_client_uri: &str,
        registration_access_token: &Sensitive<String>,
    ) -> Result<(), AxiamError> {
        self.ensure_open()?;
        let url = check_registration_uri(
            self.base_url(),
            registration_client_uri,
            "delete_client_registration",
        )?;
        let response = self
            .http_bare()
            .delete(url)
            .bearer_auth(registration_access_token.expose())
            .send()
            .await
            .map_err(|e| {
                AxiamError::network(format!("delete_client_registration request failed: {e}"))
            })?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(oauth2_error_or_fallback(response).await)
    }
}

async fn decode_registration(
    response: reqwest::Response,
    operation: &str,
) -> Result<ClientRegistration, AxiamError> {
    if !response.status().is_success() {
        return Err(oauth2_error_or_fallback(response).await);
    }
    let value: Value = response.json().await.map_err(|e| {
        AxiamError::network(format!("{operation}: failed to parse the response: {e}"))
    })?;
    ClientRegistration::from_json(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn the_same_origin_is_accepted_with_its_query_intact() {
        let u = check_registration_uri(
            &base("https://iam.example.test"),
            "https://iam.example.test:443/oauth2/register/c1?tenant_id=t",
            "op",
        )
        .unwrap();
        assert_eq!(u.query(), Some("tenant_id=t"));
    }

    #[test]
    fn another_host_port_scheme_or_garbage_is_refused() {
        let b = base("https://iam.example.test");
        for uri in [
            "https://evil.example.test/oauth2/register/c1",
            "https://iam.example.test:8443/oauth2/register/c1",
            "http://iam.example.test/oauth2/register/c1",
            "ftp://iam.example.test/x",
            "/oauth2/register/c1",
        ] {
            let e = check_registration_uri(&b, uri, "op").unwrap_err();
            assert!(e.validation().is_some(), "{uri}");
        }
    }

    #[test]
    fn http_is_allowed_only_against_an_http_loopback_base() {
        assert!(
            check_registration_uri(
                &base("http://127.0.0.1:8080"),
                "http://127.0.0.1:8080/oauth2/register/c1",
                "op"
            )
            .is_ok()
        );
        assert!(
            check_registration_uri(
                &base("http://iam.internal:8080"),
                "http://iam.internal:8080/oauth2/register/c1",
                "op"
            )
            .is_err()
        );
    }

    #[test]
    fn decoding_keeps_unknown_members_and_wraps_both_secrets() {
        let r = ClientRegistration::from_json(serde_json::json!({
            "client_id": "c1",
            "client_secret": "s",
            "registration_access_token": "t",
            "backchannel_token_delivery_mode": "poll",
            "client_id_issued_at": "not-a-number",
            "redirect_uris": ["https://a"],
        }))
        .unwrap();
        assert_eq!(r.extra["backchannel_token_delivery_mode"], "poll");
        assert_eq!(r.extra["client_id_issued_at"], "not-a-number");
        assert!(r.client_secret.is_some() && r.registration_access_token.is_some());
        // ... and the update body drops the mistyped server-stated member too.
        let body = r.update_body();
        assert!(body.get("client_id_issued_at").is_none());
        assert_eq!(body["backchannel_token_delivery_mode"], "poll");
    }

    #[test]
    fn a_response_without_a_client_id_or_not_an_object_is_refused() {
        assert!(ClientRegistration::from_json(serde_json::json!([])).is_err());
        assert!(ClientRegistration::from_json(serde_json::json!({"x": 1})).is_err());
    }
}
