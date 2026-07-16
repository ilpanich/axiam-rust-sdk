//! Proc-macro Actix-Web authorization attributes for the AXIAM Rust SDK.
//!
//! This crate is an implementation detail of [`axiam-sdk`]; do not depend on
//! it directly. The three attribute macros it exports are re-exported from
//! `axiam-sdk` behind its `macros` feature, so consumers write
//! `use axiam_sdk::require_access;` and never name this crate.
//!
//! The macros implement the CONTRACT.md §11 *declarative authorization
//! helpers* on top of the §10 `AxiamUser` route-guard extractor. They are
//! deliberately **thin**: each one expands to a small wrapper that delegates
//! to the runtime helpers in [`axiam_sdk::middleware`] (`RequireAccess`,
//! `resource_from_path`, `require_role_check`, …), so the enforcement logic
//! lives in ordinary, unit-testable library code rather than inside macro
//! expansion.
//!
//! - [`macro@require_auth`] — require an authenticated AXIAM identity (401 on
//!   failure).
//! - [`macro@require_access`] — require the authenticated caller to pass an
//!   AXIAM authorization check for an `action` on a request-resolved resource
//!   (401 unauthenticated, 403 denied, 400 unresolvable resource, 503 authz
//!   transport failure — fail closed).
//! - [`macro@require_role`] — require one of a set of roles, checked locally
//!   against the verified token's claims (403 on failure).
//!
//! [`axiam-sdk`]: https://docs.rs/axiam-sdk
//! [`axiam_sdk::middleware`]: https://docs.rs/axiam-sdk/latest/axiam_sdk/middleware/

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Expr, ExprLit, ExprPath, ItemFn, Lit, Meta, Pat, Token};

/// Require an authenticated AXIAM identity on an Actix-Web handler
/// (CONTRACT.md §11 `require_auth`).
///
/// Pure sugar over the §10 [`AxiamUser`] extractor: the attribute injects an
/// `AxiamUser` extractor parameter into the handler, so Actix rejects the
/// request with `401 authentication_failed` before the handler body runs if
/// no verified identity is present. The handler's own signature, parameters
/// and return type are otherwise unchanged.
///
/// ```ignore
/// use axiam_sdk::require_auth;
///
/// #[require_auth]
/// async fn whoami() -> &'static str {
///     "you are authenticated"
/// }
/// ```
///
/// The handler may still declare its own `AxiamUser` parameter if it needs
/// the identity in its body — the injected extractor is independent of it.
///
/// [`AxiamUser`]: https://docs.rs/axiam-sdk/latest/axiam_sdk/middleware/struct.AxiamUser.html
#[proc_macro_attribute]
pub fn require_auth(args: TokenStream, item: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return compile_error(
            proc_macro2::TokenStream::from(args),
            "require_auth takes no arguments",
        );
    }
    let mut func = parse_macro_input!(item as ItemFn);
    if func.sig.asyncness.is_none() {
        return compile_error_spanned(func.sig.fn_token, "require_auth requires an `async fn`");
    }

    // Inject a leading `AxiamUser` extractor parameter. Named with a leading
    // underscore so it does not trip `unused_variables` when the body ignores
    // it — Actix still runs the extractor (and its §10 401 path) regardless.
    let injected: syn::FnArg = syn::parse_quote! {
        _axiam_require_auth_user: ::axiam_sdk::middleware::AxiamUser
    };
    func.sig.inputs.insert(0, injected);

    quote!(#func).into()
}

/// Require the authenticated caller to pass an AXIAM authorization check on an
/// Actix-Web handler (CONTRACT.md §11 `require_access`).
///
/// Runs strictly *after* §10 authentication and consumes the identity it
/// injected — it never re-implements token extraction/verification. The check
/// is issued for the **request's** authenticated user (its `user_id` is sent
/// as `subject_id`), not for the application's own `AxiamClient` session.
///
/// # Arguments
///
/// - `action` (**required**) — the permission action string, e.g.
///   `action = "read"`.
/// - Exactly one resource selector:
///   - `resource_param = "id"` — the name of a path parameter whose value is
///     parsed as the resource `Uuid`;
///   - `resource_id = "<uuid>"` — a static UUID literal, for singleton
///     resources;
///   - `resolver = path::to::fn` — a function
///     `fn(&actix_web::HttpRequest) -> Result<uuid::Uuid, axiam_sdk::middleware::AuthzGuardError>`
///     for anything else (body fields, headers, composite lookups).
/// - `scope = "…"` (optional) — passed through to `check_access` verbatim.
///
/// # Requirements on the annotated handler
///
/// - It must be an `async fn`.
/// - The application must register `web::Data<AxiamClient>` (used to issue the
///   check) and `web::Data<JwksVerifier>` (used by the §10 extractor) as app
///   data.
/// - Any handler parameters must be simple identifiers (so they can be
///   forwarded to the original body).
///
/// # Error mapping (CONTRACT.md §11.5)
///
/// | Condition | Status | `error` code |
/// |-----------|--------|--------------|
/// | no verified identity | 401 | `authentication_failed` |
/// | check returns `allowed = false` / server 403 | 403 | `authorization_denied` |
/// | resource id missing or not a UUID | 400 | `invalid_request` |
/// | transport failure reaching authz (fail closed) | 503 | `authz_unavailable` |
///
/// ```ignore
/// use axiam_sdk::{require_access, middleware::AxiamUser};
///
/// #[require_access(action = "read", resource_param = "id")]
/// async fn get_document(user: AxiamUser) -> String {
///     format!("user {} may read this document", user.user_id)
/// }
/// ```
#[proc_macro_attribute]
pub fn require_access(args: TokenStream, item: TokenStream) -> TokenStream {
    let metas = parse_macro_input!(args with Punctuated::<Meta, Token![,]>::parse_terminated);
    let func = parse_macro_input!(item as ItemFn);

    let mut action: Option<String> = None;
    let mut resource_param: Option<String> = None;
    let mut resource_id: Option<String> = None;
    let mut resolver: Option<ExprPath> = None;
    let mut scope: Option<String> = None;

    for meta in metas {
        let nv = match meta {
            Meta::NameValue(nv) => nv,
            other => {
                return compile_error_spanned(
                    &other,
                    "require_access arguments must be `name = value` pairs",
                )
            }
        };
        if nv.path.is_ident("action") {
            match lit_string(&nv.value) {
                Some(s) => action = Some(s),
                None => {
                    return compile_error_spanned(&nv.value, "`action` must be a string literal")
                }
            }
        } else if nv.path.is_ident("resource_param") {
            match lit_string(&nv.value) {
                Some(s) => resource_param = Some(s),
                None => {
                    return compile_error_spanned(
                        &nv.value,
                        "`resource_param` must be a string literal",
                    )
                }
            }
        } else if nv.path.is_ident("resource_id") {
            match lit_string(&nv.value) {
                Some(s) => resource_id = Some(s),
                None => {
                    return compile_error_spanned(
                        &nv.value,
                        "`resource_id` must be a string literal (a UUID)",
                    )
                }
            }
        } else if nv.path.is_ident("scope") {
            match lit_string(&nv.value) {
                Some(s) => scope = Some(s),
                None => {
                    return compile_error_spanned(&nv.value, "`scope` must be a string literal")
                }
            }
        } else if nv.path.is_ident("resolver") {
            match &nv.value {
                Expr::Path(p) => resolver = Some(p.clone()),
                other => {
                    return compile_error_spanned(other, "`resolver` must be a path to a function")
                }
            }
        } else {
            return compile_error_spanned(
                &nv.path,
                "unknown argument (expected one of: action, resource_param, resource_id, resolver, scope)",
            );
        }
    }

    let action = match action {
        Some(a) => a,
        None => {
            return compile_error_spanned(
                &func.sig,
                "require_access requires an `action`, e.g. #[require_access(action = \"read\", resource_param = \"id\")]",
            )
        }
    };

    let selector_count =
        resource_param.is_some() as u8 + resource_id.is_some() as u8 + resolver.is_some() as u8;
    if selector_count == 0 {
        return compile_error_spanned(
            &func.sig,
            "require_access requires exactly one resource selector: `resource_param`, `resource_id`, or `resolver`",
        );
    }
    if selector_count > 1 {
        return compile_error_spanned(
            &func.sig,
            "require_access accepts only one resource selector: specify exactly one of `resource_param`, `resource_id`, or `resolver`",
        );
    }

    if func.sig.asyncness.is_none() {
        return compile_error_spanned(func.sig.fn_token, "require_access requires an `async fn`");
    }

    // How to resolve the resource `Uuid` from the request, per selector.
    let resolve_expr = if let Some(param) = resource_param {
        quote! { ::axiam_sdk::middleware::resource_from_path(&__axiam_req, #param) }
    } else if let Some(id) = resource_id {
        quote! { ::axiam_sdk::middleware::resource_from_static(#id) }
    } else {
        let resolver = resolver.expect("selector_count guarantees a resolver here");
        quote! { #resolver(&__axiam_req) }
    };

    let scope_call = match scope {
        Some(s) => quote! { .scope(#s) },
        None => quote! {},
    };

    let guard = quote! {
        // Type is inferred as `uuid::Uuid` from the resolver's return type, so
        // the expansion does not require the consumer crate to name `uuid`.
        let __axiam_resource_id = match #resolve_expr {
            ::core::result::Result::Ok(id) => id,
            ::core::result::Result::Err(err) => {
                return ::actix_web::ResponseError::error_response(&err);
            }
        };
        if let ::core::result::Result::Err(err) = ::axiam_sdk::middleware::RequireAccess::new(#action)
            #scope_call
            .check(&__axiam_client, &__axiam_require_access_user, __axiam_resource_id)
            .await
        {
            return ::actix_web::ResponseError::error_response(&err);
        }
    };

    let extra_inputs = quote! {
        __axiam_req: ::actix_web::HttpRequest,
        __axiam_require_access_user: ::axiam_sdk::middleware::AxiamUser,
        __axiam_client: ::actix_web::web::Data<::axiam_sdk::client::AxiamClient>,
    };

    expand_wrapper(func, extra_inputs, guard)
}

/// Require one of a set of roles on an Actix-Web handler (CONTRACT.md §11
/// `require_role`).
///
/// A **local** check against the verified token's `roles` claim — it performs
/// no server round-trip, so it is cheaper but coarser than
/// [`macro@require_access`]. Role names are tenant-defined; `require_access`
/// remains the authoritative, resource-level check. Passes if the caller
/// holds **at least one** of the listed roles, otherwise responds
/// `403 authorization_denied`. An unauthenticated request is rejected with
/// `401 authentication_failed` by the injected §10 extractor first.
///
/// ```ignore
/// use axiam_sdk::require_role;
///
/// #[require_role("admin", "superadmin")]
/// async fn admin_panel() -> &'static str {
///     "welcome, admin"
/// }
/// ```
#[proc_macro_attribute]
pub fn require_role(args: TokenStream, item: TokenStream) -> TokenStream {
    let roles = parse_macro_input!(args with Punctuated::<Expr, Token![,]>::parse_terminated);
    let func = parse_macro_input!(item as ItemFn);

    let mut role_lits: Vec<String> = Vec::new();
    for expr in &roles {
        match lit_string(expr) {
            Some(s) => role_lits.push(s),
            None => {
                return compile_error_spanned(
                    expr,
                    "require_role arguments must be string literals",
                )
            }
        }
    }
    if role_lits.is_empty() {
        return compile_error_spanned(
            &func.sig,
            "require_role requires at least one role, e.g. #[require_role(\"admin\")]",
        );
    }

    if func.sig.asyncness.is_none() {
        return compile_error_spanned(func.sig.fn_token, "require_role requires an `async fn`");
    }

    let guard = quote! {
        if let ::core::result::Result::Err(err) = ::axiam_sdk::middleware::require_role_check(
            &__axiam_require_role_user,
            &[#(#role_lits),*],
        ) {
            return ::actix_web::ResponseError::error_response(&err);
        }
    };

    let extra_inputs = quote! {
        __axiam_req: ::actix_web::HttpRequest,
        __axiam_require_role_user: ::axiam_sdk::middleware::AxiamUser,
    };

    expand_wrapper(func, extra_inputs, guard)
}

/// Build the wrapper handler shared by `require_access` and `require_role`.
///
/// The original handler is nested (renamed) inside a generated wrapper that
/// declares the injected extractor parameters (`extra_inputs`) alongside the
/// original ones, runs `guard`, then — on success — calls the original body
/// and adapts its return value with `Responder::respond_to`. This keeps the
/// wrapper compatible with any handler whose return type implements
/// `Responder` (including `Result<T, actix_web::Error>`).
fn expand_wrapper(
    func: ItemFn,
    extra_inputs: proc_macro2::TokenStream,
    guard: proc_macro2::TokenStream,
) -> TokenStream {
    let attrs = &func.attrs;
    let vis = &func.vis;
    let sig = &func.sig;
    let name = &sig.ident;
    let orig_inputs = &sig.inputs;

    // Collect the original parameter identifiers to forward to the nested
    // implementation. Only simple `ident: Type` parameters are supported.
    let mut forward = Vec::new();
    for input in orig_inputs.iter() {
        match input {
            syn::FnArg::Receiver(recv) => {
                return compile_error_spanned(
                    recv,
                    "require_* macros cannot be applied to methods with a `self` receiver",
                );
            }
            syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                Pat::Ident(pat_ident) => forward.push(pat_ident.ident.clone()),
                other => {
                    return compile_error_spanned(
                        other,
                        "require_* handler parameters must be simple identifiers",
                    )
                }
            },
        }
    }

    let inner_name = format_ident!("__axiam_impl_{}", name);
    let inner_sig = {
        let mut s = sig.clone();
        s.ident = inner_name.clone();
        s
    };
    let inner_block = &func.block;

    let comma = if orig_inputs.is_empty() {
        quote! {}
    } else {
        quote! {,}
    };

    let expanded = quote! {
        #(#attrs)*
        #vis async fn #name(
            #extra_inputs
            #orig_inputs #comma
        ) -> ::actix_web::HttpResponse {
            // The original handler, nested so it does not leak into the
            // surrounding namespace.
            #inner_sig #inner_block

            #guard

            let __axiam_inner_result = #inner_name(#(#forward),*).await;
            ::actix_web::Responder::respond_to(__axiam_inner_result, &__axiam_req)
                .map_into_boxed_body()
        }
    };
    expanded.into()
}

/// Extract a `String` from a string-literal expression, if that is what it is.
fn lit_string(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Some(s.value()),
        _ => None,
    }
}

/// Emit a `compile_error!` at the call site (no useful span available).
fn compile_error(tokens: proc_macro2::TokenStream, message: &str) -> TokenStream {
    syn::Error::new_spanned(tokens, message)
        .to_compile_error()
        .into()
}

/// Emit a `compile_error!` spanned at `tokens` with `message`.
fn compile_error_spanned<T: quote::ToTokens>(tokens: T, message: &str) -> TokenStream {
    syn::Error::new_spanned(tokens, message)
        .to_compile_error()
        .into()
}
