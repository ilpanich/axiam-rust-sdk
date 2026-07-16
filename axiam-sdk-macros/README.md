# axiam-sdk-macros

Proc-macro companion crate for [`axiam-sdk`](https://crates.io/crates/axiam-sdk).

This crate provides the `#[require_access]`, `#[require_auth]` and
`#[require_role]` Actix-Web attribute macros that implement the CONTRACT.md §11
*declarative authorization helpers*. It is an implementation detail of
`axiam-sdk`: **do not depend on it directly.** Enable the `macros` feature on
`axiam-sdk` and import the attributes from there:

```toml
[dependencies]
axiam-sdk = { version = "1.0.0-alpha", features = ["macros"] }
```

```rust,ignore
use axiam_sdk::{require_access, middleware::AxiamUser};

#[require_access(action = "read", resource_param = "id")]
async fn get_document(user: AxiamUser) -> String {
    format!("user {} may read this document", user.user_id)
}
```

See the [`axiam-sdk` documentation](https://docs.rs/axiam-sdk) for the full
declarative-authorization guide and the shared behavioral contract
(`CONTRACT.md` §11).

Licensed under Apache-2.0.
