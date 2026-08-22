//! REST transport (owned by 16-02): `AxiamClient` + builder, login/MFA/
//! refresh/logout, `check_access`/`batch_check`.

pub mod account;
pub mod auth;
pub mod authz;
#[cfg(feature = "opaque")]
pub mod opaque;
pub mod webauthn;

pub use account::{
    MfaEnrollment, PasswordResetConfirmation, PasswordResetContext, PasswordResetRequest,
};
pub use auth::LoginResult;
pub use webauthn::{
    WebauthnChallenge, WebauthnCredential, WebauthnFailure, WebauthnLoginResult, WebauthnWorkspace,
    webauthn_response_from_json,
};
