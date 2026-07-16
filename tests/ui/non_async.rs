use axiam_sdk::require_access;

#[require_access(action = "read", resource_param = "id")]
fn handler() -> &'static str {
    "x"
}

fn main() {}
