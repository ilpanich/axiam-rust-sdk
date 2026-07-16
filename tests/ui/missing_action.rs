use axiam_sdk::require_access;

#[require_access(resource_param = "id")]
async fn handler() -> &'static str {
    "x"
}

fn main() {}
