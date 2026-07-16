use axiam_sdk::require_access;

#[require_access(action = "read", resource_id = "0f14d0ab-9605-4a62-a9e4-5ed26688389b", resource_param = "id")]
async fn handler() -> &'static str {
    "x"
}

fn main() {}
