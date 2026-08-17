// The macro replaces the whole item with a compile_error!, so the imports the
// annotated fn would have used go unread. Silenced to keep the expected
// diagnostic below to the one error this case is about.
#![allow(unused_imports)]

use axiam_sdk::amqp::reactor::{ReactorDecision, ReactorEvent};
use axiam_sdk::reactor_handler;

// §22.7's hot-path operations are in no registry row, so they are refused by
// the same rule that catches a typo — and the diagnostic names the registry
// rather than the exclusions, because a hot-path list inside the SDK is the
// constant §22.13 forbids.
#[reactor_handler("authz.check")]
async fn check(_event: ReactorEvent) -> ReactorDecision {
    ReactorDecision::allow()
}

fn main() {}
