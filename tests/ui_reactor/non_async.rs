// The macro replaces the whole item with a compile_error!, so the imports the
// annotated fn would have used go unread. Silenced to keep the expected
// diagnostic below to the one error this case is about.
#![allow(unused_imports)]

use axiam_sdk::amqp::reactor::{ReactorDecision, ReactorEvent};
use axiam_sdk::reactor_handler;

// A handler resolves to a decision; a synchronous fn cannot be awaited by the
// runtime.
#[reactor_handler("token.pre_issue")]
fn enrich(_event: ReactorEvent) -> ReactorDecision {
    ReactorDecision::allow()
}

fn main() {}
