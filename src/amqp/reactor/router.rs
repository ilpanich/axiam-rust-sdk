//! Declarative reactor handler binding — CONTRACT.md §22.14.
//!
//! [`reactor_serve`](super::runtime::reactor_serve) takes **one** function from
//! an event to one answer, which is the right shape for the wire and the wrong
//! shape for the code. A reactor registered for three events opens with a
//! `match event.event.as_str()`, and that `match` carries two defects.
//!
//! The first is cheap: a misspelled event name is a valid `&str`, matches no
//! arm, and is discovered as an event that never fires. The second is not. It
//! is the `_ =>` arm, which is almost always written
//! `ReactorDecision::allow()`. That answers on behalf of code that never ran —
//! the defect §22.10 rule 2 forbids the *runtime* from committing, relocated
//! into user code where the rule does not reach it. An operator who set
//! `fail_closed` on a registration has it defeated by a catch-all arm in a file
//! they never read.
//!
//! [`ReactorRouter`] is the declarative form:
//!
//! ```no_run
//! use axiam_sdk::amqp::reactor::{ReactorDecision, ReactorRouter, events, reactor_serve};
//! # use axiam_sdk::amqp::reactor::ReactorConfig;
//! # async fn run(config: ReactorConfig) -> Result<(), axiam_sdk::AxiamError> {
//! let handler = ReactorRouter::new()
//!     .bind(events::TOKEN_PRE_ISSUE, |event| async move {
//!         ReactorDecision::mutate([("ext.department", "engineering")])
//!     })
//!     .bind(events::LOGIN_POST_AUTH, |event| async move {
//!         ReactorDecision::deny("embargoed region")
//!     })
//!     .build()?;
//!
//! reactor_serve(config, handler).await
//! # }
//! ```
//!
//! With the `reactor-macros` feature, [`macro@crate::reactor_handler`] moves the
//! event name next to the function it belongs to and validates it **at compile
//! time**:
//!
//! ```ignore
//! use axiam_sdk::reactor_handler;
//!
//! #[reactor_handler("token.pre_issue")]
//! async fn enrich_token(event: ReactorEvent) -> ReactorDecision {
//!     ReactorDecision::mutate([("ext.department", "engineering")])
//! }
//!
//! let handler = ReactorRouter::new().on::<enrich_token>().build()?;
//! ```
//!
//! It is **pure sugar** (§22.14 rule 1): [`ReactorRouter::build`] produces
//! exactly the handler `reactor_serve` already takes. It opens nothing,
//! verifies nothing, signs nothing, and does not filter a patch (§22.10
//! rule 3).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::AxiamError;

use super::protocol::ReactorEvent;
use super::registry::{EVENT_REGISTRY, event_spec};
use super::runtime::ReactorDecision;

/// The boxed future a bound handler resolves to.
///
/// Boxing is deliberate and cheap at this scale: a reactor dispatch is bounded
/// by a network round trip and a `timeout_ms` measured in hundreds of
/// milliseconds, so one allocation per event is not measurable, and it is what
/// lets handlers of different concrete types share one table.
pub type BoxedReactorFuture = Pin<Box<dyn Future<Output = ReactorDecision> + Send>>;

type BoxedHandler = Arc<dyn Fn(ReactorEvent) -> BoxedReactorFuture + Send + Sync>;

/// A function bound to one hook event, as produced by
/// [`macro@crate::reactor_handler`].
///
/// Implemented by the attribute macro on a marker type named after the
/// function, so [`ReactorRouter::on`] can read the event name the macro already
/// validated. It is not meant to be implemented by hand — use
/// [`ReactorRouter::bind`] for a closure.
pub trait ReactorHandlerFn {
    /// The §22.5 registry event this function handles.
    const EVENT: &'static str;

    /// Invoke the handler.
    fn call(event: ReactorEvent) -> BoxedReactorFuture;
}

/// One handler per hook event, composed into the single §22.10 handler
/// (CONTRACT.md §22.14).
///
/// Bindings are recorded rather than panicked on; [`ReactorRouter::build`]
/// reports everything that went wrong at once, so fixing three typos takes one
/// run rather than three.
#[derive(Default)]
pub struct ReactorRouter {
    handlers: BTreeMap<&'static str, BoxedHandler>,
    order: Vec<&'static str>,
    errors: Vec<String>,
}

impl std::fmt::Debug for ReactorRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReactorRouter")
            .field("events", &self.order)
            .field("errors", &self.errors)
            .finish()
    }
}

impl ReactorRouter {
    /// An empty binding table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a closure or `async fn` to `event`.
    ///
    /// The binding is rejected — and reported by [`build`](Self::build) — when
    /// `event` is outside the §22.5 registry, or is already bound.
    ///
    /// An unregistered name is the typo guard, and it is also what refuses
    /// §22.7's three hot-path operations: authorization checks and token
    /// introspection are not hookable, so they are in no registry row and
    /// cannot be bound here either.
    #[must_use]
    pub fn bind<F, Fut>(mut self, event: &'static str, handler: F) -> Self
    where
        F: Fn(ReactorEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ReactorDecision> + Send + 'static,
    {
        if event_spec(event).is_none() {
            // The message names what IS hookable. It deliberately does not name
            // what is excluded: §22.13 requires the three hot-path operations to
            // be absent from every event constant this SDK exposes, and a list
            // of them here — even only to say they are refused — is exactly the
            // constant that would break it (§22.14 rule 2).
            let hookable: Vec<&str> = EVENT_REGISTRY.iter().map(|spec| spec.name).collect();
            self.errors.push(format!(
                "{event} is not a hookable reactor event; the registry is [{}]",
                hookable.join(", ")
            ));
            return self;
        }
        if self.handlers.contains_key(event) {
            // Never a silent overwrite: which of two handlers runs is not
            // something the author of either one can see from their own file.
            self.errors
                .push(format!("reactor event {event} is already bound"));
            return self;
        }

        self.handlers
            .insert(event, Arc::new(move |ev| Box::pin(handler(ev))));
        self.order.push(event);
        self
    }

    /// Bind a function carrying a [`macro@crate::reactor_handler`] attribute.
    ///
    /// The event name comes from the attribute, so it cannot disagree with the
    /// function it annotates, and the macro already rejected an unregistered
    /// name at compile time. This method re-checks it at run time anyway: the
    /// registry is the authority, and a macro that fell out of sync with it
    /// should fail loudly rather than bind a name the runtime will never
    /// dispatch.
    #[must_use]
    pub fn on<H: ReactorHandlerFn>(self) -> Self {
        self.bind(H::EVENT, |event| H::call(event))
    }

    /// The bound event names, in binding order.
    ///
    /// Pass them to
    /// [`default_failure_policy_for`](super::registry::default_failure_policy_for)
    /// to see what an unreachable reactor costs — the strictest default among
    /// them (§22.8) — derived from the code that handles the events rather than
    /// from a restatement of the registration.
    pub fn events(&self) -> &[&'static str] {
        &self.order
    }

    /// Compose the bindings into the handler
    /// [`reactor_serve`](super::runtime::reactor_serve) accepts.
    ///
    /// # Errors
    ///
    /// [`AxiamError::network`] listing every rejected binding, or naming an
    /// empty router: a reactor that handles nothing would consume its queue and
    /// abstain from every event, which looks exactly like an outage. It is the
    /// same variant [`ReactorConfigBuilder::build`](super::runtime::ReactorConfigBuilder::build)
    /// already returns for a misconfigured reactor, so one `?` covers wiring.
    pub fn build(
        self,
    ) -> Result<impl Fn(ReactorEvent) -> BoxedReactorFuture + Send + Sync + 'static, AxiamError>
    {
        if !self.errors.is_empty() {
            return Err(AxiamError::network(self.errors.join("; ")));
        }
        if self.handlers.is_empty() {
            return Err(AxiamError::network(
                "ReactorRouter has no bindings; bind at least one event",
            ));
        }

        let handlers = self.handlers;
        Ok(move |event: ReactorEvent| -> BoxedReactorFuture {
            match handlers.get(event.event.as_str()) {
                // Called directly, NOT wrapped (§22.14 rule 5): a handler's own
                // panic must reach `reactor_serve` unchanged so it publishes
                // nothing. Catching it here would satisfy the letter of §22.10
                // rule 2 while defeating it.
                Some(handler) => handler(event),
                // §22.14 rule 4. NOT `allow()`: abstaining publishes nothing and
                // lets the registration's `failure_policy` resolve this exactly
                // as it resolves a timeout (§22.8). This router does not know
                // what the registration was for; the operator's policy does.
                None => Box::pin(std::future::ready(ReactorDecision::Abstain)),
            }
        })
    }
}
