//! Query handler trait: policy (or a test fake) behind one async entry point.

use std::sync::Mutex;

use dnscraft_policy::{PolicyAnswer, PolicyEngine, PolicyError, RequestContext};

/// Turns a [`RequestContext`] into a [`PolicyAnswer`].
///
/// Production code uses [`PolicyEngine`]; tests use [`FakeHandler`].
pub trait QueryHandler: Send + Sync {
    /// Handles one query.
    fn handle(
        &self,
        ctx: RequestContext,
    ) -> impl std::future::Future<Output = Result<PolicyAnswer, PolicyError>> + Send;
}

impl QueryHandler for PolicyEngine {
    async fn handle(&self, ctx: RequestContext) -> Result<PolicyAnswer, PolicyError> {
        PolicyEngine::handle(self, ctx).await
    }
}

impl<T: QueryHandler + ?Sized> QueryHandler for std::sync::Arc<T> {
    async fn handle(&self, ctx: RequestContext) -> Result<PolicyAnswer, PolicyError> {
        (**self).handle(ctx).await
    }
}

/// Test double: records every context and returns a canned answer.
#[derive(Debug)]
pub struct FakeHandler {
    recorded: Mutex<Vec<RequestContext>>,
    answer: Mutex<PolicyAnswer>,
}

impl FakeHandler {
    /// Creates a fake that returns `answer` for every call.
    pub fn new(answer: PolicyAnswer) -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            answer: Mutex::new(answer),
        }
    }

    /// Contexts seen so far (clone).
    pub fn recorded(&self) -> Vec<RequestContext> {
        self.recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replaces the canned answer.
    pub fn set_answer(&self, answer: PolicyAnswer) {
        *self
            .answer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = answer;
    }
}

impl QueryHandler for FakeHandler {
    async fn handle(&self, ctx: RequestContext) -> Result<PolicyAnswer, PolicyError> {
        self.recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ctx);
        Ok(self
            .answer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }
}
