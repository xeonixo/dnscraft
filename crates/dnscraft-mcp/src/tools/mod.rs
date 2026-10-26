//! Server handler and tool catalog.
//!
//! Each tool lives in a submodule and is registered on [`McpServer`] by the
//! `#[tool_router]` macro. The per-request factory clones the shared handle.

pub mod read;

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::ProtocolVersion;
use rmcp::{ServerHandler, tool_handler};

use crate::backend::McpBackend;
use crate::config::McpConfig;

/// Shared state cloned into every per-request server instance.
#[derive(Clone)]
pub struct McpServer {
    pub(crate) backend: Arc<dyn McpBackend>,
    pub(crate) config: McpConfig,
}

impl McpServer {
    /// A server handle over `backend` and `config`.
    pub fn new(backend: Arc<dyn McpBackend>, config: McpConfig) -> Self {
        Self { backend, config }
    }
}

#[tool_handler(name = "dnscraft-mcp")]
impl ServerHandler for McpServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        if self.config.legacy_session_mode {
            Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS)
        } else {
            Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
        }
    }
}
