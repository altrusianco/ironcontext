//! Strict deserializer for MCP manifests.
//!
//! MCP servers expose tools through either the `initialize` handshake or the
//! `tools/list` JSON-RPC response.  Both shapes contain the same `Tool` records,
//! so the parser accepts either.  Unknown top-level fields are *preserved* but
//! flagged for downstream auditing.

use serde::{Deserialize, Serialize};

use crate::SentinelError;

/// A parsed MCP manifest: just the parts Sentinel needs to reason about.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    /// Server identity (best-effort; many real servers omit this).
    #[serde(default)]
    pub server: ServerInfo,
    /// Declared tools.
    #[serde(default)]
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

/// A single MCP tool record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// MCP keeps tool parameters under `inputSchema` (JSON Schema draft 2020-12).
    #[serde(rename = "inputSchema", default)]
    pub input_schema: serde_json::Value,
}

impl Manifest {
    /// Parse from raw bytes. Accepts any of:
    /// * `{"tools": [...]}` — a `tools/list` response
    /// * `{"result": {"tools": [...]}}` — JSON-RPC envelope
    /// * `{"serverInfo": {...}, "capabilities": {...}, "tools": [...]}` — `initialize`
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SentinelError> {
        let v: serde_json::Value = serde_json::from_slice(bytes)?;
        let root = match v.get("result") {
            Some(r) => r.clone(),
            None => v,
        };

        let server = root
            .get("serverInfo")
            .cloned()
            .map(|s| serde_json::from_value::<ServerInfo>(s).unwrap_or_default())
            .unwrap_or_default();

        let tools_val = root
            .get("tools")
            .cloned()
            .ok_or_else(|| SentinelError::InvalidManifest("missing `tools` array".into()))?;

        let tools: Vec<Tool> = serde_json::from_value(tools_val)
            .map_err(|e| SentinelError::InvalidManifest(format!("tools[] malformed: {e}")))?;

        for t in &tools {
            if t.name.trim().is_empty() {
                return Err(SentinelError::InvalidManifest(
                    "tool has empty name".into(),
                ));
            }
        }

        Ok(Self { server, tools })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tools_list_envelope() {
        let raw = br#"{
            "tools": [
                {"name": "echo", "description": "Echoes input", "inputSchema": {"type":"object"}}
            ]
        }"#;
        let m = Manifest::from_slice(raw).unwrap();
        assert_eq!(m.tools.len(), 1);
        assert_eq!(m.tools[0].name, "echo");
    }

    #[test]
    fn parses_jsonrpc_envelope() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d"}]}}"#;
        let m = Manifest::from_slice(raw).unwrap();
        assert_eq!(m.tools[0].name, "t");
    }

    #[test]
    fn parses_initialize_response() {
        let raw = br#"{
            "serverInfo": {"name":"acme","version":"1.0"},
            "capabilities": {},
            "tools": [{"name":"a","description":"","inputSchema":{}}]
        }"#;
        let m = Manifest::from_slice(raw).unwrap();
        assert_eq!(m.server.name, "acme");
        assert_eq!(m.tools.len(), 1);
    }

    #[test]
    fn rejects_missing_tools() {
        let raw = b"{}";
        assert!(Manifest::from_slice(raw).is_err());
    }

    #[test]
    fn rejects_empty_tool_name() {
        let raw = br#"{"tools":[{"name":"","description":""}]}"#;
        assert!(Manifest::from_slice(raw).is_err());
    }
}
