//! Minimal SARIF 2.1.0 emitter.
//!
//! SARIF is the standard format consumed by GitHub Code Scanning, Azure
//! DevOps, and most enterprise SAST dashboards.  We hand-build the JSON
//! rather than pulling a heavyweight schema crate; the subset we emit is
//! validated by `tests/sarif_validates.rs` against a vendored schema fixture.

use serde::Serialize;
use serde_json::{json, Value};

use crate::rules::{Finding, RuleId, Severity};

const TOOL_NAME: &str = "IronContext";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const INFO_URI: &str = "https://github.com/altrusianco/ironcontext";

#[derive(Debug, Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Value>,
}

pub fn to_sarif(findings: &[Finding], manifest_uri: &str) -> SarifLog {
    let rules: Vec<Value> = all_rule_ids()
        .iter()
        .map(|r| {
            json!({
                "id": r.code(),
                "name": format!("{:?}", r),
                "shortDescription": {"text": r.title()},
                "defaultConfiguration": {"level": default_level(*r)}
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule.code(),
                "level": severity_to_level(f.severity),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": manifest_uri},
                        "region": {"startLine": 1}
                    },
                    "logicalLocations": [{
                        "name": f.tool,
                        "kind": "function"
                    }]
                }],
                "properties": {
                    "tool": f.tool,
                    "excerpt": f.excerpt,
                }
            })
        })
        .collect();

    SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![json!({
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": INFO_URI,
                    "rules": rules
                }
            },
            "results": results
        })],
    }
}

fn severity_to_level(s: Severity) -> &'static str {
    match s {
        Severity::Info => "note",
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High => "error",
        Severity::Critical => "error",
    }
}

fn default_level(r: RuleId) -> &'static str {
    match r {
        RuleId::Cc001HiddenInstructions | RuleId::Cc010ExfilSink => "error",
        RuleId::Cc002InvisibleUnicode
        | RuleId::Cc003CrossToolShadow
        | RuleId::Cc005ConfusedDeputy
        | RuleId::Cc007ExcessivePrivilege
        | RuleId::Cc008HomoglyphName
        | RuleId::Cc009UriPreFetch => "error",
        RuleId::Cc004RugPullSurface | RuleId::Cc006OpenRedirect => "warning",
    }
}

fn all_rule_ids() -> [RuleId; 10] {
    [
        RuleId::Cc001HiddenInstructions,
        RuleId::Cc002InvisibleUnicode,
        RuleId::Cc003CrossToolShadow,
        RuleId::Cc004RugPullSurface,
        RuleId::Cc005ConfusedDeputy,
        RuleId::Cc006OpenRedirect,
        RuleId::Cc007ExcessivePrivilege,
        RuleId::Cc008HomoglyphName,
        RuleId::Cc009UriPreFetch,
        RuleId::Cc010ExfilSink,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_valid_sarif_skeleton() {
        let s = to_sarif(&[], "manifest.json");
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len() >= 10);
    }
}
