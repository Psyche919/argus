use super::Renderer;
use crate::report::Report;

pub struct JsonRenderer;

impl Renderer for JsonRenderer {
    fn render(&self, reports: &[Report]) -> String {
        serde_json::to_string_pretty(reports)
            .unwrap_or_else(|e| format!("{{\"error\": \"failed to serialize report: {e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{RiskScoreSummary, TokenSummary};
    use crate::scoring::SeverityCounts;

    #[test]
    fn renders_valid_json_array() {
        let report = Report {
            token_summary: TokenSummary {
                header: serde_json::json!({"alg": "HS256"}),
                payload: serde_json::json!({"sub": "test"}),
            },
            findings: vec![],
            risk: RiskScoreSummary {
                overall: None,
                counts: SeverityCounts::default(),
            },
        };

        let output = JsonRenderer.render(&[report]);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("output should be valid JSON");

        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }
}
