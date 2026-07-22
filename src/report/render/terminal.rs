use super::Renderer;
use crate::report::Report;
use std::fmt::Write;

pub struct TerminalRenderer;

impl Renderer for TerminalRenderer {
    fn render(&self, reports: &[Report]) -> String {
        let mut out = String::new();

        for report in reports {
            render_one(report, &mut out);
        }

        out
    }
}

fn render_one(report: &Report, out: &mut String) {
    if report.findings.is_empty() {
        writeln!(out, "No issues found. Overall risk: None").unwrap();
        return;
    }

    match report.risk.overall {
        Some(severity) => writeln!(out, "Overall risk: {severity:?}").unwrap(),
        None => unreachable!("overall is None only when findings is empty, handled above"),
    }

    writeln!(
        out,
        "Findings: {} Critical, {} High, {} Medium, {} Low, {} Info\n",
        report.risk.counts.critical,
        report.risk.counts.high,
        report.risk.counts.medium,
        report.risk.counts.low,
        report.risk.counts.info
    )
    .unwrap();

    for finding in &report.findings {
        writeln!(out, "[{:?}] {}", finding.severity, finding.title).unwrap();
        writeln!(out, "  {}", finding.description).unwrap();
        writeln!(out).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Finding, Severity};
    use crate::report::{RiskScoreSummary, TokenSummary};
    use crate::scoring::SeverityCounts;

    fn sample_report(findings: Vec<Finding>, overall: Option<Severity>) -> Report {
        Report {
            token_summary: TokenSummary {
                header: serde_json::json!({"alg": "HS256"}),
                payload: serde_json::json!({"sub": "test"}),
            },
            findings,
            risk: RiskScoreSummary {
                overall,
                counts: SeverityCounts::default(),
            },
        }
    }

    #[test]
    fn renders_clean_message_when_no_findings() {
        let report = sample_report(vec![], None);
        let output = TerminalRenderer.render(&[report]);

        assert!(output.contains("No issues found"));
    }

    #[test]
    fn renders_overall_severity_and_finding_details() {
        let finding = Finding {
            id: "alg-none",
            severity: Severity::Critical,
            title: "Token uses alg: none".to_string(),
            description: "some description".to_string(),
        };
        let report = sample_report(vec![finding], Some(Severity::Critical));
        let output = TerminalRenderer.render(&[report]);

        assert!(output.contains("Overall risk: Critical"));
        assert!(output.contains("Token uses alg: none"));
        assert!(output.contains("some description"));
    }

    #[test]
    fn renders_multiple_reports_in_sequence() {
        let report_a = sample_report(vec![], None);
        let report_b = sample_report(vec![], None);
        let output = TerminalRenderer.render(&[report_a, report_b]);

        // Both reports' "clean" messages should appear — proving a
        // slice of multiple reports renders each one, not just the first.
        assert_eq!(output.matches("No issues found").count(), 2);
    }
}
