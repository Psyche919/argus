use super::Renderer;
use crate::report::{Report, VerifyOutcomeSummary};
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
    if let Some(verification) = &report.verification {
        writeln!(out, "Verification").unwrap();
        writeln!(out, "------------").unwrap();
        match &verification.outcome {
            VerifyOutcomeSummary::Verified => {
                writeln!(out, "\u{2713} Signature verified").unwrap();
                writeln!(out, "Key Type: {}", verification.key_type).unwrap();
            }
            VerifyOutcomeSummary::Failed { reason } => {
                writeln!(out, "\u{2717} Signature verification failed").unwrap();
                writeln!(out, "Reason: {reason}").unwrap();
            }
            VerifyOutcomeSummary::KeyTypeMismatch {
                declared_alg,
                supplied_key_type,
            } => {
                writeln!(out, "\u{26A0} Key type does not match declared algorithm").unwrap();
                writeln!(out, "Declared algorithm: {declared_alg}").unwrap();
                writeln!(out, "Supplied key type: {supplied_key_type}").unwrap();
            }
        }
        writeln!(out).unwrap();
    }

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
            verification: None,
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

        assert_eq!(output.matches("No issues found").count(), 2);
    }
}
