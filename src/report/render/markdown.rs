use super::Renderer;
use crate::report::{Report, VerifyOutcomeSummary};
use std::fmt::Write;

pub struct MarkdownRenderer;

impl Renderer for MarkdownRenderer {
    fn render(&self, reports: &[Report]) -> String {
        let mut out = String::new();

        writeln!(out, "# Argus Security Report\n").unwrap();
        writeln!(out, "Analyzed **{}** token(s).\n", reports.len()).unwrap();

        for (i, report) in reports.iter().enumerate() {
            writeln!(out, "## Token {}\n", i + 1).unwrap();
            render_one(report, &mut out);
        }

        out
    }
}

fn render_one(report: &Report, out: &mut String) {
    if let Some(verification) = &report.verification {
        writeln!(out, "### Verification\n").unwrap();
        match &verification.outcome {
            VerifyOutcomeSummary::Verified => {
                writeln!(out, "- **Status:** ✅ Signature verified").unwrap();
                writeln!(out, "- **Key Type:** {}\n", verification.key_type).unwrap();
            }
            VerifyOutcomeSummary::Failed { reason } => {
                writeln!(out, "- **Status:** ❌ Signature verification failed").unwrap();
                writeln!(out, "- **Reason:** {reason}\n").unwrap();
            }
            VerifyOutcomeSummary::KeyTypeMismatch {
                declared_alg,
                supplied_key_type,
            } => {
                writeln!(out, "- **Status:** ⚠️ Key type mismatch").unwrap();
                writeln!(out, "- **Declared algorithm:** {declared_alg}").unwrap();
                writeln!(out, "- **Supplied key type:** {supplied_key_type}\n").unwrap();
            }
        }
    }

    if report.findings.is_empty() {
        writeln!(out, "**No issues found.** Overall risk: None\n").unwrap();
        return;
    }

    let overall = report
        .risk
        .overall
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| "None".to_string());

    writeln!(out, "**Overall risk:** {overall}\n").unwrap();
    writeln!(
        out,
        "| Critical | High | Medium | Low | Info |\n|---|---|---|---|---|\n| {} | {} | {} | {} | {} |\n",
        report.risk.counts.critical,
        report.risk.counts.high,
        report.risk.counts.medium,
        report.risk.counts.low,
        report.risk.counts.info
    )
    .unwrap();

    writeln!(out, "### Findings\n").unwrap();
    for finding in &report.findings {
        writeln!(out, "#### [{:?}] {}\n", finding.severity, finding.title).unwrap();
        writeln!(out, "{}\n", finding.description).unwrap();
    }
}
