use super::Renderer;
use crate::report::{Report, VerifyOutcomeSummary};
use std::fmt::Write;

pub struct HtmlRenderer;

impl Renderer for HtmlRenderer {
    fn render(&self, reports: &[Report]) -> String {
        let mut out = String::new();

        writeln!(out, "<!DOCTYPE html>").unwrap();
        writeln!(
            out,
            "<html><head><meta charset=\"utf-8\"><title>Argus Security Report</title>"
        )
        .unwrap();
        writeln!(out, "<style>{}</style></head><body>", CSS).unwrap();
        writeln!(out, "<h1>Argus Security Report</h1>").unwrap();
        writeln!(out, "<p>Analyzed {} token(s).</p>", reports.len()).unwrap();

        for (i, report) in reports.iter().enumerate() {
            writeln!(out, "<div class=\"token-report\">").unwrap();
            writeln!(out, "<h2>Token {}</h2>", i + 1).unwrap();
            render_one(report, &mut out);
            writeln!(out, "</div>").unwrap();
        }

        writeln!(out, "</body></html>").unwrap();
        out
    }
}

fn render_one(report: &Report, out: &mut String) {
    if let Some(verification) = &report.verification {
        writeln!(out, "<h3>Verification</h3>").unwrap();
        match &verification.outcome {
            VerifyOutcomeSummary::Verified => {
                writeln!(
                    out,
                    "<p class=\"verified\">&#10003; Signature verified</p><p>Key Type: {}</p>",
                    escape(verification.key_type)
                )
                .unwrap();
            }
            VerifyOutcomeSummary::Failed { reason } => {
                writeln!(
                    out,
                    "<p class=\"failed\">&#10007; Signature verification failed</p><p>Reason: {}</p>",
                    escape(reason)
                )
                .unwrap();
            }
            VerifyOutcomeSummary::KeyTypeMismatch {
                declared_alg,
                supplied_key_type,
            } => {
                writeln!(
                    out,
                    "<p class=\"mismatch\">&#9888; Key type mismatch</p><p>Declared: {} | Supplied: {}</p>",
                    escape(declared_alg),
                    escape(supplied_key_type)
                )
                .unwrap();
            }
        }
    }

    if report.findings.is_empty() {
        writeln!(
            out,
            "<p class=\"clean\">No issues found. Overall risk: None</p>"
        )
        .unwrap();
        return;
    }

    let overall = report
        .risk
        .overall
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| "None".to_string());

    writeln!(
        out,
        "<p class=\"overall-risk risk-{}\">Overall risk: {}</p>",
        overall.to_lowercase(),
        overall
    )
    .unwrap();

    writeln!(
        out,
        "<table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>"
    )
    .unwrap();
    writeln!(
        out,
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr></table>",
        report.risk.counts.critical,
        report.risk.counts.high,
        report.risk.counts.medium,
        report.risk.counts.low,
        report.risk.counts.info
    )
    .unwrap();

    writeln!(out, "<h3>Findings</h3>").unwrap();
    for finding in &report.findings {
        writeln!(
            out,
            "<div class=\"finding finding-{}\"><h4>[{:?}] {}</h4><p>{}</p></div>",
            format!("{:?}", finding.severity).to_lowercase(),
            finding.severity,
            escape(&finding.title),
            escape(&finding.description)
        )
        .unwrap();
    }
}

/// Escapes HTML-significant characters. This matters because finding
/// descriptions and titles are static text we wrote — but the payload
/// data displayed elsewhere in a report ultimately originates from the
/// JWT itself, which is attacker-controlled input. Never interpolate
/// untrusted content into HTML without escaping it first.
fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const CSS: &str = r#"
body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
.token-report { border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
.verified, .clean { color: #1a7f37; font-weight: bold; }
.failed { color: #cf222e; font-weight: bold; }
.mismatch { color: #9a6700; font-weight: bold; }
.overall-risk { font-weight: bold; padding: 0.5rem; border-radius: 4px; display: inline-block; }
.risk-critical { background: #ffebe9; color: #cf222e; }
.risk-high { background: #fff1e5; color: #bc4c00; }
.risk-medium { background: #fff8c5; color: #9a6700; }
.risk-low { background: #ddf4ff; color: #0969da; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #ddd; padding: 0.5rem 1rem; text-align: center; }
.finding { border-left: 4px solid #ccc; padding: 0.5rem 1rem; margin: 1rem 0; background: #f6f8fa; }
.finding-critical { border-color: #cf222e; }
.finding-high { border-color: #bc4c00; }
.finding-medium { border-color: #9a6700; }
.finding-low { border-color: #0969da; }
"#;
