use serde::Serialize;

use crate::checks::{Finding, Severity};

/// A summary of a token's overall risk, derived from its findings.
///
/// The `overall` severity answers "what's the single worst thing found
/// here?" — mirroring how a pentester actually triages: the first
/// question is always "is there a Critical in here," not "what's the
/// weighted average of every issue." The `counts` breakdown preserves
/// full detail underneath that headline number.
#[derive(Debug, Clone)]
pub struct RiskScore {
    /// The highest severity among all findings, or `None` if there were
    /// no findings at all (a clean token).
    pub overall: Option<Severity>,
    pub counts: SeverityCounts,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Computes a [`RiskScore`] from a set of findings.
///
/// This is a pure function: same findings in, same score out, every
/// time. It has no knowledge of where the findings came from (which
/// checks ran, in what order) — that separation is what makes this
/// trivial to unit test in isolation from the check engine.
pub fn score(findings: &[Finding]) -> RiskScore {
    let mut counts = SeverityCounts::default();

    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }

    let overall = findings.iter().map(|f| f.severity).max();

    RiskScore { overall, counts }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &'static str, severity: Severity) -> Finding {
        Finding {
            id,
            severity,
            title: "test finding".to_string(),
            description: "test description".to_string(),
        }
    }

    #[test]
    fn empty_findings_produce_no_overall_severity() {
        let result = score(&[]);

        assert!(result.overall.is_none());
        assert_eq!(result.counts.critical, 0);
        assert_eq!(result.counts.high, 0);
        assert_eq!(result.counts.medium, 0);
        assert_eq!(result.counts.low, 0);
        assert_eq!(result.counts.info, 0);
    }

    #[test]
    fn single_finding_sets_overall_to_its_severity() {
        let findings = vec![finding("x", Severity::Medium)];
        let result = score(&findings);

        assert_eq!(result.overall, Some(Severity::Medium));
        assert_eq!(result.counts.medium, 1);
    }

    #[test]
    fn overall_reflects_the_highest_severity_present() {
        let findings = vec![
            finding("a", Severity::Low),
            finding("b", Severity::Critical),
            finding("c", Severity::High),
        ];
        let result = score(&findings);

        assert_eq!(result.overall, Some(Severity::Critical));
    }

    #[test]
    fn counts_correctly_tally_multiple_findings_of_the_same_severity() {
        let findings = vec![
            finding("a", Severity::High),
            finding("b", Severity::High),
            finding("c", Severity::Medium),
        ];
        let result = score(&findings);

        assert_eq!(result.counts.high, 2);
        assert_eq!(result.counts.medium, 1);
        assert_eq!(result.overall, Some(Severity::High));
    }

    #[test]
    fn order_of_findings_does_not_affect_overall() {
        // Critical first vs. last should produce the same overall result —
        // overall must depend on severity value, not position in the list.
        let ascending = vec![
            finding("a", Severity::Low),
            finding("b", Severity::Critical),
        ];
        let descending = vec![
            finding("a", Severity::Critical),
            finding("b", Severity::Low),
        ];

        assert_eq!(score(&ascending).overall, score(&descending).overall);
    }
}
