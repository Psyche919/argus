pub mod render;

use crate::checks::{Finding, Severity};
use crate::scoring::{RiskScore, SeverityCounts};
use serde::Serialize;

/// A summary of the decoded token, independent of any findings —
/// just enough context for a report to show *what* was analyzed.
#[derive(Debug, Clone, Serialize)]
pub struct TokenSummary {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
}

/// The complete result of analyzing one JWT: what it contained, what
/// was found, and the overall risk. This is the single source of truth
/// every renderer works from — no renderer re-derives data from a
/// `DecodedToken` or `Vec<Finding>` directly.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub token_summary: TokenSummary,
    pub findings: Vec<Finding>,
    pub risk: RiskScoreSummary,
}

/// A `Serialize`-friendly mirror of `RiskScore`. Kept as a separate type
/// (rather than deriving `Serialize` on `RiskScore` itself) so that
/// `scoring.rs` stays focused purely on computing risk, with no
/// knowledge of output formats leaking into it.
#[derive(Debug, Clone, Serialize)]
pub struct RiskScoreSummary {
    pub overall: Option<Severity>,
    pub counts: SeverityCounts,
}

impl From<RiskScore> for RiskScoreSummary {
    fn from(risk: RiskScore) -> Self {
        RiskScoreSummary {
            overall: risk.overall,
            counts: risk.counts,
        }
    }
}
