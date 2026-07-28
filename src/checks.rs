mod alg_none;
mod excessive_lifetime;
mod expired;
mod header_shape;
mod iat_future;
mod missing_exp;
mod nbf_future;
mod sensitive_data;

use serde::Serialize;

use crate::token::DecodedToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

pub trait Check {
    fn id(&self) -> &'static str;
    fn run(&self, token: &DecodedToken) -> Option<Finding>;
}

/// Returns every check Argus knows about, in a fixed, deterministic order.
///
/// This is the single place that decides which checks exist — adding a
/// new check means adding one line here, not modifying any existing check.
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(header_shape::HeaderShapeCheck),
        Box::new(alg_none::AlgNoneCheck),
        Box::new(missing_exp::MissingExpCheck),
        Box::new(expired::ExpiredCheck),
        Box::new(nbf_future::NbfFutureCheck),
        Box::new(iat_future::IatFutureCheck),
        Box::new(sensitive_data::SensitiveDataCheck),
        Box::new(excessive_lifetime::ExcessiveLifetimeCheck),
    ]
}

/// Runs every registered check against a token, collecting all findings.
pub fn run_all(token: &DecodedToken, config: &crate::config::Config) -> Vec<Finding> {
    all_checks()
        .iter()
        .filter(|check| !config.is_disabled(check.id()))
        .filter_map(|check| check.run(token))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::decode;

    #[test]
    fn alg_none_check_fires_on_alg_none_token() {
        let token = decode("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.").unwrap();
        let finding = alg_none::AlgNoneCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "alg-none");
    }

    #[test]
    fn alg_none_check_does_not_fire_on_hs256_token() {
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let finding = alg_none::AlgNoneCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn header_shape_check_fires_when_alg_is_missing() {
        let token = decode("eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0In0.").unwrap();
        let finding = header_shape::HeaderShapeCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "header-shape");
    }

    #[test]
    fn header_shape_check_does_not_fire_on_well_formed_header() {
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let finding = header_shape::HeaderShapeCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn missing_exp_check_fires_when_exp_is_absent() {
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let finding = missing_exp::MissingExpCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "missing-exp");
    }

    #[test]
    fn missing_exp_check_does_not_fire_when_exp_is_present() {
        let token = decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwMDAwMDAwfQ.c2lnbmF0dXJl",
        )
        .unwrap();
        let finding = missing_exp::MissingExpCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn expired_check_fires_on_past_exp() {
        let token = decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwMDAwMDAwfQ.c2lnbmF0dXJl",
        )
        .unwrap();
        let finding = expired::ExpiredCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "expired");
    }

    #[test]
    fn expired_check_does_not_fire_when_exp_is_absent() {
        // This is the important boundary case you designed for: expired
        // only judges tokens that HAVE an exp claim. A missing exp claim
        // is missing_exp's responsibility, not expired's.
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let finding = expired::ExpiredCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn run_all_collects_findings_from_multiple_checks() {
        // The alg:none token should trigger both alg-none and missing-exp.
        let token = decode("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.").unwrap();
        let config = crate::config::Config::default();
        let findings = run_all(&token, &config);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.id == "alg-none"));
        assert!(findings.iter().any(|f| f.id == "missing-exp"));
    }

    #[test]
    fn nbf_future_check_fires_when_nbf_is_in_future() {
        let token = decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmJmIjo5OTk5OTk5OTk5fQ.c2ln",
        )
        .unwrap();
        let finding = nbf_future::NbfFutureCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "nbf-future");
    }

    #[test]
    fn nbf_future_check_does_not_fire_when_nbf_is_absent() {
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let finding = nbf_future::NbfFutureCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn iat_future_check_fires_when_iat_is_in_future() {
        let token = decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0Ijo5OTk5OTk5OTk5fQ.c2ln",
        )
        .unwrap();
        let finding = iat_future::IatFutureCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "iat-future");
    }

    #[test]
    fn iat_future_check_does_not_fire_when_iat_is_in_past() {
        let token = decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxMDAwMDAwMDAwfQ.c2ln",
        )
        .unwrap();
        let finding = iat_future::IatFutureCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn sensitive_data_check_fires_on_password_claim() {
        let token =
            decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXNzd29yZCI6InNlY3JldDEyMyJ9.c2ln")
                .unwrap();
        let finding = sensitive_data::SensitiveDataCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "sensitive-data-exposure");
    }

    #[test]
    fn sensitive_data_check_does_not_fire_on_benign_claims() {
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let finding = sensitive_data::SensitiveDataCheck.run(&token);

        assert!(finding.is_none());
    }

    #[test]
    fn excessive_lifetime_check_fires_on_long_lived_token() {
        // iat=0, exp=1000000 (~277 hours) — far beyond the 24-hour threshold.
        let token =
            decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjAsImV4cCI6MTAwMDAwMH0.c2ln")
                .unwrap();
        let finding = excessive_lifetime::ExcessiveLifetimeCheck.run(&token);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().id, "excessive-lifetime");
    }

    #[test]
    fn excessive_lifetime_check_does_not_fire_on_short_lived_token() {
        // iat=0, exp=3600 (1 hour) — well within the 24-hour threshold.
        let token = decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjAsImV4cCI6MzYwMH0.c2ln")
            .unwrap();
        let finding = excessive_lifetime::ExcessiveLifetimeCheck.run(&token);

        assert!(finding.is_none());
    }
}
