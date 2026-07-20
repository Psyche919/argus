use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// Argus's resolved configuration, after merging built-in defaults with
/// an optional `argus.toml` file.
///
/// A `Config` with no file present is always valid — every field has a
/// sensible default, so "no config file" is a normal, fully-functional
/// state, not an error case.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// IDs of checks that should be skipped during analysis.
    pub disabled_checks: Vec<String>,
}

/// The on-disk shape of `argus.toml`. This is intentionally a separate,
/// simpler type from `Config` — every field here is `Option`, since a
/// user's TOML file might specify none, some, or all of these settings.
/// `Config` is what the rest of Argus actually uses; `TomlConfig` is
/// purely a parsing target.
#[derive(Debug, Deserialize, Default)]
struct TomlConfig {
    disabled_checks: Option<Vec<String>>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file at {0}: {1}")]
    Read(String, std::io::Error),

    #[error("failed to parse config file at {0} as TOML: {1}")]
    Parse(String, toml::de::Error),
}

impl Config {
    /// Loads configuration by merging defaults with an optional
    /// `argus.toml` file at the given path.
    ///
    /// If `path` does not exist, this returns `Config::default()` — a
    /// missing config file is not an error, since "no config" is a
    /// deliberately valid state.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        if !path.exists() {
            return Ok(Config::default());
        }

        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.display().to_string(), e))?;

        let parsed: TomlConfig = toml::from_str(&contents)
            .map_err(|e| ConfigError::Parse(path.display().to_string(), e))?;

        Ok(Config {
            disabled_checks: parsed.disabled_checks.unwrap_or_default(),
        })
    }

    /// Returns `true` if the given check ID should be skipped.
    pub fn is_disabled(&self, check_id: &str) -> bool {
        self.disabled_checks.iter().any(|id| id == check_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_has_no_disabled_checks() {
        let config = Config::default();
        assert!(!config.is_disabled("alg-none"));
    }

    #[test]
    fn is_disabled_returns_true_for_listed_check() {
        let config = Config {
            disabled_checks: vec!["alg-none".to_string(), "expired".to_string()],
        };

        assert!(config.is_disabled("alg-none"));
        assert!(config.is_disabled("expired"));
        assert!(!config.is_disabled("missing-exp"));
    }

    #[test]
    fn load_returns_default_when_file_does_not_exist() {
        let path = Path::new("/tmp/argus-test-does-not-exist-12345.toml");
        let config = Config::load(path).expect("missing file should not be an error");

        assert!(config.disabled_checks.is_empty());
    }

    #[test]
    fn load_parses_disabled_checks_from_file() {
        let mut file = tempfile_with_contents(
            r#"
            disabled_checks = ["alg-none", "expired"]
            "#,
        );

        let config = Config::load(file.path()).expect("valid TOML should load successfully");

        assert_eq!(config.disabled_checks, vec!["alg-none", "expired"]);

        // Explicitly keep the file alive until here so it isn't deleted
        // before load() reads it.
        file.flush().unwrap();
    }

    #[test]
    fn load_returns_error_on_invalid_toml() {
        let file = tempfile_with_contents("this is not valid toml {{{");

        let result = Config::load(file.path());

        assert!(matches!(result, Err(ConfigError::Parse(_, _))));
    }

    /// Writes `contents` to a temp file and returns the open handle,
    /// keeping the file alive (and thus not deleted) for as long as the
    /// returned value is in scope.
    fn tempfile_with_contents(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("failed to create temp file");
        write!(file, "{contents}").expect("failed to write temp file contents");
        file
    }
}
