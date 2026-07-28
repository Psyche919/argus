use argus::{JsonRenderer, Renderer, Report, RiskScoreSummary, TerminalRenderer, TokenSummary};
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "argus",
    version,
    about = "See what your tokens are hiding — a JWT security analysis toolkit"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a JWT and print its header and payload as JSON
    Decode {
        /// The raw JWT string to decode
        token: String,
    },
    /// Analyze a JWT for common security issues
    #[command(group(
        ArgGroup::new("key_source")
            .args(["secret", "secret_file", "public_key"])
            .multiple(false)
    ))]
    Analyze {
        /// The raw JWT string to analyze
        token: String,

        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Terminal)]
        format: Format,

        /// HMAC secret, passed directly (avoid for sensitive secrets —
        /// prefer --secret-file, since shell history can leak this)
        #[arg(long)]
        secret: Option<String>,

        /// Path to a file containing the HMAC secret
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Path to a PEM-encoded RSA public key file
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Terminal,
    Json,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Decode { token } => match argus::decode(&token) {
            Ok(decoded) => {
                println!("Header:");
                println!("{}", serde_json::to_string_pretty(&decoded.header).unwrap());
                println!();
                println!("Payload:");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&decoded.payload).unwrap()
                );
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
        Commands::Analyze {
            token,
            format,
            secret,
            secret_file,
            public_key,
        } => run_analyze(token, format, secret, secret_file, public_key),
    }
}

fn run_analyze(
    token: String,
    format: Format,
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    public_key: Option<PathBuf>,
) {
    let config = match argus::Config::load(std::path::Path::new("argus.toml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config: {e}");
            std::process::exit(1);
        }
    };

    let decoded = match argus::decode(&token) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let findings = argus::run_all(&decoded, &config);
    let risk = argus::score(&findings);

    let verification_key = build_verification_key(secret, secret_file, public_key);

    let verification = verification_key.map(|key| {
        let outcome = argus::verify::verify(&decoded, &key);
        argus::report::VerificationSummary {
            outcome: outcome.into(),
            key_type: key.type_name(),
        }
    });

    let report = Report {
        token_summary: TokenSummary {
            header: decoded.header,
            payload: decoded.payload,
        },
        findings,
        risk: RiskScoreSummary::from(risk),
        verification,
    };

    let renderer: Box<dyn Renderer> = match format {
        Format::Terminal => Box::new(TerminalRenderer),
        Format::Json => Box::new(JsonRenderer),
    };

    let output = renderer.render(&[report]);
    println!("{output}");
}

/// Resolves the mutually-exclusive key-source flags into a single
/// `VerificationKey`, or `None` if no key was supplied at all.
fn build_verification_key(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    public_key: Option<PathBuf>,
) -> Option<argus::VerificationKey> {
    if let Some(secret) = secret {
        return Some(argus::VerificationKey::Hmac(secret.into_bytes()));
    }

    if let Some(path) = secret_file {
        let contents = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Error reading secret file {}: {e}", path.display());
            std::process::exit(1);
        });
        return Some(argus::VerificationKey::Hmac(
            contents.trim_end().as_bytes().to_vec(),
        ));
    }

    if let Some(path) = public_key {
        let key = argus::load_rsa_public_key(&path).unwrap_or_else(|e| {
            eprintln!("Error loading public key: {e}");
            std::process::exit(1);
        });
        return Some(argus::VerificationKey::RsaPublic(key));
    }

    None
}
