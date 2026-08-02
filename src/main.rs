use argus::{
    HtmlRenderer, JsonRenderer, MarkdownRenderer, Renderer, Report, RiskScoreSummary,
    TerminalRenderer, TokenSummary,
};
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

        /// Write output to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,

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
    /// Analyze multiple JWTs from a file (one token per line) or stdin
    #[command(group(
        ArgGroup::new("batch_key_source")
            .args(["secret", "secret_file", "public_key"])
            .multiple(false)
    ))]
    Batch {
        /// Path to a file containing one JWT per line. Omit to read
        /// tokens from stdin instead.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Terminal)]
        format: Format,

        /// Write output to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// HMAC secret applied to every token in the batch
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
    Markdown,
    Html,
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
            output,
            secret,
            secret_file,
            public_key,
        } => {
            let config = load_config_or_exit();
            let key = build_verification_key(secret, secret_file, public_key);
            let report = analyze_one(&token, &config, key.as_ref());
            emit_reports(&[report], format, output);
        }
        Commands::Batch {
            file,
            format,
            output,
            secret,
            secret_file,
            public_key,
        } => {
            let config = load_config_or_exit();
            let key = build_verification_key(secret, secret_file, public_key);
            let tokens = read_tokens(file);

            let reports: Vec<Report> = tokens
                .iter()
                .map(|token| analyze_one(token, &config, key.as_ref()))
                .collect();

            emit_reports(&reports, format, output);
        }
    }
}

/// Reads tokens either from a file (one per line) or from stdin if no
/// file path was given. Blank lines are skipped.
fn read_tokens(file: Option<PathBuf>) -> Vec<String> {
    let contents = match file {
        Some(path) => std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {e}", path.display());
            std::process::exit(1);
        }),
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .unwrap_or_else(|e| {
                    eprintln!("Error reading stdin: {e}");
                    std::process::exit(1);
                });
            buf
        }
    };

    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn load_config_or_exit() -> argus::Config {
    argus::Config::load(std::path::Path::new("argus.toml")).unwrap_or_else(|e| {
        eprintln!("Error loading config: {e}");
        std::process::exit(1);
    })
}

/// Runs the full analysis pipeline (decode, checks, scoring, optional
/// verification) for a single token, producing one `Report`.
///
/// This is the single core function both `analyze` and `batch` call —
/// batch mode is purely "call this once per token, collect the
/// results," with no separate analysis logic of its own.
fn analyze_one(
    token: &str,
    config: &argus::Config,
    key: Option<&argus::VerificationKey>,
) -> Report {
    let decoded = argus::decode(token).unwrap_or_else(|e| {
        eprintln!("Error decoding token: {e}");
        std::process::exit(1);
    });

    let findings = argus::run_all(&decoded, config);
    let risk = argus::score(&findings);

    let verification = key.map(|key| {
        let outcome = argus::verify::verify(&decoded, key);
        argus::report::VerificationSummary {
            outcome: outcome.into(),
            key_type: key.type_name(),
        }
    });

    Report {
        token_summary: TokenSummary {
            header: decoded.header,
            payload: decoded.payload,
        },
        findings,
        risk: RiskScoreSummary::from(risk),
        verification,
    }
}

fn emit_reports(reports: &[Report], format: Format, output: Option<PathBuf>) {
    let renderer: Box<dyn Renderer> = match format {
        Format::Terminal => Box::new(TerminalRenderer),
        Format::Json => Box::new(JsonRenderer),
        Format::Markdown => Box::new(MarkdownRenderer),
        Format::Html => Box::new(HtmlRenderer),
    };

    let rendered = renderer.render(reports);

    match output {
        Some(path) => {
            std::fs::write(&path, &rendered).unwrap_or_else(|e| {
                eprintln!("Error writing to {}: {e}", path.display());
                std::process::exit(1);
            });
            eprintln!("Report written to {}", path.display());
        }
        None => println!("{rendered}"),
    }
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
