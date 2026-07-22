use argus::{JsonRenderer, Renderer, Report, RiskScoreSummary, TerminalRenderer, TokenSummary};
use clap::{Parser, Subcommand, ValueEnum};

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
    Analyze {
        /// The raw JWT string to analyze
        token: String,

        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Terminal)]
        format: Format,
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
        Commands::Analyze { token, format } => {
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

            let report = Report {
                token_summary: TokenSummary {
                    header: decoded.header,
                    payload: decoded.payload,
                },
                findings,
                risk: RiskScoreSummary::from(risk),
            };

            let renderer: Box<dyn Renderer> = match format {
                Format::Terminal => Box::new(TerminalRenderer),
                Format::Json => Box::new(JsonRenderer),
            };

            let output = renderer.render(&[report]);
            println!("{output}");
        }
    }
}
