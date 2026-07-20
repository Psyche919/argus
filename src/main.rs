use clap::{Parser, Subcommand};

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
    },
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
        Commands::Analyze { token } => match argus::decode(&token) {
            Ok(decoded) => {
                let findings = argus::run_all(&decoded);
                let risk = argus::score(&findings);

                if findings.is_empty() {
                    println!("No issues found. Overall risk: None");
                    return;
                }

                match risk.overall {
                    Some(severity) => println!("Overall risk: {severity:?}"),
                    None => {
                        unreachable!("overall is None only when findings is empty, handled above")
                    }
                }
                println!(
                    "Findings: {} Critical, {} High, {} Medium, {} Low, {} Info\n",
                    risk.counts.critical,
                    risk.counts.high,
                    risk.counts.medium,
                    risk.counts.low,
                    risk.counts.info
                );

                for finding in &findings {
                    println!("[{:?}] {}", finding.severity, finding.title);
                    println!("  {}", finding.description);
                    println!();
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
    }
}
