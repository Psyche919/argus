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
    }
}
