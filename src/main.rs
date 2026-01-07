use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Split ca-bundle into separate files
    Split {
        /// The ca-bundle to split. Special name "-" reads from stdin.
        path: PathBuf,
        /// The output file prefix
        output_prefix: Option<String>,
    },
    /// Print information about each certificate in the bundle
    Info {
        /// The ca-bundle to read. Special name "-" reads from stdin.
        path: PathBuf,
    },

    /// Print the version of cert-inspector
    Version {},
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn stdin_or_file(path: &Path) -> Result<Box<dyn Read + 'static>, String> {
    let input: Box<dyn std::io::Read + 'static> = if path.as_os_str() == "-" {
        Box::new(std::io::stdin())
    } else {
        match std::fs::File::open(&path) {
            Ok(file) => Box::new(file),
            Err(err) => {
                return Err(format!("{}: {}", path.display(), err));
            }
        }
    };
    Ok(input)
}

fn main() {
    let args = Cli::parse();

    match &args.command {
        Command::Split {
            path,
            output_prefix,
        } => {
            let mut input = stdin_or_file(&path).expect("opening file");
            let mut cabundle = String::new();
            input.read_to_string(&mut cabundle).expect("reading file");

            let n = commands::split_bundle(cabundle.as_bytes(), path, output_prefix);
            println!(
                "Split bundle {} into {n} certificates",
                path.as_os_str().to_str().unwrap()
            );
        }
        Command::Info { path } => {
            let bundlefile = stdin_or_file(&path).expect("opening file");
            let mut buf = BufReader::new(bundlefile);
            for (i, cert) in rustls_pemfile::certs(&mut buf).enumerate() {
                if let Ok(cert) = cert {
                    println!("Certificate {i}:");
                    commands::cert_info(&cert, &mut std::io::stdout()).expect("printing info");
                }
            }
        }
        Command::Version {} => {
            println!("cert-inspector v{VERSION}");
        }
    }
}
