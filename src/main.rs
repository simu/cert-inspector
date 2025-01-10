use std::{io::BufReader, path::PathBuf};

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
        /// The ca-bundle to split
        path: PathBuf,
        /// The output file prefix
        output_prefix: Option<String>,
    },
    /// Print information about each certificate in the bundle
    Info {
        /// The ca-bundle to split
        path: PathBuf,
    },
}

fn main() {
    let args = Cli::parse();

    match &args.command {
        Command::Split {
            path,
            output_prefix,
        } => {
            let cabundle = std::fs::read(path).expect("Reading file");

            let n = commands::split_bundle(&cabundle, path, output_prefix);
            println!(
                "Split bundle {} into {n} certificates",
                path.as_os_str().to_str().unwrap()
            );
        }
        Command::Info { path } => {
            let bundlefile = std::fs::File::open(path).expect("opening file");
            let mut buf = BufReader::new(bundlefile);
            for (i, cert) in rustls_pemfile::certs(&mut buf).enumerate() {
                if let Ok(cert) = cert {
                    println!("Certificate {i}:");
                    commands::cert_info(&cert, &mut std::io::stdout()).expect("printing info");
                }
            }
        }
    }
}
