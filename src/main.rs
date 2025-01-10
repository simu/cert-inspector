use std::{
    fs::OpenOptions,
    io::{BufReader, BufWriter, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use rustls_pki_types::CertificateDer;
use x509_parser::prelude::*;

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

fn split_bundle(bundle: &[u8], path: &Path, output_prefix: &Option<String>) {
    for (i, cert) in ::pem::parse_many(bundle).unwrap().iter().enumerate() {
        let p = if let Some(prefix) = output_prefix {
            format!("{prefix}-{i}.crt")
        } else {
            let base = path
                .file_stem()
                .expect("stem")
                .to_str()
                .expect("stem string");
            format!("{base}-{i}.crt")
        };
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(p)
            .expect("opening output file");
        let mut outbuf = BufWriter::new(f);
        write!(&mut outbuf, "{cert}").expect("Writing cert");
        outbuf.flush().expect("Flushing file");
    }
}

fn extract_dns_names(cert: &X509Certificate) -> Vec<String> {
    if let Ok(Some(dns_ext)) = cert.get_extension_unique(&OID_X509_EXT_SUBJECT_ALT_NAME) {
        // copied from https://docs.rs/x509-parser/latest/src/print_cert/print-cert.rs.html
        match dns_ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                let mut res = vec![];
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => res.push(dns.to_string()),
                        GeneralName::IPAddress(b) => {
                            let ip = match b.len() {
                                4 => {
                                    let b = <[u8; 4]>::try_from(*b).unwrap();
                                    let ip = Ipv4Addr::from(b);
                                    format!("{}", ip)
                                }
                                16 => {
                                    let b = <[u8; 16]>::try_from(*b).unwrap();
                                    let ip = Ipv6Addr::from(b);
                                    format!("{}", ip)
                                }
                                l => format!("invalid (len={})", l),
                            };
                            res.push(ip.to_string())
                        }
                        _ => res.push(format!("{name:?}")),
                    }
                }
                res
            }
            _ => vec![],
        }
    } else {
        vec![]
    }
}

fn cert_info(cert: &CertificateDer) {
    let (_, c) = X509Certificate::from_der(cert.as_ref()).expect("Parsing certificate");
    println!("Subject:     {}", c.subject);
    println!("Issuer:      {}", c.issuer);
    println!("Not Before:  {}", c.validity.not_before);
    println!("Not After:   {}", c.validity.not_after);
    println!("DNS names:   {:?}", extract_dns_names(&c));
}

fn main() {
    let args = Cli::parse();

    match &args.command {
        Command::Split {
            path,
            output_prefix,
        } => {
            let cabundle = std::fs::read(path).expect("Reading file");

            split_bundle(&cabundle, path, output_prefix);
        }
        Command::Info { path } => {
            let bundlefile = std::fs::File::open(path).expect("opening file");
            let mut buf = BufReader::new(bundlefile);
            for (i, cert) in rustls_pemfile::certs(&mut buf).enumerate() {
                if let Ok(cert) = cert {
                    println!("Certificate {i}:");
                    cert_info(&cert);
                }
            }
        }
    }
}
