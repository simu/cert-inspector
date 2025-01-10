use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
};

use clap::Parser;

#[derive(Parser)]
struct Cli {
    /// The ca-bundle to split
    path: std::path::PathBuf,
    /// The output file prefix
    output_prefix: Option<String>,
}
fn main() {
    let args = Cli::parse();
    println!(
        "Called with {:?} and output pattern {:?}",
        args.path, args.output_prefix,
    );

    let cabundle = std::fs::read(&args.path).expect("Reading file");

    for (i, cert) in pem::parse_many(&cabundle[0..]).unwrap().iter().enumerate() {
        let p = if let Some(prefix) = &args.output_prefix {
            format!("{prefix}-{i}.crt")
        } else {
            let base = args
                .path
                .file_stem()
                .expect("stem")
                .to_str()
                .expect("stem string");
            format!("{base}-{i}.crt")
        };
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .open(p)
            .expect("opening output file");
        let mut outbuf = BufWriter::new(f);
        write!(&mut outbuf, "{cert}").expect("Writing cert");
        outbuf.flush().expect("Flushing file");
    }
}
