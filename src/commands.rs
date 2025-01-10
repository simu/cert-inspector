use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

use ::pem::{EncodeConfig, LineEnding};
use oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use rustls_pki_types::CertificateDer;
use x509_parser::prelude::*;

pub fn split_bundle(bundle: &[u8], path: &Path, output_prefix: &Option<String>) -> usize {
    let certs = ::pem::parse_many(bundle).unwrap();
    for (i, cert) in certs.iter().enumerate() {
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
        write!(
            &mut outbuf,
            "{}",
            ::pem::encode_config(cert, EncodeConfig::new().set_line_ending(LineEnding::LF))
        )
        .expect("Writing cert");
        outbuf.flush().expect("Flushing file");
    }
    certs.len()
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

pub fn cert_info<W: Write>(cert: &CertificateDer, out: &mut W) -> std::io::Result<()> {
    let (_, c) = X509Certificate::from_der(cert.as_ref()).expect("Parsing certificate");
    writeln!(out, "Subject:     {}", c.subject)?;
    writeln!(out, "Issuer:      {}", c.issuer)?;
    writeln!(out, "Not Before:  {}", c.validity.not_before)?;
    writeln!(out, "Not After:   {}", c.validity.not_after)?;
    writeln!(out, "DNS names:   {:?}", extract_dns_names(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::io::BufReader;
    use std::path::PathBuf;
    use std::str::FromStr;

    fn tmp_dir() -> PathBuf {
        let mut tmp_dir = std::env::temp_dir();
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        tmp_dir.push(format!("cert-inspector-test_{rand_string}"));
        tmp_dir
    }

    #[test]
    fn test_split_bundle() {
        let out_prefix = tmp_dir();
        std::fs::create_dir_all(&out_prefix).expect("creating temp dir");
        let out_prefix_str = out_prefix.as_os_str().to_str().unwrap().to_string();

        let path = PathBuf::from_str("testdata/ca-bundle.crt").unwrap();
        let bundledata = std::fs::read(&path).unwrap();

        let n = split_bundle(&bundledata, &path, &Some(format!("{out_prefix_str}/ca")));
        assert_eq!(n, 5);

        for i in 0..5 {
            let expected = std::fs::read(format!("testdata/ca-{i}.crt")).unwrap();
            let split = std::fs::read(format!("{out_prefix_str}/ca-{i}.crt")).unwrap();
            assert_eq!(split, expected);
        }
        std::fs::remove_dir_all(&out_prefix).expect("deleting tmp dir");
    }

    #[test]
    fn test_cert_info_0() {
        let cert = std::fs::File::open("testdata/ca-0.crt").unwrap();
        let mut buf = BufReader::new(cert);
        let cert = rustls_pemfile::certs(&mut buf).next().unwrap().unwrap();

        let mut out = std::io::Cursor::new(Vec::new());
        cert_info(&cert, &mut out).unwrap();

        let res = String::from_utf8(out.into_inner()).unwrap();
        let lines = res.trim_end().split("\n").collect::<Vec<&str>>();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "Subject:     CN=Test CA 1");
        assert_eq!(lines[1], "Issuer:      CN=Test CA 1");
        assert_eq!(lines[2], "Not Before:  Jan 10 13:18:59 2025 +00:00");
        assert_eq!(lines[3], "Not After:   Jan 10 13:18:59 2026 +00:00");
        assert_eq!(lines[4], "DNS names:   []");
    }

    #[test]
    fn test_cert_info_1() {
        let cert = std::fs::File::open("testdata/ca-1.crt").unwrap();
        let mut buf = BufReader::new(cert);
        let cert = rustls_pemfile::certs(&mut buf).next().unwrap().unwrap();

        let mut out = std::io::Cursor::new(Vec::new());
        cert_info(&cert, &mut out).unwrap();

        let res = String::from_utf8(out.into_inner()).unwrap();
        let lines = res.trim_end().split("\n").collect::<Vec<&str>>();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "Subject:     CN=Test CA 2");
        assert_eq!(lines[1], "Issuer:      CN=Test CA 2");
        assert_eq!(lines[2], "Not Before:  Jan 10 13:19:00 2025 +00:00");
        assert_eq!(lines[3], "Not After:   Jan 10 13:19:00 2027 +00:00");
        assert_eq!(lines[4], "DNS names:   []");
    }

    #[test]
    fn test_cert_info_2() {
        let cert = std::fs::File::open("testdata/ca-2.crt").unwrap();
        let mut buf = BufReader::new(cert);
        let cert = rustls_pemfile::certs(&mut buf).next().unwrap().unwrap();

        let mut out = std::io::Cursor::new(Vec::new());
        cert_info(&cert, &mut out).unwrap();

        let res = String::from_utf8(out.into_inner()).unwrap();
        let lines = res.trim_end().split("\n").collect::<Vec<&str>>();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "Subject:     CN=Test CA 3");
        assert_eq!(lines[1], "Issuer:      CN=Test CA 3");
        assert_eq!(lines[2], "Not Before:  Jan 10 13:19:00 2025 +00:00");
        assert_eq!(lines[3], "Not After:   Jan 10 13:19:00 2028 +00:00");
        assert_eq!(lines[4], "DNS names:   []");
    }

    #[test]
    fn test_cert_info_3() {
        let cert = std::fs::File::open("testdata/ca-3.crt").unwrap();
        let mut buf = BufReader::new(cert);
        let cert = rustls_pemfile::certs(&mut buf).next().unwrap().unwrap();

        let mut out = std::io::Cursor::new(Vec::new());
        cert_info(&cert, &mut out).unwrap();

        let res = String::from_utf8(out.into_inner()).unwrap();
        let lines = res.trim_end().split("\n").collect::<Vec<&str>>();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "Subject:     CN=Test CA 4");
        assert_eq!(lines[1], "Issuer:      CN=Test CA 4");
        assert_eq!(lines[2], "Not Before:  Jan 10 13:19:01 2025 +00:00");
        assert_eq!(lines[3], "Not After:   Jan  9 13:19:01 2029 +00:00");
        assert_eq!(lines[4], "DNS names:   []");
    }

    #[test]
    fn test_cert_info_4() {
        let cert = std::fs::File::open("testdata/ca-4.crt").unwrap();
        let mut buf = BufReader::new(cert);
        let cert = rustls_pemfile::certs(&mut buf).next().unwrap().unwrap();

        let mut out = std::io::Cursor::new(Vec::new());
        cert_info(&cert, &mut out).unwrap();

        let res = String::from_utf8(out.into_inner()).unwrap();
        let lines = res.trim_end().split("\n").collect::<Vec<&str>>();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "Subject:     CN=Test CA 5");
        assert_eq!(lines[1], "Issuer:      CN=Test CA 5");
        assert_eq!(lines[2], "Not Before:  Jan 10 13:19:02 2025 +00:00");
        assert_eq!(lines[3], "Not After:   Jan  9 13:19:02 2030 +00:00");
        assert_eq!(lines[4], "DNS names:   []");
    }
}
