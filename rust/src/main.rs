//! check: verify a made-up certificate for api.example.com the way a Rust
//! program using rustls and the Mac's own trusted roots does
//! (rustls-native-certs; read only, nothing about trust is changed).
//!
//!   ./check            the made-up leaf and Sectigo's AAA cross-sign of
//!                      EM DV TLS CA - G3B (the real, public certificate)
//!   ./check --control  the made-up leaf alone: no way to a trusted root
//!
//! The leaf's signature is made up (setup.sh signs it with a throwaway key),
//! so the best it can do is fail on that signature: the one check that
//! someone holding the real key would pass. Run from ~/app; prints file
//! names only, never paths.
use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage, anchor_from_trusted_cert};

const LEAF: &str = "certs/api.example.com.pem";
const CROSS_SIGN: &str = "certs/EM-DV-TLS-CA-G3B-AAA.pem";

fn load(path: &str) -> Vec<CertificateDer<'static>> {
    let certs: Result<Vec<_>, _> = match CertificateDer::pem_file_iter(path) {
        Ok(it) => it.collect(),
        Err(_) => {
            println!("cannot read {path}: run this from ~/app");
            std::process::exit(2)
        }
    };
    certs.unwrap_or_else(|_| {
        println!("{path}: not a PEM certificate");
        std::process::exit(2)
    })
}

// A minimal DER walk to the subject's and issuer's common names, so the
// program can say what it was handed without another dependency.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for _ in 0..n {
            let (&x, r) = rest.split_first()?;
            len = (len << 8) | x as usize;
            rest = r;
        }
        len
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn common_name(name: &[u8]) -> String {
    let mut sets = name;
    let mut cn = String::from("?");
    while let Some((_, set, next)) = tlv(sets) {
        let mut atvs = set;
        while let Some((_, atv, more)) = tlv(atvs) {
            if let Some((_, oid, val)) = tlv(atv) {
                if oid == [0x55, 0x04, 0x03] {
                    if let Some((_, v, _)) = tlv(val) {
                        cn = String::from_utf8_lossy(v).into_owned();
                    }
                }
            }
            atvs = more;
        }
        sets = next;
    }
    cn
}

/// (subject CN, issuer CN)
fn names(der: &[u8]) -> (String, String) {
    let parse = || -> Option<(String, String)> {
        let (_, cert, _) = tlv(der)?;
        let (_, tbs, _) = tlv(cert)?;
        let mut f = tbs;
        let (tag, _, r) = tlv(f)?;
        if tag == 0xa0 {
            f = r; // explicit version
        }
        let (_, _, f) = tlv(f)?; // serial
        let (_, _, f) = tlv(f)?; // signature algorithm
        let (_, issuer, f) = tlv(f)?;
        let (_, _, f) = tlv(f)?; // validity
        let (_, subject, _) = tlv(f)?;
        Some((common_name(subject), common_name(issuer)))
    };
    parse().unwrap_or_else(|| ("?".into(), "?".into()))
}

fn main() {
    let control = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--control") => true,
        Some(_) => {
            println!("usage: ./check [--control]");
            std::process::exit(2)
        }
    };
    let leaf = load(LEAF).remove(0);
    let handed_over: Vec<CertificateDer> = if control { vec![] } else { load(CROSS_SIGN) };

    let native = rustls_native_certs::load_native_certs();
    let anchors: Vec<_> = native
        .certs
        .iter()
        .filter_map(|c| anchor_from_trusted_cert(c).ok())
        .collect();

    println!(
        "rustls-webpki {}, checking against this Mac's trusted roots ({})",
        env!("WEBPKI_VERSION"),
        anchors.len()
    );
    println!("handed:");
    for der in std::iter::once(&leaf).chain(handed_over.iter()) {
        let (subject, issuer) = names(der);
        println!("  {subject:<20} issued by {issuer}");
    }

    let ee = match EndEntityCert::try_from(&leaf) {
        Ok(ee) => ee,
        Err(e) => {
            println!("cannot parse the leaf: {e}");
            std::process::exit(2)
        }
    };
    let res = ee
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &anchors,
            &handed_over,
            UnixTime::now(),
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .and_then(|_| {
            ee.verify_is_valid_for_subject_name(&ServerName::try_from("api.example.com").unwrap())
        });

    match res {
        Ok(()) => println!("trusted"),
        Err(e) => {
            // By name: CertDistrusted only exists from 0.103.16 on, and the
            // same source builds against both versions.
            let name = format!("{e:?}");
            let label = match name.as_str() {
                "InvalidSignatureForPublicKey" => "trusted root: found, signature: made up",
                "UnknownIssuer" => "no trusted root",
                "CertDistrusted" => "distrusted key",
                _ => "rejected",
            };
            println!("{label}");
            println!("error: {e}");
            std::process::exit(1)
        }
    }
}
