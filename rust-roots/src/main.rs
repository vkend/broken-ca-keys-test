//! check-roots: the made-up leaf for api.example.com against the roots
//! bundled in webpki-roots (no OS roots), handed the eMudhra-issued
//! intermediate and emSign Root TLS CA - G3's cross-sign by emSign ECC Root
//! CA - G3. rustls-webpki is 0.103.15, so the only thing that changes between
//! runs is the webpki-roots version.
//!
//!   check-roots <leaf.pem> <intermediate.pem>...
use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let leaf = CertificateDer::from_pem_file(&args[0]).expect("leaf");
    let handed: Vec<CertificateDer> = args[1..].iter().map(|p| CertificateDer::from_pem_file(p).expect("cert")).collect();
    let roots = webpki_roots::TLS_SERVER_ROOTS;
    let has = |name: &[u8]| roots.iter().any(|r| r.subject.as_ref().windows(name.len()).any(|w| w == name));
    println!("webpki-roots: {} roots; emSign ECC Root CA - G3 {}; AAA Certificate Services {}", roots.len(),
             if has(b"emSign ECC Root CA - G3") { "included" } else { "not included" },
             if has(b"AAA Certificate Services") { "included" } else { "not included" });
    let ee = EndEntityCert::try_from(&leaf).expect("parse leaf");
    let res = ee
        .verify_for_usage(ALL_VERIFICATION_ALGS, roots, &handed, UnixTime::now(), KeyUsage::server_auth(), None, None)
        .map(|_| ())
        .and_then(|_| ee.verify_is_valid_for_subject_name(&ServerName::try_from("api.example.com").unwrap()));
    match res {
        Ok(()) => println!("result: trusted"),
        Err(e) => {
            let label = match format!("{e:?}").as_str() {
                "InvalidSignatureForPublicKey" => "trusted root: found, signature: made up",
                "UnknownIssuer" => "no trusted root",
                _ => "rejected",
            };
            println!("result: {label} ({e:?})");
        }
    }
}
