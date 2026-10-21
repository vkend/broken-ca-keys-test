// Bakes the rustls-webpki version from Cargo.lock into the binary, so the
// program says which version it was built with (what's compiled in, not
// what the lockfile says now).
fn main() {
    let lock = std::fs::read_to_string("Cargo.lock").expect("Cargo.lock");
    let v = lock
        .split("name = \"rustls-webpki\"\nversion = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("unknown")
        .to_string();
    println!("cargo:rustc-env=WEBPKI_VERSION={v}");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
