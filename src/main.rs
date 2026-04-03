use clap::Parser;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha256};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "tls-inspector")]
#[command(about = "Inspect TLS certificate of an HTTPS URL", long_about = None)]
struct Args {
    #[arg(help = "HTTPS URL to inspect")]
    url: String,
}

fn get_proxy() -> Option<(String, u16)> {
    for var in &["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Ok(val) = env::var(var) {
            if !val.is_empty() {
                if let Ok(url) = Url::parse(&val) {
                    let host = url.host_str().map(|s| s.to_string());
                    let port = url.port().unwrap_or(8080);
                    if let Some(h) = host {
                        return Some((h, port));
                    }
                }
            }
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let parsed_url = Url::parse(&args.url).map_err(|e| format!("Invalid URL: {}", e))?;

    if parsed_url.scheme() != "https" {
        return Err("Only HTTPS URLs are supported".into());
    }

    let host = parsed_url.host_str().ok_or("URL must have a host")?;
    let port = parsed_url.port().unwrap_or(443);

    let proxy = get_proxy();
    if let Some(ref p) = proxy {
        println!("Using proxy {}:{}", p.0, p.1);
    }
    println!("Connecting to {}:{}...", host, port);
    println!();

    let config = ClientConfig::builder()
        .with_platform_verifier()
        .map_err(|e| format!("Failed to create config: {}", e))?
        .with_no_client_auth();

    let config = Arc::new(config);

    let server_name: ServerName = host
        .to_string()
        .try_into()
        .map_err(|_| "Invalid server name")?;

    let mut conn = rustls::client::ClientConnection::new(config, server_name)?;

    let connect_host;
    let connect_port;
    if let Some(ref p) = proxy {
        connect_host = p.0.clone();
        connect_port = p.1;
    } else {
        connect_host = host.to_string();
        connect_port = port;
    }

    let mut tcp_stream = TcpStream::connect(format!("{}:{}", connect_host, connect_port))?;
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp_stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    if proxy.is_some() {
        let target_host = host.to_string();
        let target_port = port;
        let connect_msg = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            target_host, target_port, target_host, target_port
        );
        tcp_stream.write_all(connect_msg.as_bytes())?;

        let mut response = String::new();
        tcp_stream.read_to_string(&mut response)?;

        if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
            return Err(format!("Proxy connection failed: {}", response).into());
        }

        if let Some(pos) = response.find("\r\n\r\n") {
            let body = &response[pos + 4..];
            if !body.is_empty() && !body.trim().is_empty() {
                return Err(format!("Proxy connection failed: {}", body).into());
            }
        }
    }

    let mut verification_error: Option<String> = None;

    loop {
        if conn.wants_write() {
            conn.write_tls(&mut tcp_stream)?;
        }
        if conn.wants_read() {
            match conn.read_tls(&mut tcp_stream) {
                Ok(0) => break,
                Ok(_) => {
                    if let Err(e) = conn.process_new_packets() {
                        verification_error = Some(e.to_string());
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    verification_error = Some(e.to_string());
                    break;
                }
            }
        }
        if !conn.is_handshaking() {
            break;
        }
    }

    let certs = conn
        .peer_certificates()
        .filter(|c| !c.is_empty())
        .unwrap_or_default();

    if certs.is_empty() {
        if let Some(ref err) = verification_error {
            println!("=== Connection Failed ===");
            println!();
            println!("✗ NOT TRUSTED");
            println!();
            println!("Error: {}", err);
            return Ok(());
        }
        return Err("No certificates received".into());
    }

    let cert_der = &certs[0];
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    println!("=== Certificate Information ===");
    println!();

    let subject = cert.subject();
    let issuer = cert.issuer();
    println!("Subject: {}", subject);
    println!("Issuer:  {}", issuer);
    println!();

    let serial = cert.serial.to_str_radix(16);
    println!("Serial Number: {}", serial);
    println!();

    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    println!("Validity:");
    println!("  Not Before: {}", validity.not_before);
    println!("  Not After:  {}", validity.not_after);

    println!();
    println!("Certificate Status:");
    if now < not_before {
        println!("  NOT YET VALID");
    } else if now > not_after {
        println!("  EXPIRED");
    } else {
        let days_remaining = (not_after - now) / 86400;
        println!("  VALID");
        println!("  ({} days remaining)", days_remaining);
    }
    println!();

    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let fingerprint = hex::encode(hasher.finalize());

    println!("SHA-256 Fingerprint:");
    for (i, chunk) in fingerprint.as_bytes().chunks(2).enumerate() {
        if i > 0 && i % 8 == 0 {
            print!(":\n  ");
        } else if i > 0 {
            print!(":");
        }
        print!("{}", std::str::from_utf8(chunk).unwrap());
    }
    println!();
    println!();

    println!("=== Trust Status ===");
    println!();

    if verification_error.is_none()
        && !conn.is_handshaking()
        && conn.negotiated_cipher_suite().is_some()
    {
        println!("✓ TRUSTED");
        println!();
        println!("Reason: The certificate chain was verified successfully using the system's");
        println!("root certificate store. The certificate is signed by a trusted CA");
        println!("and is within its valid period.");
    } else {
        println!("✗ NOT TRUSTED");
        println!();
        if let Some(ref err) = verification_error {
            println!("Error: {}", err);
        }
        println!();
        println!("Reason: Certificate verification failed. Possible reasons:");
        println!("  - Certificate is self-signed");
        println!("  - Certificate chain is incomplete");
        println!("  - Certificate has expired");
        println!("  - Certificate is revoked");
        println!("  - Root CA not found in system trust store");
    }

    println!();
    println!("=== Certificate Chain ===");
    println!();
    println!("Chain length: {} certificate(s)", certs.len());
    for (i, cert_der) in certs.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
            .map_err(|e| format!("Failed to parse certificate: {}", e))?;
        println!("[{}] {}", i + 1, cert.subject());
    }

    Ok(())
}
