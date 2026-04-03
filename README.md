# TLS Inspector

A Rust command-line tool that inspects TLS certificates of HTTPS URLs and displays certificate information along with trust status.

## Features

- Connect to any HTTPS URL and retrieve TLS certificate information
- Display certificate details:
  - Subject and Issuer
  - Serial Number
  - Validity period (Not Before / Not After)
  - SHA-256 Fingerprint
  - Certificate chain
- Verify certificate trust using the system's root certificate store
- Explain whether the certificate is trusted and why

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/tls-inspector`

## Usage

```bash
tls-inspector <HTTPS_URL>
```

### Examples

Inspect a valid certificate:
```bash
tls-inspector https://example.com
```

Inspect a certificate with trust issues:
```bash
tls-inspector https://untrusted-root.badssl.com
```

## Output Example

```
Connecting to example.com:443...

=== Certificate Information ===

Subject: CN=example.com
Issuer:  C=US, O=CLOUDFLARE, INC., CN=Cloudflare TLS Issuing ECC CA 1

Serial Number: 6520589ef17eb55c664433f29f2e684a

Validity:
  Not Before: Apr  2 21:18:57 2026 +00:00
  Not After:  Jul  1 21:24:46 2026 +00:00

Certificate Status:
  VALID (89 days remaining)

=== Trust Status ===

✓ TRUSTED

Reason: The certificate chain was verified successfully using the system's
root certificate store. The certificate is signed by a trusted CA
and is within its valid period.

=== Certificate Chain ===

Chain length: 3 certificate(s)
[1] CN=example.com
[2] C=US, O=CLOUDFLARE, INC., CN=Cloudflare TLS Issuing ECC CA 1
[3] C=US, O=SSL Corporation, CN=SSL.com TLS Transit ECC CA R2
```

## Dependencies

- **rustls** - Modern TLS library written in Rust
- **rustls-platform-verifier** - Uses the operating system's certificate verification
- **x509-parser** - X.509 certificate parsing
- **clap** - Command-line argument parsing
- **url** - URL parsing
- **sha2** - SHA-256 fingerprint calculation

## License

MIT