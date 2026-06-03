# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, via the GitHub
Security Advisory form:

<https://github.com/WitSeal/witseal-py/security/advisories/new>

Include: a description, reproduction steps, affected versions, and how to
reach you. **Do not file a public issue for a security report.**

No dedicated security email or PGP key is published at this pre-release
stage; use the advisory form above.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix or mitigation | 90 days (high/critical), 180 days (medium/low) |
| Public disclosure | on fix, or 90 days (coordinated disclosure) |

## Scope

In scope: the SDK verifier and schema code in this repository (wire-format
models, canonicalization, hashing, receipt/chain/evidence verification, the
CLI). Out of scope at this stage: vulnerabilities in third-party
dependencies (report upstream), issues in agent frameworks that consume this
SDK, social engineering, and availability/DoS.

## Safe harbor

We support good-faith security research: report promptly, do not exploit
beyond what is needed to demonstrate the issue, do not access or destroy
data that is not yours, and give us a reasonable window to remediate before
public disclosure. Good-faith research conducted under this policy will not
be pursued.

## Cryptographic posture

- Receipt and event hashing: SHA-256 over RFC 8785 (JSON Canonicalization
  Scheme) canonical bytes.
- Signature verification: Ed25519, over an explicit public key supplied by
  the caller.
- **No private-key cryptography in this SDK.** The package verifies; it does
  not sign or hold keys. There are no secrets in the local SDK to leak.

## Verifying releases

When releases are published, build artifacts (wheel + sdist) are
accompanied by a `SHA256SUMS` checksum file, a CycloneDX SBOM, and Sigstore
(Cosign keyless) signatures with Rekor transparency-log entries. Release
verification instructions are included in each GitHub release's notes.
