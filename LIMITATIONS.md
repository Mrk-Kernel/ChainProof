# ChainProof Limitations

ChainProof is a student/educational prototype. These limitations should be understood before
using the tool in any real investigation.

## Scope

- Single-case, single-user CLI tool. No multi-user access control, no case management, no
  role-based permissions.
- No graphical or web interface.
- No built-in evidence imaging or acquisition (use dedicated tools such as `dd`, FTK Imager,
  or Autopsy for forensic images).

## Cryptographic limitations

- Ed25519 signatures and SHA-256/SHA-3-256 hashes are strong primitives, but the security of
  the chain depends entirely on the secrecy of the signing key.
- The default key location (`case/keys/`) is inside the case directory and is not protected.
- RFC 3161 timestamps are optional and require network access to a TSA.
- No key rotation, no key escrow, no recovery if the private key is lost.

## Structural limitations

- Log truncation of trailing entries leaves a valid chain (see THREAT_MODEL.md).
- `--actor` is unauthenticated free text.
- No support for evidence containers, zip archives, or disk images beyond single-file hashing.
- No encryption of evidence files or log contents at rest.

## Operational limitations

- No secure deletion or wiping of evidence.
- No tamper-evident physical seals or storage logging.
- No integration with existing LIMS / evidence management systems.
- Tested only on small files; very large files stream-hash in 64 KiB chunks but have not been
  stress-tested at multi-GB scale.

## Standards

- ChainProof is *aligned with* ISO/IEC 27037 (identification, collection, acquisition,
  preservation) and ENFSI principles (integrity, documentation, traceability, reproducibility,
  independence), plus ISO/IEC 27041/27042/27043 for analysis/reporting/testimony.
- It makes **no claim of formal compliance** or legal admissibility.

## Intended audience

Educational use, learning chain-of-custody concepts, and prototyping. Not a certified forensic
product.
