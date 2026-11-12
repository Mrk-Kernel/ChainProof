# ChainProof Threat Model

ChainProof is a student/educational prototype for tamper-evident evidence and chain-of-custody
tracking. This document states honestly what it protects against and what it does not.

## Assets

- Evidence files registered in a case directory
- The hash-chained, Ed25519-signed audit log (`logs/audit.jsonl`)
- The Ed25519 signing keypair
- Exported custody reports (JSON/PDF)

## Threat actors

1. **Case-folder attacker** — has read/write access to the case directory (including the
   audit log and, by default, the signing key).
2. **External attacker** — modifies evidence files on disk without touching the log.
3. **Insider / analyst** — legitimate user who wants to deny or alter a logged action.
4. **Concurrent / crash** — two processes append at once, or power loss mid-append.

## What ChainProof protects against

| Threat | Protection |
|--------|------------|
| Evidence file altered after logging | `verify --evidence` re-hashes files on disk and compares SHA-256/SHA-3-256 to the logged values |
| Audit log entry edited after signing | Entry hash recomputation detects any field change |
| Audit log entry deleted from middle | Hash chain linkage (`prev_hash`) breaks |
| Log entry signature forged | Ed25519 signature verification with the public key |
| Concurrent writes corrupting the log | File lock + `fsync` on every append |
| Crash mid-append | `fsync` after each write; torn writes are detectable via JSON line parsing |
| Head hash repudiation | Optional RFC 3161 timestamp anchor over the head hash (`report --anchor`) |

## What ChainProof does NOT protect against (known limitations)

1. **Key compromise in the case directory** — By default the Ed25519 private key lives in
   `case/keys/`. Anyone with access to the case folder can recompute every entry hash and
   re-sign the entire chain, making verification pass on a fully fabricated log. Use
   `--key-dir` to store the key outside the case directory and protect it separately.
2. **Log truncation** — Deleting the last N entries leaves a valid chain from genesis to the
   new head. RFC 3161 anchoring bounds this window but does not eliminate it unless the head
   hash is published/archived externally after each case milestone.
3. **Reordering / swap** — Swapping two adjacent entries invalidates `prev_hash` linkage, so
   this IS detected. Reordering non-adjacent entries also breaks the chain. Truncation is the
   only structural attack that leaves a mathematically valid chain.
4. **Unauthenticated actor** — `--actor` is free text with no identity binding. An analyst can
   log actions as any name. Bind actors to per-user keys for stronger attribution.
5. **TSA compromise / unavailability** — RFC 3161 timestamps rely on a trusted third-party
   Time-Stamping Authority. If the TSA is compromised or unreachable, timestamps are untrusted
   or missing. The tool degrades gracefully (no token) but does not substitute local time.
6. **No secure deletion** — Evidence files remain on disk after the case; the tool does not
   wipe or encrypt them.
7. **No legal admissibility guarantee** — This is a prototype. Hash chains and signatures are
   supporting evidence, not proof of admissibility in any jurisdiction.

## Recommended operational mitigations

- Store the Ed25519 private key on a separate system, HSM, or offline medium; only the public
  key needs to be in the case directory.
- Publish the head hash (and report) to an external, immutable location (email, print, S3 with
  Object Lock, blockchain anchor) after each major case milestone.
- Use `verify --evidence` before every handoff and before report export.
- Restrict case directory access to authorized personnel.
- Document actors separately from the tool; treat `--actor` as a claim, not proof of identity.
