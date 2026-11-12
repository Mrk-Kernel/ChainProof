"""chainproof.py - ChainProof: tamper-evident evidence and chain-of-custody toolkit."""

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.hashing import hash_file
from modules.signing import generate_keypair, load_private_key, load_public_key
from modules.auditlog import AuditLog, GENESIS_PREV_HASH
from modules.timestamp import TimestampClient
from modules.report import ReportExporter
from modules import standards


def build_parser():
    parser = argparse.ArgumentParser(
        prog="chainproof",
        description="Tamper-evident evidence and chain-of-custody toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize a new case directory.")
    p_init.add_argument("case_dir", nargs="?", default="case", help="Case directory (default: case)")
    p_init.add_argument("--actor", default="system", help="Actor name for genesis entry")
    p_init.add_argument("--key-dir", help="Directory to store Ed25519 keypair (default: case_dir/keys)")

    p_add = sub.add_parser("add", help="Register an evidence file.")
    p_add.add_argument("file", help="Path to evidence file")
    p_add.add_argument("--case-dir", default="case", help="Case directory (default: case)")
    p_add.add_argument("--actor", default="analyst", help="Actor name")
    p_add.add_argument("--tsa-url", help="RFC 3161 TSA URL for trusted timestamps")

    p_action = sub.add_parser("action", help="Log a custody action.")
    p_action.add_argument("type", help="Action type (e.g. ACCESS, TRANSFER, ANALYSIS, RELEASE)")
    p_action.add_argument("actor", help="Actor name")
    p_action.add_argument("details", nargs="?", default="", help="Action details")
    p_action.add_argument("--case-dir", default="case", help="Case directory (default: case)")
    p_action.add_argument("--tsa-url", help="RFC 3161 TSA URL for trusted timestamps")

    p_verify = sub.add_parser("verify", help="Verify audit log chain integrity.")
    p_verify.add_argument("--case-dir", default="case", help="Case directory (default: case)")
    p_verify.add_argument("--evidence", action="store_true",
                          help="Also re-hash evidence files on disk and compare with logged hashes")
    p_verify.add_argument("--evidence-root", default=None,
                          help="Root directory for evidence files (default: case_dir/evidence)")

    p_report = sub.add_parser("report", help="Export custody report (JSON or PDF).")
    p_report.add_argument("--case-dir", default="case", help="Case directory (default: case)")
    p_report.add_argument("--format", choices=["json", "pdf"], default="json", help="Report format")
    p_report.add_argument("--out", help="Output path")
    p_report.add_argument("--anchor", action="store_true",
                          help="RFC 3161 timestamp the head hash before exporting")
    p_report.add_argument("--tsa-url", help="RFC 3161 TSA URL for anchoring")

    p_status = sub.add_parser("status", help="Show case summary.")
    p_status.add_argument("--case-dir", default="case", help="Case directory (default: case)")

    sub.add_parser("standards", help="Print ISO/IEC 27037 and ENFSI alignment.")

    return parser


def _key_dir(case_dir, args):
    if getattr(args, "key_dir", None):
        return Path(args.key_dir)
    return case_dir / "keys"


def cmd_init(args):
    case_dir = Path(args.case_dir)
    (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (case_dir / "logs").mkdir(parents=True, exist_ok=True)
    (case_dir / "reports").mkdir(parents=True, exist_ok=True)

    key_dir = _key_dir(case_dir, args)
    key_dir.mkdir(parents=True, exist_ok=True)

    generate_keypair(case_dir, key_dir=key_dir)
    private_key = load_private_key(case_dir, key_dir=key_dir)

    log = AuditLog(case_dir)
    log.genesis(actor=args.actor, private_key=private_key)

    print(f"Case initialized at {case_dir}")
    print(f"  evidence/   - evidence files")
    print(f"  logs/       - hash-chained audit log")
    print(f"  keys/       - Ed25519 signing keypair ({key_dir})")
    print(f"  reports/    - exported custody reports")
    return 0


def cmd_add(args):
    case_dir = Path(args.case_dir)
    log = AuditLog(case_dir)
    if not log.entries:
        print("Case not initialized. Run 'chainproof init' first.")
        return 1

    digest = hash_file(args.file)
    evidence = {
        "path": digest["path"],
        "name": digest["name"],
        "size": digest["size"],
        "sha256": digest["sha256"],
        "sha3_256": digest["sha3_256"],
    }

    token = None
    tsa_url = args.tsa_url
    if tsa_url:
        client = TimestampClient(tsa_url)
        result = client.request(digest["sha256"])
        token = result["token_b64"]
        print(f"Timestamp: {result['status_string']}")

    key_dir = _key_dir(case_dir, args)
    private_key = load_private_key(case_dir, key_dir=key_dir)
    entry = log.append("EVIDENCE_ADDED", args.actor, evidence=evidence,
                       timestamp_token=token, private_key=private_key)

    print(f"Evidence added: {digest['name']}")
    print(f"  SHA-256: {digest['sha256']}")
    print(f"  SHA-3-256: {digest['sha3_256']}")
    print(f"  Log entry #{entry['index']} (hash {entry['entry_hash'][:16]}...)")
    return 0


def cmd_action(args):
    case_dir = Path(args.case_dir)
    log = AuditLog(case_dir)
    if not log.entries:
        print("Case not initialized. Run 'chainproof init' first.")
        return 1

    evidence = None
    if args.details:
        evidence = {"details": args.details}

    token = None
    if args.tsa_url:
        client = TimestampClient(args.tsa_url)
        payload_hash = hashlib.sha256(f"{args.type}|{args.actor}|{args.details}".encode()).hexdigest()
        result = client.request(payload_hash)
        token = result["token_b64"]
        print(f"Timestamp: {result['status_string']}")

    key_dir = _key_dir(case_dir, args)
    private_key = load_private_key(case_dir, key_dir=key_dir)
    entry = log.append(args.type.upper(), args.actor, evidence=evidence,
                       timestamp_token=token, private_key=private_key)

    print(f"Action logged: {args.type.upper()} by {args.actor} (entry #{entry['index']})")
    return 0


def cmd_verify(args):
    case_dir = Path(args.case_dir)
    log = AuditLog(case_dir)
    if not log.entries:
        print("No audit log found.")
        return 1

    key_dir = _key_dir(case_dir, args)
    public_key = load_public_key(case_dir, key_dir=key_dir)
    ok, message = log.verify(public_key=public_key)
    status = "PASS" if ok else "FAIL"
    print(f"Chain verification: {status} - {message}")

    if args.evidence:
        ev_root = args.evidence_root
        ev_ok, results = log.verify_evidence(evidence_root=ev_root)
        print(f"Evidence verification: {'PASS' if ev_ok else 'FAIL'}")
        for r in results:
            mark = "OK " if r["match"] else "BAD"
            err = f" ({r.get('error')})" if r.get("error") else ""
            print(f"  [{mark}] {r['path']}{err}")
            if not r["match"]:
                ok = False

    return 0 if ok else 1


def cmd_report(args):
    case_dir = Path(args.case_dir)
    log = AuditLog(case_dir)
    if not log.entries:
        print("No audit log found.")
        return 1

    key_dir = _key_dir(case_dir, args)
    public_key = load_public_key(case_dir, key_dir=key_dir)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:32]

    head_hash = log.entries[-1]["entry_hash"]

    anchor_result = None
    if args.anchor:
        anchor_result = log.anchor_head(tsa_url=args.tsa_url)
        print(f"Head anchor: {anchor_result['status_string']}")

    exporter = ReportExporter(case_dir, log, public_key_fingerprint=fingerprint,
                              head_hash=head_hash, anchor_result=anchor_result)

    if args.out:
        out_path = Path(args.out)
    else:
        ext = "pdf" if args.format == "pdf" else "json"
        out_path = case_dir / "reports" / f"custody_report.{ext}"

    if args.format == "pdf":
        exporter.export_pdf(out_path)
    else:
        exporter.export_json(out_path)

    print(f"Report exported: {out_path} ({args.format})")
    return 0


def cmd_status(args):
    case_dir = Path(args.case_dir)
    log = AuditLog(case_dir)
    if not log.entries:
        print("Case not initialized.")
        return 1

    key_dir = _key_dir(case_dir, args)
    public_key = load_public_key(case_dir, key_dir=key_dir)
    ok, message = log.verify(public_key=public_key)
    print(f"Case directory: {case_dir}")
    print(f"Log entries: {len(log.entries)}")
    print(f"Chain verification: {'PASS' if ok else 'FAIL'} - {message}")
    print(f"Head hash: {log.entries[-1]['entry_hash'][:32]}...")
    genesis = log.entries[0]
    print(f"Initialized: {genesis['timestamp']} by {genesis['actor']}")
    return 0


def cmd_standards(_args):
    print("ISO/IEC 27037 alignment:")
    for phase, desc in standards.ISO_IEC_27037.items():
        print(f"  - {phase.capitalize()}: {desc}")
    print()
    print("Additional phases (ISO/IEC 27041/27042/27043):")
    for phase, desc in standards.ADDITIONAL_PHASES.items():
        print(f"  - {phase.capitalize()}: {desc}")
    print()
    print("ENFSI principles:")
    for principle, desc in standards.ENFSI.items():
        print(f"  - {principle.capitalize()}: {desc}")
    print()
    print(standards.STANDARDS_NOTE)
    print()
    print(standards.DISCLAIMER)
    return 0


COMMANDS = {
    "init": cmd_init,
    "add": cmd_add,
    "action": cmd_action,
    "verify": cmd_verify,
    "report": cmd_report,
    "status": cmd_status,
    "standards": cmd_standards,
}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
