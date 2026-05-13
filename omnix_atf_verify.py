#!/usr/bin/env python3
"""
OMNIX ATF Public Verifier — omnix_atf_verify.py
================================================
ATF-INV-006: Independent verification of Delegation Receipts and
Agent Identity Records without access to the OMNIX platform.

Usage:
    python omnix_atf_verify.py receipt.json
    python omnix_atf_verify.py receipt.json --public-key <base64-pubkey>
    python omnix_atf_verify.py receipt.json --chain chain.json
    python omnix_atf_verify.py --mode agent identity.json
    python omnix_atf_verify.py --mode chain chain.json
    python omnix_atf_verify.py --mode replay    (verify all receipts in current dir)
    echo '{"delegation_id":"..."}' | python omnix_atf_verify.py --stdin

This verifier is a standalone tool. It requires no network access, no
OMNIX account, no API key, and no database connection. All verification
is performed using cryptographic operations on the provided receipt files.

Protocol: RFC-ATF-1 (OMNIX QUANTUM Open Standard)
Reference: https://omnixquantum.com/atf/verify
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
GOLD   = "\033[33m"

ATF_BANNER = f"""
{BOLD}{GOLD}╔══════════════════════════════════════════════════════════════╗
║          OMNIX ATF Public Verifier — RFC-ATF-1               ║
║  Post-Quantum Agent Delegation Receipt Verification Tool     ║
║  Version 1.0.0 — OMNIX QUANTUM LTD — May 2026               ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""

ATF_FOOTER = f"""
{GRAY}─────────────────────────────────────────────────────────────{RESET}
{GRAY}Protocol: RFC-ATF-1 · Algorithm: ML-DSA-65 (Dilithium-3)    {RESET}
{GRAY}This verification requires no platform access (ATF-INV-006)  {RESET}
{GRAY}OMNIX QUANTUM LTD · https://omnixquantum.com/atf            {RESET}
"""


@dataclass
class VerificationResult:
    delegation_id: str
    hash_valid: bool
    pqc_signature_valid: bool
    pqc_checked: bool
    mar_invariant_valid: bool
    not_expired: bool
    fully_verified: bool
    delegation_depth: int
    authority_budget_granted: float
    authority_reduction_pct: float
    chain_root_id: str
    pqc_signed: bool
    delegator_id: str
    delegate_id: str
    status: str
    failure_reasons: List[str]
    warnings: List[str]


def _canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compute_content_hash(receipt: Dict[str, Any]) -> str:
    exclude = {"content_hash", "pqc_signature", "pqc_algorithm"}
    clean = {k: v for k, v in receipt.items() if k not in exclude}
    return _sha256(_canonical_json(clean))


def _verify_pqc_signature(
    content_hash: str,
    pqc_signature_b64: str,
    public_key_b64: str,
) -> Tuple[bool, str]:
    """
    Verify a Dilithium-3 (ML-DSA-65) signature over a content hash.
    Returns (valid: bool, algorithm: str).
    """
    try:
        from pqc.sign import dilithium3 as dil
        sig = base64.b64decode(pqc_signature_b64)
        pk  = base64.b64decode(public_key_b64)
        dil.verify(sig, content_hash.encode("utf-8"), pk)
        return True, "ML-DSA-65 (Dilithium-3)"
    except ImportError:
        pass

    try:
        import dilithium
        sig = base64.b64decode(pqc_signature_b64)
        pk  = base64.b64decode(public_key_b64)
        result = dilithium.verify(sig, content_hash.encode("utf-8"), pk)
        return bool(result), "ML-DSA-65 (Dilithium-3)"
    except ImportError:
        pass

    return False, "UNAVAILABLE — install pqc library for signature verification"


def _check_expiry(expires_at: Optional[str]) -> Tuple[bool, Optional[str]]:
    if not expires_at:
        return True, None
    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if now > exp:
            return False, f"Receipt expired at {expires_at}"
        delta = exp - now
        hours = int(delta.total_seconds() / 3600)
        return True, f"Expires in {hours}h ({expires_at})"
    except Exception as exc:
        return False, f"Could not parse expires_at: {exc}"


def verify_receipt(
    receipt: Dict[str, Any],
    public_key_override: Optional[str] = None,
) -> VerificationResult:
    failure_reasons: List[str] = []
    warnings: List[str] = []

    delegation_id = receipt.get("delegation_id", "UNKNOWN")
    delegator_id = receipt.get("delegator_id", "")
    delegate_id = receipt.get("delegate_id", "")
    chain_root_id = receipt.get("chain_root_id", "")
    delegation_depth = int(receipt.get("delegation_depth", 0))
    authority_budget_delegator = float(receipt.get("authority_budget_delegator", 0))
    authority_budget_granted = float(receipt.get("authority_budget_granted", 0))
    pqc_signature = receipt.get("pqc_signature")
    pqc_algorithm = receipt.get("pqc_algorithm")
    delegator_public_key = public_key_override or receipt.get("delegator_public_key", "")
    embedded_hash = receipt.get("content_hash", "")
    status = receipt.get("status", "UNKNOWN")
    expires_at = receipt.get("expires_at")

    recomputed_hash = _compute_content_hash(receipt)
    hash_valid = (recomputed_hash == embedded_hash)
    if not hash_valid:
        failure_reasons.append(
            f"Content hash MISMATCH — receipt has been tampered with\n"
            f"   Expected: {embedded_hash}\n"
            f"   Got:      {recomputed_hash}"
        )

    pqc_valid = False
    pqc_checked = False
    pqc_algo_used = "N/A"
    if pqc_signature and delegator_public_key:
        pqc_checked = True
        pqc_valid, pqc_algo_used = _verify_pqc_signature(
            embedded_hash, pqc_signature, delegator_public_key
        )
        if not pqc_valid:
            failure_reasons.append(
                f"PQC signature INVALID — cannot verify delegator authorization\n"
                f"   Algorithm: {pqc_algo_used}"
            )
    elif not pqc_signature:
        warnings.append("No PQC signature — SHA-256 hash only (ATF Level-1)")
    elif not delegator_public_key:
        warnings.append("delegator_public_key missing — PQC verification skipped")

    mar_valid = authority_budget_granted <= authority_budget_delegator
    if not mar_valid:
        failure_reasons.append(
            f"ATF-INV-001 VIOLATED — authority expansion detected\n"
            f"   granted={authority_budget_granted} > delegator={authority_budget_delegator}\n"
            f"   This receipt must be rejected."
        )

    not_expired, expiry_note = _check_expiry(expires_at)
    if not not_expired:
        failure_reasons.append(f"Receipt EXPIRED: {expiry_note}")
    elif expiry_note:
        warnings.append(expiry_note)

    if status == "REVOKED":
        failure_reasons.append("Receipt has been REVOKED — invalid for all purposes")
    elif status == "EXPIRED":
        failure_reasons.append("Receipt status is EXPIRED")

    if authority_budget_delegator > 0:
        reduction_pct = round(
            (1.0 - authority_budget_granted / authority_budget_delegator) * 100.0, 2
        )
    else:
        reduction_pct = 0.0

    fully_verified = (
        hash_valid and mar_valid and not_expired
        and status == "ACTIVE"
        and (pqc_valid if pqc_checked else True)
        and len(failure_reasons) == 0
    )

    return VerificationResult(
        delegation_id=delegation_id,
        hash_valid=hash_valid,
        pqc_signature_valid=pqc_valid,
        pqc_checked=pqc_checked,
        mar_invariant_valid=mar_valid,
        not_expired=not_expired,
        fully_verified=fully_verified,
        delegation_depth=delegation_depth,
        authority_budget_granted=authority_budget_granted,
        authority_reduction_pct=reduction_pct,
        chain_root_id=chain_root_id,
        pqc_signed=pqc_signature is not None,
        delegator_id=delegator_id,
        delegate_id=delegate_id,
        status=status,
        failure_reasons=failure_reasons,
        warnings=warnings,
    )


def verify_chain(chain: List[Dict[str, Any]]) -> Dict[str, Any]:
    results = []
    mar_chain_valid = True
    prev_budget = 100.0
    chain_root_ids = set()
    all_verified = True

    for dr in chain:
        vr = verify_receipt(dr)
        results.append(vr)
        chain_root_ids.add(vr.chain_root_id)
        if not vr.fully_verified:
            all_verified = False
        if vr.authority_budget_granted > prev_budget:
            mar_chain_valid = False
        prev_budget = vr.authority_budget_granted

    depth_valid = all(
        chain[i]["delegation_depth"] == chain[i-1]["delegation_depth"] + 1
        for i in range(1, len(chain))
    ) if len(chain) > 1 else True

    root_consistent = len(chain_root_ids) <= 1
    ccs = _compute_chain_ccs(results)

    return {
        "chain_length": len(chain),
        "all_verified": all_verified and mar_chain_valid and depth_valid and root_consistent,
        "mar_chain_valid": mar_chain_valid,
        "depth_monotone": depth_valid,
        "root_id_consistent": root_consistent,
        "receipt_results": results,
        "atf_ccs": ccs["score"],
        "atf_ccs_verdict": ccs["verdict"],
    }


def _compute_chain_ccs(results: List[VerificationResult]) -> Dict[str, Any]:
    if not results:
        return {"score": 0, "verdict": "NO_DATA"}
    hash_breaks = sum(1 for r in results if not r.hash_valid)
    unsigned = sum(1 for r in results if not r.pqc_signed)
    mar_valid = all(r.mar_invariant_valid for r in results)

    chain_integrity = max(0.0, 40.0 - hash_breaks * 10.0)
    pqc_coverage = max(0.0, 30.0 - unsigned * 10.0)
    mar_score = 20.0 if mar_valid else 0.0
    depth_score = 10.0 if len(results) >= 1 else 0.0
    total = round(chain_integrity + pqc_coverage + mar_score + depth_score, 1)

    if total >= 90:
        verdict = "COMPLETE"
    elif total >= 70:
        verdict = "DEGRADED"
    elif total >= 50:
        verdict = "PARTIAL"
    else:
        verdict = "COMPROMISED"

    return {"score": total, "verdict": verdict}


def verify_identity(identity: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = identity.get("agent_id", "UNKNOWN")
    exclude = {"registration_hash", "pqc_signature", "pqc_algorithm"}
    public_fields = {k: v for k, v in identity.items() if k not in exclude}
    recomputed = _sha256(_canonical_json(public_fields))
    embedded = identity.get("registration_hash", "")
    hash_valid = (recomputed == embedded)

    pqc_valid = False
    pqc_checked = False
    if identity.get("pqc_signature") and identity.get("public_key_b64"):
        pqc_checked = True
        sign_payload = (
            f"OMNIX-ATF-REG-v1|agent_id={agent_id}"
            f"|reg_hash={embedded}"
        ).encode("utf-8")
        sig_b64 = identity["pqc_signature"]
        pk_b64 = identity["public_key_b64"]
        pqc_valid, _ = _verify_pqc_signature(
            hashlib.sha256(sign_payload).hexdigest(), sig_b64, pk_b64
        )

    return {
        "agent_id": agent_id,
        "hash_valid": hash_valid,
        "pqc_signature_valid": pqc_valid,
        "pqc_checked": pqc_checked,
        "fully_verified": hash_valid and (pqc_valid if pqc_checked else True),
    }


def _ok(msg: str) -> str:
    return f"  {GREEN}✓{RESET}  {msg}"

def _fail(msg: str) -> str:
    return f"  {RED}✗{RESET}  {msg}"

def _warn(msg: str) -> str:
    return f"  {YELLOW}⚠{RESET}  {msg}"

def _info(msg: str) -> str:
    return f"  {CYAN}·{RESET}  {msg}"


def _print_receipt_result(vr: VerificationResult, verbose: bool = False) -> None:
    verdict_color = GREEN if vr.fully_verified else RED
    verdict_text = "VERIFIED" if vr.fully_verified else "INVALID"

    print(f"\n{BOLD}Receipt: {CYAN}{vr.delegation_id}{RESET}")
    print(f"  Status: {verdict_color}{BOLD}{verdict_text}{RESET}")
    print()
    print(_ok("Content hash valid") if vr.hash_valid else _fail("Content hash INVALID — tampering detected"))
    if vr.pqc_checked:
        print(_ok(f"PQC signature valid (ML-DSA-65)") if vr.pqc_signature_valid else _fail("PQC signature INVALID"))
    elif vr.pqc_signed:
        print(_warn("PQC signature present but could not be verified (install pqc library)"))
    else:
        print(_warn("No PQC signature (SHA-256 content hash only)"))
    print(_ok("MAR invariant holds") if vr.mar_invariant_valid else _fail("ATF-INV-001 VIOLATED: authority expansion"))
    print(_ok("Receipt not expired") if vr.not_expired else _fail("Receipt EXPIRED"))
    print(_ok(f"Status: {vr.status}") if vr.status == "ACTIVE" else _fail(f"Status: {vr.status}"))
    print()

    if verbose:
        print(f"{GRAY}  Delegator:  {vr.delegator_id}{RESET}")
        print(f"{GRAY}  Delegate:   {vr.delegate_id}{RESET}")
        print(f"{GRAY}  Depth:      {vr.delegation_depth}{RESET}")
        print(f"{GRAY}  Budget:     {vr.authority_budget_granted:.1f} (reduced {vr.authority_reduction_pct:.1f}%){RESET}")
        print(f"{GRAY}  Chain root: {vr.chain_root_id}{RESET}")
        print()

    for reason in vr.failure_reasons:
        for line in reason.split("\n"):
            print(f"  {RED}{line}{RESET}")
    for w in vr.warnings:
        print(_warn(w))


def _print_chain_result(result: Dict[str, Any]) -> None:
    all_ok = result["all_verified"]
    verdict_color = GREEN if all_ok else RED
    verdict = "CHAIN VERIFIED" if all_ok else "CHAIN INVALID"
    ccs_score = result["atf_ccs"]
    ccs_verdict = result["atf_ccs_verdict"]

    ccs_color = GREEN if ccs_score >= 90 else (YELLOW if ccs_score >= 70 else RED)

    print(f"\n{BOLD}Chain Verification Result{RESET}")
    print(f"  Verdict:  {verdict_color}{BOLD}{verdict}{RESET}")
    print(f"  ATF CCS:  {ccs_color}{BOLD}{ccs_score}/100 — {ccs_verdict}{RESET}")
    print()
    print(_ok(f"Depth monotone") if result["depth_monotone"] else _fail("Delegation depth not monotone"))
    print(_ok(f"Chain root consistent") if result["root_id_consistent"] else _fail("Inconsistent chain_root_id values"))
    print(_ok(f"MAR holds across chain") if result["mar_chain_valid"] else _fail("Authority expansion across chain"))
    print()

    for i, vr in enumerate(result["receipt_results"]):
        depth = vr.delegation_depth
        status_icon = f"{GREEN}✓{RESET}" if vr.fully_verified else f"{RED}✗{RESET}"
        print(f"  {status_icon}  Depth {depth}: {CYAN}{vr.delegation_id}{RESET}")
        print(f"     {GRAY}{vr.delegator_id} → {vr.delegate_id} | budget={vr.authority_budget_granted:.0f}{RESET}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OMNIX ATF Public Receipt Verifier (RFC-ATF-1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python omnix_atf_verify.py receipt.json
  python omnix_atf_verify.py receipt.json --verbose
  python omnix_atf_verify.py chain.json --mode chain
  python omnix_atf_verify.py identity.json --mode agent
  python omnix_atf_verify.py receipt.json --public-key <base64-key>
  echo '{"delegation_id":"..."}' | python omnix_atf_verify.py --stdin

Output codes:
  0 — Verified (all checks passed)
  1 — Invalid (one or more checks failed)
  2 — Error (file not found, invalid JSON, etc.)
        """,
    )
    parser.add_argument("file", nargs="?", help="Path to receipt JSON file")
    parser.add_argument("--mode", choices=["receipt", "agent", "chain", "replay"],
                        default="receipt", help="Verification mode (default: receipt)")
    parser.add_argument("--public-key", dest="public_key",
                        help="Override delegator public key (base64)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed field output")
    parser.add_argument("--stdin", action="store_true",
                        help="Read JSON from stdin instead of file")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output result as JSON (for programmatic use)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable color output")

    args = parser.parse_args()

    if not args.json_output:
        print(ATF_BANNER)

    if args.mode == "replay":
        return _replay_mode(args)

    if args.stdin:
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as exc:
            print(f"{RED}ERROR: Invalid JSON from stdin: {exc}{RESET}", file=sys.stderr)
            return 2
    elif args.file:
        if not os.path.exists(args.file):
            print(f"{RED}ERROR: File not found: {args.file}{RESET}", file=sys.stderr)
            return 2
        try:
            with open(args.file) as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"{RED}ERROR: Invalid JSON in {args.file}: {exc}{RESET}", file=sys.stderr)
            return 2
    else:
        parser.print_help()
        return 2

    if args.mode == "agent":
        result = verify_identity(data)
        if args.json_output:
            print(json.dumps(result, indent=2))
            return 0 if result["fully_verified"] else 1

        agent_id = result["agent_id"]
        verdict = "VERIFIED" if result["fully_verified"] else "INVALID"
        verdict_color = GREEN if result["fully_verified"] else RED
        print(f"\n{BOLD}Agent Identity: {CYAN}{agent_id}{RESET}")
        print(f"  Status: {verdict_color}{BOLD}{verdict}{RESET}\n")
        print(_ok("Registration hash valid") if result["hash_valid"] else _fail("Registration hash INVALID"))
        if result["pqc_checked"]:
            print(_ok("PQC registration signature valid") if result["pqc_signature_valid"]
                  else _fail("PQC registration signature INVALID"))
        print(ATF_FOOTER)
        return 0 if result["fully_verified"] else 1

    elif args.mode == "chain":
        if not isinstance(data, list):
            data = data.get("chain", [data])
        result = verify_chain(data)

        if args.json_output:
            serializable = {
                k: v for k, v in result.items() if k != "receipt_results"
            }
            serializable["receipts"] = [
                {"delegation_id": r.delegation_id, "fully_verified": r.fully_verified}
                for r in result["receipt_results"]
            ]
            print(json.dumps(serializable, indent=2))
            return 0 if result["all_verified"] else 1

        _print_chain_result(result)
        print(ATF_FOOTER)
        return 0 if result["all_verified"] else 1

    else:
        vr = verify_receipt(data, public_key_override=args.public_key)

        if args.json_output:
            out = {
                "delegation_id": vr.delegation_id,
                "hash_valid": vr.hash_valid,
                "pqc_signature_valid": vr.pqc_signature_valid,
                "mar_invariant_valid": vr.mar_invariant_valid,
                "not_expired": vr.not_expired,
                "fully_verified": vr.fully_verified,
                "status": vr.status,
                "authority_budget_granted": vr.authority_budget_granted,
                "failure_reasons": vr.failure_reasons,
                "warnings": vr.warnings,
            }
            print(json.dumps(out, indent=2))
            return 0 if vr.fully_verified else 1

        _print_receipt_result(vr, verbose=args.verbose)
        print(ATF_FOOTER)
        return 0 if vr.fully_verified else 1


def _replay_mode(args) -> int:
    import glob
    files = glob.glob("*.json") + glob.glob("receipts/*.json")
    if not files:
        print(f"{YELLOW}No JSON files found in current directory.{RESET}")
        return 2

    print(f"{BOLD}Replaying {len(files)} file(s)...{RESET}\n")
    total = 0
    verified = 0
    for path in sorted(files):
        try:
            with open(path) as f:
                data = json.load(f)
            if "delegation_id" in data or "content_hash" in data:
                vr = verify_receipt(data)
                total += 1
                icon = f"{GREEN}✓{RESET}" if vr.fully_verified else f"{RED}✗{RESET}"
                print(f"  {icon}  {path}: {vr.delegation_id}")
                if vr.fully_verified:
                    verified += 1
        except Exception:
            pass

    print(f"\n{BOLD}Results: {verified}/{total} verified{RESET}")
    return 0 if verified == total else 1


if __name__ == "__main__":
    sys.exit(main())
