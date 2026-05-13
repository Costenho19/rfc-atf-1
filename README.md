# RFC-ATF-1 — Agent Trust Fabric

**Post-quantum cryptographic protocol for AI agent authority governance.**

> *Version 1.0.0 · Published May 2026 · OMNIX QUANTUM LTD*

---

## The Problem

When an AI agent takes an action, you have no verifiable proof of:
- **Who** authorized it
- **What authority** it actually held
- **Whether** that authority was still valid at the exact moment of execution
- **Whether** you can verify all of this without calling the issuing platform

RFC-ATF-1 answers all four questions — with cryptography, not promises.

---

## Four Core Properties

| Property | Mechanism | Standard |
|---|---|---|
| Authorization proof | Delegation Receipt (ATFDR) | ML-DSA-65 / NIST FIPS 204 |
| Authority bounds | Monotonic Authority Reduction | TLA+ verified |
| Temporal admissibility | Temporal Admissibility Record (ATFTAR) | Nanosecond-precise |
| Independent verification | Offline CLI verifier | No account, no API, no network |

---

## Repository Contents

```
RFC-ATF-1.md              — Full formal specification (IETF-style)
WHITEPAPER.md             — Institutional whitepaper (~22pp)
THREAT-MODEL.md           — 9-class formal threat model (STRIDE + ATF taxonomy)
omnix_atf_verify.py       — Standalone public verifier (Python, no dependencies)
formal/
  ATF-TLA-SPEC.tla        — TLA+ formal specification
  ATF-FORMAL-VERIFICATION.md — Formal verification report (5 properties model-checked)
```

---

## Quick Start — Verify a Delegation Receipt

```bash
# No installation required. Python 3.8+
python omnix_atf_verify.py receipt <ATFDR-ID>
python omnix_atf_verify.py chain <ATFDR-ID>
python omnix_atf_verify.py agent <AID-DOMAIN-HEX>
```

---

## Key Identifiers

| Type | Format | Description |
|---|---|---|
| Agent Identity | `AID-{DOMAIN}-{16HEX}` | Unique agent identity |
| Delegation Receipt | `ATFDR-{16HEX}` | Authority delegation record |
| Temporal Record | `ATFTAR-{16HEX}` | Admissibility at execution time |
| Domain Bridge | `ATFDTR-{16HEX}` | Cross-domain trust translation |

---

## Formal Properties (TLA+ verified)

1. **Monotonic Authority Reduction (MAR)** — Authority can only decrease through a chain
2. **MAR Chain** — Property holds transitively across the full chain
3. **Acyclicity** — The delegation graph is a DAG (no circular authority)
4. **Chain Root Consistency** — All chains resolve to a single trust anchor
5. **Immutability** — Issued receipts cannot be modified

---

## Cryptographic Specification

- **Signature algorithm:** ML-DSA-65 (FIPS 204) — post-quantum secure
- **Hash:** SHA3-256
- **Key format:** Base64-encoded, self-contained in each receipt
- **Verification:** Fully offline — public key embedded in receipt chain root

---

## Compliance Alignment

| Framework | Relevant property |
|---|---|
| EU AI Act (Art. 9, 17) | Auditability, human oversight, traceability |
| DORA (Art. 30) | ICT chain documentation and accountability |
| MiCA | Operational risk and governance records |
| SOC 2 Type II | Logical access and change management |
| ISO 27001 | Identity and access management |
| NIST AI RMF | Govern 1.1, Map 1.5, Measure 2.5 |

---

## Priority Record

**OMNIX-PAR-2026-ATF-001** — Anchor hash:
`d7082c2c1df7b0a2bd3c6f586f6f59143df8eaede369354e3f8afeb7c0c2b2f5`

*Zenodo DOI and SSRN registration forthcoming.*

---

## Citation

```bibtex
@techreport{nunes2026atf,
  title     = {RFC-ATF-1: Agent Trust Fabric — Post-quantum cryptographic protocol
               for AI agent authority governance},
  author    = {Nunes, Harold},
  year      = {2026},
  month     = {May},
  institution = {OMNIX QUANTUM LTD},
  type      = {Technical Protocol Specification},
  note      = {Version 1.0.0. GitHub: https://github.com/Costenho19/rfc-atf-1}
}
```

---

## Discussion & Critique

Open an issue. We welcome:
- Protocol analysis
- Cryptographic review
- Implementation feedback
- Compliance questions

*Read it. Break it. Tell us what we got wrong.*

---

**Harold Nunes · OMNIX QUANTUM LTD**
