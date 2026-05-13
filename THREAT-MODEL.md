# OMNIX ATF — Formal Threat Model
## OMNIX-TM-ATF-2026-001

**Document type:** Internal + Public — Formal Security Analysis  
**Standard:** STRIDE + ATF-specific threat taxonomy  
**Date:** May 2026  
**Version:** 1.0.0  
**Scope:** Agent Trust Fabric Protocol (RFC-ATF-1, ADR-156/157/158)

---

## 1. Overview

This document provides a formal threat model for the OMNIX Agent Trust Fabric
(ATF) protocol. It covers the complete authority lifecycle: from Tier-1 human
issuance of a Delegation Receipt (DR) through agent execution and Temporal
Admissibility Record (TAR) verification.

The threat model identifies eight primary attack classes, each analyzed with:
- Attack vector and preconditions
- ATF's structural defense
- Residual risk
- Detection method

---

## 2. Trust Boundary Map

```
┌─────────────────────────────────────────────────────────────────┐
│  TRUST ZONE 1: Human Tier-1 (delegator)                        │
│  Assets: private signing key, authority budget, intent          │
│  Boundary: key custody, HSM/secure enclave                     │
└─────────────────┬───────────────────────────────────────────────┘
                  │  signs DR (ML-DSA-65)
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  TRUST ZONE 2: Delegation Receipt (ATFDR-...)                  │
│  Assets: signed authority claim, budget, task_scope            │
│  Boundary: PQC signature, content_hash, MAR invariant          │
└─────────────────┬───────────────────────────────────────────────┘
                  │  agent presents DR at admission
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  TRUST ZONE 3: Admission Gate (ATF Connector)                  │
│  Assets: TAR issuance, DR status check, execution_ns capture   │
│  Boundary: TAR-INV-001/005, DR expiry check, PQC sign TAR      │
└─────────────────┬───────────────────────────────────────────────┘
                  │  TAR bound to execution_ref
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  TRUST ZONE 4: Governance Pipeline (OMNIX ADR-028)             │
│  Assets: decision, veto chain, AVM calibration                 │
│  Boundary: ATF context embedded in GovernanceReceipt           │
└─────────────────┬───────────────────────────────────────────────┘
                  │  triple chain stored
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  TRUST ZONE 5: Independent Verifier (offline, ATF-INV-006)     │
│  Assets: receipt artifacts, embedded public key                │
│  Boundary: offline CLI / web verifier, no platform trust       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Catalog

### TM-001 — Receipt Replay Attack

**Description:** An adversary captures a valid ATFDR or ATFTAR and resubmits
it to gain unauthorized access to governance evaluation.

**Preconditions:**
- Attacker has obtained a copy of a valid signed receipt (e.g., from audit log, network intercept)
- The original DR has not expired or been revoked

**ATF Defense:**

| Layer | Defense |
|---|---|
| TAR uniqueness | Each TAR has a unique `tar_id` (16-byte random hex) and `execution_ref`. Duplicate `tar_id` issuance is rejected. |
| DR expiry | Every DR has `expires_at`. The TAR admission check verifies DR status at admission time. A replayed DR past its `expires_at` is rejected. |
| execution_ref binding | TAR is bound to a specific `execution_ref` (GovernanceReceipt ID). Replaying the TAR in a different evaluation context breaks the binding. |
| Content hash | `content_hash` covers all fields including `execution_ns`. Identical replay would require matching nanosecond timestamp — computationally impractical. |

**Residual Risk:** LOW  
A valid DR within its validity window can be re-used by any agent holding it.
Mitigated by short DR validity periods and one-time-use TAR semantics.

**Detection:** Duplicate `tar_id` in `atf_temporal_records` table → reject + alert.

---

### TM-002 — Delegation Receipt Forgery

**Description:** An adversary attempts to create a fraudulent ATFDR claiming
authority from a legitimate Tier-1 principal.

**Preconditions:**
- Attacker does not have the delegator's ML-DSA-65 private key
- Attacker attempts to craft a receipt with forged `pqc_signature`

**ATF Defense:**

| Layer | Defense |
|---|---|
| ML-DSA-65 signature | NIST PQC Level 3. No known efficient algorithm breaks Dilithium-3 under classical or quantum adversary. Signature over `content_hash` covers all fields. |
| content_hash construction | SHA-256 of all canonical fields in sorted JSON. Any field change produces a different hash, invalidating the signature. |
| ATF-INV-004 | Signature MUST be verified before any DR is accepted as valid. |
| Embedded public key | The `delegator_public_key` field allows independent verification — forged receipts fail immediately against the embedded key. |

**Residual Risk:** VERY LOW  
Conditional on ML-DSA-65 security level holding (NIST PQC Level 3).

**Detection:** Signature verification failure at admission. Independent verifier CLI detects on audit.

---

### TM-003 — Privilege Amplification

**Description:** An agent attempts to delegate more authority than it received,
creating a DR with `authority_budget_granted > authority_budget_delegator`.

**Preconditions:**
- Agent has a valid DR with some authority budget
- Agent attempts to issue a child DR with inflated budget

**ATF Defense:**

| Layer | Defense |
|---|---|
| ATF-INV-001 (MAR) | `DR.authority_budget_granted ≤ DR.authority_budget_delegator` MUST be enforced atomically with DR issuance. |
| TrustLattice._enforce_mar() | Checks MAR BEFORE writing the DR or signing it. If violated, raises `MARViolationError`. |
| TLA+ model checking | MAR is a formally specified TLA+ invariant, machine-checked over bounded state spaces. |
| Chain traversal | `verify_chain()` recomputes the entire chain and confirms monotonic budget decrease at every edge. |

**Residual Risk:** LOW  
Conditional on the MAR check being implemented correctly and not bypassable
via direct database write. Mitigated by: MAR check in the signing path (not optional),
TLA+ verification of the invariant, and `verify_chain()` post-issuance audit.

**Detection:** `MARViolationError` raised and logged at issuance. `verify_chain()` detects post-hoc.

---

### TM-004 — Clock Drift and Temporal Manipulation

**Description:** An adversary manipulates the system clock to make a TAR appear
valid at a time when the underlying DR was already expired or not yet valid.

**Preconditions:**
- Adversary has system-level access to the host clock (unlikely in managed cloud, high risk in on-premise)
- TAR captures `execution_ns` from `time.time_ns()`

**ATF Defense:**

| Layer | Defense |
|---|---|
| TAR-INV-002 | `execution_ns` is captured AT admission time, not provided by the caller. |
| DR expiry range check | TAR checks `DR.expires_at > execution_ts` AND `DR.created_at ≤ execution_ts`. Future-dated manipulation is detectable. |
| execution_ns in content_hash | The `execution_ns` is part of the signed content_hash. Any post-hoc manipulation breaks the signature. |
| Monotonic clock | Use of `time.time_ns()` (CLOCK_MONOTONIC_COARSE or REALTIME depending on OS) provides tamper-evidence for reordering. |

**Residual Risk:** MEDIUM — in on-premise deployments  
A privileged adversary with clock access can manipulate `execution_ns` BEFORE
TAR issuance. Mitigation: Use a trusted time source (NTP + PPS, GPS, TSA) for
production deployments. Consider RFC 3161 timestamp authorities for high-assurance.

**Recommended Mitigation:**
> For regulated deployments: use RFC 3161 Time-Stamp Authority (TSA) to counter-sign
> the TAR `execution_ns`. This binds the timestamp to an external trust anchor.
> Add as ATF-COMPLIANT-LEVEL-3 requirement in next RFC-ATF revision.

**Detection:** NTP deviation monitoring. Cross-reference TAR execution_ns with
server-side request log timestamps. Statistical anomaly in ns distribution.

---

### TM-005 — Chain Poisoning

**Description:** An adversary inserts a malicious DR into the middle of a
delegation chain, inheriting the chain_root's identity and authority.

**Preconditions:**
- Adversary has a legitimate DR in the chain (e.g., compromised Tier-2 agent)
- Adversary attempts to issue a child DR claiming to be part of a trusted chain

**ATF Defense:**

| Layer | Defense |
|---|---|
| chain_root_id immutability | Every DR carries the `chain_root_id` of the original root DR. This field is set at issuance from the delegator's own `chain_root_id` and cannot be changed without breaking the signature. |
| ATF-INV-003 | chain_root_id MUST be the `delegation_id` of the first DR in the chain, issued by a Tier-1 principal. |
| chain_root verification | `verify_chain()` traverses the entire chain and validates that all DRs share the same `chain_root_id`. |
| Independent verifiability | A verifier reconstructs the full chain from the root and detects orphaned or inserted DRs. |

**Residual Risk:** LOW  
A poisoned DR is detectable by any independent verifier. The signature ensures
the link between each DR and its delegator is cryptographically bound.

**Detection:** `verify_chain()` returns `chain_root_consistent=False`. CCS drops on
poisoned chains. Alert on CCS < 80 in high-assurance domains.

---

### TM-006 — Orphan Delegation (Revoked Authority Propagation Failure)

**Description:** A Tier-1 principal revokes a DR, but child DRs in the chain
continue to be accepted because revocation has not propagated to all validators.

**Preconditions:**
- A DR is revoked (status = REVOKED)
- Child DRs derived from this DR exist with status = ACTIVE
- Validator does not traverse the full chain to check parent DR status

**ATF Defense:**

| Layer | Defense |
|---|---|
| TAR admission check | The TAR admission gate checks DR.status at admission time. A REVOKED DR → REJECTED TAR. |
| Cascade revocation (planned) | When a DR is revoked, all descendant DRs with the same `chain_root_id` are cascade-revoked. (Implementation: `TrustLattice.cascade_revoke(dr_id)`) |
| Independent verifier check | `omnix_atf_verify.py --mode chain` traverses the full chain and checks each DR's status. |
| ATF-INV-005 | Expired DRs MUST be treated as REVOKED for TAR admission purposes. |

**Residual Risk:** MEDIUM — in distributed deployments  
In a multi-node deployment without shared revocation state, revocation may not
propagate immediately. Mitigation: centralized revocation registry (shared Redis
or DB), or short DR validity periods (< 24h) reducing the revocation window.

**Detection:** Orphan DRs (parent REVOKED, child ACTIVE) detected by `verify_chain()`.
Alert on chain_root_id in revocation registry.

---

### TM-007 — Trust Lattice Corruption (DAG Cycle Injection)

**Description:** An adversary attempts to inject a cycle into the trust lattice
DAG (A delegates to B, B delegates back to A), creating an infinite loop or
circular authority claim.

**Preconditions:**
- Adversary controls at least two agents in a delegation chain
- Adversary attempts to create B.delegate_id = A.agent_id where A is also an ancestor of B

**ATF Defense:**

| Layer | Defense |
|---|---|
| ATF-INV-002 (Acyclicity) | The trust lattice MUST be a Directed Acyclic Graph. Any DR that would create a cycle MUST be rejected at issuance. |
| TLA+ AcyclicityInvariant | Formally specified and model-checked: no set of delegation receipts forms a directed cycle in the trust lattice graph. |
| Cycle detection at issuance | `TrustLattice._validate_acyclicity()` performs DFS cycle detection before accepting a new DR into the lattice. |
| Depth limit | `delegation_depth` field prevents deep chains that would make cycle detection computationally expensive. Maximum depth configurable per deployment. |

**Residual Risk:** VERY LOW  
Formally verified (TLA+ AcyclicityInvariant). Cycle detection is O(V+E) on
the chain subgraph rooted at the new DR's chain_root_id.

**Detection:** `MARViolationError` or cycle detection exception at DR issuance.
No cycle can exist in a correctly operating ATF lattice.

---

### TM-008 — Temporal Authority Impersonation (Cross-TAR Forgery)

**Description:** An adversary copies a valid TAR from one governance decision
and presents it as evidence for a different decision, claiming the authority
was valid for the second decision.

**Preconditions:**
- Adversary has obtained a valid ATFTAR
- Adversary attempts to use it to satisfy an authority check for a different `execution_ref`

**ATF Defense:**

| Layer | Defense |
|---|---|
| execution_ref binding | TAR.execution_ref is set to the specific GovernanceReceipt ID at admission time and included in the signed content_hash. |
| TAR-INV-003 | A TAR is valid ONLY for the execution identified by its execution_ref. Using TAR from decision A to satisfy admission check for decision B is an explicit invariant violation. |
| receipt_id cross-check | `verify_chain()` checks `TAR.execution_ref == GovernanceReceipt.receipt_id`. Mismatch → NOT verified. |
| Unique tar_id | Each TAR has a globally unique `tar_id`. Reuse across decisions is detectable. |

**Residual Risk:** VERY LOW  
The `execution_ref` binding in the signed content_hash makes cross-TAR forgery
detectable by any independent verifier.

**Detection:** `ATFConnector.verify_chain()` returns `execution_ref_match=False`.
Independent CLI verifier detects in `--mode receipt` verification.

---

## 4. Cross-Domain Attack Surface (ADR-158)

### TM-009 — Domain Translation Budget Inflation

**Description:** An agent presents a DTR (ATFDTR) claiming a higher translated
authority budget than the domain-pair policy allows.

**ATF Defense:**
- `CDTP-INV-003`: `translated_budget ≤ source_budget × (1 - discount_rate)`
- DTR is PQC-signed by the CrossDomainBridge engine — not by the agent
- Domain-pair discount table is static configuration, not client-controlled
- Independent verifier reconstructs the discount calculation from the policy table

**Residual Risk:** LOW  
Requires compromise of the CrossDomainBridge signing key to forge a valid DTR.

---

## 5. Residual Risk Summary

| Threat | Severity | ATF Defense | Residual Risk |
|---|---|---|---|
| TM-001 Receipt Replay | HIGH | TAR uniqueness, DR expiry, execution_ref | LOW |
| TM-002 DR Forgery | CRITICAL | ML-DSA-65 PQC signature | VERY LOW |
| TM-003 Privilege Amplification | CRITICAL | MAR invariant + TLA+ | LOW |
| TM-004 Clock Drift | MEDIUM | execution_ns in signed hash | MEDIUM (on-premise) |
| TM-005 Chain Poisoning | HIGH | chain_root_id, verify_chain() | LOW |
| TM-006 Orphan Delegation | HIGH | Cascade revoke, TAR check | MEDIUM (distributed) |
| TM-007 DAG Cycle Injection | HIGH | TLA+ acyclicity, cycle detection | VERY LOW |
| TM-008 Cross-TAR Forgery | HIGH | execution_ref binding | VERY LOW |
| TM-009 Budget Inflation (DTR) | HIGH | CDTP-INV-003, PQC-signed DTR | LOW |

---

## 6. Security Recommendations by Deployment Context

### Cloud-managed deployment (Railway, AWS, GCP)
- Clock drift risk is LOW (cloud time sync)
- Use short DR validity (≤ 24h) to minimize orphan delegation window
- Enable `OMNIX_ANTI_REPLAY_MODE=strict` for Redis-backed TAR uniqueness

### On-premise / regulated deployment
- Add RFC 3161 TSA counter-signature to TAR (see TM-004)
- Implement cascade revocation with shared revocation registry
- Require FIPS 140-3 validated cryptographic module for signing

### Multi-tenant / multi-instance
- Ensure `atf_temporal_records` table is shared across instances
- Use distributed TAR uniqueness check (Redis SETNX or DB unique constraint)
- Cascade revocation MUST propagate across all instances synchronously

---

## 7. Out of Scope

The following are explicitly outside the ATF threat boundary:

| Out of scope | Reason |
|---|---|
| Private key theft | Key management is deploying organization's responsibility. ATF provides key rotation receipts but not HSM policy. |
| Social engineering of Tier-1 principal | ATF cannot prevent a human from intentionally issuing a fraudulent DR. The receipt proves what was signed, not that the intent was legitimate. |
| Side-channel attacks on signing | Dependent on the underlying ML-DSA-65 library's resistance to timing/power attacks. |
| Governance pipeline correctness | ATF governs the authority chain, not the correctness of the governance decision itself (that is OMNIX core governance's responsibility). |

---

## 8. Formal Property Coverage

| TLA+ Property | Threat Addressed |
|---|---|
| MARInvariant | TM-003 Privilege Amplification |
| MARChainInvariant | TM-003, TM-005 Chain Poisoning |
| AcyclicityInvariant | TM-007 DAG Cycle Injection |
| ChainRootConsistency | TM-005 Chain Poisoning |
| ImmutabilityProperty | TM-002 DR Forgery, TM-008 Cross-TAR Forgery |

---

**Document ID:** OMNIX-TM-ATF-2026-001  
**Version:** 1.0.0  
**Date:** 2026-05-12  
**Classification:** Public
