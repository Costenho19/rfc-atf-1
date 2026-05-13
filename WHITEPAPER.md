# Cryptographic Authority Governance for Autonomous AI Agents
## OMNIX Agent Trust Fabric — Technical Whitepaper

**Document:** OMNIX-WP-ATF-2026-001  
**Version:** 1.0.0  
**Date:** May 2026  
**Author:** Harold Nunes, OMNIX QUANTUM LTD, Dubai UAE  
**Contact:** harold@omnixquantum.com  
**Protocol:** RFC-ATF-1 · ADR-156/157/158  
**Classification:** Public — Institutional Distribution

---

## Abstract

Autonomous AI agents increasingly make consequential decisions in enterprise
systems — executing trades, authorizing medical procedures, routing logistics,
and managing critical infrastructure. Yet the governance of *who authorized
these agents, under what authority, and whether that authority was valid at
the moment of execution* remains largely unaddressed by existing frameworks.

This paper presents the OMNIX Agent Trust Fabric (ATF) — a formally specified,
post-quantum cryptographic protocol that answers four questions for every AI
agent execution:

1. **Who authorized this agent?** — Via ML-DSA-65 signed Delegation Receipt (DR)
2. **What authority did it hold?** — Via Monotonic Authority Reduction invariant (MAR), model-checked in TLA+
3. **Was the authority valid at execution?** — Via Temporal Admissibility Record (TAR) captured before the pipeline runs
4. **Is the full chain independently verifiable?** — Via offline CLI verifier, no platform access required

The result is a three-artifact audit chain — DR + TAR + GovernanceReceipt — for
every governance decision. This chain is PQC-signed, independently verifiable,
and designed to satisfy regulatory accountability requirements in AI governance
contexts (EU AI Act, DORA, MiCA, NIST AI RMF).

---

## 1. Problem Statement

### 1.1 The AI Agent Authorization Gap

Modern AI governance frameworks address *what decisions are made* but not *who
authorized the agent that made them*. When an enterprise AI agent executes a
high-stakes action, the audit record typically captures:

- What decision was made
- What signals influenced the decision
- A cryptographic hash of the decision receipt

What is missing:

- **Proof that the agent was authorized to act** — not just authenticated, but explicitly authorized with bounded scope
- **Proof that the authority was valid at the nanosecond of execution** — not valid yesterday, not valid in principle, but valid *then*
- **A verifiable chain from the AI agent back to a human principal** — traceable without trusting the platform

This gap is not a limitation of existing governance frameworks — it is not their
design target. OAuth 2.0 handles access delegation; W3C Verifiable Credentials
handle identity claims; JWT handles session validity. None was designed to answer
"was this autonomous AI agent's authority mathematically bounded and verified at
the moment it executed this specific governance decision?"

### 1.2 The Accountability Requirement

Regulation is closing this gap:

| Regulation | Requirement | ATF Response |
|---|---|---|
| EU AI Act Art. 13 | Transparency for high-risk AI systems — "who authorized this system" | ATF DR chain to Tier-1 human |
| EU AI Act Art. 14 | Human oversight — human principal must be identifiable | ATF chain_root_id → Tier-1 |
| DORA Art. 9 | ICT operational resilience — documented controls for automated systems | ATF TAR proves control at execution |
| MiCA Rec. 65 | Algorithmic trading controls — authorization audit trail | ATF triple chain for trading decisions |
| NIST AI RMF GOVERN | Accountable AI — "AI system decisions traceable to accountable entities" | ATF provides cryptographic traceability |
| SOC 2 CC6 | Logical access controls — non-repudiation | ATF PQC signatures |

### 1.3 Why Existing Protocols Are Insufficient

| Protocol | What it provides | What it cannot provide |
|---|---|---|
| OAuth 2.0 | Access token delegation | Monotonic authority bound; pre-execution temporal record; human chain traceability |
| JWT (RFC 7519) | Signed claims with expiry | Authority budget arithmetic; separate admissibility artifact; offline chain verification |
| W3C VC | Signed identity claims | Authority bounds; temporal admissibility; mandatory cross-domain reduction |
| SPIFFE/SPIRE | Workload identity | Authority delegation chain; governance receipt integration |
| OpenID Connect | Authentication | Authorization chain governance; PQC signatures; formal invariants |

None of these protocols is wrong — they solve different problems. ATF addresses
the gap that exists at the intersection of all of them: **authority governance
for autonomous AI agents, before and during execution**.

---

## 2. The ATF Protocol Architecture

### 2.1 Core Concepts

**Agent Identity Record (AIR):** Every AI agent registered in an ATF-compliant
system receives a globally unique identifier: `AID-{DOMAIN}-{16HEX}`. The AIR
contains the agent's authority budget cap, domain, registration tier, and
public key for verification.

**Delegation Receipt (DR / ATFDR-{16HEX}):** A PQC-signed record issued by
a principal (human or agent) to an agent, explicitly granting a bounded subset
of the principal's authority for a defined task scope. The DR is:
- Content-hashed (SHA-256 over canonical JSON)
- Signed with ML-DSA-65 (Dilithium-3, NIST FIPS 204)
- Independently verifiable offline using the embedded `delegator_public_key`

**Temporal Admissibility Record (TAR / ATFTAR-{16HEX}):** A PQC-signed record
issued at the exact moment of admission to the governance pipeline — before any
governance logic executes. The TAR proves:
- The DR was ACTIVE at `execution_ns` (nanosecond-resolution timestamp)
- The admission decision was ADMITTED or REJECTED
- The `execution_ref` binds this TAR to a specific GovernanceReceipt

**Trust Lattice:** The directed acyclic graph (DAG) of all delegation receipts.
The lattice enforces the Acyclicity invariant (ATF-INV-002) and provides chain
traversal for complete authority verification.

**GovernanceReceipt:** OMNIX's existing governance decision record (ADR-028),
extended with `atf_context` embedding the DR, TAR, and trust summary.

### 2.2 The Authority Lifecycle

```
Phase 1 — Registration
  Human Tier-1 registers agent → AIR created → authority budget assigned

Phase 2 — Delegation
  Principal signs DR → authority_budget_granted ≤ authority_budget_delegator
  DR stored in trust lattice → chain_root_id set

Phase 3 — Admission
  Agent presents DR at execution boundary
  ATFConnector.admit() called BEFORE governance pipeline
  TAR issued: execution_ns captured, DR status verified, TAR signed
  TAR.execution_ref = GovernanceReceipt.receipt_id

Phase 4 — Execution
  Governance pipeline runs (AVM, AI, veto chain)
  Decision produced with PQC-signed GovernanceReceipt
  ATF context embedded: atf_context.delegation_id, .tar_id, .authority_budget

Phase 5 — Verification
  Any party runs: python omnix_atf_verify.py receipt.json
  DR signature verified against embedded public key
  TAR status confirmed ADMITTED
  execution_ref cross-checked with GovernanceReceipt.receipt_id
  Chain root traced to Tier-1 human principal
  Result: VERIFIED or NOT VERIFIED
```

### 2.3 Authority Budget Arithmetic

The authority budget is a real number in [0.0, 100.0] representing the fraction
of full authority held by an agent. The Monotonic Authority Reduction (MAR)
invariant requires:

```
For all DRs D in the trust lattice:
  D.authority_budget_granted ≤ D.authority_budget_delegator

For all chains C = [DR₁, DR₂, ..., DRₙ]:
  DR₁.authority_budget_granted ≥ DR₂.authority_budget_granted ≥ ... ≥ DRₙ.authority_budget_granted
```

This invariant is formally specified in TLA+ and verified by model checking
over bounded state spaces (ATF-FV-1.0). It ensures that delegation cannot
create authority — only distribute and bound it.

**Example budget chain:**

```
HUMAN-TIER1          budget = 100.0  (full authority)
  └─ ATFDR-ROOT  →   AID-FINANCE-001 budget = 80.0   (20% reduction at root)
       └─ ATFDR-A  → AID-FINANCE-002 budget = 50.0   (37.5% reduction)
            └─ ATFDR-B → AID-FINANCE-003 budget = 20.0 (60% reduction)
```

Any attempt to issue a DR with `authority_budget_granted > authority_budget_delegator`
raises a `MARViolationError` and is rejected before signing.

---

## 3. Formal Invariants

ATF-1.0 defines six formally specified invariants. All are mandatory for
ATF-COMPLIANT-LEVEL-2 and above.

| Invariant | Identifier | Statement |
|---|---|---|
| Monotonic Authority Reduction | ATF-INV-001 | `DR.budget_granted ≤ DR.budget_delegator` for all DRs |
| Acyclicity | ATF-INV-002 | The trust lattice is a DAG — no delegation cycle exists |
| Chain Root Consistency | ATF-INV-003 | All DRs in a chain share the same `chain_root_id` |
| Content Hash Immutability | ATF-INV-004 | DR fields are immutable post-issuance (hash binds all fields) |
| Temporal Non-Future-Dating | ATF-INV-005 | TAR `execution_ns` ≤ current time at verification |
| Independent Verifiability | ATF-INV-006 | Full chain verifiable offline using only receipts and root public key |

**TLA+ Coverage:** INV-001 (MARInvariant), INV-002 (AcyclicityInvariant),
INV-003 (ChainRootConsistency), INV-004 (ImmutabilityProperty) are
formally specified and model-checked in `docs/formal/ATF-TLA-SPEC.tla`.

---

## 4. Cryptographic Specification

### 4.1 Signature Algorithm

| Property | Value |
|---|---|
| Algorithm | ML-DSA-65 (Dilithium-3) |
| Standard | NIST FIPS 204 (August 2024) |
| Security level | NIST PQC Level 3 |
| Public key | 1952 bytes |
| Signature | 3293 bytes |
| Hash function | SHA-256 (content hash construction) |
| Encoding | Base64 standard (signature), hex (content hash) |

### 4.2 Content Hash Construction

All ATF artifacts use a deterministic content hash:

```python
canonical = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
content_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
```

The fields included in the hash for each artifact type:

| Artifact | Hashed fields |
|---|---|
| DR | delegation_id, delegator_id, delegate_id, task_scope, authority_budget_granted, authority_budget_delegator, chain_root_id, delegation_depth, expires_at, status, created_at |
| TAR | tar_id, delegation_id, agent_id, execution_ref, execution_ns, dr_status_at_admission, dr_expires_at, authority_budget, domain, task_action, admission_status, chain_root_id |
| DTR | dtr_id, source_delegation_id, source_domain, target_domain, source_agent_id, target_agent_id, source_authority_budget, translated_budget, translation_discount, chain_root_id |

### 4.3 Fallback Mode

When ML-DSA-65 is unavailable, ATF falls back to content hash only (no signature).
This mode (`pqc_signature = null`) is explicitly:
- **Permitted** for ATF-COMPLIANT-LEVEL-1 development/test environments
- **Prohibited** for ATF-COMPLIANT-LEVEL-2+ production deployments

---

## 5. Temporal Admissibility (ADR-157)

The Temporal Admissibility Record (TAR) is ATF's mechanism for proving that
an agent's authority was valid at the exact moment of execution.

### 5.1 Why TAR Is Necessary

JWT `exp` claims verify that a token is not expired at the time of checking.
This is an implicit check — there is no artifact proving the check occurred.

TAR makes the check explicit and produces a signed, persistent record:

| Property | JWT exp check | TAR |
|---|---|---|
| Existence check | Yes | Yes |
| Signed artifact | No | Yes (ML-DSA-65) |
| Timestamp granularity | Second | Nanosecond-resolution |
| Persistence | No | Yes (database row) |
| Binding to execution | No | Yes (execution_ref) |
| Independent verifiability | No | Yes (offline CLI) |
| Rejection record | No | Yes (REJECTED status with reason) |

### 5.2 TAR Issuance Protocol

```
Input: DR, agent_id, task_action, execution_ref
Output: TemporalAdmissibilityRecord (ATFTAR-{16HEX})

1. execution_ns ← time.time_ns()   # Nanosecond-resolution capture
2. Verify DR.status == ACTIVE
3. Verify execution_ts < DR.expires_at
4. Verify execution_ts >= DR.created_at
5. Set admission_status ← ADMITTED (or REJECTED with reason)
6. Compute content_hash over all TAR fields including execution_ns
7. Sign content_hash with ML-DSA-65
8. Persist TAR to atf_temporal_records
9. Return TAR
```

Step 1 is executed before steps 2-4. This ensures the `execution_ns` reflects
the actual admission time, not the outcome of the checks.

---

## 6. Cross-Domain Trust Portability (ADR-158)

In multi-domain deployments, an agent authorized in domain FINANCE may need
to access resources in domain HEALTHCARE. Cross-domain trust requires explicit
authority translation with mandatory reduction.

### 6.1 Domain Translation Receipt (DTR / ATFDTR-{16HEX})

The DTR records a cross-domain authority translation:

```
source_budget = 60.0  (FINANCE domain)
discount = 0.30       (FINANCE → HEALTHCARE policy)
translated_budget = 60.0 × (1 - 0.30) = 42.0  (HEALTHCARE domain)
```

The discount is mandatory — cross-domain translation MUST reduce authority
(`CDTP-INV-003`). An agent cannot gain authority by crossing domains.

### 6.2 Standard Domain-Pair Discount Policies

| Source → Target | Default Discount | Rationale |
|---|---|---|
| HEALTHCARE → FINANCE | 30% | High sensitivity of both domains |
| FINANCE → HEALTHCARE | 30% | Symmetric high-sensitivity |
| FINANCE → INSURANCE | 15% | Adjacent regulatory domain |
| DEFENSE → FINANCE | 40% | Strict isolation requirement |
| DEFENSE → HEALTHCARE | 45% | Maximum cross-domain sensitivity |
| Other pairs | 20% | Default cross-domain discount |

---

## 7. Governance Receipt Integration

### 7.1 The Triple Chain

Every OMNIX governance decision that originates from an ATF-registered agent
produces three cross-referenced artifacts:

```json
{
  "receipt_id":     "OMNIX-FIN-20260512-A3F7B2",
  "decision":       "APPROVED",
  "pqc_signature":  "...",

  "atf_context": {
    "delegation_id":    "ATFDR-8B2C4D6E1F3A5B7C",
    "tar_id":           "ATFTAR-C4D8E2F1A3B5C7D9",
    "agent_id":         "AID-FINANCE-3A7F9B2C1D4E5F6A",
    "delegator_id":     "HUMAN-TIER1-HN-001",
    "admission_status": "ADMITTED",
    "execution_ns":     1747058400000000000,
    "authority_budget": 60.0,
    "chain_root_id":    "ATFDR-8B2C4D6E1F3A5B7C",
    "pqc_signed":       true,
    "connector_hash":   "a3f9b2c1..."
  }
}
```

This structure enables a verifier to answer all four questions using only
this JSON document and the root public key.

### 7.2 Verification Flow

```
verify(receipt.json):
  1. Check receipt.pqc_signature over receipt.content_hash  → receipt integrity
  2. Fetch DR by atf_context.delegation_id                  → authority claim
  3. Verify DR.pqc_signature over DR.content_hash           → delegation integrity
  4. Verify DR.delegator_public_key signed the hash         → principal identity
  5. Fetch TAR by atf_context.tar_id                        → temporal proof
  6. Verify TAR.pqc_signature over TAR.content_hash         → TAR integrity
  7. Check TAR.admission_status == ADMITTED                  → execution admitted
  8. Check TAR.execution_ref == receipt.receipt_id           → binding holds
  9. Traverse chain to chain_root_id                         → human traceability
  Result: VERIFIED | NOT VERIFIED
```

All steps can be performed offline using only the receipt artifacts.

---

## 8. Independent Verifiability (ATF-INV-006)

ATF-INV-006 is the most operationally significant invariant for regulators:

> *"Any party MUST be able to verify a delegation chain using only the receipts
> and the root public key. No access to the issuing platform, API, account,
> or internet connection is required."*

This property distinguishes ATF from platform-dependent audit trails.
A regulator conducting a post-incident review can:

1. Download the receipt artifacts from the institution's disclosure
2. Run `python omnix_atf_verify.py receipt.json`
3. Receive a complete VERIFIED/NOT VERIFIED verdict with the full chain analysis
4. Without any interaction with OMNIX or the deploying institution's systems

This is analogous to how anyone can verify a PGP-signed document without
contacting the key issuer — but applied to the entire AI agent authority chain.

---

## 9. Compliance Framework

ATF defines three compliance levels:

### Level 1 — Basic (Development and Proof-of-Concept)
- DR content hash (SHA-256)
- MAR enforcement
- Chain traversal
- PQC signature: SHOULD (not required)
- TAR: OPTIONAL

### Level 2 — Standard (Production, Enterprise)
- All Level-1 requirements
- PQC signature REQUIRED (ML-DSA-65)
- TAR REQUIRED for all governance-connected executions
- ATF CCS ≥ 80 required for high-assurance domains
- Independent verifiability demonstrated

### Level 3 — Sovereign (Regulated, Critical Infrastructure)
- All Level-2 requirements
- RFC 3161 TSA timestamp counter-signature on TARs
- FIPS 140-3 validated cryptographic module SHOULD be used
- Formal verification documentation (TLA+ or equivalent)
- Public CLI verifier available for independent audit
- Cascade revocation within 1 hour of compromise detection

---

## 10. Interoperability

### 10.1 W3C Verifiable Credentials

ATF Delegation Receipts share structural concepts with W3C VCs:
- `credential subject` ≈ ATF `delegate_id`
- `issuer` ≈ ATF `delegator_id`
- `proof` ≈ ATF `pqc_signature`
- `credentialStatus` ≈ ATF `status`

ATF extends this with:
- Authority budget arithmetic (not in VC spec)
- Monotonic reduction invariant (not in VC spec)
- Temporal admissibility as a separate signed artifact (not in VC spec)
- TLA+-verified formal invariants (not part of VC ecosystem)

### 10.2 IETF JWT (RFC 7519)

ATF receipts can be serialized as JWT claims for interoperability with
JWT-consuming systems. The `atf_context` object maps to JWT custom claims.
The `exp` claim corresponds to `DR.expires_at`. However, the TAR provides
stronger temporal evidence than `exp` alone — it is a signed artifact, not
just a claim.

### 10.3 OpenID Connect

ATF agent identities (AIR) can be registered as OAuth 2.0 clients with an
ATF-extended identity layer. The `chain_root_id` can be used as an `sub`
(subject) claim linking back to the human principal's OIDC identity.

### 10.4 AI Agent Frameworks

ATF is framework-agnostic. The ATF Connector (`atf_connector.py`) can be
integrated into any Python-based AI agent framework:

```python
# Integration with any governance evaluation flow
from omnix_core.agents.atf.atf_connector import ATFConnector

atf_ctx = ATFConnector.admit(
    agent_id=request.get("agent_id"),
    delegation_id=request.get("delegation_id"),
    task_action=f"governance:{domain}:{asset}",
    execution_ref=receipt_id,
)
if atf_ctx:
    receipt = ATFConnector.embed_in_receipt(receipt, atf_ctx)
```

Non-ATF requests (no `agent_id`) pass through unchanged — fully backward compatible.

---

## 11. Implementation Reference

| Module | Purpose |
|---|---|
| `omnix_core/agents/atf/trust_lattice.py` | TrustLattice, AgentIdentity, DelegationEngine |
| `omnix_core/agents/atf/temporal_authority.py` | TemporalAuthorityEngine, TAR |
| `omnix_core/agents/atf/domain_bridge.py` | CrossDomainBridge, DTR |
| `omnix_core/agents/atf/atf_connector.py` | ATFConnector, ATFContext |
| `omnix_web/api/agent_blueprint.py` | REST API (`/api/atf/*`) |
| `omnix_web/public/omnix_atf_verify.py` | Offline CLI verifier |
| `docs/formal/ATF-TLA-SPEC.tla` | TLA+ formal specification |
| `tests/test_agent_trust_fabric.py` | 50+ protocol tests |

---

## 12. Known Limitations and Open Questions

| Limitation | Mitigation | Status |
|---|---|---|
| Clock trust in TAR (TM-004) | RFC 3161 TSA integration (planned Level-3 req) | OPEN |
| Revocation propagation latency (TM-006) | Short DR validity + centralized revocation | PARTIAL |
| Theorem-proved MAR (vs model-checked) | Port to Coq/Lean for one invariant | PLANNED |
| FIPS 140-3 validated library | Library-agnostic spec; swap `pqc` for validated lib | OPEN |
| Multi-instance TAR uniqueness | Redis SETNX / DB unique constraint | PARTIAL |

---

## 13. Related Work

- **W3C Verifiable Credentials:** Identity claims with PQC extensions (emerging drafts). No authority budgets or temporal admissibility artifacts.
- **SPIFFE/SPIRE:** Workload identity for service meshes. No delegation chains or authority arithmetic.
- **OpenID Connect:** Authentication. No authorization governance chain.
- **NIST SP 800-207 (Zero Trust):** Zero Trust Architecture principles. ATF implements explicit trust verification before each execution event.
- **NIST AI RMF (January 2023):** AI Risk Management Framework. ATF directly implements accountability requirements in the GOVERN function.
- **EU AI Act (August 2024):** ATF addresses Arts. 13/14 (transparency and human oversight) for high-risk AI systems.

---

## 14. Conclusion

The OMNIX Agent Trust Fabric addresses a specific, well-defined gap in AI
governance infrastructure: the absence of cryptographic proof of *who authorized
an AI agent, under what authority bound, when that authority was valid, and whether
execution was admitted at that exact moment*.

ATF provides this through a three-artifact chain (DR + TAR + GovernanceReceipt),
formally specified invariants (TLA+ model-checked), post-quantum cryptography
(ML-DSA-65, NIST FIPS 204), and independent offline verifiability (ATF-INV-006).

The design is complementary to existing orchestration frameworks, not a replacement
for them. It operates at the governance layer that precedes execution — making the
authority chain verifiable before, during, and after an AI agent acts.

As autonomous AI systems take on greater responsibility in enterprise and regulated
environments, this governance layer becomes a prerequisite for institutional trust.
OMNIX ATF provides the formal specification, reference implementation, and public
verification tooling to establish that trust on a cryptographic foundation.

---

## References

- [RFC-ATF-1] Nunes, H. "RFC-ATF-1: Agent Trust Fabric Delegation Protocol." OMNIX QUANTUM Open Standard, May 2026.
- [ADR-156] OMNIX QUANTUM. "Agent Trust Fabric (ATF)." Architecture Decision Record 156, 2026.
- [ADR-157] OMNIX QUANTUM. "Temporal Authority Admissibility." Architecture Decision Record 157, 2026.
- [ADR-158] OMNIX QUANTUM. "Cross-Domain Trust Portability." Architecture Decision Record 158, 2026.
- [FIPS204] NIST. "Module-Lattice-Based Digital Signature Standard." FIPS 204, August 2024.
- [W3CVC] W3C. "Verifiable Credentials Data Model 2.0." W3C Recommendation, 2024.
- [RFC7519] Jones, M., et al. "JSON Web Token (JWT)." IETF RFC 7519, May 2015.
- [RFC3161] Adams, C., et al. "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)." IETF RFC 3161, August 2001.
- [NISTAIRGM] NIST. "Artificial Intelligence Risk Management Framework." NIST AI 100-1, January 2023.
- [SP800207] NIST. "Zero Trust Architecture." SP 800-207, August 2020.
- [TLA] Lamport, L. "Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers." Addison-Wesley, 2002.
- [EUAIACT] European Parliament. "Regulation (EU) 2024/1689 on Artificial Intelligence." Official Journal of the EU, August 2024.

---

**Document ID:** OMNIX-WP-ATF-2026-001  
**Version:** 1.0.0  
**Date:** May 12, 2026  
**Pages:** ~22 (equivalent)  
**Classification:** Public — Institutional Distribution
