```
Internet-Draft                                         OMNIX QUANTUM LTD
Category: Standards Track                                    H. Nunes, Ed.
ISSN: pending                                                    May 2026


           RFC-ATF-1: Agent Trust Fabric Delegation Protocol
           Version 1.0.0 — OMNIX QUANTUM Open Standard


Abstract

   This document specifies the Agent Trust Fabric (ATF) protocol — a
   cryptographic framework for post-quantum-secured agent-to-agent
   authority delegation.  ATF defines the structure of Agent Identity
   Records, Delegation Receipts, Trust Lattices, and the Monotonic
   Authority Reduction invariant that together enable independently
   verifiable chains of AI-agent authority traceable to a human origin.

   An ATF-compliant implementation enforces formally specified, model-checked
   invariants ensuring that no autonomous agent can possess or exercise authority
   beyond what was explicitly delegated to it by a verified principal, and that
   every delegation event produces a cryptographic artifact verifiable by any
   party without access to the issuing platform.

Status of This Memo

   This is an OMNIX QUANTUM Open Standard, published under the
   OMNIX Open Governance License v1.0.  Implementers are encouraged
   to adopt ATF-1 and reference this document as the normative
   specification.  Feedback and errata should be submitted to the
   OMNIX Standards Track at standards@omnixquantum.com.

   This document is a product of the OMNIX QUANTUM Standards Working
   Group.  It represents the consensus of the working group and has
   been approved for publication by the OMNIX Technical Committee.

Copyright Notice

   Copyright (c) 2026 OMNIX QUANTUM LTD.  All rights reserved.
   This document may be reproduced for implementation purposes.

Table of Contents

   1.  Introduction
   2.  Conventions and Terminology
   3.  Architecture Overview
   4.  Agent Identity Record (AIR)
       4.1.  Identity Fields
       4.2.  Registration Hash
       4.3.  Authority Budget
       4.4.  Registration Tiers
   5.  Delegation Receipt (DR)
       5.1.  Receipt Fields
       5.2.  Content Hash Construction
       5.3.  PQC Signature
       5.4.  Receipt Lifecycle
   6.  Trust Lattice
       6.1.  Graph Properties
       6.2.  Chain Traversal
       6.3.  ATF Chain Completeness Score (CCS)
   7.  Core Invariants
       7.1.  ATF-INV-001: Monotonic Authority Reduction (MAR)
       7.2.  ATF-INV-002: Receipt Signing
       7.3.  ATF-INV-003: Chain Root Traceability
       7.4.  ATF-INV-004: Budget Ceiling
       7.5.  ATF-INV-005: Receipt Immutability
       7.6.  ATF-INV-006: Independent Verifiability
   8.  Verification Protocol
       8.1.  Offline Verification
       8.2.  Hash Verification
       8.3.  PQC Signature Verification
       8.4.  MAR Invariant Verification
       8.5.  Chain Verification
   9.  Wire Format
       9.1.  Agent Identity Record (JSON)
       9.2.  Delegation Receipt (JSON)
       9.3.  Verification Request
       9.4.  Verification Response
  10.  Cryptographic Algorithms
      10.1. Hashing
      10.2. Signing
      10.3. Algorithm Identifiers
  11.  Security Considerations
      11.1. Authority Expansion Attack
      11.2. Receipt Forgery
      11.3. Replay Attack
      11.4. Key Compromise
      11.5. Quantum Adversary
  12.  ATF Compliance Levels
  13.  Extension Points
  14.  References
  15.  Appendix A — ABNF Grammar
  16.  Appendix B — ATF Compliance Checklist
  17.  Appendix C — Reference Implementation Notes


1.  Introduction

   The rapid adoption of autonomous AI agents in enterprise, financial,
   healthcare, and defense environments has produced a structural
   accountability gap: agents act, but their authority cannot be
   independently verified.

   Existing agent frameworks (LangChain, AutoGen, CrewAI, Microsoft
   Semantic Kernel, and others) delegate authority implicitly — through
   environment variables, API keys, or runtime role assignments — that
   are neither signed by the delegating principal nor independently
   verifiable by a third party.  When an agent takes an action, there
   is no cryptographic proof of who authorized it, under what scope,
   or whether the authorization was still valid at the time of
   execution.

   This creates three categories of failure:

   a) Legal accountability gaps — regulators cannot attribute agent
      actions to a responsible principal.

   b) Authority escalation risk — agents may acquire or exercise
      authority beyond what was intended.

   c) Audit opacity — post-hoc investigation cannot reconstruct the
      chain of authority that authorized a specific action.

   ATF resolves all three.  By requiring every delegation event to
   produce a cryptographically signed, independently verifiable
   Delegation Receipt, ATF enables:

   -  Full traceability of every agent action to its human-origin
      authorizing principal.

   -  Mathematical guarantee that authority can only decrease through
      delegation chains (Monotonic Authority Reduction).

   -  Platform-independent verification by any regulator, auditor, or
      counterparty possessing only the delegation receipts and the
      root public key.

   ATF is designed to operate orthogonally to existing agent
   frameworks — it does not replace orchestration logic but provides
   the trust layer beneath it.


2.  Conventions and Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY",
   and "OPTIONAL" in this document are to be interpreted as described
   in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in
   all capitals, as shown here.

   Terms defined in this document:

   Agent Identity Record (AIR):
      An immutable cryptographic record binding an agent identifier to
      an authority budget and a Dilithium-3 public key.

   Agent Identifier (AID):
      A unique string of the form AID-{DOMAIN}-{16HEX} that
      permanently identifies an agent within an ATF lattice.

   Delegation Receipt (DR):
      A cryptographic artifact produced by every delegation event.
      A DR is signed by the delegating principal, embeds the
      principal's public key, and records the exact authority budget
      transferred.

   Delegation Receipt Identifier (DRID):
      A unique string of the form ATFDR-{16HEX}.

   Chain Root:
      The first DR in a delegation chain, issued by a Tier-1 human
      operator.  All DRs in the chain carry the chain_root_id of
      this first receipt.

   Trust Lattice:
      The directed acyclic graph (DAG) formed by all Agent Identity
      Records (nodes) and Delegation Receipts (edges).

   Monotonic Authority Reduction (MAR):
      The invariant that authority_budget_granted MUST be less than
      or equal to authority_budget_delegator for every DR.

   Authority Budget:
      A real number in [0.0, 100.0] representing the normalized
      scope of authority held by a principal.  100.0 represents
      full Tier-1 authority; 0.0 represents no authority.

   Content Hash:
      The SHA-256 digest of the canonical JSON serialization of all
      DR fields except {content_hash, pqc_signature, pqc_algorithm}.

   PQC Signature:
      A Dilithium-3 (ML-DSA-65) digital signature over the content
      hash, produced using the delegating principal's private key.

   ATF CCS:
      ATF Chain Completeness Score — a [0, 100] metric measuring the
      cryptographic completeness of an agent's delegation chain.

   Tier-1 Principal:
      A human operator with authority_budget = 100.0, representing
      the origin of all delegated authority in a lattice.

   Independent Verification:
      Verification of a DR or chain that requires no access to the
      issuing platform — only the receipts and a known public key.

   TAR:
      Temporal Admissibility Record — a time-bound proof that a
      specific DR was valid at the exact nanosecond of execution
      (defined in ATF Extension: Temporal Authority, ADR-157).


3.  Architecture Overview

   An ATF deployment consists of three layers:

   Layer 1 — Identity Plane:
      Registration of AI agents as Agent Identity Records.  Each
      agent receives a unique AID, an authority budget, and a
      Dilithium-3 key pair.  The registration event is PQC-signed
      by the registering principal.

   Layer 2 — Delegation Plane:
      Every transfer of authority between principals produces a
      Delegation Receipt.  DRs chain to their parent via
      parent_delegation_id and trace to their origin via
      chain_root_id.

   Layer 3 — Verification Plane:
      Any party (regulator, auditor, counterparty) can verify the
      full delegation chain by traversing DRs from leaf to root,
      recomputing content hashes, and verifying PQC signatures
      using the embedded public keys.

   These three layers combine to form the Trust Lattice — a complete
   cryptographic record of every delegation event in the system.


4.  Agent Identity Record (AIR)

4.1.  Identity Fields

   An AIR MUST contain the following fields:

   agent_id (string, REQUIRED):
      Unique agent identifier.  Format: AID-{DOMAIN}-{16HEX}.
      DOMAIN is the uppercase governance domain string.
      16HEX is 16 uppercase hexadecimal characters from a
      cryptographically random UUID.
      Example: AID-FINANCE-3A7F9B2C1D4E5F6A

   display_name (string, REQUIRED):
      Human-readable name for the agent.  Maximum 128 characters.

   domain (string, REQUIRED):
      Governance domain.  MUST be uppercase.
      Examples: FINANCE, HEALTHCARE, DEFENSE, ENERGY, INSURANCE.

   vertical (string, REQUIRED):
      Sub-vertical within the domain.  MUST be lowercase.
      Examples: equity_trading, credit_risk, surgical_clearance.

   authority_budget (number, REQUIRED):
      Real number in [0.0, 100.0].  MUST NOT exceed the
      registering principal's own authority budget.

   registered_by (string, REQUIRED):
      Identifier of the principal performing registration.
      MUST be a Tier-1 AID or human operator identifier.

   registration_tier (integer, REQUIRED):
      Authority tier of the registering principal (1–4).
      Tier-1: Full authority (budget up to 100.0).
      Tier-2: Operational authority (budget up to 80.0).
      Tier-3: Supervised authority (budget up to 50.0).
      Tier-4: Read-only (budget up to 20.0).

   public_key_b64 (string, REQUIRED):
      Base64-encoded Dilithium-3 public key generated for this
      agent at registration time.

   registration_hash (string, REQUIRED):
      SHA-256 hex digest of the canonical JSON of all public
      fields (excluding registration_hash, pqc_signature,
      pqc_algorithm).

   pqc_signature (string, OPTIONAL):
      Base64-encoded Dilithium-3 signature over the registration
      payload, produced by the registering principal's private key.
      Implementations SHOULD include this field.

   pqc_algorithm (string, OPTIONAL):
      Algorithm identifier string.  MUST be "dilithium3" when
      pqc_signature is present.

   status (string, REQUIRED):
      Lifecycle status.  One of: ACTIVE | SUSPENDED | REVOKED.
      MUST be set to ACTIVE at registration time.

   capabilities (array of strings, REQUIRED):
      List of capability identifiers authorized for this agent.
      MAY be empty.

   registered_at (string, REQUIRED):
      ISO 8601 UTC timestamp of registration.

   metadata (object, OPTIONAL):
      Extension fields.  Implementations MAY add fields here.
      Private keys MUST NOT appear in metadata.

4.2.  Registration Hash

   The registration_hash MUST be computed as follows:

   1. Construct a JSON object containing all public fields of the
      AIR EXCEPT: registration_hash, pqc_signature, pqc_algorithm.

   2. Serialize to canonical JSON with keys in lexicographic order
      and no whitespace:
         json.dumps(obj, sort_keys=True, separators=(",", ":"))

   3. Encode the result as UTF-8.

   4. Compute SHA-256.  Express as lowercase hex.

4.3.  Authority Budget

   authority_budget is a normalized measure of delegated authority:

   -  100.0 — Full Tier-1 authority (human operator root)
   -  80.0  — Maximum Tier-2 agent authority
   -  50.0  — Default agent authority
   -  0.0   — No authority

   The following constraint MUST hold at all times:

      registered_agent.authority_budget
         <= registering_principal.authority_budget

   Implementations MUST enforce this at registration time.

4.4.  Registration Tiers

   | Tier | Max Budget | Description                          |
   |------|-----------|--------------------------------------|
   |  1   |   100.0   | Human operator, full authority       |
   |  2   |    80.0   | Operational agent, direct delegation |
   |  3   |    50.0   | Supervised agent, constrained scope  |
   |  4   |    20.0   | Read-only agent, no action authority |


5.  Delegation Receipt (DR)

5.1.  Receipt Fields

   A Delegation Receipt MUST contain the following fields:

   delegation_id (string, REQUIRED):
      Unique receipt identifier.  Format: ATFDR-{16HEX}.
      16HEX is 16 uppercase hexadecimal characters from a
      cryptographically random UUID.

   delegator_id (string, REQUIRED):
      AID of the delegating principal, or a Tier-1 human operator
      identifier in the form HUMAN-{identifier}.

   delegate_id (string, REQUIRED):
      AID of the receiving agent.

   task_scope (object, REQUIRED):
      JSON object describing the authorized task scope.
      MUST contain at minimum: "action" (string).
      SHOULD contain: "domain", "constraints" (array).
      Implementations MAY extend this object.

   authority_budget_delegator (number, REQUIRED):
      Authority budget held by the delegator at the time of
      delegation.  Range: [0.0, 100.0].

   authority_budget_granted (number, REQUIRED):
      Authority budget granted to the delegate.
      MUST satisfy: authority_budget_granted
                       <= authority_budget_delegator.

   parent_delegation_id (string, OPTIONAL):
      delegation_id of the DR that gave the delegator its
      authority.  NULL / absent for root delegations.

   chain_root_id (string, REQUIRED):
      delegation_id of the root DR in the chain (the first
      delegation from a Tier-1 principal).
      For root DRs, MUST be equal to delegation_id.

   delegation_depth (integer, REQUIRED):
      Zero-based depth of the delegation in the chain.
      0 = Tier-1 human delegation.
      N = Nth sub-agent delegation.
      MUST strictly increase along any chain path.

   delegator_public_key (string, REQUIRED):
      Base64-encoded Dilithium-3 public key of the delegator.
      MUST be embedded for independent verification.
      Implementations MUST include this field.

   content_hash (string, REQUIRED):
      SHA-256 hex digest of the canonical JSON of all fields
      except {content_hash, pqc_signature, pqc_algorithm}.

   pqc_signature (string, OPTIONAL):
      Base64-encoded Dilithium-3 signature over the content_hash,
      produced using the delegator's private key.
      Implementations SHOULD include this field.

   pqc_algorithm (string, OPTIONAL):
      Algorithm identifier.  MUST be "dilithium3".

   expires_at (string, OPTIONAL):
      ISO 8601 UTC timestamp after which the DR is no longer
      valid.  If absent, the DR does not expire by time.

   status (string, REQUIRED):
      Lifecycle status.  One of: ACTIVE | EXPIRED | REVOKED.
      MUST be ACTIVE at issuance.

   created_at (string, REQUIRED):
      ISO 8601 UTC timestamp of issuance.

   metadata (object, OPTIONAL):
      Extension fields.

5.2.  Content Hash Construction

   The content_hash MUST be computed as follows:

   1. Construct a JSON object containing all fields of the DR
      EXCEPT: content_hash, pqc_signature, pqc_algorithm.

   2. Serialize to canonical JSON:
         json.dumps(obj, sort_keys=True, separators=(",", ":"))

   3. Encode as UTF-8.

   4. Compute SHA-256.  Express as lowercase hex.

   Verification MUST recompute this hash and compare to the
   embedded content_hash.  A mismatch indicates field tampering.

5.3.  PQC Signature

   When pqc_signature is present, it MUST be computed as:

   1. Encode the content_hash string as UTF-8 bytes.

   2. Sign using the delegator's Dilithium-3 private key with the
      ML-DSA-65 scheme (FIPS 204).

   3. Encode the signature bytes in standard base64.

   Verification MUST use the delegator_public_key embedded in the
   DR itself.  No external key lookup is required or permitted
   for independent verification.

5.4.  Receipt Lifecycle

   DRs transition through the following states:

   ACTIVE  →  EXPIRED  (if expires_at has passed)
   ACTIVE  →  REVOKED  (explicit Tier-1 revocation)

   Revocation is permanent and irrevocable.
   Implementations MUST propagate revocation to all child DRs
   in the chain.  A chain containing any REVOKED DR MUST report
   fully_verified = false.


6.  Trust Lattice

6.1.  Graph Properties

   The Trust Lattice is a directed acyclic graph (DAG) where:

   -  Nodes are Agent Identity Records.
   -  Edges are Delegation Receipts.
   -  An edge (delegator_id → delegate_id) exists for each DR.

   The following structural invariants MUST hold:

   Acyclicity:
      No path exists from any node back to itself.
      Implementations MUST detect and reject cycles.
      delegation_depth strictly increasing along any path is a
      sufficient (though not necessary) condition.

   Unique Root:
      Every connected component of the lattice has exactly one
      root node — a Tier-1 principal with no parent delegation.

   Monotone Depth:
      For every edge (delegator, delegate):
         delegate.delegation_depth = delegator.delegation_depth + 1

6.2.  Chain Traversal

   To reconstruct the full delegation chain for a leaf agent:

   1. Retrieve the leaf agent's most recent ACTIVE DR.

   2. Follow parent_delegation_id links upward.

   3. Terminate when parent_delegation_id is absent (root node).

   4. Guard against cycles using a visited set.

   5. Reverse the collected path: present root → leaf.

   The resulting ordered list is the verified delegation chain.

6.3.  ATF Chain Completeness Score (CCS)

   The ATF CCS quantifies the cryptographic completeness of an
   agent's delegation chain on a scale of 0–100:

   Component scoring (maximum 100 points):

      chain_integrity_score  (max 40 pts):
         40 - (hash_breaks × 10)
         Measures: all receipt content hashes verify correctly.

      pqc_coverage_score (max 30 pts):
         30 - (unsigned_receipts × 10)
         Measures: all receipts carry valid PQC signatures.

      mar_invariant_score (max 20 pts):
         20 if MAR holds throughout chain; 0 otherwise.
         Measures: no authority expansion detected.

      depth_score (max 10 pts):
         10 if chain_depth >= 1; 0 otherwise.
         Measures: at least one delegation exists.

   Verdicts:

      ≥ 90  COMPLETE    — Fully defensible. Suitable for
                          institutional audit and regulatory filing.
      70–89 DEGRADED    — Minor gaps. Investigation recommended.
                          Not suitable for regulatory submission.
      50–69 PARTIAL     — Significant gaps. Audit uncertain.
                          Chain cannot be fully trusted.
      < 50  COMPROMISED — Chain integrity cannot be established.
                          Treat all associated actions as
                          unauthorized pending investigation.


7.  Core Invariants

   The following invariants are REQUIRED for ATF compliance.
   An implementation violating any invariant is NOT ATF-compliant.

7.1.  ATF-INV-001: Monotonic Authority Reduction (MAR)

   For every Delegation Receipt DR:

      DR.authority_budget_granted <= DR.authority_budget_delegator

   Additionally, for any sequence of DRs in a chain
   [DR_0, DR_1, ..., DR_n]:

      DR_i.authority_budget_granted
         <= DR_{i-1}.authority_budget_granted   for all i ≥ 1

   Implementations MUST enforce ATF-INV-001 BEFORE any signing
   or persistence occurs.  A DR that would violate this invariant
   MUST NOT be issued.  The appropriate response is to raise an
   AuthorityExpansionViolation error.

7.2.  ATF-INV-002: Receipt Signing

   Every Delegation Receipt SHOULD carry a PQC signature
   (pqc_signature field) produced by the delegator's private key
   over the receipt's content_hash.

   For ATF-COMPLIANT-LEVEL-2 and above, this is REQUIRED.

   Implementations MUST NOT issue receipts where pqc_signature
   covers a different content than the embedded content_hash.

7.3.  ATF-INV-003: Chain Root Traceability

   Every DR in a chain MUST carry the chain_root_id of the
   originating root DR.  chain_root_id MUST be identical for all
   DRs in the same chain.

   For root DRs (no parent_delegation_id):
      chain_root_id MUST equal delegation_id.

7.4.  ATF-INV-004: Budget Ceiling

   A delegating principal MUST NOT grant authority exceeding the
   authority it holds at the time of delegation:

      granted <= delegator.authority_budget

   This is the per-receipt formulation of ATF-INV-001.

7.5.  ATF-INV-005: Receipt Immutability

   Once a Delegation Receipt is issued (status = ACTIVE), its
   content fields MUST NOT be modified.  The content_hash
   provides the tamper-evidence mechanism.

   Status transitions (ACTIVE → EXPIRED, ACTIVE → REVOKED) are
   permitted and do not modify content fields.

7.6.  ATF-INV-006: Independent Verifiability

   Any party MUST be able to verify a delegation chain using only:

   a. The Delegation Receipt objects (exportable as JSON).
   b. The public key of the Tier-1 root principal (or the
      embedded delegator_public_key at each chain link).

   No access to the issuing platform, its API, its database, or
   any online service is required or permitted for verification.

   Implementations MUST embed delegator_public_key in every DR.


8.  Verification Protocol

8.1.  Offline Verification

   The following procedure verifies a Delegation Receipt DR
   without any platform access:

   INPUTS:
      dr          — the Delegation Receipt (JSON object)
      (optional)  — delegator's public key if not embedded

   OUTPUT:
      verification_result — structured result (see Section 9.4)

8.2.  Hash Verification

   1. Construct canonical_fields = dr fields EXCEPT
      {content_hash, pqc_signature, pqc_algorithm}.

   2. Compute recomputed_hash = SHA-256(
         canonical_json(canonical_fields)
      ).

   3. hash_valid = (recomputed_hash == dr.content_hash).

   If hash_valid is false, the receipt has been tampered with.
   The verification MUST stop and report fully_verified = false.

8.3.  PQC Signature Verification

   If dr.pqc_signature is present:

   1. Decode dr.pqc_signature from base64.
   2. Decode dr.delegator_public_key from base64.
   3. Verify the signature over dr.content_hash.encode("utf-8")
      using the ML-DSA-65 (Dilithium-3) verification algorithm.

   pqc_signature_valid = result of step 3.

   If dr.pqc_signature is absent, pqc_signature_valid = false
   and pqc_checked = false.

8.4.  MAR Invariant Verification

   mar_invariant_valid = (
      dr.authority_budget_granted <= dr.authority_budget_delegator
   )

   If mar_invariant_valid is false, the receipt was issued in
   violation of ATF-INV-001.  This MUST be reported.

8.5.  Chain Verification

   To verify a full delegation chain for agent A:

   1. Retrieve or receive all DRs in the chain, ordered
      root → leaf.

   2. Apply Sections 8.2–8.4 to each DR.

   3. Verify that delegation_depth strictly increases:
      DR[i].delegation_depth == DR[i-1].delegation_depth + 1

   4. Verify authority budget monotonically decreases:
      DR[i].authority_budget_granted
         <= DR[i-1].authority_budget_granted

   5. Verify all chain_root_id values are identical.

   6. Verify the leaf DR's delegate_id == A.

   fully_verified = all of the above conditions hold.


9.  Wire Format

9.1.  Agent Identity Record (JSON)

   {
     "agent_id":           "AID-FINANCE-3A7F9B2C1D4E5F6A",
     "display_name":       "Market Risk Agent",
     "domain":             "FINANCE",
     "vertical":           "market_risk",
     "authority_budget":   60.0,
     "registered_by":      "HUMAN-TIER1-HN-001",
     "registration_tier":  1,
     "public_key_b64":     "<base64-dilithium3-pubkey>",
     "registration_hash":  "<sha256-hex>",
     "pqc_signature":      "<base64-dilithium3-sig>",
     "pqc_algorithm":      "dilithium3",
     "status":             "ACTIVE",
     "capabilities":       ["read_signals", "compute_var"],
     "registered_at":      "2026-05-12T14:00:00.000000+00:00",
     "metadata":           {}
   }

9.2.  Delegation Receipt (JSON)

   {
     "delegation_id":              "ATFDR-8B2C4D6E1F3A5B7C",
     "delegator_id":               "HUMAN-TIER1-HN-001",
     "delegate_id":                "AID-FINANCE-3A7F9B2C1D4E5F6A",
     "task_scope": {
       "action":      "compute_portfolio_risk",
       "domain":      "FINANCE",
       "constraints": ["read_only", "no_trading", "approved_data_only"]
     },
     "authority_budget_delegator": 100.0,
     "authority_budget_granted":   60.0,
     "parent_delegation_id":       null,
     "chain_root_id":              "ATFDR-8B2C4D6E1F3A5B7C",
     "delegation_depth":           1,
     "delegator_public_key":       "<base64-dilithium3-pubkey>",
     "content_hash":               "<sha256-hex>",
     "pqc_signature":              "<base64-dilithium3-sig>",
     "pqc_algorithm":              "dilithium3",
     "expires_at":                 "2026-05-13T14:00:00.000000+00:00",
     "status":                     "ACTIVE",
     "created_at":                 "2026-05-12T14:00:00.000000+00:00",
     "metadata":                   {}
   }

9.3.  Verification Request

   POST /api/atf/verify   Content-Type: application/json

   Option A — by ID:
   { "delegation_id": "ATFDR-8B2C4D6E1F3A5B7C" }

   Option B — by embedded receipt:
   { "receipt": { <full DR JSON> } }

9.4.  Verification Response

   {
     "verification": {
       "delegation_id":          "ATFDR-8B2C4D6E1F3A5B7C",
       "hash_valid":             true,
       "pqc_signature_valid":    true,
       "pqc_checked":            true,
       "mar_invariant_valid":    true,
       "not_expired":            true,
       "fully_verified":         true,
       "delegation_depth":       1,
       "authority_budget_granted": 60.0,
       "authority_reduction_pct": 40.0,
       "chain_root_id":          "ATFDR-8B2C4D6E1F3A5B7C",
       "pqc_signed":             true,
       "delegator_id":           "HUMAN-TIER1-HN-001",
       "delegate_id":            "AID-FINANCE-3A7F9B2C1D4E5F6A"
     },
     "status": "verified"
   }


10.  Cryptographic Algorithms

10.1. Hashing

   Content hash algorithm: SHA-256 (FIPS 180-4).
   Output: 256-bit / 64 lowercase hexadecimal characters.
   Canonical input: UTF-8-encoded lexicographically-sorted JSON.

10.2. Signing

   Primary algorithm: ML-DSA-65 (Dilithium-3), FIPS 204.
   Security level: NIST PQC Level 3 (targeting 128-bit post-quantum security).
   Public key size: 1952 bytes.
   Private key size: 4000 bytes.
   Signature size: 3293 bytes.

   Fallback (when PQC library unavailable):
   SHA-256 content hash without digital signature.
   Fallback MUST NOT be used in production ATF-COMPLIANT-LEVEL-2+
   deployments.

10.3. Algorithm Identifiers

   | Algorithm     | Identifier   | Status     |
   |---------------|--------------|------------|
   | ML-DSA-65     | "dilithium3" | REQUIRED   |
   | SHA-256       | "sha256"     | HASH ONLY  |


11.  Security Considerations

11.1. Authority Expansion Attack

   An adversary may attempt to issue a DR with
   authority_budget_granted > authority_budget_delegator.

   ATF-INV-001 (MAR) MUST be enforced BEFORE any I/O operation.
   The check MUST be atomic with receipt issuance.
   The private key MUST NOT be accessible to the delegate.

11.2. Receipt Forgery

   An adversary may attempt to alter fields of an existing DR.

   The content_hash provides tamper evidence for field changes.
   The pqc_signature provides cryptographic non-repudiation.
   A valid signature with an altered hash is computationally
   infeasible under ML-DSA-65.

11.3. Replay Attack

   An adversary may attempt to reuse an expired or revoked DR.

   Implementations MUST check expires_at on every use.
   Revoked DRs MUST be permanently refused regardless of
   content validity.

11.4. Key Compromise

   If a delegator's private key is compromised, all DRs signed
   with that key must be revoked.

   The affected chain_root_id and all descendant DRs MUST be
   revoked immediately upon key compromise confirmation.

11.5. Quantum Adversary

   ATF uses the ML-DSA-65 algorithm (Dilithium-3), as specified in NIST
   FIPS 204 (August 2024), targeting NIST PQC Level 3 security — resistant
   to attacks by Shor's algorithm and known quantum search algorithms.

   Note on Implementation: The ATF reference implementation uses the `pqc`
   Python library for ML-DSA-65 signatures.  Deployments in regulated or
   critical-infrastructure environments SHOULD evaluate whether a FIPS 140-3
   validated cryptographic module is required for their compliance context.
   The ATF protocol specification is library-agnostic; any correct
   implementation of ML-DSA-65 per FIPS 204 satisfies the signature
   requirements.

   Implementations MUST NOT fall back to RSA, ECDSA, or other
   classical-only signature schemes for production deployments
   where ATF-COMPLIANT-LEVEL-2 or higher is required.


12.  ATF Compliance Levels

   ATF defines three compliance levels:

   ATF-COMPLIANT-LEVEL-1 (Basic):
      - MUST issue DRs with content_hash.
      - MUST enforce ATF-INV-001 (MAR).
      - MUST support chain traversal.
      - SHOULD include pqc_signature.
      - MAY use SHA-256-only fallback.

   ATF-COMPLIANT-LEVEL-2 (Standard):
      - All Level-1 requirements.
      - MUST include pqc_signature (ML-DSA-65) on every DR.
      - MUST embed delegator_public_key on every DR.
      - MUST support independent offline verification.
      - MUST NOT use SHA-256-only in production.
      - MUST report ATF CCS.

   ATF-COMPLIANT-LEVEL-3 (Sovereign):
      - All Level-2 requirements.
      - MUST provide formal verification of invariants
        (TLA+, Coq, or equivalent proof system).
      - MUST support Temporal Authority (TAR) per ATF Extension.
      - MUST support Cross-Domain Trust Portability per extension.
      - MUST support public CLI verifier.
      - RECOMMENDED for aerospace, defense, central banking.


13.  Extension Points

   ATF-1 defines the following official extension points:

   EXT-001: Temporal Authority (ATF-TAR)
      Time-bound execution admissibility records.
      Binds a DR to a specific execution timestamp.
      Reference: OMNIX ADR-157.

   EXT-002: Cross-Domain Trust Portability (ATF-CDTP)
      Authority translation across governance domains.
      Reference: OMNIX ADR-158.

   EXT-003: Formal Verification Profile (ATF-FV)
      Machine-checkable proofs of core invariants.
      Reference: OMNIX ATF-TLA-SPEC-1.0.

   EXT-004: Chain Genealogy (ATF-GEN)
      Receipt genealogy tracing across system boundaries.
      Reference: OMNIX ADR-154.

   Implementers MAY define additional extensions using the
   ATF-EXT-{vendor}-{name} naming convention.


14.  References

   [FIPS-204]  NIST, "Module-Lattice-Based Digital Signature
               Standard (ML-DSA)", FIPS 204, August 2024.

   [FIPS-180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4,
                August 2015.

   [RFC2119]   Bradner, S., "Key words for use in RFCs to Indicate
               Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC8174]   Leiba, B., "Ambiguity of Uppercase vs Lowercase in
               RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

   [ADR-156]   Nunes, H., "Agent Trust Fabric", OMNIX ADR-156,
               May 2026.

   [ADR-157]   Nunes, H., "Temporal Authority Admissibility",
               OMNIX ADR-157, May 2026.

   [ADR-158]   Nunes, H., "Cross-Domain Trust Portability",
               OMNIX ADR-158, May 2026.


Appendix A — ABNF Grammar

   Agent-ID = "AID-" DOMAIN "-" 16HEXDIG
   DOMAIN   = 1*UPALPHA
   DRID     = "ATFDR-" 16HEXDIG
   16HEXDIG = 16( HEXDIG )
   HEXDIG   = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
   UPALPHA  = %x41-5A          ; uppercase A-Z
   DIGIT    = %x30-39          ; 0-9


Appendix B — ATF Compliance Checklist

   [ ] AIRs include agent_id in AID-{DOMAIN}-{16HEX} format
   [ ] AIRs include content-hashed registration_hash
   [ ] DRs include delegation_id in ATFDR-{16HEX} format
   [ ] DRs include content_hash (SHA-256)
   [ ] ATF-INV-001 (MAR) enforced before DR issuance
   [ ] ATF-INV-003 (chain_root_id) correctly assigned
   [ ] ATF-INV-005 (immutability) enforced after issuance
   [ ] delegator_public_key embedded in every DR
   [ ] pqc_signature included on every DR (Level-2+)
   [ ] Offline verification supported
   [ ] ATF CCS computed and reported
   [ ] Public verifier available (Level-3)
   [ ] Formal verification proofs available (Level-3)


Appendix C — Reference Implementation Notes

   The OMNIX QUANTUM reference implementation of ATF-1 is available
   at:

      omnix_core/agents/atf/

   Modules:
      agent_identity.py     — AgentIdentityEngine (AIR issuance)
      delegation_receipt.py — DelegationReceiptEngine (DR issuance)
      trust_lattice.py      — TrustLattice (DAG management)
      temporal_authority.py — TemporalAuthorityEngine (EXT-001)
      domain_bridge.py      — CrossDomainBridge (EXT-002)

   Public Verifier CLI:
      omnix_web/public/omnix_atf_verify.py

   Database Tables:
      atf_agent_registry      — AIR persistence
      atf_delegation_receipts — DR persistence
      atf_temporal_records    — TAR persistence (EXT-001)
      atf_domain_bridges      — CDTP persistence (EXT-002)

   Test Coverage:
      tests/test_agent_trust_fabric.py — 50+ tests, 6 invariants


Author's Address

   Harold Nunes
   OMNIX QUANTUM LTD
   Dubai, UAE
   Email: harold@omnixquantum.com
   URI:   https://omnixquantum.com/atf


Acknowledgements

   The ATF protocol was developed by the OMNIX QUANTUM engineering
   team in response to the accountability gap in enterprise AI agent
   deployments: the absence of a formally specified, independently
   verifiable protocol answering who authorized an AI agent, under
   what authority bound, and whether that authority was valid at the
   exact moment of execution.

   The design was informed by the W3C Verifiable Credentials
   specification, IETF RFC 7519 (JWT), NIST FIPS 204 (ML-DSA),
   NIST SP 800-207 (Zero Trust Architecture), and the OMNIX
   Governance Architecture (ADR-028 through ADR-158).

   Existing AI agent orchestration frameworks (LangChain, AutoGen,
   CrewAI, Semantic Kernel, Google ADK) focus on agent execution
   and tool use, not on cryptographic governance of the authority
   chain before execution.  ATF addresses the governance layer that
   precedes these frameworks' operation and is complementary to them.
```
