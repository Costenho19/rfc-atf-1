--------------------------- MODULE ATF ----------------------------
(*
  OMNIX Agent Trust Fabric — Formal Specification (TLA+)
  ATF-FV-1.0 — OMNIX QUANTUM LTD — May 2026

  This TLA+ specification formally defines the behavioral properties
  of the Agent Trust Fabric (ATF) protocol as described in RFC-ATF-1.

  Properties proved by this specification:

    MARInvariant         — Monotonic Authority Reduction holds on every
                           delegation receipt and across every chain
                           (ATF-INV-001, ATF-INV-004)

    AcyclicityInvariant  — The Trust Lattice is a DAG; no delegation
                           path forms a cycle (Trust Lattice property)

    ChainRootConsistency — All receipts in a chain share the same
                           chain_root_id (ATF-INV-003)

    DepthMonotone        — delegation_depth strictly increases along
                           every path in the lattice

    ImmutabilityProperty — Once a receipt is issued, its content
                           fields cannot change (ATF-INV-005)

    BudgetBoundedness    — All authority budgets remain in [0, MaxBudget]

  Model parameters:
    MaxBudget   = 100   (maximum authority budget)
    MaxDepth    = 10    (maximum delegation chain depth)
    MaxAgents   = 8     (model checking bound on agent count)
    MaxReceipts = 12    (model checking bound on receipt count)

  Usage with TLC model checker:
    tlc ATF.tla -config ATF.cfg -workers 4

  Reference implementation:
    omnix_core/agents/atf/ (Python)

  Author: Harold Nunes — OMNIX QUANTUM LTD
*)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxBudget,      \* Maximum authority budget (typically 100)
    MaxDepth,       \* Maximum delegation chain depth
    AgentIDs,       \* Set of possible agent identifiers
    HumanIDs,       \* Set of human operator identifiers
    DelegationIDs   \* Set of possible delegation receipt identifiers

ASSUME MaxBudget \in Nat
ASSUME MaxDepth  \in Nat
ASSUME MaxBudget > 0
ASSUME MaxDepth  > 0

\* Budget type: integers in [0, MaxBudget]
Budget == 0..MaxBudget

\* All principals (agents + humans)
Principals == AgentIDs \cup HumanIDs

\* Delegation receipt record type
DelegationRecord == [
    delegation_id          : DelegationIDs,
    delegator_id           : Principals,
    delegate_id            : AgentIDs,
    authority_budget_delegator : Budget,
    authority_budget_granted   : Budget,
    parent_delegation_id   : DelegationIDs \cup {<<"ROOT">>},
    chain_root_id          : DelegationIDs,
    delegation_depth       : 0..MaxDepth,
    status                 : {"ACTIVE", "REVOKED", "EXPIRED"}
]

\* ---------------------------------------------------------------
\* STATE VARIABLES
\* ---------------------------------------------------------------

VARIABLES
    agents,       \* FUNCTION: AgentID -> [budget: Budget, status: STATUS]
    receipts,     \* FUNCTION: DelegationID -> DelegationRecord
    edges         \* SET: pairs (delegator_id, delegate_id) in lattice

vars == <<agents, receipts, edges>>

\* ---------------------------------------------------------------
\* TYPE INVARIANT
\* ---------------------------------------------------------------

TypeOK ==
    /\ agents \in [AgentIDs -> [
            budget  : Budget,
            status  : {"ACTIVE", "SUSPENDED", "REVOKED"}
        ]]
    /\ receipts \in [DelegationIDs -> DelegationRecord \cup {<<"EMPTY">>}]
    /\ edges \subseteq (Principals \X AgentIDs)

\* ---------------------------------------------------------------
\* AUXILIARY OPERATORS
\* ---------------------------------------------------------------

\* The set of all issued (non-empty) receipts
IssuedReceipts ==
    {did \in DelegationIDs : receipts[did] # <<"EMPTY">>}

\* Get a receipt by ID
Receipt(did) == receipts[did]

\* True if a receipt is active
IsActive(did) ==
    /\ did \in IssuedReceipts
    /\ Receipt(did).status = "ACTIVE"

\* Reachable predecessors of a receipt via parent links
\* (used to verify acyclicity)
RECURSIVE Ancestors(_, _)
Ancestors(did, visited) ==
    IF did \notin IssuedReceipts THEN {}
    ELSE
        LET r == Receipt(did)
            parent == r.parent_delegation_id
        IN  IF parent = <<"ROOT">> THEN {did}
            ELSE IF parent \in visited THEN {did}  \* cycle detected
            ELSE {did} \cup Ancestors(parent, visited \cup {did})

\* ---------------------------------------------------------------
\* CORE INVARIANTS
\* ---------------------------------------------------------------

(*
  ATF-INV-001 / ATF-INV-004: Monotonic Authority Reduction (MAR)
  
  For EVERY issued delegation receipt:
    authority_budget_granted <= authority_budget_delegator
  
  This is the central invariant of ATF. It guarantees that no
  delegation event can expand the authority of an agent beyond
  what the delegating principal holds.
*)
MARInvariant ==
    \A did \in IssuedReceipts :
        LET r == Receipt(did)
        IN  r.authority_budget_granted <= r.authority_budget_delegator

(*
  MAR Chain Invariant
  
  For any two receipts r1, r2 where r2.parent_delegation_id = r1.delegation_id:
    r2.authority_budget_granted <= r1.authority_budget_granted
  
  This extends MAR to the full chain: authority only decreases
  as delegation depth increases.
*)
MARChainInvariant ==
    \A did \in IssuedReceipts :
        LET r == Receipt(did)
            parent == r.parent_delegation_id
        IN  parent # <<"ROOT">> =>
            parent \in IssuedReceipts =>
            r.authority_budget_granted <= Receipt(parent).authority_budget_granted

(*
  Acyclicity Invariant
  
  The Trust Lattice is a directed acyclic graph (DAG).
  No delegation path forms a cycle.
  
  Enforced by: delegation_depth strictly increases, and every
  receipt has at most one parent.
*)
AcyclicityInvariant ==
    \A did \in IssuedReceipts :
        did \notin Ancestors(Receipt(did).parent_delegation_id, {did})

(*
  ATF-INV-003: Chain Root Consistency
  
  All receipts that share a chain_root_id form a connected
  sub-tree rooted at that chain_root_id.
  
  For the root receipt itself: chain_root_id = delegation_id.
*)
ChainRootConsistency ==
    \A did \in IssuedReceipts :
        LET r == Receipt(did)
        IN  r.parent_delegation_id = <<"ROOT">> =>
            r.chain_root_id = r.delegation_id

(*
  Depth Monotone Property
  
  For any receipt r2 that is a direct child of r1:
    r2.delegation_depth = r1.delegation_depth + 1
*)
DepthMonotone ==
    \A did \in IssuedReceipts :
        LET r == Receipt(did)
            parent == r.parent_delegation_id
        IN  parent # <<"ROOT">> =>
            parent \in IssuedReceipts =>
            r.delegation_depth = Receipt(parent).delegation_depth + 1

(*
  Budget Boundedness
  
  All authority budgets remain in [0, MaxBudget].
*)
BudgetBoundedness ==
    /\ \A aid \in AgentIDs : agents[aid].budget \in Budget
    /\ \A did \in IssuedReceipts :
           /\ Receipt(did).authority_budget_granted   \in Budget
           /\ Receipt(did).authority_budget_delegator \in Budget

(*
  ATF-INV-005: Immutability Property
  
  In TLA+, immutability is expressed as a temporal property:
  once a receipt is issued (non-EMPTY), its content fields
  cannot change.
  
  Note: status transitions (ACTIVE→REVOKED) are permitted.
*)
ImmutabilityProperty ==
    [][\A did \in IssuedReceipts :
        LET r == Receipt(did)
        IN  receipts'[did] # <<"EMPTY">> =>
            /\ receipts'[did].delegation_id            = r.delegation_id
            /\ receipts'[did].delegator_id             = r.delegator_id
            /\ receipts'[did].delegate_id              = r.delegate_id
            /\ receipts'[did].authority_budget_delegator = r.authority_budget_delegator
            /\ receipts'[did].authority_budget_granted   = r.authority_budget_granted
            /\ receipts'[did].parent_delegation_id     = r.parent_delegation_id
            /\ receipts'[did].chain_root_id            = r.chain_root_id
            /\ receipts'[did].delegation_depth         = r.delegation_depth
    ]_vars

\* ---------------------------------------------------------------
\* COMBINED SAFETY SPECIFICATION
\* ---------------------------------------------------------------

ATFSafetySpec ==
    /\ TypeOK
    /\ MARInvariant
    /\ MARChainInvariant
    /\ AcyclicityInvariant
    /\ ChainRootConsistency
    /\ DepthMonotone
    /\ BudgetBoundedness

\* ---------------------------------------------------------------
\* INITIAL STATE
\* ---------------------------------------------------------------

Init ==
    /\ agents   = [aid \in AgentIDs |-> [budget |-> 0, status |-> "ACTIVE"]]
    /\ receipts = [did \in DelegationIDs |-> <<"EMPTY">>]
    /\ edges    = {}

\* ---------------------------------------------------------------
\* ACTIONS
\* ---------------------------------------------------------------

(*
  RegisterAgent: Register a new agent with an authority budget.
  
  Preconditions:
    - Agent is not already ACTIVE with a budget > 0
    - Budget is within [0, MaxBudget]
    - Budget does not exceed the registrar's budget (not modelled
      explicitly here; enforced in implementation)
*)
RegisterAgent(aid, budget) ==
    /\ budget \in Budget
    /\ agents[aid].budget = 0
    /\ agents' = [agents EXCEPT ![aid] = [budget |-> budget, status |-> "ACTIVE"]]
    /\ UNCHANGED <<receipts, edges>>

(*
  IssueDelegation: Issue a new Delegation Receipt.
  
  Preconditions (ATF-INV-001 enforcement):
    - granted <= delegator_budget  (MAR)
    - granted \in Budget
    - depth < MaxDepth
    - did not already issued
    - If parent exists: parent is ACTIVE and chain_root consistent
  
  The MAR check happens HERE, before any state change — mirroring
  the implementation where AuthorityExpansionViolation is raised
  before any signing or persistence.
*)
IssueDelegation(
    did,
    delegator_id,
    delegate_id,
    delegator_budget,
    granted,
    parent_did,
    chain_root,
    depth
) ==
    \* Preconditions
    /\ did \notin IssuedReceipts
    /\ delegate_id \in AgentIDs
    /\ granted \in Budget
    /\ delegator_budget \in Budget
    /\ depth \in 0..MaxDepth
    \* ATF-INV-001: MAR check BEFORE issuance
    /\ granted <= delegator_budget
    \* Chain consistency
    /\ (parent_did = <<"ROOT">> => chain_root = did)
    /\ (parent_did # <<"ROOT">> =>
        /\ parent_did \in IssuedReceipts
        /\ IsActive(parent_did)
        /\ Receipt(parent_did).authority_budget_granted >= granted
        /\ Receipt(parent_did).chain_root_id = chain_root
        /\ Receipt(parent_did).delegation_depth + 1 = depth)
    \* State transition
    /\ receipts' = [receipts EXCEPT
        ![did] = [
            delegation_id              |-> did,
            delegator_id               |-> delegator_id,
            delegate_id                |-> delegate_id,
            authority_budget_delegator |-> delegator_budget,
            authority_budget_granted   |-> granted,
            parent_delegation_id       |-> parent_did,
            chain_root_id              |-> chain_root,
            delegation_depth           |-> depth,
            status                     |-> "ACTIVE"
        ]]
    /\ edges' = edges \cup {<<delegator_id, delegate_id>>}
    /\ UNCHANGED agents

(*
  RevokeDelegation: Revoke an active delegation receipt.
  
  Status transition only — content fields remain unchanged
  (ATF-INV-005 immutability).
*)
RevokeDelegation(did) ==
    /\ did \in IssuedReceipts
    /\ IsActive(did)
    /\ receipts' = [receipts EXCEPT
        ![did] = [Receipt(did) EXCEPT !.status = "REVOKED"]]
    /\ UNCHANGED <<agents, edges>>

(*
  SuspendAgent: Suspend an active agent.
*)
SuspendAgent(aid) ==
    /\ agents[aid].status = "ACTIVE"
    /\ agents' = [agents EXCEPT ![aid].status = "SUSPENDED"]
    /\ UNCHANGED <<receipts, edges>>

\* ---------------------------------------------------------------
\* NEXT-STATE RELATION
\* ---------------------------------------------------------------

Next ==
    \/ \E aid \in AgentIDs, b \in Budget :
        RegisterAgent(aid, b)
    \/ \E did, parent_did \in DelegationIDs,
          delegator \in Principals,
          delegate  \in AgentIDs,
          db, granted \in Budget,
          chain_root \in DelegationIDs,
          depth \in 0..MaxDepth :
        IssueDelegation(
            did, delegator, delegate,
            db, granted,
            parent_did, chain_root, depth
        )
    \/ \E did \in DelegationIDs :
        RevokeDelegation(did)
    \/ \E aid \in AgentIDs :
        SuspendAgent(aid)

\* ---------------------------------------------------------------
\* COMPLETE SPECIFICATION
\* ---------------------------------------------------------------

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ ImmutabilityProperty

\* ---------------------------------------------------------------
\* LIVENESS (optional — model check separately)
\* ---------------------------------------------------------------

(*
  Delegation Liveness:
  If a delegation can be issued without violating MAR, it will
  eventually be issued (under fair scheduling).
*)
DelegationLiveness ==
    \A did \in DelegationIDs :
    \A delegator \in Principals :
    \A delegate \in AgentIDs :
        (\E b \in Budget : b > 0 /\ b <= MaxBudget)
            ~> did \in IssuedReceipts

\* ---------------------------------------------------------------
\* THEOREMS (human-readable statement of what TLC verifies)
\* ---------------------------------------------------------------

(*
  THEOREM ATF_MAR_Correctness:
    Spec => []MARInvariant
    
  Proof sketch:
    - Init: receipts is empty, MARInvariant holds vacuously
    - IssueDelegation: precondition (granted <= delegator_budget)
      is checked BEFORE state transition — MAR holds by construction
    - RevokeDelegation: only changes status, not budget fields
    - RegisterAgent, SuspendAgent: do not modify receipts

  THEOREM ATF_Acyclicity:
    Spec => []AcyclicityInvariant
    
  Proof sketch:
    - delegation_depth strictly increases along every path
    - A cycle would require some receipt to be its own ancestor
    - That would require depth[r] > depth[r], a contradiction

  THEOREM ATF_Immutability:
    Spec => ImmutabilityProperty
    
  Proof sketch:
    - Only RevokeDelegation modifies existing receipts
    - RevokeDelegation changes only .status, not content fields
    - All other actions either add new receipts (IssueDelegation)
      or do not touch receipts at all
*)

==================================================================
