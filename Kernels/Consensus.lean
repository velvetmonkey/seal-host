/- SPDX-License-Identifier: Apache-2.0 -/

import Consensus.Checker
import Seal.Hash
import Host.Kernel

namespace Kernels

open Consensus.Checker

/-- Config section for kernel C: the trusted roster (membership-as-trusted-
    config — the gate brings its own guest list, never read from the agent),
    the votes source file, and the tools that demand a ratified quorum. -/
structure ConsensusConfig where
  roster : List Nat
  votesFile : System.FilePath
  highStakes : List String
  deriving Repr

/-- Construct the candidate certificate for an action from the gathered
    votes: the claimed value is the tool name (G3 binding granularity —
    quorum ratifies "this tool may run"; finer per-target binding is a later
    upgrade), the voters are the acceptors whose vote matches. The
    construction is host-side and untrusted: `validB` re-checks every
    conjunct (no duplicates, membership, strict majority, every voter's
    recorded vote matches), so a bad construction can only fail, never
    smuggle an allow. -/
def certFor (votes : Votes) (value : String) : Cert :=
  { value
    voters := (votes.filter (fun v => v.2 == value)).map (·.1) |>.eraseDups }

/-- The pure decision core of kernel C: allow iff the proved checker accepts
    the certificate against the trusted roster. `Consensus.Checker.agreement`
    is the no-conflicting-agreement invariant on exactly this acceptance. -/
def quorumAccepts (roster : List Nat) (votes : Votes) (value : String) : Bool :=
  validB roster votes (certFor votes value)

/-- Kernel C — the Consensus Seal. Gates only the configured high-stakes
    tools; each such call needs a ratified strict-majority quorum from the
    trusted roster, not one signer. Stateless in G3 (roster changes = gated
    epoch bump, deferred to the reconfig story). -/
def consensusKernel : Host.Kernel where
  name := "consensus"
  Config := ConsensusConfig
  Evidence := Votes
  State := Unit
  init := ()
  gates := fun cfg act => cfg.highStakes.contains act.tool
  ingest := fun _ st => st
  decide := fun act cfg votes st =>
    let cert := certFor votes act.tool
    if quorumAccepts cfg.roster votes act.tool then
      let reason := s!"quorum ok ({cert.voters.length}/{cfg.roster.length}): {act.tool}"
      ({ kernel := "consensus", kind := .allow, reason,
         certHash := Seal.auditHashParts ["consensus", "allow", reason] }, st)
    else
      let reason := s!"quorum missing ({cert.voters.length}/{cfg.roster.length}): {act.tool}"
      ({ kernel := "consensus", kind := .deny, reason,
         certHash := Seal.auditHashParts ["consensus", "deny", reason] }, st)

/-- Bridge for the composition theorem: kernel C's verdict is allow exactly
    when the proved checker accepts the certificate. -/
theorem consensus_verdict_allow_iff
    (act : Host.CanonicalAction) (cfg : ConsensusConfig)
    (votes : Votes) (st : Unit) :
    (consensusKernel.decide act cfg votes st).1.kind = .allow ↔
      quorumAccepts cfg.roster votes act.tool = true := by
  show (if quorumAccepts cfg.roster votes act.tool then _ else _ : Host.Verdict × Unit).1.kind = _ ↔ _
  by_cases h : quorumAccepts cfg.roster votes act.tool <;> simp [h]

end Kernels
