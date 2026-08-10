/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Action
import Kernels.Safety
import SealV2.Validation

/-!
# Provenance separation — the principal never comes from the request

**Claim shape (exact).** This brick proves PROVENANCE SEPARATION, not
cryptographic unforgeability: a call's `principal` may be populated only from
a trusted channel and NEVER from the untrusted request (`act.argsJson`, or any
other wire-derived field). It is the same two-trust-root shape as
`Host.verifyConfigSignature` (Host/Config.lean): the config signing key is a
STARTUP trust root, approval-token keys are the PER-CALL trust root, and the
client's wire bytes are neither.

Formally: a principal assigner is any function of everything the host holds at
dispatch time, split by provenance (`CallInputs`); the obligation
`ProvenanceSeparated` demands the assignment be invariant under ANY change of
the request. Compliance is by factoring (`factored_separated` — an assigner
that types through the trusted planes cannot read the request), and the
obligation has teeth: the spoofing assigner that reads a principal out of
`argsJson` is expressible in the seam type and REFUTED
(`spoofingAssigner_not_separated`).

**Why not unforgeability.** `Host.CanonicalAction` carries `tool`, `argsJson`,
`ast?`, `raw`, `requestId` — all derived from the wire line; MCP stdio has no
client authentication, so there is NO transport credential to bind a caller
identity against. An unforgeability theorem ("the principal is the caller")
has no seam to attach to today; adding that seam is a BUILD item, not a proof.
What this brick guarantees is exactly: whatever the principal is, the client's
request bytes cannot choose it.

**Relation to `SealV2.SessionId` (relate, don't duplicate).**
`ApprovalState.session` is set ONCE at server boot from the signed config
(`Ffi.initSession`), so `session` is a boot-scoped principal, NOT a caller
binding: `bootAssigner` assigns the same principal to every call of a server
instance (`boot_principal_constant`). The existing bricks already prove the
session plane sound: cross-session replay isolation
(`Host.ReplayIsolation.replay_isolation_trace`) and stateful non-interference
(`Host.StatefulNI.stateful_noninterference_trace`) filter the durable store on
`ReplayNamespace.session`. `replayNamespace_trusted_plane` below shows that
plane is populated from `ApprovalState` only — so a future per-call
`principal` field with a trusted source slots into exactly that plane and the
isolation theorems transport unchanged.
-/

namespace Host.Provenance

open SealV2 (ApprovalState SessionId Target ReplayNamespace replayNamespace)

/-- A principal names WHO a mediated call is attributed to. Today the only
    inhabitants with a trusted source are boot-plane identities (`session`,
    the approval root `publicKey`); a per-caller principal awaits a transport
    credential seam (build item — see the module docstring). -/
abbrev Principal := String

/-- Everything a principal assigner could read at dispatch time, split by
    provenance — the two trust roots of `Host.verifyConfigSignature` plus the
    untrusted request:

    * `boot` — the signed-config trust plane, fixed at server boot
      (`session`, the approval root `publicKey`, `policyVersion`, …);
    * `perCall` — the host-side gathered evidence (control file approvals,
      clock): the per-call trusted channel, authenticated by approval-token
      keys, never by the client;
    * `request` — the UNTRUSTED wire request (the V1 `argsJson` view, the raw
      line, the canonical `ast?`). MCP stdio attaches no client identity to
      it. -/
structure CallInputs where
  /-- The signed-config trust plane, fixed at server boot. -/
  boot : ApprovalState
  /-- Host-side gathered evidence (approvals, clock) — the per-call trusted
      channel. -/
  perCall : Kernels.SafetyEvidence
  /-- The UNTRUSTED wire request; stdio attaches no client identity to it. -/
  request : CanonicalAction

/-- A principal assigner: any function of the full dispatch-time inputs. The
    seam type deliberately ADMITS request-reading assigners — the obligation
    below is what rules them out, and `spoofingAssigner_not_separated` shows
    it really does. -/
abbrev Assigner := CallInputs → Principal

/-- **P-SEP, the provenance-separation obligation.** The assigned principal is
    invariant under ANY change of the request: same trusted planes, same
    principal. In particular the principal can never be populated from
    `act.argsJson` — the client's bytes cannot choose who they are. -/
def ProvenanceSeparated (assign : Assigner) : Prop :=
  ∀ (boot : ApprovalState) (perCall : Kernels.SafetyEvidence)
    (req req' : CanonicalAction),
    assign ⟨boot, perCall, req⟩ = assign ⟨boot, perCall, req'⟩

/-- **Compliance is a typing discipline.** ANY assigner that factors through
    the trusted planes — boot state and per-call gathered evidence — is
    provenance-separated: it never received the request to read. This is the
    positive half for every trusted-channel assigner at once. -/
theorem factored_separated (f : ApprovalState → Kernels.SafetyEvidence → Principal) :
    ProvenanceSeparated (fun c => f c.boot c.perCall) :=
  fun _ _ _ _ => rfl

/-- The boot-plane assigner: the session identity fixed at boot from the
    signed config. Trusted — and honestly scoped: boot-wide, not per-caller
    (`boot_principal_constant`). -/
def bootAssigner : Assigner := fun c => c.boot.session

theorem bootAssigner_separated : ProvenanceSeparated bootAssigner :=
  factored_separated fun boot _ => boot.session

/-- The approval-root assigner: the public key the per-call approval channel
    is verified against — the second trust root of the two-root shape. -/
def approvalRootAssigner : Assigner := fun c => c.boot.publicKey

theorem approvalRootAssigner_separated : ProvenanceSeparated approvalRootAssigner :=
  factored_separated fun boot _ => boot.publicKey

/-- **`session` is NOT a caller binding.** The boot-plane principal is
    CONSTANT across every call of a server instance — set once at boot, it
    cannot distinguish two callers of the same instance. Distinguishing
    callers requires a transport credential that `CanonicalAction` does not
    carry; that seam is a build item, not a theorem. -/
theorem boot_principal_constant (boot : ApprovalState)
    (perCall perCall' : Kernels.SafetyEvidence) (req req' : CanonicalAction) :
    bootAssigner ⟨boot, perCall, req⟩ = bootAssigner ⟨boot, perCall', req'⟩ :=
  rfl

/-- The spoofing assigner: reads the principal out of the request's
    `argsJson` — exactly what P-SEP forbids. Expressible in the seam type
    (this stands for ANY `argsJson` extractor, including
    `Seal.JsonUtil.atPath`-based ones — same provenance plane). -/
def spoofingAssigner : Assigner := fun c =>
  match c.request.argsJson with
  | .str p => p
  | _ => ""

private def spoofedReq (p : String) : CanonicalAction :=
  { tool := "t", argsJson := .str p, ast? := none, raw := "", requestId := .null }

private def anyBoot : ApprovalState :=
  { session := "s", now := 0, publicKey := "", manifestDigest := "",
    tools := [], approvals := [] }

/-- **The obligation has teeth.** The spoofing assigner is refuted: two
    requests differing only in `argsJson` yield two different principals, so
    no argsJson-reading assigner can satisfy P-SEP. A client-chosen principal
    is not a corner case the obligation misses — it is the exact thing it
    excludes. -/
theorem spoofingAssigner_not_separated : ¬ ProvenanceSeparated spoofingAssigner := by
  intro h
  have hcontra := h anyBoot { now := 0, approvalEvents := [] }
    (spoofedReq "alice") (spoofedReq "mallory")
  simp [spoofingAssigner, spoofedReq] at hcontra

/-- **The provenance plane of `ReplayNamespace`.** Its `session`, `publicKey`
    and `policyVersion` fields are drawn from `ApprovalState` ONLY — the boot
    and approval trust planes — and are invariant in the target: the request
    cannot steer them. (`targetKey` is derived from the approval-signed
    target, not from the raw request — a signed channel, but a different
    one.) The cross-session isolation and stateful-NI bricks filter the
    durable store on exactly this plane, so a future trusted `principal`
    field composes with them by construction. -/
theorem replayNamespace_trusted_plane (st : ApprovalState) (t t' : Target) :
    (replayNamespace st t).session = st.session ∧
    (replayNamespace st t).publicKey = st.publicKey ∧
    (replayNamespace st t).policyVersion = st.policyVersion ∧
    (replayNamespace st t).session = (replayNamespace st t').session ∧
    (replayNamespace st t).publicKey = (replayNamespace st t').publicKey ∧
    (replayNamespace st t).policyVersion = (replayNamespace st t').policyVersion :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

end Host.Provenance

/-! ## Axiom pins — enforced at module build -/

/-- info: 'Host.Provenance.ProvenanceSeparated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Provenance.ProvenanceSeparated
/-- info: 'Host.Provenance.factored_separated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Provenance.factored_separated
/-- info: 'Host.Provenance.bootAssigner_separated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Provenance.bootAssigner_separated
/-- info: 'Host.Provenance.approvalRootAssigner_separated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Provenance.approvalRootAssigner_separated
/-- info: 'Host.Provenance.boot_principal_constant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Provenance.boot_principal_constant
/--
info: 'Host.Provenance.spoofingAssigner_not_separated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Provenance.spoofingAssigner_not_separated
/-- info: 'Host.Provenance.replayNamespace_trusted_plane' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Provenance.replayNamespace_trusted_plane
