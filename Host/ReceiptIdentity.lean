/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Provenance
import Host.Sha256

/-!
# D3 — the authority frontier: whose identity the receipt binds,
# and the caller no-go

**The frontier, in one sentence.** An authorization decision's `approval_identity`
names the APPROVAL TRUST ROOT the operator configured at boot — the channel
kind and (on the signed channel) the SHA-256 fingerprint of the approval
verifying key — and NOTHING derived from the mediated request can name the
caller, because on a stdio mediation topology every request byte is authored
by the very agent being gated.

This module is the honest twin of `registry_closed_algebra`: there we proved
what the gate DOES enforce; here we prove what the receipt DOES bind (D3-a)
and what it structurally CANNOT bind at this topology (D3-b).

## D3-a — what `approval_identity` is

The deployed value (`rust/src/main.rs:477-500`) is a function of the boot
trust plane ONLY:

* `channel` is the literal operator CLI flag `--channel`
  (`"file" | "interactive" | "ed25519"`, `main.rs:478-484`);
* `key_id` is `SHA-256(hex-decode(--approval-pubkey))` (`main.rs:179-182`),
  present iff the channel is `ed25519`.

It is a boot-scoped constant. The signed approval token gates only WHETHER
the `approval` block appears on a receipt (the consumed-approval guard,
`rust/src/authorization_decision.rs:196-204`); it never chooses the identity VALUE
(`authorization_decision.rs:259-269` reads the boot constant). The original D3
brief said "a function of the signed approval token and the trust root";
disk says trust root alone — the theorems below state that STRONGER fact:

* `receipt_identity_separated` — P-SEP at the receipt field: perturb the
  request arbitrarily (including any self-asserted `caller`/`agent`/`origin`
  field in the arguments) and the identity does not move;
* `receipt_identity_boot_constant` — within one boot, every receipt that
  carries the field carries the SAME value;
* `token_gates_presence_not_value` — whenever the field is present, its
  value is the boot constant `receiptIdentityOf`;
* `receipt_identity_names_trust_root` — on the signed channel the `key_id`
  is exactly the fingerprint of the boot approval root
  (`ApprovalState.publicKey`, the key approval tokens verify against);
* `keyId_only_on_signed_channel` — a key fingerprint appears ONLY on the
  `ed25519` channel. The `file` and `interactive` channels are DEV-ONLY and
  UNAUTHENTICATED (`rust/src/providers.rs:236-237`): their receipts name a
  channel kind, not a verified key. "The approver is authenticated" is a
  claim SCOPED to `--channel ed25519`.

## R-IDENT — the named seam (TCB, loud, NEVER an axiom)

Same idiom as `MintFaithful`/`A-MINT` (`Host/CapabilityAdequacy.lean`): the
Rust receipt assembler is not an object of this logic. `IdentityFaithful`
names the assumption "the identity Rust wrote equals `receiptIdentityOf`
of the boot state", consumed as an explicit hypothesis by
`faithful_identity_names_trust_root`. It is discharged operationally by the
differential test `rust/tests/receipt_identity.rs`, which drives the REAL
binary and checks the written bytes against this model (including the
mutation drill that plants a request-derived `caller_id` and watches the
test refuse it).

## D3-b — the caller no-go

`Host/Provenance.lean` refuted ONE spoofing assigner
(`spoofingAssigner_not_separated`). This module proves the UNIVERSAL no-go:
the topology fact is `StdioTotal` — one pipe, one child, no transport
credential (`main.rs:544-545`, `Stdio::piped()`), so ANY caller can emit ANY
byte string. Under that fact:

* `stdio_no_caller_authentication` — NO function of everything the host
  holds at dispatch time (trusted planes INCLUDED, request included) is a
  sound caller authenticator. Not "we chose not to bind the caller":
  no such binding exists at this topology.
* `forgeable_echo` — the same fact stated positively: whatever value one
  caller can induce in ANY request-derived field, every other caller can
  induce byte-identically. A receipt field copied from the request carries
  zero authentication weight — it is an echo, not an identity.
* `credential_excludes_totality` — a transport credential (a relation
  binding who-can-send-what) is INCOMPATIBLE with `StdioTotal`: the exact
  obstruction, named.
* `caller_authenticator_satisfiable` — the no-go is not vacuous: on a
  topology whose send relation IS credential-constrained, an authenticator
  exists (`credentialed_topology_authenticates`). This is the V2.1 escape
  hatch as a theorem: per-caller transport credentials (peer creds, an
  authenticated gateway, per-caller keys — the G1 caller/principal axis)
  are exactly what make a caller binding possible. NOTE the witness models
  a HYPOTHETICAL credentialed transport; today's stdio host satisfies
  `StdioTotal`, not the credential constraint.

An evaluator asking "which agent made this call?" gets a proof-backed
answer: cannot be known at this topology; the receipt binds the approval
trust root instead, and the no-go names precisely what a V2.1 topology must
add before a `caller_id` field would mean anything.
-/

namespace Host.ReceiptIdentity

open SealV2 (ApprovalState)
open Host.Provenance (Principal CallInputs)

/-! ## D3-a — the receipt identity model -/

/-- The three deployed approval channels — the operator's `--channel` flag
    (`main.rs:478-484`). Only `ed25519` is a signed, authenticated channel;
    `file` and `interactive` are DEV-ONLY and UNAUTHENTICATED
    (`providers.rs:236-237`). -/
inductive Channel where
  | file
  | interactive
  | ed25519
  deriving Repr, DecidableEq

/-- The wire name of a channel — the exact string the receipt carries. -/
def Channel.name : Channel → String
  | .file => "file"
  | .interactive => "interactive"
  | .ed25519 => "ed25519"

/-- Lean twin of the Rust `ApprovalIdentity { channel, key_id }`
    (`rust/src/authorization_decision.rs:21-25`). -/
structure ApprovalIdentity where
  channel : Channel
  keyId : Option String
  deriving Repr, DecidableEq

/-- The key fingerprint the receipt names: SHA-256 over the HEX-DECODED
    approval verifying key, hex-encoded — byte-for-byte the Rust
    `approval_key_id` (`main.rs:179-182`). `none` iff the hex is malformed,
    a state the deployed host refuses at startup; the model records absence
    rather than fabricating a value (the receipt honesty rule). -/
def keyFingerprint (publicKeyHex : String) : Option String :=
  (SealV2.hexDecode? publicKeyHex).map Host.Sha256.sha256Hex

/-- The receipt identity VALUE: a function of the boot trust plane only —
    the channel flag and, on the signed channel, the fingerprint of the
    approval root the boot state carries (`ApprovalState.publicKey`, the key
    approval tokens are verified against). No request input exists to read. -/
def receiptIdentityOf (channel : Channel) (boot : ApprovalState) : ApprovalIdentity :=
  { channel := channel
    keyId := match channel with
      | .ed25519 => keyFingerprint boot.publicKey
      | _ => none }

/-- The receipt identity FIELD, presence included: the `approval` block
    appears iff an approval was consumed (`authorization_decision.rs:196-204`) —
    a fact of the TRUSTED planes (boot state + gathered evidence), here any
    predicate of exactly those planes. The value, when present, is the boot
    constant. -/
def receiptIdentityField (channel : Channel)
    (consumedOf : ApprovalState → Kernels.SafetyEvidence → Bool)
    (c : CallInputs) : Option ApprovalIdentity :=
  if consumedOf c.boot c.perCall then some (receiptIdentityOf channel c.boot) else none

/-- **D3-a, the request-independence half (P-SEP at the receipt field).**
    Perturb the request arbitrarily — including any self-asserted
    `caller`/`agent`/`origin` field — and the receipt's identity field
    (presence AND value) does not move. Same obligation shape as
    `Host.Provenance.ProvenanceSeparated`, at codomain
    `Option ApprovalIdentity`. -/
theorem receipt_identity_separated (channel : Channel)
    (consumedOf : ApprovalState → Kernels.SafetyEvidence → Bool)
    (boot : ApprovalState) (perCall : Kernels.SafetyEvidence)
    (req req' : Host.CanonicalAction) :
    receiptIdentityField channel consumedOf ⟨boot, perCall, req⟩
      = receiptIdentityField channel consumedOf ⟨boot, perCall, req'⟩ :=
  rfl

/-- The `key_id` projection is a `Host.Provenance.Assigner` and satisfies
    the landed P-SEP obligation — the receipt brick rides the provenance
    brick, it does not re-invent it. -/
def approvalKeyIdAssigner (channel : Channel) : Host.Provenance.Assigner :=
  fun c => ((receiptIdentityOf channel c.boot).keyId).getD ""

theorem approvalKeyIdAssigner_separated (channel : Channel) :
    Host.Provenance.ProvenanceSeparated (approvalKeyIdAssigner channel) :=
  Host.Provenance.factored_separated
    fun boot _ => ((receiptIdentityOf channel boot).keyId).getD ""

/-- **The token gates PRESENCE, never VALUE.** Whenever the field is
    present, its value is the boot constant `receiptIdentityOf` — the
    consumed approval decided that the block appears, not what it says. -/
theorem token_gates_presence_not_value (channel : Channel)
    (consumedOf : ApprovalState → Kernels.SafetyEvidence → Bool)
    (c : CallInputs) (id : ApprovalIdentity)
    (h : receiptIdentityField channel consumedOf c = some id) :
    id = receiptIdentityOf channel c.boot := by
  unfold receiptIdentityField at h
  split at h <;> simp_all

/-- **D3-a, the boot-constant half — STRONGER than the brief asked.** The
    original D3-a spec said the identity is "a function of the signed
    approval token and the trust root". Disk says trust root ALONE: within
    one boot, any two receipts that carry the field — different requests,
    different evidence, different tokens — carry the SAME identity. -/
theorem receipt_identity_boot_constant (channel : Channel)
    (consumedOf consumedOf' : ApprovalState → Kernels.SafetyEvidence → Bool)
    (boot : ApprovalState) (perCall perCall' : Kernels.SafetyEvidence)
    (req req' : Host.CanonicalAction) (id id' : ApprovalIdentity)
    (h : receiptIdentityField channel consumedOf ⟨boot, perCall, req⟩ = some id)
    (h' : receiptIdentityField channel consumedOf' ⟨boot, perCall', req'⟩ = some id') :
    id = id' := by
  rw [token_gates_presence_not_value channel consumedOf _ id h,
      token_gates_presence_not_value channel consumedOf' _ id' h']

/-- **What the receipt names on the signed channel: the approval trust
    root.** The `key_id` is exactly the fingerprint of the boot approval
    root — the verifying key approval tokens are checked against
    (`providers.rs:313`), the second trust root of the two-root shape
    (`Host/Config.lean:122-123`). -/
theorem receipt_identity_names_trust_root (boot : ApprovalState) :
    (receiptIdentityOf .ed25519 boot).keyId = keyFingerprint boot.publicKey :=
  rfl

/-- **The authentication claim is channel-scoped.** A key fingerprint
    appears ONLY on the `ed25519` channel; the DEV-ONLY `file` and
    `interactive` channels name a channel kind and no key — their receipts
    make no authentication claim, and the docs must not either. -/
theorem keyId_only_on_signed_channel (channel : Channel) (boot : ApprovalState)
    (h : (receiptIdentityOf channel boot).keyId ≠ none) :
    channel = .ed25519 := by
  cases channel <;> simp_all [receiptIdentityOf]

/-- **R-IDENT (TCB seam, made visible).** The identity the Rust assembler
    wrote (`authorization_decision.rs:259-269`) equals the model value for the
    boot state — same idiom as `Host.CapabilityAdequacy.MintFaithful`:
    an explicit hypothesis, deliberately never a Lean axiom, discharged
    operationally by `rust/tests/receipt_identity.rs` against the real
    binary. -/
def IdentityFaithful (written : ApprovalIdentity) (channel : Channel)
    (boot : ApprovalState) : Prop :=
  written = receiptIdentityOf channel boot

/-- Through the R-IDENT seam: IF Rust wrote faithfully, the written
    `key_id` on the signed channel is the trust-root fingerprint — an
    authentication claim about the APPROVER, derived from config, never
    from the request. -/
theorem faithful_identity_names_trust_root (written : ApprovalIdentity)
    (boot : ApprovalState)
    (hfaith : IdentityFaithful written .ed25519 boot) :
    written.keyId = keyFingerprint boot.publicKey := by
  rw [IdentityFaithful] at hfaith
  subst hfaith
  rfl

/-! ## D3-b — the caller no-go -/

/-- A send-capability relation: which principals can put which requests on
    the mediated pipe. The topology is encoded HERE and nowhere else. -/
abbrev Sends := Principal → Host.CanonicalAction → Prop

/-- **The stdio topology fact.** One pipe, one child, no transport
    credential (`main.rs:544-545`): EVERY caller can emit EVERY byte
    string. This is what "the request is adversary-controlled" means,
    stated as the send relation being total. -/
def StdioTotal (sends : Sends) : Prop :=
  ∀ c a, sends c a

/-- A sound caller authenticator: a function of EVERYTHING the host holds
    at dispatch time (trusted planes included) that names the sender, for
    every sender the topology admits. This is the property a receipt-borne
    `caller_id` would need for authentication weight. -/
def CallerAuthenticator (sends : Sends) (f : CallInputs → Principal) : Prop :=
  ∀ (boot : ApprovalState) (perCall : Kernels.SafetyEvidence)
    (c : Principal) (req : Host.CanonicalAction),
    sends c req → f ⟨boot, perCall, req⟩ = c

private def anyBoot : ApprovalState :=
  { session := "s", now := 0, publicKey := "", manifestDigest := "",
    tools := [], approvals := [] }

private def anyEv : Kernels.SafetyEvidence :=
  { now := 0, approvalEvents := [] }

private def anyReq : Host.CanonicalAction :=
  { tool := "t", argsJson := .null, ast? := none, raw := "", requestId := .null }

/-- **The no-go, universal.** On a topology where the send relation is
    total — stdio — NO function of the dispatch-time inputs is a sound
    caller authenticator: two distinct callers can present the host with
    bit-identical worlds, and one value cannot name both. Not a scoping
    choice; a structural impossibility. -/
theorem stdio_no_caller_authentication (sends : Sends)
    (htotal : StdioTotal sends) (f : CallInputs → Principal) :
    ¬ CallerAuthenticator sends f := by
  intro h
  have h1 := h anyBoot anyEv "alice" anyReq (htotal "alice" anyReq)
  have h2 := h anyBoot anyEv "mallory" anyReq (htotal "mallory" anyReq)
  rw [h1] at h2
  simp at h2

/-- **Zero authentication weight, stated positively.** Under totality,
    whatever value one caller can induce in ANY request-derived field —
    a `caller_id`, an `agent` tag, an origin string — every other caller
    can induce byte-identically. An echo, not an identity. -/
theorem forgeable_echo {α : Type} (sends : Sends) (htotal : StdioTotal sends)
    (g : Host.CanonicalAction → α) (c c' : Principal)
    (req : Host.CanonicalAction) (_ : sends c req) :
    ∃ req', sends c' req' ∧ g req' = g req :=
  ⟨req, htotal c' req, rfl⟩

/-- **The exact obstruction, named.** A transport credential — a witness
    binding who-can-send-what tightly enough that the request determines
    its sender — is INCOMPATIBLE with `StdioTotal`. Adding that credential
    is therefore a TOPOLOGY change (the V2.1 G1 axis), not a receipt field. -/
theorem credential_excludes_totality
    (credential : Host.CanonicalAction → Option Principal) (sends : Sends)
    (hbind : ∀ c req, sends c req → credential req = some c)
    (htotal : StdioTotal sends) : False := by
  have h1 := hbind "alice" anyReq (htotal "alice" anyReq)
  have h2 := hbind "mallory" anyReq (htotal "mallory" anyReq)
  rw [h1] at h2
  simp at h2

/-- **The escape hatch as a theorem.** On a topology whose send relation
    IS credential-constrained, an authenticator exists: read the
    credential. Per-caller transport credentials (peer creds, an
    authenticated gateway, per-caller approval keys) are exactly what make
    a caller binding possible — the G1 caller/principal axis deferred to
    V2.1. -/
theorem credentialed_topology_authenticates
    (credential : Host.CanonicalAction → Option Principal) (sends : Sends)
    (hbind : ∀ c req, sends c req → credential req = some c) :
    ∃ f, CallerAuthenticator sends f := by
  refine ⟨fun c => (credential c.request).getD "", ?_⟩
  intro boot perCall c req hsend
  simp [hbind c req hsend]

/-- **The no-go is not vacuous.** `CallerAuthenticator` is satisfiable — on
    a HYPOTHETICAL credentialed topology where a caller can only emit
    requests stamped with its own identity (the stamp being unforgeable is
    precisely what a transport credential provides, and precisely what
    stdio does not: `credential_excludes_totality`), the stamp reader
    authenticates. The definition has teeth; today's topology is what
    fails it. -/
theorem caller_authenticator_satisfiable :
    ∃ (sends : Sends) (f : CallInputs → Principal),
      (∃ c req, sends c req) ∧ CallerAuthenticator sends f := by
  refine ⟨fun c req => req.raw = c, fun ci => ci.request.raw,
    ⟨"alice", { anyReq with raw := "alice" }, rfl⟩, ?_⟩
  intro boot perCall c req hsend
  simpa using hsend

/-! ## Cross-language conformance pins (build-gated compiled evaluation)

The same key/fingerprint pair is pinned in `rust/tests/receipt_identity.rs`
against a receipt written by the REAL binary: the test's approval signing
key (seed `[9u8; 32]`) has this verifying key, and the receipt's `key_id`
must be this fingerprint. Lean's `keyFingerprint` and Rust's
`approval_key_id` agreeing on the same bytes is the operational discharge
of the R-IDENT seam. -/

/-- info: true -/
#guard_msgs in #eval
  keyFingerprint "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
    == some "dbc298251c51321b7266e78d1c151c2b62aff8cb95b293096d3463018544face"

-- Malformed hex names NOTHING — absence, never a fabricated value.
/-- info: true -/
#guard_msgs in #eval keyFingerprint "not-hex" == none

end Host.ReceiptIdentity

/-! ## Axiom pins — enforced at module build -/

/-- info: 'Host.ReceiptIdentity.receiptIdentityOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.receiptIdentityOf
/-- info: 'Host.ReceiptIdentity.receiptIdentityField' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.receiptIdentityField
/-- info: 'Host.ReceiptIdentity.receipt_identity_separated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.receipt_identity_separated
/-- info: 'Host.ReceiptIdentity.approvalKeyIdAssigner_separated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.approvalKeyIdAssigner_separated
/-- info: 'Host.ReceiptIdentity.receipt_identity_boot_constant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.receipt_identity_boot_constant
/-- info: 'Host.ReceiptIdentity.token_gates_presence_not_value' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.token_gates_presence_not_value
/-- info: 'Host.ReceiptIdentity.receipt_identity_names_trust_root' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.receipt_identity_names_trust_root
/-- info: 'Host.ReceiptIdentity.keyId_only_on_signed_channel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.keyId_only_on_signed_channel
/-- info: 'Host.ReceiptIdentity.IdentityFaithful' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.IdentityFaithful
/-- info: 'Host.ReceiptIdentity.faithful_identity_names_trust_root' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.faithful_identity_names_trust_root
/-- info: 'Host.ReceiptIdentity.StdioTotal' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.StdioTotal
/-- info: 'Host.ReceiptIdentity.CallerAuthenticator' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.CallerAuthenticator
/-- info: 'Host.ReceiptIdentity.stdio_no_caller_authentication' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.stdio_no_caller_authentication
/-- info: 'Host.ReceiptIdentity.forgeable_echo' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.forgeable_echo
/-- info: 'Host.ReceiptIdentity.credential_excludes_totality' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.credential_excludes_totality
/-- info: 'Host.ReceiptIdentity.credentialed_topology_authenticates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.credentialed_topology_authenticates
/-- info: 'Host.ReceiptIdentity.caller_authenticator_satisfiable' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ReceiptIdentity.caller_authenticator_satisfiable
