/- SPDX-License-Identifier: Apache-2.0 -/

import SealV2.Crypto
import Host.Provenance

/-!
# Authenticated principal — the V2.1 signed-envelope credential (Route 2)

**Claim shape (exact, scoped).** This module gives the host an
*authenticated principal when a signed envelope verifies* — and NOTHING
stronger. Caller authentication on bare stdio remains impossible and remains
proven impossible (`Host.ReceiptIdentity.stdio_no_caller_authentication`);
`verifyEnvelope` below is a PARTIAL authenticator (`Option`), never a
`CallerAuthenticator` in the `ReceiptIdentity.CallerAuthenticator` sense
(which must name *every* sender). The pipe stays `StdioTotal`; what changes is
that a request carrying a verifying envelope determines its sender through
cryptography, not through the pipe — the exact escape hatch already proven as
`Host.ReceiptIdentity.credentialed_topology_authenticates`, instantiated here
at the enveloped-request type (`envelope_topology_authenticates`), with its
totality-exclusion twin (`envelope_constrained_excludes_totality`) keeping the
no-go loud.

**Where the principal may come from.** ONLY from `verifyEnvelope`: a
registered Ed25519 key (the registry rides inside the *signed* TrustedConfig —
out-of-band trust, never a request field) verifying a signature over the exact
judged line. `AuthenticatedPrincipal` has a private constructor; the sole
producer in the codebase is `verifyEnvelope`. Request-derived construction is
unrepresentable outside this module (pinned by a `#guard_msgs (error)` check
in `Test/DxSurface.lean`). Un-constructibility is module discipline — an
auditable engineering invariant, not a metatheorem.

**Trusted, named, never proven (the crypto TCB at this seam):**
* `SealV2.ed25519Verify` extern faithfulness (the `@[extern]` leaf computes
  real Ed25519) — same seam class as `Host.verifyConfigSignature`, now at a
  request-path call site.
* Ed25519 existential unforgeability — "a signature that verifies was made
  with the registered key". The theorems below say the principal flows *only
  through* `verifyEnvelope`; they cannot and do not say forgery is impossible.
* Envelope freshness (nonce replay window) — a Rust-side seam, A3 pattern,
  discharged by tests, not proofs.
* Key custody, rotation-by-re-sign, revocation-by-epoch-bump. There is no
  online revocation: a compromised principal key stays valid until the
  operator re-signs the config.

What IS machine-checked: the presence/value split
(`envelope_gates_presence_not_value`, `principal_value_key_constant` — request
bytes gate only WHETHER a principal appears, never WHICH), fail-closed
behaviour on unregistered keys, registry closure of every produced id, and the
instantiation link to the credentialed-topology escape hatch.
-/

namespace Host

/-- One registered principal: the operator-pinned (id, Ed25519 verifying-key
    hex) pair. The registry is carried INSIDE the signed `TrustedConfig`
    (`principals` bundle section) — the key→principal binding is out-of-band
    trust established at config-signing time, never a request field. -/
structure PrincipalKey where
  id : String
  pubkey : String
  deriving Repr, BEq

abbrev PrincipalRegistry := List PrincipalKey

/-- Raw request-envelope fields exactly as marshalled off the step-input JSON.
    Rust passes them through UNINTERPRETED (never a principal string); only
    `verifyEnvelope` gives them meaning. -/
structure Envelope where
  keyId : String
  sigHex : String
  nonceHex : String
  issuedAt : Nat
  deriving Repr, BEq

/-- 8-byte big-endian encoding of a (u64-ranged) natural — fixed-width so the
    signed message framing is injective without separators. -/
def u64be (n : Nat) : ByteArray :=
  ByteArray.mk #[
    UInt8.ofNat (n >>> 56), UInt8.ofNat (n >>> 48), UInt8.ofNat (n >>> 40),
    UInt8.ofNat (n >>> 32), UInt8.ofNat (n >>> 24), UInt8.ofNat (n >>> 16),
    UInt8.ofNat (n >>> 8), UInt8.ofNat n]

/-- Domain-separation tag for request envelopes. Distinct from the config
    envelope (which signs raw payload bytes, `Host.verifyConfigSignature`) so
    a signature can never be replayed across the two planes. The trailing NUL
    terminates the tag unambiguously. -/
def envelopeTag : String := "seal/v2.1/principal-envelope\x00"

/-- **The canonical signed message** — the cross-language contract, pinned by
    golden vectors here and byte-twinned in
    `rust/tests/principal_identity.rs`:

        tag ‖ nonce (exactly 32 raw bytes) ‖ u64be(issuedAt) ‖ line-bytes

    All pre-`line` fields are fixed-width (tag constant, nonce 32 — enforced
    by `verifyEnvelope` —, issuedAt 8), so the encoding is injective in
    (nonce, issuedAt, line): no framing ambiguity, no separate digest needed
    (Ed25519 hashes internally). `line` is the EXACT judged line — the same
    bytes `classifyLine` routes and `auditLine`'s `request_sha256` commits to. -/
def envelopeMessage (nonce : ByteArray) (issuedAt : Nat) (line : String) :
    ByteArray :=
  envelopeTag.toUTF8 ++ nonce ++ u64be issuedAt ++ line.toUTF8

/-- THE authenticated principal. Private constructor: the only producer in the
    codebase is `verifyEnvelope`. The `id` PROJECTION is public — observation
    is free, construction is not. -/
structure AuthenticatedPrincipal where
  private mk ::
  id : String
  deriving Repr, BEq, DecidableEq

/-- Two authenticated principals with the same id are equal (exported because
    the constructor is private, so `cases` is unavailable outside this
    module). -/
theorem AuthenticatedPrincipal.ext_id {p q : AuthenticatedPrincipal}
    (h : p.id = q.id) : p = q := by
  cases p; cases q; simpa using h

/-- **The sole smart constructor.** Pure; the same extern seam as
    `Host.verifyConfigSignature`, at a new (request-path) call site.
    Fail-closed `none` on: unregistered keyId, malformed hex (key, sig, or
    nonce), wrong key or nonce length, or verification failure.
    `some ⟨k.id⟩` ONLY when the registered key verifies the signature over
    `envelopeMessage nonce issuedAt line` — the exact judged line.

    The extern result is only ever cased on as an opaque `Bool`; no theorem
    in this module depends on what it computes (that is the crypto TCB). -/
def verifyEnvelope (reg : PrincipalRegistry) (env : Envelope) (line : String) :
    Option AuthenticatedPrincipal :=
  match reg.find? (fun k => k.id == env.keyId) with
  | none => none
  | some k =>
      match SealV2.hexDecode? k.pubkey, SealV2.hexDecode? env.sigHex,
            SealV2.hexDecode? env.nonceHex with
      | some pk, some sig, some nonce =>
          if pk.size == 32 && nonce.size == 32
              && SealV2.ed25519Verify pk (envelopeMessage nonce env.issuedAt line) sig
          then some ⟨k.id⟩ else none
      | _, _, _ => none

/-! ## The presence/value split — `principal_from_auth_not_request`

The idiom of `Host.ReceiptIdentity.token_gates_presence_not_value`: request
bytes decide only WHETHER a principal appears; the config registry (+ the
keyId lookup) decides WHICH. What these theorems can never say: "an attacker
cannot set the principal" — that forged signatures do not pass `verify` is the
crypto assumption (TCB, module docstring). The theorems say the principal
flows only through `verifyEnvelope`. -/

/-- **The envelope gates PRESENCE, never VALUE.** Whenever `verifyEnvelope`
    returns `some p`, `p.id` is the id of the registry entry the keyId
    selected — a function of the config registry and the keyId lookup ONLY.
    The line, signature and nonce (all request bytes) decide only whether
    `some` appears. -/
theorem envelope_gates_presence_not_value (reg : PrincipalRegistry)
    (env : Envelope) (line : String) (p : AuthenticatedPrincipal)
    (h : verifyEnvelope reg env line = some p) :
    ∃ k, reg.find? (fun k => k.id == env.keyId) = some k ∧ p.id = k.id := by
  unfold verifyEnvelope at h
  split at h
  · cases h
  · next k hf =>
      refine ⟨k, hf, ?_⟩
      split at h
      · split at h
        · injection h with h
          subst h
          rfl
        · cases h
      all_goals cases h

/-- **Value is a key constant.** Any two successful verifications under the
    same keyId — different lines, different signatures, different nonces,
    different timestamps — name the SAME principal. The per-key analogue of
    `receipt_identity_boot_constant`. -/
theorem principal_value_key_constant (reg : PrincipalRegistry)
    (env env' : Envelope) (line line' : String)
    (p p' : AuthenticatedPrincipal) (hk : env.keyId = env'.keyId)
    (h : verifyEnvelope reg env line = some p)
    (h' : verifyEnvelope reg env' line' = some p') : p = p' := by
  obtain ⟨k, hf, hid⟩ := envelope_gates_presence_not_value reg env line p h
  obtain ⟨k', hf', hid'⟩ := envelope_gates_presence_not_value reg env' line' p' h'
  rw [hk] at hf
  rw [hf] at hf'
  injection hf' with hkk
  exact AuthenticatedPrincipal.ext_id (by rw [hid, hid', hkk])

/-- Fail-closed: an unregistered keyId yields `none` — no request can name a
    principal outside the signed registry. -/
theorem verifyEnvelope_none_of_unregistered (reg : PrincipalRegistry)
    (env : Envelope) (line : String)
    (h : reg.find? (fun k => k.id == env.keyId) = none) :
    verifyEnvelope reg env line = none := by
  unfold verifyEnvelope
  rw [h]

/-- Registry closure: every produced id is a registered id. -/
theorem verifyEnvelope_id_registered (reg : PrincipalRegistry)
    (env : Envelope) (line : String) (p : AuthenticatedPrincipal)
    (h : verifyEnvelope reg env line = some p) :
    ∃ k ∈ reg, k.id = p.id := by
  obtain ⟨k, hf, hid⟩ := envelope_gates_presence_not_value reg env line p h
  exact ⟨k, List.mem_of_find?_eq_some hf, hid.symm⟩

/-! ## Instantiation link — Route 2 stands on the existing escape hatch

`Host.ReceiptIdentity.credentialed_topology_authenticates` (the theorem this
build instantiates) is stated at `CanonicalAction → Option Principal`.
`CanonicalAction` stays bytes-determined (deliberately — the deployed-topology
reading of `StdioTotal` depends on it), so the faithful instantiation lives at
the enveloped-request type below. `ReceiptIdentity.lean` is untouched; the
no-go (`stdio_no_caller_authentication`) stays loud, and its boundary is
restated here as `envelope_constrained_excludes_totality`. -/

/-- An enveloped request: the judged line plus its envelope — the request type
    at which Route 2's send relation is credential-constrained. -/
structure EnvelopedLine where
  line : String
  env : Envelope

/-- The Route-2 credential reader: `verifyEnvelope`, projected to the plain
    principal string of the `Host.Provenance` vocabulary. -/
def envelopeCredential (reg : PrincipalRegistry) (r : EnvelopedLine) :
    Option Host.Provenance.Principal :=
  (verifyEnvelope reg r.env r.line).map (·.id)

/-- The envelope-restricted send relation: each request determines its sender
    via the credential — `credentialed_topology_authenticates`'s `hbind`
    hypothesis, instantiated with `envelopeCredential`. -/
def EnvelopeConstrained (reg : PrincipalRegistry)
    (sends : Host.Provenance.Principal → EnvelopedLine → Prop) : Prop :=
  ∀ c r, sends c r → envelopeCredential reg r = some c

/-- **Route 2 instantiates the escape hatch** — the
    `Host.ReceiptIdentity.credentialed_topology_authenticates` shape at the
    enveloped-request type: on an envelope-constrained send relation an
    authenticator exists — read the credential. -/
theorem envelope_topology_authenticates (reg : PrincipalRegistry)
    (sends : Host.Provenance.Principal → EnvelopedLine → Prop)
    (hbind : EnvelopeConstrained reg sends) :
    ∃ f : EnvelopedLine → Host.Provenance.Principal,
      ∀ c r, sends c r → f r = c := by
  refine ⟨fun r => (envelopeCredential reg r).getD "", fun c r hs => ?_⟩
  show (envelopeCredential reg r).getD "" = c
  rw [hbind c r hs]
  rfl

/-- **The no-go stays untouched, as a theorem.** An envelope-constrained send
    relation is INCOMPATIBLE with totality (`StdioTotal`'s shape at the
    enveloped type): if every principal could send every enveloped request,
    one fixed request would have to determine two distinct senders. This is
    `Host.ReceiptIdentity.credential_excludes_totality` restated at this
    type: the envelope is a partial authenticator on a restricted relation,
    never caller authentication on the total stdio relation — which remains
    proven impossible. -/
theorem envelope_constrained_excludes_totality (reg : PrincipalRegistry)
    (sends : Host.Provenance.Principal → EnvelopedLine → Prop)
    (hbind : EnvelopeConstrained reg sends)
    (htotal : ∀ c r, sends c r) : False := by
  have r0 : EnvelopedLine :=
    ⟨"", { keyId := "", sigHex := "", nonceHex := "", issuedAt := 0 }⟩
  have ha := hbind "alice" r0 (htotal "alice" r0)
  have hm := hbind "mallory" r0 (htotal "mallory" r0)
  rw [ha] at hm
  simp at hm

/-! ## Golden vectors — the cross-language signed-message contract

Byte-twinned in `rust/tests/principal_identity.rs`
(`envelope_message_golden_vector_matches_lean`). `envelopeMessage` is pure
Lean (no extern), so these pins run in every lane including the interpreter. -/

/-- Hex of a byte array (lowercase) — for golden-vector pins and tests. -/
def bytesToHex (b : ByteArray) : String :=
  String.ofList (b.toList.flatMap fun byte =>
    let hi := byte.toNat / 16
    let lo := byte.toNat % 16
    let digit := fun (n : Nat) =>
      if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    [digit hi, digit lo])

/-- info: "7365616c2f76322e312f7072696e636970616c2d656e76656c6f706500" -/
#guard_msgs in
#eval bytesToHex envelopeTag.toUTF8

/--
info: "7365616c2f76322e312f7072696e636970616c2d656e76656c6f706500000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000004d27b226d223a317d"
-/
#guard_msgs in
#eval bytesToHex (envelopeMessage
  (ByteArray.mk (Array.range 32 |>.map UInt8.ofNat)) 1234 "{\"m\":1}")

/-! ## Axiom pins -/

/-- info: 'Host.envelope_gates_presence_not_value' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms envelope_gates_presence_not_value

/-- info: 'Host.principal_value_key_constant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms principal_value_key_constant

/-- info: 'Host.verifyEnvelope_none_of_unregistered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms verifyEnvelope_none_of_unregistered

/-- info: 'Host.verifyEnvelope_id_registered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms verifyEnvelope_id_registered

/-- info: 'Host.envelope_topology_authenticates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms envelope_topology_authenticates

/-- info: 'Host.envelope_constrained_excludes_totality' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms envelope_constrained_excludes_totality

/-- info: 'Host.AuthenticatedPrincipal.ext_id' depends on axioms: [propext] -/
#guard_msgs in
#print axioms AuthenticatedPrincipal.ext_id

end Host
