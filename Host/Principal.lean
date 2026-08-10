/- SPDX-License-Identifier: Apache-2.0 -/

import SealV2.Crypto
import Host.Provenance

/-!
# Authenticated principal — the V2.2 authority-bound signed envelope (Route 2)

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

**V2.2 — the authority bind (council a1b7453d finding C1).** The V2.1 signed
message covered only (nonce, issuedAt, line). Principal id was a registry
lookup by keyId, and the registry rides inside the signed config — so a
genuine signature could be TRANSPLANTED under an attacker-minted self-signed
config (config substitution) or RELABELED to a different id registered under
the same pubkey (keyId unsigned). V2.2 closes both: `envelopeMessage` now
commits to
* the **config-signing authority** — the raw 32-byte Ed25519 pubkey that the
  trusted config's signature verifies under (the startup trust root). A
  signature minted under operator X's authority never verifies under any
  config signed by a different authority Y: the verifier reconstructs the
  message from ITS trust root, so the recomputed bytes differ and Ed25519
  rejects. Non-transplantability, modulo the crypto TCB.
* the **keyId** — the wire-claimed registry id. A signature made as `alice`
  never verifies presented as `alice-admin`, even if both ids share a pubkey.
  Non-relabelability.
Deliberately NOT committed (decided under the same council finding):
* **epoch** — the envelope's semantic claim is "principal P uttered exactly
  line L", not "under config version N". Whether L is allowed is the config's
  job at judgment time; binding the epoch would conflate authorization state
  with attribution and force every client to re-coordinate on each config
  re-sign (epoch bumps on every edit) — an availability footgun that
  pressures operators away from rotation. Freshness stays where it lives:
  the A3 nonce/TTL seam (Rust, test-discharged).
* **server-id** — no server identity exists in the signed-config vocabulary;
  inventing one touches the bundle schema, the signer and the kit (a
  separate, gated lane). RESIDUAL (documented, H-EXPORT): within the nonce
  window + TTL, a genuine envelope for server A can be presented to server B
  *only if* both run configs signed by the SAME authority key. Deployment
  guidance: per-deployment config-signing keys — then the authority bind IS
  the server bind and the residual closes with zero schema change.
The domain tag is version-bumped (`seal/v2.2/...`), and cross-version
separation is now a THEOREM (`envelope_cross_version_separated`): no byte
string is both a v2.1 and a v2.2 message. Consequence, stated plainly:
**v2.1 principal signatures do not verify under this kernel** — expected;
they were never safely verifiable (that is the hole).

**Where the principal may come from.** ONLY from `verifyEnvelope`: a
registered Ed25519 key (the registry rides inside the *signed* TrustedConfig —
out-of-band trust, never a request field) verifying a signature over the exact
judged line, bound to the config authority and the keyId as above.
`AuthenticatedPrincipal` has a private constructor; the sole producer in the
codebase is `verifyEnvelope`. Request-derived construction is unrepresentable
outside this module (pinned by a `#guard_msgs (error)` check in
`Test/DxSurface.lean`). Un-constructibility is module discipline — an
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
* That the `authority` bytes the session threads into `verifyEnvelope` ARE
  the config trust root — pinned by construction in `Ffi.initImpl` (the same
  `publicKey` string the config signature was just verified against), and
  operationally by the transplant drill in
  `rust/tests/principal_identity.rs`.

What IS machine-checked: the presence/value split
(`envelope_gates_presence_not_value`, `principal_value_key_constant` — request
bytes gate only WHETHER a principal appears, never WHICH), fail-closed
behaviour on unregistered keys, registry closure of every produced id, the
instantiation link to the credentialed-topology escape hatch, and — new in
V2.2 — that the message ENCODING binds the authority and the keyId
(`envelope_message_binds_authority_and_keyId`: equal messages force equal
authority and equal keyId), plus cross-version and cross-plane domain
separation as theorems.
-/

namespace Host

/-- One registered principal: the operator-pinned (id, Ed25519 verifying-key
    hex) pair. The registry is carried INSIDE the signed `TrustedConfig`
    (`principals` bundle section) — the key→principal binding is out-of-band
    trust established at config-signing time, never a request field. -/
structure PrincipalKey where
  /-- Operator-chosen principal identifier. -/
  id : String
  /-- Ed25519 verifying key, hex-encoded. -/
  pubkey : String
  deriving Repr, BEq

/-- The signed-config list of registered principal keys; `verifyEnvelope`
    reads the FIRST id match. -/
abbrev PrincipalRegistry := List PrincipalKey

/-- Raw request-envelope fields exactly as marshalled off the step-input JSON.
    Rust passes them through UNINTERPRETED (never a principal string); only
    `verifyEnvelope` gives them meaning. -/
structure Envelope where
  /-- The registry id the sender claims; meaningful only via `verifyEnvelope`. -/
  keyId : String
  /-- Ed25519 signature over the envelope's signed message, hex-encoded. -/
  sigHex : String
  /-- Per-request replay nonce, hex-encoded. -/
  nonceHex : String
  /-- Sender-claimed issuance time (milliseconds since the Unix epoch). -/
  issuedAt : Nat
  deriving Repr, BEq

/-- 8-byte big-endian encoding of a (u64-ranged) natural — fixed-width so the
    signed message framing is injective without separators. -/
def u64be (n : Nat) : ByteArray :=
  ByteArray.mk #[
    UInt8.ofNat (n >>> 56), UInt8.ofNat (n >>> 48), UInt8.ofNat (n >>> 40),
    UInt8.ofNat (n >>> 32), UInt8.ofNat (n >>> 24), UInt8.ofNat (n >>> 16),
    UInt8.ofNat (n >>> 8), UInt8.ofNat n]

theorem u64be_size (n : Nat) : (u64be n).size = 8 := rfl

/-- `u64be` is injective below `2^64` (the wire range). The framing lemma the
    keyId length prefix stands on. -/
theorem u64be_inj {n m : Nat} (hn : n < 2 ^ 64) (hm : m < 2 ^ 64)
    (h : u64be n = u64be m) : n = m := by
  have hl : [UInt8.ofNat (n >>> 56), UInt8.ofNat (n >>> 48), UInt8.ofNat (n >>> 40),
      UInt8.ofNat (n >>> 32), UInt8.ofNat (n >>> 24), UInt8.ofNat (n >>> 16),
      UInt8.ofNat (n >>> 8), UInt8.ofNat n]
      = [UInt8.ofNat (m >>> 56), UInt8.ofNat (m >>> 48), UInt8.ofNat (m >>> 40),
      UInt8.ofNat (m >>> 32), UInt8.ofNat (m >>> 24), UInt8.ofNat (m >>> 16),
      UInt8.ofNat (m >>> 8), UInt8.ofNat m] :=
    congrArg (fun b : ByteArray => b.data.toList) h
  simp only [List.cons.injEq, and_true] at hl
  obtain ⟨h7, h6, h5, h4, h3, h2, h1, h0⟩ := hl
  have e7 := congrArg UInt8.toNat h7
  have e6 := congrArg UInt8.toNat h6
  have e5 := congrArg UInt8.toNat h5
  have e4 := congrArg UInt8.toNat h4
  have e3 := congrArg UInt8.toNat h3
  have e2 := congrArg UInt8.toNat h2
  have e1 := congrArg UInt8.toNat h1
  have e0 := congrArg UInt8.toNat h0
  simp only [UInt8.toNat_ofNat', Nat.shiftRight_eq_div_pow] at e7 e6 e5 e4 e3 e2 e1 e0
  omega

/-- Domain-separation tag for request envelopes, V2.2 (authority-bound).
    Distinct from the config envelope (which signs raw payload bytes,
    `Host.verifyConfigSignature`) so a signature can never be replayed across
    the two planes (`envelope_cross_plane_separated`), and version-bumped
    from v2.1 so old and new envelopes can never cross-verify
    (`envelope_cross_version_separated`). The trailing NUL terminates the tag
    unambiguously. -/
def envelopeTag : String := "seal/v2.2/principal-envelope\x00"

/-- The RETIRED v2.1 tag. SPEC-ONLY: no runtime path uses it; it exists so
    cross-version separation is a theorem, not a changelog note. -/
def envelopeTagV21 : String := "seal/v2.1/principal-envelope\x00"

/-- **The canonical signed message** — the cross-language contract, pinned by
    golden vectors here, byte-twinned in `rust/tests/principal_identity.rs`,
    and frozen for downstream verifiers in
    `/home/monkey/src/seal-fixB-envelope-contract.md`:

        tag ‖ authority (exactly 32 raw bytes)
            ‖ u64be(|keyId| in UTF-8 bytes) ‖ keyId-bytes
            ‖ nonce (exactly 32 raw bytes) ‖ u64be(issuedAt) ‖ line-bytes

    * `authority` — the raw 32-byte Ed25519 config-signing pubkey (the
      startup trust root the config signature verified under). THE V2.2 BIND:
      commits the utterance to the operator whose signed config names the
      registry (non-transplantability across config authorities).
    * `keyId` — the wire-claimed registry id, length-prefixed (the one
      variable-width field before the tail, so the encoding stays injective:
      `envelope_message_binds_authority_and_keyId`). Commits the utterance to
      ONE registry entry (non-relabelability across ids sharing a pubkey).
    * `line` — the EXACT judged line, unframed tail: the same bytes
      `classifyLine` routes and `auditLine`'s `request_sha256` commits to.
    All other fields are fixed-width (tag constant, authority 32 and nonce 32
    — both enforced by `verifyEnvelope` —, the two u64be at 8), so the
    encoding is injective in (authority, keyId, nonce, issuedAt, line); no
    separate digest needed (Ed25519 hashes internally). -/
def envelopeMessage (authority : ByteArray) (keyId : String) (nonce : ByteArray)
    (issuedAt : Nat) (line : String) : ByteArray :=
  envelopeTag.toUTF8 ++ authority ++ u64be keyId.utf8ByteSize ++ keyId.toUTF8
    ++ nonce ++ u64be issuedAt ++ line.toUTF8

/-- The RETIRED v2.1 message layout. SPEC-ONLY (no runtime caller): kept so
    `envelope_cross_version_separated` can state, as a theorem, that no byte
    string is both a v2.1 and a v2.2 signed message. -/
def envelopeMessageV21 (nonce : ByteArray) (issuedAt : Nat) (line : String) :
    ByteArray :=
  envelopeTagV21.toUTF8 ++ nonce ++ u64be issuedAt ++ line.toUTF8

/-! ## Domain separation + the authority/keyId bind — theorems, not prose -/

/-- **Cross-version separation.** No byte string is both a v2.2 and a v2.1
    signed message: the fixed-width tags differ, so the messages differ
    whatever the remaining fields. Old envelopes can never cross-verify under
    the new kernel (and vice versa), modulo only Ed25519 verifying the exact
    message bytes. -/
theorem envelope_cross_version_separated (authority : ByteArray)
    (keyId : String) (nonce : ByteArray) (issuedAt : Nat) (line : String)
    (nonce' : ByteArray) (issuedAt' : Nat) (line' : String) :
    envelopeMessage authority keyId nonce issuedAt line
      ≠ envelopeMessageV21 nonce' issuedAt' line' := by
  intro h
  unfold envelopeMessage envelopeMessageV21 at h
  simp only [ByteArray.append_assoc] at h
  have htag : envelopeTag.toUTF8 = envelopeTagV21.toUTF8 :=
    ByteArray.append_inj_left h rfl
  have : envelopeTag = envelopeTagV21 := by
    simpa [String.toUTF8_eq_toByteArray, String.toByteArray_inj] using htag
  exact absurd this (by decide)

/-- **Cross-plane separation.** The config plane signs the exact trusted JSON
    object payload bytes — which always begin with `{` (0x7b). An envelope-plane
    message always begins with the tag byte `s` (0x73). So no byte string is
    both a config payload and a principal-envelope message: a principal
    signature can never double as a config signature or vice versa. -/
theorem envelope_cross_plane_separated (authority : ByteArray) (keyId : String)
    (nonce : ByteArray) (issuedAt : Nat) (line : String) (rest : ByteArray) :
    envelopeMessage authority keyId nonce issuedAt line ≠ "{".toUTF8 ++ rest := by
  intro h
  unfold envelopeMessage at h
  simp only [ByteArray.append_assoc] at h
  generalize authority ++ (u64be keyId.utf8ByteSize
    ++ (keyId.toUTF8 ++ (nonce ++ (u64be issuedAt ++ line.toUTF8)))) = tail at h
  have hL : (0 : Nat) < (envelopeTag.toUTF8 ++ tail).size := by
    rw [ByteArray.size_append]
    have : (0 : Nat) < envelopeTag.toUTF8.size := by decide
    omega
  have hR : (0 : Nat) < ("{".toUTF8 ++ rest).size := by
    rw [ByteArray.size_append]
    have : (0 : Nat) < "{".toUTF8.size := by decide
    omega
  have h0 : envelopeTag.toUTF8[0]'(by decide) = "{".toUTF8[0]'(by decide) := by
    calc envelopeTag.toUTF8[0]'(by decide)
        = (envelopeTag.toUTF8 ++ tail)[0]'hL :=
          (ByteArray.getElem_append_left ..).symm
      _ = ("{".toUTF8 ++ rest)[0]'hR := by simp only [h]
      _ = "{".toUTF8[0]'(by decide) := ByteArray.getElem_append_left ..
  exact absurd h0 (by decide)

/-- **The V2.2 bind, at the encoding.** Equal messages force equal authority
    and equal keyId (given the wire-enforced widths). With Ed25519 verifying
    exact message bytes (TCB), this is non-transplantability and
    non-relabelability: one signature can only ever verify under ONE config
    authority and ONE claimed registry id. -/
theorem envelope_message_binds_authority_and_keyId
    {a₁ a₂ : ByteArray} {k₁ k₂ : String} {n₁ n₂ : ByteArray}
    {t₁ t₂ : Nat} {l₁ l₂ : String}
    (ha₁ : a₁.size = 32) (ha₂ : a₂.size = 32)
    (hk₁ : k₁.utf8ByteSize < 2 ^ 64) (hk₂ : k₂.utf8ByteSize < 2 ^ 64)
    (h : envelopeMessage a₁ k₁ n₁ t₁ l₁ = envelopeMessage a₂ k₂ n₂ t₂ l₂) :
    a₁ = a₂ ∧ k₁ = k₂ := by
  unfold envelopeMessage at h
  simp only [ByteArray.append_assoc] at h
  rw [ByteArray.append_right_inj] at h
  have hauth : a₁ = a₂ := ByteArray.append_inj_left h (ha₁.trans ha₂.symm)
  refine ⟨hauth, ?_⟩
  rw [hauth, ByteArray.append_right_inj] at h
  have hlen : u64be k₁.utf8ByteSize = u64be k₂.utf8ByteSize :=
    ByteArray.append_inj_left h rfl
  have hsz : k₁.utf8ByteSize = k₂.utf8ByteSize := u64be_inj hk₁ hk₂ hlen
  rw [hlen, ByteArray.append_right_inj] at h
  have hkid : k₁.toUTF8 = k₂.toUTF8 := ByteArray.append_inj_left h (by
    simpa [String.toUTF8_eq_toByteArray, String.size_toByteArray] using hsz)
  simpa [String.toUTF8_eq_toByteArray, String.toByteArray_inj] using hkid

/-- THE authenticated principal. Private constructor: the only producer in the
    codebase is `verifyEnvelope`. The `id` PROJECTION is public — observation
    is free, construction is not. -/
structure AuthenticatedPrincipal where
  private mk ::
  /-- The verified principal id — observation is free, construction is not. -/
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
    `authority` is the raw 32-byte config-signing pubkey — the startup trust
    root, threaded in by the session (NEVER a request field). Fail-closed
    `none` on: unregistered keyId, malformed hex (key, sig, or nonce), wrong
    authority, key or nonce length, or verification failure. `some ⟨k.id⟩`
    ONLY when the registered key verifies the signature over
    `envelopeMessage authority env.keyId nonce issuedAt line` — the exact
    judged line, bound to the config authority and the claimed keyId.

    The extern result is only ever cased on as an opaque `Bool`; no theorem
    in this module depends on what it computes (that is the crypto TCB). -/
def verifyEnvelope (authority : ByteArray) (reg : PrincipalRegistry)
    (env : Envelope) (line : String) : Option AuthenticatedPrincipal :=
  match reg.find? (fun k => k.id == env.keyId) with
  | none => none
  | some k =>
      match SealV2.hexDecode? k.pubkey, SealV2.hexDecode? env.sigHex,
            SealV2.hexDecode? env.nonceHex with
      | some pk, some sig, some nonce =>
          if authority.size == 32 && pk.size == 32 && nonce.size == 32
              && SealV2.ed25519Verify pk
                   (envelopeMessage authority env.keyId nonce env.issuedAt line)
                   sig
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
    The line, signature, nonce and authority decide only whether `some`
    appears. -/
theorem envelope_gates_presence_not_value (authority : ByteArray)
    (reg : PrincipalRegistry) (env : Envelope) (line : String)
    (p : AuthenticatedPrincipal)
    (h : verifyEnvelope authority reg env line = some p) :
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
    different timestamps, even different authorities — name the SAME
    principal. The per-key analogue of `receipt_identity_boot_constant`. -/
theorem principal_value_key_constant (auth auth' : ByteArray)
    (reg : PrincipalRegistry) (env env' : Envelope) (line line' : String)
    (p p' : AuthenticatedPrincipal) (hk : env.keyId = env'.keyId)
    (h : verifyEnvelope auth reg env line = some p)
    (h' : verifyEnvelope auth' reg env' line' = some p') : p = p' := by
  obtain ⟨k, hf, hid⟩ := envelope_gates_presence_not_value auth reg env line p h
  obtain ⟨k', hf', hid'⟩ :=
    envelope_gates_presence_not_value auth' reg env' line' p' h'
  rw [hk] at hf
  rw [hf] at hf'
  injection hf' with hkk
  exact AuthenticatedPrincipal.ext_id (by rw [hid, hid', hkk])

/-- Fail-closed: an unregistered keyId yields `none` — no request can name a
    principal outside the signed registry. -/
theorem verifyEnvelope_none_of_unregistered (authority : ByteArray)
    (reg : PrincipalRegistry) (env : Envelope) (line : String)
    (h : reg.find? (fun k => k.id == env.keyId) = none) :
    verifyEnvelope authority reg env line = none := by
  unfold verifyEnvelope
  rw [h]

/-- Registry closure: every produced id is a registered id. -/
theorem verifyEnvelope_id_registered (authority : ByteArray)
    (reg : PrincipalRegistry) (env : Envelope) (line : String)
    (p : AuthenticatedPrincipal)
    (h : verifyEnvelope authority reg env line = some p) :
    ∃ k ∈ reg, k.id = p.id := by
  obtain ⟨k, hf, hid⟩ := envelope_gates_presence_not_value authority reg env line p h
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
  /-- The judged wire line, byte-exact. -/
  line : String
  /-- The envelope presented for that line. -/
  env : Envelope

/-- The Route-2 credential reader: `verifyEnvelope`, projected to the plain
    principal string of the `Host.Provenance` vocabulary. -/
def envelopeCredential (authority : ByteArray) (reg : PrincipalRegistry)
    (r : EnvelopedLine) : Option Host.Provenance.Principal :=
  (verifyEnvelope authority reg r.env r.line).map (·.id)

/-- The envelope-restricted send relation: each request determines its sender
    via the credential — `credentialed_topology_authenticates`'s `hbind`
    hypothesis, instantiated with `envelopeCredential`. -/
def EnvelopeConstrained (authority : ByteArray) (reg : PrincipalRegistry)
    (sends : Host.Provenance.Principal → EnvelopedLine → Prop) : Prop :=
  ∀ c r, sends c r → envelopeCredential authority reg r = some c

/-- **Route 2 instantiates the escape hatch** — the
    `Host.ReceiptIdentity.credentialed_topology_authenticates` shape at the
    enveloped-request type: on an envelope-constrained send relation an
    authenticator exists — read the credential. -/
theorem envelope_topology_authenticates (authority : ByteArray)
    (reg : PrincipalRegistry)
    (sends : Host.Provenance.Principal → EnvelopedLine → Prop)
    (hbind : EnvelopeConstrained authority reg sends) :
    ∃ f : EnvelopedLine → Host.Provenance.Principal,
      ∀ c r, sends c r → f r = c := by
  refine ⟨fun r => (envelopeCredential authority reg r).getD "", fun c r hs => ?_⟩
  show (envelopeCredential authority reg r).getD "" = c
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
theorem envelope_constrained_excludes_totality (authority : ByteArray)
    (reg : PrincipalRegistry)
    (sends : Host.Provenance.Principal → EnvelopedLine → Prop)
    (hbind : EnvelopeConstrained authority reg sends)
    (htotal : ∀ c r, sends c r) : False := by
  have r0 : EnvelopedLine :=
    ⟨"", { keyId := "", sigHex := "", nonceHex := "", issuedAt := 0 }⟩
  have ha := hbind "alice" r0 (htotal "alice" r0)
  have hm := hbind "mallory" r0 (htotal "mallory" r0)
  rw [ha] at hm
  simp at hm

/-! ## Golden vectors — the cross-language signed-message contract

Byte-twinned in `rust/tests/principal_identity.rs`
(`envelope_message_golden_vector_matches_lean`) and frozen in
`/home/monkey/src/seal-fixB-envelope-contract.md`. `envelopeMessage` is pure
Lean (no extern), so these pins run in every lane including the interpreter. -/

/-- Hex of a byte array (lowercase) — for golden-vector pins and tests. -/
def bytesToHex (b : ByteArray) : String :=
  String.ofList (b.toList.flatMap fun byte =>
    let hi := byte.toNat / 16
    let lo := byte.toNat % 16
    let digit := fun (n : Nat) =>
      if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    [digit hi, digit lo])

/-- info: "7365616c2f76322e322f7072696e636970616c2d656e76656c6f706500" -/
#guard_msgs in
#eval bytesToHex envelopeTag.toUTF8

/--
info: "7365616c2f76322e322f7072696e636970616c2d656e76656c6f706500a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000005616c696365000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000004d27b226d223a317d"
-/
#guard_msgs in
#eval bytesToHex (envelopeMessage
  (ByteArray.mk (Array.range 32 |>.map fun i => UInt8.ofNat (0xa0 + i)))
  "alice"
  (ByteArray.mk (Array.range 32 |>.map UInt8.ofNat)) 1234 "{\"m\":1}")

/-! ## Axiom pins -/

/-- info: 'Host.u64be_inj' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms u64be_inj

/-- info: 'Host.envelope_cross_version_separated' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms envelope_cross_version_separated

/-- info: 'Host.envelope_cross_plane_separated' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms envelope_cross_plane_separated

/-- info: 'Host.envelope_message_binds_authority_and_keyId' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms envelope_message_binds_authority_and_keyId

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
