/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Host.Canonical
import Host.Step
import Host.Config
import Host.Registry
import Host.Audit
import Host.Evidence
import Seal.Block
-- M.7 branch dependency: requires kernel commit 564c21f (or its merge) and
-- cannot build against the current pin before the single repin.
import SealV2.McpVersionGate
import Kernels

/-!
# FFI surface — the verified decide, exported to the Rust host

The Rust host owns transport (stdio MITM, child process), the approval
back-channel providers, A3 freshness (nonce/replay/TTL) and the wall clock.
Lean owns everything decision-bearing: canonical parsing, config
verification, every kernel's `ingest`/`decide`, the fail-closed
AND-combination and the audit certs. The seam is string-in/string-out JSON —
no structs cross the boundary.

TCB note (documented in TCB.md): this boundary GROWS the trusted base — the
Rust transport, the evidence gatherers, the C ABI and the JSON marshalling
are all trusted, where the pure-Lean stdio host trusts only the Lean
runtime. The stdio sidecar remains the cleanest assurance story; the FFI
host trades TCB for deployability.

Threading: the exports are NOT thread-safe; the Rust host serialises calls
(it does — single mediation thread).
-/

namespace Ffi

open Lean Host

structure Session where
  config : TrustedConfig
  /-- V2.2: the decoded config-signing authority pubkey (raw 32 bytes) — the
      SAME trust root the config signature was verified against at init,
      threaded into `Host.verifyEnvelope` so the principal-envelope message
      commits to it (council C1 authority bind). Never a request field; the
      model-oracle lane may leave it empty, which fail-closes every envelope
      (`verifyEnvelope` demands size 32). -/
  configAuthority : ByteArray
  safetyRef : IO.Ref SealCore.State
  temporalRef : IO.Ref Kernels.TemporalState
  linearRef : IO.Ref LinearCore.LState
  budgetRef : IO.Ref Kernels.BudgetState
  principalBudgetRef : IO.Ref Kernels.PBState
  unitRef : IO.Ref Unit

initialize sessionRef : IO.Ref (Option Session) ← IO.mkRef none

private def errJson (msg : String) : String :=
  (Json.mkObj [("ok", Json.bool false), ("error", Json.str msg)]).compress

/-! ### M.2 revision session — the wasm port of `McpRevisionSession`

The native host derives the per-session MCP adapter revision from the
received entry-call shapes (`rust/src/adapter_revision.rs`) and feeds it to
the M.7 gate as `version_gate_input()`: `""` while undetermined, the selected
revision string once one entry shape has been seen, and the
`"conflicting-entry-calls"` sentinel once both incompatible shapes have been
seen (which the gate rejects as ambiguous). The wasm `seal_decide` wrapper
carries the same fold here so the browser build and the native build gate
each request against the SAME session evidence — the method→revision mapping
is NOT re-implemented: it is the kernel-owned `mcpEntryCallOfMethod` /
`McpEntryCall.revision` seam, the same seam the native envelope path signs.

Ordering matches `rust/src/main.rs`: the gate judges a line under the
selection derived from PRIOR traffic, and only a line the gate admits is
observed. A rejected line never mutates the selection. -/

/-- The three-valued native selection state, verbatim. -/
inductive McpRevisionSelection where
  | undetermined
  | selected (revision : String)
  | conflictingEntryCalls
  deriving Repr, BEq, DecidableEq, Inhabited

/-- `McpRevisionSession::version_gate_input`: the exact string handed to
    `SealV2.Effect.mcpVersionGate` as `selectedRevision`. -/
def McpRevisionSelection.gateInput : McpRevisionSelection → String
  | .undetermined => ""
  | .selected revision => revision
  | .conflictingEntryCalls => "conflicting-entry-calls"

/-- `McpRevisionSession::observe_received_call`, purely: fold one admitted
    line into the selection. The method→revision map is the kernel's
    `mcpEntryCallOfMethod`; non-entry methods, non-object lines and
    unparseable lines observe nothing. Callers must only pass lines the
    raw-wire classifier did NOT refuse: the guards are what make this
    `Json.parse` agree with the native observer's serde_json parse
    (duplicate keys, depth, numeric form), and what make it safe to run
    on a small wasm stack. -/
def McpRevisionSelection.observe (selection : McpRevisionSelection)
    (line : String) : McpRevisionSelection :=
  match Json.parse line with
  | .error _ => selection
  | .ok request =>
      match ((request.getObjVal? "method").toOption.bind
          (·.getStr?.toOption)).bind SealV2.Effect.mcpEntryCallOfMethod with
      | none => selection
      | some entry =>
          let observed := entry.revision.version
          match selection with
          | .undetermined => .selected observed
          | .selected s =>
              if s == observed then .selected s else .conflictingEntryCalls
          | .conflictingEntryCalls => .conflictingEntryCalls

/-- Decode the gate-input encoding back into a selection. Total; the inverse
    of `gateInput` on every state the fold can reach, because a selected
    revision is always `McpEntryCall.revision.version` — nonempty and never
    the conflict sentinel. Pinned by the `example`s below. -/
def McpRevisionSelection.ofGateInput : String → McpRevisionSelection
  | "" => .undetermined
  | "conflicting-entry-calls" => .conflictingEntryCalls
  | revision => .selected revision

example : McpRevisionSelection.ofGateInput
    McpRevisionSelection.undetermined.gateInput = .undetermined := by decide
example : McpRevisionSelection.ofGateInput
    McpRevisionSelection.conflictingEntryCalls.gateInput =
      .conflictingEntryCalls := by decide
example : ∀ entry : SealV2.Effect.McpEntryCall,
    McpRevisionSelection.ofGateInput
        (McpRevisionSelection.selected entry.revision.version).gateInput =
      .selected entry.revision.version := by
  intro entry; cases entry <;> decide

/-- The wasm module's revision session. Reset by `initFromConfig` (a fresh
    session has seen no entry call), exactly as the native host constructs a
    fresh `McpRevisionSession` per mediated connection. -/
initialize mcpRevisionSelectionRef : IO.Ref McpRevisionSelection ←
  IO.mkRef .undetermined

private def initFromConfig (config : TrustedConfig)
    (configAuthority : ByteArray) : IO String := do
  let session : Session := {
    config
    configAuthority
    safetyRef := ← IO.mkRef SealCore.State.empty
    temporalRef := ← IO.mkRef Kernels.temporalKernel.init
    linearRef := ← IO.mkRef LinearCore.LState.empty
    budgetRef := ← IO.mkRef []
    principalBudgetRef := ← IO.mkRef []
    unitRef := ← IO.mkRef ()
  }
  sessionRef.set (some session)
  -- M.2: a fresh session has observed no entry call — the gate's selection
  -- input returns to `""` (undetermined), as in the native per-connection
  -- `McpRevisionSession::default()`.
  mcpRevisionSelectionRef.set .undetermined
  pure <| (Json.mkObj [
    ("ok", Json.bool true),
    ("epoch", toJson config.epoch),
    ("approval_ttl_ms", toJson config.safety.approvalTtlMs),
    ("approval_file", Json.str config.safety.approvalFile.toString),
    ("votes_file", Json.str (config.consensus.map (·.votesFile.toString) |>.getD "")),
    ("grants_file", Json.str (config.linear.map (·.grantsFile.toString) |>.getD "")),
    ("forecasts_file", Json.str (config.calibration.map (·.recordsFile.toString) |>.getD ""))
  ]).compress

/-- Initialise the session from the signed config envelope. Returns a JSON
    summary the Rust host needs for evidence gathering (file paths, TTL), or
    `{ok: false, error}` — fail-closed, no session on any failure. -/
private def initImpl (envelopeText publicKey : String) : IO String := do
  match checkEnvelope envelopeText publicKey with
  | .error err => pure (errJson s!"trusted config rejected: {err}")
  | .ok config =>
      -- V2.2 authority bind: the session pins the DECODED trust-root pubkey
      -- the config signature just verified against. `checkEnvelope` succeeded,
      -- so `hexDecode? publicKey` is `some` (verification decoded it); the
      -- `getD empty` default is unreachable and fail-closed if ever reached.
      initFromConfig config ((SealV2.hexDecode? publicKey).getD ByteArray.empty)

/-- Build the same registry `Host.Main` builds, with evidence injected from
    the step input instead of gathered from IO — `Host.dispatch` (two-phase
    ingest/decide commit) is reused verbatim.

    Public for SPECIFICATION only (see `FfiSpec.lean`: `registryFor_kernels`
    proves this list selects exactly `activeKernels s.config`, Safety and
    Temporal unconditionally). NOT callable API — the sole call site is
    `stepImpl` below; do not add another. -/
def registryFor (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option Host.AuthenticatedPrincipal) : Registry :=
  [ { kernel := Kernels.safetyKernel
      config := s.config.safety
      stateRef := s.safetyRef
      gather := fun _ => pure { now, approvalEvents } },
    { kernel := Kernels.temporalKernel
      config := s.config.temporal
      stateRef := s.temporalRef
      gather := fun _ => pure () } ]
  ++ (match s.config.consensus with
      | some cfg =>
          [{ kernel := Kernels.consensusKernel, config := cfg,
             stateRef := s.unitRef, gather := fun _ => pure votes }]
      | none => [])
  ++ (if s.config.convergence.isEmpty then []
      else
        [{ kernel := Kernels.convergenceKernel, config := s.config.convergence,
           stateRef := s.unitRef, gather := fun _ => pure () }])
  ++ (match s.config.calibration with
      | some cfg =>
          if cfg.enabled then
            [{ kernel := Kernels.calibrationKernel, config := cfg,
               stateRef := s.unitRef, gather := fun _ => pure forecasts }]
          else []
      | none => [])
  ++ (match s.config.linear with
      | some cfg =>
          [{ kernel := Kernels.linearKernel, config := cfg,
             stateRef := s.linearRef, gather := fun _ => pure grants }]
      | none => [])
  ++ (if s.config.budget.isEmpty then []
      else
        [{ kernel := Kernels.budgetKernel, config := s.config.budget,
           stateRef := s.budgetRef, gather := fun _ => pure () }])
  ++ (match s.config.principals with
      | some cfg =>
          -- Kernel PB (V2.1). Its evidence is the parse-path-verified
          -- principal — a constant-pure gather (`registryFor_gather_pure`
          -- extends over it): the value was produced by `Host.verifyEnvelope`
          -- in `stepImpl`'s marshalling, never by this IO closure and never
          -- by the Rust host.
          [{ kernel := Kernels.principalBudgetKernel, config := cfg,
             stateRef := s.principalBudgetRef, gather := fun _ => pure principal? }]
      | none => [])

private def getStrD (j : Json) (key : String) (d : String) : String :=
  ((j.getObjVal? key).toOption.bind (·.getStr?.toOption)).getD d

/-- The client-facing response for a line refused before parsing (a pathological
    numeric literal). A JSON-RPC "Invalid Request" — `id` is null because
    recovering the request id would mean parsing the line the guard refused to
    parse. Fixed bytes, so every lane emits the same block response. -/
private def refuseResponseLine : String :=
  (Json.mkObj [
    ("jsonrpc", Json.str "2.0"),
    ("id", Json.null),
    ("error", Json.mkObj [
      ("code", Json.num (-32600)),
      ("message", Json.str "seal-host: request refused — unsafe numeric literal")
    ])
  ]).compress ++ "\n"

/-- The V2.1 `principal` output member: `[("principal", <id>)]` when the
    parse path authenticated a principal, `[]` otherwise. Public for
    SPECIFICATION only (the receipt model half below and R-PRINC); the
    runtime callers are `stepImpl` and `stepRender`, which share this one
    definition — the output field has exactly one producer. -/
def principalOutField (principal? : Option Host.AuthenticatedPrincipal) :
    List (String × Json) :=
  match principal? with
  | some p => [("principal", Json.str p.id)]
  | none => []

/-- One mediation step. Input JSON:
    `{line, now, approvals: [{target, issuedAt?}], votes, grants, forecasts,
    envelope?: {key_id, sig, nonce, issued_at}}`
    (votes/grants/forecasts as raw file text; approvals already A3-filtered
    by the Rust host; `envelope` carries the RAW V2.2 principal-envelope
    fields — nonce-freshness-filtered but NEVER verified or interpreted by
    Rust: `Host.verifyEnvelope` runs HERE, in the parse path, against the
    signed config's principal registry, the session-pinned config authority
    and the exact judged `line`). Output
    JSON: `{route: "passthrough"|"forward"|"block", response?, audit?,
    principal?}` — `principal` present iff the envelope verified. -/
private def stepImpl (inputText : String) : IO String := do
  let some session ← sessionRef.get
    | pure (errJson "session not initialised")
  -- Fail closed before parsing the step envelope: a pathological numeric
  -- literal in the STRUCTURE (e.g. `now` or an approval `issuedAt` with a
  -- monster exponent) would abort `Json.parse` here. The attacker-controlled
  -- wire line is a string field (inert to this parse; its own pathological
  -- numbers are caught by `classifyLine`'s guard), so this covers the
  -- host-supplied numeric fields. (Seal.JsonUtil.wireNumbersSafe.)
  if !Seal.JsonUtil.wireNumbersSafe inputText then
    pure (errJson "bad step input: unsafe numeric literal")
  else
  match Json.parse inputText with
  | .error err => pure (errJson s!"bad step input: {err}")
  | .ok input => do
      let line := getStrD input "line" ""
      let now := ((input.getObjVal? "now").toOption.bind (·.getNat?.toOption)).getD 0
      let approvals := Evidence.approvalEventsFromJson
        ((input.getObjVal? "approvals").toOption.getD (Json.arr #[]))
        now session.config.safety.approvalTtlMs
      let votes := Host.Evidence.parseVotesText (getStrD input "votes" "")
      let grants := Host.Evidence.parseGrantsText (getStrD input "grants" "")
      let forecasts := Host.Evidence.parseForecastsText (getStrD input "forecasts" "")
      -- V2.1 principal derivation — IN THE PARSE PATH. The extern is reached
      -- only when an `envelope` object is present AND the config carries a
      -- principals section, so envelope-less traffic (the whole existing
      -- corpus, and every interpreter lane) never touches the Ed25519 leaf.
      -- The line verified is the SAME `line` binding `classifyLine` judges
      -- and `auditLine` commits to — the signature covers the exact judged
      -- bytes.
      let principal? :=
        match (input.getObjVal? "envelope").toOption, session.config.principals with
        | some env, some pcfg =>
            Host.verifyEnvelope session.configAuthority pcfg.registry
              { keyId := getStrD env "key_id" ""
                sigHex := getStrD env "sig" ""
                nonceHex := getStrD env "nonce" ""
                issuedAt := ((env.getObjVal? "issued_at").toOption.bind
                  (·.getNat?.toOption)).getD 0 }
              line
        | _, _ => none
      let lc := classifyLine line
      match lc with
      | .passthrough =>
          pure (Json.mkObj [("route", Json.str "passthrough")]).compress
      | .refuse =>
          -- Pathological numeric literal (monster exponent): fail closed. Block
          -- the line WITHOUT parsing (no `Nat.pow` abort) and WITHOUT forwarding
          -- (no bypass). No act, no verdicts ⇒ no audit certificate. Every lane
          -- runs this same branch, so the bytes are identical.
          pure (Json.mkObj [
            ("route", Json.str "block"),
            ("response", Json.str refuseResponseLine)
          ]).compress
      | .act act => do
          let registry := registryFor session now approvals votes grants forecasts
            principal?
          let (combined, verdicts) ← dispatch registry act
          -- `line` is the SAME binding `classifyLine` judged above — one
          -- binding, no rewrites (mirrors rust/src/main.rs). The kernel's
          -- request commitment is therefore over the exact bytes it judged.
          let audit := auditLine session.config.epoch act.tool combined verdicts line
          -- Route through the PURE `Host.stepRoute` — the function
          -- `step_forward_non_bypass` (Host.Composition) is proven over.
          -- `stepRoute (.act act) verdicts = .forward ↔ combineVerdicts verdicts
          -- = .allow` (`stepRoute_act_forward_iff`), and `dispatch` returns
          -- `combined = combineVerdicts verdicts`, so this is byte-identical to
          -- routing on `combined` directly.
          -- The V2.1 `principal` output field: the parse-path-verified
          -- principal's id, or absent — NEVER a request-derived string
          -- (`stepOutFields_principal` pins the model; R-PRINC discharges the
          -- Rust assembler side). Emitted on both routes so a denied call's
          -- receipt still names who was debited/denied.
          let principalField := principalOutField principal?
          match Host.stepRoute lc verdicts with
          | .forward =>
              pure (Json.mkObj ([
                ("route", Json.str "forward"), ("audit", Json.str audit)]
                ++ principalField)).compress
          | .block =>
              pure (Json.mkObj ([
                ("route", Json.str "block"),
                ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
                ("audit", Json.str audit)
              ] ++ principalField)).compress
          | .passthrough =>
              -- Unreachable: `stepRoute (.act _)` is `.forward`/`.block` only.
              -- Fail-closed to block if ever reached.
              pure (Json.mkObj ([
                ("route", Json.str "block"),
                ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
                ("audit", Json.str audit)
              ] ++ principalField)).compress

/-- Conformance-bridge model oracle. These call the SAME private `initImpl` /
    `stepImpl` the FFI exports below wrap, but WITHOUT the `unsafe`/`unsafeBaseIO`
    marshalling — so `lake env lean --run` evaluates the real Lean decision core
    in the interpreter. The bridge diffs this against the compiled native `.so`
    (and, as a stretch, the emscripten wasm) to test that codegen preserves the
    proven decisions + audit bytes on the corpus. NOT an FFI export. -/
def modelInit (envelopeText publicKey : String) : IO String :=
  initImpl envelopeText publicKey

/-- MODEL ORACLE ONLY. This intentionally bypasses config-signature verification
    because the Lean interpreter cannot execute the `@[extern]` Ed25519 leaf.
    It is not `@[export]`, not called by `seal_host_init`, and is used only by
    `scripts/model_oracle.lean`; compiled native/WASM/deployed oracles still
    initialise through `initImpl` and verify real signatures. -/
def modelInitFromTrustedPayload (payloadText : String)
    (publicKey : String := "") : IO String := do
  match Host.parseCanonicalConfigPayload payloadText with
  | .error err => pure (errJson s!"trusted config rejected: {err}")
  | .ok config =>
      -- V2.2: the model lane takes the authority hex EXPLICITLY (there is no
      -- signature to verify against). Defaults to "" → empty ByteArray →
      -- every envelope fail-closes (`verifyEnvelope` demands 32 bytes), so
      -- envelope-less oracle traffic is unaffected and enveloped scenarios
      -- must state their trust root.
      initFromConfig config ((SealV2.hexDecode? publicKey).getD ByteArray.empty)

def modelStep (inputText : String) : IO String :=
  stepImpl inputText

@[export seal_host_init]
unsafe def sealHostInit (envelopeText publicKey : String) : String :=
  unsafeBaseIO <| (initImpl envelopeText publicKey).catchExceptions
    (fun e => pure (errJson (toString e)))

@[export seal_host_step]
unsafe def sealHostStep (inputText : String) : String :=
  unsafeBaseIO <| (stepImpl inputText).catchExceptions
    (fun e => pure (errJson (toString e)))

/-- Routing classification for the differential harness / the native fast path:
    0 = passthrough, 1 = mediated tools/call, 2 = refused (pathological number,
    fail-closed). The Rust `route_of_classify` maps any value outside {0,1} to
    `Refuse`, so 2 fails closed on the classify fast path exactly as `.refuse`
    fails closed on the step path. -/
@[export seal_host_classify]
def sealHostClassify (line : String) : UInt32 :=
  match classifyLine line with
  | .passthrough => 0
  | .act _ => 1
  | .refuse => 2

/-- M.7 kernel-owned metadata, era-consistency, and error-rendering gate. -/
@[export seal_host_mcp_version_gate]
def sealHostMcpVersionGate (line selectedRevision : String) : String :=
  (SealV2.Effect.mcpVersionGate line selectedRevision).toJson.compress

/-- M.2 native observation: fold ONE gate-admitted line into the session
    selection, both encoded as the gate-input string (`""` / revision /
    `"conflicting-entry-calls"`) — the exact vocabulary
    `seal_host_mcp_version_gate` already receives. The Rust host stores the
    returned string opaquely; state stays host-side, the transition is
    kernel-owned, and the wasm session above folds the SAME
    `McpRevisionSelection.observe`.

    Precondition, kernel-owned: the fold runs only when
    `Host.SurrogateEscapes.wireSurrogatesSafe` admits the line. Native twin
    of the wasm bridge's guard story (M.2 section above): the retired native
    observer (serde_json) rejected a line carrying an unpaired UTF-16
    surrogate escape, while `Json.parse` substitutes U+FFFD and accepts —
    the one measured divergence class reachable at the native observe site
    (the other class, numerals outside binary64 round-trip, is refused
    upstream by `seal_host_first_agreement_unsafe_number`). Skipping the
    fold on that class preserves the native observer's behaviour exactly:
    no observation, no selection change — and `classifyLine` refuses the
    line itself immediately after. -/
@[export seal_host_mcp_revision_observe]
def sealHostMcpRevisionObserve (line selection : String) : String :=
  if !Host.SurrogateEscapes.wireSurrogatesSafe line then
    selection
  else
    ((McpRevisionSelection.ofGateInput selection).observe line).gateInput

/-- The step-envelope `line` extraction, shared. This is the ONE
    guard/parse/default sequence for reading the judged line out of the outer
    step input; `stepImpl` marshals through the same expressions
    (`stepLineOf?_agrees` below pins the agreement at build time — edit one
    copy without the other and the theorem breaks). `none` means the outer
    envelope itself is refused by `stepImpl`'s fail-closed step-input error
    path (unsafe host-side numeric literal, or unparseable outer JSON) — no
    line exists to gate. -/
def stepLineOf? (inputText : String) : Option String :=
  if !Seal.JsonUtil.wireNumbersSafe inputText then
    none
  else
    match Json.parse inputText with
    | .error _ => none
    | .ok input => some (getStrD input "line" "")

/-- The wasm gate bridge, purely: the gate decision handed to the C wrapper
    and the revision selection after this call.

    Composition, not duplication: the line comes from `stepLineOf?` (the same
    extraction `stepImpl` performs), and the decision to parse it AT ALL is
    delegated to the same `classifyLine` classifier `stepImpl` routes on.
    A `.refuse` line is returned as continue WITHOUT this bridge ever running
    `Json.parse` over it — `mcpVersionGate`'s own parse carries none of the
    raw-wire guards (depth, surrogate, digit, agreement), so parsing before
    the classifier would trade `stepImpl`'s fail-closed block for a wasm
    stack trap (the depth-5000 regression this ordering buries). `stepImpl`
    re-runs the identical classifier and produces the exact block bytes.

    Malformed outer envelopes (`stepLineOf? = none`) also return continue:
    `stepImpl` returns its existing fail-closed step-input ERROR (not a
    decision, not a passthrough), and keeping that path authoritative
    preserves its observable bytes (`stepLineOf?_none_respond`).

    An envelope with no usable line (`line` absent, non-string, or empty)
    yields `line = ""`, which classifies `.passthrough` and gates continue:
    there is no protocol request to judge, and `stepImpl` returns its normal
    `route:"passthrough"` — the DELIBERATE compatible-profile behaviour, not
    an oversight; see the report for the argument.

    Native ordering (`rust/src/main.rs`): gate under the selection derived
    from prior traffic; observe the entry call only when the gate admits the
    line. -/
def gatePlanFor (selection : McpRevisionSelection) (inputText : String) :
    SealV2.Effect.McpVersionGateDecision × McpRevisionSelection :=
  match stepLineOf? inputText with
  | none => (.continue, selection)
  | some line =>
      match classifyLine line with
      | .refuse => (.continue, selection)
      | _ =>
          match SealV2.Effect.mcpVersionGate line selection.gateInput with
          | .continue => (.continue, selection.observe line)
          | .reject response => (.reject response, selection)

/-- The bridge's IO shell: read the session selection, run the pure plan,
    commit the folded selection, return the decision bytes. -/
private def gateStepImpl (inputText : String) : IO String := do
  let selection ← mcpRevisionSelectionRef.get
  let (decision, next) := gatePlanFor selection inputText
  mcpRevisionSelectionRef.set next
  pure decision.toJson.compress

/-- Wasm-wrapper adapter for structural gate-before-step ordering. The public
    `seal_decide` ABI carries a step envelope rather than a raw MCP line, so
    this extracts the exact `line` field `stepImpl` judges and gates it under
    the M.2 revision session above. This symbol is linked for the C wrapper;
    it is not in the public Emscripten export list. Exceptions fail closed:
    the error result is not the exact continue object, so the C wrapper
    returns it and `seal_host_step` is never reached. -/
@[export seal_host_mcp_version_gate_step]
unsafe def sealHostMcpVersionGateStep (inputText : String) : String :=
  unsafeBaseIO <| (gateStepImpl inputText).catchExceptions
    (fun e => pure (errJson (toString e)))

/-- The deployed Rust host's pre-classify numeric-agreement seam. The empty
    string is the safe sentinel (a JSON numeric literal is never empty);
    otherwise the exact offending raw literal is returned so the host can
    name what it refused without parsing the request. The scan runs over the
    same ASCII-trimmed `line` binding handed to `sealHostClassify` and
    `sealHostStep`. -/
@[export seal_host_first_agreement_unsafe_number]
def sealHostFirstAgreementUnsafeNumber (line : String) : String :=
  (Seal.JsonUtil.firstAgreementUnsafeNumber? line.trimAscii.toString).getD ""

/-! ### Cross-implementation canonical-byte containment

The V2.3 transport reconstructs the signed effect tuple independently in
Rust.  Before Rust is allowed to verify (or a caller is allowed to mint) a
signature preimage, it asks this export for the bytes the pinned kernel
actually derives from the judged request.  The Rust boundary compares every
canonicalized seat byte-for-byte.  `ok = false` is a typed, fail-closed
classification: no guessed/default effect is returned. -/

private def canonicalSeatJson : Option String → Json
  | none => Json.mkObj [("present", Json.bool false)]
  | some bytes => Json.mkObj [
      ("present", Json.bool true),
      ("bytes", Json.str bytes)]

/-- Return the pinned kernel's exact canonical effect fields.  This is an
    observation seam only: `SealV2.Effect.deriveEffect` remains the sole Lean
    derivation and no Rust spelling is imported or reproduced here. -/
@[export seal_host_canonical_effect]
def sealHostCanonicalEffect (line : String) : String :=
  match SealV2.Effect.deriveEffect line.trimAscii.toString with
  | none => (Json.mkObj [
      ("ok", Json.bool false),
      ("error", Json.str "kernel could not classify a canonical signed effect")]).compress
  | some claim =>
      let metadata :=
        match claim.metadata with
        | .absent => none
        | .present bytes => some bytes
      let requestState :=
        match claim.requestState with
        | .absent => none
        | .present bytes => some bytes
      let inputResponses :=
        match claim.inputResponses with
        | .absent => none
        | .present bytes => some bytes
      (Json.mkObj [
        ("ok", Json.bool true),
        ("resource", Json.str claim.resource),
        ("action", Json.str claim.action),
        ("args", Json.str claim.args),
        ("metadata", canonicalSeatJson metadata),
        ("requestState", canonicalSeatJson requestState),
        ("inputResponses", canonicalSeatJson inputResponses)]).compress

/-! ### Policy schema/validate exports — `seal schema` / `seal validate`

Thin projections of the SAME `Seal.policyBundleCodec` the init path parses
with: the schema is the codec's schema projection, the validator runs the
codec's parse projection plus the host `ofBundle` mapping (so host-layer
rejects such as duplicate-Budget-cap conflicts — which the authoring signer
does NOT check — surface here too). Pure functions; no session state. -/

/-- The policy-bundle JSON Schema, straight from the repinned authority. -/
@[export seal_policy_schema]
def sealPolicySchema (_ : Unit) : String :=
  Seal.policyBundleSchema.pretty

/-- Validate raw policy-bundle payload text. Stages mirror the init path:
    the pathological-number guard (fail closed), JSON parse, the verified
    `parsePolicyBundle`, then `Host.ofBundle`. `canonical` reports whether
    the bytes satisfy the pinned SealV2 parser's one-representation grammar;
    this is a kernel-defined diagnostic, not an RFC 8785/JCS claim. It is
    reported rather than enforced so the validator can also judge
    authoring-time pretty-printed drafts. -/
@[export seal_policy_validate]
def sealPolicyValidate (payloadText : String) : String :=
  let canonical := (SealV2.parse payloadText).isSome
  let result : List (String × Json) :=
    if !Seal.JsonUtil.wireNumbersSafe payloadText then
      [("ok", Json.bool false), ("stage", Json.str "number-guard"),
       ("error", Json.str "pathological JSON number exponent (fail closed)")]
    else
      match Json.parse payloadText with
      | .error e =>
          [("ok", Json.bool false), ("stage", Json.str "json"),
           ("error", Json.str e)]
      | .ok j =>
          match Seal.parsePolicyBundle j with
          | .error e =>
              [("ok", Json.bool false), ("stage", Json.str "parse"),
               ("error", Json.str e)]
          | .ok bundle =>
              match Host.ofBundle bundle with
              | .error e =>
                  [("ok", Json.bool false), ("stage", Json.str "host"),
                   ("error", Json.str e)]
              | .ok _ => [("ok", Json.bool true)]
  (Json.mkObj (("canonical", Json.bool canonical) :: result)).compress

/-! ### The step plan, spelled — `stepImpl`'s marshalling as a pure function

SPEC ONLY (dispatch IO shell wrap-up): nothing below is called by the
exports. `stepImpl` is `private` by design (the sole runtime caller is the
FFI export pair), so its specification lives HERE, in the same file, with
file-local access. `stepImpl_spelled` proves `stepImpl` IS `stepPlanFor`
wrapped around its only two IO leaves — `sessionRef.get` and `dispatch` —
discharging the "stepImpl's JSON marshalling" residual of the dispatch IO
shell: which input field feeds which parser, the single `line` binding
judged by `classifyLine` and committed to the audit, the fail-closed
uninitialised-session / unsafe-number / bad-parse / refuse branches, and
that the dispatched registry is `registryFor` applied to exactly the
marshalled values. What it does NOT cover (unchanged, named TCB): the
`unsafeBaseIO`/`catchExceptions` export wrapper above `stepImpl`, and the
IO realization inside `dispatch` (see `Host.dispatch_spelled` and the
assurance docs). -/

/-- The per-step inputs `stepImpl` marshals out of the step input JSON —
    field by field the SAME expressions, as a pure record. -/
structure StepInputs where
  line : String
  now : Nat
  approvals : List SealCore.Event
  votes : Consensus.Checker.Votes
  grants : List LinearCore.LEvent
  forecasts : List Kernels.ForecastRecord
  /-- V2.1: the parse-path-verified principal — `Host.verifyEnvelope` over
      the exact judged `line`, or `none` (no envelope / no principals config /
      verification failure — fail-closed). -/
  principal? : Option Host.AuthenticatedPrincipal

/-- The marshalling, purely. -/
def stepInputsOf (session : Session) (input : Json) : StepInputs :=
  let now := ((input.getObjVal? "now").toOption.bind (·.getNat?.toOption)).getD 0
  { line := getStrD input "line" ""
    now := now
    approvals := Evidence.approvalEventsFromJson
      ((input.getObjVal? "approvals").toOption.getD (Json.arr #[]))
      now session.config.safety.approvalTtlMs
    votes := Host.Evidence.parseVotesText (getStrD input "votes" "")
    grants := Host.Evidence.parseGrantsText (getStrD input "grants" "")
    forecasts := Host.Evidence.parseForecastsText (getStrD input "forecasts" "")
    principal? :=
      match (input.getObjVal? "envelope").toOption, session.config.principals with
      | some env, some pcfg =>
          Host.verifyEnvelope session.configAuthority pcfg.registry
            { keyId := getStrD env "key_id" ""
              sigHex := getStrD env "sig" ""
              nonceHex := getStrD env "nonce" ""
              issuedAt := ((env.getObjVal? "issued_at").toOption.bind
                (·.getNat?.toOption)).getD 0 }
            (getStrD input "line" "")
      | _, _ => none }

/-- What one mediation step does, purely: either a fixed response line
    (fail-closed guard, parse failure, passthrough, refuse) or a mediated
    dispatch of `act` at the marshalled inputs. -/
inductive StepPlan where
  | respond (out : String)
  | mediate (inputs : StepInputs) (act : CanonicalAction)

/-- The pure step plan: everything `stepImpl` decides before and between
    its two IO leaves. -/
def stepPlanFor (session : Session) (inputText : String) : StepPlan :=
  if !Seal.JsonUtil.wireNumbersSafe inputText then
    .respond (errJson "bad step input: unsafe numeric literal")
  else
    match Json.parse inputText with
    | .error err => .respond (errJson s!"bad step input: {err}")
    | .ok input =>
        let inputs := stepInputsOf session input
        match classifyLine inputs.line with
        | .passthrough =>
            .respond (Json.mkObj [("route", Json.str "passthrough")]).compress
        | .refuse =>
            .respond (Json.mkObj [
              ("route", Json.str "block"),
              ("response", Json.str refuseResponseLine)
            ]).compress
        | .act act => .mediate inputs act

/-- The response rendering after a mediated dispatch, purely: the audit
    line over the SAME judged `line` binding, routed through the proven
    `Host.stepRoute`. -/
def stepRender (session : Session) (inputs : StepInputs)
    (act : CanonicalAction) (combined : VerdictKind)
    (verdicts : List Verdict) : String :=
  let audit := auditLine session.config.epoch act.tool combined verdicts inputs.line
  let principalField := principalOutField inputs.principal?
  match Host.stepRoute (classifyLine inputs.line) verdicts with
  | .forward =>
      (Json.mkObj ([("route", Json.str "forward"), ("audit", Json.str audit)]
        ++ principalField)).compress
  | .block =>
      (Json.mkObj ([
        ("route", Json.str "block"),
        ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
        ("audit", Json.str audit)
      ] ++ principalField)).compress
  | .passthrough =>
      (Json.mkObj ([
        ("route", Json.str "block"),
        ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
        ("audit", Json.str audit)
      ] ++ principalField)).compress

/-- **THE STEP IS ITS PLAN.** `stepImpl` equals the pure `stepPlanFor`
    wrapped around its two IO leaves: read the session, run the plan; a
    `.respond` plan returns its bytes with NO dispatch, a `.mediate` plan
    dispatches `registryFor` at EXACTLY the marshalled inputs and renders
    through the pure `Host.stepRoute`. Program equality in `IO` — the
    marshalling residual of the dispatch IO shell becomes this theorem. -/
theorem stepImpl_spelled (inputText : String) :
    stepImpl inputText
      = (do
        let some session ← sessionRef.get
          | pure (errJson "session not initialised")
        match stepPlanFor session inputText with
        | .respond out => pure out
        | .mediate inputs act => do
            let (combined, verdicts) ← dispatch
              (registryFor session inputs.now inputs.approvals inputs.votes
                inputs.grants inputs.forecasts inputs.principal?) act
            pure (stepRender session inputs act combined verdicts)) := by
  unfold stepImpl stepPlanFor stepRender stepInputsOf
  refine congrArg (sessionRef.get >>= ·) (funext fun s? => ?_)
  cases s? with
  | none => rfl
  | some session =>
    dsimp only
    by_cases hw : Seal.JsonUtil.wireNumbersSafe inputText
    · simp only [hw, Bool.not_true, Bool.false_eq_true, if_false]
      cases hp : Json.parse inputText with
      | error e => rfl
      | ok input =>
        dsimp only
        cases hlc : classifyLine (getStrD input "line" "") with
        | passthrough => rfl
        | refuse => rfl
        | act act =>
            dsimp only
            rw [hlc]
            refine congrArg (_ >>= ·) (funext fun p => ?_)
            cases Host.stepRoute (LineClass.act act) p.2 <;> rfl
    · simp only [hw, Bool.not_false, if_true]

/-! ### The gate bridge, kept in step — build-failing agreement theorems

The wasm gate bridge (`gatePlanFor`) and `stepImpl` both read the judged
line out of the outer step envelope, and both route on `classifyLine`. The
theorems below are the anti-drift contract: they tie the bridge's extraction
to `stepImpl`'s marshalling (through `stepInputsOf`, which `stepImpl_spelled`
ties to `stepImpl`) and pin the load-bearing ordering — no `Json.parse` of a
line the classifier refuses. Editing either side out of agreement breaks the
build here, not in a browser six months later. -/

/-- The bridge gates the SAME line `stepImpl` judges: on any well-formed
    outer envelope, `stepLineOf?` returns exactly the `line` `stepInputsOf`
    marshals. -/
theorem stepLineOf?_agrees (session : Session) (inputText : String)
    (input : Json)
    (hw : Seal.JsonUtil.wireNumbersSafe inputText = true)
    (hp : Json.parse inputText = .ok input) :
    stepLineOf? inputText = some (stepInputsOf session input).line := by
  simp [stepLineOf?, stepInputsOf, hw, hp]

/-- No extracted line ⇒ `stepImpl` responds with its own fail-closed
    step-input error and never mediates: the bridge's continue on a malformed
    outer envelope delegates to an error path, not to a decision. -/
theorem stepLineOf?_none_respond (session : Session) (inputText : String)
    (h : stepLineOf? inputText = none) :
    ∃ msg, stepPlanFor session inputText = .respond (errJson msg) := by
  unfold stepLineOf? at h
  by_cases hw : Seal.JsonUtil.wireNumbersSafe inputText
  · simp only [hw, Bool.not_true, Bool.false_eq_true, if_false] at h
    cases hp : Json.parse inputText with
    | error e =>
        exact ⟨s!"bad step input: {e}", by
          simp [stepPlanFor, hw, hp]⟩
    | ok input => rw [hp] at h; cases h
  · exact ⟨"bad step input: unsafe numeric literal", by
      simp [stepPlanFor, hw]⟩

/-- **The ordering, pinned.** A line the raw-wire classifier refuses is never
    parsed by the bridge: the gate is not consulted, the revision fold is
    untouched, and the exact continue result hands the line to `stepImpl`,
    whose identical classifier produces the fail-closed block. This is the
    depth-5000 regression's tombstone. -/
theorem gatePlanFor_refuse_continue (selection : McpRevisionSelection)
    (inputText line : String)
    (hl : stepLineOf? inputText = some line)
    (hr : classifyLine line = .refuse) :
    gatePlanFor selection inputText = (.continue, selection) := by
  simp [gatePlanFor, hl, hr]

/-- A malformed outer envelope gates nothing and observes nothing. -/
theorem gatePlanFor_badEnvelope_continue (selection : McpRevisionSelection)
    (inputText : String) (h : stepLineOf? inputText = none) :
    gatePlanFor selection inputText = (.continue, selection) := by
  simp [gatePlanFor, h]

/-- Observation strictly follows admission (the native gate-before-observe
    ordering): whenever the bridge's selection moved, the gate admitted the
    line. -/
theorem gatePlanFor_observe_only_admitted (selection : McpRevisionSelection)
    (inputText : String) :
    (gatePlanFor selection inputText).2 = selection ∨
      (gatePlanFor selection inputText).1 =
        SealV2.Effect.McpVersionGateDecision.continue := by
  unfold gatePlanFor
  split
  · exact .inl rfl
  · split
    · exact .inl rfl
    · split
      · exact .inr rfl
      · exact .inl rfl

/-! ### The receipt principal, modelled — `receipt_principal_authenticated`

The step-output `principal` member has exactly one producer
(`principalOutField`, shared by `stepImpl` and `stepRender`), and its value
is `stepPrincipalField` of the parse-path principal. The Lean half of the
obligation is below; the Rust half — "the receipt assembler wrote what the
step output says" — is the **R-PRINC seam** (`PrincipalFaithful`), the
`Host.ReceiptIdentity.IdentityFaithful` idiom: an explicit hypothesis, NEVER
an axiom, discharged operationally by
`rust/tests/principal_identity.rs` including the
plant-a-request-supplied-principal mutation drill. -/

/-- The model value of the step-output/receipt `principal` field: the
    parse-path-verified principal's id, or absent. -/
def stepPrincipalField (principal? : Option Host.AuthenticatedPrincipal) :
    Option String :=
  principal?.map (·.id)

/-- The output member IS the model value: `principalOutField` emits exactly
    the `stepPrincipalField` entry when present and nothing otherwise. -/
theorem principalOutField_lookup (principal? : Option Host.AuthenticatedPrincipal) :
    (principalOutField principal?).lookup "principal"
      = (stepPrincipalField principal?).map Json.str := by
  cases principal? <;> simp [principalOutField, stepPrincipalField]

/-- No principal, no field: unauthenticated steps emit byte-identical output
    to pre-V2.1 (the member list is empty, not null-valued). -/
theorem principalOutField_none :
    principalOutField none = [] := rfl

/-- If the output carries a principal entry, it is the id of the parse-path
    `AuthenticatedPrincipal` — never any other string. -/
theorem principalOutField_authenticated
    (principal? : Option Host.AuthenticatedPrincipal) (v : Json)
    (h : ("principal", v) ∈ principalOutField principal?) :
    ∃ p, principal? = some p ∧ v = Json.str p.id := by
  cases principal? with
  | none => cases h
  | some p =>
      simp only [principalOutField, List.mem_cons, List.not_mem_nil,
        or_false, Prod.mk.injEq] at h
      exact ⟨p, rfl, h.2⟩

/-- **R-PRINC (the TCB seam, made visible).** What the Rust receipt
    assembler wrote equals the model value of the step output. Explicit
    hypothesis, never an axiom; discharged by the differential test against
    the real binary (`rust/tests/principal_identity.rs`), including the
    mutation drill that plants a request-supplied principal and watches the
    test refuse it. -/
def PrincipalFaithful (written : Option String)
    (principal? : Option Host.AuthenticatedPrincipal) : Prop :=
  written = stepPrincipalField principal?

/-- A faithful receipt principal came from the parse-path verification:
    if the assembler wrote `some pid` under R-PRINC, there IS an
    `AuthenticatedPrincipal` with that id. -/
theorem faithful_principal_authenticated (written : Option String)
    (principal? : Option Host.AuthenticatedPrincipal) (pid : String)
    (hfaith : PrincipalFaithful written principal?)
    (h : written = some pid) :
    ∃ p, principal? = some p ∧ p.id = pid := by
  rw [hfaith] at h
  cases hp : principal? with
  | none => rw [hp] at h; cases h
  | some p =>
      rw [hp] at h
      simp only [stepPrincipalField, Option.map_some, Option.some.injEq] at h
      exact ⟨p, rfl, h⟩

/-- **`receipt_principal_authenticated` (Lean half, end to end).** Under the
    R-PRINC seam, a receipt that asserts principal `pid` for a step whose
    parse path ran `Host.verifyEnvelope` names a REGISTERED key's id whose
    envelope verified — never a request-derived string. (What stays TCB:
    Ed25519 unforgeability + extern faithfulness — that a VERIFYING envelope
    was really signed by the registered key — and the R-PRINC hypothesis
    itself, test-discharged.) -/
theorem receipt_principal_authenticated (authority : ByteArray)
    (reg : Host.PrincipalRegistry)
    (env : Host.Envelope) (line : String) (written : Option String)
    (pid : String)
    (hfaith : PrincipalFaithful written
      (Host.verifyEnvelope authority reg env line))
    (h : written = some pid) :
    ∃ k ∈ reg, k.id = pid := by
  obtain ⟨p, hp, hid⟩ := faithful_principal_authenticated written _ pid hfaith h
  obtain ⟨k, hk, hkid⟩ :=
    Host.verifyEnvelope_id_registered authority reg env line p hp
  exact ⟨k, hk, hkid.trans hid⟩

end Ffi

/-! ## Axiom pins — enforced at module build

The spelled step plan sits on Lean's three classical axioms at most; no
`sorryAx`, no `Lean.ofReduceBool`, and no new axioms — the program-equality
proof uses only core's lawful-monad laws and case analysis on the pure
plan. Drift fails the build here and again in `Test/Axioms.lean`. -/

/-- info: 'Ffi.stepLineOf?' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepLineOf?
/-- info: 'Ffi.gatePlanFor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.gatePlanFor
/-- info: 'Ffi.stepLineOf?_agrees' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepLineOf?_agrees
/-- info: 'Ffi.stepLineOf?_none_respond' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepLineOf?_none_respond
/-- info: 'Ffi.gatePlanFor_refuse_continue' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.gatePlanFor_refuse_continue
/-- info: 'Ffi.gatePlanFor_badEnvelope_continue' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.gatePlanFor_badEnvelope_continue
/-- info: 'Ffi.gatePlanFor_observe_only_admitted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.gatePlanFor_observe_only_admitted
/-- info: 'Ffi.stepInputsOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepInputsOf
/-- info: 'Ffi.stepPlanFor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepPlanFor
/-- info: 'Ffi.stepRender' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepRender
/-- info: 'Ffi.stepImpl_spelled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepImpl_spelled
/-- info: 'Ffi.principalOutField_lookup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.principalOutField_lookup
/-- info: 'Ffi.principalOutField_authenticated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.principalOutField_authenticated
/-- info: 'Ffi.faithful_principal_authenticated' depends on axioms: [propext] -/
#guard_msgs in #print axioms Ffi.faithful_principal_authenticated
/-- info: 'Ffi.receipt_principal_authenticated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.receipt_principal_authenticated
