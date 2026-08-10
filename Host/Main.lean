/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Std.Sync.Mutex
import Std.Time
import SealCore
import Seal.Channel
import Seal.Block
import Host.Canonical
import Host.Config
import Host.Evidence
import Host.Registry
import Host.Audit
import Kernels.Safety
import Kernels.Temporal
import Kernels.Consensus
import Kernels.Convergence
import Kernels.Calibration
import Kernels.Linear
import Kernels.Budget

namespace Host

open Lean

/-- Parsed command line of the pure-Lean demo host. -/
structure Args where
  /-- Path to the signed trusted-config JSON bundle. -/
  config : System.FilePath
  /-- Hex-encoded public key the config bundle's signature is checked against. -/
  publicKey : String
  /-- The wrapped MCP server executable. -/
  cmd : String
  /-- Arguments passed through to the wrapped server. -/
  cmdArgs : Array String

/-- Parse the fixed `--config <file> --pubkey <hex> -- <cmd> <args...>` command
    line, or return the usage string. -/
def parseArgs (args : List String) : Except String Args :=
  match args with
  | "--config" :: config :: "--pubkey" :: publicKey :: "--" :: cmd :: rest =>
      .ok { config := System.FilePath.mk config, publicKey, cmd, cmdArgs := rest.toArray }
  | _ => .error "usage: seal-host --config <trusted.json> --pubkey <config-pubkey-hex> -- <server-cmd> <args...>"

/-- Write one line to the shared output stream under the stdout mutex, so host
    verdicts and relayed child output never interleave mid-line. -/
def writeLocked (lock : Std.Mutex Unit) (out : IO.FS.Stream) (line : String) : IO Unit := do
  lock.atomically do
    out.putStr line
    out.flush

/-- Relay the wrapped server's stdout to the host's stdout line-by-line (under
    the stdout mutex) until the child closes its end. -/
partial def relayChildStdout (lock : Std.Mutex Unit) (childOut : IO.FS.Handle)
    (hostOut : IO.FS.Stream) : IO Unit := do
  let line ← childOut.getLine
  if line.isEmpty then
    pure ()
  else
    writeLocked lock hostOut line
    relayChildStdout lock childOut hostOut

/-- Evidence gatherer for kernel S — exactly the V1 host's pre-decision IO
    (`Seal/Main.lean` processHostLine): one wall-clock reading per call, and
    each approval record ingested exactly once via the seen counter. -/
def gatherSafetyEvidence (policy : Seal.Policy) (approvalSeenRef : IO.Ref Nat) :
    IO Kernels.SafetyEvidence := do
  let nowTs ← Std.Time.Timestamp.now
  let now := nowTs.toMillisecondsSinceUnixEpoch.toInt.toNat
  let seen ← approvalSeenRef.get
  let (newSeen, approvals) ← Seal.readApprovalsFrom policy.approvalFile seen now policy.approvalTtlMs
  approvalSeenRef.set newSeen
  pure { now, approvalEvents := approvals }

/-- Evidence gatherer for kernel C: read the votes file fresh per gated call.
    Malformed lines are skipped — a vote that fails to parse simply does not
    exist, which can only shrink a quorum (fail-closed for allow). -/
def gatherVotes (cfg : Kernels.ConsensusConfig) :
    IO Consensus.Checker.Votes := do
  if (← cfg.votesFile.pathExists) then
    pure <| Evidence.parseVotesText (← IO.FS.readFile cfg.votesFile)
  else
    pure []

/-- Evidence gatherer for kernel K: read the forecast records file fresh per
    gated call. Malformed lines are skipped — a record that fails to parse
    shrinks the window, and a small window denies (fail-closed). -/
def gatherForecasts (cfg : Kernels.CalibrationConfig) :
    IO (List Kernels.ForecastRecord) := do
  if (← cfg.recordsFile.pathExists) then
    pure <| Evidence.parseForecastsText (← IO.FS.readFile cfg.recordsFile)
  else
    pure []

/-- Evidence gatherer for kernel L: incrementally read freshly minted grants
    from the grants file (`{"cap": "<id>", "uses": <n>}` per line), each
    record exactly once via the seen counter — mirroring the approval channel.
    Malformed lines are skipped (a grant that fails to parse grants nothing,
    fail-closed). -/
def gatherGrants (cfg : Kernels.LinearConfig) (seenRef : IO.Ref Nat) :
    IO (List LinearCore.LEvent) := do
  if (← cfg.grantsFile.pathExists) then
    let text ← IO.FS.readFile cfg.grantsFile
    let records := text.splitOn "\n" |>.filter
      (fun line => !(line.trimAscii.toString).isEmpty)
    let seen ← seenRef.get
    let fresh := records.drop seen
    seenRef.set records.length
    pure <| Evidence.parseGrantsText ("\n".intercalate fresh)
  else
    pure []

/-- Mediate one client line: passthrough forwards it to the child untouched,
    refuse blocks it fail-closed, and a classified `tools/call` is dispatched
    through the kernel registry — forwarded on a combined allow, answered with
    a block response on deny, with an audit line either way. -/
def processHostLine
    (epoch : Nat)
    (registry : Registry)
    (hostLine : String)
    (childIn : IO.FS.Handle)
    (hostOut : IO.FS.Stream)
    (stdoutLock : Std.Mutex Unit) : IO Unit := do
  match classifyLine hostLine with
  | .passthrough =>
      childIn.putStr hostLine
      childIn.flush
  | .refuse =>
      -- Pathological numeric literal: fail closed. Block, do not forward.
      writeLocked stdoutLock hostOut
        (Seal.blockResponseLine Lean.Json.null "unsafe numeric literal")
  | .act act => do
      let (combined, verdicts) ← dispatch registry act
      -- This pure-Lean demo host commits to `hostLine` exactly as classified;
      -- its line framing differs from the deployed Rust host's `lean_view`
      -- (the deployed contract is the Rust path).
      IO.eprintln (auditLine epoch act.tool combined verdicts hostLine)
      match combined with
      | .allow =>
          childIn.putStr hostLine
          childIn.flush
      | .deny =>
          writeLocked stdoutLock hostOut (Seal.blockResponseLine act.requestId (denyReason verdicts))

/-- Read client lines from `hostIn` and mediate each via `processHostLine`
    until EOF. -/
partial def hostLoop
    (epoch : Nat)
    (registry : Registry)
    (hostIn hostOut : IO.FS.Stream)
    (childIn : IO.FS.Handle)
    (stdoutLock : Std.Mutex Unit) : IO Unit := do
  let line ← hostIn.getLine
  if line.isEmpty then
    pure ()
  else
    processHostLine epoch registry line childIn hostOut stdoutLock
    hostLoop epoch registry hostIn hostOut childIn stdoutLock

/-- Entry point of the pure-Lean demo host: load and verify the trusted
    config (fail-closed before any stdio is mediated), spawn the wrapped
    server, assemble the kernel registry from the config's deployed sections,
    then mediate stdin until EOF and return the child's exit code. -/
def main (rawArgs : List String) : IO UInt32 := do
  let parsed ←
    match parseArgs rawArgs with
    | .ok parsed => pure parsed
    | .error msg =>
        IO.eprintln msg
        return 2
  -- Fail-closed: a rejected config aborts here, before any stdio is mediated.
  let config ←
    try
      loadTrustedConfig parsed.config parsed.publicKey
    catch e =>
      IO.eprintln (toString e)
      return (3 : UInt32)
  Seal.ensureApprovalFile config.safety.approvalFile
  let child ← IO.Process.spawn {
    cmd := parsed.cmd,
    args := parsed.cmdArgs,
    stdin := .piped,
    stdout := .piped,
    stderr := .inherit
  }
  let hostIn ← IO.getStdin
  let hostOut ← IO.getStdout
  let stdoutLock ← Std.Mutex.new ()
  let approvalSeenRef ← IO.mkRef 0
  let safetyStateRef ← IO.mkRef Kernels.safetyKernel.init
  let temporalStateRef ← IO.mkRef Kernels.temporalKernel.init
  let consensusStateRef ← IO.mkRef Kernels.consensusKernel.init
  let consensusEntries : Registry :=
    match config.consensus with
    | some cfg =>
        [{ kernel := Kernels.consensusKernel
           config := cfg
           stateRef := consensusStateRef
           gather := fun _ => gatherVotes cfg }]
    | none => []
  let convergenceStateRef ← IO.mkRef Kernels.convergenceKernel.init
  let convergenceEntries : Registry :=
    if config.convergence.isEmpty then []
    else
      [{ kernel := Kernels.convergenceKernel
         config := config.convergence
         stateRef := convergenceStateRef
         gather := fun _ => pure () }]
  let calibrationStateRef ← IO.mkRef Kernels.calibrationKernel.init
  -- EXPERIMENTAL flag: K registers only when calibration.enabled is true.
  let calibrationEntries : Registry :=
    match config.calibration with
    | some cfg =>
        if cfg.enabled then
          [{ kernel := Kernels.calibrationKernel
             config := cfg
             stateRef := calibrationStateRef
             gather := fun _ => gatherForecasts cfg }]
        else []
    | none => []
  let linearStateRef ← IO.mkRef Kernels.linearKernel.init
  let linearSeenRef ← IO.mkRef 0
  let linearEntries : Registry :=
    match config.linear with
    | some cfg =>
        [{ kernel := Kernels.linearKernel
           config := cfg
           stateRef := linearStateRef
           gather := fun _ => gatherGrants cfg linearSeenRef }]
    | none => []
  let budgetStateRef ← IO.mkRef Kernels.budgetKernel.init
  let budgetEntries : Registry :=
    if config.budget.isEmpty then []
    else
      [{ kernel := Kernels.budgetKernel
         config := config.budget
         stateRef := budgetStateRef
         gather := fun _ => pure () }]
  let registry : Registry := [
    { kernel := Kernels.safetyKernel
      config := config.safety
      stateRef := safetyStateRef
      gather := fun _ => gatherSafetyEvidence config.safety approvalSeenRef },
    { kernel := Kernels.temporalKernel
      config := config.temporal
      stateRef := temporalStateRef
      gather := fun _ => pure () }
  ] ++ consensusEntries ++ convergenceEntries ++ calibrationEntries
    ++ linearEntries ++ budgetEntries
  let relayTask ← IO.asTask (relayChildStdout stdoutLock child.stdout hostOut) Task.Priority.dedicated
  hostLoop config.epoch registry hostIn hostOut child.stdin stdoutLock
  child.kill
  let exitCode ← child.wait
  match relayTask.get with
  | .ok _ => pure ()
  | .error err => throw err
  pure exitCode

end Host

/-- Executable entry point; defers to `Host.main`. -/
def main (args : List String) : IO UInt32 :=
  Host.main args
