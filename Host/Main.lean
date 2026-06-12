/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Std.Sync.Mutex
import Std.Time
import SealCore
import Seal.Channel
import Seal.Block
import Host.Canonical
import Host.Config
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

structure Args where
  config : System.FilePath
  publicKey : String
  cmd : String
  cmdArgs : Array String

def parseArgs (args : List String) : Except String Args :=
  match args with
  | "--config" :: config :: "--pubkey" :: publicKey :: "--" :: cmd :: rest =>
      .ok { config := System.FilePath.mk config, publicKey, cmd, cmdArgs := rest.toArray }
  | _ => .error "usage: seal-host --config <trusted.json> --pubkey <key> -- <server-cmd> <args...>"

def writeLocked (lock : Std.Mutex Unit) (out : IO.FS.Stream) (line : String) : IO Unit := do
  lock.atomically do
    out.putStr line
    out.flush

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
    CanonicalAction → IO Kernels.SafetyEvidence := fun _ => do
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
    CanonicalAction → IO Consensus.Checker.Votes := fun _ => do
  if (← cfg.votesFile.pathExists) then
    let text ← IO.FS.readFile cfg.votesFile
    pure <| text.splitOn "\n" |>.filterMap fun line =>
      let trimmed := line.trimAscii.toString
      if trimmed.isEmpty then none else
        match Json.parse trimmed with
        | .error _ => none
        | .ok j => do
            let acceptor ← (j.getObjVal? "acceptor").toOption.bind (·.getNat?.toOption)
            let value ← (j.getObjVal? "value").toOption.bind (·.getStr?.toOption)
            some (acceptor, value)
  else
    pure []

/-- Evidence gatherer for kernel K: read the forecast records file fresh per
    gated call. Malformed lines are skipped — a record that fails to parse
    shrinks the window, and a small window denies (fail-closed). -/
def gatherForecasts (cfg : Kernels.CalibrationConfig) :
    CanonicalAction → IO (List Kernels.ForecastRecord) := fun _ => do
  if (← cfg.recordsFile.pathExists) then
    let text ← IO.FS.readFile cfg.recordsFile
    pure <| text.splitOn "\n" |>.filterMap fun line =>
      let trimmed := line.trimAscii.toString
      if trimmed.isEmpty then none else
        match Json.parse trimmed with
        | .error _ => none
        | .ok j => do
            let confidence ← (j.getObjVal? "confidence").toOption.bind fun v =>
              match v with
              | .num n => some n.toFloat
              | _ => none
            let outcome ← (j.getObjVal? "outcome").toOption.bind (·.getNat?.toOption)
            if outcome == 0 || outcome == 1 then
              some { confidence, outcome := outcome == 1 }
            else
              none
  else
    pure []

/-- Evidence gatherer for kernel L: incrementally read freshly minted grants
    from the grants file (`{"cap": "<id>", "uses": <n>}` per line), each
    record exactly once via the seen counter — mirroring the approval channel.
    Malformed lines are skipped (a grant that fails to parse grants nothing,
    fail-closed). -/
def gatherGrants (cfg : Kernels.LinearConfig) (seenRef : IO.Ref Nat) :
    CanonicalAction → IO (List LinearCore.LEvent) := fun _ => do
  if (← cfg.grantsFile.pathExists) then
    let text ← IO.FS.readFile cfg.grantsFile
    let records := text.splitOn "\n" |>.filter
      (fun line => !(line.trimAscii.toString).isEmpty)
    let seen ← seenRef.get
    let fresh := records.drop seen
    seenRef.set records.length
    pure <| fresh.filterMap fun line =>
      match Json.parse line.trimAscii.toString with
      | .error _ => none
      | .ok j => do
          let cap ← (j.getObjVal? "cap").toOption.bind (·.getStr?.toOption)
          let uses ← (j.getObjVal? "uses").toOption.bind (·.getNat?.toOption)
          some (LinearCore.LEvent.grant cap uses)
  else
    pure []

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
  | .blockMalformed id =>
      IO.eprintln (auditLine epoch "<non-canonical>" .deny [])
      writeLocked stdoutLock hostOut (Seal.blockResponseLine id "non-canonical payload")
  | .act act => do
      let (combined, verdicts) ← dispatch registry act
      IO.eprintln (auditLine epoch act.tool combined verdicts)
      match combined with
      | .allow =>
          childIn.putStr hostLine
          childIn.flush
      | .deny =>
          writeLocked stdoutLock hostOut (Seal.blockResponseLine act.requestId (denyReason verdicts))

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
           gather := gatherVotes cfg }]
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
             gather := gatherForecasts cfg }]
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
           gather := gatherGrants cfg linearSeenRef }]
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
      gather := gatherSafetyEvidence config.safety approvalSeenRef },
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

def main (args : List String) : IO UInt32 :=
  Host.main args
