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
  let registry : Registry := [{
    kernel := Kernels.safetyKernel
    config := config.safety
    stateRef := safetyStateRef
    gather := gatherSafetyEvidence config.safety approvalSeenRef
  }]
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
