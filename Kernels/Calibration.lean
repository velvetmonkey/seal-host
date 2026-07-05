/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Host.Kernel

namespace Kernels

/-- Config for the EXPERIMENTAL kernel K. `enabled` is the experimental flag:
    the host registers K only when it is true. `deltaNum/deltaDen` encode the
    risk tolerance δ ∈ (0,1); `minSamples` is the smallest evidence window K
    will accept (fewer records ⇒ deny, fail-closed); `gatedTools` are the
    confidence-conditioned tools K governs. -/
structure CalibrationConfig where
  enabled : Bool
  deltaNum : Nat
  deltaDen : Nat
  minSamples : Nat
  recordsFile : System.FilePath
  gatedTools : List String
  deriving Repr

/-- One forecast record: the model's stated confidence in [0,1] and the
    realised binary outcome. -/
structure ForecastRecord where
  confidence : Float
  outcome : Bool

/-- Empirical mean signed calibration error over the window:
    `mean (outcome - confidence)`. Perfectly calibrated forecasts centre this
    at 0. -/
def meanError (records : List ForecastRecord) : Float :=
  let n := records.length.toFloat
  let s := records.foldl
    (fun acc r => acc + ((if r.outcome then 1.0 else 0.0) - r.confidence)) 0.0
  s / n

/-- The Hoeffding/Azuma threshold `sqrt(ln(2/δ) / (2n))`.

    HONEST STATUS — trusted mirror, not extracted code: calibration-lean's
    `ProbabilityTheory.hasCondSubgaussianMGF_of_mem_Icc` proves the
    per-step forecast errors (bounded in [-1,1], conditionally centred) are
    conditionally sub-Gaussian with proxy ((b-a)/2)²; feeding that into
    Mathlib's Azuma-Hoeffding gives exactly this concentration rate for the
    empirical mean. The Lean theorem is Prop-level measure theory, so this
    Float computation is a documented trusted mirror of the bound, cited not
    extracted. That gap is one reason K stays experimental. -/
def hoeffdingThreshold (deltaNum deltaDen n : Nat) : Float :=
  if deltaNum == 0 || n == 0 then 0.0
  else Float.sqrt (Float.log (2.0 * deltaDen.toFloat / deltaNum.toFloat)
    / (2.0 * n.toFloat))

/-- Is the forecaster calibrated within the verified bound? Fail-closed on
    evidence: too few samples is a NO, not a benefit of the doubt. -/
def calibratedB (cfg : CalibrationConfig) (records : List ForecastRecord) : Bool :=
  records.length ≥ cfg.minSamples &&
    Float.abs (meanError records) ≤
      hoeffdingThreshold cfg.deltaNum cfg.deltaDen records.length

/-- Kernel K — the Calibration kernel (EXPERIMENTAL). Gates the configured
    confidence-conditioned tools on the forecaster's empirical calibration:
    if the recent forecast window's mean error exceeds the Hoeffding bound —
    or the window is too small to say — the action is denied (escalation is
    the operator's retry path). Stops overconfident-model auto-actions and a
    Brier loop trusting noise. -/
def calibrationKernel : Host.Kernel where
  name := "calibration"
  Config := CalibrationConfig
  Evidence := List ForecastRecord
  State := Unit
  init := ()
  gates := fun cfg act => cfg.gatedTools.contains act.tool
  ingest := fun _ st => st
  decide := fun act cfg records st =>
    let n := records.length
    if calibratedB cfg records then
      let reason := s!"forecaster calibrated over {n} samples: {act.tool}"
      ({ kernel := "calibration", kind := .allow, reason,
         certHash := Seal.auditHashParts ["calibration", "allow", reason] }, st)
    else
      let reason :=
        if n < cfg.minSamples then
          s!"calibration evidence insufficient ({n}/{cfg.minSamples} samples): {act.tool}"
        else
          s!"forecaster uncalibrated over {n} samples: {act.tool}"
      ({ kernel := "calibration", kind := .deny, reason,
         certHash := Seal.auditHashParts ["calibration", "deny", reason] }, st)

end Kernels
