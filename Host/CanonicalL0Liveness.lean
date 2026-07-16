/- SPDX-License-Identifier: Apache-2.0 -/

import Host.CanonicalL0

/-!
# Non-vacuity evidence for `canonical-l0` (the expensive half)

Companion to `Host/CanonicalL0.lean` (see its liveness section for the full
theorem-vs-`#guard` split rationale). This file is a leaf module because its
kernel evaluations peak near 12 GiB — they get a `lean` process of their own.

* THEOREMS (kernel, zero extra axioms): `SealV2.parse` really rejects
  non-canonical bytes (string-escape and decimal reject classes) and really
  accepts genuinely canonical bytes — the semantic property, on minimal
  exemplars the kernel can chew. (The duplicate-key reject class does not
  fit: its minimal 13-char exemplar OOMs a 12 GiB kernel evaluation —
  measured on this development — so it is covered by the full-line `#guard`
  instead.)
* `#guard`s (build-gated TESTS, not kernel theorems, no axiom introduced):
  the REAL 69-char nested wire lines end-to-end — V1 recognition, attached
  witness state, and the profile route. Full-size parses exceed kernel memory
  and `Lean.Json.parse` is `partial`-opaque; `native_decide` would evaluate
  them but is refused — it buys the theorem at the price of
  `Lean.ofReduceBool`, torching the zero-extra-axiom property.
-/

namespace Host

/- Reject-side kernel theorems. The duplicate-key reject class — the one the
   real wire line below exercises — does NOT fit this machine as a kernel
   theorem: even the minimal 13-char duplicate-key object OOMs a 12 GiB
   kernel evaluation (object parsing re-checks canonicity per level; the
   blowup is in kernel whnf, measured on this development). The reject-class
   SEMANTIC property (canonical parser rejects non-canonical bytes) is
   kernel-proved on the two exemplar classes that DO fit — a non-canonical
   string escape and a non-canonical decimal — and the duplicate-key case is
   exercised end-to-end on the real wire line by the `#guard`s below. -/

set_option maxHeartbeats 8000000 in
/-- The canonical parser really rejects non-canonical bytes: `A` is a
    non-canonical escape for `A` (kernel evaluation, string reject class). -/
theorem sealV2_rejects_noncanonical_escape :
    (SealV2.parse "\"\\u0041\"").isNone = true := of_decide_eq_true rfl

set_option maxHeartbeats 8000000 in
/-- The canonical parser really rejects non-canonical bytes: `1.50` carries a
    trailing zero (kernel evaluation, decimal reject class). -/
theorem sealV2_rejects_noncanonical_decimal :
    (SealV2.parse "1.50").isNone = true := of_decide_eq_true rfl

set_option maxHeartbeats 8000000 in
/-- The canonical parser really accepts canonical bytes (kernel evaluation of
    the minimal exemplar). -/
theorem sealV2_accepts_canonical :
    (SealV2.parse "{\"a\":1}").isSome = true := of_decide_eq_true rfl

-- Build-gated end-to-end liveness on the REAL wire lines (evaluator: the
-- steps the kernel cannot do — `Lean.Json.parse` recognition and the
-- full-size canonical parses).
#guard (match classifyLine nonCanonicalLine with
        | .act a => a.ast?.isNone
        | .passthrough => false
        | .refuse => false)
#guard stepRouteP .canonicalL0 (classifyLine nonCanonicalLine) [allowVerdict] == .block
#guard (match classifyLine canonicalLine with
        | .act a => a.ast?.isSome
        | .passthrough => false
        | .refuse => false)
#guard stepRouteP .canonicalL0 (classifyLine canonicalLine) [allowVerdict] == .forward
-- COMPATIBLE contrast: the same non-canonical line FORWARDS under the deployed
-- profile — exactly the gap `canonicalL0` closes.
#guard stepRouteP .compatible (classifyLine nonCanonicalLine) [allowVerdict] == .forward

end Host
