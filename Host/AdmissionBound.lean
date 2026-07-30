/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# A necessary condition for durable-state instance binding (residual A7)

`CLAIMS.md` residual **A7 (replay-store instance integrity)** records, in
prose, that the host cannot detect substitution of its durable replay store
by a principal who can write the store path: the host's admission decision is
computed from the trusted config and the store's own bytes, and both of those
inputs are available to the party that provisions the store. This module
turns that prose limitation into a proved boundary.

## The model

Everything is information-theoretic and abstract. There are no files, no
SQLite, no byte layouts — only:

* `Cfg`     — configuration; its bytes are public, every party reads them.
* `Store`   — a candidate durable store, carrying a recorded history
              (`hist : Store → History`, e.g. the set of consumed nonces).
* `admit`   — the admission predicate the host evaluates at startup.
* `Producible cfg st` — the provisioning party can bring `st` into being:
  it reads `cfg` and writes the store bytes, so it can produce any store
  describable as a function of `cfg`. Since it has unrestricted write
  capability, `producible_of_writer` shows this is EVERY store — that
  collapse is not a modelling accident, it is the content of the hypothesis
  "the attacker holds write access to the store path" from the A7 ruling
  (council `5c3845e7`, shape (D)).

Two properties of an admission predicate:

* `Complete hist admit` — every history is admissible under some store:
  the store format supports arbitrary legitimate histories, and a genuine
  store must be admitted whatever it has recorded. A host that rejects some
  reachable history bricks a legitimate deployment, so completeness is not
  optional.
* `BindsTo hist admit cfg st₀` — soundness of instance binding at `(cfg,
  st₀)`: every store admitted under `cfg` records the same history as the
  genuine store `st₀`.

## Results

* `admissible_forgery` — the headline impossibility: any complete two-input
  predicate admits, for every accepted `(cfg, st₀)` and every other history,
  a producible store recording that other history.
* `no_two_input_binding` — `Complete` and `BindsTo` are jointly
  contradictory once two distinct histories exist.
* `binding_needs_underivable_input` — the necessary-condition corollary: a
  three-input predicate that IS complete and binding cannot factor through
  `(cfg, st)`; it must depend on its third input.
* `NonVacuity.admitW_needs_witness` — the condition is satisfiable: a
  predicate consulting an out-of-band witness is complete and binding, and
  (by the corollary) provably does not factor through `(cfg, st)`.
* `NonceFutility.nonce_stamp_futile` — the folk fix ("name a fresh
  identifier in `cfg`, stamp it in `st`") instantiates the impossibility,
  not the escape: the stamp check is still a function of `(cfg, st)`.
-/

namespace Host.AdmissionBound

section Model

variable {Cfg Store History : Type}

/-- The provisioning party reads `cfg` and writes the store bytes, so it can
produce any store it can describe from what it reads: `st` is producible
under `cfg` iff `st` is the value of some function of `cfg`. -/
def Producible (cfg : Cfg) (st : Store) : Prop :=
  ∃ f : Cfg → Store, f cfg = st

/-- With unrestricted write capability the description need not even consult
`cfg`: every store is producible. This collapse is the formal content of
"attacker holds write access to the store path". -/
theorem producible_of_writer (cfg : Cfg) (st : Store) : Producible cfg st :=
  ⟨fun _ => st, rfl⟩

/-- `admit` is complete when, under every config, every history is recorded
by some admitted store. A genuine store must be admitted whatever it has
legitimately recorded, so a usable admission predicate is complete. -/
def Complete (hist : Store → History) (admit : Cfg → Store → Bool) : Prop :=
  ∀ (cfg : Cfg) (h : History), ∃ st : Store, hist st = h ∧ admit cfg st = true

/-- `admit` binds the instance at `(cfg, st₀)` when every store it admits
under `cfg` records the genuine store `st₀`'s history — i.e. substituting a
store with a different history is detected. -/
def BindsTo (hist : Store → History) (admit : Cfg → Store → Bool)
    (cfg : Cfg) (st₀ : Store) : Prop :=
  ∀ st : Store, admit cfg st = true → hist st = hist st₀

/-- **Headline impossibility (residual A7 as a theorem).**

Any admission predicate whose value is determined by `(cfg, st)` alone —
which is exactly what `admit : Cfg → Store → Bool` says — cannot separate a
store that has recorded a particular history from a distinct store that has
not, when both are producible by the provisioning party: for every accepted
`(cfg, st₀)` and every history `h₁` different from `st₀`'s, completeness
hands the provisioning party an admissible store recording `h₁` instead.

Real-world reading: this is `CLAIMS.md` residual A7. The host opens its
replay store, checks whatever it likes about the config and the store's
bytes, and admits it; a backup restore, blue/green rollback, or stale prior
init with a different consumed-nonce history passes the same check, and
every nonce the displaced store had consumed is re-accepted within its TTL.
Naming a fresh identifier inside `cfg` and stamping the same identifier
inside `st` does not help: both are inputs the provisioning party can read
and produce, so the stamped store is still producible (see
`NonceFutility.nonce_stamp_futile`) — which is why a longer random constant
is no improvement over a shorter universal one.

What this does NOT say: it does not say the deployment is unprotected, and
it does not say instance binding is impossible outright. It says the
separation must come from somewhere other than these two inputs — see
`binding_needs_underivable_input` for that necessary condition and
`NonVacuity.admitW_needs_witness` for a predicate that succeeds by
consulting a third, out-of-band input. -/
theorem admissible_forgery
    (hist : Store → History) (admit : Cfg → Store → Bool)
    (hC : Complete hist admit)
    (cfg : Cfg) (st₀ : Store) (_accepted : admit cfg st₀ = true)
    (h₁ : History) (hne : h₁ ≠ hist st₀) :
    ∃ st₁ : Store, hist st₁ ≠ hist st₀ ∧ admit cfg st₁ = true
      ∧ Producible cfg st₁ := by
  obtain ⟨st₁, hh, ha⟩ := hC cfg h₁
  exact ⟨st₁, by rw [hh]; exact hne, ha, producible_of_writer cfg st₁⟩

/-- Completeness and instance binding are jointly impossible for a two-input
predicate once even two distinct histories exist. This is
`admissible_forgery` folded into contradiction form. -/
theorem no_two_input_binding
    (hist : Store → History) (admit : Cfg → Store → Bool)
    (hC : Complete hist admit)
    (cfg : Cfg) (st₀ : Store) (hB : BindsTo hist admit cfg st₀)
    (h₁ : History) (hne : h₁ ≠ hist st₀) : False := by
  obtain ⟨st₁, hh, ha⟩ := hC cfg h₁
  exact hne (hh.symm.trans (hB st₁ ha))

end Model

section NecessaryCondition

variable {Cfg Store History Aux : Type}

/-- A three-input predicate factors through `(cfg, st)` when its value is
already determined by those two inputs — the third input is ignored, i.e.
everything the predicate consults is derivable from `(cfg, st)`. -/
def FactorsThroughCfgStore (admit : Cfg → Store → Aux → Bool) : Prop :=
  ∃ g : Cfg → Store → Bool, ∀ (cfg : Cfg) (st : Store) (a : Aux),
    admit cfg st a = g cfg st

/-- **Necessary condition.**

A sound instance-binding admission predicate must depend on some value that
is NOT derivable from `(cfg, st)`.

Formally: let `admit` also receive an auxiliary input, provisioned per
instance by `auxOf` from the history the instance is bound to (an
out-of-band witness — an authority-held commitment, sealed hardware state,
an operator secret). If `admit` is complete (`hC`: every history has an
admitted store on its own instance) and binding (`hB`: under instance
`auxOf h₀`, only stores recording `h₀` are admitted), and two distinct
histories exist, then `admit` cannot factor through `(cfg, st)`: any `g`
agreeing with `admit` on all auxiliary values would admit, under the
`h₀`-instance, the store that the `h₁`-instance admits.

What this does NOT say: it does not exhibit the witness channel, price it,
or claim any particular mechanism is sound — it only says the two inputs
the provisioning party reads and writes cannot carry the separation. -/
theorem binding_needs_underivable_input
    (hist : Store → History) (admit : Cfg → Store → Aux → Bool)
    (auxOf : History → Aux)
    (hC : ∀ (cfg : Cfg) (h : History),
      ∃ st : Store, hist st = h ∧ admit cfg st (auxOf h) = true)
    (hB : ∀ (cfg : Cfg) (h₀ : History) (st : Store),
      admit cfg st (auxOf h₀) = true → hist st = h₀)
    (cfg : Cfg) (h₀ h₁ : History) (hne : h₀ ≠ h₁) :
    ¬ FactorsThroughCfgStore admit := by
  rintro ⟨g, hg⟩
  obtain ⟨st₁, hh, ha⟩ := hC cfg h₁
  have hswap : admit cfg st₁ (auxOf h₀) = true := by
    rw [hg cfg st₁ (auxOf h₀), ← hg cfg st₁ (auxOf h₁)]
    exact ha
  exact hne ((hB cfg h₀ st₁ hswap).symm.trans hh)

end NecessaryCondition

/-! ## Non-vacuity: the condition can be met

Without this the results above read as defeatism. A predicate that may
consult a third input the provisioning party cannot produce — here an
out-of-band witness naming the bound history — is complete, binding, and
therefore (by `binding_needs_underivable_input`) provably NOT a function of
`(cfg, st)`. The theorems delimit a class of predicate that fails; they do
not say nothing works. -/
namespace NonVacuity

/-- Recorded histories; any type with two distinct values would do. -/
abbrev History := Nat

/-- A store records a history; `payload` witnesses that distinct stores may
share one (the admission problem is about histories, not store identity). -/
structure Store where
  history : History
  payload : Nat

/-- Config carries nothing here — the separation comes from the witness. -/
abbrev Cfg := Unit

/-- The out-of-band input: a witness naming the history the instance is
bound to, held where the provisioning party cannot forge it. -/
abbrev Witness := History

/-- Admit exactly the stores recording the witnessed history. -/
def admitW : Cfg → Store → Witness → Bool :=
  fun _ st w => decide (st.history = w)

/-- `admitW` is complete on each instance: every history has an admitted
store under its own witness. -/
theorem admitW_complete (cfg : Cfg) (h : History) :
    ∃ st : Store, st.history = h ∧ admitW cfg st ((id : History → Witness) h) = true :=
  ⟨⟨h, 0⟩, rfl, decide_eq_true rfl⟩

/-- `admitW` is binding on each instance: under witness `h₀`, only stores
recording `h₀` are admitted. -/
theorem admitW_binding (cfg : Cfg) (h₀ : History) (st : Store)
    (ha : admitW cfg st ((id : History → Witness) h₀) = true) :
    st.history = h₀ :=
  of_decide_eq_true ha

/-- **Non-vacuity separation.** `admitW` meets both hypotheses of the
necessary-condition theorem, so that theorem applies to it: `admitW` is a
sound, complete instance binder, and consequently is provably NOT expressible
as any function of `(cfg, st)` alone. The extra input it consults is the
out-of-band witness of the bound history. -/
theorem admitW_needs_witness : ¬ FactorsThroughCfgStore admitW :=
  binding_needs_underivable_input Store.history admitW id
    admitW_complete admitW_binding () 0 1 (by decide)

end NonVacuity

/-! ## The folk fix, refuted by instantiation

"Put a fresh random identifier in the config and stamp it into the store."
The stamp check is a two-input predicate, so the headline impossibility
applies verbatim: the stamp survives every substitution the provisioning
party cares to perform, because the party reads `cfg` (where the identifier
is public) and writes `st` (where the stamp lives). -/
namespace NonceFutility

/-- Config IS the fresh identifier (its bytes are public either way). -/
abbrev Cfg := Nat

/-- A store stamped with an identifier, recording a history. -/
structure Store where
  stamp : Nat
  history : Nat

/-- Admit any store whose stamp matches the config's identifier. -/
def admitN : Cfg → Store → Bool :=
  fun cfg st => decide (st.stamp = cfg)

/-- The stamp check is complete: any history can be recorded under a
correctly-stamped store. -/
theorem admitN_complete : Complete Store.history admitN :=
  fun cfg h => ⟨⟨cfg, h⟩, rfl, decide_eq_true rfl⟩

/-- **Nonce-stamp futility.** For every accepted `(cfg, st₀)` and every
other history there is a producible, admitted store recording that history:
stamping the config's identifier into the store separates nothing, no matter
how long or how fresh the identifier is. Direct instance of
`admissible_forgery`. -/
theorem nonce_stamp_futile
    (cfg : Cfg) (st₀ : Store) (accepted : admitN cfg st₀ = true)
    (h₁ : Nat) (hne : h₁ ≠ st₀.history) :
    ∃ st₁ : Store, st₁.history ≠ st₀.history ∧ admitN cfg st₁ = true
      ∧ Producible cfg st₁ :=
  admissible_forgery Store.history admitN admitN_complete cfg st₀ accepted h₁ hne

end NonceFutility

/-! ## Axiom hygiene

Every headline result, checked in-file. Accepted baseline:
`[propext, Classical.choice, Quot.sound]`; these proofs are constructive
enough to use at most `propext` (via `decide`) — the check below prints the
actual footprint. -/

#print axioms admissible_forgery
#print axioms no_two_input_binding
#print axioms binding_needs_underivable_input
#print axioms NonVacuity.admitW_needs_witness
#print axioms NonceFutility.nonce_stamp_futile

end Host.AdmissionBound
