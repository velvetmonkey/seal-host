# seal — Decision Log

Append-only. Newest last.

**What belongs here.** Decisions, and specifically **the paths we rejected and why**. Commit
messages record what we did; they are a poor place to record what we deliberately did not do. That
second thing is what gets re-litigated, usually by someone with a plausible-sounding idea we already
tested and discarded.

**What does not belong here.** Anything the code, `CLAIMS.md`, `PINS.md` or `THREAT_MODEL.md`
already says. This file is not a summary. If a decision produced a pin, `PINS.md` owns the pin and
this file owns the reasoning.

**Format.** Date, the decision, the alternatives rejected, the evidence that settled it. Keep the
evidence concrete enough that a reader can re-run it and disagree.

---

## 2026-07-24 — Close the duplicate-key mediation bypass at the raw wire, not at the canonical parse

**Decision.** Wire `wireKeysSafe` and `wireDigitsSafe` into `classifyLine` as fail-closed guards,
and repin the kernel 37 commits forward to get them.

**Rejected: switch the routing profile to `canonicalL0`.** This was the attractive option because it
needs no repin: the already-pinned canonical parser rejects duplicate keys, and `canonicalL0` blocks
on `ast? = none`, so the hole closes with the kernel already deployed. Both its properties are
proven.

**Why it was rejected.** Measured, not argued. An additive harness compared the V1 reading against
`SealV2.parse` over the repository corpora. `canonicalL0` would newly block 10 lines, of which
**one** is the defect. The other nine are ordinary RFC 8259 JSON that any well-behaved client emits:
exponent forms (`1e-9`, `1e3`), trailing fractional zeros (`1.0`, `1.20`), negative zero, and any
literal non-ASCII string content. Python's `json.dumps(1.0)` emits `1.0`. Any accented character in
an argument emits literal UTF-8. Gating on the canonical parse breaks both.

**The trap worth remembering.** The recorded-demo slice measured **0 of 52** blocked, a perfectly
clean zero. That zero is meaningless: every demo request is ASCII with integer arguments, so the
corpus cannot exhibit the failure. Taking it as "the flip is free" would have been a textbook case
of a green check measuring the wrong thing, which is this project's signature defect.

**Rejected: hand-roll a duplicate-key guard in `seal-host`.** That is re-implementing a security
gate that already exists in the kernel, which is precisely the parser-divergence disease the bug
came from.

---

## 2026-07-24 — Move one pin, not five

**Decision.** Repin only `mcp-seal`. Leave `calibration-lean`, `consensus-lean`,
`temporal-logic-lean` and `crdt-lean` where they are.

**Rejected: a coordinated repin of all five.** Reasonable instinct, since all five were stale.

**Why.** Only one carried security. The `mcp-seal` gap held an Ed25519 malleability fix (RFC 8032
5.1.7 S-range), Stage A, Stage B2's empty/zero bypass removal, the nonce ledger, and the two wire
guards. The other four gaps were documentation, CI badges and proofs this host does not consume.
Rolling them in would have added four repos of fresh Lean build surface to a security repin for zero
benefit here. They can ride along on a later sweep where a red costs nothing.

---

## 2026-07-24 — Take the `UnicodeBasic` dependency rather than hand-roll decomposition

**Decision.** Accept `fgdorais/lean4-unicode-basic`, pinned by revision, for canonical
decomposition data in `Host/UnicodeKeys.lean`. Add a test pinning the behaviour we actually rely on.

**Rejected: implement NFD identity ourselves.** That means shipping our own copy of the Unicode
decomposition tables with less review than the library gets. Purer in appearance, worse in fact.

**Rejected: treat the gap as a documented residual and change nothing.** Defensible until you find a
real normalising child. Swift specifies that `String ==` uses canonical equivalence, `String` is an
ordinary `Dictionary` key, Foundation's JSON parser builds `[String: JSONValue]` by assignment, and
the official MCP Swift SDK decodes with Foundation. So the normalising child is any MCP server built
on Apple's own SDK. Not hypothetical.

**The condition attached.** A dependency is acceptable when you pin what you lean on. The guard
rejects a repeated canonical identity only; it does NOT reject non-ASCII keys, because that would
reintroduce the over-blocking rejected above.

---

## 2026-07-24 — Do not move `a3.rs` freshness logic behind the Lean boundary yet

**Decision.** Defer, despite three independent advisors recommending it.

**Why.** One of the three, in the same response, identified the flaw in the design all three had
proposed: if freshness moves to Lean while the nonce store stays in Rust, the host inserts the nonce
durably and then calls Lean. If that call fails, the nonce is consumed with no decision rendered.
That needs a two-phase answer before any code moves. Implementing the unanimous recommendation
immediately would have baked in the exact defect the exercise was run to find.

**Note on the current design.** The existing ordering fails CLOSED: the nonce is burned before the
decision lands, so a failure between them costs a legitimate caller their token and authorises
nothing. The in-memory cache is rebuilt from the durable store at startup and is only ever a
fast-path reject, so it cannot be more permissive than the durable record.

---

## 2026-07-24 — Do not adopt a thin host wholesale

**Decision.** Keep the principle as a direction, not a programme. Build the measurement ratchet
first.

**Why.** The premise is contested and the objection is specific: the FFI glue is already thin, and
the defect found this week was in the routing logic, which is not. "So thin that inspection
suffices" can mean "so thin we did not bother to formalise it". Two advisors backed the thin-host
direction, one rejected it, and the disagreement is unresolved. Building a programme on a contested
foundation is how three weeks disappear.

**What to do instead.** Count security decision sites (not functions, which is too coarse) and gate
the count in CI, so a change that adds a new unverified security decision has to justify itself.
That needs no architectural commitment and cannot silently regress.

---

## 2026-07-24 — Process: how findings are handled

**Never hand a reviewer the hypothesis.** A brief that states the suspected defect and asks for
confirmation produces confirmation. State the system and the security claim, ask them to break it,
require a "what I tried that did not work" section, and explicitly permit the null result.

**Classify against the code before recording a finding.** Of six sites recorded in one review, five
did not exist in either codebase; they were specification terms. Of four findings from another, two
were already disclosed in the source, in sections written to disclose them. A finding that is
already written down is not a finding.

**Verify every citation.** In one evening, reviewers produced a fabricated SHA256 digest presented
as computed, a fabricated line number, fabricated paper citations, and one misattributed venue. The
findings around them were often real. The reviewers are useful and are never quoted without
checking.
