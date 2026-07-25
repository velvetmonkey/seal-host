# Method: building things that are actually locked down

Every rule here was paid for. Each one names the instance that taught it, because a methodology
document full of "write good tests" is worth nothing, and one that says "here is the green check
that lied to us and here is what would have caught it" is worth reading twice.

This is written for a Lean-plus-Rust product with a verified core and an unverified shell, but most
of it generalises to any system with a formally specified part and a deployed part.

---

## 1. The dominant defect is not a broken check. It is a passing check that measures the wrong thing.

Every serious defect found in this project has this shape. Not a red build ignored. A **green build
that was measuring something adjacent to the property it was named for**.

Instances:

- A profile switch was measured against the recorded demo corpus and came back **0 blocked out of
  52**. Perfectly clean. The corpus is entirely ASCII with integer arguments, so it structurally
  could not exhibit the failure. The zero was not evidence of safety; it was evidence the corpus was
  unrepresentative.
- A cross-language byte-twin test passed against a **frozen expectation file** rather than the live
  definition it was supposed to mirror. It could have stopped tracking reality without ever going red.
- A verdict translation was property-tested over every possible `u32` on the Rust side. The Lean side
  that produced those integers was pinned by nothing. The test was exhaustive and half-blind.
- A theorem named `parse_total` stated `∃ result, parse raw = result`, discharged by reflexivity.
  True of every function that has ever existed.

**The rule.** For every green check, ask: *what would this do if the property were false?* If you
cannot answer concretely, the check is decoration. Write the answer down next to the check.

**The practice.** Every guard ships with a demonstrated negative control. Not an argument that it
would fail, a run where it did. The best example in this codebase is a panic probe with a
deliberately unguarded variant, whose job is to prove the fail-open it defends against is real.

---

## 2. A value crossing a boundary needs both sides pinned, in one document.

A verdict crossed an FFI boundary as an integer. Rust mapped `0` to passthrough. Lean emitted `0`
for passthrough. Correct, and correct by coincidence: nothing tied them together. Change the Lean
side and refused traffic forwards silently while every test stays green.

It was invisible in either file. It became obvious the moment both halves were written as adjacent
rows in one table, one saying `PINNED-BY-TEST` and the other `UNPINNED`.

**The rule.** When a value crosses a language, process or trust boundary, pin the encoder AND the
decoder, and record them **in the same place**. Asymmetry is only visible in a view that shows both.

**The corollary.** A headline claim that says "enforced by construction" must name what it is
conditional on. Ours was true of one side of a two-sided correspondence. The fix was not to retract
it but to state both halves and what pins each. A claim that names its conditions is stronger than
one that implies it has none.

---

## 3. To test a specification, make someone build from it without showing them the implementation.

Broad review returns your own documents. Ask a capable reviewer "what should we worry about" and it
reads the docs and tells you what the docs already worry about, in fresh words. The net is wide and
shallow.

Forced construction under withheld information is different. Two independent implementers were given
the model and NOT the code, and asked to write what the model implies. **They chose different integer
encodings for the same three-constructor type.** One matched reality, one did not. Wire them together
and refused lines forward as passthrough.

That is a real divergence, demonstrated, in one pass. Four broad reviews before it had produced
mostly things already written down.

**The rule.** The information you withhold is the instrument. If the reviewer can look up the answer,
you learn what your documents say. If they have to construct it, you learn where your specification
is ambiguous.

**The practice.** Two implementers per piece, so you get two diffs: construction versus construction,
and construction versus reality. Where two people who never met make the same choice and your code
made a different one, that is your strongest signal.

---

## 4. Classify a finding against the code before you write it down.

Six sites were reported as instances of a recurring defect family. **Five did not exist in the
codebase at all.** They were terms from a design specification. A separate review produced four
findings, of which two were already disclosed in the source, in sections written specifically to
disclose them.

A finding that is already documented is not a finding. A finding about code that does not exist is
worse than nothing, because it consumes the attention that real ones need.

**The rule.** Before a finding enters any register: locate it in the source, and check whether the
documents already disclose it. Both checks. The first catches ghosts, the second catches rediscovery.

---

## 5. Never hand a reviewer your hypothesis.

A brief that states the suspected defect and asks for confirmation produces confirmation. Two capable
seats were given a finding as four numbered evidence points and asked to "independently confirm or
refute". Both confirmed. That is homework marking with the answers attached, and it was reported
upward as though it were validation.

Writing "a refutation is as valuable as a confirmation" into the brief does not undo a leading brief.

**The rule.** State the system and the security claim. Ask them to break it. Never state the
suspected defect. Require a mandatory "what I tried that did not work" section, so the shape of the
search is visible. Explicitly permit the null result, so nobody is incentivised to manufacture a hit.

---

## 6. Verify every citation. The useful reviewers also fabricate.

In a single night, otherwise-excellent reviews produced: a SHA256 digest presented as computed that
was never computed, a confidently-cited line number pointing at the wrong lines, two invented paper
titles, and one real paper attributed to the wrong venue. The findings around them were often real.

**The rule.** A reviewer's finding is a lead. It becomes a fact when you reproduce it on disk. Quote
the code yourself. This is not distrust, it is the same discipline you apply to your own tests.

---

## 7. Disclosures rot. Make them executable.

Prose disclosures are excellent right up until they quietly become false, and nothing tells you.

A test was disabled with a comment naming the exact upstream commit that would unblock it. That
commit became an ancestor of the current pin weeks later, for unrelated reasons. Nobody noticed until
someone happened to read the file. The disclosure was perfect and stale.

**The rule.** Any ledger of what is and is not guaranteed must be checkable by a machine. A row
claiming a test exists is checked against the test existing AND being reachable from the default
build. A row claiming a term is absent from the source is checked against the source. Gate it in CI,
so a ledger that disagrees with the repository fails the build.

**The tell.** If your honesty apparatus only fails when a human reads it carefully, it will
eventually be wrong and trusted at the same time.

---

## 8. Grade your caveats, or the closable ones never close.

Disclose everything with equal weight and a reader cannot tell permanent physics from unfinished
work. Worse, *you* cannot either, and the fixable ones quietly become permanent by filing.

**The rule.** Every caveat carries a class: IRREDUCIBLE (with the reason it is irreducible),
FIXABLE-DEFERRED (with the technique and the cost), NEEDS-INTEGRATION (with the dependency), or
MISCLASSIFIED (a duplicate of another, to be merged away).

The MISCLASSIFIED bucket matters as much as the rest. A residual list padded with restatements
dilutes the real ones.

---

## 9. Record the paths you did not take, and why.

Commit messages capture what you did. They are a poor place for what you deliberately did not do, and
that second thing is what gets re-litigated six months later by someone with a plausible idea you
already tested and discarded.

Keep an append-only decision log. For each entry: the decision, the alternatives rejected, and **the
evidence that settled it**, concrete enough to re-run and disagree with. No names, no quoted
conversation. "Three independent advisors recommended X and one of them found the flaw in it" is the
reusable form; who said it is irrelevant to whether it was right.

---

## 10. Build discipline, learned the expensive way

- **One build at a time**, behind a lock. Two concurrent builds of a large dependency tree will cost
  you an evening and teach you nothing.
- **Seed fresh worktrees from the main checkout's package cache** with hardlinks. A cold dependency
  build in a throwaway worktree cost 73 minutes and blocked every other lane behind the build lock.
  The tooling had detected the cold cache and merely warned about it, which is the same as not
  knowing.
- **A tool that skips a missing input silently is a hazard.** A review that reads three of the four
  documents you meant to send, and reports confidently on what it saw, is indistinguishable from one
  that read everything. Refuse instead.
- **Never edit a running shell script.** Bash holds the original file descriptor; your change is a
  no-op and you will debug the wrong thing.
- **Verify you are on the branch you cut.** A dirty working tree silently blocks a branch switch, and
  the work then lands somewhere you did not intend.
- **A test outside the default build is not a guard.** If it does not run on every build, it does not
  exist.

---

## 11. The standard for "done"

A change is done when:

1. It builds green, and you rebuilt it yourself rather than trusting the report.
2. Its guard has been shown to go red on the thing it guards.
3. No fixture, vector, corpus or expectation was edited to make something pass. If one legitimately
   must change, that is a human decision, recorded.
4. No theorem statement changed to accommodate it. Proof bodies may change; claims may not, silently.
5. The ledger and the documents say what is now true.
6. The commit message records why, including what you rejected.

If you cannot say all six, say which one you cannot say. "I could not reproduce it" is a respectable
sentence. "It passed" without the rest is not.
