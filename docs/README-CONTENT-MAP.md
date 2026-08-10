# README content relocation map

This inventory maps every claim-bearing or caveat-bearing section of the
174-line pre-distillation README (`a87f02e:README.md`) to its current home.

| Before | Claims and caveats carried | Current home |
|---|---|---|
| Opening and family framing | guarded-call mediation, exact approval, evidence, effects/MCP/no-intent boundary | README opening; exact truth box; [front-page reference](FRONT-PAGE-REFERENCE.md#what-the-host-does) |
| Quick start and showcase | source build cost, synthetic ledger, block/allow/refuse behavior | [front-page reference](FRONT-PAGE-REFERENCE.md#alternative-demonstrations-and-their-measured-status); broken path stays labelled |
| Truth box | compatible profile, canonical-l0 gap, separate token channel, custody assumption | README guarded truth box; [Limitations](LIMITATIONS.md); [Profile](../PROFILE.md) |
| CLI, fail-closed, and Telegram dogfood | human loop, signed decline, tampered token, Telegram setup and TCB | [front-page reference](FRONT-PAGE-REFERENCE.md#alternative-demonstrations-and-their-measured-status); [Deployment](DEPLOY.md#developer-ingress-two-approval-channels-cli--telegram) |
| Receipt demo | block, SHA-256 chain, mutation/reorder rejection, theorem scope | [front-page reference](FRONT-PAGE-REFERENCE.md#alternative-demonstrations-and-their-measured-status); [Getting started](GETTING-STARTED.md#4-verify-a-receipt--and-see-verification-fail) |
| Host operation | ordinary forwarding, approval filtering, FFI decision, refusal before child, receipt forms | [front-page reference](FRONT-PAGE-REFERENCE.md#what-the-host-does); [Architecture](ARCHITECTURE.md) |
| Evaluator/proof detail | narrow proof, finite conformance, TCB, model-level non-interference and hash assumptions | [front-page reference](FRONT-PAGE-REFERENCE.md#proof-and-deployment-boundary); [Proof reference](PROOF-REFERENCE.md); [Conformance](CONFORMANCE.md); [TCB](TCB.md) |
| Distributed transfer | TTL-scoped lower bound application and mesh boundary | [front-page reference](FRONT-PAGE-REFERENCE.md#distributed-boundary); family authorization mesh |
| Mandatory non-claims | whole system, hash assumption, glue, intent, compromise, tamper, hallucination, axiom scope | README guarded claims block; [Limitations](LIMITATIONS.md) |
| Source verification sequence | Lean, FFI, Rust, and wasm checks | [Conformance](CONFORMANCE.md) with technical prerequisites; explicitly removed from first-run path |
| Family and documentation lists | public repository roles, proprietary analyzer exception, evaluator/operations links | [front-page reference](FRONT-PAGE-REFERENCE.md#documentation-and-family-map) |
| Licence | Apache-2.0 | README licence section |

The README links both this moved depth and the single getting-started journey;
the alternative demonstrations are not competing starts.
