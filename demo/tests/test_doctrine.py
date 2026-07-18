# SPDX-License-Identifier: Apache-2.0

import contextlib
import copy
import io
import sys
import unittest
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO))

import doctrine  # noqa: E402


class DoctrineUnitTests(unittest.TestCase):
    def test_every_demo_theorem_is_sourced_from_an_existing_pin(self):
        theorem_ids = [
            "Seal.shell_rm_rf_blocks_on_fresh_state",
            "Seal.shell_read_flows",
            "SealV2.tampered_approvals_deny",
            "Host.registry_closed_algebra",
            "Host.composed_budget_cap",
            "Host.composed_temporal_safety",
            "BudgetCore.over_budget_denied",
            "Host.registry_deny_no_budget_spend",
            "Host.registry_deny_temporal_frozen",
            "Host.registry_deny_no_capability_consumed",
            "Host.composed_convergent",
            "Kernels.convergence_verdict_allow_iff",
            "Host.composed_non_bypass",
            "Host.composed_no_conflicting_agreement",
            "Host.composed_linear_conservation",
            "Host.pureCommit_deny_of_member",
            "Host.linear_committed_trace_no_double_spend",
        ]
        for theorem_id in theorem_ids:
            with self.subTest(theorem_id=theorem_id):
                self.assertTrue(doctrine._pin_locations(theorem_id))
        self.assertEqual(doctrine._pin_locations("Invented.demo_theorem"), [])

    def test_first_coloured_step_is_red_deny(self):
        event = {
            "event": "step", "verdict": "DENY", "role": "ATTACK-DENY",
            "tool": "shell_exec", "args_digest": "0" * 64,
            "kernel_fired": [{"kernel":"safety", "verdict":"DENY", "participation":"ACTIVE"}],
            "deny_kernel": "safety", "proof_refs": [],
            "receipt_path": "receipts/r.json", "seal_verify": {"status":"PASS"},
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            doctrine.render_tty_event(event, color=True)
        first = output.getvalue().splitlines()[0]
        self.assertTrue(first.startswith("\x1b[31;1mDENY\x1b[0m"), first)

    def test_nested_budget_cost_path_and_arithmetic(self):
        arguments = {"prompt": "hello", "usage": {"tokens": 4}}
        self.assertEqual(doctrine.argument_at_path(arguments, "usage.tokens"), 4)
        evidence = doctrine.validate_budget_evidence(
            {
                "name": "token-usage", "cost_arg": "usage.tokens", "cap": 10,
                "remaining_before": 10, "remaining_after": 6,
            },
            arguments, verdict="ALLOW", deny_kernel=None, context="unit",
        )
        self.assertEqual(evidence["cost"], 4)
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine.argument_at_path(arguments, "usage.missing")

    def test_budget_deny_renders_cap_and_would_exceed(self):
        event = {
            "event": "step", "verdict": "DENY", "role": "ATTACK-DENY",
            "tool": "llm_call", "args_digest": "0" * 64,
            "kernel_fired": [
                {"kernel": "safety", "verdict": "ALLOW", "participation": "ACTIVE"},
                {"kernel": "budget", "verdict": "DENY", "participation": "ACTIVE"},
            ],
            "deny_kernel": "budget", "proof_refs": [],
            "receipt_path": "receipts/r.json", "seal_verify": {"status": "PASS"},
            "budget": {
                "name": "token-usage", "cost_arg": "usage.tokens", "cost": 11,
                "cap": 10, "remaining_before": 10, "remaining_after": 10,
            },
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            doctrine.render_tty_event(event, color=True)
        lines = output.getvalue().splitlines()
        self.assertTrue(lines[0].startswith("\x1b[31;1mDENY\x1b[0m"), lines[0])
        self.assertIn("cap=10", output.getvalue())
        self.assertIn("remaining=10→would-exceed (unchanged=10)", output.getvalue())

    def test_c5_c6_order_is_allow_trigger_then_deny_without_weakening_c4(self):
        c6_steps = [
            {"role": "LEGIT-TRIGGER", "verdict": "ALLOW"},
            {"role": "ATTACK-DENY", "verdict": "DENY"},
        ]
        doctrine.validate_step_order({"demo_id": "c5"}, c6_steps)
        doctrine.validate_step_order({"demo_id": "c6"}, c6_steps)
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine.validate_step_order({"demo_id": "c6"}, c6_steps + [{"role": "CONTROL", "verdict": "DENY"}])
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine.validate_step_order({"demo_id": "c4"}, c6_steps)
        doctrine.validate_step_order({"demo_id": "c4"}, [
            {"role": "ATTACK-DENY", "verdict": "DENY"},
            {"role": "LEGIT", "verdict": "ALLOW"},
        ])
        for demo_id in ["c1", "c2", "c4"]:
            with self.subTest(demo_id=demo_id), self.assertRaises(doctrine.DoctrineFailure):
                doctrine.validate_lane_scope(demo_id, "trace")
            doctrine.validate_lane_scope(demo_id, "standalone")
        doctrine.validate_lane_scope("c5", "trace")
        doctrine.validate_lane_scope("c6", "trace")

    def test_c3_order_and_lane_are_receipt_properties(self):
        c3_steps = [
            {"role": "QUORUM-SHORT", "verdict": "DENY"},
            {"role": "DEPLOY-OK", "verdict": "ALLOW"},
            {"role": "REPLAY-DENY", "verdict": "DENY"},
        ]
        doctrine.validate_step_order({"demo_id": "c3"}, c3_steps)
        doctrine.validate_lane_scope("c3", "trace")
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine.validate_step_order({"demo_id": "c3"}, c3_steps[:2])
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine.validate_step_order({"demo_id": "c3"}, [c3_steps[1], c3_steps[0], c3_steps[2]])

    def test_c7_order_is_composed_allow_then_each_kernel_veto(self):
        steps = [
            {"role": role, "verdict": "ALLOW" if index == 0 else "DENY"}
            for index, role in enumerate([
                "COMPOSED-ALLOW", "S-DENY", "T-DENY", "C-DENY",
                "V-DENY", "L-DENY", "B-DENY",
            ])
        ]
        doctrine.validate_step_order({"demo_id": "c7"}, steps)
        drifted = copy.deepcopy(steps)
        drifted[2], drifted[3] = drifted[3], drifted[2]
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine.validate_step_order({"demo_id": "c7"}, drifted)

    def test_c3_validator_locks_participation_denials_linear_state_and_lanes(self):
        theorem_sets = [
            {"Host.pureCommit_deny_of_member", "Host.registry_deny_no_capability_consumed"},
            {"Host.registry_closed_algebra", "Host.composed_non_bypass",
             "Host.composed_no_conflicting_agreement", "Host.composed_linear_conservation"},
            {"Host.linear_committed_trace_no_double_spend", "Host.pureCommit_deny_of_member",
             "Host.registry_deny_no_capability_consumed"},
        ]
        all_theorems = set().union(*theorem_sets)
        metadata = {
            "policy_recipe": "deploy", "active": ["safety", "consensus", "linear"],
            "present_but_inactive": [], "experimental": [],
        }
        manifest = {"proofs": {name: {} for name in all_theorems}}
        config = {
            "consensus": {"roster": [101, 202, 303], "votes_file": "/real/votes", "high_stakes": ["deploy"]},
            "linear": {"grants_file": "/real/grants", "tools": [{"tool": "deploy", "cap_arg": "capability.id"}]},
        }
        args_short = {"release": "short", "capability": {"id": "deploy-cap-c3-001"}}
        args_deploy = {"release": "ok", "capability": {"id": "deploy-cap-c3-001"}}
        cert_verdicts = [
            ["allow", "allow", "deny", "allow"],
            ["allow", "allow", "allow", "allow"],
            ["allow", "allow", "allow", "deny"],
        ]
        records = []
        for index, verdicts in enumerate(cert_verdicts):
            records.append({
                "arguments": args_short if index == 0 else args_deploy,
                "deny_kernel": ["consensus", None, "linear"][index],
                "kernel_config": config,
                "certs": [
                    {"kernel": kernel, "verdict": verdict, "reason": "a" * 64 if kernel == "safety" else "runtime"}
                    for kernel, verdict in zip(["safety", "temporal", "consensus", "linear"], verdicts)
                ],
            })
        consensus = [
            {"roster": [101, 202, 303], "value": "deploy", "votes": 1, "required": 2, "quorum_met": False},
            {"roster": [101, 202, 303], "value": "deploy", "votes": 2, "required": 2, "quorum_met": True},
            {"roster": [101, 202, 303], "value": "deploy", "votes": 2, "required": 2, "quorum_met": True},
        ]
        linear = [
            {"cap_arg": "capability.id", "capability_id": "deploy-cap-c3-001", "grant_events": 1,
             "remaining_before": 1, "remaining_after": 1, "consumed": False},
            {"cap_arg": "capability.id", "capability_id": "deploy-cap-c3-001", "grant_events": 0,
             "remaining_before": 1, "remaining_after": 0, "consumed": True},
            {"cap_arg": "capability.id", "capability_id": "deploy-cap-c3-001", "grant_events": 0,
             "remaining_before": 0, "remaining_after": 0, "consumed": False},
        ]
        steps = []
        for index in range(3):
            steps.append({
                "tool": "deploy", "receipt_verdict": ["BLOCK", "ALLOW", "BLOCK"][index],
                "verification_lane": "trace", "deny_kernel": ["consensus", None, "linear"][index],
                "proof_refs": [{"theorem_id": name} for name in theorem_sets[index]],
                "kernel_fired": [
                    {"kernel": kernel, "participation": participation}
                    for kernel, participation in [
                        ("safety", "ACTIVE"), ("temporal", "ABSENT/OFF"),
                        ("consensus", "ACTIVE"), ("linear", "ACTIVE"),
                    ]
                ],
                "seal_verify": {
                    "command": "seal verify", "status": "TRACE-SCOPED", "exit_code": 1,
                    "rederived_verdict": "BLOCK", "live_session_verdict": ["BLOCK", "ALLOW", "BLOCK"][index],
                    "artifact_lane_reason": "combined receipt omits votes/grants; verifier replays both empty",
                },
                "consensus": consensus[index], "linear": linear[index],
            })
        doctrine._validate_c3(metadata, steps, records, manifest)

        drifted = copy.deepcopy(steps)
        drifted[0]["kernel_fired"].pop()
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c3(metadata, drifted, records, manifest)
        drifted = copy.deepcopy(steps)
        drifted[2]["linear"]["remaining_before"] = 1
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c3(metadata, drifted, records, manifest)
        drifted = copy.deepcopy(steps)
        drifted[1]["verification_lane"] = "standalone"
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c3(metadata, drifted, records, manifest)

    def test_c5_validator_locks_stateless_lanes_operations_and_certificates(self):
        theorem_sets = [
            {"Host.composed_convergent", "Host.registry_closed_algebra"},
            {"Kernels.convergence_verdict_allow_iff", "Host.pureCommit_deny_of_member"},
        ]
        metadata = {
            "policy_recipe": "mesh",
            "active": ["safety", "convergence"],
            "present_but_inactive": [],
            "experimental": [],
        }
        manifest = {"proofs": {name: {} for name in set().union(*theorem_sets)}}
        kernel_config = {
            "convergence": {"tools": [{"tool": "store.update", "op_arg": "op"}]},
        }
        records = [
            {
                "arguments": {"op": "orset.add", "key": "team/c5", "value": "member-a"},
                "deny_kernel": None,
                "kernel_config": kernel_config,
                "certs": [
                    {"kernel": "safety", "verdict": "allow", "reason": "a" * 64},
                    {"kernel": "temporal", "verdict": "allow", "reason": "trace ok (1 events)"},
                    {"kernel": "convergence", "verdict": "allow", "reason": "convergent op admitted: orset.add"},
                ],
            },
            {
                "arguments": {"op": "assign", "key": "team/c5", "value": "blind-overwrite"},
                "deny_kernel": "convergence",
                "kernel_config": kernel_config,
                "certs": [
                    {"kernel": "safety", "verdict": "allow", "reason": "b" * 64},
                    {"kernel": "temporal", "verdict": "allow", "reason": "trace ok (2 events)"},
                    {
                        "kernel": "convergence",
                        "verdict": "deny",
                        "reason": "op not in the proven-convergent set: assign",
                    },
                ],
            },
        ]
        proven_set = [
            "gset.add", "gcounter.inc", "pncounter.inc", "pncounter.dec",
            "orset.add", "orset.remove", "rga.insert", "rga.remove",
        ]
        scope = (
            "this specific operation was mediated under the fixed kernel set; "
            "no universal replicated-store convergence claim"
        )
        steps = []
        for index, operation in enumerate(["orset.add", "assign"]):
            seal_verify = {"command": "seal verify", "status": "PASS", "exit_code": 0}
            if index == 1:
                seal_verify = {
                    "command": "seal verify",
                    "status": "TRACE-SCOPED",
                    "exit_code": 1,
                    "fresh_state_verdict": "BLOCK",
                    "live_session_verdict": "BLOCK",
                    "artifact_lane_reason": (
                        "Convergence is stateless, but the always-registered Temporal certificate "
                        "is trace-indexed and changes the composite emitted bytes"
                    ),
                }
            steps.append({
                "tool": "store.update",
                "receipt_verdict": ["ALLOW", "BLOCK"][index],
                "verification_lane": ["standalone", "trace"][index],
                "seal_verify": seal_verify,
                "deny_kernel": [None, "convergence"][index],
                "proof_refs": [{"theorem_id": name} for name in theorem_sets[index]],
                "kernel_fired": [
                    {"kernel": "safety", "participation": "ACTIVE"},
                    {"kernel": "temporal", "participation": "ABSENT/OFF"},
                    {"kernel": "convergence", "participation": "ACTIVE"},
                ],
                "convergence": {
                    "tool": "store.update", "op_arg": "op", "operation": operation,
                    "in_proven_set": index == 0, "proven_set": proven_set,
                    "stateful": False, "claim_scope": scope,
                },
            })
        doctrine._validate_c5(metadata, steps, records, manifest)

        drifted = copy.deepcopy(steps)
        drifted[1]["verification_lane"] = "standalone"
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c5(metadata, drifted, records, manifest)
        drifted = copy.deepcopy(records)
        drifted[1]["certs"][2]["reason"] = "universal convergence denied"
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c5(metadata, steps, drifted, manifest)
        drifted = copy.deepcopy(steps)
        drifted[0]["convergence"]["stateful"] = True
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c5(metadata, drifted, records, manifest)

    def test_c6_temporal_deny_renders_scope_and_theorem_backed_state(self):
        event = {
            "event": "step", "verdict": "DENY", "receipt_verdict": "BLOCK",
            "role": "ATTACK-DENY", "tool": "audit.destroy", "args_digest": "0" * 64,
            "kernel_fired": [
                {"kernel": "safety", "verdict": "ALLOW", "participation": "ACTIVE"},
                {"kernel": "temporal", "verdict": "DENY", "participation": "ACTIVE"},
            ],
            "deny_kernel": "temporal", "proof_refs": [],
            "receipt_path": "receipts/r.json", "seal_verify": {"status": "PASS"},
            "temporal": {
                "policy_name": "freeze-destructive-after-trigger", "policy_type": "no_after",
                "trigger": ["session.revoke", "audit.destroy"],
                "forbidden": ["session.revoke", "audit.destroy"],
                "trace_events_before": 1, "trace_events_after": 1,
                "trace_evidence": "theorem:Host.registry_deny_temporal_frozen",
                "deny_state": {
                    "trace_theorem": "Host.registry_deny_temporal_frozen",
                    "capability_consumed": False,
                    "capability_theorem": "Host.registry_deny_no_capability_consumed",
                },
                "freeze_scope": "this specific audit.destroy call was mediated to DENY under the armed policy",
                "wall_clock_claim": False,
            },
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            doctrine.render_tty_event(event, color=True)
        text = output.getvalue()
        self.assertTrue(text.startswith("\x1b[31;1mDENY\x1b[0m ATTACK-DENY"), text)
        self.assertIn("deny_kernel=temporal", text)
        self.assertIn("temporal-trace=1→1", text)
        self.assertIn("capability-consumed=false[Host.registry_deny_no_capability_consumed]", text)
        self.assertIn("wall-clock-claim=false", text)
        self.assertEqual(event["receipt_verdict"], "BLOCK")

    def test_c6_validator_rejects_certificate_theorem_and_scope_drift(self):
        policy = {
            "name": "freeze-destructive-after-trigger", "type": "no_after",
            "trigger": ["session.revoke", "audit.destroy"],
            "forbidden": ["session.revoke", "audit.destroy"],
        }
        metadata = {
            "policy_recipe": "init+add-kernel-T",
            "active": ["safety", "temporal"],
            "present_but_inactive": [], "experimental": [],
        }
        manifest = {"proofs": {name: {} for name in [
            "Host.composed_temporal_safety", "Host.registry_closed_algebra",
            "Host.registry_deny_no_capability_consumed", "Host.registry_deny_temporal_frozen",
        ]}}
        kernel_config = {"temporal": {"policies": [policy]}}
        records = [
            {
                "deny_kernel": None, "kernel_config": kernel_config,
                "certs": [
                    {"kernel": "safety", "verdict": "allow", "reason": "a" * 64},
                    {"kernel": "temporal", "verdict": "allow", "reason": "trace ok (1 events)"},
                ],
            },
            {
                "deny_kernel": "temporal", "kernel_config": kernel_config,
                "certs": [
                    {"kernel": "safety", "verdict": "allow", "reason": "b" * 64},
                    {"kernel": "temporal", "verdict": "deny", "reason": "temporal policy violated: freeze-destructive-after-trigger"},
                ],
            },
        ]
        temporal_common = {
            "policy_name": policy["name"], "policy_type": policy["type"],
            "trigger": policy["trigger"], "forbidden": policy["forbidden"],
            "wall_clock_claim": False,
        }
        fired_allow = [
            {"kernel": "safety", "participation": "ACTIVE"},
            {"kernel": "temporal", "participation": "ACTIVE"},
        ]
        steps = [
            {
                "tool": "session.revoke", "receipt_verdict": "ALLOW", "deny_kernel": None,
                "verification_lane": "standalone",
                "seal_verify": {"command": "seal verify", "status": "PASS", "exit_code": 0},
                "proof_refs": [
                    {"theorem_id": "Host.composed_temporal_safety"},
                    {"theorem_id": "Host.registry_closed_algebra"},
                ],
                "kernel_fired": fired_allow,
                "temporal": {
                    **temporal_common, "trace_events_before": 0, "trace_events_after": 1,
                    "trace_evidence": "runtime-certificate:trace ok (1 events)",
                    "freeze_scope": "session.revoke armed the trigger-driven freeze",
                },
            },
            {
                "tool": "audit.destroy", "receipt_verdict": "BLOCK", "deny_kernel": "temporal",
                "verification_lane": "trace",
                "seal_verify": {
                    "command": "seal verify", "status": "TRACE-SCOPED", "exit_code": 1,
                    "fresh_state_verdict": "ALLOW", "live_session_verdict": "BLOCK",
                },
                "proof_refs": [
                    {"theorem_id": "Host.registry_deny_temporal_frozen"},
                    {"theorem_id": "Host.registry_deny_no_capability_consumed"},
                ],
                "kernel_fired": fired_allow,
                "temporal": {
                    **temporal_common, "trace_events_before": 1, "trace_events_after": 1,
                    "trace_evidence": "theorem:Host.registry_deny_temporal_frozen",
                    "deny_state": {
                        "trace_theorem": "Host.registry_deny_temporal_frozen",
                        "capability_consumed": False,
                        "capability_theorem": "Host.registry_deny_no_capability_consumed",
                    },
                    "freeze_scope": "this specific audit.destroy call was mediated to DENY under the armed policy",
                },
            },
        ]
        doctrine._validate_c6(metadata, steps, records, manifest)

        drifted = copy.deepcopy(steps)
        drifted[1]["temporal"]["wall_clock_claim"] = True
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c6(metadata, drifted, records, manifest)
        drifted = copy.deepcopy(records)
        drifted[1]["certs"].pop()
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c6(metadata, steps, drifted, manifest)
        drifted = copy.deepcopy(manifest)
        drifted["proofs"]["Invented.extra"] = {}
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c6(metadata, steps, records, drifted)

    def test_c7_validator_locks_six_active_kernels_and_isolated_denials(self):
        tools = [
            "compose.allow", "deny.safety", "deny.temporal", "deny.consensus",
            "deny.convergence", "deny.linear", "deny.budget",
        ]
        kernels = ["safety", "temporal", "consensus", "convergence", "linear", "budget"]
        denies = [None, *kernels]
        tier = {"ci_tested": False, "operator_verified": False}
        config = {
            "epoch": 1,
            "server": "seal-c7-composition-demo@1.0.0",
            "safety": {"tools": [
                {"name": tool, "_seal_demo_tier": tier} for tool in tools
            ]},
            "temporal": {"policies": [{
                "name": "c7-headline-arms-temporal-veto", "type": "no_after",
                "trigger": ["compose.allow"], "forbidden": ["deny.temporal"],
            }]},
            "consensus": {
                "roster": [101, 202, 303], "votes_file": "/real/votes",
                "high_stakes": tools,
            },
            "convergence": {"tools": [{"tool": tool, "op_arg": "op"} for tool in tools]},
            "linear": {
                "grants_file": "/real/grants",
                "tools": [{"tool": tool, "cap_arg": "capability.id"} for tool in tools],
            },
            "budget": {"budgets": [{
                "name": "c7-token-budget", "cap": 20, "tools": tools,
                "cost_arg": "usage.tokens",
            }]},
        }
        headline_proofs = {
            "Host.registry_closed_algebra", "Host.composed_non_bypass",
            "Host.composed_temporal_safety", "Host.composed_no_conflicting_agreement",
            "Host.composed_convergent", "Host.composed_linear_conservation",
            "Host.composed_budget_cap",
        }
        deny_proofs = {
            "Host.pureCommit_deny_of_member", "Host.registry_deny_no_capability_consumed",
            "Host.registry_deny_no_budget_spend",
        }
        theorem_sets = [headline_proofs]
        for kernel in kernels:
            proof_set = set(deny_proofs)
            if kernel == "temporal":
                proof_set.add("Host.registry_deny_temporal_frozen")
            if kernel == "convergence":
                proof_set.add("Kernels.convergence_verdict_allow_iff")
            theorem_sets.append(proof_set)
        manifest = {"proofs": {name: {} for name in set().union(*theorem_sets)}}
        lane_reason = (
            "combined receipt omits Consensus votes and Linear grant events; C7 also carries "
            "session-scoped Temporal/Linear/Budget state"
        )
        records = []
        steps = []
        for index, (tool, deny_kernel, proof_set) in enumerate(zip(tools, denies, theorem_sets)):
            certs = [
                {
                    "kernel": kernel,
                    "verdict": "deny" if kernel == deny_kernel else "allow",
                    "reason": "runtime",
                }
                for kernel in kernels
            ]
            records.append({"deny_kernel": deny_kernel, "kernel_config": config, "certs": certs})
            steps.append({
                "tool": tool,
                "receipt_verdict": "ALLOW" if index == 0 else "BLOCK",
                "deny_kernel": deny_kernel,
                "verification_lane": "trace",
                "seal_verify": {
                    "command": "seal verify", "status": "TRACE-SCOPED", "exit_code": 1,
                    "rederived_verdict": "BLOCK",
                    "live_session_verdict": "ALLOW" if index == 0 else "BLOCK",
                    "artifact_lane_reason": lane_reason,
                },
                "kernel_fired": [
                    {"kernel": kernel, "participation": "ACTIVE"} for kernel in kernels
                ],
                "proof_refs": [{"theorem_id": name} for name in proof_set],
            })
        metadata = {
            "policy_recipe": "init+add-kernel-T+C+V+L+B",
            "active": kernels, "present_but_inactive": [], "experimental": [],
        }
        doctrine._validate_c7(metadata, steps, records, manifest)

        drifted = copy.deepcopy(records)
        drifted[4]["certs"][0]["verdict"] = "deny"
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c7(metadata, steps, drifted, manifest)
        drifted = copy.deepcopy(config)
        drifted["calibration"] = {"enabled": True}
        records_with_k = copy.deepcopy(records)
        for record in records_with_k:
            record["kernel_config"] = drifted
        with self.assertRaises(doctrine.DoctrineFailure):
            doctrine._validate_c7(metadata, steps, records_with_k, manifest)

    def test_fixed_non_claims_cover_all_three_boundaries(self):
        text = " ".join(doctrine.NON_CLAIMS).lower()
        self.assertIn("intent", text)
        self.assertIn("full-system", text)
        self.assertIn("h1 topology×config", text)


if __name__ == "__main__":
    unittest.main()
