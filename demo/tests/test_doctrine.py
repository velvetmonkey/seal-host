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

    def test_c6_order_is_allow_trigger_then_deny_without_weakening_c4(self):
        c6_steps = [
            {"role": "LEGIT-TRIGGER", "verdict": "ALLOW"},
            {"role": "ATTACK-DENY", "verdict": "DENY"},
        ]
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
        doctrine.validate_lane_scope("c6", "trace")

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

    def test_fixed_non_claims_cover_all_three_boundaries(self):
        text = " ".join(doctrine.NON_CLAIMS).lower()
        self.assertIn("intent", text)
        self.assertIn("full-system", text)
        self.assertIn("h1 topology×config", text)


if __name__ == "__main__":
    unittest.main()
