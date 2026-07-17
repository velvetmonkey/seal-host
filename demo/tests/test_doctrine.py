# SPDX-License-Identifier: Apache-2.0

import contextlib
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

    def test_fixed_non_claims_cover_all_three_boundaries(self):
        text = " ".join(doctrine.NON_CLAIMS).lower()
        self.assertIn("intent", text)
        self.assertIn("full-system", text)
        self.assertIn("h1 topology×config", text)


if __name__ == "__main__":
    unittest.main()
