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

    def test_fixed_non_claims_cover_all_three_boundaries(self):
        text = " ".join(doctrine.NON_CLAIMS).lower()
        self.assertIn("intent", text)
        self.assertIn("full-system", text)
        self.assertIn("h1 topology×config", text)


if __name__ == "__main__":
    unittest.main()
