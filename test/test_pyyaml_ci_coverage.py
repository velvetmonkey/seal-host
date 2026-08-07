#!/usr/bin/env python3
"""Negative controls for PyYAML CI provisioning coverage."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / ".github" / "check_pyyaml_provisioning.py"
SPEC = importlib.util.spec_from_file_location("check_pyyaml_provisioning", CHECK)
assert SPEC is not None and SPEC.loader is not None
coverage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage
SPEC.loader.exec_module(coverage)


ACTION = """
name: setup
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        python3 -c 'import yaml' 2>/dev/null \\
          || python3 -m pip install --break-system-packages pyyaml==6.0.2 \\
          || python3 -m pip install pyyaml==6.0.2 \\
          || sudo apt-get install -y -qq python3-yaml
"""


class PyYamlCiCoverageTests(unittest.TestCase):
    def fixture(self, workflow: str) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        root = Path(temporary.name)
        (root / ".github/workflows").mkdir(parents=True)
        (root / ".github/actions/setup-pyyaml").mkdir(parents=True)
        (root / "scripts").mkdir()
        (root / ".github/workflows/ci.yml").write_text(
            textwrap.dedent(workflow), encoding="utf-8"
        )
        (root / ".github/actions/setup-pyyaml/action.yml").write_text(
            textwrap.dedent(ACTION), encoding="utf-8"
        )
        return temporary

    def test_transitive_import_is_in_population(self) -> None:
        temporary = self.fixture(
            """
            jobs:
              covered:
                steps:
                  - uses: ./.github/actions/setup-pyyaml
                  - run: python3 scripts/wrapper.py
            """
        )
        with temporary:
            root = Path(temporary.name)
            (root / "scripts/reader.py").write_text("import yaml\n", encoding="utf-8")
            (root / "scripts/wrapper.py").write_text(
                "from reader import something\n", encoding="utf-8"
            )
            findings = coverage.analyze(root)
            self.assertEqual([item.job.job for item in findings], ["covered"])
            self.assertEqual(findings[0].entrypoints, ("scripts/wrapper.py",))

    def test_invoked_script_growing_yaml_dependency_fails(self) -> None:
        temporary = self.fixture(
            """
            jobs:
              regression:
                steps:
                  - run: python3 scripts/new_gate.py
            """
        )
        with temporary:
            root = Path(temporary.name)
            gate = root / "scripts/new_gate.py"
            gate.write_text("print('independent')\n", encoding="utf-8")
            self.assertEqual(coverage.analyze(root), ())
            gate.write_text("import yaml\n", encoding="utf-8")
            self.assertEqual(coverage.main(root), 1)

    def test_setup_must_precede_dependent_command(self) -> None:
        temporary = self.fixture(
            """
            jobs:
              too-late:
                steps:
                  - run: python3 scripts/gate.py
                  - uses: ./.github/actions/setup-pyyaml
            """
        )
        with temporary:
            root = Path(temporary.name)
            (root / "scripts/gate.py").write_text("import yaml\n", encoding="utf-8")
            self.assertEqual(coverage.main(root), 1)

    def test_unittest_discovery_is_an_invocation(self) -> None:
        temporary = self.fixture(
            """
            jobs:
              tests:
                steps:
                  - uses: ./.github/actions/setup-pyyaml
                  - run: python3 -m unittest discover -s test -p 'test_reader.py' -v
            """
        )
        with temporary:
            root = Path(temporary.name)
            (root / "test").mkdir()
            (root / "test/test_reader.py").write_text("import yaml\n", encoding="utf-8")
            self.assertEqual(coverage.main(root), 0)


if __name__ == "__main__":
    unittest.main()
