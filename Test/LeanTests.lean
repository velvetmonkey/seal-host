/- SPDX-License-Identifier: Apache-2.0 -/

namespace Test.LeanTests

private def testBinaries : Array String := #[
  "axiom_check",
  "host_unit_tests",
  "dx_surface_tests",
  "classify_encoding_tests",
  "policy_server_identity_tests",
  "honesty_matrix",
  "sha256_selfcheck",
  "repin_step2_guards",
  "guard_unify_tests",
  "perimeter_probe"
]

private def runTest (binDir : System.FilePath) (name : String) : IO UInt32 := do
  IO.println s!"[lean_tests] running {name}"
  let child ← IO.Process.spawn {
    cmd := (binDir / name).toString
    stdin := .inherit
    stdout := .inherit
    stderr := .inherit
  }
  let exitCode ← child.wait
  if exitCode != 0 then
    IO.eprintln s!"[lean_tests] {name} failed with exit code {exitCode}"
  return exitCode

def main : IO UInt32 := do
  let appPath ← IO.appPath
  let some binDir := appPath.parent
    | IO.eprintln s!"[lean_tests] cannot determine binary directory from {appPath}"
      return 1
  let mut passed : Array String := #[]
  for name in testBinaries do
    let exitCode ← runTest binDir name
    if exitCode != 0 then
      return exitCode
    passed := passed.push name
  if passed.isEmpty then
    IO.eprintln "[lean_tests] no test binaries ran; refusing to pass vacuously"
    return 1
  IO.println s!"[lean_tests] all {passed.size} test binaries passed: {String.intercalate ", " passed.toList}"
  return 0

end Test.LeanTests

def main : IO UInt32 := Test.LeanTests.main
