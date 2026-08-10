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

/-- The number of test binaries this suite must run. A literal, not
    `testBinaries.size`: a count derived from the list would shrink along with
    any truncation of the loop's input and the runtime assertion below could
    never fire. The `#guard` keeps the literal and the declared list from
    drifting apart, so adding or removing a test binary fails the build until
    this number is updated to match. -/
private def expectedTestCount : Nat := 10

#guard testBinaries.size = expectedTestCount

private def runTest (binDir : System.FilePath) (name : String) : IO UInt32 := do
  IO.println s!"[lean_tests] running {name}"
  let path := binDir / name
  try
    let metadata ← path.metadata
    if metadata.type != IO.FS.FileType.file then
      IO.eprintln s!"[lean_tests] {name} is not a regular file: {path}"
      return 1
    if metadata.byteSize == 0 then
      IO.eprintln s!"[lean_tests] {name} is empty: {path}"
      return 1
    -- Opening before spawn makes unreadable inputs fail explicitly instead of
    -- relying on platform-specific executable-loading behavior.
    let _ ← IO.FS.Handle.mk path .read
    let child ← IO.Process.spawn {
      cmd := path.toString
      stdin := .inherit
      stdout := .inherit
      stderr := .inherit
    }
    let exitCode ← child.wait
    if exitCode != 0 then
      IO.eprintln s!"[lean_tests] {name} failed with exit code {exitCode}"
    return exitCode
  catch error =>
    IO.eprintln s!"[lean_tests] {name} cannot be read or started: {error}"
    return 1

def main : IO UInt32 := do
  let appPath ← IO.appPath
  let some binDir := appPath.parent
    | IO.eprintln s!"[lean_tests] cannot determine binary directory from {appPath}"
      return 1
  let mut ran : Nat := 0
  let mut failures : Array (String × UInt32) := #[]
  for name in testBinaries do
    ran := ran + 1
    let exitCode ← runTest binDir name
    if exitCode != 0 then
      failures := failures.push (name, exitCode)
  if ran != expectedTestCount then
    IO.eprintln s!"[lean_tests] COUNT MISMATCH: expected {expectedTestCount} test binaries but only {ran} ran; refusing to pass"
    return 1
  if failures.isEmpty then
    IO.println s!"[lean_tests] all {ran} test binaries passed: {String.intercalate ", " testBinaries.toList}"
    return 0
  IO.eprintln s!"[lean_tests] {failures.size} of {ran} test binaries failed:"
  for (name, exitCode) in failures do
    IO.eprintln s!"[lean_tests]   {name}: exit code {exitCode}"
  return 1

end Test.LeanTests

def main : IO UInt32 := Test.LeanTests.main
