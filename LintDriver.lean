/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# Lint driver wrapper

`lake lint` runs this exe (`lintDriver` in `lakefile.toml`). It exists because
the workspace has colliding module roots: this package and its `mcp-seal`
dependency both ship `Test.*` modules, and the `LEAN_PATH` Lake hands a driver
lists dependency build dirs BEFORE the root package's. A runtime
`importModules` of `Test.<X>` therefore resolves into `mcp-seal`'s tree —
linting the wrong module (`Test.Axioms`) or dying with "olean does not exist"
(`Test.HostUnit`). This wrapper moves the root package's build dir to the
front of `LEAN_PATH` — matching the resolution `lake build` itself uses —
ensures Batteries' `runLinter` is built, and runs it, propagating its exit
code so a lint failure fails `lake lint`.
-/

/-- Entry point: reorder `LEAN_PATH` (root package first), build and run
    `batteries/runLinter`, and exit with its status. -/
def main (args : List String) : IO UInt32 := do
  let cwd ← IO.currentDir
  let rootLib := cwd / ".lake" / "build" / "lib" / "lean"
  let sep := if System.Platform.isWindows then ";" else ":"
  let leanPath := (← IO.getEnv "LEAN_PATH").getD ""
  let entries := leanPath.splitOn sep |>.filter fun e =>
    e ≠ rootLib.toString && !e.isEmpty
  let fixed := sep.intercalate (rootLib.toString :: entries)
  let bin := cwd / ".lake" / "packages" / "batteries" / ".lake" / "build" / "bin" / "runLinter"
  -- Build the real linter only when its binary is absent. A nested `lake
  -- build` while `lake lint` is running the driver deadlocks on the
  -- workspace, so the common case must not spawn lake at all.
  unless (← bin.pathExists) do
    let lake := (← IO.getEnv "LAKE").getD "lake"
    let build ← IO.Process.spawn { cmd := lake, args := #["build", "batteries/runLinter"] }
    if (← build.wait) != 0 then
      IO.eprintln "lint driver: failed to build batteries/runLinter"
      return 1
  unless (← bin.pathExists) do
    IO.eprintln s!"lint driver: runLinter binary not found at {bin}"
    return 1
  let child ← IO.Process.spawn {
    cmd := bin.toString
    args := args.toArray
    env := #[("LEAN_PATH", some fixed)]
  }
  child.wait
