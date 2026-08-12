/-
Copyright (c) 2026 velvetmonkey
SPDX-License-Identifier: Apache-2.0

Ask Lake which configuration file wins and which dependency blocks in Lake's
normalized TOML name `mcp-seal`. This deliberately does not choose a
configuration file, parse TOML, or decode Lean names independently.
-/
import Lake.Load.Package
import Lake.Load.Toml

open Lake System

private def dependencyRevision? (dep : Dependency) : Option String := do
  let .git _ rev? _ ← dep.src? | none
  rev?

private def jsonString (value : String) : String :=
  (Lean.toJson value).compress

private def run (packageInput normalizedInput : String) : IO UInt32 := do
  let pkgDir := FilePath.mk packageInput
  let chosenConfig ← realConfigFile (pkgDir / defaultConfigFile)
  let some chosenName := chosenConfig.fileName
    | IO.eprintln "Lake did not choose a package configuration" *> pure 1
  let configFile := FilePath.mk normalizedInput
  let config : LoadConfig := {
    lakeEnv := default
    wsDir := pkgDir
    pkgDir
    relConfigFile := "lakefile.toml"
    configFile
  }
  let some pkg ← loadTomlConfig config |>.toBaseIO
    | pure 1
  let targetName := stringToLegalOrSimpleName "mcp-seal"
  let dependencies := pkg.depConfigs.filter (fun dep => dep.name == targetName)
  let entries := dependencies.toList.mapIdx fun index dep =>
    "{\"block\":" ++ toString (index + 1) ++
      ",\"name\":" ++ jsonString dep.name.toString ++ ",\"revision\":" ++
      match dependencyRevision? dep with
      | some revision => jsonString revision ++ "}"
      | none => "null}"
  IO.println <| "MCP_SEAL_LAKE_RESULT={\"chosenConfig\":" ++
    jsonString chosenName ++ ",\"dependencies\":[" ++
    String.intercalate "," entries ++ "]}"
  pure 0

def main (args : List String) : IO UInt32 :=
  match args with
  | [packageInput, normalizedInput] => run packageInput normalizedInput
  | _ => IO.eprintln "usage: lake_mcp_seal_revision <package-directory> <normalized-toml>" *> pure 2
