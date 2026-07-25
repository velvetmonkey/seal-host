/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Canonical

namespace Test.RepinStep2Guards

open Host

private def duplicateKeyLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"DROP TABLE users\",\"sql\":\"SELECT 1\"}}}"

private def ordinaryLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"SELECT 1\"}}}"

private def literalUtf8Line : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"memo\":\"naïve 日本語\"}}}"

private def canonicalEquivalentKeyLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"kéy\":\"safe\",\"kéy\":\"dangerous\"}}}"

private def distinctUtf8KeysLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"名前\":\"seal\",\"値\":\"naïve 日本語\"}}}"

private def className : LineClass → String
  | .passthrough => "passthrough"
  | .act _ => "act"
  | .refuse => "refuse"

example : className (classifyLine duplicateKeyLine) = "refuse" := by native_decide
example : className (classifyLine ordinaryLine) = "act" := by native_decide
example : className (classifyLine literalUtf8Line) = "act" := by native_decide
example : className (classifyLine canonicalEquivalentKeyLine) = "refuse" := by native_decide
example : className (classifyLine distinctUtf8KeysLine) = "act" := by native_decide

#eval "duplicate-key: " ++ className (classifyLine duplicateKeyLine)
#eval "ordinary: " ++ className (classifyLine ordinaryLine)
#eval "literal-utf8: " ++ className (classifyLine literalUtf8Line)
#eval "canonical-equivalent-key: " ++ className (classifyLine canonicalEquivalentKeyLine)
#eval "distinct-utf8-keys: " ++ className (classifyLine distinctUtf8KeysLine)

end Test.RepinStep2Guards

def main : IO Unit := IO.println "repin_step2_guards: all five raw-wire guard cases hold (compile-time)"
