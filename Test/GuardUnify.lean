/- SPDX-License-Identifier: Apache-2.0 -/

import Host.ObjectA
import Host.UnicodeKeys
import Host.SurrogateEscapes
import Host.NestingDepth

open Lean

namespace Test.GuardUnify

private def digits : String :=
  "{\"route\":\"forward\",\"n\":1000000000000000000}"

private def unicodeKeys : String :=
  "{\"route\":\"forward\",\"kéy\":\"safe\",\"kéy\":\"dangerous\"}"

private def numberAgreement : String :=
  "{\"route\":\"forward\",\"n\":-1e+9999}"

private def surrogate : String :=
  "{\"route\":\"forward\",\"note\":\"\\ud800\"}"

private def depth : String :=
  "{\"route\":\"forward\",\"nested\":" ++
    String.ofList (List.replicate 129 '[' ++ ['0'] ++ List.replicate 129 ']') ++
    "}"

-- F1 first: the significant-digit bound rejects a literal both parsers used
-- to accept.
#guard Seal.JsonUtil.wireDigitsSafe digits = false
#guard Seal.JsonUtil.wireNumbersAgreementSafe digits = true
#guard Host.StatementParsing.presentedJson? digits.toUTF8 = none
#guard Host.ObjectB.verdictOfRaw digits.toUTF8 = none

#guard Host.UnicodeKeys.wireKeysSafe unicodeKeys = false
#guard Host.StatementParsing.presentedJson? unicodeKeys.toUTF8 = none
#guard Host.ObjectB.verdictOfRaw unicodeKeys.toUTF8 = none

#guard Seal.JsonUtil.wireNumbersAgreementSafe numberAgreement = false
#guard Host.StatementParsing.presentedJson? numberAgreement.toUTF8 = none
#guard Host.ObjectB.verdictOfRaw numberAgreement.toUTF8 = none

#guard Host.SurrogateEscapes.wireSurrogatesSafe surrogate = false
#guard Host.StatementParsing.presentedJson? surrogate.toUTF8 = none
#guard Host.ObjectB.verdictOfRaw surrogate.toUTF8 = none

#guard Host.NestingDepth.wireDepthSafe depth = false
#guard Host.StatementParsing.presentedJson? depth.toUTF8 = none
#guard Host.ObjectB.verdictOfRaw depth.toUTF8 = none

end Test.GuardUnify

def main : IO Unit :=
  IO.println "guard_unify_tests: both raw parsers enforce all seven wire guards"
