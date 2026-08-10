/- SPDX-License-Identifier: Apache-2.0 -/

import Ffi

private def duplicateKeyLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"a\",\"sql\":\"b\"}}}"

private def ordinaryToolsCallLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"SELECT 1\"}}}"

private def nonToolsCallLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"

private def numericCall (arguments : String) : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"external.json_corpus\",\"arguments\":"
    ++ arguments ++ "}}"

private def negIntHugeExpLine : String := numericCall "[-1e+9999]"
private def posDoubleHugeExpLine : String := numericCall "[1.5e+9999]"
private def realNegOverflowLine : String := numericCall "[-123123e100000]"
private def realPosOverflowLine : String := numericCall "[123123e100000]"

-- Ordinary integers, decimals, negatives, and exponents that satisfy the
-- binary64 agreement predicate remain mediated acts.
private def ordinaryNumbersLine : String :=
  numericCall "[0,42,-17,1.5,-0.125,1e3,-2.5e-4,1e308]"

#guard Ffi.sealHostClassify duplicateKeyLine == (2 : UInt32)
#guard Ffi.sealHostClassify ordinaryToolsCallLine == (1 : UInt32)
#guard Ffi.sealHostClassify nonToolsCallLine == (0 : UInt32)
#guard Ffi.sealHostClassify negIntHugeExpLine == (2 : UInt32)
#guard Ffi.sealHostClassify posDoubleHugeExpLine == (2 : UInt32)
#guard Ffi.sealHostClassify realNegOverflowLine == (2 : UInt32)
#guard Ffi.sealHostClassify realPosOverflowLine == (2 : UInt32)
#guard Seal.JsonUtil.wireNumbersAgreementSafe
  ordinaryNumbersLine.trimAscii.toString = true
#guard Ffi.sealHostClassify ordinaryNumbersLine == (1 : UInt32)

def main : IO Unit := pure ()
