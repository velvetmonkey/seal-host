/- SPDX-License-Identifier: Apache-2.0 -/

import Ffi

private def duplicateKeyLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"a\",\"sql\":\"b\"}}}"

private def ordinaryToolsCallLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"SELECT 1\"}}}"

private def nonToolsCallLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"

#guard Ffi.sealHostClassify duplicateKeyLine == (2 : UInt32)
#guard Ffi.sealHostClassify ordinaryToolsCallLine == (1 : UInt32)
#guard Ffi.sealHostClassify nonToolsCallLine == (0 : UInt32)

def main : IO Unit := pure ()
