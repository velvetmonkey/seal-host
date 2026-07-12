/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Config

private def expect (name : String) (condition : Bool) : IO Unit :=
  unless condition do throw <| IO.userError s!"FAIL: {name}"

def main : IO Unit := do
  let outer := "{\"epoch\":1,\"server\":\"github-main\",\"safety\":{\"approval\":{\"control_file\":\"/tmp/a\",\"ttl_seconds\":120},\"tools\":[]}}"
  expect "outer trusted-config server is accepted by released policy core"
    (match Host.parseCanonicalConfigPayload outer with
     | .ok _ => true
     | .error _ => false)

  let conflict := "{\"epoch\":1,\"server\":\"outer\",\"safety\":{\"server\":\"inner\",\"approval\":{\"control_file\":\"/tmp/a\",\"ttl_seconds\":120},\"tools\":[]}}"
  expect "conflicting server identities fail closed"
    (match Host.parseCanonicalConfigPayload conflict with
     | .error error => error == "server identity conflicts between trusted config and safety policy"
     | .ok _ => false)

  IO.println "policy server identity tests passed"
