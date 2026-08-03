/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.JsonUtil
import Host.UnicodeKeys
import Host.SurrogateEscapes
import Host.NestingDepth

/-!
# Shared raw-JSON wire boundary

Every host path that parses presenter-controlled JSON first crosses this one
ordered guard set. The checks close, respectively: pathological exponent
cost, duplicate or escaped keys, Unicode-canonical-equivalent keys, excessive
mantissa digits, binary64 disagreement, unpaired surrogate escapes, and
excessive nesting depth.
-/

namespace Host.JsonWire

/-- The host's complete pre-parse JSON wire guard set, in perimeter order. -/
def safe (text : String) : Bool :=
  Seal.JsonUtil.wireNumbersSafe text &&
  Seal.JsonUtil.wireKeysSafe text &&
  Host.UnicodeKeys.wireKeysSafe text &&
  Seal.JsonUtil.wireDigitsSafe text &&
  Seal.JsonUtil.wireNumbersAgreementSafe text &&
  Host.SurrogateEscapes.wireSurrogatesSafe text &&
  Host.NestingDepth.wireDepthSafe text

end Host.JsonWire
