import SealModule from './build-core/seal.js';
let errlog = [];
const M = await SealModule({
  print:    (t) => errlog.push("[out] "+t),
  printErr: (t) => errlog.push("[err] "+t),
});
const toolCall = JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"db.execute",arguments:{sql:"DROP TABLE users"}}});
const input = JSON.stringify({ line: toolCall, now: 1000, approvals: [], votes:"", grants:[], forecasts:"" });
try {
  const verdict = M.ccall('seal_decide','string',['string'],[input]);
  console.log("VERDICT:", verdict);
} catch(e) {
  console.log("TRAP:", e.message);
}
console.log("--- lean/emscripten output captured ---");
console.log(errlog.slice(-25).join("\n") || "(none)");
