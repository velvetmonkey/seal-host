import SealModule from './build-core/seal_a.js';
const M = await SealModule();
const decide = (obj) => M.ccall('seal_decide','string',['string'],[JSON.stringify(obj)]);

const toolCall = JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"db.execute",arguments:{sql:"DROP TABLE users"}}});
const input = { line: toolCall, now: 1000, approvals: [], votes: "", grants: [], forecasts: "" };

console.log("INPUT tool-call:", "db.execute / DROP TABLE users  (no approval)");
const verdict = decide(input);
console.log("VERIFIED VERDICT:", verdict);

// second: same call WITH an approval present
const input2 = { ...input, approvals: [{target:"db.execute", issuedAt: 999}] };
console.log("\nINPUT tool-call: same, WITH approval for db.execute");
console.log("VERIFIED VERDICT:", decide(input2));
