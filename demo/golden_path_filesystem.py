#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Filesystem flagship: real reads, guarded writes, Budget, and no host mounts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path

import golden_path as gp

ROOT = gp.ROOT
KIT = gp.KIT
HOST = ROOT / "rust" / "target" / "release" / "seal-host-rs"
# MUST move with the kernel: this pins the assurance kit whose wasm verifies
# the receipts this demo produces. Stale pin = verifying today's receipts with
# yesterday's kernel. Keep it in step with the checkout ref in
# .github/workflows/golden-path.yml — a `grep <kernel-sha>` sweep cannot see
# either, because both name the staleness as a COMMIT sha.
# 0aeb35a carries kernel ff1bfd68 (6d0d6eb carried d3067bc0, 0db03ef carried df42).
PHASE_B_KIT_REV = "0aeb35a60adfa4c50b6bfcf761967b1c6280fde7"
PINNED_FILESYSTEM_IMAGE = "node@sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4"
FILESYSTEM_IMAGE = os.environ.get("SEAL_FILESYSTEM_IMAGE", PINNED_FILESYSTEM_IMAGE)

FILESYSTEM_TIER = {
    "tier": "dev-box deterministic-tested (local run); CI configured but not run; operator-verified: NO",
    "evidence_scope": "local containment, benign read, both tamper legs, approved absolute/traversal rejection, real one-shot write, accumulated Budget denial, fresh-state receipt verification, stateful audit evidence, and scan passed",
    "proven": "S+B reference invariants are machine-checked; filesystem containment is integration evidence",
    "ci_tested": False,
    "ci_status": "configured; pending Phase B assurance-kit and seal-host pushes plus first green workflow",
    "operator_verified": False,
    "operator_status": "operator-untested until run by Ben",
}

IDLE_SOURCE = "setInterval(()=>{},1000000)"
WORKSPACE = "/workspace"

SERVER_SOURCE = r'''const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const ROOT = "/workspace";

const send = value => { process.stdout.write(JSON.stringify(value) + "\n"); };
const result = (id, text, error=false) => send({jsonrpc:"2.0",id,result:{content:[{type:"text",text}],isError:error}});
const rejectPath = value => {
  console.error("SEAL_FILESYSTEM_PATH_REJECTED " + JSON.stringify(value));
  throw new Error("PATH_REJECTED: path must remain beneath /workspace");
};
function confined(value, allowRoot=true) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) return rejectPath(value);
  const candidate = path.isAbsolute(value) ? path.resolve(value) : path.resolve(ROOT, value);
  if (candidate !== ROOT && !candidate.startsWith(ROOT + path.sep)) return rejectPath(value);
  if (!allowRoot && candidate === ROOT) return rejectPath(value);
  let probe = candidate;
  while (!fs.existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) return rejectPath(value);
    probe = parent;
  }
  const real = fs.realpathSync(probe);
  if (real !== ROOT && !real.startsWith(ROOT + path.sep)) return rejectPath(value);
  return candidate;
}
function walk(dir) {
  return fs.readdirSync(dir, {withFileTypes:true}).map(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? {name:entry.name,type:"directory",children:walk(full)} : {name:entry.name,type:"file"};
  });
}
const tools = [
  {name:"read_text_file",description:"Read UTF-8 text beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"read_media_file",description:"Read a file beneath /workspace as base64.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"read_multiple_files",description:"Read multiple UTF-8 files beneath /workspace.",inputSchema:{type:"object",properties:{paths:{type:"array",items:{type:"string"}}},required:["paths"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"list_directory",description:"List one directory beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"list_directory_with_sizes",description:"List a directory and file sizes beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"directory_tree",description:"Return a directory tree beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"search_files",description:"Search filenames beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"},pattern:{type:"string"}},required:["path","pattern"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"get_file_info",description:"Stat one path beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"list_allowed_directories",description:"List the sole writable filesystem root.",inputSchema:{type:"object",properties:{},additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:"write_file",description:"Write UTF-8 content beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"},content:{type:"string"}},required:["path","content"],additionalProperties:false},annotations:{destructiveHint:true}},
  {name:"edit_file",description:"Replace UTF-8 content in an existing file beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"},content:{type:"string"}},required:["path","content"],additionalProperties:false},annotations:{destructiveHint:true}},
  {name:"create_directory",description:"Create a directory beneath /workspace.",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false},annotations:{destructiveHint:true}},
  {name:"move_file",description:"Move a file within /workspace.",inputSchema:{type:"object",properties:{source:{type:"string"},destination:{type:"string"}},required:["source","destination"],additionalProperties:false},annotations:{destructiveHint:true}},
];

console.error("SEAL_FILESYSTEM_SERVER_READY");
const rl = readline.createInterface({input:process.stdin,crlfDelay:Infinity});
rl.on("line", line => {
  let message;
  try { message = JSON.parse(line); } catch { return; }
  const id = message.id;
  const method = message.method;
  if (method === "initialize") {
    send({jsonrpc:"2.0",id,result:{protocolVersion:"2025-06-18",capabilities:{tools:{}},serverInfo:{name:"seal-filesystem-demo",version:"1.0.0"}}});
  } else if (method === "tools/list") {
    console.error("SEAL_FILESYSTEM_TOOLS_LIST_RECEIVED");
    send({jsonrpc:"2.0",id,result:{tools}});
  } else if (method === "tools/call") {
    const name = message.params?.name;
    const args = message.params?.arguments || {};
    try {
      if (name === "read_text_file") {
        console.error("SEAL_FILESYSTEM_READ_RECEIVED");
        result(id, fs.readFileSync(confined(args.path, false), "utf8"));
      } else if (name === "read_media_file") {
        result(id, fs.readFileSync(confined(args.path, false)).toString("base64"));
      } else if (name === "read_multiple_files") {
        result(id, JSON.stringify(args.paths.map(p => ({path:p,content:fs.readFileSync(confined(p,false),"utf8")}))));
      } else if (name === "list_directory") {
        result(id, JSON.stringify(fs.readdirSync(confined(args.path))));
      } else if (name === "list_directory_with_sizes") {
        const dir = confined(args.path); result(id, JSON.stringify(fs.readdirSync(dir).map(n => ({name:n,size:fs.statSync(path.join(dir,n)).size}))));
      } else if (name === "directory_tree") {
        result(id, JSON.stringify(walk(confined(args.path))));
      } else if (name === "search_files") {
        const base = confined(args.path); const needle = String(args.pattern).toLowerCase();
        const found=[]; const visit=d=>fs.readdirSync(d,{withFileTypes:true}).forEach(e=>{const f=path.join(d,e.name);if(e.isDirectory())visit(f);else if(e.name.toLowerCase().includes(needle))found.push(f)}); visit(base); result(id,JSON.stringify(found));
      } else if (name === "get_file_info") {
        const stat=fs.statSync(confined(args.path)); result(id,JSON.stringify({size:stat.size,isFile:stat.isFile(),isDirectory:stat.isDirectory()}));
      } else if (name === "list_allowed_directories") {
        result(id, ROOT);
      } else if (name === "write_file" || name === "edit_file") {
        const target=confined(args.path,false); if(name === "edit_file" && !fs.existsSync(target)) throw new Error("edit target missing");
        fs.writeFileSync(target,String(args.content),"utf8"); console.error("SEAL_FILESYSTEM_" + name.toUpperCase() + "_RECEIVED"); result(id,"written");
      } else if (name === "create_directory") {
        fs.mkdirSync(confined(args.path,false)); console.error("SEAL_FILESYSTEM_CREATE_DIRECTORY_RECEIVED"); result(id,"created");
      } else if (name === "move_file") {
        fs.renameSync(confined(args.source,false),confined(args.destination,false)); console.error("SEAL_FILESYSTEM_MOVE_FILE_RECEIVED"); result(id,"moved");
      } else result(id,"unknown tool",true);
    } catch (error) { result(id,String(error.message || error),true); }
  } else if (id !== undefined) send({jsonrpc:"2.0",id,error:{code:-32601,message:"method not found"}});
});
'''


@dataclass
class Check:
    name: str
    status: str
    evidence: str


CHECKS: list[Check] = []
VALIDATED_CONTAINER: str | None = None


def check(name: str, status: str, evidence: str) -> None:
    CHECKS.append(Check(name, status, evidence))
    print(f"[{status}] {name}: {evidence}", flush=True)


def print_table() -> None:
    print("\n=============== FILESYSTEM ADVERSARIAL ACCEPTANCE ===============")
    for row in CHECKS: print(f"{row.status:<4} | {row.name:<35} | {row.evidence}")
    print("=================================================================")


def build_named_release_targets() -> None:
    env = os.environ.copy(); env.pop("SEAL_LAKE_OLD", None)
    gp.run(["bash", "scripts/build_ffi_so.sh"], env=env)
    gp.run(["cargo", "build", "--release", "--manifest-path", "rust/Cargo.toml", "--bin", "seal-host-rs"], env=env)
    if not HOST.is_file(): raise gp.DemoFailure("named release host build did not produce seal-host-rs")
    check("named release build", "PASS", "exact FFI runtime closure + release seal-host-rs")


def preflight(deterministic: bool) -> None:
    branch = gp.run(["git", "branch", "--show-current"]).stdout.strip()
    head = gp.run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    if branch != "main" and os.environ.get("GITHUB_ACTIONS") != "true":
        raise gp.DemoSkip(f"seal-host must run from main, got {branch or 'detached'}")
    for binary in ["docker", "node", "npm", "cargo", "lake", "python3"]:
        if not shutil.which(binary): raise gp.DemoSkip(f"required command missing: {binary}")
    if FILESYSTEM_IMAGE != PINNED_FILESYSTEM_IMAGE:
        raise gp.DemoSkip(f"refusing unpinned filesystem image override: {FILESYSTEM_IMAGE}")
    kit_head = gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip()
    if kit_head != PHASE_B_KIT_REV: raise gp.DemoSkip(f"Phase B assurance kit required: got {kit_head}")
    image = subprocess.run(["docker","image","inspect",FILESYSTEM_IMAGE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if image.returncode != 0: raise gp.DemoSkip(f"pinned filesystem image is not local; refusing to pull: {FILESYSTEM_IMAGE}")
    if not deterministic and (not sys.stdin.isatty() or not sys.stderr.isatty()):
        raise gp.DemoSkip("live mode requires a controlling TTY")
    check("base + prerequisites", "PASS", f"main@{head}; Phase B kit pinned; mode={'deterministic' if deterministic else 'live'}")


def container_args(name: str) -> list[str]:
    return [
        "docker","run","--pull=never","--rm","--detach","--name",name,
        "--network","none","--read-only","--user","1000:1000",
        "--cap-drop","ALL","--security-opt","no-new-privileges:true",
        "--tmpfs","/workspace:rw,nosuid,nodev,size=32m,uid=1000,gid=1000",
        FILESYSTEM_IMAGE,"node","-e",IDLE_SOURCE,
    ]


def inspect_containment(name: str) -> None:
    global VALIDATED_CONTAINER
    info = json.loads(gp.run(["docker","inspect",name]).stdout)[0]
    host = info["HostConfig"]; failures=[]
    if info.get("Name") != f"/{name}": failures.append("wrong name")
    if not info["State"].get("Running"): failures.append("not running")
    if not host.get("AutoRemove"): failures.append("AutoRemove != true")
    if host.get("NetworkMode") != "none": failures.append("network != none")
    if not host.get("ReadonlyRootfs"): failures.append("root writable")
    if info["Config"].get("User") != "1000:1000": failures.append("user != 1000:1000")
    if info["Config"].get("Image") != FILESYSTEM_IMAGE: failures.append("wrong image")
    if info["Config"].get("Cmd") != ["node","-e",IDLE_SOURCE]: failures.append("wrong idle command")
    if info.get("Mounts"): failures.append("host/container mounts present")
    if host.get("Binds"): failures.append("bind present")
    if host.get("PortBindings") or host.get("PublishAllPorts"): failures.append("published port")
    if set(host.get("Tmpfs") or {}) != {"/workspace"}: failures.append("/workspace is not sole tmpfs")
    if "ALL" not in (host.get("CapDrop") or []): failures.append("CapDrop lacks ALL")
    if not any(str(x).startswith("no-new-privileges") for x in (host.get("SecurityOpt") or [])): failures.append("NPP absent")
    if failures: raise gp.DemoSkip("filesystem containment failed: " + "; ".join(failures))
    VALIDATED_CONTAINER = name
    check("containment preflight", "PASS", f"{name}: --rm/network-none/RO/rootless/no-mounts/no-ports; only /workspace writable")


def start_container() -> str:
    name = f"seal-gp-filesystem-{uuid.uuid4().hex[:12]}"
    gp.run(container_args(name)); gp.ACTIVE_CONTAINERS.add(name)
    inspect_containment(name)
    probe = subprocess.run(["docker","exec",name,"node","-e",'require("fs").accessSync("/workspace",require("fs").constants.W_OK)'])
    if probe.returncode != 0: raise gp.DemoFailure("/workspace not writable after containment validation")
    return name


def stop_container(name: str) -> None:
    global VALIDATED_CONTAINER
    gp.stop_container(name)
    if VALIDATED_CONTAINER == name: VALIDATED_CONTAINER = None


def exec_node(name: str, source: str, args: list[str] | None = None, expect: int = 0) -> subprocess.CompletedProcess[str]:
    if VALIDATED_CONTAINER != name: raise gp.DemoFailure("refusing container file access before validation")
    command = ["docker","exec",name,"node","-e",source,"--",*(args or [])]
    print("$ " + " ".join(command[:5]) + " <container-only script>", flush=True)
    result = subprocess.run(command,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode != expect:
        raise gp.DemoFailure(f"container node expected {expect}, got {result.returncode}: {result.stderr}")
    return result


def seed_file(name: str, path: str, content: str) -> None:
    script='const fs=require("fs"),p=require("path");const f=process.argv[1],c=process.argv[2];fs.mkdirSync(p.dirname(f),{recursive:true});fs.writeFileSync(f,c,"utf8")'
    exec_node(name,script,[path,content])


def file_exists(name: str, path: str) -> bool:
    result=exec_node(name,'process.stdout.write(require("fs").existsSync(process.argv[1])?"yes":"no")',[path])
    return result.stdout == "yes"


def read_file(name: str, path: str) -> str:
    return exec_node(name,'process.stdout.write(require("fs").readFileSync(process.argv[1],"utf8"))',[path]).stdout


def server_command(name: str) -> list[str]:
    if VALIDATED_CONTAINER != name: raise gp.DemoFailure("refusing MCP server before containment validation")
    return ["docker","exec","-i",name,"node","-e",SERVER_SOURCE]


def capture_manifest(name: str, work: Path) -> Path:
    proc=gp.LineProcess(server_command(name))
    try:
        proc.send(gp.request(100,"initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fs-gp","version":"1"}})); init=json.loads(proc.line())
        proc.send(gp.request(101,"tools/list")); listed=json.loads(proc.line())
        ident=init["result"]["serverInfo"]
        manifest={"server":f"{ident['name']}@{ident['version']}","tools":listed["result"]["tools"]}
        expected=["read_text_file","read_media_file","read_multiple_files","list_directory","list_directory_with_sizes","directory_tree","search_files","get_file_info","list_allowed_directories","write_file","edit_file","create_directory","move_file"]
        if [t["name"] for t in manifest["tools"]] != expected: raise gp.DemoFailure("filesystem manifest mismatch")
        path=work/"filesystem.tools.json"; path.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
        check("live tools/list manifest","PASS",f"captured {len(expected)} filesystem tools from contained server")
        return path
    finally: proc.close()


def prepare_policy(seal: Path, manifest: Path, work: Path, deterministic: bool):
    policy=work/"filesystem.policy.json"
    gp.run([str(seal),"init",str(manifest),"--out",str(policy)])
    added=gp.run([str(seal),"add-kernel","B",str(manifest),"--policy",str(policy)])
    if "added kernel  budget (B) — ACTIVE" not in added.stdout: raise gp.DemoFailure("add-kernel B did not report ACTIVE")
    before=policy.read_text(encoding="utf-8"); value=json.loads(before)
    approvals=work/"unused-control-approvals.ndjson"; approvals.write_text("",encoding="utf-8")
    value["safety"]["approval"]["control_file"]=str(approvals)
    value["safety"]["approval"]["replay_store"]={"sqlite_path":str(work/"approval-replay.sqlite")}
    for rule in value["safety"]["tools"]:
        if rule["mode"] == "allow": rule["_comment"]="unverified suggestion -- server self-described readOnly"
    value["budget"]={"budgets":[{"name":"destructive-file-ops","cap":2,"tools":["write_file","edit_file","create_directory","move_file"],"_comment":"reviewed demo cap: two executed destructive file operations per host session"}]}
    value["safety"]["_seal_demo_tier"]=FILESYSTEM_TIER
    after=json.dumps(value,indent=2)+"\n"
    if "EDIT-ME" in after: raise gp.DemoFailure("reviewed filesystem policy still contains EDIT-ME")
    print("\n=== VISIBLE INIT + ADD-KERNEL B REVIEW ===")
    print("".join(unified_diff(before.splitlines(True),after.splitlines(True),fromfile="init + add-kernel B",tofile="reviewed S+B")))
    policy.write_text(after,encoding="utf-8")
    config_key=work/"filesystem-policy.seed"; approval_key=work/"filesystem-approval.seed"
    config_key.write_text(os.urandom(32).hex()+"\n",encoding="utf-8"); approval_key.write_text(os.urandom(32).hex()+"\n",encoding="utf-8")
    os.chmod(config_key,0o600); os.chmod(approval_key,0o600)
    config_pub=gp.node_public_key(config_key); approval_pub=gp.node_public_key(approval_key)
    trusted=work/"filesystem.policy.signed.json"
    command=[str(seal),"policy","sign",str(policy),"--key",str(config_key),"--out",str(trusted)]
    signed=gp.run(command+(["--yes"] if deterministic else []),visible=not deterministic)
    if deterministic:
        output=(signed.stdout or "")+(signed.stderr or "")
        if "ACTIVE (2)" not in output or "PRESENT-BUT-INACTIVE (0)" not in output: raise gp.DemoFailure("sign ack not ACTIVE {S,B}")
    check("init + add-kernel B policy","PASS","ACTIVE {S,B}; cap=2 over four destructive tools; zero vacuity/placeholders")
    return policy,trusted,config_pub,approval_key,approval_pub


def host_command(name: str, trusted: Path, config_pub: str, approval_pub: str, tokens: Path, receipts: Path) -> list[str]:
    return [str(HOST),"--config",str(trusted),"--pubkey",config_pub,"--channel","ed25519","--token-file",str(tokens),"--approval-pubkey",approval_pub,"--receipt-dir",str(receipts),"--",*server_command(name)]


class HostSession:
    def __init__(self,label: str,name: str,trusted: Path,config_pub: str,approval_pub: str,work: Path):
        self.label=label; self.tokens=work/f"{label}-tokens.ndjson"; self.tokens.write_text("",encoding="utf-8"); self.receipts=work/f"{label}-receipts"
        self.proc=gp.LineProcess(host_command(name,trusted,config_pub,approval_pub,self.tokens,self.receipts))
        self.proc.send(gp.request(100,"initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":label,"version":"1"}})); json.loads(self.proc.line())
        self.proc.send(gp.request(101,"tools/list")); json.loads(self.proc.line()); self.wait_stderr("SEAL_FILESYSTEM_SERVER_READY")
    def wait_stderr(self,text: str,timeout: float=5)->None:
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if any(text in line for line in self.proc.stderr_lines): return
            time.sleep(.02)
        raise gp.DemoFailure(f"{self.label}: missing stderr marker {text}")
    def wait_marker_count(self,text: str,count: int,timeout: float=5)->None:
        """Wait for EXACTLY `count` occurrences of a stderr marker.

        Markers travel on stderr; responses travel on stdout. They are separate
        pipes with independent buffering and NO ordering guarantee between them,
        so having read a response tells you nothing about whether that call's
        marker has been drained yet. `wait_stderr` returns on the FIRST match,
        which is instant once any earlier call emitted one -- so waiting for the
        marker and then asserting a count of N is a race, not a check. Wait for
        the COUNT. Overshoot is reported as itself, never rounded down to pass."""
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            seen=self.marker_count(text)
            if seen>=count: break
            time.sleep(.02)
        seen=self.marker_count(text)
        if seen!=count: raise gp.DemoFailure(f"{self.label}: expected {count}x {text}, saw {seen}")
    def call(self,tool: str,args: dict)->tuple[dict,Path]:
        before=set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
        self.proc.send(gp.request(1,"tools/call",{"name":tool,"arguments":args})); response=json.loads(self.proc.line())
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            created=sorted((set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set())-before)
            if len(created)==1: return response,created[0]
            if len(created)>1: raise gp.DemoFailure("multiple receipts for one call")
            time.sleep(.02)
        raise gp.DemoFailure(f"missing receipt for {tool}")
    def append(self,token: dict)->None:
        with self.tokens.open("a",encoding="utf-8") as f: f.write(gp.compact(token)+"\n")
    def marker_count(self,text: str)->int: return sum(text in line for line in self.proc.stderr_lines)
    def close(self)->None: self.proc.close()


def block(response: dict,contains: str="approval required")->None:
    if response.get("result",{}).get("isError") is not True or contains.lower() not in gp.compact(response).lower(): raise gp.DemoFailure(f"expected BLOCK {contains}: {response}")


def forwarded(response: dict)->None:
    if response.get("result",{}).get("isError") is not False: raise gp.DemoFailure(f"expected forwarded success: {response}")


def token(key: Path,target: str,label: str)->dict: return gp.approval_token(key,target,f"filesystem-{label}-{uuid.uuid4().hex}")
def receipt(path: Path)->dict: return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path)->str:
    digest=hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()


def export_gate0a_receipts(work: Path,output: Path,trusted: Path,config_pub: str)->None:
    read_records=sorted((work/"read-receipts").glob("receipt-*.json"))
    one_shot_records=sorted((work/"one-shot-receipts").glob("receipt-*.json"))
    if len(read_records)!=1 or len(one_shot_records)<2: raise gp.DemoFailure("Gate 0A receipt selection is ambiguous")
    selected={"allow.json":read_records[0],"block.json":one_shot_records[0]}
    expected={
        "native_executable_sha256":sha256_file(HOST),
        "lean_ffi_sha256":sha256_file(ROOT/".lake"/"build"/"lib"/"libsealffi.so"),
        "equivalence":"not_proven",
    }
    envelope=json.loads(trusted.read_text(encoding="utf-8"))
    expected_signed_config={"payload":envelope["payload"],"signature":envelope["signature"],"pubkey":config_pub}
    records={name:receipt(path) for name,path in selected.items()}
    if records["allow.json"].get("verdict")!="ALLOW" or records["allow.json"].get("authorization")!="explicit_policy_allow": raise gp.DemoFailure("selected Gate 0A ALLOW receipt is not explicit-policy ALLOW")
    if records["block.json"].get("verdict")!="BLOCK": raise gp.DemoFailure("selected Gate 0A BLOCK receipt is not BLOCK")
    for name,record in records.items():
        if record.get("host_identity")!=expected: raise gp.DemoFailure(f"{name} host_identity does not match release artifacts")
        if record.get("signed_config")!=expected_signed_config: raise gp.DemoFailure(f"{name} signed_config does not equal the init envelope + pubkey")
        if gp.compact(record.get("kernel_config"))!=expected_signed_config["payload"]: raise gp.DemoFailure(f"{name} kernel_config is not byte-identical to signed_config.payload")
    output.mkdir(parents=True,exist_ok=False)
    for name,source in selected.items(): shutil.copyfile(source,output/name)
    print("\n=== GATE 0A PRESERVED RECEIPTS ===")
    for name in ["allow.json","block.json"]:
        record=records[name]
        print(json.dumps({"file":str(output/name),"verdict":record["verdict"],"authorization":record.get("authorization"),"signed_config":record["signed_config"],"host_identity":record["host_identity"]},indent=2))
    check("Gate 0A receipt export", "PASS", "release ALLOW + BLOCK carry the exact init envelope + matching config pubkey; host hashes match live artifacts; equivalence=not_proven")


def verify_receipt(seal: Path,path: Path,verdict: str)->None:
    record=receipt(path)
    if record.get("kernel_config",{}).get("safety",{}).get("_seal_demo_tier")!=FILESYSTEM_TIER: raise gp.DemoFailure("receipt tier mismatch")
    result=gp.run([str(seal),"verify",str(path)])
    if "PASS  VERIFIED" not in result.stdout or record.get("verdict")!=verdict: raise gp.DemoFailure(f"receipt verification failed: {path}")


def approved_retry(session: HostSession,key: Path,tool: str,args: dict,label: str):
    first,_=session.call(tool,args); block(first); session.append(token(key,gp.target_from(first),label)); return session.call(tool,args)


def read_leg(name: str,seal: Path,trusted: Path,config_pub: str,approval_pub: str,work: Path)->None:
    path="/workspace/demo_read.txt"; content="contained benign read\n"; seed_file(name,path,content)
    session=HostSession("read",name,trusted,config_pub,approval_pub,work)
    try:
        response,record=session.call("read_text_file",{"path":path}); forwarded(response)
        observed=response["result"]["content"][0]["text"]
        if observed != content: raise gp.DemoFailure("read response content mismatch")
        verify_receipt(seal,record,"ALLOW")
        check("benign read flows","PASS","read_text_file forwarded; exact tmpfs content observed; fresh-state ALLOW receipt VERIFIED")
    finally: session.close()


def policy_tamper(name: str,trusted: Path,config_pub: str,approval_pub: str,work: Path)->None:
    sentinel="/workspace/demo_policy_tamper.txt"; seed_file(name,sentinel,"unchanged")
    envelope=json.loads(trusted.read_text(encoding="utf-8")); marker="seal-filesystem-demo@1.0.0"
    if marker not in envelope["payload"]: raise gp.DemoFailure("signed filesystem server marker missing")
    envelope["payload"]=envelope["payload"].replace(marker,"seal-filesystem-demo@1.0.1",1)
    tampered=work/"filesystem.policy.tampered.json"; tampered.write_text(gp.compact(envelope)+"\n",encoding="utf-8")
    tokens=work/"policy-tamper-tokens.ndjson"; tokens.write_text("",encoding="utf-8")
    result=subprocess.run(host_command(name,tampered,config_pub,approval_pub,tokens,work/"policy-tamper-receipts"),cwd=ROOT,text=True,input="",stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode!=3 or "trusted config rejected" not in result.stderr or "SEAL_FILESYSTEM_SERVER_READY" in result.stderr: raise gp.DemoFailure("policy tamper did not reject before MCP exec")
    if read_file(name,sentinel)!="unchanged": raise gp.DemoFailure("policy tamper changed sentinel")
    check("policy tamper fail-closed","PASS","payload byte changed; host rejected before filesystem MCP exec; sentinel unchanged")


def approval_tamper(name: str,seal: Path,trusted: Path,config_pub: str,key: Path,approval_pub: str,work: Path)->None:
    path="/workspace/demo_approval_tamper.txt"; session=HostSession("approval-tamper",name,trusted,config_pub,approval_pub,work)
    try:
        args={"path":path,"content":"must not exist"}; first,_=session.call("write_file",args); block(first); bad=token(key,gp.target_from(first),"bad-signature"); sig=bad["signature"]; bad["signature"]=sig[:-1]+("0" if sig[-1]!="0" else "1"); session.append(bad)
        second,record=session.call("write_file",args); block(second); session.wait_stderr("bad_signature")
        if file_exists(name,path) or session.marker_count("SEAL_FILESYSTEM_WRITE_FILE_RECEIVED")!=0: raise gp.DemoFailure("tampered approval wrote file")
        verify_receipt(seal,record,"BLOCK")
        check("approval tamper fail-closed","PASS","bad_signature; no downstream write; file absent; fresh-state BLOCK receipt VERIFIED")
    finally: session.close()


def path_escape_leg(name: str,trusted: Path,config_pub: str,key: Path,approval_pub: str,work: Path)->None:
    session=HostSession("path-escape",name,trusted,config_pub,approval_pub,work)
    try:
        paths=["/etc/seal_demo_escape","../../etc/seal_demo_escape"]
        for index,path in enumerate(paths):
            response,_=approved_retry(session,key,"write_file",{"path":path,"content":"escape"},f"escape-{index}")
            if response.get("result",{}).get("isError") is not True or "PATH_REJECTED" not in gp.compact(response): raise gp.DemoFailure(f"approved escape was not rejected: {response}")
        # Both escapes were already asserted PATH_REJECTED on their responses
        # above, so the adapter HAS rejected both. The markers are a different
        # channel: `rejectPath` console.error()s before throwing, but stderr and
        # stdout are separate pipes, so the marker for escape 1 may not be drained
        # when its response arrives. wait_stderr returns instantly here (escape 0
        # emitted a marker long ago), so the old count-of-2 assertion on the next
        # line was pure timing -- it passes on a warm dev box and loses on a
        # loaded CI runner. Wait for the count.
        session.wait_marker_count("SEAL_FILESYSTEM_PATH_REJECTED",2)
        if session.marker_count("SEAL_FILESYSTEM_WRITE_FILE_RECEIVED")!=0: raise gp.DemoFailure("escape reached write marker")
        if exec_node(name,'process.exit(require("fs").existsSync("/etc/seal_demo_escape")?1:0)').returncode!=0: raise gp.DemoFailure("absolute escape exists")
        if file_exists(name,"/workspace/seal_demo_escape"): raise gp.DemoFailure("workspace escape artifact exists")
        check("path escape rejection","PASS","valid approvals forwarded absolute + traversal paths; adapter PATH_REJECTED both before filesystem access")
    finally: session.close()


def one_shot(name: str,seal: Path,trusted: Path,config_pub: str,key: Path,approval_pub: str,work: Path)->None:
    path="/workspace/demo_approved_once.txt"; args={"path":path,"content":"written exactly once\n"}; session=HostSession("one-shot",name,trusted,config_pub,approval_pub,work)
    try:
        first,block_record=session.call("write_file",args); block(first); verify_receipt(seal,block_record,"BLOCK"); signed=token(key,gp.target_from(first),"one-shot"); session.append(signed)
        allowed,allow_record=session.call("write_file",args); forwarded(allowed)
        if read_file(name,path)!=args["content"] or session.marker_count("SEAL_FILESYSTEM_WRITE_FILE_RECEIVED")!=1: raise gp.DemoFailure("approved write observation mismatch")
        verify_receipt(seal,allow_record,"ALLOW"); session.append(signed); replay,_=session.call("write_file",args); block(replay); session.wait_stderr("replayed_nonce")
        if session.marker_count("SEAL_FILESYSTEM_WRITE_FILE_RECEIVED")!=1: raise gp.DemoFailure("replay reached filesystem")
        check("approved one-shot real write","PASS","BLOCK→signed ALLOW→file observed; replayed_nonce BLOCK; one downstream write")
        check("fresh write receipt verification","PASS","initial write BLOCK + first approved write ALLOW independently re-derived")
    finally: session.close()


def audit_material(session: HostSession):
    audits=[]; records=[]
    for line in session.proc.stderr_lines:
        try: value=json.loads(line)
        except json.JSONDecodeError: continue
        if value.get("seal_record")=="v1": records.append(value)
        elif "epoch" in value and "verdict" in value and "certs" in value: audits.append(line)
    return audits,records


def verify_audit(session: HostSession,work: Path)->None:
    audits,records=audit_material(session)
    if not audits or len(audits)!=len(records): raise gp.DemoFailure(f"audit mismatch {len(audits)}/{len(records)}")
    source=work/"budget-audit.ndjson"; sealed=work/"budget-audit.sealed.json"; source.write_text("\n".join(audits)+"\n",encoding="utf-8")
    gp.run(["node","scripts/seal_log.mjs","seal",str(source),str(sealed)]); gp.run(["node","scripts/seal_log.mjs","verify",str(sealed)])
    computed=json.loads(sealed.read_text(encoding="utf-8"))
    if [x["head"] for x in computed["entries"]]!=[x["head"] for x in records]: raise gp.DemoFailure("audit heads differ")


def budget_leg(name: str,trusted: Path,config_pub: str,key: Path,approval_pub: str,work: Path)->None:
    paths=[f"/workspace/demo_budget_{x}.txt" for x in ["one","two","three"]]; session=HostSession("budget",name,trusted,config_pub,approval_pub,work); terminal=None
    try:
        for index,path in enumerate(paths):
            response,record=approved_retry(session,key,"write_file",{"path":path,"content":f"budget {index}\n"},f"budget-{index}")
            if index<2: forwarded(response)
            else: block(response,"over budget"); terminal=record
        if not file_exists(name,paths[0]) or not file_exists(name,paths[1]) or file_exists(name,paths[2]): raise gp.DemoFailure("Budget file observations mismatch")
        if session.marker_count("SEAL_FILESYSTEM_WRITE_FILE_RECEIVED")!=2: raise gp.DemoFailure("Budget downstream count != 2")
        if receipt(terminal).get("deny_kernel")!="budget": raise gp.DemoFailure("terminal receipt deny_kernel != budget")
        verify_audit(session,work)
        check("accumulated Budget cap","PASS","two approved writes executed; N+1 fresh approval denied by Budget; third file absent")
        check("Budget stateful evidence","PASS","deny_kernel=budget; file/marker/audit-chain evidence retained; receipt not called independently verified")
    finally: session.close()


def scan(seal: Path,manifest: Path,policy: Path)->None:
    result=gp.run([str(seal),"scan",str(manifest),str(policy)])
    if "ACTIVE (2)" not in result.stdout or "PRESENT-BUT-INACTIVE (0)" not in result.stdout or not re.search(r"^\s*PASS\s+0 uncovered, 0 ungated,",result.stdout,re.M): raise gp.DemoFailure("filesystem scan not clean ACTIVE {S,B}")
    check("seal scan composition","PASS","ACTIVE {S,B}; zero vacuous, unknown, uncovered, or ungated entries")


def boundary_card(config_pub: str,approval_pub: str)->None:
    print(f"""
===================== FILESYSTEM SEAL BOUNDARY CARD =====================
PROVEN REFERENCE ENFORCEMENT
  Safety approval binding/one-shot; composed_budget_cap.
  Budget enforcement is machine-checked by composed_budget_cap; the specific
  runtime receipt for the accumulated N+1 block is evidence, not independently
  re-derivable by the fresh-state verifier because prior spend state is not
  receipt-carried.

SIGNED / VERIFIED KEYS
  Policy exact payload bytes: Ed25519 {config_pub}
  Approval exact {{target,issuedAt,nonce}} bytes: Ed25519 {approval_pub}

RECEIPTS / CONTAINMENT EVIDENCE
  Fresh-state read ALLOW, Safety BLOCK, bad-signature BLOCK, and first approved
  write ALLOW independently re-derived. Budget receipt + file observations +
  markers + audit chain are stateful evidence. Absolute/traversal rejection is
  runtime integration evidence; adapter/path resolver/Node/Docker/symlink
  behavior remain TCB. Session/trace receipt verification is future work.

HOST IDENTITY NON-CLAIM
  host_identity is ASSERTED provenance. The portable verifier checks shape
  only; a valid-hex substitution is NOT detected. Cross-checking the binary/FFI
  hashes requires the artifacts out-of-band. equivalence stays not_proven.
  Cryptographically binding host_identity is a future seal-check design
  question; this demo does not implement it.

DOES NOT ESTABLISH — LOUDLY
  MEDIATED MCP PATH ONLY. Direct host filesystem access, another MCP server,
  Docker access, or unmediated container exec is OUT OF SCOPE. No host path is
  mounted into the demo container; destructive tools can reach only /workspace.

TIER
  {FILESYSTEM_TIER['tier']}
  ci_tested=false; {FILESYSTEM_TIER['ci_status']}
  operator-untested until run by Ben.
==========================================================================
""",flush=True)
    check("boundary card","PASS","proof-vs-receipt, path-containment TCB, mediated-only boundary, tier, and roadmap printed")


def live_claude(name: str,trusted: Path,config_pub: str,key: Path,approval_pub: str,work: Path)->None:
    claude=shutil.which("claude")
    if not claude: raise gp.DemoSkip("Claude Code not installed")
    auth=gp.run([claude,"auth","status"])
    try: logged=json.loads(auth.stdout).get("loggedIn") is True
    except json.JSONDecodeError: logged='"loggedIn": true' in auth.stdout
    if not logged: raise gp.DemoSkip("Claude Code not authenticated")
    path="/workspace/project/README.md"; original="# Demo project\nStatus: draft\n"; seed_file(name,path,original)
    tokens=work/"claude-filesystem-tokens.ndjson"; tokens.write_text("",encoding="utf-8"); receipts=work/"claude-filesystem-receipts"; config=work/"claude-filesystem-mcp.json"
    config.write_text(json.dumps({"mcpServers":{"sealFilesystem":{"type":"stdio","command":str(HOST),"args":host_command(name,trusted,config_pub,approval_pub,tokens,receipts)[1:]}}},indent=2)+"\n",encoding="utf-8")
    command=[claude,"--output-format","stream-json","--verbose","--input-format","stream-json","--mcp-config",str(config),"--strict-mcp-config","--tools","","--allowedTools","mcp__sealFilesystem__read_text_file,mcp__sealFilesystem__write_file,mcp__sealFilesystem__edit_file","--permission-mode","dontAsk","--effort","high"]
    proc=gp.LineProcess(command)
    try:
        prompt="Review /workspace/project/README.md and update its status from draft to ready. Use only the sealFilesystem MCP tools; do not use Bash."
        proc.send({"type":"user","message":{"role":"user","content":prompt},"parent_tool_use_id":None,"session_id":"filesystem-golden-path"}); events=gp.claude_events_until_result(proc); uses=gp.tool_uses(events)
        reads=[u for u in uses if u.get("name","").endswith("__read_text_file") and (u.get("input") or {}).get("path")==path]
        writes=[u for u in uses if any(u.get("name","").endswith("__"+n) for n in ["write_file","edit_file"]) and (u.get("input") or {}).get("path")==path]
        records=[receipt(p) for p in receipts.glob("receipt-*.json")]
        if not reads or not any(r.get("tool")=="read_text_file" and r.get("verdict")=="ALLOW" for r in records): raise gp.DemoSkip("Claude did not naturally complete the benign read leg")
        check("live Claude benign read","PASS","Claude naturally read README and the mediated read flowed")
        if not writes or not any(r.get("tool") in {"write_file","edit_file"} and r.get("verdict")=="BLOCK" for r in records): raise gp.DemoSkip("Claude did not naturally attempt the guarded edit; no injected fallback counted")
        if read_file(name,path)!=original: raise gp.DemoFailure("live blocked edit changed README")
        match=re.search(r"approval required: ([0-9a-f]{64})",gp.compact(events))
        if not match: raise gp.DemoFailure("live guarded edit lacks approval target")
        target=match.group(1)
        print("\nHUMAN APPROVAL PATH (shown, not executed):")
        print(f"python3 demo/approve_cli.py --token-file {tokens} --target {target} --key-file {key} --approve")
        check("live Claude guarded edit","PASS","Claude naturally attempted destructive edit; Seal BLOCKED; README unchanged")
        check("actionable human approval prompt","PASS",f"target={target}; command printed; no approval/retry")
    finally: proc.close()


def execute(deterministic: bool,receipt_output: Path|None=None)->int:
    if receipt_output is not None and not deterministic: raise gp.DemoFailure("receipt export requires deterministic mode")
    preflight(deterministic); build_named_release_targets()
    with tempfile.TemporaryDirectory(prefix="seal-filesystem-golden-path-") as td:
        work=Path(td); name=start_container()
        try:
            seal=gp.temporary_install(work); manifest=capture_manifest(name,work); policy,trusted,config_pub,key,approval_pub=prepare_policy(seal,manifest,work,deterministic)
            if deterministic:
                read_leg(name,seal,trusted,config_pub,approval_pub,work); policy_tamper(name,trusted,config_pub,approval_pub,work); approval_tamper(name,seal,trusted,config_pub,key,approval_pub,work); path_escape_leg(name,trusted,config_pub,key,approval_pub,work); one_shot(name,seal,trusted,config_pub,key,approval_pub,work); budget_leg(name,trusted,config_pub,key,approval_pub,work); check("live authenticated Claude","SKIP","not invoked by deterministic/CI mode; operator-verified remains NO")
            else: live_claude(name,trusted,config_pub,key,approval_pub,work)
            scan(seal,manifest,policy); boundary_card(config_pub,approval_pub)
            if receipt_output is not None: export_gate0a_receipts(work,receipt_output,trusted,config_pub)
        finally: stop_container(name)
    return 0


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--deterministic",action="store_true"); parser.add_argument("--receipt-output"); args=parser.parse_args()
    try: return execute(args.deterministic,Path(args.receipt_output).resolve() if args.receipt_output else None)
    except gp.DemoSkip as error: check("demo","SKIP",str(error)); return 2
    except Exception as error: check("demo","FAIL",str(error)); return 1
    finally:
        for name in list(gp.ACTIVE_CONTAINERS): gp.stop_container(name)
        print_table()


if __name__=="__main__": raise SystemExit(main())
