#include <lean/lean.h>
#include <string.h>
#include <stdlib.h>
#include <emscripten.h>
#include <stdio.h>

extern void lean_initialize_runtime_module(void);
extern void lean_io_mark_end_initialization(void);
extern void lean_init_task_manager(void);
extern lean_object* seal_ffi_initialize(uint8_t builtin, lean_object* w);
extern uint8_t      seal_lean_io_result_is_ok(b_lean_obj_arg r);
extern lean_object* seal_host_init(lean_object*, lean_object*);
extern lean_object* seal_host_step(lean_object*);
extern lean_object* seal_host_mcp_version_gate(lean_object*, lean_object*);
extern lean_object* seal_host_mcp_version_gate_step(lean_object*);

/* Browser mediation never creates temporary files. Lean's native runtime
 * implementations pull libuv, which is deliberately absent from this wasm
 * build. Keep the current one-world-argument ABI so generated callers type
 * check, and trap fail-closed if a future reachable path starts using either
 * primitive. */
LEAN_EXPORT lean_object* lean_io_create_tempfile(lean_object* world) {
    (void)world;
    __builtin_trap();
}

LEAN_EXPORT lean_object* lean_io_create_tempdir(lean_object* world) {
    (void)world;
    __builtin_trap();
}

static int g_inited = 0;
static int ensure_init(void) {
    if (g_inited) return 1;
    printf("[seal] init: runtime_module\n"); fflush(stdout);
    lean_initialize_runtime_module();
    printf("[seal] runtime_module returned, calling ffi_initialize\n"); fflush(stdout);
    lean_object* res = seal_ffi_initialize(1, lean_io_mk_world());
    if (!seal_lean_io_result_is_ok(res)) { lean_dec(res); return 0; }
    lean_dec(res);
    printf("[seal] init: ffi ok, mark_end\n"); fflush(stdout);
    lean_io_mark_end_initialization();
    lean_init_task_manager();
    g_inited = 1;
    return 1;
}

/* Load the signed trusted-config envelope into the session (must be called
 * once before seal_decide). Returns the init summary JSON (or {ok:false,...}). */
EMSCRIPTEN_KEEPALIVE
char* seal_init(const char* envelope, const char* pubkey) {
    if (!ensure_init()) return strdup("{\"error\":\"init failed\"}");
    lean_object* env = lean_mk_string_from_bytes(envelope, strlen(envelope));
    lean_object* pk  = lean_mk_string_from_bytes(pubkey, strlen(pubkey));
    lean_object* out = seal_host_init(env, pk);
    char* ret = strdup(lean_string_cstr(out));
    lean_dec(out);
    return ret;
}

/* JSON step input in -> verified verdict JSON string out. The kernel-owned
 * MCP version gate is structurally ordered before seal_host_step. The Lean
 * adapter extracts the exact judged line, refuses to parse any line the
 * raw-wire classifier refuses (stepImpl's fail-closed block stays the
 * authority for those), and gates under the module's M.2 revision session:
 * entry calls (initialize / server/discover) observed by PRIOR admitted
 * seal_decide traffic select the session revision exactly as the native
 * host's McpRevisionSession does, and a rejected line is never observed.
 * Only the gate's exact continue result can reach a decision; every rejection
 * (and any future/unknown gate result) is returned without falling through.
 * Requires a prior seal_init for a decision; note the gate itself is
 * config-independent, so a gate-rejected input is rejected even before
 * seal_init — only gate-admitted inputs reach the kernel's
 * {"ok":false,"error":"session not initialised"} result. seal_init resets
 * the revision session. */
EMSCRIPTEN_KEEPALIVE
char* seal_decide(const char* input) {
    if (!ensure_init()) return strdup("{\"error\":\"init failed\"}");

    lean_object* gate_in = lean_mk_string_from_bytes(input, strlen(input));
    lean_object* gate_out = seal_host_mcp_version_gate_step(gate_in);
    if (strcmp(lean_string_cstr(gate_out), "{\"route\":\"continue\"}") != 0) {
        char* ret = strdup(lean_string_cstr(gate_out));
        lean_dec(gate_out);
        return ret;
    }
    lean_dec(gate_out);

    lean_object* in  = lean_mk_string_from_bytes(input, strlen(input));
    lean_object* out = seal_host_step(in);
    char* ret = strdup(lean_string_cstr(out));
    lean_dec(out);
    return ret;
}

/* Raw MCP request line plus the negotiated protocol revision in -> the
 * kernel-owned version-gate verdict JSON string out. */
EMSCRIPTEN_KEEPALIVE
char* seal_mcp_version_gate(const char* line, const char* selected_revision) {
    if (!ensure_init()) return strdup("{\"error\":\"init failed\"}");
    lean_object* in  = lean_mk_string_from_bytes(line, strlen(line));
    lean_object* rev = lean_mk_string_from_bytes(selected_revision, strlen(selected_revision));
    lean_object* out = seal_host_mcp_version_gate(in, rev);
    char* ret = strdup(lean_string_cstr(out));
    lean_dec(out);
    return ret;
}
