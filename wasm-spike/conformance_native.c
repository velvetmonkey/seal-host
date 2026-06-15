/* SPDX-License-Identifier: Apache-2.0
 * Native conformance driver: boots the Lean runtime via libsealffi.so and runs
 * the exact same seal_host_init / seal_host_step path the WASM wrapper runs, so
 * verdict + cert hashes can be diffed target-for-target (D3 conformance gate).
 *
 * Protocol: read tab-delimited commands from stdin, one per line, echo each
 * result on its own line:
 *   INIT\t<envelope-json>\t<pubkey>
 *   STEP\t<step-input-json>
 * (Payloads are compact single-line JSON — no literal tabs/newlines.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void* lean_obj;
extern void   lean_initialize_runtime_module(void);
extern void   lean_io_mark_end_initialization(void);
extern void   lean_init_task_manager(void);
extern lean_obj seal_ffi_initialize(unsigned char builtin, lean_obj w);
extern unsigned char seal_lean_io_result_is_ok(lean_obj r);
extern void   seal_lean_dec(lean_obj o);
extern lean_obj seal_lean_mk_string(const char* s, size_t n);
extern const char* seal_lean_string_cstr(lean_obj o);
extern lean_obj seal_host_init(lean_obj envelope, lean_obj pubkey);
extern lean_obj seal_host_step(lean_obj input);

static void boot(void) {
    lean_initialize_runtime_module();
    lean_obj res = seal_ffi_initialize(1, (lean_obj)(size_t)1 /* lean_box(0) */);
    if (!seal_lean_io_result_is_ok(res)) { fprintf(stderr, "ffi init failed\n"); exit(2); }
    seal_lean_dec(res);
    lean_io_mark_end_initialization();
    lean_init_task_manager();
}

static char* call1(lean_obj (*fn)(lean_obj), const char* a) {
    lean_obj in = seal_lean_mk_string(a, strlen(a));
    lean_obj out = fn(in);
    char* r = strdup(seal_lean_string_cstr(out));
    seal_lean_dec(out);
    return r;
}

int main(void) {
    boot();
    char* line = NULL; size_t cap = 0; ssize_t n;
    while ((n = getline(&line, &cap, stdin)) != -1) {
        if (n > 0 && line[n-1] == '\n') line[n-1] = '\0';
        if (strncmp(line, "INIT\t", 5) == 0) {
            char* env = line + 5;
            char* tab = strchr(env, '\t');
            if (!tab) { printf("{\"error\":\"bad INIT\"}\n"); continue; }
            *tab = '\0';
            const char* pk = tab + 1;
            lean_obj e = seal_lean_mk_string(env, strlen(env));
            lean_obj p = seal_lean_mk_string(pk, strlen(pk));
            lean_obj out = seal_host_init(e, p);
            char* r = strdup(seal_lean_string_cstr(out));
            seal_lean_dec(out);
            printf("%s\n", r); free(r);
        } else if (strncmp(line, "STEP\t", 5) == 0) {
            char* r = call1(seal_host_step, line + 5);
            printf("%s\n", r); free(r);
        } else if (line[0] == '\0') {
            continue;
        } else {
            printf("{\"error\":\"unknown command\"}\n");
        }
        fflush(stdout);
    }
    free(line);
    return 0;
}
