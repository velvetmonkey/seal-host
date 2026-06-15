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
extern lean_object* seal_host_step(lean_object*);

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

/* JSON tool-call string in -> verified verdict JSON string out. */
EMSCRIPTEN_KEEPALIVE
char* seal_decide(const char* input) {
    if (!ensure_init()) return strdup("{\"error\":\"init failed\"}");
    printf("[seal] init done, calling step\n"); fflush(stdout);
    lean_object* in  = lean_mk_string_from_bytes(input, strlen(input));
    lean_object* out = seal_host_step(in);
    printf("[seal] step returned\n"); fflush(stdout);
    char* ret = strdup(lean_string_cstr(out));
    lean_dec(out);
    return ret;
}
