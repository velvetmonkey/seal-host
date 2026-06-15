// Extracted ST.Ref ops from lean4 runtime/io.cpp (lines ~1414-1520).
// Avoids compiling io.cpp (which pulls libuv). seal_host_step needs only these.
#include <atomic>
#include "runtime/object.h"

namespace lean {
using std::atomic;

static inline atomic<object*> * mt_ref_val_addr(object * o) {
    return reinterpret_cast<atomic<object*> *>(&(lean_to_ref(o)->m_value));
}
static inline bool ref_maybe_mt(b_obj_arg ref) { return lean_is_mt(ref) || lean_is_persistent(ref); }

extern "C" LEAN_EXPORT obj_res lean_st_ref_get(b_obj_arg ref) {
    if (ref_maybe_mt(ref)) {
        atomic<object *> * val_addr = mt_ref_val_addr(ref);
        while (true) {
            object * val = val_addr->exchange(nullptr);
            if (val != nullptr) {
                inc(val);
                object * tmp = val_addr->exchange(val);
                if (tmp != nullptr) dec(tmp);
                return val;
            }
        }
    } else {
        object * val = lean_to_ref(ref)->m_value;
        lean_assert(val != nullptr);
        inc(val);
        return val;
    }
}
extern "C" LEAN_EXPORT obj_res lean_st_ref_take(b_obj_arg ref) {
    if (ref_maybe_mt(ref)) {
        atomic<object *> * val_addr = mt_ref_val_addr(ref);
        while (true) { object * val = val_addr->exchange(nullptr); if (val != nullptr) return val; }
    } else {
        object * val = lean_to_ref(ref)->m_value;
        lean_assert(val != nullptr);
        lean_to_ref(ref)->m_value = nullptr;
        return val;
    }
}
extern "C" LEAN_EXPORT obj_res lean_st_ref_set(b_obj_arg ref, obj_arg a) {
    if (ref_maybe_mt(ref)) {
        mark_mt(a);
        atomic<object *> * val_addr = mt_ref_val_addr(ref);
        object * old_a = val_addr->exchange(a);
        if (old_a != nullptr) dec(old_a);
        return box(0);
    } else {
        if (lean_to_ref(ref)->m_value != nullptr) dec(lean_to_ref(ref)->m_value);
        lean_to_ref(ref)->m_value = a;
        return box(0);
    }
}
extern "C" LEAN_EXPORT obj_res lean_st_ref_swap(b_obj_arg ref, obj_arg a) {
    if (ref_maybe_mt(ref)) {
        mark_mt(a);
        atomic<object *> * val_addr = mt_ref_val_addr(ref);
        while (true) { object * old_a = val_addr->exchange(a); if (old_a != nullptr) return old_a; }
    } else {
        object * old_a = lean_to_ref(ref)->m_value;
        if (old_a == nullptr) lean_internal_panic("null reference read");
        lean_to_ref(ref)->m_value = a;
        return old_a;
    }
}
extern "C" LEAN_EXPORT uint8_t lean_st_ref_ptr_eq(b_obj_arg ref1, b_obj_arg ref2) {
    return lean_to_ref(ref1) == lean_to_ref(ref2);
}
}
