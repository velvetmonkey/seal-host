/* Lives in a module that IS initialised and cannot see the table's contents,
   so the compiler must emit a real call_indirect. */
extern int (*const dispatch_table[2])(int);

int dispatch_entry(int value) { return dispatch_table[value & 1](value); }

int initialize_fixture_dispatch(unsigned char builtin) {
  (void)builtin;
  return 0;
}
