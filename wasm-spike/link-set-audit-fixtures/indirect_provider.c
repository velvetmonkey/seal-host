/* The unsafe body is never named by a direct call anywhere in the link.  Its
   only retention edge is a function pointer stored in this module's static
   data, and the only way in is call_indirect from another object. */
static int initializer_state;

int hidden_offender(int value) { return value + initializer_state; }
int hidden_benign(int value) { return value - 1; }

int (*const dispatch_table[2])(int) = { hidden_offender, hidden_benign };

int initialize_fixture_indirect(unsigned char builtin) {
  initializer_state = builtin + 1;
  return 0;
}
