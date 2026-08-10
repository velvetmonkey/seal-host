/* A link-time-constant table of pointers into this module's own mutable state.
   The table itself is read-only; what it points at is not, and this module's
   initializer does not run.  Same shape as the real Lean `___closed__N` tables. */
int table_state;

int *const table_of_state[1] = { &table_state };

int initialize_fixture_table(unsigned char builtin) {
  table_state = builtin + 1;
  return 0;
}
