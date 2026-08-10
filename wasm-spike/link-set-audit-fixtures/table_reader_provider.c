/* Reads only read-only data, from a module that IS initialised.  The unsafety is
   one pointer hop away, inside the table's bytes. */
extern int *const table_of_state[1];

int table_reader(int value) { return value + *table_of_state[0]; }

int initialize_fixture_reader2(unsigned char builtin) {
  (void)builtin;
  return 0;
}
