/* The reader lives in a module that IS initialised; the state it reads does not. */
extern int foreign_state;

int cross_reader(int value) { return value + foreign_state; }

int initialize_fixture_reader(unsigned char builtin) {
  (void)builtin;
  return 0;
}
