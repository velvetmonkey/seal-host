static int initializer_state;

int proof_library_offender(int value) { return value + initializer_state; }

int initialize_fixture_offender(unsigned char builtin) {
  initializer_state = builtin + 1;
  return 0;
}
