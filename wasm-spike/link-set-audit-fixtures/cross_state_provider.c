/* Mutable state owned by a module whose initializer is NOT run in this link. */
int foreign_state;

int initialize_fixture_state(unsigned char builtin) {
  foreign_state = builtin + 1;
  return 0;
}
