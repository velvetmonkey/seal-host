static int initializer_state;

int ordinary_business_logic(int value) { return value + initializer_state; }

int initialize_fixture_renamed(unsigned char builtin) {
  initializer_state = builtin + 1;
  return 0;
}
