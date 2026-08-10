/* Calls a symbol no object in the link set defines. */
extern int absent_host_helper(int);

int calls_missing(int value) { return absent_host_helper(value); }

int initialize_fixture_missing(unsigned char builtin) {
  (void)builtin;
  return 0;
}
