static const int compile_time_table[] = {17, 19};

int checked_safe(int index) { return compile_time_table[index & 1]; }

int initialize_fixture_benign(unsigned char builtin) {
  (void)builtin;
  return 0;
}
