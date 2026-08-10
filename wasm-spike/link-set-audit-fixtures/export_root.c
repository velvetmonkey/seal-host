/* Exported C ABI stand-in for seal_init / seal_decide / seal_mcp_version_gate.
   TARGET names the retained callee under test.  INIT, when defined, names an
   initializer the ABI really runs, so a fixture can model a module that IS
   initialised in this link. */
#ifndef TARGET
#define TARGET checked_safe
#endif

extern int TARGET(int);
#ifdef INIT
extern int INIT(unsigned char);
#endif

int seal_init(void) {
#ifdef INIT
  INIT(0);
#endif
  return TARGET(7);
}
int seal_decide(void) { return TARGET(11); }
int seal_mcp_version_gate(void) { return TARGET(13); }
