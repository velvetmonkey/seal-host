# Starter profiles

- `hosts/` contains copy-and-edit MCP host configurations for Claude Code,
  Claude Desktop, Cursor, and VS Code.
- `policies-v1/sqlite-sandbox.payload.json` is compatible with the currently
  deployed policy language.
- `policies-v2/` demonstrates explicit read ALLOW plus full-arguments guarding
  for pinned DBHub, filesystem, and GitHub server profiles. These require the
  policy-v2 Lean core and are not accepted by the currently pinned host build.
- `manifests/` are the finite inventories those starter policies were checked
  against. The GitHub file is explicitly a subset and must be replaced by a
  fresh exported inventory before trust.
- `adequacy/` supplies finite separation examples for the server + tool + full
  arguments target model.

The authoring loop from the sibling assurance kit is:

```bash
node ../seal-assurance-kit/bin/seal policy sign policies-v2/dbhub-0.23.0.payload.json --key /path/to/config.seed --out trusted.json
node ../seal-assurance-kit/bin/seal scan manifests/dbhub-0.23.0.tools.json policies-v2/dbhub-0.23.0.payload.json
node ../seal-assurance-kit/bin/seal adequacy check adequacy/dbhub-0.23.0.labels.json
```

`seal scan` has the finite-manifest theorem `Seal.scan_pass_sound`; the shipped
JavaScript mirror is not yet theorem-bound. `seal adequacy` has a proved finite
checker in `attention-lean` and a JS↔Lean corpus bridge, but its PASS is only
about the finite supplied states.

The v2 examples deliberately compose tool identity with argument predicates:
DBHub permits only table-name searches at `detail_level=names`; filesystem
reads are limited to `/ABS/PATH/safe-read/`; GitHub reads are scoped to
`YOUR_ORG/YOUR_REPO`, with method and path/query restrictions where the tool
supports them. Replace those literals for your environment. A failed predicate
does not fall through to allow: no match means default deny.

The guarded DBHub call with the exact ordered arguments
`{"sql":"DROP TABLE receipts"}` commits the parts
`["bytebase/dbhub@0.23.0", "execute_sql", "{\"sql\":\"DROP TABLE receipts\"}"]`
to target
`fe0eebfb14836c463ff644f596a5bc8a48b590d689972c97cbc4bf077d865a04`.
Changing the SQL, adding an argument, or removing an argument changes the
full-arguments pre-image. Object-key order alone does not: Lean applies its
kernel-defined Unicode-scalar object-key order before hashing (not RFC
8785/JCS; see [`../docs/CANONICAL-BYTE-CONTRACT.md`](../docs/CANONICAL-BYTE-CONTRACT.md)), while the receipt separately preserves and
hashes incoming argument order. The 64-hex value shown by the live host remains
the value to compare before signing.

Replace every `/ABS/PATH` and public-key placeholder before use. These files
are starter profiles: verify tool coverage and target adequacy before trusting
them.

The v1 sandbox policy guards every declared tool. It deliberately does not
pretend to provide safe read ALLOW rules: the current deployed policy language
has only `guarded` and `deny`. Explicit safe-allow composition belongs to
policy-v2 and must land inside Lean before production server profiles claim it.
