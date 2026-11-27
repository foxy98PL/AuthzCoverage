# authzcov export --plan

Writes the gaps of a `coverage.json` as a versioned JSON probe plan that another
authorization tester (or a script) can execute. authzcov itself never sends a request.

```
authzcov export --plan --in authzcov-out/coverage.json [--out plan.json] [--include waived]
authzcov export --plan --in authzcov-out/coverage.json --out plan.json \
    --har tests.har --spec openapi.yaml --identities identities.yaml     # adds raw example IDs
```

- Gaps are required cells that are not covered. Waived cells are left out unless `--include waived`
  (they then carry `"waived": true`). Covered, unknown and not-required cells are never exported.
- Default output is stdout; `--out` writes atomically.
- Deterministic: probes are sorted by endpoint ID, relationship, attacker. `generated_at`
  honours `SOURCE_DATE_EPOCH` like coverage.json. `source.coverage_sha256` hashes the input file.
- Schema: `schema/plan.v1.json` (informational; authzcov builds the document in Go).

## Format (plan_version 1)

```json
{"plan_version": 1, "tool": {"name": "authzcov", "version": "dev", "commit": ""},
 "generated_at": "2026-01-01T00:00:00Z",
 "source": {"coverage_sha256": "...", "generated_at": "2026-01-01T00:00:00Z"},
 "contains_raw_ids": false,
 "probes": [{
   "id": "c1a28e7387a65fd8", "endpoint": "DELETE /orgs/{orgId}/orders/{orderId}", "method": "DELETE",
   "path_template": "/orgs/{orgId}/orders/{orderId}", "relationship": "other_tenant",
   "attacker": {"identity": "ben", "role": "customer", "tenant": "OrgB"},
   "object": {"resource": "orders", "param": "orderId", "id_hash": "ee65589a", "owner": "ann", "tenant": "OrgA"},
   "expect": "deny"}]}
```

| field | meaning |
|---|---|
| `id` | stable fingerprint of (endpoint, relationship); one probe per gap |
| `attacker` | identity NAME from identities.yaml, role and tenant; `"anonymous"` for the anonymous relationship; `null` plus a `note` when no matching identity was seen. Never a token |
| `object` | object-level endpoints only: resource, path parameter, `id_hash` (as in coverage.json), owner and tenant; `id` only in raw mode |
| `expect` | `deny` (must be refused), `allow` (owner, or a role above the minimum on a function-level endpoint), `policy` (higher_role on another's object: your policy decides, record it) |
| `path_params` | tenant path parameters (`tenancy.tenant_params`) set to the object's tenant; raw mode only |
| `note` | why `attacker` is null: no identity with the relationship, no object with a known owner for the resource, no inferred minimum role |

Attacker choice mirrors the relationship rules: `other_tenant` an identity in another tenant (not `*`);
`same_role_other_user` the owner's rank, a different user, same tenant; `lower_role` / `higher_role`
a lower / higher rank than the owner (function-level: than the inferred minimum role); `owner` the
owner (function-level: an identity at the minimum rank). The first match in name order and object
`id_hash` order is used. Identities come from coverage.json (those seen in the recording); with
`--har` also from identities.yaml.

## Raw IDs

coverage.json stores only `id_hash`, so a plan built from it alone has no usable object ID
(`contains_raw_ids: false`). With `--har --spec --identities` the pipeline is re-run (the same code as
`authzcov coverage`) and each object's `id_hash` is matched to the raw ID in the recording, written as
`object.id`. That file contains raw IDs: it is written with mode 0600, has
`"contains_raw_ids": true`, and a warning is printed. **Never commit or share it.** The flag is true
whenever `--har` is given. Objects of self-claim (`subject`) resources get no raw ID. The plan never
contains credentials in either mode.

## Interop

Checked on 2026-11-27 from the tools' public GitHub pages (README and wiki); only what those pages
document is stated here. No adapter is provided.

- **possession** (github.com/bugsyhewitt/possession, Go CLI): reads captures (HAR, curl, OpenAPI,
  Postman, mitmproxy JSON, Burp XML) and one YAML "role matrix" with `identities[]` (name, rank, role,
  `creds`, `resources`). It has no plan or probe input; it generates its own mutations from the capture.
  Not mappable directly: the plan names identities without credentials, and `creds` are what possession
  needs. The `resources` map (`order_id: "12345"`) is where raw example IDs would go. Sub-schemas of
  `creds.cookies/headers/basic` and `refresh` are not documented, so none are assumed.
- **Hadrian** (github.com/praetorian-inc/hadrian): `hadrian test rest --api <openapi> --roles roles.yaml
  --auth auth.yaml`. `roles.yaml` has `objects`, `roles[]` (name, `level`, `permissions` as
  `action:object:scope`) and `endpoints[]` (path, object, owner_field); `auth.yaml` has `method` and a
  `roles` map of credentials. Templates are YAML with endpoint/role selectors and detection logic
  (structure not documented on the pages read). It has no probe-list input either. Conceptually
  authzcov roles/ranks resemble `roles[].level`, but permissions and credentials are not in the plan or
  in coverage.json.
- Others found but not examined in detail: peerigon/access-control-testing (enhanced OpenAPI input),
  Mutasem-mk4/bola (multi-user config file). Not verified; no mapping claimed.

Conclusion: none of these tools verified takes a list of concrete probes. The plan is meant for custom
runners, test generators and humans; a thin script can turn `probes[]` into requests using your own
credentials for the named identities.
