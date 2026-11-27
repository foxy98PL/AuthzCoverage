# identities.yaml (version 1)

`identities.yaml` tells authzcov who the callers in your recording are and what
they own. It never contains secrets: tokens are matched by SHA-256 hash, by env
var name, by decoded JWT claims, or learned from login traffic. Raw credentials
in the file are rejected.

authzcov validates the file with its own line-numbered validator (errors read
`file:line: key.path: message`, exit code 2). `schema/identities.v1.json` is a
JSON Schema for editors (yaml-language-server); the validator is authoritative.

## Top-level keys

| key | required | meaning |
|---|---|---|
| `version` | yes | must be `1` |
| `roles` | yes | map of role name to integer rank; higher rank = more privilege |
| `identities` | yes | 1 to 200 declared callers |
| `credentials` | no | where requests carry credentials |
| `jwt` | no | `subject:` dot path of the subject claim (default `sub`); `tenant:` dot path of the caller's tenant claim |
| `learn_tokens` | no | login exchanges that bind tokens to identities |
| `resources` | no | path parameter name to resource name |
| `ownership` | no | `self_params`, `learn_from_create`, `learn_from_lists` |
| `tenancy` | no | `tenant_params`: path parameters whose value is the object's tenant |
| `requirements` | no | `overrides`: pick the object parameter of an endpoint by hand |

### credentials

Default: `[{type: bearer, header: Authorization, schemes: [Bearer]}]`. Entries
are tried in order and the first hit wins. After them, authzcov still notices
any `Authorization`, `Cookie` or API-key header so such a request is `unknown`,
never `anonymous`.

- `{type: bearer, header: Authorization, schemes: [Bearer, Token]}`
- `{type: cookie, name: SESSION}`
- `{type: apikey, header: X-API-Key}`
- `{type: basic}` (only the user name is kept; the password is discarded)

### identities[]

- `name` (required): `^[a-z0-9][a-z0-9._-]{0,62}$`, unique; `anonymous` and `unknown-*` are reserved.
- `role` (required): a key of `roles`.
- `tenant`: optional string. Callers in different tenants are `other_tenant`; `"*"` is exempt (e.g. a platform admin).
- `markers`: optional list of strings (6+ characters) to look for in responses.
- `match` (required, at least one key; all given matchers must hold):
  - `jwt: {claim.path: value}`: decoded claims, all must match (signature is not verified; claims only label traffic).
  - `token_sha256` / `apikey_sha256`: 64 lower-case hex of SHA-256 of the credential (aliases; give one). Only the first 12 hex are kept.
  - `token_env`: name of an env var holding the credential (must be set).
  - `basic_user`: HTTP Basic user name.
  - `login`: login name, bound to a token by `learn_tokens`.

### learn_tokens[]

```yaml
learn_tokens:
  - match: {method: POST, path: /users/v1/login}   # spec template or literal path
    identity_from: {request_json: username}        # dot path in the request body
    token_from: {response_json: auth_token}        # dot path in the response body
```

A 2xx exchange matching the rule binds the token's fingerprint to the identity
whose `login` equals the login name (then its JWT `sub` expectation, then its
`name`). A fingerprint bound to two different identities is conflicted and
resolves to nothing. All logins are learned before any request is resolved, so
HAR order does not matter.

### resources and ownership

```yaml
resources: {book_title: books, username: users}
ownership:
  self_params: {username: subject}
  learn_from_create:
    - match: {method: POST, path: /books/v1}
      resource: books
      id_from: {request_json: book_title}
```

`id_from` takes exactly one of `request_json` (a dot path into the request body)
or `response_json` (a dot path into the 2xx response body), for servers that
generate the id:

```yaml
    - match: {method: POST, path: "/orgs/{orgId}/orders"}
      resource: orders
      id_from: {response_json: id}   # or data.id
```

The path must resolve to one non-empty string or number; `[]` is rejected. A
non-2xx response, a body that is not JSON, a missing or non-scalar field, or a
body redacted or dropped at ingest (over 64 KiB) teaches nothing. A redacted
placeholder is never learned as an id. Conflict rules are the same for both.

### learn_from_lists (inferred ownership)

```yaml
ownership:
  learn_from_lists:
    - match: {method: GET, path: /books/v1}
      resource: books
      ids_from: {response_json: "books[].book_title"}
```

Every id found in a 2xx response of a known caller (confidence learned or
better) is owned by that caller, with confidence `inferred`. Use it only for
lists that return the caller's own objects. The path is dotted; `[]` after a
name means every element (`items[].id`, `data.items[].id`), and `[].id` reads a
top-level array. Conflicts: higher confidence wins (a `learn_from_create` or
self param beats a list); equal confidence with different callers leaves the
object unknown.

A cell covered only by inferred evidence prints `ok~` and the table ends with
`~ covered only by inferred ownership evidence`. `coverage --strict` does not
count such evidence: an observation counts only if the caller is known with
confidence learned or better and, for object-level endpoints, so is the owner.

### tenancy and jwt.tenant

```yaml
jwt: {subject: sub, tenant: org_id}   # caller tenant claim, used when the identity has no tenant
tenancy:
  tenant_params: {orgId: name}        # the value of {orgId} is the object's tenant
```

Caller tenant: the identity's `tenant`, else the string claim at `jwt.tenant`.
Object tenant: the value of the endpoint's tenant parameter (first one in path
order) when it has one, else the owner's tenant. With a tenant parameter the
owner need not be known: a caller whose tenant differs from the path value is
`other_tenant` (so `GET /orgs/OrgA/projects/{id}` by a caller in OrgB is
`other_tenant` even if nobody is known to own the project). A caller with no
tenant at all is also `other_tenant` against a known object tenant, because
tenant parameters only exist when the file declares tenancy. A caller tenant of
`"*"` is never `other_tenant`. `other_tenant` is a required column when any
identity has a tenant, `tenancy.tenant_params` is set, or `jwt.tenant` is set.
`ObjectParam` stays the last path parameter; a tenant parameter in the last
position is still the object parameter and the tenant comes from it as well.

### requirements.overrides

```yaml
requirements:
  overrides:
    - {endpoint: "GET /orgs/{orgId}/repos/{repo}", object_param: orgId}
```

By default the object of an endpoint is its last path parameter. An override
names the exact endpoint ID and the path parameter that addresses the object
instead; its resource becomes the literal segment before that parameter. An
unknown endpoint or parameter is an error (exit 2).

## Examples

VAmPI with JWT subjects: `testdata/identities/vampi.yaml`.

```yaml
version: 1
roles: {user: 10, admin: 100}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
```

VAmPI with opaque tokens learned from login: `testdata/identities/vampi-learn.yaml`.

```yaml
version: 1
roles: {user: 10, admin: 100}
learn_tokens:
  - match: {method: POST, path: /users/v1/login}
    identity_from: {request_json: username}
    token_from: {response_json: auth_token}
identities:
  - {name: alice, role: user, match: {login: alice}}
  - {name: bob, role: user, match: {login: bob}}
```

## Resolution order and confidence

Every request resolves in this order: declared match (jwt, token hash, basic
user) first, then learned tokens, then `unknown`. A request with no credential
at all is `anonymous`. A request with any credential that matches nothing is
`unknown-N`, never `anonymous`, and unknown never counts as covered.
Confidence levels: declared (matched by the file), learned (via
`learn_tokens`), unknown. Learned identities count as covered.

## Warnings

Printed to stderr as `warning: <message>` before the table. Currently: a role
(per tenant) with fewer than two identities, because same-role-other-user
cannot be covered.

## discover

```
authzcov discover --har f.har [--har g.har.zip] [--identities existing.yaml] [--write out.yaml] [--force]
```

Groups recorded requests by credential fingerprint and prints a skeleton that
`config.Parse` accepts: one identity per distinct JWT `sub` and per Basic user
(role `user`), and commented-out entries for opaque tokens, cookies and API
keys (only 12 hex of the hash are known, so fill the full `token_sha256` or use
`learn_tokens`). If nothing can be proposed, a `change-me` placeholder is
written. Names are sanitised and de-duplicated (`-2`, `-3`). `--write` refuses
to overwrite an existing file unless `--force` (exit 2). The summary
`discover: <n> principals from <m> requests` goes to stderr. Review names and
roles before use.

## Golden matrices

`testdata/golden/*.txt` hold full `coverage` output for synthetic fixtures
(`vampi-fixture`, `tenants-fixture`, `lists-fixture`, `lists-fixture-strict`),
checked by `internal/cli/golden_test.go`; `make golden` rewrites them (review
the diff). Goldens from real VAmPI, crAPI and RealWorld recordings will be
added once those recordings exist.

## Not supported yet

Other `requirements` keys (only `overrides` with `endpoint` and `object_param`), `ignore`, `identity_from`
`request_form` and `basic_user`, `token_from` `response_header` and
`set_cookie`, and API keys in the query string. The validator rejects these
with a clear message where the key is recognised.
