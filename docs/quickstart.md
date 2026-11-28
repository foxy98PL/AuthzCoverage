# Quickstart (about five minutes)

You will run authzcov on a small demo shop API that has one planted
authorization bug. You need Go (see `go.mod` for the version), git and curl.
No Docker and no proxy are needed. authzcov sends no requests; only the demo
recorder talks to the demo server on your machine.

## 1. Get and build

```
git clone https://github.com/foxy98PL/AuthzCoverage
cd AuthzCoverage
make build        # or: go build -o bin/authzcov ./cmd/authzcov
```

This writes `bin/authzcov`. There are no release binaries yet.

## 2. Start the demo API and record a session

`tenantshop` is a toy multi-tenant shop in `e2e/apps/tenantshop`. It is a
separate Go module, so start it from its own directory. Run this in one
terminal and leave it running:

```
(cd e2e/apps/tenantshop && go run . -addr :8090)
```

In a second terminal, in the repository root, record a scripted session. This
plays a normal test run through the API and writes a HAR file:

```
BASE=http://localhost:8090 e2e/recorders/tenantshop.sh
```

The file is `testdata/raw/tenantshop.har`. The `testdata/raw/` directory is
git-ignored. Never commit HAR files: they contain real credentials.

## 3. Compute coverage

```
./bin/authzcov coverage \
  --spec e2e/apps/tenantshop/shop/openapi.yaml \
  --identities e2e/apps/tenantshop/identities.yaml \
  --har testdata/raw/tenantshop.har
```

authzcov prints a few progress lines on stderr, writes
`authzcov-out/coverage.json`, and prints this table:

```
ENDPOINT                                OWNER  SAME_ROLE  LOWER   OTHER_TENANT  ANON
DELETE  /orgs/{orgId}/orders/{orderId}  ok     GAP        -       ok 403        GAP
GET     /me                             ok     -          -       -             GAP
GET     /openapi.yaml                   GAP    -          GAP     -             GAP
GET     /orgs/{orgId}/customers         ok     -          ok 403  ok 403        GAP
GET     /orgs/{orgId}/orders            ok     -          -       ok 403        GAP
GET     /orgs/{orgId}/orders/{orderId}  ok     ok 403     -       ok 200,403    ok 401
POST    /login                          GAP    -          GAP     -             ok
POST    /orgs/{orgId}/orders            ok     -          -       GAP           GAP
PUT     /orgs/{orgId}/orders/{orderId}  ok     GAP        -       ok 403        GAP

required 30  covered 16 (53.3%)  gaps 14
! 1 suspicious allow(s): run "authzcov report --format markdown" for details
```

How to read it:

- Each row is an endpoint from the OpenAPI spec. Each column is a relationship
  between the caller and the object: the owner, another user with the same
  role, a lower role, a user from another tenant, or no login (anonymous).
- `-` means the combination does not apply to that endpoint.
- `ok 403` means your tests tried it and the API answered 403. The status
  codes seen are listed.
- `GAP` means no test tried it. The test you never wrote is the gap.
- 30 combinations are required and 16 are covered.

### The line with `!`

The row `GET /orgs/{orgId}/orders/{orderId}` / `OTHER_TENANT` shows
`ok 200,403`. One of the cross-tenant reads returned 200. That is not a
passing test. It is the planted bug: the shop checks "owner or admin" but never
checks the tenant, so the admin of tenant OrgB can read an order that belongs
to tenant OrgA. authzcov marks this with `!` because a request that should
have been refused succeeded. Read the details:

```
./bin/authzcov report --format markdown --in authzcov-out/coverage.json
```

The "Suspicious allows" section says: `adminb (tenant OrgB) received 200 for an
object owned by ann in tenant OrgA`.

## 4. Open the HTML report

```
./bin/authzcov report --format html --in authzcov-out/coverage.json > report.html
```

Open `report.html` in a browser (for example `xdg-open report.html` on Linux or
`open report.html` on macOS). It is one self-contained file with filters. It
loads nothing from the network.

## 5. Stop the demo

Press Ctrl-C in the terminal that runs the server.

## Next: your own API

You need an OpenAPI 3 file, a HAR recorded from your tests, and an
`identities.yaml` that names your test users.

1. Record your tests to HAR. See "Recording HARs" in the [README](../README.md).
2. Let authzcov propose the identities file, then edit names and roles:

   ```
   ./bin/authzcov discover --har my.har --write identities.yaml
   ```

   The file format is in [identities.md](identities.md).
3. Run `authzcov coverage` as above with your own files.
4. If requests do not match the spec, run
   `authzcov explain --spec api.yml 'GET /some/path'`. See
   [explain.md](explain.md).

Other demos:

- Docker: `docker compose -f e2e/apps/tenantshop/compose.yaml up -d` starts the
  same shop on port 8090 instead of `go run`. Then continue at
  the recording step.
- VAmPI, a public vulnerable demo API: `e2e/recorders/vampi.sh` records it with
  mitmproxy (`mitmdump`) and Docker. It needs those two tools installed.
