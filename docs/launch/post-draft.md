<!-- DRAFT, not for publication until owner G1 IP check -->

# What our API tests never check

Most API test suites check that alice can read her own order. Far fewer check that bob cannot read it, or
that a user from another tenant gets a 403 or 404. Broken object level authorization (BOLA, also called
IDOR) is number 1 in the OWASP API Security Top 10, and it lives in those untested combinations. A suite can
be green, and have good line coverage, while never sending a single cross-user request.

Line coverage tells you which code your tests ran. We wanted the same kind of answer for authorization:
which caller and object combinations did the tests ever try?

## What authzcov does

authzcov is a command line tool. You record your existing test run to a HAR file and give it your OpenAPI
spec and a small `identities.yaml` that says who your test users are. It then:

1. matches each recorded request to an operation in the spec;
2. works out who made it (by JWT subject or similar, from the identities file) and who owns the object in
   the path;
3. builds a matrix of endpoint by relationship: owner, same role, lower role, other tenant, anonymous.
   Each cell is covered (with the status codes seen), a gap, or not applicable;
4. flags a "suspicious allow": a request that should have been refused but got a 2xx.

Some design rules we kept strict:

- It sends no requests and uses no network in `coverage`. It only reads files.
- Unknown never counts as covered. If it cannot tell who the caller was or who owned the object, the cell
  is not covered.
- Raw credentials do not survive ingest, and raw object IDs do not reach the shareable output. The one
  exception is an opt-in plan for the HAR you record yourself.

## Does it find anything? Results

We checked it against three kinds of target. Every number below comes from the files under
`eval/results/`, written by `make eval`; the setup is described in `eval/README.md`. Precision is
tp/(tp+fp), recall is tp/(tp+fn).

| Suite (file) | tp | fp | fn | tn | Precision | Recall |
|---|---|---|---|---|---|---|
| tenantshop mutants (`tenantshop-mutants.json`) | 11 | 0 | 0 | 1 | 1 | 1 |
| tenantshop ablation (`tenantshop-ablation.json`) | 16 | 0 | 0 | 0 | 1 | 1 |
| VAmPI (`vampi.json`) | 16 | 3 | 2 | 11 | 0.842 | 0.889 |
| crAPI v1.1.6 (`crapi.json`) | 10 | 2 | 2 | 8 | 0.833 | 0.833 |
| RealWorld (`realworld.json`) | 0 | 7 | 0 | 11 | 0 | undefined |

What each row is:

- **tenantshop** is a small demo app written by the same team. In the mutant suite we remove exactly one
  authorization check at a time, and `suspicious_allow` fired on the right endpoint and relationship 11
  times, with no extra alarms; on the unmutated app it raised nothing. In the ablation suite we drop one
  attacker request from the recording and check that exactly that cell goes from covered to gap and
  nothing else changes: 16 of 16. These numbers show the method works on these patterns. They do not show
  how common the patterns are in real code.
- **VAmPI** and **crAPI** are deliberately vulnerable third-party apps, pinned by image digest, scored
  against a ground truth of their documented issues (VAmPI's is hand-labelled). Both numbers mix
  categories; some ground truth items are out of scope (12 for VAmPI, 11 for crAPI).
- **RealWorld** (a Conduit backend) enforces ownership, so there is no real bug to find. It measures
  false positives and true negatives only, which is why recall is undefined.

## Where it is wrong

We would rather list these than have you find them.

- **crAPI challenge 2 is a miss (false negative).** The object is addressed by a query parameter, and
  authzcov only reads path parameters.
- **VAmPI `_debug` is a miss in both builds.** The spec declares no `security` on that endpoint, so it
  looks public, and an unknown or public endpoint never counts. The app has no token check, so the spec
  is wrong, but authzcov cannot see that from the spec.
- **`suspicious_allow` raises false alarms on public reads and on ignored path parameters.** All 7
  RealWorld false positives are of this kind: public article and comment reads, and actions such as
  favoriting another user's article that are the feature. In crAPI, public community posts and a video
  update that ignores the path parameter are flagged. In VAmPI, three calls were flagged although the
  handler ignored the path and changed only the caller's own record. authzcov sees a 2xx on another
  user's path and cannot tell the difference.
- **RealWorld has no real bug,** so it tells you about noise, not about detection.
- The evaluations use one release of each app on one machine, and the mutants come from one small app. Treat the
  figures as a sanity check, not a benchmark of how many real bugs it finds.

In practice the output is a list of questions for a human, not a verdict.

## Try it

The README quickstart (`README.md`, with a longer walkthrough and real output in `docs/quickstart.md`)
needs Go, git and curl. It builds the tool, starts the demo API with one planted bug, records a session to
a HAR, and runs:

```
./bin/authzcov coverage \
  --spec e2e/apps/tenantshop/shop/openapi.yaml \
  --identities e2e/apps/tenantshop/identities.yaml \
  --har testdata/raw/tenantshop.har
```

The result is `authzcov-out/coverage.json`, which `authzcov report --format html` turns into a page. To
use it on your own tests, record them to a HAR (see "Recording HARs" in the README), write an
`identities.yaml`, and point `--spec` at your OpenAPI file. Keep recorded HARs out of version control:
they contain real tokens until redacted.

Feedback on the false alarms is the most useful thing you can send: which public or path-ignoring
patterns should it learn to recognise?
