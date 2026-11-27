# authzcov redact --pseudonymize

Turns a raw HAR (a real recording) into a fixture that is safe to commit and
still produces the same coverage table.

```
authzcov redact --pseudonymize --in raw.har --out fixture.har \
    [--keep-claims sub,org_id,role] [--key-file k] [--force]
```

- `--pseudonymize` is required (plain redaction is not implemented; exit 2).
- `--out` must differ from `--in` and must not exist unless `--force`. It is
  written atomically (temp file + rename) with mode 0600.
- The input is streamed entry by entry; only `log.entries` is read. Bodies
  over 64 KiB are dropped, as in ingest.
- `--key-file` (at least 32 bytes) makes the output reproducible: same input and
  same key give byte-identical output. Without it a random 32-byte key is used
  per run and never written. Keep the key file out of the repository.
- stderr prints counts only (entries, tokens re-signed/replaced, headers and
  cookies masked, hosts mapped, body fields masked). It never prints a secret.

## What changes

| what | becomes |
|---|---|
| JWT (Authorization Bearer, any header, cookie value, query, JSON/form string, path segment) | new HS256 JWT signed with the public authzcov test key, `iss: authzcov-test`, only the `--keep-claims` claims (default `sub`) with their values; the same input token always gives the same output token |
| JWT-shaped but undecodable value | treated as opaque |
| opaque bearer, cookie values, Set-Cookie, and the value of EVERY header not on the benign allowlist (headers are default-deny: `X-Session-Token`, `X-Goog-Api-Key`, ... all qualify; a JWT there is re-signed) | `tok_<hash8>`, hash8 = first 8 hex of HMAC-SHA256(run key, raw value); Set-Cookie keeps only `name=tok_...` |
| Basic auth | scheme kept, user `user_<hash8>`, password dropped |
| body values under a sensitive key | the WHOLE value is masked, whatever its type. Keys are normalised (lower-case, `-` `_` `.` dropped) and match when they contain `secret`, `token`, `passw`, `pwd`, `apikey`, `accesskey`, `privatekey`, `credential`, `session`, `auth`, `signature`, `cookie`, or are `pin`, `cvv`, `ssn`, or start/end with `otp`. Low-entropy keys (`passw*`, `pwd`, `pin`, `cvv`, `ssn`, `otp`) give `[redacted]` with no hash; other string values give a re-signed JWT or `tok_<hash8>` (so login-learned tokens still match); objects, arrays, numbers and booleans become the string `[redacted]`. Substring matching over-masks (`author`, `authority`); ids such as `id`, `orderId`, `username`, `book_title`, `name` are never matched |
| JWT-shaped strings anywhere | any `a.b.c` whose first part decodes to a JSON object with `alg` (leading whitespace allowed) is a JWT: re-signed, or `tok_<hash8>` if its claims cannot be decoded |
| free-text credentials | `bearer`, `basic`, `token`, `apikey`, `api-key` followed by `:`, `=` or a space and 8+ token characters: the word is kept, the value becomes `tok_<hash8>` |
| percent-encoded e-mails (`a%40b.com`) | pseudonymised like plain e-mails |
| bare cookie parts without `=` | masked whole |
| email addresses (bodies, headers, URLs, path) | `user_<hash8>@example.test` (case-insensitive) |
| hosts | `h1.test`, `h2.test`, ... in first-seen order; ports and userinfo dropped (so `postgres://user:pw@db:5432/x` becomes `postgres://h3.test/x`), scheme kept. Applies to URLs of any scheme (http, ws, ftp, git, redis, postgres, mongodb, amqp, ...) and scheme-relative `//host/...` in request URLs, `Host`, `Origin`, `Referer`, `Location`, `Content-Location` and strings inside bodies. Distinct host:port pairs stay distinct hosts. |
| query values | `x` (keys kept); fragments dropped |
| dropped | `cookies` arrays, `_initiator`, `serverIPAddress`, `connection`, pages, extra timings (send/wait/receive are zeroed), proxy/forwarded-for headers, non-JSON/non-form bodies |

Path segments are kept: they are the object ids coverage needs (unless a
segment holds an email or JWT).

## Coverage invariance

Run coverage with the same spec on the raw and the redacted HAR; the tables are
identical as long as the identities file matches on what you kept. A
`jwt: {sub: alice}` matcher works with the default `--keep-claims`; if your
file matches `org_id` or `role` or sets `jwt.tenant`, add them:
`--keep-claims sub,org_id,role`. Matchers by `token_sha256`, `token_env` or
`basic_user` cannot survive pseudonymisation (the raw credential is gone); use
`jwt` matchers.

## Writing identities.yaml for the fixture

Subjects can change (an e-mail `sub` is pseudonymised). Run
`authzcov discover` on the redacted HAR to see the pseudonymised subjects and
write the identities file from that output.

## Limits: review before committing

- Kept claim values are copied verbatim, except e-mail addresses in string
  claims, which become `user_<hash8>@example.test` (same mapping as in bodies).
  Other personal data in a kept claim (a real name as `sub`) is not detected.
- Benign headers that keep their value: accept*, content-type/length/encoding,
  cache-control, pragma, user-agent, x-requested-with, origin, referer, host,
  location, date, etag, vary, age, expires, last-modified, if-none-match,
  if-modified-since (values still scrubbed for JWTs, e-mails and URLs).
- Only top-level claim names are supported in `--keep-claims`.
- Arbitrary free-text secrets without a marker word (`bearer`, `token`, ...)
  or a sensitive key are not detected. Review the output before committing.
- Path segments, JSON keys outside the sensitive-key list and ordinary JSON
  string values are kept as recorded (apart from emails, JWTs and URLs). Free
  text and ids that are themselves personal data are not detected.
- `tok_<hash8>` is 32 bits: it distinguishes identities in one fixture, it is
  not a collision-resistant id.
- Always read the output and `git diff` before committing.
