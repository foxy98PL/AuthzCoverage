# Explain and base-path detection

`authzcov explain --spec api.yml 'GET /books/v1/x'` shows how one request is matched
against the spec without any HAR or identities file. It prints the request segments
(after `;matrix` stripping and unescaping), every template whose shape fits the path
(`*` marks the winner, with its literal-segment count and whether the method is defined),
the winner's bound path parameters, and a reason such as
`literal "_debug" beats parameter {username} at segment 3` or
`path matches but method PATCH is not defined (allowed: GET, POST)`.
It exits 0 even when nothing matches; a bad spec exits 3, a bad argument exits 2.
`--base-path /gw` strips a prefix from the request first.

`coverage --base-path` controls the URL prefix between host and spec paths (a gateway
mount such as `/petclinic`). `auto` (default) picks, per host, the prefix of up to 4
leading segments (or none) under which most requests match a spec operation; ties pick the
shortest prefix, and a prefix never counts a request that is reduced to `/`. `none` disables
stripping; `/prefix` forces one for every host. Hosts with zero matches are dropped and
counted. Each host gets a stderr line `base path for <host>: "<prefix>" (matched m/n, p%)`.
Unmatched requests are grouped by shape (IDs become `<id>`) on stderr, top 20 by count.
