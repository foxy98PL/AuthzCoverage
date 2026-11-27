# Demo for the README. Render with `make gif` (needs vhs, ttyd and ffmpeg).
# Everything runs locally against the bundled tenantshop demo API; authzcov itself sends no requests.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 16
Set TypingSpeed 40ms
Set Theme "Dracula"

# Hidden setup: build, start tenantshop, record a session, prepare a stricter baseline.
Hide
Type "R=$PWD; D=$(mktemp -d); S=$D/.bin; mkdir -p $S" Enter
Type "go build -o $S/authzcov ./cmd/authzcov && (cd e2e/apps/tenantshop && go build -o $S/shop . && go build -o $S/record ./cmd/record) && export PATH=$S:$PATH" Enter
Type "($S/shop -addr :8091 >/dev/null 2>&1 &) ; sleep 2; cd $D && $S/record -base http://localhost:8091 -out shop.har >/dev/null && cp $R/e2e/apps/tenantshop/shop/openapi.yaml $R/e2e/apps/tenantshop/identities.yaml ." Enter
Type `authzcov coverage --spec openapi.yaml --identities identities.yaml --har shop.har >/dev/null 2>&1 && authzcov baseline write >/dev/null && sed -i '0,/"anonymous": "missing"/s//"anonymous": "covered"/' .authzcov/baseline.json && rm -rf authzcov-out; clear` Enter
Show

Type "# 1. We recorded our test run as a HAR. Which identities appear in it?" Enter
Sleep 1s
Type "authzcov discover --har shop.har | head -14" Enter
Sleep 5s

Type "clear" Enter
Type "# 2. Which endpoint x relationship cells do the tests actually exercise?" Enter
Sleep 1s
Type "authzcov coverage --spec openapi.yaml --identities identities.yaml --har shop.har 2>/dev/null" Enter
Sleep 8s

Type "clear" Enter
Type "# 3. CI gate: the baseline had more coverage than this run, so it fails" Enter
Sleep 1s
Type "authzcov gate" Enter
Sleep 6s
Type "echo exit code: $?" Enter
Sleep 3s

Hide
Type "pkill -f $S/shop; cd $R; rm -rf $D" Enter
Show
