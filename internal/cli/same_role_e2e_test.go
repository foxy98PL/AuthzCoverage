package cli

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

func TestSameRoleOtherUserEndToEnd(t *testing.T) {
	for _, bobStatus := range []int{200, 403} {
		t.Run(fmt.Sprintf("bob_%d", bobStatus), func(t *testing.T) {
			a := hartest.Bearer(hartest.JWT(t, "alice", nil))
			b := hartest.Bearer(hartest.JWT(t, "bob", nil))
			es := []hartest.Entry{
				{Method: "POST", URL: base + "/books/v1", Status: 200, Headers: a, ReqJSON: `{"book_title":"a1","secret":"x"}`},
				{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: a},
				{Method: "GET", URL: base + "/books/v1/a1", Status: bobStatus, Headers: b},
				{Method: "GET", URL: base + "/users/v1/alice", Status: 200, Headers: b},
				{Method: "GET", URL: base + "/books/v1/a1", Status: 401},
			}
			code, out, errs := run(t, es)
			t.Logf("stdout:\n%s\nstderr:\n%s", out, errs)
			if code != ExitOK {
				t.Fatalf("exit = %d; stderr=%s", code, errs)
			}
			lines := strings.Split(out, "\n")
			cols := regexp.MustCompile(`\s{2,}`)
			header := cols.Split(strings.TrimSpace(lines[0]), -1)
			row := func(prefix string) map[string]string {
				for _, l := range lines[1:] {
					if strings.HasPrefix(l, prefix) {
						f := cols.Split(strings.TrimSpace(strings.TrimPrefix(l, prefix)), -1)
						m := map[string]string{}
						for i, h := range header[1:] {
							if i < len(f) {
								m[h] = f[i]
							}
						}
						return m
					}
				}
				t.Fatalf("no row %q in:\n%s", prefix, out)
				return nil
			}
			sameRole := "ok"
			if bobStatus != 200 {
				sameRole = fmt.Sprintf("ok %d", bobStatus)
			}
			book := row("GET     /books/v1/{book_title}")
			for col, want := range map[string]string{"OWNER": "ok", "SAME_ROLE": sameRole, "ANON": "ok 401"} {
				if book[col] != want {
					t.Errorf("books %s = %q, want %q (row %v)", col, book[col], want, book)
				}
			}
			if u := row("GET     /users/v1/{username}"); u["SAME_ROLE"] != "ok" {
				t.Errorf("users SAME_ROLE = %q (row %v)", u["SAME_ROLE"], u)
			}
		})
	}
}
