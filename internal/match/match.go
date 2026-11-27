// Package match maps a method and escaped request path to an endpoint
// template using a segment trie. Stdlib only, no internal imports.
package match

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

var (
	ErrDuplicate = errors.New("duplicate template")
	ErrTemplate  = errors.New("invalid template")
)

// Op is one method + template registered in the trie.
type Op struct {
	ID       string
	Method   string
	Template string
	Params   []string // param names in path order

	pattern []bool // per segment: true = literal
	nLit    int
}

// Result of a match. Op is nil when nothing matched.
type Result struct {
	Op         *Op
	Params     map[string]string // unescaped values; nil when Op is nil
	Ambiguous  []*Op             // other candidates with as many literal segments as Op, sorted by ID
	MethodMiss bool              // path matched a template but not for this method
}

type node struct {
	lit   map[string]*node
	param *node          // one whole-segment {param} child
	ops   map[string]*Op // method -> op, on terminal nodes
}

// Trie is not safe for concurrent Add; Match is safe once building is done.
type Trie struct{ root *node }

func New() *Trie { return &Trie{root: &node{}} }

// Add registers method + template under id.
func (t *Trie) Add(method, template, id string) error {
	method = strings.ToUpper(method)
	if method == "" {
		return fmt.Errorf("%w: empty method for %q", ErrTemplate, template)
	}
	segs, err := templateSegments(template)
	if err != nil {
		return err
	}
	op := &Op{ID: id, Method: method, Template: template}
	n := t.root
	for _, s := range segs {
		if name, ok := paramName(s); ok {
			op.Params = append(op.Params, name)
			op.pattern = append(op.pattern, false)
			if n.param == nil {
				n.param = &node{}
			}
			n = n.param
			continue
		}
		op.pattern = append(op.pattern, true)
		op.nLit++
		if n.lit == nil {
			n.lit = map[string]*node{}
		}
		child, ok := n.lit[s]
		if !ok {
			child = &node{}
			n.lit[s] = child
		}
		n = child
	}
	if n.ops == nil {
		n.ops = map[string]*Op{}
	}
	if prev, ok := n.ops[method]; ok {
		return fmt.Errorf("%w: %s %s and %s %s match the same requests", ErrDuplicate, method, prev.Template, method, template)
	}
	n.ops[method] = op
	return nil
}

// Match finds the best template for method and an escaped request path.
// Precedence: at the first differing segment a literal beats a parameter.
func (t *Trie) Match(method, escapedPath string) Result {
	segs, ok := requestSegments(escapedPath)
	if !ok {
		return Result{}
	}
	method = strings.ToUpper(method)

	var terminals []*node
	collect(t.root, segs, &terminals)

	var cands []*Op
	pathMatched := false
	for _, n := range terminals {
		if len(n.ops) > 0 {
			pathMatched = true
		}
		if op, ok := n.ops[method]; ok {
			cands = append(cands, op)
		}
	}
	if len(cands) == 0 {
		return Result{MethodMiss: pathMatched}
	}

	best := cands[0]
	for _, c := range cands[1:] {
		if beats(c, best) {
			best = c
		}
	}
	res := Result{Op: best, Params: make(map[string]string, len(best.Params))}
	pi := 0
	for i, lit := range best.pattern {
		if !lit {
			res.Params[best.Params[pi]] = segs[i]
			pi++
		}
	}
	for _, c := range cands {
		if c != best && c.nLit == best.nLit {
			res.Ambiguous = append(res.Ambiguous, c)
		}
	}
	sort.Slice(res.Ambiguous, func(i, j int) bool { return res.Ambiguous[i].ID < res.Ambiguous[j].ID })
	return res
}

// collect walks every trie branch consistent with segs. Each trie node sits at
// one depth, so the walk visits each node at most once (linear in trie size).
func collect(n *node, segs []string, out *[]*node) {
	if len(segs) == 0 {
		*out = append(*out, n)
		return
	}
	s := segs[0]
	if child, ok := n.lit[s]; ok {
		collect(child, segs[1:], out)
	}
	if n.param != nil && s != "" {
		collect(n.param, segs[1:], out)
	}
}

// beats reports whether a outranks b: first differing segment, literal wins.
// Templates in one terminal have equal length, so patterns align.
func beats(a, b *Op) bool {
	for i := range a.pattern {
		if a.pattern[i] != b.pattern[i] {
			return a.pattern[i]
		}
	}
	return a.ID < b.ID // unreachable for distinct terminals; keeps order total
}

// requestSegments splits the escaped path on "/" first, then per segment drops
// ";matrix" params and unescapes, so %2F stays inside one segment.
func requestSegments(p string) ([]string, bool) {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	p = p[1:]
	if p == "" {
		return nil, true // root
	}
	p = strings.TrimSuffix(p, "/")
	raw := strings.Split(p, "/")
	segs := make([]string, len(raw))
	for i, s := range raw {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			s = s[:j]
		}
		u, err := url.PathUnescape(s)
		if err != nil {
			return nil, false
		}
		segs[i] = u // "" never binds a param and matches no literal
	}
	return segs, true
}

func templateSegments(tmpl string) ([]string, error) {
	if !strings.HasPrefix(tmpl, "/") {
		return nil, fmt.Errorf("%w: %q must start with /", ErrTemplate, tmpl)
	}
	t := strings.TrimSuffix(tmpl[1:], "/")
	if t == "" {
		return nil, nil
	}
	segs := strings.Split(t, "/")
	for _, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("%w: %q has an empty segment", ErrTemplate, tmpl)
		}
		if _, ok := paramName(s); !ok && strings.ContainsAny(s, "{}") {
			return nil, fmt.Errorf("%w: %q: parameter must fill a whole segment", ErrTemplate, tmpl)
		}
	}
	return segs, nil
}

func paramName(s string) (string, bool) {
	if len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' && !strings.ContainsAny(s[1:len(s)-1], "{}") {
		return s[1 : len(s)-1], true
	}
	return "", false
}

// Candidate is one template whose shape matches a request path.
type Candidate struct {
	Op       *Op
	Literals int  // literal segments in the template
	MethodOK bool // Op.Method equals the requested method
}

// Explanation describes how Match reached its Result.
type Explanation struct {
	Segments   []string    // unescaped request segments after ;matrix strip
	Candidates []Candidate // winner first, then by rank (literal first), then ID
	Result     Result      // exactly what Match returns
	Reason     string
}

// Explain reports every template matching the path shape, any method, and why
// Match chose its result. Result always equals Match(method, escapedPath).
func (t *Trie) Explain(method, escapedPath string) Explanation {
	e := Explanation{Result: t.Match(method, escapedPath)}
	segs, ok := requestSegments(escapedPath)
	if !ok {
		e.Reason = "request path is invalid"
		return e
	}
	e.Segments = segs
	method = strings.ToUpper(method)

	var terminals []*node
	collect(t.root, segs, &terminals)
	for _, n := range terminals {
		for _, op := range n.ops {
			e.Candidates = append(e.Candidates, Candidate{Op: op, Literals: op.nLit, MethodOK: op.Method == method})
		}
	}
	win := e.Result.Op
	sort.Slice(e.Candidates, func(i, j int) bool {
		a, b := e.Candidates[i].Op, e.Candidates[j].Op
		if (a == win) != (b == win) {
			return a == win
		}
		if a.Method == b.Method {
			return beats(a, b)
		}
		for k := range a.pattern {
			if a.pattern[k] != b.pattern[k] {
				return a.pattern[k]
			}
		}
		return a.ID < b.ID
	})
	e.Reason = e.reason(method)
	return e
}

func (e *Explanation) reason(method string) string {
	if len(e.Candidates) == 0 {
		return "no template matches this path"
	}
	win := e.Result.Op
	if win == nil {
		seen := map[string]bool{}
		var allowed []string
		for _, c := range e.Candidates {
			if !seen[c.Op.Method] {
				seen[c.Op.Method] = true
				allowed = append(allowed, c.Op.Method)
			}
		}
		sort.Strings(allowed)
		return fmt.Sprintf("path matches but method %s is not defined (allowed: %s)", method, strings.Join(allowed, ", "))
	}
	var next *Op
	for _, c := range e.Candidates[1:] {
		if c.MethodOK {
			next = c.Op
			break
		}
	}
	if next == nil {
		return "only candidate"
	}
	ws, _ := templateSegments(win.Template)
	ns, _ := templateSegments(next.Template)
	for i := range win.pattern {
		if win.pattern[i] != next.pattern[i] && i < len(ws) && i < len(ns) {
			if win.pattern[i] {
				return fmt.Sprintf("literal %q beats parameter %s at segment %d", ws[i], ns[i], i+1)
			}
			return fmt.Sprintf("parameter %s loses to literal %q at segment %d", ws[i], ns[i], i+1)
		}
	}
	return fmt.Sprintf("ties with %s; lowest ID wins", next.ID)
}
