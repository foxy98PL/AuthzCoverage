// Package basepath detects the URL prefix under which recorded traffic reaches
// the API described by a spec (for example a gateway mounting it at /petclinic).
package basepath

import (
	"sort"
	"strings"

	"authzcov/internal/match"
	"authzcov/internal/model"
)

const (
	maxSegments   = 4   // longest prefix tried, in segments
	maxCandidates = 200 // most frequent prefixes tried per host
)

// Choice is the prefix picked for one host.
type Choice struct {
	Host, Prefix   string
	Matched, Total int
}

type reqKey struct{ method, path string }

// Detect picks, per host, the path prefix (at segment boundaries, up to 4
// leading segments, including "") that maximises the number of exchanges whose
// remaining path gets a match Op. Ties: shortest prefix, then lexicographic.
// Hosts are sorted. The result does not depend on exchange order.
func Detect(xs []*model.Exchange, t *match.Trie) []Choice {
	c := NewCounter()
	for _, x := range xs {
		c.Add(x.Host, x.Method, x.Path)
	}
	return c.Choices(t)
}

// Counter accumulates the (host, method, path) multiset Detect works on, so a
// caller that streams requests need not build exchanges first.
type Counter struct{ byHost map[string]map[reqKey]int }

// NewCounter returns an empty Counter.
func NewCounter() *Counter { return &Counter{byHost: map[string]map[reqKey]int{}} }

// Add counts one request.
func (c *Counter) Add(host, method, path string) {
	m := c.byHost[host]
	if m == nil {
		m = map[reqKey]int{}
		c.byHost[host] = m
	}
	m[reqKey{strings.ToUpper(method), path}]++
}

// Choices is Detect over everything added so far.
func (c *Counter) Choices(t *match.Trie) []Choice {
	byHost := c.byHost
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	out := make([]Choice, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, detectHost(h, byHost[h], t))
	}
	return out
}

func detectHost(host string, reqs map[reqKey]int, t *match.Trie) Choice {
	total := 0
	freq := map[string]int{"": 0}
	for k, n := range reqs {
		total += n
		for _, p := range prefixes(k.path) {
			freq[p] += n
		}
	}
	cands := make([]string, 0, len(freq))
	for p := range freq {
		cands = append(cands, p)
	}
	sort.Slice(cands, func(i, j int) bool {
		if freq[cands[i]] != freq[cands[j]] {
			return freq[cands[i]] > freq[cands[j]]
		}
		return cands[i] < cands[j]
	})
	if len(cands) > maxCandidates {
		cands = cands[:maxCandidates]
	}
	if !contains(cands, "") {
		cands = append(cands, "")
	}

	best := Choice{Host: host, Total: total, Matched: -1}
	for _, p := range cands {
		matched := 0
		for k, n := range reqs {
			if rest, ok := Strip(k.path, p); ok && (p == "" || rest != "/") && t.Match(k.method, rest).Op != nil {
				matched += n
			}
		}
		better := matched > best.Matched ||
			(matched == best.Matched && (len(p) < len(best.Prefix) || (len(p) == len(best.Prefix) && p < best.Prefix)))
		if better {
			best.Prefix, best.Matched = p, matched
		}
	}
	return best
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// prefixes lists the non-empty segment-boundary prefixes of path, up to maxSegments.
func prefixes(path string) []string {
	if !strings.HasPrefix(path, "/") {
		return nil
	}
	segs := strings.Split(path[1:], "/")
	var out []string
	for k := 1; k <= len(segs) && k <= maxSegments; k++ {
		if segs[k-1] == "" {
			break
		}
		out = append(out, "/"+strings.Join(segs[:k], "/"))
	}
	return out
}

// Strip returns path with prefix removed at a segment boundary. An empty
// prefix leaves path unchanged. The result always starts with "/"; ok is false
// when path is not under prefix.
func Strip(path, prefix string) (string, bool) {
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		return path, true
	}
	if path == prefix {
		return "/", true
	}
	if strings.HasPrefix(path, prefix+"/") {
		return path[len(prefix):], true
	}
	return "", false
}
