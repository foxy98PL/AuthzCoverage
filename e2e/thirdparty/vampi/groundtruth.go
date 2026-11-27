package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type gtItem struct {
	ID, Name, Category, Endpoint, Relationship string
	Authz                                      bool
	V1, V0                                     string // allow | deny | n/a
	Probe, Source                              string
}

// loadGroundTruth parses the flat YAML subset used by groundtruth.yaml.
func loadGroundTruth(path string) ([]gtItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var items []gtItem
	var cur *gtItem
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "- ") {
			items = append(items, gtItem{})
			cur = &items[len(items)-1]
			t = strings.TrimPrefix(t, "- ")
		}
		if cur == nil {
			return nil, fmt.Errorf("%s: key outside item: %q", path, t)
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			return nil, fmt.Errorf("%s: bad line %q", path, t)
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "id":
			cur.ID = v
		case "name":
			cur.Name = v
		case "category":
			cur.Category = v
		case "authz":
			cur.Authz = v == "true"
		case "endpoint":
			cur.Endpoint = v
		case "relationship":
			cur.Relationship = v
		case "vulnerable_1":
			cur.V1 = v
		case "vulnerable_0":
			cur.V0 = v
		case "probe":
			cur.Probe = v
		case "source":
			cur.Source = v
		}
	}
	return items, sc.Err()
}
