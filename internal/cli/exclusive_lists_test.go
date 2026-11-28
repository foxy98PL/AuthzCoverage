package cli

import (
	"os"
	"testing"

	"authzcov/internal/config"
	"authzcov/internal/model"
	"authzcov/internal/ownership"
)

func listClassify(t *testing.T, cfg *config.File, path, body string) []ownership.Object {
	t.Helper()
	alice := &model.Identity{Name: "alice", Role: "user"}
	ep := &model.Endpoint{ID: "GET " + path, Method: "GET", Template: path, Kind: model.FunctionLevel}
	o := &model.Observation{Endpoint: ep, Identity: alice, IDConf: model.ConfLearned,
		X: &model.Exchange{Method: "GET", Path: path, Status: 200, RespJSON: []byte(body)}}
	return classify(cfg, []*model.Observation{o})
}

// KAN-102 F1: classify must carry the exclusive flag into the ownership rule.
func TestClassifyExclusiveListIsLearned(t *testing.T) {
	for _, tc := range []struct {
		excl string
		want model.Confidence
	}{{"true", model.ConfLearned}, {"false", model.ConfInferred}} {
		y := "version: 1\nroles: {user: 10}\nidentities:\n  - {name: alice, role: user, match: {jwt: {sub: a}}}\n" +
			"ownership:\n  learn_from_lists:\n    - match: {method: GET, path: /books}\n      resource: books\n" +
			"      ids_from: {response_json: \"[].id\"}\n      exclusive: " + tc.excl + "\n"
		cfg, err := config.Parse([]byte(y), "t.yaml")
		if err != nil {
			t.Fatal(err)
		}
		objs := listClassify(t, cfg, "/books", `[{"id":"b1"}]`)
		if len(objs) != 1 || objs[0].Conf != tc.want {
			t.Fatalf("exclusive=%s: objects = %+v, want conf %v", tc.excl, objs, tc.want)
		}
	}
}

// KAN-102 gap: the crAPI identities file parses offline and its vehicles list
// rule is exclusive, so listed vehicles are learned (not inferred).
func TestCrapiIdentitiesParse(t *testing.T) {
	const p = "../../e2e/thirdparty/crapi/identities.yaml"
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data, p)
	if err != nil {
		t.Fatal(err)
	}
	lists := cfg.Ownership.LearnFromLists
	if len(lists) != 1 || !lists[0].Exclusive || lists[0].Resource != "vehicles" {
		t.Fatalf("lists = %+v", lists)
	}
	objs := listClassify(t, cfg, "/identity/api/v2/vehicle/vehicles", `[{"uuid":"v1"}]`)
	if len(objs) != 1 || objs[0].ID != "v1" || objs[0].Conf != model.ConfLearned {
		t.Fatalf("objects = %+v", objs)
	}
}
