package cli

import (
	"reflect"
	"testing"

	"authzcov/internal/config"
	"authzcov/internal/model"
)

func TestRecStoreRoundTrip(t *testing.T) {
	cfg := &config.File{LearnTokens: []config.LearnToken{{Method: "POST", Path: "/login"}}}
	st := newRecStore(newBodyNeeds(cfg))
	cred := model.Credential{Kind: "bearer", Fingerprint: "abc"}
	login := &model.Exchange{Source: "a.har#7", Method: "POST", Host: "h", Path: "/login", Cred: cred, Status: 200,
		ReqJSON: []byte(`{"u":"x"}`), RespJSON: []byte(`{"t":"y"}`)}
	get := &model.Exchange{Source: "a.har#8", Method: "GET", Host: "h", Path: "/a/1", Cred: cred, Status: 200,
		RespJSON: []byte(`{"k":1}`), Query: map[string][]string{"uid": {"z"}}}
	empty := &model.Exchange{Source: "weird", Method: "GET", Host: "h", Path: "/b", Cred: cred, Status: 200, RespJSON: []byte(`[]`)}
	for _, x := range []*model.Exchange{login, get, empty} {
		st.add(x)
	}
	var got []*model.Exchange
	st.each(false, func(r *rec) { got = append(got, st.exchange(r, r.path)) })
	if !reflect.DeepEqual(got[0], login) {
		t.Errorf("login: %+v", got[0])
	}
	// A GET no rule reads keeps only whether its response was empty.
	if got[1].Source != "a.har#8" || got[1].Path != "/a/1" || got[1].ReqJSON != nil || string(got[1].RespJSON) != "1" || got[1].Query["uid"][0] != "z" {
		t.Errorf("get: %+v", got[1])
	}
	if got[2].Source != "weird" || got[2].RespJSON == nil || len(got[2].RespJSON) != 0 {
		t.Errorf("empty: %+v", got[2])
	}
	// Look-alikes share one slim exchange; the source position survives.
	var shapes []*model.Exchange
	st.each(false, func(r *rec) { shapes = append(shapes, st.obsShape(r)) })
	if shapes[1] == shapes[2] || shapes[1] != st.obsShape(&st.chunks[0][1]) {
		t.Errorf("obs shapes: bodies must split shapes, equal ones must share")
	}
}
