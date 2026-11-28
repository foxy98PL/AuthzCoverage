package config

import (
	"errors"
	"strings"

	"go.yaml.in/yaml/v3"

	"authzcov/internal/probe/credentials"
)

// loginRecipe parses identities[i].login_recipe. Structure and value rules
// live in credentials.Recipe.Validate; this maps its errors to YAML paths and
// Env placeholders are syntax-checked only; credentials.Provider.CheckEnv
// resolves them at probe time, so coverage and report need no secrets.
func (p *parser) loginRecipe(n *yaml.Node, rp string) (*credentials.Recipe, *Error) {
	m, e := p.fields(n, rp, "method", "path", "content_type", "fields", "token_from", "apply")
	if e != nil {
		return nil, e
	}
	for _, k := range []string{"method", "path", "content_type", "fields", "token_from"} {
		if m[k] == nil {
			return nil, p.err(n, rp+"."+k, "%s is required", k)
		}
	}
	r := &credentials.Recipe{}
	for key, dst := range map[string]*string{"method": &r.Method, "path": &r.Path, "content_type": &r.ContentType} {
		s, e := p.scalar(m[key], rp+"."+key)
		if e != nil {
			return nil, e
		}
		*dst = s
	}
	fn := m["fields"]
	fm, e := p.fields(fn, rp+".fields")
	if e != nil {
		return nil, e
	}
	r.Fields = map[string]string{}
	for k, v := range fm {
		s, e := p.scalar(v, rp+".fields."+k)
		if e != nil {
			return nil, e
		}
		r.Fields[k] = s
	}
	tp := rp + ".token_from"
	tm, e := p.fields(m["token_from"], tp, "json", "header", "cookie")
	if e != nil {
		return nil, e
	}
	if len(tm) != 1 {
		return nil, p.err(m["token_from"], tp, "give exactly one of json, header, cookie")
	}
	for k, v := range tm {
		s, e := p.scalar(v, tp+"."+k)
		if e != nil {
			return nil, e
		}
		r.TokenFrom = credentials.TokenFrom{Kind: k, Name: s}
	}
	r.Apply = credentials.Apply{Kind: "bearer"}
	if an := m["apply"]; an != nil {
		s, e := p.scalar(an, rp+".apply")
		if e != nil {
			return nil, e
		}
		a, err := credentials.ParseApply(s)
		if err != nil {
			return nil, p.recipeErr(n, m, rp, err)
		}
		r.Apply = a
	}
	if err := r.Validate(); err != nil {
		return nil, p.recipeErr(n, m, rp, err)
	}
	return r, nil
}

func (p *parser) recipeErr(n *yaml.Node, m map[string]*yaml.Node, rp string, err error) *Error {
	var re *credentials.RecipeError
	if !errors.As(err, &re) {
		return p.err(n, rp, "%s", err.Error())
	}
	key, _, _ := strings.Cut(re.Field, ".")
	node := m[key]
	if node == nil {
		node = n
	}
	path := rp + "." + re.Field
	if key == "fields" && strings.HasPrefix(re.Field, "fields.") {
		if fm, e := p.fields(node, rp+".fields"); e == nil {
			if v := fm[strings.TrimPrefix(re.Field, "fields.")]; v != nil {
				node = v
			}
		}
	}
	return p.err(node, path, "%s", re.Msg)
}

// ProbeRecipes returns the login recipes by identity name, and the expected
// token fingerprint (12 hex of SHA-256, from token_sha256) for the identities
// that have both a recipe and a hash. It feeds credentials.Provider.
func (f *File) ProbeRecipes() (recipes map[string]credentials.Recipe, expectFP map[string]string) {
	recipes, expectFP = map[string]credentials.Recipe{}, map[string]string{}
	for _, id := range f.Identities {
		if id.LoginRecipe == nil {
			continue
		}
		recipes[id.Name] = *id.LoginRecipe
		if id.TokenFP != "" {
			expectFP[id.Name] = id.TokenFP
		}
	}
	return recipes, expectFP
}
