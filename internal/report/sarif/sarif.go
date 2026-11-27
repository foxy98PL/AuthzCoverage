// Package sarif renders a coverage.json Report as SARIF 2.1.0 for GitHub code
// scanning. Output is deterministic (no timestamps, no absolute paths added)
// and every message is plain text: message.markdown is never set.
//
// Spec paths are emitted as recorded in the report, with forward slashes. A
// path that is absolute, has a URL scheme or drive letter, or climbs with
// ".." is reduced to its file name: GitHub can only place alerts on files
// inside the repository, and an absolute path would leak local directory
// names (often the user name) into an uploaded file. Run authzcov from the
// repository root with a relative --spec to get exact locations.
package sarif

import (
	"encoding/json"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"authzcov/internal/report/coveragejson"
)

const (
	schemaURL      = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion   = "2.1.0"
	fingerprintKey = "authzcovFinding/v1"
	maxMessage     = 1000
	srcRoot        = "%SRCROOT%"
	fallbackURI    = "openapi-spec"
)

type rule struct {
	kind, name, short, full, help, level, precision, severity string
}

// rules is the fixed rule table; its order defines ruleIndex.
var rules = []rule{
	{coveragejson.KindGap, "AuthorizationGap",
		"Required authorization check was never exercised",
		"An endpoint requires an authorization check for a relationship (for example another user's object) that no recorded request exercised. Coverage counts the call itself, whatever the response status.",
		"Record a test where a caller with that relationship calls the endpoint and assert the expected outcome (success for the owner; 401, 403 or 404 for other users, other tenants, lower roles and anonymous callers), then re-run authzcov.",
		"error", "high", "7.5"},
	{coveragejson.KindSuspiciousAllow, "SuspiciousAllow",
		"Request succeeded where authorization should have denied it",
		"A recorded request succeeded although the caller's relationship to the object suggests it should have been denied.",
		"Check the endpoint's authorization logic for the caller and object in question, fix it so the request is denied, and keep a test that expects the denial.",
		"warning", "medium", "6.5"},
	{coveragejson.KindUnmatchedRequest, "UnmatchedRequest",
		"Recorded requests match no operation in the spec",
		"Requests in the recording match no operation in the OpenAPI spec, so their authorization cannot be assessed.",
		"Add the missing operation to the spec or correct the base path, then re-run authzcov.",
		"note", "medium", ""},
	{coveragejson.KindAmbiguousMatch, "AmbiguousMatch",
		"Recorded requests fit more than one operation",
		"Requests fit more than one spec operation, so coverage may be attributed to the wrong endpoint.",
		"Make the spec paths unambiguous (for example distinct literal segments) and re-run authzcov.",
		"note", "medium", ""},
	{coveragejson.KindUndocumentedMeth, "UndocumentedMethod",
		"Recorded requests use a method the spec does not document",
		"Requests use an HTTP method that the spec does not document for an existing path.",
		"Document the method in the spec, or remove the call if it should not exist.",
		"note", "medium", ""},
}

type text struct {
	Text string `json:"text"`
}

type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool              tool       `json:"tool"`
	AutomationDetails automation `json:"automationDetails"`
	Results           []result   `json:"results"`
}

type automation struct {
	ID string `json:"id"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string       `json:"name"`
	Version         string       `json:"version,omitempty"`
	SemanticVersion string       `json:"semanticVersion,omitempty"`
	Rules           []ruleObject `json:"rules"`
}

type ruleObject struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	ShortDescription     text          `json:"shortDescription"`
	FullDescription      text          `json:"fullDescription"`
	Help                 text          `json:"help"`
	DefaultConfiguration defaultConfig `json:"defaultConfiguration"`
	Properties           ruleProps     `json:"properties"`
}

type defaultConfig struct {
	Level string `json:"level"`
}

type ruleProps struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          resultProps       `json:"properties"`
}

type resultProps struct {
	Endpoint     string `json:"endpoint"`
	Relationship string `json:"relationship,omitempty"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type region struct {
	StartLine int `json:"startLine"`
}

var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// Render writes r as SARIF 2.1.0.
func Render(w io.Writer, r *coveragejson.Report) error {
	if r == nil {
		r = &coveragejson.Report{}
	}
	ruleIdx := map[string]int{}
	table := rules
	if hasUnknownKind(r.Findings) {
		table = append(slices.Clone(rules), otherRule)
	}
	ros := make([]ruleObject, len(table))
	for i, ru := range table {
		ruleIdx[ru.kind] = i
		ros[i] = ruleObject{
			ID: "authzcov/" + ru.kind, Name: ru.name,
			ShortDescription: text{ru.short}, FullDescription: text{ru.full}, Help: text{ru.help},
			DefaultConfiguration: defaultConfig{Level: ru.level},
			Properties: ruleProps{Tags: []string{"security", "authorization"}, Precision: ru.precision,
				SecuritySeverity: ru.severity},
		}
	}

	type epInfo struct {
		file string
		line int
	}
	eps := make(map[string]epInfo, len(r.Endpoints))
	for _, e := range r.Endpoints {
		eps[e.ID] = epInfo{e.SpecFile, e.SpecLine}
	}

	results := make([]result, 0, len(r.Findings))
	for _, f := range r.Findings {
		kind := f.Kind
		idx, ok := ruleIdx[kind]
		if !ok {
			// A kind from a newer build: report it under the fallback rule
			// rather than drop it.
			kind, idx = otherRule.kind, ruleIdx[otherRule.kind]
		}
		file, line := r.Inputs.Spec.Path, 1
		if e, ok := eps[f.Endpoint]; ok {
			if e.file != "" {
				file = e.file
			}
			if e.line > 0 {
				line = e.line
			}
		}
		file = repoURI(file)
		results = append(results, result{
			RuleID: "authzcov/" + kind, RuleIndex: idx, Level: level(f.Severity),
			Message: text{plain(f.Message)},
			Locations: []location{{physicalLocation{
				ArtifactLocation: artifactLocation{URI: file, URIBaseID: srcRoot},
				Region:           region{StartLine: line},
			}}},
			PartialFingerprints: map[string]string{fingerprintKey: fingerprint(f)},
			Properties:          resultProps{Endpoint: plain(f.Endpoint), Relationship: plain(f.Relationship)},
		})
	}

	d := driver{Name: "authzcov", Version: plain(r.Tool.Version), Rules: ros}
	if semver.MatchString(r.Tool.Version) {
		d.SemanticVersion = r.Tool.Version
	}
	doc := document{Schema: schemaURL, Version: sarifVersion, Runs: []run{{
		Tool: tool{Driver: d}, AutomationDetails: automation{ID: "authzcov/"}, Results: results,
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func level(sev string) string {
	switch sev {
	case "error", "warning", "note":
		return sev
	}
	return "note"
}

// plain makes s safe as a plain-text message: CR, LF and TAB become spaces,
// other control and format characters are dropped, and the result is capped
// at maxMessage runes.
func plain(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			b.WriteByte(' ')
		case c == '\u2028' || c == '\u2029':
			b.WriteByte(' ')
		case unicode.IsControl(c) || unicode.In(c, unicode.Cf, unicode.Co, unicode.Cs):
		default:
			b.WriteRune(c)
		}
	}
	out := b.String()
	if rs := []rune(out); len(rs) > maxMessage {
		out = string(rs[:maxMessage-3]) + "..."
	}
	return out
}

// otherRule covers finding kinds this build does not know (a coverage.json
// written by a newer authzcov).
var otherRule = rule{"other", "OtherFinding",
	"Finding of a kind this authzcov build does not know",
	"The coverage.json contains a finding kind that this version of authzcov has no dedicated rule for.",
	"Upgrade authzcov to get the dedicated rule and guidance for this finding.",
	"note", "medium", ""}

func hasUnknownKind(fs []coveragejson.Finding) bool {
	for _, f := range fs {
		if !slices.ContainsFunc(rules, func(r rule) bool { return r.kind == f.Kind }) {
			return true
		}
	}
	return false
}

// winDrive matches a Windows drive prefix such as "C:/".
var winDrive = regexp.MustCompile(`^[A-Za-z]:/`)

// repoURI returns a repository-relative URI for a spec path; see the package doc.
func repoURI(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" {
		return fallbackURI
	}
	external := strings.HasPrefix(p, "/") || strings.Contains(p, "://") || winDrive.MatchString(p) ||
		slices.Contains(strings.Split(p, "/"), "..")
	if external {
		p = path.Base(p)
	}
	p = strings.TrimPrefix(path.Clean(p), "./")
	if p == "" || p == "." || p == "/" {
		return fallbackURI
	}
	return p
}

// fingerprint returns the finding's stable fingerprint, computing it when a
// hand-edited report left it empty.
func fingerprint(f coveragejson.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return coveragejson.Fingerprint(f.Kind, f.Endpoint, f.Relationship)
}
