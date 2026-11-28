package main

import (
	"encoding/json"
	"os"
	"time"
)

// Minimal HAR 1.2 writer. URLs are rewritten to http://realworld.test so the
// output does not depend on the random localhost port.

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harEntry struct {
	Started  string   `json:"startedDateTime"`
	Time     int      `json:"time"`
	Request  harReq   `json:"request"`
	Response harRes   `json:"response"`
	Cache    struct{} `json:"cache"`
	Timings  struct {
		Send    int `json:"send"`
		Wait    int `json:"wait"`
		Receive int `json:"receive"`
	} `json:"timings"`
}

type harReq struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []string    `json:"cookies"`
	Headers     []harHeader `json:"headers"`
	QueryString []string    `json:"queryString"`
	PostData    *harPost    `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harRes struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []string    `json:"cookies"`
	Headers     []harHeader `json:"headers"`
	Content     harContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

func writeHAR(path string, entries []harEntry) error {
	doc := map[string]any{"log": map[string]any{
		"version": "1.2",
		"creator": map[string]string{"name": "rweval-recorder", "version": "1"},
		"entries": entries,
	}}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// clock gives deterministic timestamps.
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
