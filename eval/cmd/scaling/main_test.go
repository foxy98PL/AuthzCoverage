package main

import (
	"math"
	"reflect"
	"testing"
)

func TestSlopeLinearAndQuadratic(t *testing.T) {
	lin := []Point{{Entries: 1000, WallMsMed: 10}, {Entries: 10000, WallMsMed: 100}, {Entries: 100000, WallMsMed: 1000}}
	if s := slope(lin); math.Abs(s-1) > 1e-9 {
		t.Errorf("linear slope = %v", s)
	}
	quad := []Point{{Entries: 10, WallMsMed: 1}, {Entries: 100, WallMsMed: 100}}
	if s := slope(quad); math.Abs(s-2) > 1e-9 {
		t.Errorf("quadratic slope = %v", s)
	}
}

func TestParseSizes(t *testing.T) {
	got, err := parseSizes("10000, 1000")
	if err != nil || !reflect.DeepEqual(got, []int{1000, 10000}) {
		t.Errorf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", "0", "x", "1,-2"} {
		if _, err := parseSizes(bad); err == nil {
			t.Errorf("parseSizes(%q) accepted", bad)
		}
	}
}

func TestRSSParse(t *testing.T) {
	m := rssRE.FindStringSubmatch("\tMaximum resident set size (kbytes): 12345\n")
	if m == nil || m[1] != "12345" {
		t.Errorf("match = %v", m)
	}
}

func TestMedian(t *testing.T) {
	if median([]float64{1, 2, 9}) != 2 || median([]float64{1, 3}) != 2 {
		t.Error("median")
	}
}
