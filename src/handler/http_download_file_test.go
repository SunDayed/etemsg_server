package handler

import "testing"

// Resume Range parsing: only the `bytes=<start>-` form is accepted.
func TestParseRangeStart(t *testing.T) {
	cases := []struct {
		header string
		size   int64
		want   int64
		ok     bool
	}{
		{"bytes=0-", 100, 0, true},
		{"bytes=1-", 100, 1, true},
		{"bytes=99-", 100, 99, true},
		{"bytes=100-", 100, 0, false},      // start == size: nothing left to serve
		{"bytes=200-", 100, 0, false},      // start > size
		{"bytes=-10", 100, 0, false},       // trailing N bytes is not supported
		{"bytes=0-9", 100, 0, true},        // end is ignored; resume from start
		{"bytes=0-9,20-29", 100, 0, false}, // multi-range is not supported
		{"items=0-", 100, 0, false},        // unit is not "bytes"
		{"", 100, 0, false},
		{"bytes=abc-", 100, 0, false},
		{"bytes=", 100, 0, false},
	}
	for _, c := range cases {
		got, ok := parseRangeStart(c.header, c.size)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseRangeStart(%q, %d) = (%d, %v), want (%d, %v)",
				c.header, c.size, got, ok, c.want, c.ok)
		}
	}
}
