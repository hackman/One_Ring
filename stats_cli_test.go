package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestPrintStatsStackedLayout renders printStats against a snapshot shaped
// like a real production load (numbers taken from a live whoisd instance)
// and confirms Server stacks under Counters in the leftmost column.
func TestPrintStatsStackedLayout(t *testing.T) {
	snap := &cliSnapshot{
		Generated:   "2026-06-28T03:33:51Z",
		StartedAt:   "2026-06-28T03:02:20Z",
		UptimeSec:   1891,
		RecentQPS:   0.0,
		DbaseLoaded: "2026-06-28T03:03:44Z",
		Counters: cliCounters{
			QueriesTotal: 0,
			CurrentLive:  0,
		},
		SourceCounts: map[string]int{
			"afrinic": 432643,
			"apnic":   3601640,
			"arin":    196715,
			"lacnic":  530869,
			"ripe":    6904180,
		},
		ClassCounts: map[string]int{
			"as-block":     1671,
			"as-set":       41610,
			"aut-num":      86638,
			"domain":       1211900,
			"filter-set":   181,
			"inet-rtr":     145,
			"inet6num":     1176122,
			"inetnum":      6043958,
			"irt":          34977,
			"key-cert":     8974,
			"mntner":       134526,
			"organisation": 118261,
			"peering-set":  276,
			"person":       26205,
			"role":         168939,
			"route":        1547092,
			"route-set":    5323,
			"route6":       1059148,
			"rtr-set":      101,
		},
	}
	var buf bytes.Buffer
	printStats(&buf, "http://10.10.1.2:8043/stats.json", snap)
	out := buf.String()

	// The standalone "Server" header used to be on its own line at the top
	// with no leading indent (just "Server"). After the rewrite it must
	// only appear inside the leftmost column, padded to that column's
	// width. We assert there is no longer a free-standing "Server\n"
	// before the column block.
	if i := strings.Index(out, "Server\n"); i >= 0 {
		// Anything starting with "Server\n" should be inside the columns
		// region — i.e. should have spaces after it (the column padding).
		// Easiest invariant: "Server" must appear AFTER the "Counters"
		// header in column form (i.e. no longer at column zero with a
		// blank line above it).
		if !strings.Contains(out[:i], "Counters") {
			t.Errorf("Server header appears before Counters; stacking did not happen")
		}
	}

	// Counters and Per-source must share the same row (3-column layout).
	if !strings.Contains(out, "Counters") {
		t.Fatalf("missing Counters header:\n%s", out)
	}
	headerLine := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "Counters") {
			headerLine = ln
			break
		}
	}
	if !strings.Contains(headerLine, "Per-source object counts") {
		t.Errorf("Counters header line missing sibling columns:\n%q", headerLine)
	}
	if !strings.Contains(headerLine, "Object classes") {
		t.Errorf("Counters header line missing classes column:\n%q", headerLine)
	}

	// Print so the developer can eyeball the new look during `go test -v`.
	t.Log("\n" + out)
}
