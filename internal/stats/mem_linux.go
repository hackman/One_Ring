//go:build linux

package stats

import (
	"os"
	"strconv"
	"strings"
)

// readMemStats parses /proc/self/statm. The file is a single line of
// space-separated counters in page units:
//
//	size resident shared text lib data dt
//
// We only need the first three. Errors at any step return a zero MemStats
// (consumers treat that as "unknown") rather than propagating, because
// memory reporting is best-effort instrumentation.
func readMemStats() MemStats {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return MemStats{}
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return MemStats{}
	}
	size, err1 := strconv.ParseInt(fields[0], 10, 64)
	rss, err2 := strconv.ParseInt(fields[1], 10, 64)
	shr, err3 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return MemStats{}
	}
	page := int64(os.Getpagesize())
	return MemStats{
		VirtBytes: size * page,
		RSSBytes:  rss * page,
		ShrBytes:  shr * page,
	}
}
