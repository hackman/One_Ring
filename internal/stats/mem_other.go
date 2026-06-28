//go:build !linux

package stats

// Non-Linux platforms have no portable equivalent of /proc/self/statm, so
// we report all zeros. The dashboard renders that as "—".
func readMemStats() MemStats { return MemStats{} }
