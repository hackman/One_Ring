package stats

// MemStats is the process memory footprint as reported by the kernel —
// the same numbers `top` shows in its VIRT / RES / SHR columns.
//
// Values are in bytes for ease of presentation. On platforms that don't
// expose these values (anything other than Linux, currently) all three
// fields are zero; consumers should treat that as "unknown".
type MemStats struct {
	VirtBytes int64 `json:"virt_bytes"` // VIRT — total mapped address space
	RSSBytes  int64 `json:"rss_bytes"`  // RES  — resident set size
	ShrBytes  int64 `json:"shr_bytes"`  // SHR  — shared / file-backed pages
}
