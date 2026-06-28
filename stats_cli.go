package main

// --stats client. Fetches the JSON snapshot from the running server's
// embedded HTTP listener (cfg.Stats.HTTPBind) and pretty-prints it.
//
// The data model below mirrors the JSON shape produced by stats.Snapshot
// without importing the unexported snap types from the stats package — it
// keeps the CLI plumbing self-contained.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hackman/One_Ring/internal/config"
)

type cliSnapshot struct {
	Generated    string         `json:"generated_at"`
	StartedAt    string         `json:"started_at"`
	UptimeSec    float64        `json:"uptime_s"`
	Live         []cliConn      `json:"live"`
	Counters     cliCounters    `json:"counters"`
	RecentQPS    float64        `json:"recent_qps"`
	DbaseLoaded  string         `json:"dbase_last_loaded,omitempty"`
	ClassCounts  map[string]int `json:"class_counts,omitempty"`
	SourceCounts map[string]int `json:"source_counts,omitempty"`
}

type cliConn struct {
	ID         uint64  `json:"id"`
	Src        string  `json:"src"`
	StartedAt  string  `json:"started_at"`
	DurationMS int64   `json:"duration_ms"`
	State      string  `json:"state"`
	Query      string  `json:"query"`
	BytesIn    int64   `json:"bytes_in"`
	BytesOut   int64   `json:"bytes_out"`
	Result     int     `json:"result_objects"`
	Error      string  `json:"error"`
	RateKBps   float64 `json:"rate_kbps"`
}

type cliCounters struct {
	QueriesTotal    uint64 `json:"queries_total"`
	QueriesHit      uint64 `json:"queries_hit"`
	QueriesMiss     uint64 `json:"queries_miss"`
	QueriesEmpty    uint64 `json:"queries_empty"`
	DeniesACL       uint64 `json:"denies_acl"`
	DeniesRateLimit uint64 `json:"denies_rate_limit"`
	DeniesBusy      uint64 `json:"denies_busy"`
	ErrorsRead      uint64 `json:"errors_read"`
	ErrorsWrite     uint64 `json:"errors_write"`
	BytesIn         int64  `json:"bytes_in"`
	BytesOut        int64  `json:"bytes_out"`
	CurrentLive     int    `json:"current_live"`
}

func runStatsCLI(cfg *config.Config) error {
	if !cfg.Stats.Enabled {
		return fmt.Errorf("stats are disabled in %s (stats.enabled: false)", "config.yaml")
	}
	if cfg.Stats.HTTPBind == "" {
		return fmt.Errorf("stats.http_bind is empty — set it in config.yaml so --stats can reach the server")
	}

	// Map "0.0.0.0:8080" / ":8080" to a usable client address.
	host, port := splitHostPort(cfg.Stats.HTTPBind)
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s:%s/stats.json", host, port)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w (is whoisd running?)", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var snap cliSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	printStats(os.Stdout, url, &snap)
	return nil
}

func splitHostPort(s string) (host, port string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", s
	}
	return s[:i], s[i+1:]
}

func printStats(w io.Writer, endpoint string, s *cliSnapshot) {
	title := fmt.Sprintf("One Ring — whoisd  %s · live status", Version)
	bar := strings.Repeat("=", len(title))
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, bar)
	fmt.Fprintf(w, "Endpoint:        %s\n", endpoint)
	fmt.Fprintf(w, "Last update:     %s (%s ago)\n",
		fmtTime(s.Generated), fmtSince(s.Generated))
	fmt.Fprintln(w)

	// Counters + Server stack into the left column to save vertical space.
	// Sources and Classes are the other two columns. Server timestamps use a
	// short format (YYYY-MM-DD HH:MM) inside the column so they fit; the full
	// absolute time is already shown in the Endpoint header above.
	left := countersColumn(s.Counters)
	left = append(left, "", "Server")
	left = append(left, fmt.Sprintf("  Started:       %s", fmtTimeShort(s.StartedAt)))
	left = append(left, fmt.Sprintf("  Uptime:        %s", fmtSeconds(s.UptimeSec)))
	if s.DbaseLoaded != "" {
		left = append(left, fmt.Sprintf("  DB last load:  %s (%s ago)",
			fmtTimeShort(s.DbaseLoaded), fmtSince(s.DbaseLoaded)))
	}
	left = append(left, fmt.Sprintf("  Recent QPS:    %.2f", s.RecentQPS))

	renderColumns(w,
		column{Width: 48, Lines: left},
		column{Width: 26, Lines: sourcesColumn(s.SourceCounts)},
		column{Width: 28, Lines: classesColumn(s.ClassCounts)},
	)
	fmt.Fprintln(w)

	// Active connections
	fmt.Fprintf(w, "Active connections (%d)\n", len(s.Live))
	if len(s.Live) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	// sort newest-busiest first
	sort.Slice(s.Live, func(i, j int) bool { return s.Live[i].DurationMS > s.Live[j].DurationMS })
	fmt.Fprintf(w, "  %-6s  %-18s  %-22s  %-11s  %-8s  %-10s\n",
		"ID", "Source", "Query", "State", "Dur", "Out")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 82))
	for _, c := range s.Live {
		fmt.Fprintf(w, "  %-6d  %-18s  %-22s  %-11s  %-8s  %-10s\n",
			c.ID,
			truncate(c.Src, 18),
			truncate(c.Query, 22),
			c.State,
			fmtDurationMS(c.DurationMS),
			fmtBytes(c.BytesOut),
		)
	}
}

// --- three-column rendering ---

// column is one column in the side-by-side counters/sources/classes layout.
type column struct {
	Width int      // padded character width; lines longer than this are truncated
	Lines []string // first entry is the section header
}

// renderColumns prints the supplied columns side-by-side, padding each line
// to its column's Width and joining columns with two spaces.
func renderColumns(w io.Writer, cols ...column) {
	maxRows := 0
	for _, c := range cols {
		if len(c.Lines) > maxRows {
			maxRows = len(c.Lines)
		}
	}
	const sep = "  "
	for i := 0; i < maxRows; i++ {
		for j, c := range cols {
			if j > 0 {
				fmt.Fprint(w, sep)
			}
			line := ""
			if i < len(c.Lines) {
				line = c.Lines[i]
			}
			if len(line) > c.Width {
				line = line[:c.Width]
			} else if len(line) < c.Width {
				line += strings.Repeat(" ", c.Width-len(line))
			}
			fmt.Fprint(w, line)
		}
		fmt.Fprintln(w)
	}
}

func countersColumn(c cliCounters) []string {
	out := []string{"Counters"}
	out = append(out, fmt.Sprintf("  Queries total: %s", fmtInt(int64(c.QueriesTotal))))
	out = append(out, fmt.Sprintf("    hit:         %s", fmtInt(int64(c.QueriesHit))))
	out = append(out, fmt.Sprintf("    miss:        %s", fmtInt(int64(c.QueriesMiss))))
	if c.QueriesEmpty > 0 {
		out = append(out, fmt.Sprintf("    empty:       %s", fmtInt(int64(c.QueriesEmpty))))
	}
	out = append(out, fmt.Sprintf("  Bytes in:      %s", fmtBytes(c.BytesIn)))
	out = append(out, fmt.Sprintf("  Bytes out:     %s", fmtBytes(c.BytesOut)))
	denied := c.DeniesACL + c.DeniesRateLimit + c.DeniesBusy
	out = append(out, fmt.Sprintf("  Denied:        %s", fmtInt(int64(denied))))
	if denied > 0 {
		out = append(out, fmt.Sprintf("    acl:         %s", fmtInt(int64(c.DeniesACL))))
		out = append(out, fmt.Sprintf("    rate-limit:  %s", fmtInt(int64(c.DeniesRateLimit))))
		out = append(out, fmt.Sprintf("    busy:        %s", fmtInt(int64(c.DeniesBusy))))
	}
	errs := c.ErrorsRead + c.ErrorsWrite
	out = append(out, fmt.Sprintf("  Errors:        %s", fmtInt(int64(errs))))
	if errs > 0 {
		out = append(out, fmt.Sprintf("    read:        %s", fmtInt(int64(c.ErrorsRead))))
		out = append(out, fmt.Sprintf("    write:       %s", fmtInt(int64(c.ErrorsWrite))))
	}
	out = append(out, fmt.Sprintf("  Live conns:    %d", c.CurrentLive))
	return out
}

func sourcesColumn(counts map[string]int) []string {
	if len(counts) == 0 {
		return []string{"Per-source object counts", "  (none loaded)"}
	}
	out := []string{"Per-source object counts"}
	for _, k := range sortedKeys(counts) {
		out = append(out, fmt.Sprintf("  %-10s %s", k, fmtInt(int64(counts[k]))))
	}
	return out
}

func classesColumn(counts map[string]int) []string {
	if len(counts) == 0 {
		return []string{"Object classes", "  (none indexed)"}
	}
	out := []string{"Object classes"}
	for _, k := range sortedKeys(counts) {
		out = append(out, fmt.Sprintf("  %-14s %s", k, fmtInt(int64(counts[k]))))
	}
	return out
}

// --- formatting helpers ---

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fmtInt(n int64) string {
	// thousands separator
	neg := n < 0
	if neg {
		n = -n
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		if len(s) > pre {
			b.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fmtSeconds(s float64) string {
	d := time.Duration(s * float64(time.Second))
	return fmtDuration(d)
}

func fmtDurationMS(ms int64) string {
	return fmtDuration(time.Duration(ms) * time.Millisecond)
}

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours()/24), int(d.Hours())%24)
}

func fmtTime(iso string) string {
	if iso == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		t, err = time.Parse(time.RFC3339, iso)
		if err != nil {
			return iso
		}
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// fmtTimeShort is fmtTime without seconds or the "UTC" suffix — used inside
// width-constrained columns where the full form doesn't fit.
func fmtTimeShort(iso string) string {
	if iso == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		t, err = time.Parse(time.RFC3339, iso)
		if err != nil {
			return iso
		}
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func fmtSince(iso string) string {
	if iso == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		t, err = time.Parse(time.RFC3339, iso)
		if err != nil {
			return iso
		}
	}
	return fmtDuration(time.Since(t).Round(time.Second))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 1 {
		return ""
	}
	return s[:max-1] + "…"
}
