package ripe

import (
	"fmt"
	"path"
	"strings"
)

// Format describes how an upstream WHOIS database publishes its bulk dump.
type Format string

const (
	// FormatSplit publishes one .gz file per object class. The URL is treated
	// as a directory; per-class files live at
	//   ${base_url}/${db_name}.db.${class}.gz
	// RIPE and APNIC use this layout.
	FormatSplit Format = "split"

	// FormatSingle publishes the entire database as one .gz file. The URL is
	// the file URL itself. ARIN, AFRINIC, and LACNIC use this layout.
	FormatSingle Format = "single"
)

// Source describes one upstream RPSL database (RIPE, ARIN, APNIC, ...).
type Source struct {
	Name    string   `yaml:"name"`
	Enabled bool     `yaml:"enabled"`
	Format  Format   `yaml:"format"`
	URL     string   `yaml:"url"`
	DBName  string   `yaml:"db_name"` // override file-prefix for split format
	Classes []string `yaml:"classes"`
}

// FileSpec is one HTTP fetch we need to perform on behalf of a Source.
type FileSpec struct {
	URL       string // absolute URL to GET
	LocalName string // filename within the source's cache dir
	Class     string // RPSL class — empty for FormatSingle
}

// Files enumerates the HTTP fetches for this source. For FormatSingle the
// list is always a single entry; for FormatSplit it's one entry per class.
func (s *Source) Files() ([]FileSpec, error) {
	switch s.Format {
	case FormatSingle:
		if s.URL == "" {
			return nil, fmt.Errorf("source %q: missing url", s.Name)
		}
		local := path.Base(s.URL)
		if local == "" || local == "." || local == "/" {
			local = s.Name + ".db.gz"
		}
		return []FileSpec{{URL: s.URL, LocalName: local}}, nil

	case FormatSplit:
		if s.URL == "" {
			return nil, fmt.Errorf("source %q: missing url", s.Name)
		}
		if len(s.Classes) == 0 {
			return nil, fmt.Errorf("source %q: split format requires classes", s.Name)
		}
		name := s.DBName
		if name == "" {
			name = s.Name
		}
		base := strings.TrimRight(s.URL, "/")
		out := make([]FileSpec, 0, len(s.Classes))
		for _, c := range s.Classes {
			fn := name + ".db." + c + ".gz"
			out = append(out, FileSpec{
				URL:       base + "/" + fn,
				LocalName: fn,
				Class:     c,
			})
		}
		return out, nil

	default:
		return nil, fmt.Errorf("source %q: unknown format %q", s.Name, s.Format)
	}
}
