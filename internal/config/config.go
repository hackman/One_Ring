package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DailyAt is a parsed HH:MM (UTC) time-of-day.
type DailyAt struct {
	Hour   int
	Minute int
}

// Next returns the next instant strictly after `from` matching this clock.
func (d DailyAt) Next(from time.Time) time.Time {
	from = from.UTC()
	cand := time.Date(from.Year(), from.Month(), from.Day(), d.Hour, d.Minute, 0, 0, time.UTC)
	if !cand.After(from) {
		cand = cand.Add(24 * time.Hour)
	}
	return cand
}

// ParseDailyAt accepts "HH:MM" (UTC). Whitespace and a trailing "UTC" are
// tolerated.
func ParseDailyAt(s string) (DailyAt, error) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "UTC"))
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return DailyAt{}, fmt.Errorf("want HH:MM, got %q", s)
	}
	h, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || h < 0 || h > 23 {
		return DailyAt{}, fmt.Errorf("bad hour %q", parts[0])
	}
	m, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || m < 0 || m > 59 {
		return DailyAt{}, fmt.Errorf("bad minute %q", parts[1])
	}
	return DailyAt{Hour: h, Minute: m}, nil
}

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Dbase     DbaseConfig     `yaml:"dbase"`
	ACL       ACLConfig       `yaml:"acl"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Stats     StatsConfig     `yaml:"stats"`
	Log       LogConfig       `yaml:"log"`
}

type StatsConfig struct {
	Enabled bool `yaml:"enabled"`
	// JSON file to atomically rewrite every DumpInterval. Empty disables.
	DumpPath string `yaml:"dump_path"`
	// May be sub-second (e.g. "500ms", "100ms").
	DumpInterval time.Duration `yaml:"dump_interval"`
	// Optional HTTP listener serving / (dashboard) and /stats.json. Empty disables.
	HTTPBind string `yaml:"http_bind"`
}

type ServerConfig struct {
	Bind          string        `yaml:"bind"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
	MaxConcurrent int           `yaml:"max_concurrent"`
	MaxQueryBytes int           `yaml:"max_query_bytes"`
	// PidFile is the path the daemon writes its pid to on startup, and that
	// `whoisd --reload` reads to locate the running instance. Empty disables
	// pid-file management entirely.
	PidFile string `yaml:"pid_file"`
}

// DbaseConfig holds the upstream-database polling settings shared across all
// configured sources, plus the per-source list itself.
type DbaseConfig struct {
	CacheDir string `yaml:"cache_dir"`

	// PollInterval is how often we ask each upstream "has anything changed?".
	// Conditional GETs make this cheap.
	PollInterval time.Duration `yaml:"poll_interval"`

	// DailyAt, if non-empty, anchors at least one refresh per day to this
	// UTC time-of-day (HH:MM, 24h). RIRs publish new dumps once a day, so
	// scheduling a check shortly after their publication window picks up
	// changes promptly without paying the polling overhead.
	DailyAt string `yaml:"daily_at"`

	// RetryOnFailure is the backoff applied when an update attempt errors.
	RetryOnFailure time.Duration `yaml:"retry_on_failure"`

	// Sources is the list of upstream databases to fetch and merge.
	Sources []SourceConfig `yaml:"sources"`
}

// SourceConfig is one upstream database entry. It maps directly onto
// ripe.Source.
type SourceConfig struct {
	Name    string   `yaml:"name"`
	Enabled bool     `yaml:"enabled"`
	Format  string   `yaml:"format"`  // "split" or "single"
	URL     string   `yaml:"url"`     // directory for split; full file for single
	DBName  string   `yaml:"db_name"` // override file prefix for split
	Classes []string `yaml:"classes"`
}

type ACLConfig struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow"`
	Deny    []string `yaml:"deny"`
}

type RateLimitConfig struct {
	Enabled  bool          `yaml:"enabled"`
	RPS      float64       `yaml:"rps"`
	Burst    int           `yaml:"burst"`
	V4Prefix int           `yaml:"v4_prefix"`
	V6Prefix int           `yaml:"v6_prefix"`
	IdleTTL  time.Duration `yaml:"idle_ttl"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	return &c, c.validate()
}

func (c *Config) applyDefaults() {
	if c.Server.Bind == "" {
		c.Server.Bind = "0.0.0.0:43"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 5 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 30 * time.Second
	}
	if c.Server.MaxConcurrent == 0 {
		c.Server.MaxConcurrent = 1024
	}
	if c.Server.MaxQueryBytes == 0 {
		c.Server.MaxQueryBytes = 512
	}
	if c.Server.PidFile == "" {
		c.Server.PidFile = "/run/whoisd.pid"
	}
	if c.Dbase.CacheDir == "" {
		c.Dbase.CacheDir = "./var/dbase"
	}
	if c.Dbase.PollInterval == 0 {
		c.Dbase.PollInterval = time.Hour
	}
	if c.Dbase.DailyAt == "" {
		c.Dbase.DailyAt = "02:00"
	}
	if c.Dbase.RetryOnFailure == 0 {
		c.Dbase.RetryOnFailure = 5 * time.Minute
	}
	if c.ACL.Default == "" {
		c.ACL.Default = "allow"
	}
	if c.RateLimit.IdleTTL == 0 {
		c.RateLimit.IdleTTL = 10 * time.Minute
	}
	if c.RateLimit.V4Prefix == 0 {
		c.RateLimit.V4Prefix = 32
	}
	if c.RateLimit.V6Prefix == 0 {
		c.RateLimit.V6Prefix = 128
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Stats.DumpInterval == 0 {
		c.Stats.DumpInterval = time.Second
	}
}

func (c *Config) validate() error {
	switch c.ACL.Default {
	case "allow", "deny":
	default:
		return fmt.Errorf("acl.default must be allow|deny, got %q", c.ACL.Default)
	}
	if c.Dbase.DailyAt != "" {
		if _, err := ParseDailyAt(c.Dbase.DailyAt); err != nil {
			return fmt.Errorf("dbase.daily_at: %w", err)
		}
	}
	if c.Dbase.PollInterval < 30*time.Second {
		return fmt.Errorf("dbase.poll_interval too small: %s", c.Dbase.PollInterval)
	}
	seen := map[string]bool{}
	enabled := 0
	for i, src := range c.Dbase.Sources {
		if src.Name == "" {
			return fmt.Errorf("dbase.sources[%d]: name required", i)
		}
		if seen[src.Name] {
			return fmt.Errorf("dbase.sources: duplicate name %q", src.Name)
		}
		seen[src.Name] = true
		if !src.Enabled {
			continue
		}
		enabled++
		switch src.Format {
		case "split":
			if len(src.Classes) == 0 {
				return fmt.Errorf("dbase.sources[%s]: split format requires classes", src.Name)
			}
		case "single":
			// nothing
		default:
			return fmt.Errorf("dbase.sources[%s]: format must be split|single, got %q", src.Name, src.Format)
		}
		if src.URL == "" {
			return fmt.Errorf("dbase.sources[%s]: url required", src.Name)
		}
	}
	if enabled == 0 {
		return fmt.Errorf("dbase.sources: at least one source must be enabled")
	}
	if c.Stats.Enabled && c.Stats.DumpInterval < 50*time.Millisecond {
		return fmt.Errorf("stats.dump_interval too small (min 50ms): %s", c.Stats.DumpInterval)
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.RPS <= 0 {
			return fmt.Errorf("rate_limit.rps must be > 0 when enabled")
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be > 0 when enabled")
		}
		if c.RateLimit.V4Prefix < 0 || c.RateLimit.V4Prefix > 32 {
			return fmt.Errorf("rate_limit.v4_prefix out of range")
		}
		if c.RateLimit.V6Prefix < 0 || c.RateLimit.V6Prefix > 128 {
			return fmt.Errorf("rate_limit.v6_prefix out of range")
		}
	}
	return nil
}
