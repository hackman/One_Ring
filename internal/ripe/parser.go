// Package ripe parses RIPE Routing Policy Specification Language (RPSL)
// objects out of the split-database .gz files.
//
// An RPSL object is a sequence of "attribute: value" lines. Continuation lines
// start with whitespace or '+' and append to the previous attribute. Objects
// are separated by one or more blank lines. Lines beginning with '#' or '%'
// are comments.
//
// The first attribute of an object is by convention its class (e.g. "inetnum",
// "person", "route") and its value is the object's primary key.
package ripe

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"
)

// Handle attribute slots stored eagerly on each Object. These are the only
// attributes the server reads at query time (writeRelated in server.go), so
// pre-extracting them lets us drop the per-object []Attribute slice entirely
// — saving ~30-45% of total heap on a full 5-RIR load.
const (
	HandleAdminC = 0
	HandleTechC  = 1
	HandleAbuseC = 2
	HandleZoneC  = 3
)

// Object is one RPSL object.
//
// Memory layout note: Object intentionally does NOT keep a parsed
// []Attribute slice. Raw is the source of truth and is what the WHOIS
// server emits to the wire byte-for-byte. NicHdl and Handles are eagerly
// extracted because they're the only attributes the server consults at
// query time. Any other attribute can be retrieved by Lookup/LookupAll,
// which scan Raw on demand — fine for the occasional caller, never used on
// the per-query hot path.
//
// To add another eagerly-indexed attribute, extend Handles or add a new
// field; do NOT reintroduce []Attribute.
type Object struct {
	Class      string      // e.g. "inetnum"; interned to one of ~20 strings
	PrimaryKey string      // value of the first attribute
	NicHdl     string      // for class person/role, the nic-hdl value
	Handles    [4][]string // 0=admin-c, 1=tech-c, 2=abuse-c, 3=zone-c
	Raw        string      // verbatim text, ready to write back to a WHOIS client
}

// Lookup returns the first folded value for the named attribute by
// scanning Raw, or "" if not present.
//
// This is the slow path. Hot-path consumers should read NicHdl or
// Handles directly. Used by tests and any future generic attribute query.
func (o *Object) Lookup(name string) string {
	if v := scanAttr(o.Raw, name, false); len(v) > 0 {
		return v[0]
	}
	return ""
}

// LookupAll returns every folded value for the named attribute. See
// Lookup for caveats.
func (o *Object) LookupAll(name string) []string {
	return scanAttr(o.Raw, name, true)
}

// scanAttr walks o.Raw line by line, returning the (continuation-folded)
// value(s) of `name`. If all is false it stops after the first match.
func scanAttr(raw, name string, all bool) []string {
	var out []string
	var buf strings.Builder
	matching := false

	commit := func() {
		if matching {
			out = append(out, buf.String())
			buf.Reset()
			matching = false
		}
	}

	for len(raw) > 0 {
		// extract next line including its trailing newline
		nl := strings.IndexByte(raw, '\n')
		var line string
		if nl < 0 {
			line, raw = raw, ""
		} else {
			line, raw = raw[:nl], raw[nl+1:]
		}
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			commit()
			if !all && len(out) > 0 {
				return out
			}
			continue
		}
		if trimmed[0] == '#' || trimmed[0] == '%' {
			continue
		}
		if isContinuation(trimmed) {
			if matching {
				buf.WriteByte('\n')
				buf.WriteString(stripContPrefix(trimmed))
			}
			continue
		}
		// new attribute line — commit any pending capture first
		commit()
		if !all && len(out) > 0 {
			return out
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		if strings.TrimSpace(trimmed[:colon]) != name {
			continue
		}
		matching = true
		buf.WriteString(strings.TrimSpace(trimmed[colon+1:]))
	}
	commit()
	return out
}

// handleIdx returns the Handles[] index for the given attribute name, or
// -1 if the attribute isn't one we track.
func handleIdx(name string) int {
	switch name {
	case "admin-c":
		return HandleAdminC
	case "tech-c":
		return HandleTechC
	case "abuse-c":
		return HandleAbuseC
	case "zone-c":
		return HandleZoneC
	}
	return -1
}

// Parse opens path (gzip-compressed) and invokes fn for each parsed object.
// Returning a non-nil error from fn aborts parsing.
func Parse(ctx context.Context, path string, fn func(*Object) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	return parseStream(ctx, r, fn)
}

func parseStream(ctx context.Context, r io.Reader, fn func(*Object) error) error {
	br := bufio.NewReaderSize(r, 1<<20)

	var (
		raw     strings.Builder
		curName string // attribute under construction; "" if none
		curVal  strings.Builder

		class   string
		pk      string
		nicHdl  string
		handles [4][]string
		hadAttr bool
	)

	// commit finalises the in-flight attribute (curName/curVal) into the
	// Object-being-built. For the first attribute it also fixes Class +
	// PrimaryKey. Only attributes we eagerly track land on the Object;
	// everything else is reachable via Lookup() against Raw on demand.
	commit := func() {
		if curName == "" {
			return
		}
		val := curVal.String()
		if !hadAttr {
			class = curName
			pk = val
			hadAttr = true
		}
		if curName == "nic-hdl" && nicHdl == "" {
			nicHdl = val
		}
		if i := handleIdx(curName); i >= 0 {
			handles[i] = append(handles[i], val)
		}
		curName = ""
		curVal.Reset()
	}

	flush := func() error {
		commit()
		if !hadAttr {
			raw.Reset()
			return nil
		}
		obj := &Object{
			Class:      class,
			PrimaryKey: pk,
			NicHdl:     nicHdl,
			Handles:    handles,
			Raw:        raw.String(),
		}
		raw.Reset()
		class = ""
		pk = ""
		nicHdl = ""
		for i := range handles {
			handles[i] = nil
		}
		hadAttr = false
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fn(obj)
	}

	for {
		line, err := br.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")

		if line != "" {
			if strings.TrimSpace(trimmed) == "" {
				// blank line -> object separator
				if ferr := flush(); ferr != nil {
					return ferr
				}
			} else if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "%") {
				raw.WriteString(line)
			} else if isContinuation(trimmed) {
				if curName != "" {
					curVal.WriteByte('\n')
					curVal.WriteString(stripContPrefix(trimmed))
				}
				raw.WriteString(line)
			} else {
				name, value, ok := splitAttr(trimmed)
				if ok {
					commit() // finalise the previous attribute before starting a new one
					curName = name
					curVal.WriteString(value)
					raw.WriteString(line)
				}
			}
		}

		if err == io.EOF {
			if ferr := flush(); ferr != nil {
				return ferr
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func isContinuation(line string) bool {
	if line == "" {
		return false
	}
	c := line[0]
	return c == ' ' || c == '\t' || c == '+'
}

func stripContPrefix(line string) string {
	// Drop a single leading '+' or any leading whitespace run.
	if line != "" && line[0] == '+' {
		return strings.TrimLeft(line[1:], " \t")
	}
	return strings.TrimLeft(line, " \t")
}

func splitAttr(line string) (name, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	if name == "" {
		return "", "", false
	}
	// Attribute names in RPSL are lowercase ASCII letters, digits, dashes.
	for _, r := range name {
		if !(r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "", "", false
		}
	}
	return intern(strings.ToLower(name)), value, true
}
