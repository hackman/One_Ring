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

// Attribute is a single "name: value" pair (with continuations flattened).
type Attribute struct {
	Name  string
	Value string
}

// Object is one RPSL object.
type Object struct {
	Class      string      // e.g. "inetnum"
	PrimaryKey string      // the value of the first attribute
	Attrs      []Attribute // in source order
	Raw        string      // verbatim text, ready to write back to a WHOIS client
}

// Lookup returns the first value for the named attribute, or "".
func (o *Object) Lookup(name string) string {
	for _, a := range o.Attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// LookupAll returns every value for the named attribute.
func (o *Object) LookupAll(name string) []string {
	var out []string
	for _, a := range o.Attrs {
		if a.Name == name {
			out = append(out, a.Value)
		}
	}
	return out
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
		raw    strings.Builder
		attrs  []Attribute
		curIdx = -1 // index in attrs of the attribute under construction
	)

	flush := func() error {
		if len(attrs) == 0 {
			raw.Reset()
			return nil
		}
		obj := &Object{
			Class:      attrs[0].Name,
			PrimaryKey: attrs[0].Value,
			Attrs:      attrs,
			Raw:        raw.String(),
		}
		raw.Reset()
		attrs = nil
		curIdx = -1
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fn(obj)
	}

	for {
		line, err := br.ReadString('\n')
		// Trim trailing newline but keep the rest intact for Raw.
		trimmed := strings.TrimRight(line, "\r\n")

		if line != "" {
			// Object separator: a blank (or whitespace-only) line.
			if strings.TrimSpace(trimmed) == "" {
				if ferr := flush(); ferr != nil {
					return ferr
				}
			} else if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "%") {
				// Comment line — keep it in Raw so the WHOIS output is faithful,
				// but do not attach it to any attribute.
				raw.WriteString(line)
			} else if isContinuation(trimmed) {
				// Continuation line. RFC 2622 allows leading whitespace or '+'.
				if curIdx >= 0 {
					attrs[curIdx].Value += "\n" + stripContPrefix(trimmed)
				}
				raw.WriteString(line)
			} else {
				name, value, ok := splitAttr(trimmed)
				if ok {
					attrs = append(attrs, Attribute{Name: name, Value: value})
					curIdx = len(attrs) - 1
					raw.WriteString(line)
				}
				// Lines that don't split are silently dropped (malformed
				// records are common in real-world RPSL exports).
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
	return strings.ToLower(name), value, true
}
