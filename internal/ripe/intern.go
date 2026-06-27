package ripe

// intern.go contains a tiny string-interning helper for the small fixed
// vocabularies that appear in every RPSL object — attribute names (~30
// distinct strings), class names (~20), and source identifiers (~5).
//
// At ~5-8 M objects per full RIR load, every attribute carries a Name
// string. Without interning the parser allocates a fresh string per
// occurrence of "source", "netname", "inetnum", etc. — millions of duplicate
// allocations, each carrying a 16-byte string header plus the underlying
// bytes. Interning collapses these to one canonical copy per name and frees
// the rest as garbage.
//
// The map is populated at package init and never written to afterwards, so
// no locking is needed on the hot path. Strings not in the canonical set
// pass through unchanged — they don't dedupe, which is the conservative
// behavior for parser bugs or upstream additions.

// canonicalStrings is the lookup table used by intern(). Pre-populated with
// every known RPSL attribute name, class, and source label.
var canonicalStrings = map[string]string{}

func init() {
	for _, s := range knownAttrNames {
		canonicalStrings[s] = s
	}
	for _, s := range knownClasses {
		canonicalStrings[s] = s
	}
	for _, s := range knownSources {
		canonicalStrings[s] = s
	}
}

// intern returns a canonical (shared) copy of s if one exists; otherwise it
// returns s unchanged. Safe for concurrent reads.
func intern(s string) string {
	if c, ok := canonicalStrings[s]; ok {
		return c
	}
	return s
}

// knownAttrNames is the union of RPSL attribute names that appear across
// the five RIR databases. Maintained by hand — additions only need to land
// here to get interning, but missing entries don't break anything (they
// just don't dedupe).
var knownAttrNames = []string{
	// person / role / common
	"address", "admin-c", "as-block", "as-name", "as-set", "auth",
	"changed", "country", "created", "descr", "domain", "e-mail",
	"fax-no", "geoloc", "holes", "import", "import-via", "ifaddr",
	"inet-rtr", "inet6num", "inetnum", "interface", "irt", "key-cert",
	"language", "last-modified", "local-as", "members", "members-by-ref",
	"method", "mnt-by", "mnt-domains", "mnt-irt", "mnt-lower", "mnt-nfy",
	"mnt-ref", "mnt-routes", "mntner", "mp-default", "mp-export", "mp-filter",
	"mp-import", "mp-members", "mp-peer", "mp-peering", "name",
	"netname", "nic-hdl", "notify", "nserver", "org", "org-name",
	"org-type", "organisation", "origin", "owner", "peer", "peering",
	"peering-set", "person", "phone", "ping-hdl", "pingable", "ref-nfy",
	"referral-by", "remarks", "role", "route", "route-set", "route6",
	"rtr-set", "signature", "source", "sponsoring-org", "status", "tech-c",
	"trouble", "upd-to", "abuse-c", "abuse-mailbox", "zone-c",
	"alias", "default", "export", "export-comps", "filter", "filter-set",
	"fingerpr", "owner-c", "aut-num", "certif", "components", "as-name",
}

// knownClasses is the closed set of RPSL object classes we index.
var knownClasses = []string{
	"as-block", "as-set", "aut-num", "domain", "filter-set", "inet-rtr",
	"inet6num", "inetnum", "irt", "key-cert", "mntner", "organisation",
	"peering-set", "person", "role", "route", "route-set", "route6",
	"rtr-set",
}

// knownSources is the closed set of "source:" attribute values across the
// five RIRs. Each appears literally millions of times.
var knownSources = []string{
	"RIPE", "ARIN", "APNIC", "LACNIC", "AFRINIC",
	"RIPE-NONAUTH", "APNIC-GRS",
}
