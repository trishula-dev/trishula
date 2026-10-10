package botdef

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// HeaderView is the h1-style header plane the fingerprint consumes: the
// exact ordered (name, value-as-sent-casing) pairs the reconstructor saw
// on the wire. Order and original casing are the signal — both are lost
// the moment a server normalizes into a map, so the ingest path must
// attach this slice BEFORE folding into http1.Request.Headers
// (AttachHeaderView; http1 itself parses into the map for rule
// evaluation and keeps no order).
//
// §11.3's request.header_names carries this same concept as a []string of
// lowercased names; TR-04's FlowEvent has no header plane yet, so the
// summary byte supply again arrives with TR-15. Until a view is attached,
// the S5 stage emits no fragment.
type HeaderView struct {
	Method  string            // "GET" (sent casing)
	Version string            // "1.1" | "1.0" (h2 arrives with TR-15's planes)
	Headers [][2]string       // wire order, original name casing
	Values  map[string]string // lowercased name → value (lookup convenience)
}

// HeaderFingerprint is the computed header-plane fingerprint: stable hash
// over the normalized ordered-name vector + presence bitmask + a
// tool-vs-browser classification verdict with the evidence that drove it.
type HeaderFingerprint struct {
	Hash        string   // stable 16-hex fingerprint of the vector+presence
	Order       []string // normalized ordered header names (the hashed vector)
	Presence    uint64   // h1-style presence bitmask over headerPresentOrder
	Casing      string   // "canonical" | "lower" | "mixed" | "empty"
	UserAgent   string   // detected UA value ("" = none)
	Toolish     bool     // tool-shaped: no UA, or a curl/python/go/wget UA
	Browserish  bool     // browser-shaped: UA + accept-language or sec-ch hints
	Reasons     []string // classification evidence (stable order)
	HasUA       bool
	HasAL       bool // accept-language present
	HasSecCH    bool // any sec-ch-ua* hint present
	headerCount int
}

// headerPresentOrder is the stable bit order of the presence vector
// (h1-style named-vector; index = bit).
var headerPresentOrder = []string{
	"host", "user-agent", "accept", "accept-language", "accept-encoding",
	"connection", "content-type", "content-length", "cookie", "referer",
	"authorization", "origin", "upgrade-insecure-requests", "sec-ch-ua",
	"sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site",
	"sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "pragma",
	"cache-control", "x-requested-with", "postman-token",
}

// headerFingerprint computes the stable hash + classification over the
// ordered header view. Order and casing are evidence on the h1 wire; the
// normalized name vector enters the hash byte-for-byte (NUL-joined), the
// presence bitmask rides the same preimage. Deterministic: no map
// iteration (headerPresentOrder is a fixed slice for bit assignment;
// classification reasons append in fixed order).
func headerFingerprint(hv *HeaderView) HeaderFingerprint {
	fp := HeaderFingerprint{
		Order:       make([]string, len(hv.Headers)),
		headerCount: len(hv.Headers),
	}
	bitOf := make(map[string]int, len(headerPresentOrder))
	for i, n := range headerPresentOrder {
		bitOf[n] = i
	}
	canonical, lowercased := 0, 0
	values := hv.Values
	if values == nil {
		// No lookup map supplied: derive values from the wire pairs (the
		// attach path may pre-build it; absence never blanks evidence).
		values = make(map[string]string, len(hv.Headers))
		for _, kv := range hv.Headers {
			values[lower(kv[0])] = kv[1]
		}
	}
	for i, kv := range hv.Headers {
		name := lower(kv[0])
		fp.Order[i] = name
		if b, known := bitOf[name]; known {
			fp.Presence |= 1 << uint(b)
		}
		if kv[0] == canonicalTitle(name) {
			canonical++
		} else if kv[0] == name {
			lowercased++
		}
		switch name {
		case "user-agent":
			fp.HasUA = true
			fp.UserAgent = values["user-agent"]
		case "accept-language":
			fp.HasAL = true
		case "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
			"sec-ch-ua-model", "sec-ch-ua-arch", "sec-ch-ua-bitness",
			"sec-ch-ua-platform-version", "sec-ch-ua-form-factors", "sec-ch-ua-wow64":
			fp.HasSecCH = true
		}
	}
	switch {
	case canonical == len(hv.Headers) && len(hv.Headers) > 0:
		fp.Casing = "canonical"
	case lowercased == len(hv.Headers) && len(hv.Headers) > 0:
		fp.Casing = "lower"
	case len(hv.Headers) > 0:
		fp.Casing = "mixed"
	default:
		fp.Casing = "empty"
	}

	// --- classification (§12.1 header-plane family): evidence, not identity.
	// UA taxonomy: a tool prefix (curl/wget/python/go-http/…) is direct tool
	// evidence; a Mozilla-family UA is browser evidence; browser UA WITHOUT
	// any client-hint/AL backing is the masquerade tell (§12.1: "detects
	// curl/python/bot-framework masquerades").
	browserUA := strings.Contains(lower(fp.UserAgent), "mozilla/5")
	toolUA := toolUAPrefix(fp.UserAgent)
	if toolUA {
		fp.Reasons = append(fp.Reasons, "tool user-agent")
		fp.Toolish = true
	}
	if !fp.HasUA {
		fp.Reasons = append(fp.Reasons, "no user-agent header")
		fp.Toolish = true
	}
	if fp.HasSecCH {
		fp.Reasons = append(fp.Reasons, "sec-ch-ua hints present")
		fp.Browserish = true
	}
	if browserUA {
		fp.Reasons = append(fp.Reasons, "browser user-agent")
		fp.Browserish = true
		if !fp.HasAL && !fp.HasSecCH {
			fp.Reasons = append(fp.Reasons, "browser user-agent without accept-language or sec-ch hints (masquerade shape)")
			fp.Toolish = true
		}
	}
	if fp.HasAL && !fp.Browserish {
		fp.Reasons = append(fp.Reasons, "accept-language without browser identity")
	}

	// --- stable hash: ordered normalized-name vector + casing class +
	// presence bitmask (version-tagged preimage). Casing rides the hash:
	// on the h1 wire the sent name casing IS evidence (test-pinned), and
	// the class keeps the preimage bounded. SHA-256's 16-hex prefix keeps
	// the vector the identity of record; the raw Order[] rides alongside
	// for exact comparison and the lab log.
	hashIn := "h1|" + fp.Casing + "|" + strings.Join(fp.Order, "\x00") + "|pb=" +
		strconv.FormatUint(fp.Presence, 10)
	sum := sha256.Sum256([]byte(hashIn))
	fp.Hash = hex.EncodeToString(sum[:])[:16]
	return fp
}

// canonicalTitle is the canonical h1 capitalization of a lowercased header
// name: every dash-delimited token's first byte upper, rest as-is
// ("user-agent" -> "User-Agent"; "sec-ch-ua" -> "Sec-Ch-Ua").
func canonicalTitle(name string) string {
	var b strings.Builder
	upNext := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' {
			upNext = true
			b.WriteByte(c)
			continue
		}
		if upNext && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		upNext = false
		b.WriteByte(c)
	}
	return b.String()
}

// toolUAPrefixes are the command-line/library HTTP tools whose UA head is
// fixed (prefix match, lowercased).
var toolUAPrefixes = []string{
	"curl/", "wget/", "python-requests/", "python-urllib", "python-httpx",
	"go-http-client", "aiohttp/", "httpclient", "java/", "okhttp/",
	"apache-httpclient", "libwww-perl", "lwp-request", "scrapy",
	"apachebench", "masscan/", "zgrab/", "nuclei/", "sqlmap/",
}

// toolUAPrefix reports whether the UA names a known HTTP tool.
func toolUAPrefix(ua string) bool {
	l := lower(ua)
	for _, p := range toolUAPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// lower is the ASCII lowercaser for header names (h1 names are ASCII; a
// non-ASCII byte passes through — normalization is deliberately narrow).
func lower(s string) string { return strings.ToLower(s) }
