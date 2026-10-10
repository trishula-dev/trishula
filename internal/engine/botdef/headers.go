package botdef

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
	Casing      string   // "canonical" | "lower" | "mixed"
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

// headerFingerprint computes the fingerprint + classification. GREEN fills
// this; RED stub fails.
func headerFingerprint(hv *HeaderView) HeaderFingerprint { return HeaderFingerprint{} }
