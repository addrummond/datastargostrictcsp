// Package datastargostrictcsp makes the [Datastar] hypermedia framework
// compatible with strict Content Security Policies (no unsafe-eval, no
// unsafe-inline). It works by precompiling Datastar expressions on the server
// and serving them via backend-signed URLs, side-stepping the need for the
// JavaScript Function constructor at runtime.
//
// Basic usage: mount [Precompiler.ScriptHandler] at a fixed path, then wrap
// your mux with [Precompiler.Middleware] (optionally combined with [NonceMiddleware]
// for per-request nonce protection). Load the companion client-side script
// (dist/datastargostrictcsp-client.js) before the Datastar module script.
//
// [Datastar]: https://data-star.dev/
package datastargostrictcsp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// Precompiler signs expression arg-lists so they can be served via a dedicated
// JS endpoint rather than inline scripts, removing the need for 'unsafe-inline'
// in the Content-Security-Policy.
//
// Set Key to a 32-byte secret before use. Use a persistent secret in
// production so cached script URLs remain valid across restarts.
//
// OldKeys lists previously active signing keys that are still accepted during
// verification. See the 'Key rotation' section of the README for usage.
//
// ScriptPath specifies where ScriptHandler is mounted. It defaults
// to "/ds-precompile.js" if empty.
//
// MaxURLLen is the maximum length of a generated script URL. When the signed
// expression parameters for a page or fragment would produce a URL longer than
// this, the expressions are split across multiple URLs and multiple <script>
// tags (or, for SSE, multiple space-separated URLs in the data: url line).
// Defaults to 2000 if zero.
type Precompiler struct {
	Key        [32]byte
	OldKeys    [][32]byte
	// ScriptPath overrides the default script path ("/ds-precompile.js").
	// Use GetScriptPath() to get the effective path.
	ScriptPath string
	MaxURLLen        int
	// Alias is the Datastar bundle alias, if using a custom aliased bundle.
	// When set, attributes of the form data-{Alias}-{attr} are recognized.
	Alias string
}

// GetScriptPath returns the effective script path: ScriptPath if set,
// otherwise the default "/ds-precompile.js".
func (p *Precompiler) GetScriptPath() string {
	if p.ScriptPath != "" {
		return p.ScriptPath
	}
	return "/ds-precompile.js"
}

func (p *Precompiler) maxURLLen() int {
	if p.MaxURLLen > 0 {
		return p.MaxURLLen
	}
	return 2000
}

var errZeroKey = errors.New("datastargostrictcsp: Key must not be zero")

func generateNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

type nonceContextKey struct{}

func contextWithNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceContextKey{}, nonce)
}

// NonceFromContext retrieves the per-request nonce stored by NonceMiddleware.
// Returns an empty string if none is set.
func NonceFromContext(ctx context.Context) string {
	n, _ := ctx.Value(nonceContextKey{}).(string)
	return n
}

// signURL builds a signed script URL for the given pre-encoded e values.
// Format: <scriptPath>?e=<b64url(JSON(funcArgs))>&...&sig=<b64url(HMAC-SHA256[:12])>[&i=1]
// The HMAC covers the canonical "e=...&e=..." query string.
//
// The HMAC-SHA256 output is truncated to 12 bytes (96 bits). This is
// intentional: 96-bit MACs are well within accepted practice for URL signing
// (NIST SP 800-107 allows truncation to half the hash length), and keeping
// the signature short reduces URL length.
//
// If initMap is true, &i=1 is appended; the served script will initialise
// window.__datastar_precompiled_expressions if it does not already exist.
func (p *Precompiler) signURL(eVals []string, initMap bool) (string, error) {
	if p.Key == [32]byte{} {
		return "", errZeroKey
	}
	canonical := url.Values{"e": eVals}.Encode()
	mac := hmac.New(sha256.New, p.Key[:])
	mac.Write([]byte(canonical))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	scriptPath := p.GetScriptPath()
	var b strings.Builder
	b.Grow(len(scriptPath) + 1 + len(canonical) + 5 + len(sig) + 4)
	b.WriteString(scriptPath)
	b.WriteByte('?')
	b.WriteString(canonical)
	b.WriteString("&sig=")
	b.WriteString(sig)
	if initMap {
		b.WriteString("&i=1")
	}
	return b.String(), nil
}

// verifyURL checks the URL-level signature and returns entries for all e params.
// It tries Key first, then each entry in OldKeys.
func (p *Precompiler) verifyURL(q url.Values) ([]precompileEntry, error) {
	if p.Key == [32]byte{} {
		return nil, errZeroKey
	}
	eVals := q["e"]
	sigVals := q["sig"]
	if len(sigVals) != 1 {
		return nil, errors.New("missing sig")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigVals[0])
	if err != nil {
		return nil, err
	}
	canonical := url.Values{"e": eVals}.Encode()
	keys := append([][32]byte{p.Key}, p.OldKeys...)
	var matched bool
	for _, k := range keys {
		mac := hmac.New(sha256.New, k[:])
		mac.Write([]byte(canonical))
		if hmac.Equal(sig, mac.Sum(nil)[:12]) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, errors.New("invalid signature")
	}
	entries := make([]precompileEntry, len(eVals))
	for i, e := range eVals {
		payload, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil {
			return nil, err
		}
		var funcArgs []string
		if err := json.Unmarshal(payload, &funcArgs); err != nil {
			return nil, err
		}
		entries[i] = precompileEntry{funcArgs: funcArgs}
	}
	return entries, nil
}

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// jsonMarshal is json.Marshal with HTML escaping disabled so characters like &
// are encoded as & rather than &, keeping URLs and generated scripts compact.
func jsonMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1] // Encode always appends a newline; strip it
	}
	return b, nil
}

// ScriptHandler returns an http.Handler that verifies signed expression
// parameters and serves a cacheable JS file that registers the corresponding
// functions.
func (p *Precompiler) ScriptHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		entries, err := p.verifyURL(q)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(buildJS(entries, q.Get("i") == "1"))
	})
}

// buildSignedURLs returns one or more signed script URLs for entries. When the
// URL would exceed MaxURLLen the entries are split across multiple URLs; all of
// them write into the same window.__datastar_precompiled_expressions map so the
// JS composes cleanly. A single entry that by itself exceeds the limit is
// emitted as its own URL rather than silently dropped.
func (p *Precompiler) buildSignedURLs(entries []precompileEntry) ([]string, error) {
	// Pre-encode all funcArgs to base64url(JSON) so each entry's contribution
	// to the URL length is known before signing.
	eVals := make([]string, len(entries))
	for i, entry := range entries {
		payload, err := jsonMarshal(entry.funcArgs)
		if err != nil {
			return nil, err
		}
		eVals[i] = base64.RawURLEncoding.EncodeToString(payload)
	}

	const sigOverhead = len("&sig=") + 16 // 12 bytes = 16 base64url chars
	prefix := p.GetScriptPath() + "?"
	maxLen := p.maxURLLen()

	var urls []string
	var chunk []string

	for _, ev := range eVals {
		next := append(chunk, ev)
		if len(chunk) > 0 && len(prefix)+len(url.Values{"e": next}.Encode())+sigOverhead > maxLen {
			u, err := p.signURL(chunk, len(urls) == 0)
			if err != nil {
				return nil, err
			}
			urls = append(urls, u)
			chunk = []string{ev}
		} else {
			chunk = next
		}
	}
	if len(chunk) > 0 {
		u, err := p.signURL(chunk, len(urls) == 0)
		if err != nil {
			return nil, err
		}
		urls = append(urls, u)
	}
	return urls, nil
}

// DatastarExpression is a Datastar attribute expression to precompile.
// Attribute is the base name of the Datastar attribute (e.g. "on", "show",
// "effect"). Value is the raw expression string.
type DatastarExpression struct {
	Attribute string
	Value     string
}

// SignedURLs precompiles exprs and returns one or more signed script URLs
// covering all of them. The URLs can be injected as <script type="module" src="..."> tags
// in any template engine. URLs are stable for a given set of expressions and
// signing key, so they are safe to cache indefinitely.
func (p *Precompiler) SignedURLs(exprs []DatastarExpression) ([]string, error) {
	seen := map[string]bool{}
	var entries []precompileEntry
	for _, e := range exprs {
		attr, known := dsAttrs[e.Attribute]
		if !known || attr.Kind == dsAttrNone {
			continue
		}
		variants := []bool{attr.Kind == dsAttrValue}
		if attr.Kind == dsAttrBoth {
			variants = []bool{true, false}
		}
		for _, isValue := range variants {
			fa := genRxCached(e.Value, genRxOptions{ReturnsValue: isValue, ArgNames: attr.ArgNames})
			if j, err := jsonMarshal(fa); err == nil {
				if k := string(j); !seen[k] {
					seen[k] = true
					entries = append(entries, precompileEntry{funcArgs: fa})
				}
			}
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return p.buildSignedURLs(entries)
}

type skipKey struct{}

// Skip wraps a handler so that Middleware passes its response through without
// any processing. Use it for routes within a
// Middleware-wrapped mux that serve large HTML responses with no Datastar
// expressions, or streaming responses where buffering would be inappropriate.
// Handlers that return non-HTML content types (JSON, JS, images, …) are
// already passed through automatically and do not need Skip.
func Skip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sp, ok := r.Context().Value(skipKey{}).(*bool); ok {
			*sp = true
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware wraps a handler and automatically injects Datastar precompile
// scripts into the response. It detects the response type from the
// Content-Type header set by the handler:
//
//   - text/event-stream (SSE): intercepts datastar-patch-elements events and
//     injects a precompileUrl field so the client shim can load the precompile
//     script before Datastar applies the patch.
//   - text/html (full page): injects <script type="module" src="..."> tags before </head>.
//   - text/html (fragment): prepends a <!-- precompile-url: ... --> comment.
//   - anything else (JS, images, …): passed through.
//
// Handlers must set Content-Type explicitly before writing. Responses with no
// Content-Type header are passed through unchanged (Go's automatic content
// sniffing happens inside the underlying http.ResponseWriter, which the
// middleware intercepts before sniffing can occur).
//
// Use it in combination with NonceMiddleware to protect against expression
// injection from untrusted HTML.
func (p *Precompiler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := NonceFromContext(r.Context())
		skip := false
		r = r.WithContext(context.WithValue(r.Context(), skipKey{}, &skip))
		dw := &detectWriter{ResponseWriter: w, p: p, nonce: nonce, skip: &skip}
		next.ServeHTTP(dw, r)
		dw.flush()
	})
}

// NonceMiddleware generates a fresh cryptographic nonce for each request and
// stores it in the context. Templates retrieve it with NonceFromContext.
// Compose it with Precompiler.Middleware to enable nonce-based expression
// filtering:
//
//	NonceMiddleware(p.Middleware(mux))
func NonceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateNonce()
		next.ServeHTTP(w, r.WithContext(contextWithNonce(r.Context(), nonce)))
	})
}

// detectWriter routes to SSE or HTML processing based on the response
// Content-Type, which is inspected on the first Write or WriteHeader call.
type detectWriter struct {
	http.ResponseWriter
	p        *Precompiler
	nonce    string
	skip     *bool
	detected bool
	mode     detectMode
	buf      *bytes.Buffer // HTML mode: accumulates body
	code     int           // HTML mode: deferred status code
	sseW     *sseWriter    // SSE mode: event processor
}

type detectMode int

const (
	detectPending     detectMode = iota
	detectHTML                   // buffer and inject script tags / comment
	detectSSE                    // delegate to sseWriter
	detectPassthrough            // non-HTML, non-SSE: pass through unchanged
)

func (dw *detectWriter) detect() {
	if dw.detected {
		return
	}
	dw.detected = true
	if dw.skip != nil && *dw.skip {
		dw.mode = detectPassthrough
		return
	}
	ct := dw.ResponseWriter.Header().Get("Content-Type")
	if dw.ResponseWriter.Header().Get("Content-Encoding") != "" {
		dw.mode = detectPassthrough
		return
	}
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		dw.mode = detectSSE
		dw.sseW = &sseWriter{ResponseWriter: dw.ResponseWriter, p: dw.p, nonce: dw.nonce}
	case strings.HasPrefix(ct, "text/html"):
		dw.mode = detectHTML
		dw.buf = bufPool.Get().(*bytes.Buffer)
		dw.buf.Reset()
	default:
		dw.mode = detectPassthrough
	}
}

func (dw *detectWriter) WriteHeader(code int) {
	dw.detect()
	switch dw.mode {
	case detectSSE, detectPassthrough:
		dw.ResponseWriter.WriteHeader(code)
	default:
		dw.code = code
	}
}

func (dw *detectWriter) Write(b []byte) (int, error) {
	dw.detect()
	switch dw.mode {
	case detectSSE:
		return dw.sseW.Write(b)
	case detectPassthrough:
		return dw.ResponseWriter.Write(b)
	default:
		return dw.buf.Write(b)
	}
}

// Unwrap lets http.ResponseController reach the underlying writer for flushing.
func (dw *detectWriter) Unwrap() http.ResponseWriter {
	if dw.sseW != nil {
		return dw.sseW
	}
	return dw.ResponseWriter
}


func (dw *detectWriter) flush() {
	if dw.mode != detectHTML {
		return
	}
	defer func() {
		if dw.buf.Cap() < 256*1024 {
			bufPool.Put(dw.buf)
		}
	}()

	body := dw.buf.Bytes()
	entries := scanHTML(body, dw.nonce, dw.p.Alias)
	if len(entries) > 0 {
		if urls, err := dw.p.buildSignedURLs(entries); err == nil {
			dw.ResponseWriter.Header().Del("Content-Length")
			if modified, ok := injectIntoHead(body, nonceMeta(dw.nonce), scriptTags(urls)); ok {
				body = modified
			} else {
				// Fragment: one comment per URL, with the nonce on the first.
				var comments []byte
				for i, u := range urls {
					comment := "<!-- "
					if i == 0 && dw.nonce != "" {
						comment += "ds-nonce: " + dw.nonce + " "
					}
					comment += "precompile-url: " + u + " -->\n"
					comments = append(comments, comment...)
				}
				body = append(comments, body...)
			}
		}
	} else if dw.nonce != "" && !looksLikeFullDocument(body) {
		// No expressions but nonce is active: still tell the client the nonce
		// so elements on this fragment pass the bloom filter check.
		dw.ResponseWriter.Header().Del("Content-Length")
		comment := "<!-- ds-nonce: " + dw.nonce + " -->\n"
		body = append([]byte(comment), body...)
	}
	if dw.code != 0 {
		dw.ResponseWriter.WriteHeader(dw.code)
	}
	_, _ = dw.ResponseWriter.Write(body)
}

const (
	elementsPrefix     = "data: elements "
	patchElementsEvent = "event: datastar-patch-elements"
)

type sseWriter struct {
	http.ResponseWriter
	p     *Precompiler
	buf   bytes.Buffer
	nonce string
}

// Unwrap lets http.ResponseController reach the underlying writer for flushing.
func (sw *sseWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

func (sw *sseWriter) Write(b []byte) (int, error) {
	sw.buf.Write(b)
	for {
		data := sw.buf.Bytes()
		idx := bytes.Index(data, []byte("\n\n"))
		if idx < 0 {
			break
		}
		event := make([]byte, idx+2)
		copy(event, data[:idx+2])
		sw.buf.Next(idx + 2)
		if err := sw.processEvent(event); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (sw *sseWriter) processEvent(event []byte) error {
	if !bytes.Contains(event, []byte(patchElementsEvent)) {
		_, err := sw.ResponseWriter.Write(event)
		return err
	}

	// Reconstruct the HTML from "data: elements " lines.
	var parts []string
	for _, line := range bytes.Split(event, []byte("\n")) {
		if after, ok := bytes.CutPrefix(line, []byte(elementsPrefix)); ok {
			parts = append(parts, string(after))
		}
	}
	htmlBody := strings.Join(parts, "\n")

	// Inject the nonce so the client can register it in the bloom filter before
	// evaluating expressions on the patched elements.
	if sw.nonce != "" {
		event = bytes.Replace(event, []byte(elementsPrefix),
			[]byte("data: dsNonce "+sw.nonce+"\n"+elementsPrefix), 1)
	}

	if entries := scanHTML([]byte(htmlBody), sw.nonce, sw.p.Alias); len(entries) > 0 {
		if urls, err := sw.p.buildSignedURLs(entries); err == nil {
			// Inject precompile URLs as a single space-separated data field.
			// The client shim intercepts datastar-patch-elements events that
			// carry this field, loads each script, then re-dispatches.
			event = bytes.Replace(event, []byte(elementsPrefix),
				[]byte("data: precompileUrl "+strings.Join(urls, " ")+"\n"+elementsPrefix), 1)
		}
	}

	_, err := sw.ResponseWriter.Write(event)
	return err
}

// precompileEntry holds one precompiled function. The key used to register it
// in the Map equals funcArgs: Datastar's genRx() is deterministic per attribute
// kind, so DSAttrValue attrs always produce a body with "return (...)" and
// DSAttrStatement attrs never do.
type precompileEntry struct {
	funcArgs []string
}

func scanHTML(body []byte, nonce, alias string) []precompileEntry {
	seen := map[string]bool{}
	var results []precompileEntry

	z := html.NewTokenizer(bytes.NewReader(body))
	ignoreDepth := 0
tokenLoop:
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.EndTagToken {
			if ignoreDepth > 0 {
				ignoreDepth--
			}
			continue
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		name, _ := z.TagName()
		isVoid := tt == html.SelfClosingTagToken || voidElements[string(name)]

		// Collect all attributes before deciding what to do.
		type kv struct{ key, val string }
		var attrs []kv
		for {
			k, v, more := z.TagAttr()
			attrs = append(attrs, kv{string(k), string(v)})
			if !more {
				break
			}
		}

		if ignoreDepth > 0 {
			if !isVoid {
				ignoreDepth++
			}
			continue
		}

		// Check whether this element opts out of scanning.
		for _, a := range attrs {
			if a.key == "data-ignore" {
				if !isVoid {
					ignoreDepth++
				}
				continue tokenLoop
			}
		}

		// When a nonce is active, only process elements that carry the matching
		// data-ds-nonce attribute. This prevents expressions injected via
		// untrusted HTML from being included in the signed precompile URL.
		if nonce != "" {
			var hasNonce bool
			for _, a := range attrs {
				if a.key == "data-ds-nonce" && a.val == nonce {
					hasNonce = true
					break
				}
			}
			if !hasNonce {
				continue tokenLoop
			}
		}

		for _, a := range attrs {
			base, found := strings.CutPrefix(a.key, "data-")
			if !found {
				continue
			}
			if alias != "" {
				base, found = strings.CutPrefix(base, alias+"-")
				if !found {
					continue
				}
			}
			if i := strings.IndexByte(base, ':'); i >= 0 {
				base = base[:i]
			}
			if attr, ok := dsAttrs[base]; ok && attr.Kind != dsAttrNone {
				variants := []bool{attr.Kind == dsAttrValue}
				if attr.Kind == dsAttrBoth {
					variants = []bool{true, false}
				}
				for _, isValue := range variants {
					funcArgs := genRxCached(a.val, genRxOptions{ReturnsValue: isValue, ArgNames: attr.ArgNames})
					if primaryJSON, err := jsonMarshal(funcArgs); err == nil {
						if k := string(primaryJSON); !seen[k] {
							seen[k] = true
							results = append(results, precompileEntry{funcArgs: funcArgs})
						}
					}
				}
			}
		}

	}
	return results
}

func buildJS(entries []precompileEntry, initMap bool) []byte {
	// Group entries by their param list (all funcArgs except the body).
	// Each unique param signature gets one helper that handles the
	// p.set(JSON.stringify([...params, b]), fn) boilerplate.
	type group struct {
		name             string
		dedupedParamsCSV string
		keyPrefix        string // JSON array of params with closing ] removed
	}
	groupByKey := map[string]*group{}
	var groups []*group

	for _, entry := range entries {
		params := entry.funcArgs[:len(entry.funcArgs)-1]
		paramsJSON, err := jsonMarshal(params)
		if err != nil {
			continue
		}
		k := string(paramsJSON)
		if _, ok := groupByKey[k]; !ok {
			counts := make(map[string]int, len(params))
			for _, p := range params {
				counts[p]++
			}
			seenCount := make(map[string]int, len(params))
			deduped := make([]string, len(params))
			for i, p := range params {
				seenCount[p]++
				if seenCount[p] < counts[p] {
					deduped[i] = fmt.Sprintf("_%d%s", seenCount[p], p)
				} else {
					deduped[i] = p
				}
			}
			g := &group{
				name:             fmt.Sprintf("r%d", len(groups)),
				dedupedParamsCSV: strings.Join(deduped, ","),
				keyPrefix:        k[:len(k)-1],
			}
			groupByKey[k] = g
			groups = append(groups, g)
		}
	}

	var b strings.Builder
	if initMap {
		b.WriteString("const p=(window.__datastar_precompiled_expressions??=new Map())\n")
	} else {
		b.WriteString("const p=window.__datastar_precompiled_expressions\n")
	}
	b.WriteString("const s=(x,y)=>p.set(JSON.stringify(x),y)\n")

	// One helper per unique param signature.
	for _, g := range groups {
		b.WriteString("const ")
		b.WriteString(g.name)
		b.WriteString("=(b,fn)=>s(")
		b.WriteString(g.keyPrefix)
		b.WriteString(",b],fn)\n")
	}

	// One call per entry.
	for _, entry := range entries {
		params := entry.funcArgs[:len(entry.funcArgs)-1]
		body := entry.funcArgs[len(entry.funcArgs)-1]
		paramsJSON, err := jsonMarshal(params)
		if err != nil {
			continue
		}
		bodyJSON, err := jsonMarshal(body)
		if err != nil {
			continue
		}
		g := groupByKey[string(paramsJSON)]
		b.WriteString(g.name)
		b.WriteByte('(')
		b.Write(bodyJSON)
		b.WriteString(",(")
		b.WriteString(g.dedupedParamsCSV)
		b.WriteString(")=>{")
		b.WriteString(strings.TrimSpace(body))
		b.WriteString("})\n")
	}

	return []byte(b.String())
}

// scriptTags renders one <script type="module" src="..."> tag per URL.
func nonceMeta(nonce string) []byte {
	if nonce == "" {
		return nil
	}
	return []byte(`<meta name="datastargostrictcsp-ds-nonce" content="` + nonce + `">` + "\n")
}

func scriptTags(urls []string) []byte {
	var b bytes.Buffer
	for i, u := range urls {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(`<script type="module" src="`)
		b.WriteString(stdhtml.EscapeString(u))
		b.WriteString(`"></script>`)
	}
	return b.Bytes()
}

func looksLikeFullDocument(body []byte) bool {
	prefix := body
	if len(prefix) > 512 {
		prefix = prefix[:512]
	}
	// upper doesn't escape; stack allocation cost is negligible
	upper := bytes.ToUpper(prefix)
	return bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<HTML"))
}

// injectIntoHead inserts meta immediately before the first non-<meta> tag in
// <head> (or before </head> if head is empty/all-meta), and inserts scripts
// immediately before the first <script> tag in <head> (or before </head> if
// there are none). Either slice may be nil. If no </head> is found but a
// <body> tag is present, both are injected immediately before <body>.
// Returns (modified body, true) on success, (original body, false) otherwise.
func injectIntoHead(body, meta, scripts []byte) ([]byte, bool) {
	// Without this heuristic check, every text/html response containing an HTML
	// fragment would be fully scanned by the HTML tokenizer, which is wasteful.
	if !looksLikeFullDocument(body) {
		return body, false
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	pos := 0
	inHead := false
	metaInsertPos := -1   // before first non-<meta> tag in head; falls back to </head>
	scriptInsertPos := -1 // before first <script> tag in head; falls back to </head>
	bodyPos := -1         // fallback injection point if no </head> found
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		rawLen := len(z.Raw())
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "head":
				inHead = true
			case "body":
				if bodyPos < 0 {
					bodyPos = pos
				}
			default:
				if inHead {
					if metaInsertPos < 0 && string(name) != "meta" {
						metaInsertPos = pos
					}
					if scriptInsertPos < 0 && string(name) == "script" {
						scriptInsertPos = pos
					}
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "head" {
				if metaInsertPos < 0 {
					metaInsertPos = pos // head was empty or contained only <meta> tags
				}
				if scriptInsertPos < 0 {
					scriptInsertPos = pos // no <script> in head; fall back to before </head>
				}
				return splice(body, meta, metaInsertPos, scripts, scriptInsertPos), true
			}
		}
		pos += rawLen
	}
	// No </head> — fall back to injecting before <body>.
	if bodyPos >= 0 {
		return splice(body, meta, bodyPos, scripts, bodyPos), true
	}
	return body, false
}

// splice builds: body[:metaAt] + meta + body[metaAt:scriptsAt] + scripts + body[scriptsAt:]
func splice(body, meta []byte, metaAt int, scripts []byte, scriptsAt int) []byte {
	out := make([]byte, 0, len(body)+len(meta)+len(scripts)+2)
	if len(meta) > 0 {
		out = append(out, body[:metaAt]...)
		out = append(out, '\n')
		out = append(out, meta...)
		out = append(out, body[metaAt:scriptsAt]...)
	} else {
		out = append(out, body[:scriptsAt]...)
	}
	out = append(out, scripts...)
	out = append(out, '\n')
	out = append(out, body[scriptsAt:]...)
	return out
}

// voidElements is the set of HTML void elements that have no closing tag.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "keygen": true, "link": true,
	"meta": true, "param": true, "source": true, "track": true, "wbr": true,
}
