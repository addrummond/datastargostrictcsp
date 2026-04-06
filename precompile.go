// Package datastargostrictcsp makes the [Datastar] hypermedia framework
// compatible with strict Content Security Policies (no unsafe-eval, no
// unsafe-inline). It works by precompiling Datastar expressions on the server
// and serving them via backend-signed URLs, side-stepping the need for the
// JavaScript Function constructor at runtime.
//
// Basic usage: mount [Precompiler.ScriptHandler] at a fixed path, then wrap
// your mux with [Precompiler.Middleware] (or [Precompiler.MiddlewareWithNonce]
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
	ScriptPath string
	MaxURLLen  int
}

func (p *Precompiler) scriptPath() string {
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

// NonceFromContext retrieves the per-request nonce stored by MiddlewareWithNonce.
// Returns an empty string if none is set.
func NonceFromContext(ctx context.Context) string {
	n, _ := ctx.Value(nonceContextKey{}).(string)
	return n
}

// sign encodes funcArgs as a self-contained token:
//
//	<base64url(JSON(funcArgs))>.<base64url(HMAC-SHA256(payload)[:12])>
func (p *Precompiler) sign(funcArgs []string) (string, error) {
	if p.Key == [32]byte{} {
		return "", errZeroKey
	}
	payload, err := json.Marshal(funcArgs)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, p.Key[:])
	mac.Write(payload)
	sig := mac.Sum(nil)[:12]
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// verify checks the token signature and returns the funcArgs on success.
// It tries Key first, then each entry in OldKeys.
func (p *Precompiler) verify(e string) ([]string, error) {
	if p.Key == [32]byte{} {
		return nil, errZeroKey
	}
	dot := strings.LastIndexByte(e, '.')
	if dot < 0 {
		return nil, errors.New("missing separator")
	}
	payload, err := base64.RawURLEncoding.DecodeString(e[:dot])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(e[dot+1:])
	if err != nil {
		return nil, err
	}
	keys := append([][32]byte{p.Key}, p.OldKeys...)
	var matched bool
	for _, k := range keys {
		mac := hmac.New(sha256.New, k[:])
		mac.Write(payload)
		if hmac.Equal(sig, mac.Sum(nil)[:12]) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, errors.New("invalid signature")
	}
	var funcArgs []string
	if err := json.Unmarshal(payload, &funcArgs); err != nil {
		return nil, err
	}
	return funcArgs, nil
}

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// ScriptHandler returns an http.Handler that verifies signed expression
// parameters and serves a cacheable JS file that registers the corresponding
// functions.
func (p *Precompiler) ScriptHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		eParams := q["e"]
		entries := make([]precompileEntry, 0, len(eParams))
		for _, e := range eParams {
			funcArgs, err := p.verify(e)
			if err != nil {
				http.Error(w, "invalid signature", http.StatusBadRequest)
				return
			}
			entries = append(entries, precompileEntry{funcArgs: funcArgs})
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(buildJS(entries, q.Get("n")))
	})
}

// buildSignedURLs returns one or more signed script URLs for entries. When the
// query string would exceed MaxURLLen the entries are split across multiple
// URLs; all of them write into the same window.__datastar_precompiled_expressions
// map so the JS composes cleanly. A single entry that by itself exceeds the
// limit is emitted as its own URL rather than silently dropped.
func (p *Precompiler) buildSignedURLs(entries []precompileEntry, nonce string) ([]string, error) {
	base := p.scriptPath() + "?"
	maxLen := p.maxURLLen()

	var urls []string
	var chunk []string

	flush := func() {
		q := url.Values{"e": chunk}
		if nonce != "" {
			q.Set("n", nonce)
		}
		urls = append(urls, base+q.Encode())
		chunk = nil
	}

	for _, entry := range entries {
		e, err := p.sign(entry.funcArgs)
		if err != nil {
			return nil, err
		}
		if len(chunk) > 0 {
			q := url.Values{"e": append(append([]string{}, chunk...), e)}
			if nonce != "" {
				q.Set("n", nonce)
			}
			if len(base)+len(q.Encode()) > maxLen {
				flush()
			}
		}
		chunk = append(chunk, e)
	}
	if len(chunk) > 0 {
		flush()
	}
	return urls, nil
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
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), skipKey{}, true)))
	})
}

// Middleware wraps a handler and automatically injects Datastar precompile
// scripts into the response. It detects the response type from the
// Content-Type header set by the handler:
//
//   - text/event-stream (SSE): intercepts datastar-patch-elements events and
//     injects a precompileUrl field so the client shim can load the precompile
//     script before Datastar applies the patch.
//   - text/html (full page): injects <script src="..."> tags before </head>.
//   - text/html (fragment): prepends a <!-- precompile-url: ... --> comment.
//   - anything else (JS, images, …): passed through.
//
// A single Middleware wrapping the whole mux is sufficient; there is no need
// to distinguish between HTML and SSE routes. Wrap individual handlers with
// Skip to opt specific routes out of processing.
//
// Use MiddlewareWithNonce to automatically generate and inject a per-request
// nonce.
func (p *Precompiler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(skipKey{}) != nil {
			next.ServeHTTP(w, r)
			return
		}
		nonce := NonceFromContext(r.Context())
		dw := &detectWriter{ResponseWriter: w, p: p, nonce: nonce}
		next.ServeHTTP(dw, r)
		dw.flush()
	})
}

// MiddlewareWithNonce is like Middleware, but generates a fresh nonce for each
// request and stores it in the request context. Templates can retrieve it with
// NonceFromContext(r.Context()).
func (p *Precompiler) MiddlewareWithNonce(next http.Handler) http.Handler {
	inner := p.Middleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateNonce()
		inner.ServeHTTP(w, r.WithContext(contextWithNonce(r.Context(), nonce)))
	})
}

// detectWriter routes to SSE or HTML processing based on the response
// Content-Type, which is inspected on the first Write or WriteHeader call.
type detectWriter struct {
	http.ResponseWriter
	p        *Precompiler
	nonce    string
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
	ct := dw.ResponseWriter.Header().Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		dw.mode = detectSSE
		dw.sseW = &sseWriter{ResponseWriter: dw.ResponseWriter, p: dw.p, nonce: dw.nonce}
	case ct == "" || strings.HasPrefix(ct, "text/html"):
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
	if entries := scanHTML(body, dw.nonce); len(entries) > 0 {
		if urls, err := dw.p.buildSignedURLs(entries, dw.nonce); err == nil {
			dw.ResponseWriter.Header().Del("Content-Length")
			if modified, ok := injectBeforeHeadClose(body, scriptTags(urls)); ok {
				body = modified
			} else {
				comment := "<!-- precompile-url: " + strings.Join(urls, " ") + " -->\n"
				body = append([]byte(comment), body...)
			}
		}
	}
	if dw.code != 0 {
		dw.ResponseWriter.WriteHeader(dw.code)
	}
	dw.ResponseWriter.Write(body)
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
	html := strings.Join(parts, "\n")

	if entries := scanHTML([]byte(html), sw.nonce); len(entries) > 0 {
		if urls, err := sw.p.buildSignedURLs(entries, sw.nonce); err == nil {
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

func scanHTML(body []byte, nonce string) []precompileEntry {
	seen := map[string]bool{}
	var results []precompileEntry

	z := html.NewTokenizer(bytes.NewReader(body))
	ignoreDepth := 0
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
				goto nextToken
			}
		}

		// When a nonce is active, only process elements that carry the matching
		// data-ds-nonce attribute. This prevents expressions injected via
		// untrusted HTML (e.g. via innerHTML from user input) from being
		// included in the signed precompile URL.
		if nonce != "" {
			var hasNonce bool
			for _, a := range attrs {
				if a.key == "data-ds-nonce" && a.val == nonce {
					hasNonce = true
					break
				}
			}
			if !hasNonce {
				goto nextToken
			}
		}

		for _, a := range attrs {
			base, found := strings.CutPrefix(a.key, "data-")
			if !found {
				continue
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
					if primaryJSON, err := json.Marshal(funcArgs); err == nil {
						if k := string(primaryJSON); !seen[k] {
							seen[k] = true
							results = append(results, precompileEntry{funcArgs: funcArgs})
						}
					}
				}
			}
		}

	nextToken:
	}
	return results
}

func buildJS(entries []precompileEntry, nonce string) []byte {
	// Group entries by their param list (all funcArgs except the body).
	// Each unique param signature gets one helper that handles the
	// p.set(JSON.stringify([...params, b]), fn) boilerplate.
	type group struct {
		name      string
		paramsCSV string
		keyPrefix string // JSON array of params with closing ] removed
	}
	groupByKey := map[string]*group{}
	var groups []*group

	for _, entry := range entries {
		params := entry.funcArgs[:len(entry.funcArgs)-1]
		paramsJSON, err := json.Marshal(params)
		if err != nil {
			continue
		}
		k := string(paramsJSON)
		if _, ok := groupByKey[k]; !ok {
			g := &group{
				name:      fmt.Sprintf("r%d", len(groups)),
				paramsCSV: strings.Join(params, ","),
				keyPrefix: k[:len(k)-1],
			}
			groupByKey[k] = g
			groups = append(groups, g)
		}
	}

	var b strings.Builder
	b.WriteString("(function(){\n")
	if nonce != "" {
		nonceJSON, _ := json.Marshal(nonce)
		b.WriteString("window.__ds_bloom_add&&window.__ds_bloom_add(")
		b.Write(nonceJSON)
		b.WriteString(");\n")
	}
	b.WriteString("const p=window.__datastar_precompiled_expressions=window.__datastar_precompiled_expressions||new Map();\nfunction s(x,y){return p.set(JSON.stringify(x),y)}\n")

	// One helper per unique param signature.
	for _, g := range groups {
		b.WriteString("function ")
		b.WriteString(g.name)
		b.WriteString("(b,fn){s(")
		b.WriteString(g.keyPrefix)
		b.WriteString(",b],fn)}\n")
	}

	// One call per entry.
	for _, entry := range entries {
		params := entry.funcArgs[:len(entry.funcArgs)-1]
		body := entry.funcArgs[len(entry.funcArgs)-1]
		paramsJSON, err := json.Marshal(params)
		if err != nil {
			continue
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			continue
		}
		g := groupByKey[string(paramsJSON)]
		b.WriteString(g.name)
		b.WriteByte('(')
		b.Write(bodyJSON)
		b.WriteString(",function(")
		b.WriteString(g.paramsCSV)
		b.WriteString("){")
		b.WriteString(body)
		b.WriteString("})\n")
	}

	b.WriteString("})()")
	return []byte(b.String())
}

// scriptTags renders one <script src="..."> tag per URL.
func scriptTags(urls []string) []byte {
	var b bytes.Buffer
	for i, u := range urls {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(`<script src="`)
		b.WriteString(u)
		b.WriteString(`"></script>`)
	}
	return b.Bytes()
}

func looksLikeFullDocument(body []byte) bool {
	prefix := body
	if len(prefix) > 512 {
		prefix = prefix[:512]
	}
	upper := bytes.ToUpper(prefix)
	return bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<HTML"))
}

// injectBeforeHeadClose inserts script immediately before the closing </head> tag.
// Returns (modified body, true) if </head> was found, (original body, false) otherwise.
func injectBeforeHeadClose(body, script []byte) ([]byte, bool) {
	if !looksLikeFullDocument(body) {
		return body, false
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	pos := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		rawLen := len(z.Raw())
		if tt == html.EndTagToken {
			name, _ := z.TagName()
			if string(name) == "head" {
				out := make([]byte, 0, len(body)+len(script)+2)
				out = append(out, body[:pos]...)
				out = append(out, script...)
				out = append(out, '\n')
				out = append(out, body[pos:]...)
				return out, true
			}
		}
		pos += rawLen
	}
	return body, false
}

// voidElements is the set of HTML void elements that have no closing tag.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "keygen": true, "link": true,
	"meta": true, "param": true, "source": true, "track": true, "wbr": true,
}
