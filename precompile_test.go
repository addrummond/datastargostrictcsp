package datastargostrictcsp

import (
	"context"
	"encoding/base64"
	stdhtml "html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testPrecompiler(t *testing.T) *Precompiler {
	t.Helper()
	var p Precompiler
	for i := range p.Key {
		p.Key[i] = byte(i + 1)
	}
	return &p
}

func TestNonceFromContext_EmptyByDefault(t *testing.T) {
	if got := NonceFromContext(context.Background()); got != "" {
		t.Errorf("expected empty string from bare context, got %q", got)
	}
}

func TestMiddlewareWithNonce_SetsNonceInContext(t *testing.T) {
	p := testPrecompiler(t)
	var got string
	handler := NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = NonceFromContext(r.Context())
		w.Write([]byte(`<p>hi</p>`))
	})))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if got == "" {
		t.Error("expected non-empty nonce in context from MiddlewareWithNonce")
	}
}

func TestMiddleware_FullPage_NoExpressions(t *testing.T) {
	p := testPrecompiler(t)

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><p>no datastar here</p></body></html>`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("unexpected <script> tag in response with no DS expressions:\n%s", rec.Body)
	}
}

func TestMiddleware_FullPage_InjectsScriptBeforeHeadClose(t *testing.T) {
	p := testPrecompiler(t)

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-text="mySignal"></div></body></html>`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	scriptIdx := strings.Index(body, "<script")
	headCloseIdx := strings.Index(body, "</head>")
	if scriptIdx < 0 {
		t.Fatalf("no <script> tag injected; body:\n%s", body)
	}
	if scriptIdx > headCloseIdx {
		t.Errorf("<script> appears after </head>; body:\n%s", body)
	}
	if !strings.Contains(body, `src="/ds-precompile.js?`) {
		t.Errorf("script src doesn't point to precompile handler; body:\n%s", body)
	}
}

func TestMiddleware_FullPage_CustomScriptPath(t *testing.T) {
	p := testPrecompiler(t)
	p.ScriptPath = "/custom/precompile.js"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-text="x"></div></body></html>`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `src="/custom/precompile.js?`) {
		t.Errorf("expected custom script path in src; body:\n%s", rec.Body)
	}
}

func TestMiddleware_Fragment_PrependsComment(t *testing.T) {
	p := testPrecompiler(t)

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<div data-text="mySignal"></div>`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.HasPrefix(body, "<!-- precompile-url:") {
		t.Errorf("fragment response should start with <!-- precompile-url: ... -->;\ngot: %q", body)
	}
}

func TestMiddleware_WithNonce_OnlyMatchingElementsCompiled(t *testing.T) {
	p := testPrecompiler(t)

	handler := NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := NonceFromContext(r.Context())
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body>` +
			`<div data-text="signalA" data-ds-nonce="` + nonce + `"></div>` +
			`<div data-text="signalB"></div>` +
			`</body></html>`))
	})))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "<script") {
		t.Fatalf("expected <script> for matching nonce element; body:\n%s", body)
	}
	if !strings.Contains(body, `<meta name="datastargostrictcsp-ds-nonce"`) {
		t.Errorf("expected datastargostrictcsp-ds-nonce meta tag in page; body:\n%s", body)
	}
}

func TestMiddleware_WithNonce_NoMatchingElements(t *testing.T) {
	p := testPrecompiler(t)

	handler := NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Element has a DS attr but no matching nonce attribute
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-text="x"></div></body></html>`))
	})))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("unexpected <script> when no elements match nonce; body:\n%s", rec.Body)
	}
}

func TestMiddleware_NoContentType_PassesThroughUnchanged(t *testing.T) {
	p := testPrecompiler(t)

	const htmlBody = `<html><head></head><body><div data-text="x"></div></body></html>`
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately no Content-Type header.
		w.Write([]byte(htmlBody))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("response with no Content-Type should not be processed;\nbody: %s", rec.Body)
	}
	if rec.Body.String() != htmlBody {
		t.Errorf("body should be unchanged;\ngot: %s\nwant: %s", rec.Body, htmlBody)
	}
}

func TestMiddleware_ZeroKey_PassesThroughUnchanged(t *testing.T) {
	var p Precompiler // zero key

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-text="x"></div></body></html>`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("zero-key Precompiler should not inject script tags; body:\n%s", rec.Body)
	}
}

// scriptURLFromPage runs Middleware against a page containing the given body
// HTML and returns the first script src URL injected.
func scriptURLFromPage(t *testing.T, p *Precompiler, body string) string {
	t.Helper()
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body>` + body + `</body></html>`))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	page := rec.Body.String()
	i := strings.Index(page, `src="`)
	if i < 0 {
		t.Fatal("no script tag found in page; body:\n" + page)
	}
	i += 5
	j := strings.Index(page[i:], `"`)
	return stdhtml.UnescapeString(page[i : i+j])
}

func TestMiddleware_Alias_RecognisesAliasedAttributes(t *testing.T) {
	p := testPrecompiler(t)
	p.Alias = "ds"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-ds-text="mySignal"></div></body></html>`))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if !strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("aliased attribute should produce a script tag;\nbody: %s", rec.Body)
	}
}

func TestMiddleware_Alias_StandardAttributesIgnoredWhenAliasSet(t *testing.T) {
	p := testPrecompiler(t)
	p.Alias = "ds"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-text="mySignal"></div></body></html>`))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("standard (non-aliased) attribute should be ignored when alias is set;\nbody: %s", rec.Body)
	}
}

func TestMiddleware_Alias_UnknownPrefixNotRecognized(t *testing.T) {
	p := testPrecompiler(t)
	p.Alias = "myalias"

	// data-other-text uses a different prefix — should not be compiled.
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div data-other-text="someSignal"></div></body></html>`))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("unrecognized prefix should not produce a script tag;\nbody: %s", rec.Body)
	}
}

func TestScriptHandler_ValidToken(t *testing.T) {
	p := testPrecompiler(t)
	url := scriptURLFromPage(t, p, `<div data-text="mySignal"></div>`)

	req := httptest.NewRequest("GET", url, nil)
	rec := httptest.NewRecorder()
	p.ScriptHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("expected JS content type, got %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("expected immutable cache header, got %q", cc)
	}
	// The compiled function body for data-text="mySignal" includes "mySignal"
	if !strings.Contains(rec.Body.String(), "mySignal") {
		t.Errorf("JS output should contain expression body;\ngot: %s", rec.Body)
	}
}

func TestScriptHandler_InvalidToken(t *testing.T) {
	p := testPrecompiler(t)

	req := httptest.NewRequest("GET", "/ds-precompile.js?e=notavalidtoken", nil)
	rec := httptest.NewRecorder()
	p.ScriptHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestScriptHandler_TamperedToken(t *testing.T) {
	p := testPrecompiler(t)
	rawURL := scriptURLFromPage(t, p, `<div data-text="x"></div>`)

	// Replace the sig param value with an invalid one.
	sigIdx := strings.Index(rawURL, "&sig=")
	if sigIdx < 0 {
		t.Fatal("no &sig= param found in URL: " + rawURL)
	}
	tampered := rawURL[:sigIdx] + "&sig=AAAAAAAAAAAAAAAA"

	req := httptest.NewRequest("GET", tampered, nil)
	rec := httptest.NewRecorder()
	p.ScriptHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for tampered token, got %d", rec.Code)
	}
}

func TestScriptHandler_WithNonce_EmitsBloomAdd(t *testing.T) {
	p := testPrecompiler(t)

	var capturedNonce string
	pageHandler := NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = NonceFromContext(r.Context())
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body>` +
			`<div data-text="x" data-ds-nonce="` + capturedNonce + `"></div>` +
			`</body></html>`))
	})))

	rec := httptest.NewRecorder()
	pageHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	page := rec.Body.String()

	if !strings.Contains(page, `src="`) {
		t.Fatal("no script tag found in page; body:\n" + page)
	}
	if !strings.Contains(page, `<meta name="datastargostrictcsp-ds-nonce"`) {
		t.Errorf("expected datastargostrictcsp-ds-nonce meta tag in page; body:\n%s", page)
	}
}

func TestScriptHandler_WrongKeyRejectsToken(t *testing.T) {
	p1 := testPrecompiler(t)
	url := scriptURLFromPage(t, p1, `<div data-text="x"></div>`)

	// Different key
	var p2 Precompiler
	for i := range p2.Key {
		p2.Key[i] = 0xff
	}

	req := httptest.NewRequest("GET", url, nil)
	rec := httptest.NewRecorder()
	p2.ScriptHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when verifying with wrong key, got %d", rec.Code)
	}
}

func TestScriptHandler_FirstURLHasInitParam(t *testing.T) {
	p := testPrecompiler(t)

	// Single URL: must carry &i=1.
	url := scriptURLFromPage(t, p, `<div data-text="sig"></div>`)
	if !strings.Contains(url, "&i=1") {
		t.Errorf("first (and only) URL should carry &i=1; got: %s", url)
	}

	// Fetch with i=1: output must contain the map initialisation line.
	rec := httptest.NewRecorder()
	p.ScriptHandler().ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "window.__datastar_precompiled_expressions??=new Map()") {
		t.Errorf("script with i=1 should include map init; got:\n%s", rec.Body)
	}

	// Fetch without i=1: output must NOT contain the map initialisation line.
	noInit := strings.ReplaceAll(url, "&i=1", "")
	rec2 := httptest.NewRecorder()
	p.ScriptHandler().ServeHTTP(rec2, httptest.NewRequest("GET", noInit, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 without i=1, got %d", rec2.Code)
	}
	if strings.Contains(rec2.Body.String(), "??=new Map()") {
		t.Errorf("script without i=1 should not include map init; got:\n%s", rec2.Body)
	}
}

func TestSSEMiddleware_NonPatchEventPassesThrough(t *testing.T) {
	p := testPrecompiler(t)
	const event = "event: datastar-patch-signals\ndata: signals {foo:1}\n\n"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(event))
	}))

	req := httptest.NewRequest("POST", "/sse", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != event {
		t.Errorf("non-patch event should pass through unchanged\ngot:  %q\nwant: %q", got, event)
	}
}

func TestSSEMiddleware_PatchElementsInjectsPrecompileUrl(t *testing.T) {
	p := testPrecompiler(t)
	const event = "event: datastar-patch-elements\ndata: elements <div data-text=\"mySignal\"></div>\n\n"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(event))
	}))

	req := httptest.NewRequest("POST", "/sse", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Body.String()
	if !strings.Contains(got, "data: precompileUrl") {
		t.Errorf("expected precompileUrl field in SSE event\ngot: %q", got)
	}
	if !strings.Contains(got, "data: elements") {
		t.Errorf("original elements field should still be present\ngot: %q", got)
	}
}

func TestSSEMiddleware_PatchElementsNoExpressions_PassesThrough(t *testing.T) {
	p := testPrecompiler(t)
	const event = "event: datastar-patch-elements\ndata: elements <div class=\"plain\"></div>\n\n"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(event))
	}))

	req := httptest.NewRequest("POST", "/sse", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Body.String()
	if strings.Contains(got, "precompileUrl") {
		t.Errorf("expected no precompileUrl for element with no DS expressions\ngot: %q", got)
	}
}

func TestSSEMiddleware_MultipleEventsInOneBatch(t *testing.T) {
	p := testPrecompiler(t)
	signals := "event: datastar-patch-signals\ndata: signals {x:1}\n\n"
	patch := "event: datastar-patch-elements\ndata: elements <div data-text=\"sig\"></div>\n\n"

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(signals + patch))
	}))

	req := httptest.NewRequest("POST", "/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Body.String()
	if !strings.Contains(got, "datastar-patch-signals") {
		t.Errorf("signals event should be present\ngot: %q", got)
	}
	if !strings.Contains(got, "data: precompileUrl") {
		t.Errorf("precompileUrl should be injected into patch event\ngot: %q", got)
	}
}

func TestInjectIntoHead(t *testing.T) {
	meta := []byte(`<meta name="x" content="nonce">`)
	scripts := []byte(`<script src="precompile.js"></script>`)

	tests := []struct {
		name             string
		input            string
		wantMetaBefore   string
		wantMetaAfter    string
		wantScriptBefore string
		wantOK           bool
	}{
		{
			name:             "meta and scripts both injected before first script in head",
			input:            `<html><head><script src="client.js"></script></head><body></body></html>`,
			wantMetaBefore:   `<script src="client.js">`,
			wantScriptBefore: `<script src="client.js">`,
			wantOK:           true,
		},
		{
			name:             "scripts injected before first script, meta before first non-meta",
			input:            `<html><head><link rel="stylesheet" href="x.css"><script src="app.js"></script></head><body></body></html>`,
			wantMetaBefore:   `<link rel="stylesheet"`,
			wantScriptBefore: `<script src="app.js">`,
			wantOK:           true,
		},
		{
			name:             "meta inserted after existing meta tags, before first non-meta",
			input:            `<html><head><meta charset="UTF-8"><title>T</title></head><body></body></html>`,
			wantMetaAfter:    `<meta charset="UTF-8">`,
			wantMetaBefore:   `<title>T</title>`,
			wantScriptBefore: `</head>`,
			wantOK:           true,
		},
		{
			name:             "empty head: both inserted before </head>",
			input:            `<html><head></head><body></body></html>`,
			wantMetaBefore:   `</head>`,
			wantScriptBefore: `</head>`,
			wantOK:           true,
		},
		{
			name:             "head contains only meta tags: inserted before </head>",
			input:            `<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"></head><body></body></html>`,
			wantMetaAfter:    `<meta name="viewport" content="width=device-width">`,
			wantMetaBefore:   `</head>`,
			wantScriptBefore: `</head>`,
			wantOK:           true,
		},
		{
			name:             "no </head> but <body> present: both injected before <body>",
			input:            `<html><body><p>hi</p></body></html>`,
			wantMetaBefore:   `<body>`,
			wantScriptBefore: `<body>`,
			wantOK:           true,
		},
		{
			name:   "no </head> and no <body>: no injection",
			input:  `<html><p>hi</p></html>`,
			wantOK: false,
		},
		{
			name:   "fragment (not a full document): no injection",
			input:  `<div><p>hi</p></div>`,
			wantOK: false,
		},
		{
			name:             "doctype triggers full-document detection",
			input:            `<!DOCTYPE html><html><head></head><body></body></html>`,
			wantMetaBefore:   `</head>`,
			wantScriptBefore: `</head>`,
			wantOK:           true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := injectIntoHead([]byte(tc.input), meta, scripts)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v, want %v; output: %s", ok, tc.wantOK, out)
			}
			if !ok {
				return
			}
			s := string(out)
			metaStr := string(meta)
			scriptStr := string(scripts)

			metaIdx := strings.Index(s, metaStr)
			if metaIdx < 0 {
				t.Fatalf("meta not found in output: %s", s)
			}
			scriptIdx := strings.Index(s, scriptStr)
			if scriptIdx < 0 {
				t.Fatalf("scripts not found in output: %s", s)
			}

			if tc.wantMetaBefore != "" {
				if i := strings.Index(s, tc.wantMetaBefore); i < 0 {
					t.Errorf("wantMetaBefore %q not found in output", tc.wantMetaBefore)
				} else if metaIdx > i {
					t.Errorf("meta appears after %q in output:\n%s", tc.wantMetaBefore, s)
				}
			}
			if tc.wantMetaAfter != "" {
				if i := strings.Index(s, tc.wantMetaAfter); i < 0 {
					t.Errorf("wantMetaAfter %q not found in output", tc.wantMetaAfter)
				} else if metaIdx < i+len(tc.wantMetaAfter) {
					t.Errorf("meta appears before end of %q in output:\n%s", tc.wantMetaAfter, s)
				}
			}
			if tc.wantScriptBefore != "" {
				if i := strings.Index(s, tc.wantScriptBefore); i < 0 {
					t.Errorf("wantScriptBefore %q not found in output", tc.wantScriptBefore)
				} else if scriptIdx > i {
					t.Errorf("scripts appear after %q in output:\n%s", tc.wantScriptBefore, s)
				}
			}
		})
	}
}

// buildEntriesOfSize returns n precompileEntries whose combined e= URL
// contribution is approximately targetBytes bytes each (useful for splitting tests).
func buildEntriesOfSize(n, bodyLen int) []precompileEntry {
	entries := make([]precompileEntry, n)
	for i := range entries {
		body := strings.Repeat("x", bodyLen)
		entries[i] = precompileEntry{funcArgs: []string{"el", "$", "__action", "evt", body}}
	}
	return entries
}

func TestBuildSignedURLs_SingleURL_FitsWithinLimit(t *testing.T) {
	p := testPrecompiler(t)
	p.MaxURLLen = 2000

	entries := buildEntriesOfSize(1, 50)
	urls, err := p.buildSignedURLs(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(urls), urls)
	}
	if len(urls[0]) > p.MaxURLLen {
		t.Errorf("URL length %d exceeds MaxURLLen %d", len(urls[0]), p.MaxURLLen)
	}
}

func TestBuildSignedURLs_SplitsWhenLimitExceeded(t *testing.T) {
	p := testPrecompiler(t)
	p.MaxURLLen = 300 // small limit to force splitting

	// Each entry encodes a body string long enough that two of them
	// together would exceed 300 bytes but one fits comfortably.
	entries := buildEntriesOfSize(4, 30)
	urls, err := p.buildSignedURLs(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) < 2 {
		t.Fatalf("expected multiple URLs due to splitting, got %d: %v", len(urls), urls)
	}
	for i, u := range urls {
		// The &i=1 suffix is not part of the signed payload so subtract it when
		// checking the limit for the first URL.
		checkLen := len(u)
		if i == 0 {
			checkLen -= len("&i=1")
		}
		if checkLen > p.MaxURLLen {
			t.Errorf("URL[%d] length %d exceeds MaxURLLen %d: %s", i, checkLen, p.MaxURLLen, u)
		}
		if i == 0 && !strings.HasSuffix(u, "&i=1") {
			t.Errorf("first URL should end with &i=1; got: %s", u)
		}
		if i > 0 && strings.Contains(u, "&i=1") {
			t.Errorf("non-first URL[%d] should not contain &i=1; got: %s", i, u)
		}
	}
}

func TestBuildSignedURLs_OversizeEntryEmittedAlone(t *testing.T) {
	p := testPrecompiler(t)
	p.MaxURLLen = 100 // tiny limit — even one entry won't fit

	entries := buildEntriesOfSize(1, 200)
	urls, err := p.buildSignedURLs(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The single entry must still be emitted even though it exceeds the limit.
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL for oversized single entry, got %d", len(urls))
	}
}

func TestBuildSignedURLs_AllExpressionsPresent(t *testing.T) {
	p := testPrecompiler(t)
	p.MaxURLLen = 300

	bodies := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	entries := make([]precompileEntry, len(bodies))
	for i, b := range bodies {
		entries[i] = precompileEntry{funcArgs: []string{"el", "$", "__action", "evt", b}}
	}

	urls, err := p.buildSignedURLs(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Collect all decoded e= payloads across all URLs.
	var allPayloads []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("could not parse URL %q: %v", u, err)
		}
		for _, eVal := range parsed.Query()["e"] {
			decoded, err := base64.RawURLEncoding.DecodeString(eVal)
			if err != nil {
				t.Fatalf("could not base64-decode e= value %q: %v", eVal, err)
			}
			allPayloads = append(allPayloads, string(decoded))
		}
	}

	// Verify every body appears in the decoded payloads.
	for _, body := range bodies {
		found := false
		for _, payload := range allPayloads {
			if strings.Contains(payload, body) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expression body %q not found in any decoded e= payload", body)
		}
	}
}

func TestBuildSignedURLs_EmptyEntries_ReturnsNil(t *testing.T) {
	p := testPrecompiler(t)
	urls, err := p.buildSignedURLs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected no URLs for empty entries, got %v", urls)
	}
}

func TestSkip_PreventsMidllewareBuffering(t *testing.T) {
	p := testPrecompiler(t)

	// A handler with Datastar expressions wrapped in Skip.
	const htmlBody = `<html><head></head><body><div data-text="mySignal"></div></body></html>`
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlBody))
	})

	// Simulate the real-world layout: Middleware wraps the mux, Skip wraps the inner handler.
	mux := http.NewServeMux()
	mux.Handle("GET /page", Skip(inner))
	handler := p.Middleware(mux)

	req := httptest.NewRequest("GET", "/page", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("Skip should prevent script injection; body:\n%s", rec.Body)
	}
	if rec.Body.String() != htmlBody {
		t.Errorf("body should be unchanged;\ngot:  %s\nwant: %s", rec.Body, htmlBody)
	}
}
