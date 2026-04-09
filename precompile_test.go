package datastargostrictcsp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dscsp "github.com/addrummond/datastargostrictcsp"
)

func testPrecompiler(t *testing.T) *dscsp.Precompiler {
	t.Helper()
	var p dscsp.Precompiler
	for i := range p.Key {
		p.Key[i] = byte(i + 1)
	}
	return &p
}

func TestNonceFromContext_EmptyByDefault(t *testing.T) {
	if got := dscsp.NonceFromContext(context.Background()); got != "" {
		t.Errorf("expected empty string from bare context, got %q", got)
	}
}

func TestMiddlewareWithNonce_SetsNonceInContext(t *testing.T) {
	p := testPrecompiler(t)
	var got string
	handler := dscsp.NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = dscsp.NonceFromContext(r.Context())
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

	handler := dscsp.NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := dscsp.NonceFromContext(r.Context())
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

	handler := dscsp.NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Element has a DS attr but no matching nonce attribute
		w.Write([]byte(`<html><head></head><body><div data-text="x"></div></body></html>`))
	})))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("unexpected <script> when no elements match nonce; body:\n%s", rec.Body)
	}
}

func TestMiddleware_ZeroKey_PassesThroughUnchanged(t *testing.T) {
	var p dscsp.Precompiler // zero key

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
func scriptURLFromPage(t *testing.T, p *dscsp.Precompiler, body string) string {
	t.Helper()
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	return page[i : i+j]
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
	url := scriptURLFromPage(t, p, `<div data-text="x"></div>`)

	// Flip a byte in the signature (after the last dot)
	dot := strings.LastIndex(url, ".")
	tampered := url[:dot+1] + "AAAAAAAAAAAAAAAA"

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
	pageHandler := dscsp.NonceMiddleware(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = dscsp.NonceFromContext(r.Context())
		w.Write([]byte(`<html><head></head><body>` +
			`<div data-text="x" data-ds-nonce="` + capturedNonce + `"></div>` +
			`</body></html>`))
	})))

	rec := httptest.NewRecorder()
	pageHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	page := rec.Body.String()

	i := strings.Index(page, `src="`)
	if i < 0 {
		t.Fatal("no script tag found in page; body:\n" + page)
	}
	i += 5
	url := page[i : i+strings.Index(page[i:], `"`)]

	rec2 := httptest.NewRecorder()
	p.ScriptHandler().ServeHTTP(rec2, httptest.NewRequest("GET", url, nil))

	js := rec2.Body.String()
	if !strings.Contains(js, "__ds_bloom_add") {
		t.Errorf("expected bloom add call in JS;\ngot: %s", js)
	}
	if !strings.Contains(js, `querySelector('meta[name="datastargostrictcsp-ds-nonce"]')`) {
		t.Errorf("expected meta tag nonce read in JS bloom call;\ngot: %s", js)
	}
}

func TestScriptHandler_WrongKeyRejectsToken(t *testing.T) {
	p1 := testPrecompiler(t)
	url := scriptURLFromPage(t, p1, `<div data-text="x"></div>`)

	// Different key
	var p2 dscsp.Precompiler
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
