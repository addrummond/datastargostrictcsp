# datastar-go-strict-csp

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)
![Datastar](https://img.shields.io/badge/Datastar-1.0.0--RC.8-blueviolet?style=flat)
[![Go Reference](https://pkg.go.dev/badge/github.com/addrummond/datastargostrictcsp.svg)](https://pkg.go.dev/github.com/addrummond/datastargostrictcsp)

A Go package that makes [Datastar](https://data-star.dev/) compatible with strict [Content Security Policies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP).

**No `unsafe-eval`**.

**No `unsafe-inline`**.

**2.0KB** minified client-side JS.

🚧 **Not officially supported. Not tested with Datastar Pro.**

---

## How does it work?

Datastar compiles expressions down to invocations of the JavaScript `Function` constructor, e.g.:
```js
new Function("el", "$", "__action", "evt", "return el.id")
```

This module sidesteps that with a Go precompiler:

1. **Reimplements** Datastar's expression compiler in Go (~150 LOC).
2. **Middleware** scans HTML pages/fragments and collates Datastar expressions (respecting the `data-ignore` attribute).
3. A **signed URL** keyed by the relevant expressions is delivered to the client together with the HTML.
4. **A GET request** to the signed URL returns a JavaScript source file with a compiled expression lookup table.
5. The **`Function`** constructor is monkey patched to use the lookup table.

The signed URL reaches the client in one of three ways:

| Context | Delivery method |
|---|---|
| Full HTML document | `<script src="$URL">` injected before `</head>` |
| SSE (`datastar-patch-elements`) | `data: precompileUrl <url>` field injected; client library intercepts `datastar-fetch`, loads script, then re-dispatches |
| Non-SSE HTML fragment | `<!-- precompile-url: <url> -->` prepended; client library strips comment, loads script, then re-dispatches |

**URL length:** Signed URLs can carry many expressions in query params. If a URL would exceed 2000 bytes, the server automatically splits it into multiple URLs. (An individual Datastar expression cannot be split across multiple URLs, so don't write ludicrously humungous expressions.)

## Getting started

**1.** Add a Content Security Policy **without** `unsafe-inline` or `unsafe-eval`.

**2.** Load `dist/datastargostrictcsp-client.lite.js` via a plain `<script>` tag (not `type="module"`, `defer`, or `async`) and place it **before** the Datastar `<script type="module">` tag. Classic scripts execute before module scripts, which is how event listener ordering is guaranteed.

**3.** Generate a persistent 32-byte signing key (or in dev, generate a random key on start up).

**4.** Mount the script handler and wrap your whole mux with `Middleware`.

```go
pc := &datastargostrictcsp.Precompiler{}
if _, err := rand.Read(pc.Key[:]); err != nil { // ⚠️ don't use ephemeral random key in prod
    panic(err)
}

// Optional: override the default script path ("/ds-precompile.js").
// pc.ScriptPath = "/my-custom-path.js"

// Mount the script handler (default path: "/ds-precompile.js").
// Update pc.ScriptPath and your CSP if you change it.
mux.Handle("GET /ds-precompile.js", pc.ScriptHandler())

// Register all your handlers normally.
mux.HandleFunc("GET /{$}", handleIndex)
mux.HandleFunc("POST /api/todos", handleTodosAdd)   // SSE handler — detected automatically
mux.HandleFunc("GET /api/feed", handleFeed)         // non-Datastar HTML — buffered harmlessly

// Wrap the whole mux once at the server level.
// Use pc.MiddlewareWithNonce(mux) instead if you are using nonces
// (see 'Adding nonces for extra protection' below).
http.ListenAndServe(":8080", pc.Middleware(mux))
```

Handlers that return non-HTML content types (JSON, JS, images, …) are automatically passed through. For large HTML responses with no Datastar expressions, you can wrap the handler with `Skip`:

```go
mux.Handle("GET /docs", datastargostrictcsp.Skip(docsHandler))
```

## Example app

The `example/` directory contains a simple Datastar app exercising various framework features.

```sh
go run .
# → http://localhost:8080
```

To run over https and HTTP 2:

```sh
# with mkcert command installed
./run_https.sh
```

Without https, the connection will use HTTP 1.1. Limits on the maximum number of simultaneous connections may cause some initial SSE connection errors to show in the console.

If you have Go ≥ 1.25, you can install [`air`](https://github.com/air-verse/air) with `go mod download` and then run `go tool air` to start the example app with auto-reload-on-change functionality enabled. Go to `http://localhost:8090` (not 8080).

By default, the example app runs without client-side nonce checks (the more typical scenario).
To try the app with client-side nonce checks enabled, go to `http://localhost:8080/?lite=false`.
For more information on nonce checks, see [Adding nonces for extra protection](#adding-nonces-for-extra-protection).

## Security

### The default configuration

With datastar-go-strict-csp's default configuration:

- Datastar works without `unsafe-inline` or `unsafe-eval` in your CSP.
- Precompiled expressions are only obtainable via backend-signed URLs.
- The datastar-go-strict-csp client adds some protection against client-side injection of Datastar attributes. (It tracks which DOM elements were either created on the initial page render or inserted via a Datastar DOM patching operation, and ensures that Datastar attributes on other elements are ignored.)
- Even if an attacker succeeds in injecting Datastar attributes on the client side, they are limited to injecting existing pre-compiled attributes.

⚠️ That said, the default config does leave a **server-side injection** attack vector open.
This is because the middleware trusts all HTML that the server produces. If an injection vulnerability allows an attacker to insert their own Datastar expressions into HTML pages/fragments generated by the server, then the middleware will dutifully precompile those expressions.

The mitigation for server-side injection is, of course, exactly what you should do anyway: escape untrusted values in your HTML templates, and wrap any raw HTML with [`data-ignore`](https://data-star.dev/reference/attributes#data-ignore).

### Adding nonces for extra protection

**_Adding nonces is arguably a bit over the top. See [Should I go to the trouble of adding nonces?](#should-i-go-to-the-trouble-of-adding-nonces)._**

To protect fully against injection attacks, we need to know that any given Datastar attribute was generated by *us*, not an attacker.

To do this, we can create a one-off random value (a 'nonce') and add it alongside the other Datastar attributes as `data-ds-nonce="$VAL"`. The middleware precompiles only those Datastar expressions accompanied by the correct nonce. Meanwhile, the client intercepts Datastar's DOM patching and also checks the nonce, ensuring that even existing precompiled attributes cannot be injected to any effect (while also providing another layer of protection against client-side injection).

Manually adding nonce attributes to your HTML is tedious. This module provides a utility function, `AddNonceToTemplate`, which takes a Go `html/template` string and adds `data-ds-nonce="{{$.Nonce}}"` before an element's first Datastar attribute.

How to modify your app to use nonces:

**1.** Use `dist/datastargostrictcsp-client.js` rather than `dist/datastargostrictcsp-client.lite.js`.

**2.** Use `MiddlewareWithNonce` instead of `Middleware`. It generates a fresh nonce per request and stores it in the request context automatically:

```go
http.ListenAndServe(":8080", pc.MiddlewareWithNonce(mux))
```

**3.** Include a `Nonce` field in your template data and apply `AddNonceToTemplate` once at startup:

```go
type pageData struct {
    Items []Item
    Nonce string
}

var tmpl = template.Must(template.New("").Parse(
	  // Use `{{$.Nonce}}` rather than `{{.Nonce}}` (because inside a range block, `.` rebinds to the loop element).
    datastargostrictcsp.AddNonceToTemplate(pageHTML, "{{$.Nonce}}"),
))
```

**4.** Pass the nonce when rendering:

```go
func handleIndex(w http.ResponseWriter, r *http.Request) {
    tmpl.Execute(w, pageData{
        Items: loadItems(),
        Nonce: datastargostrictcsp.NonceFromContext(r.Context()),
    })
}

func renderFragment(r *http.Request) string {
    var buf bytes.Buffer
    tmpl.ExecuteTemplate(&buf, "fragment", pageData{
        Items: loadItems(),
        Nonce: datastargostrictcsp.NonceFromContext(r.Context()),
    })
    return buf.String()
}
```

### Should I go to the trouble of adding nonces?

Probably not! datastar-go-strict-csp will let you be a an obsessive CSP weenie if you want – but is that who you are?

The default configuration already mitigates client-side attribute injection attacks by maintaining a set of 'blessed' DOM nodes. 

Server-side injection attacks are best avoided by (i) using any sane templating system and (ii) being careful in the rare few cases where you intentionally substitute untrusted HTML into a page. If you care enough to be reading this, then you're almost certainly not going to screw this up.

It might make sense to *selectively* use nonces when rendering especially sensitive or risky pages. Nonce protection is opt-in at the middleware level. Use `MiddlewareWithNonce` for routes where you want it, and plain `Middleware` for routes where you don't.

## Signing key rotation

The `Precompiler.Key` field is the active signing key. To rotate it:

**Planned rotation** (e.g. periodic hygiene):

```go
pc.OldKeys = append(pc.OldKeys, pc.Key)
pc.Key = newKey
```

New requests will be signed with `newKey`. Existing clients holding URLs signed with the old key will continue to work because `OldKeys` is still checked during verification. Once you are confident that old signed URLs are no longer in circulation (e.g. after a suitable grace period), remove the old key from `OldKeys`.

Script URLs are served with `Cache-Control: immutable, max-age=31536000`. Dropping a key from `OldKeys` will cause any cached URLs signed by that key to return a 400 error. The consequence is just a broken page until the user reloads, at which point fresh HTML generates a new signed URL with the current key.

**Compromised key** (the key is known to an attacker):

Set the new key immediately and do **not** add the compromised key to `OldKeys`:

```go
pc.Key = newKey
// Do NOT add the old key to OldKeys
```

This invalidates all URLs signed with the compromised key right away. Users with cached pages will get a one-time error on the script request and will need to reload.

## How bad of a hack is this?

- Monkey-patching `Function` is gross. However, under a strict CSP, calls to `Function` won't work anyway, so it's unlikely to break anything.
- The library depends on Datastar's private internals in a few ways:
  - Reimplements the Datastar expression parser in Go.
  - Relies on the internal `datastar-fetch` CustomEvent and the structure of its `argsRaw` payload.
  - Makes specific assumptions about how various Datastar attributes are compiled.
