# datastar-go-strict-csp

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)
![Datastar](https://img.shields.io/badge/Datastar-1.0.1-blueviolet?style=flat)
[![Go Reference](https://pkg.go.dev/badge/github.com/addrummond/datastargostrictcsp.svg)](https://pkg.go.dev/github.com/addrummond/datastargostrictcsp)

A Go package that makes [Datastar](https://data-star.dev/) compatible with a strict [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP).

**No `unsafe-eval`**.

**No `unsafe-inline`**.

**1.9KB** minified client-side JS.

🚀 Minimal changes to your app. No restrictions on Datastar expressions.

🚧 **Not officially supported. Not tested with Datastar Pro.**

---

## How does it work?

Datastar compiles expressions down to invocations of the JavaScript `Function` constructor, e.g.:
```js
new Function("el", "$", "__action", "evt", "return el.id")
```

This module sidesteps that with a Go precompiler:

1. Reimplements Datastar's expression compiler in Go (~200 LOC).
2. Middleware scans HTML pages/fragments and collates Datastar expressions (respecting the `data-ignore` attribute).
3. A signed URL containing the relevant expressions is delivered to the client together with the HTML.
4. A GET request to the signed URL returns JavaScript with a pre-compiled expression lookup table.
5. The datastar-go-strict-csp client library monkey-patches `Function` to use the lookup table.

The signed URL reaches the client in one of three ways:

| Context | Delivery method |
|---|---|
| Full HTML document | `<script type="module" src="$URL">` injected before `</head>` |
| SSE (`datastar-patch-elements`) | `data: precompileUrl <url>` field injected; client library intercepts `datastar-fetch`, loads script, then re-dispatches |
| Non-SSE HTML fragment | `<!-- precompile-url: <url> -->` prepended; client library intercepts `datastar-fetch`, strips comment and loads script, then re-dispatches |

**URL length:** Signed URLs can contain many Datastar expressions. If a URL would exceed 2000 bytes, the server automatically splits it into multiple URLs. (An individual Datastar expression cannot be split across multiple URLs, so don't write ludicrously humungous expressions.)

## Getting started

**1.** Add a Content Security Policy **without** `unsafe-inline` or `unsafe-eval`.

**2.** Add the following **before** the Datastar script tag:
```html
<script type="module" src="https://cdn.jsdelivr.net/gh/addrummond/datastargostrictcsp@0.12.6/dist/datastargostrictcsp-client.lite.min.js"></script>
```

**3.** Generate a persistent 32-byte signing key (or in dev, generate a random key on start up).

**4.** Mount the script handler and wrap your whole mux with `Middleware`.

```go
pc := &datastargostrictcsp.Precompiler{}
if _, err := rand.Read(pc.Key[:]); err != nil { // ⚠️ don't use ephemeral random key in prod
    panic(err)
}

// Optional: override the default script path ("/ds-precompile.js").
// pc.ScriptPath = "/my-custom-path.js"

// Mount the script handler. pc.GetScriptPath() returns the effective path.
mux.Handle("GET "+pc.GetScriptPath(), pc.ScriptHandler())

// Register all your handlers normally.
mux.HandleFunc("GET /{$}", handleIndex)
mux.HandleFunc("POST /api/todos", handleTodosAdd)
mux.HandleFunc("GET /api/feed", handleFeed)

// Wrap the whole mux once at the server level.
// Compose with NonceMiddleware if you are using nonces
// (see 'Adding nonces for extra protection' below).
http.ListenAndServe(":8080", pc.Middleware(mux))
```

Handlers that return non-HTML content types (JSON, JS, images, …) are automatically passed through. For large HTML responses with no Datastar expressions, you can wrap the handler with `Skip`:

```go
mux.Handle("GET /docs", datastargostrictcsp.Skip(docsHandler))
```

**Frameworks with non-standard middleware**

<img src="https://raw.githubusercontent.com/addrummond/datastargostrictcsp/main/.readmeassets/gin-icon.webp" width="24" style="vertical-align:middle" alt="Gin"> If you're using [Gin](https://gin-gonic.com/en/), [gin-adapter](https://github.com/gwatts/gin-adapter) can convert the standard `func(http.Handler) http.Handler` middleware to a `gin.HandlerFunc`:

```go
router.Use(adapter.New(datastargostrictcsp.NonceMiddleware))
router.Use(adapter.New(pc.Middleware))
```

<img src="https://raw.githubusercontent.com/addrummond/datastargostrictcsp/main/.readmeassets/fiber-logo.svg" width="50" style="vertical-align:middle" alt="Fiber"> If you're using [Fiber](https://gofiber.io/), use the [adaptor package](https://docs.gofiber.io/next/middleware/adaptor/):

```go
import "github.com/gofiber/fiber/v3/middleware/adaptor"

app := fiber.New()
app.Use(adaptor.HTTPMiddleware(datastargostrictcsp.NonceMiddleware))
app.Use(adaptor.HTTPMiddleware(pc.Middleware))
```

## Custom aliased bundles

Datastar supports aliased bundles where attribute names take the form `data-{alias}-*` instead of `data-*`. If you're using one, set `Alias` on your `Precompiler`:

```go
pc.Alias = "myalias" // matches data-myalias-on:click, data-myalias-text, etc.
```

When an alias is set, only aliased attributes are recognized; standard `data-*` attributes are ignored.

## Using compression

### Compressing non-SSE responses

For regular HTML responses, compression works without any special setup as long as the compression middleware wraps `pc.Middleware` on the outside:

```go
compress, _ := httpcompression.DefaultAdapter()
http.ListenAndServe(":8080", compress(pc.Middleware(mux)))
```

`pc.Middleware` buffers the raw HTML, injects script tags, and then passes the result to the compressor.

ℹ️ The middleware automatically skips any response that has a `Content-Encoding` header set. Thus, it's only a problem for the middleware to wrap a handler that returns a compressed response if the response needs to be scanned for Datastar expressions.

### Compressing SSE responses

For SSE, **do not** use the SDK's `WithCompression` option. That compresses the stream before it reaches `pc.Middleware`, making it impossible for the middleware to parse.

Instead, use a compression library such as [github.com/CAFxX/httpcompression](https://github.com/CAFxX/httpcompression) directly. Route SSE traffic through a sub-mux so the compressor wraps `pc.Middleware`:

```go
rootMux := http.NewServeMux()
// ... register page and asset handlers on rootMux ...

sseMux := http.NewServeMux()
sseMux.HandleFunc("GET /events", handleEvents)

compress, _ := httpcompression.DefaultAdapter()

mux := http.NewServeMux()
mux.Handle("/",     pc.Middleware(rootMux))
mux.Handle("/sse/", compress(pc.Middleware(http.StripPrefix("/sse", sseMux))))

http.ListenAndServe(":8080", mux)
```

The ordering matters: `compress(pc.Middleware(...))` means the middleware sees raw SSE events, injects the precompile URL fields, and then the compressor takes the result.

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

If you have Go ≥ 1.25, you can run `go tool air` to start the example app with auto-reload-on-change functionality enabled. Go to `http://localhost:8090` (not 8080).

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

To do this, we can create a one-off random value (a 'nonce') and add it alongside the other Datastar attributes as `data-ds-nonce="$VAL"`. The middleware precompiles only those Datastar expressions accompanied by the correct nonce. Meanwhile, the client intercepts Datastar's DOM patching and also checks the nonce, ensuring that even existing precompiled expressions can't be injected server-side (and providing another layer of protection against client-side injection).

Manually adding nonce attributes to your HTML is tedious. You'll probably want to find a way of setting up your templating system to automatically add a `data-ds-nonce` attribute to any tag with other Datastar attributes.

How to modify your app to use nonces:

**1.** If you want client-side nonce checks, use `dist/datastargostrictcsp-client.js` rather than `dist/datastargostrictcsp-client.lite.js`.

**2.** Compose `NonceMiddleware` with `Middleware`. It generates a fresh nonce per request and stores it in the request context:

```go
http.ListenAndServe(":8080", datastargostrictcsp.NonceMiddleware(pc.Middleware(mux)))
```

**3.** Include a `Nonce` field in your template data and ensure that your templates add the required `data-ds-nonce` attributes.

**4.** Pass the nonce when rendering HTML pages or fragments:

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

The default configuration already mitigates client-side attribute injection attacks by maintaining a set of 'blessed' DOM nodes, and by restricting the blast radius of such attacks to injection of existing pre-compiled expressions.

Server-side injection attacks are best avoided by (i) using any sane templating system and (ii) being careful in the rare few cases where you intentionally substitute untrusted HTML into a page. If you care enough to be reading this, then you're almost certainly not going to screw this up.

It might make sense to *selectively* use nonces when rendering especially sensitive or risky pages. Nonce protection is opt-in at the middleware level. Just wrap `Middleware` with `NonceMiddleware` where you want it.

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
