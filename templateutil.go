package datastargostrictcsp

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// AddNonceToTemplate scans the HTML template source tmplSrc and returns a
// copy with a data-ds-nonce="<nonceExpr>" attribute added to every element
// that carries at least one Datastar data-* attribute. Elements inside a
// data-ignore subtree are left untouched.
//
// nonceExpr is inserted literally as the attribute value, so pass a Go
// template expression such as "{{$.Nonce}}". (Prefer {{$.Nonce}} over
// {{.Nonce}} to ensure the nonce is always resolved from the root data.)
func AddNonceToTemplate(tmplSrc, nonceExpr string) string {
	src := []byte(tmplSrc)
	var out bytes.Buffer
	out.Grow(len(src))

	z := html.NewTokenizer(bytes.NewReader(src))
	ignoreDepth := 0

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		// Copy raw bytes before TagName/TagAttr calls, which may mutate the slice.
		raw := append([]byte(nil), z.Raw()...)

		switch {
		case tt == html.EndTagToken:
			if ignoreDepth > 0 {
				ignoreDepth--
			}
			out.Write(raw)

		case tt != html.StartTagToken && tt != html.SelfClosingTagToken:
			out.Write(raw)

		default:
			tagName, _ := z.TagName()
			isVoid := tt == html.SelfClosingTagToken || voidElements[string(tagName)]

			type kv struct{ key, val string }
			var attrs []kv
			for {
				k, v, more := z.TagAttr()
				attrs = append(attrs, kv{string(k), string(v)})
				if !more {
					break
				}
			}

			write := raw // default: pass through unmodified

			if ignoreDepth > 0 {
				if !isVoid {
					ignoreDepth++
				}
			} else {
				ignored := false
				for _, a := range attrs {
					if a.key == "data-ignore" {
						ignored = true
						break
					}
				}
				if ignored {
					if !isVoid {
						ignoreDepth++
					}
				} else {
					hasDatastar, hasNonce := false, false
					for _, a := range attrs {
						if a.key == "data-ds-nonce" {
							hasNonce = true
							break
						}
						base, ok := strings.CutPrefix(a.key, "data-")
						if !ok {
							continue
						}
						if i := strings.IndexByte(base, ':'); i >= 0 {
							base = base[:i]
						}
						if attr, ok := dsAttrs[base]; ok && attr.Kind != dsAttrNone {
							hasDatastar = true
						}
					}
					if hasDatastar && !hasNonce {
						nonce := ` data-ds-nonce="` + nonceExpr + `"`
						// Insert before the closing > or />.
						cut := len(raw) - 1 // index of >
						if raw[cut-1] == '/' {
							cut-- // step back over / in />
						}
						modified := make([]byte, 0, len(raw)+len(nonce))
						modified = append(modified, raw[:cut]...)
						modified = append(modified, nonce...)
						modified = append(modified, raw[cut:]...)
						write = modified
					}
				}
			}

			out.Write(write)
		}
	}

	return out.String()
}
