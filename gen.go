package datastargostrictcsp

import (
	"container/list"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const genRxCacheMax = 512

type genRxKey struct {
	value        string
	returnsValue bool
	argNames     string // elements joined with \x00
}

var (
	genRxMu   sync.Mutex
	genRxList = list.New()
	genRxMap  = make(map[genRxKey]*list.Element, genRxCacheMax)
)

type genRxEntry struct {
	key    genRxKey
	result []string
}

func genRxCached(value string, opts genRxOptions) []string {
	key := genRxKey{
		value:        value,
		returnsValue: opts.ReturnsValue,
		argNames:     strings.Join(opts.ArgNames, "\x00"),
	}

	genRxMu.Lock()
	if el, ok := genRxMap[key]; ok {
		genRxList.MoveToFront(el)
		result := el.Value.(*genRxEntry).result
		genRxMu.Unlock()
		return result
	}
	genRxMu.Unlock()

	// Compute outside the lock so concurrent callers don't serialize.
	result := genRx(value, opts)

	genRxMu.Lock()
	defer genRxMu.Unlock()
	// Re-check: another goroutine may have inserted the same key.
	if el, ok := genRxMap[key]; ok {
		genRxList.MoveToFront(el)
		return el.Value.(*genRxEntry).result
	}
	if genRxList.Len() >= genRxCacheMax {
		oldest := genRxList.Back()
		genRxList.Remove(oldest)
		delete(genRxMap, oldest.Value.(*genRxEntry).key)
	}
	el := genRxList.PushFront(&genRxEntry{key: key, result: result})
	genRxMap[key] = el
	return result
}

const (
	dsp = "🖕JS_"
	dss = "_DS🚀"
)

var (
	statementRe = regexp.MustCompile(
		`(?m)(/(\\/|[^/])*/|"(\\"|[^"])*"|'(\\'|[^'])*'` +
			"|`(\\\\`|[^`])*`" +
			`|\(\s*((function)\s*\(\s*\)|(\(\s*\))\s*=>)\s*(?:\{[\s\S]*?\}|[^;){]*)\s*\)\s*\(\s*\)|[^;])+`,
	)

	escapeRe = regexp.MustCompile(
		regexp.QuoteMeta(dsp) + `(.*?)` + regexp.QuoteMeta(dss),
	)

	signalRe = regexp.MustCompile(
		`("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` +
			// We can't do negative lookahead with the Go regexp stdlib, so we add
			// some additional code in genRx to compensate for the removal of (?!\{)
			// from the original regex.
			//"`" + `(?:\\.|[^` + "`" + `\\$]|\$(?!\{))*` + "`" +
			"`" + `(?:\\.|[^` + "`" + `\\$]|\$)*` + "`" +
			`)|\$\{([^{}]*)\}|\$([a-zA-Z_\d]\w*(?:[-.]\w+)*)`,
	)

	innerSignalRe = regexp.MustCompile(`\$([a-zA-Z_\d]\w*(?:[-.]\w+)*)`)

	actionRe = regexp.MustCompile(`@([A-Za-z_$][\w$]*)\(`)
)

func signalToBracket(name string) string {
	parts := strings.Split(name, ".")
	result := "$"
	for _, part := range parts {
		result += "['" + part + "']"
	}
	return result
}

type genRxOptions struct {
	ReturnsValue bool
	ArgNames     []string
}

// Compare https://github.com/starfederation/datastar/blob/5f43d33ee55b17ebb254b9d7115f39c852159169/library/src/engine/engine.ts#L373
func genRx(value string, opts genRxOptions) []string {
	var expr string

	if opts.ReturnsValue {
		trimmed := strings.TrimSpace(value)
		statements := statementRe.FindAllString(trimmed, -1)
		if len(statements) > 0 {
			lastIdx := len(statements) - 1
			last := strings.TrimSpace(statements[lastIdx])
			if !strings.HasPrefix(last, "return") {
				statements[lastIdx] = "return (" + last + ");"
			}
			expr = strings.Join(statements, ";\n")
		}
	} else {
		expr = strings.TrimSpace(value)
	}

	escaped := make(map[string]string)
	counter := 0
	for _, match := range escapeRe.FindAllStringSubmatch(expr, -1) {
		k := match[1]
		v := fmt.Sprintf("__escaped%d", counter)
		counter++
		escaped[v] = k
		expr = strings.Replace(expr, dsp+k+dss, v, 1)
	}

	var replacer func(m []string) string
	replacer = func(m []string) string {
		switch {
		case m[1] != "":
			// Work around deletion of the $(?!\{) lookahead in the signalRe regex.
			// If there's a '${' in the match, then strip the ``, run the replacement
			// again (which now won't try the `` string branch of the regex), and add
			// the `` back.
			if m[1][0] == '`' && strings.Contains(m[1], "${") {
				return "`" + replaceAllSubmatchFunc(signalRe, m[1][1:len(m[1])-1], replacer) + "`"
			}
			return m[1]
		case m[2] != "":
			replaced := innerSignalRe.ReplaceAllStringFunc(m[2], func(inner string) string {
				return signalToBracket(inner[1:])
			})
			return "${" + replaced + "}"
		case m[3] != "":
			return signalToBracket(m[3])
		}
		return m[0]
	}

	expr = replaceAllSubmatchFunc(signalRe, expr, replacer)
	expr = actionRe.ReplaceAllString(expr, `__action("$1",evt,`)

	for k, v := range escaped {
		expr = strings.Replace(expr, k, v, 1)
	}

	result := []string{"el", "$", "__action", "evt"}
	result = append(result, opts.ArgNames...)
	result = append(result, expr)
	return result
}

// replaceAllSubmatchFunc calls repl for each match, passing the full slice of
// submatches, and replaces each match with the returned string.
func replaceAllSubmatchFunc(re *regexp.Regexp, src string, repl func([]string) string) string {
	indices := re.FindAllStringSubmatchIndex(src, -1)
	if len(indices) == 0 {
		return src
	}
	var b strings.Builder
	pos := 0
	for _, idx := range indices {
		b.WriteString(src[pos:idx[0]])
		groups := make([]string, len(idx)/2)
		for i := range groups {
			lo, hi := idx[i*2], idx[i*2+1]
			if lo >= 0 {
				groups[i] = src[lo:hi]
			}
		}
		b.WriteString(repl(groups))
		pos = idx[1]
	}
	b.WriteString(src[pos:])
	return b.String()
}
