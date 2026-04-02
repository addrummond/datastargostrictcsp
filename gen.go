package datastargostrictcsp

import (
	"container/list"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
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

func genRxCached(value string, opts GenRxOptions) []string {
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

	// Go stdlib regex engine can't handle negative lookaheads, so use regexp2 for this one.
	signalRe = regexp2.MustCompile(
		`("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`+
			"`"+`(?:\\.|[^`+"`"+`\\$]|\$(?!\{))*`+"`"+
			`)|\$\{([^{}]*)\}|\$([a-zA-Z_\d]\w*(?:[-.]\w+)*)`,
		0,
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

type GenRxOptions struct {
	ReturnsValue bool
	ArgNames     []string
}

// Compare https://github.com/starfederation/datastar/blob/5f43d33ee55b17ebb254b9d7115f39c852159169/library/src/engine/engine.ts#L373
func genRx(value string, opts GenRxOptions) []string {
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

	expr, _ = signalRe.ReplaceFunc(expr, func(m regexp2.Match) string {
		g1 := m.GroupByNumber(1)
		g2 := m.GroupByNumber(2)
		g3 := m.GroupByNumber(3)
		switch {
		case len(g1.Captures) > 0:
			return m.String()
		case len(g2.Captures) > 0:
			replaced := innerSignalRe.ReplaceAllStringFunc(g2.String(), func(inner string) string {
				return signalToBracket(inner[1:])
			})
			return "${" + replaced + "}"
		case len(g3.Captures) > 0:
			return signalToBracket(g3.String())
		}
		return m.String()
	}, 0, -1)

	expr = actionRe.ReplaceAllString(expr, `__action("$1",evt,`)

	for k, v := range escaped {
		expr = strings.Replace(expr, k, v, 1)
	}

	result := []string{"el", "$", "__action", "evt"}
	result = append(result, opts.ArgNames...)
	result = append(result, expr)
	return result
}
