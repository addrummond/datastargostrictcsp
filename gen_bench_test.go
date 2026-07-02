package datastargostrictcsp

import (
	"regexp"
	"testing"
)

var (
	genRxBenchmarkSink   []string
	bracketBenchmarkSink string
)

func BenchmarkGenRx(b *testing.B) {
	benchmarks := []struct {
		name  string
		value string
		opts  genRxOptions
	}{
		{
			name:  "StatementNoMarkers",
			value: "count = count + 1",
			opts:  genRxOptions{ReturnsValue: false},
		},
		{
			name:  "ValueNoMarkers",
			value: "visible && count > 0",
			opts:  genRxOptions{ReturnsValue: true},
		},
		{
			name:  "SignalPathValue",
			value: "$todo.items.0.title + ' ' + $suffix",
			opts:  genRxOptions{ReturnsValue: true},
		},
		{
			name:  "ActionWithSignals",
			value: "@setItem($key, $value)",
			opts:  genRxOptions{ReturnsValue: false},
		},
		{
			name:  "TemplateInterpolation",
			value: "`item ${$todo.title}: ${$count}`",
			opts:  genRxOptions{ReturnsValue: true},
		},
		{
			name:  "EscapedPlaceholder",
			value: dsp + "el.dataset.value" + dss + " + $count",
			opts:  genRxOptions{ReturnsValue: true},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				genRxBenchmarkSink = genRx(bm.value, bm.opts)
			}
		})
	}
}

// statementReCapturing is statementRe as defined before its groups were made
// non-capturing. It exists only so BenchmarkStatementRe can confirm the
// speedup from the conversion.
var statementReCapturing = regexp.MustCompile(
	`(?m)(/(\\/|[^/])*/|"(\\"|[^"])*"|'(\\'|[^'])*'` +
		"|`(\\\\`|[^`])*`" +
		`|\(\s*((function)\s*\(\s*\)|(\(\s*\))\s*=>)\s*(?:\{[\s\S]*?\}|[^;){]*)\s*\)\s*\(\s*\)|[^;])+`,
)

func BenchmarkStatementRe(b *testing.B) {
	input := `let x = $count + 1; y = "a;b" + 'c;d'; /a;b/.test(y); ` +
		"`tpl ${$v};`" + `; (function () { doThing(); })(); (() => x)()`

	// Sanity check: both patterns must split the input identically.
	if want, got := statementReCapturing.FindAllString(input, -1), statementRe.FindAllString(input, -1); len(want) != len(got) {
		b.Fatalf("patterns disagree: capturing found %d statements, non-capturing found %d", len(want), len(got))
	}

	for _, bm := range []struct {
		name string
		re   *regexp.Regexp
	}{
		{"NonCapturing", statementRe},
		{"Capturing", statementReCapturing},
	} {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				genRxBenchmarkSink = bm.re.FindAllString(input, -1)
			}
		})
	}
}

func BenchmarkGenRxCachedHit(b *testing.B) {
	value := "$todo.items.0.title + ' ' + $suffix"
	opts := genRxOptions{ReturnsValue: true}
	genRxBenchmarkSink = genRxCached(value, opts)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		genRxBenchmarkSink = genRxCached(value, opts)
	}
}

func BenchmarkSignalToBracket(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bracketBenchmarkSink = signalToBracket("todo.items.0.title")
	}
}
