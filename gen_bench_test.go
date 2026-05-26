package datastargostrictcsp

import "testing"

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
