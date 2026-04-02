package datastargostrictcsp

// Tests that Go's genRx output exactly matches the reference JS implementation
// in test_support/gen.js for a range of Datastar expressions.
//
// Each test case runs the expression through genRxCached (Go) and through
// node (JS) and compares the resulting []string slices.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runGenJS executes the reference JS implementation in test_support/gen.js via
// node and returns its result. The test is skipped if node is not in PATH.
func runGenJS(t *testing.T, value string, opts GenRxOptions) []string {
	t.Helper()

	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node not found in PATH — required for JS parity tests")
	}

	raw, err := os.ReadFile("test_support/gen.js")
	if err != nil {
		t.Fatalf("could not read test_support/gen.js: %v", err)
	}

	// Strip the trailing console.log line and append our own call.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	src := strings.Join(lines[:len(lines)-1], "\n")

	argNames := opts.ArgNames
	if argNames == nil {
		argNames = []string{}
	}
	inputJSON, _ := json.Marshal(map[string]any{
		"value":        value,
		"returnsValue": opts.ReturnsValue,
		"argNames":     argNames,
	})
	src += fmt.Sprintf(`
const _a = %s;
process.stdout.write(JSON.stringify(genRx(_a.value, {returnsValue: _a.returnsValue, argNames: _a.argNames})));
`, string(inputJSON))

	cmd := exec.Command("node", "-e", src)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("node failed: %v\nstderr: %s", err, ee.Stderr)
		}
		t.Fatalf("node failed: %v", err)
	}

	var result []string
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("could not parse node output %q: %v", out, err)
	}
	return result
}

func TestGenRx_ParityWithJS(t *testing.T) {
	tests := []struct {
		name  string
		value string
		opts  GenRxOptions
	}{
		// ── signal access ─────────────────────────────────────────────────────
		{
			name:  "simple signal read",
			value: "$count",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "simple signal statement",
			value: "$count++",
			opts:  GenRxOptions{ReturnsValue: false},
		},
		{
			name:  "nested signal path",
			value: "$foo.bar",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "hyphenated signal name",
			value: "$my-signal",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "hyphenated nested path",
			value: "$foo.bar-baz",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "multiple signals in expression",
			value: "$a + $b",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "signal assignment",
			value: "$count = $count + 1",
			opts:  GenRxOptions{ReturnsValue: false},
		},

		// ── string/template literals ──────────────────────────────────────────
		{
			name:  "signal inside double-quoted string not transformed",
			value: `"$foo"`,
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "signal inside single-quoted string not transformed",
			value: `'$foo'`,
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "template literal with signal interpolation",
			value: "`value: ${$count}`",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "template literal with nested signal path in interpolation",
			value: "`${$foo.bar}`",
			opts:  GenRxOptions{ReturnsValue: true},
		},

		// ── actions ───────────────────────────────────────────────────────────
		{
			name:  "action with string arg",
			value: "@post('/api/counter/increment')",
			opts:  GenRxOptions{ReturnsValue: false},
		},
		{
			name:  "action with signal arg",
			value: "@toggle($open)",
			opts:  GenRxOptions{ReturnsValue: false},
		},
		{
			name:  "action with multiple args",
			value: "@setItem($key, $value)",
			opts:  GenRxOptions{ReturnsValue: false},
		},

		// ── multiple statements ───────────────────────────────────────────────
		{
			name:  "multiple statements return added to last",
			value: "$a++; $b = $a",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "explicit return left alone",
			value: "$x > 0; return $x",
			opts:  GenRxOptions{ReturnsValue: true},
		},

		// ── extra argNames ────────────────────────────────────────────────────
		{
			name:  "extra argName (on-signal-patch style)",
			value: "$count = patch.value",
			opts:  GenRxOptions{ReturnsValue: true, ArgNames: []string{"patch"}},
		},

		// ── miscellaneous ─────────────────────────────────────────────────────
		{
			name:  "boolean expression",
			value: "$visible && $count > 0",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "ternary",
			value: "$open ? 'yes' : 'no'",
			opts:  GenRxOptions{ReturnsValue: true},
		},
		{
			name:  "bare true literal",
			value: "true",
			opts:  GenRxOptions{ReturnsValue: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := runGenJS(t, tc.value, tc.opts)
			got := genRxCached(tc.value, tc.opts)

			if len(got) != len(want) {
				t.Fatalf("length mismatch\n  go:  %q\n  js:  %q", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("element [%d] differs\n  go:  %q\n  js:  %q\n  full go: %q\n  full js: %q",
						i, got[i], want[i], got, want)
				}
			}
		})
	}
}
