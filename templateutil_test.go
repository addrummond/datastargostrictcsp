package datastargostrictcsp_test

import (
	"strings"
	"testing"

	dscsp "github.com/addrummond/datastargostrictcsp"
)

func TestAddNonceToTemplate_MultipleElements(t *testing.T) {
	const expr = "{{$.Nonce}}"
	in := `<div data-text="a"></div><span data-show="$x"></span><p>plain</p>`
	got := dscsp.AddNonceToTemplate(in, expr)

	count := strings.Count(got, `data-ds-nonce="`+expr+`"`)
	if count != 2 {
		t.Errorf("expected 2 nonce attrs, got %d;\noutput: %q", count, got)
	}
	if strings.Count(got, "<p>plain</p>") != 1 {
		t.Errorf("plain element should be unchanged;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_NestedDSElements(t *testing.T) {
	const expr = "{{$.Nonce}}"
	in := `<div data-text="outer"><span data-show="$x"></span></div>`
	got := dscsp.AddNonceToTemplate(in, expr)

	if strings.Count(got, `data-ds-nonce="`+expr+`"`) != 2 {
		t.Errorf("expected both nested DS elements to get nonce;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_NonceInsertedBeforeClosingBracket(t *testing.T) {
	const expr = "{{$.Nonce}}"
	got := dscsp.AddNonceToTemplate(`<div data-text="x" class="foo"></div>`, expr)

	// Nonce must appear before the closing > of the opening tag.
	openTagEnd := strings.Index(got, ">")
	noncePos := strings.Index(got, "data-ds-nonce")
	if noncePos < 0 {
		t.Fatal("data-ds-nonce not found")
	}
	if noncePos > openTagEnd {
		t.Errorf("data-ds-nonce appears after closing > of opening tag;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_SelfClosingVoidNoDS(t *testing.T) {
	const expr = "{{$.Nonce}}"
	// Void element with no DS attrs should be untouched
	in := `<br/>`
	got := dscsp.AddNonceToTemplate(in, expr)
	if strings.Contains(got, "data-ds-nonce") {
		t.Errorf("void element with no DS attrs should not get nonce;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_NonDatastarDataAttr(t *testing.T) {
	// data-foo is not a Datastar attr — should not trigger a nonce
	const expr = "{{$.Nonce}}"
	got := dscsp.AddNonceToTemplate(`<div data-foo="bar"></div>`, expr)
	if strings.Contains(got, "data-ds-nonce") {
		t.Errorf("non-Datastar data-* attr should not trigger nonce;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_DataIgnoreOnVoidDoesNotStartSubtree(t *testing.T) {
	// data-ignore on a void element should not suppress the following element
	const expr = "{{$.Nonce}}"
	in := `<input data-ignore><div data-text="x"></div>`
	got := dscsp.AddNonceToTemplate(in, expr)
	if !strings.Contains(got, "data-ds-nonce") {
		t.Errorf("element after data-ignore on void should still get nonce;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_MultipleIgnoreSubtrees(t *testing.T) {
	// Two separate data-ignore subtrees followed by a normal DS element
	const expr = "{{$.Nonce}}"
	in := `` +
		`<div data-ignore><span data-text="ignored1"></span></div>` +
		`<section data-ignore><p data-show="$ignored2"></p></section>` +
		`<article data-text="visible"></article>`
	got := dscsp.AddNonceToTemplate(in, expr)

	if count := strings.Count(got, "data-ds-nonce"); count != 1 {
		t.Errorf("expected exactly 1 nonce attr (only the visible element), got %d;\noutput: %q", count, got)
	}
	if !strings.Contains(got, `<article data-text="visible" data-ds-nonce="`+expr+`"`) {
		t.Errorf("nonce should be on the visible article;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_GoTemplateDirectivesPreserved(t *testing.T) {
	// Template directives in text content and attribute values must survive intact
	const expr = "{{$.Nonce}}"
	in := `<div data-text="x">{{if .Cond}}<span data-show="$y"></span>{{end}}</div>`
	got := dscsp.AddNonceToTemplate(in, expr)
	if !strings.Contains(got, "{{if .Cond}}") || !strings.Contains(got, "{{end}}") {
		t.Errorf("Go template directives in text content should be preserved;\noutput: %q", got)
	}
}

func TestAddNonceToTemplate_ExistingAttributesPreserved(t *testing.T) {
	const expr = "{{$.Nonce}}"
	in := `<div id="myid" class="foo" data-text="x" aria-label="bar"></div>`
	got := dscsp.AddNonceToTemplate(in, expr)
	for _, attr := range []string{`id="myid"`, `class="foo"`, `data-text="x"`, `aria-label="bar"`} {
		if !strings.Contains(got, attr) {
			t.Errorf("existing attribute %q lost;\noutput: %q", attr, got)
		}
	}
}

func TestAddNonceToTemplate_DSAttrWithSubkey(t *testing.T) {
	// data-on:click, data-attr:href etc. — subkey after : should still be recognised
	const expr = "{{$.Nonce}}"
	tests := []string{
		`<button data-on:click="doThing()"></button>`,
		`<a data-attr:href="$url"></a>`,
	}
	for _, in := range tests {
		got := dscsp.AddNonceToTemplate(in, expr)
		if !strings.Contains(got, "data-ds-nonce") {
			t.Errorf("data-on/data-attr with subkey should trigger nonce;\ninput:  %q\noutput: %q", in, got)
		}
	}
}

func TestAddNonceToTemplate_EmptyInput(t *testing.T) {
	got := dscsp.AddNonceToTemplate("", "{{$.Nonce}}")
	if got != "" {
		t.Errorf("empty input should produce empty output, got %q", got)
	}
}

func TestAddNonceToTemplate_NonceExprAppearedLiterally(t *testing.T) {
	// Whatever nonceExpr string is passed should appear verbatim in the output
	const customExpr = "CUSTOM_NONCE_PLACEHOLDER"
	got := dscsp.AddNonceToTemplate(`<div data-text="x"></div>`, customExpr)
	if !strings.Contains(got, `data-ds-nonce="CUSTOM_NONCE_PLACEHOLDER"`) {
		t.Errorf("custom nonce expr not present verbatim;\noutput: %q", got)
	}
}
