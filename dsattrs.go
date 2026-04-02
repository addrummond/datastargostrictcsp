package datastargostrictcsp

type dsAttrKind int

const (
	dsAttrNone      dsAttrKind = iota // no JS expression (skip)
	dsAttrStatement                   // expression for side effects (returnsValue: false)
	dsAttrValue                       // expression returning a value (returnsValue: true)
	dsAttrBoth                        // generate both variants (used for pro attrs with uncertain kind)
)

type dsAttr struct {
	Kind     dsAttrKind
	ArgNames []string
}

// confirmed from library/src/plugins/*
var dsAttrs = map[string]dsAttr{
	"attr":            {Kind: dsAttrValue},
	"bind":            {Kind: dsAttrNone},
	"class":           {Kind: dsAttrValue},
	"computed":        {Kind: dsAttrValue},
	"effect":          {Kind: dsAttrStatement},
	"ignore":          {Kind: dsAttrNone},
	"ignore-morph":    {Kind: dsAttrNone},
	"indicator":       {Kind: dsAttrNone},
	"init":            {Kind: dsAttrStatement},
	"json-signals":    {Kind: dsAttrNone},
	"on":              {Kind: dsAttrStatement, ArgNames: []string{"evt"}},
	"on-intersect":    {Kind: dsAttrStatement},
	"on-interval":     {Kind: dsAttrStatement},
	"on-signal-patch": {Kind: dsAttrValue, ArgNames: []string{"patch"}},
	"preserve-attr":   {Kind: dsAttrNone},
	"ref":             {Kind: dsAttrNone},
	"show":            {Kind: dsAttrValue},
	"signals":         {Kind: dsAttrValue},
	"style":           {Kind: dsAttrValue},
	"text":            {Kind: dsAttrValue},

	// pro attributes — kind is uncertain, so both variants are precompiled
	"animate":                {Kind: dsAttrBoth},
	"custom-validity":        {Kind: dsAttrBoth},
	"match-media":            {Kind: dsAttrNone}, // media query string literal, not a JS expr
	"on-raf":                 {Kind: dsAttrBoth},
	"on-resize":              {Kind: dsAttrBoth},
	"on-signal-patch-filter": {Kind: dsAttrBoth},
	"persist":                {Kind: dsAttrNone}, // signal name list, not an expression
	"query-string":           {Kind: dsAttrNone}, // signal name list, not an expression
	"replace-url":            {Kind: dsAttrBoth},
	"rocket":                 {Kind: dsAttrNone}, // unknown — conservative default
	"scroll-into-view":       {Kind: dsAttrNone}, // likely options literal, not a JS expr
	"view-transition":        {Kind: dsAttrBoth},
}
