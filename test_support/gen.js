// Taken from code in https://github.com/starfederation/datastar/blob/5f43d33ee55b17ebb254b9d7115f39c852159169/library/src/engine/engine.ts#L373
// Used for testing for parity with go reimplementation.

const lol = /🖕JS_DS🚀/.source;
const DSP = lol.slice(0, 5);
const DSS = lol.slice(4);

const error = (...args) => new Error(JSON.stringify(args));
const err = (...args) => new Error(JSON.stringify(args));

const genRx = (
  value,
  { returnsValue = false, argNames = [], cleanups = new Map() } = {},
) => {
  let expr = "";
  if (returnsValue) {
    // This regex allows Datastar expressions to support nested
    // regex and strings that contain ; without breaking.
    //
    // Each of these regex defines a block type we want to match
    // (importantly we ignore the content within these blocks):
    //
    // regex            \/(\\\/|[^\/])*\/
    // double quotes      "(\\"|[^\"])*"
    // single quotes      '(\\'|[^'])*'
    // ticks              `(\\`|[^`])*`
    // iife               \(\s*((function)\s*\(\s*\)|(\(\s*\))\s*=>)\s*(?:\{[\s\S]*?\}|[^;)\{]*)\s*\)\s*\(\s*\)
    //
    // The iife support is (intentionally) limited. It only supports
    // function and arrow syntax with no arguments, and no nested IIFEs.
    //
    // We also want to match the non delimiter part of statements
    // note we only support ; statement delimiters:
    //
    // [^;]
    //
    const statementRe =
      /(\/(\\\/|[^/])*\/|"(\\"|[^"])*"|'(\\'|[^'])*'|`(\\`|[^`])*`|\(\s*((function)\s*\(\s*\)|(\(\s*\))\s*=>)\s*(?:\{[\s\S]*?\}|[^;){]*)\s*\)\s*\(\s*\)|[^;])+/gm;
    const statements = value.trim().match(statementRe);
    if (statements) {
      const lastIdx = statements.length - 1;
      const last = statements[lastIdx].trim();
      if (!last.startsWith("return")) {
        statements[lastIdx] = `return (${last});`;
      }
      expr = statements.join(";\n");
    }
  } else {
    expr = value.trim();
  }

  // Ignore any escaped values
  const escaped = new Map();
  const escapeRe = RegExp(`(?:${DSP})(.*?)(?:${DSS})`, "gm");
  let counter = 0;
  for (const match of expr.matchAll(escapeRe)) {
    const k = match[1];
    const v = `__escaped${counter++}`;
    escaped.set(v, k);
    expr = expr.replace(DSP + k + DSS, v);
  }

  // Replace signal references with bracket notation
  // Examples:
  //   $count          -> $['count']
  //   $count--        -> $['count']--
  //   $foo.bar        -> $['foo']['bar']
  //   $foo-bar        -> $['foo-bar']
  //   $foo.bar-baz    -> $['foo']['bar-baz']
  //   $foo-$bar       -> $['foo']-$['bar']
  //   $arr[$index]    -> $['arr'][$['index']]
  //   $['foo']        -> $['foo']
  //   $foo[obj.bar]   -> $['foo'][obj.bar]
  //   $foo['bar.baz'] -> $['foo']['bar.baz']
  //   $123            -> $['123']
  //   $foo.0.name     -> $['foo']['0']['name']

  // Skip replacements inside string/template literals.
  // Template interpolation support rewrites `${...}` only when braces are non-nested.
  expr = expr.replace(
    /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\$]|\$(?!\{))*`)|\$\{([^{}]*)\}|\$([a-zA-Z_\d]\w*(?:[.-]\w+)*)/g,
    (match, quoted, interpolationExpr, signalName) => {
      if (quoted) return match;
      if (interpolationExpr !== undefined) {
        return `\${${interpolationExpr.replace(
          /\$([a-zA-Z_\d]\w*(?:[.-]\w+)*)/g,
          (_, innerSignalName) =>
            innerSignalName
              .split(".")
              .reduce((acc, part) => `${acc}['${part}']`, "$"),
        )}}`;
      }
      return signalName
        .split(".")
        .reduce((acc, part) => `${acc}['${part}']`, "$");
    },
  );

  expr = expr.replaceAll(/@([A-Za-z_$][\w$]*)\(/g, '__action("$1",evt,');

  // Replace any escaped values
  for (const [k, v] of escaped) {
    expr = expr.replace(k, v);
  }

  return ["el", "$", "__action", "evt", ...argNames, expr];
};

console.log(genRx("@post('/api/counter/increment')"));
