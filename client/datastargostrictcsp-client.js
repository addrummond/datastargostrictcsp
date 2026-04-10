(() => {
  // <nonce_check>
  // Nonce bloom filter
  //
  // Tracks per-render nonces from precompile scripts. We reject expression
  // invocations on elements whose data-ds-nonce is not in the filter.
  // This is primarily a protection against server-side injection (handling
  // the case where an attacker has injected an existing precompiled attribute),
  // but it also adds an additional layer of protection against client-side
  // injection.
  //
  // Two rotating bloom filters, each m=2^14 bits (2 KB), k=9.
  // Insertions go into `cur`; after 1000 insertions `cur` and `old` swap and
  // the newly-demoted filter is cleared. Membership tests check both filters,
  // so the effective window always covers the last ~2000 nonces.
  // FP rate: ~0.04% at 1000 nonces per filter.
  const M = 1 << 14;
  let cur = new Int32Array(M >> 5); // 512 × Int32 = 2 KB, current window
  let old = new Int32Array(M >> 5); // 512 × Int32 = 2 KB, previous window
  let insertCount = 0;
  let nonceCheckActive = false;

  function bloomOp(filter, s, write) {
    for (let i = 0; i < 9; i++) {
      let h = i * 2654435761;
      for (let j = 0; j < s.length; j++)
        h = Math.imul(h ^ s.charCodeAt(j), 16777619);
      h = (h >>> 0) & (M - 1);
      if (write) filter[h >> 5] |= 1 << (h & 31);
      else if (!(filter[h >> 5] & (1 << (h & 31)))) return false;
    }
    return true;
  }

  function bloomHas(s) {
    return bloomOp(cur, s, false) || bloomOp(old, s, false);
  }

  function bloomAdd(nonce) {
    if (!nonce) return;
    if (++insertCount > 1000) {
      old.fill(0);
      const tmp = old;
      old = cur;
      cur = tmp;
      insertCount = 1;
    }
    bloomOp(cur, nonce, true);
    nonceCheckActive = true;
  }

  bloomAdd(
    document.querySelector('meta[name="datastargostrictcsp-ds-nonce"]')
      ?.content,
  );

  let lastNonce = ""; // fast path: skip bloom lookup when nonce matches last valid hit
  // </nonce_check>

  // Blessed/cursed element registry
  //
  // document.documentElement is the single blessed seed — all initial DOM nodes
  // inherit blessing by walking up to it. When the MutationObserver fires, the
  // root of each inserted subtree is added to `cursed` if it is not inserted
  // via a legitimate Datastar patching operation. The isBlessed function walks
  // up the ancestor chain, looking for either a blessed or a cursed ancestor.
  // To make repeated checks faster, we add the 5th ancestor of a
  // blessed/cursed node to the blessed/cursed set after the initial walk to
  // the blessed/cursed ancestor.
  //
  // This protection is complementary to the nonce bloom filter: the nonce
  // filter is opt-in; the blessing check is always active.
  const blessed = new WeakSet();
  const cursed = new WeakSet();
  let blessingEnabled = false;

  blessed.add(document.documentElement);

  const mo = new MutationObserver((records) => {
    if (blessingEnabled) return;
    for (const r of records) {
      for (const node of r.addedNodes) {
        if (node.nodeType === 1) cursed.add(node);
      }
    }
  });
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () =>
      mo.observe(document.documentElement, { childList: true, subtree: true }),
    );
  } else {
    mo.observe(document.documentElement, { childList: true, subtree: true });
  }

  function isBlessed(el) {
    let node = el;
    let steps = 0;
    let midpoint = null;
    while (node && node.nodeType === 1) {
      if (steps === 5) midpoint = node;
      if (cursed.has(node)) {
        if (midpoint) cursed.add(midpoint);
        return false;
      }
      if (blessed.has(node)) {
        // Two situations to think about here:
        //   (i)  A cursed node later gets added *within* midpoint. In that case, the walk from that node will reach the cursed node first.
        //   (ii) A cursed node later gets added *above* midpoint. In that case, midpoint will have been replaced with a new subtree, so won't be visited on the walk.
        if (midpoint) blessed.add(midpoint);
        return true;
      }
      node = node.parentElement;
      steps++;
    }
    return false;
  }

  // Wrap fn so blessing and nonce checks run at invocation time (when el is available).
  function checked(fn) {
    return function (el) {
      // <nonce_check>
      if (nonceCheckActive) {
        const nonce = (el && el.dataset && el.dataset.dsNonce) ?? "";
        if (nonce !== lastNonce) {
          if (!bloomHas(nonce)) {
            console.error(
              "[datastarstrictcsp] nonce check failed: expression blocked on element:",
              el,
            );
            return;
          }
          lastNonce = nonce;
        }
      }
      // </nonce_check>
      if (!isBlessed(el)) {
        console.error(
          "[datastarstrictcsp] element not blessed: expression blocked on element:",
          el,
        );
        return;
      }
      return fn.apply(this, arguments);
    };
  }

  // Function proxy
  //
  // Intercepts new Function(...) calls so Datastar uses precompiled functions
  // from window.__datastar_precompiled_expressions instead of eval-ing expressions at runtime.
  const _Function = Function;
  const p = (window.__datastar_precompiled_expressions =
    window.__datastar_precompiled_expressions ?? new Map());

  function proxyHandler(args) {
    const fn = p.get(JSON.stringify(args));
    return fn ? checked(fn) : new _Function(...args);
  }
  window.Function = new Proxy(_Function, {
    apply: (_t, _th, args) => proxyHandler(args),
    construct: (_t, args) => proxyHandler(args),
  });

  // Precompile interceptor
  //
  // Datastar dispatches a datastar-fetch CustomEvent before applying any patch.
  // We intercept datastar-patch-elements events that carry a precompile signal —
  // either argsRaw.precompileUrl (SSE path, added as a data: field) or an HTML
  // comment at the top of argsRaw.elements (text/html path, added by Middleware).
  // We load the precompile script(s), then re-dispatch the cleaned event so
  // Datastar applies the patch with all expressions already registered.
  //
  // Our listener is registered before Datastar's, so stopImmediatePropagation
  // prevents Datastar from seeing the original event.
  const loadedScripts = new Set();

  function loadScript(url) {
    const key = url.slice(url.lastIndexOf("&sig=") + 5);
    if (loadedScripts.has(key)) return Promise.resolve();
    loadedScripts.add(key);
    return new Promise((resolve) => {
      const s = document.createElement("script");
      s.src = url;
      s.onload = resolve;
      s.onerror = resolve; // fail open: patch proceeds even if script 404s
      document.head.appendChild(s);
    });
  }

  // Matches <!-- [ds-nonce: NONCE] [precompile-url: URL] --> (capture 1: nonce, capture 2: URL).
  // Both parts are optional but at least one must be present (checked in code).
  const COMMENT_RE =
    /^<!--\s*(?:ds-nonce:\s*(\S+))?\s*(?:precompile-url:\s*(\S+))?\s*-->\n?/;

  document.addEventListener("datastar-fetch", (evt) => {
    if (evt.detail.type !== "datastar-patch-elements") return;
    const argsRaw = evt.detail.argsRaw;

    // <nonce_check>
    // SSE path: register nonce immediately so bloom checks pass on patched elements.
    if (argsRaw.dsNonce) {
      bloomAdd(argsRaw.dsNonce);
      delete argsRaw.dsNonce;
    }
    // </nonce_check>

    let urls = null;
    if (argsRaw.precompileUrl) {
      // SSE path: precompile URLs in a data: precompileUrl field.
      urls = argsRaw.precompileUrl.split(" ");
      delete argsRaw.precompileUrl;
    } else if (argsRaw.elements) {
      // text/html path: one comment per URL (nonce on the first), consume all.
      urls = [];
      let rest = argsRaw.elements;
      for (let m; (m = rest.match(COMMENT_RE)) && (m[1] ?? m[2]); ) {
        // <nonce_check>
        if (m[1]) bloomAdd(m[1]);
        // </nonce_check>
        if (m[2]) urls.push(m[2]);
        rest = rest.slice(m[0].length);
      }
      argsRaw.elements = rest;
      if (!urls.length) urls = null;
    }

    if (!urls) return;

    evt.stopImmediatePropagation();

    Promise.all(urls.map(loadScript)).then(() => {
      blessingEnabled = true;
      document.dispatchEvent(
        new CustomEvent("datastar-fetch", {
          detail: {
            type: "datastar-patch-elements",
            el: evt.detail.el,
            argsRaw: argsRaw,
          },
        }),
      );
      // MutationObserver callbacks are microtasks; setTimeout (macrotask)
      // fires after them, so newly patched elements are blessed before we
      // close the window.
      setTimeout(() => (blessingEnabled = false), 0);
    });
  });
})();
