(() => {

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
  // filter is opt-in (activated only when a precompile script calls
  // __ds_bloom_add); the blessing check is always active.
  const blessed = new WeakSet();
  const cursed = new WeakSet();
  let blessingEnabled = false;

  blessed.add(document.documentElement);

  const mo = new MutationObserver((records) => {
    for (const r of records) {
      for (const node of r.addedNodes) {
        if (node.nodeType === 1 && !blessingEnabled && isBlessed(node)) {
          cursed.add(node);
        }
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
    window.__datastar_precompiled_expressions || new Map());

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
  // Our listener is registered before Datastar's (classic script vs deferred
  // module), so stopImmediatePropagation prevents Datastar from seeing the
  // original event.
  const loadedScripts = new Set();

  // Two independent 32-bit FNV-1a hashes with different seeds → effective 64-bit key.
  // Avoids storing full (potentially large) signed URLs in the set.
  function urlKey(s) {
    let h0 = 0x811c9dc5,
      h1 = 0xdeadbeef;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      h0 = Math.imul(h0 ^ c, 16777619);
      h1 = Math.imul(h1 ^ c, 16777619);
    }
    return (h0 >>> 0).toString(36) + "_" + (h1 >>> 0).toString(36);
  }

  function loadScript(url) {
    const key = urlKey(url);
    if (loadedScripts.has(key)) {
      // Script already loaded. Still register the current page nonce in case
      // it hasn't been added yet (e.g. the initial page had no expressions,
      // so no <script> was injected).
      window.__ds_bloom_add?.(
        document.querySelector('meta[name="datastargostrictcsp-ds-nonce"]')
          ?.content,
      );
      return Promise.resolve();
    }
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
  // The server always emits a space before --> so \S+ cleanly stops at the right boundary.
  const COMMENT_RE =
    /^<!--\s*(?:ds-nonce:\s*(\S+))?\s*(?:precompile-url:\s*(\S+))?\s*-->\n?/;

  document.addEventListener("datastar-fetch", (evt) => {
    if (evt.detail.type !== "datastar-patch-elements") return;
    const argsRaw = evt.detail.argsRaw;

    // SSE path: register nonce immediately so bloom checks pass on patched elements.
    if (argsRaw.dsNonce) {
      window.__ds_bloom_add?.(argsRaw.dsNonce);
      delete argsRaw.dsNonce;
    }

    let urls = null;
    if (argsRaw.precompileUrl) {
      // SSE path: precompile URLs in a data: precompileUrl field.
      urls = argsRaw.precompileUrl.split(" ");
      delete argsRaw.precompileUrl;
    } else if (argsRaw.elements) {
      // text/html path: one comment per URL (nonce on the first), consume all.
      urls = [];
      let rest = argsRaw.elements;
      for (let m; (m = rest.match(COMMENT_RE)) && (m[1] || m[2]); ) {
        if (m[1]) window.__ds_bloom_add?.(m[1]);
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
