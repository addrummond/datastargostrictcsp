(() => {

  // Blessed/cursed element registry
  //
  // document.documentElement is the single blessed seed — all initial page
  // content inherits blessing lazily by walking up to it. When the
  // MutationObserver fires, the root of each inserted subtree is added to
  // `blessed` (Datastar-controlled patch, blessingEnabled=true) or `cursed`
  // (any other insertion). isEffectivelyBlessed walks up the ancestor chain:
  // a cursed ancestor wins even if a blessed ancestor lies higher, so injected
  // subtrees nested inside legitimate content are still blocked. Path
  // compression caches an intermediate ancestor after 5 steps to amortise
  // future walks on deep trees.
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
        if (node.nodeType === 1) {
          // If it's not blessed then it already has a cursed parent (given
          // that doc root is blessed). As cursed status always wins, adding
          // the element to either the blessed or cursed sets won't make a
          // difference.
          if (!isBlessed(node)) continue;
          if (blessingEnabled) blessed.add(node);
          else cursed.add(node);
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

  window.Function = new Proxy(_Function, {
    apply: function (_t, _th, args) {
      const fn = p.get(JSON.stringify(args));
      if (!fn) return new _Function(...args);
      return checked(fn);
    },
    construct: function (_t, args) {
      const fn = p.get(JSON.stringify(args));
      if (!fn) return new _Function(...args);
      return checked(fn);
    },
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

  const COMMENT_RE = /^<!--\s*precompile-url:\s*(.*?)\s*-->\n?/;

  document.addEventListener("datastar-fetch", (evt) => {
    if (evt.detail.type !== "datastar-patch-elements") return;
    const argsRaw = evt.detail.argsRaw;

    let urls;
    if (argsRaw.precompileUrl) {
      // SSE path: precompile URLs in a data: precompileUrl field.
      urls = argsRaw.precompileUrl.split(" ");
      delete argsRaw.precompileUrl;
    } else if (argsRaw.elements) {
      // text/html path: precompile URLs embedded as an HTML comment.
      const m = argsRaw.elements.match(COMMENT_RE);
      if (!m) return;
      urls = m[1].split(" ");
      argsRaw.elements = argsRaw.elements.slice(m[0].length);
    } else {
      return;
    }

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
