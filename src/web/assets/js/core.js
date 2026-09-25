/*
 * apt-cacher-rs web interface: shared helpers for the optional scripts.
 *
 * The pages are complete without any script: every figure is server-rendered
 * text, sections open from `open=`, the nav links carry `refresh=`/`theme=`
 * and a <noscript> meta tag reloads the page. The files under js/ only
 * enhance that markup, and they run under a strict Content-Security-Policy
 * with Trusted Types enforced, so:
 *
 * - DOM is built with createElement/createElementNS and textContent only
 *   (`el`, `svg` below); never an HTML-parsing sink.
 * - No inline style: state is shown through classes, `hidden`, aria-* and
 *   data-* attributes, and SVG geometry attributes.
 * - Every file after this one is an IIFE registering with `ACR.feature`, so
 *   one feature failing leaves the others running.
 */
"use strict";

const ACR = (function () {
  const root = document.documentElement;
  // Before any feature runs, so the stylesheet's `.js` rules apply to the
  // scripted page as early as a deferred script can mark it.
  root.classList.add("js");

  const STORAGE_PREFIX = "apt-cacher-rs.";
  const SVG_NS = "http://www.w3.org/2000/svg";

  /* Browser storage for per-viewer conveniences (theme, sort order). Every
   * access may throw (disabled storage, private windows), and a missing
   * value must never break the page. */
  const store = Object.freeze({
    get: function (key) {
      try {
        return window.localStorage.getItem(STORAGE_PREFIX + key);
      } catch (err) {
        return null;
      }
    },
    set: function (key, value) {
      try {
        window.localStorage.setItem(STORAGE_PREFIX + key, value);
      } catch (err) {
        /* storage unavailable: the convenience is simply not remembered */
      }
    },
    remove: function (key) {
      try {
        window.localStorage.removeItem(STORAGE_PREFIX + key);
      } catch (err) {
        /* storage unavailable */
      }
    }
  });

  /* Attribute names a builder must never set: inline styles are refused by
   * the CSP anyway, and event-handler attributes would be inline script. */
  function checkAttr(name) {
    const lower = name.toLowerCase();
    if (lower === "style" || lower.startsWith("on") || lower === "srcdoc") {
      throw new Error("refusing attribute " + name);
    }
  }

  function setAttrs(node, attrs) {
    if (!attrs) {
      return node;
    }
    for (const name of Object.keys(attrs)) {
      const value = attrs[name];
      if (value === undefined || value === null || value === false) {
        continue;
      }
      checkAttr(name);
      node.setAttribute(name, value === true ? "" : String(value));
    }
    return node;
  }

  /* An HTML element with attributes and optional text content. */
  function el(tag, attrs, text) {
    const node = setAttrs(document.createElement(tag), attrs);
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  /* An SVG element; geometry goes in attributes, colour in classes. */
  function svg(tag, attrs) {
    return setAttrs(document.createElementNS(SVG_NS, tag), attrs);
  }

  function all(scope, selector) {
    return Array.prototype.slice.call(scope.querySelectorAll(selector));
  }

  /* The block a node belongs to: the top-level element carrying
   * data-section, which the background refresh swaps as a whole. */
  function sectionOf(node) {
    return node && node.closest ? node.closest("[data-section]") : null;
  }

  /* Run `change`, which may grow or shrink blocks above the reader, and
   * scroll so the first block on screen stays where it was. The page opts
   * out of the browser's own scroll anchoring (style.css), which loses its
   * anchor when the block holding it is replaced. */
  function keepScroll(change) {
    let anchor = null;
    for (const node of all(document, "body > [data-section]")) {
      const rect = node.getBoundingClientRect();
      if (rect.bottom > 0) {
        anchor = { key: node.getAttribute("data-section"), top: rect.top };
        break;
      }
    }
    const result = change();
    if (anchor) {
      const now = document.querySelector("body > [data-section=" + anchor.key + "]");
      if (now) {
        const delta = now.getBoundingClientRect().top - anchor.top;
        if (delta !== 0) {
          window.scrollBy({ top: delta, left: 0, behavior: "instant" });
        }
      }
    }
    return result;
  }

  /* ---- URL state -------------------------------------------------------
   * The page's state lives in its query string exactly as the server reads
   * it (page.rs `parse_query`): refresh=1..3600, theme=light|dark|auto,
   * open=<section,...>. Scripts change it with history.replaceState, so a
   * reload, a bookmark or a copied link shows the same page without script. */

  /* Mirrors `parse_query` rule for rule: `&`-separated raw pairs (no
   * percent-decoding), the last occurrence of a key wins, an unknown value
   * is ignored, and a query past 256 bytes is ignored as a whole. */
  const MAX_QUERY_LEN = 256;

  function parseState(search) {
    const state = { refresh: null, theme: null, open: [] };
    const query = search.charAt(0) === "?" ? search.slice(1) : search;
    if (query.length > MAX_QUERY_LEN) {
      return state;
    }
    for (const pair of query.split("&")) {
      const at = pair.indexOf("=");
      if (at < 0) {
        continue;
      }
      const key = pair.slice(0, at);
      const value = pair.slice(at + 1);
      if (key === "refresh") {
        // Rust's u32 parse: an optional `+`, then digits.
        if (/^\+?[0-9]+$/.test(value)) {
          const secs = Number(value);
          if (secs >= 1 && secs <= 3600) {
            state.refresh = secs;
          }
        }
      } else if (key === "theme") {
        if (value === "light" || value === "dark" || value === "auto") {
          state.theme = value;
        }
      } else if (key === "open") {
        state.open = value.split(",").filter(function (name) {
          return /^[a-z-]+$/.test(name);
        });
      }
    }
    return state;
  }

  function state() {
    return parseState(window.location.search);
  }

  /* Section keys in page order, so `open=` reads the same as the server
   * renders it. */
  function sectionOrder() {
    return all(document, "[data-section]").map(function (node) {
      return node.getAttribute("data-section");
    });
  }

  function query(st) {
    const parts = [];
    if (st.refresh) {
      parts.push("refresh=" + st.refresh);
    }
    if (st.theme) {
      parts.push("theme=" + st.theme);
    }
    if (st.open.length > 0) {
      const order = sectionOrder();
      const open = st.open.slice().sort(function (a, b) {
        return order.indexOf(a) - order.indexOf(b);
      });
      parts.push("open=" + open.join(","));
    }
    return parts.length > 0 ? "?" + parts.join("&") : "";
  }

  function href(path, st) {
    return path + query(st);
  }

  const listeners = { state: [] };

  /* Replace the page's query string and tell the features about it. */
  function setState(st) {
    const url = href(window.location.pathname, st) + window.location.hash;
    window.history.replaceState(window.history.state, "", url);
    for (const listener of listeners.state) {
      listener(st);
    }
  }

  function onState(listener) {
    listeners.state.push(listener);
  }

  /* ---- Features ----------------------------------------------------------
   * A feature is an object with optional hooks:
   *   init()          once, after the page is parsed;
   *   enhance(root)   for the document at start, then for every section a
   *                   background refresh swapped in;
   *   refreshed()     after every completed refresh, and once at start. */

  const features = [];

  function feature(name, hooks) {
    features.push({ name: name, hooks: hooks });
  }

  /* What one feature offers the others (the refresh loop's fetch-and-swap,
   * say), looked up by name once the page runs. */
  const apis = new Map();

  function expose(name, value) {
    apis.set(name, Object.freeze(value));
  }

  function api(name) {
    return apis.get(name) || null;
  }

  function run(hook, arg) {
    for (const entry of features) {
      const fn = entry.hooks[hook];
      if (typeof fn !== "function") {
        continue;
      }
      try {
        fn(arg);
      } catch (err) {
        window.console.error("apt-cacher-rs: " + entry.name + "." + hook + " failed", err);
      }
    }
  }

  function start() {
    run("init");
    run("enhance", document);
    run("refreshed");
  }

  // A deferred script runs before DOMContentLoaded, so every feature file in
  // this bundle has registered by the time this fires.
  document.addEventListener("DOMContentLoaded", start);

  /* ---- Formatting ---------------------------------------------------------
   * The server's renderings (web/fmt.rs, humanfmt.rs), for figures a script
   * computes itself. */

  /* `Count`: digit groups from five digits on, narrow no-break spaces. */
  function count(value) {
    const text = String(Math.round(value));
    if (text.length < 5) {
      return text;
    }
    return text.replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f");
  }

  /* `HumanFmt::Size`: decimal units, three significant figures. */
  function size(bytes) {
    if (bytes < 1000) {
      return Math.round(bytes) + "B";
    }
    const units = ["kB", "MB", "GB", "TB"];
    let value = bytes;
    for (let i = 0; i < units.length; i += 1) {
      value /= 1000;
      if (value < 999.5 || i === units.length - 1) {
        const digits = value > 100 ? 0 : value > 10 ? 1 : 2;
        return value.toFixed(digits) + units[i];
      }
    }
    return String(bytes);
  }

  /* `fmt::Age`: the most significant unit only. */
  function age(secs) {
    const s = Math.max(0, Math.floor(secs));
    if (s < 60) {
      return s + " s";
    }
    if (s < 3600) {
      return Math.floor(s / 60) + " min";
    }
    if (s < 86400) {
      return Math.floor(s / 3600) + " h";
    }
    return Math.floor(s / 86400) + " d";
  }

  /* hh:mm:ss UTC, the page's time zone ("All dates are in UTC"). */
  function clock(date) {
    return date.toISOString().slice(11, 19) + " UTC";
  }

  return Object.freeze({
    store: store,
    el: el,
    svg: svg,
    all: all,
    sectionOf: sectionOf,
    keepScroll: keepScroll,
    state: state,
    parseState: parseState,
    href: href,
    setState: setState,
    onState: onState,
    feature: feature,
    expose: expose,
    api: api,
    run: run,
    page: function () {
      return document.body ? document.body.getAttribute("data-page") : null;
    },
    count: count,
    size: size,
    age: age,
    clock: clock
  });
})();
