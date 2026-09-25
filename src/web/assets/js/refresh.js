/*
 * Background refresh: with `refresh=N` in the URL, re-fetch this same page
 * every N seconds and swap its [data-section] blocks in place, instead of the
 * full reload the <noscript> meta tag does. What a reload would lose stays:
 * opened and closed sections, the scroll position, sort order and filters,
 * a text selection. The nav's auto-refresh link toggles it without a reload.
 *
 * A section is left alone for one round while it holds keyboard focus or a
 * text entry, a selection, or an open "?" explanation; hidden tabs are not
 * refreshed at all, and catch up once shown. A failed fetch keeps the page as
 * it is and retries with a growing delay, up to five minutes.
 */
(function () {
  "use strict";

  const MAX_BACKOFF_MS = 5 * 60 * 1000;
  const FETCH_TIMEOUT_MS = 30 * 1000;

  let timer = null;
  let inFlight = false;
  let overdue = false;
  let failures = 0;
  let status = null;
  let failure = null;

  /* ---- Fetching and swapping ------------------------------------------- */

  /* GET `url` as a parsed document. XHR's document parsing is not a Trusted
   * Types sink, so this needs no policy; the result is inert (its scripts
   * never run) until nodes are adopted. */
  function fetchPage(url, done) {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url);
    xhr.responseType = "document";
    xhr.timeout = FETCH_TIMEOUT_MS;
    xhr.addEventListener("load", function () {
      const doc = xhr.response;
      if (xhr.status === 200 && doc && doc.body) {
        done(null, doc);
      } else {
        done("HTTP " + xhr.status, null);
      }
    });
    xhr.addEventListener("error", function () {
      done("network error", null);
    });
    xhr.addEventListener("timeout", function () {
      done("timed out", null);
    });
    xhr.send();
  }

  function topSections(doc) {
    const map = new Map();
    for (const node of Array.prototype.slice.call(doc.body.children)) {
      const key = node.getAttribute("data-section");
      if (key) {
        map.set(key, node);
      }
    }
    return map;
  }

  /* Input types a reader types into. */
  const TEXT_ENTRY = /^(text|search|number|email|url|tel|password)$/;

  /* Whether a section is busy for the reader: swapping it would steal a
   * caret, drop a selection or close what they are reading. Focus counts
   * when it is a text entry or keyboard focus (:focus-visible), not the
   * leftover focus of a clicked button, checkbox or select. */
  function busy(section) {
    const active = document.activeElement;
    if (active && active !== document.body && section.contains(active)) {
      const tag = active.tagName;
      if (tag === "TEXTAREA" || (tag === "INPUT" && TEXT_ENTRY.test(active.type))) {
        return true;
      }
      try {
        if (active.matches(":focus-visible")) {
          return true;
        }
      } catch (err) {
        return true;
      }
    }
    // Any part of a selection: one spanning several sections holds each of
    // them (their common ancestor is the body, which no section contains).
    const selection = window.getSelection ? window.getSelection() : null;
    if (selection && !selection.isCollapsed) {
      for (let i = 0; i < selection.rangeCount; i += 1) {
        if (selection.getRangeAt(i).intersectsNode(section)) {
          return true;
        }
      }
    }
    return section.querySelector("dd.help details[open]") !== null;
  }

  /* Sections the reader opened or closed on this page, by key: their
   * choice wins over the server's default (a row section renders open once
   * it has rows). A section the reader never touched takes what the server
   * renders, as a reload would. */
  const chosen = new Map();

  function carryDetails(key, to) {
    const details = to.querySelector(":scope > details");
    if (details && chosen.has(key) && details.open !== chosen.get(key)) {
      details.open = chosen.get(key);
    }
  }

  /* Set once the refresh feature took over keeping sections open. */
  let keepsSections = false;

  /* The keep-open links have nothing left to do once this feature keeps
   * sections open (and `open=` records the ones the reader opened). They go
   * from the DOM, not only from view, before a swapped-in section is
   * inserted: a link inside a <summary> is interactive content assistive
   * technology cannot reach there. */
  function dropPins(root) {
    if (!keepsSections) {
      return;
    }
    for (const pin of ACR.all(root, "a.pin")) {
      pin.remove();
    }
  }

  /* Whether `doc` links other asset versions than this page: the daemon
   * was upgraded since the page loaded, and its markup may need the new
   * script and stylesheet (assets.rs serves each version under its own
   * URL). */
  function staleAssets(doc) {
    return [["link[rel=stylesheet]", "href"], ["script[src]", "src"]].some(function (pair) {
      const mine = document.querySelector(pair[0]);
      const theirs = doc.querySelector(pair[0]);
      return mine !== null && theirs !== null && mine.getAttribute(pair[1]) !== theirs.getAttribute(pair[1]);
    });
  }

  /* Swap the sections of `doc` into this page, keeping the reader's place,
   * then let the features enhance what came in. A section that is busy
   * (see `busy`) keeps its old content until the next round. A page from
   * another build is loaded in full instead: the URL carries its state. */
  function swap(doc) {
    if (staleAssets(doc)) {
      window.location.reload();
      return;
    }
    ACR.keepScroll(function () {
      const current = topSections(document);
      const fresh = topSections(doc);
      const swapped = [];
      for (const [key, node] of current) {
        if (!fresh.has(key)) {
          node.remove();
        }
      }
      let previous = null;
      for (const [key, incoming] of fresh) {
        const old = current.get(key);
        if (old && busy(old)) {
          previous = old;
          continue;
        }
        const node = document.adoptNode(incoming);
        dropPins(node);
        if (old) {
          carryDetails(key, node);
          old.replaceWith(node);
        } else if (previous) {
          previous.after(node);
        } else {
          document.body.prepend(node);
        }
        swapped.push(node);
        previous = node;
      }
      if (doc.title) {
        document.title = doc.title;
      }
      for (const node of swapped) {
        ACR.run("enhance", node);
      }
      ACR.run("refreshed");
    });
  }

  /* ---- The auto-refresh loop -------------------------------------------- */

  function interval() {
    return ACR.state().refresh;
  }

  function schedule() {
    if (timer !== null) {
      window.clearTimeout(timer);
      timer = null;
    }
    const secs = interval();
    // Only the dashboard auto-refreshes: /logs is read as a tail, and its
    // Dashboard link carries refresh= along only for the way back.
    if (!secs || ACR.page() !== "dashboard") {
      return;
    }
    const base = secs * 1000;
    const delay = failures === 0 ? base : Math.min(MAX_BACKOFF_MS, base * Math.pow(2, failures));
    timer = window.setTimeout(tick, delay);
  }

  function tick() {
    timer = null;
    if (document.hidden) {
      overdue = true;
      return;
    }
    refreshNow();
  }

  function refreshNow() {
    if (inFlight) {
      return;
    }
    inFlight = true;
    overdue = false;
    fetchPage(window.location.pathname + window.location.search, function (err, doc) {
      inFlight = false;
      if (err === null) {
        failures = 0;
        swap(doc);
        showStatus(null);
      } else {
        failures += 1;
        showStatus(err);
      }
      schedule();
    });
  }

  /* ---- The nav: status line and the toggle link -------------------------- */

  function ensureStatus() {
    const nav = document.querySelector("[data-section=nav]");
    if (!nav) {
      return;
    }
    if (!status) {
      status = ACR.el("span", { class: "refresh-status" });
      failure = ACR.el("span", { class: "refresh-failure", role: "status" });
    }
    const spacer = nav.querySelector(".spacer");
    if (status.parentNode !== nav) {
      nav.insertBefore(status, spacer);
      nav.insertBefore(failure, spacer);
    }
  }

  function showStatus(err) {
    ensureStatus();
    if (!status) {
      return;
    }
    const now = ACR.clock(new Date());
    if (err === null) {
      status.textContent = interval() ? "updated " + now : "";
      failure.textContent = "";
    } else {
      failure.textContent = "update failed " + now + " (" + err + "), retrying";
    }
  }

  function refreshLabel(st, secs) {
    return st.refresh ? "Stop auto-refresh (" + st.refresh + "s)" : "Auto-refresh (" + secs + "s)";
  }

  /* Links whose query mirrors the page state follow it, so opening one in a
   * new tab (or with scripts off) lands on the same view. */
  function syncLinks() {
    const st = ACR.state();
    for (const link of ACR.all(document, "a[data-carry]")) {
      const path = new URL(link.href, window.location.href).pathname;
      link.setAttribute("href", ACR.href(path, st));
    }
    for (const link of ACR.all(document, "a[data-action=refresh-toggle]")) {
      const secs = Number(link.getAttribute("data-secs")) || 30;
      const next = Object.assign({}, st, { refresh: st.refresh ? null : secs });
      link.setAttribute("href", ACR.href(window.location.pathname, next));
      link.textContent = refreshLabel(st, secs);
    }
  }

  function toggle(link) {
    const st = ACR.state();
    const secs = Number(link.getAttribute("data-secs")) || 30;
    st.refresh = st.refresh ? null : secs;
    failures = 0;
    ACR.setState(st);
    schedule();
    showStatus(null);
  }

  ACR.feature("refresh", {
    init: function () {
      if (ACR.page() !== "dashboard") {
        return;
      }
      document.addEventListener("click", function (event) {
        const link = event.target.closest ? event.target.closest("a[data-action=refresh-toggle]") : null;
        if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
          return;
        }
        event.preventDefault();
        toggle(link);
      });
      document.addEventListener("visibilitychange", function () {
        if (!document.hidden && overdue) {
          refreshNow();
        }
      });
      // The reader's section choice is kept across refreshes, and an opened
      // section rides in `open=` like the keep-open links would have put
      // it, so a reload or a shared link opens it too (`open=` cannot say
      // "closed": a row section with rows renders open on a reload). Only a
      // reader's toggle counts: a summary click (keyboard activation clicks
      // too), never the toggle events of sections that render open.
      document.addEventListener("click", function (event) {
        const summary = event.target.closest ? event.target.closest("summary") : null;
        const details = summary ? summary.parentNode : null;
        const section = details ? details.parentNode : null;
        if (!section || details.tagName !== "DETAILS" || !section.hasAttribute("data-section") ||
            section.parentNode !== document.body || event.target.closest("a")) {
          return;
        }
        // The click's default action toggles after the listeners ran.
        const opening = !details.open;
        const key = section.getAttribute("data-section");
        chosen.set(key, opening);
        const st = ACR.state();
        st.open = st.open.filter(function (k) {
          return k !== key;
        });
        if (opening) {
          st.open.push(key);
        }
        ACR.setState(st);
      });
      ACR.onState(syncLinks);
      keepsSections = true;
      schedule();
    },
    enhance: dropPins,
    refreshed: function () {
      if (ACR.page() === "dashboard") {
        ensureStatus();
        syncLinks();
      }
    }
  });

  ACR.expose("refresh", { fetchPage: fetchPage, swap: swap, now: refreshNow });
})();
