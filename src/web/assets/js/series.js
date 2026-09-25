/*
 * Movement since the page was opened. Every counter row of the Metrics
 * section carries its figure (div[data-series][data-v]); it is sampled on
 * load and after every background refresh, and a row whose counter moved
 * gets a "+N since open" note under its value, briefly highlighted when it
 * moved in the latest round (not with reduced motion).
 *
 * The page's own refreshes are web-interface requests too, and move the
 * rows marked data-polled by one each: those rows count from the first
 * figures a refresh brought (after the page's assets loaded) and discount
 * the page's own fetches those figures count, so an idle daemon reads idle.
 * Other viewers' polls still count.
 *
 * Only a page with auto-refresh on samples more than once. A daemon restart
 * (the Metrics section's data-started changes) resets the counters, so the
 * samples start over. Without script the rows keep their "last: 3 h ago".
 */
(function () {
  "use strict";

  const HISTORY = 40;

  /* key -> { label, unit, base, samples: [values] } */
  let series = new Map();
  let started = null;

  function startedAt() {
    const node = document.querySelector("[data-started]");
    return node ? node.getAttribute("data-started") : null;
  }

  function format(value, unit) {
    return unit === "B" ? ACR.size(value) : ACR.count(value);
  }

  function rows() {
    return ACR.all(document, "[data-section=metrics] div[data-series][data-v]");
  }

  function sample() {
    const now = startedAt();
    if (now !== started) {
      series = new Map();
      started = now;
    }
    // The fetches counted in the figures on screen, not the fetches so far:
    // a section the refresh left alone (refresh.js `busy`) still shows an
    // older round's.
    const refresh = ACR.api("refresh");
    const section = document.querySelector("[data-section=metrics]");
    const polls = refresh && section ? refresh.polls(section) : 0;
    for (const row of rows()) {
      const key = row.getAttribute("data-series");
      const polled = row.hasAttribute("data-polled");
      const raw = Number(row.getAttribute("data-v"));
      if (!Number.isFinite(raw)) {
        continue;
      }
      const value = polled ? raw - polls : raw;
      let entry = series.get(key);
      if (!entry) {
        const dt = row.querySelector("dt");
        entry = {
          label: dt ? dt.textContent : key,
          unit: row.getAttribute("data-unit"),
          base: value,
          samples: [],
          // A polled row's load-time figure predates the page's own
          // asset requests: it counts from the first refreshed figure.
          settled: !polled || polls > 0
        };
        series.set(key, entry);
      } else if (!entry.settled && polls > 0) {
        entry.base = value;
        entry.samples = [];
        entry.settled = true;
      }
      // A section the refresh left alone (refresh.js `busy`) repeats its
      // last figure: a flat step, never a false one.
      entry.samples.push(value);
      if (entry.samples.length > HISTORY) {
        entry.samples.shift();
      }
    }
  }

  function annotate() {
    for (const row of rows()) {
      const entry = series.get(row.getAttribute("data-series"));
      const old = row.querySelector(":scope > dd.delta");
      if (old) {
        old.remove();
      }
      if (!entry) {
        continue;
      }
      const latest = entry.samples[entry.samples.length - 1];
      const moved = latest - entry.base;
      if (moved <= 0) {
        continue;
      }
      const step = entry.samples.length > 1 ? latest - entry.samples[entry.samples.length - 2] : 0;
      const note = ACR.el("dd", {
        class: step > 0 ? "delta moved" : "delta",
        title: "Moved since this page was opened"
      }, "+" + format(moved, entry.unit) + " since open");
      const value = row.querySelector(":scope > dd");
      if (value) {
        value.after(note);
      }
    }
  }

  ACR.feature("series", {
    refreshed: function () {
      if (ACR.page() !== "dashboard") {
        return;
      }
      sample();
      annotate();
    }
  });
})();
