/*
 * Movement since the page was opened. Every counter row of the Metrics
 * section carries its figure (div[data-series][data-v]); it is sampled on
 * load and after every background refresh, and
 *
 * - a row whose counter moved gets a "+N since open" note under its value,
 *   briefly highlighted when it moved in the latest round (not with
 *   reduced motion);
 * - the "Activity since page open" panel under the hero lists every
 *   counter that moved, with a sparkline of its movement per refresh (the
 *   last 40 rounds), so the busy counters can be read in one place. Away
 *   from their group a label like "2xx" or "Other" is ambiguous, so the
 *   panel names each by its series key: the row's path (group, total,
 *   label), which the server renders unique.
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
  let panel = null;

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
        entry = {
          label: key,
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

  /* A sparkline of the per-refresh increments. Hidden from assistive
   * technology: the figure beside it carries the information, the line
   * only its shape. */
  function sparkline(samples) {
    const width = 100;
    const height = 20;
    const steps = [];
    for (let i = 1; i < samples.length; i += 1) {
      steps.push(Math.max(0, samples[i] - samples[i - 1]));
    }
    const max = Math.max.apply(null, steps.concat([1]));
    const points = steps.map(function (step, i) {
      const x = steps.length === 1 ? width : (i * width) / (steps.length - 1);
      const y = height - 1 - (step / max) * (height - 2);
      return x.toFixed(1) + "," + y.toFixed(1);
    });
    if (points.length === 1) {
      points.unshift("0," + points[0].split(",")[1]);
    }
    const graph = ACR.svg("svg", {
      class: "spark",
      viewBox: "0 0 " + width + " " + height,
      preserveAspectRatio: "none",
      "aria-hidden": "true",
      focusable: "false"
    });
    graph.appendChild(ACR.svg("polyline", {
      points: points.join(" "),
      "vector-effect": "non-scaling-stroke"
    }));
    return graph;
  }

  /* The panel under the hero, rebuilt after every sample; absent until a
   * counter moved. Outside every [data-section], so the refresh never swaps
   * it; it holds no control, so rebuilding it takes nothing from the
   * reader. */
  function buildPanel() {
    const moved = [];
    for (const entry of series.values()) {
      if (entry.samples[entry.samples.length - 1] > entry.base) {
        moved.push(entry);
      }
    }
    const hero = document.querySelector("[data-section=hero]");
    if (moved.length === 0 || !hero) {
      if (panel) {
        panel.remove();
        panel = null;
      }
      return;
    }
    const list = ACR.el("dl", { class: "details activity-list" });
    for (const entry of moved) {
      const total = entry.samples[entry.samples.length - 1] - entry.base;
      const row = ACR.el("div");
      row.append(
        ACR.el("dt", null, entry.label),
        ACR.el("dd", null, "+" + format(total, entry.unit))
      );
      if (entry.samples.length > 1) {
        const graph = ACR.el("dd", { class: "spark" });
        graph.appendChild(sparkline(entry.samples));
        row.appendChild(graph);
      }
      list.appendChild(row);
    }
    const fresh = ACR.el("div", {
      class: "section activity",
      role: "region",
      "aria-labelledby": "activity-head",
      "data-anchor": "activity"
    });
    fresh.append(
      ACR.el("h2", { id: "activity-head" }, "Activity since page open"),
      ACR.el("p", { class: "scope-note" },
        "The Metrics counters that moved while this page was open; each line plots their movement per refresh."),
      list
    );
    if (panel && panel.isConnected) {
      panel.replaceWith(fresh);
    } else {
      hero.after(fresh);
    }
    panel = fresh;
  }

  ACR.feature("series", {
    refreshed: function () {
      if (ACR.page() !== "dashboard") {
        return;
      }
      sample();
      ACR.keepScroll(function () {
        annotate();
        buildPanel();
      });
    }
  });
})();
