/*
 * Filters. The row tables (Mirrors, Origins, Clients, Uncacheables) get a
 * text box that hides the rows not containing every typed word, with a
 * "3 / 40 shown" count. The Metrics section gets a text box matched against
 * each row's label and explanation (so a config option name finds the rows
 * it governs), "only highlighted" and "hide zero" switches. Filters survive
 * the background refresh; without script the browser's find-in-page does
 * the same job.
 */
(function () {
  "use strict";

  /* The tables worth filtering: the top-packages pair holds five rows. */
  const FILTERED = ["mirrors", "origins", "clients", "uncacheables"];

  /* Remembered for the page's life, so a swapped-in section filters again. */
  const tableTerms = new Map();
  const metrics = { text: "", highlighted: false, nonzero: false };

  function words(text) {
    return text.toLowerCase().split(/\s+/).filter(function (word) {
      return word !== "";
    });
  }

  function matches(haystack, terms) {
    const lower = haystack.toLowerCase();
    return terms.every(function (term) {
      return lower.indexOf(term) >= 0;
    });
  }

  function setHidden(node, hidden) {
    if (node.hidden !== hidden) {
      node.hidden = hidden;
    }
  }

  /* The counts are live regions: written only when they change, and
   * filled before their bar is inserted, so a background refresh that
   * recreates them announces nothing the reader already heard. */
  function say(node, text) {
    if (node.textContent !== text) {
      node.textContent = text;
    }
  }

  /* `name` identifies the control for autofill and devtools; nothing is
   * ever submitted (the page has no form, and the CSP forbids one). */
  function searchBox(name, label, value) {
    return ACR.el("input", {
      type: "search",
      name: name,
      class: "filter-text",
      placeholder: "Filter",
      "aria-label": label,
      autocomplete: "off",
      spellcheck: "false",
      value: value
    });
  }

  /* ---- Row tables -------------------------------------------------------- */

  function filterTable(table, box, shown) {
    const terms = words(box.value);
    const rows = table.tBodies[0] ? Array.prototype.slice.call(table.tBodies[0].rows) : [];
    let visible = 0;
    for (const row of rows) {
      const keep = terms.length === 0 || matches(row.textContent, terms);
      setHidden(row, !keep);
      if (keep) {
        visible += 1;
      }
    }
    say(shown, terms.length === 0 ? "" : visible + " / " + rows.length + " shown");
  }

  function setupTable(table) {
    const key = table.getAttribute("data-table");
    if (FILTERED.indexOf(key) < 0 || table.hasAttribute("data-filtered")) {
      return;
    }
    table.setAttribute("data-filtered", "");
    const wrap = table.closest(".tablewrap") || table;
    const heading = ACR.sectionOf(table);
    const title = heading ? heading.querySelector("h2") : null;
    const label = "Filter " + (title ? title.textContent : key) + " rows";
    const box = searchBox("filter-" + key, label, tableTerms.get(key) || "");
    const shown = ACR.el("span", { class: "filter-shown", role: "status" });
    const bar = ACR.el("div", { class: "filter" });
    bar.append(box, shown);
    filterTable(table, box, shown);
    wrap.before(bar);
    box.addEventListener("input", function () {
      tableTerms.set(key, box.value);
      filterTable(table, box, shown);
    });
  }

  /* ---- Metrics ------------------------------------------------------------ */

  const ZERO = /^(0|0B|none since start)$/;

  function rowText(row) {
    let text = "";
    for (const dt of ACR.all(row, "dt")) {
      text += " " + dt.textContent + " " + (dt.getAttribute("title") || "");
    }
    return text;
  }

  function isZero(row) {
    const figure = row.getAttribute("data-v");
    if (figure !== null) {
      return figure === "0";
    }
    const value = row.querySelector(":scope > dd");
    return value !== null && ZERO.test(value.textContent.trim());
  }

  function filterMetrics(body, shown) {
    const terms = words(metrics.text);
    let total = 0;
    let visible = 0;
    for (const list of ACR.all(body, "dl.details")) {
      let listVisible = 0;
      for (const row of ACR.all(list, ":scope > div")) {
        total += 1;
        const keep = (terms.length === 0 || matches(rowText(row), terms)) &&
          (!metrics.highlighted || row.querySelector(".warn, .alert") !== null) &&
          (!metrics.nonzero || !isZero(row));
        setHidden(row, !keep);
        if (keep) {
          listVisible += 1;
        }
      }
      visible += listVisible;
      setHidden(list, listVisible === 0);
      const heading = list.previousElementSibling;
      if (heading && heading.matches("h3.group")) {
        setHidden(heading, listVisible === 0);
      }
    }
    const active = terms.length > 0 || metrics.highlighted || metrics.nonzero;
    say(shown, active ? visible + " / " + total + " rows shown" : "");
  }

  function checkbox(name, text, checked, onChange) {
    const box = ACR.el("input", { type: "checkbox", name: name, checked: checked });
    const label = ACR.el("label", { class: "filter-check" });
    label.append(box, " " + text);
    box.addEventListener("change", function () {
      onChange(box.checked);
    });
    return label;
  }

  function setupMetrics(section) {
    const details = section.querySelector(":scope > details");
    if (!details || details.hasAttribute("data-filtered")) {
      return;
    }
    details.setAttribute("data-filtered", "");
    const shown = ACR.el("span", { class: "filter-shown", role: "status" });
    const box = searchBox("filter-metrics", "Filter metrics by name or explanation", metrics.text);
    const refilter = function () {
      filterMetrics(details, shown);
    };
    box.addEventListener("input", function () {
      metrics.text = box.value;
      refilter();
    });
    const bar = ACR.el("div", { class: "filter" });
    bar.append(
      box,
      checkbox("only-highlighted", "only highlighted", metrics.highlighted, function (on) {
        metrics.highlighted = on;
        refilter();
      }),
      checkbox("hide-zero", "hide zero", metrics.nonzero, function (on) {
        metrics.nonzero = on;
        refilter();
      }),
      shown
    );
    const summary = details.querySelector(":scope > summary");
    refilter();
    summary.after(bar);
  }

  ACR.feature("filter", {
    enhance: function (root) {
      for (const table of ACR.all(root, "table[data-table]")) {
        setupTable(table);
      }
      const section = root.matches && root.matches("[data-section=metrics]") ?
        root : (root.querySelector ? root.querySelector("[data-section=metrics]") : null);
      if (section) {
        setupMetrics(section);
      }
    }
  });

  ACR.expose("filter", {
    /* The filter box a reader most likely means: the first one in an open
     * section on screen, else the Metrics one (opening the section). */
    focus: function () {
      const boxes = ACR.all(document, "input.filter-text");
      for (const box of boxes) {
        const details = box.closest("details");
        const rect = box.getBoundingClientRect();
        if ((!details || details.open) && rect.bottom > 0 && rect.top < window.innerHeight) {
          box.focus();
          return true;
        }
      }
      const metricsBox = document.querySelector("[data-section=metrics] input.filter-text");
      if (metricsBox) {
        const details = metricsBox.closest("details");
        // Opened as a reader would, so the refresh keeps it open and
        // `open=` records it.
        if (details && !details.open) {
          details.querySelector(":scope > summary").click();
        }
        metricsBox.focus();
        metricsBox.scrollIntoView({ block: "center" });
        return true;
      }
      return false;
    }
  });
})();
