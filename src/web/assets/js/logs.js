/*
 * The /logs page: a toolbar above the log with a level choice, a text filter
 * and "Follow", which re-fetches the page every few seconds and swaps the
 * entries in, keeping the view at the newest entry while it was there.
 * Without script the page is the same list; reload it for new entries.
 */
(function () {
  "use strict";

  const FOLLOW_MS = 5000;

  const view = { level: "", text: "", follow: false };
  let timer = null;
  let shown = null;
  let inFlight = false;
  let generation = 0;

  function logBlock() {
    return document.querySelector("[data-section=logs] pre.log");
  }

  function levelOf(line) {
    const match = /\b(ERROR|WARN)\b/.exec(line);
    return match ? match[1].toLowerCase() : "";
  }

  /* One span per entry, so entries can be hidden one by one. The text is
   * moved as text: nothing here is ever parsed as markup. */
  function split(pre) {
    if (pre.hasAttribute("data-split")) {
      return;
    }
    pre.setAttribute("data-split", "");
    const lines = pre.textContent.split("\n").filter(function (line) {
      return line !== "";
    });
    const entries = document.createDocumentFragment();
    for (const line of lines) {
      const level = levelOf(line);
      entries.appendChild(ACR.el("span", { class: level ? "entry " + level : "entry" }, line + "\n"));
    }
    pre.replaceChildren(entries);
  }

  function apply() {
    const pre = logBlock();
    if (!pre) {
      return;
    }
    split(pre);
    const terms = view.text.toLowerCase().split(/\s+/).filter(function (word) {
      return word !== "";
    });
    const entries = ACR.all(pre, "span.entry");
    let visible = 0;
    for (const entry of entries) {
      const text = entry.textContent.toLowerCase();
      const keep = (view.level === "" || entry.classList.contains(view.level)) &&
        terms.every(function (term) {
          return text.indexOf(term) >= 0;
        });
      entry.hidden = !keep;
      if (keep) {
        visible += 1;
      }
    }
    const active = view.level !== "" || terms.length > 0;
    // A live region: rewritten only when the count changes, so following
    // does not announce the same count every few seconds.
    const text = active ? visible + " / " + entries.length + " entries shown" : "";
    if (shown.textContent !== text) {
      shown.textContent = text;
    }
  }

  function atBottom(pre) {
    return pre.scrollHeight - pre.scrollTop - pre.clientHeight < 8;
  }

  /* One fetch of the entries, keeping the reader at the newest entry if
   * they were there, else where they were. At most one runs at a time;
   * `then` runs once it is done. False when one was already running. */
  function fetchEntries(then) {
    const refresh = ACR.api("refresh");
    if (!refresh || inFlight) {
      return false;
    }
    inFlight = true;
    const pre = logBlock();
    const stick = pre ? atBottom(pre) : true;
    const scrollTop = pre ? pre.scrollTop : 0;
    refresh.fetchPage(window.location.pathname + window.location.search, function (err, doc) {
      inFlight = false;
      try {
        if (err === null) {
          refresh.swap(doc);
          const now = logBlock();
          if (now && now !== pre) {
            now.scrollTop = stick ? now.scrollHeight : scrollTop;
          }
        }
      } finally {
        then();
      }
    });
    return true;
  }

  /* The Follow loop. Each start bumps `generation`, and a round of an
   * older loop ends there, so toggling Follow quickly never leaves two
   * loops polling side by side. */
  function follow(gen) {
    timer = null;
    if (!view.follow || gen !== generation) {
      return;
    }
    const again = function () {
      if (view.follow && gen === generation) {
        timer = window.setTimeout(function () {
          follow(gen);
        }, FOLLOW_MS);
      }
    };
    if (document.hidden || !fetchEntries(again)) {
      again();
    }
  }

  function setFollow(on) {
    view.follow = on;
    generation += 1;
    if (timer !== null) {
      window.clearTimeout(timer);
      timer = null;
    }
    if (on) {
      follow(generation);
    }
  }

  function toolbar(section) {
    const level = ACR.el("select", { name: "level", "aria-label": "Log level" });
    for (const [value, text] of [["", "All levels"], ["error", "Errors"], ["warn", "Warnings"]]) {
      level.appendChild(ACR.el("option", { value: value }, text));
    }
    level.addEventListener("change", function () {
      view.level = level.value;
      apply();
    });
    const text = ACR.el("input", {
      type: "search",
      name: "filter-logs",
      class: "filter-text",
      placeholder: "Filter",
      "aria-label": "Filter log entries",
      autocomplete: "off",
      spellcheck: "false"
    });
    text.addEventListener("input", function () {
      view.text = text.value;
      apply();
    });
    const followBox = ACR.el("input", { type: "checkbox", name: "follow" });
    followBox.addEventListener("change", function () {
      setFollow(followBox.checked);
    });
    const followLabel = ACR.el("label", { class: "filter-check", title: "Fetch new entries every 5 s" });
    followLabel.append(followBox, " Follow");
    shown = ACR.el("span", { class: "filter-shown", role: "status" });
    const bar = ACR.el("div", { class: "filter logtools" });
    bar.append(level, text, followLabel, shown);
    // Outside the swapped section, so following never resets the controls.
    section.before(bar);
    ACR.expose("logs", {
      toggleFollow: function () {
        followBox.checked = !followBox.checked;
        setFollow(followBox.checked);
      },
      fetchNow: function () {
        fetchEntries(function () {});
      }
    });
  }

  ACR.feature("logs", {
    init: function () {
      if (ACR.page() !== "logs") {
        return;
      }
      const section = document.querySelector("[data-section=logs]");
      if (section) {
        toolbar(section);
      }
    },
    enhance: function () {
      if (ACR.page() === "logs" && shown) {
        apply();
      }
    }
  });
})();
