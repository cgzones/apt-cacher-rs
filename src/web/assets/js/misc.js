/*
 * Small conveniences:
 *
 * - the Getting Started hint's apt line gets a Copy button (a Select button
 *   where the Clipboard API is unavailable: it needs a secure context, and
 *   the dashboard is usually plain HTTP);
 * - relative times ("3 h ago") keep counting while the page stays open,
 *   against the server's clock, which the footer's "Page generated at"
 *   carries.
 */
(function () {
  "use strict";

  const TICK_MS = 15 * 1000;
  const RELATIVE = /^(just now|[0-9]+ (s|min|h|d) ago|in [0-9]+ (s|min|h|d))$/;

  /* Server time minus client time, in milliseconds. */
  let skew = 0;

  function readSkew() {
    const stamp = document.querySelector("[data-section=footer] time[datetime]");
    const server = stamp ? Date.parse(stamp.getAttribute("datetime")) : NaN;
    if (Number.isFinite(server)) {
      skew = server - Date.now();
    }
  }

  function relative(epochMs, nowMs) {
    const secs = Math.round((nowMs - epochMs) / 1000);
    if (secs === 0) {
      return "just now";
    }
    return secs > 0 ? ACR.age(secs) + " ago" : "in " + ACR.age(-secs);
  }

  function tick() {
    const now = Date.now() + skew;
    for (const time of ACR.all(document, "time[datetime][title]")) {
      if (!RELATIVE.test(time.textContent)) {
        continue;
      }
      const at = Date.parse(time.getAttribute("datetime"));
      if (Number.isFinite(at)) {
        const text = relative(at, now);
        if (time.textContent !== text) {
          time.textContent = text;
        }
      }
    }
  }

  function copyButton(section) {
    const code = section.querySelector("code");
    if (!code || section.querySelector("button.copy")) {
      return;
    }
    const canCopy = window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText;
    const button = ACR.el("button", { type: "button", class: "copy" }, canCopy ? "Copy" : "Select");
    const note = ACR.el("span", { class: "copy-note", role: "status" });
    button.addEventListener("click", function () {
      const selection = window.getSelection();
      selection.selectAllChildren(code);
      if (!canCopy) {
        note.textContent = "selected: press Ctrl+C to copy";
        return;
      }
      navigator.clipboard.writeText(code.textContent).then(function () {
        note.textContent = "copied";
      }, function () {
        note.textContent = "copying failed: the line is selected, press Ctrl+C";
      });
    });
    code.after(" ", button, " ", note);
  }

  ACR.feature("misc", {
    init: function () {
      window.setInterval(tick, TICK_MS);
    },
    enhance: function (root) {
      const setup = root.matches && root.matches("[data-section=setup]") ?
        root : (root.querySelector ? root.querySelector("[data-section=setup]") : null);
      if (setup) {
        copyButton(setup);
      }
    },
    refreshed: function () {
      readSkew();
      tick();
    }
  });
})();
