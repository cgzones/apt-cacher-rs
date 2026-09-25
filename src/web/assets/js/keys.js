/*
 * Keyboard shortcuts, ignored while typing in a field, while an input
 * method composes, on key repeat, or with a modifier:
 *
 *   /   focus a filter box (the one on screen, else the Metrics filter)
 *   r   refresh now: the figures on the dashboard, the entries on /logs
 *   p   pause or unpause: auto-refresh on the dashboard, Follow on /logs
 *
 * Single-character shortcuts can fire by accident, from speech input for
 * one (WCAG 2.1.4), so a note in the footer names them and turns them off
 * (remembered in browser storage). The controls they drive announce them
 * through aria-keyshortcuts and a title while they are on.
 */
(function () {
  "use strict";

  /* The switch lives here; storage only remembers it for later visits, and
   * without storage it holds for this page. */
  let on = ACR.store.get("keys") !== "off";

  function enabled() {
    return on;
  }

  function typing(target) {
    if (!target || !target.tagName) {
      return false;
    }
    const tag = target.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
  }

  function handle(event) {
    if (!enabled() || event.defaultPrevented || event.repeat || event.isComposing ||
        event.ctrlKey || event.metaKey || event.altKey || typing(event.target)) {
      return;
    }
    const page = ACR.page();
    let done = false;
    if (event.key === "/") {
      const filter = ACR.api("filter");
      done = filter !== null && filter.focus();
    } else if (event.key === "r") {
      const target = page === "logs" ? ACR.api("logs") : ACR.api("refresh");
      if (target) {
        if (page === "logs") {
          target.fetchNow();
        } else {
          target.now();
        }
        done = true;
      }
    } else if (event.key === "p") {
      if (page === "dashboard") {
        const link = document.querySelector("a[data-action=refresh-toggle]");
        if (link) {
          link.click();
          done = true;
        }
      } else if (page === "logs") {
        const logs = ACR.api("logs");
        if (logs) {
          logs.toggleFollow();
          done = true;
        }
      }
    }
    if (done) {
      event.preventDefault();
    }
  }

  function announce(node, keys, title) {
    if (enabled()) {
      node.setAttribute("aria-keyshortcuts", keys);
      node.setAttribute("title", title);
    } else {
      node.removeAttribute("aria-keyshortcuts");
      node.removeAttribute("title");
    }
  }

  function announceAll(root) {
    for (const link of ACR.all(root, "a[data-action=refresh-toggle]")) {
      announce(link, "p", "Keyboard: p toggles auto-refresh, r refreshes now, / filters");
    }
    for (const box of ACR.all(root, "input.filter-text")) {
      announce(box, "/", "Keyboard: / jumps to a filter");
    }
    for (const follow of ACR.all(root, ".logtools input[name=follow]")) {
      announce(follow, "p", "Keyboard: p toggles Follow, r fetches new entries now, / filters");
    }
  }

  /* The footer's note: which keys work, and the switch. */
  function note(footer) {
    if (footer.querySelector(".keys-note")) {
      return;
    }
    const text = ACR.el("span");
    const button = ACR.el("button", { type: "button", class: "keys-toggle" });
    const show = function () {
      text.textContent = enabled() ?
        "Keyboard shortcuts: / filter, r refresh now, p pause or unpause. " :
        "Keyboard shortcuts are off. ";
      button.textContent = enabled() ? "Turn off" : "Turn on";
    };
    button.addEventListener("click", function () {
      on = !on;
      if (on) {
        ACR.store.remove("keys");
      } else {
        ACR.store.set("keys", "off");
      }
      show();
      announceAll(document);
    });
    show();
    const line = ACR.el("p", { class: "keys-note" });
    line.append(text, button);
    footer.appendChild(line);
  }

  ACR.feature("keys", {
    init: function () {
      document.addEventListener("keydown", handle);
    },
    enhance: function (root) {
      announceAll(root);
      // The /logs toolbar sits outside the swapped sections.
      announceAll(document.querySelector(".logtools") || root);
      const footer = root.matches && root.matches("[data-section=footer]") ?
        root : (root.querySelector ? root.querySelector("[data-section=footer]") : null);
      if (footer) {
        note(footer);
      }
    }
  });
})();
