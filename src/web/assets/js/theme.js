/*
 * Theme memory. The nav's theme link cycles auto -> light -> dark -> auto in
 * place, and the choice is remembered in browser storage: a later visit to
 * a bare URL applies it (after one paint in the default theme). An explicit
 * `theme=` in the URL always wins, `theme=auto` included, which is why the
 * server renders the dark -> auto link with it.
 */
(function () {
  "use strict";

  const NEXT = { auto: "light", light: "dark", dark: "auto" };

  function apply(theme) {
    const root = document.documentElement;
    if (theme === "light" || theme === "dark") {
      root.setAttribute("data-theme", theme);
    } else {
      root.removeAttribute("data-theme");
    }
  }

  function label(theme) {
    return "Theme: " + theme + " \u2192 " + NEXT[theme];
  }

  function syncLink() {
    const st = ACR.state();
    const current = st.theme || "auto";
    for (const link of ACR.all(document, "a[data-action=theme-cycle]")) {
      const next = Object.assign({}, st, { theme: NEXT[current] });
      link.setAttribute("href", ACR.href(window.location.pathname, next));
      link.textContent = label(current);
    }
  }

  function cycle() {
    const st = ACR.state();
    st.theme = NEXT[st.theme || "auto"];
    apply(st.theme);
    ACR.store.set("theme", st.theme);
    ACR.setState(st);
  }

  ACR.feature("theme", {
    init: function () {
      const st = ACR.state();
      if (st.theme === null) {
        const saved = ACR.store.get("theme");
        if (saved === "light" || saved === "dark" || saved === "auto") {
          st.theme = saved;
          apply(saved);
          ACR.setState(st);
        }
      } else {
        ACR.store.set("theme", st.theme);
      }
      document.addEventListener("click", function (event) {
        const link = event.target.closest ? event.target.closest("a[data-action=theme-cycle]") : null;
        if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
          return;
        }
        event.preventDefault();
        cycle();
      });
      ACR.onState(syncLink);
    },
    refreshed: syncLink
  });
})();
