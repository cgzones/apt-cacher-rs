/*
 * Sortable tables: every column header of a table[data-table] becomes a
 * button. A click sorts by that column (figures largest first, text A to Z),
 * a second click reverses, a third restores the server's order. Cells sort
 * by their data-sort key where the server gave one (sizes, times, counts
 * rendered for reading), else by their text; "N/A" and empty cells stay
 * last either way. The choice holds for the page's life, across background
 * refreshes, and is remembered per table in browser storage for the next
 * visit (as long as the column keeps its header).
 */
(function () {
  "use strict";

  const serverOrder = new WeakMap();
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

  /* The order per table key for the page's life: the source of truth across
   * background refreshes, so unavailable storage cannot reset it and another
   * tab's choice cannot change it. Storage only seeds it, once per key. */
  const orders = new Map();

  function storageKey(key) {
    return "sort." + key;
  }

  function headerName(table, col) {
    const header = table.tHead.rows[0].cells[col];
    return header ? header.textContent.trim() : "";
  }

  function stored(key) {
    const raw = ACR.store.get(storageKey(key));
    if (!raw) {
      return null;
    }
    try {
      const saved = JSON.parse(raw);
      if (saved && Number.isInteger(saved.col) && typeof saved.name === "string" &&
          (saved.dir === "ascending" || saved.dir === "descending")) {
        return saved;
      }
    } catch (err) {
      /* a corrupt entry is dropped below */
    }
    ACR.store.remove(storageKey(key));
    return null;
  }

  /* The order to apply to `table`, if its column still has the header it
   * had when the order was chosen (a new build may add columns). */
  function load(table) {
    const key = table.getAttribute("data-table");
    if (!orders.has(key)) {
      orders.set(key, stored(key));
    }
    const order = orders.get(key);
    return order !== null && headerName(table, order.col) === order.name ? order : null;
  }

  function save(table, col, dir) {
    const key = table.getAttribute("data-table");
    if (dir === null) {
      orders.set(key, null);
      ACR.store.remove(storageKey(key));
    } else {
      const order = { col: col, dir: dir, name: headerName(table, col) };
      orders.set(key, order);
      ACR.store.set(storageKey(key), JSON.stringify(order));
    }
  }

  /* A cell's sort value: a number, a string, or null for "no value". */
  function sortValue(cell) {
    if (!cell) {
      return null;
    }
    const key = cell.getAttribute("data-sort");
    const text = key !== null ? key : cell.textContent.trim();
    if (text === "" || text === "N/A") {
      return null;
    }
    const plain = key !== null ? text : text.replace(/[\u202f\s]/g, "");
    if (/^-?[0-9]+(\.[0-9]+)?$/.test(plain)) {
      return Number(plain);
    }
    return text;
  }

  function compare(a, b) {
    if (typeof a === "number" && typeof b === "number") {
      return a - b;
    }
    return collator.compare(String(a), String(b));
  }

  function apply(table, col, dir) {
    const body = table.tBodies[0];
    const original = serverOrder.get(table);
    if (!body || !original) {
      return;
    }
    const headers = table.tHead.rows[0].cells;
    for (let i = 0; i < headers.length; i += 1) {
      if (i === col && dir !== null) {
        headers[i].setAttribute("aria-sort", dir);
      } else {
        headers[i].removeAttribute("aria-sort");
      }
    }
    let rows = original.slice();
    if (dir !== null) {
      const sign = dir === "ascending" ? 1 : -1;
      const keyed = rows.map(function (row, index) {
        return { row: row, index: index, value: sortValue(row.cells[col]) };
      });
      keyed.sort(function (x, y) {
        if (x.value === null || y.value === null) {
          if (x.value === y.value) {
            return x.index - y.index;
          }
          return x.value === null ? 1 : -1;
        }
        return sign * compare(x.value, y.value) || x.index - y.index;
      });
      rows = keyed.map(function (entry) {
        return entry.row;
      });
    }
    for (const row of rows) {
      body.appendChild(row);
    }
  }

  function cycle(table, col) {
    const header = table.tHead.rows[0].cells[col];
    const current = header.getAttribute("aria-sort");
    const first = header.classList.contains("num") ? "descending" : "ascending";
    const second = first === "ascending" ? "descending" : "ascending";
    let next;
    if (current === null) {
      next = first;
    } else if (current === first) {
      next = second;
    } else {
      next = null;
    }
    apply(table, col, next);
    save(table, col, next);
  }

  function setup(table) {
    if (!table.tHead || !table.tBodies[0] || serverOrder.has(table)) {
      return;
    }
    serverOrder.set(table, Array.prototype.slice.call(table.tBodies[0].rows));
    const headers = table.tHead.rows[0].cells;
    for (let i = 0; i < headers.length; i += 1) {
      const header = headers[i];
      const button = ACR.el("button", { type: "button", class: "sort" });
      while (header.firstChild) {
        button.appendChild(header.firstChild);
      }
      header.appendChild(button);
      button.addEventListener("click", function () {
        cycle(table, i);
      });
    }
    const saved = load(table);
    if (saved) {
      apply(table, saved.col, saved.dir);
    }
  }

  ACR.feature("sort", {
    enhance: function (root) {
      for (const table of ACR.all(root, "table[data-table]")) {
        setup(table);
      }
    }
  });
})();
