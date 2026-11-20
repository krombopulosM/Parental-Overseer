"use strict";
// Devices: a desktop-style table. Click selects (Ctrl/Shift for more), double-click
// or Enter opens, right-click / long-press / the ⋯ button opens the options menu,
// F2 renames in place. Uses the helpers from app.js ($, api, post, act, toast...).

const DT = {
  rows: [], you: null, sel: new Set(), anchor: null, sort: { key: "status", dir: 1 },
  renaming: null, menu: null, selecting: false, lastLongPress: 0,
};
try { Object.assign(DT.sort, JSON.parse(localStorage.getItem("pg-dev-sort") || "{}")); } catch (_) { /* private mode */ }

const coarse = () => matchMedia("(pointer: coarse)").matches;
const narrow = () => matchMedia("(max-width: 700px)").matches;
const devById = id => DT.rows.find(r => r.device_id === id);
const groupInfo = name => state.groups.find(g => g.name === name) || { name, filtered: true };

function devState(x) {
  if (x.blocked_all) return { key: 0, html: `<span class="badge bad">Blocked</span>`, text: "Blocked" };
  if (x.paused) return { key: 1, html: `<span class="badge warn" title="${esc(x.paused_reason)}">Paused</span>`, text: "Paused" };
  if (x.online) return { key: 2, html: `<span class="dt-on"><span class="status-dot on"></span>Online</span>`, text: "Online" };
  return { key: 3, html: `<span class="muted"><span class="status-dot"></span>Offline</span>`, text: "Offline" };
}

const COLS = [
  { key: "name", label: "Device", sort: x => x.label.toLowerCase(),
    cell: x => `<div class="dt-name"><span class="status-dot ${x.online ? "on" : ""}" aria-hidden="true"></span>
      <a href="#device/${encodeURIComponent(x.device_id)}" class="dt-label" tabindex="-1">${esc(x.label)}</a>
      ${x.device_id === DT.you ? `<span class="badge info">this device</span>` : ""}
      ${!x.group_set ? `<span class="badge info" title="Not assigned yet - using the default group">new</span>` : ""}
      ${Object.keys(x.category_overrides || {}).length ? `<span class="badge" title="${esc(Object.entries(x.category_overrides)
        .map(([c, h]) => `${c}: ${h === "allow" ? "allowed" : "blocked"} for this device`).join(", "))}">${Object.keys(x.category_overrides).length} own setting${Object.keys(x.category_overrides).length === 1 ? "" : "s"}</span>` : ""}
      ${x.suspect ? `<span class="badge bad" title="Its identity looks copied - filtered until you confirm">identity check</span>` : ""}
      ${x.blocked_all ? `<span class="badge bad show-sm-inline">blocked</span>` : x.paused ? `<span class="badge warn show-sm-inline">paused</span>` : ""}
      ${x.alerts ? `<span class="badge bad show-sm-inline" title="bypass attempts today">${x.alerts} ⚠</span>` : ""}</div>
      <div class="dt-sub show-sm">${esc(x.group)} · ${x.online ? "online" : "seen " + ago(x.last_seen)}${x.ip ? " · " + esc(x.ip) : ""}</div>` },
  { key: "status", label: "Status", cls: "hide-sm", sort: x => devState(x).key * 1e12 - (x.last_seen || 0),
    cell: x => devState(x).html },
  { key: "group", label: "Group", cls: "hide-sm", sort: x => x.group.toLowerCase(),
    cell: x => `${esc(x.group)}${x.filtered ? "" : ` <span class="badge">unfiltered</span>`}` },
  { key: "ip", label: "Address", cls: "hide-sm", sort: x => (x.ip || "").split(".").map(n => n.padStart(3, "0")).join("."),
    cell: x => `<span class="mono small">${esc(x.ip || "")}</span><div class="faint mono small">${esc(x.mac || "")}</div>` },
  { key: "today", label: "Online today", cls: "right", sort: x => x.minutes_today, cell: x => fmtMins(x.minutes_today) },
  { key: "data", label: "Data", cls: "right hide-sm", sort: x => x.bytes_down + x.bytes_up,
    cell: x => `<span title="${fmtBytes(x.bytes_down)} down / ${fmtBytes(x.bytes_up)} up">${fmtBytes(x.bytes_down + x.bytes_up)}</span>` },
  { key: "blocked", label: "Blocked", cls: "right hide-sm", sort: x => x.blocked, cell: x => x.blocked },
  { key: "alerts", label: "Alerts", cls: "right hide-sm", sort: x => x.alerts,
    cell: x => x.alerts ? `<span class="badge bad">${x.alerts}</span>` : "0" },
  { key: "last", label: "Last seen", cls: "hide-sm nowrap", sort: x => -(x.last_seen || 0),
    cell: x => `<span class="muted small">${x.online ? "now" : ago(x.last_seen)}</span>` },
];

function sortedRows() {
  const col = COLS.find(c => c.key === DT.sort.key) || COLS[1];
  const f = $("#dt-filter") ? $("#dt-filter").value.trim().toLowerCase() : "";
  const show = $("#dt-show") ? $("#dt-show").value : "";
  return DT.rows.filter(x => {
    if (show === "online" && !x.online) return false;
    if (show === "new" && x.group_set) return false;
    if (show === "paused" && !x.paused) return false;
    if (show && show.startsWith("g:") && x.group !== show.slice(2)) return false;
    return !f || [x.label, x.ip, x.mac, x.hostname, x.group].some(v => v && String(v).toLowerCase().includes(f));
  }).sort((a, b) => {
    const va = col.sort(a), vb = col.sort(b);
    return (va < vb ? -1 : va > vb ? 1 : 0) * DT.sort.dir;
  });
}

function dtBusy() {
  return DT.renaming || DT.menu || $("#dt-dialog[open]") || $("#dt-confirm[open]");
}

function renderTable() {
  const table = $("#dt");
  if (!table) return;
  const focusedId = document.activeElement && document.activeElement.closest && document.activeElement.closest("#dt tbody tr")
    ? document.activeElement.closest("tr").dataset.id : null;
  table.querySelector("thead").innerHTML = `<tr>${COLS.map(c => {
    const on = DT.sort.key === c.key;
    return `<th class="${c.cls || ""}" aria-sort="${on ? (DT.sort.dir > 0 ? "ascending" : "descending") : "none"}">
      <button class="dt-sort ${on ? "on" : ""}" data-sort="${c.key}">${esc(c.label)}<span class="dt-arrow">${on ? (DT.sort.dir > 0 ? "▲" : "▼") : ""}</span></button></th>`;
  }).join("")}<th class="dt-kebab-col"><span class="sr-only">Options</span></th></tr>`;
  const rows = sortedRows();
  for (const id of [...DT.sel]) if (!devById(id)) DT.sel.delete(id);
  table.querySelector("tbody").innerHTML = rows.length ? rows.map(x => `
    <tr data-id="${esc(x.device_id)}" tabindex="-1" aria-selected="${DT.sel.has(x.device_id)}"
        class="${x.online ? "" : "offline"} ${x.paused ? "paused" : ""}">
      ${COLS.map(c => `<td class="${c.cls || ""} c-${c.key}">${c.cell(x)}</td>`).join("")}
      <td class="dt-kebab-col"><button class="dt-kebab" data-kebab aria-label="Options for ${esc(x.label)}" aria-haspopup="menu">⋯</button></td>
    </tr>`).join("") : `<tr class="dt-empty"><td colspan="${COLS.length + 1}"><div class="empty">${DT.rows.length ? "No devices match." : "No devices yet. Point a device's DNS at this gateway."}</div></td></tr>`;
  const first = focusedId && table.querySelector(`tbody tr[data-id="${CSS.escape(focusedId)}"]`);
  const target = first || table.querySelector("tbody tr[data-id]");
  if (target) target.tabIndex = 0;
  if (first) first.focus({ preventScroll: true });
  renderBar();
}

function renderBar() {
  const n = DT.sel.size, online = DT.rows.filter(x => x.online).length;
  $("#dt-status").textContent = `${DT.rows.length} device${DT.rows.length === 1 ? "" : "s"} · ${online} online` +
    (n ? ` · ${n} selected` : "") + (coarse() ? " · Press and hold a device for options" : " · Right-click a device for options, double-click to open");
  const bar = $("#dt-bar");
  // phones: the bar is for "Select more…" mode; a long-press alone just opens the menu
  if ((!n && !DT.selecting) || (coarse() && !DT.selecting)) { bar.hidden = true; bar.innerHTML = ""; return; }
  bar.hidden = false;
  bar.innerHTML = `<b>${n} selected</b>
    <button class="small" data-bar="pause">Pause 1h</button>
    <button class="small" data-bar="resume">Resume</button>
    <button class="small danger" data-bar="block">Block all traffic</button>
    <select class="small" data-bar-group aria-label="Move selected to group"><option value="">Move to group…</option>
      ${state.groups.map(g => `<option value="${esc(g.name)}">${esc(g.name)}${g.filtered ? "" : " (unfiltered)"}</option>`).join("")}</select>
    <button class="small" data-bar="menu" aria-haspopup="menu">More…</button>
    <button class="small link" data-bar="clear">${DT.selecting ? "Done" : "Clear"}</button>`;
}

// ------------------------------------------------------------------ selection
function setSel(ids, anchor) {
  DT.sel = new Set(ids);
  if (anchor !== undefined) DT.anchor = anchor;
  $$("#dt tbody tr[data-id]").forEach(tr => tr.setAttribute("aria-selected", DT.sel.has(tr.dataset.id)));
  renderBar();
}
function visibleIds() { return $$("#dt tbody tr[data-id]").map(tr => tr.dataset.id); }
function focusRow(id) {
  const tr = id && $(`#dt tbody tr[data-id="${CSS.escape(id)}"]`);
  if (!tr) return;
  $$("#dt tbody tr[tabindex='0']").forEach(r => { r.tabIndex = -1; });
  tr.tabIndex = 0; tr.focus();
  tr.scrollIntoView({ block: "nearest" });
}
function clickSelect(id, e) {
  if (e.shiftKey && DT.anchor) {
    const ids = visibleIds(), a = ids.indexOf(DT.anchor), b = ids.indexOf(id);
    if (a >= 0 && b >= 0) return setSel(ids.slice(Math.min(a, b), Math.max(a, b) + 1));
  }
  if (e.ctrlKey || e.metaKey || DT.selecting) {
    const s = new Set(DT.sel);
    s.has(id) ? s.delete(id) : s.add(id);
    if (DT.selecting && !s.size) DT.selecting = false;
    return setSel(s, id);
  }
  setSel([id], id);
}

// ------------------------------------------------------------------ actions
const openDevice = id => { location.hash = `#device/${encodeURIComponent(id)}`; };
const names = ids => ids.length === 1 ? (devById(ids[0]) || {}).label || "this device" : `${ids.length} devices`;

async function forEachDev(ids, fn, msg) {
  await act(async () => { for (const id of ids) await fn(encodeURIComponent(id)); }, msg);
}
function pauseDevs(ids, minutes) {
  return forEachDev(ids, id => post(`/api/devices/${id}/pause`, { minutes }),
    minutes > 0 ? `${names(ids)}: paused for ${fmtMins(minutes)}` : minutes < 0 ? `${names(ids)}: all traffic blocked` : `${names(ids)}: internet back on`);
}
async function blockDevs(ids) {
  const self = ids.includes(DT.you);
  const ok = await askConfirm({
    title: `Block all traffic for ${names(ids)}?`,
    body: `${ids.length === 1 ? "It" : "They"} won't reach the internet at all until you unblock ${ids.length === 1 ? "it" : "them"} here
      - no schedule or timer will turn it back on.${self ? " <b>This includes the device you're using now</b>; this dashboard stays reachable from it so you can unblock it." : ""}`,
    ok: "Block all traffic", danger: true,
  });
  if (ok) await pauseDevs(ids, -1);
}
function moveDevs(ids, group) {
  return forEachDev(ids, id => post(`/api/devices/${id}`, { group }), `${names(ids)}: moved to ${group}`);
}
async function forgetDevs(ids) {
  const online = ids.filter(id => (devById(id) || {}).online).length;
  const ok = await askConfirm({
    title: `Forget ${names(ids)}?`,
    body: `Its name, group and any pause are removed from the list; its history stays. ${online
      ? "It's online, so it will reappear straight away as a <b>new device in the default group</b>."
      : "If it connects again it comes back as a new device in the default group."}`,
    ok: "Forget", danger: true,
  });
  if (ok) await forEachDev(ids, id => del(`/api/devices/${id}`), `${names(ids)}: forgotten`);
}
async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); toast(`${what} copied`); }
  catch (_) { toast(`${what}: ${text}`, 5000); }
}
function untilMorning() {
  const now = new Date(), t = new Date(now);
  t.setHours(7, 0, 0, 0);
  if (t <= now) t.setDate(t.getDate() + 1);
  return Math.round((t - now) / 60000);
}

// ------------------------------------------------------------------ inline rename
function startRename(id) {
  closeMenu();
  const x = devById(id), tr = x && $(`#dt tbody tr[data-id="${CSS.escape(id)}"]`);
  if (!tr) return;
  DT.renaming = id;
  const cell = tr.querySelector(".dt-name .dt-label");
  const input = document.createElement("input");
  input.className = "dt-rename"; input.value = x.name || ""; input.placeholder = x.label;
  input.setAttribute("aria-label", "Device name"); input.maxLength = 60;
  cell.replaceWith(input);
  input.focus(); input.select();
  let done = false;
  const finish = async save => {
    if (done) return; done = true;
    DT.renaming = null;
    const v = input.value.trim();
    if (save && v !== (x.name || "")) {
      x.name = v; x.label = v || x.hostname || x.ip || x.device_id;
      renderTable(); focusRow(id);
      await act(() => post(`/api/devices/${encodeURIComponent(id)}`, { name: v }), v ? `Renamed to ${v}` : "Name cleared");
    } else { renderTable(); focusRow(id); }
  };
  input.addEventListener("keydown", e => {
    e.stopPropagation();
    if (e.key === "Enter") finish(true);
    else if (e.key === "Escape") finish(false);
  });
  input.addEventListener("blur", () => finish(true));
  ["click", "dblclick", "pointerdown", "contextmenu"].forEach(t => input.addEventListener(t, e => e.stopPropagation()));
}

// ------------------------------------------------------------------ menu
function menuItems(ids) {
  const one = ids.length === 1 ? devById(ids[0]) : null;
  const devs = ids.map(devById).filter(Boolean);
  const anyPaused = devs.some(x => x.paused), allBlocked = devs.length && devs.every(x => x.blocked_all);
  const groups = state.groups.map(g => ({
    label: g.name + (g.filtered ? "" : " (unfiltered)"), check: devs.length && devs.every(x => x.group === g.name),
    run: () => moveDevs(ids, g.name),
  }));
  const pause = [[15, "15 minutes"], [60, "1 hour"], [120, "2 hours"], [untilMorning(), "Until 7:00"]]
    .map(([m, label]) => ({ label, run: () => pauseDevs(ids, m) }));
  const items = [];
  if (one) {
    items.push({ label: "Open", bold: true, hint: "Enter", run: () => openDevice(one.device_id) });
    items.push({ label: "Watch live", run: () => { location.hash = `#live/${encodeURIComponent(one.device_id)}`; } });
    items.push("-");
    items.push({ label: "Rename", hint: "F2", run: () => startRename(one.device_id) });
  }
  items.push({ label: "Move to group", sub: groups });
  if (one) items.push({ label: "Allow or block categories…", run: () => openSettings(one.device_id, "cats") });
  if (one) items.push({ label: "Settings…", run: () => openSettings(one.device_id) });
  items.push("-");
  if (anyPaused) items.push({ label: allBlocked ? "Unblock" : devs.length > 1 ? "Resume / unblock" : "Resume", strong: true, run: () => pauseDevs(ids, 0) });
  items.push({ label: "Pause internet", sub: pause });
  if (!allBlocked) items.push({ label: "Block all traffic", danger: true, run: () => blockDevs(ids) });
  if (one && one.suspect) items.push({ label: "It's me (trust again)", run: () => act(() => post(`/api/devices/${encodeURIComponent(one.device_id)}/trust`), "Trusted again") });
  if (one && (one.ip || one.mac)) {
    items.push("-");
    if (one.ip) items.push({ label: "Copy IP address", run: () => copyText(one.ip, "IP address") });
    if (one.mac) items.push({ label: "Copy MAC address", run: () => copyText(one.mac, "MAC address") });
  }
  if (coarse() && !DT.selecting) {
    items.push("-");
    items.push({ label: "Select more…", run: () => { DT.selecting = true; setSel(ids, ids[0]); } });
  }
  items.push("-");
  items.push({ label: "Forget device" + (ids.length > 1 ? "s" : "") + "…", danger: true, run: () => forgetDevs(ids) });
  return items;
}

function buildMenu(items, sub) {
  return `<div class="ctx-list" role="menu">${items.map((it, i) => {
    if (it === "-") return `<div class="ctx-sep" role="separator"></div>`;
    const cls = ["ctx-item", it.danger ? "danger" : "", it.bold ? "bold" : "", it.strong ? "strong" : ""].join(" ");
    if (it.sub) return `<div class="ctx-has-sub"><button class="${cls}" role="menuitem" aria-haspopup="menu" aria-expanded="false" data-i="${sub}${i}">
        <span class="ctx-check"></span><span class="ctx-label">${esc(it.label)}</span><span class="ctx-hint">▸</span></button>
        <div class="ctx-sub">${buildMenu(it.sub, `${sub}${i}.`)}</div></div>`;
    return `<button class="${cls}" role="${it.check !== undefined ? "menuitemradio" : "menuitem"}" ${it.check !== undefined ? `aria-checked="${!!it.check}"` : ""} data-i="${sub}${i}">
      <span class="ctx-check">${it.check ? "✓" : ""}</span><span class="ctx-label">${esc(it.label)}</span><span class="ctx-hint">${esc(it.hint || "")}</span></button>`;
  }).join("")}</div>`;
}

function itemAt(items, path) {
  let list = items, it;
  for (const p of path.split(".")) { it = list[Number(p)]; list = it && it.sub; }
  return it;
}

function openMenu(ids, at) {
  closeMenu();
  if (!ids.length) return;
  const sheet = narrow() || at.touch;
  const items = menuItems(ids);
  const el = document.createElement("div");
  el.className = "ctx " + (sheet ? "ctx-sheet" : "ctx-pop");
  el.setAttribute("aria-label", `Options for ${names(ids)}`);
  const one = ids.length === 1 && devById(ids[0]);
  el.innerHTML = (sheet ? `<div class="sheet-grip"></div><div class="ctx-head"><b>${esc(names(ids))}</b>
      ${one ? `<div class="muted small">${esc(one.group)} · ${esc(devState(one).text)}${one.ip ? " · " + esc(one.ip) : ""}</div>` : ""}</div>`
      : ids.length > 1 ? `<div class="ctx-title">${esc(names(ids))}</div>` : "")
    + buildMenu(items, "");
  const back = document.createElement("div");
  back.className = "ctx-backdrop" + (sheet ? " dim" : "");
  document.body.append(back, el);
  DT.menu = { el, back, items, ids, sheet, returnTo: document.activeElement };
  if (sheet) requestAnimationFrame(() => el.classList.add("open"));
  else {
    const r = el.getBoundingClientRect(), vw = innerWidth, vh = innerHeight;
    let x = at.x, y = at.y;
    if (x + r.width > vw - 8) x = Math.max(8, vw - r.width - 8);
    if (y + r.height > vh - 8) y = Math.max(8, at.y - r.height);
    el.style.left = x + "px"; el.style.top = y + "px";
    if (x + r.width * 2 > vw) el.classList.add("flip");
  }
  back.addEventListener("pointerdown", e => { e.preventDefault(); closeMenu(); });
  back.addEventListener("contextmenu", e => { e.preventDefault(); closeMenu(); });
  el.addEventListener("click", e => {
    const b = e.target.closest(".ctx-item");
    if (!b) return;
    const it = itemAt(items, b.dataset.i);
    if (it.sub) return toggleSub(b, b.getAttribute("aria-expanded") !== "true");
    closeMenu(false);
    it.run();
  });
  if (!sheet) el.addEventListener("pointerover", e => {
    const b = e.target.closest(".ctx-item");
    if (!b || e.pointerType === "touch") return;
    const list = b.closest(".ctx-list");
    $$(":scope > .ctx-has-sub > .ctx-item", list).forEach(o => { if (o !== b) toggleSub(o, false); });
    if (b.getAttribute("aria-haspopup")) toggleSub(b, true);
    b.focus({ preventScroll: true });
  });
  el.addEventListener("keydown", menuKeys);
  const first = el.querySelector(".ctx-item");
  if (first && !at.touch) first.focus({ preventScroll: true });
}

function toggleSub(btn, open) {
  btn.setAttribute("aria-expanded", open);
  btn.parentElement.classList.toggle("open", open);
}

function menuKeys(e) {
  const cur = document.activeElement && document.activeElement.closest(".ctx-item");
  const list = cur ? cur.closest(".ctx-list") : DT.menu.el.querySelector(".ctx-list");
  const items = $$(":scope > .ctx-item, :scope > .ctx-has-sub > .ctx-item", list);
  const i = items.indexOf(cur);
  const go = j => { e.preventDefault(); items[(j + items.length) % items.length].focus(); };
  if (e.key === "ArrowDown") go(i + 1);
  else if (e.key === "ArrowUp") go(i - 1);
  else if (e.key === "Home") go(0);
  else if (e.key === "End") go(items.length - 1);
  else if (e.key === "ArrowRight" && cur && cur.getAttribute("aria-haspopup")) {
    e.preventDefault(); toggleSub(cur, true); cur.parentElement.querySelector(".ctx-sub .ctx-item").focus();
  } else if (e.key === "ArrowLeft" && list.closest(".ctx-sub")) {
    e.preventDefault(); const p = list.closest(".ctx-has-sub").querySelector(":scope > .ctx-item"); toggleSub(p, false); p.focus();
  } else if (e.key === "Escape") { e.preventDefault(); closeMenu(); }
  else if (e.key === "Tab") { e.preventDefault(); go(i + (e.shiftKey ? -1 : 1)); }
}

function closeMenu(restoreFocus = true) {
  const m = DT.menu;
  if (!m) return;
  DT.menu = null;
  m.back.remove();
  if (m.el.classList.contains("ctx-sheet")) {
    m.el.classList.remove("open");
    setTimeout(() => m.el.remove(), 200);
  } else m.el.remove();
  if (m.sheet && coarse() && !DT.selecting) setSel([]);       // a long-press selection is only for the menu
  if (restoreFocus && !m.sheet && m.returnTo && document.contains(m.returnTo)) m.returnTo.focus({ preventScroll: true });
}

function menuFor(id, at) {
  if (!DT.sel.has(id)) setSel([id], id);
  openMenu(DT.sel.size ? [...DT.sel] : [id], at);
}

// ------------------------------------------------------------------ dialogs
function askConfirm({ title, body, ok, danger }) {
  return new Promise(resolve => {
    let d = $("#dt-confirm");
    if (!d) { d = document.createElement("dialog"); d.id = "dt-confirm"; d.className = "dt-dialog"; document.body.append(d); }
    d.innerHTML = `<form method="dialog"><h2>${esc(title)}</h2><p class="muted">${body}</p>
      <div class="dt-dialog-foot"><button value="no">Cancel</button>
      <button value="yes" class="${danger ? "danger-fill" : "primary"}">${esc(ok)}</button></div></form>`;
    d.onclose = () => resolve(d.returnValue === "yes");
    d.returnValue = "";
    d.showModal();
    d.querySelector("button[value=no]").focus();
  });
}

async function openSettings(id, focus) {
  const x = devById(id);
  if (!x) return;
  let catalog = null;
  try { catalog = await api("/api/categories"); } catch (_) { /* the rest of the dialog still works */ }
  const ov = x.category_overrides || {};
  const groupBlocks = (grp, cat) => !!catalog && (catalog.groups.find(g => g.name === grp) || { categories: [] }).categories.includes(cat);
  const inheritText = (grp, cat) => `Like its group (${groupBlocks(grp, cat) ? "blocked" : "allowed"})`;
  const catRows = catalog ? catalog.categories.map(c => `
      <label class="dt-cat"><span class="dt-cat-name" title="${esc(c.description)}">${esc(c.label)}</span>
        <select name="cat:${esc(c.key)}" data-cat="${esc(c.key)}" aria-label="${esc(c.label)} for this device">
          <option value="" ${!ov[c.key] ? "selected" : ""}>${esc(inheritText(x.group, c.key))}</option>
          <option value="allow" ${ov[c.key] === "allow" ? "selected" : ""}>Always allow</option>
          <option value="block" ${ov[c.key] === "block" ? "selected" : ""}>Always block</option>
        </select></label>`).join("") : `<div class="small muted">Couldn't load the categories.</div>`;
  let d = $("#dt-dialog");
  if (!d) { d = document.createElement("dialog"); d.id = "dt-dialog"; d.className = "dt-dialog"; document.body.append(d); }
  const net = x.blocked_all ? "block" : x.paused ? "keep" : "on";
  const gi = g => g.filtered ? "filtered" : "not filtered";
  d.innerHTML = `<form method="dialog" id="dt-set">
    <h2>Device settings</h2>
    <label class="dt-field"><span>Name</span><input name="name" maxlength="60" value="${esc(x.name || "")}" placeholder="${esc(x.label)}"></label>
    <label class="dt-field"><span>Group</span><select name="group">${state.groups.map(g =>
      `<option value="${esc(g.name)}" ${g.name === x.group ? "selected" : ""}>${esc(g.name)} (${gi(g)})</option>`).join("")}</select></label>
    <div class="dt-field" id="dt-cats"><span>What's blocked for this device</span>
      <div class="small muted">Only this device - the group's choices are in <a href="#system">Settings</a>.</div>
      <div class="dt-cat-list">${catRows}</div></div>
    <div class="dt-field"><span>Internet</span><div class="dt-radios">
      <label class="dt-radio"><input type="radio" name="net" value="on" ${net === "on" ? "checked" : ""}> On</label>
      ${x.paused && !x.blocked_all ? `<label class="dt-radio"><input type="radio" name="net" value="keep" checked> Keep it ${esc(x.paused_reason)}</label>` : ""}
      <label class="dt-radio"><input type="radio" name="net" value="pause"> Pause for 1 hour</label>
      <label class="dt-radio"><input type="radio" name="net" value="block" ${net === "block" ? "checked" : ""}> Block all traffic until I unblock it</label>
    </div></div>
    <p class="small muted">The ways-around-the-filter protections come from the group:
      <a href="#rules">change them per group</a>.</p>
    <dl class="dt-facts small">
      <dt>IP address</dt><dd class="mono">${esc(x.ip || "-")}</dd>
      <dt>MAC address</dt><dd class="mono">${esc(x.mac || "-")}</dd>
      ${x.hostname ? `<dt>Calls itself</dt><dd>${esc(x.hostname)}</dd>` : ""}
      <dt>First seen</dt><dd>${x.first_seen ? new Date(x.first_seen * 1000).toLocaleString() : "-"}</dd>
      <dt>Last seen</dt><dd>${x.online ? "now" : ago(x.last_seen)}</dd>
    </dl>
    <div class="dt-dialog-foot"><button value="cancel" formnovalidate>Cancel</button><button value="save" class="primary">Save</button></div>
  </form>`;
  d.returnValue = "";
  d.onclose = async () => {
    if (d.returnValue !== "save") return;
    const f = new FormData(d.querySelector("form"));
    const name = String(f.get("name") || "").trim(), group = f.get("group"), netNew = f.get("net");
    const cats = {};
    $$("select[data-cat]", d).forEach(sel => {
      const now = sel.value || null, before = ov[sel.dataset.cat] || null;
      if (now !== before) cats[sel.dataset.cat] = now;
    });
    if (netNew === "block" && net !== "block" && x.device_id === DT.you &&
      !(await askConfirm({ title: "Block the device you're using?", body: "This dashboard stays reachable from it so you can unblock it.", ok: "Block", danger: true }))) return;
    await act(async () => {
      const body = {};
      if (name !== (x.name || "")) body.name = name;
      if (group !== x.group) body.group = group;
      if (Object.keys(cats).length) body.category_overrides = cats;
      if (Object.keys(body).length) await post(`/api/devices/${encodeURIComponent(id)}`, body);
      const m = { on: 0, pause: 60, block: -1 }[netNew];
      if (m !== undefined && netNew !== net) await post(`/api/devices/${encodeURIComponent(id)}/pause`, { minutes: m });
    }, "Saved");
  };
  // "Like its group" follows the group picked above
  const grpSel = d.querySelector("select[name=group]");
  grpSel.addEventListener("change", () => $$("select[data-cat]", d).forEach(sel => {
    sel.options[0].textContent = inheritText(grpSel.value, sel.dataset.cat);
  }));
  d.showModal();
  if (focus === "cats" && $("#dt-cats", d)) {
    $("#dt-cats", d).scrollIntoView({ block: "start" });
    const first = d.querySelector("select[data-cat]");
    if (first) first.focus();
  } else d.querySelector("input[name=name]").focus();
}

// ------------------------------------------------------------------ the view
views.devices = {
  shell: () => `
    <div class="page-head"><div><h1>Devices</h1><div class="muted">New devices land in <b>${esc(state.defaultGroup)}</b> until you assign them.
      Only devices in an unfiltered group (e.g. adults) bypass the filter.</div></div>
      <div class="actions">
        <input type="search" id="dt-filter" placeholder="Find a device" aria-label="Find a device">
        <select id="dt-show" aria-label="Show"><option value="">All devices</option><option value="online">Online now</option>
          <option value="new">New (not assigned)</option><option value="paused">Paused or blocked</option>
          ${state.groups.map(g => `<option value="g:${esc(g.name)}">Group: ${esc(g.name)}</option>`).join("")}</select>
      </div></div>
    <div class="panel dt-panel">
      <div class="dt-bar" id="dt-bar" hidden></div>
      <div class="scroll"><table class="dt" id="dt" aria-label="Devices" aria-multiselectable="true"><thead></thead><tbody></tbody></table></div>
      <div class="dt-status small muted" id="dt-status"></div>
    </div>`,
  init() {
    DT.sel = new Set(); DT.selecting = false; DT.renaming = null;
    const table = $("#dt"), tbody = table.querySelector("tbody");
    $("#dt-filter").oninput = renderTable;
    $("#dt-show").onchange = renderTable;
    table.querySelector("thead").addEventListener("click", e => {
      const b = e.target.closest("[data-sort]");
      if (!b) return;
      DT.sort = DT.sort.key === b.dataset.sort ? { key: b.dataset.sort, dir: -DT.sort.dir } : { key: b.dataset.sort, dir: 1 };
      try { localStorage.setItem("pg-dev-sort", JSON.stringify(DT.sort)); } catch (_) { /* fine */ }
      renderTable();
    });

    // mouse/keyboard: click selects, the name link and double-click open
    tbody.addEventListener("click", e => {
      const tr = e.target.closest("tr[data-id]");
      if (!tr) return;
      if (Date.now() - DT.lastLongPress < 700) { e.preventDefault(); return; }
      const id = tr.dataset.id;
      if (e.target.closest("[data-kebab]")) {
        const r = e.target.getBoundingClientRect();
        return menuFor(id, { x: r.right - 4, y: r.bottom + 2, touch: false });
      }
      const link = e.target.closest("a.dt-label");
      if (DT.selecting) { e.preventDefault(); return clickSelect(id, e); }
      if (link && !(e.ctrlKey || e.metaKey || e.shiftKey)) return;      // the name opens the device
      if (link) e.preventDefault();
      if (coarse() && !(e.ctrlKey || e.metaKey || e.shiftKey)) return openDevice(id);   // phones: tap opens
      clickSelect(id, e);
      focusRow(id);
    });
    tbody.addEventListener("dblclick", e => {
      const tr = e.target.closest("tr[data-id]");
      if (tr && !e.target.closest("[data-kebab]")) openDevice(tr.dataset.id);
    });
    tbody.addEventListener("contextmenu", e => {
      const tr = e.target.closest("tr[data-id]");
      if (!tr) return;
      e.preventDefault();
      if (Date.now() - DT.lastLongPress < 700) return;     // Android fires this after our long-press
      menuFor(tr.dataset.id, { x: e.clientX, y: e.clientY, touch: e.pointerType === "touch" || (e.sourceCapabilities && e.sourceCapabilities.firesTouchEvents) });
    });

    // touch: press and hold = right-click (iOS has no contextmenu event)
    let lp = null;
    const cancel = () => { if (lp) { clearTimeout(lp.t); lp.tr.classList.remove("pressing"); lp = null; } };
    tbody.addEventListener("pointerdown", e => {
      if (e.pointerType === "mouse") return;
      const tr = e.target.closest("tr[data-id]");
      if (!tr || e.target.closest("[data-kebab]")) return;
      cancel();
      tr.classList.add("pressing");
      lp = { tr, x: e.clientX, y: e.clientY, t: setTimeout(() => {
        const id = tr.dataset.id;
        tr.classList.remove("pressing");
        lp = null;
        DT.lastLongPress = Date.now();
        if (navigator.vibrate) try { navigator.vibrate(12); } catch (_) { /* not allowed */ }
        if (DT.selecting) return clickSelect(id, {});
        menuFor(id, { x: e.clientX, y: e.clientY, touch: true });
      }, 480) };
    });
    tbody.addEventListener("pointermove", e => { if (lp && Math.hypot(e.clientX - lp.x, e.clientY - lp.y) > 10) cancel(); });
    ["pointerup", "pointercancel", "pointerleave"].forEach(t => tbody.addEventListener(t, cancel));
    table.closest(".scroll").addEventListener("scroll", cancel, { passive: true });

    table.addEventListener("keydown", e => {
      if (e.target.closest(".dt-rename")) return;
      const tr = e.target.closest("tbody tr[data-id]");
      const ids = visibleIds();
      if (!tr || !ids.length) return;
      const id = tr.dataset.id, i = ids.indexOf(id);
      const move = j => {
        e.preventDefault();
        const to = ids[Math.max(0, Math.min(ids.length - 1, j))];
        if (e.shiftKey && DT.anchor) {
          const a = ids.indexOf(DT.anchor), b = ids.indexOf(to);
          setSel(ids.slice(Math.min(a, b), Math.max(a, b) + 1));
        } else if (!(e.ctrlKey || e.metaKey)) setSel([to], to);
        focusRow(to);
      };
      if (e.key === "ArrowDown") move(i + 1);
      else if (e.key === "ArrowUp") move(i - 1);
      else if (e.key === "Home") move(0);
      else if (e.key === "End") move(ids.length - 1);
      else if (e.key === " ") { e.preventDefault(); clickSelect(id, { ctrlKey: e.ctrlKey || e.metaKey }); }
      else if (e.key === "Enter") { e.preventDefault(); openDevice(id); }
      else if (e.key === "F2") { e.preventDefault(); startRename(id); }
      else if (e.key === "Delete") { e.preventDefault(); forgetDevs(DT.sel.has(id) ? [...DT.sel] : [id]); }
      else if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
        e.preventDefault();
        const r = tr.querySelector(".dt-name").getBoundingClientRect();
        menuFor(id, { x: r.left + 24, y: r.bottom, touch: false });
      } else if (e.key === "a" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); setSel(ids, ids[0]); }
      else if (e.key === "Escape") setSel([]);
    });

    $("#dt-bar").addEventListener("click", e => {
      const b = e.target.closest("[data-bar]");
      if (!b) return;
      const ids = [...DT.sel];
      const what = b.dataset.bar;
      if (what === "clear") { DT.selecting = false; return setSel([]); }
      if (!ids.length) return toast("Select a device first");
      if (what === "pause") pauseDevs(ids, 60);
      else if (what === "resume") pauseDevs(ids, 0);
      else if (what === "block") blockDevs(ids);
      else if (what === "menu") { const r = b.getBoundingClientRect(); openMenu(ids, { x: r.left, y: r.bottom + 4, touch: false }); }
    });
    $("#dt-bar").addEventListener("change", e => {
      const s = e.target.closest("[data-bar-group]");
      if (s && s.value && DT.sel.size) moveDevs([...DT.sel], s.value);
    });
    addEventListener("resize", () => closeMenu(false));
  },
  async refresh() {
    const d = await api("/api/devices");
    DT.rows = d.devices; DT.you = d.you;
    if (!dtBusy()) renderTable();
  },
};

window.addEventListener("hashchange", () => { closeMenu(false); DT.selecting = false; });
document.addEventListener("keydown", e => { if (e.key === "Escape" && DT.menu) closeMenu(); });
