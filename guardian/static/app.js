"use strict";
/* Parental Gateway dashboard - plain JS, no build step. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ------------------------------------------------------------------ api
class AuthError extends Error {}
async function api(path, opts = {}) {
  const r = await fetch(path, {
    credentials: "same-origin",
    ...opts,
    headers: { "Content-Type": "application/json", "X-Guardian": "1", ...(opts.headers || {}) },
  });
  if (r.status === 401 && !path.startsWith("/api/login")) { showLogin(); throw new AuthError("login required"); }
  let body = null;
  try { body = await r.json(); } catch (_) { /* empty */ }
  if (!r.ok) throw new Error((body && (body.detail || body.error)) || `HTTP ${r.status}`);
  return body;
}
const post = (p, b) => api(p, { method: "POST", body: JSON.stringify(b || {}) });
const del = p => api(p, { method: "DELETE" });

// ------------------------------------------------------------------ formatting
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"]; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)} ${u[i]}`;
}
function fmtMins(m) {
  m = Math.round(Number(m) || 0);
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}
function fmtDur(s) {
  s = Math.max(0, Math.round(Number(s) || 0));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  return fmtMins(s / 60);
}
function ago(ts) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}
const clock = ts => ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
const sevClass = s => ({ high: "bad", medium: "warn", low: "info" }[s] || "");

function toast(msg, ms = 2600) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), ms);
}
async function act(fn, okMsg) {
  try { await fn(); if (okMsg) toast(okMsg); await refresh(); }
  catch (e) { if (!(e instanceof AuthError)) toast(e.message, 4000); }
}

// ------------------------------------------------------------------ state
const state = { groups: [], view: null, param: null, timer: null, mode: "" };

function groupSelect(device) {
  const opts = state.groups.map(g =>
    `<option value="${esc(g.name)}" ${g.name === device.group ? "selected" : ""}>${esc(g.name)}${g.filtered ? "" : " (unfiltered)"}</option>`).join("");
  return `<select data-group="${esc(device.device_id)}" aria-label="Group">${opts}</select>`;
}
function deviceLink(id, label) { return `<a href="#device/${encodeURIComponent(id)}">${esc(label)}</a>`; }
function verdictBadge(v) {
  if (v === "blocked") return `<span class="badge bad">blocked</span>`;
  if (v === "allowed") return `<span class="badge ok">allowed</span>`;
  if (v === "error") return `<span class="badge warn">error</span>`;
  return `<span class="badge">${esc(v || "")}</span>`;
}
function bars(rows, valueKey, fmt, extra) {
  if (!rows.length) return `<div class="empty">Nothing yet today.</div>`;
  const max = Math.max(1, ...rows.map(r => Number(r[valueKey]) || 0));
  return `<div class="bars">${rows.map(r => `
    <div class="bar-row">
      <div class="bar-name" title="${esc(r.service)}">${esc(r.service)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(100 * (Number(r[valueKey]) || 0) / max).toFixed(1)}%"></div></div>
      <div class="small muted nowrap">${fmt(r[valueKey])}${extra ? " · " + extra(r) : ""}</div>
    </div>`).join("")}</div>`;
}
function alertList(alerts, withActions) {
  if (!alerts.length) return `<div class="empty">No bypass attempts. 👍</div>`;
  return alerts.map(a => `
    <div class="alert-item ${a.acknowledged ? "acked" : ""}">
      <div class="sev ${esc(a.severity)}"></div>
      <div class="body">
        <div class="title">${esc(a.title)} ${a.count > 1 ? `<span class="badge">×${a.count}</span>` : ""}</div>
        <div class="detail">${esc(a.detail)}</div>
        <div class="meta">${a.device_id ? deviceLink(a.device_id, a.device) : esc(a.client_ip || "")} · ${esc(a.action || "")} · ${ago(a.last_ts)}</div>
      </div>
      ${withActions && !a.acknowledged ? `<div class="row" style="align-items:flex-start">
        <button class="small" data-ack="${a.id}">Dismiss</button>
        ${a.dst || a.domain ? `<button class="small" data-allow="${a.id}" title="Exempt this destination and lift any automatic block">This is fine</button>` : ""}
      </div>` : ""}
    </div>`).join("");
}
function flowTable(flows, showDevice = true) {
  if (!flows.length) return `<div class="empty">No connections right now.</div>`;
  return `<div class="scroll tall"><table><thead><tr>
    ${showDevice ? "<th>Device</th>" : ""}<th>Site / service</th><th>Destination</th><th class="right">Duration</th>
    <th class="right">↓ Down</th><th class="right">↑ Up</th><th>Status</th></tr></thead><tbody>
    ${flows.map(f => `<tr>
      ${showDevice ? `<td class="nowrap">${deviceLink(f.device_id, f.device)}</td>` : ""}
      <td class="trunc" title="${esc(f.domain || "")}">${esc(f.domain || f.service)}
        ${f.domain && f.service && f.service !== f.domain ? `<div class="small faint">${esc(f.service)}${f.domain_src ? " · via " + esc(f.domain_src) : ""}</div>` : ""}</td>
      <td class="mono nowrap">${esc(f.dst_ip)}:${esc(f.dst_port)} <span class="faint">${esc(f.proto)}</span></td>
      <td class="right nowrap">${fmtDur(f.duration)}</td>
      <td class="right nowrap">${fmtBytes(f.bytes_down)}</td>
      <td class="right nowrap">${fmtBytes(f.bytes_up)}</td>
      <td>${f.verdict === "blocked" ? `<span class="badge bad" title="${esc(f.reason || "")}">blocked</span>` : f.ended ? `<span class="badge">closed</span>` : `<span class="badge ok">open</span>`}</td>
    </tr>`).join("")}</tbody></table></div>`;
}
function queryTable(rows, showDevice = true) {
  if (!rows.length) return `<div class="empty">No lookups yet.</div>`;
  return `<div class="scroll tall"><table><thead><tr><th>Time</th>${showDevice ? "<th>Device</th>" : ""}
    <th>Domain</th><th>Type</th><th>Result</th><th>Why</th></tr></thead><tbody>
    ${rows.map(q => `<tr>
      <td class="muted mono nowrap">${clock(q.ts)}</td>
      ${showDevice ? `<td class="nowrap">${deviceLink(q.device_id || q.client_ip, q.device || q.client_ip)}</td>` : ""}
      <td class="mono trunc" title="${esc(q.qname)}">${esc(q.qname)}</td>
      <td class="faint small">${esc(q.qtype)}</td>
      <td>${verdictBadge(q.action)}</td>
      <td class="small muted trunc" title="${esc(q.reason || "")}">${esc(q.reason || "")}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

// ------------------------------------------------------------------ views
const views = {};

views.overview = {
  shell: () => `
    <div class="page-head"><div><h1>Today</h1><div class="muted">Since midnight · updates every few seconds</div></div></div>
    <div class="tiles" id="ov-tiles"></div>
    <div class="grid3">
      <div>
        <div class="panel"><div class="panel-head"><h2>Time by service (all devices)</h2></div><div class="panel-body" id="ov-services"></div></div>
        <div class="panel"><div class="panel-head"><h2>Devices</h2><div class="tools"><a href="#devices">All devices →</a></div></div><div class="scroll" id="ov-devices"></div></div>
      </div>
      <div class="panel"><div class="panel-head"><h2>Latest bypass attempts</h2><div class="tools"><a href="#alerts">All →</a></div></div><div id="ov-alerts"></div></div>
    </div>`,
  async refresh() {
    const d = await api("/api/overview");
    $("#ov-tiles").innerHTML = [
      [d.devices_online + " / " + d.devices_total, "Devices online"],
      [d.counts.total.toLocaleString(), "Sites looked up"],
      [d.counts.blocked.toLocaleString(), "Lookups blocked"],
      [d.bypass_attempts.toLocaleString(), "Bypass attempts", d.bypass_attempts > 0 ? "bad" : ""],
      [fmtBytes(d.data_down + d.data_up), "Data used"],
    ].map(([n, l, c]) => `<div class="tile ${c || ""}"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");
    $("#ov-services").innerHTML = bars(d.top_services, "minutes", fmtMins, r => fmtBytes(r.bytes_down + r.bytes_up));
    $("#ov-alerts").innerHTML = alertList(d.recent_alerts, false);
    $("#ov-devices").innerHTML = d.devices.length ? `<table><thead><tr><th>Device</th><th>Group</th><th class="right">Online today</th><th class="right">Data</th><th class="right">Blocked</th></tr></thead><tbody>
      ${d.devices.map(x => `<tr><td><span class="status-dot ${x.online ? "on" : ""}"></span>${deviceLink(x.device_id, x.label)}${x.paused ? ` <span class="badge warn">paused</span>` : ""}</td>
        <td>${esc(x.group)}</td><td class="right">${fmtMins(x.minutes_today)}</td>
        <td class="right">${fmtBytes(x.bytes_down + x.bytes_up)}</td><td class="right">${x.blocked}</td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">No devices seen yet. Point a device's DNS at this gateway.</div>`;
  },
};

views.devices = {
  shell: () => `
    <div class="page-head"><div><h1>Devices</h1><div class="muted">New devices land in <b>${esc(state.defaultGroup)}</b> until you assign them. Only devices in an unfiltered group (e.g. adults) bypass the filter.</div></div></div>
    <div class="panel"><div class="scroll" id="dev-table"></div></div>`,
  async refresh() {
    const { devices } = await api("/api/devices");
    $("#dev-table").innerHTML = devices.length ? `<table><thead><tr>
      <th>Device</th><th>Group</th><th>Address</th><th class="right">Online today</th><th class="right">↓ / ↑</th>
      <th class="right">Lookups</th><th class="right">Blocked</th><th class="right">Alerts</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${devices.map(x => `<tr>
        <td><span class="status-dot ${x.online ? "on" : ""}"></span>${deviceLink(x.device_id, x.label)}
          ${x.paused ? `<span class="badge warn" title="${esc(x.paused_reason)}">paused</span>` : ""}
          ${!x.group_set ? `<span class="badge info" title="Not assigned yet - using the default group">new</span>` : ""}</td>
        <td>${groupSelect(x)}</td>
        <td class="mono small">${esc(x.ip || "")}<div class="faint">${esc(x.mac || "")}</div></td>
        <td class="right">${fmtMins(x.minutes_today)}</td>
        <td class="right nowrap">${fmtBytes(x.bytes_down)} / ${fmtBytes(x.bytes_up)}</td>
        <td class="right">${x.queries}</td><td class="right">${x.blocked}</td>
        <td class="right">${x.alerts ? `<span class="badge bad">${x.alerts}</span>` : "0"}</td>
        <td class="muted small nowrap">${ago(x.last_seen)}</td>
        <td class="nowrap">${x.paused ? `<button class="small" data-pause="${esc(x.device_id)}" data-min="0">Resume</button>`
          : `<button class="small" data-pause="${esc(x.device_id)}" data-min="60">Pause 1h</button>`}</td>
      </tr>`).join("")}</tbody></table>` : `<div class="empty">No devices yet.</div>`;
  },
};

views.device = {
  shell: () => `
    <a class="back" href="#devices">← Devices</a>
    <div class="page-head">
      <div><input class="name-input" id="dv-name" aria-label="Device name" placeholder="Name this device">
        <div class="muted small" id="dv-sub"></div></div>
      <div class="actions" id="dv-actions"></div>
    </div>
    <div class="tiles" id="dv-tiles"></div>
    <div class="grid2">
      <div class="panel"><div class="panel-head"><h2>Today by service</h2></div><div class="panel-body" id="dv-services"></div></div>
      <div class="panel"><div class="panel-head"><h2>Last 7 days</h2></div><div class="panel-body" id="dv-week"></div></div>
    </div>
    <div class="panel"><div class="panel-head"><h2>Live connections</h2></div><div id="dv-flows"></div></div>
    <div class="grid2">
      <div class="panel"><div class="panel-head"><h2>Recent lookups</h2></div><div id="dv-queries"></div></div>
      <div class="panel"><div class="panel-head"><h2>Bypass attempts</h2></div><div class="tall" id="dv-alerts"></div></div>
    </div>`,
  async refresh() {
    const id = state.param;
    const d = await api(`/api/devices/${encodeURIComponent(id)}`);
    const x = d.device;
    const nameEl = $("#dv-name");
    if (document.activeElement !== nameEl) nameEl.value = x.name || "";
    nameEl.placeholder = x.label;
    $("#dv-sub").innerHTML = `${esc(x.ip || "")} · ${esc(x.mac || "no MAC")} ${x.hostname ? "· " + esc(x.hostname) : ""} · last seen ${ago(x.last_seen)}`;
    if (!$("#dv-actions select")) {
      $("#dv-actions").innerHTML = `${groupSelect(x)}
        <button data-pause="${esc(x.device_id)}" data-min="15">Pause 15m</button>
        <button data-pause="${esc(x.device_id)}" data-min="60">Pause 1h</button>
        <button data-pause="${esc(x.device_id)}" data-min="0">Resume</button>`;
    }
    $("#dv-tiles").innerHTML = [
      [fmtMins(x.minutes_today), "Online today (approx.)"],
      [fmtBytes(x.bytes_down), "Downloaded today"],
      [fmtBytes(x.bytes_up), "Uploaded today"],
      [x.queries, "Lookups today"],
      [x.blocked, "Blocked today"],
      [x.paused ? "Paused" : x.filtered ? "Filtered" : "Unfiltered", x.paused ? x.paused_reason : "Group: " + x.group, x.paused ? "bad" : ""],
    ].map(([n, l, c]) => `<div class="tile ${c || ""}"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");
    $("#dv-services").innerHTML = bars(d.services, "minutes", fmtMins, r => fmtBytes(r.bytes_down + r.bytes_up));
    $("#dv-week").innerHTML = bars(d.week, "minutes", fmtMins, r => fmtBytes(r.bytes_down + r.bytes_up));
    $("#dv-flows").innerHTML = flowTable(d.flows, false);
    $("#dv-queries").innerHTML = queryTable(d.queries, false);
    $("#dv-alerts").innerHTML = alertList(d.alerts, true);
  },
};

views.activity = {
  shell: () => `
    <div class="page-head"><div><h1>Activity</h1><div class="muted">Live connections (where, how long, how much) and every site lookup.</div></div>
      <div class="actions">
        <select id="ac-device" aria-label="Device"><option value="">All devices</option></select>
        <label class="check"><input type="checkbox" id="ac-blocked"> Blocked lookups only</label>
      </div></div>
    <div class="panel"><div class="panel-head"><h2>Connections</h2><div class="tools muted small" id="ac-note"></div></div><div id="ac-flows"></div></div>
    <div class="panel"><div class="panel-head"><h2>Lookups</h2></div><div id="ac-queries"></div></div>`,
  async init() {
    const { devices } = await api("/api/devices");
    $("#ac-device").innerHTML += devices.map(d => `<option value="${esc(d.device_id)}">${esc(d.label)}</option>`).join("");
    $("#ac-device").onchange = refresh;
    $("#ac-blocked").onchange = refresh;
  },
  async refresh() {
    const dev = $("#ac-device").value;
    const q = dev ? `device=${encodeURIComponent(dev)}&` : "";
    const [f, qs] = await Promise.all([
      api(`/api/flows?${q}limit=300`),
      api(`/api/queries?${q}blocked=${$("#ac-blocked").checked}&limit=300`),
    ]);
    $("#ac-note").textContent = f.monitor ? `${f.live.length} open · ${f.recent.length} closed in the last hour` : "Traffic accounting is off (see System)";
    $("#ac-flows").innerHTML = flowTable([...f.live, ...f.recent]);
    $("#ac-queries").innerHTML = queryTable(qs.queries);
  },
};

views.alerts = {
  shell: () => `
    <div class="page-head"><div><h1>Bypass attempts</h1><div class="muted">Every time a device tried to get around the filter: VPNs, proxies, encrypted DNS, disguised tunnels.</div></div>
      <div class="actions"><label class="check"><input type="checkbox" id="al-unacked"> Hide dismissed</label></div></div>
    <div class="panel" id="al-list"></div>`,
  init() { $("#al-unacked").onchange = refresh; },
  async refresh() {
    const { alerts } = await api(`/api/alerts?limit=300&unacked=${$("#al-unacked").checked}`);
    $("#al-list").innerHTML = alertList(alerts, true);
  },
};

views.rules = {
  shell: () => `
    <div class="page-head"><div><h1>Rules &amp; schedules</h1><div class="muted">An allow rule beats any blocklist; a block rule adds a site to the filter.</div></div></div>
    <div class="grid2">
      <div class="panel"><div class="panel-head"><h2>Site rules</h2></div>
        <div class="panel-body"><form class="row" id="rule-form">
          <select id="r-action"><option value="block">Block</option><option value="allow">Allow</option></select>
          <select id="r-scope"></select>
          <input class="grow" id="r-pattern" placeholder="e.g. tiktok.com" required>
          <button class="primary">Add</button></form></div>
        <div class="scroll" id="rules-table"></div></div>
      <div class="panel"><div class="panel-head"><h2>Internet-off times</h2></div>
        <div class="panel-body"><form class="row" id="sched-form">
          <select id="s-target"></select>
          <input id="s-start" type="time" value="21:00" required> to <input id="s-end" type="time" value="07:00" required>
          <select id="s-days"><option value="mon,tue,wed,thu,sun">School nights (Sun–Thu)</option>
            <option value="mon,tue,wed,thu,fri,sat,sun">Every day</option><option value="mon,tue,wed,thu,fri">Weekdays</option>
            <option value="sat,sun">Weekends</option></select>
          <button class="primary">Add</button></form></div>
        <div class="scroll" id="sched-table"></div></div>
    </div>
    <div class="grid2">
      <div class="panel"><div class="panel-head"><h2>Automatically blocked destinations</h2></div><div class="scroll" id="dyn-table"></div></div>
      <div class="panel"><div class="panel-head"><h2>Marked as fine</h2></div><div class="scroll" id="allow-table"></div></div>
    </div>`,
  async init() {
    const scopes = [`<option value="global|">Everyone</option>`,
      ...state.groups.map(g => `<option value="group|${esc(g.name)}">Group: ${esc(g.name)}</option>`)];
    $("#r-scope").innerHTML = scopes.join("");
    $("#s-target").innerHTML = state.groups.filter(g => g.filtered).map(g => `<option value="group|${esc(g.name)}">Group: ${esc(g.name)}</option>`).join("")
      + `<option value="all|">All devices</option>`;
    $("#rule-form").onsubmit = e => {
      e.preventDefault();
      const [scope, target] = $("#r-scope").value.split("|");
      act(() => post("/api/rules", { action: $("#r-action").value, scope, target, pattern: $("#r-pattern").value }), "Rule added")
        .then(() => { $("#r-pattern").value = ""; });
    };
    $("#sched-form").onsubmit = e => {
      e.preventDefault();
      const [scope, target] = $("#s-target").value.split("|");
      act(() => post("/api/schedules", { scope, target, start: $("#s-start").value, end: $("#s-end").value, days: $("#s-days").value }), "Schedule added");
    };
  },
  async refresh() {
    const [r, s] = await Promise.all([api("/api/rules"), api("/api/schedules")]);
    $("#rules-table").innerHTML = r.rules.length ? `<table><thead><tr><th>Action</th><th>Applies to</th><th>Site</th><th></th></tr></thead><tbody>
      ${r.rules.map(x => `<tr><td><span class="badge ${x.action === "block" ? "bad" : "ok"}">${esc(x.action)}</span></td>
        <td>${x.scope === "global" ? "Everyone" : esc(x.scope + ": " + (x.target || ""))}</td><td class="mono">${esc(x.pattern)}</td>
        <td class="right"><button class="small danger" data-del="/api/rules/${x.id}">Remove</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">No custom rules.</div>`;
    $("#sched-table").innerHTML = s.schedules.length ? `<table><thead><tr><th>Who</th><th>Off between</th><th>Days</th><th></th></tr></thead><tbody>
      ${s.schedules.map(x => `<tr><td>${x.scope === "all" ? "All devices" : esc(x.scope + ": " + (x.target || ""))}</td>
        <td class="nowrap">${esc(x.start)} – ${esc(x.end)}</td><td class="small">${esc(x.days)}</td>
        <td class="right"><button class="small danger" data-del="/api/schedules/${x.id}">Remove</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">No schedules.</div>`;
    $("#dyn-table").innerHTML = r.dyn_blocks.length ? `<table><thead><tr><th>Destination</th><th>Why</th><th>Until</th><th></th></tr></thead><tbody>
      ${r.dyn_blocks.map(x => `<tr><td class="mono">${esc(x.ip)}</td><td class="small muted">${esc(x.reason)}</td>
        <td class="small nowrap">${new Date(x.expires * 1000).toLocaleString()}</td>
        <td class="right"><button class="small" data-del="/api/dynblocks/${encodeURIComponent(x.ip)}">Unblock</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">Nothing blocked by the behaviour detector.</div>`;
    $("#allow-table").innerHTML = r.allowlist.length ? `<table><tbody>
      ${r.allowlist.map(x => `<tr><td><span class="badge">${esc(x.kind)}</span></td><td class="mono">${esc(x.value)}</td>
        <td class="small muted">${esc(x.note || "")}</td><td class="right"><button class="small danger" data-del="/api/allowlist/${x.id}">Remove</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">Nothing exempted.</div>`;
  },
};

views.system = {
  shell: () => `
    <div class="page-head"><div><h1>System</h1></div>
      <div class="actions"><button id="sys-update">Update blocklists now</button></div></div>
    <div class="tiles" id="sys-tiles"></div>
    <div class="grid2">
      <div class="panel"><div class="panel-head"><h2>Components</h2></div><div class="panel-body" id="sys-comp"></div></div>
      <div class="panel"><div class="panel-head"><h2>Change password</h2></div><div class="panel-body">
        <form class="row" id="pw-form"><input type="password" id="pw-cur" placeholder="Current" required autocomplete="current-password">
          <input type="password" id="pw-new" placeholder="New (8+ chars)" required autocomplete="new-password">
          <button class="primary">Change</button></form></div></div>
    </div>
    <div class="panel"><div class="panel-head"><h2>Blocklists</h2><div class="tools small muted" id="sys-lists-note"></div></div><div class="scroll" id="sys-lists"></div></div>
    <div class="panel"><div class="panel-head"><h2>Inspector counters</h2></div><div class="panel-body" id="sys-insp"></div></div>`,
  init() {
    $("#sys-update").onclick = () => act(() => post("/api/system/update-lists"), "Updating lists in the background…");
    $("#pw-form").onsubmit = e => {
      e.preventDefault();
      act(() => post("/api/password", { current: $("#pw-cur").value, new: $("#pw-new").value }), "Password changed")
        .then(() => { $("#pw-cur").value = $("#pw-new").value = ""; });
    };
  },
  async refresh() {
    const s = await api("/api/system");
    $("#sys-tiles").innerHTML = [
      [s.mode === "gateway" ? "Gateway" : "Monitor", "Mode"],
      [fmtDur(s.uptime), "Uptime"],
      [s.dns.queries.toLocaleString(), "Lookups since start"],
      [s.dns.remembered_answers.toLocaleString(), "Remembered DNS answers"],
      [s.monitor ? s.monitor.active_flows : "—", "Open connections"],
    ].map(([n, l]) => `<div class="tile"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");
    const ok = (b, t) => `<span class="badge ${b ? "ok" : "bad"}">${esc(t)}</span>`;
    const gw = s.gateway;
    $("#sys-comp").innerHTML = `<dl class="kv">
      <dt>DNS filter</dt><dd>${ok(true, "running")}</dd>
      <dt>Firewall</dt><dd>${gw ? ok(gw.applied, gw.applied ? `active (${gw.backend})` : "not applied") : `<span class="badge">off in monitor mode</span>`}</dd>
      <dt>Inspector</dt><dd>${gw ? ok(gw.nfq_running, gw.nfq_running ? `running · ${(gw.nfq_handled || 0).toLocaleString()} packets` : "stopped") : `<span class="badge">off in monitor mode</span>`}</dd>
      <dt>Traffic accounting</dt><dd>${s.monitor ? ok(!s.monitor.error, s.monitor.error ? s.monitor.error : `${s.monitor.backend}, updated ${ago(s.monitor.last_tick)}`) : ok(false, "unavailable")}</dd>
      <dt>Behaviour detector</dt><dd>${s.detector ? ok(true, "last run " + ago(s.detector.last_run)) : `<span class="badge">off</span>`}</dd>
      ${Object.entries(s.errors || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${ok(false, v)}</dd>`).join("")}
    </dl>`;
    $("#sys-lists-note").textContent = s.lists.updating ? "Updating…" : s.lists.last_update ? `Updated ${ago(s.lists.last_update)}` : "Not downloaded yet this run";
    $("#sys-lists").innerHTML = `<table><thead><tr><th>List</th><th class="right">Entries</th><th>Sources</th></tr></thead><tbody>
      ${Object.entries(s.lists.status).map(([k, v]) => `<tr><td class="nowrap"><b>${esc(k.split(":")[1])}</b> <span class="faint small">${esc(v.kind)}</span></td>
        <td class="right">${v.entries.toLocaleString()}</td>
        <td class="small">${v.sources.map(src => `<div>${src.ok ? "✅" : "⚠️"} <span class="mono">${esc(src.source.length > 70 ? "…" + src.source.slice(-68) : src.source)}</span>
          <span class="muted">${src.entries.toLocaleString()}${src.error ? " · " + esc(src.error) : ""}</span></div>`).join("")}</td></tr>`).join("")}
      </tbody></table>`;
    const insp = Object.entries(s.inspector || {}).sort((a, b) => b[1] - a[1]);
    $("#sys-insp").innerHTML = insp.length ? `<dl class="kv">${insp.map(([k, v]) => `<dt class="mono">${esc(k)}</dt><dd>${v.toLocaleString()}</dd>`).join("")}</dl>`
      : `<span class="muted">No packets inspected (inline inspection runs in gateway mode).</span>`;
  },
};

// ------------------------------------------------------------------ router & events
async function render() {
  const [view, ...rest] = (location.hash.slice(1) || "overview").split("/");
  const v = views[view] ? view : "overview";
  state.view = v; state.param = rest.length ? decodeURIComponent(rest.join("/")) : null;
  $$("#tabs a").forEach(a => a.classList.toggle("active", a.dataset.v === (v === "device" ? "devices" : v)));
  $("#view").innerHTML = views[v].shell();
  try {
    if (views[v].init) await views[v].init();
    await views[v].refresh();
  } catch (e) { if (!(e instanceof AuthError)) $("#view").insertAdjacentHTML("afterbegin", `<div class="error">${esc(e.message)}</div>`); }
}
async function refresh() {
  if (!state.view) return;
  try {
    await views[state.view].refresh();
    const { alerts } = await api("/api/alerts?limit=200&unacked=true");
    const n = alerts.filter(a => a.severity !== "info").length;
    const c = $("#alert-count"); c.hidden = !n; c.textContent = n;
  } catch (_) { /* shown elsewhere */ }
}

document.addEventListener("change", e => {
  const sel = e.target.closest("select[data-group]");
  if (sel) act(() => post(`/api/devices/${encodeURIComponent(sel.dataset.group)}`, { group: sel.value }), `Moved to ${sel.value}`);
});
document.addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.pause !== undefined) {
    const m = Number(b.dataset.min);
    act(() => post(`/api/devices/${encodeURIComponent(b.dataset.pause)}/pause`, { minutes: m }), m ? `Paused for ${fmtMins(m)}` : "Resumed");
  } else if (b.dataset.ack) act(() => post(`/api/alerts/${b.dataset.ack}/ack`), "Dismissed");
  else if (b.dataset.allow) act(() => post(`/api/alerts/${b.dataset.allow}/allow`), "Marked as fine");
  else if (b.dataset.del) act(() => del(b.dataset.del), "Removed");
});
document.addEventListener("focusout", e => {
  if (e.target.id === "dv-name" && state.param) {
    act(() => post(`/api/devices/${encodeURIComponent(state.param)}`, { name: e.target.value }), "Saved");
  }
});
document.addEventListener("keydown", e => { if (e.target.id === "dv-name" && e.key === "Enter") e.target.blur(); });
window.addEventListener("hashchange", render);

// ------------------------------------------------------------------ login
let setupMode = false;
function showLogin(sess) {
  clearInterval(state.timer);
  $("#app").hidden = true; $("#login").hidden = false;
  setupMode = !!(sess && sess.needs_setup);
  $("#login-pw2").hidden = !setupMode;
  $("#login-title").textContent = setupMode ? "Welcome" : "Parental Gateway";
  $("#login-sub").textContent = setupMode
    ? (sess.setup_allowed ? "Choose a dashboard password (8+ characters)." : "Set a password on the gateway first: python run.py --set-password")
    : "Sign in to manage your network.";
  $("#login-btn").textContent = setupMode ? "Set password" : "Sign in";
  $("#login-btn").disabled = setupMode && !sess.setup_allowed;
  $("#login-pw").focus();
}
$("#login-form").onsubmit = async e => {
  e.preventDefault();
  $("#login-err").textContent = "";
  const pw = $("#login-pw").value;
  try {
    if (setupMode) {
      if (pw !== $("#login-pw2").value) throw new Error("Passwords don't match");
      await post("/api/setup", { password: pw });
    } else {
      await post("/api/login", { password: pw });
    }
    $("#login-pw").value = $("#login-pw2").value = "";
    start();
  } catch (err) { $("#login-err").textContent = err.message; }
};
$("#logout").onclick = async () => { try { await post("/api/logout"); } catch (_) { } location.reload(); };

async function start() {
  const sess = await api("/api/session");
  if (!sess.authenticated) return showLogin(sess);
  $("#login").hidden = true; $("#app").hidden = false;
  const g = await api("/api/groups");
  state.groups = g.groups; state.defaultGroup = g.default_group; state.mode = sess.mode;
  const mb = $("#mode-badge");
  mb.textContent = sess.mode === "gateway" ? "Gateway mode" : "Monitor mode";
  mb.className = "badge " + (sess.mode === "gateway" ? "ok" : "info");
  await render();
  clearInterval(state.timer);
  state.timer = setInterval(() => { if (!document.hidden) refresh(); }, 5000);
}
start();
