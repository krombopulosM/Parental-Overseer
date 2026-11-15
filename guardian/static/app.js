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
function confBadge(a) {
  if (a.confidence == null) return "";
  const c = a.confidence, cls = c >= 80 ? "hi" : c >= 50 ? "mid" : "";
  const fp = c >= 80 ? "low" : c >= 50 ? "medium" : "high";
  const tip = [`${c}% likely to be a deliberate bypass attempt (false-positive risk: ${fp})`, "",
    ...(a.confidence_why || []), "", a.fp_note ? `Could be innocent if: ${a.fp_note}` : ""].join("\n");
  return `<span class="conf ${cls}" title="${esc(tip)}"><span class="bar"><i style="width:${c}%"></i></span>${c}% deliberate</span>`;
}
const REVIEW_HELP = {
  allow_ip: "Not a bypass: stop blocking this destination for this check, and trust similar alerts less",
  identity: "It's me: trust this device again and accept its new fingerprint",
  none: "Not a bypass: trust similar alerts less in future (use Rules to unblock a site)",
};
function alertList(alerts, withActions) {
  if (!alerts.length) return `<div class="empty">No bypass attempts. 👍</div>`;
  return alerts.map(a => `
    <div class="alert-item ${a.acknowledged ? "acked" : ""}">
      <div class="sev ${esc(a.severity)}"></div>
      <div class="body">
        <div class="title">${esc(a.title)} ${a.count > 1 ? `<span class="badge">×${a.count}</span>` : ""} ${confBadge(a)}</div>
        <div class="detail">${esc(a.detail)}</div>
        <div class="meta">${a.device_id ? deviceLink(a.device_id, a.device) : esc(a.device || "")} · ${esc(a.action || "")} · ${ago(a.last_ts)}
          ${a.category_label && a.category !== "info" ? ` · ${esc(a.category_label)}` : ""}
          ${a.review ? ` · <span class="reviewed">${a.review === "fp" ? "you marked: not a bypass" : "you confirmed it"}</span>` : ""}</div>
      </div>
      ${withActions && !a.acknowledged ? `<div class="row" style="align-items:flex-start">
        ${a.confidence != null ? `<button class="small" data-review="${a.id}" data-verdict="tp" title="Yes, this was a real attempt: trust similar alerts more">Confirmed</button>
        <button class="small" data-review="${a.id}" data-verdict="fp" title="${esc(REVIEW_HELP[a.fp_action] || REVIEW_HELP.none)}">${a.fp_action === "identity" ? "It's me" : "Not a bypass"}</button>` : ""}
        <button class="small" data-ack="${a.id}">Dismiss</button>
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

const CATS = ["vpn", "dns", "disguise", "torrent", "tamper", "download"];
const ACTS = ["video", "gaming", "browsing", "download", "social", "music", "call", "other"];
const fmtRate = v => fmtBytes(v) + "/s";
function actBadge(cls, label) {
  return `<span class="actbadge"><span class="sw" style="background:var(--act-${esc(cls)})"></span>${esc(label)}</span>`;
}
function liveArea(el, series, classes, poll) {
  const W = Math.max(320, el.clientWidth - 32), H = 230, L = 62, B = 22, T = 10, R = 8;
  const now = Date.now() / 1000, span = 300, x0 = now - span;
  const pts = series.filter(p => p.ts >= x0 - poll);
  const val = (p, c) => Number(p[c]) || 0;
  const totals = pts.map(p => ACTS.reduce((s, c) => s + val(p, c), 0));
  const max = niceMax(Math.max(...totals, 50000));
  const pw = W - L - R, ph = H - T - B;
  const x = ts => L + Math.max(0, Math.min(1, (ts - x0) / span)) * pw;
  const y = v => T + ph - (v / max) * ph;
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Live throughput by activity, last 5 minutes">`;
  for (const t of [0, max / 2, max]) {
    svg += `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}"/>`;
    svg += `<text class="axis" x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${t ? fmtRate(t) : "0"}</text>`;
  }
  for (let m = 5; m >= 0; m--) {
    svg += `<text class="axis" x="${x(now - m * 60)}" y="${H - 6}" text-anchor="${m === 0 ? "end" : "middle"}">${m ? `-${m} min` : "now"}</text>`;
  }
  if (pts.length > 1) {
    const base = pts.map(() => 0);
    for (const c of ACTS) {
      if (!pts.some(p => val(p, c))) continue;
      const top = pts.map((p, i) => base[i] + val(p, c));
      const up = pts.map((p, i) => `${x(p.ts).toFixed(1)},${y(top[i]).toFixed(1)}`);
      const down = pts.map((p, i) => `${x(p.ts).toFixed(1)},${y(base[i]).toFixed(1)}`).reverse();
      svg += `<path d="M${up.join(" L")} L${down.join(" L")} Z" fill="var(--act-${c})" stroke="var(--panel)" stroke-width="1"/>`;
      top.forEach((v, i) => { base[i] = v; });
    }
  }
  svg += `<line id="xh" x1="0" x2="0" y1="${T}" y2="${T + ph}" stroke="var(--muted)" stroke-dasharray="3 3" visibility="hidden"/>`;
  svg += `<rect id="hit" x="${L}" y="${T}" width="${pw}" height="${ph}" fill="transparent"/></svg><div class="tip" hidden></div>`;
  el.innerHTML = svg;
  if (!pts.length) return;
  const tip = $(".tip", el), xh = $("#xh", el);
  el.onmousemove = e => {
    if (e.target.id !== "hit") { tip.hidden = true; xh.setAttribute("visibility", "hidden"); return; }
    const box = el.querySelector("svg").getBoundingClientRect();
    const ts = x0 + ((e.clientX - box.left) * (W / box.width) - L) / pw * span;
    let k = 0;
    pts.forEach((p, i) => { if (Math.abs(p.ts - ts) < Math.abs(pts[k].ts - ts)) k = i; });
    const p = pts[k];
    xh.setAttribute("x1", x(p.ts)); xh.setAttribute("x2", x(p.ts)); xh.setAttribute("visibility", "visible");
    const rows = ACTS.filter(c => val(p, c)).map(c => `<div class="row"><span><span class="sw" style="background:var(--act-${c})"></span>${esc(classes[c])}</span><b>${fmtRate(val(p, c))}</b></div>`);
    tip.innerHTML = `<div class="muted" style="margin-bottom:4px">${clock(p.ts)}</div>${rows.join("") || `<div class="muted">idle</div>`}`;
    tip.hidden = false;
    const ob = el.getBoundingClientRect();
    tip.style.left = Math.min(ob.width - tip.offsetWidth - 4, e.clientX - ob.left + 14) + "px";
    tip.style.top = Math.max(0, Math.min(ob.height - tip.offsetHeight - 4, e.clientY - ob.top - 30)) + "px";
  };
  el.onmouseleave = () => { tip.hidden = true; xh.setAttribute("visibility", "hidden"); };
}
function miniSpark(vals) {
  const max = Math.max(...vals, 1), w = 120, h = 28;
  const pts = vals.map((v, i) => `${(i / Math.max(1, vals.length - 1) * w).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`);
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-hidden="true"><polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${pts.join(" ")}"/></svg>`;
}

views.live = {
  fast: true,
  shell: () => state.param ? `
    <a class="back" href="#live">← All devices</a>
    <div class="page-head"><div><h1 id="lv-title">…</h1><div class="muted">Updates every 2 seconds. Inferred from the shape of the traffic - encrypted content is never read.</div></div>
      <div class="actions"><a class="btn" id="lv-dev-link">Device page</a></div></div>
    <div class="now"><span class="pulse"></span><div class="headline" id="lv-now">…<div class="why"></div></div><div id="lv-conf"></div></div>
    <div class="panel"><div class="panel-head"><h2>What it's doing, last 5 minutes</h2><div class="tools legend-live" id="lv-legend"></div></div>
      <div class="chart-wrap" id="lv-chart"></div></div>
    <div class="panel"><div class="panel-head"><h2>Connections right now</h2></div><div id="lv-flows"></div></div>` : `
    <div class="page-head"><div><h1>Live</h1><div class="muted">What each device is doing right now, judged from its traffic.</div></div></div>
    <div class="live-grid" id="lv-grid"></div>`,
  async refresh() {
    if (!state.param) {
      const d = await api("/api/live");
      $("#lv-grid").innerHTML = !d.monitor ? `<div class="empty">Traffic accounting is off (see System).</div>` :
        d.devices.length ? d.devices.map(x => `<a class="card live-card" href="#live/${encodeURIComponent(x.device_id)}">
          <div class="card-head"><div class="name">${esc(x.label)}</div>${x.activity !== "idle" ? actBadge(x.activity, x.activity) : `<span class="badge">idle</span>`}</div>
          <div class="hl">${esc(x.headline)}</div>
          <div class="row" style="justify-content:space-between"><span class="small muted">${fmtRate(x.rate)} · ${esc(x.group)}</span>${miniSpark(x.spark)}</div></a>`).join("")
        : `<div class="empty">No device is using the internet right now.</div>`;
      return;
    }
    const d = await api(`/api/live/${encodeURIComponent(state.param)}`);
    $("#lv-title").textContent = d.label || state.param;
    $("#lv-dev-link").href = `#device/${encodeURIComponent(state.param)}`;
    const n = d.now || { headline: "Idle", why: [] };
    $("#lv-now").innerHTML = `${esc(n.headline)}<div class="why">${esc((n.why || []).join(" · "))}</div>`;
    $("#lv-conf").innerHTML = n.confidence ? `<span class="conf ${n.confidence >= 80 ? "" : ""}" title="How sure the traffic analysis is"><span class="bar"><i style="width:${n.confidence}%"></i></span>${n.confidence}% sure</span>` : "";
    const last = d.series.slice(-3);
    const cur = c => last.reduce((s, p) => s + (Number(p[c]) || 0), 0) / Math.max(1, last.length);
    $("#lv-legend").innerHTML = ACTS.filter(c => d.series.some(p => p[c])).map(c =>
      `<span><span class="sw" style="background:var(--act-${c})"></span>${esc(d.classes[c])} <b>${fmtRate(cur(c))}</b></span>`).join("") || "<span>idle</span>";
    liveArea($("#lv-chart"), d.series, d.classes, d.poll || 2);
    $("#lv-flows").innerHTML = d.flows.length ? `<div class="scroll tall"><table><thead><tr><th>Site / service</th><th>Doing</th>
      <th class="right">↓ now</th><th class="right">↑ now</th><th class="right">Duration</th><th class="right">Total ↓</th><th>Destination</th></tr></thead><tbody>
      ${d.flows.map(f => `<tr><td class="trunc" title="${esc(f.domain || "")}">${esc(f.domain || f.service)}</td>
        <td title="${esc((f.activity_why || []).join("; "))}">${f.activity !== "idle" ? actBadge(f.activity, f.activity_label) : `<span class="faint small">idle</span>`}
          ${f.download === "held" ? ` <span class="badge bad">held</span>` : ""}</td>
        <td class="right nowrap">${fmtRate(f.rate_down)}</td><td class="right nowrap">${fmtRate(f.rate_up)}</td>
        <td class="right nowrap">${fmtDur(f.duration)}</td><td class="right nowrap">${fmtBytes(f.bytes_down)}</td>
        <td class="mono small nowrap">${esc(f.dst_ip)}:${esc(f.dst_port)} <span class="faint">${esc(f.proto)}</span></td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty">No connections right now.</div>`;
  },
};

views.downloads = {
  shell: () => `
    <div class="page-head"><div><h1>Downloads</h1><div class="muted" id="dl-sub"></div></div></div>
    <div class="page-head" style="margin:4px 0 10px"><h2>Waiting for your decision</h2></div>
    <div class="cards" id="dl-pending"></div>
    <div class="panel" style="margin-top:18px"><div class="panel-head"><h2>All downloads</h2></div><div class="scroll" id="dl-all"></div></div>`,
  async refresh() {
    const d = await api("/api/downloads?limit=300");
    $("#dl-sub").textContent = `Policy: ${d.policy.replace("_", " ")}. Files are judged by where they come from and who's downloading - ` +
      `encrypted downloads can't be opened. ` + (d.inline ? "" : "Monitor mode: nothing is actually stopped.");
    $("#dl-pending").innerHTML = d.pending.length ? d.pending.map(x => `
      <div class="card dl-card">
        <div class="card-head"><div style="min-width:0"><div class="site">${esc(x.filename || x.site)}</div>
          <div class="small muted">${x.filename ? esc(x.site) + " · " : ""}${deviceLink(x.device_id, x.device)} · ${ago(x.ts)}</div></div>
          <span class="score-pill" title="Suspicion score">${x.score}/100</span></div>
        <div class="small" style="margin-top:8px">${x.bytes_seen ? `${fmtBytes(x.bytes_seen)} received before it was stopped` : "stopped before it started"}</div>
        <ul>${x.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>
        <div class="row" style="margin-top:12px"><button class="primary" data-dl="${x.id}" data-do="approve" title="Unblock this site for this device; the download can be retried">Approve</button>
          <button class="danger" data-dl="${x.id}" data-do="deny" title="Keep this site blocked for this device">Deny</button></div>
      </div>`).join("") : `<div class="empty">Nothing waiting. 👍</div>`;
    const st = { pending: "warn", approved: "ok", allowed: "", denied: "bad" };
    $("#dl-all").innerHTML = d.downloads.length ? `<table><thead><tr><th>When</th><th>Device</th><th>From</th><th>File</th>
      <th class="right">Seen</th><th class="right">Suspicion</th><th>Status</th></tr></thead><tbody>
      ${d.downloads.map(x => `<tr><td class="small nowrap muted">${new Date(x.ts * 1000).toLocaleString()}</td>
        <td class="nowrap">${deviceLink(x.device_id, x.device)}</td><td class="mono small">${esc(x.site)}</td>
        <td class="small">${esc(x.filename || "")}</td><td class="right nowrap">${x.bytes_seen ? fmtBytes(x.bytes_seen) : ""}</td>
        <td class="right" title="${esc(x.reasons.join("\n"))}">${x.score}</td>
        <td><span class="badge ${st[x.status] || ""}" title="${esc(x.note || "")}">${esc(x.status)}</span></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">No downloads noticed yet.</div>`;
  },
};
const STATUS = {
  tampering: ["critical", "!", "Tampering"], persistent: ["serious", "!", "Persistent"],
  curious: ["warning", "?", "Curious"], clean: ["good", "✓", "Clean"],
};
function statusBadge(s) {
  const [lvl, icon, label] = STATUS[s] || STATUS.clean;
  return `<span class="status"><span class="ic" style="background:var(--st-${lvl});${lvl === "warning" ? "color:#222" : ""}">${icon}</span>${label}</span>`;
}
function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function stackedBars(el, h, catLabels) {
  // h.hourly: {cat: [24 counts]}, oldest first; one stacked bar per hour
  const n = 24, W = Math.max(320, el.clientWidth - 32), H = 210, L = 34, B = 22, T = 8;
  const totals = [...Array(n).keys()].map(i => CATS.reduce((s, c) => s + h.hourly[c][i], 0));
  const max = niceMax(Math.max(...totals, 1));
  const pw = W - L - 6, ph = H - T - B, slot = pw / n, bw = Math.max(4, Math.min(22, slot - 4));
  const y = v => T + ph - (v / max) * ph;
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Bypass attempts per hour, last 24 hours">`;
  for (const t of [0, max / 2, max]) {
    svg += `<line class="grid" x1="${L}" x2="${W - 6}" y1="${y(t)}" y2="${y(t)}"/>`;
    svg += `<text class="axis" x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${t}</text>`;
  }
  for (let i = 0; i < n; i++) {
    const x = L + i * slot + (slot - bw) / 2;
    let base = 0;
    const segs = CATS.filter(c => h.hourly[c][i] > 0);
    segs.forEach((c, k) => {
      const v = h.hourly[c][i], y0 = y(base), y1 = y(base + v);
      const gap = k > 0 ? 2 : 0, top = k === segs.length - 1;
      const hh = Math.max(1, y0 - y1 - gap), yy = y1;
      if (top && hh > 4) {
        const r = Math.min(4, bw / 2);
        svg += `<path fill="var(--cat-${c})" d="M${x},${yy + hh} V${yy + r} Q${x},${yy} ${x + r},${yy} H${x + bw - r} Q${x + bw},${yy} ${x + bw},${yy + r} V${yy + hh} Z"/>`;
      } else {
        svg += `<rect fill="var(--cat-${c})" x="${x}" y="${yy}" width="${bw}" height="${hh}"/>`;
      }
      base += v;
    });
    if (i % 4 === 3 || i === n - 1) {
      const d = new Date((h.hourly_start + (i + 1) * 3600) * 1000);
      svg += `<text class="axis" x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${String(d.getHours()).padStart(2, "0")}:00</text>`;
    }
    svg += `<rect data-i="${i}" x="${L + i * slot}" y="${T}" width="${slot}" height="${ph}" fill="transparent"/>`;
  }
  svg += `</svg><div class="tip" hidden></div>`;
  el.innerHTML = svg;
  const tip = $(".tip", el);
  el.onmousemove = e => {
    const r = e.target.closest("rect[data-i]");
    if (!r) { tip.hidden = true; return; }
    const i = Number(r.dataset.i), s = new Date((h.hourly_start + i * 3600) * 1000);
    const hh = d => String(d.getHours()).padStart(2, "0") + ":00";
    tip.innerHTML = `<div class="muted" style="margin-bottom:4px">${hh(s)}–${hh(new Date(s.getTime() + 3600e3))}</div>` +
      CATS.filter(c => h.hourly[c][i]).map(c => `<div class="row"><span><span class="sw" style="background:var(--cat-${c})"></span>${esc(catLabels[c])}</span><b>${h.hourly[c][i]}</b></div>`).join("") +
      `<div class="row" style="margin-top:4px"><span class="muted">Total</span><b>${totals[i]}</b></div>`;
    tip.hidden = false;
    const box = el.getBoundingClientRect();
    tip.style.left = Math.min(box.width - tip.offsetWidth - 4, e.clientX - box.left + 12) + "px";
    tip.style.top = Math.max(0, Math.min(box.height - tip.offsetHeight - 4, e.clientY - box.top - 20)) + "px";
  };
  el.onmouseleave = () => { tip.hidden = true; };
}
function spark(daily, title) {
  const max = Math.max(...daily, 1);
  return `<div class="spark" title="${esc(title)}">${daily.map((v, i) =>
    `<span class="${v ? "" : "zero"}" style="height:${v ? Math.max(8, 100 * v / max) : 6}%" title="${daily.length - 1 - i === 0 ? "today" : (daily.length - 1 - i) + "d ago"}: ${v}"></span>`).join("")}</div>`;
}

views.health = {
  shell: () => `
    <div class="page-head"><div><h1>Health</h1><div class="muted">Is the protection working, and who has been trying to get around it?</div></div>
      <div class="actions"><select id="hl-days" aria-label="Period"><option value="7">Last 7 days</option><option value="14">Last 14 days</option><option value="30">Last 30 days</option></select></div></div>
    <div class="health-top">
      <div class="score" id="hl-score"></div>
      <div class="panel" style="margin:0"><div class="panel-head"><h2>Protection checks</h2></div><div class="checks" id="hl-checks"></div></div>
    </div>
    <div class="tiles" id="hl-tiles"></div>
    <div class="panel"><div class="panel-head"><h2>Bypass attempts, last 24 hours</h2>
      <div class="tools"><div class="legend" id="hl-legend"></div><button class="small" id="hl-table-btn">Table</button></div></div>
      <div class="chart-wrap" id="hl-chart"></div><div class="scroll" id="hl-table" hidden></div></div>
    <div class="page-head" style="margin:22px 0 12px"><div><h2>Devices</h2></div></div>
    <div class="cards" id="hl-cards"></div>
    <div class="panel" style="margin-top:16px"><div class="panel-head"><h2>Your reviews</h2></div><div class="panel-body" id="hl-reviews"></div></div>`,
  init() {
    $("#hl-days").onchange = refresh;
    $("#hl-table-btn").onclick = () => {
      const t = $("#hl-table"), c = $("#hl-chart");
      t.hidden = !t.hidden; c.hidden = !t.hidden; $("#hl-table-btn").textContent = t.hidden ? "Table" : "Chart";
      if (!c.hidden && views.health.last) stackedBars(c, views.health.last, views.health.last.categories);
    };
  },
  async refresh() {
    const h = await api(`/api/health?days=${$("#hl-days").value}`);
    views.health.last = h;
    const lv = h.overall === "Healthy" ? "good" : h.overall === "At risk" ? "critical" : "warning";
    $("#hl-score").innerHTML = `<div class="n">${h.score}</div><div><span class="status"><span class="ic" style="background:var(--st-${lv});${lv === "warning" ? "color:#222" : ""}">${lv === "good" ? "✓" : "!"}</span>${esc(h.overall)}</span></div>
      <div class="l small" style="margin-top:8px">${h.checks.filter(c => c.level !== "ok").length} of ${h.checks.length} checks need attention</div>`;
    $("#hl-checks").innerHTML = h.checks.map(c => `<div class="check"><span class="ic ${c.level}">${c.level === "ok" ? "✓" : "!"}</span>
      <div><div class="t">${esc(c.name)}</div><div class="d">${esc(c.detail)}</div></div></div>`).join("");
    $("#hl-tiles").innerHTML = CATS.map(c => `<div class="tile"><div class="n">${h.totals[c].toLocaleString()}</div>
      <div class="l"><span class="sw" style="background:var(--cat-${c})"></span>${esc(h.categories[c])} · ${h.days}d</div></div>`).join("");
    $("#hl-legend").innerHTML = CATS.map(c => `<span><span class="sw" style="background:var(--cat-${c})"></span>${esc(h.categories[c])}</span>`).join("");
    if (!$("#hl-chart").hidden) stackedBars($("#hl-chart"), h, h.categories);
    $("#hl-table").innerHTML = `<table><thead><tr><th>Hour</th>${CATS.map(c => `<th class="right">${esc(h.categories[c])}</th>`).join("")}<th class="right">Total</th></tr></thead><tbody>
      ${[...Array(24).keys()].reverse().filter(i => CATS.some(c => h.hourly[c][i])).map(i => {
        const d = new Date((h.hourly_start + i * 3600) * 1000);
        return `<tr><td class="nowrap">${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</td>${CATS.map(c => `<td class="right">${h.hourly[c][i]}</td>`).join("")}
          <td class="right"><b>${CATS.reduce((s, c) => s + h.hourly[c][i], 0)}</b></td></tr>`; }).join("") || `<tr><td colspan="7" class="empty">No attempts in the last 24 hours.</td></tr>`}
      </tbody></table>`;
    $("#hl-cards").innerHTML = h.devices.length ? h.devices.map(d => `
      <div class="card">
        <div class="card-head"><div style="min-width:0"><div class="name">${d.device_id === "gateway" ? esc(d.label) : deviceLink(d.device_id, d.label)}</div>
          <div class="small muted">${esc(d.group || "")}${d.online ? " · online" : ""}${d.paused ? " · paused" : ""}${d.suspect ? " · identity check" : ""}</div></div>
          ${statusBadge(d.status)}</div>
        <div class="stat-row">
          <div><div class="n">${d.attempts_today}</div><div class="l">attempts today</div></div>
          <div><div class="n">${d.attempts}</div><div class="l">attempts · ${h.days}d</div></div>
          <div><div class="n">${d.techniques}</div><div class="l">techniques</div></div>
          <div><div class="n">${d.blocked_total}</div><div class="l">sites blocked</div></div>
        </div>
        ${spark(d.daily, `Bypass attempts per day, last ${h.days} days`)}
        <div class="chips">${CATS.filter(c => d.by_category[c]).map(c => `<span class="chip"><span class="sw" style="background:var(--cat-${c})"></span>${esc(h.categories[c])} <b>${d.by_category[c]}</b></span>`).join("")}
          ${d.max_confidence ? `<span class="chip">most certain: <b>${d.max_confidence}%</b></span>` : ""}
          ${d.last_attempt ? `<span class="chip">last try ${ago(d.last_attempt)}</span>` : ""}</div>
        ${(d.top_blocked || []).length ? `<div class="small muted" style="margin-top:10px">Most-blocked: ${d.top_blocked.map(t => `<span class="mono">${esc(t.qname)}</span> ×${t.n}`).join(", ")}</div>` : ""}
      </div>`).join("") : `<div class="empty">No filtered devices yet.</div>`;
    const r = h.reviews;
    $("#hl-reviews").innerHTML = r.reviewed ? `<div style="margin-bottom:10px">You reviewed <b>${r.reviewed}</b> alerts; <b>${r.fp}</b> were not real bypass attempts.
      Each review recalibrates the confidence of similar alerts.</div>
      <table><thead><tr><th>Alert type</th><th class="right">Reviewed</th><th class="right">Not a bypass</th></tr></thead><tbody>
      ${r.by_kind.map(k => `<tr><td>${esc(k.title)}</td><td class="right">${k.reviewed}</td><td class="right">${k.fp}</td></tr>`).join("")}</tbody></table>`
      : `<span class="muted">No reviews yet. Use <b>Confirmed</b> / <b>Not a bypass</b> on alerts to teach the confidence scores about your household.</span>`;
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
          ${x.suspect ? `<span class="badge bad" title="Its identity looks copied - filtered until you confirm">identity check</span>` : ""}
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
    <div class="panel"><div class="panel-head"><h2>Today's activity</h2><div class="tools"><a id="dv-live" class="btn">Watch live</a></div></div>
      <div class="panel-body"><div class="timeline" id="dv-timeline"></div><div class="timeline-axis" id="dv-axis"></div>
      <div class="legend-live" id="dv-tl-legend" style="margin-top:10px"></div></div></div>
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
        <button data-pause="${esc(x.device_id)}" data-min="0">Resume</button>
        ${x.suspect ? `<button class="primary" data-trust="${esc(x.device_id)}" title="Its hardware address was used by a device that identified itself differently. Click if that was you.">It's me</button>` : ""}`;
    }
    $("#dv-tiles").innerHTML = [
      [fmtMins(x.minutes_today), "Online today (approx.)"],
      [fmtBytes(x.bytes_down), "Downloaded today"],
      [fmtBytes(x.bytes_up), "Uploaded today"],
      [x.queries, "Lookups today"],
      [x.blocked, "Blocked today"],
      [x.paused ? "Paused" : x.filtered ? "Filtered" : "Unfiltered", x.paused ? x.paused_reason : "Group: " + x.group, x.paused ? "bad" : ""],
    ].map(([n, l, c]) => `<div class="tile ${c || ""}"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");
    $("#dv-live").href = `#live/${encodeURIComponent(id)}`;
    const t0 = d.midnight, t1 = Date.now() / 1000, span = Math.max(3600, t1 - t0);
    $("#dv-timeline").innerHTML = d.timeline.map(t => `<span title="${esc(t.headline)} (${clock(t.start).slice(0, 5)}–${clock(t.end).slice(0, 5)})"
      style="left:${(100 * (t.start - t0) / span).toFixed(2)}%;width:${(100 * (t.end - t.start) / span).toFixed(2)}%;background:var(--act-${esc(t.activity)})"></span>`).join("");
    $("#dv-axis").innerHTML = [0, 0.25, 0.5, 0.75, 1].map(f => `<span>${new Date((t0 + f * span) * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>`).join("");
    const used = [...new Set(d.timeline.map(t => t.activity))];
    $("#dv-tl-legend").innerHTML = used.length ? used.map(c => `<span><span class="sw" style="background:var(--act-${esc(c)})"></span>${esc(d.timeline.find(t => t.activity === c).label)}
      <b>${fmtMins(d.timeline.filter(t => t.activity === c).reduce((s, t) => s + (t.end - t.start) / 60, 0))}</b></span>`).join("") : `<span>No activity recorded today.</span>`;
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
  clearInterval(state.timer);
  state.timer = setInterval(() => { if (!document.hidden) refresh(); }, views[v].fast ? 2000 : 5000);
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
    const dl = await api("/api/downloads?limit=1");
    const dc = $("#dl-count"); dc.hidden = !dl.pending.length; dc.textContent = dl.pending.length;
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
  else if (b.dataset.review) act(async () => {
    const r = await post(`/api/alerts/${b.dataset.review}/review`, { verdict: b.dataset.verdict });
    toast(b.dataset.verdict === "tp" ? "Confirmed - similar alerts will score higher" : `Noted: ${r.note}`, 3500);
  });
  else if (b.dataset.dl) act(async () => {
    const r = await post(`/api/downloads/${b.dataset.dl}/${b.dataset.do}`);
    toast(r.note, 3500);
  });
  else if (b.dataset.trust) act(() => post(`/api/devices/${encodeURIComponent(b.dataset.trust)}/trust`), "Trusted again");
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
}
start();
