"use strict";
/* First-run setup wizard. Shown after the first sign-in (and from System -> Run setup again).
   Relies on helpers from app.js: $, $$, esc, api, post, toast, AuthError, ago. */

const WZ_STEPS = [
  ["welcome", "Welcome"], ["run", "How it runs"], ["level", "Level"], ["tune", "Fine-tune"],
  ["block", "What to block"], ["devices", "Devices"], ["bedtime", "Bedtime"], ["privacy", "Privacy"],
  ["review", "Review"],
];
const WZ_GROUPS = {
  adults: "No filtering. Activity is still shown if you choose to record it.",
  kids: "Full filtering and every anti-bypass check.",
  consoles: "Filtered, with the online-gaming traffic consoles need allowed.",
  quarantine: "New and unrecognised devices - filtered like a child's until you say otherwise.",
};
const WZ_DAYS = [["mon", "Mon"], ["tue", "Tue"], ["wed", "Wed"], ["thu", "Thu"], ["fri", "Fri"], ["sat", "Sat"], ["sun", "Sun"]];

// Each fine-tune setting: key, label, help, options [[value, label]] or "bool" / "minutes".
const WZ_FIELDS = [
  ["Adult content", [
    ["adult_mode", "Adult-content protection", "Strict also blocks site names with weaker adult terms (matched as whole words, so Essex and Sussex are safe) and holds video from unknown sites.",
      [["strict", "Strict"], ["standard", "Standard"], ["off", "Lists only"]]],
    ["safesearch", "Lock SafeSearch on", "Google, Bing, DuckDuckGo and Yandex always answer with their locked safe-search versions.", "bool"],
    ["youtube", "YouTube Restricted Mode", "Strict hides the most videos; Moderate hides fewer. Uses YouTube's own mechanism.",
      [["strict", "Strict"], ["moderate", "Moderate"], ["off", "Off"]]],
    ["family_dns", "Second opinion from family DNS", "Children's lookups are also checked against Cloudflare for Families, which knows millions of sites - including brand-new ones.", "bool"],
    ["unknown_video", "Video from unknown sites", "Video streaming from a site that isn't a known video service - typically adult or pirate streaming no list knows yet.",
      [["review", "Stop and hold for review"], ["block", "Block"], ["alert", "Allow and tell me"], ["off", "Ignore"]]],
  ]],
  ["Downloads", [
    ["downloads", "Downloads", "Suspicious = risky file types, unknown sites, file lockers. Holding cuts the download and waits for you on the Reviews page.",
      [["review_suspicious", "Hold suspicious ones for review"], ["review_all", "Hold every download"], ["block_suspicious", "Block suspicious ones"], ["off", "Don't check"]]],
  ]],
  ["Getting around the filter", [
    ["unknown_destinations", "Heavy traffic to unknown destinations", "A VPN on a brand-new server is still a lot of traffic to somewhere nobody else in the house uses. Known services and popular sites are never affected.",
      [["review", "Stop and hold for review"], ["alert", "Allow and tell me"], ["off", "Ignore"]]],
    ["escalation_pause", "Pause after repeated bypass attempts", "When several different bypass techniques are tried within 10 minutes (a VPN app working through its options), pause the device. 0 = only report it.", "minutes"],
    ["tamper_pause", "Pause after attacks on the network", "ARP spoofing, a rogue DHCP server, a cloned address. 0 = only report it.", "minutes"],
  ]],
];

const wz = { data: null, step: 0, values: {}, devices: {}, bedtime: null, preset: null, busy: false };

function wzPresetOf(values) {
  for (const [k, p] of Object.entries(wz.data.presets)) {
    const same = Object.entries(p.values).every(([key, v]) => key === "categories" ||
      JSON.stringify(v) === JSON.stringify(values[key]));
    if (same) return k;
  }
  return "custom";
}

async function openWizard(startAt = 0) {
  wz.data = await api("/api/wizard");
  wz.values = JSON.parse(JSON.stringify(wz.data.values));
  wz.preset = wzPresetOf(wz.values);
  wz.devices = {};
  for (const d of wz.data.devices) {
    let group = d.group_set ? d.group : "";
    if (!d.group_set && d.device_id === wz.data.this_device) group = "adults";   // the parent setting it up
    wz.devices[d.device_id] = { name: d.name || "", group };
  }
  wz.bedtime = JSON.parse(JSON.stringify(wz.data.bedtime));
  wz.step = startAt;
  clearInterval(state.timer);
  $("#wizard").hidden = false;
  document.body.classList.add("wz-open");
  wzRender();
}
function closeWizard() {
  $("#wizard").hidden = true;
  document.body.classList.remove("wz-open");
  render();
}

function wzRender() {
  const [key, title] = WZ_STEPS[wz.step];
  const n = WZ_STEPS.length;
  const dots = WZ_STEPS.map(([k, t], i) =>
    `<li class="${i === wz.step ? "on" : i < wz.step ? "done" : ""}"><button data-wz-go="${i}" ${i > wz.step ? "disabled" : ""} title="${esc(t)}"><span>${i + 1}</span><em>${esc(t)}</em></button></li>`).join("");
  $("#wizard").innerHTML = `
    <div class="wz" role="dialog" aria-modal="true" aria-labelledby="wz-title">
      <div class="wz-head">
        <div class="wz-brand"><span class="dot"></span>Parental Gateway setup</div>
        <ol class="wz-steps">${dots}</ol>
        <div class="wz-count small muted">Step ${wz.step + 1} of ${n} · ${esc(title)}</div>
      </div>
      <div class="wz-body" id="wz-body">${WZ_VIEWS[key]()}</div>
      <div class="wz-foot">
        ${wz.step === 0 ? `<button class="link" id="wz-skip">Skip - keep the current settings</button>` :
          `<button id="wz-back">Back</button>`}
        <span class="grow"></span>
        ${wz.step < n - 1 ? `<button class="primary" id="wz-next">${wz.step === 0 ? "Start setup" : "Next"}</button>` :
          `<button class="primary" id="wz-finish">Finish setup</button>`}
      </div>
    </div>`;
  const body = $("#wz-body");
  body.scrollTop = 0;
  $("#wz-title")?.focus?.();
  if (WZ_BIND[key]) WZ_BIND[key](body);
  $("#wz-next") && ($("#wz-next").onclick = () => { wz.step++; wzRender(); });
  $("#wz-back") && ($("#wz-back").onclick = () => { wz.step--; wzRender(); });
  $("#wz-finish") && ($("#wz-finish").onclick = wzFinish);
  $("#wz-skip") && ($("#wz-skip").onclick = async () => {
    try { await post("/api/wizard/skip"); toast("Setup skipped - you can run it again from System."); closeWizard(); }
    catch (e) { toast(e.message, 4000); }
  });
  $$("[data-wz-go]").forEach(b => b.onclick = () => { wz.step = Number(b.dataset.wzGo); wzRender(); });
}

function wzChoice(name, options, value, cls = "") {
  return `<div class="wz-choices ${cls}" role="radiogroup">${options.map(([v, label, desc, extra]) => `
    <label class="wz-choice ${String(v) === String(value) ? "on" : ""} ${extra && extra.disabled ? "disabled" : ""}">
      <input type="radio" name="${esc(name)}" value="${esc(v)}" ${String(v) === String(value) ? "checked" : ""} ${extra && extra.disabled ? "disabled" : ""}>
      <span class="t">${esc(label)}${extra && extra.badge ? ` <span class="badge ok">${esc(extra.badge)}</span>` : ""}</span>
      ${desc ? `<span class="d">${desc}</span>` : ""}
    </label>`).join("")}</div>`;
}
function wzToggle(id, on, label, help) {
  return `<label class="wz-toggle"><input type="checkbox" id="${esc(id)}" ${on ? "checked" : ""}>
    <span class="sw" aria-hidden="true"></span><span><span class="t">${esc(label)}</span>${help ? `<span class="d">${esc(help)}</span>` : ""}</span></label>`;
}
function wzBindChoices(body, name, fn) {
  $$(`input[name="${name}"]`, body).forEach(r => r.onchange = () => {
    $$(`input[name="${name}"]`, body).forEach(x => x.closest(".wz-choice").classList.toggle("on", x.checked));
    fn(r.value);
  });
}
const wzStatus = s => ({ ok: "✅", warn: "⚠️", bad: "⛔" }[s] || "•");
const wzIsLocal = () => ["127.0.0.1", "::1", "localhost", "testclient"].includes(wz.data.this_ip);

const WZ_VIEWS = {
  welcome: () => `
    <h1 id="wz-title" tabindex="-1">Welcome - let's set things up</h1>
    <p class="lead">A few questions, about five minutes. Every answer can be changed later, and each step explains what it does.</p>
    <div class="wz-list">
      <div><b>How it runs</b><span>Checks this ${wz.data.mode === "gateway" ? "Raspberry Pi" : "computer"} is ready and how the dashboard is reached.</span></div>
      <div><b>Protection level</b><span>Strict, Balanced or Light - then fine-tune anything.</span></div>
      <div><b>What to block</b><span>Adult content, gambling, torrents, the ways around the filter…</span></div>
      <div><b>Devices</b><span>Name the devices already seen and say whose they are.</span></div>
      <div><b>Bedtime &amp; privacy</b><span>An internet-off time for the children, and how long history is kept.</span></div>
    </div>
    <p class="muted small">${wz.data.complete ? "Setup was completed before - running it again shows your current settings." :
      "Until you finish, the gateway runs with the recommended (Strict) settings."}</p>`,

  run: () => {
    const env = wz.data.environment;
    const gw = env.mode === "gateway";
    const checks = env.checks.map(c => `<li class="wz-check ${c.status}"><span class="i">${wzStatus(c.status)}</span>
      <span><b>${esc(c.title)}</b><span class="d">${esc(c.detail)}</span></span></li>`).join("");
    const ifaces = env.interfaces.length ? `<div class="scroll"><table class="wz-table"><thead><tr><th>Interface</th><th>Type</th><th>Address</th><th>Role</th></tr></thead><tbody>
      ${env.interfaces.map(i => `<tr><td class="mono">${esc(i.name)}</td><td>${esc(i.kind)}${i.state && i.state !== "up" ? ` <span class="faint small">${esc(i.state)}</span>` : ""}</td>
        <td class="mono small">${esc((i.ipv4 || []).join(", ") || "—")}</td>
        <td>${i.name === env.configured.wan ? `<span class="badge info">internet</span>` : i.name === env.configured.lan ? `<span class="badge ok">home network</span>` : i.default_route ? `<span class="faint small">default route</span>` : ""}</td></tr>`).join("")}
      </tbody></table></div>` : "";
    const local = wzIsLocal();
    return `
      <h1 id="wz-title" tabindex="-1">How it runs</h1>
      <div class="wz-mode">
        <div class="wz-mode-icon">${gw ? "🛡️" : "🖥️"}</div>
        <div><b>${gw ? "Gateway mode" : "Monitor mode"}</b> <span class="muted">on ${esc(env.hostname)} · ${esc(env.platform)}${env.raspberry_pi ? " (Raspberry Pi)" : ""}</span>
          <p class="d">${gw ? "This machine is the router: every device's traffic passes through it, so filtering, the anti-bypass checks and blocking all happen in the network itself. Nothing on the children's devices can switch it off."
            : "This machine filters the devices that use it for DNS and watches the traffic it can see. It's ideal for trying things out and debugging - for real protection run it on the Raspberry Pi in gateway mode."}</p></div>
      </div>
      <h2>Checklist</h2>
      <ul class="wz-checks">${checks}</ul>
      ${gw ? `<h2>Network ports</h2>${ifaces}
        <p class="muted small">Which port faces the internet and which faces your home is chosen by <span class="mono">deploy/setup-pi.sh</span> - run it again to change them. It isn't offered here: one wrong choice would cut this dashboard off.</p>
        <div class="wz-note"><b>House checklist</b><ul>
          <li>Your ISP router's Wi-Fi is turned off (or its password changed and not shared), so nobody can join the network behind the gateway's back.</li>
          <li>Your Wi-Fi access point is in <i>access point / bridge</i> mode, plugged into the gateway's home-network port, with its own DHCP off.</li>
          <li>Children don't know the ISP router's admin password.</li></ul></div>`
      : `<h2>Which devices it filters</h2>
        ${wzChoice("dns_port", [
          [53, "Real devices (port 53)", "Point a device's DNS at this computer's address and it's filtered. Needs administrator rights."],
          [5353, "Testing only (port 5353)", "Nothing changes for the devices in the house - use <span class='mono'>nslookup -port=5353</span> or the e2e tests to try it out."],
        ].concat([53, 5353].includes(Number(wz.values.dns_port)) ? [] :
          [[wz.values.dns_port, `Keep port ${wz.values.dns_port}`, "Your current custom port - for testing."]]), wz.values.dns_port, "two")}
        <h2>Who can open this dashboard</h2>
        ${wzChoice("web_host", [
          ["127.0.0.1", "Only this computer", "The safest choice while the gateway runs on your own PC.", local ? null : { disabled: true }],
          ["0.0.0.0", "Any device on the network", "Open it from your phone too. It's still protected by your password."],
        ], wz.values.web_host, "two")}
        ${local ? "" : `<p class="muted small">You're using the dashboard from another device (${esc(wz.data.this_ip)}), so “Only this computer” would lock you out.</p>`}`}`;
  },

  level: () => {
    const opts = Object.entries(wz.data.presets).map(([k, p]) => [k, p.label, esc(p.summary), p.recommended ? { badge: "Recommended" } : null]);
    opts.push(["custom", "Custom", "Your own mix - set on the next step.", null]);
    return `<h1 id="wz-title" tabindex="-1">How strict should it be?</h1>
      <p class="lead">This sets everything on the next two steps in one go. Adults' devices are never filtered whatever you pick.</p>
      ${wzChoice("preset", opts, wz.preset, "stack")}`;
  },

  tune: () => `<h1 id="wz-title" tabindex="-1">Fine-tune</h1>
    <p class="lead">Starting from <b>${esc(wz.preset === "custom" ? "your own settings" : wz.data.presets[wz.preset].label)}</b>. Change anything; the explanations say what each does.</p>
    ${WZ_FIELDS.map(([section, fields]) => `<h2>${esc(section)}</h2><div class="wz-fields">${fields.map(([k, label, help, opts]) => {
      const v = wz.values[k];
      let ctl;
      if (opts === "bool") ctl = `<label class="wz-toggle inline"><input type="checkbox" data-wz-key="${k}" ${v ? "checked" : ""}><span class="sw" aria-hidden="true"></span></label>`;
      else if (opts === "minutes") ctl = `<select data-wz-key="${k}" data-num="1">${[[0, "Don't pause"], [15, "15 minutes"], [30, "30 minutes"], [60, "1 hour"], [120, "2 hours"]]
        .concat([[v, `${v} minutes`]].filter(([x]) => ![0, 15, 30, 60, 120].includes(Number(x))))
        .map(([x, l]) => `<option value="${x}" ${Number(x) === Number(v) ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
      else ctl = `<select data-wz-key="${k}">${opts.map(([x, l]) => `<option value="${esc(x)}" ${x === v ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
      return `<div class="wz-field"><div><b>${esc(label)}</b><span class="d">${esc(help)}</span></div><div class="ctl">${ctl}</div></div>`;
    }).join("")}</div>`).join("")}`,

  block: () => `<h1 id="wz-title" tabindex="-1">What to block for children</h1>
    <p class="lead">Applies to the kids, consoles and new-device groups. Adults are never filtered.</p>
    <div class="wz-cats">${wz.data.categories.map(c => {
      const on = wz.values.categories.includes(c.key), locked = c.key === "bypass";
      return `<label class="wz-cat ${on ? "on" : ""} ${locked ? "locked" : ""}"><input type="checkbox" data-cat="${esc(c.key)}" ${on || locked ? "checked" : ""} ${locked ? "disabled" : ""}>
        <span><b>${esc(c.label)}</b>${locked ? ` <span class="badge">always on</span>` : ""}<span class="d">${esc(c.description)}</span></span></label>`;
    }).join("")}</div>
    <p class="muted small">Blocking ways around the filter can't be turned off - without it every other choice could be undone with a free VPN app.</p>`,

  devices: () => {
    const devs = wz.data.devices;
    const opts = (cur) => `<option value="" ${!cur ? "selected" : ""}>Decide later (${esc(wz.values.default_group)})</option>` +
      wz.data.groups.map(g => `<option value="${esc(g.name)}" ${g.name === cur ? "selected" : ""}>${esc(g.name)}${g.filtered ? "" : " - not filtered"}</option>`).join("");
    const list = devs.length ? devs.map(d => {
      const st = wz.devices[d.device_id];
      const me = d.device_id === wz.data.this_device;
      return `<div class="wz-dev"><div class="who"><span class="st ${d.online ? "on" : ""}" title="${d.online ? "online" : "offline"}"></span>
          <div><div class="small muted mono">${esc(d.ip || "")} · ${esc(d.mac || d.device_id)}</div>
          <div class="small faint">${esc(d.hostname || "")}${me ? ` <span class="badge info">this device</span>` : ""} · seen ${esc(ago(d.last_seen))}</div></div></div>
        <input data-dev-name="${esc(d.device_id)}" value="${esc(st.name)}" placeholder="${esc(d.hostname || "Name, e.g. Sam's tablet")}" maxlength="60" aria-label="Name">
        <select data-dev-group="${esc(d.device_id)}" aria-label="Group">${opts(st.group)}</select></div>`;
    }).join("") : `<div class="empty">No devices seen yet. They'll appear as they connect - you can name them on the Devices page.</div>`;
    return `<h1 id="wz-title" tabindex="-1">Devices</h1>
      <p class="lead">Name the devices seen so far and say whose they are. ${wz.data.this_device && wz.devices[wz.data.this_device] ? "The device you're using now is marked - it's suggested as an adult's." : ""}</p>
      <div class="wz-groups">${wz.data.groups.map(g => `<div><b>${esc(g.name)}</b> <span class="muted small">${esc(WZ_GROUPS[g.name] || (g.filtered ? "Filtered." : "Not filtered."))}</span></div>`).join("")}</div>
      <div class="wz-devs">${list}</div>
      <h2>New devices</h2>
      ${wzChoice("default_group", [
        ["quarantine", "Treat as a child's until I decide", "Recommended. A new phone, or a child's device that changed its identity, is filtered straight away."],
        ["kids", "Put straight into kids", "Same filtering, without the “new device” label."],
      ].concat(["quarantine", "kids"].includes(wz.values.default_group) ? [] : [[wz.values.default_group, wz.values.default_group, "Your current setting."]]), wz.values.default_group, "two")}`;
  },

  bedtime: () => {
    const b = wz.bedtime;
    const groups = wz.data.groups.filter(g => g.filtered);
    const days = (b.days || "").split(",");
    return `<h1 id="wz-title" tabindex="-1">Bedtime</h1>
      <p class="lead">Turn the internet off for children's devices overnight. Adults are never included. You can add more schedules, or pause a single device, later.</p>
      ${wzToggle("bt-on", b.enabled, "Internet off at bedtime", "Applies to the groups below, every night it's set for.")}
      <div class="wz-bed ${b.enabled ? "" : "off"}">
        <div class="row"><label>From <input type="time" id="bt-start" value="${esc(b.start)}"></label>
          <label>until <input type="time" id="bt-end" value="${esc(b.end)}"></label>
          <span class="muted small">${b.start > b.end ? "the next morning" : ""}</span></div>
        <div class="wz-days">${WZ_DAYS.map(([k, l]) => `<label class="chip ${days.includes(k) ? "on" : ""}"><input type="checkbox" data-day="${k}" ${days.includes(k) ? "checked" : ""}>${l}</label>`).join("")}</div>
        <p class="muted small">Pick the nights it <b>starts</b> - Sunday to Thursday covers school nights.</p>
        <div class="wz-days">${groups.map(g => `<label class="chip ${(b.groups || []).includes(g.name) ? "on" : ""}"><input type="checkbox" data-bgroup="${esc(g.name)}" ${(b.groups || []).includes(g.name) ? "checked" : ""}>${esc(g.name)}</label>`).join("")}</div>
      </div>`;
  },

  privacy: () => {
    const gw = wz.data.mode === "gateway";
    return `<h1 id="wz-title" tabindex="-1">Privacy &amp; safety</h1>
      <h2>How long to keep history</h2>
      ${wzChoice("retention_days", [[7, "1 week", ""], [14, "2 weeks", ""], [30, "30 days", "Recommended"], [90, "90 days", ""]], wz.values.retention_days, "four")}
      <p class="muted small">Sites visited, time online and alerts. Everything stays on this ${gw ? "Pi" : "computer"} - nothing is sent anywhere.</p>
      <h2>Adults' devices</h2>
      ${wzToggle("log-trusted", wz.values.log_trusted, "Record adults' activity too", "Off: adults' devices are not filtered and their connections aren't recorded. Their DNS lookups are still used, anonymously, to learn which sites are normal in your house.")}
      ${gw ? `<h2>If the inspector stops</h2>
      ${wzChoice("fail_open", [
        [false, "Block children's new connections until it's back", "Recommended. A crash, or someone trying to crash it, can't be used as a way around the filter."],
        [true, "Let traffic through unchecked", "Nobody loses internet while it restarts - but neither is anything checked."],
      ], wz.values.fail_open, "two")}` : ""}`;
  },

  review: () => {
    const v = wz.values, d = wz.data;
    const lab = (k, x) => { for (const [, fields] of WZ_FIELDS) for (const f of fields) if (f[0] === k && Array.isArray(f[3])) return (f[3].find(o => o[0] === x) || [, x])[1]; return x; };
    const yes = b => b ? "on" : "off";
    const catLabels = d.categories.filter(c => v.categories.includes(c.key) || c.key === "bypass").map(c => c.label);
    const named = Object.entries(wz.devices).filter(([id, s]) => s.name || s.group);
    const restart = wzRestartKeys();
    const rows = [
      [1, "How it runs", d.mode === "gateway" ? "Gateway mode" : `Monitor mode · DNS port ${v.dns_port} · dashboard ${v.web_host === "0.0.0.0" ? "open to the network" : "this computer only"}`],
      [2, "Level", wz.preset === "custom" ? "Custom" : d.presets[wz.preset].label],
      [3, "Adult content", `${lab("adult_mode", v.adult_mode)} · SafeSearch ${yes(v.safesearch)} · YouTube ${lab("youtube", v.youtube)} · family DNS ${yes(v.family_dns)} · unknown video: ${lab("unknown_video", v.unknown_video).toLowerCase()}`],
      [3, "Downloads", lab("downloads", v.downloads)],
      [3, "Bypass", `unknown destinations: ${lab("unknown_destinations", v.unknown_destinations).toLowerCase()} · pause after attempts: ${v.escalation_pause ? v.escalation_pause + " min" : "no"} · after attacks: ${v.tamper_pause ? v.tamper_pause + " min" : "no"}`],
      [4, "Blocked", catLabels.join(", ")],
      [5, "Devices", `${named.length} named or assigned · new devices go to ${v.default_group}`],
      [6, "Bedtime", wz.bedtime.enabled ? `${wz.bedtime.start}-${wz.bedtime.end}, ${(wz.bedtime.days || "").split(",").filter(Boolean).length} nights a week, for ${(wz.bedtime.groups || []).join(", ") || "nobody"}` : "off"],
      [7, "Privacy", `keep ${v.retention_days} days · adults recorded: ${v.log_trusted ? "yes" : "no"}${d.mode === "gateway" ? ` · if the inspector stops: ${v.fail_open ? "let traffic through" : "block"}` : ""}`],
    ];
    return `<h1 id="wz-title" tabindex="-1">Ready to go</h1>
      <p class="lead">Here's what will be set. Most of it applies the moment you press Finish.</p>
      <dl class="wz-review">${rows.map(([step, k, val]) => `<dt>${esc(k)}</dt><dd><span>${esc(val)}</span><button class="link small" data-wz-go="${step}">Change</button></dd>`).join("")}</dl>
      ${restart.length ? `<div class="wz-note warn"><b>A restart is needed</b> for ${esc(restart.map(k => ({ dns_port: "the DNS port", web_host: "dashboard access", fail_open: "the inspector setting" }[k])).join(" and "))}. The service restarts itself after you press Finish and this page reconnects - it takes a few seconds.</div>` : ""}
      <p class="muted small">Settings are saved to <span class="mono">config.local.yaml</span> next to <span class="mono">config.yaml</span>.</p>`;
  },
};

function wzRestartKeys() {
  const o = wz.data.values, v = wz.values, out = [];
  for (const k of ["dns_port", "web_host", "fail_open"]) {
    if (wz.data.mode === "gateway" && k !== "fail_open") continue;
    if (String(o[k]) !== String(v[k])) out.push(k);
  }
  return out;
}

const WZ_BIND = {
  run(body) {
    wzBindChoices(body, "dns_port", v => { wz.values.dns_port = Number(v); });
    wzBindChoices(body, "web_host", v => { wz.values.web_host = v; });
  },
  level(body) {
    wzBindChoices(body, "preset", v => {
      wz.preset = v;
      if (v !== "custom") {
        const p = wz.data.presets[v].values;
        Object.assign(wz.values, JSON.parse(JSON.stringify(p)));
      }
    });
  },
  tune(body) {
    $$("[data-wz-key]", body).forEach(el => el.onchange = () => {
      const k = el.dataset.wzKey;
      wz.values[k] = el.type === "checkbox" ? el.checked : el.dataset.num ? Number(el.value) : el.value;
      wz.preset = wzPresetOf(wz.values);
    });
  },
  block(body) {
    $$("[data-cat]", body).forEach(el => el.onchange = () => {
      const k = el.dataset.cat;
      const set = new Set(wz.values.categories);
      el.checked ? set.add(k) : set.delete(k);
      wz.values.categories = [...set];
      el.closest(".wz-cat").classList.toggle("on", el.checked);
    });
  },
  devices(body) {
    $$("[data-dev-name]", body).forEach(el => el.oninput = () => { wz.devices[el.dataset.devName].name = el.value; });
    $$("[data-dev-group]", body).forEach(el => el.onchange = () => { wz.devices[el.dataset.devGroup].group = el.value; });
    wzBindChoices(body, "default_group", v => { wz.values.default_group = v; });
  },
  bedtime(body) {
    const b = wz.bedtime;
    $("#bt-on", body).onchange = e => { b.enabled = e.target.checked; $(".wz-bed", body).classList.toggle("off", !b.enabled); };
    $("#bt-start", body).onchange = e => { b.start = e.target.value; };
    $("#bt-end", body).onchange = e => { b.end = e.target.value; };
    $$("[data-day]", body).forEach(el => el.onchange = () => {
      b.days = $$("[data-day]", body).filter(x => x.checked).map(x => x.dataset.day).join(",");
      el.closest(".chip").classList.toggle("on", el.checked);
    });
    $$("[data-bgroup]", body).forEach(el => el.onchange = () => {
      b.groups = $$("[data-bgroup]", body).filter(x => x.checked).map(x => x.dataset.bgroup);
      el.closest(".chip").classList.toggle("on", el.checked);
    });
  },
  privacy(body) {
    wzBindChoices(body, "retention_days", v => { wz.values.retention_days = Number(v); });
    $("#log-trusted", body).onchange = e => { wz.values.log_trusted = e.target.checked; };
    wzBindChoices(body, "fail_open", v => { wz.values.fail_open = v === "true"; });
  },
};

async function wzFinish() {
  if (wz.busy) return;
  wz.busy = true;
  const btn = $("#wz-finish");
  btn.disabled = true; btn.textContent = "Saving…";
  const values = { ...wz.values };
  if (wz.data.mode === "gateway") { delete values.dns_port; delete values.web_host; }
  else delete values.fail_open;
  const devices = Object.entries(wz.devices).map(([device_id, s]) => ({ device_id, name: s.name, group: s.group || null }));
  try {
    const r = await post("/api/wizard/apply", { values, devices, bedtime: wz.bedtime, finish: true });
    if (r.restart_required && r.restart_required.length) {
      await post("/api/system/restart");
      wzDone(true);
      await wzWaitForRestart();
    }
    wzDone(false);
  } catch (e) {
    if (!(e instanceof AuthError)) toast(e.message, 5000);
    btn.disabled = false; btn.textContent = "Finish setup";
  } finally { wz.busy = false; }
}

async function wzWaitForRestart() {
  await new Promise(r => setTimeout(r, 2500));
  for (let i = 0; i < 40; i++) {
    try { const s = await fetch("/api/session", { cache: "no-store" }); if (s.ok) return; } catch (_) { /* still restarting */ }
    await new Promise(r => setTimeout(r, 1000));
  }
}

function wzDone(restarting) {
  const gw = wz.data.mode === "gateway";
  $("#wizard").innerHTML = `<div class="wz done"><div class="wz-body wz-done">
    ${restarting ? `<div class="spinner" aria-hidden="true"></div><h1>Restarting…</h1><p class="lead">Applying the new settings. This page reconnects by itself.</p>` : `
    <div class="wz-big">✓</div><h1>You're all set</h1>
    <p class="lead">Protection is running with your settings.</p>
    <div class="wz-list">
      ${!gw && wz.values.dns_port === 53 ? `<div><b>Point devices at this computer</b><span>Set a device's DNS server to this computer's address (or set it in your router's DHCP settings) to filter it.</span></div>` : ""}
      <div><b>Watch it live</b><span>The <a href="#live" data-wz-close>Live</a> page shows what each device is doing right now.</span></div>
      <div><b>Name devices as they appear</b><span>New devices are ${esc(wz.values.default_group === "quarantine" ? "filtered as a child's" : "put into " + wz.values.default_group)} until you say otherwise - see <a href="#devices" data-wz-close>Devices</a>.</span></div>
      <div><b>Read the Guide</b><span>How every protection works, and what children try - <a href="#guide" data-wz-close>Guide</a>.</span></div>
    </div>
    <div class="wz-foot"><span class="grow"></span><button class="primary" id="wz-close">Go to the dashboard</button></div>`}
  </div></div>`;
  if (!restarting) {
    $("#wz-close").onclick = () => { location.hash = "#overview"; closeWizard(); };
    $$("[data-wz-close]").forEach(a => a.addEventListener("click", () => setTimeout(closeWizard, 0)));
  }
}
