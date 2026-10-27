"use strict";

const KEY_STORE = "logbook-key";
const THEME_STORE = "logbook-theme";
const state = { data: null, byPath: new Map(), graphs: [] };
const GRAPH_MODE_STORE = "logbook-graph-mode";
const $ = (id) => document.getElementById(id);

// ---------- storage (can fail in private windows) ----------
const store = {
  get(k) {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set(k, v) {
    try {
      localStorage.setItem(k, v);
    } catch {}
  },
  del(k) {
    try {
      localStorage.removeItem(k);
    } catch {}
  },
};

// ---------- crypto ----------
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toB64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

async function fetchBundle() {
  const res = await fetch("data.json", { cache: "no-store" });
  if (!res.ok) throw new Error("Could not load the notebook (" + res.status + ")");
  return res.json();
}

async function deriveKey(password, bundle) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode(bundle.salt), iterations: bundle.iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"],
  );
}

async function decrypt(key, bundle) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(bundle.iv) }, key, fromB64(bundle.data));
  return JSON.parse(new TextDecoder().decode(plain));
}

const keyTag = (bundle) => bundle.salt + ":" + bundle.iterations;

async function tryStoredKey(bundle) {
  const saved = store.get(KEY_STORE);
  if (!saved) return null;
  try {
    const { tag, raw } = JSON.parse(saved);
    if (tag !== keyTag(bundle)) return null;
    const key = await crypto.subtle.importKey("raw", fromB64(raw), "AES-GCM", false, ["decrypt"]);
    return await decrypt(key, bundle);
  } catch {
    store.del(KEY_STORE);
    return null;
  }
}

// ---------- lock screen ----------
async function boot() {
  applyTheme(store.get(THEME_STORE));
  let bundle;
  try {
    bundle = await fetchBundle();
  } catch (error) {
    $("lock-error").textContent = error.message;
    return;
  }
  const data = await tryStoredKey(bundle);
  if (data) return open(data);

  $("lock-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $("unlock");
    button.disabled = true;
    button.textContent = "Unlocking…";
    $("lock-error").textContent = "";
    try {
      const key = await deriveKey($("password").value, bundle);
      const data = await decrypt(key, bundle);
      if ($("remember").checked) {
        const raw = await crypto.subtle.exportKey("raw", key);
        store.set(KEY_STORE, JSON.stringify({ tag: keyTag(bundle), raw: toB64(raw) }));
      }
      $("password").value = "";
      open(data);
    } catch {
      $("lock-error").textContent = "Wrong password.";
      $("password").select();
    } finally {
      button.disabled = false;
      button.textContent = "Unlock";
    }
  });
}

function open(data) {
  state.data = data;
  data.notes.forEach((n) => state.byPath.set(n.path, n));
  document.title = data.title;
  $("brand").textContent = data.title;
  $("lock").hidden = true;
  $("app").hidden = false;
  setupChrome();
  window.addEventListener("hashchange", route);
  route();
}

// ---------- helpers ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pad = (n) => String(n).padStart(2, "0");
const ymd = (d) => d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
const today = () => ymd(new Date());
const fmtDate = (s) => (s ? new Date(s + "T00:00:00").toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : "");
const fmtShort = (s) => (s ? new Date(s + "T00:00:00").toLocaleDateString("en-GB", { day: "numeric", month: "short" }) : "");
const allSections = () => [...state.data.subjects, ...(state.data.collections || [])];
const subjectName = (id) => allSections().find((s) => s.id === id)?.name || id || "Notes";
const noteHref = (path) => "#/n/" + encodeURI(path);
const pct = (p) => (p.total ? Math.round((100 * p.done) / p.total) : 0);

function resolveLink(target) {
  const t = target.trim().replace(/\.md$/, "").replace(/^content\//, "").toLowerCase();
  const notes = state.data.notes;
  return (
    notes.find((n) => n.path.toLowerCase() === t) ||
    notes.find((n) => n.path.toLowerCase().endsWith("/" + t)) ||
    notes.find((n) => n.title.toLowerCase() === t) ||
    null
  );
}

function resolveAsset(target, fromPath) {
  const assets = state.data.assets;
  const t = decodeURI(target.trim());
  if (assets[t]) return assets[t];
  const dir = fromPath.includes("/") ? fromPath.slice(0, fromPath.lastIndexOf("/") + 1) : "";
  if (assets[dir + t]) return assets[dir + t];
  const key = Object.keys(assets).find((k) => k.endsWith("/" + t) || k === t);
  return key ? assets[key] : null;
}

// ---------- markdown ----------
function renderMarkdown(body, fromPath) {
  const stash = [];
  const hold = (s) => "\u0000" + (stash.push(s) - 1) + "\u0000";
  // keep code untouched by the math and link handling
  let text = body.replace(/^(```|~~~)[^\n]*\n[\s\S]*?\n\1[ \t]*$/gm, hold).replace(/`[^`\n]+`/g, hold);

  const math = [];
  const mathToken = (tex, display) => "MATHTOKEN" + (math.push({ tex, display }) - 1) + "X";
  text = text.replace(/\$\$([\s\S]+?)\$\$/g, (_, tex) => "\n\n" + mathToken(tex, true) + "\n\n");
  text = text.replace(/(^|[^\\$])\$(?!\s)([^$\n]+?)(?<!\s)\$(?!\d)/g, (_, pre, tex) => pre + mathToken(tex, false));

  // Obsidian embeds and wikilinks
  text = text.replace(/!\[\[([^\]|]+)(?:\|([^\]]*))?\]\]/g, (_, target, alt) => {
    const src = resolveAsset(target, fromPath);
    return src ? `![${alt || target}](${src})` : `*(missing image: ${target})*`;
  });
  text = text.replace(/\[\[([^\]|#]+)(#[^\]|]*)?(?:\|([^\]]+))?\]\]/g, (_, target, _hash, alias) => {
    const note = resolveLink(target);
    const label = alias || (note ? note.title : target.split("/").pop());
    return note ? `[${label}](${noteHref(note.path)})` : `<span class="missing-link" title="No note called ${esc(target)} yet">${esc(label)}</span>`;
  });
  // relative image paths
  text = text.replace(/!\[([^\]]*)\]\((?!https?:|data:)([^)\s]+)\)/g, (m, alt, src) => {
    const data = resolveAsset(src, fromPath);
    return data ? `![${alt}](${data})` : m;
  });

  text = text.replace(/\u0000(\d+)\u0000/g, (_, i) => stash[+i]);
  let html = marked.parse(text, { gfm: true });
  html = html.replace(/MATHTOKEN(\d+)X/g, (_, i) => {
    const { tex, display } = math[+i];
    try {
      return katex.renderToString(tex, { displayMode: display, throwOnError: false });
    } catch {
      return esc(tex);
    }
  });
  return html;
}

function enhance(root) {
  // Obsidian callouts: > [!note] Title
  root.querySelectorAll("blockquote").forEach((bq) => {
    const first = bq.querySelector("p");
    const m = first && first.innerHTML.match(/^\[!(\w+)\][+-]?\s*([^\n<]*)/);
    if (!m) return;
    bq.classList.add("callout", "callout-" + m[1].toLowerCase());
    first.innerHTML = first.innerHTML.replace(m[0], `<strong class="callout-title">${m[2] || m[1]}</strong>`);
  });
  root.querySelectorAll("a[href^='http']").forEach((a) => {
    a.target = "_blank";
    a.rel = "noopener";
  });
  root.querySelectorAll("table").forEach((t) => {
    if (t.parentElement.classList.contains("table-wrap")) return;
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    t.replaceWith(wrap);
    wrap.appendChild(t);
  });
}

// ---------- chrome: sidebar, search, theme ----------
function setupChrome() {
  renderSidebar();
  $("menu-btn").onclick = () => document.body.classList.toggle("nav-open");
  $("view").addEventListener("click", () => document.body.classList.remove("nav-open"));
  $("theme-btn").onclick = () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    store.set(THEME_STORE, next);
    if (state.graphs.length) route(); // repaint graph colours
  };
  $("lock-btn").onclick = () => {
    store.del(KEY_STORE);
    location.hash = "";
    location.reload();
  };
  setupSearch();
  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => state.graphs.forEach((g) => g.__el && g.width(g.__el.clientWidth).height(g.__el.clientHeight)), 150);
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      $("search").focus();
    }
  });
}

function applyTheme(theme) {
  if (theme === "dark" || theme === "light") document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

function renderSidebar() {
  const { subjects, notes } = state.data;
  const logCount = notes.filter((n) => n.subject === "log").length;
  $("sidebar").innerHTML = `
    <a href="#/" data-route="">Dashboard</a>
    <a href="#/log" data-route="log">Log <span class="count">${logCount}</span></a>
    <a href="#/problems" data-route="problems">Problems <span class="count">${state.data.problems.length}</span></a>
    <a href="#/graph" data-route="graph">Graph</a>
    <div class="nav-label">Subjects</div>
    ${subjects
      .map(
        (s) => `<a href="#/s/${s.id}" data-route="s/${s.id}" class="nav-subject">
          <span>${esc(s.name)}</span>
          <span class="meter" role="img" aria-label="${pct(s.progress)}% of roadmap done"><span style="width:${pct(s.progress)}%"></span></span>
        </a>`,
      )
      .join("")}
    ${
      (state.data.collections || []).length
        ? `<div class="nav-label">Library</div>` +
          state.data.collections.map((c) => `<a href="#/s/${c.id}" data-route="s/${c.id}"><span>${esc(c.name)}</span><span class="count">${c.noteCount}</span></a>`).join("")
        : ""
    }
    ${notes.some((n) => !n.subject) ? `<div class="nav-label">Other</div>` + notes.filter((n) => !n.subject).map((n) => `<a href="${noteHref(n.path)}" data-route="n/${esc(n.path)}">${esc(n.title)}</a>`).join("") : ""}
  `;
}

function markActive(route) {
  document.querySelectorAll("#sidebar a").forEach((a) => {
    const r = a.dataset.route;
    a.classList.toggle("active", r === route || (r && route.startsWith(r + "/")) || (r.startsWith("s/") && route.startsWith("n/" + r.slice(2) + "/")) || (r === "log" && route.startsWith("n/log/")));
  });
}

function setupSearch() {
  const input = $("search");
  const box = $("search-results");
  let selected = 0;
  let results = [];
  const show = () => {
    const q = input.value.trim().toLowerCase();
    if (!q) {
      box.hidden = true;
      return;
    }
    const words = q.split(/\s+/);
    results = state.data.notes
      .map((n) => {
        const title = n.title.toLowerCase();
        const body = n.body.toLowerCase();
        if (!words.every((w) => title.includes(w) || body.includes(w) || n.tags.some((t) => t.toLowerCase().includes(w)))) return null;
        const score = words.reduce((s, w) => s + (title.includes(w) ? 10 : 0) + (body.split(w).length - 1), 0);
        const at = body.indexOf(words[0]);
        const snippet = at >= 0 ? n.body.slice(Math.max(0, at - 40), at + 80).replace(/\s+/g, " ") : "";
        return { n, score, snippet };
      })
      .filter(Boolean)
      .sort((a, b) => b.score - a.score)
      .slice(0, 12);
    selected = 0;
    box.innerHTML = results.length
      ? results
          .map(
            (r, i) => `<a href="${noteHref(r.n.path)}" class="${i === 0 ? "sel" : ""}">
              <span class="r-title">${esc(r.n.title)}</span><span class="r-sub">${esc(subjectName(r.n.subject))}</span>
              ${r.snippet ? `<span class="r-snip">…${esc(r.snippet)}…</span>` : ""}</a>`,
          )
          .join("")
      : `<div class="empty">No matches</div>`;
    box.hidden = false;
  };
  input.addEventListener("input", show);
  input.addEventListener("focus", show);
  input.addEventListener("keydown", (e) => {
    const links = box.querySelectorAll("a");
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!links.length) return;
      selected = (selected + (e.key === "ArrowDown" ? 1 : -1) + links.length) % links.length;
      links.forEach((a, i) => a.classList.toggle("sel", i === selected));
    } else if (e.key === "Enter" && links[selected]) {
      location.hash = links[selected].getAttribute("href");
      input.value = "";
      box.hidden = true;
      input.blur();
    } else if (e.key === "Escape") {
      box.hidden = true;
      input.blur();
    }
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".search")) box.hidden = true;
    else if (e.target.closest(".search-results a")) {
      input.value = "";
      box.hidden = true;
    }
  });
}

// ---------- tooltip ----------
function attachTooltips(root) {
  const tip = $("tooltip");
  const showTip = (el) => {
    tip.innerHTML = el.dataset.tip;
    tip.hidden = false;
    const r = el.getBoundingClientRect();
    const w = tip.offsetWidth;
    tip.style.left = Math.min(window.innerWidth - w - 8, Math.max(8, r.left + r.width / 2 - w / 2)) + "px";
    tip.style.top = r.top - tip.offsetHeight - 8 + window.scrollY + "px";
  };
  root.querySelectorAll("[data-tip]").forEach((el) => {
    el.addEventListener("mouseenter", () => showTip(el));
    el.addEventListener("focus", () => showTip(el));
    el.addEventListener("mouseleave", () => (tip.hidden = true));
    el.addEventListener("blur", () => (tip.hidden = true));
  });
}

// ---------- views ----------
function route() {
  const hash = decodeURI(location.hash.replace(/^#\/?/, ""));
  const view = $("view");
  $("tooltip").hidden = true;
  document.body.classList.remove("nav-open");
  destroyGraphs();
  document.body.classList.toggle("wide", hash === "graph");
  if (hash.startsWith("n/")) viewNote(hash.slice(2));
  else if (hash === "graph") viewGraph();
  else if (hash.startsWith("s/")) viewSubject(hash.slice(2));
  else if (hash === "log") viewLog();
  else if (hash.startsWith("problems")) viewProblems(hash.split("/")[1]);
  else viewDashboard();
  markActive(hash);
  enhance(view);
  attachTooltips(view);
  view.querySelectorAll(".heatmap").forEach((h) => (h.scrollLeft = h.scrollWidth)); // newest weeks first on small screens
  window.scrollTo(0, 0);
}

function streak(activity) {
  const d = new Date();
  if (!activity[ymd(d)]) d.setDate(d.getDate() - 1);
  let n = 0;
  while (activity[ymd(d)]) {
    n++;
    d.setDate(d.getDate() - 1);
  }
  return n;
}

function heatmap(activity, weeks = 26) {
  const end = new Date();
  const start = new Date(end);
  start.setDate(start.getDate() - ((start.getDay() + 6) % 7) - (weeks - 1) * 7); // a Monday
  const level = (c) => (c === 0 ? 0 : c === 1 ? 1 : c === 2 ? 2 : c <= 4 ? 3 : 4);
  let cells = "";
  let months = "";
  let lastMonth = -1;
  for (let w = 0; w < weeks; w++) {
    const monday = new Date(start);
    monday.setDate(start.getDate() + w * 7);
    if (monday.getMonth() !== lastMonth) {
      months += `<span style="grid-column:${w + 1}">${monday.toLocaleDateString(undefined, { month: "short" })}</span>`;
      lastMonth = monday.getMonth();
    }
    for (let dow = 0; dow < 7; dow++) {
      const d = new Date(monday);
      d.setDate(monday.getDate() + dow);
      if (d > end) {
        cells += `<span class="cell future" style="grid-column:${w + 1};grid-row:${dow + 1}"></span>`;
        continue;
      }
      const key = ymd(d);
      const c = activity[key] || 0;
      const label = `${c ? c + (c === 1 ? " entry" : " entries") : "Nothing logged"} · ${fmtDate(key)}`;
      cells += `<span class="cell l${level(c)}" style="grid-column:${w + 1};grid-row:${dow + 1}" tabindex="0" data-tip="${esc(label)}" aria-label="${esc(label)}"></span>`;
    }
  }
  return `<div class="heatmap" style="--weeks:${weeks}">
    <div class="hm-months">${months}</div>
    <div class="hm-days"><span>Mon</span><span></span><span>Wed</span><span></span><span>Fri</span><span></span><span></span></div>
    <div class="hm-grid">${cells}</div>
    <div class="hm-legend">Less <span class="cell l0"></span><span class="cell l1"></span><span class="cell l2"></span><span class="cell l3"></span><span class="cell l4"></span> More</div>
  </div>`;
}

function problemRows(list, showSubject) {
  if (!list.length) return `<p class="muted">Nothing here yet.</p>`;
  return `<div class="table-wrap"><table class="data">
    <thead><tr><th>Date</th><th>Problem</th>${showSubject ? "<th>Subject</th>" : ""}<th>Topic</th><th>Difficulty</th><th>Result</th><th>Revisit</th></tr></thead>
    <tbody>${list
      .map(
        (p) => `<tr>
        <td class="nowrap">${esc(fmtDate(p.date))}</td>
        <td>${p.url ? `<a href="${esc(p.url)}">${esc(p.name)}</a>` : esc(p.name)}</td>
        ${showSubject ? `<td>${esc(subjectName(p.subject))}</td>` : ""}
        <td>${esc(p.topic)}</td><td>${esc(p.difficulty)}</td><td>${esc(p.result)}</td>
        <td class="nowrap ${p.revisit && p.revisit <= today() ? "due" : ""}">${esc(fmtDate(p.revisit))}</td></tr>`,
      )
      .join("")}</tbody></table></div>`;
}

function viewDashboard() {
  const { subjects, notes, problems, activity } = state.data;
  const t = today();
  const weekAgo = new Date();
  weekAgo.setDate(weekAgo.getDate() - 6);
  const thisWeek = Object.entries(activity)
    .filter(([d]) => d >= ymd(weekAgo) && d <= t)
    .reduce((s, [, c]) => s + c, 0);
  const due = problems.filter((p) => p.revisit && p.revisit <= t).sort((a, b) => a.revisit.localeCompare(b.revisit));
  const logs = notes.filter((n) => n.subject === "log" && n.date).sort((a, b) => b.date.localeCompare(a.date)).slice(0, 5);
  const solved = (id) => problems.filter((p) => p.subject === id).length;
  const current = state.byPath.get("now");

  $("view").innerHTML = `
    <h1 class="page-title">Dashboard</h1>
    <div class="tiles">
      <div class="tile"><div class="tile-num">${streak(activity)}</div><div class="tile-label">day streak</div></div>
      <div class="tile"><div class="tile-num">${thisWeek}</div><div class="tile-label">entries in the last 7 days</div></div>
      <div class="tile"><div class="tile-num">${solved("dsa")}</div><div class="tile-label">DSA problems</div></div>
      <div class="tile"><div class="tile-num">${solved("sql")}</div><div class="tile-label">SQL problems</div></div>
    </div>

    <section class="panel">
      <h2>Activity</h2>
      ${heatmap(activity)}
    </section>

    ${current ? `<section class="panel"><h2><a href="${noteHref("now")}">Now</a></h2><div class="prose">${renderMarkdown(current.body.replace(/^#\s+.+\n/, ""), "now")}</div></section>` : ""}

    <section class="panel">
      <h2>Subjects</h2>
      <div class="subject-grid">
        ${subjects
          .map(
            (s) => `<a class="subject-card" href="#/s/${s.id}">
            <div class="sc-head"><span class="sc-name">${esc(s.name)}</span><span class="sc-pct">${pct(s.progress)}%</span></div>
            <div class="meter big" role="img" aria-label="${s.progress.done} of ${s.progress.total} roadmap items done"><span style="width:${pct(s.progress)}%"></span></div>
            <div class="sc-meta">${s.progress.done}/${s.progress.total} roadmap · ${s.noteCount} note${s.noteCount === 1 ? "" : "s"}${s.updated ? " · " + esc(fmtShort(s.updated)) : ""}</div>
          </a>`,
          )
          .join("")}
      </div>
    </section>

    <div class="two-col">
      <section class="panel">
        <h2>Due for revision <span class="count">${due.length}</span></h2>
        ${
          due.length
            ? `<ul class="plain">${due
                .slice(0, 8)
                .map((p) => `<li>${p.url ? `<a href="${esc(p.url)}">${esc(p.name)}</a>` : esc(p.name)} <span class="muted">· ${esc(subjectName(p.subject))} · since ${esc(fmtDate(p.revisit))}</span></li>`)
                .join("")}</ul>`
            : `<p class="muted">Nothing due. Add a revisit date to a problem to see it here.</p>`
        }
      </section>
      <section class="panel">
        <h2><a href="#/log">Recent log</a></h2>
        ${
          logs.length
            ? `<ul class="plain">${logs.map((n) => `<li><a href="${noteHref(n.path)}">${esc(fmtDate(n.date))}</a> <span class="muted">· ${esc(n.title === n.date ? firstLine(n.body) : n.title)}</span></li>`).join("")}</ul>`
            : `<p class="muted">No log entries yet.</p>`
        }
      </section>
    </div>`;
}

function firstLine(body) {
  const line = body.split("\n").find((l) => l.trim() && !l.startsWith("#"));
  return line ? line.replace(/^[-*]\s+(\[.\]\s+)?/, "").slice(0, 90) : "";
}

function noteList(list) {
  if (!list.length) return `<p class="muted">No notes yet.</p>`;
  return `<ul class="note-list">${list
    .map(
      (n) => `<li><a href="${noteHref(n.path)}">${esc(n.title)}</a>
      ${n.status ? `<span class="badge badge-${esc(String(n.status).toLowerCase())}">${esc(n.status)}</span>` : ""}
      <span class="muted">${esc(fmtDate(n.date || n.updated))}</span></li>`,
    )
    .join("")}</ul>`;
}

function viewSubject(id) {
  const s = state.data.subjects.find((x) => x.id === id);
  const collection = (state.data.collections || []).find((x) => x.id === id);
  if (collection) return viewCollection(collection);
  if (!s) return notFound();
  const index = state.byPath.get(id + "/index");
  const notes = state.data.notes.filter((n) => n.subject === id && n.path !== id + "/index" && n.tracker !== "problems");
  const trackers = state.data.notes.filter((n) => n.subject === id && n.tracker === "problems");
  const problems = state.data.problems.filter((p) => p.subject === id);
  $("view").innerHTML = `
    <div class="crumbs"><a href="#/">Dashboard</a> / ${esc(s.name)}</div>
    <div class="subject-head">
      <h1 class="page-title">${esc(s.name)}</h1>
      <div class="subject-progress"><div class="meter big"><span style="width:${pct(s.progress)}%"></span></div><span>${s.progress.done}/${s.progress.total} done</span></div>
    </div>
    ${trackers.length ? `<section class="panel"><h2>Problems <span class="count">${problems.length}</span></h2>${problemRows(problems.slice().sort((a, b) => (b.date || "").localeCompare(a.date || "")).slice(0, 10), false)}${trackers.map((t) => `<p><a href="${noteHref(t.path)}">Open ${esc(t.title)} →</a></p>`).join("")}</section>` : ""}
    <section class="panel"><h2>Notes <span class="count">${notes.length}</span></h2>${noteList(notes.sort((a, b) => a.title.localeCompare(b.title)))}</section>
    ${index ? `<section class="panel"><h2>Roadmap</h2><div class="prose">${renderMarkdown(index.body.replace(/^#\s+.+\n/, ""), index.path)}</div><p class="muted small"><a href="${noteHref(index.path)}">Open as a note</a></p></section>` : ""}
  `;
}

function viewCollection(c) {
  const index = state.byPath.get(c.id + "/index");
  const notes = state.data.notes.filter((n) => n.subject === c.id && n.path !== c.id + "/index");
  notes.sort((a, b) => (b.date || b.updated || "").localeCompare(a.date || a.updated || ""));
  $("view").innerHTML = `
    <div class="crumbs"><a href="#/">Dashboard</a> / ${esc(c.name)}</div>
    <h1 class="page-title">${esc(c.name)}</h1>
    ${index ? `<div class="prose intro">${renderMarkdown(index.body.replace(/^\s*#\s+.+\n?/, ""), index.path)}</div>` : ""}
    <section class="panel"><h2>${esc(c.name)} <span class="count">${notes.length}</span></h2>${noteList(notes)}</section>`;
}

function viewNote(path) {
  const n = state.byPath.get(path);
  if (!n) return notFound();
  const backlinks = state.data.notes.filter((o) => o !== n && o.links.includes(n.path));
  const body = n.body.replace(/^\s*#\s+.+\n?/, "");
  $("view").innerHTML = `
    <div class="crumbs"><a href="#/">Dashboard</a>${n.subject === "log" ? ` / <a href="#/log">Log</a>` : n.subject ? ` / <a href="#/s/${n.subject}">${esc(subjectName(n.subject))}</a>` : ""}</div>
    <article class="prose note">
      <h1>${esc(n.title)}</h1>
      <div class="note-meta">
        ${n.date ? `<span>${esc(fmtDate(n.date))}</span>` : ""}
        ${n.status ? `<span class="badge badge-${esc(String(n.status).toLowerCase())}">${esc(n.status)}</span>` : ""}
        ${n.ai ? `<span class="badge badge-ai" title="Drafted with AI help: ${esc(n.ai)}">AI draft</span>` : ""}
        ${n.tags.map((t) => `<span class="tag">#${esc(t)}</span>`).join("")}
      </div>
      ${renderMarkdown(body, n.path)}
    </article>
    <div class="note-foot">
      ${backlinks.length ? `<section class="panel backlinks"><h2>Linked from</h2>${noteList(backlinks)}</section>` : ""}
      ${
        n.links.length || backlinks.length
          ? `<section class="panel"><h2>Connections <a class="small" href="#/graph">full graph →</a></h2><div id="local-graph" class="graph-box local"></div></section>`
          : ""
      }
    </div>
  `;
  if ($("local-graph")) requestAnimationFrame(() => renderGraph($("local-graph"), "2d", { focus: n.path }));
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function viewLog() {
  const logs = state.data.notes.filter((n) => n.subject === "log").sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  $("view").innerHTML = `
    <div class="crumbs"><a href="#/">Dashboard</a> / Log</div>
    <h1 class="page-title">Log</h1>
    ${
      logs.length
        ? logs
            .map(
              (n) => `<article class="panel log-entry">
          <h2><a href="${noteHref(n.path)}">${esc(n.date ? fmtDate(n.date) : n.title)}</a></h2>
          <div class="prose">${renderMarkdown(n.body.replace(/^#\s+.+\n/, ""), n.path)}</div></article>`,
            )
            .join("")
        : `<p class="muted">No log entries yet. Add a file like <code>content/log/${today()}.md</code>.</p>`
    }`;
}

function viewProblems(subject) {
  const all = state.data.problems.slice().sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  const list = subject ? all.filter((p) => p.subject === subject) : all;
  const subjectsWith = [...new Set(all.map((p) => p.subject))];
  const byTopic = {};
  list.forEach((p) => p.topic && (byTopic[p.topic] = (byTopic[p.topic] || 0) + 1));
  const topics = Object.entries(byTopic).sort((a, b) => b[1] - a[1]);
  const max = topics.length ? topics[0][1] : 1;
  $("view").innerHTML = `
    <div class="crumbs"><a href="#/">Dashboard</a> / Problems</div>
    <h1 class="page-title">Problems</h1>
    <div class="filters">
      <a href="#/problems" class="chip ${subject ? "" : "on"}">All <span class="count">${all.length}</span></a>
      ${subjectsWith.map((s) => `<a href="#/problems/${s}" class="chip ${s === subject ? "on" : ""}">${esc(subjectName(s))} <span class="count">${all.filter((p) => p.subject === s).length}</span></a>`).join("")}
    </div>
    ${
      topics.length
        ? `<section class="panel"><h2>By topic</h2><div class="bars">${topics
            .map(
              ([t, c]) => `<div class="bar-row" tabindex="0" data-tip="${esc(t)}: ${c} problem${c === 1 ? "" : "s"}">
            <span class="bar-label">${esc(t)}</span><span class="bar-track"><span class="bar" style="width:${(100 * c) / max}%"></span></span><span class="bar-val">${c}</span></div>`,
            )
            .join("")}</div></section>`
        : ""
    }
    <section class="panel"><h2>All problems <span class="count">${list.length}</span></h2>${problemRows(list, !subject)}</section>`;
}

// ---------- graph ----------
const scripts = {};
function loadScript(src) {
  return (scripts[src] ||= new Promise((resolve, reject) => {
    const el = document.createElement("script");
    el.src = src;
    el.onload = resolve;
    el.onerror = () => reject(new Error("Could not load " + src));
    document.head.appendChild(el);
  }));
}
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const subjectColor = (id) => cssVar("--c-" + id) || cssVar("--muted");

function destroyGraphs() {
  state.graphs.forEach((g) => {
    try {
      g.pauseAnimation && g.pauseAnimation();
      g._destructor && g._destructor();
    } catch {}
  });
  state.graphs = [];
}

function graphData({ includeLog = false, focus = null } = {}) {
  let notes = state.data.notes.filter((n) => n.subject && (includeLog || n.subject !== "log" || n.path === focus));
  let ids = new Set(notes.map((n) => n.path));
  let links = [];
  notes.forEach((n) => {
    n.links.forEach((t) => ids.has(t) && links.push({ source: n.path, target: t, kind: "link" }));
    const hub = n.subject && n.subject !== "log" ? n.subject + "/index" : null;
    if (hub && hub !== n.path && ids.has(hub) && !n.links.includes(hub)) links.push({ source: n.path, target: hub, kind: "member" });
  });
  if (focus) {
    const keep = new Set([focus]);
    links.forEach((l) => {
      if (l.source === focus) keep.add(l.target);
      if (l.target === focus) keep.add(l.source);
    });
    notes = notes.filter((n) => keep.has(n.path));
    ids = keep;
    links = links.filter((l) => keep.has(l.source) && keep.has(l.target) && (l.source === focus || l.target === focus || l.kind === "link"));
  }
  const degree = {};
  links.forEach((l) => {
    degree[l.source] = (degree[l.source] || 0) + 1;
    degree[l.target] = (degree[l.target] || 0) + 1;
  });
  const nodes = notes.map((n) => {
    const hub = n.path.endsWith("/index");
    return {
      id: n.path,
      name: hub ? subjectName(n.subject) : n.title,
      subject: n.subject || "other",
      hub,
      focus: n.path === focus,
      val: hub ? 6 + (degree[n.path] || 0) * 0.5 : 1 + (degree[n.path] || 0),
    };
  });
  return { nodes, links };
}

async function renderGraph(el, mode, options = {}) {
  const data = graphData(options);
  const width = el.clientWidth;
  const height = el.clientHeight;
  const text = cssVar("--text");
  const muted = cssVar("--muted");
  const surface = cssVar("--surface");
  const linkStrong = cssVar("--graph-link");
  const linkFaint = cssVar("--graph-link-faint");
  const neighbours = new Map(data.nodes.map((n) => [n.id, new Set([n.id])]));
  data.links.forEach((l) => {
    neighbours.get(l.source)?.add(l.target);
    neighbours.get(l.target)?.add(l.source);
  });
  const open = (node) => node && (location.hash = noteHref(node.id));
  const label = (node) => `<div class="graph-tip"><b>${esc(node.name)}</b><span>${esc(subjectName(node.subject === "other" ? "" : node.subject))}</span></div>`;
  let graph;
  try {
    if (mode === "3d") {
      await loadScript("vendor/3d-force-graph.min.js");
      if (!el.isConnected) return;
      graph = ForceGraph3D({ controlType: "orbit" })(el)
        .width(width)
        .height(height)
        .backgroundColor(surface)
        .showNavInfo(false)
        .graphData(data)
        .nodeVal("val")
        .nodeRelSize(4)
        .nodeColor((n) => subjectColor(n.subject))
        .nodeOpacity(0.95)
        .nodeResolution(16)
        .nodeLabel(label)
        .linkColor((l) => (l.kind === "member" ? linkFaint : linkStrong))
        .linkOpacity(0.55)
        .linkWidth((l) => (l.kind === "member" ? 0 : 0.8))
        .onNodeClick(open)
        .onNodeHover((n) => (el.style.cursor = n ? "pointer" : ""))
        .cooldownTicks(150)
        .onEngineStop(() => graph.zoomToFit(600, 40));
      graph.d3Force("charge").strength(-60);
    } else {
      await loadScript("vendor/force-graph.min.js");
      if (!el.isConnected) return;
      let hover = null;
      graph = ForceGraph()(el)
        .width(width)
        .height(height)
        .backgroundColor("rgba(0,0,0,0)")
        .graphData(data)
        .nodeVal("val")
        .nodeRelSize(4)
        .nodeLabel(label)
        .linkColor((l) => {
          const lit = hover && (l.source.id === hover.id || l.target.id === hover.id);
          return lit ? text : l.kind === "member" ? linkFaint : linkStrong;
        })
        .linkWidth((l) => (l.kind === "member" ? 0.6 : 1.3))
        .nodeCanvasObject((node, ctx, scale) => {
          const r = Math.sqrt(node.val) * (options.focus ? 2.5 : 4);
          const dim = hover && !neighbours.get(hover.id).has(node.id);
          ctx.globalAlpha = dim ? 0.2 : 1;
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
          ctx.fillStyle = subjectColor(node.subject);
          ctx.fill();
          ctx.lineWidth = (node.focus ? 3 : 1.5) / scale;
          ctx.strokeStyle = node.focus ? text : surface;
          ctx.stroke();
          const showLabel = node.hub || node.focus || scale > 1.6 || (hover && neighbours.get(hover.id).has(node.id)) || options.focus;
          if (showLabel) {
            const size = (node.hub ? 13 : 11) / scale;
            ctx.font = `${node.hub ? 600 : 400} ${size}px Inter, system-ui, sans-serif`;
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            ctx.fillStyle = node.hub ? text : muted;
            ctx.fillText(node.name, node.x, node.y + r + 2 / scale);
          }
          ctx.globalAlpha = 1;
        })
        .nodePointerAreaPaint((node, color, ctx) => {
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(node.x, node.y, Math.sqrt(node.val) * 4 + 4, 0, 2 * Math.PI);
          ctx.fill();
        })
        .onNodeHover((n) => {
          hover = n;
          el.style.cursor = n ? "pointer" : "";
        })
        .onNodeClick(open)
        .cooldownTicks(120)
        .onEngineStop(() => graph.zoomToFit(400, options.focus ? 30 : 50));
      graph.d3Force("charge").strength(options.focus ? -180 : -90);
    }
  } catch (error) {
    el.innerHTML = `<p class="muted graph-error">${esc(error.message)}</p>`;
    return;
  }
  graph.__el = el;
  state.graphs.push(graph);
}

function viewGraph() {
  const mode = store.get(GRAPH_MODE_STORE) === "3d" ? "3d" : "2d";
  const includeLog = store.get("logbook-graph-log") === "1";
  const used = new Set(state.data.notes.map((n) => n.subject).filter((s) => s && s !== "log"));
  $("view").innerHTML = `
    <div class="graph-head">
      <h1 class="page-title">Graph</h1>
      <div class="graph-controls">
        <div class="seg" role="group" aria-label="Graph view">
          <button data-mode="2d" class="${mode === "2d" ? "on" : ""}">2D</button>
          <button data-mode="3d" class="${mode === "3d" ? "on" : ""}">3D</button>
        </div>
        <label class="check"><input type="checkbox" id="g-log" ${includeLog ? "checked" : ""}/> Include log</label>
      </div>
    </div>
    <div class="legend">${allSections()
      .filter((s) => used.has(s.id))
      .map((s) => `<span class="legend-item"><span class="swatch" style="background:var(--c-${s.id}, var(--c-other))"></span>${esc(s.name)}</span>`)
      .join("")}</div>
    <div id="graph" class="graph-box full"></div>
    <p class="muted small">Each dot is a note; bigger dots have more connections. Solid lines are links you wrote between notes, faint lines join a note to its subject. ${
      mode === "3d" ? "Drag to rotate, right-drag to pan, scroll to zoom." : "Drag to pan, scroll to zoom, hover to highlight neighbours."
    } Click a dot to open it.</p>`;
  document.querySelectorAll(".seg button").forEach((b) =>
    b.addEventListener("click", () => {
      store.set(GRAPH_MODE_STORE, b.dataset.mode);
      route();
    }),
  );
  $("g-log").addEventListener("change", (e) => {
    store.set("logbook-graph-log", e.target.checked ? "1" : "0");
    route();
  });
  requestAnimationFrame(() => renderGraph($("graph"), mode, { includeLog }));
}

function notFound() {
  $("view").innerHTML = `<h1 class="page-title">Not found</h1><p><a href="#/">Back to the dashboard</a></p>`;
}

boot();
