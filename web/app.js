// Entry point: start-up, language, live events, rendering and the wiring of
// controls that are not owned by a single module.
import { t, lang, effectiveLang, cachedLang, loadCatalog, translateDOM } from "./i18n.js";
import { $, S, settings, apiJSON, normalizeView, refreshState, saveSettings, banner, removeBanner, isRunning, speedActive } from "./core.js";
import { renderHeader, renderControls, renderEnv, renderLangSelect, applyTheme, updateStartButton } from "./header.js";
import { renderSummary, renderStatus, renderCards, renderDetails, renderVerdicts, startRun, stopRun, saveReport } from "./run.js";
import { renderSpeed, renderSpeedHistory, startSpeed } from "./speed.js";
import { renderIPStrip } from "./ipstrip.js";
import { renderHistory, compareRuns } from "./history.js";
import { renderDrawer, openDrawer, closeDrawer, quitApp, wireDrawer } from "./drawer.js";

export function renderAll() {
  renderHeader(); renderEnv(); renderControls(); renderSummary(); renderSpeed(); renderIPStrip(); renderSpeedHistory();
  renderStatus(); renderVerdicts(); renderCards(); renderDetails(); renderHistory();
  if (!$("drawer").hidden) renderDrawer();
}
function scheduleRender() {
  if (S.renderQueued) return;
  S.renderQueued = true;
  requestAnimationFrame(() => {
    S.renderQueued = false;
    renderSummary(); renderSpeed(); renderIPStrip(); renderStatus(); renderVerdicts(); renderCards(); renderDetails(); renderHeader();
  });
}
async function fetchCurrent() {
  const cur = normalizeView(await apiJSON("/api/run/current"));
  if (!S.viewingHistory) { S.view = cur; scheduleRender(); }
  return cur;
}

// ---------- language ----------
// Switches the interface language: catalog, static text, every rendered part,
// and the server texts (verdicts, errors), which are re-read in the new language.
async function useLanguage(code) {
  await loadCatalog(code);
  translateDOM(document.body);
  renderLangSelect();
  if (!S.state) return;
  applyTheme();
  try {
    await refreshState();
    if (S.viewingHistory && S.view && S.view.run) S.view = normalizeView(await apiJSON("/api/history/" + encodeURIComponent(S.view.run.id)));
  } catch {}
  renderAll();
}
async function changeLanguage(value) {
  settings().language = value;
  await saveSettings(true);
  await useLanguage(effectiveLang(value, S.state && S.state.app && S.state.app.systemLang));
}

// ---------- start-up ----------
async function init() {
  // Until the settings arrive, use the language of the previous session or of the browser.
  const catalog = loadCatalog(cachedLang() || effectiveLang(""));
  try {
    const sess = await apiJSON("/api/session");
    S.csrf = sess.csrf;
    await refreshState();
    await catalog;
    const want = effectiveLang(settings().language, S.state.app && S.state.app.systemLang);
    if (want !== lang()) { await loadCatalog(want); await refreshState(); }
    translateDOM(document.body);
    renderLangSelect();
    applyTheme();
    renderAll();
    openSSE();
    // Results age while the page is open: once a minute refresh the ages and the
    // faded look of results older than 30 minutes (nothing moves, no requests).
    setInterval(() => {
      if (S.quitting || isRunning()) return;
      renderSummary(); renderStatus(); renderCards(); renderIPStrip();
      if (!speedActive()) renderSpeed();
    }, 60000);
    if (S.state.current.run) { S.view = S.state.current; renderAll(); }
    else if (S.state.history.length) {
      // Show the latest saved run offline; no network activity is triggered.
      try { S.view = normalizeView(await apiJSON("/api/history/" + encodeURIComponent(S.state.history[0].id))); S.viewingHistory = true; renderAll(); } catch {}
    }
  } catch (e) {
    await catalog;
    translateDOM(document.body);
    renderLangSelect();
    if (e.message !== "session_required") banner("err", t("Не удалось загрузить состояние: %s", e.message), "init");
  }
}

// ---------- live events ----------
// EventSource cannot send headers; the server keeps the language of the last
// API request, which every action of this page sends.
function openSSE() {
  const es = new EventSource("/api/events");
  S.sse = es;
  es.onopen = () => removeBanner("sse");
  es.onerror = () => { if (!S.quitting) banner("warn", t("Связь с приложением потеряна. Переподключение…"), "sse"); };
  es.addEventListener("run.started", () => { S.viewingHistory = false; fetchCurrent().catch(() => {}); refreshState().then(renderAll).catch(() => {}); });
  es.addEventListener("probe.started", (e) => {
    if (S.viewingHistory || !S.view) return;
    const p = JSON.parse(e.data); S.view.progress = p.progress; scheduleRender();
  });
  es.addEventListener("probe.finished", (e) => {
    if (S.viewingHistory || !S.view || !S.view.run) return;
    const p = JSON.parse(e.data);
    if (p.progress && p.progress.runId !== S.view.run.id) return;
    normalizeView(S.view);
    if (!S.view.run.results.some(r => r.endpointId === p.result.endpointId && r.attempt === p.result.attempt)) S.view.run.results.push(p.result);
    S.view.progress = p.progress;
    const i = S.view.groups.findIndex(g => g.groupId === p.group.groupId);
    if (i >= 0) S.view.groups[i] = p.group; else S.view.groups.push(p.group);
    scheduleRender();
  });
  es.addEventListener("externalip", (e) => {
    if (S.viewingHistory || !S.view || !S.view.run) return;
    S.view.run.externalIp = JSON.parse(e.data).externalIp; scheduleRender();
  });
  es.addEventListener("speed.started", (e) => { S.speedView = null; S.state.speed.current = JSON.parse(e.data).progress; renderHeader(); scheduleRender(); });
  es.addEventListener("speed.progress", (e) => { if (!S.state.speed) return; S.state.speed.current = JSON.parse(e.data).progress; scheduleRender(); });
  es.addEventListener("speed.finished", async () => { try { await refreshState(); renderAll(); } catch {} });
  es.addEventListener("run.finished", async () => {
    try { await refreshState(); if (!S.viewingHistory) S.view = S.state.current; renderAll(); } catch {}
  });
}

// ---------- folds: remember open/closed per viewer ----------
for (const d of document.querySelectorAll("details.fold[data-fold]")) {
  const key = "vpncheck.fold." + d.dataset.fold;
  try { const v = localStorage.getItem(key); if (v !== null) d.open = v === "1"; } catch {}
  d.addEventListener("toggle", () => { try { localStorage.setItem(key, d.open ? "1" : "0"); } catch {} });
}

// ---------- wiring ----------
$("btnStart").addEventListener("click", startRun);
$("btnReport").addEventListener("click", saveReport);
$("btnStop").addEventListener("click", stopRun);
$("btnSpeed").addEventListener("click", startSpeed);
$("btnQuit").addEventListener("click", quitApp);
$("btnSettings").addEventListener("click", () => ($("drawer").hidden ? openDrawer() : closeDrawer()));
$("routeBadge").addEventListener("click", () => { openDrawer(); });
$("btnTheme").addEventListener("click", () => { settings().theme = settings().theme === "light" ? "dark" : "light"; applyTheme(); saveSettings(); });
$("langSelect").addEventListener("change", (e) => { changeLanguage(e.target.value); });
$("btnCompare").addEventListener("click", compareRuns);
$("profileName").addEventListener("input", (e) => { settings().profileName = e.target.value; saveSettings(); });
$("search").addEventListener("input", (e) => { S.search = e.target.value; renderCards(); renderDetails(); });
$("modeSwitch").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-mode]"); if (!b) return;
  settings().mode = b.dataset.mode; saveSettings(); renderControls(); updateStartButton();
});
$("filterSwitch").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-filter]"); if (!b) return;
  S.filter = b.dataset.filter; renderControls(); renderCards(); renderDetails();
});
wireDrawer();
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (!$("drawer").hidden) { closeDrawer(); return; }
    if (S.expanded) { S.expanded = null; renderCards(); renderDetails(); }
  }
});
try { const th = localStorage.getItem("vpncheck.theme"); if (th === "light" || th === "dark") document.documentElement.dataset.theme = th; } catch {}

init();
