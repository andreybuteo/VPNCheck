// Shared core: page state, DOM helpers, API access, banners and toasts,
// formatting and the names of levels, statuses and stages.
import { t, lang, numLocale, LANG_HEADER, effectiveLang } from "./i18n.js";
import { renderHeader } from "./header.js";

// ---------- DOM helpers ----------
export const $ = (id) => document.getElementById(id);

export const el = (tag, attrs, ...children) => {
  const n = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k === "html") n.innerHTML = v; // only for trusted static markup (flags)
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(n.dataset, v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return n;
};

// Figures, times and addresses keep left-to-right order inside RTL text.
export const ltr = (...children) => el("bdi", { dir: "ltr" }, ...children);

export const icon = (name, cls) => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("class", "icon" + (cls ? " " + cls : ""));
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS("http://www.w3.org/2000/svg", "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
};

// ---------- state ----------
export const S = {
  csrf: null, state: null, view: null, viewingHistory: false,
  filter: "all", search: "", expanded: null, compareSel: [], sensitiveExport: false,
  quitting: false, sse: null, saveTimer: null, countdown: null, speedCountdown: null, renderQueued: false,
  flyer: null, envOpen: false, diagOpenedFor: null,
  speedView: null, // id of a past speed result shown in the speed tiles, or null for the latest
};
export const settings = () => S.state.settings;
export const registry = () => S.state.registry.endpoints;
export const isRunning = () => !!(S.state && S.state.current.progress && S.state.current.progress.status === "running");
export const speedActive = () => !!(S.state && S.state.speed && S.state.speed.current);

// ---------- API ----------
// Every request carries the interface language, so the server writes
// verdicts, errors and exports in it.
export async function api(path, opts = {}) {
  if (S.quitting) throw new Error(t("Приложение завершено"));
  const headers = Object.assign({}, opts.headers || {});
  headers[LANG_HEADER] = lang();
  if (opts.method && opts.method !== "GET" && S.csrf) headers["X-VPNCheck-CSRF"] = S.csrf;
  if (opts.body && typeof opts.body !== "string") { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.body); }
  const r = await fetch(path, Object.assign({}, opts, { headers, credentials: "same-origin" }));
  if (r.status === 401) { sessionLost(); throw new Error("session_required"); }
  return r;
}
export async function apiJSON(path, opts) {
  const r = await api(path, opts);
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!r.ok) {
    const e = new Error((data && data.message) || t("Ошибка %d", r.status));
    e.code = data && data.error; e.until = data && data.until; e.status = r.status;
    throw e;
  }
  return data;
}

export function normalizeView(v) {
  if (v && v.run) { v.run.results = v.run.results || []; v.run.endpoints = v.run.endpoints || []; }
  if (v) v.groups = v.groups || [];
  return v;
}
// Groups of the "home country direct" checks (split routing).
export const SPLIT_GROUPS = ["ru-direct", "cn-direct", "ir-direct"];
// The user's home-country group: by the Windows region first (ru-RU, zh-CN, fa-IR), then by language.
function homeGroup(s) {
  const app = (S.state && S.state.app) || {};
  let region;
  try { region = new Intl.Locale(app.systemLocale.replaceAll("_", "-")).region; } catch {}
  const byRegion = { RU: "ru-direct", CN: "cn-direct", IR: "ir-direct" }[region];
  if (byRegion) return byRegion;
  return { ru: "ru-direct", fa: "ir-direct" }[effectiveLang(s.language, app.systemLang)] || "";
}
let refreshSequence = 0;
let unsavedRevision = 0;
export async function refreshState() {
  const sequence = ++refreshSequence;
  const revision = settingsRevision;
  const hadUnsaved = unsavedRevision !== 0;
  const next = await apiJSON("/api/state");
  if (sequence !== refreshSequence) return;
  if (S.state && (hadUnsaved || unsavedRevision || revision !== settingsRevision)) next.settings = settings();
  S.state = next;
  normalizeView(S.state.current);
  const s = settings();
  // An empty or missing list means "defaults" (settings saved before 4.4 store [] for "all").
  if (!s.selectedEndpoints || s.selectedEndpoints.length === 0) {
    // "Home country direct" checks: only the user's own country is selected by default.
    const home = homeGroup(s);
    s.selectedEndpoints = registry().filter(e => e.enabled && (!SPLIT_GROUPS.includes(e.groupId) || e.groupId === home)).map(e => e.id);
  }
  if (!S.viewingHistory) S.view = S.state.current.run ? S.state.current : S.view;
}
let saveQueue = Promise.resolve();
let settingsRevision = 0;
export function saveSettings(immediate) {
  clearTimeout(S.saveTimer);
  const revision = ++settingsRevision;
  unsavedRevision = revision;
  const s = settings();
  const body = JSON.stringify(s);
  const persist = async () => {
    try {
      const saved = await apiJSON("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body });
      if (revision === settingsRevision && settings() === s) Object.assign(s, saved);
    }
    catch (e) { if (e.message !== "session_required") toast(t("Настройки не сохранены: %s", e.message), true); }
    if (unsavedRevision === revision) unsavedRevision = 0;
    renderHeader();
  };
  const enqueue = () => {
    saveQueue = saveQueue.then(persist, persist);
    return saveQueue;
  };
  if (immediate) return enqueue();
  S.saveTimer = setTimeout(enqueue, 350);
}

// ---------- toast and banners ----------
// ---------- balloon: an in-page confirmation anchored to a button ----------
// Replaces the browser's confirm(): the page's own look, Enter = OK, Esc or a
// click outside = cancel, focus returns to the button. Positioned over the page
// in viewport pixels, so nothing underneath moves.
let dismissBalloon;
export function balloon(anchor, o) {
  return new Promise((resolve) => {
    dismissBalloon?.();
    const cb = o.check ? el("input", { type: "checkbox" }) : null;
    const okBtn = el("button", { type: "button", class: "btn btn-small " + (o.danger ? "btn-danger" : "btn-primary") }, o.ok || "OK");
    const altBtn = o.alt ? el("button", { type: "button", class: "btn btn-small" }, o.alt) : null;
    const cancelBtn = el("button", { type: "button", class: "btn btn-small" }, o.cancel || t("Отмена"));
    const box = el("div", { class: "balloon", role: "dialog", "aria-modal": "false", "aria-label": o.title },
      el("div", { class: "b-arrow" }),
      el("div", { class: "b-title", text: o.title }),
      o.rows ? el("dl", { class: "b-rows" }, ...o.rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })])) : null,
      o.note ? el("div", { class: "b-note", text: o.note }) : null,
      el("div", { class: "b-foot" }, cb ? el("label", { class: "check" }, cb, el("span", { text: o.check })) : el("span"), el("div", { class: "grow" }), cancelBtn, altBtn, okBtn));
    document.body.append(box);
    const r = anchor.getBoundingClientRect();
    const w = box.offsetWidth;
    const left = Math.max(8, Math.min(window.innerWidth - w - 8, r.left + r.width / 2 - w / 2));
    box.style.left = left + "px";
    // Below the button; above it when there is no room (buttons near the bottom of the page or drawer).
    const above = r.bottom + 10 + box.offsetHeight > window.innerHeight - 8 && r.top - 10 - box.offsetHeight >= 8;
    box.classList.toggle("above", above);
    box.style.top = (above ? r.top - 10 - box.offsetHeight : r.bottom + 10) + "px";
    box.querySelector(".b-arrow").style.left = (r.left + r.width / 2 - left - 7) + "px";
    const done = (ok, alt) => {
      dismissBalloon = null;
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("mousedown", onOut, true);
      box.remove();
      if (anchor.isConnected) anchor.focus();
      resolve({ ok, alt: !!alt, checked: !!(cb && cb.checked) });
    };
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); done(false); }
      else if (e.key === "Enter" && box.contains(e.target) && e.target.tagName !== "BUTTON") { e.preventDefault(); done(true); }
    };
    const onOut = (e) => { if (!box.contains(e.target) && e.target !== anchor) done(false); };
    okBtn.addEventListener("click", () => done(true));
    cancelBtn.addEventListener("click", () => done(false));
    if (altBtn) altBtn.addEventListener("click", () => done(true, true));
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousedown", onOut, true);
    dismissBalloon = () => done(false);
    (o.focusAlt && altBtn ? altBtn : okBtn).focus();
  });
}

export function toast(msg, isErr) {
  const box = $("toast");
  box.textContent = msg; box.className = "toast" + (isErr ? " err" : ""); box.hidden = false;
  clearTimeout(box._timer);
  box._timer = setTimeout(() => { box.hidden = true; }, isErr ? 7000 : 3500);
}
export function banner(kind, text, key, actions) {
  const box = $("banners");
  let b = key ? box.querySelector(`[data-key="${key}"]`) : null;
  if (!b) { b = el("div", { class: "banner " + kind, dataset: { key: key || "" } }); box.append(b); }
  b.className = "banner " + kind;
  b.replaceChildren(icon(kind === "err" ? "error" : kind === "warn" ? "warn" : "info"), el("span", { class: "grow", text }));
  if (actions) b.append(...actions);
  return b;
}
export function removeBanner(key) { const b = $("banners").querySelector(`[data-key="${key}"]`); if (b) b.remove(); }
export function disableAll() {
  for (const b of document.querySelectorAll("button, input, select")) b.disabled = true;
}
function sessionLost() {
  S.quitting = true;
  banner("err", t("Сессия не найдена. Запустите VPNCheck.exe ещё раз: он откроет интерфейс с действующей сессией."), "session");
  disableAll();
}
// Starts a download through a temporary link.
export function download(href, name) {
  const a = el("a", { href, download: name || "" });
  document.body.append(a); a.click(); a.remove();
}

// ---------- formatting ----------
const pad = (n) => String(n).padStart(2, "0");
export const fmtMs = (v) => (v === null || v === undefined) ? "—" : (v < 10 ? v.toFixed(1) : String(Math.round(v)));
export const fmtMsUnit = (v) => (v === null || v === undefined) ? "—" : t("%s мс", fmtMs(v));
export const fmtTime = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
export const fmtShort = (iso) => {
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
export const fmtMbps = (v) => v === null || v === undefined ? "—" : v.toLocaleString(numLocale(), { maximumFractionDigits: v >= 100 ? 0 : 1 });
export const fmtMB = (b) => (b / 1048576).toLocaleString(numLocale(), { maximumFractionDigits: 0 });
export const fmtPause = (sec) => sec >= 60 ? t("%d мин", Math.round(sec / 60)) : t("%v с", sec);
export const proxyKindName = (k) => k === "socks5" ? "SOCKS5" : "HTTP";
export const routeLabel = (r) => !r ? "—" : (r.mode === "proxy" ? t("прокси %s %s", proxyKindName(r.proxyKind), r.proxyAddr) : t("системный маршрут"));
export const routeShort = (r) => r.mode === "proxy" ? t("прокси") : t("системный маршрут");

// ---------- names ----------
export const LEVEL_ICON = { ok: "ok", warn: "warn", error: "error", neutral: "neutral", running: "spin", queued: "queue" };
export const levelText = (l) => ({ ok: t("Доступно"), warn: t("Внимание"), error: t("Ошибка"), neutral: t("Не проверено") })[l] || "";
export const modeName = (m) => ({ fast: t("Быстрая"), stability: t("Стабильность"), diag: t("Диагностика") })[m];
export const confName = (c) => ({ high: t("уверенность высокая"), medium: t("уверенность средняя"), low: t("уверенность низкая") })[c];
export const statusName = (st) => ({ running: t("Выполняется"), completed: t("Завершён"), cancelled: t("Отменён"), partial: t("Частичный"), failed: t("Не выполнен") })[st] || st;
export const stageName = (st) => ({ dns: "DNS", tcp: "TCP", proxy: t("прокси"), tls: "TLS", http: "HTTP", done: t("готово"), "": t("старт") })[st];
export const KIND_NAME = { tls: "TLS", https: "HTTPS GET" };
export const statusClass = (st) => st === "completed" ? "ok" : st === "cancelled" || st === "failed" ? "err" : st === "partial" ? "warn" : "";
