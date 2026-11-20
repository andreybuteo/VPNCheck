// Speed test: the row of speed tiles with the flying-dot animation and the
// still trace, the in-page confirmation balloon, the speed button, the speed
// settings and the speed history table.
import { t } from "./i18n.js";
import {
  $, el, ltr, S, settings, isRunning, speedActive, apiJSON, saveSettings, refreshState, toast,
  fmtMs, fmtTime, fmtShort, fmtMbps, fmtMB, fmtPause, routeLabel,
} from "./core.js";
import { renderHeader } from "./header.js";
import { renderStatus } from "./run.js";
import { renderIPStrip } from "./ipstrip.js";
import { renderHistory } from "./history.js";

const phaseName = (p) => ({ latency: t("задержка"), download: t("скачивание"), upload: t("отдача"), done: t("готово") })[p] || p;
const speedStatusName = (s) => ({ running: t("идёт"), completed: t("готово"), partial: t("частично"), cancelled: t("остановлен"), failed: t("не удался") })[s] || s;
const speedServers = () => (S.state.speed && S.state.speed.servers) || [];
const speedServer = () => { const id = settings().speedServer || "cloudflare"; return speedServers().find(x => x.id === id) || speedServers()[0]; };
const speedHistory = () => (S.state.speed && S.state.speed.history) || [];

// ---------- balloon: an in-page confirmation anchored to a button ----------
// Replaces the browser's confirm(): the page's own look, Enter = OK, Esc or a
// click outside = cancel, focus returns to the button. Positioned over the page
// in viewport pixels, so nothing underneath moves.
export function balloon(anchor, o) {
  return new Promise((resolve) => {
    document.querySelector(".balloon")?.remove();
    const cb = o.check ? el("input", { type: "checkbox" }) : null;
    const okBtn = el("button", { type: "button", class: "btn btn-primary btn-small" }, o.ok || "OK");
    const cancelBtn = el("button", { type: "button", class: "btn btn-small" }, o.cancel || t("Отмена"));
    const box = el("div", { class: "balloon", role: "dialog", "aria-modal": "false", "aria-label": o.title },
      el("div", { class: "b-arrow" }),
      el("div", { class: "b-title", text: o.title }),
      o.rows ? el("dl", { class: "b-rows" }, ...o.rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })])) : null,
      o.note ? el("div", { class: "b-note", text: o.note }) : null,
      el("div", { class: "b-foot" }, cb ? el("label", { class: "check" }, cb, el("span", { text: o.check })) : el("span"), el("div", { class: "grow" }), cancelBtn, okBtn));
    document.body.append(box);
    const r = anchor.getBoundingClientRect();
    const w = box.offsetWidth;
    const left = Math.max(8, Math.min(window.innerWidth - w - 8, r.left + r.width / 2 - w / 2));
    box.style.left = left + "px";
    box.style.top = (r.bottom + 10) + "px";
    box.querySelector(".b-arrow").style.left = (r.left + r.width / 2 - left - 7) + "px";
    const done = (ok) => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("mousedown", onOut, true);
      box.remove();
      anchor.focus();
      resolve({ ok, checked: !!(cb && cb.checked) });
    };
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); done(false); }
      else if (e.key === "Enter" && e.target.tagName !== "BUTTON") { e.preventDefault(); done(true); }
    };
    const onOut = (e) => { if (!box.contains(e.target) && e.target !== anchor) done(false); };
    okBtn.addEventListener("click", () => done(true));
    cancelBtn.addEventListener("click", () => done(false));
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousedown", onOut, true);
    okBtn.focus();
  });
}

// ---------- past results: shown from the exit-IP strip ----------
export function showSpeedResult(id) {
  if (!speedHistory().some(x => x.id === id)) { toast(t("Замер не найден в истории"), true); return; }
  S.speedView = id;
  renderSpeed(); renderIPStrip(); renderStatus();
}
export function backToLatestSpeed() {
  S.speedView = null;
  renderSpeed(); renderIPStrip(); renderStatus();
}
const viewedSpeed = () => (S.speedView && !speedActive() && speedHistory().find(x => x.id === S.speedView)) || null;
// Nodes for the run note while a past speed result is on display.
export function speedNote() {
  const r = viewedSpeed();
  if (!r) return [];
  return [el("span", {}, t("Замер скорости от %s", fmtTime(r.startedAt)) + " · ", el("button", { type: "button", class: "btn-link", onclick: backToLatestSpeed }, t("к текущему")))];
}

// ---------- speed tiles ----------
const small = (text) => el("small", { text });
const mbps = (v) => [fmtMbps(v) + " ", small(t("Мбит/с"))];

export function renderSpeed() {
  const box = $("speedBox");
  const sp = S.state.speed;
  if (!sp || !sp.enabled) { box.hidden = true; return; }
  box.hidden = false;
  const cur = sp.current;
  if (S.speedView && !viewedSpeed()) S.speedView = null;
  const last = cur || viewedSpeed() || speedHistory()[0] || null;
  const srv = last ? (speedServers().find(x => x.id === last.serverId) || { name: last.serverName, kind: "cloudflare" }) : speedServer();
  const cell = (label, value, sub, cls) => el("div", { class: "tile sp-cell" + (cls ? " " + cls : "") }, el("div", { class: "t-label", text: label }), el("div", { class: "t-value" }, value), el("div", { class: "t-sub", text: sub || "" }));
  const fileOnly = srv && srv.kind === "file";
  const live = (ph) => cur && cur.phase === ph && cur.liveMbps !== null && cur.liveMbps !== undefined;
  const valMbps = (v, ph) => live(ph) ? mbps(cur.liveMbps) : (v === null || v === undefined ? "—" : mbps(v));
  const inPhase = (ph) => !!cur && cur.phase === ph;
  const nodeName = last ? t((srv && srv.name) || last.serverName) + (last.colo ? " · " + t("узел %s", last.colo) : "") : (srv ? t(srv.name) : "");
  const first = cell(t("Скорость"), cur ? el("span", { class: "sp-run", text: t("идёт замер") }) : (last ? speedStatusName(last.status) : "—"), nodeName, last && !cur ? "st-" + last.status : "");
  const down = cell(t("Скачивание"), valMbps(last && last.downMbps, "download"),
    inPhase("download") ? t("сейчас · %s МБ", fmtMB(cur.liveBytes)) : (last && last.downBytes ? t("%s МБ за %d с", fmtMB(last.downBytes), Math.round(last.downSeconds)) : t("загрузка с сервера")),
    inPhase("download") ? "active" : "");
  const up = cell(t("Отдача"), fileOnly ? "—" : valMbps(last && last.upMbps, "upload"),
    fileOnly ? t("этот сервер только для скачивания") : (inPhase("upload") ? t("сейчас · %s МБ", fmtMB(cur.liveBytes)) : (last && last.upBytes ? t("%s МБ за %d с", fmtMB(last.upBytes), Math.round(last.upSeconds)) : t("отправка на сервер"))),
    inPhase("upload") ? "active" : "");
  const hasLat = last && last.latencyMs !== null && last.latencyMs !== undefined;
  const lat = cell(t("Задержка"),
    fileOnly ? "—" : (hasLat ? [fmtMs(last.latencyMs) + " ", small(t("мс"))] : (inPhase("latency") ? el("span", { class: "sp-run", text: t("замер…") }) : "—")),
    fileOnly ? t("только через Cloudflare") : (last && last.jitterMs !== null && last.jitterMs !== undefined ? t("разброс ±%s мс", fmtMs(last.jitterMs)) : t("медиана 10 запросов")),
    inPhase("latency") ? "active" : "");
  let metaText, metaSub;
  if (cur) {
    metaText = phaseName(cur.phase) + ` ${cur.phaseIndex || 0}/${cur.phaseCount || 0}`;
    metaSub = cur.phaseMs ? t("%.0f из %.0f с · %s", Math.min(cur.phaseMs / 1000, cur.elapsedMs / 1000), cur.phaseMs / 1000, routeLabel(cur.route)) : routeLabel(cur.route);
  } else if (last) {
    metaText = ltr(fmtShort(last.startedAt));
    metaSub = routeLabel(last.route) + (last.profileName ? " · " + last.profileName : "");
  } else {
    metaText = t("ещё не замеряли");
    metaSub = t("кнопка «Скорость» в шапке");
  }
  const meta = cell(cur ? t("Этап") : t("Когда"), metaText, metaSub, "sp-meta");
  if (last && last.message && !cur) meta.title = last.message;
  // progress runs along the bottom edge of the first tile, which says "measuring"
  const bar = el("div", { class: "sp-bar" });
  if (cur) {
    const total = cur.phaseCount || 1;
    const part = cur.phaseMs ? Math.min(1, cur.elapsedMs / cur.phaseMs) : 0.5;
    bar.style.width = `${Math.round(((cur.phaseIndex - 1 + part) / total) * 100)}%`;
  }
  first.append(bar);
  if (last) {
    down.dataset.phase = "download"; up.dataset.phase = "upload";
    addSpark(down, last.downSeries, inPhase("download"), cur && cur.liveMbps);
    if (!fileOnly) addSpark(up, last.upSeries, inPhase("upload"), cur && cur.liveMbps);
  }
  if (S.flyer && !(cur && (cur.phase === "download" || cur.phase === "upload") && S.flyer.phase === cur.phase)) { S.flyer.stop(); S.flyer = null; }
  box.replaceChildren(first, down, up, lat, meta);
  box.classList.toggle("running", !!cur);
}

// Rate spread after warm-up, for the tooltip and the verdict word of a trace.
const WARM_SAMPLES = 6;
function sparkStats(series) {
  const v = (series || []).slice(WARM_SAMPLES).filter(x => x > 0);
  if (v.length < 4) return null;
  const sorted = [...v].sort((a, b) => a - b);
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const sd = Math.sqrt(v.reduce((a, b) => a + (b - mean) * (b - mean), 0) / v.length);
  const cv = mean > 0 ? sd / mean : 0;
  return { min: sorted[0], med: sorted[Math.floor(sorted.length / 2)], max: sorted[sorted.length - 1], word: cv < 0.12 ? t("ровно") : cv < 0.3 ? t("колеблется") : t("с провалами") };
}

// ---- speed animation: a glowing dot that seems to fly forward ----
// The dot stays at ~3/4 of the width while its trail and the "road" ticks
// scroll left, so it looks like it flies and draws the rate. Its height eases
// toward the live value (which arrives 4 times a second) on every frame, and
// the big number counts toward it the same way. After the phase the trace is
// drawn once, still, in the same style. Reduced-motion users get the still one.
// In right-to-left layout the canvas is mirrored by CSS.
const reduceMotion = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)").matches : false;
function cssVar(name, fallback) { const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim(); return v || fallback; }
function fitCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(10, Math.round(cv.clientWidth * dpr)), h = Math.max(10, Math.round(cv.clientHeight * dpr));
  if (cv.width !== w || cv.height !== h) { cv.width = w; cv.height = h; }
  return dpr;
}
function rgba(color, a) {
  const m = color.match(/^#([0-9a-f]{6})$/i);
  if (!m) return color;
  const n = parseInt(m[1], 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}
class Flyer {
  constructor(phase) {
    this.phase = phase;
    this.canvas = el("canvas", { class: "sp-fly", "aria-hidden": "true" });
    this.num = el("span", { class: "sp-num", text: "0" });
    this.target = 0; this.shown = 0; this.max = 10; this.trail = []; this.last = 0; this.clock = 0; this.raf = 0;
  }
  feed(v) {
    this.target = Math.max(0, v || 0);
    if (!this.raf && !reduceMotion) this.start();
    if (reduceMotion) { this.shown = this.target; this.num.textContent = fmtMbps(this.shown); }
  }
  start() { this.last = performance.now(); const tick = (now) => { this.frame(now); this.raf = requestAnimationFrame(tick); }; this.raf = requestAnimationFrame(tick); }
  stop() { if (this.raf) cancelAnimationFrame(this.raf); this.raf = 0; }
  frame(now) {
    const dt = Math.min(0.05, (now - this.last) / 1000); this.last = now; this.clock += dt;
    this.shown += (this.target - this.shown) * (1 - Math.exp(-dt * 5));
    const peak = Math.max(this.target, ...this.trail.map(p => p.v), 1);
    this.max += (peak * 1.3 - this.max) * (1 - Math.exp(-dt * 2));
    this.trail.push({ t: this.clock, v: this.shown });
    this.num.textContent = fmtMbps(this.shown);
    this.draw();
  }
  draw() {
    const cv = this.canvas; if (!cv.isConnected) return;
    const dpr = fitCanvas(cv); const ctx = cv.getContext("2d"); const W = cv.width, H = cv.height;
    const green = cssVar("--ok", "#2fbf71");
    const speed = 34 * dpr;            // px per second the world scrolls left
    const dotX = W * 0.76, pad = 5 * dpr;
    const yOf = (v) => H - pad - (v / this.max) * (H - pad * 2);
    ctx.clearRect(0, 0, W, H);
    // road ticks flying past
    ctx.strokeStyle = rgba(green, 0.13); ctx.lineWidth = 1 * dpr;
    const gap = 22 * dpr, off = (this.clock * speed * 1.6) % gap;
    for (let x = W - off; x > -gap; x -= gap) { ctx.beginPath(); ctx.moveTo(x, H - pad); ctx.lineTo(x - 7 * dpr, H - pad); ctx.stroke(); }
    // trail
    while (this.trail.length && dotX - (this.clock - this.trail[0].t) * speed < -10) this.trail.shift();
    if (this.trail.length > 1) {
      const pts = this.trail.map(p => [dotX - (this.clock - p.t) * speed, yOf(p.v)]);
      const fill = ctx.createLinearGradient(0, 0, 0, H); fill.addColorStop(0, rgba(green, 0.28)); fill.addColorStop(1, rgba(green, 0));
      ctx.beginPath(); ctx.moveTo(pts[0][0], H); pts.forEach(([x, y]) => ctx.lineTo(x, y)); ctx.lineTo(pts[pts.length - 1][0], H); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
      const fade = ctx.createLinearGradient(0, 0, dotX, 0); fade.addColorStop(0, rgba(green, 0)); fade.addColorStop(0.45, rgba(green, 0.55)); fade.addColorStop(1, rgba(green, 1));
      ctx.beginPath(); pts.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
      ctx.strokeStyle = fade; ctx.lineWidth = 2 * dpr; ctx.lineJoin = "round"; ctx.lineCap = "round"; ctx.stroke();
    }
    // speed streaks just behind the dot
    const y = yOf(this.shown);
    for (let i = 0; i < 3; i++) {
      const ph = (this.clock * 2.2 + i / 3) % 1;
      ctx.strokeStyle = rgba(green, 0.35 * (1 - ph)); ctx.lineWidth = 1.2 * dpr;
      const sx = dotX - 8 * dpr - ph * 26 * dpr, sy = y + (i - 1) * 3.5 * dpr;
      ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(sx - 9 * dpr, sy); ctx.stroke();
    }
    // pulsing halo and the dot
    const pulse = (this.clock * 1.1) % 1;
    ctx.beginPath(); ctx.arc(dotX, y, (4 + pulse * 9) * dpr, 0, Math.PI * 2); ctx.fillStyle = rgba(green, 0.28 * (1 - pulse)); ctx.fill();
    ctx.save(); ctx.shadowColor = green; ctx.shadowBlur = 12 * dpr;
    ctx.beginPath(); ctx.arc(dotX, y, 3.6 * dpr, 0, Math.PI * 2); ctx.fillStyle = green; ctx.fill(); ctx.restore();
    ctx.beginPath(); ctx.arc(dotX, y, 1.4 * dpr, 0, Math.PI * 2); ctx.fillStyle = "#fff"; ctx.fill();
  }
}
// Still trace of a finished phase, same style, dot at the end.
function drawStill(cv, series) {
  if (!cv.isConnected) return;
  const dpr = fitCanvas(cv); const ctx = cv.getContext("2d"); const W = cv.width, H = cv.height;
  const green = cssVar("--ok", "#2fbf71"); const pad = 5 * dpr;
  const max = Math.max(...series, 1) * 1.25;
  const pts = series.map((v, i) => [pad + (i / Math.max(1, series.length - 1)) * (W - pad * 3), H - pad - (v / max) * (H - pad * 2)]);
  ctx.clearRect(0, 0, W, H);
  const fill = ctx.createLinearGradient(0, 0, 0, H); fill.addColorStop(0, rgba(green, 0.22)); fill.addColorStop(1, rgba(green, 0));
  ctx.beginPath(); ctx.moveTo(pts[0][0], H); pts.forEach(([x, y]) => ctx.lineTo(x, y)); ctx.lineTo(pts[pts.length - 1][0], H); ctx.closePath(); ctx.fillStyle = fill; ctx.fill();
  const fade = ctx.createLinearGradient(0, 0, W, 0); fade.addColorStop(0, rgba(green, 0.35)); fade.addColorStop(1, rgba(green, 0.95));
  ctx.beginPath(); pts.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)); ctx.strokeStyle = fade; ctx.lineWidth = 1.8 * dpr; ctx.lineJoin = "round"; ctx.stroke();
  const [ex, ey] = pts[pts.length - 1];
  ctx.save(); ctx.shadowColor = green; ctx.shadowBlur = 8 * dpr; ctx.beginPath(); ctx.arc(ex, ey, 3 * dpr, 0, Math.PI * 2); ctx.fillStyle = green; ctx.fill(); ctx.restore();
}
function addSpark(tile, series, running, liveValue) {
  const pts = series || [];
  const phase = tile.dataset.phase;
  if (running) {
    if (!S.flyer || S.flyer.phase !== phase) { if (S.flyer) S.flyer.stop(); S.flyer = new Flyer(phase); }
    const f = S.flyer;
    f.feed(liveValue);
    const val = tile.querySelector(".t-value");
    if (val) val.replaceChildren(f.num, small(" " + t("Мбит/с")));
    tile.append(f.canvas);
    if (reduceMotion && pts.length) requestAnimationFrame(() => drawStill(f.canvas, pts));
    return;
  }
  if (!pts.length) return;
  const cv = el("canvas", { class: "sp-fly still", "aria-hidden": "true" });
  const st = sparkStats(pts);
  if (st) {
    cv.title = t("после разгона: мин %s · медиана %s · макс %s Мбит/с — %s", fmtMbps(st.min), fmtMbps(st.med), fmtMbps(st.max), st.word);
    const sub = tile.querySelector(".t-sub"); if (sub && sub.textContent) sub.textContent += " · " + st.word;
  }
  tile.append(cv);
  requestAnimationFrame(() => drawStill(cv, pts));
}

// ---------- speed button ----------
export function updateSpeedButton() {
  const btn = $("btnSpeed");
  clearInterval(S.speedCountdown);
  const sp = S.state.speed;
  if (!sp || !sp.enabled) { btn.hidden = true; return; }
  const lim = sp.limits || {};
  const srv = speedServer();
  const block = srv && lim.blocks && lim.blocks[srv.host];
  const until = lim.cooldownUntil ? new Date(lim.cooldownUntil) : null;
  const tick = () => {
    const left = until ? Math.ceil((until - Date.now()) / 1000) : 0;
    btn.textContent = t("Скорость");
    btn.disabled = S.quitting || isRunning() || speedActive();
    btn.title = t("Замер скорости: %s, через выбранный маршрут", srv ? t(srv.name) : "");
    if (isRunning()) btn.title = t("Идёт проверка сервисов: замер скорости можно запустить после неё");
    if (block && new Date(block.until) > Date.now()) { btn.disabled = true; btn.title = t("Сервер приостановлен до %s: %s. Выберите другой сервер в настройках.", fmtTime(block.until), block.reason); return; }
    if (lim.capFreeAt) { btn.disabled = true; btn.title = t("За сутки сделано %v замеров — это предел. Следующий после %s.", lim.used24h, fmtTime(lim.capFreeAt)); return; }
    if (left > 0) {
      btn.disabled = true;
      btn.textContent = t("Скорость %d:%s", Math.floor(left / 60), String(left % 60).padStart(2, "0"));
      btn.title = t("Между замерами скорости пауза %s, чтобы не нагружать сервер", fmtPause(lim.cooldownSec));
      return;
    }
    clearInterval(S.speedCountdown);
  };
  tick();
  if (until && until > Date.now()) S.speedCountdown = setInterval(tick, 1000);
}

export async function startSpeed() {
  const s = settings();
  const srv = speedServer();
  const plan = S.state.speed.plan;
  if (!s.speedAcknowledged) {
    const cloudflare = srv.kind === "cloudflare";
    const answer = await balloon($("btnSpeed"), {
      title: t("Начать замер скорости?"),
      rows: [
        [t("Сервер"), t(srv.name)],
        [t("Маршрут"), routeLabel(s.route)],
        [t("Трафик"), cloudflare ? t("до %v МБ скачивания и до %v МБ отдачи", plan.downCapMB, plan.upCapMB) : t("до %v МБ скачивания", plan.downCapMB)],
        [t("Время"), cloudflare ? t("около 20 с") : t("около %d с", Math.round(plan.phaseSec))],
      ],
      note: t("На мобильном интернете это заметный расход трафика."),
      check: t("Больше не спрашивать"),
      ok: t("Начать замер"), cancel: t("Отмена"),
    });
    if (!answer.ok) return;
    if (answer.checked) s.speedAcknowledged = true;
  }
  $("btnSpeed").disabled = true;
  S.speedView = null;
  try {
    await saveSettings(true);
    const r = await apiJSON("/api/speed", { method: "POST", body: { profileName: s.profileName || "", route: s.route, serverId: srv.id } });
    S.state.speed.current = r.progress;
    renderHeader(); renderSpeed(); renderIPStrip(); renderStatus();
  } catch (e) {
    toast(e.message, true);
    await refreshState().catch(() => {});
    renderHeader(); renderSpeed();
  }
}

// ---------- settings section and history table ----------
export function renderSpeedSettings() {
  const sel = $("speedServer");
  const list = speedServers();
  if (sel.options.length !== list.length || sel.dataset.lang !== document.documentElement.lang) {
    sel.replaceChildren(...list.map(x => el("option", { value: x.id, text: t(x.name) })));
    sel.dataset.lang = document.documentElement.lang;
  }
  sel.value = settings().speedServer || "cloudflare";
  const srv = speedServer();
  $("speedServerNote").textContent = srv ? t(srv.note) : "";
  const plan = S.state.speed && S.state.speed.plan;
  const lim = S.state.speed && S.state.speed.limits;
  if (plan && lim) $("speedLimitsNote").textContent = t("Бережный режим: только по кнопке; %d с на этап, %v соединения, не больше %v МБ скачивания и %v МБ отдачи; пауза %s между замерами и не больше %v замеров в сутки (сделано %v). При ответе 429, 403 или проверке «человек ли вы» замер сразу прекращается, а сервер откладывается на время из Retry-After или на час. Повторов нет.",
    Math.round(plan.phaseSec), plan.parallel, plan.downCapMB, plan.upCapMB, fmtPause(lim.cooldownSec), lim.dailyCap, lim.used24h);
}
export function renderSpeedHistory() {
  const box = $("speedHistory");
  const list = speedHistory();
  if (!list.length) { box.replaceChildren(el("div", { class: "hint", text: t("Замеров ещё не было.") })); return; }
  const heads = [t("Начало"), t("Профиль"), t("Сервер"), t("Маршрут"), t("Скачивание, Мбит/с"), t("Отдача, Мбит/с"), t("Задержка, мс"), t("Итог"), ""];
  const thead = el("thead", {}, el("tr", {}, ...heads.map((h, i) => el("th", { class: i >= 4 && i <= 6 ? "num" : "", text: h }))));
  const rows = list.map(r => el("tr", { title: r.message || "" },
    el("td", { text: fmtShort(r.startedAt) }),
    el("td", { text: r.profileName || "—" }),
    el("td", { text: t(r.serverName || r.serverId) + (r.colo ? " · " + r.colo : "") }),
    el("td", { text: routeLabel(r.route) }),
    el("td", { class: "num", text: fmtMbps(r.downMbps) }),
    el("td", { class: "num", text: fmtMbps(r.upMbps) }),
    el("td", { class: "num", text: r.latencyMs === null || r.latencyMs === undefined ? "—" : fmtMs(r.latencyMs) + (r.jitterMs ? " ±" + fmtMs(r.jitterMs) : "") }),
    el("td", { text: speedStatusName(r.status) + (r.demo ? " " + t("(демо)") : "") }),
    el("td", { class: "actions" }, el("button", { type: "button", class: "btn-link", onclick: async () => {
      if (!confirm(t("Удалить этот замер из истории?"))) return;
      try {
        S.state.speed = await apiJSON(`/api/speed/${encodeURIComponent(r.id)}`, { method: "DELETE" });
        renderSpeed(); renderSpeedHistory(); renderHistory(); renderIPStrip(); renderStatus();
      } catch (e) { toast(e.message, true); }
    } }, t("Удалить")))));
  box.replaceChildren(el("div", { class: "table-wrap" }, el("table", { class: "grid" }, thead, el("tbody", {}, ...rows))));
}
