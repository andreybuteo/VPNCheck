// Speed test: the row of speed tiles with the flying-dot animation and the
// still trace, the speed button, the speed
// settings and the speed history table.
import { t, numLocale } from "./i18n.js";
import {
  $, el, ltr, S, settings, isRunning, speedActive, apiJSON, saveSettings, refreshState, toast,
  fmtMs, fmtTime, fmtShort, fmtMbps, fmtMB, fmtPause, routeLabel,
  balloon,
} from "./core.js";
import { renderHeader } from "./header.js";
import { renderStatus } from "./run.js";
import { renderIPStrip } from "./ipstrip.js";
import { renderHistory } from "./history.js";
import { isStale, ageText } from "./stale.js";

const phaseName = (p) => ({ latency: t("задержка"), download: t("скачивание"), upload: t("отдача"), done: t("готово") })[p] || p;
const speedStatusName = (s) => ({ running: t("идёт"), completed: t("готово"), partial: t("частично"), cancelled: t("остановлен"), failed: t("не удался") })[s] || s;
const speedServers = () => (S.state.speed && S.state.speed.servers) || [];
const speedServer = () => { const id = settings().speedServer || "cloudflare"; return speedServers().find(x => x.id === id) || speedServers()[0]; };
const speedHistory = () => (S.state.speed && S.state.speed.history) || [];

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
  // short form under the status: "22.11 19:38 · Cloudflare · узел AMS"; the full server name is in the tooltip
  const fullName = t((srv && srv.name) || (last && last.serverName) || "");
  const shortName = (srv && srv.kind === "cloudflare" ? "Cloudflare" : fullName.split(" (")[0]) + (last && last.colo ? " · " + t("узел %s", last.colo) : "");
  const firstSub = last && !cur ? [ltr(fmtShort(last.startedAt)), " · " + shortName] : nodeName;
  const first = cell(t("Скорость"), cur ? el("span", { class: "sp-run", text: t("идёт замер") }) : (last ? (last.status === "completed" ? "✓ " : "") + speedStatusName(last.status) : "—"), "", last && !cur ? "st-" + last.status : "");
  first.querySelector(".t-sub").append(...[].concat(firstSub));
  first.title = [last && !cur && last.status === "completed" ? t("Все этапы замера завершены штатно.") : "", nodeName].filter(Boolean).join("\n");
  const down = cell(t("Скачивание"), valMbps(last && last.downMbps, "download"),
    inPhase("download") ? t("сейчас · %s МБ", fmtMB(cur.liveBytes)) : (last && last.downBytes ? phaseEnd(last, "down", sp.plan) : t("загрузка с сервера")),
    inPhase("download") ? "active" : "");
  const up = cell(t("Отдача"), fileOnly ? "—" : valMbps(last && last.upMbps, "upload"),
    fileOnly ? t("этот сервер только для скачивания") : (inPhase("upload") ? t("сейчас · %s МБ", fmtMB(cur.liveBytes)) : (last && last.upBytes ? phaseEnd(last, "up", sp.plan) : t("отправка на сервер"))),
    inPhase("upload") ? "active" : "");
  // Finished figures keep their heat: amber from 100 Mbit/s, glowing from 200, gold from 500.
  for (const [cellEl, v, ph] of [[down, last && last.downMbps, "download"], [up, fileOnly ? null : last && last.upMbps, "upload"]]) {
    const tier = !inPhase(ph) && v ? speedTier(v) : "";
    if (tier) cellEl.classList.add(tier);
  }
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
    metaText = last.exitIp
      ? [el("span", { class: "ip-flag", html: window.flagSVG ? window.flagSVG(last.exitCountry) : "" }), " ", ltr(last.exitIp)]
      : t("не определён");
    metaSub = routeLabel(last.route) + (last.profileName ? " · " + last.profileName : "");
  } else {
    metaText = t("ещё не замеряли");
    metaSub = t("кнопка «Скорость» в шапке");
  }
  const meta = cell(cur ? t("Этап") : t("IP выхода"), metaText, metaSub, "sp-meta");
  if (last && last.message && !cur) meta.title = last.message;
  // progress runs along the bottom edge of the first tile, which says "measuring"
  const bar = el("div", { class: "sp-bar" });
  if (cur) {
    const total = cur.phaseCount || 1;
    const part = cur.phaseMs ? Math.min(1, cur.elapsedMs / cur.phaseMs) : 0.5;
    bar.style.width = `${Math.round(((cur.phaseIndex - 1 + part) / total) * 100)}%`;
  }
  first.append(bar);
  for (const [tile, side] of [[down, "down"], [up, "up"]]) {
    const why = last && !inPhase(side === "down" ? "download" : "upload") && phaseEndTitle(last, side, sp.plan);
    if (why) tile.title = why;
  }
  if (last) {
    down.dataset.phase = "download"; up.dataset.phase = "upload";
    addSpark(down, last.downSeries, inPhase("download"), cur && cur.liveMbps, !cur && phaseOK(last, "down"));
    if (!fileOnly) addSpark(up, last.upSeries, inPhase("upload"), cur && cur.liveMbps, !cur && phaseOK(last, "up"));
  }
  if (S.flyer && !(cur && (cur.phase === "download" || cur.phase === "upload") && S.flyer.phase === cur.phase)) { S.flyer.stop(); S.flyer = null; }
  const legend = speedLegend(cur, last);
  box.replaceChildren(first, down, up, lat, meta, legend);
  box.classList.toggle("running", !!cur);
  // A speed test older than 30 minutes is faded on its own, apart from the check.
  const when = last && (last.finishedAt || last.startedAt);
  const stale = !cur && isStale(when);
  box.classList.toggle("stale", stale);
  for (const c of [first, down, up, lat, meta]) if (stale) c.title = [c.title, t("Замер %s: с тех пор скорость могла измениться. Нажмите «Скорость», чтобы замерить заново.", ageText(when))].filter(Boolean).join("\n");
}

// ---- caption over the speed row: the speed test is a separate test, with its
// own time, exit IP and route, and it says so when they differ from the check
// shown above it.
function runExitIP(run) {
  const x = run && run.externalIp;
  return x ? (x.after || x.before || "") : "";
}
function sameRoute(a, b) {
  return !!a && !!b && a.mode === b.mode && (a.proxyAddr || "") === (b.proxyAddr || "");
}
// The speed tiles are framed as one group; this legend sits on the frame.
function speedLegend(cur, last) {
  const head = el("div", { class: "sp-legend" });
  const parts = [];
  let warn = "";
  if (cur) {
    parts.push(t("идёт сейчас"), routeLabel(cur.route));
  } else if (last) {
    const run = S.view && S.view.run;
    if (run) {
      const ip = runExitIP(run);
      if (ip && last.exitIp && ip !== last.exitIp) warn = t("⚠ другой IP, чем у проверки (%s)", ip);
      else if (!sameRoute(run.route, last.route)) warn = t("⚠ другой маршрут, чем у проверки");
    }
  } else {
    parts.push(t("ещё не замеряли"));
  }
  const hint = el("span", { class: "hint" });
  parts.forEach((p, i) => { if (i) hint.append(" · "); hint.append(...[].concat(p)); });
  head.replaceChildren(
    el("span", { class: "ip-title", text: t("Замер скорости — отдельный тест") }),
    hint,
    warn ? el("span", { class: "sp-warn", text: warn }) : "");
  head.title = t("Скорость замеряется отдельной кнопкой и в своё время. Её IP и маршрут могут отличаться от проверки доступности выше.");
  return head;
}

// ---- why a phase ended: a finished phase says so, so a short one does not
// look like an interruption. A phase ends normally either at the byte cap
// (fast link: the rate is already measured, no need to move more data) or
// after the full phase time.
const fmtSec = (v) => Number(v || 0).toLocaleString(numLocale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 });
function phaseOK(r, side) {
  const v = side === "down" ? r.downMbps : r.upMbps;
  return v !== null && v !== undefined && r.status !== "failed";
}
function phaseEnd(r, side, plan) {
  const bytes = side === "down" ? r.downBytes : r.upBytes;
  const sec = side === "down" ? r.downSeconds : r.upSeconds;
  const cap = side === "down" ? r.downCapReached : r.upCapReached;
  if (!phaseOK(r, side)) return t("%s МБ за %d с", fmtMB(bytes), Math.round(sec));
  if (cap) return t("✓ потолок %s МБ за %s с", fmtMB(bytes), fmtSec(sec));
  return t("✓ %s МБ за полные %d с", fmtMB(bytes), Math.round(sec));
}
function phaseEndTitle(r, side, plan) {
  if (!r || !phaseOK(r, side)) return "";
  const bytes = side === "down" ? r.downBytes : r.upBytes;
  const sec = side === "down" ? r.downSeconds : r.upSeconds;
  const cap = side === "down" ? r.downCapReached : r.upCapReached;
  return cap
    ? t("Этап завершён штатно: за %s с передано %s МБ — это потолок одного замера. Канал быстрый, скорость уже измерена, дальше гонять трафик не нужно.", fmtSec(sec), fmtMB(bytes))
    : t("Этап завершён штатно: прошли все %d с замера, передано %s МБ.", Math.round(sec), fmtMB(bytes));
}

// Scale of the speed graphs: 100 Mbit/s, then 200, 500, 1000… when exceeded.
const SCALE_STEPS = [100, 200, 500, 1000, 2000, 5000, 10000];
function scaleFor(v) {
  for (const s of SCALE_STEPS) if (v <= s) return s;
  return SCALE_STEPS[SCALE_STEPS.length - 1];
}
function scaleLabel(tile, scale) {
  let lab = tile.querySelector(".sp-scale");
  if (!lab) { lab = el("span", { class: "sp-scale" }); tile.append(lab); }
  const text = t("шкала %d Мбит/с", scale);
  if (lab.textContent !== text) lab.textContent = text;
  return lab;
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
// ---------- heat: the faster the line, the hotter it looks ----------
// Up to about 80 Mbit/s the dot stays calm green. From 100 it warms to amber,
// from 200 an orange comet tail with sparks grows behind it, from 500 the
// dot burns gold. Fast is good news, so the colours are warm, never red.
function heatOf(v) {
  if (!(v > 0)) return 0;
  const h = (Math.log10(v) - Math.log10(80)) / (Math.log10(600) - Math.log10(80));
  return Math.min(1, Math.max(0, h));
}
function hexRGB(c) { const n = parseInt(c.slice(1), 16); return [n >> 16, (n >> 8) & 255, n & 255]; }
function mix(a, b, k) {
  if (!/^#[0-9a-f]{6}$/i.test(a) || !/^#[0-9a-f]{6}$/i.test(b)) return a;
  const x = hexRGB(a), y = hexRGB(b);
  return "#" + x.map((v, i) => Math.round(v + (y[i] - v) * k).toString(16).padStart(2, "0")).join("");
}
function heatPalette() {
  return { green: cssVar("--ok", "#2fbf71"), amber: cssVar("--hot-amber", "#f5a623"), orange: cssVar("--hot-orange", "#ff7a1a"), gold: cssVar("--hot-gold", "#ffd24a") };
}
// green -> amber (around 200) -> orange (500 and more)
function heatColor(pal, h) { return h < 0.5 ? mix(pal.green, pal.amber, h * 2) : mix(pal.amber, pal.orange, (h - 0.5) * 2); }
// speedTier names the class of a finished figure: fast 100+, hot 200+, blazing 500+.
function speedTier(v) { return v >= 500 ? "tier-blazing" : v >= 200 ? "tier-hot" : v >= 100 ? "tier-fast" : ""; }
// strokeHeat draws a line whose every segment is coloured by its own speed.
function strokeHeat(ctx, pts, vals, pal, alphaAt, width) {
  ctx.lineWidth = width; ctx.lineJoin = "round"; ctx.lineCap = "round";
  for (let i = 1; i < pts.length; i++) {
    ctx.strokeStyle = rgba(heatColor(pal, heatOf(vals[i])), alphaAt(pts[i][0]));
    ctx.beginPath(); ctx.moveTo(pts[i - 1][0], pts[i - 1][1]); ctx.lineTo(pts[i][0], pts[i][1]); ctx.stroke();
  }
}

class Flyer {
  constructor(phase) {
    this.phase = phase;
    this.canvas = el("canvas", { class: "sp-fly", "aria-hidden": "true" });
    this.num = el("span", { class: "sp-num", text: "0" });
    this.target = 0; this.shown = 0; this.max = 100; this.scale = 100; this.trail = []; this.last = 0; this.clock = 0; this.raf = 0;
    this.sparks = []; this.dt = 0; this.spawn = 0;
    this.label = null;
  }
  feed(v) {
    this.target = Math.max(0, v || 0);
    if (!this.raf && !reduceMotion) this.start();
    if (reduceMotion) { this.shown = this.target; this.num.textContent = fmtMbps(this.shown); this.paintNumber(); }
  }
  start() { this.last = performance.now(); const tick = (now) => { this.frame(now); this.raf = requestAnimationFrame(tick); }; this.raf = requestAnimationFrame(tick); }
  stop() { if (this.raf) cancelAnimationFrame(this.raf); this.raf = 0; }
  frame(now) {
    const dt = Math.min(0.05, (now - this.last) / 1000); this.last = now; this.clock += dt; this.dt = dt;
    this.shown += (this.target - this.shown) * (1 - Math.exp(-dt * 5));
    const peak = Math.max(this.target, this.shown, ...this.trail.map(p => p.v), 1);
    this.scale = scaleFor(peak);
    this.max += (this.scale - this.max) * (1 - Math.exp(-dt * 4));   // the jump to 200/500 is eased
    if (this.label) { const text = t("шкала %d Мбит/с", this.scale); if (this.label.textContent !== text) this.label.textContent = text; }
    this.trail.push({ t: this.clock, v: this.shown });
    this.num.textContent = fmtMbps(this.shown);
    this.paintNumber();
    this.draw();
  }
  // The figure glows with the speed: green glow from 100, towards gold from 200,
  // bright gold from 500. Not amber: amber is the colour of warnings here.
  paintNumber() {
    const pal = heatPalette(), h = heatOf(this.shown);
    if (h < 0.11) { this.num.style.color = ""; this.num.style.textShadow = ""; return; }
    const c = h < 0.45 ? pal.green : mix(pal.green, pal.gold, Math.min(1, (h - 0.45) / 0.45));
    this.num.style.color = c;
    this.num.style.textShadow = "0 0 " + Math.round(4 + 9 * h) + "px " + rgba(c, 0.3 + 0.35 * h);
  }
  draw() {
    const cv = this.canvas; if (!cv.isConnected) return;
    const dpr = fitCanvas(cv); const ctx = cv.getContext("2d"); const W = cv.width, H = cv.height;
    const pal = heatPalette(), green = pal.green;
    const h = heatOf(this.shown), hot = heatColor(pal, h);
    const speed = (34 + 40 * h) * dpr;   // the world scrolls faster when the link is fast
    const dotX = W * 0.76, pad = 5 * dpr;
    const yOf = (v) => H - pad - (v / this.max) * (H - pad * 2);
    ctx.clearRect(0, 0, W, H);
    gridLines(ctx, W, H, pad, dpr, green);
    // road ticks flying past
    ctx.strokeStyle = rgba(green, 0.13); ctx.lineWidth = 1 * dpr;
    const gap = 22 * dpr, off = (this.clock * speed * 1.6) % gap;
    for (let x = W - off; x > -gap; x -= gap) { ctx.beginPath(); ctx.moveTo(x, H - pad); ctx.lineTo(x - 7 * dpr, H - pad); ctx.stroke(); }
    const y = yOf(this.shown);
    // trail: the fill warms with the current speed, the line is coloured point by point
    while (this.trail.length && dotX - (this.clock - this.trail[0].t) * speed < -10) this.trail.shift();
    if (this.trail.length > 1) {
      const pts = this.trail.map(p => [dotX - (this.clock - p.t) * speed, yOf(p.v)]);
      const vals = this.trail.map(p => p.v);
      const fill = ctx.createLinearGradient(0, 0, 0, H); fill.addColorStop(0, rgba(mix(green, pal.amber, h * 0.7), 0.28)); fill.addColorStop(1, rgba(green, 0));
      ctx.beginPath(); ctx.moveTo(pts[0][0], H); pts.forEach(([x, py]) => ctx.lineTo(x, py)); ctx.lineTo(pts[pts.length - 1][0], H); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
      strokeHeat(ctx, pts, vals, pal, (x) => Math.max(0, Math.min(1, x / dotX)) ** 1.4, 2 * dpr);
      // comet tail: a glowing streak over the most recent part, longer and hotter with speed
      if (h > 0.08) {
        const tail = (40 + 170 * h) * dpr;
        const recent = pts.filter(([x]) => x > dotX - tail);
        if (recent.length > 1) {
          ctx.save();
          const g = ctx.createLinearGradient(dotX - tail, 0, dotX, 0);
          g.addColorStop(0, rgba(hot, 0)); g.addColorStop(0.6, rgba(hot, 0.45 * h + 0.15)); g.addColorStop(1, rgba(h > 0.9 ? pal.gold : hot, 0.95));
          ctx.shadowColor = hot; ctx.shadowBlur = (6 + 14 * h) * dpr;
          ctx.beginPath(); recent.forEach(([x, py], i) => i ? ctx.lineTo(x, py) : ctx.moveTo(x, py));
          ctx.strokeStyle = g; ctx.lineWidth = (2.5 + 4 * h) * dpr; ctx.lineCap = "round"; ctx.lineJoin = "round"; ctx.stroke();
          ctx.restore();
        }
      }
    }
    // sparks thrown back from the dot once the link is fast (200 and more)
    if (h > 0.4 && !reduceMotion) {
      this.spawn += this.dt * 70 * (h - 0.4) / 0.6;
      while (this.spawn >= 1) {
        this.spawn -= 1;
        this.sparks.push({ age: 0, max: 0.35 + Math.random() * 0.45, vx: 40 + Math.random() * 110, vy: (Math.random() - 0.5) * 50, y0: y, gold: Math.random() < 0.5 });
      }
    }
    this.sparks = this.sparks.filter(s => (s.age += this.dt) < s.max);
    for (const s of this.sparks) {
      const k = 1 - s.age / s.max;
      const sx = dotX - 6 * dpr - (s.vx + speed / dpr) * s.age * dpr, sy = s.y0 + s.vy * s.age * dpr;
      ctx.beginPath(); ctx.arc(sx, sy, (0.8 + 1.4 * k) * dpr, 0, Math.PI * 2);
      ctx.fillStyle = rgba(s.gold ? pal.gold : pal.orange, 0.85 * k); ctx.fill();
    }
    // speed streaks just behind the dot: more and longer when fast
    const streaks = 3 + Math.round(4 * h);
    for (let i = 0; i < streaks; i++) {
      const ph = (this.clock * (2.2 + 2 * h) + i / streaks) % 1;
      ctx.strokeStyle = rgba(hot, (0.35 + 0.3 * h) * (1 - ph)); ctx.lineWidth = (1.2 + 0.6 * h) * dpr;
      const len = (9 + 18 * h) * dpr;
      const sx = dotX - 8 * dpr - ph * (26 + 30 * h) * dpr, sy = y + (i - (streaks - 1) / 2) * 3.2 * dpr;
      ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(sx - len, sy); ctx.stroke();
    }
    // plasma cap from 200 Mbit/s: a bright bow wrapping the front of the dot,
    // like a meteor entering the air: white-gold inside, orange at the edge, flickering
    if (h > 0.45) {
      const p = Math.min(1, (h - 0.45) / 0.55);
      const flick = 0.82 + 0.18 * Math.sin(this.clock * 37) * Math.sin(this.clock * 23 + 1);
      const r = (6 + 8 * p) * dpr, cx = dotX + r * 0.3;
      ctx.save();
      const glow = ctx.createRadialGradient(cx, y, 0, cx, y, r * 1.7);
      glow.addColorStop(0, rgba("#ffffff", 0.5 * p * flick));
      glow.addColorStop(0.35, rgba(pal.gold, 0.42 * p * flick));
      glow.addColorStop(1, rgba(pal.orange, 0));
      ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(cx, y, r * 1.7, 0, Math.PI * 2); ctx.fill();
      ctx.shadowColor = pal.gold; ctx.shadowBlur = (8 + 12 * p) * dpr; ctx.lineCap = "round";
      const bows = [[r, (2 + 2.2 * p) * dpr, pal.orange, 0.75], [r * 0.8, (1.3 + 1.3 * p) * dpr, pal.gold, 0.9], [r * 0.62, 1.1 * dpr, "#ffffff", 0.95]];
      for (const [rr, w, c, a] of bows) {
        ctx.strokeStyle = rgba(c, a * flick); ctx.lineWidth = w;
        ctx.beginPath(); ctx.arc(dotX - r * 0.15, y, rr, -Math.PI * 0.42, Math.PI * 0.42); ctx.stroke();
      }
      ctx.restore();
    }
    // pulsing halo and the dot: green when calm, amber when fast, gold when blazing
    const dot = h > 0.9 ? mix(hot, pal.gold, (h - 0.9) * 10) : hot;
    const pulse = (this.clock * (1.1 + h)) % 1;
    ctx.beginPath(); ctx.arc(dotX, y, (4 + pulse * (9 + 6 * h)) * dpr, 0, Math.PI * 2); ctx.fillStyle = rgba(dot, (0.28 + 0.15 * h) * (1 - pulse)); ctx.fill();
    ctx.save(); ctx.shadowColor = dot; ctx.shadowBlur = (12 + 16 * h) * dpr;
    ctx.beginPath(); ctx.arc(dotX, y, 3.6 * (1 + 0.35 * h) * dpr, 0, Math.PI * 2); ctx.fillStyle = dot; ctx.fill(); ctx.restore();
    ctx.beginPath(); ctx.arc(dotX, y, 1.4 * (1 + 0.6 * h) * dpr, 0, Math.PI * 2); ctx.fillStyle = "#fff"; ctx.fill();
  }
}
// Still trace of a finished phase, same style, dot at the end.
// Faint top and middle lines of the scale (the label is HTML, so it is not
// mirrored with the canvas in right-to-left layout).
function gridLines(ctx, W, H, pad, dpr, green) {
  ctx.save();
  ctx.strokeStyle = rgba(green, 0.16); ctx.lineWidth = 1 * dpr; ctx.setLineDash([3 * dpr, 4 * dpr]);
  for (const y of [pad, pad + (H - pad * 2) / 2]) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
  ctx.restore();
}
function drawStill(cv, series, finished) {
  if (!cv.isConnected) return;
  const dpr = fitCanvas(cv); const ctx = cv.getContext("2d"); const W = cv.width, H = cv.height;
  const pal = heatPalette(), green = pal.green; const pad = 5 * dpr;
  const max = scaleFor(Math.max(...series, 1));
  const pts = series.map((v, i) => [pad + (i / Math.max(1, series.length - 1)) * (W - pad * 3), H - pad - (v / max) * (H - pad * 2)]);
  const end = heatColor(pal, heatOf(series[series.length - 1]));
  ctx.clearRect(0, 0, W, H);
  gridLines(ctx, W, H, pad, dpr, green);
  const hMax = heatOf(Math.max(...series));
  const fill = ctx.createLinearGradient(0, 0, 0, H); fill.addColorStop(0, rgba(mix(green, pal.amber, hMax * 0.7), 0.22)); fill.addColorStop(1, rgba(green, 0));
  ctx.beginPath(); ctx.moveTo(pts[0][0], H); pts.forEach(([x, y]) => ctx.lineTo(x, y)); ctx.lineTo(pts[pts.length - 1][0], H); ctx.closePath(); ctx.fillStyle = fill; ctx.fill();
  // the still trace keeps the heat colours: fast parts of the test stay amber or orange
  strokeHeat(ctx, pts, series, pal, (x) => 0.35 + 0.6 * (x / W), 1.8 * dpr);
  const [ex, ey] = pts[pts.length - 1];
  if (finished) {
    // finish line and a ringed dot: the phase ended normally
    ctx.save(); ctx.strokeStyle = rgba(end, 0.55); ctx.lineWidth = 1 * dpr; ctx.setLineDash([2 * dpr, 2 * dpr]);
    ctx.beginPath(); ctx.moveTo(ex, pad); ctx.lineTo(ex, H - pad); ctx.stroke(); ctx.restore();
    ctx.beginPath(); ctx.arc(ex, ey, 5.5 * dpr, 0, Math.PI * 2); ctx.strokeStyle = end; ctx.lineWidth = 1.5 * dpr; ctx.stroke();
  }
  ctx.save(); ctx.shadowColor = end; ctx.shadowBlur = 8 * dpr; ctx.beginPath(); ctx.arc(ex, ey, 3 * dpr, 0, Math.PI * 2); ctx.fillStyle = end; ctx.fill(); ctx.restore();
}
function addSpark(tile, series, running, liveValue, finished) {
  const pts = series || [];
  const phase = tile.dataset.phase;
  if (running) {
    if (!S.flyer || S.flyer.phase !== phase) { if (S.flyer) S.flyer.stop(); S.flyer = new Flyer(phase); }
    const f = S.flyer;
    f.feed(liveValue);
    const val = tile.querySelector(".t-value");
    if (val) val.replaceChildren(f.num, small(" " + t("Мбит/с")));
    tile.append(f.canvas);
    f.label = scaleLabel(tile, f.scale);
    if (reduceMotion && pts.length) requestAnimationFrame(() => drawStill(f.canvas, pts, false));
    return;
  }
  if (!pts.length) return;
  scaleLabel(tile, scaleFor(Math.max(...pts, 1)));
  const cv = el("canvas", { class: "sp-fly still", "aria-hidden": "true" });
  const st = sparkStats(pts);
  if (st) {
    cv.title = t("после разгона: мин %s · медиана %s · макс %s Мбит/с — %s", fmtMbps(st.min), fmtMbps(st.med), fmtMbps(st.max), st.word);
    const sub = tile.querySelector(".t-sub"); if (sub && sub.textContent) sub.textContent += " · " + st.word;
  }
  tile.append(cv);
  requestAnimationFrame(() => drawStill(cv, pts, finished));
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
    el("td", { class: "actions" }, el("button", { type: "button", class: "btn-link", onclick: async (ev) => {
      if (!(await balloon(ev.currentTarget, { title: t("Удалить этот замер из истории?"), ok: t("Удалить"), danger: true })).ok) return;
      try {
        S.state.speed = await apiJSON(`/api/speed/${encodeURIComponent(r.id)}`, { method: "DELETE" });
        renderSpeed(); renderSpeedHistory(); renderHistory(); renderIPStrip(); renderStatus();
      } catch (e) { toast(e.message, true); }
    } }, t("Удалить")))));
  box.replaceChildren(el("div", { class: "table-wrap" }, el("table", { class: "grid" }, thead, el("tbody", {}, ...rows))));
}
