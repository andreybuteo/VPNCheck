// History fold: saved runs, export links, comparison of two runs.
import { t, tp } from "./i18n.js";
import {
  $, el, icon, S, api, apiJSON, normalizeView, refreshState, toast, isRunning, balloon,
  fmtMs, fmtShort, modeName, statusName, LEVEL_ICON,
} from "./core.js";
import { renderAll } from "./app.js";

export function renderHistory() {
  const list = S.state.history || [];
  const sn = ((S.state.speed && S.state.speed.history) || []).length;
  $("historyCount").textContent = (list.length ? tp(list.length, "%d запуск", "%d запуска", "%d запусков") : t("запусков нет"))
    + (sn ? " · " + t("%s скорости", tp(sn, "%d замер", "%d замера", "%d замеров")) : "") + " · " + t("сравнение, экспорт JSON/CSV");
  const body = $("historyBody");
  if (!list.length) {
    body.replaceChildren(el("div", { class: "hint", text: t("История пуста. Результаты каждого запуска сохраняются локально и доступны без интернета.") }));
    $("btnCompare").disabled = true;
    return;
  }
  S.compareSel = S.compareSel.filter(id => list.some(r => r.id === id));
  const sens = el("label", { class: "check" },
    el("input", { type: "checkbox", checked: S.sensitiveExport, onchange: (e) => { S.sensitiveExport = e.target.checked; renderHistory(); } }),
    el("span", { text: t("Включать внешний IP и адреса прокси в экспорт и итог (подробные сетевые данные)") }));
  const heads = ["", t("Начало"), t("Профиль"), t("Режим"), t("Маршрут"), t("Статус"), t("Узлов"), "TLS", "HTTP", t("Ошибки"), t("Медиана, мс"), t("Действия")];
  const thead = el("thead", {}, el("tr", {}, ...heads.map(h => el("th", { text: h }))));
  const rows = list.map(r => {
    const q = S.sensitiveExport ? "?sensitive=1" : "";
    const c = r.counts || {};
    return el("tr", {},
      el("td", {}, el("input", { type: "checkbox", "aria-label": t("Выбрать для сравнения"), checked: S.compareSel.includes(r.id), onchange: (e) => {
        if (e.target.checked) { S.compareSel.push(r.id); if (S.compareSel.length > 2) S.compareSel.shift(); } else S.compareSel = S.compareSel.filter(x => x !== r.id);
        renderHistory();
      } })),
      el("td", { text: fmtShort(r.startedAt) }),
      el("td", { text: r.profileName || "—" }),
      el("td", { text: modeName(r.mode) || r.mode }),
      el("td", { text: r.route.mode === "proxy" ? t("прокси %s", r.route.proxyKind) : t("система") }),
      el("td", { text: statusName(r.status) }),
      el("td", { class: "num", text: `${c.probed || 0}/${c.planned || 0}` }),
      el("td", { class: "num", text: `${c.tlsOk || 0}` }),
      el("td", { class: "num", text: c.httpsTotal ? `${c.httpMatch}/${c.httpsTotal}` : "—" }),
      el("td", { class: "num", text: `${c.errors || 0}` }),
      el("td", { class: "num", text: fmtMs(r.medianTlsReadyMs) }),
      el("td", { class: "actions" },
        el("button", { type: "button", class: "btn-link", onclick: () => openHistory(r.id) }, t("Открыть")),
        el("a", { class: "btn-link", href: `/api/export/${r.id}/json${q}`, download: "" }, "JSON"),
        el("a", { class: "btn-link", href: `/api/export/${r.id}/csv${q}`, download: "" }, "CSV"),
        el("button", { type: "button", class: "btn-link", onclick: () => copySummary(r.id) }, t("Копировать итог")),
        el("button", { type: "button", class: "btn-link", onclick: (ev) => deleteRun(r.id, ev.currentTarget) }, t("Удалить"))));
  });
  body.replaceChildren(sens, el("div", { class: "table-wrap" }, el("table", { class: "grid" }, thead, el("tbody", {}, ...rows))));
  $("btnCompare").disabled = S.compareSel.length !== 2;
}

export async function openHistory(id) {
  try {
    const v = normalizeView(await apiJSON("/api/history/" + encodeURIComponent(id)));
    S.view = v; S.viewingHistory = !(S.state.current.run && S.state.current.run.id === id && isRunning());
    S.expanded = null; renderAll(); window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (e) { toast(t("Не удалось открыть запуск: %s", e.message), true); }
}
export function backToCurrent() { S.viewingHistory = false; S.view = S.state.current.run ? S.state.current : null; S.expanded = null; renderAll(); }

async function copySummary(id) {
  try {
    const r = await api(`/api/summary/${encodeURIComponent(id)}${S.sensitiveExport ? "?sensitive=1" : ""}`);
    await navigator.clipboard.writeText(await r.text());
    toast(S.sensitiveExport ? t("Краткий итог скопирован (с IP и адресами прокси)") : t("Краткий итог скопирован (без IP и адресов прокси)"));
  } catch (e) { toast(t("Не удалось скопировать: %s", e.message), true); }
}
async function deleteRun(id, anchor) {
  if (!(await balloon(anchor, { title: t("Удалить этот запуск из истории?"), ok: t("Удалить"), danger: true })).ok) return;
  try {
    await apiJSON("/api/history/" + encodeURIComponent(id), { method: "DELETE" });
    await refreshState();
    if (S.view && S.view.run && S.view.run.id === id) backToCurrent();
    renderAll();
  } catch (e) { toast(e.message, true); }
}

const routeText = (r) => r.mode === "proxy" ? t("прокси %s %s", r.proxyKind, r.proxyAddr) : t("системный маршрут");
const pill = (s) => el("span", { class: "pill " + s.level }, icon(LEVEL_ICON[s.level] || "neutral"), s.label);
export async function compareRuns() {
  if (S.compareSel.length !== 2) return;
  const [a, b] = S.compareSel;
  try {
    const c = await apiJSON(`/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    c.rows = c.rows || []; c.notes = c.notes || []; c.onlyInA = c.onlyInA || []; c.onlyInB = c.onlyInB || [];
    const box = $("compare");
    const noName = t("без имени");
    const title = el("h3", { text: t("Сравнение: %s (%s) → %s (%s)", c.a.profileName || noName, fmtShort(c.a.startedAt), c.b.profileName || noName, fmtShort(c.b.startedAt)) });
    const notes = el("ul", { class: "note-list" },
      el("li", { text: t("Маршрут: %s → %s", routeText(c.a.route), routeText(c.b.route)) }),
      el("li", { text: t("Метрика: %s", c.metric) }),
      ...c.notes.map(n => el("li", { text: n })));
    const heads = [t("Точка"), t("Хост"), t("Было"), t("Стало"), t("Было, мс"), t("Стало, мс"), t("Δ, мс"), t("Δ, %"), t("Примечание")];
    const thead = el("thead", {}, el("tr", {}, ...heads.map(h => el("th", { text: h }))));
    const rows = c.rows.map(r => {
      const d = r.deltaMs;
      const dCls = d === null ? "" : d > 0 ? "delta up" : d < 0 ? "delta down" : "delta";
      return el("tr", {},
        el("td", { text: t(r.group) + " — " + t(r.label) }), el("td", { class: "mono", text: r.host }),
        el("td", {}, pill(r.before)),
        el("td", {}, pill(r.after)),
        el("td", { class: "num", text: fmtMs(r.beforeMs) }), el("td", { class: "num", text: fmtMs(r.afterMs) }),
        el("td", { class: "num " + dCls, text: d === null ? "—" : (d > 0 ? "+" : "") + fmtMs(d) }),
        el("td", { class: "num " + dCls, text: r.deltaPct === null ? "—" : (r.deltaPct > 0 ? "+" : "") + r.deltaPct.toFixed(1) }),
        el("td", { text: r.comparable ? (r.changed ? t("статус изменился") : "") : t("несопоставимо: %s", r.reason) }));
    });
    const extra = [];
    if (c.onlyInA.length) extra.push(el("div", { class: "hint", text: t("Только в первом запуске: %s", c.onlyInA.join(", ")) }));
    if (c.onlyInB.length) extra.push(el("div", { class: "hint", text: t("Только во втором запуске: %s", c.onlyInB.join(", ")) }));
    box.replaceChildren(title, notes, el("div", { class: "table-wrap" }, el("table", { class: "grid" }, thead, el("tbody", {}, ...rows))), ...extra,
      el("div", { class: "row compare-foot" }, el("button", { type: "button", class: "btn btn-small", onclick: () => { box.hidden = true; } }, t("Скрыть сравнение"))));
    box.hidden = false;
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) { toast(t("Сравнение не удалось: %s", e.message), true); }
}
