// A check run: summary tiles, run note and status line, service cards, group
// details, the diagnosis fold, and the start / stop / diagnose / report actions.
import { t, tp } from "./i18n.js";
import {
  $, el, ltr, icon, S, settings, registry, isRunning, speedActive, apiJSON, saveSettings, refreshState, toast, removeBanner, download, balloon, SPLIT_GROUPS,
  fmtMs, fmtMsUnit, fmtTime, fmtShort, routeLabel, routeShort, levelText, modeName, confName, statusName, stageName, statusClass,
  LEVEL_ICON, KIND_NAME,
} from "./core.js";
import { renderHeader, selectedIDs } from "./header.js";
import { backToCurrent } from "./history.js";
import { speedNote } from "./speed.js";

// ---------- derived data ----------
function latestResults(run) {
  const m = new Map();
  for (const r of run.results) {
    const prev = m.get(r.endpointId);
    if (!prev || r.attempt >= prev.attempt) m.set(r.endpointId, r);
  }
  return m;
}
function computeCounts(run, progress) {
  const c = { planned: progress ? progress.total : run.results.length, probed: 0, tlsOk: 0, httpsTotal: 0, httpMatch: 0, errors: 0, limited: 0, skipped: 0, median: null };
  const expected = new Map(run.endpoints.map(e => [e.id, e.expectedStatuses || []]));
  const lat = [];
  for (const r of run.results) {
    if (r.skipped || r.outcome.code === "cancelled") {
      c.skipped++;
      if (["hourly_cap", "rate_limited_429", "run_block_403", "run_block_captcha"].includes(r.outcome.code)) c.limited++;
      continue;
    }
    c.probed++;
    if (r.transport.ok) { c.tlsOk++; if (r.timings.tlsReadyMs !== null) lat.push(r.timings.tlsReadyMs); }
    if (r.kind === "https") {
      c.httpsTotal++;
      if (r.http) {
        if ((expected.get(r.endpointId) || []).includes(r.http.status)) c.httpMatch++;
        if (r.http.status === 429) c.limited++;
      }
    }
    if (r.outcome.level === "error") c.errors++;
  }
  if (lat.length) { lat.sort((a, b) => a - b); const mid = lat.length >> 1; c.median = lat.length % 2 ? lat[mid] : (lat[mid - 1] + lat[mid]) / 2; }
  return c;
}
function groupEndpoints(list) {
  const groups = new Map();
  for (const e of list) {
    if (!groups.has(e.groupId)) groups.set(e.groupId, { id: e.groupId, name: t(e.group), endpoints: [] });
    groups.get(e.groupId).endpoints.push(e);
  }
  return groups;
}
function cardsData() {
  const run = S.view && S.view.run;
  const prog = S.view && S.view.progress;
  const cards = [];
  if (!run) {
    for (const g of groupEndpoints(registry().filter(e => e.enabled)).values()) {
      cards.push({ id: g.id, name: g.name, level: "neutral", label: t("Не проверялось"), endpoints: g.endpoints, results: new Map(), median: null, checked: 0, active: [] });
    }
    return cards;
  }
  const latest = latestResults(run);
  const byGroup = new Map(S.view.groups.map(g => [g.groupId, g]));
  const active = new Map();
  for (const a of (prog && prog.active) || []) { if (!active.has(a.endpointId)) active.set(a.endpointId, a); }
  for (const g of groupEndpoints(run.endpoints).values()) {
    const sum = byGroup.get(g.id);
    const act = g.endpoints.filter(e => active.has(e.id)).map(e => active.get(e.id));
    const checked = g.endpoints.filter(e => latest.has(e.id)).length;
    let level = "neutral", label = t("В очереди");
    if (sum) { level = sum.level; label = sum.label; }
    if (!sum && act.length) { label = t("Проверяется…"); level = "running"; }
    if (!sum && !act.length && prog && prog.status !== "running") { label = t("Не проверено"); }
    cards.push({ id: g.id, name: g.name, level, label, endpoints: g.endpoints, results: latest, median: sum ? sum.medianTlsReadyMs : null, checked, active: act });
  }
  return cards;
}
function matchesFilter(card) {
  const f = S.filter;
  if (f === "problems" && !(card.level === "warn" || card.level === "error")) return false;
  if (f === "ok" && card.level !== "ok") return false;
  if (f === "unchecked" && !(card.level === "neutral" || card.level === "running")) return false;
  const q = S.search.trim().toLowerCase();
  if (!q) return true;
  if (card.name.toLowerCase().includes(q)) return true;
  return card.endpoints.some(e => e.host.toLowerCase().includes(q) || t(e.label || "").toLowerCase().includes(q));
}
export function verdictFor(groupId) {
  const run = S.view && S.view.run;
  return run && run.verdicts ? run.verdicts.find(v => v.groupId === groupId) : null;
}

// ---------- summary tiles ----------
const small = (text) => el("small", { text });
const fraction = (a, b) => ltr(a + " ", small("/ " + b));
const tile = (label, value, sub) => el("div", { class: "tile" }, el("div", { class: "t-label", text: label }), el("div", { class: "t-value" }, value), el("div", { class: "t-sub", text: sub }));

export function renderSummary() {
  const box = $("summary");
  const run = S.view && S.view.run;
  if (!run) {
    const enabled = registry().filter(e => e.enabled).length;
    box.replaceChildren(
      tile(t("Узлов проверено"), fraction(0, enabled), t("нажмите «Начать проверку»")),
      tile(t("TLS подтверждён"), "—", t("рукопожатие и сертификат")),
      tile(t("Ошибки / ограничения"), "—", t("транспорт / лимиты и 429")),
      tile(t("Медиана TLS готов"), "—", t("от старта пробы до проверки сертификата")),
      runTile(null));
    return;
  }
  const c = computeCounts(run, S.view.progress);
  box.replaceChildren(
    tile(t("Узлов проверено"), fraction(c.probed, c.planned), c.skipped ? t("%d пропущено или отменено", c.skipped) : (run.mode === "stability" ? t("проб, 3 на узел") : t("узлов в запуске"))),
    tile(t("TLS подтверждён"), fraction(c.tlsOk, c.probed), t("рукопожатие и сертификат")),
    tile(t("Ошибки / ограничения"), fraction(c.errors, c.limited), t("транспортные ошибки / лимиты и 429")),
    tile(t("Медиана TLS готов"), c.median === null ? "—" : [fmtMs(c.median) + " ", small(t("мс"))], t("от старта пробы до проверки сертификата")),
    runTile(run));
}
function runTile(run) {
  const tl = el("div", { class: "tile tile-run" }, el("div", { class: "t-label", text: t("Запуск") }));
  if (!run) { tl.append(el("div", { class: "t-value", text: "—" }), el("div", { class: "t-sub", text: t("ещё не запускалась") })); return tl; }
  const prog = S.view.progress || {};
  const st = prog.runId === run.id ? prog.status : run.status;
  tl.append(el("div", { class: "t-value t-status " + statusClass(st), text: statusName(st) }),
    el("div", { class: "t-sub" }, ltr(fmtShort(run.startedAt)), " · " + routeShort(run.route)));
  return tl;
}

// ---------- run note (one fixed line) and the status line in the run fold ----------
export function renderStatus() {
  const box = $("statusLine");
  const run = S.view && S.view.run;
  const speedLine = speedNote();
  $("foldRun").hidden = !run;
  if (!run) {
    box.replaceChildren();
    $("runNote").replaceChildren(...speedLine, el("span", {}, el("b", { text: t("Первый запуск.") }), " " + t("Подключите VPN, при необходимости выберите маршрут и нажмите «Начать проверку». При открытии никаких внешних запросов не выполняется.")));
    return;
  }
  const prog = S.view.progress || {};
  const st = prog.runId === run.id ? prog.status : run.status;
  const note = [];
  if (S.viewingHistory) note.push(el("span", {}, t("Просмотр запуска от %s из истории", fmtTime(run.startedAt)) + " · ", el("button", { type: "button", class: "btn-link", onclick: backToCurrent }, t("к текущему"))));
  if (st === "running") note.push(el("span", { class: "st" }, icon("spin", "spin"), " " + t("Идёт проверка: %d из %d", prog.done || 0, prog.total || 0)));
  const msg = run.message || prog.message;
  if (msg) note.push(el("span", { class: "st warn", text: msg }));
  const cnt = computeCounts(run, prog);
  if (st !== "running" && cnt.probed > 0 && run.results.every(r => r.skipped || !r.transport.ok && ["dns", "tcp"].includes(r.transport.failedStage)))
    note.unshift(el("span", { class: "st err", text: t("Все узлы завершились ошибкой на этапе DNS/TCP: похоже, сеть или выбранный маршрут недоступны.") }));
  if (!note.length) note.push(el("span", {}, statusName(st) + " · " + fmtTime(run.startedAt) + " · " + routeLabel(run.route)));
  $("runNote").replaceChildren(...speedLine, ...note);
  $("runSummary").textContent = statusName(st) + " · " + fmtTime(run.startedAt) + " · " + routeShort(run.route);

  const item = (label, value, cls) => el("span", {}, label + " ", el("span", { class: "st" + (cls ? " " + cls : ""), text: value }));
  const items = [];
  if (cnt.httpsTotal) items.push(item(t("HTTP по профилю:"), t("%d из %d https-точек", cnt.httpMatch, cnt.httpsTotal)));
  items.push(item(t("Профиль:"), run.profileName || "—"));
  items.push(item(t("Начало:"), fmtTime(run.startedAt)));
  items.push(item(t("Маршрут:"), run.route.mode === "proxy" ? t("прокси %s %s", run.route.proxyKind, run.route.proxyAddr) : t("системный маршрут")));
  if (run.altRoute) items.push(item(t("Альтернативный маршрут:"), routeLabel(run.altRoute)));
  items.push(item("IP:", run.ipFamily));
  let stText = statusName(st);
  if (st === "running") stText += ` ${prog.done || 0}/${prog.total || 0}`;
  items.push(item(t("Статус:"), stText, statusClass(st)));
  if (run.mode) items.push(item(t("Режим:"), modeName(run.mode)));
  if (run.systemProxyHint) items.push(item(t("Системный прокси во время запуска:"), run.systemProxyHint));
  const x = run.externalIp;
  if (x) {
    const unknown = t("не определён");
    let s = (x.before || unknown) + " → " + (x.after || unknown);
    if (x.country) s = t("%s, страна %s", s, x.country);
    if (x.error) s += "; " + x.error;
    if (x.afterCountry && x.afterCountry !== x.country) s += " → " + x.afterCountry;
    if (x.changed) s = t("%s — IP изменился во время запуска, условия менялись", s);
    items.push(item(t("Внешний IP (%s, запрос передан провайдеру):", x.provider), s, x.changed ? "warn" : ""));
  }
  if (x && x.comparison) {
    const labels = {
      same: t("IP совпадает"), different: t("IP изменился"), no_baseline: t("прошлого успешного запуска нет"),
      previous_ip_unknown: t("IP прошлого успешного запуска не записан или менялся"), current_ip_unknown: t("текущий IP определён не полностью"),
      changed_during_run: t("IP менялся во время проверки"), history_unavailable: t("история недоступна"),
    };
    const previous = x.previousAt ? "; " + fmtTime(x.previousAt) + ", " + (x.previousProfile || t("без названия")) + ", " + (x.previousIp || t("IP не определён")) + (x.previousCountry ? ", " + x.previousCountry : "") : "";
    items.push(el("span", { class: "st", text: t("Anthropic — последний успешный сетевой тест: %s%s. IP определён у контрольного провайдера; при раздельной маршрутизации выход к Anthropic может отличаться.", labels[x.comparison], previous) }));
  }
  if (run.message || prog.message) items.push(el("span", { class: "st warn", text: run.message || prog.message }));
  box.replaceChildren(...items);

  // The no-internet message lives in the fixed run note line, not in a banner, so nothing above the cards moves.
  removeBanner("noinet");
}

// ---------- service cards ----------
export function renderCards() {
  const cards = cardsData();
  const run = S.view && S.view.run;
  const nodes = [];
  for (const c of cards) {
    if (!matchesFilter(c)) continue;
    // The "Russia direct" card shows the split-routing conclusion, not only reachability.
    const split = SPLIT_GROUPS.includes(c.id) && run && !isRunning() ? verdictFor(c.id) : null;
    const lvl = split ? split.level : c.level;
    const problem = lvl === "warn" || lvl === "error";
    const vd = run && !isRunning() && problem ? verdictFor(c.id) : null;
    const count = (c.label.match(/^\d+\/\d+/) || [""])[0];
    let text = c.label;
    if (!run) text = tp(c.endpoints.length, "%d узел", "%d узла", "%d узлов");
    else if (c.active.length) text = t("Сейчас: %s", c.active.map(a => `${a.host} (${stageName(a.stage || "") || a.stage})`).join(", "));
    else if (split) text = split.title;
    else if (vd) text = (count ? count + " · " : "") + vd.title;
    else if (lvl === "ok") text = t("%s доступны", count || "");
    const lat = c.median === null ? "" : t("%s мс", fmtMs(c.median));
    nodes.push(el("button", {
      type: "button", class: "card " + lvl, "aria-expanded": String(S.expanded === c.id), dataset: { group: c.id },
      title: [levelText(lvl), c.label, lat ? t("медиана времени до готовности TLS %s", lat) : ""].filter(Boolean).join(" · "),
      onclick: () => { S.expanded = S.expanded === c.id ? null : c.id; renderCards(); renderDetails(); },
    },
      el("div", { class: "card-title" }, icon(LEVEL_ICON[lvl] || "neutral", lvl === "running" ? "spin" : ""), el("span", { class: "card-name", text: c.name }), el("span", { class: "card-lat", text: lat })),
      el("div", { class: "card-status" }, ...(split ? splitFlag(splitOf(run, c.id)) : []), text)));
  }
  if (!nodes.length && cards.length) nodes.push(el("div", { class: "hint", text: t("Ничего не найдено по текущему фильтру.") }));
  $("cards").replaceChildren(...nodes);
}

// ---------- group details ----------
function verdictBox(vd, title) {
  const vb = el("div", { class: "verdict " + vd.level },
    el("div", { class: "v-title" }, icon(LEVEL_ICON[vd.level] || "neutral"), el("span", { text: title }), el("span", { class: "conf", text: confName(vd.confidence) || "" })),
    el("div", { class: "v-text", text: vd.explanation }));
  if (vd.advice) vb.append(el("div", { class: "v-advice", text: t("Что делать: %s", vd.advice) }));
  return vb;
}
export function renderDetails() {
  const box = $("details");
  const c = cardsData().find(x => x.id === S.expanded);
  if (!c) { box.hidden = true; box.replaceChildren(); return; }
  box.hidden = false;
  const run = S.view && S.view.run;
  const proxyMode = run && run.route.mode === "proxy";
  const canDiag = run && !isRunning() && (c.level === "warn" || c.level === "error");
  const head = el("div", { class: "details-head" }, el("h3", { text: c.name }), el("span", { class: "hint", text: c.label }), el("div", { class: "grow" }),
    canDiag ? el("button", { type: "button", class: "btn btn-small", title: t("Проверить узлы группы по выбранному и альтернативному маршруту и получить вердикт"), onclick: () => diagnose(c.id) }, t("Диагностика по двум маршрутам")) : "",
    el("button", { type: "button", class: "btn btn-icon", "aria-label": t("Свернуть"), onclick: () => { S.expanded = null; renderCards(); renderDetails(); } }, icon("close")));
  const cols = [t("Адрес"), t("Роль"), t("Проба"), t("DNS, мс"), t("TCP, мс"), t("Прокси, мс"), t("TLS, мс"), t("TTFB, мс"), "HTTP", "IP", t("Итог")];
  const thead = el("thead", {}, el("tr", {}, ...cols.map((h, i) => el("th", { class: i >= 3 && i <= 7 ? "num" : "", text: h }))));
  const rows = [];
  const stab = S.view && S.view.stability;
  for (const ep of c.endpoints) {
    const list = run ? run.results.filter(r => r.endpointId === ep.id).sort((a, b) => a.attempt - b.attempt) : [];
    if (!list.length) {
      rows.push(el("tr", {}, el("td", { class: "mono", text: ep.host }), el("td", { text: t(ep.label || "") }), el("td", { text: KIND_NAME[ep.kind] }),
        ...["—", "—", "—", "—", "—"].map(v => el("td", { class: "num", text: v })), el("td", { text: "—" }), el("td", { text: "—" }),
        el("td", {}, el("span", { class: "pill neutral" }, icon("queue"), run && isRunning() ? t("в очереди") : t("не проверено")))));
      continue;
    }
    const showAll = run.mode === "stability" || run.mode === "diag";
    for (const r of (showAll ? list : [list[list.length - 1]])) rows.push(resultRow(ep, r, showAll, r.route && r.route.mode === "proxy", run.mode === "diag"));
    if (showAll && stab && stab[ep.id]) {
      const s = stab[ep.id];
      rows.push(el("tr", { class: "explain" }, el("td", { colspan: cols.length },
        t("Стабильность (%s): проб %v, успешных %v; min %s, медиана %s, max %s, размах %s мс", s.metric, s.n, s.success, fmtMs(s.minMs), fmtMs(s.medianMs), fmtMs(s.maxMs), fmtMs(s.spreadMs)),
        s.smallSample ? " · " + t("малая выборка") : "", " · " + t("доля неудачных проб — не потеря пакетов, размах — не сетевой jitter."))));
    }
  }
  const vd = verdictFor(c.id);
  const sp = run ? splitOf(run, c.id) : null;
  box.replaceChildren(head, ...(sp ? [splitBox(sp)] : []), ...(vd && (vd.level !== "ok" || sp) ? [verdictBox(vd, vd.title)] : []),
    el("div", { class: "table-wrap" }, el("table", { class: "grid" }, thead, el("tbody", {}, ...rows))),
    el("div", { class: "hint", text: t("Значения «—» означают «не измерено». Доступность узла не гарантирует полноценную работу приложения.") + (proxyMode ? " " + t("В режиме прокси DNS и семейство IP конечного сервера не наблюдаются («не измерено через прокси»).") : "") }));
}
// The split-routing check of a group; 4.3 runs kept the Russian one in run.split.
function splitOf(run, gid) {
  if (!SPLIT_GROUPS.includes(gid)) return null;
  return (run.splits || []).find(x => x.group === gid) || (gid === "ru-direct" ? run.split || null : null);
}
// The flag of the country home sites go through (RU when they go direct).
function splitFlag(sp) {
  const cc = sp && sp.domesticCountry;
  if (!cc || !window.flagSVG) return [];
  return [el("span", { class: "ip-flag card-flag", title: cc, html: window.flagSVG(cc) })];
}
function splitBox(sp) {
  const row = (label, ip, cc, extra) => el("div", { class: "split-row" },
    el("span", { class: "split-label", text: label }),
    el("span", { class: "split-ip" },
      cc ? el("span", { class: "ip-flag", html: window.flagSVG ? window.flagSVG(cc) : "" }) : "",
      el("span", { class: "mono", dir: "ltr", text: ip || t("не определён") }),
      cc ? el("span", { class: "hint", text: cc }) : "",
      extra ? el("span", { class: "hint", text: extra }) : ""));
  const vpnFlag = sp.domesticVpn === true ? t("Яндекс: VPN или хостинг") : sp.domesticVpn === false ? t("Яндекс: не VPN") : "";
  return el("div", { class: "split" },
    row(t("Местный сайт (%s) видит", t(sp.source)), sp.domesticIp, sp.domesticCountry, vpnFlag),
    row(t("Зарубежный узел (Cloudflare) видит"), sp.foreignIp, sp.foreignCountry, ""),
    el("div", { class: "hint", text: t("Программа только наблюдает: маршруты, прокси и правила клиента VPN она не меняет, поэтому проверка не может отключить VPN.") }));
}
function resultRow(ep, r, showAttempt, proxyMode, diagMode) {
  const tm = r.timings, h = r.http, tr = r.transport;
  const lvl = r.outcome.level;
  const attemptText = " · " + (diagMode ? routeLabel(r.route) : t("проба %v", r.attempt));
  const httpText = h ? String(h.status) + (h.proto === "HTTP/2.0" ? " h2" : "") : "—";
  let ipText = "—";
  if (tr.peerFamily) ipText = tr.peerFamily.toUpperCase() + (tr.familyProven ? "" : " " + t("(прокси)"));
  else if (proxyMode) ipText = t("не измерено через прокси");
  const cells = [
    el("td", { class: "mono", text: (r.url || r.host) + (showAttempt ? attemptText : "") }),
    el("td", { text: t(ep.label || "") }),
    el("td", { text: KIND_NAME[r.kind] || r.kind }),
    el("td", { class: "num", text: proxyMode && tm.dnsMs === null ? "—" : fmtMs(tm.dnsMs) }),
    el("td", { class: "num", text: fmtMs(tm.tcpMs) }),
    el("td", { class: "num", text: fmtMs(tm.proxyMs) }),
    el("td", { class: "num", text: fmtMs(tm.tlsMs) }),
    el("td", { class: "num", text: fmtMs(tm.ttfbMs) }),
    el("td", { text: httpText }),
    el("td", { text: ipText }),
    el("td", {}, el("span", { class: "pill " + lvl }, icon(LEVEL_ICON[lvl] || "neutral"), r.outcome.label)),
  ];
  const row = el("tr", { class: "row-click", tabindex: "0", role: "button", "aria-expanded": "false" }, ...cells);
  const explain = el("tr", { class: "explain", hidden: true }, el("td", { colspan: cells.length }));
  const fill = () => {
    const parts = [el("div", {}, el("b", { text: r.outcome.label }))];
    if (r.outcome.detail) parts.push(el("div", { text: t("Пояснение: %s", r.outcome.detail) }));
    if (!tr.ok && !r.skipped) parts.push(el("div", { text: t("Этап сбоя: %s · тип: %s · техническая причина: %s", stageName(tr.failedStage) || tr.failedStage || "—", tr.errorKind || "—", tr.errorText || "—") }));
    if (r.skipped) parts.push(el("div", { text: t("Причина пропуска: %s", r.skipReason || "—") }));
    const tech = [t("старт %s", fmtTime(r.startedAt)), t("всего %s", fmtMsUnit(tm.totalMs)), t("TLS готов %s", fmtMsUnit(tm.tlsReadyMs))];
    if (tr.peerAddr) tech.push(tr.familyProven ? "peer " + tr.peerAddr : t("peer %s (это прокси, не конечный сервер)", tr.peerAddr));
    if (tr.resolvedAddrs && tr.resolvedAddrs.length) tech.push("DNS: " + tr.resolvedAddrs.join(", "));
    if (tr.tlsVersion) tech.push(tr.tlsVersion + (tr.alpn ? " / " + tr.alpn : ""));
    if (tr.certVerified) tech.push(t("сертификат: %s от %s до %s", tr.certSubject || "?", tr.certIssuer || "?", tr.certNotAfter ? fmtTime(tr.certNotAfter) : "?"));
    if (h) {
      tech.push(`HTTP ${h.status} ${h.proto || ""}`);
      if (h.location) tech.push("Location: " + h.location);
      if (h.server) tech.push("Server: " + h.server);
      if (h.contentType) tech.push("Content-Type: " + h.contentType);
      tech.push(t("прочитано %v байт", h.bytesRead) + (h.bodyLimited ? " " + t("(тело ограничено лимитом; это не время полной загрузки)") : ""));
      if (h.bodyError) tech.push(t("тело: %s", h.bodyError));
      if (h.retryAfter) tech.push("Retry-After: " + h.retryAfter);
      if (h.rateLimitReset) tech.push(t("повтор после %s", fmtTime(h.rateLimitReset)));
      if (h.captcha) tech.push(t("обнаружены признаки CAPTCHA/challenge"));
      if (h.geoBlocked) tech.push(t("гео-ограничение: %s", h.geoSignature));
      if (h.bodySnippet) tech.push(t("фрагмент ответа: %s", h.bodySnippet));
    }
    tech.push(t("маршрут %s, семейство %s, профиль v%v", r.route.mode + (r.route.proxyAddr ? " " + r.route.proxyKind + " " + r.route.proxyAddr : ""), r.ipFamily, r.profileVersion));
    parts.push(el("div", { class: "mono", text: tech.join(" · ") }));
    if (ep.note) parts.push(el("div", { text: t("Примечание к точке: %s", t(ep.note)) }));
    explain.firstChild.replaceChildren(...parts);
  };
  const toggle = () => { const open = explain.hidden; if (open) fill(); explain.hidden = !open; row.setAttribute("aria-expanded", String(open)); };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  const frag = document.createDocumentFragment();
  frag.append(row, explain);
  return frag;
}

// ---------- diagnosis fold ----------
export function renderVerdicts() {
  const box = $("verdicts");
  const run = S.view && S.view.run;
  const vs = run && run.verdicts;
  const fold = $("foldVerdicts");
  if (!vs || !vs.length) { fold.hidden = true; box.replaceChildren(); return; }
  const rank = { error: 0, warn: 1, neutral: 2, ok: 3 };
  const sorted = [...vs].sort((a, b) => (rank[a.level] ?? 9) - (rank[b.level] ?? 9));
  const problems = sorted.filter(v => v.level === "error" || v.level === "warn");
  $("verdictsSummary").textContent = (run.mode === "diag" ? t("по двум маршрутам") + " · " : "")
    + (problems.length ? t("%s с проблемами — причины и что делать", tp(problems.length, "%d группа", "%d группы", "%d групп")) : t("проблем не найдено"));
  if (run.mode === "diag" && S.diagOpenedFor !== run.id) { S.diagOpenedFor = run.id; fold.open = true; }
  const nodes = [el("div", { class: "hint", text: t("Вердикты — эвристики без захвата пакетов; у каждого указана уверенность.") })];
  const showAll = run.mode === "diag" || problems.length === 0;
  const visible = showAll ? sorted : sorted.filter(v => v.level === "error" || v.level === "warn" || v.groupId === "anthropic" || SPLIT_GROUPS.includes(v.groupId));
  for (const v of visible.slice(0, 14)) {
    const card = verdictBox(v, t(v.group) + ": " + v.title);
    if (v.evidence && v.evidence.length) card.append(el("ul", {}, ...v.evidence.map(e => el("li", { text: e }))));
    if (v.level !== "ok" && !isRunning()) card.append(el("div", { class: "card-actions" }, el("button", { type: "button", class: "btn btn-small btn-diag", onclick: () => diagnose(v.groupId) }, run.mode === "diag" ? t("Повторить диагностику") : t("Диагностика по двум маршрутам"))));
    nodes.push(card);
  }
  if (!showAll && sorted.length > visible.length) nodes.push(el("div", { class: "hint", text: t("Остальные %d групп: см. результаты проб.", sorted.length - visible.length) }));
  box.replaceChildren(...nodes);
  fold.hidden = false;
}

// ---------- actions ----------
export async function startRun() {
  const s = settings();
  const ids = s.mode === "stability" ? (s.stabilityEndpoints || []) : selectedIDs();
  if (!ids.length) { toast(t("Выберите хотя бы один узел"), true); return; }
  $("btnStart").disabled = true;
  try {
    await saveSettings(true);
    await apiJSON("/api/run", { method: "POST", body: { profileName: s.profileName || "", mode: s.mode, route: s.route, ipFamily: s.ipFamily, endpointIds: ids, showExternalIp: !!s.showExternalIp, slowThresholdMs: s.slowThresholdMs } });
    S.viewingHistory = false; S.expanded = null;
  } catch (e) {
    if (e.code === "cooldown" && e.until) { S.state.limiter.cooldownUntil = e.until; }
    toast(e.message, true);
    await refreshState().catch(() => {});
    renderHeader();
  }
}
export async function stopRun() {
  $("btnStop").disabled = true;
  const speed = speedActive();
  try {
    await apiJSON(speed ? "/api/speed/cancel" : "/api/run/cancel", { method: "POST" });
    toast(speed ? t("Замер скорости останавливается") : t("Остановка: активные пробы завершаются, новые не запускаются"));
  } catch (e) { toast(e.message, true); }
  finally { $("btnStop").disabled = false; }
}
async function diagnose(groupId) {
  const s = settings();
  try {
    await saveSettings(true);
    const r = await apiJSON("/api/diagnose", { method: "POST", body: { profileName: s.profileName || "", route: s.route, groupId, showExternalIp: !!s.showExternalIp, slowThresholdMs: s.slowThresholdMs } });
    S.viewingHistory = false; S.expanded = groupId;
    toast(t("Диагностика: узлы группы проверяются по маршруту «%s» и по альтернативному «%s»", routeLabel(s.route), routeLabel(r.altRoute)));
  } catch (e) {
    if (e.code === "cooldown" && e.until) S.state.limiter.cooldownUntil = e.until;
    toast(e.message, true); renderHeader();
  }
}
export async function saveReport(ev) {
  const run = S.view && S.view.run;
  if (!run) return;
  const answer = await balloon(ev.currentTarget, {
    title: t("Включить в отчёт внешний IP, адреса прокси и локальные адреса адаптеров?"),
    note: t("С ними отчёт подробнее для диагностики. Без них его безопаснее передавать другим."),
    ok: t("Включить"), alt: t("Скрыть"), cancel: t("Отмена"),
  });
  if (!answer.ok) return;
  const sensitive = !answer.alt;
  download(`/api/report/${encodeURIComponent(run.id)}/json${sensitive ? "?sensitive=1" : ""}`);
  toast(sensitive
    ? t("Отчёт сохраняется с подробными сетевыми данными. Файл можно передать администратору или загрузить в LLM для анализа.")
    : t("Отчёт сохраняется без чувствительных данных. Файл можно передать администратору или загрузить в LLM для анализа."));
}
