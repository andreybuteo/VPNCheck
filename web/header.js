// Header (route badge, start / speed / stop buttons, theme, language),
// warning banners, the environment passport and the "what to check" fold.
import { t, languageList, effectiveLang } from "./i18n.js";
import {
  $, el, icon, S, settings, registry, isRunning, speedActive, apiJSON, saveSettings, toast, banner, removeBanner,
  routeLabel, proxyKindName, confName,
} from "./core.js";
import { updateSpeedButton } from "./speed.js";
import { renderDrawer } from "./drawer.js";

// ---------- header ----------
export function renderHeader() {
  $("appVersion").textContent = "v" + S.state.app.version;
  document.title = "VPN Check " + S.state.app.version;
  const s = settings();
  if (document.activeElement !== $("profileName")) $("profileName").value = s.profileName || "";
  const running = isRunning();
  const run = S.state.current.run;
  const route = running && run ? run.route : s.route;
  const badge = $("routeBadge");
  const sp = S.state.sysproxy;
  let text = route.mode === "proxy" ? t("Прокси %s %s", proxyKindName(route.proxyKind), route.proxyAddr) : t("Системный маршрут / TUN");
  if (running) text = t("Применён: %s", text);
  let warn = false, title = t("Открыть настройки маршрута");
  if (route.mode === "system" && sp && sp.found && (sp.enabled || Object.keys(sp.env || {}).length)) {
    warn = true;
    title = t("Обнаружен системный прокси (%s). Браузер может ходить через него, а программа в этом режиме идёт напрямую по маршрутизации Windows: пути могут различаться.", sp.sources.join(", "));
    text = t("%s · системный прокси обнаружен", text);
  }
  badge.className = "route-badge" + (warn ? " warn" : "");
  badge.title = title;
  badge.replaceChildren(el("span", { class: "dot" }), el("span", { id: "routeText", text }));

  const speeding = speedActive();
  $("btnStop").hidden = !(running || speeding);
  $("btnStart").hidden = running;
  $("btnSpeed").hidden = speeding;
  // "Stop" takes the place of the button that started the work, so nothing shifts.
  if (speeding) $("btnSpeed").after($("btnStop")); else $("btnStart").after($("btnStop"));
  $("btnReport").disabled = !(S.view && S.view.run) || S.quitting;
  updateStartButton();
  updateSpeedButton();
  $("btnQuit").disabled = false;

  if (S.state.app.demo) banner("warn", t("ДЕМО-РЕЖИМ для проверки интерфейса: результаты подставные, сетевые запросы не выполняются, данные хранятся в отдельном каталоге."), "demo");
  const warnings = S.state.warnings || [];
  for (const old of $("banners").querySelectorAll('[data-key^="warn"]')) {
    if (Number(old.dataset.key.slice(4)) >= warnings.length) old.remove();
  }
  for (const [i, w] of warnings.entries()) banner("warn", w, "warn" + i);
  if (sp && sp.found && sp.pac) banner("info", t("Обнаружен PAC/автоконфигурация прокси: в этой версии не поддерживается, укажите прокси вручную."), "pac");
  else removeBanner("pac");
}

export function updateStartButton() {
  const btn = $("btnStart");
  clearInterval(S.countdown);
  const until = S.state.limiter.cooldownUntil ? new Date(S.state.limiter.cooldownUntil) : null;
  const stability = settings().mode === "stability";
  const selEmpty = stability ? (settings().stabilityEndpoints || []).length === 0 : selectedIDs().length === 0;
  const hint = $("startHint");
  const tick = () => {
    const left = until ? Math.ceil((until - Date.now()) / 1000) : 0;
    if (left > 0) {
      btn.disabled = true;
      btn.textContent = t("Пауза %d с", left);
      btn.title = t("Пауза %v с от начала предыдущего запуска (меняется в настройках)", S.state.limits.cooldownSec);
      hint.hidden = true;
      return;
    }
    clearInterval(S.countdown);
    btn.textContent = t("Начать проверку");
    const why = !selEmpty ? "" : stability
      ? t("Для «Стабильности» отметьте от 1 до 5 узлов в разделе «Что проверять»")
      : t("Выберите хотя бы одну группу в разделе «Что проверять»");
    btn.title = why;
    hint.textContent = why; hint.hidden = !why;
    if (why) $("foldSelect").open = true;
    btn.disabled = selEmpty || S.quitting || speedActive();
    if (speedActive()) btn.title = t("Идёт замер скорости: проверка сервисов запустится после него");
  };
  tick();
  if (until && until > Date.now()) S.countdown = setInterval(tick, 1000);
}

export function applyTheme() {
  const theme = settings().theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem("vpncheck.theme", theme); } catch {}
  const btn = $("btnTheme");
  btn.replaceChildren(icon(theme === "dark" ? "sun" : "moon"));
  btn.title = theme === "dark" ? t("Светлая тема") : t("Тёмная тема");
}

// Language menu: "Auto" plus the languages under their own names.
// "Auto · Русский": shows which language Auto resolved to.
function autoLabel() {
  const code = effectiveLang("", S.state && S.state.app && S.state.app.systemLang);
  const l = languageList().find(x => x.code === code);
  return t("Авто") + (l ? " · " + l.name : "");
}
export function renderLangSelect() {
  const sel = $("langSelect");
  sel.replaceChildren(
    el("option", { value: "", text: autoLabel() }),
    ...languageList().map(l => el("option", { value: l.code, text: l.name, lang: l.code, dir: l.rtl ? "rtl" : null })));
  sel.value = (S.state && settings().language) || "";
}

// ---------- "what to check" ----------
export function selectedIDs() {
  const enabled = new Set(registry().filter(e => e.enabled).map(e => e.id));
  return (settings().selectedEndpoints || []).filter(id => enabled.has(id));
}
export function renderControls() {
  const s = settings();
  for (const b of $("modeSwitch").querySelectorAll("button")) b.setAttribute("aria-checked", String(b.dataset.mode === s.mode));
  $("selectFast").hidden = s.mode !== "fast";
  $("selectStability").hidden = s.mode !== "stability";
  for (const b of $("filterSwitch").querySelectorAll("button")) b.setAttribute("aria-checked", String(b.dataset.filter === S.filter));

  // group chips
  const sel = new Set(selectedIDs());
  const groups = new Map();
  for (const e of registry()) {
    if (!e.enabled) continue;
    if (!groups.has(e.groupId)) groups.set(e.groupId, { id: e.groupId, name: t(e.group), ids: [] });
    groups.get(e.groupId).ids.push(e.id);
  }
  const chips = [];
  for (const g of groups.values()) {
    const n = g.ids.filter(id => sel.has(id)).length;
    chips.push(el("button", {
      type: "button", class: "chip", "aria-pressed": String(n > 0), title: n > 0 ? t("Исключить группу") : t("Включить группу"),
      onclick: () => {
        const cur = new Set(selectedIDs());
        if (n > 0) g.ids.forEach(id => cur.delete(id)); else g.ids.forEach(id => cur.add(id));
        s.selectedEndpoints = [...cur]; saveSettings(); renderControls(); updateStartButton();
      },
    }, g.name, el("span", { class: "cnt", text: `${n}/${g.ids.length}` })));
  }
  if (chips.length) {
    const all = [...groups.values()].every(g => g.ids.every(id => sel.has(id)));
    chips.push(el("button", { type: "button", class: "btn-link", onclick: () => {
      s.selectedEndpoints = all ? [] : registry().filter(e => e.enabled).map(e => e.id);
      saveSettings(); renderControls(); updateStartButton();
    } }, all ? t("Снять все") : t("Выбрать все")));
  }
  $("selectFast").replaceChildren(...chips);
  const total = [...groups.values()];
  const selGroups = total.filter(g => g.ids.some(id => sel.has(id))).length;
  $("selectSummary").textContent = s.mode === "stability"
    ? t("Стабильность · узлов %d из %v", (s.stabilityEndpoints || []).length, S.state.limits.stabilityMax)
    : t("Быстрая · %s, узлов %d", selGroups === total.length ? t("все группы") : t("групп %d из %d", selGroups, total.length), sel.size);

  // stability checkboxes (at most stabilityMax)
  const max = S.state.limits.stabilityMax;
  const enabledIDs = new Set(registry().filter(e => e.enabled).map(e => e.id));
  s.stabilityEndpoints = (s.stabilityEndpoints || []).filter(id => enabledIDs.has(id));
  const chosen = new Set(s.stabilityEndpoints);
  $("stabilityCount").textContent = t("Узлы: выбрано %d из %v", chosen.size, max);
  const full = chosen.size >= max;
  $("stabilityList").replaceChildren(...registry().filter(e => e.enabled).map(e => {
    const on = chosen.has(e.id);
    const cb = el("input", { type: "checkbox", checked: on, disabled: !on && full, onchange: () => {
      if (cb.checked) chosen.add(e.id); else chosen.delete(e.id);
      s.stabilityEndpoints = [...chosen]; saveSettings(); renderControls(); updateStartButton();
    } });
    return el("label", { class: !on && full ? "off" : "", title: e.host + " (" + e.kind + ")" }, cb, t(e.group) + " — " + (e.label ? t(e.label) : e.host));
  }));
}

// ---------- environment passport ----------
export function renderEnv() {
  const box = $("envBox");
  const env = S.state.environment;
  if (!env || !env.verdict) { box.replaceChildren(); return; }
  const v = env.verdict;
  const warn = v.mode === "proxy" || v.mode === "client-no-proxy" || v.mode === "unknown";
  const card = el("div", { class: "envcard" + (warn ? " warn" : "") });
  const line = el("div", { class: "env-line" }, icon(warn ? "warn" : "info"), el("span", { class: "env-title", text: v.title }));
  const cur = settings().route;
  const sug = v.suggestedRoute;
  if (sug && (sug.mode !== cur.mode || (sug.proxyAddr || "") !== (cur.proxyAddr || ""))) {
    line.append(el("button", { type: "button", class: "btn btn-small btn-primary", onclick: () => {
      settings().route = Object.assign({}, sug); saveSettings(true); renderHeader(); renderEnv(); renderDrawer();
      toast(t("Маршрут применён: %s", routeLabel(sug)));
    } }, t("Применить маршрут: %s", routeLabel(sug))));
  } else if (sug) {
    line.append(el("span", { class: "hint", text: t("маршрут выбран верно") }));
  }
  card.append(line);
  const det = el("details", { class: "env-more" }, el("summary", { text: t("подробнее") }));
  det.open = !!S.envOpen;
  det.addEventListener("toggle", () => { S.envOpen = det.open; });
  det.append(el("div", { class: "env-text", text: t("%s (уверенность: %s)", v.text, confName(v.confidence) || v.confidence) }));
  const split = splitTunnelNote(env);
  if (split) det.append(el("div", { class: "env-text", text: split }));
  det.append(el("button", { type: "button", class: "btn-link", onclick: async () => {
    try { const e = await apiJSON("/api/environment"); S.state.environment = e.environment; renderEnv(); renderHeader(); toast(t("Окружение обновлено")); }
    catch (err) { toast(err.message, true); }
  } }, t("Обновить сведения об окружении")));

  const dr = env.defaultRoute;
  const none = t("не обнаружены");
  const rows = [];
  rows.push([t("Маршрут по умолчанию"), dr.known
    ? (dr.viaTunnel ? t("%s — %s (туннель), шлюз %s", dr.ifName, dr.ifDescription, dr.nextHop) : t("%s — %s, шлюз %s", dr.ifName, dr.ifDescription, dr.nextHop))
    : t("не определён %s", dr.note || "")]);
  rows.push([t("VPN-клиенты"), env.vpnClients.length ? env.vpnClients.map(c => c.listening.length
    ? t("%s (%s, pid %v, порты %s)", c.name, c.process, c.pid, c.listening.map(l => l.port + (l.guess ? "/" + l.guess : "")).join(", "))
    : t("%s (%s, pid %v)", c.name, c.process, c.pid)).join("; ") : none]);
  rows.push([t("Локальные прокси"), env.localProxyListeners.length
    ? env.localProxyListeners.map(l => `${l.addr}:${l.port} ${l.guess || ""} (${l.process || "pid " + l.pid})`).join("; ") : none]);
  const px = env.proxies;
  rows.push([t("Прокси Windows / переменные"), px.found
    ? ((px.server ? (px.enabled ? "WinINET " + px.server : t("WinINET %s (выкл.)", px.server)) + "; " : "")
      + Object.entries(px.env || {}).map(([k, v2]) => `${k}=${v2}`).join("; ") + (px.pac ? "; PAC " + px.pac : ""))
    : t("не заданы")]);
  const ups = env.adapters.filter(a => a.up);
  rows.push([t("Активные адаптеры"), ups.length ? ups.map(a => {
    const ip = a.ipv4.join(", ") || "—", dns = a.dns.filter(d => !d.startsWith("fec0")).join(", ") || "—";
    return a.tunLike ? t("%s (%s) [туннель]: %s; DNS %s", a.name, a.description, ip, dns) : `${a.name} (${a.description}): ${ip}; DNS ${dns}`;
  }).join(" · ") : "—"]);
  rows.push([t("ОС"), env.os]);
  if (env.errors && env.errors.length) rows.push([t("Ошибки сбора"), env.errors.join("; ")]);
  det.append(el("div", { class: "table-wrap" }, el("table", { class: "grid" }, el("tbody", {},
    ...rows.map(([k, v2]) => el("tr", {}, el("td", { text: k }), el("td", { class: "wrap", text: v2 })))))));
  line.append(det);
  box.replaceChildren(card);
}
function splitTunnelNote(env) {
  const s = env.adapters.filter(a => a.tunLike && a.up && (a.ipv4.length || a.ipv6.length) && a.index !== env.defaultRoute.ifIndex);
  if (!s.length) return "";
  return t("Есть активный туннельный адаптер без маршрута по умолчанию (split tunneling): %s. Через него идёт только часть трафика.",
    s.map(a => `${a.name} (${a.description}, ${a.ipv4.join(", ")})`).join("; "));
}

