// Settings drawer: route, check options, speed server, the endpoint registry
// with custom endpoints, help, and quitting the application.
import { t } from "./i18n.js";
import { $, el, S, settings, registry, apiJSON, saveSettings, refreshState, toast, banner, disableAll, download, proxyKindName } from "./core.js";
import { renderHeader, renderControls, updateStartButton } from "./header.js";
import { renderCards } from "./run.js";
import { renderSpeed, renderSpeedSettings } from "./speed.js";
import { renderAll } from "./app.js";

export function renderDrawer() {
  const s = settings();
  for (const r of document.querySelectorAll('input[name="routeMode"]')) r.checked = r.value === s.route.mode;
  $("proxyFields").hidden = s.route.mode !== "proxy";
  $("proxyKind").value = s.route.proxyKind || "http";
  if (document.activeElement !== $("proxyAddr")) $("proxyAddr").value = s.route.proxyAddr || "";
  $("ipFamily").value = s.ipFamily || "auto";
  $("ipFamily").disabled = s.route.mode === "proxy";
  $("slowThreshold").value = s.slowThresholdMs;
  const lim = S.state.limits;
  $("runCooldown").min = lim.cooldownMinSec; $("runCooldown").max = lim.cooldownMaxSec;
  if (document.activeElement !== $("runCooldown")) $("runCooldown").value = s.runCooldownSec || lim.cooldownSec;
  $("showExternalIp").checked = !!s.showExternalIp;
  $("ipLogOn").checked = !s.ipLogOff;
  const p = S.state.externalIpProvider;
  $("externalIpHint").textContent = t("Для Anthropic сбор IP включён автоматически. Для остальных групп — по флажку. Запрос к %s (%s) в начале и конце через выбранный маршрут; провайдер видит адрес выхода. ASN не определяется. В экспорте IP скрыт по умолчанию.", p.name, p.url);
  $("versionNote").textContent = t("Версия программы: %s. Правило нумерации: большое изменение +1.0, остальные +0.1.", S.state.app.version);
  $("dataDirNote").textContent = t("Данные: %s (%s). Запись атомарная; повреждённый файл переносится в копию .corrupt-*, история при этом не теряется.",
    S.state.app.dataDir, "settings.json, registry.json, limiter.json, history\\");
  renderSpeedSettings();
  renderSysProxy();
  renderRegistry();
}

function renderSysProxy() {
  const box = $("sysproxyBox");
  const sp = S.state.sysproxy;
  if (!sp || !sp.found) { box.replaceChildren(el("span", { text: t("Системный прокси Windows и переменные окружения не обнаружены.") })); return; }
  const parts = [el("div", {}, el("b", { text: t("Обнаружено в системе (только подсказка):") + " " }), sp.sources.join("; "))];
  if (sp.server) parts.push(el("div", { text: sp.enabled ? t("WinINET: %s (включён)", sp.server) : t("WinINET: %s (выключен)", sp.server) }));
  if (sp.pac) parts.push(el("div", { text: "PAC: " + sp.pac }));
  for (const [k, v] of Object.entries(sp.env || {})) parts.push(el("div", { class: "mono", text: `${k}=${v}` }));
  for (const n of sp.notes || []) parts.push(el("div", { text: n }));
  if (sp.suggested) {
    parts.push(el("div", { class: "row" }, el("button", { type: "button", class: "btn btn-small", onclick: () => {
      settings().route = Object.assign({}, sp.suggested); saveSettings(true); renderDrawer(); renderHeader(); toast(t("Прокси из системных настроек применён"));
    } }, t("Применить %s %s", proxyKindName(sp.suggested.proxyKind), sp.suggested.proxyAddr))));
  }
  box.replaceChildren(...parts);
}

function registryChanged(endpoints) {
  S.state.registry.endpoints = endpoints;
  renderControls(); renderRegistry(); renderCards(); updateStartButton();
}
function renderRegistry() {
  const groups = new Map();
  for (const e of registry()) {
    if (!groups.has(e.groupId)) groups.set(e.groupId, { name: t(e.group), list: [] });
    groups.get(e.groupId).list.push(e);
  }
  const nodes = [];
  for (const g of groups.values()) {
    nodes.push(el("div", { class: "rg", text: g.name }));
    for (const e of g.list) {
      const row = el("div", { class: "re" },
        el("input", { type: "checkbox", checked: e.enabled, "aria-label": t("Включить %s", e.host), onchange: async (ev) => {
          try { const r = await apiJSON(`/api/registry/${encodeURIComponent(e.id)}/enabled`, { method: "PUT", body: { enabled: ev.target.checked } }); registryChanged(r.endpoints); }
          catch (err) { toast(err.message, true); ev.target.checked = !ev.target.checked; }
        } }),
        el("span", { text: e.label ? t(e.label) : e.host }), el("span", { class: "host mono", text: e.host }),
        el("span", { class: "kind", text: e.kind + (e.url ? " " + e.url.replace(/^https:\/\/[^/]+/, "") : "") }),
        el("span", { class: "grow" }));
      if (e.custom) row.append(el("button", { type: "button", class: "btn-link", onclick: async () => {
        if (!confirm(t("Удалить точку %s?", e.host))) return;
        try {
          const r = await apiJSON(`/api/registry/${encodeURIComponent(e.id)}`, { method: "DELETE" });
          S.state.registry.endpoints = r.endpoints; renderControls(); renderRegistry(); renderCards();
        } catch (err) { toast(err.message, true); }
      } }, t("удалить")));
      else if (e.source) row.append(el("a", { class: "btn-link", href: e.source, target: "_blank", rel: "noopener noreferrer", title: t("Источник, проверено %s", e.verifiedAt || "") }, t("источник")));
      nodes.push(row);
      if (e.disabledReason) nodes.push(el("div", { class: "re reason", text: e.disabledReason }));
    }
  }
  $("registryList").replaceChildren(...nodes);
}

export function openDrawer() {
  $("drawer").hidden = false; $("drawerBackdrop").hidden = false; $("btnSettings").setAttribute("aria-expanded", "true");
  renderDrawer(); $("btnDrawerClose").focus();
}
export function closeDrawer() {
  $("drawer").hidden = true; $("drawerBackdrop").hidden = true; $("btnSettings").setAttribute("aria-expanded", "false");
  $("btnSettings").focus();
}

export async function quitApp() {
  if (!confirm(t("Завершить приложение? Backend остановится, порт освободится, эту вкладку можно будет закрыть."))) return;
  try {
    await apiJSON("/api/quit", { method: "POST" });
    S.quitting = true;
    if (S.sse) S.sse.close();
    $("banners").replaceChildren();
    banner("info", t("Приложение завершено, порт освобождён. Эту вкладку можно закрыть. Для новой проверки снова запустите VPNCheck.exe."), "quit");
    disableAll();
    closeDrawer();
  } catch (e) { toast(t("Не удалось завершить: %s", e.message), true); }
}

export function wireDrawer() {
  $("btnQuit2").addEventListener("click", quitApp);
  $("btnDrawerClose").addEventListener("click", closeDrawer);
  $("drawerBackdrop").addEventListener("click", closeDrawer);
  $("speedServer").addEventListener("change", (e) => { settings().speedServer = e.target.value; saveSettings(); renderSpeedSettings(); renderSpeed(); });
  for (const r of document.querySelectorAll('input[name="routeMode"]')) r.addEventListener("change", () => {
    const s = settings();
    s.route.mode = r.value;
    if (r.value === "proxy") {
      s.route.proxyKind = $("proxyKind").value; s.route.proxyAddr = $("proxyAddr").value.trim();
      if (!s.route.proxyAddr && S.state.sysproxy && S.state.sysproxy.suggested) s.route = Object.assign({}, S.state.sysproxy.suggested);
    } else {
      s.route = { mode: "system" };
    }
    saveSettings(); renderDrawer(); renderHeader();
  });
  $("proxyKind").addEventListener("change", (e) => { settings().route.proxyKind = e.target.value; saveSettings(); renderHeader(); });
  $("proxyAddr").addEventListener("change", (e) => { settings().route.proxyAddr = e.target.value.trim(); saveSettings(); renderHeader(); });
  $("ipFamily").addEventListener("change", (e) => { settings().ipFamily = e.target.value; saveSettings(); });
  $("slowThreshold").addEventListener("change", (e) => {
    const v = Math.max(0, Math.min(60000, parseInt(e.target.value, 10) || 0));
    e.target.value = v; settings().slowThresholdMs = v; saveSettings();
  });
  $("runCooldown").addEventListener("change", async (e) => {
    const lim = S.state.limits;
    const v = Math.max(lim.cooldownMinSec, Math.min(lim.cooldownMaxSec, parseInt(e.target.value, 10) || 60));
    e.target.value = v;
    settings().runCooldownSec = v;
    await saveSettings(true);
    try { await refreshState(); renderAll(); updateStartButton(); } catch {}
  });
  $("ipLogOn").addEventListener("change", async (e) => { settings().ipLogOff = !e.target.checked; await saveSettings(true); try { await refreshState(); renderAll(); } catch {} });
  $("showExternalIp").addEventListener("change", (e) => { settings().showExternalIp = e.target.checked; saveSettings(); });
  $("cKind").addEventListener("change", (e) => { $("cHttpsRow").hidden = e.target.value !== "https"; });
  $("btnCustomAdd").addEventListener("click", async () => {
    const kind = $("cKind").value;
    const body = { host: $("cHost").value.trim(), label: $("cLabel").value.trim(), kind, enabled: true };
    if (kind === "https") {
      body.url = $("cUrl").value.trim();
      body.expectedStatuses = $("cStatuses").value.split(/[,\s]+/).filter(Boolean).map(Number).filter(n => n >= 100 && n <= 599);
    }
    try {
      const r = await apiJSON("/api/registry", { method: "POST", body });
      $("customMsg").textContent = t("Добавлено: %s", body.host);
      $("cHost").value = ""; $("cLabel").value = ""; $("cUrl").value = ""; $("cStatuses").value = "";
      registryChanged(r.endpoints);
    } catch (e) { $("customMsg").textContent = e.message; }
  });
  $("btnRegExport").addEventListener("click", () => download("/api/registry/export", "vpncheck-registry.json"));
  $("regImport").addEventListener("change", async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const r = await apiJSON("/api/registry/import", { method: "POST", body: await f.text(), headers: { "Content-Type": "application/json" } });
      registryChanged(r.endpoints); toast(t("Реестр импортирован"));
    } catch (err) { toast(err.message, true); }
    e.target.value = "";
  });
  $("btnRegReset").addEventListener("click", async () => {
    if (!confirm(t("Вернуть встроенный реестр? Свои точки будут удалены."))) return;
    try { const r = await apiJSON("/api/registry/reset", { method: "POST" }); registryChanged(r.endpoints); }
    catch (err) { toast(err.message, true); }
  });
}
