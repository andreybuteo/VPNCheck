// Exit-IP strip: the last addresses seen at checks and speed tests. A filled
// cell opens its result: a check like "Open" in History, a speed test in the
// speed tiles.
//
// Four hues only: on both themes no fifth one stays distinguishable from all
// the others (checked with the dataviz palette validator). A fifth and later
// distinct address is grey and labelled "other"; the address is always
// written, so colour never carries identity alone.
import { t, tp } from "./i18n.js";
import { $, el, ltr, S, fmtTime, fmtShort, routeLabel } from "./core.js";
import { openHistory } from "./history.js";
import { showSpeedResult } from "./speed.js";

const IP_SLOTS = 4;
const kindName = (k) => ({ run: t("проверка"), speed: t("скорость") })[k] || k;

function isSelected(e) {
  if (e.kind === "run") return !!(S.viewingHistory && S.view && S.view.run && S.view.run.id === e.id);
  if (e.kind === "speed") return !!S.speedView && S.speedView === e.id && !(S.state.speed && S.state.speed.current);
  return false;
}
function openEntry(e) {
  if (e.kind === "run") openHistory(e.id);
  else if (e.kind === "speed") showSpeedResult(e.id);
}

export function renderIPStrip() {
  const box = $("ipStrip");
  const log = S.state.ipLog;
  if (!log) { box.hidden = true; return; }
  box.hidden = false;
  // keep keyboard focus on the same cell across re-renders
  const focused = box.contains(document.activeElement) ? document.activeElement.dataset.idx : undefined;
  const entries = log.entries || [];
  const slot = new Map();
  for (const e of entries) if (!slot.has(e.ip)) slot.set(e.ip, slot.size < IP_SLOTS ? slot.size + 1 : 0);
  const distinct = slot.size;
  let switches = 0;
  for (let i = 1; i < entries.length; i++) if (entries[i].ip !== entries[i - 1].ip) switches++;
  const legend = !log.enabled ? t("журнал выключен в настройках")
    : !entries.length ? t("появится после первой проверки или замера скорости")
    : tp(distinct, "%d адрес", "%d адреса", "%d адресов") + " · " + (switches ? tp(switches, "%d смена", "%d смены", "%d смен") : t("без смен"))
      + (distinct > IP_SLOTS ? " · " + t("после %d-го серым", IP_SLOTS) : "");
  const head = el("div", { class: "ip-head" }, el("span", { class: "ip-title", text: t("IP выхода — последние %v", log.size) }), el("span", { class: "hint", text: legend }));
  const cells = [];
  const padN = log.size - entries.length;
  for (let i = 0; i < padN; i++) cells.push(el("div", { class: "ipcell empty" }, el("div", { class: "ip-addr", text: "—" }), el("div", { class: "ip-sub", text: " " }), el("div", { class: "ip-sub", text: " " })));
  entries.forEach((e, i) => {
    const k = slot.get(e.ip);
    const prev = entries[i - 1];
    const changed = prev && prev.ip !== e.ip;
    const last = i === entries.length - 1;
    const kind = kindName(e.kind);
    const other = k === 0 ? " · " + t("другой") : "";
    const clickable = !!e.id && (e.kind === "run" || e.kind === "speed");
    const title = [
      e.ip + (e.country ? " (" + e.country + ")" : ""),
      fmtTime(e.at),
      kind + (e.profile ? " · " + t("профиль %s", e.profile) : ""),
      t("маршрут: %s", routeLabel(e.route)),
      e.from ? t("во время проверки адрес сменился: %s → %s", e.from, e.ip) : "",
      changed ? t("до этого: %s", prev.ip) : "",
      k === 0 ? t("цвет: другой (больше четырёх разных адресов)") : "",
      clickable ? t("Нажмите, чтобы показать результаты") : "",
    ].filter(Boolean).join("\n");
    const sub2 = [kind, e.country || "", e.from ? t("менялся") : ""].filter(Boolean).join(" · ") + other;
    const flag = el("span", { class: "ip-flag", html: window.flagSVG ? window.flagSVG(e.country) : "" });
    const cls = `ipcell ip-c${k}` + (last ? " latest" : "") + (changed ? " changed" : "") + (clickable && isSelected(e) ? " selected" : "");
    const attrs = { class: cls, title };
    if (clickable) {
      Object.assign(attrs, {
        role: "button", tabindex: "0", "aria-pressed": String(isSelected(e)), dataset: { idx: String(i) },
        onclick: () => openEntry(e),
        onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openEntry(e); } },
      });
    }
    cells.push(el("div", attrs,
      el("div", { class: "ip-addr" }, flag, el("span", { class: "mono", dir: "ltr", text: e.ip })),
      el("div", { class: "ip-sub" }, ltr(fmtShort(e.at)), " · " + kind + (e.from ? " · " + t("менялся") : "") + other),
      el("div", { class: "ip-sub", text: sub2 })));
  });
  box.replaceChildren(head, el("div", { class: "ip-cells" }, ...cells));
  if (focused !== undefined) { const c = box.querySelector(`[data-idx="${focused}"]`); if (c) c.focus(); }
}
