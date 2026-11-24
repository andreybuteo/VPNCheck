// Freshness of results: a check or a speed test older than 30 minutes is
// shown faded, so an old result on opening the page does not look like one
// that has just been made. The VPN may have reconnected or changed its
// server or IP since then.
import { t, tp } from "./i18n.js";

export const STALE_MS = 30 * 60 * 1000;

const ageMs = (ts) => Date.now() - new Date(ts).getTime();

// isStale reports whether a timestamp (ISO string or Date) is older than 30 minutes.
export function isStale(ts) {
  return !!ts && ageMs(ts) > STALE_MS;
}

// ageText says how long ago: "45 минут назад", "18 часов назад", "3 дня назад".
export function ageText(ts) {
  const min = Math.max(0, Math.floor(ageMs(ts) / 60000));
  if (min < 60) return tp(min, "%d минуту назад", "%d минуты назад", "%d минут назад");
  const h = Math.floor(min / 60);
  if (h < 48) return tp(h, "%d час назад", "%d часа назад", "%d часов назад");
  return tp(Math.floor(h / 24), "%d день назад", "%d дня назад", "%d дней назад");
}

// runFinished is the moment a check run ended (or started, for older records).
export function runTime(run) {
  return run && (run.finishedAt || run.startedAt);
}

// staleRun: the run shown is finished and older than 30 minutes.
export function staleRun(run, running) {
  return !!run && !running && run.status !== "running" && isStale(runTime(run));
}

// staleHint is the explanation shown in tooltips of faded blocks.
export function staleHint(ts) {
  return t("Результат %s: с тех пор VPN мог переподключиться или сменить сервер. Нажмите «Начать проверку», чтобы обновить.", ageText(ts));
}
