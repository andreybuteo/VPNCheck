// Interface language (gettext style): the Russian source text is the key.
//
//   t("Пауза %d с", 30)                 -> catalog["Пауза %d с"] or the source, then formatted
//   tp(n, "%d узел", "%d узла", "%d узлов") -> plural form, translated, %d replaced by n
//
// Placeholders are the printf verbs shared with the Go side and the same
// catalog files: %s %d %v %% and a precision such as %.0f or %.1f. A string
// without arguments is returned as is (a bare % is literal there). Keys are
// plain double-quoted literals, so that an extractor can find them; data that
// arrives from the server (group names, labels, notes) is passed through t()
// at display time and simply stays unchanged when the catalog has no entry.
//
// Static text in index.html is translated by translateDOM(): every text node
// and title / placeholder / aria-label attribute containing Cyrillic is a key
// (whitespace collapsed, trimmed). The content of elements marked
// data-i18n-skip is rendered by scripts and is not walked.

export const SOURCE = "ru";
export const LANG_HEADER = "X-VPNCheck-Lang";
const LANG_CACHE = "vpncheck.lang";

// Fallback list until the server's list arrives (same codes and native names).
let languages = [
  { code: "ru", name: "Русский" },
  { code: "en", name: "English" },
  { code: "de", name: "Deutsch" },
  { code: "zh", name: "中文" },
  { code: "fa", name: "فارسی", rtl: true },
  { code: "ar", name: "العربية", rtl: true },
];
let current = SOURCE;
let catalog = {};

export const lang = () => current;
export const languageList = () => languages;
const isRTL = (code) => !!(languages.find(l => l.code === code) || {}).rtl;

// Number formatting locale. Persian and Arabic keep Latin digits, like the
// rest of the figures on the page (times, IP addresses, milliseconds).
export function numLocale() {
  return { ru: "ru-RU", de: "de-DE", zh: "zh-CN" }[current] || "en-US";
}

export function sprintf(fmt, args) {
  let i = 0;
  return fmt.replace(/%(?:\.(\d+))?([sdvf%])/g, (m, prec, verb) => {
    if (verb === "%") return "%";
    if (i >= args.length) return m;
    const a = args[i++];
    if (verb === "d") { const n = Number(a); return Number.isFinite(n) ? String(Math.trunc(n)) : String(a); }
    if (verb === "f") { const n = Number(a); return Number.isFinite(n) ? n.toFixed(prec === undefined ? 6 : Number(prec)) : String(a); }
    return String(a);
  });
}

// Lookup keeps the spaces around fragments that are glued to other text:
// the catalog keys are trimmed, so " (до " is found as "(до" and padded back.
function lookup(src) {
  if (current === SOURCE || !src) return src;
  if (Object.hasOwn(catalog, src)) return catalog[src];
  const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(src);
  const hit = m && m[2] && Object.hasOwn(catalog, m[2]) && catalog[m[2]];
  return hit ? m[1] + hit + m[3] : src;
}

export function t(src, ...args) {
  const s = lookup(src);
  return args.length ? sprintf(s, args) : s;
}

export function tp(n, one, few, many) {
  let form;
  if (current === SOURCE) {
    const m10 = n % 10, m100 = n % 100;
    form = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
  } else {
    form = t(n === 1 && current !== "zh" ? one : many);
  }
  return form.includes("%") ? sprintf(form, [n]) : form;
}

// "de-AT" -> "de", "zh_CN" -> "zh"; "" when the language is not supported.
export function normalize(tag) {
  const base = String(tag || "").trim().toLowerCase().split(/[-_]/)[0];
  return languages.some(l => l.code === base) ? base : "";
}

// The language to use: the setting when set; otherwise the Windows regional
// format reported by the backend (it reflects the user's language better than
// the browser list, which follows the display language: English Windows with
// Russian formats is common); otherwise the browser's first supported
// language; otherwise Russian.
export function effectiveLang(setting, systemLang) {
  const fixed = normalize(setting);
  if (fixed) return fixed;
  const sys = normalize(systemLang);
  if (sys) return sys;
  for (const tag of navigator.languages || [navigator.language]) {
    const code = normalize(tag);
    if (code) return code;
  }
  return SOURCE;
}

export function cachedLang() {
  try { return normalize(localStorage.getItem(LANG_CACHE)); } catch { return ""; }
}

function setLang(code) {
  current = code;
  try { localStorage.setItem(LANG_CACHE, code); } catch {}
  const root = document.documentElement;
  root.lang = code;
  if (isRTL(code)) root.dir = "rtl"; else root.removeAttribute("dir");
}

// Loads the catalog and the language list from the server and switches to the
// language. On failure the language is still switched, with an empty catalog.
export async function loadCatalog(code) {
  catalog = {};
  setLang(code); // requests sent meanwhile already carry the new language
  try {
    const r = await fetch("/api/i18n/" + encodeURIComponent(code), { headers: { [LANG_HEADER]: code }, credentials: "same-origin" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    if (Array.isArray(d.languages) && d.languages.length) languages = d.languages;
    catalog = d.catalog || {};
  } catch {
    catalog = {};
  }
  setLang(code); // again: the server's list may change the RTL flag
}

const CYRILLIC = /[Ѐ-ӿ]/;
const ATTRS = ["title", "placeholder", "aria-label"];
const origText = new WeakMap();
const origAttrs = new WeakMap();
const keyOf = (s) => s.replace(/\s+/g, " ").trim();
// Inside an element marked data-i18n-skip (its content is rendered by scripts
// with t()), nothing is touched; the marked element's own attributes are.
const skipped = (node) => !!(node && node.closest("[data-i18n-skip], script, style"));

// Translates static text in place. The Russian original of every node is kept,
// so the page can be switched between languages any number of times.
export function translateDOM(root = document.body) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    let src = origText.get(n);
    if (src === undefined) {
      if (!CYRILLIC.test(n.nodeValue) || skipped(n.parentElement)) continue;
      src = n.nodeValue;
      origText.set(n, src);
    }
    const key = keyOf(src), tr = t(key);
    n.nodeValue = tr === key ? src : src.match(/^\s*/)[0] + tr + src.match(/\s*$/)[0];
  }
  const els = [root, ...root.querySelectorAll("[title], [placeholder], [aria-label]")];
  for (const e of els) {
    if (!e.getAttribute || skipped(e.parentElement)) continue;
    let o = origAttrs.get(e);
    if (!o) {
      o = {};
      for (const a of ATTRS) { const v = e.getAttribute(a); if (v && CYRILLIC.test(v)) o[a] = v; }
      if (!Object.keys(o).length) continue;
      origAttrs.set(e, o);
    }
    for (const [a, v] of Object.entries(o)) { const key = keyOf(v), tr = t(key); e.setAttribute(a, tr === key ? v : tr); }
  }
}
