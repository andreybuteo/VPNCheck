import assert from "node:assert/strict";
import test from "node:test";

// The controls import renderAll from the application entry point. Suppress
// its startup network requests while exercising the real control modules.
import { registerHooks } from "node:module";
const hooks = registerHooks({
  resolve(specifier, context, next) {
    if (specifier === "./app.js") return { url: "data:text/javascript,export function renderAll() {}", shortCircuit: true };
    return next(specifier, context);
  },
});
globalThis.window = { innerWidth: 800, innerHeight: 600 };
const { S, refreshState, balloon } = await import("../../web/core.js");
const { renderCards } = await import("../../web/run.js");
const { loadCatalog, t } = await import("../../web/i18n.js");

hooks.deregister();

test("regional defaults, also for an empty saved selection", async (ctx) => {
  const endpoints = ["ordinary", "ru-direct", "cn-direct", "ir-direct"].map(groupId => ({ id: groupId, groupId, enabled: true }));
  const state = { settings: { language: "fa" }, app: {}, current: {}, registry: { endpoints } };
  ctx.mock.method(globalThis, "fetch", async () => Response.json(state));
  for (const [locale, expected] of [["zh-Hans-CN", "cn-direct"], ["en-RU-u-nu-latn", "ru-direct"], ["en-US", "ir-direct"]]) {
    state.app.systemLocale = locale;
    await refreshState();
    assert.deepEqual(S.state.settings.selectedEndpoints, ["ordinary", expected]);
  }
  // Settings saved before 4.4 keep [] for "all": it still means the defaults.
  state.settings.selectedEndpoints = [];
  state.app.systemLocale = "ru-RU";
  await refreshState();
  assert.deepEqual(S.state.settings.selectedEndpoints, ["ordinary", "ru-direct"]);
});

// Only the DOM operations exercised by these controls. Geometry is fixed.
class Element extends EventTarget {
  nodeType = 1;
  children = [];
  dataset = {};
  style = {};
  classList = { toggle() {} };
  offsetHeight = 80;
  offsetWidth = 220;
  isConnected = true;
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(key, value) { this[key] = value; }
  removeAttribute(key) { delete this[key]; }
  querySelector(selector) { return this.children.find(n => "." + n.className === selector); }
  getBoundingClientRect() { return { left: 20, width: 80, top: 100, bottom: 120 }; }
  remove() { this.isConnected = false; }
  focus() { document.activeElement = this; }
}
function page() {
  const cards = new Element();
  globalThis.document = Object.assign(new EventTarget(), {
    documentElement: new Element(), body: new Element(),
    createElement: () => new Element(), createElementNS: () => new Element(),
    createTextNode: textContent => ({ textContent }),
    getElementById: id => id === "cards" ? cards : null,
  });
  return cards;
}

test("problem and OK filters use the visible split verdict", () => {
  const cards = page();
  const groupId = "cn-direct";
  S.view = { groups: [{ groupId, level: "ok", label: "1/1", medianTlsReadyMs: null }],
    run: { status: "completed", endpoints: [{ id: "a", groupId, group: "China" }], results: [],
      splits: [null, { group: groupId }], verdicts: [{ groupId, level: "error", title: "split" }] } };
  for (const [filter, count] of [["problems", 1], ["ok", 0], ["unchecked", 0]]) {
    S.filter = filter;
    renderCards();
    assert.equal(cards.children.filter(c => c.dataset.group === groupId).length, count);
  }
});

test("replacing a confirmation cancels it and returns focus after Escape", async () => {
  page();
  const anchor = new Element();
  const first = balloon(anchor, { title: "first" });
  const second = balloon(anchor, { title: "report", alt: "Hide", focusAlt: true });
  assert.equal((await first).ok, false);
  assert.equal(document.activeElement.children[0].textContent, "Hide");
  document.dispatchEvent(Object.assign(new Event("keydown"), { key: "Escape" }));
  assert.equal((await second).ok, false);
  assert.equal(document.activeElement, anchor);
});

test("RTL languages and custom labels that match object properties", async (ctx) => {
  page();
  ctx.mock.method(globalThis, "fetch", async () => Response.json({ catalog: {} }));
  for (const lang of ["fa", "ar"]) {
    await loadCatalog(lang);
    assert.equal(document.documentElement.dir, "rtl");
    assert.equal(t("constructor"), "constructor");
    assert.equal(t(" __proto__ "), " __proto__ ");
  }
  await loadCatalog("en");
  assert.equal(document.documentElement.dir, undefined);
});
