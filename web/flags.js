/* Simplified country flags (3.0), drawn as tiny SVGs without coats of arms.
   Windows does not render flag emoji, and the page loads nothing from outside,
   so the flags most often seen at VPN exits are drawn here from stripes,
   crosses and simple shapes. Unknown codes get a neutral badge with the code. */
(function () {
  "use strict";
  const W = 24, H = 16;
  const rect = (x, y, w, h, c) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${c}"/>`;
  const hs = (...cs) => cs.map((c, i) => rect(0, (H / cs.length) * i, W, H / cs.length + 0.01, c)).join("");
  const vs = (...cs) => cs.map((c, i) => rect((W / cs.length) * i, 0, W / cs.length + 0.01, H, c)).join("");
  // weighted horizontal stripes: [[color, weight], ...]
  const hw = (parts) => { const t = parts.reduce((a, p) => a + p[1], 0); let y = 0; return parts.map(([c, w]) => { const r = rect(0, y, W, (H * w) / t + 0.01, c); y += (H * w) / t; return r; }).join(""); };
  const vw = (parts) => { const t = parts.reduce((a, p) => a + p[1], 0); let x = 0; return parts.map(([c, w]) => { const r = rect(x, 0, (W * w) / t + 0.01, H, c); x += (W * w) / t; return r; }).join(""); };
  // Nordic cross: background, cross, optional inner cross
  const nordic = (bg, cross, inner) => rect(0, 0, W, H, bg) + rect(7, 0, 4, H, cross) + rect(0, 6, W, 4, cross) + (inner ? rect(8, 0, 2, H, inner) + rect(0, 7, W, 2, inner) : "");
  const circle = (cx, cy, r, c) => `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${c}"/>`;
  const poly = (pts, c) => `<polygon points="${pts}" fill="${c}"/>`;
  const star = (cx, cy, r, c) => { const p = []; for (let i = 0; i < 10; i++) { const a = -Math.PI / 2 + (i * Math.PI) / 5; const rr = i % 2 ? r * 0.42 : r; p.push((cx + rr * Math.cos(a)).toFixed(2) + "," + (cy + rr * Math.sin(a)).toFixed(2)); } return poly(p.join(" "), c); };

  const F = {
    FI: nordic("#fff", "#003580"), SE: nordic("#006aa7", "#fecc00"), NO: nordic("#ba0c2f", "#fff", "#00205b"),
    DK: nordic("#c8102e", "#fff"), IS: nordic("#02529c", "#fff", "#dc1e35"),
    DE: hs("#000", "#dd0000", "#ffce00"), NL: hs("#ae1c28", "#fff", "#21468b"), RU: hs("#fff", "#0039a6", "#d52b1e"),
    AT: hs("#ed2939", "#fff", "#ed2939"), HU: hs("#ce2939", "#fff", "#477050"), BG: hs("#fff", "#00966e", "#d62612"),
    LT: hs("#fdb913", "#006a44", "#c1272d"), EE: hs("#0072ce", "#000", "#fff"), LU: hs("#ed2939", "#fff", "#00a1de"),
    UA: hs("#0057b7", "#ffd700"), PL: hs("#fff", "#dc143c"), ID: hs("#ce1126", "#fff"), MC: hs("#ce1126", "#fff"),
    LV: hw([["#9e3039", 2], ["#fff", 1], ["#9e3039", 2]]), BY: hw([["#c8313e", 2], ["#4aa657", 1]]),
    AM: hs("#d90012", "#0033a0", "#f2a800"), AZ: hs("#00b5e2", "#ef3340", "#509e2f"), UZ: hw([["#1eb53a", 0], ["#0099b5", 5], ["#ce1126", 0.4], ["#fff", 5], ["#ce1126", 0.4], ["#1eb53a", 5]]),
    RS: hs("#c6363c", "#0c4076", "#fff"), SK: hs("#fff", "#0b4ea2", "#ee1c25"), SI: hs("#fff", "#005da4", "#ed1c24"),
    HR: hs("#ff0000", "#fff", "#171796"), ES: hw([["#aa151b", 1], ["#f1bf00", 2], ["#aa151b", 1]]), YE: hs("#ce1126", "#fff", "#000"),
    FR: vs("#0055a4", "#fff", "#ef4135"), IT: vs("#009246", "#fff", "#ce2b37"), IE: vs("#169b62", "#fff", "#ff883e"),
    BE: vs("#000", "#fdda24", "#ef3340"), RO: vs("#002b7f", "#fcd116", "#ce1126"), MD: vs("#0046ae", "#ffd200", "#cc092f"),
    MX: vs("#006847", "#fff", "#ce1126"), PE: vs("#d91023", "#fff", "#d91023"), NG: vs("#008751", "#fff", "#008751"),
    PT: vw([["#006600", 2], ["#ff0000", 3]]), TH: hw([["#a51931", 1], ["#f4f5f8", 1], ["#2d2a4a", 2], ["#f4f5f8", 1], ["#a51931", 1]]),
    AR: hs("#74acdf", "#fff", "#74acdf") + circle(12, 8, 1.8, "#f6b40e"), CO: hw([["#fcd116", 2], ["#003893", 1], ["#ce1126", 1]]),
    CH: rect(0, 0, W, H, "#d52b1e") + rect(10.5, 3.5, 3, 9, "#fff") + rect(7.5, 6.5, 9, 3, "#fff"),
    GE: rect(0, 0, W, H, "#fff") + rect(10.5, 0, 3, H, "#ff0000") + rect(0, 6.5, W, 3, "#ff0000"),
    JP: rect(0, 0, W, H, "#fff") + circle(12, 8, 4.6, "#bc002d"), KR: rect(0, 0, W, H, "#fff") + circle(12, 8, 4, "#cd2e3a") + `<path d="M8 8a4 4 0 0 0 8 0a2 2 0 0 0-4 0a2 2 0 0 1-4 0z" fill="#0047a0"/>`,
    BD: rect(0, 0, W, H, "#006a4e") + circle(10.5, 8, 4.5, "#f42a41"), KZ: rect(0, 0, W, H, "#00afca") + circle(12, 7.5, 3.2, "#fec50c"),
    CN: rect(0, 0, W, H, "#de2910") + star(5, 4.5, 3, "#ffde00"), VN: rect(0, 0, W, H, "#da251d") + star(12, 8, 4.2, "#ffff00"),
    HK: rect(0, 0, W, H, "#de2910") + circle(12, 8, 3.6, "#fff"), TR: rect(0, 0, W, H, "#e30a17") + circle(9.5, 8, 4, "#fff") + circle(10.6, 8, 3.2, "#e30a17") + star(15, 8, 2.2, "#fff"),
    SG: hs("#ef3340", "#fff") + circle(5, 4, 2.6, "#fff") + circle(6, 4, 2.3, "#ef3340"),
    IL: rect(0, 0, W, H, "#fff") + rect(0, 1.8, W, 2.2, "#0038b8") + rect(0, 12, W, 2.2, "#0038b8") + `<polygon points="12,4.6 15,9.8 9,9.8" fill="none" stroke="#0038b8" stroke-width="0.9"/><polygon points="12,11.4 15,6.2 9,6.2" fill="none" stroke="#0038b8" stroke-width="0.9"/>`,
    IN: hs("#ff9933", "#fff", "#138808") + `<circle cx="12" cy="8" r="1.9" fill="none" stroke="#000080" stroke-width="0.7"/>`,
    BR: rect(0, 0, W, H, "#009b3a") + poly("12,1.6 22,8 12,14.4 2,8", "#fedf00") + circle(12, 8, 3.6, "#002776"),
    CA: vw([["#d80621", 1], ["#fff", 2], ["#d80621", 1]]) + star(12, 8, 3.4, "#d80621"),
    US: hw(Array.from({ length: 13 }, (_, i) => [i % 2 ? "#fff" : "#b22234", 1])) + rect(0, 0, 10, 8.6, "#3c3b6e"),
    GB: rect(0, 0, W, H, "#012169") + `<path d="M0 0L24 16M24 0L0 16" stroke="#fff" stroke-width="3.2"/><path d="M0 0L24 16M24 0L0 16" stroke="#c8102e" stroke-width="1.1"/>` + rect(9.5, 0, 5, H, "#fff") + rect(0, 5.5, W, 5, "#fff") + rect(10.5, 0, 3, H, "#c8102e") + rect(0, 6.5, W, 3, "#c8102e"),
    AU: rect(0, 0, W, H, "#012169") + star(6, 12, 1.8, "#fff") + star(18, 4, 1.1, "#fff") + star(20, 9, 1.1, "#fff") + star(17, 12.5, 1.1, "#fff"),
    NZ: rect(0, 0, W, H, "#012169") + star(17, 4, 1.1, "#c8102e") + star(19.5, 8, 1.1, "#c8102e") + star(17, 12.5, 1.1, "#c8102e"),
    GR: hw(Array.from({ length: 9 }, (_, i) => [i % 2 ? "#fff" : "#0d5eaf", 1])) + rect(0, 0, 8.9, 8.9, "#0d5eaf") + rect(3.6, 0, 1.8, 8.9, "#fff") + rect(0, 3.55, 8.9, 1.8, "#fff"),
    CZ: hs("#fff", "#d7141a") + poly("0,0 11,8 0,16", "#11457e"),
    AE: hs("#00732f", "#fff", "#000") + rect(0, 0, 6, H, "#ff0000"),
    QA: rect(0, 0, W, H, "#8a1538") + poly("0,0 7,0 9,0.9 7,1.8 9,2.7 7,3.6 9,4.4 7,5.3 9,6.2 7,7.1 9,8 7,8.9 9,9.8 7,10.7 9,11.6 7,12.4 9,13.3 7,14.2 9,15.1 7,16 0,16", "#fff"),
    SA: rect(0, 0, W, H, "#006c35") + rect(6, 10.5, 12, 1, "#fff"), EG: hs("#ce1126", "#fff", "#000"), IR: hs("#239f40", "#fff", "#da0000"),
    TW: rect(0, 0, W, H, "#fe0000") + rect(0, 0, 12, 8, "#000095") + circle(6, 4, 2.2, "#fff"),
    MY: hw(Array.from({ length: 14 }, (_, i) => [i % 2 ? "#fff" : "#cc0001", 1])) + rect(0, 0, 12, 9.1, "#010066") + circle(5, 4.5, 2.6, "#fc0") + circle(5.9, 4.5, 2.2, "#010066"),
    PH: hs("#0038a8", "#ce1126") + poly("0,0 11,8 0,16", "#fff"), CL: hs("#fff", "#d52b1e") + rect(0, 0, 8, 8, "#0039a6") + star(4, 4, 2, "#fff"),
    ZA: rect(0, 0, W, H, "#fff") + rect(0, 0, W, 5.3, "#e03c31") + rect(0, 10.7, W, 5.3, "#001489") + poly("0,1.5 9,8 0,14.5", "#007a4d") + poly("0,3.5 6.5,8 0,12.5", "#ffb81c") + poly("0,4.8 4.8,8 0,11.2", "#000"),
    CY: rect(0, 0, W, H, "#fff") + `<ellipse cx="12" cy="7.2" rx="5" ry="2.4" fill="#d57800"/>`,
    AL: rect(0, 0, W, H, "#e41e20") + circle(12, 8, 3, "#000"), MK: rect(0, 0, W, H, "#d20000") + circle(12, 8, 3, "#ffe600"),
    ME: rect(0, 0, W, H, "#d3ae3b") + rect(1, 1, 22, 14, "#c40308"), BA: rect(0, 0, W, H, "#002395") + poly("6,0 17,0 17,16", "#fecb00"),
    KG: rect(0, 0, W, H, "#e8112d") + circle(12, 8, 3.6, "#ffef00"), TJ: hw([["#cc0000", 2], ["#fff", 3], ["#006600", 2]]),
    TM: rect(0, 0, W, H, "#00843d") + rect(3, 0, 4, H, "#d22630"), MN: vs("#c4272f", "#015197", "#c4272f"),
  };

  const esc = (s) => String(s).replace(/[^A-Z0-9]/g, "");
  // Returns trusted static SVG markup for a country code (letters only are used).
  window.flagSVG = function (code) {
    const c = esc(String(code || "").toUpperCase()).slice(0, 3);
    const body = F[c];
    if (!body) {
      const t = c || "?";
      return `<svg class="flag flag-unknown" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${t}"><rect x="0.5" y="0.5" width="23" height="15" rx="2" fill="none" stroke="currentColor" stroke-width="1"/><text x="12" y="11.3" text-anchor="middle" font-size="8.5" font-family="Segoe UI, sans-serif" font-weight="600" fill="currentColor">${t}</text></svg>`;
    }
    return `<svg class="flag" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${c}"><clipPath id="fc-${c}"><rect width="${W}" height="${H}" rx="2"/></clipPath><g clip-path="url(#fc-${c})">${body}</g><rect x="0.5" y="0.5" width="23" height="15" rx="2" fill="none" stroke="rgba(127,127,127,.45)" stroke-width="1"/></svg>`;
  };
  window.flagKnown = (code) => !!F[esc(String(code || "").toUpperCase())];
})();
