// Цветовая палитра постера: [тёмный фон, средний, акцентный, светлый]
function rgb2hsl(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2;
  let h = 0, s = 0;
  if (mx !== mn) {
    const d = mx - mn;
    s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn);
    h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
    h /= 6;
  }
  return [h, s, l];
}

function hsl2hex(h, s, l) {
  const f = n => {
    const k = (n + h * 12) % 12, a = s * Math.min(l, 1 - l);
    const c = l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1));
    return Math.round(255 * c).toString(16).padStart(2, '0');
  };
  return '#' + f(0) + f(8) + f(4);
}

export function makePalette({ data, width, height }) {
  const step = Math.max(1, Math.floor(Math.sqrt((width * height) / 3000)));
  const px = [];
  for (let y = 0; y < height; y += step) {
    for (let x = 0; x < width; x += step) {
      const i = (y * width + x) * 4;
      if (data[i + 3] < 200) continue;
      px.push([data[i], data[i + 1], data[i + 2]]);
    }
  }
  if (px.length < 50) return null;

  // k-means на 6 кластеров, стартовые центры выбраны по яркости
  const K = 6;
  px.sort((a, b) => (a[0] + a[1] + a[2]) - (b[0] + b[1] + b[2]));
  let cs = Array.from({ length: K }, (_, i) => px[Math.floor((i + 0.5) * px.length / K)].slice());
  let cnt = new Array(K).fill(0);
  for (let it = 0; it < 8; it++) {
    const sum = cs.map(() => [0, 0, 0, 0]);
    for (const p of px) {
      let b = 0, bd = Infinity;
      for (let k = 0; k < K; k++) {
        const d = (p[0] - cs[k][0]) ** 2 + (p[1] - cs[k][1]) ** 2 + (p[2] - cs[k][2]) ** 2;
        if (d < bd) { bd = d; b = k; }
      }
      const s = sum[b]; s[0] += p[0]; s[1] += p[1]; s[2] += p[2]; s[3]++;
    }
    cs = cs.map((c, k) => sum[k][3] ? [sum[k][0] / sum[k][3], sum[k][1] / sum[k][3], sum[k][2] / sum[k][3]] : c);
    cnt = sum.map(s => s[3]);
  }
  const cl = cs.map((c, k) => { const [h, s, l] = rgb2hsl(...c); return { h, s, l, ch: (Math.max(...c) - Math.min(...c)) / 255, w: cnt[k] / px.length }; }).filter(c => c.w > 0.02);
  if (!cl.length) return null;

  const gray = Math.max(...cl.map(c => c.ch)) < 0.1; // чёрно-белый постер
  const best = score => [...cl].sort((a, b) => score(b) - score(a))[0];
  const dark = [...cl].sort((a, b) => a.l - b.l)[0];
  const mid = best(c => c.w * (c.ch + 0.1));
  const acc = best(c => c.ch * Math.sqrt(c.w) * (1 - Math.abs(c.l - 0.55)));

  const c1 = hsl2hex(dark.h, gray ? 0.04 : Math.min(dark.s, 0.55), Math.min(Math.max(dark.l * 0.6, 0.035), 0.085));
  const c2 = hsl2hex(mid.h, gray ? 0.05 : Math.min(mid.s * 0.9, 0.65), 0.2 + Math.min(mid.l, 0.5) * 0.2);
  const c3 = gray ? hsl2hex(0.1, 0.12, 0.78) : hsl2hex(acc.h, Math.max(Math.min(acc.s, 0.85), 0.5), Math.min(Math.max(acc.l, 0.52), 0.68));
  const c4 = hsl2hex(acc.h, gray ? 0.08 : Math.min(acc.s, 0.6), 0.88);
  return [c1, c2, c3, c4];
}
