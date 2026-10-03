/* Hand-rolled SVG charts (zero dependencies, works offline) */
Charts = {
  donut(pct, color, size = 120, stroke = 10) {
    pct = Math.max(0, Math.min(100, pct ?? 0));
    const r = (size - stroke) / 2, c = size / 2;
    const circ = 2 * Math.PI * r;
    const dash = (pct / 100) * circ;
    const glow = pct >= 80 ? '#00e5a0' : pct >= 60 ? '#4dd8ff' : pct >= 40 ? '#ffd23d' : '#ff3b5c';
    const col = color || glow;
    return `
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="#1c2738" stroke-width="${stroke}"/>
        <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${col}" stroke-width="${stroke}"
          stroke-linecap="round" stroke-dasharray="${dash} ${circ - dash}"
          transform="rotate(-90 ${c} ${c})" style="filter:drop-shadow(0 0 6px ${col}66)"/>
        <text x="${c}" y="${c + 2}" text-anchor="middle" dominant-baseline="middle"
          fill="${col}" font-size="${size / 3.4}" font-weight="800" font-family="Segoe UI">${Math.round(pct)}</text>
      </svg>`;
  },

  bars(items) {
    // items: [{label, value, color}]
    const max = Math.max(1, ...items.map(i => i.value));
    return `<div class="barchart">` + items.map(i => `
      <div class="bar">
        <div class="v" style="height:${(i.value / max) * 100}%;background:${i.color};
             box-shadow:0 0 10px ${i.color}55"></div>
        <div class="l">${esc(i.label)}<br><b style="color:${i.color}">${i.value}</b></div>
      </div>`).join('') + `</div>`;
  }
};
