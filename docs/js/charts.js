/* Hand-rolled SVG charts (zero dependencies, works offline) */
Charts = {
  donut(pct, color, size = 120, stroke = 8, label) {
    pct = Math.max(0, Math.min(100, pct ?? 0));
    const r = (size - stroke) / 2, c = size / 2;
    const circ = 2 * Math.PI * r;
    const dash = (pct / 100) * circ;
    const grade = pct >= 80 ? '#34d399' : pct >= 60 ? '#38bdf8' : pct >= 40 ? '#fbbf24' : '#f87171';
    const col = color || grade;
    const text = label !== undefined ? label : Math.round(pct);
    const arc = pct > 0 ? `
        <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${col}" stroke-width="${stroke}"
          stroke-linecap="round" stroke-dasharray="${dash} ${circ - dash}"
          transform="rotate(-90 ${c} ${c})"/>` : '';
    return `
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="${stroke}"/>
        ${arc}
        <text x="${c}" y="${c + 3}" text-anchor="middle" dominant-baseline="middle"
          fill="#f4f5f7" font-size="${size / 3.6}" font-weight="700"
          font-family="'Cascadia Code',Consolas,monospace">${text}</text>
      </svg>`;
  },

  bars(items) {
    // items: [{label, value, color}]
    const max = Math.max(1, ...items.map(i => i.value));
    return `<div class="barchart">` + items.map(i => `
      <div class="bar">
        <div class="v" style="height:${(i.value / max) * 100}%;background:${i.color}"></div>
        <div class="l">${esc(i.label)}<br><b style="color:${i.color}">${i.value}</b></div>
      </div>`).join('') + `</div>`;
  }
};
