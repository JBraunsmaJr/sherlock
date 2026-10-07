(() => {
  'use strict';

  const $ = (s) => document.querySelector(s);
  const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

  const KIND = {
    link_down: 'Link down',
    speed_change: 'Speed change',
    interface_errors: 'Adapter errors',
    gateway_loss: 'Gateway loss',
    gateway_latency: 'Gateway latency',
    internet_loss: 'Internet loss',
    dns_failure: 'DNS failure',
    throughput_low: 'Slow speed test',
    link_up: 'Link back up',
    recovered: 'Recovered',
  };

  const FILES = {
    'capture.pcap': 'Packet headers, opens in Wireshark',
    'samples-link.csv': 'Adapter samples, one per second',
    'samples-probes.csv': 'Ping and DNS samples',
    'event.json': 'Everything here, as JSON',
    'ipconfig.txt': 'IP configuration at trigger',
    'routes.txt': 'Routing table at trigger',
    'ip-interfaces.txt': 'Interface metrics at trigger',
    'adapter.txt': 'Adapter properties and counters',
    'system-events.txt': 'Windows System log, last 10 min',
    'ip-addr.txt': 'Addresses at trigger',
    'link-stats.txt': 'Link counters at trigger',
    'ethtool.txt': 'Negotiated speed and duplex',
    'ethtool-stats.txt': 'Driver counters',
    'kernel-log.txt': 'Kernel log, last 10 min',
  };

  // ---------- formatting ----------
  const fmtMs = (v) => (v == null ? '–' : v < 1 ? v.toFixed(2) + ' ms' : v < 10 ? v.toFixed(1) + ' ms' : Math.round(v) + ' ms');
  const fmtMbps = (v) => {
    if (v == null) return '–';
    if (v >= 1000) return (v / 1000).toFixed(v % 1000 === 0 ? 0 : 2) + ' Gbps';
    if (v >= 10) return Math.round(v) + ' Mbps';
    if (v >= 0.1) return v.toFixed(1) + ' Mbps';
    return v > 0 ? Math.round(v * 1000) + ' kbps' : '0';
  };
  const fmtPct = (v) => (v == null ? '–' : (v >= 10 || v === 0 ? Math.round(v) : v.toFixed(1)) + '%');
  const fmtCount = (v) => (v == null ? '–' : String(Math.round(v)));
  const fmtClock = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const fmtWhen = (ms) => {
    const d = new Date(ms);
    const sameDay = d.toDateString() === new Date().toDateString();
    return sameDay ? fmtClock(ms) : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ', ' + fmtClock(ms);
  };
  const fmtDur = (ms) => {
    const s = Math.round(ms / 1000);
    if (s < 90) return s + ' s';
    const m = Math.round(s / 60);
    return m < 90 ? m + ' min' : (m / 60).toFixed(1) + ' h';
  };
  const ago = (ms) => fmtDur(Date.now() - ms) + ' ago';

  function rgba(hex, a) {
    const m = /^#?([0-9a-f]{6})$/i.exec(hex);
    if (!m) return hex;
    const n = parseInt(m[1], 16);
    return `rgba(${n >> 16}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
  }

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : String(kid));
    }
    return el;
  }

  // replaceChildren() would print null children as the text "null", so filter them out.
  const fill = (el, ...kids) => el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));

  // ---------- API ----------
  async function api(path, opts) {
    const r = await fetch(path, opts);
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || r.statusText);
    return body;
  }
  const post = (path, body) =>
    api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

  let toastTimer;
  function toast(msg, bad) {
    const t = $('#toast');
    t.textContent = msg;
    t.className = 'toast' + (bad ? ' bad' : '');
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), 3500);
  }

  // ---------- state ----------
  const state = {
    span: 15 * 60 * 1000,
    view: null, // {from, to} while zoomed; null means "live"
    shown: null,
    events: [],
    notes: [],
    hot: null, // event id highlighted from the list
    status: null,
    detail: null,
  };
  const currentRange = () => state.view || { from: Date.now() - state.span, to: Date.now() };

  // ---------- charts ----------
  const CHARTS = [
    {
      id: 'latency', title: 'Latency', unit: 'ms, average per bucket', height: 170,
      series: [
        { key: 'gw_avg', label: 'Gateway', color: '--gateway', fmt: fmtMs },
        { key: 'inet_avg', label: 'Internet', color: '--internet', fmt: fmtMs },
        { key: 'dns_avg', label: 'DNS lookup', color: '--dns', fmt: fmtMs, dash: [5, 4] },
        { key: 'gw_max', label: 'Gateway worst', color: '--gateway', fmt: fmtMs, width: 1, dash: [2, 3] },
      ],
    },
    {
      id: 'loss', title: 'Packet loss', unit: '% of probes lost', yMax: 100,
      series: [
        { key: 'gw_loss', label: 'Gateway', color: '--gateway', fmt: fmtPct, step: true },
        { key: 'inet_loss', label: 'Internet', color: '--internet', fmt: fmtPct, step: true },
        { key: 'dns_loss', label: 'DNS', color: '--dns', fmt: fmtPct, step: true, dash: [5, 4] },
      ],
    },
    {
      id: 'link', title: 'Link speed', unit: 'negotiated, lowest per bucket',
      series: [{ key: 'speed_min', label: 'Speed', color: '--link', fmt: fmtMbps, step: true, fill: 0.14 }],
    },
    {
      id: 'errors', title: 'Adapter errors', unit: 'bad or dropped frames per bucket',
      series: [
        { key: 'rx_errors', label: 'Receive errors', color: '--bad', fmt: fmtCount, bars: true },
        { key: 'rx_discards', label: 'Receive discards', color: '--warn', fmt: fmtCount, bars: true },
        { key: 'tx_errors', label: 'Send errors', color: '--internet', fmt: fmtCount, bars: true },
        { key: 'tx_discards', label: 'Send discards', color: '--dns', fmt: fmtCount, bars: true },
      ],
    },
    {
      id: 'traffic', title: 'Traffic', unit: 'Mbps, dots are speed tests',
      series: [
        { key: 'rx_mbps', label: 'Download', color: '--link', fmt: fmtMbps, fill: 0.1 },
        { key: 'tx_mbps', label: 'Upload', color: '--tx', fmt: fmtMbps },
        { key: 'iperf_down', label: 'Test down', color: '--link', fmt: fmtMbps, dots: true },
        { key: 'iperf_up', label: 'Test up', color: '--tx', fmt: fmtMbps, dots: true },
      ],
    },
  ];

  let plots = [];
  let lastData = null;

  function overlay(chartIndex) {
    const bandCtx = (u) => {
      const { ctx } = u;
      const { left, top, width, height } = u.bbox;
      ctx.save();
      ctx.beginPath();
      ctx.rect(left, top, width, height);
      ctx.clip();
      return { ctx, top, height };
    };
    return {
      hooks: {
        // Bands go under the series so the lines stay readable.
        drawClear: [
          (u) => {
            const { ctx, top, height } = bandCtx(u);
            const minW = 2 * devicePixelRatio;
            for (const ev of state.events) {
              const hot = ev.id === state.hot;
              if (hot) {
                const p0 = u.valToPos(ev.window_start / 1000, 'x', true);
                const p1 = u.valToPos(ev.start / 1000, 'x', true);
                ctx.fillStyle = cssVar('--band-quiet');
                ctx.fillRect(p0, top, Math.max(p1 - p0, 0), height);
              }
              const x0 = u.valToPos(ev.start / 1000, 'x', true);
              const x1 = u.valToPos(ev.end / 1000, 'x', true);
              ctx.fillStyle = cssVar(hot ? '--band-hot' : ev.full ? '--band' : '--band-quiet');
              ctx.fillRect(x0, top, Math.max(x1 - x0, minW), height);
            }
            ctx.restore();
          },
        ],
        draw: [
          (u) => {
            const { ctx, top, height } = bandCtx(u);
            ctx.strokeStyle = cssVar('--note');
            ctx.fillStyle = cssVar('--note');
            ctx.lineWidth = devicePixelRatio;
            ctx.setLineDash([4 * devicePixelRatio, 3 * devicePixelRatio]);
            ctx.font = `${11 * devicePixelRatio}px ${cssVar('--font')}`;
            for (const n of state.notes) {
              const x = Math.round(u.valToPos(n.ts / 1000, 'x', true)) + 0.5;
              ctx.beginPath();
              ctx.moveTo(x, top);
              ctx.lineTo(x, top + height);
              ctx.stroke();
              if (chartIndex === 0) {
                const label = n.text.length > 32 ? n.text.slice(0, 31) + '…' : n.text;
                ctx.fillText(label, x + 4 * devicePixelRatio, top + 12 * devicePixelRatio);
              }
            }
            ctx.restore();
          },
        ],
      },
    };
  }

  function buildCharts() {
    plots.forEach((p) => p.destroy());
    plots = [];
    const host = $('#charts');
    host.querySelectorAll('.chart').forEach((el) => el.remove());
    const width = host.clientWidth;
    const axisFont = `12px ${cssVar('--font')}`;
    const axis = {
      stroke: cssVar('--muted'),
      font: axisFont,
      grid: { stroke: cssVar('--rule'), width: 1 },
      ticks: { stroke: cssVar('--rule'), width: 1, size: 4 },
    };

    CHARTS.forEach((def, i) => {
      const box = h('div', { class: 'chart', id: 'chart-' + def.id },
        h('div', { class: 'chart-head' }, h('h2', {}, def.title), h('span', { class: 'unit' }, def.unit)));
      host.append(box);

      const series = [{ label: 'Time', value: (u, v) => (v == null ? '–' : fmtWhen(v * 1000)) }];
      for (const s of def.series) {
        const color = cssVar(s.color);
        const cfg = {
          label: s.label,
          stroke: color,
          width: s.width || 1.5,
          dash: s.dash,
          value: (u, v) => s.fmt(v),
          points: { show: false },
        };
        if (s.fill) cfg.fill = rgba(color, s.fill);
        if (s.step) cfg.paths = uPlot.paths.stepped({ align: 1 });
        if (s.bars) {
          cfg.paths = uPlot.paths.bars({ size: [0.7, 40], align: 1 });
          cfg.fill = rgba(color, 0.55);
          cfg.width = 0;
        }
        if (s.dots) {
          cfg.paths = () => null;
          cfg.points = { show: true, size: 9, width: 2, stroke: color, fill: cssVar('--panel') };
        }
        series.push(cfg);
      }

      const opts = {
        width,
        height: def.height || 130,
        series,
        legend: { live: true },
        cursor: {
          sync: { key: 'sherlock' },
          drag: { x: true, y: false, setScale: false },
          points: { size: 6 },
        },
        scales: {
          x: { time: true, range: () => (state.shown ? [state.shown.from / 1000, state.shown.to / 1000] : [0, 1]) },
          y: { range: (u, min, max) => [0, def.yMax || (max > 0 ? max * 1.15 : 1)] },
        },
        axes: [
          // Only the bottom chart labels the time axis; the others keep the grid lines.
          i === CHARTS.length - 1 ? { ...axis } : { ...axis, size: 8, values: (u, vals) => vals.map(() => '') },
          { ...axis, size: 60, values: (u, vals) => vals.map((v) => (def.yMax ? v + '%' : compact(v))) },
        ],
        plugins: [overlay(i)],
        hooks: {
          setSelect: [
            (u) => {
              if (u.select.width < 4) return;
              const a = u.posToVal(u.select.left, 'x');
              const b = u.posToVal(u.select.left + u.select.width, 'x');
              u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
              zoomTo(a * 1000, b * 1000);
            },
          ],
        },
      };
      const empty = [[], ...def.series.map(() => [])];
      plots.push(new uPlot(opts, lastData ? dataFor(def, lastData) : empty, box));
    });
  }

  function compact(v) {
    if (v >= 1000) return (v / 1000).toFixed(v % 1000 ? 1 : 0) + 'k';
    if (v > 0 && v < 1) return v.toFixed(2);
    return String(v);
  }

  function dataFor(def, ser) {
    const n = ser.t.length;
    return [ser.t, ...def.series.map((s) => ser.series[s.key] || new Array(n).fill(null))];
  }

  // ---------- data refresh ----------
  let refreshing = false;
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const r = currentRange();
      const points = Math.max(200, Math.min(2000, Math.round($('#charts').clientWidth)));
      const q = `from=${Math.round(r.from)}&to=${Math.round(r.to)}`;
      const [ser, events, notes] = await Promise.all([
        api(`/api/series?${q}&points=${points}`),
        api(`/api/events?${q}`),
        api(`/api/notes?${q}`),
      ]);
      state.shown = r;
      state.events = events;
      state.notes = notes;
      lastData = ser;
      CHARTS.forEach((def, i) => plots[i].setData(dataFor(def, ser)));
      renderEvents();
    } catch (e) {
      toast('Could not load data: ' + e.message, true);
    } finally {
      refreshing = false;
    }
  }

  function zoomTo(from, to) {
    if (to - from < 10_000) {
      const mid = (from + to) / 2;
      from = mid - 5_000;
      to = mid + 5_000;
    }
    state.view = { from, to };
    $('#unzoom').hidden = false;
    document.querySelectorAll('.ranges [data-range]').forEach((b) => b.classList.remove('on'));
    refresh();
  }

  function goLive(span) {
    if (span) state.span = span;
    state.view = null;
    $('#unzoom').hidden = true;
    document.querySelectorAll('.ranges [data-range]').forEach((b) =>
      b.classList.toggle('on', Number(b.dataset.range) === state.span));
    refresh();
  }

  function redrawOverlays() {
    plots.forEach((p) => p.redraw(false));
  }

  // ---------- events ----------
  function kindsLabel(kinds) {
    if (!kinds || !kinds.length) return 'Event';
    const first = KIND[kinds[0]] || kinds[0];
    return kinds.length > 1 ? `${first} +${kinds.length - 1}` : first;
  }

  function renderEvents() {
    const list = $('#event-list');
    list.replaceChildren();
    const full = state.events.filter((e) => e.full).length;
    $('#event-count').textContent = state.events.length ? `${full} in range` : '';
    $('#events-empty').hidden = state.events.length > 0;
    for (const ev of state.events) {
      const btn = h('button', {
        type: 'button',
        onmouseenter: () => { state.hot = ev.id; redrawOverlays(); },
        onmouseleave: () => { state.hot = null; redrawOverlays(); },
        onfocus: () => { state.hot = ev.id; redrawOverlays(); },
        onblur: () => { state.hot = null; redrawOverlays(); },
        onclick: () => (ev.full ? openDetail(ev) : zoomTo(ev.start - 60_000, ev.end + 60_000)),
      },
        h('span', { class: 'ev-time' }, fmtWhen(ev.start)),
        h('span', { class: 'ev-kind' }, kindsLabel(ev.kinds)),
        h('div', { class: 'ev-sum' }, ev.summary));
      list.append(h('li', { class: ev.full ? '' : 'quiet' }, btn));
    }
  }

  async function openDetail(ev) {
    state.detail = ev.id;
    $('#events-panel').hidden = true;
    const panel = $('#detail');
    const body = $('#detail-body');
    panel.hidden = false;
    body.replaceChildren(h('p', { class: 'when' }, 'Loading…'));
    let d;
    try {
      d = await api('/api/events/' + encodeURIComponent(ev.id));
    } catch (e) {
      body.replaceChildren(h('p', { class: 'when' }, e.message));
      return;
    }
    if (state.detail !== ev.id) return;
    if (!d.complete) {
      body.replaceChildren(
        h('h3', {}, kindsLabel(ev.kinds)),
        h('p', { class: 'when' }, 'Still recording. The snapshot finishes a few seconds after the trigger, once the recovery has been captured.'));
      setTimeout(() => state.detail === ev.id && openDetail(ev), 4000);
      return;
    }
    const base = '/api/events/' + encodeURIComponent(d.id) + '/files/';
    const iface = d.interface_at_trigger || {};
    const linkAt = !iface.up ? 'Down' : iface.speed_mbps > 0 ? fmtMbps(iface.speed_mbps) : 'Up, speed not reported';
    const facts = [
      ['Adapter', iface.name || '–'],
      ['Link at trigger', linkAt],
      ['Gateway', d.gateway || '–'],
      ['Window', `${fmtClock(d.window_start)} to ${fmtClock(d.end)}`],
    ];
    if (d.capture) facts.push(['Packets', d.capture.error ? `${d.capture.packets} (${d.capture.error})` : String(d.capture.packets)]);

    fill(body,
      h('h3', {}, kindsLabel(ev.kinds)),
      h('p', { class: 'when' }, `${fmtWhen(d.start)}, recorded for ${fmtDur(d.end - d.start)} after the trigger`),
      h('h4', {}, 'What happened'),
      h('ol', { class: 'triggers' }, d.triggers.map((t) =>
        h('li', { class: t.info ? 'info' : '' }, h('time', {}, fmtClock(t.ts)), t.detail))),
      Array.isArray(d.notes) && d.notes.length > 0
        ? [h('h4', {}, 'Your notes'), h('ol', { class: 'triggers' }, d.notes.map((n) =>
            h('li', { class: 'info' }, h('time', {}, fmtClock(n.ts)), n.text)))]
        : null,
      h('h4', {}, 'Details'),
      h('dl', { class: 'facts' }, facts.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
      h('h4', {}, 'Files'),
      h('ul', { class: 'files' }, (d.files || []).map((f) =>
        h('li', {},
          h('a', { href: base + encodeURIComponent(f), target: f.endsWith('.pcap') ? null : '_blank', rel: 'noopener' }, f),
          h('span', { class: 'what' }, FILES[f] || '')))),
      h('button', { class: 'zoom', type: 'button', onclick: () => zoomTo(d.window_start - 10_000, d.end + 30_000) },
        'Show this window on the charts'));
  }

  function closeDetail() {
    state.detail = null;
    $('#detail').hidden = true;
    $('#events-panel').hidden = false;
  }

  // ---------- status ----------
  function setVital(id, value, sub, level, title) {
    const el = $('#v-' + id);
    el.querySelector('.vv').textContent = value;
    el.querySelector('.vs').textContent = sub;
    el.classList.toggle('warn', level === 'warn');
    el.classList.toggle('bad', level === 'bad');
    if (title) el.title = title;
  }

  function probeVital(id, p, rttWarn) {
    if (!p || !p.addr) return setVital(id, '–', 'not configured');
    if (!p.samples) return setVital(id, '–', 'waiting', null, p.addr);
    const lostNow = p.last_rtt_ms == null;
    const level = lostNow || p.loss_pct >= 20 ? 'bad' : p.loss_pct > 0 || (rttWarn && p.last_rtt_ms > rttWarn) ? 'warn' : null;
    setVital(id, lostNow ? 'No reply' : fmtMs(p.last_rtt_ms), `${fmtPct(p.loss_pct)} lost recently`, level, p.addr);
  }

  async function pollStatus() {
    let s;
    try {
      s = await api('/api/status');
    } catch {
      $('#adapter').textContent = 'Sherlock is not responding';
      return;
    }
    state.status = s;
    const i = s.interface || {};
    $('#adapter').textContent = s.interface_error
      ? s.interface_error
      : [i.name, i.description].filter(Boolean).join(', ');

    if (!i.up) setVital('link', 'Down', s.interface_error ? 'adapter missing' : 'no link', 'bad');
    else {
      const slow = i.speed_mbps > 0 && i.speed_mbps < 1000;
      const errs = (i.rx_errors || 0) + (i.tx_errors || 0);
      setVital('link', i.speed_mbps ? fmtMbps(i.speed_mbps) : 'Up',
        slow ? 'below gigabit' : `${errs} errors since boot`, slow ? 'warn' : null);
    }
    probeVital('gateway', s.probes.gateway, 20);
    probeVital('internet', s.probes.internet);
    probeVital('dns', s.probes.dns);
    setVital('traffic', fmtMbps(s.traffic_mbps), 'last 10 s');

    const rec = $('#recording');
    rec.hidden = !s.active_event;
    if (s.active_event) {
      $('#recording-text').textContent =
        'Recording an event. Sherlock is saving the lead-up and watching the recovery.';
    }

    // capture
    const c = s.capture;
    const sw = $('#capture-switch');
    sw.setAttribute('aria-checked', String(!!c.enabled));
    const cn = $('#capture-note');
    cn.classList.toggle('bad', !!c.error);
    cn.textContent = c.error
      ? c.error
      : !c.enabled
        ? 'Off. Events still record metrics and system state, just no packets.'
        : c.running
          ? `${c.packets.toLocaleString()} packet headers seen this session${c.dropped ? `, ${c.dropped.toLocaleString()} dropped by the driver` : ''}. Only the last couple of minutes are kept on disk.`
          : 'Starting…';

    // throughput
    const t = s.throughput;
    document.querySelectorAll('#mode [data-mode]').forEach((b) =>
      b.setAttribute('aria-checked', String(b.dataset.mode === t.mode)));
    const tn = $('#tput-note');
    tn.classList.remove('bad');
    let note;
    if (!t.configured) note = 'Set throughput.server in sherlock.json to your iperf3 server to use this.';
    else if (t.running) note = `Testing against ${t.server}…`;
    else if (t.mode === 'off') note = 'Off. No tests will run, so nothing competes with your games.';
    else {
      const parts = [];
      if (t.last) {
        if (t.last.error) { parts.push(`Last test failed ${ago(t.last.ts)}: ${t.last.error}`); tn.classList.add('bad'); }
        else parts.push(`Last: ${fmtMbps(t.last.down_mbps)} down, ${fmtMbps(t.last.up_mbps)} up, ${ago(t.last.ts)}.`);
      }
      if (t.skip) parts.push(t.skip + '.');
      if (t.mode === 'scheduled' && t.next_run) {
        const mins = Math.max(0, Math.round((t.next_run - Date.now()) / 60000));
        parts.push(mins ? `Next run in about ${mins} min.` : 'Next run within a minute.');
      }
      if (!parts.length) parts.push(`Ready to test against ${t.server}.`);
      note = parts.join(' ');
    }
    tn.textContent = note;
    $('#run-test').disabled = !t.configured || t.mode === 'off' || t.running;
    $('#run-test').textContent = t.running ? 'Testing…' : 'Run speed test';
  }

  // ---------- wiring ----------
  document.querySelectorAll('.ranges [data-range]').forEach((b) =>
    b.addEventListener('click', () => goLive(Number(b.dataset.range))));
  $('#unzoom').addEventListener('click', () => goLive());
  $('#detail-back').addEventListener('click', closeDetail);

  $('#note-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('#note-text');
    const text = input.value.trim();
    if (!text) return input.focus();
    try {
      await post('/api/notes', { text });
      input.value = '';
      toast('Note added');
      refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $('#capture-switch').addEventListener('click', async () => {
    const on = $('#capture-switch').getAttribute('aria-checked') !== 'true';
    try {
      await post('/api/capture', { enabled: on });
      toast(on ? 'Capture on' : 'Capture off');
    } catch (err) {
      toast(err.message, true);
    }
    pollStatus();
  });

  document.querySelectorAll('#mode [data-mode]').forEach((b) =>
    b.addEventListener('click', async () => {
      try {
        await post('/api/throughput/mode', { mode: b.dataset.mode });
      } catch (err) {
        toast(err.message, true);
      }
      pollStatus();
    }));

  $('#run-test').addEventListener('click', async () => {
    try {
      await post('/api/throughput/run');
      toast('Speed test started');
      setTimeout(pollStatus, 300);
    } catch (err) {
      toast(err.message, true);
    }
  });

  new ResizeObserver(() => {
    const w = $('#charts').clientWidth;
    plots.forEach((p, i) => p.setSize({ width: w, height: CHARTS[i].height || 130 }));
  }).observe($('#charts'));

  matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
    buildCharts();
  });

  // Live mode refreshes often for short ranges and rarely for long ones.
  // Nothing polls while the tab is hidden, so a background tab costs nothing.
  let ticks = 0;
  setInterval(() => {
    if (document.hidden) return;
    ticks++;
    if (ticks % 2 === 0) pollStatus();
    const every = state.span <= 3_600_000 ? 5 : 30;
    if (!state.view && ticks % (every) === 0) refresh();
  }, 1000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) { pollStatus(); if (!state.view) refresh(); }
  });

  buildCharts();
  pollStatus();
  refresh();
})();
