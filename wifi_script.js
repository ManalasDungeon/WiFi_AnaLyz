(function() {
'use strict';
const $ = id => document.getElementById(id);
const enc = s => (s||'').replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);

// ── Alkutila ──────────────────────────────────────────────────────
let state  = JSON.parse($('__initial').textContent);
let alerts = JSON.parse($('__alerts').textContent);

// ── Asiakaspuoli: RSSI-historia per BSSID (sparklines) ───────────
const rssiHistory = {};   
const HIST_MAX    = 40;   

function pushHistory(bssid, rssi) {
  if (!rssiHistory[bssid]) rssiHistory[bssid] = [];
  rssiHistory[bssid].push({ t: Date.now(), v: rssi });
  if (rssiHistory[bssid].length > HIST_MAX) rssiHistory[bssid].shift();
}

(state.Networks || []).forEach(ap => pushHistory(ap.Bssid, ap.Rssi));

// ── Chart.js ─────────────────────────────────────────────────────
Chart.defaults.color = '#9ca3af';
Chart.defaults.borderColor = '#1e2840';
Chart.defaults.font.family = 'system-ui,sans-serif';
Chart.defaults.font.size   = 11;

const rssiColor = r => r>=-50?'#10b981':r>=-60?'#3b82f6':r>=-70?'#f59e0b':r>=-80?'#f97316':'#ef4444';
const secClass  = s => /3/.test(s)?'sec-wpa3':/Ent/.test(s)?'sec-wpa2':/2/.test(s)?'sec-wpa2':
                       s==='WPA'?'sec-wpa':s==='Open'?'sec-open':'';
const secColor  = s => /3/.test(s)?'#10b981':/2/.test(s)?'#3b82f6':s==='WPA'?'#f59e0b':
                       s==='Open'?'#ef4444':'#6b7280';
const barColor  = r => r>=-55?'#10b981':r>=-65?'#3b82f6':r>=-75?'#f59e0b':r>=-85?'#f97316':'#ef4444';
const barPct    = r => Math.max(2, Math.min(100, Math.round((r+100)/70*100)));

const CHART_ANIM = { duration:400, easing:'easeOutQuart' };

const charts = {};
function buildCharts() {
  charts.rssi = new Chart($('c-rssi'), {
    type:'bar',
    data:{labels:[],datasets:[{data:[],backgroundColor:[],borderRadius:5,borderWidth:0}]},
    options:{plugins:{legend:{display:false}},animation:CHART_ANIM,
             scales:{y:{min:-100,max:-20,title:{display:true,text:'dBm'}}}}
  });
  charts.ch = new Chart($('c-ch'), {
    type:'bar',
    data:{labels:[],datasets:[{data:[],backgroundColor:'#3b82f6',borderRadius:5,borderWidth:0}]},
    options:{plugins:{legend:{display:false}},animation:CHART_ANIM,
             scales:{y:{ticks:{stepSize:1}}}}
  });
  charts.sec = new Chart($('c-sec'), {
    type:'doughnut',
    data:{labels:[],datasets:[{data:[],backgroundColor:[],borderWidth:2,borderColor:'#131826'}]},
    options:{plugins:{legend:{position:'bottom'}},animation:CHART_ANIM}
  });
  charts.score = new Chart($('c-score'), {
    type:'bar',
    data:{labels:[],datasets:[{data:[],backgroundColor:'#3b82f6',borderRadius:5,borderWidth:0}]},
    options:{indexAxis:'y',plugins:{legend:{display:false}},animation:CHART_ANIM}
  });
}

// ── Lajittelu ────────────────────────────────────────────────────
let sortCol = 'Rssi', sortAsc = false, filterStr = '';
document.querySelectorAll('thead th[data-col]').forEach(th => {
  if (th.classList.contains('no-sort')) return;
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = col === 'Ssid' || col === 'Vendor'; }
    document.querySelectorAll('thead th').forEach(t => t.classList.remove('sorted-asc','sorted-desc'));
    th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
    renderTable(state.Networks || []);
  });
});

$('filter').addEventListener('input', e => {
  filterStr = e.target.value.toLowerCase().trim();
  renderTable(state.Networks || []);
});

function sortAps(aps) {
  return [...aps].sort((a, b) => {
    let av, bv;
    if (sortCol === '_int') { av = (a.CoChannelCount||0)+(a.AdjacentOverlapCount||0); bv = (b.CoChannelCount||0)+(b.AdjacentOverlapCount||0); }
    else { av = a[sortCol] ?? ''; bv = b[sortCol] ?? ''; }
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ?  1 : -1;
    return 0;
  });
}

// ── Sparkline Canvas ─────────────────────────────────────────────
function drawSparkline(canvas, bssid) {
  const hist = rssiHistory[bssid] || [];
  const ctx  = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  if (hist.length < 2) {
    ctx.fillStyle = '#374151'; ctx.fillRect(0, H/2-1, W, 2); return;
  }
  const MIN = -100, MAX = -30, RANGE = MAX - MIN;
  const pts = hist.slice(-30);
  const step = W / (pts.length - 1);

  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(59,130,246,.3)');
  grad.addColorStop(1, 'rgba(59,130,246,0)');
  ctx.fillStyle = grad;
  ctx.beginPath();
  pts.forEach((p, i) => {
    const x = i * step, y = H - Math.max(1, Math.min(H-1, (p.v - MIN) / RANGE * H));
    i === 0 ? ctx.moveTo(x, H) : void 0;
    ctx.lineTo(x, y);
  });
  ctx.lineTo((pts.length-1)*step, H); ctx.closePath(); ctx.fill();

  ctx.strokeStyle = barColor(pts[pts.length-1].v);
  ctx.lineWidth = 1.5; ctx.lineJoin = 'round';
  ctx.beginPath();
  pts.forEach((p, i) => {
    const x = i * step, y = H - Math.max(1, Math.min(H-1, (p.v - MIN) / RANGE * H));
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
}

// ── Taulukko ─────────────────────────────────────────────────────
const prevRssi = {};

function renderTable(aps) {
  const filtered = filterStr ? aps.filter(a => (a.Ssid||'').toLowerCase().includes(filterStr)) : aps;
  const sorted   = sortAps(filtered);
  $('net-count').textContent = '(' + sorted.length + (filterStr ? ' / ' + aps.length : '') + ')';
  const tbody = $('ap-tbody');

  const existing = {};
  Array.from(tbody.querySelectorAll('tr[data-bssid]')).forEach(tr => existing[tr.dataset.bssid] = tr);

  const fragment = document.createDocumentFragment();
  sorted.forEach(ap => {
    const bssid = ap.Bssid || '';
    const pct   = barPct(ap.Rssi);
    const bc    = barColor(ap.Rssi);
    const g     = ap.Grade || 'F';
    const trend = ap.SignalTrend > 1.5 ? '↑ +'+ap.SignalTrend.toFixed(1) :
                  ap.SignalTrend < -1.5? '↓ '+ap.SignalTrend.toFixed(1) : '→';
    const trendCls = ap.SignalTrend > 1.5 ? 'success' : ap.SignalTrend < -1.5 ? 'error' : 'muted';
    const util  = ap.ChannelUtilization != null ? ap.ChannelUtilization + '%' : '—';
    const int   = (ap.CoChannelCount||0) + (ap.AdjacentOverlapCount||0);
    const mesh  = ap.MeshNote ? ' <span class="muted small">'+enc(ap.MeshNote)+'</span>' : '';

    let tr = existing[bssid];
    const isNew = !tr;
    if (isNew) {
      tr = document.createElement('tr');
      tr.dataset.bssid = bssid;
    }
    if (ap.IsConnected) tr.classList.add('connected-row');
    else                tr.classList.remove('connected-row');

    if (!isNew && prevRssi[bssid] !== undefined && prevRssi[bssid] !== ap.Rssi) {
      tr.classList.remove('flash');
      void tr.offsetWidth;
      tr.classList.add('flash');
    }
    prevRssi[bssid] = ap.Rssi;

    tr.innerHTML =
      '<td>' + (ap.IsConnected ? '<span class="success">★</span> ' : '') +
               enc(ap.Ssid || '<piilotettu>') + mesh + '</td>' +
      '<td class="mono grade-' + g + '">' + ap.Rssi + ' dBm</td>' +
      '<td>' +
        '<div class="rssi-bar-wrap"><div class="rssi-bar" style="width:' + pct + '%;background:' + bc + '"></div></div>' +
      '</td>' +
      '<td><canvas class="spark" width="60" height="24" data-bssid="' + enc(bssid) + '"></canvas></td>' +
      '<td>' + (ap.Channel||'?') + '</td>' +
      '<td class="muted">' + enc(ap.Band||'') + '</td>' +
      '<td class="' + secClass(ap.Security||'') + '">' + enc(ap.Security||'?') + '</td>' +
      '<td class="' + (int>=4?'error':int>=2?'warn':'muted') + '">' + int + '</td>' +
      '<td class="muted">' + util + '</td>' +
      '<td class="muted">±' + (ap.SignalJitter||0).toFixed(1) + '</td>' +
      '<td class="accent">' + (ap.Score||0).toFixed(1) + '</td>' +
      '<td class="' + trendCls + '">' + trend + '</td>' +
      '<td class="muted small">' + enc(ap.Vendor||'') + '</td>';

    fragment.appendChild(tr);
  });

  tbody.innerHTML = '';
  tbody.appendChild(fragment);

  tbody.querySelectorAll('canvas.spark').forEach(c => {
    drawSparkline(c, c.dataset.bssid);
  });
}

function renderCharts(aps) {
  const top = [...aps].sort((a,b)=>a.Rssi-b.Rssi).slice(0,15);
  charts.rssi.data.labels = top.map(a => a.Ssid || '?');
  charts.rssi.data.datasets[0].data = top.map(a => a.Rssi);
  charts.rssi.data.datasets[0].backgroundColor = top.map(a => rssiColor(a.Rssi));
  charts.rssi.update();

  const chCount = {};
  aps.forEach(a => { if (a.Channel>0) chCount[a.Channel]=(chCount[a.Channel]||0)+1; });
  const chKeys = Object.keys(chCount).map(Number).sort((a,b)=>a-b);
  charts.ch.data.labels = chKeys.map(k=>'CH'+k);
  charts.ch.data.datasets[0].data = chKeys.map(k=>chCount[k]);
  charts.ch.update();

  const sec = {};
  aps.forEach(a=>{const k=a.Security||'?';sec[k]=(sec[k]||0)+1;});
  const secKeys = Object.keys(sec).sort((a,b)=>sec[b]-sec[a]);
  charts.sec.data.labels = secKeys;
  charts.sec.data.datasets[0].data = secKeys.map(k=>sec[k]);
  charts.sec.data.datasets[0].backgroundColor = secKeys.map(secColor);
  charts.sec.update();

  const scoreTop = [...aps].sort((a,b)=>(b.Score||0)-(a.Score||0)).slice(0,10);
  charts.score.data.labels = scoreTop.map(a=>a.Ssid||'?');
  charts.score.data.datasets[0].data = scoreTop.map(a=>a.Score);
  charts.score.update();
}

let knownAlertTimes = new Set(alerts.map(a=>a.Time));

function renderAlerts(list) {
  const section = $('alerts-section');
  if (!list || list.length === 0) { section.hidden = true; return; }
  section.hidden = false;
  $('alert-count-badge').textContent = '(' + list.length + ')';
  $('alert-list').innerHTML = list.slice(0,30).map(a=>{
    const t = new Date(a.Time).toLocaleTimeString('fi-FI');
    const cls = 'alert-row type-' + (a.Type||'');
    return '<div class="'+cls+'"><span class="alert-ts">'+t+'</span>' +
           '<span class="alert-type">'+enc(a.Type)+'</span>' +
           '<span class="alert-msg">'+enc(a.Bssid||'')+(a.Bssid?' — ':'')+enc(a.Message)+'</span></div>';
  }).join('');
}

function checkNewAlerts(list) {
  if (!list) return;
  list.forEach(a => {
    if (!knownAlertTimes.has(a.Time)) {
      knownAlertTimes.add(a.Time);
      showToast(a);
    }
  });
}

function showToast(alert) {
  const el   = document.createElement('div');
  const tCls = alert.Type==='EvilTwin'?'t-evil':alert.Type==='NewAP'?'t-ok':'';
  const icon = alert.Type==='EvilTwin'?'🚨':alert.Type==='WeakSignal'?'📶':
               alert.Type==='NewAP'?'🆕':alert.Type==='Roaming'?'📍':'ℹ️';
  el.className = 'toast ' + tCls;
  el.innerHTML = '<div class="toast-type">' + icon + ' ' + enc(alert.Type) + '</div>' +
                 '<div>' + enc(alert.Message) + '</div>';
  $('toasts').appendChild(el);
  setTimeout(()=>{
    el.classList.add('out');
    setTimeout(()=>el.remove(), 260);
  }, 4500);
}

function updateScanStatus(d) {
  const pill  = $('scan-pill');
  const dot   = $('scan-dot');
  const label = $('scan-label');
  const running = !!d.IsScanRunning;
  pill.classList.toggle('running', running);
  dot.classList.toggle('running', running);
  const status = d.ScanStatus || '';
  const short  = running ? 'Skannaus...' :
                 status.includes('valmis') ? 'Valmis ✓' :
                 status.includes('virhe')  ? 'Virhe ⚠'  : 'Valmiustila';
  label.textContent = short;
  label.title = status;
}

function updateSpeed(speed) {
  if (!speed) return;
  $('s-ping').textContent = speed.PingMs < 0 ? '—' : Math.round(speed.PingMs) + '';
  $('s-dl').textContent   = speed.ThroughputKBs > 0 ? Math.round(speed.ThroughputKBs) + '' : '—';
  $('s-ping').style.color = speed.PingMs > 100 ? 'var(--warn)' :
                            speed.PingMs > 30  ? 'var(--accent)' : 'var(--success)';
}

function render(d) {
  if (!d) return;
  const aps = d.Networks || [];
  aps.forEach(a => pushHistory(a.Bssid, a.Rssi));
  if (d.Timestamp) $('ts').textContent = new Date(d.Timestamp).toLocaleString('fi-FI');
  if (d.BestChannel) $('best-ch').textContent = d.BestChannel;

  $('s-total').textContent  = aps.length;
  $('s-wpa3').textContent   = aps.filter(a=>/3/.test(a.Security||'')).length;
  $('s-open').textContent   = aps.filter(a=>a.Security==='Open').length;
  $('s-alerts').textContent = d.AlertCount || 0;

  renderTable(aps);
  renderCharts(aps);
  updateScanStatus(d);
  updateSpeed(d.Speed);

  if (d.RecentAlerts) checkNewAlerts(d.RecentAlerts);
}

let retryDelay = 1000;
let sseActive  = false;
let evt        = null;

function setConnStatus(status) {
  const dot   = $('conn-dot');
  const label = $('conn-label');
  dot.className   = 'conn-dot ' + status;
  label.textContent = status==='live'?'Live':status==='connecting'?'Yhdistää...':'Katkaistu';
}

function connect() {
  if (sseActive) return;
  sseActive = true;
  setConnStatus('connecting');
  try {
    evt = new EventSource('/api/events');
    evt.onopen = () => {
      setConnStatus('live');
      retryDelay = 1000;
    };
    evt.onmessage = e => {
      try {
        const d = JSON.parse(e.data);
        state = d;
        render(d);
        if (d.RecentAlerts) {
          alerts = d.RecentAlerts;
          renderAlerts(d.RecentAlerts.slice().reverse());
        }
        setConnStatus('live');
      } catch(err) { console.warn('SSE parse:', err); }
    };
    evt.onerror = () => {
      sseActive = false;
      setConnStatus('offline');
      try { evt.close(); } catch(e) {}
      retryDelay = Math.min(retryDelay * 2, 16000);
      setTimeout(connect, retryDelay);
    };
  } catch(err) {
    sseActive = false;
    setConnStatus('offline');
  }
}

buildCharts();
render(state);
renderAlerts(alerts.slice().reverse());

if (location.protocol === 'http:' || location.protocol === 'https:') {
  connect();
} else {
  setConnStatus('offline');
  $('conn-label').textContent = 'Staattinen tiedosto';
}
})();