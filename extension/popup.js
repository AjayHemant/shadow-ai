const BASE = 'http://127.0.0.1:5000';

async function load() {
    try {
        const [statsRes, alertsRes] = await Promise.all([
            fetch(`${BASE}/api/stats`),
            fetch(`${BASE}/api/alerts`),
        ]);
        const stats = await statsRes.json();
        const alerts = await alertsRes.json();

        document.getElementById('numBlocked').textContent = stats.blocked ?? 0;
        document.getElementById('numWarned').textContent = stats.warned ?? 0;
        document.getElementById('numAllowed').textContent = stats.allowed ?? 0;

        renderAlerts(alerts.slice(0, 10));
        setOnline(true);
    } catch (e) {
        setOnline(false);
    }
}

function setOnline(on) {
    const bar = document.getElementById('statusBar');
    bar.innerHTML = on
        ? `<div style="display:flex;align-items:center;">
         <span class="status-dot"></span>
         <span class="status-text">DLP Active — Monitoring all sites</span>
       </div>`
        : `<div style="display:flex;align-items:center;">
         <span class="offline-dot"></span>
         <span class="offline-text">Backend offline — start dashboard.py</span>
       </div>`;
}

function renderAlerts(alerts) {
    const el = document.getElementById('alertList');
    if (!alerts.length) {
        el.innerHTML = '<div class="empty">No alerts yet — send a test message!</div>';
        return;
    }
    el.innerHTML = alerts.map(a => {
        const t = new Date(a.timestamp + 'Z').toLocaleTimeString('en-GB', { hour12: false });
        return `<div class="alert-item">
      <span class="alert-time">${t}</span>
      <span class="alert-dest">${esc(a.destination)}</span>
      <span class="action-badge ${a.action}">${a.action}</span>
    </div>`;
    }).join('');
}

function openDash() {
    chrome.tabs.create({ url: `${BASE}/` });
}

async function clearAll() {
    try {
        await fetch(`${BASE}/api/clear`, { method: 'POST' });
        load();
    } catch (e) { }
}

function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

load();
