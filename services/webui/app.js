const state = {
  generatedAt: null,
  leases: [],
  dnsRecords: [],
  staticHosts: [],
};

const els = {};

function q(id) {
  const el = document.getElementById(id);
  els[id] = el;
  return el;
}

q('generated-at');
q('feed-status');
q('lease-count');
q('dns-count');
q('static-count');
q('lease-body');
q('dns-body');
q('static-body');
q('lease-filter');
q('dns-filter');
q('static-filter');

function canonical(v) {
  return String(v || '').trim().toLowerCase();
}

function esc(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function splitFields(value) {
  return canonical(value).split(/\s+/).filter(Boolean);
}

function globToRegex(pattern) {
  let escaped = '';
  for (const ch of pattern) {
    if (ch === '*') {
      escaped += '.*';
    } else if (ch === '?') {
      escaped += '.';
    } else if ('.+^${}[]()|\\'.includes(ch)) {
      escaped += '\\' + ch;
    } else {
      escaped += ch;
    }
  }
  return escaped;
}

function matchesWildcard(row, term) {
  if (!term) return true;
  const terms = splitFields(term);
  const rowText = canonical(Object.values(row).join(' '));
  for (const t of terms) {
    const regex = globToRegex(t);
    try {
      if (!new RegExp(regex).test(rowText)) return false;
    } catch {
      if (!rowText.includes(t)) return false;
    }
  }
  return true;
}

function formatTime(value) {
  if (!value) return 'n/a';
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value);
  return new Intl.DateTimeFormat([], {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(dt);
}

function replaceByKey(list, item) {
  const idx = list.findIndex(e => e.key === item.key);
  if (idx >= 0) { list[idx] = item; return; }
  list.unshift(item);
}

// ── Table Component ──────────────────────────────────────────

const tableSort = {};

function makeTable(config) {
  const { tbodyId, filterId, countId, columns, renderRow, dataKey } = config;
  const tbody = document.getElementById(tbodyId);
  const filter = document.getElementById(filterId);
  const count = countId ? document.getElementById(countId) : null;

  let data = [];
  let sortCol = null;
  let sortDir = 'asc';

  function setData(d) { data = d; render(); }
  function getData() { return data; }

  function getValue(row, col) {
    let v = row[col.key];
    if (col.sortKey) v = row[col.sortKey];
    if (col.type === 'time' && v) {
      try { return new Date(v).getTime(); } catch { return 0; }
    }
    if (col.type === 'ip' && v) {
      const parts = v.split('.');
      if (parts.length === 4) {
        return parts.reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0);
      }
    }
    return canonical(v);
  }

  function sortRows(rows) {
    if (!sortCol) return rows;
    const col = columns.find(c => c.key === sortCol);
    if (!col) return rows;
    return [...rows].sort((a, b) => {
      const va = getValue(a, col);
      const vb = getValue(b, col);
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  function render() {
    const term = canonical(filter.value);
    let filtered = data.filter(row => matchesWildcard(row, term));
    filtered = sortRows(filtered);

    tbody.innerHTML = '';
    if (filtered.length === 0) {
      const tr = document.createElement('tr');
      tr.className = 'empty-row';
      const td = document.createElement('td');
      td.colSpan = columns.length;
      td.textContent = 'No matching entries.';
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      for (const row of filtered) {
        tbody.appendChild(renderRow(row));
      }
    }
    if (count) count.textContent = String(data.length);
    return filtered.length;
  }

  function handleSort(colKey) {
    if (sortCol === colKey) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortCol = colKey;
      sortDir = 'asc';
    }
    updateSortIndicators();
    render();
  }

  function updateSortIndicators() {
    document.querySelectorAll(`#${tbodyId.replace('-body', '-section')} thead th`).forEach(th => {
      const key = th.dataset.sort;
      const arrow = th.querySelector('.sort-arrow');
      if (key === sortCol && arrow) {
        arrow.textContent = sortDir === 'asc' ? ' \u2191' : ' \u2193';
        arrow.classList.add('active');
      } else if (arrow) {
        arrow.textContent = ' \u2195';
        arrow.classList.remove('active');
      }
    });
  }

  const thead = document.querySelector(`#${tbodyId.replace('-body', '-section')} thead`);
  if (thead) {
    thead.querySelectorAll('th[data-sort]').forEach(th => {
      const key = th.dataset.sort;
      const arrow = document.createElement('span');
      arrow.className = 'sort-arrow';
      arrow.textContent = ' \u2195';
      th.appendChild(arrow);
      th.addEventListener('click', () => handleSort(key));
    });
  }

  filter.addEventListener('input', render);

  return { setData, getData, render };
}

// ── Tables ────────────────────────────────────────────────────

const leaseTable = makeTable({
  tbodyId: 'lease-body',
  filterId: 'lease-filter',
  countId: 'lease-count',
  sectionId: 'leases-section',
  columns: [
    { key: 'hostname' },
    { key: 'hardwareAddr' },
    { key: 'address', type: 'ip' },
    { key: 'interface' },
    { key: 'leaseUntil', type: 'time', sortKey: 'leaseUntil' },
    { key: 'updatedAt', type: 'time', sortKey: 'updatedAt' },
  ],
  renderRow(row) {
    const tr = document.createElement('tr');
    const cells = [
      row.hostname || 'n/a',
      row.hardwareAddr || 'n/a',
      row.address || 'n/a',
      row.interface || 'n/a',
      formatTime(row.leaseUntil),
      formatTime(row.updatedAt),
    ];
    for (const val of cells) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    }
    return tr;
  },
});

const dnsTable = makeTable({
  tbodyId: 'dns-body',
  filterId: 'dns-filter',
  countId: 'dns-count',
  sectionId: 'dns-section',
  columns: [
    { key: 'name' },
    { key: 'type' },
    { key: 'address', type: 'ip' },
    { key: 'cname' },
    { key: 'updatedAt', type: 'time', sortKey: 'updatedAt' },
  ],
  renderRow(row) {
    const tr = document.createElement('tr');
    const nameTd = document.createElement('td');
    nameTd.textContent = row.name || 'n/a';
    tr.appendChild(nameTd);

    const typeTd = document.createElement('td');
    const chip = document.createElement('span');
    chip.className = 'chip' + (row.type === 'A' ? ' good' : row.type === 'CNAME' ? ' warn' : '');
    chip.textContent = row.type || 'unknown';
    typeTd.appendChild(chip);
    tr.appendChild(typeTd);

    const addrTd = document.createElement('td');
    addrTd.textContent = row.address || 'n/a';
    tr.appendChild(addrTd);

    const cnameTd = document.createElement('td');
    cnameTd.textContent = row.cname || 'n/a';
    tr.appendChild(cnameTd);

    const updTd = document.createElement('td');
    updTd.textContent = formatTime(row.updatedAt);
    tr.appendChild(updTd);

    return tr;
  },
});

const staticTable = makeTable({
  tbodyId: 'static-body',
  filterId: 'static-filter',
  countId: 'static-count',
  sectionId: 'static-section',
  columns: [
    { key: 'hostname' },
    { key: 'hardwareAddr' },
    { key: 'address', type: 'ip' },
  ],
  renderRow(row) {
    const tr = document.createElement('tr');
    const cells = [
      row.hostname || 'n/a',
      row.hardwareAddr || 'n/a',
      row.address || 'n/a',
    ];
    for (const val of cells) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    }
    return tr;
  },
});

// ── State Management ──────────────────────────────────────────

function applySnapshot(snapshot) {
  state.generatedAt = snapshot.generatedAt || null;
  state.leases = Array.isArray(snapshot.leases) ? snapshot.leases : [];
  state.dnsRecords = Array.isArray(snapshot.dnsRecords) ? snapshot.dnsRecords : [];
  state.staticHosts = Array.isArray(snapshot.staticHosts) ? snapshot.staticHosts : [];
  renderAll();
}

function upsertLease(lease) {
  if (!lease || !lease.key) return;
  replaceByKey(state.leases, lease);
  renderAll();
}

function upsertDNS(record) {
  if (!record || !record.name) return;
  replaceByKey(state.dnsRecords, record);
  renderAll();
}

function upsertStatic(entry) {
  if (!entry || !entry.hostname) return;
  const idx = state.staticHosts.findIndex(s => s.hostname === entry.hostname && s.hardwareAddr === entry.hardwareAddr);
  if (idx >= 0) { state.staticHosts[idx] = entry; }
  else { state.staticHosts.push(entry); }
  renderAll();
}

function renderAll() {
  els['generated-at'].textContent = state.generatedAt ? formatTime(state.generatedAt) : '--';
  leaseTable.setData(state.leases);
  dnsTable.setData(state.dnsRecords);
  staticTable.setData(state.staticHosts);
}

async function loadState() {
  const resp = await fetch('/api/state', { cache: 'no-store' });
  if (!resp.ok) throw new Error('failed to load state');
  applySnapshot(await resp.json());
}

function connectFeed() {
  const source = new EventSource('/events');
  source.addEventListener('open', () => {
    els['feed-status'].textContent = 'connected';
    els['feed-status'].className = 'status-connected';
  });
  source.addEventListener('snapshot', e => applySnapshot(JSON.parse(e.data)));
  source.addEventListener('lease', e => upsertLease(JSON.parse(e.data)));
  source.addEventListener('dns', e => upsertDNS(JSON.parse(e.data)));
  source.addEventListener('static', e => upsertStatic(JSON.parse(e.data)));
  source.onerror = () => {
    els['feed-status'].textContent = 'reconnecting';
    els['feed-status'].className = 'status-reconnecting';
  };
  return source;
}

// ── Network Map (Cytoscape) ───────────────────────────────────

let cy = null;

const cyStyles = [
  {
    selector: 'node',
    style: {
      'background-color': '#3b82f6',
      label: 'data(label)',
      color: '#fafafa',
      'font-size': '12px',
      'font-family': 'Inter, sans-serif',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 6,
      width: 32,
      height: 32,
    }
  },
  {
    selector: 'node[type="nettle"]',
    style: {
      'background-color': '#3b82f6',
      width: 48,
      height: 48,
      'font-size': '14px',
      'font-weight': 700,
      'text-valign': 'center',
      'text-halign': 'center',
      'text-margin-y': 0,
      color: '#fff',
    }
  },
  {
    selector: 'node[type="dhcp"]',
    style: {
      'background-color': '#22c55e',
      width: 28,
      height: 28,
    }
  },
  {
    selector: 'node[type="vpn"]',
    style: {
      'background-color': '#f59e0b',
      width: 28,
      height: 28,
    }
  },
  {
    selector: 'node[type="connect"]',
    style: {
      'background-color': '#a78bfa',
      width: 32,
      height: 32,
    }
  },
  {
    selector: 'edge',
    style: {
      width: 2,
      'line-color': 'rgba(255,255,255,0.12)',
      'target-arrow-color': 'rgba(255,255,255,0.12)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'straight',
      'arrow-scale': 0.8,
    }
  },
  {
    selector: 'edge[type="dhcp"]',
    style: {
      'line-color': 'rgba(34,197,94,0.3)',
      'target-arrow-color': 'rgba(34,197,94,0.3)',
    }
  },
  {
    selector: 'edge[type="vpn"]',
    style: {
      'line-color': 'rgba(245,158,11,0.3)',
      'target-arrow-color': 'rgba(245,158,11,0.3)',
    }
  },
  {
    selector: 'edge[type="connect"]',
    style: {
      'line-color': 'rgba(167,139,250,0.3)',
      'target-arrow-color': 'rgba(167,139,250,0.3)',
      'line-style': 'dashed',
    }
  },
];

function initCytoscape() {
  const container = document.getElementById('cy-network');
  cy = cytoscape({
    container,
    style: cyStyles,
    wheelSensitivity: 0.3,
    minZoom: 0.4,
    maxZoom: 3,
  });
  container.addEventListener('click', () => {
    if (cy) cy.resize();
  });
  setTimeout(() => { if (cy) cy.resize(); }, 0);
}

function buildNetworkElements(data) {
  const dhcp = Array.isArray(data.leases) ? data.leases : [];
  const vpn = Array.isArray(data.vpn) ? data.vpn : [];
  const connect = Array.isArray(data.connect) ? data.connect : [];

  const elements = [];

  elements.push({
    data: { id: 'nettle', label: 'Nettle', type: 'nettle' },
  });

  for (let i = 0; i < dhcp.length; i++) {
    const l = dhcp[i];
    const id = 'dhcp-' + i;
    elements.push({
      data: { id, label: l.hostname || l.address || '?', type: 'dhcp' },
    });
    elements.push({
      data: { id: id + '-edge', source: 'nettle', target: id, type: 'dhcp' },
    });
  }

  for (let i = 0; i < vpn.length; i++) {
    const p = vpn[i];
    const id = 'vpn-' + i;
    elements.push({
      data: { id, label: p.name || '?', type: 'vpn' },
    });
    elements.push({
      data: { id: id + '-edge', source: 'nettle', target: id, type: 'vpn' },
    });
  }

  for (let i = 0; i < connect.length; i++) {
    const t = connect[i];
    const id = 'conn-' + i;
    elements.push({
      data: { id, label: t.name || '?', type: 'connect' },
    });
    elements.push({
      data: { id: id + '-edge', source: 'nettle', target: id, type: 'connect' },
    });
  }

  return elements;
}

function renderNetworkMap(data) {
  if (!cy) initCytoscape();
  cy.elements().remove();
  const elements = buildNetworkElements(data);
  cy.add(elements);

  cy.layout({
    name: 'cose',
    idealEdgeLength: 150,
    nodeOverlap: 20,
    gravity: 80,
    edgeElasticity: 100,
    numIter: 1000,
    fit: true,
    padding: 50,
  }).run();

  cy.resize();
}

async function loadNetworkMap() {
  try {
    const resp = await fetch('/api/network', { cache: 'no-store' });
    if (!resp.ok) return;
    const data = await resp.json();
    renderNetworkMap(data);
  } catch {}
}

// ── VPN ───────────────────────────────────────────────────────

let vpnServerKey = '';

async function loadVPNPeers() {
  try {
    const resp = await fetch('/api/vpn/peers', { cache: 'no-store' });
    if (!resp.ok) {
      document.getElementById('vpn-panel').style.display = 'none';
      return;
    }
    document.getElementById('vpn-panel').style.display = '';
    const data = await resp.json();
    vpnServerKey = data.serverPubKey || '';
    renderVPNPeers(data.peers || []);
  } catch {
    document.getElementById('vpn-panel').style.display = 'none';
  }
}

function renderVPNPeers(peers) {
  const keyEl = document.getElementById('vpn-server-key');
  const qrEl = document.getElementById('vpn-server-qr');
  qrEl.innerHTML = '';
  if (vpnServerKey) {
    keyEl.textContent = vpnServerKey;
    if (typeof QRCode !== 'undefined') {
      new QRCode(qrEl, { text: vpnServerKey, width: 110, height: 110, colorDark: '#000', colorLight: '#fff' });
    }
  } else {
    keyEl.textContent = '';
  }

  const body = document.getElementById('vpn-peers-body');
  body.innerHTML = '';
  if (peers.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-row';
    const td = document.createElement('td');
    td.colSpan = 4;
    td.textContent = 'No VPN peers configured.';
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  for (const peer of peers) {
    const tr = document.createElement('tr');

    const nameTd = document.createElement('td');
    nameTd.textContent = peer.name || 'n/a';
    tr.appendChild(nameTd);

    const statusTd = document.createElement('td');
    const dot = document.createElement('span');
    dot.className = 'status-dot ' + (peer.connected ? 'on' : 'off');
    statusTd.appendChild(dot);
    statusTd.appendChild(document.createTextNode(peer.connected ? 'Connected' : 'Offline'));
    tr.appendChild(statusTd);

    const epTd = document.createElement('td');
    epTd.textContent = peer.endpoint || 'n/a';
    tr.appendChild(epTd);

    const actionTd = document.createElement('td');
    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove-btn';
    removeBtn.textContent = 'Remove';
    removeBtn.dataset.pubkey = peer.publicKey || '';
    removeBtn.addEventListener('click', () => removeVPNPeer(removeBtn.dataset.pubkey));
    actionTd.appendChild(removeBtn);
    tr.appendChild(actionTd);

    body.appendChild(tr);
  }
}

async function removeVPNPeer(pubKey) {
  if (!pubKey || !confirm('Remove this VPN peer?')) return;
  try {
    const resp = await fetch('/api/vpn/peers', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKey: pubKey }),
    });
    if (resp.ok) loadVPNPeers();
  } catch {}
}

document.getElementById('vpn-refresh').addEventListener('click', loadVPNPeers);

document.getElementById('vpn-generate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('vpn-name').value.trim();
  const endpoint = document.getElementById('vpn-endpoint').value.trim();
  if (!name || !endpoint) return;

  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Generating...';

  try {
    const resp = await fetch('/api/vpn/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, endpoint }),
    });
    if (!resp.ok) {
      const err = await resp.json();
      alert('Error: ' + (err.error || 'unknown'));
      return;
    }
    const data = await resp.json();
    showVPNResult(data);
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Generate config';
  }
});

function showVPNResult(data) {
  const result = document.getElementById('vpn-result');
  result.style.display = 'flex';

  document.getElementById('vpn-result-private').textContent = 'Private key: ' + (data.privateKey || '');
  document.getElementById('vpn-result-config').value = data.config || '';

  const qrEl = document.getElementById('vpn-result-qr');
  qrEl.innerHTML = '';
  if (typeof QRCode !== 'undefined' && data.config) {
    new QRCode(qrEl, { text: data.config, width: 160, height: 160, colorDark: '#000', colorLight: '#fff', correctLevel: QRCode.CorrectLevel.M });
  }

  document.getElementById('vpn-download-btn').onclick = () => {
    const blob = new Blob([data.config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (data.name || 'vpn-client') + '.conf';
    a.click();
    URL.revokeObjectURL(url);
  };

  loadVPNPeers();
}

// ── Connect ───────────────────────────────────────────────────

async function loadConnectTunnels() {
  try {
    const resp = await fetch('/api/connect/tunnels', { cache: 'no-store' });
    if (!resp.ok) {
      document.getElementById('connect-panel').style.display = 'none';
      return;
    }
    document.getElementById('connect-panel').style.display = '';
    const data = await resp.json();
    renderConnectGlue(data.glue || []);
    renderConnectTunnels(data.tunnels || []);
  } catch {
    document.getElementById('connect-panel').style.display = 'none';
  }
}

function renderConnectGlue(glueList) {
  const el = document.getElementById('connect-glue-info');
  const qrRow = document.getElementById('connect-glue-qr');
  qrRow.innerHTML = '';
  if (glueList.length === 0) {
    el.textContent = 'No glue addresses configured.';
    return;
  }
  const parts = glueList.map(g => {
    let s = 'Glue: ' + (g.address || '?') + ' \u2014 key: ' + (g.publicKey || '');
    if (g.localPrefixes && g.localPrefixes.length > 0) {
      s += ' \u2014 prefixes: ' + g.localPrefixes.join(', ');
    }
    return s;
  });
  el.innerHTML = parts.join('<br>');

  if (typeof QRCode !== 'undefined') {
    for (const g of glueList) {
      if (g.publicKey) {
        const wrap = document.createElement('div');
        wrap.className = 'qr-wrap';
        const label = document.createElement('span');
        label.textContent = g.address || '';
        wrap.appendChild(label);
        new QRCode(wrap, { text: g.publicKey, width: 100, height: 100, colorDark: '#000', colorLight: '#fff' });
        qrRow.appendChild(wrap);
      }
    }
  }
}

function renderConnectTunnels(tunnels) {
  const body = document.getElementById('connect-tunnels-body');
  body.innerHTML = '';
  if (tunnels.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-row';
    const td = document.createElement('td');
    td.colSpan = 5;
    td.textContent = 'No tunnels configured.';
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  for (const tun of tunnels) {
    const tr = document.createElement('tr');

    const localTd = document.createElement('td');
    localTd.textContent = tun.address || 'n/a';
    tr.appendChild(localTd);

    const targetTd = document.createElement('td');
    targetTd.textContent = tun.target || 'n/a';
    tr.appendChild(targetTd);

    const statusTd = document.createElement('td');
    const dot = document.createElement('span');
    dot.className = 'status-dot ' + (tun.established ? 'on' : 'off');
    statusTd.appendChild(dot);
    statusTd.appendChild(document.createTextNode(tun.established ? 'Paired' : 'Pending'));
    tr.appendChild(statusTd);

    const epTd = document.createElement('td');
    epTd.textContent = tun.endpoint || 'n/a';
    tr.appendChild(epTd);

    const prefixTd = document.createElement('td');
    prefixTd.textContent = tun.remotePrefix || 'n/a';
    tr.appendChild(prefixTd);

    body.appendChild(tr);
  }
}

document.getElementById('network-refresh').addEventListener('click', loadNetworkMap);
document.getElementById('connect-refresh').addEventListener('click', loadConnectTunnels);

document.getElementById('connect-pair-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = document.getElementById('connect-target').value.trim();
  const endpoint = document.getElementById('connect-endpoint').value.trim();
  const publicKey = document.getElementById('connect-pubkey').value.trim();
  const remotePrefix = document.getElementById('connect-prefix').value.trim();

  if (!target || !publicKey || !remotePrefix) {
    alert('Target, public key, and remote prefix are required.');
    return;
  }

  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Pairing...';

  try {
    const resp = await fetch('/api/connect/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, endpoint: endpoint || target, publicKey, remotePrefix }),
    });
    if (!resp.ok) {
      const err = await resp.json();
      alert('Error: ' + (err.error || 'unknown'));
      return;
    }
    loadConnectTunnels();
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Pair';
  }
});

// ── Init ──────────────────────────────────────────────────────

loadState()
  .catch(() => {
    els['feed-status'].textContent = 'waiting';
  })
  .finally(() => {
    connectFeed();
    loadVPNPeers();
    loadConnectTunnels();
    loadNetworkMap();
  });
