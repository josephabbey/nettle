const state = {
  generatedAt: null,
  leases: [],
  dnsRecords: [],
  staticHosts: [],
};

const els = {
  generatedAt: document.getElementById('generated-at'),
  feedStatus: document.getElementById('feed-status'),
  leaseCount: document.getElementById('lease-count'),
  dnsCount: document.getElementById('dns-count'),
  staticCount: document.getElementById('static-count'),
  leaseActive: document.getElementById('lease-active'),
  dnsActive: document.getElementById('dns-active'),
  staticActive: document.getElementById('static-active'),
  leaseBody: document.getElementById('lease-body'),
  dnsBody: document.getElementById('dns-body'),
  staticBody: document.getElementById('static-body'),
  leaseFilter: document.getElementById('lease-filter'),
  dnsFilter: document.getElementById('dns-filter'),
  staticFilter: document.getElementById('static-filter'),
};

function canonical(value) {
  return String(value || '').trim().toLowerCase();
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

function matches(row, term) {
  if (!term) return true;
  return canonical(Object.values(row).join(' ')).includes(term);
}

function replaceByKey(list, item) {
  const index = list.findIndex((entry) => entry.key === item.key);
  if (index >= 0) {
    list[index] = item;
    return;
  }
  list.unshift(item);
}

function applySnapshot(snapshot) {
  state.generatedAt = snapshot.generatedAt || null;
  state.leases = Array.isArray(snapshot.leases) ? snapshot.leases : [];
  state.dnsRecords = Array.isArray(snapshot.dnsRecords) ? snapshot.dnsRecords : [];
  state.staticHosts = Array.isArray(snapshot.staticHosts) ? snapshot.staticHosts : [];
  render();
}

function upsertLease(lease) {
  if (!lease || !lease.key) return;
  replaceByKey(state.leases, lease);
  render();
}

function upsertDNS(record) {
  if (!record || !record.name) return;
  replaceByKey(state.dnsRecords, record);
  render();
}

function upsertStatic(entry) {
  if (!entry || !entry.hostname) return;
  const index = state.staticHosts.findIndex((s) => s.hostname === entry.hostname && s.hardwareAddr === entry.hardwareAddr);
  if (index >= 0) {
    state.staticHosts[index] = entry;
  } else {
    state.staticHosts.push(entry);
  }
  render();
}

function renderCards(filteredLeaseCount, filteredDNSCount, filteredStaticCount) {
  els.generatedAt.textContent = state.generatedAt ? formatTime(state.generatedAt) : 'waiting...';
  els.leaseCount.textContent = String(state.leases.length);
  els.dnsCount.textContent = String(state.dnsRecords.length);
  els.staticCount.textContent = String(state.staticHosts.length);
  els.leaseActive.textContent = String(filteredLeaseCount);
  els.dnsActive.textContent = String(filteredDNSCount);
  els.staticActive.textContent = String(filteredStaticCount);
}

function renderLeases() {
  const term = canonical(els.leaseFilter.value);
  const filtered = state.leases.filter((row) => matches(row, term));
  els.leaseBody.innerHTML = '';
  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'empty';
    td.textContent = 'No leases match the current filter.';
    tr.appendChild(td);
    els.leaseBody.appendChild(tr);
    return filtered.length;
  }
  for (const row of filtered) {
    const tr = document.createElement('tr');
    const cells = [
      row.hostname || 'n/a',
      row.hardwareAddr || 'n/a',
      row.address || 'n/a',
      row.interface || 'n/a',
      formatTime(row.leaseUntil),
      formatTime(row.updatedAt),
    ];
    for (const value of cells) {
      const td = document.createElement('td');
      td.textContent = value;
      tr.appendChild(td);
    }
    els.leaseBody.appendChild(tr);
  }
  return filtered.length;
}

function renderDNS() {
  const term = canonical(els.dnsFilter.value);
  const filtered = state.dnsRecords.filter((row) => matches(row, term));
  els.dnsBody.innerHTML = '';
  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'empty';
    td.textContent = 'No DNS records match the current filter.';
    tr.appendChild(td);
    els.dnsBody.appendChild(tr);
    return filtered.length;
  }
  for (const row of filtered) {
    const tr = document.createElement('tr');
    const typeCell = document.createElement('td');
    const chip = document.createElement('span');
    chip.className = 'chip' + (row.type === 'A' ? ' good' : row.type === 'CNAME' ? ' warn' : '');
    chip.textContent = row.type || 'unknown';
    typeCell.appendChild(chip);
    const cells = [
      row.name || 'n/a',
      typeCell,
      row.address || 'n/a',
      row.cname || 'n/a',
      formatTime(row.updatedAt),
    ];
    for (const value of cells) {
      if (value instanceof HTMLElement) {
        tr.appendChild(value);
      } else {
        const td = document.createElement('td');
        td.textContent = value;
        tr.appendChild(td);
      }
    }
    els.dnsBody.appendChild(tr);
  }
  return filtered.length;
}

function renderStatics() {
  const term = canonical(els.staticFilter.value);
  const filtered = state.staticHosts.filter((row) => matches(row, term));
  els.staticBody.innerHTML = '';
  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'empty';
    td.textContent = 'No static IPs match the current filter.';
    tr.appendChild(td);
    els.staticBody.appendChild(tr);
    return filtered.length;
  }
  for (const row of filtered) {
    const tr = document.createElement('tr');
    const cells = [
      row.hostname || 'n/a',
      row.hardwareAddr || 'n/a',
      row.address || 'n/a',
    ];
    for (const value of cells) {
      const td = document.createElement('td');
      td.textContent = value;
      tr.appendChild(td);
    }
    els.staticBody.appendChild(tr);
  }
  return filtered.length;
}

function render() {
  const leaseCount = renderLeases();
  const dnsCount = renderDNS();
  const staticCount = renderStatics();
  renderCards(leaseCount, dnsCount, staticCount);
}

async function loadState() {
  const resp = await fetch('/api/state', { cache: 'no-store' });
  if (!resp.ok) throw new Error('failed to load state');
  applySnapshot(await resp.json());
}

function connectFeed() {
  const source = new EventSource('/events');
  source.addEventListener('open', () => {
    els.feedStatus.textContent = 'connected';
  });
  source.addEventListener('snapshot', (event) => {
    applySnapshot(JSON.parse(event.data));
  });
  source.addEventListener('lease', (event) => {
    upsertLease(JSON.parse(event.data));
  });
  source.addEventListener('dns', (event) => {
    upsertDNS(JSON.parse(event.data));
  });
  source.addEventListener('static', (event) => {
    upsertStatic(JSON.parse(event.data));
  });
  source.onerror = () => {
    els.feedStatus.textContent = 'reconnecting';
  };
  return source;
}

els.leaseFilter.addEventListener('input', render);
els.dnsFilter.addEventListener('input', render);
els.staticFilter.addEventListener('input', render);

loadState()
  .catch(() => {
    els.feedStatus.textContent = 'waiting';
  })
  .finally(() => {
    connectFeed();
  });
