const state = {
  generatedAt: null,
  leases: [],
  dnsRecords: [],
};

const els = {
  generatedAt: document.getElementById('generated-at'),
  feedStatus: document.getElementById('feed-status'),
  leaseCount: document.getElementById('lease-count'),
  dnsCount: document.getElementById('dns-count'),
  leaseActive: document.getElementById('lease-active'),
  dnsActive: document.getElementById('dns-active'),
  leaseBody: document.getElementById('lease-body'),
  dnsBody: document.getElementById('dns-body'),
  leaseFilter: document.getElementById('lease-filter'),
  dnsFilter: document.getElementById('dns-filter'),
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

function renderCards(filteredLeaseCount, filteredDNSCount) {
  els.generatedAt.textContent = state.generatedAt ? formatTime(state.generatedAt) : 'waiting...';
  els.leaseCount.textContent = String(state.leases.length);
  els.dnsCount.textContent = String(state.dnsRecords.length);
  els.leaseActive.textContent = String(filteredLeaseCount);
  els.dnsActive.textContent = String(filteredDNSCount);
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

function render() {
  const leaseCount = renderLeases();
  const dnsCount = renderDNS();
  renderCards(leaseCount, dnsCount);
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
  source.onerror = () => {
    els.feedStatus.textContent = 'reconnecting';
  };
  return source;
}

els.leaseFilter.addEventListener('input', render);
els.dnsFilter.addEventListener('input', render);

loadState()
  .catch(() => {
    els.feedStatus.textContent = 'waiting';
  })
  .finally(() => {
    connectFeed();
  });
