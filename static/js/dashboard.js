const POLL_MS = 2500;

// ---------------- 1. Throughput Chart ----------------
let bwChart = null;
const bwCanvas = document.getElementById('bwChart');

function initThroughputChart() {
  if (bwChart || !bwCanvas || typeof Chart === 'undefined') return;
  bwChart = new Chart(bwCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Download (Mbps)',
          data: [],
          borderColor: '#2dd4bf',
          backgroundColor: 'rgba(45,212,191,0.08)',
          fill: true,
          tension: 0.35,
          pointRadius: 0,
          borderWidth: 2
        },
        {
          label: 'Upload (Mbps)',
          data: [],
          borderColor: '#60a5fa',
          backgroundColor: 'rgba(96,165,250,0.06)',
          fill: true,
          tension: 0.35,
          pointRadius: 0,
          borderWidth: 2
        }
      ]
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: {
          display: true,
          grid: { color: 'rgba(255,255,255,0.02)' },
          ticks: { color: '#54687c', font: { family: 'IBM Plex Mono', size: 9 }, maxTicksLimit: 6 }
        },
        y: {
          beginAtZero: true,
          suggestedMax: 1.0,
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: {
            color: '#7d93a8',
            font: { family: 'IBM Plex Mono', size: 10 },
            callback: (v) => v + ' Mbps'
          }
        }
      },
      plugins: {
        legend: { labels: { color: '#7d93a8', font: { family: 'Inter', size: 11 } } },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${Number(ctx.parsed.y).toFixed(3)} Mbps`
          }
        }
      }
    }
  });
}
initThroughputChart();

// ---------------- 2. Traffic Prediction Chart ----------------
let predChart = null;
const predCanvas = document.getElementById('predChart');

function initPredictionChart() {
  if (predChart || !predCanvas || typeof Chart === 'undefined') return;
  predChart = new Chart(predCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Observed Actuals',
          data: [],
          borderColor: '#60a5fa',
          backgroundColor: 'transparent',
          borderWidth: 2,
          pointRadius: 2,
          tension: 0.25
        },
        {
          label: 'Fitted Baseline (SMA)',
          data: [],
          borderColor: 'rgba(148,163,184,0.4)',
          borderDash: [4, 4],
          backgroundColor: 'transparent',
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.25
        },
        {
          label: 'Forecast Trend (Holt-Winters)',
          data: [],
          borderColor: '#2dd4bf',
          borderDash: [5, 3],
          backgroundColor: 'rgba(45,212,191,0.06)',
          fill: true,
          borderWidth: 2.5,
          pointRadius: 4,
          pointBackgroundColor: '#2dd4bf',
          tension: 0.2
        }
      ]
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: {
          display: true,
          grid: { color: 'rgba(255,255,255,0.02)' },
          ticks: { color: '#54687c', font: { family: 'IBM Plex Mono', size: 9 }, maxTicksLimit: 6 }
        },
        y: {
          beginAtZero: true,
          suggestedMax: 1.0,
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: {
            color: '#7d93a8',
            font: { family: 'IBM Plex Mono', size: 10 },
            callback: (v) => v + ' Mbps'
          }
        }
      },
      plugins: {
        legend: { labels: { color: '#7d93a8', font: { family: 'Inter', size: 11 } } },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${Number(ctx.parsed.y).toFixed(3)} Mbps`
          }
        }
      }
    }
  });
}
initPredictionChart();

// ---------------- 3. AI Allocation Chart ----------------
let allocChart = null;
const allocCanvas = document.getElementById('allocChart');

function initAllocationChart() {
  if (allocChart || !allocCanvas || typeof Chart === 'undefined') return;
  allocChart = new Chart(allocCanvas.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }]
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${Number(ctx.parsed).toFixed(2)} Mbps`
          }
        }
      },
      cutout: '68%'
    }
  });
}
initAllocationChart();

// ---------------- 4. Knowledge Graph ----------------
let network = null;
let currentGraphNodes = {};

function renderGraph(graph) {
  const container = document.getElementById('kgraph');
  if (!container || typeof vis === 'undefined' || !graph || !Array.isArray(graph.nodes)) return;

  currentGraphNodes = {};
  graph.nodes.forEach(n => { currentGraphNodes[n.id] = n; });

  const data = {
    nodes: new vis.DataSet(graph.nodes),
    edges: new vis.DataSet(graph.edges)
  };

  const options = {
    physics: {
      stabilization: true,
      barnesHut: {
        gravitationalConstant: -2400,
        springLength: 95,
        springConstant: 0.03
      }
    },
    interaction: { hover: true, zoomView: true, dragView: true }
  };

  if (!network) {
    network = new vis.Network(container, data, options);

    // Node selection inspector event
    network.on('click', function(params) {
      if (params.nodes && params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        displayNodeProperties(currentGraphNodes[nodeId]);
      }
    });
  } else {
    network.setData(data);
  }
}

function displayNodeProperties(node) {
  const details = document.getElementById('inspectorDetails');
  const title = document.getElementById('inspectorTitle');
  if (!details || !node) return;

  title.textContent = `Entity: ${node.label ? node.label.replace('\n', ' — ') : node.id}`;
  
  if (!node.properties || Object.keys(node.properties).length === 0) {
    details.innerHTML = `<p class="muted">Group: ${node.group || 'Node'}</p>`;
    return;
  }

  let html = '<table><tbody>';
  for (const [k, v] of Object.entries(node.properties)) {
    html += `<tr><th>${k}</th><td>${v}</td></tr>`;
  }
  html += '</tbody></table>';
  details.innerHTML = html;
}

// ---------------- 5. Device Table, Priority Cycling & Internet Cut-Off ----------------
async function cycleDevicePriority(ip, currentPriority) {
  const priorityOrder = { 'High': 'Normal', 'Normal': 'Low', 'Low': 'High' };
  const nextPriority = priorityOrder[currentPriority] || 'Normal';

  try {
    const res = await fetch('/api/device/priority', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, priority: nextPriority })
    });
    if (res.ok) {
      pollDevices();
      pollAllocation();
    }
  } catch (e) {
    console.error('Error updating priority:', e);
  }
}

async function toggleBlockDevice(ip, shouldBlock) {
  // 1. Instant Optimistic Cutoff: Immediately drop client's bandwidth to 0 Mbps in the DOM
  try {
    const rows = document.querySelectorAll('#deviceRows tr');
    rows.forEach(tr => {
      const ipCells = tr.querySelectorAll('.dev-ip');
      const hasMatchingIp = Array.from(ipCells).some(c => c.textContent.trim() === ip);
      if (hasMatchingIp) {
        if (shouldBlock) {
          tr.style.background = 'rgba(239,68,68,0.06)';
          const statusPill = tr.querySelector('.status-pill');
          if (statusPill) {
            statusPill.innerHTML = '<span class="dot" style="background:#ef4444"></span>🚫 BLOCKED';
            statusPill.style.borderColor = 'rgba(239,68,68,0.4)';
            statusPill.style.color = '#f87171';
          }
          const usageBar = tr.querySelector('.usage-bar');
          if (usageBar) {
            usageBar.style.width = '0%';
            usageBar.style.background = 'var(--red)';
          }
          const usageTexts = tr.querySelectorAll('.mono');
          usageTexts.forEach(el => {
            if (el.textContent.includes('Mbps') || el.textContent.includes('Kbps')) {
              el.textContent = 'Traffic Cut-Off (0.0 Mbps)';
              el.style.color = 'var(--red)';
            }
          });
          // Drop AI allocation directly to 0.00 Mbps
          if (tr.cells.length >= 7) {
            tr.cells[6].textContent = '0.00 Mbps (Blocked)';
            tr.cells[6].style.color = 'var(--red)';
          }
          const ratEl = tr.querySelector('.rationale-text');
          if (ratEl) {
            ratEl.textContent = '🚫 Internet access blocked by administrator (Traffic Cut-Off).';
            ratEl.style.color = 'var(--red)';
          }
          const lastCell = tr.cells[tr.cells.length - 1];
          const actionWrap = lastCell ? lastCell.querySelector('div') : null;
          if (actionWrap) {
            actionWrap.innerHTML = `
              <button class="btn-action-restore" onclick="toggleBlockDevice('${ip}', false)" title="Restore Internet access for this device">
                🟢 Restore Access
              </button>
              <button class="btn-action-role" onclick="setDeviceRole('${ip}', 'upstream')" title="Move to Upstream Internet Provider section">
                ⬆ Set as Upstream
              </button>
            `;
          }
        }
      }
    });
  } catch (err) {
    console.warn('Optimistic block update warning:', err);
  }

  // 2. Wire up block action directly to backend
  try {
    const res = await fetch('/api/device/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, blocked: shouldBlock })
    });
    if (res.ok) {
      await Promise.allSettled([pollDevices(), pollAllocation(), pollGraph(), pollLog()]);
    } else {
      console.error('Failed to update device block state on backend');
      pollDevices();
    }
  } catch (e) {
    console.error('Error toggling device block:', e);
    pollDevices();
  }
}

async function setDeviceRole(ip, role) {
  try {
    const res = await fetch('/api/device/role', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, role })
    });
    if (res.ok) {
      await Promise.allSettled([pollDevices(), pollUpstream(), pollAllocation(), pollGraph(), pollLog()]);
    }
  } catch (e) {
    console.error('Error setting device role:', e);
  }
}

function renderUpstream(upstreamList) {
  const tbody = document.getElementById('upstreamRows');
  if (!tbody) return;
  tbody.innerHTML = '';

  // Strictly filter for the active device/router currently providing internet to this laptop
  const activeList = (upstreamList || []).filter(up => {
    if (up.is_active_uplink === false) return false;
    if (up.status && !up.status.toLowerCase().includes('active')) return false;
    return true;
  });

  if (activeList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--muted);">No active upstream internet router currently detected.</td></tr>';
    return;
  }

  // Strictly display ONLY the single active uplink router/device currently providing internet
  const up = activeList[0];
  const tr = document.createElement('tr');
  tr.style.background = 'rgba(56,189,248,0.03)';
  const host = up.hostname || 'Active Internet Router';
  const isTether = (up.role || '').includes('tether') || host.toLowerCase().includes('iphone');
  const roleIcon = isTether ? '📱' : '🌐';
  const roleText = isTether ? 'Active Tether Source' : 'Active Internet Router (Default Gateway)';

  tr.innerHTML = `
    <td>
      <span class="badge-upstream-role">${roleIcon} ${roleText}</span>
    </td>
    <td>
      <div class="dev-name" style="color:var(--cyan);font-weight:600;">${host}</div>
      <div class="dev-ip" style="font-size:0.70rem;">${up.description || 'Active Uplink Provider'}</div>
    </td>
    <td class="dev-ip mono" style="font-weight:600;">${up.ip}</td>
    <td class="dev-ip mono">${up.mac || '—'}</td>
    <td style="font-size:0.75rem;color:var(--muted);">${up.interface || 'Wi-Fi Uplink'}</td>
    <td>
      <span class="status-pill">
        <span class="dot" style="background:#34d399"></span>
        Active Provider
      </span>
    </td>
    <td>
      <span class="mono" style="font-size:0.75rem;color:#34d399;font-weight:600;">
        ✔ Primary Uplink
      </span>
    </td>
  `;
  tbody.appendChild(tr);
}

function renderDevices(devices) {
  const tbody = document.getElementById('deviceRows');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!devices || devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:24px;color:var(--muted);">No client devices currently connected on the managed subnet.</td></tr>';
    return;
  }

  devices.sort((a, b) => (b.download_mbps || 0) - (a.download_mbps || 0));
  const maxBar = Math.max(1, ...devices.map(x => Math.max(x.download_mbps || 0, 1)));

  for (const d of devices) {
    const isBlocked = !!d.blocked;
    const download = isBlocked ? 0 : (d.download_mbps || 0);
    const upload = isBlocked ? 0 : (d.upload_mbps || 0);
    const packets = d.total_packets || d.packets || 0;
    const latency = (!isBlocked && d.latency_ms != null) ? `${Number(d.latency_ms).toFixed(0)} ms` : '—';
    const pct = isBlocked ? 0 : Math.min(100, (download / maxBar) * 100);

    const isInactive = !isBlocked && (!d.online || d.status === 'inactive' || d.status === 'offline');
    let statusColor = '#94a3b8';
    let statusText = 'Inactive';
    if (isBlocked) {
      statusColor = '#ef4444';
      statusText = '🚫 BLOCKED';
    } else if (d.status === 'confirmed_active') {
      statusColor = '#34d399';
      statusText = 'Active (Pinged)';
    } else if (d.online) {
      statusColor = '#fbbf24';
      statusText = 'Recently Seen';
    } else {
      statusColor = '#94a3b8';
      statusText = 'Inactive (Disconnected)';
    }

    const prio = d.priority || 'Normal';
    const cat = isBlocked ? 'Unknown' : (isInactive ? 'Low' : (d.category || 'Normal'));
    const qosClass = isBlocked ? 'Blocked (Traffic Cut-Off)' : (isInactive ? 'Inactive / Disconnected' : (d.qos_class || 'Interactive Web & Cloud'));
    const qosIcon = isBlocked ? '🚫' : (isInactive ? '⚪' : (d.qos_icon || '🌐'));
    const serviceDetail = isBlocked ? '0.0 Mbps Traffic Blackholed' : (isInactive ? 'No Active Traffic' : (d.traffic_service || 'Standard Web'));
    const domainText = (!isBlocked && !isInactive && d.recent_domain) ? ` · ${d.recent_domain}` : '';

    // Determine traffic state description
    let trafficSummary = '';
    if (isBlocked) {
      trafficSummary = 'Traffic Cut-Off (0.0 Mbps)';
    } else if (isInactive) {
      trafficSummary = 'Disconnected (0.0 Mbps)';
    } else if (download >= 0.01 || upload >= 0.01) {
      trafficSummary = `↓ ${Number(download).toFixed(2)} · ↑ ${Number(upload).toFixed(2)} Mbps`;
    } else if (download > 0.0001 || upload > 0.0001) {
      const downKbps = (download * 1000).toFixed(1);
      const upKbps = (upload * 1000).toFixed(1);
      trafficSummary = `↓ ${downKbps} · ↑ ${upKbps} Kbps`;
    } else if (packets > 0) {
      trafficSummary = `Idle (<0.1 Kbps)`;
    } else {
      trafficSummary = `No recent packets`;
    }

    const volumeStr = d.total_data_str ? `Total: ${d.total_data_str}` : (packets > 0 ? `${packets} pkts` : '0 B');
    const allocatedDisplay = isBlocked ? '0.00 Mbps (Blocked)' : (isInactive ? '0.00 Mbps (Inactive)' : `${Number(d.allocated_mbps || 0).toFixed(2)} Mbps`);

    const tr = document.createElement('tr');
    if (isBlocked) {
      tr.style.background = 'rgba(239,68,68,0.06)';
    } else if (isInactive) {
      tr.style.opacity = '0.62';
    }
    tr.innerHTML = `
      <td>
        <span class="status-pill" style="${isBlocked ? 'border-color:rgba(239,68,68,0.4);color:#f87171;' : ''}">
          <span class="dot" style="background:${statusColor}"></span>
          ${statusText}
        </span>
      </td>
      <td>
        <div class="dev-name">${d.hostname && d.hostname !== d.ip ? d.hostname : 'Device'}</div>
        <div class="dev-ip">${d.mac || '—'}</div>
      </td>
      <td class="dev-ip">${d.ip}</td>
      <td>
        <span class="priority-pill ${prio}" title="Click to cycle priority" onclick="cycleDevicePriority('${d.ip}', '${prio}')">
          ${prio} ↕
        </span>
      </td>
      <td>
        <span class="qos-pill ${cat}" title="${d.classification_reason || ''}">
          <span>${qosIcon}</span> ${qosClass}
        </span>
        <div class="qos-sub mono" title="${d.classification_reason || ''}">
          ${serviceDetail}${domainText}
        </div>
      </td>
      <td>
        <div class="usage-bar-wrap"><div class="usage-bar" style="width:${pct}%;${isBlocked ? 'background:var(--red);' : ''}"></div></div>
        <div class="mono" style="font-size:0.72rem;color:${isBlocked ? 'var(--red)' : 'var(--text)'};margin-top:2px;">
          ${trafficSummary}
        </div>
        <div class="mono" style="font-size:0.67rem;color:var(--muted)">
          ${volumeStr} · ${packets} pkts
        </div>
      </td>
      <td class="mono" style="color:${isBlocked ? 'var(--red)' : 'var(--cyan)'};font-weight:600;">
        ${allocatedDisplay}
      </td>
      <td>
        <span class="rationale-text" style="${isBlocked ? 'color:var(--red);font-weight:500;' : ''}">
          ${d.allocation_reason || 'Standard priority share'}
        </span>
      </td>
      <td class="mono">${latency}</td>
      <td>
        <div style="display:flex;flex-direction:column;gap:4px;">
          ${isBlocked ? `
            <button class="btn-action-restore" onclick="toggleBlockDevice('${d.ip}', false)" title="Restore Internet access for this device">
              🟢 Restore Access
            </button>
          ` : `
            <button class="btn-action-cutoff" onclick="toggleBlockDevice('${d.ip}', true)" title="Completely cut off all Internet access for this device">
              🚫 Cut Off Internet
            </button>
          `}
          <button class="btn-action-role" onclick="setDeviceRole('${d.ip}', 'upstream')" title="Move to Upstream Internet Provider section">
            ⬆ Set as Upstream
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

// ---------------- 6. Decision Log ----------------
function renderLog(entries) {
  const list = document.getElementById('logList');
  const countEl = document.getElementById('logCount');
  if (!list) return;

  if (countEl) countEl.textContent = `${entries.length} decisions`;
  list.innerHTML = '';

  for (const e of entries.slice(0, 25)) {
    const li = document.createElement('li');
    li.className = e.bucket || 'low';
    const time = new Date(e.t * 1000).toLocaleTimeString();
    li.innerHTML = `<span class="t">${time}</span><span>${e.text}</span>`;
    list.appendChild(li);
  }
}

// ---------------- 7. Pollers ----------------

async function pollStatus() {
  try {
    const r = await fetch('/api/status');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const s = await r.json();

    document.getElementById('kpiDown').innerHTML = `${Number(s.down_mbps || 0).toFixed(1)}<small>Mbps</small>`;
    document.getElementById('kpiUp').innerHTML = `${Number(s.up_mbps || 0).toFixed(1)}<small>Mbps</small>`;
    document.getElementById('kpiLatency').innerHTML = `${s.avg_latency != null ? Number(s.avg_latency).toFixed(0) : '—'}<small>ms</small>`;
    document.getElementById('kpiDevices').innerHTML = `${s.online_count || 0}<small id="kpiDevicesTotal">/${s.device_count || 0}</small>`;
    document.getElementById('kpiCapacity').innerHTML = `${Number(s.capacity_mbps || 0).toFixed(1)}<small>Mbps</small>`;

    const activeEl = document.getElementById('kpiActiveDetail');
    if (activeEl) activeEl.textContent = `${s.confirmed_active_count || 0} Confirmed Active`;

    // Congestion chip
    const chip = document.getElementById('congestionChip');
    if (chip) {
      chip.textContent = `${s.congestion || 'low'} load`;
      chip.className = `status-chip mono ${s.congestion || 'low'}`;
    }

    // Link interface chip
    const dot = document.getElementById('linkDot');
    const text = document.getElementById('linkText');
    if (s.interface) {
      if (dot) dot.className = 'dot on';
      const capInfo = s.capture_status === 'running' ? `Sniffing (${s.packets_captured || 0} pkts)` : (s.capture_status || 'Sockets');
      if (text) text.textContent = `${s.capture_interface || s.interface} · ${capInfo}`;
    } else {
      if (dot) dot.className = 'dot off';
      if (text) text.textContent = 'No Interface';
    }

    // Enforcement status chip
    const enfDot = document.getElementById('enfDot');
    const enfText = document.getElementById('enfText');
    if (enfText) {
      const modeLabels = {
        'simulation': 'Mode: Simulation (Dry-Run)',
        'windows_qos': 'Mode: Windows NetQos (Host Sockets)',
        'router_linux_tc': 'Mode: Linux/Router tc HTB'
      };
      enfText.textContent = modeLabels[s.qos_mode] || `Mode: ${s.qos_mode}`;
      if (enfDot) enfDot.className = s.is_simulation ? 'dot warn' : 'dot on';
    }

    // Device note
    const note = document.getElementById('deviceModeNote');
    if (note) {
      note.textContent = s.demo_mode
        ? 'Simulation demo mode active — synthetic devices generated'
        : 'Subnet-Scoped ARP Discovery + Gateway Filtered + Live Npcap Packets';
    }

  } catch (e) {
    const dot = document.getElementById('linkDot');
    const text = document.getElementById('linkText');
    if (dot) dot.className = 'dot off';
    if (text) text.textContent = 'Backend Offline';
    console.error('Status poll error:', e);
  }
}

async function pollHistory() {
  try {
    const r = await fetch('/api/history');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const h = await r.json();

    const emptyEl = document.getElementById('bwEmptyState');
    const subEl = document.getElementById('throughputSub');

    if (!h || h.length === 0) {
      if (emptyEl) emptyEl.style.display = 'flex';
      return;
    }
    if (emptyEl) emptyEl.style.display = 'none';

    if (!bwChart) {
      initThroughputChart();
      if (!bwChart) return;
    }

    // Use readable clock timestamps for labels
    const labels = h.map(p => {
      if (!p.t) return '';
      const d = new Date(p.t * 1000);
      return d.toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
    });

    const downData = h.map(p => p.down || 0);
    const upData = h.map(p => p.up || 0);

    const maxVal = Math.max(0.1, ...downData, ...upData);
    bwChart.options.scales.y.suggestedMax = Math.max(1.0, Math.ceil(maxVal * 1.3 * 10) / 10);

    bwChart.data.labels = labels;
    bwChart.data.datasets[0].data = downData;
    bwChart.data.datasets[1].data = upData;
    bwChart.update();

    if (subEl && h.length > 0) {
      const last = h[h.length - 1];
      const lastT = new Date(last.t * 1000).toLocaleTimeString();
      subEl.textContent = `Updated: ${lastT} · Last: ↓ ${Number(last.down || 0).toFixed(2)} / ↑ ${Number(last.up || 0).toFixed(2)} Mbps`;
    }
  } catch (e) {
    console.error('History poll error:', e);
  }
}

async function pollPrediction() {
  try {
    const r = await fetch('/api/prediction');
    if (!r.ok) return;
    const p = await r.json();

    const maeBadge = document.getElementById('maeBadge');
    const peakBadge = document.getElementById('peakBadge');
    const emptyEl = document.getElementById('predEmptyState');

    if (maeBadge && p.mae !== undefined) {
      maeBadge.textContent = `MAE: ${Number(p.mae).toFixed(2)} Mbps`;
    }

    if (peakBadge && p.peak_status) {
      if (p.peak_status === 'PEAK_HOUR') {
        peakBadge.textContent = `🔥 Peak Active (${p.surge_multiplier}x)`;
        peakBadge.style.background = 'rgba(239, 68, 68, 0.15)';
        peakBadge.style.color = '#f87171';
        peakBadge.style.borderColor = 'rgba(239, 68, 68, 0.4)';
      } else if (p.peak_status === 'SHOULDER') {
        peakBadge.textContent = `⚠️ Shoulder (${p.surge_multiplier}x)`;
        peakBadge.style.background = 'rgba(245, 158, 11, 0.15)';
        peakBadge.style.color = '#fbbf24';
        peakBadge.style.borderColor = 'rgba(245, 158, 11, 0.4)';
      } else {
        peakBadge.textContent = '🟢 Off-Peak Normal';
        peakBadge.style.background = 'rgba(56, 189, 248, 0.12)';
        peakBadge.style.color = '#38bdf8';
        peakBadge.style.borderColor = 'rgba(56, 189, 248, 0.3)';
      }
      peakBadge.title = p.interpretation || 'Historical Peak Demand Status';
    }

    if (!p || !p.observed || p.observed.length === 0) {
      if (emptyEl) emptyEl.style.display = 'flex';
      return;
    }
    if (emptyEl) emptyEl.style.display = 'none';

    if (!predChart) {
      initPredictionChart();
      if (!predChart) return;
    }

    const obsLen = p.observed.length;
    const foreLen = (p.forecast || []).length;
    const totalPoints = obsLen + foreLen;

    // Labels with step indicator
    const labels = Array.from({ length: totalPoints }, (_, i) => {
      if (i < obsLen) return `T-${obsLen - 1 - i}`;
      return `+${(i - obsLen + 1) * 2.5}s`;
    });

    const obsData = [...p.observed, ...Array(foreLen).fill(null)];
    const fitData = [...(p.fitted_baseline || []), ...Array(foreLen).fill(null)];

    const foreData = Array(obsLen > 0 ? obsLen - 1 : 0).fill(null);
    if (obsLen > 0) foreData.push(p.observed[obsLen - 1]);
    foreData.push(...(p.forecast || []));

    const allVals = [...p.observed, ...(p.forecast || [])].filter(v => v !== null);
    const maxVal = Math.max(0.1, ...allVals);
    predChart.options.scales.y.suggestedMax = Math.max(1.0, Math.ceil(maxVal * 1.3 * 10) / 10);

    predChart.data.labels = labels;
    predChart.data.datasets[0].data = obsData;
    predChart.data.datasets[1].data = fitData;
    predChart.data.datasets[2].data = foreData;
    predChart.update();

  } catch (e) {
    console.error('Prediction poll error:', e);
  }
}

async function pollAllocation() {
  try {
    const r = await fetch('/api/allocation');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const a = await r.json();

    const actionDesc = document.getElementById('allocActionDesc');
    if (actionDesc && a.action_desc) actionDesc.textContent = a.action_desc;

    const jainsTag = document.getElementById('jainsTag');
    if (jainsTag && a.jains_index) jainsTag.textContent = `Jain: ${a.jains_index}`;

    const kpiJains = document.getElementById('kpiJains');
    if (kpiJains && a.jains_index) kpiJains.textContent = `Jain's Fairness: ${a.jains_index}`;

    const rawAlloc = a.allocation || {};
    const labels = Object.keys(rawAlloc);
    const values = Object.values(rawAlloc);
    const colors = labels.map(l => (a.colors || {})[l] || '#888');

    const totalAlloc = values.reduce((acc, v) => acc + (Number(v) || 0), 0);
    const emptyEl = document.getElementById('allocEmptyState');

    if (!allocChart) {
      initAllocationChart();
    }
    if (allocChart) {
      if (totalAlloc <= 0) {
        // Zero allocations across all categories: show empty-state placeholder in doughnut
        allocChart.data.labels = ['Unallocated Capacity'];
        allocChart.data.datasets[0].data = [a.total_capacity || 50.0];
        allocChart.data.datasets[0].backgroundColor = ['rgba(255,255,255,0.04)'];
        if (emptyEl) emptyEl.style.display = 'flex';
      } else {
        if (emptyEl) emptyEl.style.display = 'none';
        allocChart.data.labels = labels;
        allocChart.data.datasets[0].data = values;
        allocChart.data.datasets[0].backgroundColor = colors;
      }
      allocChart.update();
    }

    const legend = document.getElementById('allocLegend');
    if (!legend) return;
    legend.innerHTML = '';

    labels.forEach((l, i) => {
      const li = document.createElement('li');
      li.innerHTML = `
        <span><span class="swatch" style="background:${colors[i]}"></span>${l}</span>
        <span class="amt">${Number(values[i]).toFixed(2)} Mbps</span>
      `;
      legend.appendChild(li);
    });

  } catch (e) {
    console.error('Allocation poll error:', e);
  }
}

async function pollDevices() {
  try {
    const r = await fetch('/api/devices');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    renderDevices(await r.json());
  } catch (e) {
    console.error('Devices poll error:', e);
  }
}

async function pollUpstream() {
  try {
    const r = await fetch('/api/upstream');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    renderUpstream(await r.json());
  } catch (e) {
    console.error('Upstream poll error:', e);
  }
}

async function pollGraph() {
  try {
    const r = await fetch('/api/graph');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    renderGraph(await r.json());
  } catch (e) {
    console.error('Graph poll error:', e);
  }
}

async function pollLog() {
  try {
    const r = await fetch('/api/log');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    renderLog(await r.json());
  } catch (e) {
    console.error('Log poll error:', e);
  }
}

async function pollAll() {
  await Promise.allSettled([
    pollStatus(),
    pollHistory(),
    pollPrediction(),
    pollAllocation(),
    pollDevices(),
    pollUpstream(),
    pollLog()
  ]);
}

// ---------------- 8. Settings & QoS Modal ----------------
const settingsBackdrop = document.getElementById('settingsBackdrop');
const settingsBtn = document.getElementById('settingsBtn');
const closeSettings = document.getElementById('closeSettings');
const saveSettings = document.getElementById('saveSettings');
const resetQoSBtn = document.getElementById('resetQoSBtn');

if (settingsBtn) {
  settingsBtn.addEventListener('click', async () => {
    try {
      const [cfgRes, enfRes] = await Promise.all([
        fetch('/api/config').then(r => r.json()),
        fetch('/api/enforcement').then(r => r.json())
      ]);

      document.getElementById('capacityInput').value = cfgRes.capacity_mbps;
      const sel = document.getElementById('interfaceSelect');
      sel.innerHTML = '';
      (cfgRes.available_interfaces || []).forEach(name => {
        const opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name;
        if (name === cfgRes.interface) opt.selected = true;
        sel.appendChild(opt);
      });

      document.getElementById('enfModeSelect').value = enfRes.mode || 'simulation';
      document.getElementById('adminAuthCheck').checked = !!enfRes.admin_authorized;

      settingsBackdrop.classList.add('open');
    } catch (e) {
      console.error('Settings load error:', e);
    }
  });
}

if (closeSettings) {
  closeSettings.addEventListener('click', () => settingsBackdrop.classList.remove('open'));
}

if (saveSettings) {
  saveSettings.addEventListener('click', async () => {
    const capacity_mbps = parseFloat(document.getElementById('capacityInput').value);
    const iface = document.getElementById('interfaceSelect').value;
    const mode = document.getElementById('enfModeSelect').value;
    const admin_authorized = document.getElementById('adminAuthCheck').checked;

    await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capacity_mbps, interface: iface })
    });

    await fetch('/api/enforcement', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'set_mode', mode, admin_authorized })
    });

    settingsBackdrop.classList.remove('open');
    pollStatus();
  });
}

if (resetQoSBtn) {
  resetQoSBtn.addEventListener('click', async () => {
    if (confirm('Safely clear all QoS bandwidth rate limits and restore default queues?')) {
      await fetch('/api/enforcement', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'reset_all' })
      });
      alert('All QoS rate limits successfully reset.');
      settingsBackdrop.classList.remove('open');
    }
  });
}

// ---------------- 9. Evaluation Benchmark Modal ----------------
const evalBackdrop = document.getElementById('evalBackdrop');
const evalBtn = document.getElementById('evalBtn');
const closeEval = document.getElementById('closeEval');
const dismissEval = document.getElementById('dismissEval');
const reRunEval = document.getElementById('reRunEval');

async function loadBenchmarkResults() {
  const tbody = document.getElementById('evalRows');
  const summaryBox = document.getElementById('evalSummaryText');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;">Running multi-policy benchmark...</td></tr>';

  try {
    const res = await fetch('/api/evaluation');
    const data = await res.json();

    document.getElementById('evalSub').textContent = `Environment: ${data.test_environment}`;
    tbody.innerHTML = '';

    for (const [name, p] of Object.entries(data.policies)) {
      const tr = document.createElement('tr');
      const isNetPilot = name.includes('NetPilot');
      tr.style.background = isNetPilot ? 'rgba(45,212,191,0.06)' : 'transparent';
      tr.innerHTML = `
        <td style="font-weight:${isNetPilot ? '700;color:var(--cyan)' : '500'}">${name}</td>
        <td><span class="mono" style="color:${p.latency_ms <= 25 ? '#34d399' : '#f87171'}">${p.latency_ms} ms</span></td>
        <td><span class="mono">${p.throughput_mbps} Mbps</span></td>
        <td><span class="mono">${p.jains_fairness}</span></td>
        <td><span class="mono" style="color:${p.voip_satisfaction_pct >= 95 ? '#34d399' : '#fbbf24'}">${p.voip_satisfaction_pct}%</span></td>
        <td><span class="mono">${p.unmet_demand_pct}%</span> <small class="muted">(${p.unmet_demand_mbps}M)</small></td>
        <td><span class="mono muted">${p.overhead_ms} ms</span></td>
      `;
      tbody.appendChild(tr);
    }

    summaryBox.textContent = data.summary;
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--red);">Failed to run benchmark evaluation.</td></tr>';
  }
}

if (evalBtn) {
  evalBtn.addEventListener('click', () => {
    evalBackdrop.classList.add('open');
    loadBenchmarkResults();
  });
}
if (closeEval) closeEval.addEventListener('click', () => evalBackdrop.classList.remove('open'));
if (dismissEval) dismissEval.addEventListener('click', () => evalBackdrop.classList.remove('open'));
if (reRunEval) reRunEval.addEventListener('click', loadBenchmarkResults);

// ---------------- 10. Diagnostics Modal ----------------
const diagBackdrop = document.getElementById('diagBackdrop');
const diagBtn = document.getElementById('diagBtn');
const closeDiag = document.getElementById('closeDiag');
const dismissDiag = document.getElementById('dismissDiag');
const reRunDiag = document.getElementById('reRunDiag');

async function loadDiagnostics() {
  const tbody = document.getElementById('diagRows');
  const summaryBox = document.getElementById('diagSummaryBox');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:16px;">Scanning system interfaces and routes...</td></tr>';

  try {
    const res = await fetch('/api/diagnostics');
    const data = await res.json();

    document.getElementById('diagSub').textContent = `Client Subnet: ${data.client_facing_subnet || 'Auto'} | Capture Interface: ${data.capture_interface || 'None'} (${data.capture_status ? data.capture_status.status : 'unknown'})`;
    tbody.innerHTML = '';

    const entities = data.all_entities || {};
    for (const [ip, item] of Object.entries(entities)) {
      const tr = document.createElement('tr');
      const isClient = !!item.is_client;
      tr.style.background = isClient ? 'rgba(45,212,191,0.06)' : 'transparent';
      tr.innerHTML = `
        <td class="mono">${ip}</td>
        <td><span class="status-pill"><span class="dot" style="background:${isClient ? '#34d399' : '#f87171'}"></span>${item.classification || 'unknown'}</span></td>
        <td>${isClient ? '<strong style="color:var(--cyan)">YES</strong>' : '<span style="color:var(--muted)">NO</span>'}</td>
        <td style="font-size:0.73rem;">${item.reason || '—'}</td>
      `;
      tbody.appendChild(tr);
    }

    summaryBox.innerHTML = `
      <strong>Detected Uplink Gateways:</strong> ${data.detected_gateways ? data.detected_gateways.join(', ') : 'None'}<br>
      <strong>Local Host PC Addresses:</strong> ${data.detected_local_ips ? data.detected_local_ips.join(', ') : 'None'}<br>
      <strong>Capture Status:</strong> Interface: ${data.capture_interface || 'None'} · Packets Captured: ${(data.capture_status && data.capture_status.packets_captured) || 0}
    `;
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--red);">Failed to load diagnostics.</td></tr>';
  }
}

if (diagBtn) {
  diagBtn.addEventListener('click', () => {
    diagBackdrop.classList.add('open');
    loadDiagnostics();
  });
}
if (closeDiag) closeDiag.addEventListener('click', () => diagBackdrop.classList.remove('open'));
if (dismissDiag) dismissDiag.addEventListener('click', () => diagBackdrop.classList.remove('open'));
if (reRunDiag) reRunDiag.addEventListener('click', loadDiagnostics);

// ---------------- Initialization ----------------
console.log('[NetPilot AI] Frontend Console Initialized');
pollAll();
pollGraph();
setInterval(pollAll, POLL_MS);
setInterval(pollGraph, POLL_MS * 3);