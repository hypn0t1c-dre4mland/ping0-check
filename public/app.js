// App State
let currentData = null;
let autoRefreshTimer = null;
let isRefreshing = false;

// DOM Elements
const ipAddressEl = document.getElementById('ipAddress');
const copyIpBtn = document.getElementById('copyIpBtn');
const geoFlagEl = document.getElementById('geoFlag');
const geoLocEl = document.getElementById('geoLoc');
const asnTagEl = document.getElementById('asnTag');
const orgTagEl = document.getElementById('orgTag');
const ping0TagEl = document.getElementById('ping0Tag');
const usersTagEl = document.getElementById('usersTag');
const checkTimeTagEl = document.getElementById('checkTimeTag');
const proxyStatusBadgeEl = document.getElementById('proxyStatusBadge');
const latencyBadgeEl = document.getElementById('latencyBadge');

const riskValueNumberEl = document.getElementById('riskValueNumber');
const riskValueLabelEl = document.getElementById('riskValueLabel');
const riskDescriptionEl = document.getElementById('riskDescription');
const breakdownListEl = document.getElementById('breakdownList');

const nativeStatusEl = document.getElementById('nativeStatus');
const ipTypeStatusEl = document.getElementById('ipTypeStatus');
const ping0TypeTextEl = document.getElementById('ping0TypeText');
const sharedUsersTextEl = document.getElementById('sharedUsersText');
const aiCheckTextEl = document.getElementById('aiCheckText');
const privacyStatusEl = document.getElementById('privacyStatus');

const starTiktokEl = document.getElementById('starTiktok');
const starChatgptEl = document.getElementById('starChatgpt');
const starEcommerceEl = document.getElementById('starEcommerce');
const starStreamingEl = document.getElementById('starStreaming');

const specTableBodyEl = document.getElementById('specTableBody');
const tableGenTimeEl = document.getElementById('tableGenTime');
const speedTableBodyEl = document.getElementById('speedTableBody');
const speedGenTimeEl = document.getElementById('speedGenTime');

const refreshBtn = document.getElementById('refreshBtn');
const notifyBtn = document.getElementById('notifyBtn');
const autoRefreshCheckbox = document.getElementById('autoRefreshCheckbox');
const statusAlert = document.getElementById('statusAlert');
const historyTableBody = document.getElementById('historyTableBody');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

// Country to Flag emoji map
function getFlagEmoji(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// Convert score to Star string
function getStars(num) {
  return '⭐'.repeat(Math.max(1, Math.min(5, num)));
}

// Highlight risk bar segment
function updateRiskBar(score) {
  const segments = document.querySelectorAll('.risk-seg');
  segments.forEach(seg => seg.classList.remove('active-seg'));
  let activeRange = '0-15';
  if (score <= 15) activeRange = '0-15';
  else if (score <= 25) activeRange = '15-25';
  else if (score <= 40) activeRange = '25-40';
  else if (score <= 50) activeRange = '40-50';
  else if (score <= 70) activeRange = '50-70';
  else activeRange = '70-100';
  const target = document.querySelector(`.risk-seg[data-range="${activeRange}"]`);
  if (target) target.classList.add('active-seg');
}

// Update UI with detection data
function renderData(data) {
  currentData = data;

  // Latency badge
  if (typeof data.latencyMs === 'number') {
    latencyBadgeEl.textContent = `⚡ 引擎耗时: ${data.latencyMs}ms`;
  }

  // IP & Geo
  ipAddressEl.textContent = data.ip || '---';
  geoLocEl.textContent = data.loc || '未知位置';
  geoFlagEl.textContent = getFlagEmoji(data.countryCode || (data.loc.includes('美国') ? 'US' : ''));
  asnTagEl.textContent = data.asn || 'AS未知';
  orgTagEl.textContent = data.org || '未知运营商';
  if (ping0TagEl) {
    ping0TagEl.textContent = `Ping0: ${data.ping0OfficialType || '未同步'}`;
    if (data.ping0OfficialType && data.ping0OfficialType !== '未同步') {
      ping0TagEl.style.background = 'rgba(16,185,129,0.15)';
      ping0TagEl.style.color = '#10b981';
      ping0TagEl.style.borderColor = 'rgba(16,185,129,0.3)';
    }
  }
  if (usersTagEl) {
    usersTagEl.textContent = `👥 共享: ${data.estimatedUsers || '未知'}`;
  }
  checkTimeTagEl.textContent = `检测时间: ${data.formattedTime || '刚刚'}`;

  // Risk Score & Badge
  riskValueNumberEl.textContent = `${data.score}%`;
  riskValueNumberEl.style.color = data.riskColor || '#22c55e';
  riskValueLabelEl.textContent = data.riskLabel || '纯净';
  riskValueLabelEl.className = `score-badge ${data.badgeClass || 'badge-green'}`;
  riskDescriptionEl.textContent = data.riskDesc || '当前 IP 处于安全纯净区间。';

  // Highlight risk segment
  updateRiskBar(data.score);

  // Breakdown items
  if (Array.isArray(data.breakdown) && data.breakdown.length > 0) {
    breakdownListEl.innerHTML = data.breakdown.map(item => {
      const sign = item.delta > 0 ? `+${item.delta}%` : (item.delta === 0 ? '0%' : `${item.delta}%`);
      const color = item.delta > 0 ? '#f97316' : (item.delta < 0 ? '#10b981' : '#9ca3af');
      return `<span class="breakdown-item"><strong style="color:${color}">${sign}</strong> ${item.item} (${item.note})</span>`;
    }).join('');
  } else {
    breakdownListEl.innerHTML = `<span class="breakdown-item">基准评定良好</span>`;
  }

  // Attributes
  nativeStatusEl.innerHTML = `<span class="indicator-icon">${data.isNative ? '✅' : '📡'}</span><span>${data.nativeStatus || (data.isNative ? '物理原生单播 IP (Native)' : '跨国广播 IP (Anycast)')}</span>`;

  ipTypeStatusEl.innerHTML = `<span class="indicator-icon">${data.ipType && data.ipType.includes('家庭') ? '🏠' : '🏢'}</span><span>${data.ipType || 'IDC 机房 IP'}</span>`;

  if (ping0TypeTextEl) {
    ping0TypeTextEl.textContent = data.ping0OfficialType || '未同步';
  }

  if (sharedUsersTextEl) {
    sharedUsersTextEl.textContent = data.estimatedUsers || '评估中...';
  }

  aiCheckTextEl.textContent = data.aiCheck || '本地特征模型完成评估';

  // Privacy & Threat Intelligence
  if (data.privacy && data.privacy.tor) {
    privacyStatusEl.innerHTML = `<span class="indicator-icon">🚨</span><span style="color:#ef4444;">命中 Tor 匿名暗网出口</span>`;
  } else if (data.dnsbl && data.dnsbl.listed) {
    const listNames = Array.isArray(data.dnsbl.details) && data.dnsbl.details.length > 0 ? data.dnsbl.details.join(', ') : '实时黑名单';
    privacyStatusEl.innerHTML = `<span class="indicator-icon">⚠️</span><span style="color:#f97316;">命中实时 DNSBL 黑名单 (${listNames})</span>`;
  } else if (data.privacy && (data.privacy.vpn || data.privacy.proxy)) {
    privacyStatusEl.innerHTML = `<span class="indicator-icon">🛡️</span><span>公开代理 / VPN 出口</span>`;
  } else {
    privacyStatusEl.innerHTML = `<span class="indicator-icon">🛡️</span><span>未发现恶意标记或黑名单记录</span>`;
  }

  // Recommendations
  if (data.recommendations) {
    starTiktokEl.textContent = getStars(data.recommendations.tiktok);
    starChatgptEl.textContent = getStars(data.recommendations.chatgpt);
    starEcommerceEl.textContent = getStars(data.recommendations.ecommerce);
    starStreamingEl.textContent = getStars(data.recommendations.streaming);
  }

  // Render Specification Report Table (本次检测规格详表)
  if (Array.isArray(data.reportRows) && data.reportRows.length > 0) {
    tableGenTimeEl.textContent = `生成时间: ${data.formattedTime}`;
    specTableBodyEl.innerHTML = data.reportRows.map(row => `
      <tr>
        <td class="metric-title">${row.metric}</td>
        <td class="val-text">${row.value}</td>
        <td><span class="badge-status-${row.badgeType || 'neutral'}">${row.badge}</span></td>
        <td class="note-text">${row.note}</td>
      </tr>
    `).join('');
  }

  // Render Website Speed Results Table (常用网站测速表)
  if (Array.isArray(data.speedResults) && data.speedResults.length > 0) {
    if (speedGenTimeEl) speedGenTimeEl.textContent = `完成时间: ${data.formattedTime}`;
    if (speedTableBodyEl) {
      speedTableBodyEl.innerHTML = data.speedResults.map(site => {
        const badgeClass = `badge-status-${site.badgeType || 'neutral'}`;

        const latencyColor = (site.latency !== null && site.latency < 500) 
          ? '#22c55e' 
          : (site.latency !== null ? '#eab308' : '#ef4444');

        return `
          <tr>
            <td class="metric-title" style="font-size:14px;">${site.icon} ${site.name}</td>
            <td class="val-text" style="color: ${latencyColor};">${site.latencyText}</td>
            <td><span class="badge-status-neutral">${site.status}</span></td>
            <td><span class="${badgeClass}">${site.grade}</span></td>
          </tr>
        `;
      }).join('');
    }
  }

  // Status Pill
  proxyStatusBadgeEl.className = 'status-pill status-active';
  proxyStatusBadgeEl.innerHTML = `<span class="pulse-dot"></span> 代理正常 (7897)`;
  statusAlert.classList.add('hidden');
}

// Fetch detection data from backend
async function fetchCurrentStatus(isManual = false) {
  if (isRefreshing) return;
  isRefreshing = true;

  const refreshIcon = refreshBtn.querySelector('.refresh-icon');
  if (refreshIcon) refreshIcon.classList.add('rotating');

  try {
    const res = await fetch('/api/current-ip');
    const json = await res.json();

    if (json.success) {
      if (currentData && currentData.ip && currentData.ip !== json.ip) {
        console.log(`[IP Switch] Node IP changed: ${currentData.ip} -> ${json.ip}`);
        triggerNotification();
      }
      renderData(json);
      await loadHistory();
    } else {
      showError(json.error || '获取 IP 风控信息失败');
    }
  } catch (err) {
    showError(`网络请求异常: ${err.message} (请确认本地服务及 Clash 7897 端口已启动)`);
  } finally {
    isRefreshing = false;
    if (refreshIcon) refreshIcon.classList.remove('rotating');
  }
}

// Fetch detection history
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const list = await res.json();
    if (!Array.isArray(list) || list.length === 0) {
      historyTableBody.innerHTML = `<tr><td colspan="6" class="empty-cell">暂无历史检测记录</td></tr>`;
      return;
    }

    historyTableBody.innerHTML = list.map(item => `
      <tr>
        <td style="color:#9ca3af; font-family:monospace;">${item.time}</td>
        <td style="font-weight:600; font-family:monospace;">${item.ip}</td>
        <td>${item.loc}</td>
        <td style="color:#9ca3af;">${item.ipType || 'IDC 机房'}</td>
        <td><strong style="color:${item.color}">${item.score}%</strong></td>
        <td><span class="score-badge" style="background:${item.color}22; color:${item.color}; border: 1px solid ${item.color}55;">${item.label}</span></td>
      </tr>
    `).join('');
  } catch (e) {
    console.error('Failed to load history:', e);
  }
}

// Show alert banner
function showError(msg) {
  statusAlert.textContent = `⚠️ ${msg}`;
  statusAlert.className = 'alert alert-error';
  statusAlert.classList.remove('hidden');
  proxyStatusBadgeEl.className = 'status-pill';
  proxyStatusBadgeEl.style.background = 'rgba(239, 68, 68, 0.15)';
  proxyStatusBadgeEl.style.color = '#ef4444';
  proxyStatusBadgeEl.style.borderColor = 'rgba(239, 68, 68, 0.3)';
  proxyStatusBadgeEl.innerHTML = `<span style="color:#ef4444;">●</span> 代理异常 / 未连接`;
}

// Trigger Windows Toast
async function triggerNotification() {
  try {
    await fetch('/api/notify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentData || {})
    });
  } catch (e) {
    console.error('Failed to trigger toast:', e);
  }
}

// Setup Auto-refresh
function setupAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  if (autoRefreshCheckbox.checked) {
    autoRefreshTimer = setInterval(() => {
      fetchCurrentStatus(false);
    }, 15000);
  }
}

// Event Listeners
refreshBtn.addEventListener('click', () => fetchCurrentStatus(true));
notifyBtn.addEventListener('click', triggerNotification);
autoRefreshCheckbox.addEventListener('change', setupAutoRefresh);

copyIpBtn.addEventListener('click', () => {
  if (currentData && currentData.ip) {
    navigator.clipboard.writeText(currentData.ip).then(() => {
      copyIpBtn.textContent = '✅';
      setTimeout(() => copyIpBtn.textContent = '📋', 1500);
    });
  }
});

clearHistoryBtn.addEventListener('click', () => {
  historyTableBody.innerHTML = `<tr><td colspan="6" class="empty-cell">记录已清空</td></tr>`;
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  fetchCurrentStatus(true);
  setupAutoRefresh();
});
