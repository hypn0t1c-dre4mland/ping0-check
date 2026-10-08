const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { calculateRiskScore } = require('./risk_engine');
const { testAllWebsites } = require('./speed_tester');

const PORT = 39088;
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 7897;

// In-memory cache & history
let lastCheckResult = null;
let checkHistory = [];
const ping0MemoryCache = new Map();

/**
 * Visual width calculator for console table formatting (supports CJK, ASCII & emojis accurately)
 */
function getVisualWidth(str) {
  let width = 0;
  for (const ch of String(str || '')) {
    const code = ch.codePointAt(0);
    // Ignore zero-width variation selectors, joiners and enclosing modifiers
    if ((code >= 0xfe00 && code <= 0xfe0f) || code === 0x200d || code === 0x20e3 || (code >= 0x1f3fb && code <= 0x1f3ff)) {
      continue;
    }
    if ((code >= 0x4e00 && code <= 0x9fff) || (code >= 0x3400 && code <= 0x4dbf) ||
        (code >= 0x3000 && code <= 0x303f) || (code >= 0xff01 && code <= 0xff60) ||
        (code >= 0x1f300 && code <= 0x1faff) || (code >= 0x2600 && code <= 0x27bf)) {
      width += 2;
    } else {
      width += 1;
    }
  }
  return width;
}

function padVisual(str, targetWidth) {
  const w = getVisualWidth(str);
  if (w >= targetWidth) return String(str || '');
  return String(str || '') + ' '.repeat(targetWidth - w);
}

function fitVisual(str, targetWidth) {
  const s = String(str || '');
  const w = getVisualWidth(s);
  if (w <= targetWidth) {
    return s + ' '.repeat(targetWidth - w);
  }
  let currentWidth = 0;
  let res = '';
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if ((code >= 0xfe00 && code <= 0xfe0f) || code === 0x200d || code === 0x20e3 || (code >= 0x1f3fb && code <= 0x1f3ff)) {
      res += ch;
      continue;
    }
    const charW = ((code >= 0x4e00 && code <= 0x9fff) || (code >= 0x3400 && code <= 0x4dbf) ||
        (code >= 0x3000 && code <= 0x303f) || (code >= 0xff01 && code <= 0xff60) ||
        (code >= 0x1f300 && code <= 0x1faff) || (code >= 0x2600 && code <= 0x27bf)) ? 2 : 1;
    if (currentWidth + charW > targetWidth - 2) {
      res += '..';
      currentWidth += 2;
      break;
    }
    res += ch;
    currentWidth += charW;
  }
  return res + ' '.repeat(Math.max(0, targetWidth - currentWidth));
}

/**
 * Print a sleek console report table on every detection request
 */
function printConsoleReportTable(data) {
  const wKey = 16;
  const wVal = 76;

  const breakdownSummary = (data.breakdown || [])
    .map(b => (b.delta > 0 ? (b === data.breakdown[0] ? `${b.delta}%` : `+${b.delta}%`) : (b.delta === 0 ? '0%' : `${b.delta}%`)) + ' ' + (b.short || b.item))
    .join(' | ');

  const threatText = data.privacy?.tor 
    ? '命中 Tor 出口节点 (高危)'
    : (data.dnsbl?.listed
      ? `命中 DNSBL 黑名单 (${data.dnsbl.details.join(', ')})`
      : ((data.privacy?.proxy || data.privacy?.vpn)
        ? '公开代理 / VPN 出口' 
        : '未发现恶意标记或黑名单记录'));

  const rows = [
    ['出口 IP 地址', `${data.ip}`],
    ['地理归属位置', `${data.loc}`],
    ['自治系统 ASN', `${data.asn} (${data.org})`],
    ['IP 类型', `${data.ipType}`],
    ['原生单播属性', `${data.nativeStatus || (data.isNative ? '物理原生单播 IP (Native)' : '跨国广播 IP (Anycast)')}`],
    ['预估共享人数', `${data.estimatedUsers || '未知'}`],
    ['综合风控评级', `${data.score}% [${data.riskLabel}]`],
    ['分值评定构成', `${breakdownSummary}`],
    ['威胁情报状态', `${threatText}`],
    ['业务适用建议', `TikTok: ${data.recommendations?.tiktok || 5}星 | ChatGPT: ${data.recommendations?.chatgpt || 5}星 | 电商: ${data.recommendations?.ecommerce || 4}星`],
    ['全流程耗时', `${data.latencyMs}ms`]
  ];

  console.log('\n┌' + '─'.repeat(wKey + 2) + '┬' + '─'.repeat(wVal + 2) + '┐');
  console.log('│ ' + padVisual(`📋 节点 IP 纯净度与风控报告 [${data.formattedTime}]`, wKey + wVal + 3) + ' │');
  console.log('├' + '─'.repeat(wKey + 2) + '┼' + '─'.repeat(wVal + 2) + '┤');
  for (const [k, v] of rows) {
    console.log('│ ' + fitVisual(k, wKey) + ' │ ' + fitVisual(v, wVal) + ' │');
  }
  console.log('└' + '─'.repeat(wKey + 2) + '┴' + '─'.repeat(wVal + 2) + '┘');

  if (Array.isArray(data.speedResults) && data.speedResults.length > 0) {
    const c1 = 20, c2 = 14, c3 = 18, c4 = 14;
    console.log('\n┌' + '─'.repeat(c1 + 2) + '┬' + '─'.repeat(c2 + 2) + '┬' + '─'.repeat(c3 + 2) + '┬' + '─'.repeat(c4 + 2) + '┐');
    console.log('│ ' + padVisual('⚡ 常用服务连通性与延迟测速', c1 + c2 + c3 + c4 + 9) + ' │');
    console.log('├' + '─'.repeat(c1 + 2) + '┼' + '─'.repeat(c2 + 2) + '┼' + '─'.repeat(c3 + 2) + '┼' + '─'.repeat(c4 + 2) + '┤');
    console.log('│ ' + fitVisual('目标服务', c1) + ' │ ' + fitVisual('往返延迟', c2) + ' │ ' + fitVisual('HTTP 状态', c3) + ' │ ' + fitVisual('连通评级', c4) + ' │');
    console.log('├' + '─'.repeat(c1 + 2) + '┼' + '─'.repeat(c2 + 2) + '┼' + '─'.repeat(c3 + 2) + '┼' + '─'.repeat(c4 + 2) + '┤');
    for (const site of data.speedResults) {
      console.log('│ ' + fitVisual(`${site.icon} ${site.name}`, c1) + ' │ ' + fitVisual(site.latencyText, c2) + ' │ ' + fitVisual(site.status, c3) + ' │ ' + fitVisual(site.grade, c4) + ' │');
    }
    console.log('└' + '─'.repeat(c1 + 2) + '┴' + '─'.repeat(c2 + 2) + '┴' + '─'.repeat(c3 + 2) + '┴' + '─'.repeat(c4 + 2) + '┘\n');
  }
}

/**
 * Standard HTTP/HTTPS tunnel via Clash proxy (127.0.0.1:7897)
 */
function fetchViaProxy(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const isHttps = url.protocol === 'https:';
    const port = url.port || (isHttps ? 443 : 80);
    const timeout = options.timeout || 6000;

    const proxyReq = net.connect(PROXY_PORT, PROXY_HOST, () => {
      proxyReq.write(`CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\n\r\n`);
      proxyReq.once('data', (d) => {
        if (!d.toString().includes('200')) {
          proxyReq.destroy();
          return reject(new Error(`Proxy CONNECT error: ${d.toString().split('\r\n')[0]}`));
        }

        const transport = isHttps ? https : http;
        const agent = new transport.Agent({ socket: proxyReq, rejectUnauthorized: false });

        const req = transport.get(urlStr, {
          agent,
          timeout,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            ...(options.headers || {})
          }
        }, (res) => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });

        req.on('timeout', () => req.destroy(new Error('Request timed out')));
        req.on('error', reject);
      });
    });

    proxyReq.setTimeout(timeout, () => proxyReq.destroy(new Error('Proxy connection timed out')));
    proxyReq.on('error', reject);
  });
}

/**
 * Parse Ping0 official native ipleak response (supports window.ipinfo object & HTML table fallback)
 */
function parsePing0Leak(html) {
  if (!html || typeof html !== 'string') return null;

  // 1. 优先提取嵌入的 window.ipinfo 原生 JS 对象
  const scriptMatch = html.match(/window\.ipinfo\s*=\s*\{([\s\S]*?)\}/);
  if (scriptMatch) {
    const content = scriptMatch[1];
    const extract = (key) => {
      const regex = new RegExp(key + "\\s*:\\s*['\"]([^'\"]*)['\"]");
      const match = content.match(regex);
      return match ? match[1].trim() : '';
    };
    const ip = extract('ip');
    if (ip) {
      return {
        ip,
        addr: extract('addr'),
        countrycode: extract('countrycode').toUpperCase(),
        asn: extract('asn').replace(/&mdash;/g, '—'),
        org: extract('org'),
        iptype: extract('iptype')
      };
    }
  }

  // 2. 备用兜底：从页面 HTML 规格表格 table.myip 中提取
  const extractRow = (label) => {
    const regex = new RegExp(label + '[\\s\\S]*?<td>([\\s\\S]*?)<\\/td>', 'i');
    const match = html.match(regex);
    if (!match) return '';
    return match[1].replace(/<[^>]+>/g, '').replace(/&mdash;/g, '—').trim();
  };
  const ip = extractRow('IP地址');
  if (ip && net.isIPv4(ip)) {
    const addr = extractRow('IP位置');
    const asn = extractRow('ASN');
    const org = extractRow('企业');
    const iptype = extractRow('IP 类型');
    const flagMatch = html.match(/flags\/([a-z]{2})\.png/i);
    const countrycode = flagMatch ? flagMatch[1].toUpperCase() : '';
    return { ip, addr, countrycode, asn, org, iptype };
  }

  return null;
}

/**
 * 备用免盾快速 Geo 解析器 (http://ipv4.ping0.cc/geo/jsonp/ipv4cb)
 */
function parsePing0Geo(text) {
  if (!text || typeof text !== 'string') return null;
  const match = text.match(/ipv4cb\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"(?:\s*,\s*"([^"]+)")?/);
  if (match) {
    return {
      ip: match[1],
      addr: match[2],
      asn: match[3],
      org: match[4],
      countrycode: (match[5] || '').toUpperCase(),
      iptype: ''
    };
  }
  return null;
}

/**
 * Query real-time DNSBL blacklist via Google DoH over Clash proxy
 */
async function checkDnsbl(ip, timeout = 2500) {
  if (!ip || typeof ip !== 'string' || !net.isIPv4(ip)) {
    return { listed: false, details: [] };
  }
  const reversed = ip.split('.').reverse().join('.');
  const dnsbls = [
    { host: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT-L1' },
    { host: 'bl.spamcop.net', name: 'SpamCop' }
  ];

  const results = await Promise.all(dnsbls.map(async ({ host, name }) => {
    try {
      const qname = `${reversed}.${host}`;
      const urlStr = `https://dns.google/resolve?name=${qname}&type=A`;
      const res = await fetchViaProxy(urlStr, { timeout });
      if (res && res.status === 200) {
        const json = JSON.parse(res.body);
        if (json.Status === 0 && Array.isArray(json.Answer) && json.Answer.length > 0) {
          const hitIp = json.Answer[0].data;
          if (hitIp && hitIp.startsWith('127.')) {
            return { listed: true, name, hitIp };
          }
        }
      }
    } catch (e) {}
    return { listed: false, name };
  }));

  const hits = results.filter(r => r.listed);
  return {
    listed: hits.length > 0,
    details: hits.map(h => h.name)
  };
}

/**
 * 综合风控检测流程（并发请求 Ping0 接口、Google DoH DNSBL 黑名单与主流测速）
 */
async function performIndependentRiskCheck() {
  const startTime = Date.now();

  let ipData = {
    ip: '',
    country: '',
    countryCode: '',
    registeredCountry: '',
    region: '',
    city: '',
    isp: '',
    org: '',
    asn: '',
    isAnycast: false,
    ping0Type: '',
    privacy: { vpn: false, proxy: false, hosting: false, tor: false },
    dnsbl: { listed: false, details: [] }
  };
  let ping0Info = null;

  // 1. 并发请求：ip-api + ping0 ipleak 原生接口 + 常用网站测速
  const [ipRes, ping0Res, speedResults] = await Promise.all([
    fetchViaProxy('http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query', { timeout: 4000 }).catch(err => {
      console.warn('[Risk Server] ip-api request failed:', err.message);
      return null;
    }),
    fetchViaProxy('http://ipv4.ping0.cc/ipleak', { timeout: 5000 }).catch(err => {
      console.warn('[Risk Server] ping0 ipleak request failed:', err.message);
      return null;
    }),
    testAllWebsites(4000)
  ]);

  // 同步 ping0.cc 原生接口认证数据 (权威 iptype 与 中文位置)
  if (ping0Res && ping0Res.status === 200) {
    ping0Info = parsePing0Leak(ping0Res.body);
    if (ping0Info && ping0Info.ip) {
      ping0MemoryCache.set(ping0Info.ip, ping0Info);
    }
  }

  // 备用降级：若 ipleak 触发 Cloudflare 盾或超时，优先读缓存或请求免盾 geo 接口
  if (!ping0Info) {
    const detectedIp = (ipRes && ipRes.status === 200) ? (() => { try { return JSON.parse(ipRes.body).query; } catch(e){ return ''; } })() : '';
    if (detectedIp && ping0MemoryCache.has(detectedIp)) {
      ping0Info = ping0MemoryCache.get(detectedIp);
    } else {
      const geoRes = await fetchViaProxy('http://ipv4.ping0.cc/geo/jsonp/ipv4cb', { timeout: 3000 }).catch(() => null);
      if (geoRes && geoRes.status === 200) {
        const geoInfo = parsePing0Geo(geoRes.body);
        if (geoInfo) {
          ping0Info = geoInfo;
          if (ping0MemoryCache.has(geoInfo.ip) && ping0MemoryCache.get(geoInfo.ip).iptype) {
            ping0Info.iptype = ping0MemoryCache.get(geoInfo.ip).iptype;
          }
        }
      }
    }
  }

  if (ping0Info) {
    ipData.ip = ping0Info.ip || ipData.ip;
    ipData.ping0Type = ping0Info.iptype || ipData.ping0Type;
    ipData.ping0Synced = true;
    if (ping0Info.countrycode && !ipData.countryCode) ipData.countryCode = ping0Info.countrycode;
    if (ping0Info.asn && !ipData.asn) ipData.asn = ping0Info.asn.split(' ')[0];
    if (ping0Info.org && !ipData.org) ipData.org = ping0Info.org;
  }

  // 解析 ip-api 接口数据补充特征
  if (ipRes && ipRes.status === 200) {
    try {
      const data = JSON.parse(ipRes.body);
      if (data.status === 'success') {
        ipData.ip = data.query || ipData.ip;
        ipData.country = data.country || ipData.country;
        ipData.countryCode = data.countryCode || ipData.countryCode;
        ipData.region = data.regionName || ipData.region;
        ipData.city = data.city || ipData.city;
        ipData.isp = data.isp || ipData.isp;
        ipData.org = data.org || ipData.org;
        ipData.asn = (data.as || '').split(' ')[0] || ipData.asn;
        ipData.privacy.proxy = !!data.proxy;
        ipData.privacy.hosting = !!data.hosting;
      }
    } catch (e) {}
  }

  if (!ipData.ip) {
    throw new Error('无法连接到 Clash Verge 代理出口（请确认 127.0.0.1:7897 正常运行）');
  }

  // 2. 阶段二：针对出口 IP 并发执行 Google DoH DNSBL 黑名单探测与 ipinfo 提取真实 RIR 注册国
  const [dnsblResult, infoRes] = await Promise.all([
    checkDnsbl(ipData.ip, 2500).catch(() => ({ listed: false, details: [] })),
    fetchViaProxy(`https://ipinfo.io/widget/demo/${ipData.ip}`, {
      headers: { 'Referer': 'https://ipinfo.io/' },
      timeout: 3000
    }).catch(err => {
      console.warn('[Risk Server] ipinfo supplementary check failed:', err.message);
      return null;
    })
  ]);

  ipData.dnsbl = dnsblResult || { listed: false, details: [] };

  if (infoRes && infoRes.status === 200) {
    try {
      const parsed = JSON.parse(infoRes.body);
      if (parsed && parsed.data) {
        const d = parsed.data;
        // RIR 注册国来源于 WHOIS / abuse.country，与实际物理落地国 d.country 区分
        if (d.abuse && d.abuse.country) {
          ipData.registeredCountry = String(d.abuse.country).trim().toUpperCase();
        } else if (d.country && !ipData.registeredCountry) {
          ipData.registeredCountry = String(d.country).trim().toUpperCase();
        }
        if (d.country && !ipData.countryCode) {
          ipData.countryCode = String(d.country).trim().toUpperCase();
        }
        if (d.asn) {
          ipData.asn = d.asn.asn || ipData.asn;
          ipData.org = d.asn.name || ipData.org;
        }
        if (typeof d.is_anycast === 'boolean') {
          ipData.isAnycast = d.is_anycast;
        }
        if (d.privacy) {
          ipData.privacy.vpn = !!d.privacy.vpn;
          ipData.privacy.proxy = ipData.privacy.proxy || !!d.privacy.proxy;
          ipData.privacy.hosting = typeof d.privacy.hosting === 'boolean' ? d.privacy.hosting : ipData.privacy.hosting;
          ipData.privacy.tor = !!d.privacy.tor;
        }
      }
    } catch (e) {}
  }

  // 3. 送入【本地独立风控评估模型】计算最终综合风控分
  const riskResult = calculateRiskScore(ipData);
  const latencyMs = Date.now() - startTime;
  let loc = '';
  if (ping0Info && ping0Info.addr) {
    loc = ping0Info.addr;
  } else {
    loc = `${ipData.country || ''} ${ipData.region || ''} ${ipData.city || ''}`.replace(/\s+/g, ' ').trim();
  }
  if (!loc) loc = '全球节点';

  // 构建结构化表格数据 (用于 Web UI 规格表)
  const isThreat = ipData.privacy.tor || ipData.privacy.proxy || ipData.privacy.vpn || ipData.dnsbl.listed;
  const threatText = ipData.privacy.tor 
    ? '命中 Tor 出口节点 (高危)' 
    : (ipData.dnsbl.listed 
      ? `命中 DNSBL 黑名单 (${ipData.dnsbl.details.join(', ')})` 
      : (isThreat ? '公开代理 / VPN 出口' : '未发现恶意标记或黑名单记录'));

  const breakdownSummary = (riskResult.breakdown || [])
    .map(b => (b.delta > 0 ? (b === riskResult.breakdown[0] ? `${b.delta}%` : `+${b.delta}%`) : (b.delta === 0 ? '0%' : `${b.delta}%`)) + ' ' + (b.short || b.item))
    .join(' | ');

  const reportRows = [
    { metric: '出口 IP 地址', value: ipData.ip, badge: '正常连通', badgeType: 'success', note: '通过 Clash 代理出境' },
    { metric: '地理归属位置', value: loc || '全球节点', badge: ipData.countryCode || 'LOC', badgeType: 'info', note: '高精度地理定位' },
    { metric: '自治系统 ASN', value: `${ipData.asn} (${ipData.org || ipData.isp})`, badge: 'BGP广播', badgeType: 'info', note: '单播路由' },
    { metric: 'IP 类型', value: riskResult.ipType, badge: riskResult.ipType.includes('家庭') ? '家庭宽带' : 'IDC机房', badgeType: riskResult.ipType.includes('家庭') ? 'success' : 'neutral', note: riskResult.ipType.includes('家庭') ? '住宅宽带出口' : '商业数据中心服务器' },
    { metric: '原生单播属性', value: riskResult.nativeStatus, badge: riskResult.isNative ? '原生' : '广播', badgeType: riskResult.isNative ? 'success' : 'warning', note: riskResult.nativeReason },
    { metric: '预估共享人数', value: riskResult.estimatedUsers, badge: '信誉评估', badgeType: riskResult.score <= 25 ? 'success' : (riskResult.score <= 40 ? 'lime' : (riskResult.score <= 70 ? 'warning' : 'danger')), note: '基于网络拓扑与代理属性估算' },
    { metric: '综合风控评级', value: `${riskResult.score}% [${riskResult.riskLabel}]`, badge: riskResult.riskLabel, badgeType: (riskResult.riskLevel === 'very_clean' || riskResult.riskLevel === 'clean') ? 'success' : (riskResult.riskLevel === 'neutral' ? 'lime' : (riskResult.riskLevel === 'high_risk' ? 'danger' : 'warning')), note: riskResult.riskDesc },
    { metric: '分值评定构成', value: breakdownSummary, badge: '加权明细', badgeType: 'info', note: '多维因子动态加权' },
    { metric: '威胁情报状态', value: threatText, badge: ipData.privacy.tor ? '高危' : (ipData.dnsbl.listed ? '黑名单' : (isThreat ? '代理出口' : '安全良好')), badgeType: ipData.privacy.tor ? 'danger' : (ipData.dnsbl.listed ? 'danger' : (isThreat ? (riskResult.score <= 25 ? 'info' : 'warning') : 'success')), note: ipData.dnsbl.listed ? '检测到历史黑名单记录' : '未检出安全威胁' },
    { metric: '业务适用建议', value: `TikTok: ${riskResult.recommendations?.tiktok || 5}星 | ChatGPT: ${riskResult.recommendations?.chatgpt || 5}星 | 电商: ${riskResult.recommendations?.ecommerce || 4}星`, badge: '多场景适用', badgeType: 'success', note: '可稳定访问海外主流平台' },
    { metric: '全流程耗时', value: `${latencyMs}ms`, badge: '极速', badgeType: 'success', note: '端到端探测总耗时' }
  ];

  const finalResult = {
    success: true,
    engine: 'Local Native Risk Engine (100% 独立本地引擎 · 动态加权)',
    timestamp: new Date().toISOString(),
    formattedTime: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
    latencyMs,
    ip: ipData.ip,
    loc: loc || '全球节点',
    country: ipData.country,
    countryCode: ipData.countryCode,
    region: ipData.region,
    city: ipData.city,
    asn: ipData.asn || 'AS未知',
    org: ipData.org || ipData.isp || '未知运营商',
    ...riskResult,
    privacy: ipData.privacy,
    dnsbl: ipData.dnsbl,
    reportRows,
    speedResults
  };

  // 控制台打印好看的表格
  printConsoleReportTable(finalResult);

  lastCheckResult = finalResult;

  // 记录历史（最多保留 30 条）
  checkHistory.unshift({
    time: finalResult.formattedTime,
    ip: finalResult.ip,
    loc: finalResult.loc,
    score: finalResult.score,
    label: finalResult.riskLabel,
    color: finalResult.riskColor,
    ipType: finalResult.ipType,
    estimatedUsers: finalResult.estimatedUsers
  });
  if (checkHistory.length > 30) checkHistory.pop();

  return finalResult;
}

/**
 * Windows 原生气泡通知
 */
function sendToastNotification(title, message) {
  const scriptPath = path.join(__dirname, 'send_toast.ps1');
  const safeTitle = title.replace(/"/g, '`"');
  const safeMsg = message.replace(/"/g, '`"');
  const cmd = `powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}" -Title "${safeTitle}" -Message "${safeMsg}"`;
  exec(cmd, (err) => {
    if (err) console.error('Toast execution failed:', err.message);
  });
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // API 接口
  if (pathname === '/api/current-ip' || pathname === '/api/check') {
    try {
      const data = await performIndependentRiskCheck();
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
    return;
  }

  if (pathname === '/api/last-status') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(lastCheckResult || { success: false, message: '尚未执行检测' }));
    return;
  }

  if (pathname === '/api/history') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(checkHistory));
    return;
  }

  if (pathname === '/api/notify' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const payload = body ? JSON.parse(body) : (lastCheckResult || {});
        const title = "Clash Verge - IP 纯净度检测";
        const msg = `IP: ${payload.ip || 'Unknown'} | 风控: ${payload.score || 0}% (${payload.riskLabel || 'OK'}) | ${payload.loc || 'Global'}`;
        sendToastNotification(title, msg);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // 静态页面托管
  let filePath = path.join(__dirname, 'public', pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath).toLowerCase();

  const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('500 Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
      res.end(content);
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n======================================================`);
  console.log(`  🛡️ Clash Verge 独立 IP 纯净度与风控中枢已启动`);
  console.log(`  ⚡ 本地引擎: 动态多层级风控模型 + Ping0 权威类型同步`);
  console.log(`  🔗 本地面板: http://127.0.0.1:${PORT}`);
  console.log(`  🎯 监听代理: 127.0.0.1:${PROXY_PORT}`);
  console.log(`======================================================\n`);

  performIndependentRiskCheck().then(res => {
    sendToastNotification(
      "Clash Verge - IP Risk Ready",
      `IP: ${res.ip} | Score: ${res.score}% (${res.riskLabel}) | ${res.loc}`
    );
  }).catch(e => {
    console.warn('[LocalEngine] 初始检测失败（Clash可能未就绪）:', e.message);
  });
});
