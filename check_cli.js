const { calculateRiskScore } = require('./risk_engine');
const { testAllWebsites } = require('./speed_tester');
const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

if (process.platform === 'win32') {
  try {
    process.title = 'Clash 节点 IP 纯净度与连通性检测';
  } catch (e) {}
}

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 7897;

/**
 * Visual width calculator supporting CJK, ASCII and emojis (accurately handles zero-width variation selectors)
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

/**
 * Exact width fitter for flawless console table box alignment
 */
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
 * Standard HTTP/HTTPS tunnel via Clash proxy (127.0.0.1:7897)
 */
function fetchViaProxy(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const isHttps = url.protocol === 'https:';
    const port = url.port || (isHttps ? 443 : 80);
    const timeout = options.timeout || 5000;

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
          res.on('end', () => resolve({ status: res.statusCode, body }));
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

function loadPing0Cache() {
  try {
    const p = path.join(__dirname, '.ping0_cache.json');
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {}
  return {};
}

function savePing0Cache(cache) {
  try {
    const p = path.join(__dirname, '.ping0_cache.json');
    fs.writeFileSync(p, JSON.stringify(cache, null, 2), 'utf8');
  } catch (e) {}
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

function sendToast(title, message) {
  const scriptPath = path.join(__dirname, 'send_toast.ps1');
  const safeTitle = title.replace(/"/g, '`"');
  const safeMsg = message.replace(/"/g, '`"');
  exec(`powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}" -Title "${safeTitle}" -Message "${safeMsg}"`);
}

async function run() {
  const startTime = Date.now();
  console.log('\n========================================================================');
  console.log('  🛡️  Clash 节点 IP 纯净度与连通性检测');
  console.log('========================================================================');
  console.log('[1/2] 正在探测出口 IP 拓扑与主流服务连通性...');

  let ipData = {
    ip: '', country: '', countryCode: '', registeredCountry: '', region: '', city: '',
    isp: '', org: '', asn: '', isAnycast: false, ping0Type: '',
    privacy: { vpn: false, proxy: false, hosting: false, tor: false },
    dnsbl: { listed: false, details: [] }
  };
  let ping0Info = null;
  const ping0Cache = loadPing0Cache();

  // 并发请求：IP 基础归属 + Ping0 官方 ipleak 原生接口 + 常用网站测速
  const [ipRes, ping0Res, speedResults] = await Promise.all([
    fetchViaProxy('http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query').catch(() => null),
    fetchViaProxy('http://ipv4.ping0.cc/ipleak', { timeout: 5000 }).catch(() => null),
    testAllWebsites(4000)
  ]);

  if (!ipRes && !ping0Res) {
    console.error('\n[错误] 无法连接到 Clash 代理端口 7897！请先确认 Clash Verge 客户端已打开。');
    process.exit(1);
  }

  // 1. 同步 Ping0 原生认证接口数据 (权威 iptype 与 中文位置)
  if (ping0Res && ping0Res.status === 200) {
    ping0Info = parsePing0Leak(ping0Res.body);
    if (ping0Info && ping0Info.ip) {
      ping0Cache[ping0Info.ip] = ping0Info;
      savePing0Cache(ping0Cache);
    }
  }

  // 备用降级：若 ipleak 触发 Cloudflare 盾或超时，优先读缓存或请求免盾 geo 接口
  if (!ping0Info) {
    const detectedIp = (ipRes && ipRes.status === 200) ? (() => { try { return JSON.parse(ipRes.body).query; } catch(e){ return ''; } })() : '';
    if (detectedIp && ping0Cache[detectedIp]) {
      ping0Info = ping0Cache[detectedIp];
    } else {
      const geoRes = await fetchViaProxy('http://ipv4.ping0.cc/geo/jsonp/ipv4cb', { timeout: 3000 }).catch(() => null);
      if (geoRes && geoRes.status === 200) {
        const geoInfo = parsePing0Geo(geoRes.body);
        if (geoInfo) {
          ping0Info = geoInfo;
          if (ping0Cache[geoInfo.ip] && ping0Cache[geoInfo.ip].iptype) {
            ping0Info.iptype = ping0Cache[geoInfo.ip].iptype;
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

  // 2. 解析 ip-api 接口数据补充特征
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

  // 3. 辅助检测：实时 DNSBL 黑名单探测 + ipinfo 提取真实 RIR 注册国与 Anycast 属性
  if (ipData.ip) {
    const [dnsblResult, infoRes] = await Promise.all([
      checkDnsbl(ipData.ip, 2500).catch(() => ({ listed: false, details: [] })),
      fetchViaProxy(`https://ipinfo.io/widget/demo/${ipData.ip}`, {
        headers: { 'Referer': 'https://ipinfo.io/' },
        timeout: 2500
      }).catch(() => null)
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
  }

  console.log('[2/2] 评估完成，检测报告如下：');

  const risk = calculateRiskScore(ipData);
  const latency = Date.now() - startTime;
  let loc = '';
  if (ping0Info && ping0Info.addr) {
    loc = ping0Info.addr;
  } else {
    loc = `${ipData.country || ''} ${ipData.region || ''} ${ipData.city || ''}`.replace(/\s+/g, ' ').trim();
  }
  if (!loc) loc = '全球节点';
  const timeStr = new Date().toLocaleTimeString('zh-CN', { hour12: false });

  // ---------------- 表格一：IP 纯净度与多维风控报告 ----------------
  const wKey1 = 16;
  const wVal1 = 76;
  const threatText = ipData.privacy.tor 
    ? '命中 Tor 出口节点 (高危)'
    : (ipData.dnsbl.listed
      ? `命中 DNSBL 黑名单 (${ipData.dnsbl.details.join(', ')})`
      : ((ipData.privacy.proxy || ipData.privacy.vpn)
        ? '公开代理 / VPN 出口' 
        : '未发现恶意标记或黑名单记录'));

  const breakdownSummary = risk.breakdown
    .map(b => (b.delta > 0 ? (b === risk.breakdown[0] ? `${b.delta}%` : `+${b.delta}%`) : (b.delta === 0 ? '0%' : `${b.delta}%`)) + ' ' + (b.short || b.item))
    .join(' | ');

  const rows1 = [
    ['出口 IP 地址', `${ipData.ip}`],
    ['地理归属位置', `${loc}`],
    ['自治系统 ASN', `${ipData.asn} (${ipData.org || ipData.isp})`],
    ['IP 类型', `${risk.ipType}`],
    ['原生单播属性', `${risk.nativeStatus}`],
    ['预估共享人数', `${risk.estimatedUsers}`],
    ['综合风控评级', `${risk.score}% [${risk.riskLabel}]`],
    ['分值评定构成', `${breakdownSummary}`],
    ['威胁情报状态', `${threatText}`],
    ['业务适用建议', `TikTok: ${risk.recommendations.tiktok}星 | ChatGPT: ${risk.recommendations.chatgpt}星 | 电商: ${risk.recommendations.ecommerce}星`],
    ['全流程耗时', `${latency}ms`]
  ];

  console.log('\n┌' + '─'.repeat(wKey1 + 2) + '┬' + '─'.repeat(wVal1 + 2) + '┐');
  console.log('│ ' + padVisual(`📋 节点 IP 纯净度与风控报告 [${timeStr}]`, wKey1 + wVal1 + 3) + ' │');
  console.log('├' + '─'.repeat(wKey1 + 2) + '┼' + '─'.repeat(wVal1 + 2) + '┤');
  for (const [k, v] of rows1) {
    console.log('│ ' + fitVisual(k, wKey1) + ' │ ' + fitVisual(v, wVal1) + ' │');
  }
  console.log('└' + '─'.repeat(wKey1 + 2) + '┴' + '─'.repeat(wVal1 + 2) + '┘');

  // ---------------- 表格二：常用主流服务连通性测速表 ----------------
  const c1 = 20; // 目标服务
  const c2 = 14; // 往返延迟
  const c3 = 18; // HTTP 状态
  const c4 = 14; // 连通评级

  console.log('\n┌' + '─'.repeat(c1 + 2) + '┬' + '─'.repeat(c2 + 2) + '┬' + '─'.repeat(c3 + 2) + '┬' + '─'.repeat(c4 + 2) + '┐');
  console.log('│ ' + padVisual('⚡ 常用服务连通性与延迟测速', c1 + c2 + c3 + c4 + 9) + ' │');
  console.log('├' + '─'.repeat(c1 + 2) + '┼' + '─'.repeat(c2 + 2) + '┼' + '─'.repeat(c3 + 2) + '┼' + '─'.repeat(c4 + 2) + '┤');
  console.log('│ ' + fitVisual('目标服务', c1) + ' │ ' + fitVisual('往返延迟', c2) + ' │ ' + fitVisual('HTTP 状态', c3) + ' │ ' + fitVisual('连通评级', c4) + ' │');
  console.log('├' + '─'.repeat(c1 + 2) + '┼' + '─'.repeat(c2 + 2) + '┼' + '─'.repeat(c3 + 2) + '┼' + '─'.repeat(c4 + 2) + '┤');

  for (const site of speedResults) {
    console.log('│ ' + fitVisual(`${site.icon} ${site.name}`, c1) + ' │ ' + fitVisual(site.latencyText, c2) + ' │ ' + fitVisual(site.status, c3) + ' │ ' + fitVisual(site.grade, c4) + ' │');
  }
  console.log('└' + '─'.repeat(c1 + 2) + '┴' + '─'.repeat(c2 + 2) + '┴' + '─'.repeat(c3 + 2) + '┴' + '─'.repeat(c4 + 2) + '┘\n');

  // 发送系统桌面通知
  const avgPing = Math.round(speedResults.filter(s => s.latency).reduce((acc, cur) => acc + cur.latency, 0) / (speedResults.filter(s => s.latency).length || 1));
  sendToast(
    "节点 IP 检测与测速完成",
    `IP: ${ipData.ip} | 风控: ${risk.score}% (${risk.riskLabel}) | 均延: ${avgPing}ms`
  );

  console.log('✅ 检测完成。\n');
}

if (require.main === module) {
  run();
}

module.exports = {
  getVisualWidth,
  padVisual,
  fitVisual,
  run
};
