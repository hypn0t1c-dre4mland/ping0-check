/**
 * Local IP Risk & Cleanliness Evaluation Engine (100% 独立本地风控计算引擎 · 动态加权架构)
 * 具备 4 级 ASN 声誉库、双重原生 IP 校验、动态代理加权、实时 DNSBL 威胁情报、网段离散扰动算法与预估共享人数模型
 */

// 1. Tier 1 顶级云厂商 (高信用，严格风控合规，风控减免 -2%)
const TIER1_CLOUD_ASNS = new Set([
  'AS16509', 'AS14618', 'AS8987',   // Amazon AWS
  'AS15169', 'AS396982', 'AS36492', // Google Cloud
  'AS8075', 'AS8068', 'AS8069',     // Microsoft Azure
  'AS13335',                        // Cloudflare Inc
  'AS31898',                        // Oracle Corporation
  'AS45102', 'AS37963',             // Alibaba Cloud
  'AS132203', 'AS45090',            // Tencent Cloud
  'AS714'                           // Apple Inc
]);

// 2. Tier 2 标准商业 VPS / 优质中转 ASN (基准信用 0% 浮动)
const TIER2_STANDARD_VPS_ASNS = new Set([
  'AS25820',                        // IT7 Networks (搬瓦工 BandwagonHost)
  'AS14061', 'AS62567',             // DigitalOcean
  'AS63949',                        // Linode / Akamai
  'AS20473', 'AS64512',             // The Constant Company / Vultr
  'AS24940',                        // Hetzner Online GmbH
  'AS16276',                        // OVH SAS
  'AS979',                          // NetLab Global
  'AS174',                          // Cogent Communications
  'AS209',                          // CenturyLink / Lumen
  'AS3257',                         // GTT Communications
  'AS1299',                         // Arelion / Telia
  'AS36351',                        // IBM Cloud / SoftLayer
  'AS2906'                          // Netflix
]);
const STANDARD_VPS_ASNS = TIER2_STANDARD_VPS_ASNS;

// 3. Tier 3 商业 VPN / 骨干中转 ASN (多用户中转，轻度加权 +2%，不打高危标签)
const TIER3_COMMERCIAL_VPN_ASNS = new Set([
  'AS46997',                        // Black Mesa Corporation
  'AS60068',                        // Datacamp Limited
  'AS9009',                         // M247 Ltd
  'AS212238',                       // Datapacket
  'AS53667',                        // FranTech / BuyVM
  'AS54600',                        // Peg Tech Inc
  'AS46652',                        // Leaseweb
  'AS49981',                        // WorldStream B.V.
  'AS47583',                        // Hostinger
  'AS200651'                        // WebHorizon
]);
const TIER3_TRANSIT_ASNS = TIER3_COMMERCIAL_VPN_ASNS;

// 4. Tier 4 高危 / 高滥用主机 ASN (常年作为黑灰产或滥用节点，风险加权 +7%)
const TIER4_HIGH_RISK_ASNS = new Set([
  'AS51167',                        // Contabo GmbH
  'AS200019',                       // Alexhost SRL
  'AS30058',                        // FDCservers
  'AS55081'                         // 24-7 Internet
]);
const HIGH_RISK_PROXY_ASNS = TIER4_HIGH_RISK_ASNS;

// 5. Residential 全球主流家庭宽带 / 住宅运营商 ASN 白名单 (天然纯净)
const RESIDENTIAL_ISPS = new Set([
  'AS7922', 'AS7015',               // Comcast Cable
  'AS7018', 'AS6327',               // AT&T Services
  'AS701', 'AS6167',                // Verizon
  'AS20115', 'AS10796',             // Charter Spectrum
  'AS22773',                        // Cox Communications
  'AS5650',                         // Frontier Communications
  'AS3462', 'AS9924',               // Chunghwa Telecom (台湾中华电信)
  'AS4760', 'AS9269',               // HKT / PCCW (香港电讯盈科)
  'AS17676',                        // SoftBank Corp (日本软银)
  'AS4713', 'AS2516',               // NTT Communications / OCN
  'AS9318',                         // SK Broadband (韩国)
  'AS4766',                         // Korea Telecom (KT)
  'AS4134', 'AS4809', 'AS4812',     // China Telecom (中国电信)
  'AS4837', 'AS9929',               // China Unicom (中国联通)
  'AS9808', 'AS58453',              // China Mobile (中国移动)
  'AS2856',                         // British Telecom (BT)
  'AS3215',                         // Orange (法国)
  'AS3320',                         // Deutsche Telekom (德国电信)
  'AS6830',                         // Liberty Global (欧洲)
  'AS1221'                          // Telstra (澳大利亚)
]);

/**
 * 6-tier Risk Classification matching industry & Ping0 standards
 */
function classifyRiskTier(score) {
  if (score <= 15) {
    return {
      level: 'very_clean',
      label: '极度纯净',
      color: '#10b981',
      badgeClass: 'badge-emerald',
      desc: '独享住宅或优质本土出口，未检出任何扫描、爆破或滥用标记，信誉极高。'
    };
  } else if (score <= 25) {
    return {
      level: 'clean',
      label: '纯净',
      color: '#22c55e',
      badgeClass: 'badge-green',
      desc: '常规清洁 IP，属于正常商业服务器或原生宽带，未见异常黑名单记录。'
    };
  } else if (score <= 40) {
    return {
      level: 'neutral',
      label: '中性',
      color: '#84cc16',
      badgeClass: 'badge-lime',
      desc: '中性公用 IP，存在机房公用广播或节点共享，普通浏览与流媒体正常。'
    };
  } else if (score <= 50) {
    return {
      level: 'low_risk',
      label: '轻微风险',
      color: '#eab308',
      badgeClass: 'badge-yellow',
      desc: '检测到共享爬虫、代理池出口或轻微频繁访问行为，部分敏感平台可能有验证码。'
    };
  } else if (score <= 70) {
    return {
      level: 'medium_risk',
      label: '稍高风险',
      color: '#f97316',
      badgeClass: 'badge-orange',
      desc: '有历史滥用报告、高并发端口扫描或邮件群发特征，易触发风控限制。'
    };
  } else {
    return {
      level: 'high_risk',
      label: '极度风险',
      color: '#ef4444',
      badgeClass: 'badge-red',
      desc: '高危黑名单 IP，存在多次暴力破解、黑客攻击或木马 C&C 行为，建议拉黑更换。'
    };
  }
}

/**
 * 判断是否为私有/局域网/保留 IP 地址
 */
function isPrivateOrReservedIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  if (trimmed === '127.0.0.1' || trimmed === '::1' || trimmed === 'localhost') return true;
  const parts = trimmed.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return false;
  if (parts[0] === 10) return true; // 10.0.0.0/8
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
  if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
  if (parts[0] === 127) return true; // 127.0.0.0/8
  if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16
  if (parts[0] === 0) return true; // 0.0.0.0/8
  return false;
}

/**
 * 确定性网段离散扰动算法 (-1% ~ +1% 确定性幂等微调)
 * 同一 IP 散列结果 100% 确定幂等，不同 IP/网段产生微离散分值，支持 IPv4 与 IPv6
 */
function getIpSubnetOffset(ip) {
  if (!ip || typeof ip !== 'string' || isPrivateOrReservedIp(ip)) return 0;
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && !parts.some(isNaN)) {
    const seed = parts[0] * 7 + parts[1] * 13 + parts[2] * 19 + parts[3] * 31;
    return (Math.abs(seed) % 3) - 1;
  }
  if (ip.includes(':')) {
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
      hash = ((hash << 5) - hash) + ip.charCodeAt(i);
      hash |= 0;
    }
    return (Math.abs(hash) % 3) - 1;
  }
  return 0;
}

/**
 * 严格双重校验原生 IP (必须非 Anycast 且 RIR 注册国等于实际落地国)
 */
function checkNativeStatus({ isAnycast = false, countryCode = '', registeredCountry = '' }) {
  const c1 = (countryCode || '').trim().toUpperCase();
  const c2 = (registeredCountry || '').trim().toUpperCase();

  if (isAnycast) {
    return {
      isNative: false,
      nativeStatus: '跨国 Anycast 广播 IP',
      nativeReason: 'Anycast 跨国节点广播，非物理机房直连'
    };
  }

  if (c1 && c2 && c1 !== c2) {
    return {
      isNative: false,
      nativeStatus: `非原生广播 IP (${c2} 广播至 ${c1})`,
      nativeReason: `RIR 注册国 (${c2}) 与实际落地探测国 (${c1}) 不一致`
    };
  }

  if (c1 && c2 && c1 === c2) {
    return {
      isNative: true,
      nativeStatus: '物理原生单播 IP (Native)',
      nativeReason: `RIR 注册国与落地物理机房一致 (${c1})，单播路由`
    };
  }

  if (c1 && !c2) {
    return {
      isNative: true,
      nativeStatus: '物理原生单播 IP (Native)',
      nativeReason: `落地物理机房单播路由 (${c1})`
    };
  }

  return {
    isNative: false,
    nativeStatus: '待检测 / 未知属性',
    nativeReason: '未获取到有效物理位置与注册数据'
  };
}

/**
 * 拟真预估共享人数算法 (与 Ping0 官方 5 档 1-10, 10-100, 100-1000, 1000-10000, 10000+ 严格对齐)
 * 对中国大陆 IP (countryCode === 'CN') 抑制具体数字并提示 CGNAT 机制
 */
function estimateSharedUsers({ isResidential, isProxyNode, normalizedAsn, ip, countryCode, isTor = false, country = '' }) {
  if (isPrivateOrReservedIp(ip)) {
    return '本地独享';
  }
  if (!ip) {
    return '未知';
  }

  const cc = String(countryCode || '').trim().toUpperCase();
  const cName = String(country || '').trim().toLowerCase();
  if (cc === 'CN' || cName.includes('中国') || cName === 'china') {
    return '默认不公开 (中国大陆 CGNAT 机制)';
  }

  if (isTor) {
    return '10000+ 人';
  }

  if (isResidential) {
    if (!isProxyNode) {
      return '1-10 人';
    } else {
      return '10-100 人';
    }
  }

  if (!isProxyNode) {
    return '1-10 人';
  }

  if (TIER1_CLOUD_ASNS.has(normalizedAsn)) {
    return '10-100 人';
  }

  if (TIER2_STANDARD_VPS_ASNS.has(normalizedAsn)) {
    return '10-100 人';
  }

  if (TIER3_COMMERCIAL_VPN_ASNS.has(normalizedAsn)) {
    return '100-1000 人';
  }

  if (TIER4_HIGH_RISK_ASNS.has(normalizedAsn)) {
    return '1000-10000 人';
  }

  return '100-1000 人';
}

/**
 * 动态综合风控评估核心计算引擎
 * 公式: S = S_base + Delta_proxy + Delta_asn_tier + Delta_threat + Delta_subnet
 * @param {Object} ipData 包含基础网络拓扑、Ping0同步数据与威胁情报
 */
function calculateRiskScore(ipData = {}) {
  const safeData = ipData || {};
  const {
    ip = '',
    asn = '',
    isp = '',
    org = '',
    countryCode = '',
    registeredCountry = '',
    isAnycast = false,
    privacy = {},
    dnsbl = {}, // { listed: boolean, details: string[] }
    abuseScore = null,
    ping0Type = '', // e.g. 'IDC机房IP' | '家庭宽带IP'
    isProxy = false,
    isProxyNode = false
  } = safeData;

  const asnStr = String(asn || '');
  const normalizedAsn = (asnStr.match(/AS\d+/i) || [asnStr.match(/^\d+$/) ? `AS${asnStr}` : ''])[0].toUpperCase();
  const orgLower = (String(org || '') + ' ' + String(isp || '')).toLowerCase();

  // 处理局域网/保留/回环私有 IP
  if (isPrivateOrReservedIp(ip)) {
    const tier = classifyRiskTier(5);
    return {
      score: 5,
      riskLevel: tier.level,
      riskLabel: tier.label,
      riskColor: tier.color,
      badgeClass: tier.badgeClass,
      riskDesc: '本地局域网或回环地址，无公网路由及外部威胁。',
      isNative: true,
      nativeStatus: '本地私有回环地址 (Local Loopback/LAN)',
      nativeReason: '本地局域网或回环地址，无公网路由',
      ipType: '私有局域网 IP',
      ping0OfficialType: '本地私有',
      estimatedUsers: '本地独享',
      aiCheck: '本地特征模型评估: 本地局域网/私有回环地址，无外部风控风险',
      breakdown: [
        { item: '本地回环/私有局域网基准 (5%)', short: '本地私有', delta: 5, note: '无外部风控' }
      ],
      recommendations: { tiktok: 5, chatgpt: 5, ecommerce: 5, streaming: 5 }
    };
  }

  // 1. 判断是 IDC 机房还是家庭宽带 (优先采纳 Ping0 官方权威认证类型)
  let isDatacenter = false;
  let isResidential = false;

  if (typeof ping0Type === 'string' && ping0Type.includes('家庭宽带')) {
    isResidential = true;
  } else if (typeof ping0Type === 'string' && (ping0Type.includes('IDC') || ping0Type.includes('机房'))) {
    isDatacenter = true;
  } else if (RESIDENTIAL_ISPS.has(normalizedAsn)) {
    isResidential = true;
  } else if (TIER1_CLOUD_ASNS.has(normalizedAsn) || TIER2_STANDARD_VPS_ASNS.has(normalizedAsn) || TIER3_COMMERCIAL_VPN_ASNS.has(normalizedAsn) || TIER4_HIGH_RISK_ASNS.has(normalizedAsn)) {
    isDatacenter = true;
  } else if (privacy && privacy.hosting === true) {
    isDatacenter = true;
  } else {
    const idcKeywords = ['hosting', 'cloud', 'datacenter', 'data center', 'vps', 'dedicated', 'server', 'netlab', 'leaseweb', 'm247', 'packet', 'black mesa', 'fastly', 'ovh'];
    const resKeywords = ['broadband', 'telecom', 'cable', 'residential', 'consumer', 'fiber', 'home', 'dynamic'];
    if (idcKeywords.some(k => orgLower.includes(k))) {
      isDatacenter = true;
    } else if (resKeywords.some(k => orgLower.includes(k))) {
      isResidential = true;
    } else {
      isDatacenter = true;
    }
  }

  // 2. 严格双重校验原生单播属性
  const { isNative, nativeStatus, nativeReason } = checkNativeStatus({
    isAnycast,
    countryCode,
    registeredCountry
  });

  // 3. 基准分 S_base: 原生住宅 5%（与官方范例5%一致），原生单播机房 12%，跨国 Anycast/广播机房 15%
  let baseScore;
  const breakdown = [];

  if (!isNative) {
    baseScore = 15;
    breakdown.push({ item: '非原生/Anycast广播机房基准 (15%)', short: '广播路由', delta: baseScore, note: 'Anycast或跨国广播' });
  } else if (isResidential) {
    baseScore = 5;
    breakdown.push({ item: '家庭住宅宽带出口基准 (5%)', short: '住宅宽带', delta: baseScore, note: '天然纯净' });
  } else {
    baseScore = 12;
    breakdown.push({ item: '商业数据中心原生单播基准 (12%)', short: '原生单播', delta: baseScore, note: '基础IDC单播' });
  }
  let score = baseScore;

  // 4. 代理出口增量 Delta_proxy (常规代理出口 +5%，复合双重标记 proxy+vpn +7%，彻底废除二次重罚)
  const isProxyActive = !!(privacy.proxy || privacy.vpn || isProxy || isProxyNode);
  if (isProxyActive) {
    const isDualProxy = (privacy.proxy && privacy.vpn) || (isProxy && privacy.vpn) || (isProxyNode && privacy.vpn);
    const proxyDelta = isDualProxy ? 7 : 5;
    score += proxyDelta;
    breakdown.push({
      item: isDualProxy ? '双重代理/VPN复合中转 (+7%)' : '公开代理出口中转 (+5%)',
      short: '代理出口',
      delta: proxyDelta,
      note: isDualProxy ? '双重代理标记' : '已被标记代理'
    });
  } else {
    breakdown.push({ item: '非公开代理独立出口 (0%)', short: '独立出口', delta: 0, note: '无代理标记' });
  }

  // 5. ASN 声誉层级 Delta_asn_tier (4 级声誉梯队)
  let asnTierDelta = 0;
  if (TIER1_CLOUD_ASNS.has(normalizedAsn)) {
    asnTierDelta = -2; // Tier 1 顶级云厂商信誉折扣 -2%
    score += asnTierDelta;
    breakdown.push({ item: 'Tier 1 顶级云厂商信誉扣减 (-2%)', short: '顶级云厂商', delta: asnTierDelta, note: '高信誉云厂商' });
  } else if (TIER4_HIGH_RISK_ASNS.has(normalizedAsn)) {
    asnTierDelta = 7; // Tier 4 高危/高滥用主机风险加权 +7%
    score += asnTierDelta;
    breakdown.push({ item: 'Tier 4 高危/高滥用主机加权 (+7%)', short: '高风险主机', delta: asnTierDelta, note: '高滥用主机' });
  } else if (TIER3_COMMERCIAL_VPN_ASNS.has(normalizedAsn)) {
    asnTierDelta = 2; // Tier 3 商业 VPN / 骨干中转 ASN 加权 +2%
    score += asnTierDelta;
    breakdown.push({ item: 'Tier 3 商业VPN/中转网络加权 (+2%)', short: '中转网络', delta: asnTierDelta, note: '多用户中转' });
  } else if (TIER2_STANDARD_VPS_ASNS.has(normalizedAsn)) {
    asnTierDelta = 0; // Tier 2 标准商业 VPS 基准 0%
    breakdown.push({ item: 'Tier 2 标准商业 VPS 基准 (0%)', short: '标准VPS', delta: 0, note: '商业VPS基准' });
  } else if (!isResidential) {
    breakdown.push({ item: '标准商业 IDC 基准 (0%)', short: '标准机房', delta: 0, note: '常规机房ASN' });
  }

  // 6. 实时威胁情报与 DNSBL 黑名单 Delta_threat
  let threatDelta = 0;
  if (privacy.tor) {
    threatDelta += 35;
    score += 35;
    breakdown.push({ item: '命中 Tor 匿名暗网出口 (+35%)', short: 'Tor暗网', delta: 35, note: '极高危匿名' });
  }

  if (dnsbl && dnsbl.listed) {
    let dnsblScore = 0;
    const details = Array.isArray(dnsbl.details) ? dnsbl.details : [];
    if (details.length > 0) {
      details.forEach(d => {
        if (d.includes('UCEPROTECT')) dnsblScore += 2; // 邮件黑名单下调至 +2%
        else if (d.includes('SpamCop')) dnsblScore += 6; // SpamCop 下调至 +6%
        else dnsblScore += 3; // 其他常规黑名单 +3%
      });
    } else {
      dnsblScore = 2;
    }
    dnsblScore = Math.min(15, dnsblScore);
    threatDelta += dnsblScore;
    score += dnsblScore;
    const detailText = details.length > 0 ? details.join(', ') : '实时黑名单标记';
    breakdown.push({ item: `命中实时DNSBL黑名单 (${detailText}) (+${dnsblScore}%)`, short: 'DNSBL黑名单', delta: dnsblScore, note: '邮件/扫描威胁源' });
  }

  const numAbuseScore = typeof abuseScore === 'number' ? abuseScore : (typeof abuseScore === 'string' && !isNaN(Number(abuseScore)) ? Number(abuseScore) : 0);
  if (numAbuseScore > 0) {
    const abuseBonus = Math.min(25, Math.round(numAbuseScore * 0.25));
    if (abuseBonus > 0) {
      threatDelta += abuseBonus;
      score += abuseBonus;
      breakdown.push({ item: `网络安全情报滥用举报 (${numAbuseScore}%) (+${abuseBonus}%)`, short: '安全情报', delta: abuseBonus, note: '历史滥用行为' });
    }
  }

  // 7. 网段离散扰动修正 Delta_subnet (-1% ~ +1%)
  // 纯原生家庭住宅宽带保持稳定 5% 基准，仅对商业机房及代理网段执行离散微调
  const subnetDelta = (isResidential && !isProxyActive) ? 0 : getIpSubnetOffset(ip);
  if (subnetDelta !== 0) {
    score += subnetDelta;
    breakdown.push({ item: `IPv4网段离散微调 (${subnetDelta > 0 ? `+${subnetDelta}%` : `${subnetDelta}%`})`, short: '网段离散', delta: subnetDelta, note: '同网段确定性散列' });
  }

  // Tor 匿名暗网出口保底 75% 极度风险
  if (privacy.tor) {
    score = Math.max(75, score);
  }

  // 限制最终得分在 5% ~ 99% 区间
  const finalScore = Math.min(99, Math.max(5, Math.round(score)));
  const tier = classifyRiskTier(finalScore);

  // 8. 拟真预估共享人数 (严格对齐 Ping0 5档标准，CN 隐藏)
  const estimatedUsers = estimateSharedUsers({
    isResidential,
    isProxyNode: isProxyActive,
    normalizedAsn,
    ip,
    countryCode,
    country: safeData.country,
    isTor: !!privacy.tor
  });

  // 9. Ping0 数据类型展示
  const ping0OfficialType = ping0Type
    || (safeData.ping0Synced ? (isResidential ? '家庭宽带IP' : 'IDC机房IP') : '未同步');

  // 10. IP 类型展示
  const ipTypeDisplay = isResidential
    ? (isProxyActive ? '家庭宽带 IP, 代理出口' : '家庭宽带 IP')
    : (isProxyActive ? 'IDC 机房 IP, 代理出口' : 'IDC 机房 IP');

  // 11. AI/本地分类器综合描述
  let aiCheckDisplay = '';
  if (isProxyActive) {
    if (TIER4_HIGH_RISK_ASNS.has(normalizedAsn)) {
      aiCheckDisplay = '本地特征模型评估: 商业数据中心高危/高滥用主机出口，存在共享多用户使用特征，部分敏感平台易受风控拦截';
    } else if (TIER3_COMMERCIAL_VPN_ASNS.has(normalizedAsn)) {
      aiCheckDisplay = '本地特征模型评估: 商业 VPN / 骨干中转节点，多用户共享出口，主流平台表现优良';
    } else if (TIER1_CLOUD_ASNS.has(normalizedAsn)) {
      aiCheckDisplay = '本地特征模型评估: Tier1 顶级云厂商出口，虽有代理中转但网络声誉优良，主流平台表现稳定';
    } else {
      aiCheckDisplay = '本地特征模型评估: 商业数据中心标准代理节点 (Proxy IP)，轻微风险，建议定期轮换';
    }
  } else if (isResidential) {
    aiCheckDisplay = '本地特征模型评估: 原生家庭住宅宽带出口，未见代理及滥用行为，防封能力极强';
  } else {
    aiCheckDisplay = '本地特征模型评估: 洁净商业数据中心原生出口，未被列入公开代理池，表现优良';
  }

  // 12. 业务场景适用度
  let scenarios;
  if (finalScore <= 15) {
    scenarios = { tiktok: 5, chatgpt: 5, ecommerce: 5, streaming: 5 };
  } else if (finalScore <= 25) {
    scenarios = { tiktok: 5, chatgpt: 5, ecommerce: 4, streaming: 5 };
  } else if (finalScore <= 40) {
    scenarios = { tiktok: 4, chatgpt: 4, ecommerce: 4, streaming: 5 };
  } else if (finalScore <= 60) {
    scenarios = { tiktok: 2, chatgpt: 3, ecommerce: 2, streaming: 4 };
  } else {
    scenarios = { tiktok: 1, chatgpt: 1, ecommerce: 1, streaming: 1 };
  }

  return {
    score: finalScore,
    riskLevel: tier.level,
    riskLabel: tier.label,
    riskColor: tier.color,
    badgeClass: tier.badgeClass,
    riskDesc: tier.desc,
    isNative,
    nativeStatus,
    nativeReason,
    ipType: ipTypeDisplay,
    ping0OfficialType,
    estimatedUsers,
    aiCheck: aiCheckDisplay,
    breakdown,
    recommendations: scenarios
  };
}

module.exports = {
  calculateRiskScore,
  classifyRiskTier,
  getIpSubnetOffset,
  checkNativeStatus,
  estimateSharedUsers,
  TIER1_CLOUD_ASNS,
  TIER2_STANDARD_VPS_ASNS,
  STANDARD_VPS_ASNS,
  TIER3_COMMERCIAL_VPN_ASNS,
  TIER3_TRANSIT_ASNS,
  TIER4_HIGH_RISK_ASNS,
  HIGH_RISK_PROXY_ASNS,
  RESIDENTIAL_ISPS
};
