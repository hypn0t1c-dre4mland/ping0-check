/**
 * Clash Verge 网页与常用服务测速模块 (Speed & Latency Tester)
 * 并发测试 Google / YouTube / GitHub / Apple / Cloudflare / OpenAI / Bilibili 等主流网站延迟
 */

const net = require('net');
const https = require('https');
const http = require('http');

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 7897;

const TEST_TARGETS = [
  { id: 'google', name: 'Google', icon: '🔍', url: 'https://www.google.com/generate_204' },
  { id: 'youtube', name: 'YouTube', icon: '📺', url: 'https://www.youtube.com' },
  { id: 'github', name: 'GitHub', icon: '🐙', url: 'https://github.com' },
  { id: 'apple', name: 'Apple', icon: '🍏', url: 'https://www.apple.com' },
  { id: 'cloudflare', name: 'Cloudflare', icon: '☁️', url: 'https://www.cloudflare.com' },
  { id: 'openai', name: 'OpenAI', icon: '🤖', url: 'https://api.openai.com/v1/models' },
  { id: 'bilibili', name: 'Bilibili', icon: '📺', url: 'https://www.bilibili.com' }
];

/**
 * 单个 URL 延迟测试 (通过 Clash 代理)
 */
function testSingleUrl(target, timeout = 4000) {
  return new Promise((resolve) => {
    const url = new URL(target.url);
    const isHttps = url.protocol === 'https:';
    const port = url.port || (isHttps ? 443 : 80);
    const start = Date.now();

    const proxyReq = net.connect(PROXY_PORT, PROXY_HOST, () => {
      proxyReq.write(`CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\n\r\n`);
      proxyReq.once('data', (d) => {
        if (!d.toString().includes('200')) {
          proxyReq.destroy();
          return resolve({ ...target, latency: null, status: 'Proxy Connect Fail', grade: '❌ 失败', badgeType: 'danger' });
        }

        const transport = isHttps ? https : http;
        const agent = new transport.Agent({ socket: proxyReq, rejectUnauthorized: false });

        const req = transport.request({
          hostname: url.hostname,
          port,
          path: url.pathname || '/',
          method: 'HEAD',
          agent,
          timeout,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        }, (res) => {
          const latency = Date.now() - start;
          res.destroy();

          let grade = '良好';
          let icon = '🟢';
          let badgeType = 'success';

          if (latency < 300) {
            grade = '极速';
            icon = '🟢';
            badgeType = 'success';
          } else if (latency < 800) {
            grade = '良好';
            icon = '🟢';
            badgeType = 'success';
          } else if (latency < 1500) {
            grade = '较慢';
            icon = '🟡';
            badgeType = 'neutral';
          } else {
            grade = '较差';
            icon = '🟠';
            badgeType = 'warning';
          }

          const statusText = http.STATUS_CODES[res.statusCode] || (res.statusCode === 204 ? 'No Content' : 'OK');

          resolve({
            ...target,
            latency,
            latencyText: `${latency}ms`,
            status: `${res.statusCode} ${statusText}`,
            grade: `${icon} ${grade}`,
            badgeType
          });
        });

        req.on('timeout', () => {
          req.destroy();
          resolve({ ...target, latency: null, latencyText: '超时', status: 'Timeout', grade: '❌ 超时', badgeType: 'danger' });
        });

        req.on('error', (e) => {
          resolve({ ...target, latency: null, latencyText: '异常', status: e.message.slice(0, 15), grade: '⚠️ 异常', badgeType: 'danger' });
        });

        req.end();
      });
    });

    proxyReq.setTimeout(timeout, () => {
      proxyReq.destroy();
      resolve({ ...target, latency: null, latencyText: '超时', status: 'Proxy Timeout', grade: '❌ 超时', badgeType: 'danger' });
    });

    proxyReq.on('error', (e) => {
      resolve({ ...target, latency: null, latencyText: '异常', status: e.message.slice(0, 15), grade: '⚠️ 异常', badgeType: 'danger' });
    });
  });
}

/**
 * 并发测试所有目标网站
 */
async function testAllWebsites(timeout = 4000) {
  return Promise.all(TEST_TARGETS.map(t => testSingleUrl(t, timeout)));
}

module.exports = {
  testAllWebsites,
  TEST_TARGETS
};
