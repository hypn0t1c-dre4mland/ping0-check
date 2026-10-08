const net = require('net');
const https = require('https');

function fetchDirect(urlStr) {
  return new Promise((resolve, reject) => {
    https.get(urlStr, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9'
      }
    }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

function parsePing0Risk(html) {
  const turnstile = html.includes('turnstile');
  if (turnstile) return { turnstile: true };
  
  const riskMatch = html.match(/class=["']riskitem riskcurrent["'][^>]*style=["']background:\s*([^"']+)["'][^>]*title=["']([^"']+)["']>.*?<span class=["']value["']>([^<]+)<\/span>.*?<span class=["']lab["']>([^<]+)<\/span>/s);
  
  // Also parse native / broadcast IP
  const nativeMatch = html.match(/原生 IP/);
  const typeMatch = html.match(/(IDC机房 IP|家庭宽带 IP|商业宽带)/);

  if (riskMatch) {
    return {
      turnstile: false,
      color: riskMatch[1].trim(),
      range: riskMatch[2].trim(),
      score: parseInt(riskMatch[3].replace('%', '').trim(), 10),
      label: riskMatch[4].trim(),
      ipType: typeMatch ? typeMatch[1] : 'IDC机房 IP',
      isNative: !!nativeMatch
    };
  }
  return { turnstile: false, notFound: true };
}

async function main() {
  console.log('Testing direct query for 154.12.39.12...');
  const res = await fetchDirect('https://ping0.cc/ip/154.12.39.12');
  console.log('Direct status:', res.status, 'Len:', res.body.length);
  const parsed = parsePing0Risk(res.body);
  console.log('Parsed result:', parsed);
}

main().catch(console.error);
