// Run with aTrust's bundled Electron Node runtime; never emit account data.
const https = require('https');
const body = JSON.stringify({
  type: 'cs', addr: 'https://vpn.ecnu.edu.cn',
  guid: '', lang: 'zh-CN', token: '', sdpTraceId: '', data: {}
});
const request = https.request({
  hostname: '127.0.0.1', port: 54631, path: '/v1/service/status',
  method: 'POST', rejectUnauthorized: false, // Only the container loopback API.
  headers: {
    'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
    Referer: 'https://vpn.ecnu.edu.cn/portal/',
    'User-Agent': 'aTrustTray-Linux-Ubuntu-x64 SPCClientType'
  }
}, response => {
  let data = '';
  response.setEncoding('utf8');
  response.on('data', chunk => { data += chunk; });
  response.on('end', () => {
    if (response.statusCode !== 200) {
      process.stdout.write(JSON.stringify({error: 'HTTP_' + response.statusCode}));
      process.exitCode = 1;
      return;
    }
    try {
      const result = JSON.parse(data);
      process.stdout.write(JSON.stringify({code: result.code, status: result.data && result.data.status}));
    } catch (_) {
      process.stdout.write(JSON.stringify({error: 'INVALID_JSON'}));
      process.exitCode = 1;
    }
  });
});
request.setTimeout(5000, () => request.destroy(new Error('TIMEOUT')));
request.on('error', error => {
  process.stdout.write(JSON.stringify({error: error.code || error.message}));
  process.exitCode = 1;
});
request.end(body);
