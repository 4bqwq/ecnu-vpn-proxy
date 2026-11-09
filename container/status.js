// Run with aTrust's bundled Electron Node runtime; never emit account data.
const https = require('https');
const fs = require('fs');
const readline = require('readline');

// Read only this container's current core process and whitelisted update
// events. Native logs can contain credentials; never return their contents.
async function certificateUpdate(startedAt) {
  const since = Date.parse(startedAt);
  if (!Number.isFinite(since)) throw new Error('INVALID_CONTAINER_START_TIME');
  const pids = fs.readdirSync('/proc').filter(name => /^\d+$/.test(name)).filter(pid => {
    try {
      const args = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').split('\0');
      const plugin = args.indexOf('--plugin');
      return plugin >= 0 && args[plugin + 1] === 'plugins/aTrustCore';
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ESRCH') return false;
      throw error;
    }
  });
  if (pids.length !== 1) throw new Error('CORE_PROCESS_NOT_UNIQUE');
  let result = {state: 'unknown', reason: 'NO_UPDATE_EVENT'};
  const log = '/home/sangfor/.aTrust/logs/aTrustAgent_plugins_aTrustCore_h_e';
  for (const path of [log + '.1.log', log + '.log']) {
    if (!fs.existsSync(path)) continue;
    const lines = readline.createInterface({input: fs.createReadStream(path), crlfDelay: Infinity});
    for await (const line of lines) {
      const match = /^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\]\[\s*(\d+):/.exec(line);
      if (!match || match[2] !== pids[0] || Date.parse(match[1].replace(' ', 'T') + 'Z') < since) continue;
      if (line.indexOf('[aTrustCaService]') < 0) continue;
      if (line.indexOf('Obtain a valid credit certificate...') >= 0) {
        result = {state: 'pending', reason: ''};
      } else if (/A valid credit certificate is obtained|certificate has not expired and does not need/.test(line)) {
        result = {state: 'ready', reason: ''};
      } else if (/Failed to obtain the credit certificate|Failed to download a certificate|downloaded certificate is not within the validity period/.test(line)) {
        // Preserve the useful transport reason across subsequent generic
        // failures (including the school's unsupported alternative source).
        let reason = result.state === 'failed' ? result.reason : 'UPDATE_FAILED';
        if (/code:28\b|Timeout was reached/.test(line)) reason = 'DOWNLOAD_TIMEOUT';
        else if (/code:35\b|SSL connect error/.test(line)) reason = 'DOWNLOAD_TLS';
        else if (/code:6\b/.test(line)) reason = 'DOWNLOAD_DNS';
        else if (/code:7\b/.test(line)) reason = 'DOWNLOAD_CONNECT';
        else if (/not within the validity period/.test(line)) reason = 'DOWNLOADED_CERTIFICATE_EXPIRED';
        result = {state: 'failed', reason: reason};
      }
    }
  }
  return result;
}

function getClientStatus() {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({type: 'cs', addr: 'https://vpn.ecnu.edu.cn',
      guid: '', lang: 'zh-CN', token: '', sdpTraceId: '', data: {}});
    let timer;
    const request = https.request({hostname: '127.0.0.1', port: 54631,
      path: '/v1/service/status', method: 'POST', rejectUnauthorized: false,
      headers: {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        Referer: 'https://vpn.ecnu.edu.cn/portal/', 'User-Agent': 'aTrustTray-Linux-Ubuntu-x64 SPCClientType'}
    }, response => {
      let data = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { data += chunk; });
      response.on('error', error => { clearTimeout(timer); reject(error); });
      response.on('aborted', () => { clearTimeout(timer); reject(new Error('ECONNRESET')); });
      response.on('end', () => {
        clearTimeout(timer);
        if (response.statusCode !== 200) { reject(new Error('HTTP_' + response.statusCode)); return; }
        try {
          const result = JSON.parse(data);
          resolve({code: result.code, status: result.data && result.data.status});
        } catch (_) { reject(new Error('INVALID_JSON')); }
      });
    });
    timer = setTimeout(() => request.destroy(new Error('TIMEOUT')), 5000);
    request.on('error', error => { clearTimeout(timer); reject(error); });
    request.end(body);
  });
}

module.exports = {getClientStatus};
if (require.main === module) {
  if (process.argv[2] === 'certificate-update') {
    certificateUpdate(process.argv[3]).then(result => process.stdout.write(JSON.stringify(result))).catch(error => {
      const allowed = ['INVALID_CONTAINER_START_TIME', 'CORE_PROCESS_NOT_UNIQUE'];
      process.stdout.write(JSON.stringify({state: 'unknown', reason: allowed.includes(error.message) ? error.message : 'UPDATE_LOG_READ_FAILED'}));
      process.exitCode = 1;
    });
  } else {
    getClientStatus().then(result => process.stdout.write(JSON.stringify(result))).catch(error => {
      process.stdout.write(JSON.stringify({error: error.code || error.message}));
      process.exitCode = 1;
    });
  }
}
