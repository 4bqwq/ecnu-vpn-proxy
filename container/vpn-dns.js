// Run with aTrust's bundled Node runtime (Node 12). No host DNS lookup is
// needed to reach the DoH servers; only this VPN hostname is managed here.
'use strict';
const fs = require('fs');
const path = require('path');
const net = require('net');
const https = require('https');
const childProcess = require('child_process');

const HOSTNAME = 'vpn.ecnu.edu.cn';
const PROVIDERS = [
  {name: 'AliDNS', hostname: 'dns.alidns.com', ip: '223.5.5.5'},
  {name: 'DNSPod', hostname: 'doh.pub', ip: '1.12.12.12'}
];
const BEGIN = '# BEGIN ecnu-proxy VPN DNS';
const END = '# END ecnu-proxy VPN DNS';
const activeRequests = new Set();

function publicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const a = ip.split('.').map(Number);
  return !(a[0] === 0 || a[0] === 10 || a[0] === 127 || a[0] >= 224 ||
    (a[0] === 100 && a[1] >= 64 && a[1] <= 127) ||
    (a[0] === 169 && a[1] === 254) ||
    (a[0] === 172 && a[1] >= 16 && a[1] <= 31) ||
    (a[0] === 192 && (a[1] === 168 || (a[1] === 0 && (a[2] === 0 || a[2] === 2)))) ||
    (a[0] === 198 && (a[1] === 18 || a[1] === 19 || (a[1] === 51 && a[2] === 100))) ||
    (a[0] === 203 && a[1] === 0 && a[2] === 113));
}

function queryMessage(hostname) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header].concat(hostname.split('.').map(label =>
    Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')])
  ), [Buffer.from([0, 0, 1, 0, 1])]));
}

function parseAnswer(buffer, hostname, age) {
  const need = (offset, count) => {
    if (offset < 0 || offset + count > buffer.length) throw new Error('DNS 响应不完整');
  };
  const nameAt = start => {
    const labels = [], seen = new Set();
    let offset = start, next = null, length = 0;
    while (true) {
      need(offset, 1);
      if (seen.has(offset)) throw new Error('DNS 名称压缩指针循环');
      seen.add(offset);
      const size = buffer[offset++];
      if ((size & 0xc0) === 0xc0) {
        need(offset, 1);
        if (next === null) next = offset + 1;
        offset = ((size & 0x3f) << 8) | buffer[offset];
        continue;
      }
      if (size & 0xc0) throw new Error('DNS 名称格式错误');
      if (size === 0) return {name: labels.join('.').toLowerCase(), next: next === null ? offset : next};
      need(offset, size);
      length += size + 1;
      if (length > 254) throw new Error('DNS 名称过长');
      labels.push(buffer.toString('ascii', offset, offset + size));
      offset += size;
    }
  };
  need(0, 12);
  const flags = buffer.readUInt16BE(2);
  if (buffer.readUInt16BE(0) !== 0 || !(flags & 0x8000) || (flags & 0x7a00)) {
    throw new Error('DNS 响应标识、操作类型或截断标记错误');
  }
  if (flags & 15) throw new Error('DNS 返回错误码 ' + (flags & 15));
  if (buffer.readUInt16BE(4) !== 1) throw new Error('DNS 查询数量不匹配');
  const question = nameAt(12);
  need(question.next, 4);
  if (question.name !== hostname || buffer.readUInt16BE(question.next) !== 1 ||
      buffer.readUInt16BE(question.next + 2) !== 1) throw new Error('DNS 响应的域名或记录类型不匹配');
  let offset = question.next + 4;
  const records = [];
  for (let i = 0; i < buffer.readUInt16BE(6); i++) {
    const owner = nameAt(offset);
    offset = owner.next;
    need(offset, 10);
    const type = buffer.readUInt16BE(offset), klass = buffer.readUInt16BE(offset + 2);
    // RFC 2181: TTL values with the high bit set are treated as zero.
    const rawTTL = buffer.readUInt32BE(offset + 4);
    const ttl = rawTTL > 0x7fffffff ? 0 : rawTTL;
    const size = buffer.readUInt16BE(offset + 8);
    offset += 10;
    need(offset, size);
    if (klass === 1 && type === 1) {
      if (size !== 4) throw new Error('DNS IPv4 记录长度错误');
      records.push({name: owner.name, type, ttl, ip: Array.from(buffer.slice(offset, offset + 4)).join('.')});
    } else if (klass === 1 && type === 5) {
      const alias = nameAt(offset);
      if (alias.next !== offset + size) throw new Error('DNS CNAME 记录长度错误');
      records.push({name: owner.name, type, ttl, alias: alias.name});
    }
    offset += size;
  }
  let current = hostname, ttl = Infinity;
  const visited = new Set();
  while (true) {
    if (visited.has(current)) throw new Error('DNS CNAME 循环');
    visited.add(current);
    const matched = records.filter(record => record.name === current);
    const aliases = matched.filter(record => record.type === 5);
    const addresses = matched.filter(record => record.type === 1);
    if (aliases.length) {
      if (addresses.length || new Set(aliases.map(record => record.alias)).size !== 1) throw new Error('DNS CNAME 记录冲突');
      ttl = Math.min(ttl, ...aliases.map(record => record.ttl));
      current = aliases[0].alias;
      continue;
    }
    if (!addresses.length) throw new Error('DNS 没有返回目标域名的 IPv4 地址');
    if (addresses.some(record => !publicIPv4(record.ip))) throw new Error('DNS 返回了 FakeIP 或非公网 IPv4 地址');
    ttl = Math.max(0, Math.min(ttl, ...addresses.map(record => record.ttl)) - age);
    return {addresses: Array.from(new Set(addresses.map(record => record.ip))), ttl};
  }
}

function requestHTTPS(hostname, ip, requestPath, body) {
  return new Promise((resolve, reject) => {
    let settled = false, timer;
    const options = {
      hostname, servername: hostname, port: 443, path: requestPath,
      method: body ? 'POST' : 'GET', agent: false, rejectUnauthorized: true,
      lookup: (_name, _options, callback) => callback(null, ip, 4),
      headers: body ? {'Content-Type': 'application/dns-message', Accept: 'application/dns-message', 'Content-Length': body.length} : {}
    };
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      activeRequests.delete(request);
      if (error) { request.destroy(); reject(error); } else resolve(value);
    };
    const request = https.request(options, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > 65535) { finish(new Error('HTTPS 响应超过 65535 字节')); return; }
        chunks.push(chunk);
      });
      response.on('error', error => finish(error));
      response.on('aborted', () => finish(new Error('HTTPS 响应中途断开')));
      response.on('end', () => finish(null, {status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks)}));
    });
    activeRequests.add(request);
    request.on('error', error => finish(error));
    // Bound one attempt so another provider can be tried. The updater itself
    // has no total retry deadline and never stops a VPN on a network timeout.
    timer = setTimeout(() => finish(new Error('HTTPS 请求在 15 秒内未完成')), 15000);
    request.end(body);
  });
}

async function queryProvider(provider) {
  const response = await requestHTTPS(provider.hostname, provider.ip, '/dns-query', queryMessage(HOSTNAME));
  if (response.status !== 200) throw new Error('DoH HTTP ' + response.status);
  if ((response.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/dns-message') {
    throw new Error('DoH 响应类型不是 application/dns-message');
  }
  const age = response.headers.age === undefined ? 0 : Number(response.headers.age);
  if (!Number.isFinite(age) || age < 0) throw new Error('DoH Age 响应头无效');
  return parseAnswer(response.body, HOSTNAME, age);
}

async function checkCachedAddress(ip) {
  const response = await requestHTTPS(HOSTNAME, ip, '/public/manifest');
  if (response.status !== 200) throw new Error('学校接口 HTTP ' + response.status);
}

function hostsWithAddresses(original, addresses) {
  const lines = original.split('\n');
  const starts = [], ends = [];
  lines.forEach((line, index) => { if (line.trim() === BEGIN) starts.push(index); if (line.trim() === END) ends.push(index); });
  if (starts.length !== ends.length || starts.length > 1 || (starts.length && starts[0] >= ends[0])) {
    throw new Error('/etc/hosts 中 VPN DNS 标记不完整，未改写文件');
  }
  if (starts.length) lines.splice(starts[0], ends[0] - starts[0] + 1);
  if (lines.some(line => line.split('#')[0].trim().split(/\s+/).slice(1).includes(HOSTNAME))) {
    throw new Error('/etc/hosts 已有其他程序管理的 ' + HOSTNAME + ' 记录，未覆盖');
  }
  let text = lines.join('\n');
  if (text && !text.endsWith('\n')) text += '\n';
  return text + BEGIN + '\n' + addresses.map(ip => ip + ' ' + HOSTNAME).join('\n') + '\n' + END + '\n';
}

function writeHosts(file, addresses) {
  const previous = fs.readFileSync(file, 'utf8');
  const text = hostsWithAddresses(previous, addresses);
  if (text === previous) return;
  // Docker bind-mounts /etc/hosts, so renaming a replacement over it fails.
  // Keep its inode and permissions, and write before truncating the old tail.
  const fd = fs.openSync(file, 'r+');
  try { fs.writeSync(fd, text, 0, 'utf8'); fs.ftruncateSync(fd, Buffer.byteLength(text)); }
  finally { fs.closeSync(fd); }
}

function refreshDelay(ttl) { return Math.max(1000, Math.min(ttl * 800, 0x7fffffff)); }
function retryDelay(failures) { return Math.min(30000, 5000 * Math.pow(2, Math.min(failures - 1, 3))); }

class ResolutionFailure extends Error {}

class Updater {
  constructor(options) {
    options = options || {};
    this.hosts = options.hosts || '/etc/hosts';
    this.cache = options.cache || '/root/.ecnu-proxy/vpn-dns-cache.json';
    this.ready = options.ready || '/run/ecnu-vpn-dns.ready';
    this.query = options.query || queryProvider;
    this.checkCached = options.checkCached || checkCachedAddress;
    this.now = options.now || Date.now;
    this.log = options.log || (message => console.log('[vpn-dns] ' + new Date().toISOString() + ' ' + message));
    this.lastGood = null;
    this.stopped = false;
    this.wake = null;
  }
  apply(record) {
    if (this.stopped) return;
    writeHosts(this.hosts, record.addresses);
    this.lastGood = record;
    fs.writeFileSync(this.ready, JSON.stringify({pid: process.pid, hostname: HOSTNAME}));
  }
  async restore() {
    let text;
    try { text = fs.readFileSync(this.cache, 'utf8'); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    let record;
    try {
      record = JSON.parse(text);
      if (record.version !== 1 || record.hostname !== HOSTNAME || !Array.isArray(record.addresses) ||
          !record.addresses.length || record.addresses.some(ip => !publicIPv4(ip)) ||
          !Number.isFinite(record.fetchedAt) || !Number.isFinite(record.expiresAt) ||
          record.fetchedAt > this.now() || record.expiresAt < record.fetchedAt) throw new Error('缓存字段或地址无效');
    } catch (error) { this.log('忽略无效 DNS 缓存：' + error.message); return; }
    if (record.expiresAt <= this.now()) {
      const verified = [];
      for (const ip of record.addresses) {
        if (this.stopped) return;
        try { await this.checkCached(ip); verified.push(ip); }
        catch (error) { this.log('过期缓存地址 ' + ip + ' 校验失败：' + error.message); }
      }
      if (!verified.length) return;
      record.addresses = verified;
      this.log('DNS 缓存已过期；学校 HTTPS 校验通过，暂时使用缓存并立即重新解析。');
    } else this.log('恢复尚未过期的 DNS 缓存，并立即检查更新。');
    this.apply(record);
  }
  async refresh() {
    let answer, source;
    for (const provider of PROVIDERS) {
      if (this.stopped) return null;
      try { answer = await this.query(provider); source = provider.name; break; }
      catch (error) {
        if (this.stopped) return null;
        this.log(provider.name + ' 解析失败：' + error.message + (provider === PROVIDERS[0] ? '；尝试备用 ' + PROVIDERS[1].name + '。' : '。'));
      }
    }
    if (!answer) throw new ResolutionFailure('所有 DoH 服务均未获得可用结果');
    if (this.stopped) return null;
    const fetchedAt = this.now();
    const record = {version: 1, hostname: HOSTNAME, addresses: answer.addresses, fetchedAt, expiresAt: fetchedAt + answer.ttl * 1000};
    // Failure to save or install an answer is a local error, not a DNS outage.
    fs.mkdirSync(path.dirname(this.cache), {recursive: true});
    fs.writeFileSync(this.cache + '.tmp', JSON.stringify(record) + '\n', {mode: 0o600});
    fs.renameSync(this.cache + '.tmp', this.cache);
    this.apply(record);
    const delay = refreshDelay(answer.ttl);
    this.log(source + ' 已更新 ' + HOSTNAME + ' → ' + answer.addresses.join(', ') +
      '；TTL ' + answer.ttl + ' 秒，' + Math.ceil(delay / 1000) + ' 秒后刷新。');
    return delay;
  }
  async run() {
    await this.restore();
    let failures = 0;
    while (!this.stopped) {
      let delay;
      try { delay = await this.refresh(); failures = 0; }
      catch (error) {
        if (!(error instanceof ResolutionFailure)) throw error;
        delay = retryDelay(++failures);
        const cached = this.lastGood ? (this.lastGood.expiresAt <= this.now() ? '保留已过期的最近成功记录' : '保留最近成功记录') : '尚无可用记录，等待首次解析';
        this.log(error.message + '；' + cached + '；' + delay / 1000 + ' 秒后重试。');
      }
      if (this.stopped) break;
      await new Promise(resolve => {
        const timer = setTimeout(() => { this.wake = null; resolve(); }, delay);
        this.wake = () => { clearTimeout(timer); this.wake = null; resolve(); };
      });
    }
  }
  stop() {
    this.stopped = true;
    if (this.wake) this.wake();
    for (const request of activeRequests) request.destroy(new Error('DNS 更新程序正在停止'));
  }
}

function installRoutes(execute) {
  const installed = [];
  const cleanup = () => {
    for (const args of installed.splice(0)) execute('ip', ['-4', 'rule', 'del'].concat(args));
  };
  try {
    for (const provider of PROVIDERS) {
      // Before aTrust starts, an empty table 2 falls through to the original
      // default route. Upstream then saves those Docker routes in table 2.
      const args = ['to', provider.ip + '/32', 'ipproto', 'tcp', 'dport', '443', 'table', '2'];
      execute('ip', ['-4', 'rule', 'add'].concat(args));
      installed.push(args);
    }
  } catch (error) { cleanup(); throw error; }
  return cleanup;
}

async function main() {
  const updater = new Updater();
  try { fs.unlinkSync(updater.ready); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const cleanupRoutes = installRoutes((file, args) => childProcess.execFileSync(file, args, {stdio: ['ignore', 'pipe', 'pipe']}));
  const stop = () => updater.stop();
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  try { await updater.run(); }
  finally {
    updater.stop();
    cleanupRoutes();
    try { fs.unlinkSync(updater.ready); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    process.removeListener('SIGTERM', stop);
    process.removeListener('SIGINT', stop);
  }
}

module.exports = {HOSTNAME, PROVIDERS, BEGIN, END, publicIPv4, queryMessage, parseAnswer,
  requestHTTPS, queryProvider, hostsWithAddresses, writeHosts, refreshDelay, retryDelay, Updater, ResolutionFailure, installRoutes};
if (require.main === module) main().catch(error => {
  console.error('[vpn-dns] 无法继续运行：' + error.message);
  process.exitCode = 1;
});
