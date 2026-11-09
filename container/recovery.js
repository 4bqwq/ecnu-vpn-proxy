// Node 12, supplied by aTrust. No Docker socket, browser, or campus credentials.
'use strict';
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const {getClientStatus} = require('./status');

const TUNNEL = '/usr/share/sangfor/aTrust/resources/bin/aTrustXtunnel-64';
const REPORT = '/run/ecnu-recovery.json';
const LOCK = '/run/ecnu-recovery.lock';
const INTERVAL = 15000;
const PROBE_TIMEOUT = 15000;
const FAILURES = 3;
const COOLDOWN = 120000;
const active = new Set();

function processIdentity(pid) {
  const stat = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  return {pid: Number(pid), start: fields[19], zombie: fields[0] === 'Z'};
}
function sameProcess(a, b) { return !!a && !!b && a.pid === b.pid && a.start === b.start; }
function isTunnel(pid) {
  // Some unrelated processes restrict /proc/<pid>/exe even for container
  // root. Read the public task name first, then verify candidate executables.
  if (fs.readFileSync('/proc/' + pid + '/comm', 'utf8').trim() !== 'aTrustXtunnel-6') return false;
  if (fs.readlinkSync('/proc/' + pid + '/exe') !== TUNNEL) return false;
  const args = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').split('\0');
  return !args.includes('-check') && !processIdentity(pid).zombie;
}
function tunnelProcess() {
  const found = [];
  for (const pid of fs.readdirSync('/proc').filter(p => /^\d+$/.test(p))) {
    try { if (isTunnel(pid)) found.push(processIdentity(pid)); }
    catch (error) { if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error; }
  }
  if (found.length > 1) throw new Error('TUNNEL_PROCESS_NOT_UNIQUE');
  return found[0] || null;
}
function endpointKey(endpoint) { return endpoint.host + ':' + endpoint.port; }
function gatewaysFromConfig(config) {
  if (typeof config === 'string') config = JSON.parse(config);
  let apps = config.applist;
  if (typeof apps === 'string') apps = JSON.parse(apps);
  const groups = apps && apps.data && apps.data.config && apps.data.config.nodeGroupConf;
  if (!groups || !Array.isArray(groups.nodeGroupList)) throw new Error('GATEWAY_CONFIG_UNSUPPORTED');
  const endpoints = new Map();
  for (const group of groups.nodeGroupList) {
    for (const entry of group.addressInfo || []) {
      // WAN endpoints include their service port. Never guess one from a LAN IP.
      const match = typeof entry.address === 'string' && /^(\d+\.\d+\.\d+\.\d+):(\d+)$/.exec(entry.address);
      if (!match || net.isIP(match[1]) !== 4 || +match[2] < 1 || +match[2] > 65535) continue;
      const endpoint = {host: match[1], port: +match[2]};
      endpoints.set(endpointKey(endpoint), endpoint);
    }
  }
  if (!endpoints.size) throw new Error('NO_IPV4_GATEWAY_ENDPOINTS');
  return Array.from(endpoints.values());
}
function getGateways() {
  // Use the client's own generated RPC binding. Full session configuration
  // stays in memory; only gateway addresses leave this function.
  const base = '/usr/share/sangfor/aTrust/resources/app/';
  const thrift = require(base + 'node_modules/thrift');
  const service = require(base + 'src/service/thrift/SdpCoreService.js');
  return new Promise((resolve, reject) => {
    let finished = false;
    const connection = thrift.createUDSConnection('/usr/share/sangfor/.aTrust/var/run/aTrustCore-fcd60898-3ef4-423f-acc9-3b28dc0e9e22',
      {transport: thrift.TBufferedTransport, protocol: thrift.TBinaryProtocol, max_attempts: 0});
    const finish = (error, result) => {
      if (finished) return;
      finished = true; clearTimeout(timer); active.delete(cancel); connection.destroy();
      if (error) reject(error); else resolve(result);
    };
    const cancel = () => finish(new Error('STOPPED'));
    active.add(cancel);
    const timer = setTimeout(() => finish(new Error('GATEWAY_CONFIG_TIMEOUT')), 5000);
    connection.on('error', () => finish(new Error('GATEWAY_CONFIG_RPC_FAILED')));
    connection.on('connect', () => {
      const client = new thrift.Multiplexer().createClient('SdpCoreService', service, connection);
      client.GetSdpConfig((error, result) => {
        if (error) { finish(new Error('GATEWAY_CONFIG_RPC_FAILED')); return; }
        try { finish(null, gatewaysFromConfig(result)); } catch (failure) { finish(failure); }
      });
    });
  });
}
function parsePeers(tcp, inodes, gateways) {
  const known = new Map(gateways.map(g => [endpointKey(g), g]));
  const found = new Map();
  for (const line of tcp.trim().split('\n').slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (!inodes.has(fields[9]) || !['01', '02'].includes(fields[3])) continue;
    const remote = fields[2].split(':');
    if (!/^[0-9A-F]{8}$/i.test(remote[0])) continue;
    const host = remote[0].match(/../g).reverse().map(x => parseInt(x, 16)).join('.');
    const key = host + ':' + parseInt(remote[1], 16);
    if (known.has(key)) found.set(key, known.get(key));
  }
  return Array.from(found.values());
}
function currentGateways(process, gateways) {
  const inodes = new Set();
  for (const fd of fs.readdirSync('/proc/' + process.pid + '/fd')) {
    try {
      const match = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync('/proc/' + process.pid + '/fd/' + fd));
      if (match) inodes.add(match[1]);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return parsePeers(fs.readFileSync('/proc/' + process.pid + '/net/tcp', 'utf8'), inodes, gateways);
}
function probe(endpoint, kind, timeout) {
  return new Promise(resolve => {
    let finished = false, banner = '';
    // This credential-free handshake checks reachability, not gateway identity.
    // aTrust retains responsibility for certificate and session authentication.
    const socket = kind === 'tls' ? tls.connect({host: endpoint.host, port: endpoint.port,
      servername: 'vpn.ecnu.edu.cn', rejectUnauthorized: false}) : net.connect(endpoint.port, endpoint.host);
    const finish = reason => {
      if (finished) return;
      finished = true; clearTimeout(timer); active.delete(cancel); socket.destroy();
      resolve({ok: reason === 'ok', reason});
    };
    const cancel = () => finish('stopped');
    active.add(cancel);
    const timer = setTimeout(() => finish('timeout'), timeout || PROBE_TIMEOUT);
    socket.on('error', error => finish(error.code || 'SOCKET_ERROR'));
    socket.on('end', () => finish('closed'));
    if (kind === 'tls') socket.once('secureConnect', () => finish('ok'));
    else if (kind === 'ssh') socket.on('data', chunk => {
      banner += chunk.toString('ascii');
      if (banner.includes('\n')) finish(banner.startsWith('SSH-') ? 'ok' : 'invalid-ssh');
      else if (banner.length > 255) finish('invalid-ssh');
    });
    else socket.once('connect', () => finish('ok'));
  });
}
function loadTargets(file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(value.targets)) throw new Error('INVALID_RECOVERY_TARGETS');
  for (const target of value.targets) {
    if (!target || typeof target.host !== 'string' || !target.host || !Number.isInteger(target.port) ||
        target.port < 1 || target.port > 65535 || typeof target.ssh !== 'boolean') throw new Error('INVALID_RECOVERY_TARGETS');
  }
  return value.targets;
}
async function observe(targets) {
  const status = await getClientStatus();
  if (status.code !== 0 || typeof status.status !== 'string') throw new Error('CLIENT_STATUS_INVALID');
  if (status.status !== 'online') return {state: status.status};
  const process = tunnelProcess();
  if (!process) return {state: 'starting'};
  const gateways = await getGateways();
  const current = currentGateways(process, gateways);
  const [targetResults, gatewayResults] = await Promise.all([
    Promise.all(targets.map(t => probe(t, t.ssh ? 'ssh' : 'tcp'))),
    Promise.all(gateways.map(async g => ({endpoint: g, result: await probe(g, 'tls')})))
  ]);
  return {state: 'online', process, targetsConfigured: targets.length > 0,
    targetOK: targetResults.some(r => r.ok),
    currentOK: gatewayResults.some(r => r.result.ok && current.some(c => endpointKey(c) === endpointKey(r.endpoint))),
    available: gatewayResults.filter(r => r.result.ok).map(r => r.endpoint),
    current, failures: targetResults.filter(r => !r.ok).map(r => r.reason)};
}
function restartDataTunnel(expected) {
  if (!isTunnel(expected.pid) || !sameProcess(expected, processIdentity(expected.pid))) throw new Error('TUNNEL_PROCESS_CHANGED');
  process.kill(expected.pid, 'SIGTERM');
}

class Monitor {
  constructor(options) {
    options = options || {};
    this.observe = options.observe || observe;
    this.status = options.status || getClientStatus;
    this.find = options.find || tunnelProcess;
    this.restart = options.restart || restartDataTunnel;
    this.now = options.now || Date.now;
    this.publish = options.publish || (() => {});
    this.log = options.log || (line => console.log('[vpn-recovery] ' + new Date().toISOString() + ' ' + line));
    this.failures = 0; this.attempts = 0; this.lastAction = null; this.recoveredAt = null;
    this.lastProcess = null; this.hadTargetSuccess = false; this.pending = false;
    this.lastSummary = ''; this.stopped = false;
  }
  report(state, summary) {
    const report = {state, summary, failures: this.failures, attempts: this.attempts,
      checkedAt: this.now(),
      lastActionAt: this.lastAction, lastRecoveredAt: this.recoveredAt};
    this.publish(report);
    if (summary !== this.lastSummary) { this.log(summary); this.lastSummary = summary; }
    return report;
  }
  async tick(targets) {
    const sample = await this.observe(targets);
    if (this.stopped) return;
    if (sample.state !== 'online') {
      this.failures = 0;
      if (sample.state === 'logout' || sample.state === 'login') {
        this.pending = false; this.hadTargetSuccess = false;
        return this.report('waiting-login', '等待校园认证；当前不触发数据通道重建。');
      }
      return this.report('waiting-client', '客户端状态：' + sample.state + '；等待客户端恢复。');
    }
    if (sample.targetOK || (!sample.targetsConfigured && sample.currentOK)) {
      if (sample.targetOK) this.hadTargetSuccess = true;
      this.failures = 0;
      if (this.pending) { this.recoveredAt = this.now(); this.pending = false; }
      return this.report('healthy', (sample.targetOK ? '校内连接可用' : '当前网关握手成功（未配置校内检查目标）') +
        (this.attempts ? '；已自动重建数据通道 ' + this.attempts + ' 次。' : '。'));
    }
    this.failures = Math.min(FAILURES, this.failures + 1);
    if (this.lastAction !== null && this.now() - this.lastAction < COOLDOWN) {
      return this.report('recovering', '已请求重建数据通道，正在检查恢复结果；暂不重复触发。');
    }
    if (this.failures < FAILURES) return this.report('suspect', '连接检查连续失败 ' + this.failures + '/' + FAILURES + ' 次，继续检查。');
    if (!sample.available.length) return this.report('waiting-network', '各数据网关均无法完成握手，继续检测网络；暂不重建数据通道。');
    if (sample.currentOK && !this.hadTargetSuccess) {
      return this.report('target-failed', '网关握手成功，但校内目标均未通过检查；当前数据通道尚无成功记录，保留连接。');
    }
    // Recheck session and PID immediately before acting. A manual logout,
    // native replacement, or PID reuse must never target another process.
    const status = await this.status();
    const process = this.find();
    if (this.stopped || status.code !== 0 || status.status !== 'online' || !sameProcess(sample.process, process)) {
      this.failures = 0;
      return this.report('waiting-client', '客户端状态或数据进程已改变，将重新检查。');
    }
    if (sameProcess(this.lastProcess, process)) return this.report('error', '上次请求的数据进程仍未退出；保留现场，不反复发送退出信号。');
    await this.restart(process);
    this.lastAction = this.now(); this.lastProcess = process; this.attempts++; this.pending = true; this.failures = 0;
    this.hadTargetSuccess = false;
    this.report('recovering', '连接检查连续失败，已请求 aTrust 重建数据通道并重新选路（第 ' + this.attempts + ' 次）。');
  }
  stop() { this.stopped = true; for (const cancel of Array.from(active)) cancel(); if (this.wake) this.wake(); }
  async run(targets) {
    while (!this.stopped) {
      const started = this.now();
      try { await this.tick(targets); }
      catch (error) {
        if (this.stopped) break;
        this.failures = 0;
        // Never log a native RPC response: it can contain session credentials.
        this.report('error', '自动恢复检查失败：' + (error.code || (/^[A-Z0-9_]+$/.test(error.message) ? error.message : 'CHECK_FAILED')) + '；稍后重试。');
      }
      if (this.stopped) break;
      await new Promise(resolve => {
        const timer = setTimeout(() => { this.wake = null; resolve(); }, Math.max(1000, INTERVAL - (this.now() - started)));
        this.wake = () => { clearTimeout(timer); this.wake = null; resolve(); };
      });
    }
  }
}
function readReport() {
  let report;
  try { report = JSON.parse(fs.readFileSync(REPORT, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return {state: 'inactive', summary: '监控尚未启动。'}; throw error; }
  try {
    const current = processIdentity(report.monitor.pid);
    if (current.zombie || !sameProcess(report.monitor, current)) return {state: 'inactive', summary: '监控进程已停止。'};
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ESRCH') return {state: 'inactive', summary: '监控进程已停止。'};
    throw error;
  }
  return report;
}
async function main() {
  const identity = processIdentity(process.pid);
  if (fs.existsSync(LOCK)) {
    const previous = JSON.parse(fs.readFileSync(LOCK, 'utf8'));
    let alive = false;
    try {
      const current = processIdentity(previous.pid);
      alive = !current.zombie && sameProcess(previous, current);
    }
    catch (error) { if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error; }
    if (alive) throw new Error('RECOVERY_ALREADY_RUNNING');
    fs.unlinkSync(LOCK);
  }
  fs.writeFileSync(LOCK, JSON.stringify(identity), {flag: 'wx'});
  const monitor = new Monitor({publish: report => {
    fs.writeFileSync(REPORT + '.tmp', JSON.stringify(Object.assign({monitor: identity}, report)) + '\n');
    fs.renameSync(REPORT + '.tmp', REPORT);
  }});
  const stop = () => monitor.stop();
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  try {
    monitor.report('starting', '监控已启动：每 15 秒检查，连续 3 次失败后判断是否需要重新选路。');
    await monitor.run(loadTargets('/ecnu/recovery-targets.json'));
  } finally {
    monitor.stop(); fs.unlinkSync(LOCK);
    process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
  }
}
module.exports = {Monitor, probe, parsePeers, gatewaysFromConfig, sameProcess, restartDataTunnel, loadTargets, readReport,
  INTERVAL, PROBE_TIMEOUT, FAILURES, COOLDOWN, tunnelProcess};
if (require.main === module) {
  const work = process.argv[2] === 'status' ? Promise.resolve().then(() => console.log(JSON.stringify(readReport()))) : main();
  work.catch(error => { console.error('[vpn-recovery] ' + (error.code || error.message)); process.exitCode = 1; });
}
