'use strict';
const assert = require('assert');
const net = require('net');
const {
  Monitor, probe, gatewaysFromConfig, parsePeers, sameProcess, restartDataTunnel, COOLDOWN
} = require('../container/recovery');

let passed = 0;
async function check(name, body) { await body(); passed++; console.log('PASS: ' + name); }
const worker = {pid: 100, start: '200'};
const gateway = {host: '192.0.2.10', port: 441};
function fixture() {
  const f = {time: 1000, restarts: [], reports: [], session: {code: 0, status: 'online'}, process: worker,
    sample: {state: 'online', process: worker, targetsConfigured: true, targetOK: false,
      currentOK: false, available: [gateway]}};
  f.monitor = new Monitor({observe: async () => f.sample, status: async () => f.session,
    find: () => f.process, restart: async p => { f.restarts.push(p); }, now: () => f.time,
    publish: r => f.reports.push(r), log: () => {}});
  f.tick = async () => { await f.monitor.tick([]); f.time += 15000; };
  f.last = () => f.reports[f.reports.length - 1];
  return f;
}
async function repeat(f, n) { for (let i = 0; i < n; i++) await f.tick(); }
async function socketFixture(handler, body) {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket)); handler(socket);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await body({host: '127.0.0.1', port: server.address().port}); }
  finally { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); }
}

async function main() {
  await check('Native gateway configuration supports serialized applist and excludes LAN-only addresses', () => {
    const applist = {data: {config: {nodeGroupConf: {nodeGroupList: [{addressInfo: [
      {address: gateway.host}, {address: gateway.host + ':441'}, {address: gateway.host + ':441'},
      {address: '999.0.0.1:441'}, {address: '192.0.2.11:0'}, {address: '192.0.2.12:70000'}
    ]}]}}}};
    assert.deepStrictEqual(gatewaysFromConfig({applist}), [gateway]);
    assert.deepStrictEqual(gatewaysFromConfig(JSON.stringify({applist: JSON.stringify(applist), sdpc_sid: 'must-not-leak'})), [gateway]);
    assert.throws(() => gatewaysFromConfig({applist: {}}), /GATEWAY_CONFIG_UNSUPPORTED/);
    applist.data.config.nodeGroupConf.nodeGroupList = [];
    assert.throws(() => gatewaysFromConfig({applist}), /NO_IPV4_GATEWAY_ENDPOINTS/);
  });
  await check('Gateway selection uses the data worker socket ownership, peer and connection state', () => {
    const header = 'sl local_address rem_address st tx_queue rx_queue tr tm retr uid timeout inode';
    const row = (inode, state, peer) => '0: 0100007F:1234 ' + peer + ' ' + state + ' 0:0 0:0 0 0 0 ' + inode;
    const tcp = [header, row('42', '01', '0A0200C0:01B9'), row('43', '02', '0B0200C0:01B9'),
      row('44', '01', '0C0200C0:01B9'), row('45', '06', '0D0200C0:01B9'), row('42', '01', '0A0200C0:0050')].join('\n');
    const all = [10, 11, 12, 13].map(n => ({host: '192.0.2.' + n, port: 441}));
    assert.deepStrictEqual(parsePeers(tcp, new Set(['42', '43', '45']), all), all.slice(0, 2));
    assert(!sameProcess(worker, {pid: 100, start: '201'}));
  });
  await check('Three consecutive failures request exactly one data tunnel replacement', async () => {
    const f = fixture(); await repeat(f, 2); assert.equal(f.restarts.length, 0);
    await f.tick(); assert.deepStrictEqual(f.restarts, [worker]);
    assert.equal(f.last().state, 'recovering'); assert.equal(f.last().attempts, 1);
  });
  await check('An intermittent failure or any working campus target prevents recovery', async () => {
    const f = fixture(); await repeat(f, 2);
    f.sample.targetOK = true; await f.tick(); assert.equal(f.last().state, 'healthy');
    f.sample.targetOK = false; await repeat(f, 2); assert.equal(f.restarts.length, 0);
    f.sample.targetOK = true; await repeat(f, 5); assert.equal(f.restarts.length, 0);
  });
  await check('Logout, disconnect and authentication in progress do not terminate the tunnel', async () => {
    for (const state of ['logout', 'offline', 'login', 'disconnect', 'connect', 'networkUnavailable']) {
      const f = fixture(); f.sample.state = state; await repeat(f, 4);
      assert.equal(f.restarts.length, 0); assert.equal(f.monitor.failures, 0);
    }
  });
  await check('No campus configuration still permits recovery from a failed active gateway', async () => {
    const f = fixture(); f.sample.targetsConfigured = false; await repeat(f, 3);
    assert.equal(f.restarts.length, 1);
    f.sample.currentOK = true; await f.tick(); assert.equal(f.last().state, 'healthy');
    assert(f.last().lastRecoveredAt !== null);
  });
  await check('A working gateway without any previously successful campus target does not cause a restart loop', async () => {
    const f = fixture(); f.sample.currentOK = true; await repeat(f, 6);
    assert.equal(f.restarts.length, 0); assert.equal(f.last().state, 'target-failed');
    f.sample.targetOK = true; await f.tick(); f.sample.targetOK = false; await repeat(f, 3);
    assert.equal(f.restarts.length, 1);
  });
  await check('Unavailable network waits; a returning alternative gateway enables recovery', async () => {
    const f = fixture(); f.sample.available = []; await repeat(f, 5);
    assert.equal(f.restarts.length, 0); assert.equal(f.last().state, 'waiting-network');
    f.sample.available = [gateway]; await f.tick(); assert.equal(f.restarts.length, 1);
  });
  await check('A reachable gateway with persistently broken campus services is not restarted endlessly', async () => {
    const f = fixture(); f.sample.currentOK = true; f.sample.targetOK = true; await f.tick();
    f.sample.targetOK = false; await repeat(f, 3); assert.equal(f.restarts.length, 1);
    f.process = f.sample.process = {pid: 101, start: '300'};
    f.time += COOLDOWN; await repeat(f, 5);
    assert.equal(f.restarts.length, 1); assert.equal(f.last().state, 'target-failed');
  });
  await check('Cooldown and process identity prevent repeated termination of the same worker', async () => {
    const f = fixture(); await repeat(f, 3); await repeat(f, 3); assert.equal(f.restarts.length, 1);
    f.time += COOLDOWN; await f.tick(); assert.equal(f.restarts.length, 1); assert.equal(f.last().state, 'error');
    f.process = f.sample.process = {pid: 101, start: '300'}; await f.tick(); assert.equal(f.restarts.length, 2);
  });
  await check('A session change or PID reuse immediately before the action cancels it', async () => {
    const f = fixture(); await repeat(f, 2); f.session.status = 'logout'; await f.tick(); assert.equal(f.restarts.length, 0);
    f.session.status = 'online'; f.process = {pid: worker.pid, start: '201'}; await repeat(f, 3);
    assert.equal(f.restarts.length, 0);
  });
  await check('An unsuccessful termination request is not reported as a successful attempt', async () => {
    const f = fixture(); f.monitor.restart = async () => { throw new Error('ESRCH'); };
    await repeat(f, 2); await assert.rejects(f.tick(), /ESRCH/);
    assert.equal(f.monitor.attempts, 0); assert.equal(f.monitor.lastAction, null);
  });
  await check('The recovery action refuses to signal an unrelated live process', () => {
    assert.throws(() => restartDataTunnel({pid: process.pid, start: '0'}), /TUNNEL_PROCESS_CHANGED/);
  });
  await check('TCP success does not count as SSH success until the server sends its banner', async () => {
    await socketFixture(() => {}, async endpoint => {
      assert((await probe(endpoint, 'tcp', 100)).ok);
      assert.deepStrictEqual(await probe(endpoint, 'ssh', 100), {ok: false, reason: 'timeout'});
      assert.deepStrictEqual(await probe(endpoint, 'tls', 100), {ok: false, reason: 'timeout'});
    });
    await socketFixture(s => s.end('SSH-2.0-fixture\r\n'), async endpoint => assert((await probe(endpoint, 'ssh', 500)).ok));
    await socketFixture(s => s.end(), async endpoint => assert.deepStrictEqual(await probe(endpoint, 'ssh', 500), {ok: false, reason: 'closed'}));
    await socketFixture(s => s.end('not-ssh\n'), async endpoint => assert.equal((await probe(endpoint, 'ssh', 500)).reason, 'invalid-ssh'));
  });
  await check('Stopping the monitor cancels in-flight probes without requesting recovery', async () => {
    await socketFixture(() => {}, async endpoint => {
      const pending = probe(endpoint, 'ssh', 10000);
      const f = fixture(); f.monitor.stop();
      assert.equal((await pending).reason, 'stopped');
      await f.tick(); assert.equal(f.restarts.length, 0);
    });
  });
  console.log('All ' + passed + ' checks passed.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
