'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const https = require('https');
const EventEmitter = require('events');
const dns = require('../container/vpn-dns');
const cases = [];
const test = (label, body) => cases.push({label, body});
const root = path.resolve(process.argv[2] || path.join(__dirname, '../.runtime/tests-vpn-dns'));
fs.mkdirSync(root, {recursive: true});

function name(value) {
  return Buffer.concat(value.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)] )).concat([Buffer.from([0])]));
}
function record(owner, type, ttl, data) {
  const head = Buffer.alloc(10);
  head.writeUInt16BE(type, 0); head.writeUInt16BE(1, 2);
  head.writeUInt32BE(ttl, 4); head.writeUInt16BE(data.length, 8);
  return Buffer.concat([name(owner), head, data]);
}
function answer(records) {
  const query = dns.queryMessage(dns.HOSTNAME);
  query.writeUInt16BE(0x8180, 2); query.writeUInt16BE(records.length, 6);
  return Buffer.concat([query].concat(records));
}
const a = (ip, ttl, owner) => record(owner || dns.HOSTNAME, 1, ttl === undefined ? 60 : ttl, Buffer.from(ip.split('.').map(Number)));
const cached = (addresses, fetchedAt, expiresAt) => ({version: 1, hostname: dns.HOSTNAME, addresses, fetchedAt, expiresAt});
function remove(directory) {
  for (const entry of fs.readdirSync(directory)) {
    const file = path.join(directory, entry);
    if (fs.lstatSync(file).isDirectory()) remove(file); else fs.unlinkSync(file);
  }
  fs.rmdirSync(directory);
}
async function fixture(body) {
  const dir = fs.mkdtempSync(path.join(root, 'case-'));
  const files = {hosts: path.join(dir, 'hosts'), cache: path.join(dir, 'cache', 'dns.json'), ready: path.join(dir, 'ready')};
  fs.writeFileSync(files.hosts, '127.0.0.1 localhost\n10.1.2.3 internal.example # retained\n');
  const logs = [];
  const make = options => new dns.Updater(Object.assign({}, files, {log: message => logs.push(message)}, options));
  const save = value => { fs.mkdirSync(path.dirname(files.cache), {recursive: true}); fs.writeFileSync(files.cache, JSON.stringify(value)); };
  try { await body({files, logs, make, save}); } finally { remove(dir); }
}

test('CNAME ownership, multiple A records and minimum TTL/Age are honored', () => {
  const wire = answer([a('9.9.9.9', 1, 'unrelated.example'), a('1.1.1.1', 600, 'gateway.example'),
    record(dns.HOSTNAME, 5, 30, name('gateway.example')), a('8.8.8.8', 90, 'gateway.example')]);
  assert.deepStrictEqual(dns.parseAnswer(wire, dns.HOSTNAME, 10), {addresses: ['1.1.1.1', '8.8.8.8'], ttl: 20});
  assert.strictEqual(dns.parseAnswer(wire, dns.HOSTNAME, 40).ttl, 0);
});
test('FakeIP, private, local, documentation and multicast answers are rejected', () => {
  for (const ip of ['198.18.0.40', '198.19.1.1', '127.0.0.1', '10.0.0.1', '172.18.0.1', '192.168.1.1',
    '100.64.0.1', '169.254.1.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '0.0.0.0']) {
    assert.throws(() => dns.parseAnswer(answer([a(ip)]), dns.HOSTNAME, 0), /FakeIP/);
  }
  assert.strictEqual(dns.publicIPv4('::1'), false);
  assert.strictEqual(dns.publicIPv4('222.66.117.113'), true);
});
test('Truncated, mismatched, negative and looping DNS replies cannot replace hosts', () => {
  const wire = answer([a('1.1.1.1')]);
  assert.throws(() => dns.parseAnswer(wire.slice(0, -1), dns.HOSTNAME, 0), /不完整/);
  assert.throws(() => dns.parseAnswer(wire, 'other.example', 0), /不匹配/);
  const bad = Buffer.from(wire); bad.writeUInt16BE(0x8182, 2);
  assert.throws(() => dns.parseAnswer(bad, dns.HOSTNAME, 0), /错误码 2/);
  bad.writeUInt16BE(0x8380, 2);
  assert.throws(() => dns.parseAnswer(bad, dns.HOSTNAME, 0), /截断/);
  assert.throws(() => dns.parseAnswer(answer([record(dns.HOSTNAME, 5, 30, name(dns.HOSTNAME))]), dns.HOSTNAME, 0), /循环/);
  const pointer = Buffer.from(wire); pointer[12] = 0xc0; pointer[13] = 12;
  assert.throws(() => dns.parseAnswer(pointer, dns.HOSTNAME, 0), /循环/);
  assert.throws(() => dns.parseAnswer(answer([a('1.1.1.1', 60, 'other.example')]), dns.HOSTNAME, 0), /没有返回/);
});
test('Hosts updates are idempotent and preserve unrelated entries', () => {
  const original = '127.0.0.1 localhost\n10.1.2.3 private.example # custom\n';
  const once = dns.hostsWithAddresses(original, ['1.1.1.1']);
  assert.strictEqual(dns.hostsWithAddresses(once, ['1.1.1.1']), once);
  const changed = dns.hostsWithAddresses(once, ['8.8.8.8']);
  assert(changed.startsWith(original)); assert(!changed.includes('1.1.1.1'));
  assert.throws(() => dns.hostsWithAddresses(original + dns.BEGIN + '\n', ['8.8.8.8']), /标记不完整/);
  assert.throws(() => dns.hostsWithAddresses(original + '1.1.1.1 ' + dns.HOSTNAME + '\n', ['8.8.8.8']), /其他程序/);
});
test('Changed DNS answers replace hosts and survive updater recreation', () => fixture(async ({files, make}) => {
  let now = 100000, ip = '1.1.1.1';
  const updater = make({now: () => now, query: async () => ({addresses: [ip], ttl: 60})});
  assert.strictEqual(await updater.refresh(), 48000);
  now += 60000; ip = '8.8.8.8';
  await updater.refresh();
  assert(fs.readFileSync(files.hosts, 'utf8').includes(ip));
  assert(!fs.readFileSync(files.hosts, 'utf8').includes('1.1.1.1'));
  const saved = JSON.parse(fs.readFileSync(files.cache));
  assert.strictEqual(saved.expiresAt, now + 60000);
  fs.writeFileSync(files.hosts, '127.0.0.1 localhost\n');
  const next = make({now: () => now + 1000, checkCached: async () => { throw new Error('Fresh cache should not need HTTPS validation'); }});
  await next.restore();
  assert(fs.readFileSync(files.hosts, 'utf8').includes(ip)); assert(fs.existsSync(files.ready));
}));
test('Primary failure tries the secondary and makes the reason visible', () => fixture(async ({make, logs}) => {
  const calls = [];
  const updater = make({query: async provider => {
    calls.push(provider.name);
    if (provider.name === 'AliDNS') throw new Error('TLS fixture failure');
    return {addresses: ['1.1.1.1'], ttl: 60};
  }});
  await updater.refresh();
  assert.deepStrictEqual(calls, ['AliDNS', 'DNSPod']);
  assert(logs.some(line => /TLS fixture failure.*备用 DNSPod/.test(line)));
}));
test('A total DNS outage preserves last good hosts and cache', () => fixture(async ({make, files}) => {
  const updater = make({query: async () => ({addresses: ['1.1.1.1'], ttl: 60})});
  await updater.refresh();
  const hosts = fs.readFileSync(files.hosts, 'utf8'), cache = fs.readFileSync(files.cache, 'utf8');
  updater.query = async () => { throw new Error('Unavailable'); };
  await assert.rejects(updater.refresh(), dns.ResolutionFailure);
  assert.strictEqual(fs.readFileSync(files.hosts, 'utf8'), hosts);
  assert.strictEqual(fs.readFileSync(files.cache, 'utf8'), cache);
}));
test('Cold start without DNS or cache waits without declaring readiness', () => fixture(async ({make, files}) => {
  let updater;
  const lines = [];
  updater = make({query: async () => { throw new Error('Unavailable'); }, log: message => {
    lines.push(message);
    if (message.includes('秒后重试')) updater.stop();
  }});
  await updater.run();
  assert(lines.some(line => /尚无可用记录.*5 秒后重试/.test(line)));
  assert(!fs.existsSync(files.ready)); assert(!fs.existsSync(files.cache));
  assert(!fs.readFileSync(files.hosts, 'utf8').includes(dns.HOSTNAME));
}));
test('Expired cache requires school HTTPS validation and keeps its original expiry', () => fixture(async ({make, files, save, logs}) => {
  save(cached(['1.1.1.1', '8.8.8.8'], 1000, 2000));
  const updater = make({now: () => 3000, checkCached: async ip => { if (ip === '1.1.1.1') throw new Error('TLS failed'); }});
  await updater.restore();
  const hosts = fs.readFileSync(files.hosts, 'utf8');
  assert(hosts.includes('8.8.8.8')); assert(!hosts.includes('1.1.1.1'));
  assert.strictEqual(updater.lastGood.expiresAt, 2000);
  assert(logs.some(line => line.includes('缓存已过期')));
}));
test('Unusable expired cache and invalid FakeIP cache never establish readiness', () => fixture(async ({make, files, save}) => {
  save(cached(['1.1.1.1'], 1000, 2000));
  await make({now: () => 3000, checkCached: async () => { throw new Error('TLS failed'); }}).restore();
  assert(!fs.existsSync(files.ready));
  save(cached(['198.18.0.40'], 1000, 4000));
  await make({now: () => 3000}).restore();
  assert(!fs.existsSync(files.ready));
}));
test('Local persistence errors remain fatal rather than becoming DNS retries', () => fixture(async ({make, files}) => {
  fs.writeFileSync(path.dirname(files.cache), 'not a directory');
  await assert.rejects(make({query: async () => ({addresses: ['1.1.1.1'], ttl: 60})}).run(), error => !(error instanceof dns.ResolutionFailure));
}));
test('Stopping during a query prevents late writes', () => fixture(async ({make, files}) => {
  let complete;
  const updater = make({query: () => new Promise(resolve => { complete = resolve; })});
  const pending = updater.refresh();
  updater.stop(); complete({addresses: ['1.1.1.1'], ttl: 60});
  await pending;
  assert(!fs.existsSync(files.cache)); assert(!fs.existsSync(files.ready));
}));
test('DoH connects to bootstrap IP with SNI, verification and DNS wire data', async () => {
  const original = https.request;
  let options, body;
  https.request = (value, callback) => {
    options = value;
    const req = new EventEmitter(); req.destroy = () => {};
    req.end = data => { body = data; process.nextTick(() => {
      const res = new EventEmitter(); res.statusCode = 200;
      res.headers = {'content-type': 'application/dns-message', age: '10'};
      callback(res); res.emit('data', answer([a('1.1.1.1', 60)])); res.emit('end');
    }); };
    return req;
  };
  try {
    assert.deepStrictEqual(await dns.queryProvider(dns.PROVIDERS[0]), {addresses: ['1.1.1.1'], ttl: 50});
    assert.strictEqual(options.servername, dns.PROVIDERS[0].hostname);
    assert.strictEqual(options.rejectUnauthorized, true);
    assert.strictEqual(options.port, 443); assert.strictEqual(options.path, '/dns-query');
    assert.strictEqual(options.method, 'POST'); assert(body.equals(dns.queryMessage(dns.HOSTNAME)));
    options.lookup('ignored', {}, (error, ip, family) => {
      assert.strictEqual(error, null); assert.strictEqual(ip, dns.PROVIDERS[0].ip); assert.strictEqual(family, 4);
    });
  } finally { https.request = original; }
});
test('Refresh timing respects short TTLs and retries have no increasing long wait', () => {
  assert.strictEqual(dns.refreshDelay(0), 1000); assert.strictEqual(dns.refreshDelay(30), 24000);
  assert.deepStrictEqual([1, 2, 3, 4, 50].map(dns.retryDelay), [5000, 10000, 20000, 30000, 30000]);
});
test('Routing changes are limited to provider IPv4 HTTPS and cleaned up', () => {
  const calls = [];
  const cleanup = dns.installRoutes((file, args) => calls.push({file, args}));
  for (let i = 0; i < dns.PROVIDERS.length; i++) {
    assert.deepStrictEqual(calls[i], {file: 'ip', args: ['-4', 'rule', 'add', 'to', dns.PROVIDERS[i].ip + '/32', 'ipproto', 'tcp', 'dport', '443', 'table', '2']});
  }
  cleanup(); assert.strictEqual(calls.length, 4); assert(calls.slice(2).every(call => call.args[2] === 'del'));
});

(async () => {
  for (const item of cases) { await item.body(); console.log('PASS: ' + item.label); }
  console.log('All ' + cases.length + ' VPN DNS checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
