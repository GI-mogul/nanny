const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function main() {
  const html = fs.readFileSync('index.html', 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const server = fs.readFileSync('server.js', 'utf8');
  const storage = new Map();
  const status = { textContent: '' };
  const login = { hidden: true };
  const day = (id) => ({ id, date: '2026-10-29', elapsedMs: 3600000, trips: 2 });
  const initial = { hourRate: 15, historicalHourRate: 13, tripRate: 4.86, days: [day('old')] };
  const remote = { ...initial, days: [day('old'), day('new')] };
  let httpStatus = 200;
  let putCount = 0;
  const context = vm.createContext({
    state: initial, defaultState: initial, localChangeVersion: 0, syncInFlight: false,
    serverSyncReady: false, editingDayId: null, saveTimer: null, location: { protocol: 'https:' },
    STORAGE_KEY: 'test', AbortSignal, readNumber: Number, readOvernight: Number,
    document: { querySelector: (id) => id === '#syncStatus' ? status : login },
    els: { ratesEdit: { hidden: true }, hourRate: {}, tripRate: {} },
    localStorage: { setItem: (key, value) => storage.set(key, value) },
    render() {}, loadAuditLog() {}, setTimeout() {}, clearTimeout() {},
    fetch: async (_, options) => {
      if (options.method === 'PUT') putCount++;
      return { status: httpStatus, ok: httpStatus === 200, json: async () => ({state: remote}) };
    }
  });
  vm.runInContext(script.slice(script.indexOf('    async function loadServerState('), script.indexOf('    async function loadAuditLog(')), context);
  vm.runInContext(script.slice(script.indexOf('    function normalizeClientState('), script.indexOf('    function render()')), context);
  vm.runInContext('function timestampMs(value) { return Date.parse(value) || 0; }', context);
  await context.loadServerState();
  assert.equal(context.state.days.length, 2, 'Open page receives new server records');
  assert.equal(putCount, 0, 'Unchanged state does not write');
  httpStatus = 401;
  await context.saveServerStateNow();
  assert.equal(login.hidden, false, 'Expired session offers login');
  assert.match(status.textContent, /Вход истек/);
  assert.equal(context.state.days.length, 2, '401 preserves browser records');
  httpStatus = 503;
  await context.saveServerStateNow();
  assert.match(status.textContent, /Нет подтверждения/);
  httpStatus = 200;
  await context.saveServerStateNow();
  assert.equal(login.hidden, true);
  assert.equal(context.state.days.length, 2, 'PUT accepts canonical server state');
  assert.ok(html.includes('setInterval(loadServerState, 15000)'));

  let saved = null;
  let pendingLock = Promise.resolve();
  const dbPool = { connect: async () => {
    let unlock;
    return {
      query: async (sql, args) => {
        if (sql.includes('pg_advisory_xact_lock')) {
          const previousLock = pendingLock;
          pendingLock = new Promise((resolve) => { unlock = resolve; });
          await previousLock;
        }
        if (sql.startsWith('select value')) return { rows: saved ? [{ value: saved }] : [] };
        if (sql.includes('insert into app_state')) saved = args[1];
        if (sql === 'COMMIT' || sql === 'ROLLBACK') unlock();
        return { rows: [] };
      },
      release() {}
    };
  } };
  const dbContext = vm.createContext({dbPool, dataStoreReady: Promise.resolve()});
  vm.runInContext(server.slice(server.indexOf('function normalizeState('), server.indexOf('function readJsonBody(')), dbContext);
  vm.runInContext(server.slice(server.indexOf('async function saveSharedState('), server.indexOf('async function getAuditLog(')), dbContext);
  await Promise.all([
    dbContext.saveSharedState({ ...initial, days: [day('one')] }),
    dbContext.saveSharedState({ ...initial, days: [day('two')] })
  ]);
  assert.equal(saved.days.length, 2, 'Concurrent users do not lose each other\'s additions');
  console.log('Sync refresh, 401/503 visibility, acknowledgement, concurrent database writes: passed.');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
