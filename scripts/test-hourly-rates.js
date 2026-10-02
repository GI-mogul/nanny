const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('index.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);

function extract(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `Missing ${name}`);
  const end = source.indexOf('\n    function ', start + 1);
  return source.slice(start, end < 0 ? source.length : end);
}

const context = vm.createContext({ state: { hourRate: 15, historicalHourRate: 13, tripRate: 4.86 } });
for (const name of ['currentElapsed', 'hourRateFor', 'payFor', 'calculateTotals', 'countUniqueDates']) {
  vm.runInContext(extract(script, name), context);
}
const day = (date, id) => ({ id, date, elapsedMs: 2 * 3600000, trips: 2, parking: 3, overnight: 100 });
const before = day('2026-09-30', 'before');
const after = day('2026-10-01', 'after');
assert.equal(context.payFor(before), 138.72);
assert.equal(context.payFor(after), 142.72);
assert.equal(context.hourRateFor(day('2027-01-01', 'future')), 15);
assert.equal(context.calculateTotals([before, after]).pay, 281.44);
assert.equal(context.calculateTotals([before, after]).hoursByRate.size, 2);
assert.equal(context.countUniqueDates([after, day('2026-10-01', 'second')]), 1);
context.state.hourRate = 18;
assert.equal(context.payFor(before), 138.72);
assert.equal(context.payFor(after), 148.72);

const server = fs.readFileSync('server.js', 'utf8');
const normalizers = server.slice(server.indexOf('function normalizeState('), server.indexOf('function readJsonBody('));
vm.runInContext(normalizers, context);
const legacy = { hourRate: 13, tripRate: 4.86, days: [before, after] };
const changed = { ...legacy, hourRate: 18, historicalHourRate: 99, ratesUpdatedAt: '2026-10-02T12:00:00Z' };
const merged = context.mergeStates(legacy, changed);
assert.equal(merged.hourRate, 18);
assert.equal(merged.historicalHourRate, 13);
assert.equal(context.mergeStates(merged, legacy).hourRate, 18);
assert.equal(context.mergeStates(merged, legacy).historicalHourRate, 13);
assert.equal(context.mergeStates(merged, { ...changed, days: [before] }).days.length, 2);
assert.equal(context.normalizeState({ ...legacy, historicalHourRate: 0 }).historicalHourRate, 0);
console.log('Hourly rate boundary, historical totals, extras, and server merge: passed.');
