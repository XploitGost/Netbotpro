const { test } = require('node:test');
const assert = require('node:assert/strict');
const { observeInterfaceCycle: observe } = require('./candidate-cycle.cjs');
const sample = (selected_iface, count) => ({ selected_iface, ipc_accepted: count, journal_acknowledged_records: count });
test('idle or absent interface cannot establish a baseline', () => {
  assert.deepEqual(observe({}, sample('A', 0)), {});
  assert.deepEqual(observe({}, sample(null, 10)), {});
});
test('profiling counters cannot impersonate an interface change', () => {
  const baseline = observe({}, sample('A', 1));
  const next = observe(baseline, { ...sample('A', 20), capture_profile: { seen_packets: 20 } });
  assert.equal(next.left, undefined);
  assert.equal(baseline.left, undefined);
});
test('departure alone is not a completed return', () => {
  const state = observe(observe({}, sample('A', 1)), sample('B', 2));
  assert.equal(state.left, true);
  assert.equal(state.returned, undefined);
});
test('return requires subsequent confirmed traffic', () => {
  const returned = observe(observe(observe({}, sample('A', 1)), sample('B', 2)), sample('A', 3));
  assert.equal(returned.returned, true);
  assert.equal(returned.trafficAfterReturn, undefined);
  assert.equal(observe(returned, sample('A', 4)).trafficAfterReturn, true);
});
