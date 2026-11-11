const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const taskSource = fs.readFileSync('web/static/js/tasks.js','utf8');
function concurrencyHarness(value) {
 let calls = 0, message, focused = false;
 const input = {value, focus() { focused = true; }};
 const ctx = {_bqInlineSaving:false, batchQueuesState:{currentQueueId:'q'},
  document:{getElementById:() => input}, _t:x => x, alert:x => {message=x;},
  apiFetch:async () => {calls++;return {ok:true,json:async () => ({queue:{title:'title'}})};},
  showBatchQueueDetail() {},refreshBatchQueues() {},console};
 vm.createContext(ctx);
 const start = taskSource.indexOf('async function saveInlineConcurrency(');
 vm.runInContext(taskSource.slice(start,taskSource.indexOf('// --- 单条执行 ---',start)),ctx);
 return {ctx,calls:() => calls,message:() => message,focused:() => focused};
}
test('invalid concurrency leaves the editor open and makes no API calls', async () => {
 for (const value of ['0','9','1.5','2abc','']) {
  const h=concurrencyHarness(value);
  await h.ctx.saveInlineConcurrency();
  assert.equal(h.calls(),0);
  assert.equal(h.message(),'tasks.concurrencyInvalid');
  assert.equal(h.focused(),true);
  assert.equal(h.ctx._bqInlineSaving,false);
 }
});
test('valid concurrency updates and refreshes normally',async () => {
 for (const value of ['1','8']) {
  const h=concurrencyHarness(value);
  await h.ctx.saveInlineConcurrency();
  assert.equal(h.calls(),2);
  assert.equal(h.message(),undefined);
 }
});
