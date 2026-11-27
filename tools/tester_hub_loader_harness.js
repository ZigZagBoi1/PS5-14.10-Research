'use strict';

const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const functionStart = html.indexOf('function runProbeStage(');
const functionEnd = html.indexOf('/* ============================================================', functionStart);
if (functionStart < 0 || functionEnd < 0) throw new Error('runProbeStage not found');
const source = html.slice(functionStart, functionEnd);

function makeLoader() {
  const timers = [];
  let nextId = 1;
  let lastScript = null;
  const context = {
    window: {},
    document: {
      body: { appendChild(script) { lastScript = script; } },
      createElement() { return {}; },
    },
    UID: 'TEST',
    FW: '14.10',
    Date: { now: () => 123 },
    beacon() {},
    setTimeout(fn, delay) {
      const id = nextId++;
      timers.push({id, fn, delay, cleared: false});
      return id;
    },
    clearTimeout(id) {
      const timer = timers.find(item => item.id === id);
      if (timer) timer.cleared = true;
    },
  };
  vm.createContext(context);
  vm.runInContext(source + '\nthis.runProbeStage = runProbeStage;', context);
  return {
    context,
    timers,
    script() { return lastScript; },
    fireTimer() {
      const timer = timers.find(item => !item.cleared && !item.fired);
      if (!timer) throw new Error('no live timer');
      timer.fired = true;
      timer.fn();
    },
  };
}

function start(loader, stage, events, onScript) {
  const previousAppend = loader.context.document.body.appendChild;
  loader.context.document.body.appendChild = script => {
    previousAppend(script);
    if (onScript) onScript(loader.context, script);
  };
  loader.context.runProbeStage(stage, success => events.push(success));
  loader.context.document.body.appendChild = previousAppend;
}

function capturedComplete(context) {
  const token = context.window.__probeRunToken;
  return success => context.window.__probeComplete(success, token);
}

const results = {};

{
  const loader = makeLoader();
  const events = [];
  let syncComplete;
  start(loader, 'A', events, context => {
    syncComplete = capturedComplete(context);
    syncComplete(true);
  });
  loader.script().onload();
  syncComplete(true);
  results.sync_duplicate = events;
  results.sync_timer_cleared = loader.timers.every(timer => timer.cleared || timer.fired);
}

{
  const loader = makeLoader();
  const events = [];
  start(loader, 'A', events);
  const late = capturedComplete(loader.context);
  loader.script().onload();
  loader.fireTimer();
  late(true);
  results.timeout_late = events;
}

{
  const loader = makeLoader();
  const events = [];
  start(loader, 'A', events);
  const late = capturedComplete(loader.context);
  loader.script().onload();
  loader.script().onerror();
  late(true);
  results.error_late = events;
}

for (const mode of ['timeout', 'sync', 'error']) {
  const loader = makeLoader();
  const events = [];
  let lateA;
  start(loader, 'A', events, context => {
    lateA = capturedComplete(context);
    if (mode === 'sync') lateA(true);
  });
  loader.script().onload();
  if (mode === 'timeout') loader.fireTimer();
  if (mode === 'error') loader.script().onerror();
  start(loader, 'B', events);
  lateA(mode === 'sync' ? false : true);
  results['cross_' + mode] = events;
}

{
  const loader = makeLoader();
  const events = [];
  let lateA;
  start(loader, 'same', events, context => { lateA = capturedComplete(context); });
  loader.script().onload();
  loader.fireTimer();
  start(loader, 'same', events);
  loader.script().onload();
  lateA(true);
  results.same_stage_timeout = events;
}

{
  const loader = makeLoader();
  const events = [];
  start(loader, 'A', events);
  const valid = capturedComplete(loader.context);
  results.has_run_token = typeof loader.context.window.__probeRunToken === 'string';
  loader.script().onload();
  loader.context.window.__probeComplete(true);
  results.missing_token_before_valid = events.slice();
  loader.context.window.__probeComplete(true, 'wrong-token');
  results.wrong_token_before_valid = events.slice();
  valid(true);
  results.valid_token = events;
}

process.stdout.write(JSON.stringify(results) + '\n');
