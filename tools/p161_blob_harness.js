// Runs probes/phase13_webkit/p161-length-window.js outside the console.
//
// The probe builds the blob that carries the metadata overflow and checks its
// own size: it beacons BLOB-MISMATCH when the generated source is not
// exactly calls * 4 + 53 bytes. This harness gives the probe the browser
// pieces it needs (location, beacon XHR, worker, script element) and reports
// the beacons, so the size claim can be tested without a console.
//
// Usage: node tools/p161_blob_harness.js <probe path> <mode> <calls>
// Prints one JSON object: {"beacons": [...], "blobMB": "15"}

'use strict';

const fs = require('fs');
const path = require('path');

const probePath = process.argv[2];
const mode = process.argv[3] || 'pair';
const calls = process.argv[4] || '4000000';

if (!probePath || !fs.existsSync(probePath)) {
  console.error('probe not found: ' + probePath);
  process.exit(2);
}

const beacons = [];

global.location = {
  search: '?mode=' + mode + '&calls=' + calls,
  protocol: 'http:',
  host: '127.0.0.1:8080'
};
global.self = global;

global.XMLHttpRequest = class {
  open(method, url) {
    this.url = url;
  }
  send() {
    const tag = String(this.url).split('/beacon/')[1];
    if (tag) beacons.push(tag.split('?')[0]);
  }
};

global.Worker = class {
  constructor() {
    this.onmessage = null;
  }
  postMessage(msg) {
    if (msg && msg.cmd === 'alloc') {
      setTimeout(() => {
        if (this.onmessage) this.onmessage({ data: { ready: true } });
      }, 0);
    }
  }
};

global.document = {
  createElement() {
    return {
      set onload(fn) { this._onload = fn; },
      get onload() { return this._onload; },
      set src(v) { this._src = v; },
      get src() { return this._src; },
      setAttribute() {}
    };
  },
  body: { appendChild() {} },
  head: { appendChild() {} }
};

if (typeof global.Blob !== 'function') {
  console.error('this node build has no Blob');
  process.exit(2);
}

const src = fs.readFileSync(probePath, 'utf8');
try {
  // eslint-disable-next-line no-eval
  (0, eval)(src);
} catch (err) {
  console.error('probe threw: ' + err.message);
}

const deadline = Date.now() + 30000;
const timer = setInterval(() => {
  const blob = beacons.find((b) => b.indexOf('-BLOB-') !== -1);
  if (blob) {
    clearInterval(timer);
    const size = blob.split('-BLOB-')[1].split('-')[0];
    console.log(JSON.stringify({ beacons, blobMB: size }));
    process.exit(0);
  }
  if (Date.now() > deadline) {
    clearInterval(timer);
    console.log(JSON.stringify({ beacons, blobMB: null }));
    process.exit(1);
  }
}, 100);
