#!/usr/bin/env node
/*
 * watch-p720.js — alerts when pastawithpesto pushes the promised
 * p719/p720/p721 probes or the NEW_CVE_CANDIDATES doc.
 *
 * Checks the GitHub API for:
 *   - pastawithpesto/PS5-14.10-Jailbreak-Research master tree (p719/p720/p721/NEW_CVE)
 *   - pastawithpesto/PS5-14.10-Research (stale, but cheap to include)
 *   - ZigZagBoi1/PS5-14.10-Research master (the shared board repo)
 *
 * Usage:  node tools/watch-p720.js [interval-minutes]
 *         (default 15 min; Ctrl+C to stop; state kept in .watch-p720-state.json)
 */

const fs = require('fs');
const path = require('path');
const INTERVAL_MS = (parseInt(process.argv[2], 10) || 15) * 60 * 1000;
const STATE_FILE = path.join(__dirname, '.watch-p720-state.json');
const MARKERS = [/p719/i, /p720/i, /p721/i, /NEW_CVE_CANDIDATES/i];

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (e) { return {}; }
}
function saveState(s) { fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2)); }

async function ghJson(url) {
  const res = await fetch(url, { headers: { 'User-Agent': 'watch-p720' } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.json();
}

async function checkRepo(fullName) {
  const head = await ghJson(`https://api.github.com/repos/${fullName}/commits/master`);
  const sha = head.sha;
  const state = loadState();
  const prev = state[fullName];
  state[fullName] = sha;
  saveState(state);
  let files = '';
  try {
    const tree = await ghJson(`https://api.github.com/repos/${fullName}/git/trees/master?recursive=1`);
    files = tree.tree.map(t => t.path).join('\n');
  } catch (e) { files = ''; }
  const hits = MARKERS.filter(re => re.test(files)).map(re => re.source);
  return { sha, changed: prev && prev !== sha, hits, headMsg: (head.commit.message || '').split('\n')[0] };
}

async function tick() {
  const repos = [
    'pastawithpesto/PS5-14.10-Jailbreak-Research',
    'pastawithpesto/PS5-14.10-Research',
    'ZigZagBoi1/PS5-14.10-Research',
  ];
  const ts = new Date().toISOString().slice(0, 19);
  for (const repo of repos) {
    try {
      const r = await checkRepo(repo);
      console.log(`[${ts}] ${repo}: ${r.changed ? 'CHANGED' : 'unchanged'} @ ${r.sha.slice(0, 8)} hits=[${r.hits.join(',') || 'none'}]`);
      if (r.changed && r.hits.length) {
        console.log(`  *** MARKERS IN ${repo}: ${r.hits.join(', ')} ***`);
        console.log(`  *** last commit: ${r.headMsg} ***`);
        console.log('  => fetch + copy the probes into probes/phase13_webkit/ and run the 14.22 battery');
      }
    } catch (e) {
      console.log(`[${ts}] ${repo}: ERROR ${e.message}`);
    }
  }
}

console.log(`watch-p720: polling every ${INTERVAL_MS / 60000} min for p719/p720/p721/NEW_CVE markers`);
tick().then(() => setInterval(tick, INTERVAL_MS));
