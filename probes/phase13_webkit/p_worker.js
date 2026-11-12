// Entry: WorkerThread stale-proxy UAF probe (upstream fix 926054f254 shape).
location.replace('/corpus/poc-worker.html?t=' + Date.now());
