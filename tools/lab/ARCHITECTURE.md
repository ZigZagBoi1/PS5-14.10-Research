# PS5 Research Laboratory Architecture

## Infrastructure Map

```
 Windows (this machine)                Linux (10.0.0.80)
 ========================              ============================
 orchestrator.py (main)   --SCP-->    /var/www/ps5-guide-entry/
 chiaki_control.py        --SSH-->    nginx (80/443) -> PS5 browser
 beacon_monitor.py        --SSH-->    /api/beacon (8081 telemetry)
 dashboard.py (local)                 /api/status, /api/events
 state.py (existing)                  DNS: manuals.playstation.net
                                      chromedriver on 9515 (unused)
              |
              v
 Chiaki-ng (remote play) ----------> PS5 (10.0.0.96)
                                      :9026 Lua handler (game process)
                                      :9021 elfldr (when jailbroken)
                                      Browser (WebKit 605.1.15)
```

## Environments

| Environment | Firmware | Status | Purpose |
|------------|----------|--------|---------|
| 13.60 reference | 13.60 | WORKING (Relapse exploit) | Baseline, known-good primitives |
| 14.10 target | 14.10 | RESEARCH (UAF + fault oracle) | Exploit development |

## Component Responsibilities

### orchestrator.py (NEW)
- Experiment scheduling and execution
- Restart-safe state (JSON file)
- Bounded retries per experiment
- Global stop switch (file-based)
- Failure classification
- Calls other components as needed

### beacon_monitor.py (NEW)
- Polls /api/events on 10.0.0.80 for new telemetry
- Also tails nginx access log for GET /beacon requests
- Classifies beacon patterns into outcomes
- Returns structured results to orchestrator

### chiaki_control.py (NEW, integrates existing tools)
- Wraps chiaki_keys.py / chiaki_bridge.py
- PS5 UI recovery sequences:
  - Dismiss crash dialog
  - Navigate to User Guide
  - Refresh current page
  - Close and reopen browser
- Health check: can we see the PS5 screen?
- CANNOT recover: kernel panic, hard freeze

### probe_deployer.py (NEW)
- SCP probe HTML to /var/www/ps5-guide-entry/
- Optionally as index.html or as /probes/<name>.html
- Verifies deployment via HTTP GET
- Computes and stores probe hash for evidence

### hypothesis_registry.json (NEW)
- Structured list of hypotheses
- Fields: id, claim, supporting_evidence[], contradictory_evidence[],
  next_experiment, status (open/confirmed/dead/blocked), dead_end_reason

### experiment_state.json (NEW)
- Current experiment ID
- Run count, max retries
- Last beacon timestamp
- Failure history
- Console status (UP/DOWN/PANIC)

## Beacon Protocol

Two parallel channels:
1. **GET /beacon?m=<msg>** - logged in nginx access log, simple
2. **POST /api/beacon** - JSON to telemetry server, structured

Research probes use GET /beacon (lightweight, works without CORS).
The existing Relapse exploit uses POST /api/beacon.

## Failure Classification

| Class | Detection | Recovery |
|-------|-----------|----------|
| SUCCESS | Beacon with expected result tag | None needed |
| JS_EXCEPTION | Beacon with ERR/FAIL tag | Auto-refresh |
| WEBPROCESS_CRASH | No beacons after timeout, page reloads | Wait + retry |
| APP_FREEZE | Beacons stop mid-sequence | Chiaki: close + reopen browser |
| REMOTE_PLAY_DISCONNECT | Chiaki window gone | Restart Chiaki, reconnect |
| SERVER_FAILURE | HTTP 5xx or connection refused | Alert, stop |
| CONSOLE_PANIC | No response after multiple recovery attempts | STOP, alert user |

## Safety Constraints

- Max 3 consecutive crashes before pause
- Max 10 total runs per experiment without success
- Global stop file: tools/lab/STOP (existence halts all experiments)
- No firmware updates, factory resets, or system modifications
- Dangerous probes (CRASH_CLASS: HIGH/RISKY) require explicit opt-in
- All experiments log to tools/lab/runs/ with full evidence
