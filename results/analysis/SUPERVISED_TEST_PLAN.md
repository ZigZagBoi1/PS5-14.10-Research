# Supervised Console Testing Plan

**Prepared:** 2026-11-11  
**Target:** PS5 firmware 14.10, WebKit 605.1.15  
**Precondition:** Console online, game process with Lua loader active on TCP 9026

---

## Pre-Test Checklist

1. [ ] Verify firmware: 14.10 (Settings → System → System Software)
2. [ ] Verify Lua loader: `python tools/send_probe.py --save probes/phase1/hello.lua` returns output
3. [ ] Re-measure kernel base: `.local/1331a.lua` — record new base if rebooted
4. [ ] Start beacon server: `python tools/browser_runner/serve.py`
5. [ ] Record git revision: `git rev-parse HEAD`
6. [ ] Verify browser entry method is stable

## Test Sequence (Bounded, Supervised)

### Phase 1: Environment Verification (5 min)

**Test 1.1: structuredClone availability**
Quick JS probe to check `typeof structuredClone`. This determines whether p719 vectors D and F are viable.
- CRASH_CLASS: NONE
- Expected: "function" or "undefined"
- Record: exact output

**Test 1.2: API inventory confirmation**
Verify RAB, DataView, BigUint64Array, RegExp are all functional.
- CRASH_CLASS: NONE
- Expected: all available (already confirmed in p601)

### Phase 2: p719 OOB Read Survey (15 min)

**Run p719 under supervision.**
- Serve via beacon infrastructure
- Monitor all beacon callbacks
- CRASH_CLASS: MODERATE (WebProcess may crash on OOB access)
- If WebProcess crashes: record beacon log up to crash point, do NOT auto-retry
- Record: firmware, probe git hash, raw beacon output, crash/no-crash

**Expected outcomes per vector:**
| Vector | Expected | If Unexpected |
|--------|----------|---------------|
| A (RAB stale) | Bounds check catches, no OOB | If OOB succeeds: MAJOR FINDING — examine pointer values |
| B (DFG string) | NO-OOB-CHARS (no DFG) | If OOB: re-examine JIT tier assumption |
| C (RegExp) | Unknown | Any OOB data → examine for pointers |
| D (Transfer) | Throws on detached buffer | If stale data: SIGNIFICANT — examine for pointers |
| E (DataView RAB) | Bounds check catches | Same as A |
| F (Clone valueOf) | Likely benign | Any length confusion → examine carefully |

### Phase 3: CVE-2026-64718 Canvas UAF (15 min)

**Run p721 under supervision.**
- Tests 6 Canvas lifecycle patterns (A-F)
- CRASH_CLASS: MODERATE
- Record: which patterns trigger, any freed-memory reads

### Phase 4: CVE-2023-41976 SVG Animation UAF (15 min)

**Run p686 under supervision.**
- Different size class from FontFace (192B)
- CRASH_CLASS: MODERATE
- Record: UAF trigger, reclaim success, any info leak

### Phase 5+: Lower priority probes (as time allows)

p692 → p694 → p693 → p689/p690

---

## Recording Protocol

For EVERY probe execution:

```yaml
probe: <name>
firmware: 14.10
git_hash: <sha>
date: <ISO 8601>
beacon_log: <path to raw beacon output>
crash: yes/no
crash_details: <if yes, last beacon before crash>
vectors_tested: <list>
vectors_triggered: <list>
pointer_candidates: <list of hex values>
classification: VOID | MEASURED | INFERRED
notes: <anything unexpected>
```

Save to `results/analysis/console_test_<date>.yaml`

## Safety Rules

1. **Do NOT auto-loop crash-inducing tests.** One run, record, assess.
2. **Do NOT claim arbitrary memory access** from: an address calculation, a crash, or unexpected JS behavior. An OOB read of heap data ≠ info leak. A pointer-shaped value needs independent verification.
3. **WebProcess restarts on every navigation** — each probe is single-shot, single-page.
4. **If a probe crashes WebProcess:** wait for restart, verify beacon server is listening, then proceed to next probe (do not re-run the crashing probe without analysis).
5. **Update STATE.md and INDEX.md** after each probe with actual results.
6. **Commit results** after each phase completes.

## Success Criteria

A probe result **materially changes** the kernel R/W assessment if and only if:

1. It provides a **reproducible** read of data the attacker should not see (not just a crash or unexpected exception)
2. The leaked data contains **code pointers** (vtable pointers, function pointers) or **heap metadata** that can be used to compute WebProcess text base
3. The leak is **controllable** (attacker can choose what to read, not just random heap noise)
4. The technique survives **at least 2 independent runs** on the same boot

Anything less is classified as INFERRED [I] or VOID [V], not MEASURED [M].

## Queued Console Experiments (Not Part of This Plan)

These require separate assessment and may be higher-risk:
- 1407a (ktimer CLOCK_TAI leak, SA-26:51)
- 1408a (sysvsem OOB, SA-26:54)
- 1409a (kevent ext[] leak)
- p800 (TransformStream typeconf)
