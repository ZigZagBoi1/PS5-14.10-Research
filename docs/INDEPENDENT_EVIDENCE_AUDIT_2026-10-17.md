# Independent Evidence Audit — `ps5_1410_evidence_audit.json` (ledger) vs cited sources & primary logs

This is the detailed claim-by-claim source review. It records the state as of 2026-10-17, before probes 53a–53d were prepared. Those probes remain unrun; no new console result is implied by this report.

**2026-10-18 interpretation correction:** This remains a read-only audit snapshot from 2026-10-17. Its historical status-source quotes and some 45c conclusions below are not current claims. Probe 45c recorded tested calls persisting after selected metadata mutations in one run; it does not identify the complete dispatch implementation. Use the updated 2026-10-17 evidence audit, Finding 56, and probe index for current scope. No new hardware results are implied.

**Audit date:** 2026-10-17 (same day the ledger was produced)
**Mode:** read-only; no research files modified. Working scripts confined to `.swarm/audit/` (`elf_probe.py`, `dump_text.py`, `headtail.py`, `probe_meta.py`, `count_match.py`).
**Guardrails:** no console contact, no exploitation attempted, no writes outside `.swarm/`; network access limited to the two cited public URLs.

---

## 1. Artifact hash register (recomputed during the 2026-10-17 audit)

| Artifact | SHA-256 | Size (B) | mtime |
|---|---|---|---|
| `ps5_1410_evidence_audit.json` (ledger) | `563fa659…01da3585` | 2,367 | 2026-10-17 21:39:55 |
| `kernel_1360.elf` | `31968bce…4e020cec` | 47,451,147 | 2026-10-17 18:25:01 |
| `PS5-14.10-Research/CLAUDE.md` | `684ac8dd…df80ae189` | 15,170 | 2026-10-16 21:52:57 |
| `PS5-14.10-Research/README.md` | `6baa2148…f166763ea` | 14,641 | 2026-10-17 15:40:13 |
| `PS5-14.10-Research/docs/EVIDENCE_AUDIT_2026-10-17.md` | `c2e47ae9…d26c22465` | 6,381 | 2026-10-17 15:51:57 |

## 2. Per-claim adjudication (every ledger field)

Verdicts: VERIFIED / CONSISTENT / SUPPORTED / PARTIAL / NOT-ESTABLISHED / CONTRADICTED / HYPOTHESIS / MISSING-EVIDENCE.

### 2a. Static file facts — independently recomputed
| # | Ledger claim | Verdict | Evidence |
|---|---|---|---|
| 1 | `file_size_bytes: 47451147` | **VERIFIED** | byte count recomputed |
| 2 | `sha256: 31968bce…020cec` | **VERIFIED** | recomputed, exact match |
| 3 | ELF64 / little-endian / OSABI=FreeBSD / amd64 | **VERIFIED** | ELF ident parsed: `7f454c46`, class 2, data 1, OSABI 9, machine 0x3e |
| 4 | exec segment @ `0x10000`, 13,369,344 B, sha `20da45a0…129673` | **VERIFIED** | segment hashed byte-exact |
| 5 | `matches_public_13_60_text_hash: true` | **VERIFIED** | live fetch of `terrafirma2021/ps5-13.60-kernel-dump/…/kernel-13.60-live.bin.json`; its `kernel_text.source_sha256` = `20da45a0…129673` (exact) |
| 6 | `13_60_firmware_string_present: true` | **VERIFIED** | `"13.60"` ×2 (0x138d812, 0x1a93f51); `"FreeBSD"` present; string `"14.10"` absent from file |
| 7 | `known_elf_issue: PHDR not covered by LOAD; section headers absent` | **VERIFIED** | PT_PHDR vaddr 0 not covered by any LOAD; `e_shnum = 0` |

### 2b. Conclusions block
| # | Ledger claim | Verdict | Notes |
|---|---|---|---|
| 8 | `13_60_elf_loadable_or_original: not established` | **CONSISTENT** | Both structural issues confirmed; the public capture itself says it is “not a decrypted nested PUP kernel.bin or a bootable executable”. |
| 9 | `14_10_kernel_code_present: not established` | **CONSISTENT** | Artifact is labeled 13.60 and internally hash-consistent with the cited public metadata. Acquisition authenticity remains unresolved: matching hashes and embedded strings do not authenticate firmware or exclude all 14.10-derived content. No authenticated 14.10 kernel artifact was identified in the examined materials (the saved version banner is session-reported identity — see §6). |
| 10 | `14_10_kernel_exploit_or_jailbreak: no confirmed evidence in examined materials` | **SUPPORTED** | Every examined log is a failure/negative/truncation (see §§4–6). The cited status doc itself (live) states: “NO native code execution and NO KASLR defeat”. No promotion of hypotheses — none warranted. |

### 2c. Project status block
| # | Ledger claim | Verdict | Notes |
|---|---|---|---|
| 11 | `latest_status_source` = GitHub CLAUDE.md URL | **VERIFIED** | Fetched live 2026-10-17; contains exactly the attributed statements (45c disproof; AIO/AF_ROUTE dead ends). Local copy matches the live master on all key lines (L26, L32, L187, L189–L191, L211, L231–248). |
| 12 | `readme_is_stale: "claims … 43x probes ready"` | **PARTIAL** | True for parts (L45 “**16 targeted probes (43a–43p) are ready to send**”; L261 “ready to test”), but the same README also contains updated corrections (L110 “do **not** establish kernel read/write…”, L124 “already contains results … outcomes authoritative”). Verdict: README is **internally inconsistent (partially updated)**, not uniformly stale. |
| 13 | code_execution: userland yes / native not demonstrated | SUPPORTED WITH LIMITS | 45c records sysctl/getpid results persisting after selected fn_addr changes and chain-entry corruption in one run. This contradicts the earlier dependency model for those tested calls; the implementation and other paths remain unidentified. 47b did not test offset +0. Native execution is not demonstrated. |
| 14 | `kernel_rw: not demonstrated` | **SUPPORTED** | 42h2 (ROP kernel read): every target BLOCKED (`kern.proc.all`, `kern.file`, `kstack`, pcblist …); 42a: kinfo_proc gives sentinel `0xFFFFFFFF00000000`, vmmap ret=-1; 42c/42b: sentinels only. |
| 15 | `kaslr_defeat: not demonstrated` | **SUPPORTED** | 43a/43b: header-only logs (no output); 43o: failed writes, 0 kernel pointers; 42c/42b/42a: no real kernel VA in any inspected structure. |

### 2d. AIO / AF_ROUTE relay block (ledger explicitly marked “primary logs not independently inspected”)
| # | Ledger claim | Verdict | Now-inspected primary logs |
|---|---|---|---|
| 16 | `aio: reported sandbox-killed …` | **Relay accurate; underlying assertion NOT-ESTABLISHED** | 43p (323 B) ends at “`[1/10] aio_error (syscall 317) — Check AIO request status (safest)`” — no outcome, no kill record. 19g shows `aio_error: rv=-1` — **a returned error**, then ends at “`--- PART 2: alternate aio_read numbers ---`”. No log anywhere records a kill; “instant-kills even raw” (CLAUDE.md L190) is contradicted by 19g for `aio_error`, and unsupported for the rest. |
| 17 | `af_route: reported no kernel pointer leak …` | **Relay accurate; “patched” assertion NOT-ESTABLISHED** | 43o (COMPLETE marker): `write ret=-1` on the RTM_GET send, all RTM_GET destination writes “failed”, read returns 108 B, `kernel pointers found: 0`. Response attribution is unresolved; no successful request delivery or valid disclosure test is established; “info leak patched on 14.10” (CLAUDE.md L189) asserts a kernel property the test never exercised. |
| 18 | `confidence_note: assertions from project docs, not independent replication` | **VERIFIED** | Correct and prudent characterization. |
| 19 | `prudent_next_evidence` list | **SOUND** | None of the three items exist in-repo (no authenticated 14.10 code reference; primary logs corroborate only negatives; static re-analysis done here — PHDR/e_shnum reconfirmed). |
| 20 | `limits` (static-only, no exploitation) | **TRUE** | Consistent with the artifact; same limits observed here. |

## 3. Contradictions register (doc claim vs primary artifact)

- **C1 — “AIO sandbox-killed … confirmed kernel-level” + “aio_error instant-kills even raw” (CLAUDE.md L30, L190)** vs 19g `aio_error: rv=-1` (a return exists) and 43p ending at the call line with no kill record. Kill is **not evidenced**; one call demonstrably returned.
- **C2 — “Info leak patched on 14.10” (CLAUDE.md L189)** vs 43o `write ret=-1` — no successful RTM_GET delivery is recorded; the 108-byte read has unresolved attribution and zero detected pointers, which cannot establish “patched”.
- **C3 — “kldstat/kldsym … sandbox-killed at kernel level” (CLAUDE.md L191)** vs 43a (145 B) / 43b (116 B) — header-only logs; no output, no error, no kill wording.
- **C4 — “Probe 47b confirmed CClosure C func ptr is read-only” (CLAUDE.md L233)** vs 47b log internal conflict: `+0` was never write-tested; `+16` (same value `0x3105AF820`) reported WRITABLE; Section F: “CClosure function pointer is NOT writable (or offset unknown)”; Section G: “C func ptr writable: false”. The log does not cleanly establish the doc’s claim.
- **C5 — README internal inconsistency**: L45/L261 (“probes … ready to send / ready to test”) vs L124 (“already contains results … treat outcomes as authoritative”). Same file, same timestamp.
- **C6 — “AIO was killed (43p)” (README L124)** vs 43p raw log (no kill record) — the repo’s own `docs/EVIDENCE_AUDIT_2026-10-17.md` corrects this (“does not show that call killing the process”).
- **C7 — metadata**: CLAUDE.md header “Updated 2026-10-17 — post-51b” vs file mtime 2026-10-16 21:52:57 (predates the 51c run at 21:58 and the second 51b at 23:04). Content otherwise matches live master; flagged as a minor metadata inconsistency only.

## 4. Failed tests / aborted runs register (primary logs)

| Log | State | Detail |
|---|---|---|
| 42g | **CRASHED (Lua bug)** | `attempt to perform arithmetic on global 'MB' (a nil value)` at STEP 2 → kptr-leak scan never ran (only `kptrs=0` from STEP 1) |
| 46a run1 (194741) | **CRASHED (Lua bug)** | `invalid option '%b' to 'format'` at section D |
| 46a run2 (195704) | Truncated | ends at “`=== F: NEIGHBOR SWEEP 550-625 ===`”; note `620 struct: no kernel pointers` |
| 42g2 | Truncated | ends at “`--- STEP 1: KENV (syscall 390) ---`” (88 B) |
| 45c run1 (192602) | Truncated | ends at “`=== B: SYSCALL STUB BYTES ===`” (798 B) |
| 42h | Truncated | ends at “`--- STEP 4: IDENTIFY FN_ADDR ---`” (2520 B) |
| 42f | Truncated | “surveying 80 physical offsets…” → 1 result line recorded (459 B) |
| 42g3 | Truncated | ends after “`4.0GB: zeros`” (404 B) |
| 43a / 43b | Truncated | header-only: 145 B / 116 B |
| 51b dynlib fuzz | Truncated | ends at “`--- PHASE 1: Zero-arg baseline ---`” (135 B) |
| 42b | Truncated | ends mid-TCB dump with binary tail (2017 B) |
| 19g / 43p | Truncated | end at PART 2 header / at the `[1/10]` call line |

**Pattern:** logs end at section boundaries/headers with **no `COMPLETE` marker and no kill/pkill wording anywhere**. This is consistent with process death *or* crash *or* connection loss *or* capture truncation — the logs **cannot** distinguish them. No “kill” claim is mechanically supported by any log.

## 5. Stated vs recorded counts (mechanically re-derived)

| Log | Stated | Recorded | Note |
|---|---|---|---|
| 51a (214814) | “Testing 110 Sony syscalls” | **55** records | matches in-repo doc’s “55” |
| 51a (220811) | “all 145 syscalls” | **29**; stops at `[560]` | confirms “29 records, stops at 560” |
| 51c | “Testing 54 Sony syscalls” | **2** (625, 626) | confirms doc |
| 51b accessible | — | **47** call records | in-repo doc “30 call patterns” = sections A–D+G only (excl. E/F sweeps); both bases defensible, raw = 47 |
| 42f | “surveying 80 offsets” | **1** | additional truncation instance |
| 42h2 | “mapped 13 slots” | **13** ✓ | count cross-checked |
| 51b accessible | — | non-sentinel returns: 596=0, 585=1, 624=0xD30, 606=0, 643=0, 640=0 (outbuf all zeros); **no kernel pointers** | confirms “no leaks in 51b” |

## 6. Source versions & provenance register

- **Session-reported console target:** FreeBSD `r230171/releases/14.10 Sep 28 2026 02:18:33`, 16 KB pages, 16 CPUs (`41w`, `42a`). No authenticated 14.10 kernel image was identified in the examined materials; the banner alone does not authenticate firmware/build identity.
- **Kernel artifacts in repo:** capture labeled 13.60 (`kernel_text.bin` 15,132,096 B, sha `406ab210…`, kernel_base `0xffffffff8a9c0000`) — different retained bytes from the ELF (13,369,344 B segment, sha `20da45a0…`).
- **Public source:** `terrafirma2021/ps5-13.60-kernel-dump` JSON fetched live; `source_sha256` match exact; reconstruction `c3f745e2…`, 103,546,880 B; documented caveat quoted.
- **Status doc:** remote CLAUDE.md fetched live 2026-10-17; key post-51b statements present (`45c proved…`, `47b confirmed…`, `51a output truncated`); local copy consistent.

## 7. Missing evidence register

1. No kernel-side logs (dmesg/console/panic) for any alleged “kill” — cause of truncation undeterminable from userland logs.
2. No 14.10 kernel code or authenticated 14.10 reference exists in the corpus.
3. No transcript of a successful kernel read/write; **no real kernel pointer appears in any log** (only `0xFFFFFFFF_00000000`, `0xFFFFFFFF_FFFFFFFF` sentinels).
4. No reproducible native code execution; no memory-corruption symptom beyond sentinels and failed writes.
5. 47b’s `+0` writability was never tested (probe skipped live redirect).
6. Partial coverage remains for several surveys (42f set, 51a/51c ranges) until reruns complete.

## 8. Bottom line

- **Static integrity/source-content claims (fields 1–7, 11):** the recorded checks support file properties, hash consistency and the fetched document content. They do not authenticate acquisition, historically executed collector identity or firmware/build provenance.
- **Negative conclusions (fields 8–10, 13–15):** supported; nothing found this session contradicts them.
- **Relayed status claims (16–17):** accurately relayed and rightly marked as un-inspected by the ledger; now inspected — the underlying doc assertions (“confirmed kernel-level kill”, “leak patched”) are **NOT ESTABLISHED** and collide with C1–C2.
- **No jailbreak, no new kernel vulnerability, no native code execution is claimed** — and none is supportable from this corpus as of this audit.

## 9. Secondary findings (flag, do not promote)

- S1: In-repo audit-doc figure “30 call patterns” (51b) vs raw 47 — count-basis difference; raw log authoritative (report 47).
- S2: CLAUDE.md mtime vs “Updated” header mismatch (C7).
- S3: 46a/42g Lua crashes were probe-code bugs (not console faults) — relevant to any rerun.

---

*Read-only audit. No hypothesis promoted to verified finding. Work artifacts: `.swarm/audit/`.*
