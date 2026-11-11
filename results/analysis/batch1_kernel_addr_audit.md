# Batch 1: Kernel Address Consistency & SDK Offset Audit

**Date:** 2026-11-11  
**Tasks:** calc-5f3f097, calc-ac24784

---

## Task 1: Kernel Address Consistency (calc-5f3f097)

### STATE.md values under audit

| Symbol | STATE.md Value | Source |
|--------|---------------|--------|
| kernel_text | 0xFFFFFFFFD5000000 | **MEASURED** — probe 1199b fault oracle |
| kernel_data | 0xFFFFFFFFD5CE0000 | **COMPUTED** — TEXT + 0xCE0000 (SDK v0.45) |
| allproc | 0xFFFFFFFFD85B9EA0 | **COMPUTED** — DATA + 0x28D9EA0 (SDK v0.45) |
| security_flags | 0xFFFFFFFFD6A84064 | **COMPUTED** — DATA + 0x0DA4064 (SDK v0.45) |
| rootvnode | 0xFFFFFFFFD8E3B510 | **COMPUTED** — DATA + 0x315B510 (SDK v0.45) |

### Arithmetic verification

```
TEXT  = 0xFFFFFFFFD5000000 (measured, probe 1199b)
DATA  = TEXT + 0xCE0000 = 0xFFFFFFFFD5000000 + 0xCE0000 = 0xFFFFFFFFD5CE0000 ✓ matches STATE.md

allproc        = DATA + 0x28D9EA0 = 0xFFFFFFFFD5CE0000 + 0x28D9EA0 = 0xFFFFFFFFD85B9EA0 ✓
security_flags = DATA + 0x0DA4064 = 0xFFFFFFFFD5CE0000 + 0x0DA4064 = 0xFFFFFFFFD6A84064 ✓
rootvnode      = DATA + 0x315B510 = 0xFFFFFFFFD5CE0000 + 0x315B510 = 0xFFFFFFFFD8E3B510 ✓
```

All five values are **arithmetically consistent** with each other.

### Cross-document consistency

| Document | kernel_text | kernel_data | allproc | security_flags | rootvnode | Consistent? |
|----------|------------|-------------|---------|----------------|-----------|-------------|
| STATE.md | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| INDEX.md:3462 | ✓ | ✓ | ✓ | — | — | ✓ |
| CAPABILITY_GRAPH.md:124 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| EXTERNAL_AUDIT.md:41-44 | — | ✓ | ✓ | ✓ | ✓ | ✓ |

**No contradictions found.** All documents reference the same values.

### Critical finding: only ONE value is measured

The INDEX.md:3462 entry records the 1199b fault oracle results. The probe output (results/phase17_new_vectors/1199b_fault_oracle_upper_20261110_131841.txt) contains only presence/absence scanning — it determines which VA ranges are mapped but **never reads kernel memory content**. The TEXT base is genuinely measured. Everything else is derived.

**Provenance chain:**
```
MEASURED:  kernel_text (fault oracle, probe 1199b)
COMPUTED:  kernel_data = kernel_text + 0xCE0000        [SDK v0.45 offset]
COMPUTED:  allproc = kernel_data + 0x28D9EA0            [SDK v0.45 offset]
COMPUTED:  security_flags = kernel_data + 0x0DA4064     [SDK v0.45 offset]
COMPUTED:  rootvnode = kernel_data + 0x315B510           [SDK v0.45 offset]
```

All four computed values depend entirely on the correctness of SDK v0.45 offsets for firmware 14.10.

---

## Task 2: SDK-Derived Address Audit (calc-ac24784)

### SDK offset provenance

The offsets come from `ps5-payload-dev/sdk` v0.45:
- **Commit:** a7685ce8e97c (2026-10-12) — adds cases 0x14000000 and 0x14100000 to `crt/kernel.c`
- **Source:** docs/PRIVATE_UPSTREAM_1410_KERNEL_OFFSETS_2026-10-21.md, docs/KERNEL_OFFSETS_14_10_SDK_V045.md
- **Note from source:** "The SDK does NOT find these addresses itself. The kernel exploit passes them in." The offsets were determined by someone who already had kernel R/W on 14.10.

### Are SDK offsets validated?

**The constant drain campaign (docs/CONSTANT_DRAIN_HYPOTHESIS_14_10.md) tested 25 constants from the 13.60 offset table:**
- Only **1/25** confirmed valid (lk__thread_list)
- **7/25** confirmed WRONG
- **2/25** caused crashes
- **3/25** untestable (in XO text segment)

**However**, the constant drain tested the **13.60 Relapse offset table** (soniciso1/relapse-dev), NOT the SDK v0.45 14.10 offsets. The drain specifically found the 13.60 kernel offsets are wrong for 14.10:
- KERNEL_DATA: 13.60 says 0xCC0000, SDK v0.45 says 0xCE0000 — **different by 0x20000**
- KERNEL_ALLPROC: 13.60 says 0x03589E80, SDK v0.45 says D+0x28D9EA0 — **completely different base**

The SDK v0.45 offsets have **NOT been independently validated on the device**. They come from an upstream researcher who had kernel R/W through an unpublished exploit ("Gezine"). We trust them because:
1. They're published in a well-known SDK by a credible source
2. The 13.60→14.10 deltas are plausible (~64KB shift, consistent with a kernel rebuild)
3. They correctly predict that TEXT_BASE = DATA_BASE - 0xCE0000 (vs 13.60's 0xCC0000)

But point 3 is circular — we use the SDK offset to compute DATA from TEXT, then note the SDK offset is "consistent." No independent validation exists.

### Blast radius if SDK offsets are wrong

| Scenario | Impact |
|----------|--------|
| TEXT-to-DATA offset (0xCE0000) wrong | Every computed address is wrong. allproc, security_flags, rootvnode all invalid. |
| allproc offset wrong | Process list walk fails — cannot find our process or patch credentials. |
| security_flags offset wrong | Cannot disable security flags — jailbreak fails. |
| rootvnode offset wrong | Cannot escape sandbox via vnode manipulation. |

**Blast radius: TOTAL.** If the TEXT-to-DATA offset is wrong, the entire exploitation chain after KASLR defeat is broken. If individual symbol offsets are wrong, specific post-exploitation steps fail.

### What could validate these offsets?

1. **Kernel memory read** — read DATA_BASE and check for expected data patterns (impossible without kernel R/W, which is what we need the offsets for — circular)
2. **Crash oracle** — attempt to call a function at a computed address and observe crash/survive (risky, needs console)
3. **Cross-version analysis** — compare 13.60 dump offsets with 14.10 SDK offsets for structural consistency (partially done: the ~64KB shift is plausible)
4. **Second independent source** — another researcher publishes 14.10 offsets that match (none known)

### Existing indirect evidence

The 13.60→14.10 offset comparison (KERNEL_OFFSETS_14_10_SDK_V045.md:100-108) shows:
```
TEXT delta:        13.60=-0xCC0000   14.10=-0xCE0000   Δ=+0x20000
ALLPROC:           13.60=+0x28C9E80  14.10=+0x28D9EA0  Δ=+0x10020
SECURITY_FLAGS:    13.60=+0xD9C064   14.10=+0xDA4064   Δ=+0x8000
ROOTVNODE:         13.60=+0x314B510  14.10=+0x315B510  Δ=+0x10000
```

These deltas are **structurally plausible** — small, consistent shifts (~0x8000-0x20000) suggesting a kernel rebuild added a few pages. But plausibility is not validation.

---

## Answers to Research Questions

### Task 1 (address consistency)

1. **What did we previously believe?** All five kernel addresses in STATE.md are consistent and measured.
2. **What did the evidence actually establish?** Only kernel_text is measured (fault oracle). The other four are computed from SDK v0.45 offsets applied to the measured base. All documents are arithmetically consistent — no contradictions.
3. **Was anything overlooked or incorrectly classified?** The INDEX.md:3462 entry presents DATA/ALLPROC alongside TEXT without distinguishing measured from computed. EXTERNAL_AUDIT.md correctly flags security_flags and rootvnode as "SDK-derived, not independently measured" but does not flag kernel_data or allproc the same way. **allproc is also SDK-derived.**
4. **Did this investigation demonstrate a genuinely new capability?** No.
5. **What specific uncertainty remains?** The SDK v0.45 offsets are unvalidated on this console. The TEXT-to-DATA offset (0xCE0000) is the single point of failure: if wrong, all computed addresses are wrong.

### Task 2 (SDK audit)

1. **What did we previously believe?** SDK v0.45 provides reliable 14.10 kernel offsets.
2. **What did the evidence actually establish?** The offsets come from a credible upstream source (ps5-payload-dev) who had kernel R/W via an unpublished exploit. The 13.60→14.10 deltas are structurally plausible. But no independent on-device measurement validates them.
3. **Was anything overlooked or incorrectly classified?** The constant drain campaign proved the 13.60 Relapse offsets are wrong for 14.10, which is often conflated with the SDK v0.45 offsets. These are DIFFERENT offset sets — the SDK v0.45 offsets may well be correct even though the 13.60 Relapse offsets are wrong.
4. **Did this investigation demonstrate a genuinely new capability?** No.
5. **What specific uncertainty remains?** We cannot validate any SDK offset without kernel memory access. This is a fundamental chicken-and-egg: we need the offsets to exploit, but we need to exploit to validate the offsets. The only mitigation is trust in the upstream SDK publisher.

---

## Recommendations

1. **Relabel STATE.md entries** to distinguish measured [M] from SDK-derived [S]:
   - kernel_text: [M] measured
   - kernel_data: [S] SDK v0.45
   - allproc: [S] SDK v0.45
   - security_flags: [S] SDK v0.45
   - rootvnode: [S] SDK v0.45

2. **EXTERNAL_AUDIT.md correction:** allproc should be flagged as SDK-derived alongside security_flags and rootvnode.

3. **Do not spend further effort validating these offsets offline.** Validation requires kernel memory access. The offsets are either correct (exploit chain works once we get kernel R/W) or wrong (we discover this when the exploit chain fails). No offline analysis can resolve this.
