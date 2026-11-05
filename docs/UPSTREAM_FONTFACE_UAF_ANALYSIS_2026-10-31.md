# WebKit FontFace UAF — Upstream Analysis (2026-10-31)

## Executive Summary

All three FontFace UAF fixes (bugs 312202, 313577, 322233) were committed in **2026** — approximately 3 years AFTER the WebKit-605.1.15 / Safari 17.0 branch point (September 2023). **The FontFace UAF vulnerability is confirmed STILL VULNERABLE on PS5 14.10.**

## WebKit-605.1.15 Environment

- **Target:** PS5 firmware 14.10
- **Browser:** PlayStation 5/14.10 guide browser
- **WebKit:** 605.1.15 / Safari 17.0
- **Confirmed via:** p573 (2026-10-31)

## Vulnerability Timeline

| Bug | Description | Fix Date | Fix Commit | Branch |
|-----|-------------|----------|------------|--------|
| 312202 | Use-after-free in CSSFontFace::setStatus and CSSFontFace::pump | 2026-05-25 | 5f0480f771ba | safari-7624-branch (305413.664) |
| 313577 | Use-after-free in CSSFontFace::setStatus via CSSFontFace::load | 2026-07-03 | 5aedb82710ba | main (originally 305413.775@safari-7624-branch) |
| 322233 | CSSFontFace::setStatus should commit m_status before notifying clients | 2026-08-20 | 64a55fd574c4 | main |

## Vulnerability Details

### Bug 312202 — CSSFontFace UAF via std::reference_wrapper

**Root Cause:** `CSSFontFaceSet::matchingFacesExcludingPreinstalledFonts` returns `Vector<std::reference_wrapper<CSSFontFace>>`, which is a raw pointer wrapper. When the CSS @font-face rule is deleted (e.g., via a thenable getter during FontFaceSet::load), the CSSFontFace is freed, but the reference_wrapper still holds a dangling pointer.

**Vulnerable Code (pre-fix):**
```cpp
// CSSFontFaceSet.cpp
ExceptionOr<Vector<std::reference_wrapper<CSSFontFace>>>
CSSFontFaceSet::matchingFacesExcludingPreinstalledFonts(...)

// FontFaceSet.cpp
auto matchingFaces = m_backing->matchingFacesExcludingPreinstalledFonts(...);
for (auto& face : matchingFaces)
    face.get().load();  // face.get() returns dangling ref after CSS rule deleted
```

**Fix:** Changed return type to `Vector<Ref<CSSFontFace>>`. `Ref` is a smart pointer that keeps the object alive.
```cpp
// Post-fix
ExceptionOr<Vector<Ref<CSSFontFace>>>
CSSFontFaceSet::matchingFacesExcludingPreinstalledFonts(...)

// FontFaceSet.cpp
for (Ref face : matchingFaces)
    face->load();  // face stays alive even if CSS rule deleted
```

### Bug 313577 — FontFace::load UAF + iterateClients safety

**Root Cause:** When `FontFace::loadForBindings` triggers a thenable check (via `FontFace.prototype.then` getter), the getter can delete the CSS @font-face rule, freeing the CSSFontFace. The `FontFaceSet::load` loop still holds a reference to the freed object.

**Fix (two parts):**
1. Deployed smart pointer in `FontFace::loadForBindings`
2. Added `clients.contains(client)` check in `iterateClients`:
```cpp
// Post-fix (commit 5aedb82710ba)
static void iterateClients(WeakHashSet<CSSFontFaceClient>& clients, ...) {
    for (auto& client : copyToVectorOf<Ref<CSSFontFaceClient>>(clients)) {
        if (clients.contains(client))  // NEW: check still alive
            callback(client);
    }
}
```

### Bug 322233 — m_status reentrancy

**Root Cause:** `CSSFontFace::setStatus` notifies clients BEFORE committing `m_status`. If a client re-enters `setStatus`, the old `m_status` value is still visible, causing incorrect state transitions.

**Vulnerable Code (pre-fix):**
```cpp
void CSSFontFace::setStatus(Status newStatus) {
    // ...
    iterateClients(m_clients, [&](CSSFontFaceClient& client) {
        client.fontStateChanged(*this, m_status, newStatus);  // m_status still old!
    });
    m_status = newStatus;  // committed AFTER notify — race window
}
```

**Fix:** Commit `m_status` BEFORE notifying clients:
```cpp
// Post-fix (commit 64a55fd574c4)
void CSSFontFace::setStatus(Status newStatus) {
    // ...
    auto oldStatus = std::exchange(m_status, newStatus);  // commit FIRST
    iterateClients(m_clients, [&](CSSFontFaceClient& client) {
        client.fontStateChanged(*this, oldStatus, newStatus);  // oldStatus captured
    });
    // m_status = newStatus;  // REMOVED — already committed above
}
```

## Impact on PS5 14.10

**ALL THREE FIXES ABSENT from WebKit-605.1.15.**

The vulnerable pattern is confirmed present:
- `matchingFacesExcludingPreinstalledFonts` returns `Vector<std::reference_wrapper<CSSFontFace>>` (raw pointer)
- `CSSFontFace::setStatus` commits `m_status` AFTER notifying clients
- No `clients.contains(client)` check in `iterateClients`

**Exploit viability: CONFIRMED.** The FontFace UAF exploit chain (p563 leak → p571 forge → p575 combined) is still viable on PS5 14.10.

## Evidence from PS5 14.10

| Probe | Result | Relevance |
|-------|--------|-----------|
| p563 | FontFaceSet::load() UAF: 192B reclaim with +0x58/+0x68 heap pointers | Confirms UAF trigger |
| p564 | FontFace self-referential template: S1-HIT, S2-RESOLVED, S2-ALIVE-1 | Confirms engine accepts UAF |
| p571 | All 4 forge values (self, cross, null, bad) → RESOLVED + ALIVE-1 | Confirms vtable forge accepted |
| p572 | S1-RESOLVED + S1-CLEAN | Confirms no non-zero bytes in forged region |
| p553 | Canvas getContext reentrancy UAF: bidirectional R/W confirmed | Confirms write primitive |
| p573 | WebKit 605.1.15 / Safari 17.0 confirmed | Confirms version |

## Next Steps

1. **Run p574 on PS5 14.10** — FontFace vtable forge behavior analysis
2. **Run p575 on PS5 14.10** — Combined FontFace leak + Canvas write primitive
3. **Forge stateStack** — Use leaked FontFace pointer to forge Canvas stateStack
4. **Kernel pointer search** — Scan WebProcess heap for kernel pointers

## References

- WebKit Bug 312202: https://bugs.webkit.org/show_bug.cgi?id=312202
- WebKit Bug 313577: https://bugs.webkit.org/show_bug.cgi?id=313577
- WebKit Bug 322233: https://bugs.webkit.org/show_bug.cgi?id=322233
- Fix commit 312202: https://github.com/WebKit/WebKit/commit/5f0480f771ba
- Fix commit 313577: https://github.com/WebKit/WebKit/commit/5aedb82710ba
- Fix commit 322233: https://github.com/WebKit/WebKit/commit/64a55fd574c4
