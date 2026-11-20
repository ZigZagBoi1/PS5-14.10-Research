# 14.00 WeakHashSet layout and the FontFace `iterateClients` plant

Firmware: 14.00 (Sony-published WebKit source drop, Release/NDEBUG)
Date: 2026-11-17 (captures), 2026-11-18 (write-up)
Capture: results/p659_fw1400_weakhashset_decode_20261117.txt
Related: docs/FONTFACE_ITERATECLIENTS_14_10.md (14.10, checking build)

## Grades

| Claim | Grade | Detail |
|---|---|---|
| 14.00 drop is Release/NDEBUG | [S] | Sony source; no `CHECK_HASHTABLE_ITERATORS`, no assert-only bools |
| live `m_clients` header is `{dc=0,key=3,mask=7,size=8}` | [M] | `W1-RAW` in UIDs VE77NB and DWE4LW |
| bucket value is `WeakPtrImpl*`; W2 resolves client via `impl+0x08` | [M] | `W1-IM`, `W2-*`, `FPTR-*` in VE77NB |
| 14.10 checking-build `m_ptr` placement does not apply here | [I] | source-derived; the 14.00 live chain fits `+0x08` |
| direct-client plant dies at dispatch | [M] outcome, [I] mechanism | VE77NB `LAY-OK` + `RIP2-GO`, no `RIP2-AFTER` |
| two-layer plant survives dispatch | [M] | DWE4LW `LAYFIX` + `RIP2-AFTER`; 16 `R2-RIP2-AFTER` in log |
| absolute `m_clients`/`m_wrapper` offsets | [I] | hand-math only; verification probe still needed |

## Build difference

The 14.10 analysis in `docs/FONTFACE_ITERATECLIENTS_14_10.md` is for a checking
build: it calls out assert-dependent fields and an `ASSERT_ENABLED` bool. The
14.00 Sony drop is Release/NDEBUG. In that configuration `WeakPtrImpl` is
vptr (8) + refcount (4) + `m_ptr` at **+0x08**; the assert-only field that
shifts `m_ptr` in checking builds is absent.

The bucket type is unchanged: `WeakHashSet<Client>::m_set` is a
`HashSet<Ref<WeakPtrImpl>>`, so a bucket holds a `WeakPtrImpl*`. Iteration
therefore follows two layers:

```
bucket[0] -> WeakPtrImpl*
WeakPtrImpl::m_ptr (+0x08) -> Client*
Client vtable (+0x00) -> fontStateChanged/fontPropertyChanged slots
```

## Live decode (14.00)

UID `VE77NB`, `W1-RAW` hex (little-endian u32s):

```
00000000 03000000 07000000 08000000 00000000
deleted=0 keyCount=3 tableSizeMask=7 tableSize=8 bucket[0]=0
```

This matches `HashTable.h:586-588`: metadata lives in the bucket array, 16 B
before the first bucket. In the same run:

- `W1-IM-0x10007eae00` — bucket value, a `WeakPtrImpl*`.
- `W2-UPD` / `W2-PRE-RD` / `W2-POST-RD` — follow the impl.
- `FPTR-0x10003e70c8` — resolved client, i.e. read from `impl+0x08`.

Grade [M] for the beacon chain. The field-name mapping is [S] from
`WeakHashSet.h:203-205`, `WeakPtr.h:47-75`, and `HashTable.h:586-588`.

## Why the direct-client plant dies

The same `VE77NB` run then planted `LAY-OK-cli=SKIPJ+88,bk=0,kc=0`, putting
the **client object itself** where the walk expects a `WeakPtrImpl*`. The run
emitted `RIP2-GO-cli0x10007eae00` but no `RIP2-AFTER`.

Under the decoded chain, W2 reads `client+0x08` as `WeakPtrImpl::m_ptr`. In
that plant the bytes at `client+0x08` are the planted refcount region, not a
client pointer, so the callback dispatches through a bogus `this`. The beacon
sequence is measured; this causal step is [I].

This is the cross-firmware trap: the 14.10 plant assumed the bucket value was
the client. On 14.00 that omits one indirection layer.

## Corrected plant shape

UID `DWE4LW` used the two-layer form and reached `RIP2-AFTER`:

```
sk+0x08          16 vtable slots (slots 6/7 = real ref/deref leaked from VP)
sk+0x88          CLIENT: vptr -> sk+0x08
sk+0xA0          FAKE WeakPtrImpl: vptr, refcount >= 1, m_ptr(+0x08) -> sk+0x88
bucket[0]        -> sk+0xA0
table metadata   -> deleted=0, keyCount=1, mask=7, size=8 at m_table-16..-4
```

This is a fix direction validated for survival, not a claim that every face
field offset is final.

## What is still open

- Absolute `m_clients` start (`self+0x50` vs `self+0x58`, and any wrapper
  indirection) remains [I]. Verification: forgeRead `self+0x50` (48 B) and
  `self+0x58` (48 B); if a candidate table pointer is heap-shaped, read
  `table-16` (16 B) and expect `{8,7,>=1,0}`.
- Bench VP page-offset mode `0x8A0` is still unanchored; `0xBE0` is the same
  vtable read `+0xB8` and should be normalized before comparing with #299.
- No 14.10 checking-build offsets are reused here.
