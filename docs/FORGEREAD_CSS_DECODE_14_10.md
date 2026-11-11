# forgeRead CSS Escape Decode — Analysis & Fix

## The Bug

p692's `forgeRead()` returns the raw CSS-serialized `face.style` string.
The caller decodes it with:

```js
for (var i = 0; i < raw.length; i++) rawBytes.push(raw.charCodeAt(i));
```

This is **wrong**. CSS serialization escapes non-printable bytes (< 0x20)
as `\HH ` (backslash + hex digits + trailing space delimiter). A byte
sequence like `0xB0 0xDA 0x0D 0x08 0x00 0x00 0x00` becomes the CSS string
`°Ú\d \8 \0 \0 \0 `, which is 21 characters but only 7 bytes of data.

The `charCodeAt` loop produces 21 values (the ASCII codes of `°`, `Ú`, `\`,
`d`, ` `, `\`, `8`, ` `, ...) instead of the 7 intended byte values.

This is why `raw4len=175` but `h4len=144`: the 72-byte vtable region
(9 × 8-byte slots) serialized to 175 CSS characters because ~50 of the 72
bytes are below 0x20 and each escape takes 2-4 characters.

## The Evidence

From the p691 beacon log (2026-11-09 23:54:29):

```
raw4="°Ú\d \8 \0 \0 \0 àÚ\d \8 \0 \0 \0 P×&\c \8 \0 \0 \0 °Ú\d ..."
h4=b08fda0d08000000e08fda0d0800000050d7260c08000000b096da0d08000000...
```

The `h4` hex is correct: `b0 8f da 0d 08 00 00 00` = pointer `0x080dda8fb0`
(little-endian). The p691 code had a working CSS escape parser; p692 lost it
because the p691 source was never persisted to disk.

## CSS Escape Encoding Rules (CSSOMUtils.cpp)

WebKit's `serializeFontFamily()` / `cssTextForFontFamily()` delegates to
CSS value serialization which applies these rules to raw bytes:

1. Bytes `0x01-0x1F` and `0x7F` → `\HH ` (hex + space)
2. Byte `0x00` → `\0 ` (special case, just `\0` + space)
3. Bytes `0x20-0x7E` (printable ASCII) → literal, except:
   - `-` at start of identifier → `\-`
   - Digits at start of identifier → `\3N ` (hex)
   - `"` `'` `\` → always escaped
4. Bytes `0x80-0xFF` → passed through as Latin-1 codepoints (one char each)
5. Multi-byte UTF-8 → decoded to Unicode codepoints, then literal or `\HHHHHH`

For pointer data (mostly small bytes from addresses like `0x080dda8fb0`),
most bytes are 0x00 or 0x08 or 0x0d, so nearly every byte gets escaped.

## The Fix — CSS Escape Parser

```js
function decodeCssStyleBytes(raw) {
    var bytes = [];
    var i = 0;
    while (i < raw.length) {
        if (raw.charAt(i) === '\\') {
            i++; // skip backslash
            var hex = '';
            while (i < raw.length && hex.length < 6 && /[0-9a-fA-F]/.test(raw.charAt(i))) {
                hex += raw.charAt(i);
                i++;
            }
            if (hex.length > 0) {
                bytes.push(parseInt(hex, 16) & 0xFF);
                // CSS spec: optional single space delimiter after hex escape
                if (i < raw.length && raw.charAt(i) === ' ') i++;
            } else {
                // \<non-hex> → literal next character
                if (i < raw.length) {
                    bytes.push(raw.charCodeAt(i) & 0xFF);
                    i++;
                }
            }
        } else {
            bytes.push(raw.charCodeAt(i) & 0xFF);
            i++;
        }
    }
    return bytes;
}
```

This correctly handles all three cases:
- `\d ` → byte 0x0D (hex `d`, space consumed)
- `\0 ` → byte 0x00
- `°`   → byte 0xB0 (literal, charCodeAt gives 176 = 0xB0)

## Impact

Without this fix, **no forgeRead-based probe can produce valid byte arrays**.
The walk chain's hex encoding (`h4` field in p691) worked because p691 had
the correct parser inline. Every p692 read operation (ELF header scan,
vtable slot extraction) is operating on garbled data.

## What p691 Got Right

The p691 beacon shows correct hex decoding in the `h4` / `VT` fields:
```
VT=b08fda0d08000000e08fda0d0800000050d7260c08000000...
```
These are 9 vtable slots (72 bytes) correctly decoded from the 175-character
CSS string. The VP value 0x80f4b9b28 at slot[0] was extracted from this.

The p691 source HTML was served from memory during the session and never
saved to disk (serve.py does not have a p691 route). This must be
reconstructed or p692 must be fixed with the CSS parser above.
