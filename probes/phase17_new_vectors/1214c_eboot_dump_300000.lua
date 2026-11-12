-- CRASH_CLASS: LOW
-- PROBE 1214c: dump eboot .text [0x300000, +0x194000) as hex, one line per 0x1000.
-- eboot .text is RX and readable (docs/EXEC_ONLY_LIBKERNEL_14_10.md); this completes the
-- 4.6 MB image so that r10 shims and syscall sites can be disassembled offline.
print("=== PROBE 1214c: eboot dump ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local eb = N(eboot_base)
local OFF, SIZE, CH = 0x300000, 0x194000, 0x1000
print(string.format("[0] eboot=0x%X off=0x%X size=0x%X", eb, OFF, SIZE))
local done = 0
while done < SIZE do
    local want = math.min(CH, SIZE - done)
    local ok, buf = pcall(function() return memory.read_buffer(eb + OFF + done, want) end)
    if not ok then print(string.format("[!] read failed at +0x%X", done)) break end
    local hex = buf:gsub(".", function(c) return string.format("%02X", string.byte(c)) end)
    print(string.format("[D] off=0x%X len=0x%X %s", OFF + done, want, hex))
    done = done + want
end
print("=== DONE ===")
