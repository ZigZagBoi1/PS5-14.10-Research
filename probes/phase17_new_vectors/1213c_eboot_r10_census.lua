-- CRASH_CLASS: LOW
-- PROBE 1213c: byte-pattern census over the whole readable eboot .text (0x494000 bytes) for
--              the register shims that argument 4 needs.
--
-- Readable-text routes for "set r10 from rcx" were only ever searched in the first megabyte
-- (docs/SYSCALL_ARG4_R10_14_10.md 10.1). eboot .text is 0x494000 bytes and fully readable
-- (docs/EXEC_ONLY_LIBKERNEL_14_10.md), so the census is completed here with string.find in
-- plain mode: no per-byte Lua loop, no hex dump, only hits and 24 bytes of their tail.
--
-- For each hit the next 24 bytes are printed so the tail can be disassembled offline and a
-- "register-only until ret" shim can be picked.

print("=== PROBE 1213c: eboot .text census for r10 shims ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(a) local hi=math.floor(a/4294967296) return string.format("0x%08X%08X",hi,a-hi*4294967296) end
local eb = N(eboot_base)
local SIZE = 0x494000
local CH = 0x8000
print(string.format("[0] eboot=%s size=0x%X", hexn(eb), SIZE))

local pats = {
  { "mov r10,rcx",  string.char(0x49,0x89,0xca) },
  { "mov r10,rcx;ret", string.char(0x49,0x89,0xca,0xc3) },
  { "pop r10",      string.char(0x41,0x5a) },
  { "syscall",      string.char(0x0f,0x05) },
  { "mov r10,rdx",  string.char(0x49,0x89,0xd2) },
}
local hits = {}
for i = 1, #pats do hits[i] = 0 end

local function tail(buf, pos, n)
    local s = {}
    for k = 0, n - 1 do
        local b = string.byte(buf, pos + k)
        if not b then break end
        s[#s + 1] = string.format("%02X", b)
    end
    return table.concat(s, " ")
end

local off = 0
while off < SIZE do
    local want = math.min(CH, SIZE - off)
    local ok, buf = pcall(function() return memory.read_buffer(eb + off, want) end)
    if not ok then print(string.format("[!] read failed at +0x%X", off)) break end
    for pi = 1, #pats do
        local pat = pats[pi][2]
        local i = 1
        while true do
            local a, b = string.find(buf, pat, i, true)
            if not a then break end
            hits[pi] = hits[pi] + 1
            print(string.format("[%d] eboot+0x%X %s | %s", pi, off + (a - 1), pats[pi][1], tail(buf, a, 24)))
            i = b + 1
        end
    end
    off = off + want
end

for i = 1, #pats do print(string.format("[N] %s total=%d", pats[i][1], hits[i])) end
print("=== DONE ===")
