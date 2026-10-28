-- CRASH_CLASS: LOW
-- PROBE 548a: eboot gadgets for the fourth and fifth syscall arguments
--
-- Context: the raw-child chain calls syscalls through the loader stub with
-- RDI, RSI, RDX and RAX. aio_multi_wait (663) and the aio delete take a fourth
-- and fifth argument, so the chain needs `pop r10` (the FreeBSD syscall ABI's
-- fourth argument register) and `pop r8`.
--
-- This probe scans eboot's readable .text only, inside the size that 593
-- reports, for pop r10, pop r8 and pop rcx epilogues. It reads nothing else.

print("=== PROBE 548a: EBOOT POP GADGETS ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local lo = rd(N(ib) + 0x108) or 0
local hi = rd(N(ib) + 0x10C) or 0
local size = rd(N(ib) + 0x110) or 0
if lo < 0 then lo = lo + 0x100000000 end
if hi < 0 then hi = hi + 0x100000000 end
print(string.format("[A] eboot=%08X%08X size=%X", hi, lo, size))

local pats = {
    { name = "pop r10; ret", bytes = { 0x41, 0x5A, 0xC3 } },
    { name = "pop r10; pop r11; ret", bytes = { 0x41, 0x5A, 0x41, 0x5B, 0xC3 } },
    { name = "pop r8; ret", bytes = { 0x41, 0x58, 0xC3 } },
    { name = "pop rcx; ret", bytes = { 0x59, 0xC3 } },
    { name = "pop r9; ret", bytes = { 0x41, 0x59, 0xC3 } },
}
local found = {}
for i = 1, #pats do found[i] = {} end

local CHUNK = 0x8000
local a = lo
while a < lo + size do
    local n = CHUNK
    if a + n > lo + size then n = lo + size - a end
    local ok, buf = pcall(function() return memory.read_buffer(a, n) end)
    if ok and buf then
        for p = 1, #pats do
            local b = pats[p].bytes
            local first = string.char(b[1])
            local pos = 1
            while #found[p] < 8 do
                local s = string.find(buf, first, pos, true)
                if not s then break end
                local match = true
                for k = 2, #b do
                    if buf:byte(s + k - 1) ~= b[k] then match = false; break end
                end
                if match then found[p][#found[p] + 1] = a + s - 1 end
                pos = s + 1
            end
        end
    end
    a = a + n
end

for p = 1, #pats do
    local line = string.format("[B] %-24s", pats[p].name)
    if #found[p] == 0 then line = line .. " none"
    else for k = 1, #found[p] do line = line .. string.format(" %08X", found[p][k] - lo) end end
    print(line)
end
print("=== DONE ===")
