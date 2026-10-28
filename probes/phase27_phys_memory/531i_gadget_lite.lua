-- CRASH_CLASS: LOW
-- PROBE 531i: Minimal gadget search for r8/r9
-- Only aligned 4-byte patterns, full eboot

print("=== PROBE 531i: GADGET LITE ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb_size = rd(N(ib) + 0x110) or 0
if eb_size < 0 then eb_size = eb_size + 0x100000000 end
print(string.format("eb=0x%X%08X+0x%X", eb_hi, eb_lo, eb_size))

local ebn = eb_hi * 0x100000000 + eb_lo
local scan = math.min(eb_size, 0x494000)

-- Targets (LE dword values)
-- 49 89 C0 C3 = mov r8, rax; ret → 0xC3C08949
-- 49 89 C1 C3 = mov r9, rcx; ret → 0xC3C18949
-- 49 89 D0 C3 = mov r8, rdx; ret → 0xC3D08949
-- 49 89 F0 C3 = mov r8, rsi; ret → 0xC3F08949
-- 49 87 C0 C3 = xchg r8, rax; ret → 0xC3C08749

local t = {}
t[0xC3C08949] = "mov_r8_rax"
t[0xC3C18949] = "mov_r9_rcx"
t[0xC3D08949] = "mov_r8_rdx"
t[0xC3F08949] = "mov_r8_rsi"
t[0xC3C08749] = "xchg_r8_rax"
t[0xC3D18949] = "mov_r9_rdx"
t[0xC3F18949] = "mov_r9_rsi"
t[0xC3F88949] = "mov_r8_rdi"

local hits = {}
for off = 0, scan - 4, 4 do
    local d = rd(ebn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        local name = t[d]
        if name then
            if not hits[name] then hits[name] = {} end
            table.insert(hits[name], off)
        end
    end
end

for name, offsets in pairs(hits) do
    print(string.format("  %s: %d hits, first=+0x%X", name, #offsets, offsets[1]))
end

-- Count total
local total = 0
for _, v in pairs(hits) do total = total + #v end
print(string.format("total: %d", total))

-- If none found, we need another approach entirely
if total == 0 then
    print("NO r8/r9 gadgets found (aligned)")
    print("Alternative: use syscall from ROP chain")
    print("FreeBSD syscall ABI: rax=num, rdi..r9=args")
    print("syscall instruction: rcx clobbered, use r10 for 4th arg")
    print("In child ROP, we control the stack fully")
    print("So: use 'syscall; ret' gadget + manual arg setup")
    print("For MapDM: it's a LIBRARY call not a syscall")
    print("Need to find the underlying syscall number")
end

print("")
print("=== 531i DONE ===")
