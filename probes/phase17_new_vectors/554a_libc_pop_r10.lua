-- CRASH_CLASS: LOW
-- PROBE 554a: does a readable module carry `pop r10` / `syscall; ret`?
--
-- Context: 552a and 553a show the raw-child chain cannot deliver a fourth
-- syscall argument (mmap with MAP_ANON in RCX created no region, while a umtx
-- lock in the same chain worked). The fourth argument lives in R10 and eboot
-- has no `pop r10`. libc.prx and libSceFios2.prx are readable+exec, so their
-- epilogues can be scanned from userland.

print("=== PROBE 554a: POP R10 IN READABLE MODULES ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function h(v) if v < 0 then v = v + 0x100000000 end return v end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc674 = mk(674)
local rbuf = memory.alloc(72 * 500)
local countp = memory.alloc(8)
for i = 0, 72 * 500 - 4, 4 do wd(N(rbuf) + i, 0) end
wd(N(countp), 0)
pcall(function() sc674(uint64(N(rbuf)), uint64(72), uint64(500), uint64(N(countp)), uint64(0x40000000)) end)
local count = rd(N(countp)) or 0
print("[A] regions=" .. count)

local targets = {}
for i = 0, count - 1 do
    local r = N(rbuf) + i * 72
    local name = ""
    for k = 0, 20 do
        local c = (rd(r + 0x20 + k) or 0) % 256
        if c == 0 then break end
        if c >= 32 and c < 127 then name = name .. string.char(c) end
    end
    local loom = h(rd(r) or 0)
    local him = h(rd(r + 4) or 0)
    local lo = him * 4294967296 + loom
    local endm = h(rd(r + 8) or 0)
    local endh = h(rd(r + 12) or 0)
    local en = endh * 4294967296 + endm
    local prot = rd(r + 0x18) or 0
    if prot % 8 >= 4 and (en - lo) > 0x1000 and (en - lo) < 0x400000 then
        targets[#targets + 1] = { name = name, lo = lo, size = en - lo, prot = prot }
    end
end
print(string.format("[B] scannable exec regions=%d", #targets))

local pats = {
    { {0x41,0x5A,0xC3}, "pop r10;ret" },
    { {0x41,0x58,0xC3}, "pop r8;ret" },
    { {0x41,0x59,0xC3}, "pop r9;ret" },
    { {0x0F,0x05,0xC3}, "syscall;ret" },
    { {0x49,0x89,0xCA,0x0F}, "mov r10,rcx..." },
}

local function byte_of(v, k)
    if k == 0 then return v % 256 end
    if k == 1 then return math.floor(v / 256) % 256 end
    if k == 2 then return math.floor(v / 65536) % 256 end
    return math.floor(v / 16777216) % 256
end

for t = 1, #targets do
    local tg = targets[t]
    local hits = {}
    local total = 0
    local step = 4
    local prev = nil
    local base = tg.lo
    local n = math.floor(tg.size / step) - 2
    for i = 0, n do
        local a = base + i * step
        local v0 = rd(a)
        local v1 = rd(a + 4)
        if v0 == nil or v1 == nil then break end
        for k = 0, 3 do
            for p = 1, #pats do
                local pat = pats[p][1]
                local okp = true
                for j = 0, #pat - 1 do
                    local idx = k + j
                    local b
                    if idx < 4 then b = byte_of(v0, idx) else b = byte_of(v1, idx - 4) end
                    if b ~= pat[j + 1] then okp = false break end
                end
                if okp then
                    total = total + 1
                    if #hits < 6 then
                        hits[#hits + 1] = string.format("%s@%X", pats[p][2], a - base + k)
                    end
                end
            end
        end
    end
    print(string.format("[C] %-28s %08X size=%X prot=%d hits=%d %s",
        tg.name, tg.lo, tg.size, tg.prot, total, table.concat(hits, " ")))
end
print("[D] alive=" .. tostring(alive()))
print("=== DONE ===")
