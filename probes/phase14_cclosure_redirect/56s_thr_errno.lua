-- CRASH_CLASS: MODERATE
-- PROBE 56s: thr_create errno extraction + MAP_STACK + alternative layouts
--
-- Context: 56r confirmed thr_create returns -1 via both make_syscall and
-- fcall_with_rax. thr_self/thr_set_name work fine. Need errno to diagnose.
-- Strategy: read errno from TCB (FS base + offset), try MAP_STACK,
-- and try alternative argument layouts.

print("=== PROBE 56s: THR_CREATE ERRNO + FIXES ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Setup
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)

local ret_gadget = nil
if eboot_lo and eboot_hi then
    local ok_sc, scan_data = pcall(function()
        return native.read_buffer(uint64(string.format("0x%X%08X", eboot_hi, eboot_lo)), 4096)
    end)
    if ok_sc and scan_data then
        for i = 1, #scan_data do
            if scan_data:byte(i) == 0xC3 then
                ret_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                break
            end
        end
    end
end
print("ret_gadget=" .. fmt_addr(ret_gadget))

-- Get FS base for errno reading
local sc_sysarch = make_syscall(165)
local fsbase_buf = memory.alloc(16)
safe_wq(fsbase_buf, uint64(0))
pcall(function() sc_sysarch(uint64(128), uint64(to_num(fsbase_buf))) end)
local fsbase = safe_rq(fsbase_buf)
print("fsbase=" .. fmt_addr(fsbase))

local stub = syscall.pipe.fn_addr

-- ============================================================
-- TEST A: Read errno from TCB after a KNOWN failing syscall
-- FreeBSD TCB: struct tcb { void *tcb_self; void *tcb_dtv; int *tcb_errno; ... }
-- Or errno might be at a negative offset from fsbase
-- ============================================================
print("")
print("--- TEST A: ERRNO LOCATION DISCOVERY ---")

-- First, do a known-error syscall to set errno
-- open("/nonexistent", 0) should return -1 with errno=ENOENT(2)
local sc_open = make_syscall(5)
local path_buf = memory.alloc(64)
-- "/tmp/AAAA"
safe_wd(path_buf, 0x706D742F)  -- "/tmp"
safe_wd(path_buf + 4, 0x4141412F)  -- "/AAA"
safe_wd(path_buf + 8, 0x41)  -- "A\0"

local ok_open, ret_open = pcall(function()
    return sc_open(uint64(to_num(path_buf)), uint64(0), uint64(0))
end)
print("open(/tmp/AAAA): ret=" .. tostring(ret_open))

-- Now scan around fsbase for errno value
-- errno should be 2 (ENOENT) after this call
-- On FreeBSD, libc stores errno pointer at tcb+0x00 (tcb_self), tcb+0x08 (tcb_dtv),
-- tcb+0x10 might be errno pointer
-- But actually, libthr uses __error() which accesses thread-specific errno

local fs_h, fs_l = get_hi_lo(fsbase)
print("Scanning around FS base for errno value (looking for 0x2=ENOENT):")

-- Scan negative offsets (common on FreeBSD/PS5)
for off = -0x100, 0x100, 4 do
    local addr = uint64(string.format("0x%X%08X", fs_h, fs_l + off))
    local val = safe_rd(addr)
    if val == 2 then
        print(string.format("  FOUND errno=2 at fsbase%+d (0x%X)", off, off))
    end
end

-- ============================================================
-- TEST B: thr_create with MAP_STACK
-- ============================================================
print("")
print("--- TEST B: MAP_STACK ---")

local sc_mmap = make_syscall(477)
-- MAP_PRIVATE=0x0002, MAP_ANON=0x1000, MAP_STACK=0x0400
local ok_stk, stack_b = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1402), -- MAP_PRIVATE | MAP_ANON | MAP_STACK
        uint64(0xFFFFFFFF), uint64(0))
end)
local sb_h, sb_l = get_hi_lo(stack_b)
print(string.format("MAP_STACK: ok=%s addr=0x%X_%08X", tostring(ok_stk), sb_h, sb_l))

if ok_stk and sb_h ~= 0xFFFFFFFF then
    local uctx = memory.alloc(0x500)
    for i = 0, 0x4FF, 4 do safe_wd(uctx + i, 0) end
    local mc = to_num(uctx) + 0x10

    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc + 0xB0, rg_l)
    safe_wd(mc + 0xB4, rg_h)
    safe_wd(mc + 0xB8, 0x43)
    safe_wd(mc + 0xC0, 0x202)
    local sp_l = sb_l + 0x10000 - 0x100
    safe_wd(mc + 0xC8, sp_l)
    safe_wd(mc + 0xCC, sb_h)
    safe_wd(mc + 0xD0, 0x3B)
    safe_wd(mc + 0x48, sp_l)
    safe_wd(mc + 0x4C, sb_h)

    local tid_out = memory.alloc(16)
    safe_wq(tid_out, uint64(0))

    local ok_b, ret_b = pcall(function()
        return make_syscall(430)(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
    end)
    local tid_b = to_num(safe_rq(tid_out))
    print("thr_create: ret=" .. tostring(ret_b) .. " TID=" .. tid_b)

    -- Read errno
    -- (will use discovered offset from Test A if found)
end

-- ============================================================
-- TEST C: Try calling thr_new(455) instead of thr_create(430)
-- thr_new takes struct thr_param, NOT ucontext
-- ============================================================
print("")
print("--- TEST C: THR_NEW(455) VIA MAKE_SYSCALL ---")

-- struct thr_param {
--   void (*start_func)(void *);  // +0x00
--   void *arg;                    // +0x08
--   char *stack_base;             // +0x10
--   size_t stack_size;            // +0x18
--   char *tls_base;               // +0x20
--   size_t tls_size;              // +0x28
--   long *child_tid;              // +0x30
--   long *parent_tid;             // +0x38
--   int flags;                    // +0x40
--   struct rtprio *rtp;           // +0x48
--   void *spare[3];               // +0x50
-- };

-- Allocate thread stack for thr_new
local ok_stk2, stack_c = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local sc_h, sc_l = get_hi_lo(stack_c)

if ok_stk2 and sc_h ~= 0xFFFFFFFF and ret_gadget then
    local param = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(param + i, 0) end

    -- start_func = ret gadget (thread entry point)
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(param + 0x00, rg_l)
    safe_wd(param + 0x04, rg_h)

    -- arg = 0
    safe_wq(param + 0x08, uint64(0))

    -- stack_base
    safe_wd(param + 0x10, sc_l)
    safe_wd(param + 0x14, sc_h)

    -- stack_size = 0x10000
    safe_wd(param + 0x18, 0x10000)
    safe_wd(param + 0x1C, 0)

    -- tls_base = current FS base (copy from parent)
    safe_wd(param + 0x20, fs_l)
    safe_wd(param + 0x24, fs_h)

    -- tls_size = 0x1000
    safe_wd(param + 0x28, 0x1000)

    -- child_tid output
    local child_tid = memory.alloc(16)
    safe_wq(child_tid, uint64(0))
    safe_wd(param + 0x30, to_num(child_tid))
    safe_wd(param + 0x34, 0)

    -- parent_tid output
    local parent_tid = memory.alloc(16)
    safe_wq(parent_tid, uint64(0))
    safe_wd(param + 0x38, to_num(parent_tid))
    safe_wd(param + 0x3C, 0)

    -- flags = 0
    safe_wd(param + 0x40, 0)

    local sc_thr_new = make_syscall(455)
    local ok_c, ret_c = pcall(function()
        return sc_thr_new(uint64(to_num(param)), uint64(0x58))
    end)
    print("thr_new(455): ok=" .. tostring(ok_c) .. " ret=" .. tostring(ret_c))

    local c_tid = to_num(safe_rq(child_tid))
    local p_tid = to_num(safe_rq(parent_tid))
    print("  child_tid=" .. c_tid .. " parent_tid=" .. p_tid)

    if c_tid > 0 then
        local sc_thr_kill = make_syscall(433)
        local ok_k, ret_k = pcall(function()
            return sc_thr_kill(uint64(c_tid), uint64(0))
        end)
        print("  thr_kill(child): ret=" .. tostring(ret_k))
    end
else
    print("Stack alloc or ret gadget failed, skip")
end

-- ============================================================
-- TEST D: Check what OTHER errors look like (errno capture)
-- ============================================================
print("")
print("--- TEST D: KNOWN ERRNO PATTERNS ---")

-- Call pipe(42) via make_syscall — known to return -1
local sc_pipe = make_syscall(42)
local pipe_buf = memory.alloc(16)
local ok_p, ret_p = pcall(function()
    return sc_pipe(uint64(to_num(pipe_buf)))
end)
print("pipe(42): ret=" .. tostring(ret_p))

-- Call write to fd=-1 — should give EBADF(9)
local sc_write = make_syscall(4)
local wr_buf = memory.alloc(16)
safe_wd(wr_buf, 0x41414141)
local ok_w, ret_w = pcall(function()
    return sc_write(uint64(0xFFFFFFFF), uint64(to_num(wr_buf)), uint64(4))
end)
print("write(fd=-1): ret=" .. tostring(ret_w))

-- Call read from fd=-1 — should give EBADF(9)
local sc_read = make_syscall(3)
local ok_r, ret_r = pcall(function()
    return sc_read(uint64(0xFFFFFFFF), uint64(to_num(wr_buf)), uint64(4))
end)
print("read(fd=-1): ret=" .. tostring(ret_r))

-- Known success: getpid
print("getpid: ret=" .. tostring(syscall.getpid()))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56s COMPLETE ===")
