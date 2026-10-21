-- CRASH_CLASS: LOW
-- PROBE 242a: how many parked child threads a process really holds
--
-- Context: 202a, 207a and 208a "wedged" after three or four children, and the
-- explanation recorded was a thread budget of roughly fifteen to nineteen, with
-- `thr_create` itself stopping to return. 241a shows that explanation may be
-- wrong: a child spawned with `RIP = syscall_address` resumes inside the
-- loader's wrapper when its call returns, with a zeroed stack, so it returns to
-- address zero and runs wild - and a wild thread inside the loader looks exactly
-- like a wedged loader from outside.
--
-- This probe removes that confound. Each child gets `RIP = jmp $` in eboot, so
-- it parks immediately and executes nothing else, and its own stack page is
-- filled with the same gadget. Only `thr_create` is exercised.
--
--   A  spawn parked children one at a time, printing the index, the tid and the
--      return value after each, up to 40
--   B  report where it stopped, and whether the process is still answering
--
-- Stops at 40 without failing  -> there is no small budget, and the earlier
--                                 wedges were the wild-child artefact
-- Stops near 15-19 with a failed -> the budget is real and this probe pins its
--                                 number

print("=== PROBE 242a: parked thread capacity ===")
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
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100

local function pid()
    local ok, v = pcall(function() return sc_getpid():tonumber() end)
    if ok then return v end
    return nil
end
print("[0] canary pid=" .. tostring(pid()))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
local jmp_self = eboot_base + 0x15481
print("[0] jmp$=" .. q(jmp_self) .. " first bytes=" .. q(rd(jmp_self)))

local function map(n)
    return sc_mmap(uint64(0), uint64(n), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end

local function spawn_parker()
    local stack = map(0x4000)
    for i = 0, 8 do wq(stack + 0x3000 + i * 8, jmp_self) end
    local ctx = map(0x1000)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, jmp_self)
    wq(ctx + C_RSP, stack + 0x3000)
    wd(ctx + C_SS, 0x3B)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    if not ok then return nil, nil, false end
    return rq(id_buf), rv, ok
end

print("")
print("[A] spawn parked children")
local last = 0
local tids = {}
for i = 1, 40 do
    local tid, rv, ok = spawn_parker()
    if not ok then
        print(string.format("    #%d  thr_create killed the process", i))
        return
    end
    local rvn = rv and to_num(rv) or nil
    print(string.format("    #%d  tid=%s  ret=%s  pid=%s", i, q(tid),
        rvn == nil and "nil" or tostring(rvn), tostring(pid())))
    if tid == nil or tid == 0 or (rvn ~= nil and rvn ~= 0) then
        print("    stopped at #" .. i)
        break
    end
    tids[#tids + 1] = tid
    last = i
end

print("")
print("[B] summary")
print("    spawned=" .. last)
local alive = 0
for i = 1, #tids do
    local ok, v = pcall(function() return sc_thr_kill(tids[i], uint64(0)):tonumber() end)
    if ok and to_num(v) == 0 then alive = alive + 1 end
end
print("    still alive=" .. alive)
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 242a COMPLETE ===")
