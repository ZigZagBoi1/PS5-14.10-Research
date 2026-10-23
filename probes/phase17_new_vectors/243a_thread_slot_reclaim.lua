-- CRASH_CLASS: MODERATE
-- PROBE 243a: does a completed wait free its thread slot?
--
-- Context: 242a spawned parked children one at a time and the process accepted
-- 25 of them; the 26th spawn never returned and wedged the Lua thread (socket
-- accepting, no output). So the process holds roughly twenty-five live child
-- threads and `thr_create` blocks past that - the "thread budget" is real, and
-- the earlier wedges in 202a/207a/208a were that budget, not a wild child.
--
-- What is not known is whether the slot comes back. A parked child never exits,
-- so capacity is fixed unless a thread whose wait has completed is destroyed by
-- the kernel. That decides how many waiters a race experiment can run in one
-- session, so it is worth one wedge.
--
--   A  spawn 10 children blocked in 542 on bit 1 of one flag
--   B  544(H,1) completes all ten, page must change
--   C  spawn up to 20 parkers afterwards and print how many succeed
--
-- C reaching 20 (30 spawns total)  -> a completed wait frees the thread slot
-- C stopping near 15               -> the slot is permanent and the budget is
--                                     spent by every waiter ever spawned

print("=== PROBE 243a: does a completed wait free its thread slot ===")
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
local sc_create = make_syscall(538)
local sc_delete = make_syscall(539)
local sc_set = make_syscall(544)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_RAX = 0x068, 0x078

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
local SW = syscall.syscall_address
print("[0] jmp$=" .. q(jmp_self) .. "  SW=" .. q(SW))

local function map(n)
    return sc_mmap(uint64(0), uint64(n), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end

local function spawn(ctx_args)
    local stack = map(0x4000)
    for i = 0, 8 do wq(stack + 0x3000 + i * 8, jmp_self) end
    local ctx = map(0x1000)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, ctx_args.total or SW)
    wq(ctx + C_RSP, stack + 0x3000)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, uint64(ctx_args.num or 0))
    wq(ctx + C_RDI, uint64(ctx_args.a or 0))
    wq(ctx + C_RSI, uint64(ctx_args.b or 0))
    wq(ctx + C_RDX, uint64(ctx_args.c or 0))
    wq(ctx + C_RCX, ctx_args.d or uint64(0))
    wq(ctx + C_R8, uint64(ctx_args.e or 0))
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    if not ok then return nil, nil, false end
    return rq(id_buf), rv, true
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    local a = to_num(addr)
    local len = #s + 1
    for i = 0, len - 1, 4 do
        local b0 = (i < #s) and s:byte(i + 1) or 0
        local b1 = (i + 1 < #s) and s:byte(i + 2) or 0
        local b2 = (i + 2 < #s) and s:byte(i + 3) or 0
        local b3 = (i + 3 < #s) and s:byte(i + 4) or 0
        wd(a + i, b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
put_str(NAME, "evf_243a")
local H = nil
local ok, hv = pcall(function() return sc_create(uint64(NAME), uint64(0), uint64(0)):tonumber() end)
if ok then H = hv end
local OUT = map(0x4000)
wd(OUT, 0xDEADBEEF)
print("")
print("[A] ten waiters on bit 1")
print("    538 -> " .. tostring(H) .. "  page=" .. q(rd(OUT)))
if H == nil then return end
local tids = {}
for i = 1, 10 do
    local tid, rv, alive = spawn({ num = 542, a = H, b = 1, c = 1, d = OUT, e = 0 })
    if not alive then
        print("    spawn #" .. i .. " killed the process")
        return
    end
    tids[#tids + 1] = tid
end
local x = 0
for k = 1, 60000 do x = x + k end
print("    spawned=" .. #tids .. "  page=" .. q(rd(OUT)) .. "  pid=" .. tostring(pid()))

print("")
print("[B] complete all ten")
local ok2, sv = pcall(function() return sc_set(uint64(H), uint64(1)) end)
print("    544(H,1) ret=" .. (ok2 and tostring(to_num(sv)) or "killed") .. "  page=" .. q(rd(OUT)))
x = 0
for k = 1, 60000 do x = x + k end
print("    page after completion=" .. q(rd(OUT)))

print("")
print("[C] spawn parkers on top")
local last = 0
for i = 1, 20 do
    local tid, rv, alive = spawn({})
    if not alive then
        print(string.format("    #%d thr_create killed the process", i))
        break
    end
    local rvn = rv and to_num(rv) or nil
    print(string.format("    #%d tid=%s ret=%s pid=%s", i, q(tid),
        rvn == nil and "nil" or tostring(rvn), tostring(pid())))
    if tid == nil or tid == 0 or (rvn ~= nil and rvn ~= 0) then break end
    last = i
end
print("")
print("[D] summary")
print("    waiters=10  parkers=" .. last .. "  total spawns=" .. (10 + last))
pcall(function() sc_delete(uint64(H)) end)
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 243a COMPLETE ===")
