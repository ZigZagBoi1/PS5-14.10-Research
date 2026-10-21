-- CRASH_CLASS: MODERATE
-- PROBE 244a: one waiter, two waiters, then count the remaining thread slots
--
-- Context: 243a spawned ten waiters at once and its result page read back as
-- zero both before and after 544 set the bit, which is not what 200a measured
-- for a single waiter (page stayed 0xDEADBEEF until the set, then 1). Either ten
-- waiters on one flag behave differently, or the page read itself failed and the
-- probe printed the same 0 it prints for nil. 243a also died at its thirteenth
-- parker, leaving twenty-two children where 242a allowed twenty-five.
--
-- So this probe does it one step at a time, with the read error visible:
--
--   A  one waiter blocked on bit 1, page must stay 0xDEADBEEF
--   B  a second waiter on the same flag, page must still stay 0xDEADBEEF
--   C  544(H,1) completes both, page must change
--   D  spawn parkers until thr_create stops returning, and report the count
--
-- C reaching a non-zero page with two waiters afloat fixes 243a's read. D gives
-- the live-thread budget with waiters present instead of empty.

print("=== PROBE 244a: waiters one at a time, then the slot count ===")
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
    if v == nil then return "read-failed" end
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok and val ~= nil then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val ~= nil then return val end
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

local function spawn(args)
    local stack = map(0x4000)
    local ctx = map(0x1000)
    for i = 0, 8 do wq(stack + 0x3000 + i * 8, jmp_self) end
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, args.rip or SW)
    wq(ctx + C_RSP, stack + 0x3000)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, uint64(args.num or 0))
    wq(ctx + C_RDI, uint64(args.a or 0))
    wq(ctx + C_RSI, uint64(args.b or 0))
    wq(ctx + C_RDX, uint64(args.c or 0))
    wq(ctx + C_RCX, args.d or uint64(0))
    wq(ctx + C_R8, uint64(args.e or 0))
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    if not ok then return nil, nil, false end
    return rq(id_buf), rv, true
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, uint64(string.format("0x%02X", s:byte(i)))) end)
    end
    pcall(function() memory.write_byte(addr + #s, uint64(0)) end)
end
put_str(NAME, "evf_244a")
local H = nil
local okh, hv = pcall(function() return sc_create(uint64(NAME), uint64(0), uint64(0)):tonumber() end)
if okh then H = hv end
print("    538(name, 0, 0) -> " .. tostring(H) .. " (" .. q(H) .. ")")

local OUT = map(0x4000)
local OUT2 = map(0x4000)
wd(OUT, 0xDEADBEEF)
wd(OUT2, 0xDEADBEEF)

print("")
print("[A] one waiter on bit 1")
local tid1, rv1 = spawn({ num = 542, a = H, b = 1, c = 1, d = OUT, e = 0 })
print("    tid=" .. q(tid1) .. " ret=" .. q(rv1) .. " page=" .. q(rd(OUT)))
local x = 0
for k = 1, 200000 do x = x + k end
print("    page after delay=" .. q(rd(OUT)) .. " pid=" .. tostring(pid()))

print("")
print("[B] second waiter on the same flag")
local tid2, rv2 = spawn({ num = 542, a = H, b = 1, c = 1, d = OUT2, e = 0 })
print("    tid=" .. q(tid2) .. " ret=" .. q(rv2) .. " page1=" .. q(rd(OUT)) .. " page2=" .. q(rd(OUT2)))
x = 0
for k = 1, 200000 do x = x + k end
print("    page1=" .. q(rd(OUT)) .. " page2=" .. q(rd(OUT2)))

print("")
print("[C] complete both")
local oks, sv = pcall(function() return sc_set(uint64(H), uint64(1)) end)
print("    544(H,1) ret=" .. (oks and tostring(to_num(sv)) or "killed"))
x = 0
for k = 1, 400000 do x = x + k end
print("    page1=" .. q(rd(OUT)) .. " page2=" .. q(rd(OUT2)) .. " pid=" .. tostring(pid()))

print("")
print("[D] parkers until thr_create stops returning")
local last = 0
for i = 1, 30 do
    local tid, rv, alive = spawn({ rip = jmp_self })
    if not alive then
        print(string.format("    #%d thr_create killed the process", i))
        break
    end
    print(string.format("    #%d tid=%s ret=%s pid=%s", i, q(tid), q(rv), tostring(pid())))
    if tid == nil or to_num(tid) == 0 or (rv ~= nil and to_num(rv) ~= 0) then
        print("    stopped at #" .. i)
        break
    end
    last = i
end
print("")
print("[E] summary: waiters=2 parkers=" .. last .. " children=" .. (2 + last))
pcall(function() sc_delete(uint64(H)) end)
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 244a COMPLETE ===")
