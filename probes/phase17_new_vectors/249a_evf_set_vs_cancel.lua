-- CRASH_CLASS: MODERATE
-- PROBE 249a: race 544 set against 546 cancel on a blocked waiter
--
-- Every event-flag measurement so far is sequential: block a waiter, then
-- complete it or cancel it and look at the result page. The lifecycle question
-- that a memory bug would live in is what happens when the two wake paths run
-- at the same time - `544 set` completing the sleep entry while `546 cancel`
-- removes it. A missing reference or a double completion here is the shape of
-- the bug the whole evf family was being searched for.
--
-- In each round the main thread sets the bit while a child calls `546` on the
-- same flag, with the waiter already blocked, so the two kernel paths overlap.
-- A child spawned with `RIP = syscall_address` parks on `jmp $` when its call
-- returns, so nothing runs wild.
--
--   three rounds, two children each: waiter, canceler; the main thread sets
--   after each round: the result page, the process, and the handle reuse
--
-- A page left at 0xDEADBEEF means neither path completed the waiter, which is
-- also worth knowing: the delete in the next round then wakes it.

print("=== PROBE 249a: set racing cancel ===")
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
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
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
local sc_cancel = make_syscall(546)
local sc_thr_create = make_syscall(430)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_RAX = 0x068, 0x078

local function pid()
    local ok, v = pcall(function() return sc_getpid() end)
    if ok then return to_num(v) end
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
    wq(ctx + C_R8, uint64(0))
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    if not ok then return nil, nil end
    return rq(id_buf), rv
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, uint64(string.format("0x%02X", s:byte(i)))) end)
    end
    pcall(function() memory.write_byte(addr + #s, uint64(0)) end)
end
local function create(name, init)
    put_str(NAME, name)
    local ok, h = pcall(function() return sc_create(uint64(NAME), uint64(init), uint64(0)) end)
    if ok then return to_num(h) end
    return nil
end
local function delay(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

local OUT = map(0x4000)
local rounds = 3
for r = 1, rounds do
    local H = create("evf_249a_" .. r, 0)
    wd(OUT, 0xDEADBEEF)
    print("")
    print("[R" .. r .. "] 538 -> " .. tostring(H) .. " (" .. q(H) .. ")  page=" .. q(rd(OUT)))
    if H == nil then
        print("    create failed; stopping")
        break
    end
    -- the waiter needs its result page: 249a's first run passed a null RCX and
    -- had nothing to observe even when the set returned 0
    local tw, rvw = spawn({ num = 542, a = H, b = 1, c = 1, d = OUT })
    delay(20000)
    print("    waiter up, page=" .. q(rd(OUT)))
    local tc, rvc = spawn({ num = 546, a = H, b = 1, c = 0 })
    -- main sets at the same time the canceler runs
    local oks, sv = pcall(function() return sc_set(uint64(H), uint64(1)) end)
    print("    waiter=" .. q(tw) .. " canceler=" .. q(tc) ..
        " set=" .. (oks and q(sv) or "raised"))
    delay(400000)
    print("    page=" .. q(rd(OUT)) .. "  pid=" .. tostring(pid()))
    local okd, dv = pcall(function() return sc_delete(uint64(H)) end)
    print("    delete=" .. (okd and q(dv) or "raised") .. "  page after delete=" .. q(rd(OUT)))
    local H2 = create("evf_249a_c" .. r, 0)
    print("    next create -> " .. q(H2))
    if H2 ~= nil then pcall(function() sc_delete(uint64(H2)) end) end
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 249a COMPLETE ===")
