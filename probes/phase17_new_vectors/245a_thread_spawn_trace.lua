-- CRASH_CLASS: LOW
-- PROBE 245a: where the thread spawn actually stops
--
-- Context: two measurements disagree. 242a spawned 25 parkers on a fresh
-- process and the 26th blocked inside thr_create. 244a spawned two waiters and
-- nine parkers and the tenth parker blocked. Either the budget depends on what
-- the threads are doing, or the block is not thr_create at all - a failing
-- mmap would leave the context page unwritten and thr_create would be handed a
-- garbage context.
--
-- This probe removes every unknown from the loop. For each attempt it prints
-- the two mmap return values, the tid, thr_create's return value, and the pid,
-- then stops at the first non-zero return instead of pressing on.
--
--   25 attempts, parkers only, full trace
--   a failing map shows as its own value before the spawn, so the trace says
--   whether the budget is thread slots or mappings

print("=== PROBE 245a: thread spawn trace ===")
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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)

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
print("[0] jmp$=" .. q(jmp_self) .. " bytes=" .. q(rd(jmp_self)))

local function map(n)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(n), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    return v
end

print("")
print("[A] attempt loop")
local last_ok = 0
for i = 1, 25 do
    local stack = map(0x4000)
    local ctx = map(0x1000)
    if stack == nil or ctx == nil then
        print(string.format("    #%d mmap raised: stack=%s ctx=%s", i, q(stack), q(ctx)))
        break
    end
    local sn, cn = to_num(stack), to_num(ctx)
    if sn < 0 then sn = sn + 18446744073709551616 end
    if cn < 0 then cn = cn + 18446744073709551616 end
    if sn == 0 or cn == 0 or sn == cn then
        print(string.format("    #%d bad mmap: stack=%s ctx=%s  (pid=%s)", i, q(stack), q(ctx), tostring(pid())))
        break
    end
    for k = 0, 8 do wq(stack + 0x3000 + k * 8, jmp_self) end
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
    if not ok then
        print(string.format("    #%d thr_create raised", i))
        break
    end
    local tid = nil
    local okr, tv = pcall(function() return memory.read_qword(id_buf) end)
    if okr and tv ~= nil then tid = tv end
    print(string.format("    #%d stack=%s ctx=%s tid=%s ret=%s pid=%s",
        i, q(stack), q(ctx), q(tid), q(rv), tostring(pid())))
    local rvn = to_num(rv)
    if rvn ~= 0 or tid == nil or to_num(tid) == 0 then
        print("    stopped at #" .. i)
        break
    end
    last_ok = i
end
print("")
print("[B] spawned=" .. last_ok .. "  pid -> " .. tostring(pid()))
print("")
print("=== PROBE 245a COMPLETE ===")
