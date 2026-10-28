-- CRASH_CLASS: MODERATE
-- PROBE 272a: the shortest thr_create(430) that works, with RIP and RSP set
--
-- Context: a userland snippet found elsewhere populates the three validator
-- gates and CS/SS but never writes +0x0e0 (RIP) or +0x0f8 (RSP), and calls
-- memory.fill(), which the loader does not have. A zeroed RIP starts the child
-- at address 0 and panics the console.
--
-- This is the same recipe as 156c reduced to what a caller actually needs:
-- every field that must be present, nothing else. The child starts at an
-- eboot `jmp $` so an accepted thread cannot fault, and the result is read
-- back with thr_kill(tid, 0):
--
--   rv = 0, thr_kill = 0   -> the thread exists
--   rv = -1                -> a gate or a field is wrong

print("=== PROBE 272a: minimal thr_create(430) ===")
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
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_mmap = make_syscall(477)
local sc_info = make_syscall(593)
local sc_thr_self = make_syscall(432)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)

-- [1] main TID, so the new one can be told apart from it
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[1] main TID=" .. q(main_tid))

-- [2] eboot text base, from the module query on handle 0
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo or text_lo == 0 then
    print("[2] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[2] eboot text base=" .. q(eboot_base))

-- [3] a jmp $ in eboot: an entry point that cannot fault while it is observed
local spin = nil
local scanned = 0
while scanned < 0x100000 do
    local v = rd(eboot_base + scanned)
    if v then
        local b0 = v % 0x100
        local b1 = math.floor(v / 0x100) % 0x100
        local b2 = math.floor(v / 0x10000) % 0x100
        local b3 = math.floor(v / 0x1000000) % 0x100
        if b0 == 0xEB and b1 == 0xFE then spin = eboot_base + scanned end
        if b1 == 0xEB and b2 == 0xFE and not spin then spin = eboot_base + scanned + 1 end
        if b2 == 0xEB and b3 == 0xFE and not spin then spin = eboot_base + scanned + 2 end
        if spin then break end
    end
    scanned = scanned + 4
end
if not spin then
    print("[3] no EB FE found; aborting")
    return
end
if rb(spin) ~= 0xEB or rb(spin + 1) ~= 0xFE then
    print("[3] gadget verify failed; aborting")
    return
end
print("[3] entry (jmp $)=" .. q(spin))

-- [4] the child's stack: four pages, RX not needed, RW is enough
local stack_size = 4 * 0x4000
local ok_mm, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local sb_h, sb_l = 0, to_num(stack_base)
if type(stack_base) == "table" and stack_base.h then sb_h, sb_l = stack_base.h, stack_base.l end
if not ok_mm or (sb_h == 0 and sb_l == 0) then
    print("[4] stack mmap failed; aborting")
    return
end
local stack_base_u = uint64(string.format("0x%X%08X", sb_h, sb_l))
local stack_top = stack_base_u + stack_size - 0x100
print("[4] stack=" .. q(stack_base_u) .. " top=" .. q(stack_top))

-- [5] the context: every field the handler reads, and nothing else
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))   -- gate 1
wd(ctx + 0x0d0, 0)               -- gate 2
wq(ctx + 0x110, uint64(0x10000)) -- gate 3
wq(ctx + 0x0c0, uint64(0x43))    -- CS
wq(ctx + 0x0e0, spin)            -- RIP
wq(ctx + 0x0f8, stack_top)       -- RSP
wq(ctx + 0x100, uint64(0x3b))    -- SS
print("[5] context: RIP=" .. q(rq(ctx + 0x0e0)) .. " RSP=" .. q(rq(ctx + 0x0f8)))

-- [6] the call
local out_tid = memory.alloc(8)
zero(out_tid, 8)
local ok, ret = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(out_tid), uint64(0))
end)
print("[6] thr_create rv=" .. (ok and q(ret) or "PCALL-FAIL"))
local new_tid = rq(out_tid)
print("[6] tid_out=" .. q(new_tid))

-- [7] does the thread exist?
local ok_kill, kill_ret = pcall(function()
    return sc_thr_kill(new_tid, 0)
end)
print("[7] thr_kill(tid, 0)=" .. (ok_kill and q(kill_ret) or "PCALL-FAIL"))

if ok and to_num(ret) == 0 and ok_kill and to_num(kill_ret) == 0 then
    print("[7] *** THREAD EXISTS: thr_create(430) accepted the context ***")
else
    print("[7] not established: rv=" .. (ok and q(ret) or "?")
        .. " kill=" .. (ok_kill and q(kill_ret) or "?"))
end
print("=== PROBE 272a END ===")
