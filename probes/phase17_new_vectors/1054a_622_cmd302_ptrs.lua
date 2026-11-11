-- CRASH_CLASS: HIGH
-- PROBE 1054a: sys 622 cmd 0x302 with pointer-shaped input
--
-- 1053a: 0x300 returns 0 with a 0x40-byte zero buffer, 0x302 dies even with that buffer
-- fully defined.  So the arm is not reading uninitialised stack - it either dereferences a
-- field or it is a deliberate kill.  This feeds it 0x40 bytes of valid user pointers at
-- every 8-byte offset: if the arm follows one of them, it must survive; if it dies anyway,
-- the pointers are not the input and the arm is a kill/panic path.
--
-- Layout reminder (asm 7dcfdc-7dd006): slot 2 = 4-byte reply, slot 3 = source, slot 4 =
-- length (<= 0x40), copyin to a 0x40 stack buffer before the per-command call.
print("=== PROBE 1054a: 622 0x302 with pointer-shaped input ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function as_addr(x) local m = tostring(x):match("0x(%x+)"); if m then return tonumber(m, 16) end return to_num(x) end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function wd(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end return -1 end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end return -1 end
local function hex(v) return string.format("%X", v) end

local sc622, sc_pid = mk(622), mk(20)
print(string.format("[S] pid=%d", to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))

local target = memory.alloc(0x1000); local tg = as_addr(target)   -- what the pointers point at
local page = memory.alloc(0x1000);   local pg = as_addr(page)     -- the 0x40-byte input
local buf = memory.alloc(0x200);     local ba = as_addr(buf)
print(string.format("[A] target=%X src=%X buf=%X", tg, pg, ba))
if tg == 0 or pg == 0 or ba == 0 then print("[!] address conversion failed"); return end
for o = 0, 0xFFC, 4 do wd(tg + o, 0) end
for o = 0, 0xFFC, 4 do wd(pg + o, 0) end

local function arm(ptr)
    for o = 0, 0x3C, 8 do wq(pg + o, ptr) end        -- eight copies inside 0x40 bytes
    return rq(pg) == ptr
end
local function fill_target(v)
    for o = 0, 0xFFC, 4 do wd(tg + o, v) end
end
local function run(tag, cmd, ptr)
    for o = 0, 0x1FC, 8 do wq(ba + o, 0xFFFFFFFFFFFFFFFF) end
    if not arm(ptr) then print("> " .. tag .. " [!] input page did not arm"); return end
    print(string.format(">%s cmd=%s src[0]=%s len=0x40", tag, hex(cmd), hex(rq(pg))))
    local ok, v = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(ba), uint64(pg), uint64(0x40), uint64(0))
    end)
    print(string.format("[%s] rv=%s reply=%s", tag, ok and hex(to_num(v)) or "FAIL", hex(rq(ba))))
end

-- control: the same shape on a command that returns
fill_target(0)
run("A_ctl300", 0x300, tg)
-- the arm under test, pointers to a zero page
fill_target(0)
run("B_302_zptr", 0x302, tg)
-- pointers to a recognisable pattern, in case a field has to be non-zero
fill_target(0x41414141)
run("C_302_aptr", 0x302, tg)
-- pointers at the present kernel stub page: a kernel-mode read would succeed, CPL3 would not
fill_target(0)
run("D_302_kptr", 0x302, 0xFFFFFFFF80000000)
print("[Z] done pid=" .. tostring(to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))
