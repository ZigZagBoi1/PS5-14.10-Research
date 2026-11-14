-- CRASH_CLASS: HIGH
-- PROBE 1055a: sys 622 cmd 0x302 with every argument slot populated
--
-- 1039a/1040a/1053a/1054a: 0x302 kills for len=0, for a defined 0x40-byte zero buffer and
-- for 0x40 bytes of valid user pointers in slot 3; the same shapes on 0x300 return 0 with
-- 0xFFFFFFFF.  The only axis never varied is the other slots: every earlier run passed 0 in
-- slot 1, 5 and 6.  If the arm reads a pointer or a handle from one of them, a NULL there is
-- the fault; if it dies with all of them pointing at a mapped page, 0x302 is a kill path.
print("=== PROBE 1055a: 622 0x302, all slots populated ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function as_addr(x) local m = tostring(x):match("0x(%x+)"); if m then return tonumber(m, 16) end return to_num(x) end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function wd(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end return -1 end
local function hex(v) return string.format("%X", v) end
local sc622, sc_pid = mk(622), mk(20)
print(string.format("[S] pid=%d", to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))

local page = memory.alloc(0x1000); local pg = as_addr(page)
local buf = memory.alloc(0x200);  local ba = as_addr(buf)
print(string.format("[A] src=%X buf=%X", pg, ba))
if pg == 0 or ba == 0 then print("[!] address conversion failed"); return end
for o = 0, 0xFFC, 4 do wd(pg + o, 0) end

local function run(tag, cmd, s1, s5, s6)
    for o = 0, 0x1FC, 8 do wq(ba + o, 0xFFFFFFFFFFFFFFFF) end
    for o = 0, 0x3C, 8 do wq(pg + o, s1) end
    print(string.format(">%s cmd=%s s1=%s s5=%s s6=%s len=0x40", tag, hex(cmd), hex(s1), hex(s5), hex(s6)))
    local ok, v = pcall(function()
        return sc622(uint64(cmd), uint64(s1), uint64(ba), uint64(pg), uint64(0x40), uint64(s6))
    end)
    print(string.format("[%s] rv=%s reply=%s", tag, ok and hex(to_num(v)) or "FAIL", hex(rq(ba))))
end

run("A_ctl300_null", 0x300, 0, 0, 0)      -- control: every slot zero still returns
run("B_302_src", 0x302, pg, 0, 0)         -- slot 1 filled
run("C_302_s1s6", 0x302, pg, 0, pg)       -- slots 1 and 6 filled
print("[Z] done pid=" .. tostring(to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))
