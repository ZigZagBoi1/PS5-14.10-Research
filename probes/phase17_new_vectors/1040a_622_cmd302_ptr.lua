-- CRASH_CLASS: HIGH
-- PROBE 1040a: what does sys 622 cmd 0x302 read through?
-- 1039a: `622(0x302, 0, buf, 0, 0, 0)` kills the process deterministically even with len=0,
-- while 0x300/0x301 answer rv=0 with 0xFFFFFFFF.  The 0x302 arm therefore touches an
-- argument before it copies anything.
--
-- Layout from the decompile (sys_622_deep.c:92,116 and asm 7dcd62..7dcfe6):
--   slot 1 (rsi+0x00) = command, r15d
--   slot 2 (rsi+0x10) = 4-byte reply target
--   slot 3 (rsi+0x18) = pointer the arm copies from   <- the candidate
--   slot 4 (rsi+0x20) = length, gated <= 0x40
-- CheckerA4 caught the first draft passing the candidate in the buffer instead of slot 3,
-- which made every case identical.
-- Cases: our own zeroed page, present kernel text, NULL, and the reply buffer itself.
print("=== PROBE 1040a: 622 cmd 0x302 pointer dereference ===")
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
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end return -1 end
local function hex(v) return string.format("%X", v) end

local sc622, sc_pid = mk(622), mk(20)
print(string.format("[S] pid=%d", to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))

local page = memory.alloc(0x1000); local pg = as_addr(page)
local watch = memory.alloc(0x1000); local wg = as_addr(watch)
local buf = memory.alloc(0x200); local ba = as_addr(buf)
print(string.format("[A] page=%X watch=%X buf=%X", pg, wg, ba))
if pg == 0 or wg == 0 or ba == 0 then print("[!] address conversion failed"); return end

for o = 0, 0xFFC, 4 do wd(pg + o, 0) end
for o = 0, 0xFFC, 4 do wd(wg + o, 0xAAAAAAAA) end          -- exact in a double
if rd(wg) ~= 0xAAAAAAAA then print("[!] watch page did not arm"); return end
if rd(pg) ~= 0 then print("[!] page not zeroed"); return end

local function run(tag, cand)
    for o = 0, 0x1FC, 8 do wq(ba + o, 0) end
    wq(ba, cand)
    local back = rq(ba)
    if back ~= cand then
        print(string.format(">%s [!] buf0 stored %s, wanted %s - skipped", tag, hex(back), hex(cand)))
        return
    end
    print(string.format(">%s arg3=%s", tag, hex(cand)))
    local ok, v = pcall(function()
        return sc622(uint64(0x302), uint64(0), uint64(ba), uint64(cand), uint64(0), uint64(0))
    end)
    print(string.format("[%s] rv=%s reply=%s page0=%s page8=%s watch0=%s", tag,
        ok and hex(to_num(v)) or "FAIL", hex(rq(ba)), hex(rq(pg)), hex(rq(pg + 8)), hex(rq(wg))))
end

run("A_user", pg)
run("B_ktext", 0xFFFFFFFF80000000)
run("C_null", 0)
run("D_selfbuf", ba)
print("[Z] done pid=" .. tostring(to_num(select(2, pcall(function() return sc_pid(uint64(0)) end)))))
