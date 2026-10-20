-- CRASH_CLASS: LOW
-- PROBE 156b: recover the real ucontext layout via thr_get_ucontext(634)
--
-- Context: 80a/156a placed CS/SS/RFLAGS/RIP/RSP at ucontext+0x90..0xB0 and the
-- length field at +0x118. Both runs returned rv=-1 with a TID written but
-- thr_kill(tid, 0) then said ESRCH (results/phase17_new_vectors/156a_
-- thr_create_spin_observable_20261020_163827.txt), while the older 58e
-- context (which wrote +0x108, +0x110, +0x0d0 instead) was accepted and
-- panicked. That is a layout disagreement, not a CS answer.
--
-- Instead of guessing the offsets again, ask the kernel for a real ucontext:
-- thr_get_ucontext(634) fills the caller's buffer for the current thread.
-- The dump shows exactly where RIP, CS, RFLAGS, RSP and SS sit, because CS
-- must be 0x43, SS 0x3B, RFLAGS must carry bit 1, and RIP must point into
-- eboot for this process.

print("=== PROBE 156b: ucontext LAYOUT VIA thr_get_ucontext(634) ===")
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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end

local sc_getpid = make_syscall(20)
local sc_thr_self = make_syscall(432)
local sc_thr_get_ucontext = make_syscall(634)

local ok_pid, pid = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main TID=" .. hx(main_tid))

-- eboot base, to recognise the real RIP when it shows up in the dump
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = 0
if text_lo then
    eboot_base = (text_hi or 0) * 4294967296 + text_lo
end
print("[0] eboot text base=" .. string.format("0x%X", eboot_base))

local BUF = 0x400
local buf = memory.alloc(BUF)

-- Variant A: single pointer argument (59b's assumed signature)
zero(buf, BUF)
local okA, rvA = pcall(function()
    return sc_thr_get_ucontext(uint64(buf))
end)
print("[1] 634(buf): ok=" .. tostring(okA) .. " rv=" .. tostring(to_num(rvA)))

-- Variant B: (tid, buf)
local bufB = memory.alloc(BUF)
zero(bufB, BUF)
local okB, rvB = pcall(function()
    return sc_thr_get_ucontext(main_tid, uint64(bufB))
end)
print("[1] 634(tid, buf): ok=" .. tostring(okB) .. " rv=" .. tostring(to_num(rvB)))

local function dump(tag, base)
    print("")
    print("=== DUMP " .. tag .. " ===")
    local candidates = {}
    for off = 0, 0x200 - 8, 8 do
        local v = rq(base + off)
        if v then
            local vh, vl = 0, 0
            if type(v) == "table" and v.h then vh, vl = v.h, v.l else vl = to_num(v) end
            local s = string.format("0x%08X_%08X", vh, vl)
            local mark = ""
            if vh == 0 and vl == 0x43 then mark = "  <== CS?" end
            if vh == 0 and vl == 0x3B then mark = "  <== SS?" end
            if vh == 0 and vl ~= 0 and (vl % 4) == 2 and vl < 0x100000 then mark = "  <== RFLAGS?" end
            if vh == 0 and vl >= eboot_base and vl < eboot_base + 0x1000000 and eboot_base ~= 0 then
                mark = "  <== RIP (eboot text)?"
            end
            if vh > 0 and vh < 0x10 and vl > 0x1000000 then mark = "  <== RSP?" end
            if mark ~= "" then candidates[#candidates + 1] = string.format("  +0x%03X = %s%s", off, s, mark) end
            print(string.format("  +0x%03X: %s", off, s))
        end
    end
    print("--- candidates ---")
    for i = 1, #candidates do print(candidates[i]) end
    if #candidates == 0 then print("  (none)") end
end

if okA and to_num(rvA) == 0 then
    dump("A (single arg)", buf)
elseif okB and to_num(rvB) == 0 then
    dump("B (tid, buf)", bufB)
else
    print("")
    print("[2] 634 refused both shapes; dumping variant A anyway to check for writes")
    dump("A (raw)", buf)
end

print("")
print("=== PROBE 156b COMPLETE ===")
print("=== PROBE 156b COMPLETE ===")
