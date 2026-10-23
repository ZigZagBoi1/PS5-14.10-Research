-- CRASH_CLASS: HIGH (705 killed 275a, but without signal handlers)
-- PROBE 275b: sysent tail with SIGSYS/SIGSEGV/SIGBUS ignore
--
-- 275a died on try(705) without signal handlers. If the kill is SIGSYS(12),
-- ignoring it lets us survive and test more. SIGSYS ignore was confirmed
-- working via sigaction(416) in prior probes.
--
-- Tests 705 first (zero-arg read). If it survives:
--   713, 733, 687, 690, then a broader sweep of 708-734.
-- If 705 still kills with SIGSYS ignored → true hard kill, table ends at 676.

print("=== PROBE 275b: GUARDED SYSENT TAIL ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- [A] Install signal handlers: SIGSYS(12), SIGSEGV(11), SIGBUS(10), SIGPIPE(13)
print("")
print("[A] Signal handlers")
local sc_sigaction = mk(416)
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end

for _, sig in ipairs({12, 11, 10, 13}) do
    wq(N(act), uint64(1))  -- SIG_IGN
    wd(N(act) + 8, 0)
    local sr = nil
    pcall(function()
        sr = sc_sigaction(uint64(sig), act, uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  sig %d IGN: %s", sig, fmt(sr)))
end

if not alive() then print("DIED in signal setup!") return end
print("  canary OK")

-- [B] The critical test: sys 705 (get_phys_page_size, zero args on 13.60)
print("")
print("[B] sys 705 get_phys_page_size (zero-arg read)")
local sc705 = mk(705)
local r705 = nil
local ok705 = pcall(function()
    r705 = sc705(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  ok=%s ret=%s", tostring(ok705), fmt(r705)))

if not alive() then
    print("  DIED on 705 even with SIGSYS ignore!")
    return
end

-- If we survived 705, the table EXTENDS past 676!
if ok705 then
    print("  *** 705 RETURNED — SYSENT EXTENDS PAST 676! ***")
    if r705 then
        local v705 = N(r705)
        if v705 == 0x4000 then
            print("  page_size=0x4000 (16KB) — CONFIRMED")
        else
            print(string.format("  value=%d (0x%X)", v705, v705))
        end
    end
else
    print("  pcall caught error — handler exists but faulted")
end

-- [C] More zero-arg reads
print("")
print("[C] More candidates")

local function try(num, label, args)
    if not alive() then print(string.format("  %-4d SKIP (dead)", num)) return nil, nil end
    local sc = mk(num)
    local a = args or {}
    local ok, rv = pcall(function()
        return sc(a[1] or uint64(0), a[2] or uint64(0), a[3] or uint64(0),
                  a[4] or uint64(0), a[5] or uint64(0), a[6] or uint64(0))
    end)
    print(string.format("  %-4d %-32s ok=%-5s ret=%s", num, label, tostring(ok), fmt(rv)))
    return ok, rv
end

try(713, "get_ppr_sdk_version")
try(706, "begin_app_mount")
try(707, "end_app_mount")
try(676, "cpumode_yield")
try(677, "wait6")

if not alive() then print("DIED in C!") return end

-- [D] Buffer-taking syscalls
print("")
print("[D] Buffer-taking syscalls")
local buf = memory.alloc(0x200)
for off = 0, 0x1FC, 4 do wd(N(buf) + off, 0) end

try(733, "get_resident_fmem_count2", {uint64(0), uint64(N(buf))})
local b733 = rq(N(buf))
if b733 then print("    buf[0]=" .. fmt(b733)) end

for off = 0, 0x1C, 4 do wd(N(buf) + off, 0) end
try(687, "pipe2", {uint64(N(buf)), uint64(0)})
local p0 = rd(N(buf))
local p1 = rd(N(buf) + 4)
if p0 then print(string.format("    fds: %d, %d", p0, p1 or -1)) end
if p0 and p0 > 0 then pcall(function() mk(6)(uint64(p0)) end) end
if p1 and p1 > 0 then pcall(function() mk(6)(uint64(p1)) end) end

try(690, "ppoll(nfds=0)", {uint64(N(buf)), uint64(0), uint64(0), uint64(0)})
try(689, "procctl", {uint64(0), uint64(pid), uint64(0), uint64(0)})

if not alive() then print("DIED in D!") return end

-- [E] Sony-specific high-value targets (if table extends)
print("")
print("[E] Sony syscalls 708-734")
local sony = {
    {708, "fsc2h_ctrl"},
    {709, "streamwrite"},
    {710, "app_save"},
    {711, "app_restore"},
    {712, "saved_app_delete"},
    {714, "notify_app_event"},
    {715, "ioreq"},
    {716, "openintr"},
    {717, "dl_get_info_2"},
    {718, "acinfo_add"},
    {719, "acinfo_delete"},
    {720, "acinfo_get_all_for_coredump"},
    {721, "ampr_ctrl_debug"},
    {722, "workspace_ctrl"},
    {723, "notify_a53_bind_progress"},
    {724, "dynlib_get_lid_mid_info"},
    {725, "mmap2"},
    {726, "get_aio_debug_submit_info"},
    {727, "get_aio_debug_request_info"},
    {728, "virtual_query_by_pid"},
    {729, "fgcinfo_add"},
    {730, "fgcinfo_delete"},
    {731, "fgcinfo_get_all_for_coredump"},
    {732, "cffmgr_call"},
    {734, "trace_ctrl"},
}

for _, s in ipairs(sony) do
    if not alive() then print("  DIED at " .. s[1]) break end
    try(s[1], s[2])
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 275b COMPLETE ===")
