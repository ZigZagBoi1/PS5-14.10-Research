-- CRASH_CLASS: MODERATE
-- PROBE 56q: thr_create mc_len sweep — find the right sizeof(mcontext_t)
--
-- Context: 56p confirmed thr_create returns -1 despite CS=0x43 preventing panic.
-- TIDs are allocated (incrementing) but threads don't exist (thr_kill returns -1).
-- Hypothesis: FreeBSD set_mcontext() checks mc_len == sizeof(mcontext_t),
-- returns EINVAL if wrong. We never set mc_len.
--
-- This probe tries multiple mc_len values at two possible offsets
-- (standard FreeBSD layout vs PS5 shifted layout).
-- Also reads the current thread's ucontext via sigaction context dump.

print("=== PROBE 56q: THR_CREATE MC_LEN SWEEP ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Get eboot base and find ret gadget
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
print(string.format("eboot: 0x%X_%08X", eboot_hi or 0, eboot_lo or 0))

local ret_gadget = nil
if eboot_lo and eboot_hi then
    local ok_sc, scan_data = pcall(function()
        return native.read_buffer(uint64(string.format("0x%X%08X", eboot_hi, eboot_lo)), 4096)
    end)
    if ok_sc and scan_data then
        for i = 1, #scan_data do
            if scan_data:byte(i) == 0xC3 then
                ret_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                break
            end
        end
    end
end
print("ret_gadget=" .. fmt_addr(ret_gadget))

-- Get FS base
local sc_sysarch = make_syscall(165)
local fsbase_buf = memory.alloc(16)
safe_wq(fsbase_buf, uint64(0))
pcall(function() sc_sysarch(uint64(128), uint64(to_num(fsbase_buf))) end)
local fsbase = safe_rq(fsbase_buf)
print("fsbase=" .. fmt_addr(fsbase))

-- Allocate stack (shared across tests)
local sc_mmap = make_syscall(477)
local ok_stk, new_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stk_h, stk_l = get_hi_lo(new_stack)
print(string.format("stack: 0x%X_%08X", stk_h, stk_l))

local sc_thr = make_syscall(430)
local sc_thr_kill = make_syscall(433)

-- ============================================================
-- Helper: try thr_create with a given mc_len at a given offset
-- Uses the "shifted" layout (mc_rip at mcontext+0xB0, mc_cs at +0xB8)
-- which matched the CS=0x43 panic-prevention result
-- ============================================================
local function try_thr_shifted(mc_len_val, mc_len_offset, label)
    local uctx = memory.alloc(0x500)
    for i = 0, 0x4FF, 4 do safe_wd(uctx + i, 0) end

    local mc = to_num(uctx) + 0x10

    -- Shifted layout (proven by CS=0x43 fix working at these offsets)
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc + 0xB0, rg_l)      -- mc_rip
    safe_wd(mc + 0xB4, rg_h)
    safe_wd(mc + 0xB8, 0x43)      -- mc_cs
    safe_wd(mc + 0xC0, 0x202)     -- mc_rflags
    local sp_l = stk_l + 0x10000 - 0x100
    safe_wd(mc + 0xC8, sp_l)      -- mc_rsp
    safe_wd(mc + 0xCC, stk_h)
    safe_wd(mc + 0xD0, 0x3B)      -- mc_ss
    safe_wd(mc + 0x48, sp_l)      -- mc_rbp
    safe_wd(mc + 0x4C, stk_h)
    safe_wd(mc + 0xA4, 0x3B)      -- mc_ds
    safe_wd(mc + 0xA0, 0x3B)      -- mc_es

    -- Set mc_len at the specified offset
    safe_wd(mc + mc_len_offset, mc_len_val)
    safe_wd(mc + mc_len_offset + 4, 0)

    local tid_out = memory.alloc(16)
    safe_wq(tid_out, uint64(0))

    local ok_tc, ret_tc = pcall(function()
        return sc_thr(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
    end)
    local tid = to_num(safe_rq(tid_out))

    local alive = "?"
    if tid > 0 then
        local ok_k, ret_k = pcall(function()
            return sc_thr_kill(uint64(tid), uint64(0))
        end)
        local ret_k_n = to_num(ret_k)
        alive = (ret_k_n == 0) and "ALIVE!" or "dead"
    end

    local ret_n = -999
    if ok_tc then
        local rh, rl = get_hi_lo(ret_tc)
        if rh == 0xFFFFFFFF then ret_n = -1
        elseif rh == 0 then ret_n = rl
        else ret_n = -2
        end
    end

    print(string.format("  %s: ret=%d TID=%d %s", label, ret_n, tid, alive))
    return ret_n == 0 and tid > 0
end

-- ============================================================
-- SWEEP: mc_len values at shifted offset +0xD8
-- (mc_ss at +0xD0, so mc_len should be at +0xD8)
-- ============================================================
print("")
print("--- SWEEP A: mc_len at mcontext+0xD8 (shifted layout) ---")

local mc_len_candidates = {
    0x320, 0x328, 0x330, 0x338, 0x340, 0x348, 0x350, 0x358,
    0x360, 0x368, 0x370, 0x378, 0x380, 0x390, 0x3A0, 0x3B0,
    0x400, 0x440, 0x480, 0x500, 0x540, 0x580, 0x600,
    0x800, 0xA00, 0xC00
}

for _, mclen in ipairs(mc_len_candidates) do
    local ok = try_thr_shifted(mclen, 0xD8, string.format("len=0x%X@+0xD8", mclen))
    if ok then
        print("*** SUCCESS with mc_len=0x" .. string.format("%X", mclen) .. " ***")
        break
    end
end

-- Also check canary
local c1 = to_num(syscall.getpid())
print("canary=" .. c1)
if c1 ~= pid then
    print("CANARY MISMATCH - STOP")
    return
end

-- ============================================================
-- SWEEP B: mc_len at mcontext+0xC8 (standard FreeBSD layout)
-- This would mean mc_ss is at +0xC0 and mc_len at +0xC8
-- But we'd also need to adjust ALL field offsets to standard layout
-- ============================================================
print("")
print("--- SWEEP B: STANDARD FREEBSD LAYOUT (mc_rip at +0xA0) ---")

local function try_thr_standard(mc_len_val, label)
    local uctx = memory.alloc(0x500)
    for i = 0, 0x4FF, 4 do safe_wd(uctx + i, 0) end

    local mc = to_num(uctx) + 0x10

    -- Standard FreeBSD amd64 layout
    -- mc_rbp at +0x48 (same)
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc + 0x48, stk_l + 0x10000 - 0x100)  -- mc_rbp
    safe_wd(mc + 0x4C, stk_h)

    -- mc_trapno at +0x80 (uint32_t)
    -- mc_fs at +0x84 (uint16_t)
    -- mc_gs at +0x86 (uint16_t)
    -- mc_addr at +0x88 (8 bytes)
    -- mc_flags at +0x90 (uint32_t)
    -- mc_es at +0x94 (uint16_t) = 0x3B
    -- mc_ds at +0x96 (uint16_t) = 0x3B
    safe_wd(mc + 0x94, 0x003B003B)  -- es=0x3B ds=0x3B packed

    -- mc_err at +0x98 (8 bytes)
    -- mc_rip at +0xA0
    safe_wd(mc + 0xA0, rg_l)
    safe_wd(mc + 0xA4, rg_h)

    -- mc_cs at +0xA8 = 0x43
    safe_wd(mc + 0xA8, 0x43)

    -- mc_rflags at +0xB0 = 0x202
    safe_wd(mc + 0xB0, 0x202)

    -- mc_rsp at +0xB8
    safe_wd(mc + 0xB8, stk_l + 0x10000 - 0x100)
    safe_wd(mc + 0xBC, stk_h)

    -- mc_ss at +0xC0 = 0x3B
    safe_wd(mc + 0xC0, 0x3B)

    -- mc_len at +0xC8
    safe_wd(mc + 0xC8, mc_len_val)
    safe_wd(mc + 0xCC, 0)

    local tid_out = memory.alloc(16)
    safe_wq(tid_out, uint64(0))

    local ok_tc, ret_tc = pcall(function()
        return sc_thr(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
    end)
    local tid = to_num(safe_rq(tid_out))

    local alive = "?"
    if tid > 0 then
        local ok_k, ret_k = pcall(function()
            return sc_thr_kill(uint64(tid), uint64(0))
        end)
        local ret_k_n = to_num(ret_k)
        alive = (ret_k_n == 0) and "ALIVE!" or "dead"
    end

    local ret_n = -999
    if ok_tc then
        local rh, rl = get_hi_lo(ret_tc)
        if rh == 0xFFFFFFFF then ret_n = -1
        elseif rh == 0 then ret_n = rl
        else ret_n = -2
        end
    end

    print(string.format("  %s: ret=%d TID=%d %s", label, ret_n, tid, alive))
    return ret_n == 0 and tid > 0
end

local std_candidates = {0x320, 0x330, 0x340, 0x350, 0x360, 0x380, 0x400, 0x500, 0x800}

for _, mclen in ipairs(std_candidates) do
    local ok = try_thr_standard(mclen, string.format("len=0x%X@+0xC8", mclen))
    if ok then
        print("*** SUCCESS with STANDARD layout mc_len=0x" .. string.format("%X", mclen) .. " ***")
        break
    end
end

-- ============================================================
-- SWEEP C: Try with NO mc_len check bypass
-- Maybe the PS5 variant doesn't check mc_len at all
-- and the issue is something else entirely.
-- Try setting mc_fpformat and mc_ownedfp to see if those matter.
-- ============================================================
print("")
print("--- SWEEP C: SHIFTED LAYOUT + EXTRA FIELDS ---")

local function try_thr_extra(fpformat, ownedfp, mc_len_val, label)
    local uctx = memory.alloc(0x500)
    for i = 0, 0x4FF, 4 do safe_wd(uctx + i, 0) end

    local mc = to_num(uctx) + 0x10

    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc + 0xB0, rg_l)
    safe_wd(mc + 0xB4, rg_h)
    safe_wd(mc + 0xB8, 0x43)
    safe_wd(mc + 0xC0, 0x202)
    local sp_l = stk_l + 0x10000 - 0x100
    safe_wd(mc + 0xC8, sp_l)
    safe_wd(mc + 0xCC, stk_h)
    safe_wd(mc + 0xD0, 0x3B)
    safe_wd(mc + 0x48, sp_l)
    safe_wd(mc + 0x4C, stk_h)
    safe_wd(mc + 0xA4, 0x3B)
    safe_wd(mc + 0xA0, 0x3B)

    -- mc_len at +0xD8
    safe_wd(mc + 0xD8, mc_len_val)
    -- mc_fpformat at +0xE0
    safe_wd(mc + 0xE0, fpformat)
    -- mc_ownedfp at +0xE8
    safe_wd(mc + 0xE8, ownedfp)

    local tid_out = memory.alloc(16)
    safe_wq(tid_out, uint64(0))

    local ok_tc, ret_tc = pcall(function()
        return sc_thr(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
    end)
    local tid = to_num(safe_rq(tid_out))

    local alive = "?"
    if tid > 0 then
        local ok_k, ret_k = pcall(function()
            return sc_thr_kill(uint64(tid), uint64(0))
        end)
        local ret_k_n = to_num(ret_k)
        alive = (ret_k_n == 0) and "ALIVE!" or "dead"
    end

    local ret_n = -999
    if ok_tc then
        local rh, rl = get_hi_lo(ret_tc)
        if rh == 0xFFFFFFFF then ret_n = -1
        elseif rh == 0 then ret_n = rl
        else ret_n = -2
        end
    end

    print(string.format("  %s: ret=%d TID=%d %s", label, ret_n, tid, alive))
    return ret_n == 0 and tid > 0
end

-- _MC_FPFMT_NODEV = 0x10000, _MC_FPFMT_XMM = 0x10002
-- _MC_FPOWNED_NONE = 0x20000, _MC_FPOWNED_FPU = 0x20001, _MC_FPOWNED_PCB = 0x20002
local extra_tests = {
    {0x10002, 0x20001, 0x340, "xmm+fpu+0x340"},
    {0x10002, 0x20001, 0x350, "xmm+fpu+0x350"},
    {0x10002, 0x20001, 0x360, "xmm+fpu+0x360"},
    {0x10002, 0x20001, 0x400, "xmm+fpu+0x400"},
    {0x10002, 0x20001, 0x500, "xmm+fpu+0x500"},
    {0x10002, 0x20001, 0x800, "xmm+fpu+0x800"},
    {0x10000, 0x20000, 0x340, "nodev+none+0x340"},
    {0x10000, 0x20000, 0x350, "nodev+none+0x350"},
    {0x10000, 0x20000, 0x400, "nodev+none+0x400"},
    {0x10000, 0x20000, 0x800, "nodev+none+0x800"},
}

for _, t in ipairs(extra_tests) do
    local ok = try_thr_extra(t[1], t[2], t[3], t[4])
    if ok then
        print("*** SUCCESS ***")
        break
    end
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56q COMPLETE ===")
