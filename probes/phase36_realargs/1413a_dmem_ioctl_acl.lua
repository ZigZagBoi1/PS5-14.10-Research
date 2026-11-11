-- CRASH_CLASS: MODERATE
-- PROBE 1413a: /dev/dmem driver ioctls - the ACL / set_pid_and_prot path - and the full /dev name list.
--
-- prior art:
--   results/phase36_realargs/1412a_dmem_64g_window_20261109_153207.txt
--     the aperture is [0, ~0x110000000) RW plus a second window at exactly 0x1000000000 that
--     accepts prot 0 and prot 1 and refuses prot 2/3/5/7/0x13 - granted READ-ONLY. MAP_PRIVATE
--     is refused EINVAL. The 64 GiB page reads all zero except +0x120 = 2.
--   results/phase36_realargs/1411a_dmem_range_check_20261109_153133.txt
--     the driver checks offset+length, not offset alone.
--   agent://DmemDriver (scout, this session): 13.60 dmem dispatch at 0xffffffff8ad91ec9; the
--     arm at 0xffffffff8ad92213 covers commands 0x80108002 / 0x80108015 / 0xC010801A and
--     "hands a caller-controlled GPU-side address to a range walk over the 0x138-byte
--     container records"; function-name strings include dmem_set_pid_and_prot and dmem_acl.
--   probes/phase17_new_vectors/278a_node_ioctl_sweep.lua - the earlier sweep used only
--     16-bit command numbers 0x0000..0xFFFF on /dev/<name>, so the 0x80-group IOC-encoded
--     dmem commands were never sent.
--   docs/DEVICE_IOCTL_14_10.md
--
-- Why: the read-only grant at 64 GiB is probably dmem_acl's doing. If one of these ioctls
-- sets pid+prot for a GPU range - the names in the dump say exactly that - then a range we
-- are not entitled to could be granted read-write, and the same call pointed at another
-- process's pid would be a cross-process GPU memory window.
--
-- Also: list every /dev entry, because the driver's error strings parse a name of the shape
-- /dev/dmem/cnt[0-9], which no probe in this tree has ever opened.

print("=== PROBE 1413a: DMEM IOCTLS + /dev NAMES ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end

print(string.format("[0] pid=%d", sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local sc_open, sc_close, sc_ioctl = mk(5), mk(6), mk(54)
local sc_getd = mk(272)

local function openp(p, fl)
    return sg(sc_open(uint64(str_addr(p)), uint64(fl or 2), uint64(0), uint64(0), uint64(0), uint64(0)))
end

print("")
print("[A] every /dev entry as the kernel lists it")
local dfd = openp("/dev", 0x0)
print(string.format("  open(/dev)=%d", dfd))
if dfd >= 0 then
    local buf = memory.alloc(0x800)
    for page = 1, 12 do
        local pos = memory.alloc(8)
        pcall(function() memory.write_qword(pos, uint64(0)) end)
        local rv = sg(sc_getd(uint64(dfd), uint64(buf), uint64(0x800), uint64(pos), uint64(0), uint64(0)))
        if rv <= 0 then print(string.format("  page %d: rv=%d %s", page, rv, es())) break end
        local names = {}
        local off = 0
        while off + 8 <= rv do
            local namlen = rd(buf + off + 7) % 256
            local rec = rd(buf + off + 6)
            local reclen = rec and math.floor((rec % 65536) / 256) % 65536 or 0
            local nm = ""
            for i = 0, namlen - 1 do
                local c = rd(buf + off + 8 + i)
                if c then nm = nm .. string.char(c % 256) end
            end
            if nm ~= "" and nm ~= "." and nm ~= ".." then names[#names + 1] = nm end
            if reclen < 9 then break end
            off = off + reclen
        end
        print(string.format("  page %d: %s", page, table.concat(names, " ")))
    end
    pcall(function() sc_close(uint64(dfd)) end)
end

print("")
print("[B] candidate node names the driver's own strings imply")
for _, nm in ipairs({"/dev/dmem3", "/dev/dmem", "/dev/dmem/cnt0", "/dev/dmem/cnt1",
                     "/dev/dmem/cnt2", "/dev/dmem/cnt3", "/dev/dmem_cnt0", "/dev/dmemcnt0",
                     "/dev/dmem/cnt9", "/dev/dmemu", "/dev/sce_dmem"}) do
    local fd = openp(nm, 0x4002)
    if fd < 0 then fd = openp(nm, 2) end
    print(string.format("  %-18s %s", nm, fd >= 0 and ("fd=" .. fd) or es()))
    if fd >= 0 then pcall(function() sc_close(uint64(fd)) end) end
end

print("")
print("[C] the dmem ACL ioctls with a zeroed 0x40-byte argument")
local fd0 = openp("/dev/dmem0", 0x4002)
print(string.format("  open(/dev/dmem0)=%d", fd0))
if fd0 >= 0 then
    local arg = memory.alloc(0x40)
    for off = 0, 0x3C, 4 do pcall(function() memory.write_dword(arg + off, 0) end) end
    for _, cmd in ipairs({0x80108002, 0x80108015, 0xC010801A, 0x80088002, 0xC0088015,
                          0x80108001, 0x80108003, 0x80108010, 0x80108016, 0x8010801A}) do
        local rv = sg(sc_ioctl(uint64(fd0), uint64(cmd), uint64(arg)))
        print(string.format("  cmd=0x%08X rv=%d errno=%s  buf=%s %s %s %s",
            cmd, rv, es(), hex4(rd(arg)), hex4(rd(arg + 4)), hex4(rd(arg + 8)), hex4(rd(arg + 12))))
    end

    print("")
    print("[D] same commands with a GPU address in the first qword (the 64 GiB window)")
    for _, cmd in ipairs({0x80108002, 0x80108015, 0xC010801A}) do
        for _, val in ipairs({0x1000000000, 0x0, 0xFFFFFFFF}) do
            for off = 0, 0x3C, 4 do pcall(function() memory.write_dword(arg + off, 0) end) end
            pcall(function() memory.write_dword(arg, val % 4294967296) end)
            pcall(function() memory.write_dword(arg + 4, math.floor(val / 4294967296) % 4294967296) end)
            local rv = sg(sc_ioctl(uint64(fd0), uint64(cmd), uint64(arg)))
            print(string.format("  cmd=0x%08X arg0=0x%-12X rv=%d errno=%s buf=%s %s %s %s",
                cmd, val, rv, es(), hex4(rd(arg)), hex4(rd(arg + 4)), hex4(rd(arg + 8)), hex4(rd(arg + 12))))
        end
    end
    pcall(function() sc_close(uint64(fd0)) end)
end

print("")
print("=== 1413a DONE ===")
