-- CRASH_CLASS: LOW -- opens file descriptors and makes five 601 calls; no known-lethal code.
-- PROBE 1385a: does opening a device set the process attach object at proc+0x568?
--
-- Every 601 branch that does real work tests a pointer at process+0x568 first and answers
-- ENOENT(22) when it is NULL (results/kernel_handlers/asm/sys_601_deep.asm, ca0735, ca0e9c,
-- ca18cd). Measured on 14.10: 601(0x0A) is EPERM(1), 601(0x12) is -1 even with a mapped arg2
-- (results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt,
-- 1355a_sys601_cmd12_shape_20261109_110324.txt). The 13.60 analysis calls the 0x13-0x19 family
-- "device state reads" and 0x05 a 0xb8-byte process info leak, i.e. the object behind
-- proc+0x568 is a *device* context attached to the process, which is why every branch needs it.
--
-- 1379a showed that all fourteen openable nodes accept O_RDWR on 14.10 (the old "read-only"
-- readings were EBADF on read-only descriptors). Nobody has ever opened a device *before*
-- calling 601. If the attach object is installed by a driver open rather than by 601(0x03),
-- opening the right node turns EPERM/ENOENT into a real answer with no argument guessing.
--
-- This probe opens every node that opened in 1379a, keeps all the descriptors, and then calls the
-- five cheap 601 codes and prints rv plus errno. It repeats with the descriptor set closed and
-- re-opened in a different order, so a result that appears in one order only is detectable.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1379a_dev_write_gate_20261109_132830.txt (which nodes open)
--   results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt (601 errno map)
--   results/kernel_handlers/asm/sys_601_deep.asm (ca0735, ca0e9c, ca18cd: the +0x568 tests)
--   results/kernel_handlers/analysis/sys_601_deep.md (cmds 0x13-0x19 = device state)

print("=== PROBE 1385a: DEVICE OPEN vs THE 601 ATTACH OBJECT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local A, OPEN, CLOSE = mk(20), mk(5), mk(6)
print(string.format("[0] pid=%d", N(A(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))))

local P = memory.alloc(0x200)
local B = N(P)
local sc = mk(601)
local function zero() pcall(function() memory.write_buffer(P, string.rep("\0", 0x200)) end) end

local NODES = {"/dev/ugen0.2", "/dev/sce_zlib", "/dev/dmem0", "/dev/dmem1", "/dev/dmem2",
    "/dev/uvd_enc", "/dev/hmd_cmd", "/dev/hmd2_cmd", "/dev/bt", "/dev/gic", "/dev/gc",
    "/dev/dce", "/dev/camera", "/dev/hid", "/dev/deci_stdout"}
local PATH = memory.alloc(0x100)
local PA = N(PATH)

local function open_all(tag)
    local fds = {}
    for i = 1, #NODES do
        pcall(function() memory.write_buffer(PATH, NODES[i] .. "\0") end)
        local ok, rv = pcall(function() return OPEN(uint64(PA), uint64(2), uint64(0)) end)
        local fd = ok and N(rv) or -99999
        if fd >= 0 then fds[#fds + 1] = fd end
    end
    print(string.format("  %s opened %d/%d fds", tag, #fds, #NODES))
    return fds
end
local function close_all(fds)
    for i = 1, #fds do pcall(function() CLOSE(uint64(fds[i])) end) end
end

local function probes(tag)
    local codes = {0x00, 0x0A, 0x0E, 0x12, 0x13}
    for i = 1, #codes do
        local c = codes[i]
        zero()
        local ok, rv = pcall(function()
            local a1 = (c == 0x00) and uint64(B) or uint64(0)
            local a2 = (c == 0x12) and uint64(B) or uint64(0)
            return sc(uint64(c), a1, a2, uint64(0), uint64(0), uint64(0))
        end)
        local r = ok and N(rv) or -99999
        local w = 0
        local head = ""
        for i2 = 0, 15 do
            local ok2, v = pcall(function() return N(memory.read_dword(B + i2 * 4)) end)
            if ok2 and v ~= 0 then w = w + 1; if #head < 50 then head = head .. string.format(" %08X", v) end end
        end
        print(string.format("  %-18s 601(0x%02X) rv=%-6s errno=%-24s nz=%d%s", tag, c, tostring(r),
            ok and es() or "EXC", w, head))
    end
end

print("[A] baseline, no device open")
probes("no-fds")

local fds = open_all("first")
print(string.format("[B] with %d descriptors open", #fds))
probes("with-fds")
close_all(fds)

local fds2 = open_all("second")
print(string.format("[C] reopened in the same order, %d descriptors", #fds2))
probes("reopened")
close_all(fds2)

print("[D] only /dev/deci_stdout and /dev/gc")
local keep = {}
for _, name in ipairs({"/dev/deci_stdout", "/dev/gc"}) do
    pcall(function() memory.write_buffer(PATH, name .. "\0") end)
    local ok, rv = pcall(function() return OPEN(uint64(PA), uint64(2), uint64(0)) end)
    local fd = ok and N(rv) or -99999
    if fd >= 0 then keep[#keep + 1] = fd end
end
print(string.format("  opened %d", #keep))
probes("two-fds")
close_all(keep)

print("=== PROBE 1385a COMPLETE ===")
