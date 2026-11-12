-- CRASH_CLASS: MODERATE -- read-only.  No store is issued to any device page: a stray store into
-- GPU MMIO is what hangs a console (1396b's own note).
-- PROBE 1463a: mmap every openable /dev node, not just the three that were mapped before
--
-- Context:
--   1395a/1396b/1397* characterised /dev/dmem0, /dev/dmem1, /dev/dmem2, /dev/gc, /dev/dce and
--   /dev/zero.  dmem0/dmem1 serve a per-process copy of kernel-initialised structures (1455a), gc
--   serves all-FF dummy pages, dce refuses.  Every other openable node in the inventory - rng, hid,
--   bt, usb, camera, gic, ajm - has never been mmapped at all, and a cdev that maps a register or
--   DMA window is a new surface: it would be the first device memory this process can address that
--   is not a copy of a static block.
--
--   1395a's lesson about argument shape is applied: the path must be a NUL-terminated buffer
--   address (a Lua string passed to uint64() raises), and the flags are 0x4002 (O_RDWR|O_NONBLOCK,
--   never 0x4 - O_NONBLOCK is 0x4000 on this platform).
--
--   The probe is read-only on purpose.  Each node is printed BEFORE it is touched, so a death names
--   the node; /dev/notification0 is never opened (reading it blocks the loader thread forever).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt
--   results/phase36_realargs/1455a_dmem_persist_after_restart_20261109_174425.txt
--   docs/DMEM_WINDOW_14_10.md
--   docs/DEVICE_IOCTL_14_10.md (the /dev node census: 34 of 76 nodes open)

print("=== PROBE 1463a: MMAP EVERY OPENABLE /dev NODE ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function hx(v) if v==nil then return "????????" end return string.format("%08X", v) end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

-- SIG_IGN for SIGSYS so an absent slot returns -1 instead of killing us
local sa = as_addr(memory.alloc(0x80))
for i = 0, 0x78, 8 do pcall(function() memory.write_qword(uint64(sa + i), uint64(0)) end) end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    local a = as_addr(b)
    for i = 1, #s do pcall(function() memory.write_byte(uint64(a + i - 1), string.byte(s, i)) end) end
    pcall(function() memory.write_byte(uint64(a + #s), 0) end)
    return a
end

local function readback(va)
    local out = {}
    for i = 0, 7 do out[#out + 1] = hx(rd(va + i * 4)) end
    return table.concat(out, " ")
end

local NODES = {
    "/dev/rng", "/dev/hid", "/dev/bt", "/dev/usb", "/dev/camera", "/dev/gic", "/dev/ajm",
    "/dev/dce", "/dev/gc", "/dev/dmem0", "/dev/dmem1", "/dev/dmem2", "/dev/zero",
}

local function probe_node(node)
    print(string.format("[N] %s", node))
    local path = str_addr(node)
    local fd = to_num(mk(5)(uint64(path), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
    if fd < 0 then print(string.format("   open -> %d %s", fd, es())); return end
    print(string.format("   fd=%d", fd))
    for _, off in ipairs({ 0, 0x1000, 0x10000 }) do
        print(string.format("   mmap off=0x%X ...", off))
        local va = to_num(mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(1), uint64(fd), uint64(off)))
        if va < 0 and va > -4096 then
            print(string.format("   off=0x%X -> %d %s", off, va, es()))
        elseif va == 0 or va >= 0x8000000000 then
            print(string.format("   off=0x%X -> bad va 0x%X", off, va))
        else
            print(string.format("   off=0x%X -> va=0x%X", off, va))
            print(string.format("   data: %s", readback(va)))
        end
    end
    pcall(function() mk(6)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

for i = 1, #NODES do probe_node(NODES[i]) end

print("")
print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1463a COMPLETE ===")
