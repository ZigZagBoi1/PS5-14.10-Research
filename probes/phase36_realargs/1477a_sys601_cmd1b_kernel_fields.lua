-- CRASH_CLASS: HIGH -- every call in this probe can end the process; the loader may need a relaunch.
-- Nothing here writes to a kernel address on purpose: the kernel values only ever sit in *data* fields.
-- PROBE 1477a: 601 command 0x1B with kernel addresses in the struct fields
--
-- 601 is the mdbg multiplexer.  Commands 0x1B and 0x27 are the two numbers in 0x00-0x27 that kill the
-- caller with no crash blob and no returned value, and 0x1B does it in the sweep shape
-- `601(0x1B, arg2, arg3)` that 1355a used.  A kill with no fault record is what a kernel-mode
-- dereference of a bad pointer looks like from here, so the question is whether the body reads a
-- pointer out of the struct we hand it.
--
-- A kernel-mode raw dereference of a *user* address dies on SMAP; a dereference of a *mapped supervisor*
-- address succeeds, because the access already originates in the kernel.  So the discriminator is the
-- field's value:
--   zeros            -> died in 1355a, and dies again here as the baseline [C]
--   kernel image VA  -> [A]; if the body dereferences the field this survives where zeros did not
--   user page VA     -> [B]; a raw dereference of this dies on SMAP, a copyin/copyout of it does not
--   whichever comes back is the finding, and every phase prints before it calls.
--
-- -- prior art:
--   docs/MDBG_601_COMMAND_MAP_14_10.md:54   (0x1B kills, no crash blob)
--   docs/MDBG_601_COMMAND_MAP_14_10.md:108  (the kill list is 0x1B and 0x27)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt:54  (last line is
--     "calling 0x1B ...", so the death is inside the call)
--   probes/phase35_dead_end_reruns/1355a_sys601_cmd12_shape.lua:116  (the sweep's shape)
--   docs/HANDLER_SHAPE_HUNT_14_10.md  (the 13.60 601 tail stores caller qwords at fixed offsets of a
--     kernel object; if 0x1B is that family the fields are data, not pointers, and every phase returns)

print("=== PROBE 1477a: 601 CMD 0x1B WITH KERNEL FIELDS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function wq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a) local ok,v = pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function addr_of(v) return string.format("0x%08X%08X", math.floor(v / 4294967296), v % 4294967296) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIGSYS ignored so that a nosys trampoline could not be mistaken for a fault (601 is a real handler,
-- but the cost of ignoring a signal nobody raises is zero).
local sa = memory.alloc(0x80)
for i = 0, 0x78, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc = mk(601)

-- the struct the kernel reads, and a second page whose address is a legal field value
local page = N(mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
local dest = N(mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if page == 0 or dest == 0 then
    print("[0] mmap failed, aborting")
    print("=== COMPLETE ===")
    return
end
for i = 0, 0xFFF, 4 do pcall(function() memory.write_dword(dest + i, uint64(0xA5A5A5A5)) end) end
print(string.format("[0] page=%s dest=%s", addr_of(page), addr_of(dest)))

local KIMG = 0xFFFFFFFFC1000000   -- kernel image start, measured this boot by the fault oracle

local function fill_qword(v)
    for i = 0, 0xFF8, 8 do wq(page + i, v) end
end
local function fill_zero() fill_qword(0) end
local function count_changed()
    local n = 0
    for i = 0, 0xFFF, 4 do
        local x = N(memory.read_dword(dest + i)) % 4294967296
        if x ~= 0xA5A5A5A5 then n = n + 1 end
    end
    return n
end

-- [0] control: the command we know answers
fill_zero()
print("[0] control 601(0x00, page, 0x100)")
local ok0, rv0 = pcall(function() return sc(uint64(0x00), uint64(page), uint64(0x100)) end)
print(string.format("[0] -> ok=%s rv=%s", tostring(ok0), tostring(rv0)))

-- [A] kernel image addresses in every field
fill_qword(KIMG)
wq(dest, 0)  -- reset the marker page's first qword so a write is visible
print("[A] 601(0x1B, 0, page) with every field = 0xFFFFFFFFC1000000")
local okA, rvA = pcall(function() return sc(uint64(0x1B), uint64(0), uint64(page)) end)
print(string.format("[A] -> ok=%s rv=%s errno=%s", tostring(okA), tostring(rvA), es()))

-- [B] user page addresses in every field
fill_qword(dest)
print("[B] 601(0x1B, 0, page) with every field = the user page address")
local okB, rvB = pcall(function() return sc(uint64(0x1B), uint64(0), uint64(page)) end)
print(string.format("[B] -> ok=%s rv=%s errno=%s dest_changed=%d", tostring(okB), tostring(rvB), es(), count_changed()))

-- [C] the baseline that died in 1355a
fill_zero()
print("[C] 601(0x1B, 0, page) with every field = 0 (the 1355a baseline)")
local okC, rvC = pcall(function() return sc(uint64(0x1B), uint64(0), uint64(page)) end)
print(string.format("[C] -> ok=%s rv=%s errno=%s", tostring(okC), tostring(rvC), es()))

-- [D] only reached if [C] came back, which would mean the kill in 1355a used a different argument slot
fill_qword(KIMG)
print("[D] 601(0x1B, page, 0x100) with every field = 0xFFFFFFFFC1000000")
local okD, rvD = pcall(function() return sc(uint64(0x1B), uint64(page), uint64(0x100)) end)
print(string.format("[D] -> ok=%s rv=%s errno=%s", tostring(okD), tostring(rvD), es()))

print(string.format("[E] alive pid=%d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== COMPLETE ===")
