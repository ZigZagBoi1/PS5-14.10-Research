-- CRASH_CLASS: LOW
-- PROBE 1467a: is the 653 blockpool handle a first-class id in Sony's object table?
--
-- Context:
--   1465a measured the first working blockpool call: 653(0x400000) returns a handle (0x324) and a
--   second 653 returns EMFILE, so one pool exists per process.  Every other member of the family
--   (654 map, 655 unmap, 657 batch, 673 move) resolves an ADDRESS through vm_map_lookup_entry and
--   then demands `cmp byte [obj+0x9d],0xb` -- a type-11 vm_object that no mapping we can create
--   produces (1466a tried anonymous, GPU 0x33, /dev/zero, a file mapping and shm: all EINVAL).
--
--   So the handle is the only reachable blockpool artifact.  The question is whether it also lives in
--   the shared Sony object table, where 532 command 0x18 already performs a handle lookup: 1353a
--   measured `0x18` returning 0x800D0204 when in[0] != 0 and 0x800D0203 when in[0] == 0, i.e. the
--   decision is driven by a handle-shaped dword in the input page.  Every handle passed so far was
--   junk.  This probe passes a REAL handle, and a different status word would mean the blockpool
--   object is addressable through 532 -- an object whose fields are kernel pointers.
--
--   653's fields as built by the 13.60 body: +0x30 and +0x40 hold kernel pointers returned by
--   0x8ad836b0 / the caller of 0x8ad83640, +0x58 is the refcount, +0x60/+0x64 are [proc+0x5c4] and
--   [proc+0x5d0].  A copy-out of any of those would be the first kernel pointer this project has
--   obtained from a syscall.
--
-- -- prior art:
--   results/phase36_realargs/1465a_blockpool_open_flags_20261109_175825.txt
--   results/phase36_realargs/1466a_sys673_flavours_20261109_175951.txt
--   results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt
--   results/phase35_dead_end_reruns/1353a_sys532_low_step2_20261109_105622.txt
--   docs/SYS_532_UNPRIV_COMMANDS_14_10.md

print("=== PROBE 1467a: BLOCKPOOL HANDLE VIA 532 ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wr(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function hx(v) if v==nil then return "????????" end return string.format("%08X", v) end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local ina  = as_addr(memory.alloc(0x400))
local outa = as_addr(memory.alloc(0x400))

local function clear(a, n)
    for o = 0, n - 8, 8 do wq(a + o, 0) end
end
local function dump(tag, a, n)
    local out, cnt = {}, 0
    for o = 0, n - 4, 4 do
        local v = rd(a + o)
        if v ~= 0 then cnt = cnt + 1 if cnt <= 16 then out[#out + 1] = string.format("+%03X=%s", o, hx(v)) end end
    end
    print(string.format("   %s: %d non-zero %s", tag, cnt, table.concat(out, " ")))
end

local function c532(cmd, a1, a2, inp, size)
    local ok, rv = pcall(function() return mk(532)(uint64(cmd),uint64(a1),uint64(a2),uint64(inp),uint64(size),uint64(0)) end)
    if not ok then return nil end
    return to_num(rv)
end

-- [A] obtain a real blockpool handle
print("[A] 653 blockpool_open(0x400000)")
local h = nil
local rv653 = nil
do
    local ok, r = pcall(function() return mk(653)(uint64(0x400000),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    if ok then rv653 = to_num(r) end
end
print(string.format("[A] 653 -> %s", rv653 == nil and "EXC" or tostring(rv653)))
if rv653 and rv653 >= 0 and rv653 < 0x10000 then h = rv653 end
if not h then
    print("[A] no handle; using 0x324 as a guess would be dishonest, stopping the 532 pass")
else
    print(string.format("[A] handle = %d (0x%X)", h, h))
end
print("")

-- [B] the 532 handle lookup with a real handle and with junk, side by side
print("[B] 532 cmd 0x18/0x19 with handle-in-input vs junk")
local HANDLES = { h or 0x324, 0x324, 0x125, 0xFFFFFFFF, 0 }
local CMDS = { 0x18, 0x19, 0x1A, 0x20 }
for ci = 1, #CMDS do
    local cmd = CMDS[ci]
    for hi = 1, #HANDLES do
        clear(ina, 0x400); clear(outa, 0x400)
        wr(ina + 0, HANDLES[hi])
        local rv = c532(cmd, 0, outa, ina, 0x40)
        local st = rd(outa + 0)
        local s
        if rv == nil then s = "EXC"
        elseif rv == -1 then s = "-1 errno=" .. es()
        else s = string.format("%d (0x%X)", rv, rv) end
        print(string.format("[B] 0x%02X h=0x%X -> %s out0=%s", cmd, HANDLES[hi], s, hx(st)))
    end
end
print("")

-- [C] the out buffer in arg2, the handle in arg1
print("[C] 532 with the handle in arg1 and out in arg2")
for ci = 1, #CMDS do
    local cmd = CMDS[ci]
    clear(ina, 0x400); clear(outa, 0x400)
    local rv = c532(cmd, h or 0x324, outa, ina, 0x40)
    print(string.format("[C] 0x%02X a1=h -> %s out0=%s", cmd, rv == nil and "EXC" or tostring(rv), hx(rd(outa + 0))))
end
print("")

print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1467a COMPLETE ===")
