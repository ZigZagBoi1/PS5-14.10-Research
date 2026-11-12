-- CRASH_CLASS: LOW
-- PROBE 1465a: blockpool_open(653) flag mask and blockpool_map(654) argument shape
--
-- Context:
--   673 blockpool_move (measured: needs a vm_object of type 11, 1451a) and 657 blockpool_batch
--   both begin by looking up an address in the caller's vm_map and demanding
--   `cmp byte [obj+0x9d], 0xb`.  Nothing a game process has mapped creates such an object, so the
--   whole blockpool family looked unreachable.  The 13.60 body of 653 says otherwise: it allocates a
--   0x410b0-byte object, registers it with type 0x11, and RETURNS the handle in td_retval[0]
--   (movsxd rax,[rbp-0x3c]; mov [rbx+0x408],rax where rbx is the syscall frame).
--
--   653's only caller-visible gate is `test r15d, 0xffafffff; jne EINVAL`, i.e. arg1 may only carry
--   bits 20 and 22 -- so 653(0) should pass the mask.  We measured 653(0) = EINVAL(22), which means
--   either the mask is not the gate we think it is, or a later call (0x8b0ec7a0) refuses.  The four
--   allowed flag values have never been tried.
--
--   654 (blockpool_map) takes arg1 = 64 KiB-aligned address < map bound, arg2 = 64 KiB-aligned length,
--   arg3 = a DWORD in {0, 3, 10} (`cmp r13d,0xa; ja fail` then `bt 0x409, r13d`), arg4/arg5 read as
--   dwords.  Its first visible check is `cmp [vm_map+0x20], arg1; jbe EINVAL`, so a low address is
--   what it wants.
--
--   A success here would be the first reachable blockpool object, and therefore the first path to a
--   type-11 vm_object -- the gate that has blocked 673 and 657.
--
-- -- prior art:
--   results/phase36_realargs/1451a_sys673_object_type_20261109_172829.txt (type-11 gate, no store of 0xb anywhere)
--   results/phase17_new_vectors/1344a_arg4_classes_*.txt / 1343b_* (654/655/657 writer rows)
--   PR #71 (657 "still writes after close(h)")
--   results/kernel_handlers/asm/sys_653_deep.asm, sys_654.asm, sys_657.asm (13.60 bodies)
--   docs/VM_LAYER_14_10.md section 2

print("=== PROBE 1465a: BLOCKPOOL OPEN/MAP SHAPES ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function mmap(px)
    local ok,a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x8000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc653, sc654, sc655 = mk(653), mk(654), mk(655)

local function call3(sc, a1, a2, a3, a4, a5)
    local ok, rv = pcall(function() return sc(uint64(a1),uint64(a2),uint64(a3),uint64(a4),uint64(a5),uint64(0)) end)
    if not ok then return nil end
    return to_num(rv)
end

print("[A] 653 blockpool_open, every allowed flag value plus two rejected ones")
local FLAGS = { 0, 0x100000, 0x400000, 0x500000, 0x1, 0xFFFFFFFF }
local handle = nil
for i = 1, #FLAGS do
    local f = FLAGS[i]
    local rv = call3(sc653, f, 0, 0, 0, 0)
    if rv == nil then
        print(string.format("[A] 653(0x%X) -> EXC", f))
    elseif rv == -1 then
        print(string.format("[A] 653(0x%X) -> -1 errno=%s", f, es()))
    else
        print(string.format("[A] 653(0x%X) -> %d (0x%X)", f, rv, rv))
        if rv >= 0 and handle == nil then handle = rv end
    end
end
print("")

print("[B] 654 blockpool_map at a 64 KiB-aligned low address")
local base = mmap(0x40000)
print(string.format("[B] scratch mapping = 0x%X", base))
local MAPS = {
    { 0x10000,     0x10000, 0, 0, 0 },
    { 0x10000,     0x10000, 3, 0, 0 },
    { 0x10000,     0x10000, 10, 0, 0 },
    { 0x1000000,   0x10000, 3, 0, 0 },
    { 0x40000000,  0x100000, 3, 0, 0 },
    { 0x10000,     0x20000, 3, 0, 0 },
}
for i = 1, #MAPS do
    local m = MAPS[i]
    local rv = call3(sc654, m[1], m[2], m[3], m[4], m[5])
    if rv == nil then print(string.format("[B] 654(0x%X,0x%X,%d) -> EXC", m[1], m[2], m[3]))
    elseif rv == -1 then print(string.format("[B] 654(0x%X,0x%X,%d) -> -1 errno=%s", m[1], m[2], m[3], es()))
    else print(string.format("[B] 654(0x%X,0x%X,%d) -> %d (0x%X)", m[1], m[2], m[3], rv, rv)) end
end
print("")

if handle and handle >= 0 then
    print(string.format("[C] handle = %d (0x%X): 655 unmap and 657 batch", handle, handle))
    local r1 = call3(sc655, handle, 0, 0, 0, 0)
    print(string.format("[C] 655(h) -> %s", r1 == nil and "EXC" or tostring(r1)))
    local buf = as_addr(memory.alloc(0x100))
    for o = 0, 0xF8, 8 do wq(buf + o, 0) end
    local r2 = call3(mk(657), buf, 1, 0, 0, 0)
    print(string.format("[C] 657(buf,1,0,0) -> %s", r2 == nil and "EXC" or tostring(r2)))
else
    print("[C] no handle was issued, 655/657 skipped")
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1465a COMPLETE ===")
