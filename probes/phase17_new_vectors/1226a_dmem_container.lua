-- CRASH_CLASS: LOW
-- PROBE 1226a: dmem_container(586) selects proc+0x5c4, then mmap_dmem(628) maps that container.
--
-- 586 body 0x3ce150: reads proc+0x5c4, returns (slot-1 < 3) as a predicate, calls priv_check(0x2ad),
-- bounds the index by 4 with a 0x138-byte stride table and checks the slot is populated before
-- writing proc+0x5c4 (0x3ce1bd). 628 body 0xabd540: arg0 must be a clean low address, arg1 a
-- page-aligned length >= 0x4000, arg2 a protection word with mask 0x9fdf2f.
print("=== PROBE 1226a: dmem container then mmap_dmem ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
print(string.format("[0] pid=%d", N(mk(20)())))
print("[1] 586 query form and indices")
call("586(0xFFFFFFFF)", function() return mk(586)(uint64(0xFFFFFFFF),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
for i = 0, 4 do
    call(string.format("586(%d)", i), function() return mk(586)(uint64(i),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
end
print("[2] 628 mmap_dmem with the selected container")
local ob = memory.alloc(0x40)
local va = 0
for _, pr in ipairs({3, 0x33, 0x1002, 0}) do
    local rv = N(mk(628)(uint64(0),uint64(0x4000),uint64(pr),uint64(0),uint64(0),uint64(0)))
    print(string.format("    628(0,0x4000,prot=0x%X) -> 0x%X err=%s", pr, rv, ES()))
    if rv > 0x10000 and rv < 0x7FFFFFFFFF then va = rv break end
end
if va ~= 0 then
    print(string.format("[3] mapped 0x%X", va))
    for i=0,0x3C,4 do wd(ob+i,0xDEADBEEF) end
    call("547", function() return mk(547)(uint64(va),uint64(ob),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    local s={} for i=0,5 do s[#s+1]=string.format("%08X",rd(ob+i*4)) end
    print("    547: "..table.concat(s," "))
    print(string.format("    first bytes: %08X %08X", rd(va), rd(va+4)))
else
    print("[3] no mapping")
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
