-- CRASH_CLASS: MODERATE
-- PROBE 1022a: does MAP_FIXED accept an address outside the user half?
--
-- The presence oracle (1001a/1005a) shows the kernel image lives at a 2 MB aligned
-- address in 0xFFFFFFFF8.. - that is per boot. The obvious next question is whether the
-- address-space bound check can be walked past: if mmap(MAP_FIXED) accepted an unmapped
-- address in the kernel half, the process would own a page there.
--
-- Only UNMAPPED addresses are probed, so no live kernel page is replaced: the oracle says
-- 0xFFFFFFFF00000000 (below the image) and 0xFFFFFFFFE0000000 (above it) hold nothing on
-- this boot. A rejection is the expected answer and costs nothing; an acceptance would be
-- the first mapping-level hole found. Every success is unmapped again immediately.

print("=== PROBE 1022a: MAP_FIXED OUTSIDE THE USER HALF ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hx(x) return string.format("0x%X", to_num(x)) end
local sc_mmap = mk(477); local sc_munmap = mk(73); local sc_getpid = mk(20)
local MAP_PRIVATE, MAP_FIXED, MAP_ANON = 0x0002, 0x0010, 0x1000

local cases = {
    {0xFFFFFFFF00000000, "kernel half, below the image"},
    {0xFFFFFFFFE0000000, "kernel half, above the image"},
    {0xFFFFF00000000000, "far outside both halves"},
    {0x0000800000000000, "top of the user half"},
}
local pid = to_num(select(2, pcall(function() return sc_getpid() end)))
print(string.format("[0] pid=%d", pid))
for _, c in ipairs(cases) do
    local addr, len = c[1], 0x2000
    local ok, rv = pcall(function()
        return sc_mmap(uint64(addr), uint64(len), uint64(3), uint64(MAP_PRIVATE+MAP_FIXED+MAP_ANON), uint64(0xFFFFFFFF), uint64(0))
    end)
    local r = ok and to_num(rv) or -999
    print(string.format("[%s] rv=%s (%s)", c[2], hx(r), r == 0xFFFFFFFF or r < 0 and "-1" or "mapped"))
    if r ~= 0xFFFFFFFF and r > 0xFFF and ok then
        local ok2, w = pcall(function() return memory.write_dword(uint64(addr), uint64(0x12345678)) end)
        local ok3, v = pcall(function() return memory.read_dword(uint64(addr)) end)
        print(string.format("    [%s] write=%s read=%s", c[2], tostring(ok2), ok3 and hx(v) or "?"))
        pcall(function() return sc_munmap(uint64(addr), uint64(len)) end)
        print(string.format("    [%s] unmapped", c[2]))
    end
end
print(string.format("[Z] alive pid=%d", to_num(select(2, pcall(function() return sc_getpid() end)))))
print("=== COMPLETE ===")
