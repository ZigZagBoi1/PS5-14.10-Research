-- CRASH_CLASS: LOW
-- PROBE 1215b: dump libc [0x114000, 0x118000) - the gap between .text and .data that holds the
-- import slots. libc_addrofs.gettimeofday_import lands at libc+0x1179A8, so this range pins the
-- libkernel base for the dump and lets every import slot be mapped to a libkernel stub offset.
print("=== PROBE 1215b: libc import-slot window ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local lc = N(libc_base)
local imp = N(libc_addrofs.gettimeofday_import)
print(string.format("[0] libc=0x%X gettimeofday_import=0x%X delta=0x%X", lc, imp, imp - lc))
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
print(string.format("[0] *import = 0x%X", rq(imp) or 0))
local CH = 0x1000
local lo, hi = 0x114000, 0x118000
local off = lo
while off < hi do
    local ok, buf = pcall(function() return memory.read_buffer(lc + off, CH) end)
    if not ok then print(string.format("[!] read failed at +0x%X", off)) break end
    print(string.format("[I] off=0x%X len=0x%X %s", off, CH, (buf:gsub(".", function(c) return string.format("%02X", string.byte(c)) end))))
    off = off + CH
end
print("=== DONE ===")
