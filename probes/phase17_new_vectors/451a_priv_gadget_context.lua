-- CRASH_CLASS: LOW
-- PROBE 451a: dump the bytes around the privileged candidates
print("=== PROBE 451a: CANDIDATE CONTEXTS ===")
print("")
local Z = uint64(0)
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
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
local function call(sc, ...)
    local ok, rv = pcall(function(...) return sc(...) end, ...)
    if ok then return to_num(rv) end
    return -999
end
local function rd32(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return to_num(v) end return -1 end
local function fmt(v) return string.format("0x%X", v) end
local function hexat(buf, off, n)
    local t = {}
    for i = off, off + n - 1 do
        if i < 1 or i > #buf then break end
        t[#t + 1] = string.format("%02X", string.byte(buf, i))
    end
    return table.concat(t, " ")
end

local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local base, size = 0, 0
if call(make_syscall(593), Z, info) == 0 then
    local lo, hi = rd32(info + 0x108), rd32(info + 0x10C)
    if lo and hi and lo >= 0 and hi >= 0 then base = hi * 4294967296 + lo end
    size = rd32(info + 0x110)
end
print(string.format("  base=%s size=%s", fmt(base), fmt(size)))
local buf = nil
pcall(function() buf = memory.read_buffer(base, size) end)
if type(buf) ~= "string" then print("  read failed"); return end

local hits = {
  { n = "rdmsr", h = "0F32" },
  { n = "cli",   h = "FAC3" },
}
for _, p in ipairs(hits) do
    local want = {}
    for i = 1, #p.h, 2 do want[#want + 1] = tonumber(string.sub(p.h, i, i + 1), 16) end
    local shown = 0
    for i = 1, #buf - #want + 1 do
        local ok = true
        for j = 1, #want do
            if string.byte(buf, i + j - 1) ~= want[j] then ok = false; break end
        end
        if ok then
            print(string.format("  %-6s +%06X  %s", p.n, i - 1, hexat(buf, i, 16)))
            shown = shown + 1
            if shown >= 8 then break end
            i = i + 8
        end
    end
    if shown == 0 then print(string.format("  %-6s none", p.n)) end
end
print("")
print("=== 451a DONE ===")
