-- CRASH_CLASS: LOW
-- PROBE 449a: find a privileged-only instruction in eboot's text
--
-- 448a showed a child with CS = 0x40 executes a user gadget without a
-- panic. That is either "the selector was replaced, we are still ring 3"
-- or "we are ring 0 and SMAP/SMEP are off".
--
-- The discriminator is an instruction that #GPs at CPL 3 and is legal at
-- CPL 0, whose result we can see. `mov rax, cr0` is ideal: at ring 3 it
-- faults, at ring 0 it loads CR0 into RAX, and the following gadget
-- writes RAX to our marker, so the marker becomes the CR0 value.
--
-- This probe only scans; it executes nothing.

print("=== PROBE 450a: PRIVILEGED GADGET SCAN 2 ===")
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

local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local base, size = 0, 0
if call(make_syscall(593), Z, info) == 0 then
    local lo, hi = rd32(info + 0x108), rd32(info + 0x10C)
    if lo and hi and lo >= 0 and hi >= 0 then base = hi * 4294967296 + lo end
    size = rd32(info + 0x110)
end
print(string.format("  eboot base=%s size=%s", fmt(base), fmt(size)))
if base == 0 or size <= 0 then print("  no base"); return end

local buf = nil
pcall(function() buf = memory.read_buffer(base, size) end)
if type(buf) ~= "string" then print("  read failed"); return end
print(string.format("  read %d bytes", #buf))

-- patterns that are illegal at CPL 3 and legal at CPL 0, followed by ret
local pats = {
    { name = "rdmsr; ret",         hex = "0F32C3" },
    { name = "rdmsr",              hex = "0F32" },
    { name = "mov rax, dr0; ret",  hex = "0F21C0C3" },
    { name = "mov rax, dr0",       hex = "0F21C0" },
    { name = "in al, dx; ret",     hex = "ECC3" },
    { name = "invlpg [rax]; ret",  hex = "0F0138C3" },
    { name = "sgdt [rax]; ret",    hex = "0F0100C3" },
    { name = "cli; ret",           hex = "FAC3" },
}

local bytes = {}
for i = 1, #buf do bytes[i] = string.byte(buf, i) end

for _, p in ipairs(pats) do
    local want = {}
    for i = 1, #p.hex, 2 do want[#want + 1] = tonumber(string.sub(p.hex, i, i + 1), 16) end
    local hits = {}
    local limit = #bytes - #want + 1
    for i = 1, limit do
        local ok = true
        for j = 1, #want do
            if bytes[i + j - 1] ~= want[j] then ok = false; break end
        end
        if ok then
            hits[#hits + 1] = base + (i - 1)
            if #hits >= 6 then break end
        end
    end
    if #hits == 0 then
        print(string.format("  %-22s none", p.name))
    else
        local list = {}
        for k, a in ipairs(hits) do list[k] = fmt(a) end
        print(string.format("  %-22s %d+  %s", p.name, #hits, table.concat(list, " ")))
    end
end

print("")
print("=== 450a DONE ===")
