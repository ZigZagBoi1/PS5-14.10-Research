-- CRASH_CLASS: HIGH
-- PROBE 248a: sys 622 cmd 0x400 with a self-referential copied struct
--
-- Context: 622's 0x400-0x493 group kills the process whenever the copyin from
-- arg3 succeeds, at any size, and returns -1 when it fails. The death is after
-- the copy (247a). Two readings fit that: the handler dereferences an absent
-- device context (nothing we control), or it dereferences a pointer that came
-- out of the copied bytes (something we control).
--
-- This separates them. Every qword of the copied struct holds the address of
-- the struct itself, so any offset the handler dereferences lands on a mapped
-- page instead of zero. If the pointer comes from the copied data, the call
-- should stop faulting and return something; if the handler uses its own null
-- context, the call dies exactly as it did with zeros.

print("=== PROBE 248a: 622 CMD 0x400 FAKE CONTEXT ===")
print("")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function sgn(v)
    if type(v) == "table" and v.h then
        local h = to_num(v.h)
        local l = to_num(v.l)
        if h % 4294967296 == 4294967295 and l % 4294967296 == 4294967295 then
            return -1
        end
        return v
    end
    return v
end

local sc = make_syscall(622)

-- [A] a page the kernel can reach, filled with its own address
local page = memory.alloc(0x1000)
for i = 0, 0x1000 - 8, 8 do
    memory.write_qword(uint64(page + i), uint64(page))
end
print(string.format("[A] struct page = %s", tostring(page)))
print(string.format("    page[0x00] = %s", tostring(safe_rq(page))))
print(string.format("    page[0x08] = %s", tostring(safe_rq(page + 8))))

-- [B] the call. Every qword of the copied 0x40 bytes is the page address.
local buf = memory.alloc(0x1000)
for i = 0, 0x1000 - 8, 8 do
    memory.write_dword(uint64(buf + i), 0xDEADBEEF)
end

print("")
print("[B] 622(0x400, 0, buf, page, 0x40, 0)")
print("    BEFORE")
local ret = sc(uint64(0x400), uint64(0), uint64(buf), uint64(page),
    uint64(0x40), uint64(0))
print(string.format("    AFTER ret=%s", tostring(sgn(ret))))
print(string.format("    buf[0x00]=0x%08X buf[0x04]=0x%08X",
    to_num(memory.read_dword(uint64(buf))),
    to_num(memory.read_dword(uint64(buf + 4)))))

-- [C] did the kernel write through the pointer?
print("")
print("[C] struct page after the call")
local want = tostring(uint64(page))
for i = 0, 0x38, 8 do
    local v = safe_rq(uint64(page + i))
    local state = "CHANGED"
    if v == nil then
        state = "READ_FAIL"
    elseif tostring(v) == want then
        state = "same"
    end
    print(string.format("    +0x%02X = %s  %s", i, tostring(v), state))
end

print("")
print("=== PROBE 248a COMPLETE ===")
