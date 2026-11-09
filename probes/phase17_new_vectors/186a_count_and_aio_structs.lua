-- CRASH_CLASS: HIGH
-- PROBE 186a: size-sensitive counts, process suspend/resume, and AIO with a struct
--
-- Context: 185a found 615 get_resident_fmem_count writing 0xC42 to its output and
-- still returning -1, so the -1 may be a size check rather than a refusal. That is
-- section A. Section B gives suspend_process/resume_process the calling pid instead
-- of zero, since both have real handlers and both killed on zeros. Section C hands
-- aio_submit/aio_get_data/aio_create a real struct instead of NULL - the earlier
-- "AIO is absent" reading came from a zero-argument kill, which no longer proves
-- absence (622 kills on zeros and returns 0 on a real request).
--
-- Sections run in the order that survives a kill: a kill ends the capture at that
-- line and the loader restarts about nine seconds later.

print("=== PROBE 186a: COUNTS, SUSPEND/RESUME, AIO STRUCTS ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local function hx(v)
    return tostring(v)
end
local zero = u64(0)

local pid = to_num(make_syscall(20)())
local out = memory.alloc(0x1000)
local function zero_page(p, n)
    for off = 0, (n or 0x1000) - 8, 8 do
        pcall(function() memory.write_qword(p + off, zero) end)
    end
end
local function dump(p, n)
    local parts = {}
    for off = 0, (n or 0x20) - 8, 8 do
        local ok, v = pcall(function() return memory.read_qword(p + off) end)
        parts[#parts + 1] = ok and hx(v) or "fault"
    end
    return table.concat(parts, " ")
end
local function call(num, a1, a2, a3)
    local sc = make_syscall(num)
    local ok, ret = pcall(function() return sc(a1, a2 or zero, a3 or zero, zero, zero, zero) end)
    if not ok then return "KILLED" end
    return hx(ret)
end

print(string.format("[0] pid=%d out=0x%X", pid, to_num(out)))
print("")

print("[0] A: count calls with size variants")
for _, num in ipairs({ 613, 615 }) do
    for _, size in ipairs({ 0, 1, 4, 8, 16, 0x100 }) do
        zero_page(out, 0x40)
        local r = call(num, u64(pid), out, u64(size))
        print(string.format("[*] %d(pid,out,%d) -> %s | %s", num, size, r, dump(out, 0x10)))
    end
end
print("")

print("[0] B: suspend/resume with the calling pid")
local before = call(613, u64(pid), out, u64(8))
print("[*] 613(pid,out,8) -> " .. before .. " | " .. dump(out, 0x10))
print("[*] 561(pid) -> " .. call(561, u64(pid)))
print("[*] 562(pid) -> " .. call(562, u64(pid)))
print("")

print("[0] C: AIO with a struct instead of NULL")
zero_page(out, 0x200)
print("[*] 668 aio_create(zeroed struct) -> " .. call(668, out) .. " | " .. dump(out, 0x20))
print("[*] 661 aio_submit(zeroed struct) -> " .. call(661, out) .. " | " .. dump(out, 0x20))
print("[*] 665 aio_get_data(zeroed struct) -> " .. call(665, out) .. " | " .. dump(out, 0x20))

zero_page(out, 0x200)
-- a plausible request: {op=1, size=0x10, buf=out+0x100, off=0}
pcall(function() memory.write_qword(out + 0x00, u64(1)) end)
pcall(function() memory.write_qword(out + 0x08, u64(0x10)) end)
pcall(function() memory.write_qword(out + 0x10, out + 0x100) end)
pcall(function() memory.write_qword(out + 0x18, zero) end)
print("[*] 661 aio_submit(filled struct) -> " .. call(661, out) .. " | " .. dump(out, 0x20))

print("")
print("[*] done")
