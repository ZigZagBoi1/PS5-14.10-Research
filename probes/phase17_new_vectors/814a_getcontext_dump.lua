-- CRASH_CLASS: MODERATE
-- PROBE 814a: dump the 0x4c0-byte record that syscall 421 copies out
--
-- Context: sigreturn (417) copies 0xC0 bytes of user data into [td+0x460]
-- before installing a context, but one gate rejects every frame we tried:
--   ([frame+0x190] ^ [[td+0x460]+0xf8]) & 0xFFFFFFFFFFDAB22A == 0
-- The 421 handler (0xc37860) zeroes a 0x500 stack buffer, calls the same
-- 0x8af1d900 helper, stores [td+0x3b0] and [td+0x3b8], then copyout 0x4c0
-- bytes to arg1. If that record is the mirror of the sigreturn frame, it
-- carries both the layout and the value at the +0xf8 field.
-- This probe only reads: no 417 and no 422.

print("=== PROBE 814a: GETCONTEXT RECORD DUMP ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function q(addr)
    local v = safe_rq(addr)
    if v == nil then return 0 end
    return to_num(v)
end

local sc421 = make_syscall(421)

local page = memory.alloc(0x600)
for off = 0, 0x5FF, 4 do safe_wd(page + off, 0) end

-- Prefill the tail with a canary so we can see the real record length.
for off = 0x4C0, 0x5FF, 4 do safe_wd(page + off, 0xCCCCCCCC) end

print(string.format("[0] pid=%d page=0x%08X", to_num(syscall.getpid()), to_num(page)))

local ok, r = pcall(function() return sc421(uint64(page)) end)
print(string.format("[A] 421 ret=%s ok=%s", tostring(r), tostring(ok)))

-- How far did the kernel actually write?
local last = -1
for off = 0, 0x5FF, 4 do
    local v = safe_rd(page + off)
    if v ~= nil and v ~= 0xCCCCCCCC then last = off end
end
print(string.format("[B] last written dword at +0x%03X (canary starts 0x4C0)", last))

-- Dump 0x4c0 as qwords, four per line.
local n = 0
local line = ""
for off = 0, 0x4B8, 8 do
    local raw = safe_rq(page + off)
    local txt = "nil"
    if raw ~= nil then txt = tostring(raw) end
    if #txt > 20 then txt = txt:sub(3) end
    line = line .. string.format(" %03X:%s", off, txt)
    n = n + 1
    if n % 3 == 0 then
        print("    " .. line)
        line = ""
    end
end
if line ~= "" then print("    " .. line) end

-- Classify every qword: segment selectors, kernel pointers, our own ranges.
local labels = {}
for off = 0, 0x4B8, 8 do
    local v = q(page + off)
    local h = 0
    local raw = safe_rq(page + off)
    if raw ~= nil and type(raw) == "table" and raw.h then h = to_num(raw.h) end
    local tag = nil
    if v == 0x33 or v == 0x43 or v == 0x3B or v == 0x2B or v == 0x0B or v == 0x23 then
        tag = "SELECTOR"
    elseif h >= 0xFFFF8000 then
        tag = "KERNEL?"
    elseif v > 0x100000000 and v < 0x800000000 then
        tag = "PTR?"
    end
    if tag then labels[#labels + 1] = string.format("%03X=%s", off, tag) end
end
print("[C] tagged qwords: " .. tostring(#labels))
for i = 1, #labels, 3 do
    local a, b, c = labels[i], labels[i + 1], labels[i + 2]
    print("    " .. table.concat({a or "", b or "", c or ""}, "  "))
end

print("")
print("[D] reading the signal mask the kernel just wrote:")
print(string.format("    421 again -> ret=%s", tostring(select(2, pcall(function() return sc421(uint64(page)) end)))))

print("")
print("=== PROBE 814a DONE ===")
