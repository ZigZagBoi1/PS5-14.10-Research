-- CRASH_CLASS: LOW
-- PROBE 849a: what does syscall 421 actually write into the 0x4c0-byte record?
--
-- Context: 814a was written to dump this record but died on a Lua format bug
-- (a qword table reaching string.format), so the record has never been
-- inspected.  417 treats the same 0x500 struct as a signal frame and compares
-- [user+0x190] against a kernel-side value masked by ~0xFFFFFFFFFFDAB22A.
-- If any field of the record that 421 hands back is a kernel address, that is
-- the KASLR leak no syscall has given us so far.

print("=== PROBE 849a: GETCONTEXT RECORD DUMP ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
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

local sc421 = make_syscall(421)

local page = memory.alloc(0x600)
for off = 0, 0x5FF, 4 do safe_wd(page + off, 0) end
for off = 0x4C0, 0x5FF, 4 do safe_wd(page + off, 0xCCCCCCCC) end

print(string.format("[0] pid=%d page=0x%s", to_num(syscall.getpid()), hx(page)))

local ok, r = pcall(function() return sc421(uint64(page)) end)
print(string.format("[A] 421 ret=%s ok=%s", hx(r), tostring(ok)))

-- How far did the kernel write?
local last = -1
for off = 0, 0x5FF, 4 do
    local v = safe_rd(page + off)
    if v ~= nil and v ~= 0xCCCCCCCC then last = off end
end
print(string.format("[B] last non-canary dword at +0x%03X (canary starts 0x4C0)", last))

-- Raw dump of the first 0x200 bytes, four qwords per line.
print("[C] record 0x000-0x1FF:")
local n = 0
local line = ""
for off = 0, 0x1F8, 8 do
    local v = safe_rq(page + off)
    local txt = "nil"
    if v ~= nil then txt = hx(v) end
    line = line .. string.format(" %03X:%s", off, txt)
    n = n + 1
    if n % 2 == 0 then
        print("    " .. line)
        line = ""
    end
end
if line ~= "" then print("    " .. line) end

-- Classify the whole record.
print("[D] classification 0x000-0x4BF:")
local labels = {}
for off = 0, 0x4B8, 8 do
    local v = safe_rq(page + off)
    if v ~= nil then
        local h = 0
        local l = 0
        if type(v) == "table" and v.h then h = to_num(v.h); l = to_num(v.l) end
        local tag = nil
        if l == 0x33 or l == 0x43 or l == 0x3B or l == 0x2B or l == 0x0B or l == 0x23 then
            if h == 0 then tag = "SEL" end
        end
        if tag == nil and h >= 0xFFFF8000 and h <= 0xFFFFFFFF then
            tag = "KERNEL"
        elseif tag == nil and h == 0 and l ~= 0 then
            -- printable or small: report only pointers into our own maps
            if l > 0x10000000 then tag = "LOWPTR" end
        end
        if tag then labels[#labels + 1] = string.format("%03X=%s:%s", off, tag, hx(v)) end
    end
end
print(string.format("[D] tagged qwords: %d", #labels))
for i = 1, #labels do print("    " .. labels[i]) end

-- The two fields the frame path cares about.
local f = safe_rq(page + 0xF8)
local rfl = safe_rq(page + 0x190)
print(string.format("[E] +0x0F8 = %s   +0x190 = %s", f and hx(f) or "nil", rfl and hx(rfl) or "nil"))

print("[F] alive=true")
