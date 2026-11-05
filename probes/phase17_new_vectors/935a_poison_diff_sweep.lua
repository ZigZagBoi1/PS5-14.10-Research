-- CRASH_CLASS: LOW
-- PROBE 935a: poison-diff the syscalls that copy structures out
--
-- Every earlier survey zeroed its buffer first, which cannot tell "the kernel
-- wrote 0" from "the kernel wrote nothing". A buffer pre-filled with 0xA5 can:
-- any byte still 0xA5 was never written, so a hole in a kernel structure shows
-- up directly. Holes in copied-out kernel structures are where pointers leak
-- (padding, union tails, error paths that skip initialisation).
--
-- Section A: 587(pid, buf)                  - credential metadata, 0x88 bytes
-- Section B: 593(handle, buf)               - dynlib info per module handle
-- Section C: 649(out, handle, member, 0x100) - module member query
-- Section D: 674(buf, 72, 512, cnt, 0x40000000) - the whole VM map
--
-- Any 8-byte window matching 0xFFFF8xxx_xxxxxxxx is printed as a hit.

print("=== PROBE 935a: poison-diff of copyout structures ===")

local A5 = 0xA5
local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end
local function fill(a,n) for i=0,n-1 do memory.write_byte(a+i, A5) end end
local function rd8(a) local ok,v=pcall(function() return memory.read_qword(a) end) if not ok then return nil end local h,l=0,0 if type(v)=="table" and v.h then h,l=v.h,v.l else l=to_num(v) end return string.format("0x%08X%08X",h,l) end

local function diff(tag, a, n, ret)
    local changed, first, last = 0, nil, nil
    local runs = {}
    local i = 0
    while i < n do
        if memory.read_byte(a+i) ~= A5 then
            local s = i
            while i < n and memory.read_byte(a+i) ~= A5 do i = i + 1 end
            local e = i - 1
            changed = changed + (e - s + 1)
            if #runs < 6 then runs[#runs+1] = string.format("+0x%X..+0x%X", s, e) end
            if first == nil then first = s end
            last = e
        else
            i = i + 1
        end
    end
    print(string.format("  %-22s ret=%-4d wrote=%-5d %s", tag, ret, changed,
        (#runs > 0) and table.concat(runs, " ") or "(nothing - buffer untouched)"))
    -- kernel-pointer scan over the written range, and over the whole buffer
    for off = 0, n - 8 do
        local s = rd8(a + off)
        if s and (string.sub(s, 3, 5) == "FFF" and string.sub(s, 3, 7) ~= "FFFFF") then
            -- 0xFFFF8.. - 0xFFFFFFFF range
            local hi = tonumber(string.sub(s, 3, 8), 16)
            if hi and hi >= 0xFFFF80 and hi <= 0xFFFFFFFF then
                print("    [KPTR] +0x" .. string.format("%X", off) .. " = " .. s)
            end
        end
    end
    return changed
end

local buf = memory.alloc(0x300)
local big = memory.alloc(72 * 512 + 0x40)
local list = memory.alloc(0x100)
local cnt = memory.alloc(8)
local cntp = memory.alloc(8)
local p = pid()
print("[0] pid=" .. tostring(p))

print("")
print("--- A: 587 credential metadata ---")
fill(buf, 0x100)
local r = call(mk(587), uint64(p), uint64(buf), uint64(0), uint64(0))
diff("587(pid,buf)", buf, 0x100, r)

print("")
print("--- B: 592 module list, then 593 per handle ---")
for i = 0, 0x100 - 1 do memory.write_byte(list + i, A5) end
r = call(mk(592), uint64(list), uint64(0x100), uint64(cnt), uint64(0), uint64(0), uint64(0))
local n = 0
local okn, nv = pcall(function() return memory.read_dword(cnt) end)
if okn then n = to_num(nv) end
print(string.format("  592 ret=%d count=%d", r, n))
local handles = {}
for i = 0, math.min(n, 8) - 1 do
    local ok, hv = pcall(function() return memory.read_qword(list + i * 8) end)
    if ok then
        local lo = 0
        if type(hv)=="table" and hv.l then lo = hv.l else lo = to_num(hv) end
        handles[#handles+1] = lo
    end
end
print("  handles: " .. table.concat(handles, ","))
for i = 1, math.min(#handles, 3) do
    fill(buf, 0x200)
    r = call(mk(593), uint64(handles[i]), uint64(buf))
    diff("593(h=" .. handles[i] .. ")", buf, 0x200, r)
end

print("")
print("--- C: 649 member query ---")
for _, mt in ipairs({1, 2, 3, 4, 7, 8}) do
    if handles[1] then
        fill(buf, 0x100)
        r = call(mk(649), uint64(buf), uint64(handles[1]), uint64(mt), uint64(0x100), uint64(0), uint64(0))
        diff("649(mt=" .. mt .. ")", buf, 0x100, r)
    end
end

print("")
print("--- D: 674 VM map ---")
fill(big, 72 * 512)
memory.write_dword(cntp, 0)
r = call(mk(674), uint64(big), uint64(72), uint64(512), uint64(cntp), uint64(0x40000000), uint64(0))
local cc = 0
local okc, cv = pcall(function() return memory.read_dword(cntp) end)
if okc then cc = to_num(cv) end
print(string.format("  674 ret=%d count=%d", r, cc))
diff("674 map", big, 72 * math.max(cc, 1), r)

print("")
print("[Z] alive=" .. tostring(pid()))
print("=== PROBE 935a COMPLETE ===")
