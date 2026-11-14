-- CRASH_CLASS: HIGH -- [D] writes a marker through the device alias and reads the executable
-- mapping for it. If they are the same physical pages this modifies live code; the offset is
-- chosen only after [C] shows both views read zero there, and the marker is restored immediately.
-- PROBE 1481e: is the driver's eboot.bin window an alias of executable code?
--
-- 1481b proved that 548 op 2 turns a driver-created device window into genuinely writable memory:
-- six stores landed and read back with restore. The windows are named "(NoName)eboot.bin" and sit
-- at 0xC80000000 (288 KiB) and 0xF0000000 (16 KiB), while the process's own executable eboot text
-- is somewhere else entirely.
--
-- If those windows are page-table aliases of the same physical pages, then a page that the CPU
-- treats as execute-only can be written through the alias: the first write primitive into
-- executable memory this project has had, and a W^X bypass that does not need prot 4 (which 548
-- and mprotect both refuse).
--
-- The probe is built to fail safely. [A] prints every eboot-named window and every executable
-- mapping with its first bytes. [C] compares the two views at five offsets without writing
-- anything. [D] writes only at an offset where BOTH views read zero, reads the other view, and
-- restores at once.
--
-- -- prior art:
--   results/phase36_realargs/1481b_gpu_windows_write_20261109_201732.txt (6 of 6 stores landed)
--   results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt (windows are zeros)
--   results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt (the named extents)
--   docs/DEAD_ENDS.md (W^X: mprotect refuses bit 0x4 everywhere)

print("=== PROBE 1481e: IS THE DEVICE WINDOW AN ALIAS OF CODE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local sc674 = mk(674)
local sc547 = mk(547)
local ent = memory.alloc(0x40)
local rec = memory.alloc(0x20)
local cnt = memory.alloc(0x10)

local function set_entry(start, offset, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", offset))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

local function prot_to3(addr, len)
    set_entry(addr, 0, len, 3, 2)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    if not ok then return -999 end
    return N(rv)
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

local function rd(a)
    local v = nil
    pcall(function() v = N(memory.read_dword(a)) end)
    return v
end

local function hex32(a, n)
    local s = ""
    for i = 0, n - 1, 4 do
        local v = rd(a + i)
        s = s .. (v and string.format("%08X ", v) or "???????? ")
    end
    return s
end

-- ---------------------------------------------------------------- [A] the map
print("")
print("--- [A] every eboot-named window and every executable mapping ---")
local buf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[A] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("=== PROBE 1481e INCOMPLETE ===")
    return
end
if nrec > 400 then nrec = 400 end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

local eboot = {}
local exec = {}
for i = 0, nrec - 1 do
    local b = buf + i * 72
    local s = u64at(b, 0x00)
    local e = u64at(b, 0x08)
    local pr = 0
    pcall(function() pr = N(memory.read_dword(b + 0x18)) end)
    local name = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        name = name .. string.char(ch)
    end
    if name:find("eboot") and s >= 0x10000 then
        eboot[#eboot + 1] = {s = s, e = e, pr = pr, name = name}
        print(string.format("[A] eboot 0x%X-0x%X prot=0x%X %s", s, e, pr, name))
        if pr == 3 or pr == 5 then
            print("      " .. hex32(s, 16))
        end
    end
    if (pr == 5 or pr == 4) and s >= 0x10000000 and (exec[1] == nil or e - s > exec[1].e - exec[1].s) then
        exec[1] = {s = s, e = e, pr = pr, name = name}
    end
end
if exec[1] then
    print(string.format("[A] largest exec region 0x%X-0x%X prot=0x%X %s",
        exec[1].s, exec[1].e, exec[1].pr, exec[1].name))
    print("      " .. hex32(exec[1].s, 16))
end

-- ---------------------------------------------------------------- [B] pick the two views
print("")
print("--- [B] pick the device view and the executable view ---")
local dev = nil
for i = 1, #eboot do
    if eboot[i].s >= 0xC00000000 and eboot[i].e - eboot[i].s >= 0x10000 then dev = eboot[i] break end
end
if not dev then
    for i = 1, #eboot do
        if eboot[i].e - eboot[i].s >= 0x4000 then dev = eboot[i] break end
    end
end
if not dev then
    print("[B] no device window found")
    print("=== PROBE 1481e INCOMPLETE ===")
    return
end
print(string.format("[B] device view 0x%X-0x%X prot=0x%X", dev.s, dev.e, dev.pr))
if dev.pr ~= 3 then
    local rv = prot_to3(dev.s - (dev.s % 0x4000), 0x4000)
    print(string.format("[B] protect -> rv=%s prot now %s", tostring(rv), tostring(prot_of(dev.s))))
end

-- The executable view is the process's own eboot text: prefer a 0x532xxxxxxx-style mapping,
-- otherwise the largest executable region 674 reports.
local code = nil
for i = 1, #eboot do
    if eboot[i].pr == 5 or eboot[i].pr == 4 or eboot[i].pr == 1 then code = eboot[i] end
end
if not code then code = exec[1] end
if not code then
    print("[B] no executable view found; only the device window can be tested")
    print("=== PROBE 1481e INCOMPLETE ===")
    return
end
print(string.format("[B] code view   0x%X-0x%X prot=0x%X", code.s, code.e, code.pr))
print("      " .. hex32(code.s, 16))

-- ---------------------------------------------------------------- [C] compare, no writes
print("")
print("--- [C] compare the two views at five offsets (read only) ---")
local OFFS = {0x0, 0x1000, 0x8000, 0x10000, 0x40000}
local equal, nonzero = 0, 0
for _, off in ipairs(OFFS) do
    if dev.s + off + 4 <= dev.e and code.s + off + 4 <= code.e then
        local a = rd(dev.s + off)
        local b = rd(code.s + off)
        local same = (a ~= nil and b ~= nil and a == b)
        if same then equal = equal + 1 end
        if a and a ~= 0 then nonzero = nonzero + 1 end
        print(string.format("[C] +0x%-6X dev=%s code=%s %s",
            off, a and string.format("%08X", a) or "????????",
            b and string.format("%08X", b) or "????????",
            same and "SAME" or ""))
    end
end
print(string.format("[C] %d of %d offsets agree, %d device dwords non-zero", equal, #OFFS, nonzero))

-- ---------------------------------------------------------------- [D] the alias test
print("")
print("--- [D] write through the device view, read the code view ---")
local MARK = 0x51A5F00D
local done = false
for _, off in ipairs(OFFS) do
    if not done and dev.s + off + 4 <= dev.e and code.s + off + 4 <= code.e then
        local a = rd(dev.s + off)
        local b = rd(code.s + off)
        if a == 0 and b == 0 then
            print(string.format("[D] offset +0x%X: both views read zero, writing %08X", off, MARK))
            pcall(function() memory.write_dword(dev.s + off, uint64(MARK)) end)
            local da = rd(dev.s + off)
            local db = rd(code.s + off)
            print(string.format("[D]   dev reads %s, code reads %s -> %s",
                da and string.format("%08X", da) or "????????",
                db and string.format("%08X", db) or "????????",
                (db == MARK) and "*** THE CODE VIEW SEES THE WRITE (SAME PAGES) ***" or "different pages"))
            pcall(function() memory.write_dword(dev.s + off, uint64(0)) end)
            print(string.format("[D]   restored: dev=%s code=%s",
                tostring(rd(dev.s + off)), tostring(rd(code.s + off))))
            done = true
        end
    end
end
if not done then
    print("[D] no offset where both views read zero; the write test was not run")
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481e COMPLETE ===")
