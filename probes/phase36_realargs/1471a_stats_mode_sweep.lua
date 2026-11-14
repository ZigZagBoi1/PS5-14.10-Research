-- CRASH_CLASS: LOW
-- PROBE 1471a: 671 get_page_table_stats and 642 get_map_statistics -- sweep the mode space
--
-- Context:
--   671 is named get_page_table_stats in the 13.60 table.  The only measurement on record used
--   sel=-1 with modes 1 and 2 and read two numbers back (6144/3948 and 2560/2014); explicit
--   selectors 0-10 were refused because they need credential bit 62, which a game process does not
--   have.  So the SELF path works and only two modes were ever tried.  A statistics call that
--   returns a page-table COUNT is harmless; one that returns a page-table ADDRESS, or copies a
--   record out, would be the first kernel pointer this project has ever seen from a syscall.
--
--   642 get_map_statistics is the same shape for the VM map and has never been swept at all.
--
--   The probe walks mode 0..0x40 for both, with a zeroed output buffer each time, and prints only
--   the calls that return 0 or write something.  sel = -1 (self) is used because the selector
--   space is credential-gated.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt (671 in the arg1 sweep)
--   results/phase17_new_vectors/55e*.txt (671 modes 1/2, 642 never swept)
--   docs/SYSENT_PRESENCE_14_10.md

print("=== PROBE 1471a: 671 / 642 MODE SWEEP ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function hx(v) if v==nil then return "--------" end return string.format("%08X", v) end

local function call(sc, a1, a2, a3, a4, a5, a6)
    a3 = a3 or 0; a4 = a4 or 0; a5 = a5 or 0; a6 = a6 or 0
    local ok, rv = pcall(function() return sc(uint64(a1),uint64(a2),uint64(a3),uint64(a4),uint64(a5),uint64(a6)) end)
    if not ok then return nil end
    return to_num(rv)
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local out = as_addr(memory.alloc(0x400))
local function clear() for o = 0, 0x3F8, 8 do wq(out + o, 0) end end
local function dump()
    local parts, n = {}, 0
    for o = 0, 0x3C, 4 do
        local v = rd(out + o)
        if v ~= 0 then n = n + 1; parts[#parts + 1] = string.format("+%02X=%s", o, hx(v)) end
    end
    return n, table.concat(parts, " ")
end

local function sweep(name, sc, sel)
    print(string.format("[%s] sel=%d, modes 0..0x40", name, sel))
    for mode = 0, 0x40 do
        clear()
        local rv = call(sc, sel, mode, out, 0x40, 0, 0)
        if rv == nil then
            print(string.format("   mode=0x%02X EXC", mode))
        elseif rv ~= -1 then
            local n, s = dump()
            print(string.format("   mode=0x%02X rv=%d written=%d %s", mode, rv, n, s))
        else
            local n, s = dump()
            if n > 0 then print(string.format("   mode=0x%02X rv=-1 %s BUT wrote %d: %s", mode, es(), n, s)) end
        end
    end
    print("")
end

sweep("671", mk(671), -1)
sweep("642", mk(642), -1)

print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1471a COMPLETE ===")
