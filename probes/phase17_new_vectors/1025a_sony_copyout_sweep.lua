-- CRASH_CLASS: MODERATE
-- PROBE 1025a: every Sony number 532-676 with a user buffer, under the SIGSYS shield
--
-- Every earlier sweep called the numbers with six zeros, so a handler that writes only
-- when it is given a buffer was indistinguishable from an absent slot. This one hands each
-- number a 0xCC sentinel page and asks two layouts: (out, len) and (arg, out, len). A
-- touched buffer proves the handler ran and wrote something; a supervisor-range qword in
-- what it wrote is the whole point of the exercise.
--
-- The shield (struct sigaction, SIG_IGN for 12) turns the nosys death into -1, so the
-- sweep survives absent slots. 561/562 are skipped: both are known to park or kill the
-- caller regardless of disposition. A marker prints before each call, so a wedge names
-- the number that caused it.

print("=== PROBE 1025a: SONY COPYOUT SWEEP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return to_num(v) end return nil end
local function hi(v) return math.floor(v/4294967296) end

local buf = memory.alloc(0x1000); local ba = as_addr(buf)
local SENT = 0xCCCCCCCC   -- exactly representable in a Lua double; 0xCCCCCCCCCCCCCCCC is not
local function fill() for o=0,0xFF8,8 do wq(ba+o, SENT) end end
local function touched()
    local n = 0
    for o=0,0xFF8,8 do
        local v = rq(ba+o)
        if v and v ~= SENT then n = n + 1 end
    end
    return n
end

-- shield
local act = memory.alloc(0x28); local aa = as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa, 1)
local sc_sig = mk(416); local sc_pid = mk(20)
local okS = pcall(function() return sc_sig(uint64(12), uint64(aa), uint64(0)) end)
local ctl = mk(4095)
local okc, ctlv = pcall(function() return ctl(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[0] shield=%s control4095=%s pid=%d", tostring(okS), okc and tostring(to_num(ctlv)) or "KILLED", to_num(select(2,pcall(function() return sc_pid() end)))))
if not okc then print("shield not effective; aborting"); return end

local skip = {[561]=true,[562]=true,[622]=true}  -- 561/562 park, 622 dies on a non-command arg2
local shapes = {
    {"A", function(sc) return sc(uint64(ba), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0)) end},
    {"B", function(sc) return sc(uint64(0), uint64(ba), uint64(0x100), uint64(0), uint64(0), uint64(0)) end},
    {"C", function(sc) return sc(uint64(0), uint64(0), uint64(ba), uint64(0x100), uint64(0), uint64(0)) end},
}
local interesting = 0
for n = 532, 676 do
    if not skip[n] then
        local sc = mk(n)
        for _, sh in ipairs(shapes) do
            fill()
            print(string.format("  > %d%s", n, sh[1]))
            local ok, rv = pcall(function() return sh[2](sc) end)
            local r = ok and to_num(rv) or -999
            local t = touched()
            if t > 0 or (r ~= 0xFFFFFFFF and r ~= -999) then
                local vals, kp = {}, 0
                for o=0,0x38,8 do
                    local v = rq(ba+o)
                    if v then
                        vals[#vals+1] = string.format("%X", v)
                        if hi(v) >= 0xFFFF8000 and hi(v) ~= 0xFFFFFFFF then kp = kp + 1 end
                    end
                end
                print(string.format("  %d%s rv=%d touched=%d kp=%d %s", n, sh[1], r, t, kp, table.concat(vals, " ")))
                interesting = interesting + 1
            end
        end
    end
end
print(string.format("[Z] interesting=%d alive pid=%d", interesting, to_num(select(2,pcall(function() return sc_pid() end)))))
print("=== COMPLETE ===")
