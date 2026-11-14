-- CRASH_CLASS: MODERATE (arg2 is an unmapped but in-range user address; copyin turns that into EFAULT,
-- raw-deref commands are the skipped ones. arg3 = 0 everywhere.)
-- PROBE 1194d: which 601 commands consume a STRUCT from arg2?
-- Stage two begins with copyin(arg2, stack, 0x3c). A command that copyin's from arg2 answers EFAULT(14)
-- when arg2 is unmapped. Commands that ignore arg2 do not. This is the struct-consumer detector.
print("=== PROBE 1194d: 601 ARG2 STRUCT-CONSUMER DETECTOR ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local sc = mk(601)
local BAD = 0x500000000000
local ok0, base = pcall(function() return N(memory.alloc(0x100)) end)
local SKIP = {[0x00]=true,[0x03]=true,[0x04]=true,[0x08]=true,[0x0C]=true,[0x1B]=true,[0x27]=true}
print("[S] unmapped arg2 = "..string.format("0x%08X%08X", math.floor(BAD/4294967296), BAD % 4294967296))
local hits = {}
for cmd=0,0x27 do
  if not SKIP[cmd] then
    local ok, ret = pcall(function() return sc(U(cmd), U(BAD), U(0), U(0), U(0), U(0)) end)
    local rv, er = "PCALLFAIL", "-"
    if ok then rv = tostring(N(ret)) er = es() end
    if er == "14" or (type(er)=="string" and string.find(er,"Bad address")) then hits[#hits+1] = cmd end
    print(string.format("[%02X] rv=%-3s errno=%s", cmd, rv, er))
  end
end
print("[SUM] EFAULT-on-bad-arg2 = "..table.concat(hits, ","))
print("[Z] alive")
print("=== DONE ===")
