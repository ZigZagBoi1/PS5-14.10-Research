-- CRASH_CLASS: MODERATE (skips the known-lethal numbers; every pointer argument is a mapped 0x200 buffer)
-- PROBE 1197a: the errno census. 1196b proved the loader's return path does expose errno, and that
-- 608/659/660 were reachable all along (EFAULT = "give me a valid pointer"). This probe calls every
-- number in 600..680 with six argument shapes and groups the results by errno, so the next round of
-- struct work targets only handlers that are demonstrably implemented.
print("=== PROBE 1197a: SONY RANGE ERRNO CENSUS (600..680) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local B = N(memory.alloc(0x200))
local C = N(memory.alloc(0x20))
local function sent() for o=0,0x1FC,4 do wd(B+o,0xA5A5A5A5) end for o=0,0x1C,4 do wd(C+o,0xA5A5A5A5) end end
local SKIP = {[601]=true,[622]=true,[637]=true,[677]=true,[678]=true,[645]=true}
local SHAPES = {
  "buf,0,0,0,0", "0,buf,0,0,0", "0,0,buf,0,0", "0,0,0,buf,0", "0,0,0,0,buf", "buf,0x200,0x200,0x200,0x200",
}
local function callshape(f, k)
  if k==1 then return f(U(B),U(0),U(0),U(0),U(0)) end
  if k==2 then return f(U(0),U(B),U(0),U(0),U(0)) end
  if k==3 then return f(U(0),U(0),U(B),U(0),U(0)) end
  if k==4 then return f(U(0),U(0),U(0),U(B),U(0)) end
  if k==5 then return f(U(0),U(0),U(0),U(0),U(B)) end
  return f(U(B),U(0x200),U(0x200),U(0x200),U(0x200))
end
local byerr = {}
local function note(e, n) if not byerr[e] then byerr[e]={} end local t=byerr[e] if t[#t]~=n then t[#t+1]=n end end
local oklist = {}
for n=600,680 do
  if not SKIP[n] then
    local f = mk(n)
    for k=1,#SHAPES do
      sent()
      local ok, rv = pcall(function() return callshape(f,k) end)
      if not ok then note("PCALLFAIL", n)
      else
        local r = N(rv)
        if r == 0 then note("SUCCESS", n); oklist[n]=true
        else note(es(), n) end
      end
    end
  end
end
for e,t in pairs(byerr) do
  local s={} for i=1,#t do s[#s+1]=tostring(t[i]) end
  print(string.format("%-30s : %s", e, table.concat(s,",")))
end
print("[Z] alive")
print("=== DONE ===")
