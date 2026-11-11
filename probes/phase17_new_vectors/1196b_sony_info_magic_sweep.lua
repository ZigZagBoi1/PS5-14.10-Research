-- CRASH_CLASS: MODERATE (all args are mapped pointers / small ints; a bad handler can still die)
-- PROBE 1196b: the magic-word class. 674 needed uap+0x20 == 0x40000000 and no earlier sweep ever
-- passed it, so 674 looked dead for a year. Here every "info" syscall in the Sony range is offered the
-- same handful of structured shapes. Report rv + errno + whether the buffer changed.
print("=== PROBE 1196b: STRUCTURED-ARGUMENT SWEEP OF THE SONY INFO FAMILY ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hx(n) n = n % 4294967296 local hi = math.floor(n/65536) local lo = n - hi*65536 return string.format("%04X%04X", hi, lo) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local B = N(memory.alloc(0x800))
local function sent() for o=0,0x7FC,4 do wd(B+o,0xA5A5A5A5) end end
local function changed()
  local n=0
  for i=0,0x1FF do if rd(B+i*4)~=0xA5A5A5A5 then n=n+1 end end
  return n
end
local function head()
  local t={}
  for i=0,3 do t[#t+1]=hx(rd(B+i*4)) end
  return table.concat(t," ")
end
local TARGETS = {
  {646,"get_kernel_mem_statistics"},{671,"get_page_table_stats"},{642,"get_map_statistics"},
  {618,"paging_stats_objects"},{611,"paging_stats_threads"},{613,"get_resident_count"},
  {615,"get_resident_fmem_count"},{627,"cpu_usage_all"},{641,"cpu_usage_proc"},
  {604,"dl_get_metadata"},{608,"dynlib_get_info_ex"},{649,"dynlib_get_obj_member"},
  {656,"dynlib_info_libdbg"},{659,"dynlib_get_list2"},{660,"dynlib_get_info2"},
  {672,"dynlib_list_libdbg"},{676,"cpumode_yield"},{675,"reserve_2mb_page"},
  {674,"virtual_query_all(CONTROL)"},
}
local SHAPES = {
  {"buf,size,0,0,MAGIC", function(f,b,s) return f(U(b),U(s),U(0),U(0),U(0x40000000)) end},
  {"buf,size,MAGIC,0,0", function(f,b,s) return f(U(b),U(s),U(0x40000000),U(0),U(0)) end},
  {"buf,size,0,MAGIC,0", function(f,b,s) return f(U(b),U(s),U(0),U(0x40000000),U(0)) end},
  {"buf,size,0,0,0x10",  function(f,b,s) return f(U(b),U(s),U(0),U(0),U(0x10)) end},
  {"size,buf,0,0,MAGIC", function(f,b,s) return f(U(s),U(b),U(0),U(0),U(0x40000000)) end},
  {"buf,0,0,0,MAGIC",    function(f,b,s) return f(U(b),U(0),U(0),U(0),U(0x40000000)) end},
}
local survivors ={}
for _,t in ipairs(TARGETS) do
  local n,name = t[1],t[2]
  local f = mk(n)
  local best=nil
  for _,sh in ipairs(SHAPES) do
    sent()
    local ok, rv = pcall(function() return sh[2](f,B,0x400) end)
    local rvs = ok and tostring(N(rv)) or "PCALLFAIL"
    local ch = changed()
    if rvs~="4294967295" or ch>0 then
      print(string.format("%-4d %-26s %-20s rv=%-12s errno=%-26s changed=%-6d %s", n, name, sh[1], rvs, es(), ch, ch>0 and head() or ""))
      if rvs~="4294967295" then best=rvs end
    end
  end
  if best then survivors[#survivors+1]=n end
end
print("[SUM] syscalls that returned something other than -1: "..(#survivors>0 and table.concat(survivors,",") or "none"))
print("[Z] alive")
print("=== DONE ===")
