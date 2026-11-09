-- CRASH_CLASS: MODERATE
-- PROBE 697a: what does the mmap offset mean? Write a canary at page 1 of an
-- offset-0 mapping, then map offset 0x1000 and see whether the canary is there
-- (offset is a byte offset into one window) or not (separate windows).
print("=== PROBE 697a: DMEM OFFSET MODEL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return -1 end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local A=N(select(2,pcall(function() return mk(477)(U(0),U(0x4000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] fd=%d A(off0)=0x%X A[0]=%016X A[1000]=%016X",fd,A,rq(A),rq(A+0x1000)))
pcall(function() memory.write_qword(A+0x1000,uint64("0x00000000FACEFEED")) end)
print(string.format("[B] wrote canary at A+1000 -> %016X",rq(A+0x1000)))
local B=N(select(2,pcall(function() return mk(477)(U(0),U(0x1000),U(3),U(1),U(fd),U(0x1000)) end)))
print(string.format("[C] B(off1000)=0x%X B[0]=%016X",B,rq(B)))
local C=N(select(2,pcall(function() return mk(477)(U(0),U(0x1000),U(3),U(1),U(fd),U(0x20000)) end)))
print(string.format("[D] C(off20000)=0x%X C[0]=%016X",C,rq(C)))
pcall(function() memory.write_qword(C,uint64("0x00000000FEEDFACE")) end)
print(string.format("[E] C[0] after write=%016X ; A[20000]=%016X",rq(C),rq(A+0x20000)))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
