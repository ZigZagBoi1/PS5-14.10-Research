-- CRASH_CLASS: MODERATE
-- PROBE 1241a: is syscall 393 (sendfile) present on 14.10?
--
-- Context: the 13.60 capture has 393 with narg=7 and a real thunk at 0x265b88, and the
-- offline suite still carries a standing failure (test_no_sendfile_in_the_corpus) because
-- some doc claimed sendfile absent while the capture contains it. No probe in this
-- repository has ever called 393 on 14.10, and CLAD.md's dead-end list never mentions it.
-- On this firmware an absent sysent slot delivers SIGSYS and kills the connection's loader
-- process, so presence is directly observable: the print immediately before the call
-- arrives, and nothing after it does.
--
-- The 7th argument (flags) cannot be supplied by this loader (six argument registers only);
-- the kernel reads it from the user stack and sendfile rejects unknown flag bits with
-- EINVAL, so an arbitrary value there is safe.

print("=== PROBE 1241a: SENDFILE PRESENCE ===")
print("")

local function N(v)
  if type(v) == "table" and v.tonumber then return v:tonumber() end
  return tonumber(v) or 0
end
local function mk(n)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = n
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function ES()
  local ok, s = pcall(function() return get_error_string() end)
  if ok and s then return tostring(s) end
  return "?"
end
local function Z(n)
  local b = memory.alloc(n)
  for i = 0, n - 1 do memory.write_byte(b + i, 0) end
  return b
end
local function G(a)
  local ok, v = pcall(function() return memory.read_qword(a) end)
  if ok then return N(v) end
  return nil
end
local function D(a)
  local ok, v = pcall(function() return memory.read_dword(a) end)
  if ok then return N(v) end
  return nil
end
local function put(s, n)
  local p = Z(n + 1)
  for i = 1, #s do memory.write_byte(p + i - 1, s:byte(i)) end
  memory.write_byte(p + #s, 0)
  return p
end

local pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("[id] pid=" .. pid)

local path = put("/app0/eboot.bin", 0x20)
local fd = N(mk(5)(uint64(path), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("[setup] open(/app0/eboot.bin) -> " .. fd .. " (rv==-1 means errno=" .. ES() .. ")")

local fds = Z(8)
local rv_sp = N(mk(135)(uint64(1), uint64(1), uint64(0), uint64(fds), uint64(0), uint64(0)))
local s0 = D(fds)
local s1 = D(fds + 4)
print("[setup] socketpair rv=" .. rv_sp .. " fds=" .. tostring(s0) .. "," .. tostring(s1) .. " (rv==-1 means errno=" .. ES() .. ")")

local sb = Z(8)
print("[call] 393(fd=" .. fd .. ", s=" .. tostring(s1) .. ", off=0, nbytes=0x100, hdtr=NULL, sbytes=&out)")
print("[call] a SIGSYS death from an absent slot stops the output here")
local rv = N(mk(393)(uint64(fd), uint64(s1), uint64(0), uint64(0x100), uint64(0), uint64(sb)))
print("[call] rv=" .. rv .. " sbytes=" .. tostring(G(sb)))
if rv == -1 then print("[call] errno=" .. ES()) end

if rv == 0 and s1 and s1 > 0 then
  local buf = Z(0x100)
  for i = 0, 0xFF do memory.write_byte(buf + i, 0xCD) end
  local n = N(mk(29)(uint64(s0), uint64(buf), uint64(0x100), uint64(0x80), uint64(0), uint64(0)))
  print("[recv] n=" .. n)
  if n == -1 then print("[recv] errno=" .. ES()) end
  if n > 0 then
    local out = {}
    for i = 0, math.min(n, 32) - 1 do
      out[#out + 1] = string.format("%02X", N(memory.read_byte(buf + i)))
    end
    print("[recv] first bytes = " .. table.concat(out, " "))
    local ok, hdr = pcall(function() return memory.read_qword(buf) end)
    print("[recv] first qword as number = " .. tostring(ok and N(hdr) or "?") .. " (ELF magic 7F 45 4C 46 expected)")
  end
end

if s0 then pcall(function() mk(6)(uint64(s0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end
if s1 then pcall(function() mk(6)(uint64(s1), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end
if fd and fd > 0 then pcall(function() mk(6)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end

print("")
print("=== DONE ===")
