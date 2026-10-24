-- CRASH_CLASS: MODERATE
-- PROBE 500a: aio descriptor layout
-- Every job so far used a zeroed 0x28 descriptor, so the kernel never had an operation
-- to run. FreeBSD aiocb and a compact Sony 0x28 record both start with op/fd, so test
-- four field orders against a real file fd and look for the file's bytes in the buffer.
print("=== PROBE 500a: aio descriptor layout ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
local desc = memory.alloc(0x40)
local out, st = memory.alloc(0x40), memory.alloc(0x40)
local ids = memory.alloc(0x20)
local buf = memory.alloc(0x200)
local function zero(p, n) for o = 0, n - 1, 4 do pcall(function() memory.write_dword(p + o, 0) end) end end
local function wq(p, v) pcall(function() memory.write_qword(p, uint64(v)) end) end
local function wd(p, v) pcall(function() memory.write_dword(p, v) end) end
local function rq(p) local ok, v = pcall(function() return memory.read_qword(p) end); if ok then return v end return nil end
-- open the loader's own source as read material
local fd = nil
do
  local ok, v = pcall(function() return syscall.open("/savedata0/thread.lua", 0) end)
  if ok then fd = to_num(v) end
end
print("open thread.lua -> fd " .. tostring(fd))
-- fall back to a path we know exists if that open failed
if not fd or fd == 0 then
  local ok, v = pcall(function() return syscall.open("/app0/sce_sys/param.json", 0) end)
  if ok then fd = to_num(v) end
  print("fallback open -> fd " .. tostring(fd))
end
local layouts = {
  { name = "op0 fd4 off8 buf10 len18", op = 0x00, fd = 0x04, off = 0x08, buf = 0x10, len = 0x18 },
  { name = "op0 fd4 buf8 len10 off18", op = 0x00, fd = 0x04, buf = 0x08, len = 0x10, off = 0x18 },
  { name = "op0 buf4 lenC off14 fd1C", op = 0x00, buf = 0x04, len = 0x0C, off = 0x14, fd = 0x1C },
  { name = "op18 buf8 len10 off0 fd4", op = 0x18, buf = 0x08, len = 0x10, off = 0x00, fd = 0x04 },
}
for li, L in ipairs(layouts) do
  zero(desc, 0x40); zero(out, 0x40); zero(st, 0x40); zero(buf, 0x200); zero(ids, 0x20)
  pcallaay = nil
  wd(desc + L.op, 1)
  if fd and fd > 0 then wd(desc + L.fd, fd) end
  wq(desc + L.off, 0)
  wq(desc + L.buf, (type(buf) == "userdata") and tostring(to_num(buf)) or 0)
  wq(desc + L.len, 64)
  -- the address helpers in this loader take uint64 via tostring for pointers
  local bufa = to_num(buf) or 0
  pcall(function() memory.write_qword(desc + L.buf, uint64(string.format("0x%X", bufa))) end)
  local okc, ret = pcall(function() return sc669(uint64(1), uint64(desc), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  print(string.format("[%d] %s ret=%s id=%d", li, L.name, tostring(ret), id))
  if id > 0 then
    pcall(function() memory.write_dword(ids, id) end)
    local last = 0
    for k = 1, 200 do
      zero(st, 0x40)
      pcall(function() return sc664(uint64(ids), uint64(1), uint64(st)) end)
      last = to_num(memory.read_dword(st))
      if last == 3 then break end
    end
    local s = ""
    for o = 0, 31 do s = s .. string.format("%02x", to_num(memory.read_byte(buf + o)) or 0) end
    print(string.format("[%d] poll=%x buf=%s", li, last, s))
    zero(st, 0x40)
    pcall(function() return sc662(uint64(ids), uint64(1), uint64(st)) end)
    print(string.format("[%d] delete=%x", li, to_num(memory.read_dword(st))))
  end
end
print("=== PROBE 500a COMPLETE ===")
