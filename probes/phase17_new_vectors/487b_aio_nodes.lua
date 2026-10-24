-- CRASH_CLASS: LOW
-- PROBE 487b: is there an aio device node to create the context table?
-- 662 runs its delete body on 14.10 but no id resolves (16k ids, 0 hits) and
-- 661/668 kill on every shape. If a devfs node owns the table, opening it may
-- create the per-process context that 662 indexes.
print("=== PROBE 487b: aio device nodes ===")
io.stdout:setvbuf("no")
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
local function put_str(buf, s)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
end
local sc_open = make_syscall(5)
local names = {"/dev/aio","/dev/aio0","/dev/aio1","/dev/sce_aio","/dev/sceAio","/dev/Aio",
               "/dev/aioc","/dev/aioctl","/dev/aio_multi","/dev/async","/dev/kqueue",
               "/dev/ajm","/dev/dce"}
local buf = memory.alloc(0x100)
for _, n in ipairs(names) do
  put_str(buf, n)
  local ok, rv = pcall(function() return sc_open(uint64(buf), uint64(2), uint64(0)) end)
  print(string.format("  open(%-14s) ok=%s rv=%s", n, tostring(ok), ok and tostring(to_num(rv)) or "-"))
end
print("=== PROBE 487b COMPLETE ===")
