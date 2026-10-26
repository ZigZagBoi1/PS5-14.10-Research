-- CRASH_CLASS: LOW
-- PROBE 566e: run the failing init line one operand at a time
print("=== PROBE 566e: INIT LINE ===")
local function wd(addr, value) pcall(function() memory.write_dword(addr, value) end) end
local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
local fds = memory.alloc(0x20)
local msg = memory.alloc(0x20)
print("alloc ok")
for i = 0, 0x1F do
    print("i=" .. i)
    wd(result + i * 4, 0)
    print("  result ok")
    wd(ids + i * 4, 0)
    print("  ids ok")
    wd(states + i * 4, 0)
    print("  states ok")
    wd(reqs + i * 8, 0)
    print("  reqs ok")
    wd(fds + i * 4, 0)
    print("  fds ok")
    wd(msg + i * 4, 0)
    print("  msg ok")
end
print("=== 566e DONE ===")
