-- CRASH_CLASS: LOW
-- PROBE 85i: kevent test with dword writes only

print("=== PROBE 85i ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- kqueue
local kq = to_num(make_syscall(362)())
print("kq=" .. kq)

-- pipe
local pipebuf = memory.alloc(8)
memory.write_dword(pipebuf, 0)
memory.write_dword(pipebuf + 4, 0)
syscall.pipe(uint64(pipebuf))
local pipe_rd = to_num(memory.read_dword(pipebuf))
local pipe_wr = to_num(memory.read_dword(pipebuf + 4))
print("pipes=" .. pipe_rd .. "," .. pipe_wr)

-- Write data to pipe
local wbuf = memory.alloc(8)
memory.write_dword(wbuf, 0x41414141)
memory.write_dword(wbuf + 4, 0x42424242)
syscall.write(uint64(pipe_wr), uint64(wbuf), uint64(8))
print("wrote")

-- kevent struct (32 bytes): ident(8) filter(2)+flags(2)+fflags(4)=8 data(8) udata(8)
local changelist = memory.alloc(32)
memory.write_qword(changelist, uint64(pipe_rd))  -- ident
-- filter=EVFILT_READ=-1 (0xFFFF), flags=EV_ADD=1 → combined dword = 0x0001FFFF
memory.write_dword(changelist + 8, 0x0001FFFF)
memory.write_dword(changelist + 12, 0)            -- fflags
memory.write_qword(changelist + 16, uint64(0))    -- data
memory.write_qword(changelist + 24, uint64(0xDEAD)) -- udata

local eventlist = memory.alloc(128)
for i = 0, 124, 4 do memory.write_dword(eventlist + i, 0) end

local timeout = memory.alloc(16)
memory.write_qword(timeout, uint64(0))
memory.write_qword(timeout + 8, uint64(0))

print("calling kevent")
local ok, ret = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(changelist), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

if ok then
    local n = to_num(ret)
    print("n=" .. n)
    for ev = 0, math.min(n - 1, 3) do
        local base = eventlist + ev * 32
        for off = 0, 24, 8 do
            local q = memory.read_qword(base + off)
            local h, l = get_hi_lo(q)
            print(string.format("ev%d+0x%02X=%s", ev, off, tostring(q)))
            if h >= 0xFFFF8000 then print("  *** KPTR ***") end
        end
    end
end

syscall.close(uint64(kq))
syscall.close(uint64(pipe_rd))
syscall.close(uint64(pipe_wr))
print("=== PROBE 85i COMPLETE ===")
