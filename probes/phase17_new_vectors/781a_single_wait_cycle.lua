-- CRASH_CLASS: LOW
-- PROBE 781a: one request, one wait, one cancel, in a clean process
--
-- Context: 780a ran inside a process whose aio workers were already saturated
-- (every request stayed in state 1, not started), because earlier in-flight
-- requests cannot be deleted (delete wants state 3 or 4). This probe does the
-- smallest possible cycle so nothing can be left behind:
--   submit -> poll -> wait(10ms, mode 0) -> poll -> cancel -> poll -> delete
-- and repeats it once to show the second cycle behaves the same.

print("=== PROBE 781a: SINGLE WAIT CYCLE ===")

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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local sink   = to_num(memory.alloc(0x2000))
local req    = to_num(memory.alloc(0x1000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local tmo    = to_num(memory.alloc(0x40))
local fds    = to_num(memory.alloc(64))

local SOCKETPAIR = 135
local AIO_DEL, AIO_WAIT, AIO_POLL, AIO_CANCEL, AIO_SUBMIT = 662, 663, 664, 666, 669

local function state_of(id)
    wd(ids, id)
    wd(states, 0xDEADBEEF)
    local r = sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
    return r, rd(states)
end

local function cycle(tag)
    wd(fds, 0); wd(fds + 4, 0)
    local pr = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
    local rfd = rd(fds)
    wq(req + 0x00, Z)
    wq(req + 0x08, U(16))
    wq(req + 0x10, U(sink))
    wq(req + 0x18, U(sink + 0x1000))
    wd(req + 0x20, rfd)
    wd(req + 0x24, 0)
    local sr = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req), U(1), U(3), U(idout), Z))
    local id = rd(idout)
    print(string.format("[%s] pair=%d rfd=%d submit=%d id=%s", tag, pr, rfd, sr, hx(id)))

    local pr1, st1 = state_of(id)
    print(string.format("[%s] poll1 ret=%d state=%s", tag, pr1, hx(st1)))

    wd(tmo, 10000)
    wd(ids, id)
    wd(states, 0xDEADBEEF)
    local wr = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), Z, U(tmo), Z))
    print(string.format("[%s] wait ret=%d states=%s", tag, wr, hx(rd(states))))

    local pr2, st2 = state_of(id)
    print(string.format("[%s] poll2 ret=%d state=%s", tag, pr2, hx(st2)))

    wd(ids, id)
    wd(states, 0xDEADBEEF)
    local cr = sgn(make_syscall(AIO_CANCEL)(U(ids), U(1), U(states), Z, Z, Z))
    print(string.format("[%s] cancel ret=%d states=%s", tag, cr, hx(rd(states))))

    local pr3, st3 = state_of(id)
    print(string.format("[%s] poll3 ret=%d state=%s", tag, pr3, hx(st3)))

    wd(ids, id)
    wd(states, 0xDEADBEEF)
    local dr = sgn(make_syscall(AIO_DEL)(U(ids), U(1), U(states), Z, Z, Z))
    print(string.format("[%s] delete ret=%d status=%s", tag, dr, hx(rd(states))))
end

cycle("A")
cycle("B")
print("=== PROBE 781a DONE ===")
