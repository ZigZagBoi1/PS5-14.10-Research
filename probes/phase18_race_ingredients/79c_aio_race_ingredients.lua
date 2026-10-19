-- 79c: Relapse kernel-stage INGREDIENT check on 14.10 (zero crash risk).
-- The Relapse race (dead since 14.00) needs three ingredients:
--   (a) ioctl(0xffffffff, churn, buf) fast-faults with -1  (speculation window)
--   (b) aio syscall family 661-669 present and callable
--   (c) aio_create(668) succeeds (proc aio_info gate the UAF rides on)
-- If all three are alive on 14.10, Sony's fix is localized to AIO node
-- lifetime/locking, NOT removal of the attack surface -- that distinction
-- tells the next kernel-dump diff exactly where to look.
-- All calls use bogus ids/buffers: copyin faults are handled, bad ids
-- return ESRCH/EINVAL. Nothing here can reach the race window itself.
print("=== PROBE 79c: AIO RACE INGREDIENTS ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function call(num, ...)
    local ok, rv = pcall(function()
        local sc = {}
        for k, v in pairs(syscall.pipe) do sc[k] = v end
        sc.syscall_no = num
        setmetatable(sc, getmetatable(syscall.pipe))
        local args = {}
        for i = 1, select("#", ...) do
            local a = select(i, ...)
            args[i] = (type(a) == "table" and a) or uint64(a)
        end
        return sc(table.unpack(args))
    end)
    if not ok then return "THREW:" .. tostring(rv) end
    return q(rv)
end

syscall.resolve({ sc_getpid = 20 })
print("canary_getpid=" .. tostring(syscall.sc_getpid():tonumber()))

local buf     = memory.alloc(0x100)   -- generic scratch (valid copyin source)
local ids     = memory.alloc(0x10)
local states  = memory.alloc(0x100)
local timeout = memory.alloc(0x10)    -- Relapse convention: usec u32 at +0
memory.write_dword(ids, 0, 0x7FFFFFFF)      -- id that was never created
memory.write_dword(timeout, 0, 1)           -- 1 usec
memory.write_qword(buf, 0)

-- (a) bad-fd ioctl fast fault: Relapse preflight REQUIRES -1 here.
-- churn encoding per relapse_exploit.js: (0x80000000 | (len<<16) | 0x4101)
local churn = 0x80000000 | ((4 * 0x60) << 16) | 0x4101
print("[54 ] ioctl(-1, 0x4101, buf)          rv=" .. call(54, 0xFFFFFFFF, 0x4101, buf))
print("[54 ] ioctl(-1, churn, buf)           rv=" .. call(54, 0xFFFFFFFF, churn, buf))

-- (c) aio_create: the gate. Expect 0 (allocates proc aio_info).
print("[668] aio_create                      rv=" .. call(668))

-- (b) family presence with a never-created id. Expect -1/errno, NOT -1-ENOSYS
-- style refusal and NOT a hang.
print("[661] aio_submit(bogus)               rv=" .. call(661, buf, 1, buf))
print("[662] aio_multi_delete(bogus)         rv=" .. call(662, ids, 1, states))
print("[663] aio_multi_wait(bogus,1us)       rv=" .. call(663, ids, 1, states, 0, timeout))
print("[664] aio_multi_poll(bogus)           rv=" .. call(664, ids, 1, states))
print("[665] aio_get_data(bogus)             rv=" .. call(665, 0x7FFFFFFF, buf, 8))
print("[666] aio_multi_cancel(bogus)         rv=" .. call(666, ids, 1, states))
print("[669] aio_submit_cmd(READ,zeroed)     rv=" .. call(669, 1, buf, 1, 3, ids))

-- Re-do submit_cmd AFTER aio_create so aio_info exists (this is the exact
-- call shape Relapse's spray uses; zeroed node should still fail validation).
print("[669] aio_submit_cmd(post-create)     rv=" .. call(669, 1, buf, 1, 3, ids))

local ok2, pid2 = pcall(function() return syscall.sc_getpid():tonumber() end)
print("canary2_getpid=" .. tostring(pid2))
print("=== PROBE 79c COMPLETE ===")
print("JUDGE: ioctl rows must be -1 (ingredient a). 668 must be 0 (c).")
print("663/664/669 returning errno (not ENOSYS) = family alive (b).")
print("All alive + race still loses => fix is node-lifetime only.")
