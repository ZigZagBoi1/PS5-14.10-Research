-- CRASH_CLASS: LOW
-- PROBE 978a: device nodes beyond null/zero/urandom
--
-- 930a only asked /dev, /dev/null, /dev/zero, /dev/urandom, /dev/dmem0. The jail may
-- still expose klog (dmesg), bpf, crypto, mem or a tty, any of which would be a
-- different kernel surface from the syscall table.
print("=== PROBE 978a: DEVICE NODES ===")
print("")
local PATHS = {
    "/dev/klog", "/dev/console", "/dev/tty", "/dev/mem", "/dev/kmem",
    "/dev/random", "/dev/ptmx", "/dev/fd/0", "/dev/stdin", "/dev/stdout",
    "/dev/bpf", "/dev/bpf0", "/dev/crypto", "/dev/ipfw", "/dev/pf",
    "/dev/kqueue", "/dev/event", "/dev/tap", "/dev/uhid", "/dev/sndstat",
    "/dev/ata", "/dev/da0", "/dev/ada0", "/dev/null", "/dev/zero",
    "/dev/urandom", "/dev/dmem0", "/dev/gpu", "/dev/video0", "/dev/ao",
    "/dev/cd0", "/dev/ugen0", "/dev/console0",
}
for i=1,#PATHS do
    local p = PATHS[i]
    local ok, f = pcall(function() return io.open(p, "rb") end)
    if ok and f then
        local data = nil
        local ok2, d = pcall(function() return f:read(64) end)
        if ok2 and d and #d > 0 then
            local s = ""
            for j=1,math.min(#d, 32) do
                local c = string.byte(d, j)
                if c>=32 and c<127 then s = s .. string.char(c) else s = s .. string.format("\\x%02x", c) end
            end
            data = string.format(" %d bytes: %s", #d, s)
        else
            data = " open, empty"
        end
        pcall(function() f:close() end)
        print(string.format("  [OK] %-18s%s", p, data))
    end
end
print("[Z] done")
print("=== COMPLETE ===")
