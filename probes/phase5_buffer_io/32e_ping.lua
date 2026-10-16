-- 14.10 Recon Probe 32e: bare minimum ping
print("=== PING ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())
print("=== PONG ===")
