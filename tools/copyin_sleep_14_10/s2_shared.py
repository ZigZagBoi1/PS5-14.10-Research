
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *

seen,calls,order=walk(0x5620e0, max_ins=1500)
print("insns",len(order),"calls",len(calls))
for a,t,o in calls: print("call @%08x -> %s (%s)"%(a,o, hex(t) if t else 'ind'))
print("----- first 90 -----")
for a in order[:90]:
    i=seen[a]; print("%08x  %-22s %s %s"%(a,i.bytes.hex(),i.mnemonic,i.op_str))
