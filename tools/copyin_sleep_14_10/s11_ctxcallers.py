
import sys, pickle, collections
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
calls=pickle.load(open(r"C:\PS5contrib\tools\copyin_sleep_14_10\calls.pkl","rb"))
by=collections.defaultdict(list)
for site,t in calls: by[t].append(site)
tgts=sorted(t for t in by if 0x250000<=t<0x253000)
print("targets in 0x250000-0x253000:",len(tgts))
for t in tgts:
    sites=sorted(by[t])
    print("%08x  n=%-3d sites=%s"%(t,len(sites),[hex(s) for s in sites[:8]]))
