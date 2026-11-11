import sys, json
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import fstart
def show(site, backn=20, headn=5):
    fs=fstart(site) or (site-0x80)
    il=A.dis_window(fs, site+8)
    k=None
    for j,ins in enumerate(il):
        if ins.address-A.BASE==site: k=j; break
        if ins.address-A.BASE>site: break
    if k is None:
        print("!! %06x misaligned (fs=%06x)"%(site,fs)); return
    print("### site %06x  fs %06x  insn#%d"%(site,fs,k))
    lo=max(0,k-backn)
    for j in range(0, min(headn,k)):
        i=il[j]; print("   %06x  %-24s %s %s"%(i.address-A.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
    if lo>headn: print("   ...")
    for j in range(lo,k+1):
        i=il[j]; print("   %06x  %-24s %s %s"%(i.address-A.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
if __name__=="__main__":
    for a in sys.argv[1:]:
        s=int(a,16); show(s)
