
import sys
from array import array
N=15132096
own=array('i',[-1])*N
b=open(r'C:\PS5contrib\tools\_own.bin','rb').read()
print('file bytes',len(b),'expect',4*N)
own.frombytes(b)
c=sum(1 for x in own if x!=-1)
print('verified boundaries',c)
print(own[0x5304eb], own[0x279814], own[0x6bdffc])
