p = r"C:\PS5contrib\docs\COPYOUT_LENGTH_AUDIT_14_10.md"
b = open(p,"rb").read()
print("bytes", len(b), "first3", b[:3].hex())
try:
    b.decode("ascii"); print("ascii OK")
except Exception as e:
    print("NONASCII", e)
print("lf", b.count(b"\n"), "crlf", b.count(b"\r\n"))
