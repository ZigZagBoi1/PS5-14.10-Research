
import json
cls={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_cls.json"))}
for r in (0x5f9f5b,0x7b03e0,0x60eb3e,0x73b343,0xc02a34):
    c=cls[r]
    print(hex(r), "fall=", [hex(x) for x in (c.get("calls_fall") or [])], "taken=", [hex(x) for x in (c.get("calls_taken") or [])],
          "| jcc=", c.get("jcc"), c.get("target") and hex(c["target"]))
