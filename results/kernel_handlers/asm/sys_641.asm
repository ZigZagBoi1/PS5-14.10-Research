; REA 6.7.0 full disassembly of handler_641.bin
; SHA256 f1e7bb90afcf3cc6c29b7864af10139f3f3ac206e7e153c2f30d15a88e0751c2; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25f28, kernel RVA 0x265f28.
; REA inspect_with_objdump Evidence: ev_1457313697d41ef226bc8d483bdcea70fac613334a6546bc1611d8c141e31422
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 641; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_641.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25f28 <handler_641_entry>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266f20+0x23bec0>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266f20+0x856bb0>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266f20+0x7d0740>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266f20+0x8572a0>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266f20+0x857890>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266f20+0x7912d0>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266f20+0x9825f0>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266f20+0x740df0>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266f20+0x742640>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266f20+0x742ef0>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266f20+0x743020>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266f20+0x694520>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266f20+0x23c280>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266f20+0x857990>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266f20+0x7442d0>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266f20+0x854a60>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266f20+0x4923c0>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266f20+0x1cde80>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266f20+0x1cde90>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266f20+0x1cdea0>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266f20+0x1d0e70>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266f20+0x1d1360>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266f20+0x87f770>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266f20+0x87f660>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266f20+0x1e21b0>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_641_entry-0x1bf168>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266f20+0x1e3b50>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266f20+0x74f1f0>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_641_entry-0x1be8b8>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_641_entry-0x1be6d8>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_641_entry-0x1be6a8>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266f20+0x1eb120>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266f20+0x1edda0>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266f20+0x1f0900>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266f20+0x207050>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266f20+0x207160>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266f20+0x20ba70>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266f20+0x20c490>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266f20+0x20c990>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266f20+0x20d330>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266f20+0x20de90>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266f20+0x2160d0>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_641_entry-0x47f38>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266f20+0x2293e0>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266f20+0x229e90>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266f20+0x231090>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266f20+0x2310c0>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266f20+0x231710>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266f20+0x231720>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266f20+0x690ca0>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266f20+0x68f8e0>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266f20+0x690500>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266f20+0x693060>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266f20+0x378430>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266f20+0x378900>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266f20+0x7cddc0>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266f20+0x381580>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266f20+0x6912d0>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266f20+0x6924f0>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266f20+0x6954d0>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266f20+0x68fd70>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266f20+0xa4aaf0>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266f20+0x851480>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266f20+0x851490>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266f20+0x6932a0>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266f20+0x690c20>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266f20+0x239a40>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266f20+0x4c2860>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266f20+0x4c2870>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266f20+0x4c2880>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266f20+0x454670>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266f20+0x851e80>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266f20+0x693250>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266f20+0x9181a0>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266f20+0x9181e0>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266f20+0x692dd0>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266f20+0x693820>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266f20+0x2ebc50>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266f20+0x2ebcd0>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266f20+0x2ebd30>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266f20+0x2ebd60>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266f20+0x2ebd90>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266f20+0x2ebdc0>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266f20+0x9178e0>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266f20+0x917cc0>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266f20+0x918050>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266f20+0x99fe10>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266f20+0x52b770>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266f20+0x381c00>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266f20+0x2ebdf0>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266f20+0x918240>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266f20+0x377330>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266f20+0x7edb10>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266f20+0x7edb20>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266f20+0x7edb30>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266f20+0x7edb40>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266f20+0x7edb60>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266f20+0x7edb70>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266f20+0x692800>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266f20+0x7edb90>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266f20+0x68f5c0>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266f20+0x68efd0>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266f20+0x7edb00>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266f20+0x7edb50>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266f20+0x7edb80>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266f20+0x47e5b0>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266f20+0x918590>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266f20+0x5d6740>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266f20+0x5d68a0>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266f20+0x5d6b90>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266f20+0x5d6f60>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266f20+0x692d60>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266f20+0x6931f0>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266f20+0x692290>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266f20+0x6935d0>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266f20+0x691170>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266f20+0x694c60>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266f20+0x690c60>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266f20+0x690970>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266f20+0x694980>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266f20+0x6915f0>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266f20+0x6918e0>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266f20+0x234160>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266f20+0x234170>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266f20+0x2f8b30>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266f20+0x9cd950>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266f20+0x575dd0>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266f20+0x575de0>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266f20+0x575df0>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266f20+0x575e00>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266f20+0x575e10>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266f20+0x33fd70>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266f20+0x3403e0>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266f20+0x3406f0>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266f20+0x3409e0>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266f20+0xa35910>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266f20+0x340fe0>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266f20+0x341150>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266f20+0x981560>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266f20+0x234180>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266f20+0x2341a0>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266f20+0x2341b0>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266f20+0x2341c0>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266f20+0x2341d0>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266f20+0x2c9800>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266f20+0x2ca750>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266f20+0x6927d0>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266f20+0x2ca310>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266f20+0x59bed0>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266f20+0x918220>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266f20+0x87c6c0>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266f20+0x287f00>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266f20+0x693bf0>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266f20+0x693f10>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266f20+0x762300>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266f20+0x7621e0>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266f20+0x3db3f0>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266f20+0x3db900>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266f20+0x3dc7c0>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266f20+0x3dc9b0>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266f20+0x3dcd40>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266f20+0x791370>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266f20+0x794c50>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266f20+0x7de360>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266f20+0xa20d80>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266f20+0x7980e0>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266f20+0x799860>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266f20+0x7998c0>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266f20+0x857910>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266f20+0x796010>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266f20+0x38a0a0>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266f20+0x6904d0>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266f20+0x290330>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266f20+0x796bb0>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266f20+0x796e90>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266f20+0x796ff0>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266f20+0x3dd5b0>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266f20+0x3ea0b0>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266f20+0x797b10>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266f20+0x290a20>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266f20+0x851bc0>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266f20+0x854740>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266f20+0x797340>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266f20+0x7975c0>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266f20+0x797710>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266f20+0x531410>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266f20+0x8560e0>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_641_entry-0x169698>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266f20+0x238170>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266f20+0x2382e0>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266f20+0x259670>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266f20+0x259690>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_641_entry-0x1bcaf8>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266f20+0x263430>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266f20+0x263b20>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_641_entry-0x1bba18>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266f20+0x26e2b0>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266f20+0x5aa290>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_641_entry-0x24b098>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266f20+0x289110>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266f20+0x294cb0>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266f20+0x2a5fb0>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266f20+0x2a5fc0>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266f20+0x2a6010>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266f20+0x2a6050>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266f20+0x2a6090>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266f20+0x2a60c0>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266f20+0x2b75b0>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266f20+0x2b8040>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266f20+0x2b80e0>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266f20+0x2b8190>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266f20+0x2b83c0>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266f20+0x2b8750>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266f20+0x2b8fc0>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266f20+0x2cf4e0>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266f20+0x2ddd80>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266f20+0x2df9d0>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_641_entry-0x1b48f8>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_641_entry-0x1b3f78>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266f20+0x2f5020>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266f20+0x2f5110>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266f20+0x2f5130>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266f20+0x3072e0>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266f20+0x318580>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266f20+0x72d6c0>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266f20+0x31ea30>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266f20+0x332900>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266f20+0x3334c0>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266f20+0x333610>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266f20+0x3337e0>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266f20+0x3338b0>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266f20+0x333b30>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266f20+0x333c40>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266f20+0x333d40>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266f20+0x374fb0>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266f20+0x384800>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266f20+0x385110>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266f20+0x385bb0>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266f20+0x386520>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266f20+0x386c10>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_641_entry-0x117ca8>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266f20+0x38a990>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266f20+0x38bc10>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266f20+0x3961a0>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266f20+0x399760>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266f20+0x39a020>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266f20+0x87f580>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266f20+0x3c6b80>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266f20+0x3c93b0>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266f20+0x3cdff0>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266f20+0x3d8600>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266f20+0x3f0a90>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266f20+0xa403f0>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266f20+0x3fbf50>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266f20+0x3fbf60>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266f20+0x411ef0>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266f20+0x411f40>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266f20+0x411fa0>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266f20+0x412040>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266f20+0x412270>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266f20+0x412440>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266f20+0x412760>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_641_entry-0x232398>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_641_entry-0x232288>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_641_entry-0x232208>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_641_entry-0x228fb8>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_641_entry-0x228e48>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_641_entry-0x2288c8>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_641_entry-0x227e28>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_641_entry-0x227dc8>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_641_entry-0x227d68>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_641_entry-0x226eb8>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_641_entry-0x226e58>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_641_entry-0x226a78>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_641_entry-0x226a18>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_641_entry-0x2269b8>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_641_entry-0x226378>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_641_entry-0x225f68>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_641_entry-0x2255c8>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_641_entry-0x2253d8>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_641_entry-0x2252f8>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_641_entry-0x2248f8>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_641_entry-0x2247d8>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_641_entry-0x2246f8>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_641_entry-0x224668>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_641_entry-0x223ec8>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_641_entry-0x223a58>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_641_entry-0x223988>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_641_entry-0x223928>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266f20+0x429110>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266f20+0x42fda0>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266f20+0x4316b0>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266f20+0x43b130>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266f20+0x43b390>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266f20+0x447720>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266f20+0x4478d0>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_641_entry-0xe4b78>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266f20+0x458080>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_641_entry-0xddee8>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266f20+0x469be0>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266f20+0x46a1e0>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266f20+0x46a340>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266f20+0x46a4c0>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266f20+0x46a600>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266f20+0x46a720>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266f20+0x46a800>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266f20+0x475740>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266f20+0x475770>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266f20+0x475780>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266f20+0x479a00>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266f20+0x47a520>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266f20+0x47a530>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_641_entry-0xdc4b8>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_641_entry-0xd5488>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266f20+0x49ba50>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266f20+0x49be40>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266f20+0x49f250>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266f20+0x49f2d0>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266f20+0x4a8fe0>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266f20+0x4a9090>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266f20+0x4a92a0>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266f20+0x4a9400>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266f20+0x4abc90>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266f20+0x4af440>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266f20+0x4c8a50>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266f20+0x4c8a70>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266f20+0x4c8b00>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_641_entry-0x1f0f8>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266f20+0x4fd8d0>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266f20+0x50c7f0>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266f20+0x50ea30>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266f20+0x532f70>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266f20+0x54c2d0>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266f20+0x57b480>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266f20+0x5814c0>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266f20+0x581560>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266f20+0x9d4290>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266f20+0x9d57c0>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266f20+0x9d5770>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266f20+0x9d5810>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266f20+0x59b300>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266f20+0x59b5d0>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266f20+0x5a5650>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266f20+0x5c43e0>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266f20+0x6b9fc0>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266f20+0x6b9c70>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266f20+0x5c98f0>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266f20+0x5c9fe0>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266f20+0x5ce390>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266f20+0x5ce3a0>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266f20+0x5ce3b0>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266f20+0x5ce3d0>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266f20+0x5ce520>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266f20+0x5ce530>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266f20+0x5ce570>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266f20+0x5cebb0>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266f20+0x5e9950>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266f20+0x6093d0>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266f20+0x6096b0>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266f20+0x60bbd0>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266f20+0x60c8e0>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_641_entry-0x2024e8>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_641_entry-0x1ffbb8>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_641_entry-0x17f998>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_641_entry-0x17f988>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_641_entry-0x17f7c8>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_641_entry-0x17f6b8>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_641_entry-0x17df98>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_641_entry-0x17bf88>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_641_entry-0x17b8b8>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_641_entry-0x17b7c8>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_641_entry-0x17ae88>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_641_entry-0x17ad98>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_641_entry-0x178f28>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_641_entry-0x178e18>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266f20+0x623980>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266f20+0x635ed0>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_641_entry-0x1773d8>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266f20+0x664330>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266f20+0x664470>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266f20+0x66c040>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266f20+0x66c070>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266f20+0x671310>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266f20+0x671ec0>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266f20+0x672890>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266f20+0x6729f0>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266f20+0x6735a0>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266f20+0x673650>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266f20+0x673690>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266f20+0x69dd60>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266f20+0x69df40>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266f20+0x6b64e0>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266f20+0x6b6580>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266f20+0x81b2b0>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266f20+0x8db200>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266f20+0x6fe010>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266f20+0x70f030>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266f20+0x70f2e0>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266f20+0x725a30>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266f20+0x725d10>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266f20+0x726010>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266f20+0x7267c0>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266f20+0x7276b0>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266f20+0x7277e0>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266f20+0x72b250>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266f20+0x72b320>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_641_entry-0x170b28>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266f20+0x73b400>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266f20+0x73e800>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266f20+0x745a80>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266f20+0x745b00>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_641_entry-0xa78e8>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266f20+0x757e00>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266f20+0x75f130>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266f20+0x75f1b0>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266f20+0x75f360>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266f20+0x75f3f0>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266f20+0x75f570>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266f20+0x75f690>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266f20+0x75f970>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266f20+0x762420>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266f20+0x762440>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266f20+0x762450>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266f20+0x762460>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266f20+0x773e90>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266f20+0x774080>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266f20+0x775940>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266f20+0x775d20>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266f20+0x775f60>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266f20+0x7765e0>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266f20+0xa43db0>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266f20+0x7768b0>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266f20+0x776a70>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266f20+0x776c80>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266f20+0x776ce0>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266f20+0x776f30>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266f20+0x776f90>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266f20+0x7770d0>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266f20+0x777150>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266f20+0x7771d0>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266f20+0x779c70>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266f20+0x779db0>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266f20+0x779e50>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266f20+0x779fd0>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266f20+0x77a130>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266f20+0x77a570>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266f20+0x79f6c0>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_641_entry-0x164be8>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266f20+0x7cc010>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266f20+0x7cc7a0>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266f20+0x7d1d70>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266f20+0x803be0>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266f20+0x803c90>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266f20+0x827cf0>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266f20+0x827ee0>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266f20+0x84a890>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266f20+0x859890>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266f20+0x85bbd0>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_641_entry-0x14b7d8>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266f20+0x87a380>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266f20+0x87c4e0>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266f20+0x87c610>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266f20+0x87f4a0>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266f20+0x8a0fc0>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266f20+0x8a1270>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266f20+0x8a1610>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266f20+0x8a18f0>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266f20+0x8a2780>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266f20+0x8a45d0>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_641_entry-0x76e38>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_641_entry-0x75ec8>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_641_entry-0x14a578>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266f20+0x8d4210>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266f20+0x8e0b20>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266f20+0x8e94a0>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266f20+0x8e9ff0>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266f20+0x8ea090>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266f20+0x8ea190>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266f20+0x8ea270>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266f20+0x8ea370>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266f20+0x8ea3b0>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266f20+0x8ea400>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266f20+0x8ef980>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_641_entry-0x1cbe48>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266f20+0x903f50>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266f20+0x904c70>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266f20+0x906a60>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266f20+0x906b80>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266f20+0x907260>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266f20+0x90a400>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266f20+0x90a450>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266f20+0x90a4a0>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266f20+0x90a4f0>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266f20+0x90aa40>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266f20+0x90aab0>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266f20+0x90ab20>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266f20+0x90ab90>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266f20+0x90b700>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

ffffffff8ac26eb8 <neighbor_trampoline_266eb8>:
ffffffff8ac26eb8:	e9 a3 b9 90 00       	jmp    ffffffff8b532860 <neighbor_trampoline_266f20+0x90b940>
ffffffff8ac26ebd:	cc                   	int3
ffffffff8ac26ebe:	cc                   	int3
ffffffff8ac26ebf:	cc                   	int3

ffffffff8ac26ec0 <neighbor_trampoline_266ec0>:
ffffffff8ac26ec0:	e9 0b 23 91 00       	jmp    ffffffff8b5391d0 <neighbor_trampoline_266f20+0x9122b0>
ffffffff8ac26ec5:	cc                   	int3
ffffffff8ac26ec6:	cc                   	int3
ffffffff8ac26ec7:	cc                   	int3

ffffffff8ac26ec8 <neighbor_trampoline_266ec8>:
ffffffff8ac26ec8:	e9 c3 23 91 00       	jmp    ffffffff8b539290 <neighbor_trampoline_266f20+0x912370>
ffffffff8ac26ecd:	cc                   	int3
ffffffff8ac26ece:	cc                   	int3
ffffffff8ac26ecf:	cc                   	int3

ffffffff8ac26ed0 <neighbor_trampoline_266ed0>:
ffffffff8ac26ed0:	e9 1b 25 91 00       	jmp    ffffffff8b5393f0 <neighbor_trampoline_266f20+0x9124d0>
ffffffff8ac26ed5:	cc                   	int3
ffffffff8ac26ed6:	cc                   	int3
ffffffff8ac26ed7:	cc                   	int3

ffffffff8ac26ed8 <neighbor_trampoline_266ed8>:
ffffffff8ac26ed8:	e9 43 25 91 00       	jmp    ffffffff8b539420 <neighbor_trampoline_266f20+0x912500>
ffffffff8ac26edd:	cc                   	int3
ffffffff8ac26ede:	cc                   	int3
ffffffff8ac26edf:	cc                   	int3

ffffffff8ac26ee0 <neighbor_trampoline_266ee0>:
ffffffff8ac26ee0:	e9 7b 25 91 00       	jmp    ffffffff8b539460 <neighbor_trampoline_266f20+0x912540>
ffffffff8ac26ee5:	cc                   	int3
ffffffff8ac26ee6:	cc                   	int3
ffffffff8ac26ee7:	cc                   	int3

ffffffff8ac26ee8 <neighbor_trampoline_266ee8>:
ffffffff8ac26ee8:	e9 93 25 91 00       	jmp    ffffffff8b539480 <neighbor_trampoline_266f20+0x912560>
ffffffff8ac26eed:	cc                   	int3
ffffffff8ac26eee:	cc                   	int3
ffffffff8ac26eef:	cc                   	int3

ffffffff8ac26ef0 <neighbor_trampoline_266ef0>:
ffffffff8ac26ef0:	e9 9b 25 91 00       	jmp    ffffffff8b539490 <neighbor_trampoline_266f20+0x912570>
ffffffff8ac26ef5:	cc                   	int3
ffffffff8ac26ef6:	cc                   	int3
ffffffff8ac26ef7:	cc                   	int3

ffffffff8ac26ef8 <neighbor_trampoline_266ef8>:
ffffffff8ac26ef8:	e9 b3 25 91 00       	jmp    ffffffff8b5394b0 <neighbor_trampoline_266f20+0x912590>
ffffffff8ac26efd:	cc                   	int3
ffffffff8ac26efe:	cc                   	int3
ffffffff8ac26eff:	cc                   	int3

ffffffff8ac26f00 <neighbor_trampoline_266f00>:
ffffffff8ac26f00:	e9 eb 26 91 00       	jmp    ffffffff8b5395f0 <neighbor_trampoline_266f20+0x9126d0>
ffffffff8ac26f05:	cc                   	int3
ffffffff8ac26f06:	cc                   	int3
ffffffff8ac26f07:	cc                   	int3

ffffffff8ac26f08 <neighbor_trampoline_266f08>:
ffffffff8ac26f08:	e9 13 27 91 00       	jmp    ffffffff8b539620 <neighbor_trampoline_266f20+0x912700>
ffffffff8ac26f0d:	cc                   	int3
ffffffff8ac26f0e:	cc                   	int3
ffffffff8ac26f0f:	cc                   	int3

ffffffff8ac26f10 <neighbor_trampoline_266f10>:
ffffffff8ac26f10:	e9 1b 29 91 00       	jmp    ffffffff8b539830 <neighbor_trampoline_266f20+0x912910>
ffffffff8ac26f15:	cc                   	int3
ffffffff8ac26f16:	cc                   	int3
ffffffff8ac26f17:	cc                   	int3

ffffffff8ac26f18 <neighbor_trampoline_266f18>:
ffffffff8ac26f18:	e9 73 9f 91 00       	jmp    ffffffff8b540e90 <neighbor_trampoline_266f20+0x919f70>
ffffffff8ac26f1d:	cc                   	int3
ffffffff8ac26f1e:	cc                   	int3
ffffffff8ac26f1f:	cc                   	int3

ffffffff8ac26f20 <neighbor_trampoline_266f20>:
ffffffff8ac26f20:	e9 fb 9f 91 00       	jmp    ffffffff8b540f20 <neighbor_trampoline_266f20+0x91a000>
ffffffff8ac26f25:	cc                   	int3
ffffffff8ac26f26:	cc                   	int3
ffffffff8ac26f27:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8ae62de0, handler_body_641; REA Evidence ev_46a147fd05b6465bb6a8f5a75ff65cd449ac67a974e00e46ed2be19354e0aa9e
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8ae62de0", "end": "0xffffffff8ae62e98"}, {"start": "0xffffffff8ae62ea0", "end": "0xffffffff8ae62f49"}, {"start": "0xffffffff8ae62f50", "end": "0xffffffff8ae63198"}], "total_bytes": 940, "span_bytes": 953, "non_contiguous": true, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_641:
0xffffffff8ae62de0: PUSH RBP
0xffffffff8ae62de1: MOV RBP, RSP
0xffffffff8ae62de4: PUSH R15
0xffffffff8ae62de6: PUSH R14
0xffffffff8ae62de8: PUSH R13
0xffffffff8ae62dea: PUSH R12
0xffffffff8ae62dec: PUSH RBX
0xffffffff8ae62ded: SUB RSP, 0xe8
0xffffffff8ae62df4: LEA R12, [-0x71d23cf0]
0xffffffff8ae62dfb: MOV R15, RDI
0xffffffff8ae62dfe: MOV R13, RSI
0xffffffff8ae62e01: MOV RAX, qword ptr [R12]
0xffffffff8ae62e05: MOV qword ptr [RBP + -0x30], RAX
0xffffffff8ae62e09: MOV RDI, qword ptr [RDI + 0x140]
0xffffffff8ae62e10: CALL 0xffffffff8afc8f90
0xffffffff8ae62e15: TEST EAX, EAX
0xffffffff8ae62e17: JZ 0xffffffff8ae62f8b
loc_ffffffff8ae62e1d:
0xffffffff8ae62e1d: CALL 0xffffffff8ae62ce0
0xffffffff8ae62e22: LEA RDI, [RBP + -0x68]
0xffffffff8ae62e26: MOV ESI, 0x38
0xffffffff8ae62e2b: CALL 0xffffffff8ac18ff0
0xffffffff8ae62e30: MOV EDI, dword ptr [R13]
0xffffffff8ae62e34: CALL 0xffffffff8aefc170
0xffffffff8ae62e39: TEST RAX, RAX
0xffffffff8ae62e3c: JZ 0xffffffff8ae62f95
loc_ffffffff8ae62e42:
0xffffffff8ae62e42: CMP dword ptr [RAX + 0xb8], 0x1
0xffffffff8ae62e49: MOV R14, RAX
0xffffffff8ae62e4c: JNZ 0xffffffff8ae630c4
loc_ffffffff8ae62e52:
0xffffffff8ae62e52: LEA RDI, [R14 + 0x168]
0xffffffff8ae62e59: MOV qword ptr [RBP + -0x108], R13
0xffffffff8ae62e60: XOR ESI, ESI
0xffffffff8ae62e62: XOR EDX, EDX
0xffffffff8ae62e64: XOR ECX, ECX
0xffffffff8ae62e66: MOV qword ptr [RBP + -0x100], RDI
0xffffffff8ae62e6d: CALL 0xffffffff8ae87190
0xffffffff8ae62e72: MOV R12, qword ptr [R14 + 0x10]
0xffffffff8ae62e76: MOV RBX, 0x431bde82d7b634db
0xffffffff8ae62e80: TEST R12, R12
0xffffffff8ae62e83: JZ 0xffffffff8ae630e3
loc_ffffffff8ae62e89:
0xffffffff8ae62e89: LEA R13, [-0x74395e33]
0xffffffff8ae62e90: LEA R15, [RBP + -0xf8]
0xffffffff8ae62e97: JMP 0xffffffff8ae62ed9
loc_ffffffff8ae62ea0:
0xffffffff8ae62ea0: MULX RAX, RAX, RBX
0xffffffff8ae62ea5: SHR RAX, 0x12
0xffffffff8ae62ea9: IMUL RAX, RAX, 0xf4240
0xffffffff8ae62eb0: SUB RDX, RAX
0xffffffff8ae62eb3: MOV RAX, qword ptr [RBP + -0xe8]
0xffffffff8ae62eba: MOV qword ptr [RBP + -0x48], RDX
0xffffffff8ae62ebe: MOV RCX, qword ptr [RBP + -0x50]
0xffffffff8ae62ec2: LEA RAX, [RAX + RCX*0x1 + 0x1]
loc_ffffffff8ae62ec7:
0xffffffff8ae62ec7: MOV qword ptr [RBP + -0x50], RAX
0xffffffff8ae62ecb: MOV R12, qword ptr [R12 + 0x10]
0xffffffff8ae62ed0: TEST R12, R12
0xffffffff8ae62ed3: JZ 0xffffffff8ae630e3
loc_ffffffff8ae62ed9:
0xffffffff8ae62ed9: MOV RDI, R12
0xffffffff8ae62edc: MOV RDX, R13
0xffffffff8ae62edf: MOV ECX, 0x6a8
0xffffffff8ae62ee4: XOR ESI, ESI
0xffffffff8ae62ee6: CALL 0xffffffff8ae878b0
0xffffffff8ae62eeb: MOV RDI, R12
0xffffffff8ae62eee: MOV RSI, R15
0xffffffff8ae62ef1: CALL 0xffffffff8ae61a20
0xffffffff8ae62ef6: MOV RDI, qword ptr [R12]
0xffffffff8ae62efa: XOR ESI, ESI
0xffffffff8ae62efc: XOR EDX, EDX
0xffffffff8ae62efe: XOR ECX, ECX
0xffffffff8ae62f00: ADD RDI, 0x18
0xffffffff8ae62f04: CALL 0xffffffff8ae87520
0xffffffff8ae62f09: MOV RDX, qword ptr [RBP + -0x58]
0xffffffff8ae62f0d: ADD RDX, qword ptr [RBP + -0xf0]
0xffffffff8ae62f14: MOV qword ptr [RBP + -0x58], RDX
0xffffffff8ae62f18: CMP RDX, 0xf4240
0xffffffff8ae62f1f: JL 0xffffffff8ae62f50
loc_ffffffff8ae62f21:
0xffffffff8ae62f21: MULX RAX, RAX, RBX
0xffffffff8ae62f26: SHR RAX, 0x12
0xffffffff8ae62f2a: IMUL RAX, RAX, 0xf4240
0xffffffff8ae62f31: SUB RDX, RAX
0xffffffff8ae62f34: MOV RAX, qword ptr [RBP + -0xf8]
0xffffffff8ae62f3b: MOV qword ptr [RBP + -0x58], RDX
0xffffffff8ae62f3f: MOV RCX, qword ptr [RBP + -0x60]
0xffffffff8ae62f43: LEA RAX, [RAX + RCX*0x1 + 0x1]
0xffffffff8ae62f48: JMP 0xffffffff8ae62f5b
loc_ffffffff8ae62f50:
0xffffffff8ae62f50: MOV RAX, qword ptr [RBP + -0x60]
0xffffffff8ae62f54: ADD RAX, qword ptr [RBP + -0xf8]
loc_ffffffff8ae62f5b:
0xffffffff8ae62f5b: MOV qword ptr [RBP + -0x60], RAX
0xffffffff8ae62f5f: MOV RDX, qword ptr [RBP + -0x48]
0xffffffff8ae62f63: ADD RDX, qword ptr [RBP + -0xe0]
0xffffffff8ae62f6a: MOV qword ptr [RBP + -0x48], RDX
0xffffffff8ae62f6e: CMP RDX, 0xf4240
0xffffffff8ae62f75: JGE 0xffffffff8ae62ea0
loc_ffffffff8ae62f7b:
0xffffffff8ae62f7b: MOV RAX, qword ptr [RBP + -0x50]
0xffffffff8ae62f7f: ADD RAX, qword ptr [RBP + -0xe8]
0xffffffff8ae62f86: JMP 0xffffffff8ae62ec7
loc_ffffffff8ae62f8b:
0xffffffff8ae62f8b: MOV EAX, 0x4e
0xffffffff8ae62f90: JMP 0xffffffff8ae63176
loc_ffffffff8ae62f95:
0xffffffff8ae62f95: MOV RBX, qword ptr [R15 + 0x8]
0xffffffff8ae62f99: MOV EDI, dword ptr [R13]
0xffffffff8ae62f9d: MOV ESI, dword ptr [RBX + 0xbc]
0xffffffff8ae62fa3: CALL 0xffffffff8b552420
0xffffffff8ae62fa8: TEST RAX, RAX
0xffffffff8ae62fab: JZ 0xffffffff8ae630d9
loc_ffffffff8ae62fb1:
0xffffffff8ae62fb1: LEA R14, [RBX + 0x168]
0xffffffff8ae62fb8: MOV R15, RAX
0xffffffff8ae62fbb: XOR ESI, ESI
0xffffffff8ae62fbd: XOR EDX, EDX
0xffffffff8ae62fbf: XOR ECX, ECX
0xffffffff8ae62fc1: MOV RDI, R14
0xffffffff8ae62fc4: CALL 0xffffffff8ae87190
0xffffffff8ae62fc9: LEA RDX, [-0x74395e33]
0xffffffff8ae62fd0: MOV RDI, R15
0xffffffff8ae62fd3: MOV ECX, 0x68b
0xffffffff8ae62fd8: XOR ESI, ESI
0xffffffff8ae62fda: CALL 0xffffffff8ae878b0
0xffffffff8ae62fdf: LEA RSI, [RBP + -0xf8]
0xffffffff8ae62fe6: MOV RDI, R15
0xffffffff8ae62fe9: CALL 0xffffffff8ae61a20
0xffffffff8ae62fee: MOV RDI, qword ptr [R15]
0xffffffff8ae62ff1: XOR ESI, ESI
0xffffffff8ae62ff3: XOR EDX, EDX
0xffffffff8ae62ff5: XOR ECX, ECX
0xffffffff8ae62ff7: ADD RDI, 0x18
0xffffffff8ae62ffb: CALL 0xffffffff8ae87520
0xffffffff8ae63000: MOV RCX, qword ptr [RBP + -0xf0]
0xffffffff8ae63007: MOV RAX, qword ptr [RBP + -0xf8]
0xffffffff8ae6300e: MOV RDX, qword ptr [RBP + -0xe0]
0xffffffff8ae63015: MOV qword ptr [RBP + -0x58], RCX
0xffffffff8ae63019: MOV RCX, qword ptr [RBP + -0xe8]
0xffffffff8ae63020: MOV qword ptr [RBP + -0x60], RAX
0xffffffff8ae63024: MOV qword ptr [RBP + -0x48], RDX
0xffffffff8ae63028: MOV qword ptr [RBP + -0x50], RCX
0xffffffff8ae6302c: MOV RDI, qword ptr [RBX + 0x2c0]
0xffffffff8ae63033: CALL 0xffffffff8b4909c0
0xffffffff8ae63038: MOV RDI, R14
0xffffffff8ae6303b: MOV R15, RAX
0xffffffff8ae6303e: XOR ESI, ESI
0xffffffff8ae63040: XOR EDX, EDX
0xffffffff8ae63042: XOR ECX, ECX
0xffffffff8ae63044: CALL 0xffffffff8ae87520
0xffffffff8ae63049: MOV RAX, 0x431bde82d7b634db
0xffffffff8ae63053: MOV RDX, R15
0xffffffff8ae63056: LEA RDI, [RBX + 0x148]
0xffffffff8ae6305d: XOR ESI, ESI
0xffffffff8ae6305f: XOR ECX, ECX
0xffffffff8ae63061: MULX RAX, RAX, RAX
0xffffffff8ae63066: XOR EDX, EDX
0xffffffff8ae63068: SHR RAX, 0x12
0xffffffff8ae6306c: MOV qword ptr [RBP + -0x40], RAX
0xffffffff8ae63070: IMUL RAX, RAX, 0xf4240
0xffffffff8ae63077: SUB R15, RAX
0xffffffff8ae6307a: MOV qword ptr [RBP + -0x38], R15
0xffffffff8ae6307e: CALL 0xffffffff8ae86fa0
0xffffffff8ae63083: MOV EAX, dword ptr [RBX + 0xbc]
0xffffffff8ae63089: LEA RSI, [-0x742f0d69]
0xffffffff8ae63090: XOR EDX, EDX
0xffffffff8ae63092: MOV dword ptr [RBP + -0x68], EAX
0xffffffff8ae63095: MOV EAX, dword ptr [R13]
0xffffffff8ae63099: MOV dword ptr [RBP + -0x64], EAX
0xffffffff8ae6309c: MOV RBX, qword ptr [R13 + 0x8]
0xffffffff8ae630a0: MOV RDI, qword ptr GS:[0x0]
0xffffffff8ae630a9: CALL 0xffffffff8b5da3e0
0xffffffff8ae630ae: LEA RDI, [RBP + -0x68]
0xffffffff8ae630b2: MOV EDX, 0x38
0xffffffff8ae630b7: MOV RSI, RBX
0xffffffff8ae630ba: CALL 0xffffffff8ac191d0
0xffffffff8ae630bf: JMP 0xffffffff8ae63176
loc_ffffffff8ae630c4:
0xffffffff8ae630c4: ADD R14, 0x148
0xffffffff8ae630cb: XOR ESI, ESI
0xffffffff8ae630cd: XOR EDX, EDX
0xffffffff8ae630cf: XOR ECX, ECX
0xffffffff8ae630d1: MOV RDI, R14
0xffffffff8ae630d4: CALL 0xffffffff8ae86fa0
loc_ffffffff8ae630d9:
0xffffffff8ae630d9: MOV EAX, 0x3
0xffffffff8ae630de: JMP 0xffffffff8ae63176
loc_ffffffff8ae630e3:
0xffffffff8ae630e3: MOV RDI, qword ptr [R14 + 0x2c0]
0xffffffff8ae630ea: CALL 0xffffffff8b4909c0
0xffffffff8ae630ef: MOV RDI, qword ptr [RBP + -0x100]
0xffffffff8ae630f6: MOV R15, RAX
0xffffffff8ae630f9: XOR ESI, ESI
0xffffffff8ae630fb: XOR EDX, EDX
0xffffffff8ae630fd: XOR ECX, ECX
0xffffffff8ae630ff: CALL 0xffffffff8ae87520
0xffffffff8ae63104: MOV RDX, R15
0xffffffff8ae63107: ADD R14, 0x148
0xffffffff8ae6310e: XOR ESI, ESI
0xffffffff8ae63110: XOR ECX, ECX
0xffffffff8ae63112: MULX RAX, RAX, RBX
0xffffffff8ae63117: MOV RDI, R14
0xffffffff8ae6311a: XOR EDX, EDX
0xffffffff8ae6311c: SHR RAX, 0x12
0xffffffff8ae63120: MOV qword ptr [RBP + -0x40], RAX
0xffffffff8ae63124: IMUL RAX, RAX, 0xf4240
0xffffffff8ae6312b: SUB R15, RAX
0xffffffff8ae6312e: MOV qword ptr [RBP + -0x38], R15
0xffffffff8ae63132: CALL 0xffffffff8ae86fa0
0xffffffff8ae63137: MOV RCX, qword ptr [RBP + -0x108]
0xffffffff8ae6313e: LEA RSI, [-0x742f0d69]
0xffffffff8ae63145: XOR EDX, EDX
0xffffffff8ae63147: MOV EAX, dword ptr [RCX]
0xffffffff8ae63149: MOV dword ptr [RBP + -0x68], EAX
0xffffffff8ae6314c: MOV RBX, qword ptr [RCX + 0x8]
0xffffffff8ae63150: MOV RDI, qword ptr GS:[0x0]
0xffffffff8ae63159: CALL 0xffffffff8b5da3e0
0xffffffff8ae6315e: LEA RDI, [RBP + -0x68]
0xffffffff8ae63162: MOV EDX, 0x38
0xffffffff8ae63167: MOV RSI, RBX
0xffffffff8ae6316a: CALL 0xffffffff8ac191d0
0xffffffff8ae6316f: LEA R12, [-0x71d23cf0]
loc_ffffffff8ae63176:
0xffffffff8ae63176: MOV RCX, qword ptr [R12]
0xffffffff8ae6317a: CMP RCX, qword ptr [RBP + -0x30]
0xffffffff8ae6317e: JNZ 0xffffffff8ae63192
loc_ffffffff8ae63180:
0xffffffff8ae63180: ADD RSP, 0xe8
0xffffffff8ae63187: POP RBX
0xffffffff8ae63188: POP R12
0xffffffff8ae6318a: POP R13
0xffffffff8ae6318c: POP R14
0xffffffff8ae6318e: POP R15
0xffffffff8ae63190: POP RBP
0xffffffff8ae63191: RET
loc_ffffffff8ae63192:
0xffffffff8ae63192: CALL 0xffffffff8b0bd6b0
0xffffffff8ae63197: UD2
; END FUNCTION handler_body_641

; SUPPLEMENTAL DIRECT CALLEE 0xffffffff8ae62ce0; Evidence ev_24a85f2e3ea167b97382abb39da26f2936b7d42aad9967fb328baae282ac8c7d
; Body: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8ae62ce0", "end": "0xffffffff8ae62d25"}, {"start": "0xffffffff8ae62d30", "end": "0xffffffff8ae62da8"}, {"start": "0xffffffff8ae62db0", "end": "0xffffffff8ae62dd0"}], "total_bytes": 224, "span_bytes": 241, "non_contiguous": true, "contains_entry": true}
sub_4a2ce0:
0xffffffff8ae62ce0: PUSH RBP
0xffffffff8ae62ce1: MOV RBP, RSP
0xffffffff8ae62ce4: PUSH R14
0xffffffff8ae62ce6: PUSH RBX
0xffffffff8ae62ce7: LEA RDI, [-0x72109a88]
0xffffffff8ae62cee: XOR R14D, R14D
0xffffffff8ae62cf1: XOR ESI, ESI
0xffffffff8ae62cf3: XOR EDX, EDX
0xffffffff8ae62cf5: XOR ECX, ECX
0xffffffff8ae62cf7: CALL 0xffffffff8ae86a00
0xffffffff8ae62cfc: MOV qword ptr [0xffffffff8def6528], 0x0
0xffffffff8ae62d07: MOV RAX, qword ptr GS:[0x0]
0xffffffff8ae62d10: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0xffffffff8ae62d18: CALL 0xffffffff8b077940
0xffffffff8ae62d1d: MOV EAX, 0x1
0xffffffff8ae62d22: XOR EBX, EBX
0xffffffff8ae62d24: JMP 0xffffffff8ae62d44
loc_ffffffff8ae62d30:
0xffffffff8ae62d30: SHLX RCX, RAX, R14
0xffffffff8ae62d35: OR RBX, RCX
loc_ffffffff8ae62d38:
0xffffffff8ae62d38: INC R14D
0xffffffff8ae62d3b: CMP R14D, dword ptr [0xffffffff8e6ce8b8]
0xffffffff8ae62d42: JA 0xffffffff8ae62d75
loc_ffffffff8ae62d44:
0xffffffff8ae62d44: MOV RCX, qword ptr [0xffffffff8e6ce8e8]
0xffffffff8ae62d4b: BT RCX, R14
0xffffffff8ae62d4f: JNC 0xffffffff8ae62d38
loc_ffffffff8ae62d51:
0xffffffff8ae62d51: MOV ECX, dword ptr GS:[0x34]
0xffffffff8ae62d59: CMP R14D, ECX
0xffffffff8ae62d5c: JNZ 0xffffffff8ae62d30
loc_ffffffff8ae62d5e:
0xffffffff8ae62d5e: MOV ECX, dword ptr GS:[0x34]
0xffffffff8ae62d66: SHLX RCX, RAX, RCX
0xffffffff8ae62d6b: OR.LOCK qword ptr [0xffffffff8def6528], RCX
0xffffffff8ae62d73: JMP 0xffffffff8ae62d30
loc_ffffffff8ae62d75:
0xffffffff8ae62d75: MOV EDI, 0x8
0xffffffff8ae62d7a: CALL 0xffffffff8b1de5b0
0xffffffff8ae62d7f: CALL 0xffffffff8b077960
0xffffffff8ae62d84: MOV RAX, qword ptr GS:[0x0]
0xffffffff8ae62d8d: MOV ECX, 0xffffffff
0xffffffff8ae62d92: XADD.LOCK dword ptr [RAX + 0x5a8], ECX
0xffffffff8ae62d9a: CMP ECX, 0x80000001
0xffffffff8ae62da0: JNZ 0xffffffff8ae62db2
loc_ffffffff8ae62da2:
0xffffffff8ae62da2: CALL 0xffffffff8b077af0
0xffffffff8ae62da7: JMP 0xffffffff8ae62db2
loc_ffffffff8ae62db0:
0xffffffff8ae62db0: PAUSE
loc_ffffffff8ae62db2:
0xffffffff8ae62db2: CMP RBX, qword ptr [0xffffffff8def6528]
0xffffffff8ae62db9: JNZ 0xffffffff8ae62db0
loc_ffffffff8ae62dbb:
0xffffffff8ae62dbb: LEA RDI, [-0x72109a88]
0xffffffff8ae62dc2: XOR ESI, ESI
0xffffffff8ae62dc4: XOR EDX, EDX
0xffffffff8ae62dc6: XOR ECX, ECX
0xffffffff8ae62dc8: POP RBX
0xffffffff8ae62dc9: POP R14
0xffffffff8ae62dcb: POP RBP
0xffffffff8ae62dcc: JMP 0xffffffff8ae86fa0
; END FUNCTION sub_4a2ce0

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_f42190d5c8f7538883436af180330925a0e1c975b7262cbbe069e4b1653e63ea
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_641.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ae62de0 <handler_641_body>:
ffffffff8ae62de0:	55                   	push   %rbp
ffffffff8ae62de1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae62de4:	41 57                	push   %r15
ffffffff8ae62de6:	41 56                	push   %r14
ffffffff8ae62de8:	41 55                	push   %r13
ffffffff8ae62dea:	41 54                	push   %r12
ffffffff8ae62dec:	53                   	push   %rbx
ffffffff8ae62ded:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
ffffffff8ae62df4:	4c 8d 25 15 95 47 03 	lea    0x3479515(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae62dfb:	49 89 ff             	mov    %rdi,%r15
ffffffff8ae62dfe:	49 89 f5             	mov    %rsi,%r13
ffffffff8ae62e01:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8ae62e05:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8ae62e09:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8ae62e10:	e8 7b 61 16 00       	call   ffffffff8afc8f90 <frame_candidate_4a4a40+0x164550>
ffffffff8ae62e15:	85 c0                	test   %eax,%eax
ffffffff8ae62e17:	0f 84 6e 01 00 00    	je     ffffffff8ae62f8b <handler_641_body+0x1ab>
ffffffff8ae62e1d:	e8 be fe ff ff       	call   ffffffff8ae62ce0 <handler_641_body-0x100>
ffffffff8ae62e22:	48 8d 7d 98          	lea    -0x68(%rbp),%rdi
ffffffff8ae62e26:	be 38 00 00 00       	mov    $0x38,%esi
ffffffff8ae62e2b:	e8 c0 61 db ff       	call   ffffffff8ac18ff0 <handler_641_body-0x249df0>
ffffffff8ae62e30:	41 8b 7d 00          	mov    0x0(%r13),%edi
ffffffff8ae62e34:	e8 37 93 09 00       	call   ffffffff8aefc170 <frame_candidate_4a4a40+0x97730>
ffffffff8ae62e39:	48 85 c0             	test   %rax,%rax
ffffffff8ae62e3c:	0f 84 53 01 00 00    	je     ffffffff8ae62f95 <handler_641_body+0x1b5>
ffffffff8ae62e42:	83 b8 b8 00 00 00 01 	cmpl   $0x1,0xb8(%rax)
ffffffff8ae62e49:	49 89 c6             	mov    %rax,%r14
ffffffff8ae62e4c:	0f 85 72 02 00 00    	jne    ffffffff8ae630c4 <handler_641_body+0x2e4>
ffffffff8ae62e52:	49 8d be 68 01 00 00 	lea    0x168(%r14),%rdi
ffffffff8ae62e59:	4c 89 ad f8 fe ff ff 	mov    %r13,-0x108(%rbp)
ffffffff8ae62e60:	31 f6                	xor    %esi,%esi
ffffffff8ae62e62:	31 d2                	xor    %edx,%edx
ffffffff8ae62e64:	31 c9                	xor    %ecx,%ecx
ffffffff8ae62e66:	48 89 bd 00 ff ff ff 	mov    %rdi,-0x100(%rbp)
ffffffff8ae62e6d:	e8 1e 43 02 00       	call   ffffffff8ae87190 <frame_candidate_4a4a40+0x22750>
ffffffff8ae62e72:	4d 8b 66 10          	mov    0x10(%r14),%r12
ffffffff8ae62e76:	48 bb db 34 b6 d7 82 	movabs $0x431bde82d7b634db,%rbx
ffffffff8ae62e7d:	de 1b 43 
ffffffff8ae62e80:	4d 85 e4             	test   %r12,%r12
ffffffff8ae62e83:	0f 84 5a 02 00 00    	je     ffffffff8ae630e3 <handler_641_body+0x303>
ffffffff8ae62e89:	4c 8d 2d 3d 73 e0 00 	lea    0xe0733d(%rip),%r13        # ffffffff8bc6a1cd <frame_candidate_4a4a40+0xe0578d>
ffffffff8ae62e90:	4c 8d bd 08 ff ff ff 	lea    -0xf8(%rbp),%r15
ffffffff8ae62e97:	eb 40                	jmp    ffffffff8ae62ed9 <handler_641_body+0xf9>
ffffffff8ae62e99:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8ae62ea0:	c4 e2 fb f6 c3       	mulx   %rbx,%rax,%rax
ffffffff8ae62ea5:	48 c1 e8 12          	shr    $0x12,%rax
ffffffff8ae62ea9:	48 69 c0 40 42 0f 00 	imul   $0xf4240,%rax,%rax
ffffffff8ae62eb0:	48 29 c2             	sub    %rax,%rdx
ffffffff8ae62eb3:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
ffffffff8ae62eba:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8ae62ebe:	48 8b 4d b0          	mov    -0x50(%rbp),%rcx
ffffffff8ae62ec2:	48 8d 44 08 01       	lea    0x1(%rax,%rcx,1),%rax
ffffffff8ae62ec7:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8ae62ecb:	4d 8b 64 24 10       	mov    0x10(%r12),%r12
ffffffff8ae62ed0:	4d 85 e4             	test   %r12,%r12
ffffffff8ae62ed3:	0f 84 0a 02 00 00    	je     ffffffff8ae630e3 <handler_641_body+0x303>
ffffffff8ae62ed9:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae62edc:	4c 89 ea             	mov    %r13,%rdx
ffffffff8ae62edf:	b9 a8 06 00 00       	mov    $0x6a8,%ecx
ffffffff8ae62ee4:	31 f6                	xor    %esi,%esi
ffffffff8ae62ee6:	e8 c5 49 02 00       	call   ffffffff8ae878b0 <frame_candidate_4a4a40+0x22e70>
ffffffff8ae62eeb:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae62eee:	4c 89 fe             	mov    %r15,%rsi
ffffffff8ae62ef1:	e8 2a eb ff ff       	call   ffffffff8ae61a20 <handler_641_body-0x13c0>
ffffffff8ae62ef6:	49 8b 3c 24          	mov    (%r12),%rdi
ffffffff8ae62efa:	31 f6                	xor    %esi,%esi
ffffffff8ae62efc:	31 d2                	xor    %edx,%edx
ffffffff8ae62efe:	31 c9                	xor    %ecx,%ecx
ffffffff8ae62f00:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8ae62f04:	e8 17 46 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae62f09:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
ffffffff8ae62f0d:	48 03 95 10 ff ff ff 	add    -0xf0(%rbp),%rdx
ffffffff8ae62f14:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
ffffffff8ae62f18:	48 81 fa 40 42 0f 00 	cmp    $0xf4240,%rdx
ffffffff8ae62f1f:	7c 2f                	jl     ffffffff8ae62f50 <handler_641_body+0x170>
ffffffff8ae62f21:	c4 e2 fb f6 c3       	mulx   %rbx,%rax,%rax
ffffffff8ae62f26:	48 c1 e8 12          	shr    $0x12,%rax
ffffffff8ae62f2a:	48 69 c0 40 42 0f 00 	imul   $0xf4240,%rax,%rax
ffffffff8ae62f31:	48 29 c2             	sub    %rax,%rdx
ffffffff8ae62f34:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
ffffffff8ae62f3b:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
ffffffff8ae62f3f:	48 8b 4d a0          	mov    -0x60(%rbp),%rcx
ffffffff8ae62f43:	48 8d 44 08 01       	lea    0x1(%rax,%rcx,1),%rax
ffffffff8ae62f48:	eb 11                	jmp    ffffffff8ae62f5b <handler_641_body+0x17b>
ffffffff8ae62f4a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8ae62f50:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
ffffffff8ae62f54:	48 03 85 08 ff ff ff 	add    -0xf8(%rbp),%rax
ffffffff8ae62f5b:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
ffffffff8ae62f5f:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
ffffffff8ae62f63:	48 03 95 20 ff ff ff 	add    -0xe0(%rbp),%rdx
ffffffff8ae62f6a:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8ae62f6e:	48 81 fa 40 42 0f 00 	cmp    $0xf4240,%rdx
ffffffff8ae62f75:	0f 8d 25 ff ff ff    	jge    ffffffff8ae62ea0 <handler_641_body+0xc0>
ffffffff8ae62f7b:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
ffffffff8ae62f7f:	48 03 85 18 ff ff ff 	add    -0xe8(%rbp),%rax
ffffffff8ae62f86:	e9 3c ff ff ff       	jmp    ffffffff8ae62ec7 <handler_641_body+0xe7>
ffffffff8ae62f8b:	b8 4e 00 00 00       	mov    $0x4e,%eax
ffffffff8ae62f90:	e9 e1 01 00 00       	jmp    ffffffff8ae63176 <handler_641_body+0x396>
ffffffff8ae62f95:	49 8b 5f 08          	mov    0x8(%r15),%rbx
ffffffff8ae62f99:	41 8b 7d 00          	mov    0x0(%r13),%edi
ffffffff8ae62f9d:	8b b3 bc 00 00 00    	mov    0xbc(%rbx),%esi
ffffffff8ae62fa3:	e8 78 f4 6e 00       	call   ffffffff8b552420 <frame_candidate_4a4a40+0x6ed9e0>
ffffffff8ae62fa8:	48 85 c0             	test   %rax,%rax
ffffffff8ae62fab:	0f 84 28 01 00 00    	je     ffffffff8ae630d9 <handler_641_body+0x2f9>
ffffffff8ae62fb1:	4c 8d b3 68 01 00 00 	lea    0x168(%rbx),%r14
ffffffff8ae62fb8:	49 89 c7             	mov    %rax,%r15
ffffffff8ae62fbb:	31 f6                	xor    %esi,%esi
ffffffff8ae62fbd:	31 d2                	xor    %edx,%edx
ffffffff8ae62fbf:	31 c9                	xor    %ecx,%ecx
ffffffff8ae62fc1:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae62fc4:	e8 c7 41 02 00       	call   ffffffff8ae87190 <frame_candidate_4a4a40+0x22750>
ffffffff8ae62fc9:	48 8d 15 fd 71 e0 00 	lea    0xe071fd(%rip),%rdx        # ffffffff8bc6a1cd <frame_candidate_4a4a40+0xe0578d>
ffffffff8ae62fd0:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae62fd3:	b9 8b 06 00 00       	mov    $0x68b,%ecx
ffffffff8ae62fd8:	31 f6                	xor    %esi,%esi
ffffffff8ae62fda:	e8 d1 48 02 00       	call   ffffffff8ae878b0 <frame_candidate_4a4a40+0x22e70>
ffffffff8ae62fdf:	48 8d b5 08 ff ff ff 	lea    -0xf8(%rbp),%rsi
ffffffff8ae62fe6:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae62fe9:	e8 32 ea ff ff       	call   ffffffff8ae61a20 <handler_641_body-0x13c0>
ffffffff8ae62fee:	49 8b 3f             	mov    (%r15),%rdi
ffffffff8ae62ff1:	31 f6                	xor    %esi,%esi
ffffffff8ae62ff3:	31 d2                	xor    %edx,%edx
ffffffff8ae62ff5:	31 c9                	xor    %ecx,%ecx
ffffffff8ae62ff7:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8ae62ffb:	e8 20 45 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae63000:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
ffffffff8ae63007:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
ffffffff8ae6300e:	48 8b 95 20 ff ff ff 	mov    -0xe0(%rbp),%rdx
ffffffff8ae63015:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
ffffffff8ae63019:	48 8b 8d 18 ff ff ff 	mov    -0xe8(%rbp),%rcx
ffffffff8ae63020:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
ffffffff8ae63024:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8ae63028:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8ae6302c:	48 8b bb c0 02 00 00 	mov    0x2c0(%rbx),%rdi
ffffffff8ae63033:	e8 88 d9 62 00       	call   ffffffff8b4909c0 <frame_candidate_4a4a40+0x62bf80>
ffffffff8ae63038:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae6303b:	49 89 c7             	mov    %rax,%r15
ffffffff8ae6303e:	31 f6                	xor    %esi,%esi
ffffffff8ae63040:	31 d2                	xor    %edx,%edx
ffffffff8ae63042:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63044:	e8 d7 44 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae63049:	48 b8 db 34 b6 d7 82 	movabs $0x431bde82d7b634db,%rax
ffffffff8ae63050:	de 1b 43 
ffffffff8ae63053:	4c 89 fa             	mov    %r15,%rdx
ffffffff8ae63056:	48 8d bb 48 01 00 00 	lea    0x148(%rbx),%rdi
ffffffff8ae6305d:	31 f6                	xor    %esi,%esi
ffffffff8ae6305f:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63061:	c4 e2 fb f6 c0       	mulx   %rax,%rax,%rax
ffffffff8ae63066:	31 d2                	xor    %edx,%edx
ffffffff8ae63068:	48 c1 e8 12          	shr    $0x12,%rax
ffffffff8ae6306c:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8ae63070:	48 69 c0 40 42 0f 00 	imul   $0xf4240,%rax,%rax
ffffffff8ae63077:	49 29 c7             	sub    %rax,%r15
ffffffff8ae6307a:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
ffffffff8ae6307e:	e8 1d 3f 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae63083:	8b 83 bc 00 00 00    	mov    0xbc(%rbx),%eax
ffffffff8ae63089:	48 8d 35 07 c2 ea 00 	lea    0xeac207(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_4a4a40+0xeaa857>
ffffffff8ae63090:	31 d2                	xor    %edx,%edx
ffffffff8ae63092:	89 45 98             	mov    %eax,-0x68(%rbp)
ffffffff8ae63095:	41 8b 45 00          	mov    0x0(%r13),%eax
ffffffff8ae63099:	89 45 9c             	mov    %eax,-0x64(%rbp)
ffffffff8ae6309c:	49 8b 5d 08          	mov    0x8(%r13),%rbx
ffffffff8ae630a0:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8ae630a7:	00 00 
ffffffff8ae630a9:	e8 32 73 77 00       	call   ffffffff8b5da3e0 <frame_candidate_4a4a40+0x7759a0>
ffffffff8ae630ae:	48 8d 7d 98          	lea    -0x68(%rbp),%rdi
ffffffff8ae630b2:	ba 38 00 00 00       	mov    $0x38,%edx
ffffffff8ae630b7:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae630ba:	e8 11 61 db ff       	call   ffffffff8ac191d0 <handler_641_body-0x249c10>
ffffffff8ae630bf:	e9 b2 00 00 00       	jmp    ffffffff8ae63176 <handler_641_body+0x396>
ffffffff8ae630c4:	49 81 c6 48 01 00 00 	add    $0x148,%r14
ffffffff8ae630cb:	31 f6                	xor    %esi,%esi
ffffffff8ae630cd:	31 d2                	xor    %edx,%edx
ffffffff8ae630cf:	31 c9                	xor    %ecx,%ecx
ffffffff8ae630d1:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae630d4:	e8 c7 3e 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae630d9:	b8 03 00 00 00       	mov    $0x3,%eax
ffffffff8ae630de:	e9 93 00 00 00       	jmp    ffffffff8ae63176 <handler_641_body+0x396>
ffffffff8ae630e3:	49 8b be c0 02 00 00 	mov    0x2c0(%r14),%rdi
ffffffff8ae630ea:	e8 d1 d8 62 00       	call   ffffffff8b4909c0 <frame_candidate_4a4a40+0x62bf80>
ffffffff8ae630ef:	48 8b bd 00 ff ff ff 	mov    -0x100(%rbp),%rdi
ffffffff8ae630f6:	49 89 c7             	mov    %rax,%r15
ffffffff8ae630f9:	31 f6                	xor    %esi,%esi
ffffffff8ae630fb:	31 d2                	xor    %edx,%edx
ffffffff8ae630fd:	31 c9                	xor    %ecx,%ecx
ffffffff8ae630ff:	e8 1c 44 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae63104:	4c 89 fa             	mov    %r15,%rdx
ffffffff8ae63107:	49 81 c6 48 01 00 00 	add    $0x148,%r14
ffffffff8ae6310e:	31 f6                	xor    %esi,%esi
ffffffff8ae63110:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63112:	c4 e2 fb f6 c3       	mulx   %rbx,%rax,%rax
ffffffff8ae63117:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae6311a:	31 d2                	xor    %edx,%edx
ffffffff8ae6311c:	48 c1 e8 12          	shr    $0x12,%rax
ffffffff8ae63120:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8ae63124:	48 69 c0 40 42 0f 00 	imul   $0xf4240,%rax,%rax
ffffffff8ae6312b:	49 29 c7             	sub    %rax,%r15
ffffffff8ae6312e:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
ffffffff8ae63132:	e8 69 3e 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae63137:	48 8b 8d f8 fe ff ff 	mov    -0x108(%rbp),%rcx
ffffffff8ae6313e:	48 8d 35 52 c1 ea 00 	lea    0xeac152(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_4a4a40+0xeaa857>
ffffffff8ae63145:	31 d2                	xor    %edx,%edx
ffffffff8ae63147:	8b 01                	mov    (%rcx),%eax
ffffffff8ae63149:	89 45 98             	mov    %eax,-0x68(%rbp)
ffffffff8ae6314c:	48 8b 59 08          	mov    0x8(%rcx),%rbx
ffffffff8ae63150:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8ae63157:	00 00 
ffffffff8ae63159:	e8 82 72 77 00       	call   ffffffff8b5da3e0 <frame_candidate_4a4a40+0x7759a0>
ffffffff8ae6315e:	48 8d 7d 98          	lea    -0x68(%rbp),%rdi
ffffffff8ae63162:	ba 38 00 00 00       	mov    $0x38,%edx
ffffffff8ae63167:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae6316a:	e8 61 60 db ff       	call   ffffffff8ac191d0 <handler_641_body-0x249c10>
ffffffff8ae6316f:	4c 8d 25 9a 91 47 03 	lea    0x347919a(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae63176:	49 8b 0c 24          	mov    (%r12),%rcx
ffffffff8ae6317a:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8ae6317e:	75 12                	jne    ffffffff8ae63192 <handler_641_body+0x3b2>
ffffffff8ae63180:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
ffffffff8ae63187:	5b                   	pop    %rbx
ffffffff8ae63188:	41 5c                	pop    %r12
ffffffff8ae6318a:	41 5d                	pop    %r13
ffffffff8ae6318c:	41 5e                	pop    %r14
ffffffff8ae6318e:	41 5f                	pop    %r15
ffffffff8ae63190:	5d                   	pop    %rbp
ffffffff8ae63191:	c3                   	ret
ffffffff8ae63192:	e8 19 a5 25 00       	call   ffffffff8b0bd6b0 <frame_candidate_4a4a40+0x258c70>
ffffffff8ae63197:	0f 0b                	ud2
ffffffff8ae63199:	90                   	nop
ffffffff8ae6319a:	90                   	nop
ffffffff8ae6319b:	90                   	nop
ffffffff8ae6319c:	90                   	nop
ffffffff8ae6319d:	90                   	nop
ffffffff8ae6319e:	90                   	nop
ffffffff8ae6319f:	90                   	nop

ffffffff8ae631a0 <frame_candidate_4a31a0>:
ffffffff8ae631a0:	55                   	push   %rbp
ffffffff8ae631a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae631a4:	41 57                	push   %r15
ffffffff8ae631a6:	41 56                	push   %r14
ffffffff8ae631a8:	41 55                	push   %r13
ffffffff8ae631aa:	41 54                	push   %r12
ffffffff8ae631ac:	53                   	push   %rbx
ffffffff8ae631ad:	48 83 ec 68          	sub    $0x68,%rsp
ffffffff8ae631b1:	4c 8d 35 58 91 47 03 	lea    0x3479158(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae631b8:	48 89 fb             	mov    %rdi,%rbx
ffffffff8ae631bb:	49 89 f7             	mov    %rsi,%r15
ffffffff8ae631be:	49 8b 06             	mov    (%r14),%rax
ffffffff8ae631c1:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8ae631c5:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8ae631cc:	e8 bf 5d 16 00       	call   ffffffff8afc8f90 <frame_candidate_4a4a40+0x164550>
ffffffff8ae631d1:	85 c0                	test   %eax,%eax
ffffffff8ae631d3:	0f 84 ee 02 00 00    	je     ffffffff8ae634c7 <frame_candidate_4a31a0+0x327>
ffffffff8ae631d9:	49 83 3f 00          	cmpq   $0x0,(%r15)
ffffffff8ae631dd:	0f 84 ee 02 00 00    	je     ffffffff8ae634d1 <frame_candidate_4a31a0+0x331>
ffffffff8ae631e3:	49 8b 7f 08          	mov    0x8(%r15),%rdi
ffffffff8ae631e7:	e8 54 f8 2d 00       	call   ffffffff8b142a40 <frame_candidate_4a4a40+0x2de000>
ffffffff8ae631ec:	83 f8 ff             	cmp    $0xffffffff,%eax
ffffffff8ae631ef:	0f 84 cf 03 00 00    	je     ffffffff8ae635c4 <frame_candidate_4a31a0+0x424>
ffffffff8ae631f5:	89 c1                	mov    %eax,%ecx
ffffffff8ae631f7:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8ae631fc:	8d 91 ef d8 ff ff    	lea    -0x2711(%rcx),%edx
ffffffff8ae63202:	81 fa f0 d8 ff ff    	cmp    $0xffffd8f0,%edx
ffffffff8ae63208:	0f 82 f4 03 00 00    	jb     ffffffff8ae63602 <frame_candidate_4a31a0+0x462>
ffffffff8ae6320e:	49 8b 07             	mov    (%r15),%rax
ffffffff8ae63211:	c1 e1 03             	shl    $0x3,%ecx
ffffffff8ae63214:	48 8d 3d 45 6c 0e 03 	lea    0x30e6c45(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_4a4a40+0x30e5420>
ffffffff8ae6321b:	4c 89 bd 78 ff ff ff 	mov    %r15,-0x88(%rbp)
ffffffff8ae63222:	48 c7 45 80 00 00 00 	movq   $0x0,-0x80(%rbp)
ffffffff8ae63229:	00 
ffffffff8ae6322a:	31 f6                	xor    %esi,%esi
ffffffff8ae6322c:	31 d2                	xor    %edx,%edx
ffffffff8ae6322e:	48 89 45 90          	mov    %rax,-0x70(%rbp)
ffffffff8ae63232:	8d 04 89             	lea    (%rcx,%rcx,4),%eax
ffffffff8ae63235:	48 8d 4d 90          	lea    -0x70(%rbp),%rcx
ffffffff8ae63239:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
ffffffff8ae6323d:	c7 45 a8 01 00 00 00 	movl   $0x1,-0x58(%rbp)
ffffffff8ae63244:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
ffffffff8ae6324b:	00 
ffffffff8ae6324c:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6324e:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8ae63252:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8ae63259:	00 
ffffffff8ae6325a:	48 89 45 98          	mov    %rax,-0x68(%rbp)
ffffffff8ae6325e:	48 89 5d c8          	mov    %rbx,-0x38(%rbp)
ffffffff8ae63262:	e8 e9 80 7a 00       	call   ffffffff8b60b350 <frame_candidate_4a4a40+0x7a6910>
ffffffff8ae63267:	4c 8b 3d 12 6c 0e 03 	mov    0x30e6c12(%rip),%r15        # ffffffff8df49e80 <frame_candidate_4a4a40+0x30e5440>
ffffffff8ae6326e:	4d 85 ff             	test   %r15,%r15
ffffffff8ae63271:	0f 84 54 03 00 00    	je     ffffffff8ae635cb <frame_candidate_4a31a0+0x42b>
ffffffff8ae63277:	4c 8d 2d a2 4e 62 01 	lea    0x1624ea2(%rip),%r13        # ffffffff8c488120 <frame_candidate_4a4a40+0x16236e0>
ffffffff8ae6327e:	48 c7 45 80 00 00 00 	movq   $0x0,-0x80(%rbp)
ffffffff8ae63285:	00 
ffffffff8ae63286:	eb 22                	jmp    ffffffff8ae632aa <frame_candidate_4a31a0+0x10a>
ffffffff8ae63288:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8ae6328f:	00 
ffffffff8ae63290:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae63293:	31 f6                	xor    %esi,%esi
ffffffff8ae63295:	31 d2                	xor    %edx,%edx
ffffffff8ae63297:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63299:	e8 02 3d 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae6329e:	4d 8b 3f             	mov    (%r15),%r15
ffffffff8ae632a1:	4d 85 ff             	test   %r15,%r15
ffffffff8ae632a4:	0f 84 21 03 00 00    	je     ffffffff8ae635cb <frame_candidate_4a31a0+0x42b>
ffffffff8ae632aa:	4d 8d a7 48 01 00 00 	lea    0x148(%r15),%r12
ffffffff8ae632b1:	31 f6                	xor    %esi,%esi
ffffffff8ae632b3:	31 d2                	xor    %edx,%edx
ffffffff8ae632b5:	31 c9                	xor    %ecx,%ecx
ffffffff8ae632b7:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae632ba:	e8 41 37 02 00       	call   ffffffff8ae86a00 <frame_candidate_4a4a40+0x21fc0>
ffffffff8ae632bf:	41 83 bf d0 05 00 00 	cmpl   $0x2,0x5d0(%r15)
ffffffff8ae632c6:	02 
ffffffff8ae632c7:	72 c7                	jb     ffffffff8ae63290 <frame_candidate_4a31a0+0xf0>
ffffffff8ae632c9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8ae632d0:	41 83 bf b8 00 00 00 	cmpl   $0x1,0xb8(%r15)
ffffffff8ae632d7:	01 
ffffffff8ae632d8:	75 b6                	jne    ffffffff8ae63290 <frame_candidate_4a31a0+0xf0>
ffffffff8ae632da:	49 63 9f 48 0b 00 00 	movslq 0xb48(%r15),%rbx
ffffffff8ae632e1:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae632e4:	31 f6                	xor    %esi,%esi
ffffffff8ae632e6:	31 d2                	xor    %edx,%edx
ffffffff8ae632e8:	31 c9                	xor    %ecx,%ecx
ffffffff8ae632ea:	e8 b1 3c 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae632ef:	48 89 d8             	mov    %rbx,%rax
ffffffff8ae632f2:	4c 89 ee             	mov    %r13,%rsi
ffffffff8ae632f5:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8ae632fa:	48 c1 e0 03          	shl    $0x3,%rax
ffffffff8ae632fe:	48 8d 3c 80          	lea    (%rax,%rax,4),%rdi
ffffffff8ae63302:	e8 49 58 76 00       	call   ffffffff8b5c8b50 <frame_candidate_4a4a40+0x764110>
ffffffff8ae63307:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae6330a:	49 89 c6             	mov    %rax,%r14
ffffffff8ae6330d:	31 f6                	xor    %esi,%esi
ffffffff8ae6330f:	31 d2                	xor    %edx,%edx
ffffffff8ae63311:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63313:	e8 e8 36 02 00       	call   ffffffff8ae86a00 <frame_candidate_4a4a40+0x21fc0>
ffffffff8ae63318:	41 3b 9f 48 0b 00 00 	cmp    0xb48(%r15),%ebx
ffffffff8ae6331f:	7d 36                	jge    ffffffff8ae63357 <frame_candidate_4a31a0+0x1b7>
ffffffff8ae63321:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae63324:	31 f6                	xor    %esi,%esi
ffffffff8ae63326:	31 d2                	xor    %edx,%edx
ffffffff8ae63328:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6332a:	e8 71 3c 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae6332f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae63332:	4c 89 ee             	mov    %r13,%rsi
ffffffff8ae63335:	e8 b6 5a 76 00       	call   ffffffff8b5c8df0 <frame_candidate_4a4a40+0x7643b0>
ffffffff8ae6333a:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae6333d:	31 f6                	xor    %esi,%esi
ffffffff8ae6333f:	31 d2                	xor    %edx,%edx
ffffffff8ae63341:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63343:	e8 b8 36 02 00       	call   ffffffff8ae86a00 <frame_candidate_4a4a40+0x21fc0>
ffffffff8ae63348:	41 83 bf b8 00 00 00 	cmpl   $0x1,0xb8(%r15)
ffffffff8ae6334f:	01 
ffffffff8ae63350:	74 88                	je     ffffffff8ae632da <frame_candidate_4a31a0+0x13a>
ffffffff8ae63352:	e9 39 ff ff ff       	jmp    ffffffff8ae63290 <frame_candidate_4a31a0+0xf0>
ffffffff8ae63357:	49 8d 5f 38          	lea    0x38(%r15),%rbx
ffffffff8ae6335b:	31 f6                	xor    %esi,%esi
ffffffff8ae6335d:	31 d2                	xor    %edx,%edx
ffffffff8ae6335f:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63361:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63364:	e8 27 3e 02 00       	call   ffffffff8ae87190 <frame_candidate_4a4a40+0x22750>
ffffffff8ae63369:	4d 8b 6f 10          	mov    0x10(%r15),%r13
ffffffff8ae6336d:	4d 85 ed             	test   %r13,%r13
ffffffff8ae63370:	0f 84 e2 00 00 00    	je     ffffffff8ae63458 <frame_candidate_4a31a0+0x2b8>
ffffffff8ae63376:	48 89 9d 70 ff ff ff 	mov    %rbx,-0x90(%rbp)
ffffffff8ae6337d:	4c 89 f3             	mov    %r14,%rbx
ffffffff8ae63380:	c7 45 8c 00 00 00 00 	movl   $0x0,-0x74(%rbp)
ffffffff8ae63387:	eb 73                	jmp    ffffffff8ae633fc <frame_candidate_4a31a0+0x25c>
ffffffff8ae63389:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8ae63390:	41 8b 87 bc 00 00 00 	mov    0xbc(%r15),%eax
ffffffff8ae63397:	31 f6                	xor    %esi,%esi
ffffffff8ae63399:	31 d2                	xor    %edx,%edx
ffffffff8ae6339b:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6339d:	89 03                	mov    %eax,(%rbx)
ffffffff8ae6339f:	41 8b 85 9c 00 00 00 	mov    0x9c(%r13),%eax
ffffffff8ae633a6:	89 43 04             	mov    %eax,0x4(%rbx)
ffffffff8ae633a9:	49 8b 85 b0 05 00 00 	mov    0x5b0(%r13),%rax
ffffffff8ae633b0:	48 89 43 08          	mov    %rax,0x8(%rbx)
ffffffff8ae633b4:	49 8b 85 b8 05 00 00 	mov    0x5b8(%r13),%rax
ffffffff8ae633bb:	48 89 43 10          	mov    %rax,0x10(%rbx)
ffffffff8ae633bf:	49 8b 85 c0 05 00 00 	mov    0x5c0(%r13),%rax
ffffffff8ae633c6:	48 89 43 18          	mov    %rax,0x18(%rbx)
ffffffff8ae633ca:	49 8b 85 c8 05 00 00 	mov    0x5c8(%r13),%rax
ffffffff8ae633d1:	48 89 43 20          	mov    %rax,0x20(%rbx)
ffffffff8ae633d5:	49 8b 7d 00          	mov    0x0(%r13),%rdi
ffffffff8ae633d9:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8ae633dd:	e8 3e 41 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae633e2:	ff 45 8c             	incl   -0x74(%rbp)
ffffffff8ae633e5:	48 8b 45 80          	mov    -0x80(%rbp),%rax
ffffffff8ae633e9:	48 83 c3 28          	add    $0x28,%rbx
ffffffff8ae633ed:	ff c0                	inc    %eax
ffffffff8ae633ef:	48 89 45 80          	mov    %rax,-0x80(%rbp)
ffffffff8ae633f3:	4d 8b 6d 10          	mov    0x10(%r13),%r13
ffffffff8ae633f7:	4d 85 ed             	test   %r13,%r13
ffffffff8ae633fa:	74 47                	je     ffffffff8ae63443 <frame_candidate_4a31a0+0x2a3>
ffffffff8ae633fc:	4c 89 ef             	mov    %r13,%rdi
ffffffff8ae633ff:	48 8d 15 c7 6d e0 00 	lea    0xe06dc7(%rip),%rdx        # ffffffff8bc6a1cd <frame_candidate_4a4a40+0xe0578d>
ffffffff8ae63406:	b9 2f 07 00 00       	mov    $0x72f,%ecx
ffffffff8ae6340b:	31 f6                	xor    %esi,%esi
ffffffff8ae6340d:	e8 9e 44 02 00       	call   ffffffff8ae878b0 <frame_candidate_4a4a40+0x22e70>
ffffffff8ae63412:	49 83 bd b0 05 00 00 	cmpq   $0x0,0x5b0(%r13)
ffffffff8ae63419:	00 
ffffffff8ae6341a:	0f 85 70 ff ff ff    	jne    ffffffff8ae63390 <frame_candidate_4a31a0+0x1f0>
ffffffff8ae63420:	49 83 bd c0 05 00 00 	cmpq   $0x0,0x5c0(%r13)
ffffffff8ae63427:	00 
ffffffff8ae63428:	0f 85 62 ff ff ff    	jne    ffffffff8ae63390 <frame_candidate_4a31a0+0x1f0>
ffffffff8ae6342e:	49 8b 7d 00          	mov    0x0(%r13),%rdi
ffffffff8ae63432:	31 f6                	xor    %esi,%esi
ffffffff8ae63434:	31 d2                	xor    %edx,%edx
ffffffff8ae63436:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63438:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8ae6343c:	e8 df 40 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae63441:	eb b0                	jmp    ffffffff8ae633f3 <frame_candidate_4a31a0+0x253>
ffffffff8ae63443:	48 63 45 8c          	movslq -0x74(%rbp),%rax
ffffffff8ae63447:	48 8b 9d 70 ff ff ff 	mov    -0x90(%rbp),%rbx
ffffffff8ae6344e:	48 c1 e0 03          	shl    $0x3,%rax
ffffffff8ae63452:	4c 8d 2c 80          	lea    (%rax,%rax,4),%r13
ffffffff8ae63456:	eb 03                	jmp    ffffffff8ae6345b <frame_candidate_4a31a0+0x2bb>
ffffffff8ae63458:	45 31 ed             	xor    %r13d,%r13d
ffffffff8ae6345b:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae6345e:	31 f6                	xor    %esi,%esi
ffffffff8ae63460:	31 d2                	xor    %edx,%edx
ffffffff8ae63462:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63464:	e8 b7 40 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae63469:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae6346c:	31 f6                	xor    %esi,%esi
ffffffff8ae6346e:	31 d2                	xor    %edx,%edx
ffffffff8ae63470:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63472:	e8 29 3b 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae63477:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
ffffffff8ae6347b:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae6347e:	48 8d 55 a0          	lea    -0x60(%rbp),%rdx
ffffffff8ae63482:	4c 39 e8             	cmp    %r13,%rax
ffffffff8ae63485:	4c 0f 42 e8          	cmovb  %rax,%r13
ffffffff8ae63489:	44 89 ee             	mov    %r13d,%esi
ffffffff8ae6348c:	e8 8f f0 2d 00       	call   ffffffff8b142520 <frame_candidate_4a4a40+0x2ddae0>
ffffffff8ae63491:	4c 8d 2d 88 4c 62 01 	lea    0x1624c88(%rip),%r13        # ffffffff8c488120 <frame_candidate_4a4a40+0x16236e0>
ffffffff8ae63498:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae6349b:	41 89 c4             	mov    %eax,%r12d
ffffffff8ae6349e:	4c 89 ee             	mov    %r13,%rsi
ffffffff8ae634a1:	e8 4a 59 76 00       	call   ffffffff8b5c8df0 <frame_candidate_4a4a40+0x7643b0>
ffffffff8ae634a6:	45 85 e4             	test   %r12d,%r12d
ffffffff8ae634a9:	0f 84 ef fd ff ff    	je     ffffffff8ae6329e <frame_candidate_4a31a0+0xfe>
ffffffff8ae634af:	48 8d 3d aa 69 0e 03 	lea    0x30e69aa(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_4a4a40+0x30e5420>
ffffffff8ae634b6:	31 f6                	xor    %esi,%esi
ffffffff8ae634b8:	31 d2                	xor    %edx,%edx
ffffffff8ae634ba:	e8 41 8e 7a 00       	call   ffffffff8b60c300 <frame_candidate_4a4a40+0x7a78c0>
ffffffff8ae634bf:	44 89 e0             	mov    %r12d,%eax
ffffffff8ae634c2:	e9 34 01 00 00       	jmp    ffffffff8ae635fb <frame_candidate_4a31a0+0x45b>
ffffffff8ae634c7:	b8 4e 00 00 00       	mov    $0x4e,%eax
ffffffff8ae634cc:	e9 31 01 00 00       	jmp    ffffffff8ae63602 <frame_candidate_4a31a0+0x462>
ffffffff8ae634d1:	48 8d 3d 88 69 0e 03 	lea    0x30e6988(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_4a4a40+0x30e5420>
ffffffff8ae634d8:	4c 89 bd 78 ff ff ff 	mov    %r15,-0x88(%rbp)
ffffffff8ae634df:	31 db                	xor    %ebx,%ebx
ffffffff8ae634e1:	31 f6                	xor    %esi,%esi
ffffffff8ae634e3:	31 d2                	xor    %edx,%edx
ffffffff8ae634e5:	31 c9                	xor    %ecx,%ecx
ffffffff8ae634e7:	e8 64 7e 7a 00       	call   ffffffff8b60b350 <frame_candidate_4a4a40+0x7a6910>
ffffffff8ae634ec:	4c 8b 2d 8d 69 0e 03 	mov    0x30e698d(%rip),%r13        # ffffffff8df49e80 <frame_candidate_4a4a40+0x30e5440>
ffffffff8ae634f3:	4d 85 ed             	test   %r13,%r13
ffffffff8ae634f6:	0f 84 ad 00 00 00    	je     ffffffff8ae635a9 <frame_candidate_4a31a0+0x409>
ffffffff8ae634fc:	4c 8d 35 ca 6c e0 00 	lea    0xe06cca(%rip),%r14        # ffffffff8bc6a1cd <frame_candidate_4a4a40+0xe0578d>
ffffffff8ae63503:	31 db                	xor    %ebx,%ebx
ffffffff8ae63505:	eb 24                	jmp    ffffffff8ae6352b <frame_candidate_4a31a0+0x38b>
ffffffff8ae63507:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8ae6350e:	00 00 
ffffffff8ae63510:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae63513:	31 f6                	xor    %esi,%esi
ffffffff8ae63515:	31 d2                	xor    %edx,%edx
ffffffff8ae63517:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63519:	e8 82 3a 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae6351e:	4d 8b 6d 00          	mov    0x0(%r13),%r13
ffffffff8ae63522:	4d 85 ed             	test   %r13,%r13
ffffffff8ae63525:	0f 84 7e 00 00 00    	je     ffffffff8ae635a9 <frame_candidate_4a31a0+0x409>
ffffffff8ae6352b:	4d 8d bd 48 01 00 00 	lea    0x148(%r13),%r15
ffffffff8ae63532:	31 f6                	xor    %esi,%esi
ffffffff8ae63534:	31 d2                	xor    %edx,%edx
ffffffff8ae63536:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63538:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae6353b:	e8 c0 34 02 00       	call   ffffffff8ae86a00 <frame_candidate_4a4a40+0x21fc0>
ffffffff8ae63540:	41 83 bd d0 05 00 00 	cmpl   $0x2,0x5d0(%r13)
ffffffff8ae63547:	02 
ffffffff8ae63548:	72 c6                	jb     ffffffff8ae63510 <frame_candidate_4a31a0+0x370>
ffffffff8ae6354a:	41 83 bd b8 00 00 00 	cmpl   $0x1,0xb8(%r13)
ffffffff8ae63551:	01 
ffffffff8ae63552:	75 bc                	jne    ffffffff8ae63510 <frame_candidate_4a31a0+0x370>
ffffffff8ae63554:	4d 8b 65 10          	mov    0x10(%r13),%r12
ffffffff8ae63558:	eb 20                	jmp    ffffffff8ae6357a <frame_candidate_4a31a0+0x3da>
ffffffff8ae6355a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8ae63560:	ff c3                	inc    %ebx
ffffffff8ae63562:	49 8b 3c 24          	mov    (%r12),%rdi
ffffffff8ae63566:	31 f6                	xor    %esi,%esi
ffffffff8ae63568:	31 d2                	xor    %edx,%edx
ffffffff8ae6356a:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6356c:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8ae63570:	e8 ab 3f 02 00       	call   ffffffff8ae87520 <frame_candidate_4a4a40+0x22ae0>
ffffffff8ae63575:	4d 8b 64 24 10       	mov    0x10(%r12),%r12
ffffffff8ae6357a:	4d 85 e4             	test   %r12,%r12
ffffffff8ae6357d:	74 91                	je     ffffffff8ae63510 <frame_candidate_4a31a0+0x370>
ffffffff8ae6357f:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae63582:	4c 89 f2             	mov    %r14,%rdx
ffffffff8ae63585:	b9 ed 06 00 00       	mov    $0x6ed,%ecx
ffffffff8ae6358a:	31 f6                	xor    %esi,%esi
ffffffff8ae6358c:	e8 1f 43 02 00       	call   ffffffff8ae878b0 <frame_candidate_4a4a40+0x22e70>
ffffffff8ae63591:	49 83 bc 24 b0 05 00 	cmpq   $0x0,0x5b0(%r12)
ffffffff8ae63598:	00 00 
ffffffff8ae6359a:	75 c4                	jne    ffffffff8ae63560 <frame_candidate_4a31a0+0x3c0>
ffffffff8ae6359c:	49 83 bc 24 c0 05 00 	cmpq   $0x0,0x5c0(%r12)
ffffffff8ae635a3:	00 00 
ffffffff8ae635a5:	75 b9                	jne    ffffffff8ae63560 <frame_candidate_4a31a0+0x3c0>
ffffffff8ae635a7:	eb b9                	jmp    ffffffff8ae63562 <frame_candidate_4a31a0+0x3c2>
ffffffff8ae635a9:	48 8d 3d b0 68 0e 03 	lea    0x30e68b0(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_4a4a40+0x30e5420>
ffffffff8ae635b0:	31 f6                	xor    %esi,%esi
ffffffff8ae635b2:	31 d2                	xor    %edx,%edx
ffffffff8ae635b4:	e8 47 8d 7a 00       	call   ffffffff8b60c300 <frame_candidate_4a4a40+0x7a78c0>
ffffffff8ae635b9:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
ffffffff8ae635c0:	89 de                	mov    %ebx,%esi
ffffffff8ae635c2:	eb 22                	jmp    ffffffff8ae635e6 <frame_candidate_4a31a0+0x446>
ffffffff8ae635c4:	b8 0e 00 00 00       	mov    $0xe,%eax
ffffffff8ae635c9:	eb 37                	jmp    ffffffff8ae63602 <frame_candidate_4a31a0+0x462>
ffffffff8ae635cb:	48 8d 3d 8e 68 0e 03 	lea    0x30e688e(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_4a4a40+0x30e5420>
ffffffff8ae635d2:	31 f6                	xor    %esi,%esi
ffffffff8ae635d4:	31 d2                	xor    %edx,%edx
ffffffff8ae635d6:	e8 25 8d 7a 00       	call   ffffffff8b60c300 <frame_candidate_4a4a40+0x7a78c0>
ffffffff8ae635db:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
ffffffff8ae635e2:	48 8b 75 80          	mov    -0x80(%rbp),%rsi
ffffffff8ae635e6:	48 8b 78 08          	mov    0x8(%rax),%rdi
ffffffff8ae635ea:	e8 a1 61 db ff       	call   ffffffff8ac19790 <handler_641_body-0x249650>
ffffffff8ae635ef:	89 c1                	mov    %eax,%ecx
ffffffff8ae635f1:	85 c0                	test   %eax,%eax
ffffffff8ae635f3:	b8 0e 00 00 00       	mov    $0xe,%eax
ffffffff8ae635f8:	0f 44 c1             	cmove  %ecx,%eax
ffffffff8ae635fb:	4c 8d 35 0e 8d 47 03 	lea    0x3478d0e(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae63602:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8ae63605:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8ae63609:	75 0f                	jne    ffffffff8ae6361a <frame_candidate_4a31a0+0x47a>
ffffffff8ae6360b:	48 83 c4 68          	add    $0x68,%rsp
ffffffff8ae6360f:	5b                   	pop    %rbx
ffffffff8ae63610:	41 5c                	pop    %r12
ffffffff8ae63612:	41 5d                	pop    %r13
ffffffff8ae63614:	41 5e                	pop    %r14
ffffffff8ae63616:	41 5f                	pop    %r15
ffffffff8ae63618:	5d                   	pop    %rbp
ffffffff8ae63619:	c3                   	ret
ffffffff8ae6361a:	e8 91 a0 25 00       	call   ffffffff8b0bd6b0 <frame_candidate_4a4a40+0x258c70>
ffffffff8ae6361f:	0f 0b                	ud2
ffffffff8ae63621:	90                   	nop
ffffffff8ae63622:	90                   	nop
ffffffff8ae63623:	90                   	nop
ffffffff8ae63624:	90                   	nop
ffffffff8ae63625:	90                   	nop
ffffffff8ae63626:	90                   	nop
ffffffff8ae63627:	90                   	nop
ffffffff8ae63628:	90                   	nop
ffffffff8ae63629:	90                   	nop
ffffffff8ae6362a:	90                   	nop
ffffffff8ae6362b:	90                   	nop
ffffffff8ae6362c:	90                   	nop
ffffffff8ae6362d:	90                   	nop
ffffffff8ae6362e:	90                   	nop
ffffffff8ae6362f:	90                   	nop

ffffffff8ae63630 <frame_candidate_4a3630>:
ffffffff8ae63630:	55                   	push   %rbp
ffffffff8ae63631:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63634:	5d                   	pop    %rbp
ffffffff8ae63635:	c3                   	ret
ffffffff8ae63636:	90                   	nop
ffffffff8ae63637:	90                   	nop
ffffffff8ae63638:	90                   	nop
ffffffff8ae63639:	90                   	nop
ffffffff8ae6363a:	90                   	nop
ffffffff8ae6363b:	90                   	nop
ffffffff8ae6363c:	90                   	nop
ffffffff8ae6363d:	90                   	nop
ffffffff8ae6363e:	90                   	nop
ffffffff8ae6363f:	90                   	nop

ffffffff8ae63640 <frame_candidate_4a3640>:
ffffffff8ae63640:	55                   	push   %rbp
ffffffff8ae63641:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63644:	41 57                	push   %r15
ffffffff8ae63646:	41 56                	push   %r14
ffffffff8ae63648:	53                   	push   %rbx
ffffffff8ae63649:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8ae6364d:	4c 8d 3d bc 8c 47 03 	lea    0x3478cbc(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae63654:	48 89 fb             	mov    %rdi,%rbx
ffffffff8ae63657:	49 8b 07             	mov    (%r15),%rax
ffffffff8ae6365a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8ae6365e:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
ffffffff8ae63665:	00 
ffffffff8ae63666:	48 8b 87 40 03 00 00 	mov    0x340(%rdi),%rax
ffffffff8ae6366d:	66 c7 40 0c 00 00    	movw   $0x0,0xc(%rax)
ffffffff8ae63673:	48 85 f6             	test   %rsi,%rsi
ffffffff8ae63676:	74 39                	je     ffffffff8ae636b1 <frame_candidate_4a3640+0x71>
ffffffff8ae63678:	48 8d 7d d8          	lea    -0x28(%rbp),%rdi
ffffffff8ae6367c:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae6367f:	e8 bc 2a 6b 00       	call   ffffffff8b516140 <frame_candidate_4a4a40+0x6b1700>
ffffffff8ae63684:	85 c0                	test   %eax,%eax
ffffffff8ae63686:	0f 84 8d 00 00 00    	je     ffffffff8ae63719 <frame_candidate_4a3640+0xd9>
ffffffff8ae6368c:	48 8d 3d 81 f9 0e 01 	lea    0x10ef981(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae63693:	48 8d 0d 05 c8 f0 00 	lea    0xf0c805(%rip),%rcx        # ffffffff8bd6fe9f <frame_candidate_4a4a40+0xf0b45f>
ffffffff8ae6369a:	be 6f 00 00 00       	mov    $0x6f,%esi
ffffffff8ae6369f:	89 c2                	mov    %eax,%edx
ffffffff8ae636a1:	89 c3                	mov    %eax,%ebx
ffffffff8ae636a3:	31 c0                	xor    %eax,%eax
ffffffff8ae636a5:	e8 e6 43 25 00       	call   ffffffff8b0b7a90 <frame_candidate_4a4a40+0x253050>
ffffffff8ae636aa:	89 d8                	mov    %ebx,%eax
ffffffff8ae636ac:	e9 27 01 00 00       	jmp    ffffffff8ae637d8 <frame_candidate_4a3640+0x198>
ffffffff8ae636b1:	48 8b b3 78 03 00 00 	mov    0x378(%rbx),%rsi
ffffffff8ae636b8:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae636bb:	31 d2                	xor    %edx,%edx
ffffffff8ae636bd:	e8 ee 78 10 00       	call   ffffffff8af6afb0 <frame_candidate_4a4a40+0x106570>
ffffffff8ae636c2:	85 c0                	test   %eax,%eax
ffffffff8ae636c4:	0f 85 0e 01 00 00    	jne    ffffffff8ae637d8 <frame_candidate_4a3640+0x198>
ffffffff8ae636ca:	4c 8d b3 e0 02 00 00 	lea    0x2e0(%rbx),%r14
ffffffff8ae636d1:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae636d4:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae636d7:	e8 b4 fa 0e 00       	call   ffffffff8af53190 <frame_candidate_4a4a40+0xee750>
ffffffff8ae636dc:	85 c0                	test   %eax,%eax
ffffffff8ae636de:	0f 85 f4 00 00 00    	jne    ffffffff8ae637d8 <frame_candidate_4a3640+0x198>
ffffffff8ae636e4:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8ae636e7:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
ffffffff8ae636eb:	48 85 ff             	test   %rdi,%rdi
ffffffff8ae636ee:	75 32                	jne    ffffffff8ae63722 <frame_candidate_4a3640+0xe2>
ffffffff8ae636f0:	48 8d 3d 1d f9 0e 01 	lea    0x10ef91d(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae636f7:	48 8d 15 6a dc ea 00 	lea    0xeadc6a(%rip),%rdx        # ffffffff8bd11368 <frame_candidate_4a4a40+0xeac928>
ffffffff8ae636fe:	be 88 00 00 00       	mov    $0x88,%esi
ffffffff8ae63703:	49 89 d8             	mov    %rbx,%r8
ffffffff8ae63706:	31 c9                	xor    %ecx,%ecx
ffffffff8ae63708:	31 c0                	xor    %eax,%eax
ffffffff8ae6370a:	e8 e1 42 25 00       	call   ffffffff8b0b79f0 <frame_candidate_4a4a40+0x252fb0>
ffffffff8ae6370f:	b8 02 30 00 00       	mov    $0x3002,%eax
ffffffff8ae63714:	e9 bf 00 00 00       	jmp    ffffffff8ae637d8 <frame_candidate_4a3640+0x198>
ffffffff8ae63719:	48 8b 7d d8          	mov    -0x28(%rbp),%rdi
ffffffff8ae6371d:	48 85 ff             	test   %rdi,%rdi
ffffffff8ae63720:	74 ce                	je     ffffffff8ae636f0 <frame_candidate_4a3640+0xb0>
ffffffff8ae63722:	48 8d 75 d0          	lea    -0x30(%rbp),%rsi
ffffffff8ae63726:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8ae6372b:	e8 30 7d e8 ff       	call   ffffffff8aceb460 <handler_641_body-0x177980>
ffffffff8ae63730:	41 89 c6             	mov    %eax,%r14d
ffffffff8ae63733:	85 c0                	test   %eax,%eax
ffffffff8ae63735:	75 73                	jne    ffffffff8ae637aa <frame_candidate_4a3640+0x16a>
ffffffff8ae63737:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
ffffffff8ae6373b:	80 7f 09 01          	cmpb   $0x1,0x9(%rdi)
ffffffff8ae6373f:	75 3d                	jne    ffffffff8ae6377e <frame_candidate_4a3640+0x13e>
ffffffff8ae63741:	e8 6a a1 51 00       	call   ffffffff8b37d8b0 <frame_candidate_4a4a40+0x518e70>
ffffffff8ae63746:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
ffffffff8ae6374a:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6374c:	31 d2                	xor    %edx,%edx
ffffffff8ae6374e:	41 be 05 40 00 00    	mov    $0x4005,%r14d
ffffffff8ae63754:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae63757:	48 83 78 10 00       	cmpq   $0x0,0x10(%rax)
ffffffff8ae6375c:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
ffffffff8ae63763:	0f 95 c2             	setne  %dl
ffffffff8ae63766:	44 0f 45 f1          	cmovne %ecx,%r14d
ffffffff8ae6376a:	66 89 50 0a          	mov    %dx,0xa(%rax)
ffffffff8ae6376e:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae63773:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
ffffffff8ae63777:	e8 24 75 10 00       	call   ffffffff8af6aca0 <frame_candidate_4a4a40+0x106260>
ffffffff8ae6377c:	eb 2c                	jmp    ffffffff8ae637aa <frame_candidate_4a3640+0x16a>
ffffffff8ae6377e:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
ffffffff8ae63782:	48 8d 3d 8b f8 0e 01 	lea    0x10ef88b(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae63789:	48 8d 15 4b 30 ec 00 	lea    0xec304b(%rip),%rdx        # ffffffff8bd267db <frame_candidate_4a4a40+0xec1d9b>
ffffffff8ae63790:	be 9b 00 00 00       	mov    $0x9b,%esi
ffffffff8ae63795:	49 89 d8             	mov    %rbx,%r8
ffffffff8ae63798:	31 c0                	xor    %eax,%eax
ffffffff8ae6379a:	44 0f b6 49 09       	movzbl 0x9(%rcx),%r9d
ffffffff8ae6379f:	e8 4c 42 25 00       	call   ffffffff8b0b79f0 <frame_candidate_4a4a40+0x252fb0>
ffffffff8ae637a4:	41 be 03 30 00 00    	mov    $0x3003,%r14d
ffffffff8ae637aa:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
ffffffff8ae637ae:	48 8b 7d d8          	mov    -0x28(%rbp),%rdi
ffffffff8ae637b2:	48 39 f8             	cmp    %rdi,%rax
ffffffff8ae637b5:	74 0c                	je     ffffffff8ae637c3 <frame_candidate_4a3640+0x183>
ffffffff8ae637b7:	48 89 c7             	mov    %rax,%rdi
ffffffff8ae637ba:	e8 01 6d 6a 00       	call   ffffffff8b50a4c0 <frame_candidate_4a4a40+0x6a5a80>
ffffffff8ae637bf:	48 8b 7d d8          	mov    -0x28(%rbp),%rdi
ffffffff8ae637c3:	e8 f8 6c 6a 00       	call   ffffffff8b50a4c0 <frame_candidate_4a4a40+0x6a5a80>
ffffffff8ae637c8:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
ffffffff8ae637cf:	66 c7 40 0c c0 00    	movw   $0xc0,0xc(%rax)
ffffffff8ae637d5:	44 89 f0             	mov    %r14d,%eax
ffffffff8ae637d8:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8ae637db:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8ae637df:	75 0b                	jne    ffffffff8ae637ec <frame_candidate_4a3640+0x1ac>
ffffffff8ae637e1:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8ae637e5:	5b                   	pop    %rbx
ffffffff8ae637e6:	41 5e                	pop    %r14
ffffffff8ae637e8:	41 5f                	pop    %r15
ffffffff8ae637ea:	5d                   	pop    %rbp
ffffffff8ae637eb:	c3                   	ret
ffffffff8ae637ec:	e8 bf 9e 25 00       	call   ffffffff8b0bd6b0 <frame_candidate_4a4a40+0x258c70>
ffffffff8ae637f1:	0f 0b                	ud2
ffffffff8ae637f3:	90                   	nop
ffffffff8ae637f4:	90                   	nop
ffffffff8ae637f5:	90                   	nop
ffffffff8ae637f6:	90                   	nop
ffffffff8ae637f7:	90                   	nop
ffffffff8ae637f8:	90                   	nop
ffffffff8ae637f9:	90                   	nop
ffffffff8ae637fa:	90                   	nop
ffffffff8ae637fb:	90                   	nop
ffffffff8ae637fc:	90                   	nop
ffffffff8ae637fd:	90                   	nop
ffffffff8ae637fe:	90                   	nop
ffffffff8ae637ff:	90                   	nop

ffffffff8ae63800 <frame_candidate_4a3800>:
ffffffff8ae63800:	55                   	push   %rbp
ffffffff8ae63801:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63804:	41 57                	push   %r15
ffffffff8ae63806:	41 56                	push   %r14
ffffffff8ae63808:	53                   	push   %rbx
ffffffff8ae63809:	50                   	push   %rax
ffffffff8ae6380a:	4c 8b b7 78 03 00 00 	mov    0x378(%rdi),%r14
ffffffff8ae63811:	49 89 f7             	mov    %rsi,%r15
ffffffff8ae63814:	48 89 fb             	mov    %rdi,%rbx
ffffffff8ae63817:	4d 85 f6             	test   %r14,%r14
ffffffff8ae6381a:	74 70                	je     ffffffff8ae6388c <frame_candidate_4a3800+0x8c>
ffffffff8ae6381c:	4c 3b b3 88 03 00 00 	cmp    0x388(%rbx),%r14
ffffffff8ae63823:	0f 84 86 00 00 00    	je     ffffffff8ae638af <frame_candidate_4a3800+0xaf>
ffffffff8ae63829:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
ffffffff8ae63830:	48 85 c0             	test   %rax,%rax
ffffffff8ae63833:	74 19                	je     ffffffff8ae6384e <frame_candidate_4a3800+0x4e>
ffffffff8ae63835:	66 81 78 0c c1 00    	cmpw   $0xc1,0xc(%rax)
ffffffff8ae6383b:	75 11                	jne    ffffffff8ae6384e <frame_candidate_4a3800+0x4e>
ffffffff8ae6383d:	66 c7 40 0c c2 00    	movw   $0xc2,0xc(%rax)
ffffffff8ae63843:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
ffffffff8ae6384a:	4c 89 70 10          	mov    %r14,0x10(%rax)
ffffffff8ae6384e:	48 8b 8b 80 03 00 00 	mov    0x380(%rbx),%rcx
ffffffff8ae63855:	41 0f b7 46 0a       	movzwl 0xa(%r14),%eax
ffffffff8ae6385a:	0f b6 51 0b          	movzbl 0xb(%rcx),%edx
ffffffff8ae6385e:	66 83 f8 2d          	cmp    $0x2d,%ax
ffffffff8ae63862:	b9 03 00 00 00       	mov    $0x3,%ecx
ffffffff8ae63867:	0f 45 ca             	cmovne %edx,%ecx
ffffffff8ae6386a:	80 f9 03             	cmp    $0x3,%cl
ffffffff8ae6386d:	74 4a                	je     ffffffff8ae638b9 <frame_candidate_4a3800+0xb9>
ffffffff8ae6386f:	0f b6 c1             	movzbl %cl,%eax
ffffffff8ae63872:	83 f8 04             	cmp    $0x4,%eax
ffffffff8ae63875:	75 48                	jne    ffffffff8ae638bf <frame_candidate_4a3800+0xbf>
ffffffff8ae63877:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae6387a:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae6387d:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae63881:	5b                   	pop    %rbx
ffffffff8ae63882:	41 5e                	pop    %r14
ffffffff8ae63884:	41 5f                	pop    %r15
ffffffff8ae63886:	5d                   	pop    %rbp
ffffffff8ae63887:	e9 14 9c 2a 00       	jmp    ffffffff8b10d4a0 <frame_candidate_4a4a40+0x2a8a60>
ffffffff8ae6388c:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae6388f:	4c 89 fe             	mov    %r15,%rsi
ffffffff8ae63892:	e8 71 b9 dc ff       	call   ffffffff8ac2f208 <handler_641_body-0x233bd8>
ffffffff8ae63897:	85 c0                	test   %eax,%eax
ffffffff8ae63899:	74 31                	je     ffffffff8ae638cc <frame_candidate_4a3800+0xcc>
ffffffff8ae6389b:	89 c7                	mov    %eax,%edi
ffffffff8ae6389d:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae638a0:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae638a4:	5b                   	pop    %rbx
ffffffff8ae638a5:	41 5e                	pop    %r14
ffffffff8ae638a7:	41 5f                	pop    %r15
ffffffff8ae638a9:	5d                   	pop    %rbp
ffffffff8ae638aa:	e9 51 e3 04 00       	jmp    ffffffff8aeb1c00 <frame_candidate_4a4a40+0x4d1c0>
ffffffff8ae638af:	4d 85 ff             	test   %r15,%r15
ffffffff8ae638b2:	74 0b                	je     ffffffff8ae638bf <frame_candidate_4a3800+0xbf>
ffffffff8ae638b4:	4d 89 37             	mov    %r14,(%r15)
ffffffff8ae638b7:	eb 06                	jmp    ffffffff8ae638bf <frame_candidate_4a3800+0xbf>
ffffffff8ae638b9:	f6 43 09 01          	testb  $0x1,0x9(%rbx)
ffffffff8ae638bd:	75 4e                	jne    ffffffff8ae6390d <frame_candidate_4a3800+0x10d>
ffffffff8ae638bf:	31 c0                	xor    %eax,%eax
ffffffff8ae638c1:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae638c5:	5b                   	pop    %rbx
ffffffff8ae638c6:	41 5e                	pop    %r14
ffffffff8ae638c8:	41 5f                	pop    %r15
ffffffff8ae638ca:	5d                   	pop    %rbp
ffffffff8ae638cb:	c3                   	ret
ffffffff8ae638cc:	4d 8b 37             	mov    (%r15),%r14
ffffffff8ae638cf:	4c 89 b3 78 03 00 00 	mov    %r14,0x378(%rbx)
ffffffff8ae638d6:	41 0f b7 7e 0a       	movzwl 0xa(%r14),%edi
ffffffff8ae638db:	66 89 7b 0a          	mov    %di,0xa(%rbx)
ffffffff8ae638df:	e8 2c 04 71 00       	call   ffffffff8b573d10 <frame_candidate_4a4a40+0x70f2d0>
ffffffff8ae638e4:	48 89 83 80 03 00 00 	mov    %rax,0x380(%rbx)
ffffffff8ae638eb:	0f b6 78 0a          	movzbl 0xa(%rax),%edi
ffffffff8ae638ef:	e8 bc 35 62 00       	call   ffffffff8b486eb0 <frame_candidate_4a4a40+0x622470>
ffffffff8ae638f4:	85 c0                	test   %eax,%eax
ffffffff8ae638f6:	0f 84 20 ff ff ff    	je     ffffffff8ae6381c <frame_candidate_4a3800+0x1c>
ffffffff8ae638fc:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae638ff:	e8 fc c3 35 00       	call   ffffffff8b1bfd00 <frame_candidate_4a4a40+0x35b2c0>
ffffffff8ae63904:	85 c0                	test   %eax,%eax
ffffffff8ae63906:	75 93                	jne    ffffffff8ae6389b <frame_candidate_4a3800+0x9b>
ffffffff8ae63908:	e9 0f ff ff ff       	jmp    ffffffff8ae6381c <frame_candidate_4a3800+0x1c>
ffffffff8ae6390d:	66 83 f8 10          	cmp    $0x10,%ax
ffffffff8ae63911:	75 1a                	jne    ffffffff8ae6392d <frame_candidate_4a3800+0x12d>
ffffffff8ae63913:	49 8b 7e 20          	mov    0x20(%r14),%rdi
ffffffff8ae63917:	48 89 da             	mov    %rbx,%rdx
ffffffff8ae6391a:	0f b6 77 09          	movzbl 0x9(%rdi),%esi
ffffffff8ae6391e:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae63922:	5b                   	pop    %rbx
ffffffff8ae63923:	41 5e                	pop    %r14
ffffffff8ae63925:	41 5f                	pop    %r15
ffffffff8ae63927:	5d                   	pop    %rbp
ffffffff8ae63928:	e9 23 c3 35 00       	jmp    ffffffff8b1bfc50 <frame_candidate_4a4a40+0x35b210>
ffffffff8ae6392d:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63930:	31 f6                	xor    %esi,%esi
ffffffff8ae63932:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae63936:	5b                   	pop    %rbx
ffffffff8ae63937:	41 5e                	pop    %r14
ffffffff8ae63939:	41 5f                	pop    %r15
ffffffff8ae6393b:	5d                   	pop    %rbp
ffffffff8ae6393c:	e9 c7 b8 dc ff       	jmp    ffffffff8ac2f208 <handler_641_body-0x233bd8>
ffffffff8ae63941:	90                   	nop
ffffffff8ae63942:	90                   	nop
ffffffff8ae63943:	90                   	nop
ffffffff8ae63944:	90                   	nop
ffffffff8ae63945:	90                   	nop
ffffffff8ae63946:	90                   	nop
ffffffff8ae63947:	90                   	nop
ffffffff8ae63948:	90                   	nop
ffffffff8ae63949:	90                   	nop
ffffffff8ae6394a:	90                   	nop
ffffffff8ae6394b:	90                   	nop
ffffffff8ae6394c:	90                   	nop
ffffffff8ae6394d:	90                   	nop
ffffffff8ae6394e:	90                   	nop
ffffffff8ae6394f:	90                   	nop

ffffffff8ae63950 <frame_candidate_4a3950>:
ffffffff8ae63950:	55                   	push   %rbp
ffffffff8ae63951:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63954:	41 57                	push   %r15
ffffffff8ae63956:	41 56                	push   %r14
ffffffff8ae63958:	41 54                	push   %r12
ffffffff8ae6395a:	53                   	push   %rbx
ffffffff8ae6395b:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8ae6395f:	48 8b 87 80 03 00 00 	mov    0x380(%rdi),%rax
ffffffff8ae63966:	4c 8b b7 78 03 00 00 	mov    0x378(%rdi),%r14
ffffffff8ae6396d:	0f b6 48 0b          	movzbl 0xb(%rax),%ecx
ffffffff8ae63971:	83 f9 0a             	cmp    $0xa,%ecx
ffffffff8ae63974:	75 29                	jne    ffffffff8ae6399f <frame_candidate_4a3950+0x4f>
ffffffff8ae63976:	41 0f b7 4e 0a       	movzwl 0xa(%r14),%ecx
ffffffff8ae6397b:	48 8d 3d 92 f6 0e 01 	lea    0x10ef692(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae63982:	48 8d 15 49 40 dd 00 	lea    0xdd4049(%rip),%rdx        # ffffffff8bc379d2 <frame_candidate_4a4a40+0xdd2f92>
ffffffff8ae63989:	be 99 01 00 00       	mov    $0x199,%esi
ffffffff8ae6398e:	31 c0                	xor    %eax,%eax
ffffffff8ae63990:	e8 5b 40 25 00       	call   ffffffff8b0b79f0 <frame_candidate_4a4a40+0x252fb0>
ffffffff8ae63995:	b8 0e 00 00 00       	mov    $0xe,%eax
ffffffff8ae6399a:	e9 13 04 00 00       	jmp    ffffffff8ae63db2 <frame_candidate_4a3950+0x462>
ffffffff8ae6399f:	44 0f b6 60 0c       	movzbl 0xc(%rax),%r12d
ffffffff8ae639a4:	49 8b 76 28          	mov    0x28(%r14),%rsi
ffffffff8ae639a8:	48 89 fb             	mov    %rdi,%rbx
ffffffff8ae639ab:	66 c7 47 0d 00 00    	movw   $0x0,0xd(%rdi)
ffffffff8ae639b1:	48 c7 87 a0 03 00 00 	movq   $0x0,0x3a0(%rdi)
ffffffff8ae639b8:	00 00 00 00 
ffffffff8ae639bc:	48 c7 87 90 03 00 00 	movq   $0x0,0x390(%rdi)
ffffffff8ae639c3:	00 00 00 00 
ffffffff8ae639c7:	85 c9                	test   %ecx,%ecx
ffffffff8ae639c9:	74 21                	je     ffffffff8ae639ec <frame_candidate_4a3950+0x9c>
ffffffff8ae639cb:	83 f9 02             	cmp    $0x2,%ecx
ffffffff8ae639ce:	75 30                	jne    ffffffff8ae63a00 <frame_candidate_4a3950+0xb0>
ffffffff8ae639d0:	66 83 7b 0a 2d       	cmpw   $0x2d,0xa(%rbx)
ffffffff8ae639d5:	0f 85 c7 02 00 00    	jne    ffffffff8ae63ca2 <frame_candidate_4a3950+0x352>
ffffffff8ae639db:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae639de:	e8 3d 79 10 00       	call   ffffffff8af6b320 <frame_candidate_4a4a40+0x1068e0>
ffffffff8ae639e3:	85 c0                	test   %eax,%eax
ffffffff8ae639e5:	75 11                	jne    ffffffff8ae639f8 <frame_candidate_4a3950+0xa8>
ffffffff8ae639e7:	e9 b6 02 00 00       	jmp    ffffffff8ae63ca2 <frame_candidate_4a3950+0x352>
ffffffff8ae639ec:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae639ef:	e8 1c 78 10 00       	call   ffffffff8af6b210 <frame_candidate_4a4a40+0x1067d0>
ffffffff8ae639f4:	85 c0                	test   %eax,%eax
ffffffff8ae639f6:	74 3e                	je     ffffffff8ae63a36 <frame_candidate_4a3950+0xe6>
ffffffff8ae639f8:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae639fb:	e9 83 03 00 00       	jmp    ffffffff8ae63d83 <frame_candidate_4a3950+0x433>
ffffffff8ae63a00:	41 8d 44 24 f0       	lea    -0x10(%r12),%eax
ffffffff8ae63a05:	83 f8 0a             	cmp    $0xa,%eax
ffffffff8ae63a08:	0f 87 48 01 00 00    	ja     ffffffff8ae63b56 <frame_candidate_4a3950+0x206>
ffffffff8ae63a0e:	48 8d 15 d3 f5 0e 01 	lea    0x10ef5d3(%rip),%rdx        # ffffffff8bf52fe8 <frame_candidate_4a4a40+0x10ee5a8>
ffffffff8ae63a15:	48 63 04 82          	movslq (%rdx,%rax,4),%rax
ffffffff8ae63a19:	48 01 d0             	add    %rdx,%rax
ffffffff8ae63a1c:	ff e0                	jmp    *%rax
ffffffff8ae63a1e:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63a21:	e8 f2 61 dc ff       	call   ffffffff8ac29c18 <handler_641_body-0x2391c8>
ffffffff8ae63a26:	85 c0                	test   %eax,%eax
ffffffff8ae63a28:	0f 84 d2 00 00 00    	je     ffffffff8ae63b00 <frame_candidate_4a3950+0x1b0>
ffffffff8ae63a2e:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63a31:	e9 4b 02 00 00       	jmp    ffffffff8ae63c81 <frame_candidate_4a3950+0x331>
ffffffff8ae63a36:	48 8b 83 80 03 00 00 	mov    0x380(%rbx),%rax
ffffffff8ae63a3d:	f6 40 09 40          	testb  $0x40,0x9(%rax)
ffffffff8ae63a41:	0f 85 88 00 00 00    	jne    ffffffff8ae63acf <frame_candidate_4a3950+0x17f>
ffffffff8ae63a47:	0f b6 43 0d          	movzbl 0xd(%rbx),%eax
ffffffff8ae63a4b:	0f b7 7b 0a          	movzwl 0xa(%rbx),%edi
ffffffff8ae63a4f:	48 89 da             	mov    %rbx,%rdx
ffffffff8ae63a52:	48 8d b4 c3 d8 02 00 	lea    0x2d8(%rbx,%rax,8),%rsi
ffffffff8ae63a59:	00 
ffffffff8ae63a5a:	e8 a1 3c 61 00       	call   ffffffff8b477700 <frame_candidate_4a4a40+0x612cc0>
ffffffff8ae63a5f:	85 c0                	test   %eax,%eax
ffffffff8ae63a61:	74 6c                	je     ffffffff8ae63acf <frame_candidate_4a3950+0x17f>
ffffffff8ae63a63:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63a66:	3d 05 30 00 00       	cmp    $0x3005,%eax
ffffffff8ae63a6b:	0f 85 d7 01 00 00    	jne    ffffffff8ae63c48 <frame_candidate_4a3950+0x2f8>
ffffffff8ae63a71:	0f b7 43 0a          	movzwl 0xa(%rbx),%eax
ffffffff8ae63a75:	66 83 f8 70          	cmp    $0x70,%ax
ffffffff8ae63a79:	0f 85 cd 01 00 00    	jne    ffffffff8ae63c4c <frame_candidate_4a3950+0x2fc>
ffffffff8ae63a7f:	48 8d 83 e0 02 00 00 	lea    0x2e0(%rbx),%rax
ffffffff8ae63a86:	48 8b 08             	mov    (%rax),%rcx
ffffffff8ae63a89:	66 b8 70 00          	mov    $0x70,%ax
ffffffff8ae63a8d:	80 79 09 14          	cmpb   $0x14,0x9(%rcx)
ffffffff8ae63a91:	0f 85 b5 01 00 00    	jne    ffffffff8ae63c4c <frame_candidate_4a3950+0x2fc>
ffffffff8ae63a97:	48 8b 93 e8 02 00 00 	mov    0x2e8(%rbx),%rdx
ffffffff8ae63a9e:	80 7a 09 14          	cmpb   $0x14,0x9(%rdx)
ffffffff8ae63aa2:	0f 85 a4 01 00 00    	jne    ffffffff8ae63c4c <frame_candidate_4a3950+0x2fc>
ffffffff8ae63aa8:	0f b6 71 0d          	movzbl 0xd(%rcx),%esi
ffffffff8ae63aac:	40 3a 72 0d          	cmp    0xd(%rdx),%sil
ffffffff8ae63ab0:	0f 85 96 01 00 00    	jne    ffffffff8ae63c4c <frame_candidate_4a3950+0x2fc>
ffffffff8ae63ab6:	8b 49 30             	mov    0x30(%rcx),%ecx
ffffffff8ae63ab9:	3b 4a 30             	cmp    0x30(%rdx),%ecx
ffffffff8ae63abc:	0f 85 8a 01 00 00    	jne    ffffffff8ae63c4c <frame_candidate_4a3950+0x2fc>
ffffffff8ae63ac2:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63ac5:	e8 96 74 10 00       	call   ffffffff8af6af60 <frame_candidate_4a4a40+0x106520>
ffffffff8ae63aca:	e9 c3 01 00 00       	jmp    ffffffff8ae63c92 <frame_candidate_4a3950+0x342>
ffffffff8ae63acf:	48 8d 05 4a bd 9d 00 	lea    0x9dbd4a(%rip),%rax        # ffffffff8b83f820 <frame_candidate_4a4a40+0x9dade0>
ffffffff8ae63ad6:	4e 8b 3c e0          	mov    (%rax,%r12,8),%r15
ffffffff8ae63ada:	48 8d 05 97 62 dc ff 	lea    -0x239d69(%rip),%rax        # ffffffff8ac29d78 <handler_641_body-0x239068>
ffffffff8ae63ae1:	4c 29 f8             	sub    %r15,%rax
ffffffff8ae63ae4:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8ae63ae8:	48 83 f8 37          	cmp    $0x37,%rax
ffffffff8ae63aec:	0f 87 d4 02 00 00    	ja     ffffffff8ae63dc6 <frame_candidate_4a3950+0x476>
ffffffff8ae63af2:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63af5:	41 ff d7             	call   *%r15
ffffffff8ae63af8:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63afb:	e9 74 01 00 00       	jmp    ffffffff8ae63c74 <frame_candidate_4a3950+0x324>
ffffffff8ae63b00:	41 0f b7 46 0a       	movzwl 0xa(%r14),%eax
ffffffff8ae63b05:	3d 88 5b 00 00       	cmp    $0x5b88,%eax
ffffffff8ae63b0a:	0f 84 2a 02 00 00    	je     ffffffff8ae63d3a <frame_candidate_4a3950+0x3ea>
ffffffff8ae63b10:	3d 87 5b 00 00       	cmp    $0x5b87,%eax
ffffffff8ae63b15:	0f 84 12 02 00 00    	je     ffffffff8ae63d2d <frame_candidate_4a3950+0x3dd>
ffffffff8ae63b1b:	3d 80 5b 00 00       	cmp    $0x5b80,%eax
ffffffff8ae63b20:	0f 85 7c 01 00 00    	jne    ffffffff8ae63ca2 <frame_candidate_4a3950+0x352>
ffffffff8ae63b26:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63b29:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae63b2c:	e8 9f 6c 69 00       	call   ffffffff8b4fa7d0 <frame_candidate_4a4a40+0x695d90>
ffffffff8ae63b31:	e9 35 02 00 00       	jmp    ffffffff8ae63d6b <frame_candidate_4a3950+0x41b>
ffffffff8ae63b36:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63b39:	e8 da 60 dc ff       	call   ffffffff8ac29c18 <handler_641_body-0x2391c8>
ffffffff8ae63b3e:	85 c0                	test   %eax,%eax
ffffffff8ae63b40:	0f 85 e8 fe ff ff    	jne    ffffffff8ae63a2e <frame_candidate_4a3950+0xde>
ffffffff8ae63b46:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63b49:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae63b4c:	e8 6f 69 69 00       	call   ffffffff8b4fa4c0 <frame_candidate_4a4a40+0x695a80>
ffffffff8ae63b51:	e9 15 02 00 00       	jmp    ffffffff8ae63d6b <frame_candidate_4a3950+0x41b>
ffffffff8ae63b56:	45 0f b7 4e 0a       	movzwl 0xa(%r14),%r9d
ffffffff8ae63b5b:	48 8d 3d b2 f4 0e 01 	lea    0x10ef4b2(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae63b62:	48 8d 15 8f 7b de 00 	lea    0xde7b8f(%rip),%rdx        # ffffffff8bc4b6f8 <frame_candidate_4a4a40+0xde6cb8>
ffffffff8ae63b69:	be d3 02 00 00       	mov    $0x2d3,%esi
ffffffff8ae63b6e:	45 89 e0             	mov    %r12d,%r8d
ffffffff8ae63b71:	31 c0                	xor    %eax,%eax
ffffffff8ae63b73:	4c 89 34 24          	mov    %r14,(%rsp)
ffffffff8ae63b77:	e8 74 3e 25 00       	call   ffffffff8b0b79f0 <frame_candidate_4a4a40+0x252fb0>
ffffffff8ae63b7c:	41 bf 0e 00 00 00    	mov    $0xe,%r15d
ffffffff8ae63b82:	e9 fa 00 00 00       	jmp    ffffffff8ae63c81 <frame_candidate_4a3950+0x331>
ffffffff8ae63b87:	49 8b 06             	mov    (%r14),%rax
ffffffff8ae63b8a:	48 85 c0             	test   %rax,%rax
ffffffff8ae63b8d:	0f 84 66 01 00 00    	je     ffffffff8ae63cf9 <frame_candidate_4a3950+0x3a9>
ffffffff8ae63b93:	0f b7 40 0a          	movzwl 0xa(%rax),%eax
ffffffff8ae63b97:	83 e0 fe             	and    $0xfffffffe,%eax
ffffffff8ae63b9a:	66 83 f8 12          	cmp    $0x12,%ax
ffffffff8ae63b9e:	0f 85 55 01 00 00    	jne    ffffffff8ae63cf9 <frame_candidate_4a3950+0x3a9>
ffffffff8ae63ba4:	49 8b 46 28          	mov    0x28(%r14),%rax
ffffffff8ae63ba8:	48 8b 40 20          	mov    0x20(%rax),%rax
ffffffff8ae63bac:	49 89 46 20          	mov    %rax,0x20(%r14)
ffffffff8ae63bb0:	48 8b 38             	mov    (%rax),%rdi
ffffffff8ae63bb3:	e8 f8 6e 6a 00       	call   ffffffff8b50aab0 <frame_candidate_4a4a40+0x6a6070>
ffffffff8ae63bb8:	31 c0                	xor    %eax,%eax
ffffffff8ae63bba:	e9 f3 01 00 00       	jmp    ffffffff8ae63db2 <frame_candidate_4a3950+0x462>
ffffffff8ae63bbf:	48 8d 3d 4e f4 0e 01 	lea    0x10ef44e(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae63bc6:	48 8d 15 75 14 f0 00 	lea    0xf01475(%rip),%rdx        # ffffffff8bd65042 <frame_candidate_4a4a40+0xf00602>
ffffffff8ae63bcd:	be c6 02 00 00       	mov    $0x2c6,%esi
ffffffff8ae63bd2:	4c 89 f1             	mov    %r14,%rcx
ffffffff8ae63bd5:	31 c0                	xor    %eax,%eax
ffffffff8ae63bd7:	e8 14 3e 25 00       	call   ffffffff8b0b79f0 <frame_candidate_4a4a40+0x252fb0>
ffffffff8ae63bdc:	b8 0e 00 00 00       	mov    $0xe,%eax
ffffffff8ae63be1:	e9 cc 01 00 00       	jmp    ffffffff8ae63db2 <frame_candidate_4a3950+0x462>
ffffffff8ae63be6:	49 8b 06             	mov    (%r14),%rax
ffffffff8ae63be9:	0f b7 48 0a          	movzwl 0xa(%rax),%ecx
ffffffff8ae63bed:	83 f9 37             	cmp    $0x37,%ecx
ffffffff8ae63bf0:	74 35                	je     ffffffff8ae63c27 <frame_candidate_4a3950+0x2d7>
ffffffff8ae63bf2:	83 f9 08             	cmp    $0x8,%ecx
ffffffff8ae63bf5:	0f 85 4c 01 00 00    	jne    ffffffff8ae63d47 <frame_candidate_4a3950+0x3f7>
ffffffff8ae63bfb:	48 8b 40 20          	mov    0x20(%rax),%rax
ffffffff8ae63bff:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63c02:	48 89 83 e0 02 00 00 	mov    %rax,0x2e0(%rbx)
ffffffff8ae63c09:	c6 43 0d 01          	movb   $0x1,0xd(%rbx)
ffffffff8ae63c0d:	49 8b 16             	mov    (%r14),%rdx
ffffffff8ae63c10:	48 8b 72 20          	mov    0x20(%rdx),%rsi
ffffffff8ae63c14:	e8 17 86 66 00       	call   ffffffff8b4cc230 <frame_candidate_4a4a40+0x6677f0>
ffffffff8ae63c19:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63c1c:	85 c0                	test   %eax,%eax
ffffffff8ae63c1e:	0f 85 33 01 00 00    	jne    ffffffff8ae63d57 <frame_candidate_4a3950+0x407>
ffffffff8ae63c24:	49 8b 06             	mov    (%r14),%rax
ffffffff8ae63c27:	48 8b 78 20          	mov    0x20(%rax),%rdi
ffffffff8ae63c2b:	e8 90 55 13 00       	call   ffffffff8af991c0 <frame_candidate_4a4a40+0x134780>
ffffffff8ae63c30:	48 89 c2             	mov    %rax,%rdx
ffffffff8ae63c33:	e9 11 01 00 00       	jmp    ffffffff8ae63d49 <frame_candidate_4a3950+0x3f9>
ffffffff8ae63c38:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63c3b:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae63c3e:	e8 0d 99 2a 00       	call   ffffffff8b10d550 <frame_candidate_4a4a40+0x2a8b10>
ffffffff8ae63c43:	e9 23 01 00 00       	jmp    ffffffff8ae63d6b <frame_candidate_4a3950+0x41b>
ffffffff8ae63c48:	0f b7 43 0a          	movzwl 0xa(%rbx),%eax
ffffffff8ae63c4c:	0f b7 f8             	movzwl %ax,%edi
ffffffff8ae63c4f:	e8 0c 01 71 00       	call   ffffffff8b573d60 <frame_candidate_4a4a40+0x70f320>
ffffffff8ae63c54:	49 89 c0             	mov    %rax,%r8
ffffffff8ae63c57:	48 8d 3d b6 f3 0e 01 	lea    0x10ef3b6(%rip),%rdi        # ffffffff8bf53014 <frame_candidate_4a4a40+0x10ee5d4>
ffffffff8ae63c5e:	48 8d 0d 81 3d dd 00 	lea    0xdd3d81(%rip),%rcx        # ffffffff8bc379e6 <frame_candidate_4a4a40+0xdd2fa6>
ffffffff8ae63c65:	be f1 01 00 00       	mov    $0x1f1,%esi
ffffffff8ae63c6a:	44 89 fa             	mov    %r15d,%edx
ffffffff8ae63c6d:	31 c0                	xor    %eax,%eax
ffffffff8ae63c6f:	e8 1c 3e 25 00       	call   ffffffff8b0b7a90 <frame_candidate_4a4a40+0x253050>
ffffffff8ae63c74:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63c77:	e8 e4 72 10 00       	call   ffffffff8af6af60 <frame_candidate_4a4a40+0x106520>
ffffffff8ae63c7c:	45 85 ff             	test   %r15d,%r15d
ffffffff8ae63c7f:	74 11                	je     ffffffff8ae63c92 <frame_candidate_4a3950+0x342>
ffffffff8ae63c81:	48 8b bb 90 03 00 00 	mov    0x390(%rbx),%rdi
ffffffff8ae63c88:	e8 23 9c 51 00       	call   ffffffff8b37d8b0 <frame_candidate_4a4a40+0x518e70>
ffffffff8ae63c8d:	e9 f1 00 00 00       	jmp    ffffffff8ae63d83 <frame_candidate_4a3950+0x433>
ffffffff8ae63c92:	48 8b bb 90 03 00 00 	mov    0x390(%rbx),%rdi
ffffffff8ae63c99:	48 85 ff             	test   %rdi,%rdi
ffffffff8ae63c9c:	0f 85 c1 00 00 00    	jne    ffffffff8ae63d63 <frame_candidate_4a3950+0x413>
ffffffff8ae63ca2:	48 8b bb 90 03 00 00 	mov    0x390(%rbx),%rdi
ffffffff8ae63ca9:	e8 02 9c 51 00       	call   ffffffff8b37d8b0 <frame_candidate_4a4a40+0x518e70>
ffffffff8ae63cae:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
ffffffff8ae63cb5:	45 31 ff             	xor    %r15d,%r15d
ffffffff8ae63cb8:	48 85 c0             	test   %rax,%rax
ffffffff8ae63cbb:	0f 84 c2 00 00 00    	je     ffffffff8ae63d83 <frame_candidate_4a3950+0x433>
ffffffff8ae63cc1:	66 81 78 0c c2 00    	cmpw   $0xc2,0xc(%rax)
ffffffff8ae63cc7:	0f 85 b6 00 00 00    	jne    ffffffff8ae63d83 <frame_candidate_4a3950+0x433>
ffffffff8ae63ccd:	4c 39 70 10          	cmp    %r14,0x10(%rax)
ffffffff8ae63cd1:	0f 85 ac 00 00 00    	jne    ffffffff8ae63d83 <frame_candidate_4a3950+0x433>
ffffffff8ae63cd7:	48 8b b3 90 03 00 00 	mov    0x390(%rbx),%rsi
ffffffff8ae63cde:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63ce1:	e8 5a f9 ff ff       	call   ffffffff8ae63640 <frame_candidate_4a3640>
ffffffff8ae63ce6:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63ce9:	48 c7 83 90 03 00 00 	movq   $0x0,0x390(%rbx)
ffffffff8ae63cf0:	00 00 00 00 
ffffffff8ae63cf4:	e9 a1 00 00 00       	jmp    ffffffff8ae63d9a <frame_candidate_4a3950+0x44a>
ffffffff8ae63cf9:	48 8b 76 18          	mov    0x18(%rsi),%rsi
ffffffff8ae63cfd:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63d00:	e8 0b 75 10 00       	call   ffffffff8af6b210 <frame_candidate_4a4a40+0x1067d0>
ffffffff8ae63d05:	85 c0                	test   %eax,%eax
ffffffff8ae63d07:	0f 85 21 fd ff ff    	jne    ffffffff8ae63a2e <frame_candidate_4a3950+0xde>
ffffffff8ae63d0d:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63d10:	e8 fb 71 10 00       	call   ffffffff8af6af10 <frame_candidate_4a4a40+0x1064d0>
ffffffff8ae63d15:	85 c0                	test   %eax,%eax
ffffffff8ae63d17:	0f 84 a2 00 00 00    	je     ffffffff8ae63dbf <frame_candidate_4a3950+0x46f>
ffffffff8ae63d1d:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63d20:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63d23:	e8 38 72 10 00       	call   ffffffff8af6af60 <frame_candidate_4a4a40+0x106520>
ffffffff8ae63d28:	e9 54 ff ff ff       	jmp    ffffffff8ae63c81 <frame_candidate_4a3950+0x331>
ffffffff8ae63d2d:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63d30:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae63d33:	e8 c8 6d 69 00       	call   ffffffff8b4fab00 <frame_candidate_4a4a40+0x6960c0>
ffffffff8ae63d38:	eb 31                	jmp    ffffffff8ae63d6b <frame_candidate_4a3950+0x41b>
ffffffff8ae63d3a:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63d3d:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae63d40:	e8 2b 6b 69 00       	call   ffffffff8b4fa870 <frame_candidate_4a4a40+0x695e30>
ffffffff8ae63d45:	eb 24                	jmp    ffffffff8ae63d6b <frame_candidate_4a3950+0x41b>
ffffffff8ae63d47:	31 d2                	xor    %edx,%edx
ffffffff8ae63d49:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae63d4c:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae63d4f:	e8 8c 6c 69 00       	call   ffffffff8b4fa9e0 <frame_candidate_4a4a40+0x695fa0>
ffffffff8ae63d54:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63d57:	48 8b bb 90 03 00 00 	mov    0x390(%rbx),%rdi
ffffffff8ae63d5e:	48 85 ff             	test   %rdi,%rdi
ffffffff8ae63d61:	74 0b                	je     ffffffff8ae63d6e <frame_candidate_4a3950+0x41e>
ffffffff8ae63d63:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae63d66:	e8 e5 24 6b 00       	call   ffffffff8b516250 <frame_candidate_4a4a40+0x6b1810>
ffffffff8ae63d6b:	41 89 c7             	mov    %eax,%r15d
ffffffff8ae63d6e:	48 8b bb 90 03 00 00 	mov    0x390(%rbx),%rdi
ffffffff8ae63d75:	e8 36 9b 51 00       	call   ffffffff8b37d8b0 <frame_candidate_4a4a40+0x518e70>
ffffffff8ae63d7a:	45 85 ff             	test   %r15d,%r15d
ffffffff8ae63d7d:	0f 84 2b ff ff ff    	je     ffffffff8ae63cae <frame_candidate_4a3950+0x35e>
ffffffff8ae63d83:	48 8b b3 90 03 00 00 	mov    0x390(%rbx),%rsi
ffffffff8ae63d8a:	48 85 f6             	test   %rsi,%rsi
ffffffff8ae63d8d:	74 0b                	je     ffffffff8ae63d9a <frame_candidate_4a3950+0x44a>
ffffffff8ae63d8f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae63d92:	48 89 da             	mov    %rbx,%rdx
ffffffff8ae63d95:	e8 d6 70 10 00       	call   ffffffff8af6ae70 <frame_candidate_4a4a40+0x106430>
ffffffff8ae63d9a:	45 85 ff             	test   %r15d,%r15d
ffffffff8ae63d9d:	74 0d                	je     ffffffff8ae63dac <frame_candidate_4a3950+0x45c>
ffffffff8ae63d9f:	44 89 ff             	mov    %r15d,%edi
ffffffff8ae63da2:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae63da5:	e8 56 de 04 00       	call   ffffffff8aeb1c00 <frame_candidate_4a4a40+0x4d1c0>
ffffffff8ae63daa:	eb 02                	jmp    ffffffff8ae63dae <frame_candidate_4a3950+0x45e>
ffffffff8ae63dac:	31 c0                	xor    %eax,%eax
ffffffff8ae63dae:	c6 43 0d 00          	movb   $0x0,0xd(%rbx)
ffffffff8ae63db2:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8ae63db6:	5b                   	pop    %rbx
ffffffff8ae63db7:	41 5c                	pop    %r12
ffffffff8ae63db9:	41 5e                	pop    %r14
ffffffff8ae63dbb:	41 5f                	pop    %r15
ffffffff8ae63dbd:	5d                   	pop    %rbp
ffffffff8ae63dbe:	c3                   	ret
ffffffff8ae63dbf:	b8 08 40 00 00       	mov    $0x4008,%eax
ffffffff8ae63dc4:	eb ec                	jmp    ffffffff8ae63db2 <frame_candidate_4a3950+0x462>
ffffffff8ae63dc6:	48 8d 3d 93 43 62 01 	lea    0x1624393(%rip),%rdi        # ffffffff8c488160 <frame_candidate_4a4a40+0x1623720>
ffffffff8ae63dcd:	4c 89 fe             	mov    %r15,%rsi
ffffffff8ae63dd0:	e8 eb ba fa ff       	call   ffffffff8ae0f8c0 <handler_641_body-0x53520>
ffffffff8ae63dd5:	e9 18 fd ff ff       	jmp    ffffffff8ae63af2 <frame_candidate_4a3950+0x1a2>
ffffffff8ae63dda:	90                   	nop
ffffffff8ae63ddb:	90                   	nop
ffffffff8ae63ddc:	90                   	nop
ffffffff8ae63ddd:	90                   	nop
ffffffff8ae63dde:	90                   	nop
ffffffff8ae63ddf:	90                   	nop

ffffffff8ae63de0 <frame_candidate_4a3de0>:
ffffffff8ae63de0:	55                   	push   %rbp
ffffffff8ae63de1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63de4:	48 85 f6             	test   %rsi,%rsi
ffffffff8ae63de7:	74 3c                	je     ffffffff8ae63e25 <frame_candidate_4a3de0+0x45>
ffffffff8ae63de9:	31 c0                	xor    %eax,%eax
ffffffff8ae63deb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8ae63df0:	8b 0c 87             	mov    (%rdi,%rax,4),%ecx
ffffffff8ae63df3:	48 ff c0             	inc    %rax
ffffffff8ae63df6:	44 69 c1 51 2d 9e cc 	imul   $0xcc9e2d51,%ecx,%r8d
ffffffff8ae63dfd:	69 c9 00 80 a8 16    	imul   $0x16a88000,%ecx,%ecx
ffffffff8ae63e03:	41 c1 e8 11          	shr    $0x11,%r8d
ffffffff8ae63e07:	41 09 c8             	or     %ecx,%r8d
ffffffff8ae63e0a:	41 69 c8 93 35 87 1b 	imul   $0x1b873593,%r8d,%ecx
ffffffff8ae63e11:	31 d1                	xor    %edx,%ecx
ffffffff8ae63e13:	c4 e3 7b f0 c9 13    	rorx   $0x13,%ecx,%ecx
ffffffff8ae63e19:	8d 94 89 64 6b 54 e6 	lea    -0x19ab949c(%rcx,%rcx,4),%edx
ffffffff8ae63e20:	48 39 c6             	cmp    %rax,%rsi
ffffffff8ae63e23:	75 cb                	jne    ffffffff8ae63df0 <frame_candidate_4a3de0+0x10>
ffffffff8ae63e25:	31 d6                	xor    %edx,%esi
ffffffff8ae63e27:	89 f0                	mov    %esi,%eax
ffffffff8ae63e29:	c1 e8 10             	shr    $0x10,%eax
ffffffff8ae63e2c:	31 f0                	xor    %esi,%eax
ffffffff8ae63e2e:	69 c0 6b ca eb 85    	imul   $0x85ebca6b,%eax,%eax
ffffffff8ae63e34:	89 c1                	mov    %eax,%ecx
ffffffff8ae63e36:	c1 e9 0d             	shr    $0xd,%ecx
ffffffff8ae63e39:	31 c1                	xor    %eax,%ecx
ffffffff8ae63e3b:	69 c9 35 ae b2 c2    	imul   $0xc2b2ae35,%ecx,%ecx
ffffffff8ae63e41:	89 c8                	mov    %ecx,%eax
ffffffff8ae63e43:	c1 e8 10             	shr    $0x10,%eax
ffffffff8ae63e46:	31 c8                	xor    %ecx,%eax
ffffffff8ae63e48:	5d                   	pop    %rbp
ffffffff8ae63e49:	c3                   	ret
ffffffff8ae63e4a:	90                   	nop
ffffffff8ae63e4b:	90                   	nop
ffffffff8ae63e4c:	90                   	nop
ffffffff8ae63e4d:	90                   	nop
ffffffff8ae63e4e:	90                   	nop
ffffffff8ae63e4f:	90                   	nop

ffffffff8ae63e50 <frame_candidate_4a3e50>:
ffffffff8ae63e50:	55                   	push   %rbp
ffffffff8ae63e51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63e54:	c4 e1 f9 7e c0       	vmovq  %xmm0,%rax
ffffffff8ae63e59:	48 89 c1             	mov    %rax,%rcx
ffffffff8ae63e5c:	48 c1 e9 20          	shr    $0x20,%rcx
ffffffff8ae63e60:	89 ca                	mov    %ecx,%edx
ffffffff8ae63e62:	81 e2 ff ff ff 7f    	and    $0x7fffffff,%edx
ffffffff8ae63e68:	81 fa 00 00 90 40    	cmp    $0x40900000,%edx
ffffffff8ae63e6e:	72 2d                	jb     ffffffff8ae63e9d <frame_candidate_4a3e50+0x4d>
ffffffff8ae63e70:	81 fa 00 00 f0 7f    	cmp    $0x7ff00000,%edx
ffffffff8ae63e76:	72 37                	jb     ffffffff8ae63eaf <frame_candidate_4a3e50+0x5f>
ffffffff8ae63e78:	c5 fb 58 c0          	vaddsd %xmm0,%xmm0,%xmm0
ffffffff8ae63e7c:	81 e1 ff ff 0f 00    	and    $0xfffff,%ecx
ffffffff8ae63e82:	09 c1                	or     %eax,%ecx
ffffffff8ae63e84:	c5 f9 28 c8          	vmovapd %xmm0,%xmm1
ffffffff8ae63e88:	75 04                	jne    ffffffff8ae63e8e <frame_candidate_4a3e50+0x3e>
ffffffff8ae63e8a:	c5 f1 57 c9          	vxorpd %xmm1,%xmm1,%xmm1
ffffffff8ae63e8e:	48 85 c0             	test   %rax,%rax
ffffffff8ae63e91:	0f 89 1d 01 00 00    	jns    ffffffff8ae63fb4 <frame_candidate_4a3e50+0x164>
ffffffff8ae63e97:	c5 f9 28 c1          	vmovapd %xmm1,%xmm0
ffffffff8ae63e9b:	5d                   	pop    %rbp
ffffffff8ae63e9c:	c3                   	ret
ffffffff8ae63e9d:	81 fa ff ff 8f 3c    	cmp    $0x3c8fffff,%edx
ffffffff8ae63ea3:	77 2a                	ja     ffffffff8ae63ecf <frame_candidate_4a3e50+0x7f>
ffffffff8ae63ea5:	c5 fb 58 05 33 68 f1 	vaddsd 0xf16833(%rip),%xmm0,%xmm0        # ffffffff8bd7a6e0 <frame_candidate_4a4a40+0xf15ca0>
ffffffff8ae63eac:	00 
ffffffff8ae63ead:	5d                   	pop    %rbp
ffffffff8ae63eae:	c3                   	ret
ffffffff8ae63eaf:	c5 f9 2e 05 79 6c f1 	vucomisd 0xf16c79(%rip),%xmm0        # ffffffff8bd7ab30 <frame_candidate_4a4a40+0xf160f0>
ffffffff8ae63eb6:	00 
ffffffff8ae63eb7:	0f 83 d7 00 00 00    	jae    ffffffff8ae63f94 <frame_candidate_4a3e50+0x144>
ffffffff8ae63ebd:	c5 fb 10 0d 3b 6c f1 	vmovsd 0xf16c3b(%rip),%xmm1        # ffffffff8bd7ab00 <frame_candidate_4a4a40+0xf160c0>
ffffffff8ae63ec4:	00 
ffffffff8ae63ec5:	c5 f9 2e c8          	vucomisd %xmm0,%xmm1
ffffffff8ae63ec9:	0f 83 d5 00 00 00    	jae    ffffffff8ae63fa4 <frame_candidate_4a3e50+0x154>
ffffffff8ae63ecf:	c5 fb 58 0d 19 6e f1 	vaddsd 0xf16e19(%rip),%xmm0,%xmm1        # ffffffff8bd7acf0 <frame_candidate_4a4a40+0xf162b0>
ffffffff8ae63ed6:	00 
ffffffff8ae63ed7:	48 8d 15 52 f1 0e 01 	lea    0x10ef152(%rip),%rdx        # ffffffff8bf53030 <frame_candidate_4a4a40+0x10ee5f0>
ffffffff8ae63ede:	c4 e1 f9 7e c8       	vmovq  %xmm1,%rax
ffffffff8ae63ee3:	c5 f3 58 0d 75 6d f1 	vaddsd 0xf16d75(%rip),%xmm1,%xmm1        # ffffffff8bd7ac60 <frame_candidate_4a4a40+0xf16220>
ffffffff8ae63eea:	00 
ffffffff8ae63eeb:	83 e8 80             	sub    $0xffffff80,%eax
ffffffff8ae63eee:	0f b6 c8             	movzbl %al,%ecx
ffffffff8ae63ef1:	c1 e0 0c             	shl    $0xc,%eax
ffffffff8ae63ef4:	c1 e1 04             	shl    $0x4,%ecx
ffffffff8ae63ef7:	25 00 00 f0 ff       	and    $0xfff00000,%eax
ffffffff8ae63efc:	c5 fb 5c c9          	vsubsd %xmm1,%xmm0,%xmm1
ffffffff8ae63f00:	c5 f3 5c 4c 0a 08    	vsubsd 0x8(%rdx,%rcx,1),%xmm1,%xmm1
ffffffff8ae63f06:	c5 fb 10 04 11       	vmovsd (%rcx,%rdx,1),%xmm0
ffffffff8ae63f0b:	3d 00 00 30 c0       	cmp    $0xc0300000,%eax
ffffffff8ae63f10:	7c 11                	jl     ffffffff8ae63f23 <frame_candidate_4a3e50+0xd3>
ffffffff8ae63f12:	8d 88 00 00 f0 3f    	lea    0x3ff00000(%rax),%ecx
ffffffff8ae63f18:	48 c1 e1 20          	shl    $0x20,%rcx
ffffffff8ae63f1c:	c4 e1 f9 6e d1       	vmovq  %rcx,%xmm2
ffffffff8ae63f21:	eb 0f                	jmp    ffffffff8ae63f32 <frame_candidate_4a3e50+0xe2>
ffffffff8ae63f23:	8d 88 00 00 70 7e    	lea    0x7e700000(%rax),%ecx
ffffffff8ae63f29:	48 c1 e1 20          	shl    $0x20,%rcx
ffffffff8ae63f2d:	c4 e1 f9 6e d9       	vmovq  %rcx,%xmm3
ffffffff8ae63f32:	c5 f3 59 2d 9e 65 f1 	vmulsd 0xf1659e(%rip),%xmm1,%xmm5        # ffffffff8bd7a4d8 <frame_candidate_4a4a40+0xf15a98>
ffffffff8ae63f39:	00 
ffffffff8ae63f3a:	c5 fb 59 e1          	vmulsd %xmm1,%xmm0,%xmm4
ffffffff8ae63f3e:	c5 d3 58 2d b2 6d f1 	vaddsd 0xf16db2(%rip),%xmm5,%xmm5        # ffffffff8bd7acf8 <frame_candidate_4a4a40+0xf162b8>
ffffffff8ae63f45:	00 
ffffffff8ae63f46:	c5 f3 59 ed          	vmulsd %xmm5,%xmm1,%xmm5
ffffffff8ae63f4a:	c5 d3 58 2d 3e 66 f1 	vaddsd 0xf1663e(%rip),%xmm5,%xmm5        # ffffffff8bd7a590 <frame_candidate_4a4a40+0xf15b50>
ffffffff8ae63f51:	00 
ffffffff8ae63f52:	c5 f3 59 ed          	vmulsd %xmm5,%xmm1,%xmm5
ffffffff8ae63f56:	c5 d3 58 2d 12 67 f1 	vaddsd 0xf16712(%rip),%xmm5,%xmm5        # ffffffff8bd7a670 <frame_candidate_4a4a40+0xf15c30>
ffffffff8ae63f5d:	00 
ffffffff8ae63f5e:	c5 f3 59 cd          	vmulsd %xmm5,%xmm1,%xmm1
ffffffff8ae63f62:	c5 f3 58 0d 36 6b f1 	vaddsd 0xf16b36(%rip),%xmm1,%xmm1        # ffffffff8bd7aaa0 <frame_candidate_4a4a40+0xf16060>
ffffffff8ae63f69:	00 
ffffffff8ae63f6a:	c5 db 59 c9          	vmulsd %xmm1,%xmm4,%xmm1
ffffffff8ae63f6e:	c5 fb 58 c1          	vaddsd %xmm1,%xmm0,%xmm0
ffffffff8ae63f72:	3d 00 00 30 c0       	cmp    $0xc0300000,%eax
ffffffff8ae63f77:	7c 15                	jl     ffffffff8ae63f8e <frame_candidate_4a3e50+0x13e>
ffffffff8ae63f79:	3d 00 00 00 40       	cmp    $0x40000000,%eax
ffffffff8ae63f7e:	75 1e                	jne    ffffffff8ae63f9e <frame_candidate_4a3e50+0x14e>
ffffffff8ae63f80:	c5 fb 58 c0          	vaddsd %xmm0,%xmm0,%xmm0
ffffffff8ae63f84:	c5 fb 59 05 14 69 f1 	vmulsd 0xf16914(%rip),%xmm0,%xmm0        # ffffffff8bd7a8a0 <frame_candidate_4a4a40+0xf15e60>
ffffffff8ae63f8b:	00 
ffffffff8ae63f8c:	5d                   	pop    %rbp
ffffffff8ae63f8d:	c3                   	ret
ffffffff8ae63f8e:	c5 fb 59 c3          	vmulsd %xmm3,%xmm0,%xmm0
ffffffff8ae63f92:	eb 18                	jmp    ffffffff8ae63fac <frame_candidate_4a3e50+0x15c>
ffffffff8ae63f94:	c5 fb 10 05 ec 65 f1 	vmovsd 0xf165ec(%rip),%xmm0        # ffffffff8bd7a588 <frame_candidate_4a4a40+0xf15b48>
ffffffff8ae63f9b:	00 
ffffffff8ae63f9c:	5d                   	pop    %rbp
ffffffff8ae63f9d:	c3                   	ret
ffffffff8ae63f9e:	c5 fb 59 c2          	vmulsd %xmm2,%xmm0,%xmm0
ffffffff8ae63fa2:	5d                   	pop    %rbp
ffffffff8ae63fa3:	c3                   	ret
ffffffff8ae63fa4:	c5 fb 10 05 d4 41 62 	vmovsd 0x16241d4(%rip),%xmm0        # ffffffff8c488180 <frame_candidate_4a4a40+0x1623740>
ffffffff8ae63fab:	01 
ffffffff8ae63fac:	c5 fb 59 05 cc 41 62 	vmulsd 0x16241cc(%rip),%xmm0,%xmm0        # ffffffff8c488180 <frame_candidate_4a4a40+0x1623740>
ffffffff8ae63fb3:	01 
ffffffff8ae63fb4:	5d                   	pop    %rbp
ffffffff8ae63fb5:	c3                   	ret
ffffffff8ae63fb6:	90                   	nop
ffffffff8ae63fb7:	90                   	nop
ffffffff8ae63fb8:	90                   	nop
ffffffff8ae63fb9:	90                   	nop
ffffffff8ae63fba:	90                   	nop
ffffffff8ae63fbb:	90                   	nop
ffffffff8ae63fbc:	90                   	nop
ffffffff8ae63fbd:	90                   	nop
ffffffff8ae63fbe:	90                   	nop
ffffffff8ae63fbf:	90                   	nop

ffffffff8ae63fc0 <frame_candidate_4a3fc0>:
ffffffff8ae63fc0:	55                   	push   %rbp
ffffffff8ae63fc1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae63fc4:	41 57                	push   %r15
ffffffff8ae63fc6:	41 56                	push   %r14
ffffffff8ae63fc8:	41 55                	push   %r13
ffffffff8ae63fca:	41 54                	push   %r12
ffffffff8ae63fcc:	53                   	push   %rbx
ffffffff8ae63fcd:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8ae63fd1:	4c 8d 2d 38 83 47 03 	lea    0x3478338(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae63fd8:	49 89 fe             	mov    %rdi,%r14
ffffffff8ae63fdb:	48 89 f3             	mov    %rsi,%rbx
ffffffff8ae63fde:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8ae63fe2:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8ae63fe6:	4c 8b 7f 48          	mov    0x48(%rdi),%r15
ffffffff8ae63fea:	44 8b 67 78          	mov    0x78(%rdi),%r12d
ffffffff8ae63fee:	48 8d 7d b8          	lea    -0x48(%rbp),%rdi
ffffffff8ae63ff2:	e8 49 b7 62 00       	call   ffffffff8b48f740 <frame_candidate_4a4a40+0x62ad00>
ffffffff8ae63ff7:	41 f6 46 78 01       	testb  $0x1,0x78(%r14)
ffffffff8ae63ffc:	74 22                	je     ffffffff8ae64020 <frame_candidate_4a3fc0+0x60>
ffffffff8ae63ffe:	41 8b 97 84 00 00 00 	mov    0x84(%r15),%edx
ffffffff8ae64005:	03 53 30             	add    0x30(%rbx),%edx
ffffffff8ae64008:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae6400b:	be 05 00 00 00       	mov    $0x5,%esi
ffffffff8ae64010:	e8 eb 7e 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae64015:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
ffffffff8ae64019:	49 89 87 f0 00 00 00 	mov    %rax,0xf0(%r15)
ffffffff8ae64020:	8b 53 30             	mov    0x30(%rbx),%edx
ffffffff8ae64023:	83 fa 04             	cmp    $0x4,%edx
ffffffff8ae64026:	77 5b                	ja     ffffffff8ae64083 <frame_candidate_4a3fc0+0xc3>
ffffffff8ae64028:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae6402c:	48 8d 3d 58 55 e2 00 	lea    0xe25558(%rip),%rdi        # ffffffff8bc8958b <frame_candidate_4a4a40+0xe24b4b>
ffffffff8ae64033:	31 c0                	xor    %eax,%eax
ffffffff8ae64035:	e8 d6 93 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae6403a:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae6403f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae64042:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8ae64047:	e8 b4 7e 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae6404c:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae64051:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae64054:	be 09 00 00 00       	mov    $0x9,%esi
ffffffff8ae64059:	e8 a2 7e 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae6405e:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64061:	e8 ea 67 f8 ff       	call   ffffffff8adea850 <handler_641_body-0x78590>
ffffffff8ae64066:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8ae6406a:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8ae6406e:	0f 85 ae 03 00 00    	jne    ffffffff8ae64422 <frame_candidate_4a3fc0+0x462>
ffffffff8ae64074:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8ae64078:	5b                   	pop    %rbx
ffffffff8ae64079:	41 5c                	pop    %r12
ffffffff8ae6407b:	41 5d                	pop    %r13
ffffffff8ae6407d:	41 5e                	pop    %r14
ffffffff8ae6407f:	41 5f                	pop    %r15
ffffffff8ae64081:	5d                   	pop    %rbp
ffffffff8ae64082:	c3                   	ret
ffffffff8ae64083:	39 53 18             	cmp    %edx,0x18(%rbx)
ffffffff8ae64086:	7d 12                	jge    ffffffff8ae6409a <frame_candidate_4a3fc0+0xda>
ffffffff8ae64088:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae6408b:	89 d6                	mov    %edx,%esi
ffffffff8ae6408d:	e8 be 50 57 00       	call   ffffffff8b3d9150 <frame_candidate_4a4a40+0x574710>
ffffffff8ae64092:	48 89 c3             	mov    %rax,%rbx
ffffffff8ae64095:	48 85 c0             	test   %rax,%rax
ffffffff8ae64098:	74 cc                	je     ffffffff8ae64066 <frame_candidate_4a3fc0+0xa6>
ffffffff8ae6409a:	41 f6 87 80 00 00 00 	testb  $0x20,0x80(%r15)
ffffffff8ae640a1:	20 
ffffffff8ae640a2:	4c 8b 6b 10          	mov    0x10(%rbx),%r13
ffffffff8ae640a6:	75 6b                	jne    ffffffff8ae64113 <frame_candidate_4a3fc0+0x153>
ffffffff8ae640a8:	49 8d 45 02          	lea    0x2(%r13),%rax
ffffffff8ae640ac:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae640af:	be 04 00 00 00       	mov    $0x4,%esi
ffffffff8ae640b4:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8ae640b8:	e8 a3 4f 57 00       	call   ffffffff8b3d9060 <frame_candidate_4a4a40+0x574620>
ffffffff8ae640bd:	41 0f b6 55 00       	movzbl 0x0(%r13),%edx
ffffffff8ae640c2:	83 fa 0f             	cmp    $0xf,%edx
ffffffff8ae640c5:	0f 84 cc 00 00 00    	je     ffffffff8ae64197 <frame_candidate_4a3fc0+0x1d7>
ffffffff8ae640cb:	81 fa 8f 00 00 00    	cmp    $0x8f,%edx
ffffffff8ae640d1:	0f 84 c0 00 00 00    	je     ffffffff8ae64197 <frame_candidate_4a3fc0+0x1d7>
ffffffff8ae640d7:	81 fa ff 00 00 00    	cmp    $0xff,%edx
ffffffff8ae640dd:	0f 85 bc 02 00 00    	jne    ffffffff8ae6439f <frame_candidate_4a3fc0+0x3df>
ffffffff8ae640e3:	41 80 7d 01 03       	cmpb   $0x3,0x1(%r13)
ffffffff8ae640e8:	b2 ff                	mov    $0xff,%dl
ffffffff8ae640ea:	0f 85 af 02 00 00    	jne    ffffffff8ae6439f <frame_candidate_4a3fc0+0x3df>
ffffffff8ae640f0:	41 f6 87 80 00 00 00 	testb  $0x2,0x80(%r15)
ffffffff8ae640f7:	02 
ffffffff8ae640f8:	0f 85 d2 02 00 00    	jne    ffffffff8ae643d0 <frame_candidate_4a3fc0+0x410>
ffffffff8ae640fe:	4c 8b 65 b0          	mov    -0x50(%rbp),%r12
ffffffff8ae64102:	41 0f b7 04 24       	movzwl (%r12),%eax
ffffffff8ae64107:	66 0f 38 f1 45 ce    	movbe  %ax,-0x32(%rbp)
ffffffff8ae6410d:	66 c1 c0 08          	rol    $0x8,%ax
ffffffff8ae64111:	eb 30                	jmp    ffffffff8ae64143 <frame_candidate_4a3fc0+0x183>
ffffffff8ae64113:	48 8d 7d ce          	lea    -0x32(%rbp),%rdi
ffffffff8ae64117:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8ae6411c:	4c 89 ee             	mov    %r13,%rsi
ffffffff8ae6411f:	e8 8c 4f db ff       	call   ffffffff8ac190b0 <handler_641_body-0x249d30>
ffffffff8ae64124:	0f b7 45 ce          	movzwl -0x32(%rbp),%eax
ffffffff8ae64128:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae6412b:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8ae64130:	66 0f 38 f1 45 ce    	movbe  %ax,-0x32(%rbp)
ffffffff8ae64136:	4c 8b 63 10          	mov    0x10(%rbx),%r12
ffffffff8ae6413a:	e8 21 4f 57 00       	call   ffffffff8b3d9060 <frame_candidate_4a4a40+0x574620>
ffffffff8ae6413f:	0f b7 45 ce          	movzwl -0x32(%rbp),%eax
ffffffff8ae64143:	4c 8d 2d c6 81 47 03 	lea    0x34781c6(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae6414a:	0f b7 c8             	movzwl %ax,%ecx
ffffffff8ae6414d:	81 f9 20 c0 00 00    	cmp    $0xc020,%ecx
ffffffff8ae64153:	7e 72                	jle    ffffffff8ae641c7 <frame_candidate_4a3fc0+0x207>
ffffffff8ae64155:	81 f9 21 c0 00 00    	cmp    $0xc021,%ecx
ffffffff8ae6415b:	0f 84 d2 00 00 00    	je     ffffffff8ae64233 <frame_candidate_4a3fc0+0x273>
ffffffff8ae64161:	81 f9 23 c0 00 00    	cmp    $0xc023,%ecx
ffffffff8ae64167:	0f 84 dd 00 00 00    	je     ffffffff8ae6424a <frame_candidate_4a3fc0+0x28a>
ffffffff8ae6416d:	81 f9 23 c2 00 00    	cmp    $0xc223,%ecx
ffffffff8ae64173:	0f 85 24 01 00 00    	jne    ffffffff8ae6429d <frame_candidate_4a3fc0+0x2dd>
ffffffff8ae64179:	41 83 bf 18 01 00 00 	cmpl   $0x3,0x118(%r15)
ffffffff8ae64180:	03 
ffffffff8ae64181:	0f 8c d7 fe ff ff    	jl     ffffffff8ae6405e <frame_candidate_4a3fc0+0x9e>
ffffffff8ae64187:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae6418a:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae6418d:	e8 1e 22 00 00       	call   ffffffff8ae663b0 <frame_candidate_4a4a40+0x1970>
ffffffff8ae64192:	e9 c7 fe ff ff       	jmp    ffffffff8ae6405e <frame_candidate_4a3fc0+0x9e>
ffffffff8ae64197:	41 f6 87 80 00 00 00 	testb  $0x2,0x80(%r15)
ffffffff8ae6419e:	02 
ffffffff8ae6419f:	75 52                	jne    ffffffff8ae641f3 <frame_candidate_4a3fc0+0x233>
ffffffff8ae641a1:	41 f6 c4 04          	test   $0x4,%r12b
ffffffff8ae641a5:	0f 84 e6 00 00 00    	je     ffffffff8ae64291 <frame_candidate_4a3fc0+0x2d1>
ffffffff8ae641ab:	66 41 0f 38 f0 45 02 	movbe  0x2(%r13),%ax
ffffffff8ae641b2:	41 0f b6 4d 01       	movzbl 0x1(%r13),%ecx
ffffffff8ae641b7:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae641bb:	48 8d 3d 01 45 e4 00 	lea    0xe44501(%rip),%rdi        # ffffffff8bca86c3 <frame_candidate_4a4a40+0xe43c83>
ffffffff8ae641c2:	e9 f2 01 00 00       	jmp    ffffffff8ae643b9 <frame_candidate_4a3fc0+0x3f9>
ffffffff8ae641c7:	83 f9 21             	cmp    $0x21,%ecx
ffffffff8ae641ca:	0f 84 98 00 00 00    	je     ffffffff8ae64268 <frame_candidate_4a3fc0+0x2a8>
ffffffff8ae641d0:	81 f9 21 80 00 00    	cmp    $0x8021,%ecx
ffffffff8ae641d6:	0f 85 c1 00 00 00    	jne    ffffffff8ae6429d <frame_candidate_4a3fc0+0x2dd>
ffffffff8ae641dc:	41 83 bf 18 01 00 00 	cmpl   $0x4,0x118(%r15)
ffffffff8ae641e3:	04 
ffffffff8ae641e4:	0f 85 74 fe ff ff    	jne    ffffffff8ae6405e <frame_candidate_4a3fc0+0x9e>
ffffffff8ae641ea:	48 8d 3d 9f b8 9d 00 	lea    0x9db89f(%rip),%rdi        # ffffffff8b83fa90 <frame_candidate_4a4a40+0x9db050>
ffffffff8ae641f1:	eb 47                	jmp    ffffffff8ae6423a <frame_candidate_4a3fc0+0x27a>
ffffffff8ae641f3:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
ffffffff8ae641f7:	66 0f 38 f0 00       	movbe  (%rax),%ax
ffffffff8ae641fc:	66 3d 00 08          	cmp    $0x800,%ax
ffffffff8ae64200:	0f 84 84 00 00 00    	je     ffffffff8ae6428a <frame_candidate_4a3fc0+0x2ca>
ffffffff8ae64206:	0f b7 c0             	movzwl %ax,%eax
ffffffff8ae64209:	3d 35 80 00 00       	cmp    $0x8035,%eax
ffffffff8ae6420e:	0f 85 74 01 00 00    	jne    ffffffff8ae64388 <frame_candidate_4a3fc0+0x3c8>
ffffffff8ae64214:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae64217:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae6421a:	e8 11 02 00 00       	call   ffffffff8ae64430 <frame_candidate_4a4430>
ffffffff8ae6421f:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64222:	e8 29 66 f8 ff       	call   ffffffff8adea850 <handler_641_body-0x78590>
ffffffff8ae64227:	4c 8d 2d e2 80 47 03 	lea    0x34780e2(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae6422e:	e9 33 fe ff ff       	jmp    ffffffff8ae64066 <frame_candidate_4a3fc0+0xa6>
ffffffff8ae64233:	48 8d 3d 46 b6 9d 00 	lea    0x9db646(%rip),%rdi        # ffffffff8b83f880 <frame_candidate_4a4a40+0x9dae40>
ffffffff8ae6423a:	4c 89 fe             	mov    %r15,%rsi
ffffffff8ae6423d:	48 89 da             	mov    %rbx,%rdx
ffffffff8ae64240:	e8 fb 07 00 00       	call   ffffffff8ae64a40 <frame_candidate_4a4a40>
ffffffff8ae64245:	e9 14 fe ff ff       	jmp    ffffffff8ae6405e <frame_candidate_4a3fc0+0x9e>
ffffffff8ae6424a:	41 83 bf 18 01 00 00 	cmpl   $0x3,0x118(%r15)
ffffffff8ae64251:	03 
ffffffff8ae64252:	0f 8c 06 fe ff ff    	jl     ffffffff8ae6405e <frame_candidate_4a3fc0+0x9e>
ffffffff8ae64258:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae6425b:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae6425e:	e8 0d 1b 00 00       	call   ffffffff8ae65d70 <frame_candidate_4a4a40+0x1330>
ffffffff8ae64263:	e9 f6 fd ff ff       	jmp    ffffffff8ae6405e <frame_candidate_4a3fc0+0x9e>
ffffffff8ae64268:	48 8d 7d b8          	lea    -0x48(%rbp),%rdi
ffffffff8ae6426c:	e8 cf b4 62 00       	call   ffffffff8b48f740 <frame_candidate_4a4a40+0x62ad00>
ffffffff8ae64271:	41 83 bf 30 01 00 00 	cmpl   $0x9,0x130(%r15)
ffffffff8ae64278:	09 
ffffffff8ae64279:	0f 85 bb fd ff ff    	jne    ffffffff8ae6403a <frame_candidate_4a3fc0+0x7a>
ffffffff8ae6427f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
ffffffff8ae64283:	49 89 87 00 01 00 00 	mov    %rax,0x100(%r15)
ffffffff8ae6428a:	41 f6 46 78 01       	testb  $0x1,0x78(%r14)
ffffffff8ae6428f:	75 7d                	jne    ffffffff8ae6430e <frame_candidate_4a3fc0+0x34e>
ffffffff8ae64291:	4c 8d 2d 78 80 47 03 	lea    0x3478078(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae64298:	e9 9d fd ff ff       	jmp    ffffffff8ae6403a <frame_candidate_4a3fc0+0x7a>
ffffffff8ae6429d:	41 83 bf 2c 01 00 00 	cmpl   $0x9,0x12c(%r15)
ffffffff8ae642a4:	09 
ffffffff8ae642a5:	75 37                	jne    ffffffff8ae642de <frame_candidate_4a3fc0+0x31e>
ffffffff8ae642a7:	49 8b 87 98 00 00 00 	mov    0x98(%r15),%rax
ffffffff8ae642ae:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae642b1:	be 21 c0 00 00       	mov    $0xc021,%esi
ffffffff8ae642b6:	4d 89 e1             	mov    %r12,%r9
ffffffff8ae642b9:	48 ff c0             	inc    %rax
ffffffff8ae642bc:	49 89 87 98 00 00 00 	mov    %rax,0x98(%r15)
ffffffff8ae642c3:	0f b6 c8             	movzbl %al,%ecx
ffffffff8ae642c6:	8b 53 30             	mov    0x30(%rbx),%edx
ffffffff8ae642c9:	83 c2 02             	add    $0x2,%edx
ffffffff8ae642cc:	44 0f b7 c2          	movzwl %dx,%r8d
ffffffff8ae642d0:	ba 08 00 00 00       	mov    $0x8,%edx
ffffffff8ae642d5:	e8 76 03 00 00       	call   ffffffff8ae64650 <frame_candidate_4a4650>
ffffffff8ae642da:	0f b7 45 ce          	movzwl -0x32(%rbp),%eax
ffffffff8ae642de:	66 c1 c0 08          	rol    $0x8,%ax
ffffffff8ae642e2:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae642e6:	48 8d 3d 2e 89 e7 00 	lea    0xe7892e(%rip),%rdi        # ffffffff8bcdcc1b <frame_candidate_4a4a40+0xe781db>
ffffffff8ae642ed:	0f b7 d0             	movzwl %ax,%edx
ffffffff8ae642f0:	31 c0                	xor    %eax,%eax
ffffffff8ae642f2:	e8 19 91 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae642f7:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae642fc:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae642ff:	be 0b 00 00 00       	mov    $0xb,%esi
ffffffff8ae64304:	e8 f7 7b 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae64309:	e9 2c fd ff ff       	jmp    ffffffff8ae6403a <frame_candidate_4a3fc0+0x7a>
ffffffff8ae6430e:	49 81 c7 88 01 00 00 	add    $0x188,%r15
ffffffff8ae64315:	31 f6                	xor    %esi,%esi
ffffffff8ae64317:	31 d2                	xor    %edx,%edx
ffffffff8ae64319:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6431b:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae6431e:	e8 dd 26 02 00       	call   ffffffff8ae86a00 <frame_candidate_4a4a40+0x21fc0>
ffffffff8ae64323:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8ae64328:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae6432b:	e8 90 3f e5 ff       	call   ffffffff8acb82c0 <handler_641_body-0x1aab20>
ffffffff8ae64330:	4c 8d 2d d9 7f 47 03 	lea    0x3477fd9(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae64337:	85 c0                	test   %eax,%eax
ffffffff8ae64339:	0f 84 d0 00 00 00    	je     ffffffff8ae6440f <frame_candidate_4a3fc0+0x44f>
ffffffff8ae6433f:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae64343:	48 8d 3d be 36 dd 00 	lea    0xdd36be(%rip),%rdi        # ffffffff8bc37a08 <frame_candidate_4a4a40+0xdd2fc8>
ffffffff8ae6434a:	31 c0                	xor    %eax,%eax
ffffffff8ae6434c:	e8 bf 90 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64351:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae64354:	31 f6                	xor    %esi,%esi
ffffffff8ae64356:	31 d2                	xor    %edx,%edx
ffffffff8ae64358:	31 c9                	xor    %ecx,%ecx
ffffffff8ae6435a:	e8 41 2c 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae6435f:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae64364:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae64367:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8ae6436c:	e8 8f 7b 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae64371:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae64376:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae64379:	be 09 00 00 00       	mov    $0x9,%esi
ffffffff8ae6437e:	e8 7d 7b 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae64383:	e9 de fc ff ff       	jmp    ffffffff8ae64066 <frame_candidate_4a3fc0+0xa6>
ffffffff8ae64388:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae6438d:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae64390:	be 0b 00 00 00       	mov    $0xb,%esi
ffffffff8ae64395:	e8 66 7b 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae6439a:	41 0f b6 55 00       	movzbl 0x0(%r13),%edx
ffffffff8ae6439f:	66 41 0f 38 f0 45 02 	movbe  0x2(%r13),%ax
ffffffff8ae643a6:	41 0f b6 4d 01       	movzbl 0x1(%r13),%ecx
ffffffff8ae643ab:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae643af:	0f b6 d2             	movzbl %dl,%edx
ffffffff8ae643b2:	48 8d 3d 5f 24 ec 00 	lea    0xec245f(%rip),%rdi        # ffffffff8bd26818 <frame_candidate_4a4a40+0xec1dd8>
ffffffff8ae643b9:	44 0f b7 c0          	movzwl %ax,%r8d
ffffffff8ae643bd:	31 c0                	xor    %eax,%eax
ffffffff8ae643bf:	e8 4c 90 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae643c4:	4c 8d 2d 45 7f 47 03 	lea    0x3477f45(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae643cb:	e9 6a fc ff ff       	jmp    ffffffff8ae6403a <frame_candidate_4a3fc0+0x7a>
ffffffff8ae643d0:	4c 8d 2d 39 7f 47 03 	lea    0x3477f39(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae643d7:	41 f6 c4 04          	test   $0x4,%r12b
ffffffff8ae643db:	0f 84 59 fc ff ff    	je     ffffffff8ae6403a <frame_candidate_4a3fc0+0x7a>
ffffffff8ae643e1:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
ffffffff8ae643e5:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae643e9:	48 8d 3d 1d 5e e0 00 	lea    0xe05e1d(%rip),%rdi        # ffffffff8bc6a20d <frame_candidate_4a4a40+0xe057cd>
ffffffff8ae643f0:	ba ff 00 00 00       	mov    $0xff,%edx
ffffffff8ae643f5:	b9 03 00 00 00       	mov    $0x3,%ecx
ffffffff8ae643fa:	66 0f 38 f0 00       	movbe  (%rax),%ax
ffffffff8ae643ff:	44 0f b7 c0          	movzwl %ax,%r8d
ffffffff8ae64403:	31 c0                	xor    %eax,%eax
ffffffff8ae64405:	e8 06 90 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae6440a:	e9 2b fc ff ff       	jmp    ffffffff8ae6403a <frame_candidate_4a3fc0+0x7a>
ffffffff8ae6440f:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae64412:	31 f6                	xor    %esi,%esi
ffffffff8ae64414:	31 d2                	xor    %edx,%edx
ffffffff8ae64416:	31 c9                	xor    %ecx,%ecx
ffffffff8ae64418:	e8 83 2b 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae6441d:	e9 44 fc ff ff       	jmp    ffffffff8ae64066 <frame_candidate_4a3fc0+0xa6>
ffffffff8ae64422:	e8 89 92 25 00       	call   ffffffff8b0bd6b0 <frame_candidate_4a4a40+0x258c70>
ffffffff8ae64427:	0f 0b                	ud2
ffffffff8ae64429:	90                   	nop
ffffffff8ae6442a:	90                   	nop
ffffffff8ae6442b:	90                   	nop
ffffffff8ae6442c:	90                   	nop
ffffffff8ae6442d:	90                   	nop
ffffffff8ae6442e:	90                   	nop
ffffffff8ae6442f:	90                   	nop

ffffffff8ae64430 <frame_candidate_4a4430>:
ffffffff8ae64430:	55                   	push   %rbp
ffffffff8ae64431:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae64434:	41 57                	push   %r15
ffffffff8ae64436:	41 56                	push   %r14
ffffffff8ae64438:	41 55                	push   %r13
ffffffff8ae6443a:	41 54                	push   %r12
ffffffff8ae6443c:	53                   	push   %rbx
ffffffff8ae6443d:	50                   	push   %rax
ffffffff8ae6443e:	4c 8b 37             	mov    (%rdi),%r14
ffffffff8ae64441:	8b 56 30             	mov    0x30(%rsi),%edx
ffffffff8ae64444:	83 fa 11             	cmp    $0x11,%edx
ffffffff8ae64447:	7f 23                	jg     ffffffff8ae6446c <frame_candidate_4a4430+0x3c>
ffffffff8ae64449:	49 83 c6 60          	add    $0x60,%r14
ffffffff8ae6444d:	48 8d 3d cd cf ea 00 	lea    0xeacfcd(%rip),%rdi        # ffffffff8bd11421 <frame_candidate_4a4a40+0xeac9e1>
ffffffff8ae64454:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae64457:	31 c0                	xor    %eax,%eax
ffffffff8ae64459:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae6445d:	5b                   	pop    %rbx
ffffffff8ae6445e:	41 5c                	pop    %r12
ffffffff8ae64460:	41 5d                	pop    %r13
ffffffff8ae64462:	41 5e                	pop    %r14
ffffffff8ae64464:	41 5f                	pop    %r15
ffffffff8ae64466:	5d                   	pop    %rbp
ffffffff8ae64467:	e9 a4 8f db ff       	jmp    ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae6446c:	45 8b 7e 78          	mov    0x78(%r14),%r15d
ffffffff8ae64470:	4c 8b 66 10          	mov    0x10(%rsi),%r12
ffffffff8ae64474:	48 89 fb             	mov    %rdi,%rbx
ffffffff8ae64477:	41 f6 c7 04          	test   $0x4,%r15b
ffffffff8ae6447b:	74 42                	je     ffffffff8ae644bf <frame_candidate_4a4430+0x8f>
ffffffff8ae6447d:	41 0f 38 f0 0c 24    	movbe  (%r12),%ecx
ffffffff8ae64483:	45 8b 44 24 04       	mov    0x4(%r12),%r8d
ffffffff8ae64488:	45 8b 4c 24 08       	mov    0x8(%r12),%r9d
ffffffff8ae6448d:	45 0f b7 54 24 0c    	movzwl 0xc(%r12),%r10d
ffffffff8ae64493:	45 0f b7 5c 24 0e    	movzwl 0xe(%r12),%r11d
ffffffff8ae64499:	45 0f b7 6c 24 10    	movzwl 0x10(%r12),%r13d
ffffffff8ae6449f:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae644a3:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8ae644a7:	48 8d 3d 1f c1 df 00 	lea    0xdfc11f(%rip),%rdi        # ffffffff8bc605cd <frame_candidate_4a4a40+0xdfbb8d>
ffffffff8ae644ae:	31 c0                	xor    %eax,%eax
ffffffff8ae644b0:	41 55                	push   %r13
ffffffff8ae644b2:	41 53                	push   %r11
ffffffff8ae644b4:	41 52                	push   %r10
ffffffff8ae644b6:	e8 55 8f db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae644bb:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8ae644bf:	41 0f 38 f0 14 24    	movbe  (%r12),%edx
ffffffff8ae644c5:	85 d2                	test   %edx,%edx
ffffffff8ae644c7:	0f 84 80 00 00 00    	je     ffffffff8ae6454d <frame_candidate_4a4430+0x11d>
ffffffff8ae644cd:	83 fa 01             	cmp    $0x1,%edx
ffffffff8ae644d0:	0f 84 15 01 00 00    	je     ffffffff8ae645eb <frame_candidate_4a4430+0x1bb>
ffffffff8ae644d6:	83 fa 02             	cmp    $0x2,%edx
ffffffff8ae644d9:	0f 85 95 00 00 00    	jne    ffffffff8ae64574 <frame_candidate_4a4430+0x144>
ffffffff8ae644df:	c7 83 88 00 00 00 00 	movl   $0x0,0x88(%rbx)
ffffffff8ae644e6:	00 00 00 
ffffffff8ae644e9:	41 0f 38 f0 44 24 04 	movbe  0x4(%r12),%eax
ffffffff8ae644f0:	48 89 83 c0 00 00 00 	mov    %rax,0xc0(%rbx)
ffffffff8ae644f7:	48 39 83 98 00 00 00 	cmp    %rax,0x98(%rbx)
ffffffff8ae644fe:	0f 85 86 00 00 00    	jne    ffffffff8ae6458a <frame_candidate_4a4430+0x15a>
ffffffff8ae64504:	83 bb 8c 00 00 00 03 	cmpl   $0x3,0x8c(%rbx)
ffffffff8ae6450b:	72 27                	jb     ffffffff8ae64534 <frame_candidate_4a4430+0x104>
ffffffff8ae6450d:	49 8d 76 60          	lea    0x60(%r14),%rsi
ffffffff8ae64511:	48 8d 3d 33 c0 df 00 	lea    0xdfc033(%rip),%rdi        # ffffffff8bc6054b <frame_candidate_4a4a40+0xdfbb0b>
ffffffff8ae64518:	31 c0                	xor    %eax,%eax
ffffffff8ae6451a:	e8 f1 8e db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae6451f:	c7 83 8c 00 00 00 00 	movl   $0x0,0x8c(%rbx)
ffffffff8ae64526:	00 00 00 
ffffffff8ae64529:	41 f6 46 78 01       	testb  $0x1,0x78(%r14)
ffffffff8ae6452e:	0f 85 c6 00 00 00    	jne    ffffffff8ae645fa <frame_candidate_4a4430+0x1ca>
ffffffff8ae64534:	ff 83 8c 00 00 00    	incl   0x8c(%rbx)
ffffffff8ae6453a:	e8 91 e7 4e 00       	call   ffffffff8b352cd0 <frame_candidate_4a4a40+0x4ee290>
ffffffff8ae6453f:	89 c0                	mov    %eax,%eax
ffffffff8ae64541:	48 89 83 98 00 00 00 	mov    %rax,0x98(%rbx)
ffffffff8ae64548:	e9 9e 00 00 00       	jmp    ffffffff8ae645eb <frame_candidate_4a4430+0x1bb>
ffffffff8ae6454d:	48 8b 03             	mov    (%rbx),%rax
ffffffff8ae64550:	31 d2                	xor    %edx,%edx
ffffffff8ae64552:	48 8b 80 80 02 00 00 	mov    0x280(%rax),%rax
ffffffff8ae64559:	48 85 c0             	test   %rax,%rax
ffffffff8ae6455c:	74 6c                	je     ffffffff8ae645ca <frame_candidate_4a4430+0x19a>
ffffffff8ae6455e:	66 90                	xchg   %ax,%ax
ffffffff8ae64560:	48 8b 08             	mov    (%rax),%rcx
ffffffff8ae64563:	80 79 01 02          	cmpb   $0x2,0x1(%rcx)
ffffffff8ae64567:	74 4d                	je     ffffffff8ae645b6 <frame_candidate_4a4430+0x186>
ffffffff8ae64569:	48 8b 40 28          	mov    0x28(%rax),%rax
ffffffff8ae6456d:	48 85 c0             	test   %rax,%rax
ffffffff8ae64570:	75 ee                	jne    ffffffff8ae64560 <frame_candidate_4a4430+0x130>
ffffffff8ae64572:	eb 56                	jmp    ffffffff8ae645ca <frame_candidate_4a4430+0x19a>
ffffffff8ae64574:	41 f6 c7 04          	test   $0x4,%r15b
ffffffff8ae64578:	74 71                	je     ffffffff8ae645eb <frame_candidate_4a4430+0x1bb>
ffffffff8ae6457a:	49 83 c6 60          	add    $0x60,%r14
ffffffff8ae6457e:	48 8d 3d eb b6 ee 00 	lea    0xeeb6eb(%rip),%rdi        # ffffffff8bd4fc70 <frame_candidate_4a4a40+0xeeb230>
ffffffff8ae64585:	e9 ca fe ff ff       	jmp    ffffffff8ae64454 <frame_candidate_4a4430+0x24>
ffffffff8ae6458a:	c7 83 8c 00 00 00 00 	movl   $0x0,0x8c(%rbx)
ffffffff8ae64591:	00 00 00 
ffffffff8ae64594:	41 8b 46 78          	mov    0x78(%r14),%eax
ffffffff8ae64598:	83 e0 41             	and    $0x41,%eax
ffffffff8ae6459b:	83 f8 40             	cmp    $0x40,%eax
ffffffff8ae6459e:	75 4b                	jne    ffffffff8ae645eb <frame_candidate_4a4430+0x1bb>
ffffffff8ae645a0:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae645a3:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae645a7:	5b                   	pop    %rbx
ffffffff8ae645a8:	41 5c                	pop    %r12
ffffffff8ae645aa:	41 5d                	pop    %r13
ffffffff8ae645ac:	41 5e                	pop    %r14
ffffffff8ae645ae:	41 5f                	pop    %r15
ffffffff8ae645b0:	5d                   	pop    %rbp
ffffffff8ae645b1:	e9 ea 8c 01 00       	jmp    ffffffff8ae7d2a0 <frame_candidate_4a4a40+0x18860>
ffffffff8ae645b6:	8b 71 04             	mov    0x4(%rcx),%esi
ffffffff8ae645b9:	85 f6                	test   %esi,%esi
ffffffff8ae645bb:	74 0d                	je     ffffffff8ae645ca <frame_candidate_4a4430+0x19a>
ffffffff8ae645bd:	48 8b 40 10          	mov    0x10(%rax),%rax
ffffffff8ae645c1:	89 f2                	mov    %esi,%edx
ffffffff8ae645c3:	0f 38 f0 48 04       	movbe  0x4(%rax),%ecx
ffffffff8ae645c8:	eb 00                	jmp    ffffffff8ae645ca <frame_candidate_4a4430+0x19a>
ffffffff8ae645ca:	0f ca                	bswap  %edx
ffffffff8ae645cc:	85 d2                	test   %edx,%edx
ffffffff8ae645ce:	74 1b                	je     ffffffff8ae645eb <frame_candidate_4a4430+0x1bb>
ffffffff8ae645d0:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae645d3:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8ae645d8:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae645dc:	5b                   	pop    %rbx
ffffffff8ae645dd:	41 5c                	pop    %r12
ffffffff8ae645df:	41 5d                	pop    %r13
ffffffff8ae645e1:	41 5e                	pop    %r14
ffffffff8ae645e3:	41 5f                	pop    %r15
ffffffff8ae645e5:	5d                   	pop    %rbp
ffffffff8ae645e6:	e9 d5 8b 00 00       	jmp    ffffffff8ae6d1c0 <frame_candidate_4a4a40+0x8780>
ffffffff8ae645eb:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8ae645ef:	5b                   	pop    %rbx
ffffffff8ae645f0:	41 5c                	pop    %r12
ffffffff8ae645f2:	41 5d                	pop    %r13
ffffffff8ae645f4:	41 5e                	pop    %r14
ffffffff8ae645f6:	41 5f                	pop    %r15
ffffffff8ae645f8:	5d                   	pop    %rbp
ffffffff8ae645f9:	c3                   	ret
ffffffff8ae645fa:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae645fd:	e8 1e 8b 01 00       	call   ffffffff8ae7d120 <frame_candidate_4a4a40+0x186e0>
ffffffff8ae64602:	eb 1c                	jmp    ffffffff8ae64620 <frame_candidate_4a4430+0x1f0>
ffffffff8ae64604:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8ae6460b:	00 00 00 00 00 
ffffffff8ae64610:	48 c7 47 08 00 00 00 	movq   $0x0,0x8(%rdi)
ffffffff8ae64617:	00 
ffffffff8ae64618:	ff 4b 50             	decl   0x50(%rbx)
ffffffff8ae6461b:	e8 30 62 f8 ff       	call   ffffffff8adea850 <handler_641_body-0x78590>
ffffffff8ae64620:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8ae64624:	48 85 ff             	test   %rdi,%rdi
ffffffff8ae64627:	0f 84 07 ff ff ff    	je     ffffffff8ae64534 <frame_candidate_4a4430+0x104>
ffffffff8ae6462d:	48 8b 47 08          	mov    0x8(%rdi),%rax
ffffffff8ae64631:	48 89 43 40          	mov    %rax,0x40(%rbx)
ffffffff8ae64635:	48 85 c0             	test   %rax,%rax
ffffffff8ae64638:	75 d6                	jne    ffffffff8ae64610 <frame_candidate_4a4430+0x1e0>
ffffffff8ae6463a:	48 c7 43 48 00 00 00 	movq   $0x0,0x48(%rbx)
ffffffff8ae64641:	00 
ffffffff8ae64642:	eb cc                	jmp    ffffffff8ae64610 <frame_candidate_4a4430+0x1e0>
ffffffff8ae64644:	90                   	nop
ffffffff8ae64645:	90                   	nop
ffffffff8ae64646:	90                   	nop
ffffffff8ae64647:	90                   	nop
ffffffff8ae64648:	90                   	nop
ffffffff8ae64649:	90                   	nop
ffffffff8ae6464a:	90                   	nop
ffffffff8ae6464b:	90                   	nop
ffffffff8ae6464c:	90                   	nop
ffffffff8ae6464d:	90                   	nop
ffffffff8ae6464e:	90                   	nop
ffffffff8ae6464f:	90                   	nop

ffffffff8ae64650 <frame_candidate_4a4650>:
ffffffff8ae64650:	55                   	push   %rbp
ffffffff8ae64651:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae64654:	41 57                	push   %r15
ffffffff8ae64656:	41 56                	push   %r14
ffffffff8ae64658:	41 55                	push   %r13
ffffffff8ae6465a:	41 54                	push   %r12
ffffffff8ae6465c:	53                   	push   %rbx
ffffffff8ae6465d:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8ae64661:	48 8d 05 a8 7c 47 03 	lea    0x3477ca8(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae64668:	89 55 c4             	mov    %edx,-0x3c(%rbp)
ffffffff8ae6466b:	4c 89 4d 90          	mov    %r9,-0x70(%rbp)
ffffffff8ae6466f:	89 4d c0             	mov    %ecx,-0x40(%rbp)
ffffffff8ae64672:	45 31 ed             	xor    %r13d,%r13d
ffffffff8ae64675:	41 89 f6             	mov    %esi,%r14d
ffffffff8ae64678:	48 8d 75 c8          	lea    -0x38(%rbp),%rsi
ffffffff8ae6467c:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae64681:	48 8b 00             	mov    (%rax),%rax
ffffffff8ae64684:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8ae64688:	48 89 7d a0          	mov    %rdi,-0x60(%rbp)
ffffffff8ae6468c:	44 89 45 bc          	mov    %r8d,-0x44(%rbp)
ffffffff8ae64690:	48 8b 07             	mov    (%rdi),%rax
ffffffff8ae64693:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
ffffffff8ae64697:	8b 40 78             	mov    0x78(%rax),%eax
ffffffff8ae6469a:	89 45 b0             	mov    %eax,-0x50(%rbp)
ffffffff8ae6469d:	8b 87 80 00 00 00    	mov    0x80(%rdi),%eax
ffffffff8ae646a3:	48 8b 3d 76 09 05 03 	mov    0x3050976(%rip),%rdi        # ffffffff8deb5020 <frame_candidate_4a4a40+0x30505e0>
ffffffff8ae646aa:	c7 45 c8 02 00 00 00 	movl   $0x2,-0x38(%rbp)
ffffffff8ae646b1:	66 c7 45 cc 01 00    	movw   $0x1,-0x34(%rbp)
ffffffff8ae646b7:	a8 20                	test   $0x20,%al
ffffffff8ae646b9:	44 89 c0             	mov    %r8d,%eax
ffffffff8ae646bc:	41 0f 94 c5          	sete   %r13b
ffffffff8ae646c0:	45 01 ed             	add    %r13d,%r13d
ffffffff8ae646c3:	4d 89 ec             	mov    %r13,%r12
ffffffff8ae646c6:	49 81 f4 82 00 00 00 	xor    $0x82,%r12
ffffffff8ae646cd:	49 39 c4             	cmp    %rax,%r12
ffffffff8ae646d0:	4c 0f 43 e0          	cmovae %rax,%r12
ffffffff8ae646d4:	e8 a7 71 f9 ff       	call   ffffffff8adfb880 <handler_641_body-0x67560>
ffffffff8ae646d9:	48 8d 1d 30 25 0c 02 	lea    0x20c2530(%rip),%rbx        # ffffffff8cf26c10 <frame_candidate_4a4a40+0x20c21d0>
ffffffff8ae646e0:	49 89 c7             	mov    %rax,%r15
ffffffff8ae646e3:	48 8b 7b 48          	mov    0x48(%rbx),%rdi
ffffffff8ae646e7:	48 85 ff             	test   %rdi,%rdi
ffffffff8ae646ea:	0f 85 cf 02 00 00    	jne    ffffffff8ae649bf <frame_candidate_4a4650+0x36f>
ffffffff8ae646f0:	4d 85 ff             	test   %r15,%r15
ffffffff8ae646f3:	0f 84 a7 02 00 00    	je     ffffffff8ae649a0 <frame_candidate_4a4650+0x350>
ffffffff8ae646f9:	48 8b 4d a0          	mov    -0x60(%rbp),%rcx
ffffffff8ae646fd:	49 83 c5 02          	add    $0x2,%r13
ffffffff8ae64701:	49 8d 44 24 04       	lea    0x4(%r12),%rax
ffffffff8ae64706:	41 01 c5             	add    %eax,%r13d
ffffffff8ae64709:	45 89 6f 18          	mov    %r13d,0x18(%r15)
ffffffff8ae6470d:	45 89 6f 30          	mov    %r13d,0x30(%r15)
ffffffff8ae64711:	49 c7 47 20 00 00 00 	movq   $0x0,0x20(%r15)
ffffffff8ae64718:	00 
ffffffff8ae64719:	f6 81 80 00 00 00 20 	testb  $0x20,0x80(%rcx)
ffffffff8ae64720:	75 18                	jne    ffffffff8ae6473a <frame_candidate_4a4650+0xea>
ffffffff8ae64722:	4d 8b 6f 10          	mov    0x10(%r15),%r13
ffffffff8ae64726:	66 41 c7 45 00 ff 03 	movw   $0x3ff,0x0(%r13)
ffffffff8ae6472d:	66 45 0f 38 f1 75 02 	movbe  %r14w,0x2(%r13)
ffffffff8ae64734:	49 83 c5 04          	add    $0x4,%r13
ffffffff8ae64738:	eb 12                	jmp    ffffffff8ae6474c <frame_candidate_4a4650+0xfc>
ffffffff8ae6473a:	49 8b 4f 10          	mov    0x10(%r15),%rcx
ffffffff8ae6473e:	66 44 0f 38 f1 31    	movbe  %r14w,(%rcx)
ffffffff8ae64744:	4d 8b 6f 10          	mov    0x10(%r15),%r13
ffffffff8ae64748:	49 83 c5 02          	add    $0x2,%r13
ffffffff8ae6474c:	66 83 7d bc 00       	cmpw   $0x0,-0x44(%rbp)
ffffffff8ae64751:	8b 55 c4             	mov    -0x3c(%rbp),%edx
ffffffff8ae64754:	8b 5d b0             	mov    -0x50(%rbp),%ebx
ffffffff8ae64757:	8b 4d c0             	mov    -0x40(%rbp),%ecx
ffffffff8ae6475a:	41 88 55 00          	mov    %dl,0x0(%r13)
ffffffff8ae6475e:	41 88 4d 01          	mov    %cl,0x1(%r13)
ffffffff8ae64762:	66 41 0f 38 f1 45 02 	movbe  %ax,0x2(%r13)
ffffffff8ae64769:	74 10                	je     ffffffff8ae6477b <frame_candidate_4a4650+0x12b>
ffffffff8ae6476b:	48 8b 7d 90          	mov    -0x70(%rbp),%rdi
ffffffff8ae6476f:	49 8d 75 04          	lea    0x4(%r13),%rsi
ffffffff8ae64773:	4c 89 e2             	mov    %r12,%rdx
ffffffff8ae64776:	e8 65 54 db ff       	call   ffffffff8ac19be0 <handler_641_body-0x249200>
ffffffff8ae6477b:	f6 c3 04             	test   $0x4,%bl
ffffffff8ae6477e:	0f 84 53 01 00 00    	je     ffffffff8ae648d7 <frame_candidate_4a4650+0x287>
ffffffff8ae64784:	41 0f b7 ce          	movzwl %r14w,%ecx
ffffffff8ae64788:	81 f9 20 c0 00 00    	cmp    $0xc020,%ecx
ffffffff8ae6478e:	7e 21                	jle    ffffffff8ae647b1 <frame_candidate_4a4650+0x161>
ffffffff8ae64790:	81 f9 21 c0 00 00    	cmp    $0xc021,%ecx
ffffffff8ae64796:	74 32                	je     ffffffff8ae647ca <frame_candidate_4a4650+0x17a>
ffffffff8ae64798:	81 f9 23 c0 00 00    	cmp    $0xc023,%ecx
ffffffff8ae6479e:	74 33                	je     ffffffff8ae647d3 <frame_candidate_4a4650+0x183>
ffffffff8ae647a0:	81 f9 23 c2 00 00    	cmp    $0xc223,%ecx
ffffffff8ae647a6:	75 3d                	jne    ffffffff8ae647e5 <frame_candidate_4a4650+0x195>
ffffffff8ae647a8:	4c 8d 35 95 84 e7 00 	lea    0xe78495(%rip),%r14        # ffffffff8bcdcc44 <frame_candidate_4a4a40+0xe78204>
ffffffff8ae647af:	eb 51                	jmp    ffffffff8ae64802 <frame_candidate_4a4650+0x1b2>
ffffffff8ae647b1:	81 f9 21 80 00 00    	cmp    $0x8021,%ecx
ffffffff8ae647b7:	74 23                	je     ffffffff8ae647dc <frame_candidate_4a4650+0x18c>
ffffffff8ae647b9:	81 f9 57 80 00 00    	cmp    $0x8057,%ecx
ffffffff8ae647bf:	75 24                	jne    ffffffff8ae647e5 <frame_candidate_4a4650+0x195>
ffffffff8ae647c1:	4c 8d 35 81 84 e7 00 	lea    0xe78481(%rip),%r14        # ffffffff8bcdcc49 <frame_candidate_4a4a40+0xe78209>
ffffffff8ae647c8:	eb 38                	jmp    ffffffff8ae64802 <frame_candidate_4a4650+0x1b2>
ffffffff8ae647ca:	4c 8d 35 b9 c1 ec 00 	lea    0xecc1b9(%rip),%r14        # ffffffff8bd3098a <frame_candidate_4a4a40+0xecbf4a>
ffffffff8ae647d1:	eb 2f                	jmp    ffffffff8ae64802 <frame_candidate_4a4650+0x1b2>
ffffffff8ae647d3:	4c 8d 35 18 a1 e1 00 	lea    0xe1a118(%rip),%r14        # ffffffff8bc7e8f2 <frame_candidate_4a4a40+0xe19eb2>
ffffffff8ae647da:	eb 26                	jmp    ffffffff8ae64802 <frame_candidate_4a4650+0x1b2>
ffffffff8ae647dc:	4c 8d 35 6d 03 e1 00 	lea    0xe1036d(%rip),%r14        # ffffffff8bc74b50 <frame_candidate_4a4a40+0xe10110>
ffffffff8ae647e3:	eb 1d                	jmp    ffffffff8ae64802 <frame_candidate_4a4650+0x1b2>
ffffffff8ae647e5:	4c 8d 35 e8 1d 09 03 	lea    0x3091de8(%rip),%r14        # ffffffff8def65d4 <frame_candidate_4a4a40+0x3091b94>
ffffffff8ae647ec:	48 8d 15 1d f1 ed 00 	lea    0xedf11d(%rip),%rdx        # ffffffff8bd43910 <frame_candidate_4a4a40+0xedeed0>
ffffffff8ae647f3:	be 0c 00 00 00       	mov    $0xc,%esi
ffffffff8ae647f8:	31 c0                	xor    %eax,%eax
ffffffff8ae647fa:	4c 89 f7             	mov    %r14,%rdi
ffffffff8ae647fd:	e8 3e a6 00 00       	call   ffffffff8ae6ee40 <frame_candidate_4a4a40+0xa400>
ffffffff8ae64802:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
ffffffff8ae64806:	41 0f b6 4d 00       	movzbl 0x0(%r13),%ecx
ffffffff8ae6480b:	48 8d 70 60          	lea    0x60(%rax),%rsi
ffffffff8ae6480f:	8d 41 ff             	lea    -0x1(%rcx),%eax
ffffffff8ae64812:	3c 0b                	cmp    $0xb,%al
ffffffff8ae64814:	73 10                	jae    ffffffff8ae64826 <frame_candidate_4a4650+0x1d6>
ffffffff8ae64816:	0f b6 c0             	movzbl %al,%eax
ffffffff8ae64819:	48 8d 0d 40 b3 9d 00 	lea    0x9db340(%rip),%rcx        # ffffffff8b83fb60 <frame_candidate_4a4a40+0x9db120>
ffffffff8ae64820:	48 8b 1c c1          	mov    (%rcx,%rax,8),%rbx
ffffffff8ae64824:	eb 2b                	jmp    ffffffff8ae64851 <frame_candidate_4a4650+0x201>
ffffffff8ae64826:	48 8d 1d e3 1d 09 03 	lea    0x3091de3(%rip),%rbx        # ffffffff8def6610 <frame_candidate_4a4a40+0x3091bd0>
ffffffff8ae6482d:	4c 89 75 b0          	mov    %r14,-0x50(%rbp)
ffffffff8ae64831:	49 89 f6             	mov    %rsi,%r14
ffffffff8ae64834:	48 8d 15 d5 f0 ed 00 	lea    0xedf0d5(%rip),%rdx        # ffffffff8bd43910 <frame_candidate_4a4a40+0xedeed0>
ffffffff8ae6483b:	be 0c 00 00 00       	mov    $0xc,%esi
ffffffff8ae64840:	31 c0                	xor    %eax,%eax
ffffffff8ae64842:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64845:	e8 f6 a5 00 00       	call   ffffffff8ae6ee40 <frame_candidate_4a4a40+0xa400>
ffffffff8ae6484a:	4c 89 f6             	mov    %r14,%rsi
ffffffff8ae6484d:	4c 8b 75 b0          	mov    -0x50(%rbp),%r14
ffffffff8ae64851:	66 41 0f 38 f0 45 02 	movbe  0x2(%r13),%ax
ffffffff8ae64858:	45 0f b6 45 01       	movzbl 0x1(%r13),%r8d
ffffffff8ae6485d:	48 8d 3d f4 8a e5 00 	lea    0xe58af4(%rip),%rdi        # ffffffff8bcbd358 <frame_candidate_4a4a40+0xe58918>
ffffffff8ae64864:	4c 89 f2             	mov    %r14,%rdx
ffffffff8ae64867:	48 89 d9             	mov    %rbx,%rcx
ffffffff8ae6486a:	44 0f b7 c8          	movzwl %ax,%r9d
ffffffff8ae6486e:	31 c0                	xor    %eax,%eax
ffffffff8ae64870:	e8 9b 8b db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64875:	66 83 7d bc 00       	cmpw   $0x0,-0x44(%rbp)
ffffffff8ae6487a:	74 4d                	je     ffffffff8ae648c9 <frame_candidate_4a4650+0x279>
ffffffff8ae6487c:	41 0f b6 75 04       	movzbl 0x4(%r13),%esi
ffffffff8ae64881:	48 8d 3d b6 a7 f0 00 	lea    0xf0a7b6(%rip),%rdi        # ffffffff8bd6f03e <frame_candidate_4a4a40+0xf0a5fe>
ffffffff8ae64888:	31 c0                	xor    %eax,%eax
ffffffff8ae6488a:	e8 81 8b db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae6488f:	66 41 83 fc 01       	cmp    $0x1,%r12w
ffffffff8ae64894:	74 33                	je     ffffffff8ae648c9 <frame_candidate_4a4650+0x279>
ffffffff8ae64896:	49 ff cc             	dec    %r12
ffffffff8ae64899:	48 8d 1d b0 83 e7 00 	lea    0xe783b0(%rip),%rbx        # ffffffff8bcdcc50 <frame_candidate_4a4a40+0xe78210>
ffffffff8ae648a0:	45 31 f6             	xor    %r14d,%r14d
ffffffff8ae648a3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8ae648aa:	84 00 00 00 00 00 
ffffffff8ae648b0:	43 0f b6 74 35 05    	movzbl 0x5(%r13,%r14,1),%esi
ffffffff8ae648b6:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae648b9:	31 c0                	xor    %eax,%eax
ffffffff8ae648bb:	e8 50 8b db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae648c0:	49 ff c6             	inc    %r14
ffffffff8ae648c3:	66 45 39 f4          	cmp    %r14w,%r12w
ffffffff8ae648c7:	75 e7                	jne    ffffffff8ae648b0 <frame_candidate_4a4650+0x260>
ffffffff8ae648c9:	48 8d 3d ce 79 eb 00 	lea    0xeb79ce(%rip),%rdi        # ffffffff8bd1c29e <frame_candidate_4a4a40+0xeb785e>
ffffffff8ae648d0:	31 c0                	xor    %eax,%eax
ffffffff8ae648d2:	e8 39 8b db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae648d7:	4c 8b 6d a0          	mov    -0x60(%rbp),%r13
ffffffff8ae648db:	41 8b 45 50          	mov    0x50(%r13),%eax
ffffffff8ae648df:	41 3b 45 54          	cmp    0x54(%r13),%eax
ffffffff8ae648e3:	7d 2d                	jge    ffffffff8ae64912 <frame_candidate_4a4650+0x2c2>
ffffffff8ae648e5:	49 8d 5d 70          	lea    0x70(%r13),%rbx
ffffffff8ae648e9:	31 f6                	xor    %esi,%esi
ffffffff8ae648eb:	31 d2                	xor    %edx,%edx
ffffffff8ae648ed:	31 c9                	xor    %ecx,%ecx
ffffffff8ae648ef:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae648f2:	e8 09 21 02 00       	call   ffffffff8ae86a00 <frame_candidate_4a4a40+0x21fc0>
ffffffff8ae648f7:	49 c7 47 08 00 00 00 	movq   $0x0,0x8(%r15)
ffffffff8ae648fe:	00 
ffffffff8ae648ff:	4c 8b 65 a8          	mov    -0x58(%rbp),%r12
ffffffff8ae64903:	49 8b 45 48          	mov    0x48(%r13),%rax
ffffffff8ae64907:	48 85 c0             	test   %rax,%rax
ffffffff8ae6490a:	74 33                	je     ffffffff8ae6493f <frame_candidate_4a4650+0x2ef>
ffffffff8ae6490c:	4c 89 78 08          	mov    %r15,0x8(%rax)
ffffffff8ae64910:	eb 31                	jmp    ffffffff8ae64943 <frame_candidate_4a4650+0x2f3>
ffffffff8ae64912:	48 8b 5d a8          	mov    -0x58(%rbp),%rbx
ffffffff8ae64916:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae6491b:	be 0a 00 00 00       	mov    $0xa,%esi
ffffffff8ae64920:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64923:	e8 d8 75 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae64928:	4c 89 ff             	mov    %r15,%rdi
ffffffff8ae6492b:	e8 20 5f f8 ff       	call   ffffffff8adea850 <handler_641_body-0x78590>
ffffffff8ae64930:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae64935:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64938:	be 03 00 00 00       	mov    $0x3,%esi
ffffffff8ae6493d:	eb 5c                	jmp    ffffffff8ae6499b <frame_candidate_4a4650+0x34b>
ffffffff8ae6493f:	4d 89 7d 40          	mov    %r15,0x40(%r13)
ffffffff8ae64943:	4d 89 7d 48          	mov    %r15,0x48(%r13)
ffffffff8ae64947:	41 ff 45 50          	incl   0x50(%r13)
ffffffff8ae6494b:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae6494e:	31 f6                	xor    %esi,%esi
ffffffff8ae64950:	31 d2                	xor    %edx,%edx
ffffffff8ae64952:	31 c9                	xor    %ecx,%ecx
ffffffff8ae64954:	e8 47 26 02 00       	call   ffffffff8ae86fa0 <frame_candidate_4a4a40+0x22560>
ffffffff8ae64959:	41 f6 44 24 79 04    	testb  $0x4,0x79(%r12)
ffffffff8ae6495f:	75 27                	jne    ffffffff8ae64988 <frame_candidate_4a4650+0x338>
ffffffff8ae64961:	49 8b 9c 24 98 04 00 	mov    0x498(%r12),%rbx
ffffffff8ae64968:	00 
ffffffff8ae64969:	48 8d 05 60 09 dc ff 	lea    -0x23f6a0(%rip),%rax        # ffffffff8ac252d0 <handler_641_body-0x23db10>
ffffffff8ae64970:	48 29 d8             	sub    %rbx,%rax
ffffffff8ae64973:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8ae64977:	48 3d bc 08 00 00    	cmp    $0x8bc,%rax
ffffffff8ae6497d:	0f 87 82 00 00 00    	ja     ffffffff8ae64a05 <frame_candidate_4a4650+0x3b5>
ffffffff8ae64983:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae64986:	ff d3                	call   *%rbx
ffffffff8ae64988:	41 8b 95 84 00 00 00 	mov    0x84(%r13),%edx
ffffffff8ae6498f:	41 03 57 30          	add    0x30(%r15),%edx
ffffffff8ae64993:	4c 89 e7             	mov    %r12,%rdi
ffffffff8ae64996:	be 06 00 00 00       	mov    $0x6,%esi
ffffffff8ae6499b:	e8 60 75 01 00       	call   ffffffff8ae7bf00 <frame_candidate_4a4a40+0x174c0>
ffffffff8ae649a0:	48 8d 05 69 79 47 03 	lea    0x3477969(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae649a7:	48 8b 00             	mov    (%rax),%rax
ffffffff8ae649aa:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8ae649ae:	75 4e                	jne    ffffffff8ae649fe <frame_candidate_4a4650+0x3ae>
ffffffff8ae649b0:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8ae649b4:	5b                   	pop    %rbx
ffffffff8ae649b5:	41 5c                	pop    %r12
ffffffff8ae649b7:	41 5d                	pop    %r13
ffffffff8ae649b9:	41 5e                	pop    %r14
ffffffff8ae649bb:	41 5f                	pop    %r15
ffffffff8ae649bd:	5d                   	pop    %rbp
ffffffff8ae649be:	c3                   	ret
ffffffff8ae649bf:	48 8d 05 62 75 5f 01 	lea    0x15f7562(%rip),%rax        # ffffffff8c45bf28 <frame_candidate_4a4a40+0x15f74e8>
ffffffff8ae649c6:	4c 8b 10             	mov    (%rax),%r10
ffffffff8ae649c9:	48 8d 05 18 38 dc ff 	lea    -0x23c7e8(%rip),%rax        # ffffffff8ac281e8 <handler_641_body-0x23abf8>
ffffffff8ae649d0:	4c 29 d0             	sub    %r10,%rax
ffffffff8ae649d3:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8ae649d7:	48 83 f8 01          	cmp    $0x1,%rax
ffffffff8ae649db:	77 3c                	ja     ffffffff8ae64a19 <frame_candidate_4a4650+0x3c9>
ffffffff8ae649dd:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8ae649e2:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8ae649e7:	4c 89 f9             	mov    %r15,%rcx
ffffffff8ae649ea:	45 31 c0             	xor    %r8d,%r8d
ffffffff8ae649ed:	45 31 c9             	xor    %r9d,%r9d
ffffffff8ae649f0:	41 ff d2             	call   *%r10
ffffffff8ae649f3:	4d 85 ff             	test   %r15,%r15
ffffffff8ae649f6:	0f 85 fd fc ff ff    	jne    ffffffff8ae646f9 <frame_candidate_4a4650+0xa9>
ffffffff8ae649fc:	eb a2                	jmp    ffffffff8ae649a0 <frame_candidate_4a4650+0x350>
ffffffff8ae649fe:	e8 ad 8c 25 00       	call   ffffffff8b0bd6b0 <frame_candidate_4a4a40+0x258c70>
ffffffff8ae64a03:	0f 0b                	ud2
ffffffff8ae64a05:	48 8d 3d 64 3b 62 01 	lea    0x1623b64(%rip),%rdi        # ffffffff8c488570 <frame_candidate_4a4a40+0x1623b30>
ffffffff8ae64a0c:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae64a0f:	e8 ac ae fa ff       	call   ffffffff8ae0f8c0 <handler_641_body-0x53520>
ffffffff8ae64a14:	e9 6a ff ff ff       	jmp    ffffffff8ae64983 <frame_candidate_4a4650+0x333>
ffffffff8ae64a19:	48 8d 3d 30 3a 62 01 	lea    0x1623a30(%rip),%rdi        # ffffffff8c488450 <frame_candidate_4a4a40+0x1623a10>
ffffffff8ae64a20:	4c 89 d6             	mov    %r10,%rsi
ffffffff8ae64a23:	4c 89 55 98          	mov    %r10,-0x68(%rbp)
ffffffff8ae64a27:	e8 94 ae fa ff       	call   ffffffff8ae0f8c0 <handler_641_body-0x53520>
ffffffff8ae64a2c:	4c 8b 55 98          	mov    -0x68(%rbp),%r10
ffffffff8ae64a30:	48 8b 7b 48          	mov    0x48(%rbx),%rdi
ffffffff8ae64a34:	eb a7                	jmp    ffffffff8ae649dd <frame_candidate_4a4650+0x38d>
ffffffff8ae64a36:	90                   	nop
ffffffff8ae64a37:	90                   	nop
ffffffff8ae64a38:	90                   	nop
ffffffff8ae64a39:	90                   	nop
ffffffff8ae64a3a:	90                   	nop
ffffffff8ae64a3b:	90                   	nop
ffffffff8ae64a3c:	90                   	nop
ffffffff8ae64a3d:	90                   	nop
ffffffff8ae64a3e:	90                   	nop
ffffffff8ae64a3f:	90                   	nop

ffffffff8ae64a40 <frame_candidate_4a4a40>:
ffffffff8ae64a40:	55                   	push   %rbp
ffffffff8ae64a41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8ae64a44:	41 57                	push   %r15
ffffffff8ae64a46:	41 56                	push   %r14
ffffffff8ae64a48:	41 55                	push   %r13
ffffffff8ae64a4a:	41 54                	push   %r12
ffffffff8ae64a4c:	53                   	push   %rbx
ffffffff8ae64a4d:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8ae64a51:	4c 8d 3d b8 78 47 03 	lea    0x34778b8(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae64a58:	49 89 fa             	mov    %rdi,%r10
ffffffff8ae64a5b:	49 8b 07             	mov    (%r15),%rax
ffffffff8ae64a5e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8ae64a62:	48 8b 1e             	mov    (%rsi),%rbx
ffffffff8ae64a65:	44 8b 6a 30          	mov    0x30(%rdx),%r13d
ffffffff8ae64a69:	41 83 fd 03          	cmp    $0x3,%r13d
ffffffff8ae64a6d:	7f 37                	jg     ffffffff8ae64aa6 <frame_candidate_4a4a40+0x66>
ffffffff8ae64a6f:	49 8b 52 08          	mov    0x8(%r10),%rdx
ffffffff8ae64a73:	49 8b 07             	mov    (%r15),%rax
ffffffff8ae64a76:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8ae64a7a:	0f 85 a0 11 00 00    	jne    ffffffff8ae65c20 <frame_candidate_4a4a40+0x11e0>
ffffffff8ae64a80:	48 83 c3 60          	add    $0x60,%rbx
ffffffff8ae64a84:	48 8d 3d 40 4b e2 00 	lea    0xe24b40(%rip),%rdi        # ffffffff8bc895cb <frame_candidate_4a4a40+0xe24b8b>
ffffffff8ae64a8b:	44 89 e9             	mov    %r13d,%ecx
ffffffff8ae64a8e:	31 c0                	xor    %eax,%eax
ffffffff8ae64a90:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae64a93:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8ae64a97:	5b                   	pop    %rbx
ffffffff8ae64a98:	41 5c                	pop    %r12
ffffffff8ae64a9a:	41 5d                	pop    %r13
ffffffff8ae64a9c:	41 5e                	pop    %r14
ffffffff8ae64a9e:	41 5f                	pop    %r15
ffffffff8ae64aa0:	5d                   	pop    %rbp
ffffffff8ae64aa1:	e9 6a 89 db ff       	jmp    ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64aa6:	44 8b 5b 78          	mov    0x78(%rbx),%r11d
ffffffff8ae64aaa:	4c 8b 62 10          	mov    0x10(%rdx),%r12
ffffffff8ae64aae:	49 89 f6             	mov    %rsi,%r14
ffffffff8ae64ab1:	41 f6 c3 04          	test   $0x4,%r11b
ffffffff8ae64ab5:	0f 84 36 01 00 00    	je     ffffffff8ae64bf1 <frame_candidate_4a4a40+0x1b1>
ffffffff8ae64abb:	41 0f b6 42 02       	movzbl 0x2(%r10),%eax
ffffffff8ae64ac0:	4c 89 75 a8          	mov    %r14,-0x58(%rbp)
ffffffff8ae64ac4:	41 8b 84 86 2c 01 00 	mov    0x12c(%r14,%rax,4),%eax
ffffffff8ae64acb:	00 
ffffffff8ae64acc:	48 83 f8 09          	cmp    $0x9,%rax
ffffffff8ae64ad0:	77 0d                	ja     ffffffff8ae64adf <frame_candidate_4a4a40+0x9f>
ffffffff8ae64ad2:	48 8d 0d df b0 9d 00 	lea    0x9db0df(%rip),%rcx        # ffffffff8b83fbb8 <frame_candidate_4a4a40+0x9db178>
ffffffff8ae64ad9:	4c 8b 04 c1          	mov    (%rcx,%rax,8),%r8
ffffffff8ae64add:	eb 07                	jmp    ffffffff8ae64ae6 <frame_candidate_4a4a40+0xa6>
ffffffff8ae64adf:	4c 8d 05 9f 59 ef 00 	lea    0xef599f(%rip),%r8        # ffffffff8bd5a485 <frame_candidate_4a4a40+0xef5a45>
ffffffff8ae64ae6:	41 0f b6 0c 24       	movzbl (%r12),%ecx
ffffffff8ae64aeb:	4d 8b 7a 08          	mov    0x8(%r10),%r15
ffffffff8ae64aef:	48 8d 73 60          	lea    0x60(%rbx),%rsi
ffffffff8ae64af3:	48 89 5d c0          	mov    %rbx,-0x40(%rbp)
ffffffff8ae64af7:	48 89 55 98          	mov    %rdx,-0x68(%rbp)
ffffffff8ae64afb:	4c 89 55 b0          	mov    %r10,-0x50(%rbp)
ffffffff8ae64aff:	44 89 5d b8          	mov    %r11d,-0x48(%rbp)
ffffffff8ae64b03:	8d 41 ff             	lea    -0x1(%rcx),%eax
ffffffff8ae64b06:	3c 0b                	cmp    $0xb,%al
ffffffff8ae64b08:	73 10                	jae    ffffffff8ae64b1a <frame_candidate_4a4a40+0xda>
ffffffff8ae64b0a:	0f b6 c0             	movzbl %al,%eax
ffffffff8ae64b0d:	48 8d 0d 4c b0 9d 00 	lea    0x9db04c(%rip),%rcx        # ffffffff8b83fb60 <frame_candidate_4a4a40+0x9db120>
ffffffff8ae64b14:	48 8b 1c c1          	mov    (%rcx,%rax,8),%rbx
ffffffff8ae64b18:	eb 2b                	jmp    ffffffff8ae64b45 <frame_candidate_4a4a40+0x105>
ffffffff8ae64b1a:	48 8d 1d ef 1a 09 03 	lea    0x3091aef(%rip),%rbx        # ffffffff8def6610 <frame_candidate_4a4a40+0x3091bd0>
ffffffff8ae64b21:	48 89 75 a0          	mov    %rsi,-0x60(%rbp)
ffffffff8ae64b25:	48 8d 15 e4 ed ed 00 	lea    0xedede4(%rip),%rdx        # ffffffff8bd43910 <frame_candidate_4a4a40+0xedeed0>
ffffffff8ae64b2c:	be 0c 00 00 00       	mov    $0xc,%esi
ffffffff8ae64b31:	31 c0                	xor    %eax,%eax
ffffffff8ae64b33:	4d 89 c6             	mov    %r8,%r14
ffffffff8ae64b36:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64b39:	e8 02 a3 00 00       	call   ffffffff8ae6ee40 <frame_candidate_4a4a40+0xa400>
ffffffff8ae64b3e:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
ffffffff8ae64b42:	4d 89 f0             	mov    %r14,%r8
ffffffff8ae64b45:	66 41 0f 38 f0 44 24 	movbe  0x2(%r12),%ax
ffffffff8ae64b4c:	02 
ffffffff8ae64b4d:	45 0f b6 4c 24 01    	movzbl 0x1(%r12),%r9d
ffffffff8ae64b53:	44 0f b7 d0          	movzwl %ax,%r10d
ffffffff8ae64b57:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8ae64b5b:	4c 89 c1             	mov    %r8,%rcx
ffffffff8ae64b5e:	48 8d 3d a3 ba df 00 	lea    0xdfbaa3(%rip),%rdi        # ffffffff8bc60608 <frame_candidate_4a4a40+0xdfbbc8>
ffffffff8ae64b65:	4c 89 fa             	mov    %r15,%rdx
ffffffff8ae64b68:	49 89 d8             	mov    %rbx,%r8
ffffffff8ae64b6b:	31 c0                	xor    %eax,%eax
ffffffff8ae64b6d:	41 52                	push   %r10
ffffffff8ae64b6f:	e8 9c 88 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64b74:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8ae64b78:	41 83 fd 04          	cmp    $0x4,%r13d
ffffffff8ae64b7c:	74 4a                	je     ffffffff8ae64bc8 <frame_candidate_4a4a40+0x188>
ffffffff8ae64b7e:	41 0f b6 74 24 04    	movzbl 0x4(%r12),%esi
ffffffff8ae64b84:	48 8d 3d b3 a4 f0 00 	lea    0xf0a4b3(%rip),%rdi        # ffffffff8bd6f03e <frame_candidate_4a4a40+0xf0a5fe>
ffffffff8ae64b8b:	31 c0                	xor    %eax,%eax
ffffffff8ae64b8d:	e8 7e 88 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64b92:	66 41 83 fd 05       	cmp    $0x5,%r13w
ffffffff8ae64b97:	74 2f                	je     ffffffff8ae64bc8 <frame_candidate_4a4a40+0x188>
ffffffff8ae64b99:	41 be 05 00 00 00    	mov    $0x5,%r14d
ffffffff8ae64b9f:	48 8d 1d aa 80 e7 00 	lea    0xe780aa(%rip),%rbx        # ffffffff8bcdcc50 <frame_candidate_4a4a40+0xe78210>
ffffffff8ae64ba6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8ae64bad:	00 00 00 
ffffffff8ae64bb0:	43 0f b6 34 34       	movzbl (%r12,%r14,1),%esi
ffffffff8ae64bb5:	48 89 df             	mov    %rbx,%rdi
ffffffff8ae64bb8:	31 c0                	xor    %eax,%eax
ffffffff8ae64bba:	e8 51 88 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64bbf:	49 ff c6             	inc    %r14
ffffffff8ae64bc2:	66 45 39 f5          	cmp    %r14w,%r13w
ffffffff8ae64bc6:	75 e8                	jne    ffffffff8ae64bb0 <frame_candidate_4a4a40+0x170>
ffffffff8ae64bc8:	48 8d 3d cf 76 eb 00 	lea    0xeb76cf(%rip),%rdi        # ffffffff8bd1c29e <frame_candidate_4a4a40+0xeb785e>
ffffffff8ae64bcf:	31 c0                	xor    %eax,%eax
ffffffff8ae64bd1:	e8 3a 88 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64bd6:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
ffffffff8ae64bda:	4c 8d 3d 2f 77 47 03 	lea    0x347772f(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_4a4a40+0x34778d0>
ffffffff8ae64be1:	4c 8b 75 a8          	mov    -0x58(%rbp),%r14
ffffffff8ae64be5:	48 8b 5d c0          	mov    -0x40(%rbp),%rbx
ffffffff8ae64be9:	4c 8b 55 b0          	mov    -0x50(%rbp),%r10
ffffffff8ae64bed:	44 8b 5d b8          	mov    -0x48(%rbp),%r11d
ffffffff8ae64bf1:	66 41 0f 38 f0 4c 24 	movbe  0x2(%r12),%cx
ffffffff8ae64bf8:	02 
ffffffff8ae64bf9:	48 89 d0             	mov    %rdx,%rax
ffffffff8ae64bfc:	0f b7 d1             	movzwl %cx,%edx
ffffffff8ae64bff:	41 0f b6 0c 24       	movzbl (%r12),%ecx
ffffffff8ae64c04:	41 39 d5             	cmp    %edx,%r13d
ffffffff8ae64c07:	41 0f 42 d5          	cmovb  %r13d,%edx
ffffffff8ae64c0b:	8d 71 ff             	lea    -0x1(%rcx),%esi
ffffffff8ae64c0e:	83 fe 0a             	cmp    $0xa,%esi
ffffffff8ae64c11:	0f 87 3a 03 00 00    	ja     ffffffff8ae64f51 <frame_candidate_4a4a40+0x511>
ffffffff8ae64c17:	48 8d 3d 12 f4 0e 01 	lea    0x10ef412(%rip),%rdi        # ffffffff8bf54030 <frame_candidate_4a4a40+0x10ef5f0>
ffffffff8ae64c1e:	4d 8d 6c 24 04       	lea    0x4(%r12),%r13
ffffffff8ae64c23:	48 63 34 b7          	movslq (%rdi,%rsi,4),%rsi
ffffffff8ae64c27:	48 01 fe             	add    %rdi,%rsi
ffffffff8ae64c2a:	ff e6                	jmp    *%rsi
ffffffff8ae64c2c:	41 0f b6 72 02       	movzbl 0x2(%r10),%esi
ffffffff8ae64c31:	41 0f b6 44 24 01    	movzbl 0x1(%r12),%eax
ffffffff8ae64c37:	45 0f b6 84 36 40 01 	movzbl 0x140(%r14,%rsi,1),%r8d
ffffffff8ae64c3e:	00 00 
ffffffff8ae64c40:	44 38 c0             	cmp    %r8b,%al
ffffffff8ae64c43:	0f 85 53 01 00 00    	jne    ffffffff8ae64d9c <frame_candidate_4a4a40+0x35c>
ffffffff8ae64c49:	48 89 5d c0          	mov    %rbx,-0x40(%rbp)
ffffffff8ae64c4d:	83 f9 03             	cmp    $0x3,%ecx
ffffffff8ae64c50:	0f 85 70 03 00 00    	jne    ffffffff8ae64fc6 <frame_candidate_4a4a40+0x586>
ffffffff8ae64c56:	49 8b 5a 48          	mov    0x48(%r10),%rbx
ffffffff8ae64c5a:	48 8d 05 77 35 dc ff 	lea    -0x23ca89(%rip),%rax        # ffffffff8ac281d8 <handler_641_body-0x23ac08>
ffffffff8ae64c61:	4d 89 d5             	mov    %r10,%r13
ffffffff8ae64c64:	48 29 d8             	sub    %rbx,%rax
ffffffff8ae64c67:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8ae64c6b:	48 83 f8 13          	cmp    $0x13,%rax
ffffffff8ae64c6f:	0f 86 70 03 00 00    	jbe    ffffffff8ae64fe5 <frame_candidate_4a4a40+0x5a5>
ffffffff8ae64c75:	48 8d 3d 14 3a 62 01 	lea    0x1623a14(%rip),%rdi        # ffffffff8c488690 <frame_candidate_4a4a40+0x1623c50>
ffffffff8ae64c7c:	48 89 de             	mov    %rbx,%rsi
ffffffff8ae64c7f:	4c 89 75 a8          	mov    %r14,-0x58(%rbp)
ffffffff8ae64c83:	41 89 d6             	mov    %edx,%r14d
ffffffff8ae64c86:	e8 35 ac fa ff       	call   ffffffff8ae0f8c0 <handler_641_body-0x53520>
ffffffff8ae64c8b:	e9 ad 0f 00 00       	jmp    ffffffff8ae65c3d <frame_candidate_4a4a40+0x11fd>
ffffffff8ae64c90:	41 0f b7 0a          	movzwl (%r10),%ecx
ffffffff8ae64c94:	81 f9 20 c0 00 00    	cmp    $0xc020,%ecx
ffffffff8ae64c9a:	0f 8e 31 04 00 00    	jle    ffffffff8ae650d1 <frame_candidate_4a4a40+0x691>
ffffffff8ae64ca0:	81 f9 21 c0 00 00    	cmp    $0xc021,%ecx
ffffffff8ae64ca6:	0f 84 81 04 00 00    	je     ffffffff8ae6512d <frame_candidate_4a4a40+0x6ed>
ffffffff8ae64cac:	81 f9 23 c0 00 00    	cmp    $0xc023,%ecx
ffffffff8ae64cb2:	0f 84 7e 04 00 00    	je     ffffffff8ae65136 <frame_candidate_4a4a40+0x6f6>
ffffffff8ae64cb8:	81 f9 23 c2 00 00    	cmp    $0xc223,%ecx
ffffffff8ae64cbe:	0f 85 84 04 00 00    	jne    ffffffff8ae65148 <frame_candidate_4a4a40+0x708>
ffffffff8ae64cc4:	48 8d 0d 79 7f e7 00 	lea    0xe77f79(%rip),%rcx        # ffffffff8bcdcc44 <frame_candidate_4a4a40+0xe78204>
ffffffff8ae64ccb:	e9 ad 04 00 00       	jmp    ffffffff8ae6517d <frame_candidate_4a4a40+0x73d>
ffffffff8ae64cd0:	66 41 81 3a 21 c0    	cmpw   $0xc021,(%r10)
ffffffff8ae64cd6:	0f 85 75 02 00 00    	jne    ffffffff8ae64f51 <frame_candidate_4a4a40+0x511>
ffffffff8ae64cdc:	41 0f b6 44 24 01    	movzbl 0x1(%r12),%eax
ffffffff8ae64ce2:	41 3a 86 38 03 00 00 	cmp    0x338(%r14),%al
ffffffff8ae64ce9:	0f 85 b5 03 00 00    	jne    ffffffff8ae650a4 <frame_candidate_4a4a40+0x664>
ffffffff8ae64cef:	83 fa 07             	cmp    $0x7,%edx
ffffffff8ae64cf2:	0f 87 b0 05 00 00    	ja     ffffffff8ae652a8 <frame_candidate_4a4a40+0x868>
ffffffff8ae64cf8:	41 f6 c3 04          	test   $0x4,%r11b
ffffffff8ae64cfc:	0f 84 63 0b 00 00    	je     ffffffff8ae65865 <frame_candidate_4a4a40+0xe25>
ffffffff8ae64d02:	49 8b 07             	mov    (%r15),%rax
ffffffff8ae64d05:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8ae64d09:	0f 85 11 0f 00 00    	jne    ffffffff8ae65c20 <frame_candidate_4a4a40+0x11e0>
ffffffff8ae64d0f:	48 83 c3 60          	add    $0x60,%rbx
ffffffff8ae64d13:	48 8d 3d ad 57 ef 00 	lea    0xef57ad(%rip),%rdi        # ffffffff8bd5a4c7 <frame_candidate_4a4a40+0xef5a87>
ffffffff8ae64d1a:	e9 1a 02 00 00       	jmp    ffffffff8ae64f39 <frame_candidate_4a4a40+0x4f9>
ffffffff8ae64d1f:	83 fa 03             	cmp    $0x3,%edx
ffffffff8ae64d22:	0f 87 35 03 00 00    	ja     ffffffff8ae6505d <frame_candidate_4a4a40+0x61d>
ffffffff8ae64d28:	41 f6 c3 04          	test   $0x4,%r11b
ffffffff8ae64d2c:	0f 84 72 03 00 00    	je     ffffffff8ae650a4 <frame_candidate_4a4a40+0x664>
ffffffff8ae64d32:	49 8b 42 08          	mov    0x8(%r10),%rax
ffffffff8ae64d36:	89 d1                	mov    %edx,%ecx
ffffffff8ae64d38:	48 8d 73 60          	lea    0x60(%rbx),%rsi
ffffffff8ae64d3c:	48 8d 3d 16 6a de 00 	lea    0xde6a16(%rip),%rdi        # ffffffff8bc4b759 <frame_candidate_4a4a40+0xde6d19>
ffffffff8ae64d43:	48 89 c2             	mov    %rax,%rdx
ffffffff8ae64d46:	31 c0                	xor    %eax,%eax
ffffffff8ae64d48:	e8 c3 86 db ff       	call   ffffffff8ac1d410 <handler_641_body-0x2459d0>
ffffffff8ae64d4d:	e9 52 03 00 00       	jmp    ffffffff8ae650a4 <frame_candidate_4a4a40+0x664>
ffffffff8ae64d52:	41 0f b6 42 02       	movzbl 0x2(%r10),%eax
ffffffff8ae64d57:	41 0f b6 4c 24 01    	movzbl 0x1(%r12),%ecx
ffffffff8ae64d5d:	45 0f b6 84 06 40 01 	movzbl 0x140(%r14,%rax,1),%r8d
ffffffff8ae64d64:	00 00 
ffffffff8ae64d66:	44 38 c1             	cmp    %r8b,%cl
ffffffff8ae64d69:	0f 85 19 03 00 00    	jne    ffffffff8ae65088 <frame_candidate_4a4a40+0x648>
ffffffff8ae64d6f:	41 8b bc 86 2c 01 00 	mov    0x12c(%r14,%rax,4),%edi
ffffffff8ae64d76:	00 
ffffffff8ae64d77:	8d 57 fe             	lea    -0x2(%rdi),%edx
ffffffff8ae64d7a:	83 fa 07             	cmp    $0x7,%edx
ffffffff8ae64d7d:	0f 87 aa 0c 00 00    	ja     ffffffff8ae65a2d <frame_candidate_4a4a40+0xfed>
ffffffff8ae64d83:	48 8d 35 12 f3 0e 01 	lea    0x10ef312(%rip),%rsi        # ffffffff8bf5409c <frame_candidate_4a4a40+0x10ef65c>
ffffffff8ae64d8a:	48 63 14 96          	movslq (%rsi,%rdx,4),%rdx
ffffffff8ae64d8e:	48 01 f2             	add    %rsi,%rdx
ffffffff8ae64d91:	ff e2                	jmp    *%rdx
ffffffff8ae64d93:	41 0f b7 32          	movzwl (%r10),%esi
ffffffff8ae64d97:	e9 de 04 00 00       	jmp    ffffffff8ae6527a <frame_candidate_4a4a40+0x83a>
ffffffff8ae64d9c:	41 f6 c3 04          	test   $0x4,%r11b
ffffffff8ae64da0:	0f 84 fe 02 00 00    	je     ffffffff8ae650a4 <frame_candidate_4a4a40+0x664>
ffffffff8ae64da6:	49 8b 52 08          	mov    0x8(%r10),%rdx
ffffffff8ae64daa:	48 8d 73 60          	lea    0x60(%rbx),%rsi
ffffffff8ae64dae:	48 8d 3d f3 54 e0 00 	lea    0xe054f3(%rip),%rdi        # ffffffff8bc6a2a8 <frame_candidate_4a4a40+0xe05868>
ffffffff8ae64db5:	89 c1                	mov    %eax,%ecx
ffffffff8ae64db7:	e9 e1 02 00 00       	jmp    ffffffff8ae6509d <frame_candidate_4a4a40+0x65d>
ffffffff8ae64dbc:	83 fa 06             	cmp    $0x6,%edx
ffffffff8ae64dbf:	0f 82 a0 0a 00 00    	jb     ffffffff8ae65865 <frame_candidate_4a4a40+0xe25>
ffffffff8ae64dc5:	66 41 0f 38 f0 44 24 	movbe  0x4(%r12),%ax
ffffffff8ae64dcc:	04 
ffffffff8ae64dcd:	48 89 5d c0          	mov    %rbx,-0x40(%rbp)
ffffffff8ae64dd1:	44 0f b7 c8          	movzwl %ax,%r9d
ffffffff8ae64dd5:	41 81 f9 20 c0 00 00 	cmp    $0xc020,%r9d
ffffffff8ae64ddc:	0f                   	.byte 0xf
ffffffff8ae64ddd:	8e                   	.byte 0x8e
ffffffff8ae64dde:	25                   	.byte 0x25
ffffffff8ae64ddf:	03                   	.byte 0x3
