; REA 6.7.0 full disassembly of handler_640.bin
; SHA256 ebb8f337e391fd63a3b51a79c8f3c3ada0de752a6febe666a9b1d1079243982c; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25f20, kernel RVA 0x265f20.
; REA inspect_with_objdump Evidence: ev_14a38ead7e38a51193ffbbd1dd26b65fafb24e7871d5a4df3a750bab2900bf35
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 640; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_640.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25f20 <handler_640_entry>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266f18+0x829ef8>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266f18+0x23bec8>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266f18+0x856bb8>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266f18+0x7d0748>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266f18+0x8572a8>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266f18+0x857898>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266f18+0x7912d8>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266f18+0x9825f8>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266f18+0x740df8>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266f18+0x742648>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266f18+0x742ef8>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266f18+0x743028>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266f18+0x694528>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266f18+0x23c288>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266f18+0x857998>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266f18+0x7442d8>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266f18+0x854a68>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266f18+0x4923c8>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266f18+0x1cde88>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266f18+0x1cde98>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266f18+0x1cdea8>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266f18+0x1d0e78>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266f18+0x1d1368>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266f18+0x87f778>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266f18+0x87f668>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266f18+0x1e21b8>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_640_entry-0x1bf160>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266f18+0x1e3b58>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266f18+0x74f1f8>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_640_entry-0x1be8b0>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_640_entry-0x1be6d0>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_640_entry-0x1be6a0>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266f18+0x1eb128>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266f18+0x1edda8>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266f18+0x1f0908>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266f18+0x207058>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266f18+0x207168>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266f18+0x20ba78>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266f18+0x20c498>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266f18+0x20c998>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266f18+0x20d338>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266f18+0x20de98>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266f18+0x2160d8>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_640_entry-0x47f30>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266f18+0x2293e8>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266f18+0x229e98>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266f18+0x231098>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266f18+0x2310c8>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266f18+0x231718>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266f18+0x231728>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266f18+0x690ca8>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266f18+0x68f8e8>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266f18+0x690508>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266f18+0x693068>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266f18+0x378438>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266f18+0x378908>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266f18+0x7cddc8>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266f18+0x381588>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266f18+0x6912d8>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266f18+0x6924f8>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266f18+0x6954d8>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266f18+0x68fd78>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266f18+0xa4aaf8>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266f18+0x851488>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266f18+0x851498>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266f18+0x6932a8>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266f18+0x690c28>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266f18+0x239a48>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266f18+0x4c2868>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266f18+0x4c2878>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266f18+0x4c2888>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266f18+0x454678>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266f18+0x851e88>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266f18+0x693258>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266f18+0x9181a8>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266f18+0x9181e8>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266f18+0x692dd8>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266f18+0x693828>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266f18+0x2ebc58>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266f18+0x2ebcd8>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266f18+0x2ebd38>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266f18+0x2ebd68>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266f18+0x2ebd98>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266f18+0x2ebdc8>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266f18+0x9178e8>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266f18+0x917cc8>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266f18+0x918058>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266f18+0x99fe18>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266f18+0x52b778>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266f18+0x381c08>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266f18+0x2ebdf8>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266f18+0x918248>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266f18+0x377338>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266f18+0x7edb18>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266f18+0x7edb28>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266f18+0x7edb38>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266f18+0x7edb48>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266f18+0x7edb68>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266f18+0x7edb78>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266f18+0x692808>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266f18+0x7edb98>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266f18+0x68f5c8>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266f18+0x68efd8>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266f18+0x7edb08>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266f18+0x7edb58>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266f18+0x7edb88>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266f18+0x47e5b8>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266f18+0x918598>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266f18+0x5d6748>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266f18+0x5d68a8>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266f18+0x5d6b98>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266f18+0x5d6f68>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266f18+0x692d68>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266f18+0x6931f8>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266f18+0x692298>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266f18+0x6935d8>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266f18+0x691178>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266f18+0x694c68>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266f18+0x690c68>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266f18+0x690978>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266f18+0x694988>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266f18+0x6915f8>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266f18+0x6918e8>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266f18+0x234168>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266f18+0x234178>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266f18+0x2f8b38>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266f18+0x9cd958>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266f18+0x575dd8>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266f18+0x575de8>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266f18+0x575df8>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266f18+0x575e08>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266f18+0x575e18>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266f18+0x33fd78>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266f18+0x3403e8>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266f18+0x3406f8>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266f18+0x3409e8>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266f18+0xa35918>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266f18+0x340fe8>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266f18+0x341158>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266f18+0x981568>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266f18+0x234188>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266f18+0x2341a8>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266f18+0x2341b8>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266f18+0x2341c8>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266f18+0x2341d8>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266f18+0x2c9808>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266f18+0x2ca758>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266f18+0x6927d8>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266f18+0x2ca318>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266f18+0x59bed8>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266f18+0x918228>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266f18+0x87c6c8>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266f18+0x287f08>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266f18+0x693bf8>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266f18+0x693f18>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266f18+0x762308>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266f18+0x7621e8>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266f18+0x3db3f8>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266f18+0x3db908>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266f18+0x3dc7c8>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266f18+0x3dc9b8>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266f18+0x3dcd48>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266f18+0x791378>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266f18+0x794c58>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266f18+0x7de368>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266f18+0xa20d88>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266f18+0x7980e8>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266f18+0x799868>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266f18+0x7998c8>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266f18+0x857918>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266f18+0x796018>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266f18+0x38a0a8>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266f18+0x6904d8>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266f18+0x290338>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266f18+0x796bb8>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266f18+0x796e98>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266f18+0x796ff8>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266f18+0x3dd5b8>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266f18+0x3ea0b8>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266f18+0x797b18>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266f18+0x290a28>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266f18+0x851bc8>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266f18+0x854748>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266f18+0x797348>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266f18+0x7975c8>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266f18+0x797718>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266f18+0x531418>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266f18+0x8560e8>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_640_entry-0x169690>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266f18+0x238178>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266f18+0x2382e8>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266f18+0x259678>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266f18+0x259698>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_640_entry-0x1bcaf0>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266f18+0x263438>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266f18+0x263b28>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_640_entry-0x1bba10>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266f18+0x26e2b8>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266f18+0x5aa298>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_640_entry-0x24b090>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266f18+0x289118>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266f18+0x294cb8>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266f18+0x2a5fb8>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266f18+0x2a5fc8>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266f18+0x2a6018>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266f18+0x2a6058>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266f18+0x2a6098>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266f18+0x2a60c8>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266f18+0x2b75b8>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266f18+0x2b8048>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266f18+0x2b80e8>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266f18+0x2b8198>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266f18+0x2b83c8>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266f18+0x2b8758>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266f18+0x2b8fc8>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266f18+0x2cf4e8>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266f18+0x2ddd88>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266f18+0x2df9d8>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_640_entry-0x1b48f0>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_640_entry-0x1b3f70>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266f18+0x2f5028>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266f18+0x2f5118>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266f18+0x2f5138>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266f18+0x3072e8>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266f18+0x318588>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266f18+0x72d6c8>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266f18+0x31ea38>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266f18+0x332908>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266f18+0x3334c8>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266f18+0x333618>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266f18+0x3337e8>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266f18+0x3338b8>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266f18+0x333b38>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266f18+0x333c48>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266f18+0x333d48>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266f18+0x374fb8>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266f18+0x384808>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266f18+0x385118>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266f18+0x385bb8>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266f18+0x386528>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266f18+0x386c18>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_640_entry-0x117ca0>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266f18+0x38a998>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266f18+0x38bc18>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266f18+0x3961a8>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266f18+0x399768>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266f18+0x39a028>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266f18+0x87f588>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266f18+0x3c6b88>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266f18+0x3c93b8>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266f18+0x3cdff8>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266f18+0x3d8608>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266f18+0x3f0a98>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266f18+0xa403f8>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266f18+0x3fbf58>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266f18+0x3fbf68>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266f18+0x411ef8>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266f18+0x411f48>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266f18+0x411fa8>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266f18+0x412048>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266f18+0x412278>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266f18+0x412448>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266f18+0x412768>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_640_entry-0x232390>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_640_entry-0x232280>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_640_entry-0x232200>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_640_entry-0x228fb0>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_640_entry-0x228e40>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_640_entry-0x2288c0>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_640_entry-0x227e20>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_640_entry-0x227dc0>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_640_entry-0x227d60>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_640_entry-0x226eb0>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_640_entry-0x226e50>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_640_entry-0x226a70>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_640_entry-0x226a10>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_640_entry-0x2269b0>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_640_entry-0x226370>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_640_entry-0x225f60>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_640_entry-0x2255c0>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_640_entry-0x2253d0>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_640_entry-0x2252f0>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_640_entry-0x2248f0>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_640_entry-0x2247d0>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_640_entry-0x2246f0>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_640_entry-0x224660>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_640_entry-0x223ec0>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_640_entry-0x223a50>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_640_entry-0x223980>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_640_entry-0x223920>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266f18+0x429118>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266f18+0x42fda8>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266f18+0x4316b8>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266f18+0x43b138>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266f18+0x43b398>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266f18+0x447728>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266f18+0x4478d8>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_640_entry-0xe4b70>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266f18+0x458088>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_640_entry-0xddee0>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266f18+0x469be8>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266f18+0x46a1e8>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266f18+0x46a348>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266f18+0x46a4c8>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266f18+0x46a608>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266f18+0x46a728>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266f18+0x46a808>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266f18+0x475748>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266f18+0x475778>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266f18+0x475788>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266f18+0x479a08>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266f18+0x47a528>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266f18+0x47a538>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_640_entry-0xdc4b0>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_640_entry-0xd5480>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266f18+0x49ba58>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266f18+0x49be48>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266f18+0x49f258>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266f18+0x49f2d8>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266f18+0x4a8fe8>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266f18+0x4a9098>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266f18+0x4a92a8>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266f18+0x4a9408>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266f18+0x4abc98>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266f18+0x4af448>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266f18+0x4c8a58>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266f18+0x4c8a78>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266f18+0x4c8b08>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_640_entry-0x1f0f0>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266f18+0x4fd8d8>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266f18+0x50c7f8>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266f18+0x50ea38>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266f18+0x532f78>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266f18+0x54c2d8>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266f18+0x57b488>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266f18+0x5814c8>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266f18+0x581568>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266f18+0x9d4298>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266f18+0x9d57c8>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266f18+0x9d5778>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266f18+0x9d5818>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266f18+0x59b308>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266f18+0x59b5d8>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266f18+0x5a5658>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266f18+0x5c43e8>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266f18+0x6b9fc8>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266f18+0x6b9c78>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266f18+0x5c98f8>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266f18+0x5c9fe8>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266f18+0x5ce398>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266f18+0x5ce3a8>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266f18+0x5ce3b8>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266f18+0x5ce3d8>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266f18+0x5ce528>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266f18+0x5ce538>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266f18+0x5ce578>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266f18+0x5cebb8>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266f18+0x5e9958>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266f18+0x6093d8>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266f18+0x6096b8>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266f18+0x60bbd8>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266f18+0x60c8e8>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_640_entry-0x2024e0>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_640_entry-0x1ffbb0>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_640_entry-0x17f990>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_640_entry-0x17f980>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_640_entry-0x17f7c0>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_640_entry-0x17f6b0>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_640_entry-0x17df90>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_640_entry-0x17bf80>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_640_entry-0x17b8b0>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_640_entry-0x17b7c0>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_640_entry-0x17ae80>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_640_entry-0x17ad90>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_640_entry-0x178f20>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_640_entry-0x178e10>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266f18+0x623988>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266f18+0x635ed8>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_640_entry-0x1773d0>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266f18+0x664338>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266f18+0x664478>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266f18+0x66c048>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266f18+0x66c078>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266f18+0x671318>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266f18+0x671ec8>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266f18+0x672898>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266f18+0x6729f8>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266f18+0x6735a8>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266f18+0x673658>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266f18+0x673698>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266f18+0x69dd68>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266f18+0x69df48>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266f18+0x6b64e8>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266f18+0x6b6588>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266f18+0x81b2b8>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266f18+0x8db208>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266f18+0x6fe018>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266f18+0x70f038>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266f18+0x70f2e8>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266f18+0x725a38>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266f18+0x725d18>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266f18+0x726018>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266f18+0x7267c8>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266f18+0x7276b8>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266f18+0x7277e8>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266f18+0x72b258>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266f18+0x72b328>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_640_entry-0x170b20>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266f18+0x73b408>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266f18+0x73e808>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266f18+0x745a88>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266f18+0x745b08>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_640_entry-0xa78e0>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266f18+0x757e08>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266f18+0x75f138>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266f18+0x75f1b8>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266f18+0x75f368>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266f18+0x75f3f8>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266f18+0x75f578>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266f18+0x75f698>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266f18+0x75f978>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266f18+0x762428>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266f18+0x762448>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266f18+0x762458>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266f18+0x762468>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266f18+0x773e98>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266f18+0x774088>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266f18+0x775948>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266f18+0x775d28>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266f18+0x775f68>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266f18+0x7765e8>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266f18+0xa43db8>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266f18+0x7768b8>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266f18+0x776a78>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266f18+0x776c88>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266f18+0x776ce8>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266f18+0x776f38>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266f18+0x776f98>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266f18+0x7770d8>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266f18+0x777158>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266f18+0x7771d8>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266f18+0x779c78>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266f18+0x779db8>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266f18+0x779e58>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266f18+0x779fd8>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266f18+0x77a138>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266f18+0x77a578>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266f18+0x79f6c8>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_640_entry-0x164be0>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266f18+0x7cc018>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266f18+0x7cc7a8>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266f18+0x7d1d78>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266f18+0x803be8>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266f18+0x803c98>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266f18+0x827cf8>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266f18+0x827ee8>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266f18+0x84a898>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266f18+0x859898>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266f18+0x85bbd8>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_640_entry-0x14b7d0>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266f18+0x87a388>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266f18+0x87c4e8>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266f18+0x87c618>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266f18+0x87f4a8>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266f18+0x8a0fc8>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266f18+0x8a1278>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266f18+0x8a1618>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266f18+0x8a18f8>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266f18+0x8a2788>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266f18+0x8a45d8>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_640_entry-0x76e30>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_640_entry-0x75ec0>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_640_entry-0x14a570>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266f18+0x8d4218>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266f18+0x8e0b28>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266f18+0x8e94a8>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266f18+0x8e9ff8>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266f18+0x8ea098>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266f18+0x8ea198>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266f18+0x8ea278>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266f18+0x8ea378>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266f18+0x8ea3b8>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266f18+0x8ea408>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266f18+0x8ef988>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_640_entry-0x1cbe40>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266f18+0x903f58>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266f18+0x904c78>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266f18+0x906a68>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266f18+0x906b88>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266f18+0x907268>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266f18+0x90a408>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266f18+0x90a458>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266f18+0x90a4a8>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266f18+0x90a4f8>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266f18+0x90aa48>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266f18+0x90aab8>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266f18+0x90ab28>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266f18+0x90ab98>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266f18+0x90b708>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

ffffffff8ac26eb8 <neighbor_trampoline_266eb8>:
ffffffff8ac26eb8:	e9 a3 b9 90 00       	jmp    ffffffff8b532860 <neighbor_trampoline_266f18+0x90b948>
ffffffff8ac26ebd:	cc                   	int3
ffffffff8ac26ebe:	cc                   	int3
ffffffff8ac26ebf:	cc                   	int3

ffffffff8ac26ec0 <neighbor_trampoline_266ec0>:
ffffffff8ac26ec0:	e9 0b 23 91 00       	jmp    ffffffff8b5391d0 <neighbor_trampoline_266f18+0x9122b8>
ffffffff8ac26ec5:	cc                   	int3
ffffffff8ac26ec6:	cc                   	int3
ffffffff8ac26ec7:	cc                   	int3

ffffffff8ac26ec8 <neighbor_trampoline_266ec8>:
ffffffff8ac26ec8:	e9 c3 23 91 00       	jmp    ffffffff8b539290 <neighbor_trampoline_266f18+0x912378>
ffffffff8ac26ecd:	cc                   	int3
ffffffff8ac26ece:	cc                   	int3
ffffffff8ac26ecf:	cc                   	int3

ffffffff8ac26ed0 <neighbor_trampoline_266ed0>:
ffffffff8ac26ed0:	e9 1b 25 91 00       	jmp    ffffffff8b5393f0 <neighbor_trampoline_266f18+0x9124d8>
ffffffff8ac26ed5:	cc                   	int3
ffffffff8ac26ed6:	cc                   	int3
ffffffff8ac26ed7:	cc                   	int3

ffffffff8ac26ed8 <neighbor_trampoline_266ed8>:
ffffffff8ac26ed8:	e9 43 25 91 00       	jmp    ffffffff8b539420 <neighbor_trampoline_266f18+0x912508>
ffffffff8ac26edd:	cc                   	int3
ffffffff8ac26ede:	cc                   	int3
ffffffff8ac26edf:	cc                   	int3

ffffffff8ac26ee0 <neighbor_trampoline_266ee0>:
ffffffff8ac26ee0:	e9 7b 25 91 00       	jmp    ffffffff8b539460 <neighbor_trampoline_266f18+0x912548>
ffffffff8ac26ee5:	cc                   	int3
ffffffff8ac26ee6:	cc                   	int3
ffffffff8ac26ee7:	cc                   	int3

ffffffff8ac26ee8 <neighbor_trampoline_266ee8>:
ffffffff8ac26ee8:	e9 93 25 91 00       	jmp    ffffffff8b539480 <neighbor_trampoline_266f18+0x912568>
ffffffff8ac26eed:	cc                   	int3
ffffffff8ac26eee:	cc                   	int3
ffffffff8ac26eef:	cc                   	int3

ffffffff8ac26ef0 <neighbor_trampoline_266ef0>:
ffffffff8ac26ef0:	e9 9b 25 91 00       	jmp    ffffffff8b539490 <neighbor_trampoline_266f18+0x912578>
ffffffff8ac26ef5:	cc                   	int3
ffffffff8ac26ef6:	cc                   	int3
ffffffff8ac26ef7:	cc                   	int3

ffffffff8ac26ef8 <neighbor_trampoline_266ef8>:
ffffffff8ac26ef8:	e9 b3 25 91 00       	jmp    ffffffff8b5394b0 <neighbor_trampoline_266f18+0x912598>
ffffffff8ac26efd:	cc                   	int3
ffffffff8ac26efe:	cc                   	int3
ffffffff8ac26eff:	cc                   	int3

ffffffff8ac26f00 <neighbor_trampoline_266f00>:
ffffffff8ac26f00:	e9 eb 26 91 00       	jmp    ffffffff8b5395f0 <neighbor_trampoline_266f18+0x9126d8>
ffffffff8ac26f05:	cc                   	int3
ffffffff8ac26f06:	cc                   	int3
ffffffff8ac26f07:	cc                   	int3

ffffffff8ac26f08 <neighbor_trampoline_266f08>:
ffffffff8ac26f08:	e9 13 27 91 00       	jmp    ffffffff8b539620 <neighbor_trampoline_266f18+0x912708>
ffffffff8ac26f0d:	cc                   	int3
ffffffff8ac26f0e:	cc                   	int3
ffffffff8ac26f0f:	cc                   	int3

ffffffff8ac26f10 <neighbor_trampoline_266f10>:
ffffffff8ac26f10:	e9 1b 29 91 00       	jmp    ffffffff8b539830 <neighbor_trampoline_266f18+0x912918>
ffffffff8ac26f15:	cc                   	int3
ffffffff8ac26f16:	cc                   	int3
ffffffff8ac26f17:	cc                   	int3

ffffffff8ac26f18 <neighbor_trampoline_266f18>:
ffffffff8ac26f18:	e9 73 9f 91 00       	jmp    ffffffff8b540e90 <neighbor_trampoline_266f18+0x919f78>
ffffffff8ac26f1d:	cc                   	int3
ffffffff8ac26f1e:	cc                   	int3
ffffffff8ac26f1f:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8b450e10, handler_body_640; REA Evidence ev_8185574cb8dd2212da24a2c9df037d1976d30b331c610dadce1d16b007d361c3
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8b450e10", "end": "0xffffffff8b450e17"}], "total_bytes": 8, "span_bytes": 8, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_640:
0xffffffff8b450e10: PUSH RBP
0xffffffff8b450e11: MOV RBP, RSP
0xffffffff8b450e14: XOR EAX, EAX
0xffffffff8b450e16: POP RBP
0xffffffff8b450e17: RET
; END FUNCTION handler_body_640

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_1b9d46d50f23b8899a0d786f73966305d819a446b06a019b1eb294cfd27dcca7
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_640.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8b450e10 <handler_640_body>:
ffffffff8b450e10:	55                   	push   %rbp
ffffffff8b450e11:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b450e14:	31 c0                	xor    %eax,%eax
ffffffff8b450e16:	5d                   	pop    %rbp
ffffffff8b450e17:	c3                   	ret
ffffffff8b450e18:	90                   	nop
ffffffff8b450e19:	90                   	nop
ffffffff8b450e1a:	90                   	nop
ffffffff8b450e1b:	90                   	nop
ffffffff8b450e1c:	90                   	nop
ffffffff8b450e1d:	90                   	nop
ffffffff8b450e1e:	90                   	nop
ffffffff8b450e1f:	90                   	nop

ffffffff8b450e20 <frame_candidate_a90e20>:
ffffffff8b450e20:	55                   	push   %rbp
ffffffff8b450e21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b450e24:	53                   	push   %rbx
ffffffff8b450e25:	50                   	push   %rax
ffffffff8b450e26:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b450e2b:	31 c0                	xor    %eax,%eax
ffffffff8b450e2d:	f0 0f b1 0d a3 5a 16 	lock cmpxchg %ecx,0x3165aa3(%rip)        # ffffffff8e5b68d8 <frame_candidate_a92d00+0x3163bd8>
ffffffff8b450e34:	03 
ffffffff8b450e35:	0f 85 9a 02 00 00    	jne    ffffffff8b4510d5 <frame_candidate_a90e20+0x2b5>
ffffffff8b450e3b:	4c 8d 1d e6 08 7e ff 	lea    -0x81f71a(%rip),%r11        # ffffffff8ac31728 <handler_640_body-0x81f6e8>
ffffffff8b450e42:	4c 8d 15 d7 08 7e ff 	lea    -0x81f729(%rip),%r10        # ffffffff8ac31720 <handler_640_body-0x81f6f0>
ffffffff8b450e49:	48 8d 0d 00 a9 7d ff 	lea    -0x825700(%rip),%rcx        # ffffffff8ac2b750 <handler_640_body-0x8256c0>
ffffffff8b450e50:	4c 8d 05 41 f5 7d ff 	lea    -0x820abf(%rip),%r8        # ffffffff8ac30398 <handler_640_body-0x820a78>
ffffffff8b450e57:	48 8d 05 72 ce 7d ff 	lea    -0x82318e(%rip),%rax        # ffffffff8ac2dcd0 <handler_640_body-0x823140>
ffffffff8b450e5e:	48 8d 15 53 c6 7c ff 	lea    -0x8339ad(%rip),%rdx        # ffffffff8ac1d4b8 <handler_640_body-0x833958>
ffffffff8b450e65:	48 8d 35 24 ec 7d ff 	lea    -0x8213dc(%rip),%rsi        # ffffffff8ac2fa90 <handler_640_body-0x821380>
ffffffff8b450e6c:	48 8d 3d cd 9e 7d ff 	lea    -0x826133(%rip),%rdi        # ffffffff8ac2ad40 <handler_640_body-0x8260d0>
ffffffff8b450e73:	48 8d 1d 16 c2 7d ff 	lea    -0x823dea(%rip),%rbx        # ffffffff8ac2d090 <handler_640_body-0x823d80>
ffffffff8b450e7a:	4c 8d 0d 67 85 7d ff 	lea    -0x827a99(%rip),%r9        # ffffffff8ac293e8 <handler_640_body-0x827a28>
ffffffff8b450e81:	4c 89 1d a8 5a 16 03 	mov    %r11,0x3165aa8(%rip)        # ffffffff8e5b6930 <frame_candidate_a92d00+0x3163c30>
ffffffff8b450e88:	4c 8d 1d 99 10 7e ff 	lea    -0x81ef67(%rip),%r11        # ffffffff8ac31f28 <handler_640_body-0x81eee8>
ffffffff8b450e8f:	4c 89 15 92 5a 16 03 	mov    %r10,0x3165a92(%rip)        # ffffffff8e5b6928 <frame_candidate_a92d00+0x3163c28>
ffffffff8b450e96:	4c 8d 15 73 95 7d ff 	lea    -0x826a8d(%rip),%r10        # ffffffff8ac2a410 <handler_640_body-0x826a00>
ffffffff8b450e9d:	48 89 0d 44 5a 16 03 	mov    %rcx,0x3165a44(%rip)        # ffffffff8e5b68e8 <frame_candidate_a92d00+0x3163be8>
ffffffff8b450ea4:	48 8d 0d 05 c6 7c ff 	lea    -0x8339fb(%rip),%rcx        # ffffffff8ac1d4b0 <handler_640_body-0x833960>
ffffffff8b450eab:	4c 89 05 5e 5a 16 03 	mov    %r8,0x3165a5e(%rip)        # ffffffff8e5b6910 <frame_candidate_a92d00+0x3163c10>
ffffffff8b450eb2:	4c 8d 05 a7 0f 7e ff 	lea    -0x81f059(%rip),%r8        # ffffffff8ac31e60 <handler_640_body-0x81efb0>
ffffffff8b450eb9:	48 89 05 20 5a 16 03 	mov    %rax,0x3165a20(%rip)        # ffffffff8e5b68e0 <frame_candidate_a92d00+0x3163be0>
ffffffff8b450ec0:	48 89 15 31 5a 16 03 	mov    %rdx,0x3165a31(%rip)        # ffffffff8e5b68f8 <frame_candidate_a92d00+0x3163bf8>
ffffffff8b450ec7:	48 89 35 32 5a 16 03 	mov    %rsi,0x3165a32(%rip)        # ffffffff8e5b6900 <frame_candidate_a92d00+0x3163c00>
ffffffff8b450ece:	48 89 3d 33 5a 16 03 	mov    %rdi,0x3165a33(%rip)        # ffffffff8e5b6908 <frame_candidate_a92d00+0x3163c08>
ffffffff8b450ed5:	4c 89 0d 44 5a 16 03 	mov    %r9,0x3165a44(%rip)        # ffffffff8e5b6920 <frame_candidate_a92d00+0x3163c20>
ffffffff8b450edc:	48 89 1d b5 5a 16 03 	mov    %rbx,0x3165ab5(%rip)        # ffffffff8e5b6998 <frame_candidate_a92d00+0x3163c98>
ffffffff8b450ee3:	48 89 05 36 5b 16 03 	mov    %rax,0x3165b36(%rip)        # ffffffff8e5b6a20 <frame_candidate_a92d00+0x3163d20>
ffffffff8b450eea:	48 89 15 3f 5b 16 03 	mov    %rdx,0x3165b3f(%rip)        # ffffffff8e5b6a30 <frame_candidate_a92d00+0x3163d30>
ffffffff8b450ef1:	48 89 35 40 5b 16 03 	mov    %rsi,0x3165b40(%rip)        # ffffffff8e5b6a38 <frame_candidate_a92d00+0x3163d38>
ffffffff8b450ef8:	48 89 3d 41 5b 16 03 	mov    %rdi,0x3165b41(%rip)        # ffffffff8e5b6a40 <frame_candidate_a92d00+0x3163d40>
ffffffff8b450eff:	48 89 1d 4a 5b 16 03 	mov    %rbx,0x3165b4a(%rip)        # ffffffff8e5b6a50 <frame_candidate_a92d00+0x3163d50>
ffffffff8b450f06:	4c 89 1d 33 5a 16 03 	mov    %r11,0x3165a33(%rip)        # ffffffff8e5b6940 <frame_candidate_a92d00+0x3163c40>
ffffffff8b450f0d:	4c 8d 1d 54 ea 7d ff 	lea    -0x8215ac(%rip),%r11        # ffffffff8ac2f968 <handler_640_body-0x8214a8>
ffffffff8b450f14:	4c 89 15 1d 5a 16 03 	mov    %r10,0x3165a1d(%rip)        # ffffffff8e5b6938 <frame_candidate_a92d00+0x3163c38>
ffffffff8b450f1b:	4c 8d 15 d6 f1 7d ff 	lea    -0x820e2a(%rip),%r10        # ffffffff8ac300f8 <handler_640_body-0x820d18>
ffffffff8b450f22:	48 89 0d c7 59 16 03 	mov    %rcx,0x31659c7(%rip)        # ffffffff8e5b68f0 <frame_candidate_a92d00+0x3163bf0>
ffffffff8b450f29:	4c 89 05 e8 59 16 03 	mov    %r8,0x31659e8(%rip)        # ffffffff8e5b6918 <frame_candidate_a92d00+0x3163c18>
ffffffff8b450f30:	48 89 0d f1 5a 16 03 	mov    %rcx,0x3165af1(%rip)        # ffffffff8e5b6a28 <frame_candidate_a92d00+0x3163d28>
ffffffff8b450f37:	4c 89 05 0a 5b 16 03 	mov    %r8,0x3165b0a(%rip)        # ffffffff8e5b6a48 <frame_candidate_a92d00+0x3163d48>
ffffffff8b450f3e:	4c 89 1d 0b 5a 16 03 	mov    %r11,0x3165a0b(%rip)        # ffffffff8e5b6950 <frame_candidate_a92d00+0x3163c50>
ffffffff8b450f45:	4c 8d 1d bc b5 7d ff 	lea    -0x824a44(%rip),%r11        # ffffffff8ac2c508 <handler_640_body-0x824908>
ffffffff8b450f4c:	4c 89 15 f5 59 16 03 	mov    %r10,0x31659f5(%rip)        # ffffffff8e5b6948 <frame_candidate_a92d00+0x3163c48>
ffffffff8b450f53:	4c 8d 15 be ea 7d ff 	lea    -0x821542(%rip),%r10        # ffffffff8ac2fa18 <handler_640_body-0x8213f8>
ffffffff8b450f5a:	4c 89 1d ff 59 16 03 	mov    %r11,0x31659ff(%rip)        # ffffffff8e5b6960 <frame_candidate_a92d00+0x3163c60>
ffffffff8b450f61:	4c 8d 1d b0 94 7d ff 	lea    -0x826b50(%rip),%r11        # ffffffff8ac2a418 <handler_640_body-0x8269f8>
ffffffff8b450f68:	4c 89 15 e9 59 16 03 	mov    %r10,0x31659e9(%rip)        # ffffffff8e5b6958 <frame_candidate_a92d00+0x3163c58>
ffffffff8b450f6f:	4c 8d 15 9a b5 7d ff 	lea    -0x824a66(%rip),%r10        # ffffffff8ac2c510 <handler_640_body-0x824900>
ffffffff8b450f76:	4c 89 1d 53 59 16 03 	mov    %r11,0x3165953(%rip)        # ffffffff8e5b68d0 <frame_candidate_a92d00+0x3163bd0>
ffffffff8b450f7d:	4c 8d 1d ac f0 7d ff 	lea    -0x820f54(%rip),%r11        # ffffffff8ac30030 <handler_640_body-0x820de0>
ffffffff8b450f84:	4c 89 15 dd 59 16 03 	mov    %r10,0x31659dd(%rip)        # ffffffff8e5b6968 <frame_candidate_a92d00+0x3163c68>
ffffffff8b450f8b:	4c 8d 15 36 c5 7c ff 	lea    -0x833aca(%rip),%r10        # ffffffff8ac1d4c8 <handler_640_body-0x833948>
ffffffff8b450f92:	4c 89 1d df 59 16 03 	mov    %r11,0x31659df(%rip)        # ffffffff8e5b6978 <frame_candidate_a92d00+0x3163c78>
ffffffff8b450f99:	4c 8d 1d 90 07 7e ff 	lea    -0x81f870(%rip),%r11        # ffffffff8ac31730 <handler_640_body-0x81f6e0>
ffffffff8b450fa0:	4c 89 15 c9 59 16 03 	mov    %r10,0x31659c9(%rip)        # ffffffff8e5b6970 <frame_candidate_a92d00+0x3163c70>
ffffffff8b450fa7:	4c 8d 15 8a f0 7d ff 	lea    -0x820f76(%rip),%r10        # ffffffff8ac30038 <handler_640_body-0x820dd8>
ffffffff8b450fae:	4c 89 1d d3 59 16 03 	mov    %r11,0x31659d3(%rip)        # ffffffff8e5b6988 <frame_candidate_a92d00+0x3163c88>
ffffffff8b450fb5:	4c 8d 1d dc 9f 7d ff 	lea    -0x826024(%rip),%r11        # ffffffff8ac2af98 <handler_640_body-0x825e78>
ffffffff8b450fbc:	4c 89 15 bd 59 16 03 	mov    %r10,0x31659bd(%rip)        # ffffffff8e5b6980 <frame_candidate_a92d00+0x3163c80>
ffffffff8b450fc3:	4c 8d 15 6e 07 7e ff 	lea    -0x81f892(%rip),%r10        # ffffffff8ac31738 <handler_640_body-0x81f6d8>
ffffffff8b450fca:	4c 89 1d d7 59 16 03 	mov    %r11,0x31659d7(%rip)        # ffffffff8e5b69a8 <frame_candidate_a92d00+0x3163ca8>
ffffffff8b450fd1:	4c 8d 1d d0 b4 7d ff 	lea    -0x824b30(%rip),%r11        # ffffffff8ac2c4a8 <handler_640_body-0x824968>
ffffffff8b450fd8:	4c 89 15 b1 59 16 03 	mov    %r10,0x31659b1(%rip)        # ffffffff8e5b6990 <frame_candidate_a92d00+0x3163c90>
ffffffff8b450fdf:	4c 8d 15 fa ca 7d ff 	lea    -0x823506(%rip),%r10        # ffffffff8ac2dae0 <handler_640_body-0x823330>
ffffffff8b450fe6:	4c 89 1d c3 59 16 03 	mov    %r11,0x31659c3(%rip)        # ffffffff8e5b69b0 <frame_candidate_a92d00+0x3163cb0>
ffffffff8b450fed:	4c 8d 1d ac 9f 7d ff 	lea    -0x826054(%rip),%r11        # ffffffff8ac2afa0 <handler_640_body-0x825e70>
ffffffff8b450ff4:	4c 89 15 a5 59 16 03 	mov    %r10,0x31659a5(%rip)        # ffffffff8e5b69a0 <frame_candidate_a92d00+0x3163ca0>
ffffffff8b450ffb:	4c 89 15 56 5a 16 03 	mov    %r10,0x3165a56(%rip)        # ffffffff8e5b6a58 <frame_candidate_a92d00+0x3163d58>
ffffffff8b451002:	4c 89 1d af 59 16 03 	mov    %r11,0x31659af(%rip)        # ffffffff8e5b69b8 <frame_candidate_a92d00+0x3163cb8>
ffffffff8b451009:	4c 8d 1d 28 c1 7d ff 	lea    -0x823ed8(%rip),%r11        # ffffffff8ac2d138 <handler_640_body-0x823cd8>
ffffffff8b451010:	4c 89 1d a9 59 16 03 	mov    %r11,0x31659a9(%rip)        # ffffffff8e5b69c0 <frame_candidate_a92d00+0x3163cc0>
ffffffff8b451017:	4c 8d 1d 9a e5 7d ff 	lea    -0x821a66(%rip),%r11        # ffffffff8ac2f5b8 <handler_640_body-0x821858>
ffffffff8b45101e:	4c 89 1d a3 59 16 03 	mov    %r11,0x31659a3(%rip)        # ffffffff8e5b69c8 <frame_candidate_a92d00+0x3163cc8>
ffffffff8b451025:	4c 8d 1d ec c7 7d ff 	lea    -0x823814(%rip),%r11        # ffffffff8ac2d818 <handler_640_body-0x8235f8>
ffffffff8b45102c:	4c 89 1d 9d 59 16 03 	mov    %r11,0x316599d(%rip)        # ffffffff8e5b69d0 <frame_candidate_a92d00+0x3163cd0>
ffffffff8b451033:	4c 8d 1d c6 f2 7d ff 	lea    -0x820d3a(%rip),%r11        # ffffffff8ac30300 <handler_640_body-0x820b10>
ffffffff8b45103a:	4c 89 1d 97 59 16 03 	mov    %r11,0x3165997(%rip)        # ffffffff8e5b69d8 <frame_candidate_a92d00+0x3163cd8>
ffffffff8b451041:	4c 8d 1d c0 f2 7d ff 	lea    -0x820d40(%rip),%r11        # ffffffff8ac30308 <handler_640_body-0x820b08>
ffffffff8b451048:	4c 89 1d 91 59 16 03 	mov    %r11,0x3165991(%rip)        # ffffffff8e5b69e0 <frame_candidate_a92d00+0x3163ce0>
ffffffff8b45104f:	4c 8d 1d 52 9f 7d ff 	lea    -0x8260ae(%rip),%r11        # ffffffff8ac2afa8 <handler_640_body-0x825e68>
ffffffff8b451056:	4c 89 1d 8b 59 16 03 	mov    %r11,0x316598b(%rip)        # ffffffff8e5b69e8 <frame_candidate_a92d00+0x3163ce8>
ffffffff8b45105d:	4c 8d 1d 9c b1 7d ff 	lea    -0x824e64(%rip),%r11        # ffffffff8ac2c200 <handler_640_body-0x824c10>
ffffffff8b451064:	4c 89 1d 85 59 16 03 	mov    %r11,0x3165985(%rip)        # ffffffff8e5b69f0 <frame_candidate_a92d00+0x3163cf0>
ffffffff8b45106b:	4c 8d 1d 96 b1 7d ff 	lea    -0x824e6a(%rip),%r11        # ffffffff8ac2c208 <handler_640_body-0x824c08>
ffffffff8b451072:	4c 89 1d 7f 59 16 03 	mov    %r11,0x316597f(%rip)        # ffffffff8e5b69f8 <frame_candidate_a92d00+0x3163cf8>
ffffffff8b451079:	4c 8d 1d 90 e8 7d ff 	lea    -0x821770(%rip),%r11        # ffffffff8ac2f910 <handler_640_body-0x821500>
ffffffff8b451080:	4c 89 1d 79 59 16 03 	mov    %r11,0x3165979(%rip)        # ffffffff8e5b6a00 <frame_candidate_a92d00+0x3163d00>
ffffffff8b451087:	4c 8d 1d 8a e8 7d ff 	lea    -0x821776(%rip),%r11        # ffffffff8ac2f918 <handler_640_body-0x8214f8>
ffffffff8b45108e:	4c 89 1d 73 59 16 03 	mov    %r11,0x3165973(%rip)        # ffffffff8e5b6a08 <frame_candidate_a92d00+0x3163d08>
ffffffff8b451095:	4c 8d 1d 84 e8 7d ff 	lea    -0x82177c(%rip),%r11        # ffffffff8ac2f920 <handler_640_body-0x8214f0>
ffffffff8b45109c:	4c 89 1d 6d 59 16 03 	mov    %r11,0x316596d(%rip)        # ffffffff8e5b6a10 <frame_candidate_a92d00+0x3163d10>
ffffffff8b4510a3:	4c 8d 1d 7e e8 7d ff 	lea    -0x821782(%rip),%r11        # ffffffff8ac2f928 <handler_640_body-0x8214e8>
ffffffff8b4510aa:	4c 89 1d 67 59 16 03 	mov    %r11,0x3165967(%rip)        # ffffffff8e5b6a18 <frame_candidate_a92d00+0x3163d18>
ffffffff8b4510b1:	e8 1a 68 07 00       	call   ffffffff8b4c78d0 <frame_candidate_a92d00+0x74bd0>
ffffffff8b4510b6:	85 c0                	test   %eax,%eax
ffffffff8b4510b8:	74 1b                	je     ffffffff8b4510d5 <frame_candidate_a90e20+0x2b5>
ffffffff8b4510ba:	e8 51 bd 03 00       	call   ffffffff8b48ce10 <frame_candidate_a92d00+0x3a110>
ffffffff8b4510bf:	89 c3                	mov    %eax,%ebx
ffffffff8b4510c1:	e8 8a bd 03 00       	call   ffffffff8b48ce50 <frame_candidate_a92d00+0x3a150>
ffffffff8b4510c6:	31 c9                	xor    %ecx,%ecx
ffffffff8b4510c8:	85 c0                	test   %eax,%eax
ffffffff8b4510ca:	0f 94 c1             	sete   %cl
ffffffff8b4510cd:	21 d9                	and    %ebx,%ecx
ffffffff8b4510cf:	89 0d 2b ef 21 02    	mov    %ecx,0x221ef2b(%rip)        # ffffffff8d670000 <frame_candidate_a92d00+0x221d300>
ffffffff8b4510d5:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b4510d9:	5b                   	pop    %rbx
ffffffff8b4510da:	5d                   	pop    %rbp
ffffffff8b4510db:	c3                   	ret
ffffffff8b4510dc:	90                   	nop
ffffffff8b4510dd:	90                   	nop
ffffffff8b4510de:	90                   	nop
ffffffff8b4510df:	90                   	nop

ffffffff8b4510e0 <frame_candidate_a910e0>:
ffffffff8b4510e0:	55                   	push   %rbp
ffffffff8b4510e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4510e4:	5d                   	pop    %rbp
ffffffff8b4510e5:	c3                   	ret
ffffffff8b4510e6:	90                   	nop
ffffffff8b4510e7:	90                   	nop
ffffffff8b4510e8:	90                   	nop
ffffffff8b4510e9:	90                   	nop
ffffffff8b4510ea:	90                   	nop
ffffffff8b4510eb:	90                   	nop
ffffffff8b4510ec:	90                   	nop
ffffffff8b4510ed:	90                   	nop
ffffffff8b4510ee:	90                   	nop
ffffffff8b4510ef:	90                   	nop

ffffffff8b4510f0 <frame_candidate_a910f0>:
ffffffff8b4510f0:	55                   	push   %rbp
ffffffff8b4510f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4510f4:	5d                   	pop    %rbp
ffffffff8b4510f5:	c3                   	ret
ffffffff8b4510f6:	90                   	nop
ffffffff8b4510f7:	90                   	nop
ffffffff8b4510f8:	90                   	nop
ffffffff8b4510f9:	90                   	nop
ffffffff8b4510fa:	90                   	nop
ffffffff8b4510fb:	90                   	nop
ffffffff8b4510fc:	90                   	nop
ffffffff8b4510fd:	90                   	nop
ffffffff8b4510fe:	90                   	nop
ffffffff8b4510ff:	90                   	nop

ffffffff8b451100 <frame_candidate_a91100>:
ffffffff8b451100:	55                   	push   %rbp
ffffffff8b451101:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451104:	5d                   	pop    %rbp
ffffffff8b451105:	c3                   	ret
ffffffff8b451106:	90                   	nop
ffffffff8b451107:	90                   	nop
ffffffff8b451108:	90                   	nop
ffffffff8b451109:	90                   	nop
ffffffff8b45110a:	90                   	nop
ffffffff8b45110b:	90                   	nop
ffffffff8b45110c:	90                   	nop
ffffffff8b45110d:	90                   	nop
ffffffff8b45110e:	90                   	nop
ffffffff8b45110f:	90                   	nop

ffffffff8b451110 <frame_candidate_a91110>:
ffffffff8b451110:	55                   	push   %rbp
ffffffff8b451111:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451114:	5d                   	pop    %rbp
ffffffff8b451115:	c3                   	ret
ffffffff8b451116:	90                   	nop
ffffffff8b451117:	90                   	nop
ffffffff8b451118:	90                   	nop
ffffffff8b451119:	90                   	nop
ffffffff8b45111a:	90                   	nop
ffffffff8b45111b:	90                   	nop
ffffffff8b45111c:	90                   	nop
ffffffff8b45111d:	90                   	nop
ffffffff8b45111e:	90                   	nop
ffffffff8b45111f:	90                   	nop

ffffffff8b451120 <frame_candidate_a91120>:
ffffffff8b451120:	55                   	push   %rbp
ffffffff8b451121:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451124:	5d                   	pop    %rbp
ffffffff8b451125:	c3                   	ret
ffffffff8b451126:	90                   	nop
ffffffff8b451127:	90                   	nop
ffffffff8b451128:	90                   	nop
ffffffff8b451129:	90                   	nop
ffffffff8b45112a:	90                   	nop
ffffffff8b45112b:	90                   	nop
ffffffff8b45112c:	90                   	nop
ffffffff8b45112d:	90                   	nop
ffffffff8b45112e:	90                   	nop
ffffffff8b45112f:	90                   	nop

ffffffff8b451130 <frame_candidate_a91130>:
ffffffff8b451130:	55                   	push   %rbp
ffffffff8b451131:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451134:	5d                   	pop    %rbp
ffffffff8b451135:	c3                   	ret
ffffffff8b451136:	90                   	nop
ffffffff8b451137:	90                   	nop
ffffffff8b451138:	90                   	nop
ffffffff8b451139:	90                   	nop
ffffffff8b45113a:	90                   	nop
ffffffff8b45113b:	90                   	nop
ffffffff8b45113c:	90                   	nop
ffffffff8b45113d:	90                   	nop
ffffffff8b45113e:	90                   	nop
ffffffff8b45113f:	90                   	nop

ffffffff8b451140 <frame_candidate_a91140>:
ffffffff8b451140:	55                   	push   %rbp
ffffffff8b451141:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451144:	5d                   	pop    %rbp
ffffffff8b451145:	c3                   	ret
ffffffff8b451146:	90                   	nop
ffffffff8b451147:	90                   	nop
ffffffff8b451148:	90                   	nop
ffffffff8b451149:	90                   	nop
ffffffff8b45114a:	90                   	nop
ffffffff8b45114b:	90                   	nop
ffffffff8b45114c:	90                   	nop
ffffffff8b45114d:	90                   	nop
ffffffff8b45114e:	90                   	nop
ffffffff8b45114f:	90                   	nop

ffffffff8b451150 <frame_candidate_a91150>:
ffffffff8b451150:	55                   	push   %rbp
ffffffff8b451151:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451154:	5d                   	pop    %rbp
ffffffff8b451155:	c3                   	ret
ffffffff8b451156:	90                   	nop
ffffffff8b451157:	90                   	nop
ffffffff8b451158:	90                   	nop
ffffffff8b451159:	90                   	nop
ffffffff8b45115a:	90                   	nop
ffffffff8b45115b:	90                   	nop
ffffffff8b45115c:	90                   	nop
ffffffff8b45115d:	90                   	nop
ffffffff8b45115e:	90                   	nop
ffffffff8b45115f:	90                   	nop

ffffffff8b451160 <frame_candidate_a91160>:
ffffffff8b451160:	55                   	push   %rbp
ffffffff8b451161:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451164:	31 c0                	xor    %eax,%eax
ffffffff8b451166:	5d                   	pop    %rbp
ffffffff8b451167:	c3                   	ret
ffffffff8b451168:	90                   	nop
ffffffff8b451169:	90                   	nop
ffffffff8b45116a:	90                   	nop
ffffffff8b45116b:	90                   	nop
ffffffff8b45116c:	90                   	nop
ffffffff8b45116d:	90                   	nop
ffffffff8b45116e:	90                   	nop
ffffffff8b45116f:	90                   	nop

ffffffff8b451170 <frame_candidate_a91170>:
ffffffff8b451170:	55                   	push   %rbp
ffffffff8b451171:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451174:	5d                   	pop    %rbp
ffffffff8b451175:	c3                   	ret
ffffffff8b451176:	90                   	nop
ffffffff8b451177:	90                   	nop
ffffffff8b451178:	90                   	nop
ffffffff8b451179:	90                   	nop
ffffffff8b45117a:	90                   	nop
ffffffff8b45117b:	90                   	nop
ffffffff8b45117c:	90                   	nop
ffffffff8b45117d:	90                   	nop
ffffffff8b45117e:	90                   	nop
ffffffff8b45117f:	90                   	nop

ffffffff8b451180 <frame_candidate_a91180>:
ffffffff8b451180:	55                   	push   %rbp
ffffffff8b451181:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451184:	5d                   	pop    %rbp
ffffffff8b451185:	c3                   	ret
ffffffff8b451186:	90                   	nop
ffffffff8b451187:	90                   	nop
ffffffff8b451188:	90                   	nop
ffffffff8b451189:	90                   	nop
ffffffff8b45118a:	90                   	nop
ffffffff8b45118b:	90                   	nop
ffffffff8b45118c:	90                   	nop
ffffffff8b45118d:	90                   	nop
ffffffff8b45118e:	90                   	nop
ffffffff8b45118f:	90                   	nop

ffffffff8b451190 <frame_candidate_a91190>:
ffffffff8b451190:	55                   	push   %rbp
ffffffff8b451191:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451194:	5d                   	pop    %rbp
ffffffff8b451195:	c3                   	ret
ffffffff8b451196:	90                   	nop
ffffffff8b451197:	90                   	nop
ffffffff8b451198:	90                   	nop
ffffffff8b451199:	90                   	nop
ffffffff8b45119a:	90                   	nop
ffffffff8b45119b:	90                   	nop
ffffffff8b45119c:	90                   	nop
ffffffff8b45119d:	90                   	nop
ffffffff8b45119e:	90                   	nop
ffffffff8b45119f:	90                   	nop

ffffffff8b4511a0 <frame_candidate_a911a0>:
ffffffff8b4511a0:	55                   	push   %rbp
ffffffff8b4511a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4511a4:	5d                   	pop    %rbp
ffffffff8b4511a5:	c3                   	ret
ffffffff8b4511a6:	90                   	nop
ffffffff8b4511a7:	90                   	nop
ffffffff8b4511a8:	90                   	nop
ffffffff8b4511a9:	90                   	nop
ffffffff8b4511aa:	90                   	nop
ffffffff8b4511ab:	90                   	nop
ffffffff8b4511ac:	90                   	nop
ffffffff8b4511ad:	90                   	nop
ffffffff8b4511ae:	90                   	nop
ffffffff8b4511af:	90                   	nop

ffffffff8b4511b0 <frame_candidate_a911b0>:
ffffffff8b4511b0:	55                   	push   %rbp
ffffffff8b4511b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4511b4:	5d                   	pop    %rbp
ffffffff8b4511b5:	c3                   	ret
ffffffff8b4511b6:	90                   	nop
ffffffff8b4511b7:	90                   	nop
ffffffff8b4511b8:	90                   	nop
ffffffff8b4511b9:	90                   	nop
ffffffff8b4511ba:	90                   	nop
ffffffff8b4511bb:	90                   	nop
ffffffff8b4511bc:	90                   	nop
ffffffff8b4511bd:	90                   	nop
ffffffff8b4511be:	90                   	nop
ffffffff8b4511bf:	90                   	nop

ffffffff8b4511c0 <frame_candidate_a911c0>:
ffffffff8b4511c0:	55                   	push   %rbp
ffffffff8b4511c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4511c4:	5d                   	pop    %rbp
ffffffff8b4511c5:	c3                   	ret
ffffffff8b4511c6:	90                   	nop
ffffffff8b4511c7:	90                   	nop
ffffffff8b4511c8:	90                   	nop
ffffffff8b4511c9:	90                   	nop
ffffffff8b4511ca:	90                   	nop
ffffffff8b4511cb:	90                   	nop
ffffffff8b4511cc:	90                   	nop
ffffffff8b4511cd:	90                   	nop
ffffffff8b4511ce:	90                   	nop
ffffffff8b4511cf:	90                   	nop

ffffffff8b4511d0 <frame_candidate_a911d0>:
ffffffff8b4511d0:	55                   	push   %rbp
ffffffff8b4511d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4511d4:	5d                   	pop    %rbp
ffffffff8b4511d5:	c3                   	ret
ffffffff8b4511d6:	90                   	nop
ffffffff8b4511d7:	90                   	nop
ffffffff8b4511d8:	90                   	nop
ffffffff8b4511d9:	90                   	nop
ffffffff8b4511da:	90                   	nop
ffffffff8b4511db:	90                   	nop
ffffffff8b4511dc:	90                   	nop
ffffffff8b4511dd:	90                   	nop
ffffffff8b4511de:	90                   	nop
ffffffff8b4511df:	90                   	nop

ffffffff8b4511e0 <frame_candidate_a911e0>:
ffffffff8b4511e0:	55                   	push   %rbp
ffffffff8b4511e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4511e4:	5d                   	pop    %rbp
ffffffff8b4511e5:	c3                   	ret
ffffffff8b4511e6:	90                   	nop
ffffffff8b4511e7:	90                   	nop
ffffffff8b4511e8:	90                   	nop
ffffffff8b4511e9:	90                   	nop
ffffffff8b4511ea:	90                   	nop
ffffffff8b4511eb:	90                   	nop
ffffffff8b4511ec:	90                   	nop
ffffffff8b4511ed:	90                   	nop
ffffffff8b4511ee:	90                   	nop
ffffffff8b4511ef:	90                   	nop

ffffffff8b4511f0 <frame_candidate_a911f0>:
ffffffff8b4511f0:	55                   	push   %rbp
ffffffff8b4511f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4511f4:	5d                   	pop    %rbp
ffffffff8b4511f5:	c3                   	ret
ffffffff8b4511f6:	90                   	nop
ffffffff8b4511f7:	90                   	nop
ffffffff8b4511f8:	90                   	nop
ffffffff8b4511f9:	90                   	nop
ffffffff8b4511fa:	90                   	nop
ffffffff8b4511fb:	90                   	nop
ffffffff8b4511fc:	90                   	nop
ffffffff8b4511fd:	90                   	nop
ffffffff8b4511fe:	90                   	nop
ffffffff8b4511ff:	90                   	nop

ffffffff8b451200 <frame_candidate_a91200>:
ffffffff8b451200:	55                   	push   %rbp
ffffffff8b451201:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451204:	5d                   	pop    %rbp
ffffffff8b451205:	c3                   	ret
ffffffff8b451206:	90                   	nop
ffffffff8b451207:	90                   	nop
ffffffff8b451208:	90                   	nop
ffffffff8b451209:	90                   	nop
ffffffff8b45120a:	90                   	nop
ffffffff8b45120b:	90                   	nop
ffffffff8b45120c:	90                   	nop
ffffffff8b45120d:	90                   	nop
ffffffff8b45120e:	90                   	nop
ffffffff8b45120f:	90                   	nop

ffffffff8b451210 <frame_candidate_a91210>:
ffffffff8b451210:	55                   	push   %rbp
ffffffff8b451211:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451214:	31 c0                	xor    %eax,%eax
ffffffff8b451216:	5d                   	pop    %rbp
ffffffff8b451217:	c3                   	ret
ffffffff8b451218:	90                   	nop
ffffffff8b451219:	90                   	nop
ffffffff8b45121a:	90                   	nop
ffffffff8b45121b:	90                   	nop
ffffffff8b45121c:	90                   	nop
ffffffff8b45121d:	90                   	nop
ffffffff8b45121e:	90                   	nop
ffffffff8b45121f:	90                   	nop

ffffffff8b451220 <frame_candidate_a91220>:
ffffffff8b451220:	55                   	push   %rbp
ffffffff8b451221:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451224:	5d                   	pop    %rbp
ffffffff8b451225:	c3                   	ret
ffffffff8b451226:	90                   	nop
ffffffff8b451227:	90                   	nop
ffffffff8b451228:	90                   	nop
ffffffff8b451229:	90                   	nop
ffffffff8b45122a:	90                   	nop
ffffffff8b45122b:	90                   	nop
ffffffff8b45122c:	90                   	nop
ffffffff8b45122d:	90                   	nop
ffffffff8b45122e:	90                   	nop
ffffffff8b45122f:	90                   	nop

ffffffff8b451230 <frame_candidate_a91230>:
ffffffff8b451230:	55                   	push   %rbp
ffffffff8b451231:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451234:	5d                   	pop    %rbp
ffffffff8b451235:	c3                   	ret
ffffffff8b451236:	90                   	nop
ffffffff8b451237:	90                   	nop
ffffffff8b451238:	90                   	nop
ffffffff8b451239:	90                   	nop
ffffffff8b45123a:	90                   	nop
ffffffff8b45123b:	90                   	nop
ffffffff8b45123c:	90                   	nop
ffffffff8b45123d:	90                   	nop
ffffffff8b45123e:	90                   	nop
ffffffff8b45123f:	90                   	nop

ffffffff8b451240 <frame_candidate_a91240>:
ffffffff8b451240:	55                   	push   %rbp
ffffffff8b451241:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451244:	5d                   	pop    %rbp
ffffffff8b451245:	c3                   	ret
ffffffff8b451246:	90                   	nop
ffffffff8b451247:	90                   	nop
ffffffff8b451248:	90                   	nop
ffffffff8b451249:	90                   	nop
ffffffff8b45124a:	90                   	nop
ffffffff8b45124b:	90                   	nop
ffffffff8b45124c:	90                   	nop
ffffffff8b45124d:	90                   	nop
ffffffff8b45124e:	90                   	nop
ffffffff8b45124f:	90                   	nop

ffffffff8b451250 <frame_candidate_a91250>:
ffffffff8b451250:	55                   	push   %rbp
ffffffff8b451251:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451254:	5d                   	pop    %rbp
ffffffff8b451255:	c3                   	ret
ffffffff8b451256:	90                   	nop
ffffffff8b451257:	90                   	nop
ffffffff8b451258:	90                   	nop
ffffffff8b451259:	90                   	nop
ffffffff8b45125a:	90                   	nop
ffffffff8b45125b:	90                   	nop
ffffffff8b45125c:	90                   	nop
ffffffff8b45125d:	90                   	nop
ffffffff8b45125e:	90                   	nop
ffffffff8b45125f:	90                   	nop

ffffffff8b451260 <frame_candidate_a91260>:
ffffffff8b451260:	55                   	push   %rbp
ffffffff8b451261:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451264:	5d                   	pop    %rbp
ffffffff8b451265:	c3                   	ret
ffffffff8b451266:	90                   	nop
ffffffff8b451267:	90                   	nop
ffffffff8b451268:	90                   	nop
ffffffff8b451269:	90                   	nop
ffffffff8b45126a:	90                   	nop
ffffffff8b45126b:	90                   	nop
ffffffff8b45126c:	90                   	nop
ffffffff8b45126d:	90                   	nop
ffffffff8b45126e:	90                   	nop
ffffffff8b45126f:	90                   	nop

ffffffff8b451270 <frame_candidate_a91270>:
ffffffff8b451270:	55                   	push   %rbp
ffffffff8b451271:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451274:	5d                   	pop    %rbp
ffffffff8b451275:	c3                   	ret
ffffffff8b451276:	90                   	nop
ffffffff8b451277:	90                   	nop
ffffffff8b451278:	90                   	nop
ffffffff8b451279:	90                   	nop
ffffffff8b45127a:	90                   	nop
ffffffff8b45127b:	90                   	nop
ffffffff8b45127c:	90                   	nop
ffffffff8b45127d:	90                   	nop
ffffffff8b45127e:	90                   	nop
ffffffff8b45127f:	90                   	nop

ffffffff8b451280 <frame_candidate_a91280>:
ffffffff8b451280:	55                   	push   %rbp
ffffffff8b451281:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451284:	5d                   	pop    %rbp
ffffffff8b451285:	c3                   	ret
ffffffff8b451286:	90                   	nop
ffffffff8b451287:	90                   	nop
ffffffff8b451288:	90                   	nop
ffffffff8b451289:	90                   	nop
ffffffff8b45128a:	90                   	nop
ffffffff8b45128b:	90                   	nop
ffffffff8b45128c:	90                   	nop
ffffffff8b45128d:	90                   	nop
ffffffff8b45128e:	90                   	nop
ffffffff8b45128f:	90                   	nop

ffffffff8b451290 <frame_candidate_a91290>:
ffffffff8b451290:	55                   	push   %rbp
ffffffff8b451291:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451294:	5d                   	pop    %rbp
ffffffff8b451295:	c3                   	ret
ffffffff8b451296:	90                   	nop
ffffffff8b451297:	90                   	nop
ffffffff8b451298:	90                   	nop
ffffffff8b451299:	90                   	nop
ffffffff8b45129a:	90                   	nop
ffffffff8b45129b:	90                   	nop
ffffffff8b45129c:	90                   	nop
ffffffff8b45129d:	90                   	nop
ffffffff8b45129e:	90                   	nop
ffffffff8b45129f:	90                   	nop

ffffffff8b4512a0 <frame_candidate_a912a0>:
ffffffff8b4512a0:	55                   	push   %rbp
ffffffff8b4512a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4512a4:	5d                   	pop    %rbp
ffffffff8b4512a5:	c3                   	ret
ffffffff8b4512a6:	90                   	nop
ffffffff8b4512a7:	90                   	nop
ffffffff8b4512a8:	90                   	nop
ffffffff8b4512a9:	90                   	nop
ffffffff8b4512aa:	90                   	nop
ffffffff8b4512ab:	90                   	nop
ffffffff8b4512ac:	90                   	nop
ffffffff8b4512ad:	90                   	nop
ffffffff8b4512ae:	90                   	nop
ffffffff8b4512af:	90                   	nop

ffffffff8b4512b0 <frame_candidate_a912b0>:
ffffffff8b4512b0:	55                   	push   %rbp
ffffffff8b4512b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4512b4:	5d                   	pop    %rbp
ffffffff8b4512b5:	c3                   	ret
ffffffff8b4512b6:	90                   	nop
ffffffff8b4512b7:	90                   	nop
ffffffff8b4512b8:	90                   	nop
ffffffff8b4512b9:	90                   	nop
ffffffff8b4512ba:	90                   	nop
ffffffff8b4512bb:	90                   	nop
ffffffff8b4512bc:	90                   	nop
ffffffff8b4512bd:	90                   	nop
ffffffff8b4512be:	90                   	nop
ffffffff8b4512bf:	90                   	nop

ffffffff8b4512c0 <frame_candidate_a912c0>:
ffffffff8b4512c0:	55                   	push   %rbp
ffffffff8b4512c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4512c4:	5d                   	pop    %rbp
ffffffff8b4512c5:	c3                   	ret
ffffffff8b4512c6:	90                   	nop
ffffffff8b4512c7:	90                   	nop
ffffffff8b4512c8:	90                   	nop
ffffffff8b4512c9:	90                   	nop
ffffffff8b4512ca:	90                   	nop
ffffffff8b4512cb:	90                   	nop
ffffffff8b4512cc:	90                   	nop
ffffffff8b4512cd:	90                   	nop
ffffffff8b4512ce:	90                   	nop
ffffffff8b4512cf:	90                   	nop

ffffffff8b4512d0 <frame_candidate_a912d0>:
ffffffff8b4512d0:	55                   	push   %rbp
ffffffff8b4512d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4512d4:	5d                   	pop    %rbp
ffffffff8b4512d5:	c3                   	ret
ffffffff8b4512d6:	90                   	nop
ffffffff8b4512d7:	90                   	nop
ffffffff8b4512d8:	90                   	nop
ffffffff8b4512d9:	90                   	nop
ffffffff8b4512da:	90                   	nop
ffffffff8b4512db:	90                   	nop
ffffffff8b4512dc:	90                   	nop
ffffffff8b4512dd:	90                   	nop
ffffffff8b4512de:	90                   	nop
ffffffff8b4512df:	90                   	nop

ffffffff8b4512e0 <frame_candidate_a912e0>:
ffffffff8b4512e0:	55                   	push   %rbp
ffffffff8b4512e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4512e4:	5d                   	pop    %rbp
ffffffff8b4512e5:	c3                   	ret
ffffffff8b4512e6:	90                   	nop
ffffffff8b4512e7:	90                   	nop
ffffffff8b4512e8:	90                   	nop
ffffffff8b4512e9:	90                   	nop
ffffffff8b4512ea:	90                   	nop
ffffffff8b4512eb:	90                   	nop
ffffffff8b4512ec:	90                   	nop
ffffffff8b4512ed:	90                   	nop
ffffffff8b4512ee:	90                   	nop
ffffffff8b4512ef:	90                   	nop

ffffffff8b4512f0 <frame_candidate_a912f0>:
ffffffff8b4512f0:	55                   	push   %rbp
ffffffff8b4512f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4512f4:	5d                   	pop    %rbp
ffffffff8b4512f5:	c3                   	ret
ffffffff8b4512f6:	90                   	nop
ffffffff8b4512f7:	90                   	nop
ffffffff8b4512f8:	90                   	nop
ffffffff8b4512f9:	90                   	nop
ffffffff8b4512fa:	90                   	nop
ffffffff8b4512fb:	90                   	nop
ffffffff8b4512fc:	90                   	nop
ffffffff8b4512fd:	90                   	nop
ffffffff8b4512fe:	90                   	nop
ffffffff8b4512ff:	90                   	nop

ffffffff8b451300 <frame_candidate_a91300>:
ffffffff8b451300:	55                   	push   %rbp
ffffffff8b451301:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451304:	5d                   	pop    %rbp
ffffffff8b451305:	c3                   	ret
ffffffff8b451306:	90                   	nop
ffffffff8b451307:	90                   	nop
ffffffff8b451308:	90                   	nop
ffffffff8b451309:	90                   	nop
ffffffff8b45130a:	90                   	nop
ffffffff8b45130b:	90                   	nop
ffffffff8b45130c:	90                   	nop
ffffffff8b45130d:	90                   	nop
ffffffff8b45130e:	90                   	nop
ffffffff8b45130f:	90                   	nop

ffffffff8b451310 <frame_candidate_a91310>:
ffffffff8b451310:	55                   	push   %rbp
ffffffff8b451311:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451314:	5d                   	pop    %rbp
ffffffff8b451315:	c3                   	ret
ffffffff8b451316:	90                   	nop
ffffffff8b451317:	90                   	nop
ffffffff8b451318:	90                   	nop
ffffffff8b451319:	90                   	nop
ffffffff8b45131a:	90                   	nop
ffffffff8b45131b:	90                   	nop
ffffffff8b45131c:	90                   	nop
ffffffff8b45131d:	90                   	nop
ffffffff8b45131e:	90                   	nop
ffffffff8b45131f:	90                   	nop

ffffffff8b451320 <frame_candidate_a91320>:
ffffffff8b451320:	55                   	push   %rbp
ffffffff8b451321:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451324:	5d                   	pop    %rbp
ffffffff8b451325:	c3                   	ret
ffffffff8b451326:	90                   	nop
ffffffff8b451327:	90                   	nop
ffffffff8b451328:	90                   	nop
ffffffff8b451329:	90                   	nop
ffffffff8b45132a:	90                   	nop
ffffffff8b45132b:	90                   	nop
ffffffff8b45132c:	90                   	nop
ffffffff8b45132d:	90                   	nop
ffffffff8b45132e:	90                   	nop
ffffffff8b45132f:	90                   	nop

ffffffff8b451330 <frame_candidate_a91330>:
ffffffff8b451330:	55                   	push   %rbp
ffffffff8b451331:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451334:	5d                   	pop    %rbp
ffffffff8b451335:	c3                   	ret
ffffffff8b451336:	90                   	nop
ffffffff8b451337:	90                   	nop
ffffffff8b451338:	90                   	nop
ffffffff8b451339:	90                   	nop
ffffffff8b45133a:	90                   	nop
ffffffff8b45133b:	90                   	nop
ffffffff8b45133c:	90                   	nop
ffffffff8b45133d:	90                   	nop
ffffffff8b45133e:	90                   	nop
ffffffff8b45133f:	90                   	nop

ffffffff8b451340 <frame_candidate_a91340>:
ffffffff8b451340:	55                   	push   %rbp
ffffffff8b451341:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451344:	5d                   	pop    %rbp
ffffffff8b451345:	c3                   	ret
ffffffff8b451346:	90                   	nop
ffffffff8b451347:	90                   	nop
ffffffff8b451348:	90                   	nop
ffffffff8b451349:	90                   	nop
ffffffff8b45134a:	90                   	nop
ffffffff8b45134b:	90                   	nop
ffffffff8b45134c:	90                   	nop
ffffffff8b45134d:	90                   	nop
ffffffff8b45134e:	90                   	nop
ffffffff8b45134f:	90                   	nop

ffffffff8b451350 <frame_candidate_a91350>:
ffffffff8b451350:	55                   	push   %rbp
ffffffff8b451351:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451354:	5d                   	pop    %rbp
ffffffff8b451355:	c3                   	ret
ffffffff8b451356:	90                   	nop
ffffffff8b451357:	90                   	nop
ffffffff8b451358:	90                   	nop
ffffffff8b451359:	90                   	nop
ffffffff8b45135a:	90                   	nop
ffffffff8b45135b:	90                   	nop
ffffffff8b45135c:	90                   	nop
ffffffff8b45135d:	90                   	nop
ffffffff8b45135e:	90                   	nop
ffffffff8b45135f:	90                   	nop

ffffffff8b451360 <frame_candidate_a91360>:
ffffffff8b451360:	55                   	push   %rbp
ffffffff8b451361:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451364:	5d                   	pop    %rbp
ffffffff8b451365:	c3                   	ret
ffffffff8b451366:	90                   	nop
ffffffff8b451367:	90                   	nop
ffffffff8b451368:	90                   	nop
ffffffff8b451369:	90                   	nop
ffffffff8b45136a:	90                   	nop
ffffffff8b45136b:	90                   	nop
ffffffff8b45136c:	90                   	nop
ffffffff8b45136d:	90                   	nop
ffffffff8b45136e:	90                   	nop
ffffffff8b45136f:	90                   	nop

ffffffff8b451370 <frame_candidate_a91370>:
ffffffff8b451370:	55                   	push   %rbp
ffffffff8b451371:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451374:	41 56                	push   %r14
ffffffff8b451376:	53                   	push   %rbx
ffffffff8b451377:	48 83 ec 60          	sub    $0x60,%rsp
ffffffff8b45137b:	48 8d 1d 8e af e8 02 	lea    0x2e8af8e(%rip),%rbx        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451382:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b451385:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8b451389:	4c 8b 35 f8 56 16 03 	mov    0x31656f8(%rip),%r14        # ffffffff8e5b6a88 <frame_candidate_a92d00+0x3163d88>
ffffffff8b451390:	4d 85 f6             	test   %r14,%r14
ffffffff8b451393:	74 73                	je     ffffffff8b451408 <frame_candidate_a91370+0x98>
ffffffff8b451395:	48 8d 7d 90          	lea    -0x70(%rbp),%rdi
ffffffff8b451399:	e8 22 f7 03 00       	call   ffffffff8b490ac0 <frame_candidate_a92d00+0x3ddc0>
ffffffff8b45139e:	c7 45 94 00 00 00 00 	movl   $0x0,-0x6c(%rbp)
ffffffff8b4513a5:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b4513a8:	41 8b 4e 04          	mov    0x4(%r14),%ecx
ffffffff8b4513ac:	41 8b 56 08          	mov    0x8(%r14),%edx
ffffffff8b4513b0:	ff c1                	inc    %ecx
ffffffff8b4513b2:	8d 72 01             	lea    0x1(%rdx),%esi
ffffffff8b4513b5:	83 f9 04             	cmp    $0x4,%ecx
ffffffff8b4513b8:	44 0f 42 c1          	cmovb  %ecx,%r8d
ffffffff8b4513bc:	83 fe 01             	cmp    $0x1,%esi
ffffffff8b4513bf:	83 d2 01             	adc    $0x1,%edx
ffffffff8b4513c2:	45 89 46 04          	mov    %r8d,0x4(%r14)
ffffffff8b4513c6:	49 6b c8 58          	imul   $0x58,%r8,%rcx
ffffffff8b4513ca:	41 89 56 08          	mov    %edx,0x8(%r14)
ffffffff8b4513ce:	4d 63 0e             	movslq (%r14),%r9
ffffffff8b4513d1:	4c 03 0d 88 56 16 03 	add    0x3165688(%rip),%r9        # ffffffff8e5b6a60 <frame_candidate_a92d00+0x3163d60>
ffffffff8b4513d8:	42 c7 44 09 14 00 00 	movl   $0x0,0x14(%rcx,%r9,1)
ffffffff8b4513df:	00 00 
ffffffff8b4513e1:	4a 8d 54 09 10       	lea    0x10(%rcx,%r9,1),%rdx
ffffffff8b4513e6:	85 c0                	test   %eax,%eax
ffffffff8b4513e8:	74 0f                	je     ffffffff8b4513f9 <frame_candidate_a91370+0x89>
ffffffff8b4513ea:	48 8d 75 90          	lea    -0x70(%rbp),%rsi
ffffffff8b4513ee:	b9 0b 00 00 00       	mov    $0xb,%ecx
ffffffff8b4513f3:	48 89 d7             	mov    %rdx,%rdi
ffffffff8b4513f6:	f3 48 a5             	rep movsq (%rsi),(%rdi)
ffffffff8b4513f9:	41 8b 4e 08          	mov    0x8(%r14),%ecx
ffffffff8b4513fd:	89 4a 04             	mov    %ecx,0x4(%rdx)
ffffffff8b451400:	45 89 41 08          	mov    %r8d,0x8(%r9)
ffffffff8b451404:	41 89 41 04          	mov    %eax,0x4(%r9)
ffffffff8b451408:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b45140b:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
ffffffff8b45140f:	75 09                	jne    ffffffff8b45141a <frame_candidate_a91370+0xaa>
ffffffff8b451411:	48 83 c4 60          	add    $0x60,%rsp
ffffffff8b451415:	5b                   	pop    %rbx
ffffffff8b451416:	41 5e                	pop    %r14
ffffffff8b451418:	5d                   	pop    %rbp
ffffffff8b451419:	c3                   	ret
ffffffff8b45141a:	e8 91 c2 c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b45141f:	0f 0b                	ud2
ffffffff8b451421:	90                   	nop
ffffffff8b451422:	90                   	nop
ffffffff8b451423:	90                   	nop
ffffffff8b451424:	90                   	nop
ffffffff8b451425:	90                   	nop
ffffffff8b451426:	90                   	nop
ffffffff8b451427:	90                   	nop
ffffffff8b451428:	90                   	nop
ffffffff8b451429:	90                   	nop
ffffffff8b45142a:	90                   	nop
ffffffff8b45142b:	90                   	nop
ffffffff8b45142c:	90                   	nop
ffffffff8b45142d:	90                   	nop
ffffffff8b45142e:	90                   	nop
ffffffff8b45142f:	90                   	nop

ffffffff8b451430 <frame_candidate_a91430>:
ffffffff8b451430:	55                   	push   %rbp
ffffffff8b451431:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451434:	41 57                	push   %r15
ffffffff8b451436:	41 56                	push   %r14
ffffffff8b451438:	41 55                	push   %r13
ffffffff8b45143a:	41 54                	push   %r12
ffffffff8b45143c:	53                   	push   %rbx
ffffffff8b45143d:	48 83 ec 68          	sub    $0x68,%rsp
ffffffff8b451441:	4c 8d 25 c8 ae e8 02 	lea    0x2e8aec8(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451448:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b45144c:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b451450:	f6 87 a2 00 00 00 01 	testb  $0x1,0xa2(%rdi)
ffffffff8b451457:	0f 84 ff 01 00 00    	je     ffffffff8b45165c <frame_candidate_a91430+0x22c>
ffffffff8b45145d:	48 8b 05 2c 56 16 03 	mov    0x316562c(%rip),%rax        # ffffffff8e5b6a90 <frame_candidate_a92d00+0x3163d90>
ffffffff8b451464:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b451467:	31 f6                	xor    %esi,%esi
ffffffff8b451469:	31 d2                	xor    %edx,%edx
ffffffff8b45146b:	31 c9                	xor    %ecx,%ecx
ffffffff8b45146d:	48 89 87 d8 00 00 00 	mov    %rax,0xd8(%rdi)
ffffffff8b451474:	48 8b 47 40          	mov    0x40(%rdi),%rax
ffffffff8b451478:	4c 8b 77 38          	mov    0x38(%rdi),%r14
ffffffff8b45147c:	48 8d 3d e5 55 16 03 	lea    0x31655e5(%rip),%rdi        # ffffffff8e5b6a68 <frame_candidate_a92d00+0x3163d68>
ffffffff8b451483:	4c 63 38             	movslq (%rax),%r15
ffffffff8b451486:	e8 95 a6 1b 00       	call   ffffffff8b60bb20 <frame_candidate_a92d00+0x1b8e20>
ffffffff8b45148b:	8b 05 07 56 16 03    	mov    0x3165607(%rip),%eax        # ffffffff8e5b6a98 <frame_candidate_a92d00+0x3163d98>
ffffffff8b451491:	48 8b 35 f8 55 16 03 	mov    0x31655f8(%rip),%rsi        # ffffffff8e5b6a90 <frame_candidate_a92d00+0x3163d90>
ffffffff8b451498:	49 c7 c5 ff ff ff ff 	mov    $0xffffffffffffffff,%r13
ffffffff8b45149f:	8d 48 0f             	lea    0xf(%rax),%ecx
ffffffff8b4514a2:	83 c0 1e             	add    $0x1e,%eax
ffffffff8b4514a5:	48 8b b6 88 00 00 00 	mov    0x88(%rsi),%rsi
ffffffff8b4514ac:	85 c9                	test   %ecx,%ecx
ffffffff8b4514ae:	0f 49 c1             	cmovns %ecx,%eax
ffffffff8b4514b1:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8b4514b4:	42 8d 0c 38          	lea    (%rax,%r15,1),%ecx
ffffffff8b4514b8:	48 c1 e6 0e          	shl    $0xe,%rsi
ffffffff8b4514bc:	48 63 d1             	movslq %ecx,%rdx
ffffffff8b4514bf:	48 39 d6             	cmp    %rdx,%rsi
ffffffff8b4514c2:	7e 23                	jle    ffffffff8b4514e7 <frame_candidate_a91430+0xb7>
ffffffff8b4514c4:	89 0d ce 55 16 03    	mov    %ecx,0x31655ce(%rip)        # ffffffff8e5b6a98 <frame_candidate_a92d00+0x3163d98>
ffffffff8b4514ca:	83 f8 ff             	cmp    $0xffffffff,%eax
ffffffff8b4514cd:	74 18                	je     ffffffff8b4514e7 <frame_candidate_a91430+0xb7>
ffffffff8b4514cf:	48 8b 35 8a 55 16 03 	mov    0x316558a(%rip),%rsi        # ffffffff8e5b6a60 <frame_candidate_a92d00+0x3163d60>
ffffffff8b4514d6:	4c 63 e8             	movslq %eax,%r13
ffffffff8b4514d9:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b4514dc:	4c 89 fa             	mov    %r15,%rdx
ffffffff8b4514df:	4c 01 ee             	add    %r13,%rsi
ffffffff8b4514e2:	e8 f9 86 7c ff       	call   ffffffff8ac19be0 <handler_640_body-0x837230>
ffffffff8b4514e7:	48 8d 3d 7a 55 16 03 	lea    0x316557a(%rip),%rdi        # ffffffff8e5b6a68 <frame_candidate_a92d00+0x3163d68>
ffffffff8b4514ee:	31 f6                	xor    %esi,%esi
ffffffff8b4514f0:	31 d2                	xor    %edx,%edx
ffffffff8b4514f2:	e8 b9 af 1b 00       	call   ffffffff8b60c4b0 <frame_candidate_a92d00+0x1b97b0>
ffffffff8b4514f7:	4c 89 ab d0 00 00 00 	mov    %r13,0xd0(%rbx)
ffffffff8b4514fe:	b8 ff 00 04 00       	mov    $0x400ff,%eax
ffffffff8b451503:	23 83 a0 00 00 00    	and    0xa0(%rbx),%eax
ffffffff8b451509:	3d 09 00 04 00       	cmp    $0x40009,%eax
ffffffff8b45150e:	0f 85 48 01 00 00    	jne    ffffffff8b45165c <frame_candidate_a91430+0x22c>
ffffffff8b451514:	48 8d 35 65 ab 16 02 	lea    0x216ab65(%rip),%rsi        # ffffffff8d5bc080 <frame_candidate_a92d00+0x2169380>
ffffffff8b45151b:	bf 0c 00 00 00       	mov    $0xc,%edi
ffffffff8b451520:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8b451525:	c7 85 74 ff ff ff 01 	movl   $0x1,-0x8c(%rbp)
ffffffff8b45152c:	00 00 00 
ffffffff8b45152f:	e8 1c 76 17 00       	call   ffffffff8b5c8b50 <frame_candidate_a92d00+0x175e50>
ffffffff8b451534:	48 8d 3d 2d 55 16 03 	lea    0x316552d(%rip),%rdi        # ffffffff8e5b6a68 <frame_candidate_a92d00+0x3163d68>
ffffffff8b45153b:	49 89 c6             	mov    %rax,%r14
ffffffff8b45153e:	31 f6                	xor    %esi,%esi
ffffffff8b451540:	31 d2                	xor    %edx,%edx
ffffffff8b451542:	31 c9                	xor    %ecx,%ecx
ffffffff8b451544:	e8 d7 a5 1b 00       	call   ffffffff8b60bb20 <frame_candidate_a92d00+0x1b8e20>
ffffffff8b451549:	8b 05 49 55 16 03    	mov    0x3165549(%rip),%eax        # ffffffff8e5b6a98 <frame_candidate_a92d00+0x3163d98>
ffffffff8b45154f:	48 8b 35 3a 55 16 03 	mov    0x316553a(%rip),%rsi        # ffffffff8e5b6a90 <frame_candidate_a92d00+0x3163d90>
ffffffff8b451556:	41 bf ff ff ff ff    	mov    $0xffffffff,%r15d
ffffffff8b45155c:	8d 48 0f             	lea    0xf(%rax),%ecx
ffffffff8b45155f:	83 c0 1e             	add    $0x1e,%eax
ffffffff8b451562:	48 8b b6 88 00 00 00 	mov    0x88(%rsi),%rsi
ffffffff8b451569:	85 c9                	test   %ecx,%ecx
ffffffff8b45156b:	0f 49 c1             	cmovns %ecx,%eax
ffffffff8b45156e:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8b451571:	8d 88 70 01 00 00    	lea    0x170(%rax),%ecx
ffffffff8b451577:	48 c1 e6 0e          	shl    $0xe,%rsi
ffffffff8b45157b:	48 63 d1             	movslq %ecx,%rdx
ffffffff8b45157e:	48 39 d6             	cmp    %rdx,%rsi
ffffffff8b451581:	7e 09                	jle    ffffffff8b45158c <frame_candidate_a91430+0x15c>
ffffffff8b451583:	41 89 c7             	mov    %eax,%r15d
ffffffff8b451586:	89 0d 0c 55 16 03    	mov    %ecx,0x316550c(%rip)        # ffffffff8e5b6a98 <frame_candidate_a92d00+0x3163d98>
ffffffff8b45158c:	48 8d 3d d5 54 16 03 	lea    0x31654d5(%rip),%rdi        # ffffffff8e5b6a68 <frame_candidate_a92d00+0x3163d68>
ffffffff8b451593:	31 f6                	xor    %esi,%esi
ffffffff8b451595:	31 d2                	xor    %edx,%edx
ffffffff8b451597:	e8 14 af 1b 00       	call   ffffffff8b60c4b0 <frame_candidate_a92d00+0x1b97b0>
ffffffff8b45159c:	48 8b 35 bd 54 16 03 	mov    0x31654bd(%rip),%rsi        # ffffffff8e5b6a60 <frame_candidate_a92d00+0x3163d60>
ffffffff8b4515a3:	4d 63 ff             	movslq %r15d,%r15
ffffffff8b4515a6:	48 8d bd 74 ff ff ff 	lea    -0x8c(%rbp),%rdi
ffffffff8b4515ad:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b4515b2:	4c 01 fe             	add    %r15,%rsi
ffffffff8b4515b5:	e8 26 86 7c ff       	call   ffffffff8ac19be0 <handler_640_body-0x837230>
ffffffff8b4515ba:	4c 8b 2d c7 54 16 03 	mov    0x31654c7(%rip),%r13        # ffffffff8e5b6a88 <frame_candidate_a92d00+0x3163d88>
ffffffff8b4515c1:	45 89 3e             	mov    %r15d,(%r14)
ffffffff8b4515c4:	4d 85 ed             	test   %r13,%r13
ffffffff8b4515c7:	0f 84 81 00 00 00    	je     ffffffff8b45164e <frame_candidate_a91430+0x21e>
ffffffff8b4515cd:	48 8d bd 78 ff ff ff 	lea    -0x88(%rbp),%rdi
ffffffff8b4515d4:	e8 e7 f4 03 00       	call   ffffffff8b490ac0 <frame_candidate_a92d00+0x3ddc0>
ffffffff8b4515d9:	c7 85 7c ff ff ff 00 	movl   $0x0,-0x84(%rbp)
ffffffff8b4515e0:	00 00 00 
ffffffff8b4515e3:	ba 00 00 00 00       	mov    $0x0,%edx
ffffffff8b4515e8:	45 8b 45 04          	mov    0x4(%r13),%r8d
ffffffff8b4515ec:	41 8b 4d 08          	mov    0x8(%r13),%ecx
ffffffff8b4515f0:	41 ff c0             	inc    %r8d
ffffffff8b4515f3:	8d 71 01             	lea    0x1(%rcx),%esi
ffffffff8b4515f6:	41 83 f8 04          	cmp    $0x4,%r8d
ffffffff8b4515fa:	44 0f 43 c2          	cmovae %edx,%r8d
ffffffff8b4515fe:	83 fe 01             	cmp    $0x1,%esi
ffffffff8b451601:	83 d1 01             	adc    $0x1,%ecx
ffffffff8b451604:	45 89 45 04          	mov    %r8d,0x4(%r13)
ffffffff8b451608:	41 89 4d 08          	mov    %ecx,0x8(%r13)
ffffffff8b45160c:	49 6b c8 58          	imul   $0x58,%r8,%rcx
ffffffff8b451610:	4d 63 4d 00          	movslq 0x0(%r13),%r9
ffffffff8b451614:	4c 03 0d 45 54 16 03 	add    0x3165445(%rip),%r9        # ffffffff8e5b6a60 <frame_candidate_a92d00+0x3163d60>
ffffffff8b45161b:	42 c7 44 09 14 00 00 	movl   $0x0,0x14(%rcx,%r9,1)
ffffffff8b451622:	00 00 
ffffffff8b451624:	4a 8d 54 09 10       	lea    0x10(%rcx,%r9,1),%rdx
ffffffff8b451629:	85 c0                	test   %eax,%eax
ffffffff8b45162b:	74 12                	je     ffffffff8b45163f <frame_candidate_a91430+0x20f>
ffffffff8b45162d:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8b451634:	b9 0b 00 00 00       	mov    $0xb,%ecx
ffffffff8b451639:	48 89 d7             	mov    %rdx,%rdi
ffffffff8b45163c:	f3 48 a5             	rep movsq (%rsi),(%rdi)
ffffffff8b45163f:	41 8b 4d 08          	mov    0x8(%r13),%ecx
ffffffff8b451643:	89 4a 04             	mov    %ecx,0x4(%rdx)
ffffffff8b451646:	45 89 41 08          	mov    %r8d,0x8(%r9)
ffffffff8b45164a:	41 89 41 04          	mov    %eax,0x4(%r9)
ffffffff8b45164e:	4c 89 35 33 54 16 03 	mov    %r14,0x3165433(%rip)        # ffffffff8e5b6a88 <frame_candidate_a92d00+0x3163d88>
ffffffff8b451655:	4c 89 bb c8 00 00 00 	mov    %r15,0xc8(%rbx)
ffffffff8b45165c:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b451660:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b451664:	75 0f                	jne    ffffffff8b451675 <frame_candidate_a91430+0x245>
ffffffff8b451666:	48 83 c4 68          	add    $0x68,%rsp
ffffffff8b45166a:	5b                   	pop    %rbx
ffffffff8b45166b:	41 5c                	pop    %r12
ffffffff8b45166d:	41 5d                	pop    %r13
ffffffff8b45166f:	41 5e                	pop    %r14
ffffffff8b451671:	41 5f                	pop    %r15
ffffffff8b451673:	5d                   	pop    %rbp
ffffffff8b451674:	c3                   	ret
ffffffff8b451675:	e8 36 c0 c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b45167a:	0f 0b                	ud2
ffffffff8b45167c:	90                   	nop
ffffffff8b45167d:	90                   	nop
ffffffff8b45167e:	90                   	nop
ffffffff8b45167f:	90                   	nop

ffffffff8b451680 <frame_candidate_a91680>:
ffffffff8b451680:	55                   	push   %rbp
ffffffff8b451681:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451684:	41 56                	push   %r14
ffffffff8b451686:	53                   	push   %rbx
ffffffff8b451687:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8b45168b:	4c 8d 35 7e ac e8 02 	lea    0x2e8ac7e(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451692:	48 8d 3d cf 53 16 03 	lea    0x31653cf(%rip),%rdi        # ffffffff8e5b6a68 <frame_candidate_a92d00+0x3163d68>
ffffffff8b451699:	48 8d 35 be bb 7e 00 	lea    0x7ebbbe(%rip),%rsi        # ffffffff8bc3d25e <frame_candidate_a92d00+0x7ea55e>
ffffffff8b4516a0:	31 d2                	xor    %edx,%edx
ffffffff8b4516a2:	49 8b 06             	mov    (%r14),%rax
ffffffff8b4516a5:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8b4516a9:	e8 e2 9b 1b 00       	call   ffffffff8b60b290 <frame_candidate_a92d00+0x1b8590>
ffffffff8b4516ae:	ba 00 40 00 00       	mov    $0x4000,%edx
ffffffff8b4516b3:	bf 04 00 00 00       	mov    $0x4,%edi
ffffffff8b4516b8:	b9 07 00 00 00       	mov    $0x7,%ecx
ffffffff8b4516bd:	31 f6                	xor    %esi,%esi
ffffffff8b4516bf:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b4516c2:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b4516c5:	e8 f6 c2 9c ff       	call   ffffffff8ae1d9c0 <handler_640_body-0x633450>
ffffffff8b4516ca:	48 8d 78 18          	lea    0x18(%rax),%rdi
ffffffff8b4516ce:	48 89 05 bb 53 16 03 	mov    %rax,0x31653bb(%rip)        # ffffffff8e5b6a90 <frame_candidate_a92d00+0x3163d90>
ffffffff8b4516d5:	31 f6                	xor    %esi,%esi
ffffffff8b4516d7:	31 d2                	xor    %edx,%edx
ffffffff8b4516d9:	e8 c2 2f d4 ff       	call   ffffffff8b1946a0 <handler_640_body-0x2bc770>
ffffffff8b4516de:	48 8b 3d ab 53 16 03 	mov    0x31653ab(%rip),%rdi        # ffffffff8e5b6a90 <frame_candidate_a92d00+0x3163d90>
ffffffff8b4516e5:	ba 40 02 00 00       	mov    $0x240,%edx
ffffffff8b4516ea:	31 f6                	xor    %esi,%esi
ffffffff8b4516ec:	e8 3f bb 0f 00       	call   ffffffff8b54d230 <frame_candidate_a92d00+0xfa530>
ffffffff8b4516f1:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b4516f5:	c7 40 6c ff ff ff ff 	movl   $0xffffffff,0x6c(%rax)
ffffffff8b4516fc:	31 f6                	xor    %esi,%esi
ffffffff8b4516fe:	31 d2                	xor    %edx,%edx
ffffffff8b451700:	48 8b 3d 89 53 16 03 	mov    0x3165389(%rip),%rdi        # ffffffff8e5b6a90 <frame_candidate_a92d00+0x3163d90>
ffffffff8b451707:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8b45170b:	e8 a0 37 d4 ff       	call   ffffffff8b194eb0 <handler_640_body-0x2bbf60>
ffffffff8b451710:	bf 00 40 00 00       	mov    $0x4000,%edi
ffffffff8b451715:	e8 96 1c a7 ff       	call   ffffffff8aec33b0 <handler_640_body-0x58da60>
ffffffff8b45171a:	48 8d 75 e0          	lea    -0x20(%rbp),%rsi
ffffffff8b45171e:	48 89 c7             	mov    %rax,%rdi
ffffffff8b451721:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8b451726:	48 89 c3             	mov    %rax,%rbx
ffffffff8b451729:	e8 52 d5 e4 ff       	call   ffffffff8b29ec80 <handler_640_body-0x1b2190>
ffffffff8b45172e:	48 89 1d 2b 53 16 03 	mov    %rbx,0x316532b(%rip)        # ffffffff8e5b6a60 <frame_candidate_a92d00+0x3163d60>
ffffffff8b451735:	49 8b 06             	mov    (%r14),%rax
ffffffff8b451738:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
ffffffff8b45173c:	75 09                	jne    ffffffff8b451747 <frame_candidate_a91680+0xc7>
ffffffff8b45173e:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b451742:	5b                   	pop    %rbx
ffffffff8b451743:	41 5e                	pop    %r14
ffffffff8b451745:	5d                   	pop    %rbp
ffffffff8b451746:	c3                   	ret
ffffffff8b451747:	e8 64 bf c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b45174c:	0f 0b                	ud2
ffffffff8b45174e:	90                   	nop
ffffffff8b45174f:	90                   	nop

ffffffff8b451750 <frame_candidate_a91750>:
ffffffff8b451750:	55                   	push   %rbp
ffffffff8b451751:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451754:	41 57                	push   %r15
ffffffff8b451756:	41 56                	push   %r14
ffffffff8b451758:	41 55                	push   %r13
ffffffff8b45175a:	41 54                	push   %r12
ffffffff8b45175c:	53                   	push   %rbx
ffffffff8b45175d:	50                   	push   %rax
ffffffff8b45175e:	41 89 fe             	mov    %edi,%r14d
ffffffff8b451761:	e8 6a ea 20 00       	call   ffffffff8b6601d0 <frame_candidate_a92d00+0x20d4d0>
ffffffff8b451766:	48 8d 3d 3b 40 84 00 	lea    0x84403b(%rip),%rdi        # ffffffff8bc957a8 <frame_candidate_a92d00+0x842aa8>
ffffffff8b45176d:	e8 6e cb ca ff       	call   ffffffff8b0fe2e0 <handler_640_body-0x352b30>
ffffffff8b451772:	48 85 c0             	test   %rax,%rax
ffffffff8b451775:	0f 84 bd 00 00 00    	je     ffffffff8b451838 <frame_candidate_a91750+0xe8>
ffffffff8b45177b:	48 89 c3             	mov    %rax,%rbx
ffffffff8b45177e:	8b 40 0c             	mov    0xc(%rax),%eax
ffffffff8b451781:	8d 48 01             	lea    0x1(%rax),%ecx
ffffffff8b451784:	89 4b 0c             	mov    %ecx,0xc(%rbx)
ffffffff8b451787:	4c 8b 63 40          	mov    0x40(%rbx),%r12
ffffffff8b45178b:	4d 85 e4             	test   %r12,%r12
ffffffff8b45178e:	74 79                	je     ffffffff8b451809 <frame_candidate_a91750+0xb9>
ffffffff8b451790:	4c 8d 7b 28          	lea    0x28(%rbx),%r15
ffffffff8b451794:	eb 2c                	jmp    ffffffff8b4517c2 <frame_candidate_a91750+0x72>
ffffffff8b451796:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b45179d:	00 00 00 
ffffffff8b4517a0:	49 8b 7c 24 18       	mov    0x18(%r12),%rdi
ffffffff8b4517a5:	44 89 f6             	mov    %r14d,%esi
ffffffff8b4517a8:	41 ff d5             	call   *%r13
ffffffff8b4517ab:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b4517ae:	31 f6                	xor    %esi,%esi
ffffffff8b4517b0:	31 d2                	xor    %edx,%edx
ffffffff8b4517b2:	31 c9                	xor    %ecx,%ecx
ffffffff8b4517b4:	e8 47 52 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b4517b9:	4d 8b 24 24          	mov    (%r12),%r12
ffffffff8b4517bd:	4d 85 e4             	test   %r12,%r12
ffffffff8b4517c0:	74 42                	je     ffffffff8b451804 <frame_candidate_a91750+0xb4>
ffffffff8b4517c2:	41 83 7c 24 10 ff    	cmpl   $0xffffffff,0x10(%r12)
ffffffff8b4517c8:	74 ef                	je     ffffffff8b4517b9 <frame_candidate_a91750+0x69>
ffffffff8b4517ca:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b4517cd:	31 f6                	xor    %esi,%esi
ffffffff8b4517cf:	31 d2                	xor    %edx,%edx
ffffffff8b4517d1:	31 c9                	xor    %ecx,%ecx
ffffffff8b4517d3:	e8 c8 57 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b4517d8:	4d 8b 6c 24 28       	mov    0x28(%r12),%r13
ffffffff8b4517dd:	48 8d 05 84 97 7d ff 	lea    -0x82687c(%rip),%rax        # ffffffff8ac2af68 <handler_640_body-0x825ea8>
ffffffff8b4517e4:	4c 29 e8             	sub    %r13,%rax
ffffffff8b4517e7:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b4517eb:	48 3d 0b 01 00 00    	cmp    $0x10b,%rax
ffffffff8b4517f1:	76 ad                	jbe    ffffffff8b4517a0 <frame_candidate_a91750+0x50>
ffffffff8b4517f3:	48 8d 3d 96 3e df 01 	lea    0x1df3e96(%rip),%rdi        # ffffffff8d245690 <frame_candidate_a92d00+0x1df2990>
ffffffff8b4517fa:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b4517fd:	e8 be e0 9b ff       	call   ffffffff8ae0f8c0 <handler_640_body-0x641550>
ffffffff8b451802:	eb 9c                	jmp    ffffffff8b4517a0 <frame_candidate_a91750+0x50>
ffffffff8b451804:	8b 43 0c             	mov    0xc(%rbx),%eax
ffffffff8b451807:	ff c8                	dec    %eax
ffffffff8b451809:	89 43 0c             	mov    %eax,0xc(%rbx)
ffffffff8b45180c:	85 c0                	test   %eax,%eax
ffffffff8b45180e:	75 08                	jne    ffffffff8b451818 <frame_candidate_a91750+0xc8>
ffffffff8b451810:	48 89 df             	mov    %rbx,%rdi
ffffffff8b451813:	e8 58 cb ca ff       	call   ffffffff8b0fe370 <handler_640_body-0x352aa0>
ffffffff8b451818:	48 83 c3 28          	add    $0x28,%rbx
ffffffff8b45181c:	31 f6                	xor    %esi,%esi
ffffffff8b45181e:	31 d2                	xor    %edx,%edx
ffffffff8b451820:	31 c9                	xor    %ecx,%ecx
ffffffff8b451822:	48 89 df             	mov    %rbx,%rdi
ffffffff8b451825:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b451829:	5b                   	pop    %rbx
ffffffff8b45182a:	41 5c                	pop    %r12
ffffffff8b45182c:	41 5d                	pop    %r13
ffffffff8b45182e:	41 5e                	pop    %r14
ffffffff8b451830:	41 5f                	pop    %r15
ffffffff8b451832:	5d                   	pop    %rbp
ffffffff8b451833:	e9 68 57 a3 ff       	jmp    ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b451838:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b45183c:	5b                   	pop    %rbx
ffffffff8b45183d:	41 5c                	pop    %r12
ffffffff8b45183f:	41 5d                	pop    %r13
ffffffff8b451841:	41 5e                	pop    %r14
ffffffff8b451843:	41 5f                	pop    %r15
ffffffff8b451845:	5d                   	pop    %rbp
ffffffff8b451846:	c3                   	ret
ffffffff8b451847:	90                   	nop
ffffffff8b451848:	90                   	nop
ffffffff8b451849:	90                   	nop
ffffffff8b45184a:	90                   	nop
ffffffff8b45184b:	90                   	nop
ffffffff8b45184c:	90                   	nop
ffffffff8b45184d:	90                   	nop
ffffffff8b45184e:	90                   	nop
ffffffff8b45184f:	90                   	nop

ffffffff8b451850 <frame_candidate_a91850>:
ffffffff8b451850:	55                   	push   %rbp
ffffffff8b451851:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451854:	41 57                	push   %r15
ffffffff8b451856:	41 56                	push   %r14
ffffffff8b451858:	41 55                	push   %r13
ffffffff8b45185a:	41 54                	push   %r12
ffffffff8b45185c:	53                   	push   %rbx
ffffffff8b45185d:	48 83 ec 68          	sub    $0x68,%rsp
ffffffff8b451861:	4c 8d 25 a8 aa e8 02 	lea    0x2e8aaa8(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451868:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b45186b:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b45186f:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b451873:	44 8b b7 bc 00 00 00 	mov    0xbc(%rdi),%r14d
ffffffff8b45187a:	e8 41 db e2 ff       	call   ffffffff8b27f3c0 <handler_640_body-0x1d1a50>
ffffffff8b45187f:	48 8d 3d 81 0e 8c 00 	lea    0x8c0e81(%rip),%rdi        # ffffffff8bd12707 <frame_candidate_a92d00+0x8bfa07>
ffffffff8b451886:	e8 55 ca ca ff       	call   ffffffff8b0fe2e0 <handler_640_body-0x352b30>
ffffffff8b45188b:	48 85 c0             	test   %rax,%rax
ffffffff8b45188e:	0f 84 c1 00 00 00    	je     ffffffff8b451955 <frame_candidate_a91850+0x105>
ffffffff8b451894:	49 89 c7             	mov    %rax,%r15
ffffffff8b451897:	8b 40 0c             	mov    0xc(%rax),%eax
ffffffff8b45189a:	48 89 9d 78 ff ff ff 	mov    %rbx,-0x88(%rbp)
ffffffff8b4518a1:	8d 48 01             	lea    0x1(%rax),%ecx
ffffffff8b4518a4:	41 89 4f 0c          	mov    %ecx,0xc(%r15)
ffffffff8b4518a8:	49 8b 5f 40          	mov    0x40(%r15),%rbx
ffffffff8b4518ac:	48 85 db             	test   %rbx,%rbx
ffffffff8b4518af:	74 7b                	je     ffffffff8b45192c <frame_candidate_a91850+0xdc>
ffffffff8b4518b1:	4d 8d 67 28          	lea    0x28(%r15),%r12
ffffffff8b4518b5:	eb 29                	jmp    ffffffff8b4518e0 <frame_candidate_a91850+0x90>
ffffffff8b4518b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b4518be:	00 00 
ffffffff8b4518c0:	48 8b 7b 18          	mov    0x18(%rbx),%rdi
ffffffff8b4518c4:	44 89 f6             	mov    %r14d,%esi
ffffffff8b4518c7:	41 ff d5             	call   *%r13
ffffffff8b4518ca:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b4518cd:	31 f6                	xor    %esi,%esi
ffffffff8b4518cf:	31 d2                	xor    %edx,%edx
ffffffff8b4518d1:	31 c9                	xor    %ecx,%ecx
ffffffff8b4518d3:	e8 28 51 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b4518d8:	48 8b 1b             	mov    (%rbx),%rbx
ffffffff8b4518db:	48 85 db             	test   %rbx,%rbx
ffffffff8b4518de:	74 3f                	je     ffffffff8b45191f <frame_candidate_a91850+0xcf>
ffffffff8b4518e0:	83 7b 10 ff          	cmpl   $0xffffffff,0x10(%rbx)
ffffffff8b4518e4:	74 f2                	je     ffffffff8b4518d8 <frame_candidate_a91850+0x88>
ffffffff8b4518e6:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b4518e9:	31 f6                	xor    %esi,%esi
ffffffff8b4518eb:	31 d2                	xor    %edx,%edx
ffffffff8b4518ed:	31 c9                	xor    %ecx,%ecx
ffffffff8b4518ef:	e8 ac 56 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b4518f4:	4c 8b 6b 28          	mov    0x28(%rbx),%r13
ffffffff8b4518f8:	48 8d 05 69 96 7d ff 	lea    -0x826997(%rip),%rax        # ffffffff8ac2af68 <handler_640_body-0x825ea8>
ffffffff8b4518ff:	4c 29 e8             	sub    %r13,%rax
ffffffff8b451902:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b451906:	48 3d 0b 01 00 00    	cmp    $0x10b,%rax
ffffffff8b45190c:	76 b2                	jbe    ffffffff8b4518c0 <frame_candidate_a91850+0x70>
ffffffff8b45190e:	48 8d 3d cb 3d df 01 	lea    0x1df3dcb(%rip),%rdi        # ffffffff8d2456e0 <frame_candidate_a92d00+0x1df29e0>
ffffffff8b451915:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b451918:	e8 a3 df 9b ff       	call   ffffffff8ae0f8c0 <handler_640_body-0x641550>
ffffffff8b45191d:	eb a1                	jmp    ffffffff8b4518c0 <frame_candidate_a91850+0x70>
ffffffff8b45191f:	41 8b 47 0c          	mov    0xc(%r15),%eax
ffffffff8b451923:	4c 8d 25 e6 a9 e8 02 	lea    0x2e8a9e6(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b45192a:	ff c8                	dec    %eax
ffffffff8b45192c:	41 89 47 0c          	mov    %eax,0xc(%r15)
ffffffff8b451930:	85 c0                	test   %eax,%eax
ffffffff8b451932:	75 08                	jne    ffffffff8b45193c <frame_candidate_a91850+0xec>
ffffffff8b451934:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b451937:	e8 34 ca ca ff       	call   ffffffff8b0fe370 <handler_640_body-0x352aa0>
ffffffff8b45193c:	49 83 c7 28          	add    $0x28,%r15
ffffffff8b451940:	31 f6                	xor    %esi,%esi
ffffffff8b451942:	31 d2                	xor    %edx,%edx
ffffffff8b451944:	31 c9                	xor    %ecx,%ecx
ffffffff8b451946:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b451949:	e8 52 56 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b45194e:	48 8b 9d 78 ff ff ff 	mov    -0x88(%rbp),%rbx
ffffffff8b451955:	44 89 f7             	mov    %r14d,%edi
ffffffff8b451958:	e8 a3 e7 20 00       	call   ffffffff8b660100 <frame_candidate_a92d00+0x20d400>
ffffffff8b45195d:	48 8d 7d 80          	lea    -0x80(%rbp),%rdi
ffffffff8b451961:	be 50 00 00 00       	mov    $0x50,%esi
ffffffff8b451966:	e8 85 76 7c ff       	call   ffffffff8ac18ff0 <handler_640_body-0x837e20>
ffffffff8b45196b:	4c 8d b3 48 01 00 00 	lea    0x148(%rbx),%r14
ffffffff8b451972:	c7 45 a0 ff ff ff ff 	movl   $0xffffffff,-0x60(%rbp)
ffffffff8b451979:	31 f6                	xor    %esi,%esi
ffffffff8b45197b:	31 d2                	xor    %edx,%edx
ffffffff8b45197d:	31 c9                	xor    %ecx,%ecx
ffffffff8b45197f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b451982:	e8 79 50 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b451987:	48 8b 83 68 05 00 00 	mov    0x568(%rbx),%rax
ffffffff8b45198e:	48 85 c0             	test   %rax,%rax
ffffffff8b451991:	74 54                	je     ffffffff8b4519e7 <frame_candidate_a91850+0x197>
ffffffff8b451993:	8b 88 00 01 00 00    	mov    0x100(%rax),%ecx
ffffffff8b451999:	89 4d a0             	mov    %ecx,-0x60(%rbp)
ffffffff8b45199c:	8b 88 04 01 00 00    	mov    0x104(%rax),%ecx
ffffffff8b4519a2:	89 4d a4             	mov    %ecx,-0x5c(%rbp)
ffffffff8b4519a5:	48 8b 88 50 01 00 00 	mov    0x150(%rax),%rcx
ffffffff8b4519ac:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
ffffffff8b4519b0:	8b 88 08 01 00 00    	mov    0x108(%rax),%ecx
ffffffff8b4519b6:	89 4d b0             	mov    %ecx,-0x50(%rbp)
ffffffff8b4519b9:	8b 88 0c 01 00 00    	mov    0x10c(%rax),%ecx
ffffffff8b4519bf:	89 4d b4             	mov    %ecx,-0x4c(%rbp)
ffffffff8b4519c2:	8b 8b bc 00 00 00    	mov    0xbc(%rbx),%ecx
ffffffff8b4519c8:	89 4d c0             	mov    %ecx,-0x40(%rbp)
ffffffff8b4519cb:	8b 88 8c 00 00 00    	mov    0x8c(%rax),%ecx
ffffffff8b4519d1:	89 4d c4             	mov    %ecx,-0x3c(%rbp)
ffffffff8b4519d4:	8b 80 e8 00 00 00    	mov    0xe8(%rax),%eax
ffffffff8b4519da:	89 45 bc             	mov    %eax,-0x44(%rbp)
ffffffff8b4519dd:	48 c7 45 c8 ff ff ff 	movq   $0xffffffffffffffff,-0x38(%rbp)
ffffffff8b4519e4:	ff 
ffffffff8b4519e5:	eb 07                	jmp    ffffffff8b4519ee <frame_candidate_a91850+0x19e>
ffffffff8b4519e7:	c7 45 a0 07 00 00 00 	movl   $0x7,-0x60(%rbp)
ffffffff8b4519ee:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b4519f1:	31 f6                	xor    %esi,%esi
ffffffff8b4519f3:	31 d2                	xor    %edx,%edx
ffffffff8b4519f5:	31 c9                	xor    %ecx,%ecx
ffffffff8b4519f7:	e8 a4 55 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b4519fc:	83 7d a0 00          	cmpl   $0x0,-0x60(%rbp)
ffffffff8b451a00:	7e 2e                	jle    ffffffff8b451a30 <frame_candidate_a91850+0x1e0>
ffffffff8b451a02:	48 8d 7d 80          	lea    -0x80(%rbp),%rdi
ffffffff8b451a06:	be 50 00 00 00       	mov    $0x50,%esi
ffffffff8b451a0b:	48 c7 45 80 16 00 00 	movq   $0x16,-0x80(%rbp)
ffffffff8b451a12:	00 
ffffffff8b451a13:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8b451a1a:	00 
ffffffff8b451a1b:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8b451a22:	00 
ffffffff8b451a23:	48 c7 45 98 30 00 00 	movq   $0x30,-0x68(%rbp)
ffffffff8b451a2a:	00 
ffffffff8b451a2b:	e8 60 90 20 00       	call   ffffffff8b65aa90 <frame_candidate_a92d00+0x207d90>
ffffffff8b451a30:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b451a34:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b451a38:	75 0f                	jne    ffffffff8b451a49 <frame_candidate_a91850+0x1f9>
ffffffff8b451a3a:	48 83 c4 68          	add    $0x68,%rsp
ffffffff8b451a3e:	5b                   	pop    %rbx
ffffffff8b451a3f:	41 5c                	pop    %r12
ffffffff8b451a41:	41 5d                	pop    %r13
ffffffff8b451a43:	41 5e                	pop    %r14
ffffffff8b451a45:	41 5f                	pop    %r15
ffffffff8b451a47:	5d                   	pop    %rbp
ffffffff8b451a48:	c3                   	ret
ffffffff8b451a49:	e8 62 bc c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b451a4e:	0f 0b                	ud2

ffffffff8b451a50 <frame_candidate_a91a50>:
ffffffff8b451a50:	55                   	push   %rbp
ffffffff8b451a51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451a54:	41 57                	push   %r15
ffffffff8b451a56:	41 56                	push   %r14
ffffffff8b451a58:	41 55                	push   %r13
ffffffff8b451a5a:	41 54                	push   %r12
ffffffff8b451a5c:	53                   	push   %rbx
ffffffff8b451a5d:	50                   	push   %rax
ffffffff8b451a5e:	48 8d 9f 48 01 00 00 	lea    0x148(%rdi),%rbx
ffffffff8b451a65:	49 89 fe             	mov    %rdi,%r14
ffffffff8b451a68:	4c 8d bf 30 01 00 00 	lea    0x130(%rdi),%r15
ffffffff8b451a6f:	31 f6                	xor    %esi,%esi
ffffffff8b451a71:	31 d2                	xor    %edx,%edx
ffffffff8b451a73:	31 c9                	xor    %ecx,%ecx
ffffffff8b451a75:	48 89 df             	mov    %rbx,%rdi
ffffffff8b451a78:	e8 83 4f a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b451a7d:	4d 8d a6 60 05 00 00 	lea    0x560(%r14),%r12
ffffffff8b451a84:	4c 8d 2d 78 59 8c 00 	lea    0x8c5978(%rip),%r13        # ffffffff8bd17403 <frame_candidate_a92d00+0x8c4703>
ffffffff8b451a8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8b451a90:	49 81 3c 24 ff ff ff 	cmpq   $0x7fffffff,(%r12)
ffffffff8b451a97:	7f 
ffffffff8b451a98:	76 3a                	jbe    ffffffff8b451ad4 <frame_candidate_a91a50+0x84>
ffffffff8b451a9a:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b451a9d:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b451aa0:	ba 64 00 00 00       	mov    $0x64,%edx
ffffffff8b451aa5:	4c 89 e9             	mov    %r13,%rcx
ffffffff8b451aa8:	c7 04 24 00 01 00 00 	movl   $0x100,(%rsp)
ffffffff8b451aaf:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b451ab2:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b451ab5:	e8 a6 47 17 00       	call   ffffffff8b5c6260 <frame_candidate_a92d00+0x173560>
ffffffff8b451aba:	49 83 be 68 05 00 00 	cmpq   $0x0,0x568(%r14)
ffffffff8b451ac1:	00 
ffffffff8b451ac2:	75 cc                	jne    ffffffff8b451a90 <frame_candidate_a91a50+0x40>
ffffffff8b451ac4:	48 8d 3d b3 da 83 00 	lea    0x83dab3(%rip),%rdi        # ffffffff8bc8f57e <frame_candidate_a92d00+0x83c87e>
ffffffff8b451acb:	31 c0                	xor    %eax,%eax
ffffffff8b451acd:	e8 3e b9 7c ff       	call   ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b451ad2:	eb 3f                	jmp    ffffffff8b451b13 <frame_candidate_a91a50+0xc3>
ffffffff8b451ad4:	4d 8b b6 68 05 00 00 	mov    0x568(%r14),%r14
ffffffff8b451adb:	4d 85 f6             	test   %r14,%r14
ffffffff8b451ade:	74 33                	je     ffffffff8b451b13 <frame_candidate_a91a50+0xc3>
ffffffff8b451ae0:	41 83 be 00 01 00 00 	cmpl   $0x7,0x100(%r14)
ffffffff8b451ae7:	07 
ffffffff8b451ae8:	74 0b                	je     ffffffff8b451af5 <frame_candidate_a91a50+0xa5>
ffffffff8b451aea:	41 c7 86 00 01 00 00 	movl   $0x4,0x100(%r14)
ffffffff8b451af1:	04 00 00 00 
ffffffff8b451af5:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b451af8:	e8 13 4e 17 00       	call   ffffffff8b5c6910 <frame_candidate_a92d00+0x173c10>
ffffffff8b451afd:	48 8b 3d 9c 4f 16 03 	mov    0x3164f9c(%rip),%rdi        # ffffffff8e5b6aa0 <frame_candidate_a92d00+0x3163da0>
ffffffff8b451b04:	49 81 c6 30 01 00 00 	add    $0x130,%r14
ffffffff8b451b0b:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b451b0e:	e8 9d 8e a5 ff       	call   ffffffff8aeaa9b0 <handler_640_body-0x5a6460>
ffffffff8b451b13:	48 89 df             	mov    %rbx,%rdi
ffffffff8b451b16:	31 f6                	xor    %esi,%esi
ffffffff8b451b18:	31 d2                	xor    %edx,%edx
ffffffff8b451b1a:	31 c9                	xor    %ecx,%ecx
ffffffff8b451b1c:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b451b20:	5b                   	pop    %rbx
ffffffff8b451b21:	41 5c                	pop    %r12
ffffffff8b451b23:	41 5d                	pop    %r13
ffffffff8b451b25:	41 5e                	pop    %r14
ffffffff8b451b27:	41 5f                	pop    %r15
ffffffff8b451b29:	5d                   	pop    %rbp
ffffffff8b451b2a:	e9 71 54 a3 ff       	jmp    ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b451b2f:	90                   	nop
ffffffff8b451b30:	48 8b b7 68 05 00 00 	mov    0x568(%rdi),%rsi
ffffffff8b451b37:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8b451b3c:	48 85 f6             	test   %rsi,%rsi
ffffffff8b451b3f:	74 4a                	je     ffffffff8b451b8b <frame_candidate_a91b4a+0x41>
ffffffff8b451b41:	83 be 00 01 00 00 01 	cmpl   $0x1,0x100(%rsi)
ffffffff8b451b48:	75 41                	jne    ffffffff8b451b8b <frame_candidate_a91b4a+0x41>

ffffffff8b451b4a <frame_candidate_a91b4a>:
ffffffff8b451b4a:	55                   	push   %rbp
ffffffff8b451b4b:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451b4e:	48 b8 04 00 00 00 01 	movabs $0x100000004,%rax
ffffffff8b451b55:	00 00 00 
ffffffff8b451b58:	48 89 86 00 01 00 00 	mov    %rax,0x100(%rsi)
ffffffff8b451b5f:	48 c7 86 50 01 00 00 	movq   $0x0,0x150(%rsi)
ffffffff8b451b66:	00 00 00 00 
ffffffff8b451b6a:	48 c7 86 08 01 00 00 	movq   $0x0,0x108(%rsi)
ffffffff8b451b71:	00 00 00 00 
ffffffff8b451b75:	48 81 c6 30 01 00 00 	add    $0x130,%rsi
ffffffff8b451b7c:	48 8b 3d 1d 4f 16 03 	mov    0x3164f1d(%rip),%rdi        # ffffffff8e5b6aa0 <frame_candidate_a92d00+0x3163da0>
ffffffff8b451b83:	e8 28 8e a5 ff       	call   ffffffff8aeaa9b0 <handler_640_body-0x5a6460>
ffffffff8b451b88:	31 c0                	xor    %eax,%eax
ffffffff8b451b8a:	5d                   	pop    %rbp
ffffffff8b451b8b:	c3                   	ret
ffffffff8b451b8c:	90                   	nop
ffffffff8b451b8d:	90                   	nop
ffffffff8b451b8e:	90                   	nop
ffffffff8b451b8f:	90                   	nop
ffffffff8b451b90:	41 89 f1             	mov    %esi,%r9d
ffffffff8b451b93:	48 8b b7 68 05 00 00 	mov    0x568(%rdi),%rsi
ffffffff8b451b9a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8b451b9f:	48 85 f6             	test   %rsi,%rsi
ffffffff8b451ba2:	0f 84 f9 00 00 00    	je     ffffffff8b451ca1 <frame_candidate_a91ba8+0xf9>

ffffffff8b451ba8 <frame_candidate_a91ba8>:
ffffffff8b451ba8:	55                   	push   %rbp
ffffffff8b451ba9:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451bac:	53                   	push   %rbx
ffffffff8b451bad:	50                   	push   %rax
ffffffff8b451bae:	44 8b 96 00 01 00 00 	mov    0x100(%rsi),%r10d
ffffffff8b451bb5:	41 83 f8 ff          	cmp    $0xffffffff,%r8d
ffffffff8b451bb9:	75 24                	jne    ffffffff8b451bdf <frame_candidate_a91ba8+0x37>
ffffffff8b451bbb:	45 89 d3             	mov    %r10d,%r11d
ffffffff8b451bbe:	44 89 cb             	mov    %r9d,%ebx
ffffffff8b451bc1:	41 83 f3 02          	xor    $0x2,%r11d
ffffffff8b451bc5:	83 f3 02             	xor    $0x2,%ebx
ffffffff8b451bc8:	44 09 db             	or     %r11d,%ebx
ffffffff8b451bcb:	75 12                	jne    ffffffff8b451bdf <frame_candidate_a91ba8+0x37>
ffffffff8b451bcd:	4c 8b 97 60 05 00 00 	mov    0x560(%rdi),%r10
ffffffff8b451bd4:	49 c1 ea 1f          	shr    $0x1f,%r10
ffffffff8b451bd8:	74 38                	je     ffffffff8b451c12 <frame_candidate_a91ba8+0x6a>
ffffffff8b451bda:	e9 bc 00 00 00       	jmp    ffffffff8b451c9b <frame_candidate_a91ba8+0xf3>
ffffffff8b451bdf:	41 83 fa 01          	cmp    $0x1,%r10d
ffffffff8b451be3:	0f 85 b2 00 00 00    	jne    ffffffff8b451c9b <frame_candidate_a91ba8+0xf3>
ffffffff8b451be9:	83 f9 7e             	cmp    $0x7e,%ecx
ffffffff8b451bec:	77 24                	ja     ffffffff8b451c12 <frame_candidate_a91ba8+0x6a>
ffffffff8b451bee:	48 8b 87 60 05 00 00 	mov    0x560(%rdi),%rax
ffffffff8b451bf5:	83 e0 10             	and    $0x10,%eax
ffffffff8b451bf8:	74 18                	je     ffffffff8b451c12 <frame_candidate_a91ba8+0x6a>
ffffffff8b451bfa:	48 8d 3d 23 a6 8d 00 	lea    0x8da623(%rip),%rdi        # ffffffff8bd2c224 <frame_candidate_a92d00+0x8d9524>
ffffffff8b451c01:	31 c0                	xor    %eax,%eax
ffffffff8b451c03:	e8 08 b8 7c ff       	call   ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b451c08:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8b451c0d:	e9 89 00 00 00       	jmp    ffffffff8b451c9b <frame_candidate_a91ba8+0xf3>
ffffffff8b451c12:	44 89 c8             	mov    %r9d,%eax
ffffffff8b451c15:	c7 86 00 01 00 00 02 	movl   $0x2,0x100(%rsi)
ffffffff8b451c1c:	00 00 00 
ffffffff8b451c1f:	44 89 8e 04 01 00 00 	mov    %r9d,0x104(%rsi)
ffffffff8b451c26:	48 89 96 50 01 00 00 	mov    %rdx,0x150(%rsi)
ffffffff8b451c2d:	89 8e 08 01 00 00    	mov    %ecx,0x108(%rsi)
ffffffff8b451c33:	44 89 86 0c 01 00 00 	mov    %r8d,0x10c(%rsi)
ffffffff8b451c3a:	41 f7 d0             	not    %r8d
ffffffff8b451c3d:	83 f0 02             	xor    $0x2,%eax
ffffffff8b451c40:	44 09 c0             	or     %r8d,%eax
ffffffff8b451c43:	75 17                	jne    ffffffff8b451c5c <frame_candidate_a91ba8+0xb4>
ffffffff8b451c45:	48 c7 c1 00 00 00 80 	mov    $0xffffffff80000000,%rcx
ffffffff8b451c4c:	48 0b 8f 60 05 00 00 	or     0x560(%rdi),%rcx
ffffffff8b451c53:	48 89 8f 60 05 00 00 	mov    %rcx,0x560(%rdi)
ffffffff8b451c5a:	eb 0d                	jmp    ffffffff8b451c69 <frame_candidate_a91ba8+0xc1>
ffffffff8b451c5c:	48 8b 8f 60 05 00 00 	mov    0x560(%rdi),%rcx
ffffffff8b451c63:	41 83 f9 01          	cmp    $0x1,%r9d
ffffffff8b451c67:	74 0f                	je     ffffffff8b451c78 <frame_candidate_a91ba8+0xd0>
ffffffff8b451c69:	f6 c1 01             	test   $0x1,%cl
ffffffff8b451c6c:	75 0a                	jne    ffffffff8b451c78 <frame_candidate_a91ba8+0xd0>
ffffffff8b451c6e:	31 c0                	xor    %eax,%eax
ffffffff8b451c70:	48 c1 e9 1f          	shr    $0x1f,%rcx
ffffffff8b451c74:	75 10                	jne    ffffffff8b451c86 <frame_candidate_a91ba8+0xde>
ffffffff8b451c76:	eb 23                	jmp    ffffffff8b451c9b <frame_candidate_a91ba8+0xf3>
ffffffff8b451c78:	48 81 c9 00 00 00 80 	or     $0xffffffff80000000,%rcx
ffffffff8b451c7f:	48 89 8f 60 05 00 00 	mov    %rcx,0x560(%rdi)
ffffffff8b451c86:	48 8b 3d 13 4e 16 03 	mov    0x3164e13(%rip),%rdi        # ffffffff8e5b6aa0 <frame_candidate_a92d00+0x3163da0>
ffffffff8b451c8d:	48 81 c6 10 01 00 00 	add    $0x110,%rsi
ffffffff8b451c94:	e8 17 8d a5 ff       	call   ffffffff8aeaa9b0 <handler_640_body-0x5a6460>
ffffffff8b451c99:	31 c0                	xor    %eax,%eax
ffffffff8b451c9b:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b451c9f:	5b                   	pop    %rbx
ffffffff8b451ca0:	5d                   	pop    %rbp
ffffffff8b451ca1:	c3                   	ret
ffffffff8b451ca2:	90                   	nop
ffffffff8b451ca3:	90                   	nop
ffffffff8b451ca4:	90                   	nop
ffffffff8b451ca5:	90                   	nop
ffffffff8b451ca6:	90                   	nop
ffffffff8b451ca7:	90                   	nop
ffffffff8b451ca8:	90                   	nop
ffffffff8b451ca9:	90                   	nop
ffffffff8b451caa:	90                   	nop
ffffffff8b451cab:	90                   	nop
ffffffff8b451cac:	90                   	nop
ffffffff8b451cad:	90                   	nop
ffffffff8b451cae:	90                   	nop
ffffffff8b451caf:	90                   	nop
ffffffff8b451cb0:	48 8b 87 68 05 00 00 	mov    0x568(%rdi),%rax
ffffffff8b451cb7:	48 85 c0             	test   %rax,%rax
ffffffff8b451cba:	74 1a                	je     ffffffff8b451cd6 <frame_candidate_a91cbc+0x1a>

ffffffff8b451cbc <frame_candidate_a91cbc>:
ffffffff8b451cbc:	55                   	push   %rbp
ffffffff8b451cbd:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451cc0:	c7 80 00 01 00 00 01 	movl   $0x1,0x100(%rax)
ffffffff8b451cc7:	00 00 00 
ffffffff8b451cca:	48 c7 80 60 01 00 00 	movq   $0x0,0x160(%rax)
ffffffff8b451cd1:	00 00 00 00 
ffffffff8b451cd5:	5d                   	pop    %rbp
ffffffff8b451cd6:	c3                   	ret
ffffffff8b451cd7:	90                   	nop
ffffffff8b451cd8:	90                   	nop
ffffffff8b451cd9:	90                   	nop
ffffffff8b451cda:	90                   	nop
ffffffff8b451cdb:	90                   	nop
ffffffff8b451cdc:	90                   	nop
ffffffff8b451cdd:	90                   	nop
ffffffff8b451cde:	90                   	nop
ffffffff8b451cdf:	90                   	nop

ffffffff8b451ce0 <frame_candidate_a91ce0>:
ffffffff8b451ce0:	55                   	push   %rbp
ffffffff8b451ce1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451ce4:	53                   	push   %rbx
ffffffff8b451ce5:	50                   	push   %rax
ffffffff8b451ce6:	48 8b 9f 68 05 00 00 	mov    0x568(%rdi),%rbx
ffffffff8b451ced:	48 85 db             	test   %rbx,%rbx
ffffffff8b451cf0:	74 37                	je     ffffffff8b451d29 <frame_candidate_a91ce0+0x49>
ffffffff8b451cf2:	83 bb 00 01 00 00 02 	cmpl   $0x2,0x100(%rbx)
ffffffff8b451cf9:	75 2e                	jne    ffffffff8b451d29 <frame_candidate_a91ce0+0x49>
ffffffff8b451cfb:	48 89 df             	mov    %rbx,%rdi
ffffffff8b451cfe:	c7 83 00 01 00 00 04 	movl   $0x4,0x100(%rbx)
ffffffff8b451d05:	00 00 00 
ffffffff8b451d08:	e8 03 4c 17 00       	call   ffffffff8b5c6910 <frame_candidate_a92d00+0x173c10>
ffffffff8b451d0d:	48 8b 3d 8c 4d 16 03 	mov    0x3164d8c(%rip),%rdi        # ffffffff8e5b6aa0 <frame_candidate_a92d00+0x3163da0>
ffffffff8b451d14:	48 81 c3 30 01 00 00 	add    $0x130,%rbx
ffffffff8b451d1b:	48 89 de             	mov    %rbx,%rsi
ffffffff8b451d1e:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b451d22:	5b                   	pop    %rbx
ffffffff8b451d23:	5d                   	pop    %rbp
ffffffff8b451d24:	e9 87 8c a5 ff       	jmp    ffffffff8aeaa9b0 <handler_640_body-0x5a6460>
ffffffff8b451d29:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b451d2d:	5b                   	pop    %rbx
ffffffff8b451d2e:	5d                   	pop    %rbp
ffffffff8b451d2f:	c3                   	ret

ffffffff8b451d30 <frame_candidate_a91d30>:
ffffffff8b451d30:	55                   	push   %rbp
ffffffff8b451d31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451d34:	41 56                	push   %r14
ffffffff8b451d36:	53                   	push   %rbx
ffffffff8b451d37:	48 8d 15 da f6 7c ff 	lea    -0x830926(%rip),%rdx        # ffffffff8ac21418 <handler_640_body-0x82f9f8>
ffffffff8b451d3e:	48 8d 1d 52 cb 85 00 	lea    0x85cb52(%rip),%rbx        # ffffffff8bcae897 <frame_candidate_a92d00+0x85bb97>
ffffffff8b451d45:	4c 8d 35 54 4d 16 03 	lea    0x3164d54(%rip),%r14        # ffffffff8e5b6aa0 <frame_candidate_a92d00+0x3163da0>
ffffffff8b451d4c:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8b451d51:	48 89 df             	mov    %rbx,%rdi
ffffffff8b451d54:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b451d57:	e8 04 8a a5 ff       	call   ffffffff8aeaa760 <handler_640_body-0x5a66b0>
ffffffff8b451d5c:	48 89 05 3d 4d 16 03 	mov    %rax,0x3164d3d(%rip)        # ffffffff8e5b6aa0 <frame_candidate_a92d00+0x3163da0>
ffffffff8b451d63:	48 8d 0d 83 8a 8c 00 	lea    0x8c8a83(%rip),%rcx        # ffffffff8bd1a7ed <frame_candidate_a92d00+0x8c7aed>
ffffffff8b451d6a:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b451d6d:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8b451d72:	ba 5c 00 00 00       	mov    $0x5c,%edx
ffffffff8b451d77:	49 89 d8             	mov    %rbx,%r8
ffffffff8b451d7a:	31 c0                	xor    %eax,%eax
ffffffff8b451d7c:	5b                   	pop    %rbx
ffffffff8b451d7d:	41 5e                	pop    %r14
ffffffff8b451d7f:	5d                   	pop    %rbp
ffffffff8b451d80:	e9 9b 9a a5 ff       	jmp    ffffffff8aeab820 <handler_640_body-0x5a55f0>
ffffffff8b451d85:	90                   	nop
ffffffff8b451d86:	90                   	nop
ffffffff8b451d87:	90                   	nop
ffffffff8b451d88:	90                   	nop
ffffffff8b451d89:	90                   	nop
ffffffff8b451d8a:	90                   	nop
ffffffff8b451d8b:	90                   	nop
ffffffff8b451d8c:	90                   	nop
ffffffff8b451d8d:	90                   	nop
ffffffff8b451d8e:	90                   	nop
ffffffff8b451d8f:	90                   	nop

ffffffff8b451d90 <frame_candidate_a91d90>:
ffffffff8b451d90:	55                   	push   %rbp
ffffffff8b451d91:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451d94:	41 57                	push   %r15
ffffffff8b451d96:	41 56                	push   %r14
ffffffff8b451d98:	41 54                	push   %r12
ffffffff8b451d9a:	53                   	push   %rbx
ffffffff8b451d9b:	48 83 ec 20          	sub    $0x20,%rsp
ffffffff8b451d9f:	4c 8d 25 6a a5 e8 02 	lea    0x2e8a56a(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451da6:	49 89 f7             	mov    %rsi,%r15
ffffffff8b451da9:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
ffffffff8b451dad:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b451db1:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
ffffffff8b451db5:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
ffffffff8b451dbc:	00 
ffffffff8b451dbd:	8b 5f 18             	mov    0x18(%rdi),%ebx
ffffffff8b451dc0:	4c 8b 77 10          	mov    0x10(%rdi),%r14
ffffffff8b451dc4:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b451dc7:	89 de                	mov    %ebx,%esi
ffffffff8b451dc9:	e8 c2 5c c0 ff       	call   ffffffff8b057a90 <handler_640_body-0x3f9380>
ffffffff8b451dce:	85 c0                	test   %eax,%eax
ffffffff8b451dd0:	75 30                	jne    ffffffff8b451e02 <frame_candidate_a91d90+0x72>
ffffffff8b451dd2:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
ffffffff8b451dd6:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b451dd9:	e8 22 3a aa ff       	call   ffffffff8aef5800 <handler_640_body-0x55b610>
ffffffff8b451dde:	85 c0                	test   %eax,%eax
ffffffff8b451de0:	75 20                	jne    ffffffff8b451e02 <frame_candidate_a91d90+0x72>
ffffffff8b451de2:	49 8b 47 08          	mov    0x8(%r15),%rax
ffffffff8b451de6:	48 8d 0d 33 b3 7d ff 	lea    -0x824ccd(%rip),%rcx        # ffffffff8ac2d120 <handler_640_body-0x823cf0>
ffffffff8b451ded:	4c 8d 45 c8          	lea    -0x38(%rbp),%r8
ffffffff8b451df1:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b451df4:	48 89 da             	mov    %rbx,%rdx
ffffffff8b451df7:	31 ff                	xor    %edi,%edi
ffffffff8b451df9:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8b451dfd:	e8 be c3 a4 ff       	call   ffffffff8ae9e1c0 <handler_640_body-0x5b2c50>
ffffffff8b451e02:	49 8b 0c 24          	mov    (%r12),%rcx
ffffffff8b451e06:	48 3b 4d d8          	cmp    -0x28(%rbp),%rcx
ffffffff8b451e0a:	75 0d                	jne    ffffffff8b451e19 <frame_candidate_a91d90+0x89>
ffffffff8b451e0c:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b451e10:	5b                   	pop    %rbx
ffffffff8b451e11:	41 5c                	pop    %r12
ffffffff8b451e13:	41 5e                	pop    %r14
ffffffff8b451e15:	41 5f                	pop    %r15
ffffffff8b451e17:	5d                   	pop    %rbp
ffffffff8b451e18:	c3                   	ret
ffffffff8b451e19:	e8 92 b8 c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b451e1e:	0f 0b                	ud2

ffffffff8b451e20 <frame_candidate_a91e20>:
ffffffff8b451e20:	55                   	push   %rbp
ffffffff8b451e21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b451e24:	41 57                	push   %r15
ffffffff8b451e26:	41 56                	push   %r14
ffffffff8b451e28:	41 55                	push   %r13
ffffffff8b451e2a:	41 54                	push   %r12
ffffffff8b451e2c:	53                   	push   %rbx
ffffffff8b451e2d:	48 83 ec 38          	sub    $0x38,%rsp
ffffffff8b451e31:	4c 8d 25 d8 a4 e8 02 	lea    0x2e8a4d8(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451e38:	49 89 f6             	mov    %rsi,%r14
ffffffff8b451e3b:	48 8d 75 c8          	lea    -0x38(%rbp),%rsi
ffffffff8b451e3f:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b451e42:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b451e46:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b451e4a:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b451e51:	00 
ffffffff8b451e52:	e8 69 5e c0 ff       	call   ffffffff8b057cc0 <handler_640_body-0x3f9150>
ffffffff8b451e57:	85 c0                	test   %eax,%eax
ffffffff8b451e59:	75 10                	jne    ffffffff8b451e6b <frame_candidate_a91e20+0x4b>
ffffffff8b451e5b:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
ffffffff8b451e5f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b451e62:	e8 99 39 aa ff       	call   ffffffff8aef5800 <handler_640_body-0x55b610>
ffffffff8b451e67:	85 c0                	test   %eax,%eax
ffffffff8b451e69:	74 1d                	je     ffffffff8b451e88 <frame_candidate_a91e20+0x68>
ffffffff8b451e6b:	49 8b 0c 24          	mov    (%r12),%rcx
ffffffff8b451e6f:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8b451e73:	0f 85 3c 02 00 00    	jne    ffffffff8b4520b5 <frame_candidate_a91e20+0x295>
ffffffff8b451e79:	48 83 c4 38          	add    $0x38,%rsp
ffffffff8b451e7d:	5b                   	pop    %rbx
ffffffff8b451e7e:	41 5c                	pop    %r12
ffffffff8b451e80:	41 5d                	pop    %r13
ffffffff8b451e82:	41 5e                	pop    %r14
ffffffff8b451e84:	41 5f                	pop    %r15
ffffffff8b451e86:	5d                   	pop    %rbp
ffffffff8b451e87:	c3                   	ret
ffffffff8b451e88:	8b 53 2c             	mov    0x2c(%rbx),%edx
ffffffff8b451e8b:	48 85 d2             	test   %rdx,%rdx
ffffffff8b451e8e:	0f 84 3c 01 00 00    	je     ffffffff8b451fd0 <frame_candidate_a91e20+0x1b0>
ffffffff8b451e94:	4d 8b 7e 08          	mov    0x8(%r14),%r15
ffffffff8b451e98:	48 8b 73 18          	mov    0x18(%rbx),%rsi
ffffffff8b451e9c:	31 db                	xor    %ebx,%ebx
ffffffff8b451e9e:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
ffffffff8b451ea2:	41 8b 0f             	mov    (%r15),%ecx
ffffffff8b451ea5:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
ffffffff8b451ea9:	89 c8                	mov    %ecx,%eax
ffffffff8b451eab:	41 c7 04 07 14 00 00 	movl   $0x14,(%r15,%rax,1)
ffffffff8b451eb2:	00 
ffffffff8b451eb3:	48 8b 0c de          	mov    (%rsi,%rbx,8),%rcx
ffffffff8b451eb7:	44 8b 41 2c          	mov    0x2c(%rcx),%r8d
ffffffff8b451ebb:	41 83 f8 04          	cmp    $0x4,%r8d
ffffffff8b451ebf:	0f 85 8f 01 00 00    	jne    ffffffff8b452054 <frame_candidate_a91e20+0x234>
ffffffff8b451ec5:	4c 8b 69 18          	mov    0x18(%rcx),%r13
ffffffff8b451ec9:	49 8b 7d 00          	mov    0x0(%r13),%rdi
ffffffff8b451ecd:	48 85 ff             	test   %rdi,%rdi
ffffffff8b451ed0:	0f 84 01 01 00 00    	je     ffffffff8b451fd7 <frame_candidate_a91e20+0x1b7>
ffffffff8b451ed6:	80 7f 09 01          	cmpb   $0x1,0x9(%rdi)
ffffffff8b451eda:	0f 85 f7 00 00 00    	jne    ffffffff8b451fd7 <frame_candidate_a91e20+0x1b7>
ffffffff8b451ee0:	48 8b 4f 10          	mov    0x10(%rdi),%rcx
ffffffff8b451ee4:	49 01 c7             	add    %rax,%r15
ffffffff8b451ee7:	49 89 4f 08          	mov    %rcx,0x8(%r15)
ffffffff8b451eeb:	49 8b 7d 08          	mov    0x8(%r13),%rdi
ffffffff8b451eef:	48 85 ff             	test   %rdi,%rdi
ffffffff8b451ef2:	0f 84 f9 00 00 00    	je     ffffffff8b451ff1 <frame_candidate_a91e20+0x1d1>
ffffffff8b451ef8:	80 7f 09 01          	cmpb   $0x1,0x9(%rdi)
ffffffff8b451efc:	0f 85 ef 00 00 00    	jne    ffffffff8b451ff1 <frame_candidate_a91e20+0x1d1>
ffffffff8b451f02:	8b 47 10             	mov    0x10(%rdi),%eax
ffffffff8b451f05:	b9 18 00 00 00       	mov    $0x18,%ecx
ffffffff8b451f0a:	41 89 47 04          	mov    %eax,0x4(%r15)
ffffffff8b451f0e:	4d 8b 65 10          	mov    0x10(%r13),%r12
ffffffff8b451f12:	4d 85 e4             	test   %r12,%r12
ffffffff8b451f15:	0f 84 83 00 00 00    	je     ffffffff8b451f9e <frame_candidate_a91e20+0x17e>
ffffffff8b451f1b:	41 0f b6 44 24 09    	movzbl 0x9(%r12),%eax
ffffffff8b451f21:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b451f24:	74 78                	je     ffffffff8b451f9e <frame_candidate_a91e20+0x17e>
ffffffff8b451f26:	83 f8 02             	cmp    $0x2,%eax
ffffffff8b451f29:	74 4e                	je     ffffffff8b451f79 <frame_candidate_a91e20+0x159>
ffffffff8b451f2b:	83 f8 14             	cmp    $0x14,%eax
ffffffff8b451f2e:	0f 85 46 01 00 00    	jne    ffffffff8b45207a <frame_candidate_a91e20+0x25a>
ffffffff8b451f34:	45 0f b6 44 24 0d    	movzbl 0xd(%r12),%r8d
ffffffff8b451f3a:	41 83 f8 05          	cmp    $0x5,%r8d
ffffffff8b451f3e:	0f 85 53 01 00 00    	jne    ffffffff8b452097 <frame_candidate_a91e20+0x277>
ffffffff8b451f44:	41 8b 4e 08          	mov    0x8(%r14),%ecx
ffffffff8b451f48:	49 8b 06             	mov    (%r14),%rax
ffffffff8b451f4b:	49 8b 7c 24 18       	mov    0x18(%r12),%rdi
ffffffff8b451f50:	4d 8d 67 14          	lea    0x14(%r15),%r12
ffffffff8b451f54:	48 8d 75 b8          	lea    -0x48(%rbp),%rsi
ffffffff8b451f58:	44 89 e2             	mov    %r12d,%edx
ffffffff8b451f5b:	29 ca                	sub    %ecx,%edx
ffffffff8b451f5d:	48 29 d0             	sub    %rdx,%rax
ffffffff8b451f60:	31 d2                	xor    %edx,%edx
ffffffff8b451f62:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8b451f66:	4c 89 65 c0          	mov    %r12,-0x40(%rbp)
ffffffff8b451f6a:	e8 91 5e a4 ff       	call   ffffffff8ae97e00 <handler_640_body-0x5b9010>
ffffffff8b451f6f:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b451f72:	e8 29 08 da ff       	call   ffffffff8b1f27a0 <handler_640_body-0x25e670>
ffffffff8b451f77:	eb 13                	jmp    ffffffff8b451f8c <frame_candidate_a91e20+0x16c>
ffffffff8b451f79:	49 8b 74 24 10       	mov    0x10(%r12),%rsi
ffffffff8b451f7e:	49 8d 7f 14          	lea    0x14(%r15),%rdi
ffffffff8b451f82:	e8 a9 3c f7 ff       	call   ffffffff8b3c5c30 <handler_640_body-0x8b1e0>
ffffffff8b451f87:	41 8b 44 24 18       	mov    0x18(%r12),%eax
ffffffff8b451f8c:	41 8b 0f             	mov    (%r15),%ecx
ffffffff8b451f8f:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
ffffffff8b451f93:	48 8b 75 b0          	mov    -0x50(%rbp),%rsi
ffffffff8b451f97:	8d 4c 08 08          	lea    0x8(%rax,%rcx,1),%ecx
ffffffff8b451f9b:	83 e1 f8             	and    $0xfffffff8,%ecx
ffffffff8b451f9e:	41 89 0f             	mov    %ecx,(%r15)
ffffffff8b451fa1:	49 8b 7d 18          	mov    0x18(%r13),%rdi
ffffffff8b451fa5:	48 85 ff             	test   %rdi,%rdi
ffffffff8b451fa8:	74 75                	je     ffffffff8b45201f <frame_candidate_a91e20+0x1ff>
ffffffff8b451faa:	80 7f 09 01          	cmpb   $0x1,0x9(%rdi)
ffffffff8b451fae:	75 6f                	jne    ffffffff8b45201f <frame_candidate_a91e20+0x1ff>
ffffffff8b451fb0:	8b 47 10             	mov    0x10(%rdi),%eax
ffffffff8b451fb3:	4c 8d 25 56 a3 e8 02 	lea    0x2e8a356(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b451fba:	48 ff c3             	inc    %rbx
ffffffff8b451fbd:	41 89 47 10          	mov    %eax,0x10(%r15)
ffffffff8b451fc1:	31 c0                	xor    %eax,%eax
ffffffff8b451fc3:	39 da                	cmp    %ebx,%edx
ffffffff8b451fc5:	0f 85 de fe ff ff    	jne    ffffffff8b451ea9 <frame_candidate_a91e20+0x89>
ffffffff8b451fcb:	e9 9b fe ff ff       	jmp    ffffffff8b451e6b <frame_candidate_a91e20+0x4b>
ffffffff8b451fd0:	31 c0                	xor    %eax,%eax
ffffffff8b451fd2:	e9 94 fe ff ff       	jmp    ffffffff8b451e6b <frame_candidate_a91e20+0x4b>
ffffffff8b451fd7:	e8 54 7c a3 ff       	call   ffffffff8ae89c30 <handler_640_body-0x5c71e0>
ffffffff8b451fdc:	48 8d 3d eb 49 e4 00 	lea    0xe449eb(%rip),%rdi        # ffffffff8c2969ce <frame_candidate_a92d00+0xe43cce>
ffffffff8b451fe3:	48 8d 15 23 54 8c 00 	lea    0x8c5423(%rip),%rdx        # ffffffff8bd1740d <frame_candidate_a92d00+0x8c470d>
ffffffff8b451fea:	be 46 01 00 00       	mov    $0x146,%esi
ffffffff8b451fef:	eb 18                	jmp    ffffffff8b452009 <frame_candidate_a91e20+0x1e9>
ffffffff8b451ff1:	e8 3a 7c a3 ff       	call   ffffffff8ae89c30 <handler_640_body-0x5c71e0>
ffffffff8b451ff6:	48 8d 3d d1 49 e4 00 	lea    0xe449d1(%rip),%rdi        # ffffffff8c2969ce <frame_candidate_a92d00+0xe43cce>
ffffffff8b451ffd:	48 8d 15 52 68 86 00 	lea    0x866852(%rip),%rdx        # ffffffff8bcb8856 <frame_candidate_a92d00+0x865b56>
ffffffff8b452004:	be 53 01 00 00       	mov    $0x153,%esi
ffffffff8b452009:	49 89 c0             	mov    %rax,%r8
ffffffff8b45200c:	89 d9                	mov    %ebx,%ecx
ffffffff8b45200e:	31 c0                	xor    %eax,%eax
ffffffff8b452010:	e8 db 59 c6 ff       	call   ffffffff8b0b79f0 <handler_640_body-0x399420>
ffffffff8b452015:	b8 04 10 00 00       	mov    $0x1004,%eax
ffffffff8b45201a:	e9 4c fe ff ff       	jmp    ffffffff8b451e6b <frame_candidate_a91e20+0x4b>
ffffffff8b45201f:	e8 0c 7c a3 ff       	call   ffffffff8ae89c30 <handler_640_body-0x5c71e0>
ffffffff8b452024:	48 8d 3d a3 49 e4 00 	lea    0xe449a3(%rip),%rdi        # ffffffff8c2969ce <frame_candidate_a92d00+0xe43cce>
ffffffff8b45202b:	48 8d 15 32 b2 7e 00 	lea    0x7eb232(%rip),%rdx        # ffffffff8bc3d264 <frame_candidate_a92d00+0x7ea564>
ffffffff8b452032:	be a5 01 00 00       	mov    $0x1a5,%esi
ffffffff8b452037:	49 89 c0             	mov    %rax,%r8
ffffffff8b45203a:	89 d9                	mov    %ebx,%ecx
ffffffff8b45203c:	31 c0                	xor    %eax,%eax
ffffffff8b45203e:	e8 ad 59 c6 ff       	call   ffffffff8b0b79f0 <handler_640_body-0x399420>
ffffffff8b452043:	4c 8d 25 c6 a2 e8 02 	lea    0x2e8a2c6(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b45204a:	b8 04 10 00 00       	mov    $0x1004,%eax
ffffffff8b45204f:	e9 17 fe ff ff       	jmp    ffffffff8b451e6b <frame_candidate_a91e20+0x4b>
ffffffff8b452054:	48 8d 3d 73 49 e4 00 	lea    0xe44973(%rip),%rdi        # ffffffff8c2969ce <frame_candidate_a92d00+0xe43cce>
ffffffff8b45205b:	48 8d 15 94 93 91 00 	lea    0x919394(%rip),%rdx        # ffffffff8bd6b3f6 <frame_candidate_a92d00+0x9186f6>
ffffffff8b452062:	be 34 01 00 00       	mov    $0x134,%esi
ffffffff8b452067:	89 d9                	mov    %ebx,%ecx
ffffffff8b452069:	31 c0                	xor    %eax,%eax
ffffffff8b45206b:	e8 80 59 c6 ff       	call   ffffffff8b0b79f0 <handler_640_body-0x399420>
ffffffff8b452070:	b8 0b 30 00 00       	mov    $0x300b,%eax
ffffffff8b452075:	e9 f1 fd ff ff       	jmp    ffffffff8b451e6b <frame_candidate_a91e20+0x4b>
ffffffff8b45207a:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b45207d:	e8 ae 7b a3 ff       	call   ffffffff8ae89c30 <handler_640_body-0x5c71e0>
ffffffff8b452082:	48 8d 3d 45 49 e4 00 	lea    0xe44945(%rip),%rdi        # ffffffff8c2969ce <frame_candidate_a92d00+0xe43cce>
ffffffff8b452089:	48 8d 15 f8 ae 89 00 	lea    0x89aef8(%rip),%rdx        # ffffffff8bcecf88 <frame_candidate_a92d00+0x89a288>
ffffffff8b452090:	be 95 01 00 00       	mov    $0x195,%esi
ffffffff8b452095:	eb a0                	jmp    ffffffff8b452037 <frame_candidate_a91e20+0x217>
ffffffff8b452097:	48 8d 3d 30 49 e4 00 	lea    0xe44930(%rip),%rdi        # ffffffff8c2969ce <frame_candidate_a92d00+0xe43cce>
ffffffff8b45209e:	48 8d 15 b9 94 8f 00 	lea    0x8f94b9(%rip),%rdx        # ffffffff8bd4b55e <frame_candidate_a92d00+0x8f885e>
ffffffff8b4520a5:	be 67 01 00 00       	mov    $0x167,%esi
ffffffff8b4520aa:	89 d9                	mov    %ebx,%ecx
ffffffff8b4520ac:	31 c0                	xor    %eax,%eax
ffffffff8b4520ae:	e8 3d 59 c6 ff       	call   ffffffff8b0b79f0 <handler_640_body-0x399420>
ffffffff8b4520b3:	eb 8e                	jmp    ffffffff8b452043 <frame_candidate_a91e20+0x223>
ffffffff8b4520b5:	e8 f6 b5 c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b4520ba:	0f 0b                	ud2
ffffffff8b4520bc:	90                   	nop
ffffffff8b4520bd:	90                   	nop
ffffffff8b4520be:	90                   	nop
ffffffff8b4520bf:	90                   	nop

ffffffff8b4520c0 <frame_candidate_a920c0>:
ffffffff8b4520c0:	55                   	push   %rbp
ffffffff8b4520c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4520c4:	41 57                	push   %r15
ffffffff8b4520c6:	41 56                	push   %r14
ffffffff8b4520c8:	53                   	push   %rbx
ffffffff8b4520c9:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b4520cd:	4c 8d 3d 3c a2 e8 02 	lea    0x2e8a23c(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b4520d4:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b4520d7:	49 89 fe             	mov    %rdi,%r14
ffffffff8b4520da:	48 8d 55 d8          	lea    -0x28(%rbp),%rdx
ffffffff8b4520de:	49 8b 07             	mov    (%r15),%rax
ffffffff8b4520e1:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b4520e5:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
ffffffff8b4520ec:	00 
ffffffff8b4520ed:	48 8b 37             	mov    (%rdi),%rsi
ffffffff8b4520f0:	48 8b 7f 08          	mov    0x8(%rdi),%rdi
ffffffff8b4520f4:	e8 17 58 c0 ff       	call   ffffffff8b057910 <handler_640_body-0x3f9500>
ffffffff8b4520f9:	85 c0                	test   %eax,%eax
ffffffff8b4520fb:	75 21                	jne    ffffffff8b45211e <frame_candidate_a920c0+0x5e>
ffffffff8b4520fd:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
ffffffff8b452101:	48 89 df             	mov    %rbx,%rdi
ffffffff8b452104:	e8 f7 36 aa ff       	call   ffffffff8aef5800 <handler_640_body-0x55b610>
ffffffff8b452109:	85 c0                	test   %eax,%eax
ffffffff8b45210b:	75 11                	jne    ffffffff8b45211e <frame_candidate_a920c0+0x5e>
ffffffff8b45210d:	49 8b 7e 08          	mov    0x8(%r14),%rdi
ffffffff8b452111:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
ffffffff8b452115:	48 8b 53 08          	mov    0x8(%rbx),%rdx
ffffffff8b452119:	e8 d2 36 bf ff       	call   ffffffff8b0457f0 <handler_640_body-0x40b620>
ffffffff8b45211e:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b452121:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8b452125:	75 0b                	jne    ffffffff8b452132 <frame_candidate_a920c0+0x72>
ffffffff8b452127:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b45212b:	5b                   	pop    %rbx
ffffffff8b45212c:	41 5e                	pop    %r14
ffffffff8b45212e:	41 5f                	pop    %r15
ffffffff8b452130:	5d                   	pop    %rbp
ffffffff8b452131:	c3                   	ret
ffffffff8b452132:	e8 79 b5 c6 ff       	call   ffffffff8b0bd6b0 <handler_640_body-0x393760>
ffffffff8b452137:	0f 0b                	ud2
ffffffff8b452139:	90                   	nop
ffffffff8b45213a:	90                   	nop
ffffffff8b45213b:	90                   	nop
ffffffff8b45213c:	90                   	nop
ffffffff8b45213d:	90                   	nop
ffffffff8b45213e:	90                   	nop
ffffffff8b45213f:	90                   	nop

ffffffff8b452140 <frame_candidate_a92140>:
ffffffff8b452140:	55                   	push   %rbp
ffffffff8b452141:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452144:	48 83 ec 20          	sub    $0x20,%rsp
ffffffff8b452148:	db 6d 10             	fldt   0x10(%rbp)
ffffffff8b45214b:	d9 c0                	fld    %st(0)
ffffffff8b45214d:	db 7d f0             	fstpt  -0x10(%rbp)
ffffffff8b452150:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
ffffffff8b452154:	89 c1                	mov    %eax,%ecx
ffffffff8b452156:	81 e1 ff 7f 00 00    	and    $0x7fff,%ecx
ffffffff8b45215c:	81 f9 ff 7f 00 00    	cmp    $0x7fff,%ecx
ffffffff8b452162:	74 51                	je     ffffffff8b4521b5 <frame_candidate_a92140+0x75>
ffffffff8b452164:	85 c9                	test   %ecx,%ecx
ffffffff8b452166:	75 31                	jne    ffffffff8b452199 <frame_candidate_a92140+0x59>
ffffffff8b452168:	d9 c0                	fld    %st(0)
ffffffff8b45216a:	db 7d e0             	fstpt  -0x20(%rbp)
ffffffff8b45216d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
ffffffff8b452171:	89 c1                	mov    %eax,%ecx
ffffffff8b452173:	48 c1 e8 20          	shr    $0x20,%rax
ffffffff8b452177:	48 09 c1             	or     %rax,%rcx
ffffffff8b45217a:	74 44                	je     ffffffff8b4521c0 <frame_candidate_a92140+0x80>
ffffffff8b45217c:	dc 0d 06 86 92 00    	fmull  0x928606(%rip)        # ffffffff8bd7a788 <frame_candidate_a92d00+0x927a88>
ffffffff8b452182:	db 7d f0             	fstpt  -0x10(%rbp)
ffffffff8b452185:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
ffffffff8b452189:	89 c1                	mov    %eax,%ecx
ffffffff8b45218b:	81 e1 ff 7f 00 00    	and    $0x7fff,%ecx
ffffffff8b452191:	81 c1 00 be ff ff    	add    $0xffffbe00,%ecx
ffffffff8b452197:	eb 08                	jmp    ffffffff8b4521a1 <frame_candidate_a92140+0x61>
ffffffff8b452199:	81 c1 02 c0 ff ff    	add    $0xffffc002,%ecx
ffffffff8b45219f:	dd d8                	fstp   %st(0)
ffffffff8b4521a1:	48 25 00 80 ff ff    	and    $0xffffffffffff8000,%rax
ffffffff8b4521a7:	89 0f                	mov    %ecx,(%rdi)
ffffffff8b4521a9:	48 0d fe 3f 00 00    	or     $0x3ffe,%rax
ffffffff8b4521af:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
ffffffff8b4521b3:	d9 ee                	fldz
ffffffff8b4521b5:	dd d8                	fstp   %st(0)
ffffffff8b4521b7:	db 6d f0             	fldt   -0x10(%rbp)
ffffffff8b4521ba:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b4521be:	5d                   	pop    %rbp
ffffffff8b4521bf:	c3                   	ret
ffffffff8b4521c0:	dd d8                	fstp   %st(0)
ffffffff8b4521c2:	c7 07 00 00 00 00    	movl   $0x0,(%rdi)
ffffffff8b4521c8:	eb e9                	jmp    ffffffff8b4521b3 <frame_candidate_a92140+0x73>
ffffffff8b4521ca:	90                   	nop
ffffffff8b4521cb:	90                   	nop
ffffffff8b4521cc:	90                   	nop
ffffffff8b4521cd:	90                   	nop
ffffffff8b4521ce:	90                   	nop
ffffffff8b4521cf:	90                   	nop

ffffffff8b4521d0 <frame_candidate_a921d0>:
ffffffff8b4521d0:	55                   	push   %rbp
ffffffff8b4521d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4521d4:	41 57                	push   %r15
ffffffff8b4521d6:	41 56                	push   %r14
ffffffff8b4521d8:	41 55                	push   %r13
ffffffff8b4521da:	41 54                	push   %r12
ffffffff8b4521dc:	53                   	push   %rbx
ffffffff8b4521dd:	50                   	push   %rax
ffffffff8b4521de:	83 ff 02             	cmp    $0x2,%edi
ffffffff8b4521e1:	73 4b                	jae    ffffffff8b45222e <frame_candidate_a921d0+0x5e>
ffffffff8b4521e3:	49 89 f7             	mov    %rsi,%r15
ffffffff8b4521e6:	48 8d 15 bb 59 7d ff 	lea    -0x82a645(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b4521ed:	48 8d 0d b4 48 16 03 	lea    0x31648b4(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b4521f4:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4521f9:	be 77 00 00 00       	mov    $0x77,%esi
ffffffff8b4521fe:	e8 fd bb 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b452203:	85 c0                	test   %eax,%eax
ffffffff8b452205:	74 53                	je     ffffffff8b45225a <frame_candidate_a921d0+0x8a>
ffffffff8b452207:	48 8d 3d 8c c0 7d 00 	lea    0x7dc08c(%rip),%rdi        # ffffffff8bc2e29a <frame_candidate_a92d00+0x7db59a>
ffffffff8b45220e:	48 8d 35 5f f6 89 00 	lea    0x89f65f(%rip),%rsi        # ffffffff8bcf1874 <frame_candidate_a92d00+0x89eb74>
ffffffff8b452215:	ba aa f0 00 00       	mov    $0xf0aa,%edx
ffffffff8b45221a:	b9 f8 00 00 00       	mov    $0xf8,%ecx
ffffffff8b45221f:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b452222:	31 c0                	xor    %eax,%eax
ffffffff8b452224:	e8 e7 b1 7c ff       	call   ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b452229:	e9 90 01 00 00       	jmp    ffffffff8b4523be <frame_candidate_a921d0+0x1ee>
ffffffff8b45222e:	41 89 f8             	mov    %edi,%r8d
ffffffff8b452231:	48 8d 3d 62 c0 7d 00 	lea    0x7dc062(%rip),%rdi        # ffffffff8bc2e29a <frame_candidate_a92d00+0x7db59a>
ffffffff8b452238:	48 8d 35 35 f6 89 00 	lea    0x89f635(%rip),%rsi        # ffffffff8bcf1874 <frame_candidate_a92d00+0x89eb74>
ffffffff8b45223f:	ba aa f0 00 00       	mov    $0xf0aa,%edx
ffffffff8b452244:	b9 ee 00 00 00       	mov    $0xee,%ecx
ffffffff8b452249:	31 c0                	xor    %eax,%eax
ffffffff8b45224b:	e8 c0 b1 7c ff       	call   ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b452250:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b452255:	e9 73 01 00 00       	jmp    ffffffff8b4523cd <frame_candidate_a921d0+0x1fd>
ffffffff8b45225a:	48 8d 15 47 59 7d ff 	lea    -0x82a6b9(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b452261:	48 8d 0d 40 48 16 03 	lea    0x3164840(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b452268:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45226d:	be 78 00 00 00       	mov    $0x78,%esi
ffffffff8b452272:	e8 89 bb 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b452277:	85 c0                	test   %eax,%eax
ffffffff8b452279:	74 31                	je     ffffffff8b4522ac <frame_candidate_a921d0+0xdc>
ffffffff8b45227b:	48 8d 3d 18 c0 7d 00 	lea    0x7dc018(%rip),%rdi        # ffffffff8bc2e29a <frame_candidate_a92d00+0x7db59a>
ffffffff8b452282:	48 8d 35 eb f5 89 00 	lea    0x89f5eb(%rip),%rsi        # ffffffff8bcf1874 <frame_candidate_a92d00+0x89eb74>
ffffffff8b452289:	ba aa f0 00 00       	mov    $0xf0aa,%edx
ffffffff8b45228e:	b9 00 01 00 00       	mov    $0x100,%ecx
ffffffff8b452293:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b452296:	31 c0                	xor    %eax,%eax
ffffffff8b452298:	e8 73 b1 7c ff       	call   ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b45229d:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4522a2:	be 77 00 00 00       	mov    $0x77,%esi
ffffffff8b4522a7:	e9 0d 01 00 00       	jmp    ffffffff8b4523b9 <frame_candidate_a921d0+0x1e9>
ffffffff8b4522ac:	48 8d 15 f5 58 7d ff 	lea    -0x82a70b(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b4522b3:	48 8d 0d ee 47 16 03 	lea    0x31647ee(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b4522ba:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4522bf:	be 79 00 00 00       	mov    $0x79,%esi
ffffffff8b4522c4:	e8 37 bb 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b4522c9:	89 c3                	mov    %eax,%ebx
ffffffff8b4522cb:	41 b6 01             	mov    $0x1,%r14b
ffffffff8b4522ce:	b9 08 01 00 00       	mov    $0x108,%ecx
ffffffff8b4522d3:	85 c0                	test   %eax,%eax
ffffffff8b4522d5:	75 2a                	jne    ffffffff8b452301 <frame_candidate_a921d0+0x131>
ffffffff8b4522d7:	48 8d 15 ca 58 7d ff 	lea    -0x82a736(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b4522de:	48 8d 0d c3 47 16 03 	lea    0x31647c3(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b4522e5:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4522ea:	be 86 00 00 00       	mov    $0x86,%esi
ffffffff8b4522ef:	e8 0c bb 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b4522f4:	b9 10 01 00 00       	mov    $0x110,%ecx
ffffffff8b4522f9:	85 c0                	test   %eax,%eax
ffffffff8b4522fb:	0f 84 db 00 00 00    	je     ffffffff8b4523dc <frame_candidate_a921d0+0x20c>
ffffffff8b452301:	41 b5 01             	mov    $0x1,%r13b
ffffffff8b452304:	41 b4 01             	mov    $0x1,%r12b
ffffffff8b452307:	41 b7 01             	mov    $0x1,%r15b
ffffffff8b45230a:	48 8d 3d 89 bf 7d 00 	lea    0x7dbf89(%rip),%rdi        # ffffffff8bc2e29a <frame_candidate_a92d00+0x7db59a>
ffffffff8b452311:	48 8d 35 5c f5 89 00 	lea    0x89f55c(%rip),%rsi        # ffffffff8bcf1874 <frame_candidate_a92d00+0x89eb74>
ffffffff8b452318:	ba aa f0 00 00       	mov    $0xf0aa,%edx
ffffffff8b45231d:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b452320:	31 c0                	xor    %eax,%eax
ffffffff8b452322:	e8 e9 b0 7c ff       	call   ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b452327:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45232c:	be 77 00 00 00       	mov    $0x77,%esi
ffffffff8b452331:	e8 3a bb 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452336:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45233b:	be 78 00 00 00       	mov    $0x78,%esi
ffffffff8b452340:	e8 2b bb 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452345:	85 db                	test   %ebx,%ebx
ffffffff8b452347:	74 16                	je     ffffffff8b45235f <frame_candidate_a921d0+0x18f>
ffffffff8b452349:	45 84 ed             	test   %r13b,%r13b
ffffffff8b45234c:	74 25                	je     ffffffff8b452373 <frame_candidate_a921d0+0x1a3>
ffffffff8b45234e:	45 84 e4             	test   %r12b,%r12b
ffffffff8b452351:	74 34                	je     ffffffff8b452387 <frame_candidate_a921d0+0x1b7>
ffffffff8b452353:	45 84 ff             	test   %r15b,%r15b
ffffffff8b452356:	74 43                	je     ffffffff8b45239b <frame_candidate_a921d0+0x1cb>
ffffffff8b452358:	45 84 f6             	test   %r14b,%r14b
ffffffff8b45235b:	74 52                	je     ffffffff8b4523af <frame_candidate_a921d0+0x1df>
ffffffff8b45235d:	eb 5f                	jmp    ffffffff8b4523be <frame_candidate_a921d0+0x1ee>
ffffffff8b45235f:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b452364:	be 79 00 00 00       	mov    $0x79,%esi
ffffffff8b452369:	e8 02 bb 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b45236e:	45 84 ed             	test   %r13b,%r13b
ffffffff8b452371:	75 db                	jne    ffffffff8b45234e <frame_candidate_a921d0+0x17e>
ffffffff8b452373:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b452378:	be 86 00 00 00       	mov    $0x86,%esi
ffffffff8b45237d:	e8 ee ba 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452382:	45 84 e4             	test   %r12b,%r12b
ffffffff8b452385:	75 cc                	jne    ffffffff8b452353 <frame_candidate_a921d0+0x183>
ffffffff8b452387:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45238c:	be 87 00 00 00       	mov    $0x87,%esi
ffffffff8b452391:	e8 da ba 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452396:	45 84 ff             	test   %r15b,%r15b
ffffffff8b452399:	75 bd                	jne    ffffffff8b452358 <frame_candidate_a921d0+0x188>
ffffffff8b45239b:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4523a0:	be 88 00 00 00       	mov    $0x88,%esi
ffffffff8b4523a5:	e8 c6 ba 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b4523aa:	45 84 f6             	test   %r14b,%r14b
ffffffff8b4523ad:	75 0f                	jne    ffffffff8b4523be <frame_candidate_a921d0+0x1ee>
ffffffff8b4523af:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4523b4:	be 7a 00 00 00       	mov    $0x7a,%esi
ffffffff8b4523b9:	e8 b2 ba 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b4523be:	bf f0 ff ff ff       	mov    $0xfffffff0,%edi
ffffffff8b4523c3:	e8 f8 18 88 ff       	call   ffffffff8acd3cc0 <handler_640_body-0x77d150>
ffffffff8b4523c8:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8b4523cd:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b4523d1:	5b                   	pop    %rbx
ffffffff8b4523d2:	41 5c                	pop    %r12
ffffffff8b4523d4:	41 5d                	pop    %r13
ffffffff8b4523d6:	41 5e                	pop    %r14
ffffffff8b4523d8:	41 5f                	pop    %r15
ffffffff8b4523da:	5d                   	pop    %rbp
ffffffff8b4523db:	c3                   	ret
ffffffff8b4523dc:	48 8d 15 c5 57 7d ff 	lea    -0x82a83b(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b4523e3:	48 8d 0d be 46 16 03 	lea    0x31646be(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b4523ea:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4523ef:	be 87 00 00 00       	mov    $0x87,%esi
ffffffff8b4523f4:	e8 07 ba 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b4523f9:	85 c0                	test   %eax,%eax
ffffffff8b4523fb:	74 0d                	je     ffffffff8b45240a <frame_candidate_a921d0+0x23a>
ffffffff8b4523fd:	b9 18 01 00 00       	mov    $0x118,%ecx
ffffffff8b452402:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b452405:	e9 fa fe ff ff       	jmp    ffffffff8b452304 <frame_candidate_a921d0+0x134>
ffffffff8b45240a:	48 8d 15 97 57 7d ff 	lea    -0x82a869(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b452411:	48 8d 0d 90 46 16 03 	lea    0x3164690(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b452418:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45241d:	be 88 00 00 00       	mov    $0x88,%esi
ffffffff8b452422:	e8 d9 b9 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b452427:	85 c0                	test   %eax,%eax
ffffffff8b452429:	74 10                	je     ffffffff8b45243b <frame_candidate_a921d0+0x26b>
ffffffff8b45242b:	b9 20 01 00 00       	mov    $0x120,%ecx
ffffffff8b452430:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b452433:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b452436:	e9 cc fe ff ff       	jmp    ffffffff8b452307 <frame_candidate_a921d0+0x137>
ffffffff8b45243b:	48 8d 15 66 57 7d ff 	lea    -0x82a89a(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b452442:	48 8d 0d 5f 46 16 03 	lea    0x316465f(%rip),%rcx        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b452449:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45244e:	be 7a 00 00 00       	mov    $0x7a,%esi
ffffffff8b452453:	e8 a8 b9 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b452458:	85 c0                	test   %eax,%eax
ffffffff8b45245a:	74 13                	je     ffffffff8b45246f <frame_candidate_a921d0+0x29f>
ffffffff8b45245c:	b9 28 01 00 00       	mov    $0x128,%ecx
ffffffff8b452461:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b452464:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b452467:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b45246a:	e9 9b fe ff ff       	jmp    ffffffff8b45230a <frame_candidate_a921d0+0x13a>
ffffffff8b45246f:	4c 8d 35 32 46 16 03 	lea    0x3164632(%rip),%r14        # ffffffff8e5b6aa8 <frame_candidate_a92d00+0x3163da8>
ffffffff8b452476:	48 8d 15 2b 57 7d ff 	lea    -0x82a8d5(%rip),%rdx        # ffffffff8ac27ba8 <handler_640_body-0x829268>
ffffffff8b45247d:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b452482:	be 7c 00 00 00       	mov    $0x7c,%esi
ffffffff8b452487:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b45248a:	e8 71 b9 04 00       	call   ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b45248f:	85 c0                	test   %eax,%eax
ffffffff8b452491:	74 16                	je     ffffffff8b4524a9 <frame_candidate_a921d0+0x2d9>
ffffffff8b452493:	b9 30 01 00 00       	mov    $0x130,%ecx
ffffffff8b452498:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b45249b:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b45249e:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b4524a1:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b4524a4:	e9 61 fe ff ff       	jmp    ffffffff8b45230a <frame_candidate_a921d0+0x13a>
ffffffff8b4524a9:	be 28 00 00 00       	mov    $0x28,%esi
ffffffff8b4524ae:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b4524b1:	e8 3a 6b 7c ff       	call   ffffffff8ac18ff0 <handler_640_body-0x837e20>
ffffffff8b4524b6:	48 8d 0d 9b 88 7d ff 	lea    -0x827765(%rip),%rcx        # ffffffff8ac2ad58 <handler_640_body-0x8260b8>
ffffffff8b4524bd:	31 c0                	xor    %eax,%eax
ffffffff8b4524bf:	4c 89 3d 02 46 16 03 	mov    %r15,0x3164602(%rip)        # ffffffff8e5b6ac8 <frame_candidate_a92d00+0x3163dc8>
ffffffff8b4524c6:	c7 05 e0 45 16 03 00 	movl   $0x0,0x31645e0(%rip)        # ffffffff8e5b6ab0 <frame_candidate_a92d00+0x3163db0>
ffffffff8b4524cd:	00 00 00 
ffffffff8b4524d0:	48 89 0d e1 45 16 03 	mov    %rcx,0x31645e1(%rip)        # ffffffff8e5b6ab8 <frame_candidate_a92d00+0x3163db8>
ffffffff8b4524d7:	4c 89 35 e2 45 16 03 	mov    %r14,0x31645e2(%rip)        # ffffffff8e5b6ac0 <frame_candidate_a92d00+0x3163dc0>
ffffffff8b4524de:	e9 ea fe ff ff       	jmp    ffffffff8b4523cd <frame_candidate_a921d0+0x1fd>
ffffffff8b4524e3:	90                   	nop
ffffffff8b4524e4:	90                   	nop
ffffffff8b4524e5:	90                   	nop
ffffffff8b4524e6:	90                   	nop
ffffffff8b4524e7:	90                   	nop
ffffffff8b4524e8:	90                   	nop
ffffffff8b4524e9:	90                   	nop
ffffffff8b4524ea:	90                   	nop
ffffffff8b4524eb:	90                   	nop
ffffffff8b4524ec:	90                   	nop
ffffffff8b4524ed:	90                   	nop
ffffffff8b4524ee:	90                   	nop
ffffffff8b4524ef:	90                   	nop

ffffffff8b4524f0 <frame_candidate_a924f0>:
ffffffff8b4524f0:	55                   	push   %rbp
ffffffff8b4524f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4524f4:	5d                   	pop    %rbp
ffffffff8b4524f5:	e9 06 b9 04 00       	jmp    ffffffff8b49de00 <frame_candidate_a92d00+0x4b100>
ffffffff8b4524fa:	90                   	nop
ffffffff8b4524fb:	90                   	nop
ffffffff8b4524fc:	90                   	nop
ffffffff8b4524fd:	90                   	nop
ffffffff8b4524fe:	90                   	nop
ffffffff8b4524ff:	90                   	nop

ffffffff8b452500 <frame_candidate_a92500>:
ffffffff8b452500:	55                   	push   %rbp
ffffffff8b452501:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452504:	5d                   	pop    %rbp
ffffffff8b452505:	e9 66 b9 04 00       	jmp    ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b45250a:	90                   	nop
ffffffff8b45250b:	90                   	nop
ffffffff8b45250c:	90                   	nop
ffffffff8b45250d:	90                   	nop
ffffffff8b45250e:	90                   	nop
ffffffff8b45250f:	90                   	nop

ffffffff8b452510 <frame_candidate_a92510>:
ffffffff8b452510:	55                   	push   %rbp
ffffffff8b452511:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452514:	48 89 fe             	mov    %rdi,%rsi
ffffffff8b452517:	48 8b 3d 52 14 ab 02 	mov    0x2ab1452(%rip),%rdi        # ffffffff8df03970 <frame_candidate_a92d00+0x2ab0c70>
ffffffff8b45251e:	5d                   	pop    %rbp
ffffffff8b45251f:	e9 8c 84 a5 ff       	jmp    ffffffff8aeaa9b0 <handler_640_body-0x5a6460>
ffffffff8b452524:	90                   	nop
ffffffff8b452525:	90                   	nop
ffffffff8b452526:	90                   	nop
ffffffff8b452527:	90                   	nop
ffffffff8b452528:	90                   	nop
ffffffff8b452529:	90                   	nop
ffffffff8b45252a:	90                   	nop
ffffffff8b45252b:	90                   	nop
ffffffff8b45252c:	90                   	nop
ffffffff8b45252d:	90                   	nop
ffffffff8b45252e:	90                   	nop
ffffffff8b45252f:	90                   	nop

ffffffff8b452530 <frame_candidate_a92530>:
ffffffff8b452530:	55                   	push   %rbp
ffffffff8b452531:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452534:	48 8b 7f 20          	mov    0x20(%rdi),%rdi
ffffffff8b452538:	5d                   	pop    %rbp
ffffffff8b452539:	e9 12 44 17 00       	jmp    ffffffff8b5c6950 <frame_candidate_a92d00+0x173c50>
ffffffff8b45253e:	90                   	nop
ffffffff8b45253f:	90                   	nop
ffffffff8b452540:	83 ff 02             	cmp    $0x2,%edi
ffffffff8b452543:	73 7d                	jae    ffffffff8b4525c2 <frame_candidate_a92545+0x7d>

ffffffff8b452545 <frame_candidate_a92545>:
ffffffff8b452545:	55                   	push   %rbp
ffffffff8b452546:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452549:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45254e:	be 77 00 00 00       	mov    $0x77,%esi
ffffffff8b452553:	e8 18 b9 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452558:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45255d:	be 78 00 00 00       	mov    $0x78,%esi
ffffffff8b452562:	e8 09 b9 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452567:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45256c:	be 79 00 00 00       	mov    $0x79,%esi
ffffffff8b452571:	e8 fa b8 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452576:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45257b:	be 86 00 00 00       	mov    $0x86,%esi
ffffffff8b452580:	e8 eb b8 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452585:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b45258a:	be 87 00 00 00       	mov    $0x87,%esi
ffffffff8b45258f:	e8 dc b8 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b452594:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b452599:	be 88 00 00 00       	mov    $0x88,%esi
ffffffff8b45259e:	e8 cd b8 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b4525a3:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4525a8:	be 7a 00 00 00       	mov    $0x7a,%esi
ffffffff8b4525ad:	e8 be b8 04 00       	call   ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b4525b2:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b4525b7:	be 7c 00 00 00       	mov    $0x7c,%esi
ffffffff8b4525bc:	5d                   	pop    %rbp
ffffffff8b4525bd:	e9 ae b8 04 00       	jmp    ffffffff8b49de70 <frame_candidate_a92d00+0x4b170>
ffffffff8b4525c2:	41 89 f8             	mov    %edi,%r8d
ffffffff8b4525c5:	48 8d 3d ce bc 7d 00 	lea    0x7dbcce(%rip),%rdi        # ffffffff8bc2e29a <frame_candidate_a92d00+0x7db59a>
ffffffff8b4525cc:	48 8d 35 a1 f2 89 00 	lea    0x89f2a1(%rip),%rsi        # ffffffff8bcf1874 <frame_candidate_a92d00+0x89eb74>
ffffffff8b4525d3:	ba aa f0 00 00       	mov    $0xf0aa,%edx
ffffffff8b4525d8:	b9 a5 01 00 00       	mov    $0x1a5,%ecx
ffffffff8b4525dd:	31 c0                	xor    %eax,%eax
ffffffff8b4525df:	e9 2c ae 7c ff       	jmp    ffffffff8ac1d410 <handler_640_body-0x833a00>
ffffffff8b4525e4:	90                   	nop
ffffffff8b4525e5:	90                   	nop
ffffffff8b4525e6:	90                   	nop
ffffffff8b4525e7:	90                   	nop
ffffffff8b4525e8:	90                   	nop
ffffffff8b4525e9:	90                   	nop
ffffffff8b4525ea:	90                   	nop
ffffffff8b4525eb:	90                   	nop
ffffffff8b4525ec:	90                   	nop
ffffffff8b4525ed:	90                   	nop
ffffffff8b4525ee:	90                   	nop
ffffffff8b4525ef:	90                   	nop

ffffffff8b4525f0 <frame_candidate_a925f0>:
ffffffff8b4525f0:	55                   	push   %rbp
ffffffff8b4525f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b4525f4:	8b 05 26 39 aa 02    	mov    0x2aa3926(%rip),%eax        # ffffffff8def5f20 <frame_candidate_a92d00+0x2aa3220>
ffffffff8b4525fa:	03 05 08 ec 2a 02    	add    0x22aec08(%rip),%eax        # ffffffff8d701208 <frame_candidate_a92d00+0x22ae508>
ffffffff8b452600:	03 05 2e 39 aa 02    	add    0x2aa392e(%rip),%eax        # ffffffff8def5f34 <frame_candidate_a92d00+0x2aa3234>
ffffffff8b452606:	48 2b 05 b3 31 df 01 	sub    0x1df31b3(%rip),%rax        # ffffffff8d2457c0 <frame_candidate_a92d00+0x1df2ac0>
ffffffff8b45260d:	78 02                	js     ffffffff8b452611 <frame_candidate_a925f0+0x21>
ffffffff8b45260f:	5d                   	pop    %rbp
ffffffff8b452610:	c3                   	ret
ffffffff8b452611:	31 c0                	xor    %eax,%eax
ffffffff8b452613:	5d                   	pop    %rbp
ffffffff8b452614:	c3                   	ret
ffffffff8b452615:	90                   	nop
ffffffff8b452616:	90                   	nop
ffffffff8b452617:	90                   	nop
ffffffff8b452618:	90                   	nop
ffffffff8b452619:	90                   	nop
ffffffff8b45261a:	90                   	nop
ffffffff8b45261b:	90                   	nop
ffffffff8b45261c:	90                   	nop
ffffffff8b45261d:	90                   	nop
ffffffff8b45261e:	90                   	nop
ffffffff8b45261f:	90                   	nop

ffffffff8b452620 <frame_candidate_a92620>:
ffffffff8b452620:	55                   	push   %rbp
ffffffff8b452621:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452624:	8b 47 28             	mov    0x28(%rdi),%eax
ffffffff8b452627:	48 69 c0 28 01 00 00 	imul   $0x128,%rax,%rax
ffffffff8b45262e:	48 05 ff 3f 00 00    	add    $0x3fff,%rax
ffffffff8b452634:	48 c1 e8 0e          	shr    $0xe,%rax
ffffffff8b452638:	48 03 47 08          	add    0x8(%rdi),%rax
ffffffff8b45263c:	5d                   	pop    %rbp
ffffffff8b45263d:	c3                   	ret
ffffffff8b45263e:	90                   	nop
ffffffff8b45263f:	90                   	nop

ffffffff8b452640 <frame_candidate_a92640>:
ffffffff8b452640:	55                   	push   %rbp
ffffffff8b452641:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452644:	41 57                	push   %r15
ffffffff8b452646:	41 56                	push   %r14
ffffffff8b452648:	41 55                	push   %r13
ffffffff8b45264a:	41 54                	push   %r12
ffffffff8b45264c:	53                   	push   %rbx
ffffffff8b45264d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b452651:	8b 46 28             	mov    0x28(%rsi),%eax
ffffffff8b452654:	41 be 1c 00 00 00    	mov    $0x1c,%r14d
ffffffff8b45265a:	3b 46 18             	cmp    0x18(%rsi),%eax
ffffffff8b45265d:	0f 83 85 02 00 00    	jae    ffffffff8b4528e8 <frame_candidate_a92640+0x2a8>
ffffffff8b452663:	44 8b 15 b6 38 aa 02 	mov    0x2aa38b6(%rip),%r10d        # ffffffff8def5f20 <frame_candidate_a92d00+0x2aa3220>
ffffffff8b45266a:	44 03 15 97 eb 2a 02 	add    0x22aeb97(%rip),%r10d        # ffffffff8d701208 <frame_candidate_a92d00+0x22ae508>
ffffffff8b452671:	44 03 15 bc 38 aa 02 	add    0x2aa38bc(%rip),%r10d        # ffffffff8def5f34 <frame_candidate_a92d00+0x2aa3234>
ffffffff8b452678:	4c 3b 15 41 31 df 01 	cmp    0x1df3141(%rip),%r10        # ffffffff8d2457c0 <frame_candidate_a92d00+0x1df2ac0>
ffffffff8b45267f:	41 0f 98 c2          	sets   %r10b
ffffffff8b452683:	41 0f 94 c3          	sete   %r11b
ffffffff8b452687:	45 08 d3             	or     %r10b,%r11b
ffffffff8b45268a:	0f 85 58 02 00 00    	jne    ffffffff8b4528e8 <frame_candidate_a92640+0x2a8>
ffffffff8b452690:	4c 8b 16             	mov    (%rsi),%r10
ffffffff8b452693:	49 83 fa ff          	cmp    $0xffffffffffffffff,%r10
ffffffff8b452697:	74 23                	je     ffffffff8b4526bc <frame_candidate_a92640+0x7c>
ffffffff8b452699:	48 69 c0 28 01 00 00 	imul   $0x128,%rax,%rax
ffffffff8b4526a0:	4c 8b 5e 08          	mov    0x8(%rsi),%r11
ffffffff8b4526a4:	48 05 ff 3f 00 00    	add    $0x3fff,%rax
ffffffff8b4526aa:	48 c1 e8 0e          	shr    $0xe,%rax
ffffffff8b4526ae:	4a 8d 44 18 01       	lea    0x1(%rax,%r11,1),%rax
ffffffff8b4526b3:	49 39 c2             	cmp    %rax,%r10
ffffffff8b4526b6:	0f 82 2c 02 00 00    	jb     ffffffff8b4528e8 <frame_candidate_a92640+0x2a8>
ffffffff8b4526bc:	f6 87 93 00 00 00 01 	testb  $0x1,0x93(%rdi)
ffffffff8b4526c3:	41 be 10 00 00 00    	mov    $0x10,%r14d
ffffffff8b4526c9:	0f 85 19 02 00 00    	jne    ffffffff8b4528e8 <frame_candidate_a92640+0x2a8>
ffffffff8b4526cf:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
ffffffff8b4526d3:	48 8b 7e 68          	mov    0x68(%rsi),%rdi
ffffffff8b4526d7:	41 89 d4             	mov    %edx,%r12d
ffffffff8b4526da:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b4526df:	49 89 f6             	mov    %rsi,%r14
ffffffff8b4526e2:	44 89 4d d4          	mov    %r9d,-0x2c(%rbp)
ffffffff8b4526e6:	45 89 c7             	mov    %r8d,%r15d
ffffffff8b4526e9:	41 89 cd             	mov    %ecx,%r13d
ffffffff8b4526ec:	e8 8f 91 9a ff       	call   ffffffff8adfb880 <handler_640_body-0x655590>
ffffffff8b4526f1:	48 8d 78 48          	lea    0x48(%rax),%rdi
ffffffff8b4526f5:	48 89 c3             	mov    %rax,%rbx
ffffffff8b4526f8:	44 89 60 10          	mov    %r12d,0x10(%rax)
ffffffff8b4526fc:	e8 cf 53 ab ff       	call   ffffffff8af07ad0 <handler_640_body-0x549340>
ffffffff8b452701:	48 8b 43 48          	mov    0x48(%rbx),%rax
ffffffff8b452705:	48 8b 4b 50          	mov    0x50(%rbx),%rcx
ffffffff8b452709:	4d 89 f4             	mov    %r14,%r12
ffffffff8b45270c:	48 89 4b 60          	mov    %rcx,0x60(%rbx)
ffffffff8b452710:	48 89 43 58          	mov    %rax,0x58(%rbx)
ffffffff8b452714:	48 89 43 68          	mov    %rax,0x68(%rbx)
ffffffff8b452718:	48 89 4b 70          	mov    %rcx,0x70(%rbx)
ffffffff8b45271c:	48 89 43 78          	mov    %rax,0x78(%rbx)
ffffffff8b452720:	8b 45 d4             	mov    -0x2c(%rbp),%eax
ffffffff8b452723:	48 89 8b 80 00 00 00 	mov    %rcx,0x80(%rbx)
ffffffff8b45272a:	44 89 6b 28          	mov    %r13d,0x28(%rbx)
ffffffff8b45272e:	44 89 7b 2c          	mov    %r15d,0x2c(%rbx)
ffffffff8b452732:	66 89 43 30          	mov    %ax,0x30(%rbx)
ffffffff8b452736:	49 8b 7e 20          	mov    0x20(%r14),%rdi
ffffffff8b45273a:	e8 d1 d2 f7 ff       	call   ffffffff8b3cfa10 <handler_640_body-0x81400>
ffffffff8b45273f:	89 43 14             	mov    %eax,0x14(%rbx)
ffffffff8b452742:	8b 43 10             	mov    0x10(%rbx),%eax
ffffffff8b452745:	ff c8                	dec    %eax
ffffffff8b452747:	83 f8 06             	cmp    $0x6,%eax
ffffffff8b45274a:	0f 87 aa 01 00 00    	ja     ffffffff8b4528fa <frame_candidate_a92640+0x2ba>
ffffffff8b452750:	48 8d 0d 81 42 e4 00 	lea    0xe44281(%rip),%rcx        # ffffffff8c2969d8 <frame_candidate_a92d00+0xe43cd8>
ffffffff8b452757:	4c 8b 7d c8          	mov    -0x38(%rbp),%r15
ffffffff8b45275b:	48 63 04 81          	movslq (%rcx,%rax,4),%rax
ffffffff8b45275f:	48 01 c8             	add    %rcx,%rax
ffffffff8b452762:	ff e0                	jmp    *%rax
ffffffff8b452764:	8b 45 20             	mov    0x20(%rbp),%eax
ffffffff8b452767:	89 83 c0 00 00 00    	mov    %eax,0xc0(%rbx)
ffffffff8b45276d:	e9 26 01 00 00       	jmp    ffffffff8b452898 <frame_candidate_a92640+0x258>
ffffffff8b452772:	48 8b 45 10          	mov    0x10(%rbp),%rax
ffffffff8b452776:	48 89 df             	mov    %rbx,%rdi
ffffffff8b452779:	48 c7 83 c8 00 00 00 	movq   $0x0,0xc8(%rbx)
ffffffff8b452780:	00 00 00 00 
ffffffff8b452784:	48 c7 83 d0 00 00 00 	movq   $0x0,0xd0(%rbx)
ffffffff8b45278b:	00 00 00 00 
ffffffff8b45278f:	48 85 c0             	test   %rax,%rax
ffffffff8b452792:	48 0f 45 f8          	cmovne %rax,%rdi
ffffffff8b452796:	31 f6                	xor    %esi,%esi
ffffffff8b452798:	31 d2                	xor    %edx,%edx
ffffffff8b45279a:	31 c9                	xor    %ecx,%ecx
ffffffff8b45279c:	48 89 bb c0 00 00 00 	mov    %rdi,0xc0(%rbx)
ffffffff8b4527a3:	48 c7 83 d8 00 00 00 	movq   $0x0,0xd8(%rbx)
ffffffff8b4527aa:	00 00 00 00 
ffffffff8b4527ae:	48 c7 83 e0 00 00 00 	movq   $0x0,0xe0(%rbx)
ffffffff8b4527b5:	00 00 00 00 
ffffffff8b4527b9:	66 ff 43 40          	incw   0x40(%rbx)
ffffffff8b4527bd:	48 81 c7 b0 00 00 00 	add    $0xb0,%rdi
ffffffff8b4527c4:	e8 37 42 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b4527c9:	48 8b 83 c0 00 00 00 	mov    0xc0(%rbx),%rax
ffffffff8b4527d0:	bf b0 00 00 00       	mov    $0xb0,%edi
ffffffff8b4527d5:	31 f6                	xor    %esi,%esi
ffffffff8b4527d7:	31 d2                	xor    %edx,%edx
ffffffff8b4527d9:	31 c9                	xor    %ecx,%ecx
ffffffff8b4527db:	66 ff 40 40          	incw   0x40(%rax)
ffffffff8b4527df:	48 03 bb c0 00 00 00 	add    0xc0(%rbx),%rdi
ffffffff8b4527e6:	e8 b5 47 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b4527eb:	e9 a8 00 00 00       	jmp    ffffffff8b452898 <frame_candidate_a92640+0x258>
ffffffff8b4527f0:	4c 8b 75 18          	mov    0x18(%rbp),%r14
ffffffff8b4527f4:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b4527f7:	e8 a4 ff d9 ff       	call   ffffffff8b1f27a0 <handler_640_body-0x25e670>
ffffffff8b4527fc:	48 8d 35 9d 22 76 01 	lea    0x176229d(%rip),%rsi        # ffffffff8cbb4aa0 <frame_candidate_a92d00+0x1761da0>
ffffffff8b452803:	48 89 c7             	mov    %rax,%rdi
ffffffff8b452806:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b45280b:	48 89 43 20          	mov    %rax,0x20(%rbx)
ffffffff8b45280f:	e8 3c 63 17 00       	call   ffffffff8b5c8b50 <frame_candidate_a92d00+0x175e50>
ffffffff8b452814:	48 89 83 c0 00 00 00 	mov    %rax,0xc0(%rbx)
ffffffff8b45281b:	48 89 c7             	mov    %rax,%rdi
ffffffff8b45281e:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b452821:	48 8b 53 20          	mov    0x20(%rbx),%rdx
ffffffff8b452825:	e8 86 68 7c ff       	call   ffffffff8ac190b0 <handler_640_body-0x837d60>
ffffffff8b45282a:	eb 6c                	jmp    ffffffff8b452898 <frame_candidate_a92640+0x258>
ffffffff8b45282c:	41 8b 87 30 03 00 00 	mov    0x330(%r15),%eax
ffffffff8b452833:	45 8b 97 34 03 00 00 	mov    0x334(%r15),%r10d
ffffffff8b45283a:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b45283f:	31 f6                	xor    %esi,%esi
ffffffff8b452841:	31 d2                	xor    %edx,%edx
ffffffff8b452843:	b9 07 00 00 00       	mov    $0x7,%ecx
ffffffff8b452848:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b45284b:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b45284e:	50                   	push   %rax
ffffffff8b45284f:	41 52                	push   %r10
ffffffff8b452851:	e8 0a b2 9c ff       	call   ffffffff8ae1da60 <handler_640_body-0x6333b0>
ffffffff8b452856:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b45285a:	4c 8d 78 18          	lea    0x18(%rax),%r15
ffffffff8b45285e:	49 89 c6             	mov    %rax,%r14
ffffffff8b452861:	48 89 83 c0 00 00 00 	mov    %rax,0xc0(%rbx)
ffffffff8b452868:	31 f6                	xor    %esi,%esi
ffffffff8b45286a:	31 d2                	xor    %edx,%edx
ffffffff8b45286c:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b45286f:	e8 2c 1e d4 ff       	call   ffffffff8b1946a0 <handler_640_body-0x2bc770>
ffffffff8b452874:	41 81 8e a0 00 00 00 	orl    $0x210,0xa0(%r14)
ffffffff8b45287b:	10 02 00 00 
ffffffff8b45287f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b452882:	be 00 20 00 00       	mov    $0x2000,%esi
ffffffff8b452887:	e8 34 f1 9c ff       	call   ffffffff8ae219c0 <handler_640_body-0x62f450>
ffffffff8b45288c:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b45288f:	31 f6                	xor    %esi,%esi
ffffffff8b452891:	31 d2                	xor    %edx,%edx
ffffffff8b452893:	e8 18 26 d4 ff       	call   ffffffff8b194eb0 <handler_640_body-0x2bbf60>
ffffffff8b452898:	4c 8b 6d 28          	mov    0x28(%rbp),%r13
ffffffff8b45289c:	4d 8d 7c 24 58       	lea    0x58(%r12),%r15
ffffffff8b4528a1:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b4528a4:	31 f6                	xor    %esi,%esi
ffffffff8b4528a6:	31 d2                	xor    %edx,%edx
ffffffff8b4528a8:	31 c9                	xor    %ecx,%ecx
ffffffff8b4528aa:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b4528ad:	e8 4e 41 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b4528b2:	49 8b 54 24 38       	mov    0x38(%r12),%rdx
ffffffff8b4528b7:	4c 89 e0             	mov    %r12,%rax
ffffffff8b4528ba:	49 8d 4c 24 38       	lea    0x38(%r12),%rcx
ffffffff8b4528bf:	48 89 13             	mov    %rdx,(%rbx)
ffffffff8b4528c2:	48 85 d2             	test   %rdx,%rdx
ffffffff8b4528c5:	74 04                	je     ffffffff8b4528cb <frame_candidate_a92640+0x28b>
ffffffff8b4528c7:	48 89 5a 08          	mov    %rbx,0x8(%rdx)
ffffffff8b4528cb:	48 89 58 38          	mov    %rbx,0x38(%rax)
ffffffff8b4528cf:	48 89 4b 08          	mov    %rcx,0x8(%rbx)
ffffffff8b4528d3:	ff 40 28             	incl   0x28(%rax)
ffffffff8b4528d6:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b4528d9:	31 f6                	xor    %esi,%esi
ffffffff8b4528db:	31 d2                	xor    %edx,%edx
ffffffff8b4528dd:	31 c9                	xor    %ecx,%ecx
ffffffff8b4528df:	e8 bc 46 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b4528e4:	49 89 5d 00          	mov    %rbx,0x0(%r13)
ffffffff8b4528e8:	44 89 f0             	mov    %r14d,%eax
ffffffff8b4528eb:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b4528ef:	5b                   	pop    %rbx
ffffffff8b4528f0:	41 5c                	pop    %r12
ffffffff8b4528f2:	41 5d                	pop    %r13
ffffffff8b4528f4:	41 5e                	pop    %r14
ffffffff8b4528f6:	41 5f                	pop    %r15
ffffffff8b4528f8:	5d                   	pop    %rbp
ffffffff8b4528f9:	c3                   	ret
ffffffff8b4528fa:	e8 51 f0 d5 ff       	call   ffffffff8b1b1950 <handler_640_body-0x29f4c0>
ffffffff8b4528ff:	48 63 53 10          	movslq 0x10(%rbx),%rdx
ffffffff8b452903:	48 8d 3d f0 ff ff ff 	lea    -0x10(%rip),%rdi        # ffffffff8b4528fa <frame_candidate_a92640+0x2ba>
ffffffff8b45290a:	48 89 de             	mov    %rbx,%rsi
ffffffff8b45290d:	e8 fe f6 d5 ff       	call   ffffffff8b1b2010 <handler_640_body-0x29ee00>
ffffffff8b452912:	8b 4b 10             	mov    0x10(%rbx),%ecx
ffffffff8b452915:	48 8d 35 ef 76 84 00 	lea    0x8476ef(%rip),%rsi        # ffffffff8bc9a00b <frame_candidate_a92d00+0x84730b>
ffffffff8b45291c:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b452921:	48 89 da             	mov    %rbx,%rdx
ffffffff8b452924:	31 c0                	xor    %eax,%eax
ffffffff8b452926:	e8 e5 80 20 00       	call   ffffffff8b65aa10 <frame_candidate_a92d00+0x207d10>
ffffffff8b45292b:	0f 0b                	ud2
ffffffff8b45292d:	90                   	nop
ffffffff8b45292e:	90                   	nop
ffffffff8b45292f:	90                   	nop

ffffffff8b452930 <frame_candidate_a92930>:
ffffffff8b452930:	55                   	push   %rbp
ffffffff8b452931:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452934:	41 57                	push   %r15
ffffffff8b452936:	41 56                	push   %r14
ffffffff8b452938:	41 54                	push   %r12
ffffffff8b45293a:	53                   	push   %rbx
ffffffff8b45293b:	4c 8d 7f 58          	lea    0x58(%rdi),%r15
ffffffff8b45293f:	49 89 fe             	mov    %rdi,%r14
ffffffff8b452942:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b452945:	31 f6                	xor    %esi,%esi
ffffffff8b452947:	31 d2                	xor    %edx,%edx
ffffffff8b452949:	31 c9                	xor    %ecx,%ecx
ffffffff8b45294b:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b45294e:	e8 ad 40 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b452953:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b452956:	48 85 c0             	test   %rax,%rax
ffffffff8b452959:	74 24                	je     ffffffff8b45297f <frame_candidate_a92930+0x4f>
ffffffff8b45295b:	48 39 58 08          	cmp    %rbx,0x8(%rax)
ffffffff8b45295f:	0f 85 08 01 00 00    	jne    ffffffff8b452a6d <frame_candidate_a92930+0x13d>
ffffffff8b452965:	48 8b 4b 08          	mov    0x8(%rbx),%rcx
ffffffff8b452969:	48 39 19             	cmp    %rbx,(%rcx)
ffffffff8b45296c:	0f 85 c1 00 00 00    	jne    ffffffff8b452a33 <frame_candidate_a92930+0x103>
ffffffff8b452972:	48 89 48 08          	mov    %rcx,0x8(%rax)
ffffffff8b452976:	48 8b 0b             	mov    (%rbx),%rcx
ffffffff8b452979:	48 8b 43 08          	mov    0x8(%rbx),%rax
ffffffff8b45297d:	eb 0f                	jmp    ffffffff8b45298e <frame_candidate_a92930+0x5e>
ffffffff8b45297f:	48 8b 43 08          	mov    0x8(%rbx),%rax
ffffffff8b452983:	48 39 18             	cmp    %rbx,(%rax)
ffffffff8b452986:	0f 85 a7 00 00 00    	jne    ffffffff8b452a33 <frame_candidate_a92930+0x103>
ffffffff8b45298c:	31 c9                	xor    %ecx,%ecx
ffffffff8b45298e:	48 89 08             	mov    %rcx,(%rax)
ffffffff8b452991:	41 ff 4e 28          	decl   0x28(%r14)
ffffffff8b452995:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b452998:	31 f6                	xor    %esi,%esi
ffffffff8b45299a:	31 d2                	xor    %edx,%edx
ffffffff8b45299c:	31 c9                	xor    %ecx,%ecx
ffffffff8b45299e:	e8 fd 45 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b4529a3:	8b 43 10             	mov    0x10(%rbx),%eax
ffffffff8b4529a6:	83 f8 07             	cmp    $0x7,%eax
ffffffff8b4529a9:	0f 87 fe 00 00 00    	ja     ffffffff8b452aad <frame_candidate_a92930+0x17d>
ffffffff8b4529af:	b9 dd 00 00 00       	mov    $0xdd,%ecx
ffffffff8b4529b4:	0f a3 c1             	bt     %eax,%ecx
ffffffff8b4529b7:	73 22                	jae    ffffffff8b4529db <frame_candidate_a92930+0xab>
ffffffff8b4529b9:	49 8b 7e 20          	mov    0x20(%r14),%rdi
ffffffff8b4529bd:	8b 73 14             	mov    0x14(%rbx),%esi
ffffffff8b4529c0:	e8 2b d5 f7 ff       	call   ffffffff8b3cfef0 <handler_640_body-0x80f20>
ffffffff8b4529c5:	49 8b 7e 68          	mov    0x68(%r14),%rdi
ffffffff8b4529c9:	48 89 de             	mov    %rbx,%rsi
ffffffff8b4529cc:	31 d2                	xor    %edx,%edx
ffffffff8b4529ce:	5b                   	pop    %rbx
ffffffff8b4529cf:	41 5c                	pop    %r12
ffffffff8b4529d1:	41 5e                	pop    %r14
ffffffff8b4529d3:	41 5f                	pop    %r15
ffffffff8b4529d5:	5d                   	pop    %rbp
ffffffff8b4529d6:	e9 e5 96 9a ff       	jmp    ffffffff8adfc0c0 <handler_640_body-0x654d50>
ffffffff8b4529db:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b4529de:	75 3e                	jne    ffffffff8b452a1e <frame_candidate_a92930+0xee>
ffffffff8b4529e0:	4c 8b a3 c0 00 00 00 	mov    0xc0(%rbx),%r12
ffffffff8b4529e7:	4d 85 e4             	test   %r12,%r12
ffffffff8b4529ea:	74 cd                	je     ffffffff8b4529b9 <frame_candidate_a92930+0x89>
ffffffff8b4529ec:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b4529ef:	31 f6                	xor    %esi,%esi
ffffffff8b4529f1:	31 d2                	xor    %edx,%edx
ffffffff8b4529f3:	31 c9                	xor    %ecx,%ecx
ffffffff8b4529f5:	e8 06 40 a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b4529fa:	49 8b 84 24 88 00 00 	mov    0x88(%r12),%rax
ffffffff8b452a01:	00 
ffffffff8b452a02:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b452a05:	31 f6                	xor    %esi,%esi
ffffffff8b452a07:	31 d2                	xor    %edx,%edx
ffffffff8b452a09:	31 c9                	xor    %ecx,%ecx
ffffffff8b452a0b:	49 29 46 08          	sub    %rax,0x8(%r14)
ffffffff8b452a0f:	e8 8c 45 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b452a14:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b452a17:	e8 84 f1 9c ff       	call   ffffffff8ae21ba0 <handler_640_body-0x62f270>
ffffffff8b452a1c:	eb 9b                	jmp    ffffffff8b4529b9 <frame_candidate_a92930+0x89>
ffffffff8b452a1e:	48 8b bb c0 00 00 00 	mov    0xc0(%rbx),%rdi
ffffffff8b452a25:	48 8d 35 74 20 76 01 	lea    0x1762074(%rip),%rsi        # ffffffff8cbb4aa0 <frame_candidate_a92d00+0x1761da0>
ffffffff8b452a2c:	e8 bf 63 17 00       	call   ffffffff8b5c8df0 <frame_candidate_a92d00+0x1760f0>
ffffffff8b452a31:	eb 86                	jmp    ffffffff8b4529b9 <frame_candidate_a92930+0x89>
ffffffff8b452a33:	e8 18 ef d5 ff       	call   ffffffff8b1b1950 <handler_640_body-0x29f4c0>
ffffffff8b452a38:	48 8b 53 08          	mov    0x8(%rbx),%rdx
ffffffff8b452a3c:	48 8d 3d f0 ff ff ff 	lea    -0x10(%rip),%rdi        # ffffffff8b452a33 <frame_candidate_a92930+0x103>
ffffffff8b452a43:	48 89 de             	mov    %rbx,%rsi
ffffffff8b452a46:	48 8b 0a             	mov    (%rdx),%rcx
ffffffff8b452a49:	e8 72 f6 d5 ff       	call   ffffffff8b1b20c0 <handler_640_body-0x29ed50>
ffffffff8b452a4e:	48 8b 4b 08          	mov    0x8(%rbx),%rcx
ffffffff8b452a52:	48 8d 35 74 ec 7f 00 	lea    0x7fec74(%rip),%rsi        # ffffffff8bc516cd <frame_candidate_a92d00+0x7fe9cd>
ffffffff8b452a59:	bf 0b 00 00 00       	mov    $0xb,%edi
ffffffff8b452a5e:	48 89 da             	mov    %rbx,%rdx
ffffffff8b452a61:	31 c0                	xor    %eax,%eax
ffffffff8b452a63:	4c 8b 01             	mov    (%rcx),%r8
ffffffff8b452a66:	e8 a5 7f 20 00       	call   ffffffff8b65aa10 <frame_candidate_a92d00+0x207d10>
ffffffff8b452a6b:	0f 0b                	ud2
ffffffff8b452a6d:	e8 de ee d5 ff       	call   ffffffff8b1b1950 <handler_640_body-0x29f4c0>
ffffffff8b452a72:	48 8b 13             	mov    (%rbx),%rdx
ffffffff8b452a75:	48 8d 3d f1 ff ff ff 	lea    -0xf(%rip),%rdi        # ffffffff8b452a6d <frame_candidate_a92930+0x13d>
ffffffff8b452a7c:	48 89 de             	mov    %rbx,%rsi
ffffffff8b452a7f:	49 89 d8             	mov    %rbx,%r8
ffffffff8b452a82:	48 8b 4a 08          	mov    0x8(%rdx),%rcx
ffffffff8b452a86:	e8 f5 f6 d5 ff       	call   ffffffff8b1b2180 <handler_640_body-0x29ec90>
ffffffff8b452a8b:	48 8b 0b             	mov    (%rbx),%rcx
ffffffff8b452a8e:	48 8d 35 02 33 81 00 	lea    0x813302(%rip),%rsi        # ffffffff8bc65d97 <frame_candidate_a92d00+0x813097>
ffffffff8b452a95:	bf 07 00 00 00       	mov    $0x7,%edi
ffffffff8b452a9a:	48 89 da             	mov    %rbx,%rdx
ffffffff8b452a9d:	49 89 d9             	mov    %rbx,%r9
ffffffff8b452aa0:	31 c0                	xor    %eax,%eax
ffffffff8b452aa2:	4c 8b 41 08          	mov    0x8(%rcx),%r8
ffffffff8b452aa6:	e8 65 7f 20 00       	call   ffffffff8b65aa10 <frame_candidate_a92d00+0x207d10>
ffffffff8b452aab:	0f 0b                	ud2
ffffffff8b452aad:	e8 9e ee d5 ff       	call   ffffffff8b1b1950 <handler_640_body-0x29f4c0>
ffffffff8b452ab2:	48 63 53 10          	movslq 0x10(%rbx),%rdx
ffffffff8b452ab6:	48 8d 3d f0 ff ff ff 	lea    -0x10(%rip),%rdi        # ffffffff8b452aad <frame_candidate_a92930+0x17d>
ffffffff8b452abd:	48 89 de             	mov    %rbx,%rsi
ffffffff8b452ac0:	e8 4b f5 d5 ff       	call   ffffffff8b1b2010 <handler_640_body-0x29ee00>
ffffffff8b452ac5:	8b 4b 10             	mov    0x10(%rbx),%ecx
ffffffff8b452ac8:	48 8d 35 8c 46 8a 00 	lea    0x8a468c(%rip),%rsi        # ffffffff8bcf715b <frame_candidate_a92d00+0x8a445b>
ffffffff8b452acf:	bf 0f 00 00 00       	mov    $0xf,%edi
ffffffff8b452ad4:	48 89 da             	mov    %rbx,%rdx
ffffffff8b452ad7:	31 c0                	xor    %eax,%eax
ffffffff8b452ad9:	e8 32 7f 20 00       	call   ffffffff8b65aa10 <frame_candidate_a92d00+0x207d10>
ffffffff8b452ade:	0f 0b                	ud2

ffffffff8b452ae0 <frame_candidate_a92ae0>:
ffffffff8b452ae0:	55                   	push   %rbp
ffffffff8b452ae1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452ae4:	41 56                	push   %r14
ffffffff8b452ae6:	53                   	push   %rbx
ffffffff8b452ae7:	89 d3                	mov    %edx,%ebx
ffffffff8b452ae9:	49 89 fe             	mov    %rdi,%r14
ffffffff8b452aec:	85 d2                	test   %edx,%edx
ffffffff8b452aee:	74 36                	je     ffffffff8b452b26 <frame_candidate_a92ae0+0x46>
ffffffff8b452af0:	8d 83 23 00 00 02    	lea    0x2000023(%rbx),%eax
ffffffff8b452af6:	89 da                	mov    %ebx,%edx
ffffffff8b452af8:	31 c9                	xor    %ecx,%ecx
ffffffff8b452afa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8b452b00:	69 f8 93 01 00 01    	imul   $0x1000193,%eax,%edi
ffffffff8b452b06:	0f b6 04 0e          	movzbl (%rsi,%rcx,1),%eax
ffffffff8b452b0a:	48 ff c1             	inc    %rcx
ffffffff8b452b0d:	31 f8                	xor    %edi,%eax
ffffffff8b452b0f:	48 39 ca             	cmp    %rcx,%rdx
ffffffff8b452b12:	75 ec                	jne    ffffffff8b452b00 <frame_candidate_a92ae0+0x20>
ffffffff8b452b14:	25 ff ff ff 3f       	and    $0x3fffffff,%eax
ffffffff8b452b19:	89 c1                	mov    %eax,%ecx
ffffffff8b452b1b:	83 c9 04             	or     $0x4,%ecx
ffffffff8b452b1e:	83 f8 04             	cmp    $0x4,%eax
ffffffff8b452b21:	0f 43 c8             	cmovae %eax,%ecx
ffffffff8b452b24:	eb 07                	jmp    ffffffff8b452b2d <frame_candidate_a92ae0+0x4d>
ffffffff8b452b26:	b9 23 00 00 02       	mov    $0x2000023,%ecx
ffffffff8b452b2b:	31 d2                	xor    %edx,%edx
ffffffff8b452b2d:	41 89 4e 20          	mov    %ecx,0x20(%r14)
ffffffff8b452b31:	41 89 4e 24          	mov    %ecx,0x24(%r14)
ffffffff8b452b35:	49 8b 7e 38          	mov    0x38(%r14),%rdi
ffffffff8b452b39:	e8 72 65 7c ff       	call   ffffffff8ac190b0 <handler_640_body-0x837d60>
ffffffff8b452b3e:	41 89 5e 28          	mov    %ebx,0x28(%r14)
ffffffff8b452b42:	5b                   	pop    %rbx
ffffffff8b452b43:	41 5e                	pop    %r14
ffffffff8b452b45:	5d                   	pop    %rbp
ffffffff8b452b46:	c3                   	ret
ffffffff8b452b47:	90                   	nop
ffffffff8b452b48:	90                   	nop
ffffffff8b452b49:	90                   	nop
ffffffff8b452b4a:	90                   	nop
ffffffff8b452b4b:	90                   	nop
ffffffff8b452b4c:	90                   	nop
ffffffff8b452b4d:	90                   	nop
ffffffff8b452b4e:	90                   	nop
ffffffff8b452b4f:	90                   	nop

ffffffff8b452b50 <frame_candidate_a92b50>:
ffffffff8b452b50:	55                   	push   %rbp
ffffffff8b452b51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452b54:	41 57                	push   %r15
ffffffff8b452b56:	41 56                	push   %r14
ffffffff8b452b58:	41 55                	push   %r13
ffffffff8b452b5a:	41 54                	push   %r12
ffffffff8b452b5c:	53                   	push   %rbx
ffffffff8b452b5d:	50                   	push   %rax
ffffffff8b452b5e:	48 8b 7f 60          	mov    0x60(%rdi),%rdi
ffffffff8b452b62:	49 89 d5             	mov    %rdx,%r13
ffffffff8b452b65:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b452b6a:	49 89 f6             	mov    %rsi,%r14
ffffffff8b452b6d:	31 f6                	xor    %esi,%esi
ffffffff8b452b6f:	4c 89 45 d0          	mov    %r8,-0x30(%rbp)
ffffffff8b452b73:	41 89 cf             	mov    %ecx,%r15d
ffffffff8b452b76:	31 db                	xor    %ebx,%ebx
ffffffff8b452b78:	e8 03 8d 9a ff       	call   ffffffff8adfb880 <handler_640_body-0x655590>
ffffffff8b452b7d:	49 89 c4             	mov    %rax,%r12
ffffffff8b452b80:	4c 89 70 30          	mov    %r14,0x30(%rax)
ffffffff8b452b84:	4d 85 ed             	test   %r13,%r13
ffffffff8b452b87:	0f 84 7c 00 00 00    	je     ffffffff8b452c09 <frame_candidate_a92b50+0xb9>
ffffffff8b452b8d:	48 8d 35 0c 1f 76 01 	lea    0x1761f0c(%rip),%rsi        # ffffffff8cbb4aa0 <frame_candidate_a92d00+0x1761da0>
ffffffff8b452b94:	44 89 fb             	mov    %r15d,%ebx
ffffffff8b452b97:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b452b9c:	48 89 df             	mov    %rbx,%rdi
ffffffff8b452b9f:	e8 ac 5f 17 00       	call   ffffffff8b5c8b50 <frame_candidate_a92d00+0x175e50>
ffffffff8b452ba4:	49 89 44 24 38       	mov    %rax,0x38(%r12)
ffffffff8b452ba9:	45 85 ff             	test   %r15d,%r15d
ffffffff8b452bac:	74 3b                	je     ffffffff8b452be9 <frame_candidate_a92b50+0x99>
ffffffff8b452bae:	41 8d 8f 23 00 00 02 	lea    0x2000023(%r15),%ecx
ffffffff8b452bb5:	31 d2                	xor    %edx,%edx
ffffffff8b452bb7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b452bbe:	00 00 
ffffffff8b452bc0:	69 f1 93 01 00 01    	imul   $0x1000193,%ecx,%esi
ffffffff8b452bc6:	41 0f b6 4c 15 00    	movzbl 0x0(%r13,%rdx,1),%ecx
ffffffff8b452bcc:	48 ff c2             	inc    %rdx
ffffffff8b452bcf:	31 f1                	xor    %esi,%ecx
ffffffff8b452bd1:	48 39 d3             	cmp    %rdx,%rbx
ffffffff8b452bd4:	75 ea                	jne    ffffffff8b452bc0 <frame_candidate_a92b50+0x70>
ffffffff8b452bd6:	81 e1 ff ff ff 3f    	and    $0x3fffffff,%ecx
ffffffff8b452bdc:	89 ca                	mov    %ecx,%edx
ffffffff8b452bde:	83 ca 04             	or     $0x4,%edx
ffffffff8b452be1:	83 f9 04             	cmp    $0x4,%ecx
ffffffff8b452be4:	0f 43 d1             	cmovae %ecx,%edx
ffffffff8b452be7:	eb 05                	jmp    ffffffff8b452bee <frame_candidate_a92b50+0x9e>
ffffffff8b452be9:	ba 23 00 00 02       	mov    $0x2000023,%edx
ffffffff8b452bee:	41 89 54 24 20       	mov    %edx,0x20(%r12)
ffffffff8b452bf3:	41 89 54 24 24       	mov    %edx,0x24(%r12)
ffffffff8b452bf8:	48 89 c7             	mov    %rax,%rdi
ffffffff8b452bfb:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b452bfe:	48 89 da             	mov    %rbx,%rdx
ffffffff8b452c01:	e8 aa 64 7c ff       	call   ffffffff8ac190b0 <handler_640_body-0x837d60>
ffffffff8b452c06:	44 89 fb             	mov    %r15d,%ebx
ffffffff8b452c09:	41 89 5c 24 28       	mov    %ebx,0x28(%r12)
ffffffff8b452c0e:	4d 85 f6             	test   %r14,%r14
ffffffff8b452c11:	74 05                	je     ffffffff8b452c18 <frame_candidate_a92b50+0xc8>
ffffffff8b452c13:	66 41 ff 46 40       	incw   0x40(%r14)
ffffffff8b452c18:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
ffffffff8b452c1c:	4c 89 20             	mov    %r12,(%rax)
ffffffff8b452c1f:	31 c0                	xor    %eax,%eax
ffffffff8b452c21:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b452c25:	5b                   	pop    %rbx
ffffffff8b452c26:	41 5c                	pop    %r12
ffffffff8b452c28:	41 5d                	pop    %r13
ffffffff8b452c2a:	41 5e                	pop    %r14
ffffffff8b452c2c:	41 5f                	pop    %r15
ffffffff8b452c2e:	5d                   	pop    %rbp
ffffffff8b452c2f:	c3                   	ret

ffffffff8b452c30 <frame_candidate_a92c30>:
ffffffff8b452c30:	55                   	push   %rbp
ffffffff8b452c31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452c34:	41 56                	push   %r14
ffffffff8b452c36:	53                   	push   %rbx
ffffffff8b452c37:	48 8b 46 30          	mov    0x30(%rsi),%rax
ffffffff8b452c3b:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b452c3e:	48 85 c0             	test   %rax,%rax
ffffffff8b452c41:	74 04                	je     ffffffff8b452c47 <frame_candidate_a92c30+0x17>
ffffffff8b452c43:	66 ff 48 40          	decw   0x40(%rax)
ffffffff8b452c47:	83 7e 20 00          	cmpl   $0x0,0x20(%rsi)
ffffffff8b452c4b:	78 1e                	js     ffffffff8b452c6b <frame_candidate_a92c30+0x3b>
ffffffff8b452c4d:	48 8b 7e 38          	mov    0x38(%rsi),%rdi
ffffffff8b452c51:	48 85 ff             	test   %rdi,%rdi
ffffffff8b452c54:	74 15                	je     ffffffff8b452c6b <frame_candidate_a92c30+0x3b>
ffffffff8b452c56:	48 8d 05 43 1e 76 01 	lea    0x1761e43(%rip),%rax        # ffffffff8cbb4aa0 <frame_candidate_a92d00+0x1761da0>
ffffffff8b452c5d:	49 89 f6             	mov    %rsi,%r14
ffffffff8b452c60:	48 89 c6             	mov    %rax,%rsi
ffffffff8b452c63:	e8 88 61 17 00       	call   ffffffff8b5c8df0 <frame_candidate_a92d00+0x1760f0>
ffffffff8b452c68:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b452c6b:	48 8b 7b 60          	mov    0x60(%rbx),%rdi
ffffffff8b452c6f:	31 d2                	xor    %edx,%edx
ffffffff8b452c71:	5b                   	pop    %rbx
ffffffff8b452c72:	41 5e                	pop    %r14
ffffffff8b452c74:	5d                   	pop    %rbp
ffffffff8b452c75:	e9 46 94 9a ff       	jmp    ffffffff8adfc0c0 <handler_640_body-0x654d50>
ffffffff8b452c7a:	90                   	nop
ffffffff8b452c7b:	90                   	nop
ffffffff8b452c7c:	90                   	nop
ffffffff8b452c7d:	90                   	nop
ffffffff8b452c7e:	90                   	nop
ffffffff8b452c7f:	90                   	nop
ffffffff8b452c80:	48 85 f6             	test   %rsi,%rsi
ffffffff8b452c83:	74 7a                	je     ffffffff8b452cff <frame_candidate_a92c8e+0x71>
ffffffff8b452c85:	83 bf d4 01 00 00 01 	cmpl   $0x1,0x1d4(%rdi)
ffffffff8b452c8c:	75 71                	jne    ffffffff8b452cff <frame_candidate_a92c8e+0x71>

ffffffff8b452c8e <frame_candidate_a92c8e>:
ffffffff8b452c8e:	55                   	push   %rbp
ffffffff8b452c8f:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452c92:	41 57                	push   %r15
ffffffff8b452c94:	41 56                	push   %r14
ffffffff8b452c96:	53                   	push   %rbx
ffffffff8b452c97:	50                   	push   %rax
ffffffff8b452c98:	48 8d 5e 18          	lea    0x18(%rsi),%rbx
ffffffff8b452c9c:	49 89 fe             	mov    %rdi,%r14
ffffffff8b452c9f:	49 89 f7             	mov    %rsi,%r15
ffffffff8b452ca2:	31 f6                	xor    %esi,%esi
ffffffff8b452ca4:	31 d2                	xor    %edx,%edx
ffffffff8b452ca6:	48 89 df             	mov    %rbx,%rdi
ffffffff8b452ca9:	e8 f2 19 d4 ff       	call   ffffffff8b1946a0 <handler_640_body-0x2bc770>
ffffffff8b452cae:	49 81 c6 b0 00 00 00 	add    $0xb0,%r14
ffffffff8b452cb5:	31 f6                	xor    %esi,%esi
ffffffff8b452cb7:	31 d2                	xor    %edx,%edx
ffffffff8b452cb9:	31 c9                	xor    %ecx,%ecx
ffffffff8b452cbb:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b452cbe:	e8 3d 3d a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b452cc3:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b452cc6:	be 00 80 00 00       	mov    $0x8000,%esi
ffffffff8b452ccb:	e8 f0 ec 9c ff       	call   ffffffff8ae219c0 <handler_640_body-0x62f450>
ffffffff8b452cd0:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b452cd3:	49 c7 87 58 01 00 00 	movq   $0x0,0x158(%r15)
ffffffff8b452cda:	00 00 00 00 
ffffffff8b452cde:	31 f6                	xor    %esi,%esi
ffffffff8b452ce0:	31 d2                	xor    %edx,%edx
ffffffff8b452ce2:	31 c9                	xor    %ecx,%ecx
ffffffff8b452ce4:	e8 b7 42 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b452ce9:	48 89 df             	mov    %rbx,%rdi
ffffffff8b452cec:	31 f6                	xor    %esi,%esi
ffffffff8b452cee:	31 d2                	xor    %edx,%edx
ffffffff8b452cf0:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b452cf4:	5b                   	pop    %rbx
ffffffff8b452cf5:	41 5e                	pop    %r14
ffffffff8b452cf7:	41 5f                	pop    %r15
ffffffff8b452cf9:	5d                   	pop    %rbp
ffffffff8b452cfa:	e9 b1 21 d4 ff       	jmp    ffffffff8b194eb0 <handler_640_body-0x2bbf60>
ffffffff8b452cff:	c3                   	ret

ffffffff8b452d00 <frame_candidate_a92d00>:
ffffffff8b452d00:	55                   	push   %rbp
ffffffff8b452d01:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b452d04:	41 57                	push   %r15
ffffffff8b452d06:	41 56                	push   %r14
ffffffff8b452d08:	41 55                	push   %r13
ffffffff8b452d0a:	41 54                	push   %r12
ffffffff8b452d0c:	53                   	push   %rbx
ffffffff8b452d0d:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8b452d11:	48 8d 05 f8 95 e8 02 	lea    0x2e895f8(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_a92d00+0x2e89610>
ffffffff8b452d18:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8b452d1c:	48 89 7d a0          	mov    %rdi,-0x60(%rbp)
ffffffff8b452d20:	4c 8d b6 98 00 00 00 	lea    0x98(%rsi),%r14
ffffffff8b452d27:	4c 8d ae b0 00 00 00 	lea    0xb0(%rsi),%r13
ffffffff8b452d2e:	4c 8d a6 90 00 00 00 	lea    0x90(%rsi),%r12
ffffffff8b452d35:	4c 8d be b8 00 00 00 	lea    0xb8(%rsi),%r15
ffffffff8b452d3c:	48 8d 1d f3 46 8c 00 	lea    0x8c46f3(%rip),%rbx        # ffffffff8bd17436 <frame_candidate_a92d00+0x8c4736>
ffffffff8b452d43:	48 8b 00             	mov    (%rax),%rax
ffffffff8b452d46:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b452d4a:	89 55 ac             	mov    %edx,-0x54(%rbp)
ffffffff8b452d4d:	81 ca 00 01 00 00    	or     $0x100,%edx
ffffffff8b452d53:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
ffffffff8b452d57:	4c 89 6d b8          	mov    %r13,-0x48(%rbp)
ffffffff8b452d5b:	89 55 a8             	mov    %edx,-0x58(%rbp)
ffffffff8b452d5e:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b452d61:	31 f6                	xor    %esi,%esi
ffffffff8b452d63:	31 d2                	xor    %edx,%edx
ffffffff8b452d65:	31 c9                	xor    %ecx,%ecx
ffffffff8b452d67:	e8 94 3c a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b452d6c:	4d 8b 2c 24          	mov    (%r12),%r13
ffffffff8b452d70:	4c 89 6d c8          	mov    %r13,-0x38(%rbp)
ffffffff8b452d74:	4d 85 ed             	test   %r13,%r13
ffffffff8b452d77:	0f 84 b3 00 00 00    	je     ffffffff8b452e30 <frame_candidate_a92d00+0x130>
ffffffff8b452d7d:	0f 1f 00             	nopl   (%rax)
ffffffff8b452d80:	49 8d bd b0 00 00 00 	lea    0xb0(%r13),%rdi
ffffffff8b452d87:	31 f6                	xor    %esi,%esi
ffffffff8b452d89:	31 d2                	xor    %edx,%edx
ffffffff8b452d8b:	31 c9                	xor    %ecx,%ecx
ffffffff8b452d8d:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
ffffffff8b452d91:	e8 6a 3c a3 ff       	call   ffffffff8ae86a00 <handler_640_body-0x5ca410>
ffffffff8b452d96:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b452d9a:	83 78 10 02          	cmpl   $0x2,0x10(%rax)
ffffffff8b452d9e:	75 12                	jne    ffffffff8b452db2 <frame_candidate_a92d00+0xb2>
ffffffff8b452da0:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b452da4:	48 83 b8 c0 00 00 00 	cmpq   $0x0,0xc0(%rax)
ffffffff8b452dab:	00 
ffffffff8b452dac:	0f 84 3c 01 00 00    	je     ffffffff8b452eee <frame_candidate_a92d00+0x1ee>
ffffffff8b452db2:	f7 45 ac 00 02 00 00 	testl  $0x200,-0x54(%rbp)
ffffffff8b452db9:	41 8b 85 c4 01 00 00 	mov    0x1c4(%r13),%eax
ffffffff8b452dc0:	74 0e                	je     ffffffff8b452dd0 <frame_candidate_a92d00+0xd0>
ffffffff8b452dc2:	89 c1                	mov    %eax,%ecx
ffffffff8b452dc4:	81 e1 80 00 00 00    	and    $0x80,%ecx
ffffffff8b452dca:	0f 85 1e 01 00 00    	jne    ffffffff8b452eee <frame_candidate_a92d00+0x1ee>
ffffffff8b452dd0:	84 c0                	test   %al,%al
ffffffff8b452dd2:	0f 89 c2 00 00 00    	jns    ffffffff8b452e9a <frame_candidate_a92d00+0x19a>
ffffffff8b452dd8:	48 8b 7d 98          	mov    -0x68(%rbp),%rdi
ffffffff8b452ddc:	31 f6                	xor    %esi,%esi
ffffffff8b452dde:	31 d2                	xor    %edx,%edx
ffffffff8b452de0:	31 c9                	xor    %ecx,%ecx
ffffffff8b452de2:	e8 b9 41 a3 ff       	call   ffffffff8ae86fa0 <handler_640_body-0x5c9e70>
ffffffff8b452de7:	41 80 0f 08          	orb    $0x8,(%r15)
ffffffff8b452deb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8b452df0:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b452df3:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b452df6:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b452df9:	c7 04 24 00 01 00 00 	movl   $0x100,(%rsp)
ffffffff8b452e00:	31 d2                	xor    %edx,%edx
ffffffff8b452e02:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b452e05:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b452e08:	e8 53 34 17 00       	call   ffffffff8b5c6260 <frame_candidate_a92d00+0x173560>
ffffffff8b452e0d:	41 8b 07             	mov    (%r15),%eax
