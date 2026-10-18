; REA 6.7.0 full disassembly of handler_639.bin
; SHA256 518db4b010a92d1a46b872265cdd4971197555e13a446b7c85b334004d113c99; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25f18, kernel RVA 0x265f18.
; REA inspect_with_objdump Evidence: ev_d8f5f497c82ce1bcfc265ec54038aa123dcc1ac7486171a12d61b90f505dd752
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 639; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_639.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25f18 <handler_639_entry>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266f10+0x4578f0>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266f10+0x829f00>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266f10+0x23bed0>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266f10+0x856bc0>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266f10+0x7d0750>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266f10+0x8572b0>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266f10+0x8578a0>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266f10+0x7912e0>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266f10+0x982600>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266f10+0x740e00>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266f10+0x742650>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266f10+0x742f00>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266f10+0x743030>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266f10+0x694530>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266f10+0x23c290>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266f10+0x8579a0>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266f10+0x7442e0>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266f10+0x854a70>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266f10+0x4923d0>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266f10+0x1cde90>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266f10+0x1cdea0>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266f10+0x1cdeb0>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266f10+0x1d0e80>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266f10+0x1d1370>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266f10+0x87f780>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266f10+0x87f670>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266f10+0x1e21c0>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_639_entry-0x1bf158>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266f10+0x1e3b60>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266f10+0x74f200>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_639_entry-0x1be8a8>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_639_entry-0x1be6c8>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_639_entry-0x1be698>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266f10+0x1eb130>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266f10+0x1eddb0>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266f10+0x1f0910>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266f10+0x207060>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266f10+0x207170>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266f10+0x20ba80>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266f10+0x20c4a0>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266f10+0x20c9a0>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266f10+0x20d340>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266f10+0x20dea0>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266f10+0x2160e0>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_639_entry-0x47f28>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266f10+0x2293f0>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266f10+0x229ea0>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266f10+0x2310a0>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266f10+0x2310d0>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266f10+0x231720>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266f10+0x231730>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266f10+0x690cb0>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266f10+0x68f8f0>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266f10+0x690510>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266f10+0x693070>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266f10+0x378440>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266f10+0x378910>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266f10+0x7cddd0>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266f10+0x381590>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266f10+0x6912e0>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266f10+0x692500>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266f10+0x6954e0>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266f10+0x68fd80>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266f10+0xa4ab00>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266f10+0x851490>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266f10+0x8514a0>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266f10+0x6932b0>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266f10+0x690c30>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266f10+0x239a50>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266f10+0x4c2870>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266f10+0x4c2880>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266f10+0x4c2890>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266f10+0x454680>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266f10+0x851e90>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266f10+0x693260>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266f10+0x9181b0>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266f10+0x9181f0>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266f10+0x692de0>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266f10+0x693830>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266f10+0x2ebc60>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266f10+0x2ebce0>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266f10+0x2ebd40>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266f10+0x2ebd70>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266f10+0x2ebda0>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266f10+0x2ebdd0>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266f10+0x9178f0>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266f10+0x917cd0>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266f10+0x918060>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266f10+0x99fe20>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266f10+0x52b780>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266f10+0x381c10>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266f10+0x2ebe00>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266f10+0x918250>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266f10+0x377340>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266f10+0x7edb20>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266f10+0x7edb30>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266f10+0x7edb40>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266f10+0x7edb50>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266f10+0x7edb70>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266f10+0x7edb80>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266f10+0x692810>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266f10+0x7edba0>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266f10+0x68f5d0>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266f10+0x68efe0>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266f10+0x7edb10>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266f10+0x7edb60>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266f10+0x7edb90>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266f10+0x47e5c0>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266f10+0x9185a0>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266f10+0x5d6750>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266f10+0x5d68b0>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266f10+0x5d6ba0>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266f10+0x5d6f70>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266f10+0x692d70>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266f10+0x693200>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266f10+0x6922a0>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266f10+0x6935e0>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266f10+0x691180>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266f10+0x694c70>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266f10+0x690c70>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266f10+0x690980>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266f10+0x694990>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266f10+0x691600>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266f10+0x6918f0>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266f10+0x234170>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266f10+0x234180>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266f10+0x2f8b40>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266f10+0x9cd960>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266f10+0x575de0>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266f10+0x575df0>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266f10+0x575e00>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266f10+0x575e10>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266f10+0x575e20>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266f10+0x33fd80>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266f10+0x3403f0>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266f10+0x340700>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266f10+0x3409f0>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266f10+0xa35920>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266f10+0x340ff0>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266f10+0x341160>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266f10+0x981570>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266f10+0x234190>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266f10+0x2341b0>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266f10+0x2341c0>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266f10+0x2341d0>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266f10+0x2341e0>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266f10+0x2c9810>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266f10+0x2ca760>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266f10+0x6927e0>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266f10+0x2ca320>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266f10+0x59bee0>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266f10+0x918230>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266f10+0x87c6d0>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266f10+0x287f10>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266f10+0x693c00>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266f10+0x693f20>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266f10+0x762310>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266f10+0x7621f0>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266f10+0x3db400>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266f10+0x3db910>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266f10+0x3dc7d0>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266f10+0x3dc9c0>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266f10+0x3dcd50>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266f10+0x791380>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266f10+0x794c60>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266f10+0x7de370>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266f10+0xa20d90>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266f10+0x7980f0>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266f10+0x799870>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266f10+0x7998d0>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266f10+0x857920>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266f10+0x796020>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266f10+0x38a0b0>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266f10+0x6904e0>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266f10+0x290340>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266f10+0x796bc0>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266f10+0x796ea0>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266f10+0x797000>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266f10+0x3dd5c0>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266f10+0x3ea0c0>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266f10+0x797b20>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266f10+0x290a30>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266f10+0x851bd0>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266f10+0x854750>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266f10+0x797350>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266f10+0x7975d0>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266f10+0x797720>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266f10+0x531420>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266f10+0x8560f0>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_639_entry-0x169688>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266f10+0x238180>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266f10+0x2382f0>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266f10+0x259680>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266f10+0x2596a0>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_639_entry-0x1bcae8>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266f10+0x263440>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266f10+0x263b30>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_639_entry-0x1bba08>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266f10+0x26e2c0>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266f10+0x5aa2a0>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_639_entry-0x24b088>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266f10+0x289120>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266f10+0x294cc0>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266f10+0x2a5fc0>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266f10+0x2a5fd0>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266f10+0x2a6020>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266f10+0x2a6060>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266f10+0x2a60a0>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266f10+0x2a60d0>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266f10+0x2b75c0>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266f10+0x2b8050>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266f10+0x2b80f0>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266f10+0x2b81a0>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266f10+0x2b83d0>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266f10+0x2b8760>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266f10+0x2b8fd0>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266f10+0x2cf4f0>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266f10+0x2ddd90>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266f10+0x2df9e0>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_639_entry-0x1b48e8>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_639_entry-0x1b3f68>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266f10+0x2f5030>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266f10+0x2f5120>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266f10+0x2f5140>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266f10+0x3072f0>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266f10+0x318590>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266f10+0x72d6d0>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266f10+0x31ea40>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266f10+0x332910>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266f10+0x3334d0>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266f10+0x333620>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266f10+0x3337f0>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266f10+0x3338c0>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266f10+0x333b40>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266f10+0x333c50>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266f10+0x333d50>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266f10+0x374fc0>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266f10+0x384810>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266f10+0x385120>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266f10+0x385bc0>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266f10+0x386530>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266f10+0x386c20>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_639_entry-0x117c98>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266f10+0x38a9a0>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266f10+0x38bc20>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266f10+0x3961b0>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266f10+0x399770>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266f10+0x39a030>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266f10+0x87f590>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266f10+0x3c6b90>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266f10+0x3c93c0>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266f10+0x3ce000>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266f10+0x3d8610>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266f10+0x3f0aa0>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266f10+0xa40400>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266f10+0x3fbf60>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266f10+0x3fbf70>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266f10+0x411f00>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266f10+0x411f50>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266f10+0x411fb0>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266f10+0x412050>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266f10+0x412280>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266f10+0x412450>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266f10+0x412770>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_639_entry-0x232388>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_639_entry-0x232278>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_639_entry-0x2321f8>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_639_entry-0x228fa8>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_639_entry-0x228e38>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_639_entry-0x2288b8>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_639_entry-0x227e18>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_639_entry-0x227db8>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_639_entry-0x227d58>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_639_entry-0x226ea8>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_639_entry-0x226e48>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_639_entry-0x226a68>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_639_entry-0x226a08>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_639_entry-0x2269a8>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_639_entry-0x226368>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_639_entry-0x225f58>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_639_entry-0x2255b8>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_639_entry-0x2253c8>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_639_entry-0x2252e8>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_639_entry-0x2248e8>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_639_entry-0x2247c8>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_639_entry-0x2246e8>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_639_entry-0x224658>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_639_entry-0x223eb8>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_639_entry-0x223a48>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_639_entry-0x223978>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_639_entry-0x223918>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266f10+0x429120>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266f10+0x42fdb0>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266f10+0x4316c0>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266f10+0x43b140>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266f10+0x43b3a0>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266f10+0x447730>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266f10+0x4478e0>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_639_entry-0xe4b68>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266f10+0x458090>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_639_entry-0xdded8>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266f10+0x469bf0>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266f10+0x46a1f0>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266f10+0x46a350>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266f10+0x46a4d0>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266f10+0x46a610>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266f10+0x46a730>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266f10+0x46a810>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266f10+0x475750>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266f10+0x475780>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266f10+0x475790>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266f10+0x479a10>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266f10+0x47a530>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266f10+0x47a540>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_639_entry-0xdc4a8>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_639_entry-0xd5478>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266f10+0x49ba60>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266f10+0x49be50>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266f10+0x49f260>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266f10+0x49f2e0>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266f10+0x4a8ff0>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266f10+0x4a90a0>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266f10+0x4a92b0>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266f10+0x4a9410>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266f10+0x4abca0>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266f10+0x4af450>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266f10+0x4c8a60>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266f10+0x4c8a80>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266f10+0x4c8b10>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_639_entry-0x1f0e8>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266f10+0x4fd8e0>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266f10+0x50c800>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266f10+0x50ea40>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266f10+0x532f80>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266f10+0x54c2e0>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266f10+0x57b490>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266f10+0x5814d0>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266f10+0x581570>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266f10+0x9d42a0>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266f10+0x9d57d0>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266f10+0x9d5780>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266f10+0x9d5820>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266f10+0x59b310>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266f10+0x59b5e0>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266f10+0x5a5660>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266f10+0x5c43f0>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266f10+0x6b9fd0>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266f10+0x6b9c80>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266f10+0x5c9900>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266f10+0x5c9ff0>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266f10+0x5ce3a0>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266f10+0x5ce3b0>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266f10+0x5ce3c0>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266f10+0x5ce3e0>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266f10+0x5ce530>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266f10+0x5ce540>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266f10+0x5ce580>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266f10+0x5cebc0>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266f10+0x5e9960>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266f10+0x6093e0>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266f10+0x6096c0>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266f10+0x60bbe0>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266f10+0x60c8f0>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_639_entry-0x2024d8>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_639_entry-0x1ffba8>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_639_entry-0x17f988>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_639_entry-0x17f978>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_639_entry-0x17f7b8>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_639_entry-0x17f6a8>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_639_entry-0x17df88>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_639_entry-0x17bf78>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_639_entry-0x17b8a8>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_639_entry-0x17b7b8>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_639_entry-0x17ae78>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_639_entry-0x17ad88>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_639_entry-0x178f18>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_639_entry-0x178e08>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266f10+0x623990>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266f10+0x635ee0>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_639_entry-0x1773c8>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266f10+0x664340>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266f10+0x664480>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266f10+0x66c050>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266f10+0x66c080>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266f10+0x671320>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266f10+0x671ed0>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266f10+0x6728a0>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266f10+0x672a00>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266f10+0x6735b0>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266f10+0x673660>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266f10+0x6736a0>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266f10+0x69dd70>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266f10+0x69df50>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266f10+0x6b64f0>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266f10+0x6b6590>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266f10+0x81b2c0>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266f10+0x8db210>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266f10+0x6fe020>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266f10+0x70f040>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266f10+0x70f2f0>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266f10+0x725a40>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266f10+0x725d20>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266f10+0x726020>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266f10+0x7267d0>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266f10+0x7276c0>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266f10+0x7277f0>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266f10+0x72b260>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266f10+0x72b330>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_639_entry-0x170b18>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266f10+0x73b410>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266f10+0x73e810>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266f10+0x745a90>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266f10+0x745b10>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_639_entry-0xa78d8>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266f10+0x757e10>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266f10+0x75f140>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266f10+0x75f1c0>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266f10+0x75f370>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266f10+0x75f400>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266f10+0x75f580>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266f10+0x75f6a0>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266f10+0x75f980>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266f10+0x762430>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266f10+0x762450>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266f10+0x762460>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266f10+0x762470>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266f10+0x773ea0>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266f10+0x774090>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266f10+0x775950>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266f10+0x775d30>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266f10+0x775f70>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266f10+0x7765f0>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266f10+0xa43dc0>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266f10+0x7768c0>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266f10+0x776a80>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266f10+0x776c90>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266f10+0x776cf0>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266f10+0x776f40>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266f10+0x776fa0>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266f10+0x7770e0>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266f10+0x777160>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266f10+0x7771e0>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266f10+0x779c80>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266f10+0x779dc0>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266f10+0x779e60>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266f10+0x779fe0>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266f10+0x77a140>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266f10+0x77a580>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266f10+0x79f6d0>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_639_entry-0x164bd8>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266f10+0x7cc020>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266f10+0x7cc7b0>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266f10+0x7d1d80>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266f10+0x803bf0>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266f10+0x803ca0>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266f10+0x827d00>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266f10+0x827ef0>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266f10+0x84a8a0>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266f10+0x8598a0>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266f10+0x85bbe0>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_639_entry-0x14b7c8>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266f10+0x87a390>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266f10+0x87c4f0>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266f10+0x87c620>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266f10+0x87f4b0>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266f10+0x8a0fd0>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266f10+0x8a1280>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266f10+0x8a1620>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266f10+0x8a1900>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266f10+0x8a2790>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266f10+0x8a45e0>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_639_entry-0x76e28>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_639_entry-0x75eb8>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_639_entry-0x14a568>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266f10+0x8d4220>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266f10+0x8e0b30>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266f10+0x8e94b0>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266f10+0x8ea000>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266f10+0x8ea0a0>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266f10+0x8ea1a0>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266f10+0x8ea280>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266f10+0x8ea380>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266f10+0x8ea3c0>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266f10+0x8ea410>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266f10+0x8ef990>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_639_entry-0x1cbe38>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266f10+0x903f60>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266f10+0x904c80>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266f10+0x906a70>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266f10+0x906b90>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266f10+0x907270>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266f10+0x90a410>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266f10+0x90a460>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266f10+0x90a4b0>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266f10+0x90a500>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266f10+0x90aa50>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266f10+0x90aac0>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266f10+0x90ab30>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266f10+0x90aba0>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266f10+0x90b710>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

ffffffff8ac26eb8 <neighbor_trampoline_266eb8>:
ffffffff8ac26eb8:	e9 a3 b9 90 00       	jmp    ffffffff8b532860 <neighbor_trampoline_266f10+0x90b950>
ffffffff8ac26ebd:	cc                   	int3
ffffffff8ac26ebe:	cc                   	int3
ffffffff8ac26ebf:	cc                   	int3

ffffffff8ac26ec0 <neighbor_trampoline_266ec0>:
ffffffff8ac26ec0:	e9 0b 23 91 00       	jmp    ffffffff8b5391d0 <neighbor_trampoline_266f10+0x9122c0>
ffffffff8ac26ec5:	cc                   	int3
ffffffff8ac26ec6:	cc                   	int3
ffffffff8ac26ec7:	cc                   	int3

ffffffff8ac26ec8 <neighbor_trampoline_266ec8>:
ffffffff8ac26ec8:	e9 c3 23 91 00       	jmp    ffffffff8b539290 <neighbor_trampoline_266f10+0x912380>
ffffffff8ac26ecd:	cc                   	int3
ffffffff8ac26ece:	cc                   	int3
ffffffff8ac26ecf:	cc                   	int3

ffffffff8ac26ed0 <neighbor_trampoline_266ed0>:
ffffffff8ac26ed0:	e9 1b 25 91 00       	jmp    ffffffff8b5393f0 <neighbor_trampoline_266f10+0x9124e0>
ffffffff8ac26ed5:	cc                   	int3
ffffffff8ac26ed6:	cc                   	int3
ffffffff8ac26ed7:	cc                   	int3

ffffffff8ac26ed8 <neighbor_trampoline_266ed8>:
ffffffff8ac26ed8:	e9 43 25 91 00       	jmp    ffffffff8b539420 <neighbor_trampoline_266f10+0x912510>
ffffffff8ac26edd:	cc                   	int3
ffffffff8ac26ede:	cc                   	int3
ffffffff8ac26edf:	cc                   	int3

ffffffff8ac26ee0 <neighbor_trampoline_266ee0>:
ffffffff8ac26ee0:	e9 7b 25 91 00       	jmp    ffffffff8b539460 <neighbor_trampoline_266f10+0x912550>
ffffffff8ac26ee5:	cc                   	int3
ffffffff8ac26ee6:	cc                   	int3
ffffffff8ac26ee7:	cc                   	int3

ffffffff8ac26ee8 <neighbor_trampoline_266ee8>:
ffffffff8ac26ee8:	e9 93 25 91 00       	jmp    ffffffff8b539480 <neighbor_trampoline_266f10+0x912570>
ffffffff8ac26eed:	cc                   	int3
ffffffff8ac26eee:	cc                   	int3
ffffffff8ac26eef:	cc                   	int3

ffffffff8ac26ef0 <neighbor_trampoline_266ef0>:
ffffffff8ac26ef0:	e9 9b 25 91 00       	jmp    ffffffff8b539490 <neighbor_trampoline_266f10+0x912580>
ffffffff8ac26ef5:	cc                   	int3
ffffffff8ac26ef6:	cc                   	int3
ffffffff8ac26ef7:	cc                   	int3

ffffffff8ac26ef8 <neighbor_trampoline_266ef8>:
ffffffff8ac26ef8:	e9 b3 25 91 00       	jmp    ffffffff8b5394b0 <neighbor_trampoline_266f10+0x9125a0>
ffffffff8ac26efd:	cc                   	int3
ffffffff8ac26efe:	cc                   	int3
ffffffff8ac26eff:	cc                   	int3

ffffffff8ac26f00 <neighbor_trampoline_266f00>:
ffffffff8ac26f00:	e9 eb 26 91 00       	jmp    ffffffff8b5395f0 <neighbor_trampoline_266f10+0x9126e0>
ffffffff8ac26f05:	cc                   	int3
ffffffff8ac26f06:	cc                   	int3
ffffffff8ac26f07:	cc                   	int3

ffffffff8ac26f08 <neighbor_trampoline_266f08>:
ffffffff8ac26f08:	e9 13 27 91 00       	jmp    ffffffff8b539620 <neighbor_trampoline_266f10+0x912710>
ffffffff8ac26f0d:	cc                   	int3
ffffffff8ac26f0e:	cc                   	int3
ffffffff8ac26f0f:	cc                   	int3

ffffffff8ac26f10 <neighbor_trampoline_266f10>:
ffffffff8ac26f10:	e9 1b 29 91 00       	jmp    ffffffff8b539830 <neighbor_trampoline_266f10+0x912920>
ffffffff8ac26f15:	cc                   	int3
ffffffff8ac26f16:	cc                   	int3
ffffffff8ac26f17:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8b07e800, handler_body_639; REA Evidence ev_5e70ad79608dfb5504ea3e2ee918df169630734faffbc3de6d437a53a49c3f0b
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8b07e800", "end": "0xffffffff8b07e868"}, {"start": "0xffffffff8b07e870", "end": "0xffffffff8b07e8a0"}, {"start": "0xffffffff8b07e8b0", "end": "0xffffffff8b07eb12"}], "total_bytes": 765, "span_bytes": 787, "non_contiguous": true, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_639:
0xffffffff8b07e800: PUSH RBP
0xffffffff8b07e801: MOV RBP, RSP
0xffffffff8b07e804: PUSH R15
0xffffffff8b07e806: PUSH R14
0xffffffff8b07e808: PUSH RBX
0xffffffff8b07e809: SUB RSP, 0x28
0xffffffff8b07e80d: LEA R15, [-0x71d23cf0]
0xffffffff8b07e814: LEA RDI, [-0x71d2a700]
0xffffffff8b07e81b: MOV RBX, RSI
0xffffffff8b07e81e: XOR ESI, ESI
0xffffffff8b07e820: XOR EDX, EDX
0xffffffff8b07e822: XOR ECX, ECX
0xffffffff8b07e824: MOV RAX, qword ptr [R15]
0xffffffff8b07e827: MOV qword ptr [RBP + -0x20], RAX
0xffffffff8b07e82b: MOV dword ptr [RBP + -0x3c], 0x0
0xffffffff8b07e832: CALL 0xffffffff8b60b350
0xffffffff8b07e837: MOV EAX, dword ptr [0xffffffff8e2d7920]
0xffffffff8b07e83d: TEST EAX, EAX
0xffffffff8b07e83f: JZ 0xffffffff8b07e961
loc_ffffffff8b07e845:
0xffffffff8b07e845: MOV ESI, dword ptr [0xffffffff8e4305b0]
0xffffffff8b07e84b: MOV ECX, 0x1
0xffffffff8b07e850: CMP EAX, 0x2
0xffffffff8b07e853: JL 0xffffffff8b07e8cc
loc_ffffffff8b07e855:
0xffffffff8b07e855: MOV RDX, qword ptr [RBX]
0xffffffff8b07e858: MOV ECX, 0x1
0xffffffff8b07e85d: LEA RDI, [-0x71d2a6e0]
0xffffffff8b07e864: MOV R8D, EAX
0xffffffff8b07e867: JMP 0xffffffff8b07e87b
loc_ffffffff8b07e870:
0xffffffff8b07e870: INC R9D
0xffffffff8b07e873: MOV ECX, R9D
0xffffffff8b07e876: CMP ECX, R8D
0xffffffff8b07e879: JGE 0xffffffff8b07e8cc
loc_ffffffff8b07e87b:
0xffffffff8b07e87b: LEA R10D, [R8 + RCX*0x1]
0xffffffff8b07e87f: MOV R9D, R10D
0xffffffff8b07e882: SHR R9D, 0x1f
0xffffffff8b07e886: ADD R9D, R10D
0xffffffff8b07e889: SAR R9D, 0x1
0xffffffff8b07e88c: MOVSXD R10, R9D
0xffffffff8b07e88f: SHL R10, 0x4
0xffffffff8b07e893: TEST ESI, ESI
0xffffffff8b07e895: JS 0xffffffff8b07e8b0
loc_ffffffff8b07e897:
0xffffffff8b07e897: LEA R11, [RDI + R10*0x1]
0xffffffff8b07e89b: MOVSXD R11, dword ptr [R11 + 0xc]
0xffffffff8b07e89f: JMP 0xffffffff8b07e8b3
loc_ffffffff8b07e8b0:
0xffffffff8b07e8b0: XOR R11D, R11D
loc_ffffffff8b07e8b3:
0xffffffff8b07e8b3: MOVSXD R14, dword ptr [R10 + RDI*0x1 + 0x8]
0xffffffff8b07e8b8: ADD R14, qword ptr [R10 + RDI*0x1]
0xffffffff8b07e8bc: ADD R14, R11
0xffffffff8b07e8bf: CMP R14, RDX
0xffffffff8b07e8c2: JLE 0xffffffff8b07e870
loc_ffffffff8b07e8c4:
0xffffffff8b07e8c4: MOV R8D, R9D
0xffffffff8b07e8c7: CMP ECX, R8D
0xffffffff8b07e8ca: JL 0xffffffff8b07e87b
loc_ffffffff8b07e8cc:
0xffffffff8b07e8cc: LEA EDX, [RCX + -0x1]
0xffffffff8b07e8cf: TEST ESI, ESI
0xffffffff8b07e8d1: JS 0xffffffff8b07e97b
loc_ffffffff8b07e8d7:
0xffffffff8b07e8d7: MOV ESI, dword ptr [RBX + 0x8]
0xffffffff8b07e8da: TEST ESI, ESI
0xffffffff8b07e8dc: SETS DIL
0xffffffff8b07e8e0: CMP ECX, 0x2
0xffffffff8b07e8e3: SETL R8B
0xffffffff8b07e8e7: OR R8B, DIL
0xffffffff8b07e8ea: JNZ 0xffffffff8b07e99f
loc_ffffffff8b07e8f0:
0xffffffff8b07e8f0: MOV R8D, EDX
0xffffffff8b07e8f3: LEA R9D, [RCX + -0x2]
0xffffffff8b07e8f7: LEA RDI, [-0x71d2a6e0]
0xffffffff8b07e8fe: MOV R10, R8
0xffffffff8b07e901: MOV R11, R9
0xffffffff8b07e904: SHL R11, 0x4
0xffffffff8b07e908: SHL R10, 0x4
0xffffffff8b07e90c: MOVSXD R14, dword ptr [R11 + RDI*0x1 + 0x8]
0xffffffff8b07e911: ADD R14, qword ptr [R10 + RDI*0x1]
0xffffffff8b07e915: MOVSXD R10, dword ptr [R11 + RDI*0x1 + 0xc]
0xffffffff8b07e91a: ADD R14, R10
0xffffffff8b07e91d: CMP qword ptr [RBX], R14
0xffffffff8b07e920: JGE 0xffffffff8b07e93f
loc_ffffffff8b07e922:
0xffffffff8b07e922: MOV R8D, R10D
0xffffffff8b07e925: OR R8D, ESI
0xffffffff8b07e928: MOV R8D, EDX
0xffffffff8b07e92b: CMOVZ R8D, R9D
0xffffffff8b07e92f: TEST R10D, R10D
0xffffffff8b07e932: CMOVLE R9D, R8D
0xffffffff8b07e936: TEST ESI, ESI
0xffffffff8b07e938: CMOVZ R9D, R8D
0xffffffff8b07e93c: MOV R8, R9
loc_ffffffff8b07e93f:
0xffffffff8b07e93f: SHL R8, 0x4
0xffffffff8b07e943: MOV dword ptr [RBP + -0x3c], 0x0
0xffffffff8b07e94a: MOV R9, qword ptr [R8 + RDI*0x1]
0xffffffff8b07e94e: LEA RSI, [RDI + R8*0x1]
0xffffffff8b07e952: MOV RDI, qword ptr [R8 + RDI*0x1 + 0x8]
0xffffffff8b07e957: MOV qword ptr [RBP + -0x28], RDI
0xffffffff8b07e95b: MOV qword ptr [RBP + -0x30], R9
0xffffffff8b07e95f: JMP 0xffffffff8b07e9cd
loc_ffffffff8b07e961:
0xffffffff8b07e961: LEA RDI, [-0x71d2a700]
0xffffffff8b07e968: XOR ESI, ESI
0xffffffff8b07e96a: XOR EDX, EDX
0xffffffff8b07e96c: CALL 0xffffffff8b60c300
0xffffffff8b07e971: MOV EAX, 0x22
0xffffffff8b07e976: JMP 0xffffffff8b07eaf8
loc_ffffffff8b07e97b:
0xffffffff8b07e97b: MOVSXD RAX, EDX
0xffffffff8b07e97e: LEA RCX, [-0x71d2a6e0]
0xffffffff8b07e985: SHL RAX, 0x4
0xffffffff8b07e989: MOV RDX, qword ptr [RAX + RCX*0x1]
0xffffffff8b07e98d: MOV RAX, qword ptr [RAX + RCX*0x1 + 0x8]
0xffffffff8b07e992: MOV qword ptr [RBP + -0x28], RAX
0xffffffff8b07e996: MOV qword ptr [RBP + -0x30], RDX
0xffffffff8b07e99a: JMP 0xffffffff8b07ea1e
loc_ffffffff8b07e99f:
0xffffffff8b07e99f: MOVSXD RDI, EDX
0xffffffff8b07e9a2: LEA R8, [-0x71d2a6e0]
0xffffffff8b07e9a9: MOV dword ptr [RBP + -0x3c], 0x0
0xffffffff8b07e9b0: SHL RDI, 0x4
0xffffffff8b07e9b4: MOV R9, qword ptr [RDI + R8*0x1]
0xffffffff8b07e9b8: LEA RSI, [R8 + RDI*0x1]
0xffffffff8b07e9bc: MOV RDI, qword ptr [RDI + R8*0x1 + 0x8]
0xffffffff8b07e9c1: MOV qword ptr [RBP + -0x28], RDI
0xffffffff8b07e9c5: MOV qword ptr [RBP + -0x30], R9
0xffffffff8b07e9c9: TEST ECX, ECX
0xffffffff8b07e9cb: JLE 0xffffffff8b07e9f7
loc_ffffffff8b07e9cd:
0xffffffff8b07e9cd: LEA RDI, [-0x71d2a6e0]
0xffffffff8b07e9d4: NOP word ptr CS:[RAX + RAX*0x1]
loc_ffffffff8b07e9e0:
0xffffffff8b07e9e0: DEC ECX
0xffffffff8b07e9e2: MOV R8, RCX
0xffffffff8b07e9e5: SHL R8, 0x4
0xffffffff8b07e9e9: MOV R8D, dword ptr [R8 + RDI*0x1 + 0xc]
0xffffffff8b07e9ee: TEST R8D, R8D
0xffffffff8b07e9f1: JNZ 0xffffffff8b07e9ff
loc_ffffffff8b07e9f3:
0xffffffff8b07e9f3: TEST ECX, ECX
0xffffffff8b07e9f5: JG 0xffffffff8b07e9e0
loc_ffffffff8b07e9f7:
0xffffffff8b07e9f7: XOR ECX, ECX
0xffffffff8b07e9f9: CMP EDX, EAX
0xffffffff8b07e9fb: JC 0xffffffff8b07ea0c
loc_ffffffff8b07e9fd:
0xffffffff8b07e9fd: JMP 0xffffffff8b07ea1e
loc_ffffffff8b07e9ff:
0xffffffff8b07e9ff: CMP EDX, ECX
0xffffffff8b07ea01: MOV dword ptr [RBP + -0x3c], R8D
0xffffffff8b07ea05: SETLE CL
0xffffffff8b07ea08: CMP EDX, EAX
0xffffffff8b07ea0a: JNC 0xffffffff8b07ea1e
loc_ffffffff8b07ea0c:
0xffffffff8b07ea0c: MOV EAX, dword ptr [RSI + 0xc]
0xffffffff8b07ea0f: TEST EAX, EAX
0xffffffff8b07ea11: SETZ DL
0xffffffff8b07ea14: OR DL, CL
0xffffffff8b07ea16: TEST DL, 0x1
0xffffffff8b07ea19: JNZ 0xffffffff8b07ea1e
loc_ffffffff8b07ea1b:
0xffffffff8b07ea1b: MOV dword ptr [RBP + -0x3c], EAX
loc_ffffffff8b07ea1e:
0xffffffff8b07ea1e: LEA RDI, [-0x71d2a700]
0xffffffff8b07ea25: XOR ESI, ESI
0xffffffff8b07ea27: XOR EDX, EDX
0xffffffff8b07ea29: CALL 0xffffffff8b60c300
0xffffffff8b07ea2e: CMP dword ptr [0xffffffff8e4305b0], 0x0
0xffffffff8b07ea35: JS 0xffffffff8b07ea3d
loc_ffffffff8b07ea37:
0xffffffff8b07ea37: MOVSXD RAX, dword ptr [RBP + -0x24]
0xffffffff8b07ea3b: JMP 0xffffffff8b07ea46
loc_ffffffff8b07ea3d:
0xffffffff8b07ea3d: XOR EAX, EAX
0xffffffff8b07ea3f: MOV dword ptr [RBP + -0x24], 0x0
loc_ffffffff8b07ea46:
0xffffffff8b07ea46: MOVSXD RDX, dword ptr [RBP + -0x28]
0xffffffff8b07ea4a: MOV RCX, qword ptr [RBX]
0xffffffff8b07ea4d: ADD RDX, RAX
0xffffffff8b07ea50: SUB RCX, RDX
0xffffffff8b07ea53: MOV qword ptr [RBP + -0x38], RCX
0xffffffff8b07ea57: MOV R14, qword ptr [RBX + 0x10]
0xffffffff8b07ea5b: TEST R14, R14
0xffffffff8b07ea5e: JZ 0xffffffff8b07ea8c
loc_ffffffff8b07ea60:
0xffffffff8b07ea60: MOV RDI, qword ptr GS:[0x0]
0xffffffff8b07ea69: LEA RSI, [-0x742f0d69]
0xffffffff8b07ea70: XOR EDX, EDX
0xffffffff8b07ea72: CALL 0xffffffff8b5da3e0
0xffffffff8b07ea77: LEA RDI, [RBP + -0x38]
0xffffffff8b07ea7b: MOV EDX, 0x8
0xffffffff8b07ea80: MOV RSI, R14
0xffffffff8b07ea83: CALL 0xffffffff8ac191d0
0xffffffff8b07ea88: TEST EAX, EAX
0xffffffff8b07ea8a: JNZ 0xffffffff8b07eaf8
loc_ffffffff8b07ea8c:
0xffffffff8b07ea8c: MOV R14, qword ptr [RBX + 0x18]
0xffffffff8b07ea90: TEST R14, R14
0xffffffff8b07ea93: JZ 0xffffffff8b07eac1
loc_ffffffff8b07ea95:
0xffffffff8b07ea95: MOV RDI, qword ptr GS:[0x0]
0xffffffff8b07ea9e: LEA RSI, [-0x742f0d69]
0xffffffff8b07eaa5: XOR EDX, EDX
0xffffffff8b07eaa7: CALL 0xffffffff8b5da3e0
0xffffffff8b07eaac: LEA RDI, [RBP + -0x30]
0xffffffff8b07eab0: MOV EDX, 0x10
0xffffffff8b07eab5: MOV RSI, R14
0xffffffff8b07eab8: CALL 0xffffffff8ac191d0
0xffffffff8b07eabd: TEST EAX, EAX
0xffffffff8b07eabf: JNZ 0xffffffff8b07eaf8
loc_ffffffff8b07eac1:
0xffffffff8b07eac1: MOV RBX, qword ptr [RBX + 0x20]
0xffffffff8b07eac5: TEST RBX, RBX
0xffffffff8b07eac8: JZ 0xffffffff8b07eaf6
loc_ffffffff8b07eaca:
0xffffffff8b07eaca: MOV RDI, qword ptr GS:[0x0]
0xffffffff8b07ead3: LEA RSI, [-0x742f0d69]
0xffffffff8b07eada: XOR EDX, EDX
0xffffffff8b07eadc: CALL 0xffffffff8b5da3e0
0xffffffff8b07eae1: LEA RDI, [RBP + -0x3c]
0xffffffff8b07eae5: MOV EDX, 0x4
0xffffffff8b07eaea: MOV RSI, RBX
0xffffffff8b07eaed: CALL 0xffffffff8ac191d0
0xffffffff8b07eaf2: TEST EAX, EAX
0xffffffff8b07eaf4: JNZ 0xffffffff8b07eaf8
loc_ffffffff8b07eaf6:
0xffffffff8b07eaf6: XOR EAX, EAX
loc_ffffffff8b07eaf8:
0xffffffff8b07eaf8: MOV RCX, qword ptr [R15]
0xffffffff8b07eafb: CMP RCX, qword ptr [RBP + -0x20]
0xffffffff8b07eaff: JNZ 0xffffffff8b07eb0c
loc_ffffffff8b07eb01:
0xffffffff8b07eb01: ADD RSP, 0x28
0xffffffff8b07eb05: POP RBX
0xffffffff8b07eb06: POP R14
0xffffffff8b07eb08: POP R15
0xffffffff8b07eb0a: POP RBP
0xffffffff8b07eb0b: RET
loc_ffffffff8b07eb0c:
0xffffffff8b07eb0c: CALL 0xffffffff8b0bd6b0
0xffffffff8b07eb11: UD2
; END FUNCTION handler_body_639

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_4bb1c7508b3d6dd4d666ab770150998edddf69db592d0387e5fa0330b0480913
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_639.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8b07e800 <handler_639_body>:
ffffffff8b07e800:	55                   	push   %rbp
ffffffff8b07e801:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07e804:	41 57                	push   %r15
ffffffff8b07e806:	41 56                	push   %r14
ffffffff8b07e808:	53                   	push   %rbx
ffffffff8b07e809:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8b07e80d:	4c 8d 3d fc da 25 03 	lea    0x325dafc(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_6c0080+0x325c290>
ffffffff8b07e814:	48 8d 3d e5 70 25 03 	lea    0x32570e5(%rip),%rdi        # ffffffff8e2d5900 <frame_candidate_6c0080+0x3255880>
ffffffff8b07e81b:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b07e81e:	31 f6                	xor    %esi,%esi
ffffffff8b07e820:	31 d2                	xor    %edx,%edx
ffffffff8b07e822:	31 c9                	xor    %ecx,%ecx
ffffffff8b07e824:	49 8b 07             	mov    (%r15),%rax
ffffffff8b07e827:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b07e82b:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
ffffffff8b07e832:	e8 19 cb 58 00       	call   ffffffff8b60b350 <frame_candidate_6c0080+0x58b2d0>
ffffffff8b07e837:	8b 05 e3 90 25 03    	mov    0x32590e3(%rip),%eax        # ffffffff8e2d7920 <frame_candidate_6c0080+0x32578a0>
ffffffff8b07e83d:	85 c0                	test   %eax,%eax
ffffffff8b07e83f:	0f 84 1c 01 00 00    	je     ffffffff8b07e961 <handler_639_body+0x161>
ffffffff8b07e845:	8b 35 65 1d 3b 03    	mov    0x33b1d65(%rip),%esi        # ffffffff8e4305b0 <frame_candidate_6c0080+0x33b0530>
ffffffff8b07e84b:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b07e850:	83 f8 02             	cmp    $0x2,%eax
ffffffff8b07e853:	7c 77                	jl     ffffffff8b07e8cc <handler_639_body+0xcc>
ffffffff8b07e855:	48 8b 13             	mov    (%rbx),%rdx
ffffffff8b07e858:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b07e85d:	48 8d 3d bc 70 25 03 	lea    0x32570bc(%rip),%rdi        # ffffffff8e2d5920 <frame_candidate_6c0080+0x32558a0>
ffffffff8b07e864:	41 89 c0             	mov    %eax,%r8d
ffffffff8b07e867:	eb 12                	jmp    ffffffff8b07e87b <handler_639_body+0x7b>
ffffffff8b07e869:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8b07e870:	41 ff c1             	inc    %r9d
ffffffff8b07e873:	44 89 c9             	mov    %r9d,%ecx
ffffffff8b07e876:	44 39 c1             	cmp    %r8d,%ecx
ffffffff8b07e879:	7d 51                	jge    ffffffff8b07e8cc <handler_639_body+0xcc>
ffffffff8b07e87b:	45 8d 14 08          	lea    (%r8,%rcx,1),%r10d
ffffffff8b07e87f:	45 89 d1             	mov    %r10d,%r9d
ffffffff8b07e882:	41 c1 e9 1f          	shr    $0x1f,%r9d
ffffffff8b07e886:	45 01 d1             	add    %r10d,%r9d
ffffffff8b07e889:	41 d1 f9             	sar    $1,%r9d
ffffffff8b07e88c:	4d 63 d1             	movslq %r9d,%r10
ffffffff8b07e88f:	49 c1 e2 04          	shl    $0x4,%r10
ffffffff8b07e893:	85 f6                	test   %esi,%esi
ffffffff8b07e895:	78 19                	js     ffffffff8b07e8b0 <handler_639_body+0xb0>
ffffffff8b07e897:	4e 8d 1c 17          	lea    (%rdi,%r10,1),%r11
ffffffff8b07e89b:	4d 63 5b 0c          	movslq 0xc(%r11),%r11
ffffffff8b07e89f:	eb 12                	jmp    ffffffff8b07e8b3 <handler_639_body+0xb3>
ffffffff8b07e8a1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b07e8a8:	0f 1f 84 00 00 00 00 
ffffffff8b07e8af:	00 
ffffffff8b07e8b0:	45 31 db             	xor    %r11d,%r11d
ffffffff8b07e8b3:	4d 63 74 3a 08       	movslq 0x8(%r10,%rdi,1),%r14
ffffffff8b07e8b8:	4d 03 34 3a          	add    (%r10,%rdi,1),%r14
ffffffff8b07e8bc:	4d 01 de             	add    %r11,%r14
ffffffff8b07e8bf:	49 39 d6             	cmp    %rdx,%r14
ffffffff8b07e8c2:	7e ac                	jle    ffffffff8b07e870 <handler_639_body+0x70>
ffffffff8b07e8c4:	45 89 c8             	mov    %r9d,%r8d
ffffffff8b07e8c7:	44 39 c1             	cmp    %r8d,%ecx
ffffffff8b07e8ca:	7c af                	jl     ffffffff8b07e87b <handler_639_body+0x7b>
ffffffff8b07e8cc:	8d 51 ff             	lea    -0x1(%rcx),%edx
ffffffff8b07e8cf:	85 f6                	test   %esi,%esi
ffffffff8b07e8d1:	0f 88 a4 00 00 00    	js     ffffffff8b07e97b <handler_639_body+0x17b>
ffffffff8b07e8d7:	8b 73 08             	mov    0x8(%rbx),%esi
ffffffff8b07e8da:	85 f6                	test   %esi,%esi
ffffffff8b07e8dc:	40 0f 98 c7          	sets   %dil
ffffffff8b07e8e0:	83 f9 02             	cmp    $0x2,%ecx
ffffffff8b07e8e3:	41 0f 9c c0          	setl   %r8b
ffffffff8b07e8e7:	41 08 f8             	or     %dil,%r8b
ffffffff8b07e8ea:	0f 85 af 00 00 00    	jne    ffffffff8b07e99f <handler_639_body+0x19f>
ffffffff8b07e8f0:	41 89 d0             	mov    %edx,%r8d
ffffffff8b07e8f3:	44 8d 49 fe          	lea    -0x2(%rcx),%r9d
ffffffff8b07e8f7:	48 8d 3d 22 70 25 03 	lea    0x3257022(%rip),%rdi        # ffffffff8e2d5920 <frame_candidate_6c0080+0x32558a0>
ffffffff8b07e8fe:	4d 89 c2             	mov    %r8,%r10
ffffffff8b07e901:	4d 89 cb             	mov    %r9,%r11
ffffffff8b07e904:	49 c1 e3 04          	shl    $0x4,%r11
ffffffff8b07e908:	49 c1 e2 04          	shl    $0x4,%r10
ffffffff8b07e90c:	4d 63 74 3b 08       	movslq 0x8(%r11,%rdi,1),%r14
ffffffff8b07e911:	4d 03 34 3a          	add    (%r10,%rdi,1),%r14
ffffffff8b07e915:	4d 63 54 3b 0c       	movslq 0xc(%r11,%rdi,1),%r10
ffffffff8b07e91a:	4d 01 d6             	add    %r10,%r14
ffffffff8b07e91d:	4c 39 33             	cmp    %r14,(%rbx)
ffffffff8b07e920:	7d 1d                	jge    ffffffff8b07e93f <handler_639_body+0x13f>
ffffffff8b07e922:	45 89 d0             	mov    %r10d,%r8d
ffffffff8b07e925:	41 09 f0             	or     %esi,%r8d
ffffffff8b07e928:	41 89 d0             	mov    %edx,%r8d
ffffffff8b07e92b:	45 0f 44 c1          	cmove  %r9d,%r8d
ffffffff8b07e92f:	45 85 d2             	test   %r10d,%r10d
ffffffff8b07e932:	45 0f 4e c8          	cmovle %r8d,%r9d
ffffffff8b07e936:	85 f6                	test   %esi,%esi
ffffffff8b07e938:	45 0f 44 c8          	cmove  %r8d,%r9d
ffffffff8b07e93c:	4d 89 c8             	mov    %r9,%r8
ffffffff8b07e93f:	49 c1 e0 04          	shl    $0x4,%r8
ffffffff8b07e943:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
ffffffff8b07e94a:	4d 8b 0c 38          	mov    (%r8,%rdi,1),%r9
ffffffff8b07e94e:	4a 8d 34 07          	lea    (%rdi,%r8,1),%rsi
ffffffff8b07e952:	49 8b 7c 38 08       	mov    0x8(%r8,%rdi,1),%rdi
ffffffff8b07e957:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
ffffffff8b07e95b:	4c 89 4d d0          	mov    %r9,-0x30(%rbp)
ffffffff8b07e95f:	eb 6c                	jmp    ffffffff8b07e9cd <handler_639_body+0x1cd>
ffffffff8b07e961:	48 8d 3d 98 6f 25 03 	lea    0x3256f98(%rip),%rdi        # ffffffff8e2d5900 <frame_candidate_6c0080+0x3255880>
ffffffff8b07e968:	31 f6                	xor    %esi,%esi
ffffffff8b07e96a:	31 d2                	xor    %edx,%edx
ffffffff8b07e96c:	e8 8f d9 58 00       	call   ffffffff8b60c300 <frame_candidate_6c0080+0x58c280>
ffffffff8b07e971:	b8 22 00 00 00       	mov    $0x22,%eax
ffffffff8b07e976:	e9 7d 01 00 00       	jmp    ffffffff8b07eaf8 <handler_639_body+0x2f8>
ffffffff8b07e97b:	48 63 c2             	movslq %edx,%rax
ffffffff8b07e97e:	48 8d 0d 9b 6f 25 03 	lea    0x3256f9b(%rip),%rcx        # ffffffff8e2d5920 <frame_candidate_6c0080+0x32558a0>
ffffffff8b07e985:	48 c1 e0 04          	shl    $0x4,%rax
ffffffff8b07e989:	48 8b 14 08          	mov    (%rax,%rcx,1),%rdx
ffffffff8b07e98d:	48 8b 44 08 08       	mov    0x8(%rax,%rcx,1),%rax
ffffffff8b07e992:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
ffffffff8b07e996:	48 89 55 d0          	mov    %rdx,-0x30(%rbp)
ffffffff8b07e99a:	e9 7f 00 00 00       	jmp    ffffffff8b07ea1e <handler_639_body+0x21e>
ffffffff8b07e99f:	48 63 fa             	movslq %edx,%rdi
ffffffff8b07e9a2:	4c 8d 05 77 6f 25 03 	lea    0x3256f77(%rip),%r8        # ffffffff8e2d5920 <frame_candidate_6c0080+0x32558a0>
ffffffff8b07e9a9:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
ffffffff8b07e9b0:	48 c1 e7 04          	shl    $0x4,%rdi
ffffffff8b07e9b4:	4e 8b 0c 07          	mov    (%rdi,%r8,1),%r9
ffffffff8b07e9b8:	49 8d 34 38          	lea    (%r8,%rdi,1),%rsi
ffffffff8b07e9bc:	4a 8b 7c 07 08       	mov    0x8(%rdi,%r8,1),%rdi
ffffffff8b07e9c1:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
ffffffff8b07e9c5:	4c 89 4d d0          	mov    %r9,-0x30(%rbp)
ffffffff8b07e9c9:	85 c9                	test   %ecx,%ecx
ffffffff8b07e9cb:	7e 2a                	jle    ffffffff8b07e9f7 <handler_639_body+0x1f7>
ffffffff8b07e9cd:	48 8d 3d 4c 6f 25 03 	lea    0x3256f4c(%rip),%rdi        # ffffffff8e2d5920 <frame_candidate_6c0080+0x32558a0>
ffffffff8b07e9d4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b07e9db:	00 00 00 00 00 
ffffffff8b07e9e0:	ff c9                	dec    %ecx
ffffffff8b07e9e2:	49 89 c8             	mov    %rcx,%r8
ffffffff8b07e9e5:	49 c1 e0 04          	shl    $0x4,%r8
ffffffff8b07e9e9:	45 8b 44 38 0c       	mov    0xc(%r8,%rdi,1),%r8d
ffffffff8b07e9ee:	45 85 c0             	test   %r8d,%r8d
ffffffff8b07e9f1:	75 0c                	jne    ffffffff8b07e9ff <handler_639_body+0x1ff>
ffffffff8b07e9f3:	85 c9                	test   %ecx,%ecx
ffffffff8b07e9f5:	7f e9                	jg     ffffffff8b07e9e0 <handler_639_body+0x1e0>
ffffffff8b07e9f7:	31 c9                	xor    %ecx,%ecx
ffffffff8b07e9f9:	39 c2                	cmp    %eax,%edx
ffffffff8b07e9fb:	72 0f                	jb     ffffffff8b07ea0c <handler_639_body+0x20c>
ffffffff8b07e9fd:	eb 1f                	jmp    ffffffff8b07ea1e <handler_639_body+0x21e>
ffffffff8b07e9ff:	39 ca                	cmp    %ecx,%edx
ffffffff8b07ea01:	44 89 45 c4          	mov    %r8d,-0x3c(%rbp)
ffffffff8b07ea05:	0f 9e c1             	setle  %cl
ffffffff8b07ea08:	39 c2                	cmp    %eax,%edx
ffffffff8b07ea0a:	73 12                	jae    ffffffff8b07ea1e <handler_639_body+0x21e>
ffffffff8b07ea0c:	8b 46 0c             	mov    0xc(%rsi),%eax
ffffffff8b07ea0f:	85 c0                	test   %eax,%eax
ffffffff8b07ea11:	0f 94 c2             	sete   %dl
ffffffff8b07ea14:	08 ca                	or     %cl,%dl
ffffffff8b07ea16:	f6 c2 01             	test   $0x1,%dl
ffffffff8b07ea19:	75 03                	jne    ffffffff8b07ea1e <handler_639_body+0x21e>
ffffffff8b07ea1b:	89 45 c4             	mov    %eax,-0x3c(%rbp)
ffffffff8b07ea1e:	48 8d 3d db 6e 25 03 	lea    0x3256edb(%rip),%rdi        # ffffffff8e2d5900 <frame_candidate_6c0080+0x3255880>
ffffffff8b07ea25:	31 f6                	xor    %esi,%esi
ffffffff8b07ea27:	31 d2                	xor    %edx,%edx
ffffffff8b07ea29:	e8 d2 d8 58 00       	call   ffffffff8b60c300 <frame_candidate_6c0080+0x58c280>
ffffffff8b07ea2e:	83 3d 7b 1b 3b 03 00 	cmpl   $0x0,0x33b1b7b(%rip)        # ffffffff8e4305b0 <frame_candidate_6c0080+0x33b0530>
ffffffff8b07ea35:	78 06                	js     ffffffff8b07ea3d <handler_639_body+0x23d>
ffffffff8b07ea37:	48 63 45 dc          	movslq -0x24(%rbp),%rax
ffffffff8b07ea3b:	eb 09                	jmp    ffffffff8b07ea46 <handler_639_body+0x246>
ffffffff8b07ea3d:	31 c0                	xor    %eax,%eax
ffffffff8b07ea3f:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
ffffffff8b07ea46:	48 63 55 d8          	movslq -0x28(%rbp),%rdx
ffffffff8b07ea4a:	48 8b 0b             	mov    (%rbx),%rcx
ffffffff8b07ea4d:	48 01 c2             	add    %rax,%rdx
ffffffff8b07ea50:	48 29 d1             	sub    %rdx,%rcx
ffffffff8b07ea53:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
ffffffff8b07ea57:	4c 8b 73 10          	mov    0x10(%rbx),%r14
ffffffff8b07ea5b:	4d 85 f6             	test   %r14,%r14
ffffffff8b07ea5e:	74 2c                	je     ffffffff8b07ea8c <handler_639_body+0x28c>
ffffffff8b07ea60:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b07ea67:	00 00 
ffffffff8b07ea69:	48 8d 35 27 08 c9 00 	lea    0xc90827(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_6c0080+0xc8f217>
ffffffff8b07ea70:	31 d2                	xor    %edx,%edx
ffffffff8b07ea72:	e8 69 b9 55 00       	call   ffffffff8b5da3e0 <frame_candidate_6c0080+0x55a360>
ffffffff8b07ea77:	48 8d 7d c8          	lea    -0x38(%rbp),%rdi
ffffffff8b07ea7b:	ba 08 00 00 00       	mov    $0x8,%edx
ffffffff8b07ea80:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b07ea83:	e8 48 a7 b9 ff       	call   ffffffff8ac191d0 <handler_639_body-0x465630>
ffffffff8b07ea88:	85 c0                	test   %eax,%eax
ffffffff8b07ea8a:	75 6c                	jne    ffffffff8b07eaf8 <handler_639_body+0x2f8>
ffffffff8b07ea8c:	4c 8b 73 18          	mov    0x18(%rbx),%r14
ffffffff8b07ea90:	4d 85 f6             	test   %r14,%r14
ffffffff8b07ea93:	74 2c                	je     ffffffff8b07eac1 <handler_639_body+0x2c1>
ffffffff8b07ea95:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b07ea9c:	00 00 
ffffffff8b07ea9e:	48 8d 35 f2 07 c9 00 	lea    0xc907f2(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_6c0080+0xc8f217>
ffffffff8b07eaa5:	31 d2                	xor    %edx,%edx
ffffffff8b07eaa7:	e8 34 b9 55 00       	call   ffffffff8b5da3e0 <frame_candidate_6c0080+0x55a360>
ffffffff8b07eaac:	48 8d 7d d0          	lea    -0x30(%rbp),%rdi
ffffffff8b07eab0:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b07eab5:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b07eab8:	e8 13 a7 b9 ff       	call   ffffffff8ac191d0 <handler_639_body-0x465630>
ffffffff8b07eabd:	85 c0                	test   %eax,%eax
ffffffff8b07eabf:	75 37                	jne    ffffffff8b07eaf8 <handler_639_body+0x2f8>
ffffffff8b07eac1:	48 8b 5b 20          	mov    0x20(%rbx),%rbx
ffffffff8b07eac5:	48 85 db             	test   %rbx,%rbx
ffffffff8b07eac8:	74 2c                	je     ffffffff8b07eaf6 <handler_639_body+0x2f6>
ffffffff8b07eaca:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b07ead1:	00 00 
ffffffff8b07ead3:	48 8d 35 bd 07 c9 00 	lea    0xc907bd(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_6c0080+0xc8f217>
ffffffff8b07eada:	31 d2                	xor    %edx,%edx
ffffffff8b07eadc:	e8 ff b8 55 00       	call   ffffffff8b5da3e0 <frame_candidate_6c0080+0x55a360>
ffffffff8b07eae1:	48 8d 7d c4          	lea    -0x3c(%rbp),%rdi
ffffffff8b07eae5:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b07eaea:	48 89 de             	mov    %rbx,%rsi
ffffffff8b07eaed:	e8 de a6 b9 ff       	call   ffffffff8ac191d0 <handler_639_body-0x465630>
ffffffff8b07eaf2:	85 c0                	test   %eax,%eax
ffffffff8b07eaf4:	75 02                	jne    ffffffff8b07eaf8 <handler_639_body+0x2f8>
ffffffff8b07eaf6:	31 c0                	xor    %eax,%eax
ffffffff8b07eaf8:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b07eafb:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8b07eaff:	75 0b                	jne    ffffffff8b07eb0c <handler_639_body+0x30c>
ffffffff8b07eb01:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8b07eb05:	5b                   	pop    %rbx
ffffffff8b07eb06:	41 5e                	pop    %r14
ffffffff8b07eb08:	41 5f                	pop    %r15
ffffffff8b07eb0a:	5d                   	pop    %rbp
ffffffff8b07eb0b:	c3                   	ret
ffffffff8b07eb0c:	e8 9f eb 03 00       	call   ffffffff8b0bd6b0 <frame_candidate_6c0080+0x3d630>
ffffffff8b07eb11:	0f 0b                	ud2
ffffffff8b07eb13:	90                   	nop
ffffffff8b07eb14:	90                   	nop
ffffffff8b07eb15:	90                   	nop
ffffffff8b07eb16:	90                   	nop
ffffffff8b07eb17:	90                   	nop
ffffffff8b07eb18:	90                   	nop
ffffffff8b07eb19:	90                   	nop
ffffffff8b07eb1a:	90                   	nop
ffffffff8b07eb1b:	90                   	nop
ffffffff8b07eb1c:	90                   	nop
ffffffff8b07eb1d:	90                   	nop
ffffffff8b07eb1e:	90                   	nop
ffffffff8b07eb1f:	90                   	nop

ffffffff8b07eb20 <frame_candidate_6beb20>:
ffffffff8b07eb20:	55                   	push   %rbp
ffffffff8b07eb21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07eb24:	48 8d 3d b8 1d c2 00 	lea    0xc21db8(%rip),%rdi        # ffffffff8bca08e3 <frame_candidate_6c0080+0xc20863>
ffffffff8b07eb2b:	4c 8d 05 96 85 ba ff 	lea    -0x457a6a(%rip),%r8        # ffffffff8ac270c8 <handler_639_body-0x457738>
ffffffff8b07eb32:	4c 8d 0d 07 bf ba ff 	lea    -0x4540f9(%rip),%r9        # ffffffff8ac2aa40 <handler_639_body-0x453dc0>
ffffffff8b07eb39:	be 60 01 00 00       	mov    $0x160,%esi
ffffffff8b07eb3e:	31 d2                	xor    %edx,%edx
ffffffff8b07eb40:	31 c9                	xor    %ecx,%ecx
ffffffff8b07eb42:	6a 00                	push   $0x0
ffffffff8b07eb44:	6a 07                	push   $0x7
ffffffff8b07eb46:	e8 95 c5 d7 ff       	call   ffffffff8adfb0e0 <handler_639_body-0x283720>
ffffffff8b07eb4b:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b07eb4f:	4c 8b 05 ca 41 7c 00 	mov    0x7c41ca(%rip),%r8        # ffffffff8b842d20 <frame_candidate_6c0080+0x7c2ca0>
ffffffff8b07eb56:	48 8b 0d cb 41 7c 00 	mov    0x7c41cb(%rip),%rcx        # ffffffff8b842d28 <frame_candidate_6c0080+0x7c2ca8>
ffffffff8b07eb5d:	48 8b 15 cc 41 7c 00 	mov    0x7c41cc(%rip),%rdx        # ffffffff8b842d30 <frame_candidate_6c0080+0x7c2cb0>
ffffffff8b07eb64:	48 8b 35 cd 41 7c 00 	mov    0x7c41cd(%rip),%rsi        # ffffffff8b842d38 <frame_candidate_6c0080+0x7c2cb8>
ffffffff8b07eb6b:	48 8b 3d ce 41 7c 00 	mov    0x7c41ce(%rip),%rdi        # ffffffff8b842d40 <frame_candidate_6c0080+0x7c2cc0>
ffffffff8b07eb72:	48 89 05 7f 6d 25 03 	mov    %rax,0x3256d7f(%rip)        # ffffffff8e2d58f8 <frame_candidate_6c0080+0x3255878>
ffffffff8b07eb79:	4c 89 05 b0 6c 25 03 	mov    %r8,0x3256cb0(%rip)        # ffffffff8e2d5830 <frame_candidate_6c0080+0x32557b0>
ffffffff8b07eb80:	48 89 0d b1 6c 25 03 	mov    %rcx,0x3256cb1(%rip)        # ffffffff8e2d5838 <frame_candidate_6c0080+0x32557b8>
ffffffff8b07eb87:	48 89 15 b2 6c 25 03 	mov    %rdx,0x3256cb2(%rip)        # ffffffff8e2d5840 <frame_candidate_6c0080+0x32557c0>
ffffffff8b07eb8e:	48 89 35 b3 6c 25 03 	mov    %rsi,0x3256cb3(%rip)        # ffffffff8e2d5848 <frame_candidate_6c0080+0x32557c8>
ffffffff8b07eb95:	48 89 3d b4 6c 25 03 	mov    %rdi,0x3256cb4(%rip)        # ffffffff8e2d5850 <frame_candidate_6c0080+0x32557d0>
ffffffff8b07eb9c:	48 89 35 45 6d 25 03 	mov    %rsi,0x3256d45(%rip)        # ffffffff8e2d58e8 <frame_candidate_6c0080+0x3255868>
ffffffff8b07eba3:	48 89 3d 46 6d 25 03 	mov    %rdi,0x3256d46(%rip)        # ffffffff8e2d58f0 <frame_candidate_6c0080+0x3255870>
ffffffff8b07ebaa:	bf 0e 00 00 00       	mov    $0xe,%edi
ffffffff8b07ebaf:	be b0 0d 03 00       	mov    $0x30db0,%esi
ffffffff8b07ebb4:	4c 89 05 15 6d 25 03 	mov    %r8,0x3256d15(%rip)        # ffffffff8e2d58d0 <frame_candidate_6c0080+0x3255850>
ffffffff8b07ebbb:	48 89 0d 16 6d 25 03 	mov    %rcx,0x3256d16(%rip)        # ffffffff8e2d58d8 <frame_candidate_6c0080+0x3255858>
ffffffff8b07ebc2:	48 89 15 17 6d 25 03 	mov    %rdx,0x3256d17(%rip)        # ffffffff8e2d58e0 <frame_candidate_6c0080+0x3255860>
ffffffff8b07ebc9:	e8 32 68 4d 00       	call   ffffffff8b555400 <frame_candidate_6c0080+0x4d5380>
ffffffff8b07ebce:	bf 12 00 00 00       	mov    $0x12,%edi
ffffffff8b07ebd3:	be ff ff ff 7f       	mov    $0x7fffffff,%esi
ffffffff8b07ebd8:	e8 23 68 4d 00       	call   ffffffff8b555400 <frame_candidate_6c0080+0x4d5380>
ffffffff8b07ebdd:	bf 19 00 00 00       	mov    $0x19,%edi
ffffffff8b07ebe2:	be 20 00 00 00       	mov    $0x20,%esi
ffffffff8b07ebe7:	e8 14 68 4d 00       	call   ffffffff8b555400 <frame_candidate_6c0080+0x4d5380>
ffffffff8b07ebec:	48 8d 35 ab 8a c2 00 	lea    0xc28aab(%rip),%rsi        # ffffffff8bca769e <frame_candidate_6c0080+0xc2761e>
ffffffff8b07ebf3:	48 8d 15 ae 8b ba ff 	lea    -0x457452(%rip),%rdx        # ffffffff8ac277a8 <handler_639_body-0x457058>
ffffffff8b07ebfa:	48 8d 0d 3a d9 be 00 	lea    0xbed93a(%rip),%rcx        # ffffffff8bc6c53b <frame_candidate_6c0080+0xbec4bb>
ffffffff8b07ec01:	41 b8 01 00 00 00    	mov    $0x1,%r8d
ffffffff8b07ec07:	41 b9 10 27 00 00    	mov    $0x2710,%r9d
ffffffff8b07ec0d:	31 ff                	xor    %edi,%edi
ffffffff8b07ec0f:	e8 2c f1 07 00       	call   ffffffff8b0fdd40 <frame_candidate_6c0080+0x7dcc0>
ffffffff8b07ec14:	48 8d 35 c3 56 cc 00 	lea    0xcc56c3(%rip),%rsi        # ffffffff8bd442de <frame_candidate_6c0080+0xcc425e>
ffffffff8b07ec1b:	48 8d 15 de 96 ba ff 	lea    -0x456922(%rip),%rdx        # ffffffff8ac28300 <handler_639_body-0x456500>
ffffffff8b07ec22:	48 8d 0d ab f3 c7 00 	lea    0xc7f3ab(%rip),%rcx        # ffffffff8bcfdfd4 <frame_candidate_6c0080+0xc7df54>
ffffffff8b07ec29:	41 b9 10 27 00 00    	mov    $0x2710,%r9d
ffffffff8b07ec2f:	31 ff                	xor    %edi,%edi
ffffffff8b07ec31:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b07ec34:	e8 07 f1 07 00       	call   ffffffff8b0fdd40 <frame_candidate_6c0080+0x7dcc0>
ffffffff8b07ec39:	48 8d 3d c0 6c 25 03 	lea    0x3256cc0(%rip),%rdi        # ffffffff8e2d5900 <frame_candidate_6c0080+0x3255880>
ffffffff8b07ec40:	48 8d 35 88 ad bb 00 	lea    0xbbad88(%rip),%rsi        # ffffffff8bc399cf <frame_candidate_6c0080+0xbb994f>
ffffffff8b07ec47:	31 d2                	xor    %edx,%edx
ffffffff8b07ec49:	5d                   	pop    %rbp
ffffffff8b07ec4a:	e9 41 c6 58 00       	jmp    ffffffff8b60b290 <frame_candidate_6c0080+0x58b210>
ffffffff8b07ec4f:	90                   	nop

ffffffff8b07ec50 <frame_candidate_6bec50>:
ffffffff8b07ec50:	55                   	push   %rbp
ffffffff8b07ec51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07ec54:	48 89 fe             	mov    %rdi,%rsi
ffffffff8b07ec57:	48 81 c7 20 01 00 00 	add    $0x120,%rdi
ffffffff8b07ec5e:	31 d2                	xor    %edx,%edx
ffffffff8b07ec60:	e8 2b ca 4d 00       	call   ffffffff8b55b690 <frame_candidate_6c0080+0x4db610>
ffffffff8b07ec65:	31 c0                	xor    %eax,%eax
ffffffff8b07ec67:	5d                   	pop    %rbp
ffffffff8b07ec68:	c3                   	ret
ffffffff8b07ec69:	90                   	nop
ffffffff8b07ec6a:	90                   	nop
ffffffff8b07ec6b:	90                   	nop
ffffffff8b07ec6c:	90                   	nop
ffffffff8b07ec6d:	90                   	nop
ffffffff8b07ec6e:	90                   	nop
ffffffff8b07ec6f:	90                   	nop

ffffffff8b07ec70 <frame_candidate_6bec70>:
ffffffff8b07ec70:	55                   	push   %rbp
ffffffff8b07ec71:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07ec74:	41 57                	push   %r15
ffffffff8b07ec76:	41 56                	push   %r14
ffffffff8b07ec78:	41 55                	push   %r13
ffffffff8b07ec7a:	41 54                	push   %r12
ffffffff8b07ec7c:	53                   	push   %rbx
ffffffff8b07ec7d:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8b07ec81:	4c 8d 0d 88 d6 25 03 	lea    0x325d688(%rip),%r9        # ffffffff8e2dc310 <frame_candidate_6c0080+0x325c290>
ffffffff8b07ec88:	41 be 16 00 00 00    	mov    $0x16,%r14d
ffffffff8b07ec8e:	49 8b 01             	mov    (%r9),%rax
ffffffff8b07ec91:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b07ec95:	4c 8b 7a 10          	mov    0x10(%rdx),%r15
ffffffff8b07ec99:	48 8b 5a 18          	mov    0x18(%rdx),%rbx
ffffffff8b07ec9d:	4d 85 ff             	test   %r15,%r15
ffffffff8b07eca0:	0f 98 c0             	sets   %al
ffffffff8b07eca3:	48 81 fb 00 ca 9a 3b 	cmp    $0x3b9aca00,%rbx
ffffffff8b07ecaa:	41 0f 93 c0          	setae  %r8b
ffffffff8b07ecae:	41 08 c0             	or     %al,%r8b
ffffffff8b07ecb1:	0f 85 52 02 00 00    	jne    ffffffff8b07ef09 <frame_candidate_6bec70+0x299>
ffffffff8b07ecb7:	4d 85 ff             	test   %r15,%r15
ffffffff8b07ecba:	4c 8b 22             	mov    (%rdx),%r12
ffffffff8b07ecbd:	4c 8b 6a 08          	mov    0x8(%rdx),%r13
ffffffff8b07ecc1:	0f 95 c0             	setne  %al
ffffffff8b07ecc4:	48 85 db             	test   %rbx,%rbx
ffffffff8b07ecc7:	0f 94 c2             	sete   %dl
ffffffff8b07ecca:	08 c2                	or     %al,%dl
ffffffff8b07eccc:	74 11                	je     ffffffff8b07ecdf <frame_candidate_6bec70+0x6f>
ffffffff8b07ecce:	48 89 d8             	mov    %rbx,%rax
ffffffff8b07ecd1:	4c 09 f8             	or     %r15,%rax
ffffffff8b07ecd4:	75 1c                	jne    ffffffff8b07ecf2 <frame_candidate_6bec70+0x82>
ffffffff8b07ecd6:	31 d2                	xor    %edx,%edx
ffffffff8b07ecd8:	31 db                	xor    %ebx,%ebx
ffffffff8b07ecda:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b07ecdd:	eb 50                	jmp    ffffffff8b07ed2f <frame_candidate_6bec70+0xbf>
ffffffff8b07ecdf:	69 05 df 16 26 03 e8 	imul   $0x3e8,0x32616df(%rip),%eax        # ffffffff8e2e03c8 <frame_candidate_6c0080+0x3260348>
ffffffff8b07ece6:	03 00 00 
ffffffff8b07ece9:	48 98                	cltq
ffffffff8b07eceb:	48 39 c3             	cmp    %rax,%rbx
ffffffff8b07ecee:	48 0f 4e d8          	cmovle %rax,%rbx
ffffffff8b07ecf2:	4d 85 e4             	test   %r12,%r12
ffffffff8b07ecf5:	0f 98 c0             	sets   %al
ffffffff8b07ecf8:	49 81 fd 00 ca 9a 3b 	cmp    $0x3b9aca00,%r13
ffffffff8b07ecff:	0f 93 c2             	setae  %dl
ffffffff8b07ed02:	08 c2                	or     %al,%dl
ffffffff8b07ed04:	0f 85 ff 01 00 00    	jne    ffffffff8b07ef09 <frame_candidate_6bec70+0x299>
ffffffff8b07ed0a:	4d 85 e4             	test   %r12,%r12
ffffffff8b07ed0d:	0f 95 c0             	setne  %al
ffffffff8b07ed10:	4d 85 ed             	test   %r13,%r13
ffffffff8b07ed13:	0f 94 c2             	sete   %dl
ffffffff8b07ed16:	08 c2                	or     %al,%dl
ffffffff8b07ed18:	b2 01                	mov    $0x1,%dl
ffffffff8b07ed1a:	75 16                	jne    ffffffff8b07ed32 <frame_candidate_6bec70+0xc2>
ffffffff8b07ed1c:	69 05 a2 16 26 03 e8 	imul   $0x3e8,0x32616a2(%rip),%eax        # ffffffff8e2e03c8 <frame_candidate_6c0080+0x3260348>
ffffffff8b07ed23:	03 00 00 
ffffffff8b07ed26:	48 98                	cltq
ffffffff8b07ed28:	49 39 c5             	cmp    %rax,%r13
ffffffff8b07ed2b:	4c 0f 4e e8          	cmovle %rax,%r13
ffffffff8b07ed2f:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b07ed32:	48 85 c9             	test   %rcx,%rcx
ffffffff8b07ed35:	0f 84 a4 00 00 00    	je     ffffffff8b07eddf <frame_candidate_6bec70+0x16f>
ffffffff8b07ed3b:	83 bf a8 00 00 00 00 	cmpl   $0x0,0xa8(%rdi)
ffffffff8b07ed42:	49 89 fe             	mov    %rdi,%r14
ffffffff8b07ed45:	48 89 55 a0          	mov    %rdx,-0x60(%rbp)
ffffffff8b07ed49:	48 89 4d 98          	mov    %rcx,-0x68(%rbp)
ffffffff8b07ed4d:	89 75 ac             	mov    %esi,-0x54(%rbp)
ffffffff8b07ed50:	74 0b                	je     ffffffff8b07ed5d <frame_candidate_6bec70+0xed>
ffffffff8b07ed52:	48 8d 7d c0          	lea    -0x40(%rbp),%rdi
ffffffff8b07ed56:	e8 a5 09 41 00       	call   ffffffff8b48f700 <frame_candidate_6c0080+0x40f680>
ffffffff8b07ed5b:	eb 09                	jmp    ffffffff8b07ed66 <frame_candidate_6bec70+0xf6>
ffffffff8b07ed5d:	48 8d 7d c0          	lea    -0x40(%rbp),%rdi
ffffffff8b07ed61:	e8 1a 0a 41 00       	call   ffffffff8b48f780 <frame_candidate_6c0080+0x40f700>
ffffffff8b07ed66:	49 8b 8e 88 00 00 00 	mov    0x88(%r14),%rcx
ffffffff8b07ed6d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
ffffffff8b07ed71:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07ed74:	48 89 48 18          	mov    %rcx,0x18(%rax)
ffffffff8b07ed78:	49 8b 96 80 00 00 00 	mov    0x80(%r14),%rdx
ffffffff8b07ed7f:	48 89 50 10          	mov    %rdx,0x10(%rax)
ffffffff8b07ed83:	49 8b 76 70          	mov    0x70(%r14),%rsi
ffffffff8b07ed87:	4d 8b 46 78          	mov    0x78(%r14),%r8
ffffffff8b07ed8b:	48 89 30             	mov    %rsi,(%rax)
ffffffff8b07ed8e:	48 89 d6             	mov    %rdx,%rsi
ffffffff8b07ed91:	4c 89 40 08          	mov    %r8,0x8(%rax)
ffffffff8b07ed95:	48 09 ce             	or     %rcx,%rsi
ffffffff8b07ed98:	8b 75 ac             	mov    -0x54(%rbp),%esi
ffffffff8b07ed9b:	74 3e                	je     ffffffff8b07eddb <frame_candidate_6bec70+0x16b>
ffffffff8b07ed9d:	48 2b 55 c0          	sub    -0x40(%rbp),%rdx
ffffffff8b07eda1:	48 89 50 10          	mov    %rdx,0x10(%rax)
ffffffff8b07eda5:	48 2b 4d c8          	sub    -0x38(%rbp),%rcx
ffffffff8b07eda9:	48 89 48 18          	mov    %rcx,0x18(%rax)
ffffffff8b07edad:	79 12                	jns    ffffffff8b07edc1 <frame_candidate_6bec70+0x151>
ffffffff8b07edaf:	48 ff ca             	dec    %rdx
ffffffff8b07edb2:	48 81 c1 00 ca 9a 3b 	add    $0x3b9aca00,%rcx
ffffffff8b07edb9:	48 89 50 10          	mov    %rdx,0x10(%rax)
ffffffff8b07edbd:	48 89 48 18          	mov    %rcx,0x18(%rax)
ffffffff8b07edc1:	48 85 d2             	test   %rdx,%rdx
ffffffff8b07edc4:	78 05                	js     ffffffff8b07edcb <frame_candidate_6bec70+0x15b>
ffffffff8b07edc6:	48 09 ca             	or     %rcx,%rdx
ffffffff8b07edc9:	75 10                	jne    ffffffff8b07eddb <frame_candidate_6bec70+0x16b>
ffffffff8b07edcb:	48 c7 40 10 00 00 00 	movq   $0x0,0x10(%rax)
ffffffff8b07edd2:	00 
ffffffff8b07edd3:	48 c7 40 18 01 00 00 	movq   $0x1,0x18(%rax)
ffffffff8b07edda:	00 
ffffffff8b07eddb:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
ffffffff8b07eddf:	4c 89 67 70          	mov    %r12,0x70(%rdi)
ffffffff8b07ede3:	4c 89 6f 78          	mov    %r13,0x78(%rdi)
ffffffff8b07ede7:	4c 89 bf 80 00 00 00 	mov    %r15,0x80(%rdi)
ffffffff8b07edee:	48 89 9f 88 00 00 00 	mov    %rbx,0x88(%rdi)
ffffffff8b07edf5:	84 d2                	test   %dl,%dl
ffffffff8b07edf7:	74 1a                	je     ffffffff8b07ee13 <frame_candidate_6bec70+0x1a3>
ffffffff8b07edf9:	83 bf a8 00 00 00 00 	cmpl   $0x0,0xa8(%rdi)
ffffffff8b07ee00:	41 89 f4             	mov    %esi,%r12d
ffffffff8b07ee03:	49 89 fe             	mov    %rdi,%r14
ffffffff8b07ee06:	74 23                	je     ffffffff8b07ee2b <frame_candidate_6bec70+0x1bb>
ffffffff8b07ee08:	48 8d 7d c0          	lea    -0x40(%rbp),%rdi
ffffffff8b07ee0c:	e8 ef 08 41 00       	call   ffffffff8b48f700 <frame_candidate_6c0080+0x40f680>
ffffffff8b07ee11:	eb 21                	jmp    ffffffff8b07ee34 <frame_candidate_6bec70+0x1c4>
ffffffff8b07ee13:	48 81 c7 20 01 00 00 	add    $0x120,%rdi
ffffffff8b07ee1a:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b07ee1d:	31 f6                	xor    %esi,%esi
ffffffff8b07ee1f:	31 d2                	xor    %edx,%edx
ffffffff8b07ee21:	e8 aa c1 4d 00       	call   ffffffff8b55afd0 <frame_candidate_6c0080+0x4daf50>
ffffffff8b07ee26:	e9 d7 00 00 00       	jmp    ffffffff8b07ef02 <frame_candidate_6bec70+0x292>
ffffffff8b07ee2b:	48 8d 7d c0          	lea    -0x40(%rbp),%rdi
ffffffff8b07ee2f:	e8 4c 09 41 00       	call   ffffffff8b48f780 <frame_candidate_6c0080+0x40f700>
ffffffff8b07ee34:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b07ee38:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b07ee3b:	41 f6 c4 01          	test   $0x1,%r12b
ffffffff8b07ee3f:	75 43                	jne    ffffffff8b07ee84 <frame_candidate_6bec70+0x214>
ffffffff8b07ee41:	48 03 81 80 00 00 00 	add    0x80(%rcx),%rax
ffffffff8b07ee48:	48 89 81 80 00 00 00 	mov    %rax,0x80(%rcx)
ffffffff8b07ee4f:	48 8b 91 88 00 00 00 	mov    0x88(%rcx),%rdx
ffffffff8b07ee56:	48 03 55 c8          	add    -0x38(%rbp),%rdx
ffffffff8b07ee5a:	48 89 91 88 00 00 00 	mov    %rdx,0x88(%rcx)
ffffffff8b07ee61:	48 81 fa 00 ca 9a 3b 	cmp    $0x3b9aca00,%rdx
ffffffff8b07ee68:	7c 2d                	jl     ffffffff8b07ee97 <frame_candidate_6bec70+0x227>
ffffffff8b07ee6a:	48 ff c0             	inc    %rax
ffffffff8b07ee6d:	48 81 c2 00 36 65 c4 	add    $0xffffffffc4653600,%rdx
ffffffff8b07ee74:	48 89 81 80 00 00 00 	mov    %rax,0x80(%rcx)
ffffffff8b07ee7b:	48 89 91 88 00 00 00 	mov    %rdx,0x88(%rcx)
ffffffff8b07ee82:	eb 13                	jmp    ffffffff8b07ee97 <frame_candidate_6bec70+0x227>
ffffffff8b07ee84:	49 29 c7             	sub    %rax,%r15
ffffffff8b07ee87:	48 2b 5d c8          	sub    -0x38(%rbp),%rbx
ffffffff8b07ee8b:	79 0a                	jns    ffffffff8b07ee97 <frame_candidate_6bec70+0x227>
ffffffff8b07ee8d:	49 ff cf             	dec    %r15
ffffffff8b07ee90:	48 81 c3 00 ca 9a 3b 	add    $0x3b9aca00,%rbx
ffffffff8b07ee97:	48 89 d8             	mov    %rbx,%rax
ffffffff8b07ee9a:	48 ba cf f7 53 e3 a5 	movabs $0x20c49ba5e353f7cf,%rdx
ffffffff8b07eea1:	9b c4 20 
ffffffff8b07eea4:	4c 8b 35 25 15 26 03 	mov    0x3261525(%rip),%r14        # ffffffff8e2e03d0 <frame_candidate_6c0080+0x3260350>
ffffffff8b07eeab:	48 8d 7d b0          	lea    -0x50(%rbp),%rdi
ffffffff8b07eeaf:	4c 89 7d b0          	mov    %r15,-0x50(%rbp)
ffffffff8b07eeb3:	48 8d 99 20 01 00 00 	lea    0x120(%rcx),%rbx
ffffffff8b07eeba:	49 89 cf             	mov    %rcx,%r15
ffffffff8b07eebd:	48 f7 ea             	imul   %rdx
ffffffff8b07eec0:	48 89 d0             	mov    %rdx,%rax
ffffffff8b07eec3:	48 c1 fa 07          	sar    $0x7,%rdx
ffffffff8b07eec7:	48 c1 e8 3f          	shr    $0x3f,%rax
ffffffff8b07eecb:	48 01 c2             	add    %rax,%rdx
ffffffff8b07eece:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8b07eed2:	e8 a9 7d 5a 00       	call   ffffffff8b626c80 <frame_candidate_6c0080+0x5a6c00>
ffffffff8b07eed7:	48 63 f0             	movslq %eax,%rsi
ffffffff8b07eeda:	48 8d 0d b7 40 ba ff 	lea    -0x45bf49(%rip),%rcx        # ffffffff8ac22f98 <handler_639_body-0x45b868>
ffffffff8b07eee1:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07eee4:	4d 89 f8             	mov    %r15,%r8
ffffffff8b07eee7:	41 b9 ff ff ff ff    	mov    $0xffffffff,%r9d
ffffffff8b07eeed:	c7 04 24 00 01 00 00 	movl   $0x100,(%rsp)
ffffffff8b07eef4:	31 d2                	xor    %edx,%edx
ffffffff8b07eef6:	49 0f af f6          	imul   %r14,%rsi
ffffffff8b07eefa:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b07eefd:	e8 3e bb 4d 00       	call   ffffffff8b55aa40 <frame_candidate_6c0080+0x4da9c0>
ffffffff8b07ef02:	4c 8d 0d 07 d4 25 03 	lea    0x325d407(%rip),%r9        # ffffffff8e2dc310 <frame_candidate_6c0080+0x325c290>
ffffffff8b07ef09:	49 8b 01             	mov    (%r9),%rax
ffffffff8b07ef0c:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b07ef10:	75 12                	jne    ffffffff8b07ef24 <frame_candidate_6bec70+0x2b4>
ffffffff8b07ef12:	44 89 f0             	mov    %r14d,%eax
ffffffff8b07ef15:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8b07ef19:	5b                   	pop    %rbx
ffffffff8b07ef1a:	41 5c                	pop    %r12
ffffffff8b07ef1c:	41 5d                	pop    %r13
ffffffff8b07ef1e:	41 5e                	pop    %r14
ffffffff8b07ef20:	41 5f                	pop    %r15
ffffffff8b07ef22:	5d                   	pop    %rbp
ffffffff8b07ef23:	c3                   	ret
ffffffff8b07ef24:	e8 87 e7 03 00       	call   ffffffff8b0bd6b0 <frame_candidate_6c0080+0x3d630>
ffffffff8b07ef29:	0f 0b                	ud2
ffffffff8b07ef2b:	90                   	nop
ffffffff8b07ef2c:	90                   	nop
ffffffff8b07ef2d:	90                   	nop
ffffffff8b07ef2e:	90                   	nop
ffffffff8b07ef2f:	90                   	nop

ffffffff8b07ef30 <frame_candidate_6bef30>:
ffffffff8b07ef30:	55                   	push   %rbp
ffffffff8b07ef31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07ef34:	41 56                	push   %r14
ffffffff8b07ef36:	53                   	push   %rbx
ffffffff8b07ef37:	4c 8d 77 18          	lea    0x18(%rdi),%r14
ffffffff8b07ef3b:	48 c7 87 88 00 00 00 	movq   $0x0,0x88(%rdi)
ffffffff8b07ef42:	00 00 00 00 
ffffffff8b07ef46:	48 c7 87 80 00 00 00 	movq   $0x0,0x80(%rdi)
ffffffff8b07ef4d:	00 00 00 00 
ffffffff8b07ef51:	48 c7 47 78 00 00 00 	movq   $0x0,0x78(%rdi)
ffffffff8b07ef58:	00 
ffffffff8b07ef59:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b07ef5c:	48 c7 47 70 00 00 00 	movq   $0x0,0x70(%rdi)
ffffffff8b07ef63:	00 
ffffffff8b07ef64:	31 f6                	xor    %esi,%esi
ffffffff8b07ef66:	31 d2                	xor    %edx,%edx
ffffffff8b07ef68:	31 c9                	xor    %ecx,%ecx
ffffffff8b07ef6a:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07ef6d:	e8 2e 80 e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b07ef72:	48 81 c3 20 01 00 00 	add    $0x120,%rbx
ffffffff8b07ef79:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8b07ef7e:	31 d2                	xor    %edx,%edx
ffffffff8b07ef80:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07ef83:	e8 48 c0 4d 00       	call   ffffffff8b55afd0 <frame_candidate_6c0080+0x4daf50>
ffffffff8b07ef88:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07ef8b:	31 f6                	xor    %esi,%esi
ffffffff8b07ef8d:	31 d2                	xor    %edx,%edx
ffffffff8b07ef8f:	31 c9                	xor    %ecx,%ecx
ffffffff8b07ef91:	e8 6a 7a e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b07ef96:	31 c0                	xor    %eax,%eax
ffffffff8b07ef98:	5b                   	pop    %rbx
ffffffff8b07ef99:	41 5e                	pop    %r14
ffffffff8b07ef9b:	5d                   	pop    %rbp
ffffffff8b07ef9c:	c3                   	ret
ffffffff8b07ef9d:	90                   	nop
ffffffff8b07ef9e:	90                   	nop
ffffffff8b07ef9f:	90                   	nop

ffffffff8b07efa0 <frame_candidate_6befa0>:
ffffffff8b07efa0:	55                   	push   %rbp
ffffffff8b07efa1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07efa4:	41 57                	push   %r15
ffffffff8b07efa6:	41 56                	push   %r14
ffffffff8b07efa8:	53                   	push   %rbx
ffffffff8b07efa9:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b07efad:	4c 8d 3d 5c d3 25 03 	lea    0x325d35c(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_6c0080+0x325c290>
ffffffff8b07efb4:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b07efb7:	49 89 fe             	mov    %rdi,%r14
ffffffff8b07efba:	49 8b 07             	mov    (%r15),%rax
ffffffff8b07efbd:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b07efc1:	83 bf a8 00 00 00 00 	cmpl   $0x0,0xa8(%rdi)
ffffffff8b07efc8:	74 0b                	je     ffffffff8b07efd5 <frame_candidate_6befa0+0x35>
ffffffff8b07efca:	48 8d 7d d0          	lea    -0x30(%rbp),%rdi
ffffffff8b07efce:	e8 2d 07 41 00       	call   ffffffff8b48f700 <frame_candidate_6c0080+0x40f680>
ffffffff8b07efd3:	eb 09                	jmp    ffffffff8b07efde <frame_candidate_6befa0+0x3e>
ffffffff8b07efd5:	48 8d 7d d0          	lea    -0x30(%rbp),%rdi
ffffffff8b07efd9:	e8 a2 07 41 00       	call   ffffffff8b48f780 <frame_candidate_6c0080+0x40f700>
ffffffff8b07efde:	49 8b 86 88 00 00 00 	mov    0x88(%r14),%rax
ffffffff8b07efe5:	48 89 43 18          	mov    %rax,0x18(%rbx)
ffffffff8b07efe9:	49 8b 8e 80 00 00 00 	mov    0x80(%r14),%rcx
ffffffff8b07eff0:	48 89 4b 10          	mov    %rcx,0x10(%rbx)
ffffffff8b07eff4:	49 8b 76 78          	mov    0x78(%r14),%rsi
ffffffff8b07eff8:	49 8b 56 70          	mov    0x70(%r14),%rdx
ffffffff8b07effc:	48 89 73 08          	mov    %rsi,0x8(%rbx)
ffffffff8b07f000:	48 89 ce             	mov    %rcx,%rsi
ffffffff8b07f003:	48 89 13             	mov    %rdx,(%rbx)
ffffffff8b07f006:	48 09 c6             	or     %rax,%rsi
ffffffff8b07f009:	74 44                	je     ffffffff8b07f04f <frame_candidate_6befa0+0xaf>
ffffffff8b07f00b:	48 2b 4d d0          	sub    -0x30(%rbp),%rcx
ffffffff8b07f00f:	48 89 4b 10          	mov    %rcx,0x10(%rbx)
ffffffff8b07f013:	48 2b 45 d8          	sub    -0x28(%rbp),%rax
ffffffff8b07f017:	48 89 43 18          	mov    %rax,0x18(%rbx)
ffffffff8b07f01b:	78 07                	js     ffffffff8b07f024 <frame_candidate_6befa0+0x84>
ffffffff8b07f01d:	48 85 c9             	test   %rcx,%rcx
ffffffff8b07f020:	79 18                	jns    ffffffff8b07f03a <frame_candidate_6befa0+0x9a>
ffffffff8b07f022:	eb 1b                	jmp    ffffffff8b07f03f <frame_candidate_6befa0+0x9f>
ffffffff8b07f024:	48 ff c9             	dec    %rcx
ffffffff8b07f027:	48 05 00 ca 9a 3b    	add    $0x3b9aca00,%rax
ffffffff8b07f02d:	48 89 4b 10          	mov    %rcx,0x10(%rbx)
ffffffff8b07f031:	48 89 43 18          	mov    %rax,0x18(%rbx)
ffffffff8b07f035:	48 85 c9             	test   %rcx,%rcx
ffffffff8b07f038:	78 05                	js     ffffffff8b07f03f <frame_candidate_6befa0+0x9f>
ffffffff8b07f03a:	48 09 c1             	or     %rax,%rcx
ffffffff8b07f03d:	75 10                	jne    ffffffff8b07f04f <frame_candidate_6befa0+0xaf>
ffffffff8b07f03f:	48 c7 43 10 00 00 00 	movq   $0x0,0x10(%rbx)
ffffffff8b07f046:	00 
ffffffff8b07f047:	48 c7 43 18 01 00 00 	movq   $0x1,0x18(%rbx)
ffffffff8b07f04e:	00 
ffffffff8b07f04f:	49 8b 07             	mov    (%r15),%rax
ffffffff8b07f052:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
ffffffff8b07f056:	75 0d                	jne    ffffffff8b07f065 <frame_candidate_6befa0+0xc5>
ffffffff8b07f058:	31 c0                	xor    %eax,%eax
ffffffff8b07f05a:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b07f05e:	5b                   	pop    %rbx
ffffffff8b07f05f:	41 5e                	pop    %r14
ffffffff8b07f061:	41 5f                	pop    %r15
ffffffff8b07f063:	5d                   	pop    %rbp
ffffffff8b07f064:	c3                   	ret
ffffffff8b07f065:	e8 46 e6 03 00       	call   ffffffff8b0bd6b0 <frame_candidate_6c0080+0x3d630>
ffffffff8b07f06a:	0f 0b                	ud2
ffffffff8b07f06c:	90                   	nop
ffffffff8b07f06d:	90                   	nop
ffffffff8b07f06e:	90                   	nop
ffffffff8b07f06f:	90                   	nop

ffffffff8b07f070 <frame_candidate_6bf070>:
ffffffff8b07f070:	55                   	push   %rbp
ffffffff8b07f071:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07f074:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8b07f078:	48 8d 35 f0 32 cf 00 	lea    0xcf32f0(%rip),%rsi        # ffffffff8bd7236f <frame_candidate_6c0080+0xcf22ef>
ffffffff8b07f07f:	31 d2                	xor    %edx,%edx
ffffffff8b07f081:	31 c9                	xor    %ecx,%ecx
ffffffff8b07f083:	e8 48 8d e0 ff       	call   ffffffff8ae87dd0 <handler_639_body-0x1f6a30>
ffffffff8b07f088:	31 c0                	xor    %eax,%eax
ffffffff8b07f08a:	5d                   	pop    %rbp
ffffffff8b07f08b:	c3                   	ret
ffffffff8b07f08c:	90                   	nop
ffffffff8b07f08d:	90                   	nop
ffffffff8b07f08e:	90                   	nop
ffffffff8b07f08f:	90                   	nop

ffffffff8b07f090 <frame_candidate_6bf090>:
ffffffff8b07f090:	55                   	push   %rbp
ffffffff8b07f091:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07f094:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8b07f098:	5d                   	pop    %rbp
ffffffff8b07f099:	e9 b2 8d e0 ff       	jmp    ffffffff8ae87e50 <handler_639_body-0x1f69b0>
ffffffff8b07f09e:	90                   	nop
ffffffff8b07f09f:	90                   	nop

ffffffff8b07f0a0 <frame_candidate_6bf0a0>:
ffffffff8b07f0a0:	55                   	push   %rbp
ffffffff8b07f0a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07f0a4:	41 57                	push   %r15
ffffffff8b07f0a6:	41 56                	push   %r14
ffffffff8b07f0a8:	41 54                	push   %r12
ffffffff8b07f0aa:	53                   	push   %rbx
ffffffff8b07f0ab:	4c 8b b6 b8 03 00 00 	mov    0x3b8(%rsi),%r14
ffffffff8b07f0b2:	4d 85 f6             	test   %r14,%r14
ffffffff8b07f0b5:	0f 84 48 01 00 00    	je     ffffffff8b07f203 <frame_candidate_6bf0a0+0x163>
ffffffff8b07f0bb:	4c 8b 25 8e 67 25 03 	mov    0x325678e(%rip),%r12        # ffffffff8e2d5850 <frame_candidate_6c0080+0x32557d0>
ffffffff8b07f0c2:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b07f0c5:	49 89 ff             	mov    %rdi,%r15
ffffffff8b07f0c8:	4d 85 e4             	test   %r12,%r12
ffffffff8b07f0cb:	74 1a                	je     ffffffff8b07f0e7 <frame_candidate_6bf0a0+0x47>
ffffffff8b07f0cd:	48 8d 3d 8c 83 b3 01 	lea    0x1b3838c(%rip),%rdi        # ffffffff8cbb7460 <frame_candidate_6c0080+0x1b373e0>
ffffffff8b07f0d4:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b07f0d7:	e8 e4 07 d9 ff       	call   ffffffff8ae0f8c0 <handler_639_body-0x26ef40>
ffffffff8b07f0dc:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07f0df:	44 89 fa             	mov    %r15d,%edx
ffffffff8b07f0e2:	31 f6                	xor    %esi,%esi
ffffffff8b07f0e4:	41 ff d4             	call   *%r12
ffffffff8b07f0e7:	4c 8b 25 8a 67 25 03 	mov    0x325678a(%rip),%r12        # ffffffff8e2d5878 <frame_candidate_6c0080+0x32557f8>
ffffffff8b07f0ee:	4d 85 e4             	test   %r12,%r12
ffffffff8b07f0f1:	74 1d                	je     ffffffff8b07f110 <frame_candidate_6bf0a0+0x70>
ffffffff8b07f0f3:	48 8d 3d 66 83 b3 01 	lea    0x1b38366(%rip),%rdi        # ffffffff8cbb7460 <frame_candidate_6c0080+0x1b373e0>
ffffffff8b07f0fa:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b07f0fd:	e8 be 07 d9 ff       	call   ffffffff8ae0f8c0 <handler_639_body-0x26ef40>
ffffffff8b07f102:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07f105:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8b07f10a:	44 89 fa             	mov    %r15d,%edx
ffffffff8b07f10d:	41 ff d4             	call   *%r12
ffffffff8b07f110:	4c 8b 25 89 67 25 03 	mov    0x3256789(%rip),%r12        # ffffffff8e2d58a0 <frame_candidate_6c0080+0x3255820>
ffffffff8b07f117:	4d 85 e4             	test   %r12,%r12
ffffffff8b07f11a:	74 1d                	je     ffffffff8b07f139 <frame_candidate_6bf0a0+0x99>
ffffffff8b07f11c:	48 8d 3d 3d 83 b3 01 	lea    0x1b3833d(%rip),%rdi        # ffffffff8cbb7460 <frame_candidate_6c0080+0x1b373e0>
ffffffff8b07f123:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b07f126:	e8 95 07 d9 ff       	call   ffffffff8ae0f8c0 <handler_639_body-0x26ef40>
ffffffff8b07f12b:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07f12e:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8b07f133:	44 89 fa             	mov    %r15d,%edx
ffffffff8b07f136:	41 ff d4             	call   *%r12
ffffffff8b07f139:	4c 8b 25 88 67 25 03 	mov    0x3256788(%rip),%r12        # ffffffff8e2d58c8 <frame_candidate_6c0080+0x3255848>
ffffffff8b07f140:	4d 85 e4             	test   %r12,%r12
ffffffff8b07f143:	74 1d                	je     ffffffff8b07f162 <frame_candidate_6bf0a0+0xc2>
ffffffff8b07f145:	48 8d 3d 14 83 b3 01 	lea    0x1b38314(%rip),%rdi        # ffffffff8cbb7460 <frame_candidate_6c0080+0x1b373e0>
ffffffff8b07f14c:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b07f14f:	e8 6c 07 d9 ff       	call   ffffffff8ae0f8c0 <handler_639_body-0x26ef40>
ffffffff8b07f154:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07f157:	be 03 00 00 00       	mov    $0x3,%esi
ffffffff8b07f15c:	44 89 fa             	mov    %r15d,%edx
ffffffff8b07f15f:	41 ff d4             	call   *%r12
ffffffff8b07f162:	4c 8b 25 87 67 25 03 	mov    0x3256787(%rip),%r12        # ffffffff8e2d58f0 <frame_candidate_6c0080+0x3255870>
ffffffff8b07f169:	4d 85 e4             	test   %r12,%r12
ffffffff8b07f16c:	74 1d                	je     ffffffff8b07f18b <frame_candidate_6bf0a0+0xeb>
ffffffff8b07f16e:	48 8d 3d eb 82 b3 01 	lea    0x1b382eb(%rip),%rdi        # ffffffff8cbb7460 <frame_candidate_6c0080+0x1b373e0>
ffffffff8b07f175:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b07f178:	e8 43 07 d9 ff       	call   ffffffff8ae0f8c0 <handler_639_body-0x26ef40>
ffffffff8b07f17d:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07f180:	be 04 00 00 00       	mov    $0x4,%esi
ffffffff8b07f185:	44 89 fa             	mov    %r15d,%edx
ffffffff8b07f188:	41 ff d4             	call   *%r12
ffffffff8b07f18b:	41 bc 03 00 00 00    	mov    $0x3,%r12d
ffffffff8b07f191:	45 85 ff             	test   %r15d,%r15d
ffffffff8b07f194:	74 23                	je     ffffffff8b07f1b9 <frame_candidate_6bf0a0+0x119>
ffffffff8b07f196:	41 83 ff 01          	cmp    $0x1,%r15d
ffffffff8b07f19a:	75 70                	jne    ffffffff8b07f20c <frame_candidate_6bf0a0+0x16c>
ffffffff8b07f19c:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b07f19f:	eb 18                	jmp    ffffffff8b07f1b9 <frame_candidate_6bf0a0+0x119>
ffffffff8b07f1a1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b07f1a8:	0f 1f 84 00 00 00 00 
ffffffff8b07f1af:	00 
ffffffff8b07f1b0:	49 ff c4             	inc    %r12
ffffffff8b07f1b3:	49 83 fc 20          	cmp    $0x20,%r12
ffffffff8b07f1b7:	74 1b                	je     ffffffff8b07f1d4 <frame_candidate_6bf0a0+0x134>
ffffffff8b07f1b9:	4b 83 7c e6 20 00    	cmpq   $0x0,0x20(%r14,%r12,8)
ffffffff8b07f1bf:	74 ef                	je     ffffffff8b07f1b0 <frame_candidate_6bf0a0+0x110>
ffffffff8b07f1c1:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b07f1c8:	00 00 
ffffffff8b07f1ca:	44 89 e6             	mov    %r12d,%esi
ffffffff8b07f1cd:	e8 ee eb ff ff       	call   ffffffff8b07ddc0 <handler_639_body-0xa40>
ffffffff8b07f1d2:	eb dc                	jmp    ffffffff8b07f1b0 <frame_candidate_6bf0a0+0x110>
ffffffff8b07f1d4:	49 83 7e 20 00       	cmpq   $0x0,0x20(%r14)
ffffffff8b07f1d9:	75 28                	jne    ffffffff8b07f203 <frame_candidate_6bf0a0+0x163>
ffffffff8b07f1db:	49 83 7e 28 00       	cmpq   $0x0,0x28(%r14)
ffffffff8b07f1e0:	75 21                	jne    ffffffff8b07f203 <frame_candidate_6bf0a0+0x163>
ffffffff8b07f1e2:	49 83 7e 30 00       	cmpq   $0x0,0x30(%r14)
ffffffff8b07f1e7:	75 1a                	jne    ffffffff8b07f203 <frame_candidate_6bf0a0+0x163>
ffffffff8b07f1e9:	48 8d 35 f0 29 41 01 	lea    0x14129f0(%rip),%rsi        # ffffffff8c491be0 <frame_candidate_6c0080+0x1411b60>
ffffffff8b07f1f0:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07f1f3:	e8 f8 9b 54 00       	call   ffffffff8b5c8df0 <frame_candidate_6c0080+0x548d70>
ffffffff8b07f1f8:	48 c7 83 b8 03 00 00 	movq   $0x0,0x3b8(%rbx)
ffffffff8b07f1ff:	00 00 00 00 
ffffffff8b07f203:	5b                   	pop    %rbx
ffffffff8b07f204:	41 5c                	pop    %r12
ffffffff8b07f206:	41 5e                	pop    %r14
ffffffff8b07f208:	41 5f                	pop    %r15
ffffffff8b07f20a:	5d                   	pop    %rbp
ffffffff8b07f20b:	c3                   	ret
ffffffff8b07f20c:	e8 3f 27 13 00       	call   ffffffff8b1b1950 <frame_candidate_6c0080+0x1318d0>
ffffffff8b07f211:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b07f20c <frame_candidate_6bf0a0+0x16c>
ffffffff8b07f218:	e8 f3 25 13 00       	call   ffffffff8b1b1810 <frame_candidate_6c0080+0x131790>
ffffffff8b07f21d:	48 8d 35 ba 76 bf 00 	lea    0xbf76ba(%rip),%rsi        # ffffffff8bc768de <frame_candidate_6c0080+0xbf685e>
ffffffff8b07f224:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b07f229:	31 c0                	xor    %eax,%eax
ffffffff8b07f22b:	e8 e0 b7 5d 00       	call   ffffffff8b65aa10 <frame_candidate_6c0080+0x5da990>
ffffffff8b07f230:	0f 0b                	ud2
ffffffff8b07f232:	90                   	nop
ffffffff8b07f233:	90                   	nop
ffffffff8b07f234:	90                   	nop
ffffffff8b07f235:	90                   	nop
ffffffff8b07f236:	90                   	nop
ffffffff8b07f237:	90                   	nop
ffffffff8b07f238:	90                   	nop
ffffffff8b07f239:	90                   	nop
ffffffff8b07f23a:	90                   	nop
ffffffff8b07f23b:	90                   	nop
ffffffff8b07f23c:	90                   	nop
ffffffff8b07f23d:	90                   	nop
ffffffff8b07f23e:	90                   	nop
ffffffff8b07f23f:	90                   	nop

ffffffff8b07f240 <frame_candidate_6bf240>:
ffffffff8b07f240:	55                   	push   %rbp
ffffffff8b07f241:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07f244:	5d                   	pop    %rbp
ffffffff8b07f245:	e9 56 fe ff ff       	jmp    ffffffff8b07f0a0 <frame_candidate_6bf0a0>
ffffffff8b07f24a:	90                   	nop
ffffffff8b07f24b:	90                   	nop
ffffffff8b07f24c:	90                   	nop
ffffffff8b07f24d:	90                   	nop
ffffffff8b07f24e:	90                   	nop
ffffffff8b07f24f:	90                   	nop

ffffffff8b07f250 <frame_candidate_6bf250>:
ffffffff8b07f250:	55                   	push   %rbp
ffffffff8b07f251:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07f254:	41 57                	push   %r15
ffffffff8b07f256:	41 56                	push   %r14
ffffffff8b07f258:	41 54                	push   %r12
ffffffff8b07f25a:	53                   	push   %rbx
ffffffff8b07f25b:	48 83 ec 40          	sub    $0x40,%rsp
ffffffff8b07f25f:	4c 8d 25 aa d0 25 03 	lea    0x325d0aa(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_6c0080+0x325c290>
ffffffff8b07f266:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b07f269:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b07f26d:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
ffffffff8b07f271:	83 bf a8 00 00 00 00 	cmpl   $0x0,0xa8(%rdi)
ffffffff8b07f278:	74 0b                	je     ffffffff8b07f285 <frame_candidate_6bf250+0x35>
ffffffff8b07f27a:	48 8d 7d c0          	lea    -0x40(%rbp),%rdi
ffffffff8b07f27e:	e8 7d 04 41 00       	call   ffffffff8b48f700 <frame_candidate_6c0080+0x40f680>
ffffffff8b07f283:	eb 09                	jmp    ffffffff8b07f28e <frame_candidate_6bf250+0x3e>
ffffffff8b07f285:	48 8d 7d c0          	lea    -0x40(%rbp),%rdi
ffffffff8b07f289:	e8 f2 04 41 00       	call   ffffffff8b48f780 <frame_candidate_6c0080+0x40f700>
ffffffff8b07f28e:	48 8b bb 80 00 00 00 	mov    0x80(%rbx),%rdi
ffffffff8b07f295:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b07f299:	48 89 f9             	mov    %rdi,%rcx
ffffffff8b07f29c:	48 29 c1             	sub    %rax,%rcx
ffffffff8b07f29f:	75 1b                	jne    ffffffff8b07f2bc <frame_candidate_6bf250+0x6c>
ffffffff8b07f2a1:	48 8b 93 88 00 00 00 	mov    0x88(%rbx),%rdx
ffffffff8b07f2a8:	48 39 55 c8          	cmp    %rdx,-0x38(%rbp)
ffffffff8b07f2ac:	0f 8d a3 00 00 00    	jge    ffffffff8b07f355 <frame_candidate_6bf250+0x105>
ffffffff8b07f2b2:	48 09 d7             	or     %rdx,%rdi
ffffffff8b07f2b5:	75 1b                	jne    ffffffff8b07f2d2 <frame_candidate_6bf250+0x82>
ffffffff8b07f2b7:	e9 3d 03 00 00       	jmp    ffffffff8b07f5f9 <frame_candidate_6bf250+0x3a9>
ffffffff8b07f2bc:	0f 8e 93 00 00 00    	jle    ffffffff8b07f355 <frame_candidate_6bf250+0x105>
ffffffff8b07f2c2:	48 8b 93 88 00 00 00 	mov    0x88(%rbx),%rdx
ffffffff8b07f2c9:	48 09 d7             	or     %rdx,%rdi
ffffffff8b07f2cc:	0f 84 27 03 00 00    	je     ffffffff8b07f5f9 <frame_candidate_6bf250+0x3a9>
ffffffff8b07f2d2:	48 2b 55 c8          	sub    -0x38(%rbp),%rdx
ffffffff8b07f2d6:	4c 8b 3d f3 10 26 03 	mov    0x32610f3(%rip),%r15        # ffffffff8e2e03d0 <frame_candidate_6c0080+0x3260350>
ffffffff8b07f2dd:	48 8d 7d b0          	lea    -0x50(%rbp),%rdi
ffffffff8b07f2e1:	4c 8d b3 20 01 00 00 	lea    0x120(%rbx),%r14
ffffffff8b07f2e8:	48 89 d6             	mov    %rdx,%rsi
ffffffff8b07f2eb:	48 8d 82 00 ca 9a 3b 	lea    0x3b9aca00(%rdx),%rax
ffffffff8b07f2f2:	48 c1 fe 3f          	sar    $0x3f,%rsi
ffffffff8b07f2f6:	48 01 f1             	add    %rsi,%rcx
ffffffff8b07f2f9:	48 85 d2             	test   %rdx,%rdx
ffffffff8b07f2fc:	48 0f 49 c2          	cmovns %rdx,%rax
ffffffff8b07f300:	48 ba cf f7 53 e3 a5 	movabs $0x20c49ba5e353f7cf,%rdx
ffffffff8b07f307:	9b c4 20 
ffffffff8b07f30a:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8b07f30e:	48 f7 ea             	imul   %rdx
ffffffff8b07f311:	48 89 d0             	mov    %rdx,%rax
ffffffff8b07f314:	48 c1 fa 07          	sar    $0x7,%rdx
ffffffff8b07f318:	48 c1 e8 3f          	shr    $0x3f,%rax
ffffffff8b07f31c:	48 01 c2             	add    %rax,%rdx
ffffffff8b07f31f:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8b07f323:	e8 58 79 5a 00       	call   ffffffff8b626c80 <frame_candidate_6c0080+0x5a6c00>
ffffffff8b07f328:	48 63 f0             	movslq %eax,%rsi
ffffffff8b07f32b:	48 8d 0d 66 3c ba ff 	lea    -0x45c39a(%rip),%rcx        # ffffffff8ac22f98 <handler_639_body-0x45b868>
ffffffff8b07f332:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07f335:	49 89 d8             	mov    %rbx,%r8
ffffffff8b07f338:	41 b9 ff ff ff ff    	mov    $0xffffffff,%r9d
ffffffff8b07f33e:	c7 04 24 00 01 00 00 	movl   $0x100,(%rsp)
ffffffff8b07f345:	31 d2                	xor    %edx,%edx
ffffffff8b07f347:	49 0f af f7          	imul   %r15,%rsi
ffffffff8b07f34b:	e8 f0 b6 4d 00       	call   ffffffff8b55aa40 <frame_candidate_6c0080+0x4da9c0>
ffffffff8b07f350:	e9 a4 02 00 00       	jmp    ffffffff8b07f5f9 <frame_candidate_6bf250+0x3a9>
ffffffff8b07f355:	48 8b 53 70          	mov    0x70(%rbx),%rdx
ffffffff8b07f359:	48 8b 73 78          	mov    0x78(%rbx),%rsi
ffffffff8b07f35d:	48 89 d1             	mov    %rdx,%rcx
ffffffff8b07f360:	48 09 f1             	or     %rsi,%rcx
ffffffff8b07f363:	75 1b                	jne    ffffffff8b07f380 <frame_candidate_6bf250+0x130>
ffffffff8b07f365:	48 c7 83 88 00 00 00 	movq   $0x0,0x88(%rbx)
ffffffff8b07f36c:	00 00 00 00 
ffffffff8b07f370:	48 c7 83 80 00 00 00 	movq   $0x0,0x80(%rbx)
ffffffff8b07f377:	00 00 00 00 
ffffffff8b07f37b:	e9 52 01 00 00       	jmp    ffffffff8b07f4d2 <frame_candidate_6bf250+0x282>
ffffffff8b07f380:	48 01 d7             	add    %rdx,%rdi
ffffffff8b07f383:	48 89 bb 80 00 00 00 	mov    %rdi,0x80(%rbx)
ffffffff8b07f38a:	48 8b 8b 88 00 00 00 	mov    0x88(%rbx),%rcx
ffffffff8b07f391:	48 01 f1             	add    %rsi,%rcx
ffffffff8b07f394:	48 89 8b 88 00 00 00 	mov    %rcx,0x88(%rbx)
ffffffff8b07f39b:	48 81 f9 00 ca 9a 3b 	cmp    $0x3b9aca00,%rcx
ffffffff8b07f3a2:	7c 18                	jl     ffffffff8b07f3bc <frame_candidate_6bf250+0x16c>
ffffffff8b07f3a4:	48 ff c7             	inc    %rdi
ffffffff8b07f3a7:	48 81 c1 00 36 65 c4 	add    $0xffffffffc4653600,%rcx
ffffffff8b07f3ae:	48 89 bb 80 00 00 00 	mov    %rdi,0x80(%rbx)
ffffffff8b07f3b5:	48 89 8b 88 00 00 00 	mov    %rcx,0x88(%rbx)
ffffffff8b07f3bc:	4c 8b 45 c8          	mov    -0x38(%rbp),%r8
ffffffff8b07f3c0:	4c 8d 52 01          	lea    0x1(%rdx),%r10
ffffffff8b07f3c4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b07f3cb:	00 00 00 00 00 
ffffffff8b07f3d0:	49 89 f9             	mov    %rdi,%r9
ffffffff8b07f3d3:	48 39 f8             	cmp    %rdi,%rax
ffffffff8b07f3d6:	75 08                	jne    ffffffff8b07f3e0 <frame_candidate_6bf250+0x190>
ffffffff8b07f3d8:	4c 39 c1             	cmp    %r8,%rcx
ffffffff8b07f3db:	7e 05                	jle    ffffffff8b07f3e2 <frame_candidate_6bf250+0x192>
ffffffff8b07f3dd:	eb 64                	jmp    ffffffff8b07f443 <frame_candidate_6bf250+0x1f3>
ffffffff8b07f3df:	90                   	nop
ffffffff8b07f3e0:	7c 64                	jl     ffffffff8b07f446 <frame_candidate_6bf250+0x1f6>
ffffffff8b07f3e2:	8b bb a0 00 00 00    	mov    0xa0(%rbx),%edi
ffffffff8b07f3e8:	81 ff ff ff ff 7f    	cmp    $0x7fffffff,%edi
ffffffff8b07f3ee:	75 10                	jne    ffffffff8b07f400 <frame_candidate_6bf250+0x1b0>
ffffffff8b07f3f0:	c7 83 c4 00 00 00 22 	movl   $0x22,0xc4(%rbx)
ffffffff8b07f3f7:	00 00 00 
ffffffff8b07f3fa:	eb 0c                	jmp    ffffffff8b07f408 <frame_candidate_6bf250+0x1b8>
ffffffff8b07f3fc:	0f 1f 40 00          	nopl   0x0(%rax)
ffffffff8b07f400:	ff c7                	inc    %edi
ffffffff8b07f402:	89 bb a0 00 00 00    	mov    %edi,0xa0(%rbx)
ffffffff8b07f408:	49 8d 3c 11          	lea    (%r9,%rdx,1),%rdi
ffffffff8b07f40c:	48 01 f1             	add    %rsi,%rcx
ffffffff8b07f40f:	48 89 bb 80 00 00 00 	mov    %rdi,0x80(%rbx)
ffffffff8b07f416:	48 89 8b 88 00 00 00 	mov    %rcx,0x88(%rbx)
ffffffff8b07f41d:	48 81 f9 00 ca 9a 3b 	cmp    $0x3b9aca00,%rcx
ffffffff8b07f424:	7c aa                	jl     ffffffff8b07f3d0 <frame_candidate_6bf250+0x180>
ffffffff8b07f426:	4d 01 d1             	add    %r10,%r9
ffffffff8b07f429:	48 81 c1 00 36 65 c4 	add    $0xffffffffc4653600,%rcx
ffffffff8b07f430:	4c 89 8b 80 00 00 00 	mov    %r9,0x80(%rbx)
ffffffff8b07f437:	48 89 8b 88 00 00 00 	mov    %rcx,0x88(%rbx)
ffffffff8b07f43e:	4c 89 cf             	mov    %r9,%rdi
ffffffff8b07f441:	eb 8d                	jmp    ffffffff8b07f3d0 <frame_candidate_6bf250+0x180>
ffffffff8b07f443:	49 89 c1             	mov    %rax,%r9
ffffffff8b07f446:	4c 89 ca             	mov    %r9,%rdx
ffffffff8b07f449:	48 09 ca             	or     %rcx,%rdx
ffffffff8b07f44c:	0f 84 80 00 00 00    	je     ffffffff8b07f4d2 <frame_candidate_6bf250+0x282>
ffffffff8b07f452:	4c 29 c1             	sub    %r8,%rcx
ffffffff8b07f455:	49 29 c1             	sub    %rax,%r9
ffffffff8b07f458:	4c 8b 3d 71 0f 26 03 	mov    0x3260f71(%rip),%r15        # ffffffff8e2e03d0 <frame_candidate_6c0080+0x3260350>
ffffffff8b07f45f:	48 8d 7d b0          	lea    -0x50(%rbp),%rdi
ffffffff8b07f463:	4c 8d b3 20 01 00 00 	lea    0x120(%rbx),%r14
ffffffff8b07f46a:	48 89 ca             	mov    %rcx,%rdx
ffffffff8b07f46d:	48 8d 81 00 ca 9a 3b 	lea    0x3b9aca00(%rcx),%rax
ffffffff8b07f474:	48 c1 fa 3f          	sar    $0x3f,%rdx
ffffffff8b07f478:	4c 01 ca             	add    %r9,%rdx
ffffffff8b07f47b:	48 85 c9             	test   %rcx,%rcx
ffffffff8b07f47e:	48 89 55 b0          	mov    %rdx,-0x50(%rbp)
ffffffff8b07f482:	48 0f 49 c1          	cmovns %rcx,%rax
ffffffff8b07f486:	48 ba cf f7 53 e3 a5 	movabs $0x20c49ba5e353f7cf,%rdx
ffffffff8b07f48d:	9b c4 20 
ffffffff8b07f490:	48 f7 ea             	imul   %rdx
ffffffff8b07f493:	48 89 d0             	mov    %rdx,%rax
ffffffff8b07f496:	48 c1 fa 07          	sar    $0x7,%rdx
ffffffff8b07f49a:	48 c1 e8 3f          	shr    $0x3f,%rax
ffffffff8b07f49e:	48 01 c2             	add    %rax,%rdx
ffffffff8b07f4a1:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8b07f4a5:	e8 d6 77 5a 00       	call   ffffffff8b626c80 <frame_candidate_6c0080+0x5a6c00>
ffffffff8b07f4aa:	48 63 f0             	movslq %eax,%rsi
ffffffff8b07f4ad:	48 8d 0d e4 3a ba ff 	lea    -0x45c51c(%rip),%rcx        # ffffffff8ac22f98 <handler_639_body-0x45b868>
ffffffff8b07f4b4:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07f4b7:	49 89 d8             	mov    %rbx,%r8
ffffffff8b07f4ba:	41 b9 ff ff ff ff    	mov    $0xffffffff,%r9d
ffffffff8b07f4c0:	c7 04 24 00 01 00 00 	movl   $0x100,(%rsp)
ffffffff8b07f4c7:	31 d2                	xor    %edx,%edx
ffffffff8b07f4c9:	49 0f af f7          	imul   %r15,%rsi
ffffffff8b07f4cd:	e8 6e b5 4d 00       	call   ffffffff8b55aa40 <frame_candidate_6c0080+0x4da9c0>
ffffffff8b07f4d2:	ff 83 9c 00 00 00    	incl   0x9c(%rbx)
ffffffff8b07f4d8:	4c 8d 73 18          	lea    0x18(%rbx),%r14
ffffffff8b07f4dc:	31 f6                	xor    %esi,%esi
ffffffff8b07f4de:	31 d2                	xor    %edx,%edx
ffffffff8b07f4e0:	31 c9                	xor    %ecx,%ecx
ffffffff8b07f4e2:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07f4e5:	e8 b6 7a e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b07f4ea:	4c 8b bb 90 00 00 00 	mov    0x90(%rbx),%r15
ffffffff8b07f4f1:	8b 43 20             	mov    0x20(%rbx),%eax
ffffffff8b07f4f4:	83 f8 04             	cmp    $0x4,%eax
ffffffff8b07f4f7:	74 09                	je     ffffffff8b07f502 <frame_candidate_6bf250+0x2b2>
ffffffff8b07f4f9:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b07f4fc:	0f 85 d0 00 00 00    	jne    ffffffff8b07f5d2 <frame_candidate_6bf250+0x382>
ffffffff8b07f502:	48 8d 73 20          	lea    0x20(%rbx),%rsi
ffffffff8b07f506:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
ffffffff8b07f50a:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b07f50d:	e8 8e 1c ea ff       	call   ffffffff8af211a0 <handler_639_body-0x15d660>
ffffffff8b07f512:	85 c0                	test   %eax,%eax
ffffffff8b07f514:	74 49                	je     ffffffff8b07f55f <frame_candidate_6bf250+0x30f>
ffffffff8b07f516:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07f519:	31 f6                	xor    %esi,%esi
ffffffff8b07f51b:	31 d2                	xor    %edx,%edx
ffffffff8b07f51d:	31 c9                	xor    %ecx,%ecx
ffffffff8b07f51f:	e8 dc 74 e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b07f524:	48 8d bb 20 01 00 00 	lea    0x120(%rbx),%rdi
ffffffff8b07f52b:	48 c7 83 88 00 00 00 	movq   $0x0,0x88(%rbx)
ffffffff8b07f532:	00 00 00 00 
ffffffff8b07f536:	48 c7 83 80 00 00 00 	movq   $0x0,0x80(%rbx)
ffffffff8b07f53d:	00 00 00 00 
ffffffff8b07f541:	48 c7 43 78 00 00 00 	movq   $0x0,0x78(%rbx)
ffffffff8b07f548:	00 
ffffffff8b07f549:	48 c7 43 70 00 00 00 	movq   $0x0,0x70(%rbx)
ffffffff8b07f550:	00 
ffffffff8b07f551:	31 f6                	xor    %esi,%esi
ffffffff8b07f553:	31 d2                	xor    %edx,%edx
ffffffff8b07f555:	e8 76 ba 4d 00       	call   ffffffff8b55afd0 <frame_candidate_6c0080+0x4daf50>
ffffffff8b07f55a:	4d 89 f7             	mov    %r14,%r15
ffffffff8b07f55d:	eb 65                	jmp    ffffffff8b07f5c4 <frame_candidate_6bf250+0x374>
ffffffff8b07f55f:	48 83 bb 18 01 00 00 	cmpq   $0x0,0x118(%rbx)
ffffffff8b07f566:	00 
ffffffff8b07f567:	74 19                	je     ffffffff8b07f582 <frame_candidate_6bf250+0x332>
ffffffff8b07f569:	8b 83 a0 00 00 00    	mov    0xa0(%rbx),%eax
ffffffff8b07f56f:	3d ff ff ff 7f       	cmp    $0x7fffffff,%eax
ffffffff8b07f574:	75 3f                	jne    ffffffff8b07f5b5 <frame_candidate_6bf250+0x365>
ffffffff8b07f576:	c7 83 c4 00 00 00 22 	movl   $0x22,0xc4(%rbx)
ffffffff8b07f57d:	00 00 00 
ffffffff8b07f580:	eb 3b                	jmp    ffffffff8b07f5bd <frame_candidate_6bf250+0x36d>
ffffffff8b07f582:	c7 83 c4 00 00 00 00 	movl   $0x0,0xc4(%rbx)
ffffffff8b07f589:	00 00 00 
ffffffff8b07f58c:	48 8d 8b b0 00 00 00 	lea    0xb0(%rbx),%rcx
ffffffff8b07f593:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b07f596:	8b 53 24             	mov    0x24(%rbx),%edx
ffffffff8b07f599:	89 93 c0 00 00 00    	mov    %edx,0xc0(%rbx)
ffffffff8b07f59f:	48 8b 43 28          	mov    0x28(%rbx),%rax
ffffffff8b07f5a3:	48 89 83 e0 00 00 00 	mov    %rax,0xe0(%rbx)
ffffffff8b07f5aa:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
ffffffff8b07f5ae:	e8 8d 0f ea ff       	call   ffffffff8af20540 <handler_639_body-0x15e2c0>
ffffffff8b07f5b3:	eb 08                	jmp    ffffffff8b07f5bd <frame_candidate_6bf250+0x36d>
ffffffff8b07f5b5:	ff c0                	inc    %eax
ffffffff8b07f5b7:	89 83 a0 00 00 00    	mov    %eax,0xa0(%rbx)
ffffffff8b07f5bd:	49 81 c7 48 01 00 00 	add    $0x148,%r15
ffffffff8b07f5c4:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b07f5c7:	31 f6                	xor    %esi,%esi
ffffffff8b07f5c9:	31 d2                	xor    %edx,%edx
ffffffff8b07f5cb:	31 c9                	xor    %ecx,%ecx
ffffffff8b07f5cd:	e8 ce 79 e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b07f5d2:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07f5d5:	31 f6                	xor    %esi,%esi
ffffffff8b07f5d7:	31 d2                	xor    %edx,%edx
ffffffff8b07f5d9:	31 c9                	xor    %ecx,%ecx
ffffffff8b07f5db:	e8 20 74 e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b07f5e0:	ff 8b 9c 00 00 00    	decl   0x9c(%rbx)
ffffffff8b07f5e6:	75 11                	jne    ffffffff8b07f5f9 <frame_candidate_6bf250+0x3a9>
ffffffff8b07f5e8:	f6 83 98 00 00 00 02 	testb  $0x2,0x98(%rbx)
ffffffff8b07f5ef:	74 08                	je     ffffffff8b07f5f9 <frame_candidate_6bf250+0x3a9>
ffffffff8b07f5f1:	48 89 df             	mov    %rbx,%rdi
ffffffff8b07f5f4:	e8 17 73 54 00       	call   ffffffff8b5c6910 <frame_candidate_6c0080+0x546890>
ffffffff8b07f5f9:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b07f5fd:	48 3b 45 d8          	cmp    -0x28(%rbp),%rax
ffffffff8b07f601:	75 0d                	jne    ffffffff8b07f610 <frame_candidate_6bf250+0x3c0>
ffffffff8b07f603:	48 83 c4 40          	add    $0x40,%rsp
ffffffff8b07f607:	5b                   	pop    %rbx
ffffffff8b07f608:	41 5c                	pop    %r12
ffffffff8b07f60a:	41 5e                	pop    %r14
ffffffff8b07f60c:	41 5f                	pop    %r15
ffffffff8b07f60e:	5d                   	pop    %rbp
ffffffff8b07f60f:	c3                   	ret
ffffffff8b07f610:	e8 9b e0 03 00       	call   ffffffff8b0bd6b0 <frame_candidate_6c0080+0x3d630>
ffffffff8b07f615:	0f 0b                	ud2
ffffffff8b07f617:	90                   	nop
ffffffff8b07f618:	90                   	nop
ffffffff8b07f619:	90                   	nop
ffffffff8b07f61a:	90                   	nop
ffffffff8b07f61b:	90                   	nop
ffffffff8b07f61c:	90                   	nop
ffffffff8b07f61d:	90                   	nop
ffffffff8b07f61e:	90                   	nop
ffffffff8b07f61f:	90                   	nop

ffffffff8b07f620 <frame_candidate_6bf620>:
ffffffff8b07f620:	55                   	push   %rbp
ffffffff8b07f621:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07f624:	41 57                	push   %r15
ffffffff8b07f626:	41 56                	push   %r14
ffffffff8b07f628:	41 55                	push   %r13
ffffffff8b07f62a:	41 54                	push   %r12
ffffffff8b07f62c:	53                   	push   %rbx
ffffffff8b07f62d:	48 81 ec d8 00 00 00 	sub    $0xd8,%rsp
ffffffff8b07f634:	41 89 f4             	mov    %esi,%r12d
ffffffff8b07f637:	83 fe 61             	cmp    $0x61,%esi
ffffffff8b07f63a:	72 50                	jb     ffffffff8b07f68c <frame_candidate_6bf620+0x6c>
ffffffff8b07f63c:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8b07f643:	00 00 
ffffffff8b07f645:	48 8b 40 08          	mov    0x8(%rax),%rax
ffffffff8b07f649:	48 8d 15 90 9b 06 01 	lea    0x1069b90(%rip),%rdx        # ffffffff8c0e91e0 <frame_candidate_6c0080+0x1069160>
ffffffff8b07f650:	48 8d 0d 70 45 bc 00 	lea    0xbc4570(%rip),%rcx        # ffffffff8bc43bc7 <frame_candidate_6c0080+0xbc3b47>
ffffffff8b07f657:	41 b8 7f 01 00 00    	mov    $0x17f,%r8d
ffffffff8b07f65d:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b07f660:	31 ff                	xor    %edi,%edi
ffffffff8b07f662:	31 f6                	xor    %esi,%esi
ffffffff8b07f664:	44 8b 88 bc 00 00 00 	mov    0xbc(%rax),%r9d
ffffffff8b07f66b:	31 c0                	xor    %eax,%eax
ffffffff8b07f66d:	e8 5e 4e 44 00       	call   ffffffff8b4c44d0 <frame_candidate_6c0080+0x444450>
ffffffff8b07f672:	48 8d 15 77 9b 06 01 	lea    0x1069b77(%rip),%rdx        # ffffffff8c0e91f0 <frame_candidate_6c0080+0x1069170>
ffffffff8b07f679:	44 89 e1             	mov    %r12d,%ecx
ffffffff8b07f67c:	31 ff                	xor    %edi,%edi
ffffffff8b07f67e:	31 f6                	xor    %esi,%esi
ffffffff8b07f680:	31 c0                	xor    %eax,%eax
ffffffff8b07f682:	e8 49 4e 44 00       	call   ffffffff8b4c44d0 <frame_candidate_6c0080+0x444450>
ffffffff8b07f687:	e9 0a 06 00 00       	jmp    ffffffff8b07fc96 <frame_candidate_6bf620+0x676>
ffffffff8b07f68c:	41 83 fc 29          	cmp    $0x29,%r12d
ffffffff8b07f690:	74 10                	je     ffffffff8b07f6a2 <frame_candidate_6bf620+0x82>
ffffffff8b07f692:	44 89 e3             	mov    %r12d,%ebx
ffffffff8b07f695:	41 83 fc 2a          	cmp    $0x2a,%r12d
ffffffff8b07f699:	75 0c                	jne    ffffffff8b07f6a7 <frame_candidate_6bf620+0x87>
ffffffff8b07f69b:	bb 2e 00 00 00       	mov    $0x2e,%ebx
ffffffff8b07f6a0:	eb 05                	jmp    ffffffff8b07f6a7 <frame_candidate_6bf620+0x87>
ffffffff8b07f6a2:	bb 08 00 00 00       	mov    $0x8,%ebx
ffffffff8b07f6a7:	89 d8                	mov    %ebx,%eax
ffffffff8b07f6a9:	48 8d 35 a0 99 06 01 	lea    0x10699a0(%rip),%rsi        # ffffffff8c0e9050 <frame_candidate_6c0080+0x1068fd0>
ffffffff8b07f6b0:	8b 04 86             	mov    (%rsi,%rax,4),%eax
ffffffff8b07f6b3:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b07f6b6:	85 c0                	test   %eax,%eax
ffffffff8b07f6b8:	0f 84 79 01 00 00    	je     ffffffff8b07f837 <frame_candidate_6bf620+0x217>
ffffffff8b07f6be:	44 89 e0             	mov    %r12d,%eax
ffffffff8b07f6c1:	48 8d 35 08 de cf 00 	lea    0xcfde08(%rip),%rsi        # ffffffff8bd7d4d0 <frame_candidate_6c0080+0xcfd450>
ffffffff8b07f6c8:	41 bd cd cc cc cc    	mov    $0xcccccccd,%r13d
ffffffff8b07f6ce:	89 4d 90             	mov    %ecx,-0x70(%rbp)
ffffffff8b07f6d1:	83 c3 c8             	add    $0xffffffc8,%ebx
ffffffff8b07f6d4:	44 89 45 d0          	mov    %r8d,-0x30(%rbp)
ffffffff8b07f6d8:	48 89 bd 00 ff ff ff 	mov    %rdi,-0x100(%rbp)
ffffffff8b07f6df:	89 55 c8             	mov    %edx,-0x38(%rbp)
ffffffff8b07f6e2:	4c 69 f8 98 00 00 00 	imul   $0x98,%rax,%r15
ffffffff8b07f6e9:	89 5d cc             	mov    %ebx,-0x34(%rbp)
ffffffff8b07f6ec:	41 8b 44 37 04       	mov    0x4(%r15,%rsi,1),%eax
ffffffff8b07f6f1:	41 0f b6 4c 37 38    	movzbl 0x38(%r15,%rsi,1),%ecx
ffffffff8b07f6f7:	45 8b 74 37 08       	mov    0x8(%r15,%rsi,1),%r14d
ffffffff8b07f6fc:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
ffffffff8b07f703:	48 ff c0             	inc    %rax
ffffffff8b07f706:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
ffffffff8b07f70a:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
ffffffff8b07f711:	41 8b 44 37 58       	mov    0x58(%r15,%rsi,1),%eax
ffffffff8b07f716:	83 c0 05             	add    $0x5,%eax
ffffffff8b07f719:	4c 0f af e8          	imul   %rax,%r13
ffffffff8b07f71d:	41 8b 44 37 0c       	mov    0xc(%r15,%rsi,1),%eax
ffffffff8b07f722:	49 c1 ed 23          	shr    $0x23,%r13
ffffffff8b07f726:	c4 42 f1 f7 e5       	shlx   %rcx,%r13,%r12
ffffffff8b07f72b:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
ffffffff8b07f72f:	89 c3                	mov    %eax,%ebx
ffffffff8b07f731:	e8 1a 7a 3f 00       	call   ffffffff8b477150 <frame_candidate_6c0080+0x3f70d0>
ffffffff8b07f736:	45 89 f0             	mov    %r14d,%r8d
ffffffff8b07f739:	89 c6                	mov    %eax,%esi
ffffffff8b07f73b:	48 b8 00 00 00 40 0d 	movabs $0x30d40000000,%rax
ffffffff8b07f742:	03 00 00 
ffffffff8b07f745:	44 89 b5 74 ff ff ff 	mov    %r14d,-0x8c(%rbp)
ffffffff8b07f74c:	89 9d 7c ff ff ff    	mov    %ebx,-0x84(%rbp)
ffffffff8b07f752:	31 d2                	xor    %edx,%edx
ffffffff8b07f754:	31 c9                	xor    %ecx,%ecx
ffffffff8b07f756:	41 29 d8             	sub    %ebx,%r8d
ffffffff8b07f759:	48 8b 9d 50 ff ff ff 	mov    -0xb0(%rbp),%rbx
ffffffff8b07f760:	49 f7 f4             	div    %r12
ffffffff8b07f763:	ba ff 3f 00 00       	mov    $0x3fff,%edx
ffffffff8b07f768:	45 89 c2             	mov    %r8d,%r10d
ffffffff8b07f76b:	49 89 c6             	mov    %rax,%r14
ffffffff8b07f76e:	48 89 45 98          	mov    %rax,-0x68(%rbp)
ffffffff8b07f772:	4c 0f af f3          	imul   %rbx,%r14
ffffffff8b07f776:	4a 8d 04 b5 00 00 00 	lea    0x0(,%r14,4),%rax
ffffffff8b07f77d:	00 
ffffffff8b07f77e:	48 c1 e8 1a          	shr    $0x1a,%rax
ffffffff8b07f782:	48 3d ff 3f 00 00    	cmp    $0x3fff,%rax
ffffffff8b07f788:	0f 42 d0             	cmovb  %eax,%edx
ffffffff8b07f78b:	48 b8 9e 36 d0 69 03 	movabs $0x369d0369d0369e,%rax
ffffffff8b07f792:	9d 36 00 
ffffffff8b07f795:	41 d1 ea             	shr    $1,%r10d
ffffffff8b07f798:	89 95 78 ff ff ff    	mov    %edx,-0x88(%rbp)
ffffffff8b07f79e:	49 69 d4 93 00 00 00 	imul   $0x93,%r12,%rdx
ffffffff8b07f7a5:	c4 e2 c3 f6 f8       	mulx   %rax,%rdi,%rdi
ffffffff8b07f7aa:	49 6b d4 57          	imul   $0x57,%r12,%rdx
ffffffff8b07f7ae:	4c 89 a5 10 ff ff ff 	mov    %r12,-0xf0(%rbp)
ffffffff8b07f7b5:	c4 e2 fb f6 c0       	mulx   %rax,%rax,%rax
ffffffff8b07f7ba:	69 55 c8 e8 03 00 00 	imul   $0x3e8,-0x38(%rbp),%edx
ffffffff8b07f7c1:	44 89 85 70 ff ff ff 	mov    %r8d,-0x90(%rbp)
ffffffff8b07f7c8:	4c 8d 05 61 ac cf 00 	lea    0xcfac61(%rip),%r8        # ffffffff8bd7a430 <frame_candidate_6c0080+0xcfa3b0>
ffffffff8b07f7cf:	48 01 c2             	add    %rax,%rdx
ffffffff8b07f7d2:	48 01 fa             	add    %rdi,%rdx
ffffffff8b07f7d5:	48 8d 3d f4 dc cf 00 	lea    0xcfdcf4(%rip),%rdi        # ffffffff8bd7d4d0 <frame_candidate_6c0080+0xcfd450>
ffffffff8b07f7dc:	83 7d cc 05          	cmpl   $0x5,-0x34(%rbp)
ffffffff8b07f7e0:	41 8b 44 3f 20       	mov    0x20(%r15,%rdi,1),%eax
ffffffff8b07f7e5:	45 8b 64 3f 18       	mov    0x18(%r15,%rdi,1),%r12d
ffffffff8b07f7ea:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
ffffffff8b07f7f1:	48 63 c6             	movslq %esi,%rax
ffffffff8b07f7f4:	48 be f0 a7 c6 4b 37 	movabs $0x4189374bc6a7f0,%rsi
ffffffff8b07f7fb:	89 41 00 
ffffffff8b07f7fe:	44 0f 43 d1          	cmovae %ecx,%r10d
ffffffff8b07f802:	48 b9 00 00 00 00 ff 	movabs $0x1fffff00000000,%rcx
ffffffff8b07f809:	ff 1f 00 
ffffffff8b07f80c:	41 8b 04 80          	mov    (%r8,%rax,4),%eax
ffffffff8b07f810:	89 45 b0             	mov    %eax,-0x50(%rbp)
ffffffff8b07f813:	41 8b 44 3f 1c       	mov    0x1c(%r15,%rdi,1),%eax
ffffffff8b07f818:	48 89 45 88          	mov    %rax,-0x78(%rbp)
ffffffff8b07f81c:	c4 62 bb f6 c6       	mulx   %rsi,%r8,%r8
ffffffff8b07f821:	48 69 c3 40 42 0f 00 	imul   $0xf4240,%rbx,%rax
ffffffff8b07f828:	48 85 c8             	test   %rcx,%rax
ffffffff8b07f82b:	74 5d                	je     ffffffff8b07f88a <frame_candidate_6bf620+0x26a>
ffffffff8b07f82d:	31 d2                	xor    %edx,%edx
ffffffff8b07f82f:	49 f7 f5             	div    %r13
ffffffff8b07f832:	49 89 c3             	mov    %rax,%r11
ffffffff8b07f835:	eb 5b                	jmp    ffffffff8b07f892 <frame_candidate_6bf620+0x272>
ffffffff8b07f837:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8b07f83e:	00 00 
ffffffff8b07f840:	48 8b 40 08          	mov    0x8(%rax),%rax
ffffffff8b07f844:	48 8d 15 b5 99 06 01 	lea    0x10699b5(%rip),%rdx        # ffffffff8c0e9200 <frame_candidate_6c0080+0x1069180>
ffffffff8b07f84b:	48 8d 0d 75 43 bc 00 	lea    0xbc4375(%rip),%rcx        # ffffffff8bc43bc7 <frame_candidate_6c0080+0xbc3b47>
ffffffff8b07f852:	41 b8 92 01 00 00    	mov    $0x192,%r8d
ffffffff8b07f858:	31 ff                	xor    %edi,%edi
ffffffff8b07f85a:	31 f6                	xor    %esi,%esi
ffffffff8b07f85c:	44 8b 88 bc 00 00 00 	mov    0xbc(%rax),%r9d
ffffffff8b07f863:	31 c0                	xor    %eax,%eax
ffffffff8b07f865:	e8 66 4c 44 00       	call   ffffffff8b4c44d0 <frame_candidate_6c0080+0x444450>
ffffffff8b07f86a:	48 8d 15 9f 99 06 01 	lea    0x106999f(%rip),%rdx        # ffffffff8c0e9210 <frame_candidate_6c0080+0x1069190>
ffffffff8b07f871:	44 89 e1             	mov    %r12d,%ecx
ffffffff8b07f874:	41 89 d8             	mov    %ebx,%r8d
ffffffff8b07f877:	31 ff                	xor    %edi,%edi
ffffffff8b07f879:	31 f6                	xor    %esi,%esi
ffffffff8b07f87b:	31 c0                	xor    %eax,%eax
ffffffff8b07f87d:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b07f880:	e8 4b 4c 44 00       	call   ffffffff8b4c44d0 <frame_candidate_6c0080+0x444450>
ffffffff8b07f885:	e9 0c 04 00 00       	jmp    ffffffff8b07fc96 <frame_candidate_6bf620+0x676>
ffffffff8b07f88a:	31 d2                	xor    %edx,%edx
ffffffff8b07f88c:	41 f7 f5             	div    %r13d
ffffffff8b07f88f:	41 89 c3             	mov    %eax,%r11d
ffffffff8b07f892:	48 8b 8d 58 ff ff ff 	mov    -0xa8(%rbp),%rcx
ffffffff8b07f899:	48 bf c0 cd 95 d4 e8 	movabs $0xe8d495cdc0,%rdi
ffffffff8b07f8a0:	00 00 00 
ffffffff8b07f8a3:	44 8b 7d d4          	mov    -0x2c(%rbp),%r15d
ffffffff8b07f8a7:	48 8d 41 08          	lea    0x8(%rcx),%rax
ffffffff8b07f8ab:	48 83 c1 04          	add    $0x4,%rcx
ffffffff8b07f8af:	48 c1 e8 03          	shr    $0x3,%rax
ffffffff8b07f8b3:	48 c1 e9 02          	shr    $0x2,%rcx
ffffffff8b07f8b7:	48 83 7d a0 00       	cmpq   $0x0,-0x60(%rbp)
ffffffff8b07f8bc:	48 0f 45 c8          	cmovne %rax,%rcx
ffffffff8b07f8c0:	49 69 d5 40 c0 65 03 	imul   $0x365c040,%r13,%rdx
ffffffff8b07f8c7:	48 b8 89 50 6f 09 cc 	movabs $0x8cbccc096f5089,%rax
ffffffff8b07f8ce:	bc 8c 00 
ffffffff8b07f8d1:	48 01 fa             	add    %rdi,%rdx
ffffffff8b07f8d4:	c4 e2 cb f6 f0       	mulx   %rax,%rsi,%rsi
ffffffff8b07f8d9:	49 69 d5 40 59 73 07 	imul   $0x7735940,%r13,%rdx
ffffffff8b07f8e0:	48 89 8d 18 ff ff ff 	mov    %rcx,-0xe8(%rbp)
ffffffff8b07f8e7:	4c 89 ad 08 ff ff ff 	mov    %r13,-0xf8(%rbp)
ffffffff8b07f8ee:	48 c1 ee 1f          	shr    $0x1f,%rsi
ffffffff8b07f8f2:	48 01 fa             	add    %rdi,%rdx
ffffffff8b07f8f5:	48 89 b5 20 ff ff ff 	mov    %rsi,-0xe0(%rbp)
ffffffff8b07f8fc:	4c 8d 0c 0e          	lea    (%rsi,%rcx,1),%r9
ffffffff8b07f900:	c4 e2 f3 f6 c8       	mulx   %rax,%rcx,%rcx
ffffffff8b07f905:	4c 89 d8             	mov    %r11,%rax
ffffffff8b07f908:	48 69 f3 e8 03 00 00 	imul   $0x3e8,%rbx,%rsi
ffffffff8b07f90f:	48 8b bd 00 ff ff ff 	mov    -0x100(%rbp),%rdi
ffffffff8b07f916:	48 c1 e9 1f          	shr    $0x1f,%rcx
ffffffff8b07f91a:	49 01 c9             	add    %rcx,%r9
ffffffff8b07f91d:	48 89 8d 28 ff ff ff 	mov    %rcx,-0xd8(%rbp)
ffffffff8b07f924:	49 0f af c1          	imul   %r9,%rax
ffffffff8b07f928:	48 89 c1             	mov    %rax,%rcx
ffffffff8b07f92b:	48 09 f1             	or     %rsi,%rcx
ffffffff8b07f92e:	48 c1 e9 20          	shr    $0x20,%rcx
ffffffff8b07f932:	8b 4d d0             	mov    -0x30(%rbp),%ecx
ffffffff8b07f935:	74 07                	je     ffffffff8b07f93e <frame_candidate_6bf620+0x31e>
ffffffff8b07f937:	31 d2                	xor    %edx,%edx
ffffffff8b07f939:	48 f7 f6             	div    %rsi
ffffffff8b07f93c:	eb 04                	jmp    ffffffff8b07f942 <frame_candidate_6bf620+0x322>
ffffffff8b07f93e:	31 d2                	xor    %edx,%edx
ffffffff8b07f940:	f7 f6                	div    %esi
ffffffff8b07f942:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8b07f946:	49 69 c1 e8 03 00 00 	imul   $0x3e8,%r9,%rax
ffffffff8b07f94d:	48 be 00 00 00 00 ff 	movabs $0x7ff00000000,%rsi
ffffffff8b07f954:	07 00 00 
ffffffff8b07f957:	48 89 c2             	mov    %rax,%rdx
ffffffff8b07f95a:	48 09 da             	or     %rbx,%rdx
ffffffff8b07f95d:	48 85 f2             	test   %rsi,%rdx
ffffffff8b07f960:	74 07                	je     ffffffff8b07f969 <frame_candidate_6bf620+0x349>
ffffffff8b07f962:	31 d2                	xor    %edx,%edx
ffffffff8b07f964:	48 f7 f3             	div    %rbx
ffffffff8b07f967:	eb 04                	jmp    ffffffff8b07f96d <frame_candidate_6bf620+0x34d>
ffffffff8b07f969:	31 d2                	xor    %edx,%edx
ffffffff8b07f96b:	f7 f3                	div    %ebx
ffffffff8b07f96d:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b07f971:	49 81 fb 80 bb 23 0f 	cmp    $0xf23bb80,%r11
ffffffff8b07f978:	77 13                	ja     ffffffff8b07f98d <frame_candidate_6bf620+0x36d>
ffffffff8b07f97a:	b8 80 bb 23 0f       	mov    $0xf23bb80,%eax
ffffffff8b07f97f:	31 d2                	xor    %edx,%edx
ffffffff8b07f981:	41 f7 f3             	div    %r11d
ffffffff8b07f984:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
ffffffff8b07f98b:	eb 0b                	jmp    ffffffff8b07f998 <frame_candidate_6bf620+0x378>
ffffffff8b07f98d:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
ffffffff8b07f994:	00 00 00 00 
ffffffff8b07f998:	69 45 b0 e8 03 00 00 	imul   $0x3e8,-0x50(%rbp),%eax
ffffffff8b07f99f:	0f b6 c9             	movzbl %cl,%ecx
ffffffff8b07f9a2:	4c 39 d8             	cmp    %r11,%rax
ffffffff8b07f9a5:	72 0a                	jb     ffffffff8b07f9b1 <frame_candidate_6bf620+0x391>
ffffffff8b07f9a7:	31 d2                	xor    %edx,%edx
ffffffff8b07f9a9:	41 f7 f3             	div    %r11d
ffffffff8b07f9ac:	41 89 c5             	mov    %eax,%r13d
ffffffff8b07f9af:	eb 03                	jmp    ffffffff8b07f9b4 <frame_candidate_6bf620+0x394>
ffffffff8b07f9b1:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b07f9b4:	41 29 cf             	sub    %ecx,%r15d
ffffffff8b07f9b7:	4d 01 d0             	add    %r10,%r8
ffffffff8b07f9ba:	49 81 fb c0 5d 00 00 	cmp    $0x5dc0,%r11
ffffffff8b07f9c1:	77 10                	ja     ffffffff8b07f9d3 <frame_candidate_6bf620+0x3b3>
ffffffff8b07f9c3:	b8 c0 5d 00 00       	mov    $0x5dc0,%eax
ffffffff8b07f9c8:	31 d2                	xor    %edx,%edx
ffffffff8b07f9ca:	41 f7 f3             	div    %r11d
ffffffff8b07f9cd:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b07f9d1:	eb 08                	jmp    ffffffff8b07f9db <frame_candidate_6bf620+0x3bb>
ffffffff8b07f9d3:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
ffffffff8b07f9da:	00 
ffffffff8b07f9db:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
ffffffff8b07f9e2:	48 8b 45 88          	mov    -0x78(%rbp),%rax
ffffffff8b07f9e6:	4c 8b 55 a8          	mov    -0x58(%rbp),%r10
ffffffff8b07f9ea:	4c 0f af 55 98       	imul   -0x68(%rbp),%r10
ffffffff8b07f9ef:	41 ff c4             	inc    %r12d
ffffffff8b07f9f2:	0f b6 75 90          	movzbl -0x70(%rbp),%esi
ffffffff8b07f9f6:	44 89 65 d4          	mov    %r12d,-0x2c(%rbp)
ffffffff8b07f9fa:	29 c8                	sub    %ecx,%eax
ffffffff8b07f9fc:	48 0f af cb          	imul   %rbx,%rcx
ffffffff8b07fa00:	89 45 d0             	mov    %eax,-0x30(%rbp)
ffffffff8b07fa03:	44 89 f8             	mov    %r15d,%eax
ffffffff8b07fa06:	48 0f af c3          	imul   %rbx,%rax
ffffffff8b07fa0a:	4c 29 c8             	sub    %r9,%rax
ffffffff8b07fa0d:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b07fa10:	48 39 c8             	cmp    %rcx,%rax
ffffffff8b07fa13:	4c 89 c0             	mov    %r8,%rax
ffffffff8b07fa16:	0f 96 c1             	setbe  %cl
ffffffff8b07fa19:	03 75 a0             	add    -0x60(%rbp),%esi
ffffffff8b07fa1c:	48 09 d8             	or     %rbx,%rax
ffffffff8b07fa1f:	48 c1 e8 20          	shr    $0x20,%rax
ffffffff8b07fa23:	66 85 c0             	test   %ax,%ax
ffffffff8b07fa26:	74 0d                	je     ffffffff8b07fa35 <frame_candidate_6bf620+0x415>
ffffffff8b07fa28:	4c 89 c0             	mov    %r8,%rax
ffffffff8b07fa2b:	31 d2                	xor    %edx,%edx
ffffffff8b07fa2d:	48 f7 f3             	div    %rbx
ffffffff8b07fa30:	49 89 c4             	mov    %rax,%r12
ffffffff8b07fa33:	eb 0a                	jmp    ffffffff8b07fa3f <frame_candidate_6bf620+0x41f>
ffffffff8b07fa35:	44 89 c0             	mov    %r8d,%eax
ffffffff8b07fa38:	31 d2                	xor    %edx,%edx
ffffffff8b07fa3a:	f7 f3                	div    %ebx
ffffffff8b07fa3c:	41 89 c4             	mov    %eax,%r12d
ffffffff8b07fa3f:	4c 89 d8             	mov    %r11,%rax
ffffffff8b07fa42:	4c 8b 45 a0          	mov    -0x60(%rbp),%r8
ffffffff8b07fa46:	41 88 c9             	mov    %cl,%r9b
ffffffff8b07fa49:	48 8b 4d 98          	mov    -0x68(%rbp),%rcx
ffffffff8b07fa4d:	49 01 f4             	add    %rsi,%r12
ffffffff8b07fa50:	49 c1 ea 1a          	shr    $0x1a,%r10
ffffffff8b07fa54:	49 c1 ee 12          	shr    $0x12,%r14
ffffffff8b07fa58:	48 c1 e8 02          	shr    $0x2,%rax
ffffffff8b07fa5c:	4c 89 55 a8          	mov    %r10,-0x58(%rbp)
ffffffff8b07fa60:	4c 89 75 90          	mov    %r14,-0x70(%rbp)
ffffffff8b07fa64:	4c 89 a5 48 ff ff ff 	mov    %r12,-0xb8(%rbp)
ffffffff8b07fa6b:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
ffffffff8b07fa72:	8b 45 d4             	mov    -0x2c(%rbp),%eax
ffffffff8b07fa75:	2b 45 d0             	sub    -0x30(%rbp),%eax
ffffffff8b07fa78:	c4 e2 b9 f7 75 b8    	shlx   %r8,-0x48(%rbp),%rsi
ffffffff8b07fa7e:	44 89 4d b8          	mov    %r9d,-0x48(%rbp)
ffffffff8b07fa82:	89 45 80             	mov    %eax,-0x80(%rbp)
ffffffff8b07fa85:	c4 e2 b9 f7 45 c0    	shlx   %r8,-0x40(%rbp),%rax
ffffffff8b07fa8b:	49 89 d0             	mov    %rdx,%r8
ffffffff8b07fa8e:	48 89 55 c0          	mov    %rdx,-0x40(%rbp)
ffffffff8b07fa92:	4c 0f af c1          	imul   %rcx,%r8
ffffffff8b07fa96:	48 c1 e9 07          	shr    $0x7,%rcx
ffffffff8b07fa9a:	48 89 4d 98          	mov    %rcx,-0x68(%rbp)
ffffffff8b07fa9e:	49 69 cc e8 03 00 00 	imul   $0x3e8,%r12,%rcx
ffffffff8b07faa5:	48 89 b5 38 ff ff ff 	mov    %rsi,-0xc8(%rbp)
ffffffff8b07faac:	49 c1 e8 1a          	shr    $0x1a,%r8
ffffffff8b07fab0:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
ffffffff8b07fab7:	48 69 c2 e8 03 00 00 	imul   $0x3e8,%rdx,%rax
ffffffff8b07fabe:	48 89 c2             	mov    %rax,%rdx
ffffffff8b07fac1:	48 09 da             	or     %rbx,%rdx
ffffffff8b07fac4:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8b07fac8:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
ffffffff8b07facc:	8d 14 95 00 00 00 00 	lea    0x0(,%rdx,4),%edx
ffffffff8b07fad3:	89 55 84             	mov    %edx,-0x7c(%rbp)
ffffffff8b07fad6:	74 07                	je     ffffffff8b07fadf <frame_candidate_6bf620+0x4bf>
ffffffff8b07fad8:	31 d2                	xor    %edx,%edx
ffffffff8b07fada:	48 f7 f3             	div    %rbx
ffffffff8b07fadd:	eb 04                	jmp    ffffffff8b07fae3 <frame_candidate_6bf620+0x4c3>
ffffffff8b07fadf:	31 d2                	xor    %edx,%edx
ffffffff8b07fae1:	f7 f3                	div    %ebx
ffffffff8b07fae3:	45 31 d2             	xor    %r10d,%r10d
ffffffff8b07fae6:	83 7d cc 05          	cmpl   $0x5,-0x34(%rbp)
ffffffff8b07faea:	4d 89 ee             	mov    %r13,%r14
ffffffff8b07faed:	4c 89 de             	mov    %r11,%rsi
ffffffff8b07faf0:	41 0f 92 c2          	setb   %r10b
ffffffff8b07faf4:	48 01 c1             	add    %rax,%rcx
ffffffff8b07faf7:	48 b8 db 34 b6 d7 82 	movabs $0x431bde82d7b634db,%rax
ffffffff8b07fafe:	de 1b 43 
ffffffff8b07fb01:	48 89 ca             	mov    %rcx,%rdx
ffffffff8b07fb04:	49 0f af d3          	imul   %r11,%rdx
ffffffff8b07fb08:	4d 89 eb             	mov    %r13,%r11
ffffffff8b07fb0b:	c4 e2 eb f6 d0       	mulx   %rax,%rdx,%rdx
ffffffff8b07fb10:	4c 8b 4d b0          	mov    -0x50(%rbp),%r9
ffffffff8b07fb14:	41 69 c7 e8 03 00 00 	imul   $0x3e8,%r15d,%eax
ffffffff8b07fb1b:	4c 8b a5 40 ff ff ff 	mov    -0xc0(%rbp),%r12
ffffffff8b07fb22:	48 c1 ea 12          	shr    $0x12,%rdx
ffffffff8b07fb26:	4d 39 e9             	cmp    %r13,%r9
ffffffff8b07fb29:	4c 8b ad 68 ff ff ff 	mov    -0x98(%rbp),%r13
ffffffff8b07fb30:	4d 0f 47 f1          	cmova  %r9,%r14
ffffffff8b07fb34:	45 01 ee             	add    %r13d,%r14d
ffffffff8b07fb37:	45 01 e6             	add    %r12d,%r14d
ffffffff8b07fb3a:	41 01 ce             	add    %ecx,%r14d
ffffffff8b07fb3d:	44 29 f0             	sub    %r14d,%eax
ffffffff8b07fb40:	4c 8b b5 58 ff ff ff 	mov    -0xa8(%rbp),%r14
ffffffff8b07fb47:	44 89 37             	mov    %r14d,(%rdi)
ffffffff8b07fb4a:	89 5f 04             	mov    %ebx,0x4(%rdi)
ffffffff8b07fb4d:	48 8b 5d a0          	mov    -0x60(%rbp),%rbx
ffffffff8b07fb51:	44 8b b5 74 ff ff ff 	mov    -0x8c(%rbp),%r14d
ffffffff8b07fb58:	89 5f 08             	mov    %ebx,0x8(%rdi)
ffffffff8b07fb5b:	48 8b 9d 18 ff ff ff 	mov    -0xe8(%rbp),%rbx
ffffffff8b07fb62:	89 5f 0c             	mov    %ebx,0xc(%rdi)
ffffffff8b07fb65:	48 8b 9d 08 ff ff ff 	mov    -0xf8(%rbp),%rbx
ffffffff8b07fb6c:	89 5f 10             	mov    %ebx,0x10(%rdi)
ffffffff8b07fb6f:	48 8b 9d 10 ff ff ff 	mov    -0xf0(%rbp),%rbx
ffffffff8b07fb76:	89 5f 14             	mov    %ebx,0x14(%rdi)
ffffffff8b07fb79:	48 8b 9d 28 ff ff ff 	mov    -0xd8(%rbp),%rbx
ffffffff8b07fb80:	89 77 18             	mov    %esi,0x18(%rdi)
ffffffff8b07fb83:	44 89 7f 1c          	mov    %r15d,0x1c(%rdi)
ffffffff8b07fb87:	89 5f 20             	mov    %ebx,0x20(%rdi)
ffffffff8b07fb8a:	48 8b 9d 20 ff ff ff 	mov    -0xe0(%rbp),%rbx
ffffffff8b07fb91:	89 5f 24             	mov    %ebx,0x24(%rdi)
ffffffff8b07fb94:	8b 9d 7c ff ff ff    	mov    -0x84(%rbp),%ebx
ffffffff8b07fb9a:	89 5f 28             	mov    %ebx,0x28(%rdi)
ffffffff8b07fb9d:	44 89 77 2c          	mov    %r14d,0x2c(%rdi)
ffffffff8b07fba1:	48 8b 9d 60 ff ff ff 	mov    -0xa0(%rbp),%rbx
ffffffff8b07fba8:	4c 8b 75 88          	mov    -0x78(%rbp),%r14
ffffffff8b07fbac:	89 5f 30             	mov    %ebx,0x30(%rdi)
ffffffff8b07fbaf:	44 89 77 34          	mov    %r14d,0x34(%rdi)
ffffffff8b07fbb3:	89 5f 38             	mov    %ebx,0x38(%rdi)
ffffffff8b07fbb6:	8b 5d 84             	mov    -0x7c(%rbp),%ebx
ffffffff8b07fbb9:	44 89 77 3c          	mov    %r14d,0x3c(%rdi)
ffffffff8b07fbbd:	44 89 77 40          	mov    %r14d,0x40(%rdi)
ffffffff8b07fbc1:	89 5f 44             	mov    %ebx,0x44(%rdi)
ffffffff8b07fbc4:	8b 5d b8             	mov    -0x48(%rbp),%ebx
ffffffff8b07fbc7:	44 89 7f 48          	mov    %r15d,0x48(%rdi)
ffffffff8b07fbcb:	89 5f 4c             	mov    %ebx,0x4c(%rdi)
ffffffff8b07fbce:	44 89 4f 50          	mov    %r9d,0x50(%rdi)
ffffffff8b07fbd2:	4c 8b 8d 38 ff ff ff 	mov    -0xc8(%rbp),%r9
ffffffff8b07fbd9:	8b 5d d4             	mov    -0x2c(%rbp),%ebx
ffffffff8b07fbdc:	44 89 5f 54          	mov    %r11d,0x54(%rdi)
ffffffff8b07fbe0:	44 89 6f 58          	mov    %r13d,0x58(%rdi)
ffffffff8b07fbe4:	44 89 67 5c          	mov    %r12d,0x5c(%rdi)
ffffffff8b07fbe8:	44 8b 5d 80          	mov    -0x80(%rbp),%r11d
ffffffff8b07fbec:	44 89 4f 60          	mov    %r9d,0x60(%rdi)
ffffffff8b07fbf0:	89 5f 64             	mov    %ebx,0x64(%rdi)
ffffffff8b07fbf3:	8b 5d d0             	mov    -0x30(%rbp),%ebx
ffffffff8b07fbf6:	4c 8b 4d 98          	mov    -0x68(%rbp),%r9
ffffffff8b07fbfa:	89 5f 68             	mov    %ebx,0x68(%rdi)
ffffffff8b07fbfd:	44 89 5f 70          	mov    %r11d,0x70(%rdi)
ffffffff8b07fc01:	4c 8b 9d 30 ff ff ff 	mov    -0xd0(%rbp),%r11
ffffffff8b07fc08:	8b 9d 78 ff ff ff    	mov    -0x88(%rbp),%ebx
ffffffff8b07fc0e:	44 89 5f 7c          	mov    %r11d,0x7c(%rdi)
ffffffff8b07fc12:	44 89 8f 80 00 00 00 	mov    %r9d,0x80(%rdi)
ffffffff8b07fc19:	4c 8b 4d 90          	mov    -0x70(%rbp),%r9
ffffffff8b07fc1d:	44 89 8f 84 00 00 00 	mov    %r9d,0x84(%rdi)
ffffffff8b07fc24:	4c 8b 4d a8          	mov    -0x58(%rbp),%r9
ffffffff8b07fc28:	44 89 8f 88 00 00 00 	mov    %r9d,0x88(%rdi)
ffffffff8b07fc2f:	89 9f 8c 00 00 00    	mov    %ebx,0x8c(%rdi)
ffffffff8b07fc35:	44 89 97 90 00 00 00 	mov    %r10d,0x90(%rdi)
ffffffff8b07fc3c:	44 8b 55 c8          	mov    -0x38(%rbp),%r10d
ffffffff8b07fc40:	4c 8b 4d c0          	mov    -0x40(%rbp),%r9
ffffffff8b07fc44:	44 89 97 94 00 00 00 	mov    %r10d,0x94(%rdi)
ffffffff8b07fc4b:	4c 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%r10
ffffffff8b07fc52:	44 89 97 9c 00 00 00 	mov    %r10d,0x9c(%rdi)
ffffffff8b07fc59:	44 89 8f a0 00 00 00 	mov    %r9d,0xa0(%rdi)
ffffffff8b07fc60:	44 89 97 a4 00 00 00 	mov    %r10d,0xa4(%rdi)
ffffffff8b07fc67:	44 89 87 a8 00 00 00 	mov    %r8d,0xa8(%rdi)
ffffffff8b07fc6e:	89 8f ac 00 00 00    	mov    %ecx,0xac(%rdi)
ffffffff8b07fc74:	89 97 b0 00 00 00    	mov    %edx,0xb0(%rdi)
ffffffff8b07fc7a:	8b 95 70 ff ff ff    	mov    -0x90(%rbp),%edx
ffffffff8b07fc80:	44 89 9f b4 00 00 00 	mov    %r11d,0xb4(%rdi)
ffffffff8b07fc87:	89 b7 b8 00 00 00    	mov    %esi,0xb8(%rdi)
ffffffff8b07fc8d:	89 57 6c             	mov    %edx,0x6c(%rdi)
ffffffff8b07fc90:	89 87 bc 00 00 00    	mov    %eax,0xbc(%rdi)
ffffffff8b07fc96:	44 89 f8             	mov    %r15d,%eax
ffffffff8b07fc99:	48 81 c4 d8 00 00 00 	add    $0xd8,%rsp
ffffffff8b07fca0:	5b                   	pop    %rbx
ffffffff8b07fca1:	41 5c                	pop    %r12
ffffffff8b07fca3:	41 5d                	pop    %r13
ffffffff8b07fca5:	41 5e                	pop    %r14
ffffffff8b07fca7:	41 5f                	pop    %r15
ffffffff8b07fca9:	5d                   	pop    %rbp
ffffffff8b07fcaa:	c3                   	ret
ffffffff8b07fcab:	90                   	nop
ffffffff8b07fcac:	90                   	nop
ffffffff8b07fcad:	90                   	nop
ffffffff8b07fcae:	90                   	nop
ffffffff8b07fcaf:	90                   	nop

ffffffff8b07fcb0 <frame_candidate_6bfcb0>:
ffffffff8b07fcb0:	55                   	push   %rbp
ffffffff8b07fcb1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07fcb4:	5d                   	pop    %rbp
ffffffff8b07fcb5:	c3                   	ret
ffffffff8b07fcb6:	90                   	nop
ffffffff8b07fcb7:	90                   	nop
ffffffff8b07fcb8:	90                   	nop
ffffffff8b07fcb9:	90                   	nop
ffffffff8b07fcba:	90                   	nop
ffffffff8b07fcbb:	90                   	nop
ffffffff8b07fcbc:	90                   	nop
ffffffff8b07fcbd:	90                   	nop
ffffffff8b07fcbe:	90                   	nop
ffffffff8b07fcbf:	90                   	nop

ffffffff8b07fcc0 <frame_candidate_6bfcc0>:
ffffffff8b07fcc0:	55                   	push   %rbp
ffffffff8b07fcc1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07fcc4:	41 57                	push   %r15
ffffffff8b07fcc6:	41 56                	push   %r14
ffffffff8b07fcc8:	41 55                	push   %r13
ffffffff8b07fcca:	41 54                	push   %r12
ffffffff8b07fccc:	53                   	push   %rbx
ffffffff8b07fccd:	50                   	push   %rax
ffffffff8b07fcce:	89 f3                	mov    %esi,%ebx
ffffffff8b07fcd0:	48 85 d2             	test   %rdx,%rdx
ffffffff8b07fcd3:	8d 8b d3 fe ff ff    	lea    -0x12d(%rbx),%ecx
ffffffff8b07fcd9:	0f 94 c0             	sete   %al
ffffffff8b07fcdc:	81 f9 d4 fe ff ff    	cmp    $0xfffffed4,%ecx
ffffffff8b07fce2:	0f 92 c1             	setb   %cl
ffffffff8b07fce5:	08 c1                	or     %al,%cl
ffffffff8b07fce7:	b8 01 00 3b 80       	mov    $0x803b0001,%eax
ffffffff8b07fcec:	0f 85 8b 00 00 00    	jne    ffffffff8b07fd7d <frame_candidate_6bfcc0+0xbd>
ffffffff8b07fcf2:	8d 04 dd 00 00 00 00 	lea    0x0(,%rbx,8),%eax
ffffffff8b07fcf9:	49 89 d4             	mov    %rdx,%r12
ffffffff8b07fcfc:	44 8d 3c 40          	lea    (%rax,%rax,2),%r15d
ffffffff8b07fd00:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b07fd03:	e8 68 70 c8 ff       	call   ffffffff8ad06d70 <handler_639_body-0x377a90>
ffffffff8b07fd08:	48 85 c0             	test   %rax,%rax
ffffffff8b07fd0b:	74 6b                	je     ffffffff8b07fd78 <frame_candidate_6bfcc0+0xb8>
ffffffff8b07fd0d:	48 89 c7             	mov    %rax,%rdi
ffffffff8b07fd10:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b07fd13:	49 89 c6             	mov    %rax,%r14
ffffffff8b07fd16:	e8 d5 92 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b07fd1b:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b07fd1e:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b07fd21:	44 89 fa             	mov    %r15d,%edx
ffffffff8b07fd24:	e8 67 78 c8 ff       	call   ffffffff8ad07590 <handler_639_body-0x377270>
ffffffff8b07fd29:	41 89 c5             	mov    %eax,%r13d
ffffffff8b07fd2c:	85 c0                	test   %eax,%eax
ffffffff8b07fd2e:	75 3b                	jne    ffffffff8b07fd6b <frame_candidate_6bfcc0+0xab>
ffffffff8b07fd30:	4c 8d 25 e1 a2 25 03 	lea    0x325a2e1(%rip),%r12        # ffffffff8e2da018 <frame_candidate_6c0080+0x3259f98>
ffffffff8b07fd37:	31 f6                	xor    %esi,%esi
ffffffff8b07fd39:	31 d2                	xor    %edx,%edx
ffffffff8b07fd3b:	31 c9                	xor    %ecx,%ecx
ffffffff8b07fd3d:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b07fd40:	e8 bb 6c e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b07fd45:	48 8d 3d 94 84 25 03 	lea    0x3258494(%rip),%rdi        # ffffffff8e2d81e0 <frame_candidate_6c0080+0x3258160>
ffffffff8b07fd4c:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b07fd4f:	4c 89 fa             	mov    %r15,%rdx
ffffffff8b07fd52:	89 1d f0 7b 25 03    	mov    %ebx,0x3257bf0(%rip)        # ffffffff8e2d7948 <frame_candidate_6c0080+0x32578c8>
ffffffff8b07fd58:	e8 53 93 b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b07fd5d:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b07fd60:	31 f6                	xor    %esi,%esi
ffffffff8b07fd62:	31 d2                	xor    %edx,%edx
ffffffff8b07fd64:	31 c9                	xor    %ecx,%ecx
ffffffff8b07fd66:	e8 35 72 e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b07fd6b:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07fd6e:	e8 cd 71 c8 ff       	call   ffffffff8ad06f40 <handler_639_body-0x3778c0>
ffffffff8b07fd73:	44 89 e8             	mov    %r13d,%eax
ffffffff8b07fd76:	eb 05                	jmp    ffffffff8b07fd7d <frame_candidate_6bfcc0+0xbd>
ffffffff8b07fd78:	b8 0a 00 3b 80       	mov    $0x803b000a,%eax
ffffffff8b07fd7d:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b07fd81:	5b                   	pop    %rbx
ffffffff8b07fd82:	41 5c                	pop    %r12
ffffffff8b07fd84:	41 5d                	pop    %r13
ffffffff8b07fd86:	41 5e                	pop    %r14
ffffffff8b07fd88:	41 5f                	pop    %r15
ffffffff8b07fd8a:	5d                   	pop    %rbp
ffffffff8b07fd8b:	c3                   	ret
ffffffff8b07fd8c:	90                   	nop
ffffffff8b07fd8d:	90                   	nop
ffffffff8b07fd8e:	90                   	nop
ffffffff8b07fd8f:	90                   	nop

ffffffff8b07fd90 <frame_candidate_6bfd90>:
ffffffff8b07fd90:	55                   	push   %rbp
ffffffff8b07fd91:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07fd94:	41 57                	push   %r15
ffffffff8b07fd96:	41 56                	push   %r14
ffffffff8b07fd98:	53                   	push   %rbx
ffffffff8b07fd99:	50                   	push   %rax
ffffffff8b07fd9a:	49 89 fe             	mov    %rdi,%r14
ffffffff8b07fd9d:	bf 20 00 00 00       	mov    $0x20,%edi
ffffffff8b07fda2:	41 89 f7             	mov    %esi,%r15d
ffffffff8b07fda5:	e8 c6 6f c8 ff       	call   ffffffff8ad06d70 <handler_639_body-0x377a90>
ffffffff8b07fdaa:	48 85 c0             	test   %rax,%rax
ffffffff8b07fdad:	74 52                	je     ffffffff8b07fe01 <frame_candidate_6bfd90+0x71>
ffffffff8b07fdaf:	be 20 00 00 00       	mov    $0x20,%esi
ffffffff8b07fdb4:	48 89 c7             	mov    %rax,%rdi
ffffffff8b07fdb7:	48 89 c3             	mov    %rax,%rbx
ffffffff8b07fdba:	e8 31 92 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b07fdbf:	44 89 7b 08          	mov    %r15d,0x8(%rbx)
ffffffff8b07fdc3:	4c 89 73 10          	mov    %r14,0x10(%rbx)
ffffffff8b07fdc7:	31 f6                	xor    %esi,%esi
ffffffff8b07fdc9:	31 d2                	xor    %edx,%edx
ffffffff8b07fdcb:	31 c9                	xor    %ecx,%ecx
ffffffff8b07fdcd:	49 8b 86 80 01 00 00 	mov    0x180(%r14),%rax
ffffffff8b07fdd4:	4c 8d 35 6d a2 25 03 	lea    0x325a26d(%rip),%r14        # ffffffff8e2da048 <frame_candidate_6c0080+0x3259fc8>
ffffffff8b07fddb:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07fdde:	48 89 43 18          	mov    %rax,0x18(%rbx)
ffffffff8b07fde2:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
ffffffff8b07fde9:	e8 12 6c e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b07fdee:	48 83 3d 2a a2 25 03 	cmpq   $0x0,0x325a22a(%rip)        # ffffffff8e2da020 <frame_candidate_6c0080+0x3259fa0>
ffffffff8b07fdf5:	00 
ffffffff8b07fdf6:	74 14                	je     ffffffff8b07fe0c <frame_candidate_6bfd90+0x7c>
ffffffff8b07fdf8:	48 8b 05 29 a2 25 03 	mov    0x325a229(%rip),%rax        # ffffffff8e2da028 <frame_candidate_6c0080+0x3259fa8>
ffffffff8b07fdff:	eb 12                	jmp    ffffffff8b07fe13 <frame_candidate_6bfd90+0x83>
ffffffff8b07fe01:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b07fe05:	5b                   	pop    %rbx
ffffffff8b07fe06:	41 5e                	pop    %r14
ffffffff8b07fe08:	41 5f                	pop    %r15
ffffffff8b07fe0a:	5d                   	pop    %rbp
ffffffff8b07fe0b:	c3                   	ret
ffffffff8b07fe0c:	48 8d 05 0d a2 25 03 	lea    0x325a20d(%rip),%rax        # ffffffff8e2da020 <frame_candidate_6c0080+0x3259fa0>
ffffffff8b07fe13:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07fe16:	48 89 18             	mov    %rbx,(%rax)
ffffffff8b07fe19:	48 89 1d 08 a2 25 03 	mov    %rbx,0x325a208(%rip)        # ffffffff8e2da028 <frame_candidate_6c0080+0x3259fa8>
ffffffff8b07fe20:	31 f6                	xor    %esi,%esi
ffffffff8b07fe22:	31 d2                	xor    %edx,%edx
ffffffff8b07fe24:	31 c9                	xor    %ecx,%ecx
ffffffff8b07fe26:	e8 75 71 e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b07fe2b:	48 8d 3d 1e a2 25 03 	lea    0x325a21e(%rip),%rdi        # ffffffff8e2da050 <frame_candidate_6c0080+0x3259fd0>
ffffffff8b07fe32:	31 f6                	xor    %esi,%esi
ffffffff8b07fe34:	31 d2                	xor    %edx,%edx
ffffffff8b07fe36:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b07fe3a:	5b                   	pop    %rbx
ffffffff8b07fe3b:	41 5e                	pop    %r14
ffffffff8b07fe3d:	41 5f                	pop    %r15
ffffffff8b07fe3f:	5d                   	pop    %rbp
ffffffff8b07fe40:	e9 0b d5 f6 ff       	jmp    ffffffff8afed350 <handler_639_body-0x914b0>
ffffffff8b07fe45:	90                   	nop
ffffffff8b07fe46:	90                   	nop
ffffffff8b07fe47:	90                   	nop
ffffffff8b07fe48:	90                   	nop
ffffffff8b07fe49:	90                   	nop
ffffffff8b07fe4a:	90                   	nop
ffffffff8b07fe4b:	90                   	nop
ffffffff8b07fe4c:	90                   	nop
ffffffff8b07fe4d:	90                   	nop
ffffffff8b07fe4e:	90                   	nop
ffffffff8b07fe4f:	90                   	nop

ffffffff8b07fe50 <frame_candidate_6bfe50>:
ffffffff8b07fe50:	55                   	push   %rbp
ffffffff8b07fe51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07fe54:	41 56                	push   %r14
ffffffff8b07fe56:	53                   	push   %rbx
ffffffff8b07fe57:	48 8b 05 f2 7a 25 03 	mov    0x3257af2(%rip),%rax        # ffffffff8e2d7950 <frame_candidate_6c0080+0x32578d0>
ffffffff8b07fe5e:	48 8b 78 10          	mov    0x10(%rax),%rdi
ffffffff8b07fe62:	e8 d9 75 c8 ff       	call   ffffffff8ad07440 <handler_639_body-0x3773c0>
ffffffff8b07fe67:	bf 20 00 00 00       	mov    $0x20,%edi
ffffffff8b07fe6c:	e8 ff 6e c8 ff       	call   ffffffff8ad06d70 <handler_639_body-0x377a90>
ffffffff8b07fe71:	48 85 c0             	test   %rax,%rax
ffffffff8b07fe74:	74 46                	je     ffffffff8b07febc <frame_candidate_6bfe50+0x6c>
ffffffff8b07fe76:	be 20 00 00 00       	mov    $0x20,%esi
ffffffff8b07fe7b:	48 89 c7             	mov    %rax,%rdi
ffffffff8b07fe7e:	48 89 c3             	mov    %rax,%rbx
ffffffff8b07fe81:	e8 6a 91 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b07fe86:	4c 8d 35 bb a1 25 03 	lea    0x325a1bb(%rip),%r14        # ffffffff8e2da048 <frame_candidate_6c0080+0x3259fc8>
ffffffff8b07fe8d:	c7 43 08 0b 00 00 00 	movl   $0xb,0x8(%rbx)
ffffffff8b07fe94:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
ffffffff8b07fe9b:	31 f6                	xor    %esi,%esi
ffffffff8b07fe9d:	31 d2                	xor    %edx,%edx
ffffffff8b07fe9f:	31 c9                	xor    %ecx,%ecx
ffffffff8b07fea1:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07fea4:	e8 57 6b e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b07fea9:	48 83 3d 6f a1 25 03 	cmpq   $0x0,0x325a16f(%rip)        # ffffffff8e2da020 <frame_candidate_6c0080+0x3259fa0>
ffffffff8b07feb0:	00 
ffffffff8b07feb1:	74 0e                	je     ffffffff8b07fec1 <frame_candidate_6bfe50+0x71>
ffffffff8b07feb3:	48 8b 05 6e a1 25 03 	mov    0x325a16e(%rip),%rax        # ffffffff8e2da028 <frame_candidate_6c0080+0x3259fa8>
ffffffff8b07feba:	eb 0c                	jmp    ffffffff8b07fec8 <frame_candidate_6bfe50+0x78>
ffffffff8b07febc:	5b                   	pop    %rbx
ffffffff8b07febd:	41 5e                	pop    %r14
ffffffff8b07febf:	5d                   	pop    %rbp
ffffffff8b07fec0:	c3                   	ret
ffffffff8b07fec1:	48 8d 05 58 a1 25 03 	lea    0x325a158(%rip),%rax        # ffffffff8e2da020 <frame_candidate_6c0080+0x3259fa0>
ffffffff8b07fec8:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b07fecb:	48 89 18             	mov    %rbx,(%rax)
ffffffff8b07fece:	48 89 1d 53 a1 25 03 	mov    %rbx,0x325a153(%rip)        # ffffffff8e2da028 <frame_candidate_6c0080+0x3259fa8>
ffffffff8b07fed5:	31 f6                	xor    %esi,%esi
ffffffff8b07fed7:	31 d2                	xor    %edx,%edx
ffffffff8b07fed9:	31 c9                	xor    %ecx,%ecx
ffffffff8b07fedb:	e8 c0 70 e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b07fee0:	48 8d 3d 69 a1 25 03 	lea    0x325a169(%rip),%rdi        # ffffffff8e2da050 <frame_candidate_6c0080+0x3259fd0>
ffffffff8b07fee7:	31 f6                	xor    %esi,%esi
ffffffff8b07fee9:	31 d2                	xor    %edx,%edx
ffffffff8b07feeb:	5b                   	pop    %rbx
ffffffff8b07feec:	41 5e                	pop    %r14
ffffffff8b07feee:	5d                   	pop    %rbp
ffffffff8b07feef:	e9 5c d4 f6 ff       	jmp    ffffffff8afed350 <handler_639_body-0x914b0>
ffffffff8b07fef4:	90                   	nop
ffffffff8b07fef5:	90                   	nop
ffffffff8b07fef6:	90                   	nop
ffffffff8b07fef7:	90                   	nop
ffffffff8b07fef8:	90                   	nop
ffffffff8b07fef9:	90                   	nop
ffffffff8b07fefa:	90                   	nop
ffffffff8b07fefb:	90                   	nop
ffffffff8b07fefc:	90                   	nop
ffffffff8b07fefd:	90                   	nop
ffffffff8b07fefe:	90                   	nop
ffffffff8b07feff:	90                   	nop

ffffffff8b07ff00 <frame_candidate_6bff00>:
ffffffff8b07ff00:	55                   	push   %rbp
ffffffff8b07ff01:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07ff04:	48 8b 05 45 7a 25 03 	mov    0x3257a45(%rip),%rax        # ffffffff8e2d7950 <frame_candidate_6c0080+0x32578d0>
ffffffff8b07ff0b:	6b 35 2e 05 26 03 3c 	imul   $0x3c,0x326052e(%rip),%esi        # ffffffff8e2e0440 <frame_candidate_6c0080+0x32603c0>
ffffffff8b07ff12:	48 8b 78 10          	mov    0x10(%rax),%rdi
ffffffff8b07ff16:	5d                   	pop    %rbp
ffffffff8b07ff17:	e9 74 75 c8 ff       	jmp    ffffffff8ad07490 <handler_639_body-0x377370>
ffffffff8b07ff1c:	90                   	nop
ffffffff8b07ff1d:	90                   	nop
ffffffff8b07ff1e:	90                   	nop
ffffffff8b07ff1f:	90                   	nop

ffffffff8b07ff20 <frame_candidate_6bff20>:
ffffffff8b07ff20:	55                   	push   %rbp
ffffffff8b07ff21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07ff24:	48 8b 05 25 7a 25 03 	mov    0x3257a25(%rip),%rax        # ffffffff8e2d7950 <frame_candidate_6c0080+0x32578d0>
ffffffff8b07ff2b:	48 8b 78 10          	mov    0x10(%rax),%rdi
ffffffff8b07ff2f:	5d                   	pop    %rbp
ffffffff8b07ff30:	e9 ab 75 c8 ff       	jmp    ffffffff8ad074e0 <handler_639_body-0x377320>
ffffffff8b07ff35:	90                   	nop
ffffffff8b07ff36:	90                   	nop
ffffffff8b07ff37:	90                   	nop
ffffffff8b07ff38:	90                   	nop
ffffffff8b07ff39:	90                   	nop
ffffffff8b07ff3a:	90                   	nop
ffffffff8b07ff3b:	90                   	nop
ffffffff8b07ff3c:	90                   	nop
ffffffff8b07ff3d:	90                   	nop
ffffffff8b07ff3e:	90                   	nop
ffffffff8b07ff3f:	90                   	nop

ffffffff8b07ff40 <frame_candidate_6bff40>:
ffffffff8b07ff40:	55                   	push   %rbp
ffffffff8b07ff41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b07ff44:	48 8d 3d 15 7a 25 03 	lea    0x3257a15(%rip),%rdi        # ffffffff8e2d7960 <frame_candidate_6c0080+0x32578e0>
ffffffff8b07ff4b:	be 00 01 00 00       	mov    $0x100,%esi
ffffffff8b07ff50:	e8 9b 90 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b07ff55:	48 8d 3d 04 7b 25 03 	lea    0x3257b04(%rip),%rdi        # ffffffff8e2d7a60 <frame_candidate_6c0080+0x32579e0>
ffffffff8b07ff5c:	be 80 07 00 00       	mov    $0x780,%esi
ffffffff8b07ff61:	e8 8a 90 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b07ff66:	48 8d 0d 73 82 25 03 	lea    0x3258273(%rip),%rcx        # ffffffff8e2d81e0 <frame_candidate_6c0080+0x3258160>
ffffffff8b07ff6d:	31 c0                	xor    %eax,%eax
ffffffff8b07ff6f:	90                   	nop
ffffffff8b07ff70:	c6 04 08 ff          	movb   $0xff,(%rax,%rcx,1)
ffffffff8b07ff74:	48 ff c0             	inc    %rax
ffffffff8b07ff77:	48 3d 20 1c 00 00    	cmp    $0x1c20,%rax
ffffffff8b07ff7d:	75 f1                	jne    ffffffff8b07ff70 <frame_candidate_6bff40+0x30>
ffffffff8b07ff7f:	48 8d 3d c2 a0 25 03 	lea    0x325a0c2(%rip),%rdi        # ffffffff8e2da048 <frame_candidate_6c0080+0x3259fc8>
ffffffff8b07ff86:	48 8d 35 fb cc cb 00 	lea    0xcbccfb(%rip),%rsi        # ffffffff8bd3cc88 <frame_candidate_6c0080+0xcbcc08>
ffffffff8b07ff8d:	b9 04 00 00 00       	mov    $0x4,%ecx
ffffffff8b07ff92:	31 d2                	xor    %edx,%edx
ffffffff8b07ff94:	e8 37 7e e0 ff       	call   ffffffff8ae87dd0 <handler_639_body-0x1f6a30>
ffffffff8b07ff99:	48 8d 3d 78 a0 25 03 	lea    0x325a078(%rip),%rdi        # ffffffff8e2da018 <frame_candidate_6c0080+0x3259f98>
ffffffff8b07ffa0:	48 8d 35 21 8d c8 00 	lea    0xc88d21(%rip),%rsi        # ffffffff8bd08cc8 <frame_candidate_6c0080+0xc88c48>
ffffffff8b07ffa7:	b9 04 00 00 00       	mov    $0x4,%ecx
ffffffff8b07ffac:	31 d2                	xor    %edx,%edx
ffffffff8b07ffae:	e8 1d 7e e0 ff       	call   ffffffff8ae87dd0 <handler_639_body-0x1f6a30>
ffffffff8b07ffb3:	48 8d 3d 2e 30 ba ff 	lea    -0x45cfd2(%rip),%rdi        # ffffffff8ac22fe8 <handler_639_body-0x45b818>
ffffffff8b07ffba:	48 8d 15 ee 77 cc 00 	lea    0xcc77ee(%rip),%rdx        # ffffffff8bd477af <frame_candidate_6c0080+0xcc772f>
ffffffff8b07ffc1:	48 8d 0d 88 79 25 03 	lea    0x3257988(%rip),%rcx        # ffffffff8e2d7950 <frame_candidate_6c0080+0x32578d0>
ffffffff8b07ffc8:	31 f6                	xor    %esi,%esi
ffffffff8b07ffca:	e8 01 74 c8 ff       	call   ffffffff8ad073d0 <handler_639_body-0x377430>
ffffffff8b07ffcf:	85 c0                	test   %eax,%eax
ffffffff8b07ffd1:	74 02                	je     ffffffff8b07ffd5 <frame_candidate_6bff40+0x95>
ffffffff8b07ffd3:	5d                   	pop    %rbp
ffffffff8b07ffd4:	c3                   	ret
ffffffff8b07ffd5:	48 8d 05 c3 9b 06 01 	lea    0x1069bc3(%rip),%rax        # ffffffff8c0e9b9f <frame_candidate_6c0080+0x1069b1f>
ffffffff8b07ffdc:	48 8d 15 1d 9e 25 03 	lea    0x3259e1d(%rip),%rdx        # ffffffff8e2d9e00 <frame_candidate_6c0080+0x3259d80>
ffffffff8b07ffe3:	31 c9                	xor    %ecx,%ecx
ffffffff8b07ffe5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b07ffec:	00 00 00 00 
ffffffff8b07fff0:	8b 70 fd             	mov    -0x3(%rax),%esi
ffffffff8b07fff3:	48 83 c0 fc          	add    $0xfffffffffffffffc,%rax
ffffffff8b07fff7:	0f 38 f1 34 11       	movbe  %esi,(%rcx,%rdx,1)
ffffffff8b07fffc:	48 83 c1 04          	add    $0x4,%rcx
ffffffff8b080000:	48 81 f9 00 01 00 00 	cmp    $0x100,%rcx
ffffffff8b080007:	75 e7                	jne    ffffffff8b07fff0 <frame_candidate_6bff40+0xb0>
ffffffff8b080009:	48 8d 05 8f 9c 06 01 	lea    0x1069c8f(%rip),%rax        # ffffffff8c0e9c9f <frame_candidate_6c0080+0x1069c1f>
ffffffff8b080010:	48 8d 15 e9 9e 25 03 	lea    0x3259ee9(%rip),%rdx        # ffffffff8e2d9f00 <frame_candidate_6c0080+0x3259e80>
ffffffff8b080017:	31 c9                	xor    %ecx,%ecx
ffffffff8b080019:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8b080020:	0f b6 78 fe          	movzbl -0x2(%rax),%edi
ffffffff8b080024:	0f b6 30             	movzbl (%rax),%esi
ffffffff8b080027:	48 83 c0 fc          	add    $0xfffffffffffffffc,%rax
ffffffff8b08002b:	c1 e7 10             	shl    $0x10,%edi
ffffffff8b08002e:	09 f7                	or     %esi,%edi
ffffffff8b080030:	89 3c 11             	mov    %edi,(%rcx,%rdx,1)
ffffffff8b080033:	48 83 c1 04          	add    $0x4,%rcx
ffffffff8b080037:	48 81 f9 00 01 00 00 	cmp    $0x100,%rcx
ffffffff8b08003e:	75 e0                	jne    ffffffff8b080020 <frame_candidate_6bff40+0xe0>
ffffffff8b080040:	e8 3b 2e f2 ff       	call   ffffffff8afa2e80 <handler_639_body-0xdb980>
ffffffff8b080045:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b08004a:	85 c0                	test   %eax,%eax
ffffffff8b08004c:	75 22                	jne    ffffffff8b080070 <frame_candidate_6bff40+0x130>
ffffffff8b08004e:	e8 4d 2d f2 ff       	call   ffffffff8afa2da0 <handler_639_body-0xdba60>
ffffffff8b080053:	b9 02 00 00 00       	mov    $0x2,%ecx
ffffffff8b080058:	85 c0                	test   %eax,%eax
ffffffff8b08005a:	75 14                	jne    ffffffff8b080070 <frame_candidate_6bff40+0x130>
ffffffff8b08005c:	e8 5f 2c f2 ff       	call   ffffffff8afa2cc0 <handler_639_body-0xdbb40>
ffffffff8b080061:	85 c0                	test   %eax,%eax
ffffffff8b080063:	b8 ff 00 00 00       	mov    $0xff,%eax
ffffffff8b080068:	b9 04 00 00 00       	mov    $0x4,%ecx
ffffffff8b08006d:	0f 44 c8             	cmove  %eax,%ecx
ffffffff8b080070:	89 0d ca 74 b3 01    	mov    %ecx,0x1b374ca(%rip)        # ffffffff8cbb7540 <frame_candidate_6c0080+0x1b374c0>
ffffffff8b080076:	5d                   	pop    %rbp
ffffffff8b080077:	c3                   	ret
ffffffff8b080078:	90                   	nop
ffffffff8b080079:	90                   	nop
ffffffff8b08007a:	90                   	nop
ffffffff8b08007b:	90                   	nop
ffffffff8b08007c:	90                   	nop
ffffffff8b08007d:	90                   	nop
ffffffff8b08007e:	90                   	nop
ffffffff8b08007f:	90                   	nop

ffffffff8b080080 <frame_candidate_6c0080>:
ffffffff8b080080:	55                   	push   %rbp
ffffffff8b080081:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b080084:	41 57                	push   %r15
ffffffff8b080086:	41 56                	push   %r14
ffffffff8b080088:	41 55                	push   %r13
ffffffff8b08008a:	41 54                	push   %r12
ffffffff8b08008c:	53                   	push   %rbx
ffffffff8b08008d:	48 81 ec 18 02 00 00 	sub    $0x218,%rsp
ffffffff8b080094:	4c 8d 35 14 77 cc 00 	lea    0xcc7714(%rip),%r14        # ffffffff8bd477af <frame_candidate_6c0080+0xcc772f>
ffffffff8b08009b:	be 08 02 00 00       	mov    $0x208,%esi
ffffffff8b0800a0:	ba 07 00 00 00       	mov    $0x7,%edx
ffffffff8b0800a5:	31 c9                	xor    %ecx,%ecx
ffffffff8b0800a7:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b0800aa:	e8 b1 63 26 00       	call   ffffffff8b2e6460 <frame_candidate_6c0080+0x2663e0>
ffffffff8b0800af:	4c 8d 25 9a 9f 25 03 	lea    0x3259f9a(%rip),%r12        # ffffffff8e2da050 <frame_candidate_6c0080+0x3259fd0>
ffffffff8b0800b6:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b0800b9:	31 f6                	xor    %esi,%esi
ffffffff8b0800bb:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b0800be:	e8 0d d2 f6 ff       	call   ffffffff8afed2d0 <handler_639_body-0x91530>
ffffffff8b0800c3:	4c 8d 2d 7e 9f 25 03 	lea    0x3259f7e(%rip),%r13        # ffffffff8e2da048 <frame_candidate_6c0080+0x3259fc8>
ffffffff8b0800ca:	48 8d 1d 77 91 06 01 	lea    0x1069177(%rip),%rbx        # ffffffff8c0e9248 <frame_candidate_6c0080+0x10691c8>
ffffffff8b0800d1:	4c 8d 3d a8 79 25 03 	lea    0x32579a8(%rip),%r15        # ffffffff8e2d7a80 <frame_candidate_6c0080+0x3257a00>
ffffffff8b0800d8:	eb 0e                	jmp    ffffffff8b0800e8 <frame_candidate_6c0080+0x68>
ffffffff8b0800da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8b0800e0:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b0800e3:	e8 58 6e c8 ff       	call   ffffffff8ad06f40 <handler_639_body-0x3778c0>
ffffffff8b0800e8:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b0800eb:	31 f6                	xor    %esi,%esi
ffffffff8b0800ed:	31 d2                	xor    %edx,%edx
ffffffff8b0800ef:	e8 bc d2 f6 ff       	call   ffffffff8afed3b0 <handler_639_body-0x91450>
ffffffff8b0800f4:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b0800f7:	31 f6                	xor    %esi,%esi
ffffffff8b0800f9:	31 d2                	xor    %edx,%edx
ffffffff8b0800fb:	31 c9                	xor    %ecx,%ecx
ffffffff8b0800fd:	e8 fe 68 e0 ff       	call   ffffffff8ae86a00 <handler_639_body-0x1f7e00>
ffffffff8b080102:	4c 8b 35 17 9f 25 03 	mov    0x3259f17(%rip),%r14        # ffffffff8e2da020 <frame_candidate_6c0080+0x3259fa0>
ffffffff8b080109:	4d 85 f6             	test   %r14,%r14
ffffffff8b08010c:	74 52                	je     ffffffff8b080160 <frame_candidate_6c0080+0xe0>
ffffffff8b08010e:	49 8b 06             	mov    (%r14),%rax
ffffffff8b080111:	48 89 05 08 9f 25 03 	mov    %rax,0x3259f08(%rip)        # ffffffff8e2da020 <frame_candidate_6c0080+0x3259fa0>
ffffffff8b080118:	48 85 c0             	test   %rax,%rax
ffffffff8b08011b:	75 0b                	jne    ffffffff8b080128 <frame_candidate_6c0080+0xa8>
ffffffff8b08011d:	48 c7 05 00 9f 25 03 	movq   $0x0,0x3259f00(%rip)        # ffffffff8e2da028 <frame_candidate_6c0080+0x3259fa8>
ffffffff8b080124:	00 00 00 00 
ffffffff8b080128:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b08012b:	31 f6                	xor    %esi,%esi
ffffffff8b08012d:	31 d2                	xor    %edx,%edx
ffffffff8b08012f:	31 c9                	xor    %ecx,%ecx
ffffffff8b080131:	e8 6a 6e e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b080136:	41 83 7e 08 0b       	cmpl   $0xb,0x8(%r14)
ffffffff8b08013b:	75 43                	jne    ffffffff8b080180 <frame_candidate_6c0080+0x100>
ffffffff8b08013d:	e8 3e 73 c8 ff       	call   ffffffff8ad07480 <handler_639_body-0x377380>
ffffffff8b080142:	41 83 7e 08 0b       	cmpl   $0xb,0x8(%r14)
ffffffff8b080147:	74 97                	je     ffffffff8b0800e0 <frame_candidate_6c0080+0x60>
ffffffff8b080149:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b08014c:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8b080151:	e8 5a 31 00 00       	call   ffffffff8b0832b0 <frame_candidate_6c0080+0x3230>
ffffffff8b080156:	eb 88                	jmp    ffffffff8b0800e0 <frame_candidate_6c0080+0x60>
ffffffff8b080158:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8b08015f:	00 
ffffffff8b080160:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b080163:	31 f6                	xor    %esi,%esi
ffffffff8b080165:	31 d2                	xor    %edx,%edx
ffffffff8b080167:	31 c9                	xor    %ecx,%ecx
ffffffff8b080169:	e8 32 6e e0 ff       	call   ffffffff8ae86fa0 <handler_639_body-0x1f7860>
ffffffff8b08016e:	e9 75 ff ff ff       	jmp    ffffffff8b0800e8 <frame_candidate_6c0080+0x68>
ffffffff8b080173:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b08017a:	84 00 00 00 00 00 
ffffffff8b080180:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b080183:	31 f6                	xor    %esi,%esi
ffffffff8b080185:	e8 26 31 00 00       	call   ffffffff8b0832b0 <frame_candidate_6c0080+0x3230>
ffffffff8b08018a:	85 c0                	test   %eax,%eax
ffffffff8b08018c:	0f 88 4e ff ff ff    	js     ffffffff8b0800e0 <frame_candidate_6c0080+0x60>
ffffffff8b080192:	41 8b 46 08          	mov    0x8(%r14),%eax
ffffffff8b080196:	48 83 f8 0b          	cmp    $0xb,%rax
ffffffff8b08019a:	0f 87 a1 09 00 00    	ja     ffffffff8b080b41 <frame_candidate_6c0080+0xac1>
ffffffff8b0801a0:	48 63 04 83          	movslq (%rbx,%rax,4),%rax
ffffffff8b0801a4:	48 01 d8             	add    %rbx,%rax
ffffffff8b0801a7:	ff e0                	jmp    *%rax
ffffffff8b0801a9:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b0801ac:	83 3d cd 78 25 03 01 	cmpl   $0x1,0x32578cd(%rip)        # ffffffff8e2d7a80 <frame_candidate_6c0080+0x3257a00>
ffffffff8b0801b3:	ba b4 00 00 00       	mov    $0xb4,%edx
ffffffff8b0801b8:	48 8d bd e0 fd ff ff 	lea    -0x220(%rbp),%rdi
ffffffff8b0801bf:	c7 85 50 ff ff ff 00 	movl   $0x0,-0xb0(%rbp)
ffffffff8b0801c6:	00 00 00 
ffffffff8b0801c9:	0f 95 c3             	setne  %bl
ffffffff8b0801cc:	31 f6                	xor    %esi,%esi
ffffffff8b0801ce:	e8 5d ad dd ff       	call   ffffffff8ae5af30 <handler_639_body-0x2238d0>
ffffffff8b0801d3:	80 3d b4 7b 25 03 00 	cmpb   $0x0,0x3257bb4(%rip)        # ffffffff8e2d7d8e <frame_candidate_6c0080+0x3257d0e>
ffffffff8b0801da:	c7 85 c0 fe ff ff 00 	movl   $0x0,-0x140(%rbp)
ffffffff8b0801e1:	00 00 00 
ffffffff8b0801e4:	48 c7 85 b8 fe ff ff 	movq   $0x0,-0x148(%rbp)
ffffffff8b0801eb:	00 00 00 00 
ffffffff8b0801ef:	48 c7 85 b0 fe ff ff 	movq   $0x0,-0x150(%rbp)
ffffffff8b0801f6:	00 00 00 00 
ffffffff8b0801fa:	0f 84 d8 0e 00 00    	je     ffffffff8b0810d8 <frame_candidate_6c0080+0x1058>
ffffffff8b080200:	8b 3d ba 7b 25 03    	mov    0x3257bba(%rip),%edi        # ffffffff8e2d7dc0 <frame_candidate_6c0080+0x3257d40>
ffffffff8b080206:	48 8d b5 b0 fe ff ff 	lea    -0x150(%rbp),%rsi
ffffffff8b08020d:	e8 ae 81 10 00       	call   ffffffff8b1883c0 <frame_candidate_6c0080+0x108340>
ffffffff8b080212:	85 c0                	test   %eax,%eax
ffffffff8b080214:	0f 84 7a 10 00 00    	je     ffffffff8b081294 <frame_candidate_6c0080+0x1214>
ffffffff8b08021a:	48 8d 3d b2 0b c3 00 	lea    0xc30bb2(%rip),%rdi        # ffffffff8bcb0dd3 <frame_candidate_6c0080+0xc30d53>
ffffffff8b080221:	48 8d 35 8b 67 c1 00 	lea    0xc1678b(%rip),%rsi        # ffffffff8bc969b3 <frame_candidate_6c0080+0xc16933>
ffffffff8b080228:	ba ff 22 00 00       	mov    $0x22ff,%edx
ffffffff8b08022d:	41 89 c7             	mov    %eax,%r15d
ffffffff8b080230:	31 c0                	xor    %eax,%eax
ffffffff8b080232:	e8 d9 d1 b9 ff       	call   ffffffff8ac1d410 <handler_639_body-0x4613f0>
ffffffff8b080237:	8b 15 83 7b 25 03    	mov    0x3257b83(%rip),%edx        # ffffffff8e2d7dc0 <frame_candidate_6c0080+0x3257d40>
ffffffff8b08023d:	48 8d 3d 5b b3 c0 00 	lea    0xc0b35b(%rip),%rdi        # ffffffff8bc8b59f <frame_candidate_6c0080+0xc0b51f>
ffffffff8b080244:	44 89 fe             	mov    %r15d,%esi
ffffffff8b080247:	31 c0                	xor    %eax,%eax
ffffffff8b080249:	e8 c2 d1 b9 ff       	call   ffffffff8ac1d410 <handler_639_body-0x4613f0>
ffffffff8b08024e:	c7 05 10 78 25 03 67 	movl   $0x67,0x3257810(%rip)        # ffffffff8e2d7a68 <frame_candidate_6c0080+0x32579e8>
ffffffff8b080255:	00 00 00 
ffffffff8b080258:	e9 a6 12 00 00       	jmp    ffffffff8b081503 <frame_candidate_6c0080+0x1483>
ffffffff8b08025d:	48 8d bd e0 fd ff ff 	lea    -0x220(%rbp),%rdi
ffffffff8b080264:	ba 82 00 00 00       	mov    $0x82,%edx
ffffffff8b080269:	31 f6                	xor    %esi,%esi
ffffffff8b08026b:	48 c7 85 c8 fe ff ff 	movq   $0x0,-0x138(%rbp)
ffffffff8b080272:	00 00 00 00 
ffffffff8b080276:	48 c7 85 c0 fe ff ff 	movq   $0x0,-0x140(%rbp)
ffffffff8b08027d:	00 00 00 00 
ffffffff8b080281:	48 c7 85 b8 fe ff ff 	movq   $0x0,-0x148(%rbp)
ffffffff8b080288:	00 00 00 00 
ffffffff8b08028c:	48 c7 85 b0 fe ff ff 	movq   $0x0,-0x150(%rbp)
ffffffff8b080293:	00 00 00 00 
ffffffff8b080297:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b08029a:	e8 91 ac dd ff       	call   ffffffff8ae5af30 <handler_639_body-0x2238d0>
ffffffff8b08029f:	0f b7 05 e6 79 25 03 	movzwl 0x32579e6(%rip),%eax        # ffffffff8e2d7c8c <frame_candidate_6c0080+0x3257c0c>
ffffffff8b0802a6:	4c 8d 3d b3 77 25 03 	lea    0x32577b3(%rip),%r15        # ffffffff8e2d7a60 <frame_candidate_6c0080+0x32579e0>
ffffffff8b0802ad:	0f b7 35 ee 79 25 03 	movzwl 0x32579ee(%rip),%esi        # ffffffff8e2d7ca2 <frame_candidate_6c0080+0x3257c22>
ffffffff8b0802b4:	0f b7 0d d3 79 25 03 	movzwl 0x32579d3(%rip),%ecx        # ffffffff8e2d7c8e <frame_candidate_6c0080+0x3257c0e>
ffffffff8b0802bb:	44 0f b7 0d db 79 25 	movzwl 0x32579db(%rip),%r9d        # ffffffff8e2d7c9e <frame_candidate_6c0080+0x3257c1e>
ffffffff8b0802c2:	03 
ffffffff8b0802c3:	48 8d 3d c6 72 b3 01 	lea    0x1b372c6(%rip),%rdi        # ffffffff8cbb7590 <frame_candidate_6c0080+0x1b37510>
ffffffff8b0802ca:	4a 8d 94 38 78 02 00 	lea    0x278(%rax,%r15,1),%rdx
ffffffff8b0802d1:	00 
ffffffff8b0802d2:	0f b7 05 c3 79 25 03 	movzwl 0x32579c3(%rip),%eax        # ffffffff8e2d7c9c <frame_candidate_6c0080+0x3257c1c>
ffffffff8b0802d9:	89 74 24 08          	mov    %esi,0x8(%rsp)
ffffffff8b0802dd:	be 41 00 00 00       	mov    $0x41,%esi
ffffffff8b0802e2:	4e 8d 84 38 78 02 00 	lea    0x278(%rax,%r15,1),%r8
ffffffff8b0802e9:	00 
ffffffff8b0802ea:	0f b7 05 af 79 25 03 	movzwl 0x32579af(%rip),%eax        # ffffffff8e2d7ca0 <frame_candidate_6c0080+0x3257c20>
ffffffff8b0802f1:	4a 8d 84 38 78 02 00 	lea    0x278(%rax,%r15,1),%rax
ffffffff8b0802f8:	00 
ffffffff8b0802f9:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b0802fd:	e8 3e ea d9 ff       	call   ffffffff8ae1ed40 <handler_639_body-0x25fac0>
ffffffff8b080302:	85 c0                	test   %eax,%eax
ffffffff8b080304:	0f 88 fb 08 00 00    	js     ffffffff8b080c05 <frame_candidate_6c0080+0xb85>
ffffffff8b08030a:	0f b7 05 87 79 25 03 	movzwl 0x3257987(%rip),%eax        # ffffffff8e2d7c98 <frame_candidate_6c0080+0x3257c18>
ffffffff8b080311:	44 0f b7 15 a1 79 25 	movzwl 0x32579a1(%rip),%r10d        # ffffffff8e2d7cba <frame_candidate_6c0080+0x3257c3a>
ffffffff8b080318:	03 
ffffffff8b080319:	0f b7 35 7a 79 25 03 	movzwl 0x325797a(%rip),%esi        # ffffffff8e2d7c9a <frame_candidate_6c0080+0x3257c1a>
ffffffff8b080320:	0f b7 0d 7f 79 25 03 	movzwl 0x325797f(%rip),%ecx        # ffffffff8e2d7ca6 <frame_candidate_6c0080+0x3257c26>
ffffffff8b080327:	44 0f b7 0d 87 79 25 	movzwl 0x3257987(%rip),%r9d        # ffffffff8e2d7cb6 <frame_candidate_6c0080+0x3257c36>
ffffffff8b08032e:	03 
ffffffff8b08032f:	4a 8d bc 38 78 02 00 	lea    0x278(%rax,%r15,1),%rdi
ffffffff8b080336:	00 
ffffffff8b080337:	0f b7 05 66 79 25 03 	movzwl 0x3257966(%rip),%eax        # ffffffff8e2d7ca4 <frame_candidate_6c0080+0x3257c24>
ffffffff8b08033e:	44 89 54 24 08       	mov    %r10d,0x8(%rsp)
ffffffff8b080343:	4a 8d 94 38 78 02 00 	lea    0x278(%rax,%r15,1),%rdx
ffffffff8b08034a:	00 
ffffffff8b08034b:	0f b7 05 62 79 25 03 	movzwl 0x3257962(%rip),%eax        # ffffffff8e2d7cb4 <frame_candidate_6c0080+0x3257c34>
ffffffff8b080352:	4e 8d 84 38 78 02 00 	lea    0x278(%rax,%r15,1),%r8
ffffffff8b080359:	00 
ffffffff8b08035a:	0f b7 05 57 79 25 03 	movzwl 0x3257957(%rip),%eax        # ffffffff8e2d7cb8 <frame_candidate_6c0080+0x3257c38>
ffffffff8b080361:	4a 8d 84 38 78 02 00 	lea    0x278(%rax,%r15,1),%rax
ffffffff8b080368:	00 
ffffffff8b080369:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b08036d:	e8 ce e9 d9 ff       	call   ffffffff8ae1ed40 <handler_639_body-0x25fac0>
ffffffff8b080372:	85 c0                	test   %eax,%eax
ffffffff8b080374:	0f 88 04 0f 00 00    	js     ffffffff8b08127e <frame_candidate_6c0080+0x11fe>
ffffffff8b08037a:	ba 41 00 00 00       	mov    $0x41,%edx
ffffffff8b08037f:	48 89 df             	mov    %rbx,%rdi
ffffffff8b080382:	48 8d 35 01 77 25 03 	lea    0x3257701(%rip),%rsi        # ffffffff8e2d7a8a <frame_candidate_6c0080+0x3257a0a>
ffffffff8b080389:	e8 22 8d b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b08038e:	0f b7 05 f3 78 25 03 	movzwl 0x32578f3(%rip),%eax        # ffffffff8e2d7c88 <frame_candidate_6c0080+0x3257c08>
ffffffff8b080395:	ba 41 00 00 00       	mov    $0x41,%edx
ffffffff8b08039a:	48 8d bd 21 fe ff ff 	lea    -0x1df(%rbp),%rdi
ffffffff8b0803a1:	4a 8d b4 38 78 02 00 	lea    0x278(%rax,%r15,1),%rsi
ffffffff8b0803a8:	00 
ffffffff8b0803a9:	e8 02 8d b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b0803ae:	0f b7 05 fb 78 25 03 	movzwl 0x32578fb(%rip),%eax        # ffffffff8e2d7cb0 <frame_candidate_6c0080+0x3257c30>
ffffffff8b0803b5:	0f b7 0d 06 79 25 03 	movzwl 0x3257906(%rip),%ecx        # ffffffff8e2d7cc2 <frame_candidate_6c0080+0x3257c42>
ffffffff8b0803bc:	0f b7 35 ef 78 25 03 	movzwl 0x32578ef(%rip),%esi        # ffffffff8e2d7cb2 <frame_candidate_6c0080+0x3257c32>
ffffffff8b0803c3:	44 0f b7 0d f3 78 25 	movzwl 0x32578f3(%rip),%r9d        # ffffffff8e2d7cbe <frame_candidate_6c0080+0x3257c3e>
ffffffff8b0803ca:	03 
ffffffff8b0803cb:	48 89 da             	mov    %rbx,%rdx
ffffffff8b0803ce:	4a 8d bc 38 78 02 00 	lea    0x278(%rax,%r15,1),%rdi
ffffffff8b0803d5:	00 
ffffffff8b0803d6:	0f b7 05 df 78 25 03 	movzwl 0x32578df(%rip),%eax        # ffffffff8e2d7cbc <frame_candidate_6c0080+0x3257c3c>
ffffffff8b0803dd:	89 4c 24 08          	mov    %ecx,0x8(%rsp)
ffffffff8b0803e1:	b9 82 00 00 00       	mov    $0x82,%ecx
ffffffff8b0803e6:	4e 8d 84 38 78 02 00 	lea    0x278(%rax,%r15,1),%r8
ffffffff8b0803ed:	00 
ffffffff8b0803ee:	0f b7 05 cb 78 25 03 	movzwl 0x32578cb(%rip),%eax        # ffffffff8e2d7cc0 <frame_candidate_6c0080+0x3257c40>
ffffffff8b0803f5:	4a 8d 84 38 78 02 00 	lea    0x278(%rax,%r15,1),%rax
ffffffff8b0803fc:	00 
ffffffff8b0803fd:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b080401:	e8 3a e9 d9 ff       	call   ffffffff8ae1ed40 <handler_639_body-0x25fac0>
ffffffff8b080406:	85 c0                	test   %eax,%eax
ffffffff8b080408:	0f 88 b0 0f 00 00    	js     ffffffff8b0813be <frame_candidate_6c0080+0x133e>
ffffffff8b08040e:	4c 8d bd b0 fe ff ff 	lea    -0x150(%rbp),%r15
ffffffff8b080415:	41 b9 f0 01 00 00    	mov    $0x1f0,%r9d
ffffffff8b08041b:	bf 0e 00 00 00       	mov    $0xe,%edi
ffffffff8b080420:	48 8d 35 79 98 06 01 	lea    0x1069879(%rip),%rsi        # ffffffff8c0e9ca0 <frame_candidate_6c0080+0x1069c20>
ffffffff8b080427:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8b08042c:	48 8d 0d 6d 9b 06 01 	lea    0x1069b6d(%rip),%rcx        # ffffffff8c0e9fa0 <frame_candidate_6c0080+0x1069f20>
ffffffff8b080433:	4c 8d 05 66 a0 06 01 	lea    0x106a066(%rip),%r8        # ffffffff8c0ea4a0 <frame_candidate_6c0080+0x106a420>
ffffffff8b08043a:	c6 05 fd 7a 25 03 01 	movb   $0x1,0x3257afd(%rip)        # ffffffff8e2d7f3e <frame_candidate_6c0080+0x3257ebe>
ffffffff8b080441:	4c 89 3c 24          	mov    %r15,(%rsp)
ffffffff8b080445:	e8 56 77 57 00       	call   ffffffff8b5f7ba0 <frame_candidate_6c0080+0x577b20>
ffffffff8b08044a:	48 8d 1d f7 8d 06 01 	lea    0x1068df7(%rip),%rbx        # ffffffff8c0e9248 <frame_candidate_6c0080+0x10691c8>
ffffffff8b080451:	85 c0                	test   %eax,%eax
ffffffff8b080453:	0f 88 20 10 00 00    	js     ffffffff8b081479 <frame_candidate_6c0080+0x13f9>
ffffffff8b080459:	bf 40 00 00 00       	mov    $0x40,%edi
ffffffff8b08045e:	e8 0d 69 c8 ff       	call   ffffffff8ad06d70 <handler_639_body-0x377a90>
ffffffff8b080463:	bf 40 00 00 00       	mov    $0x40,%edi
ffffffff8b080468:	49 89 c4             	mov    %rax,%r12
ffffffff8b08046b:	e8 00 69 c8 ff       	call   ffffffff8ad06d70 <handler_639_body-0x377a90>
ffffffff8b080470:	48 89 c1             	mov    %rax,%rcx
ffffffff8b080473:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b080476:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
ffffffff8b08047a:	48 8d b5 e0 fd ff ff 	lea    -0x220(%rbp),%rsi
ffffffff8b080481:	ba 82 00 00 00       	mov    $0x82,%edx
ffffffff8b080486:	4c 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%r8
ffffffff8b08048d:	49 89 cf             	mov    %rcx,%r15
ffffffff8b080490:	4c 89 e1             	mov    %r12,%rcx
ffffffff8b080493:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b080497:	4d 89 f9             	mov    %r15,%r9
ffffffff8b08049a:	e8 01 ea d9 ff       	call   ffffffff8ae1eea0 <handler_639_body-0x25f960>
ffffffff8b08049f:	85 c0                	test   %eax,%eax
ffffffff8b0804a1:	0f 88 af 11 00 00    	js     ffffffff8b081656 <frame_candidate_6c0080+0x15d6>
ffffffff8b0804a7:	0f b7 95 50 ff ff ff 	movzwl -0xb0(%rbp),%edx
ffffffff8b0804ae:	0f b6 45 b0          	movzbl -0x50(%rbp),%eax
ffffffff8b0804b2:	48 8d 3d 27 7a 25 03 	lea    0x3257a27(%rip),%rdi        # ffffffff8e2d7ee0 <frame_candidate_6c0080+0x3257e60>
ffffffff8b0804b9:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b0804bc:	c6 05 19 7a 25 03 30 	movb   $0x30,0x3257a19(%rip)        # ffffffff8e2d7edc <frame_candidate_6c0080+0x3257e5c>
ffffffff8b0804c3:	00 d0                	add    %dl,%al
ffffffff8b0804c5:	04 04                	add    $0x4,%al
ffffffff8b0804c7:	88 05 10 7a 25 03    	mov    %al,0x3257a10(%rip)        # ffffffff8e2d7edd <frame_candidate_6c0080+0x3257e5d>
ffffffff8b0804cd:	c6 05 0a 7a 25 03 02 	movb   $0x2,0x3257a0a(%rip)        # ffffffff8e2d7ede <frame_candidate_6c0080+0x3257e5e>
ffffffff8b0804d4:	88 15 05 7a 25 03    	mov    %dl,0x3257a05(%rip)        # ffffffff8e2d7edf <frame_candidate_6c0080+0x3257e5f>
ffffffff8b0804da:	e8 d1 8b b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b0804df:	0f b7 85 50 ff ff ff 	movzwl -0xb0(%rbp),%eax
ffffffff8b0804e6:	0f b7 55 b0          	movzwl -0x50(%rbp),%edx
ffffffff8b0804ea:	48 8d 0d 6f 75 25 03 	lea    0x325756f(%rip),%rcx        # ffffffff8e2d7a60 <frame_candidate_6c0080+0x32579e0>
ffffffff8b0804f1:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b0804f4:	48 8d bc 08 82 04 00 	lea    0x482(%rax,%rcx,1),%rdi
ffffffff8b0804fb:	00 
ffffffff8b0804fc:	c6 84 08 80 04 00 00 	movb   $0x2,0x480(%rax,%rcx,1)
ffffffff8b080503:	02 
ffffffff8b080504:	88 94 08 81 04 00 00 	mov    %dl,0x481(%rax,%rcx,1)
ffffffff8b08050b:	e8 a0 8b b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b080510:	0f b7 85 50 ff ff ff 	movzwl -0xb0(%rbp),%eax
ffffffff8b080517:	0f b7 4d b0          	movzwl -0x50(%rbp),%ecx
ffffffff8b08051b:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b08051e:	8d 44 08 06          	lea    0x6(%rax,%rcx,1),%eax
ffffffff8b080522:	89 05 b0 79 25 03    	mov    %eax,0x32579b0(%rip)        # ffffffff8e2d7ed8 <frame_candidate_6c0080+0x3257e58>
ffffffff8b080528:	e8 13 6a c8 ff       	call   ffffffff8ad06f40 <handler_639_body-0x3778c0>
ffffffff8b08052d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b080530:	e8 0b 6a c8 ff       	call   ffffffff8ad06f40 <handler_639_body-0x3778c0>
ffffffff8b080535:	c7 05 25 75 25 03 08 	movl   $0x8,0x3257525(%rip)        # ffffffff8e2d7a64 <frame_candidate_6c0080+0x32579e4>
ffffffff8b08053c:	00 00 00 
ffffffff8b08053f:	e9 33 11 00 00       	jmp    ffffffff8b081677 <frame_candidate_6c0080+0x15f7>
ffffffff8b080544:	0f b6 05 39 78 25 03 	movzbl 0x3257839(%rip),%eax        # ffffffff8e2d7d84 <frame_candidate_6c0080+0x3257d04>
ffffffff8b08054b:	be 18 00 00 00       	mov    $0x18,%esi
ffffffff8b080550:	48 8d bd b0 fe ff ff 	lea    -0x150(%rbp),%rdi
ffffffff8b080557:	49 89 df             	mov    %rbx,%r15
ffffffff8b08055a:	88 45 a0             	mov    %al,-0x60(%rbp)
ffffffff8b08055d:	e8 8e 8a b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b080562:	be 18 00 00 00       	mov    $0x18,%esi
ffffffff8b080567:	48 8d bd 50 ff ff ff 	lea    -0xb0(%rbp),%rdi
ffffffff8b08056e:	e8 7d 8a b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b080573:	48 8d 9d e0 fd ff ff 	lea    -0x220(%rbp),%rbx
ffffffff8b08057a:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b08057f:	48 8d 35 ce 77 25 03 	lea    0x32577ce(%rip),%rsi        # ffffffff8e2d7d54 <frame_candidate_6c0080+0x3257cd4>
ffffffff8b080586:	48 89 df             	mov    %rbx,%rdi
ffffffff8b080589:	e8 22 8b b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b08058e:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b080593:	48 8d bd f0 fd ff ff 	lea    -0x210(%rbp),%rdi
ffffffff8b08059a:	48 8d 35 a3 77 25 03 	lea    0x32577a3(%rip),%rsi        # ffffffff8e2d7d44 <frame_candidate_6c0080+0x3257cc4>
ffffffff8b0805a1:	e8 0a 8b b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b0805a6:	ba 20 00 00 00       	mov    $0x20,%edx
ffffffff8b0805ab:	48 8d 7d b0          	lea    -0x50(%rbp),%rdi
ffffffff8b0805af:	48 89 de             	mov    %rbx,%rsi
ffffffff8b0805b2:	48 8d 0d d6 77 25 03 	lea    0x32577d6(%rip),%rcx        # ffffffff8e2d7d8f <frame_candidate_6c0080+0x3257d0f>
ffffffff8b0805b9:	e8 02 e3 d9 ff       	call   ffffffff8ae1e8c0 <handler_639_body-0x25ff40>
ffffffff8b0805be:	85 c0                	test   %eax,%eax
ffffffff8b0805c0:	0f 84 55 06 00 00    	je     ffffffff8b080c1b <frame_candidate_6c0080+0xb9b>
ffffffff8b0805c6:	c7 05 98 74 25 03 9c 	movl   $0x9c,0x3257498(%rip)        # ffffffff8e2d7a68 <frame_candidate_6c0080+0x32579e8>
ffffffff8b0805cd:	00 00 00 
ffffffff8b0805d0:	4c 89 fb             	mov    %r15,%rbx
ffffffff8b0805d3:	e9 9a 0d 00 00       	jmp    ffffffff8b081372 <frame_candidate_6c0080+0x12f2>
ffffffff8b0805d8:	8b 05 a2 74 25 03    	mov    0x32574a2(%rip),%eax        # ffffffff8e2d7a80 <frame_candidate_6c0080+0x3257a00>
ffffffff8b0805de:	ba 70 00 00 00       	mov    $0x70,%edx
ffffffff8b0805e3:	bb 48 00 00 00       	mov    $0x48,%ebx
ffffffff8b0805e8:	be 28 01 00 00       	mov    $0x128,%esi
ffffffff8b0805ed:	4c 8d 2d e0 74 25 03 	lea    0x32574e0(%rip),%r13        # ffffffff8e2d7ad4 <frame_candidate_6c0080+0x3257a54>
ffffffff8b0805f4:	41 bf 30 00 00 00    	mov    $0x30,%r15d
ffffffff8b0805fa:	b9 10 01 00 00       	mov    $0x110,%ecx
ffffffff8b0805ff:	48 8d 3d 1e 76 25 03 	lea    0x325761e(%rip),%rdi        # ffffffff8e2d7c24 <frame_candidate_6c0080+0x3257ba4>
ffffffff8b080606:	4c 8d a5 b0 fe ff ff 	lea    -0x150(%rbp),%r12
ffffffff8b08060d:	83 f8 11             	cmp    $0x11,%eax
ffffffff8b080610:	89 45 a0             	mov    %eax,-0x60(%rbp)
ffffffff8b080613:	b8 50 01 00 00       	mov    $0x150,%eax
ffffffff8b080618:	0f 44 de             	cmove  %esi,%ebx
ffffffff8b08061b:	48 0f 44 d0          	cmove  %rax,%rdx
ffffffff8b08061f:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b080622:	44 0f 44 f9          	cmove  %ecx,%r15d
ffffffff8b080626:	e8 85 8a b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b08062b:	be 20 00 00 00       	mov    $0x20,%esi
ffffffff8b080630:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b080633:	e8 b8 89 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b080638:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b08063b:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b08063e:	89 da                	mov    %ebx,%edx
ffffffff8b080640:	48 8d 0d 49 a4 06 01 	lea    0x106a449(%rip),%rcx        # ffffffff8c0eaa90 <frame_candidate_6c0080+0x106aa10>
ffffffff8b080647:	41 b8 40 00 00 00    	mov    $0x40,%r8d
ffffffff8b08064d:	e8 ce b9 24 00       	call   ffffffff8b2cc020 <frame_candidate_6c0080+0x24bfa0>
ffffffff8b080652:	85 c0                	test   %eax,%eax
ffffffff8b080654:	0f 84 54 08 00 00    	je     ffffffff8b080eae <frame_candidate_6c0080+0xe2e>
ffffffff8b08065a:	41 89 c4             	mov    %eax,%r12d
ffffffff8b08065d:	b8 c0 02 00 00       	mov    $0x2c0,%eax
ffffffff8b080662:	48 8d 1d df 8b 06 01 	lea    0x1068bdf(%rip),%rbx        # ffffffff8c0e9248 <frame_candidate_6c0080+0x10691c8>
ffffffff8b080669:	4c 8d 3d 10 74 25 03 	lea    0x3257410(%rip),%r15        # ffffffff8e2d7a80 <frame_candidate_6c0080+0x3257a00>
ffffffff8b080670:	4c 8d 2d d1 99 25 03 	lea    0x32599d1(%rip),%r13        # ffffffff8e2da048 <frame_candidate_6c0080+0x3259fc8>
ffffffff8b080677:	89 05 eb 73 25 03    	mov    %eax,0x32573eb(%rip)        # ffffffff8e2d7a68 <frame_candidate_6c0080+0x32579e8>
ffffffff8b08067d:	44 89 25 e8 73 25 03 	mov    %r12d,0x32573e8(%rip)        # ffffffff8e2d7a6c <frame_candidate_6c0080+0x32579ec>
ffffffff8b080684:	c7 05 d6 73 25 03 15 	movl   $0x15,0x32573d6(%rip)        # ffffffff8e2d7a64 <frame_candidate_6c0080+0x32579e4>
ffffffff8b08068b:	00 00 00 
ffffffff8b08068e:	4c 8d 25 bb 99 25 03 	lea    0x32599bb(%rip),%r12        # ffffffff8e2da050 <frame_candidate_6c0080+0x3259fd0>
ffffffff8b080695:	e9 a8 fa ff ff       	jmp    ffffffff8b080142 <frame_candidate_6c0080+0xc2>
ffffffff8b08069a:	48 8d 9d e0 fd ff ff 	lea    -0x220(%rbp),%rbx
ffffffff8b0806a1:	ba c0 00 00 00       	mov    $0xc0,%edx
ffffffff8b0806a6:	31 f6                	xor    %esi,%esi
ffffffff8b0806a8:	48 89 df             	mov    %rbx,%rdi
ffffffff8b0806ab:	e8 80 a8 dd ff       	call   ffffffff8ae5af30 <handler_639_body-0x2238d0>
ffffffff8b0806b0:	be 18 00 00 00       	mov    $0x18,%esi
ffffffff8b0806b5:	48 8d bd 50 ff ff ff 	lea    -0xb0(%rbp),%rdi
ffffffff8b0806bc:	48 c7 85 c8 fe ff ff 	movq   $0x0,-0x138(%rbp)
ffffffff8b0806c3:	00 00 00 00 
ffffffff8b0806c7:	48 c7 85 c0 fe ff ff 	movq   $0x0,-0x140(%rbp)
ffffffff8b0806ce:	00 00 00 00 
ffffffff8b0806d2:	48 c7 85 b8 fe ff ff 	movq   $0x0,-0x148(%rbp)
ffffffff8b0806d9:	00 00 00 00 
ffffffff8b0806dd:	48 c7 85 b0 fe ff ff 	movq   $0x0,-0x150(%rbp)
ffffffff8b0806e4:	00 00 00 00 
ffffffff8b0806e8:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
ffffffff8b0806ef:	00 
ffffffff8b0806f0:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
ffffffff8b0806f7:	00 
ffffffff8b0806f8:	e8 f3 88 b9 ff       	call   ffffffff8ac18ff0 <handler_639_body-0x465810>
ffffffff8b0806fd:	80 3d 8a 76 25 03 00 	cmpb   $0x0,0x325768a(%rip)        # ffffffff8e2d7d8e <frame_candidate_6c0080+0x3257d0e>
ffffffff8b080704:	0f 84 65 08 00 00    	je     ffffffff8b080f6f <frame_candidate_6c0080+0xeef>
ffffffff8b08070a:	4c 8d bd b0 fe ff ff 	lea    -0x150(%rbp),%r15
ffffffff8b080711:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b080716:	48 8d 35 17 74 25 03 	lea    0x3257417(%rip),%rsi        # ffffffff8e2d7b34 <frame_candidate_6c0080+0x3257ab4>
ffffffff8b08071d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b080720:	e8 8b 89 b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b080725:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b08072a:	48 8d bd c0 fe ff ff 	lea    -0x140(%rbp),%rdi
ffffffff8b080731:	48 8d 35 ac 74 25 03 	lea    0x32574ac(%rip),%rsi        # ffffffff8e2d7be4 <frame_candidate_6c0080+0x3257b64>
ffffffff8b080738:	e8 73 89 b9 ff       	call   ffffffff8ac190b0 <handler_639_body-0x465750>
ffffffff8b08073d:	8b 3d 7d 76 25 03    	mov    0x325767d(%rip),%edi        # ffffffff8e2d7dc0 <frame_candidate_6c0080+0x3257d40>
ffffffff8b080743:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b080746:	4c 8d 7d b0          	lea    -0x50(%rbp),%r15
ffffffff8b08074a:	48 8d 0d 3e 76 25 03 	lea    0x325763e(%rip),%rcx        # ffffffff8e2d7d8f <frame_candidate_6c0080+0x3257d0f>
ffffffff8b080751:	4c 8d 05 58 76 25 03 	lea    0x3257658(%rip),%r8        # ffffffff8e2d7db0 <frame_candidate_6c0080+0x3257d30>
ffffffff8b080758:	4c 89 fa             	mov    %r15,%rdx
ffffffff8b08075b:	e8 90 7f 10 00       	call   ffffffff8b1886f0 <frame_candidate_6c0080+0x108670>
ffffffff8b080760:	48 89 c1             	mov    %rax,%rcx
ffffffff8b080763:	48 c1 e9 20          	shr    $0x20,%rcx
ffffffff8b080767:	0f 84 76 08 00 00    	je     ffffffff8b080fe3 <frame_candidate_6c0080+0xf63>
ffffffff8b08076d:	83 f8 08             	cmp    $0x8,%eax
ffffffff8b080770:	ba 08 00 00 00       	mov    $0x8,%edx
ffffffff8b080775:	0f 43 c2             	cmovae %edx,%eax
ffffffff8b080778:	05 aa 00 00 00       	add    $0xaa,%eax
ffffffff8b08077d:	e9 23 0c 00 00       	jmp    ffffffff8b0813a5 <frame_candidate_6c0080+0x1325>
ffffffff8b080782:	ba 20 00 00 00       	mov    $0x20,%edx
ffffffff8b080787:	48 8d 3d 12 73 25 03 	lea    0x3257312(%rip),%rdi        # ffffffff8e2d7aa0 <frame_candidate_6c0080+0x3257a20>
ffffffff8b08078e:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b080791:	48 8d 0d f7 75 25 03 	lea    0x32575f7(%rip),%rcx        # ffffffff8e2d7d8f <frame_candidate_6c0080+0x3257d0f>
ffffffff8b080798:	e8 23 e1 d9 ff       	call   ffffffff8ae1e8c0 <handler_639_body-0x25ff40>
ffffffff8b08079d:	85 c0                	test   %eax,%eax
ffffffff8b08079f:	0f 84 02 09 00 00    	je     ffffffff8b0810a7 <frame_candidate_6c0080+0x1027>
ffffffff8b0807a5:	b9 0f 00 00 00       	mov    $0xf,%ecx
ffffffff8b0807aa:	c7 05 b4 72 25 03 88 	movl   $0x88,0x32572b4(%rip)        # ffffffff8e2d7a68 <frame_candidate_6c0080+0x32579e8>
ffffffff8b0807b1:	00 00 00 
ffffffff8b0807b4:	89 05 b2 72 25 03    	mov    %eax,0x32572b2(%rip)        # ffffffff8e2d7a6c <frame_candidate_6c0080+0x32579ec>
ffffffff8b0807ba:	89 0d a4 72 25 03    	mov    %ecx,0x32572a4(%rip)        # ffffffff8e2d7a64 <frame_candidate_6c0080+0x32579e4>
ffffffff8b0807c0:	e9 7d f9 ff ff       	jmp    ffffffff8b080142 <frame_candidate_6c0080+0xc2>
ffffffff8b0807c5:	66 81 3d a2 72 25 03 	cmpw   $0x54c,0x32572a2(%rip)        # ffffffff8e2d7a70 <frame_candidate_6c0080+0x32579f0>
ffffffff8b0807cc:	4c 05 
ffffffff8b0807ce:	48 8d 35 cb 94 06 01 	lea    0x10694cb(%rip),%rsi        # ffffffff8c0e9ca0 <frame_candidate_6c0080+0x1069c20>
ffffffff8b0807d5:	48 8d 0d c4 97 06 01 	lea    0x10697c4(%rip),%rcx        # ffffffff8c0e9fa0 <frame_candidate_6c0080+0x1069f20>
ffffffff8b0807dc:	75 31                	jne    ffffffff8b08080f <frame_candidate_6c0080+0x78f>
ffffffff8b0807de:	0f b7 05 8d 72 25 03 	movzwl 0x325728d(%rip),%eax        # ffffffff8e2d7a72 <frame_candidate_6c0080+0x32579f2>
ffffffff8b0807e5:	4c 8d 05 a4 9e 06 01 	lea    0x1069ea4(%rip),%r8        # ffffffff8c0ea690 <frame_candidate_6c0080+0x106a610>
ffffffff8b0807ec:	3d 4c 0e 00 00       	cmp    $0xe4c,%eax
ffffffff8b0807f1:	74 23                	je     ffffffff8b080816 <frame_candidate_6c0080+0x796>
ffffffff8b0807f3:	4c 8d 05 96 9e 06 01 	lea    0x1069e96(%rip),%r8        # ffffffff8c0ea690 <frame_candidate_6c0080+0x106a610>
ffffffff8b0807fa:	3d c0 0e 00 00       	cmp    $0xec0,%eax
ffffffff8b0807ff:	74                   	.byte 0x74
