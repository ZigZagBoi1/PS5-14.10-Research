; REA 6.7.0 full disassembly of handler_629.bin
; SHA256 3a21c927dae8a20ad2478bd2b258bb46106da60d032c4fe8dfaac0f807f5d905; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25ed0, kernel RVA 0x265ed0.
; REA inspect_with_objdump Evidence: ev_4beecc2e5c9f5e71694d1152e138439ea3d0b62bd106877325474e3603af8c24
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 629; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_629.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25ed0 <handler_629_entry>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266ec8+0x6b5778>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266ec8+0x6b5da8>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266ec8+0x1d1f68>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266ec8+0x1d21a8>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266ec8+0x1d2288>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266ec8+0x1d24d8>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266ec8+0x457608>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266ec8+0x856a68>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266ec8+0x4576f8>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266ec8+0x457938>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266ec8+0x829f48>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266ec8+0x23bf18>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266ec8+0x856c08>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266ec8+0x7d0798>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266ec8+0x8572f8>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266ec8+0x8578e8>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266ec8+0x791328>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266ec8+0x982648>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266ec8+0x740e48>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266ec8+0x742698>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266ec8+0x742f48>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266ec8+0x743078>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266ec8+0x694578>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266ec8+0x23c2d8>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266ec8+0x8579e8>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266ec8+0x744328>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266ec8+0x854ab8>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266ec8+0x492418>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266ec8+0x1cded8>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266ec8+0x1cdee8>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266ec8+0x1cdef8>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266ec8+0x1d0ec8>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266ec8+0x1d13b8>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266ec8+0x87f7c8>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266ec8+0x87f6b8>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266ec8+0x1e2208>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_629_entry-0x1bf110>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266ec8+0x1e3ba8>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266ec8+0x74f248>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_629_entry-0x1be860>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_629_entry-0x1be680>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_629_entry-0x1be650>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266ec8+0x1eb178>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266ec8+0x1eddf8>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266ec8+0x1f0958>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266ec8+0x2070a8>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266ec8+0x2071b8>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266ec8+0x20bac8>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266ec8+0x20c4e8>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266ec8+0x20c9e8>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266ec8+0x20d388>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266ec8+0x20dee8>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266ec8+0x216128>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_629_entry-0x47ee0>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266ec8+0x229438>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266ec8+0x229ee8>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266ec8+0x2310e8>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266ec8+0x231118>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266ec8+0x231768>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266ec8+0x231778>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266ec8+0x690cf8>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266ec8+0x68f938>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266ec8+0x690558>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266ec8+0x6930b8>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266ec8+0x378488>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266ec8+0x378958>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266ec8+0x7cde18>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266ec8+0x3815d8>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266ec8+0x691328>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266ec8+0x692548>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266ec8+0x695528>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266ec8+0x68fdc8>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266ec8+0xa4ab48>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266ec8+0x8514d8>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266ec8+0x8514e8>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266ec8+0x6932f8>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266ec8+0x690c78>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266ec8+0x239a98>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266ec8+0x4c28b8>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266ec8+0x4c28c8>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266ec8+0x4c28d8>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266ec8+0x4546c8>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266ec8+0x851ed8>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266ec8+0x6932a8>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266ec8+0x9181f8>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266ec8+0x918238>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266ec8+0x692e28>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266ec8+0x693878>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266ec8+0x2ebca8>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266ec8+0x2ebd28>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266ec8+0x2ebd88>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266ec8+0x2ebdb8>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266ec8+0x2ebde8>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266ec8+0x2ebe18>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266ec8+0x917938>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266ec8+0x917d18>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266ec8+0x9180a8>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266ec8+0x99fe68>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266ec8+0x52b7c8>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266ec8+0x381c58>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266ec8+0x2ebe48>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266ec8+0x918298>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266ec8+0x377388>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266ec8+0x7edb68>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266ec8+0x7edb78>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266ec8+0x7edb88>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266ec8+0x7edb98>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266ec8+0x7edbb8>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266ec8+0x7edbc8>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266ec8+0x692858>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266ec8+0x7edbe8>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266ec8+0x68f618>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266ec8+0x68f028>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266ec8+0x7edb58>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266ec8+0x7edba8>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266ec8+0x7edbd8>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266ec8+0x47e608>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266ec8+0x9185e8>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266ec8+0x5d6798>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266ec8+0x5d68f8>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266ec8+0x5d6be8>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266ec8+0x5d6fb8>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266ec8+0x692db8>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266ec8+0x693248>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266ec8+0x6922e8>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266ec8+0x693628>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266ec8+0x6911c8>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266ec8+0x694cb8>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266ec8+0x690cb8>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266ec8+0x6909c8>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266ec8+0x6949d8>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266ec8+0x691648>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266ec8+0x691938>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266ec8+0x2341b8>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266ec8+0x2341c8>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266ec8+0x2f8b88>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266ec8+0x9cd9a8>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266ec8+0x575e28>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266ec8+0x575e38>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266ec8+0x575e48>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266ec8+0x575e58>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266ec8+0x575e68>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266ec8+0x33fdc8>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266ec8+0x340438>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266ec8+0x340748>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266ec8+0x340a38>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266ec8+0xa35968>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266ec8+0x341038>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266ec8+0x3411a8>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266ec8+0x9815b8>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266ec8+0x2341d8>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266ec8+0x2341f8>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266ec8+0x234208>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266ec8+0x234218>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266ec8+0x234228>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266ec8+0x2c9858>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266ec8+0x2ca7a8>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266ec8+0x692828>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266ec8+0x2ca368>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266ec8+0x59bf28>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266ec8+0x918278>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266ec8+0x87c718>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266ec8+0x287f58>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266ec8+0x693c48>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266ec8+0x693f68>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266ec8+0x762358>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266ec8+0x762238>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266ec8+0x3db448>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266ec8+0x3db958>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266ec8+0x3dc818>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266ec8+0x3dca08>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266ec8+0x3dcd98>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266ec8+0x7913c8>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266ec8+0x794ca8>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266ec8+0x7de3b8>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266ec8+0xa20dd8>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266ec8+0x798138>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266ec8+0x7998b8>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266ec8+0x799918>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266ec8+0x857968>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266ec8+0x796068>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266ec8+0x38a0f8>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266ec8+0x690528>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266ec8+0x290388>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266ec8+0x796c08>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266ec8+0x796ee8>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266ec8+0x797048>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266ec8+0x3dd608>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266ec8+0x3ea108>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266ec8+0x797b68>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266ec8+0x290a78>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266ec8+0x851c18>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266ec8+0x854798>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266ec8+0x797398>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266ec8+0x797618>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266ec8+0x797768>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266ec8+0x531468>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266ec8+0x856138>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_629_entry-0x169640>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266ec8+0x2381c8>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266ec8+0x238338>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266ec8+0x2596c8>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266ec8+0x2596e8>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_629_entry-0x1bcaa0>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266ec8+0x263488>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266ec8+0x263b78>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_629_entry-0x1bb9c0>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266ec8+0x26e308>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266ec8+0x5aa2e8>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_629_entry-0x24b040>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266ec8+0x289168>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266ec8+0x294d08>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266ec8+0x2a6008>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266ec8+0x2a6018>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266ec8+0x2a6068>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266ec8+0x2a60a8>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266ec8+0x2a60e8>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266ec8+0x2a6118>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266ec8+0x2b7608>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266ec8+0x2b8098>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266ec8+0x2b8138>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266ec8+0x2b81e8>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266ec8+0x2b8418>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266ec8+0x2b87a8>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266ec8+0x2b9018>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266ec8+0x2cf538>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266ec8+0x2dddd8>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266ec8+0x2dfa28>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_629_entry-0x1b48a0>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_629_entry-0x1b3f20>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266ec8+0x2f5078>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266ec8+0x2f5168>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266ec8+0x2f5188>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266ec8+0x307338>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266ec8+0x3185d8>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266ec8+0x72d718>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266ec8+0x31ea88>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266ec8+0x332958>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266ec8+0x333518>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266ec8+0x333668>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266ec8+0x333838>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266ec8+0x333908>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266ec8+0x333b88>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266ec8+0x333c98>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266ec8+0x333d98>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266ec8+0x375008>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266ec8+0x384858>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266ec8+0x385168>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266ec8+0x385c08>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266ec8+0x386578>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266ec8+0x386c68>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_629_entry-0x117c50>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266ec8+0x38a9e8>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266ec8+0x38bc68>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266ec8+0x3961f8>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266ec8+0x3997b8>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266ec8+0x39a078>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266ec8+0x87f5d8>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266ec8+0x3c6bd8>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266ec8+0x3c9408>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266ec8+0x3ce048>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266ec8+0x3d8658>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266ec8+0x3f0ae8>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266ec8+0xa40448>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266ec8+0x3fbfa8>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266ec8+0x3fbfb8>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266ec8+0x411f48>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266ec8+0x411f98>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266ec8+0x411ff8>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266ec8+0x412098>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266ec8+0x4122c8>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266ec8+0x412498>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266ec8+0x4127b8>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_629_entry-0x232340>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_629_entry-0x232230>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_629_entry-0x2321b0>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_629_entry-0x228f60>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_629_entry-0x228df0>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_629_entry-0x228870>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_629_entry-0x227dd0>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_629_entry-0x227d70>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_629_entry-0x227d10>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_629_entry-0x226e60>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_629_entry-0x226e00>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_629_entry-0x226a20>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_629_entry-0x2269c0>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_629_entry-0x226960>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_629_entry-0x226320>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_629_entry-0x225f10>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_629_entry-0x225570>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_629_entry-0x225380>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_629_entry-0x2252a0>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_629_entry-0x2248a0>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_629_entry-0x224780>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_629_entry-0x2246a0>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_629_entry-0x224610>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_629_entry-0x223e70>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_629_entry-0x223a00>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_629_entry-0x223930>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_629_entry-0x2238d0>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266ec8+0x429168>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266ec8+0x42fdf8>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266ec8+0x431708>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266ec8+0x43b188>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266ec8+0x43b3e8>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266ec8+0x447778>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266ec8+0x447928>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_629_entry-0xe4b20>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266ec8+0x4580d8>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_629_entry-0xdde90>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266ec8+0x469c38>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266ec8+0x46a238>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266ec8+0x46a398>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266ec8+0x46a518>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266ec8+0x46a658>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266ec8+0x46a778>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266ec8+0x46a858>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266ec8+0x475798>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266ec8+0x4757c8>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266ec8+0x4757d8>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266ec8+0x479a58>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266ec8+0x47a578>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266ec8+0x47a588>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_629_entry-0xdc460>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_629_entry-0xd5430>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266ec8+0x49baa8>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266ec8+0x49be98>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266ec8+0x49f2a8>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266ec8+0x49f328>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266ec8+0x4a9038>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266ec8+0x4a90e8>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266ec8+0x4a92f8>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266ec8+0x4a9458>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266ec8+0x4abce8>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266ec8+0x4af498>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266ec8+0x4c8aa8>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266ec8+0x4c8ac8>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266ec8+0x4c8b58>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_629_entry-0x1f0a0>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266ec8+0x4fd928>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266ec8+0x50c848>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266ec8+0x50ea88>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266ec8+0x532fc8>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266ec8+0x54c328>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266ec8+0x57b4d8>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266ec8+0x581518>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266ec8+0x5815b8>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266ec8+0x9d42e8>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266ec8+0x9d5818>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266ec8+0x9d57c8>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266ec8+0x9d5868>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266ec8+0x59b358>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266ec8+0x59b628>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266ec8+0x5a56a8>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266ec8+0x5c4438>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266ec8+0x6ba018>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266ec8+0x6b9cc8>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266ec8+0x5c9948>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266ec8+0x5ca038>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266ec8+0x5ce3e8>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266ec8+0x5ce3f8>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266ec8+0x5ce408>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266ec8+0x5ce428>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266ec8+0x5ce578>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266ec8+0x5ce588>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266ec8+0x5ce5c8>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266ec8+0x5cec08>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266ec8+0x5e99a8>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266ec8+0x609428>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266ec8+0x609708>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266ec8+0x60bc28>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266ec8+0x60c938>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_629_entry-0x202490>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_629_entry-0x1ffb60>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_629_entry-0x17f940>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_629_entry-0x17f930>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_629_entry-0x17f770>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_629_entry-0x17f660>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_629_entry-0x17df40>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_629_entry-0x17bf30>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_629_entry-0x17b860>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_629_entry-0x17b770>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_629_entry-0x17ae30>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_629_entry-0x17ad40>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_629_entry-0x178ed0>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_629_entry-0x178dc0>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266ec8+0x6239d8>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266ec8+0x635f28>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_629_entry-0x177380>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266ec8+0x664388>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266ec8+0x6644c8>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266ec8+0x66c098>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266ec8+0x66c0c8>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266ec8+0x671368>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266ec8+0x671f18>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266ec8+0x6728e8>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266ec8+0x672a48>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266ec8+0x6735f8>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266ec8+0x6736a8>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266ec8+0x6736e8>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266ec8+0x69ddb8>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266ec8+0x69df98>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266ec8+0x6b6538>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266ec8+0x6b65d8>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266ec8+0x81b308>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266ec8+0x8db258>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266ec8+0x6fe068>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266ec8+0x70f088>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266ec8+0x70f338>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266ec8+0x725a88>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266ec8+0x725d68>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266ec8+0x726068>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266ec8+0x726818>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266ec8+0x727708>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266ec8+0x727838>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266ec8+0x72b2a8>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266ec8+0x72b378>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_629_entry-0x170ad0>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266ec8+0x73b458>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266ec8+0x73e858>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266ec8+0x745ad8>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266ec8+0x745b58>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_629_entry-0xa7890>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266ec8+0x757e58>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266ec8+0x75f188>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266ec8+0x75f208>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266ec8+0x75f3b8>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266ec8+0x75f448>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266ec8+0x75f5c8>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266ec8+0x75f6e8>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266ec8+0x75f9c8>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266ec8+0x762478>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266ec8+0x762498>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266ec8+0x7624a8>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266ec8+0x7624b8>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266ec8+0x773ee8>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266ec8+0x7740d8>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266ec8+0x775998>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266ec8+0x775d78>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266ec8+0x775fb8>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266ec8+0x776638>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266ec8+0xa43e08>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266ec8+0x776908>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266ec8+0x776ac8>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266ec8+0x776cd8>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266ec8+0x776d38>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266ec8+0x776f88>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266ec8+0x776fe8>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266ec8+0x777128>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266ec8+0x7771a8>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266ec8+0x777228>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266ec8+0x779cc8>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266ec8+0x779e08>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266ec8+0x779ea8>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266ec8+0x77a028>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266ec8+0x77a188>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266ec8+0x77a5c8>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266ec8+0x79f718>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_629_entry-0x164b90>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266ec8+0x7cc068>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266ec8+0x7cc7f8>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266ec8+0x7d1dc8>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266ec8+0x803c38>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266ec8+0x803ce8>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266ec8+0x827d48>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266ec8+0x827f38>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266ec8+0x84a8e8>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266ec8+0x8598e8>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266ec8+0x85bc28>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_629_entry-0x14b780>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266ec8+0x87a3d8>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266ec8+0x87c538>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266ec8+0x87c668>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266ec8+0x87f4f8>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266ec8+0x8a1018>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266ec8+0x8a12c8>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266ec8+0x8a1668>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266ec8+0x8a1948>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266ec8+0x8a27d8>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266ec8+0x8a4628>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_629_entry-0x76de0>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_629_entry-0x75e70>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_629_entry-0x14a520>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266ec8+0x8d4268>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266ec8+0x8e0b78>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266ec8+0x8e94f8>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266ec8+0x8ea048>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266ec8+0x8ea0e8>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266ec8+0x8ea1e8>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266ec8+0x8ea2c8>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266ec8+0x8ea3c8>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266ec8+0x8ea408>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266ec8+0x8ea458>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266ec8+0x8ef9d8>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_629_entry-0x1cbdf0>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266ec8+0x903fa8>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266ec8+0x904cc8>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266ec8+0x906ab8>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266ec8+0x906bd8>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266ec8+0x9072b8>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266ec8+0x90a458>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266ec8+0x90a4a8>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266ec8+0x90a4f8>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266ec8+0x90a548>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266ec8+0x90aa98>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266ec8+0x90ab08>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266ec8+0x90ab78>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266ec8+0x90abe8>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266ec8+0x90b758>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

ffffffff8ac26eb8 <neighbor_trampoline_266eb8>:
ffffffff8ac26eb8:	e9 a3 b9 90 00       	jmp    ffffffff8b532860 <neighbor_trampoline_266ec8+0x90b998>
ffffffff8ac26ebd:	cc                   	int3
ffffffff8ac26ebe:	cc                   	int3
ffffffff8ac26ebf:	cc                   	int3

ffffffff8ac26ec0 <neighbor_trampoline_266ec0>:
ffffffff8ac26ec0:	e9 0b 23 91 00       	jmp    ffffffff8b5391d0 <neighbor_trampoline_266ec8+0x912308>
ffffffff8ac26ec5:	cc                   	int3
ffffffff8ac26ec6:	cc                   	int3
ffffffff8ac26ec7:	cc                   	int3

ffffffff8ac26ec8 <neighbor_trampoline_266ec8>:
ffffffff8ac26ec8:	e9 c3 23 91 00       	jmp    ffffffff8b539290 <neighbor_trampoline_266ec8+0x9123c8>
ffffffff8ac26ecd:	cc                   	int3
ffffffff8ac26ece:	cc                   	int3
ffffffff8ac26ecf:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8b2dc640, handler_body_629; REA Evidence ev_5aa01f4ed4f350e07834ff29c35eb1795427b17baf6dc10025caa84fa8d2c74e
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8b2dc640", "end": "0xffffffff8b2dc73c"}], "total_bytes": 253, "span_bytes": 253, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_629:
0xffffffff8b2dc640: PUSH RBP
0xffffffff8b2dc641: MOV RBP, RSP
0xffffffff8b2dc644: PUSH R15
0xffffffff8b2dc646: PUSH R14
0xffffffff8b2dc648: PUSH R12
0xffffffff8b2dc64a: PUSH RBX
0xffffffff8b2dc64b: CMP qword ptr [RSI], 0x1
0xffffffff8b2dc64f: MOV R14, RSI
0xffffffff8b2dc652: JZ 0xffffffff8b2dc6f8
loc_ffffffff8b2dc658:
0xffffffff8b2dc658: MOV R15, RDI
0xffffffff8b2dc65b: LEA RSI, [-0x730ee1f0]
0xffffffff8b2dc662: MOV EDI, 0x400
0xffffffff8b2dc667: MOV EDX, 0x2
0xffffffff8b2dc66c: CALL 0xffffffff8b5c8b50
0xffffffff8b2dc671: MOV R12, qword ptr [R14]
0xffffffff8b2dc674: MOV RDI, qword ptr GS:[0x0]
0xffffffff8b2dc67d: LEA RSI, [-0x742e5f7c]
0xffffffff8b2dc684: XOR EDX, EDX
0xffffffff8b2dc686: MOV RBX, RAX
0xffffffff8b2dc689: CALL 0xffffffff8b5da3e0
0xffffffff8b2dc68e: MOV EDX, 0x400
0xffffffff8b2dc693: MOV RDI, R12
0xffffffff8b2dc696: MOV RSI, RBX
0xffffffff8b2dc699: XOR ECX, ECX
0xffffffff8b2dc69b: CALL 0xffffffff8ac19900
0xffffffff8b2dc6a0: TEST EAX, EAX
0xffffffff8b2dc6a2: JNZ 0xffffffff8b2dc71a
loc_ffffffff8b2dc6a4:
0xffffffff8b2dc6a4: CMP byte ptr [RBX], 0x2f
0xffffffff8b2dc6a7: MOV R12D, 0x16
0xffffffff8b2dc6ad: JNZ 0xffffffff8b2dc71d
loc_ffffffff8b2dc6af:
0xffffffff8b2dc6af: MOV RDI, qword ptr [R15 + 0x140]
0xffffffff8b2dc6b6: CALL 0xffffffff8afc92d0
0xffffffff8b2dc6bb: TEST EAX, EAX
0xffffffff8b2dc6bd: JZ 0xffffffff8b2dc738
loc_ffffffff8b2dc6bf:
0xffffffff8b2dc6bf: LEA RSI, [-0x73e22b6c]
0xffffffff8b2dc6c6: MOV EDX, 0xc
0xffffffff8b2dc6cb: MOV RDI, RBX
0xffffffff8b2dc6ce: CALL 0xffffffff8b291a30
0xffffffff8b2dc6d3: TEST EAX, EAX
0xffffffff8b2dc6d5: JZ 0xffffffff8b2dc738
loc_ffffffff8b2dc6d7:
0xffffffff8b2dc6d7: LEA RDI, [-0x7439b480]
0xffffffff8b2dc6de: LEA RCX, [-0x73e22b6c]
0xffffffff8b2dc6e5: MOV RSI, R15
0xffffffff8b2dc6e8: MOV RDX, RBX
0xffffffff8b2dc6eb: CALL 0xffffffff8b1cd5a0
0xffffffff8b2dc6f0: MOV R12D, 0x2
0xffffffff8b2dc6f6: JMP 0xffffffff8b2dc71d
loc_ffffffff8b2dc6f8:
0xffffffff8b2dc6f8: XOR EBX, EBX
loc_ffffffff8b2dc6fa:
0xffffffff8b2dc6fa: MOV RSI, qword ptr [R14]
0xffffffff8b2dc6fd: MOV EDX, dword ptr [R14 + 0x8]
0xffffffff8b2dc701: MOVZX ECX, word ptr [R14 + 0x10]
0xffffffff8b2dc706: MOV R8D, dword ptr [R14 + 0x18]
0xffffffff8b2dc70a: CMP RSI, 0x1
0xffffffff8b2dc70e: CMOVNZ RSI, RBX
0xffffffff8b2dc712: XOR R9D, R9D
0xffffffff8b2dc715: CALL 0xffffffff8b2dbca0
loc_ffffffff8b2dc71a:
0xffffffff8b2dc71a: MOV R12D, EAX
loc_ffffffff8b2dc71d:
0xffffffff8b2dc71d: LEA RSI, [-0x730ee1f0]
0xffffffff8b2dc724: MOV RDI, RBX
0xffffffff8b2dc727: CALL 0xffffffff8b5c8df0
0xffffffff8b2dc72c: MOV EAX, R12D
0xffffffff8b2dc72f: POP RBX
0xffffffff8b2dc730: POP R12
0xffffffff8b2dc732: POP R14
0xffffffff8b2dc734: POP R15
0xffffffff8b2dc736: POP RBP
0xffffffff8b2dc737: RET
loc_ffffffff8b2dc738:
0xffffffff8b2dc738: MOV RDI, R15
0xffffffff8b2dc73b: JMP 0xffffffff8b2dc6fa
; END FUNCTION handler_body_629

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_ebd141a49c0619c60b12e9a18ccb01b4f8a2e85387232c34ebb33c3248adaf3b
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_629.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8b2dc640 <handler_629_body>:
ffffffff8b2dc640:	55                   	push   %rbp
ffffffff8b2dc641:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dc644:	41 57                	push   %r15
ffffffff8b2dc646:	41 56                	push   %r14
ffffffff8b2dc648:	41 54                	push   %r12
ffffffff8b2dc64a:	53                   	push   %rbx
ffffffff8b2dc64b:	48 83 3e 01          	cmpq   $0x1,(%rsi)
ffffffff8b2dc64f:	49 89 f6             	mov    %rsi,%r14
ffffffff8b2dc652:	0f 84 a0 00 00 00    	je     ffffffff8b2dc6f8 <handler_629_body+0xb8>
ffffffff8b2dc658:	49 89 ff             	mov    %rdi,%r15
ffffffff8b2dc65b:	48 8d 35 ae 57 c3 01 	lea    0x1c357ae(%rip),%rsi        # ffffffff8cf11e10 <frame_candidate_91e450+0x1c339c0>
ffffffff8b2dc662:	bf 00 04 00 00       	mov    $0x400,%edi
ffffffff8b2dc667:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b2dc66c:	e8 df c4 2e 00       	call   ffffffff8b5c8b50 <frame_candidate_91e450+0x2ea700>
ffffffff8b2dc671:	4d 8b 26             	mov    (%r14),%r12
ffffffff8b2dc674:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b2dc67b:	00 00 
ffffffff8b2dc67d:	48 8d 35 00 da a3 00 	lea    0xa3da00(%rip),%rsi        # ffffffff8bd1a084 <frame_candidate_91e450+0xa3bc34>
ffffffff8b2dc684:	31 d2                	xor    %edx,%edx
ffffffff8b2dc686:	48 89 c3             	mov    %rax,%rbx
ffffffff8b2dc689:	e8 52 dd 2f 00       	call   ffffffff8b5da3e0 <frame_candidate_91e450+0x2fbf90>
ffffffff8b2dc68e:	ba 00 04 00 00       	mov    $0x400,%edx
ffffffff8b2dc693:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b2dc696:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dc699:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dc69b:	e8 60 d2 93 ff       	call   ffffffff8ac19900 <handler_629_body-0x6c2d40>
ffffffff8b2dc6a0:	85 c0                	test   %eax,%eax
ffffffff8b2dc6a2:	75 76                	jne    ffffffff8b2dc71a <handler_629_body+0xda>
ffffffff8b2dc6a4:	80 3b 2f             	cmpb   $0x2f,(%rbx)
ffffffff8b2dc6a7:	41 bc 16 00 00 00    	mov    $0x16,%r12d
ffffffff8b2dc6ad:	75 6e                	jne    ffffffff8b2dc71d <handler_629_body+0xdd>
ffffffff8b2dc6af:	49 8b bf 40 01 00 00 	mov    0x140(%r15),%rdi
ffffffff8b2dc6b6:	e8 15 cc ce ff       	call   ffffffff8afc92d0 <handler_629_body-0x313370>
ffffffff8b2dc6bb:	85 c0                	test   %eax,%eax
ffffffff8b2dc6bd:	74 79                	je     ffffffff8b2dc738 <handler_629_body+0xf8>
ffffffff8b2dc6bf:	48 8d 35 ce 0d f0 00 	lea    0xf00dce(%rip),%rsi        # ffffffff8c1dd494 <frame_candidate_91e450+0xeff044>
ffffffff8b2dc6c6:	ba 0c 00 00 00       	mov    $0xc,%edx
ffffffff8b2dc6cb:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dc6ce:	e8 5d 53 fb ff       	call   ffffffff8b291a30 <handler_629_body-0x4ac10>
ffffffff8b2dc6d3:	85 c0                	test   %eax,%eax
ffffffff8b2dc6d5:	74 61                	je     ffffffff8b2dc738 <handler_629_body+0xf8>
ffffffff8b2dc6d7:	48 8d 3d a2 84 98 00 	lea    0x9884a2(%rip),%rdi        # ffffffff8bc64b80 <frame_candidate_91e450+0x986730>
ffffffff8b2dc6de:	48 8d 0d af 0d f0 00 	lea    0xf00daf(%rip),%rcx        # ffffffff8c1dd494 <frame_candidate_91e450+0xeff044>
ffffffff8b2dc6e5:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2dc6e8:	48 89 da             	mov    %rbx,%rdx
ffffffff8b2dc6eb:	e8 b0 0e ef ff       	call   ffffffff8b1cd5a0 <handler_629_body-0x10f0a0>
ffffffff8b2dc6f0:	41 bc 02 00 00 00    	mov    $0x2,%r12d
ffffffff8b2dc6f6:	eb 25                	jmp    ffffffff8b2dc71d <handler_629_body+0xdd>
ffffffff8b2dc6f8:	31 db                	xor    %ebx,%ebx
ffffffff8b2dc6fa:	49 8b 36             	mov    (%r14),%rsi
ffffffff8b2dc6fd:	41 8b 56 08          	mov    0x8(%r14),%edx
ffffffff8b2dc701:	41 0f b7 4e 10       	movzwl 0x10(%r14),%ecx
ffffffff8b2dc706:	45 8b 46 18          	mov    0x18(%r14),%r8d
ffffffff8b2dc70a:	48 83 fe 01          	cmp    $0x1,%rsi
ffffffff8b2dc70e:	48 0f 45 f3          	cmovne %rbx,%rsi
ffffffff8b2dc712:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b2dc715:	e8 86 f5 ff ff       	call   ffffffff8b2dbca0 <handler_629_body-0x9a0>
ffffffff8b2dc71a:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2dc71d:	48 8d 35 ec 56 c3 01 	lea    0x1c356ec(%rip),%rsi        # ffffffff8cf11e10 <frame_candidate_91e450+0x1c339c0>
ffffffff8b2dc724:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dc727:	e8 c4 c6 2e 00       	call   ffffffff8b5c8df0 <frame_candidate_91e450+0x2ea9a0>
ffffffff8b2dc72c:	44 89 e0             	mov    %r12d,%eax
ffffffff8b2dc72f:	5b                   	pop    %rbx
ffffffff8b2dc730:	41 5c                	pop    %r12
ffffffff8b2dc732:	41 5e                	pop    %r14
ffffffff8b2dc734:	41 5f                	pop    %r15
ffffffff8b2dc736:	5d                   	pop    %rbp
ffffffff8b2dc737:	c3                   	ret
ffffffff8b2dc738:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b2dc73b:	eb bd                	jmp    ffffffff8b2dc6fa <handler_629_body+0xba>
ffffffff8b2dc73d:	90                   	nop
ffffffff8b2dc73e:	90                   	nop
ffffffff8b2dc73f:	90                   	nop

ffffffff8b2dc740 <frame_candidate_91c740>:
ffffffff8b2dc740:	55                   	push   %rbp
ffffffff8b2dc741:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dc744:	41 57                	push   %r15
ffffffff8b2dc746:	41 56                	push   %r14
ffffffff8b2dc748:	53                   	push   %rbx
ffffffff8b2dc749:	50                   	push   %rax
ffffffff8b2dc74a:	49 89 fe             	mov    %rdi,%r14
ffffffff8b2dc74d:	48 8d 3d fc a1 25 03 	lea    0x325a1fc(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dc754:	49 89 f7             	mov    %rsi,%r15
ffffffff8b2dc757:	31 f6                	xor    %esi,%esi
ffffffff8b2dc759:	31 d2                	xor    %edx,%edx
ffffffff8b2dc75b:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dc75d:	e8 9e a2 ba ff       	call   ffffffff8ae86a00 <handler_629_body-0x455c40>
ffffffff8b2dc762:	48 8b 1d f7 a1 25 03 	mov    0x325a1f7(%rip),%rbx        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc769:	eb 08                	jmp    ffffffff8b2dc773 <frame_candidate_91c740+0x33>
ffffffff8b2dc76b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8b2dc770:	48 8b 1b             	mov    (%rbx),%rbx
ffffffff8b2dc773:	48 85 db             	test   %rbx,%rbx
ffffffff8b2dc776:	74 1d                	je     ffffffff8b2dc795 <frame_candidate_91c740+0x55>
ffffffff8b2dc778:	48 8b 73 20          	mov    0x20(%rbx),%rsi
ffffffff8b2dc77c:	ba 00 04 00 00       	mov    $0x400,%edx
ffffffff8b2dc781:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b2dc784:	e8 a7 52 fb ff       	call   ffffffff8b291a30 <handler_629_body-0x4ac10>
ffffffff8b2dc789:	85 c0                	test   %eax,%eax
ffffffff8b2dc78b:	78 e3                	js     ffffffff8b2dc770 <frame_candidate_91c740+0x30>
ffffffff8b2dc78d:	74 2c                	je     ffffffff8b2dc7bb <frame_candidate_91c740+0x7b>
ffffffff8b2dc78f:	48 83 c3 08          	add    $0x8,%rbx
ffffffff8b2dc793:	eb db                	jmp    ffffffff8b2dc770 <frame_candidate_91c740+0x30>
ffffffff8b2dc795:	48 8d 3d b4 a1 25 03 	lea    0x325a1b4(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dc79c:	31 f6                	xor    %esi,%esi
ffffffff8b2dc79e:	31 d2                	xor    %edx,%edx
ffffffff8b2dc7a0:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dc7a2:	e8 f9 a7 ba ff       	call   ffffffff8ae86fa0 <handler_629_body-0x4556a0>
ffffffff8b2dc7a7:	41 be 02 00 00 00    	mov    $0x2,%r14d
ffffffff8b2dc7ad:	44 89 f0             	mov    %r14d,%eax
ffffffff8b2dc7b0:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dc7b4:	5b                   	pop    %rbx
ffffffff8b2dc7b5:	41 5e                	pop    %r14
ffffffff8b2dc7b7:	41 5f                	pop    %r15
ffffffff8b2dc7b9:	5d                   	pop    %rbp
ffffffff8b2dc7ba:	c3                   	ret
ffffffff8b2dc7bb:	48 8b 43 28          	mov    0x28(%rbx),%rax
ffffffff8b2dc7bf:	4d 8b 8e 40 01 00 00 	mov    0x140(%r14),%r9
ffffffff8b2dc7c6:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2dc7cb:	41 b8 80 00 00 00    	mov    $0x80,%r8d
ffffffff8b2dc7d1:	0f b7 70 10          	movzwl 0x10(%rax),%esi
ffffffff8b2dc7d5:	8b 50 08             	mov    0x8(%rax),%edx
ffffffff8b2dc7d8:	8b 48 0c             	mov    0xc(%rax),%ecx
ffffffff8b2dc7db:	48 c7 04 24 00 00 00 	movq   $0x0,(%rsp)
ffffffff8b2dc7e2:	00 
ffffffff8b2dc7e3:	e8 88 02 c3 ff       	call   ffffffff8af0ca70 <handler_629_body-0x3cfbd0>
ffffffff8b2dc7e8:	85 c0                	test   %eax,%eax
ffffffff8b2dc7ea:	74 17                	je     ffffffff8b2dc803 <frame_candidate_91c740+0xc3>
ffffffff8b2dc7ec:	48 8d 3d 5d a1 25 03 	lea    0x325a15d(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dc7f3:	41 89 c6             	mov    %eax,%r14d
ffffffff8b2dc7f6:	31 f6                	xor    %esi,%esi
ffffffff8b2dc7f8:	31 d2                	xor    %edx,%edx
ffffffff8b2dc7fa:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dc7fc:	e8 9f a7 ba ff       	call   ffffffff8ae86fa0 <handler_629_body-0x4556a0>
ffffffff8b2dc801:	eb aa                	jmp    ffffffff8b2dc7ad <frame_candidate_91c740+0x6d>
ffffffff8b2dc803:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b2dc806:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8b2dc80a:	48 85 c0             	test   %rax,%rax
ffffffff8b2dc80d:	74 40                	je     ffffffff8b2dc84f <frame_candidate_91c740+0x10f>
ffffffff8b2dc80f:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dc812:	74 4c                	je     ffffffff8b2dc860 <frame_candidate_91c740+0x120>
ffffffff8b2dc814:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dc81b:	00 00 00 00 00 
ffffffff8b2dc820:	48 89 fe             	mov    %rdi,%rsi
ffffffff8b2dc823:	48 8b 3f             	mov    (%rdi),%rdi
ffffffff8b2dc826:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dc829:	75 f5                	jne    ffffffff8b2dc820 <frame_candidate_91c740+0xe0>
ffffffff8b2dc82b:	48 8b 46 08          	mov    0x8(%rsi),%rax
ffffffff8b2dc82f:	48 8b 4e 10          	mov    0x10(%rsi),%rcx
ffffffff8b2dc833:	8b 56 18             	mov    0x18(%rsi),%edx
ffffffff8b2dc836:	48 85 c0             	test   %rax,%rax
ffffffff8b2dc839:	74 04                	je     ffffffff8b2dc83f <frame_candidate_91c740+0xff>
ffffffff8b2dc83b:	48 89 48 10          	mov    %rcx,0x10(%rax)
ffffffff8b2dc83f:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dc842:	74 37                	je     ffffffff8b2dc87b <frame_candidate_91c740+0x13b>
ffffffff8b2dc844:	48 39 31             	cmp    %rsi,(%rcx)
ffffffff8b2dc847:	74 52                	je     ffffffff8b2dc89b <frame_candidate_91c740+0x15b>
ffffffff8b2dc849:	48 89 41 08          	mov    %rax,0x8(%rcx)
ffffffff8b2dc84d:	eb 4f                	jmp    ffffffff8b2dc89e <frame_candidate_91c740+0x15e>
ffffffff8b2dc84f:	48 8b 4b 10          	mov    0x10(%rbx),%rcx
ffffffff8b2dc853:	8b 53 18             	mov    0x18(%rbx),%edx
ffffffff8b2dc856:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dc859:	74 2e                	je     ffffffff8b2dc889 <frame_candidate_91c740+0x149>
ffffffff8b2dc85b:	48 89 f8             	mov    %rdi,%rax
ffffffff8b2dc85e:	eb 07                	jmp    ffffffff8b2dc867 <frame_candidate_91c740+0x127>
ffffffff8b2dc860:	48 8b 4b 10          	mov    0x10(%rbx),%rcx
ffffffff8b2dc864:	8b 53 18             	mov    0x18(%rbx),%edx
ffffffff8b2dc867:	48 89 48 10          	mov    %rcx,0x10(%rax)
ffffffff8b2dc86b:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dc86e:	74 20                	je     ffffffff8b2dc890 <frame_candidate_91c740+0x150>
ffffffff8b2dc870:	48 39 19             	cmp    %rbx,(%rcx)
ffffffff8b2dc873:	74 0f                	je     ffffffff8b2dc884 <frame_candidate_91c740+0x144>
ffffffff8b2dc875:	48 89 41 08          	mov    %rax,0x8(%rcx)
ffffffff8b2dc879:	eb 7d                	jmp    ffffffff8b2dc8f8 <frame_candidate_91c740+0x1b8>
ffffffff8b2dc87b:	48 89 05 de a0 25 03 	mov    %rax,0x325a0de(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc882:	eb 1a                	jmp    ffffffff8b2dc89e <frame_candidate_91c740+0x15e>
ffffffff8b2dc884:	48 89 01             	mov    %rax,(%rcx)
ffffffff8b2dc887:	eb 6f                	jmp    ffffffff8b2dc8f8 <frame_candidate_91c740+0x1b8>
ffffffff8b2dc889:	31 c0                	xor    %eax,%eax
ffffffff8b2dc88b:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dc88e:	75 e0                	jne    ffffffff8b2dc870 <frame_candidate_91c740+0x130>
ffffffff8b2dc890:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dc892:	48 89 05 c7 a0 25 03 	mov    %rax,0x325a0c7(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc899:	eb 5d                	jmp    ffffffff8b2dc8f8 <frame_candidate_91c740+0x1b8>
ffffffff8b2dc89b:	48 89 01             	mov    %rax,(%rcx)
ffffffff8b2dc89e:	48 8b 7b 18          	mov    0x18(%rbx),%rdi
ffffffff8b2dc8a2:	48 39 5e 10          	cmp    %rbx,0x10(%rsi)
ffffffff8b2dc8a6:	48 89 7e 18          	mov    %rdi,0x18(%rsi)
ffffffff8b2dc8aa:	48 8b 7b 10          	mov    0x10(%rbx),%rdi
ffffffff8b2dc8ae:	48 0f 44 ce          	cmove  %rsi,%rcx
ffffffff8b2dc8b2:	48 89 7e 10          	mov    %rdi,0x10(%rsi)
ffffffff8b2dc8b6:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8b2dc8b9:	4c 8b 43 08          	mov    0x8(%rbx),%r8
ffffffff8b2dc8bd:	4c 89 46 08          	mov    %r8,0x8(%rsi)
ffffffff8b2dc8c1:	48 89 3e             	mov    %rdi,(%rsi)
ffffffff8b2dc8c4:	48 8b 7b 10          	mov    0x10(%rbx),%rdi
ffffffff8b2dc8c8:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dc8cb:	74 0b                	je     ffffffff8b2dc8d8 <frame_candidate_91c740+0x198>
ffffffff8b2dc8cd:	48 39 1f             	cmp    %rbx,(%rdi)
ffffffff8b2dc8d0:	74 0f                	je     ffffffff8b2dc8e1 <frame_candidate_91c740+0x1a1>
ffffffff8b2dc8d2:	48 89 77 08          	mov    %rsi,0x8(%rdi)
ffffffff8b2dc8d6:	eb 0c                	jmp    ffffffff8b2dc8e4 <frame_candidate_91c740+0x1a4>
ffffffff8b2dc8d8:	48 89 35 81 a0 25 03 	mov    %rsi,0x325a081(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc8df:	eb 03                	jmp    ffffffff8b2dc8e4 <frame_candidate_91c740+0x1a4>
ffffffff8b2dc8e1:	48 89 37             	mov    %rsi,(%rdi)
ffffffff8b2dc8e4:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8b2dc8e7:	48 89 77 10          	mov    %rsi,0x10(%rdi)
ffffffff8b2dc8eb:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8b2dc8ef:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dc8f2:	74 04                	je     ffffffff8b2dc8f8 <frame_candidate_91c740+0x1b8>
ffffffff8b2dc8f4:	48 89 77 10          	mov    %rsi,0x10(%rdi)
ffffffff8b2dc8f8:	85 d2                	test   %edx,%edx
ffffffff8b2dc8fa:	0f 85 86 02 00 00    	jne    ffffffff8b2dcb86 <frame_candidate_91c740+0x446>
ffffffff8b2dc900:	eb 19                	jmp    ffffffff8b2dc91b <frame_candidate_91c740+0x1db>
ffffffff8b2dc902:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dc909:	1f 84 00 00 00 00 00 
ffffffff8b2dc910:	c7 41 18 01 00 00 00 	movl   $0x1,0x18(%rcx)
ffffffff8b2dc917:	48 8b 48 10          	mov    0x10(%rax),%rcx
ffffffff8b2dc91b:	48 89 c2             	mov    %rax,%rdx
ffffffff8b2dc91e:	48 89 c8             	mov    %rcx,%rax
ffffffff8b2dc921:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dc924:	74 18                	je     ffffffff8b2dc93e <frame_candidate_91c740+0x1fe>
ffffffff8b2dc926:	83 7a 18 00          	cmpl   $0x0,0x18(%rdx)
ffffffff8b2dc92a:	0f 85 4f 02 00 00    	jne    ffffffff8b2dcb7f <frame_candidate_91c740+0x43f>
ffffffff8b2dc930:	48 3b 15 29 a0 25 03 	cmp    0x325a029(%rip),%rdx        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc937:	75 13                	jne    ffffffff8b2dc94c <frame_candidate_91c740+0x20c>
ffffffff8b2dc939:	e9 41 02 00 00       	jmp    ffffffff8b2dcb7f <frame_candidate_91c740+0x43f>
ffffffff8b2dc93e:	48 83 3d 1a a0 25 03 	cmpq   $0x0,0x325a01a(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc945:	00 
ffffffff8b2dc946:	0f 84 3a 02 00 00    	je     ffffffff8b2dcb86 <frame_candidate_91c740+0x446>
ffffffff8b2dc94c:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2dc94f:	48 39 d1             	cmp    %rdx,%rcx
ffffffff8b2dc952:	74 43                	je     ffffffff8b2dc997 <frame_candidate_91c740+0x257>
ffffffff8b2dc954:	83 79 18 01          	cmpl   $0x1,0x18(%rcx)
ffffffff8b2dc958:	0f 85 98 00 00 00    	jne    ffffffff8b2dc9f6 <frame_candidate_91c740+0x2b6>
ffffffff8b2dc95e:	c7 41 18 00 00 00 00 	movl   $0x0,0x18(%rcx)
ffffffff8b2dc965:	c7 40 18 01 00 00 00 	movl   $0x1,0x18(%rax)
ffffffff8b2dc96c:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2dc96f:	48 8b 51 08          	mov    0x8(%rcx),%rdx
ffffffff8b2dc973:	48 89 10             	mov    %rdx,(%rax)
ffffffff8b2dc976:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dc979:	74 04                	je     ffffffff8b2dc97f <frame_candidate_91c740+0x23f>
ffffffff8b2dc97b:	48 89 42 10          	mov    %rax,0x10(%rdx)
ffffffff8b2dc97f:	48 8b 50 10          	mov    0x10(%rax),%rdx
ffffffff8b2dc983:	48 89 51 10          	mov    %rdx,0x10(%rcx)
ffffffff8b2dc987:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dc98a:	74 53                	je     ffffffff8b2dc9df <frame_candidate_91c740+0x29f>
ffffffff8b2dc98c:	48 3b 02             	cmp    (%rdx),%rax
ffffffff8b2dc98f:	74 57                	je     ffffffff8b2dc9e8 <frame_candidate_91c740+0x2a8>
ffffffff8b2dc991:	48 89 4a 08          	mov    %rcx,0x8(%rdx)
ffffffff8b2dc995:	eb 54                	jmp    ffffffff8b2dc9eb <frame_candidate_91c740+0x2ab>
ffffffff8b2dc997:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b2dc99b:	83 79 18 01          	cmpl   $0x1,0x18(%rcx)
ffffffff8b2dc99f:	0f 85 93 00 00 00    	jne    ffffffff8b2dca38 <frame_candidate_91c740+0x2f8>
ffffffff8b2dc9a5:	c7 41 18 00 00 00 00 	movl   $0x0,0x18(%rcx)
ffffffff8b2dc9ac:	c7 40 18 01 00 00 00 	movl   $0x1,0x18(%rax)
ffffffff8b2dc9b3:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b2dc9b7:	48 8b 11             	mov    (%rcx),%rdx
ffffffff8b2dc9ba:	48 89 50 08          	mov    %rdx,0x8(%rax)
ffffffff8b2dc9be:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dc9c1:	74 04                	je     ffffffff8b2dc9c7 <frame_candidate_91c740+0x287>
ffffffff8b2dc9c3:	48 89 42 10          	mov    %rax,0x10(%rdx)
ffffffff8b2dc9c7:	48 8b 50 10          	mov    0x10(%rax),%rdx
ffffffff8b2dc9cb:	48 89 51 10          	mov    %rdx,0x10(%rcx)
ffffffff8b2dc9cf:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dc9d2:	74 4d                	je     ffffffff8b2dca21 <frame_candidate_91c740+0x2e1>
ffffffff8b2dc9d4:	48 3b 02             	cmp    (%rdx),%rax
ffffffff8b2dc9d7:	74 51                	je     ffffffff8b2dca2a <frame_candidate_91c740+0x2ea>
ffffffff8b2dc9d9:	48 89 4a 08          	mov    %rcx,0x8(%rdx)
ffffffff8b2dc9dd:	eb 4e                	jmp    ffffffff8b2dca2d <frame_candidate_91c740+0x2ed>
ffffffff8b2dc9df:	48 89 0d 7a 9f 25 03 	mov    %rcx,0x3259f7a(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dc9e6:	eb 03                	jmp    ffffffff8b2dc9eb <frame_candidate_91c740+0x2ab>
ffffffff8b2dc9e8:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2dc9eb:	48 89 41 08          	mov    %rax,0x8(%rcx)
ffffffff8b2dc9ef:	48 89 48 10          	mov    %rcx,0x10(%rax)
ffffffff8b2dc9f3:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2dc9f6:	48 8b 11             	mov    (%rcx),%rdx
ffffffff8b2dc9f9:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dc9fc:	74 0a                	je     ffffffff8b2dca08 <frame_candidate_91c740+0x2c8>
ffffffff8b2dc9fe:	83 7a 18 00          	cmpl   $0x0,0x18(%rdx)
ffffffff8b2dca02:	0f 85 10 01 00 00    	jne    ffffffff8b2dcb18 <frame_candidate_91c740+0x3d8>
ffffffff8b2dca08:	48 8b 71 08          	mov    0x8(%rcx),%rsi
ffffffff8b2dca0c:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dca0f:	0f 84 fb fe ff ff    	je     ffffffff8b2dc910 <frame_candidate_91c740+0x1d0>
ffffffff8b2dca15:	83 7e 18 00          	cmpl   $0x0,0x18(%rsi)
ffffffff8b2dca19:	0f 84 f1 fe ff ff    	je     ffffffff8b2dc910 <frame_candidate_91c740+0x1d0>
ffffffff8b2dca1f:	eb 41                	jmp    ffffffff8b2dca62 <frame_candidate_91c740+0x322>
ffffffff8b2dca21:	48 89 0d 38 9f 25 03 	mov    %rcx,0x3259f38(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dca28:	eb 03                	jmp    ffffffff8b2dca2d <frame_candidate_91c740+0x2ed>
ffffffff8b2dca2a:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2dca2d:	48 89 01             	mov    %rax,(%rcx)
ffffffff8b2dca30:	48 89 48 10          	mov    %rcx,0x10(%rax)
ffffffff8b2dca34:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b2dca38:	48 8b 11             	mov    (%rcx),%rdx
ffffffff8b2dca3b:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dca3e:	74 06                	je     ffffffff8b2dca46 <frame_candidate_91c740+0x306>
ffffffff8b2dca40:	83 7a 18 00          	cmpl   $0x0,0x18(%rdx)
ffffffff8b2dca44:	75 65                	jne    ffffffff8b2dcaab <frame_candidate_91c740+0x36b>
ffffffff8b2dca46:	48 8b 51 08          	mov    0x8(%rcx),%rdx
ffffffff8b2dca4a:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dca4d:	0f 84 bd fe ff ff    	je     ffffffff8b2dc910 <frame_candidate_91c740+0x1d0>
ffffffff8b2dca53:	83 7a 18 00          	cmpl   $0x0,0x18(%rdx)
ffffffff8b2dca57:	0f 84 b3 fe ff ff    	je     ffffffff8b2dc910 <frame_candidate_91c740+0x1d0>
ffffffff8b2dca5d:	e9 a4 01 00 00       	jmp    ffffffff8b2dcc06 <frame_candidate_91c740+0x4c6>
ffffffff8b2dca62:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dca65:	74 0a                	je     ffffffff8b2dca71 <frame_candidate_91c740+0x331>
ffffffff8b2dca67:	83 7a 18 00          	cmpl   $0x0,0x18(%rdx)
ffffffff8b2dca6b:	0f 85 a7 00 00 00    	jne    ffffffff8b2dcb18 <frame_candidate_91c740+0x3d8>
ffffffff8b2dca71:	c7 46 18 00 00 00 00 	movl   $0x0,0x18(%rsi)
ffffffff8b2dca78:	48 8b 51 08          	mov    0x8(%rcx),%rdx
ffffffff8b2dca7c:	c7 41 18 01 00 00 00 	movl   $0x1,0x18(%rcx)
ffffffff8b2dca83:	48 8b 32             	mov    (%rdx),%rsi
ffffffff8b2dca86:	48 89 71 08          	mov    %rsi,0x8(%rcx)
ffffffff8b2dca8a:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dca8d:	74 04                	je     ffffffff8b2dca93 <frame_candidate_91c740+0x353>
ffffffff8b2dca8f:	48 89 4e 10          	mov    %rcx,0x10(%rsi)
ffffffff8b2dca93:	48 8b 71 10          	mov    0x10(%rcx),%rsi
ffffffff8b2dca97:	48 89 72 10          	mov    %rsi,0x10(%rdx)
ffffffff8b2dca9b:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dca9e:	74 62                	je     ffffffff8b2dcb02 <frame_candidate_91c740+0x3c2>
ffffffff8b2dcaa0:	48 3b 0e             	cmp    (%rsi),%rcx
ffffffff8b2dcaa3:	74 66                	je     ffffffff8b2dcb0b <frame_candidate_91c740+0x3cb>
ffffffff8b2dcaa5:	48 89 56 08          	mov    %rdx,0x8(%rsi)
ffffffff8b2dcaa9:	eb 63                	jmp    ffffffff8b2dcb0e <frame_candidate_91c740+0x3ce>
ffffffff8b2dcaab:	48 8b 71 08          	mov    0x8(%rcx),%rsi
ffffffff8b2dcaaf:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dcab2:	74 0a                	je     ffffffff8b2dcabe <frame_candidate_91c740+0x37e>
ffffffff8b2dcab4:	83 7e 18 00          	cmpl   $0x0,0x18(%rsi)
ffffffff8b2dcab8:	0f 85 48 01 00 00    	jne    ffffffff8b2dcc06 <frame_candidate_91c740+0x4c6>
ffffffff8b2dcabe:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%rdx)
ffffffff8b2dcac5:	48 8b 11             	mov    (%rcx),%rdx
ffffffff8b2dcac8:	c7 41 18 01 00 00 00 	movl   $0x1,0x18(%rcx)
ffffffff8b2dcacf:	48 8b 72 08          	mov    0x8(%rdx),%rsi
ffffffff8b2dcad3:	48 89 31             	mov    %rsi,(%rcx)
ffffffff8b2dcad6:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dcad9:	74 04                	je     ffffffff8b2dcadf <frame_candidate_91c740+0x39f>
ffffffff8b2dcadb:	48 89 4e 10          	mov    %rcx,0x10(%rsi)
ffffffff8b2dcadf:	48 8b 71 10          	mov    0x10(%rcx),%rsi
ffffffff8b2dcae3:	48 89 72 10          	mov    %rsi,0x10(%rdx)
ffffffff8b2dcae7:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dcaea:	0f 84 fe 00 00 00    	je     ffffffff8b2dcbee <frame_candidate_91c740+0x4ae>
ffffffff8b2dcaf0:	48 3b 0e             	cmp    (%rsi),%rcx
ffffffff8b2dcaf3:	0f 84 fe 00 00 00    	je     ffffffff8b2dcbf7 <frame_candidate_91c740+0x4b7>
ffffffff8b2dcaf9:	48 89 56 08          	mov    %rdx,0x8(%rsi)
ffffffff8b2dcafd:	e9 f8 00 00 00       	jmp    ffffffff8b2dcbfa <frame_candidate_91c740+0x4ba>
ffffffff8b2dcb02:	48 89 15 57 9e 25 03 	mov    %rdx,0x3259e57(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dcb09:	eb 03                	jmp    ffffffff8b2dcb0e <frame_candidate_91c740+0x3ce>
ffffffff8b2dcb0b:	48 89 16             	mov    %rdx,(%rsi)
ffffffff8b2dcb0e:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2dcb11:	48 89 51 10          	mov    %rdx,0x10(%rcx)
ffffffff8b2dcb15:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2dcb18:	8b 50 18             	mov    0x18(%rax),%edx
ffffffff8b2dcb1b:	89 51 18             	mov    %edx,0x18(%rcx)
ffffffff8b2dcb1e:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%rax)
ffffffff8b2dcb25:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8b2dcb28:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dcb2b:	74 07                	je     ffffffff8b2dcb34 <frame_candidate_91c740+0x3f4>
ffffffff8b2dcb2d:	c7 41 18 00 00 00 00 	movl   $0x0,0x18(%rcx)
ffffffff8b2dcb34:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2dcb37:	48 8b 51 08          	mov    0x8(%rcx),%rdx
ffffffff8b2dcb3b:	48 89 10             	mov    %rdx,(%rax)
ffffffff8b2dcb3e:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcb41:	74 04                	je     ffffffff8b2dcb47 <frame_candidate_91c740+0x407>
ffffffff8b2dcb43:	48 89 42 10          	mov    %rax,0x10(%rdx)
ffffffff8b2dcb47:	48 8b 50 10          	mov    0x10(%rax),%rdx
ffffffff8b2dcb4b:	48 89 51 10          	mov    %rdx,0x10(%rcx)
ffffffff8b2dcb4f:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcb52:	74 0b                	je     ffffffff8b2dcb5f <frame_candidate_91c740+0x41f>
ffffffff8b2dcb54:	48 3b 02             	cmp    (%rdx),%rax
ffffffff8b2dcb57:	74 0f                	je     ffffffff8b2dcb68 <frame_candidate_91c740+0x428>
ffffffff8b2dcb59:	48 89 4a 08          	mov    %rcx,0x8(%rdx)
ffffffff8b2dcb5d:	eb 0c                	jmp    ffffffff8b2dcb6b <frame_candidate_91c740+0x42b>
ffffffff8b2dcb5f:	48 89 0d fa 9d 25 03 	mov    %rcx,0x3259dfa(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dcb66:	eb 03                	jmp    ffffffff8b2dcb6b <frame_candidate_91c740+0x42b>
ffffffff8b2dcb68:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2dcb6b:	48 89 41 08          	mov    %rax,0x8(%rcx)
ffffffff8b2dcb6f:	48 89 48 10          	mov    %rcx,0x10(%rax)
ffffffff8b2dcb73:	48 8b 15 e6 9d 25 03 	mov    0x3259de6(%rip),%rdx        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dcb7a:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcb7d:	74 07                	je     ffffffff8b2dcb86 <frame_candidate_91c740+0x446>
ffffffff8b2dcb7f:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%rdx)
ffffffff8b2dcb86:	48 8d 3d c3 9d 25 03 	lea    0x3259dc3(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dcb8d:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dcb90:	31 f6                	xor    %esi,%esi
ffffffff8b2dcb92:	31 d2                	xor    %edx,%edx
ffffffff8b2dcb94:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dcb96:	e8 05 a4 ba ff       	call   ffffffff8ae86fa0 <handler_629_body-0x4556a0>
ffffffff8b2dcb9b:	4c 8b 7b 28          	mov    0x28(%rbx),%r15
ffffffff8b2dcb9f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8b2dcba4:	f0 41 0f c1 47 14    	lock xadd %eax,0x14(%r15)
ffffffff8b2dcbaa:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b2dcbad:	75 19                	jne    ffffffff8b2dcbc8 <frame_candidate_91c740+0x488>
ffffffff8b2dcbaf:	49 8b 3f             	mov    (%r15),%rdi
ffffffff8b2dcbb2:	e8 e9 4f b4 ff       	call   ffffffff8ae21ba0 <handler_629_body-0x4baaa0>
ffffffff8b2dcbb7:	48 8b 3d aa 9d 25 03 	mov    0x3259daa(%rip),%rdi        # ffffffff8e536968 <frame_candidate_91e450+0x3258518>
ffffffff8b2dcbbe:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2dcbc1:	31 d2                	xor    %edx,%edx
ffffffff8b2dcbc3:	e8 f8 f4 b1 ff       	call   ffffffff8adfc0c0 <handler_629_body-0x4e0580>
ffffffff8b2dcbc8:	48 8b 7b 20          	mov    0x20(%rbx),%rdi
ffffffff8b2dcbcc:	48 8d 35 3d 52 c3 01 	lea    0x1c3523d(%rip),%rsi        # ffffffff8cf11e10 <frame_candidate_91e450+0x1c339c0>
ffffffff8b2dcbd3:	e8 18 c2 2e 00       	call   ffffffff8b5c8df0 <frame_candidate_91e450+0x2ea9a0>
ffffffff8b2dcbd8:	48 8b 3d 79 9d 25 03 	mov    0x3259d79(%rip),%rdi        # ffffffff8e536958 <frame_candidate_91e450+0x3258508>
ffffffff8b2dcbdf:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dcbe2:	31 d2                	xor    %edx,%edx
ffffffff8b2dcbe4:	e8 d7 f4 b1 ff       	call   ffffffff8adfc0c0 <handler_629_body-0x4e0580>
ffffffff8b2dcbe9:	e9 bf fb ff ff       	jmp    ffffffff8b2dc7ad <frame_candidate_91c740+0x6d>
ffffffff8b2dcbee:	48 89 15 6b 9d 25 03 	mov    %rdx,0x3259d6b(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dcbf5:	eb 03                	jmp    ffffffff8b2dcbfa <frame_candidate_91c740+0x4ba>
ffffffff8b2dcbf7:	48 89 16             	mov    %rdx,(%rsi)
ffffffff8b2dcbfa:	48 89 4a 08          	mov    %rcx,0x8(%rdx)
ffffffff8b2dcbfe:	48 89 51 10          	mov    %rdx,0x10(%rcx)
ffffffff8b2dcc02:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b2dcc06:	8b 50 18             	mov    0x18(%rax),%edx
ffffffff8b2dcc09:	89 51 18             	mov    %edx,0x18(%rcx)
ffffffff8b2dcc0c:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%rax)
ffffffff8b2dcc13:	48 8b 49 08          	mov    0x8(%rcx),%rcx
ffffffff8b2dcc17:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dcc1a:	74 07                	je     ffffffff8b2dcc23 <frame_candidate_91c740+0x4e3>
ffffffff8b2dcc1c:	c7 41 18 00 00 00 00 	movl   $0x0,0x18(%rcx)
ffffffff8b2dcc23:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b2dcc27:	48 8b 11             	mov    (%rcx),%rdx
ffffffff8b2dcc2a:	48 89 50 08          	mov    %rdx,0x8(%rax)
ffffffff8b2dcc2e:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcc31:	74 04                	je     ffffffff8b2dcc37 <frame_candidate_91c740+0x4f7>
ffffffff8b2dcc33:	48 89 42 10          	mov    %rax,0x10(%rdx)
ffffffff8b2dcc37:	48 8b 50 10          	mov    0x10(%rax),%rdx
ffffffff8b2dcc3b:	48 89 51 10          	mov    %rdx,0x10(%rcx)
ffffffff8b2dcc3f:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcc42:	74 11                	je     ffffffff8b2dcc55 <frame_candidate_91c740+0x515>
ffffffff8b2dcc44:	48 3b 02             	cmp    (%rdx),%rax
ffffffff8b2dcc47:	74 1b                	je     ffffffff8b2dcc64 <frame_candidate_91c740+0x524>
ffffffff8b2dcc49:	48 89 4a 08          	mov    %rcx,0x8(%rdx)
ffffffff8b2dcc4d:	48 89 01             	mov    %rax,(%rcx)
ffffffff8b2dcc50:	e9 1a ff ff ff       	jmp    ffffffff8b2dcb6f <frame_candidate_91c740+0x42f>
ffffffff8b2dcc55:	48 89 0d 04 9d 25 03 	mov    %rcx,0x3259d04(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dcc5c:	48 89 01             	mov    %rax,(%rcx)
ffffffff8b2dcc5f:	e9 0b ff ff ff       	jmp    ffffffff8b2dcb6f <frame_candidate_91c740+0x42f>
ffffffff8b2dcc64:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2dcc67:	48 89 01             	mov    %rax,(%rcx)
ffffffff8b2dcc6a:	e9 00 ff ff ff       	jmp    ffffffff8b2dcb6f <frame_candidate_91c740+0x42f>
ffffffff8b2dcc6f:	90                   	nop

ffffffff8b2dcc70 <frame_candidate_91cc70>:
ffffffff8b2dcc70:	55                   	push   %rbp
ffffffff8b2dcc71:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dcc74:	41 57                	push   %r15
ffffffff8b2dcc76:	41 56                	push   %r14
ffffffff8b2dcc78:	53                   	push   %rbx
ffffffff8b2dcc79:	50                   	push   %rax
ffffffff8b2dcc7a:	49 89 f7             	mov    %rsi,%r15
ffffffff8b2dcc7d:	49 89 fe             	mov    %rdi,%r14
ffffffff8b2dcc80:	48 8d 35 89 51 c3 01 	lea    0x1c35189(%rip),%rsi        # ffffffff8cf11e10 <frame_candidate_91e450+0x1c339c0>
ffffffff8b2dcc87:	bf 00 04 00 00       	mov    $0x400,%edi
ffffffff8b2dcc8c:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b2dcc91:	e8 ba be 2e 00       	call   ffffffff8b5c8b50 <frame_candidate_91e450+0x2ea700>
ffffffff8b2dcc96:	4d 8b 3f             	mov    (%r15),%r15
ffffffff8b2dcc99:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b2dcca0:	00 00 
ffffffff8b2dcca2:	48 8d 35 db d3 a3 00 	lea    0xa3d3db(%rip),%rsi        # ffffffff8bd1a084 <frame_candidate_91e450+0xa3bc34>
ffffffff8b2dcca9:	31 d2                	xor    %edx,%edx
ffffffff8b2dccab:	48 89 c3             	mov    %rax,%rbx
ffffffff8b2dccae:	e8 2d d7 2f 00       	call   ffffffff8b5da3e0 <frame_candidate_91e450+0x2fbf90>
ffffffff8b2dccb3:	ba 00 04 00 00       	mov    $0x400,%edx
ffffffff8b2dccb8:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b2dccbb:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dccbe:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dccc0:	e8 3b cc 93 ff       	call   ffffffff8ac19900 <handler_629_body-0x6c2d40>
ffffffff8b2dccc5:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dccc8:	85 c0                	test   %eax,%eax
ffffffff8b2dccca:	75 57                	jne    ffffffff8b2dcd23 <frame_candidate_91cc70+0xb3>
ffffffff8b2dcccc:	49 8b be 40 01 00 00 	mov    0x140(%r14),%rdi
ffffffff8b2dccd3:	e8 f8 c5 ce ff       	call   ffffffff8afc92d0 <handler_629_body-0x313370>
ffffffff8b2dccd8:	85 c0                	test   %eax,%eax
ffffffff8b2dccda:	74 39                	je     ffffffff8b2dcd15 <frame_candidate_91cc70+0xa5>
ffffffff8b2dccdc:	48 8d 35 be 07 f0 00 	lea    0xf007be(%rip),%rsi        # ffffffff8c1dd4a1 <frame_candidate_91e450+0xeff051>
ffffffff8b2dcce3:	ba 0c 00 00 00       	mov    $0xc,%edx
ffffffff8b2dcce8:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dcceb:	e8 40 4d fb ff       	call   ffffffff8b291a30 <handler_629_body-0x4ac10>
ffffffff8b2dccf0:	85 c0                	test   %eax,%eax
ffffffff8b2dccf2:	74 21                	je     ffffffff8b2dcd15 <frame_candidate_91cc70+0xa5>
ffffffff8b2dccf4:	48 8d 3d 62 d1 a6 00 	lea    0xa6d162(%rip),%rdi        # ffffffff8bd49e5d <frame_candidate_91e450+0xa6ba0d>
ffffffff8b2dccfb:	48 8d 0d 9f 07 f0 00 	lea    0xf0079f(%rip),%rcx        # ffffffff8c1dd4a1 <frame_candidate_91e450+0xeff051>
ffffffff8b2dcd02:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b2dcd05:	48 89 da             	mov    %rbx,%rdx
ffffffff8b2dcd08:	e8 93 08 ef ff       	call   ffffffff8b1cd5a0 <handler_629_body-0x10f0a0>
ffffffff8b2dcd0d:	41 bf 02 00 00 00    	mov    $0x2,%r15d
ffffffff8b2dcd13:	eb 0e                	jmp    ffffffff8b2dcd23 <frame_candidate_91cc70+0xb3>
ffffffff8b2dcd15:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dcd18:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dcd1b:	e8 20 fa ff ff       	call   ffffffff8b2dc740 <frame_candidate_91c740>
ffffffff8b2dcd20:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dcd23:	48 8d 35 e6 50 c3 01 	lea    0x1c350e6(%rip),%rsi        # ffffffff8cf11e10 <frame_candidate_91e450+0x1c339c0>
ffffffff8b2dcd2a:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dcd2d:	e8 be c0 2e 00       	call   ffffffff8b5c8df0 <frame_candidate_91e450+0x2ea9a0>
ffffffff8b2dcd32:	44 89 f8             	mov    %r15d,%eax
ffffffff8b2dcd35:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dcd39:	5b                   	pop    %rbx
ffffffff8b2dcd3a:	41 5e                	pop    %r14
ffffffff8b2dcd3c:	41 5f                	pop    %r15
ffffffff8b2dcd3e:	5d                   	pop    %rbp
ffffffff8b2dcd3f:	c3                   	ret

ffffffff8b2dcd40 <frame_candidate_91cd40>:
ffffffff8b2dcd40:	55                   	push   %rbp
ffffffff8b2dcd41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dcd44:	41 57                	push   %r15
ffffffff8b2dcd46:	41 56                	push   %r14
ffffffff8b2dcd48:	41 55                	push   %r13
ffffffff8b2dcd4a:	41 54                	push   %r12
ffffffff8b2dcd4c:	53                   	push   %rbx
ffffffff8b2dcd4d:	50                   	push   %rax
ffffffff8b2dcd4e:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcd51:	0f 84 e6 00 00 00    	je     ffffffff8b2dce3d <frame_candidate_91cd40+0xfd>
ffffffff8b2dcd57:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dcd5a:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b2dcd5d:	49 89 f6             	mov    %rsi,%r14
ffffffff8b2dcd60:	49 89 ff             	mov    %rdi,%r15
ffffffff8b2dcd63:	0f 94 c0             	sete   %al
ffffffff8b2dcd66:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dcd69:	0f 94 c1             	sete   %cl
ffffffff8b2dcd6c:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b2dcd6f:	08 c1                	or     %al,%cl
ffffffff8b2dcd71:	75 03                	jne    ffffffff8b2dcd76 <frame_candidate_91cd40+0x36>
ffffffff8b2dcd73:	45 8b 26             	mov    (%r14),%r12d
ffffffff8b2dcd76:	48 8d 3d d3 9b 25 03 	lea    0x3259bd3(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dcd7d:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b2dcd80:	31 f6                	xor    %esi,%esi
ffffffff8b2dcd82:	31 d2                	xor    %edx,%edx
ffffffff8b2dcd84:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dcd86:	e8 75 9c ba ff       	call   ffffffff8ae86a00 <handler_629_body-0x455c40>
ffffffff8b2dcd8b:	48 8d 0d ce 9b 25 03 	lea    0x3259bce(%rip),%rcx        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dcd92:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dcd99:	1f 84 00 00 00 00 00 
ffffffff8b2dcda0:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8b2dcda3:	4c 89 e8             	mov    %r13,%rax
ffffffff8b2dcda6:	49 89 cd             	mov    %rcx,%r13
ffffffff8b2dcda9:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dcdac:	75 f2                	jne    ffffffff8b2dcda0 <frame_candidate_91cd40+0x60>
ffffffff8b2dcdae:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b2dcdb1:	48 85 c0             	test   %rax,%rax
ffffffff8b2dcdb4:	74 5e                	je     ffffffff8b2dce14 <frame_candidate_91cd40+0xd4>
ffffffff8b2dcdb6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dcdbd:	00 00 00 
ffffffff8b2dcdc0:	48 89 c1             	mov    %rax,%rcx
ffffffff8b2dcdc3:	45 39 e5             	cmp    %r12d,%r13d
ffffffff8b2dcdc6:	7d 0b                	jge    ffffffff8b2dcdd3 <frame_candidate_91cd40+0x93>
ffffffff8b2dcdc8:	48 8b 41 28          	mov    0x28(%rcx),%rax
ffffffff8b2dcdcc:	49 63 d5             	movslq %r13d,%rdx
ffffffff8b2dcdcf:	49 89 04 d7          	mov    %rax,(%r15,%rdx,8)
ffffffff8b2dcdd3:	48 8b 51 08          	mov    0x8(%rcx),%rdx
ffffffff8b2dcdd7:	41 ff c5             	inc    %r13d
ffffffff8b2dcdda:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcddd:	74 11                	je     ffffffff8b2dcdf0 <frame_candidate_91cd40+0xb0>
ffffffff8b2dcddf:	90                   	nop
ffffffff8b2dcde0:	48 89 d0             	mov    %rdx,%rax
ffffffff8b2dcde3:	48 8b 12             	mov    (%rdx),%rdx
ffffffff8b2dcde6:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcde9:	75 f5                	jne    ffffffff8b2dcde0 <frame_candidate_91cd40+0xa0>
ffffffff8b2dcdeb:	eb d3                	jmp    ffffffff8b2dcdc0 <frame_candidate_91cd40+0x80>
ffffffff8b2dcded:	0f 1f 00             	nopl   (%rax)
ffffffff8b2dcdf0:	48 8b 41 10          	mov    0x10(%rcx),%rax
ffffffff8b2dcdf4:	48 85 c0             	test   %rax,%rax
ffffffff8b2dcdf7:	74 07                	je     ffffffff8b2dce00 <frame_candidate_91cd40+0xc0>
ffffffff8b2dcdf9:	48 3b 08             	cmp    (%rax),%rcx
ffffffff8b2dcdfc:	74 c2                	je     ffffffff8b2dcdc0 <frame_candidate_91cd40+0x80>
ffffffff8b2dcdfe:	66 90                	xchg   %ax,%ax
ffffffff8b2dce00:	48 8b 41 10          	mov    0x10(%rcx),%rax
ffffffff8b2dce04:	48 85 c0             	test   %rax,%rax
ffffffff8b2dce07:	74 0b                	je     ffffffff8b2dce14 <frame_candidate_91cd40+0xd4>
ffffffff8b2dce09:	48 3b 48 08          	cmp    0x8(%rax),%rcx
ffffffff8b2dce0d:	48 89 c1             	mov    %rax,%rcx
ffffffff8b2dce10:	74 ee                	je     ffffffff8b2dce00 <frame_candidate_91cd40+0xc0>
ffffffff8b2dce12:	eb ac                	jmp    ffffffff8b2dcdc0 <frame_candidate_91cd40+0x80>
ffffffff8b2dce14:	48 8d 3d 35 9b 25 03 	lea    0x3259b35(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dce1b:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b2dce1e:	31 f6                	xor    %esi,%esi
ffffffff8b2dce20:	31 d2                	xor    %edx,%edx
ffffffff8b2dce22:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dce24:	e8 77 a1 ba ff       	call   ffffffff8ae86fa0 <handler_629_body-0x4556a0>
ffffffff8b2dce29:	4d 85 f6             	test   %r14,%r14
ffffffff8b2dce2c:	74 0a                	je     ffffffff8b2dce38 <frame_candidate_91cd40+0xf8>
ffffffff8b2dce2e:	45 39 ec             	cmp    %r13d,%r12d
ffffffff8b2dce31:	45 0f 4d e5          	cmovge %r13d,%r12d
ffffffff8b2dce35:	45 89 26             	mov    %r12d,(%r14)
ffffffff8b2dce38:	44 89 2b             	mov    %r13d,(%rbx)
ffffffff8b2dce3b:	eb 06                	jmp    ffffffff8b2dce43 <frame_candidate_91cd40+0x103>
ffffffff8b2dce3d:	41 bf 16 00 00 00    	mov    $0x16,%r15d
ffffffff8b2dce43:	44 89 f8             	mov    %r15d,%eax
ffffffff8b2dce46:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dce4a:	5b                   	pop    %rbx
ffffffff8b2dce4b:	41 5c                	pop    %r12
ffffffff8b2dce4d:	41 5d                	pop    %r13
ffffffff8b2dce4f:	41 5e                	pop    %r14
ffffffff8b2dce51:	41 5f                	pop    %r15
ffffffff8b2dce53:	5d                   	pop    %rbp
ffffffff8b2dce54:	c3                   	ret
ffffffff8b2dce55:	90                   	nop
ffffffff8b2dce56:	90                   	nop
ffffffff8b2dce57:	90                   	nop
ffffffff8b2dce58:	90                   	nop
ffffffff8b2dce59:	90                   	nop
ffffffff8b2dce5a:	90                   	nop
ffffffff8b2dce5b:	90                   	nop
ffffffff8b2dce5c:	90                   	nop
ffffffff8b2dce5d:	90                   	nop
ffffffff8b2dce5e:	90                   	nop
ffffffff8b2dce5f:	90                   	nop

ffffffff8b2dce60 <frame_candidate_91ce60>:
ffffffff8b2dce60:	55                   	push   %rbp
ffffffff8b2dce61:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dce64:	41 57                	push   %r15
ffffffff8b2dce66:	41 56                	push   %r14
ffffffff8b2dce68:	41 55                	push   %r13
ffffffff8b2dce6a:	41 54                	push   %r12
ffffffff8b2dce6c:	53                   	push   %rbx
ffffffff8b2dce6d:	50                   	push   %rax
ffffffff8b2dce6e:	49 89 ff             	mov    %rdi,%r15
ffffffff8b2dce71:	48 8d 3d d8 9a 25 03 	lea    0x3259ad8(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dce78:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b2dce7b:	49 89 f6             	mov    %rsi,%r14
ffffffff8b2dce7e:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b2dce81:	31 f6                	xor    %esi,%esi
ffffffff8b2dce83:	31 d2                	xor    %edx,%edx
ffffffff8b2dce85:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dce87:	e8 74 9b ba ff       	call   ffffffff8ae86a00 <handler_629_body-0x455c40>
ffffffff8b2dce8c:	48 8d 0d cd 9a 25 03 	lea    0x3259acd(%rip),%rcx        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dce93:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dce9a:	84 00 00 00 00 00 
ffffffff8b2dcea0:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8b2dcea3:	4c 89 e0             	mov    %r12,%rax
ffffffff8b2dcea6:	49 89 cc             	mov    %rcx,%r12
ffffffff8b2dcea9:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dceac:	75 f2                	jne    ffffffff8b2dcea0 <frame_candidate_91ce60+0x40>
ffffffff8b2dceae:	41 bc 09 00 00 00    	mov    $0x9,%r12d
ffffffff8b2dceb4:	48 85 c0             	test   %rax,%rax
ffffffff8b2dceb7:	74 37                	je     ffffffff8b2dcef0 <frame_candidate_91ce60+0x90>
ffffffff8b2dceb9:	4c 39 78 28          	cmp    %r15,0x28(%rax)
ffffffff8b2dcebd:	75 6a                	jne    ffffffff8b2dcf29 <frame_candidate_91ce60+0xc9>
ffffffff8b2dcebf:	49 89 c5             	mov    %rax,%r13
ffffffff8b2dcec2:	4d 85 f6             	test   %r14,%r14
ffffffff8b2dcec5:	74 10                	je     ffffffff8b2dced7 <frame_candidate_91ce60+0x77>
ffffffff8b2dcec7:	ba 20 00 00 00       	mov    $0x20,%edx
ffffffff8b2dcecc:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b2dcecf:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b2dced2:	e8 09 cd 93 ff       	call   ffffffff8ac19be0 <handler_629_body-0x6c2a60>
ffffffff8b2dced7:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b2dceda:	48 85 db             	test   %rbx,%rbx
ffffffff8b2dcedd:	74 11                	je     ffffffff8b2dcef0 <frame_candidate_91ce60+0x90>
ffffffff8b2dcedf:	49 8b 75 20          	mov    0x20(%r13),%rsi
ffffffff8b2dcee3:	ba 00 04 00 00       	mov    $0x400,%edx
ffffffff8b2dcee8:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dceeb:	e8 80 ac 03 00       	call   ffffffff8b317b70 <frame_candidate_91e450+0x39720>
ffffffff8b2dcef0:	48 8d 3d 59 9a 25 03 	lea    0x3259a59(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dcef7:	31 f6                	xor    %esi,%esi
ffffffff8b2dcef9:	31 d2                	xor    %edx,%edx
ffffffff8b2dcefb:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dcefd:	e8 9e a0 ba ff       	call   ffffffff8ae86fa0 <handler_629_body-0x4556a0>
ffffffff8b2dcf02:	44 89 e0             	mov    %r12d,%eax
ffffffff8b2dcf05:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dcf09:	5b                   	pop    %rbx
ffffffff8b2dcf0a:	41 5c                	pop    %r12
ffffffff8b2dcf0c:	41 5d                	pop    %r13
ffffffff8b2dcf0e:	41 5e                	pop    %r14
ffffffff8b2dcf10:	41 5f                	pop    %r15
ffffffff8b2dcf12:	5d                   	pop    %rbp
ffffffff8b2dcf13:	c3                   	ret
ffffffff8b2dcf14:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dcf1b:	00 00 00 00 00 
ffffffff8b2dcf20:	4c 89 e8             	mov    %r13,%rax
ffffffff8b2dcf23:	4d 39 7d 28          	cmp    %r15,0x28(%r13)
ffffffff8b2dcf27:	74 99                	je     ffffffff8b2dcec2 <frame_candidate_91ce60+0x62>
ffffffff8b2dcf29:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b2dcf2d:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dcf30:	74 1e                	je     ffffffff8b2dcf50 <frame_candidate_91ce60+0xf0>
ffffffff8b2dcf32:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dcf39:	1f 84 00 00 00 00 00 
ffffffff8b2dcf40:	49 89 cd             	mov    %rcx,%r13
ffffffff8b2dcf43:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8b2dcf46:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2dcf49:	75 f5                	jne    ffffffff8b2dcf40 <frame_candidate_91ce60+0xe0>
ffffffff8b2dcf4b:	eb d3                	jmp    ffffffff8b2dcf20 <frame_candidate_91ce60+0xc0>
ffffffff8b2dcf4d:	0f 1f 00             	nopl   (%rax)
ffffffff8b2dcf50:	4c 8b 68 10          	mov    0x10(%rax),%r13
ffffffff8b2dcf54:	4d 85 ed             	test   %r13,%r13
ffffffff8b2dcf57:	74 07                	je     ffffffff8b2dcf60 <frame_candidate_91ce60+0x100>
ffffffff8b2dcf59:	49 3b 45 00          	cmp    0x0(%r13),%rax
ffffffff8b2dcf5d:	74 c1                	je     ffffffff8b2dcf20 <frame_candidate_91ce60+0xc0>
ffffffff8b2dcf5f:	90                   	nop
ffffffff8b2dcf60:	4c 8b 68 10          	mov    0x10(%rax),%r13
ffffffff8b2dcf64:	4d 85 ed             	test   %r13,%r13
ffffffff8b2dcf67:	74 87                	je     ffffffff8b2dcef0 <frame_candidate_91ce60+0x90>
ffffffff8b2dcf69:	49 3b 45 08          	cmp    0x8(%r13),%rax
ffffffff8b2dcf6d:	4c 89 e8             	mov    %r13,%rax
ffffffff8b2dcf70:	74 ee                	je     ffffffff8b2dcf60 <frame_candidate_91ce60+0x100>
ffffffff8b2dcf72:	eb ac                	jmp    ffffffff8b2dcf20 <frame_candidate_91ce60+0xc0>
ffffffff8b2dcf74:	90                   	nop
ffffffff8b2dcf75:	90                   	nop
ffffffff8b2dcf76:	90                   	nop
ffffffff8b2dcf77:	90                   	nop
ffffffff8b2dcf78:	90                   	nop
ffffffff8b2dcf79:	90                   	nop
ffffffff8b2dcf7a:	90                   	nop
ffffffff8b2dcf7b:	90                   	nop
ffffffff8b2dcf7c:	90                   	nop
ffffffff8b2dcf7d:	90                   	nop
ffffffff8b2dcf7e:	90                   	nop
ffffffff8b2dcf7f:	90                   	nop

ffffffff8b2dcf80 <frame_candidate_91cf80>:
ffffffff8b2dcf80:	55                   	push   %rbp
ffffffff8b2dcf81:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dcf84:	41 57                	push   %r15
ffffffff8b2dcf86:	41 56                	push   %r14
ffffffff8b2dcf88:	41 55                	push   %r13
ffffffff8b2dcf8a:	41 54                	push   %r12
ffffffff8b2dcf8c:	53                   	push   %rbx
ffffffff8b2dcf8d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b2dcf91:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dcf94:	0f 84 01 01 00 00    	je     ffffffff8b2dd09b <frame_candidate_91cf80+0x11b>
ffffffff8b2dcf9a:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dcf9d:	bb 00 00 00 00       	mov    $0x0,%ebx
ffffffff8b2dcfa2:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
ffffffff8b2dcfa6:	48 89 7d c0          	mov    %rdi,-0x40(%rbp)
ffffffff8b2dcfaa:	0f 94 c0             	sete   %al
ffffffff8b2dcfad:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dcfb0:	0f 94 c1             	sete   %cl
ffffffff8b2dcfb3:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b2dcfb6:	08 c1                	or     %al,%cl
ffffffff8b2dcfb8:	75 02                	jne    ffffffff8b2dcfbc <frame_candidate_91cf80+0x3c>
ffffffff8b2dcfba:	8b 1e                	mov    (%rsi),%ebx
ffffffff8b2dcfbc:	48 8d 3d 9d ce c6 02 	lea    0x2c6ce9d(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_91e450+0x2c6ba10>
ffffffff8b2dcfc3:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
ffffffff8b2dcfc7:	31 f6                	xor    %esi,%esi
ffffffff8b2dcfc9:	31 d2                	xor    %edx,%edx
ffffffff8b2dcfcb:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dcfcd:	e8 7e e3 32 00       	call   ffffffff8b60b350 <frame_candidate_91e450+0x32cf00>
ffffffff8b2dcfd2:	4c 8b 35 a7 ce c6 02 	mov    0x2c6cea7(%rip),%r14        # ffffffff8df49e80 <frame_candidate_91e450+0x2c6ba30>
ffffffff8b2dcfd9:	4d 85 f6             	test   %r14,%r14
ffffffff8b2dcfdc:	0f 84 8b 00 00 00    	je     ffffffff8b2dd06d <frame_candidate_91cf80+0xed>
ffffffff8b2dcfe2:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b2dcfe5:	eb 1d                	jmp    ffffffff8b2dd004 <frame_candidate_91cf80+0x84>
ffffffff8b2dcfe7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b2dcfee:	00 00 
ffffffff8b2dcff0:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b2dcff3:	31 f6                	xor    %esi,%esi
ffffffff8b2dcff5:	31 d2                	xor    %edx,%edx
ffffffff8b2dcff7:	e8 04 f3 32 00       	call   ffffffff8b60c300 <frame_candidate_91e450+0x32deb0>
ffffffff8b2dcffc:	4d 8b 36             	mov    (%r14),%r14
ffffffff8b2dcfff:	4d 85 f6             	test   %r14,%r14
ffffffff8b2dd002:	74 69                	je     ffffffff8b2dd06d <frame_candidate_91cf80+0xed>
ffffffff8b2dd004:	4d 8b 7e 48          	mov    0x48(%r14),%r15
ffffffff8b2dd008:	31 f6                	xor    %esi,%esi
ffffffff8b2dd00a:	31 d2                	xor    %edx,%edx
ffffffff8b2dd00c:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd00e:	4d 8d 67 40          	lea    0x40(%r15),%r12
ffffffff8b2dd012:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b2dd015:	e8 36 e3 32 00       	call   ffffffff8b60b350 <frame_candidate_91e450+0x32cf00>
ffffffff8b2dd01a:	41 8b 4f 28          	mov    0x28(%r15),%ecx
ffffffff8b2dd01e:	85 c9                	test   %ecx,%ecx
ffffffff8b2dd020:	78 ce                	js     ffffffff8b2dcff0 <frame_candidate_91cf80+0x70>
ffffffff8b2dd022:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
ffffffff8b2dd026:	31 c0                	xor    %eax,%eax
ffffffff8b2dd028:	eb 0f                	jmp    ffffffff8b2dd039 <frame_candidate_91cf80+0xb9>
ffffffff8b2dd02a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8b2dd030:	41 ff c5             	inc    %r13d
ffffffff8b2dd033:	ff c0                	inc    %eax
ffffffff8b2dd035:	39 c8                	cmp    %ecx,%eax
ffffffff8b2dd037:	7f b7                	jg     ffffffff8b2dcff0 <frame_candidate_91cf80+0x70>
ffffffff8b2dd039:	48 63 f0             	movslq %eax,%rsi
ffffffff8b2dd03c:	49 8b 17             	mov    (%r15),%rdx
ffffffff8b2dd03f:	48 8d 34 76          	lea    (%rsi,%rsi,2),%rsi
ffffffff8b2dd043:	48 c1 e6 04          	shl    $0x4,%rsi
ffffffff8b2dd047:	48 8b 54 32 08       	mov    0x8(%rdx,%rsi,1),%rdx
ffffffff8b2dd04c:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dd04f:	74 e2                	je     ffffffff8b2dd033 <frame_candidate_91cf80+0xb3>
ffffffff8b2dd051:	66 83 7a 20 10       	cmpw   $0x10,0x20(%rdx)
ffffffff8b2dd056:	75 db                	jne    ffffffff8b2dd033 <frame_candidate_91cf80+0xb3>
ffffffff8b2dd058:	41 39 dd             	cmp    %ebx,%r13d
ffffffff8b2dd05b:	7d d3                	jge    ffffffff8b2dd030 <frame_candidate_91cf80+0xb0>
ffffffff8b2dd05d:	48 8b 0a             	mov    (%rdx),%rcx
ffffffff8b2dd060:	49 63 d5             	movslq %r13d,%rdx
ffffffff8b2dd063:	48 89 0c d7          	mov    %rcx,(%rdi,%rdx,8)
ffffffff8b2dd067:	41 8b 4f 28          	mov    0x28(%r15),%ecx
ffffffff8b2dd06b:	eb c3                	jmp    ffffffff8b2dd030 <frame_candidate_91cf80+0xb0>
ffffffff8b2dd06d:	48 8d 3d ec cd c6 02 	lea    0x2c6cdec(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_91e450+0x2c6ba10>
ffffffff8b2dd074:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b2dd077:	31 f6                	xor    %esi,%esi
ffffffff8b2dd079:	31 d2                	xor    %edx,%edx
ffffffff8b2dd07b:	e8 80 f2 32 00       	call   ffffffff8b60c300 <frame_candidate_91e450+0x32deb0>
ffffffff8b2dd080:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
ffffffff8b2dd084:	48 85 c0             	test   %rax,%rax
ffffffff8b2dd087:	74 09                	je     ffffffff8b2dd092 <frame_candidate_91cf80+0x112>
ffffffff8b2dd089:	44 39 eb             	cmp    %r13d,%ebx
ffffffff8b2dd08c:	41 0f 4d dd          	cmovge %r13d,%ebx
ffffffff8b2dd090:	89 18                	mov    %ebx,(%rax)
ffffffff8b2dd092:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b2dd096:	44 89 28             	mov    %r13d,(%rax)
ffffffff8b2dd099:	eb 06                	jmp    ffffffff8b2dd0a1 <frame_candidate_91cf80+0x121>
ffffffff8b2dd09b:	41 bf 16 00 00 00    	mov    $0x16,%r15d
ffffffff8b2dd0a1:	44 89 f8             	mov    %r15d,%eax
ffffffff8b2dd0a4:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b2dd0a8:	5b                   	pop    %rbx
ffffffff8b2dd0a9:	41 5c                	pop    %r12
ffffffff8b2dd0ab:	41 5d                	pop    %r13
ffffffff8b2dd0ad:	41 5e                	pop    %r14
ffffffff8b2dd0af:	41 5f                	pop    %r15
ffffffff8b2dd0b1:	5d                   	pop    %rbp
ffffffff8b2dd0b2:	c3                   	ret
ffffffff8b2dd0b3:	90                   	nop
ffffffff8b2dd0b4:	90                   	nop
ffffffff8b2dd0b5:	90                   	nop
ffffffff8b2dd0b6:	90                   	nop
ffffffff8b2dd0b7:	90                   	nop
ffffffff8b2dd0b8:	90                   	nop
ffffffff8b2dd0b9:	90                   	nop
ffffffff8b2dd0ba:	90                   	nop
ffffffff8b2dd0bb:	90                   	nop
ffffffff8b2dd0bc:	90                   	nop
ffffffff8b2dd0bd:	90                   	nop
ffffffff8b2dd0be:	90                   	nop
ffffffff8b2dd0bf:	90                   	nop

ffffffff8b2dd0c0 <frame_candidate_91d0c0>:
ffffffff8b2dd0c0:	55                   	push   %rbp
ffffffff8b2dd0c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd0c4:	41 57                	push   %r15
ffffffff8b2dd0c6:	41 56                	push   %r14
ffffffff8b2dd0c8:	41 55                	push   %r13
ffffffff8b2dd0ca:	41 54                	push   %r12
ffffffff8b2dd0cc:	53                   	push   %rbx
ffffffff8b2dd0cd:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b2dd0d1:	8b 1a                	mov    (%rdx),%ebx
ffffffff8b2dd0d3:	49 89 fc             	mov    %rdi,%r12
ffffffff8b2dd0d6:	48 8d 3d 83 cd c6 02 	lea    0x2c6cd83(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_91e450+0x2c6ba10>
ffffffff8b2dd0dd:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
ffffffff8b2dd0e1:	49 89 d6             	mov    %rdx,%r14
ffffffff8b2dd0e4:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
ffffffff8b2dd0e8:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b2dd0eb:	31 f6                	xor    %esi,%esi
ffffffff8b2dd0ed:	31 d2                	xor    %edx,%edx
ffffffff8b2dd0ef:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd0f1:	e8 5a e2 32 00       	call   ffffffff8b60b350 <frame_candidate_91e450+0x32cf00>
ffffffff8b2dd0f6:	85 db                	test   %ebx,%ebx
ffffffff8b2dd0f8:	74 43                	je     ffffffff8b2dd13d <frame_candidate_91d0c0+0x7d>
ffffffff8b2dd0fa:	89 df                	mov    %ebx,%edi
ffffffff8b2dd0fc:	e8 6f f0 c1 ff       	call   ffffffff8aefc170 <handler_629_body-0x3e04d0>
ffffffff8b2dd101:	48 85 c0             	test   %rax,%rax
ffffffff8b2dd104:	0f 84 f9 00 00 00    	je     ffffffff8b2dd203 <frame_candidate_91d0c0+0x143>
ffffffff8b2dd10a:	48 89 c7             	mov    %rax,%rdi
ffffffff8b2dd10d:	49 89 c5             	mov    %rax,%r13
ffffffff8b2dd110:	4c 89 75 d0          	mov    %r14,-0x30(%rbp)
ffffffff8b2dd114:	31 f6                	xor    %esi,%esi
ffffffff8b2dd116:	31 d2                	xor    %edx,%edx
ffffffff8b2dd118:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd11a:	48 81 c7 48 01 00 00 	add    $0x148,%rdi
ffffffff8b2dd121:	e8 7a 9e ba ff       	call   ffffffff8ae86fa0 <handler_629_body-0x4556a0>
ffffffff8b2dd126:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b2dd12a:	41 bf ff ff ff ff    	mov    $0xffffffff,%r15d
ffffffff8b2dd130:	8b 00                	mov    (%rax),%eax
ffffffff8b2dd132:	85 c0                	test   %eax,%eax
ffffffff8b2dd134:	44 0f 49 f8          	cmovns %eax,%r15d
ffffffff8b2dd138:	41 ff c7             	inc    %r15d
ffffffff8b2dd13b:	eb 2f                	jmp    ffffffff8b2dd16c <frame_candidate_91d0c0+0xac>
ffffffff8b2dd13d:	4c 8b 2d 3c cd c6 02 	mov    0x2c6cd3c(%rip),%r13        # ffffffff8df49e80 <frame_candidate_91e450+0x2c6ba30>
ffffffff8b2dd144:	4c 89 75 d0          	mov    %r14,-0x30(%rbp)
ffffffff8b2dd148:	eb 22                	jmp    ffffffff8b2dd16c <frame_candidate_91d0c0+0xac>
ffffffff8b2dd14a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8b2dd150:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd153:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b2dd156:	31 f6                	xor    %esi,%esi
ffffffff8b2dd158:	31 d2                	xor    %edx,%edx
ffffffff8b2dd15a:	e8 a1 f1 32 00       	call   ffffffff8b60c300 <frame_candidate_91e450+0x32deb0>
ffffffff8b2dd15f:	4d 8b 6d 00          	mov    0x0(%r13),%r13
ffffffff8b2dd163:	4d 85 ed             	test   %r13,%r13
ffffffff8b2dd166:	0f 84 9f 00 00 00    	je     ffffffff8b2dd20b <frame_candidate_91d0c0+0x14b>
ffffffff8b2dd16c:	4d 8b 75 48          	mov    0x48(%r13),%r14
ffffffff8b2dd170:	31 f6                	xor    %esi,%esi
ffffffff8b2dd172:	31 d2                	xor    %edx,%edx
ffffffff8b2dd174:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd176:	49 8d 5e 40          	lea    0x40(%r14),%rbx
ffffffff8b2dd17a:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd17d:	e8 ce e1 32 00       	call   ffffffff8b60b350 <frame_candidate_91e450+0x32cf00>
ffffffff8b2dd182:	41 8b 46 28          	mov    0x28(%r14),%eax
ffffffff8b2dd186:	41 39 c7             	cmp    %eax,%r15d
ffffffff8b2dd189:	7f c5                	jg     ffffffff8b2dd150 <frame_candidate_91d0c0+0x90>
ffffffff8b2dd18b:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8b2dd18e:	48 83 c1 08          	add    $0x8,%rcx
ffffffff8b2dd192:	eb 14                	jmp    ffffffff8b2dd1a8 <frame_candidate_91d0c0+0xe8>
ffffffff8b2dd194:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2dd19b:	00 00 00 00 00 
ffffffff8b2dd1a0:	41 ff c7             	inc    %r15d
ffffffff8b2dd1a3:	41 39 c7             	cmp    %eax,%r15d
ffffffff8b2dd1a6:	7f a8                	jg     ffffffff8b2dd150 <frame_candidate_91d0c0+0x90>
ffffffff8b2dd1a8:	49 63 d7             	movslq %r15d,%rdx
ffffffff8b2dd1ab:	48 8d 14 52          	lea    (%rdx,%rdx,2),%rdx
ffffffff8b2dd1af:	48 c1 e2 04          	shl    $0x4,%rdx
ffffffff8b2dd1b3:	48 8b 14 11          	mov    (%rcx,%rdx,1),%rdx
ffffffff8b2dd1b7:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dd1ba:	74 e4                	je     ffffffff8b2dd1a0 <frame_candidate_91d0c0+0xe0>
ffffffff8b2dd1bc:	66 83 7a 20 10       	cmpw   $0x10,0x20(%rdx)
ffffffff8b2dd1c1:	75 dd                	jne    ffffffff8b2dd1a0 <frame_candidate_91d0c0+0xe0>
ffffffff8b2dd1c3:	4c 39 22             	cmp    %r12,(%rdx)
ffffffff8b2dd1c6:	75 d8                	jne    ffffffff8b2dd1a0 <frame_candidate_91d0c0+0xe0>
ffffffff8b2dd1c8:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
ffffffff8b2dd1cc:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dd1cf:	74 0d                	je     ffffffff8b2dd1de <frame_candidate_91d0c0+0x11e>
ffffffff8b2dd1d1:	ba 20 00 00 00       	mov    $0x20,%edx
ffffffff8b2dd1d6:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b2dd1d9:	e8 02 ca 93 ff       	call   ffffffff8ac19be0 <handler_629_body-0x6c2a60>
ffffffff8b2dd1de:	41 8b 85 bc 00 00 00 	mov    0xbc(%r13),%eax
ffffffff8b2dd1e5:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
ffffffff8b2dd1e9:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd1ec:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dd1ef:	31 f6                	xor    %esi,%esi
ffffffff8b2dd1f1:	31 d2                	xor    %edx,%edx
ffffffff8b2dd1f3:	89 01                	mov    %eax,(%rcx)
ffffffff8b2dd1f5:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
ffffffff8b2dd1f9:	44 89 39             	mov    %r15d,(%rcx)
ffffffff8b2dd1fc:	e8 ff f0 32 00       	call   ffffffff8b60c300 <frame_candidate_91e450+0x32deb0>
ffffffff8b2dd201:	eb 0e                	jmp    ffffffff8b2dd211 <frame_candidate_91d0c0+0x151>
ffffffff8b2dd203:	41 be 03 00 00 00    	mov    $0x3,%r14d
ffffffff8b2dd209:	eb 06                	jmp    ffffffff8b2dd211 <frame_candidate_91d0c0+0x151>
ffffffff8b2dd20b:	41 be 09 00 00 00    	mov    $0x9,%r14d
ffffffff8b2dd211:	48 8d 3d 48 cc c6 02 	lea    0x2c6cc48(%rip),%rdi        # ffffffff8df49e60 <frame_candidate_91e450+0x2c6ba10>
ffffffff8b2dd218:	31 f6                	xor    %esi,%esi
ffffffff8b2dd21a:	31 d2                	xor    %edx,%edx
ffffffff8b2dd21c:	e8 df f0 32 00       	call   ffffffff8b60c300 <frame_candidate_91e450+0x32deb0>
ffffffff8b2dd221:	44 89 f0             	mov    %r14d,%eax
ffffffff8b2dd224:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b2dd228:	5b                   	pop    %rbx
ffffffff8b2dd229:	41 5c                	pop    %r12
ffffffff8b2dd22b:	41 5d                	pop    %r13
ffffffff8b2dd22d:	41 5e                	pop    %r14
ffffffff8b2dd22f:	41 5f                	pop    %r15
ffffffff8b2dd231:	5d                   	pop    %rbp
ffffffff8b2dd232:	c3                   	ret
ffffffff8b2dd233:	90                   	nop
ffffffff8b2dd234:	90                   	nop
ffffffff8b2dd235:	90                   	nop
ffffffff8b2dd236:	90                   	nop
ffffffff8b2dd237:	90                   	nop
ffffffff8b2dd238:	90                   	nop
ffffffff8b2dd239:	90                   	nop
ffffffff8b2dd23a:	90                   	nop
ffffffff8b2dd23b:	90                   	nop
ffffffff8b2dd23c:	90                   	nop
ffffffff8b2dd23d:	90                   	nop
ffffffff8b2dd23e:	90                   	nop
ffffffff8b2dd23f:	90                   	nop

ffffffff8b2dd240 <frame_candidate_91d240>:
ffffffff8b2dd240:	55                   	push   %rbp
ffffffff8b2dd241:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd244:	48 8d 3d fc 31 97 00 	lea    0x9731fc(%rip),%rdi        # ffffffff8bc50447 <frame_candidate_91e450+0x971ff7>
ffffffff8b2dd24b:	be 20 00 00 00       	mov    $0x20,%esi
ffffffff8b2dd250:	31 d2                	xor    %edx,%edx
ffffffff8b2dd252:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd254:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b2dd257:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b2dd25a:	6a 00                	push   $0x0
ffffffff8b2dd25c:	6a 07                	push   $0x7
ffffffff8b2dd25e:	e8 7d de b1 ff       	call   ffffffff8adfb0e0 <handler_629_body-0x4e1560>
ffffffff8b2dd263:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b2dd267:	48 89 05 fa 96 25 03 	mov    %rax,0x32596fa(%rip)        # ffffffff8e536968 <frame_candidate_91e450+0x3258518>
ffffffff8b2dd26e:	5d                   	pop    %rbp
ffffffff8b2dd26f:	c3                   	ret

ffffffff8b2dd270 <frame_candidate_91d270>:
ffffffff8b2dd270:	55                   	push   %rbp
ffffffff8b2dd271:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd274:	48 8d 3d d5 96 25 03 	lea    0x32596d5(%rip),%rdi        # ffffffff8e536950 <frame_candidate_91e450+0x3258500>
ffffffff8b2dd27b:	48 8d 35 ee 34 a2 00 	lea    0xa234ee(%rip),%rsi        # ffffffff8bd00770 <frame_candidate_91e450+0xa22320>
ffffffff8b2dd282:	31 d2                	xor    %edx,%edx
ffffffff8b2dd284:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd286:	e8 45 ab ba ff       	call   ffffffff8ae87dd0 <handler_629_body-0x454870>
ffffffff8b2dd28b:	48 c7 05 ca 96 25 03 	movq   $0x0,0x32596ca(%rip)        # ffffffff8e536960 <frame_candidate_91e450+0x3258510>
ffffffff8b2dd292:	00 00 00 00 
ffffffff8b2dd296:	48 8d 3d d6 83 a5 00 	lea    0xa583d6(%rip),%rdi        # ffffffff8bd35673 <frame_candidate_91e450+0xa57223>
ffffffff8b2dd29d:	be 30 00 00 00       	mov    $0x30,%esi
ffffffff8b2dd2a2:	31 d2                	xor    %edx,%edx
ffffffff8b2dd2a4:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd2a6:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b2dd2a9:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b2dd2ac:	6a 00                	push   $0x0
ffffffff8b2dd2ae:	6a 07                	push   $0x7
ffffffff8b2dd2b0:	e8 2b de b1 ff       	call   ffffffff8adfb0e0 <handler_629_body-0x4e1560>
ffffffff8b2dd2b5:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b2dd2b9:	48 89 05 98 96 25 03 	mov    %rax,0x3259698(%rip)        # ffffffff8e536958 <frame_candidate_91e450+0x3258508>
ffffffff8b2dd2c0:	5d                   	pop    %rbp
ffffffff8b2dd2c1:	c3                   	ret
ffffffff8b2dd2c2:	90                   	nop
ffffffff8b2dd2c3:	90                   	nop
ffffffff8b2dd2c4:	90                   	nop
ffffffff8b2dd2c5:	90                   	nop
ffffffff8b2dd2c6:	90                   	nop
ffffffff8b2dd2c7:	90                   	nop
ffffffff8b2dd2c8:	90                   	nop
ffffffff8b2dd2c9:	90                   	nop
ffffffff8b2dd2ca:	90                   	nop
ffffffff8b2dd2cb:	90                   	nop
ffffffff8b2dd2cc:	90                   	nop
ffffffff8b2dd2cd:	90                   	nop
ffffffff8b2dd2ce:	90                   	nop
ffffffff8b2dd2cf:	90                   	nop
ffffffff8b2dd2d0:	83 ff 14             	cmp    $0x14,%edi
ffffffff8b2dd2d3:	77 1b                	ja     ffffffff8b2dd2f0 <frame_candidate_91d2f0>
ffffffff8b2dd2d5:	b8 ff fb 1f 00       	mov    $0x1ffbff,%eax
ffffffff8b2dd2da:	c4 e2 43 f7 c0       	shrx   %edi,%eax,%eax
ffffffff8b2dd2df:	a8 01                	test   $0x1,%al
ffffffff8b2dd2e1:	74 0d                	je     ffffffff8b2dd2f0 <frame_candidate_91d2f0>
ffffffff8b2dd2e3:	89 f8                	mov    %edi,%eax
ffffffff8b2dd2e5:	48 8d 0d c4 01 f0 00 	lea    0xf001c4(%rip),%rcx        # ffffffff8c1dd4b0 <frame_candidate_91e450+0xeff060>
ffffffff8b2dd2ec:	8b 04 81             	mov    (%rcx,%rax,4),%eax
ffffffff8b2dd2ef:	c3                   	ret

ffffffff8b2dd2f0 <frame_candidate_91d2f0>:
ffffffff8b2dd2f0:	55                   	push   %rbp
ffffffff8b2dd2f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd2f4:	53                   	push   %rbx
ffffffff8b2dd2f5:	50                   	push   %rax
ffffffff8b2dd2f6:	89 fb                	mov    %edi,%ebx
ffffffff8b2dd2f8:	e8 53 46 ed ff       	call   ffffffff8b1b1950 <handler_629_body-0x12acf0>
ffffffff8b2dd2fd:	48 63 f3             	movslq %ebx,%rsi
ffffffff8b2dd300:	48 8d 3d e9 ff ff ff 	lea    -0x17(%rip),%rdi        # ffffffff8b2dd2f0 <frame_candidate_91d2f0>
ffffffff8b2dd307:	e8 94 45 ed ff       	call   ffffffff8b1b18a0 <handler_629_body-0x12ada0>
ffffffff8b2dd30c:	48 8d 35 8f 74 97 00 	lea    0x97748f(%rip),%rsi        # ffffffff8bc547a2 <frame_candidate_91e450+0x976352>
ffffffff8b2dd313:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b2dd318:	89 da                	mov    %ebx,%edx
ffffffff8b2dd31a:	31 c0                	xor    %eax,%eax
ffffffff8b2dd31c:	e8 ef d6 37 00       	call   ffffffff8b65aa10 <frame_candidate_91e450+0x37c5c0>
ffffffff8b2dd321:	0f 0b                	ud2
ffffffff8b2dd323:	90                   	nop
ffffffff8b2dd324:	90                   	nop
ffffffff8b2dd325:	90                   	nop
ffffffff8b2dd326:	90                   	nop
ffffffff8b2dd327:	90                   	nop
ffffffff8b2dd328:	90                   	nop
ffffffff8b2dd329:	90                   	nop
ffffffff8b2dd32a:	90                   	nop
ffffffff8b2dd32b:	90                   	nop
ffffffff8b2dd32c:	90                   	nop
ffffffff8b2dd32d:	90                   	nop
ffffffff8b2dd32e:	90                   	nop
ffffffff8b2dd32f:	90                   	nop

ffffffff8b2dd330 <frame_candidate_91d330>:
ffffffff8b2dd330:	55                   	push   %rbp
ffffffff8b2dd331:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd334:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b2dd339:	5d                   	pop    %rbp
ffffffff8b2dd33a:	c3                   	ret
ffffffff8b2dd33b:	90                   	nop
ffffffff8b2dd33c:	90                   	nop
ffffffff8b2dd33d:	90                   	nop
ffffffff8b2dd33e:	90                   	nop
ffffffff8b2dd33f:	90                   	nop

ffffffff8b2dd340 <frame_candidate_91d340>:
ffffffff8b2dd340:	55                   	push   %rbp
ffffffff8b2dd341:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd344:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b2dd349:	5d                   	pop    %rbp
ffffffff8b2dd34a:	c3                   	ret
ffffffff8b2dd34b:	90                   	nop
ffffffff8b2dd34c:	90                   	nop
ffffffff8b2dd34d:	90                   	nop
ffffffff8b2dd34e:	90                   	nop
ffffffff8b2dd34f:	90                   	nop

ffffffff8b2dd350 <frame_candidate_91d350>:
ffffffff8b2dd350:	55                   	push   %rbp
ffffffff8b2dd351:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd354:	41 57                	push   %r15
ffffffff8b2dd356:	41 56                	push   %r14
ffffffff8b2dd358:	53                   	push   %rbx
ffffffff8b2dd359:	50                   	push   %rax
ffffffff8b2dd35a:	48 8b 07             	mov    (%rdi),%rax
ffffffff8b2dd35d:	49 89 f7             	mov    %rsi,%r15
ffffffff8b2dd360:	31 f6                	xor    %esi,%esi
ffffffff8b2dd362:	31 d2                	xor    %edx,%edx
ffffffff8b2dd364:	49 81 c7 ff 3f 00 00 	add    $0x3fff,%r15
ffffffff8b2dd36b:	49 c1 ff 0e          	sar    $0xe,%r15
ffffffff8b2dd36f:	4c 8b 30             	mov    (%rax),%r14
ffffffff8b2dd372:	49 8d 5e 18          	lea    0x18(%r14),%rbx
ffffffff8b2dd376:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd379:	e8 22 73 eb ff       	call   ffffffff8b1946a0 <handler_629_body-0x147fa0>
ffffffff8b2dd37e:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2dd381:	41 bf 2d 00 00 00    	mov    $0x2d,%r15d
ffffffff8b2dd387:	49 3b b6 88 00 00 00 	cmp    0x88(%r14),%rsi
ffffffff8b2dd38e:	72 0b                	jb     ffffffff8b2dd39b <frame_candidate_91d350+0x4b>
ffffffff8b2dd390:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dd393:	e8 68 e6 ff ff       	call   ffffffff8b2dba00 <handler_629_body-0xc40>
ffffffff8b2dd398:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd39b:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd39e:	31 f6                	xor    %esi,%esi
ffffffff8b2dd3a0:	31 d2                	xor    %edx,%edx
ffffffff8b2dd3a2:	e8 09 7b eb ff       	call   ffffffff8b194eb0 <handler_629_body-0x147790>
ffffffff8b2dd3a7:	44 89 f8             	mov    %r15d,%eax
ffffffff8b2dd3aa:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dd3ae:	5b                   	pop    %rbx
ffffffff8b2dd3af:	41 5e                	pop    %r14
ffffffff8b2dd3b1:	41 5f                	pop    %r15
ffffffff8b2dd3b3:	5d                   	pop    %rbp
ffffffff8b2dd3b4:	c3                   	ret
ffffffff8b2dd3b5:	90                   	nop
ffffffff8b2dd3b6:	90                   	nop
ffffffff8b2dd3b7:	90                   	nop
ffffffff8b2dd3b8:	90                   	nop
ffffffff8b2dd3b9:	90                   	nop
ffffffff8b2dd3ba:	90                   	nop
ffffffff8b2dd3bb:	90                   	nop
ffffffff8b2dd3bc:	90                   	nop
ffffffff8b2dd3bd:	90                   	nop
ffffffff8b2dd3be:	90                   	nop
ffffffff8b2dd3bf:	90                   	nop
ffffffff8b2dd3c0:	b8 19 00 00 00       	mov    $0x19,%eax
ffffffff8b2dd3c5:	48 81 fe 00 a2 04 40 	cmp    $0x4004a200,%rsi
ffffffff8b2dd3cc:	75 15                	jne    ffffffff8b2dd3e3 <frame_candidate_91d3ce+0x15>

ffffffff8b2dd3ce <frame_candidate_91d3ce>:
ffffffff8b2dd3ce:	55                   	push   %rbp
ffffffff8b2dd3cf:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd3d2:	48 8b 07             	mov    (%rdi),%rax
ffffffff8b2dd3d5:	31 c9                	xor    %ecx,%ecx
ffffffff8b2dd3d7:	83 78 18 00          	cmpl   $0x0,0x18(%rax)
ffffffff8b2dd3db:	0f 95 c1             	setne  %cl
ffffffff8b2dd3de:	31 c0                	xor    %eax,%eax
ffffffff8b2dd3e0:	89 0a                	mov    %ecx,(%rdx)
ffffffff8b2dd3e2:	5d                   	pop    %rbp
ffffffff8b2dd3e3:	c3                   	ret
ffffffff8b2dd3e4:	90                   	nop
ffffffff8b2dd3e5:	90                   	nop
ffffffff8b2dd3e6:	90                   	nop
ffffffff8b2dd3e7:	90                   	nop
ffffffff8b2dd3e8:	90                   	nop
ffffffff8b2dd3e9:	90                   	nop
ffffffff8b2dd3ea:	90                   	nop
ffffffff8b2dd3eb:	90                   	nop
ffffffff8b2dd3ec:	90                   	nop
ffffffff8b2dd3ed:	90                   	nop
ffffffff8b2dd3ee:	90                   	nop
ffffffff8b2dd3ef:	90                   	nop

ffffffff8b2dd3f0 <frame_candidate_91d3f0>:
ffffffff8b2dd3f0:	55                   	push   %rbp
ffffffff8b2dd3f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd3f4:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b2dd3f9:	5d                   	pop    %rbp
ffffffff8b2dd3fa:	c3                   	ret
ffffffff8b2dd3fb:	90                   	nop
ffffffff8b2dd3fc:	90                   	nop
ffffffff8b2dd3fd:	90                   	nop
ffffffff8b2dd3fe:	90                   	nop
ffffffff8b2dd3ff:	90                   	nop

ffffffff8b2dd400 <frame_candidate_91d400>:
ffffffff8b2dd400:	55                   	push   %rbp
ffffffff8b2dd401:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd404:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b2dd409:	5d                   	pop    %rbp
ffffffff8b2dd40a:	c3                   	ret
ffffffff8b2dd40b:	90                   	nop
ffffffff8b2dd40c:	90                   	nop
ffffffff8b2dd40d:	90                   	nop
ffffffff8b2dd40e:	90                   	nop
ffffffff8b2dd40f:	90                   	nop

ffffffff8b2dd410 <frame_candidate_91d410>:
ffffffff8b2dd410:	55                   	push   %rbp
ffffffff8b2dd411:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd414:	41 57                	push   %r15
ffffffff8b2dd416:	41 56                	push   %r14
ffffffff8b2dd418:	41 54                	push   %r12
ffffffff8b2dd41a:	53                   	push   %rbx
ffffffff8b2dd41b:	4c 8b 3f             	mov    (%rdi),%r15
ffffffff8b2dd41e:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b2dd421:	31 f6                	xor    %esi,%esi
ffffffff8b2dd423:	31 d2                	xor    %edx,%edx
ffffffff8b2dd425:	4d 8b 27             	mov    (%r15),%r12
ffffffff8b2dd428:	4d 8d 74 24 18       	lea    0x18(%r12),%r14
ffffffff8b2dd42d:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dd430:	e8 6b 72 eb ff       	call   ffffffff8b1946a0 <handler_629_body-0x147fa0>
ffffffff8b2dd435:	4d 8b a4 24 88 00 00 	mov    0x88(%r12),%r12
ffffffff8b2dd43c:	00 
ffffffff8b2dd43d:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dd440:	31 f6                	xor    %esi,%esi
ffffffff8b2dd442:	31 d2                	xor    %edx,%edx
ffffffff8b2dd444:	e8 67 7a eb ff       	call   ffffffff8b194eb0 <handler_629_body-0x147790>
ffffffff8b2dd449:	be 78 00 00 00       	mov    $0x78,%esi
ffffffff8b2dd44e:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd451:	e8 9a bb 93 ff       	call   ffffffff8ac18ff0 <handler_629_body-0x6c3650>
ffffffff8b2dd456:	4c 89 e0             	mov    %r12,%rax
ffffffff8b2dd459:	c7 43 58 00 40 00 00 	movl   $0x4000,0x58(%rbx)
ffffffff8b2dd460:	48 c1 e0 0e          	shl    $0xe,%rax
ffffffff8b2dd464:	48 89 43 48          	mov    %rax,0x48(%rbx)
ffffffff8b2dd468:	4c 89 63 50          	mov    %r12,0x50(%rbx)
ffffffff8b2dd46c:	b8 00 90 00 00       	mov    $0x9000,%eax
ffffffff8b2dd471:	41 0b 47 10          	or     0x10(%r15),%eax
ffffffff8b2dd475:	66 89 43 08          	mov    %ax,0x8(%rbx)
ffffffff8b2dd479:	41 8b 47 08          	mov    0x8(%r15),%eax
ffffffff8b2dd47d:	89 43 0c             	mov    %eax,0xc(%rbx)
ffffffff8b2dd480:	41 8b 47 0c          	mov    0xc(%r15),%eax
ffffffff8b2dd484:	89 43 10             	mov    %eax,0x10(%rbx)
ffffffff8b2dd487:	31 c0                	xor    %eax,%eax
ffffffff8b2dd489:	5b                   	pop    %rbx
ffffffff8b2dd48a:	41 5c                	pop    %r12
ffffffff8b2dd48c:	41 5e                	pop    %r14
ffffffff8b2dd48e:	41 5f                	pop    %r15
ffffffff8b2dd490:	5d                   	pop    %rbp
ffffffff8b2dd491:	c3                   	ret
ffffffff8b2dd492:	90                   	nop
ffffffff8b2dd493:	90                   	nop
ffffffff8b2dd494:	90                   	nop
ffffffff8b2dd495:	90                   	nop
ffffffff8b2dd496:	90                   	nop
ffffffff8b2dd497:	90                   	nop
ffffffff8b2dd498:	90                   	nop
ffffffff8b2dd499:	90                   	nop
ffffffff8b2dd49a:	90                   	nop
ffffffff8b2dd49b:	90                   	nop
ffffffff8b2dd49c:	90                   	nop
ffffffff8b2dd49d:	90                   	nop
ffffffff8b2dd49e:	90                   	nop
ffffffff8b2dd49f:	90                   	nop

ffffffff8b2dd4a0 <frame_candidate_91d4a0>:
ffffffff8b2dd4a0:	55                   	push   %rbp
ffffffff8b2dd4a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd4a4:	53                   	push   %rbx
ffffffff8b2dd4a5:	50                   	push   %rax
ffffffff8b2dd4a6:	48 8b 1f             	mov    (%rdi),%rbx
ffffffff8b2dd4a9:	48 c7 07 00 00 00 00 	movq   $0x0,(%rdi)
ffffffff8b2dd4b0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8b2dd4b5:	f0 0f c1 43 14       	lock xadd %eax,0x14(%rbx)
ffffffff8b2dd4ba:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b2dd4bd:	75 19                	jne    ffffffff8b2dd4d8 <frame_candidate_91d4a0+0x38>
ffffffff8b2dd4bf:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8b2dd4c2:	e8 d9 46 b4 ff       	call   ffffffff8ae21ba0 <handler_629_body-0x4baaa0>
ffffffff8b2dd4c7:	48 8b 3d 9a 94 25 03 	mov    0x325949a(%rip),%rdi        # ffffffff8e536968 <frame_candidate_91e450+0x3258518>
ffffffff8b2dd4ce:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dd4d1:	31 d2                	xor    %edx,%edx
ffffffff8b2dd4d3:	e8 e8 eb b1 ff       	call   ffffffff8adfc0c0 <handler_629_body-0x4e0580>
ffffffff8b2dd4d8:	31 c0                	xor    %eax,%eax
ffffffff8b2dd4da:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dd4de:	5b                   	pop    %rbx
ffffffff8b2dd4df:	5d                   	pop    %rbp
ffffffff8b2dd4e0:	c3                   	ret
ffffffff8b2dd4e1:	90                   	nop
ffffffff8b2dd4e2:	90                   	nop
ffffffff8b2dd4e3:	90                   	nop
ffffffff8b2dd4e4:	90                   	nop
ffffffff8b2dd4e5:	90                   	nop
ffffffff8b2dd4e6:	90                   	nop
ffffffff8b2dd4e7:	90                   	nop
ffffffff8b2dd4e8:	90                   	nop
ffffffff8b2dd4e9:	90                   	nop
ffffffff8b2dd4ea:	90                   	nop
ffffffff8b2dd4eb:	90                   	nop
ffffffff8b2dd4ec:	90                   	nop
ffffffff8b2dd4ed:	90                   	nop
ffffffff8b2dd4ee:	90                   	nop
ffffffff8b2dd4ef:	90                   	nop

ffffffff8b2dd4f0 <frame_candidate_91d4f0>:
ffffffff8b2dd4f0:	55                   	push   %rbp
ffffffff8b2dd4f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd4f4:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b2dd4f9:	5d                   	pop    %rbp
ffffffff8b2dd4fa:	c3                   	ret
ffffffff8b2dd4fb:	90                   	nop
ffffffff8b2dd4fc:	90                   	nop
ffffffff8b2dd4fd:	90                   	nop
ffffffff8b2dd4fe:	90                   	nop
ffffffff8b2dd4ff:	90                   	nop

ffffffff8b2dd500 <frame_candidate_91d500>:
ffffffff8b2dd500:	55                   	push   %rbp
ffffffff8b2dd501:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd504:	b8 2d 00 00 00       	mov    $0x2d,%eax
ffffffff8b2dd509:	5d                   	pop    %rbp
ffffffff8b2dd50a:	c3                   	ret
ffffffff8b2dd50b:	90                   	nop
ffffffff8b2dd50c:	90                   	nop
ffffffff8b2dd50d:	90                   	nop
ffffffff8b2dd50e:	90                   	nop
ffffffff8b2dd50f:	90                   	nop

ffffffff8b2dd510 <frame_candidate_91d510>:
ffffffff8b2dd510:	55                   	push   %rbp
ffffffff8b2dd511:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd514:	c7 46 04 ff 00 00 00 	movl   $0xff,0x4(%rsi)
ffffffff8b2dd51b:	31 c0                	xor    %eax,%eax
ffffffff8b2dd51d:	5d                   	pop    %rbp
ffffffff8b2dd51e:	c3                   	ret
ffffffff8b2dd51f:	90                   	nop

ffffffff8b2dd520 <frame_candidate_91d520>:
ffffffff8b2dd520:	55                   	push   %rbp
ffffffff8b2dd521:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd524:	41 57                	push   %r15
ffffffff8b2dd526:	41 56                	push   %r14
ffffffff8b2dd528:	41 55                	push   %r13
ffffffff8b2dd52a:	41 54                	push   %r12
ffffffff8b2dd52c:	53                   	push   %rbx
ffffffff8b2dd52d:	50                   	push   %rax
ffffffff8b2dd52e:	8b 45 10             	mov    0x10(%rbp),%eax
ffffffff8b2dd531:	41 be 16 00 00 00    	mov    $0x16,%r14d
ffffffff8b2dd537:	a8 02                	test   $0x2,%al
ffffffff8b2dd539:	75 6e                	jne    ffffffff8b2dd5a9 <frame_candidate_91d520+0x89>
ffffffff8b2dd53b:	8b 47 24             	mov    0x24(%rdi),%eax
ffffffff8b2dd53e:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
ffffffff8b2dd542:	b9 11 00 00 00       	mov    $0x11,%ecx
ffffffff8b2dd547:	49 89 d7             	mov    %rdx,%r15
ffffffff8b2dd54a:	45 89 c4             	mov    %r8d,%r12d
ffffffff8b2dd54d:	49 89 f5             	mov    %rsi,%r13
ffffffff8b2dd550:	83 e0 01             	and    $0x1,%eax
ffffffff8b2dd553:	0f 44 c8             	cmove  %eax,%ecx
ffffffff8b2dd556:	8b 47 24             	mov    0x24(%rdi),%eax
ffffffff8b2dd559:	48 8b 1f             	mov    (%rdi),%rbx
ffffffff8b2dd55c:	8d 51 22             	lea    0x22(%rcx),%edx
ffffffff8b2dd55f:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8b2dd562:	a8 02                	test   $0x2,%al
ffffffff8b2dd564:	0f 44 d1             	cmove  %ecx,%edx
ffffffff8b2dd567:	41 21 d1             	and    %edx,%r9d
ffffffff8b2dd56a:	45 89 ce             	mov    %r9d,%r14d
ffffffff8b2dd56d:	e8 ae 45 b4 ff       	call   ffffffff8ae21b20 <handler_629_body-0x4bab20>
ffffffff8b2dd572:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
ffffffff8b2dd576:	44 8b 4d 10          	mov    0x10(%rbp),%r9d
ffffffff8b2dd57a:	41 0f b7 cc          	movzwl %r12w,%ecx
ffffffff8b2dd57e:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b2dd581:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2dd584:	45 89 f0             	mov    %r14d,%r8d
ffffffff8b2dd587:	ff 75 20             	push   0x20(%rbp)
ffffffff8b2dd58a:	6a 00                	push   $0x0
ffffffff8b2dd58c:	ff 75 18             	push   0x18(%rbp)
ffffffff8b2dd58f:	ff 33                	push   (%rbx)
ffffffff8b2dd591:	e8 9a c9 19 00       	call   ffffffff8b479f30 <frame_candidate_91e450+0x19bae0>
ffffffff8b2dd596:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b2dd59a:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dd59d:	85 c0                	test   %eax,%eax
ffffffff8b2dd59f:	74 08                	je     ffffffff8b2dd5a9 <frame_candidate_91d520+0x89>
ffffffff8b2dd5a1:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8b2dd5a4:	e8 f7 45 b4 ff       	call   ffffffff8ae21ba0 <handler_629_body-0x4baaa0>
ffffffff8b2dd5a9:	44 89 f0             	mov    %r14d,%eax
ffffffff8b2dd5ac:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2dd5b0:	5b                   	pop    %rbx
ffffffff8b2dd5b1:	41 5c                	pop    %r12
ffffffff8b2dd5b3:	41 5d                	pop    %r13
ffffffff8b2dd5b5:	41 5e                	pop    %r14
ffffffff8b2dd5b7:	41 5f                	pop    %r15
ffffffff8b2dd5b9:	5d                   	pop    %rbp
ffffffff8b2dd5ba:	c3                   	ret
ffffffff8b2dd5bb:	90                   	nop
ffffffff8b2dd5bc:	90                   	nop
ffffffff8b2dd5bd:	90                   	nop
ffffffff8b2dd5be:	90                   	nop
ffffffff8b2dd5bf:	90                   	nop

ffffffff8b2dd5c0 <frame_candidate_91d5c0>:
ffffffff8b2dd5c0:	55                   	push   %rbp
ffffffff8b2dd5c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd5c4:	41 57                	push   %r15
ffffffff8b2dd5c6:	41 56                	push   %r14
ffffffff8b2dd5c8:	41 55                	push   %r13
ffffffff8b2dd5ca:	41 54                	push   %r12
ffffffff8b2dd5cc:	53                   	push   %rbx
ffffffff8b2dd5cd:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8b2dd5d1:	48 8d 1d 38 ed ff 02 	lea    0x2ffed38(%rip),%rbx        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2dd5d8:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2dd5dd:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b2dd5e0:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b2dd5e4:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8b2dd5eb:	00 
ffffffff8b2dd5ec:	e8 af a8 19 00       	call   ffffffff8b477ea0 <frame_candidate_91e450+0x199a50>
ffffffff8b2dd5f1:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd5f4:	85 c0                	test   %eax,%eax
ffffffff8b2dd5f6:	75 2e                	jne    ffffffff8b2dd626 <frame_candidate_91d5c0+0x66>
ffffffff8b2dd5f8:	48 83 3d 98 c0 0a 03 	cmpq   $0x0,0x30ac098(%rip)        # ffffffff8e389698 <frame_candidate_91e450+0x30ab248>
ffffffff8b2dd5ff:	00 
ffffffff8b2dd600:	74 43                	je     ffffffff8b2dd645 <frame_candidate_91d5c0+0x85>
ffffffff8b2dd602:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2dd607:	e8 14 a9 19 00       	call   ffffffff8b477f20 <frame_candidate_91e450+0x199ad0>
ffffffff8b2dd60c:	48 8d 35 4b 8a a1 00 	lea    0xa18a4b(%rip),%rsi        # ffffffff8bcf605e <frame_candidate_91e450+0xa17c0e>
ffffffff8b2dd613:	48 8d 0d 86 c0 0a 03 	lea    0x30ac086(%rip),%rcx        # ffffffff8e3896a0 <frame_candidate_91e450+0x30ab250>
ffffffff8b2dd61a:	31 ff                	xor    %edi,%edi
ffffffff8b2dd61c:	31 d2                	xor    %edx,%edx
ffffffff8b2dd61e:	e8 dd 98 1a 00       	call   ffffffff8b486f00 <frame_candidate_91e450+0x1a8ab0>
ffffffff8b2dd623:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd626:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b2dd629:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b2dd62d:	0f 85 65 02 00 00    	jne    ffffffff8b2dd898 <frame_candidate_91d5c0+0x2d8>
ffffffff8b2dd633:	44 89 f8             	mov    %r15d,%eax
ffffffff8b2dd636:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8b2dd63a:	5b                   	pop    %rbx
ffffffff8b2dd63b:	41 5c                	pop    %r12
ffffffff8b2dd63d:	41 5d                	pop    %r13
ffffffff8b2dd63f:	41 5e                	pop    %r14
ffffffff8b2dd641:	41 5f                	pop    %r15
ffffffff8b2dd643:	5d                   	pop    %rbp
ffffffff8b2dd644:	c3                   	ret
ffffffff8b2dd645:	48 8d 05 24 c0 0a 03 	lea    0x30ac024(%rip),%rax        # ffffffff8e389670 <frame_candidate_91e450+0x30ab220>
ffffffff8b2dd64c:	48 8d 1d 2d 67 56 00 	lea    0x56672d(%rip),%rbx        # ffffffff8b843d80 <frame_candidate_91e450+0x565930>
ffffffff8b2dd653:	4c 8d 2d 71 90 9b 00 	lea    0x9b9071(%rip),%r13        # ffffffff8bc966cb <frame_candidate_91e450+0x9b827b>
ffffffff8b2dd65a:	4c 8d 35 76 25 a0 00 	lea    0xa02576(%rip),%r14        # ffffffff8bcdfbd7 <frame_candidate_91e450+0xa01787>
ffffffff8b2dd661:	48 89 05 30 c0 0a 03 	mov    %rax,0x30ac030(%rip)        # ffffffff8e389698 <frame_candidate_91e450+0x30ab248>
ffffffff8b2dd668:	eb 39                	jmp    ffffffff8b2dd6a3 <frame_candidate_91d5c0+0xe3>
ffffffff8b2dd66a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8b2dd670:	48 8d 3d b1 fe ef 00 	lea    0xeffeb1(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2dd677:	be 7c 00 00 00       	mov    $0x7c,%esi
ffffffff8b2dd67c:	89 c2                	mov    %eax,%edx
ffffffff8b2dd67e:	48 8d 0d cb 2d 97 00 	lea    0x972dcb(%rip),%rcx        # ffffffff8bc50450 <frame_candidate_91e450+0x972000>
ffffffff8b2dd685:	4d 89 e8             	mov    %r13,%r8
ffffffff8b2dd688:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd68b:	31 c0                	xor    %eax,%eax
ffffffff8b2dd68d:	e8 fe a3 dd ff       	call   ffffffff8b0b7a90 <handler_629_body-0x224bb0>
ffffffff8b2dd692:	4c 8b 6b 18          	mov    0x18(%rbx),%r13
ffffffff8b2dd696:	48 83 c3 18          	add    $0x18,%rbx
ffffffff8b2dd69a:	4d 85 ed             	test   %r13,%r13
ffffffff8b2dd69d:	0f 84 ad 01 00 00    	je     ffffffff8b2dd850 <frame_candidate_91d5c0+0x290>
ffffffff8b2dd6a3:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b2dd6a6:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b2dd6a9:	e8 02 e3 94 ff       	call   ffffffff8ac2b9b0 <handler_629_body-0x6b0c90>
ffffffff8b2dd6ae:	44 0f b6 63 08       	movzbl 0x8(%rbx),%r12d
ffffffff8b2dd6b3:	48 8d 45 c8          	lea    -0x38(%rbp),%rax
ffffffff8b2dd6b7:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b2dd6ba:	b9 02 00 00 00       	mov    $0x2,%ecx
ffffffff8b2dd6bf:	31 ff                	xor    %edi,%edi
ffffffff8b2dd6c1:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b2dd6c4:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b2dd6c7:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b2dd6cb:	44 89 e2             	mov    %r12d,%edx
ffffffff8b2dd6ce:	e8 cd 01 00 00       	call   ffffffff8b2dd8a0 <frame_candidate_91d8a0>
ffffffff8b2dd6d3:	85 c0                	test   %eax,%eax
ffffffff8b2dd6d5:	75 99                	jne    ffffffff8b2dd670 <frame_candidate_91d5c0+0xb0>
ffffffff8b2dd6d7:	4c 8b 73 10          	mov    0x10(%rbx),%r14
ffffffff8b2dd6db:	4d 85 f6             	test   %r14,%r14
ffffffff8b2dd6de:	0f 84 8b 00 00 00    	je     ffffffff8b2dd76f <frame_candidate_91d5c0+0x1af>
ffffffff8b2dd6e4:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2dd6e7:	48 8d 75 c0          	lea    -0x40(%rbp),%rsi
ffffffff8b2dd6eb:	e8 c0 16 05 00       	call   ffffffff8b32edb0 <frame_candidate_91e450+0x50960>
ffffffff8b2dd6f0:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd6f3:	85 c0                	test   %eax,%eax
ffffffff8b2dd6f5:	74 1d                	je     ffffffff8b2dd714 <frame_candidate_91d5c0+0x154>
ffffffff8b2dd6f7:	48 8d 3d 2a fe ef 00 	lea    0xeffe2a(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2dd6fe:	be 8b 00 00 00       	mov    $0x8b,%esi
ffffffff8b2dd703:	48 8d 15 0b 89 a3 00 	lea    0xa3890b(%rip),%rdx        # ffffffff8bd16015 <frame_candidate_91e450+0xa37bc5>
ffffffff8b2dd70a:	4c 89 e9             	mov    %r13,%rcx
ffffffff8b2dd70d:	31 c0                	xor    %eax,%eax
ffffffff8b2dd70f:	e8 dc a2 dd ff       	call   ffffffff8b0b79f0 <handler_629_body-0x224c50>
ffffffff8b2dd714:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
ffffffff8b2dd719:	75 04                	jne    ffffffff8b2dd71f <frame_candidate_91d5c0+0x15f>
ffffffff8b2dd71b:	4c 89 75 c0          	mov    %r14,-0x40(%rbp)
ffffffff8b2dd71f:	48 8d 3d 02 fe ef 00 	lea    0xeffe02(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2dd726:	be 99 00 00 00       	mov    $0x99,%esi
ffffffff8b2dd72b:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b2dd730:	44 89 e1             	mov    %r12d,%ecx
ffffffff8b2dd733:	e8 e8 ed 38 00       	call   ffffffff8b66c520 <frame_candidate_91e450+0x38e0d0>
ffffffff8b2dd738:	48 85 c0             	test   %rax,%rax
ffffffff8b2dd73b:	0f 84 2e 01 00 00    	je     ffffffff8b2dd86f <frame_candidate_91d5c0+0x2af>
ffffffff8b2dd741:	49 89 c6             	mov    %rax,%r14
ffffffff8b2dd744:	41 8d 44 24 ff       	lea    -0x1(%r12),%eax
ffffffff8b2dd749:	83 f8 08             	cmp    $0x8,%eax
ffffffff8b2dd74c:	0f 87 cd 00 00 00    	ja     ffffffff8b2dd81f <frame_candidate_91d5c0+0x25f>
ffffffff8b2dd752:	48 8d 0d ab fd ef 00 	lea    0xeffdab(%rip),%rcx        # ffffffff8c1dd504 <frame_candidate_91e450+0xeff0b4>
ffffffff8b2dd759:	48 63 04 81          	movslq (%rcx,%rax,4),%rax
ffffffff8b2dd75d:	48 01 c8             	add    %rcx,%rax
ffffffff8b2dd760:	ff e0                	jmp    *%rax
ffffffff8b2dd762:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b2dd766:	49 89 46 10          	mov    %rax,0x10(%r14)
ffffffff8b2dd76a:	e9 9a 00 00 00       	jmp    ffffffff8b2dd809 <frame_candidate_91d5c0+0x249>
ffffffff8b2dd76f:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b2dd772:	e9 cd 00 00 00       	jmp    ffffffff8b2dd844 <frame_candidate_91d5c0+0x284>
ffffffff8b2dd777:	0f b6 45 c0          	movzbl -0x40(%rbp),%eax
ffffffff8b2dd77b:	41 88 46 0e          	mov    %al,0xe(%r14)
ffffffff8b2dd77f:	41 80 4e 0c 04       	orb    $0x4,0xc(%r14)
ffffffff8b2dd784:	48 8d 05 9d c5 94 ff 	lea    -0x6b3a63(%rip),%rax        # ffffffff8ac29d28 <handler_629_body-0x6b2918>
ffffffff8b2dd78b:	41 c6 46 0d 02       	movb   $0x2,0xd(%r14)
ffffffff8b2dd790:	49 89 46 28          	mov    %rax,0x28(%r14)
ffffffff8b2dd794:	eb 73                	jmp    ffffffff8b2dd809 <frame_candidate_91d5c0+0x249>
ffffffff8b2dd796:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
ffffffff8b2dd79a:	e8 01 50 f1 ff       	call   ffffffff8b1f27a0 <handler_629_body-0xe9ea0>
ffffffff8b2dd79f:	41 89 46 18          	mov    %eax,0x18(%r14)
ffffffff8b2dd7a3:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b2dd7a7:	49 89 46 10          	mov    %rax,0x10(%r14)
ffffffff8b2dd7ab:	41 80 4e 0c 02       	orb    $0x2,0xc(%r14)
ffffffff8b2dd7b0:	eb 57                	jmp    ffffffff8b2dd809 <frame_candidate_91d5c0+0x249>
ffffffff8b2dd7b2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b2dd7b6:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dd7b9:	48 83 c7 10          	add    $0x10,%rdi
ffffffff8b2dd7bd:	49 89 46 38          	mov    %rax,0x38(%r14)
ffffffff8b2dd7c1:	0f b6 45 c0          	movzbl -0x40(%rbp),%eax
ffffffff8b2dd7c5:	fe c8                	dec    %al
ffffffff8b2dd7c7:	41 88 46 0d          	mov    %al,0xd(%r14)
ffffffff8b2dd7cb:	e8 00 c8 a5 ff       	call   ffffffff8ad39fd0 <handler_629_body-0x5a2670>
ffffffff8b2dd7d0:	85 c0                	test   %eax,%eax
ffffffff8b2dd7d2:	0f 85 9f 00 00 00    	jne    ffffffff8b2dd877 <frame_candidate_91d5c0+0x2b7>
ffffffff8b2dd7d8:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b2dd7db:	48 8d 35 d0 fa 98 00 	lea    0x98fad0(%rip),%rsi        # ffffffff8bc6d2b2 <frame_candidate_91e450+0x98ee62>
ffffffff8b2dd7e2:	e8 c9 e1 94 ff       	call   ffffffff8ac2b9b0 <handler_629_body-0x6b0c90>
ffffffff8b2dd7e7:	85 c0                	test   %eax,%eax
ffffffff8b2dd7e9:	75 1e                	jne    ffffffff8b2dd809 <frame_candidate_91d5c0+0x249>
ffffffff8b2dd7eb:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2dd7f0:	48 8d 15 71 bd 0a 03 	lea    0x30abd71(%rip),%rdx        # ffffffff8e389568 <frame_candidate_91e450+0x30ab118>
ffffffff8b2dd7f7:	31 f6                	xor    %esi,%esi
ffffffff8b2dd7f9:	4c 89 35 60 bd 0a 03 	mov    %r14,0x30abd60(%rip)        # ffffffff8e389560 <frame_candidate_91e450+0x30ab110>
ffffffff8b2dd800:	e8 1b c3 a5 ff       	call   ffffffff8ad39b20 <handler_629_body-0x5a2b20>
ffffffff8b2dd805:	85 c0                	test   %eax,%eax
ffffffff8b2dd807:	75 6e                	jne    ffffffff8b2dd877 <frame_candidate_91d5c0+0x2b7>
ffffffff8b2dd809:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b2dd80d:	41 0f b6 56 09       	movzbl 0x9(%r14),%edx
ffffffff8b2dd812:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b2dd815:	e8 86 b7 cb ff       	call   ffffffff8af98fa0 <handler_629_body-0x3436a0>
ffffffff8b2dd81a:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd81d:	eb 1d                	jmp    ffffffff8b2dd83c <frame_candidate_91d5c0+0x27c>
ffffffff8b2dd81f:	48 8d 3d 02 fd ef 00 	lea    0xeffd02(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2dd826:	be e9 00 00 00       	mov    $0xe9,%esi
ffffffff8b2dd82b:	48 8d 15 72 60 9a 00 	lea    0x9a6072(%rip),%rdx        # ffffffff8bc838a4 <frame_candidate_91e450+0x9a5454>
ffffffff8b2dd832:	44 89 e1             	mov    %r12d,%ecx
ffffffff8b2dd835:	31 c0                	xor    %eax,%eax
ffffffff8b2dd837:	e8 b4 a1 dd ff       	call   ffffffff8b0b79f0 <handler_629_body-0x224c50>
ffffffff8b2dd83c:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dd83f:	e8 7c cc 22 00       	call   ffffffff8b50a4c0 <frame_candidate_91e450+0x22c070>
ffffffff8b2dd844:	4c 8d 35 8c 23 a0 00 	lea    0xa0238c(%rip),%r14        # ffffffff8bcdfbd7 <frame_candidate_91e450+0xa01787>
ffffffff8b2dd84b:	e9 42 fe ff ff       	jmp    ffffffff8b2dd692 <frame_candidate_91d5c0+0xd2>
ffffffff8b2dd850:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2dd855:	e8 c6 a6 19 00       	call   ffffffff8b477f20 <frame_candidate_91e450+0x199ad0>
ffffffff8b2dd85a:	48 8d 1d af ea ff 02 	lea    0x2ffeaaf(%rip),%rbx        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2dd861:	45 85 ff             	test   %r15d,%r15d
ffffffff8b2dd864:	0f 85 bc fd ff ff    	jne    ffffffff8b2dd626 <frame_candidate_91d5c0+0x66>
ffffffff8b2dd86a:	e9 9d fd ff ff       	jmp    ffffffff8b2dd60c <frame_candidate_91d5c0+0x4c>
ffffffff8b2dd86f:	41 bf 04 00 00 00    	mov    $0x4,%r15d
ffffffff8b2dd875:	eb 0b                	jmp    ffffffff8b2dd882 <frame_candidate_91d5c0+0x2c2>
ffffffff8b2dd877:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2dd87a:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2dd87d:	e8 3e cc 22 00       	call   ffffffff8b50a4c0 <frame_candidate_91e450+0x22c070>
ffffffff8b2dd882:	48 8d 1d 87 ea ff 02 	lea    0x2ffea87(%rip),%rbx        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2dd889:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2dd88e:	e8 8d a6 19 00       	call   ffffffff8b477f20 <frame_candidate_91e450+0x199ad0>
ffffffff8b2dd893:	e9 8e fd ff ff       	jmp    ffffffff8b2dd626 <frame_candidate_91d5c0+0x66>
ffffffff8b2dd898:	e8 13 fe dd ff       	call   ffffffff8b0bd6b0 <handler_629_body-0x21ef90>
ffffffff8b2dd89d:	0f 0b                	ud2
ffffffff8b2dd89f:	90                   	nop

ffffffff8b2dd8a0 <frame_candidate_91d8a0>:
ffffffff8b2dd8a0:	55                   	push   %rbp
ffffffff8b2dd8a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2dd8a4:	41 57                	push   %r15
ffffffff8b2dd8a6:	41 56                	push   %r14
ffffffff8b2dd8a8:	41 55                	push   %r13
ffffffff8b2dd8aa:	41 54                	push   %r12
ffffffff8b2dd8ac:	53                   	push   %rbx
ffffffff8b2dd8ad:	48 83 ec 38          	sub    $0x38,%rsp
ffffffff8b2dd8b1:	4c 8d 3d 58 ea ff 02 	lea    0x2ffea58(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2dd8b8:	89 4d b0             	mov    %ecx,-0x50(%rbp)
ffffffff8b2dd8bb:	4c 8b 65 10          	mov    0x10(%rbp),%r12
ffffffff8b2dd8bf:	49 8b 07             	mov    (%r15),%rax
ffffffff8b2dd8c2:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b2dd8c6:	4d 85 e4             	test   %r12,%r12
ffffffff8b2dd8c9:	74 5d                	je     ffffffff8b2dd928 <frame_candidate_91d8a0+0x88>
ffffffff8b2dd8cb:	49 c7 04 24 00 00 00 	movq   $0x0,(%r12)
ffffffff8b2dd8d2:	00 
ffffffff8b2dd8d3:	ff 05 7b bd 0a 03    	incl   0x30abd7b(%rip)        # ffffffff8e389654 <frame_candidate_91e450+0x30ab204>
ffffffff8b2dd8d9:	41 89 d6             	mov    %edx,%r14d
ffffffff8b2dd8dc:	48 8b 15 b5 bd 0a 03 	mov    0x30abdb5(%rip),%rdx        # ffffffff8e389698 <frame_candidate_91e450+0x30ab248>
ffffffff8b2dd8e3:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dd8e6:	74 4a                	je     ffffffff8b2dd932 <frame_candidate_91d8a0+0x92>
ffffffff8b2dd8e8:	44 89 45 b4          	mov    %r8d,-0x4c(%rbp)
ffffffff8b2dd8ec:	4c 89 4d b8          	mov    %r9,-0x48(%rbp)
ffffffff8b2dd8f0:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2dd8f3:	74 7c                	je     ffffffff8b2dd971 <frame_candidate_91d8a0+0xd1>
ffffffff8b2dd8f5:	4c 8b 6f 10          	mov    0x10(%rdi),%r13
ffffffff8b2dd8f9:	4d 85 ed             	test   %r13,%r13
ffffffff8b2dd8fc:	74 73                	je     ffffffff8b2dd971 <frame_candidate_91d8a0+0xd1>
ffffffff8b2dd8fe:	41 80 7d 08 0f       	cmpb   $0xf,0x8(%r13)
ffffffff8b2dd903:	75 37                	jne    ffffffff8b2dd93c <frame_candidate_91d8a0+0x9c>
ffffffff8b2dd905:	f6 45 b4 10          	testb  $0x10,-0x4c(%rbp)
ffffffff8b2dd909:	75 63                	jne    ffffffff8b2dd96e <frame_candidate_91d8a0+0xce>
ffffffff8b2dd90b:	41 0f b6 7d 09       	movzbl 0x9(%r13),%edi
ffffffff8b2dd910:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b2dd913:	e8 98 95 1a 00       	call   ffffffff8b486eb0 <frame_candidate_91e450+0x1a8a60>
ffffffff8b2dd918:	4c 89 ea             	mov    %r13,%rdx
ffffffff8b2dd91b:	85 c0                	test   %eax,%eax
ffffffff8b2dd91d:	0f 84 ab 02 00 00    	je     ffffffff8b2ddbce <frame_candidate_91d8a0+0x32e>
ffffffff8b2dd923:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dd926:	eb 49                	jmp    ffffffff8b2dd971 <frame_candidate_91d8a0+0xd1>
ffffffff8b2dd928:	b8 01 10 00 00       	mov    $0x1001,%eax
ffffffff8b2dd92d:	e9 80 02 00 00       	jmp    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2dd932:	b8 03 00 00 00       	mov    $0x3,%eax
ffffffff8b2dd937:	e9 76 02 00 00       	jmp    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2dd93c:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b2dd93f:	e8 8c c3 ba ff       	call   ffffffff8ae89cd0 <handler_629_body-0x452970>
ffffffff8b2dd944:	49 89 c0             	mov    %rax,%r8
ffffffff8b2dd947:	48 8d 3d da fb ef 00 	lea    0xeffbda(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2dd94e:	48 8d 15 4a b7 9b 00 	lea    0x9bb74a(%rip),%rdx        # ffffffff8bc9909f <frame_candidate_91e450+0x9bac4f>
ffffffff8b2dd955:	be 5d 01 00 00       	mov    $0x15d,%esi
ffffffff8b2dd95a:	4c 89 e9             	mov    %r13,%rcx
ffffffff8b2dd95d:	31 c0                	xor    %eax,%eax
ffffffff8b2dd95f:	e8 8c a0 dd ff       	call   ffffffff8b0b79f0 <handler_629_body-0x224c50>
ffffffff8b2dd964:	b8 0f 30 00 00       	mov    $0x300f,%eax
ffffffff8b2dd969:	e9 44 02 00 00       	jmp    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2dd96e:	4c 89 ea             	mov    %r13,%rdx
ffffffff8b2dd971:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2dd974:	74 22                	je     ffffffff8b2dd998 <frame_candidate_91d8a0+0xf8>
ffffffff8b2dd976:	0f b6 06             	movzbl (%rsi),%eax
ffffffff8b2dd979:	44 89 75 c0          	mov    %r14d,-0x40(%rbp)
ffffffff8b2dd97d:	3c 5c                	cmp    $0x5c,%al
ffffffff8b2dd97f:	75 2b                	jne    ffffffff8b2dd9ac <frame_candidate_91d8a0+0x10c>
ffffffff8b2dd981:	48 8b 15 10 bd 0a 03 	mov    0x30abd10(%rip),%rdx        # ffffffff8e389698 <frame_candidate_91e450+0x30ab248>
ffffffff8b2dd988:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dd98b:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
ffffffff8b2dd98f:	0f b6 46 01          	movzbl 0x1(%rsi),%eax
ffffffff8b2dd993:	48 ff c6             	inc    %rsi
ffffffff8b2dd996:	eb 49                	jmp    ffffffff8b2dd9e1 <frame_candidate_91d8a0+0x141>
ffffffff8b2dd998:	48 8b 15 f9 bc 0a 03 	mov    0x30abcf9(%rip),%rdx        # ffffffff8e389698 <frame_candidate_91e450+0x30ab248>
ffffffff8b2dd99f:	48 8b 5d b8          	mov    -0x48(%rbp),%rbx
ffffffff8b2dd9a3:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
ffffffff8b2dd9a7:	e9 c8 01 00 00       	jmp    ffffffff8b2ddb74 <frame_candidate_91d8a0+0x2d4>
ffffffff8b2dd9ac:	41 be 01 00 00 00    	mov    $0x1,%r14d
ffffffff8b2dd9b2:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
ffffffff8b2dd9b6:	3c 5e                	cmp    $0x5e,%al
ffffffff8b2dd9b8:	75 27                	jne    ffffffff8b2dd9e1 <frame_candidate_91d8a0+0x141>
ffffffff8b2dd9ba:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b2dd9bd:	0f 1f 00             	nopl   (%rax)
ffffffff8b2dd9c0:	48 8b 52 10          	mov    0x10(%rdx),%rdx
ffffffff8b2dd9c4:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
ffffffff8b2dd9c8:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dd9cb:	0f 84 14 01 00 00    	je     ffffffff8b2ddae5 <frame_candidate_91d8a0+0x245>
ffffffff8b2dd9d1:	0f b6 43 01          	movzbl 0x1(%rbx),%eax
ffffffff8b2dd9d5:	48 ff c3             	inc    %rbx
ffffffff8b2dd9d8:	3c 5e                	cmp    $0x5e,%al
ffffffff8b2dd9da:	74 e4                	je     ffffffff8b2dd9c0 <frame_candidate_91d8a0+0x120>
ffffffff8b2dd9dc:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dd9df:	eb 03                	jmp    ffffffff8b2dd9e4 <frame_candidate_91d8a0+0x144>
ffffffff8b2dd9e1:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b2dd9e4:	3c 2f                	cmp    $0x2f,%al
ffffffff8b2dd9e6:	74 33                	je     ffffffff8b2dda1b <frame_candidate_91d8a0+0x17b>
ffffffff8b2dd9e8:	0f b6 c8             	movzbl %al,%ecx
ffffffff8b2dd9eb:	83 f9 2e             	cmp    $0x2e,%ecx
ffffffff8b2dd9ee:	74 17                	je     ffffffff8b2dda07 <frame_candidate_91d8a0+0x167>
ffffffff8b2dd9f0:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b2dd9f5:	85 c9                	test   %ecx,%ecx
ffffffff8b2dd9f7:	75 19                	jne    ffffffff8b2dda12 <frame_candidate_91d8a0+0x172>
ffffffff8b2dd9f9:	44 0f b6 72 09       	movzbl 0x9(%rdx),%r14d
ffffffff8b2dd9fe:	48 8b 5d b8          	mov    -0x48(%rbp),%rbx
ffffffff8b2dda02:	e9 6d 01 00 00       	jmp    ffffffff8b2ddb74 <frame_candidate_91d8a0+0x2d4>
ffffffff8b2dda07:	48 ff c3             	inc    %rbx
ffffffff8b2dda0a:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dda0d:	b8 02 00 00 00       	mov    $0x2,%eax
ffffffff8b2dda12:	85 c0                	test   %eax,%eax
ffffffff8b2dda14:	75 18                	jne    ffffffff8b2dda2e <frame_candidate_91d8a0+0x18e>
ffffffff8b2dda16:	e9 51 01 00 00       	jmp    ffffffff8b2ddb6c <frame_candidate_91d8a0+0x2cc>
ffffffff8b2dda1b:	0f b6 43 01          	movzbl 0x1(%rbx),%eax
ffffffff8b2dda1f:	48 83 c3 02          	add    $0x2,%rbx
ffffffff8b2dda23:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2dda26:	85 c0                	test   %eax,%eax
ffffffff8b2dda28:	0f 84 3e 01 00 00    	je     ffffffff8b2ddb6c <frame_candidate_91d8a0+0x2cc>
ffffffff8b2dda2e:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dda31:	0f 84 35 01 00 00    	je     ffffffff8b2ddb6c <frame_candidate_91d8a0+0x2cc>
ffffffff8b2dda37:	8b 4d b4             	mov    -0x4c(%rbp),%ecx
ffffffff8b2dda3a:	41 81 ce 88 00 00 00 	or     $0x88,%r14d
ffffffff8b2dda41:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2dda44:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b2dda47:	49 8d 44 24 ff       	lea    -0x1(%r12),%rax
ffffffff8b2dda4c:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
ffffffff8b2dda50:	41 89 cd             	mov    %ecx,%r13d
ffffffff8b2dda53:	41 21 ce             	and    %ecx,%r14d
ffffffff8b2dda56:	41 81 e5 76 ff ff ff 	and    $0xffffff76,%r13d
ffffffff8b2dda5d:	eb 0a                	jmp    ffffffff8b2dda69 <frame_candidate_91d8a0+0x1c9>
ffffffff8b2dda5f:	90                   	nop
ffffffff8b2dda60:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2dda63:	0f 84 f6 00 00 00    	je     ffffffff8b2ddb5f <frame_candidate_91d8a0+0x2bf>
ffffffff8b2dda69:	44 39 7d a8          	cmp    %r15d,-0x58(%rbp)
ffffffff8b2dda6d:	41 b8 00 00 00 00    	mov    $0x0,%r8d
ffffffff8b2dda73:	42 8b 3c bb          	mov    (%rbx,%r15,4),%edi
ffffffff8b2dda77:	44 89 e8             	mov    %r13d,%eax
ffffffff8b2dda7a:	41 bd 00 00 00 00    	mov    $0x0,%r13d
ffffffff8b2dda80:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
ffffffff8b2dda84:	8b 4d b0             	mov    -0x50(%rbp),%ecx
ffffffff8b2dda87:	89 7d c4             	mov    %edi,-0x3c(%rbp)
ffffffff8b2dda8a:	44 0f 44 45 c0       	cmove  -0x40(%rbp),%r8d
ffffffff8b2dda8f:	45 0f 44 ee          	cmove  %r14d,%r13d
ffffffff8b2dda93:	41 09 c5             	or     %eax,%r13d
ffffffff8b2dda96:	48 8d 45 c8          	lea    -0x38(%rbp),%rax
ffffffff8b2dda9a:	45 89 e9             	mov    %r13d,%r9d
ffffffff8b2dda9d:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b2ddaa1:	e8 8a a7 09 00       	call   ffffffff8b378230 <frame_candidate_91e450+0x99de0>
ffffffff8b2ddaa6:	85 c0                	test   %eax,%eax
ffffffff8b2ddaa8:	75 62                	jne    ffffffff8b2ddb0c <frame_candidate_91d8a0+0x26c>
ffffffff8b2ddaaa:	49 ff c7             	inc    %r15
ffffffff8b2ddaad:	45 39 fc             	cmp    %r15d,%r12d
ffffffff8b2ddab0:	74 71                	je     ffffffff8b2ddb23 <frame_candidate_91d8a0+0x283>
ffffffff8b2ddab2:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b2ddab6:	80 7a 09 15          	cmpb   $0x15,0x9(%rdx)
ffffffff8b2ddaba:	75 a4                	jne    ffffffff8b2dda60 <frame_candidate_91d8a0+0x1c0>
ffffffff8b2ddabc:	48 8b 02             	mov    (%rdx),%rax
ffffffff8b2ddabf:	48 85 c0             	test   %rax,%rax
ffffffff8b2ddac2:	0f 84 47 01 00 00    	je     ffffffff8b2ddc0f <frame_candidate_91d8a0+0x36f>
ffffffff8b2ddac8:	0f b6 78 09          	movzbl 0x9(%rax),%edi
ffffffff8b2ddacc:	e8 df 93 1a 00       	call   ffffffff8b486eb0 <frame_candidate_91e450+0x1a8a60>
ffffffff8b2ddad1:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b2ddad5:	85 c0                	test   %eax,%eax
ffffffff8b2ddad7:	74 87                	je     ffffffff8b2dda60 <frame_candidate_91d8a0+0x1c0>
ffffffff8b2ddad9:	48 8b 12             	mov    (%rdx),%rdx
ffffffff8b2ddadc:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
ffffffff8b2ddae0:	e9 7b ff ff ff       	jmp    ffffffff8b2dda60 <frame_candidate_91d8a0+0x1c0>
ffffffff8b2ddae5:	48 89 f1             	mov    %rsi,%rcx
ffffffff8b2ddae8:	48 8d 3d 39 fa ef 00 	lea    0xeffa39(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2ddaef:	48 8d 15 a0 9a 9d 00 	lea    0x9d9aa0(%rip),%rdx        # ffffffff8bcb7596 <frame_candidate_91e450+0x9d9146>
ffffffff8b2ddaf6:	be c2 01 00 00       	mov    $0x1c2,%esi
ffffffff8b2ddafb:	31 c0                	xor    %eax,%eax
ffffffff8b2ddafd:	e8 ee 9e dd ff       	call   ffffffff8b0b79f0 <handler_629_body-0x224c50>
ffffffff8b2ddb02:	b8 05 00 00 00       	mov    $0x5,%eax
ffffffff8b2ddb07:	e9 a6 00 00 00       	jmp    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2ddb0c:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
ffffffff8b2ddb10:	48 8b 55 10          	mov    0x10(%rbp),%rdx
ffffffff8b2ddb14:	4c 8d 3d f5 e7 ff 02 	lea    0x2ffe7f5(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2ddb1b:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2ddb1e:	e9 8f 00 00 00       	jmp    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2ddb23:	44 8b 75 c0          	mov    -0x40(%rbp),%r14d
ffffffff8b2ddb27:	41 83 fe 1b          	cmp    $0x1b,%r14d
ffffffff8b2ddb2b:	0f 87 ec 00 00 00    	ja     ffffffff8b2ddc1d <frame_candidate_91d8a0+0x37d>
ffffffff8b2ddb31:	b8 01 00 60 08       	mov    $0x8600001,%eax
ffffffff8b2ddb36:	44 0f a3 f0          	bt     %r14d,%eax
ffffffff8b2ddb3a:	0f 83 dd 00 00 00    	jae    ffffffff8b2ddc1d <frame_candidate_91d8a0+0x37d>
ffffffff8b2ddb40:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b2ddb44:	4c 8d 3d c5 e7 ff 02 	lea    0x2ffe7c5(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2ddb4b:	48 8b 5d b8          	mov    -0x48(%rbp),%rbx
ffffffff8b2ddb4f:	45 85 f6             	test   %r14d,%r14d
ffffffff8b2ddb52:	75 05                	jne    ffffffff8b2ddb59 <frame_candidate_91d8a0+0x2b9>
ffffffff8b2ddb54:	44 0f b6 72 09       	movzbl 0x9(%rdx),%r14d
ffffffff8b2ddb59:	4c 8b 65 10          	mov    0x10(%rbp),%r12
ffffffff8b2ddb5d:	eb 15                	jmp    ffffffff8b2ddb74 <frame_candidate_91d8a0+0x2d4>
ffffffff8b2ddb5f:	4c 8d 3d aa e7 ff 02 	lea    0x2ffe7aa(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2ddb66:	4c 8b 65 10          	mov    0x10(%rbp),%r12
ffffffff8b2ddb6a:	31 d2                	xor    %edx,%edx
ffffffff8b2ddb6c:	48 8b 5d b8          	mov    -0x48(%rbp),%rbx
ffffffff8b2ddb70:	44 8b 75 c0          	mov    -0x40(%rbp),%r14d
ffffffff8b2ddb74:	8b 4d b4             	mov    -0x4c(%rbp),%ecx
ffffffff8b2ddb77:	83 e1 02             	and    $0x2,%ecx
ffffffff8b2ddb7a:	d1 e9                	shr    $1,%ecx
ffffffff8b2ddb7c:	48 85 db             	test   %rbx,%rbx
ffffffff8b2ddb7f:	0f 94 c0             	sete   %al
ffffffff8b2ddb82:	08 c8                	or     %cl,%al
ffffffff8b2ddb84:	75 26                	jne    ffffffff8b2ddbac <frame_candidate_91d8a0+0x30c>
ffffffff8b2ddb86:	44 89 f7             	mov    %r14d,%edi
ffffffff8b2ddb89:	e8 22 93 1a 00       	call   ffffffff8b486eb0 <frame_candidate_91e450+0x1a8a60>
ffffffff8b2ddb8e:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b2ddb92:	85 c0                	test   %eax,%eax
ffffffff8b2ddb94:	74 16                	je     ffffffff8b2ddbac <frame_candidate_91d8a0+0x30c>
ffffffff8b2ddb96:	48 89 d7             	mov    %rdx,%rdi
ffffffff8b2ddb99:	44 89 f6             	mov    %r14d,%esi
ffffffff8b2ddb9c:	48 89 da             	mov    %rbx,%rdx
ffffffff8b2ddb9f:	e8 ac 20 ee ff       	call   ffffffff8b1bfc50 <handler_629_body-0x11c9f0>
ffffffff8b2ddba4:	85 c0                	test   %eax,%eax
ffffffff8b2ddba6:	75 0a                	jne    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2ddba8:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b2ddbac:	31 c0                	xor    %eax,%eax
ffffffff8b2ddbae:	49 89 14 24          	mov    %rdx,(%r12)
ffffffff8b2ddbb2:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b2ddbb5:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8b2ddbb9:	0f 85 b2 00 00 00    	jne    ffffffff8b2ddc71 <frame_candidate_91d8a0+0x3d1>
ffffffff8b2ddbbf:	48 83 c4 38          	add    $0x38,%rsp
ffffffff8b2ddbc3:	5b                   	pop    %rbx
ffffffff8b2ddbc4:	41 5c                	pop    %r12
ffffffff8b2ddbc6:	41 5d                	pop    %r13
ffffffff8b2ddbc8:	41 5e                	pop    %r14
ffffffff8b2ddbca:	41 5f                	pop    %r15
ffffffff8b2ddbcc:	5d                   	pop    %rbp
ffffffff8b2ddbcd:	c3                   	ret
ffffffff8b2ddbce:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2ddbd1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2ddbd8:	0f 1f 84 00 00 00 00 
ffffffff8b2ddbdf:	00 
ffffffff8b2ddbe0:	80 7a 09 00          	cmpb   $0x0,0x9(%rdx)
ffffffff8b2ddbe4:	0f 84 87 fd ff ff    	je     ffffffff8b2dd971 <frame_candidate_91d8a0+0xd1>
ffffffff8b2ddbea:	48 8b 52 10          	mov    0x10(%rdx),%rdx
ffffffff8b2ddbee:	45 89 f5             	mov    %r14d,%r13d
ffffffff8b2ddbf1:	0f b6 7a 09          	movzbl 0x9(%rdx),%edi
ffffffff8b2ddbf5:	49 89 d6             	mov    %rdx,%r14
ffffffff8b2ddbf8:	e8 b3 92 1a 00       	call   ffffffff8b486eb0 <frame_candidate_91e450+0x1a8a60>
ffffffff8b2ddbfd:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b2ddc00:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2ddc03:	45 89 ee             	mov    %r13d,%r14d
ffffffff8b2ddc06:	85 c0                	test   %eax,%eax
ffffffff8b2ddc08:	74 d6                	je     ffffffff8b2ddbe0 <frame_candidate_91d8a0+0x340>
ffffffff8b2ddc0a:	e9 62 fd ff ff       	jmp    ffffffff8b2dd971 <frame_candidate_91d8a0+0xd1>
ffffffff8b2ddc0f:	4c 8d 3d fa e6 ff 02 	lea    0x2ffe6fa(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2ddc16:	b8 06 00 00 00       	mov    $0x6,%eax
ffffffff8b2ddc1b:	eb 95                	jmp    ffffffff8b2ddbb2 <frame_candidate_91d8a0+0x312>
ffffffff8b2ddc1d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b2ddc21:	0f b6 78 09          	movzbl 0x9(%rax),%edi
ffffffff8b2ddc25:	85 ff                	test   %edi,%edi
ffffffff8b2ddc27:	0f 94 c0             	sete   %al
ffffffff8b2ddc2a:	41 39 fe             	cmp    %edi,%r14d
ffffffff8b2ddc2d:	0f 94 c1             	sete   %cl
ffffffff8b2ddc30:	08 c1                	or     %al,%cl
ffffffff8b2ddc32:	0f 85 08 ff ff ff    	jne    ffffffff8b2ddb40 <frame_candidate_91d8a0+0x2a0>
ffffffff8b2ddc38:	e8 c3 bf ba ff       	call   ffffffff8ae89c00 <handler_629_body-0x452a40>
ffffffff8b2ddc3d:	44 89 f7             	mov    %r14d,%edi
ffffffff8b2ddc40:	49 89 c4             	mov    %rax,%r12
ffffffff8b2ddc43:	e8 b8 bf ba ff       	call   ffffffff8ae89c00 <handler_629_body-0x452a40>
ffffffff8b2ddc48:	49 89 c1             	mov    %rax,%r9
ffffffff8b2ddc4b:	48 8d 3d d6 f8 ef 00 	lea    0xeff8d6(%rip),%rdi        # ffffffff8c1dd528 <frame_candidate_91e450+0xeff0d8>
ffffffff8b2ddc52:	48 8d 15 76 b6 99 00 	lea    0x99b676(%rip),%rdx        # ffffffff8bc792cf <frame_candidate_91e450+0x99ae7f>
ffffffff8b2ddc59:	48 8d 4d c4          	lea    -0x3c(%rbp),%rcx
ffffffff8b2ddc5d:	be 94 02 00 00       	mov    $0x294,%esi
ffffffff8b2ddc62:	4d 89 e0             	mov    %r12,%r8
ffffffff8b2ddc65:	31 c0                	xor    %eax,%eax
ffffffff8b2ddc67:	e8 e4 9e dd ff       	call   ffffffff8b0b7b50 <handler_629_body-0x224af0>
ffffffff8b2ddc6c:	e9 cf fe ff ff       	jmp    ffffffff8b2ddb40 <frame_candidate_91d8a0+0x2a0>
ffffffff8b2ddc71:	e8 3a fa dd ff       	call   ffffffff8b0bd6b0 <handler_629_body-0x21ef90>
ffffffff8b2ddc76:	0f 0b                	ud2
ffffffff8b2ddc78:	90                   	nop
ffffffff8b2ddc79:	90                   	nop
ffffffff8b2ddc7a:	90                   	nop
ffffffff8b2ddc7b:	90                   	nop
ffffffff8b2ddc7c:	90                   	nop
ffffffff8b2ddc7d:	90                   	nop
ffffffff8b2ddc7e:	90                   	nop
ffffffff8b2ddc7f:	90                   	nop

ffffffff8b2ddc80 <frame_candidate_91dc80>:
ffffffff8b2ddc80:	55                   	push   %rbp
ffffffff8b2ddc81:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2ddc84:	41 57                	push   %r15
ffffffff8b2ddc86:	41 56                	push   %r14
ffffffff8b2ddc88:	41 55                	push   %r13
ffffffff8b2ddc8a:	41 54                	push   %r12
ffffffff8b2ddc8c:	53                   	push   %rbx
ffffffff8b2ddc8d:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8b2ddc91:	31 c0                	xor    %eax,%eax
ffffffff8b2ddc93:	48 89 7d b0          	mov    %rdi,-0x50(%rbp)
ffffffff8b2ddc97:	e8 14 30 17 00       	call   ffffffff8b450cb0 <frame_candidate_91e450+0x172860>
ffffffff8b2ddc9c:	89 45 b8             	mov    %eax,-0x48(%rbp)
ffffffff8b2ddc9f:	31 c0                	xor    %eax,%eax
ffffffff8b2ddca1:	e8 8a 2e 17 00       	call   ffffffff8b450b30 <frame_candidate_91e450+0x1726e0>
ffffffff8b2ddca6:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2ddca9:	31 c0                	xor    %eax,%eax
ffffffff8b2ddcab:	e8 00 2f 17 00       	call   ffffffff8b450bb0 <frame_candidate_91e450+0x172760>
ffffffff8b2ddcb0:	bf d7 00 00 00       	mov    $0xd7,%edi
ffffffff8b2ddcb5:	89 45 bc             	mov    %eax,-0x44(%rbp)
ffffffff8b2ddcb8:	e8 33 2f 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddcbd:	bf 10 01 00 00       	mov    $0x110,%edi
ffffffff8b2ddcc2:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2ddcc5:	e8 26 2f 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddcca:	bf 04 00 00 00       	mov    $0x4,%edi
ffffffff8b2ddccf:	89 45 c0             	mov    %eax,-0x40(%rbp)
ffffffff8b2ddcd2:	e8 19 2f 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddcd7:	bf 9e 00 00 00       	mov    $0x9e,%edi
ffffffff8b2ddcdc:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2ddcdf:	e8 0c 2f 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddce4:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b2ddce9:	89 45 c4             	mov    %eax,-0x3c(%rbp)
ffffffff8b2ddcec:	e8 ff 2e 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddcf1:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2ddcf6:	89 45 c8             	mov    %eax,-0x38(%rbp)
ffffffff8b2ddcf9:	e8 f2 2e 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddcfe:	bf 42 00 00 00       	mov    $0x42,%edi
ffffffff8b2ddd03:	41 89 c6             	mov    %eax,%r14d
ffffffff8b2ddd06:	e8 e5 2e 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddd0b:	bf cb 00 00 00       	mov    $0xcb,%edi
ffffffff8b2ddd10:	89 45 cc             	mov    %eax,-0x34(%rbp)
ffffffff8b2ddd13:	e8 d8 2e 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddd18:	89 45 d0             	mov    %eax,-0x30(%rbp)
ffffffff8b2ddd1b:	31 c0                	xor    %eax,%eax
ffffffff8b2ddd1d:	e8 fe 2e 17 00       	call   ffffffff8b450c20 <frame_candidate_91e450+0x1727d0>
ffffffff8b2ddd22:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b2ddd25:	31 c0                	xor    %eax,%eax
ffffffff8b2ddd27:	e8 04 2e 17 00       	call   ffffffff8b450b30 <frame_candidate_91e450+0x1726e0>
ffffffff8b2ddd2c:	89 c3                	mov    %eax,%ebx
ffffffff8b2ddd2e:	31 c0                	xor    %eax,%eax
ffffffff8b2ddd30:	e8 6b 2f 17 00       	call   ffffffff8b450ca0 <frame_candidate_91e450+0x172850>
ffffffff8b2ddd35:	44 03 6d c0          	add    -0x40(%rbp),%r13d
ffffffff8b2ddd39:	44 03 75 c8          	add    -0x38(%rbp),%r14d
ffffffff8b2ddd3d:	8b 75 b8             	mov    -0x48(%rbp),%esi
ffffffff8b2ddd40:	44 03 65 bc          	add    -0x44(%rbp),%r12d
ffffffff8b2ddd44:	03 5d d4             	add    -0x2c(%rbp),%ebx
ffffffff8b2ddd47:	31 d2                	xor    %edx,%edx
ffffffff8b2ddd49:	44 03 75 cc          	add    -0x34(%rbp),%r14d
ffffffff8b2ddd4d:	44 03 6d c4          	add    -0x3c(%rbp),%r13d
ffffffff8b2ddd51:	44 03 75 d0          	add    -0x30(%rbp),%r14d
ffffffff8b2ddd55:	41 01 f7             	add    %esi,%r15d
ffffffff8b2ddd58:	45 01 fc             	add    %r15d,%r12d
ffffffff8b2ddd5b:	45 01 e5             	add    %r12d,%r13d
ffffffff8b2ddd5e:	45 01 ee             	add    %r13d,%r14d
ffffffff8b2ddd61:	44 01 f3             	add    %r14d,%ebx
ffffffff8b2ddd64:	8d 4c 18 ff          	lea    -0x1(%rax,%rbx,1),%ecx
ffffffff8b2ddd68:	89 c8                	mov    %ecx,%eax
ffffffff8b2ddd6a:	f7 f6                	div    %esi
ffffffff8b2ddd6c:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
ffffffff8b2ddd70:	29 d1                	sub    %edx,%ecx
ffffffff8b2ddd72:	c1 e1 02             	shl    $0x2,%ecx
ffffffff8b2ddd75:	89 08                	mov    %ecx,(%rax)
ffffffff8b2ddd77:	31 c0                	xor    %eax,%eax
ffffffff8b2ddd79:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8b2ddd7d:	5b                   	pop    %rbx
ffffffff8b2ddd7e:	41 5c                	pop    %r12
ffffffff8b2ddd80:	41 5d                	pop    %r13
ffffffff8b2ddd82:	41 5e                	pop    %r14
ffffffff8b2ddd84:	41 5f                	pop    %r15
ffffffff8b2ddd86:	5d                   	pop    %rbp
ffffffff8b2ddd87:	c3                   	ret
ffffffff8b2ddd88:	90                   	nop
ffffffff8b2ddd89:	90                   	nop
ffffffff8b2ddd8a:	90                   	nop
ffffffff8b2ddd8b:	90                   	nop
ffffffff8b2ddd8c:	90                   	nop
ffffffff8b2ddd8d:	90                   	nop
ffffffff8b2ddd8e:	90                   	nop
ffffffff8b2ddd8f:	90                   	nop

ffffffff8b2ddd90 <frame_candidate_91dd90>:
ffffffff8b2ddd90:	55                   	push   %rbp
ffffffff8b2ddd91:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2ddd94:	41 57                	push   %r15
ffffffff8b2ddd96:	41 56                	push   %r14
ffffffff8b2ddd98:	41 55                	push   %r13
ffffffff8b2ddd9a:	41 54                	push   %r12
ffffffff8b2ddd9c:	53                   	push   %rbx
ffffffff8b2ddd9d:	50                   	push   %rax
ffffffff8b2ddd9e:	31 c0                	xor    %eax,%eax
ffffffff8b2ddda0:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b2ddda3:	41 89 ff             	mov    %edi,%r15d
ffffffff8b2ddda6:	e8 05 2f 17 00       	call   ffffffff8b450cb0 <frame_candidate_91e450+0x172860>
ffffffff8b2dddab:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b2dddb0:	48 89 de             	mov    %rbx,%rsi
ffffffff8b2dddb3:	41 89 c6             	mov    %eax,%r14d
ffffffff8b2dddb6:	e8 f5 2c 17 00       	call   ffffffff8b450ab0 <frame_candidate_91e450+0x172660>
ffffffff8b2dddbb:	31 c0                	xor    %eax,%eax
ffffffff8b2dddbd:	e8 6e 2d 17 00       	call   ffffffff8b450b30 <frame_candidate_91e450+0x1726e0>
ffffffff8b2dddc2:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2dddc5:	89 c0                	mov    %eax,%eax
ffffffff8b2dddc7:	48 8d 3c 83          	lea    (%rbx,%rax,4),%rdi
ffffffff8b2dddcb:	e8 70 2d 17 00       	call   ffffffff8b450b40 <frame_candidate_91e450+0x1726f0>
ffffffff8b2dddd0:	31 c0                	xor    %eax,%eax
ffffffff8b2dddd2:	e8 d9 2d 17 00       	call   ffffffff8b450bb0 <frame_candidate_91e450+0x172760>
ffffffff8b2dddd7:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2dddda:	48 8d 35 5f f7 ef 00 	lea    0xeff75f(%rip),%rsi        # ffffffff8c1dd540 <frame_candidate_91e450+0xeff0f0>
ffffffff8b2ddde1:	bf 00 a0 00 00       	mov    $0xa000,%edi
ffffffff8b2ddde6:	ba d7 00 00 00       	mov    $0xd7,%edx
ffffffff8b2dddeb:	45 01 e5             	add    %r12d,%r13d
ffffffff8b2dddee:	4a 8d 0c ab          	lea    (%rbx,%r13,4),%rcx
ffffffff8b2dddf2:	e8 c9 2d 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2dddf7:	bf d7 00 00 00       	mov    $0xd7,%edi
ffffffff8b2dddfc:	e8 ef 2d 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2dde01:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2dde04:	48 8d 35 35 fd ef 00 	lea    0xeffd35(%rip),%rsi        # ffffffff8c1ddb40 <frame_candidate_91e450+0xeff6f0>
ffffffff8b2dde0b:	bf d8 a0 00 00       	mov    $0xa0d8,%edi
ffffffff8b2dde10:	ba 10 01 00 00       	mov    $0x110,%edx
ffffffff8b2dde15:	45 01 ec             	add    %r13d,%r12d
ffffffff8b2dde18:	4a 8d 0c a3          	lea    (%rbx,%r12,4),%rcx
ffffffff8b2dde1c:	e8 9f 2d 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2dde21:	bf 10 01 00 00       	mov    $0x110,%edi
ffffffff8b2dde26:	e8 c5 2d 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2dde2b:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2dde2e:	48 8d 35 6b fa ef 00 	lea    0xeffa6b(%rip),%rsi        # ffffffff8c1dd8a0 <frame_candidate_91e450+0xeff450>
ffffffff8b2dde35:	bf f5 a1 00 00       	mov    $0xa1f5,%edi
ffffffff8b2dde3a:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b2dde3f:	45 01 e5             	add    %r12d,%r13d
ffffffff8b2dde42:	4a 8d 0c ab          	lea    (%rbx,%r13,4),%rcx
ffffffff8b2dde46:	e8 75 2d 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2dde4b:	bf 04 00 00 00       	mov    $0x4,%edi
ffffffff8b2dde50:	e8 9b 2d 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2dde55:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2dde58:	48 8d 35 51 fa ef 00 	lea    0xeffa51(%rip),%rsi        # ffffffff8c1dd8b0 <frame_candidate_91e450+0xeff460>
ffffffff8b2dde5f:	bf ff a1 00 00       	mov    $0xa1ff,%edi
ffffffff8b2dde64:	ba 9e 00 00 00       	mov    $0x9e,%edx
ffffffff8b2dde69:	45 01 ec             	add    %r13d,%r12d
ffffffff8b2dde6c:	4a 8d 0c a3          	lea    (%rbx,%r12,4),%rcx
ffffffff8b2dde70:	e8 4b 2d 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2dde75:	bf 9e 00 00 00       	mov    $0x9e,%edi
ffffffff8b2dde7a:	e8 71 2d 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2dde7f:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2dde82:	48 8d 35 9f fc ef 00 	lea    0xeffc9f(%rip),%rsi        # ffffffff8c1ddb28 <frame_candidate_91e450+0xeff6d8>
ffffffff8b2dde89:	bf a0 a2 00 00       	mov    $0xa2a0,%edi
ffffffff8b2dde8e:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b2dde93:	45 01 e5             	add    %r12d,%r13d
ffffffff8b2dde96:	4a 8d 0c ab          	lea    (%rbx,%r13,4),%rcx
ffffffff8b2dde9a:	e8 21 2d 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2dde9f:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b2ddea4:	e8 47 2d 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddea9:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2ddeac:	48 8d 35 7d fc ef 00 	lea    0xeffc7d(%rip),%rsi        # ffffffff8c1ddb30 <frame_candidate_91e450+0xeff6e0>
ffffffff8b2ddeb3:	bf a3 a2 00 00       	mov    $0xa2a3,%edi
ffffffff8b2ddeb8:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8b2ddebd:	45 01 ec             	add    %r13d,%r12d
ffffffff8b2ddec0:	4a 8d 0c a3          	lea    (%rbx,%r12,4),%rcx
ffffffff8b2ddec4:	e8 f7 2c 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2ddec9:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2ddece:	e8 1d 2d 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2dded3:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2dded6:	48 8d 35 a3 00 f0 00 	lea    0xf000a3(%rip),%rsi        # ffffffff8c1ddf80 <frame_candidate_91e450+0xeffb30>
ffffffff8b2ddedd:	bf a5 a2 00 00       	mov    $0xa2a5,%edi
ffffffff8b2ddee2:	ba 42 00 00 00       	mov    $0x42,%edx
ffffffff8b2ddee7:	45 01 e5             	add    %r12d,%r13d
ffffffff8b2ddeea:	4a 8d 0c ab          	lea    (%rbx,%r13,4),%rcx
ffffffff8b2ddeee:	e8 cd 2c 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2ddef3:	bf 42 00 00 00       	mov    $0x42,%edi
ffffffff8b2ddef8:	e8 f3 2c 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddefd:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2ddf00:	48 8d 35 89 01 f0 00 	lea    0xf00189(%rip),%rsi        # ffffffff8c1de090 <frame_candidate_91e450+0xeffc40>
ffffffff8b2ddf07:	bf f5 a2 00 00       	mov    $0xa2f5,%edi
ffffffff8b2ddf0c:	ba cb 00 00 00       	mov    $0xcb,%edx
ffffffff8b2ddf11:	45 01 ec             	add    %r13d,%r12d
ffffffff8b2ddf14:	4a 8d 0c a3          	lea    (%rbx,%r12,4),%rcx
ffffffff8b2ddf18:	e8 a3 2c 17 00       	call   ffffffff8b450bc0 <frame_candidate_91e450+0x172770>
ffffffff8b2ddf1d:	bf cb 00 00 00       	mov    $0xcb,%edi
ffffffff8b2ddf22:	e8 c9 2c 17 00       	call   ffffffff8b450bf0 <frame_candidate_91e450+0x1727a0>
ffffffff8b2ddf27:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2ddf2a:	bf d7 a0 00 00       	mov    $0xa0d7,%edi
ffffffff8b2ddf2f:	44 89 fe             	mov    %r15d,%esi
ffffffff8b2ddf32:	45 01 e5             	add    %r12d,%r13d
ffffffff8b2ddf35:	4a 8d 14 ab          	lea    (%rbx,%r13,4),%rdx
ffffffff8b2ddf39:	e8 c2 2c 17 00       	call   ffffffff8b450c00 <frame_candidate_91e450+0x1727b0>
ffffffff8b2ddf3e:	31 c0                	xor    %eax,%eax
ffffffff8b2ddf40:	e8 db 2c 17 00       	call   ffffffff8b450c20 <frame_candidate_91e450+0x1727d0>
ffffffff8b2ddf45:	41 89 c7             	mov    %eax,%r15d
ffffffff8b2ddf48:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b2ddf4d:	45 01 ef             	add    %r13d,%r15d
ffffffff8b2ddf50:	4a 8d 34 bb          	lea    (%rbx,%r15,4),%rsi
ffffffff8b2ddf54:	e8 57 2b 17 00       	call   ffffffff8b450ab0 <frame_candidate_91e450+0x172660>
ffffffff8b2ddf59:	31 c0                	xor    %eax,%eax
ffffffff8b2ddf5b:	e8 d0 2b 17 00       	call   ffffffff8b450b30 <frame_candidate_91e450+0x1726e0>
ffffffff8b2ddf60:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2ddf63:	45 01 fc             	add    %r15d,%r12d
ffffffff8b2ddf66:	4a 8d 3c a3          	lea    (%rbx,%r12,4),%rdi
ffffffff8b2ddf6a:	e8 c1 2c 17 00       	call   ffffffff8b450c30 <frame_candidate_91e450+0x1727e0>
ffffffff8b2ddf6f:	31 c0                	xor    %eax,%eax
ffffffff8b2ddf71:	e8 2a 2d 17 00       	call   ffffffff8b450ca0 <frame_candidate_91e450+0x172850>
ffffffff8b2ddf76:	89 c1                	mov    %eax,%ecx
ffffffff8b2ddf78:	31 d2                	xor    %edx,%edx
ffffffff8b2ddf7a:	44 01 e1             	add    %r12d,%ecx
ffffffff8b2ddf7d:	89 c8                	mov    %ecx,%eax
ffffffff8b2ddf7f:	41 f7 f6             	div    %r14d
ffffffff8b2ddf82:	85 d2                	test   %edx,%edx
ffffffff8b2ddf84:	74 1b                	je     ffffffff8b2ddfa1 <frame_candidate_91dd90+0x211>
ffffffff8b2ddf86:	41 29 d6             	sub    %edx,%r14d
ffffffff8b2ddf89:	89 c8                	mov    %ecx,%eax
ffffffff8b2ddf8b:	be 01 40 00 00       	mov    $0x4001,%esi
ffffffff8b2ddf90:	41 83 fe 01          	cmp    $0x1,%r14d
ffffffff8b2ddf94:	48 8d 3c 83          	lea    (%rbx,%rax,4),%rdi
ffffffff8b2ddf98:	41 0f 45 f6          	cmovne %r14d,%esi
ffffffff8b2ddf9c:	e8 1f 2d 17 00       	call   ffffffff8b450cc0 <frame_candidate_91e450+0x172870>
ffffffff8b2ddfa1:	31 c0                	xor    %eax,%eax
ffffffff8b2ddfa3:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2ddfa7:	5b                   	pop    %rbx
ffffffff8b2ddfa8:	41 5c                	pop    %r12
ffffffff8b2ddfaa:	41 5d                	pop    %r13
ffffffff8b2ddfac:	41 5e                	pop    %r14
ffffffff8b2ddfae:	41 5f                	pop    %r15
ffffffff8b2ddfb0:	5d                   	pop    %rbp
ffffffff8b2ddfb1:	c3                   	ret
ffffffff8b2ddfb2:	90                   	nop
ffffffff8b2ddfb3:	90                   	nop
ffffffff8b2ddfb4:	90                   	nop
ffffffff8b2ddfb5:	90                   	nop
ffffffff8b2ddfb6:	90                   	nop
ffffffff8b2ddfb7:	90                   	nop
ffffffff8b2ddfb8:	90                   	nop
ffffffff8b2ddfb9:	90                   	nop
ffffffff8b2ddfba:	90                   	nop
ffffffff8b2ddfbb:	90                   	nop
ffffffff8b2ddfbc:	90                   	nop
ffffffff8b2ddfbd:	90                   	nop
ffffffff8b2ddfbe:	90                   	nop
ffffffff8b2ddfbf:	90                   	nop
ffffffff8b2ddfc0:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2ddfc3:	74 6e                	je     ffffffff8b2de033 <frame_candidate_91dfc5+0x6e>

ffffffff8b2ddfc5 <frame_candidate_91dfc5>:
ffffffff8b2ddfc5:	55                   	push   %rbp
ffffffff8b2ddfc6:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2ddfc9:	40 0f b6 c6          	movzbl %sil,%eax
ffffffff8b2ddfcd:	49 89 f9             	mov    %rdi,%r9
ffffffff8b2ddfd0:	48 01 fa             	add    %rdi,%rdx
ffffffff8b2ddfd3:	69 c0 01 01 01 01    	imul   $0x1010101,%eax,%eax
ffffffff8b2ddfd9:	49 83 e1 f8          	and    $0xfffffffffffffff8,%r9
ffffffff8b2ddfdd:	49 8d 49 08          	lea    0x8(%r9),%rcx
ffffffff8b2ddfe1:	49 89 c0             	mov    %rax,%r8
ffffffff8b2ddfe4:	49 c1 e0 20          	shl    $0x20,%r8
ffffffff8b2ddfe8:	49 09 c0             	or     %rax,%r8
ffffffff8b2ddfeb:	48 39 cf             	cmp    %rcx,%rdi
ffffffff8b2ddfee:	73 21                	jae    ffffffff8b2de011 <frame_candidate_91dfc5+0x4c>
ffffffff8b2ddff0:	4d 39 01             	cmp    %r8,(%r9)
ffffffff8b2ddff3:	74 1c                	je     ffffffff8b2de011 <frame_candidate_91dfc5+0x4c>
ffffffff8b2ddff5:	48 89 f8             	mov    %rdi,%rax
ffffffff8b2ddff8:	4c 29 c8             	sub    %r9,%rax
ffffffff8b2ddffb:	48 83 c0 f8          	add    $0xfffffffffffffff8,%rax
ffffffff8b2ddfff:	90                   	nop
ffffffff8b2de000:	40 38 37             	cmp    %sil,(%rdi)
ffffffff8b2de003:	0f 85 99 00 00 00    	jne    ffffffff8b2de0a2 <frame_candidate_91dfc5+0xdd>
ffffffff8b2de009:	48 ff c7             	inc    %rdi
ffffffff8b2de00c:	48 ff c0             	inc    %rax
ffffffff8b2de00f:	75 ef                	jne    ffffffff8b2de000 <frame_candidate_91dfc5+0x3b>
ffffffff8b2de011:	31 c0                	xor    %eax,%eax
ffffffff8b2de013:	48 39 d1             	cmp    %rdx,%rcx
ffffffff8b2de016:	73 19                	jae    ffffffff8b2de031 <frame_candidate_91dfc5+0x6c>
ffffffff8b2de018:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8b2de01f:	00 
ffffffff8b2de020:	48 8b 39             	mov    (%rcx),%rdi
ffffffff8b2de023:	4c 39 c7             	cmp    %r8,%rdi
ffffffff8b2de026:	75 0e                	jne    ffffffff8b2de036 <frame_candidate_91dfc5+0x71>
ffffffff8b2de028:	48 83 c1 08          	add    $0x8,%rcx
ffffffff8b2de02c:	48 39 d1             	cmp    %rdx,%rcx
ffffffff8b2de02f:	72 ef                	jb     ffffffff8b2de020 <frame_candidate_91dfc5+0x5b>
ffffffff8b2de031:	5d                   	pop    %rbp
ffffffff8b2de032:	c3                   	ret
ffffffff8b2de033:	31 c0                	xor    %eax,%eax
ffffffff8b2de035:	c3                   	ret
ffffffff8b2de036:	40 38 f7             	cmp    %sil,%dil
ffffffff8b2de039:	75 64                	jne    ffffffff8b2de09f <frame_candidate_91dfc5+0xda>
ffffffff8b2de03b:	89 f8                	mov    %edi,%eax
ffffffff8b2de03d:	c1 e8 08             	shr    $0x8,%eax
ffffffff8b2de040:	40 38 f0             	cmp    %sil,%al
ffffffff8b2de043:	75 3f                	jne    ffffffff8b2de084 <frame_candidate_91dfc5+0xbf>
ffffffff8b2de045:	89 f8                	mov    %edi,%eax
ffffffff8b2de047:	c1 e8 10             	shr    $0x10,%eax
ffffffff8b2de04a:	40 38 f0             	cmp    %sil,%al
ffffffff8b2de04d:	75 3a                	jne    ffffffff8b2de089 <frame_candidate_91dfc5+0xc4>
ffffffff8b2de04f:	89 f8                	mov    %edi,%eax
ffffffff8b2de051:	c1 e8 18             	shr    $0x18,%eax
ffffffff8b2de054:	40 38 f0             	cmp    %sil,%al
ffffffff8b2de057:	75 36                	jne    ffffffff8b2de08f <frame_candidate_91dfc5+0xca>
ffffffff8b2de059:	48 89 f8             	mov    %rdi,%rax
ffffffff8b2de05c:	48 c1 e8 20          	shr    $0x20,%rax
ffffffff8b2de060:	40 38 f0             	cmp    %sil,%al
ffffffff8b2de063:	75 30                	jne    ffffffff8b2de095 <frame_candidate_91dfc5+0xd0>
ffffffff8b2de065:	48 89 f8             	mov    %rdi,%rax
ffffffff8b2de068:	48 c1 e8 28          	shr    $0x28,%rax
ffffffff8b2de06c:	40 38 f0             	cmp    %sil,%al
ffffffff8b2de06f:	75 2a                	jne    ffffffff8b2de09b <frame_candidate_91dfc5+0xd6>
ffffffff8b2de071:	48 c1 ef 30          	shr    $0x30,%rdi
ffffffff8b2de075:	31 c0                	xor    %eax,%eax
ffffffff8b2de077:	40 38 f7             	cmp    %sil,%dil
ffffffff8b2de07a:	0f 94 c0             	sete   %al
ffffffff8b2de07d:	48 8d 7c 01 06       	lea    0x6(%rcx,%rax,1),%rdi
ffffffff8b2de082:	eb 1e                	jmp    ffffffff8b2de0a2 <frame_candidate_91dfc5+0xdd>
ffffffff8b2de084:	48 ff c1             	inc    %rcx
ffffffff8b2de087:	eb 16                	jmp    ffffffff8b2de09f <frame_candidate_91dfc5+0xda>
ffffffff8b2de089:	48 83 c1 02          	add    $0x2,%rcx
ffffffff8b2de08d:	eb 10                	jmp    ffffffff8b2de09f <frame_candidate_91dfc5+0xda>
ffffffff8b2de08f:	48 83 c1 03          	add    $0x3,%rcx
ffffffff8b2de093:	eb 0a                	jmp    ffffffff8b2de09f <frame_candidate_91dfc5+0xda>
ffffffff8b2de095:	48 83 c1 04          	add    $0x4,%rcx
ffffffff8b2de099:	eb 04                	jmp    ffffffff8b2de09f <frame_candidate_91dfc5+0xda>
ffffffff8b2de09b:	48 83 c1 05          	add    $0x5,%rcx
ffffffff8b2de09f:	48 89 cf             	mov    %rcx,%rdi
ffffffff8b2de0a2:	31 c0                	xor    %eax,%eax
ffffffff8b2de0a4:	48 39 d7             	cmp    %rdx,%rdi
ffffffff8b2de0a7:	48 0f 42 c7          	cmovb  %rdi,%rax
ffffffff8b2de0ab:	5d                   	pop    %rbp
ffffffff8b2de0ac:	c3                   	ret
ffffffff8b2de0ad:	90                   	nop
ffffffff8b2de0ae:	90                   	nop
ffffffff8b2de0af:	90                   	nop

ffffffff8b2de0b0 <frame_candidate_91e0b0>:
ffffffff8b2de0b0:	55                   	push   %rbp
ffffffff8b2de0b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de0b4:	41 56                	push   %r14
ffffffff8b2de0b6:	53                   	push   %rbx
ffffffff8b2de0b7:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b2de0ba:	48 8d 3d df 88 25 03 	lea    0x32588df(%rip),%rdi        # ffffffff8e5369a0 <frame_candidate_91e450+0x3258550>
ffffffff8b2de0c1:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b2de0c4:	31 f6                	xor    %esi,%esi
ffffffff8b2de0c6:	31 d2                	xor    %edx,%edx
ffffffff8b2de0c8:	31 c9                	xor    %ecx,%ecx
ffffffff8b2de0ca:	e8 51 da 32 00       	call   ffffffff8b60bb20 <frame_candidate_91e450+0x32d6d0>
ffffffff8b2de0cf:	48 8d 05 2a 9f 25 03 	lea    0x3259f2a(%rip),%rax        # ffffffff8e538000 <frame_candidate_91e450+0x3259bb0>
ffffffff8b2de0d6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b2de0dd:	00 00 00 
ffffffff8b2de0e0:	4a 39 5c f0 28       	cmp    %rbx,0x28(%rax,%r14,8)
ffffffff8b2de0e5:	74 20                	je     ffffffff8b2de107 <frame_candidate_91e0b0+0x57>
ffffffff8b2de0e7:	49 ff c6             	inc    %r14
ffffffff8b2de0ea:	49 81 fe 80 00 00 00 	cmp    $0x80,%r14
ffffffff8b2de0f1:	75 ed                	jne    ffffffff8b2de0e0 <frame_candidate_91e0b0+0x30>
ffffffff8b2de0f3:	48 8d 3d a6 88 25 03 	lea    0x32588a6(%rip),%rdi        # ffffffff8e5369a0 <frame_candidate_91e450+0x3258550>
ffffffff8b2de0fa:	31 db                	xor    %ebx,%ebx
ffffffff8b2de0fc:	31 f6                	xor    %esi,%esi
ffffffff8b2de0fe:	31 d2                	xor    %edx,%edx
ffffffff8b2de100:	e8 ab e3 32 00       	call   ffffffff8b60c4b0 <frame_candidate_91e450+0x32e060>
ffffffff8b2de105:	eb 16                	jmp    ffffffff8b2de11d <frame_candidate_91e0b0+0x6d>
ffffffff8b2de107:	48 8d 3d 92 88 25 03 	lea    0x3258892(%rip),%rdi        # ffffffff8e5369a0 <frame_candidate_91e450+0x3258550>
ffffffff8b2de10e:	31 f6                	xor    %esi,%esi
ffffffff8b2de110:	31 d2                	xor    %edx,%edx
ffffffff8b2de112:	e8 99 e3 32 00       	call   ffffffff8b60c4b0 <frame_candidate_91e450+0x32e060>
ffffffff8b2de117:	8b 1d e7 9e 25 03    	mov    0x3259ee7(%rip),%ebx        # ffffffff8e538004 <frame_candidate_91e450+0x3259bb4>
ffffffff8b2de11d:	89 d8                	mov    %ebx,%eax
ffffffff8b2de11f:	5b                   	pop    %rbx
ffffffff8b2de120:	41 5e                	pop    %r14
ffffffff8b2de122:	5d                   	pop    %rbp
ffffffff8b2de123:	c3                   	ret
ffffffff8b2de124:	90                   	nop
ffffffff8b2de125:	90                   	nop
ffffffff8b2de126:	90                   	nop
ffffffff8b2de127:	90                   	nop
ffffffff8b2de128:	90                   	nop
ffffffff8b2de129:	90                   	nop
ffffffff8b2de12a:	90                   	nop
ffffffff8b2de12b:	90                   	nop
ffffffff8b2de12c:	90                   	nop
ffffffff8b2de12d:	90                   	nop
ffffffff8b2de12e:	90                   	nop
ffffffff8b2de12f:	90                   	nop

ffffffff8b2de130 <frame_candidate_91e130>:
ffffffff8b2de130:	55                   	push   %rbp
ffffffff8b2de131:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de134:	53                   	push   %rbx
ffffffff8b2de135:	50                   	push   %rax
ffffffff8b2de136:	83 fe 01             	cmp    $0x1,%esi
ffffffff8b2de139:	0f 84 89 00 00 00    	je     ffffffff8b2de1c8 <frame_candidate_91e130+0x98>
ffffffff8b2de13f:	bb 2d 00 00 00       	mov    $0x2d,%ebx
ffffffff8b2de144:	85 f6                	test   %esi,%esi
ffffffff8b2de146:	0f 85 ad 00 00 00    	jne    ffffffff8b2de1f9 <frame_candidate_91e130+0xc9>
ffffffff8b2de14c:	48 8d 3d 65 3e c3 01 	lea    0x1c33e65(%rip),%rdi        # ffffffff8cf11fb8 <frame_candidate_91e450+0x1c33b68>
ffffffff8b2de153:	4c 8d 0d 45 6c 98 00 	lea    0x986c45(%rip),%r9        # ffffffff8bc64d9f <frame_candidate_91e450+0x98694f>
ffffffff8b2de15a:	41 b8 80 01 00 00    	mov    $0x180,%r8d
ffffffff8b2de160:	31 db                	xor    %ebx,%ebx
ffffffff8b2de162:	31 f6                	xor    %esi,%esi
ffffffff8b2de164:	31 d2                	xor    %edx,%edx
ffffffff8b2de166:	31 c9                	xor    %ecx,%ecx
ffffffff8b2de168:	31 c0                	xor    %eax,%eax
ffffffff8b2de16a:	e8 11 13 dc ff       	call   ffffffff8b09f480 <handler_629_body-0x23d1c0>
ffffffff8b2de16f:	48 89 05 ba a2 25 03 	mov    %rax,0x325a2ba(%rip)        # ffffffff8e538430 <frame_candidate_91e450+0x3259fe0>
ffffffff8b2de176:	48 85 c0             	test   %rax,%rax
ffffffff8b2de179:	74 79                	je     ffffffff8b2de1f4 <frame_candidate_91e130+0xc4>
ffffffff8b2de17b:	48 8d 3d 1e 88 25 03 	lea    0x325881e(%rip),%rdi        # ffffffff8e5369a0 <frame_candidate_91e450+0x3258550>
ffffffff8b2de182:	48 8d 35 a4 4e 9c 00 	lea    0x9c4ea4(%rip),%rsi        # ffffffff8bca302d <frame_candidate_91e450+0x9c4bdd>
ffffffff8b2de189:	31 d2                	xor    %edx,%edx
ffffffff8b2de18b:	e8 00 d1 32 00       	call   ffffffff8b60b290 <frame_candidate_91e450+0x32ce40>
ffffffff8b2de190:	48 8d 3d a1 a2 25 03 	lea    0x325a2a1(%rip),%rdi        # ffffffff8e538438 <frame_candidate_91e450+0x3259fe8>
ffffffff8b2de197:	be 08 08 00 00       	mov    $0x808,%esi
ffffffff8b2de19c:	e8 4f ae 93 ff       	call   ffffffff8ac18ff0 <handler_629_body-0x6c3650>
ffffffff8b2de1a1:	48 8d 35 30 a1 98 00 	lea    0x98a130(%rip),%rsi        # ffffffff8bc682d8 <frame_candidate_91e450+0x989e88>
ffffffff8b2de1a8:	48 8d 15 69 5d 94 ff 	lea    -0x6ba297(%rip),%rdx        # ffffffff8ac23f18 <handler_629_body-0x6b8728>
ffffffff8b2de1af:	48 8d 0d dc 82 96 00 	lea    0x9682dc(%rip),%rcx        # ffffffff8bc46492 <frame_candidate_91e450+0x968042>
ffffffff8b2de1b6:	41 b9 20 4e 00 00    	mov    $0x4e20,%r9d
ffffffff8b2de1bc:	31 ff                	xor    %edi,%edi
ffffffff8b2de1be:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b2de1c1:	e8 7a fb e1 ff       	call   ffffffff8b0fdd40 <handler_629_body-0x1de900>
ffffffff8b2de1c6:	eb 31                	jmp    ffffffff8b2de1f9 <frame_candidate_91e130+0xc9>
ffffffff8b2de1c8:	48 8d 3d d1 87 25 03 	lea    0x32587d1(%rip),%rdi        # ffffffff8e5369a0 <frame_candidate_91e450+0x3258550>
ffffffff8b2de1cf:	e8 bc 2e 94 ff       	call   ffffffff8ac21090 <handler_629_body-0x6bb5b0>
ffffffff8b2de1d4:	48 8b 3d 55 a2 25 03 	mov    0x325a255(%rip),%rdi        # ffffffff8e538430 <frame_candidate_91e450+0x3259fe0>
ffffffff8b2de1db:	31 db                	xor    %ebx,%ebx
ffffffff8b2de1dd:	48 85 ff             	test   %rdi,%rdi
ffffffff8b2de1e0:	74 17                	je     ffffffff8b2de1f9 <frame_candidate_91e130+0xc9>
ffffffff8b2de1e2:	e8 c9 19 dc ff       	call   ffffffff8b09fbb0 <handler_629_body-0x23ca90>
ffffffff8b2de1e7:	48 c7 05 3e a2 25 03 	movq   $0x0,0x325a23e(%rip)        # ffffffff8e538430 <frame_candidate_91e450+0x3259fe0>
ffffffff8b2de1ee:	00 00 00 00 
ffffffff8b2de1f2:	eb 05                	jmp    ffffffff8b2de1f9 <frame_candidate_91e130+0xc9>
ffffffff8b2de1f4:	bb 0c 00 00 00       	mov    $0xc,%ebx
ffffffff8b2de1f9:	89 d8                	mov    %ebx,%eax
ffffffff8b2de1fb:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b2de1ff:	5b                   	pop    %rbx
ffffffff8b2de200:	5d                   	pop    %rbp
ffffffff8b2de201:	c3                   	ret
ffffffff8b2de202:	90                   	nop
ffffffff8b2de203:	90                   	nop
ffffffff8b2de204:	90                   	nop
ffffffff8b2de205:	90                   	nop
ffffffff8b2de206:	90                   	nop
ffffffff8b2de207:	90                   	nop
ffffffff8b2de208:	90                   	nop
ffffffff8b2de209:	90                   	nop
ffffffff8b2de20a:	90                   	nop
ffffffff8b2de20b:	90                   	nop
ffffffff8b2de20c:	90                   	nop
ffffffff8b2de20d:	90                   	nop
ffffffff8b2de20e:	90                   	nop
ffffffff8b2de20f:	90                   	nop
ffffffff8b2de210:	83 3d 21 a2 25 03 00 	cmpl   $0x0,0x325a221(%rip)        # ffffffff8e538438 <frame_candidate_91e450+0x3259fe8>
ffffffff8b2de217:	74 47                	je     ffffffff8b2de260 <frame_candidate_91e219+0x47>

ffffffff8b2de219 <frame_candidate_91e219>:
ffffffff8b2de219:	55                   	push   %rbp
ffffffff8b2de21a:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de21d:	44 8b 05 18 a2 25 03 	mov    0x325a218(%rip),%r8d        # ffffffff8e53843c <frame_candidate_91e450+0x3259fec>
ffffffff8b2de224:	48 8d 15 15 a2 25 03 	lea    0x325a215(%rip),%rdx        # ffffffff8e538440 <frame_candidate_91e450+0x3259ff0>
ffffffff8b2de22b:	b9 00 08 00 00       	mov    $0x800,%ecx
ffffffff8b2de230:	41 b9 01 00 00 00    	mov    $0x1,%r9d
ffffffff8b2de236:	31 ff                	xor    %edi,%edi
ffffffff8b2de238:	31 f6                	xor    %esi,%esi
ffffffff8b2de23a:	e8 11 02 00 00       	call   ffffffff8b2de450 <frame_candidate_91e450>
ffffffff8b2de23f:	85 c0                	test   %eax,%eax
ffffffff8b2de241:	5d                   	pop    %rbp
ffffffff8b2de242:	74 1c                	je     ffffffff8b2de260 <frame_candidate_91e219+0x47>
ffffffff8b2de244:	89 c1                	mov    %eax,%ecx
ffffffff8b2de246:	48 8d 3d 20 7e a1 00 	lea    0xa17e20(%rip),%rdi        # ffffffff8bcf606d <frame_candidate_91e450+0xa17c1d>
ffffffff8b2de24d:	48 8d 35 3e 82 96 00 	lea    0x96823e(%rip),%rsi        # ffffffff8bc46492 <frame_candidate_91e450+0x968042>
ffffffff8b2de254:	ba 59 01 00 00       	mov    $0x159,%edx
ffffffff8b2de259:	31 c0                	xor    %eax,%eax
ffffffff8b2de25b:	e9 b0 f1 93 ff       	jmp    ffffffff8ac1d410 <handler_629_body-0x6bf230>
ffffffff8b2de260:	c3                   	ret
ffffffff8b2de261:	90                   	nop
ffffffff8b2de262:	90                   	nop
ffffffff8b2de263:	90                   	nop
ffffffff8b2de264:	90                   	nop
ffffffff8b2de265:	90                   	nop
ffffffff8b2de266:	90                   	nop
ffffffff8b2de267:	90                   	nop
ffffffff8b2de268:	90                   	nop
ffffffff8b2de269:	90                   	nop
ffffffff8b2de26a:	90                   	nop
ffffffff8b2de26b:	90                   	nop
ffffffff8b2de26c:	90                   	nop
ffffffff8b2de26d:	90                   	nop
ffffffff8b2de26e:	90                   	nop
ffffffff8b2de26f:	90                   	nop

ffffffff8b2de270 <frame_candidate_91e270>:
ffffffff8b2de270:	55                   	push   %rbp
ffffffff8b2de271:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de274:	48 8b b9 40 01 00 00 	mov    0x140(%rcx),%rdi
ffffffff8b2de27b:	e8 20 ee 94 ff       	call   ffffffff8ac2d0a0 <handler_629_body-0x6af5a0>
ffffffff8b2de280:	31 c9                	xor    %ecx,%ecx
ffffffff8b2de282:	85 c0                	test   %eax,%eax
ffffffff8b2de284:	0f 94 c1             	sete   %cl
ffffffff8b2de287:	89 c8                	mov    %ecx,%eax
ffffffff8b2de289:	5d                   	pop    %rbp
ffffffff8b2de28a:	c3                   	ret
ffffffff8b2de28b:	90                   	nop
ffffffff8b2de28c:	90                   	nop
ffffffff8b2de28d:	90                   	nop
ffffffff8b2de28e:	90                   	nop
ffffffff8b2de28f:	90                   	nop

ffffffff8b2de290 <frame_candidate_91e290>:
ffffffff8b2de290:	55                   	push   %rbp
ffffffff8b2de291:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de294:	31 c0                	xor    %eax,%eax
ffffffff8b2de296:	5d                   	pop    %rbp
ffffffff8b2de297:	c3                   	ret
ffffffff8b2de298:	90                   	nop
ffffffff8b2de299:	90                   	nop
ffffffff8b2de29a:	90                   	nop
ffffffff8b2de29b:	90                   	nop
ffffffff8b2de29c:	90                   	nop
ffffffff8b2de29d:	90                   	nop
ffffffff8b2de29e:	90                   	nop
ffffffff8b2de29f:	90                   	nop

ffffffff8b2de2a0 <frame_candidate_91e2a0>:
ffffffff8b2de2a0:	55                   	push   %rbp
ffffffff8b2de2a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de2a4:	41 57                	push   %r15
ffffffff8b2de2a6:	41 56                	push   %r14
ffffffff8b2de2a8:	41 55                	push   %r13
ffffffff8b2de2aa:	41 54                	push   %r12
ffffffff8b2de2ac:	53                   	push   %rbx
ffffffff8b2de2ad:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b2de2b1:	4c 8d 3d 58 e0 ff 02 	lea    0x2ffe058(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2de2b8:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b2de2bb:	49 8b 07             	mov    (%r15),%rax
ffffffff8b2de2be:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b2de2c2:	b8 03 52 30 c0       	mov    $0xc0305203,%eax
ffffffff8b2de2c7:	48 39 c6             	cmp    %rax,%rsi
ffffffff8b2de2ca:	0f 84 e6 00 00 00    	je     ffffffff8b2de3b6 <frame_candidate_91e2a0+0x116>
ffffffff8b2de2d0:	b8 02 52 30 c0       	mov    $0xc0305202,%eax
ffffffff8b2de2d5:	48 39 c6             	cmp    %rax,%rsi
ffffffff8b2de2d8:	74 22                	je     ffffffff8b2de2fc <frame_candidate_91e2a0+0x5c>
ffffffff8b2de2da:	b8 fd ff ff ff       	mov    $0xfffffffd,%eax
ffffffff8b2de2df:	b9 01 52 30 c0       	mov    $0xc0305201,%ecx
ffffffff8b2de2e4:	48 39 ce             	cmp    %rcx,%rsi
ffffffff8b2de2e7:	0f 85 05 01 00 00    	jne    ffffffff8b2de3f2 <frame_candidate_91e2a0+0x152>
ffffffff8b2de2ed:	41 bc 00 88 00 00    	mov    $0x8800,%r12d
ffffffff8b2de2f3:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
ffffffff8b2de2fa:	eb 0d                	jmp    ffffffff8b2de309 <frame_candidate_91e2a0+0x69>
ffffffff8b2de2fc:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%rbp)
ffffffff8b2de303:	41 bc 00 08 10 00    	mov    $0x100800,%r12d
ffffffff8b2de309:	48 8d 35 a0 3b c3 01 	lea    0x1c33ba0(%rip),%rsi        # ffffffff8cf11eb0 <frame_candidate_91e450+0x1c33a60>
ffffffff8b2de310:	bf 00 08 10 00       	mov    $0x100800,%edi
ffffffff8b2de315:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8b2de31a:	e8 31 a8 2e 00       	call   ffffffff8b5c8b50 <frame_candidate_91e450+0x2ea700>
ffffffff8b2de31f:	4c 8b 6b 20          	mov    0x20(%rbx),%r13
ffffffff8b2de323:	49 89 c6             	mov    %rax,%r14
ffffffff8b2de326:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b2de32d:	00 
ffffffff8b2de32e:	49 81 fd 01 08 00 00 	cmp    $0x801,%r13
ffffffff8b2de335:	0f 92 c0             	setb   %al
ffffffff8b2de338:	4d 39 e5             	cmp    %r12,%r13
ffffffff8b2de33b:	0f 97 c1             	seta   %cl
ffffffff8b2de33e:	08 c1                	or     %al,%cl
ffffffff8b2de340:	74 10                	je     ffffffff8b2de352 <frame_candidate_91e2a0+0xb2>
ffffffff8b2de342:	41 bc ea ff ff ff    	mov    $0xffffffea,%r12d
ffffffff8b2de348:	4d 85 f6             	test   %r14,%r14
ffffffff8b2de34b:	75 58                	jne    ffffffff8b2de3a5 <frame_candidate_91e2a0+0x105>
ffffffff8b2de34d:	e9 9a 00 00 00       	jmp    ffffffff8b2de3ec <frame_candidate_91e2a0+0x14c>
ffffffff8b2de352:	4c 8b 63 18          	mov    0x18(%rbx),%r12
ffffffff8b2de356:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b2de35d:	00 00 
ffffffff8b2de35f:	48 8d 35 d7 9b a7 00 	lea    0xa79bd7(%rip),%rsi        # ffffffff8bd57f3d <frame_candidate_91e450+0xa79aed>
ffffffff8b2de366:	31 d2                	xor    %edx,%edx
ffffffff8b2de368:	e8 73 c0 2f 00       	call   ffffffff8b5da3e0 <frame_candidate_91e450+0x2fbf90>
ffffffff8b2de36d:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b2de370:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b2de373:	4c 89 ea             	mov    %r13,%rdx
ffffffff8b2de376:	e8 05 af 93 ff       	call   ffffffff8ac19280 <handler_629_body-0x6c33c0>
ffffffff8b2de37b:	41 bc f2 ff ff ff    	mov    $0xfffffff2,%r12d
ffffffff8b2de381:	85 c0                	test   %eax,%eax
ffffffff8b2de383:	75 20                	jne    ffffffff8b2de3a5 <frame_candidate_91e2a0+0x105>
ffffffff8b2de385:	44 8b 45 c4          	mov    -0x3c(%rbp),%r8d
ffffffff8b2de389:	48 8d 75 c8          	lea    -0x38(%rbp),%rsi
ffffffff8b2de38d:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2de390:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b2de393:	4c 89 e9             	mov    %r13,%rcx
ffffffff8b2de396:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b2de399:	e8 b2 00 00 00       	call   ffffffff8b2de450 <frame_candidate_91e450>
ffffffff8b2de39e:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2de3a1:	85 c0                	test   %eax,%eax
ffffffff8b2de3a3:	74 65                	je     ffffffff8b2de40a <frame_candidate_91e2a0+0x16a>
ffffffff8b2de3a5:	48 8d 35 04 3b c3 01 	lea    0x1c33b04(%rip),%rsi        # ffffffff8cf11eb0 <frame_candidate_91e450+0x1c33a60>
ffffffff8b2de3ac:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2de3af:	e8 3c aa 2e 00       	call   ffffffff8b5c8df0 <frame_candidate_91e450+0x2ea9a0>
ffffffff8b2de3b4:	eb 36                	jmp    ffffffff8b2de3ec <frame_candidate_91e2a0+0x14c>
ffffffff8b2de3b6:	83 3d 7b a0 25 03 00 	cmpl   $0x0,0x325a07b(%rip)        # ffffffff8e538438 <frame_candidate_91e450+0x3259fe8>
ffffffff8b2de3bd:	74 27                	je     ffffffff8b2de3e6 <frame_candidate_91e2a0+0x146>
ffffffff8b2de3bf:	44 8b 05 76 a0 25 03 	mov    0x325a076(%rip),%r8d        # ffffffff8e53843c <frame_candidate_91e450+0x3259fec>
ffffffff8b2de3c6:	48 8d 15 73 a0 25 03 	lea    0x325a073(%rip),%rdx        # ffffffff8e538440 <frame_candidate_91e450+0x3259ff0>
ffffffff8b2de3cd:	b9 00 08 00 00       	mov    $0x800,%ecx
ffffffff8b2de3d2:	41 b9 01 00 00 00    	mov    $0x1,%r9d
ffffffff8b2de3d8:	31 ff                	xor    %edi,%edi
ffffffff8b2de3da:	31 f6                	xor    %esi,%esi
ffffffff8b2de3dc:	e8 6f 00 00 00       	call   ffffffff8b2de450 <frame_candidate_91e450>
ffffffff8b2de3e1:	41 89 c4             	mov    %eax,%r12d
ffffffff8b2de3e4:	eb 06                	jmp    ffffffff8b2de3ec <frame_candidate_91e2a0+0x14c>
ffffffff8b2de3e6:	41 bc d8 ff ff ff    	mov    $0xffffffd8,%r12d
ffffffff8b2de3ec:	31 c0                	xor    %eax,%eax
ffffffff8b2de3ee:	44 89 63 28          	mov    %r12d,0x28(%rbx)
ffffffff8b2de3f2:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b2de3f5:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8b2de3f9:	75 47                	jne    ffffffff8b2de442 <frame_candidate_91e2a0+0x1a2>
ffffffff8b2de3fb:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b2de3ff:	5b                   	pop    %rbx
ffffffff8b2de400:	41 5c                	pop    %r12
ffffffff8b2de402:	41 5d                	pop    %r13
ffffffff8b2de404:	41 5e                	pop    %r14
ffffffff8b2de406:	41 5f                	pop    %r15
ffffffff8b2de408:	5d                   	pop    %rbp
ffffffff8b2de409:	c3                   	ret
ffffffff8b2de40a:	48 8b 43 08          	mov    0x8(%rbx),%rax
ffffffff8b2de40e:	41 bc ea ff ff ff    	mov    $0xffffffea,%r12d
ffffffff8b2de414:	48 85 c0             	test   %rax,%rax
ffffffff8b2de417:	74 8c                	je     ffffffff8b2de3a5 <frame_candidate_91e2a0+0x105>
ffffffff8b2de419:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b2de41d:	48 39 d0             	cmp    %rdx,%rax
ffffffff8b2de420:	72 83                	jb     ffffffff8b2de3a5 <frame_candidate_91e2a0+0x105>
ffffffff8b2de422:	48 89 53 10          	mov    %rdx,0x10(%rbx)
ffffffff8b2de426:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2de429:	48 8b 33             	mov    (%rbx),%rsi
ffffffff8b2de42c:	e8 df 03 00 00       	call   ffffffff8b2de810 <frame_candidate_91e450+0x3c0>
ffffffff8b2de431:	85 c0                	test   %eax,%eax
ffffffff8b2de433:	41 bc f2 ff ff ff    	mov    $0xfffffff2,%r12d
ffffffff8b2de439:	44 0f 44 e0          	cmove  %eax,%r12d
ffffffff8b2de43d:	e9 63 ff ff ff       	jmp    ffffffff8b2de3a5 <frame_candidate_91e2a0+0x105>
ffffffff8b2de442:	e8 69 f2 dd ff       	call   ffffffff8b0bd6b0 <handler_629_body-0x21ef90>
ffffffff8b2de447:	0f 0b                	ud2
ffffffff8b2de449:	90                   	nop
ffffffff8b2de44a:	90                   	nop
ffffffff8b2de44b:	90                   	nop
ffffffff8b2de44c:	90                   	nop
ffffffff8b2de44d:	90                   	nop
ffffffff8b2de44e:	90                   	nop
ffffffff8b2de44f:	90                   	nop

ffffffff8b2de450 <frame_candidate_91e450>:
ffffffff8b2de450:	55                   	push   %rbp
ffffffff8b2de451:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2de454:	41 57                	push   %r15
ffffffff8b2de456:	41 56                	push   %r14
ffffffff8b2de458:	41 55                	push   %r13
ffffffff8b2de45a:	41 54                	push   %r12
ffffffff8b2de45c:	53                   	push   %rbx
ffffffff8b2de45d:	48 81 ec 48 01 00 00 	sub    $0x148,%rsp
ffffffff8b2de464:	48 8d 05 a5 de ff 02 	lea    0x2ffdea5(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_91e450+0x2ffdec0>
ffffffff8b2de46b:	48 89 bd a8 fe ff ff 	mov    %rdi,-0x158(%rbp)
ffffffff8b2de472:	48 89 b5 a0 fe ff ff 	mov    %rsi,-0x160(%rbp)
ffffffff8b2de479:	45 85 c0             	test   %r8d,%r8d
ffffffff8b2de47c:	41 be 00 08 10 00    	mov    $0x100800,%r14d
ffffffff8b2de482:	48 8d 3d 17 85 25 03 	lea    0x3258517(%rip),%rdi        # ffffffff8e5369a0 <frame_candidate_91e450+0x3258550>
ffffffff8b2de489:	45 89 cc             	mov    %r9d,%r12d
ffffffff8b2de48c:	45 89 c7             	mov    %r8d,%r15d
ffffffff8b2de48f:	48 89 cb             	mov    %rcx,%rbx
ffffffff8b2de492:	49 89 d5             	mov    %rdx,%r13
ffffffff8b2de495:	48 8b 00             	mov    (%rax),%rax
ffffffff8b2de498:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b2de49c:	b8 00 88 00 00       	mov    $0x8800,%eax
ffffffff8b2de4a1:	48 c7 85 c8 fe ff ff 	movq   $0xffffffffffffffff,-0x138(%rbp)
ffffffff8b2de4a8:	ff ff ff ff 
ffffffff8b2de4ac:	48 c7 85 48 ff ff ff 	movq   $0x0,-0xb8(%rbp)
ffffffff8b2de4b3:	00 00 00 00 
ffffffff8b2de4b7:	48 c7 85 40 ff ff ff 	movq   $0x0,-0xc0(%rbp)
ffffffff8b2de4be:	00 00 00 00 
ffffffff8b2de4c2:	48 c7 85 38 ff ff ff 	movq   $0x0,-0xc8(%rbp)
ffffffff8b2de4c9:	00 00 00 00 
ffffffff8b2de4cd:	48 c7 85 30 ff ff ff 	movq   $0x0,-0xd0(%rbp)
ffffffff8b2de4d4:	00 00 00 00 
ffffffff8b2de4d8:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
ffffffff8b2de4df:	00 00 00 00 
ffffffff8b2de4e3:	48 c7 85 20 ff ff ff 	movq   $0x0,-0xe0(%rbp)
ffffffff8b2de4ea:	00 00 00 00 
ffffffff8b2de4ee:	48 c7 85 18 ff ff ff 	movq   $0x0,-0xe8(%rbp)
ffffffff8b2de4f5:	00 00 00 00 
ffffffff8b2de4f9:	48 c7 85 10 ff ff ff 	movq   $0x0,-0xf0(%rbp)
ffffffff8b2de500:	00 00 00 00 
ffffffff8b2de504:	48 c7 85 08 ff ff ff 	movq   $0x0,-0xf8(%rbp)
ffffffff8b2de50b:	00 00 00 00 
ffffffff8b2de50f:	48 c7 85 00 ff ff ff 	movq   $0x0,-0x100(%rbp)
ffffffff8b2de516:	00 00 00 00 
ffffffff8b2de51a:	48 c7 85 f8 fe ff ff 	movq   $0x0,-0x108(%rbp)
ffffffff8b2de521:	00 00 00 00 
ffffffff8b2de525:	48 c7 85 f0 fe ff ff 	movq   $0x0,-0x110(%rbp)
ffffffff8b2de52c:	00 00 00 00 
ffffffff8b2de530:	48 c7 85 e8 fe ff ff 	movq   $0x0,-0x118(%rbp)
ffffffff8b2de537:	00 00 00 00 
ffffffff8b2de53b:	48 c7 85 e0 fe ff ff 	movq   $0x0,-0x120(%rbp)
ffffffff8b2de542:	00 00 00 00 
ffffffff8b2de546:	48 c7 85 d8 fe ff ff 	movq   $0x0,-0x128(%rbp)
ffffffff8b2de54d:	00 00 00 00 
ffffffff8b2de551:	48 c7 85 d0 fe ff ff 	movq   $0x0,-0x130(%rbp)
ffffffff8b2de558:	00 00 00 00 
ffffffff8b2de55c:	48 c7 85 c0 fe ff ff 	movq   $0x0,-0x140(%rbp)
ffffffff8b2de563:	00 00 00 00 
ffffffff8b2de567:	48 c7 85 b8 fe ff ff 	movq   $0x0,-0x148(%rbp)
ffffffff8b2de56e:	00 00 00 00 
ffffffff8b2de572:	4c 0f 44 f0          	cmove  %rax,%r14
ffffffff8b2de576:	31 f6                	xor    %esi,%esi
ffffffff8b2de578:	31 d2                	xor    %edx,%edx
ffffffff8b2de57a:	31 c9                	xor    %ecx,%ecx
ffffffff8b2de57c:	e8 9f d5 32 00       	call   ffffffff8b60bb20 <frame_candidate_91e450+0x32d6d0>
ffffffff8b2de581:	45 85 e4             	test   %r12d,%r12d
ffffffff8b2de584:	75 25                	jne    ffffffff8b2de5ab <frame_candidate_91e450+0x15b>
ffffffff8b2de586:	48 8d 3d b3 9e 25 03 	lea    0x3259eb3(%rip),%rdi        # ffffffff8e538440 <frame_candidate_91e450+0x3259ff0>
ffffffff8b2de58d:	ba 00 08 00 00       	mov    $0x800,%edx
ffffffff8b2de592:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b2de595:	c7 05 99 9e 25 03 01 	movl   $0x1,0x3259e99(%rip)        # ffffffff8e538438 <frame_candidate_91e450+0x3259fe8>
ffffffff8b2de59c:	00 00 00 
ffffffff8b2de59f:	44 89 3d 96 9e 25 03 	mov    %r15d,0x3259e96(%rip)        # ffffffff8e53843c <frame_candidate_91e450+0x3259fec>
ffffffff8b2de5a6:	e8 05 ab 93 ff       	call   ffffffff8ac190b0 <handler_629_body-0x6c3590>
ffffffff8b2de5ab:	4c 8d 05 4e da 25 03 	lea    0x325da4e(%rip),%r8        # ffffffff8e53c000 <frame_candidate_91e450+0x325dbb0>
ffffffff8b2de5b2:	48 8d bd c0 fe ff ff 	lea    -0x140(%rbp),%rdi
ffffffff8b2de5b9:	48 8d b5 b8 fe ff ff 	lea    -0x148(%rbp),%rsi
ffffffff8b2de5c0:	41 b9 00 40 00 00    	mov    $0x4000,%r9d
ffffffff8b2de5c6:	4c 89 ea             	mov    %r13,%rdx
ffffffff8b2de5c9:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b2de5cc:	e8 9f 94 d1 ff       	call   ffffffff8aff7a70 <handler_629_body-0x2e4bd0>
ffffffff8b2de5d1:	85 c0                	test   %eax,%eax
ffffffff8b2de5d3:	75 35                	jne    ffffffff8b2de60a <frame_candidate_91e450+0x1ba>
ffffffff8b2de5d5:	48 8d 85 c8 fe ff ff 	lea    -0x138(%rbp),%rax
ffffffff8b2de5dc:	48 8d 3d 81 7a a1 00 	lea    0xa17a81(%rip),%rdi        # ffffffff8bcf6064 <frame_candidate_91e450+0xa17c14>
ffffffff8b2de5e3:	41 b9 01 00 00 00    	mov    $0x1,%r9d
ffffffff8b2de5e9:	4c 89 ad b0 fe ff ff 	mov    %r13,-0x150(%rbp)
ffffffff8b2de5f0:	31 f6                	xor    %esi,%esi
ffffffff8b2de5f2:	31 d2                	xor    %edx,%edx
ffffffff8b2de5f4:	31 c9                	xor    %ecx,%ecx
ffffffff8b2de5f6:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b2de5f9:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8b2de5fd:	e8 fe 5b c8 ff       	call   ffffffff8af64200 <handler_629_body-0x378440>
ffffffff8b2de602:	85 c0                	test   %eax,%eax
ffffffff8b2de604:	0f 84 17 01 00 00    	je     ffffffff8b2de721 <frame_candidate_91e450+0x2d1>
ffffffff8b2de60a:	41 89 c5             	mov    %eax,%r13d
ffffffff8b2de60d:	48 8b 9d c8 fe ff ff 	mov    -0x138(%rbp),%rbx
ffffffff8b2de614:	48 83 fb ff          	cmp    $0xffffffffffffffff,%rbx
ffffffff8b2de618:	0f 84 b9 00 00 00    	je     ffffffff8b2de6d7 <frame_candidate_91e450+0x287>
ffffffff8b2de61e:	48 8d 95 50 ff ff ff 	lea    -0xb0(%rbp),%rdx
ffffffff8b2de625:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2de628:	48 c7 85 50 ff ff ff 	movq   $0x0,-0xb0(%rbp)
ffffffff8b2de62f:	00 00 00 00 
ffffffff8b2de633:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b2de63a:	00 
ffffffff8b2de63b:	48                   	rex.W
ffffffff8b2de63c:	c7                   	.byte 0xc7
ffffffff8b2de63d:	45                   	rex.RB
ffffffff8b2de63e:	c0                   	.byte 0xc0
	...
ffffffff8b2de63f: 00   .byte 0x00 ; exact source byte suppressed by objdump zero elision
