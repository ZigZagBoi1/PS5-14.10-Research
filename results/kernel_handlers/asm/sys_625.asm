; REA 6.7.0 full disassembly of handler_625.bin
; SHA256 0b560f61ebd53023272e9f4eb457bccef9a60fb2808fe8cf0893253bd2aeba50; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25eb0, kernel RVA 0x265eb0.
; REA inspect_with_objdump Evidence: ev_ff31b31a417a1381d8b55bfaf229ae477317a9ba56faad59d9bbdd13255bb9b8
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 625; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_625.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25eb0 <handler_625_entry>:
ffffffff8ac25eb0:	e9 db dd 39 00       	jmp    ffffffff8afc3c90 <neighbor_trampoline_266ea8+0x39cde8>
ffffffff8ac25eb5:	cc                   	int3
ffffffff8ac25eb6:	cc                   	int3
ffffffff8ac25eb7:	cc                   	int3

ffffffff8ac25eb8 <neighbor_trampoline_265eb8>:
ffffffff8ac25eb8:	e9 33 ee 39 00       	jmp    ffffffff8afc4cf0 <neighbor_trampoline_266ea8+0x39de48>
ffffffff8ac25ebd:	cc                   	int3
ffffffff8ac25ebe:	cc                   	int3
ffffffff8ac25ebf:	cc                   	int3

ffffffff8ac25ec0 <neighbor_trampoline_265ec0>:
ffffffff8ac25ec0:	e9 8b c9 23 00       	jmp    ffffffff8ae62850 <neighbor_trampoline_266ea8+0x23b9a8>
ffffffff8ac25ec5:	cc                   	int3
ffffffff8ac25ec6:	cc                   	int3
ffffffff8ac25ec7:	cc                   	int3

ffffffff8ac25ec8 <neighbor_trampoline_265ec8>:
ffffffff8ac25ec8:	e9 73 76 85 00       	jmp    ffffffff8b47d540 <neighbor_trampoline_266ea8+0x856698>
ffffffff8ac25ecd:	cc                   	int3
ffffffff8ac25ece:	cc                   	int3
ffffffff8ac25ecf:	cc                   	int3

ffffffff8ac25ed0 <neighbor_trampoline_265ed0>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266ea8+0x6b5798>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266ea8+0x6b5dc8>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266ea8+0x1d1f88>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266ea8+0x1d21c8>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266ea8+0x1d22a8>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266ea8+0x1d24f8>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266ea8+0x457628>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266ea8+0x856a88>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266ea8+0x457718>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266ea8+0x457958>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266ea8+0x829f68>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266ea8+0x23bf38>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266ea8+0x856c28>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266ea8+0x7d07b8>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266ea8+0x857318>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266ea8+0x857908>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266ea8+0x791348>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266ea8+0x982668>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266ea8+0x740e68>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266ea8+0x7426b8>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266ea8+0x742f68>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266ea8+0x743098>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266ea8+0x694598>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266ea8+0x23c2f8>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266ea8+0x857a08>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266ea8+0x744348>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266ea8+0x854ad8>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266ea8+0x492438>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266ea8+0x1cdef8>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266ea8+0x1cdf08>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266ea8+0x1cdf18>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266ea8+0x1d0ee8>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266ea8+0x1d13d8>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266ea8+0x87f7e8>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266ea8+0x87f6d8>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266ea8+0x1e2228>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_625_entry-0x1bf0f0>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266ea8+0x1e3bc8>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266ea8+0x74f268>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_625_entry-0x1be840>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_625_entry-0x1be660>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_625_entry-0x1be630>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266ea8+0x1eb198>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266ea8+0x1ede18>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266ea8+0x1f0978>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266ea8+0x2070c8>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266ea8+0x2071d8>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266ea8+0x20bae8>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266ea8+0x20c508>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266ea8+0x20ca08>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266ea8+0x20d3a8>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266ea8+0x20df08>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266ea8+0x216148>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_625_entry-0x47ec0>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266ea8+0x229458>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266ea8+0x229f08>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266ea8+0x231108>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266ea8+0x231138>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266ea8+0x231788>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266ea8+0x231798>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266ea8+0x690d18>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266ea8+0x68f958>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266ea8+0x690578>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266ea8+0x6930d8>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266ea8+0x3784a8>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266ea8+0x378978>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266ea8+0x7cde38>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266ea8+0x3815f8>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266ea8+0x691348>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266ea8+0x692568>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266ea8+0x695548>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266ea8+0x68fde8>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266ea8+0xa4ab68>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266ea8+0x8514f8>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266ea8+0x851508>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266ea8+0x693318>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266ea8+0x690c98>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266ea8+0x239ab8>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266ea8+0x4c28d8>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266ea8+0x4c28e8>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266ea8+0x4c28f8>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266ea8+0x4546e8>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266ea8+0x851ef8>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266ea8+0x6932c8>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266ea8+0x918218>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266ea8+0x918258>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266ea8+0x692e48>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266ea8+0x693898>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266ea8+0x2ebcc8>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266ea8+0x2ebd48>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266ea8+0x2ebda8>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266ea8+0x2ebdd8>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266ea8+0x2ebe08>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266ea8+0x2ebe38>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266ea8+0x917958>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266ea8+0x917d38>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266ea8+0x9180c8>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266ea8+0x99fe88>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266ea8+0x52b7e8>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266ea8+0x381c78>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266ea8+0x2ebe68>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266ea8+0x9182b8>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266ea8+0x3773a8>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266ea8+0x7edb88>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266ea8+0x7edb98>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266ea8+0x7edba8>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266ea8+0x7edbb8>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266ea8+0x7edbd8>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266ea8+0x7edbe8>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266ea8+0x692878>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266ea8+0x7edc08>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266ea8+0x68f638>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266ea8+0x68f048>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266ea8+0x7edb78>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266ea8+0x7edbc8>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266ea8+0x7edbf8>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266ea8+0x47e628>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266ea8+0x918608>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266ea8+0x5d67b8>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266ea8+0x5d6918>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266ea8+0x5d6c08>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266ea8+0x5d6fd8>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266ea8+0x692dd8>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266ea8+0x693268>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266ea8+0x692308>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266ea8+0x693648>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266ea8+0x6911e8>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266ea8+0x694cd8>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266ea8+0x690cd8>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266ea8+0x6909e8>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266ea8+0x6949f8>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266ea8+0x691668>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266ea8+0x691958>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266ea8+0x2341d8>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266ea8+0x2341e8>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266ea8+0x2f8ba8>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266ea8+0x9cd9c8>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266ea8+0x575e48>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266ea8+0x575e58>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266ea8+0x575e68>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266ea8+0x575e78>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266ea8+0x575e88>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266ea8+0x33fde8>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266ea8+0x340458>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266ea8+0x340768>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266ea8+0x340a58>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266ea8+0xa35988>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266ea8+0x341058>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266ea8+0x3411c8>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266ea8+0x9815d8>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266ea8+0x2341f8>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266ea8+0x234218>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266ea8+0x234228>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266ea8+0x234238>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266ea8+0x234248>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266ea8+0x2c9878>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266ea8+0x2ca7c8>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266ea8+0x692848>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266ea8+0x2ca388>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266ea8+0x59bf48>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266ea8+0x918298>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266ea8+0x87c738>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266ea8+0x287f78>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266ea8+0x693c68>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266ea8+0x693f88>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266ea8+0x762378>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266ea8+0x762258>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266ea8+0x3db468>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266ea8+0x3db978>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266ea8+0x3dc838>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266ea8+0x3dca28>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266ea8+0x3dcdb8>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266ea8+0x7913e8>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266ea8+0x794cc8>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266ea8+0x7de3d8>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266ea8+0xa20df8>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266ea8+0x798158>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266ea8+0x7998d8>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266ea8+0x799938>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266ea8+0x857988>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266ea8+0x796088>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266ea8+0x38a118>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266ea8+0x690548>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266ea8+0x2903a8>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266ea8+0x796c28>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266ea8+0x796f08>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266ea8+0x797068>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266ea8+0x3dd628>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266ea8+0x3ea128>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266ea8+0x797b88>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266ea8+0x290a98>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266ea8+0x851c38>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266ea8+0x8547b8>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266ea8+0x7973b8>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266ea8+0x797638>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266ea8+0x797788>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266ea8+0x531488>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266ea8+0x856158>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_625_entry-0x169620>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266ea8+0x2381e8>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266ea8+0x238358>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266ea8+0x2596e8>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266ea8+0x259708>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_625_entry-0x1bca80>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266ea8+0x2634a8>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266ea8+0x263b98>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_625_entry-0x1bb9a0>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266ea8+0x26e328>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266ea8+0x5aa308>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_625_entry-0x24b020>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266ea8+0x289188>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266ea8+0x294d28>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266ea8+0x2a6028>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266ea8+0x2a6038>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266ea8+0x2a6088>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266ea8+0x2a60c8>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266ea8+0x2a6108>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266ea8+0x2a6138>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266ea8+0x2b7628>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266ea8+0x2b80b8>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266ea8+0x2b8158>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266ea8+0x2b8208>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266ea8+0x2b8438>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266ea8+0x2b87c8>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266ea8+0x2b9038>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266ea8+0x2cf558>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266ea8+0x2dddf8>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266ea8+0x2dfa48>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_625_entry-0x1b4880>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_625_entry-0x1b3f00>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266ea8+0x2f5098>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266ea8+0x2f5188>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266ea8+0x2f51a8>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266ea8+0x307358>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266ea8+0x3185f8>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266ea8+0x72d738>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266ea8+0x31eaa8>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266ea8+0x332978>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266ea8+0x333538>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266ea8+0x333688>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266ea8+0x333858>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266ea8+0x333928>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266ea8+0x333ba8>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266ea8+0x333cb8>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266ea8+0x333db8>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266ea8+0x375028>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266ea8+0x384878>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266ea8+0x385188>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266ea8+0x385c28>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266ea8+0x386598>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266ea8+0x386c88>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_625_entry-0x117c30>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266ea8+0x38aa08>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266ea8+0x38bc88>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266ea8+0x396218>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266ea8+0x3997d8>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266ea8+0x39a098>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266ea8+0x87f5f8>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266ea8+0x3c6bf8>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266ea8+0x3c9428>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266ea8+0x3ce068>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266ea8+0x3d8678>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266ea8+0x3f0b08>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266ea8+0xa40468>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266ea8+0x3fbfc8>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266ea8+0x3fbfd8>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266ea8+0x411f68>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266ea8+0x411fb8>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266ea8+0x412018>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266ea8+0x4120b8>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266ea8+0x4122e8>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266ea8+0x4124b8>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266ea8+0x4127d8>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_625_entry-0x232320>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_625_entry-0x232210>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_625_entry-0x232190>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_625_entry-0x228f40>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_625_entry-0x228dd0>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_625_entry-0x228850>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_625_entry-0x227db0>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_625_entry-0x227d50>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_625_entry-0x227cf0>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_625_entry-0x226e40>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_625_entry-0x226de0>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_625_entry-0x226a00>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_625_entry-0x2269a0>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_625_entry-0x226940>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_625_entry-0x226300>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_625_entry-0x225ef0>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_625_entry-0x225550>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_625_entry-0x225360>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_625_entry-0x225280>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_625_entry-0x224880>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_625_entry-0x224760>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_625_entry-0x224680>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_625_entry-0x2245f0>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_625_entry-0x223e50>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_625_entry-0x2239e0>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_625_entry-0x223910>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_625_entry-0x2238b0>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266ea8+0x429188>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266ea8+0x42fe18>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266ea8+0x431728>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266ea8+0x43b1a8>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266ea8+0x43b408>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266ea8+0x447798>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266ea8+0x447948>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_625_entry-0xe4b00>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266ea8+0x4580f8>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_625_entry-0xdde70>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266ea8+0x469c58>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266ea8+0x46a258>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266ea8+0x46a3b8>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266ea8+0x46a538>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266ea8+0x46a678>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266ea8+0x46a798>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266ea8+0x46a878>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266ea8+0x4757b8>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266ea8+0x4757e8>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266ea8+0x4757f8>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266ea8+0x479a78>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266ea8+0x47a598>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266ea8+0x47a5a8>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_625_entry-0xdc440>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_625_entry-0xd5410>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266ea8+0x49bac8>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266ea8+0x49beb8>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266ea8+0x49f2c8>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266ea8+0x49f348>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266ea8+0x4a9058>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266ea8+0x4a9108>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266ea8+0x4a9318>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266ea8+0x4a9478>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266ea8+0x4abd08>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266ea8+0x4af4b8>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266ea8+0x4c8ac8>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266ea8+0x4c8ae8>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266ea8+0x4c8b78>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_625_entry-0x1f080>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266ea8+0x4fd948>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266ea8+0x50c868>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266ea8+0x50eaa8>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266ea8+0x532fe8>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266ea8+0x54c348>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266ea8+0x57b4f8>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266ea8+0x581538>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266ea8+0x5815d8>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266ea8+0x9d4308>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266ea8+0x9d5838>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266ea8+0x9d57e8>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266ea8+0x9d5888>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266ea8+0x59b378>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266ea8+0x59b648>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266ea8+0x5a56c8>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266ea8+0x5c4458>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266ea8+0x6ba038>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266ea8+0x6b9ce8>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266ea8+0x5c9968>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266ea8+0x5ca058>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266ea8+0x5ce408>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266ea8+0x5ce418>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266ea8+0x5ce428>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266ea8+0x5ce448>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266ea8+0x5ce598>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266ea8+0x5ce5a8>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266ea8+0x5ce5e8>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266ea8+0x5cec28>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266ea8+0x5e99c8>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266ea8+0x609448>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266ea8+0x609728>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266ea8+0x60bc48>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266ea8+0x60c958>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_625_entry-0x202470>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_625_entry-0x1ffb40>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_625_entry-0x17f920>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_625_entry-0x17f910>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_625_entry-0x17f750>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_625_entry-0x17f640>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_625_entry-0x17df20>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_625_entry-0x17bf10>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_625_entry-0x17b840>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_625_entry-0x17b750>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_625_entry-0x17ae10>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_625_entry-0x17ad20>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_625_entry-0x178eb0>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_625_entry-0x178da0>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266ea8+0x6239f8>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266ea8+0x635f48>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_625_entry-0x177360>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266ea8+0x6643a8>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266ea8+0x6644e8>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266ea8+0x66c0b8>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266ea8+0x66c0e8>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266ea8+0x671388>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266ea8+0x671f38>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266ea8+0x672908>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266ea8+0x672a68>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266ea8+0x673618>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266ea8+0x6736c8>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266ea8+0x673708>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266ea8+0x69ddd8>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266ea8+0x69dfb8>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266ea8+0x6b6558>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266ea8+0x6b65f8>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266ea8+0x81b328>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266ea8+0x8db278>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266ea8+0x6fe088>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266ea8+0x70f0a8>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266ea8+0x70f358>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266ea8+0x725aa8>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266ea8+0x725d88>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266ea8+0x726088>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266ea8+0x726838>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266ea8+0x727728>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266ea8+0x727858>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266ea8+0x72b2c8>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266ea8+0x72b398>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_625_entry-0x170ab0>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266ea8+0x73b478>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266ea8+0x73e878>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266ea8+0x745af8>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266ea8+0x745b78>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_625_entry-0xa7870>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266ea8+0x757e78>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266ea8+0x75f1a8>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266ea8+0x75f228>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266ea8+0x75f3d8>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266ea8+0x75f468>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266ea8+0x75f5e8>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266ea8+0x75f708>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266ea8+0x75f9e8>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266ea8+0x762498>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266ea8+0x7624b8>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266ea8+0x7624c8>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266ea8+0x7624d8>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266ea8+0x773f08>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266ea8+0x7740f8>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266ea8+0x7759b8>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266ea8+0x775d98>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266ea8+0x775fd8>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266ea8+0x776658>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266ea8+0xa43e28>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266ea8+0x776928>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266ea8+0x776ae8>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266ea8+0x776cf8>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266ea8+0x776d58>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266ea8+0x776fa8>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266ea8+0x777008>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266ea8+0x777148>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266ea8+0x7771c8>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266ea8+0x777248>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266ea8+0x779ce8>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266ea8+0x779e28>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266ea8+0x779ec8>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266ea8+0x77a048>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266ea8+0x77a1a8>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266ea8+0x77a5e8>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266ea8+0x79f738>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_625_entry-0x164b70>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266ea8+0x7cc088>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266ea8+0x7cc818>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266ea8+0x7d1de8>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266ea8+0x803c58>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266ea8+0x803d08>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266ea8+0x827d68>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266ea8+0x827f58>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266ea8+0x84a908>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266ea8+0x859908>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266ea8+0x85bc48>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_625_entry-0x14b760>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266ea8+0x87a3f8>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266ea8+0x87c558>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266ea8+0x87c688>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266ea8+0x87f518>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266ea8+0x8a1038>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266ea8+0x8a12e8>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266ea8+0x8a1688>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266ea8+0x8a1968>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266ea8+0x8a27f8>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266ea8+0x8a4648>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_625_entry-0x76dc0>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_625_entry-0x75e50>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_625_entry-0x14a500>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266ea8+0x8d4288>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266ea8+0x8e0b98>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266ea8+0x8e9518>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266ea8+0x8ea068>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266ea8+0x8ea108>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266ea8+0x8ea208>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266ea8+0x8ea2e8>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266ea8+0x8ea3e8>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266ea8+0x8ea428>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266ea8+0x8ea478>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266ea8+0x8ef9f8>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_625_entry-0x1cbdd0>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266ea8+0x903fc8>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266ea8+0x904ce8>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266ea8+0x906ad8>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266ea8+0x906bf8>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266ea8+0x9072d8>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266ea8+0x90a478>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266ea8+0x90a4c8>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266ea8+0x90a518>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266ea8+0x90a568>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266ea8+0x90aab8>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266ea8+0x90ab28>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266ea8+0x90ab98>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266ea8+0x90ac08>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8afc3c90, handler_body_625; REA Evidence ev_2d905ee9ac2d33a312e148624fc63002082ebeae52e3ecaf9124455c53106945
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8afc3c90", "end": "0xffffffff8afc3cd7"}, {"start": "0xffffffff8afc43be", "end": "0xffffffff8afc43c7"}], "total_bytes": 82, "span_bytes": 1848, "non_contiguous": true, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_625:
0xffffffff8afc3c90: PUSH RBP
0xffffffff8afc3c91: MOV RBP, RSP
0xffffffff8afc3c94: PUSH R15
0xffffffff8afc3c96: PUSH R14
0xffffffff8afc3c98: PUSH R13
0xffffffff8afc3c9a: PUSH R12
0xffffffff8afc3c9c: PUSH RBX
0xffffffff8afc3c9d: SUB RSP, 0x48
0xffffffff8afc3ca1: MOV EAX, dword ptr [RSI]
0xffffffff8afc3ca3: DEC EAX
0xffffffff8afc3ca5: CMP EAX, 0x16
0xffffffff8afc3ca8: JA 0xffffffff8afc43be
loc_ffffffff8afc3cae:
0xffffffff8afc3cae: LEA RCX, [-0x73f1caa0]
0xffffffff8afc3cb5: MOV R14D, dword ptr [RSI + 0x10]
0xffffffff8afc3cb9: MOV EBX, 0x6
0xffffffff8afc3cbe: MOVSXD RAX, dword ptr [RCX + RAX*0x4]
0xffffffff8afc3cc2: ADD RAX, RCX
0xffffffff8afc3cc5: JMP RAX
loc_ffffffff8afc3cc7:
0xffffffff8afc3cc7: MOV EAX, EBX
0xffffffff8afc3cc9: ADD RSP, 0x48
0xffffffff8afc3ccd: POP RBX
0xffffffff8afc3cce: POP R12
0xffffffff8afc3cd0: POP R13
0xffffffff8afc3cd2: POP R14
0xffffffff8afc3cd4: POP R15
0xffffffff8afc3cd6: POP RBP
0xffffffff8afc3cd7: RET
loc_ffffffff8afc43be:
0xffffffff8afc43be: MOV EBX, 0x16
0xffffffff8afc43c3: JMP 0xffffffff8afc3cc7
; END FUNCTION handler_body_625

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_0fbd3f7e8266a3fd791ebb08fb7863886b56e92e210d1a37b765a053b69a97dc
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_625.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8afc3c90 <handler_625_body>:
ffffffff8afc3c90:	55                   	push   %rbp
ffffffff8afc3c91:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc3c94:	41 57                	push   %r15
ffffffff8afc3c96:	41 56                	push   %r14
ffffffff8afc3c98:	41 55                	push   %r13
ffffffff8afc3c9a:	41 54                	push   %r12
ffffffff8afc3c9c:	53                   	push   %rbx
ffffffff8afc3c9d:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8afc3ca1:	8b 06                	mov    (%rsi),%eax
ffffffff8afc3ca3:	ff c8                	dec    %eax
ffffffff8afc3ca5:	83 f8 16             	cmp    $0x16,%eax
ffffffff8afc3ca8:	0f 87 10 07 00 00    	ja     ffffffff8afc43be <handler_625_body+0x72e>
ffffffff8afc3cae:	48 8d 0d ab f8 11 01 	lea    0x111f8ab(%rip),%rcx        # ffffffff8c0e3560 <frame_candidate_605c40+0x111d920>
ffffffff8afc3cb5:	44 8b 76 10          	mov    0x10(%rsi),%r14d
ffffffff8afc3cb9:	bb 06 00 00 00       	mov    $0x6,%ebx
ffffffff8afc3cbe:	48 63 04 81          	movslq (%rcx,%rax,4),%rax
ffffffff8afc3cc2:	48 01 c8             	add    %rcx,%rax
ffffffff8afc3cc5:	ff e0                	jmp    *%rax
ffffffff8afc3cc7:	89 d8                	mov    %ebx,%eax
ffffffff8afc3cc9:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8afc3ccd:	5b                   	pop    %rbx
ffffffff8afc3cce:	41 5c                	pop    %r12
ffffffff8afc3cd0:	41 5d                	pop    %r13
ffffffff8afc3cd2:	41 5e                	pop    %r14
ffffffff8afc3cd4:	41 5f                	pop    %r15
ffffffff8afc3cd6:	5d                   	pop    %rbp
ffffffff8afc3cd7:	c3                   	ret
ffffffff8afc3cd8:	44 0b 76 08          	or     0x8(%rsi),%r14d
ffffffff8afc3cdc:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc3ce1:	75 e4                	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3ce3:	31 c0                	xor    %eax,%eax
ffffffff8afc3ce5:	48 83 7e 18 00       	cmpq   $0x0,0x18(%rsi)
ffffffff8afc3cea:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc3cef:	0f 44 d8             	cmove  %eax,%ebx
ffffffff8afc3cf2:	eb d3                	jmp    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3cf4:	49 89 f7             	mov    %rsi,%r15
ffffffff8afc3cf7:	e8 14 6b 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc3cfc:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc3d01:	72 11                	jb     ffffffff8afc3d14 <handler_625_body+0x84>
ffffffff8afc3d03:	e8 08 6b 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc3d08:	b9 07 00 00 00       	mov    $0x7,%ecx
ffffffff8afc3d0d:	3d e0 0f 84 00       	cmp    $0x840fe0,%eax
ffffffff8afc3d12:	72 05                	jb     ffffffff8afc3d19 <handler_625_body+0x89>
ffffffff8afc3d14:	b9 03 00 00 00       	mov    $0x3,%ecx
ffffffff8afc3d19:	41 83 7f 08 00       	cmpl   $0x0,0x8(%r15)
ffffffff8afc3d1e:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc3d23:	75 a2                	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3d25:	41 83 fe ff          	cmp    $0xffffffff,%r14d
ffffffff8afc3d29:	0f 9c c0             	setl   %al
ffffffff8afc3d2c:	41 39 ce             	cmp    %ecx,%r14d
ffffffff8afc3d2f:	0f 9f c1             	setg   %cl
ffffffff8afc3d32:	08 c1                	or     %al,%cl
ffffffff8afc3d34:	75 91                	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3d36:	49 8b 77 18          	mov    0x18(%r15),%rsi
ffffffff8afc3d3a:	44 89 f7             	mov    %r14d,%edi
ffffffff8afc3d3d:	e8 0e 0f 00 00       	call   ffffffff8afc4c50 <frame_candidate_604c50>
ffffffff8afc3d42:	31 db                	xor    %ebx,%ebx
ffffffff8afc3d44:	eb 81                	jmp    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3d46:	44 0b 76 08          	or     0x8(%rsi),%r14d
ffffffff8afc3d4a:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc3d4f:	0f 85 72 ff ff ff    	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3d55:	48 83 7e 18 00       	cmpq   $0x0,0x18(%rsi)
ffffffff8afc3d5a:	0f 85 67 ff ff ff    	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3d60:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8afc3d64:	5b                   	pop    %rbx
ffffffff8afc3d65:	41 5c                	pop    %r12
ffffffff8afc3d67:	41 5d                	pop    %r13
ffffffff8afc3d69:	41 5e                	pop    %r14
ffffffff8afc3d6b:	41 5f                	pop    %r15
ffffffff8afc3d6d:	5d                   	pop    %rbp
ffffffff8afc3d6e:	e9 8d c0 37 00       	jmp    ffffffff8b33fe00 <frame_candidate_605c40+0x37a1c0>
ffffffff8afc3d73:	8b 4e 08             	mov    0x8(%rsi),%ecx
ffffffff8afc3d76:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc3d7b:	8d 41 fc             	lea    -0x4(%rcx),%eax
ffffffff8afc3d7e:	83 f8 fd             	cmp    $0xfffffffd,%eax
ffffffff8afc3d81:	0f 82 40 ff ff ff    	jb     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3d87:	41 be 00 00 00 00    	mov    $0x0,%r14d
ffffffff8afc3d8d:	31 db                	xor    %ebx,%ebx
ffffffff8afc3d8f:	f6 c1 01             	test   $0x1,%cl
ffffffff8afc3d92:	0f 84 dc 06 00 00    	je     ffffffff8afc4474 <handler_625_body+0x7e4>
ffffffff8afc3d98:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
ffffffff8afc3d9c:	48 8d 15 ae 77 ca 00 	lea    0xca77ae(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc3da3:	b9 6b 03 00 00       	mov    $0x36b,%ecx
ffffffff8afc3da8:	45 31 f6             	xor    %r14d,%r14d
ffffffff8afc3dab:	31 f6                	xor    %esi,%esi
ffffffff8afc3dad:	65 4c 8b 3c 25 00 00 	mov    %gs:0x0,%r15
ffffffff8afc3db4:	00 00 
ffffffff8afc3db6:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc3db9:	e8 f2 3a ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc3dbe:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc3dc5:	00 
ffffffff8afc3dc6:	89 45 a4             	mov    %eax,-0x5c(%rbp)
ffffffff8afc3dc9:	83 f8 07             	cmp    $0x7,%eax
ffffffff8afc3dcc:	77 13                	ja     ffffffff8afc3de1 <handler_625_body+0x151>
ffffffff8afc3dce:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc3dd1:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc3dd6:	e8 e5 39 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc3ddb:	41 be 01 00 00 00    	mov    $0x1,%r14d
ffffffff8afc3de1:	4c 89 7d 98          	mov    %r15,-0x68(%rbp)
ffffffff8afc3de5:	44 89 75 cc          	mov    %r14d,-0x34(%rbp)
ffffffff8afc3de9:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc3dee:	0f 32                	rdmsr
ffffffff8afc3df0:	89 d6                	mov    %edx,%esi
ffffffff8afc3df2:	89 c0                	mov    %eax,%eax
ffffffff8afc3df4:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc3df9:	48 c1 e6 20          	shl    $0x20,%rsi
ffffffff8afc3dfd:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8afc3e01:	48 09 c6             	or     %rax,%rsi
ffffffff8afc3e04:	0f 32                	rdmsr
ffffffff8afc3e06:	89 d7                	mov    %edx,%edi
ffffffff8afc3e08:	41 89 c7             	mov    %eax,%r15d
ffffffff8afc3e0b:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc3e10:	0f 32                	rdmsr
ffffffff8afc3e12:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc3e15:	41 89 c4             	mov    %eax,%r12d
ffffffff8afc3e18:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc3e1d:	0f 32                	rdmsr
ffffffff8afc3e1f:	41 89 d1             	mov    %edx,%r9d
ffffffff8afc3e22:	41 89 c5             	mov    %eax,%r13d
ffffffff8afc3e25:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc3e2a:	0f 32                	rdmsr
ffffffff8afc3e2c:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc3e2f:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc3e32:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc3e37:	0f 32                	rdmsr
ffffffff8afc3e39:	0f b6 4d d0          	movzbl -0x30(%rbp),%ecx
ffffffff8afc3e3d:	41 89 d3             	mov    %edx,%r11d
ffffffff8afc3e40:	89 c0                	mov    %eax,%eax
ffffffff8afc3e42:	48 c1 e7 20          	shl    $0x20,%rdi
ffffffff8afc3e46:	49 c1 e0 20          	shl    $0x20,%r8
ffffffff8afc3e4a:	49 c1 e1 20          	shl    $0x20,%r9
ffffffff8afc3e4e:	49 c1 e2 20          	shl    $0x20,%r10
ffffffff8afc3e52:	49 c1 e3 20          	shl    $0x20,%r11
ffffffff8afc3e56:	4c 09 ff             	or     %r15,%rdi
ffffffff8afc3e59:	4d 09 e0             	or     %r12,%r8
ffffffff8afc3e5c:	4d 09 e9             	or     %r13,%r9
ffffffff8afc3e5f:	4d 09 f2             	or     %r14,%r10
ffffffff8afc3e62:	49 09 c3             	or     %rax,%r11
ffffffff8afc3e65:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
ffffffff8afc3e69:	41 0f b6 cf          	movzbl %r15b,%ecx
ffffffff8afc3e6d:	45 0f b6 fe          	movzbl %r14b,%r15d
ffffffff8afc3e71:	45 31 f6             	xor    %r14d,%r14d
ffffffff8afc3e74:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
ffffffff8afc3e78:	41 0f b6 cc          	movzbl %r12b,%ecx
ffffffff8afc3e7c:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8afc3e80:	41 0f b6 cd          	movzbl %r13b,%ecx
ffffffff8afc3e84:	44 0f b6 e8          	movzbl %al,%r13d
ffffffff8afc3e88:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8afc3e8c:	eb 10                	jmp    ffffffff8afc3e9e <handler_625_body+0x20e>
ffffffff8afc3e8e:	66 90                	xchg   %ax,%ax
ffffffff8afc3e90:	49 83 c6 02          	add    $0x2,%r14
ffffffff8afc3e94:	49 83 fe 1a          	cmp    $0x1a,%r14
ffffffff8afc3e98:	0f 84 2a 05 00 00    	je     ffffffff8afc43c8 <handler_625_body+0x738>
ffffffff8afc3e9e:	48 8d 05 3b f7 11 01 	lea    0x111f73b(%rip),%rax        # ffffffff8c0e35e0 <frame_candidate_605c40+0x111d9a0>
ffffffff8afc3ea5:	45 0f b7 24 06       	movzwl (%r14,%rax,1),%r12d
ffffffff8afc3eaa:	44 39 65 d0          	cmp    %r12d,-0x30(%rbp)
ffffffff8afc3eae:	74 29                	je     ffffffff8afc3ed9 <handler_625_body+0x249>
ffffffff8afc3eb0:	44 39 65 c0          	cmp    %r12d,-0x40(%rbp)
ffffffff8afc3eb4:	74 48                	je     ffffffff8afc3efe <handler_625_body+0x26e>
ffffffff8afc3eb6:	44 39 65 b8          	cmp    %r12d,-0x48(%rbp)
ffffffff8afc3eba:	74 67                	je     ffffffff8afc3f23 <handler_625_body+0x293>
ffffffff8afc3ebc:	44 39 65 b0          	cmp    %r12d,-0x50(%rbp)
ffffffff8afc3ec0:	0f 84 87 00 00 00    	je     ffffffff8afc3f4d <handler_625_body+0x2bd>
ffffffff8afc3ec6:	45 39 e7             	cmp    %r12d,%r15d
ffffffff8afc3ec9:	0f 84 a7 00 00 00    	je     ffffffff8afc3f76 <handler_625_body+0x2e6>
ffffffff8afc3ecf:	45 39 e5             	cmp    %r12d,%r13d
ffffffff8afc3ed2:	75 bc                	jne    ffffffff8afc3e90 <handler_625_body+0x200>
ffffffff8afc3ed4:	e9 c6 00 00 00       	jmp    ffffffff8afc3f9f <handler_625_body+0x30f>
ffffffff8afc3ed9:	48 89 f0             	mov    %rsi,%rax
ffffffff8afc3edc:	48 c1 ee 20          	shr    $0x20,%rsi
ffffffff8afc3ee0:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc3ee5:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc3eeb:	89 f2                	mov    %esi,%edx
ffffffff8afc3eed:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc3ef3:	0f 30                	wrmsr
ffffffff8afc3ef5:	48 89 c6             	mov    %rax,%rsi
ffffffff8afc3ef8:	44 39 65 c0          	cmp    %r12d,-0x40(%rbp)
ffffffff8afc3efc:	75 b8                	jne    ffffffff8afc3eb6 <handler_625_body+0x226>
ffffffff8afc3efe:	48 89 f8             	mov    %rdi,%rax
ffffffff8afc3f01:	48 c1 ef 20          	shr    $0x20,%rdi
ffffffff8afc3f05:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc3f0a:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc3f10:	89 fa                	mov    %edi,%edx
ffffffff8afc3f12:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc3f18:	0f 30                	wrmsr
ffffffff8afc3f1a:	48 89 c7             	mov    %rax,%rdi
ffffffff8afc3f1d:	44 39 65 b8          	cmp    %r12d,-0x48(%rbp)
ffffffff8afc3f21:	75 99                	jne    ffffffff8afc3ebc <handler_625_body+0x22c>
ffffffff8afc3f23:	4c 89 c0             	mov    %r8,%rax
ffffffff8afc3f26:	49 c1 e8 20          	shr    $0x20,%r8
ffffffff8afc3f2a:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc3f2f:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc3f35:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc3f38:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc3f3e:	0f 30                	wrmsr
ffffffff8afc3f40:	49 89 c0             	mov    %rax,%r8
ffffffff8afc3f43:	44 39 65 b0          	cmp    %r12d,-0x50(%rbp)
ffffffff8afc3f47:	0f 85 79 ff ff ff    	jne    ffffffff8afc3ec6 <handler_625_body+0x236>
ffffffff8afc3f4d:	4c 89 c8             	mov    %r9,%rax
ffffffff8afc3f50:	49 c1 e9 20          	shr    $0x20,%r9
ffffffff8afc3f54:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc3f59:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc3f5f:	44 89 ca             	mov    %r9d,%edx
ffffffff8afc3f62:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc3f68:	0f 30                	wrmsr
ffffffff8afc3f6a:	49 89 c1             	mov    %rax,%r9
ffffffff8afc3f6d:	45 39 e7             	cmp    %r12d,%r15d
ffffffff8afc3f70:	0f 85 59 ff ff ff    	jne    ffffffff8afc3ecf <handler_625_body+0x23f>
ffffffff8afc3f76:	4c 89 d0             	mov    %r10,%rax
ffffffff8afc3f79:	49 c1 ea 20          	shr    $0x20,%r10
ffffffff8afc3f7d:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc3f82:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc3f88:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc3f8b:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc3f91:	0f 30                	wrmsr
ffffffff8afc3f93:	49 89 c2             	mov    %rax,%r10
ffffffff8afc3f96:	45 39 e5             	cmp    %r12d,%r13d
ffffffff8afc3f99:	0f 85 f1 fe ff ff    	jne    ffffffff8afc3e90 <handler_625_body+0x200>
ffffffff8afc3f9f:	4c 89 d8             	mov    %r11,%rax
ffffffff8afc3fa2:	49 c1 eb 20          	shr    $0x20,%r11
ffffffff8afc3fa6:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc3fab:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc3fb1:	44 89 da             	mov    %r11d,%edx
ffffffff8afc3fb4:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc3fba:	0f 30                	wrmsr
ffffffff8afc3fbc:	49 89 c3             	mov    %rax,%r11
ffffffff8afc3fbf:	e9 cc fe ff ff       	jmp    ffffffff8afc3e90 <handler_625_body+0x200>
ffffffff8afc3fc4:	44 8b 7e 08          	mov    0x8(%rsi),%r15d
ffffffff8afc3fc8:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc3fcd:	41 8d 47 fc          	lea    -0x4(%r15),%eax
ffffffff8afc3fd1:	83 f8 fd             	cmp    $0xfffffffd,%eax
ffffffff8afc3fd4:	0f 82 ed fc ff ff    	jb     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc3fda:	41 be 00 00 00 00    	mov    $0x0,%r14d
ffffffff8afc3fe0:	31 db                	xor    %ebx,%ebx
ffffffff8afc3fe2:	41 f6 c7 01          	test   $0x1,%r15b
ffffffff8afc3fe6:	0f 84 34 01 00 00    	je     ffffffff8afc4120 <handler_625_body+0x490>
ffffffff8afc3fec:	65 4c 8b 24 25 00 00 	mov    %gs:0x0,%r12
ffffffff8afc3ff3:	00 00 
ffffffff8afc3ff5:	48 8d 15 55 75 ca 00 	lea    0xca7555(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc3ffc:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc3fff:	b9 27 03 00 00       	mov    $0x327,%ecx
ffffffff8afc4004:	31 f6                	xor    %esi,%esi
ffffffff8afc4006:	45 31 f6             	xor    %r14d,%r14d
ffffffff8afc4009:	e8 a2 38 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc400e:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc4015:	00 
ffffffff8afc4016:	89 45 c0             	mov    %eax,-0x40(%rbp)
ffffffff8afc4019:	83 f8 07             	cmp    $0x7,%eax
ffffffff8afc401c:	77 13                	ja     ffffffff8afc4031 <handler_625_body+0x3a1>
ffffffff8afc401e:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc4021:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc4026:	e8 95 37 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc402b:	41 be 01 00 00 00    	mov    $0x1,%r14d
ffffffff8afc4031:	44 89 75 d0          	mov    %r14d,-0x30(%rbp)
ffffffff8afc4035:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc403a:	0f 32                	rdmsr
ffffffff8afc403c:	4d 89 e1             	mov    %r12,%r9
ffffffff8afc403f:	41 89 c4             	mov    %eax,%r12d
ffffffff8afc4042:	89 55 b8             	mov    %edx,-0x48(%rbp)
ffffffff8afc4045:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc404a:	0f 32                	rdmsr
ffffffff8afc404c:	41 89 c5             	mov    %eax,%r13d
ffffffff8afc404f:	89 55 b0             	mov    %edx,-0x50(%rbp)
ffffffff8afc4052:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc4057:	0f 32                	rdmsr
ffffffff8afc4059:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc405c:	89 55 cc             	mov    %edx,-0x34(%rbp)
ffffffff8afc405f:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc4064:	0f 32                	rdmsr
ffffffff8afc4066:	89 c6                	mov    %eax,%esi
ffffffff8afc4068:	89 55 a8             	mov    %edx,-0x58(%rbp)
ffffffff8afc406b:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc4070:	0f 32                	rdmsr
ffffffff8afc4072:	89 c7                	mov    %eax,%edi
ffffffff8afc4074:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc4077:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc407c:	0f 32                	rdmsr
ffffffff8afc407e:	41 89 c0             	mov    %eax,%r8d
ffffffff8afc4081:	41 89 d3             	mov    %edx,%r11d
ffffffff8afc4084:	8b 55 b8             	mov    -0x48(%rbp),%edx
ffffffff8afc4087:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc408c:	41 81 cc 00 00 40 00 	or     $0x400000,%r12d
ffffffff8afc4093:	41 81 cd 00 00 40 00 	or     $0x400000,%r13d
ffffffff8afc409a:	41 81 ce 00 00 40 00 	or     $0x400000,%r14d
ffffffff8afc40a1:	81 ce 00 00 40 00    	or     $0x400000,%esi
ffffffff8afc40a7:	81 cf 00 00 40 00    	or     $0x400000,%edi
ffffffff8afc40ad:	41 81 c8 00 00 40 00 	or     $0x400000,%r8d
ffffffff8afc40b4:	44 89 e0             	mov    %r12d,%eax
ffffffff8afc40b7:	0f 30                	wrmsr
ffffffff8afc40b9:	44 89 e8             	mov    %r13d,%eax
ffffffff8afc40bc:	8b 55 b0             	mov    -0x50(%rbp),%edx
ffffffff8afc40bf:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc40c4:	0f 30                	wrmsr
ffffffff8afc40c6:	44 89 f0             	mov    %r14d,%eax
ffffffff8afc40c9:	8b 55 cc             	mov    -0x34(%rbp),%edx
ffffffff8afc40cc:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc40d1:	0f 30                	wrmsr
ffffffff8afc40d3:	89 f0                	mov    %esi,%eax
ffffffff8afc40d5:	8b 55 a8             	mov    -0x58(%rbp),%edx
ffffffff8afc40d8:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc40dd:	0f 30                	wrmsr
ffffffff8afc40df:	89 f8                	mov    %edi,%eax
ffffffff8afc40e1:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc40e4:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc40e9:	0f 30                	wrmsr
ffffffff8afc40eb:	44 89 c0             	mov    %r8d,%eax
ffffffff8afc40ee:	44 89 da             	mov    %r11d,%edx
ffffffff8afc40f1:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc40f6:	0f 30                	wrmsr
ffffffff8afc40f8:	83 7d c0 07          	cmpl   $0x7,-0x40(%rbp)
ffffffff8afc40fc:	4d 89 cc             	mov    %r9,%r12
ffffffff8afc40ff:	77 08                	ja     ffffffff8afc4109 <handler_625_body+0x479>
ffffffff8afc4101:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc4104:	e8 57 37 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc4109:	49 8b 3c 24          	mov    (%r12),%rdi
ffffffff8afc410d:	31 f6                	xor    %esi,%esi
ffffffff8afc410f:	31 d2                	xor    %edx,%edx
ffffffff8afc4111:	31 c9                	xor    %ecx,%ecx
ffffffff8afc4113:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc4117:	e8 04 34 ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc411c:	44 8b 75 d0          	mov    -0x30(%rbp),%r14d
ffffffff8afc4120:	41 83 ff 02          	cmp    $0x2,%r15d
ffffffff8afc4124:	0f 82 9d fb ff ff    	jb     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc412a:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc4131:	00 00 
ffffffff8afc4133:	48 8d 15 17 74 ca 00 	lea    0xca7417(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc413a:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc413d:	b9 41 03 00 00       	mov    $0x341,%ecx
ffffffff8afc4142:	31 f6                	xor    %esi,%esi
ffffffff8afc4144:	e8 67 37 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc4149:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc4150:	00 
ffffffff8afc4151:	83 f8 08             	cmp    $0x8,%eax
ffffffff8afc4154:	72 10                	jb     ffffffff8afc4166 <handler_625_body+0x4d6>
ffffffff8afc4156:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc4159:	31 f6                	xor    %esi,%esi
ffffffff8afc415b:	e8 60 36 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc4160:	41 be 01 00 00 00    	mov    $0x1,%r14d
ffffffff8afc4166:	44 89 75 d0          	mov    %r14d,-0x30(%rbp)
ffffffff8afc416a:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc416f:	0f 32                	rdmsr
ffffffff8afc4171:	41 89 c7             	mov    %eax,%r15d
ffffffff8afc4174:	89 55 c0             	mov    %edx,-0x40(%rbp)
ffffffff8afc4177:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc417c:	0f 32                	rdmsr
ffffffff8afc417e:	41 89 c4             	mov    %eax,%r12d
ffffffff8afc4181:	89 55 b8             	mov    %edx,-0x48(%rbp)
ffffffff8afc4184:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc4189:	0f 32                	rdmsr
ffffffff8afc418b:	41 89 c5             	mov    %eax,%r13d
ffffffff8afc418e:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc4191:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc4196:	0f 32                	rdmsr
ffffffff8afc4198:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc419b:	89 c3                	mov    %eax,%ebx
ffffffff8afc419d:	41 89 d1             	mov    %edx,%r9d
ffffffff8afc41a0:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc41a5:	0f 32                	rdmsr
ffffffff8afc41a7:	89 c6                	mov    %eax,%esi
ffffffff8afc41a9:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc41ac:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc41b1:	0f 32                	rdmsr
ffffffff8afc41b3:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc41b6:	41 89 d3             	mov    %edx,%r11d
ffffffff8afc41b9:	8b 55 c0             	mov    -0x40(%rbp),%edx
ffffffff8afc41bc:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc41c1:	41 81 cf 00 00 40 00 	or     $0x400000,%r15d
ffffffff8afc41c8:	41 81 cc 00 00 40 00 	or     $0x400000,%r12d
ffffffff8afc41cf:	41 81 cd 00 00 40 00 	or     $0x400000,%r13d
ffffffff8afc41d6:	81 cb 00 00 40 00    	or     $0x400000,%ebx
ffffffff8afc41dc:	81 ce 00 00 40 00    	or     $0x400000,%esi
ffffffff8afc41e2:	41 81 ce 00 00 40 00 	or     $0x400000,%r14d
ffffffff8afc41e9:	44 89 f8             	mov    %r15d,%eax
ffffffff8afc41ec:	0f 30                	wrmsr
ffffffff8afc41ee:	44 89 e0             	mov    %r12d,%eax
ffffffff8afc41f1:	8b 55 b8             	mov    -0x48(%rbp),%edx
ffffffff8afc41f4:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc41f9:	0f 30                	wrmsr
ffffffff8afc41fb:	44 89 e8             	mov    %r13d,%eax
ffffffff8afc41fe:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4201:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc4206:	0f 30                	wrmsr
ffffffff8afc4208:	89 d8                	mov    %ebx,%eax
ffffffff8afc420a:	44 89 ca             	mov    %r9d,%edx
ffffffff8afc420d:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc4212:	0f 30                	wrmsr
ffffffff8afc4214:	89 f0                	mov    %esi,%eax
ffffffff8afc4216:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4219:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc421e:	0f 30                	wrmsr
ffffffff8afc4220:	44 89 f0             	mov    %r14d,%eax
ffffffff8afc4223:	44 89 da             	mov    %r11d,%edx
ffffffff8afc4226:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc422b:	0f 30                	wrmsr
ffffffff8afc422d:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
ffffffff8afc4231:	48 89 fb             	mov    %rdi,%rbx
ffffffff8afc4234:	0f 85 e2 04 00 00    	jne    ffffffff8afc471c <handler_625_body+0xa8c>
ffffffff8afc423a:	e9 e5 04 00 00       	jmp    ffffffff8afc4724 <handler_625_body+0xa94>
ffffffff8afc423f:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc4244:	41 83 fe 05          	cmp    $0x5,%r14d
ffffffff8afc4248:	0f 87 79 fa ff ff    	ja     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc424e:	8b 7e 08             	mov    0x8(%rsi),%edi
ffffffff8afc4251:	8d 47 fc             	lea    -0x4(%rdi),%eax
ffffffff8afc4254:	83 f8 fd             	cmp    $0xfffffffd,%eax
ffffffff8afc4257:	0f 82 6a fa ff ff    	jb     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc425d:	48 8b 56 18          	mov    0x18(%rsi),%rdx
ffffffff8afc4261:	44 89 f6             	mov    %r14d,%esi
ffffffff8afc4264:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8afc4268:	5b                   	pop    %rbx
ffffffff8afc4269:	41 5c                	pop    %r12
ffffffff8afc426b:	41 5d                	pop    %r13
ffffffff8afc426d:	41 5e                	pop    %r14
ffffffff8afc426f:	41 5f                	pop    %r15
ffffffff8afc4271:	5d                   	pop    %rbp
ffffffff8afc4272:	e9 c9 05 00 00       	jmp    ffffffff8afc4840 <frame_candidate_604840>
ffffffff8afc4277:	44 8b 6e 08          	mov    0x8(%rsi),%r13d
ffffffff8afc427b:	41 8d 4e fa          	lea    -0x6(%r14),%ecx
ffffffff8afc427f:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc4284:	41 8d 45 fc          	lea    -0x4(%r13),%eax
ffffffff8afc4288:	83 f8 fd             	cmp    $0xfffffffd,%eax
ffffffff8afc428b:	0f 92 c0             	setb   %al
ffffffff8afc428e:	83 f9 f9             	cmp    $0xfffffff9,%ecx
ffffffff8afc4291:	0f 92 c1             	setb   %cl
ffffffff8afc4294:	08 c1                	or     %al,%cl
ffffffff8afc4296:	0f 85 2b fa ff ff    	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc429c:	4c 8b 7e 18          	mov    0x18(%rsi),%r15
ffffffff8afc42a0:	41 bc 00 00 00 00    	mov    $0x0,%r12d
ffffffff8afc42a6:	31 db                	xor    %ebx,%ebx
ffffffff8afc42a8:	41 f6 c5 01          	test   $0x1,%r13b
ffffffff8afc42ac:	0f 84 e3 04 00 00    	je     ffffffff8afc4795 <handler_625_body+0xb05>
ffffffff8afc42b2:	65 4c 8b 24 25 00 00 	mov    %gs:0x0,%r12
ffffffff8afc42b9:	00 00 
ffffffff8afc42bb:	48 8d 15 8f 72 ca 00 	lea    0xca728f(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc42c2:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc42c5:	b9 f5 03 00 00       	mov    $0x3f5,%ecx
ffffffff8afc42ca:	31 f6                	xor    %esi,%esi
ffffffff8afc42cc:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
ffffffff8afc42d3:	e8 d8 35 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc42d8:	65 8b 34 25 34 00 00 	mov    %gs:0x34,%esi
ffffffff8afc42df:	00 
ffffffff8afc42e0:	83 fe 07             	cmp    $0x7,%esi
ffffffff8afc42e3:	77 1a                	ja     ffffffff8afc42ff <handler_625_body+0x66f>
ffffffff8afc42e5:	89 75 c0             	mov    %esi,-0x40(%rbp)
ffffffff8afc42e8:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc42eb:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc42f0:	e8 cb 34 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc42f5:	8b 75 c0             	mov    -0x40(%rbp),%esi
ffffffff8afc42f8:	c7 45 d0 01 00 00 00 	movl   $0x1,-0x30(%rbp)
ffffffff8afc42ff:	41 83 fe ff          	cmp    $0xffffffff,%r14d
ffffffff8afc4303:	0f 84 34 04 00 00    	je     ffffffff8afc473d <handler_625_body+0xaad>
ffffffff8afc4309:	4c 89 fa             	mov    %r15,%rdx
ffffffff8afc430c:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc4313:	c0 
ffffffff8afc4314:	44 89 f8             	mov    %r15d,%eax
ffffffff8afc4317:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc431b:	0f 30                	wrmsr
ffffffff8afc431d:	e9 4f 04 00 00       	jmp    ffffffff8afc4771 <handler_625_body+0xae1>
ffffffff8afc4322:	49 89 f7             	mov    %rsi,%r15
ffffffff8afc4325:	e8 e6 64 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc432a:	b9 03 00 00 00       	mov    $0x3,%ecx
ffffffff8afc432f:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc4334:	72 16                	jb     ffffffff8afc434c <handler_625_body+0x6bc>
ffffffff8afc4336:	e8 d5 64 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc433b:	31 c9                	xor    %ecx,%ecx
ffffffff8afc433d:	3d e0 0f 84 00       	cmp    $0x840fe0,%eax
ffffffff8afc4342:	0f 92 c1             	setb   %cl
ffffffff8afc4345:	8d 0c 8d 03 00 00 00 	lea    0x3(,%rcx,4),%ecx
ffffffff8afc434c:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc4351:	45 85 f6             	test   %r14d,%r14d
ffffffff8afc4354:	0f 88 6d f9 ff ff    	js     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc435a:	41 39 ce             	cmp    %ecx,%r14d
ffffffff8afc435d:	0f 87 64 f9 ff ff    	ja     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc4363:	41 83 7f 08 00       	cmpl   $0x0,0x8(%r15)
ffffffff8afc4368:	0f 85 59 f9 ff ff    	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc436e:	49 8b 77 18          	mov    0x18(%r15),%rsi
ffffffff8afc4372:	44 89 f7             	mov    %r14d,%edi
ffffffff8afc4375:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8afc4379:	5b                   	pop    %rbx
ffffffff8afc437a:	41 5c                	pop    %r12
ffffffff8afc437c:	41 5d                	pop    %r13
ffffffff8afc437e:	41 5e                	pop    %r14
ffffffff8afc4380:	41 5f                	pop    %r15
ffffffff8afc4382:	5d                   	pop    %rbp
ffffffff8afc4383:	e9 08 06 00 00       	jmp    ffffffff8afc4990 <frame_candidate_604990>
ffffffff8afc4388:	83 7e 08 00          	cmpl   $0x0,0x8(%rsi)
ffffffff8afc438c:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc4391:	0f 85 30 f9 ff ff    	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc4397:	e8 84 07 00 00       	call   ffffffff8afc4b20 <frame_candidate_604b20>
ffffffff8afc439c:	31 db                	xor    %ebx,%ebx
ffffffff8afc439e:	e9 24 f9 ff ff       	jmp    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc43a3:	83 7e 08 00          	cmpl   $0x0,0x8(%rsi)
ffffffff8afc43a7:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc43ac:	0f 85 15 f9 ff ff    	jne    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc43b2:	e8 39 06 00 00       	call   ffffffff8afc49f0 <frame_candidate_6049f0>
ffffffff8afc43b7:	31 db                	xor    %ebx,%ebx
ffffffff8afc43b9:	e9 09 f9 ff ff       	jmp    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc43be:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8afc43c3:	e9 ff f8 ff ff       	jmp    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc43c8:	89 f0                	mov    %esi,%eax
ffffffff8afc43ca:	48 c1 ee 20          	shr    $0x20,%rsi
ffffffff8afc43ce:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc43d3:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc43d8:	89 f2                	mov    %esi,%edx
ffffffff8afc43da:	0f 30                	wrmsr
ffffffff8afc43dc:	89 f8                	mov    %edi,%eax
ffffffff8afc43de:	48 c1 ef 20          	shr    $0x20,%rdi
ffffffff8afc43e2:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc43e7:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc43ec:	89 fa                	mov    %edi,%edx
ffffffff8afc43ee:	0f 30                	wrmsr
ffffffff8afc43f0:	44 89 c0             	mov    %r8d,%eax
ffffffff8afc43f3:	49 c1 e8 20          	shr    $0x20,%r8
ffffffff8afc43f7:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc43fc:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc4401:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4404:	0f 30                	wrmsr
ffffffff8afc4406:	44 89 c8             	mov    %r9d,%eax
ffffffff8afc4409:	49 c1 e9 20          	shr    $0x20,%r9
ffffffff8afc440d:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc4412:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc4417:	44 89 ca             	mov    %r9d,%edx
ffffffff8afc441a:	0f 30                	wrmsr
ffffffff8afc441c:	44 89 d0             	mov    %r10d,%eax
ffffffff8afc441f:	49 c1 ea 20          	shr    $0x20,%r10
ffffffff8afc4423:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc4428:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc442d:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4430:	0f 30                	wrmsr
ffffffff8afc4432:	44 89 d8             	mov    %r11d,%eax
ffffffff8afc4435:	49 c1 eb 20          	shr    $0x20,%r11
ffffffff8afc4439:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc443e:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc4443:	44 89 da             	mov    %r11d,%edx
ffffffff8afc4446:	0f 30                	wrmsr
ffffffff8afc4448:	83 7d a4 07          	cmpl   $0x7,-0x5c(%rbp)
ffffffff8afc444c:	4c 8b 75 98          	mov    -0x68(%rbp),%r14
ffffffff8afc4450:	77 08                	ja     ffffffff8afc445a <handler_625_body+0x7ca>
ffffffff8afc4452:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc4455:	e8 06 34 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc445a:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8afc445d:	31 f6                	xor    %esi,%esi
ffffffff8afc445f:	31 d2                	xor    %edx,%edx
ffffffff8afc4461:	31 c9                	xor    %ecx,%ecx
ffffffff8afc4463:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc4467:	e8 b4 30 ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc446c:	44 8b 75 cc          	mov    -0x34(%rbp),%r14d
ffffffff8afc4470:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
ffffffff8afc4474:	83 f9 02             	cmp    $0x2,%ecx
ffffffff8afc4477:	0f 82 4a f8 ff ff    	jb     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc447d:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc4484:	00 00 
ffffffff8afc4486:	48 8d 15 c4 70 ca 00 	lea    0xca70c4(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc448d:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc4490:	b9 ad 03 00 00       	mov    $0x3ad,%ecx
ffffffff8afc4495:	31 f6                	xor    %esi,%esi
ffffffff8afc4497:	e8 14 34 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc449c:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc44a3:	00 
ffffffff8afc44a4:	83 f8 08             	cmp    $0x8,%eax
ffffffff8afc44a7:	72 10                	jb     ffffffff8afc44b9 <handler_625_body+0x829>
ffffffff8afc44a9:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc44ac:	31 f6                	xor    %esi,%esi
ffffffff8afc44ae:	e8 0d 33 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc44b3:	41 be 01 00 00 00    	mov    $0x1,%r14d
ffffffff8afc44b9:	48 89 5d b0          	mov    %rbx,-0x50(%rbp)
ffffffff8afc44bd:	44 89 75 cc          	mov    %r14d,-0x34(%rbp)
ffffffff8afc44c1:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc44c6:	0f 32                	rdmsr
ffffffff8afc44c8:	41 89 c5             	mov    %eax,%r13d
ffffffff8afc44cb:	89 d6                	mov    %edx,%esi
ffffffff8afc44cd:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc44d2:	0f 32                	rdmsr
ffffffff8afc44d4:	89 d7                	mov    %edx,%edi
ffffffff8afc44d6:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc44d9:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc44de:	0f 32                	rdmsr
ffffffff8afc44e0:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc44e3:	41 89 c7             	mov    %eax,%r15d
ffffffff8afc44e6:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc44eb:	0f 32                	rdmsr
ffffffff8afc44ed:	41 89 d1             	mov    %edx,%r9d
ffffffff8afc44f0:	41 89 c4             	mov    %eax,%r12d
ffffffff8afc44f3:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc44f8:	0f 32                	rdmsr
ffffffff8afc44fa:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc44fd:	89 c3                	mov    %eax,%ebx
ffffffff8afc44ff:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc4504:	0f 32                	rdmsr
ffffffff8afc4506:	41 89 d3             	mov    %edx,%r11d
ffffffff8afc4509:	89 c0                	mov    %eax,%eax
ffffffff8afc450b:	41 0f b6 cd          	movzbl %r13b,%ecx
ffffffff8afc450f:	48 c1 e6 20          	shl    $0x20,%rsi
ffffffff8afc4513:	48 c1 e7 20          	shl    $0x20,%rdi
ffffffff8afc4517:	49 c1 e0 20          	shl    $0x20,%r8
ffffffff8afc451b:	49 c1 e1 20          	shl    $0x20,%r9
ffffffff8afc451f:	49 c1 e2 20          	shl    $0x20,%r10
ffffffff8afc4523:	49 c1 e3 20          	shl    $0x20,%r11
ffffffff8afc4527:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
ffffffff8afc452b:	41 0f b6 ce          	movzbl %r14b,%ecx
ffffffff8afc452f:	4c 09 ee             	or     %r13,%rsi
ffffffff8afc4532:	4c 09 f7             	or     %r14,%rdi
ffffffff8afc4535:	49 09 da             	or     %rbx,%r10
ffffffff8afc4538:	4d 09 f8             	or     %r15,%r8
ffffffff8afc453b:	4d 09 e1             	or     %r12,%r9
ffffffff8afc453e:	49 09 c3             	or     %rax,%r11
ffffffff8afc4541:	45 0f b6 ec          	movzbl %r12b,%r13d
ffffffff8afc4545:	0f b6 db             	movzbl %bl,%ebx
ffffffff8afc4548:	44 0f b6 f0          	movzbl %al,%r14d
ffffffff8afc454c:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
ffffffff8afc4550:	41 0f b6 cf          	movzbl %r15b,%ecx
ffffffff8afc4554:	45 31 ff             	xor    %r15d,%r15d
ffffffff8afc4557:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8afc455b:	eb 11                	jmp    ffffffff8afc456e <handler_625_body+0x8de>
ffffffff8afc455d:	0f 1f 00             	nopl   (%rax)
ffffffff8afc4560:	49 83 c7 02          	add    $0x2,%r15
ffffffff8afc4564:	49 83 ff 1a          	cmp    $0x1a,%r15
ffffffff8afc4568:	0f 84 24 01 00 00    	je     ffffffff8afc4692 <handler_625_body+0xa02>
ffffffff8afc456e:	48 8d 05 6b f0 11 01 	lea    0x111f06b(%rip),%rax        # ffffffff8c0e35e0 <frame_candidate_605c40+0x111d9a0>
ffffffff8afc4575:	45 0f b7 24 07       	movzwl (%r15,%rax,1),%r12d
ffffffff8afc457a:	44 39 65 d0          	cmp    %r12d,-0x30(%rbp)
ffffffff8afc457e:	74 28                	je     ffffffff8afc45a8 <handler_625_body+0x918>
ffffffff8afc4580:	44 39 65 c0          	cmp    %r12d,-0x40(%rbp)
ffffffff8afc4584:	74 47                	je     ffffffff8afc45cd <handler_625_body+0x93d>
ffffffff8afc4586:	44 39 65 b8          	cmp    %r12d,-0x48(%rbp)
ffffffff8afc458a:	74 66                	je     ffffffff8afc45f2 <handler_625_body+0x962>
ffffffff8afc458c:	45 39 e5             	cmp    %r12d,%r13d
ffffffff8afc458f:	0f 84 86 00 00 00    	je     ffffffff8afc461b <handler_625_body+0x98b>
ffffffff8afc4595:	44 39 e3             	cmp    %r12d,%ebx
ffffffff8afc4598:	0f 84 a6 00 00 00    	je     ffffffff8afc4644 <handler_625_body+0x9b4>
ffffffff8afc459e:	45 39 e6             	cmp    %r12d,%r14d
ffffffff8afc45a1:	75 bd                	jne    ffffffff8afc4560 <handler_625_body+0x8d0>
ffffffff8afc45a3:	e9 c5 00 00 00       	jmp    ffffffff8afc466d <handler_625_body+0x9dd>
ffffffff8afc45a8:	48 89 f0             	mov    %rsi,%rax
ffffffff8afc45ab:	48 c1 ee 20          	shr    $0x20,%rsi
ffffffff8afc45af:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc45b4:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc45ba:	89 f2                	mov    %esi,%edx
ffffffff8afc45bc:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc45c2:	0f 30                	wrmsr
ffffffff8afc45c4:	48 89 c6             	mov    %rax,%rsi
ffffffff8afc45c7:	44 39 65 c0          	cmp    %r12d,-0x40(%rbp)
ffffffff8afc45cb:	75 b9                	jne    ffffffff8afc4586 <handler_625_body+0x8f6>
ffffffff8afc45cd:	48 89 f8             	mov    %rdi,%rax
ffffffff8afc45d0:	48 c1 ef 20          	shr    $0x20,%rdi
ffffffff8afc45d4:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc45d9:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc45df:	89 fa                	mov    %edi,%edx
ffffffff8afc45e1:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc45e7:	0f 30                	wrmsr
ffffffff8afc45e9:	48 89 c7             	mov    %rax,%rdi
ffffffff8afc45ec:	44 39 65 b8          	cmp    %r12d,-0x48(%rbp)
ffffffff8afc45f0:	75 9a                	jne    ffffffff8afc458c <handler_625_body+0x8fc>
ffffffff8afc45f2:	4c 89 c0             	mov    %r8,%rax
ffffffff8afc45f5:	49 c1 e8 20          	shr    $0x20,%r8
ffffffff8afc45f9:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc45fe:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc4604:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4607:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc460d:	0f 30                	wrmsr
ffffffff8afc460f:	49 89 c0             	mov    %rax,%r8
ffffffff8afc4612:	45 39 e5             	cmp    %r12d,%r13d
ffffffff8afc4615:	0f 85 7a ff ff ff    	jne    ffffffff8afc4595 <handler_625_body+0x905>
ffffffff8afc461b:	4c 89 c8             	mov    %r9,%rax
ffffffff8afc461e:	49 c1 e9 20          	shr    $0x20,%r9
ffffffff8afc4622:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc4627:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc462d:	44 89 ca             	mov    %r9d,%edx
ffffffff8afc4630:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc4636:	0f 30                	wrmsr
ffffffff8afc4638:	49 89 c1             	mov    %rax,%r9
ffffffff8afc463b:	44 39 e3             	cmp    %r12d,%ebx
ffffffff8afc463e:	0f 85 5a ff ff ff    	jne    ffffffff8afc459e <handler_625_body+0x90e>
ffffffff8afc4644:	4c 89 d0             	mov    %r10,%rax
ffffffff8afc4647:	49 c1 ea 20          	shr    $0x20,%r10
ffffffff8afc464b:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc4650:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc4656:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4659:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc465f:	0f 30                	wrmsr
ffffffff8afc4661:	49 89 c2             	mov    %rax,%r10
ffffffff8afc4664:	45 39 e6             	cmp    %r12d,%r14d
ffffffff8afc4667:	0f 85 f3 fe ff ff    	jne    ffffffff8afc4560 <handler_625_body+0x8d0>
ffffffff8afc466d:	4c 89 d8             	mov    %r11,%rax
ffffffff8afc4670:	49 c1 eb 20          	shr    $0x20,%r11
ffffffff8afc4674:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc4679:	48 25 00 00 ff ff    	and    $0xffffffffffff0000,%rax
ffffffff8afc467f:	44 89 da             	mov    %r11d,%edx
ffffffff8afc4682:	48 0d a0 00 00 00    	or     $0xa0,%rax
ffffffff8afc4688:	0f 30                	wrmsr
ffffffff8afc468a:	49 89 c3             	mov    %rax,%r11
ffffffff8afc468d:	e9 ce fe ff ff       	jmp    ffffffff8afc4560 <handler_625_body+0x8d0>
ffffffff8afc4692:	89 f0                	mov    %esi,%eax
ffffffff8afc4694:	48 c1 ee 20          	shr    $0x20,%rsi
ffffffff8afc4698:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc469d:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc46a2:	89 f2                	mov    %esi,%edx
ffffffff8afc46a4:	0f 30                	wrmsr
ffffffff8afc46a6:	89 f8                	mov    %edi,%eax
ffffffff8afc46a8:	48 c1 ef 20          	shr    $0x20,%rdi
ffffffff8afc46ac:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc46b1:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc46b6:	89 fa                	mov    %edi,%edx
ffffffff8afc46b8:	0f 30                	wrmsr
ffffffff8afc46ba:	44 89 c0             	mov    %r8d,%eax
ffffffff8afc46bd:	49 c1 e8 20          	shr    $0x20,%r8
ffffffff8afc46c1:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc46c6:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc46cb:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc46ce:	0f 30                	wrmsr
ffffffff8afc46d0:	44 89 c8             	mov    %r9d,%eax
ffffffff8afc46d3:	49 c1 e9 20          	shr    $0x20,%r9
ffffffff8afc46d7:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc46dc:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc46e1:	44 89 ca             	mov    %r9d,%edx
ffffffff8afc46e4:	0f 30                	wrmsr
ffffffff8afc46e6:	44 89 d0             	mov    %r10d,%eax
ffffffff8afc46e9:	49 c1 ea 20          	shr    $0x20,%r10
ffffffff8afc46ed:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc46f2:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc46f7:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc46fa:	0f 30                	wrmsr
ffffffff8afc46fc:	44 89 d8             	mov    %r11d,%eax
ffffffff8afc46ff:	49 c1 eb 20          	shr    $0x20,%r11
ffffffff8afc4703:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc4708:	25 00 00 bf ff       	and    $0xffbf0000,%eax
ffffffff8afc470d:	44 89 da             	mov    %r11d,%edx
ffffffff8afc4710:	0f 30                	wrmsr
ffffffff8afc4712:	83 7d cc 00          	cmpl   $0x0,-0x34(%rbp)
ffffffff8afc4716:	48 8b 5d b0          	mov    -0x50(%rbp),%rbx
ffffffff8afc471a:	74 08                	je     ffffffff8afc4724 <handler_625_body+0xa94>
ffffffff8afc471c:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc471f:	e8 3c 31 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc4724:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc4727:	31 db                	xor    %ebx,%ebx
ffffffff8afc4729:	31 f6                	xor    %esi,%esi
ffffffff8afc472b:	31 d2                	xor    %edx,%edx
ffffffff8afc472d:	31 c9                	xor    %ecx,%ecx
ffffffff8afc472f:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc4733:	e8 e8 2d ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc4738:	e9 8a f5 ff ff       	jmp    ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc473d:	4c 89 fa             	mov    %r15,%rdx
ffffffff8afc4740:	44 89 f8             	mov    %r15d,%eax
ffffffff8afc4743:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc4748:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc474c:	0f 30                	wrmsr
ffffffff8afc474e:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc4753:	0f 30                	wrmsr
ffffffff8afc4755:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc475a:	0f 30                	wrmsr
ffffffff8afc475c:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc4761:	0f 30                	wrmsr
ffffffff8afc4763:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc4768:	0f 30                	wrmsr
ffffffff8afc476a:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc476f:	0f 30                	wrmsr
ffffffff8afc4771:	83 fe 07             	cmp    $0x7,%esi
ffffffff8afc4774:	77 08                	ja     ffffffff8afc477e <handler_625_body+0xaee>
ffffffff8afc4776:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc4779:	e8 e2 30 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc477e:	49 8b 3c 24          	mov    (%r12),%rdi
ffffffff8afc4782:	31 f6                	xor    %esi,%esi
ffffffff8afc4784:	31 d2                	xor    %edx,%edx
ffffffff8afc4786:	31 c9                	xor    %ecx,%ecx
ffffffff8afc4788:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc478c:	e8 8f 2d ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc4791:	44 8b 65 d0          	mov    -0x30(%rbp),%r12d
ffffffff8afc4795:	41 83 fd 02          	cmp    $0x2,%r13d
ffffffff8afc4799:	0f 82 28 f5 ff ff    	jb     ffffffff8afc3cc7 <handler_625_body+0x37>
ffffffff8afc479f:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc47a6:	00 00 
ffffffff8afc47a8:	48 8d 15 a2 6d ca 00 	lea    0xca6da2(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc47af:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc47b2:	b9 0c 04 00 00       	mov    $0x40c,%ecx
ffffffff8afc47b7:	31 f6                	xor    %esi,%esi
ffffffff8afc47b9:	e8 f2 30 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc47be:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc47c5:	00 
ffffffff8afc47c6:	83 f8 08             	cmp    $0x8,%eax
ffffffff8afc47c9:	72 10                	jb     ffffffff8afc47db <handler_625_body+0xb4b>
ffffffff8afc47cb:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc47ce:	31 f6                	xor    %esi,%esi
ffffffff8afc47d0:	e8 eb 2f 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc47d5:	41 bc 01 00 00 00    	mov    $0x1,%r12d
ffffffff8afc47db:	41 83 fe ff          	cmp    $0xffffffff,%r14d
ffffffff8afc47df:	74 16                	je     ffffffff8afc47f7 <handler_625_body+0xb67>
ffffffff8afc47e1:	4c 89 fa             	mov    %r15,%rdx
ffffffff8afc47e4:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc47eb:	c0 
ffffffff8afc47ec:	44 89 f8             	mov    %r15d,%eax
ffffffff8afc47ef:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc47f3:	0f 30                	wrmsr
ffffffff8afc47f5:	eb 34                	jmp    ffffffff8afc482b <handler_625_body+0xb9b>
ffffffff8afc47f7:	4c 89 fa             	mov    %r15,%rdx
ffffffff8afc47fa:	44 89 f8             	mov    %r15d,%eax
ffffffff8afc47fd:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc4802:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc4806:	0f 30                	wrmsr
ffffffff8afc4808:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc480d:	0f 30                	wrmsr
ffffffff8afc480f:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc4814:	0f 30                	wrmsr
ffffffff8afc4816:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc481b:	0f 30                	wrmsr
ffffffff8afc481d:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc4822:	0f 30                	wrmsr
ffffffff8afc4824:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc4829:	0f 30                	wrmsr
ffffffff8afc482b:	45 85 e4             	test   %r12d,%r12d
ffffffff8afc482e:	0f 85 e8 fe ff ff    	jne    ffffffff8afc471c <handler_625_body+0xa8c>
ffffffff8afc4834:	e9 eb fe ff ff       	jmp    ffffffff8afc4724 <handler_625_body+0xa94>
ffffffff8afc4839:	90                   	nop
ffffffff8afc483a:	90                   	nop
ffffffff8afc483b:	90                   	nop
ffffffff8afc483c:	90                   	nop
ffffffff8afc483d:	90                   	nop
ffffffff8afc483e:	90                   	nop
ffffffff8afc483f:	90                   	nop

ffffffff8afc4840 <frame_candidate_604840>:
ffffffff8afc4840:	55                   	push   %rbp
ffffffff8afc4841:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc4844:	41 57                	push   %r15
ffffffff8afc4846:	41 56                	push   %r14
ffffffff8afc4848:	41 55                	push   %r13
ffffffff8afc484a:	41 54                	push   %r12
ffffffff8afc484c:	53                   	push   %rbx
ffffffff8afc484d:	50                   	push   %rax
ffffffff8afc484e:	41 bf 16 00 00 00    	mov    $0x16,%r15d
ffffffff8afc4854:	48 b8 00 00 7f ff f0 	movabs $0xf0fff0ff7f0000,%rax
ffffffff8afc485b:	ff f0 00 
ffffffff8afc485e:	48 85 c2             	test   %rax,%rdx
ffffffff8afc4861:	0f 85 16 01 00 00    	jne    ffffffff8afc497d <frame_candidate_604840+0x13d>
ffffffff8afc4867:	48 89 d3             	mov    %rdx,%rbx
ffffffff8afc486a:	41 89 f6             	mov    %esi,%r14d
ffffffff8afc486d:	41 bc 00 00 00 00    	mov    $0x0,%r12d
ffffffff8afc4873:	45 31 ff             	xor    %r15d,%r15d
ffffffff8afc4876:	40 f6 c7 01          	test   $0x1,%dil
ffffffff8afc487a:	0f 84 87 00 00 00    	je     ffffffff8afc4907 <frame_candidate_604840+0xc7>
ffffffff8afc4880:	89 7d d0             	mov    %edi,-0x30(%rbp)
ffffffff8afc4883:	48 8d 15 c7 6c ca 00 	lea    0xca6cc7(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc488a:	b9 fe 02 00 00       	mov    $0x2fe,%ecx
ffffffff8afc488f:	31 f6                	xor    %esi,%esi
ffffffff8afc4891:	65 4c 8b 24 25 00 00 	mov    %gs:0x0,%r12
ffffffff8afc4898:	00 00 
ffffffff8afc489a:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc489d:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
ffffffff8afc48a4:	e8 07 30 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc48a9:	65 44 8b 2c 25 34 00 	mov    %gs:0x34,%r13d
ffffffff8afc48b0:	00 00 
ffffffff8afc48b2:	41 83 fd 07          	cmp    $0x7,%r13d
ffffffff8afc48b6:	77 14                	ja     ffffffff8afc48cc <frame_candidate_604840+0x8c>
ffffffff8afc48b8:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc48bb:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc48c0:	e8 fb 2e 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc48c5:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)
ffffffff8afc48cc:	48 89 da             	mov    %rbx,%rdx
ffffffff8afc48cf:	43 8d 8c 36 30 02 01 	lea    -0x3ffefdd0(%r14,%r14,1),%ecx
ffffffff8afc48d6:	c0 
ffffffff8afc48d7:	89 d8                	mov    %ebx,%eax
ffffffff8afc48d9:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc48dd:	0f 30                	wrmsr
ffffffff8afc48df:	41 83 fd 07          	cmp    $0x7,%r13d
ffffffff8afc48e3:	77 08                	ja     ffffffff8afc48ed <frame_candidate_604840+0xad>
ffffffff8afc48e5:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc48e8:	e8 73 2f 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc48ed:	49 8b 3c 24          	mov    (%r12),%rdi
ffffffff8afc48f1:	31 f6                	xor    %esi,%esi
ffffffff8afc48f3:	31 d2                	xor    %edx,%edx
ffffffff8afc48f5:	31 c9                	xor    %ecx,%ecx
ffffffff8afc48f7:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc48fb:	e8 20 2c ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc4900:	8b 7d d0             	mov    -0x30(%rbp),%edi
ffffffff8afc4903:	44 8b 65 d4          	mov    -0x2c(%rbp),%r12d
ffffffff8afc4907:	83 ff 02             	cmp    $0x2,%edi
ffffffff8afc490a:	72 71                	jb     ffffffff8afc497d <frame_candidate_604840+0x13d>
ffffffff8afc490c:	65 4c 8b 3c 25 00 00 	mov    %gs:0x0,%r15
ffffffff8afc4913:	00 00 
ffffffff8afc4915:	48 8d 15 35 6c ca 00 	lea    0xca6c35(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc491c:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc491f:	b9 0e 03 00 00       	mov    $0x30e,%ecx
ffffffff8afc4924:	31 f6                	xor    %esi,%esi
ffffffff8afc4926:	e8 85 2f ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc492b:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc4932:	00 
ffffffff8afc4933:	83 f8 08             	cmp    $0x8,%eax
ffffffff8afc4936:	72 10                	jb     ffffffff8afc4948 <frame_candidate_604840+0x108>
ffffffff8afc4938:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc493b:	31 f6                	xor    %esi,%esi
ffffffff8afc493d:	e8 7e 2e 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc4942:	41 bc 01 00 00 00    	mov    $0x1,%r12d
ffffffff8afc4948:	48 89 da             	mov    %rbx,%rdx
ffffffff8afc494b:	43 8d 8c 36 30 02 01 	lea    -0x3ffefdd0(%r14,%r14,1),%ecx
ffffffff8afc4952:	c0 
ffffffff8afc4953:	89 d8                	mov    %ebx,%eax
ffffffff8afc4955:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc4959:	0f 30                	wrmsr
ffffffff8afc495b:	45 85 e4             	test   %r12d,%r12d
ffffffff8afc495e:	74 08                	je     ffffffff8afc4968 <frame_candidate_604840+0x128>
ffffffff8afc4960:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc4963:	e8 f8 2e 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc4968:	49 8b 3f             	mov    (%r15),%rdi
ffffffff8afc496b:	45 31 ff             	xor    %r15d,%r15d
ffffffff8afc496e:	31 f6                	xor    %esi,%esi
ffffffff8afc4970:	31 d2                	xor    %edx,%edx
ffffffff8afc4972:	31 c9                	xor    %ecx,%ecx
ffffffff8afc4974:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc4978:	e8 a3 2b ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc497d:	44 89 f8             	mov    %r15d,%eax
ffffffff8afc4980:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8afc4984:	5b                   	pop    %rbx
ffffffff8afc4985:	41 5c                	pop    %r12
ffffffff8afc4987:	41 5d                	pop    %r13
ffffffff8afc4989:	41 5e                	pop    %r14
ffffffff8afc498b:	41 5f                	pop    %r15
ffffffff8afc498d:	5d                   	pop    %rbp
ffffffff8afc498e:	c3                   	ret
ffffffff8afc498f:	90                   	nop

ffffffff8afc4990 <frame_candidate_604990>:
ffffffff8afc4990:	55                   	push   %rbp
ffffffff8afc4991:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc4994:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4999:	48 b9 00 00 ff ff f0 	movabs $0xe7fffff0ffff0000,%rcx
ffffffff8afc49a0:	ff ff e7 
ffffffff8afc49a3:	48 85 ce             	test   %rcx,%rsi
ffffffff8afc49a6:	74 02                	je     ffffffff8afc49aa <frame_candidate_604990+0x1a>
ffffffff8afc49a8:	5d                   	pop    %rbp
ffffffff8afc49a9:	c3                   	ret
ffffffff8afc49aa:	48 b8 00 00 00 00 00 	movabs $0x1800000000000000,%rax
ffffffff8afc49b1:	00 00 18 
ffffffff8afc49b4:	48 b9 00 00 00 00 0f 	movabs $0xf00000000,%rcx
ffffffff8afc49bb:	00 00 00 
ffffffff8afc49be:	48 21 f0             	and    %rsi,%rax
ffffffff8afc49c1:	48 21 f1             	and    %rsi,%rcx
ffffffff8afc49c4:	48 8d 14 81          	lea    (%rcx,%rax,4),%rdx
ffffffff8afc49c8:	8d 0c 3f             	lea    (%rdi,%rdi,1),%ecx
ffffffff8afc49cb:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc49cf:	83 ff 03             	cmp    $0x3,%edi
ffffffff8afc49d2:	77 0c                	ja     ffffffff8afc49e0 <frame_candidate_604990+0x50>
ffffffff8afc49d4:	81 c9 40 02 01 c0    	or     $0xc0010240,%ecx
ffffffff8afc49da:	89 f0                	mov    %esi,%eax
ffffffff8afc49dc:	0f 30                	wrmsr
ffffffff8afc49de:	eb 0a                	jmp    ffffffff8afc49ea <frame_candidate_604990+0x5a>
ffffffff8afc49e0:	81 c1 88 01 01 c0    	add    $0xc0010188,%ecx
ffffffff8afc49e6:	89 f0                	mov    %esi,%eax
ffffffff8afc49e8:	0f 30                	wrmsr
ffffffff8afc49ea:	31 c0                	xor    %eax,%eax
ffffffff8afc49ec:	5d                   	pop    %rbp
ffffffff8afc49ed:	c3                   	ret
ffffffff8afc49ee:	90                   	nop
ffffffff8afc49ef:	90                   	nop

ffffffff8afc49f0 <frame_candidate_6049f0>:
ffffffff8afc49f0:	55                   	push   %rbp
ffffffff8afc49f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc49f4:	41 56                	push   %r14
ffffffff8afc49f6:	53                   	push   %rbx
ffffffff8afc49f7:	e8 34 dc 09 00       	call   ffffffff8b062630 <frame_candidate_605c40+0x9c9f0>
ffffffff8afc49fc:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc4a01:	0f 32                	rdmsr
ffffffff8afc4a03:	89 c7                	mov    %eax,%edi
ffffffff8afc4a05:	89 d6                	mov    %edx,%esi
ffffffff8afc4a07:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc4a0c:	0f 32                	rdmsr
ffffffff8afc4a0e:	41 89 c1             	mov    %eax,%r9d
ffffffff8afc4a11:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc4a14:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc4a19:	0f 32                	rdmsr
ffffffff8afc4a1b:	41 89 c3             	mov    %eax,%r11d
ffffffff8afc4a1e:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc4a21:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc4a26:	0f 32                	rdmsr
ffffffff8afc4a28:	89 c3                	mov    %eax,%ebx
ffffffff8afc4a2a:	41 89 d6             	mov    %edx,%r14d
ffffffff8afc4a2d:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc4a32:	81 cf 00 00 40 00    	or     $0x400000,%edi
ffffffff8afc4a38:	41 81 c9 00 00 40 00 	or     $0x400000,%r9d
ffffffff8afc4a3f:	41 81 cb 00 00 40 00 	or     $0x400000,%r11d
ffffffff8afc4a46:	81 cb 00 00 40 00    	or     $0x400000,%ebx
ffffffff8afc4a4c:	89 f2                	mov    %esi,%edx
ffffffff8afc4a4e:	89 f8                	mov    %edi,%eax
ffffffff8afc4a50:	0f 30                	wrmsr
ffffffff8afc4a52:	44 89 c8             	mov    %r9d,%eax
ffffffff8afc4a55:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4a58:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc4a5d:	0f 30                	wrmsr
ffffffff8afc4a5f:	44 89 d8             	mov    %r11d,%eax
ffffffff8afc4a62:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4a65:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc4a6a:	0f 30                	wrmsr
ffffffff8afc4a6c:	89 d8                	mov    %ebx,%eax
ffffffff8afc4a6e:	44 89 f2             	mov    %r14d,%edx
ffffffff8afc4a71:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc4a76:	0f 30                	wrmsr
ffffffff8afc4a78:	e8 93 5d 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4a7d:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc4a82:	0f 82 88 00 00 00    	jb     ffffffff8afc4b10 <frame_candidate_6049f0+0x120>
ffffffff8afc4a88:	e8 83 5d 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4a8d:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc4a92:	77 7c                	ja     ffffffff8afc4b10 <frame_candidate_6049f0+0x120>
ffffffff8afc4a94:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc4a99:	0f 32                	rdmsr
ffffffff8afc4a9b:	89 c7                	mov    %eax,%edi
ffffffff8afc4a9d:	89 d6                	mov    %edx,%esi
ffffffff8afc4a9f:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc4aa4:	0f 32                	rdmsr
ffffffff8afc4aa6:	41 89 c1             	mov    %eax,%r9d
ffffffff8afc4aa9:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc4aac:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc4ab1:	0f 32                	rdmsr
ffffffff8afc4ab3:	41 89 c3             	mov    %eax,%r11d
ffffffff8afc4ab6:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc4ab9:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc4abe:	0f 32                	rdmsr
ffffffff8afc4ac0:	89 c3                	mov    %eax,%ebx
ffffffff8afc4ac2:	41 89 d6             	mov    %edx,%r14d
ffffffff8afc4ac5:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc4aca:	81 cf 00 00 40 00    	or     $0x400000,%edi
ffffffff8afc4ad0:	41 81 c9 00 00 40 00 	or     $0x400000,%r9d
ffffffff8afc4ad7:	41 81 cb 00 00 40 00 	or     $0x400000,%r11d
ffffffff8afc4ade:	81 cb 00 00 40 00    	or     $0x400000,%ebx
ffffffff8afc4ae4:	89 f2                	mov    %esi,%edx
ffffffff8afc4ae6:	89 f8                	mov    %edi,%eax
ffffffff8afc4ae8:	0f 30                	wrmsr
ffffffff8afc4aea:	44 89 c8             	mov    %r9d,%eax
ffffffff8afc4aed:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4af0:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc4af5:	0f 30                	wrmsr
ffffffff8afc4af7:	44 89 d8             	mov    %r11d,%eax
ffffffff8afc4afa:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4afd:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc4b02:	0f 30                	wrmsr
ffffffff8afc4b04:	89 d8                	mov    %ebx,%eax
ffffffff8afc4b06:	44 89 f2             	mov    %r14d,%edx
ffffffff8afc4b09:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc4b0e:	0f 30                	wrmsr
ffffffff8afc4b10:	5b                   	pop    %rbx
ffffffff8afc4b11:	41 5e                	pop    %r14
ffffffff8afc4b13:	5d                   	pop    %rbp
ffffffff8afc4b14:	e9 37 db 09 00       	jmp    ffffffff8b062650 <frame_candidate_605c40+0x9ca10>
ffffffff8afc4b19:	90                   	nop
ffffffff8afc4b1a:	90                   	nop
ffffffff8afc4b1b:	90                   	nop
ffffffff8afc4b1c:	90                   	nop
ffffffff8afc4b1d:	90                   	nop
ffffffff8afc4b1e:	90                   	nop
ffffffff8afc4b1f:	90                   	nop

ffffffff8afc4b20 <frame_candidate_604b20>:
ffffffff8afc4b20:	55                   	push   %rbp
ffffffff8afc4b21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc4b24:	41 56                	push   %r14
ffffffff8afc4b26:	53                   	push   %rbx
ffffffff8afc4b27:	e8 04 db 09 00       	call   ffffffff8b062630 <frame_candidate_605c40+0x9c9f0>
ffffffff8afc4b2c:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc4b31:	0f 32                	rdmsr
ffffffff8afc4b33:	89 c7                	mov    %eax,%edi
ffffffff8afc4b35:	89 d6                	mov    %edx,%esi
ffffffff8afc4b37:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc4b3c:	0f 32                	rdmsr
ffffffff8afc4b3e:	41 89 c1             	mov    %eax,%r9d
ffffffff8afc4b41:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc4b44:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc4b49:	0f 32                	rdmsr
ffffffff8afc4b4b:	41 89 c3             	mov    %eax,%r11d
ffffffff8afc4b4e:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc4b51:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc4b56:	0f 32                	rdmsr
ffffffff8afc4b58:	89 c3                	mov    %eax,%ebx
ffffffff8afc4b5a:	41 89 d6             	mov    %edx,%r14d
ffffffff8afc4b5d:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc4b62:	81 e7 ff ff bf ff    	and    $0xffbfffff,%edi
ffffffff8afc4b68:	41 81 e1 ff ff bf ff 	and    $0xffbfffff,%r9d
ffffffff8afc4b6f:	41 81 e3 ff ff bf ff 	and    $0xffbfffff,%r11d
ffffffff8afc4b76:	81 e3 ff ff bf ff    	and    $0xffbfffff,%ebx
ffffffff8afc4b7c:	89 f2                	mov    %esi,%edx
ffffffff8afc4b7e:	89 f8                	mov    %edi,%eax
ffffffff8afc4b80:	0f 30                	wrmsr
ffffffff8afc4b82:	44 89 c8             	mov    %r9d,%eax
ffffffff8afc4b85:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4b88:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc4b8d:	0f 30                	wrmsr
ffffffff8afc4b8f:	44 89 d8             	mov    %r11d,%eax
ffffffff8afc4b92:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4b95:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc4b9a:	0f 30                	wrmsr
ffffffff8afc4b9c:	89 d8                	mov    %ebx,%eax
ffffffff8afc4b9e:	44 89 f2             	mov    %r14d,%edx
ffffffff8afc4ba1:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc4ba6:	0f 30                	wrmsr
ffffffff8afc4ba8:	e8 63 5c 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4bad:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc4bb2:	0f 82 88 00 00 00    	jb     ffffffff8afc4c40 <frame_candidate_604b20+0x120>
ffffffff8afc4bb8:	e8 53 5c 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4bbd:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc4bc2:	77 7c                	ja     ffffffff8afc4c40 <frame_candidate_604b20+0x120>
ffffffff8afc4bc4:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc4bc9:	0f 32                	rdmsr
ffffffff8afc4bcb:	89 c7                	mov    %eax,%edi
ffffffff8afc4bcd:	89 d6                	mov    %edx,%esi
ffffffff8afc4bcf:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc4bd4:	0f 32                	rdmsr
ffffffff8afc4bd6:	41 89 c1             	mov    %eax,%r9d
ffffffff8afc4bd9:	41 89 d0             	mov    %edx,%r8d
ffffffff8afc4bdc:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc4be1:	0f 32                	rdmsr
ffffffff8afc4be3:	41 89 c3             	mov    %eax,%r11d
ffffffff8afc4be6:	41 89 d2             	mov    %edx,%r10d
ffffffff8afc4be9:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc4bee:	0f 32                	rdmsr
ffffffff8afc4bf0:	89 c3                	mov    %eax,%ebx
ffffffff8afc4bf2:	41 89 d6             	mov    %edx,%r14d
ffffffff8afc4bf5:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc4bfa:	81 e7 ff ff bf ff    	and    $0xffbfffff,%edi
ffffffff8afc4c00:	41 81 e1 ff ff bf ff 	and    $0xffbfffff,%r9d
ffffffff8afc4c07:	41 81 e3 ff ff bf ff 	and    $0xffbfffff,%r11d
ffffffff8afc4c0e:	81 e3 ff ff bf ff    	and    $0xffbfffff,%ebx
ffffffff8afc4c14:	89 f2                	mov    %esi,%edx
ffffffff8afc4c16:	89 f8                	mov    %edi,%eax
ffffffff8afc4c18:	0f 30                	wrmsr
ffffffff8afc4c1a:	44 89 c8             	mov    %r9d,%eax
ffffffff8afc4c1d:	44 89 c2             	mov    %r8d,%edx
ffffffff8afc4c20:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc4c25:	0f 30                	wrmsr
ffffffff8afc4c27:	44 89 d8             	mov    %r11d,%eax
ffffffff8afc4c2a:	44 89 d2             	mov    %r10d,%edx
ffffffff8afc4c2d:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc4c32:	0f 30                	wrmsr
ffffffff8afc4c34:	89 d8                	mov    %ebx,%eax
ffffffff8afc4c36:	44 89 f2             	mov    %r14d,%edx
ffffffff8afc4c39:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc4c3e:	0f 30                	wrmsr
ffffffff8afc4c40:	5b                   	pop    %rbx
ffffffff8afc4c41:	41 5e                	pop    %r14
ffffffff8afc4c43:	5d                   	pop    %rbp
ffffffff8afc4c44:	e9 07 da 09 00       	jmp    ffffffff8b062650 <frame_candidate_605c40+0x9ca10>
ffffffff8afc4c49:	90                   	nop
ffffffff8afc4c4a:	90                   	nop
ffffffff8afc4c4b:	90                   	nop
ffffffff8afc4c4c:	90                   	nop
ffffffff8afc4c4d:	90                   	nop
ffffffff8afc4c4e:	90                   	nop
ffffffff8afc4c4f:	90                   	nop

ffffffff8afc4c50 <frame_candidate_604c50>:
ffffffff8afc4c50:	55                   	push   %rbp
ffffffff8afc4c51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc4c54:	41 56                	push   %r14
ffffffff8afc4c56:	53                   	push   %rbx
ffffffff8afc4c57:	48 89 f3             	mov    %rsi,%rbx
ffffffff8afc4c5a:	83 ff ff             	cmp    $0xffffffff,%edi
ffffffff8afc4c5d:	74 1b                	je     ffffffff8afc4c7a <frame_candidate_604c50+0x2a>
ffffffff8afc4c5f:	48 89 da             	mov    %rbx,%rdx
ffffffff8afc4c62:	8d 0c 3f             	lea    (%rdi,%rdi,1),%ecx
ffffffff8afc4c65:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc4c69:	83 ff 03             	cmp    $0x3,%edi
ffffffff8afc4c6c:	77 6f                	ja     ffffffff8afc4cdd <frame_candidate_604c50+0x8d>
ffffffff8afc4c6e:	81 c9 41 02 01 c0    	or     $0xc0010241,%ecx
ffffffff8afc4c74:	89 d8                	mov    %ebx,%eax
ffffffff8afc4c76:	0f 30                	wrmsr
ffffffff8afc4c78:	eb 6d                	jmp    ffffffff8afc4ce7 <frame_candidate_604c50+0x97>
ffffffff8afc4c7a:	49 89 de             	mov    %rbx,%r14
ffffffff8afc4c7d:	89 d8                	mov    %ebx,%eax
ffffffff8afc4c7f:	b9 41 02 01 c0       	mov    $0xc0010241,%ecx
ffffffff8afc4c84:	49 c1 ee 20          	shr    $0x20,%r14
ffffffff8afc4c88:	44 89 f2             	mov    %r14d,%edx
ffffffff8afc4c8b:	0f 30                	wrmsr
ffffffff8afc4c8d:	b9 43 02 01 c0       	mov    $0xc0010243,%ecx
ffffffff8afc4c92:	0f 30                	wrmsr
ffffffff8afc4c94:	b9 45 02 01 c0       	mov    $0xc0010245,%ecx
ffffffff8afc4c99:	0f 30                	wrmsr
ffffffff8afc4c9b:	b9 47 02 01 c0       	mov    $0xc0010247,%ecx
ffffffff8afc4ca0:	0f 30                	wrmsr
ffffffff8afc4ca2:	e8 69 5b 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4ca7:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc4cac:	72 39                	jb     ffffffff8afc4ce7 <frame_candidate_604c50+0x97>
ffffffff8afc4cae:	e8 5d 5b 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4cb3:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc4cb8:	77 2d                	ja     ffffffff8afc4ce7 <frame_candidate_604c50+0x97>
ffffffff8afc4cba:	89 d8                	mov    %ebx,%eax
ffffffff8afc4cbc:	44 89 f2             	mov    %r14d,%edx
ffffffff8afc4cbf:	b9 91 01 01 c0       	mov    $0xc0010191,%ecx
ffffffff8afc4cc4:	0f 30                	wrmsr
ffffffff8afc4cc6:	b9 93 01 01 c0       	mov    $0xc0010193,%ecx
ffffffff8afc4ccb:	0f 30                	wrmsr
ffffffff8afc4ccd:	b9 95 01 01 c0       	mov    $0xc0010195,%ecx
ffffffff8afc4cd2:	0f 30                	wrmsr
ffffffff8afc4cd4:	b9 97 01 01 c0       	mov    $0xc0010197,%ecx
ffffffff8afc4cd9:	0f 30                	wrmsr
ffffffff8afc4cdb:	eb 0a                	jmp    ffffffff8afc4ce7 <frame_candidate_604c50+0x97>
ffffffff8afc4cdd:	81 c1 89 01 01 c0    	add    $0xc0010189,%ecx
ffffffff8afc4ce3:	89 d8                	mov    %ebx,%eax
ffffffff8afc4ce5:	0f 30                	wrmsr
ffffffff8afc4ce7:	5b                   	pop    %rbx
ffffffff8afc4ce8:	41 5e                	pop    %r14
ffffffff8afc4cea:	5d                   	pop    %rbp
ffffffff8afc4ceb:	c3                   	ret
ffffffff8afc4cec:	90                   	nop
ffffffff8afc4ced:	90                   	nop
ffffffff8afc4cee:	90                   	nop
ffffffff8afc4cef:	90                   	nop

ffffffff8afc4cf0 <frame_candidate_604cf0>:
ffffffff8afc4cf0:	55                   	push   %rbp
ffffffff8afc4cf1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc4cf4:	41 57                	push   %r15
ffffffff8afc4cf6:	41 56                	push   %r14
ffffffff8afc4cf8:	53                   	push   %rbx
ffffffff8afc4cf9:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
ffffffff8afc4d00:	4c 8d 35 09 76 31 03 	lea    0x3317609(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_605c40+0x33166d0>
ffffffff8afc4d07:	49 8b 06             	mov    (%r14),%rax
ffffffff8afc4d0a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8afc4d0e:	8b 5e 10             	mov    0x10(%rsi),%ebx
ffffffff8afc4d11:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
ffffffff8afc4d18:	00 
ffffffff8afc4d19:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
ffffffff8afc4d20:	00 
ffffffff8afc4d21:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8afc4d28:	00 
ffffffff8afc4d29:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8afc4d30:	00 
ffffffff8afc4d31:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
ffffffff8afc4d38:	00 
ffffffff8afc4d39:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
ffffffff8afc4d40:	00 
ffffffff8afc4d41:	48 c7 45 a8 00 00 00 	movq   $0x0,-0x58(%rbp)
ffffffff8afc4d48:	00 
ffffffff8afc4d49:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8afc4d50:	00 
ffffffff8afc4d51:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8afc4d58:	00 
ffffffff8afc4d59:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8afc4d60:	00 
ffffffff8afc4d61:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8afc4d68:	00 
ffffffff8afc4d69:	48 c7 45 80 00 00 00 	movq   $0x0,-0x80(%rbp)
ffffffff8afc4d70:	00 
ffffffff8afc4d71:	48 c7 85 78 ff ff ff 	movq   $0x0,-0x88(%rbp)
ffffffff8afc4d78:	00 00 00 00 
ffffffff8afc4d7c:	48 c7 85 70 ff ff ff 	movq   $0x0,-0x90(%rbp)
ffffffff8afc4d83:	00 00 00 00 
ffffffff8afc4d87:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
ffffffff8afc4d8e:	00 00 00 00 
ffffffff8afc4d92:	48 c7 85 60 ff ff ff 	movq   $0x0,-0xa0(%rbp)
ffffffff8afc4d99:	00 00 00 00 
ffffffff8afc4d9d:	48 c7 85 58 ff ff ff 	movq   $0x0,-0xa8(%rbp)
ffffffff8afc4da4:	00 00 00 00 
ffffffff8afc4da8:	48 c7 85 50 ff ff ff 	movq   $0x0,-0xb0(%rbp)
ffffffff8afc4daf:	00 00 00 00 
ffffffff8afc4db3:	48 c7 85 48 ff ff ff 	movq   $0x0,-0xb8(%rbp)
ffffffff8afc4dba:	00 00 00 00 
ffffffff8afc4dbe:	48 c7 85 40 ff ff ff 	movq   $0x0,-0xc0(%rbp)
ffffffff8afc4dc5:	00 00 00 00 
ffffffff8afc4dc9:	48 c7 85 38 ff ff ff 	movq   $0x0,-0xc8(%rbp)
ffffffff8afc4dd0:	00 00 00 00 
ffffffff8afc4dd4:	48 c7 85 30 ff ff ff 	movq   $0x0,-0xd0(%rbp)
ffffffff8afc4ddb:	00 00 00 00 
ffffffff8afc4ddf:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
ffffffff8afc4de6:	00 00 00 00 
ffffffff8afc4dea:	48 c7 85 20 ff ff ff 	movq   $0x0,-0xe0(%rbp)
ffffffff8afc4df1:	00 00 00 00 
ffffffff8afc4df5:	48 c7 85 18 ff ff ff 	movq   $0x0,-0xe8(%rbp)
ffffffff8afc4dfc:	00 00 00 00 
ffffffff8afc4e00:	48 c7 85 10 ff ff ff 	movq   $0x0,-0xf0(%rbp)
ffffffff8afc4e07:	00 00 00 00 
ffffffff8afc4e0b:	48 c7 85 08 ff ff ff 	movq   $0x0,-0xf8(%rbp)
ffffffff8afc4e12:	00 00 00 00 
ffffffff8afc4e16:	48 c7 85 00 ff ff ff 	movq   $0x0,-0x100(%rbp)
ffffffff8afc4e1d:	00 00 00 00 
ffffffff8afc4e21:	48 c7 85 f8 fe ff ff 	movq   $0x0,-0x108(%rbp)
ffffffff8afc4e28:	00 00 00 00 
ffffffff8afc4e2c:	48 c7 85 f0 fe ff ff 	movq   $0x0,-0x110(%rbp)
ffffffff8afc4e33:	00 00 00 00 
ffffffff8afc4e37:	48 c7 85 e8 fe ff ff 	movq   $0x0,-0x118(%rbp)
ffffffff8afc4e3e:	00 00 00 00 
ffffffff8afc4e42:	48 c7 85 e0 fe ff ff 	movq   $0x0,-0x120(%rbp)
ffffffff8afc4e49:	00 00 00 00 
ffffffff8afc4e4d:	8b 0e                	mov    (%rsi),%ecx
ffffffff8afc4e4f:	ff c9                	dec    %ecx
ffffffff8afc4e51:	83 f9 05             	cmp    $0x5,%ecx
ffffffff8afc4e54:	0f 87 ce 00 00 00    	ja     ffffffff8afc4f28 <frame_candidate_604cf0+0x238>
ffffffff8afc4e5a:	48 8d 15 5b e7 11 01 	lea    0x111e75b(%rip),%rdx        # ffffffff8c0e35bc <frame_candidate_605c40+0x111d97c>
ffffffff8afc4e61:	b8 06 00 00 00       	mov    $0x6,%eax
ffffffff8afc4e66:	48 63 0c 8a          	movslq (%rdx,%rcx,4),%rcx
ffffffff8afc4e6a:	48 01 d1             	add    %rdx,%rcx
ffffffff8afc4e6d:	ff e1                	jmp    *%rcx
ffffffff8afc4e6f:	8b 7e 08             	mov    0x8(%rsi),%edi
ffffffff8afc4e72:	8d 47 fd             	lea    -0x3(%rdi),%eax
ffffffff8afc4e75:	83 f8 fe             	cmp    $0xfffffffe,%eax
ffffffff8afc4e78:	0f 92 c0             	setb   %al
ffffffff8afc4e7b:	83 fb 06             	cmp    $0x6,%ebx
ffffffff8afc4e7e:	0f 93 c1             	setae  %cl
ffffffff8afc4e81:	08 c1                	or     %al,%cl
ffffffff8afc4e83:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4e88:	0f 85 49 01 00 00    	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4e8e:	48 83 7e 18 00       	cmpq   $0x0,0x18(%rsi)
ffffffff8afc4e93:	0f 84 3e 01 00 00    	je     ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4e99:	48 83 7e 20 00       	cmpq   $0x0,0x20(%rsi)
ffffffff8afc4e9e:	0f 85 33 01 00 00    	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4ea4:	49 89 f7             	mov    %rsi,%r15
ffffffff8afc4ea7:	89 de                	mov    %ebx,%esi
ffffffff8afc4ea9:	e8 52 01 00 00       	call   ffffffff8afc5000 <frame_candidate_605000>
ffffffff8afc4eae:	4c 89 fe             	mov    %r15,%rsi
ffffffff8afc4eb1:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc4eb4:	e9 e8 00 00 00       	jmp    ffffffff8afc4fa1 <frame_candidate_604cf0+0x2b1>
ffffffff8afc4eb9:	0b 5e 08             	or     0x8(%rsi),%ebx
ffffffff8afc4ebc:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4ec1:	0f 85 10 01 00 00    	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4ec7:	48 83 7e 18 00       	cmpq   $0x0,0x18(%rsi)
ffffffff8afc4ecc:	0f 84 05 01 00 00    	je     ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4ed2:	48 83 7e 20 00       	cmpq   $0x0,0x20(%rsi)
ffffffff8afc4ed7:	0f 84 fa 00 00 00    	je     ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4edd:	48 89 f3             	mov    %rsi,%rbx
ffffffff8afc4ee0:	48 8d bd 60 ff ff ff 	lea    -0xa0(%rbp),%rdi
ffffffff8afc4ee7:	48 8d b5 e0 fe ff ff 	lea    -0x120(%rbp),%rsi
ffffffff8afc4eee:	e8 fd aa 37 00       	call   ffffffff8b33f9f0 <frame_candidate_605c40+0x379db0>
ffffffff8afc4ef3:	85 c0                	test   %eax,%eax
ffffffff8afc4ef5:	0f 85 dc 00 00 00    	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4efb:	48 8b 73 20          	mov    0x20(%rbx),%rsi
ffffffff8afc4eff:	48 8d bd e0 fe ff ff 	lea    -0x120(%rbp),%rdi
ffffffff8afc4f06:	e8 45 ed ff ff       	call   ffffffff8afc3c50 <handler_625_body-0x40>
ffffffff8afc4f0b:	85 c0                	test   %eax,%eax
ffffffff8afc4f0d:	0f 85 c4 00 00 00    	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4f13:	48 8b 73 18          	mov    0x18(%rbx),%rsi
ffffffff8afc4f17:	48 8d bd 60 ff ff ff 	lea    -0xa0(%rbp),%rdi
ffffffff8afc4f1e:	e8 2d ed ff ff       	call   ffffffff8afc3c50 <handler_625_body-0x40>
ffffffff8afc4f23:	e9 af 00 00 00       	jmp    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4f28:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4f2d:	e9 a5 00 00 00       	jmp    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4f32:	49 89 f7             	mov    %rsi,%r15
ffffffff8afc4f35:	e8 d6 58 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4f3a:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc4f3f:	72 11                	jb     ffffffff8afc4f52 <frame_candidate_604cf0+0x262>
ffffffff8afc4f41:	e8 ca 58 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc4f46:	b9 07 00 00 00       	mov    $0x7,%ecx
ffffffff8afc4f4b:	3d e0 0f 84 00       	cmp    $0x840fe0,%eax
ffffffff8afc4f50:	72 05                	jb     ffffffff8afc4f57 <frame_candidate_604cf0+0x267>
ffffffff8afc4f52:	b9 03 00 00 00       	mov    $0x3,%ecx
ffffffff8afc4f57:	41 83 7f 08 00       	cmpl   $0x0,0x8(%r15)
ffffffff8afc4f5c:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4f61:	75 74                	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4f63:	49 83 7f 18 00       	cmpq   $0x0,0x18(%r15)
ffffffff8afc4f68:	4c 89 fe             	mov    %r15,%rsi
ffffffff8afc4f6b:	74 6a                	je     ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4f6d:	48 83 7e 20 00       	cmpq   $0x0,0x20(%rsi)
ffffffff8afc4f72:	0f 95 c2             	setne  %dl
ffffffff8afc4f75:	39 cb                	cmp    %ecx,%ebx
ffffffff8afc4f77:	0f 97 c1             	seta   %cl
ffffffff8afc4f7a:	08 d1                	or     %dl,%cl
ffffffff8afc4f7c:	75 59                	jne    ffffffff8afc4fd7 <frame_candidate_604cf0+0x2e7>
ffffffff8afc4f7e:	8d 0c 1b             	lea    (%rbx,%rbx,1),%ecx
ffffffff8afc4f81:	83 fb 03             	cmp    $0x3,%ebx
ffffffff8afc4f84:	77 0a                	ja     ffffffff8afc4f90 <frame_candidate_604cf0+0x2a0>
ffffffff8afc4f86:	81 c9 41 02 01 c0    	or     $0xc0010241,%ecx
ffffffff8afc4f8c:	0f 32                	rdmsr
ffffffff8afc4f8e:	eb 08                	jmp    ffffffff8afc4f98 <frame_candidate_604cf0+0x2a8>
ffffffff8afc4f90:	81 c1 89 01 01 c0    	add    $0xc0010189,%ecx
ffffffff8afc4f96:	0f 32                	rdmsr
ffffffff8afc4f98:	89 c0                	mov    %eax,%eax
ffffffff8afc4f9a:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc4f9e:	48 09 c2             	or     %rax,%rdx
ffffffff8afc4fa1:	48 89 95 d8 fe ff ff 	mov    %rdx,-0x128(%rbp)
ffffffff8afc4fa8:	31 d2                	xor    %edx,%edx
ffffffff8afc4faa:	48 8b 5e 18          	mov    0x18(%rsi),%rbx
ffffffff8afc4fae:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8afc4fb5:	00 00 
ffffffff8afc4fb7:	48 8d 35 d9 a2 d4 00 	lea    0xd4a2d9(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_605c40+0xd49657>
ffffffff8afc4fbe:	e8 1d 54 61 00       	call   ffffffff8b5da3e0 <frame_candidate_605c40+0x6147a0>
ffffffff8afc4fc3:	48 8d bd d8 fe ff ff 	lea    -0x128(%rbp),%rdi
ffffffff8afc4fca:	ba 08 00 00 00       	mov    $0x8,%edx
ffffffff8afc4fcf:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc4fd2:	e8 f9 41 c5 ff       	call   ffffffff8ac191d0 <handler_625_body-0x3aaac0>
ffffffff8afc4fd7:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8afc4fda:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8afc4fde:	75 0e                	jne    ffffffff8afc4fee <frame_candidate_604cf0+0x2fe>
ffffffff8afc4fe0:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
ffffffff8afc4fe7:	5b                   	pop    %rbx
ffffffff8afc4fe8:	41 5e                	pop    %r14
ffffffff8afc4fea:	41 5f                	pop    %r15
ffffffff8afc4fec:	5d                   	pop    %rbp
ffffffff8afc4fed:	c3                   	ret
ffffffff8afc4fee:	e8 bd 86 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_605c40+0xf7a70>
ffffffff8afc4ff3:	0f 0b                	ud2
ffffffff8afc4ff5:	90                   	nop
ffffffff8afc4ff6:	90                   	nop
ffffffff8afc4ff7:	90                   	nop
ffffffff8afc4ff8:	90                   	nop
ffffffff8afc4ff9:	90                   	nop
ffffffff8afc4ffa:	90                   	nop
ffffffff8afc4ffb:	90                   	nop
ffffffff8afc4ffc:	90                   	nop
ffffffff8afc4ffd:	90                   	nop
ffffffff8afc4ffe:	90                   	nop
ffffffff8afc4fff:	90                   	nop

ffffffff8afc5000 <frame_candidate_605000>:
ffffffff8afc5000:	55                   	push   %rbp
ffffffff8afc5001:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5004:	41 56                	push   %r14
ffffffff8afc5006:	53                   	push   %rbx
ffffffff8afc5007:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc500e:	00 00 
ffffffff8afc5010:	41 89 f6             	mov    %esi,%r14d
ffffffff8afc5013:	48 8d 15 37 65 ca 00 	lea    0xca6537(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc501a:	83 ff 01             	cmp    $0x1,%edi
ffffffff8afc501d:	75 2b                	jne    ffffffff8afc504a <frame_candidate_605000+0x4a>
ffffffff8afc501f:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5022:	b9 2c 05 00 00       	mov    $0x52c,%ecx
ffffffff8afc5027:	31 f6                	xor    %esi,%esi
ffffffff8afc5029:	e8 82 28 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc502e:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc5035:	00 
ffffffff8afc5036:	83 f8 08             	cmp    $0x8,%eax
ffffffff8afc5039:	72 3a                	jb     ffffffff8afc5075 <frame_candidate_605000+0x75>
ffffffff8afc503b:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc5042:	c0 
ffffffff8afc5043:	0f 32                	rdmsr
ffffffff8afc5045:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc5048:	eb 63                	jmp    ffffffff8afc50ad <frame_candidate_605000+0xad>
ffffffff8afc504a:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc504d:	b9 39 05 00 00       	mov    $0x539,%ecx
ffffffff8afc5052:	31 f6                	xor    %esi,%esi
ffffffff8afc5054:	e8 57 28 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc5059:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8afc5060:	00 
ffffffff8afc5061:	83 f8 07             	cmp    $0x7,%eax
ffffffff8afc5064:	77 28                	ja     ffffffff8afc508e <frame_candidate_605000+0x8e>
ffffffff8afc5066:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc506d:	c0 
ffffffff8afc506e:	0f 32                	rdmsr
ffffffff8afc5070:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc5073:	eb 38                	jmp    ffffffff8afc50ad <frame_candidate_605000+0xad>
ffffffff8afc5075:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5078:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc507d:	e8 3e 27 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc5082:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc5089:	c0 
ffffffff8afc508a:	0f 32                	rdmsr
ffffffff8afc508c:	eb 14                	jmp    ffffffff8afc50a2 <frame_candidate_605000+0xa2>
ffffffff8afc508e:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5091:	31 f6                	xor    %esi,%esi
ffffffff8afc5093:	e8 28 27 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc5098:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc509f:	c0 
ffffffff8afc50a0:	0f 32                	rdmsr
ffffffff8afc50a2:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc50a5:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc50a8:	e8 b3 27 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc50ad:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc50b0:	31 f6                	xor    %esi,%esi
ffffffff8afc50b2:	31 d2                	xor    %edx,%edx
ffffffff8afc50b4:	31 c9                	xor    %ecx,%ecx
ffffffff8afc50b6:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc50ba:	e8 61 24 ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc50bf:	49 63 c6             	movslq %r14d,%rax
ffffffff8afc50c2:	5b                   	pop    %rbx
ffffffff8afc50c3:	41 5e                	pop    %r14
ffffffff8afc50c5:	5d                   	pop    %rbp
ffffffff8afc50c6:	c3                   	ret
ffffffff8afc50c7:	90                   	nop
ffffffff8afc50c8:	90                   	nop
ffffffff8afc50c9:	90                   	nop
ffffffff8afc50ca:	90                   	nop
ffffffff8afc50cb:	90                   	nop
ffffffff8afc50cc:	90                   	nop
ffffffff8afc50cd:	90                   	nop
ffffffff8afc50ce:	90                   	nop
ffffffff8afc50cf:	90                   	nop

ffffffff8afc50d0 <frame_candidate_6050d0>:
ffffffff8afc50d0:	55                   	push   %rbp
ffffffff8afc50d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc50d4:	48 8d 35 d9 bd ce 00 	lea    0xcebdd9(%rip),%rsi        # ffffffff8bcb0eb4 <frame_candidate_605c40+0xceb274>
ffffffff8afc50db:	48 8d 15 1e db c5 ff 	lea    -0x3a24e2(%rip),%rdx        # ffffffff8ac22c00 <handler_625_body-0x3a1090>
ffffffff8afc50e2:	48 8d 0d 70 6a d9 00 	lea    0xd96a70(%rip),%rcx        # ffffffff8bd5bb59 <frame_candidate_605c40+0xd95f19>
ffffffff8afc50e9:	41 b9 02 00 00 00    	mov    $0x2,%r9d
ffffffff8afc50ef:	31 ff                	xor    %edi,%edi
ffffffff8afc50f1:	45 31 c0             	xor    %r8d,%r8d
ffffffff8afc50f4:	e8 47 8c 13 00       	call   ffffffff8b0fdd40 <frame_candidate_605c40+0x138100>
ffffffff8afc50f9:	48 8d 35 65 f3 c8 00 	lea    0xc8f365(%rip),%rsi        # ffffffff8bc54465 <frame_candidate_605c40+0xc8e825>
ffffffff8afc5100:	48 8d 15 01 db c5 ff 	lea    -0x3a24ff(%rip),%rdx        # ffffffff8ac22c08 <handler_625_body-0x3a1088>
ffffffff8afc5107:	48 8d 0d 36 0c cb 00 	lea    0xcb0c36(%rip),%rcx        # ffffffff8bc75d44 <frame_candidate_605c40+0xcb0104>
ffffffff8afc510e:	31 ff                	xor    %edi,%edi
ffffffff8afc5110:	45 31 c0             	xor    %r8d,%r8d
ffffffff8afc5113:	41 b9 0c 00 00 00    	mov    $0xc,%r9d
ffffffff8afc5119:	5d                   	pop    %rbp
ffffffff8afc511a:	e9 21 8c 13 00       	jmp    ffffffff8b0fdd40 <frame_candidate_605c40+0x138100>
ffffffff8afc511f:	90                   	nop

ffffffff8afc5120 <frame_candidate_605120>:
ffffffff8afc5120:	55                   	push   %rbp
ffffffff8afc5121:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5124:	53                   	push   %rbx
ffffffff8afc5125:	50                   	push   %rax
ffffffff8afc5126:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc512b:	0f 32                	rdmsr
ffffffff8afc512d:	89 c0                	mov    %eax,%eax
ffffffff8afc512f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5133:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5136:	31 c0                	xor    %eax,%eax
ffffffff8afc5138:	48 89 15 b1 c5 0c 03 	mov    %rdx,0x30cc5b1(%rip)        # ffffffff8e0916f0 <frame_candidate_605c40+0x30cbab0>
ffffffff8afc513f:	31 d2                	xor    %edx,%edx
ffffffff8afc5141:	0f 30                	wrmsr
ffffffff8afc5143:	b9 41 02 01 c0       	mov    $0xc0010241,%ecx
ffffffff8afc5148:	0f 32                	rdmsr
ffffffff8afc514a:	89 c0                	mov    %eax,%eax
ffffffff8afc514c:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5150:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc5155:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5158:	48 89 15 d1 c5 0c 03 	mov    %rdx,0x30cc5d1(%rip)        # ffffffff8e091730 <frame_candidate_605c40+0x30cbaf0>
ffffffff8afc515f:	0f 32                	rdmsr
ffffffff8afc5161:	89 c0                	mov    %eax,%eax
ffffffff8afc5163:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5167:	48 09 c2             	or     %rax,%rdx
ffffffff8afc516a:	31 c0                	xor    %eax,%eax
ffffffff8afc516c:	48 89 15 85 c5 0c 03 	mov    %rdx,0x30cc585(%rip)        # ffffffff8e0916f8 <frame_candidate_605c40+0x30cbab8>
ffffffff8afc5173:	31 d2                	xor    %edx,%edx
ffffffff8afc5175:	0f 30                	wrmsr
ffffffff8afc5177:	b9 43 02 01 c0       	mov    $0xc0010243,%ecx
ffffffff8afc517c:	0f 32                	rdmsr
ffffffff8afc517e:	89 c0                	mov    %eax,%eax
ffffffff8afc5180:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5184:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc5189:	48 09 c2             	or     %rax,%rdx
ffffffff8afc518c:	48 89 15 a5 c5 0c 03 	mov    %rdx,0x30cc5a5(%rip)        # ffffffff8e091738 <frame_candidate_605c40+0x30cbaf8>
ffffffff8afc5193:	0f 32                	rdmsr
ffffffff8afc5195:	89 c0                	mov    %eax,%eax
ffffffff8afc5197:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc519b:	48 09 c2             	or     %rax,%rdx
ffffffff8afc519e:	31 c0                	xor    %eax,%eax
ffffffff8afc51a0:	48 89 15 59 c5 0c 03 	mov    %rdx,0x30cc559(%rip)        # ffffffff8e091700 <frame_candidate_605c40+0x30cbac0>
ffffffff8afc51a7:	31 d2                	xor    %edx,%edx
ffffffff8afc51a9:	0f 30                	wrmsr
ffffffff8afc51ab:	b9 45 02 01 c0       	mov    $0xc0010245,%ecx
ffffffff8afc51b0:	0f 32                	rdmsr
ffffffff8afc51b2:	89 c0                	mov    %eax,%eax
ffffffff8afc51b4:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc51b8:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc51bd:	48 09 c2             	or     %rax,%rdx
ffffffff8afc51c0:	48 89 15 79 c5 0c 03 	mov    %rdx,0x30cc579(%rip)        # ffffffff8e091740 <frame_candidate_605c40+0x30cbb00>
ffffffff8afc51c7:	0f 32                	rdmsr
ffffffff8afc51c9:	89 c0                	mov    %eax,%eax
ffffffff8afc51cb:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc51cf:	48 09 c2             	or     %rax,%rdx
ffffffff8afc51d2:	31 c0                	xor    %eax,%eax
ffffffff8afc51d4:	48 89 15 2d c5 0c 03 	mov    %rdx,0x30cc52d(%rip)        # ffffffff8e091708 <frame_candidate_605c40+0x30cbac8>
ffffffff8afc51db:	31 d2                	xor    %edx,%edx
ffffffff8afc51dd:	0f 30                	wrmsr
ffffffff8afc51df:	b9 47 02 01 c0       	mov    $0xc0010247,%ecx
ffffffff8afc51e4:	0f 32                	rdmsr
ffffffff8afc51e6:	89 c0                	mov    %eax,%eax
ffffffff8afc51e8:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc51ec:	48 09 c2             	or     %rax,%rdx
ffffffff8afc51ef:	48 89 15 52 c5 0c 03 	mov    %rdx,0x30cc552(%rip)        # ffffffff8e091748 <frame_candidate_605c40+0x30cbb08>
ffffffff8afc51f6:	e8 15 56 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc51fb:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc5200:	0f 82 e0 00 00 00    	jb     ffffffff8afc52e6 <frame_candidate_605120+0x1c6>
ffffffff8afc5206:	e8 05 56 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc520b:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc5210:	0f 87 d0 00 00 00    	ja     ffffffff8afc52e6 <frame_candidate_605120+0x1c6>
ffffffff8afc5216:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc521b:	0f 32                	rdmsr
ffffffff8afc521d:	89 c0                	mov    %eax,%eax
ffffffff8afc521f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5223:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5226:	31 c0                	xor    %eax,%eax
ffffffff8afc5228:	48 89 15 e1 c4 0c 03 	mov    %rdx,0x30cc4e1(%rip)        # ffffffff8e091710 <frame_candidate_605c40+0x30cbad0>
ffffffff8afc522f:	31 d2                	xor    %edx,%edx
ffffffff8afc5231:	0f 30                	wrmsr
ffffffff8afc5233:	b9 91 01 01 c0       	mov    $0xc0010191,%ecx
ffffffff8afc5238:	0f 32                	rdmsr
ffffffff8afc523a:	89 c0                	mov    %eax,%eax
ffffffff8afc523c:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5240:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc5245:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5248:	48 89 15 01 c5 0c 03 	mov    %rdx,0x30cc501(%rip)        # ffffffff8e091750 <frame_candidate_605c40+0x30cbb10>
ffffffff8afc524f:	0f 32                	rdmsr
ffffffff8afc5251:	89 c0                	mov    %eax,%eax
ffffffff8afc5253:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5257:	48 09 c2             	or     %rax,%rdx
ffffffff8afc525a:	31 c0                	xor    %eax,%eax
ffffffff8afc525c:	48 89 15 b5 c4 0c 03 	mov    %rdx,0x30cc4b5(%rip)        # ffffffff8e091718 <frame_candidate_605c40+0x30cbad8>
ffffffff8afc5263:	31 d2                	xor    %edx,%edx
ffffffff8afc5265:	0f 30                	wrmsr
ffffffff8afc5267:	b9 93 01 01 c0       	mov    $0xc0010193,%ecx
ffffffff8afc526c:	0f 32                	rdmsr
ffffffff8afc526e:	89 c0                	mov    %eax,%eax
ffffffff8afc5270:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5274:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc5279:	48 09 c2             	or     %rax,%rdx
ffffffff8afc527c:	48 89 15 d5 c4 0c 03 	mov    %rdx,0x30cc4d5(%rip)        # ffffffff8e091758 <frame_candidate_605c40+0x30cbb18>
ffffffff8afc5283:	0f 32                	rdmsr
ffffffff8afc5285:	89 c0                	mov    %eax,%eax
ffffffff8afc5287:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc528b:	48 09 c2             	or     %rax,%rdx
ffffffff8afc528e:	31 c0                	xor    %eax,%eax
ffffffff8afc5290:	48 89 15 89 c4 0c 03 	mov    %rdx,0x30cc489(%rip)        # ffffffff8e091720 <frame_candidate_605c40+0x30cbae0>
ffffffff8afc5297:	31 d2                	xor    %edx,%edx
ffffffff8afc5299:	0f 30                	wrmsr
ffffffff8afc529b:	b9 95 01 01 c0       	mov    $0xc0010195,%ecx
ffffffff8afc52a0:	0f 32                	rdmsr
ffffffff8afc52a2:	89 c0                	mov    %eax,%eax
ffffffff8afc52a4:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc52a8:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc52ad:	48 09 c2             	or     %rax,%rdx
ffffffff8afc52b0:	48 89 15 a9 c4 0c 03 	mov    %rdx,0x30cc4a9(%rip)        # ffffffff8e091760 <frame_candidate_605c40+0x30cbb20>
ffffffff8afc52b7:	0f 32                	rdmsr
ffffffff8afc52b9:	89 c0                	mov    %eax,%eax
ffffffff8afc52bb:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc52bf:	48 09 c2             	or     %rax,%rdx
ffffffff8afc52c2:	31 c0                	xor    %eax,%eax
ffffffff8afc52c4:	48 89 15 5d c4 0c 03 	mov    %rdx,0x30cc45d(%rip)        # ffffffff8e091728 <frame_candidate_605c40+0x30cbae8>
ffffffff8afc52cb:	31 d2                	xor    %edx,%edx
ffffffff8afc52cd:	0f 30                	wrmsr
ffffffff8afc52cf:	b9 97 01 01 c0       	mov    $0xc0010197,%ecx
ffffffff8afc52d4:	0f 32                	rdmsr
ffffffff8afc52d6:	89 c0                	mov    %eax,%eax
ffffffff8afc52d8:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc52dc:	48 09 c2             	or     %rax,%rdx
ffffffff8afc52df:	48 89 15 82 c4 0c 03 	mov    %rdx,0x30cc482(%rip)        # ffffffff8e091768 <frame_candidate_605c40+0x30cbb28>
ffffffff8afc52e6:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc52ed:	00 00 
ffffffff8afc52ef:	48 8d 15 5b 62 ca 00 	lea    0xca625b(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc52f6:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc52f9:	b9 c7 05 00 00       	mov    $0x5c7,%ecx
ffffffff8afc52fe:	31 f6                	xor    %esi,%esi
ffffffff8afc5300:	e8 ab 25 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc5305:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5308:	e8 53 25 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc530d:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5310:	31 f6                	xor    %esi,%esi
ffffffff8afc5312:	e8 a9 24 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc5317:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc531c:	0f 32                	rdmsr
ffffffff8afc531e:	89 c0                	mov    %eax,%eax
ffffffff8afc5320:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5324:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5329:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc532c:	48 09 c2             	or     %rax,%rdx
ffffffff8afc532f:	48 89 15 3a c4 0c 03 	mov    %rdx,0x30cc43a(%rip)        # ffffffff8e091770 <frame_candidate_605c40+0x30cbb30>
ffffffff8afc5336:	0f 32                	rdmsr
ffffffff8afc5338:	89 c0                	mov    %eax,%eax
ffffffff8afc533a:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc533e:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc5343:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5346:	48 89 15 2b c4 0c 03 	mov    %rdx,0x30cc42b(%rip)        # ffffffff8e091778 <frame_candidate_605c40+0x30cbb38>
ffffffff8afc534d:	0f 32                	rdmsr
ffffffff8afc534f:	89 c0                	mov    %eax,%eax
ffffffff8afc5351:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5355:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc535a:	48 09 c2             	or     %rax,%rdx
ffffffff8afc535d:	48 89 15 1c c4 0c 03 	mov    %rdx,0x30cc41c(%rip)        # ffffffff8e091780 <frame_candidate_605c40+0x30cbb40>
ffffffff8afc5364:	0f 32                	rdmsr
ffffffff8afc5366:	89 c0                	mov    %eax,%eax
ffffffff8afc5368:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc536c:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc5371:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5374:	48 89 15 0d c4 0c 03 	mov    %rdx,0x30cc40d(%rip)        # ffffffff8e091788 <frame_candidate_605c40+0x30cbb48>
ffffffff8afc537b:	0f 32                	rdmsr
ffffffff8afc537d:	89 c0                	mov    %eax,%eax
ffffffff8afc537f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5383:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc5388:	48 09 c2             	or     %rax,%rdx
ffffffff8afc538b:	48 89 15 fe c3 0c 03 	mov    %rdx,0x30cc3fe(%rip)        # ffffffff8e091790 <frame_candidate_605c40+0x30cbb50>
ffffffff8afc5392:	0f 32                	rdmsr
ffffffff8afc5394:	89 c0                	mov    %eax,%eax
ffffffff8afc5396:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc539a:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc539f:	48 09 c2             	or     %rax,%rdx
ffffffff8afc53a2:	31 c0                	xor    %eax,%eax
ffffffff8afc53a4:	48 89 15 ed c3 0c 03 	mov    %rdx,0x30cc3ed(%rip)        # ffffffff8e091798 <frame_candidate_605c40+0x30cbb58>
ffffffff8afc53ab:	31 d2                	xor    %edx,%edx
ffffffff8afc53ad:	0f 30                	wrmsr
ffffffff8afc53af:	31 c0                	xor    %eax,%eax
ffffffff8afc53b1:	31 d2                	xor    %edx,%edx
ffffffff8afc53b3:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc53b8:	0f 30                	wrmsr
ffffffff8afc53ba:	31 c0                	xor    %eax,%eax
ffffffff8afc53bc:	31 d2                	xor    %edx,%edx
ffffffff8afc53be:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc53c3:	0f 30                	wrmsr
ffffffff8afc53c5:	31 c0                	xor    %eax,%eax
ffffffff8afc53c7:	31 d2                	xor    %edx,%edx
ffffffff8afc53c9:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc53ce:	0f 30                	wrmsr
ffffffff8afc53d0:	31 c0                	xor    %eax,%eax
ffffffff8afc53d2:	31 d2                	xor    %edx,%edx
ffffffff8afc53d4:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc53d9:	0f 30                	wrmsr
ffffffff8afc53db:	31 c0                	xor    %eax,%eax
ffffffff8afc53dd:	31 d2                	xor    %edx,%edx
ffffffff8afc53df:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc53e4:	0f 30                	wrmsr
ffffffff8afc53e6:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc53eb:	0f 32                	rdmsr
ffffffff8afc53ed:	89 c0                	mov    %eax,%eax
ffffffff8afc53ef:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc53f3:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc53f8:	48 09 c2             	or     %rax,%rdx
ffffffff8afc53fb:	48 89 15 ce c3 0c 03 	mov    %rdx,0x30cc3ce(%rip)        # ffffffff8e0917d0 <frame_candidate_605c40+0x30cbb90>
ffffffff8afc5402:	0f 32                	rdmsr
ffffffff8afc5404:	89 c0                	mov    %eax,%eax
ffffffff8afc5406:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc540a:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc540f:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5412:	48 89 15 bf c3 0c 03 	mov    %rdx,0x30cc3bf(%rip)        # ffffffff8e0917d8 <frame_candidate_605c40+0x30cbb98>
ffffffff8afc5419:	0f 32                	rdmsr
ffffffff8afc541b:	89 c0                	mov    %eax,%eax
ffffffff8afc541d:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5421:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc5426:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5429:	48 89 15 b0 c3 0c 03 	mov    %rdx,0x30cc3b0(%rip)        # ffffffff8e0917e0 <frame_candidate_605c40+0x30cbba0>
ffffffff8afc5430:	0f 32                	rdmsr
ffffffff8afc5432:	89 c0                	mov    %eax,%eax
ffffffff8afc5434:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5438:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc543d:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5440:	48 89 15 a1 c3 0c 03 	mov    %rdx,0x30cc3a1(%rip)        # ffffffff8e0917e8 <frame_candidate_605c40+0x30cbba8>
ffffffff8afc5447:	0f 32                	rdmsr
ffffffff8afc5449:	89 c0                	mov    %eax,%eax
ffffffff8afc544b:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc544f:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc5454:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5457:	48 89 15 92 c3 0c 03 	mov    %rdx,0x30cc392(%rip)        # ffffffff8e0917f0 <frame_candidate_605c40+0x30cbbb0>
ffffffff8afc545e:	0f 32                	rdmsr
ffffffff8afc5460:	89 c0                	mov    %eax,%eax
ffffffff8afc5462:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5466:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5469:	48 89 15 88 c3 0c 03 	mov    %rdx,0x30cc388(%rip)        # ffffffff8e0917f8 <frame_candidate_605c40+0x30cbbb8>
ffffffff8afc5470:	e8 eb 23 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc5475:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5478:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc547d:	e8 3e 23 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc5482:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc5487:	0f 32                	rdmsr
ffffffff8afc5489:	89 c0                	mov    %eax,%eax
ffffffff8afc548b:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc548f:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5494:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5497:	48 09 c2             	or     %rax,%rdx
ffffffff8afc549a:	48 89 15 ff c2 0c 03 	mov    %rdx,0x30cc2ff(%rip)        # ffffffff8e0917a0 <frame_candidate_605c40+0x30cbb60>
ffffffff8afc54a1:	0f 32                	rdmsr
ffffffff8afc54a3:	89 c0                	mov    %eax,%eax
ffffffff8afc54a5:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54a9:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc54ae:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54b1:	48 89 15 f0 c2 0c 03 	mov    %rdx,0x30cc2f0(%rip)        # ffffffff8e0917a8 <frame_candidate_605c40+0x30cbb68>
ffffffff8afc54b8:	0f 32                	rdmsr
ffffffff8afc54ba:	89 c0                	mov    %eax,%eax
ffffffff8afc54bc:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54c0:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc54c5:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54c8:	48 89 15 e1 c2 0c 03 	mov    %rdx,0x30cc2e1(%rip)        # ffffffff8e0917b0 <frame_candidate_605c40+0x30cbb70>
ffffffff8afc54cf:	0f 32                	rdmsr
ffffffff8afc54d1:	89 c0                	mov    %eax,%eax
ffffffff8afc54d3:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54d7:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc54dc:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54df:	48 89 15 d2 c2 0c 03 	mov    %rdx,0x30cc2d2(%rip)        # ffffffff8e0917b8 <frame_candidate_605c40+0x30cbb78>
ffffffff8afc54e6:	0f 32                	rdmsr
ffffffff8afc54e8:	89 c0                	mov    %eax,%eax
ffffffff8afc54ea:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54ee:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc54f3:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54f6:	48 89 15 c3 c2 0c 03 	mov    %rdx,0x30cc2c3(%rip)        # ffffffff8e0917c0 <frame_candidate_605c40+0x30cbb80>
ffffffff8afc54fd:	0f 32                	rdmsr
ffffffff8afc54ff:	89 c0                	mov    %eax,%eax
ffffffff8afc5501:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5505:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc550a:	48 09 c2             	or     %rax,%rdx
ffffffff8afc550d:	31 c0                	xor    %eax,%eax
ffffffff8afc550f:	48 89 15 b2 c2 0c 03 	mov    %rdx,0x30cc2b2(%rip)        # ffffffff8e0917c8 <frame_candidate_605c40+0x30cbb88>
ffffffff8afc5516:	31 d2                	xor    %edx,%edx
ffffffff8afc5518:	0f 30                	wrmsr
ffffffff8afc551a:	31 c0                	xor    %eax,%eax
ffffffff8afc551c:	31 d2                	xor    %edx,%edx
ffffffff8afc551e:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5523:	0f 30                	wrmsr
ffffffff8afc5525:	31 c0                	xor    %eax,%eax
ffffffff8afc5527:	31 d2                	xor    %edx,%edx
ffffffff8afc5529:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc552e:	0f 30                	wrmsr
ffffffff8afc5530:	31 c0                	xor    %eax,%eax
ffffffff8afc5532:	31 d2                	xor    %edx,%edx
ffffffff8afc5534:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc5539:	0f 30                	wrmsr
ffffffff8afc553b:	31 c0                	xor    %eax,%eax
ffffffff8afc553d:	31 d2                	xor    %edx,%edx
ffffffff8afc553f:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc5544:	0f 30                	wrmsr
ffffffff8afc5546:	31 c0                	xor    %eax,%eax
ffffffff8afc5548:	31 d2                	xor    %edx,%edx
ffffffff8afc554a:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc554f:	0f 30                	wrmsr
ffffffff8afc5551:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc5556:	0f 32                	rdmsr
ffffffff8afc5558:	89 c0                	mov    %eax,%eax
ffffffff8afc555a:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc555e:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc5563:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5566:	48 89 15 93 c2 0c 03 	mov    %rdx,0x30cc293(%rip)        # ffffffff8e091800 <frame_candidate_605c40+0x30cbbc0>
ffffffff8afc556d:	0f 32                	rdmsr
ffffffff8afc556f:	89 c0                	mov    %eax,%eax
ffffffff8afc5571:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5575:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc557a:	48 09 c2             	or     %rax,%rdx
ffffffff8afc557d:	48 89 15 84 c2 0c 03 	mov    %rdx,0x30cc284(%rip)        # ffffffff8e091808 <frame_candidate_605c40+0x30cbbc8>
ffffffff8afc5584:	0f 32                	rdmsr
ffffffff8afc5586:	89 c0                	mov    %eax,%eax
ffffffff8afc5588:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc558c:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc5591:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5594:	48 89 15 75 c2 0c 03 	mov    %rdx,0x30cc275(%rip)        # ffffffff8e091810 <frame_candidate_605c40+0x30cbbd0>
ffffffff8afc559b:	0f 32                	rdmsr
ffffffff8afc559d:	89 c0                	mov    %eax,%eax
ffffffff8afc559f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc55a3:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc55a8:	48 09 c2             	or     %rax,%rdx
ffffffff8afc55ab:	48 89 15 66 c2 0c 03 	mov    %rdx,0x30cc266(%rip)        # ffffffff8e091818 <frame_candidate_605c40+0x30cbbd8>
ffffffff8afc55b2:	0f 32                	rdmsr
ffffffff8afc55b4:	89 c0                	mov    %eax,%eax
ffffffff8afc55b6:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc55ba:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc55bf:	48 09 c2             	or     %rax,%rdx
ffffffff8afc55c2:	48 89 15 57 c2 0c 03 	mov    %rdx,0x30cc257(%rip)        # ffffffff8e091820 <frame_candidate_605c40+0x30cbbe0>
ffffffff8afc55c9:	0f 32                	rdmsr
ffffffff8afc55cb:	89 c0                	mov    %eax,%eax
ffffffff8afc55cd:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc55d1:	48 09 c2             	or     %rax,%rdx
ffffffff8afc55d4:	48 89 15 4d c2 0c 03 	mov    %rdx,0x30cc24d(%rip)        # ffffffff8e091828 <frame_candidate_605c40+0x30cbbe8>
ffffffff8afc55db:	e8 80 22 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc55e0:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc55e3:	31 f6                	xor    %esi,%esi
ffffffff8afc55e5:	31 d2                	xor    %edx,%edx
ffffffff8afc55e7:	31 c9                	xor    %ecx,%ecx
ffffffff8afc55e9:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc55ed:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8afc55f1:	5b                   	pop    %rbx
ffffffff8afc55f2:	5d                   	pop    %rbp
ffffffff8afc55f3:	e9 28 1f ec ff       	jmp    ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc55f8:	90                   	nop
ffffffff8afc55f9:	90                   	nop
ffffffff8afc55fa:	90                   	nop
ffffffff8afc55fb:	90                   	nop
ffffffff8afc55fc:	90                   	nop
ffffffff8afc55fd:	90                   	nop
ffffffff8afc55fe:	90                   	nop
ffffffff8afc55ff:	90                   	nop

ffffffff8afc5600 <frame_candidate_605600>:
ffffffff8afc5600:	55                   	push   %rbp
ffffffff8afc5601:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5604:	53                   	push   %rbx
ffffffff8afc5605:	50                   	push   %rax
ffffffff8afc5606:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc560d:	00 00 
ffffffff8afc560f:	48 8d 15 3b 5f ca 00 	lea    0xca5f3b(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_605c40+0xca5911>
ffffffff8afc5616:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5619:	b9 fc 05 00 00       	mov    $0x5fc,%ecx
ffffffff8afc561e:	31 f6                	xor    %esi,%esi
ffffffff8afc5620:	e8 8b 22 ec ff       	call   ffffffff8ae878b0 <handler_625_body-0x13c3e0>
ffffffff8afc5625:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5628:	31 f6                	xor    %esi,%esi
ffffffff8afc562a:	e8 91 21 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc562f:	48 8b 05 3a c1 0c 03 	mov    0x30cc13a(%rip),%rax        # ffffffff8e091770 <frame_candidate_605c40+0x30cbb30>
ffffffff8afc5636:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc563b:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc563e:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5641:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5645:	0f 30                	wrmsr
ffffffff8afc5647:	48 8b 05 2a c1 0c 03 	mov    0x30cc12a(%rip),%rax        # ffffffff8e091778 <frame_candidate_605c40+0x30cbb38>
ffffffff8afc564e:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5653:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5656:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc565a:	0f 30                	wrmsr
ffffffff8afc565c:	48 8b 05 1d c1 0c 03 	mov    0x30cc11d(%rip),%rax        # ffffffff8e091780 <frame_candidate_605c40+0x30cbb40>
ffffffff8afc5663:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc5668:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc566b:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc566f:	0f 30                	wrmsr
ffffffff8afc5671:	48 8b 05 10 c1 0c 03 	mov    0x30cc110(%rip),%rax        # ffffffff8e091788 <frame_candidate_605c40+0x30cbb48>
ffffffff8afc5678:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc567d:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5680:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5684:	0f 30                	wrmsr
ffffffff8afc5686:	48 8b 05 03 c1 0c 03 	mov    0x30cc103(%rip),%rax        # ffffffff8e091790 <frame_candidate_605c40+0x30cbb50>
ffffffff8afc568d:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc5692:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5695:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5699:	0f 30                	wrmsr
ffffffff8afc569b:	48 8b 05 f6 c0 0c 03 	mov    0x30cc0f6(%rip),%rax        # ffffffff8e091798 <frame_candidate_605c40+0x30cbb58>
ffffffff8afc56a2:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc56a7:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56aa:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56ae:	0f 30                	wrmsr
ffffffff8afc56b0:	48 8b 05 19 c1 0c 03 	mov    0x30cc119(%rip),%rax        # ffffffff8e0917d0 <frame_candidate_605c40+0x30cbb90>
ffffffff8afc56b7:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc56bc:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56bf:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56c3:	0f 30                	wrmsr
ffffffff8afc56c5:	48 8b 05 0c c1 0c 03 	mov    0x30cc10c(%rip),%rax        # ffffffff8e0917d8 <frame_candidate_605c40+0x30cbb98>
ffffffff8afc56cc:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc56d1:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56d4:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56d8:	0f 30                	wrmsr
ffffffff8afc56da:	48 8b 05 ff c0 0c 03 	mov    0x30cc0ff(%rip),%rax        # ffffffff8e0917e0 <frame_candidate_605c40+0x30cbba0>
ffffffff8afc56e1:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc56e6:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56e9:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56ed:	0f 30                	wrmsr
ffffffff8afc56ef:	48 8b 05 f2 c0 0c 03 	mov    0x30cc0f2(%rip),%rax        # ffffffff8e0917e8 <frame_candidate_605c40+0x30cbba8>
ffffffff8afc56f6:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc56fb:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56fe:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5702:	0f 30                	wrmsr
ffffffff8afc5704:	48 8b 05 e5 c0 0c 03 	mov    0x30cc0e5(%rip),%rax        # ffffffff8e0917f0 <frame_candidate_605c40+0x30cbbb0>
ffffffff8afc570b:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc5710:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5713:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5717:	0f 30                	wrmsr
ffffffff8afc5719:	48 8b 05 d8 c0 0c 03 	mov    0x30cc0d8(%rip),%rax        # ffffffff8e0917f8 <frame_candidate_605c40+0x30cbbb8>
ffffffff8afc5720:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc5725:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5728:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc572c:	0f 30                	wrmsr
ffffffff8afc572e:	e8 2d 21 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc5733:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5736:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc573b:	e8 80 20 0b 00       	call   ffffffff8b0777c0 <frame_candidate_605c40+0xb1b80>
ffffffff8afc5740:	48 8b 05 59 c0 0c 03 	mov    0x30cc059(%rip),%rax        # ffffffff8e0917a0 <frame_candidate_605c40+0x30cbb60>
ffffffff8afc5747:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc574c:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc574f:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5752:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5756:	0f 30                	wrmsr
ffffffff8afc5758:	48 8b 05 49 c0 0c 03 	mov    0x30cc049(%rip),%rax        # ffffffff8e0917a8 <frame_candidate_605c40+0x30cbb68>
ffffffff8afc575f:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5764:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5767:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc576b:	0f 30                	wrmsr
ffffffff8afc576d:	48 8b 05 3c c0 0c 03 	mov    0x30cc03c(%rip),%rax        # ffffffff8e0917b0 <frame_candidate_605c40+0x30cbb70>
ffffffff8afc5774:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc5779:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc577c:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5780:	0f 30                	wrmsr
ffffffff8afc5782:	48 8b 05 2f c0 0c 03 	mov    0x30cc02f(%rip),%rax        # ffffffff8e0917b8 <frame_candidate_605c40+0x30cbb78>
ffffffff8afc5789:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc578e:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5791:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5795:	0f 30                	wrmsr
ffffffff8afc5797:	48 8b 05 22 c0 0c 03 	mov    0x30cc022(%rip),%rax        # ffffffff8e0917c0 <frame_candidate_605c40+0x30cbb80>
ffffffff8afc579e:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc57a3:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57a6:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57aa:	0f 30                	wrmsr
ffffffff8afc57ac:	48 8b 05 15 c0 0c 03 	mov    0x30cc015(%rip),%rax        # ffffffff8e0917c8 <frame_candidate_605c40+0x30cbb88>
ffffffff8afc57b3:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc57b8:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57bb:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57bf:	0f 30                	wrmsr
ffffffff8afc57c1:	48 8b 05 38 c0 0c 03 	mov    0x30cc038(%rip),%rax        # ffffffff8e091800 <frame_candidate_605c40+0x30cbbc0>
ffffffff8afc57c8:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc57cd:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57d0:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57d4:	0f 30                	wrmsr
ffffffff8afc57d6:	48 8b 05 2b c0 0c 03 	mov    0x30cc02b(%rip),%rax        # ffffffff8e091808 <frame_candidate_605c40+0x30cbbc8>
ffffffff8afc57dd:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc57e2:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57e5:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57e9:	0f 30                	wrmsr
ffffffff8afc57eb:	48 8b 05 1e c0 0c 03 	mov    0x30cc01e(%rip),%rax        # ffffffff8e091810 <frame_candidate_605c40+0x30cbbd0>
ffffffff8afc57f2:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc57f7:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57fa:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57fe:	0f 30                	wrmsr
ffffffff8afc5800:	48 8b 05 11 c0 0c 03 	mov    0x30cc011(%rip),%rax        # ffffffff8e091818 <frame_candidate_605c40+0x30cbbd8>
ffffffff8afc5807:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc580c:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc580f:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5813:	0f 30                	wrmsr
ffffffff8afc5815:	48 8b 05 04 c0 0c 03 	mov    0x30cc004(%rip),%rax        # ffffffff8e091820 <frame_candidate_605c40+0x30cbbe0>
ffffffff8afc581c:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc5821:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5824:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5828:	0f 30                	wrmsr
ffffffff8afc582a:	48 8b 05 f7 bf 0c 03 	mov    0x30cbff7(%rip),%rax        # ffffffff8e091828 <frame_candidate_605c40+0x30cbbe8>
ffffffff8afc5831:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc5836:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5839:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc583d:	0f 30                	wrmsr
ffffffff8afc583f:	e8 1c 20 0b 00       	call   ffffffff8b077860 <frame_candidate_605c40+0xb1c20>
ffffffff8afc5844:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc5847:	31 f6                	xor    %esi,%esi
ffffffff8afc5849:	31 d2                	xor    %edx,%edx
ffffffff8afc584b:	31 c9                	xor    %ecx,%ecx
ffffffff8afc584d:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc5851:	e8 ca 1c ec ff       	call   ffffffff8ae87520 <handler_625_body-0x13c770>
ffffffff8afc5856:	48 8b 05 d3 be 0c 03 	mov    0x30cbed3(%rip),%rax        # ffffffff8e091730 <frame_candidate_605c40+0x30cbaf0>
ffffffff8afc585d:	b9 41 02 01 c0       	mov    $0xc0010241,%ecx
ffffffff8afc5862:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5865:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5869:	0f 30                	wrmsr
ffffffff8afc586b:	48 8b 05 7e be 0c 03 	mov    0x30cbe7e(%rip),%rax        # ffffffff8e0916f0 <frame_candidate_605c40+0x30cbab0>
ffffffff8afc5872:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc5877:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc587a:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc587e:	0f 30                	wrmsr
ffffffff8afc5880:	48 8b 05 b1 be 0c 03 	mov    0x30cbeb1(%rip),%rax        # ffffffff8e091738 <frame_candidate_605c40+0x30cbaf8>
ffffffff8afc5887:	b9 43 02 01 c0       	mov    $0xc0010243,%ecx
ffffffff8afc588c:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc588f:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5893:	0f 30                	wrmsr
ffffffff8afc5895:	48 8b 05 5c be 0c 03 	mov    0x30cbe5c(%rip),%rax        # ffffffff8e0916f8 <frame_candidate_605c40+0x30cbab8>
ffffffff8afc589c:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc58a1:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58a4:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58a8:	0f 30                	wrmsr
ffffffff8afc58aa:	48 8b 05 8f be 0c 03 	mov    0x30cbe8f(%rip),%rax        # ffffffff8e091740 <frame_candidate_605c40+0x30cbb00>
ffffffff8afc58b1:	b9 45 02 01 c0       	mov    $0xc0010245,%ecx
ffffffff8afc58b6:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58b9:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58bd:	0f 30                	wrmsr
ffffffff8afc58bf:	48 8b 05 3a be 0c 03 	mov    0x30cbe3a(%rip),%rax        # ffffffff8e091700 <frame_candidate_605c40+0x30cbac0>
ffffffff8afc58c6:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc58cb:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58ce:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58d2:	0f 30                	wrmsr
ffffffff8afc58d4:	48 8b 05 6d be 0c 03 	mov    0x30cbe6d(%rip),%rax        # ffffffff8e091748 <frame_candidate_605c40+0x30cbb08>
ffffffff8afc58db:	b9 47 02 01 c0       	mov    $0xc0010247,%ecx
ffffffff8afc58e0:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58e3:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58e7:	0f 30                	wrmsr
ffffffff8afc58e9:	48 8b 05 18 be 0c 03 	mov    0x30cbe18(%rip),%rax        # ffffffff8e091708 <frame_candidate_605c40+0x30cbac8>
ffffffff8afc58f0:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc58f5:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58f8:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58fc:	0f 30                	wrmsr
ffffffff8afc58fe:	e8 0d 4f 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc5903:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc5908:	0f 82 b8 00 00 00    	jb     ffffffff8afc59c6 <frame_candidate_605600+0x3c6>
ffffffff8afc590e:	e8 fd 4e 0d 00       	call   ffffffff8b09a810 <frame_candidate_605c40+0xd4bd0>
ffffffff8afc5913:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc5918:	0f 87 a8 00 00 00    	ja     ffffffff8afc59c6 <frame_candidate_605600+0x3c6>
ffffffff8afc591e:	48 8b 05 2b be 0c 03 	mov    0x30cbe2b(%rip),%rax        # ffffffff8e091750 <frame_candidate_605c40+0x30cbb10>
ffffffff8afc5925:	b9 91 01 01 c0       	mov    $0xc0010191,%ecx
ffffffff8afc592a:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc592d:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5931:	0f 30                	wrmsr
ffffffff8afc5933:	48 8b 05 d6 bd 0c 03 	mov    0x30cbdd6(%rip),%rax        # ffffffff8e091710 <frame_candidate_605c40+0x30cbad0>
ffffffff8afc593a:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc593f:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5942:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5946:	0f 30                	wrmsr
ffffffff8afc5948:	48 8b 05 09 be 0c 03 	mov    0x30cbe09(%rip),%rax        # ffffffff8e091758 <frame_candidate_605c40+0x30cbb18>
ffffffff8afc594f:	b9 93 01 01 c0       	mov    $0xc0010193,%ecx
ffffffff8afc5954:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5957:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc595b:	0f 30                	wrmsr
ffffffff8afc595d:	48 8b 05 b4 bd 0c 03 	mov    0x30cbdb4(%rip),%rax        # ffffffff8e091718 <frame_candidate_605c40+0x30cbad8>
ffffffff8afc5964:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc5969:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc596c:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5970:	0f 30                	wrmsr
ffffffff8afc5972:	48 8b 05 e7 bd 0c 03 	mov    0x30cbde7(%rip),%rax        # ffffffff8e091760 <frame_candidate_605c40+0x30cbb20>
ffffffff8afc5979:	b9 95 01 01 c0       	mov    $0xc0010195,%ecx
ffffffff8afc597e:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5981:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5985:	0f 30                	wrmsr
ffffffff8afc5987:	48 8b 05 92 bd 0c 03 	mov    0x30cbd92(%rip),%rax        # ffffffff8e091720 <frame_candidate_605c40+0x30cbae0>
ffffffff8afc598e:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc5993:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5996:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc599a:	0f 30                	wrmsr
ffffffff8afc599c:	48 8b 05 c5 bd 0c 03 	mov    0x30cbdc5(%rip),%rax        # ffffffff8e091768 <frame_candidate_605c40+0x30cbb28>
ffffffff8afc59a3:	b9 97 01 01 c0       	mov    $0xc0010197,%ecx
ffffffff8afc59a8:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc59ab:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc59af:	0f 30                	wrmsr
ffffffff8afc59b1:	48 8b 05 70 bd 0c 03 	mov    0x30cbd70(%rip),%rax        # ffffffff8e091728 <frame_candidate_605c40+0x30cbae8>
ffffffff8afc59b8:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc59bd:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc59c0:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc59c4:	0f 30                	wrmsr
ffffffff8afc59c6:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8afc59ca:	5b                   	pop    %rbx
ffffffff8afc59cb:	5d                   	pop    %rbp
ffffffff8afc59cc:	c3                   	ret
ffffffff8afc59cd:	90                   	nop
ffffffff8afc59ce:	90                   	nop
ffffffff8afc59cf:	90                   	nop

ffffffff8afc59d0 <frame_candidate_6059d0>:
ffffffff8afc59d0:	55                   	push   %rbp
ffffffff8afc59d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc59d4:	53                   	push   %rbx
ffffffff8afc59d5:	50                   	push   %rax
ffffffff8afc59d6:	48 8d 3d 6b be 0c 03 	lea    0x30cbe6b(%rip),%rdi        # ffffffff8e091848 <frame_candidate_605c40+0x30cbc08>
ffffffff8afc59dd:	48 8d 35 b1 31 d2 00 	lea    0xd231b1(%rip),%rsi        # ffffffff8bce8b95 <frame_candidate_605c40+0xd22f55>
ffffffff8afc59e4:	b9 04 00 00 00       	mov    $0x4,%ecx
ffffffff8afc59e9:	31 d2                	xor    %edx,%edx
ffffffff8afc59eb:	e8 e0 23 ec ff       	call   ffffffff8ae87dd0 <handler_625_body-0x13bec0>
ffffffff8afc59f0:	48 8d 1d 39 be 0c 03 	lea    0x30cbe39(%rip),%rbx        # ffffffff8e091830 <frame_candidate_605c40+0x30cbbf0>
ffffffff8afc59f7:	48 8d 3d f2 be 0c 03 	lea    0x30cbef2(%rip),%rdi        # ffffffff8e0918f0 <frame_candidate_605c40+0x30cbcb0>
ffffffff8afc59fe:	48 c7 05 47 be 0c 03 	movq   $0x0,0x30cbe47(%rip)        # ffffffff8e091850 <frame_candidate_605c40+0x30cbc10>
ffffffff8afc5a05:	00 00 00 00 
ffffffff8afc5a09:	48 c7 05 5c be 0c 03 	movq   $0x0,0x30cbe5c(%rip)        # ffffffff8e091870 <frame_candidate_605c40+0x30cbc30>
ffffffff8afc5a10:	00 00 00 00 
ffffffff8afc5a14:	48 c7 05 71 be 0c 03 	movq   $0x0,0x30cbe71(%rip)        # ffffffff8e091890 <frame_candidate_605c40+0x30cbc50>
ffffffff8afc5a1b:	00 00 00 00 
ffffffff8afc5a1f:	48 c7 05 86 be 0c 03 	movq   $0x0,0x30cbe86(%rip)        # ffffffff8e0918b0 <frame_candidate_605c40+0x30cbc70>
ffffffff8afc5a26:	00 00 00 00 
ffffffff8afc5a2a:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a2d:	e8 8e e8 d0 ff       	call   ffffffff8acd42c0 <handler_625_body-0x2ef9d0>
ffffffff8afc5a32:	48 8d 3d 07 bf 0c 03 	lea    0x30cbf07(%rip),%rdi        # ffffffff8e091940 <frame_candidate_605c40+0x30cbd00>
ffffffff8afc5a39:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a3c:	e8 7f e8 d0 ff       	call   ffffffff8acd42c0 <handler_625_body-0x2ef9d0>
ffffffff8afc5a41:	48 8d 3d 48 bf 0c 03 	lea    0x30cbf48(%rip),%rdi        # ffffffff8e091990 <frame_candidate_605c40+0x30cbd50>
ffffffff8afc5a48:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a4b:	e8 70 e8 d0 ff       	call   ffffffff8acd42c0 <handler_625_body-0x2ef9d0>
ffffffff8afc5a50:	48 8d 3d 89 bf 0c 03 	lea    0x30cbf89(%rip),%rdi        # ffffffff8e0919e0 <frame_candidate_605c40+0x30cbda0>
ffffffff8afc5a57:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a5a:	e8 61 e8 d0 ff       	call   ffffffff8acd42c0 <handler_625_body-0x2ef9d0>
ffffffff8afc5a5f:	31 c0                	xor    %eax,%eax
ffffffff8afc5a61:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8afc5a65:	5b                   	pop    %rbx
ffffffff8afc5a66:	5d                   	pop    %rbp
ffffffff8afc5a67:	c3                   	ret
ffffffff8afc5a68:	90                   	nop
ffffffff8afc5a69:	90                   	nop
ffffffff8afc5a6a:	90                   	nop
ffffffff8afc5a6b:	90                   	nop
ffffffff8afc5a6c:	90                   	nop
ffffffff8afc5a6d:	90                   	nop
ffffffff8afc5a6e:	90                   	nop
ffffffff8afc5a6f:	90                   	nop

ffffffff8afc5a70 <frame_candidate_605a70>:
ffffffff8afc5a70:	55                   	push   %rbp
ffffffff8afc5a71:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5a74:	41 56                	push   %r14
ffffffff8afc5a76:	53                   	push   %rbx
ffffffff8afc5a77:	41 89 fe             	mov    %edi,%r14d
ffffffff8afc5a7a:	48 8d 3d c7 bd 0c 03 	lea    0x30cbdc7(%rip),%rdi        # ffffffff8e091848 <frame_candidate_605c40+0x30cbc08>
ffffffff8afc5a81:	31 db                	xor    %ebx,%ebx
ffffffff8afc5a83:	31 f6                	xor    %esi,%esi
ffffffff8afc5a85:	31 d2                	xor    %edx,%edx
ffffffff8afc5a87:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5a89:	e8 72 0f ec ff       	call   ffffffff8ae86a00 <handler_625_body-0x13d290>
ffffffff8afc5a8e:	0f b6 05 3b be 0c 03 	movzbl 0x30cbe3b(%rip),%eax        # ffffffff8e0918d0 <frame_candidate_605c40+0x30cbc90>
ffffffff8afc5a95:	45 85 f6             	test   %r14d,%r14d
ffffffff8afc5a98:	0f 95 c1             	setne  %cl
ffffffff8afc5a9b:	84 c0                	test   %al,%al
ffffffff8afc5a9d:	0f 94 c2             	sete   %dl
ffffffff8afc5aa0:	20 ca                	and    %cl,%dl
ffffffff8afc5aa2:	80 fa 01             	cmp    $0x1,%dl
ffffffff8afc5aa5:	0f 85 91 00 00 00    	jne    ffffffff8afc5b3c <frame_candidate_605a70+0xcc>
ffffffff8afc5aab:	48 83 3d 15 be 0c 03 	cmpq   $0x0,0x30cbe15(%rip)        # ffffffff8e0918c8 <frame_candidate_605c40+0x30cbc88>
ffffffff8afc5ab2:	00 
ffffffff8afc5ab3:	75 1a                	jne    ffffffff8afc5acf <frame_candidate_605a70+0x5f>
ffffffff8afc5ab5:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5aba:	e8 71 b1 38 00       	call   ffffffff8b350c30 <frame_candidate_605c40+0x38aff0>
ffffffff8afc5abf:	48 89 05 02 be 0c 03 	mov    %rax,0x30cbe02(%rip)        # ffffffff8e0918c8 <frame_candidate_605c40+0x30cbc88>
ffffffff8afc5ac6:	48 85 c0             	test   %rax,%rax
ffffffff8afc5ac9:	0f 84 a7 00 00 00    	je     ffffffff8afc5b76 <frame_candidate_605a70+0x106>
ffffffff8afc5acf:	48 83 3d 99 bd 0c 03 	cmpq   $0x0,0x30cbd99(%rip)        # ffffffff8e091870 <frame_candidate_605c40+0x30cbc30>
ffffffff8afc5ad6:	00 
ffffffff8afc5ad7:	75 1a                	jne    ffffffff8afc5af3 <frame_candidate_605a70+0x83>
ffffffff8afc5ad9:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5ade:	e8 4d b1 38 00       	call   ffffffff8b350c30 <frame_candidate_605c40+0x38aff0>
ffffffff8afc5ae3:	48 89 05 86 bd 0c 03 	mov    %rax,0x30cbd86(%rip)        # ffffffff8e091870 <frame_candidate_605c40+0x30cbc30>
ffffffff8afc5aea:	48 85 c0             	test   %rax,%rax
ffffffff8afc5aed:	0f 84 93 00 00 00    	je     ffffffff8afc5b86 <frame_candidate_605a70+0x116>
ffffffff8afc5af3:	48 83 3d 95 bd 0c 03 	cmpq   $0x0,0x30cbd95(%rip)        # ffffffff8e091890 <frame_candidate_605c40+0x30cbc50>
ffffffff8afc5afa:	00 
ffffffff8afc5afb:	75 16                	jne    ffffffff8afc5b13 <frame_candidate_605a70+0xa3>
ffffffff8afc5afd:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5b02:	e8 29 b1 38 00       	call   ffffffff8b350c30 <frame_candidate_605c40+0x38aff0>
ffffffff8afc5b07:	48 89 05 82 bd 0c 03 	mov    %rax,0x30cbd82(%rip)        # ffffffff8e091890 <frame_candidate_605c40+0x30cbc50>
ffffffff8afc5b0e:	48 85 c0             	test   %rax,%rax
ffffffff8afc5b11:	74 77                	je     ffffffff8afc5b8a <frame_candidate_605a70+0x11a>
ffffffff8afc5b13:	48 83 3d 95 bd 0c 03 	cmpq   $0x0,0x30cbd95(%rip)        # ffffffff8e0918b0 <frame_candidate_605c40+0x30cbc70>
ffffffff8afc5b1a:	00 
ffffffff8afc5b1b:	75 16                	jne    ffffffff8afc5b33 <frame_candidate_605a70+0xc3>
ffffffff8afc5b1d:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5b22:	e8 09 b1 38 00       	call   ffffffff8b350c30 <frame_candidate_605c40+0x38aff0>
ffffffff8afc5b27:	48 89 05 82 bd 0c 03 	mov    %rax,0x30cbd82(%rip)        # ffffffff8e0918b0 <frame_candidate_605c40+0x30cbc70>
ffffffff8afc5b2e:	48 85 c0             	test   %rax,%rax
ffffffff8afc5b31:	74 5e                	je     ffffffff8afc5b91 <frame_candidate_605a70+0x121>
ffffffff8afc5b33:	b0 01                	mov    $0x1,%al
ffffffff8afc5b35:	c6 05 94 bd 0c 03 01 	movb   $0x1,0x30cbd94(%rip)        # ffffffff8e0918d0 <frame_candidate_605c40+0x30cbc90>
ffffffff8afc5b3c:	4c 8b 35 0d bd 0c 03 	mov    0x30cbd0d(%rip),%r14        # ffffffff8e091850 <frame_candidate_605c40+0x30cbc10>
ffffffff8afc5b43:	3c 01                	cmp    $0x1,%al
ffffffff8afc5b45:	0f 94 c0             	sete   %al
ffffffff8afc5b48:	4d 85 f6             	test   %r14,%r14
ffffffff8afc5b4b:	0f 95 c1             	setne  %cl
ffffffff8afc5b4e:	20 c1                	and    %al,%cl
ffffffff8afc5b50:	80 f9 01             	cmp    $0x1,%cl
ffffffff8afc5b53:	0f 85 c0 00 00 00    	jne    ffffffff8afc5c19 <frame_candidate_605a70+0x1a9>
ffffffff8afc5b59:	41 80 7e 37 00       	cmpb   $0x0,0x37(%r14)
ffffffff8afc5b5e:	0f 85 b5 00 00 00    	jne    ffffffff8afc5c19 <frame_candidate_605a70+0x1a9>
ffffffff8afc5b64:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8afc5b67:	e8 64 ad 46 00       	call   ffffffff8b4308d0 <frame_candidate_605c40+0x46ac90>
ffffffff8afc5b6c:	41 c6 46 37 01       	movb   $0x1,0x37(%r14)
ffffffff8afc5b71:	e9 a3 00 00 00       	jmp    ffffffff8afc5c19 <frame_candidate_605a70+0x1a9>
ffffffff8afc5b76:	48 8d 3d 44 63 d7 00 	lea    0xd76344(%rip),%rdi        # ffffffff8bd3bec1 <frame_candidate_605c40+0xd76281>
ffffffff8afc5b7d:	31 c0                	xor    %eax,%eax
ffffffff8afc5b7f:	e8 8c 78 c5 ff       	call   ffffffff8ac1d410 <handler_625_body-0x3a6880>
ffffffff8afc5b84:	eb 1e                	jmp    ffffffff8afc5ba4 <frame_candidate_605a70+0x134>
ffffffff8afc5b86:	31 f6                	xor    %esi,%esi
ffffffff8afc5b88:	eb 0c                	jmp    ffffffff8afc5b96 <frame_candidate_605a70+0x126>
ffffffff8afc5b8a:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8afc5b8f:	eb 05                	jmp    ffffffff8afc5b96 <frame_candidate_605a70+0x126>
ffffffff8afc5b91:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8afc5b96:	48 8d 3d e8 59 ca 00 	lea    0xca59e8(%rip),%rdi        # ffffffff8bc6b585 <frame_candidate_605c40+0xca5945>
ffffffff8afc5b9d:	31 c0                	xor    %eax,%eax
ffffffff8afc5b9f:	e8 6c 78 c5 ff       	call   ffffffff8ac1d410 <handler_625_body-0x3a6880>
ffffffff8afc5ba4:	48 8b 3d c5 bc 0c 03 	mov    0x30cbcc5(%rip),%rdi        # ffffffff8e091870 <frame_candidate_605c40+0x30cbc30>
ffffffff8afc5bab:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5bae:	74 10                	je     ffffffff8afc5bc0 <frame_candidate_605a70+0x150>
ffffffff8afc5bb0:	e8 9b b0 38 00       	call   ffffffff8b350c50 <frame_candidate_605c40+0x38b010>
ffffffff8afc5bb5:	48 c7 05 b0 bc 0c 03 	movq   $0x0,0x30cbcb0(%rip)        # ffffffff8e091870 <frame_candidate_605c40+0x30cbc30>
ffffffff8afc5bbc:	00 00 00 00 
ffffffff8afc5bc0:	48 8b 3d c9 bc 0c 03 	mov    0x30cbcc9(%rip),%rdi        # ffffffff8e091890 <frame_candidate_605c40+0x30cbc50>
ffffffff8afc5bc7:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5bca:	74 10                	je     ffffffff8afc5bdc <frame_candidate_605a70+0x16c>
ffffffff8afc5bcc:	e8 7f b0 38 00       	call   ffffffff8b350c50 <frame_candidate_605c40+0x38b010>
ffffffff8afc5bd1:	48 c7 05 b4 bc 0c 03 	movq   $0x0,0x30cbcb4(%rip)        # ffffffff8e091890 <frame_candidate_605c40+0x30cbc50>
ffffffff8afc5bd8:	00 00 00 00 
ffffffff8afc5bdc:	48 8b 3d cd bc 0c 03 	mov    0x30cbccd(%rip),%rdi        # ffffffff8e0918b0 <frame_candidate_605c40+0x30cbc70>
ffffffff8afc5be3:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5be6:	74 10                	je     ffffffff8afc5bf8 <frame_candidate_605a70+0x188>
ffffffff8afc5be8:	e8 63 b0 38 00       	call   ffffffff8b350c50 <frame_candidate_605c40+0x38b010>
ffffffff8afc5bed:	48 c7 05 b8 bc 0c 03 	movq   $0x0,0x30cbcb8(%rip)        # ffffffff8e0918b0 <frame_candidate_605c40+0x30cbc70>
ffffffff8afc5bf4:	00 00 00 00 
ffffffff8afc5bf8:	48 8b 3d c9 bc 0c 03 	mov    0x30cbcc9(%rip),%rdi        # ffffffff8e0918c8 <frame_candidate_605c40+0x30cbc88>
ffffffff8afc5bff:	bb 0c 00 02 80       	mov    $0x8002000c,%ebx
ffffffff8afc5c04:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5c07:	74 10                	je     ffffffff8afc5c19 <frame_candidate_605a70+0x1a9>
ffffffff8afc5c09:	e8 42 b0 38 00       	call   ffffffff8b350c50 <frame_candidate_605c40+0x38b010>
ffffffff8afc5c0e:	48 c7 05 af bc 0c 03 	movq   $0x0,0x30cbcaf(%rip)        # ffffffff8e0918c8 <frame_candidate_605c40+0x30cbc88>
ffffffff8afc5c15:	00 00 00 00 
ffffffff8afc5c19:	48 8d 3d 28 bc 0c 03 	lea    0x30cbc28(%rip),%rdi        # ffffffff8e091848 <frame_candidate_605c40+0x30cbc08>
ffffffff8afc5c20:	31 f6                	xor    %esi,%esi
ffffffff8afc5c22:	31 d2                	xor    %edx,%edx
ffffffff8afc5c24:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5c26:	e8 75 13 ec ff       	call   ffffffff8ae86fa0 <handler_625_body-0x13ccf0>
ffffffff8afc5c2b:	89 d8                	mov    %ebx,%eax
ffffffff8afc5c2d:	5b                   	pop    %rbx
ffffffff8afc5c2e:	41 5e                	pop    %r14
ffffffff8afc5c30:	5d                   	pop    %rbp
ffffffff8afc5c31:	c3                   	ret
ffffffff8afc5c32:	90                   	nop
ffffffff8afc5c33:	90                   	nop
ffffffff8afc5c34:	90                   	nop
ffffffff8afc5c35:	90                   	nop
ffffffff8afc5c36:	90                   	nop
ffffffff8afc5c37:	90                   	nop
ffffffff8afc5c38:	90                   	nop
ffffffff8afc5c39:	90                   	nop
ffffffff8afc5c3a:	90                   	nop
ffffffff8afc5c3b:	90                   	nop
ffffffff8afc5c3c:	90                   	nop
ffffffff8afc5c3d:	90                   	nop
ffffffff8afc5c3e:	90                   	nop
ffffffff8afc5c3f:	90                   	nop

ffffffff8afc5c40 <frame_candidate_605c40>:
ffffffff8afc5c40:	55                   	push   %rbp
ffffffff8afc5c41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5c44:	41 57                	push   %r15
ffffffff8afc5c46:	41 56                	push   %r14
ffffffff8afc5c48:	41 55                	push   %r13
ffffffff8afc5c4a:	41 54                	push   %r12
ffffffff8afc5c4c:	53                   	push   %rbx
ffffffff8afc5c4d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8afc5c51:	89 7d d4             	mov    %edi,-0x2c(%rbp)
ffffffff8afc5c54:	41 89 f6             	mov    %esi,%r14d
ffffffff8afc5c57:	48 8b 1d ea bb 0c 03 	mov    0x30cbbea(%rip),%rbx        # ffffffff8e091848 <frame_candidate_605c40+0x30cbc08>
ffffffff8afc5c5e:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8afc5c65:	00 00 
ffffffff8afc5c67:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8afc5c6b:	48 83 e3 f8          	and    $0xfffffffffffffff8,%rbx
ffffffff8afc5c6f:	48 39 c3             	cmp    %rax,%rbx
ffffffff8afc5c72:	74 12                	je     ffffffff8afc5c86 <frame_candidate_605c40+0x46>
ffffffff8afc5c74:	48 8d 3d cd bb 0c 03 	lea    0x30cbbcd(%rip),%rdi        # ffffffff8e091848 <frame_candidate_605c40+0x30cbc08>
ffffffff8afc5c7b:	31 f6                	xor    %esi,%esi
ffffffff8afc5c7d:	31 d2                	xor    %edx,%edx
ffffffff8afc5c7f:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5c81:	e8 7a 0d ec ff       	call   ffffffff8ae86a00 <handler_625_body-0x13d290>
ffffffff8afc5c86:	80 3d 44 bc 0c 03 00 	cmpb   $0x0,0x30cbc44(%rip)        # ffffffff8e0918d1 <frame_candidate_605c40+0x30cbc91>
ffffffff8afc5c8d:	74 59                	je     ffffffff8afc5ce8 <frame_candidate_605c40+0xa8>
ffffffff8afc5c8f:	4c                   	rex.WR
