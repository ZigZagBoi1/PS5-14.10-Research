; REA 6.7.0 full disassembly of handler_626.bin
; SHA256 b731da2ee06955401f2f234a24d7310a0a1370ad14e337f5f53df1438af4a5c4; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25eb8, kernel RVA 0x265eb8.
; REA inspect_with_objdump Evidence: ev_615ff8f4e306ea1411863888b5d8507d6f5406c9414834b2cb11808e099861cc
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 626; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_626.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25eb8 <handler_626_entry>:
ffffffff8ac25eb8:	e9 33 ee 39 00       	jmp    ffffffff8afc4cf0 <neighbor_trampoline_266eb0+0x39de40>
ffffffff8ac25ebd:	cc                   	int3
ffffffff8ac25ebe:	cc                   	int3
ffffffff8ac25ebf:	cc                   	int3

ffffffff8ac25ec0 <neighbor_trampoline_265ec0>:
ffffffff8ac25ec0:	e9 8b c9 23 00       	jmp    ffffffff8ae62850 <neighbor_trampoline_266eb0+0x23b9a0>
ffffffff8ac25ec5:	cc                   	int3
ffffffff8ac25ec6:	cc                   	int3
ffffffff8ac25ec7:	cc                   	int3

ffffffff8ac25ec8 <neighbor_trampoline_265ec8>:
ffffffff8ac25ec8:	e9 73 76 85 00       	jmp    ffffffff8b47d540 <neighbor_trampoline_266eb0+0x856690>
ffffffff8ac25ecd:	cc                   	int3
ffffffff8ac25ece:	cc                   	int3
ffffffff8ac25ecf:	cc                   	int3

ffffffff8ac25ed0 <neighbor_trampoline_265ed0>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266eb0+0x6b5790>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266eb0+0x6b5dc0>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266eb0+0x1d1f80>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266eb0+0x1d21c0>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266eb0+0x1d22a0>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266eb0+0x1d24f0>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266eb0+0x457620>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266eb0+0x856a80>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266eb0+0x457710>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266eb0+0x457950>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266eb0+0x829f60>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266eb0+0x23bf30>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266eb0+0x856c20>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266eb0+0x7d07b0>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266eb0+0x857310>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266eb0+0x857900>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266eb0+0x791340>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266eb0+0x982660>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266eb0+0x740e60>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266eb0+0x7426b0>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266eb0+0x742f60>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266eb0+0x743090>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266eb0+0x694590>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266eb0+0x23c2f0>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266eb0+0x857a00>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266eb0+0x744340>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266eb0+0x854ad0>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266eb0+0x492430>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266eb0+0x1cdef0>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266eb0+0x1cdf00>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266eb0+0x1cdf10>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266eb0+0x1d0ee0>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266eb0+0x1d13d0>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266eb0+0x87f7e0>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266eb0+0x87f6d0>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266eb0+0x1e2220>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_626_entry-0x1bf0f8>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266eb0+0x1e3bc0>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266eb0+0x74f260>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_626_entry-0x1be848>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_626_entry-0x1be668>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_626_entry-0x1be638>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266eb0+0x1eb190>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266eb0+0x1ede10>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266eb0+0x1f0970>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266eb0+0x2070c0>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266eb0+0x2071d0>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266eb0+0x20bae0>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266eb0+0x20c500>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266eb0+0x20ca00>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266eb0+0x20d3a0>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266eb0+0x20df00>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266eb0+0x216140>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_626_entry-0x47ec8>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266eb0+0x229450>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266eb0+0x229f00>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266eb0+0x231100>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266eb0+0x231130>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266eb0+0x231780>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266eb0+0x231790>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266eb0+0x690d10>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266eb0+0x68f950>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266eb0+0x690570>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266eb0+0x6930d0>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266eb0+0x3784a0>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266eb0+0x378970>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266eb0+0x7cde30>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266eb0+0x3815f0>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266eb0+0x691340>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266eb0+0x692560>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266eb0+0x695540>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266eb0+0x68fde0>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266eb0+0xa4ab60>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266eb0+0x8514f0>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266eb0+0x851500>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266eb0+0x693310>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266eb0+0x690c90>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266eb0+0x239ab0>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266eb0+0x4c28d0>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266eb0+0x4c28e0>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266eb0+0x4c28f0>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266eb0+0x4546e0>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266eb0+0x851ef0>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266eb0+0x6932c0>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266eb0+0x918210>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266eb0+0x918250>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266eb0+0x692e40>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266eb0+0x693890>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266eb0+0x2ebcc0>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266eb0+0x2ebd40>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266eb0+0x2ebda0>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266eb0+0x2ebdd0>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266eb0+0x2ebe00>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266eb0+0x2ebe30>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266eb0+0x917950>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266eb0+0x917d30>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266eb0+0x9180c0>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266eb0+0x99fe80>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266eb0+0x52b7e0>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266eb0+0x381c70>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266eb0+0x2ebe60>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266eb0+0x9182b0>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266eb0+0x3773a0>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266eb0+0x7edb80>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266eb0+0x7edb90>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266eb0+0x7edba0>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266eb0+0x7edbb0>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266eb0+0x7edbd0>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266eb0+0x7edbe0>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266eb0+0x692870>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266eb0+0x7edc00>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266eb0+0x68f630>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266eb0+0x68f040>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266eb0+0x7edb70>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266eb0+0x7edbc0>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266eb0+0x7edbf0>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266eb0+0x47e620>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266eb0+0x918600>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266eb0+0x5d67b0>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266eb0+0x5d6910>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266eb0+0x5d6c00>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266eb0+0x5d6fd0>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266eb0+0x692dd0>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266eb0+0x693260>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266eb0+0x692300>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266eb0+0x693640>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266eb0+0x6911e0>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266eb0+0x694cd0>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266eb0+0x690cd0>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266eb0+0x6909e0>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266eb0+0x6949f0>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266eb0+0x691660>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266eb0+0x691950>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266eb0+0x2341d0>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266eb0+0x2341e0>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266eb0+0x2f8ba0>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266eb0+0x9cd9c0>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266eb0+0x575e40>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266eb0+0x575e50>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266eb0+0x575e60>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266eb0+0x575e70>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266eb0+0x575e80>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266eb0+0x33fde0>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266eb0+0x340450>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266eb0+0x340760>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266eb0+0x340a50>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266eb0+0xa35980>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266eb0+0x341050>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266eb0+0x3411c0>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266eb0+0x9815d0>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266eb0+0x2341f0>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266eb0+0x234210>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266eb0+0x234220>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266eb0+0x234230>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266eb0+0x234240>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266eb0+0x2c9870>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266eb0+0x2ca7c0>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266eb0+0x692840>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266eb0+0x2ca380>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266eb0+0x59bf40>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266eb0+0x918290>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266eb0+0x87c730>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266eb0+0x287f70>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266eb0+0x693c60>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266eb0+0x693f80>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266eb0+0x762370>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266eb0+0x762250>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266eb0+0x3db460>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266eb0+0x3db970>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266eb0+0x3dc830>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266eb0+0x3dca20>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266eb0+0x3dcdb0>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266eb0+0x7913e0>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266eb0+0x794cc0>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266eb0+0x7de3d0>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266eb0+0xa20df0>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266eb0+0x798150>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266eb0+0x7998d0>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266eb0+0x799930>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266eb0+0x857980>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266eb0+0x796080>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266eb0+0x38a110>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266eb0+0x690540>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266eb0+0x2903a0>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266eb0+0x796c20>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266eb0+0x796f00>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266eb0+0x797060>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266eb0+0x3dd620>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266eb0+0x3ea120>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266eb0+0x797b80>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266eb0+0x290a90>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266eb0+0x851c30>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266eb0+0x8547b0>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266eb0+0x7973b0>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266eb0+0x797630>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266eb0+0x797780>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266eb0+0x531480>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266eb0+0x856150>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_626_entry-0x169628>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266eb0+0x2381e0>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266eb0+0x238350>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266eb0+0x2596e0>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266eb0+0x259700>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_626_entry-0x1bca88>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266eb0+0x2634a0>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266eb0+0x263b90>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_626_entry-0x1bb9a8>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266eb0+0x26e320>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266eb0+0x5aa300>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_626_entry-0x24b028>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266eb0+0x289180>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266eb0+0x294d20>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266eb0+0x2a6020>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266eb0+0x2a6030>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266eb0+0x2a6080>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266eb0+0x2a60c0>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266eb0+0x2a6100>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266eb0+0x2a6130>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266eb0+0x2b7620>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266eb0+0x2b80b0>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266eb0+0x2b8150>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266eb0+0x2b8200>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266eb0+0x2b8430>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266eb0+0x2b87c0>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266eb0+0x2b9030>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266eb0+0x2cf550>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266eb0+0x2dddf0>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266eb0+0x2dfa40>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_626_entry-0x1b4888>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_626_entry-0x1b3f08>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266eb0+0x2f5090>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266eb0+0x2f5180>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266eb0+0x2f51a0>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266eb0+0x307350>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266eb0+0x3185f0>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266eb0+0x72d730>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266eb0+0x31eaa0>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266eb0+0x332970>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266eb0+0x333530>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266eb0+0x333680>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266eb0+0x333850>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266eb0+0x333920>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266eb0+0x333ba0>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266eb0+0x333cb0>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266eb0+0x333db0>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266eb0+0x375020>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266eb0+0x384870>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266eb0+0x385180>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266eb0+0x385c20>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266eb0+0x386590>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266eb0+0x386c80>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_626_entry-0x117c38>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266eb0+0x38aa00>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266eb0+0x38bc80>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266eb0+0x396210>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266eb0+0x3997d0>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266eb0+0x39a090>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266eb0+0x87f5f0>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266eb0+0x3c6bf0>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266eb0+0x3c9420>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266eb0+0x3ce060>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266eb0+0x3d8670>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266eb0+0x3f0b00>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266eb0+0xa40460>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266eb0+0x3fbfc0>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266eb0+0x3fbfd0>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266eb0+0x411f60>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266eb0+0x411fb0>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266eb0+0x412010>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266eb0+0x4120b0>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266eb0+0x4122e0>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266eb0+0x4124b0>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266eb0+0x4127d0>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_626_entry-0x232328>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_626_entry-0x232218>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_626_entry-0x232198>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_626_entry-0x228f48>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_626_entry-0x228dd8>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_626_entry-0x228858>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_626_entry-0x227db8>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_626_entry-0x227d58>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_626_entry-0x227cf8>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_626_entry-0x226e48>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_626_entry-0x226de8>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_626_entry-0x226a08>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_626_entry-0x2269a8>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_626_entry-0x226948>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_626_entry-0x226308>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_626_entry-0x225ef8>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_626_entry-0x225558>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_626_entry-0x225368>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_626_entry-0x225288>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_626_entry-0x224888>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_626_entry-0x224768>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_626_entry-0x224688>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_626_entry-0x2245f8>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_626_entry-0x223e58>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_626_entry-0x2239e8>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_626_entry-0x223918>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_626_entry-0x2238b8>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266eb0+0x429180>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266eb0+0x42fe10>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266eb0+0x431720>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266eb0+0x43b1a0>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266eb0+0x43b400>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266eb0+0x447790>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266eb0+0x447940>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_626_entry-0xe4b08>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266eb0+0x4580f0>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_626_entry-0xdde78>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266eb0+0x469c50>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266eb0+0x46a250>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266eb0+0x46a3b0>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266eb0+0x46a530>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266eb0+0x46a670>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266eb0+0x46a790>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266eb0+0x46a870>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266eb0+0x4757b0>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266eb0+0x4757e0>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266eb0+0x4757f0>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266eb0+0x479a70>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266eb0+0x47a590>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266eb0+0x47a5a0>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_626_entry-0xdc448>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_626_entry-0xd5418>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266eb0+0x49bac0>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266eb0+0x49beb0>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266eb0+0x49f2c0>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266eb0+0x49f340>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266eb0+0x4a9050>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266eb0+0x4a9100>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266eb0+0x4a9310>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266eb0+0x4a9470>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266eb0+0x4abd00>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266eb0+0x4af4b0>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266eb0+0x4c8ac0>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266eb0+0x4c8ae0>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266eb0+0x4c8b70>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_626_entry-0x1f088>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266eb0+0x4fd940>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266eb0+0x50c860>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266eb0+0x50eaa0>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266eb0+0x532fe0>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266eb0+0x54c340>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266eb0+0x57b4f0>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266eb0+0x581530>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266eb0+0x5815d0>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266eb0+0x9d4300>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266eb0+0x9d5830>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266eb0+0x9d57e0>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266eb0+0x9d5880>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266eb0+0x59b370>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266eb0+0x59b640>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266eb0+0x5a56c0>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266eb0+0x5c4450>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266eb0+0x6ba030>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266eb0+0x6b9ce0>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266eb0+0x5c9960>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266eb0+0x5ca050>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266eb0+0x5ce400>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266eb0+0x5ce410>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266eb0+0x5ce420>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266eb0+0x5ce440>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266eb0+0x5ce590>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266eb0+0x5ce5a0>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266eb0+0x5ce5e0>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266eb0+0x5cec20>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266eb0+0x5e99c0>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266eb0+0x609440>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266eb0+0x609720>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266eb0+0x60bc40>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266eb0+0x60c950>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_626_entry-0x202478>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_626_entry-0x1ffb48>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_626_entry-0x17f928>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_626_entry-0x17f918>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_626_entry-0x17f758>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_626_entry-0x17f648>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_626_entry-0x17df28>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_626_entry-0x17bf18>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_626_entry-0x17b848>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_626_entry-0x17b758>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_626_entry-0x17ae18>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_626_entry-0x17ad28>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_626_entry-0x178eb8>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_626_entry-0x178da8>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266eb0+0x6239f0>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266eb0+0x635f40>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_626_entry-0x177368>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266eb0+0x6643a0>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266eb0+0x6644e0>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266eb0+0x66c0b0>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266eb0+0x66c0e0>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266eb0+0x671380>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266eb0+0x671f30>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266eb0+0x672900>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266eb0+0x672a60>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266eb0+0x673610>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266eb0+0x6736c0>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266eb0+0x673700>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266eb0+0x69ddd0>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266eb0+0x69dfb0>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266eb0+0x6b6550>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266eb0+0x6b65f0>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266eb0+0x81b320>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266eb0+0x8db270>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266eb0+0x6fe080>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266eb0+0x70f0a0>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266eb0+0x70f350>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266eb0+0x725aa0>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266eb0+0x725d80>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266eb0+0x726080>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266eb0+0x726830>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266eb0+0x727720>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266eb0+0x727850>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266eb0+0x72b2c0>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266eb0+0x72b390>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_626_entry-0x170ab8>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266eb0+0x73b470>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266eb0+0x73e870>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266eb0+0x745af0>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266eb0+0x745b70>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_626_entry-0xa7878>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266eb0+0x757e70>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266eb0+0x75f1a0>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266eb0+0x75f220>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266eb0+0x75f3d0>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266eb0+0x75f460>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266eb0+0x75f5e0>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266eb0+0x75f700>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266eb0+0x75f9e0>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266eb0+0x762490>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266eb0+0x7624b0>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266eb0+0x7624c0>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266eb0+0x7624d0>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266eb0+0x773f00>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266eb0+0x7740f0>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266eb0+0x7759b0>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266eb0+0x775d90>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266eb0+0x775fd0>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266eb0+0x776650>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266eb0+0xa43e20>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266eb0+0x776920>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266eb0+0x776ae0>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266eb0+0x776cf0>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266eb0+0x776d50>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266eb0+0x776fa0>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266eb0+0x777000>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266eb0+0x777140>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266eb0+0x7771c0>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266eb0+0x777240>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266eb0+0x779ce0>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266eb0+0x779e20>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266eb0+0x779ec0>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266eb0+0x77a040>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266eb0+0x77a1a0>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266eb0+0x77a5e0>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266eb0+0x79f730>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_626_entry-0x164b78>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266eb0+0x7cc080>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266eb0+0x7cc810>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266eb0+0x7d1de0>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266eb0+0x803c50>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266eb0+0x803d00>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266eb0+0x827d60>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266eb0+0x827f50>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266eb0+0x84a900>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266eb0+0x859900>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266eb0+0x85bc40>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_626_entry-0x14b768>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266eb0+0x87a3f0>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266eb0+0x87c550>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266eb0+0x87c680>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266eb0+0x87f510>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266eb0+0x8a1030>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266eb0+0x8a12e0>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266eb0+0x8a1680>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266eb0+0x8a1960>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266eb0+0x8a27f0>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266eb0+0x8a4640>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_626_entry-0x76dc8>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_626_entry-0x75e58>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_626_entry-0x14a508>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266eb0+0x8d4280>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266eb0+0x8e0b90>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266eb0+0x8e9510>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266eb0+0x8ea060>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266eb0+0x8ea100>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266eb0+0x8ea200>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266eb0+0x8ea2e0>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266eb0+0x8ea3e0>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266eb0+0x8ea420>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266eb0+0x8ea470>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266eb0+0x8ef9f0>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_626_entry-0x1cbdd8>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266eb0+0x903fc0>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266eb0+0x904ce0>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266eb0+0x906ad0>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266eb0+0x906bf0>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266eb0+0x9072d0>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266eb0+0x90a470>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266eb0+0x90a4c0>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266eb0+0x90a510>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266eb0+0x90a560>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266eb0+0x90aab0>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266eb0+0x90ab20>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266eb0+0x90ab90>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266eb0+0x90ac00>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266eb0+0x90b770>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8afc4cf0, handler_body_626; REA Evidence ev_9f857b9f657662d6d694a1f5427375b79bac960e8e0a63526daa2dfc7cb9c5af
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8afc4cf0", "end": "0xffffffff8afc4e6e"}, {"start": "0xffffffff8afc4f28", "end": "0xffffffff8afc4f31"}, {"start": "0xffffffff8afc4fd7", "end": "0xffffffff8afc4ff4"}], "total_bytes": 423, "span_bytes": 773, "non_contiguous": true, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_626:
0xffffffff8afc4cf0: PUSH RBP
0xffffffff8afc4cf1: MOV RBP, RSP
0xffffffff8afc4cf4: PUSH R15
0xffffffff8afc4cf6: PUSH R14
0xffffffff8afc4cf8: PUSH RBX
0xffffffff8afc4cf9: SUB RSP, 0x118
0xffffffff8afc4d00: LEA R14, [-0x71d23cf0]
0xffffffff8afc4d07: MOV RAX, qword ptr [R14]
0xffffffff8afc4d0a: MOV qword ptr [RBP + -0x20], RAX
0xffffffff8afc4d0e: MOV EBX, dword ptr [RSI + 0x10]
0xffffffff8afc4d11: MOV qword ptr [RBP + -0x28], 0x0
0xffffffff8afc4d19: MOV qword ptr [RBP + -0x30], 0x0
0xffffffff8afc4d21: MOV qword ptr [RBP + -0x38], 0x0
0xffffffff8afc4d29: MOV qword ptr [RBP + -0x40], 0x0
0xffffffff8afc4d31: MOV qword ptr [RBP + -0x48], 0x0
0xffffffff8afc4d39: MOV qword ptr [RBP + -0x50], 0x0
0xffffffff8afc4d41: MOV qword ptr [RBP + -0x58], 0x0
0xffffffff8afc4d49: MOV qword ptr [RBP + -0x60], 0x0
0xffffffff8afc4d51: MOV qword ptr [RBP + -0x68], 0x0
0xffffffff8afc4d59: MOV qword ptr [RBP + -0x70], 0x0
0xffffffff8afc4d61: MOV qword ptr [RBP + -0x78], 0x0
0xffffffff8afc4d69: MOV qword ptr [RBP + -0x80], 0x0
0xffffffff8afc4d71: MOV qword ptr [RBP + -0x88], 0x0
0xffffffff8afc4d7c: MOV qword ptr [RBP + -0x90], 0x0
0xffffffff8afc4d87: MOV qword ptr [RBP + -0x98], 0x0
0xffffffff8afc4d92: MOV qword ptr [RBP + -0xa0], 0x0
0xffffffff8afc4d9d: MOV qword ptr [RBP + -0xa8], 0x0
0xffffffff8afc4da8: MOV qword ptr [RBP + -0xb0], 0x0
0xffffffff8afc4db3: MOV qword ptr [RBP + -0xb8], 0x0
0xffffffff8afc4dbe: MOV qword ptr [RBP + -0xc0], 0x0
0xffffffff8afc4dc9: MOV qword ptr [RBP + -0xc8], 0x0
0xffffffff8afc4dd4: MOV qword ptr [RBP + -0xd0], 0x0
0xffffffff8afc4ddf: MOV qword ptr [RBP + -0xd8], 0x0
0xffffffff8afc4dea: MOV qword ptr [RBP + -0xe0], 0x0
0xffffffff8afc4df5: MOV qword ptr [RBP + -0xe8], 0x0
0xffffffff8afc4e00: MOV qword ptr [RBP + -0xf0], 0x0
0xffffffff8afc4e0b: MOV qword ptr [RBP + -0xf8], 0x0
0xffffffff8afc4e16: MOV qword ptr [RBP + -0x100], 0x0
0xffffffff8afc4e21: MOV qword ptr [RBP + -0x108], 0x0
0xffffffff8afc4e2c: MOV qword ptr [RBP + -0x110], 0x0
0xffffffff8afc4e37: MOV qword ptr [RBP + -0x118], 0x0
0xffffffff8afc4e42: MOV qword ptr [RBP + -0x120], 0x0
0xffffffff8afc4e4d: MOV ECX, dword ptr [RSI]
0xffffffff8afc4e4f: DEC ECX
0xffffffff8afc4e51: CMP ECX, 0x5
0xffffffff8afc4e54: JA 0xffffffff8afc4f28
loc_ffffffff8afc4e5a:
0xffffffff8afc4e5a: LEA RDX, [-0x73f1ca44]
0xffffffff8afc4e61: MOV EAX, 0x6
0xffffffff8afc4e66: MOVSXD RCX, dword ptr [RDX + RCX*0x4]
0xffffffff8afc4e6a: ADD RCX, RDX
0xffffffff8afc4e6d: JMP RCX
loc_ffffffff8afc4f28:
0xffffffff8afc4f28: MOV EAX, 0x16
0xffffffff8afc4f2d: JMP 0xffffffff8afc4fd7
loc_ffffffff8afc4fd7:
0xffffffff8afc4fd7: MOV RCX, qword ptr [R14]
0xffffffff8afc4fda: CMP RCX, qword ptr [RBP + -0x20]
0xffffffff8afc4fde: JNZ 0xffffffff8afc4fee
loc_ffffffff8afc4fe0:
0xffffffff8afc4fe0: ADD RSP, 0x118
0xffffffff8afc4fe7: POP RBX
0xffffffff8afc4fe8: POP R14
0xffffffff8afc4fea: POP R15
0xffffffff8afc4fec: POP RBP
0xffffffff8afc4fed: RET
loc_ffffffff8afc4fee:
0xffffffff8afc4fee: CALL 0xffffffff8b0bd6b0
0xffffffff8afc4ff3: UD2
; END FUNCTION handler_body_626

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_01f1bb701f927b4be80f0dba78547bb3c06a5e4e36911048704315f8c4ace2ca
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_626.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8afc4cf0 <handler_626_body>:
ffffffff8afc4cf0:	55                   	push   %rbp
ffffffff8afc4cf1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc4cf4:	41 57                	push   %r15
ffffffff8afc4cf6:	41 56                	push   %r14
ffffffff8afc4cf8:	53                   	push   %rbx
ffffffff8afc4cf9:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
ffffffff8afc4d00:	4c 8d 35 09 76 31 03 	lea    0x3317609(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
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
ffffffff8afc4e54:	0f 87 ce 00 00 00    	ja     ffffffff8afc4f28 <handler_626_body+0x238>
ffffffff8afc4e5a:	48 8d 15 5b e7 11 01 	lea    0x111e75b(%rip),%rdx        # ffffffff8c0e35bc <frame_candidate_606b10+0x111caac>
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
ffffffff8afc4e88:	0f 85 49 01 00 00    	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4e8e:	48 83 7e 18 00       	cmpq   $0x0,0x18(%rsi)
ffffffff8afc4e93:	0f 84 3e 01 00 00    	je     ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4e99:	48 83 7e 20 00       	cmpq   $0x0,0x20(%rsi)
ffffffff8afc4e9e:	0f 85 33 01 00 00    	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4ea4:	49 89 f7             	mov    %rsi,%r15
ffffffff8afc4ea7:	89 de                	mov    %ebx,%esi
ffffffff8afc4ea9:	e8 52 01 00 00       	call   ffffffff8afc5000 <frame_candidate_605000>
ffffffff8afc4eae:	4c 89 fe             	mov    %r15,%rsi
ffffffff8afc4eb1:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc4eb4:	e9 e8 00 00 00       	jmp    ffffffff8afc4fa1 <handler_626_body+0x2b1>
ffffffff8afc4eb9:	0b 5e 08             	or     0x8(%rsi),%ebx
ffffffff8afc4ebc:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4ec1:	0f 85 10 01 00 00    	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4ec7:	48 83 7e 18 00       	cmpq   $0x0,0x18(%rsi)
ffffffff8afc4ecc:	0f 84 05 01 00 00    	je     ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4ed2:	48 83 7e 20 00       	cmpq   $0x0,0x20(%rsi)
ffffffff8afc4ed7:	0f 84 fa 00 00 00    	je     ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4edd:	48 89 f3             	mov    %rsi,%rbx
ffffffff8afc4ee0:	48 8d bd 60 ff ff ff 	lea    -0xa0(%rbp),%rdi
ffffffff8afc4ee7:	48 8d b5 e0 fe ff ff 	lea    -0x120(%rbp),%rsi
ffffffff8afc4eee:	e8 fd aa 37 00       	call   ffffffff8b33f9f0 <frame_candidate_606b10+0x378ee0>
ffffffff8afc4ef3:	85 c0                	test   %eax,%eax
ffffffff8afc4ef5:	0f 85 dc 00 00 00    	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4efb:	48 8b 73 20          	mov    0x20(%rbx),%rsi
ffffffff8afc4eff:	48 8d bd e0 fe ff ff 	lea    -0x120(%rbp),%rdi
ffffffff8afc4f06:	e8 45 ed ff ff       	call   ffffffff8afc3c50 <handler_626_body-0x10a0>
ffffffff8afc4f0b:	85 c0                	test   %eax,%eax
ffffffff8afc4f0d:	0f 85 c4 00 00 00    	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4f13:	48 8b 73 18          	mov    0x18(%rbx),%rsi
ffffffff8afc4f17:	48 8d bd 60 ff ff ff 	lea    -0xa0(%rbp),%rdi
ffffffff8afc4f1e:	e8 2d ed ff ff       	call   ffffffff8afc3c50 <handler_626_body-0x10a0>
ffffffff8afc4f23:	e9 af 00 00 00       	jmp    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4f28:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4f2d:	e9 a5 00 00 00       	jmp    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4f32:	49 89 f7             	mov    %rsi,%r15
ffffffff8afc4f35:	e8 d6 58 0d 00       	call   ffffffff8b09a810 <frame_candidate_606b10+0xd3d00>
ffffffff8afc4f3a:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc4f3f:	72 11                	jb     ffffffff8afc4f52 <handler_626_body+0x262>
ffffffff8afc4f41:	e8 ca 58 0d 00       	call   ffffffff8b09a810 <frame_candidate_606b10+0xd3d00>
ffffffff8afc4f46:	b9 07 00 00 00       	mov    $0x7,%ecx
ffffffff8afc4f4b:	3d e0 0f 84 00       	cmp    $0x840fe0,%eax
ffffffff8afc4f50:	72 05                	jb     ffffffff8afc4f57 <handler_626_body+0x267>
ffffffff8afc4f52:	b9 03 00 00 00       	mov    $0x3,%ecx
ffffffff8afc4f57:	41 83 7f 08 00       	cmpl   $0x0,0x8(%r15)
ffffffff8afc4f5c:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc4f61:	75 74                	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4f63:	49 83 7f 18 00       	cmpq   $0x0,0x18(%r15)
ffffffff8afc4f68:	4c 89 fe             	mov    %r15,%rsi
ffffffff8afc4f6b:	74 6a                	je     ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4f6d:	48 83 7e 20 00       	cmpq   $0x0,0x20(%rsi)
ffffffff8afc4f72:	0f 95 c2             	setne  %dl
ffffffff8afc4f75:	39 cb                	cmp    %ecx,%ebx
ffffffff8afc4f77:	0f 97 c1             	seta   %cl
ffffffff8afc4f7a:	08 d1                	or     %dl,%cl
ffffffff8afc4f7c:	75 59                	jne    ffffffff8afc4fd7 <handler_626_body+0x2e7>
ffffffff8afc4f7e:	8d 0c 1b             	lea    (%rbx,%rbx,1),%ecx
ffffffff8afc4f81:	83 fb 03             	cmp    $0x3,%ebx
ffffffff8afc4f84:	77 0a                	ja     ffffffff8afc4f90 <handler_626_body+0x2a0>
ffffffff8afc4f86:	81 c9 41 02 01 c0    	or     $0xc0010241,%ecx
ffffffff8afc4f8c:	0f 32                	rdmsr
ffffffff8afc4f8e:	eb 08                	jmp    ffffffff8afc4f98 <handler_626_body+0x2a8>
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
ffffffff8afc4fb7:	48 8d 35 d9 a2 d4 00 	lea    0xd4a2d9(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_606b10+0xd48787>
ffffffff8afc4fbe:	e8 1d 54 61 00       	call   ffffffff8b5da3e0 <frame_candidate_606b10+0x6138d0>
ffffffff8afc4fc3:	48 8d bd d8 fe ff ff 	lea    -0x128(%rbp),%rdi
ffffffff8afc4fca:	ba 08 00 00 00       	mov    $0x8,%edx
ffffffff8afc4fcf:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc4fd2:	e8 f9 41 c5 ff       	call   ffffffff8ac191d0 <handler_626_body-0x3abb20>
ffffffff8afc4fd7:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8afc4fda:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8afc4fde:	75 0e                	jne    ffffffff8afc4fee <handler_626_body+0x2fe>
ffffffff8afc4fe0:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
ffffffff8afc4fe7:	5b                   	pop    %rbx
ffffffff8afc4fe8:	41 5e                	pop    %r14
ffffffff8afc4fea:	41 5f                	pop    %r15
ffffffff8afc4fec:	5d                   	pop    %rbp
ffffffff8afc4fed:	c3                   	ret
ffffffff8afc4fee:	e8 bd 86 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
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
ffffffff8afc5013:	48 8d 15 37 65 ca 00 	lea    0xca6537(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_606b10+0xca4a41>
ffffffff8afc501a:	83 ff 01             	cmp    $0x1,%edi
ffffffff8afc501d:	75 2b                	jne    ffffffff8afc504a <frame_candidate_605000+0x4a>
ffffffff8afc501f:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5022:	b9 2c 05 00 00       	mov    $0x52c,%ecx
ffffffff8afc5027:	31 f6                	xor    %esi,%esi
ffffffff8afc5029:	e8 82 28 ec ff       	call   ffffffff8ae878b0 <handler_626_body-0x13d440>
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
ffffffff8afc5054:	e8 57 28 ec ff       	call   ffffffff8ae878b0 <handler_626_body-0x13d440>
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
ffffffff8afc507d:	e8 3e 27 0b 00       	call   ffffffff8b0777c0 <frame_candidate_606b10+0xb0cb0>
ffffffff8afc5082:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc5089:	c0 
ffffffff8afc508a:	0f 32                	rdmsr
ffffffff8afc508c:	eb 14                	jmp    ffffffff8afc50a2 <frame_candidate_605000+0xa2>
ffffffff8afc508e:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5091:	31 f6                	xor    %esi,%esi
ffffffff8afc5093:	e8 28 27 0b 00       	call   ffffffff8b0777c0 <frame_candidate_606b10+0xb0cb0>
ffffffff8afc5098:	43 8d 8c 36 31 02 01 	lea    -0x3ffefdcf(%r14,%r14,1),%ecx
ffffffff8afc509f:	c0 
ffffffff8afc50a0:	0f 32                	rdmsr
ffffffff8afc50a2:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc50a5:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc50a8:	e8 b3 27 0b 00       	call   ffffffff8b077860 <frame_candidate_606b10+0xb0d50>
ffffffff8afc50ad:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc50b0:	31 f6                	xor    %esi,%esi
ffffffff8afc50b2:	31 d2                	xor    %edx,%edx
ffffffff8afc50b4:	31 c9                	xor    %ecx,%ecx
ffffffff8afc50b6:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc50ba:	e8 61 24 ec ff       	call   ffffffff8ae87520 <handler_626_body-0x13d7d0>
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
ffffffff8afc50d4:	48 8d 35 d9 bd ce 00 	lea    0xcebdd9(%rip),%rsi        # ffffffff8bcb0eb4 <frame_candidate_606b10+0xcea3a4>
ffffffff8afc50db:	48 8d 15 1e db c5 ff 	lea    -0x3a24e2(%rip),%rdx        # ffffffff8ac22c00 <handler_626_body-0x3a20f0>
ffffffff8afc50e2:	48 8d 0d 70 6a d9 00 	lea    0xd96a70(%rip),%rcx        # ffffffff8bd5bb59 <frame_candidate_606b10+0xd95049>
ffffffff8afc50e9:	41 b9 02 00 00 00    	mov    $0x2,%r9d
ffffffff8afc50ef:	31 ff                	xor    %edi,%edi
ffffffff8afc50f1:	45 31 c0             	xor    %r8d,%r8d
ffffffff8afc50f4:	e8 47 8c 13 00       	call   ffffffff8b0fdd40 <frame_candidate_606b10+0x137230>
ffffffff8afc50f9:	48 8d 35 65 f3 c8 00 	lea    0xc8f365(%rip),%rsi        # ffffffff8bc54465 <frame_candidate_606b10+0xc8d955>
ffffffff8afc5100:	48 8d 15 01 db c5 ff 	lea    -0x3a24ff(%rip),%rdx        # ffffffff8ac22c08 <handler_626_body-0x3a20e8>
ffffffff8afc5107:	48 8d 0d 36 0c cb 00 	lea    0xcb0c36(%rip),%rcx        # ffffffff8bc75d44 <frame_candidate_606b10+0xcaf234>
ffffffff8afc510e:	31 ff                	xor    %edi,%edi
ffffffff8afc5110:	45 31 c0             	xor    %r8d,%r8d
ffffffff8afc5113:	41 b9 0c 00 00 00    	mov    $0xc,%r9d
ffffffff8afc5119:	5d                   	pop    %rbp
ffffffff8afc511a:	e9 21 8c 13 00       	jmp    ffffffff8b0fdd40 <frame_candidate_606b10+0x137230>
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
ffffffff8afc5138:	48 89 15 b1 c5 0c 03 	mov    %rdx,0x30cc5b1(%rip)        # ffffffff8e0916f0 <frame_candidate_606b10+0x30cabe0>
ffffffff8afc513f:	31 d2                	xor    %edx,%edx
ffffffff8afc5141:	0f 30                	wrmsr
ffffffff8afc5143:	b9 41 02 01 c0       	mov    $0xc0010241,%ecx
ffffffff8afc5148:	0f 32                	rdmsr
ffffffff8afc514a:	89 c0                	mov    %eax,%eax
ffffffff8afc514c:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5150:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc5155:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5158:	48 89 15 d1 c5 0c 03 	mov    %rdx,0x30cc5d1(%rip)        # ffffffff8e091730 <frame_candidate_606b10+0x30cac20>
ffffffff8afc515f:	0f 32                	rdmsr
ffffffff8afc5161:	89 c0                	mov    %eax,%eax
ffffffff8afc5163:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5167:	48 09 c2             	or     %rax,%rdx
ffffffff8afc516a:	31 c0                	xor    %eax,%eax
ffffffff8afc516c:	48 89 15 85 c5 0c 03 	mov    %rdx,0x30cc585(%rip)        # ffffffff8e0916f8 <frame_candidate_606b10+0x30cabe8>
ffffffff8afc5173:	31 d2                	xor    %edx,%edx
ffffffff8afc5175:	0f 30                	wrmsr
ffffffff8afc5177:	b9 43 02 01 c0       	mov    $0xc0010243,%ecx
ffffffff8afc517c:	0f 32                	rdmsr
ffffffff8afc517e:	89 c0                	mov    %eax,%eax
ffffffff8afc5180:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5184:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc5189:	48 09 c2             	or     %rax,%rdx
ffffffff8afc518c:	48 89 15 a5 c5 0c 03 	mov    %rdx,0x30cc5a5(%rip)        # ffffffff8e091738 <frame_candidate_606b10+0x30cac28>
ffffffff8afc5193:	0f 32                	rdmsr
ffffffff8afc5195:	89 c0                	mov    %eax,%eax
ffffffff8afc5197:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc519b:	48 09 c2             	or     %rax,%rdx
ffffffff8afc519e:	31 c0                	xor    %eax,%eax
ffffffff8afc51a0:	48 89 15 59 c5 0c 03 	mov    %rdx,0x30cc559(%rip)        # ffffffff8e091700 <frame_candidate_606b10+0x30cabf0>
ffffffff8afc51a7:	31 d2                	xor    %edx,%edx
ffffffff8afc51a9:	0f 30                	wrmsr
ffffffff8afc51ab:	b9 45 02 01 c0       	mov    $0xc0010245,%ecx
ffffffff8afc51b0:	0f 32                	rdmsr
ffffffff8afc51b2:	89 c0                	mov    %eax,%eax
ffffffff8afc51b4:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc51b8:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc51bd:	48 09 c2             	or     %rax,%rdx
ffffffff8afc51c0:	48 89 15 79 c5 0c 03 	mov    %rdx,0x30cc579(%rip)        # ffffffff8e091740 <frame_candidate_606b10+0x30cac30>
ffffffff8afc51c7:	0f 32                	rdmsr
ffffffff8afc51c9:	89 c0                	mov    %eax,%eax
ffffffff8afc51cb:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc51cf:	48 09 c2             	or     %rax,%rdx
ffffffff8afc51d2:	31 c0                	xor    %eax,%eax
ffffffff8afc51d4:	48 89 15 2d c5 0c 03 	mov    %rdx,0x30cc52d(%rip)        # ffffffff8e091708 <frame_candidate_606b10+0x30cabf8>
ffffffff8afc51db:	31 d2                	xor    %edx,%edx
ffffffff8afc51dd:	0f 30                	wrmsr
ffffffff8afc51df:	b9 47 02 01 c0       	mov    $0xc0010247,%ecx
ffffffff8afc51e4:	0f 32                	rdmsr
ffffffff8afc51e6:	89 c0                	mov    %eax,%eax
ffffffff8afc51e8:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc51ec:	48 09 c2             	or     %rax,%rdx
ffffffff8afc51ef:	48 89 15 52 c5 0c 03 	mov    %rdx,0x30cc552(%rip)        # ffffffff8e091748 <frame_candidate_606b10+0x30cac38>
ffffffff8afc51f6:	e8 15 56 0d 00       	call   ffffffff8b09a810 <frame_candidate_606b10+0xd3d00>
ffffffff8afc51fb:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc5200:	0f 82 e0 00 00 00    	jb     ffffffff8afc52e6 <frame_candidate_605120+0x1c6>
ffffffff8afc5206:	e8 05 56 0d 00       	call   ffffffff8b09a810 <frame_candidate_606b10+0xd3d00>
ffffffff8afc520b:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc5210:	0f 87 d0 00 00 00    	ja     ffffffff8afc52e6 <frame_candidate_605120+0x1c6>
ffffffff8afc5216:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc521b:	0f 32                	rdmsr
ffffffff8afc521d:	89 c0                	mov    %eax,%eax
ffffffff8afc521f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5223:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5226:	31 c0                	xor    %eax,%eax
ffffffff8afc5228:	48 89 15 e1 c4 0c 03 	mov    %rdx,0x30cc4e1(%rip)        # ffffffff8e091710 <frame_candidate_606b10+0x30cac00>
ffffffff8afc522f:	31 d2                	xor    %edx,%edx
ffffffff8afc5231:	0f 30                	wrmsr
ffffffff8afc5233:	b9 91 01 01 c0       	mov    $0xc0010191,%ecx
ffffffff8afc5238:	0f 32                	rdmsr
ffffffff8afc523a:	89 c0                	mov    %eax,%eax
ffffffff8afc523c:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5240:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc5245:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5248:	48 89 15 01 c5 0c 03 	mov    %rdx,0x30cc501(%rip)        # ffffffff8e091750 <frame_candidate_606b10+0x30cac40>
ffffffff8afc524f:	0f 32                	rdmsr
ffffffff8afc5251:	89 c0                	mov    %eax,%eax
ffffffff8afc5253:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5257:	48 09 c2             	or     %rax,%rdx
ffffffff8afc525a:	31 c0                	xor    %eax,%eax
ffffffff8afc525c:	48 89 15 b5 c4 0c 03 	mov    %rdx,0x30cc4b5(%rip)        # ffffffff8e091718 <frame_candidate_606b10+0x30cac08>
ffffffff8afc5263:	31 d2                	xor    %edx,%edx
ffffffff8afc5265:	0f 30                	wrmsr
ffffffff8afc5267:	b9 93 01 01 c0       	mov    $0xc0010193,%ecx
ffffffff8afc526c:	0f 32                	rdmsr
ffffffff8afc526e:	89 c0                	mov    %eax,%eax
ffffffff8afc5270:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5274:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc5279:	48 09 c2             	or     %rax,%rdx
ffffffff8afc527c:	48 89 15 d5 c4 0c 03 	mov    %rdx,0x30cc4d5(%rip)        # ffffffff8e091758 <frame_candidate_606b10+0x30cac48>
ffffffff8afc5283:	0f 32                	rdmsr
ffffffff8afc5285:	89 c0                	mov    %eax,%eax
ffffffff8afc5287:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc528b:	48 09 c2             	or     %rax,%rdx
ffffffff8afc528e:	31 c0                	xor    %eax,%eax
ffffffff8afc5290:	48 89 15 89 c4 0c 03 	mov    %rdx,0x30cc489(%rip)        # ffffffff8e091720 <frame_candidate_606b10+0x30cac10>
ffffffff8afc5297:	31 d2                	xor    %edx,%edx
ffffffff8afc5299:	0f 30                	wrmsr
ffffffff8afc529b:	b9 95 01 01 c0       	mov    $0xc0010195,%ecx
ffffffff8afc52a0:	0f 32                	rdmsr
ffffffff8afc52a2:	89 c0                	mov    %eax,%eax
ffffffff8afc52a4:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc52a8:	b9 96 01 01 c0       	mov    $0xc0010196,%ecx
ffffffff8afc52ad:	48 09 c2             	or     %rax,%rdx
ffffffff8afc52b0:	48 89 15 a9 c4 0c 03 	mov    %rdx,0x30cc4a9(%rip)        # ffffffff8e091760 <frame_candidate_606b10+0x30cac50>
ffffffff8afc52b7:	0f 32                	rdmsr
ffffffff8afc52b9:	89 c0                	mov    %eax,%eax
ffffffff8afc52bb:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc52bf:	48 09 c2             	or     %rax,%rdx
ffffffff8afc52c2:	31 c0                	xor    %eax,%eax
ffffffff8afc52c4:	48 89 15 5d c4 0c 03 	mov    %rdx,0x30cc45d(%rip)        # ffffffff8e091728 <frame_candidate_606b10+0x30cac18>
ffffffff8afc52cb:	31 d2                	xor    %edx,%edx
ffffffff8afc52cd:	0f 30                	wrmsr
ffffffff8afc52cf:	b9 97 01 01 c0       	mov    $0xc0010197,%ecx
ffffffff8afc52d4:	0f 32                	rdmsr
ffffffff8afc52d6:	89 c0                	mov    %eax,%eax
ffffffff8afc52d8:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc52dc:	48 09 c2             	or     %rax,%rdx
ffffffff8afc52df:	48 89 15 82 c4 0c 03 	mov    %rdx,0x30cc482(%rip)        # ffffffff8e091768 <frame_candidate_606b10+0x30cac58>
ffffffff8afc52e6:	65 48 8b 1c 25 00 00 	mov    %gs:0x0,%rbx
ffffffff8afc52ed:	00 00 
ffffffff8afc52ef:	48 8d 15 5b 62 ca 00 	lea    0xca625b(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_606b10+0xca4a41>
ffffffff8afc52f6:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc52f9:	b9 c7 05 00 00       	mov    $0x5c7,%ecx
ffffffff8afc52fe:	31 f6                	xor    %esi,%esi
ffffffff8afc5300:	e8 ab 25 ec ff       	call   ffffffff8ae878b0 <handler_626_body-0x13d440>
ffffffff8afc5305:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5308:	e8 53 25 0b 00       	call   ffffffff8b077860 <frame_candidate_606b10+0xb0d50>
ffffffff8afc530d:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5310:	31 f6                	xor    %esi,%esi
ffffffff8afc5312:	e8 a9 24 0b 00       	call   ffffffff8b0777c0 <frame_candidate_606b10+0xb0cb0>
ffffffff8afc5317:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc531c:	0f 32                	rdmsr
ffffffff8afc531e:	89 c0                	mov    %eax,%eax
ffffffff8afc5320:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5324:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5329:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc532c:	48 09 c2             	or     %rax,%rdx
ffffffff8afc532f:	48 89 15 3a c4 0c 03 	mov    %rdx,0x30cc43a(%rip)        # ffffffff8e091770 <frame_candidate_606b10+0x30cac60>
ffffffff8afc5336:	0f 32                	rdmsr
ffffffff8afc5338:	89 c0                	mov    %eax,%eax
ffffffff8afc533a:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc533e:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc5343:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5346:	48 89 15 2b c4 0c 03 	mov    %rdx,0x30cc42b(%rip)        # ffffffff8e091778 <frame_candidate_606b10+0x30cac68>
ffffffff8afc534d:	0f 32                	rdmsr
ffffffff8afc534f:	89 c0                	mov    %eax,%eax
ffffffff8afc5351:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5355:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc535a:	48 09 c2             	or     %rax,%rdx
ffffffff8afc535d:	48 89 15 1c c4 0c 03 	mov    %rdx,0x30cc41c(%rip)        # ffffffff8e091780 <frame_candidate_606b10+0x30cac70>
ffffffff8afc5364:	0f 32                	rdmsr
ffffffff8afc5366:	89 c0                	mov    %eax,%eax
ffffffff8afc5368:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc536c:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc5371:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5374:	48 89 15 0d c4 0c 03 	mov    %rdx,0x30cc40d(%rip)        # ffffffff8e091788 <frame_candidate_606b10+0x30cac78>
ffffffff8afc537b:	0f 32                	rdmsr
ffffffff8afc537d:	89 c0                	mov    %eax,%eax
ffffffff8afc537f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5383:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc5388:	48 09 c2             	or     %rax,%rdx
ffffffff8afc538b:	48 89 15 fe c3 0c 03 	mov    %rdx,0x30cc3fe(%rip)        # ffffffff8e091790 <frame_candidate_606b10+0x30cac80>
ffffffff8afc5392:	0f 32                	rdmsr
ffffffff8afc5394:	89 c0                	mov    %eax,%eax
ffffffff8afc5396:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc539a:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc539f:	48 09 c2             	or     %rax,%rdx
ffffffff8afc53a2:	31 c0                	xor    %eax,%eax
ffffffff8afc53a4:	48 89 15 ed c3 0c 03 	mov    %rdx,0x30cc3ed(%rip)        # ffffffff8e091798 <frame_candidate_606b10+0x30cac88>
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
ffffffff8afc53fb:	48 89 15 ce c3 0c 03 	mov    %rdx,0x30cc3ce(%rip)        # ffffffff8e0917d0 <frame_candidate_606b10+0x30cacc0>
ffffffff8afc5402:	0f 32                	rdmsr
ffffffff8afc5404:	89 c0                	mov    %eax,%eax
ffffffff8afc5406:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc540a:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc540f:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5412:	48 89 15 bf c3 0c 03 	mov    %rdx,0x30cc3bf(%rip)        # ffffffff8e0917d8 <frame_candidate_606b10+0x30cacc8>
ffffffff8afc5419:	0f 32                	rdmsr
ffffffff8afc541b:	89 c0                	mov    %eax,%eax
ffffffff8afc541d:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5421:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc5426:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5429:	48 89 15 b0 c3 0c 03 	mov    %rdx,0x30cc3b0(%rip)        # ffffffff8e0917e0 <frame_candidate_606b10+0x30cacd0>
ffffffff8afc5430:	0f 32                	rdmsr
ffffffff8afc5432:	89 c0                	mov    %eax,%eax
ffffffff8afc5434:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5438:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc543d:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5440:	48 89 15 a1 c3 0c 03 	mov    %rdx,0x30cc3a1(%rip)        # ffffffff8e0917e8 <frame_candidate_606b10+0x30cacd8>
ffffffff8afc5447:	0f 32                	rdmsr
ffffffff8afc5449:	89 c0                	mov    %eax,%eax
ffffffff8afc544b:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc544f:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc5454:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5457:	48 89 15 92 c3 0c 03 	mov    %rdx,0x30cc392(%rip)        # ffffffff8e0917f0 <frame_candidate_606b10+0x30cace0>
ffffffff8afc545e:	0f 32                	rdmsr
ffffffff8afc5460:	89 c0                	mov    %eax,%eax
ffffffff8afc5462:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5466:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5469:	48 89 15 88 c3 0c 03 	mov    %rdx,0x30cc388(%rip)        # ffffffff8e0917f8 <frame_candidate_606b10+0x30cace8>
ffffffff8afc5470:	e8 eb 23 0b 00       	call   ffffffff8b077860 <frame_candidate_606b10+0xb0d50>
ffffffff8afc5475:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5478:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc547d:	e8 3e 23 0b 00       	call   ffffffff8b0777c0 <frame_candidate_606b10+0xb0cb0>
ffffffff8afc5482:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc5487:	0f 32                	rdmsr
ffffffff8afc5489:	89 c0                	mov    %eax,%eax
ffffffff8afc548b:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc548f:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5494:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5497:	48 09 c2             	or     %rax,%rdx
ffffffff8afc549a:	48 89 15 ff c2 0c 03 	mov    %rdx,0x30cc2ff(%rip)        # ffffffff8e0917a0 <frame_candidate_606b10+0x30cac90>
ffffffff8afc54a1:	0f 32                	rdmsr
ffffffff8afc54a3:	89 c0                	mov    %eax,%eax
ffffffff8afc54a5:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54a9:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc54ae:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54b1:	48 89 15 f0 c2 0c 03 	mov    %rdx,0x30cc2f0(%rip)        # ffffffff8e0917a8 <frame_candidate_606b10+0x30cac98>
ffffffff8afc54b8:	0f 32                	rdmsr
ffffffff8afc54ba:	89 c0                	mov    %eax,%eax
ffffffff8afc54bc:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54c0:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc54c5:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54c8:	48 89 15 e1 c2 0c 03 	mov    %rdx,0x30cc2e1(%rip)        # ffffffff8e0917b0 <frame_candidate_606b10+0x30caca0>
ffffffff8afc54cf:	0f 32                	rdmsr
ffffffff8afc54d1:	89 c0                	mov    %eax,%eax
ffffffff8afc54d3:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54d7:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc54dc:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54df:	48 89 15 d2 c2 0c 03 	mov    %rdx,0x30cc2d2(%rip)        # ffffffff8e0917b8 <frame_candidate_606b10+0x30caca8>
ffffffff8afc54e6:	0f 32                	rdmsr
ffffffff8afc54e8:	89 c0                	mov    %eax,%eax
ffffffff8afc54ea:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc54ee:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc54f3:	48 09 c2             	or     %rax,%rdx
ffffffff8afc54f6:	48 89 15 c3 c2 0c 03 	mov    %rdx,0x30cc2c3(%rip)        # ffffffff8e0917c0 <frame_candidate_606b10+0x30cacb0>
ffffffff8afc54fd:	0f 32                	rdmsr
ffffffff8afc54ff:	89 c0                	mov    %eax,%eax
ffffffff8afc5501:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5505:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc550a:	48 09 c2             	or     %rax,%rdx
ffffffff8afc550d:	31 c0                	xor    %eax,%eax
ffffffff8afc550f:	48 89 15 b2 c2 0c 03 	mov    %rdx,0x30cc2b2(%rip)        # ffffffff8e0917c8 <frame_candidate_606b10+0x30cacb8>
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
ffffffff8afc5566:	48 89 15 93 c2 0c 03 	mov    %rdx,0x30cc293(%rip)        # ffffffff8e091800 <frame_candidate_606b10+0x30cacf0>
ffffffff8afc556d:	0f 32                	rdmsr
ffffffff8afc556f:	89 c0                	mov    %eax,%eax
ffffffff8afc5571:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc5575:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc557a:	48 09 c2             	or     %rax,%rdx
ffffffff8afc557d:	48 89 15 84 c2 0c 03 	mov    %rdx,0x30cc284(%rip)        # ffffffff8e091808 <frame_candidate_606b10+0x30cacf8>
ffffffff8afc5584:	0f 32                	rdmsr
ffffffff8afc5586:	89 c0                	mov    %eax,%eax
ffffffff8afc5588:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc558c:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc5591:	48 09 c2             	or     %rax,%rdx
ffffffff8afc5594:	48 89 15 75 c2 0c 03 	mov    %rdx,0x30cc275(%rip)        # ffffffff8e091810 <frame_candidate_606b10+0x30cad00>
ffffffff8afc559b:	0f 32                	rdmsr
ffffffff8afc559d:	89 c0                	mov    %eax,%eax
ffffffff8afc559f:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc55a3:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc55a8:	48 09 c2             	or     %rax,%rdx
ffffffff8afc55ab:	48 89 15 66 c2 0c 03 	mov    %rdx,0x30cc266(%rip)        # ffffffff8e091818 <frame_candidate_606b10+0x30cad08>
ffffffff8afc55b2:	0f 32                	rdmsr
ffffffff8afc55b4:	89 c0                	mov    %eax,%eax
ffffffff8afc55b6:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc55ba:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc55bf:	48 09 c2             	or     %rax,%rdx
ffffffff8afc55c2:	48 89 15 57 c2 0c 03 	mov    %rdx,0x30cc257(%rip)        # ffffffff8e091820 <frame_candidate_606b10+0x30cad10>
ffffffff8afc55c9:	0f 32                	rdmsr
ffffffff8afc55cb:	89 c0                	mov    %eax,%eax
ffffffff8afc55cd:	48 c1 e2 20          	shl    $0x20,%rdx
ffffffff8afc55d1:	48 09 c2             	or     %rax,%rdx
ffffffff8afc55d4:	48 89 15 4d c2 0c 03 	mov    %rdx,0x30cc24d(%rip)        # ffffffff8e091828 <frame_candidate_606b10+0x30cad18>
ffffffff8afc55db:	e8 80 22 0b 00       	call   ffffffff8b077860 <frame_candidate_606b10+0xb0d50>
ffffffff8afc55e0:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc55e3:	31 f6                	xor    %esi,%esi
ffffffff8afc55e5:	31 d2                	xor    %edx,%edx
ffffffff8afc55e7:	31 c9                	xor    %ecx,%ecx
ffffffff8afc55e9:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc55ed:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8afc55f1:	5b                   	pop    %rbx
ffffffff8afc55f2:	5d                   	pop    %rbp
ffffffff8afc55f3:	e9 28 1f ec ff       	jmp    ffffffff8ae87520 <handler_626_body-0x13d7d0>
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
ffffffff8afc560f:	48 8d 15 3b 5f ca 00 	lea    0xca5f3b(%rip),%rdx        # ffffffff8bc6b551 <frame_candidate_606b10+0xca4a41>
ffffffff8afc5616:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5619:	b9 fc 05 00 00       	mov    $0x5fc,%ecx
ffffffff8afc561e:	31 f6                	xor    %esi,%esi
ffffffff8afc5620:	e8 8b 22 ec ff       	call   ffffffff8ae878b0 <handler_626_body-0x13d440>
ffffffff8afc5625:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5628:	31 f6                	xor    %esi,%esi
ffffffff8afc562a:	e8 91 21 0b 00       	call   ffffffff8b0777c0 <frame_candidate_606b10+0xb0cb0>
ffffffff8afc562f:	48 8b 05 3a c1 0c 03 	mov    0x30cc13a(%rip),%rax        # ffffffff8e091770 <frame_candidate_606b10+0x30cac60>
ffffffff8afc5636:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc563b:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc563e:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5641:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5645:	0f 30                	wrmsr
ffffffff8afc5647:	48 8b 05 2a c1 0c 03 	mov    0x30cc12a(%rip),%rax        # ffffffff8e091778 <frame_candidate_606b10+0x30cac68>
ffffffff8afc564e:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5653:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5656:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc565a:	0f 30                	wrmsr
ffffffff8afc565c:	48 8b 05 1d c1 0c 03 	mov    0x30cc11d(%rip),%rax        # ffffffff8e091780 <frame_candidate_606b10+0x30cac70>
ffffffff8afc5663:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc5668:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc566b:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc566f:	0f 30                	wrmsr
ffffffff8afc5671:	48 8b 05 10 c1 0c 03 	mov    0x30cc110(%rip),%rax        # ffffffff8e091788 <frame_candidate_606b10+0x30cac78>
ffffffff8afc5678:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc567d:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5680:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5684:	0f 30                	wrmsr
ffffffff8afc5686:	48 8b 05 03 c1 0c 03 	mov    0x30cc103(%rip),%rax        # ffffffff8e091790 <frame_candidate_606b10+0x30cac80>
ffffffff8afc568d:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc5692:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5695:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5699:	0f 30                	wrmsr
ffffffff8afc569b:	48 8b 05 f6 c0 0c 03 	mov    0x30cc0f6(%rip),%rax        # ffffffff8e091798 <frame_candidate_606b10+0x30cac88>
ffffffff8afc56a2:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc56a7:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56aa:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56ae:	0f 30                	wrmsr
ffffffff8afc56b0:	48 8b 05 19 c1 0c 03 	mov    0x30cc119(%rip),%rax        # ffffffff8e0917d0 <frame_candidate_606b10+0x30cacc0>
ffffffff8afc56b7:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc56bc:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56bf:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56c3:	0f 30                	wrmsr
ffffffff8afc56c5:	48 8b 05 0c c1 0c 03 	mov    0x30cc10c(%rip),%rax        # ffffffff8e0917d8 <frame_candidate_606b10+0x30cacc8>
ffffffff8afc56cc:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc56d1:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56d4:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56d8:	0f 30                	wrmsr
ffffffff8afc56da:	48 8b 05 ff c0 0c 03 	mov    0x30cc0ff(%rip),%rax        # ffffffff8e0917e0 <frame_candidate_606b10+0x30cacd0>
ffffffff8afc56e1:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc56e6:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56e9:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc56ed:	0f 30                	wrmsr
ffffffff8afc56ef:	48 8b 05 f2 c0 0c 03 	mov    0x30cc0f2(%rip),%rax        # ffffffff8e0917e8 <frame_candidate_606b10+0x30cacd8>
ffffffff8afc56f6:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc56fb:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc56fe:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5702:	0f 30                	wrmsr
ffffffff8afc5704:	48 8b 05 e5 c0 0c 03 	mov    0x30cc0e5(%rip),%rax        # ffffffff8e0917f0 <frame_candidate_606b10+0x30cace0>
ffffffff8afc570b:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc5710:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5713:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5717:	0f 30                	wrmsr
ffffffff8afc5719:	48 8b 05 d8 c0 0c 03 	mov    0x30cc0d8(%rip),%rax        # ffffffff8e0917f8 <frame_candidate_606b10+0x30cace8>
ffffffff8afc5720:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc5725:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5728:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc572c:	0f 30                	wrmsr
ffffffff8afc572e:	e8 2d 21 0b 00       	call   ffffffff8b077860 <frame_candidate_606b10+0xb0d50>
ffffffff8afc5733:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5736:	be 08 00 00 00       	mov    $0x8,%esi
ffffffff8afc573b:	e8 80 20 0b 00       	call   ffffffff8b0777c0 <frame_candidate_606b10+0xb0cb0>
ffffffff8afc5740:	48 8b 05 59 c0 0c 03 	mov    0x30cc059(%rip),%rax        # ffffffff8e0917a0 <frame_candidate_606b10+0x30cac90>
ffffffff8afc5747:	b9 30 02 01 c0       	mov    $0xc0010230,%ecx
ffffffff8afc574c:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc574f:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5752:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5756:	0f 30                	wrmsr
ffffffff8afc5758:	48 8b 05 49 c0 0c 03 	mov    0x30cc049(%rip),%rax        # ffffffff8e0917a8 <frame_candidate_606b10+0x30cac98>
ffffffff8afc575f:	b9 32 02 01 c0       	mov    $0xc0010232,%ecx
ffffffff8afc5764:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5767:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc576b:	0f 30                	wrmsr
ffffffff8afc576d:	48 8b 05 3c c0 0c 03 	mov    0x30cc03c(%rip),%rax        # ffffffff8e0917b0 <frame_candidate_606b10+0x30caca0>
ffffffff8afc5774:	b9 34 02 01 c0       	mov    $0xc0010234,%ecx
ffffffff8afc5779:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc577c:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5780:	0f 30                	wrmsr
ffffffff8afc5782:	48 8b 05 2f c0 0c 03 	mov    0x30cc02f(%rip),%rax        # ffffffff8e0917b8 <frame_candidate_606b10+0x30caca8>
ffffffff8afc5789:	b9 36 02 01 c0       	mov    $0xc0010236,%ecx
ffffffff8afc578e:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5791:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5795:	0f 30                	wrmsr
ffffffff8afc5797:	48 8b 05 22 c0 0c 03 	mov    0x30cc022(%rip),%rax        # ffffffff8e0917c0 <frame_candidate_606b10+0x30cacb0>
ffffffff8afc579e:	b9 38 02 01 c0       	mov    $0xc0010238,%ecx
ffffffff8afc57a3:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57a6:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57aa:	0f 30                	wrmsr
ffffffff8afc57ac:	48 8b 05 15 c0 0c 03 	mov    0x30cc015(%rip),%rax        # ffffffff8e0917c8 <frame_candidate_606b10+0x30cacb8>
ffffffff8afc57b3:	b9 3a 02 01 c0       	mov    $0xc001023a,%ecx
ffffffff8afc57b8:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57bb:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57bf:	0f 30                	wrmsr
ffffffff8afc57c1:	48 8b 05 38 c0 0c 03 	mov    0x30cc038(%rip),%rax        # ffffffff8e091800 <frame_candidate_606b10+0x30cacf0>
ffffffff8afc57c8:	b9 31 02 01 c0       	mov    $0xc0010231,%ecx
ffffffff8afc57cd:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57d0:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57d4:	0f 30                	wrmsr
ffffffff8afc57d6:	48 8b 05 2b c0 0c 03 	mov    0x30cc02b(%rip),%rax        # ffffffff8e091808 <frame_candidate_606b10+0x30cacf8>
ffffffff8afc57dd:	b9 33 02 01 c0       	mov    $0xc0010233,%ecx
ffffffff8afc57e2:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57e5:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57e9:	0f 30                	wrmsr
ffffffff8afc57eb:	48 8b 05 1e c0 0c 03 	mov    0x30cc01e(%rip),%rax        # ffffffff8e091810 <frame_candidate_606b10+0x30cad00>
ffffffff8afc57f2:	b9 35 02 01 c0       	mov    $0xc0010235,%ecx
ffffffff8afc57f7:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc57fa:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc57fe:	0f 30                	wrmsr
ffffffff8afc5800:	48 8b 05 11 c0 0c 03 	mov    0x30cc011(%rip),%rax        # ffffffff8e091818 <frame_candidate_606b10+0x30cad08>
ffffffff8afc5807:	b9 37 02 01 c0       	mov    $0xc0010237,%ecx
ffffffff8afc580c:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc580f:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5813:	0f 30                	wrmsr
ffffffff8afc5815:	48 8b 05 04 c0 0c 03 	mov    0x30cc004(%rip),%rax        # ffffffff8e091820 <frame_candidate_606b10+0x30cad10>
ffffffff8afc581c:	b9 39 02 01 c0       	mov    $0xc0010239,%ecx
ffffffff8afc5821:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5824:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5828:	0f 30                	wrmsr
ffffffff8afc582a:	48 8b 05 f7 bf 0c 03 	mov    0x30cbff7(%rip),%rax        # ffffffff8e091828 <frame_candidate_606b10+0x30cad18>
ffffffff8afc5831:	b9 3b 02 01 c0       	mov    $0xc001023b,%ecx
ffffffff8afc5836:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5839:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc583d:	0f 30                	wrmsr
ffffffff8afc583f:	e8 1c 20 0b 00       	call   ffffffff8b077860 <frame_candidate_606b10+0xb0d50>
ffffffff8afc5844:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8afc5847:	31 f6                	xor    %esi,%esi
ffffffff8afc5849:	31 d2                	xor    %edx,%edx
ffffffff8afc584b:	31 c9                	xor    %ecx,%ecx
ffffffff8afc584d:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8afc5851:	e8 ca 1c ec ff       	call   ffffffff8ae87520 <handler_626_body-0x13d7d0>
ffffffff8afc5856:	48 8b 05 d3 be 0c 03 	mov    0x30cbed3(%rip),%rax        # ffffffff8e091730 <frame_candidate_606b10+0x30cac20>
ffffffff8afc585d:	b9 41 02 01 c0       	mov    $0xc0010241,%ecx
ffffffff8afc5862:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5865:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5869:	0f 30                	wrmsr
ffffffff8afc586b:	48 8b 05 7e be 0c 03 	mov    0x30cbe7e(%rip),%rax        # ffffffff8e0916f0 <frame_candidate_606b10+0x30cabe0>
ffffffff8afc5872:	b9 40 02 01 c0       	mov    $0xc0010240,%ecx
ffffffff8afc5877:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc587a:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc587e:	0f 30                	wrmsr
ffffffff8afc5880:	48 8b 05 b1 be 0c 03 	mov    0x30cbeb1(%rip),%rax        # ffffffff8e091738 <frame_candidate_606b10+0x30cac28>
ffffffff8afc5887:	b9 43 02 01 c0       	mov    $0xc0010243,%ecx
ffffffff8afc588c:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc588f:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5893:	0f 30                	wrmsr
ffffffff8afc5895:	48 8b 05 5c be 0c 03 	mov    0x30cbe5c(%rip),%rax        # ffffffff8e0916f8 <frame_candidate_606b10+0x30cabe8>
ffffffff8afc589c:	b9 42 02 01 c0       	mov    $0xc0010242,%ecx
ffffffff8afc58a1:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58a4:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58a8:	0f 30                	wrmsr
ffffffff8afc58aa:	48 8b 05 8f be 0c 03 	mov    0x30cbe8f(%rip),%rax        # ffffffff8e091740 <frame_candidate_606b10+0x30cac30>
ffffffff8afc58b1:	b9 45 02 01 c0       	mov    $0xc0010245,%ecx
ffffffff8afc58b6:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58b9:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58bd:	0f 30                	wrmsr
ffffffff8afc58bf:	48 8b 05 3a be 0c 03 	mov    0x30cbe3a(%rip),%rax        # ffffffff8e091700 <frame_candidate_606b10+0x30cabf0>
ffffffff8afc58c6:	b9 44 02 01 c0       	mov    $0xc0010244,%ecx
ffffffff8afc58cb:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58ce:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58d2:	0f 30                	wrmsr
ffffffff8afc58d4:	48 8b 05 6d be 0c 03 	mov    0x30cbe6d(%rip),%rax        # ffffffff8e091748 <frame_candidate_606b10+0x30cac38>
ffffffff8afc58db:	b9 47 02 01 c0       	mov    $0xc0010247,%ecx
ffffffff8afc58e0:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58e3:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58e7:	0f 30                	wrmsr
ffffffff8afc58e9:	48 8b 05 18 be 0c 03 	mov    0x30cbe18(%rip),%rax        # ffffffff8e091708 <frame_candidate_606b10+0x30cabf8>
ffffffff8afc58f0:	b9 46 02 01 c0       	mov    $0xc0010246,%ecx
ffffffff8afc58f5:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc58f8:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc58fc:	0f 30                	wrmsr
ffffffff8afc58fe:	e8 0d 4f 0d 00       	call   ffffffff8b09a810 <frame_candidate_606b10+0xd3d00>
ffffffff8afc5903:	3d c0 0f 84 00       	cmp    $0x840fc0,%eax
ffffffff8afc5908:	0f 82 b8 00 00 00    	jb     ffffffff8afc59c6 <frame_candidate_605600+0x3c6>
ffffffff8afc590e:	e8 fd 4e 0d 00       	call   ffffffff8b09a810 <frame_candidate_606b10+0xd3d00>
ffffffff8afc5913:	3d df 0f 84 00       	cmp    $0x840fdf,%eax
ffffffff8afc5918:	0f 87 a8 00 00 00    	ja     ffffffff8afc59c6 <frame_candidate_605600+0x3c6>
ffffffff8afc591e:	48 8b 05 2b be 0c 03 	mov    0x30cbe2b(%rip),%rax        # ffffffff8e091750 <frame_candidate_606b10+0x30cac40>
ffffffff8afc5925:	b9 91 01 01 c0       	mov    $0xc0010191,%ecx
ffffffff8afc592a:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc592d:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5931:	0f 30                	wrmsr
ffffffff8afc5933:	48 8b 05 d6 bd 0c 03 	mov    0x30cbdd6(%rip),%rax        # ffffffff8e091710 <frame_candidate_606b10+0x30cac00>
ffffffff8afc593a:	b9 90 01 01 c0       	mov    $0xc0010190,%ecx
ffffffff8afc593f:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5942:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5946:	0f 30                	wrmsr
ffffffff8afc5948:	48 8b 05 09 be 0c 03 	mov    0x30cbe09(%rip),%rax        # ffffffff8e091758 <frame_candidate_606b10+0x30cac48>
ffffffff8afc594f:	b9 93 01 01 c0       	mov    $0xc0010193,%ecx
ffffffff8afc5954:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5957:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc595b:	0f 30                	wrmsr
ffffffff8afc595d:	48 8b 05 b4 bd 0c 03 	mov    0x30cbdb4(%rip),%rax        # ffffffff8e091718 <frame_candidate_606b10+0x30cac08>
ffffffff8afc5964:	b9 92 01 01 c0       	mov    $0xc0010192,%ecx
ffffffff8afc5969:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc596c:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5970:	0f 30                	wrmsr
ffffffff8afc5972:	48 8b 05 e7 bd 0c 03 	mov    0x30cbde7(%rip),%rax        # ffffffff8e091760 <frame_candidate_606b10+0x30cac50>
ffffffff8afc5979:	b9 95 01 01 c0       	mov    $0xc0010195,%ecx
ffffffff8afc597e:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5981:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc5985:	0f 30                	wrmsr
ffffffff8afc5987:	48 8b 05 92 bd 0c 03 	mov    0x30cbd92(%rip),%rax        # ffffffff8e091720 <frame_candidate_606b10+0x30cac10>
ffffffff8afc598e:	b9 94 01 01 c0       	mov    $0xc0010194,%ecx
ffffffff8afc5993:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc5996:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc599a:	0f 30                	wrmsr
ffffffff8afc599c:	48 8b 05 c5 bd 0c 03 	mov    0x30cbdc5(%rip),%rax        # ffffffff8e091768 <frame_candidate_606b10+0x30cac58>
ffffffff8afc59a3:	b9 97 01 01 c0       	mov    $0xc0010197,%ecx
ffffffff8afc59a8:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc59ab:	48 c1 ea 20          	shr    $0x20,%rdx
ffffffff8afc59af:	0f 30                	wrmsr
ffffffff8afc59b1:	48 8b 05 70 bd 0c 03 	mov    0x30cbd70(%rip),%rax        # ffffffff8e091728 <frame_candidate_606b10+0x30cac18>
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
ffffffff8afc59d6:	48 8d 3d 6b be 0c 03 	lea    0x30cbe6b(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc59dd:	48 8d 35 b1 31 d2 00 	lea    0xd231b1(%rip),%rsi        # ffffffff8bce8b95 <frame_candidate_606b10+0xd22085>
ffffffff8afc59e4:	b9 04 00 00 00       	mov    $0x4,%ecx
ffffffff8afc59e9:	31 d2                	xor    %edx,%edx
ffffffff8afc59eb:	e8 e0 23 ec ff       	call   ffffffff8ae87dd0 <handler_626_body-0x13cf20>
ffffffff8afc59f0:	48 8d 1d 39 be 0c 03 	lea    0x30cbe39(%rip),%rbx        # ffffffff8e091830 <frame_candidate_606b10+0x30cad20>
ffffffff8afc59f7:	48 8d 3d f2 be 0c 03 	lea    0x30cbef2(%rip),%rdi        # ffffffff8e0918f0 <frame_candidate_606b10+0x30cade0>
ffffffff8afc59fe:	48 c7 05 47 be 0c 03 	movq   $0x0,0x30cbe47(%rip)        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc5a05:	00 00 00 00 
ffffffff8afc5a09:	48 c7 05 5c be 0c 03 	movq   $0x0,0x30cbe5c(%rip)        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5a10:	00 00 00 00 
ffffffff8afc5a14:	48 c7 05 71 be 0c 03 	movq   $0x0,0x30cbe71(%rip)        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5a1b:	00 00 00 00 
ffffffff8afc5a1f:	48 c7 05 86 be 0c 03 	movq   $0x0,0x30cbe86(%rip)        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5a26:	00 00 00 00 
ffffffff8afc5a2a:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a2d:	e8 8e e8 d0 ff       	call   ffffffff8acd42c0 <handler_626_body-0x2f0a30>
ffffffff8afc5a32:	48 8d 3d 07 bf 0c 03 	lea    0x30cbf07(%rip),%rdi        # ffffffff8e091940 <frame_candidate_606b10+0x30cae30>
ffffffff8afc5a39:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a3c:	e8 7f e8 d0 ff       	call   ffffffff8acd42c0 <handler_626_body-0x2f0a30>
ffffffff8afc5a41:	48 8d 3d 48 bf 0c 03 	lea    0x30cbf48(%rip),%rdi        # ffffffff8e091990 <frame_candidate_606b10+0x30cae80>
ffffffff8afc5a48:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a4b:	e8 70 e8 d0 ff       	call   ffffffff8acd42c0 <handler_626_body-0x2f0a30>
ffffffff8afc5a50:	48 8d 3d 89 bf 0c 03 	lea    0x30cbf89(%rip),%rdi        # ffffffff8e0919e0 <frame_candidate_606b10+0x30caed0>
ffffffff8afc5a57:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc5a5a:	e8 61 e8 d0 ff       	call   ffffffff8acd42c0 <handler_626_body-0x2f0a30>
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
ffffffff8afc5a7a:	48 8d 3d c7 bd 0c 03 	lea    0x30cbdc7(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5a81:	31 db                	xor    %ebx,%ebx
ffffffff8afc5a83:	31 f6                	xor    %esi,%esi
ffffffff8afc5a85:	31 d2                	xor    %edx,%edx
ffffffff8afc5a87:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5a89:	e8 72 0f ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc5a8e:	0f b6 05 3b be 0c 03 	movzbl 0x30cbe3b(%rip),%eax        # ffffffff8e0918d0 <frame_candidate_606b10+0x30cadc0>
ffffffff8afc5a95:	45 85 f6             	test   %r14d,%r14d
ffffffff8afc5a98:	0f 95 c1             	setne  %cl
ffffffff8afc5a9b:	84 c0                	test   %al,%al
ffffffff8afc5a9d:	0f 94 c2             	sete   %dl
ffffffff8afc5aa0:	20 ca                	and    %cl,%dl
ffffffff8afc5aa2:	80 fa 01             	cmp    $0x1,%dl
ffffffff8afc5aa5:	0f 85 91 00 00 00    	jne    ffffffff8afc5b3c <frame_candidate_605a70+0xcc>
ffffffff8afc5aab:	48 83 3d 15 be 0c 03 	cmpq   $0x0,0x30cbe15(%rip)        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc5ab2:	00 
ffffffff8afc5ab3:	75 1a                	jne    ffffffff8afc5acf <frame_candidate_605a70+0x5f>
ffffffff8afc5ab5:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5aba:	e8 71 b1 38 00       	call   ffffffff8b350c30 <frame_candidate_606b10+0x38a120>
ffffffff8afc5abf:	48 89 05 02 be 0c 03 	mov    %rax,0x30cbe02(%rip)        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc5ac6:	48 85 c0             	test   %rax,%rax
ffffffff8afc5ac9:	0f 84 a7 00 00 00    	je     ffffffff8afc5b76 <frame_candidate_605a70+0x106>
ffffffff8afc5acf:	48 83 3d 99 bd 0c 03 	cmpq   $0x0,0x30cbd99(%rip)        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5ad6:	00 
ffffffff8afc5ad7:	75 1a                	jne    ffffffff8afc5af3 <frame_candidate_605a70+0x83>
ffffffff8afc5ad9:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5ade:	e8 4d b1 38 00       	call   ffffffff8b350c30 <frame_candidate_606b10+0x38a120>
ffffffff8afc5ae3:	48 89 05 86 bd 0c 03 	mov    %rax,0x30cbd86(%rip)        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5aea:	48 85 c0             	test   %rax,%rax
ffffffff8afc5aed:	0f 84 93 00 00 00    	je     ffffffff8afc5b86 <frame_candidate_605a70+0x116>
ffffffff8afc5af3:	48 83 3d 95 bd 0c 03 	cmpq   $0x0,0x30cbd95(%rip)        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5afa:	00 
ffffffff8afc5afb:	75 16                	jne    ffffffff8afc5b13 <frame_candidate_605a70+0xa3>
ffffffff8afc5afd:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5b02:	e8 29 b1 38 00       	call   ffffffff8b350c30 <frame_candidate_606b10+0x38a120>
ffffffff8afc5b07:	48 89 05 82 bd 0c 03 	mov    %rax,0x30cbd82(%rip)        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5b0e:	48 85 c0             	test   %rax,%rax
ffffffff8afc5b11:	74 77                	je     ffffffff8afc5b8a <frame_candidate_605a70+0x11a>
ffffffff8afc5b13:	48 83 3d 95 bd 0c 03 	cmpq   $0x0,0x30cbd95(%rip)        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5b1a:	00 
ffffffff8afc5b1b:	75 16                	jne    ffffffff8afc5b33 <frame_candidate_605a70+0xc3>
ffffffff8afc5b1d:	bf 00 c0 0c 00       	mov    $0xcc000,%edi
ffffffff8afc5b22:	e8 09 b1 38 00       	call   ffffffff8b350c30 <frame_candidate_606b10+0x38a120>
ffffffff8afc5b27:	48 89 05 82 bd 0c 03 	mov    %rax,0x30cbd82(%rip)        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5b2e:	48 85 c0             	test   %rax,%rax
ffffffff8afc5b31:	74 5e                	je     ffffffff8afc5b91 <frame_candidate_605a70+0x121>
ffffffff8afc5b33:	b0 01                	mov    $0x1,%al
ffffffff8afc5b35:	c6 05 94 bd 0c 03 01 	movb   $0x1,0x30cbd94(%rip)        # ffffffff8e0918d0 <frame_candidate_606b10+0x30cadc0>
ffffffff8afc5b3c:	4c 8b 35 0d bd 0c 03 	mov    0x30cbd0d(%rip),%r14        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
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
ffffffff8afc5b67:	e8 64 ad 46 00       	call   ffffffff8b4308d0 <frame_candidate_606b10+0x469dc0>
ffffffff8afc5b6c:	41 c6 46 37 01       	movb   $0x1,0x37(%r14)
ffffffff8afc5b71:	e9 a3 00 00 00       	jmp    ffffffff8afc5c19 <frame_candidate_605a70+0x1a9>
ffffffff8afc5b76:	48 8d 3d 44 63 d7 00 	lea    0xd76344(%rip),%rdi        # ffffffff8bd3bec1 <frame_candidate_606b10+0xd753b1>
ffffffff8afc5b7d:	31 c0                	xor    %eax,%eax
ffffffff8afc5b7f:	e8 8c 78 c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc5b84:	eb 1e                	jmp    ffffffff8afc5ba4 <frame_candidate_605a70+0x134>
ffffffff8afc5b86:	31 f6                	xor    %esi,%esi
ffffffff8afc5b88:	eb 0c                	jmp    ffffffff8afc5b96 <frame_candidate_605a70+0x126>
ffffffff8afc5b8a:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8afc5b8f:	eb 05                	jmp    ffffffff8afc5b96 <frame_candidate_605a70+0x126>
ffffffff8afc5b91:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8afc5b96:	48 8d 3d e8 59 ca 00 	lea    0xca59e8(%rip),%rdi        # ffffffff8bc6b585 <frame_candidate_606b10+0xca4a75>
ffffffff8afc5b9d:	31 c0                	xor    %eax,%eax
ffffffff8afc5b9f:	e8 6c 78 c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc5ba4:	48 8b 3d c5 bc 0c 03 	mov    0x30cbcc5(%rip),%rdi        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5bab:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5bae:	74 10                	je     ffffffff8afc5bc0 <frame_candidate_605a70+0x150>
ffffffff8afc5bb0:	e8 9b b0 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5bb5:	48 c7 05 b0 bc 0c 03 	movq   $0x0,0x30cbcb0(%rip)        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5bbc:	00 00 00 00 
ffffffff8afc5bc0:	48 8b 3d c9 bc 0c 03 	mov    0x30cbcc9(%rip),%rdi        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5bc7:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5bca:	74 10                	je     ffffffff8afc5bdc <frame_candidate_605a70+0x16c>
ffffffff8afc5bcc:	e8 7f b0 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5bd1:	48 c7 05 b4 bc 0c 03 	movq   $0x0,0x30cbcb4(%rip)        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5bd8:	00 00 00 00 
ffffffff8afc5bdc:	48 8b 3d cd bc 0c 03 	mov    0x30cbccd(%rip),%rdi        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5be3:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5be6:	74 10                	je     ffffffff8afc5bf8 <frame_candidate_605a70+0x188>
ffffffff8afc5be8:	e8 63 b0 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5bed:	48 c7 05 b8 bc 0c 03 	movq   $0x0,0x30cbcb8(%rip)        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5bf4:	00 00 00 00 
ffffffff8afc5bf8:	48 8b 3d c9 bc 0c 03 	mov    0x30cbcc9(%rip),%rdi        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc5bff:	bb 0c 00 02 80       	mov    $0x8002000c,%ebx
ffffffff8afc5c04:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5c07:	74 10                	je     ffffffff8afc5c19 <frame_candidate_605a70+0x1a9>
ffffffff8afc5c09:	e8 42 b0 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5c0e:	48 c7 05 af bc 0c 03 	movq   $0x0,0x30cbcaf(%rip)        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc5c15:	00 00 00 00 
ffffffff8afc5c19:	48 8d 3d 28 bc 0c 03 	lea    0x30cbc28(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5c20:	31 f6                	xor    %esi,%esi
ffffffff8afc5c22:	31 d2                	xor    %edx,%edx
ffffffff8afc5c24:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5c26:	e8 75 13 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
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
ffffffff8afc5c57:	48 8b 1d ea bb 0c 03 	mov    0x30cbbea(%rip),%rbx        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5c5e:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8afc5c65:	00 00 
ffffffff8afc5c67:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8afc5c6b:	48 83 e3 f8          	and    $0xfffffffffffffff8,%rbx
ffffffff8afc5c6f:	48 39 c3             	cmp    %rax,%rbx
ffffffff8afc5c72:	74 12                	je     ffffffff8afc5c86 <frame_candidate_605c40+0x46>
ffffffff8afc5c74:	48 8d 3d cd bb 0c 03 	lea    0x30cbbcd(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5c7b:	31 f6                	xor    %esi,%esi
ffffffff8afc5c7d:	31 d2                	xor    %edx,%edx
ffffffff8afc5c7f:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5c81:	e8 7a 0d ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc5c86:	80 3d 44 bc 0c 03 00 	cmpb   $0x0,0x30cbc44(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc5c8d:	74 59                	je     ffffffff8afc5ce8 <frame_candidate_605c40+0xa8>
ffffffff8afc5c8f:	4c 8d 3d b2 bb 0c 03 	lea    0x30cbbb2(%rip),%r15        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5c96:	4c 8d 25 34 bc 0c 03 	lea    0x30cbc34(%rip),%r12        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc5c9d:	4c 8d 2d bd e1 ce 00 	lea    0xcee1bd(%rip),%r13        # ffffffff8bcb3e61 <frame_candidate_606b10+0xced351>
ffffffff8afc5ca4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8afc5cab:	00 00 00 00 00 
ffffffff8afc5cb0:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc5cb3:	31 f6                	xor    %esi,%esi
ffffffff8afc5cb5:	31 d2                	xor    %edx,%edx
ffffffff8afc5cb7:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5cb9:	e8 e2 12 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc5cbe:	ba e8 03 00 00       	mov    $0x3e8,%edx
ffffffff8afc5cc3:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc5cc6:	4c 89 ee             	mov    %r13,%rsi
ffffffff8afc5cc9:	44 89 f1             	mov    %r14d,%ecx
ffffffff8afc5ccc:	e8 4f ae 38 00       	call   ffffffff8b350b20 <frame_candidate_606b10+0x38a010>
ffffffff8afc5cd1:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc5cd4:	31 f6                	xor    %esi,%esi
ffffffff8afc5cd6:	31 d2                	xor    %edx,%edx
ffffffff8afc5cd8:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5cda:	e8 21 0d ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc5cdf:	80 3d eb bb 0c 03 00 	cmpb   $0x0,0x30cbbeb(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc5ce6:	75 c8                	jne    ffffffff8afc5cb0 <frame_candidate_605c40+0x70>
ffffffff8afc5ce8:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
ffffffff8afc5cec:	0f 84 80 00 00 00    	je     ffffffff8afc5d72 <frame_candidate_605c40+0x132>
ffffffff8afc5cf2:	80 3d d7 bb 0c 03 01 	cmpb   $0x1,0x30cbbd7(%rip)        # ffffffff8e0918d0 <frame_candidate_606b10+0x30cadc0>
ffffffff8afc5cf9:	75 77                	jne    ffffffff8afc5d72 <frame_candidate_605c40+0x132>
ffffffff8afc5cfb:	48 8b 3d 6e bb 0c 03 	mov    0x30cbb6e(%rip),%rdi        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5d02:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5d05:	74 10                	je     ffffffff8afc5d17 <frame_candidate_605c40+0xd7>
ffffffff8afc5d07:	e8 44 af 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5d0c:	48 c7 05 59 bb 0c 03 	movq   $0x0,0x30cbb59(%rip)        # ffffffff8e091870 <frame_candidate_606b10+0x30cad60>
ffffffff8afc5d13:	00 00 00 00 
ffffffff8afc5d17:	48 8b 3d 72 bb 0c 03 	mov    0x30cbb72(%rip),%rdi        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5d1e:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5d21:	74 10                	je     ffffffff8afc5d33 <frame_candidate_605c40+0xf3>
ffffffff8afc5d23:	e8 28 af 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5d28:	48 c7 05 5d bb 0c 03 	movq   $0x0,0x30cbb5d(%rip)        # ffffffff8e091890 <frame_candidate_606b10+0x30cad80>
ffffffff8afc5d2f:	00 00 00 00 
ffffffff8afc5d33:	48 8b 3d 76 bb 0c 03 	mov    0x30cbb76(%rip),%rdi        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5d3a:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5d3d:	74 10                	je     ffffffff8afc5d4f <frame_candidate_605c40+0x10f>
ffffffff8afc5d3f:	e8 0c af 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5d44:	48 c7 05 61 bb 0c 03 	movq   $0x0,0x30cbb61(%rip)        # ffffffff8e0918b0 <frame_candidate_606b10+0x30cada0>
ffffffff8afc5d4b:	00 00 00 00 
ffffffff8afc5d4f:	48 8b 3d 72 bb 0c 03 	mov    0x30cbb72(%rip),%rdi        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc5d56:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc5d59:	74 10                	je     ffffffff8afc5d6b <frame_candidate_605c40+0x12b>
ffffffff8afc5d5b:	e8 f0 ae 38 00       	call   ffffffff8b350c50 <frame_candidate_606b10+0x38a140>
ffffffff8afc5d60:	48 c7 05 5d bb 0c 03 	movq   $0x0,0x30cbb5d(%rip)        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc5d67:	00 00 00 00 
ffffffff8afc5d6b:	c6 05 5e bb 0c 03 00 	movb   $0x0,0x30cbb5e(%rip)        # ffffffff8e0918d0 <frame_candidate_606b10+0x30cadc0>
ffffffff8afc5d72:	48 8b 05 d7 ba 0c 03 	mov    0x30cbad7(%rip),%rax        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc5d79:	48 85 c0             	test   %rax,%rax
ffffffff8afc5d7c:	74 04                	je     ffffffff8afc5d82 <frame_candidate_605c40+0x142>
ffffffff8afc5d7e:	c6 40 37 00          	movb   $0x0,0x37(%rax)
ffffffff8afc5d82:	48 8d 3d 67 bb 0c 03 	lea    0x30cbb67(%rip),%rdi        # ffffffff8e0918f0 <frame_candidate_606b10+0x30cade0>
ffffffff8afc5d89:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc5d8e:	48 c7 05 c7 ba 0c 03 	movq   $0x0,0x30cbac7(%rip)        # ffffffff8e091860 <frame_candidate_606b10+0x30cad50>
ffffffff8afc5d95:	00 00 00 00 
ffffffff8afc5d99:	48 c7 05 dc ba 0c 03 	movq   $0x0,0x30cbadc(%rip)        # ffffffff8e091880 <frame_candidate_606b10+0x30cad70>
ffffffff8afc5da0:	00 00 00 00 
ffffffff8afc5da4:	31 f6                	xor    %esi,%esi
ffffffff8afc5da6:	48 c7 05 ef ba 0c 03 	movq   $0x0,0x30cbaef(%rip)        # ffffffff8e0918a0 <frame_candidate_606b10+0x30cad90>
ffffffff8afc5dad:	00 00 00 00 
ffffffff8afc5db1:	e8 9a df d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc5db6:	48 8d 3d 83 bb 0c 03 	lea    0x30cbb83(%rip),%rdi        # ffffffff8e091940 <frame_candidate_606b10+0x30cae30>
ffffffff8afc5dbd:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc5dc2:	31 f6                	xor    %esi,%esi
ffffffff8afc5dc4:	e8 87 df d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc5dc9:	48 8d 3d c0 bb 0c 03 	lea    0x30cbbc0(%rip),%rdi        # ffffffff8e091990 <frame_candidate_606b10+0x30cae80>
ffffffff8afc5dd0:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc5dd5:	31 f6                	xor    %esi,%esi
ffffffff8afc5dd7:	e8 74 df d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc5ddc:	48 8d 3d fd bb 0c 03 	lea    0x30cbbfd(%rip),%rdi        # ffffffff8e0919e0 <frame_candidate_606b10+0x30caed0>
ffffffff8afc5de3:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc5de8:	31 f6                	xor    %esi,%esi
ffffffff8afc5dea:	e8 61 df d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc5def:	48 3b 5d c8          	cmp    -0x38(%rbp),%rbx
ffffffff8afc5df3:	75 0f                	jne    ffffffff8afc5e04 <frame_candidate_605c40+0x1c4>
ffffffff8afc5df5:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8afc5df9:	5b                   	pop    %rbx
ffffffff8afc5dfa:	41 5c                	pop    %r12
ffffffff8afc5dfc:	41 5d                	pop    %r13
ffffffff8afc5dfe:	41 5e                	pop    %r14
ffffffff8afc5e00:	41 5f                	pop    %r15
ffffffff8afc5e02:	5d                   	pop    %rbp
ffffffff8afc5e03:	c3                   	ret
ffffffff8afc5e04:	48 8d 3d 3d ba 0c 03 	lea    0x30cba3d(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5e0b:	31 f6                	xor    %esi,%esi
ffffffff8afc5e0d:	31 d2                	xor    %edx,%edx
ffffffff8afc5e0f:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5e11:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8afc5e15:	5b                   	pop    %rbx
ffffffff8afc5e16:	41 5c                	pop    %r12
ffffffff8afc5e18:	41 5d                	pop    %r13
ffffffff8afc5e1a:	41 5e                	pop    %r14
ffffffff8afc5e1c:	41 5f                	pop    %r15
ffffffff8afc5e1e:	5d                   	pop    %rbp
ffffffff8afc5e1f:	e9 7c 11 ec ff       	jmp    ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc5e24:	90                   	nop
ffffffff8afc5e25:	90                   	nop
ffffffff8afc5e26:	90                   	nop
ffffffff8afc5e27:	90                   	nop
ffffffff8afc5e28:	90                   	nop
ffffffff8afc5e29:	90                   	nop
ffffffff8afc5e2a:	90                   	nop
ffffffff8afc5e2b:	90                   	nop
ffffffff8afc5e2c:	90                   	nop
ffffffff8afc5e2d:	90                   	nop
ffffffff8afc5e2e:	90                   	nop
ffffffff8afc5e2f:	90                   	nop

ffffffff8afc5e30 <frame_candidate_605e30>:
ffffffff8afc5e30:	55                   	push   %rbp
ffffffff8afc5e31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5e34:	41 57                	push   %r15
ffffffff8afc5e36:	41 56                	push   %r14
ffffffff8afc5e38:	53                   	push   %rbx
ffffffff8afc5e39:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8afc5e3d:	4c 8d 3d cc 64 31 03 	lea    0x33164cc(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc5e44:	48 8d 7d d8          	lea    -0x28(%rbp),%rdi
ffffffff8afc5e48:	49 8b 07             	mov    (%r15),%rax
ffffffff8afc5e4b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8afc5e4f:	e8 ac 5c e9 ff       	call   ffffffff8ae5bb00 <handler_626_body-0x1691f0>
ffffffff8afc5e54:	bb 0a 10 72 8a       	mov    $0x8a72100a,%ebx
ffffffff8afc5e59:	85 c0                	test   %eax,%eax
ffffffff8afc5e5b:	75 41                	jne    ffffffff8afc5e9e <frame_candidate_605e30+0x6e>
ffffffff8afc5e5d:	4c 8d 35 e4 b9 0c 03 	lea    0x30cb9e4(%rip),%r14        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5e64:	31 db                	xor    %ebx,%ebx
ffffffff8afc5e66:	31 f6                	xor    %esi,%esi
ffffffff8afc5e68:	31 d2                	xor    %edx,%edx
ffffffff8afc5e6a:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5e6c:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc5e6f:	e8 8c 0b ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc5e74:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
ffffffff8afc5e78:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc5e7d:	31 f6                	xor    %esi,%esi
ffffffff8afc5e7f:	c6 40 48 01          	movb   $0x1,0x48(%rax)
ffffffff8afc5e83:	48 8b 7d d8          	mov    -0x28(%rbp),%rdi
ffffffff8afc5e87:	48 83 c7 10          	add    $0x10,%rdi
ffffffff8afc5e8b:	e8 c0 de d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc5e90:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc5e93:	31 f6                	xor    %esi,%esi
ffffffff8afc5e95:	31 d2                	xor    %edx,%edx
ffffffff8afc5e97:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5e99:	e8 02 11 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc5e9e:	49 8b 07             	mov    (%r15),%rax
ffffffff8afc5ea1:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
ffffffff8afc5ea5:	75 0d                	jne    ffffffff8afc5eb4 <frame_candidate_605e30+0x84>
ffffffff8afc5ea7:	89 d8                	mov    %ebx,%eax
ffffffff8afc5ea9:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8afc5ead:	5b                   	pop    %rbx
ffffffff8afc5eae:	41 5e                	pop    %r14
ffffffff8afc5eb0:	41 5f                	pop    %r15
ffffffff8afc5eb2:	5d                   	pop    %rbp
ffffffff8afc5eb3:	c3                   	ret
ffffffff8afc5eb4:	e8 f7 77 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
ffffffff8afc5eb9:	0f 0b                	ud2
ffffffff8afc5ebb:	90                   	nop
ffffffff8afc5ebc:	90                   	nop
ffffffff8afc5ebd:	90                   	nop
ffffffff8afc5ebe:	90                   	nop
ffffffff8afc5ebf:	90                   	nop

ffffffff8afc5ec0 <frame_candidate_605ec0>:
ffffffff8afc5ec0:	55                   	push   %rbp
ffffffff8afc5ec1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5ec4:	41 56                	push   %r14
ffffffff8afc5ec6:	53                   	push   %rbx
ffffffff8afc5ec7:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8afc5ecb:	4c 8d 35 3e 64 31 03 	lea    0x331643e(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc5ed2:	48 8d 7d e0          	lea    -0x20(%rbp),%rdi
ffffffff8afc5ed6:	49 8b 06             	mov    (%r14),%rax
ffffffff8afc5ed9:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8afc5edd:	e8 1e 5c e9 ff       	call   ffffffff8ae5bb00 <handler_626_body-0x1691f0>
ffffffff8afc5ee2:	85 c0                	test   %eax,%eax
ffffffff8afc5ee4:	75 3f                	jne    ffffffff8afc5f25 <frame_candidate_605ec0+0x65>
ffffffff8afc5ee6:	48 8d 1d 5b b9 0c 03 	lea    0x30cb95b(%rip),%rbx        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5eed:	31 f6                	xor    %esi,%esi
ffffffff8afc5eef:	31 d2                	xor    %edx,%edx
ffffffff8afc5ef1:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5ef3:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5ef6:	e8 05 0b ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc5efb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
ffffffff8afc5eff:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc5f04:	31 f6                	xor    %esi,%esi
ffffffff8afc5f06:	c6 40 48 00          	movb   $0x0,0x48(%rax)
ffffffff8afc5f0a:	48 8b 7d e0          	mov    -0x20(%rbp),%rdi
ffffffff8afc5f0e:	48 83 c7 10          	add    $0x10,%rdi
ffffffff8afc5f12:	e8 39 de d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc5f17:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc5f1a:	31 f6                	xor    %esi,%esi
ffffffff8afc5f1c:	31 d2                	xor    %edx,%edx
ffffffff8afc5f1e:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5f20:	e8 7b 10 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc5f25:	49 8b 06             	mov    (%r14),%rax
ffffffff8afc5f28:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
ffffffff8afc5f2c:	75 09                	jne    ffffffff8afc5f37 <frame_candidate_605ec0+0x77>
ffffffff8afc5f2e:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8afc5f32:	5b                   	pop    %rbx
ffffffff8afc5f33:	41 5e                	pop    %r14
ffffffff8afc5f35:	5d                   	pop    %rbp
ffffffff8afc5f36:	c3                   	ret
ffffffff8afc5f37:	e8 74 77 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
ffffffff8afc5f3c:	0f 0b                	ud2
ffffffff8afc5f3e:	90                   	nop
ffffffff8afc5f3f:	90                   	nop

ffffffff8afc5f40 <frame_candidate_605f40>:
ffffffff8afc5f40:	55                   	push   %rbp
ffffffff8afc5f41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc5f44:	41 56                	push   %r14
ffffffff8afc5f46:	53                   	push   %rbx
ffffffff8afc5f47:	48 8b 46 08          	mov    0x8(%rsi),%rax
ffffffff8afc5f4b:	48 8d 3d f6 b8 0c 03 	lea    0x30cb8f6(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5f52:	31 f6                	xor    %esi,%esi
ffffffff8afc5f54:	31 d2                	xor    %edx,%edx
ffffffff8afc5f56:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5f58:	44 8b b0 bc 00 00 00 	mov    0xbc(%rax),%r14d
ffffffff8afc5f5f:	e8 9c 0a ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc5f64:	8b 05 76 b9 0c 03    	mov    0x30cb976(%rip),%eax        # ffffffff8e0918e0 <frame_candidate_606b10+0x30cadd0>
ffffffff8afc5f6a:	8b 0d c0 b9 0c 03    	mov    0x30cb9c0(%rip),%ecx        # ffffffff8e091930 <frame_candidate_606b10+0x30cae20>
ffffffff8afc5f70:	8b 35 5a ba 0c 03    	mov    0x30cba5a(%rip),%esi        # ffffffff8e0919d0 <frame_candidate_606b10+0x30caec0>
ffffffff8afc5f76:	44 39 f0             	cmp    %r14d,%eax
ffffffff8afc5f79:	0f 94 c2             	sete   %dl
ffffffff8afc5f7c:	44 39 f1             	cmp    %r14d,%ecx
ffffffff8afc5f7f:	40 0f 94 c7          	sete   %dil
ffffffff8afc5f83:	40 08 d7             	or     %dl,%dil
ffffffff8afc5f86:	8b 15 f4 b9 0c 03    	mov    0x30cb9f4(%rip),%edx        # ffffffff8e091980 <frame_candidate_606b10+0x30cae70>
ffffffff8afc5f8c:	44 39 f2             	cmp    %r14d,%edx
ffffffff8afc5f8f:	41 0f 94 c0          	sete   %r8b
ffffffff8afc5f93:	44 39 f6             	cmp    %r14d,%esi
ffffffff8afc5f96:	41 0f 94 c1          	sete   %r9b
ffffffff8afc5f9a:	45 08 c1             	or     %r8b,%r9b
ffffffff8afc5f9d:	41 08 f9             	or     %dil,%r9b
ffffffff8afc5fa0:	41 80 f9 01          	cmp    $0x1,%r9b
ffffffff8afc5fa4:	75 1a                	jne    ffffffff8afc5fc0 <frame_candidate_605f40+0x80>
ffffffff8afc5fa6:	48 8d 3d 9b b8 0c 03 	lea    0x30cb89b(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5fad:	31 f6                	xor    %esi,%esi
ffffffff8afc5faf:	31 d2                	xor    %edx,%edx
ffffffff8afc5fb1:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5fb3:	e8 e8 0f ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc5fb8:	41 be 07 10 72 8a    	mov    $0x8a721007,%r14d
ffffffff8afc5fbe:	eb 73                	jmp    ffffffff8afc6033 <frame_candidate_605f40+0xf3>
ffffffff8afc5fc0:	85 c0                	test   %eax,%eax
ffffffff8afc5fc2:	74 26                	je     ffffffff8afc5fea <frame_candidate_605f40+0xaa>
ffffffff8afc5fc4:	85 c9                	test   %ecx,%ecx
ffffffff8afc5fc6:	74 2b                	je     ffffffff8afc5ff3 <frame_candidate_605f40+0xb3>
ffffffff8afc5fc8:	85 d2                	test   %edx,%edx
ffffffff8afc5fca:	74 30                	je     ffffffff8afc5ffc <frame_candidate_605f40+0xbc>
ffffffff8afc5fcc:	85 f6                	test   %esi,%esi
ffffffff8afc5fce:	74 35                	je     ffffffff8afc6005 <frame_candidate_605f40+0xc5>
ffffffff8afc5fd0:	48 8d 3d 71 b8 0c 03 	lea    0x30cb871(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc5fd7:	31 f6                	xor    %esi,%esi
ffffffff8afc5fd9:	31 d2                	xor    %edx,%edx
ffffffff8afc5fdb:	31 c9                	xor    %ecx,%ecx
ffffffff8afc5fdd:	e8 be 0f ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc5fe2:	41 be 07 00 72 8a    	mov    $0x8a720007,%r14d
ffffffff8afc5fe8:	eb 49                	jmp    ffffffff8afc6033 <frame_candidate_605f40+0xf3>
ffffffff8afc5fea:	48 8d 1d ef b8 0c 03 	lea    0x30cb8ef(%rip),%rbx        # ffffffff8e0918e0 <frame_candidate_606b10+0x30cadd0>
ffffffff8afc5ff1:	eb 19                	jmp    ffffffff8afc600c <frame_candidate_605f40+0xcc>
ffffffff8afc5ff3:	48 8d 1d 36 b9 0c 03 	lea    0x30cb936(%rip),%rbx        # ffffffff8e091930 <frame_candidate_606b10+0x30cae20>
ffffffff8afc5ffa:	eb 10                	jmp    ffffffff8afc600c <frame_candidate_605f40+0xcc>
ffffffff8afc5ffc:	48 8d 1d 7d b9 0c 03 	lea    0x30cb97d(%rip),%rbx        # ffffffff8e091980 <frame_candidate_606b10+0x30cae70>
ffffffff8afc6003:	eb 07                	jmp    ffffffff8afc600c <frame_candidate_605f40+0xcc>
ffffffff8afc6005:	48 8d 1d c4 b9 0c 03 	lea    0x30cb9c4(%rip),%rbx        # ffffffff8e0919d0 <frame_candidate_606b10+0x30caec0>
ffffffff8afc600c:	48 8d 3d 35 b8 0c 03 	lea    0x30cb835(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6013:	44 89 33             	mov    %r14d,(%rbx)
ffffffff8afc6016:	45 31 f6             	xor    %r14d,%r14d
ffffffff8afc6019:	31 f6                	xor    %esi,%esi
ffffffff8afc601b:	31 d2                	xor    %edx,%edx
ffffffff8afc601d:	31 c9                	xor    %ecx,%ecx
ffffffff8afc601f:	e8 7c 0f ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6024:	48 8d 35 e5 cb c5 ff 	lea    -0x3a341b(%rip),%rsi        # ffffffff8ac22c10 <handler_626_body-0x3a20e0>
ffffffff8afc602b:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc602e:	e8 0d 5b e9 ff       	call   ffffffff8ae5bb40 <handler_626_body-0x1691b0>
ffffffff8afc6033:	44 89 f0             	mov    %r14d,%eax
ffffffff8afc6036:	5b                   	pop    %rbx
ffffffff8afc6037:	41 5e                	pop    %r14
ffffffff8afc6039:	5d                   	pop    %rbp
ffffffff8afc603a:	c3                   	ret
ffffffff8afc603b:	90                   	nop
ffffffff8afc603c:	90                   	nop
ffffffff8afc603d:	90                   	nop
ffffffff8afc603e:	90                   	nop
ffffffff8afc603f:	90                   	nop
ffffffff8afc6040:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc6043:	74 43                	je     ffffffff8afc6088 <frame_candidate_606045+0x43>

ffffffff8afc6045 <frame_candidate_606045>:
ffffffff8afc6045:	55                   	push   %rbp
ffffffff8afc6046:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc6049:	41 56                	push   %r14
ffffffff8afc604b:	53                   	push   %rbx
ffffffff8afc604c:	4c 8d 35 f5 b7 0c 03 	lea    0x30cb7f5(%rip),%r14        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6053:	48 89 fb             	mov    %rdi,%rbx
ffffffff8afc6056:	31 f6                	xor    %esi,%esi
ffffffff8afc6058:	31 d2                	xor    %edx,%edx
ffffffff8afc605a:	31 c9                	xor    %ecx,%ecx
ffffffff8afc605c:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc605f:	e8 9c 09 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc6064:	c7 03 00 00 00 00    	movl   $0x0,(%rbx)
ffffffff8afc606a:	48 c7 43 08 00 00 00 	movq   $0x0,0x8(%rbx)
ffffffff8afc6071:	00 
ffffffff8afc6072:	c6 43 48 00          	movb   $0x0,0x48(%rbx)
ffffffff8afc6076:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc6079:	31 f6                	xor    %esi,%esi
ffffffff8afc607b:	31 d2                	xor    %edx,%edx
ffffffff8afc607d:	31 c9                	xor    %ecx,%ecx
ffffffff8afc607f:	5b                   	pop    %rbx
ffffffff8afc6080:	41 5e                	pop    %r14
ffffffff8afc6082:	5d                   	pop    %rbp
ffffffff8afc6083:	e9 18 0f ec ff       	jmp    ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6088:	c3                   	ret
ffffffff8afc6089:	90                   	nop
ffffffff8afc608a:	90                   	nop
ffffffff8afc608b:	90                   	nop
ffffffff8afc608c:	90                   	nop
ffffffff8afc608d:	90                   	nop
ffffffff8afc608e:	90                   	nop
ffffffff8afc608f:	90                   	nop

ffffffff8afc6090 <frame_candidate_606090>:
ffffffff8afc6090:	55                   	push   %rbp
ffffffff8afc6091:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc6094:	31 c0                	xor    %eax,%eax
ffffffff8afc6096:	5d                   	pop    %rbp
ffffffff8afc6097:	c3                   	ret
ffffffff8afc6098:	90                   	nop
ffffffff8afc6099:	90                   	nop
ffffffff8afc609a:	90                   	nop
ffffffff8afc609b:	90                   	nop
ffffffff8afc609c:	90                   	nop
ffffffff8afc609d:	90                   	nop
ffffffff8afc609e:	90                   	nop
ffffffff8afc609f:	90                   	nop

ffffffff8afc60a0 <frame_candidate_6060a0>:
ffffffff8afc60a0:	55                   	push   %rbp
ffffffff8afc60a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc60a4:	41 57                	push   %r15
ffffffff8afc60a6:	41 56                	push   %r14
ffffffff8afc60a8:	41 55                	push   %r13
ffffffff8afc60aa:	41 54                	push   %r12
ffffffff8afc60ac:	53                   	push   %rbx
ffffffff8afc60ad:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8afc60b1:	4c 8d 2d 58 62 31 03 	lea    0x3316258(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc60b8:	49 89 fe             	mov    %rdi,%r14
ffffffff8afc60bb:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8afc60bf:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8afc60c3:	44 8b 7f 18          	mov    0x18(%rdi),%r15d
ffffffff8afc60c7:	48 8d 7d c8          	lea    -0x38(%rbp),%rdi
ffffffff8afc60cb:	e8 30 5a e9 ff       	call   ffffffff8ae5bb00 <handler_626_body-0x1691f0>
ffffffff8afc60d0:	bb 0a 10 72 8a       	mov    $0x8a72100a,%ebx
ffffffff8afc60d5:	85 c0                	test   %eax,%eax
ffffffff8afc60d7:	74 1f                	je     ffffffff8afc60f8 <frame_candidate_6060a0+0x58>
ffffffff8afc60d9:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8afc60dd:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8afc60e1:	0f 85 87 02 00 00    	jne    ffffffff8afc636e <frame_candidate_6060a0+0x2ce>
ffffffff8afc60e7:	89 d8                	mov    %ebx,%eax
ffffffff8afc60e9:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8afc60ed:	5b                   	pop    %rbx
ffffffff8afc60ee:	41 5c                	pop    %r12
ffffffff8afc60f0:	41 5d                	pop    %r13
ffffffff8afc60f2:	41 5e                	pop    %r14
ffffffff8afc60f4:	41 5f                	pop    %r15
ffffffff8afc60f6:	5d                   	pop    %rbp
ffffffff8afc60f7:	c3                   	ret
ffffffff8afc60f8:	bb 09 00 72 8a       	mov    $0x8a720009,%ebx
ffffffff8afc60fd:	45 85 ff             	test   %r15d,%r15d
ffffffff8afc6100:	7e d7                	jle    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc6102:	48 8d 3d 3f b7 0c 03 	lea    0x30cb73f(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6109:	44 89 7d c4          	mov    %r15d,-0x3c(%rbp)
ffffffff8afc610d:	31 f6                	xor    %esi,%esi
ffffffff8afc610f:	31 d2                	xor    %edx,%edx
ffffffff8afc6111:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6113:	e8 e8 08 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc6118:	80 3d b2 b7 0c 03 00 	cmpb   $0x0,0x30cb7b2(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc611f:	74 59                	je     ffffffff8afc617a <frame_candidate_6060a0+0xda>
ffffffff8afc6121:	4c 8d 3d 20 b7 0c 03 	lea    0x30cb720(%rip),%r15        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6128:	4c 8d 25 a2 b7 0c 03 	lea    0x30cb7a2(%rip),%r12        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc612f:	4c 8d 2d 2b dd ce 00 	lea    0xcedd2b(%rip),%r13        # ffffffff8bcb3e61 <frame_candidate_606b10+0xced351>
ffffffff8afc6136:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8afc613d:	00 00 00 
ffffffff8afc6140:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc6143:	31 f6                	xor    %esi,%esi
ffffffff8afc6145:	31 d2                	xor    %edx,%edx
ffffffff8afc6147:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6149:	e8 52 0e ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc614e:	ba e8 03 00 00       	mov    $0x3e8,%edx
ffffffff8afc6153:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc6156:	4c 89 ee             	mov    %r13,%rsi
ffffffff8afc6159:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8afc615e:	e8 bd a9 38 00       	call   ffffffff8b350b20 <frame_candidate_606b10+0x38a010>
ffffffff8afc6163:	4c 89 ff             	mov    %r15,%rdi
ffffffff8afc6166:	31 f6                	xor    %esi,%esi
ffffffff8afc6168:	31 d2                	xor    %edx,%edx
ffffffff8afc616a:	31 c9                	xor    %ecx,%ecx
ffffffff8afc616c:	e8 8f 08 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc6171:	80 3d 59 b7 0c 03 00 	cmpb   $0x0,0x30cb759(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc6178:	75 c6                	jne    ffffffff8afc6140 <frame_candidate_6060a0+0xa0>
ffffffff8afc617a:	48 8b 05 cf b6 0c 03 	mov    0x30cb6cf(%rip),%rax        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc6181:	48 85 c0             	test   %rax,%rax
ffffffff8afc6184:	74 72                	je     ffffffff8afc61f8 <frame_candidate_6060a0+0x158>
ffffffff8afc6186:	80 78 37 00          	cmpb   $0x0,0x37(%rax)
ffffffff8afc618a:	4c 8d 2d 7f 61 31 03 	lea    0x331617f(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc6191:	0f 84 84 00 00 00    	je     ffffffff8afc621b <frame_candidate_6060a0+0x17b>
ffffffff8afc6197:	8b 05 bf b6 0c 03    	mov    0x30cb6bf(%rip),%eax        # ffffffff8e09185c <frame_candidate_606b10+0x30cad4c>
ffffffff8afc619d:	ba ab aa aa aa       	mov    $0xaaaaaaab,%edx
ffffffff8afc61a2:	48 8d 0d 87 b6 0c 03 	lea    0x30cb687(%rip),%rcx        # ffffffff8e091830 <frame_candidate_606b10+0x30cad20>
ffffffff8afc61a9:	48 0f af d0          	imul   %rax,%rdx
ffffffff8afc61ad:	48 c1 ea 21          	shr    $0x21,%rdx
ffffffff8afc61b1:	8d 14 52             	lea    (%rdx,%rdx,2),%edx
ffffffff8afc61b4:	29 d0                	sub    %edx,%eax
ffffffff8afc61b6:	c1 e0 05             	shl    $0x5,%eax
ffffffff8afc61b9:	48 8b 74 08 40       	mov    0x40(%rax,%rcx,1),%rsi
ffffffff8afc61be:	48 85 f6             	test   %rsi,%rsi
ffffffff8afc61c1:	74 74                	je     ffffffff8afc6237 <frame_candidate_6060a0+0x197>
ffffffff8afc61c3:	4c 8d 64 08 30       	lea    0x30(%rax,%rcx,1),%r12
ffffffff8afc61c8:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
ffffffff8afc61cc:	48 8b 41 08          	mov    0x8(%rcx),%rax
ffffffff8afc61d0:	49 3b 04 24          	cmp    (%r12),%rax
ffffffff8afc61d4:	73 45                	jae    ffffffff8afc621b <frame_candidate_6060a0+0x17b>
ffffffff8afc61d6:	4d 63 7c 24 08       	movslq 0x8(%r12),%r15
ffffffff8afc61db:	44 39 7d c4          	cmp    %r15d,-0x3c(%rbp)
ffffffff8afc61df:	7d 72                	jge    ffffffff8afc6253 <frame_candidate_6060a0+0x1b3>
ffffffff8afc61e1:	48 8d 3d 60 b6 0c 03 	lea    0x30cb660(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc61e8:	31 f6                	xor    %esi,%esi
ffffffff8afc61ea:	31 d2                	xor    %edx,%edx
ffffffff8afc61ec:	31 c9                	xor    %ecx,%ecx
ffffffff8afc61ee:	e8 ad 0d ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc61f3:	e9 e1 fe ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc61f8:	48 8d 3d 49 b6 0c 03 	lea    0x30cb649(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc61ff:	31 f6                	xor    %esi,%esi
ffffffff8afc6201:	31 d2                	xor    %edx,%edx
ffffffff8afc6203:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6205:	e8 96 0d ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc620a:	4c 8d 2d ff 60 31 03 	lea    0x33160ff(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc6211:	bb 04 00 72 8a       	mov    $0x8a720004,%ebx
ffffffff8afc6216:	e9 be fe ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc621b:	48 8d 3d 26 b6 0c 03 	lea    0x30cb626(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6222:	31 f6                	xor    %esi,%esi
ffffffff8afc6224:	31 d2                	xor    %edx,%edx
ffffffff8afc6226:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6228:	e8 73 0d ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc622d:	bb 06 10 72 8a       	mov    $0x8a721006,%ebx
ffffffff8afc6232:	e9 a2 fe ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc6237:	48 8d 3d 0a b6 0c 03 	lea    0x30cb60a(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc623e:	31 f6                	xor    %esi,%esi
ffffffff8afc6240:	31 d2                	xor    %edx,%edx
ffffffff8afc6242:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6244:	e8 57 0d ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6249:	bb 04 00 72 8a       	mov    $0x8a720004,%ebx
ffffffff8afc624e:	e9 86 fe ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc6253:	48 8b 3d 6e b6 0c 03 	mov    0x30cb66e(%rip),%rdi        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc625a:	48 85 ff             	test   %rdi,%rdi
ffffffff8afc625d:	0f 84 89 00 00 00    	je     ffffffff8afc62ec <frame_candidate_6060a0+0x24c>
ffffffff8afc6263:	4c 89 fa             	mov    %r15,%rdx
ffffffff8afc6266:	e8 45 2e c5 ff       	call   ffffffff8ac190b0 <handler_626_body-0x3abc40>
ffffffff8afc626b:	48 8d 3d d6 b5 0c 03 	lea    0x30cb5d6(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6272:	c6 05 58 b6 0c 03 01 	movb   $0x1,0x30cb658(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc6279:	31 f6                	xor    %esi,%esi
ffffffff8afc627b:	31 d2                	xor    %edx,%edx
ffffffff8afc627d:	31 c9                	xor    %ecx,%ecx
ffffffff8afc627f:	e8 1c 0d ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6284:	48 8b 3d 3d b6 0c 03 	mov    0x30cb63d(%rip),%rdi        # ffffffff8e0918c8 <frame_candidate_606b10+0x30cadb8>
ffffffff8afc628b:	44 89 fe             	mov    %r15d,%esi
ffffffff8afc628e:	4c 89 f2             	mov    %r14,%rdx
ffffffff8afc6291:	e8 8a c2 17 00       	call   ffffffff8b142520 <frame_candidate_606b10+0x17ba10>
ffffffff8afc6296:	85 c0                	test   %eax,%eax
ffffffff8afc6298:	74 6e                	je     ffffffff8afc6308 <frame_candidate_6060a0+0x268>
ffffffff8afc629a:	4c 8d 35 a7 b5 0c 03 	lea    0x30cb5a7(%rip),%r14        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc62a1:	89 c3                	mov    %eax,%ebx
ffffffff8afc62a3:	31 f6                	xor    %esi,%esi
ffffffff8afc62a5:	31 d2                	xor    %edx,%edx
ffffffff8afc62a7:	31 c9                	xor    %ecx,%ecx
ffffffff8afc62a9:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc62ac:	e8 4f 07 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc62b1:	48 8d 3d 19 b6 0c 03 	lea    0x30cb619(%rip),%rdi        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc62b8:	c6 05 12 b6 0c 03 00 	movb   $0x0,0x30cb612(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc62bf:	e8 4c 06 60 00       	call   ffffffff8b5c6910 <frame_candidate_606b10+0x5ffe00>
ffffffff8afc62c4:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc62c7:	31 f6                	xor    %esi,%esi
ffffffff8afc62c9:	31 d2                	xor    %edx,%edx
ffffffff8afc62cb:	31 c9                	xor    %ecx,%ecx
ffffffff8afc62cd:	e8 ce 0c ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc62d2:	48 8d 3d 52 96 cd 00 	lea    0xcd9652(%rip),%rdi        # ffffffff8bc9f92b <frame_candidate_606b10+0xcd8e1b>
ffffffff8afc62d9:	89 de                	mov    %ebx,%esi
ffffffff8afc62db:	31 c0                	xor    %eax,%eax
ffffffff8afc62dd:	e8 2e 71 c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc62e2:	bb 08 10 72 8a       	mov    $0x8a721008,%ebx
ffffffff8afc62e7:	e9 ed fd ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc62ec:	48 8d 3d 55 b5 0c 03 	lea    0x30cb555(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc62f3:	31 f6                	xor    %esi,%esi
ffffffff8afc62f5:	31 d2                	xor    %edx,%edx
ffffffff8afc62f7:	31 c9                	xor    %ecx,%ecx
ffffffff8afc62f9:	e8 a2 0c ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc62fe:	bb 0a 10 72 8a       	mov    $0x8a72100a,%ebx
ffffffff8afc6303:	e9 d1 fd ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc6308:	8b 45 c4             	mov    -0x3c(%rbp),%eax
ffffffff8afc630b:	4d 8b 76 18          	mov    0x18(%r14),%r14
ffffffff8afc630f:	48 8d 3d 32 b5 0c 03 	lea    0x30cb532(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6316:	31 db                	xor    %ebx,%ebx
ffffffff8afc6318:	31 f6                	xor    %esi,%esi
ffffffff8afc631a:	31 d2                	xor    %edx,%edx
ffffffff8afc631c:	31 c9                	xor    %ecx,%ecx
ffffffff8afc631e:	44 29 f8             	sub    %r15d,%eax
ffffffff8afc6321:	4c 63 f8             	movslq %eax,%r15
ffffffff8afc6324:	e8 d7 06 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc6329:	48 8d 3d a1 b5 0c 03 	lea    0x30cb5a1(%rip),%rdi        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc6330:	c6 05 9a b5 0c 03 00 	movb   $0x0,0x30cb59a(%rip)        # ffffffff8e0918d1 <frame_candidate_606b10+0x30cadc1>
ffffffff8afc6337:	e8 d4 05 60 00       	call   ffffffff8b5c6910 <frame_candidate_606b10+0x5ffe00>
ffffffff8afc633c:	4d 39 fe             	cmp    %r15,%r14
ffffffff8afc633f:	75 11                	jne    ffffffff8afc6352 <frame_candidate_6060a0+0x2b2>
ffffffff8afc6341:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8afc6345:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
ffffffff8afc6349:	48 89 41 08          	mov    %rax,0x8(%rcx)
ffffffff8afc634d:	e9 8f fe ff ff       	jmp    ffffffff8afc61e1 <frame_candidate_6060a0+0x141>
ffffffff8afc6352:	48 8d 3d ef b4 0c 03 	lea    0x30cb4ef(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6359:	31 f6                	xor    %esi,%esi
ffffffff8afc635b:	31 d2                	xor    %edx,%edx
ffffffff8afc635d:	31 c9                	xor    %ecx,%ecx
ffffffff8afc635f:	e8 3c 0c ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6364:	bb 07 10 72 8a       	mov    $0x8a721007,%ebx
ffffffff8afc6369:	e9 6b fd ff ff       	jmp    ffffffff8afc60d9 <frame_candidate_6060a0+0x39>
ffffffff8afc636e:	e8 3d 73 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
ffffffff8afc6373:	0f 0b                	ud2
ffffffff8afc6375:	90                   	nop
ffffffff8afc6376:	90                   	nop
ffffffff8afc6377:	90                   	nop
ffffffff8afc6378:	90                   	nop
ffffffff8afc6379:	90                   	nop
ffffffff8afc637a:	90                   	nop
ffffffff8afc637b:	90                   	nop
ffffffff8afc637c:	90                   	nop
ffffffff8afc637d:	90                   	nop
ffffffff8afc637e:	90                   	nop
ffffffff8afc637f:	90                   	nop

ffffffff8afc6380 <frame_candidate_606380>:
ffffffff8afc6380:	55                   	push   %rbp
ffffffff8afc6381:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc6384:	41 56                	push   %r14
ffffffff8afc6386:	53                   	push   %rbx
ffffffff8afc6387:	48 83 ec 20          	sub    $0x20,%rsp
ffffffff8afc638b:	4c 8d 35 7e 5f 31 03 	lea    0x3315f7e(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc6392:	48 89 f3             	mov    %rsi,%rbx
ffffffff8afc6395:	48 8d 7d d8          	lea    -0x28(%rbp),%rdi
ffffffff8afc6399:	be 10 00 00 00       	mov    $0x10,%esi
ffffffff8afc639e:	49 8b 06             	mov    (%r14),%rax
ffffffff8afc63a1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8afc63a5:	e8 46 2c c5 ff       	call   ffffffff8ac18ff0 <handler_626_body-0x3abd00>
ffffffff8afc63aa:	48 8d 7d d0          	lea    -0x30(%rbp),%rdi
ffffffff8afc63ae:	e8 4d 57 e9 ff       	call   ffffffff8ae5bb00 <handler_626_body-0x1691f0>
ffffffff8afc63b3:	89 c1                	mov    %eax,%ecx
ffffffff8afc63b5:	b8 0a 10 72 8a       	mov    $0x8a72100a,%eax
ffffffff8afc63ba:	85 c9                	test   %ecx,%ecx
ffffffff8afc63bc:	74 16                	je     ffffffff8afc63d4 <frame_candidate_606380+0x54>
ffffffff8afc63be:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8afc63c1:	48 3b 4d e8          	cmp    -0x18(%rbp),%rcx
ffffffff8afc63c5:	0f 85 cb 00 00 00    	jne    ffffffff8afc6496 <frame_candidate_606380+0x116>
ffffffff8afc63cb:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8afc63cf:	5b                   	pop    %rbx
ffffffff8afc63d0:	41 5e                	pop    %r14
ffffffff8afc63d2:	5d                   	pop    %rbp
ffffffff8afc63d3:	c3                   	ret
ffffffff8afc63d4:	48 8d 3d 6d b4 0c 03 	lea    0x30cb46d(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc63db:	31 f6                	xor    %esi,%esi
ffffffff8afc63dd:	31 d2                	xor    %edx,%edx
ffffffff8afc63df:	31 c9                	xor    %ecx,%ecx
ffffffff8afc63e1:	e8 1a 06 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc63e6:	48 83 3d 62 b4 0c 03 	cmpq   $0x0,0x30cb462(%rip)        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc63ed:	00 
ffffffff8afc63ee:	74 6e                	je     ffffffff8afc645e <frame_candidate_606380+0xde>
ffffffff8afc63f0:	8b 05 66 b4 0c 03    	mov    0x30cb466(%rip),%eax        # ffffffff8e09185c <frame_candidate_606b10+0x30cad4c>
ffffffff8afc63f6:	ba ab aa aa aa       	mov    $0xaaaaaaab,%edx
ffffffff8afc63fb:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
ffffffff8afc63ff:	48 8d 0d 2a b4 0c 03 	lea    0x30cb42a(%rip),%rcx        # ffffffff8e091830 <frame_candidate_606b10+0x30cad20>
ffffffff8afc6406:	48 0f af d0          	imul   %rax,%rdx
ffffffff8afc640a:	48 c1 ea 21          	shr    $0x21,%rdx
ffffffff8afc640e:	8d 14 52             	lea    (%rdx,%rdx,2),%edx
ffffffff8afc6411:	29 d0                	sub    %edx,%eax
ffffffff8afc6413:	88 45 e4             	mov    %al,-0x1c(%rbp)
ffffffff8afc6416:	c1 e0 05             	shl    $0x5,%eax
ffffffff8afc6419:	48 8b 56 08          	mov    0x8(%rsi),%rdx
ffffffff8afc641d:	48 3b 54 08 30       	cmp    0x30(%rax,%rcx,1),%rdx
ffffffff8afc6422:	73 56                	jae    ffffffff8afc647a <frame_candidate_606380+0xfa>
ffffffff8afc6424:	48 8d 44 08 30       	lea    0x30(%rax,%rcx,1),%rax
ffffffff8afc6429:	48 8d 3d 18 b4 0c 03 	lea    0x30cb418(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6430:	31 f6                	xor    %esi,%esi
ffffffff8afc6432:	31 d2                	xor    %edx,%edx
ffffffff8afc6434:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6436:	8b 40 08             	mov    0x8(%rax),%eax
ffffffff8afc6439:	89 45 e0             	mov    %eax,-0x20(%rbp)
ffffffff8afc643c:	e8 5f 0b ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6441:	48 8d 7d d8          	lea    -0x28(%rbp),%rdi
ffffffff8afc6445:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8afc644a:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc644d:	e8 8e a7 38 00       	call   ffffffff8b350be0 <frame_candidate_606b10+0x38a0d0>
ffffffff8afc6452:	89 c1                	mov    %eax,%ecx
ffffffff8afc6454:	c1 f8 1f             	sar    $0x1f,%eax
ffffffff8afc6457:	21 c8                	and    %ecx,%eax
ffffffff8afc6459:	e9 60 ff ff ff       	jmp    ffffffff8afc63be <frame_candidate_606380+0x3e>
ffffffff8afc645e:	48 8d 3d e3 b3 0c 03 	lea    0x30cb3e3(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6465:	31 f6                	xor    %esi,%esi
ffffffff8afc6467:	31 d2                	xor    %edx,%edx
ffffffff8afc6469:	31 c9                	xor    %ecx,%ecx
ffffffff8afc646b:	e8 30 0b ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6470:	b8 04 00 72 8a       	mov    $0x8a720004,%eax
ffffffff8afc6475:	e9 44 ff ff ff       	jmp    ffffffff8afc63be <frame_candidate_606380+0x3e>
ffffffff8afc647a:	48 8d 3d c7 b3 0c 03 	lea    0x30cb3c7(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6481:	31 f6                	xor    %esi,%esi
ffffffff8afc6483:	31 d2                	xor    %edx,%edx
ffffffff8afc6485:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6487:	e8 14 0b ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc648c:	b8 06 10 72 8a       	mov    $0x8a721006,%eax
ffffffff8afc6491:	e9 28 ff ff ff       	jmp    ffffffff8afc63be <frame_candidate_606380+0x3e>
ffffffff8afc6496:	e8 15 72 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
ffffffff8afc649b:	0f 0b                	ud2
ffffffff8afc649d:	90                   	nop
ffffffff8afc649e:	90                   	nop
ffffffff8afc649f:	90                   	nop

ffffffff8afc64a0 <frame_candidate_6064a0>:
ffffffff8afc64a0:	55                   	push   %rbp
ffffffff8afc64a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc64a4:	41 56                	push   %r14
ffffffff8afc64a6:	53                   	push   %rbx
ffffffff8afc64a7:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8afc64ab:	4c 8d 35 5e 5e 31 03 	lea    0x3315e5e(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc64b2:	48 8d 7d e0          	lea    -0x20(%rbp),%rdi
ffffffff8afc64b6:	48 89 f3             	mov    %rsi,%rbx
ffffffff8afc64b9:	49 8b 06             	mov    (%r14),%rax
ffffffff8afc64bc:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8afc64c0:	e8 3b 56 e9 ff       	call   ffffffff8ae5bb00 <handler_626_body-0x1691f0>
ffffffff8afc64c5:	89 c1                	mov    %eax,%ecx
ffffffff8afc64c7:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8afc64cc:	85 c9                	test   %ecx,%ecx
ffffffff8afc64ce:	75 2a                	jne    ffffffff8afc64fa <frame_candidate_6064a0+0x5a>
ffffffff8afc64d0:	66 83 7b 38 ff       	cmpw   $0xffff,0x38(%rbx)
ffffffff8afc64d5:	75 23                	jne    ffffffff8afc64fa <frame_candidate_6064a0+0x5a>
ffffffff8afc64d7:	48 8d 05 82 3b be 01 	lea    0x1be3b82(%rip),%rax        # ffffffff8cbaa060 <frame_candidate_606b10+0x1be3550>
ffffffff8afc64de:	48 89 de             	mov    %rbx,%rsi
ffffffff8afc64e1:	31 d2                	xor    %edx,%edx
ffffffff8afc64e3:	48 89 43 68          	mov    %rax,0x68(%rbx)
ffffffff8afc64e7:	48 8b 7d e0          	mov    -0x20(%rbp),%rdi
ffffffff8afc64eb:	48 89 7b 70          	mov    %rdi,0x70(%rbx)
ffffffff8afc64ef:	48 83 c7 10          	add    $0x10,%rdi
ffffffff8afc64f3:	e8 c8 da d0 ff       	call   ffffffff8acd3fc0 <handler_626_body-0x2f0d30>
ffffffff8afc64f8:	31 c0                	xor    %eax,%eax
ffffffff8afc64fa:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8afc64fd:	48 3b 4d e8          	cmp    -0x18(%rbp),%rcx
ffffffff8afc6501:	75 09                	jne    ffffffff8afc650c <frame_candidate_6064a0+0x6c>
ffffffff8afc6503:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8afc6507:	5b                   	pop    %rbx
ffffffff8afc6508:	41 5e                	pop    %r14
ffffffff8afc650a:	5d                   	pop    %rbp
ffffffff8afc650b:	c3                   	ret
ffffffff8afc650c:	e8 9f 71 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
ffffffff8afc6511:	0f 0b                	ud2
ffffffff8afc6513:	90                   	nop
ffffffff8afc6514:	90                   	nop
ffffffff8afc6515:	90                   	nop
ffffffff8afc6516:	90                   	nop
ffffffff8afc6517:	90                   	nop
ffffffff8afc6518:	90                   	nop
ffffffff8afc6519:	90                   	nop
ffffffff8afc651a:	90                   	nop
ffffffff8afc651b:	90                   	nop
ffffffff8afc651c:	90                   	nop
ffffffff8afc651d:	90                   	nop
ffffffff8afc651e:	90                   	nop
ffffffff8afc651f:	90                   	nop

ffffffff8afc6520 <frame_candidate_606520>:
ffffffff8afc6520:	55                   	push   %rbp
ffffffff8afc6521:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc6524:	53                   	push   %rbx
ffffffff8afc6525:	50                   	push   %rax
ffffffff8afc6526:	48 89 fb             	mov    %rdi,%rbx
ffffffff8afc6529:	e8 a2 d9 ca ff       	call   ffffffff8ac73ed0 <handler_626_body-0x350e20>
ffffffff8afc652e:	48 85 c0             	test   %rax,%rax
ffffffff8afc6531:	74 5f                	je     ffffffff8afc6592 <frame_candidate_606520+0x72>
ffffffff8afc6533:	48 89 c1             	mov    %rax,%rcx
ffffffff8afc6536:	b8 06 00 00 00       	mov    $0x6,%eax
ffffffff8afc653b:	83 79 38 00          	cmpl   $0x0,0x38(%rcx)
ffffffff8afc653f:	75 69                	jne    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc6541:	66 81 39 4c 05       	cmpw   $0x54c,(%rcx)
ffffffff8afc6546:	75 62                	jne    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc6548:	66 81 79 02 de 0c    	cmpw   $0xcde,0x2(%rcx)
ffffffff8afc654e:	75 5a                	jne    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc6550:	80 79 09 ff          	cmpb   $0xff,0x9(%rcx)
ffffffff8afc6554:	75 54                	jne    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc6556:	80 79 0a 07          	cmpb   $0x7,0xa(%rcx)
ffffffff8afc655a:	75 4e                	jne    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc655c:	48 8b 49 30          	mov    0x30(%rcx),%rcx
ffffffff8afc6560:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8afc6563:	80 79 03 00          	cmpb   $0x0,0x3(%rcx)
ffffffff8afc6567:	75 41                	jne    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc6569:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc656c:	e8 6f d6 ca ff       	call   ffffffff8ac73be0 <handler_626_body-0x351110>
ffffffff8afc6571:	85 c0                	test   %eax,%eax
ffffffff8afc6573:	7e 3c                	jle    ffffffff8afc65b1 <frame_candidate_606520+0x91>
ffffffff8afc6575:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6578:	e8 63 d6 ca ff       	call   ffffffff8ac73be0 <handler_626_body-0x351110>
ffffffff8afc657d:	89 c2                	mov    %eax,%edx
ffffffff8afc657f:	48 8d 35 d1 6f d5 00 	lea    0xd56fd1(%rip),%rsi        # ffffffff8bd1d557 <frame_candidate_606b10+0xd56a47>
ffffffff8afc6586:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6589:	31 c0                	xor    %eax,%eax
ffffffff8afc658b:	e8 e0 d6 ca ff       	call   ffffffff8ac73c70 <handler_626_body-0x351080>
ffffffff8afc6590:	eb 13                	jmp    ffffffff8afc65a5 <frame_candidate_606520+0x85>
ffffffff8afc6592:	48 8d 3d cb 42 d7 00 	lea    0xd742cb(%rip),%rdi        # ffffffff8bd3a864 <frame_candidate_606b10+0xd73d54>
ffffffff8afc6599:	be bc 00 00 00       	mov    $0xbc,%esi
ffffffff8afc659e:	31 c0                	xor    %eax,%eax
ffffffff8afc65a0:	e8 6b 6e c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc65a5:	b8 06 00 00 00       	mov    $0x6,%eax
ffffffff8afc65aa:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8afc65ae:	5b                   	pop    %rbx
ffffffff8afc65af:	5d                   	pop    %rbp
ffffffff8afc65b0:	c3                   	ret
ffffffff8afc65b1:	b8 ec ff ff ff       	mov    $0xffffffec,%eax
ffffffff8afc65b6:	eb f2                	jmp    ffffffff8afc65aa <frame_candidate_606520+0x8a>
ffffffff8afc65b8:	90                   	nop
ffffffff8afc65b9:	90                   	nop
ffffffff8afc65ba:	90                   	nop
ffffffff8afc65bb:	90                   	nop
ffffffff8afc65bc:	90                   	nop
ffffffff8afc65bd:	90                   	nop
ffffffff8afc65be:	90                   	nop
ffffffff8afc65bf:	90                   	nop

ffffffff8afc65c0 <frame_candidate_6065c0>:
ffffffff8afc65c0:	55                   	push   %rbp
ffffffff8afc65c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc65c4:	41 57                	push   %r15
ffffffff8afc65c6:	41 56                	push   %r14
ffffffff8afc65c8:	41 55                	push   %r13
ffffffff8afc65ca:	41 54                	push   %r12
ffffffff8afc65cc:	53                   	push   %rbx
ffffffff8afc65cd:	48 83 ec 68          	sub    $0x68,%rsp
ffffffff8afc65d1:	4c 8d 2d 38 5d 31 03 	lea    0x3315d38(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc65d8:	48 89 fb             	mov    %rdi,%rbx
ffffffff8afc65db:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8afc65df:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8afc65e3:	e8 e8 d8 ca ff       	call   ffffffff8ac73ed0 <handler_626_body-0x350e20>
ffffffff8afc65e8:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc65eb:	49 89 c7             	mov    %rax,%r15
ffffffff8afc65ee:	e8 1d c5 ca ff       	call   ffffffff8ac72b10 <handler_626_body-0x3521e0>
ffffffff8afc65f3:	49 89 c6             	mov    %rax,%r14
ffffffff8afc65f6:	4d 85 ff             	test   %r15,%r15
ffffffff8afc65f9:	0f 95 c0             	setne  %al
ffffffff8afc65fc:	4d 85 f6             	test   %r14,%r14
ffffffff8afc65ff:	0f 95 c1             	setne  %cl
ffffffff8afc6602:	84 c8                	test   %cl,%al
ffffffff8afc6604:	0f 84 2f 01 00 00    	je     ffffffff8afc6739 <frame_candidate_6065c0+0x179>
ffffffff8afc660a:	be 68 00 00 00       	mov    $0x68,%esi
ffffffff8afc660f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc6612:	e8 d9 29 c5 ff       	call   ffffffff8ac18ff0 <handler_626_body-0x3abd00>
ffffffff8afc6617:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc661a:	e8 21 73 5e 00       	call   ffffffff8b5ad940 <frame_candidate_606b10+0x5e6e30>
ffffffff8afc661f:	41 0f b7 07          	movzwl (%r15),%eax
ffffffff8afc6623:	66 41 89 46 08       	mov    %ax,0x8(%r14)
ffffffff8afc6628:	41 0f b7 47 02       	movzwl 0x2(%r15),%eax
ffffffff8afc662d:	66 41 89 46 0a       	mov    %ax,0xa(%r14)
ffffffff8afc6632:	41 0f b7 47 04       	movzwl 0x4(%r15),%eax
ffffffff8afc6637:	66 41 89 46 0c       	mov    %ax,0xc(%r14)
ffffffff8afc663c:	41 0f b6 47 0d       	movzbl 0xd(%r15),%eax
ffffffff8afc6641:	41 88 46 0e          	mov    %al,0xe(%r14)
ffffffff8afc6645:	49 8b 47 28          	mov    0x28(%r15),%rax
ffffffff8afc6649:	0f b6 80 06 07 00 00 	movzbl 0x706(%rax),%eax
ffffffff8afc6650:	41 88 46 0f          	mov    %al,0xf(%r14)
ffffffff8afc6654:	49 8b 7f 28          	mov    0x28(%r15),%rdi
ffffffff8afc6658:	e8 d3 b2 63 00       	call   ffffffff8b601930 <frame_candidate_606b10+0x63ae20>
ffffffff8afc665d:	41 88 46 10          	mov    %al,0x10(%r14)
ffffffff8afc6661:	4c 89 bd 78 ff ff ff 	mov    %r15,-0x88(%rbp)
ffffffff8afc6668:	49 8b 47 28          	mov    0x28(%r15),%rax
ffffffff8afc666c:	48 8b 80 48 07 00 00 	mov    0x748(%rax),%rax
ffffffff8afc6673:	49 89 46 18          	mov    %rax,0x18(%r14)
ffffffff8afc6677:	49 8b 47 28          	mov    0x28(%r15),%rax
ffffffff8afc667b:	48 8b 80 50 07 00 00 	mov    0x750(%rax),%rax
ffffffff8afc6682:	49 89 46 20          	mov    %rax,0x20(%r14)
ffffffff8afc6686:	49 8b 7f 28          	mov    0x28(%r15),%rdi
ffffffff8afc668a:	49 89 7e 38          	mov    %rdi,0x38(%r14)
ffffffff8afc668e:	e8 1d b1 63 00       	call   ffffffff8b6017b0 <frame_candidate_606b10+0x63aca0>
ffffffff8afc6693:	49 89 c4             	mov    %rax,%r12
ffffffff8afc6696:	48 89 c7             	mov    %rax,%rdi
ffffffff8afc6699:	41 c7 46 28 00 00 00 	movl   $0x0,0x28(%r14)
ffffffff8afc66a0:	00 
ffffffff8afc66a1:	41 c6 46 34 00       	movb   $0x0,0x34(%r14)
ffffffff8afc66a6:	31 f6                	xor    %esi,%esi
ffffffff8afc66a8:	41 c6 46 36 00       	movb   $0x0,0x36(%r14)
ffffffff8afc66ad:	eb 07                	jmp    ffffffff8afc66b6 <frame_candidate_6065c0+0xf6>
ffffffff8afc66af:	90                   	nop
ffffffff8afc66b0:	4c 89 e7             	mov    %r12,%rdi
ffffffff8afc66b3:	48 89 c6             	mov    %rax,%rsi
ffffffff8afc66b6:	e8 f5 85 f7 ff       	call   ffffffff8af3ecb0 <handler_626_body-0x86040>
ffffffff8afc66bb:	48 85 c0             	test   %rax,%rax
ffffffff8afc66be:	0f 84 9b 00 00 00    	je     ffffffff8afc675f <frame_candidate_6065c0+0x19f>
ffffffff8afc66c4:	80 78 01 04          	cmpb   $0x4,0x1(%rax)
ffffffff8afc66c8:	75 e6                	jne    ffffffff8afc66b0 <frame_candidate_6065c0+0xf0>
ffffffff8afc66ca:	80 78 05 ff          	cmpb   $0xff,0x5(%rax)
ffffffff8afc66ce:	75 e0                	jne    ffffffff8afc66b0 <frame_candidate_6065c0+0xf0>
ffffffff8afc66d0:	80 78 06 07          	cmpb   $0x7,0x6(%rax)
ffffffff8afc66d4:	75 da                	jne    ffffffff8afc66b0 <frame_candidate_6065c0+0xf0>
ffffffff8afc66d6:	80 78 04 00          	cmpb   $0x0,0x4(%rax)
ffffffff8afc66da:	74 d4                	je     ffffffff8afc66b0 <frame_candidate_6065c0+0xf0>
ffffffff8afc66dc:	48 8d 3d 65 b1 0c 03 	lea    0x30cb165(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc66e3:	49 89 df             	mov    %rbx,%r15
ffffffff8afc66e6:	4c 89 eb             	mov    %r13,%rbx
ffffffff8afc66e9:	41 c6 46 34 09       	movb   $0x9,0x34(%r14)
ffffffff8afc66ee:	31 f6                	xor    %esi,%esi
ffffffff8afc66f0:	31 d2                	xor    %edx,%edx
ffffffff8afc66f2:	31 c9                	xor    %ecx,%ecx
ffffffff8afc66f4:	49 89 c5             	mov    %rax,%r13
ffffffff8afc66f7:	e8 04 03 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc66fc:	48 8d 3d 45 b1 0c 03 	lea    0x30cb145(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6703:	4c 89 35 46 b1 0c 03 	mov    %r14,0x30cb146(%rip)        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc670a:	31 f6                	xor    %esi,%esi
ffffffff8afc670c:	31 d2                	xor    %edx,%edx
ffffffff8afc670e:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6710:	e8 8b 08 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6715:	4c 89 e8             	mov    %r13,%rax
ffffffff8afc6718:	49 89 dd             	mov    %rbx,%r13
ffffffff8afc671b:	4c 89 fb             	mov    %r15,%rbx
ffffffff8afc671e:	0f b6 48 02          	movzbl 0x2(%rax),%ecx
ffffffff8afc6722:	41 88 4e 35          	mov    %cl,0x35(%r14)
ffffffff8afc6726:	0f b6 48 03          	movzbl 0x3(%rax),%ecx
ffffffff8afc672a:	41 38 4e 36          	cmp    %cl,0x36(%r14)
ffffffff8afc672e:	73 80                	jae    ffffffff8afc66b0 <frame_candidate_6065c0+0xf0>
ffffffff8afc6730:	41 88 4e 36          	mov    %cl,0x36(%r14)
ffffffff8afc6734:	e9 77 ff ff ff       	jmp    ffffffff8afc66b0 <frame_candidate_6065c0+0xf0>
ffffffff8afc6739:	48 8d 3d 24 41 d7 00 	lea    0xd74124(%rip),%rdi        # ffffffff8bd3a864 <frame_candidate_606b10+0xd73d54>
ffffffff8afc6740:	be 42 01 00 00       	mov    $0x142,%esi
ffffffff8afc6745:	31 c0                	xor    %eax,%eax
ffffffff8afc6747:	e8 c4 6c c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc674c:	48 8d 3d e2 8b c6 00 	lea    0xc68be2(%rip),%rdi        # ffffffff8bc2f335 <frame_candidate_606b10+0xc68825>
ffffffff8afc6753:	31 c0                	xor    %eax,%eax
ffffffff8afc6755:	e8 b6 6c c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc675a:	e9 20 01 00 00       	jmp    ffffffff8afc687f <frame_candidate_6065c0+0x2bf>
ffffffff8afc675f:	41 80 7e 34 00       	cmpb   $0x0,0x34(%r14)
ffffffff8afc6764:	0f 84 97 00 00 00    	je     ffffffff8afc6801 <frame_candidate_6065c0+0x241>
ffffffff8afc676a:	49 8b 7e 38          	mov    0x38(%r14),%rdi
ffffffff8afc676e:	41 0f b6 76 35       	movzbl 0x35(%r14),%esi
ffffffff8afc6773:	41 0f b6 56 36       	movzbl 0x36(%r14),%edx
ffffffff8afc6778:	e8 a3 84 63 00       	call   ffffffff8b5fec20 <frame_candidate_606b10+0x638110>
ffffffff8afc677d:	85 c0                	test   %eax,%eax
ffffffff8afc677f:	0f 84 1e 01 00 00    	je     ffffffff8afc68a3 <frame_candidate_6065c0+0x2e3>
ffffffff8afc6785:	89 c7                	mov    %eax,%edi
ffffffff8afc6787:	e8 14 51 38 00       	call   ffffffff8b34b8a0 <frame_candidate_606b10+0x384d90>
ffffffff8afc678c:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc678f:	48 8d 3d bd ae d2 00 	lea    0xd2aebd(%rip),%rdi        # ffffffff8bcf1653 <frame_candidate_606b10+0xd2ab43>
ffffffff8afc6796:	be 13 01 00 00       	mov    $0x113,%esi
ffffffff8afc679b:	31 c0                	xor    %eax,%eax
ffffffff8afc679d:	e8 6e 6c c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc67a2:	41 83 7e 28 00       	cmpl   $0x0,0x28(%r14)
ffffffff8afc67a7:	74 72                	je     ffffffff8afc681b <frame_candidate_6065c0+0x25b>
ffffffff8afc67a9:	49 8b 7e 38          	mov    0x38(%r14),%rdi
ffffffff8afc67ad:	49 8b 4e 48          	mov    0x48(%r14),%rcx
ffffffff8afc67b1:	4c 89 f6             	mov    %r14,%rsi
ffffffff8afc67b4:	48 8d 05 75 b0 0c 03 	lea    0x30cb075(%rip),%rax        # ffffffff8e091830 <frame_candidate_606b10+0x30cad20>
ffffffff8afc67bb:	4c 89 f2             	mov    %r14,%rdx
ffffffff8afc67be:	41 b8 01 00 00 00    	mov    $0x1,%r8d
ffffffff8afc67c4:	4d 89 f1             	mov    %r14,%r9
ffffffff8afc67c7:	48 83 c6 35          	add    $0x35,%rsi
ffffffff8afc67cb:	48 89 04 24          	mov    %rax,(%rsp)
ffffffff8afc67cf:	e8 7c 87 46 00       	call   ffffffff8b42ef50 <frame_candidate_606b10+0x468440>
ffffffff8afc67d4:	85 c0                	test   %eax,%eax
ffffffff8afc67d6:	0f 84 b6 01 00 00    	je     ffffffff8afc6992 <frame_candidate_6065c0+0x3d2>
ffffffff8afc67dc:	89 c7                	mov    %eax,%edi
ffffffff8afc67de:	41 89 c6             	mov    %eax,%r14d
ffffffff8afc67e1:	e8 ba 50 38 00       	call   ffffffff8b34b8a0 <frame_candidate_606b10+0x384d90>
ffffffff8afc67e6:	48 89 c2             	mov    %rax,%rdx
ffffffff8afc67e9:	48 8d 3d 77 d7 cc 00 	lea    0xccd777(%rip),%rdi        # ffffffff8bc93f67 <frame_candidate_606b10+0xccd457>
ffffffff8afc67f0:	be 67 01 00 00       	mov    $0x167,%esi
ffffffff8afc67f5:	44 89 f1             	mov    %r14d,%ecx
ffffffff8afc67f8:	31 c0                	xor    %eax,%eax
ffffffff8afc67fa:	e8 11 6c c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc67ff:	eb 2f                	jmp    ffffffff8afc6830 <frame_candidate_6065c0+0x270>
ffffffff8afc6801:	48 8d 3d a1 23 d0 00 	lea    0xd023a1(%rip),%rdi        # ffffffff8bcc8ba9 <frame_candidate_606b10+0xd02099>
ffffffff8afc6808:	be 0b 01 00 00       	mov    $0x10b,%esi
ffffffff8afc680d:	31 c0                	xor    %eax,%eax
ffffffff8afc680f:	e8 fc 6b c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc6814:	41 83 7e 28 00       	cmpl   $0x0,0x28(%r14)
ffffffff8afc6819:	75 8e                	jne    ffffffff8afc67a9 <frame_candidate_6065c0+0x1e9>
ffffffff8afc681b:	48 8d 3d 91 f8 d3 00 	lea    0xd3f891(%rip),%rdi        # ffffffff8bd060b3 <frame_candidate_606b10+0xd3f5a3>
ffffffff8afc6822:	be 5e 01 00 00       	mov    $0x15e,%esi
ffffffff8afc6827:	31 d2                	xor    %edx,%edx
ffffffff8afc6829:	31 c0                	xor    %eax,%eax
ffffffff8afc682b:	e8 e0 6b c5 ff       	call   ffffffff8ac1d410 <handler_626_body-0x3a78e0>
ffffffff8afc6830:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6833:	e8 d8 c2 ca ff       	call   ffffffff8ac72b10 <handler_626_body-0x3521e0>
ffffffff8afc6838:	4c 8d 35 09 b0 0c 03 	lea    0x30cb009(%rip),%r14        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc683f:	48 89 c3             	mov    %rax,%rbx
ffffffff8afc6842:	31 f6                	xor    %esi,%esi
ffffffff8afc6844:	31 d2                	xor    %edx,%edx
ffffffff8afc6846:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6848:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc684b:	e8 b0 01 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc6850:	31 ff                	xor    %edi,%edi
ffffffff8afc6852:	31 f6                	xor    %esi,%esi
ffffffff8afc6854:	e8 e7 f3 ff ff       	call   ffffffff8afc5c40 <frame_candidate_605c40>
ffffffff8afc6859:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc685c:	48 c7 05 e9 af 0c 03 	movq   $0x0,0x30cafe9(%rip)        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc6863:	00 00 00 00 
ffffffff8afc6867:	31 f6                	xor    %esi,%esi
ffffffff8afc6869:	31 d2                	xor    %edx,%edx
ffffffff8afc686b:	31 c9                	xor    %ecx,%ecx
ffffffff8afc686d:	e8 2e 07 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6872:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6875:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8afc687a:	e8 51 93 46 00       	call   ffffffff8b42fbd0 <frame_candidate_606b10+0x4690c0>
ffffffff8afc687f:	bb 06 00 00 00       	mov    $0x6,%ebx
ffffffff8afc6884:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8afc6888:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8afc688c:	0f 85 09 02 00 00    	jne    ffffffff8afc6a9b <frame_candidate_6065c0+0x4db>
ffffffff8afc6892:	89 d8                	mov    %ebx,%eax
ffffffff8afc6894:	48 83 c4 68          	add    $0x68,%rsp
ffffffff8afc6898:	5b                   	pop    %rbx
ffffffff8afc6899:	41 5c                	pop    %r12
ffffffff8afc689b:	41 5d                	pop    %r13
ffffffff8afc689d:	41 5e                	pop    %r14
ffffffff8afc689f:	41 5f                	pop    %r15
ffffffff8afc68a1:	5d                   	pop    %rbp
ffffffff8afc68a2:	c3                   	ret
ffffffff8afc68a3:	48 8b 8d 78 ff ff ff 	mov    -0x88(%rbp),%rcx
ffffffff8afc68aa:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8afc68b1:	00 
ffffffff8afc68b2:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8afc68b9:	00 
ffffffff8afc68ba:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8afc68c1:	00 
ffffffff8afc68c2:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
ffffffff8afc68c9:	00 
ffffffff8afc68ca:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
ffffffff8afc68d1:	00 
ffffffff8afc68d2:	48 c7 45 a8 00 00 00 	movq   $0x0,-0x58(%rbp)
ffffffff8afc68d9:	00 
ffffffff8afc68da:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8afc68e1:	00 
ffffffff8afc68e2:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8afc68e9:	00 
ffffffff8afc68ea:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8afc68f1:	00 
ffffffff8afc68f2:	48 c7 45 80 00 00 00 	movq   $0x0,-0x80(%rbp)
ffffffff8afc68f9:	00 
ffffffff8afc68fa:	66 c7 45 a0 02 ff    	movw   $0xff02,-0x60(%rbp)
ffffffff8afc6900:	c6 45 a2 80          	movb   $0x80,-0x5e(%rbp)
ffffffff8afc6904:	66 c7 45 c8 02 ff    	movw   $0xff02,-0x38(%rbp)
ffffffff8afc690a:	48 8d 55 80          	lea    -0x80(%rbp),%rdx
ffffffff8afc690e:	48 8b 41 30          	mov    0x30(%rcx),%rax
ffffffff8afc6912:	48 8b 00             	mov    (%rax),%rax
ffffffff8afc6915:	0f b6 40 02          	movzbl 0x2(%rax),%eax
ffffffff8afc6919:	41 88 46 35          	mov    %al,0x35(%r14)
ffffffff8afc691d:	48 8b 41 30          	mov    0x30(%rcx),%rax
ffffffff8afc6921:	48 8b 00             	mov    (%rax),%rax
ffffffff8afc6924:	0f b6 40 03          	movzbl 0x3(%rax),%eax
ffffffff8afc6928:	41 88 46 36          	mov    %al,0x36(%r14)
ffffffff8afc692c:	48 8b 41 30          	mov    0x30(%rcx),%rax
ffffffff8afc6930:	48 8b 79 28          	mov    0x28(%rcx),%rdi
ffffffff8afc6934:	48 8b 00             	mov    (%rax),%rax
ffffffff8afc6937:	0f b6 70 02          	movzbl 0x2(%rax),%esi
ffffffff8afc693b:	e8 30 72 63 00       	call   ffffffff8b5fdb70 <frame_candidate_606b10+0x637060>
ffffffff8afc6940:	48 85 c0             	test   %rax,%rax
ffffffff8afc6943:	0f 84 b1 00 00 00    	je     ffffffff8afc69fa <frame_candidate_6065c0+0x43a>
ffffffff8afc6949:	48 8b 88 40 01 00 00 	mov    0x140(%rax),%rcx
ffffffff8afc6950:	0f b6 49 02          	movzbl 0x2(%rcx),%ecx
ffffffff8afc6954:	41 88 4e 2c          	mov    %cl,0x2c(%r14)
ffffffff8afc6958:	48 8b 88 40 01 00 00 	mov    0x140(%rax),%rcx
ffffffff8afc695f:	0f b6 49 03          	movzbl 0x3(%rcx),%ecx
ffffffff8afc6963:	41 88 4e 2d          	mov    %cl,0x2d(%r14)
ffffffff8afc6967:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6969:	48 8b 80 40 01 00 00 	mov    0x140(%rax),%rax
ffffffff8afc6970:	0f b7 40 04          	movzwl 0x4(%rax),%eax
ffffffff8afc6974:	66 41 89 46 2e       	mov    %ax,0x2e(%r14)
ffffffff8afc6979:	41 8b 46 28          	mov    0x28(%r14),%eax
ffffffff8afc697d:	3a 4d a2             	cmp    -0x5e(%rbp),%cl
ffffffff8afc6980:	71 7d                	jno    ffffffff8afc69ff <frame_candidate_6065c0+0x43f>
ffffffff8afc6982:	48 8d 0d 47 ae 87 00 	lea    0x87ae47(%rip),%rcx        # ffffffff8b8417d0 <frame_candidate_606b10+0x87acc0>
ffffffff8afc6989:	83 c8 01             	or     $0x1,%eax
ffffffff8afc698c:	49 89 4e 48          	mov    %rcx,0x48(%r14)
ffffffff8afc6990:	eb 70                	jmp    ffffffff8afc6a02 <frame_candidate_6065c0+0x442>
ffffffff8afc6992:	48 8d 3d af ae 0c 03 	lea    0x30caeaf(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6999:	48 c7 05 b4 ae 0c 03 	movq   $0x0,0x30caeb4(%rip)        # ffffffff8e091858 <frame_candidate_606b10+0x30cad48>
ffffffff8afc69a0:	00 00 00 00 
ffffffff8afc69a4:	31 db                	xor    %ebx,%ebx
ffffffff8afc69a6:	31 f6                	xor    %esi,%esi
ffffffff8afc69a8:	31 d2                	xor    %edx,%edx
ffffffff8afc69aa:	31 c9                	xor    %ecx,%ecx
ffffffff8afc69ac:	e8 4f 00 ec ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc69b1:	80 3d 18 af 0c 03 01 	cmpb   $0x1,0x30caf18(%rip)        # ffffffff8e0918d0 <frame_candidate_606b10+0x30cadc0>
ffffffff8afc69b8:	4c 8b 35 91 ae 0c 03 	mov    0x30cae91(%rip),%r14        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc69bf:	0f 94 c0             	sete   %al
ffffffff8afc69c2:	4d 85 f6             	test   %r14,%r14
ffffffff8afc69c5:	0f 95 c1             	setne  %cl
ffffffff8afc69c8:	20 c1                	and    %al,%cl
ffffffff8afc69ca:	80 f9 01             	cmp    $0x1,%cl
ffffffff8afc69cd:	75 14                	jne    ffffffff8afc69e3 <frame_candidate_6065c0+0x423>
ffffffff8afc69cf:	41 80 7e 37 00       	cmpb   $0x0,0x37(%r14)
ffffffff8afc69d4:	75 0d                	jne    ffffffff8afc69e3 <frame_candidate_6065c0+0x423>
ffffffff8afc69d6:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8afc69d9:	e8 f2 9e 46 00       	call   ffffffff8b4308d0 <frame_candidate_606b10+0x469dc0>
ffffffff8afc69de:	41 c6 46 37 01       	movb   $0x1,0x37(%r14)
ffffffff8afc69e3:	48 8d 3d 5e ae 0c 03 	lea    0x30cae5e(%rip),%rdi        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc69ea:	31 f6                	xor    %esi,%esi
ffffffff8afc69ec:	31 d2                	xor    %edx,%edx
ffffffff8afc69ee:	31 c9                	xor    %ecx,%ecx
ffffffff8afc69f0:	e8 ab 05 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc69f5:	e9 8a fe ff ff       	jmp    ffffffff8afc6884 <frame_candidate_6065c0+0x2c4>
ffffffff8afc69fa:	45 31 e4             	xor    %r12d,%r12d
ffffffff8afc69fd:	eb 0d                	jmp    ffffffff8afc6a0c <frame_candidate_6065c0+0x44c>
ffffffff8afc69ff:	83 c8 02             	or     $0x2,%eax
ffffffff8afc6a02:	41 bc 01 00 00 00    	mov    $0x1,%r12d
ffffffff8afc6a08:	41 89 46 28          	mov    %eax,0x28(%r14)
ffffffff8afc6a0c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
ffffffff8afc6a13:	48 8d 55 a8          	lea    -0x58(%rbp),%rdx
ffffffff8afc6a17:	48 8b 78 28          	mov    0x28(%rax),%rdi
ffffffff8afc6a1b:	48 8b 40 30          	mov    0x30(%rax),%rax
ffffffff8afc6a1f:	48 8b 00             	mov    (%rax),%rax
ffffffff8afc6a22:	0f b6 70 02          	movzbl 0x2(%rax),%esi
ffffffff8afc6a26:	e8 45 71 63 00       	call   ffffffff8b5fdb70 <frame_candidate_606b10+0x637060>
ffffffff8afc6a2b:	48 85 c0             	test   %rax,%rax
ffffffff8afc6a2e:	74 53                	je     ffffffff8afc6a83 <frame_candidate_6065c0+0x4c3>
ffffffff8afc6a30:	48 8b 88 40 01 00 00 	mov    0x140(%rax),%rcx
ffffffff8afc6a37:	0f b6 49 02          	movzbl 0x2(%rcx),%ecx
ffffffff8afc6a3b:	43 88 4c a6 2c       	mov    %cl,0x2c(%r14,%r12,4)
ffffffff8afc6a40:	48 8b 88 40 01 00 00 	mov    0x140(%rax),%rcx
ffffffff8afc6a47:	0f b6 49 03          	movzbl 0x3(%rcx),%ecx
ffffffff8afc6a4b:	43 88 4c a6 2d       	mov    %cl,0x2d(%r14,%r12,4)
ffffffff8afc6a50:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6a52:	48 8b 80 40 01 00 00 	mov    0x140(%rax),%rax
ffffffff8afc6a59:	0f b7 40 04          	movzwl 0x4(%rax),%eax
ffffffff8afc6a5d:	66 43 89 44 a6 2e    	mov    %ax,0x2e(%r14,%r12,4)
ffffffff8afc6a63:	41 8b 46 28          	mov    0x28(%r14),%eax
ffffffff8afc6a67:	3a 4d ca             	cmp    -0x36(%rbp),%cl
ffffffff8afc6a6a:	71 10                	jno    ffffffff8afc6a7c <frame_candidate_6065c0+0x4bc>
ffffffff8afc6a6c:	83 c8 01             	or     $0x1,%eax
ffffffff8afc6a6f:	48 8d 0d 5a ad 87 00 	lea    0x87ad5a(%rip),%rcx        # ffffffff8b8417d0 <frame_candidate_606b10+0x87acc0>
ffffffff8afc6a76:	49 89 4e 48          	mov    %rcx,0x48(%r14)
ffffffff8afc6a7a:	eb 03                	jmp    ffffffff8afc6a7f <frame_candidate_6065c0+0x4bf>
ffffffff8afc6a7c:	83 c8 02             	or     $0x2,%eax
ffffffff8afc6a7f:	41 89 46 28          	mov    %eax,0x28(%r14)
ffffffff8afc6a83:	41 c7 46 14 00 00 00 	movl   $0x0,0x14(%r14)
ffffffff8afc6a8a:	00 
ffffffff8afc6a8b:	41 83 7e 28 00       	cmpl   $0x0,0x28(%r14)
ffffffff8afc6a90:	0f 85 13 fd ff ff    	jne    ffffffff8afc67a9 <frame_candidate_6065c0+0x1e9>
ffffffff8afc6a96:	e9 80 fd ff ff       	jmp    ffffffff8afc681b <frame_candidate_6065c0+0x25b>
ffffffff8afc6a9b:	e8 10 6c 0f 00       	call   ffffffff8b0bd6b0 <frame_candidate_606b10+0xf6ba0>
ffffffff8afc6aa0:	0f 0b                	ud2
ffffffff8afc6aa2:	90                   	nop
ffffffff8afc6aa3:	90                   	nop
ffffffff8afc6aa4:	90                   	nop
ffffffff8afc6aa5:	90                   	nop
ffffffff8afc6aa6:	90                   	nop
ffffffff8afc6aa7:	90                   	nop
ffffffff8afc6aa8:	90                   	nop
ffffffff8afc6aa9:	90                   	nop
ffffffff8afc6aaa:	90                   	nop
ffffffff8afc6aab:	90                   	nop
ffffffff8afc6aac:	90                   	nop
ffffffff8afc6aad:	90                   	nop
ffffffff8afc6aae:	90                   	nop
ffffffff8afc6aaf:	90                   	nop

ffffffff8afc6ab0 <frame_candidate_606ab0>:
ffffffff8afc6ab0:	55                   	push   %rbp
ffffffff8afc6ab1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc6ab4:	41 56                	push   %r14
ffffffff8afc6ab6:	53                   	push   %rbx
ffffffff8afc6ab7:	e8 54 c0 ca ff       	call   ffffffff8ac72b10 <handler_626_body-0x3521e0>
ffffffff8afc6abc:	4c 8d 35 85 ad 0c 03 	lea    0x30cad85(%rip),%r14        # ffffffff8e091848 <frame_candidate_606b10+0x30cad38>
ffffffff8afc6ac3:	48 89 c3             	mov    %rax,%rbx
ffffffff8afc6ac6:	31 f6                	xor    %esi,%esi
ffffffff8afc6ac8:	31 d2                	xor    %edx,%edx
ffffffff8afc6aca:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6acc:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc6acf:	e8 2c ff eb ff       	call   ffffffff8ae86a00 <handler_626_body-0x13e2f0>
ffffffff8afc6ad4:	31 ff                	xor    %edi,%edi
ffffffff8afc6ad6:	31 f6                	xor    %esi,%esi
ffffffff8afc6ad8:	e8 63 f1 ff ff       	call   ffffffff8afc5c40 <frame_candidate_605c40>
ffffffff8afc6add:	4c 89 f7             	mov    %r14,%rdi
ffffffff8afc6ae0:	48 c7 05 65 ad 0c 03 	movq   $0x0,0x30cad65(%rip)        # ffffffff8e091850 <frame_candidate_606b10+0x30cad40>
ffffffff8afc6ae7:	00 00 00 00 
ffffffff8afc6aeb:	31 f6                	xor    %esi,%esi
ffffffff8afc6aed:	31 d2                	xor    %edx,%edx
ffffffff8afc6aef:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6af1:	e8 aa 04 ec ff       	call   ffffffff8ae86fa0 <handler_626_body-0x13dd50>
ffffffff8afc6af6:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6af9:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8afc6afe:	e8 cd 90 46 00       	call   ffffffff8b42fbd0 <frame_candidate_606b10+0x4690c0>
ffffffff8afc6b03:	31 c0                	xor    %eax,%eax
ffffffff8afc6b05:	5b                   	pop    %rbx
ffffffff8afc6b06:	41 5e                	pop    %r14
ffffffff8afc6b08:	5d                   	pop    %rbp
ffffffff8afc6b09:	c3                   	ret
ffffffff8afc6b0a:	90                   	nop
ffffffff8afc6b0b:	90                   	nop
ffffffff8afc6b0c:	90                   	nop
ffffffff8afc6b0d:	90                   	nop
ffffffff8afc6b0e:	90                   	nop
ffffffff8afc6b0f:	90                   	nop

ffffffff8afc6b10 <frame_candidate_606b10>:
ffffffff8afc6b10:	55                   	push   %rbp
ffffffff8afc6b11:	48 89 e5             	mov    %rsp,%rbp
ffffffff8afc6b14:	41 57                	push   %r15
ffffffff8afc6b16:	41 56                	push   %r14
ffffffff8afc6b18:	41 55                	push   %r13
ffffffff8afc6b1a:	41 54                	push   %r12
ffffffff8afc6b1c:	53                   	push   %rbx
ffffffff8afc6b1d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8afc6b21:	4c 8d 25 e8 57 31 03 	lea    0x33157e8(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_606b10+0x3315800>
ffffffff8afc6b28:	41 89 f7             	mov    %esi,%r15d
ffffffff8afc6b2b:	48 89 fb             	mov    %rdi,%rbx
ffffffff8afc6b2e:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8afc6b32:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8afc6b36:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
ffffffff8afc6b3d:	e8 1e ae 46 00       	call   ffffffff8b431960 <frame_candidate_606b10+0x46ae50>
ffffffff8afc6b42:	48 85 c0             	test   %rax,%rax
ffffffff8afc6b45:	0f 84 ca 01 00 00    	je     ffffffff8afc6d15 <frame_candidate_606b10+0x205>
ffffffff8afc6b4b:	80 3d 7e ad 0c 03 00 	cmpb   $0x0,0x30cad7e(%rip)        # ffffffff8e0918d0 <frame_candidate_606b10+0x30cadc0>
ffffffff8afc6b52:	49 89 c6             	mov    %rax,%r14
ffffffff8afc6b55:	0f 84 68 01 00 00    	je     ffffffff8afc6cc3 <frame_candidate_606b10+0x1b3>
ffffffff8afc6b5b:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6b5e:	e8 4d aa 46 00       	call   ffffffff8b4315b0 <frame_candidate_606b10+0x46aaa0>
ffffffff8afc6b63:	84 c0                	test   %al,%al
ffffffff8afc6b65:	0f 84 81 01 00 00    	je     ffffffff8afc6cec <frame_candidate_606b10+0x1dc>
ffffffff8afc6b6b:	0f b6 c0             	movzbl %al,%eax
ffffffff8afc6b6e:	83 f8 01             	cmp    $0x1,%eax
ffffffff8afc6b71:	0f 85 60 01 00 00    	jne    ffffffff8afc6cd7 <frame_candidate_606b10+0x1c7>
ffffffff8afc6b77:	48 8d 75 cc          	lea    -0x34(%rbp),%rsi
ffffffff8afc6b7b:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6b7e:	31 d2                	xor    %edx,%edx
ffffffff8afc6b80:	31 c9                	xor    %ecx,%ecx
ffffffff8afc6b82:	45 31 c0             	xor    %r8d,%r8d
ffffffff8afc6b85:	e8 36 a1 46 00       	call   ffffffff8b430cc0 <frame_candidate_606b10+0x46a1b0>
ffffffff8afc6b8a:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6b8d:	31 f6                	xor    %esi,%esi
ffffffff8afc6b8f:	e8 3c a0 46 00       	call   ffffffff8b430bd0 <frame_candidate_606b10+0x46a0c0>
ffffffff8afc6b94:	8b 4d cc             	mov    -0x34(%rbp),%ecx
ffffffff8afc6b97:	be 00 40 00 00       	mov    $0x4000,%esi
ffffffff8afc6b9c:	81 f9 00 40 00 00    	cmp    $0x4000,%ecx
ffffffff8afc6ba2:	7f 0a                	jg     ffffffff8afc6bae <frame_candidate_606b10+0x9e>
ffffffff8afc6ba4:	89 ce                	mov    %ecx,%esi
ffffffff8afc6ba6:	85 c9                	test   %ecx,%ecx
ffffffff8afc6ba8:	0f 8e 3e 01 00 00    	jle    ffffffff8afc6cec <frame_candidate_606b10+0x1dc>
ffffffff8afc6bae:	44 8b 3d a3 ac 0c 03 	mov    0x30caca3(%rip),%r15d        # ffffffff8e091858 <frame_candidate_606b10+0x30cad48>
ffffffff8afc6bb5:	b9 ab aa aa aa       	mov    $0xaaaaaaab,%ecx
ffffffff8afc6bba:	48 8d 15 6f ac 0c 03 	lea    0x30cac6f(%rip),%rdx        # ffffffff8e091830 <frame_candidate_606b10+0x30cad20>
ffffffff8afc6bc1:	48 89 c7             	mov    %rax,%rdi
ffffffff8afc6bc4:	49 0f af cf          	imul   %r15,%rcx
ffffffff8afc6bc8:	48 c1 e9 21          	shr    $0x21,%rcx
ffffffff8afc6bcc:	8d 0c 49             	lea    (%rcx,%rcx,2),%ecx
ffffffff8afc6bcf:	41 29 cf             	sub    %ecx,%r15d
ffffffff8afc6bd2:	b9 00 c0 0c 00       	mov    $0xcc000,%ecx
ffffffff8afc6bd7:	41 c1 e7 05          	shl    $0x5,%r15d
ffffffff8afc6bdb:	4d 8b 6c 17 40       	mov    0x40(%r15,%rdx,1),%r13
ffffffff8afc6be0:	41 8b 56 5c          	mov    0x5c(%r14),%edx
ffffffff8afc6be4:	29 d1                	sub    %edx,%ecx
ffffffff8afc6be6:	39 ce                	cmp    %ecx,%esi
ffffffff8afc6be8:	0f 42 ce             	cmovb  %esi,%ecx
ffffffff8afc6beb:	4c 01 ea             	add    %r13,%rdx
ffffffff8afc6bee:	31 f6                	xor    %esi,%esi
ffffffff8afc6bf0:	89 4d cc             	mov    %ecx,-0x34(%rbp)
ffffffff8afc6bf3:	e8 c8 04 e4 ff       	call   ffffffff8ae070c0 <handler_626_body-0x1bdc30>
ffffffff8afc6bf8:	41 fe 46 60          	incb   0x60(%r14)
ffffffff8afc6bfc:	8b 4d cc             	mov    -0x34(%rbp),%ecx
ffffffff8afc6bff:	41 8b 46 5c          	mov    0x5c(%r14),%eax
ffffffff8afc6c03:	01 c8                	add    %ecx,%eax
ffffffff8afc6c05:	41 89 46 5c          	mov    %eax,0x5c(%r14)
ffffffff8afc6c09:	81 f9 ff 3f 00 00    	cmp    $0x3fff,%ecx
ffffffff8afc6c0f:	0f 8f d7 00 00 00    	jg     ffffffff8afc6cec <frame_candidate_606b10+0x1dc>
ffffffff8afc6c15:	83 f8 30             	cmp    $0x30,%eax
ffffffff8afc6c18:	0f 82 c1 00 00 00    	jb     ffffffff8afc6cdf <frame_candidate_606b10+0x1cf>
ffffffff8afc6c1e:	41 80 7d 00 52       	cmpb   $0x52,0x0(%r13)
ffffffff8afc6c23:	0f 85 b6 00 00 00    	jne    ffffffff8afc6cdf <frame_candidate_606b10+0x1cf>
ffffffff8afc6c29:	41 80 7d 01 50       	cmpb   $0x50,0x1(%r13)
ffffffff8afc6c2e:	0f 85 ab 00 00 00    	jne    ffffffff8afc6cdf <frame_candidate_606b10+0x1cf>
ffffffff8afc6c34:	41 39 45 04          	cmp    %eax,0x4(%r13)
ffffffff8afc6c38:	0f 85 a1 00 00 00    	jne    ffffffff8afc6cdf <frame_candidate_606b10+0x1cf>
ffffffff8afc6c3e:	48 8d 0d eb ab 0c 03 	lea    0x30cabeb(%rip),%rcx        # ffffffff8e091830 <frame_candidate_606b10+0x30cad20>
ffffffff8afc6c45:	4d 8d 7c 0f 30       	lea    0x30(%r15,%rcx,1),%r15
ffffffff8afc6c4a:	41 89 47 08          	mov    %eax,0x8(%r15)
ffffffff8afc6c4e:	8b 05 04 ac 0c 03    	mov    0x30cac04(%rip),%eax        # ffffffff8e091858 <frame_candidate_606b10+0x30cad48>
ffffffff8afc6c54:	89 05 02 ac 0c 03    	mov    %eax,0x30cac02(%rip)        # ffffffff8e09185c <frame_candidate_606b10+0x30cad4c>
ffffffff8afc6c5a:	e8 e1 9d 38 00       	call   ffffffff8b350a40 <frame_candidate_606b10+0x389f30>
ffffffff8afc6c5f:	49 89 07             	mov    %rax,(%r15)
ffffffff8afc6c62:	41 c6 46 60 00       	movb   $0x0,0x60(%r14)
ffffffff8afc6c67:	41 c7 46 5c 00 00 00 	movl   $0x0,0x5c(%r14)
ffffffff8afc6c6e:	00 
ffffffff8afc6c6f:	ff 05 e3 ab 0c 03    	incl   0x30cabe3(%rip)        # ffffffff8e091858 <frame_candidate_606b10+0x30cad48>
ffffffff8afc6c75:	48 8d 3d 74 ac 0c 03 	lea    0x30cac74(%rip),%rdi        # ffffffff8e0918f0 <frame_candidate_606b10+0x30cade0>
ffffffff8afc6c7c:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc6c81:	31 f6                	xor    %esi,%esi
ffffffff8afc6c83:	e8 c8 d0 d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc6c88:	48 8d 3d b1 ac 0c 03 	lea    0x30cacb1(%rip),%rdi        # ffffffff8e091940 <frame_candidate_606b10+0x30cae30>
ffffffff8afc6c8f:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc6c94:	31 f6                	xor    %esi,%esi
ffffffff8afc6c96:	e8 b5 d0 d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc6c9b:	48 8d 3d ee ac 0c 03 	lea    0x30cacee(%rip),%rdi        # ffffffff8e091990 <frame_candidate_606b10+0x30cae80>
ffffffff8afc6ca2:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc6ca7:	31 f6                	xor    %esi,%esi
ffffffff8afc6ca9:	e8 a2 d0 d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc6cae:	48 8d 3d 2b ad 0c 03 	lea    0x30cad2b(%rip),%rdi        # ffffffff8e0919e0 <frame_candidate_606b10+0x30caed0>
ffffffff8afc6cb5:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8afc6cba:	31 f6                	xor    %esi,%esi
ffffffff8afc6cbc:	e8 8f d0 d0 ff       	call   ffffffff8acd3d50 <handler_626_body-0x2f0fa0>
ffffffff8afc6cc1:	eb 29                	jmp    ffffffff8afc6cec <frame_candidate_606b10+0x1dc>
ffffffff8afc6cc3:	41 c6 46 37 00       	movb   $0x0,0x37(%r14)
ffffffff8afc6cc8:	41 c6 46 60 00       	movb   $0x0,0x60(%r14)
ffffffff8afc6ccd:	41 c7 46 5c 00 00 00 	movl   $0x0,0x5c(%r14)
ffffffff8afc6cd4:	00 
ffffffff8afc6cd5:	eb 3e                	jmp    ffffffff8afc6d15 <frame_candidate_606b10+0x205>
ffffffff8afc6cd7:	41 83 ff 05          	cmp    $0x5,%r15d
ffffffff8afc6cdb:	75 0f                	jne    ffffffff8afc6cec <frame_candidate_606b10+0x1dc>
ffffffff8afc6cdd:	eb 36                	jmp    ffffffff8afc6d15 <frame_candidate_606b10+0x205>
ffffffff8afc6cdf:	41 c6 46 60 00       	movb   $0x0,0x60(%r14)
ffffffff8afc6ce4:	41 c7 46 5c 00 00 00 	movl   $0x0,0x5c(%r14)
ffffffff8afc6ceb:	00 
ffffffff8afc6cec:	48 89 df             	mov    %rbx,%rdi
ffffffff8afc6cef:	e8                   	.byte 0xe8
