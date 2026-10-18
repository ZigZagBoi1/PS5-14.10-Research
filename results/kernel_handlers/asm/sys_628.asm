; REA 6.7.0 full disassembly of handler_628.bin
; SHA256 7a5560ba6ed0ec89ab0267d48f943119da03965fe93b700c2da28f576b973bcd; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25ec8, kernel RVA 0x265ec8.
; REA inspect_with_objdump Evidence: ev_cdda99ada0411d6d19bdc98860ed35e4a27b38f93605db2c264fb148ee56f807
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 628; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_628.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25ec8 <handler_628_entry>:
ffffffff8ac25ec8:	e9 73 76 85 00       	jmp    ffffffff8b47d540 <neighbor_trampoline_266ec0+0x856680>
ffffffff8ac25ecd:	cc                   	int3
ffffffff8ac25ece:	cc                   	int3
ffffffff8ac25ecf:	cc                   	int3

ffffffff8ac25ed0 <neighbor_trampoline_265ed0>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266ec0+0x6b5780>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266ec0+0x6b5db0>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266ec0+0x1d1f70>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266ec0+0x1d21b0>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266ec0+0x1d2290>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266ec0+0x1d24e0>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266ec0+0x457610>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266ec0+0x856a70>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266ec0+0x457700>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266ec0+0x457940>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266ec0+0x829f50>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266ec0+0x23bf20>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266ec0+0x856c10>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266ec0+0x7d07a0>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266ec0+0x857300>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266ec0+0x8578f0>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266ec0+0x791330>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266ec0+0x982650>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266ec0+0x740e50>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266ec0+0x7426a0>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266ec0+0x742f50>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266ec0+0x743080>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266ec0+0x694580>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266ec0+0x23c2e0>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266ec0+0x8579f0>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266ec0+0x744330>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266ec0+0x854ac0>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266ec0+0x492420>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266ec0+0x1cdee0>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266ec0+0x1cdef0>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266ec0+0x1cdf00>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266ec0+0x1d0ed0>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266ec0+0x1d13c0>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266ec0+0x87f7d0>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266ec0+0x87f6c0>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266ec0+0x1e2210>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_628_entry-0x1bf108>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266ec0+0x1e3bb0>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266ec0+0x74f250>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_628_entry-0x1be858>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_628_entry-0x1be678>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_628_entry-0x1be648>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266ec0+0x1eb180>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266ec0+0x1ede00>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266ec0+0x1f0960>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266ec0+0x2070b0>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266ec0+0x2071c0>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266ec0+0x20bad0>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266ec0+0x20c4f0>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266ec0+0x20c9f0>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266ec0+0x20d390>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266ec0+0x20def0>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266ec0+0x216130>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_628_entry-0x47ed8>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266ec0+0x229440>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266ec0+0x229ef0>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266ec0+0x2310f0>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266ec0+0x231120>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266ec0+0x231770>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266ec0+0x231780>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266ec0+0x690d00>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266ec0+0x68f940>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266ec0+0x690560>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266ec0+0x6930c0>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266ec0+0x378490>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266ec0+0x378960>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266ec0+0x7cde20>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266ec0+0x3815e0>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266ec0+0x691330>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266ec0+0x692550>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266ec0+0x695530>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266ec0+0x68fdd0>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266ec0+0xa4ab50>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266ec0+0x8514e0>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266ec0+0x8514f0>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266ec0+0x693300>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266ec0+0x690c80>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266ec0+0x239aa0>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266ec0+0x4c28c0>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266ec0+0x4c28d0>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266ec0+0x4c28e0>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266ec0+0x4546d0>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266ec0+0x851ee0>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266ec0+0x6932b0>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266ec0+0x918200>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266ec0+0x918240>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266ec0+0x692e30>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266ec0+0x693880>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266ec0+0x2ebcb0>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266ec0+0x2ebd30>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266ec0+0x2ebd90>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266ec0+0x2ebdc0>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266ec0+0x2ebdf0>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266ec0+0x2ebe20>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266ec0+0x917940>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266ec0+0x917d20>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266ec0+0x9180b0>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266ec0+0x99fe70>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266ec0+0x52b7d0>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266ec0+0x381c60>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266ec0+0x2ebe50>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266ec0+0x9182a0>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266ec0+0x377390>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266ec0+0x7edb70>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266ec0+0x7edb80>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266ec0+0x7edb90>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266ec0+0x7edba0>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266ec0+0x7edbc0>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266ec0+0x7edbd0>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266ec0+0x692860>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266ec0+0x7edbf0>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266ec0+0x68f620>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266ec0+0x68f030>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266ec0+0x7edb60>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266ec0+0x7edbb0>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266ec0+0x7edbe0>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266ec0+0x47e610>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266ec0+0x9185f0>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266ec0+0x5d67a0>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266ec0+0x5d6900>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266ec0+0x5d6bf0>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266ec0+0x5d6fc0>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266ec0+0x692dc0>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266ec0+0x693250>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266ec0+0x6922f0>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266ec0+0x693630>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266ec0+0x6911d0>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266ec0+0x694cc0>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266ec0+0x690cc0>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266ec0+0x6909d0>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266ec0+0x6949e0>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266ec0+0x691650>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266ec0+0x691940>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266ec0+0x2341c0>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266ec0+0x2341d0>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266ec0+0x2f8b90>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266ec0+0x9cd9b0>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266ec0+0x575e30>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266ec0+0x575e40>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266ec0+0x575e50>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266ec0+0x575e60>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266ec0+0x575e70>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266ec0+0x33fdd0>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266ec0+0x340440>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266ec0+0x340750>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266ec0+0x340a40>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266ec0+0xa35970>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266ec0+0x341040>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266ec0+0x3411b0>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266ec0+0x9815c0>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266ec0+0x2341e0>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266ec0+0x234200>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266ec0+0x234210>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266ec0+0x234220>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266ec0+0x234230>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266ec0+0x2c9860>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266ec0+0x2ca7b0>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266ec0+0x692830>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266ec0+0x2ca370>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266ec0+0x59bf30>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266ec0+0x918280>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266ec0+0x87c720>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266ec0+0x287f60>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266ec0+0x693c50>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266ec0+0x693f70>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266ec0+0x762360>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266ec0+0x762240>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266ec0+0x3db450>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266ec0+0x3db960>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266ec0+0x3dc820>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266ec0+0x3dca10>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266ec0+0x3dcda0>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266ec0+0x7913d0>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266ec0+0x794cb0>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266ec0+0x7de3c0>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266ec0+0xa20de0>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266ec0+0x798140>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266ec0+0x7998c0>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266ec0+0x799920>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266ec0+0x857970>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266ec0+0x796070>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266ec0+0x38a100>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266ec0+0x690530>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266ec0+0x290390>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266ec0+0x796c10>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266ec0+0x796ef0>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266ec0+0x797050>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266ec0+0x3dd610>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266ec0+0x3ea110>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266ec0+0x797b70>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266ec0+0x290a80>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266ec0+0x851c20>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266ec0+0x8547a0>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266ec0+0x7973a0>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266ec0+0x797620>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266ec0+0x797770>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266ec0+0x531470>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266ec0+0x856140>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_628_entry-0x169638>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266ec0+0x2381d0>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266ec0+0x238340>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266ec0+0x2596d0>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266ec0+0x2596f0>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_628_entry-0x1bca98>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266ec0+0x263490>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266ec0+0x263b80>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_628_entry-0x1bb9b8>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266ec0+0x26e310>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266ec0+0x5aa2f0>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_628_entry-0x24b038>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266ec0+0x289170>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266ec0+0x294d10>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266ec0+0x2a6010>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266ec0+0x2a6020>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266ec0+0x2a6070>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266ec0+0x2a60b0>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266ec0+0x2a60f0>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266ec0+0x2a6120>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266ec0+0x2b7610>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266ec0+0x2b80a0>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266ec0+0x2b8140>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266ec0+0x2b81f0>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266ec0+0x2b8420>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266ec0+0x2b87b0>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266ec0+0x2b9020>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266ec0+0x2cf540>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266ec0+0x2ddde0>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266ec0+0x2dfa30>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_628_entry-0x1b4898>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_628_entry-0x1b3f18>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266ec0+0x2f5080>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266ec0+0x2f5170>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266ec0+0x2f5190>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266ec0+0x307340>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266ec0+0x3185e0>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266ec0+0x72d720>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266ec0+0x31ea90>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266ec0+0x332960>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266ec0+0x333520>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266ec0+0x333670>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266ec0+0x333840>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266ec0+0x333910>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266ec0+0x333b90>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266ec0+0x333ca0>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266ec0+0x333da0>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266ec0+0x375010>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266ec0+0x384860>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266ec0+0x385170>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266ec0+0x385c10>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266ec0+0x386580>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266ec0+0x386c70>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_628_entry-0x117c48>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266ec0+0x38a9f0>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266ec0+0x38bc70>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266ec0+0x396200>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266ec0+0x3997c0>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266ec0+0x39a080>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266ec0+0x87f5e0>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266ec0+0x3c6be0>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266ec0+0x3c9410>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266ec0+0x3ce050>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266ec0+0x3d8660>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266ec0+0x3f0af0>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266ec0+0xa40450>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266ec0+0x3fbfb0>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266ec0+0x3fbfc0>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266ec0+0x411f50>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266ec0+0x411fa0>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266ec0+0x412000>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266ec0+0x4120a0>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266ec0+0x4122d0>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266ec0+0x4124a0>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266ec0+0x4127c0>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_628_entry-0x232338>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_628_entry-0x232228>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_628_entry-0x2321a8>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_628_entry-0x228f58>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_628_entry-0x228de8>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_628_entry-0x228868>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_628_entry-0x227dc8>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_628_entry-0x227d68>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_628_entry-0x227d08>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_628_entry-0x226e58>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_628_entry-0x226df8>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_628_entry-0x226a18>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_628_entry-0x2269b8>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_628_entry-0x226958>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_628_entry-0x226318>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_628_entry-0x225f08>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_628_entry-0x225568>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_628_entry-0x225378>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_628_entry-0x225298>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_628_entry-0x224898>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_628_entry-0x224778>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_628_entry-0x224698>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_628_entry-0x224608>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_628_entry-0x223e68>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_628_entry-0x2239f8>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_628_entry-0x223928>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_628_entry-0x2238c8>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266ec0+0x429170>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266ec0+0x42fe00>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266ec0+0x431710>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266ec0+0x43b190>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266ec0+0x43b3f0>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266ec0+0x447780>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266ec0+0x447930>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_628_entry-0xe4b18>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266ec0+0x4580e0>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_628_entry-0xdde88>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266ec0+0x469c40>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266ec0+0x46a240>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266ec0+0x46a3a0>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266ec0+0x46a520>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266ec0+0x46a660>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266ec0+0x46a780>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266ec0+0x46a860>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266ec0+0x4757a0>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266ec0+0x4757d0>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266ec0+0x4757e0>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266ec0+0x479a60>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266ec0+0x47a580>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266ec0+0x47a590>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_628_entry-0xdc458>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_628_entry-0xd5428>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266ec0+0x49bab0>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266ec0+0x49bea0>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266ec0+0x49f2b0>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266ec0+0x49f330>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266ec0+0x4a9040>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266ec0+0x4a90f0>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266ec0+0x4a9300>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266ec0+0x4a9460>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266ec0+0x4abcf0>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266ec0+0x4af4a0>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266ec0+0x4c8ab0>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266ec0+0x4c8ad0>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266ec0+0x4c8b60>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_628_entry-0x1f098>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266ec0+0x4fd930>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266ec0+0x50c850>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266ec0+0x50ea90>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266ec0+0x532fd0>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266ec0+0x54c330>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266ec0+0x57b4e0>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266ec0+0x581520>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266ec0+0x5815c0>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266ec0+0x9d42f0>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266ec0+0x9d5820>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266ec0+0x9d57d0>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266ec0+0x9d5870>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266ec0+0x59b360>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266ec0+0x59b630>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266ec0+0x5a56b0>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266ec0+0x5c4440>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266ec0+0x6ba020>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266ec0+0x6b9cd0>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266ec0+0x5c9950>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266ec0+0x5ca040>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266ec0+0x5ce3f0>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266ec0+0x5ce400>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266ec0+0x5ce410>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266ec0+0x5ce430>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266ec0+0x5ce580>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266ec0+0x5ce590>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266ec0+0x5ce5d0>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266ec0+0x5cec10>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266ec0+0x5e99b0>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266ec0+0x609430>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266ec0+0x609710>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266ec0+0x60bc30>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266ec0+0x60c940>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_628_entry-0x202488>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_628_entry-0x1ffb58>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_628_entry-0x17f938>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_628_entry-0x17f928>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_628_entry-0x17f768>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_628_entry-0x17f658>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_628_entry-0x17df38>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_628_entry-0x17bf28>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_628_entry-0x17b858>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_628_entry-0x17b768>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_628_entry-0x17ae28>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_628_entry-0x17ad38>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_628_entry-0x178ec8>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_628_entry-0x178db8>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266ec0+0x6239e0>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266ec0+0x635f30>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_628_entry-0x177378>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266ec0+0x664390>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266ec0+0x6644d0>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266ec0+0x66c0a0>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266ec0+0x66c0d0>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266ec0+0x671370>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266ec0+0x671f20>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266ec0+0x6728f0>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266ec0+0x672a50>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266ec0+0x673600>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266ec0+0x6736b0>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266ec0+0x6736f0>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266ec0+0x69ddc0>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266ec0+0x69dfa0>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266ec0+0x6b6540>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266ec0+0x6b65e0>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266ec0+0x81b310>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266ec0+0x8db260>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266ec0+0x6fe070>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266ec0+0x70f090>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266ec0+0x70f340>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266ec0+0x725a90>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266ec0+0x725d70>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266ec0+0x726070>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266ec0+0x726820>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266ec0+0x727710>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266ec0+0x727840>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266ec0+0x72b2b0>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266ec0+0x72b380>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_628_entry-0x170ac8>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266ec0+0x73b460>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266ec0+0x73e860>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266ec0+0x745ae0>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266ec0+0x745b60>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_628_entry-0xa7888>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266ec0+0x757e60>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266ec0+0x75f190>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266ec0+0x75f210>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266ec0+0x75f3c0>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266ec0+0x75f450>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266ec0+0x75f5d0>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266ec0+0x75f6f0>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266ec0+0x75f9d0>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266ec0+0x762480>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266ec0+0x7624a0>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266ec0+0x7624b0>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266ec0+0x7624c0>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266ec0+0x773ef0>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266ec0+0x7740e0>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266ec0+0x7759a0>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266ec0+0x775d80>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266ec0+0x775fc0>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266ec0+0x776640>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266ec0+0xa43e10>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266ec0+0x776910>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266ec0+0x776ad0>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266ec0+0x776ce0>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266ec0+0x776d40>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266ec0+0x776f90>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266ec0+0x776ff0>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266ec0+0x777130>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266ec0+0x7771b0>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266ec0+0x777230>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266ec0+0x779cd0>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266ec0+0x779e10>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266ec0+0x779eb0>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266ec0+0x77a030>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266ec0+0x77a190>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266ec0+0x77a5d0>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266ec0+0x79f720>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_628_entry-0x164b88>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266ec0+0x7cc070>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266ec0+0x7cc800>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266ec0+0x7d1dd0>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266ec0+0x803c40>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266ec0+0x803cf0>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266ec0+0x827d50>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266ec0+0x827f40>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266ec0+0x84a8f0>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266ec0+0x8598f0>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266ec0+0x85bc30>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_628_entry-0x14b778>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266ec0+0x87a3e0>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266ec0+0x87c540>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266ec0+0x87c670>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266ec0+0x87f500>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266ec0+0x8a1020>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266ec0+0x8a12d0>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266ec0+0x8a1670>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266ec0+0x8a1950>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266ec0+0x8a27e0>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266ec0+0x8a4630>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_628_entry-0x76dd8>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_628_entry-0x75e68>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_628_entry-0x14a518>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266ec0+0x8d4270>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266ec0+0x8e0b80>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266ec0+0x8e9500>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266ec0+0x8ea050>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266ec0+0x8ea0f0>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266ec0+0x8ea1f0>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266ec0+0x8ea2d0>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266ec0+0x8ea3d0>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266ec0+0x8ea410>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266ec0+0x8ea460>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266ec0+0x8ef9e0>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_628_entry-0x1cbde8>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266ec0+0x903fb0>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266ec0+0x904cd0>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266ec0+0x906ac0>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266ec0+0x906be0>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266ec0+0x9072c0>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266ec0+0x90a460>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266ec0+0x90a4b0>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266ec0+0x90a500>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266ec0+0x90a550>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266ec0+0x90aaa0>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266ec0+0x90ab10>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266ec0+0x90ab80>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266ec0+0x90abf0>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266ec0+0x90b760>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

ffffffff8ac26eb8 <neighbor_trampoline_266eb8>:
ffffffff8ac26eb8:	e9 a3 b9 90 00       	jmp    ffffffff8b532860 <neighbor_trampoline_266ec0+0x90b9a0>
ffffffff8ac26ebd:	cc                   	int3
ffffffff8ac26ebe:	cc                   	int3
ffffffff8ac26ebf:	cc                   	int3

ffffffff8ac26ec0 <neighbor_trampoline_266ec0>:
ffffffff8ac26ec0:	e9 0b 23 91 00       	jmp    ffffffff8b5391d0 <neighbor_trampoline_266ec0+0x912310>
ffffffff8ac26ec5:	cc                   	int3
ffffffff8ac26ec6:	cc                   	int3
ffffffff8ac26ec7:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8b47d540, handler_body_628; REA Evidence ev_d2f933d50b074c7ff41ebae816c08a9707fb4530b9eb6ae2e680ae0b6a703b59
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8b47d540", "end": "0xffffffff8b47d922"}], "total_bytes": 995, "span_bytes": 995, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_628:
0xffffffff8b47d540: PUSH RBP
0xffffffff8b47d541: MOV RBP, RSP
0xffffffff8b47d544: PUSH R15
0xffffffff8b47d546: PUSH R14
0xffffffff8b47d548: PUSH R13
0xffffffff8b47d54a: PUSH R12
0xffffffff8b47d54c: PUSH RBX
0xffffffff8b47d54d: SUB RSP, 0x48
0xffffffff8b47d551: LEA RAX, [-0x71d23cf0]
0xffffffff8b47d558: MOV R13, RDI
0xffffffff8b47d55b: MOV RAX, qword ptr [RAX]
0xffffffff8b47d55e: MOV qword ptr [RBP + -0x30], RAX
0xffffffff8b47d562: MOV R12, qword ptr [RSI]
0xffffffff8b47d565: MOV qword ptr [RBP + -0x38], R12
0xffffffff8b47d569: MOV RAX, qword ptr [RSI + 0x8]
0xffffffff8b47d56d: MOV ECX, dword ptr [RSI + 0x20]
0xffffffff8b47d570: MOV R15, qword ptr [RSI + 0x28]
0xffffffff8b47d574: MOV qword ptr [RBP + -0x48], RAX
0xffffffff8b47d578: MOV EAX, dword ptr [RSI + 0x10]
0xffffffff8b47d57b: MOV qword ptr [RBP + -0x60], RCX
0xffffffff8b47d57f: MOV qword ptr [RBP + -0x68], RAX
0xffffffff8b47d583: MOV EAX, dword ptr [RSI + 0x18]
0xffffffff8b47d586: MOV R14, qword ptr GS:[0x0]
0xffffffff8b47d58f: MOV RCX, qword ptr [R14 + 0x8]
0xffffffff8b47d593: MOV RDI, qword ptr [RDI + 0x140]
0xffffffff8b47d59a: MOVZX EBX, AL
0xffffffff8b47d59d: CMP dword ptr [RCX + 0x5d4], 0x3000000
0xffffffff8b47d5a7: CMOVNC EBX, EAX
0xffffffff8b47d5aa: CALL 0xffffffff8afc9560
0xffffffff8b47d5af: MOV ECX, 0x1
0xffffffff8b47d5b4: TEST EAX, EAX
0xffffffff8b47d5b6: JZ 0xffffffff8b47d5c1
loc_ffffffff8b47d5b8:
0xffffffff8b47d5b8: LEA R15, [-0x71d23cf0]
0xffffffff8b47d5bf: JMP 0xffffffff8b47d60e
loc_ffffffff8b47d5c1:
0xffffffff8b47d5c1: MOV RDI, qword ptr [R14 + 0x140]
0xffffffff8b47d5c8: MOV dword ptr [RBP + -0x4c], EBX
0xffffffff8b47d5cb: MOV RBX, qword ptr [RBP + -0x68]
0xffffffff8b47d5cf: MOV qword ptr [RBP + -0x58], R15
0xffffffff8b47d5d3: MOV qword ptr [RBP + -0x40], R13
0xffffffff8b47d5d7: CALL 0xffffffff8afc95a0
0xffffffff8b47d5dc: TEST EAX, EAX
0xffffffff8b47d5de: JNZ 0xffffffff8b47d602
loc_ffffffff8b47d5e0:
0xffffffff8b47d5e0: MOV RAX, qword ptr [RBP + -0x40]
0xffffffff8b47d5e4: MOV RDI, qword ptr [RAX + 0x140]
0xffffffff8b47d5eb: CALL 0xffffffff8afc92d0
0xffffffff8b47d5f0: TEST EAX, EAX
0xffffffff8b47d5f2: JZ 0xffffffff8b47d62c
loc_ffffffff8b47d5f4:
0xffffffff8b47d5f4: LEA RDI, [-0x742c93e8]
0xffffffff8b47d5fb: XOR EAX, EAX
0xffffffff8b47d5fd: CALL 0xffffffff8ac1d410
loc_ffffffff8b47d602:
0xffffffff8b47d602: LEA R15, [-0x71d23cf0]
0xffffffff8b47d609: MOV ECX, 0x1
loc_ffffffff8b47d60e:
0xffffffff8b47d60e: MOV RAX, qword ptr [R15]
0xffffffff8b47d611: CMP RAX, qword ptr [RBP + -0x30]
0xffffffff8b47d615: JNZ 0xffffffff8b47d91c
loc_ffffffff8b47d61b:
0xffffffff8b47d61b: MOV EAX, ECX
0xffffffff8b47d61d: ADD RSP, 0x48
0xffffffff8b47d621: POP RBX
0xffffffff8b47d622: POP R12
0xffffffff8b47d624: POP R13
0xffffffff8b47d626: POP R14
0xffffffff8b47d628: POP R15
0xffffffff8b47d62a: POP RBP
0xffffffff8b47d62b: RET
loc_ffffffff8b47d62c:
0xffffffff8b47d62c: MOV RAX, R12
0xffffffff8b47d62f: MOV ECX, 0x16
0xffffffff8b47d634: SHL RAX, 0x32
0xffffffff8b47d638: JNZ 0xffffffff8b47d5b8
loc_ffffffff8b47d63e:
0xffffffff8b47d63e: MOV RSI, qword ptr [RBP + -0x48]
0xffffffff8b47d642: TEST ESI, 0x3fff
0xffffffff8b47d648: SETNZ AL
0xffffffff8b47d64b: CMP RSI, 0x4000
0xffffffff8b47d652: SETC DL
0xffffffff8b47d655: OR DL, AL
0xffffffff8b47d657: JNZ 0xffffffff8b47d5b8
loc_ffffffff8b47d65d:
0xffffffff8b47d65d: MOV R13, RBX
0xffffffff8b47d660: CMP R13D, -0x1
0xffffffff8b47d664: JZ 0xffffffff8b47d698
loc_ffffffff8b47d666:
0xffffffff8b47d666: MOV RAX, qword ptr [RBP + -0x40]
0xffffffff8b47d66a: MOV EDI, R13D
0xffffffff8b47d66d: MOV RSI, qword ptr [RAX + 0x8]
0xffffffff8b47d671: CALL 0xffffffff8ad833e0
0xffffffff8b47d676: MOV EBX, dword ptr [RBP + -0x4c]
0xffffffff8b47d679: TEST EAX, EAX
0xffffffff8b47d67b: JZ 0xffffffff8b47d7b3
loc_ffffffff8b47d681:
0xffffffff8b47d681: MOV RSI, qword ptr [RBP + -0x48]
0xffffffff8b47d685: MOV EAX, EBX
0xffffffff8b47d687: MOV ECX, 0x16
0xffffffff8b47d68c: AND EAX, 0xfffffc0c
0xffffffff8b47d691: JZ 0xffffffff8b47d6a7
loc_ffffffff8b47d693:
0xffffffff8b47d693: JMP 0xffffffff8b47d5b8
loc_ffffffff8b47d698:
0xffffffff8b47d698: MOV EBX, dword ptr [RBP + -0x4c]
0xffffffff8b47d69b: TEST EBX, 0xfffffc0c
0xffffffff8b47d6a1: JNZ 0xffffffff8b47d5b8
loc_ffffffff8b47d6a7:
0xffffffff8b47d6a7: MOV RDI, qword ptr [RBP + -0x60]
0xffffffff8b47d6ab: MOV RDX, qword ptr [RBP + -0x58]
0xffffffff8b47d6af: TEST EDI, 0x9fdf2f
0xffffffff8b47d6b5: SETZ AL
0xffffffff8b47d6b8: SHL RDX, 0x32
0xffffffff8b47d6bc: SETZ DL
0xffffffff8b47d6bf: AND DL, AL
0xffffffff8b47d6c1: CMP DL, 0x1
0xffffffff8b47d6c4: JNZ 0xffffffff8b47d5b8
loc_ffffffff8b47d6ca:
0xffffffff8b47d6ca: TEST DIL, 0x40
0xffffffff8b47d6ce: JZ 0xffffffff8b47d6e8
loc_ffffffff8b47d6d0:
0xffffffff8b47d6d0: CMP RSI, 0x4000
0xffffffff8b47d6d7: JA 0xffffffff8b47d5b8
loc_ffffffff8b47d6dd:
0xffffffff8b47d6dd: MOV EAX, EBX
0xffffffff8b47d6df: AND EAX, 0x3
0xffffffff8b47d6e2: JZ 0xffffffff8b47d5b8
loc_ffffffff8b47d6e8:
0xffffffff8b47d6e8: TEST EDI, 0x200000
0xffffffff8b47d6ee: JZ 0xffffffff8b47d701
loc_ffffffff8b47d6f0:
0xffffffff8b47d6f0: MOV RDI, qword ptr [R14 + 0x8]
0xffffffff8b47d6f4: CALL 0xffffffff8b4e4300
0xffffffff8b47d6f9: TEST EAX, EAX
0xffffffff8b47d6fb: JZ 0xffffffff8b47d7b3
loc_ffffffff8b47d701:
0xffffffff8b47d701: MOV RDI, qword ptr [RBP + -0x40]
0xffffffff8b47d705: MOV R15, 0x7efffffff
0xffffffff8b47d70f: CALL 0xffffffff8b478320
0xffffffff8b47d714: MOV RDX, -0x7f0000000
0xffffffff8b47d71e: LEA RDI, [R15 + 0x10000001]
0xffffffff8b47d725: ADD RDX, RAX
0xffffffff8b47d728: CMP RDX, RDI
0xffffffff8b47d72b: JC 0xffffffff8b47d73f
loc_ffffffff8b47d72d:
0xffffffff8b47d72d: CMP EBX, 0x40
0xffffffff8b47d730: JC 0xffffffff8b47d73f
loc_ffffffff8b47d732:
0xffffffff8b47d732: MOV RCX, qword ptr [R14 + 0x8]
0xffffffff8b47d736: CMP byte ptr [RCX + 0xc81], 0x0
0xffffffff8b47d73d: JZ 0xffffffff8b47d7b3
loc_ffffffff8b47d73f:
0xffffffff8b47d73f: MOV RCX, qword ptr [RBP + -0x40]
0xffffffff8b47d743: MOV R10D, EBX
0xffffffff8b47d746: MOV R11, qword ptr [RBP + -0x60]
0xffffffff8b47d74a: SHR R10D, 0x1
0xffffffff8b47d74d: AND R10D, 0x141
0xffffffff8b47d754: OR R10D, EBX
0xffffffff8b47d757: MOV RCX, qword ptr [RCX + 0x8]
0xffffffff8b47d75b: MOV RSI, qword ptr [RCX + 0x200]
0xffffffff8b47d762: TEST R11B, 0x10
0xffffffff8b47d766: JNZ 0xffffffff8b47d7c4
loc_ffffffff8b47d768:
0xffffffff8b47d768: TEST R12, R12
0xffffffff8b47d76b: JZ 0xffffffff8b47d853
loc_ffffffff8b47d771:
0xffffffff8b47d771: MOV R8, R15
0xffffffff8b47d774: LEA R15, [-0x71d23cf0]
0xffffffff8b47d77b: CMP RDX, RDI
0xffffffff8b47d77e: JC 0xffffffff8b47d7ab
loc_ffffffff8b47d780:
0xffffffff8b47d780: MOV RDX, qword ptr [RBP + -0x48]
0xffffffff8b47d784: MOV R9, 0xff0000000
0xffffffff8b47d78e: LEA RDI, [R9 + 0x1]
0xffffffff8b47d792: ADD RDX, R12
0xffffffff8b47d795: CMP RDX, R8
0xffffffff8b47d798: SETBE DL
0xffffffff8b47d79b: CMP R12, RDI
0xffffffff8b47d79e: SETNC DIL
0xffffffff8b47d7a2: OR DIL, DL
0xffffffff8b47d7a5: JZ 0xffffffff8b47d870
loc_ffffffff8b47d7ab:
0xffffffff8b47d7ab: MOV R9, R12
0xffffffff8b47d7ae: JMP 0xffffffff8b47d874
loc_ffffffff8b47d7b3:
0xffffffff8b47d7b3: LEA R15, [-0x71d23cf0]
0xffffffff8b47d7ba: MOV ECX, 0x16
0xffffffff8b47d7bf: JMP 0xffffffff8b47d60e
loc_ffffffff8b47d7c4:
0xffffffff8b47d7c4: MOV RBX, R15
0xffffffff8b47d7c7: LEA R15, [-0x71d23cf0]
0xffffffff8b47d7ce: TEST R12, R12
0xffffffff8b47d7d1: JZ 0xffffffff8b47d89e
loc_ffffffff8b47d7d7:
0xffffffff8b47d7d7: CMP qword ptr [RSI + 0x20], R12
0xffffffff8b47d7db: MOV R8, R12
0xffffffff8b47d7de: SETA CL
0xffffffff8b47d7e1: ADD R8, qword ptr [RBP + -0x48]
0xffffffff8b47d7e5: SETC R9B
0xffffffff8b47d7e9: OR R9B, CL
0xffffffff8b47d7ec: MOV ECX, 0x16
0xffffffff8b47d7f1: JNZ 0xffffffff8b47d60e
loc_ffffffff8b47d7f7:
0xffffffff8b47d7f7: CMP qword ptr [RSI + 0x28], R8
0xffffffff8b47d7fb: JC 0xffffffff8b47d60e
loc_ffffffff8b47d801:
0xffffffff8b47d801: CMP RDX, RDI
0xffffffff8b47d804: JC 0xffffffff8b47d827
loc_ffffffff8b47d806:
0xffffffff8b47d806: CMP R8, RBX
0xffffffff8b47d809: MOV RDI, R12
0xffffffff8b47d80c: SETA DL
0xffffffff8b47d80f: SHR RDI, 0x1c
0xffffffff8b47d813: CMP RDI, 0xff
0xffffffff8b47d81a: SETC DIL
0xffffffff8b47d81e: TEST DIL, DL
0xffffffff8b47d821: JNZ 0xffffffff8b47d60e
loc_ffffffff8b47d827:
0xffffffff8b47d827: MOV RCX, qword ptr [R14 + 0x8]
0xffffffff8b47d82b: MOV ECX, dword ptr [RCX + 0x5c4]
0xffffffff8b47d831: SUB RSP, 0x8
0xffffffff8b47d835: MOV RBX, qword ptr [RBP + -0x40]
0xffffffff8b47d839: MOV R8, qword ptr [RBP + -0x58]
0xffffffff8b47d83d: LEA RDX, [RBP + -0x38]
0xffffffff8b47d841: MOV R9, R12
0xffffffff8b47d844: MOV RDI, RBX
0xffffffff8b47d847: PUSH 0x0
0xffffffff8b47d849: PUSH RAX
0xffffffff8b47d84a: PUSH R11
0xffffffff8b47d84c: PUSH 0x0
0xffffffff8b47d84e: JMP 0xffffffff8b47d8fa
loc_ffffffff8b47d853:
0xffffffff8b47d853: XOR R8D, R8D
0xffffffff8b47d856: CMP RDX, RDI
0xffffffff8b47d859: LEA R15, [-0x71d23cf0]
0xffffffff8b47d860: SETC R8B
0xffffffff8b47d864: SHL R8D, 0x4
0xffffffff8b47d868: MOV R9, qword ptr [R8 + RSI*0x1 + 0x1f8]
loc_ffffffff8b47d870:
0xffffffff8b47d870: MOV qword ptr [RBP + -0x38], R9
loc_ffffffff8b47d874:
0xffffffff8b47d874: MOV EDX, R11D
0xffffffff8b47d877: AND EDX, 0xff000000
0xffffffff8b47d87d: JZ 0xffffffff8b47d8a8
loc_ffffffff8b47d87f:
0xffffffff8b47d87f: CMP EDX, 0x1000000
0xffffffff8b47d885: JNZ 0xffffffff8b47d8ca
loc_ffffffff8b47d887:
0xffffffff8b47d887: MOV RCX, qword ptr [R14 + 0x8]
0xffffffff8b47d88b: XOR EDX, EDX
0xffffffff8b47d88d: CMP byte ptr [RCX + 0xc81], 0x0
0xffffffff8b47d894: SETNZ DL
0xffffffff8b47d897: LEA R11D, [RDX + RDX*0x1 + 0x1]
0xffffffff8b47d89c: JMP 0xffffffff8b47d8d5
loc_ffffffff8b47d89e:
0xffffffff8b47d89e: MOV ECX, 0x16
0xffffffff8b47d8a3: JMP 0xffffffff8b47d60e
loc_ffffffff8b47d8a8:
0xffffffff8b47d8a8: TEST byte ptr [RSI + 0x244], 0x2
0xffffffff8b47d8af: MOV R11D, 0x1
0xffffffff8b47d8b5: JNZ 0xffffffff8b47d8d5
loc_ffffffff8b47d8b7:
0xffffffff8b47d8b7: XOR R11D, R11D
0xffffffff8b47d8ba: CMP dword ptr [RCX + 0x5d8], 0x1500000
0xffffffff8b47d8c4: ADC R11D, 0x1
0xffffffff8b47d8c8: JMP 0xffffffff8b47d8d5
loc_ffffffff8b47d8ca:
0xffffffff8b47d8ca: SAR R11D, 0x10
0xffffffff8b47d8ce: AND R11D, 0xffffff00
loc_ffffffff8b47d8d5:
0xffffffff8b47d8d5: MOV RCX, qword ptr [R14 + 0x8]
0xffffffff8b47d8d9: MOV ECX, dword ptr [RCX + 0x5c4]
0xffffffff8b47d8df: SUB RSP, 0x8
0xffffffff8b47d8e3: MOV RBX, qword ptr [RBP + -0x40]
0xffffffff8b47d8e7: MOV R8, qword ptr [RBP + -0x58]
0xffffffff8b47d8eb: LEA RDX, [RBP + -0x38]
0xffffffff8b47d8ef: MOV RDI, RBX
0xffffffff8b47d8f2: PUSH 0x0
0xffffffff8b47d8f4: PUSH RAX
0xffffffff8b47d8f5: PUSH qword ptr [RBP + -0x60]
0xffffffff8b47d8f8: PUSH R11
loc_ffffffff8b47d8fa:
0xffffffff8b47d8fa: PUSH R10
0xffffffff8b47d8fc: PUSH R13
0xffffffff8b47d8fe: PUSH qword ptr [RBP + -0x48]
0xffffffff8b47d901: CALL 0xffffffff8ad8b450
0xffffffff8b47d906: ADD RSP, 0x40
0xffffffff8b47d90a: MOV RDX, qword ptr [RBP + -0x38]
0xffffffff8b47d90e: MOV ECX, EAX
0xffffffff8b47d910: MOV qword ptr [RBX + 0x408], RDX
0xffffffff8b47d917: JMP 0xffffffff8b47d60e
loc_ffffffff8b47d91c:
0xffffffff8b47d91c: CALL 0xffffffff8b0bd6b0
0xffffffff8b47d921: UD2
; END FUNCTION handler_body_628

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_091e943f5a16fe5c3024d5c813f2bb7966a1b949460e2eff1069ed263259f0bd
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_628.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8b47d540 <handler_628_body>:
ffffffff8b47d540:	55                   	push   %rbp
ffffffff8b47d541:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47d544:	41 57                	push   %r15
ffffffff8b47d546:	41 56                	push   %r14
ffffffff8b47d548:	41 55                	push   %r13
ffffffff8b47d54a:	41 54                	push   %r12
ffffffff8b47d54c:	53                   	push   %rbx
ffffffff8b47d54d:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8b47d551:	48 8d 05 b8 ed e5 02 	lea    0x2e5edb8(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d558:	49 89 fd             	mov    %rdi,%r13
ffffffff8b47d55b:	48 8b 00             	mov    (%rax),%rax
ffffffff8b47d55e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b47d562:	4c 8b 26             	mov    (%rsi),%r12
ffffffff8b47d565:	4c 89 65 c8          	mov    %r12,-0x38(%rbp)
ffffffff8b47d569:	48 8b 46 08          	mov    0x8(%rsi),%rax
ffffffff8b47d56d:	8b 4e 20             	mov    0x20(%rsi),%ecx
ffffffff8b47d570:	4c 8b 7e 28          	mov    0x28(%rsi),%r15
ffffffff8b47d574:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8b47d578:	8b 46 10             	mov    0x10(%rsi),%eax
ffffffff8b47d57b:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
ffffffff8b47d57f:	48 89 45 98          	mov    %rax,-0x68(%rbp)
ffffffff8b47d583:	8b 46 18             	mov    0x18(%rsi),%eax
ffffffff8b47d586:	65 4c 8b 34 25 00 00 	mov    %gs:0x0,%r14
ffffffff8b47d58d:	00 00 
ffffffff8b47d58f:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b47d593:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b47d59a:	0f b6 d8             	movzbl %al,%ebx
ffffffff8b47d59d:	81 b9 d4 05 00 00 00 	cmpl   $0x3000000,0x5d4(%rcx)
ffffffff8b47d5a4:	00 00 03 
ffffffff8b47d5a7:	0f 43 d8             	cmovae %eax,%ebx
ffffffff8b47d5aa:	e8 b1 bf b4 ff       	call   ffffffff8afc9560 <handler_628_body-0x4b3fe0>
ffffffff8b47d5af:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b47d5b4:	85 c0                	test   %eax,%eax
ffffffff8b47d5b6:	74 09                	je     ffffffff8b47d5c1 <handler_628_body+0x81>
ffffffff8b47d5b8:	4c 8d 3d 51 ed e5 02 	lea    0x2e5ed51(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d5bf:	eb 4d                	jmp    ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d5c1:	49 8b be 40 01 00 00 	mov    0x140(%r14),%rdi
ffffffff8b47d5c8:	89 5d b4             	mov    %ebx,-0x4c(%rbp)
ffffffff8b47d5cb:	48 8b 5d 98          	mov    -0x68(%rbp),%rbx
ffffffff8b47d5cf:	4c 89 7d a8          	mov    %r15,-0x58(%rbp)
ffffffff8b47d5d3:	4c 89 6d c0          	mov    %r13,-0x40(%rbp)
ffffffff8b47d5d7:	e8 c4 bf b4 ff       	call   ffffffff8afc95a0 <handler_628_body-0x4b3fa0>
ffffffff8b47d5dc:	85 c0                	test   %eax,%eax
ffffffff8b47d5de:	75 22                	jne    ffffffff8b47d602 <handler_628_body+0xc2>
ffffffff8b47d5e0:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b47d5e4:	48 8b b8 40 01 00 00 	mov    0x140(%rax),%rdi
ffffffff8b47d5eb:	e8 e0 bc b4 ff       	call   ffffffff8afc92d0 <handler_628_body-0x4b4270>
ffffffff8b47d5f0:	85 c0                	test   %eax,%eax
ffffffff8b47d5f2:	74 38                	je     ffffffff8b47d62c <handler_628_body+0xec>
ffffffff8b47d5f4:	48 8d 3d 1d 96 8b 00 	lea    0x8b961d(%rip),%rdi        # ffffffff8bd36c18 <frame_candidate_abf510+0x8b7708>
ffffffff8b47d5fb:	31 c0                	xor    %eax,%eax
ffffffff8b47d5fd:	e8 0e fe 79 ff       	call   ffffffff8ac1d410 <handler_628_body-0x860130>
ffffffff8b47d602:	4c 8d 3d 07 ed e5 02 	lea    0x2e5ed07(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d609:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b47d60e:	49 8b 07             	mov    (%r15),%rax
ffffffff8b47d611:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b47d615:	0f 85 01 03 00 00    	jne    ffffffff8b47d91c <handler_628_body+0x3dc>
ffffffff8b47d61b:	89 c8                	mov    %ecx,%eax
ffffffff8b47d61d:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8b47d621:	5b                   	pop    %rbx
ffffffff8b47d622:	41 5c                	pop    %r12
ffffffff8b47d624:	41 5d                	pop    %r13
ffffffff8b47d626:	41 5e                	pop    %r14
ffffffff8b47d628:	41 5f                	pop    %r15
ffffffff8b47d62a:	5d                   	pop    %rbp
ffffffff8b47d62b:	c3                   	ret
ffffffff8b47d62c:	4c 89 e0             	mov    %r12,%rax
ffffffff8b47d62f:	b9 16 00 00 00       	mov    $0x16,%ecx
ffffffff8b47d634:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b47d638:	0f 85 7a ff ff ff    	jne    ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d63e:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
ffffffff8b47d642:	f7 c6 ff 3f 00 00    	test   $0x3fff,%esi
ffffffff8b47d648:	0f 95 c0             	setne  %al
ffffffff8b47d64b:	48 81 fe 00 40 00 00 	cmp    $0x4000,%rsi
ffffffff8b47d652:	0f 92 c2             	setb   %dl
ffffffff8b47d655:	08 c2                	or     %al,%dl
ffffffff8b47d657:	0f 85 5b ff ff ff    	jne    ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d65d:	49 89 dd             	mov    %rbx,%r13
ffffffff8b47d660:	41 83 fd ff          	cmp    $0xffffffff,%r13d
ffffffff8b47d664:	74 32                	je     ffffffff8b47d698 <handler_628_body+0x158>
ffffffff8b47d666:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
ffffffff8b47d66a:	44 89 ef             	mov    %r13d,%edi
ffffffff8b47d66d:	48 8b 70 08          	mov    0x8(%rax),%rsi
ffffffff8b47d671:	e8 6a 5d 90 ff       	call   ffffffff8ad833e0 <handler_628_body-0x6fa160>
ffffffff8b47d676:	8b 5d b4             	mov    -0x4c(%rbp),%ebx
ffffffff8b47d679:	85 c0                	test   %eax,%eax
ffffffff8b47d67b:	0f 84 32 01 00 00    	je     ffffffff8b47d7b3 <handler_628_body+0x273>
ffffffff8b47d681:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
ffffffff8b47d685:	89 d8                	mov    %ebx,%eax
ffffffff8b47d687:	b9 16 00 00 00       	mov    $0x16,%ecx
ffffffff8b47d68c:	25 0c fc ff ff       	and    $0xfffffc0c,%eax
ffffffff8b47d691:	74 14                	je     ffffffff8b47d6a7 <handler_628_body+0x167>
ffffffff8b47d693:	e9 20 ff ff ff       	jmp    ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d698:	8b 5d b4             	mov    -0x4c(%rbp),%ebx
ffffffff8b47d69b:	f7 c3 0c fc ff ff    	test   $0xfffffc0c,%ebx
ffffffff8b47d6a1:	0f 85 11 ff ff ff    	jne    ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d6a7:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
ffffffff8b47d6ab:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
ffffffff8b47d6af:	f7 c7 2f df 9f 00    	test   $0x9fdf2f,%edi
ffffffff8b47d6b5:	0f 94 c0             	sete   %al
ffffffff8b47d6b8:	48 c1 e2 32          	shl    $0x32,%rdx
ffffffff8b47d6bc:	0f 94 c2             	sete   %dl
ffffffff8b47d6bf:	20 c2                	and    %al,%dl
ffffffff8b47d6c1:	80 fa 01             	cmp    $0x1,%dl
ffffffff8b47d6c4:	0f 85 ee fe ff ff    	jne    ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d6ca:	40 f6 c7 40          	test   $0x40,%dil
ffffffff8b47d6ce:	74 18                	je     ffffffff8b47d6e8 <handler_628_body+0x1a8>
ffffffff8b47d6d0:	48 81 fe 00 40 00 00 	cmp    $0x4000,%rsi
ffffffff8b47d6d7:	0f 87 db fe ff ff    	ja     ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d6dd:	89 d8                	mov    %ebx,%eax
ffffffff8b47d6df:	83 e0 03             	and    $0x3,%eax
ffffffff8b47d6e2:	0f 84 d0 fe ff ff    	je     ffffffff8b47d5b8 <handler_628_body+0x78>
ffffffff8b47d6e8:	f7 c7 00 00 20 00    	test   $0x200000,%edi
ffffffff8b47d6ee:	74 11                	je     ffffffff8b47d701 <handler_628_body+0x1c1>
ffffffff8b47d6f0:	49 8b 7e 08          	mov    0x8(%r14),%rdi
ffffffff8b47d6f4:	e8 07 6c 06 00       	call   ffffffff8b4e4300 <frame_candidate_abf510+0x64df0>
ffffffff8b47d6f9:	85 c0                	test   %eax,%eax
ffffffff8b47d6fb:	0f 84 b2 00 00 00    	je     ffffffff8b47d7b3 <handler_628_body+0x273>
ffffffff8b47d701:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
ffffffff8b47d705:	49 bf ff ff ff ef 07 	movabs $0x7efffffff,%r15
ffffffff8b47d70c:	00 00 00 
ffffffff8b47d70f:	e8 0c ac ff ff       	call   ffffffff8b478320 <handler_628_body-0x5220>
ffffffff8b47d714:	48 ba 00 00 00 10 f8 	movabs $0xfffffff810000000,%rdx
ffffffff8b47d71b:	ff ff ff 
ffffffff8b47d71e:	49 8d bf 01 00 00 10 	lea    0x10000001(%r15),%rdi
ffffffff8b47d725:	48 01 c2             	add    %rax,%rdx
ffffffff8b47d728:	48 39 fa             	cmp    %rdi,%rdx
ffffffff8b47d72b:	72 12                	jb     ffffffff8b47d73f <handler_628_body+0x1ff>
ffffffff8b47d72d:	83 fb 40             	cmp    $0x40,%ebx
ffffffff8b47d730:	72 0d                	jb     ffffffff8b47d73f <handler_628_body+0x1ff>
ffffffff8b47d732:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b47d736:	80 b9 81 0c 00 00 00 	cmpb   $0x0,0xc81(%rcx)
ffffffff8b47d73d:	74 74                	je     ffffffff8b47d7b3 <handler_628_body+0x273>
ffffffff8b47d73f:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
ffffffff8b47d743:	41 89 da             	mov    %ebx,%r10d
ffffffff8b47d746:	4c 8b 5d a0          	mov    -0x60(%rbp),%r11
ffffffff8b47d74a:	41 d1 ea             	shr    $1,%r10d
ffffffff8b47d74d:	41 81 e2 41 01 00 00 	and    $0x141,%r10d
ffffffff8b47d754:	41 09 da             	or     %ebx,%r10d
ffffffff8b47d757:	48 8b 49 08          	mov    0x8(%rcx),%rcx
ffffffff8b47d75b:	48 8b b1 00 02 00 00 	mov    0x200(%rcx),%rsi
ffffffff8b47d762:	41 f6 c3 10          	test   $0x10,%r11b
ffffffff8b47d766:	75 5c                	jne    ffffffff8b47d7c4 <handler_628_body+0x284>
ffffffff8b47d768:	4d 85 e4             	test   %r12,%r12
ffffffff8b47d76b:	0f 84 e2 00 00 00    	je     ffffffff8b47d853 <handler_628_body+0x313>
ffffffff8b47d771:	4d 89 f8             	mov    %r15,%r8
ffffffff8b47d774:	4c 8d 3d 95 eb e5 02 	lea    0x2e5eb95(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d77b:	48 39 fa             	cmp    %rdi,%rdx
ffffffff8b47d77e:	72 2b                	jb     ffffffff8b47d7ab <handler_628_body+0x26b>
ffffffff8b47d780:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
ffffffff8b47d784:	49 b9 00 00 00 f0 0f 	movabs $0xff0000000,%r9
ffffffff8b47d78b:	00 00 00 
ffffffff8b47d78e:	49 8d 79 01          	lea    0x1(%r9),%rdi
ffffffff8b47d792:	4c 01 e2             	add    %r12,%rdx
ffffffff8b47d795:	4c 39 c2             	cmp    %r8,%rdx
ffffffff8b47d798:	0f 96 c2             	setbe  %dl
ffffffff8b47d79b:	49 39 fc             	cmp    %rdi,%r12
ffffffff8b47d79e:	40 0f 93 c7          	setae  %dil
ffffffff8b47d7a2:	40 08 d7             	or     %dl,%dil
ffffffff8b47d7a5:	0f 84 c5 00 00 00    	je     ffffffff8b47d870 <handler_628_body+0x330>
ffffffff8b47d7ab:	4d 89 e1             	mov    %r12,%r9
ffffffff8b47d7ae:	e9 c1 00 00 00       	jmp    ffffffff8b47d874 <handler_628_body+0x334>
ffffffff8b47d7b3:	4c 8d 3d 56 eb e5 02 	lea    0x2e5eb56(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d7ba:	b9 16 00 00 00       	mov    $0x16,%ecx
ffffffff8b47d7bf:	e9 4a fe ff ff       	jmp    ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d7c4:	4c 89 fb             	mov    %r15,%rbx
ffffffff8b47d7c7:	4c 8d 3d 42 eb e5 02 	lea    0x2e5eb42(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d7ce:	4d 85 e4             	test   %r12,%r12
ffffffff8b47d7d1:	0f 84 c7 00 00 00    	je     ffffffff8b47d89e <handler_628_body+0x35e>
ffffffff8b47d7d7:	4c 39 66 20          	cmp    %r12,0x20(%rsi)
ffffffff8b47d7db:	4d 89 e0             	mov    %r12,%r8
ffffffff8b47d7de:	0f 97 c1             	seta   %cl
ffffffff8b47d7e1:	4c 03 45 b8          	add    -0x48(%rbp),%r8
ffffffff8b47d7e5:	41 0f 92 c1          	setb   %r9b
ffffffff8b47d7e9:	41 08 c9             	or     %cl,%r9b
ffffffff8b47d7ec:	b9 16 00 00 00       	mov    $0x16,%ecx
ffffffff8b47d7f1:	0f 85 17 fe ff ff    	jne    ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d7f7:	4c 39 46 28          	cmp    %r8,0x28(%rsi)
ffffffff8b47d7fb:	0f 82 0d fe ff ff    	jb     ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d801:	48 39 fa             	cmp    %rdi,%rdx
ffffffff8b47d804:	72 21                	jb     ffffffff8b47d827 <handler_628_body+0x2e7>
ffffffff8b47d806:	49 39 d8             	cmp    %rbx,%r8
ffffffff8b47d809:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47d80c:	0f 97 c2             	seta   %dl
ffffffff8b47d80f:	48 c1 ef 1c          	shr    $0x1c,%rdi
ffffffff8b47d813:	48 81 ff ff 00 00 00 	cmp    $0xff,%rdi
ffffffff8b47d81a:	40 0f 92 c7          	setb   %dil
ffffffff8b47d81e:	40 84 d7             	test   %dl,%dil
ffffffff8b47d821:	0f 85 e7 fd ff ff    	jne    ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d827:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b47d82b:	8b 89 c4 05 00 00    	mov    0x5c4(%rcx),%ecx
ffffffff8b47d831:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b47d835:	48 8b 5d c0          	mov    -0x40(%rbp),%rbx
ffffffff8b47d839:	4c 8b 45 a8          	mov    -0x58(%rbp),%r8
ffffffff8b47d83d:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
ffffffff8b47d841:	4d 89 e1             	mov    %r12,%r9
ffffffff8b47d844:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47d847:	6a 00                	push   $0x0
ffffffff8b47d849:	50                   	push   %rax
ffffffff8b47d84a:	41 53                	push   %r11
ffffffff8b47d84c:	6a 00                	push   $0x0
ffffffff8b47d84e:	e9 a7 00 00 00       	jmp    ffffffff8b47d8fa <handler_628_body+0x3ba>
ffffffff8b47d853:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b47d856:	48 39 fa             	cmp    %rdi,%rdx
ffffffff8b47d859:	4c 8d 3d b0 ea e5 02 	lea    0x2e5eab0(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47d860:	41 0f 92 c0          	setb   %r8b
ffffffff8b47d864:	41 c1 e0 04          	shl    $0x4,%r8d
ffffffff8b47d868:	4d 8b 8c 30 f8 01 00 	mov    0x1f8(%r8,%rsi,1),%r9
ffffffff8b47d86f:	00 
ffffffff8b47d870:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
ffffffff8b47d874:	44 89 da             	mov    %r11d,%edx
ffffffff8b47d877:	81 e2 00 00 00 ff    	and    $0xff000000,%edx
ffffffff8b47d87d:	74 29                	je     ffffffff8b47d8a8 <handler_628_body+0x368>
ffffffff8b47d87f:	81 fa 00 00 00 01    	cmp    $0x1000000,%edx
ffffffff8b47d885:	75 43                	jne    ffffffff8b47d8ca <handler_628_body+0x38a>
ffffffff8b47d887:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b47d88b:	31 d2                	xor    %edx,%edx
ffffffff8b47d88d:	80 b9 81 0c 00 00 00 	cmpb   $0x0,0xc81(%rcx)
ffffffff8b47d894:	0f 95 c2             	setne  %dl
ffffffff8b47d897:	44 8d 5c 12 01       	lea    0x1(%rdx,%rdx,1),%r11d
ffffffff8b47d89c:	eb 37                	jmp    ffffffff8b47d8d5 <handler_628_body+0x395>
ffffffff8b47d89e:	b9 16 00 00 00       	mov    $0x16,%ecx
ffffffff8b47d8a3:	e9 66 fd ff ff       	jmp    ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d8a8:	f6 86 44 02 00 00 02 	testb  $0x2,0x244(%rsi)
ffffffff8b47d8af:	41 bb 01 00 00 00    	mov    $0x1,%r11d
ffffffff8b47d8b5:	75 1e                	jne    ffffffff8b47d8d5 <handler_628_body+0x395>
ffffffff8b47d8b7:	45 31 db             	xor    %r11d,%r11d
ffffffff8b47d8ba:	81 b9 d8 05 00 00 00 	cmpl   $0x1500000,0x5d8(%rcx)
ffffffff8b47d8c1:	00 50 01 
ffffffff8b47d8c4:	41 83 d3 01          	adc    $0x1,%r11d
ffffffff8b47d8c8:	eb 0b                	jmp    ffffffff8b47d8d5 <handler_628_body+0x395>
ffffffff8b47d8ca:	41 c1 fb 10          	sar    $0x10,%r11d
ffffffff8b47d8ce:	41 81 e3 00 ff ff ff 	and    $0xffffff00,%r11d
ffffffff8b47d8d5:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b47d8d9:	8b 89 c4 05 00 00    	mov    0x5c4(%rcx),%ecx
ffffffff8b47d8df:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b47d8e3:	48 8b 5d c0          	mov    -0x40(%rbp),%rbx
ffffffff8b47d8e7:	4c 8b 45 a8          	mov    -0x58(%rbp),%r8
ffffffff8b47d8eb:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
ffffffff8b47d8ef:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47d8f2:	6a 00                	push   $0x0
ffffffff8b47d8f4:	50                   	push   %rax
ffffffff8b47d8f5:	ff 75 a0             	push   -0x60(%rbp)
ffffffff8b47d8f8:	41 53                	push   %r11
ffffffff8b47d8fa:	41 52                	push   %r10
ffffffff8b47d8fc:	41 55                	push   %r13
ffffffff8b47d8fe:	ff 75 b8             	push   -0x48(%rbp)
ffffffff8b47d901:	e8 4a db 90 ff       	call   ffffffff8ad8b450 <handler_628_body-0x6f20f0>
ffffffff8b47d906:	48 83 c4 40          	add    $0x40,%rsp
ffffffff8b47d90a:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b47d90e:	89 c1                	mov    %eax,%ecx
ffffffff8b47d910:	48 89 93 08 04 00 00 	mov    %rdx,0x408(%rbx)
ffffffff8b47d917:	e9 f2 fc ff ff       	jmp    ffffffff8b47d60e <handler_628_body+0xce>
ffffffff8b47d91c:	e8 8f fd c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47d921:	0f 0b                	ud2
ffffffff8b47d923:	90                   	nop
ffffffff8b47d924:	90                   	nop
ffffffff8b47d925:	90                   	nop
ffffffff8b47d926:	90                   	nop
ffffffff8b47d927:	90                   	nop
ffffffff8b47d928:	90                   	nop
ffffffff8b47d929:	90                   	nop
ffffffff8b47d92a:	90                   	nop
ffffffff8b47d92b:	90                   	nop
ffffffff8b47d92c:	90                   	nop
ffffffff8b47d92d:	90                   	nop
ffffffff8b47d92e:	90                   	nop
ffffffff8b47d92f:	90                   	nop

ffffffff8b47d930 <frame_candidate_abd930>:
ffffffff8b47d930:	55                   	push   %rbp
ffffffff8b47d931:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47d934:	41 57                	push   %r15
ffffffff8b47d936:	41 56                	push   %r14
ffffffff8b47d938:	41 55                	push   %r13
ffffffff8b47d93a:	41 54                	push   %r12
ffffffff8b47d93c:	53                   	push   %rbx
ffffffff8b47d93d:	50                   	push   %rax
ffffffff8b47d93e:	48 83 7e 08 11       	cmpq   $0x11,0x8(%rsi)
ffffffff8b47d943:	41 be 16 00 00 00    	mov    $0x16,%r14d
ffffffff8b47d949:	0f 8c 31 01 00 00    	jl     ffffffff8b47da80 <frame_candidate_abd930+0x150>
ffffffff8b47d94f:	8b 06                	mov    (%rsi),%eax
ffffffff8b47d951:	49 89 f5             	mov    %rsi,%r13
ffffffff8b47d954:	85 c0                	test   %eax,%eax
ffffffff8b47d956:	74 19                	je     ffffffff8b47d971 <frame_candidate_abd930+0x41>
ffffffff8b47d958:	65 48 8b 0c 25 00 00 	mov    %gs:0x0,%rcx
ffffffff8b47d95f:	00 00 
ffffffff8b47d961:	48 8b 49 08          	mov    0x8(%rcx),%rcx
ffffffff8b47d965:	3b 81 bc 00 00 00    	cmp    0xbc(%rcx),%eax
ffffffff8b47d96b:	0f 85 21 01 00 00    	jne    ffffffff8b47da92 <frame_candidate_abd930+0x162>
ffffffff8b47d971:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8b47d978:	00 00 
ffffffff8b47d97a:	48 8b 58 08          	mov    0x8(%rax),%rbx
ffffffff8b47d97e:	31 f6                	xor    %esi,%esi
ffffffff8b47d980:	31 d2                	xor    %edx,%edx
ffffffff8b47d982:	31 c9                	xor    %ecx,%ecx
ffffffff8b47d984:	48 8d bb 48 01 00 00 	lea    0x148(%rbx),%rdi
ffffffff8b47d98b:	e8 70 90 a0 ff       	call   ffffffff8ae86a00 <handler_628_body-0x5f6b40>
ffffffff8b47d990:	8b 83 b0 00 00 00    	mov    0xb0(%rbx),%eax
ffffffff8b47d996:	a9 00 22 00 00       	test   $0x2200,%eax
ffffffff8b47d99b:	0f 85 c1 00 00 00    	jne    ffffffff8b47da62 <frame_candidate_abd930+0x132>
ffffffff8b47d9a1:	83 bb b8 00 00 00 01 	cmpl   $0x1,0xb8(%rbx)
ffffffff8b47d9a8:	0f 85 b4 00 00 00    	jne    ffffffff8b47da62 <frame_candidate_abd930+0x132>
ffffffff8b47d9ae:	ff 83 58 03 00 00    	incl   0x358(%rbx)
ffffffff8b47d9b4:	a9 00 00 00 10       	test   $0x10000000,%eax
ffffffff8b47d9b9:	75 08                	jne    ffffffff8b47d9c3 <frame_candidate_abd930+0x93>
ffffffff8b47d9bb:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47d9be:	e8 4d d0 a7 ff       	call   ffffffff8aefaa10 <handler_628_body-0x582b30>
ffffffff8b47d9c3:	4c 8d bb 48 01 00 00 	lea    0x148(%rbx),%r15
ffffffff8b47d9ca:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b47d9cd:	31 f6                	xor    %esi,%esi
ffffffff8b47d9cf:	31 d2                	xor    %edx,%edx
ffffffff8b47d9d1:	31 c9                	xor    %ecx,%ecx
ffffffff8b47d9d3:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47d9d6:	e8 c5 95 a0 ff       	call   ffffffff8ae86fa0 <handler_628_body-0x5f65a0>
ffffffff8b47d9db:	4c 8b a3 00 02 00 00 	mov    0x200(%rbx),%r12
ffffffff8b47d9e2:	4d 85 e4             	test   %r12,%r12
ffffffff8b47d9e5:	74 3a                	je     ffffffff8b47da21 <frame_candidate_abd930+0xf1>
ffffffff8b47d9e7:	49 8d bc 24 78 02 00 	lea    0x278(%r12),%rdi
ffffffff8b47d9ee:	00 
ffffffff8b47d9ef:	31 f6                	xor    %esi,%esi
ffffffff8b47d9f1:	31 d2                	xor    %edx,%edx
ffffffff8b47d9f3:	31 c9                	xor    %ecx,%ecx
ffffffff8b47d9f5:	48 89 7d d0          	mov    %rdi,-0x30(%rbp)
ffffffff8b47d9f9:	e8 02 90 a0 ff       	call   ffffffff8ae86a00 <handler_628_body-0x5f6b40>
ffffffff8b47d9fe:	49 8b 45 08          	mov    0x8(%r13),%rax
ffffffff8b47da02:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
ffffffff8b47da06:	31 f6                	xor    %esi,%esi
ffffffff8b47da08:	31 d2                	xor    %edx,%edx
ffffffff8b47da0a:	31 c9                	xor    %ecx,%ecx
ffffffff8b47da0c:	49 89 84 24 80 02 00 	mov    %rax,0x280(%r12)
ffffffff8b47da13:	00 
ffffffff8b47da14:	e8 87 95 a0 ff       	call   ffffffff8ae86fa0 <handler_628_body-0x5f65a0>
ffffffff8b47da19:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47da1c:	e8 4f 42 bd ff       	call   ffffffff8b051c70 <handler_628_body-0x42b8d0>
ffffffff8b47da21:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47da24:	31 f6                	xor    %esi,%esi
ffffffff8b47da26:	31 d2                	xor    %edx,%edx
ffffffff8b47da28:	31 c9                	xor    %ecx,%ecx
ffffffff8b47da2a:	e8 d1 8f a0 ff       	call   ffffffff8ae86a00 <handler_628_body-0x5f6b40>
ffffffff8b47da2f:	0f b6 8b b1 00 00 00 	movzbl 0xb1(%rbx),%ecx
ffffffff8b47da36:	8b 83 58 03 00 00    	mov    0x358(%rbx),%eax
ffffffff8b47da3c:	c0 e9 05             	shr    $0x5,%cl
ffffffff8b47da3f:	ff c8                	dec    %eax
ffffffff8b47da41:	0f 94 c2             	sete   %dl
ffffffff8b47da44:	89 83 58 03 00 00    	mov    %eax,0x358(%rbx)
ffffffff8b47da4a:	20 ca                	and    %cl,%dl
ffffffff8b47da4c:	80 fa 01             	cmp    $0x1,%dl
ffffffff8b47da4f:	75 21                	jne    ffffffff8b47da72 <frame_candidate_abd930+0x142>
ffffffff8b47da51:	48 81 c3 58 03 00 00 	add    $0x358,%rbx
ffffffff8b47da58:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47da5b:	e8 b0 8e 14 00       	call   ffffffff8b5c6910 <frame_candidate_abf510+0x147400>
ffffffff8b47da60:	eb 10                	jmp    ffffffff8b47da72 <frame_candidate_abd930+0x142>
ffffffff8b47da62:	48 81 c3 48 01 00 00 	add    $0x148,%rbx
ffffffff8b47da69:	41 be 03 00 00 00    	mov    $0x3,%r14d
ffffffff8b47da6f:	49 89 df             	mov    %rbx,%r15
ffffffff8b47da72:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47da75:	31 f6                	xor    %esi,%esi
ffffffff8b47da77:	31 d2                	xor    %edx,%edx
ffffffff8b47da79:	31 c9                	xor    %ecx,%ecx
ffffffff8b47da7b:	e8 20 95 a0 ff       	call   ffffffff8ae86fa0 <handler_628_body-0x5f65a0>
ffffffff8b47da80:	44 89 f0             	mov    %r14d,%eax
ffffffff8b47da83:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47da87:	5b                   	pop    %rbx
ffffffff8b47da88:	41 5c                	pop    %r12
ffffffff8b47da8a:	41 5d                	pop    %r13
ffffffff8b47da8c:	41 5e                	pop    %r14
ffffffff8b47da8e:	41 5f                	pop    %r15
ffffffff8b47da90:	5d                   	pop    %rbp
ffffffff8b47da91:	c3                   	ret
ffffffff8b47da92:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b47da99:	e8 f2 b4 b4 ff       	call   ffffffff8afc8f90 <handler_628_body-0x4b45b0>
ffffffff8b47da9e:	85 c0                	test   %eax,%eax
ffffffff8b47daa0:	74 1d                	je     ffffffff8b47dabf <frame_candidate_abd930+0x18f>
ffffffff8b47daa2:	41 8b 7d 00          	mov    0x0(%r13),%edi
ffffffff8b47daa6:	e8 c5 e6 a7 ff       	call   ffffffff8aefc170 <handler_628_body-0x5813d0>
ffffffff8b47daab:	48 89 c3             	mov    %rax,%rbx
ffffffff8b47daae:	48 85 c0             	test   %rax,%rax
ffffffff8b47dab1:	0f 85 d9 fe ff ff    	jne    ffffffff8b47d990 <frame_candidate_abd930+0x60>
ffffffff8b47dab7:	41 be 03 00 00 00    	mov    $0x3,%r14d
ffffffff8b47dabd:	eb c1                	jmp    ffffffff8b47da80 <frame_candidate_abd930+0x150>
ffffffff8b47dabf:	41 be 01 00 00 00    	mov    $0x1,%r14d
ffffffff8b47dac5:	eb b9                	jmp    ffffffff8b47da80 <frame_candidate_abd930+0x150>
ffffffff8b47dac7:	90                   	nop
ffffffff8b47dac8:	90                   	nop
ffffffff8b47dac9:	90                   	nop
ffffffff8b47daca:	90                   	nop
ffffffff8b47dacb:	90                   	nop
ffffffff8b47dacc:	90                   	nop
ffffffff8b47dacd:	90                   	nop
ffffffff8b47dace:	90                   	nop
ffffffff8b47dacf:	90                   	nop

ffffffff8b47dad0 <frame_candidate_abdad0>:
ffffffff8b47dad0:	55                   	push   %rbp
ffffffff8b47dad1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47dad4:	41 57                	push   %r15
ffffffff8b47dad6:	41 56                	push   %r14
ffffffff8b47dad8:	41 55                	push   %r13
ffffffff8b47dada:	41 54                	push   %r12
ffffffff8b47dadc:	53                   	push   %rbx
ffffffff8b47dadd:	48 81 ec c8 00 00 00 	sub    $0xc8,%rsp
ffffffff8b47dae4:	48 8d 1d 25 e8 e5 02 	lea    0x2e5e825(%rip),%rbx        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47daeb:	49 89 f6             	mov    %rsi,%r14
ffffffff8b47daee:	48 8b 03             	mov    (%rbx),%rax
ffffffff8b47daf1:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b47daf5:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b47dafc:	e8 8f b4 b4 ff       	call   ffffffff8afc8f90 <handler_628_body-0x4b45b0>
ffffffff8b47db01:	85 c0                	test   %eax,%eax
ffffffff8b47db03:	0f 84 73 06 00 00    	je     ffffffff8b47e17c <frame_candidate_abdad0+0x6ac>
ffffffff8b47db09:	41 8b 3e             	mov    (%r14),%edi
ffffffff8b47db0c:	e8 5f e6 a7 ff       	call   ffffffff8aefc170 <handler_628_body-0x5813d0>
ffffffff8b47db11:	48 89 c1             	mov    %rax,%rcx
ffffffff8b47db14:	b8 02 00 00 00       	mov    $0x2,%eax
ffffffff8b47db19:	48 85 c9             	test   %rcx,%rcx
ffffffff8b47db1c:	0f 84 7b 06 00 00    	je     ffffffff8b47e19d <frame_candidate_abdad0+0x6cd>
ffffffff8b47db22:	8b 81 b0 00 00 00    	mov    0xb0(%rcx),%eax
ffffffff8b47db28:	a9 00 20 00 00       	test   $0x2000,%eax
ffffffff8b47db2d:	0f 85 50 06 00 00    	jne    ffffffff8b47e183 <frame_candidate_abdad0+0x6b3>
ffffffff8b47db33:	ff 81 58 03 00 00    	incl   0x358(%rcx)
ffffffff8b47db39:	4c 89 b5 48 ff ff ff 	mov    %r14,-0xb8(%rbp)
ffffffff8b47db40:	48 89 8d 50 ff ff ff 	mov    %rcx,-0xb0(%rbp)
ffffffff8b47db47:	a9 00 00 00 10       	test   $0x10000000,%eax
ffffffff8b47db4c:	75 13                	jne    ffffffff8b47db61 <frame_candidate_abdad0+0x91>
ffffffff8b47db4e:	48 8b bd 50 ff ff ff 	mov    -0xb0(%rbp),%rdi
ffffffff8b47db55:	e8 b6 ce a7 ff       	call   ffffffff8aefaa10 <handler_628_body-0x582b30>
ffffffff8b47db5a:	48 8b 8d 50 ff ff ff 	mov    -0xb0(%rbp),%rcx
ffffffff8b47db61:	48 8d b9 48 01 00 00 	lea    0x148(%rcx),%rdi
ffffffff8b47db68:	48 89 cb             	mov    %rcx,%rbx
ffffffff8b47db6b:	31 f6                	xor    %esi,%esi
ffffffff8b47db6d:	31 d2                	xor    %edx,%edx
ffffffff8b47db6f:	31 c9                	xor    %ecx,%ecx
ffffffff8b47db71:	48 89 bd 20 ff ff ff 	mov    %rdi,-0xe0(%rbp)
ffffffff8b47db78:	e8 23 94 a0 ff       	call   ffffffff8ae86fa0 <handler_628_body-0x5f65a0>
ffffffff8b47db7d:	4c 8b ab 00 02 00 00 	mov    0x200(%rbx),%r13
ffffffff8b47db84:	31 f6                	xor    %esi,%esi
ffffffff8b47db86:	31 d2                	xor    %edx,%edx
ffffffff8b47db88:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b47db8b:	e8 90 8c 80 ff       	call   ffffffff8ac86820 <handler_628_body-0x7f6d20>
ffffffff8b47db90:	48 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%rdi
ffffffff8b47db97:	be 68 00 00 00       	mov    $0x68,%esi
ffffffff8b47db9c:	c7 85 64 ff ff ff 00 	movl   $0x0,-0x9c(%rbp)
ffffffff8b47dba3:	00 00 00 
ffffffff8b47dba6:	e8 45 b4 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47dbab:	4d 8b 7d 08          	mov    0x8(%r13),%r15
ffffffff8b47dbaf:	4d 39 ef             	cmp    %r13,%r15
ffffffff8b47dbb2:	0f 84 08 05 00 00    	je     ffffffff8b47e0c0 <frame_candidate_abdad0+0x5f0>
ffffffff8b47dbb8:	4c 89 ad 18 ff ff ff 	mov    %r13,-0xe8(%rbp)
ffffffff8b47dbbf:	eb 1c                	jmp    ffffffff8b47dbdd <frame_candidate_abdad0+0x10d>
ffffffff8b47dbc1:	41 ff c6             	inc    %r14d
ffffffff8b47dbc4:	44 89 b5 64 ff ff ff 	mov    %r14d,-0x9c(%rbp)
ffffffff8b47dbcb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8b47dbd0:	4d 8b 7f 08          	mov    0x8(%r15),%r15
ffffffff8b47dbd4:	4d 39 ef             	cmp    %r13,%r15
ffffffff8b47dbd7:	0f 84 e3 04 00 00    	je     ffffffff8b47e0c0 <frame_candidate_abdad0+0x5f0>
ffffffff8b47dbdd:	66 41 83 7f 66 00    	cmpw   $0x0,0x66(%r15)
ffffffff8b47dbe3:	74 eb                	je     ffffffff8b47dbd0 <frame_candidate_abdad0+0x100>
ffffffff8b47dbe5:	41 f6 47 60 02       	testb  $0x2,0x60(%r15)
ffffffff8b47dbea:	75 e4                	jne    ffffffff8b47dbd0 <frame_candidate_abdad0+0x100>
ffffffff8b47dbec:	41 0f b7 47 64       	movzwl 0x64(%r15),%eax
ffffffff8b47dbf1:	49 8b 5f 50          	mov    0x50(%r15),%rbx
ffffffff8b47dbf5:	89 45 a0             	mov    %eax,-0x60(%rbp)
ffffffff8b47dbf8:	41 8b 4f 60          	mov    0x60(%r15),%ecx
ffffffff8b47dbfc:	f6 c1 20             	test   $0x20,%cl
ffffffff8b47dbff:	74 0c                	je     ffffffff8b47dc0d <frame_candidate_abdad0+0x13d>
ffffffff8b47dc01:	0d 00 00 01 00       	or     $0x10000,%eax
ffffffff8b47dc06:	89 45 a0             	mov    %eax,-0x60(%rbp)
ffffffff8b47dc09:	41 8b 4f 60          	mov    0x60(%r15),%ecx
ffffffff8b47dc0d:	f7 c1 00 10 00 00    	test   $0x1000,%ecx
ffffffff8b47dc13:	74 08                	je     ffffffff8b47dc1d <frame_candidate_abdad0+0x14d>
ffffffff8b47dc15:	0d 00 00 02 00       	or     $0x20000,%eax
ffffffff8b47dc1a:	89 45 a0             	mov    %eax,-0x60(%rbp)
ffffffff8b47dc1d:	49 8b 47 20          	mov    0x20(%r15),%rax
ffffffff8b47dc21:	48 89 45 88          	mov    %rax,-0x78(%rbp)
ffffffff8b47dc25:	49 8b 47 28          	mov    0x28(%r15),%rax
ffffffff8b47dc29:	48 89 45 90          	mov    %rax,-0x70(%rbp)
ffffffff8b47dc2d:	48 85 db             	test   %rbx,%rbx
ffffffff8b47dc30:	74 1f                	je     ffffffff8b47dc51 <frame_candidate_abdad0+0x181>
ffffffff8b47dc32:	0f b6 83 9d 00 00 00 	movzbl 0x9d(%rbx),%eax
ffffffff8b47dc39:	83 f8 0a             	cmp    $0xa,%eax
ffffffff8b47dc3c:	77 25                	ja     ffffffff8b47dc63 <frame_candidate_abdad0+0x193>
ffffffff8b47dc3e:	b9 87 05 00 00       	mov    $0x587,%ecx
ffffffff8b47dc43:	0f a3 c1             	bt     %eax,%ecx
ffffffff8b47dc46:	73 1b                	jae    ffffffff8b47dc63 <frame_candidate_abdad0+0x193>
ffffffff8b47dc48:	f6 83 a2 00 00 00 01 	testb  $0x1,0xa2(%rbx)
ffffffff8b47dc4f:	75 12                	jne    ffffffff8b47dc63 <frame_candidate_abdad0+0x193>
ffffffff8b47dc51:	66 41 83 7f 66 00    	cmpw   $0x0,0x66(%r15)
ffffffff8b47dc57:	74 13                	je     ffffffff8b47dc6c <frame_candidate_abdad0+0x19c>
ffffffff8b47dc59:	41 0f be 87 4c 01 00 	movsbl 0x14c(%r15),%eax
ffffffff8b47dc60:	00 
ffffffff8b47dc61:	eb 0b                	jmp    ffffffff8b47dc6e <frame_candidate_abdad0+0x19e>
ffffffff8b47dc63:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
ffffffff8b47dc6a:	eb 0e                	jmp    ffffffff8b47dc7a <frame_candidate_abdad0+0x1aa>
ffffffff8b47dc6c:	31 c0                	xor    %eax,%eax
ffffffff8b47dc6e:	89 45 cc             	mov    %eax,-0x34(%rbp)
ffffffff8b47dc71:	48 85 db             	test   %rbx,%rbx
ffffffff8b47dc74:	0f 84 b0 03 00 00    	je     ffffffff8b47e02a <frame_candidate_abdad0+0x55a>
ffffffff8b47dc7a:	4c 8d 63 18          	lea    0x18(%rbx),%r12
ffffffff8b47dc7e:	31 f6                	xor    %esi,%esi
ffffffff8b47dc80:	31 d2                	xor    %edx,%edx
ffffffff8b47dc82:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47dc85:	e8 16 6a d1 ff       	call   ffffffff8b1946a0 <handler_628_body-0x2e8ea0>
ffffffff8b47dc8a:	0f b6 83 9d 00 00 00 	movzbl 0x9d(%rbx),%eax
ffffffff8b47dc91:	04 fd                	add    $0xfd,%al
ffffffff8b47dc93:	3c 02                	cmp    $0x2,%al
ffffffff8b47dc95:	73 11                	jae    ffffffff8b47dca8 <frame_candidate_abdad0+0x1d8>
ffffffff8b47dc97:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47dc9a:	31 f6                	xor    %esi,%esi
ffffffff8b47dc9c:	31 d2                	xor    %edx,%edx
ffffffff8b47dc9e:	e8 0d 72 d1 ff       	call   ffffffff8b194eb0 <handler_628_body-0x2e8690>
ffffffff8b47dca3:	e9 28 ff ff ff       	jmp    ffffffff8b47dbd0 <frame_candidate_abdad0+0x100>
ffffffff8b47dca8:	8b 83 30 01 00 00    	mov    0x130(%rbx),%eax
ffffffff8b47dcae:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47dcb1:	48 89 9d 30 ff ff ff 	mov    %rbx,-0xd0(%rbp)
ffffffff8b47dcb8:	31 f6                	xor    %esi,%esi
ffffffff8b47dcba:	31 d2                	xor    %edx,%edx
ffffffff8b47dcbc:	89 45 a4             	mov    %eax,-0x5c(%rbp)
ffffffff8b47dcbf:	8b 83 38 01 00 00    	mov    0x138(%rbx),%eax
ffffffff8b47dcc5:	31 db                	xor    %ebx,%ebx
ffffffff8b47dcc7:	89 45 a8             	mov    %eax,-0x58(%rbp)
ffffffff8b47dcca:	e8 e1 71 d1 ff       	call   ffffffff8b194eb0 <handler_628_body-0x2e8690>
ffffffff8b47dccf:	4d 8b 77 20          	mov    0x20(%r15),%r14
ffffffff8b47dcd3:	4c 89 bd 40 ff ff ff 	mov    %r15,-0xc0(%rbp)
ffffffff8b47dcda:	4d 8b 7f 28          	mov    0x28(%r15),%r15
ffffffff8b47dcde:	48 c7 c0 00 c0 ff ff 	mov    $0xffffffffffffc000,%rax
ffffffff8b47dce5:	49 21 c6             	and    %rax,%r14
ffffffff8b47dce8:	b8 ff 3f 00 00       	mov    $0x3fff,%eax
ffffffff8b47dced:	49 01 c7             	add    %rax,%r15
ffffffff8b47dcf0:	49 81 e7 00 c0 ff ff 	and    $0xffffffffffffc000,%r15
ffffffff8b47dcf7:	4d 39 fe             	cmp    %r15,%r14
ffffffff8b47dcfa:	73 26                	jae    ffffffff8b47dd22 <frame_candidate_abdad0+0x252>
ffffffff8b47dcfc:	31 db                	xor    %ebx,%ebx
ffffffff8b47dcfe:	66 90                	xchg   %ax,%ax
ffffffff8b47dd00:	49 8b bd d8 01 00 00 	mov    0x1d8(%r13),%rdi
ffffffff8b47dd07:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47dd0a:	e8 d1 06 e2 ff       	call   ffffffff8b29e3e0 <handler_628_body-0x1df160>
ffffffff8b47dd0f:	48 83 f8 01          	cmp    $0x1,%rax
ffffffff8b47dd13:	83 db ff             	sbb    $0xffffffff,%ebx
ffffffff8b47dd16:	49 81 c6 00 40 00 00 	add    $0x4000,%r14
ffffffff8b47dd1d:	4d 39 fe             	cmp    %r15,%r14
ffffffff8b47dd20:	72 de                	jb     ffffffff8b47dd00 <frame_candidate_abdad0+0x230>
ffffffff8b47dd22:	89 5d ac             	mov    %ebx,-0x54(%rbp)
ffffffff8b47dd25:	48 8b 9d 30 ff ff ff 	mov    -0xd0(%rbp),%rbx
ffffffff8b47dd2c:	48 8d 0d e5 90 13 03 	lea    0x31390e5(%rip),%rcx        # ffffffff8e5b6e18 <frame_candidate_abf510+0x3137908>
ffffffff8b47dd33:	4c 8b bd 40 ff ff ff 	mov    -0xc0(%rbp),%r15
ffffffff8b47dd3a:	89 d8                	mov    %ebx,%eax
ffffffff8b47dd3c:	31 c8                	xor    %ecx,%eax
ffffffff8b47dd3e:	48 98                	cltq
ffffffff8b47dd40:	48 89 45 98          	mov    %rax,-0x68(%rbp)
ffffffff8b47dd44:	0f b6 83 9d 00 00 00 	movzbl 0x9d(%rbx),%eax
ffffffff8b47dd4b:	89 45 b0             	mov    %eax,-0x50(%rbp)
ffffffff8b47dd4e:	49 8b 47 28          	mov    0x28(%r15),%rax
ffffffff8b47dd52:	49 2b 47 20          	sub    0x20(%r15),%rax
ffffffff8b47dd56:	48 c7 45 b4 00 00 00 	movq   $0x0,-0x4c(%rbp)
ffffffff8b47dd5d:	00 
ffffffff8b47dd5e:	48 c7 45 bc 00 00 00 	movq   $0x0,-0x44(%rbp)
ffffffff8b47dd65:	00 
ffffffff8b47dd66:	48 c7 45 c4 00 00 00 	movq   $0x0,-0x3c(%rbp)
ffffffff8b47dd6d:	00 
ffffffff8b47dd6e:	48 c1 e8 0e          	shr    $0xe,%rax
ffffffff8b47dd72:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
ffffffff8b47dd79:	85 c0                	test   %eax,%eax
ffffffff8b47dd7b:	0f 8e ba 02 00 00    	jle    ffffffff8b47e03b <frame_candidate_abdad0+0x56b>
ffffffff8b47dd81:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
ffffffff8b47dd88:	4c 89 a5 58 ff ff ff 	mov    %r12,-0xa8(%rbp)
ffffffff8b47dd8f:	25 ff ff ff 7f       	and    $0x7fffffff,%eax
ffffffff8b47dd94:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
ffffffff8b47dd9b:	31 c0                	xor    %eax,%eax
ffffffff8b47dd9d:	eb 39                	jmp    ffffffff8b47ddd8 <frame_candidate_abdad0+0x308>
ffffffff8b47dd9f:	90                   	nop
ffffffff8b47dda0:	ff 45 c8             	incl   -0x38(%rbp)
ffffffff8b47dda3:	4c 8b a5 58 ff ff ff 	mov    -0xa8(%rbp),%r12
ffffffff8b47ddaa:	48 83 c3 18          	add    $0x18,%rbx
ffffffff8b47ddae:	31 f6                	xor    %esi,%esi
ffffffff8b47ddb0:	31 d2                	xor    %edx,%edx
ffffffff8b47ddb2:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47ddb5:	e8 f6 70 d1 ff       	call   ffffffff8b194eb0 <handler_628_body-0x2e8690>
ffffffff8b47ddba:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
ffffffff8b47ddc1:	48 8b 9d 30 ff ff ff 	mov    -0xd0(%rbp),%rbx
ffffffff8b47ddc8:	48 ff c0             	inc    %rax
ffffffff8b47ddcb:	48 3b 85 38 ff ff ff 	cmp    -0xc8(%rbp),%rax
ffffffff8b47ddd2:	0f 84 63 02 00 00    	je     ffffffff8b47e03b <frame_candidate_abdad0+0x56b>
ffffffff8b47ddd8:	4d 8b 7f 58          	mov    0x58(%r15),%r15
ffffffff8b47dddc:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
ffffffff8b47dde3:	c1 e0 0e             	shl    $0xe,%eax
ffffffff8b47dde6:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47dde9:	31 f6                	xor    %esi,%esi
ffffffff8b47ddeb:	31 d2                	xor    %edx,%edx
ffffffff8b47dded:	4c 63 e8             	movslq %eax,%r13
ffffffff8b47ddf0:	e8 ab 68 d1 ff       	call   ffffffff8b1946a0 <handler_628_body-0x2e8ea0>
ffffffff8b47ddf5:	4f 8d 34 2f          	lea    (%r15,%r13,1),%r14
ffffffff8b47ddf9:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47ddfc:	49 c1 fe 0e          	sar    $0xe,%r14
ffffffff8b47de00:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47de03:	e8 d8 b9 0c 00       	call   ffffffff8b5497e0 <frame_candidate_abf510+0xca2d0>
ffffffff8b47de08:	48 85 c0             	test   %rax,%rax
ffffffff8b47de0b:	75 69                	jne    ffffffff8b47de76 <frame_candidate_abdad0+0x3a6>
ffffffff8b47de0d:	4c 89 ad 28 ff ff ff 	mov    %r13,-0xd8(%rbp)
ffffffff8b47de14:	49 89 dd             	mov    %rbx,%r13
ffffffff8b47de17:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b47de1e:	00 00 
ffffffff8b47de20:	49 8b 9d b0 00 00 00 	mov    0xb0(%r13),%rbx
ffffffff8b47de27:	48 85 db             	test   %rbx,%rbx
ffffffff8b47de2a:	0f 84 04 01 00 00    	je     ffffffff8b47df34 <frame_candidate_abdad0+0x464>
ffffffff8b47de30:	4d 03 bd b8 00 00 00 	add    0xb8(%r13),%r15
ffffffff8b47de37:	48 8d 7b 18          	lea    0x18(%rbx),%rdi
ffffffff8b47de3b:	31 f6                	xor    %esi,%esi
ffffffff8b47de3d:	31 d2                	xor    %edx,%edx
ffffffff8b47de3f:	e8 5c 68 d1 ff       	call   ffffffff8b1946a0 <handler_628_body-0x2e8ea0>
ffffffff8b47de44:	49 83 c5 18          	add    $0x18,%r13
ffffffff8b47de48:	31 f6                	xor    %esi,%esi
ffffffff8b47de4a:	31 d2                	xor    %edx,%edx
ffffffff8b47de4c:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b47de4f:	e8 5c 70 d1 ff       	call   ffffffff8b194eb0 <handler_628_body-0x2e8690>
ffffffff8b47de54:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
ffffffff8b47de5b:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47de5e:	4d 8d 34 07          	lea    (%r15,%rax,1),%r14
ffffffff8b47de62:	49 c1 fe 0e          	sar    $0xe,%r14
ffffffff8b47de66:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47de69:	e8 72 b9 0c 00       	call   ffffffff8b5497e0 <frame_candidate_abf510+0xca2d0>
ffffffff8b47de6e:	49 89 dd             	mov    %rbx,%r13
ffffffff8b47de71:	48 85 c0             	test   %rax,%rax
ffffffff8b47de74:	74 aa                	je     ffffffff8b47de20 <frame_candidate_abdad0+0x350>
ffffffff8b47de76:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47de79:	49 89 c4             	mov    %rax,%r12
ffffffff8b47de7c:	e8 1f fa 0c 00       	call   ffffffff8b54d8a0 <frame_candidate_abf510+0xce390>
ffffffff8b47de81:	41 83 7c 24 70 00    	cmpl   $0x0,0x70(%r12)
ffffffff8b47de87:	4c 8b bd 40 ff ff ff 	mov    -0xc0(%rbp),%r15
ffffffff8b47de8e:	0f 84 8c 00 00 00    	je     ffffffff8b47df20 <frame_candidate_abdad0+0x450>
ffffffff8b47de94:	ff 45 bc             	incl   -0x44(%rbp)
ffffffff8b47de97:	41 80 7c 24 66 01    	cmpb   $0x1,0x66(%r12)
ffffffff8b47de9d:	75 03                	jne    ffffffff8b47dea2 <frame_candidate_abdad0+0x3d2>
ffffffff8b47de9f:	ff 45 c4             	incl   -0x3c(%rbp)
ffffffff8b47dea2:	41 83 7c 24 70 00    	cmpl   $0x0,0x70(%r12)
ffffffff8b47dea8:	0f 85 f5 fe ff ff    	jne    ffffffff8b47dda3 <frame_candidate_abdad0+0x2d3>
ffffffff8b47deae:	49 8b 44 24 20       	mov    0x20(%r12),%rax
ffffffff8b47deb3:	48 85 c0             	test   %rax,%rax
ffffffff8b47deb6:	0f 84 e4 fe ff ff    	je     ffffffff8b47dda0 <frame_candidate_abdad0+0x2d0>
ffffffff8b47debc:	80 b8 9d 00 00 00 00 	cmpb   $0x0,0x9d(%rax)
ffffffff8b47dec3:	0f 84 d7 fe ff ff    	je     ffffffff8b47dda0 <frame_candidate_abdad0+0x2d0>
ffffffff8b47dec9:	80 bb 9d 00 00 00 01 	cmpb   $0x1,0x9d(%rbx)
ffffffff8b47ded0:	0f 85 cd fe ff ff    	jne    ffffffff8b47dda3 <frame_candidate_abdad0+0x2d3>
ffffffff8b47ded6:	48 8d 05 33 5a 00 01 	lea    0x1005a33(%rip),%rax        # ffffffff8c483910 <frame_candidate_abf510+0x1004400>
ffffffff8b47dedd:	48 8b 40 08          	mov    0x8(%rax),%rax
ffffffff8b47dee1:	4c 8b 60 38          	mov    0x38(%rax),%r12
ffffffff8b47dee5:	48 8d 05 5c d9 7a ff 	lea    -0x8526a4(%rip),%rax        # ffffffff8ac2b848 <handler_628_body-0x851cf8>
ffffffff8b47deec:	4c 29 e0             	sub    %r12,%rax
ffffffff8b47deef:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b47def3:	48 83 f8 0d          	cmp    $0xd,%rax
ffffffff8b47def7:	0f 87 19 01 00 00    	ja     ffffffff8b47e016 <frame_candidate_abdad0+0x546>
ffffffff8b47defd:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47df00:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47df03:	31 d2                	xor    %edx,%edx
ffffffff8b47df05:	31 c9                	xor    %ecx,%ecx
ffffffff8b47df07:	41 ff d4             	call   *%r12
ffffffff8b47df0a:	85 c0                	test   %eax,%eax
ffffffff8b47df0c:	0f 85 91 fe ff ff    	jne    ffffffff8b47dda3 <frame_candidate_abdad0+0x2d3>
ffffffff8b47df12:	e9 89 fe ff ff       	jmp    ffffffff8b47dda0 <frame_candidate_abdad0+0x2d0>
ffffffff8b47df17:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b47df1e:	00 00 
ffffffff8b47df20:	ff 45 c0             	incl   -0x40(%rbp)
ffffffff8b47df23:	41 80 7c 24 66 01    	cmpb   $0x1,0x66(%r12)
ffffffff8b47df29:	0f 84 70 ff ff ff    	je     ffffffff8b47de9f <frame_candidate_abdad0+0x3cf>
ffffffff8b47df2f:	e9 6e ff ff ff       	jmp    ffffffff8b47dea2 <frame_candidate_abdad0+0x3d2>
ffffffff8b47df34:	49 83 c5 18          	add    $0x18,%r13
ffffffff8b47df38:	31 f6                	xor    %esi,%esi
ffffffff8b47df3a:	31 d2                	xor    %edx,%edx
ffffffff8b47df3c:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b47df3f:	e8 6c 6f d1 ff       	call   ffffffff8b194eb0 <handler_628_body-0x2e8690>
ffffffff8b47df44:	4c 8b bd 40 ff ff ff 	mov    -0xc0(%rbp),%r15
ffffffff8b47df4b:	48 8b bd 58 ff ff ff 	mov    -0xa8(%rbp),%rdi
ffffffff8b47df52:	31 f6                	xor    %esi,%esi
ffffffff8b47df54:	31 d2                	xor    %edx,%edx
ffffffff8b47df56:	4d 8b 67 58          	mov    0x58(%r15),%r12
ffffffff8b47df5a:	e8 41 67 d1 ff       	call   ffffffff8b1946a0 <handler_628_body-0x2e8ea0>
ffffffff8b47df5f:	48 8b 9d 30 ff ff ff 	mov    -0xd0(%rbp),%rbx
ffffffff8b47df66:	80 bb 9d 00 00 00 01 	cmpb   $0x1,0x9d(%rbx)
ffffffff8b47df6d:	75 41                	jne    ffffffff8b47dfb0 <frame_candidate_abdad0+0x4e0>
ffffffff8b47df6f:	90                   	nop
ffffffff8b47df70:	48 8d 05 99 59 00 01 	lea    0x1005999(%rip),%rax        # ffffffff8c483910 <frame_candidate_abf510+0x1004400>
ffffffff8b47df77:	48 8b 40 08          	mov    0x8(%rax),%rax
ffffffff8b47df7b:	4c 8b 70 38          	mov    0x38(%rax),%r14
ffffffff8b47df7f:	48 8d 05 c2 d8 7a ff 	lea    -0x85273e(%rip),%rax        # ffffffff8ac2b848 <handler_628_body-0x851cf8>
ffffffff8b47df86:	4c 29 f0             	sub    %r14,%rax
ffffffff8b47df89:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b47df8d:	48 83 f8 0d          	cmp    $0xd,%rax
ffffffff8b47df91:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
ffffffff8b47df98:	77 54                	ja     ffffffff8b47dfee <frame_candidate_abdad0+0x51e>
ffffffff8b47df9a:	49 8d 34 04          	lea    (%r12,%rax,1),%rsi
ffffffff8b47df9e:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47dfa1:	31 d2                	xor    %edx,%edx
ffffffff8b47dfa3:	31 c9                	xor    %ecx,%ecx
ffffffff8b47dfa5:	48 c1 fe 0e          	sar    $0xe,%rsi
ffffffff8b47dfa9:	41 ff d6             	call   *%r14
ffffffff8b47dfac:	85 c0                	test   %eax,%eax
ffffffff8b47dfae:	75 5e                	jne    ffffffff8b47e00e <frame_candidate_abdad0+0x53e>
ffffffff8b47dfb0:	4c 8b b3 b0 00 00 00 	mov    0xb0(%rbx),%r14
ffffffff8b47dfb7:	4d 85 f6             	test   %r14,%r14
ffffffff8b47dfba:	74 4a                	je     ffffffff8b47e006 <frame_candidate_abdad0+0x536>
ffffffff8b47dfbc:	4c 03 a3 b8 00 00 00 	add    0xb8(%rbx),%r12
ffffffff8b47dfc3:	49 8d 7e 18          	lea    0x18(%r14),%rdi
ffffffff8b47dfc7:	31 f6                	xor    %esi,%esi
ffffffff8b47dfc9:	31 d2                	xor    %edx,%edx
ffffffff8b47dfcb:	e8 d0 66 d1 ff       	call   ffffffff8b1946a0 <handler_628_body-0x2e8ea0>
ffffffff8b47dfd0:	48 83 c3 18          	add    $0x18,%rbx
ffffffff8b47dfd4:	31 f6                	xor    %esi,%esi
ffffffff8b47dfd6:	31 d2                	xor    %edx,%edx
ffffffff8b47dfd8:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47dfdb:	e8 d0 6e d1 ff       	call   ffffffff8b194eb0 <handler_628_body-0x2e8690>
ffffffff8b47dfe0:	4c 89 f3             	mov    %r14,%rbx
ffffffff8b47dfe3:	80 bb 9d 00 00 00 01 	cmpb   $0x1,0x9d(%rbx)
ffffffff8b47dfea:	74 84                	je     ffffffff8b47df70 <frame_candidate_abdad0+0x4a0>
ffffffff8b47dfec:	eb c2                	jmp    ffffffff8b47dfb0 <frame_candidate_abdad0+0x4e0>
ffffffff8b47dfee:	48 8d 3d 6b ad dc 01 	lea    0x1dcad6b(%rip),%rdi        # ffffffff8d248d60 <frame_candidate_abf510+0x1dc9850>
ffffffff8b47dff5:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47dff8:	e8 c3 18 99 ff       	call   ffffffff8ae0f8c0 <handler_628_body-0x66dc80>
ffffffff8b47dffd:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
ffffffff8b47e004:	eb 94                	jmp    ffffffff8b47df9a <frame_candidate_abdad0+0x4ca>
ffffffff8b47e006:	ff 45 b4             	incl   -0x4c(%rbp)
ffffffff8b47e009:	e9 95 fd ff ff       	jmp    ffffffff8b47dda3 <frame_candidate_abdad0+0x2d3>
ffffffff8b47e00e:	ff 45 b8             	incl   -0x48(%rbp)
ffffffff8b47e011:	e9 8d fd ff ff       	jmp    ffffffff8b47dda3 <frame_candidate_abdad0+0x2d3>
ffffffff8b47e016:	48 8d 3d 43 ad dc 01 	lea    0x1dcad43(%rip),%rdi        # ffffffff8d248d60 <frame_candidate_abf510+0x1dc9850>
ffffffff8b47e01d:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b47e020:	e8 9b 18 99 ff       	call   ffffffff8ae0f8c0 <handler_628_body-0x66dc80>
ffffffff8b47e025:	e9 d3 fe ff ff       	jmp    ffffffff8b47defd <frame_candidate_abdad0+0x42d>
ffffffff8b47e02a:	be 68 00 00 00       	mov    $0x68,%esi
ffffffff8b47e02f:	48 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%rdi
ffffffff8b47e036:	e8 b5 af 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47e03b:	49 8d b7 50 01 00 00 	lea    0x150(%r15),%rsi
ffffffff8b47e042:	ba 20 00 00 00       	mov    $0x20,%edx
ffffffff8b47e047:	48 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%rdi
ffffffff8b47e04e:	e8 1d 9b e9 ff       	call   ffffffff8b317b70 <handler_628_body-0x1659d0>
ffffffff8b47e053:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
ffffffff8b47e05a:	4c 63 b5 64 ff ff ff 	movslq -0x9c(%rbp),%r14
ffffffff8b47e061:	4c 8b ad 18 ff ff ff 	mov    -0xe8(%rbp),%r13
ffffffff8b47e068:	48 8b 58 10          	mov    0x10(%rax),%rbx
ffffffff8b47e06c:	48 85 db             	test   %rbx,%rbx
ffffffff8b47e06f:	0f 84 4c fb ff ff    	je     ffffffff8b47dbc1 <frame_candidate_abdad0+0xf1>
ffffffff8b47e075:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
ffffffff8b47e07c:	44 3b 70 08          	cmp    0x8(%rax),%r14d
ffffffff8b47e080:	0f 8d 3b fb ff ff    	jge    ffffffff8b47dbc1 <frame_candidate_abdad0+0xf1>
ffffffff8b47e086:	49 6b c6 68          	imul   $0x68,%r14,%rax
ffffffff8b47e08a:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b47e091:	00 00 
ffffffff8b47e093:	48 8d 35 fd 11 89 00 	lea    0x8911fd(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_abf510+0x88fd87>
ffffffff8b47e09a:	31 d2                	xor    %edx,%edx
ffffffff8b47e09c:	48 01 c3             	add    %rax,%rbx
ffffffff8b47e09f:	e8 3c c3 15 00       	call   ffffffff8b5da3e0 <frame_candidate_abf510+0x15aed0>
ffffffff8b47e0a4:	ba 68 00 00 00       	mov    $0x68,%edx
ffffffff8b47e0a9:	48 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%rdi
ffffffff8b47e0b0:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47e0b3:	e8 18 b1 79 ff       	call   ffffffff8ac191d0 <handler_628_body-0x864370>
ffffffff8b47e0b8:	85 c0                	test   %eax,%eax
ffffffff8b47e0ba:	0f 84 01 fb ff ff    	je     ffffffff8b47dbc1 <frame_candidate_abdad0+0xf1>
ffffffff8b47e0c0:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b47e0c3:	31 f6                	xor    %esi,%esi
ffffffff8b47e0c5:	31 d2                	xor    %edx,%edx
ffffffff8b47e0c7:	e8 a4 87 80 ff       	call   ffffffff8ac86870 <handler_628_body-0x7f6cd0>
ffffffff8b47e0cc:	48 8b 9d 20 ff ff ff 	mov    -0xe0(%rbp),%rbx
ffffffff8b47e0d3:	31 f6                	xor    %esi,%esi
ffffffff8b47e0d5:	31 d2                	xor    %edx,%edx
ffffffff8b47e0d7:	31 c9                	xor    %ecx,%ecx
ffffffff8b47e0d9:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47e0dc:	e8 1f 89 a0 ff       	call   ffffffff8ae86a00 <handler_628_body-0x5f6b40>
ffffffff8b47e0e1:	48 8b bd 50 ff ff ff 	mov    -0xb0(%rbp),%rdi
ffffffff8b47e0e8:	0f b6 8f b1 00 00 00 	movzbl 0xb1(%rdi),%ecx
ffffffff8b47e0ef:	8b 87 58 03 00 00    	mov    0x358(%rdi),%eax
ffffffff8b47e0f5:	c0 e9 05             	shr    $0x5,%cl
ffffffff8b47e0f8:	ff c8                	dec    %eax
ffffffff8b47e0fa:	0f 94 c2             	sete   %dl
ffffffff8b47e0fd:	89 87 58 03 00 00    	mov    %eax,0x358(%rdi)
ffffffff8b47e103:	20 ca                	and    %cl,%dl
ffffffff8b47e105:	80 fa 01             	cmp    $0x1,%dl
ffffffff8b47e108:	75 0c                	jne    ffffffff8b47e116 <frame_candidate_abdad0+0x646>
ffffffff8b47e10a:	48 81 c7 58 03 00 00 	add    $0x358,%rdi
ffffffff8b47e111:	e8 fa 87 14 00       	call   ffffffff8b5c6910 <frame_candidate_abf510+0x147400>
ffffffff8b47e116:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47e119:	31 f6                	xor    %esi,%esi
ffffffff8b47e11b:	31 d2                	xor    %edx,%edx
ffffffff8b47e11d:	31 c9                	xor    %ecx,%ecx
ffffffff8b47e11f:	e8 7c 8e a0 ff       	call   ffffffff8ae86fa0 <handler_628_body-0x5f65a0>
ffffffff8b47e124:	4c 8b b5 48 ff ff ff 	mov    -0xb8(%rbp),%r14
ffffffff8b47e12b:	48 8d 35 65 11 89 00 	lea    0x891165(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_abf510+0x88fd87>
ffffffff8b47e132:	31 d2                	xor    %edx,%edx
ffffffff8b47e134:	49 8b 5e 18          	mov    0x18(%r14),%rbx
ffffffff8b47e138:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b47e13f:	00 00 
ffffffff8b47e141:	e8 9a c2 15 00       	call   ffffffff8b5da3e0 <frame_candidate_abf510+0x15aed0>
ffffffff8b47e146:	48 8d bd 64 ff ff ff 	lea    -0x9c(%rbp),%rdi
ffffffff8b47e14d:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b47e152:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47e155:	e8 76 b0 79 ff       	call   ffffffff8ac191d0 <handler_628_body-0x864370>
ffffffff8b47e15a:	49 83 7e 10 00       	cmpq   $0x0,0x10(%r14)
ffffffff8b47e15f:	74 12                	je     ffffffff8b47e173 <frame_candidate_abdad0+0x6a3>
ffffffff8b47e161:	8b 8d 64 ff ff ff    	mov    -0x9c(%rbp),%ecx
ffffffff8b47e167:	41 3b 4e 08          	cmp    0x8(%r14),%ecx
ffffffff8b47e16b:	b9 0c 00 00 00       	mov    $0xc,%ecx
ffffffff8b47e170:	0f 4f c1             	cmovg  %ecx,%eax
ffffffff8b47e173:	48 8d 1d 96 e1 e5 02 	lea    0x2e5e196(%rip),%rbx        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e17a:	eb 21                	jmp    ffffffff8b47e19d <frame_candidate_abdad0+0x6cd>
ffffffff8b47e17c:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b47e181:	eb 1a                	jmp    ffffffff8b47e19d <frame_candidate_abdad0+0x6cd>
ffffffff8b47e183:	48 81 c1 48 01 00 00 	add    $0x148,%rcx
ffffffff8b47e18a:	31 f6                	xor    %esi,%esi
ffffffff8b47e18c:	31 d2                	xor    %edx,%edx
ffffffff8b47e18e:	48 89 cf             	mov    %rcx,%rdi
ffffffff8b47e191:	31 c9                	xor    %ecx,%ecx
ffffffff8b47e193:	e8 08 8e a0 ff       	call   ffffffff8ae86fa0 <handler_628_body-0x5f65a0>
ffffffff8b47e198:	b8 02 00 00 00       	mov    $0x2,%eax
ffffffff8b47e19d:	48 8b 0b             	mov    (%rbx),%rcx
ffffffff8b47e1a0:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8b47e1a4:	75 12                	jne    ffffffff8b47e1b8 <frame_candidate_abdad0+0x6e8>
ffffffff8b47e1a6:	48 81 c4 c8 00 00 00 	add    $0xc8,%rsp
ffffffff8b47e1ad:	5b                   	pop    %rbx
ffffffff8b47e1ae:	41 5c                	pop    %r12
ffffffff8b47e1b0:	41 5d                	pop    %r13
ffffffff8b47e1b2:	41 5e                	pop    %r14
ffffffff8b47e1b4:	41 5f                	pop    %r15
ffffffff8b47e1b6:	5d                   	pop    %rbp
ffffffff8b47e1b7:	c3                   	ret
ffffffff8b47e1b8:	e8 f3 f4 c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47e1bd:	0f 0b                	ud2
ffffffff8b47e1bf:	90                   	nop

ffffffff8b47e1c0 <frame_candidate_abe1c0>:
ffffffff8b47e1c0:	55                   	push   %rbp
ffffffff8b47e1c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47e1c4:	41 57                	push   %r15
ffffffff8b47e1c6:	41 56                	push   %r14
ffffffff8b47e1c8:	53                   	push   %rbx
ffffffff8b47e1c9:	48 81 ec 08 04 00 00 	sub    $0x408,%rsp
ffffffff8b47e1d0:	4c 8d 3d 39 e1 e5 02 	lea    0x2e5e139(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e1d7:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b47e1da:	49 8b 07             	mov    (%r15),%rax
ffffffff8b47e1dd:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b47e1e1:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b47e1e8:	e8 a3 ad b4 ff       	call   ffffffff8afc8f90 <handler_628_body-0x4b45b0>
ffffffff8b47e1ed:	85 c0                	test   %eax,%eax
ffffffff8b47e1ef:	74 40                	je     ffffffff8b47e231 <frame_candidate_abe1c0+0x71>
ffffffff8b47e1f1:	4c 8d b5 e8 fb ff ff 	lea    -0x418(%rbp),%r14
ffffffff8b47e1f8:	be f8 03 00 00       	mov    $0x3f8,%esi
ffffffff8b47e1fd:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b47e200:	e8 eb ad 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47e205:	48 8b 1b             	mov    (%rbx),%rbx
ffffffff8b47e208:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b47e20f:	00 00 
ffffffff8b47e211:	48 8d 35 7f 10 89 00 	lea    0x89107f(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_abf510+0x88fd87>
ffffffff8b47e218:	31 d2                	xor    %edx,%edx
ffffffff8b47e21a:	e8 c1 c1 15 00       	call   ffffffff8b5da3e0 <frame_candidate_abf510+0x15aed0>
ffffffff8b47e21f:	ba f8 03 00 00       	mov    $0x3f8,%edx
ffffffff8b47e224:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b47e227:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47e22a:	e8 a1 af 79 ff       	call   ffffffff8ac191d0 <handler_628_body-0x864370>
ffffffff8b47e22f:	eb 05                	jmp    ffffffff8b47e236 <frame_candidate_abe1c0+0x76>
ffffffff8b47e231:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b47e236:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b47e239:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8b47e23d:	75 0e                	jne    ffffffff8b47e24d <frame_candidate_abe1c0+0x8d>
ffffffff8b47e23f:	48 81 c4 08 04 00 00 	add    $0x408,%rsp
ffffffff8b47e246:	5b                   	pop    %rbx
ffffffff8b47e247:	41 5e                	pop    %r14
ffffffff8b47e249:	41 5f                	pop    %r15
ffffffff8b47e24b:	5d                   	pop    %rbp
ffffffff8b47e24c:	c3                   	ret
ffffffff8b47e24d:	e8 5e f4 c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47e252:	0f 0b                	ud2
ffffffff8b47e254:	90                   	nop
ffffffff8b47e255:	90                   	nop
ffffffff8b47e256:	90                   	nop
ffffffff8b47e257:	90                   	nop
ffffffff8b47e258:	90                   	nop
ffffffff8b47e259:	90                   	nop
ffffffff8b47e25a:	90                   	nop
ffffffff8b47e25b:	90                   	nop
ffffffff8b47e25c:	90                   	nop
ffffffff8b47e25d:	90                   	nop
ffffffff8b47e25e:	90                   	nop
ffffffff8b47e25f:	90                   	nop

ffffffff8b47e260 <frame_candidate_abe260>:
ffffffff8b47e260:	55                   	push   %rbp
ffffffff8b47e261:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47e264:	41 57                	push   %r15
ffffffff8b47e266:	41 56                	push   %r14
ffffffff8b47e268:	41 55                	push   %r13
ffffffff8b47e26a:	41 54                	push   %r12
ffffffff8b47e26c:	53                   	push   %rbx
ffffffff8b47e26d:	48 81 ec d8 01 00 00 	sub    $0x1d8,%rsp
ffffffff8b47e274:	48 8d 05 95 e0 e5 02 	lea    0x2e5e095(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e27b:	48 89 bd 08 fe ff ff 	mov    %rdi,-0x1f8(%rbp)
ffffffff8b47e282:	48 8d 9d 58 fe ff ff 	lea    -0x1a8(%rbp),%rbx
ffffffff8b47e289:	49 89 f4             	mov    %rsi,%r12
ffffffff8b47e28c:	be 60 00 00 00       	mov    $0x60,%esi
ffffffff8b47e291:	49 89 cd             	mov    %rcx,%r13
ffffffff8b47e294:	41 89 d6             	mov    %edx,%r14d
ffffffff8b47e297:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47e29a:	48 8b 00             	mov    (%rax),%rax
ffffffff8b47e29d:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b47e2a1:	e8 4a ad 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47e2a6:	48 8b 3d 33 33 c1 02 	mov    0x2c13333(%rip),%rdi        # ffffffff8e0915e0 <frame_candidate_abf510+0x2c120d0>
ffffffff8b47e2ad:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b47e2b2:	31 f6                	xor    %esi,%esi
ffffffff8b47e2b4:	e8 c7 d5 97 ff       	call   ffffffff8adfb880 <handler_628_body-0x681cc0>
ffffffff8b47e2b9:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b47e2c0:	00 00 
ffffffff8b47e2c2:	48 8d 35 bb bd 89 00 	lea    0x89bdbb(%rip),%rsi        # ffffffff8bd1a084 <frame_candidate_abf510+0x89ab74>
ffffffff8b47e2c9:	31 d2                	xor    %edx,%edx
ffffffff8b47e2cb:	49 89 c7             	mov    %rax,%r15
ffffffff8b47e2ce:	e8 0d c1 15 00       	call   ffffffff8b5da3e0 <frame_candidate_abf510+0x15aed0>
ffffffff8b47e2d3:	ba 00 04 00 00       	mov    $0x400,%edx
ffffffff8b47e2d8:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47e2db:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b47e2de:	31 c9                	xor    %ecx,%ecx
ffffffff8b47e2e0:	e8 1b b6 79 ff       	call   ffffffff8ac19900 <handler_628_body-0x863c40>
ffffffff8b47e2e5:	85 c0                	test   %eax,%eax
ffffffff8b47e2e7:	74 0b                	je     ffffffff8b47e2f4 <frame_candidate_abe260+0x94>
ffffffff8b47e2e9:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47e2ec:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b47e2ef:	e9 f0 00 00 00       	jmp    ffffffff8b47e3e4 <frame_candidate_abe260+0x184>
ffffffff8b47e2f4:	4c 89 ad 38 fe ff ff 	mov    %r13,-0x1c8(%rbp)
ffffffff8b47e2fb:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b47e2ff:	4d 89 fd             	mov    %r15,%r13
ffffffff8b47e302:	4d 89 f8             	mov    %r15,%r8
ffffffff8b47e305:	4c 8b bd 08 fe ff ff 	mov    -0x1f8(%rbp),%r15
ffffffff8b47e30c:	4c 8d a5 e8 fe ff ff 	lea    -0x118(%rbp),%r12
ffffffff8b47e313:	ba 44 01 00 00       	mov    $0x144,%edx
ffffffff8b47e318:	31 f6                	xor    %esi,%esi
ffffffff8b47e31a:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b47e31f:	41 b9 9c ff ff ff    	mov    $0xffffff9c,%r9d
ffffffff8b47e325:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47e328:	41 57                	push   %r15
ffffffff8b47e32a:	6a 00                	push   $0x0
ffffffff8b47e32c:	6a 00                	push   $0x0
ffffffff8b47e32e:	e8 ad c3 b3 ff       	call   ffffffff8afba6e0 <handler_628_body-0x4c2e60>
ffffffff8b47e333:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b47e337:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47e33a:	e8 e1 a8 b3 ff       	call   ffffffff8afb8c20 <handler_628_body-0x4c4920>
ffffffff8b47e33f:	85 c0                	test   %eax,%eax
ffffffff8b47e341:	74 08                	je     ffffffff8b47e34b <frame_candidate_abe260+0xeb>
ffffffff8b47e343:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47e346:	e9 96 00 00 00       	jmp    ffffffff8b47e3e1 <frame_candidate_abe260+0x181>
ffffffff8b47e34b:	4c 8b a5 48 ff ff ff 	mov    -0xb8(%rbp),%r12
ffffffff8b47e352:	48 8d bd e8 fe ff ff 	lea    -0x118(%rbp),%rdi
ffffffff8b47e359:	be 0c 00 00 00       	mov    $0xc,%esi
ffffffff8b47e35e:	e8 1d c4 b3 ff       	call   ffffffff8afba780 <handler_628_body-0x4c2dc0>
ffffffff8b47e363:	4c 89 e2             	mov    %r12,%rdx
ffffffff8b47e366:	41 bc 16 00 00 00    	mov    $0x16,%r12d
ffffffff8b47e36c:	83 ba d4 01 00 00 01 	cmpl   $0x1,0x1d4(%rdx)
ffffffff8b47e373:	75 64                	jne    ffffffff8b47e3d9 <frame_candidate_abe260+0x179>
ffffffff8b47e375:	49 8b 87 40 01 00 00 	mov    0x140(%r15),%rax
ffffffff8b47e37c:	48 8d 0d 75 c4 01 01 	lea    0x101c475(%rip),%rcx        # ffffffff8c49a7f8 <frame_candidate_abf510+0x101b2e8>
ffffffff8b47e383:	48 8d b5 b8 fe ff ff 	lea    -0x148(%rbp),%rsi
ffffffff8b47e38a:	48 89 95 28 fe ff ff 	mov    %rdx,-0x1d8(%rbp)
ffffffff8b47e391:	48 89 8d b8 fe ff ff 	mov    %rcx,-0x148(%rbp)
ffffffff8b47e398:	48 89 95 c0 fe ff ff 	mov    %rdx,-0x140(%rbp)
ffffffff8b47e39f:	c7 85 c8 fe ff ff 01 	movl   $0x1,-0x138(%rbp)
ffffffff8b47e3a6:	00 00 00 
ffffffff8b47e3a9:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
ffffffff8b47e3b0:	4c 89 bd d8 fe ff ff 	mov    %r15,-0x128(%rbp)
ffffffff8b47e3b7:	48 c7 85 e0 fe ff ff 	movq   $0x0,-0x120(%rbp)
ffffffff8b47e3be:	00 00 00 00 
ffffffff8b47e3c2:	48 8b 7a 08          	mov    0x8(%rdx),%rdi
ffffffff8b47e3c6:	e8 35 d7 ac ff       	call   ffffffff8af4bb00 <handler_628_body-0x531a40>
ffffffff8b47e3cb:	48 8b 95 28 fe ff ff 	mov    -0x1d8(%rbp),%rdx
ffffffff8b47e3d2:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47e3d5:	85 c0                	test   %eax,%eax
ffffffff8b47e3d7:	74 42                	je     ffffffff8b47e41b <frame_candidate_abe260+0x1bb>
ffffffff8b47e3d9:	48 89 d7             	mov    %rdx,%rdi
ffffffff8b47e3dc:	e8 5f c0 a8 ff       	call   ffffffff8af0a440 <handler_628_body-0x573100>
ffffffff8b47e3e1:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b47e3e4:	48 8b 3d f5 31 c1 02 	mov    0x2c131f5(%rip),%rdi        # ffffffff8e0915e0 <frame_candidate_abf510+0x2c120d0>
ffffffff8b47e3eb:	31 d2                	xor    %edx,%edx
ffffffff8b47e3ed:	e8 ce dc 97 ff       	call   ffffffff8adfc0c0 <handler_628_body-0x681480>
ffffffff8b47e3f2:	48 8d 05 17 df e5 02 	lea    0x2e5df17(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e3f9:	48 8b 00             	mov    (%rax),%rax
ffffffff8b47e3fc:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b47e400:	0f 85 9c 03 00 00    	jne    ffffffff8b47e7a2 <frame_candidate_abe260+0x542>
ffffffff8b47e406:	44 89 e0             	mov    %r12d,%eax
ffffffff8b47e409:	48 81 c4 d8 01 00 00 	add    $0x1d8,%rsp
ffffffff8b47e410:	5b                   	pop    %rbx
ffffffff8b47e411:	41 5c                	pop    %r12
ffffffff8b47e413:	41 5d                	pop    %r13
ffffffff8b47e415:	41 5e                	pop    %r14
ffffffff8b47e417:	41 5f                	pop    %r15
ffffffff8b47e419:	5d                   	pop    %rbp
ffffffff8b47e41a:	c3                   	ret
ffffffff8b47e41b:	4d 8b 8f 40 01 00 00 	mov    0x140(%r15),%r9
ffffffff8b47e422:	48 89 d6             	mov    %rdx,%rsi
ffffffff8b47e425:	bf 07 00 00 00       	mov    $0x7,%edi
ffffffff8b47e42a:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b47e42f:	31 d2                	xor    %edx,%edx
ffffffff8b47e431:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b47e434:	e8 87 f5 99 ff       	call   ffffffff8ae1d9c0 <handler_628_body-0x65fb80>
ffffffff8b47e439:	48 89 85 50 fe ff ff 	mov    %rax,-0x1b0(%rbp)
ffffffff8b47e440:	48 85 c0             	test   %rax,%rax
ffffffff8b47e443:	74 41                	je     ffffffff8b47e486 <frame_candidate_abe260+0x226>
ffffffff8b47e445:	48 8d 78 18          	lea    0x18(%rax),%rdi
ffffffff8b47e449:	49 89 c4             	mov    %rax,%r12
ffffffff8b47e44c:	31 f6                	xor    %esi,%esi
ffffffff8b47e44e:	31 d2                	xor    %edx,%edx
ffffffff8b47e450:	e8 4b 62 d1 ff       	call   ffffffff8b1946a0 <handler_628_body-0x2e8ea0>
ffffffff8b47e455:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47e458:	e8 f3 33 b7 ff       	call   ffffffff8aff1850 <handler_628_body-0x48bcf0>
ffffffff8b47e45d:	85 c0                	test   %eax,%eax
ffffffff8b47e45f:	74 33                	je     ffffffff8b47e494 <frame_candidate_abe260+0x234>
ffffffff8b47e461:	89 c2                	mov    %eax,%edx
ffffffff8b47e463:	48 8d 3d 61 ef 86 00 	lea    0x86ef61(%rip),%rdi        # ffffffff8bced3cb <frame_candidate_abf510+0x86debb>
ffffffff8b47e46a:	48 8d 35 5f 27 8c 00 	lea    0x8c275f(%rip),%rsi        # ffffffff8bd40bd0 <frame_candidate_abf510+0x8c16c0>
ffffffff8b47e471:	31 c0                	xor    %eax,%eax
ffffffff8b47e473:	e8 98 ef 79 ff       	call   ffffffff8ac1d410 <handler_628_body-0x860130>
ffffffff8b47e478:	41 bc 08 00 00 00    	mov    $0x8,%r12d
ffffffff8b47e47e:	4d 89 fe             	mov    %r15,%r14
ffffffff8b47e481:	e9 5e 02 00 00       	jmp    ffffffff8b47e6e4 <frame_candidate_abe260+0x484>
ffffffff8b47e486:	41 bc 0c 00 00 00    	mov    $0xc,%r12d
ffffffff8b47e48c:	4d 89 fe             	mov    %r15,%r14
ffffffff8b47e48f:	e9 50 02 00 00       	jmp    ffffffff8b47e6e4 <frame_candidate_abe260+0x484>
ffffffff8b47e494:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b47e497:	e8 04 3e b7 ff       	call   ffffffff8aff22a0 <handler_628_body-0x48b2a0>
ffffffff8b47e49c:	0f b7 50 10          	movzwl 0x10(%rax),%edx
ffffffff8b47e4a0:	8d 8a 00 02 ff ff    	lea    -0xfe00(%rdx),%ecx
ffffffff8b47e4a6:	83 f9 10             	cmp    $0x10,%ecx
ffffffff8b47e4a9:	77 0a                	ja     ffffffff8b47e4b5 <frame_candidate_abe260+0x255>
ffffffff8b47e4ab:	be 03 00 01 00       	mov    $0x10003,%esi
ffffffff8b47e4b0:	0f a3 ce             	bt     %ecx,%esi
ffffffff8b47e4b3:	72 09                	jb     ffffffff8b47e4be <frame_candidate_abe260+0x25e>
ffffffff8b47e4b5:	83 fa 02             	cmp    $0x2,%edx
ffffffff8b47e4b8:	0f 85 fc 01 00 00    	jne    ffffffff8b47e6ba <frame_candidate_abe260+0x45a>
ffffffff8b47e4be:	0f b7 48 38          	movzwl 0x38(%rax),%ecx
ffffffff8b47e4c2:	48 85 c9             	test   %rcx,%rcx
ffffffff8b47e4c5:	0f 84 d8 01 00 00    	je     ffffffff8b47e6a3 <frame_candidate_abe260+0x443>
ffffffff8b47e4cb:	48 89 c2             	mov    %rax,%rdx
ffffffff8b47e4ce:	48 6b f1 38          	imul   $0x38,%rcx,%rsi
ffffffff8b47e4d2:	31 ff                	xor    %edi,%edi
ffffffff8b47e4d4:	48 83 c2 40          	add    $0x40,%rdx
ffffffff8b47e4d8:	81 7c 38 40 01 00 00 	cmpl   $0x61000001,0x40(%rax,%rdi,1)
ffffffff8b47e4df:	61 
ffffffff8b47e4e0:	74 0e                	je     ffffffff8b47e4f0 <frame_candidate_abe260+0x290>
ffffffff8b47e4e2:	48 83 c7 38          	add    $0x38,%rdi
ffffffff8b47e4e6:	48 39 fe             	cmp    %rdi,%rsi
ffffffff8b47e4e9:	75 ed                	jne    ffffffff8b47e4d8 <frame_candidate_abe260+0x278>
ffffffff8b47e4eb:	e9 b3 01 00 00       	jmp    ffffffff8b47e6a3 <frame_candidate_abe260+0x443>
ffffffff8b47e4f0:	4c 8b 44 38 60       	mov    0x60(%rax,%rdi,1),%r8
ffffffff8b47e4f5:	4d 85 c0             	test   %r8,%r8
ffffffff8b47e4f8:	0f 84 a5 01 00 00    	je     ffffffff8b47e6a3 <frame_candidate_abe260+0x443>
ffffffff8b47e4fe:	48 8b 44 38 50       	mov    0x50(%rax,%rdi,1),%rax
ffffffff8b47e503:	31 f6                	xor    %esi,%esi
ffffffff8b47e505:	eb 10                	jmp    ffffffff8b47e517 <frame_candidate_abe260+0x2b7>
ffffffff8b47e507:	48 ff c6             	inc    %rsi
ffffffff8b47e50a:	48 83 c2 38          	add    $0x38,%rdx
ffffffff8b47e50e:	48 39 f1             	cmp    %rsi,%rcx
ffffffff8b47e511:	0f 84 8c 01 00 00    	je     ffffffff8b47e6a3 <frame_candidate_abe260+0x443>
ffffffff8b47e517:	8b 3a                	mov    (%rdx),%edi
ffffffff8b47e519:	81 ff 10 00 00 61    	cmp    $0x61000010,%edi
ffffffff8b47e51f:	74 05                	je     ffffffff8b47e526 <frame_candidate_abe260+0x2c6>
ffffffff8b47e521:	83 ff 01             	cmp    $0x1,%edi
ffffffff8b47e524:	75 e1                	jne    ffffffff8b47e507 <frame_candidate_abe260+0x2a7>
ffffffff8b47e526:	49 89 c4             	mov    %rax,%r12
ffffffff8b47e529:	4c 2b 62 10          	sub    0x10(%rdx),%r12
ffffffff8b47e52d:	72 d8                	jb     ffffffff8b47e507 <frame_candidate_abe260+0x2a7>
ffffffff8b47e52f:	48 8b 7a 28          	mov    0x28(%rdx),%rdi
ffffffff8b47e533:	4c 29 c7             	sub    %r8,%rdi
ffffffff8b47e536:	72 cf                	jb     ffffffff8b47e507 <frame_candidate_abe260+0x2a7>
ffffffff8b47e538:	49 39 fc             	cmp    %rdi,%r12
ffffffff8b47e53b:	77 ca                	ja     ffffffff8b47e507 <frame_candidate_abe260+0x2a7>
ffffffff8b47e53d:	49 83 f8 60          	cmp    $0x60,%r8
ffffffff8b47e541:	b8 60 00 00 00       	mov    $0x60,%eax
ffffffff8b47e546:	4c 89 e1             	mov    %r12,%rcx
ffffffff8b47e549:	4c 89 e2             	mov    %r12,%rdx
ffffffff8b47e54c:	48 89 b5 20 fe ff ff 	mov    %rsi,-0x1e0(%rbp)
ffffffff8b47e553:	49 0f 42 c0          	cmovb  %r8,%rax
ffffffff8b47e557:	48 81 e1 00 c0 ff ff 	and    $0xffffffffffffc000,%rcx
ffffffff8b47e55e:	48 81 e2 00 c0 ff ff 	and    $0xffffffffffffc000,%rdx
ffffffff8b47e565:	48 f7 d9             	neg    %rcx
ffffffff8b47e568:	48 89 85 48 fe ff ff 	mov    %rax,-0x1b8(%rbp)
ffffffff8b47e56f:	48 89 95 40 fe ff ff 	mov    %rdx,-0x1c0(%rbp)
ffffffff8b47e576:	48 89 8d 30 fe ff ff 	mov    %rcx,-0x1d0(%rbp)
ffffffff8b47e57d:	48 8b bd 50 fe ff ff 	mov    -0x1b0(%rbp),%rdi
ffffffff8b47e584:	48 8b 95 40 fe ff ff 	mov    -0x1c0(%rbp),%rdx
ffffffff8b47e58b:	e8 e0 25 b7 ff       	call   ffffffff8aff0b70 <handler_628_body-0x48c9d0>
ffffffff8b47e590:	48 8b bd 50 fe ff ff 	mov    -0x1b0(%rbp),%rdi
ffffffff8b47e597:	48 89 c6             	mov    %rax,%rsi
ffffffff8b47e59a:	e8 31 be a7 ff       	call   ffffffff8aefa3d0 <handler_628_body-0x583170>
ffffffff8b47e59f:	48 85 c0             	test   %rax,%rax
ffffffff8b47e5a2:	0f 84 a9 01 00 00    	je     ffffffff8b47e751 <frame_candidate_abe260+0x4f1>
ffffffff8b47e5a8:	48 8b 8d 40 fe ff ff 	mov    -0x1c0(%rbp),%rcx
ffffffff8b47e5af:	8b 3d e3 ac 08 03    	mov    0x308ace3(%rip),%edi        # ffffffff8e509298 <frame_candidate_abf510+0x3089d88>
ffffffff8b47e5b5:	48 be 00 00 00 00 00 	movabs $0xffff800000000000,%rsi
ffffffff8b47e5bc:	80 ff ff 
ffffffff8b47e5bf:	48 89 85 18 fe ff ff 	mov    %rax,-0x1e8(%rbp)
ffffffff8b47e5c6:	48 81 c1 00 40 00 00 	add    $0x4000,%rcx
ffffffff8b47e5cd:	48 89 ca             	mov    %rcx,%rdx
ffffffff8b47e5d0:	48 89 8d 40 fe ff ff 	mov    %rcx,-0x1c0(%rbp)
ffffffff8b47e5d7:	8b 8d 48 fe ff ff    	mov    -0x1b8(%rbp),%ecx
ffffffff8b47e5dd:	4c 29 e2             	sub    %r12,%rdx
ffffffff8b47e5e0:	48 39 ca             	cmp    %rcx,%rdx
ffffffff8b47e5e3:	48 0f 4d d1          	cmovge %rcx,%rdx
ffffffff8b47e5e7:	8b 0d a7 ac 08 03    	mov    0x308aca7(%rip),%ecx        # ffffffff8e509294 <frame_candidate_abf510+0x3089d84>
ffffffff8b47e5ed:	48 c1 e7 1e          	shl    $0x1e,%rdi
ffffffff8b47e5f1:	48 63 d2             	movslq %edx,%rdx
ffffffff8b47e5f4:	48 89 95 10 fe ff ff 	mov    %rdx,-0x1f0(%rbp)
ffffffff8b47e5fb:	48 c1 e1 27          	shl    $0x27,%rcx
ffffffff8b47e5ff:	48 09 cf             	or     %rcx,%rdi
ffffffff8b47e602:	48 8b 8d 30 fe ff ff 	mov    -0x1d0(%rbp),%rcx
ffffffff8b47e609:	48 09 f7             	or     %rsi,%rdi
ffffffff8b47e60c:	48 03 78 30          	add    0x30(%rax),%rdi
ffffffff8b47e610:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47e613:	4c 01 e1             	add    %r12,%rcx
ffffffff8b47e616:	48 01 cf             	add    %rcx,%rdi
ffffffff8b47e619:	e8 c2 b5 79 ff       	call   ffffffff8ac19be0 <handler_628_body-0x863960>
ffffffff8b47e61e:	48 8b bd 18 fe ff ff 	mov    -0x1e8(%rbp),%rdi
ffffffff8b47e625:	e8 e6 bd a7 ff       	call   ffffffff8aefa410 <handler_628_body-0x583130>
ffffffff8b47e62a:	48 81 85 30 fe ff ff 	addq   $0xffffffffffffc000,-0x1d0(%rbp)
ffffffff8b47e631:	00 c0 ff ff 
ffffffff8b47e635:	48 8b 8d 10 fe ff ff 	mov    -0x1f0(%rbp),%rcx
ffffffff8b47e63c:	48 8b 85 48 fe ff ff 	mov    -0x1b8(%rbp),%rax
ffffffff8b47e643:	48 8b b5 20 fe ff ff 	mov    -0x1e0(%rbp),%rsi
ffffffff8b47e64a:	29 c8                	sub    %ecx,%eax
ffffffff8b47e64c:	48 01 cb             	add    %rcx,%rbx
ffffffff8b47e64f:	49 01 cc             	add    %rcx,%r12
ffffffff8b47e652:	48 89 85 48 fe ff ff 	mov    %rax,-0x1b8(%rbp)
ffffffff8b47e659:	85 c0                	test   %eax,%eax
ffffffff8b47e65b:	0f 8f 1c ff ff ff    	jg     ffffffff8b47e57d <frame_candidate_abe260+0x31d>
ffffffff8b47e661:	8b 95 60 fe ff ff    	mov    -0x1a0(%rbp),%edx
ffffffff8b47e667:	48 8b 8d 58 fe ff ff 	mov    -0x1a8(%rbp),%rcx
ffffffff8b47e66e:	81 fa 4f 52 42 49    	cmp    $0x4942524f,%edx
ffffffff8b47e674:	0f 95 c0             	setne  %al
ffffffff8b47e677:	48 83 f9 14          	cmp    $0x14,%rcx
ffffffff8b47e67b:	40 0f 92 c6          	setb   %sil
ffffffff8b47e67f:	40 08 c6             	or     %al,%sil
ffffffff8b47e682:	40 80 fe 01          	cmp    $0x1,%sil
ffffffff8b47e686:	0f 85 d0 00 00 00    	jne    ffffffff8b47e75c <frame_candidate_abe260+0x4fc>
ffffffff8b47e68c:	48 8d 3d c3 8f 7c 00 	lea    0x7c8fc3(%rip),%rdi        # ffffffff8bc47656 <frame_candidate_abf510+0x7c8146>
ffffffff8b47e693:	48 8d 35 36 25 8c 00 	lea    0x8c2536(%rip),%rsi        # ffffffff8bd40bd0 <frame_candidate_abf510+0x8c16c0>
ffffffff8b47e69a:	31 c0                	xor    %eax,%eax
ffffffff8b47e69c:	e8 6f ed 79 ff       	call   ffffffff8ac1d410 <handler_628_body-0x860130>
ffffffff8b47e6a1:	eb 2c                	jmp    ffffffff8b47e6cf <frame_candidate_abe260+0x46f>
ffffffff8b47e6a3:	48 8d 3d c0 e5 88 00 	lea    0x88e5c0(%rip),%rdi        # ffffffff8bd0cc6a <frame_candidate_abf510+0x88d75a>
ffffffff8b47e6aa:	48 8d 35 1f 25 8c 00 	lea    0x8c251f(%rip),%rsi        # ffffffff8bd40bd0 <frame_candidate_abf510+0x8c16c0>
ffffffff8b47e6b1:	31 c0                	xor    %eax,%eax
ffffffff8b47e6b3:	e8 58 ed 79 ff       	call   ffffffff8ac1d410 <handler_628_body-0x860130>
ffffffff8b47e6b8:	eb 15                	jmp    ffffffff8b47e6cf <frame_candidate_abe260+0x46f>
ffffffff8b47e6ba:	48 8d 3d 8b 85 8b 00 	lea    0x8b858b(%rip),%rdi        # ffffffff8bd36c4c <frame_candidate_abf510+0x8b773c>
ffffffff8b47e6c1:	48 8d 35 08 25 8c 00 	lea    0x8c2508(%rip),%rsi        # ffffffff8bd40bd0 <frame_candidate_abf510+0x8c16c0>
ffffffff8b47e6c8:	31 c0                	xor    %eax,%eax
ffffffff8b47e6ca:	e8 41 ed 79 ff       	call   ffffffff8ac1d410 <handler_628_body-0x860130>
ffffffff8b47e6cf:	41 bc 08 00 00 00    	mov    $0x8,%r12d
ffffffff8b47e6d5:	48 8b bd 50 fe ff ff 	mov    -0x1b0(%rbp),%rdi
ffffffff8b47e6dc:	4d 89 fe             	mov    %r15,%r14
ffffffff8b47e6df:	e8 0c 3b b7 ff       	call   ffffffff8aff21f0 <handler_628_body-0x48b350>
ffffffff8b47e6e4:	49 8b 86 40 01 00 00 	mov    0x140(%r14),%rax
ffffffff8b47e6eb:	48 8d 0d 06 c2 01 01 	lea    0x101c206(%rip),%rcx        # ffffffff8c49a8f8 <frame_candidate_abf510+0x101b3e8>
ffffffff8b47e6f2:	4c 8b bd 28 fe ff ff 	mov    -0x1d8(%rbp),%r15
ffffffff8b47e6f9:	48 8d b5 b8 fe ff ff 	lea    -0x148(%rbp),%rsi
ffffffff8b47e700:	48 89 8d b8 fe ff ff 	mov    %rcx,-0x148(%rbp)
ffffffff8b47e707:	4c 89 bd c0 fe ff ff 	mov    %r15,-0x140(%rbp)
ffffffff8b47e70e:	c7 85 c8 fe ff ff 01 	movl   $0x1,-0x138(%rbp)
ffffffff8b47e715:	00 00 00 
ffffffff8b47e718:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
ffffffff8b47e71f:	4c 89 b5 d8 fe ff ff 	mov    %r14,-0x128(%rbp)
ffffffff8b47e726:	49 8b 7f 08          	mov    0x8(%r15),%rdi
ffffffff8b47e72a:	e8 b1 d5 ac ff       	call   ffffffff8af4bce0 <handler_628_body-0x531860>
ffffffff8b47e72f:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47e732:	e8 09 bd a8 ff       	call   ffffffff8af0a440 <handler_628_body-0x573100>
ffffffff8b47e737:	48 8b bd 50 fe ff ff 	mov    -0x1b0(%rbp),%rdi
ffffffff8b47e73e:	48 85 ff             	test   %rdi,%rdi
ffffffff8b47e741:	0f 84 9a fc ff ff    	je     ffffffff8b47e3e1 <frame_candidate_abe260+0x181>
ffffffff8b47e747:	e8 54 34 9a ff       	call   ffffffff8ae21ba0 <handler_628_body-0x65b9a0>
ffffffff8b47e74c:	e9 90 fc ff ff       	jmp    ffffffff8b47e3e1 <frame_candidate_abe260+0x181>
ffffffff8b47e751:	41 bc 05 00 00 00    	mov    $0x5,%r12d
ffffffff8b47e757:	e9 79 ff ff ff       	jmp    ffffffff8b47e6d5 <frame_candidate_abe260+0x475>
ffffffff8b47e75c:	41 83 fe 04          	cmp    $0x4,%r14d
ffffffff8b47e760:	75 08                	jne    ffffffff8b47e76a <frame_candidate_abe260+0x50a>
ffffffff8b47e762:	8b 85 68 fe ff ff    	mov    -0x198(%rbp),%eax
ffffffff8b47e768:	eb 0f                	jmp    ffffffff8b47e779 <frame_candidate_abe260+0x519>
ffffffff8b47e76a:	83 bd 64 fe ff ff 04 	cmpl   $0x4,-0x19c(%rbp)
ffffffff8b47e771:	72 17                	jb     ffffffff8b47e78a <frame_candidate_abe260+0x52a>
ffffffff8b47e773:	8b 85 6c fe ff ff    	mov    -0x194(%rbp),%eax
ffffffff8b47e779:	48 8b 8d 38 fe ff ff 	mov    -0x1c8(%rbp),%rcx
ffffffff8b47e780:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47e783:	89 01                	mov    %eax,(%rcx)
ffffffff8b47e785:	e9 4b ff ff ff       	jmp    ffffffff8b47e6d5 <frame_candidate_abe260+0x475>
ffffffff8b47e78a:	48 8b 85 38 fe ff ff 	mov    -0x1c8(%rbp),%rax
ffffffff8b47e791:	41 bc 16 00 00 00    	mov    $0x16,%r12d
ffffffff8b47e797:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
ffffffff8b47e79d:	e9 33 ff ff ff       	jmp    ffffffff8b47e6d5 <frame_candidate_abe260+0x475>
ffffffff8b47e7a2:	e8 09 ef c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47e7a7:	0f 0b                	ud2
ffffffff8b47e7a9:	90                   	nop
ffffffff8b47e7aa:	90                   	nop
ffffffff8b47e7ab:	90                   	nop
ffffffff8b47e7ac:	90                   	nop
ffffffff8b47e7ad:	90                   	nop
ffffffff8b47e7ae:	90                   	nop
ffffffff8b47e7af:	90                   	nop

ffffffff8b47e7b0 <frame_candidate_abe7b0>:
ffffffff8b47e7b0:	55                   	push   %rbp
ffffffff8b47e7b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47e7b4:	41 57                	push   %r15
ffffffff8b47e7b6:	41 56                	push   %r14
ffffffff8b47e7b8:	53                   	push   %rbx
ffffffff8b47e7b9:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b47e7bd:	4c 8d 3d 4c db e5 02 	lea    0x2e5db4c(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e7c4:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b47e7c7:	49 89 f6             	mov    %rsi,%r14
ffffffff8b47e7ca:	49 8b 07             	mov    (%r15),%rax
ffffffff8b47e7cd:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b47e7d1:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b47e7d8:	e8 b3 a7 b4 ff       	call   ffffffff8afc8f90 <handler_628_body-0x4b45b0>
ffffffff8b47e7dd:	85 c0                	test   %eax,%eax
ffffffff8b47e7df:	74 28                	je     ffffffff8b47e809 <frame_candidate_abe7b0+0x59>
ffffffff8b47e7e1:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
ffffffff8b47e7e8:	48 8d 4d dc          	lea    -0x24(%rbp),%rcx
ffffffff8b47e7ec:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47e7ef:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b47e7f4:	49 8b 36             	mov    (%r14),%rsi
ffffffff8b47e7f7:	e8 64 fa ff ff       	call   ffffffff8b47e260 <frame_candidate_abe260>
ffffffff8b47e7fc:	48 63 4d dc          	movslq -0x24(%rbp),%rcx
ffffffff8b47e800:	48 89 8b 08 04 00 00 	mov    %rcx,0x408(%rbx)
ffffffff8b47e807:	eb 05                	jmp    ffffffff8b47e80e <frame_candidate_abe7b0+0x5e>
ffffffff8b47e809:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b47e80e:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b47e811:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8b47e815:	75 0b                	jne    ffffffff8b47e822 <frame_candidate_abe7b0+0x72>
ffffffff8b47e817:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b47e81b:	5b                   	pop    %rbx
ffffffff8b47e81c:	41 5e                	pop    %r14
ffffffff8b47e81e:	41 5f                	pop    %r15
ffffffff8b47e820:	5d                   	pop    %rbp
ffffffff8b47e821:	c3                   	ret
ffffffff8b47e822:	e8 89 ee c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47e827:	0f 0b                	ud2
ffffffff8b47e829:	90                   	nop
ffffffff8b47e82a:	90                   	nop
ffffffff8b47e82b:	90                   	nop
ffffffff8b47e82c:	90                   	nop
ffffffff8b47e82d:	90                   	nop
ffffffff8b47e82e:	90                   	nop
ffffffff8b47e82f:	90                   	nop

ffffffff8b47e830 <frame_candidate_abe830>:
ffffffff8b47e830:	55                   	push   %rbp
ffffffff8b47e831:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47e834:	41 57                	push   %r15
ffffffff8b47e836:	41 56                	push   %r14
ffffffff8b47e838:	53                   	push   %rbx
ffffffff8b47e839:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b47e83d:	4c 8d 3d cc da e5 02 	lea    0x2e5dacc(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e844:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b47e847:	49 89 f6             	mov    %rsi,%r14
ffffffff8b47e84a:	49 8b 07             	mov    (%r15),%rax
ffffffff8b47e84d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b47e851:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b47e858:	e8 33 a7 b4 ff       	call   ffffffff8afc8f90 <handler_628_body-0x4b45b0>
ffffffff8b47e85d:	85 c0                	test   %eax,%eax
ffffffff8b47e85f:	74 28                	je     ffffffff8b47e889 <frame_candidate_abe830+0x59>
ffffffff8b47e861:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
ffffffff8b47e868:	48 8d 4d dc          	lea    -0x24(%rbp),%rcx
ffffffff8b47e86c:	48 89 df             	mov    %rbx,%rdi
ffffffff8b47e86f:	ba 05 00 00 00       	mov    $0x5,%edx
ffffffff8b47e874:	49 8b 36             	mov    (%r14),%rsi
ffffffff8b47e877:	e8 e4 f9 ff ff       	call   ffffffff8b47e260 <frame_candidate_abe260>
ffffffff8b47e87c:	48 63 4d dc          	movslq -0x24(%rbp),%rcx
ffffffff8b47e880:	48 89 8b 08 04 00 00 	mov    %rcx,0x408(%rbx)
ffffffff8b47e887:	eb 05                	jmp    ffffffff8b47e88e <frame_candidate_abe830+0x5e>
ffffffff8b47e889:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b47e88e:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8b47e891:	48 3b 4d e0          	cmp    -0x20(%rbp),%rcx
ffffffff8b47e895:	75 0b                	jne    ffffffff8b47e8a2 <frame_candidate_abe830+0x72>
ffffffff8b47e897:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b47e89b:	5b                   	pop    %rbx
ffffffff8b47e89c:	41 5e                	pop    %r14
ffffffff8b47e89e:	41 5f                	pop    %r15
ffffffff8b47e8a0:	5d                   	pop    %rbp
ffffffff8b47e8a1:	c3                   	ret
ffffffff8b47e8a2:	e8 09 ee c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47e8a7:	0f 0b                	ud2
ffffffff8b47e8a9:	90                   	nop
ffffffff8b47e8aa:	90                   	nop
ffffffff8b47e8ab:	90                   	nop
ffffffff8b47e8ac:	90                   	nop
ffffffff8b47e8ad:	90                   	nop
ffffffff8b47e8ae:	90                   	nop
ffffffff8b47e8af:	90                   	nop

ffffffff8b47e8b0 <frame_candidate_abe8b0>:
ffffffff8b47e8b0:	55                   	push   %rbp
ffffffff8b47e8b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47e8b4:	41 57                	push   %r15
ffffffff8b47e8b6:	41 56                	push   %r14
ffffffff8b47e8b8:	41 55                	push   %r13
ffffffff8b47e8ba:	41 54                	push   %r12
ffffffff8b47e8bc:	53                   	push   %rbx
ffffffff8b47e8bd:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b47e8c1:	4c 8d 2d 48 da e5 02 	lea    0x2e5da48(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_abf510+0x2e5ce00>
ffffffff8b47e8c8:	49 89 ff             	mov    %rdi,%r15
ffffffff8b47e8cb:	31 ff                	xor    %edi,%edi
ffffffff8b47e8cd:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8b47e8d1:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b47e8d5:	48 8b 46 18          	mov    0x18(%rsi),%rax
ffffffff8b47e8d9:	44 8b 26             	mov    (%rsi),%r12d
ffffffff8b47e8dc:	8b 5e 08             	mov    0x8(%rsi),%ebx
ffffffff8b47e8df:	4c 8b 76 10          	mov    0x10(%rsi),%r14
ffffffff8b47e8e3:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b47e8e7:	e8 b4 e0 00 00       	call   ffffffff8b48c9a0 <frame_candidate_abf510+0xd490>
ffffffff8b47e8ec:	85 c0                	test   %eax,%eax
ffffffff8b47e8ee:	75 22                	jne    ffffffff8b47e912 <frame_candidate_abe8b0+0x62>
ffffffff8b47e8f0:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8b47e8f7:	00 00 
ffffffff8b47e8f9:	48 8b 48 08          	mov    0x8(%rax),%rcx
ffffffff8b47e8fd:	b8 02 00 00 00       	mov    $0x2,%eax
ffffffff8b47e902:	81 b9 d4 05 00 00 00 	cmpl   $0x5000000,0x5d4(%rcx)
ffffffff8b47e909:	00 00 05 
ffffffff8b47e90c:	0f 82 e6 00 00 00    	jb     ffffffff8b47e9f8 <frame_candidate_abe8b0+0x148>
ffffffff8b47e912:	41 83 fc ff          	cmp    $0xffffffff,%r12d
ffffffff8b47e916:	74 1a                	je     ffffffff8b47e932 <frame_candidate_abe8b0+0x82>
ffffffff8b47e918:	49 8b bf 40 01 00 00 	mov    0x140(%r15),%rdi
ffffffff8b47e91f:	e8 6c a6 b4 ff       	call   ffffffff8afc8f90 <handler_628_body-0x4b45b0>
ffffffff8b47e924:	85 c0                	test   %eax,%eax
ffffffff8b47e926:	75 15                	jne    ffffffff8b47e93d <frame_candidate_abe8b0+0x8d>
ffffffff8b47e928:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b47e92d:	e9 c6 00 00 00       	jmp    ffffffff8b47e9f8 <frame_candidate_abe8b0+0x148>
ffffffff8b47e932:	49 8b 47 08          	mov    0x8(%r15),%rax
ffffffff8b47e936:	44 8b a0 c0 05 00 00 	mov    0x5c0(%rax),%r12d
ffffffff8b47e93d:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8b47e942:	41 83 fc 0a          	cmp    $0xa,%r12d
ffffffff8b47e946:	0f 87 ac 00 00 00    	ja     ffffffff8b47e9f8 <frame_candidate_abe8b0+0x148>
ffffffff8b47e94c:	83 fb 02             	cmp    $0x2,%ebx
ffffffff8b47e94f:	74 1e                	je     ffffffff8b47e96f <frame_candidate_abe8b0+0xbf>
ffffffff8b47e951:	83 fb 01             	cmp    $0x1,%ebx
ffffffff8b47e954:	0f 85 9e 00 00 00    	jne    ffffffff8b47e9f8 <frame_candidate_abe8b0+0x148>
ffffffff8b47e95a:	48 8d 75 cc          	lea    -0x34(%rbp),%rsi
ffffffff8b47e95e:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
ffffffff8b47e962:	44 89 e7             	mov    %r12d,%edi
ffffffff8b47e965:	e8 76 eb e2 ff       	call   ffffffff8b2ad4e0 <handler_628_body-0x1d0060>
ffffffff8b47e96a:	8b 45 cc             	mov    -0x34(%rbp),%eax
ffffffff8b47e96d:	eb 48                	jmp    ffffffff8b47e9b7 <frame_candidate_abe8b0+0x107>
ffffffff8b47e96f:	48 8d 75 cc          	lea    -0x34(%rbp),%rsi
ffffffff8b47e973:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
ffffffff8b47e977:	44 89 e7             	mov    %r12d,%edi
ffffffff8b47e97a:	e8 d1 4c f2 ff       	call   ffffffff8b3a3650 <handler_628_body-0xd9ef0>
ffffffff8b47e97f:	49 8b 47 08          	mov    0x8(%r15),%rax
ffffffff8b47e983:	48 8b 80 00 02 00 00 	mov    0x200(%rax),%rax
ffffffff8b47e98a:	f6 80 44 02 00 00 02 	testb  $0x2,0x244(%rax)
ffffffff8b47e991:	8b 45 cc             	mov    -0x34(%rbp),%eax
ffffffff8b47e994:	74 21                	je     ffffffff8b47e9b7 <frame_candidate_abe8b0+0x107>
ffffffff8b47e996:	8d 48 03             	lea    0x3(%rax),%ecx
ffffffff8b47e999:	85 c0                	test   %eax,%eax
ffffffff8b47e99b:	0f 49 c8             	cmovns %eax,%ecx
ffffffff8b47e99e:	8b 45 c8             	mov    -0x38(%rbp),%eax
ffffffff8b47e9a1:	c1 f9 02             	sar    $0x2,%ecx
ffffffff8b47e9a4:	89 4d cc             	mov    %ecx,-0x34(%rbp)
ffffffff8b47e9a7:	8d 50 03             	lea    0x3(%rax),%edx
ffffffff8b47e9aa:	85 c0                	test   %eax,%eax
ffffffff8b47e9ac:	0f 49 d0             	cmovns %eax,%edx
ffffffff8b47e9af:	89 c8                	mov    %ecx,%eax
ffffffff8b47e9b1:	c1 fa 02             	sar    $0x2,%edx
ffffffff8b47e9b4:	89 55 c8             	mov    %edx,-0x38(%rbp)
ffffffff8b47e9b7:	89 c1                	mov    %eax,%ecx
ffffffff8b47e9b9:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b47e9bc:	c1 f9 1f             	sar    $0x1f,%ecx
ffffffff8b47e9bf:	c4 e2 70 f2 f0       	andn   %eax,%ecx,%esi
ffffffff8b47e9c4:	e8 c7 ad 79 ff       	call   ffffffff8ac19790 <handler_628_body-0x863db0>
ffffffff8b47e9c9:	83 f8 ff             	cmp    $0xffffffff,%eax
ffffffff8b47e9cc:	74 25                	je     ffffffff8b47e9f3 <frame_candidate_abe8b0+0x143>
ffffffff8b47e9ce:	8b 45 c8             	mov    -0x38(%rbp),%eax
ffffffff8b47e9d1:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
ffffffff8b47e9d5:	89 c1                	mov    %eax,%ecx
ffffffff8b47e9d7:	c1 f9 1f             	sar    $0x1f,%ecx
ffffffff8b47e9da:	c4 e2 70 f2 f0       	andn   %eax,%ecx,%esi
ffffffff8b47e9df:	e8 ac ad 79 ff       	call   ffffffff8ac19790 <handler_628_body-0x863db0>
ffffffff8b47e9e4:	31 c9                	xor    %ecx,%ecx
ffffffff8b47e9e6:	83 f8 ff             	cmp    $0xffffffff,%eax
ffffffff8b47e9e9:	b8 0e 00 00 00       	mov    $0xe,%eax
ffffffff8b47e9ee:	0f 45 c1             	cmovne %ecx,%eax
ffffffff8b47e9f1:	eb 05                	jmp    ffffffff8b47e9f8 <frame_candidate_abe8b0+0x148>
ffffffff8b47e9f3:	b8 0e 00 00 00       	mov    $0xe,%eax
ffffffff8b47e9f8:	49 8b 4d 00          	mov    0x0(%r13),%rcx
ffffffff8b47e9fc:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8b47ea00:	75 0f                	jne    ffffffff8b47ea11 <frame_candidate_abe8b0+0x161>
ffffffff8b47ea02:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b47ea06:	5b                   	pop    %rbx
ffffffff8b47ea07:	41 5c                	pop    %r12
ffffffff8b47ea09:	41 5d                	pop    %r13
ffffffff8b47ea0b:	41 5e                	pop    %r14
ffffffff8b47ea0d:	41 5f                	pop    %r15
ffffffff8b47ea0f:	5d                   	pop    %rbp
ffffffff8b47ea10:	c3                   	ret
ffffffff8b47ea11:	e8 9a ec c3 ff       	call   ffffffff8b0bd6b0 <handler_628_body-0x3bfe90>
ffffffff8b47ea16:	0f 0b                	ud2
ffffffff8b47ea18:	90                   	nop
ffffffff8b47ea19:	90                   	nop
ffffffff8b47ea1a:	90                   	nop
ffffffff8b47ea1b:	90                   	nop
ffffffff8b47ea1c:	90                   	nop
ffffffff8b47ea1d:	90                   	nop
ffffffff8b47ea1e:	90                   	nop
ffffffff8b47ea1f:	90                   	nop
ffffffff8b47ea20:	48 8b 47 08          	mov    0x8(%rdi),%rax
ffffffff8b47ea24:	4c 8b 58 68          	mov    0x68(%rax),%r11
ffffffff8b47ea28:	4d 85 db             	test   %r11,%r11
ffffffff8b47ea2b:	74 1f                	je     ffffffff8b47ea4c <frame_candidate_abe8b0+0x19c>
ffffffff8b47ea2d:	48 8d 05 94 2e 7b ff 	lea    -0x84d16c(%rip),%rax        # ffffffff8ac318c8 <handler_628_body-0x84bc78>
ffffffff8b47ea34:	4c 29 d8             	sub    %r11,%rax
ffffffff8b47ea37:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b47ea3b:	48 83 f8 05          	cmp    $0x5,%rax
ffffffff8b47ea3f:	77 11                	ja     ffffffff8b47ea52 <frame_candidate_abea52>
ffffffff8b47ea41:	45 0f b7 c0          	movzwl %r8w,%r8d
ffffffff8b47ea45:	45 0f b7 c9          	movzwl %r9w,%r9d
ffffffff8b47ea49:	41 ff e3             	jmp    *%r11
ffffffff8b47ea4c:	b8 13 00 00 00       	mov    $0x13,%eax
ffffffff8b47ea51:	c3                   	ret

ffffffff8b47ea52 <frame_candidate_abea52>:
ffffffff8b47ea52:	55                   	push   %rbp
ffffffff8b47ea53:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47ea56:	41 57                	push   %r15
ffffffff8b47ea58:	41 56                	push   %r14
ffffffff8b47ea5a:	41 55                	push   %r13
ffffffff8b47ea5c:	41 54                	push   %r12
ffffffff8b47ea5e:	53                   	push   %rbx
ffffffff8b47ea5f:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b47ea63:	48 8d 05 d6 a2 dc 01 	lea    0x1dca2d6(%rip),%rax        # ffffffff8d248d40 <frame_candidate_abf510+0x1dc9830>
ffffffff8b47ea6a:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
ffffffff8b47ea6e:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
ffffffff8b47ea72:	4c 89 de             	mov    %r11,%rsi
ffffffff8b47ea75:	49 89 cf             	mov    %rcx,%r15
ffffffff8b47ea78:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b47ea7b:	45 89 cc             	mov    %r9d,%r12d
ffffffff8b47ea7e:	45 89 c5             	mov    %r8d,%r13d
ffffffff8b47ea81:	4d 89 de             	mov    %r11,%r14
ffffffff8b47ea84:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47ea87:	e8 34 0e 99 ff       	call   ffffffff8ae0f8c0 <handler_628_body-0x66dc80>
ffffffff8b47ea8c:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b47ea90:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
ffffffff8b47ea94:	4d 89 f3             	mov    %r14,%r11
ffffffff8b47ea97:	45 89 e8             	mov    %r13d,%r8d
ffffffff8b47ea9a:	45 89 e1             	mov    %r12d,%r9d
ffffffff8b47ea9d:	48 89 da             	mov    %rbx,%rdx
ffffffff8b47eaa0:	4c 89 f9             	mov    %r15,%rcx
ffffffff8b47eaa3:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b47eaa7:	5b                   	pop    %rbx
ffffffff8b47eaa8:	41 5c                	pop    %r12
ffffffff8b47eaaa:	41 5d                	pop    %r13
ffffffff8b47eaac:	41 5e                	pop    %r14
ffffffff8b47eaae:	41 5f                	pop    %r15
ffffffff8b47eab0:	5d                   	pop    %rbp
ffffffff8b47eab1:	eb 8e                	jmp    ffffffff8b47ea41 <frame_candidate_abe8b0+0x191>
ffffffff8b47eab3:	90                   	nop
ffffffff8b47eab4:	90                   	nop
ffffffff8b47eab5:	90                   	nop
ffffffff8b47eab6:	90                   	nop
ffffffff8b47eab7:	90                   	nop
ffffffff8b47eab8:	90                   	nop
ffffffff8b47eab9:	90                   	nop
ffffffff8b47eaba:	90                   	nop
ffffffff8b47eabb:	90                   	nop
ffffffff8b47eabc:	90                   	nop
ffffffff8b47eabd:	90                   	nop
ffffffff8b47eabe:	90                   	nop
ffffffff8b47eabf:	90                   	nop

ffffffff8b47eac0 <frame_candidate_abeac0>:
ffffffff8b47eac0:	55                   	push   %rbp
ffffffff8b47eac1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47eac4:	48 8d 3d 6e d2 7d 00 	lea    0x7dd26e(%rip),%rdi        # ffffffff8bc5bd39 <frame_candidate_abf510+0x7dc829>
ffffffff8b47eacb:	be 28 00 00 00       	mov    $0x28,%esi
ffffffff8b47ead0:	31 d2                	xor    %edx,%edx
ffffffff8b47ead2:	31 c9                	xor    %ecx,%ecx
ffffffff8b47ead4:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b47ead7:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b47eada:	6a 00                	push   $0x0
ffffffff8b47eadc:	6a 07                	push   $0x7
ffffffff8b47eade:	e8 fd c5 97 ff       	call   ffffffff8adfb0e0 <handler_628_body-0x682460>
ffffffff8b47eae3:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b47eae7:	48 89 05 2a 83 13 03 	mov    %rax,0x313832a(%rip)        # ffffffff8e5b6e18 <frame_candidate_abf510+0x3137908>
ffffffff8b47eaee:	5d                   	pop    %rbp
ffffffff8b47eaef:	c3                   	ret

ffffffff8b47eaf0 <frame_candidate_abeaf0>:
ffffffff8b47eaf0:	55                   	push   %rbp
ffffffff8b47eaf1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47eaf4:	41 57                	push   %r15
ffffffff8b47eaf6:	41 56                	push   %r14
ffffffff8b47eaf8:	41 54                	push   %r12
ffffffff8b47eafa:	53                   	push   %rbx
ffffffff8b47eafb:	89 fb                	mov    %edi,%ebx
ffffffff8b47eafd:	e8 5e 98 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47eb02:	41 89 c7             	mov    %eax,%r15d
ffffffff8b47eb05:	85 c0                	test   %eax,%eax
ffffffff8b47eb07:	78 05                	js     ffffffff8b47eb0e <frame_candidate_abeaf0+0x1e>
ffffffff8b47eb09:	45 89 fc             	mov    %r15d,%r12d
ffffffff8b47eb0c:	eb 23                	jmp    ffffffff8b47eb31 <frame_candidate_abeaf0+0x41>
ffffffff8b47eb0e:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8b47eb15:	00 00 
ffffffff8b47eb17:	48 8b b8 40 01 00 00 	mov    0x140(%rax),%rdi
ffffffff8b47eb1e:	e8 ed ad b4 ff       	call   ffffffff8afc9910 <handler_628_body-0x4b3c30>
ffffffff8b47eb23:	41 be 00 00 00 00    	mov    $0x0,%r14d
ffffffff8b47eb29:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47eb2c:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b47eb2f:	75 1b                	jne    ffffffff8b47eb4c <frame_candidate_abeaf0+0x5c>
ffffffff8b47eb31:	41 be 05 00 00 00    	mov    $0x5,%r14d
ffffffff8b47eb37:	83 fb 02             	cmp    $0x2,%ebx
ffffffff8b47eb3a:	74 0d                	je     ffffffff8b47eb49 <frame_candidate_abeaf0+0x59>
ffffffff8b47eb3c:	e8 4f d8 02 00       	call   ffffffff8b4ac390 <frame_candidate_abf510+0x2ce80>
ffffffff8b47eb41:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b47eb44:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b47eb47:	75 17                	jne    ffffffff8b47eb60 <frame_candidate_abeaf0+0x70>
ffffffff8b47eb49:	45 89 e7             	mov    %r12d,%r15d
ffffffff8b47eb4c:	44 89 ff             	mov    %r15d,%edi
ffffffff8b47eb4f:	e8 ec 98 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47eb54:	44 89 f0             	mov    %r14d,%eax
ffffffff8b47eb57:	5b                   	pop    %rbx
ffffffff8b47eb58:	41 5c                	pop    %r12
ffffffff8b47eb5a:	41 5e                	pop    %r14
ffffffff8b47eb5c:	41 5f                	pop    %r15
ffffffff8b47eb5e:	5d                   	pop    %rbp
ffffffff8b47eb5f:	c3                   	ret
ffffffff8b47eb60:	85 db                	test   %ebx,%ebx
ffffffff8b47eb62:	74 1a                	je     ffffffff8b47eb7e <frame_candidate_abeaf0+0x8e>
ffffffff8b47eb64:	83 fb 04             	cmp    $0x4,%ebx
ffffffff8b47eb67:	74 0d                	je     ffffffff8b47eb76 <frame_candidate_abeaf0+0x86>
ffffffff8b47eb69:	83 fb 03             	cmp    $0x3,%ebx
ffffffff8b47eb6c:	75 18                	jne    ffffffff8b47eb86 <frame_candidate_abeaf0+0x96>
ffffffff8b47eb6e:	41 be 04 00 00 00    	mov    $0x4,%r14d
ffffffff8b47eb74:	eb d3                	jmp    ffffffff8b47eb49 <frame_candidate_abeaf0+0x59>
ffffffff8b47eb76:	41 be 0a 00 00 00    	mov    $0xa,%r14d
ffffffff8b47eb7c:	eb cb                	jmp    ffffffff8b47eb49 <frame_candidate_abeaf0+0x59>
ffffffff8b47eb7e:	41 be 03 00 00 00    	mov    $0x3,%r14d
ffffffff8b47eb84:	eb c3                	jmp    ffffffff8b47eb49 <frame_candidate_abeaf0+0x59>
ffffffff8b47eb86:	e8 a5 e0 02 00       	call   ffffffff8b4acc30 <frame_candidate_abf510+0x2d720>
ffffffff8b47eb8b:	31 c9                	xor    %ecx,%ecx
ffffffff8b47eb8d:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b47eb90:	0f 94 c1             	sete   %cl
ffffffff8b47eb93:	44 8d 34 89          	lea    (%rcx,%rcx,4),%r14d
ffffffff8b47eb97:	eb b0                	jmp    ffffffff8b47eb49 <frame_candidate_abeaf0+0x59>
ffffffff8b47eb99:	90                   	nop
ffffffff8b47eb9a:	90                   	nop
ffffffff8b47eb9b:	90                   	nop
ffffffff8b47eb9c:	90                   	nop
ffffffff8b47eb9d:	90                   	nop
ffffffff8b47eb9e:	90                   	nop
ffffffff8b47eb9f:	90                   	nop

ffffffff8b47eba0 <frame_candidate_abeba0>:
ffffffff8b47eba0:	55                   	push   %rbp
ffffffff8b47eba1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47eba4:	41 57                	push   %r15
ffffffff8b47eba6:	41 56                	push   %r14
ffffffff8b47eba8:	41 55                	push   %r13
ffffffff8b47ebaa:	41 54                	push   %r12
ffffffff8b47ebac:	53                   	push   %rbx
ffffffff8b47ebad:	50                   	push   %rax
ffffffff8b47ebae:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47ebb1:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47ebb4:	41 89 fd             	mov    %edi,%r13d
ffffffff8b47ebb7:	e8 a4 97 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47ebbc:	89 c3                	mov    %eax,%ebx
ffffffff8b47ebbe:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ebc1:	85 c0                	test   %eax,%eax
ffffffff8b47ebc3:	78 46                	js     ffffffff8b47ec0b <frame_candidate_abeba0+0x6b>
ffffffff8b47ebc5:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ebc8:	e8 a3 db 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47ebcd:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ebd0:	85 c0                	test   %eax,%eax
ffffffff8b47ebd2:	75 37                	jne    ffffffff8b47ec0b <frame_candidate_abeba0+0x6b>
ffffffff8b47ebd4:	41 bc 02 02 0d 80    	mov    $0x800d0202,%r12d
ffffffff8b47ebda:	41 83 fd 04          	cmp    $0x4,%r13d
ffffffff8b47ebde:	77 2b                	ja     ffffffff8b47ec0b <frame_candidate_abeba0+0x6b>
ffffffff8b47ebe0:	44 89 e8             	mov    %r13d,%eax
ffffffff8b47ebe3:	48 8d 0d 46 28 3d 00 	lea    0x3d2846(%rip),%rcx        # ffffffff8b851430 <frame_candidate_abf510+0x3d1f20>
ffffffff8b47ebea:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
ffffffff8b47ebee:	4c 3b 74 c1 08       	cmp    0x8(%rcx,%rax,8),%r14
ffffffff8b47ebf3:	72 16                	jb     ffffffff8b47ec0b <frame_candidate_abeba0+0x6b>
ffffffff8b47ebf5:	48 8d 04 c1          	lea    (%rcx,%rax,8),%rax
ffffffff8b47ebf9:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ebfc:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47ebff:	48 8b 70 10          	mov    0x10(%rax),%rsi
ffffffff8b47ec03:	e8 e8 a6 02 00       	call   ffffffff8b4a92f0 <frame_candidate_abf510+0x29de0>
ffffffff8b47ec08:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47ec0b:	89 df                	mov    %ebx,%edi
ffffffff8b47ec0d:	e8 2e 98 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47ec12:	44 89 e0             	mov    %r12d,%eax
ffffffff8b47ec15:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47ec19:	5b                   	pop    %rbx
ffffffff8b47ec1a:	41 5c                	pop    %r12
ffffffff8b47ec1c:	41 5d                	pop    %r13
ffffffff8b47ec1e:	41 5e                	pop    %r14
ffffffff8b47ec20:	41 5f                	pop    %r15
ffffffff8b47ec22:	5d                   	pop    %rbp
ffffffff8b47ec23:	c3                   	ret
ffffffff8b47ec24:	90                   	nop
ffffffff8b47ec25:	90                   	nop
ffffffff8b47ec26:	90                   	nop
ffffffff8b47ec27:	90                   	nop
ffffffff8b47ec28:	90                   	nop
ffffffff8b47ec29:	90                   	nop
ffffffff8b47ec2a:	90                   	nop
ffffffff8b47ec2b:	90                   	nop
ffffffff8b47ec2c:	90                   	nop
ffffffff8b47ec2d:	90                   	nop
ffffffff8b47ec2e:	90                   	nop
ffffffff8b47ec2f:	90                   	nop

ffffffff8b47ec30 <frame_candidate_abec30>:
ffffffff8b47ec30:	55                   	push   %rbp
ffffffff8b47ec31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47ec34:	41 57                	push   %r15
ffffffff8b47ec36:	41 56                	push   %r14
ffffffff8b47ec38:	41 55                	push   %r13
ffffffff8b47ec3a:	41 54                	push   %r12
ffffffff8b47ec3c:	53                   	push   %rbx
ffffffff8b47ec3d:	50                   	push   %rax
ffffffff8b47ec3e:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47ec41:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47ec44:	41 89 fd             	mov    %edi,%r13d
ffffffff8b47ec47:	e8 14 97 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47ec4c:	89 c3                	mov    %eax,%ebx
ffffffff8b47ec4e:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ec51:	85 c0                	test   %eax,%eax
ffffffff8b47ec53:	78 46                	js     ffffffff8b47ec9b <frame_candidate_abec30+0x6b>
ffffffff8b47ec55:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ec58:	e8 13 db 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47ec5d:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ec60:	85 c0                	test   %eax,%eax
ffffffff8b47ec62:	75 37                	jne    ffffffff8b47ec9b <frame_candidate_abec30+0x6b>
ffffffff8b47ec64:	41 bc 02 02 0d 80    	mov    $0x800d0202,%r12d
ffffffff8b47ec6a:	41 83 fd 03          	cmp    $0x3,%r13d
ffffffff8b47ec6e:	77 2b                	ja     ffffffff8b47ec9b <frame_candidate_abec30+0x6b>
ffffffff8b47ec70:	44 89 e8             	mov    %r13d,%eax
ffffffff8b47ec73:	48 8d 0d 56 28 3d 00 	lea    0x3d2856(%rip),%rcx        # ffffffff8b8514d0 <frame_candidate_abf510+0x3d1fc0>
ffffffff8b47ec7a:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
ffffffff8b47ec7e:	4c 3b 74 c1 08       	cmp    0x8(%rcx,%rax,8),%r14
ffffffff8b47ec83:	72 16                	jb     ffffffff8b47ec9b <frame_candidate_abec30+0x6b>
ffffffff8b47ec85:	48 8d 04 c1          	lea    (%rcx,%rax,8),%rax
ffffffff8b47ec89:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ec8c:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47ec8f:	48 8b 70 10          	mov    0x10(%rax),%rsi
ffffffff8b47ec93:	e8 58 a6 02 00       	call   ffffffff8b4a92f0 <frame_candidate_abf510+0x29de0>
ffffffff8b47ec98:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47ec9b:	89 df                	mov    %ebx,%edi
ffffffff8b47ec9d:	e8 9e 97 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47eca2:	44 89 e0             	mov    %r12d,%eax
ffffffff8b47eca5:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47eca9:	5b                   	pop    %rbx
ffffffff8b47ecaa:	41 5c                	pop    %r12
ffffffff8b47ecac:	41 5d                	pop    %r13
ffffffff8b47ecae:	41 5e                	pop    %r14
ffffffff8b47ecb0:	41 5f                	pop    %r15
ffffffff8b47ecb2:	5d                   	pop    %rbp
ffffffff8b47ecb3:	c3                   	ret
ffffffff8b47ecb4:	90                   	nop
ffffffff8b47ecb5:	90                   	nop
ffffffff8b47ecb6:	90                   	nop
ffffffff8b47ecb7:	90                   	nop
ffffffff8b47ecb8:	90                   	nop
ffffffff8b47ecb9:	90                   	nop
ffffffff8b47ecba:	90                   	nop
ffffffff8b47ecbb:	90                   	nop
ffffffff8b47ecbc:	90                   	nop
ffffffff8b47ecbd:	90                   	nop
ffffffff8b47ecbe:	90                   	nop
ffffffff8b47ecbf:	90                   	nop

ffffffff8b47ecc0 <frame_candidate_abecc0>:
ffffffff8b47ecc0:	55                   	push   %rbp
ffffffff8b47ecc1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47ecc4:	41 57                	push   %r15
ffffffff8b47ecc6:	41 56                	push   %r14
ffffffff8b47ecc8:	41 55                	push   %r13
ffffffff8b47ecca:	41 54                	push   %r12
ffffffff8b47eccc:	53                   	push   %rbx
ffffffff8b47eccd:	50                   	push   %rax
ffffffff8b47ecce:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47ecd1:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47ecd4:	41 89 fd             	mov    %edi,%r13d
ffffffff8b47ecd7:	e8 84 96 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47ecdc:	89 c3                	mov    %eax,%ebx
ffffffff8b47ecde:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ece1:	85 c0                	test   %eax,%eax
ffffffff8b47ece3:	78 46                	js     ffffffff8b47ed2b <frame_candidate_abecc0+0x6b>
ffffffff8b47ece5:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ece8:	e8 83 da 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47eced:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ecf0:	85 c0                	test   %eax,%eax
ffffffff8b47ecf2:	75 37                	jne    ffffffff8b47ed2b <frame_candidate_abecc0+0x6b>
ffffffff8b47ecf4:	41 bc 02 02 0d 80    	mov    $0x800d0202,%r12d
ffffffff8b47ecfa:	41 83 fd 09          	cmp    $0x9,%r13d
ffffffff8b47ecfe:	77 2b                	ja     ffffffff8b47ed2b <frame_candidate_abecc0+0x6b>
ffffffff8b47ed00:	44 89 e8             	mov    %r13d,%eax
ffffffff8b47ed03:	48 8d 0d 26 28 3d 00 	lea    0x3d2826(%rip),%rcx        # ffffffff8b851530 <frame_candidate_abf510+0x3d2020>
ffffffff8b47ed0a:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
ffffffff8b47ed0e:	4c 3b 74 c1 08       	cmp    0x8(%rcx,%rax,8),%r14
ffffffff8b47ed13:	72 16                	jb     ffffffff8b47ed2b <frame_candidate_abecc0+0x6b>
ffffffff8b47ed15:	48 8d 04 c1          	lea    (%rcx,%rax,8),%rax
ffffffff8b47ed19:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ed1c:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47ed1f:	48 8b 70 10          	mov    0x10(%rax),%rsi
ffffffff8b47ed23:	e8 c8 a5 02 00       	call   ffffffff8b4a92f0 <frame_candidate_abf510+0x29de0>
ffffffff8b47ed28:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47ed2b:	89 df                	mov    %ebx,%edi
ffffffff8b47ed2d:	e8 0e 97 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47ed32:	44 89 e0             	mov    %r12d,%eax
ffffffff8b47ed35:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47ed39:	5b                   	pop    %rbx
ffffffff8b47ed3a:	41 5c                	pop    %r12
ffffffff8b47ed3c:	41 5d                	pop    %r13
ffffffff8b47ed3e:	41 5e                	pop    %r14
ffffffff8b47ed40:	41 5f                	pop    %r15
ffffffff8b47ed42:	5d                   	pop    %rbp
ffffffff8b47ed43:	c3                   	ret
ffffffff8b47ed44:	90                   	nop
ffffffff8b47ed45:	90                   	nop
ffffffff8b47ed46:	90                   	nop
ffffffff8b47ed47:	90                   	nop
ffffffff8b47ed48:	90                   	nop
ffffffff8b47ed49:	90                   	nop
ffffffff8b47ed4a:	90                   	nop
ffffffff8b47ed4b:	90                   	nop
ffffffff8b47ed4c:	90                   	nop
ffffffff8b47ed4d:	90                   	nop
ffffffff8b47ed4e:	90                   	nop
ffffffff8b47ed4f:	90                   	nop

ffffffff8b47ed50 <frame_candidate_abed50>:
ffffffff8b47ed50:	55                   	push   %rbp
ffffffff8b47ed51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47ed54:	41 57                	push   %r15
ffffffff8b47ed56:	41 56                	push   %r14
ffffffff8b47ed58:	41 55                	push   %r13
ffffffff8b47ed5a:	41 54                	push   %r12
ffffffff8b47ed5c:	53                   	push   %rbx
ffffffff8b47ed5d:	50                   	push   %rax
ffffffff8b47ed5e:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47ed61:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47ed64:	41 89 fc             	mov    %edi,%r12d
ffffffff8b47ed67:	e8 f4 95 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47ed6c:	89 c3                	mov    %eax,%ebx
ffffffff8b47ed6e:	41 89 c5             	mov    %eax,%r13d
ffffffff8b47ed71:	85 c0                	test   %eax,%eax
ffffffff8b47ed73:	78 3b                	js     ffffffff8b47edb0 <frame_candidate_abed50+0x60>
ffffffff8b47ed75:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ed78:	e8 f3 d9 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47ed7d:	41 89 c5             	mov    %eax,%r13d
ffffffff8b47ed80:	85 c0                	test   %eax,%eax
ffffffff8b47ed82:	75 2c                	jne    ffffffff8b47edb0 <frame_candidate_abed50+0x60>
ffffffff8b47ed84:	45 85 e4             	test   %r12d,%r12d
ffffffff8b47ed87:	41 bd 02 02 0d 80    	mov    $0x800d0202,%r13d
ffffffff8b47ed8d:	0f 95 c0             	setne  %al
ffffffff8b47ed90:	49 83 fe 21          	cmp    $0x21,%r14
ffffffff8b47ed94:	0f 92 c1             	setb   %cl
ffffffff8b47ed97:	08 c1                	or     %al,%cl
ffffffff8b47ed99:	75 15                	jne    ffffffff8b47edb0 <frame_candidate_abed50+0x60>
ffffffff8b47ed9b:	48 8d 35 3e d3 e1 00 	lea    0xe1d33e(%rip),%rsi        # ffffffff8c29c0e0 <frame_candidate_abf510+0xe1cbd0>
ffffffff8b47eda2:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47eda5:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47eda8:	e8 43 a5 02 00       	call   ffffffff8b4a92f0 <frame_candidate_abf510+0x29de0>
ffffffff8b47edad:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b47edb0:	89 df                	mov    %ebx,%edi
ffffffff8b47edb2:	e8 89 96 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47edb7:	44 89 e8             	mov    %r13d,%eax
ffffffff8b47edba:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47edbe:	5b                   	pop    %rbx
ffffffff8b47edbf:	41 5c                	pop    %r12
ffffffff8b47edc1:	41 5d                	pop    %r13
ffffffff8b47edc3:	41 5e                	pop    %r14
ffffffff8b47edc5:	41 5f                	pop    %r15
ffffffff8b47edc7:	5d                   	pop    %rbp
ffffffff8b47edc8:	c3                   	ret
ffffffff8b47edc9:	90                   	nop
ffffffff8b47edca:	90                   	nop
ffffffff8b47edcb:	90                   	nop
ffffffff8b47edcc:	90                   	nop
ffffffff8b47edcd:	90                   	nop
ffffffff8b47edce:	90                   	nop
ffffffff8b47edcf:	90                   	nop

ffffffff8b47edd0 <frame_candidate_abedd0>:
ffffffff8b47edd0:	55                   	push   %rbp
ffffffff8b47edd1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47edd4:	53                   	push   %rbx
ffffffff8b47edd5:	50                   	push   %rax
ffffffff8b47edd6:	89 fb                	mov    %edi,%ebx
ffffffff8b47edd8:	e8 83 95 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47eddd:	85 c0                	test   %eax,%eax
ffffffff8b47eddf:	0f 98 c1             	sets   %cl
ffffffff8b47ede2:	83 fb 05             	cmp    $0x5,%ebx
ffffffff8b47ede5:	0f 93 c2             	setae  %dl
ffffffff8b47ede8:	08 ca                	or     %cl,%dl
ffffffff8b47edea:	74 04                	je     ffffffff8b47edf0 <frame_candidate_abedd0+0x20>
ffffffff8b47edec:	31 db                	xor    %ebx,%ebx
ffffffff8b47edee:	eb 1a                	jmp    ffffffff8b47ee0a <frame_candidate_abedd0+0x3a>
ffffffff8b47edf0:	89 d9                	mov    %ebx,%ecx
ffffffff8b47edf2:	48 8d 15 37 26 3d 00 	lea    0x3d2637(%rip),%rdx        # ffffffff8b851430 <frame_candidate_abf510+0x3d1f20>
ffffffff8b47edf9:	48 8d 0c 49          	lea    (%rcx,%rcx,2),%rcx
ffffffff8b47edfd:	8b 0c ca             	mov    (%rdx,%rcx,8),%ecx
ffffffff8b47ee00:	89 ca                	mov    %ecx,%edx
ffffffff8b47ee02:	c1 fa 1f             	sar    $0x1f,%edx
ffffffff8b47ee05:	c4 e2 68 f2 d9       	andn   %ecx,%edx,%ebx
ffffffff8b47ee0a:	89 c7                	mov    %eax,%edi
ffffffff8b47ee0c:	e8 2f 96 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47ee11:	48 89 d8             	mov    %rbx,%rax
ffffffff8b47ee14:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47ee18:	5b                   	pop    %rbx
ffffffff8b47ee19:	5d                   	pop    %rbp
ffffffff8b47ee1a:	c3                   	ret
ffffffff8b47ee1b:	90                   	nop
ffffffff8b47ee1c:	90                   	nop
ffffffff8b47ee1d:	90                   	nop
ffffffff8b47ee1e:	90                   	nop
ffffffff8b47ee1f:	90                   	nop

ffffffff8b47ee20 <frame_candidate_abee20>:
ffffffff8b47ee20:	55                   	push   %rbp
ffffffff8b47ee21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47ee24:	41 57                	push   %r15
ffffffff8b47ee26:	41 56                	push   %r14
ffffffff8b47ee28:	41 55                	push   %r13
ffffffff8b47ee2a:	41 54                	push   %r12
ffffffff8b47ee2c:	53                   	push   %rbx
ffffffff8b47ee2d:	50                   	push   %rax
ffffffff8b47ee2e:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47ee31:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47ee34:	41 89 fd             	mov    %edi,%r13d
ffffffff8b47ee37:	e8 24 95 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47ee3c:	89 c3                	mov    %eax,%ebx
ffffffff8b47ee3e:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ee41:	85 c0                	test   %eax,%eax
ffffffff8b47ee43:	0f 88 ff 00 00 00    	js     ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47ee49:	e8 c2 f8 02 00       	call   ffffffff8b4ae710 <frame_candidate_abf510+0x2f200>
ffffffff8b47ee4e:	85 c0                	test   %eax,%eax
ffffffff8b47ee50:	74 08                	je     ffffffff8b47ee5a <frame_candidate_abee20+0x3a>
ffffffff8b47ee52:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47ee55:	e9 ee 00 00 00       	jmp    ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47ee5a:	80 3d c3 7f 13 03 01 	cmpb   $0x1,0x3137fc3(%rip)        # ffffffff8e5b6e24 <frame_candidate_abf510+0x3137914>
ffffffff8b47ee61:	41 bc 03 06 0d 80    	mov    $0x800d0603,%r12d
ffffffff8b47ee67:	0f 85 db 00 00 00    	jne    ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47ee6d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47ee70:	e8 fb d8 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47ee75:	85 c0                	test   %eax,%eax
ffffffff8b47ee77:	75 d9                	jne    ffffffff8b47ee52 <frame_candidate_abee20+0x32>
ffffffff8b47ee79:	41 83 fd 04          	cmp    $0x4,%r13d
ffffffff8b47ee7d:	76 0b                	jbe    ffffffff8b47ee8a <frame_candidate_abee20+0x6a>
ffffffff8b47ee7f:	41 bc 02 02 0d 80    	mov    $0x800d0202,%r12d
ffffffff8b47ee85:	e9 be 00 00 00       	jmp    ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47ee8a:	44 89 e9             	mov    %r13d,%ecx
ffffffff8b47ee8d:	48 8d 05 9c 7f 13 03 	lea    0x3137f9c(%rip),%rax        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47ee94:	48 8b 3c c8          	mov    (%rax,%rcx,8),%rdi
ffffffff8b47ee98:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
ffffffff8b47ee9c:	e8 cf d8 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47eea1:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
ffffffff8b47eea5:	85 c0                	test   %eax,%eax
ffffffff8b47eea7:	0f 85 9b 00 00 00    	jne    ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47eead:	48 8d 04 52          	lea    (%rdx,%rdx,2),%rax
ffffffff8b47eeb1:	48 8d 0d 78 25 3d 00 	lea    0x3d2578(%rip),%rcx        # ffffffff8b851430 <frame_candidate_abf510+0x3d1f20>
ffffffff8b47eeb8:	41 bc 02 02 0d 80    	mov    $0x800d0202,%r12d
ffffffff8b47eebe:	4c 3b 34 c1          	cmp    (%rcx,%rax,8),%r14
ffffffff8b47eec2:	0f 87 80 00 00 00    	ja     ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47eec8:	41 83 fd 04          	cmp    $0x4,%r13d
ffffffff8b47eecc:	77 61                	ja     ffffffff8b47ef2f <frame_candidate_abee20+0x10f>
ffffffff8b47eece:	48 8d 05 07 d1 e1 00 	lea    0xe1d107(%rip),%rax        # ffffffff8c29bfdc <frame_candidate_abf510+0xe1cacc>
ffffffff8b47eed5:	41 bd 0c 00 00 00    	mov    $0xc,%r13d
ffffffff8b47eedb:	48 63 0c 90          	movslq (%rax,%rdx,4),%rcx
ffffffff8b47eedf:	48 01 c1             	add    %rax,%rcx
ffffffff8b47eee2:	ff e1                	jmp    *%rcx
ffffffff8b47eee4:	49 89 d4             	mov    %rdx,%r12
ffffffff8b47eee7:	e8 94 76 a0 ff       	call   ffffffff8ae86580 <handler_628_body-0x5f6fc0>
ffffffff8b47eeec:	4c 89 e2             	mov    %r12,%rdx
ffffffff8b47eeef:	41 bd 10 00 00 00    	mov    $0x10,%r13d
ffffffff8b47eef5:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47eef8:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b47eefb:	75 08                	jne    ffffffff8b47ef05 <frame_candidate_abee20+0xe5>
ffffffff8b47eefd:	eb 49                	jmp    ffffffff8b47ef48 <frame_candidate_abee20+0x128>
ffffffff8b47eeff:	41 bd 04 00 00 00    	mov    $0x4,%r13d
ffffffff8b47ef05:	4c 8d 25 24 7f 13 03 	lea    0x3137f24(%rip),%r12        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47ef0c:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b47ef0f:	49 89 d7             	mov    %rdx,%r15
ffffffff8b47ef12:	49 8b 3c d4          	mov    (%r12,%rdx,8),%rdi
ffffffff8b47ef16:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47ef19:	e8 92 a1 79 ff       	call   ffffffff8ac190b0 <handler_628_body-0x864490>
ffffffff8b47ef1e:	4b 8b 3c fc          	mov    (%r12,%r15,8),%rdi
ffffffff8b47ef22:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47ef25:	4c 89 ea             	mov    %r13,%rdx
ffffffff8b47ef28:	e8 43 00 00 00       	call   ffffffff8b47ef70 <frame_candidate_abee20+0x150>
ffffffff8b47ef2d:	eb 16                	jmp    ffffffff8b47ef45 <frame_candidate_abee20+0x125>
ffffffff8b47ef2f:	48 8d 05 fa 7e 13 03 	lea    0x3137efa(%rip),%rax        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47ef36:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b47ef39:	48 8b 3c d0          	mov    (%rax,%rdx,8),%rdi
ffffffff8b47ef3d:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47ef40:	e8 6b a1 79 ff       	call   ffffffff8ac190b0 <handler_628_body-0x864490>
ffffffff8b47ef45:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47ef48:	89 df                	mov    %ebx,%edi
ffffffff8b47ef4a:	e8 f1 94 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47ef4f:	44 89 e0             	mov    %r12d,%eax
ffffffff8b47ef52:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47ef56:	5b                   	pop    %rbx
ffffffff8b47ef57:	41 5c                	pop    %r12
ffffffff8b47ef59:	41 5d                	pop    %r13
ffffffff8b47ef5b:	41 5e                	pop    %r14
ffffffff8b47ef5d:	41 5f                	pop    %r15
ffffffff8b47ef5f:	5d                   	pop    %rbp
ffffffff8b47ef60:	c3                   	ret
ffffffff8b47ef61:	90                   	nop
ffffffff8b47ef62:	90                   	nop
ffffffff8b47ef63:	90                   	nop
ffffffff8b47ef64:	90                   	nop
ffffffff8b47ef65:	90                   	nop
ffffffff8b47ef66:	90                   	nop
ffffffff8b47ef67:	90                   	nop
ffffffff8b47ef68:	90                   	nop
ffffffff8b47ef69:	90                   	nop
ffffffff8b47ef6a:	90                   	nop
ffffffff8b47ef6b:	90                   	nop
ffffffff8b47ef6c:	90                   	nop
ffffffff8b47ef6d:	90                   	nop
ffffffff8b47ef6e:	90                   	nop
ffffffff8b47ef6f:	90                   	nop
ffffffff8b47ef70:	48 85 ff             	test   %rdi,%rdi
ffffffff8b47ef73:	0f 94 c0             	sete   %al
ffffffff8b47ef76:	48 85 f6             	test   %rsi,%rsi
ffffffff8b47ef79:	0f 94 c1             	sete   %cl
ffffffff8b47ef7c:	08 c1                	or     %al,%cl
ffffffff8b47ef7e:	48 85 d2             	test   %rdx,%rdx
ffffffff8b47ef81:	0f 94 c0             	sete   %al
ffffffff8b47ef84:	08 c8                	or     %cl,%al
ffffffff8b47ef86:	75 6f                	jne    ffffffff8b47eff7 <frame_candidate_abefa4+0x53>
ffffffff8b47ef88:	48 89 d0             	mov    %rdx,%rax
ffffffff8b47ef8b:	48 09 f0             	or     %rsi,%rax
ffffffff8b47ef8e:	48 c1 e8 20          	shr    $0x20,%rax
ffffffff8b47ef92:	74 0a                	je     ffffffff8b47ef9e <frame_candidate_abee20+0x17e>
ffffffff8b47ef94:	48 89 d0             	mov    %rdx,%rax
ffffffff8b47ef97:	31 d2                	xor    %edx,%edx
ffffffff8b47ef99:	48 f7 f6             	div    %rsi
ffffffff8b47ef9c:	eb 06                	jmp    ffffffff8b47efa4 <frame_candidate_abefa4>
ffffffff8b47ef9e:	89 d0                	mov    %edx,%eax
ffffffff8b47efa0:	31 d2                	xor    %edx,%edx
ffffffff8b47efa2:	f7 f6                	div    %esi

ffffffff8b47efa4 <frame_candidate_abefa4>:
ffffffff8b47efa4:	55                   	push   %rbp
ffffffff8b47efa5:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47efa8:	53                   	push   %rbx
ffffffff8b47efa9:	0f b6 04 17          	movzbl (%rdi,%rdx,1),%eax
ffffffff8b47efad:	4c 8d 0d 4c b3 8f 00 	lea    0x8fb34c(%rip),%r9        # ffffffff8bd7a300 <frame_candidate_abf510+0x8fadf0>
ffffffff8b47efb4:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b47efb7:	45 31 d2             	xor    %r10d,%r10d
ffffffff8b47efba:	0f b6 c8             	movzbl %al,%ecx
ffffffff8b47efbd:	eb 09                	jmp    ffffffff8b47efc8 <frame_candidate_abefa4+0x24>
ffffffff8b47efbf:	90                   	nop
ffffffff8b47efc0:	49 ff c2             	inc    %r10
ffffffff8b47efc3:	4c 39 d6             	cmp    %r10,%rsi
ffffffff8b47efc6:	74 2a                	je     ffffffff8b47eff2 <frame_candidate_abefa4+0x4e>
ffffffff8b47efc8:	46 0f b6 1c 17       	movzbl (%rdi,%r10,1),%r11d
ffffffff8b47efcd:	45 84 db             	test   %r11b,%r11b
ffffffff8b47efd0:	74 ee                	je     ffffffff8b47efc0 <frame_candidate_abefa4+0x1c>
ffffffff8b47efd2:	42 8d 1c 11          	lea    (%rcx,%r10,1),%ebx
ffffffff8b47efd6:	83 e3 0f             	and    $0xf,%ebx
ffffffff8b47efd9:	42 0f b6 1c 0b       	movzbl (%rbx,%r9,1),%ebx
ffffffff8b47efde:	41 38 db             	cmp    %bl,%r11b
ffffffff8b47efe1:	45 0f b6 db          	movzbl %r11b,%r11d
ffffffff8b47efe5:	45 0f 44 d8          	cmove  %r8d,%r11d
ffffffff8b47efe9:	41 30 db             	xor    %bl,%r11b
ffffffff8b47efec:	46 88 1c 17          	mov    %r11b,(%rdi,%r10,1)
ffffffff8b47eff0:	eb ce                	jmp    ffffffff8b47efc0 <frame_candidate_abefa4+0x1c>
ffffffff8b47eff2:	88 04 17             	mov    %al,(%rdi,%rdx,1)
ffffffff8b47eff5:	5b                   	pop    %rbx
ffffffff8b47eff6:	5d                   	pop    %rbp
ffffffff8b47eff7:	c3                   	ret
ffffffff8b47eff8:	90                   	nop
ffffffff8b47eff9:	90                   	nop
ffffffff8b47effa:	90                   	nop
ffffffff8b47effb:	90                   	nop
ffffffff8b47effc:	90                   	nop
ffffffff8b47effd:	90                   	nop
ffffffff8b47effe:	90                   	nop
ffffffff8b47efff:	90                   	nop

ffffffff8b47f000 <frame_candidate_abf000>:
ffffffff8b47f000:	55                   	push   %rbp
ffffffff8b47f001:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f004:	41 57                	push   %r15
ffffffff8b47f006:	41 56                	push   %r14
ffffffff8b47f008:	41 55                	push   %r13
ffffffff8b47f00a:	41 54                	push   %r12
ffffffff8b47f00c:	53                   	push   %rbx
ffffffff8b47f00d:	50                   	push   %rax
ffffffff8b47f00e:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47f011:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47f014:	41 89 fc             	mov    %edi,%r12d
ffffffff8b47f017:	e8 44 93 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47f01c:	89 c3                	mov    %eax,%ebx
ffffffff8b47f01e:	41 89 c5             	mov    %eax,%r13d
ffffffff8b47f021:	85 c0                	test   %eax,%eax
ffffffff8b47f023:	0f 88 b0 00 00 00    	js     ffffffff8b47f0d9 <frame_candidate_abf000+0xd9>
ffffffff8b47f029:	e8 e2 f6 02 00       	call   ffffffff8b4ae710 <frame_candidate_abf510+0x2f200>
ffffffff8b47f02e:	85 c0                	test   %eax,%eax
ffffffff8b47f030:	74 08                	je     ffffffff8b47f03a <frame_candidate_abf000+0x3a>
ffffffff8b47f032:	41 89 c5             	mov    %eax,%r13d
ffffffff8b47f035:	e9 9f 00 00 00       	jmp    ffffffff8b47f0d9 <frame_candidate_abf000+0xd9>
ffffffff8b47f03a:	80 3d e3 7d 13 03 01 	cmpb   $0x1,0x3137de3(%rip)        # ffffffff8e5b6e24 <frame_candidate_abf510+0x3137914>
ffffffff8b47f041:	41 bd 03 06 0d 80    	mov    $0x800d0603,%r13d
ffffffff8b47f047:	0f 85 8c 00 00 00    	jne    ffffffff8b47f0d9 <frame_candidate_abf000+0xd9>
ffffffff8b47f04d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47f050:	e8 1b d7 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47f055:	85 c0                	test   %eax,%eax
ffffffff8b47f057:	75 d9                	jne    ffffffff8b47f032 <frame_candidate_abf000+0x32>
ffffffff8b47f059:	41 bd 02 02 0d 80    	mov    $0x800d0202,%r13d
ffffffff8b47f05f:	41 83 fc 04          	cmp    $0x4,%r12d
ffffffff8b47f063:	77 74                	ja     ffffffff8b47f0d9 <frame_candidate_abf000+0xd9>
ffffffff8b47f065:	44 89 e2             	mov    %r12d,%edx
ffffffff8b47f068:	48 8d 0d c1 23 3d 00 	lea    0x3d23c1(%rip),%rcx        # ffffffff8b851430 <frame_candidate_abf510+0x3d1f20>
ffffffff8b47f06f:	48 8d 04 52          	lea    (%rdx,%rdx,2),%rax
ffffffff8b47f073:	4c 3b 34 c1          	cmp    (%rcx,%rax,8),%r14
ffffffff8b47f077:	77 60                	ja     ffffffff8b47f0d9 <frame_candidate_abf000+0xd9>
ffffffff8b47f079:	44 89 e7             	mov    %r12d,%edi
ffffffff8b47f07c:	49 89 d5             	mov    %rdx,%r13
ffffffff8b47f07f:	e8 bc 00 03 00       	call   ffffffff8b4af140 <frame_candidate_abf510+0x2fc30>
ffffffff8b47f084:	b8 17 00 00 00       	mov    $0x17,%eax
ffffffff8b47f089:	44 0f a3 e0          	bt     %r12d,%eax
ffffffff8b47f08d:	73 31                	jae    ffffffff8b47f0c0 <frame_candidate_abf000+0xc0>
ffffffff8b47f08f:	48 8d 0d 9a 7d 13 03 	lea    0x3137d9a(%rip),%rcx        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47f096:	48 8d 05 6b d1 e1 00 	lea    0xe1d16b(%rip),%rax        # ffffffff8c29c208 <frame_candidate_abf510+0xe1ccf8>
ffffffff8b47f09d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47f0a0:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47f0a3:	4a 8b 34 e9          	mov    (%rcx,%r13,8),%rsi
ffffffff8b47f0a7:	4e 8b 24 e8          	mov    (%rax,%r13,8),%r12
ffffffff8b47f0ab:	e8 00 a0 79 ff       	call   ffffffff8ac190b0 <handler_628_body-0x864490>
ffffffff8b47f0b0:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47f0b3:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b47f0b6:	4c 89 e2             	mov    %r12,%rdx
ffffffff8b47f0b9:	e8 b2 fe ff ff       	call   ffffffff8b47ef70 <frame_candidate_abee20+0x150>
ffffffff8b47f0be:	eb 16                	jmp    ffffffff8b47f0d6 <frame_candidate_abf000+0xd6>
ffffffff8b47f0c0:	48 8d 05 69 7d 13 03 	lea    0x3137d69(%rip),%rax        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47f0c7:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47f0ca:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47f0cd:	4a 8b 34 e8          	mov    (%rax,%r13,8),%rsi
ffffffff8b47f0d1:	e8 da 9f 79 ff       	call   ffffffff8ac190b0 <handler_628_body-0x864490>
ffffffff8b47f0d6:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b47f0d9:	89 df                	mov    %ebx,%edi
ffffffff8b47f0db:	e8 60 93 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47f0e0:	44 89 e8             	mov    %r13d,%eax
ffffffff8b47f0e3:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47f0e7:	5b                   	pop    %rbx
ffffffff8b47f0e8:	41 5c                	pop    %r12
ffffffff8b47f0ea:	41 5d                	pop    %r13
ffffffff8b47f0ec:	41 5e                	pop    %r14
ffffffff8b47f0ee:	41 5f                	pop    %r15
ffffffff8b47f0f0:	5d                   	pop    %rbp
ffffffff8b47f0f1:	c3                   	ret
ffffffff8b47f0f2:	90                   	nop
ffffffff8b47f0f3:	90                   	nop
ffffffff8b47f0f4:	90                   	nop
ffffffff8b47f0f5:	90                   	nop
ffffffff8b47f0f6:	90                   	nop
ffffffff8b47f0f7:	90                   	nop
ffffffff8b47f0f8:	90                   	nop
ffffffff8b47f0f9:	90                   	nop
ffffffff8b47f0fa:	90                   	nop
ffffffff8b47f0fb:	90                   	nop
ffffffff8b47f0fc:	90                   	nop
ffffffff8b47f0fd:	90                   	nop
ffffffff8b47f0fe:	90                   	nop
ffffffff8b47f0ff:	90                   	nop

ffffffff8b47f100 <frame_candidate_abf100>:
ffffffff8b47f100:	55                   	push   %rbp
ffffffff8b47f101:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f104:	41 56                	push   %r14
ffffffff8b47f106:	53                   	push   %rbx
ffffffff8b47f107:	e8 54 92 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47f10c:	89 c3                	mov    %eax,%ebx
ffffffff8b47f10e:	41 89 c6             	mov    %eax,%r14d
ffffffff8b47f111:	85 c0                	test   %eax,%eax
ffffffff8b47f113:	78 15                	js     ffffffff8b47f12a <frame_candidate_abf100+0x2a>
ffffffff8b47f115:	e8 76 d2 02 00       	call   ffffffff8b4ac390 <frame_candidate_abf510+0x2ce80>
ffffffff8b47f11a:	41 89 de             	mov    %ebx,%r14d
ffffffff8b47f11d:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b47f120:	74 08                	je     ffffffff8b47f12a <frame_candidate_abf100+0x2a>
ffffffff8b47f122:	e8 19 00 00 00       	call   ffffffff8b47f140 <frame_candidate_abf140>
ffffffff8b47f127:	41 89 c6             	mov    %eax,%r14d
ffffffff8b47f12a:	89 df                	mov    %ebx,%edi
ffffffff8b47f12c:	e8 0f 93 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47f131:	44 89 f0             	mov    %r14d,%eax
ffffffff8b47f134:	5b                   	pop    %rbx
ffffffff8b47f135:	41 5e                	pop    %r14
ffffffff8b47f137:	5d                   	pop    %rbp
ffffffff8b47f138:	c3                   	ret
ffffffff8b47f139:	90                   	nop
ffffffff8b47f13a:	90                   	nop
ffffffff8b47f13b:	90                   	nop
ffffffff8b47f13c:	90                   	nop
ffffffff8b47f13d:	90                   	nop
ffffffff8b47f13e:	90                   	nop
ffffffff8b47f13f:	90                   	nop

ffffffff8b47f140 <frame_candidate_abf140>:
ffffffff8b47f140:	55                   	push   %rbp
ffffffff8b47f141:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f144:	c6 05 0d 7d 13 03 01 	movb   $0x1,0x3137d0d(%rip)        # ffffffff8e5b6e58 <frame_candidate_abf510+0x3137948>
ffffffff8b47f14b:	e8 30 74 a0 ff       	call   ffffffff8ae86580 <handler_628_body-0x5f6fc0>
ffffffff8b47f150:	85 c0                	test   %eax,%eax
ffffffff8b47f152:	75 13                	jne    ffffffff8b47f167 <frame_candidate_abf140+0x27>
ffffffff8b47f154:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b47f159:	e8 62 b0 aa ff       	call   ffffffff8af2a1c0 <handler_628_body-0x553380>
ffffffff8b47f15e:	e8 ed a1 02 00       	call   ffffffff8b4a9350 <frame_candidate_abf510+0x29e40>
ffffffff8b47f163:	85 c0                	test   %eax,%eax
ffffffff8b47f165:	78 38                	js     ffffffff8b47f19f <frame_candidate_abf140+0x5f>
ffffffff8b47f167:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b47f16c:	e8 4f b0 aa ff       	call   ffffffff8af2a1c0 <handler_628_body-0x553380>
ffffffff8b47f171:	85 c0                	test   %eax,%eax
ffffffff8b47f173:	75 2a                	jne    ffffffff8b47f19f <frame_candidate_abf140+0x5f>
ffffffff8b47f175:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b47f17a:	e8 41 b0 aa ff       	call   ffffffff8af2a1c0 <handler_628_body-0x553380>
ffffffff8b47f17f:	85 c0                	test   %eax,%eax
ffffffff8b47f181:	75 1c                	jne    ffffffff8b47f19f <frame_candidate_abf140+0x5f>
ffffffff8b47f183:	bf 04 00 00 00       	mov    $0x4,%edi
ffffffff8b47f188:	e8 33 b0 aa ff       	call   ffffffff8af2a1c0 <handler_628_body-0x553380>
ffffffff8b47f18d:	85 c0                	test   %eax,%eax
ffffffff8b47f18f:	75 0e                	jne    ffffffff8b47f19f <frame_candidate_abf140+0x5f>
ffffffff8b47f191:	bf 05 00 00 00       	mov    $0x5,%edi
ffffffff8b47f196:	e8 25 b0 aa ff       	call   ffffffff8af2a1c0 <handler_628_body-0x553380>
ffffffff8b47f19b:	85 c0                	test   %eax,%eax
ffffffff8b47f19d:	74 02                	je     ffffffff8b47f1a1 <frame_candidate_abf140+0x61>
ffffffff8b47f19f:	5d                   	pop    %rbp
ffffffff8b47f1a0:	c3                   	ret
ffffffff8b47f1a1:	5d                   	pop    %rbp
ffffffff8b47f1a2:	e9 d9 bc 02 00       	jmp    ffffffff8b4aae80 <frame_candidate_abf510+0x2b970>
ffffffff8b47f1a7:	90                   	nop
ffffffff8b47f1a8:	90                   	nop
ffffffff8b47f1a9:	90                   	nop
ffffffff8b47f1aa:	90                   	nop
ffffffff8b47f1ab:	90                   	nop
ffffffff8b47f1ac:	90                   	nop
ffffffff8b47f1ad:	90                   	nop
ffffffff8b47f1ae:	90                   	nop
ffffffff8b47f1af:	90                   	nop

ffffffff8b47f1b0 <frame_candidate_abf1b0>:
ffffffff8b47f1b0:	55                   	push   %rbp
ffffffff8b47f1b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f1b4:	41 56                	push   %r14
ffffffff8b47f1b6:	53                   	push   %rbx
ffffffff8b47f1b7:	e8 a4 91 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47f1bc:	89 c3                	mov    %eax,%ebx
ffffffff8b47f1be:	41 89 c6             	mov    %eax,%r14d
ffffffff8b47f1c1:	85 c0                	test   %eax,%eax
ffffffff8b47f1c3:	78 08                	js     ffffffff8b47f1cd <frame_candidate_abf1b0+0x1d>
ffffffff8b47f1c5:	e8 06 db 02 00       	call   ffffffff8b4accd0 <frame_candidate_abf510+0x2d7c0>
ffffffff8b47f1ca:	41 89 c6             	mov    %eax,%r14d
ffffffff8b47f1cd:	89 df                	mov    %ebx,%edi
ffffffff8b47f1cf:	e8 6c 92 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47f1d4:	44 89 f0             	mov    %r14d,%eax
ffffffff8b47f1d7:	5b                   	pop    %rbx
ffffffff8b47f1d8:	41 5e                	pop    %r14
ffffffff8b47f1da:	5d                   	pop    %rbp
ffffffff8b47f1db:	c3                   	ret
ffffffff8b47f1dc:	90                   	nop
ffffffff8b47f1dd:	90                   	nop
ffffffff8b47f1de:	90                   	nop
ffffffff8b47f1df:	90                   	nop

ffffffff8b47f1e0 <frame_candidate_abf1e0>:
ffffffff8b47f1e0:	55                   	push   %rbp
ffffffff8b47f1e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f1e4:	41 56                	push   %r14
ffffffff8b47f1e6:	53                   	push   %rbx
ffffffff8b47f1e7:	e8 74 91 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47f1ec:	89 c3                	mov    %eax,%ebx
ffffffff8b47f1ee:	85 c0                	test   %eax,%eax
ffffffff8b47f1f0:	78 14                	js     ffffffff8b47f206 <frame_candidate_abf1e0+0x26>
ffffffff8b47f1f2:	e8 99 d1 02 00       	call   ffffffff8b4ac390 <frame_candidate_abf510+0x2ce80>
ffffffff8b47f1f7:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b47f1fa:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b47f1fd:	41 0f 95 c6          	setne  %r14b
ffffffff8b47f201:	45 01 f6             	add    %r14d,%r14d
ffffffff8b47f204:	eb 03                	jmp    ffffffff8b47f209 <frame_candidate_abf1e0+0x29>
ffffffff8b47f206:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b47f209:	89 df                	mov    %ebx,%edi
ffffffff8b47f20b:	e8 30 92 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47f210:	44 89 f0             	mov    %r14d,%eax
ffffffff8b47f213:	5b                   	pop    %rbx
ffffffff8b47f214:	41 5e                	pop    %r14
ffffffff8b47f216:	5d                   	pop    %rbp
ffffffff8b47f217:	c3                   	ret
ffffffff8b47f218:	90                   	nop
ffffffff8b47f219:	90                   	nop
ffffffff8b47f21a:	90                   	nop
ffffffff8b47f21b:	90                   	nop
ffffffff8b47f21c:	90                   	nop
ffffffff8b47f21d:	90                   	nop
ffffffff8b47f21e:	90                   	nop
ffffffff8b47f21f:	90                   	nop

ffffffff8b47f220 <frame_candidate_abf220>:
ffffffff8b47f220:	55                   	push   %rbp
ffffffff8b47f221:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f224:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b47f229:	83 ff 04             	cmp    $0x4,%edi
ffffffff8b47f22c:	77 0c                	ja     ffffffff8b47f23a <frame_candidate_abf220+0x1a>
ffffffff8b47f22e:	89 f8                	mov    %edi,%eax
ffffffff8b47f230:	48 8d 0d f9 cf e1 00 	lea    0xe1cff9(%rip),%rcx        # ffffffff8c29c230 <frame_candidate_abf510+0xe1cd20>
ffffffff8b47f237:	8b 04 81             	mov    (%rcx,%rax,4),%eax
ffffffff8b47f23a:	5d                   	pop    %rbp
ffffffff8b47f23b:	c3                   	ret
ffffffff8b47f23c:	90                   	nop
ffffffff8b47f23d:	90                   	nop
ffffffff8b47f23e:	90                   	nop
ffffffff8b47f23f:	90                   	nop

ffffffff8b47f240 <frame_candidate_abf240>:
ffffffff8b47f240:	55                   	push   %rbp
ffffffff8b47f241:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f244:	41 57                	push   %r15
ffffffff8b47f246:	41 56                	push   %r14
ffffffff8b47f248:	41 55                	push   %r13
ffffffff8b47f24a:	41 54                	push   %r12
ffffffff8b47f24c:	53                   	push   %rbx
ffffffff8b47f24d:	50                   	push   %rax
ffffffff8b47f24e:	49 89 d6             	mov    %rdx,%r14
ffffffff8b47f251:	49 89 f7             	mov    %rsi,%r15
ffffffff8b47f254:	41 89 fd             	mov    %edi,%r13d
ffffffff8b47f257:	e8 04 91 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47f25c:	89 c3                	mov    %eax,%ebx
ffffffff8b47f25e:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47f261:	85 c0                	test   %eax,%eax
ffffffff8b47f263:	78 47                	js     ffffffff8b47f2ac <frame_candidate_abf240+0x6c>
ffffffff8b47f265:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47f268:	e8 03 d5 02 00       	call   ffffffff8b4ac770 <frame_candidate_abf510+0x2d260>
ffffffff8b47f26d:	41 89 c4             	mov    %eax,%r12d
ffffffff8b47f270:	85 c0                	test   %eax,%eax
ffffffff8b47f272:	75 38                	jne    ffffffff8b47f2ac <frame_candidate_abf240+0x6c>
ffffffff8b47f274:	41 bc 02 02 0d 80    	mov    $0x800d0202,%r12d
ffffffff8b47f27a:	41 83 fd 01          	cmp    $0x1,%r13d
ffffffff8b47f27e:	77 2c                	ja     ffffffff8b47f2ac <frame_candidate_abf240+0x6c>
ffffffff8b47f280:	44 89 e8             	mov    %r13d,%eax
ffffffff8b47f283:	48 8d 0d 26 22 3d 00 	lea    0x3d2226(%rip),%rcx        # ffffffff8b8514b0 <frame_candidate_abf510+0x3d1fa0>
ffffffff8b47f28a:	48 c1 e0 04          	shl    $0x4,%rax
ffffffff8b47f28e:	48 63 54 08 08       	movslq 0x8(%rax,%rcx,1),%rdx
ffffffff8b47f293:	49 39 d6             	cmp    %rdx,%r14
ffffffff8b47f296:	72 14                	jb     ffffffff8b47f2ac <frame_candidate_abf240+0x6c>
ffffffff8b47f298:	48 01 c1             	add    %rax,%rcx
ffffffff8b47f29b:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b47f29e:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b47f2a1:	48 8b 31             	mov    (%rcx),%rsi
ffffffff8b47f2a4:	e8 47 a0 02 00       	call   ffffffff8b4a92f0 <frame_candidate_abf510+0x29de0>
ffffffff8b47f2a9:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b47f2ac:	89 df                	mov    %ebx,%edi
ffffffff8b47f2ae:	e8 8d 91 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47f2b3:	44 89 e0             	mov    %r12d,%eax
ffffffff8b47f2b6:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47f2ba:	5b                   	pop    %rbx
ffffffff8b47f2bb:	41 5c                	pop    %r12
ffffffff8b47f2bd:	41 5d                	pop    %r13
ffffffff8b47f2bf:	41 5e                	pop    %r14
ffffffff8b47f2c1:	41 5f                	pop    %r15
ffffffff8b47f2c3:	5d                   	pop    %rbp
ffffffff8b47f2c4:	c3                   	ret
ffffffff8b47f2c5:	90                   	nop
ffffffff8b47f2c6:	90                   	nop
ffffffff8b47f2c7:	90                   	nop
ffffffff8b47f2c8:	90                   	nop
ffffffff8b47f2c9:	90                   	nop
ffffffff8b47f2ca:	90                   	nop
ffffffff8b47f2cb:	90                   	nop
ffffffff8b47f2cc:	90                   	nop
ffffffff8b47f2cd:	90                   	nop
ffffffff8b47f2ce:	90                   	nop
ffffffff8b47f2cf:	90                   	nop

ffffffff8b47f2d0 <frame_candidate_abf2d0>:
ffffffff8b47f2d0:	55                   	push   %rbp
ffffffff8b47f2d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f2d4:	41 56                	push   %r14
ffffffff8b47f2d6:	53                   	push   %rbx
ffffffff8b47f2d7:	89 fb                	mov    %edi,%ebx
ffffffff8b47f2d9:	e8 82 90 02 00       	call   ffffffff8b4a8360 <frame_candidate_abf510+0x28e50>
ffffffff8b47f2de:	41 89 c6             	mov    %eax,%r14d
ffffffff8b47f2e1:	85 c0                	test   %eax,%eax
ffffffff8b47f2e3:	78 1d                	js     ffffffff8b47f302 <frame_candidate_abf2d0+0x32>
ffffffff8b47f2e5:	41 be 02 02 0d 80    	mov    $0x800d0202,%r14d
ffffffff8b47f2eb:	83 fb 01             	cmp    $0x1,%ebx
ffffffff8b47f2ee:	77 12                	ja     ffffffff8b47f302 <frame_candidate_abf2d0+0x32>
ffffffff8b47f2f0:	89 d9                	mov    %ebx,%ecx
ffffffff8b47f2f2:	48 8d 15 b7 21 3d 00 	lea    0x3d21b7(%rip),%rdx        # ffffffff8b8514b0 <frame_candidate_abf510+0x3d1fa0>
ffffffff8b47f2f9:	48 c1 e1 04          	shl    $0x4,%rcx
ffffffff8b47f2fd:	44 8b 74 11 0c       	mov    0xc(%rcx,%rdx,1),%r14d
ffffffff8b47f302:	89 c7                	mov    %eax,%edi
ffffffff8b47f304:	e8 37 91 02 00       	call   ffffffff8b4a8440 <frame_candidate_abf510+0x28f30>
ffffffff8b47f309:	44 89 f0             	mov    %r14d,%eax
ffffffff8b47f30c:	5b                   	pop    %rbx
ffffffff8b47f30d:	41 5e                	pop    %r14
ffffffff8b47f30f:	5d                   	pop    %rbp
ffffffff8b47f310:	c3                   	ret
ffffffff8b47f311:	90                   	nop
ffffffff8b47f312:	90                   	nop
ffffffff8b47f313:	90                   	nop
ffffffff8b47f314:	90                   	nop
ffffffff8b47f315:	90                   	nop
ffffffff8b47f316:	90                   	nop
ffffffff8b47f317:	90                   	nop
ffffffff8b47f318:	90                   	nop
ffffffff8b47f319:	90                   	nop
ffffffff8b47f31a:	90                   	nop
ffffffff8b47f31b:	90                   	nop
ffffffff8b47f31c:	90                   	nop
ffffffff8b47f31d:	90                   	nop
ffffffff8b47f31e:	90                   	nop
ffffffff8b47f31f:	90                   	nop
ffffffff8b47f320:	80 3d fd 7a 13 03 00 	cmpb   $0x0,0x3137afd(%rip)        # ffffffff8e5b6e24 <frame_candidate_abf510+0x3137914>
ffffffff8b47f327:	b8 01 06 0d 80       	mov    $0x800d0601,%eax
ffffffff8b47f32c:	0f 85 23 01 00 00    	jne    ffffffff8b47f455 <frame_candidate_abf33f+0x116>
ffffffff8b47f332:	f6 05 1f 7b 13 03 01 	testb  $0x1,0x3137b1f(%rip)        # ffffffff8e5b6e58 <frame_candidate_abf510+0x3137948>
ffffffff8b47f339:	0f 85 16 01 00 00    	jne    ffffffff8b47f455 <frame_candidate_abf33f+0x116>

ffffffff8b47f33f <frame_candidate_abf33f>:
ffffffff8b47f33f:	55                   	push   %rbp
ffffffff8b47f340:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f343:	48 8d 35 96 ec e0 01 	lea    0x1e0ec96(%rip),%rsi        # ffffffff8d28dfe0 <frame_candidate_abf510+0x1e0ead0>
ffffffff8b47f34a:	bf 00 0c 00 00       	mov    $0xc00,%edi
ffffffff8b47f34f:	ba 01 01 00 00       	mov    $0x101,%edx
ffffffff8b47f354:	e8 f7 97 14 00       	call   ffffffff8b5c8b50 <frame_candidate_abf510+0x149640>
ffffffff8b47f359:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47f35c:	b8 11 02 0d 80       	mov    $0x800d0211,%eax
ffffffff8b47f361:	48 85 ff             	test   %rdi,%rdi
ffffffff8b47f364:	0f 84 ea 00 00 00    	je     ffffffff8b47f454 <frame_candidate_abf33f+0x115>
ffffffff8b47f36a:	be 00 0c 00 00       	mov    $0xc00,%esi
ffffffff8b47f36f:	48 89 3d ba 7a 13 03 	mov    %rdi,0x3137aba(%rip)        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47f376:	e8 75 9c 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47f37b:	48 8d 35 5e ec e0 01 	lea    0x1e0ec5e(%rip),%rsi        # ffffffff8d28dfe0 <frame_candidate_abf510+0x1e0ead0>
ffffffff8b47f382:	bf 00 00 0a 00       	mov    $0xa0000,%edi
ffffffff8b47f387:	ba 01 01 00 00       	mov    $0x101,%edx
ffffffff8b47f38c:	e8 bf 97 14 00       	call   ffffffff8b5c8b50 <frame_candidate_abf510+0x149640>
ffffffff8b47f391:	48 85 c0             	test   %rax,%rax
ffffffff8b47f394:	0f 84 b5 00 00 00    	je     ffffffff8b47f44f <frame_candidate_abf33f+0x110>
ffffffff8b47f39a:	be 00 00 0a 00       	mov    $0xa0000,%esi
ffffffff8b47f39f:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47f3a2:	48 89 05 8f 7a 13 03 	mov    %rax,0x3137a8f(%rip)        # ffffffff8e5b6e38 <frame_candidate_abf510+0x3137928>
ffffffff8b47f3a9:	e8 42 9c 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47f3ae:	48 8d 35 2b ec e0 01 	lea    0x1e0ec2b(%rip),%rsi        # ffffffff8d28dfe0 <frame_candidate_abf510+0x1e0ead0>
ffffffff8b47f3b5:	bf 00 80 02 00       	mov    $0x28000,%edi
ffffffff8b47f3ba:	ba 01 01 00 00       	mov    $0x101,%edx
ffffffff8b47f3bf:	e8 8c 97 14 00       	call   ffffffff8b5c8b50 <frame_candidate_abf510+0x149640>
ffffffff8b47f3c4:	48 85 c0             	test   %rax,%rax
ffffffff8b47f3c7:	0f 84 82 00 00 00    	je     ffffffff8b47f44f <frame_candidate_abf33f+0x110>
ffffffff8b47f3cd:	be 00 80 02 00       	mov    $0x28000,%esi
ffffffff8b47f3d2:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47f3d5:	48 89 05 64 7a 13 03 	mov    %rax,0x3137a64(%rip)        # ffffffff8e5b6e40 <frame_candidate_abf510+0x3137930>
ffffffff8b47f3dc:	e8 0f 9c 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47f3e1:	48 8d 35 f8 eb e0 01 	lea    0x1e0ebf8(%rip),%rsi        # ffffffff8d28dfe0 <frame_candidate_abf510+0x1e0ead0>
ffffffff8b47f3e8:	bf 00 40 01 00       	mov    $0x14000,%edi
ffffffff8b47f3ed:	ba 01 01 00 00       	mov    $0x101,%edx
ffffffff8b47f3f2:	e8 59 97 14 00       	call   ffffffff8b5c8b50 <frame_candidate_abf510+0x149640>
ffffffff8b47f3f7:	48 85 c0             	test   %rax,%rax
ffffffff8b47f3fa:	74 53                	je     ffffffff8b47f44f <frame_candidate_abf33f+0x110>
ffffffff8b47f3fc:	be 00 40 01 00       	mov    $0x14000,%esi
ffffffff8b47f401:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47f404:	48 89 05 3d 7a 13 03 	mov    %rax,0x3137a3d(%rip)        # ffffffff8e5b6e48 <frame_candidate_abf510+0x3137938>
ffffffff8b47f40b:	e8 e0 9b 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47f410:	48 8d 35 c9 eb e0 01 	lea    0x1e0ebc9(%rip),%rsi        # ffffffff8d28dfe0 <frame_candidate_abf510+0x1e0ead0>
ffffffff8b47f417:	bf 00 18 00 00       	mov    $0x1800,%edi
ffffffff8b47f41c:	ba 01 01 00 00       	mov    $0x101,%edx
ffffffff8b47f421:	e8 2a 97 14 00       	call   ffffffff8b5c8b50 <frame_candidate_abf510+0x149640>
ffffffff8b47f426:	48 89 c7             	mov    %rax,%rdi
ffffffff8b47f429:	48 85 c0             	test   %rax,%rax
ffffffff8b47f42c:	b8 11 02 0d 80       	mov    $0x800d0211,%eax
ffffffff8b47f431:	74 21                	je     ffffffff8b47f454 <frame_candidate_abf33f+0x115>
ffffffff8b47f433:	be 00 18 00 00       	mov    $0x1800,%esi
ffffffff8b47f438:	48 89 3d 11 7a 13 03 	mov    %rdi,0x3137a11(%rip)        # ffffffff8e5b6e50 <frame_candidate_abf510+0x3137940>
ffffffff8b47f43f:	e8 ac 9b 79 ff       	call   ffffffff8ac18ff0 <handler_628_body-0x864550>
ffffffff8b47f444:	31 c0                	xor    %eax,%eax
ffffffff8b47f446:	c6 05 d7 79 13 03 01 	movb   $0x1,0x31379d7(%rip)        # ffffffff8e5b6e24 <frame_candidate_abf510+0x3137914>
ffffffff8b47f44d:	eb 05                	jmp    ffffffff8b47f454 <frame_candidate_abf33f+0x115>
ffffffff8b47f44f:	b8 11 02 0d 80       	mov    $0x800d0211,%eax
ffffffff8b47f454:	5d                   	pop    %rbp
ffffffff8b47f455:	c3                   	ret
ffffffff8b47f456:	90                   	nop
ffffffff8b47f457:	90                   	nop
ffffffff8b47f458:	90                   	nop
ffffffff8b47f459:	90                   	nop
ffffffff8b47f45a:	90                   	nop
ffffffff8b47f45b:	90                   	nop
ffffffff8b47f45c:	90                   	nop
ffffffff8b47f45d:	90                   	nop
ffffffff8b47f45e:	90                   	nop
ffffffff8b47f45f:	90                   	nop

ffffffff8b47f460 <frame_candidate_abf460>:
ffffffff8b47f460:	55                   	push   %rbp
ffffffff8b47f461:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f464:	53                   	push   %rbx
ffffffff8b47f465:	50                   	push   %rax
ffffffff8b47f466:	48 8d 1d 73 eb e0 01 	lea    0x1e0eb73(%rip),%rbx        # ffffffff8d28dfe0 <frame_candidate_abf510+0x1e0ead0>
ffffffff8b47f46d:	48 8b 3d bc 79 13 03 	mov    0x31379bc(%rip),%rdi        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47f474:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47f477:	e8 74 99 14 00       	call   ffffffff8b5c8df0 <frame_candidate_abf510+0x1498e0>
ffffffff8b47f47c:	48 c7 05 a9 79 13 03 	movq   $0x0,0x31379a9(%rip)        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47f483:	00 00 00 00 
ffffffff8b47f487:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47f48a:	48 8b 3d a7 79 13 03 	mov    0x31379a7(%rip),%rdi        # ffffffff8e5b6e38 <frame_candidate_abf510+0x3137928>
ffffffff8b47f491:	e8 5a 99 14 00       	call   ffffffff8b5c8df0 <frame_candidate_abf510+0x1498e0>
ffffffff8b47f496:	48 c7 05 97 79 13 03 	movq   $0x0,0x3137997(%rip)        # ffffffff8e5b6e38 <frame_candidate_abf510+0x3137928>
ffffffff8b47f49d:	00 00 00 00 
ffffffff8b47f4a1:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47f4a4:	48 8b 3d 95 79 13 03 	mov    0x3137995(%rip),%rdi        # ffffffff8e5b6e40 <frame_candidate_abf510+0x3137930>
ffffffff8b47f4ab:	e8 40 99 14 00       	call   ffffffff8b5c8df0 <frame_candidate_abf510+0x1498e0>
ffffffff8b47f4b0:	48 c7 05 85 79 13 03 	movq   $0x0,0x3137985(%rip)        # ffffffff8e5b6e40 <frame_candidate_abf510+0x3137930>
ffffffff8b47f4b7:	00 00 00 00 
ffffffff8b47f4bb:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47f4be:	48 8b 3d 83 79 13 03 	mov    0x3137983(%rip),%rdi        # ffffffff8e5b6e48 <frame_candidate_abf510+0x3137938>
ffffffff8b47f4c5:	e8 26 99 14 00       	call   ffffffff8b5c8df0 <frame_candidate_abf510+0x1498e0>
ffffffff8b47f4ca:	48 c7 05 73 79 13 03 	movq   $0x0,0x3137973(%rip)        # ffffffff8e5b6e48 <frame_candidate_abf510+0x3137938>
ffffffff8b47f4d1:	00 00 00 00 
ffffffff8b47f4d5:	48 89 de             	mov    %rbx,%rsi
ffffffff8b47f4d8:	48 8b 3d 71 79 13 03 	mov    0x3137971(%rip),%rdi        # ffffffff8e5b6e50 <frame_candidate_abf510+0x3137940>
ffffffff8b47f4df:	e8 0c 99 14 00       	call   ffffffff8b5c8df0 <frame_candidate_abf510+0x1498e0>
ffffffff8b47f4e4:	48 c7 05 61 79 13 03 	movq   $0x0,0x3137961(%rip)        # ffffffff8e5b6e50 <frame_candidate_abf510+0x3137940>
ffffffff8b47f4eb:	00 00 00 00 
ffffffff8b47f4ef:	c6 05 2e 79 13 03 00 	movb   $0x0,0x313792e(%rip)        # ffffffff8e5b6e24 <frame_candidate_abf510+0x3137914>
ffffffff8b47f4f6:	c6 05 5b 79 13 03 00 	movb   $0x0,0x313795b(%rip)        # ffffffff8e5b6e58 <frame_candidate_abf510+0x3137948>
ffffffff8b47f4fd:	31 c0                	xor    %eax,%eax
ffffffff8b47f4ff:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b47f503:	5b                   	pop    %rbx
ffffffff8b47f504:	5d                   	pop    %rbp
ffffffff8b47f505:	c3                   	ret
ffffffff8b47f506:	90                   	nop
ffffffff8b47f507:	90                   	nop
ffffffff8b47f508:	90                   	nop
ffffffff8b47f509:	90                   	nop
ffffffff8b47f50a:	90                   	nop
ffffffff8b47f50b:	90                   	nop
ffffffff8b47f50c:	90                   	nop
ffffffff8b47f50d:	90                   	nop
ffffffff8b47f50e:	90                   	nop
ffffffff8b47f50f:	90                   	nop

ffffffff8b47f510 <frame_candidate_abf510>:
ffffffff8b47f510:	55                   	push   %rbp
ffffffff8b47f511:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b47f514:	83 ff 04             	cmp    $0x4,%edi
ffffffff8b47f517:	77 20                	ja     ffffffff8b47f539 <frame_candidate_abf510+0x29>
ffffffff8b47f519:	89 f8                	mov    %edi,%eax
ffffffff8b47f51b:	48 8d 15 0e 1f 3d 00 	lea    0x3d1f0e(%rip),%rdx        # ffffffff8b851430 <frame_candidate_abf510+0x3d1f20>
ffffffff8b47f522:	48 8d 0c 40          	lea    (%rax,%rax,2),%rcx
ffffffff8b47f526:	48 3b 34 ca          	cmp    (%rdx,%rcx,8),%rsi
ffffffff8b47f52a:	75 0d                	jne    ffffffff8b47f539 <frame_candidate_abf510+0x29>
ffffffff8b47f52c:	48 8d 0d fd 78 13 03 	lea    0x31378fd(%rip),%rcx        # ffffffff8e5b6e30 <frame_candidate_abf510+0x3137920>
ffffffff8b47f533:	48 8b 04 c1          	mov    (%rcx,%rax,8),%rax
ffffffff8b47f537:	5d                   	pop    %rbp
ffffffff8b47f538:	c3                   	ret
ffffffff8b47f539:	31 c0                	xor    %eax,%eax
ffffffff8b47f53b:	5d                   	pop    %rbp
ffffffff8b47f53c:	c3                   	ret
ffffffff8b47f53d:	90                   	nop
ffffffff8b47f53e:	90                   	nop
ffffffff8b47f53f:	90                   	nop
