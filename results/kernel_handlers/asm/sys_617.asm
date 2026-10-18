; REA 6.7.0 full disassembly of handler_617.bin
; SHA256 1eb1b195fb4eccd01454ce2180a205a881830195c6c7d8b15af1854a2e85350c; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25e78, kernel RVA 0x265e78.
; REA inspect_with_objdump Evidence: ev_26990e095ba09355aabe0454633eaf5d624ea70b05a47e41589313f6c62ae292
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 617; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_617.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25e78 <handler_617_entry>:
ffffffff8ac25e78:	e9 f3 c6 66 00       	jmp    ffffffff8b292570 <neighbor_trampoline_266e70+0x66b700>
ffffffff8ac25e7d:	cc                   	int3
ffffffff8ac25e7e:	cc                   	int3
ffffffff8ac25e7f:	cc                   	int3

ffffffff8ac25e80 <neighbor_trampoline_265e80>:
ffffffff8ac25e80:	e9 6b 72 85 00       	jmp    ffffffff8b47d0f0 <neighbor_trampoline_266e70+0x856280>
ffffffff8ac25e85:	cc                   	int3
ffffffff8ac25e86:	cc                   	int3
ffffffff8ac25e87:	cc                   	int3

ffffffff8ac25e88 <neighbor_trampoline_265e88>:
ffffffff8ac25e88:	e9 c3 17 7d 00       	jmp    ffffffff8b3f7650 <neighbor_trampoline_266e70+0x7d07e0>
ffffffff8ac25e8d:	cc                   	int3
ffffffff8ac25e8e:	cc                   	int3
ffffffff8ac25e8f:	cc                   	int3

ffffffff8ac25e90 <neighbor_trampoline_265e90>:
ffffffff8ac25e90:	e9 9b 75 85 00       	jmp    ffffffff8b47d430 <neighbor_trampoline_266e70+0x8565c0>
ffffffff8ac25e95:	cc                   	int3
ffffffff8ac25e96:	cc                   	int3
ffffffff8ac25e97:	cc                   	int3

ffffffff8ac25e98 <neighbor_trampoline_265e98>:
ffffffff8ac25e98:	e9 a3 6e 57 00       	jmp    ffffffff8b19cd40 <neighbor_trampoline_266e70+0x575ed0>
ffffffff8ac25e9d:	cc                   	int3
ffffffff8ac25e9e:	cc                   	int3
ffffffff8ac25e9f:	cc                   	int3

ffffffff8ac25ea0 <neighbor_trampoline_265ea0>:
ffffffff8ac25ea0:	e9 fb c6 66 00       	jmp    ffffffff8b2925a0 <neighbor_trampoline_266e70+0x66b730>
ffffffff8ac25ea5:	cc                   	int3
ffffffff8ac25ea6:	cc                   	int3
ffffffff8ac25ea7:	cc                   	int3

ffffffff8ac25ea8 <neighbor_trampoline_265ea8>:
ffffffff8ac25ea8:	e9 43 76 85 00       	jmp    ffffffff8b47d4f0 <neighbor_trampoline_266e70+0x856680>
ffffffff8ac25ead:	cc                   	int3
ffffffff8ac25eae:	cc                   	int3
ffffffff8ac25eaf:	cc                   	int3

ffffffff8ac25eb0 <neighbor_trampoline_265eb0>:
ffffffff8ac25eb0:	e9 db dd 39 00       	jmp    ffffffff8afc3c90 <neighbor_trampoline_266e70+0x39ce20>
ffffffff8ac25eb5:	cc                   	int3
ffffffff8ac25eb6:	cc                   	int3
ffffffff8ac25eb7:	cc                   	int3

ffffffff8ac25eb8 <neighbor_trampoline_265eb8>:
ffffffff8ac25eb8:	e9 33 ee 39 00       	jmp    ffffffff8afc4cf0 <neighbor_trampoline_266e70+0x39de80>
ffffffff8ac25ebd:	cc                   	int3
ffffffff8ac25ebe:	cc                   	int3
ffffffff8ac25ebf:	cc                   	int3

ffffffff8ac25ec0 <neighbor_trampoline_265ec0>:
ffffffff8ac25ec0:	e9 8b c9 23 00       	jmp    ffffffff8ae62850 <neighbor_trampoline_266e70+0x23b9e0>
ffffffff8ac25ec5:	cc                   	int3
ffffffff8ac25ec6:	cc                   	int3
ffffffff8ac25ec7:	cc                   	int3

ffffffff8ac25ec8 <neighbor_trampoline_265ec8>:
ffffffff8ac25ec8:	e9 73 76 85 00       	jmp    ffffffff8b47d540 <neighbor_trampoline_266e70+0x8566d0>
ffffffff8ac25ecd:	cc                   	int3
ffffffff8ac25ece:	cc                   	int3
ffffffff8ac25ecf:	cc                   	int3

ffffffff8ac25ed0 <neighbor_trampoline_265ed0>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266e70+0x6b57d0>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266e70+0x6b5e00>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266e70+0x1d1fc0>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266e70+0x1d2200>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266e70+0x1d22e0>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266e70+0x1d2530>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266e70+0x457660>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266e70+0x856ac0>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266e70+0x457750>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266e70+0x457990>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266e70+0x829fa0>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266e70+0x23bf70>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266e70+0x856c60>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266e70+0x7d07f0>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266e70+0x857350>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266e70+0x857940>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266e70+0x791380>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266e70+0x9826a0>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266e70+0x740ea0>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266e70+0x7426f0>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266e70+0x742fa0>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266e70+0x7430d0>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266e70+0x6945d0>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266e70+0x23c330>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266e70+0x857a40>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266e70+0x744380>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266e70+0x854b10>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266e70+0x492470>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266e70+0x1cdf30>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266e70+0x1cdf40>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266e70+0x1cdf50>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266e70+0x1d0f20>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266e70+0x1d1410>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266e70+0x87f820>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266e70+0x87f710>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266e70+0x1e2260>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_617_entry-0x1bf0b8>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266e70+0x1e3c00>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266e70+0x74f2a0>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_617_entry-0x1be808>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_617_entry-0x1be628>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_617_entry-0x1be5f8>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266e70+0x1eb1d0>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266e70+0x1ede50>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266e70+0x1f09b0>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266e70+0x207100>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266e70+0x207210>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266e70+0x20bb20>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266e70+0x20c540>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266e70+0x20ca40>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266e70+0x20d3e0>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266e70+0x20df40>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266e70+0x216180>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_617_entry-0x47e88>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266e70+0x229490>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266e70+0x229f40>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266e70+0x231140>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266e70+0x231170>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266e70+0x2317c0>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266e70+0x2317d0>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266e70+0x690d50>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266e70+0x68f990>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266e70+0x6905b0>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266e70+0x693110>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266e70+0x3784e0>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266e70+0x3789b0>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266e70+0x7cde70>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266e70+0x381630>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266e70+0x691380>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266e70+0x6925a0>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266e70+0x695580>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266e70+0x68fe20>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266e70+0xa4aba0>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266e70+0x851530>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266e70+0x851540>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266e70+0x693350>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266e70+0x690cd0>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266e70+0x239af0>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266e70+0x4c2910>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266e70+0x4c2920>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266e70+0x4c2930>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266e70+0x454720>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266e70+0x851f30>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266e70+0x693300>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266e70+0x918250>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266e70+0x918290>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266e70+0x692e80>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266e70+0x6938d0>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266e70+0x2ebd00>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266e70+0x2ebd80>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266e70+0x2ebde0>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266e70+0x2ebe10>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266e70+0x2ebe40>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266e70+0x2ebe70>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266e70+0x917990>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266e70+0x917d70>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266e70+0x918100>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266e70+0x99fec0>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266e70+0x52b820>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266e70+0x381cb0>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266e70+0x2ebea0>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266e70+0x9182f0>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266e70+0x3773e0>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266e70+0x7edbc0>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266e70+0x7edbd0>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266e70+0x7edbe0>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266e70+0x7edbf0>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266e70+0x7edc10>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266e70+0x7edc20>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266e70+0x6928b0>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266e70+0x7edc40>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266e70+0x68f670>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266e70+0x68f080>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266e70+0x7edbb0>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266e70+0x7edc00>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266e70+0x7edc30>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266e70+0x47e660>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266e70+0x918640>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266e70+0x5d67f0>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266e70+0x5d6950>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266e70+0x5d6c40>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266e70+0x5d7010>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266e70+0x692e10>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266e70+0x6932a0>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266e70+0x692340>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266e70+0x693680>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266e70+0x691220>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266e70+0x694d10>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266e70+0x690d10>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266e70+0x690a20>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266e70+0x694a30>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266e70+0x6916a0>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266e70+0x691990>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266e70+0x234210>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266e70+0x234220>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266e70+0x2f8be0>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266e70+0x9cda00>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266e70+0x575e80>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266e70+0x575e90>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266e70+0x575ea0>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266e70+0x575eb0>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266e70+0x575ec0>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266e70+0x33fe20>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266e70+0x340490>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266e70+0x3407a0>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266e70+0x340a90>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266e70+0xa359c0>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266e70+0x341090>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266e70+0x341200>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266e70+0x981610>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266e70+0x234230>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266e70+0x234250>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266e70+0x234260>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266e70+0x234270>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266e70+0x234280>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266e70+0x2c98b0>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266e70+0x2ca800>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266e70+0x692880>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266e70+0x2ca3c0>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266e70+0x59bf80>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266e70+0x9182d0>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266e70+0x87c770>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266e70+0x287fb0>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266e70+0x693ca0>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266e70+0x693fc0>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266e70+0x7623b0>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266e70+0x762290>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266e70+0x3db4a0>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266e70+0x3db9b0>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266e70+0x3dc870>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266e70+0x3dca60>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266e70+0x3dcdf0>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266e70+0x791420>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266e70+0x794d00>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266e70+0x7de410>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266e70+0xa20e30>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266e70+0x798190>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266e70+0x799910>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266e70+0x799970>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266e70+0x8579c0>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266e70+0x7960c0>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266e70+0x38a150>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266e70+0x690580>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266e70+0x2903e0>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266e70+0x796c60>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266e70+0x796f40>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266e70+0x7970a0>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266e70+0x3dd660>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266e70+0x3ea160>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266e70+0x797bc0>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266e70+0x290ad0>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266e70+0x851c70>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266e70+0x8547f0>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266e70+0x7973f0>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266e70+0x797670>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266e70+0x7977c0>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266e70+0x5314c0>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266e70+0x856190>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_617_entry-0x1695e8>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266e70+0x238220>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266e70+0x238390>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266e70+0x259720>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266e70+0x259740>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_617_entry-0x1bca48>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266e70+0x2634e0>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266e70+0x263bd0>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_617_entry-0x1bb968>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266e70+0x26e360>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266e70+0x5aa340>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_617_entry-0x24afe8>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266e70+0x2891c0>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266e70+0x294d60>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266e70+0x2a6060>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266e70+0x2a6070>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266e70+0x2a60c0>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266e70+0x2a6100>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266e70+0x2a6140>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266e70+0x2a6170>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266e70+0x2b7660>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266e70+0x2b80f0>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266e70+0x2b8190>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266e70+0x2b8240>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266e70+0x2b8470>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266e70+0x2b8800>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266e70+0x2b9070>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266e70+0x2cf590>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266e70+0x2dde30>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266e70+0x2dfa80>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_617_entry-0x1b4848>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_617_entry-0x1b3ec8>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266e70+0x2f50d0>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266e70+0x2f51c0>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266e70+0x2f51e0>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266e70+0x307390>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266e70+0x318630>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266e70+0x72d770>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266e70+0x31eae0>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266e70+0x3329b0>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266e70+0x333570>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266e70+0x3336c0>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266e70+0x333890>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266e70+0x333960>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266e70+0x333be0>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266e70+0x333cf0>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266e70+0x333df0>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266e70+0x375060>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266e70+0x3848b0>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266e70+0x3851c0>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266e70+0x385c60>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266e70+0x3865d0>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266e70+0x386cc0>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_617_entry-0x117bf8>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266e70+0x38aa40>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266e70+0x38bcc0>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266e70+0x396250>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266e70+0x399810>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266e70+0x39a0d0>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266e70+0x87f630>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266e70+0x3c6c30>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266e70+0x3c9460>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266e70+0x3ce0a0>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266e70+0x3d86b0>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266e70+0x3f0b40>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266e70+0xa404a0>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266e70+0x3fc000>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266e70+0x3fc010>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266e70+0x411fa0>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266e70+0x411ff0>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266e70+0x412050>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266e70+0x4120f0>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266e70+0x412320>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266e70+0x4124f0>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266e70+0x412810>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_617_entry-0x2322e8>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_617_entry-0x2321d8>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_617_entry-0x232158>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_617_entry-0x228f08>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_617_entry-0x228d98>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_617_entry-0x228818>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_617_entry-0x227d78>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_617_entry-0x227d18>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_617_entry-0x227cb8>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_617_entry-0x226e08>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_617_entry-0x226da8>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_617_entry-0x2269c8>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_617_entry-0x226968>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_617_entry-0x226908>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_617_entry-0x2262c8>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_617_entry-0x225eb8>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_617_entry-0x225518>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_617_entry-0x225328>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_617_entry-0x225248>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_617_entry-0x224848>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_617_entry-0x224728>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_617_entry-0x224648>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_617_entry-0x2245b8>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_617_entry-0x223e18>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_617_entry-0x2239a8>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_617_entry-0x2238d8>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_617_entry-0x223878>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266e70+0x4291c0>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266e70+0x42fe50>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266e70+0x431760>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266e70+0x43b1e0>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266e70+0x43b440>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266e70+0x4477d0>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266e70+0x447980>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_617_entry-0xe4ac8>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266e70+0x458130>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_617_entry-0xdde38>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266e70+0x469c90>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266e70+0x46a290>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266e70+0x46a3f0>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266e70+0x46a570>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266e70+0x46a6b0>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266e70+0x46a7d0>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266e70+0x46a8b0>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266e70+0x4757f0>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266e70+0x475820>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266e70+0x475830>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266e70+0x479ab0>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266e70+0x47a5d0>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266e70+0x47a5e0>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_617_entry-0xdc408>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_617_entry-0xd53d8>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266e70+0x49bb00>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266e70+0x49bef0>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266e70+0x49f300>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266e70+0x49f380>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266e70+0x4a9090>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266e70+0x4a9140>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266e70+0x4a9350>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266e70+0x4a94b0>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266e70+0x4abd40>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266e70+0x4af4f0>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266e70+0x4c8b00>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266e70+0x4c8b20>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266e70+0x4c8bb0>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_617_entry-0x1f048>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266e70+0x4fd980>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266e70+0x50c8a0>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266e70+0x50eae0>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266e70+0x533020>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266e70+0x54c380>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266e70+0x57b530>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266e70+0x581570>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266e70+0x581610>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266e70+0x9d4340>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266e70+0x9d5870>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266e70+0x9d5820>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266e70+0x9d58c0>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266e70+0x59b3b0>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266e70+0x59b680>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266e70+0x5a5700>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266e70+0x5c4490>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266e70+0x6ba070>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266e70+0x6b9d20>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266e70+0x5c99a0>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266e70+0x5ca090>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266e70+0x5ce440>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266e70+0x5ce450>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266e70+0x5ce460>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266e70+0x5ce480>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266e70+0x5ce5d0>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266e70+0x5ce5e0>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266e70+0x5ce620>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266e70+0x5cec60>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266e70+0x5e9a00>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266e70+0x609480>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266e70+0x609760>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266e70+0x60bc80>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266e70+0x60c990>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_617_entry-0x202438>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_617_entry-0x1ffb08>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_617_entry-0x17f8e8>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_617_entry-0x17f8d8>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_617_entry-0x17f718>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_617_entry-0x17f608>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_617_entry-0x17dee8>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_617_entry-0x17bed8>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_617_entry-0x17b808>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_617_entry-0x17b718>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_617_entry-0x17add8>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_617_entry-0x17ace8>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_617_entry-0x178e78>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_617_entry-0x178d68>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266e70+0x623a30>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266e70+0x635f80>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_617_entry-0x177328>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266e70+0x6643e0>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266e70+0x664520>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266e70+0x66c0f0>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266e70+0x66c120>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266e70+0x6713c0>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266e70+0x671f70>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266e70+0x672940>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266e70+0x672aa0>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266e70+0x673650>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266e70+0x673700>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266e70+0x673740>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266e70+0x69de10>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266e70+0x69dff0>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266e70+0x6b6590>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266e70+0x6b6630>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266e70+0x81b360>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266e70+0x8db2b0>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266e70+0x6fe0c0>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266e70+0x70f0e0>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266e70+0x70f390>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266e70+0x725ae0>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266e70+0x725dc0>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266e70+0x7260c0>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266e70+0x726870>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266e70+0x727760>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266e70+0x727890>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266e70+0x72b300>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266e70+0x72b3d0>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_617_entry-0x170a78>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266e70+0x73b4b0>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266e70+0x73e8b0>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266e70+0x745b30>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266e70+0x745bb0>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_617_entry-0xa7838>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266e70+0x757eb0>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266e70+0x75f1e0>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266e70+0x75f260>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266e70+0x75f410>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266e70+0x75f4a0>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266e70+0x75f620>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266e70+0x75f740>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266e70+0x75fa20>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266e70+0x7624d0>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266e70+0x7624f0>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266e70+0x762500>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266e70+0x762510>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266e70+0x773f40>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266e70+0x774130>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266e70+0x7759f0>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266e70+0x775dd0>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266e70+0x776010>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266e70+0x776690>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266e70+0xa43e60>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266e70+0x776960>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266e70+0x776b20>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266e70+0x776d30>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266e70+0x776d90>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266e70+0x776fe0>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266e70+0x777040>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266e70+0x777180>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266e70+0x777200>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266e70+0x777280>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266e70+0x779d20>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266e70+0x779e60>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266e70+0x779f00>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266e70+0x77a080>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266e70+0x77a1e0>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266e70+0x77a620>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266e70+0x79f770>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_617_entry-0x164b38>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266e70+0x7cc0c0>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266e70+0x7cc850>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266e70+0x7d1e20>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266e70+0x803c90>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266e70+0x803d40>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266e70+0x827da0>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266e70+0x827f90>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266e70+0x84a940>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266e70+0x859940>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266e70+0x85bc80>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_617_entry-0x14b728>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266e70+0x87a430>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266e70+0x87c590>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266e70+0x87c6c0>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266e70+0x87f550>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266e70+0x8a1070>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266e70+0x8a1320>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266e70+0x8a16c0>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266e70+0x8a19a0>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266e70+0x8a2830>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266e70+0x8a4680>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_617_entry-0x76d88>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_617_entry-0x75e18>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_617_entry-0x14a4c8>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266e70+0x8d42c0>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266e70+0x8e0bd0>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266e70+0x8e9550>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266e70+0x8ea0a0>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266e70+0x8ea140>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266e70+0x8ea240>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266e70+0x8ea320>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266e70+0x8ea420>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266e70+0x8ea460>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266e70+0x8ea4b0>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266e70+0x8efa30>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_617_entry-0x1cbd98>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266e70+0x904000>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266e70+0x904d20>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266e70+0x906b10>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266e70+0x906c30>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266e70+0x907310>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266e70+0x90a4b0>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8b292570, handler_body_617; REA Evidence ev_7b6ed1d2ce54837418f069bd977be633d4d97338092b98b90a28c9f451ebf0c9
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8b292570", "end": "0xffffffff8b292592"}], "total_bytes": 35, "span_bytes": 35, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_617:
0xffffffff8b292570: PUSH RBP
0xffffffff8b292571: MOV RBP, RSP
0xffffffff8b292574: PUSH RBX
0xffffffff8b292575: PUSH RAX
0xffffffff8b292576: MOV RBX, RSI
0xffffffff8b292579: CALL 0xffffffff8b48ce10
0xffffffff8b29257e: TEST EAX, EAX
0xffffffff8b292580: JZ 0xffffffff8b29258a
loc_ffffffff8b292582:
0xffffffff8b292582: MOVZX EDI, byte ptr [RBX]
0xffffffff8b292585: CALL 0xffffffff8b0284a0
loc_ffffffff8b29258a:
0xffffffff8b29258a: XOR EAX, EAX
0xffffffff8b29258c: ADD RSP, 0x8
0xffffffff8b292590: POP RBX
0xffffffff8b292591: POP RBP
0xffffffff8b292592: RET
; END FUNCTION handler_body_617

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_19f85fc0972f9208a64d12ef51747f53c4a246c50050948f84d624f80d1f8f7e
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_617.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8b292570 <handler_617_body>:
ffffffff8b292570:	55                   	push   %rbp
ffffffff8b292571:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292574:	53                   	push   %rbx
ffffffff8b292575:	50                   	push   %rax
ffffffff8b292576:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b292579:	e8 92 a8 1f 00       	call   ffffffff8b48ce10 <frame_candidate_8d4544+0x1f88cc>
ffffffff8b29257e:	85 c0                	test   %eax,%eax
ffffffff8b292580:	74 08                	je     ffffffff8b29258a <handler_617_body+0x1a>
ffffffff8b292582:	0f b6 3b             	movzbl (%rbx),%edi
ffffffff8b292585:	e8 16 5f d9 ff       	call   ffffffff8b0284a0 <handler_617_body-0x26a0d0>
ffffffff8b29258a:	31 c0                	xor    %eax,%eax
ffffffff8b29258c:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b292590:	5b                   	pop    %rbx
ffffffff8b292591:	5d                   	pop    %rbp
ffffffff8b292592:	c3                   	ret
ffffffff8b292593:	90                   	nop
ffffffff8b292594:	90                   	nop
ffffffff8b292595:	90                   	nop
ffffffff8b292596:	90                   	nop
ffffffff8b292597:	90                   	nop
ffffffff8b292598:	90                   	nop
ffffffff8b292599:	90                   	nop
ffffffff8b29259a:	90                   	nop
ffffffff8b29259b:	90                   	nop
ffffffff8b29259c:	90                   	nop
ffffffff8b29259d:	90                   	nop
ffffffff8b29259e:	90                   	nop
ffffffff8b29259f:	90                   	nop

ffffffff8b2925a0 <frame_candidate_8d25a0>:
ffffffff8b2925a0:	55                   	push   %rbp
ffffffff8b2925a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2925a4:	41 56                	push   %r14
ffffffff8b2925a6:	53                   	push   %rbx
ffffffff8b2925a7:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8b2925ab:	4c 8d 35 5e 9d 04 03 	lea    0x3049d5e(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_8d4544+0x3047dcc>
ffffffff8b2925b2:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b2925b5:	49 8b 06             	mov    (%r14),%rax
ffffffff8b2925b8:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8b2925bc:	48 8b bf 40 01 00 00 	mov    0x140(%rdi),%rdi
ffffffff8b2925c3:	e8 c8 69 d3 ff       	call   ffffffff8afc8f90 <handler_617_body-0x2c95e0>
ffffffff8b2925c8:	85 c0                	test   %eax,%eax
ffffffff8b2925ca:	74 46                	je     ffffffff8b292612 <frame_candidate_8d25a0+0x72>
ffffffff8b2925cc:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
ffffffff8b2925d3:	e8 38 a8 1f 00       	call   ffffffff8b48ce10 <frame_candidate_8d4544+0x1f88cc>
ffffffff8b2925d8:	85 c0                	test   %eax,%eax
ffffffff8b2925da:	74 09                	je     ffffffff8b2925e5 <frame_candidate_8d25a0+0x45>
ffffffff8b2925dc:	48 8d 7d e4          	lea    -0x1c(%rbp),%rdi
ffffffff8b2925e0:	e8 5b 5f d9 ff       	call   ffffffff8b028540 <handler_617_body-0x26a030>
ffffffff8b2925e5:	48 8b 1b             	mov    (%rbx),%rbx
ffffffff8b2925e8:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b2925ef:	00 00 
ffffffff8b2925f1:	48 8d 35 9f cc a7 00 	lea    0xa7cc9f(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_8d4544+0xa7ad53>
ffffffff8b2925f8:	31 d2                	xor    %edx,%edx
ffffffff8b2925fa:	e8 e1 7d 34 00       	call   ffffffff8b5da3e0 <frame_candidate_8d4544+0x345e9c>
ffffffff8b2925ff:	48 8d 7d e4          	lea    -0x1c(%rbp),%rdi
ffffffff8b292603:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b292608:	48 89 de             	mov    %rbx,%rsi
ffffffff8b29260b:	e8 c0 6b 98 ff       	call   ffffffff8ac191d0 <handler_617_body-0x6793a0>
ffffffff8b292610:	eb 05                	jmp    ffffffff8b292617 <frame_candidate_8d25a0+0x77>
ffffffff8b292612:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b292617:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8b29261a:	48 3b 4d e8          	cmp    -0x18(%rbp),%rcx
ffffffff8b29261e:	75 09                	jne    ffffffff8b292629 <frame_candidate_8d25a0+0x89>
ffffffff8b292620:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b292624:	5b                   	pop    %rbx
ffffffff8b292625:	41 5e                	pop    %r14
ffffffff8b292627:	5d                   	pop    %rbp
ffffffff8b292628:	c3                   	ret
ffffffff8b292629:	e8 82 b0 e2 ff       	call   ffffffff8b0bd6b0 <handler_617_body-0x1d4ec0>
ffffffff8b29262e:	0f 0b                	ud2

ffffffff8b292630 <frame_candidate_8d2630>:
ffffffff8b292630:	55                   	push   %rbp
ffffffff8b292631:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292634:	5d                   	pop    %rbp
ffffffff8b292635:	c3                   	ret
ffffffff8b292636:	90                   	nop
ffffffff8b292637:	90                   	nop
ffffffff8b292638:	90                   	nop
ffffffff8b292639:	90                   	nop
ffffffff8b29263a:	90                   	nop
ffffffff8b29263b:	90                   	nop
ffffffff8b29263c:	90                   	nop
ffffffff8b29263d:	90                   	nop
ffffffff8b29263e:	90                   	nop
ffffffff8b29263f:	90                   	nop

ffffffff8b292640 <frame_candidate_8d2640>:
ffffffff8b292640:	55                   	push   %rbp
ffffffff8b292641:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292644:	53                   	push   %rbx
ffffffff8b292645:	50                   	push   %rax
ffffffff8b292646:	be ff ff ff 7f       	mov    $0x7fffffff,%esi
ffffffff8b29264b:	31 ff                	xor    %edi,%edi
ffffffff8b29264d:	31 d2                	xor    %edx,%edx
ffffffff8b29264f:	e8 dc cb 13 00       	call   ffffffff8b3cf230 <frame_candidate_8d4544+0x13acec>
ffffffff8b292654:	48 8d 3d 45 56 27 03 	lea    0x3275645(%rip),%rdi        # ffffffff8e507ca0 <frame_candidate_8d4544+0x327375c>
ffffffff8b29265b:	48 8d 35 ed 67 9e 00 	lea    0x9e67ed(%rip),%rsi        # ffffffff8bc78e4f <frame_candidate_8d4544+0x9e490b>
ffffffff8b292662:	48 89 05 5f 56 27 03 	mov    %rax,0x327565f(%rip)        # ffffffff8e507cc8 <frame_candidate_8d4544+0x3273784>
ffffffff8b292669:	31 d2                	xor    %edx,%edx
ffffffff8b29266b:	31 c9                	xor    %ecx,%ecx
ffffffff8b29266d:	e8 5e 57 bf ff       	call   ffffffff8ae87dd0 <handler_617_body-0x40a7a0>
ffffffff8b292672:	48 8d 3d 2f 56 27 03 	lea    0x327562f(%rip),%rdi        # ffffffff8e507ca8 <frame_candidate_8d4544+0x3273764>
ffffffff8b292679:	48 8d 35 bf 20 ae 00 	lea    0xae20bf(%rip),%rsi        # ffffffff8bd7473f <frame_candidate_8d4544+0xae01fb>
ffffffff8b292680:	31 d2                	xor    %edx,%edx
ffffffff8b292682:	48 8d 1d ff 55 27 03 	lea    0x32755ff(%rip),%rbx        # ffffffff8e507c88 <frame_candidate_8d4544+0x3273744>
ffffffff8b292689:	e8 02 8c 37 00       	call   ffffffff8b60b290 <frame_candidate_8d4544+0x376d4c>
ffffffff8b29268e:	48 8d 3d 3b 56 27 03 	lea    0x327563b(%rip),%rdi        # ffffffff8e507cd0 <frame_candidate_8d4544+0x327378c>
ffffffff8b292695:	48 89 de             	mov    %rbx,%rsi
ffffffff8b292698:	31 d2                	xor    %edx,%edx
ffffffff8b29269a:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b29269e:	5b                   	pop    %rbx
ffffffff8b29269f:	5d                   	pop    %rbp
ffffffff8b2926a0:	e9 eb 8f 2c 00       	jmp    ffffffff8b55b690 <frame_candidate_8d4544+0x2c714c>
ffffffff8b2926a5:	90                   	nop
ffffffff8b2926a6:	90                   	nop
ffffffff8b2926a7:	90                   	nop
ffffffff8b2926a8:	90                   	nop
ffffffff8b2926a9:	90                   	nop
ffffffff8b2926aa:	90                   	nop
ffffffff8b2926ab:	90                   	nop
ffffffff8b2926ac:	90                   	nop
ffffffff8b2926ad:	90                   	nop
ffffffff8b2926ae:	90                   	nop
ffffffff8b2926af:	90                   	nop

ffffffff8b2926b0 <frame_candidate_8d26b0>:
ffffffff8b2926b0:	55                   	push   %rbp
ffffffff8b2926b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2926b4:	53                   	push   %rbx
ffffffff8b2926b5:	50                   	push   %rax
ffffffff8b2926b6:	e8 55 04 9e ff       	call   ffffffff8ac72b10 <handler_617_body-0x61fa60>
ffffffff8b2926bb:	48 89 c7             	mov    %rax,%rdi
ffffffff8b2926be:	48 89 c3             	mov    %rax,%rbx
ffffffff8b2926c1:	e8 ea d5 de ff       	call   ffffffff8b07fcb0 <handler_617_body-0x2128c0>
ffffffff8b2926c6:	8b 3d 44 56 27 03    	mov    0x3275644(%rip),%edi        # ffffffff8e507d10 <frame_candidate_8d4544+0x32737cc>
ffffffff8b2926cc:	85 ff                	test   %edi,%edi
ffffffff8b2926ce:	74 05                	je     ffffffff8b2926d5 <frame_candidate_8d26b0+0x25>
ffffffff8b2926d0:	e8 db 11 32 00       	call   ffffffff8b5b38b0 <frame_candidate_8d4544+0x31f36c>
ffffffff8b2926d5:	48 8b 73 30          	mov    0x30(%rbx),%rsi
ffffffff8b2926d9:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2926dc:	48 83 c7 20          	add    $0x20,%rdi
ffffffff8b2926e0:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b2926e4:	4c 8d 1d fd e2 99 ff 	lea    -0x661d03(%rip),%r11        # ffffffff8ac309e8 <handler_617_body-0x661b88>
ffffffff8b2926eb:	48 8d 05 64 f4 a2 00 	lea    0xa2f464(%rip),%rax        # ffffffff8bcc1b56 <frame_candidate_8d4544+0xa2d612>
ffffffff8b2926f2:	4c 8d 15 4e b5 ab 00 	lea    0xabb54e(%rip),%r10        # ffffffff8bd4dc47 <frame_candidate_8d4544+0xab9703>
ffffffff8b2926f9:	48 8d 0d d3 8b a7 00 	lea    0xa78bd3(%rip),%rcx        # ffffffff8bd0b2d3 <frame_candidate_8d4544+0xa76d8f>
ffffffff8b292700:	4c 8d 0d 0d 56 27 03 	lea    0x327560d(%rip),%r9        # ffffffff8e507d14 <frame_candidate_8d4544+0x32737d0>
ffffffff8b292707:	ba ff ff ff ff       	mov    $0xffffffff,%edx
ffffffff8b29270c:	41 b8 02 00 04 c0    	mov    $0xc0040002,%r8d
ffffffff8b292712:	6a 00                	push   $0x0
ffffffff8b292714:	50                   	push   %rax
ffffffff8b292715:	41 52                	push   %r10
ffffffff8b292717:	41 53                	push   %r11
ffffffff8b292719:	6a 00                	push   $0x0
ffffffff8b29271b:	e8 00 4a c8 ff       	call   ffffffff8af17120 <handler_617_body-0x37b450>
ffffffff8b292720:	48 83 c4 30          	add    $0x30,%rsp
ffffffff8b292724:	31 c0                	xor    %eax,%eax
ffffffff8b292726:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b29272a:	5b                   	pop    %rbx
ffffffff8b29272b:	5d                   	pop    %rbp
ffffffff8b29272c:	c3                   	ret
ffffffff8b29272d:	90                   	nop
ffffffff8b29272e:	90                   	nop
ffffffff8b29272f:	90                   	nop

ffffffff8b292730 <frame_candidate_8d2730>:
ffffffff8b292730:	55                   	push   %rbp
ffffffff8b292731:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292734:	89 3d d6 55 27 03    	mov    %edi,0x32755d6(%rip)        # ffffffff8e507d10 <frame_candidate_8d4544+0x32737cc>
ffffffff8b29273a:	5d                   	pop    %rbp
ffffffff8b29273b:	c3                   	ret
ffffffff8b29273c:	90                   	nop
ffffffff8b29273d:	90                   	nop
ffffffff8b29273e:	90                   	nop
ffffffff8b29273f:	90                   	nop

ffffffff8b292740 <frame_candidate_8d2740>:
ffffffff8b292740:	55                   	push   %rbp
ffffffff8b292741:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292744:	31 c0                	xor    %eax,%eax
ffffffff8b292746:	5d                   	pop    %rbp
ffffffff8b292747:	c3                   	ret
ffffffff8b292748:	90                   	nop
ffffffff8b292749:	90                   	nop
ffffffff8b29274a:	90                   	nop
ffffffff8b29274b:	90                   	nop
ffffffff8b29274c:	90                   	nop
ffffffff8b29274d:	90                   	nop
ffffffff8b29274e:	90                   	nop
ffffffff8b29274f:	90                   	nop

ffffffff8b292750 <frame_candidate_8d2750>:
ffffffff8b292750:	55                   	push   %rbp
ffffffff8b292751:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292754:	48 89 f2             	mov    %rsi,%rdx
ffffffff8b292757:	31 f6                	xor    %esi,%esi
ffffffff8b292759:	5d                   	pop    %rbp
ffffffff8b29275a:	e9 01 00 00 00       	jmp    ffffffff8b292760 <frame_candidate_8d2760>
ffffffff8b29275f:	90                   	nop

ffffffff8b292760 <frame_candidate_8d2760>:
ffffffff8b292760:	55                   	push   %rbp
ffffffff8b292761:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292764:	41 57                	push   %r15
ffffffff8b292766:	41 56                	push   %r14
ffffffff8b292768:	41 55                	push   %r13
ffffffff8b29276a:	41 54                	push   %r12
ffffffff8b29276c:	53                   	push   %rbx
ffffffff8b29276d:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8b292771:	49 89 fe             	mov    %rdi,%r14
ffffffff8b292774:	48 89 55 b0          	mov    %rdx,-0x50(%rbp)
ffffffff8b292778:	41 89 f7             	mov    %esi,%r15d
ffffffff8b29277b:	44 89 f0             	mov    %r14d,%eax
ffffffff8b29277e:	49 81 e6 00 c0 ff ff 	and    $0xffffffffffffc000,%r14
ffffffff8b292785:	25 ff 3f 00 00       	and    $0x3fff,%eax
ffffffff8b29278a:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b29278d:	8d 98 23 40 00 00    	lea    0x4023(%rax),%ebx
ffffffff8b292793:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8b292797:	81 e3 00 c0 00 00    	and    $0xc000,%ebx
ffffffff8b29279d:	e8 be 30 01 00       	call   ffffffff8b2a5860 <frame_candidate_8d4544+0x1131c>
ffffffff8b2927a2:	44 89 f9             	mov    %r15d,%ecx
ffffffff8b2927a5:	44 89 7d d4          	mov    %r15d,-0x2c(%rbp)
ffffffff8b2927a9:	c1 e1 0e             	shl    $0xe,%ecx
ffffffff8b2927ac:	4c 8d 3c 08          	lea    (%rax,%rcx,1),%r15
ffffffff8b2927b0:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
ffffffff8b2927b4:	81 fb 00 40 00 00    	cmp    $0x4000,%ebx
ffffffff8b2927ba:	74 49                	je     ffffffff8b292805 <frame_candidate_8d2760+0xa5>
ffffffff8b2927bc:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
ffffffff8b2927c0:	41 bc 00 40 00 00    	mov    $0x4000,%r12d
ffffffff8b2927c6:	4d 8d ae 00 40 00 00 	lea    0x4000(%r14),%r13
ffffffff8b2927cd:	49 29 dc             	sub    %rbx,%r12
ffffffff8b2927d0:	48 8d 9c 08 00 40 00 	lea    0x4000(%rax,%rcx,1),%rbx
ffffffff8b2927d7:	00 
ffffffff8b2927d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8b2927df:	00 
ffffffff8b2927e0:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2927e3:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b2927e6:	e8 65 c1 00 00       	call   ffffffff8b29e950 <frame_candidate_8d4544+0xa40c>
ffffffff8b2927eb:	0f 01 3b             	invlpg (%rbx)
ffffffff8b2927ee:	49 81 c5 00 40 00 00 	add    $0x4000,%r13
ffffffff8b2927f5:	48 81 c3 00 40 00 00 	add    $0x4000,%rbx
ffffffff8b2927fc:	49 81 c4 00 40 00 00 	add    $0x4000,%r12
ffffffff8b292803:	75 db                	jne    ffffffff8b2927e0 <frame_candidate_8d2760+0x80>
ffffffff8b292805:	48 8b 5d b8          	mov    -0x48(%rbp),%rbx
ffffffff8b292809:	4c 8b 65 b0          	mov    -0x50(%rbp),%r12
ffffffff8b29280d:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b292812:	49 01 df             	add    %rbx,%r15
ffffffff8b292815:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b292818:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b29281b:	e8 10 f2 ff ff       	call   ffffffff8b291a30 <handler_617_body-0xb40>
ffffffff8b292820:	85 c0                	test   %eax,%eax
ffffffff8b292822:	74 4d                	je     ffffffff8b292871 <frame_candidate_8d2760+0x111>
ffffffff8b292824:	44 89 fb             	mov    %r15d,%ebx
ffffffff8b292827:	49 81 e7 00 c0 ff ff 	and    $0xffffffffffffc000,%r15
ffffffff8b29282e:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b292831:	81 e3 ff 3f 00 00    	and    $0x3fff,%ebx
ffffffff8b292837:	81 c3 23 40 00 00    	add    $0x4023,%ebx
ffffffff8b29283d:	81 e3 00 c0 00 00    	and    $0xc000,%ebx
ffffffff8b292843:	48 f7 db             	neg    %rbx
ffffffff8b292846:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b29284d:	00 00 00 
ffffffff8b292850:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b292853:	e8 c8 c2 00 00       	call   ffffffff8b29eb20 <frame_candidate_8d4544+0xa5dc>
ffffffff8b292858:	41 0f 01 3f          	invlpg (%r15)
ffffffff8b29285c:	49 81 c7 00 40 00 00 	add    $0x4000,%r15
ffffffff8b292863:	48 81 c3 00 40 00 00 	add    $0x4000,%rbx
ffffffff8b29286a:	75 e4                	jne    ffffffff8b292850 <frame_candidate_8d2760+0xf0>
ffffffff8b29286c:	e9 f2 00 00 00       	jmp    ffffffff8b292963 <frame_candidate_8d2760+0x203>
ffffffff8b292871:	45 89 fd             	mov    %r15d,%r13d
ffffffff8b292874:	41 8b 47 04          	mov    0x4(%r15),%eax
ffffffff8b292878:	48 81 c3 ff 3f 00 00 	add    $0x3fff,%rbx
ffffffff8b29287f:	49 81 e7 00 c0 ff ff 	and    $0xffffffffffffc000,%r15
ffffffff8b292886:	41 81 e5 ff 3f 00 00 	and    $0x3fff,%r13d
ffffffff8b29288d:	41 81 c5 23 40 00 00 	add    $0x4023,%r13d
ffffffff8b292894:	41 81 e5 00 c0 00 00 	and    $0xc000,%r13d
ffffffff8b29289b:	49 f7 dd             	neg    %r13
ffffffff8b29289e:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8b2928a2:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2928a9:	1f 84 00 00 00 00 00 
ffffffff8b2928b0:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b2928b3:	e8 68 c2 00 00       	call   ffffffff8b29eb20 <frame_candidate_8d4544+0xa5dc>
ffffffff8b2928b8:	41 0f 01 3f          	invlpg (%r15)
ffffffff8b2928bc:	49 81 c7 00 40 00 00 	add    $0x4000,%r15
ffffffff8b2928c3:	49 81 c5 00 40 00 00 	add    $0x4000,%r13
ffffffff8b2928ca:	75 e4                	jne    ffffffff8b2928b0 <frame_candidate_8d2760+0x150>
ffffffff8b2928cc:	48 03 5d c8          	add    -0x38(%rbp),%rbx
ffffffff8b2928d0:	8b 75 d4             	mov    -0x2c(%rbp),%esi
ffffffff8b2928d3:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b2928d6:	48 81 e3 00 c0 ff ff 	and    $0xffffffffffffc000,%rbx
ffffffff8b2928dd:	e8 7e 2f 01 00       	call   ffffffff8b2a5860 <frame_candidate_8d4544+0x1131c>
ffffffff8b2928e2:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
ffffffff8b2928e6:	4c 8d 2c 08          	lea    (%rax,%rcx,1),%r13
ffffffff8b2928ea:	48 81 fb 00 40 00 00 	cmp    $0x4000,%rbx
ffffffff8b2928f1:	74 42                	je     ffffffff8b292935 <frame_candidate_8d2760+0x1d5>
ffffffff8b2928f3:	41 bf 00 40 00 00    	mov    $0x4000,%r15d
ffffffff8b2928f9:	49 81 c6 00 40 00 00 	add    $0x4000,%r14
ffffffff8b292900:	49 29 df             	sub    %rbx,%r15
ffffffff8b292903:	48 8d 9c 08 00 40 00 	lea    0x4000(%rax,%rcx,1),%rbx
ffffffff8b29290a:	00 
ffffffff8b29290b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8b292910:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292913:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b292916:	e8 35 c0 00 00       	call   ffffffff8b29e950 <frame_candidate_8d4544+0xa40c>
ffffffff8b29291b:	0f 01 3b             	invlpg (%rbx)
ffffffff8b29291e:	49 81 c6 00 40 00 00 	add    $0x4000,%r14
ffffffff8b292925:	48 81 c3 00 40 00 00 	add    $0x4000,%rbx
ffffffff8b29292c:	49 81 c7 00 40 00 00 	add    $0x4000,%r15
ffffffff8b292933:	75 db                	jne    ffffffff8b292910 <frame_candidate_8d2760+0x1b0>
ffffffff8b292935:	4c 03 6d b8          	add    -0x48(%rbp),%r13
ffffffff8b292939:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
ffffffff8b29293d:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b292940:	e8 4b 86 26 00       	call   ffffffff8b4faf90 <frame_candidate_8d4544+0x266a4c>
ffffffff8b292945:	84 c0                	test   %al,%al
ffffffff8b292947:	74 1a                	je     ffffffff8b292963 <frame_candidate_8d2760+0x203>
ffffffff8b292949:	83 3d 08 5f cb 02 00 	cmpl   $0x0,0x2cb5f08(%rip)        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292950:	74 11                	je     ffffffff8b292963 <frame_candidate_8d2760+0x203>
ffffffff8b292952:	48 8d 3d d5 47 a2 00 	lea    0xa247d5(%rip),%rdi        # ffffffff8bcb712e <frame_candidate_8d4544+0xa22bea>
ffffffff8b292959:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b29295c:	31 c0                	xor    %eax,%eax
ffffffff8b29295e:	e8 ad aa 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b292963:	4c 89 e8             	mov    %r13,%rax
ffffffff8b292966:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8b29296a:	5b                   	pop    %rbx
ffffffff8b29296b:	41 5c                	pop    %r12
ffffffff8b29296d:	41 5d                	pop    %r13
ffffffff8b29296f:	41 5e                	pop    %r14
ffffffff8b292971:	41 5f                	pop    %r15
ffffffff8b292973:	5d                   	pop    %rbp
ffffffff8b292974:	c3                   	ret
ffffffff8b292975:	90                   	nop
ffffffff8b292976:	90                   	nop
ffffffff8b292977:	90                   	nop
ffffffff8b292978:	90                   	nop
ffffffff8b292979:	90                   	nop
ffffffff8b29297a:	90                   	nop
ffffffff8b29297b:	90                   	nop
ffffffff8b29297c:	90                   	nop
ffffffff8b29297d:	90                   	nop
ffffffff8b29297e:	90                   	nop
ffffffff8b29297f:	90                   	nop

ffffffff8b292980 <frame_candidate_8d2980>:
ffffffff8b292980:	55                   	push   %rbp
ffffffff8b292981:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292984:	41 56                	push   %r14
ffffffff8b292986:	53                   	push   %rbx
ffffffff8b292987:	8b 47 04             	mov    0x4(%rdi),%eax
ffffffff8b29298a:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b29298d:	89 d9                	mov    %ebx,%ecx
ffffffff8b29298f:	81 e1 ff 3f 00 00    	and    $0x3fff,%ecx
ffffffff8b292995:	4c 8d b4 01 ff 3f 00 	lea    0x3fff(%rcx,%rax,1),%r14
ffffffff8b29299c:	00 
ffffffff8b29299d:	48 b8 00 c0 ff ff 01 	movabs $0x1ffffc000,%rax
ffffffff8b2929a4:	00 00 00 
ffffffff8b2929a7:	49 85 c6             	test   %rax,%r14
ffffffff8b2929aa:	74 2f                	je     ffffffff8b2929db <frame_candidate_8d2980+0x5b>
ffffffff8b2929ac:	49 81 e6 00 c0 ff ff 	and    $0xffffffffffffc000,%r14
ffffffff8b2929b3:	48 81 e3 00 c0 ff ff 	and    $0xffffffffffffc000,%rbx
ffffffff8b2929ba:	49 f7 de             	neg    %r14
ffffffff8b2929bd:	0f 1f 00             	nopl   (%rax)
ffffffff8b2929c0:	48 89 df             	mov    %rbx,%rdi
ffffffff8b2929c3:	e8 58 c1 00 00       	call   ffffffff8b29eb20 <frame_candidate_8d4544+0xa5dc>
ffffffff8b2929c8:	0f 01 3b             	invlpg (%rbx)
ffffffff8b2929cb:	48 81 c3 00 40 00 00 	add    $0x4000,%rbx
ffffffff8b2929d2:	49 81 c6 00 40 00 00 	add    $0x4000,%r14
ffffffff8b2929d9:	75 e5                	jne    ffffffff8b2929c0 <frame_candidate_8d2980+0x40>
ffffffff8b2929db:	5b                   	pop    %rbx
ffffffff8b2929dc:	41 5e                	pop    %r14
ffffffff8b2929de:	5d                   	pop    %rbp
ffffffff8b2929df:	c3                   	ret

ffffffff8b2929e0 <frame_candidate_8d29e0>:
ffffffff8b2929e0:	55                   	push   %rbp
ffffffff8b2929e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2929e4:	41 57                	push   %r15
ffffffff8b2929e6:	41 56                	push   %r14
ffffffff8b2929e8:	41 55                	push   %r13
ffffffff8b2929ea:	41 54                	push   %r12
ffffffff8b2929ec:	53                   	push   %rbx
ffffffff8b2929ed:	50                   	push   %rax
ffffffff8b2929ee:	49 89 fe             	mov    %rdi,%r14
ffffffff8b2929f1:	48 8d 3d 96 5b ac 00 	lea    0xac5b96(%rip),%rdi        # ffffffff8bd5858e <frame_candidate_8d4544+0xac404a>
ffffffff8b2929f8:	31 f6                	xor    %esi,%esi
ffffffff8b2929fa:	31 db                	xor    %ebx,%ebx
ffffffff8b2929fc:	e8 6f f4 e0 ff       	call   ffffffff8b0a1e70 <handler_617_body-0x1f0700>
ffffffff8b292a01:	85 c0                	test   %eax,%eax
ffffffff8b292a03:	0f 85 c0 02 00 00    	jne    ffffffff8b292cc9 <frame_candidate_8d29e0+0x2e9>
ffffffff8b292a09:	e8 b2 d4 eb ff       	call   ffffffff8b14fec0 <handler_617_body-0x1426b0>
ffffffff8b292a0e:	48 85 c0             	test   %rax,%rax
ffffffff8b292a11:	0f 84 b0 02 00 00    	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292a17:	be 24 00 00 00       	mov    $0x24,%esi
ffffffff8b292a1c:	48 89 c7             	mov    %rax,%rdi
ffffffff8b292a1f:	e8 ec 8f 01 00       	call   ffffffff8b2aba10 <frame_candidate_8d4544+0x174cc>
ffffffff8b292a24:	48 85 c0             	test   %rax,%rax
ffffffff8b292a27:	0f 84 ae 00 00 00    	je     ffffffff8b292adb <frame_candidate_8d29e0+0xfb>
ffffffff8b292a2d:	80 78 0f 02          	cmpb   $0x2,0xf(%rax)
ffffffff8b292a31:	49 89 c7             	mov    %rax,%r15
ffffffff8b292a34:	72 35                	jb     ffffffff8b292a6b <frame_candidate_8d29e0+0x8b>
ffffffff8b292a36:	49 83 7f 18 00       	cmpq   $0x0,0x18(%r15)
ffffffff8b292a3b:	74 2e                	je     ffffffff8b292a6b <frame_candidate_8d29e0+0x8b>
ffffffff8b292a3d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b292a40:	be 24 00 00 00       	mov    $0x24,%esi
ffffffff8b292a45:	e8 46 85 26 00       	call   ffffffff8b4faf90 <frame_candidate_8d4544+0x266a4c>
ffffffff8b292a4a:	84 c0                	test   %al,%al
ffffffff8b292a4c:	0f 84 30 01 00 00    	je     ffffffff8b292b82 <frame_candidate_8d29e0+0x1a2>
ffffffff8b292a52:	83 3d ff 5d cb 02 00 	cmpl   $0x0,0x2cb5dff(%rip)        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292a59:	0f 84 68 02 00 00    	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292a5f:	48 8d 3d 00 81 a9 00 	lea    0xa98100(%rip),%rdi        # ffffffff8bd2ab66 <frame_candidate_8d4544+0xa96622>
ffffffff8b292a66:	e9 9a 00 00 00       	jmp    ffffffff8b292b05 <frame_candidate_8d29e0+0x125>
ffffffff8b292a6b:	41 8b 7f 10          	mov    0x10(%r15),%edi
ffffffff8b292a6f:	48 8d 15 d1 09 9f 00 	lea    0x9f09d1(%rip),%rdx        # ffffffff8bc83447 <frame_candidate_8d4544+0x9eef03>
ffffffff8b292a76:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8b292a7b:	e8 e0 fc ff ff       	call   ffffffff8b292760 <frame_candidate_8d2760>
ffffffff8b292a80:	48 85 c0             	test   %rax,%rax
ffffffff8b292a83:	74 6c                	je     ffffffff8b292af1 <frame_candidate_8d29e0+0x111>
ffffffff8b292a85:	49 89 c4             	mov    %rax,%r12
ffffffff8b292a88:	8b 40 04             	mov    0x4(%rax),%eax
ffffffff8b292a8b:	49 bd dc ff ff ff 03 	movabs $0x3ffffffdc,%r13
ffffffff8b292a92:	00 00 00 
ffffffff8b292a95:	49 01 c5             	add    %rax,%r13
ffffffff8b292a98:	49 c1 ed 02          	shr    $0x2,%r13
ffffffff8b292a9c:	45 85 ed             	test   %r13d,%r13d
ffffffff8b292a9f:	7e 72                	jle    ffffffff8b292b13 <frame_candidate_8d29e0+0x133>
ffffffff8b292aa1:	41 81 e5 ff ff ff 7f 	and    $0x7fffffff,%r13d
ffffffff8b292aa8:	4c 89 7d d0          	mov    %r15,-0x30(%rbp)
ffffffff8b292aac:	31 db                	xor    %ebx,%ebx
ffffffff8b292aae:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b292ab1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b292ab8:	0f 1f 84 00 00 00 00 
ffffffff8b292abf:	00 
ffffffff8b292ac0:	43 8b 7c bc 24       	mov    0x24(%r12,%r15,4),%edi
ffffffff8b292ac5:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b292ac8:	e8 13 02 00 00       	call   ffffffff8b292ce0 <frame_candidate_8d2ce0>
ffffffff8b292acd:	85 c0                	test   %eax,%eax
ffffffff8b292acf:	75 46                	jne    ffffffff8b292b17 <frame_candidate_8d29e0+0x137>
ffffffff8b292ad1:	49 ff c7             	inc    %r15
ffffffff8b292ad4:	4d 39 fd             	cmp    %r15,%r13
ffffffff8b292ad7:	75 e7                	jne    ffffffff8b292ac0 <frame_candidate_8d29e0+0xe0>
ffffffff8b292ad9:	eb 41                	jmp    ffffffff8b292b1c <frame_candidate_8d29e0+0x13c>
ffffffff8b292adb:	83 3d 76 5d cb 02 00 	cmpl   $0x0,0x2cb5d76(%rip)        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292ae2:	0f 84 df 01 00 00    	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292ae8:	48 8d 3d 9a f0 a2 00 	lea    0xa2f09a(%rip),%rdi        # ffffffff8bcc1b89 <frame_candidate_8d4544+0xa2d645>
ffffffff8b292aef:	eb 14                	jmp    ffffffff8b292b05 <frame_candidate_8d29e0+0x125>
ffffffff8b292af1:	83 3d 60 5d cb 02 00 	cmpl   $0x0,0x2cb5d60(%rip)        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292af8:	0f 84 c9 01 00 00    	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292afe:	48 8d 3d 0f 46 a2 00 	lea    0xa2460f(%rip),%rdi        # ffffffff8bcb7114 <frame_candidate_8d4544+0xa22bd0>
ffffffff8b292b05:	31 c0                	xor    %eax,%eax
ffffffff8b292b07:	31 db                	xor    %ebx,%ebx
ffffffff8b292b09:	e8 02 a9 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b292b0e:	e9 b6 01 00 00       	jmp    ffffffff8b292cc9 <frame_candidate_8d29e0+0x2e9>
ffffffff8b292b13:	31 db                	xor    %ebx,%ebx
ffffffff8b292b15:	eb 09                	jmp    ffffffff8b292b20 <frame_candidate_8d29e0+0x140>
ffffffff8b292b17:	43 8b 5c bc 24       	mov    0x24(%r12,%r15,4),%ebx
ffffffff8b292b1c:	4c 8b 7d d0          	mov    -0x30(%rbp),%r15
ffffffff8b292b20:	41 8b 44 24 04       	mov    0x4(%r12),%eax
ffffffff8b292b25:	44 89 e1             	mov    %r12d,%ecx
ffffffff8b292b28:	81 e1 ff 3f 00 00    	and    $0x3fff,%ecx
ffffffff8b292b2e:	4c 8d ac 01 ff 3f 00 	lea    0x3fff(%rcx,%rax,1),%r13
ffffffff8b292b35:	00 
ffffffff8b292b36:	48 b8 00 c0 ff ff 01 	movabs $0x1ffffc000,%rax
ffffffff8b292b3d:	00 00 00 
ffffffff8b292b40:	49 85 c5             	test   %rax,%r13
ffffffff8b292b43:	0f 84 c8 00 00 00    	je     ffffffff8b292c11 <frame_candidate_8d29e0+0x231>
ffffffff8b292b49:	49 81 e5 00 c0 ff ff 	and    $0xffffffffffffc000,%r13
ffffffff8b292b50:	49 81 e4 00 c0 ff ff 	and    $0xffffffffffffc000,%r12
ffffffff8b292b57:	49 f7 dd             	neg    %r13
ffffffff8b292b5a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8b292b60:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b292b63:	e8 b8 bf 00 00       	call   ffffffff8b29eb20 <frame_candidate_8d4544+0xa5dc>
ffffffff8b292b68:	41 0f 01 3c 24       	invlpg (%r12)
ffffffff8b292b6d:	49 81 c4 00 40 00 00 	add    $0x4000,%r12
ffffffff8b292b74:	49 81 c5 00 40 00 00 	add    $0x4000,%r13
ffffffff8b292b7b:	75 e3                	jne    ffffffff8b292b60 <frame_candidate_8d29e0+0x180>
ffffffff8b292b7d:	e9 8f 00 00 00       	jmp    ffffffff8b292c11 <frame_candidate_8d29e0+0x231>
ffffffff8b292b82:	49 8b 7f 18          	mov    0x18(%r15),%rdi
ffffffff8b292b86:	48 8d 15 26 b3 9d 00 	lea    0x9db326(%rip),%rdx        # ffffffff8bc6deb3 <frame_candidate_8d4544+0x9d996f>
ffffffff8b292b8d:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8b292b92:	e8 c9 fb ff ff       	call   ffffffff8b292760 <frame_candidate_8d2760>
ffffffff8b292b97:	48 85 c0             	test   %rax,%rax
ffffffff8b292b9a:	74 47                	je     ffffffff8b292be3 <frame_candidate_8d29e0+0x203>
ffffffff8b292b9c:	49 89 c4             	mov    %rax,%r12
ffffffff8b292b9f:	8b 40 04             	mov    0x4(%rax),%eax
ffffffff8b292ba2:	49 bd dc ff ff ff 07 	movabs $0x7ffffffdc,%r13
ffffffff8b292ba9:	00 00 00 
ffffffff8b292bac:	49 01 c5             	add    %rax,%r13
ffffffff8b292baf:	49 c1 ed 03          	shr    $0x3,%r13
ffffffff8b292bb3:	45 85 ed             	test   %r13d,%r13d
ffffffff8b292bb6:	7e 44                	jle    ffffffff8b292bfc <frame_candidate_8d29e0+0x21c>
ffffffff8b292bb8:	41 81 e5 ff ff ff 7f 	and    $0x7fffffff,%r13d
ffffffff8b292bbf:	4c 89 7d d0          	mov    %r15,-0x30(%rbp)
ffffffff8b292bc3:	31 db                	xor    %ebx,%ebx
ffffffff8b292bc5:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b292bc8:	4b 8b 7c fc 24       	mov    0x24(%r12,%r15,8),%rdi
ffffffff8b292bcd:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b292bd0:	e8 0b 01 00 00       	call   ffffffff8b292ce0 <frame_candidate_8d2ce0>
ffffffff8b292bd5:	85 c0                	test   %eax,%eax
ffffffff8b292bd7:	75 27                	jne    ffffffff8b292c00 <frame_candidate_8d29e0+0x220>
ffffffff8b292bd9:	49 ff c7             	inc    %r15
ffffffff8b292bdc:	4d 39 fd             	cmp    %r15,%r13
ffffffff8b292bdf:	75 e7                	jne    ffffffff8b292bc8 <frame_candidate_8d29e0+0x1e8>
ffffffff8b292be1:	eb 22                	jmp    ffffffff8b292c05 <frame_candidate_8d29e0+0x225>
ffffffff8b292be3:	83 3d 6e 5c cb 02 00 	cmpl   $0x0,0x2cb5c6e(%rip)        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292bea:	0f 84 d7 00 00 00    	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292bf0:	48 8d 3d c8 5f a0 00 	lea    0xa05fc8(%rip),%rdi        # ffffffff8bc98bbf <frame_candidate_8d4544+0xa0467b>
ffffffff8b292bf7:	e9 09 ff ff ff       	jmp    ffffffff8b292b05 <frame_candidate_8d29e0+0x125>
ffffffff8b292bfc:	31 db                	xor    %ebx,%ebx
ffffffff8b292bfe:	eb 09                	jmp    ffffffff8b292c09 <frame_candidate_8d29e0+0x229>
ffffffff8b292c00:	4b 8b 5c fc 24       	mov    0x24(%r12,%r15,8),%rbx
ffffffff8b292c05:	4c 8b 7d d0          	mov    -0x30(%rbp),%r15
ffffffff8b292c09:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b292c0c:	e8 6f fd ff ff       	call   ffffffff8b292980 <frame_candidate_8d2980>
ffffffff8b292c11:	be 24 00 00 00       	mov    $0x24,%esi
ffffffff8b292c16:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b292c19:	e8 02 8e 01 00       	call   ffffffff8b2aba20 <frame_candidate_8d4544+0x174dc>
ffffffff8b292c1e:	8b 05 34 5c cb 02    	mov    0x2cb5c34(%rip),%eax        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292c24:	48 85 db             	test   %rbx,%rbx
ffffffff8b292c27:	0f 84 81 00 00 00    	je     ffffffff8b292cae <frame_candidate_8d29e0+0x2ce>
ffffffff8b292c2d:	85 c0                	test   %eax,%eax
ffffffff8b292c2f:	74 14                	je     ffffffff8b292c45 <frame_candidate_8d29e0+0x265>
ffffffff8b292c31:	48 8d 3d 05 a7 a1 00 	lea    0xa1a705(%rip),%rdi        # ffffffff8bcad33d <frame_candidate_8d4544+0xa18df9>
ffffffff8b292c38:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b292c3b:	48 89 da             	mov    %rbx,%rdx
ffffffff8b292c3e:	31 c0                	xor    %eax,%eax
ffffffff8b292c40:	e8 cb a7 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b292c45:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292c48:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b292c4b:	31 f6                	xor    %esi,%esi
ffffffff8b292c4d:	e8 0e fb ff ff       	call   ffffffff8b292760 <frame_candidate_8d2760>
ffffffff8b292c52:	48 85 c0             	test   %rax,%rax
ffffffff8b292c55:	74 70                	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292c57:	49 89 c6             	mov    %rax,%r14
ffffffff8b292c5a:	8b 40 04             	mov    0x4(%rax),%eax
ffffffff8b292c5d:	44 89 f1             	mov    %r14d,%ecx
ffffffff8b292c60:	81 e1 ff 3f 00 00    	and    $0x3fff,%ecx
ffffffff8b292c66:	4c 8d bc 01 ff 3f 00 	lea    0x3fff(%rcx,%rax,1),%r15
ffffffff8b292c6d:	00 
ffffffff8b292c6e:	48 b8 00 c0 ff ff 01 	movabs $0x1ffffc000,%rax
ffffffff8b292c75:	00 00 00 
ffffffff8b292c78:	49 85 c7             	test   %rax,%r15
ffffffff8b292c7b:	74 4c                	je     ffffffff8b292cc9 <frame_candidate_8d29e0+0x2e9>
ffffffff8b292c7d:	49 81 e7 00 c0 ff ff 	and    $0xffffffffffffc000,%r15
ffffffff8b292c84:	49 81 e6 00 c0 ff ff 	and    $0xffffffffffffc000,%r14
ffffffff8b292c8b:	49 f7 df             	neg    %r15
ffffffff8b292c8e:	66 90                	xchg   %ax,%ax
ffffffff8b292c90:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b292c93:	e8 88 be 00 00       	call   ffffffff8b29eb20 <frame_candidate_8d4544+0xa5dc>
ffffffff8b292c98:	41 0f 01 3e          	invlpg (%r14)
ffffffff8b292c9c:	49 81 c6 00 40 00 00 	add    $0x4000,%r14
ffffffff8b292ca3:	49 81 c7 00 40 00 00 	add    $0x4000,%r15
ffffffff8b292caa:	75 e4                	jne    ffffffff8b292c90 <frame_candidate_8d29e0+0x2b0>
ffffffff8b292cac:	eb 1b                	jmp    ffffffff8b292cc9 <frame_candidate_8d29e0+0x2e9>
ffffffff8b292cae:	85 c0                	test   %eax,%eax
ffffffff8b292cb0:	74 15                	je     ffffffff8b292cc7 <frame_candidate_8d29e0+0x2e7>
ffffffff8b292cb2:	48 8d 3d 20 5f a0 00 	lea    0xa05f20(%rip),%rdi        # ffffffff8bc98bd9 <frame_candidate_8d4544+0xa04695>
ffffffff8b292cb9:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b292cbc:	31 c0                	xor    %eax,%eax
ffffffff8b292cbe:	31 db                	xor    %ebx,%ebx
ffffffff8b292cc0:	e8 4b a7 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b292cc5:	eb 02                	jmp    ffffffff8b292cc9 <frame_candidate_8d29e0+0x2e9>
ffffffff8b292cc7:	31 db                	xor    %ebx,%ebx
ffffffff8b292cc9:	48 89 d8             	mov    %rbx,%rax
ffffffff8b292ccc:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b292cd0:	5b                   	pop    %rbx
ffffffff8b292cd1:	41 5c                	pop    %r12
ffffffff8b292cd3:	41 5d                	pop    %r13
ffffffff8b292cd5:	41 5e                	pop    %r14
ffffffff8b292cd7:	41 5f                	pop    %r15
ffffffff8b292cd9:	5d                   	pop    %rbp
ffffffff8b292cda:	c3                   	ret
ffffffff8b292cdb:	90                   	nop
ffffffff8b292cdc:	90                   	nop
ffffffff8b292cdd:	90                   	nop
ffffffff8b292cde:	90                   	nop
ffffffff8b292cdf:	90                   	nop

ffffffff8b292ce0 <frame_candidate_8d2ce0>:
ffffffff8b292ce0:	55                   	push   %rbp
ffffffff8b292ce1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292ce4:	41 57                	push   %r15
ffffffff8b292ce6:	41 56                	push   %r14
ffffffff8b292ce8:	41 55                	push   %r13
ffffffff8b292cea:	41 54                	push   %r12
ffffffff8b292cec:	53                   	push   %rbx
ffffffff8b292ced:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b292cf1:	49 89 fc             	mov    %rdi,%r12
ffffffff8b292cf4:	48 89 7d d0          	mov    %rdi,-0x30(%rbp)
ffffffff8b292cf8:	48 89 75 c8          	mov    %rsi,-0x38(%rbp)
ffffffff8b292cfc:	31 f6                	xor    %esi,%esi
ffffffff8b292cfe:	44 89 e3             	mov    %r12d,%ebx
ffffffff8b292d01:	49 81 e4 00 c0 ff ff 	and    $0xffffffffffffc000,%r12
ffffffff8b292d08:	81 e3 ff 3f 00 00    	and    $0x3fff,%ebx
ffffffff8b292d0e:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b292d11:	44 8d b3 23 40 00 00 	lea    0x4023(%rbx),%r14d
ffffffff8b292d18:	41 81 e6 00 c0 00 00 	and    $0xc000,%r14d
ffffffff8b292d1f:	e8 3c 2b 01 00       	call   ffffffff8b2a5860 <frame_candidate_8d4544+0x1131c>
ffffffff8b292d24:	49 89 c5             	mov    %rax,%r13
ffffffff8b292d27:	41 81 fe 00 40 00 00 	cmp    $0x4000,%r14d
ffffffff8b292d2e:	74 46                	je     ffffffff8b292d76 <frame_candidate_8d2ce0+0x96>
ffffffff8b292d30:	41 bf 00 40 00 00    	mov    $0x4000,%r15d
ffffffff8b292d36:	49 81 c4 00 40 00 00 	add    $0x4000,%r12
ffffffff8b292d3d:	4d 29 f7             	sub    %r14,%r15
ffffffff8b292d40:	4d 8d b5 00 40 00 00 	lea    0x4000(%r13),%r14
ffffffff8b292d47:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b292d4e:	00 00 
ffffffff8b292d50:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b292d53:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b292d56:	e8 f5 bb 00 00       	call   ffffffff8b29e950 <frame_candidate_8d4544+0xa40c>
ffffffff8b292d5b:	41 0f 01 3e          	invlpg (%r14)
ffffffff8b292d5f:	49 81 c4 00 40 00 00 	add    $0x4000,%r12
ffffffff8b292d66:	49 81 c6 00 40 00 00 	add    $0x4000,%r14
ffffffff8b292d6d:	49 81 c7 00 40 00 00 	add    $0x4000,%r15
ffffffff8b292d74:	75 da                	jne    ffffffff8b292d50 <frame_candidate_8d2ce0+0x70>
ffffffff8b292d76:	8b 05 dc 5a cb 02    	mov    0x2cb5adc(%rip),%eax        # ffffffff8df48858 <frame_candidate_8d4544+0x2cb4314>
ffffffff8b292d7c:	4c 01 eb             	add    %r13,%rbx
ffffffff8b292d7f:	74 74                	je     ffffffff8b292df5 <frame_candidate_8d2ce0+0x115>
ffffffff8b292d81:	85 c0                	test   %eax,%eax
ffffffff8b292d83:	74 15                	je     ffffffff8b292d9a <frame_candidate_8d2ce0+0xba>
ffffffff8b292d85:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
ffffffff8b292d89:	48 8d 3d 6b 3b a4 00 	lea    0xa43b6b(%rip),%rdi        # ffffffff8bcd68fb <frame_candidate_8d4544+0xa423b7>
ffffffff8b292d90:	48 89 de             	mov    %rbx,%rsi
ffffffff8b292d93:	31 c0                	xor    %eax,%eax
ffffffff8b292d95:	e8 76 a6 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b292d9a:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
ffffffff8b292d9e:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8b292da3:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292da6:	e8 85 ec ff ff       	call   ffffffff8b291a30 <handler_617_body-0xb40>
ffffffff8b292dab:	41 89 df             	mov    %ebx,%r15d
ffffffff8b292dae:	41 89 c6             	mov    %eax,%r14d
ffffffff8b292db1:	48 81 e3 00 c0 ff ff 	and    $0xffffffffffffc000,%rbx
ffffffff8b292db8:	41 81 e7 ff 3f 00 00 	and    $0x3fff,%r15d
ffffffff8b292dbf:	41 81 c7 23 40 00 00 	add    $0x4023,%r15d
ffffffff8b292dc6:	41 81 e7 00 c0 00 00 	and    $0xc000,%r15d
ffffffff8b292dcd:	49 f7 df             	neg    %r15
ffffffff8b292dd0:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292dd3:	e8 48 bd 00 00       	call   ffffffff8b29eb20 <frame_candidate_8d4544+0xa5dc>
ffffffff8b292dd8:	0f 01 3b             	invlpg (%rbx)
ffffffff8b292ddb:	48 81 c3 00 40 00 00 	add    $0x4000,%rbx
ffffffff8b292de2:	49 81 c7 00 40 00 00 	add    $0x4000,%r15
ffffffff8b292de9:	75 e5                	jne    ffffffff8b292dd0 <frame_candidate_8d2ce0+0xf0>
ffffffff8b292deb:	31 c0                	xor    %eax,%eax
ffffffff8b292ded:	45 85 f6             	test   %r14d,%r14d
ffffffff8b292df0:	0f 94 c0             	sete   %al
ffffffff8b292df3:	eb 18                	jmp    ffffffff8b292e0d <frame_candidate_8d2ce0+0x12d>
ffffffff8b292df5:	85 c0                	test   %eax,%eax
ffffffff8b292df7:	74 12                	je     ffffffff8b292e0b <frame_candidate_8d2ce0+0x12b>
ffffffff8b292df9:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
ffffffff8b292dfd:	48 8d 3d 46 af 9f 00 	lea    0x9faf46(%rip),%rdi        # ffffffff8bc8dd4a <frame_candidate_8d4544+0x9f9806>
ffffffff8b292e04:	31 c0                	xor    %eax,%eax
ffffffff8b292e06:	e8 05 a6 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b292e0b:	31 c0                	xor    %eax,%eax
ffffffff8b292e0d:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b292e11:	5b                   	pop    %rbx
ffffffff8b292e12:	41 5c                	pop    %r12
ffffffff8b292e14:	41 5d                	pop    %r13
ffffffff8b292e16:	41 5e                	pop    %r14
ffffffff8b292e18:	41 5f                	pop    %r15
ffffffff8b292e1a:	5d                   	pop    %rbp
ffffffff8b292e1b:	c3                   	ret
ffffffff8b292e1c:	90                   	nop
ffffffff8b292e1d:	90                   	nop
ffffffff8b292e1e:	90                   	nop
ffffffff8b292e1f:	90                   	nop

ffffffff8b292e20 <frame_candidate_8d2e20>:
ffffffff8b292e20:	55                   	push   %rbp
ffffffff8b292e21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292e24:	e8 c7 fd 31 00       	call   ffffffff8b5b2bf0 <frame_candidate_8d4544+0x31e6ac>
ffffffff8b292e29:	85 c0                	test   %eax,%eax
ffffffff8b292e2b:	b9 ec ff ff ff       	mov    $0xffffffec,%ecx
ffffffff8b292e30:	0f 44 c1             	cmove  %ecx,%eax
ffffffff8b292e33:	5d                   	pop    %rbp
ffffffff8b292e34:	c3                   	ret
ffffffff8b292e35:	90                   	nop
ffffffff8b292e36:	90                   	nop
ffffffff8b292e37:	90                   	nop
ffffffff8b292e38:	90                   	nop
ffffffff8b292e39:	90                   	nop
ffffffff8b292e3a:	90                   	nop
ffffffff8b292e3b:	90                   	nop
ffffffff8b292e3c:	90                   	nop
ffffffff8b292e3d:	90                   	nop
ffffffff8b292e3e:	90                   	nop
ffffffff8b292e3f:	90                   	nop

ffffffff8b292e40 <frame_candidate_8d2e40>:
ffffffff8b292e40:	55                   	push   %rbp
ffffffff8b292e41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292e44:	41 56                	push   %r14
ffffffff8b292e46:	53                   	push   %rbx
ffffffff8b292e47:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b292e4a:	e8 b1 6c ec ff       	call   ffffffff8b159b00 <handler_617_body-0x138a70>
ffffffff8b292e4f:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292e52:	e8 a9 a7 98 ff       	call   ffffffff8ac1d600 <handler_617_body-0x674f70>
ffffffff8b292e57:	48 8d 35 2a 6c fb 01 	lea    0x1fb6c2a(%rip),%rsi        # ffffffff8d249a88 <frame_candidate_8d4544+0x1fb5544>
ffffffff8b292e5e:	48 8b 0b             	mov    (%rbx),%rcx
ffffffff8b292e61:	0f b6 16             	movzbl (%rsi),%edx
ffffffff8b292e64:	48 8b 04 d1          	mov    (%rcx,%rdx,8),%rax
ffffffff8b292e68:	48 39 30             	cmp    %rsi,(%rax)
ffffffff8b292e6b:	74 17                	je     ffffffff8b292e84 <frame_candidate_8d2e40+0x44>
ffffffff8b292e6d:	48 8d 34 d1          	lea    (%rcx,%rdx,8),%rsi
ffffffff8b292e71:	48 8b b9 00 08 00 00 	mov    0x800(%rcx),%rdi
ffffffff8b292e78:	48 8d 15 09 6c fb 01 	lea    0x1fb6c09(%rip),%rdx        # ffffffff8d249a88 <frame_candidate_8d4544+0x1fb5544>
ffffffff8b292e7f:	e8 6c 31 a5 ff       	call   ffffffff8ace5ff0 <handler_617_body-0x5ac580>
ffffffff8b292e84:	4c 8b 70 08          	mov    0x8(%rax),%r14
ffffffff8b292e88:	48 8d 05 09 95 99 ff 	lea    -0x666af7(%rip),%rax        # ffffffff8ac2c398 <handler_617_body-0x6661d8>
ffffffff8b292e8f:	4c 29 f0             	sub    %r14,%rax
ffffffff8b292e92:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b292e96:	48 83 f8 05          	cmp    $0x5,%rax
ffffffff8b292e9a:	77 41                	ja     ffffffff8b292edd <frame_candidate_8d2e40+0x9d>
ffffffff8b292e9c:	48 8d 15 eb 56 ac 00 	lea    0xac56eb(%rip),%rdx        # ffffffff8bd5858e <frame_candidate_8d4544+0xac404a>
ffffffff8b292ea3:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292ea6:	be 0a 00 00 00       	mov    $0xa,%esi
ffffffff8b292eab:	31 c9                	xor    %ecx,%ecx
ffffffff8b292ead:	41 ff d6             	call   *%r14
ffffffff8b292eb0:	48 85 c0             	test   %rax,%rax
ffffffff8b292eb3:	74 39                	je     ffffffff8b292eee <frame_candidate_8d2e40+0xae>
ffffffff8b292eb5:	48 89 df             	mov    %rbx,%rdi
ffffffff8b292eb8:	49 89 c6             	mov    %rax,%r14
ffffffff8b292ebb:	e8 18 a7 98 ff       	call   ffffffff8ac1d5d8 <handler_617_body-0x674f98>
ffffffff8b292ec0:	85 c0                	test   %eax,%eax
ffffffff8b292ec2:	75 14                	jne    ffffffff8b292ed8 <frame_candidate_8d2e40+0x98>
ffffffff8b292ec4:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b292ec7:	89 c3                	mov    %eax,%ebx
ffffffff8b292ec9:	e8 42 fc 9d ff       	call   ffffffff8ac72b10 <handler_617_body-0x61fa60>
ffffffff8b292ece:	48 89 c7             	mov    %rax,%rdi
ffffffff8b292ed1:	e8 1a e6 ab ff       	call   ffffffff8ad514f0 <handler_617_body-0x541080>
ffffffff8b292ed6:	89 d8                	mov    %ebx,%eax
ffffffff8b292ed8:	5b                   	pop    %rbx
ffffffff8b292ed9:	41 5e                	pop    %r14
ffffffff8b292edb:	5d                   	pop    %rbp
ffffffff8b292edc:	c3                   	ret
ffffffff8b292edd:	48 8d 3d ec 89 c7 01 	lea    0x1c789ec(%rip),%rdi        # ffffffff8cf0b8d0 <frame_candidate_8d4544+0x1c7738c>
ffffffff8b292ee4:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b292ee7:	e8 d4 c9 b7 ff       	call   ffffffff8ae0f8c0 <handler_617_body-0x482cb0>
ffffffff8b292eec:	eb ae                	jmp    ffffffff8b292e9c <frame_candidate_8d2e40+0x5c>
ffffffff8b292eee:	e8 5d ea f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b292ef3:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b292eee <frame_candidate_8d2e40+0xae>
ffffffff8b292efa:	e8 11 e9 f1 ff       	call   ffffffff8b1b1810 <handler_617_body-0xe0d60>
ffffffff8b292eff:	48 8d 35 78 e6 a4 00 	lea    0xa4e678(%rip),%rsi        # ffffffff8bce157e <frame_candidate_8d4544+0xa4d03a>
ffffffff8b292f06:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b292f0b:	31 c0                	xor    %eax,%eax
ffffffff8b292f0d:	e8 fe 7a 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b292f12:	0f 0b                	ud2
ffffffff8b292f14:	90                   	nop
ffffffff8b292f15:	90                   	nop
ffffffff8b292f16:	90                   	nop
ffffffff8b292f17:	90                   	nop
ffffffff8b292f18:	90                   	nop
ffffffff8b292f19:	90                   	nop
ffffffff8b292f1a:	90                   	nop
ffffffff8b292f1b:	90                   	nop
ffffffff8b292f1c:	90                   	nop
ffffffff8b292f1d:	90                   	nop
ffffffff8b292f1e:	90                   	nop
ffffffff8b292f1f:	90                   	nop

ffffffff8b292f20 <frame_candidate_8d2f20>:
ffffffff8b292f20:	55                   	push   %rbp
ffffffff8b292f21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f24:	48 8d 05 05 71 5b 00 	lea    0x5b7105(%rip),%rax        # ffffffff8b84a030 <frame_candidate_8d4544+0x5b5aec>
ffffffff8b292f2b:	5d                   	pop    %rbp
ffffffff8b292f2c:	c3                   	ret
ffffffff8b292f2d:	90                   	nop
ffffffff8b292f2e:	90                   	nop
ffffffff8b292f2f:	90                   	nop

ffffffff8b292f30 <frame_candidate_8d2f30>:
ffffffff8b292f30:	55                   	push   %rbp
ffffffff8b292f31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f34:	48 8d 05 6d 71 5b 00 	lea    0x5b716d(%rip),%rax        # ffffffff8b84a0a8 <frame_candidate_8d4544+0x5b5b64>
ffffffff8b292f3b:	5d                   	pop    %rbp
ffffffff8b292f3c:	c3                   	ret
ffffffff8b292f3d:	90                   	nop
ffffffff8b292f3e:	90                   	nop
ffffffff8b292f3f:	90                   	nop

ffffffff8b292f40 <frame_candidate_8d2f40>:
ffffffff8b292f40:	55                   	push   %rbp
ffffffff8b292f41:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f44:	48 8b 7f 18          	mov    0x18(%rdi),%rdi
ffffffff8b292f48:	5d                   	pop    %rbp
ffffffff8b292f49:	e9 c2 32 33 00       	jmp    ffffffff8b5c6210 <frame_candidate_8d4544+0x331ccc>
ffffffff8b292f4e:	90                   	nop
ffffffff8b292f4f:	90                   	nop

ffffffff8b292f50 <frame_candidate_8d2f50>:
ffffffff8b292f50:	55                   	push   %rbp
ffffffff8b292f51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f54:	48 8b 7f 18          	mov    0x18(%rdi),%rdi
ffffffff8b292f58:	5d                   	pop    %rbp
ffffffff8b292f59:	e9 12 1e 33 00       	jmp    ffffffff8b5c4d70 <frame_candidate_8d4544+0x33082c>
ffffffff8b292f5e:	90                   	nop
ffffffff8b292f5f:	90                   	nop

ffffffff8b292f60 <frame_candidate_8d2f60>:
ffffffff8b292f60:	55                   	push   %rbp
ffffffff8b292f61:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f64:	48 89 f0             	mov    %rsi,%rax
ffffffff8b292f67:	48 8b 77 18          	mov    0x18(%rdi),%rsi
ffffffff8b292f6b:	48 89 c7             	mov    %rax,%rdi
ffffffff8b292f6e:	5d                   	pop    %rbp
ffffffff8b292f6f:	e9 cc 31 33 00       	jmp    ffffffff8b5c6140 <frame_candidate_8d4544+0x331bfc>
ffffffff8b292f74:	90                   	nop
ffffffff8b292f75:	90                   	nop
ffffffff8b292f76:	90                   	nop
ffffffff8b292f77:	90                   	nop
ffffffff8b292f78:	90                   	nop
ffffffff8b292f79:	90                   	nop
ffffffff8b292f7a:	90                   	nop
ffffffff8b292f7b:	90                   	nop
ffffffff8b292f7c:	90                   	nop
ffffffff8b292f7d:	90                   	nop
ffffffff8b292f7e:	90                   	nop
ffffffff8b292f7f:	90                   	nop

ffffffff8b292f80 <frame_candidate_8d2f80>:
ffffffff8b292f80:	55                   	push   %rbp
ffffffff8b292f81:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f84:	48 8b 7f 18          	mov    0x18(%rdi),%rdi
ffffffff8b292f88:	5d                   	pop    %rbp
ffffffff8b292f89:	e9 c2 d5 b9 ff       	jmp    ffffffff8ae30550 <handler_617_body-0x462020>
ffffffff8b292f8e:	90                   	nop
ffffffff8b292f8f:	90                   	nop

ffffffff8b292f90 <frame_candidate_8d2f90>:
ffffffff8b292f90:	55                   	push   %rbp
ffffffff8b292f91:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292f94:	48 89 f0             	mov    %rsi,%rax
ffffffff8b292f97:	48 8b 77 18          	mov    0x18(%rdi),%rsi
ffffffff8b292f9b:	48 89 c7             	mov    %rax,%rdi
ffffffff8b292f9e:	5d                   	pop    %rbp
ffffffff8b292f9f:	e9 bc d6 b9 ff       	jmp    ffffffff8ae30660 <handler_617_body-0x461f10>
ffffffff8b292fa4:	90                   	nop
ffffffff8b292fa5:	90                   	nop
ffffffff8b292fa6:	90                   	nop
ffffffff8b292fa7:	90                   	nop
ffffffff8b292fa8:	90                   	nop
ffffffff8b292fa9:	90                   	nop
ffffffff8b292faa:	90                   	nop
ffffffff8b292fab:	90                   	nop
ffffffff8b292fac:	90                   	nop
ffffffff8b292fad:	90                   	nop
ffffffff8b292fae:	90                   	nop
ffffffff8b292faf:	90                   	nop

ffffffff8b292fb0 <frame_candidate_8d2fb0>:
ffffffff8b292fb0:	55                   	push   %rbp
ffffffff8b292fb1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292fb4:	48 8b 7f 18          	mov    0x18(%rdi),%rdi
ffffffff8b292fb8:	5d                   	pop    %rbp
ffffffff8b292fb9:	e9 32 d5 b9 ff       	jmp    ffffffff8ae304f0 <handler_617_body-0x462080>
ffffffff8b292fbe:	90                   	nop
ffffffff8b292fbf:	90                   	nop

ffffffff8b292fc0 <frame_candidate_8d2fc0>:
ffffffff8b292fc0:	55                   	push   %rbp
ffffffff8b292fc1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b292fc4:	41 57                	push   %r15
ffffffff8b292fc6:	41 56                	push   %r14
ffffffff8b292fc8:	41 55                	push   %r13
ffffffff8b292fca:	41 54                	push   %r12
ffffffff8b292fcc:	53                   	push   %rbx
ffffffff8b292fcd:	48 81 ec b8 00 00 00 	sub    $0xb8,%rsp
ffffffff8b292fd4:	49 89 cc             	mov    %rcx,%r12
ffffffff8b292fd7:	48 8d 0d 32 93 04 03 	lea    0x3049332(%rip),%rcx        # ffffffff8e2dc310 <frame_candidate_8d4544+0x3047dcc>
ffffffff8b292fde:	49 89 ff             	mov    %rdi,%r15
ffffffff8b292fe1:	89 f7                	mov    %esi,%edi
ffffffff8b292fe3:	41 bd 16 00 00 00    	mov    $0x16,%r13d
ffffffff8b292fe9:	44 09 ff             	or     %r15d,%edi
ffffffff8b292fec:	48 8b 01             	mov    (%rcx),%rax
ffffffff8b292fef:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b292ff3:	f7 c7 ff ff 03 00    	test   $0x3ffff,%edi
ffffffff8b292ff9:	0f 85 04 04 00 00    	jne    ffffffff8b293403 <frame_candidate_8d2fc0+0x443>
ffffffff8b292fff:	48 8b 3d 32 4d 27 03 	mov    0x3274d32(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293006:	48 89 b5 78 ff ff ff 	mov    %rsi,-0x88(%rbp)
ffffffff8b29300d:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b293010:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
ffffffff8b293014:	48 8d 95 70 ff ff ff 	lea    -0x90(%rbp),%rdx
ffffffff8b29301b:	31 f6                	xor    %esi,%esi
ffffffff8b29301d:	45 89 c6             	mov    %r8d,%r14d
ffffffff8b293020:	4c 89 8d 38 ff ff ff 	mov    %r9,-0xc8(%rbp)
ffffffff8b293027:	e8 44 48 34 00       	call   ffffffff8b5d7870 <frame_candidate_8d4544+0x34332c>
ffffffff8b29302c:	85 c0                	test   %eax,%eax
ffffffff8b29302e:	0f 85 c5 05 00 00    	jne    ffffffff8b2935f9 <frame_candidate_8d2fc0+0x639>
ffffffff8b293034:	48 8b 3d fd 4c 27 03 	mov    0x3274cfd(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b29303b:	48 8b b5 70 ff ff ff 	mov    -0x90(%rbp),%rsi
ffffffff8b293042:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
ffffffff8b293049:	4c 8d 05 98 62 99 ff 	lea    -0x669d68(%rip),%r8        # ffffffff8ac292e8 <handler_617_body-0x669288>
ffffffff8b293050:	4c 8d 8d 70 ff ff ff 	lea    -0x90(%rbp),%r9
ffffffff8b293057:	b9 00 00 04 00       	mov    $0x40000,%ecx
ffffffff8b29305c:	c7 04 24 00 00 00 00 	movl   $0x0,(%rsp)
ffffffff8b293063:	e8 a8 0d 09 00       	call   ffffffff8b323e10 <frame_candidate_8d4544+0x8f8cc>
ffffffff8b293068:	85 c0                	test   %eax,%eax
ffffffff8b29306a:	0f 85 95 05 00 00    	jne    ffffffff8b293605 <frame_candidate_8d2fc0+0x645>
ffffffff8b293070:	48 8b 3d c1 4c 27 03 	mov    0x3274cc1(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293077:	48 8d 95 50 ff ff ff 	lea    -0xb0(%rbp),%rdx
ffffffff8b29307e:	4c 89 bd 58 ff ff ff 	mov    %r15,-0xa8(%rbp)
ffffffff8b293085:	31 f6                	xor    %esi,%esi
ffffffff8b293087:	48 89 9d 68 ff ff ff 	mov    %rbx,-0x98(%rbp)
ffffffff8b29308e:	e8 dd 47 34 00       	call   ffffffff8b5d7870 <frame_candidate_8d4544+0x34332c>
ffffffff8b293093:	85 c0                	test   %eax,%eax
ffffffff8b293095:	0f 85 a6 05 00 00    	jne    ffffffff8b293641 <frame_candidate_8d2fc0+0x681>
ffffffff8b29309b:	48 8b 3d 96 4c 27 03 	mov    0x3274c96(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2930a2:	48 8b b5 50 ff ff ff 	mov    -0xb0(%rbp),%rsi
ffffffff8b2930a9:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
ffffffff8b2930b0:	4c 8d 05 31 62 99 ff 	lea    -0x669dcf(%rip),%r8        # ffffffff8ac292e8 <handler_617_body-0x669288>
ffffffff8b2930b7:	4c 8d 8d 50 ff ff ff 	lea    -0xb0(%rbp),%r9
ffffffff8b2930be:	b9 00 00 04 00       	mov    $0x40000,%ecx
ffffffff8b2930c3:	c7 04 24 00 00 00 00 	movl   $0x0,(%rsp)
ffffffff8b2930ca:	e8 41 0d 09 00       	call   ffffffff8b323e10 <frame_candidate_8d4544+0x8f8cc>
ffffffff8b2930cf:	85 c0                	test   %eax,%eax
ffffffff8b2930d1:	0f 85 76 05 00 00    	jne    ffffffff8b29364d <frame_candidate_8d2fc0+0x68d>
ffffffff8b2930d7:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
ffffffff8b2930de:	00 
ffffffff8b2930df:	41 bd 16 00 00 00    	mov    $0x16,%r13d
ffffffff8b2930e5:	0f 84 9a 02 00 00    	je     ffffffff8b293385 <frame_candidate_8d2fc0+0x3c5>
ffffffff8b2930eb:	41 83 fe 03          	cmp    $0x3,%r14d
ffffffff8b2930ef:	75 1f                	jne    ffffffff8b293110 <frame_candidate_8d2fc0+0x150>
ffffffff8b2930f1:	48 81 fb 01 00 04 00 	cmp    $0x40001,%rbx
ffffffff8b2930f8:	72 25                	jb     ffffffff8b29311f <frame_candidate_8d2fc0+0x15f>
ffffffff8b2930fa:	48 8d 3d c6 e4 a4 00 	lea    0xa4e4c6(%rip),%rdi        # ffffffff8bce15c7 <frame_candidate_8d4544+0xa4d083>
ffffffff8b293101:	48 89 de             	mov    %rbx,%rsi
ffffffff8b293104:	31 c0                	xor    %eax,%eax
ffffffff8b293106:	e8 05 a3 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b29310b:	e9 75 02 00 00       	jmp    ffffffff8b293385 <frame_candidate_8d2fc0+0x3c5>
ffffffff8b293110:	48 8d 3d 25 8d 9a 00 	lea    0x9a8d25(%rip),%rdi        # ffffffff8bc3be3c <frame_candidate_8d4544+0x9a78f8>
ffffffff8b293117:	44 89 f6             	mov    %r14d,%esi
ffffffff8b29311a:	e9 5f 02 00 00       	jmp    ffffffff8b29337e <frame_candidate_8d2fc0+0x3be>
ffffffff8b29311f:	4c 8b 3d 2a 4c 27 03 	mov    0x3274c2a(%rip),%r15        # ffffffff8e507d50 <frame_candidate_8d4544+0x327380c>
ffffffff8b293126:	b0 30                	mov    $0x30,%al
ffffffff8b293128:	be e0 00 00 00       	mov    $0xe0,%esi
ffffffff8b29312d:	c4 62 f8 f5 2d 22 4c 	bzhi   %rax,0x3274c22(%rip),%r13        # ffffffff8e507d58 <frame_candidate_8d4544+0x3273814>
ffffffff8b293134:	27 03 
ffffffff8b293136:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b293139:	e8 b2 5e 98 ff       	call   ffffffff8ac18ff0 <handler_617_body-0x679580>
ffffffff8b29313e:	b8 ff 0f 00 00       	mov    $0xfff,%eax
ffffffff8b293143:	23 05 df 4b 27 03    	and    0x3274bdf(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b293149:	48 b9 60 02 00 00 00 	movabs $0x1000000000260,%rcx
ffffffff8b293150:	00 01 00 
ffffffff8b293153:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b29315a:	00 
ffffffff8b29315b:	4c 89 6d b8          	mov    %r13,-0x48(%rbp)
ffffffff8b29315f:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b293163:	31 ff                	xor    %edi,%edi
ffffffff8b293165:	4c 89 ad 48 ff ff ff 	mov    %r13,-0xb8(%rbp)
ffffffff8b29316c:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b293170:	48 09 c8             	or     %rcx,%rax
ffffffff8b293173:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b293177:	48 b8 18 00 50 00 e0 	movabs $0xe000500018,%rax
ffffffff8b29317e:	00 00 00 
ffffffff8b293181:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b293185:	e8 66 0c 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b29318a:	31 ff                	xor    %edi,%edi
ffffffff8b29318c:	e8 3f 0d 00 00       	call   ffffffff8b293ed0 <frame_candidate_8d3ed0>
ffffffff8b293191:	85 c0                	test   %eax,%eax
ffffffff8b293193:	0f 85 d8 01 00 00    	jne    ffffffff8b293371 <frame_candidate_8d2fc0+0x3b1>
ffffffff8b293199:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b29319d:	49 89 07             	mov    %rax,(%r15)
ffffffff8b2931a0:	49 8b 44 24 08       	mov    0x8(%r12),%rax
ffffffff8b2931a5:	4d 89 fc             	mov    %r15,%r12
ffffffff8b2931a8:	49 89 47 08          	mov    %rax,0x8(%r15)
ffffffff8b2931ac:	49 c7 47 10 00 00 00 	movq   $0x0,0x10(%r15)
ffffffff8b2931b3:	00 
ffffffff8b2931b4:	49 c7 47 18 00 00 00 	movq   $0x0,0x18(%r15)
ffffffff8b2931bb:	00 
ffffffff8b2931bc:	48 85 db             	test   %rbx,%rbx
ffffffff8b2931bf:	0f 84 9d 01 00 00    	je     ffffffff8b293362 <frame_candidate_8d2fc0+0x3a2>
ffffffff8b2931c5:	8b 05 5d 4b 27 03    	mov    0x3274b5d(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b2931cb:	b2 30                	mov    $0x30,%dl
ffffffff8b2931cd:	4c 89 a5 40 ff ff ff 	mov    %r12,-0xc0(%rbp)
ffffffff8b2931d4:	41 bc ff 0f 00 00    	mov    $0xfff,%r12d
ffffffff8b2931da:	49 89 dd             	mov    %rbx,%r13
ffffffff8b2931dd:	48 be 00 00 00 00 00 	movabs $0x3000000000000,%rsi
ffffffff8b2931e4:	00 03 00 
ffffffff8b2931e7:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b2931ec:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b2931f3:	00 
ffffffff8b2931f4:	c4 e2 e8 f5 55 80    	bzhi   %rdx,-0x80(%rbp),%rdx
ffffffff8b2931fa:	49 c1 e5 20          	shl    $0x20,%r13
ffffffff8b2931fe:	49 8d 8d 18 00 50 00 	lea    0x500018(%r13),%rcx
ffffffff8b293205:	44 21 e0             	and    %r12d,%eax
ffffffff8b293208:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b29320c:	48 09 f0             	or     %rsi,%rax
ffffffff8b29320f:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b293213:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8b293217:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b29321b:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8b29321f:	e8 cc 0b 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293224:	4c 8d 7d 90          	lea    -0x70(%rbp),%r15
ffffffff8b293228:	48 b9 00 00 00 04 02 	movabs $0x204000000,%rcx
ffffffff8b29322f:	00 00 00 
ffffffff8b293232:	0f b7 c0             	movzwl %ax,%eax
ffffffff8b293235:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8b29323c:	00 
ffffffff8b29323d:	48 c7 45 a8 00 00 00 	movq   $0x0,-0x58(%rbp)
ffffffff8b293244:	00 
ffffffff8b293245:	31 ff                	xor    %edi,%edi
ffffffff8b293247:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b29324a:	48 89 4d 90          	mov    %rcx,-0x70(%rbp)
ffffffff8b29324e:	48 89 45 98          	mov    %rax,-0x68(%rbp)
ffffffff8b293252:	e8 99 0b 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293257:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b29325c:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b29325f:	e8 8c 0b 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293264:	8b 05 be 4a 27 03    	mov    0x3274abe(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b29326a:	49 8d 8d 18 80 34 00 	lea    0x348018(%r13),%rcx
ffffffff8b293271:	49 bf 60 02 00 00 00 	movabs $0x1000000000260,%r15
ffffffff8b293278:	00 01 00 
ffffffff8b29327b:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b293280:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8b293284:	48 b9 00 00 00 00 00 	movabs $0x3000000000000,%rcx
ffffffff8b29328b:	00 03 00 
ffffffff8b29328e:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8b293292:	49 8d 4f c0          	lea    -0x40(%r15),%rcx
ffffffff8b293296:	44 21 e0             	and    %r12d,%eax
ffffffff8b293299:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b29329d:	48 09 c1             	or     %rax,%rcx
ffffffff8b2932a0:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
ffffffff8b2932a4:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
ffffffff8b2932a8:	4c 8d 7d b0          	lea    -0x50(%rbp),%r15
ffffffff8b2932ac:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2932af:	e8 3c 0b 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b2932b4:	8b 05 6e 4a 27 03    	mov    0x3274a6e(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b2932ba:	48 8b 8d 48 ff ff ff 	mov    -0xb8(%rbp),%rcx
ffffffff8b2932c1:	48 ba 60 02 00 00 00 	movabs $0x1000000000260,%rdx
ffffffff8b2932c8:	00 01 00 
ffffffff8b2932cb:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b2932d2:	00 
ffffffff8b2932d3:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2932d6:	31 ff                	xor    %edi,%edi
ffffffff8b2932d8:	44 21 e0             	and    %r12d,%eax
ffffffff8b2932db:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8b2932df:	48 8d 4a a0          	lea    -0x60(%rdx),%rcx
ffffffff8b2932e3:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b2932e7:	48 09 c1             	or     %rax,%rcx
ffffffff8b2932ea:	48 b8 18 00 50 00 20 	movabs $0x2000500018,%rax
ffffffff8b2932f1:	00 00 00 
ffffffff8b2932f4:	48 05 00 00 50 00    	add    $0x500000,%rax
ffffffff8b2932fa:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
ffffffff8b2932fe:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b293302:	e8 e9 0a 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293307:	49 81 cd 58 11 18 00 	or     $0x181158,%r13
ffffffff8b29330e:	48 b8 00 00 00 00 00 	movabs $0x43000000000000,%rax
ffffffff8b293315:	00 43 00 
ffffffff8b293318:	44 23 25 09 4a 27 03 	and    0x3274a09(%rip),%r12d        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b29331f:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b293322:	31 ff                	xor    %edi,%edi
ffffffff8b293324:	4c 89 6d b0          	mov    %r13,-0x50(%rbp)
ffffffff8b293328:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8b29332c:	b0 30                	mov    $0x30,%al
ffffffff8b29332e:	c4 e2 f8 f5 85 60 ff 	bzhi   %rax,-0xa0(%rbp),%rax
ffffffff8b293335:	ff ff 
ffffffff8b293337:	49 c1 e4 32          	shl    $0x32,%r12
ffffffff8b29333b:	4c 09 e0             	or     %r12,%rax
ffffffff8b29333e:	4c 8b a5 40 ff ff ff 	mov    -0xc0(%rbp),%r12
ffffffff8b293345:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b293349:	48 b8 60 02 00 00 00 	movabs $0x1000000000260,%rax
ffffffff8b293350:	00 01 00 
ffffffff8b293353:	48 05 a0 20 00 00    	add    $0x20a0,%rax
ffffffff8b293359:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8b29335d:	e8 8e 0a 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293362:	31 ff                	xor    %edi,%edi
ffffffff8b293364:	e8 67 0b 00 00       	call   ffffffff8b293ed0 <frame_candidate_8d3ed0>
ffffffff8b293369:	85 c0                	test   %eax,%eax
ffffffff8b29336b:	0f 84 b4 00 00 00    	je     ffffffff8b293425 <frame_candidate_8d2fc0+0x465>
ffffffff8b293371:	41 89 c5             	mov    %eax,%r13d
ffffffff8b293374:	48 8d 3d a8 29 a8 00 	lea    0xa829a8(%rip),%rdi        # ffffffff8bd15d23 <frame_candidate_8d4544+0xa817df>
ffffffff8b29337b:	44 89 ee             	mov    %r13d,%esi
ffffffff8b29337e:	31 c0                	xor    %eax,%eax
ffffffff8b293380:	e8 8b a0 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b293385:	48 8d 3d 86 35 a4 00 	lea    0xa43586(%rip),%rdi        # ffffffff8bcd6912 <frame_candidate_8d4544+0xa423ce>
ffffffff8b29338c:	44 89 ee             	mov    %r13d,%esi
ffffffff8b29338f:	48 89 da             	mov    %rbx,%rdx
ffffffff8b293392:	44 89 f1             	mov    %r14d,%ecx
ffffffff8b293395:	31 c0                	xor    %eax,%eax
ffffffff8b293397:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b29339a:	e8 71 a0 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b29339f:	48 8b b5 70 ff ff ff 	mov    -0x90(%rbp),%rsi
ffffffff8b2933a6:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2933a9:	74 13                	je     ffffffff8b2933be <frame_candidate_8d2fc0+0x3fe>
ffffffff8b2933ab:	48 8b 3d 86 49 27 03 	mov    0x3274986(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2933b2:	e8 b9 49 34 00       	call   ffffffff8b5d7d70 <frame_candidate_8d4544+0x34382c>
ffffffff8b2933b7:	4c 8b bd 70 ff ff ff 	mov    -0x90(%rbp),%r15
ffffffff8b2933be:	48 8b 3d 73 49 27 03 	mov    0x3274973(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2933c5:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b2933c8:	e8 03 45 34 00       	call   ffffffff8b5d78d0 <frame_candidate_8d4544+0x34338c>
ffffffff8b2933cd:	48 8b b5 50 ff ff ff 	mov    -0xb0(%rbp),%rsi
ffffffff8b2933d4:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2933d7:	74 15                	je     ffffffff8b2933ee <frame_candidate_8d2fc0+0x42e>
ffffffff8b2933d9:	48 8b 3d 58 49 27 03 	mov    0x3274958(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2933e0:	e8 8b 49 34 00       	call   ffffffff8b5d7d70 <frame_candidate_8d4544+0x34382c>
ffffffff8b2933e5:	48 8b b5 50 ff ff ff 	mov    -0xb0(%rbp),%rsi
ffffffff8b2933ec:	eb 02                	jmp    ffffffff8b2933f0 <frame_candidate_8d2fc0+0x430>
ffffffff8b2933ee:	31 f6                	xor    %esi,%esi
ffffffff8b2933f0:	48 8b 3d 41 49 27 03 	mov    0x3274941(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2933f7:	e8 d4 44 34 00       	call   ffffffff8b5d78d0 <frame_candidate_8d4544+0x34338c>
ffffffff8b2933fc:	48 8d 0d 0d 8f 04 03 	lea    0x3048f0d(%rip),%rcx        # ffffffff8e2dc310 <frame_candidate_8d4544+0x3047dcc>
ffffffff8b293403:	48 8b 01             	mov    (%rcx),%rax
ffffffff8b293406:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b29340a:	0f 85 e2 01 00 00    	jne    ffffffff8b2935f2 <frame_candidate_8d2fc0+0x632>
ffffffff8b293410:	44 89 e8             	mov    %r13d,%eax
ffffffff8b293413:	48 81 c4 b8 00 00 00 	add    $0xb8,%rsp
ffffffff8b29341a:	5b                   	pop    %rbx
ffffffff8b29341b:	41 5c                	pop    %r12
ffffffff8b29341d:	41 5d                	pop    %r13
ffffffff8b29341f:	41 5e                	pop    %r14
ffffffff8b293421:	41 5f                	pop    %r15
ffffffff8b293423:	5d                   	pop    %rbp
ffffffff8b293424:	c3                   	ret
ffffffff8b293425:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b29342a:	e8 a1 0a 00 00       	call   ffffffff8b293ed0 <frame_candidate_8d3ed0>
ffffffff8b29342f:	85 c0                	test   %eax,%eax
ffffffff8b293431:	74 0f                	je     ffffffff8b293442 <frame_candidate_8d2fc0+0x482>
ffffffff8b293433:	41 89 c5             	mov    %eax,%r13d
ffffffff8b293436:	48 8d 3d 2d 16 9d 00 	lea    0x9d162d(%rip),%rdi        # ffffffff8bc64a6a <frame_candidate_8d4544+0x9d0526>
ffffffff8b29343d:	e9 39 ff ff ff       	jmp    ffffffff8b29337b <frame_candidate_8d2fc0+0x3bb>
ffffffff8b293442:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b293447:	e8 84 0a 00 00       	call   ffffffff8b293ed0 <frame_candidate_8d3ed0>
ffffffff8b29344c:	85 c0                	test   %eax,%eax
ffffffff8b29344e:	74 0f                	je     ffffffff8b29345f <frame_candidate_8d2fc0+0x49f>
ffffffff8b293450:	41 89 c5             	mov    %eax,%r13d
ffffffff8b293453:	48 8d 3d 02 8a 9a 00 	lea    0x9a8a02(%rip),%rdi        # ffffffff8bc3be5c <frame_candidate_8d4544+0x9a7918>
ffffffff8b29345a:	e9 1c ff ff ff       	jmp    ffffffff8b29337b <frame_candidate_8d2fc0+0x3bb>
ffffffff8b29345f:	be 20 00 00 00       	mov    $0x20,%esi
ffffffff8b293464:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b293467:	e8 84 5b 98 ff       	call   ffffffff8ac18ff0 <handler_617_body-0x679580>
ffffffff8b29346c:	8b 05 b6 48 27 03    	mov    0x32748b6(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b293472:	41 bd ff 0f 00 00    	mov    $0xfff,%r13d
ffffffff8b293478:	48 8b 8d 48 ff ff ff 	mov    -0xb8(%rbp),%rcx
ffffffff8b29347f:	49 bf 60 02 00 00 00 	movabs $0x1000000000260,%r15
ffffffff8b293486:	00 01 00 
ffffffff8b293489:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b293490:	00 
ffffffff8b293491:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b293495:	31 ff                	xor    %edi,%edi
ffffffff8b293497:	4c 89 a5 40 ff ff ff 	mov    %r12,-0xc0(%rbp)
ffffffff8b29349e:	44 21 e8             	and    %r13d,%eax
ffffffff8b2934a1:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8b2934a5:	49 8d 8f 00 01 00 00 	lea    0x100(%r15),%rcx
ffffffff8b2934ac:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b2934b0:	48 89 8d 30 ff ff ff 	mov    %rcx,-0xd0(%rbp)
ffffffff8b2934b7:	4a 8d 84 38 00 01 00 	lea    0x100(%rax,%r15,1),%rax
ffffffff8b2934be:	00 
ffffffff8b2934bf:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b2934c3:	48 b8 18 00 50 00 20 	movabs $0x2000500018,%rax
ffffffff8b2934ca:	00 00 00 
ffffffff8b2934cd:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b2934d1:	e8 1a 09 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b2934d6:	8b 05 4c 48 27 03    	mov    0x327484c(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b2934dc:	48 8b 8d 48 ff ff ff 	mov    -0xb8(%rbp),%rcx
ffffffff8b2934e3:	49 bc 18 00 50 00 20 	movabs $0x2000500018,%r12
ffffffff8b2934ea:	00 00 00 
ffffffff8b2934ed:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b2934f1:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b2934f8:	00 
ffffffff8b2934f9:	31 ff                	xor    %edi,%edi
ffffffff8b2934fb:	44 21 e8             	and    %r13d,%eax
ffffffff8b2934fe:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8b293502:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b293506:	49 8d 84 07 e0 00 00 	lea    0xe0(%r15,%rax,1),%rax
ffffffff8b29350d:	00 
ffffffff8b29350e:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b293512:	4c 89 65 b0          	mov    %r12,-0x50(%rbp)
ffffffff8b293516:	e8 d5 08 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b29351b:	8b 05 07 48 27 03    	mov    0x3274807(%rip),%eax        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b293521:	49 8d 8c 24 00 10 48 	lea    0x481000(%r12),%rcx
ffffffff8b293528:	00 
ffffffff8b293529:	31 ff                	xor    %edi,%edi
ffffffff8b29352b:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8b29352f:	48 b9 20 02 00 00 00 	movabs $0x6d000000000220,%rcx
ffffffff8b293536:	00 6d 00 
ffffffff8b293539:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8b29353d:	44 21 e8             	and    %r13d,%eax
ffffffff8b293540:	48 c1 e0 32          	shl    $0x32,%rax
ffffffff8b293544:	4c 09 f8             	or     %r15,%rax
ffffffff8b293547:	49 81 c7 e0 20 00 00 	add    $0x20e0,%r15
ffffffff8b29354e:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b293552:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
ffffffff8b293556:	4c 8d 7d b0          	lea    -0x50(%rbp),%r15
ffffffff8b29355a:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b29355d:	e8 8e 08 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293562:	44 23 2d bf 47 27 03 	and    0x32747bf(%rip),%r13d        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b293569:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
ffffffff8b293570:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b293573:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
ffffffff8b29357a:	00 
ffffffff8b29357b:	31 ff                	xor    %edi,%edi
ffffffff8b29357d:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
ffffffff8b293581:	49 c1 e5 32          	shl    $0x32,%r13
ffffffff8b293585:	4c 03 ad 48 ff ff ff 	add    -0xb8(%rbp),%r13
ffffffff8b29358c:	4c 89 6d c0          	mov    %r13,-0x40(%rbp)
ffffffff8b293590:	4c 89 65 b0          	mov    %r12,-0x50(%rbp)
ffffffff8b293594:	e8 57 08 00 00       	call   ffffffff8b293df0 <frame_candidate_8d3df0>
ffffffff8b293599:	31 ff                	xor    %edi,%edi
ffffffff8b29359b:	e8 30 09 00 00       	call   ffffffff8b293ed0 <frame_candidate_8d3ed0>
ffffffff8b2935a0:	85 c0                	test   %eax,%eax
ffffffff8b2935a2:	0f 85 c9 fd ff ff    	jne    ffffffff8b293371 <frame_candidate_8d2fc0+0x3b1>
ffffffff8b2935a8:	48 8b bd 38 ff ff ff 	mov    -0xc8(%rbp),%rdi
ffffffff8b2935af:	48 8b b5 40 ff ff ff 	mov    -0xc0(%rbp),%rsi
ffffffff8b2935b6:	ba 10 00 00 00       	mov    $0x10,%edx
ffffffff8b2935bb:	e8 f0 5a 98 ff       	call   ffffffff8ac190b0 <handler_617_body-0x6794c0>
ffffffff8b2935c0:	48 8b b5 70 ff ff ff 	mov    -0x90(%rbp),%rsi
ffffffff8b2935c7:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b2935ca:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2935cd:	74 15                	je     ffffffff8b2935e4 <frame_candidate_8d2fc0+0x624>
ffffffff8b2935cf:	48 8b 3d 62 47 27 03 	mov    0x3274762(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2935d6:	e8 95 47 34 00       	call   ffffffff8b5d7d70 <frame_candidate_8d4544+0x34382c>
ffffffff8b2935db:	48 8b b5 70 ff ff ff 	mov    -0x90(%rbp),%rsi
ffffffff8b2935e2:	eb 02                	jmp    ffffffff8b2935e6 <frame_candidate_8d2fc0+0x626>
ffffffff8b2935e4:	31 f6                	xor    %esi,%esi
ffffffff8b2935e6:	48 8b 3d 4b 47 27 03 	mov    0x327474b(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b2935ed:	e9 d6 fd ff ff       	jmp    ffffffff8b2933c8 <frame_candidate_8d2fc0+0x408>
ffffffff8b2935f2:	e8 b9 a0 e2 ff       	call   ffffffff8b0bd6b0 <handler_617_body-0x1d4ec0>
ffffffff8b2935f7:	0f 0b                	ud2
ffffffff8b2935f9:	41 89 c6             	mov    %eax,%r14d
ffffffff8b2935fc:	48 8d 3d 83 67 ab 00 	lea    0xab6783(%rip),%rdi        # ffffffff8bd49d86 <frame_candidate_8d4544+0xab5842>
ffffffff8b293603:	eb 0a                	jmp    ffffffff8b29360f <frame_candidate_8d2fc0+0x64f>
ffffffff8b293605:	41 89 c6             	mov    %eax,%r14d
ffffffff8b293608:	48 8d 3d d9 0a ac 00 	lea    0xac0ad9(%rip),%rdi        # ffffffff8bd540e8 <frame_candidate_8d4544+0xabfba4>
ffffffff8b29360f:	44 89 f6             	mov    %r14d,%esi
ffffffff8b293612:	31 c0                	xor    %eax,%eax
ffffffff8b293614:	e8 f7 9d 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b293619:	e8 32 e3 f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b29361e:	4d 63 f6             	movslq %r14d,%r14
ffffffff8b293621:	48 8d 3d e7 ff ff ff 	lea    -0x19(%rip),%rdi        # ffffffff8b29360f <frame_candidate_8d2fc0+0x64f>
ffffffff8b293628:	48 89 da             	mov    %rbx,%rdx
ffffffff8b29362b:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b29362e:	e8 dd e9 f1 ff       	call   ffffffff8b1b2010 <handler_617_body-0xe0560>
ffffffff8b293633:	48 8d 35 6a ed 99 00 	lea    0x99ed6a(%rip),%rsi        # ffffffff8bc323a4 <frame_candidate_8d4544+0x99de60>
ffffffff8b29363a:	bf 37 00 00 00       	mov    $0x37,%edi
ffffffff8b29363f:	eb 46                	jmp    ffffffff8b293687 <frame_candidate_8d2fc0+0x6c7>
ffffffff8b293641:	41 89 c6             	mov    %eax,%r14d
ffffffff8b293644:	48 8d 3d 3b 67 ab 00 	lea    0xab673b(%rip),%rdi        # ffffffff8bd49d86 <frame_candidate_8d4544+0xab5842>
ffffffff8b29364b:	eb 0a                	jmp    ffffffff8b293657 <frame_candidate_8d2fc0+0x697>
ffffffff8b29364d:	41 89 c6             	mov    %eax,%r14d
ffffffff8b293650:	48 8d 3d 91 0a ac 00 	lea    0xac0a91(%rip),%rdi        # ffffffff8bd540e8 <frame_candidate_8d4544+0xabfba4>
ffffffff8b293657:	44 89 f6             	mov    %r14d,%esi
ffffffff8b29365a:	31 c0                	xor    %eax,%eax
ffffffff8b29365c:	e8 af 9d 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b293661:	e8 ea e2 f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293666:	4d 63 f6             	movslq %r14d,%r14
ffffffff8b293669:	48 8d 3d e7 ff ff ff 	lea    -0x19(%rip),%rdi        # ffffffff8b293657 <frame_candidate_8d2fc0+0x697>
ffffffff8b293670:	48 89 da             	mov    %rbx,%rdx
ffffffff8b293673:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b293676:	e8 95 e9 f1 ff       	call   ffffffff8b1b2010 <handler_617_body-0xe0560>
ffffffff8b29367b:	48 8d 35 ea 66 ab 00 	lea    0xab66ea(%rip),%rsi        # ffffffff8bd49d6c <frame_candidate_8d4544+0xab5828>
ffffffff8b293682:	bf 3b 00 00 00       	mov    $0x3b,%edi
ffffffff8b293687:	44 89 f2             	mov    %r14d,%edx
ffffffff8b29368a:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b29368d:	31 c0                	xor    %eax,%eax
ffffffff8b29368f:	e8 7c 73 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293694:	0f 0b                	ud2
ffffffff8b293696:	90                   	nop
ffffffff8b293697:	90                   	nop
ffffffff8b293698:	90                   	nop
ffffffff8b293699:	90                   	nop
ffffffff8b29369a:	90                   	nop
ffffffff8b29369b:	90                   	nop
ffffffff8b29369c:	90                   	nop
ffffffff8b29369d:	90                   	nop
ffffffff8b29369e:	90                   	nop
ffffffff8b29369f:	90                   	nop

ffffffff8b2936a0 <frame_candidate_8d36a0>:
ffffffff8b2936a0:	55                   	push   %rbp
ffffffff8b2936a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b2936a4:	41 57                	push   %r15
ffffffff8b2936a6:	41 56                	push   %r14
ffffffff8b2936a8:	41 55                	push   %r13
ffffffff8b2936aa:	41 54                	push   %r12
ffffffff8b2936ac:	53                   	push   %rbx
ffffffff8b2936ad:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b2936b1:	89 3d 71 46 27 03    	mov    %edi,0x3274671(%rip)        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b2936b7:	31 ff                	xor    %edi,%edi
ffffffff8b2936b9:	e8 e2 05 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b2936be:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b2936c3:	e8 d8 05 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b2936c8:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b2936cd:	e8 ce 05 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b2936d2:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b2936d7:	e8 c4 05 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b2936dc:	8b 3d 72 82 c7 01    	mov    0x1c78272(%rip),%edi        # ffffffff8cf0b954 <frame_candidate_8d4544+0x1c77410>
ffffffff8b2936e2:	bb 00 00 50 02       	mov    $0x2500000,%ebx
ffffffff8b2936e7:	31 f6                	xor    %esi,%esi
ffffffff8b2936e9:	01 df                	add    %ebx,%edi
ffffffff8b2936eb:	e8 80 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2936f0:	8b 3d 62 82 c7 01    	mov    0x1c78262(%rip),%edi        # ffffffff8cf0b958 <frame_candidate_8d4544+0x1c77414>
ffffffff8b2936f6:	31 f6                	xor    %esi,%esi
ffffffff8b2936f8:	01 df                	add    %ebx,%edi
ffffffff8b2936fa:	e8 71 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2936ff:	8b 3d 5f 82 c7 01    	mov    0x1c7825f(%rip),%edi        # ffffffff8cf0b964 <frame_candidate_8d4544+0x1c77420>
ffffffff8b293705:	31 f6                	xor    %esi,%esi
ffffffff8b293707:	01 df                	add    %ebx,%edi
ffffffff8b293709:	e8 62 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b29370e:	8b 3d 54 82 c7 01    	mov    0x1c78254(%rip),%edi        # ffffffff8cf0b968 <frame_candidate_8d4544+0x1c77424>
ffffffff8b293714:	31 f6                	xor    %esi,%esi
ffffffff8b293716:	01 df                	add    %ebx,%edi
ffffffff8b293718:	e8 53 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b29371d:	8b 3d 49 82 c7 01    	mov    0x1c78249(%rip),%edi        # ffffffff8cf0b96c <frame_candidate_8d4544+0x1c77428>
ffffffff8b293723:	31 f6                	xor    %esi,%esi
ffffffff8b293725:	01 df                	add    %ebx,%edi
ffffffff8b293727:	e8 44 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b29372c:	8b 3d 62 82 c7 01    	mov    0x1c78262(%rip),%edi        # ffffffff8cf0b994 <frame_candidate_8d4544+0x1c77450>
ffffffff8b293732:	31 f6                	xor    %esi,%esi
ffffffff8b293734:	01 df                	add    %ebx,%edi
ffffffff8b293736:	e8 35 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b29373b:	8b 3d 57 82 c7 01    	mov    0x1c78257(%rip),%edi        # ffffffff8cf0b998 <frame_candidate_8d4544+0x1c77454>
ffffffff8b293741:	31 f6                	xor    %esi,%esi
ffffffff8b293743:	01 df                	add    %ebx,%edi
ffffffff8b293745:	e8 26 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b29374a:	8b 3d 54 82 c7 01    	mov    0x1c78254(%rip),%edi        # ffffffff8cf0b9a4 <frame_candidate_8d4544+0x1c77460>
ffffffff8b293750:	31 f6                	xor    %esi,%esi
ffffffff8b293752:	01 df                	add    %ebx,%edi
ffffffff8b293754:	e8 17 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293759:	8b 3d 49 82 c7 01    	mov    0x1c78249(%rip),%edi        # ffffffff8cf0b9a8 <frame_candidate_8d4544+0x1c77464>
ffffffff8b29375f:	31 f6                	xor    %esi,%esi
ffffffff8b293761:	01 df                	add    %ebx,%edi
ffffffff8b293763:	e8 08 cc 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293768:	8b 3d 3e 82 c7 01    	mov    0x1c7823e(%rip),%edi        # ffffffff8cf0b9ac <frame_candidate_8d4544+0x1c77468>
ffffffff8b29376e:	31 f6                	xor    %esi,%esi
ffffffff8b293770:	01 df                	add    %ebx,%edi
ffffffff8b293772:	e8 f9 cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293777:	8b 3d 57 82 c7 01    	mov    0x1c78257(%rip),%edi        # ffffffff8cf0b9d4 <frame_candidate_8d4544+0x1c77490>
ffffffff8b29377d:	31 f6                	xor    %esi,%esi
ffffffff8b29377f:	01 df                	add    %ebx,%edi
ffffffff8b293781:	e8 ea cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293786:	8b 3d 4c 82 c7 01    	mov    0x1c7824c(%rip),%edi        # ffffffff8cf0b9d8 <frame_candidate_8d4544+0x1c77494>
ffffffff8b29378c:	31 f6                	xor    %esi,%esi
ffffffff8b29378e:	01 df                	add    %ebx,%edi
ffffffff8b293790:	e8 db cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293795:	8b 3d 49 82 c7 01    	mov    0x1c78249(%rip),%edi        # ffffffff8cf0b9e4 <frame_candidate_8d4544+0x1c774a0>
ffffffff8b29379b:	31 f6                	xor    %esi,%esi
ffffffff8b29379d:	01 df                	add    %ebx,%edi
ffffffff8b29379f:	e8 cc cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937a4:	8b 3d 3e 82 c7 01    	mov    0x1c7823e(%rip),%edi        # ffffffff8cf0b9e8 <frame_candidate_8d4544+0x1c774a4>
ffffffff8b2937aa:	31 f6                	xor    %esi,%esi
ffffffff8b2937ac:	01 df                	add    %ebx,%edi
ffffffff8b2937ae:	e8 bd cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937b3:	8b 3d 33 82 c7 01    	mov    0x1c78233(%rip),%edi        # ffffffff8cf0b9ec <frame_candidate_8d4544+0x1c774a8>
ffffffff8b2937b9:	31 f6                	xor    %esi,%esi
ffffffff8b2937bb:	01 df                	add    %ebx,%edi
ffffffff8b2937bd:	e8 ae cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937c2:	8b 3d 4c 82 c7 01    	mov    0x1c7824c(%rip),%edi        # ffffffff8cf0ba14 <frame_candidate_8d4544+0x1c774d0>
ffffffff8b2937c8:	31 f6                	xor    %esi,%esi
ffffffff8b2937ca:	01 df                	add    %ebx,%edi
ffffffff8b2937cc:	e8 9f cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937d1:	8b 3d 41 82 c7 01    	mov    0x1c78241(%rip),%edi        # ffffffff8cf0ba18 <frame_candidate_8d4544+0x1c774d4>
ffffffff8b2937d7:	31 f6                	xor    %esi,%esi
ffffffff8b2937d9:	01 df                	add    %ebx,%edi
ffffffff8b2937db:	e8 90 cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937e0:	8b 3d 3e 82 c7 01    	mov    0x1c7823e(%rip),%edi        # ffffffff8cf0ba24 <frame_candidate_8d4544+0x1c774e0>
ffffffff8b2937e6:	31 f6                	xor    %esi,%esi
ffffffff8b2937e8:	01 df                	add    %ebx,%edi
ffffffff8b2937ea:	e8 81 cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937ef:	8b 3d 33 82 c7 01    	mov    0x1c78233(%rip),%edi        # ffffffff8cf0ba28 <frame_candidate_8d4544+0x1c774e4>
ffffffff8b2937f5:	31 f6                	xor    %esi,%esi
ffffffff8b2937f7:	01 df                	add    %ebx,%edi
ffffffff8b2937f9:	e8 72 cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2937fe:	8b 3d 28 82 c7 01    	mov    0x1c78228(%rip),%edi        # ffffffff8cf0ba2c <frame_candidate_8d4544+0x1c774e8>
ffffffff8b293804:	31 f6                	xor    %esi,%esi
ffffffff8b293806:	01 df                	add    %ebx,%edi
ffffffff8b293808:	e8 63 cb 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b29380d:	e8 5e 02 00 00       	call   ffffffff8b293a70 <frame_candidate_8d3a70>
ffffffff8b293812:	85 c0                	test   %eax,%eax
ffffffff8b293814:	0f 85 1c 02 00 00    	jne    ffffffff8b293a36 <frame_candidate_8d36a0+0x396>
ffffffff8b29381a:	4c 8d 25 2f 81 c7 01 	lea    0x1c7812f(%rip),%r12        # ffffffff8cf0b950 <frame_candidate_8d4544+0x1c7740c>
ffffffff8b293821:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b293824:	31 db                	xor    %ebx,%ebx
ffffffff8b293826:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b29382d:	00 00 00 
ffffffff8b293830:	89 df                	mov    %ebx,%edi
ffffffff8b293832:	e8 99 03 00 00       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b293837:	89 df                	mov    %ebx,%edi
ffffffff8b293839:	e8 92 03 00 00       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b29383e:	48 8d 05 eb 44 27 03 	lea    0x32744eb(%rip),%rax        # ffffffff8e507d30 <frame_candidate_8d4544+0x32737ec>
ffffffff8b293845:	89 df                	mov    %ebx,%edi
ffffffff8b293847:	49 8b 4c 05 40       	mov    0x40(%r13,%rax,1),%rcx
ffffffff8b29384c:	4d 8b 74 05 48       	mov    0x48(%r13,%rax,1),%r14
ffffffff8b293851:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
ffffffff8b293855:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
ffffffff8b29385c:	e8 3f 04 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b293861:	8b 45 d4             	mov    -0x2c(%rbp),%eax
ffffffff8b293864:	b9 40 00 00 00       	mov    $0x40,%ecx
ffffffff8b293869:	83 e0 87             	and    $0xffffff87,%eax
ffffffff8b29386c:	83 c8 30             	or     $0x30,%eax
ffffffff8b29386f:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b293872:	8b 45 d4             	mov    -0x2c(%rbp),%eax
ffffffff8b293875:	c0 e8 03             	shr    $0x3,%al
ffffffff8b293878:	24 0f                	and    $0xf,%al
ffffffff8b29387a:	c4 62 79 f7 f9       	shlx   %eax,%ecx,%r15d
ffffffff8b29387f:	41 ff cf             	dec    %r15d
ffffffff8b293882:	45 85 fe             	test   %r15d,%r14d
ffffffff8b293885:	0f 85 48 01 00 00    	jne    ffffffff8b2939d3 <frame_candidate_8d36a0+0x333>
ffffffff8b29388b:	83 4d d4 02          	orl    $0x2,-0x2c(%rbp)
ffffffff8b29388f:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b293892:	41 bf 00 00 50 02    	mov    $0x2500000,%r15d
ffffffff8b293898:	83 65 d4 fb          	andl   $0xfffffffb,-0x2c(%rbp)
ffffffff8b29389c:	48 c1 e9 10          	shr    $0x10,%rcx
ffffffff8b2938a0:	8b 45 d4             	mov    -0x2c(%rbp),%eax
ffffffff8b2938a3:	81 e1 00 00 ff ff    	and    $0xffff0000,%ecx
ffffffff8b2938a9:	0f b7 c0             	movzwl %ax,%eax
ffffffff8b2938ac:	09 c8                	or     %ecx,%eax
ffffffff8b2938ae:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b2938b1:	8b 75 d4             	mov    -0x2c(%rbp),%esi
ffffffff8b2938b4:	43 8b 3c 6c          	mov    (%r12,%r13,2),%edi
ffffffff8b2938b8:	44 01 ff             	add    %r15d,%edi
ffffffff8b2938bb:	e8 b0 ca 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2938c0:	43 8b 7c 6c 04       	mov    0x4(%r12,%r13,2),%edi
ffffffff8b2938c5:	44 89 f6             	mov    %r14d,%esi
ffffffff8b2938c8:	44 01 ff             	add    %r15d,%edi
ffffffff8b2938cb:	e8 a0 ca 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2938d0:	43 8b 7c 6c 08       	mov    0x8(%r12,%r13,2),%edi
ffffffff8b2938d5:	44 89 f6             	mov    %r14d,%esi
ffffffff8b2938d8:	44 01 ff             	add    %r15d,%edi
ffffffff8b2938db:	e8 90 ca 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2938e0:	43 8b 7c 6c 14       	mov    0x14(%r12,%r13,2),%edi
ffffffff8b2938e5:	31 f6                	xor    %esi,%esi
ffffffff8b2938e7:	44 01 ff             	add    %r15d,%edi
ffffffff8b2938ea:	e8 81 ca 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2938ef:	43 8b 7c 6c 10       	mov    0x10(%r12,%r13,2),%edi
ffffffff8b2938f4:	be 44 04 00 00       	mov    $0x444,%esi
ffffffff8b2938f9:	44 01 ff             	add    %r15d,%edi
ffffffff8b2938fc:	e8 6f ca 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293901:	8b 35 21 44 27 03    	mov    0x3274421(%rip),%esi        # ffffffff8e507d28 <frame_candidate_8d4544+0x32737e4>
ffffffff8b293907:	43 8b 7c 6c 0c       	mov    0xc(%r12,%r13,2),%edi
ffffffff8b29390c:	c1 e6 07             	shl    $0x7,%esi
ffffffff8b29390f:	44 01 ff             	add    %r15d,%edi
ffffffff8b293912:	e8 59 ca 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293917:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b29391b:	66 43 c7 44 6c 24 00 	movw   $0x0,0x24(%r12,%r13,2)
ffffffff8b293922:	00 
ffffffff8b293923:	43 c7 44 6c 2c 00 00 	movl   $0x0,0x2c(%r12,%r13,2)
ffffffff8b29392a:	00 00 
ffffffff8b29392c:	47 89 74 6c 28       	mov    %r14d,0x28(%r12,%r13,2)
ffffffff8b293931:	4f 89 74 6c 30       	mov    %r14,0x30(%r12,%r13,2)
ffffffff8b293936:	48 ff c3             	inc    %rbx
ffffffff8b293939:	4b 89 44 6c 38       	mov    %rax,0x38(%r12,%r13,2)
ffffffff8b29393e:	49 83 c5 20          	add    $0x20,%r13
ffffffff8b293942:	48 83 fb 04          	cmp    $0x4,%rbx
ffffffff8b293946:	0f 85 e4 fe ff ff    	jne    ffffffff8b293830 <frame_candidate_8d36a0+0x190>
ffffffff8b29394c:	8b 3d fe 7f c7 01    	mov    0x1c77ffe(%rip),%edi        # ffffffff8cf0b950 <frame_candidate_8d4544+0x1c7740c>
ffffffff8b293952:	bb 00 00 50 02       	mov    $0x2500000,%ebx
ffffffff8b293957:	01 df                	add    %ebx,%edi
ffffffff8b293959:	e8 c2 c8 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b29395e:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b293961:	83 4d d4 01          	orl    $0x1,-0x2c(%rbp)
ffffffff8b293965:	8b 75 d4             	mov    -0x2c(%rbp),%esi
ffffffff8b293968:	8b 3d e2 7f c7 01    	mov    0x1c77fe2(%rip),%edi        # ffffffff8cf0b950 <frame_candidate_8d4544+0x1c7740c>
ffffffff8b29396e:	01 df                	add    %ebx,%edi
ffffffff8b293970:	e8 fb c9 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293975:	8b 3d 15 80 c7 01    	mov    0x1c78015(%rip),%edi        # ffffffff8cf0b990 <frame_candidate_8d4544+0x1c7744c>
ffffffff8b29397b:	01 df                	add    %ebx,%edi
ffffffff8b29397d:	e8 9e c8 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293982:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b293985:	83 4d d4 01          	orl    $0x1,-0x2c(%rbp)
ffffffff8b293989:	8b 75 d4             	mov    -0x2c(%rbp),%esi
ffffffff8b29398c:	8b 3d fe 7f c7 01    	mov    0x1c77ffe(%rip),%edi        # ffffffff8cf0b990 <frame_candidate_8d4544+0x1c7744c>
ffffffff8b293992:	01 df                	add    %ebx,%edi
ffffffff8b293994:	e8 d7 c9 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293999:	8b 3d 31 80 c7 01    	mov    0x1c78031(%rip),%edi        # ffffffff8cf0b9d0 <frame_candidate_8d4544+0x1c7748c>
ffffffff8b29399f:	01 df                	add    %ebx,%edi
ffffffff8b2939a1:	e8 7a c8 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b2939a6:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b2939a9:	83 4d d4 01          	orl    $0x1,-0x2c(%rbp)
ffffffff8b2939ad:	8b 75 d4             	mov    -0x2c(%rbp),%esi
ffffffff8b2939b0:	03 1d 1a 80 c7 01    	add    0x1c7801a(%rip),%ebx        # ffffffff8cf0b9d0 <frame_candidate_8d4544+0x1c7748c>
ffffffff8b2939b6:	89 df                	mov    %ebx,%edi
ffffffff8b2939b8:	e8 b3 c9 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b2939bd:	c6 05 7c 43 27 03 01 	movb   $0x1,0x327437c(%rip)        # ffffffff8e507d40 <frame_candidate_8d4544+0x32737fc>
ffffffff8b2939c4:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b2939c8:	5b                   	pop    %rbx
ffffffff8b2939c9:	41 5c                	pop    %r12
ffffffff8b2939cb:	41 5d                	pop    %r13
ffffffff8b2939cd:	41 5e                	pop    %r14
ffffffff8b2939cf:	41 5f                	pop    %r15
ffffffff8b2939d1:	5d                   	pop    %rbp
ffffffff8b2939d2:	c3                   	ret
ffffffff8b2939d3:	48 8d 3d 99 17 aa 00 	lea    0xaa1799(%rip),%rdi        # ffffffff8bd35173 <frame_candidate_8d4544+0xaa0c2f>
ffffffff8b2939da:	48 8d 35 15 79 a7 00 	lea    0xa77915(%rip),%rsi        # ffffffff8bd0b2f6 <frame_candidate_8d4544+0xa76db2>
ffffffff8b2939e1:	ba 32 01 00 00       	mov    $0x132,%edx
ffffffff8b2939e6:	31 c0                	xor    %eax,%eax
ffffffff8b2939e8:	e8 23 9a 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b2939ed:	48 8d 3d 52 0d ae 00 	lea    0xae0d52(%rip),%rdi        # ffffffff8bd74746 <frame_candidate_8d4544+0xae0202>
ffffffff8b2939f4:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b2939f7:	44 89 fa             	mov    %r15d,%edx
ffffffff8b2939fa:	31 c0                	xor    %eax,%eax
ffffffff8b2939fc:	e8 0f 9a 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b293a01:	e8 4a df f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293a06:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b293a01 <frame_candidate_8d36a0+0x361>
ffffffff8b293a0d:	be 16 00 00 00       	mov    $0x16,%esi
ffffffff8b293a12:	48 89 da             	mov    %rbx,%rdx
ffffffff8b293a15:	e8 f6 e5 f1 ff       	call   ffffffff8b1b2010 <handler_617_body-0xe0560>
ffffffff8b293a1a:	48 8d 35 78 db a4 00 	lea    0xa4db78(%rip),%rsi        # ffffffff8bce1599 <frame_candidate_8d4544+0xa4d055>
ffffffff8b293a21:	bf 43 00 00 00       	mov    $0x43,%edi
ffffffff8b293a26:	ba 16 00 00 00       	mov    $0x16,%edx
ffffffff8b293a2b:	89 d9                	mov    %ebx,%ecx
ffffffff8b293a2d:	31 c0                	xor    %eax,%eax
ffffffff8b293a2f:	e8 dc 6f 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293a34:	0f 0b                	ud2
ffffffff8b293a36:	89 c3                	mov    %eax,%ebx
ffffffff8b293a38:	e8 13 df f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293a3d:	48 63 f3             	movslq %ebx,%rsi
ffffffff8b293a40:	48 8d 3d ef ff ff ff 	lea    -0x11(%rip),%rdi        # ffffffff8b293a36 <frame_candidate_8d36a0+0x396>
ffffffff8b293a47:	e8 54 de f1 ff       	call   ffffffff8b1b18a0 <handler_617_body-0xe0cd0>
ffffffff8b293a4c:	48 8d 35 dc b8 aa 00 	lea    0xaab8dc(%rip),%rsi        # ffffffff8bd3f32f <frame_candidate_8d4544+0xaaadeb>
ffffffff8b293a53:	bf 3f 00 00 00       	mov    $0x3f,%edi
ffffffff8b293a58:	89 da                	mov    %ebx,%edx
ffffffff8b293a5a:	31 c0                	xor    %eax,%eax
ffffffff8b293a5c:	e8 af 6f 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293a61:	0f 0b                	ud2
ffffffff8b293a63:	90                   	nop
ffffffff8b293a64:	90                   	nop
ffffffff8b293a65:	90                   	nop
ffffffff8b293a66:	90                   	nop
ffffffff8b293a67:	90                   	nop
ffffffff8b293a68:	90                   	nop
ffffffff8b293a69:	90                   	nop
ffffffff8b293a6a:	90                   	nop
ffffffff8b293a6b:	90                   	nop
ffffffff8b293a6c:	90                   	nop
ffffffff8b293a6d:	90                   	nop
ffffffff8b293a6e:	90                   	nop
ffffffff8b293a6f:	90                   	nop

ffffffff8b293a70 <frame_candidate_8d3a70>:
ffffffff8b293a70:	55                   	push   %rbp
ffffffff8b293a71:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293a74:	53                   	push   %rbx
ffffffff8b293a75:	50                   	push   %rax
ffffffff8b293a76:	bf 22 10 00 00       	mov    $0x1022,%edi
ffffffff8b293a7b:	be ef 13 00 00       	mov    $0x13ef,%esi
ffffffff8b293a80:	e8 6b c2 a2 ff       	call   ffffffff8acbfcf0 <handler_617_body-0x5d2880>
ffffffff8b293a85:	48 89 05 a4 42 27 03 	mov    %rax,0x32742a4(%rip)        # ffffffff8e507d30 <frame_candidate_8d4544+0x32737ec>
ffffffff8b293a8c:	48 85 c0             	test   %rax,%rax
ffffffff8b293a8f:	0f 84 c2 00 00 00    	je     ffffffff8b293b57 <frame_candidate_8d3a70+0xe7>
ffffffff8b293a95:	48 8d 3d a2 22 a8 00 	lea    0xa822a2(%rip),%rdi        # ffffffff8bd15d3e <frame_candidate_8d4544+0xa817fa>
ffffffff8b293a9c:	48 89 c3             	mov    %rax,%rbx
ffffffff8b293a9f:	e8 9c 4d 9e ff       	call   ffffffff8ac78840 <handler_617_body-0x619d30>
ffffffff8b293aa4:	48 39 c3             	cmp    %rax,%rbx
ffffffff8b293aa7:	0f 85 d0 00 00 00    	jne    ffffffff8b293b7d <frame_candidate_8d3a70+0x10d>
ffffffff8b293aad:	48 8b 3d 7c 42 27 03 	mov    0x327427c(%rip),%rdi        # ffffffff8e507d30 <frame_candidate_8d4544+0x32737ec>
ffffffff8b293ab4:	e8 47 45 9e ff       	call   ffffffff8ac78000 <handler_617_body-0x61a570>
ffffffff8b293ab9:	4c 8d 15 78 42 27 03 	lea    0x3274278(%rip),%r10        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293ac0:	41 bb ff ff ff ff    	mov    $0xffffffff,%r11d
ffffffff8b293ac6:	be 00 00 04 00       	mov    $0x40000,%esi
ffffffff8b293acb:	48 89 c7             	mov    %rax,%rdi
ffffffff8b293ace:	31 d2                	xor    %edx,%edx
ffffffff8b293ad0:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
ffffffff8b293ad7:	49 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%r8
ffffffff8b293ade:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b293ae1:	41 52                	push   %r10
ffffffff8b293ae3:	6a 00                	push   $0x0
ffffffff8b293ae5:	6a 00                	push   $0x0
ffffffff8b293ae7:	6a 02                	push   $0x2
ffffffff8b293ae9:	41 53                	push   %r11
ffffffff8b293aeb:	6a 01                	push   $0x1
ffffffff8b293aed:	41 53                	push   %r11
ffffffff8b293aef:	6a 00                	push   $0x0
ffffffff8b293af1:	e8 8a 3b 34 00       	call   ffffffff8b5d7680 <frame_candidate_8d4544+0x34313c>
ffffffff8b293af6:	48 83 c4 40          	add    $0x40,%rsp
ffffffff8b293afa:	89 c3                	mov    %eax,%ebx
ffffffff8b293afc:	85 c0                	test   %eax,%eax
ffffffff8b293afe:	74 12                	je     ffffffff8b293b12 <frame_candidate_8d3a70+0xa2>
ffffffff8b293b00:	48 8d 3d 60 98 a1 00 	lea    0xa19860(%rip),%rdi        # ffffffff8bcad367 <frame_candidate_8d4544+0xa18e23>
ffffffff8b293b07:	89 de                	mov    %ebx,%esi
ffffffff8b293b09:	31 c0                	xor    %eax,%eax
ffffffff8b293b0b:	e8 00 99 98 ff       	call   ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b293b10:	eb 3c                	jmp    ffffffff8b293b4e <frame_candidate_8d3a70+0xde>
ffffffff8b293b12:	48 8d 3d 2f 42 27 03 	lea    0x327422f(%rip),%rdi        # ffffffff8e507d48 <frame_candidate_8d4544+0x3273804>
ffffffff8b293b19:	e8 62 04 00 00       	call   ffffffff8b293f80 <frame_candidate_8d3f80>
ffffffff8b293b1e:	48 8d 3d 43 42 27 03 	lea    0x3274243(%rip),%rdi        # ffffffff8e507d68 <frame_candidate_8d4544+0x3273824>
ffffffff8b293b25:	e8 56 04 00 00       	call   ffffffff8b293f80 <frame_candidate_8d3f80>
ffffffff8b293b2a:	48 8d 3d 57 42 27 03 	lea    0x3274257(%rip),%rdi        # ffffffff8e507d88 <frame_candidate_8d4544+0x3273844>
ffffffff8b293b31:	e8 4a 04 00 00       	call   ffffffff8b293f80 <frame_candidate_8d3f80>
ffffffff8b293b36:	48 8d 3d 6b 42 27 03 	lea    0x327426b(%rip),%rdi        # ffffffff8e507da8 <frame_candidate_8d4544+0x3273864>
ffffffff8b293b3d:	e8 3e 04 00 00       	call   ffffffff8b293f80 <frame_candidate_8d3f80>
ffffffff8b293b42:	48 8d 3d 7f 42 27 03 	lea    0x327427f(%rip),%rdi        # ffffffff8e507dc8 <frame_candidate_8d4544+0x3273884>
ffffffff8b293b49:	e8 32 04 00 00       	call   ffffffff8b293f80 <frame_candidate_8d3f80>
ffffffff8b293b4e:	89 d8                	mov    %ebx,%eax
ffffffff8b293b50:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b293b54:	5b                   	pop    %rbx
ffffffff8b293b55:	5d                   	pop    %rbp
ffffffff8b293b56:	c3                   	ret
ffffffff8b293b57:	e8 f4 dd f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293b5c:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b293b57 <frame_candidate_8d3a70+0xe7>
ffffffff8b293b63:	e8 a8 dc f1 ff       	call   ffffffff8b1b1810 <handler_617_body-0xe0d60>
ffffffff8b293b68:	48 8d 35 f9 35 a2 00 	lea    0xa235f9(%rip),%rsi        # ffffffff8bcb7168 <frame_candidate_8d4544+0xa22c24>
ffffffff8b293b6f:	bf 2f 00 00 00       	mov    $0x2f,%edi
ffffffff8b293b74:	31 c0                	xor    %eax,%eax
ffffffff8b293b76:	e8 95 6e 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293b7b:	0f 0b                	ud2
ffffffff8b293b7d:	e8 ce dd f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293b82:	48 8b 3d a7 41 27 03 	mov    0x32741a7(%rip),%rdi        # ffffffff8e507d30 <frame_candidate_8d4544+0x32737ec>
ffffffff8b293b89:	e8 42 00 9e ff       	call   ffffffff8ac73bd0 <handler_617_body-0x61e9a0>
ffffffff8b293b8e:	48 8d 3d e8 ff ff ff 	lea    -0x18(%rip),%rdi        # ffffffff8b293b7d <frame_candidate_8d3a70+0x10d>
ffffffff8b293b95:	48 89 c6             	mov    %rax,%rsi
ffffffff8b293b98:	e8 03 dd f1 ff       	call   ffffffff8b1b18a0 <handler_617_body-0xe0cd0>
ffffffff8b293b9d:	48 8b 3d 8c 41 27 03 	mov    0x327418c(%rip),%rdi        # ffffffff8e507d30 <frame_candidate_8d4544+0x32737ec>
ffffffff8b293ba4:	e8 27 00 9e ff       	call   ffffffff8ac73bd0 <handler_617_body-0x61e9a0>
ffffffff8b293ba9:	48 89 c2             	mov    %rax,%rdx
ffffffff8b293bac:	48 8d 35 2c 77 a7 00 	lea    0xa7772c(%rip),%rsi        # ffffffff8bd0b2df <frame_candidate_8d4544+0xa76d9b>
ffffffff8b293bb3:	bf 33 00 00 00       	mov    $0x33,%edi
ffffffff8b293bb8:	31 c0                	xor    %eax,%eax
ffffffff8b293bba:	e8 51 6e 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293bbf:	0f 0b                	ud2
ffffffff8b293bc1:	90                   	nop
ffffffff8b293bc2:	90                   	nop
ffffffff8b293bc3:	90                   	nop
ffffffff8b293bc4:	90                   	nop
ffffffff8b293bc5:	90                   	nop
ffffffff8b293bc6:	90                   	nop
ffffffff8b293bc7:	90                   	nop
ffffffff8b293bc8:	90                   	nop
ffffffff8b293bc9:	90                   	nop
ffffffff8b293bca:	90                   	nop
ffffffff8b293bcb:	90                   	nop
ffffffff8b293bcc:	90                   	nop
ffffffff8b293bcd:	90                   	nop
ffffffff8b293bce:	90                   	nop
ffffffff8b293bcf:	90                   	nop
ffffffff8b293bd0:	85 ff                	test   %edi,%edi
ffffffff8b293bd2:	78 01                	js     ffffffff8b293bd5 <frame_candidate_8d3bd5>
ffffffff8b293bd4:	c3                   	ret

ffffffff8b293bd5 <frame_candidate_8d3bd5>:
ffffffff8b293bd5:	55                   	push   %rbp
ffffffff8b293bd6:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293bd9:	53                   	push   %rbx
ffffffff8b293bda:	50                   	push   %rax
ffffffff8b293bdb:	89 fb                	mov    %edi,%ebx
ffffffff8b293bdd:	e8 6e dd f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293be2:	48 63 f3             	movslq %ebx,%rsi
ffffffff8b293be5:	48 8d 3d e9 ff ff ff 	lea    -0x17(%rip),%rdi        # ffffffff8b293bd5 <frame_candidate_8d3bd5>
ffffffff8b293bec:	e8 af dc f1 ff       	call   ffffffff8b1b18a0 <handler_617_body-0xe0cd0>
ffffffff8b293bf1:	48 8d 35 12 05 ac 00 	lea    0xac0512(%rip),%rsi        # ffffffff8bd5410a <frame_candidate_8d4544+0xabfbc6>
ffffffff8b293bf8:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8b293bfd:	89 da                	mov    %ebx,%edx
ffffffff8b293bff:	31 c0                	xor    %eax,%eax
ffffffff8b293c01:	e8 0a 6e 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293c06:	0f 0b                	ud2
ffffffff8b293c08:	90                   	nop
ffffffff8b293c09:	90                   	nop
ffffffff8b293c0a:	90                   	nop
ffffffff8b293c0b:	90                   	nop
ffffffff8b293c0c:	90                   	nop
ffffffff8b293c0d:	90                   	nop
ffffffff8b293c0e:	90                   	nop
ffffffff8b293c0f:	90                   	nop

ffffffff8b293c10 <frame_candidate_8d3c10>:
ffffffff8b293c10:	55                   	push   %rbp
ffffffff8b293c11:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293c14:	53                   	push   %rbx
ffffffff8b293c15:	50                   	push   %rax
ffffffff8b293c16:	31 ff                	xor    %edi,%edi
ffffffff8b293c18:	31 db                	xor    %ebx,%ebx
ffffffff8b293c1a:	e8 81 00 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b293c1f:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8b293c24:	e8 77 00 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b293c29:	bf 02 00 00 00       	mov    $0x2,%edi
ffffffff8b293c2e:	e8 6d 00 00 00       	call   ffffffff8b293ca0 <frame_candidate_8d3ca0>
ffffffff8b293c33:	48 8b 35 0e 41 27 03 	mov    0x327410e(%rip),%rsi        # ffffffff8e507d48 <frame_candidate_8d4544+0x3273804>
ffffffff8b293c3a:	48 85 f6             	test   %rsi,%rsi
ffffffff8b293c3d:	74 13                	je     ffffffff8b293c52 <frame_candidate_8d3c10+0x42>
ffffffff8b293c3f:	48 8b 3d f2 40 27 03 	mov    0x32740f2(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293c46:	e8 25 41 34 00       	call   ffffffff8b5d7d70 <frame_candidate_8d4544+0x34382c>
ffffffff8b293c4b:	48 8b 1d f6 40 27 03 	mov    0x32740f6(%rip),%rbx        # ffffffff8e507d48 <frame_candidate_8d4544+0x3273804>
ffffffff8b293c52:	48 8b 3d df 40 27 03 	mov    0x32740df(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293c59:	48 89 de             	mov    %rbx,%rsi
ffffffff8b293c5c:	e8 6f 3c 34 00       	call   ffffffff8b5d78d0 <frame_candidate_8d4544+0x34338c>
ffffffff8b293c61:	48 8b 3d e8 40 27 03 	mov    0x32740e8(%rip),%rdi        # ffffffff8e507d50 <frame_candidate_8d4544+0x327380c>
ffffffff8b293c68:	48 8b 35 f1 40 27 03 	mov    0x32740f1(%rip),%rsi        # ffffffff8e507d60 <frame_candidate_8d4544+0x327381c>
ffffffff8b293c6f:	48 8d 15 da 7d c7 01 	lea    0x1c77dda(%rip),%rdx        # ffffffff8cf0ba50 <frame_candidate_8d4544+0x1c7750c>
ffffffff8b293c76:	e8 d5 4d 33 00       	call   ffffffff8b5c8a50 <frame_candidate_8d4544+0x33450c>
ffffffff8b293c7b:	48 8b 3d b6 40 27 03 	mov    0x32740b6(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293c82:	e8 99 3b 34 00       	call   ffffffff8b5d7820 <frame_candidate_8d4544+0x3432dc>
ffffffff8b293c87:	c6 05 b2 40 27 03 00 	movb   $0x0,0x32740b2(%rip)        # ffffffff8e507d40 <frame_candidate_8d4544+0x32737fc>
ffffffff8b293c8e:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b293c92:	5b                   	pop    %rbx
ffffffff8b293c93:	5d                   	pop    %rbp
ffffffff8b293c94:	c3                   	ret
ffffffff8b293c95:	90                   	nop
ffffffff8b293c96:	90                   	nop
ffffffff8b293c97:	90                   	nop
ffffffff8b293c98:	90                   	nop
ffffffff8b293c99:	90                   	nop
ffffffff8b293c9a:	90                   	nop
ffffffff8b293c9b:	90                   	nop
ffffffff8b293c9c:	90                   	nop
ffffffff8b293c9d:	90                   	nop
ffffffff8b293c9e:	90                   	nop
ffffffff8b293c9f:	90                   	nop

ffffffff8b293ca0 <frame_candidate_8d3ca0>:
ffffffff8b293ca0:	55                   	push   %rbp
ffffffff8b293ca1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293ca4:	41 57                	push   %r15
ffffffff8b293ca6:	41 56                	push   %r14
ffffffff8b293ca8:	41 54                	push   %r12
ffffffff8b293caa:	53                   	push   %rbx
ffffffff8b293cab:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8b293caf:	89 fb                	mov    %edi,%ebx
ffffffff8b293cb1:	e8 1a ff ff ff       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b293cb6:	48 63 c3             	movslq %ebx,%rax
ffffffff8b293cb9:	48 8d 0d 90 7c c7 01 	lea    0x1c77c90(%rip),%rcx        # ffffffff8cf0b950 <frame_candidate_8d4544+0x1c7740c>
ffffffff8b293cc0:	bb 00 00 50 02       	mov    $0x2500000,%ebx
ffffffff8b293cc5:	48 c1 e0 06          	shl    $0x6,%rax
ffffffff8b293cc9:	8b 3c 08             	mov    (%rax,%rcx,1),%edi
ffffffff8b293ccc:	4c 8d 24 01          	lea    (%rcx,%rax,1),%r12
ffffffff8b293cd0:	01 df                	add    %ebx,%edi
ffffffff8b293cd2:	e8 49 c5 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293cd7:	89 45 dc             	mov    %eax,-0x24(%rbp)
ffffffff8b293cda:	8b 45 dc             	mov    -0x24(%rbp),%eax
ffffffff8b293cdd:	a8 02                	test   $0x2,%al
ffffffff8b293cdf:	75 42                	jne    ffffffff8b293d23 <frame_candidate_8d3ca0+0x83>
ffffffff8b293ce1:	41 8b 7c 24 04       	mov    0x4(%r12),%edi
ffffffff8b293ce6:	01 df                	add    %ebx,%edi
ffffffff8b293ce8:	e8 33 c5 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293ced:	41 8b 7c 24 08       	mov    0x8(%r12),%edi
ffffffff8b293cf2:	41 89 c6             	mov    %eax,%r14d
ffffffff8b293cf5:	01 df                	add    %ebx,%edi
ffffffff8b293cf7:	e8 24 c5 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293cfc:	83 65 dc fe          	andl   $0xfffffffe,-0x24(%rbp)
ffffffff8b293d00:	41 89 c7             	mov    %eax,%r15d
ffffffff8b293d03:	83 4d dc 02          	orl    $0x2,-0x24(%rbp)
ffffffff8b293d07:	41 03 1c 24          	add    (%r12),%ebx
ffffffff8b293d0b:	8b 75 dc             	mov    -0x24(%rbp),%esi
ffffffff8b293d0e:	89 df                	mov    %ebx,%edi
ffffffff8b293d10:	e8 5b c6 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293d15:	45 39 fe             	cmp    %r15d,%r14d
ffffffff8b293d18:	74 23                	je     ffffffff8b293d3d <frame_candidate_8d3ca0+0x9d>
ffffffff8b293d1a:	41 8b 7c 24 20       	mov    0x20(%r12),%edi
ffffffff8b293d1f:	31 f6                	xor    %esi,%esi
ffffffff8b293d21:	eb 0f                	jmp    ffffffff8b293d32 <frame_candidate_8d3ca0+0x92>
ffffffff8b293d23:	83 65 dc fe          	andl   $0xfffffffe,-0x24(%rbp)
ffffffff8b293d27:	83 4d dc 02          	orl    $0x2,-0x24(%rbp)
ffffffff8b293d2b:	41 8b 3c 24          	mov    (%r12),%edi
ffffffff8b293d2f:	8b 75 dc             	mov    -0x24(%rbp),%esi
ffffffff8b293d32:	81 c7 00 00 50 02    	add    $0x2500000,%edi
ffffffff8b293d38:	e8 33 c6 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293d3d:	bb 00 00 50 02       	mov    $0x2500000,%ebx
ffffffff8b293d42:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b293d49:	1f 84 00 00 00 00 00 
ffffffff8b293d50:	41 8b 3c 24          	mov    (%r12),%edi
ffffffff8b293d54:	01 df                	add    %ebx,%edi
ffffffff8b293d56:	e8 c5 c4 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293d5b:	89 45 dc             	mov    %eax,-0x24(%rbp)
ffffffff8b293d5e:	8b 45 dc             	mov    -0x24(%rbp),%eax
ffffffff8b293d61:	a8 02                	test   $0x2,%al
ffffffff8b293d63:	74 eb                	je     ffffffff8b293d50 <frame_candidate_8d3ca0+0xb0>
ffffffff8b293d65:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b293d69:	5b                   	pop    %rbx
ffffffff8b293d6a:	41 5c                	pop    %r12
ffffffff8b293d6c:	41 5e                	pop    %r14
ffffffff8b293d6e:	41 5f                	pop    %r15
ffffffff8b293d70:	5d                   	pop    %rbp
ffffffff8b293d71:	c3                   	ret
ffffffff8b293d72:	90                   	nop
ffffffff8b293d73:	90                   	nop
ffffffff8b293d74:	90                   	nop
ffffffff8b293d75:	90                   	nop
ffffffff8b293d76:	90                   	nop
ffffffff8b293d77:	90                   	nop
ffffffff8b293d78:	90                   	nop
ffffffff8b293d79:	90                   	nop
ffffffff8b293d7a:	90                   	nop
ffffffff8b293d7b:	90                   	nop
ffffffff8b293d7c:	90                   	nop
ffffffff8b293d7d:	90                   	nop
ffffffff8b293d7e:	90                   	nop
ffffffff8b293d7f:	90                   	nop

ffffffff8b293d80 <frame_candidate_8d3d80>:
ffffffff8b293d80:	55                   	push   %rbp
ffffffff8b293d81:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293d84:	53                   	push   %rbx
ffffffff8b293d85:	50                   	push   %rax
ffffffff8b293d86:	85 c9                	test   %ecx,%ecx
ffffffff8b293d88:	75 13                	jne    ffffffff8b293d9d <frame_candidate_8d3d80+0x1d>
ffffffff8b293d8a:	83 fa 01             	cmp    $0x1,%edx
ffffffff8b293d8d:	75 32                	jne    ffffffff8b293dc1 <frame_candidate_8d3d80+0x41>
ffffffff8b293d8f:	48 8b 06             	mov    (%rsi),%rax
ffffffff8b293d92:	48 89 47 10          	mov    %rax,0x10(%rdi)
ffffffff8b293d96:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b293d9a:	5b                   	pop    %rbx
ffffffff8b293d9b:	5d                   	pop    %rbp
ffffffff8b293d9c:	c3                   	ret
ffffffff8b293d9d:	89 cb                	mov    %ecx,%ebx
ffffffff8b293d9f:	e8 ac db f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293da4:	48 63 f3             	movslq %ebx,%rsi
ffffffff8b293da7:	48 8d 3d ef ff ff ff 	lea    -0x11(%rip),%rdi        # ffffffff8b293d9d <frame_candidate_8d3d80+0x1d>
ffffffff8b293dae:	e8 ed da f1 ff       	call   ffffffff8b1b18a0 <handler_617_body-0xe0cd0>
ffffffff8b293db3:	48 8d 35 f8 d7 a4 00 	lea    0xa4d7f8(%rip),%rsi        # ffffffff8bce15b2 <frame_candidate_8d4544+0xa4d06e>
ffffffff8b293dba:	bf 23 00 00 00       	mov    $0x23,%edi
ffffffff8b293dbf:	eb 22                	jmp    ffffffff8b293de3 <frame_candidate_8d3d80+0x63>
ffffffff8b293dc1:	89 d3                	mov    %edx,%ebx
ffffffff8b293dc3:	e8 88 db f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293dc8:	48 63 f3             	movslq %ebx,%rsi
ffffffff8b293dcb:	48 8d 3d ef ff ff ff 	lea    -0x11(%rip),%rdi        # ffffffff8b293dc1 <frame_candidate_8d3d80+0x41>
ffffffff8b293dd2:	e8 c9 da f1 ff       	call   ffffffff8b1b18a0 <handler_617_body-0xe0cd0>
ffffffff8b293dd7:	48 8d 35 91 7e a5 00 	lea    0xa57e91(%rip),%rsi        # ffffffff8bcebc6f <frame_candidate_8d4544+0xa5772b>
ffffffff8b293dde:	bf 27 00 00 00       	mov    $0x27,%edi
ffffffff8b293de3:	89 da                	mov    %ebx,%edx
ffffffff8b293de5:	31 c0                	xor    %eax,%eax
ffffffff8b293de7:	e8 24 6c 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293dec:	0f 0b                	ud2
ffffffff8b293dee:	90                   	nop
ffffffff8b293def:	90                   	nop

ffffffff8b293df0 <frame_candidate_8d3df0>:
ffffffff8b293df0:	55                   	push   %rbp
ffffffff8b293df1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293df4:	41 57                	push   %r15
ffffffff8b293df6:	41 56                	push   %r14
ffffffff8b293df8:	53                   	push   %rbx
ffffffff8b293df9:	50                   	push   %rax
ffffffff8b293dfa:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b293dfd:	41 89 fe             	mov    %edi,%r14d
ffffffff8b293e00:	e8 cb fd ff ff       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b293e05:	45 89 f7             	mov    %r14d,%r15d
ffffffff8b293e08:	4c 8d 35 41 7b c7 01 	lea    0x1c77b41(%rip),%r14        # ffffffff8cf0b950 <frame_candidate_8d4544+0x1c7740c>
ffffffff8b293e0f:	bf 00 00 50 02       	mov    $0x2500000,%edi
ffffffff8b293e14:	49 c1 e7 06          	shl    $0x6,%r15
ffffffff8b293e18:	43 03 3c 37          	add    (%r15,%r14,1),%edi
ffffffff8b293e1c:	e8 ff c3 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293e21:	89 45 e4             	mov    %eax,-0x1c(%rbp)
ffffffff8b293e24:	8b 45 e4             	mov    -0x1c(%rbp),%eax
ffffffff8b293e27:	a8 04                	test   $0x4,%al
ffffffff8b293e29:	75 73                	jne    ffffffff8b293e9e <frame_candidate_8d3df0+0xae>
ffffffff8b293e2b:	4d 01 fe             	add    %r15,%r14
ffffffff8b293e2e:	ba 20 00 00 00       	mov    $0x20,%edx
ffffffff8b293e33:	48 89 de             	mov    %rbx,%rsi
ffffffff8b293e36:	41 8b 7e 28          	mov    0x28(%r14),%edi
ffffffff8b293e3a:	49 03 7e 38          	add    0x38(%r14),%rdi
ffffffff8b293e3e:	41 8b 46 30          	mov    0x30(%r14),%eax
ffffffff8b293e42:	48 29 c7             	sub    %rax,%rdi
ffffffff8b293e45:	e8 66 52 98 ff       	call   ffffffff8ac190b0 <handler_617_body-0x6794c0>
ffffffff8b293e4a:	41 8b 76 28          	mov    0x28(%r14),%esi
ffffffff8b293e4e:	b9 40 00 00 00       	mov    $0x40,%ecx
ffffffff8b293e53:	83 c6 20             	add    $0x20,%esi
ffffffff8b293e56:	41 89 76 28          	mov    %esi,0x28(%r14)
ffffffff8b293e5a:	8b 45 e4             	mov    -0x1c(%rbp),%eax
ffffffff8b293e5d:	c0 e8 03             	shr    $0x3,%al
ffffffff8b293e60:	24 0f                	and    $0xf,%al
ffffffff8b293e62:	c4 e2 79 f7 c1       	shlx   %eax,%ecx,%eax
ffffffff8b293e67:	8d 48 ff             	lea    -0x1(%rax),%ecx
ffffffff8b293e6a:	85 f1                	test   %esi,%ecx
ffffffff8b293e6c:	75 06                	jne    ffffffff8b293e74 <frame_candidate_8d3df0+0x84>
ffffffff8b293e6e:	29 c6                	sub    %eax,%esi
ffffffff8b293e70:	41 89 76 28          	mov    %esi,0x28(%r14)
ffffffff8b293e74:	bf 00 00 50 02       	mov    $0x2500000,%edi
ffffffff8b293e79:	41 03 7e 08          	add    0x8(%r14),%edi
ffffffff8b293e7d:	e8 ee c4 3a 00       	call   ffffffff8b640370 <frame_candidate_8d4544+0x3abe2c>
ffffffff8b293e82:	41 8b 46 24          	mov    0x24(%r14),%eax
ffffffff8b293e86:	89 c1                	mov    %eax,%ecx
ffffffff8b293e88:	ff c1                	inc    %ecx
ffffffff8b293e8a:	66 41 89 4e 24       	mov    %cx,0x24(%r14)
ffffffff8b293e8f:	41 ff 46 2c          	incl   0x2c(%r14)
ffffffff8b293e93:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b293e97:	5b                   	pop    %rbx
ffffffff8b293e98:	41 5e                	pop    %r14
ffffffff8b293e9a:	41 5f                	pop    %r15
ffffffff8b293e9c:	5d                   	pop    %rbp
ffffffff8b293e9d:	c3                   	ret
ffffffff8b293e9e:	e8 ad da f1 ff       	call   ffffffff8b1b1950 <handler_617_body-0xe0c20>
ffffffff8b293ea3:	8b 75 e4             	mov    -0x1c(%rbp),%esi
ffffffff8b293ea6:	48 8d 3d f1 ff ff ff 	lea    -0xf(%rip),%rdi        # ffffffff8b293e9e <frame_candidate_8d3df0+0xae>
ffffffff8b293ead:	e8 ee d9 f1 ff       	call   ffffffff8b1b18a0 <handler_617_body-0xe0cd0>
ffffffff8b293eb2:	8b 55 e4             	mov    -0x1c(%rbp),%edx
ffffffff8b293eb5:	48 8d 35 96 32 a2 00 	lea    0xa23296(%rip),%rsi        # ffffffff8bcb7152 <frame_candidate_8d4544+0xa22c0e>
ffffffff8b293ebc:	bf 1f 00 00 00       	mov    $0x1f,%edi
ffffffff8b293ec1:	31 c0                	xor    %eax,%eax
ffffffff8b293ec3:	e8 48 6b 3c 00       	call   ffffffff8b65aa10 <frame_candidate_8d4544+0x3c64cc>
ffffffff8b293ec8:	0f 0b                	ud2
ffffffff8b293eca:	90                   	nop
ffffffff8b293ecb:	90                   	nop
ffffffff8b293ecc:	90                   	nop
ffffffff8b293ecd:	90                   	nop
ffffffff8b293ece:	90                   	nop
ffffffff8b293ecf:	90                   	nop

ffffffff8b293ed0 <frame_candidate_8d3ed0>:
ffffffff8b293ed0:	55                   	push   %rbp
ffffffff8b293ed1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293ed4:	41 57                	push   %r15
ffffffff8b293ed6:	41 56                	push   %r14
ffffffff8b293ed8:	41 55                	push   %r13
ffffffff8b293eda:	41 54                	push   %r12
ffffffff8b293edc:	53                   	push   %rbx
ffffffff8b293edd:	50                   	push   %rax
ffffffff8b293ede:	89 fb                	mov    %edi,%ebx
ffffffff8b293ee0:	e8 eb fc ff ff       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b293ee5:	41 89 dd             	mov    %ebx,%r13d
ffffffff8b293ee8:	89 df                	mov    %ebx,%edi
ffffffff8b293eea:	0f 31                	rdtsc
ffffffff8b293eec:	4c 8d 3d 5d 7a c7 01 	lea    0x1c77a5d(%rip),%r15        # ffffffff8cf0b950 <frame_candidate_8d4544+0x1c7740c>
ffffffff8b293ef3:	49 c1 e5 06          	shl    $0x6,%r13
ffffffff8b293ef7:	e8 d4 fc ff ff       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b293efc:	43 8b 7c 3d 04       	mov    0x4(%r13,%r15,1),%edi
ffffffff8b293f01:	41 bc 00 00 50 02    	mov    $0x2500000,%r12d
ffffffff8b293f07:	44 01 e7             	add    %r12d,%edi
ffffffff8b293f0a:	e8 11 c3 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293f0f:	45 31 f6             	xor    %r14d,%r14d
ffffffff8b293f12:	43 39 44 3d 28       	cmp    %eax,0x28(%r13,%r15,1)
ffffffff8b293f17:	74 53                	je     ffffffff8b293f6c <frame_candidate_8d3ed0+0x9c>
ffffffff8b293f19:	4d 01 ef             	add    %r13,%r15
ffffffff8b293f1c:	eb 1b                	jmp    ffffffff8b293f39 <frame_candidate_8d3ed0+0x69>
ffffffff8b293f1e:	66 90                	xchg   %ax,%ax
ffffffff8b293f20:	89 df                	mov    %ebx,%edi
ffffffff8b293f22:	e8 a9 fc ff ff       	call   ffffffff8b293bd0 <frame_candidate_8d3a70+0x160>
ffffffff8b293f27:	41 8b 7f 04          	mov    0x4(%r15),%edi
ffffffff8b293f2b:	44 01 e7             	add    %r12d,%edi
ffffffff8b293f2e:	e8 ed c2 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293f33:	41 39 47 28          	cmp    %eax,0x28(%r15)
ffffffff8b293f37:	74 33                	je     ffffffff8b293f6c <frame_candidate_8d3ed0+0x9c>
ffffffff8b293f39:	41 8b 7f 1c          	mov    0x1c(%r15),%edi
ffffffff8b293f3d:	44 01 e7             	add    %r12d,%edi
ffffffff8b293f40:	e8 db c2 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293f45:	89 45 d4             	mov    %eax,-0x2c(%rbp)
ffffffff8b293f48:	41 8b 3f             	mov    (%r15),%edi
ffffffff8b293f4b:	44 01 e7             	add    %r12d,%edi
ffffffff8b293f4e:	e8 cd c2 3a 00       	call   ffffffff8b640220 <frame_candidate_8d4544+0x3abcdc>
ffffffff8b293f53:	89 45 d0             	mov    %eax,-0x30(%rbp)
ffffffff8b293f56:	8b 45 d0             	mov    -0x30(%rbp),%eax
ffffffff8b293f59:	a8 02                	test   $0x2,%al
ffffffff8b293f5b:	74 c3                	je     ffffffff8b293f20 <frame_candidate_8d3ed0+0x50>
ffffffff8b293f5d:	8b 45 d4             	mov    -0x2c(%rbp),%eax
ffffffff8b293f60:	a8 7f                	test   $0x7f,%al
ffffffff8b293f62:	74 bc                	je     ffffffff8b293f20 <frame_candidate_8d3ed0+0x50>
ffffffff8b293f64:	44 8b 75 d4          	mov    -0x2c(%rbp),%r14d
ffffffff8b293f68:	41 83 e6 7f          	and    $0x7f,%r14d
ffffffff8b293f6c:	44 89 f0             	mov    %r14d,%eax
ffffffff8b293f6f:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b293f73:	5b                   	pop    %rbx
ffffffff8b293f74:	41 5c                	pop    %r12
ffffffff8b293f76:	41 5d                	pop    %r13
ffffffff8b293f78:	41 5e                	pop    %r14
ffffffff8b293f7a:	41 5f                	pop    %r15
ffffffff8b293f7c:	5d                   	pop    %rbp
ffffffff8b293f7d:	c3                   	ret
ffffffff8b293f7e:	90                   	nop
ffffffff8b293f7f:	90                   	nop

ffffffff8b293f80 <frame_candidate_8d3f80>:
ffffffff8b293f80:	55                   	push   %rbp
ffffffff8b293f81:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b293f84:	53                   	push   %rbx
ffffffff8b293f85:	50                   	push   %rax
ffffffff8b293f86:	48 c7 47 18 00 00 04 	movq   $0x40000,0x18(%rdi)
ffffffff8b293f8d:	00 
ffffffff8b293f8e:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b293f91:	48 8d 35 b8 7a c7 01 	lea    0x1c77ab8(%rip),%rsi        # ffffffff8cf0ba50 <frame_candidate_8d4544+0x1c7750c>
ffffffff8b293f98:	bf 00 00 04 00       	mov    $0x40000,%edi
ffffffff8b293f9d:	41 b9 00 00 04 00    	mov    $0x40000,%r9d
ffffffff8b293fa3:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8b293fa8:	49 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%r8
ffffffff8b293faf:	31 c9                	xor    %ecx,%ecx
ffffffff8b293fb1:	48 c7 04 24 00 00 00 	movq   $0x0,(%rsp)
ffffffff8b293fb8:	00 
ffffffff8b293fb9:	e8 52 49 33 00       	call   ffffffff8b5c8910 <frame_candidate_8d4544+0x3343cc>
ffffffff8b293fbe:	48 89 43 08          	mov    %rax,0x8(%rbx)
ffffffff8b293fc2:	48 89 da             	mov    %rbx,%rdx
ffffffff8b293fc5:	31 f6                	xor    %esi,%esi
ffffffff8b293fc7:	48 8b 3d 6a 3d 27 03 	mov    0x3273d6a(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293fce:	e8 9d 38 34 00       	call   ffffffff8b5d7870 <frame_candidate_8d4544+0x34332c>
ffffffff8b293fd3:	85 c0                	test   %eax,%eax
ffffffff8b293fd5:	74 09                	je     ffffffff8b293fe0 <frame_candidate_8d3f80+0x60>
ffffffff8b293fd7:	48 8d 3d a8 5d ab 00 	lea    0xab5da8(%rip),%rdi        # ffffffff8bd49d86 <frame_candidate_8d4544+0xab5842>
ffffffff8b293fde:	eb 34                	jmp    ffffffff8b294014 <frame_candidate_8d3f80+0x94>
ffffffff8b293fe0:	48 8b 3d 51 3d 27 03 	mov    0x3273d51(%rip),%rdi        # ffffffff8e507d38 <frame_candidate_8d4544+0x32737f4>
ffffffff8b293fe7:	48 8b 33             	mov    (%rbx),%rsi
ffffffff8b293fea:	48 8b 53 08          	mov    0x8(%rbx),%rdx
ffffffff8b293fee:	4c 8d 05 f3 52 99 ff 	lea    -0x66ad0d(%rip),%r8        # ffffffff8ac292e8 <handler_617_body-0x669288>
ffffffff8b293ff5:	b9 00 00 04 00       	mov    $0x40000,%ecx
ffffffff8b293ffa:	49 89 d9             	mov    %rbx,%r9
ffffffff8b293ffd:	c7 04 24 00 00 00 00 	movl   $0x0,(%rsp)
ffffffff8b294004:	e8 07 fe 08 00       	call   ffffffff8b323e10 <frame_candidate_8d4544+0x8f8cc>
ffffffff8b294009:	85 c0                	test   %eax,%eax
ffffffff8b29400b:	74 16                	je     ffffffff8b294023 <frame_candidate_8d3f80+0xa3>
ffffffff8b29400d:	48 8d 3d d4 00 ac 00 	lea    0xac00d4(%rip),%rdi        # ffffffff8bd540e8 <frame_candidate_8d4544+0xabfba4>
ffffffff8b294014:	89 c6                	mov    %eax,%esi
ffffffff8b294016:	31 c0                	xor    %eax,%eax
ffffffff8b294018:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b29401c:	5b                   	pop    %rbx
ffffffff8b29401d:	5d                   	pop    %rbp
ffffffff8b29401e:	e9 ed 93 98 ff       	jmp    ffffffff8ac1d410 <handler_617_body-0x675160>
ffffffff8b294023:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b294027:	5b                   	pop    %rbx
ffffffff8b294028:	5d                   	pop    %rbp
ffffffff8b294029:	c3                   	ret
ffffffff8b29402a:	90                   	nop
ffffffff8b29402b:	90                   	nop
ffffffff8b29402c:	90                   	nop
ffffffff8b29402d:	90                   	nop
ffffffff8b29402e:	90                   	nop
ffffffff8b29402f:	90                   	nop

ffffffff8b294030 <frame_candidate_8d4030>:
ffffffff8b294030:	55                   	push   %rbp
ffffffff8b294031:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b294034:	41 57                	push   %r15
ffffffff8b294036:	41 56                	push   %r14
ffffffff8b294038:	41 55                	push   %r13
ffffffff8b29403a:	41 54                	push   %r12
ffffffff8b29403c:	53                   	push   %rbx
ffffffff8b29403d:	50                   	push   %rax
ffffffff8b29403e:	41 bd d8 4f 07 00    	mov    $0x74fd8,%r13d
ffffffff8b294044:	48 8d 1d 85 12 99 ff 	lea    -0x66ed7b(%rip),%rbx        # ffffffff8ac252d0 <handler_617_body-0x66d2a0>
ffffffff8b29404b:	41 bc f0 4f 07 00    	mov    $0x74ff0,%r12d
ffffffff8b294051:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b294058:	0f 1f 84 00 00 00 00 
ffffffff8b29405f:	00 
ffffffff8b294060:	48 8b 0d 11 ef 1a 03 	mov    0x31aef11(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294067:	48 8b 81 e8 4f 07 00 	mov    0x74fe8(%rcx),%rax
ffffffff8b29406e:	48 85 c0             	test   %rax,%rax
ffffffff8b294071:	0f 84 13 01 00 00    	je     ffffffff8b29418a <frame_candidate_8d4030+0x15a>
ffffffff8b294077:	48 81 c1 e8 4f 07 00 	add    $0x74fe8,%rcx
ffffffff8b29407e:	48 89 ca             	mov    %rcx,%rdx
ffffffff8b294081:	eb 66                	jmp    ffffffff8b2940e9 <frame_candidate_8d4030+0xb9>
ffffffff8b294083:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b29408a:	84 00 00 00 00 00 
ffffffff8b294090:	48 8b 15 e1 ee 1a 03 	mov    0x31aeee1(%rip),%rdx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294097:	48 8b 8a e0 4f 07 00 	mov    0x74fe0(%rdx),%rcx
ffffffff8b29409e:	48 89 48 08          	mov    %rcx,0x8(%rax)
ffffffff8b2940a2:	48 8b 15 cf ee 1a 03 	mov    0x31aeecf(%rip),%rdx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2940a9:	4c 01 ea             	add    %r13,%rdx
ffffffff8b2940ac:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2940af:	48 0f 45 d1          	cmovne %rcx,%rdx
ffffffff8b2940b3:	48 89 02             	mov    %rax,(%rdx)
ffffffff8b2940b6:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
ffffffff8b2940bd:	48 8b 0d b4 ee 1a 03 	mov    0x31aeeb4(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2940c4:	48 89 81 e0 4f 07 00 	mov    %rax,0x74fe0(%rcx)
ffffffff8b2940cb:	48 8b 0d a6 ee 1a 03 	mov    0x31aeea6(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2940d2:	48 8b 81 e8 4f 07 00 	mov    0x74fe8(%rcx),%rax
ffffffff8b2940d9:	48 8d 91 e8 4f 07 00 	lea    0x74fe8(%rcx),%rdx
ffffffff8b2940e0:	48 85 c0             	test   %rax,%rax
ffffffff8b2940e3:	0f 84 a1 00 00 00    	je     ffffffff8b29418a <frame_candidate_8d4030+0x15a>
ffffffff8b2940e9:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2940ec:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2940ef:	48 8d 51 08          	lea    0x8(%rcx),%rdx
ffffffff8b2940f3:	48 8b 35 7e ee 1a 03 	mov    0x31aee7e(%rip),%rsi        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2940fa:	4c 01 e6             	add    %r12,%rsi
ffffffff8b2940fd:	48 85 c9             	test   %rcx,%rcx
ffffffff8b294100:	48 0f 45 f2          	cmovne %rdx,%rsi
ffffffff8b294104:	48 c7 06 00 00 00 00 	movq   $0x0,(%rsi)
ffffffff8b29410b:	48 8b 15 66 ee 1a 03 	mov    0x31aee66(%rip),%rdx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294112:	48 8b 8a d8 4f 07 00 	mov    0x74fd8(%rdx),%rcx
ffffffff8b294119:	48 85 c9             	test   %rcx,%rcx
ffffffff8b29411c:	0f 84 75 ff ff ff    	je     ffffffff8b294097 <frame_candidate_8d4030+0x67>
ffffffff8b294122:	48 8b 50 20          	mov    0x20(%rax),%rdx
ffffffff8b294126:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b29412d:	00 00 00 
ffffffff8b294130:	48 8b 71 20          	mov    0x20(%rcx),%rsi
ffffffff8b294134:	48 89 f7             	mov    %rsi,%rdi
ffffffff8b294137:	48 29 d7             	sub    %rdx,%rdi
ffffffff8b29413a:	7d 14                	jge    ffffffff8b294150 <frame_candidate_8d4030+0x120>
ffffffff8b29413c:	48 29 f2             	sub    %rsi,%rdx
ffffffff8b29413f:	48 89 50 20          	mov    %rdx,0x20(%rax)
ffffffff8b294143:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8b294146:	48 85 c9             	test   %rcx,%rcx
ffffffff8b294149:	75 e5                	jne    ffffffff8b294130 <frame_candidate_8d4030+0x100>
ffffffff8b29414b:	e9 40 ff ff ff       	jmp    ffffffff8b294090 <frame_candidate_8d4030+0x60>
ffffffff8b294150:	48 89 79 20          	mov    %rdi,0x20(%rcx)
ffffffff8b294154:	48 8b 51 08          	mov    0x8(%rcx),%rdx
ffffffff8b294158:	48 89 50 08          	mov    %rdx,0x8(%rax)
ffffffff8b29415c:	48 8b 35 15 ee 1a 03 	mov    0x31aee15(%rip),%rsi        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294163:	4c 01 ee             	add    %r13,%rsi
ffffffff8b294166:	48 85 d2             	test   %rdx,%rdx
ffffffff8b294169:	48 0f 45 f2          	cmovne %rdx,%rsi
ffffffff8b29416d:	48 89 06             	mov    %rax,(%rsi)
ffffffff8b294170:	48 89 08             	mov    %rcx,(%rax)
ffffffff8b294173:	48 89 41 08          	mov    %rax,0x8(%rcx)
ffffffff8b294177:	e9 4f ff ff ff       	jmp    ffffffff8b2940cb <frame_candidate_8d4030+0x9b>
ffffffff8b29417c:	0f 1f 40 00          	nopl   0x0(%rax)
ffffffff8b294180:	41 ff d6             	call   *%r14
ffffffff8b294183:	48 8b 0d ee ed 1a 03 	mov    0x31aedee(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b29418a:	48 8b 81 d8 4f 07 00 	mov    0x74fd8(%rcx),%rax
ffffffff8b294191:	48 85 c0             	test   %rax,%rax
ffffffff8b294194:	0f 84 b6 00 00 00    	je     ffffffff8b294250 <frame_candidate_8d4030+0x220>
ffffffff8b29419a:	48 83 78 20 00       	cmpq   $0x0,0x20(%rax)
ffffffff8b29419f:	0f 8f ab 00 00 00    	jg     ffffffff8b294250 <frame_candidate_8d4030+0x220>
ffffffff8b2941a5:	4c 8b 70 10          	mov    0x10(%rax),%r14
ffffffff8b2941a9:	48 8b 78 18          	mov    0x18(%rax),%rdi
ffffffff8b2941ad:	48 8b 50 28          	mov    0x28(%rax),%rdx
ffffffff8b2941b1:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2941b4:	74 0d                	je     ffffffff8b2941c3 <frame_candidate_8d4030+0x193>
ffffffff8b2941b6:	c7 02 00 00 00 00    	movl   $0x0,(%rdx)
ffffffff8b2941bc:	48 8b 0d b5 ed 1a 03 	mov    0x31aedb5(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2941c3:	48 8b 10             	mov    (%rax),%rdx
ffffffff8b2941c6:	48 8b 70 08          	mov    0x8(%rax),%rsi
ffffffff8b2941ca:	48 81 c1 e0 4f 07 00 	add    $0x74fe0,%rcx
ffffffff8b2941d1:	4c 8d 42 08          	lea    0x8(%rdx),%r8
ffffffff8b2941d5:	48 85 d2             	test   %rdx,%rdx
ffffffff8b2941d8:	49 0f 45 c8          	cmovne %r8,%rcx
ffffffff8b2941dc:	48 89 31             	mov    %rsi,(%rcx)
ffffffff8b2941df:	48 8b 15 92 ed 1a 03 	mov    0x31aed92(%rip),%rdx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2941e6:	48 8b 08             	mov    (%rax),%rcx
ffffffff8b2941e9:	4c 01 ea             	add    %r13,%rdx
ffffffff8b2941ec:	48 85 f6             	test   %rsi,%rsi
ffffffff8b2941ef:	48 0f 45 d6          	cmovne %rsi,%rdx
ffffffff8b2941f3:	48 89 0a             	mov    %rcx,(%rdx)
ffffffff8b2941f6:	48 8b 0d 7b ed 1a 03 	mov    0x31aed7b(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2941fd:	48 8b 89 d0 4f 07 00 	mov    0x74fd0(%rcx),%rcx
ffffffff8b294204:	48 89 08             	mov    %rcx,(%rax)
ffffffff8b294207:	48 8b 0d 6a ed 1a 03 	mov    0x31aed6a(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b29420e:	48 89 81 d0 4f 07 00 	mov    %rax,0x74fd0(%rcx)
ffffffff8b294215:	4d 85 f6             	test   %r14,%r14
ffffffff8b294218:	0f 84 65 ff ff ff    	je     ffffffff8b294183 <frame_candidate_8d4030+0x153>
ffffffff8b29421e:	48 89 d8             	mov    %rbx,%rax
ffffffff8b294221:	4c 29 f0             	sub    %r14,%rax
ffffffff8b294224:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b294228:	48 3d bc 08 00 00    	cmp    $0x8bc,%rax
ffffffff8b29422e:	0f 86 4c ff ff ff    	jbe    ffffffff8b294180 <frame_candidate_8d4030+0x150>
ffffffff8b294234:	49 89 ff             	mov    %rdi,%r15
ffffffff8b294237:	48 8d 3d 82 78 c7 01 	lea    0x1c77882(%rip),%rdi        # ffffffff8cf0bac0 <frame_candidate_8d4544+0x1c7757c>
ffffffff8b29423e:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b294241:	e8 7a b6 b7 ff       	call   ffffffff8ae0f8c0 <handler_617_body-0x482cb0>
ffffffff8b294246:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b294249:	e9 32 ff ff ff       	jmp    ffffffff8b294180 <frame_candidate_8d4030+0x150>
ffffffff8b29424e:	66 90                	xchg   %ax,%ax
ffffffff8b294250:	e8 8b 1e b9 ff       	call   ffffffff8ae260e0 <handler_617_body-0x46c490>
ffffffff8b294255:	48 8b 0d 1c ed 1a 03 	mov    0x31aed1c(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b29425c:	49 89 c6             	mov    %rax,%r14
ffffffff8b29425f:	48 8b 81 d8 4f 07 00 	mov    0x74fd8(%rcx),%rax
ffffffff8b294266:	48 85 c0             	test   %rax,%rax
ffffffff8b294269:	74 15                	je     ffffffff8b294280 <frame_candidate_8d4030+0x250>
ffffffff8b29426b:	4c 8b 78 20          	mov    0x20(%rax),%r15
ffffffff8b29426f:	eb 16                	jmp    ffffffff8b294287 <frame_candidate_8d4030+0x257>
ffffffff8b294271:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b294278:	0f 1f 84 00 00 00 00 
ffffffff8b29427f:	00 
ffffffff8b294280:	49 c7 c7 ff ff ff ff 	mov    $0xffffffffffffffff,%r15
ffffffff8b294287:	31 ff                	xor    %edi,%edi
ffffffff8b294289:	e8 a2 d4 d3 ff       	call   ffffffff8afd1730 <handler_617_body-0x2c0e40>
ffffffff8b29428e:	48 8b 3d e3 ec 1a 03 	mov    0x31aece3(%rip),%rdi        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294295:	b8 f8 5b 07 00       	mov    $0x75bf8,%eax
ffffffff8b29429a:	44 89 fe             	mov    %r15d,%esi
ffffffff8b29429d:	48 01 c7             	add    %rax,%rdi
ffffffff8b2942a0:	e8 bb 1c b9 ff       	call   ffffffff8ae25f60 <handler_617_body-0x46c610>
ffffffff8b2942a5:	85 c0                	test   %eax,%eax
ffffffff8b2942a7:	0f 88 92 00 00 00    	js     ffffffff8b29433f <frame_candidate_8d4030+0x30f>
ffffffff8b2942ad:	e8 fe 1e 05 00       	call   ffffffff8b2e61b0 <frame_candidate_8d4544+0x51c6c>
ffffffff8b2942b2:	e8 39 d4 d3 ff       	call   ffffffff8afd16f0 <handler_617_body-0x2c0e80>
ffffffff8b2942b7:	85 c0                	test   %eax,%eax
ffffffff8b2942b9:	0f 88 80 00 00 00    	js     ffffffff8b29433f <frame_candidate_8d4030+0x30f>
ffffffff8b2942bf:	e8 1c 1e b9 ff       	call   ffffffff8ae260e0 <handler_617_body-0x46c490>
ffffffff8b2942c4:	48 8b 0d ad ec 1a 03 	mov    0x31aecad(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2942cb:	4d 85 ff             	test   %r15,%r15
ffffffff8b2942ce:	0f 99 c2             	setns  %dl
ffffffff8b2942d1:	4c 29 f0             	sub    %r14,%rax
ffffffff8b2942d4:	40 0f 95 c6          	setne  %sil
ffffffff8b2942d8:	48 8b 89 d8 4f 07 00 	mov    0x74fd8(%rcx),%rcx
ffffffff8b2942df:	48 85 c9             	test   %rcx,%rcx
ffffffff8b2942e2:	40 0f 95 c7          	setne  %dil
ffffffff8b2942e6:	40 20 d6             	and    %dl,%sil
ffffffff8b2942e9:	40 20 fe             	and    %dil,%sil
ffffffff8b2942ec:	40 80 fe 01          	cmp    $0x1,%sil
ffffffff8b2942f0:	0f 85 6a fd ff ff    	jne    ffffffff8b294060 <frame_candidate_8d4030+0x30>
ffffffff8b2942f6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
ffffffff8b2942fd:	00 00 00 
ffffffff8b294300:	48 89 ca             	mov    %rcx,%rdx
ffffffff8b294303:	48 8b 09             	mov    (%rcx),%rcx
ffffffff8b294306:	48 63 f8             	movslq %eax,%rdi
ffffffff8b294309:	48 8b 72 20          	mov    0x20(%rdx),%rsi
ffffffff8b29430d:	49 89 f0             	mov    %rsi,%r8
ffffffff8b294310:	49 29 c0             	sub    %rax,%r8
ffffffff8b294313:	48 29 f0             	sub    %rsi,%rax
ffffffff8b294316:	48 39 fe             	cmp    %rdi,%rsi
ffffffff8b294319:	be 00 00 00 00       	mov    $0x0,%esi
ffffffff8b29431e:	49 0f 4d f0          	cmovge %r8,%rsi
ffffffff8b294322:	48 89 72 20          	mov    %rsi,0x20(%rdx)
ffffffff8b294326:	0f 8d 34 fd ff ff    	jge    ffffffff8b294060 <frame_candidate_8d4030+0x30>
ffffffff8b29432c:	48 85 c0             	test   %rax,%rax
ffffffff8b29432f:	0f 84 2b fd ff ff    	je     ffffffff8b294060 <frame_candidate_8d4030+0x30>
ffffffff8b294335:	48 85 c9             	test   %rcx,%rcx
ffffffff8b294338:	75 c6                	jne    ffffffff8b294300 <frame_candidate_8d4030+0x2d0>
ffffffff8b29433a:	e9 21 fd ff ff       	jmp    ffffffff8b294060 <frame_candidate_8d4030+0x30>
ffffffff8b29433f:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b294343:	5b                   	pop    %rbx
ffffffff8b294344:	41 5c                	pop    %r12
ffffffff8b294346:	41 5d                	pop    %r13
ffffffff8b294348:	41 5e                	pop    %r14
ffffffff8b29434a:	41 5f                	pop    %r15
ffffffff8b29434c:	5d                   	pop    %rbp
ffffffff8b29434d:	c3                   	ret
ffffffff8b29434e:	90                   	nop
ffffffff8b29434f:	90                   	nop

ffffffff8b294350 <frame_candidate_8d4350>:
ffffffff8b294350:	55                   	push   %rbp
ffffffff8b294351:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b294354:	41 57                	push   %r15
ffffffff8b294356:	41 56                	push   %r14
ffffffff8b294358:	53                   	push   %rbx
ffffffff8b294359:	50                   	push   %rax
ffffffff8b29435a:	48 8b 05 17 ec 1a 03 	mov    0x31aec17(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294361:	83 b8 2c 5c 07 00 00 	cmpl   $0x0,0x75c2c(%rax)
ffffffff8b294368:	74 76                	je     ffffffff8b2943e0 <frame_candidate_8d4350+0x90>
ffffffff8b29436a:	48 85 ff             	test   %rdi,%rdi
ffffffff8b29436d:	0f 84 0b 01 00 00    	je     ffffffff8b29447e <frame_candidate_8d4350+0x12e>
ffffffff8b294373:	4c 63 07             	movslq (%rdi),%r8
ffffffff8b294376:	4d 85 c0             	test   %r8,%r8
ffffffff8b294379:	0f 84 f2 00 00 00    	je     ffffffff8b294471 <frame_candidate_8d4350+0x121>
ffffffff8b29437f:	41 83 f8 40          	cmp    $0x40,%r8d
ffffffff8b294383:	0f 87 e8 00 00 00    	ja     ffffffff8b294471 <frame_candidate_8d4350+0x121>
ffffffff8b294389:	4f 8d 04 40          	lea    (%r8,%r8,2),%r8
ffffffff8b29438d:	4c 8d 90 e8 4f 07 00 	lea    0x74fe8(%rax),%r10
ffffffff8b294394:	49 c1 e0 04          	shl    $0x4,%r8
ffffffff8b294398:	4e 8d 8c 00 f8 4f 07 	lea    0x74ff8(%rax,%r8,1),%r9
ffffffff8b29439f:	00 
ffffffff8b2943a0:	4e 8d 84 00 c8 4f 07 	lea    0x74fc8(%rax,%r8,1),%r8
ffffffff8b2943a7:	00 
ffffffff8b2943a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8b2943af:	00 
ffffffff8b2943b0:	4d 8b 12             	mov    (%r10),%r10
ffffffff8b2943b3:	4d 85 d2             	test   %r10,%r10
ffffffff8b2943b6:	74 32                	je     ffffffff8b2943ea <frame_candidate_8d4350+0x9a>
ffffffff8b2943b8:	4d 39 d0             	cmp    %r10,%r8
ffffffff8b2943bb:	75 f3                	jne    ffffffff8b2943b0 <frame_candidate_8d4350+0x60>
ffffffff8b2943bd:	4d 8b 51 d0          	mov    -0x30(%r9),%r10
ffffffff8b2943c1:	4d 8b 49 d8          	mov    -0x28(%r9),%r9
ffffffff8b2943c5:	48 05 f0 4f 07 00    	add    $0x74ff0,%rax
ffffffff8b2943cb:	4d 8d 5a 08          	lea    0x8(%r10),%r11
ffffffff8b2943cf:	4d 85 d2             	test   %r10,%r10
ffffffff8b2943d2:	49 0f 45 c3          	cmovne %r11,%rax
ffffffff8b2943d6:	4c 89 08             	mov    %r9,(%rax)
ffffffff8b2943d9:	b8 e8 4f 07 00       	mov    $0x74fe8,%eax
ffffffff8b2943de:	eb 5e                	jmp    ffffffff8b29443e <frame_candidate_8d4350+0xee>
ffffffff8b2943e0:	b8 07 0b 2f 80       	mov    $0x802f0b07,%eax
ffffffff8b2943e5:	e9 46 01 00 00       	jmp    ffffffff8b294530 <frame_candidate_8d4350+0x1e0>
ffffffff8b2943ea:	4c 8d 90 d8 4f 07 00 	lea    0x74fd8(%rax),%r10
ffffffff8b2943f1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8b2943f8:	0f 1f 84 00 00 00 00 
ffffffff8b2943ff:	00 
ffffffff8b294400:	4d 8b 12             	mov    (%r10),%r10
ffffffff8b294403:	4d 85 d2             	test   %r10,%r10
ffffffff8b294406:	74 69                	je     ffffffff8b294471 <frame_candidate_8d4350+0x121>
ffffffff8b294408:	4d 39 d0             	cmp    %r10,%r8
ffffffff8b29440b:	75 f3                	jne    ffffffff8b294400 <frame_candidate_8d4350+0xb0>
ffffffff8b29440d:	4d 8b 59 d0          	mov    -0x30(%r9),%r11
ffffffff8b294411:	4d 8b 51 d8          	mov    -0x28(%r9),%r10
ffffffff8b294415:	4d 85 db             	test   %r11,%r11
ffffffff8b294418:	74 12                	je     ffffffff8b29442c <frame_candidate_8d4350+0xdc>
ffffffff8b29441a:	49 8b 41 f0          	mov    -0x10(%r9),%rax
ffffffff8b29441e:	49 01 43 20          	add    %rax,0x20(%r11)
ffffffff8b294422:	49 8b 41 d0          	mov    -0x30(%r9),%rax
ffffffff8b294426:	48 83 c0 08          	add    $0x8,%rax
ffffffff8b29442a:	eb 06                	jmp    ffffffff8b294432 <frame_candidate_8d4350+0xe2>
ffffffff8b29442c:	48 05 e0 4f 07 00    	add    $0x74fe0,%rax
ffffffff8b294432:	4c 89 10             	mov    %r10,(%rax)
ffffffff8b294435:	b8 d8 4f 07 00       	mov    $0x74fd8,%eax
ffffffff8b29443a:	4d 8b 49 d8          	mov    -0x28(%r9),%r9
ffffffff8b29443e:	48 03 05 33 eb 1a 03 	add    0x31aeb33(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294445:	4d 8b 10             	mov    (%r8),%r10
ffffffff8b294448:	4d 85 c9             	test   %r9,%r9
ffffffff8b29444b:	49 0f 45 c1          	cmovne %r9,%rax
ffffffff8b29444f:	4c 89 10             	mov    %r10,(%rax)
ffffffff8b294452:	48 8b 05 1f eb 1a 03 	mov    0x31aeb1f(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294459:	48 8b 80 d0 4f 07 00 	mov    0x74fd0(%rax),%rax
ffffffff8b294460:	49 89 00             	mov    %rax,(%r8)
ffffffff8b294463:	48 8b 05 0e eb 1a 03 	mov    0x31aeb0e(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b29446a:	4c 89 80 d0 4f 07 00 	mov    %r8,0x74fd0(%rax)
ffffffff8b294471:	c7 07 00 00 00 00    	movl   $0x0,(%rdi)
ffffffff8b294477:	48 8b 05 fa ea 1a 03 	mov    0x31aeafa(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b29447e:	48 8b 98 d0 4f 07 00 	mov    0x74fd0(%rax),%rbx
ffffffff8b294485:	48 85 db             	test   %rbx,%rbx
ffffffff8b294488:	0f 84 9d 00 00 00    	je     ffffffff8b29452b <frame_candidate_8d4350+0x1db>
ffffffff8b29448e:	4c 8b 03             	mov    (%rbx),%r8
ffffffff8b294491:	48 85 ff             	test   %rdi,%rdi
ffffffff8b294494:	49 89 fe             	mov    %rdi,%r14
ffffffff8b294497:	41 0f 94 c7          	sete   %r15b
ffffffff8b29449b:	4c 89 80 d0 4f 07 00 	mov    %r8,0x74fd0(%rax)
ffffffff8b2944a2:	48 89 73 10          	mov    %rsi,0x10(%rbx)
ffffffff8b2944a6:	48 89 53 18          	mov    %rdx,0x18(%rbx)
ffffffff8b2944aa:	48 89 4b 20          	mov    %rcx,0x20(%rbx)
ffffffff8b2944ae:	48 89 7b 28          	mov    %rdi,0x28(%rbx)
ffffffff8b2944b2:	b9 e8 4f 07 00       	mov    $0x74fe8,%ecx
ffffffff8b2944b7:	bf f8 5b 07 00       	mov    $0x75bf8,%edi
ffffffff8b2944bc:	48 8b 05 b5 ea 1a 03 	mov    0x31aeab5(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2944c3:	48 8b 80 f0 4f 07 00 	mov    0x74ff0(%rax),%rax
ffffffff8b2944ca:	48 89 43 08          	mov    %rax,0x8(%rbx)
ffffffff8b2944ce:	48 03 0d a3 ea 1a 03 	add    0x31aeaa3(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2944d5:	48 85 c0             	test   %rax,%rax
ffffffff8b2944d8:	48 0f 45 c8          	cmovne %rax,%rcx
ffffffff8b2944dc:	48 89 19             	mov    %rbx,(%rcx)
ffffffff8b2944df:	48 8b 05 92 ea 1a 03 	mov    0x31aea92(%rip),%rax        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2944e6:	48 89 98 f0 4f 07 00 	mov    %rbx,0x74ff0(%rax)
ffffffff8b2944ed:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
ffffffff8b2944f4:	48 03 3d 7d ea 1a 03 	add    0x31aea7d(%rip),%rdi        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b2944fb:	e8 10 1a b9 ff       	call   ffffffff8ae25f10 <handler_617_body-0x46c660>
ffffffff8b294500:	85 c0                	test   %eax,%eax
ffffffff8b294502:	0f 95 c1             	setne  %cl
ffffffff8b294505:	44 08 f9             	or     %r15b,%cl
ffffffff8b294508:	75 26                	jne    ffffffff8b294530 <frame_candidate_8d4350+0x1e0>
ffffffff8b29450a:	48 2b 1d 67 ea 1a 03 	sub    0x31aea67(%rip),%rbx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b294511:	48 81 c3 08 b0 f8 ff 	add    $0xfffffffffff8b008,%rbx
ffffffff8b294518:	48 c1 eb 04          	shr    $0x4,%rbx
ffffffff8b29451c:	69 c3 ab aa aa aa    	imul   $0xaaaaaaab,%ebx,%eax
ffffffff8b294522:	ff c0                	inc    %eax
ffffffff8b294524:	41 89 06             	mov    %eax,(%r14)
ffffffff8b294527:	31 c0                	xor    %eax,%eax
ffffffff8b294529:	eb 05                	jmp    ffffffff8b294530 <frame_candidate_8d4350+0x1e0>
ffffffff8b29452b:	b8 08 0b 2f 80       	mov    $0x802f0b08,%eax
ffffffff8b294530:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8b294534:	5b                   	pop    %rbx
ffffffff8b294535:	41 5e                	pop    %r14
ffffffff8b294537:	41 5f                	pop    %r15
ffffffff8b294539:	5d                   	pop    %rbp
ffffffff8b29453a:	c3                   	ret
ffffffff8b29453b:	90                   	nop
ffffffff8b29453c:	90                   	nop
ffffffff8b29453d:	90                   	nop
ffffffff8b29453e:	90                   	nop
ffffffff8b29453f:	90                   	nop
ffffffff8b294540:	85 ff                	test   %edi,%edi
ffffffff8b294542:	74 7d                	je     ffffffff8b2945c1 <frame_candidate_8d4544+0x7d>

ffffffff8b294544 <frame_candidate_8d4544>:
ffffffff8b294544:	55                   	push   %rbp
ffffffff8b294545:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b294548:	48 8b 0d 29 ea 1a 03 	mov    0x31aea29(%rip),%rcx        # ffffffff8e442f78 <frame_candidate_8d4544+0x31aea34>
ffffffff8b29454f:	83 b9 2c 5c 07 00 00 	cmpl   $0x0,0x75c2c(%rcx)
ffffffff8b294556:	74 6c                	je     ffffffff8b2945c4 <frame_candidate_8d4544+0x80>
ffffffff8b294558:	b8 05 0b 2f 80       	mov    $0x802f0b05,%eax
ffffffff8b29455d:	83 ff 40             	cmp    $0x40,%edi
ffffffff8b294560:	0f 87 ee 00 00 00    	ja     ffffffff8b294654 <frame_candidate_8d4544+0x110>
ffffffff8b294566:	48 63 c7             	movslq %edi,%rax
ffffffff8b294569:	48 8d b1 e8 4f 07 00 	lea    0x74fe8(%rcx),%rsi
