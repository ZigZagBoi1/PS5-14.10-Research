; REA 6.7.0 full disassembly of handler_619.bin
; SHA256 f5713fe1db5322b26ae642bb71a1fc31150e31c240ea2db10051ace0c0f3aafc; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25e88, kernel RVA 0x265e88.
; REA inspect_with_objdump Evidence: ev_11707a4e809c1269db6e7488a25b8db16fc7033dcafc03de23446f3715ed8067
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 619; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_619.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25e88 <handler_619_entry>:
ffffffff8ac25e88:	e9 c3 17 7d 00       	jmp    ffffffff8b3f7650 <neighbor_trampoline_266e80+0x7d07d0>
ffffffff8ac25e8d:	cc                   	int3
ffffffff8ac25e8e:	cc                   	int3
ffffffff8ac25e8f:	cc                   	int3

ffffffff8ac25e90 <neighbor_trampoline_265e90>:
ffffffff8ac25e90:	e9 9b 75 85 00       	jmp    ffffffff8b47d430 <neighbor_trampoline_266e80+0x8565b0>
ffffffff8ac25e95:	cc                   	int3
ffffffff8ac25e96:	cc                   	int3
ffffffff8ac25e97:	cc                   	int3

ffffffff8ac25e98 <neighbor_trampoline_265e98>:
ffffffff8ac25e98:	e9 a3 6e 57 00       	jmp    ffffffff8b19cd40 <neighbor_trampoline_266e80+0x575ec0>
ffffffff8ac25e9d:	cc                   	int3
ffffffff8ac25e9e:	cc                   	int3
ffffffff8ac25e9f:	cc                   	int3

ffffffff8ac25ea0 <neighbor_trampoline_265ea0>:
ffffffff8ac25ea0:	e9 fb c6 66 00       	jmp    ffffffff8b2925a0 <neighbor_trampoline_266e80+0x66b720>
ffffffff8ac25ea5:	cc                   	int3
ffffffff8ac25ea6:	cc                   	int3
ffffffff8ac25ea7:	cc                   	int3

ffffffff8ac25ea8 <neighbor_trampoline_265ea8>:
ffffffff8ac25ea8:	e9 43 76 85 00       	jmp    ffffffff8b47d4f0 <neighbor_trampoline_266e80+0x856670>
ffffffff8ac25ead:	cc                   	int3
ffffffff8ac25eae:	cc                   	int3
ffffffff8ac25eaf:	cc                   	int3

ffffffff8ac25eb0 <neighbor_trampoline_265eb0>:
ffffffff8ac25eb0:	e9 db dd 39 00       	jmp    ffffffff8afc3c90 <neighbor_trampoline_266e80+0x39ce10>
ffffffff8ac25eb5:	cc                   	int3
ffffffff8ac25eb6:	cc                   	int3
ffffffff8ac25eb7:	cc                   	int3

ffffffff8ac25eb8 <neighbor_trampoline_265eb8>:
ffffffff8ac25eb8:	e9 33 ee 39 00       	jmp    ffffffff8afc4cf0 <neighbor_trampoline_266e80+0x39de70>
ffffffff8ac25ebd:	cc                   	int3
ffffffff8ac25ebe:	cc                   	int3
ffffffff8ac25ebf:	cc                   	int3

ffffffff8ac25ec0 <neighbor_trampoline_265ec0>:
ffffffff8ac25ec0:	e9 8b c9 23 00       	jmp    ffffffff8ae62850 <neighbor_trampoline_266e80+0x23b9d0>
ffffffff8ac25ec5:	cc                   	int3
ffffffff8ac25ec6:	cc                   	int3
ffffffff8ac25ec7:	cc                   	int3

ffffffff8ac25ec8 <neighbor_trampoline_265ec8>:
ffffffff8ac25ec8:	e9 73 76 85 00       	jmp    ffffffff8b47d540 <neighbor_trampoline_266e80+0x8566c0>
ffffffff8ac25ecd:	cc                   	int3
ffffffff8ac25ece:	cc                   	int3
ffffffff8ac25ecf:	cc                   	int3

ffffffff8ac25ed0 <neighbor_trampoline_265ed0>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266e80+0x6b57c0>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266e80+0x6b5df0>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266e80+0x1d1fb0>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266e80+0x1d21f0>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266e80+0x1d22d0>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266e80+0x1d2520>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266e80+0x457650>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266e80+0x856ab0>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266e80+0x457740>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266e80+0x457980>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266e80+0x829f90>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266e80+0x23bf60>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266e80+0x856c50>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266e80+0x7d07e0>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266e80+0x857340>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266e80+0x857930>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266e80+0x791370>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266e80+0x982690>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266e80+0x740e90>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266e80+0x7426e0>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266e80+0x742f90>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266e80+0x7430c0>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266e80+0x6945c0>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266e80+0x23c320>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266e80+0x857a30>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266e80+0x744370>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266e80+0x854b00>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266e80+0x492460>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266e80+0x1cdf20>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266e80+0x1cdf30>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266e80+0x1cdf40>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266e80+0x1d0f10>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266e80+0x1d1400>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266e80+0x87f810>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266e80+0x87f700>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266e80+0x1e2250>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_619_entry-0x1bf0c8>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266e80+0x1e3bf0>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266e80+0x74f290>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_619_entry-0x1be818>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_619_entry-0x1be638>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_619_entry-0x1be608>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266e80+0x1eb1c0>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266e80+0x1ede40>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266e80+0x1f09a0>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266e80+0x2070f0>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266e80+0x207200>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266e80+0x20bb10>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266e80+0x20c530>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266e80+0x20ca30>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266e80+0x20d3d0>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266e80+0x20df30>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266e80+0x216170>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_619_entry-0x47e98>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266e80+0x229480>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266e80+0x229f30>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266e80+0x231130>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266e80+0x231160>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266e80+0x2317b0>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266e80+0x2317c0>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266e80+0x690d40>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266e80+0x68f980>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266e80+0x6905a0>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266e80+0x693100>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266e80+0x3784d0>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266e80+0x3789a0>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266e80+0x7cde60>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266e80+0x381620>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266e80+0x691370>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266e80+0x692590>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266e80+0x695570>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266e80+0x68fe10>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266e80+0xa4ab90>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266e80+0x851520>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266e80+0x851530>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266e80+0x693340>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266e80+0x690cc0>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266e80+0x239ae0>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266e80+0x4c2900>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266e80+0x4c2910>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266e80+0x4c2920>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266e80+0x454710>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266e80+0x851f20>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266e80+0x6932f0>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266e80+0x918240>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266e80+0x918280>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266e80+0x692e70>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266e80+0x6938c0>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266e80+0x2ebcf0>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266e80+0x2ebd70>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266e80+0x2ebdd0>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266e80+0x2ebe00>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266e80+0x2ebe30>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266e80+0x2ebe60>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266e80+0x917980>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266e80+0x917d60>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266e80+0x9180f0>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266e80+0x99feb0>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266e80+0x52b810>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266e80+0x381ca0>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266e80+0x2ebe90>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266e80+0x9182e0>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266e80+0x3773d0>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266e80+0x7edbb0>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266e80+0x7edbc0>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266e80+0x7edbd0>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266e80+0x7edbe0>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266e80+0x7edc00>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266e80+0x7edc10>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266e80+0x6928a0>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266e80+0x7edc30>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266e80+0x68f660>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266e80+0x68f070>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266e80+0x7edba0>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266e80+0x7edbf0>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266e80+0x7edc20>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266e80+0x47e650>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266e80+0x918630>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266e80+0x5d67e0>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266e80+0x5d6940>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266e80+0x5d6c30>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266e80+0x5d7000>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266e80+0x692e00>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266e80+0x693290>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266e80+0x692330>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266e80+0x693670>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266e80+0x691210>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266e80+0x694d00>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266e80+0x690d00>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266e80+0x690a10>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266e80+0x694a20>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266e80+0x691690>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266e80+0x691980>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266e80+0x234200>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266e80+0x234210>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266e80+0x2f8bd0>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266e80+0x9cd9f0>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266e80+0x575e70>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266e80+0x575e80>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266e80+0x575e90>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266e80+0x575ea0>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266e80+0x575eb0>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266e80+0x33fe10>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266e80+0x340480>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266e80+0x340790>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266e80+0x340a80>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266e80+0xa359b0>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266e80+0x341080>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266e80+0x3411f0>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266e80+0x981600>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266e80+0x234220>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266e80+0x234240>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266e80+0x234250>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266e80+0x234260>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266e80+0x234270>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266e80+0x2c98a0>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266e80+0x2ca7f0>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266e80+0x692870>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266e80+0x2ca3b0>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266e80+0x59bf70>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266e80+0x9182c0>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266e80+0x87c760>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266e80+0x287fa0>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266e80+0x693c90>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266e80+0x693fb0>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266e80+0x7623a0>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266e80+0x762280>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266e80+0x3db490>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266e80+0x3db9a0>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266e80+0x3dc860>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266e80+0x3dca50>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266e80+0x3dcde0>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266e80+0x791410>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266e80+0x794cf0>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266e80+0x7de400>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266e80+0xa20e20>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266e80+0x798180>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266e80+0x799900>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266e80+0x799960>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266e80+0x8579b0>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266e80+0x7960b0>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266e80+0x38a140>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266e80+0x690570>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266e80+0x2903d0>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266e80+0x796c50>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266e80+0x796f30>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266e80+0x797090>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266e80+0x3dd650>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266e80+0x3ea150>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266e80+0x797bb0>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266e80+0x290ac0>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266e80+0x851c60>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266e80+0x8547e0>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266e80+0x7973e0>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266e80+0x797660>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266e80+0x7977b0>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266e80+0x5314b0>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266e80+0x856180>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_619_entry-0x1695f8>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266e80+0x238210>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266e80+0x238380>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266e80+0x259710>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266e80+0x259730>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_619_entry-0x1bca58>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266e80+0x2634d0>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266e80+0x263bc0>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_619_entry-0x1bb978>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266e80+0x26e350>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266e80+0x5aa330>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_619_entry-0x24aff8>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266e80+0x2891b0>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266e80+0x294d50>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266e80+0x2a6050>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266e80+0x2a6060>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266e80+0x2a60b0>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266e80+0x2a60f0>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266e80+0x2a6130>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266e80+0x2a6160>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266e80+0x2b7650>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266e80+0x2b80e0>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266e80+0x2b8180>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266e80+0x2b8230>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266e80+0x2b8460>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266e80+0x2b87f0>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266e80+0x2b9060>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266e80+0x2cf580>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266e80+0x2dde20>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266e80+0x2dfa70>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_619_entry-0x1b4858>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_619_entry-0x1b3ed8>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266e80+0x2f50c0>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266e80+0x2f51b0>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266e80+0x2f51d0>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266e80+0x307380>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266e80+0x318620>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266e80+0x72d760>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266e80+0x31ead0>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266e80+0x3329a0>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266e80+0x333560>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266e80+0x3336b0>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266e80+0x333880>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266e80+0x333950>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266e80+0x333bd0>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266e80+0x333ce0>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266e80+0x333de0>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266e80+0x375050>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266e80+0x3848a0>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266e80+0x3851b0>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266e80+0x385c50>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266e80+0x3865c0>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266e80+0x386cb0>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_619_entry-0x117c08>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266e80+0x38aa30>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266e80+0x38bcb0>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266e80+0x396240>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266e80+0x399800>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266e80+0x39a0c0>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266e80+0x87f620>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266e80+0x3c6c20>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266e80+0x3c9450>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266e80+0x3ce090>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266e80+0x3d86a0>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266e80+0x3f0b30>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266e80+0xa40490>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266e80+0x3fbff0>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266e80+0x3fc000>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266e80+0x411f90>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266e80+0x411fe0>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266e80+0x412040>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266e80+0x4120e0>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266e80+0x412310>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266e80+0x4124e0>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266e80+0x412800>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_619_entry-0x2322f8>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_619_entry-0x2321e8>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_619_entry-0x232168>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_619_entry-0x228f18>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_619_entry-0x228da8>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_619_entry-0x228828>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_619_entry-0x227d88>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_619_entry-0x227d28>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_619_entry-0x227cc8>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_619_entry-0x226e18>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_619_entry-0x226db8>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_619_entry-0x2269d8>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_619_entry-0x226978>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_619_entry-0x226918>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_619_entry-0x2262d8>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_619_entry-0x225ec8>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_619_entry-0x225528>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_619_entry-0x225338>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_619_entry-0x225258>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_619_entry-0x224858>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_619_entry-0x224738>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_619_entry-0x224658>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_619_entry-0x2245c8>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_619_entry-0x223e28>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_619_entry-0x2239b8>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_619_entry-0x2238e8>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_619_entry-0x223888>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266e80+0x4291b0>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266e80+0x42fe40>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266e80+0x431750>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266e80+0x43b1d0>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266e80+0x43b430>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266e80+0x4477c0>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266e80+0x447970>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_619_entry-0xe4ad8>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266e80+0x458120>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_619_entry-0xdde48>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266e80+0x469c80>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266e80+0x46a280>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266e80+0x46a3e0>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266e80+0x46a560>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266e80+0x46a6a0>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266e80+0x46a7c0>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266e80+0x46a8a0>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266e80+0x4757e0>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266e80+0x475810>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266e80+0x475820>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266e80+0x479aa0>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266e80+0x47a5c0>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266e80+0x47a5d0>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_619_entry-0xdc418>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_619_entry-0xd53e8>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266e80+0x49baf0>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266e80+0x49bee0>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266e80+0x49f2f0>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266e80+0x49f370>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266e80+0x4a9080>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266e80+0x4a9130>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266e80+0x4a9340>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266e80+0x4a94a0>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266e80+0x4abd30>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266e80+0x4af4e0>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266e80+0x4c8af0>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266e80+0x4c8b10>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266e80+0x4c8ba0>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_619_entry-0x1f058>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266e80+0x4fd970>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266e80+0x50c890>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266e80+0x50ead0>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266e80+0x533010>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266e80+0x54c370>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266e80+0x57b520>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266e80+0x581560>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266e80+0x581600>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266e80+0x9d4330>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266e80+0x9d5860>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266e80+0x9d5810>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266e80+0x9d58b0>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266e80+0x59b3a0>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266e80+0x59b670>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266e80+0x5a56f0>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266e80+0x5c4480>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266e80+0x6ba060>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266e80+0x6b9d10>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266e80+0x5c9990>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266e80+0x5ca080>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266e80+0x5ce430>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266e80+0x5ce440>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266e80+0x5ce450>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266e80+0x5ce470>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266e80+0x5ce5c0>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266e80+0x5ce5d0>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266e80+0x5ce610>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266e80+0x5cec50>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266e80+0x5e99f0>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266e80+0x609470>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266e80+0x609750>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266e80+0x60bc70>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266e80+0x60c980>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_619_entry-0x202448>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_619_entry-0x1ffb18>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_619_entry-0x17f8f8>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_619_entry-0x17f8e8>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_619_entry-0x17f728>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_619_entry-0x17f618>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_619_entry-0x17def8>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_619_entry-0x17bee8>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_619_entry-0x17b818>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_619_entry-0x17b728>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_619_entry-0x17ade8>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_619_entry-0x17acf8>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_619_entry-0x178e88>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_619_entry-0x178d78>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266e80+0x623a20>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266e80+0x635f70>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_619_entry-0x177338>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266e80+0x6643d0>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266e80+0x664510>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266e80+0x66c0e0>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266e80+0x66c110>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266e80+0x6713b0>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266e80+0x671f60>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266e80+0x672930>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266e80+0x672a90>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266e80+0x673640>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266e80+0x6736f0>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266e80+0x673730>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266e80+0x69de00>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266e80+0x69dfe0>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266e80+0x6b6580>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266e80+0x6b6620>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266e80+0x81b350>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266e80+0x8db2a0>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266e80+0x6fe0b0>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266e80+0x70f0d0>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266e80+0x70f380>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266e80+0x725ad0>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266e80+0x725db0>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266e80+0x7260b0>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266e80+0x726860>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266e80+0x727750>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266e80+0x727880>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266e80+0x72b2f0>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266e80+0x72b3c0>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_619_entry-0x170a88>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266e80+0x73b4a0>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266e80+0x73e8a0>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266e80+0x745b20>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266e80+0x745ba0>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_619_entry-0xa7848>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266e80+0x757ea0>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266e80+0x75f1d0>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266e80+0x75f250>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266e80+0x75f400>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266e80+0x75f490>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266e80+0x75f610>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266e80+0x75f730>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266e80+0x75fa10>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266e80+0x7624c0>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266e80+0x7624e0>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266e80+0x7624f0>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266e80+0x762500>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266e80+0x773f30>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266e80+0x774120>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266e80+0x7759e0>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266e80+0x775dc0>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266e80+0x776000>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266e80+0x776680>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266e80+0xa43e50>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266e80+0x776950>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266e80+0x776b10>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266e80+0x776d20>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266e80+0x776d80>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266e80+0x776fd0>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266e80+0x777030>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266e80+0x777170>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266e80+0x7771f0>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266e80+0x777270>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266e80+0x779d10>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266e80+0x779e50>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266e80+0x779ef0>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266e80+0x77a070>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266e80+0x77a1d0>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266e80+0x77a610>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266e80+0x79f760>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_619_entry-0x164b48>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266e80+0x7cc0b0>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266e80+0x7cc840>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266e80+0x7d1e10>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266e80+0x803c80>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266e80+0x803d30>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266e80+0x827d90>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266e80+0x827f80>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266e80+0x84a930>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266e80+0x859930>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266e80+0x85bc70>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_619_entry-0x14b738>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266e80+0x87a420>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266e80+0x87c580>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266e80+0x87c6b0>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266e80+0x87f540>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266e80+0x8a1060>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266e80+0x8a1310>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266e80+0x8a16b0>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266e80+0x8a1990>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266e80+0x8a2820>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266e80+0x8a4670>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_619_entry-0x76d98>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_619_entry-0x75e28>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_619_entry-0x14a4d8>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266e80+0x8d42b0>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266e80+0x8e0bc0>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266e80+0x8e9540>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266e80+0x8ea090>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266e80+0x8ea130>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266e80+0x8ea230>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266e80+0x8ea310>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266e80+0x8ea410>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266e80+0x8ea450>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266e80+0x8ea4a0>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266e80+0x8efa20>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_619_entry-0x1cbda8>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266e80+0x903ff0>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266e80+0x904d10>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266e80+0x906b00>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266e80+0x906c20>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266e80+0x907300>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266e80+0x90a4a0>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266e80+0x90a4f0>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266e80+0x90a540>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8b3f7650, handler_body_619; REA Evidence ev_b861809a4f3ba87af438db9046fd18911d473c6f0c8d04321031a746d01b171e
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8b3f7650", "end": "0xffffffff8b3f765a"}], "total_bytes": 11, "span_bytes": 11, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_619:
0xffffffff8b3f7650: PUSH RBP
0xffffffff8b3f7651: MOV RBP, RSP
0xffffffff8b3f7654: MOV EAX, 0x4e
0xffffffff8b3f7659: POP RBP
0xffffffff8b3f765a: RET
; END FUNCTION handler_body_619

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_edd5b4fe6ecea30420c8d759192e20516d83c1b97bd038499848e6e21cfd9cd1
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_619.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8b3f7650 <handler_619_body>:
ffffffff8b3f7650:	55                   	push   %rbp
ffffffff8b3f7651:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f7654:	b8 4e 00 00 00       	mov    $0x4e,%eax
ffffffff8b3f7659:	5d                   	pop    %rbp
ffffffff8b3f765a:	c3                   	ret
ffffffff8b3f765b:	90                   	nop
ffffffff8b3f765c:	90                   	nop
ffffffff8b3f765d:	90                   	nop
ffffffff8b3f765e:	90                   	nop
ffffffff8b3f765f:	90                   	nop

ffffffff8b3f7660 <frame_candidate_a37660>:
ffffffff8b3f7660:	55                   	push   %rbp
ffffffff8b3f7661:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f7664:	41 56                	push   %r14
ffffffff8b3f7666:	53                   	push   %rbx
ffffffff8b3f7667:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b3f766a:	8b 36                	mov    (%rsi),%esi
ffffffff8b3f766c:	49 89 fe             	mov    %rdi,%r14
ffffffff8b3f766f:	48 8d 3d 6c a2 92 00 	lea    0x92a26c(%rip),%rdi        # ffffffff8bd218e2 <frame_candidate_a39640+0x9282a2>
ffffffff8b3f7676:	31 c0                	xor    %eax,%eax
ffffffff8b3f7678:	e8 93 5d 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f767d:	8b 03                	mov    (%rbx),%eax
ffffffff8b3f767f:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b3f7683:	09 81 34 0a 00 00    	or     %eax,0xa34(%rcx)
ffffffff8b3f7689:	31 c0                	xor    %eax,%eax
ffffffff8b3f768b:	5b                   	pop    %rbx
ffffffff8b3f768c:	41 5e                	pop    %r14
ffffffff8b3f768e:	5d                   	pop    %rbp
ffffffff8b3f768f:	c3                   	ret
ffffffff8b3f7690:	48 8b 47 20          	mov    0x20(%rdi),%rax
ffffffff8b3f7694:	48 8d 0d 75 c2 08 01 	lea    0x108c275(%rip),%rcx        # ffffffff8c483910 <frame_candidate_a39640+0x108a2d0>
ffffffff8b3f769b:	0f b6 80 9d 00 00 00 	movzbl 0x9d(%rax),%eax
ffffffff8b3f76a2:	48 8b 04 c1          	mov    (%rcx,%rax,8),%rax
ffffffff8b3f76a6:	48 8b 48 40          	mov    0x40(%rax),%rcx
ffffffff8b3f76aa:	48 85 c9             	test   %rcx,%rcx
ffffffff8b3f76ad:	74 18                	je     ffffffff8b3f76c7 <frame_candidate_a37660+0x67>
ffffffff8b3f76af:	48 8d 05 1a dc 82 ff 	lea    -0x7d23e6(%rip),%rax        # ffffffff8ac252d0 <handler_619_body-0x7d2380>
ffffffff8b3f76b6:	48 29 c8             	sub    %rcx,%rax
ffffffff8b3f76b9:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f76bd:	48 3d bc 08 00 00    	cmp    $0x8bc,%rax
ffffffff8b3f76c3:	77 03                	ja     ffffffff8b3f76c8 <frame_candidate_a376c8>
ffffffff8b3f76c5:	ff e1                	jmp    *%rcx
ffffffff8b3f76c7:	c3                   	ret

ffffffff8b3f76c8 <frame_candidate_a376c8>:
ffffffff8b3f76c8:	55                   	push   %rbp
ffffffff8b3f76c9:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f76cc:	41 56                	push   %r14
ffffffff8b3f76ce:	53                   	push   %rbx
ffffffff8b3f76cf:	48 8d 05 da 0f b3 01 	lea    0x1b30fda(%rip),%rax        # ffffffff8cf286b0 <frame_candidate_a39640+0x1b2f070>
ffffffff8b3f76d6:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b3f76d9:	48 89 ce             	mov    %rcx,%rsi
ffffffff8b3f76dc:	49 89 ce             	mov    %rcx,%r14
ffffffff8b3f76df:	48 89 c7             	mov    %rax,%rdi
ffffffff8b3f76e2:	e8 d9 81 a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f76e7:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b3f76ea:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f76ed:	5b                   	pop    %rbx
ffffffff8b3f76ee:	41 5e                	pop    %r14
ffffffff8b3f76f0:	5d                   	pop    %rbp
ffffffff8b3f76f1:	ff e1                	jmp    *%rcx
ffffffff8b3f76f3:	90                   	nop
ffffffff8b3f76f4:	90                   	nop
ffffffff8b3f76f5:	90                   	nop
ffffffff8b3f76f6:	90                   	nop
ffffffff8b3f76f7:	90                   	nop
ffffffff8b3f76f8:	90                   	nop
ffffffff8b3f76f9:	90                   	nop
ffffffff8b3f76fa:	90                   	nop
ffffffff8b3f76fb:	90                   	nop
ffffffff8b3f76fc:	90                   	nop
ffffffff8b3f76fd:	90                   	nop
ffffffff8b3f76fe:	90                   	nop
ffffffff8b3f76ff:	90                   	nop

ffffffff8b3f7700 <frame_candidate_a37700>:
ffffffff8b3f7700:	55                   	push   %rbp
ffffffff8b3f7701:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f7704:	41 57                	push   %r15
ffffffff8b3f7706:	41 56                	push   %r14
ffffffff8b3f7708:	41 55                	push   %r13
ffffffff8b3f770a:	41 54                	push   %r12
ffffffff8b3f770c:	53                   	push   %rbx
ffffffff8b3f770d:	48 81 ec 38 01 00 00 	sub    $0x138,%rsp
ffffffff8b3f7714:	4c 8d 2d f5 4b ee 02 	lea    0x2ee4bf5(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f771b:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b3f771e:	48 8d 35 8b 14 b3 01 	lea    0x1b3148b(%rip),%rsi        # ffffffff8cf28bb0 <frame_candidate_a39640+0x1b2f570>
ffffffff8b3f7725:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8b3f7729:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b3f772d:	65 4c 8b 34 25 00 00 	mov    %gs:0x0,%r14
ffffffff8b3f7734:	00 00 
ffffffff8b3f7736:	48 8b bf a8 00 00 00 	mov    0xa8(%rdi),%rdi
ffffffff8b3f773d:	e8 5e 95 ba ff       	call   ffffffff8afa0ca0 <handler_619_body-0x4569b0>
ffffffff8b3f7742:	41 bf 16 00 00 00    	mov    $0x16,%r15d
ffffffff8b3f7748:	85 c0                	test   %eax,%eax
ffffffff8b3f774a:	0f 85 52 03 00 00    	jne    ffffffff8b3f7aa2 <frame_candidate_a37700+0x3a2>
ffffffff8b3f7750:	48 83 3d 38 7c 1b 03 	cmpq   $0x0,0x31b7c38(%rip)        # ffffffff8e5af390 <frame_candidate_a39640+0x31b5d50>
ffffffff8b3f7757:	00 
ffffffff8b3f7758:	74 15                	je     ffffffff8b3f776f <frame_candidate_a37700+0x6f>
ffffffff8b3f775a:	f6 83 9a 00 00 00 01 	testb  $0x1,0x9a(%rbx)
ffffffff8b3f7761:	0f 85 bd 00 00 00    	jne    ffffffff8b3f7824 <frame_candidate_a37700+0x124>
ffffffff8b3f7767:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b3f776a:	e9 82 02 00 00       	jmp    ffffffff8b3f79f1 <frame_candidate_a37700+0x2f1>
ffffffff8b3f776f:	48 8d 3d 82 53 8f 00 	lea    0x8f5382(%rip),%rdi        # ffffffff8bcecaf8 <frame_candidate_a39640+0x8f34b8>
ffffffff8b3f7776:	be 10 01 00 00       	mov    $0x110,%esi
ffffffff8b3f777b:	31 d2                	xor    %edx,%edx
ffffffff8b3f777d:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f777f:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f7782:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f7785:	6a 00                	push   $0x0
ffffffff8b3f7787:	6a 07                	push   $0x7
ffffffff8b3f7789:	e8 52 39 a0 ff       	call   ffffffff8adfb0e0 <handler_619_body-0x5fc570>
ffffffff8b3f778e:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f7792:	48 89 05 f7 7b 1b 03 	mov    %rax,0x31b7bf7(%rip)        # ffffffff8e5af390 <frame_candidate_a39640+0x31b5d50>
ffffffff8b3f7799:	48 8d 3d f2 37 97 00 	lea    0x9737f2(%rip),%rdi        # ffffffff8bd6af92 <frame_candidate_a39640+0x971952>
ffffffff8b3f77a0:	be a8 00 00 00       	mov    $0xa8,%esi
ffffffff8b3f77a5:	31 d2                	xor    %edx,%edx
ffffffff8b3f77a7:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f77a9:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f77ac:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f77af:	6a 00                	push   $0x0
ffffffff8b3f77b1:	6a 07                	push   $0x7
ffffffff8b3f77b3:	e8 28 39 a0 ff       	call   ffffffff8adfb0e0 <handler_619_body-0x5fc570>
ffffffff8b3f77b8:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f77bc:	48 89 05 d5 7b 1b 03 	mov    %rax,0x31b7bd5(%rip)        # ffffffff8e5af398 <frame_candidate_a39640+0x31b5d58>
ffffffff8b3f77c3:	48 8d 3d f5 86 87 00 	lea    0x8786f5(%rip),%rdi        # ffffffff8bc6febf <frame_candidate_a39640+0x87687f>
ffffffff8b3f77ca:	be c8 02 00 00       	mov    $0x2c8,%esi
ffffffff8b3f77cf:	31 d2                	xor    %edx,%edx
ffffffff8b3f77d1:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f77d3:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f77d6:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f77d9:	6a 00                	push   $0x0
ffffffff8b3f77db:	6a 07                	push   $0x7
ffffffff8b3f77dd:	e8 fe 38 a0 ff       	call   ffffffff8adfb0e0 <handler_619_body-0x5fc570>
ffffffff8b3f77e2:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f77e6:	48 89 05 b3 7b 1b 03 	mov    %rax,0x31b7bb3(%rip)        # ffffffff8e5af3a0 <frame_candidate_a39640+0x31b5d60>
ffffffff8b3f77ed:	48 8d 3d 2c db 95 00 	lea    0x95db2c(%rip),%rdi        # ffffffff8bd55320 <frame_candidate_a39640+0x95bce0>
ffffffff8b3f77f4:	be 10 03 00 00       	mov    $0x310,%esi
ffffffff8b3f77f9:	31 d2                	xor    %edx,%edx
ffffffff8b3f77fb:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f77fd:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f7800:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f7803:	6a 00                	push   $0x0
ffffffff8b3f7805:	6a 07                	push   $0x7
ffffffff8b3f7807:	e8 d4 38 a0 ff       	call   ffffffff8adfb0e0 <handler_619_body-0x5fc570>
ffffffff8b3f780c:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f7810:	48 89 05 91 7b 1b 03 	mov    %rax,0x31b7b91(%rip)        # ffffffff8e5af3a8 <frame_candidate_a39640+0x31b5d68>
ffffffff8b3f7817:	f6 83 9a 00 00 00 01 	testb  $0x1,0x9a(%rbx)
ffffffff8b3f781e:	0f 84 43 ff ff ff    	je     ffffffff8b3f7767 <frame_candidate_a37700+0x67>
ffffffff8b3f7824:	4c 8b a3 98 02 00 00 	mov    0x298(%rbx),%r12
ffffffff8b3f782b:	4d 8b 7c 24 30       	mov    0x30(%r12),%r15
ffffffff8b3f7830:	41 0f b6 47 1a       	movzbl 0x1a(%r15),%eax
ffffffff8b3f7835:	84 c0                	test   %al,%al
ffffffff8b3f7837:	0f 84 00 01 00 00    	je     ffffffff8b3f793d <frame_candidate_a37700+0x23d>
ffffffff8b3f783d:	3c 01                	cmp    $0x1,%al
ffffffff8b3f783f:	0f 85 ac 01 00 00    	jne    ffffffff8b3f79f1 <frame_candidate_a37700+0x2f1>
ffffffff8b3f7845:	48 8b bb a8 00 00 00 	mov    0xa8(%rbx),%rdi
ffffffff8b3f784c:	48 8d 35 6e 9a 84 00 	lea    0x849a6e(%rip),%rsi        # ffffffff8bc412c1 <frame_candidate_a39640+0x847c81>
ffffffff8b3f7853:	4c 89 bd a8 fe ff ff 	mov    %r15,-0x158(%rbp)
ffffffff8b3f785a:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b3f785d:	31 d2                	xor    %edx,%edx
ffffffff8b3f785f:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7861:	e8 ea 99 ba ff       	call   ffffffff8afa1250 <handler_619_body-0x456400>
ffffffff8b3f7866:	85 c0                	test   %eax,%eax
ffffffff8b3f7868:	0f 85 83 01 00 00    	jne    ffffffff8b3f79f1 <frame_candidate_a37700+0x2f1>
ffffffff8b3f786e:	4c 89 a5 a0 fe ff ff 	mov    %r12,-0x160(%rbp)
ffffffff8b3f7875:	4d 8b 64 24 20       	mov    0x20(%r12),%r12
ffffffff8b3f787a:	48 8d 15 5a 39 95 00 	lea    0x95395a(%rip),%rdx        # ffffffff8bd4b1db <frame_candidate_a39640+0x951b9b>
ffffffff8b3f7881:	be 00 04 08 00       	mov    $0x80400,%esi
ffffffff8b3f7886:	b9 1b 02 00 00       	mov    $0x21b,%ecx
ffffffff8b3f788b:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f788e:	e8 bd 82 c7 ff       	call   ffffffff8b06fb50 <handler_619_body-0x387b00>
ffffffff8b3f7893:	49 8b 86 40 01 00 00 	mov    0x140(%r14),%rax
ffffffff8b3f789a:	48 8d 0d d7 31 0a 01 	lea    0x10a31d7(%rip),%rcx        # ffffffff8c49aa78 <frame_candidate_a39640+0x10a1438>
ffffffff8b3f78a1:	48 8d b5 e8 fe ff ff 	lea    -0x118(%rbp),%rsi
ffffffff8b3f78a8:	48 89 8d e8 fe ff ff 	mov    %rcx,-0x118(%rbp)
ffffffff8b3f78af:	4c 89 a5 f0 fe ff ff 	mov    %r12,-0x110(%rbp)
ffffffff8b3f78b6:	c7 85 f8 fe ff ff 80 	movl   $0x180,-0x108(%rbp)
ffffffff8b3f78bd:	01 00 00 
ffffffff8b3f78c0:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
ffffffff8b3f78c7:	4c 89 b5 08 ff ff ff 	mov    %r14,-0xf8(%rbp)
ffffffff8b3f78ce:	49 8b 7c 24 08       	mov    0x8(%r12),%rdi
ffffffff8b3f78d3:	e8 28 45 b5 ff       	call   ffffffff8af4be00 <handler_619_body-0x4ab850>
ffffffff8b3f78d8:	85 c0                	test   %eax,%eax
ffffffff8b3f78da:	74 10                	je     ffffffff8b3f78ec <frame_candidate_a37700+0x1ec>
ffffffff8b3f78dc:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f78df:	be 50 01 00 00       	mov    $0x150,%esi
ffffffff8b3f78e4:	e8 47 81 0a 00       	call   ffffffff8b49fa30 <frame_candidate_a39640+0xa63f0>
ffffffff8b3f78e9:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f78ec:	48 8d 05 d5 54 0a 01 	lea    0x10a54d5(%rip),%rax        # ffffffff8c49cdc8 <frame_candidate_a39640+0x10a3788>
ffffffff8b3f78f3:	48 8d b5 e8 fe ff ff 	lea    -0x118(%rbp),%rsi
ffffffff8b3f78fa:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
ffffffff8b3f7901:	4c 89 a5 f0 fe ff ff 	mov    %r12,-0x110(%rbp)
ffffffff8b3f7908:	c7 85 f8 fe ff ff 00 	movl   $0x0,-0x108(%rbp)
ffffffff8b3f790f:	00 00 00 
ffffffff8b3f7912:	49 8b 7c 24 08       	mov    0x8(%r12),%rdi
ffffffff8b3f7917:	e8 74 71 b5 ff       	call   ffffffff8af4ea90 <handler_619_body-0x4a8bc0>
ffffffff8b3f791c:	45 85 ff             	test   %r15d,%r15d
ffffffff8b3f791f:	0f 84 1e 03 00 00    	je     ffffffff8b3f7c43 <frame_candidate_a37700+0x543>
ffffffff8b3f7925:	48 8d 3d ea 28 85 00 	lea    0x8528ea(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f792c:	48 8d 35 74 f7 91 00 	lea    0x91f774(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7933:	ba 26 02 00 00       	mov    $0x226,%edx
ffffffff8b3f7938:	e9 58 01 00 00       	jmp    ffffffff8b3f7a95 <frame_candidate_a37700+0x395>
ffffffff8b3f793d:	48 8b bb a8 00 00 00 	mov    0xa8(%rbx),%rdi
ffffffff8b3f7944:	48 8d 35 76 99 84 00 	lea    0x849976(%rip),%rsi        # ffffffff8bc412c1 <frame_candidate_a39640+0x847c81>
ffffffff8b3f794b:	31 d2                	xor    %edx,%edx
ffffffff8b3f794d:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f794f:	e8 fc 98 ba ff       	call   ffffffff8afa1250 <handler_619_body-0x456400>
ffffffff8b3f7954:	85 c0                	test   %eax,%eax
ffffffff8b3f7956:	0f 84 88 00 00 00    	je     ffffffff8b3f79e4 <frame_candidate_a37700+0x2e4>
ffffffff8b3f795c:	48 8b 43 40          	mov    0x40(%rbx),%rax
ffffffff8b3f7960:	4c 89 a5 a0 fe ff ff 	mov    %r12,-0x160(%rbp)
ffffffff8b3f7967:	41 bc ff ff ff ff    	mov    $0xffffffff,%r12d
ffffffff8b3f796d:	4c 89 bd a8 fe ff ff 	mov    %r15,-0x158(%rbp)
ffffffff8b3f7974:	8b 78 28             	mov    0x28(%rax),%edi
ffffffff8b3f7977:	c1 ef 17             	shr    $0x17,%edi
ffffffff8b3f797a:	83 e7 02             	and    $0x2,%edi
ffffffff8b3f797d:	74 08                	je     ffffffff8b3f7987 <frame_candidate_a37700+0x287>
ffffffff8b3f797f:	e8 6c a3 b2 ff       	call   ffffffff8af21cf0 <handler_619_body-0x4d5960>
ffffffff8b3f7984:	41 89 c4             	mov    %eax,%r12d
ffffffff8b3f7987:	48 8b 43 38          	mov    0x38(%rbx),%rax
ffffffff8b3f798b:	4c 8b 78 30          	mov    0x30(%rax),%r15
ffffffff8b3f798f:	48 8d 05 4a 17 83 ff 	lea    -0x7ce8b6(%rip),%rax        # ffffffff8ac290e0 <handler_619_body-0x7ce570>
ffffffff8b3f7996:	4c 29 f8             	sub    %r15,%rax
ffffffff8b3f7999:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f799d:	48 83 f8 72          	cmp    $0x72,%rax
ffffffff8b3f79a1:	0f 87 91 04 00 00    	ja     ffffffff8b3f7e38 <frame_candidate_a37700+0x738>
ffffffff8b3f79a7:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f79aa:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8b3f79af:	41 ff d7             	call   *%r15
ffffffff8b3f79b2:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f79b5:	41 83 fc ff          	cmp    $0xffffffff,%r12d
ffffffff8b3f79b9:	74 08                	je     ffffffff8b3f79c3 <frame_candidate_a37700+0x2c3>
ffffffff8b3f79bb:	44 89 e7             	mov    %r12d,%edi
ffffffff8b3f79be:	e8 1d a4 b2 ff       	call   ffffffff8af21de0 <handler_619_body-0x4d5870>
ffffffff8b3f79c3:	45 85 ff             	test   %r15d,%r15d
ffffffff8b3f79c6:	0f 84 0f 02 00 00    	je     ffffffff8b3f7bdb <frame_candidate_a37700+0x4db>
ffffffff8b3f79cc:	48 8d 3d 43 28 85 00 	lea    0x852843(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f79d3:	48 8d 35 cd f6 91 00 	lea    0x91f6cd(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f79da:	ba ef 01 00 00       	mov    $0x1ef,%edx
ffffffff8b3f79df:	e9 b1 00 00 00       	jmp    ffffffff8b3f7a95 <frame_candidate_a37700+0x395>
ffffffff8b3f79e4:	41 0f b6 47 1a       	movzbl 0x1a(%r15),%eax
ffffffff8b3f79e9:	3c 01                	cmp    $0x1,%al
ffffffff8b3f79eb:	0f 84 54 fe ff ff    	je     ffffffff8b3f7845 <frame_candidate_a37700+0x145>
ffffffff8b3f79f1:	48 8b bb a8 00 00 00 	mov    0xa8(%rbx),%rdi
ffffffff8b3f79f8:	48 8d 35 a2 b3 87 00 	lea    0x87b3a2(%rip),%rsi        # ffffffff8bc72da1 <frame_candidate_a39640+0x879761>
ffffffff8b3f79ff:	48 8d 95 b0 fe ff ff 	lea    -0x150(%rbp),%rdx
ffffffff8b3f7a06:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7a08:	e8 c3 75 ba ff       	call   ffffffff8af9efd0 <handler_619_body-0x458680>
ffffffff8b3f7a0d:	85 c0                	test   %eax,%eax
ffffffff8b3f7a0f:	74 26                	je     ffffffff8b3f7a37 <frame_candidate_a37700+0x337>
ffffffff8b3f7a11:	48 8d 3d fe 27 85 00 	lea    0x8527fe(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7a18:	48 8d 35 88 f6 91 00 	lea    0x91f688(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7a1f:	41 bf 16 00 00 00    	mov    $0x16,%r15d
ffffffff8b3f7a25:	ba 4e 02 00 00       	mov    $0x24e,%edx
ffffffff8b3f7a2a:	b9 16 00 00 00       	mov    $0x16,%ecx
ffffffff8b3f7a2f:	41 b8 16 00 00 00    	mov    $0x16,%r8d
ffffffff8b3f7a35:	eb 64                	jmp    ffffffff8b3f7a9b <frame_candidate_a37700+0x39b>
ffffffff8b3f7a37:	4c 8b 85 b0 fe ff ff 	mov    -0x150(%rbp),%r8
ffffffff8b3f7a3e:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b3f7a42:	4c 8d bd e8 fe ff ff 	lea    -0x118(%rbp),%r15
ffffffff8b3f7a49:	ba 44 00 00 00       	mov    $0x44,%edx
ffffffff8b3f7a4e:	31 f6                	xor    %esi,%esi
ffffffff8b3f7a50:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8b3f7a55:	41 b9 9c ff ff ff    	mov    $0xffffff9c,%r9d
ffffffff8b3f7a5b:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7a5e:	41 56                	push   %r14
ffffffff8b3f7a60:	6a 00                	push   $0x0
ffffffff8b3f7a62:	6a 00                	push   $0x0
ffffffff8b3f7a64:	e8 77 2c bc ff       	call   ffffffff8afba6e0 <handler_619_body-0x43cf70>
ffffffff8b3f7a69:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b3f7a6d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7a70:	e8 ab 11 bc ff       	call   ffffffff8afb8c20 <handler_619_body-0x43ea30>
ffffffff8b3f7a75:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
ffffffff8b3f7a7b:	85 c0                	test   %eax,%eax
ffffffff8b3f7a7d:	74 46                	je     ffffffff8b3f7ac5 <frame_candidate_a37700+0x3c5>
ffffffff8b3f7a7f:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f7a82:	48 8d 3d 8d 27 85 00 	lea    0x85278d(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7a89:	48 8d 35 17 f6 91 00 	lea    0x91f617(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7a90:	ba 57 02 00 00       	mov    $0x257,%edx
ffffffff8b3f7a95:	44 89 f9             	mov    %r15d,%ecx
ffffffff8b3f7a98:	45 89 f8             	mov    %r15d,%r8d
ffffffff8b3f7a9b:	31 c0                	xor    %eax,%eax
ffffffff8b3f7a9d:	e8 6e 59 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f7aa2:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8b3f7aa6:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b3f7aaa:	0f 85 81 03 00 00    	jne    ffffffff8b3f7e31 <frame_candidate_a37700+0x731>
ffffffff8b3f7ab0:	44 89 f8             	mov    %r15d,%eax
ffffffff8b3f7ab3:	48 81 c4 38 01 00 00 	add    $0x138,%rsp
ffffffff8b3f7aba:	5b                   	pop    %rbx
ffffffff8b3f7abb:	41 5c                	pop    %r12
ffffffff8b3f7abd:	41 5d                	pop    %r13
ffffffff8b3f7abf:	41 5e                	pop    %r14
ffffffff8b3f7ac1:	41 5f                	pop    %r15
ffffffff8b3f7ac3:	5d                   	pop    %rbp
ffffffff8b3f7ac4:	c3                   	ret
ffffffff8b3f7ac5:	4c 8b bd 48 ff ff ff 	mov    -0xb8(%rbp),%r15
ffffffff8b3f7acc:	48 8d bd e8 fe ff ff 	lea    -0x118(%rbp),%rdi
ffffffff8b3f7ad3:	be df ff ff ff       	mov    $0xffffffdf,%esi
ffffffff8b3f7ad8:	e8 a3 2c bc ff       	call   ffffffff8afba780 <handler_619_body-0x43ced0>
ffffffff8b3f7add:	48 8d b5 bc fe ff ff 	lea    -0x144(%rbp),%rsi
ffffffff8b3f7ae4:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7ae7:	e8 14 4f b1 ff       	call   ffffffff8af0ca00 <handler_619_body-0x4eac50>
ffffffff8b3f7aec:	85 c0                	test   %eax,%eax
ffffffff8b3f7aee:	0f 84 29 01 00 00    	je     ffffffff8b3f7c1d <frame_candidate_a37700+0x51d>
ffffffff8b3f7af4:	48 8b 83 98 00 00 00 	mov    0x98(%rbx),%rax
ffffffff8b3f7afb:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7afd:	48 8d 15 74 2f 0a 01 	lea    0x10a2f74(%rip),%rdx        # ffffffff8c49aa78 <frame_candidate_a39640+0x10a1438>
ffffffff8b3f7b04:	48 8d b5 c0 fe ff ff 	lea    -0x140(%rbp),%rsi
ffffffff8b3f7b0b:	a8 01                	test   $0x1,%al
ffffffff8b3f7b0d:	49 8b 86 40 01 00 00 	mov    0x140(%r14),%rax
ffffffff8b3f7b14:	48 89 95 c0 fe ff ff 	mov    %rdx,-0x140(%rbp)
ffffffff8b3f7b1b:	4c 89 bd c8 fe ff ff 	mov    %r15,-0x138(%rbp)
ffffffff8b3f7b22:	0f 94 c1             	sete   %cl
ffffffff8b3f7b25:	83 c9 02             	or     $0x2,%ecx
ffffffff8b3f7b28:	c1 e1 07             	shl    $0x7,%ecx
ffffffff8b3f7b2b:	89 8d d0 fe ff ff    	mov    %ecx,-0x130(%rbp)
ffffffff8b3f7b31:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
ffffffff8b3f7b38:	4c 89 b5 e0 fe ff ff 	mov    %r14,-0x120(%rbp)
ffffffff8b3f7b3f:	49 8b 7f 08          	mov    0x8(%r15),%rdi
ffffffff8b3f7b43:	e8 b8 42 b5 ff       	call   ffffffff8af4be00 <handler_619_body-0x4ab850>
ffffffff8b3f7b48:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
ffffffff8b3f7b4e:	85 c0                	test   %eax,%eax
ffffffff8b3f7b50:	74 3d                	je     ffffffff8b3f7b8f <frame_candidate_a37700+0x48f>
ffffffff8b3f7b52:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f7b55:	be 50 01 00 00       	mov    $0x150,%esi
ffffffff8b3f7b5a:	e8 d1 7e 0a 00       	call   ffffffff8b49fa30 <frame_candidate_a39640+0xa63f0>
ffffffff8b3f7b5f:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
ffffffff8b3f7b65:	85 c0                	test   %eax,%eax
ffffffff8b3f7b67:	74 26                	je     ffffffff8b3f7b8f <frame_candidate_a37700+0x48f>
ffffffff8b3f7b69:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7b6c:	e8 cf 28 b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f7b71:	8b 8d bc fe ff ff    	mov    -0x144(%rbp),%ecx
ffffffff8b3f7b77:	48 8d 3d 98 26 85 00 	lea    0x852698(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7b7e:	48 8d 35 22 f5 91 00 	lea    0x91f522(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7b85:	ba 73 02 00 00       	mov    $0x273,%edx
ffffffff8b3f7b8a:	e9 8d 01 00 00       	jmp    ffffffff8b3f7d1c <frame_candidate_a37700+0x61c>
ffffffff8b3f7b8f:	f6 83 9a 00 00 00 01 	testb  $0x1,0x9a(%rbx)
ffffffff8b3f7b96:	0f 85 42 01 00 00    	jne    ffffffff8b3f7cde <frame_candidate_a37700+0x5de>
ffffffff8b3f7b9c:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7b9f:	48 89 de             	mov    %rbx,%rsi
ffffffff8b3f7ba2:	e8 09 1c 00 00       	call   ffffffff8b3f97b0 <frame_candidate_a39640+0x170>
ffffffff8b3f7ba7:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
ffffffff8b3f7bad:	85 c0                	test   %eax,%eax
ffffffff8b3f7baf:	0f 84 7d 01 00 00    	je     ffffffff8b3f7d32 <frame_candidate_a37700+0x632>
ffffffff8b3f7bb5:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7bb8:	e8 63 25 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f7bbd:	8b 8d bc fe ff ff    	mov    -0x144(%rbp),%ecx
ffffffff8b3f7bc3:	48 8d 3d 4c 26 85 00 	lea    0x85264c(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7bca:	48 8d 35 d6 f4 91 00 	lea    0x91f4d6(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7bd1:	ba 88 02 00 00       	mov    $0x288,%edx
ffffffff8b3f7bd6:	e9 41 01 00 00       	jmp    ffffffff8b3f7d1c <frame_candidate_a37700+0x61c>
ffffffff8b3f7bdb:	b8 13 01 00 00       	mov    $0x113,%eax
ffffffff8b3f7be0:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f7be3:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b3f7be6:	31 f6                	xor    %esi,%esi
ffffffff8b3f7be8:	c4 e2 78 f7 83 98 00 	bextr  %eax,0x98(%rbx),%eax
ffffffff8b3f7bef:	00 00 
ffffffff8b3f7bf1:	8d 54 00 04          	lea    0x4(%rax,%rax,1),%edx
ffffffff8b3f7bf5:	e8 66 28 b1 ff       	call   ffffffff8af0a460 <handler_619_body-0x4ed1f0>
ffffffff8b3f7bfa:	85 c0                	test   %eax,%eax
ffffffff8b3f7bfc:	0f 84 47 01 00 00    	je     ffffffff8b3f7d49 <frame_candidate_a37700+0x649>
ffffffff8b3f7c02:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f7c05:	48 8d 3d 0a 26 85 00 	lea    0x85260a(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7c0c:	48 8d 35 94 f4 91 00 	lea    0x91f494(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7c13:	ba fb 01 00 00       	mov    $0x1fb,%edx
ffffffff8b3f7c18:	e9 78 fe ff ff       	jmp    ffffffff8b3f7a95 <frame_candidate_a37700+0x395>
ffffffff8b3f7c1d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7c20:	e8 1b 28 b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f7c25:	8b 8d bc fe ff ff    	mov    -0x144(%rbp),%ecx
ffffffff8b3f7c2b:	48 8d 3d e4 25 85 00 	lea    0x8525e4(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7c32:	48 8d 35 6e f4 91 00 	lea    0x91f46e(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7c39:	ba 60 02 00 00       	mov    $0x260,%edx
ffffffff8b3f7c3e:	e9 d9 00 00 00       	jmp    ffffffff8b3f7d1c <frame_candidate_a37700+0x61c>
ffffffff8b3f7c43:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
ffffffff8b3f7c4a:	80 78 19 01          	cmpb   $0x1,0x19(%rax)
ffffffff8b3f7c4e:	75 28                	jne    ffffffff8b3f7c78 <frame_candidate_a37700+0x578>
ffffffff8b3f7c50:	f6 83 9a 00 00 00 08 	testb  $0x8,0x9a(%rbx)
ffffffff8b3f7c57:	41 bf 01 00 00 00    	mov    $0x1,%r15d
ffffffff8b3f7c5d:	0f 84 3f fe ff ff    	je     ffffffff8b3f7aa2 <frame_candidate_a37700+0x3a2>
ffffffff8b3f7c63:	48 8d 3d fc 20 8a 00 	lea    0x8a20fc(%rip),%rdi        # ffffffff8bc99d66 <frame_candidate_a39640+0x8a0726>
ffffffff8b3f7c6a:	48 8d 35 f8 f3 90 00 	lea    0x90f3f8(%rip),%rsi        # ffffffff8bd07069 <frame_candidate_a39640+0x90da29>
ffffffff8b3f7c71:	31 c0                	xor    %eax,%eax
ffffffff8b3f7c73:	e8 98 57 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f7c78:	48 8d 3d e9 36 ac 02 	lea    0x2ac36e9(%rip),%rdi        # ffffffff8debb368 <frame_candidate_a39640+0x2ac1d28>
ffffffff8b3f7c7f:	31 f6                	xor    %esi,%esi
ffffffff8b3f7c81:	31 d2                	xor    %edx,%edx
ffffffff8b3f7c83:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7c85:	e8 96 3e 21 00       	call   ffffffff8b60bb20 <frame_candidate_a39640+0x2124e0>
ffffffff8b3f7c8a:	4c 8b a5 a0 fe ff ff 	mov    -0x160(%rbp),%r12
ffffffff8b3f7c91:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8b3f7c96:	31 f6                	xor    %esi,%esi
ffffffff8b3f7c98:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7c9a:	49 8b 7c 24 10       	mov    0x10(%r12),%rdi
ffffffff8b3f7c9f:	e8 5c 5c dc ff       	call   ffffffff8b1bd900 <handler_619_body-0x239d50>
ffffffff8b3f7ca4:	48 8d 3d bd 36 ac 02 	lea    0x2ac36bd(%rip),%rdi        # ffffffff8debb368 <frame_candidate_a39640+0x2ac1d28>
ffffffff8b3f7cab:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f7cae:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
ffffffff8b3f7cb4:	31 f6                	xor    %esi,%esi
ffffffff8b3f7cb6:	31 d2                	xor    %edx,%edx
ffffffff8b3f7cb8:	e8 f3 47 21 00       	call   ffffffff8b60c4b0 <frame_candidate_a39640+0x212e70>
ffffffff8b3f7cbd:	45 85 ff             	test   %r15d,%r15d
ffffffff8b3f7cc0:	0f 84 dd 00 00 00    	je     ffffffff8b3f7da3 <frame_candidate_a37700+0x6a3>
ffffffff8b3f7cc6:	48 8d 3d 49 25 85 00 	lea    0x852549(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7ccd:	48 8d 35 d3 f3 91 00 	lea    0x91f3d3(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7cd4:	ba 3c 02 00 00       	mov    $0x23c,%edx
ffffffff8b3f7cd9:	e9 b7 fd ff ff       	jmp    ffffffff8b3f7a95 <frame_candidate_a37700+0x395>
ffffffff8b3f7cde:	49 8b 4c 24 20       	mov    0x20(%r12),%rcx
ffffffff8b3f7ce3:	49 8b 47 30          	mov    0x30(%r15),%rax
ffffffff8b3f7ce7:	48 3b 41 30          	cmp    0x30(%rcx),%rax
ffffffff8b3f7ceb:	74 0a                	je     ffffffff8b3f7cf7 <frame_candidate_a37700+0x5f7>
ffffffff8b3f7ced:	c7 85 bc fe ff ff 16 	movl   $0x16,-0x144(%rbp)
ffffffff8b3f7cf4:	00 00 00 
ffffffff8b3f7cf7:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7cfa:	e8 41 27 b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f7cff:	8b 8d bc fe ff ff    	mov    -0x144(%rbp),%ecx
ffffffff8b3f7d05:	85 c9                	test   %ecx,%ecx
ffffffff8b3f7d07:	74 29                	je     ffffffff8b3f7d32 <frame_candidate_a37700+0x632>
ffffffff8b3f7d09:	48 8d 3d 06 25 85 00 	lea    0x852506(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7d10:	48 8d 35 90 f3 91 00 	lea    0x91f390(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7d17:	ba 81 02 00 00       	mov    $0x281,%edx
ffffffff8b3f7d1c:	41 89 c8             	mov    %ecx,%r8d
ffffffff8b3f7d1f:	31 c0                	xor    %eax,%eax
ffffffff8b3f7d21:	e8 ea 56 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f7d26:	44 8b bd bc fe ff ff 	mov    -0x144(%rbp),%r15d
ffffffff8b3f7d2d:	e9 70 fd ff ff       	jmp    ffffffff8b3f7aa2 <frame_candidate_a37700+0x3a2>
ffffffff8b3f7d32:	48 8b b5 b0 fe ff ff 	mov    -0x150(%rbp),%rsi
ffffffff8b3f7d39:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f7d3c:	e8 df 96 ba ff       	call   ffffffff8afa1420 <handler_619_body-0x456230>
ffffffff8b3f7d41:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b3f7d44:	e9 59 fd ff ff       	jmp    ffffffff8b3f7aa2 <frame_candidate_a37700+0x3a2>
ffffffff8b3f7d49:	4c 8d 25 18 36 ac 02 	lea    0x2ac3618(%rip),%r12        # ffffffff8debb368 <frame_candidate_a39640+0x2ac1d28>
ffffffff8b3f7d50:	31 f6                	xor    %esi,%esi
ffffffff8b3f7d52:	31 d2                	xor    %edx,%edx
ffffffff8b3f7d54:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7d56:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f7d59:	e8 c2 3d 21 00       	call   ffffffff8b60bb20 <frame_candidate_a39640+0x2124e0>
ffffffff8b3f7d5e:	48 8b 85 a0 fe ff ff 	mov    -0x160(%rbp),%rax
ffffffff8b3f7d65:	ba ff ff ff ff       	mov    $0xffffffff,%edx
ffffffff8b3f7d6a:	31 f6                	xor    %esi,%esi
ffffffff8b3f7d6c:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7d6e:	48 8b 78 10          	mov    0x10(%rax),%rdi
ffffffff8b3f7d72:	e8 89 5b dc ff       	call   ffffffff8b1bd900 <handler_619_body-0x239d50>
ffffffff8b3f7d77:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f7d7a:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f7d7d:	31 f6                	xor    %esi,%esi
ffffffff8b3f7d7f:	31 d2                	xor    %edx,%edx
ffffffff8b3f7d81:	e8 2a 47 21 00       	call   ffffffff8b60c4b0 <frame_candidate_a39640+0x212e70>
ffffffff8b3f7d86:	45 85 ff             	test   %r15d,%r15d
ffffffff8b3f7d89:	74 5a                	je     ffffffff8b3f7de5 <frame_candidate_a37700+0x6e5>
ffffffff8b3f7d8b:	48 8d 3d 84 24 85 00 	lea    0x852484(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7d92:	48 8d 35 0e f3 91 00 	lea    0x91f30e(%rip),%rsi        # ffffffff8bd170a7 <frame_candidate_a39640+0x91da67>
ffffffff8b3f7d99:	ba 04 02 00 00       	mov    $0x204,%edx
ffffffff8b3f7d9e:	e9 f2 fc ff ff       	jmp    ffffffff8b3f7a95 <frame_candidate_a37700+0x395>
ffffffff8b3f7da3:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
ffffffff8b3f7daa:	4c 8d 7b 18          	lea    0x18(%rbx),%r15
ffffffff8b3f7dae:	31 f6                	xor    %esi,%esi
ffffffff8b3f7db0:	31 d2                	xor    %edx,%edx
ffffffff8b3f7db2:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7db4:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7db7:	c6 40 1a 00          	movb   $0x0,0x1a(%rax)
ffffffff8b3f7dbb:	e8 40 ec a8 ff       	call   ffffffff8ae86a00 <handler_619_body-0x570c50>
ffffffff8b3f7dc0:	80 a3 98 00 00 00 fe 	andb   $0xfe,0x98(%rbx)
ffffffff8b3f7dc7:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7dca:	31 f6                	xor    %esi,%esi
ffffffff8b3f7dcc:	31 d2                	xor    %edx,%edx
ffffffff8b3f7dce:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7dd0:	e8 cb f1 a8 ff       	call   ffffffff8ae86fa0 <handler_619_body-0x5706b0>
ffffffff8b3f7dd5:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
ffffffff8b3f7ddc:	c6 40 19 00          	movb   $0x0,0x19(%rax)
ffffffff8b3f7de0:	e9 0c fc ff ff       	jmp    ffffffff8b3f79f1 <frame_candidate_a37700+0x2f1>
ffffffff8b3f7de5:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
ffffffff8b3f7dec:	4c 8d 7b 18          	lea    0x18(%rbx),%r15
ffffffff8b3f7df0:	31 f6                	xor    %esi,%esi
ffffffff8b3f7df2:	31 d2                	xor    %edx,%edx
ffffffff8b3f7df4:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7df6:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7df9:	c6 40 1a 01          	movb   $0x1,0x1a(%rax)
ffffffff8b3f7dfd:	e8 fe eb a8 ff       	call   ffffffff8ae86a00 <handler_619_body-0x570c50>
ffffffff8b3f7e02:	48 8d 3d 53 83 96 00 	lea    0x968353(%rip),%rdi        # ffffffff8bd6015c <frame_candidate_a39640+0x966b1c>
ffffffff8b3f7e09:	31 c0                	xor    %eax,%eax
ffffffff8b3f7e0b:	e8 00 56 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f7e10:	80 8b 98 00 00 00 01 	orb    $0x1,0x98(%rbx)
ffffffff8b3f7e17:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7e1a:	31 f6                	xor    %esi,%esi
ffffffff8b3f7e1c:	31 d2                	xor    %edx,%edx
ffffffff8b3f7e1e:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f7e20:	e8 7b f1 a8 ff       	call   ffffffff8ae86fa0 <handler_619_body-0x5706b0>
ffffffff8b3f7e25:	4c 8b a5 a0 fe ff ff 	mov    -0x160(%rbp),%r12
ffffffff8b3f7e2c:	e9 c0 fb ff ff       	jmp    ffffffff8b3f79f1 <frame_candidate_a37700+0x2f1>
ffffffff8b3f7e31:	e8 7a 58 cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f7e36:	0f 0b                	ud2
ffffffff8b3f7e38:	48 8d 3d 41 0e b3 01 	lea    0x1b30e41(%rip),%rdi        # ffffffff8cf28c80 <frame_candidate_a39640+0x1b2f640>
ffffffff8b3f7e3f:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b3f7e42:	e8 79 7a a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f7e47:	e9 5b fb ff ff       	jmp    ffffffff8b3f79a7 <frame_candidate_a37700+0x2a7>
ffffffff8b3f7e4c:	90                   	nop
ffffffff8b3f7e4d:	90                   	nop
ffffffff8b3f7e4e:	90                   	nop
ffffffff8b3f7e4f:	90                   	nop

ffffffff8b3f7e50 <frame_candidate_a37e50>:
ffffffff8b3f7e50:	55                   	push   %rbp
ffffffff8b3f7e51:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f7e54:	41 57                	push   %r15
ffffffff8b3f7e56:	41 56                	push   %r14
ffffffff8b3f7e58:	41 54                	push   %r12
ffffffff8b3f7e5a:	53                   	push   %rbx
ffffffff8b3f7e5b:	48 81 ec 40 01 00 00 	sub    $0x140,%rsp
ffffffff8b3f7e62:	4c 8d 25 a7 44 ee 02 	lea    0x2ee44a7(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f7e69:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b3f7e6d:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
ffffffff8b3f7e71:	48 85 f6             	test   %rsi,%rsi
ffffffff8b3f7e74:	74 58                	je     ffffffff8b3f7ece <frame_candidate_a37e50+0x7e>
ffffffff8b3f7e76:	49 89 fe             	mov    %rdi,%r14
ffffffff8b3f7e79:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8b3f7e80:	00 00 
ffffffff8b3f7e82:	49 89 f7             	mov    %rsi,%r15
ffffffff8b3f7e85:	48 8d 35 b1 00 96 00 	lea    0x9600b1(%rip),%rsi        # ffffffff8bd57f3d <frame_candidate_a39640+0x95e8fd>
ffffffff8b3f7e8c:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b3f7e8f:	31 d2                	xor    %edx,%edx
ffffffff8b3f7e91:	e8 4a 25 1e 00       	call   ffffffff8b5da3e0 <frame_candidate_a39640+0x1e0da0>
ffffffff8b3f7e96:	48 8d b5 48 ff ff ff 	lea    -0xb8(%rbp),%rsi
ffffffff8b3f7e9d:	ba 90 00 00 00       	mov    $0x90,%edx
ffffffff8b3f7ea2:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f7ea5:	e8 d6 13 82 ff       	call   ffffffff8ac19280 <handler_619_body-0x7de3d0>
ffffffff8b3f7eaa:	85 c0                	test   %eax,%eax
ffffffff8b3f7eac:	75 25                	jne    ffffffff8b3f7ed3 <frame_candidate_a37e50+0x83>
ffffffff8b3f7eae:	48 8d bd 50 ff ff ff 	lea    -0xb0(%rbp),%rdi
ffffffff8b3f7eb5:	48 8d b5 a8 fe ff ff 	lea    -0x158(%rbp),%rsi
ffffffff8b3f7ebc:	e8 5f 97 ba ff       	call   ffffffff8afa1620 <handler_619_body-0x456030>
ffffffff8b3f7ec1:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f7ec4:	48 89 de             	mov    %rbx,%rsi
ffffffff8b3f7ec7:	e8 84 96 ba ff       	call   ffffffff8afa1550 <handler_619_body-0x456100>
ffffffff8b3f7ecc:	eb 05                	jmp    ffffffff8b3f7ed3 <frame_candidate_a37e50+0x83>
ffffffff8b3f7ece:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8b3f7ed3:	49 8b 0c 24          	mov    (%r12),%rcx
ffffffff8b3f7ed7:	48 3b 4d d8          	cmp    -0x28(%rbp),%rcx
ffffffff8b3f7edb:	75 10                	jne    ffffffff8b3f7eed <frame_candidate_a37e50+0x9d>
ffffffff8b3f7edd:	48 81 c4 40 01 00 00 	add    $0x140,%rsp
ffffffff8b3f7ee4:	5b                   	pop    %rbx
ffffffff8b3f7ee5:	41 5c                	pop    %r12
ffffffff8b3f7ee7:	41 5e                	pop    %r14
ffffffff8b3f7ee9:	41 5f                	pop    %r15
ffffffff8b3f7eeb:	5d                   	pop    %rbp
ffffffff8b3f7eec:	c3                   	ret
ffffffff8b3f7eed:	e8 be 57 cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f7ef2:	0f 0b                	ud2
ffffffff8b3f7ef4:	90                   	nop
ffffffff8b3f7ef5:	90                   	nop
ffffffff8b3f7ef6:	90                   	nop
ffffffff8b3f7ef7:	90                   	nop
ffffffff8b3f7ef8:	90                   	nop
ffffffff8b3f7ef9:	90                   	nop
ffffffff8b3f7efa:	90                   	nop
ffffffff8b3f7efb:	90                   	nop
ffffffff8b3f7efc:	90                   	nop
ffffffff8b3f7efd:	90                   	nop
ffffffff8b3f7efe:	90                   	nop
ffffffff8b3f7eff:	90                   	nop

ffffffff8b3f7f00 <frame_candidate_a37f00>:
ffffffff8b3f7f00:	55                   	push   %rbp
ffffffff8b3f7f01:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f7f04:	41 57                	push   %r15
ffffffff8b3f7f06:	41 56                	push   %r14
ffffffff8b3f7f08:	41 55                	push   %r13
ffffffff8b3f7f0a:	41 54                	push   %r12
ffffffff8b3f7f0c:	53                   	push   %rbx
ffffffff8b3f7f0d:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8b3f7f11:	4c 8d 25 f8 43 ee 02 	lea    0x2ee43f8(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f7f18:	41 89 f5             	mov    %esi,%r13d
ffffffff8b3f7f1b:	48 89 f9             	mov    %rdi,%rcx
ffffffff8b3f7f1e:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b3f7f22:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b3f7f26:	48 8b 9f 98 02 00 00 	mov    0x298(%rdi),%rbx
ffffffff8b3f7f2d:	48 8b 43 30          	mov    0x30(%rbx),%rax
ffffffff8b3f7f31:	83 bb 10 04 00 00 00 	cmpl   $0x0,0x410(%rbx)
ffffffff8b3f7f38:	8b 40 20             	mov    0x20(%rax),%eax
ffffffff8b3f7f3b:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8b3f7f3f:	0f 88 aa 00 00 00    	js     ffffffff8b3f7fef <frame_candidate_a37f00+0xef>
ffffffff8b3f7f45:	48 8b 41 40          	mov    0x40(%rcx),%rax
ffffffff8b3f7f49:	49 89 df             	mov    %rbx,%r15
ffffffff8b3f7f4c:	41 bc ff ff ff ff    	mov    $0xffffffff,%r12d
ffffffff8b3f7f52:	8b 78 28             	mov    0x28(%rax),%edi
ffffffff8b3f7f55:	c1 ef 17             	shr    $0x17,%edi
ffffffff8b3f7f58:	83 e7 02             	and    $0x2,%edi
ffffffff8b3f7f5b:	74 0e                	je     ffffffff8b3f7f6b <frame_candidate_a37f00+0x6b>
ffffffff8b3f7f5d:	48 89 cb             	mov    %rcx,%rbx
ffffffff8b3f7f60:	e8 8b 9d b2 ff       	call   ffffffff8af21cf0 <handler_619_body-0x4d5960>
ffffffff8b3f7f65:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b3f7f68:	41 89 c4             	mov    %eax,%r12d
ffffffff8b3f7f6b:	48 8b 41 38          	mov    0x38(%rcx),%rax
ffffffff8b3f7f6f:	4c 8b 70 30          	mov    0x30(%rax),%r14
ffffffff8b3f7f73:	48 8d 05 66 11 83 ff 	lea    -0x7cee9a(%rip),%rax        # ffffffff8ac290e0 <handler_619_body-0x7ce570>
ffffffff8b3f7f7a:	4c 29 f0             	sub    %r14,%rax
ffffffff8b3f7f7d:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f7f81:	48 83 f8 72          	cmp    $0x72,%rax
ffffffff8b3f7f85:	0f 87 f5 0a 00 00    	ja     ffffffff8b3f8a80 <frame_candidate_a37f00+0xb80>
ffffffff8b3f7f8b:	48 89 cf             	mov    %rcx,%rdi
ffffffff8b3f7f8e:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8b3f7f93:	48 89 cb             	mov    %rcx,%rbx
ffffffff8b3f7f96:	41 ff d6             	call   *%r14
ffffffff8b3f7f99:	41 89 c6             	mov    %eax,%r14d
ffffffff8b3f7f9c:	41 83 fc ff          	cmp    $0xffffffff,%r12d
ffffffff8b3f7fa0:	74 08                	je     ffffffff8b3f7faa <frame_candidate_a37f00+0xaa>
ffffffff8b3f7fa2:	44 89 e7             	mov    %r12d,%edi
ffffffff8b3f7fa5:	e8 36 9e b2 ff       	call   ffffffff8af21de0 <handler_619_body-0x4d5870>
ffffffff8b3f7faa:	4c 8d 25 5f 43 ee 02 	lea    0x2ee435f(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f7fb1:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b3f7fb4:	4c 89 fb             	mov    %r15,%rbx
ffffffff8b3f7fb7:	45 85 f6             	test   %r14d,%r14d
ffffffff8b3f7fba:	74 33                	je     ffffffff8b3f7fef <frame_candidate_a37f00+0xef>
ffffffff8b3f7fbc:	48 8d 3d 53 22 85 00 	lea    0x852253(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f7fc3:	48 8d 35 cb d3 95 00 	lea    0x95d3cb(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f7fca:	ba f1 0f 00 00       	mov    $0xff1,%edx
ffffffff8b3f7fcf:	44 89 f1             	mov    %r14d,%ecx
ffffffff8b3f7fd2:	45 89 f0             	mov    %r14d,%r8d
ffffffff8b3f7fd5:	31 c0                	xor    %eax,%eax
ffffffff8b3f7fd7:	e8 34 54 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f7fdc:	41 83 fe 06          	cmp    $0x6,%r14d
ffffffff8b3f7fe0:	41 bd 13 00 00 00    	mov    $0x13,%r13d
ffffffff8b3f7fe6:	45 0f 45 ee          	cmovne %r14d,%r13d
ffffffff8b3f7fea:	e9 61 0a 00 00       	jmp    ffffffff8b3f8a50 <frame_candidate_a37f00+0xb50>
ffffffff8b3f7fef:	ba 03 00 00 00       	mov    $0x3,%edx
ffffffff8b3f7ff4:	41 f7 c5 00 00 08 00 	test   $0x80000,%r13d
ffffffff8b3f7ffb:	75 55                	jne    ffffffff8b3f8052 <frame_candidate_a37f00+0x152>
ffffffff8b3f7ffd:	48 8b bb 10 02 00 00 	mov    0x210(%rbx),%rdi
ffffffff8b3f8004:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8b3f8009:	48 85 ff             	test   %rdi,%rdi
ffffffff8b3f800c:	74 44                	je     ffffffff8b3f8052 <frame_candidate_a37f00+0x152>
ffffffff8b3f800e:	49 89 de             	mov    %rbx,%r14
ffffffff8b3f8011:	48 89 cb             	mov    %rcx,%rbx
ffffffff8b3f8014:	e8 f7 20 b1 ff       	call   ffffffff8af0a110 <handler_619_body-0x4ed540>
ffffffff8b3f8019:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b3f801c:	4c 89 f3             	mov    %r14,%rbx
ffffffff8b3f801f:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8b3f8024:	83 f8 02             	cmp    $0x2,%eax
ffffffff8b3f8027:	7c 29                	jl     ffffffff8b3f8052 <frame_candidate_a37f00+0x152>
ffffffff8b3f8029:	48 8d 3d e6 21 85 00 	lea    0x8521e6(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8030:	48 8d 35 5e d3 95 00 	lea    0x95d35e(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f8037:	41 bd 10 00 00 00    	mov    $0x10,%r13d
ffffffff8b3f803d:	ba 01 10 00 00       	mov    $0x1001,%edx
ffffffff8b3f8042:	b9 10 00 00 00       	mov    $0x10,%ecx
ffffffff8b3f8047:	41 b8 10 00 00 00    	mov    $0x10,%r8d
ffffffff8b3f804d:	e9 c7 01 00 00       	jmp    ffffffff8b3f8219 <frame_candidate_a37f00+0x319>
ffffffff8b3f8052:	65 4c 8b 34 25 00 00 	mov    %gs:0x0,%r14
ffffffff8b3f8059:	00 00 
ffffffff8b3f805b:	48 89 cf             	mov    %rcx,%rdi
ffffffff8b3f805e:	49 89 cf             	mov    %rcx,%r15
ffffffff8b3f8061:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b3f8064:	31 f6                	xor    %esi,%esi
ffffffff8b3f8066:	e8 f5 23 b1 ff       	call   ffffffff8af0a460 <handler_619_body-0x4ed1f0>
ffffffff8b3f806b:	85 c0                	test   %eax,%eax
ffffffff8b3f806d:	74 33                	je     ffffffff8b3f80a2 <frame_candidate_a37f00+0x1a2>
ffffffff8b3f806f:	48 8d 3d a0 21 85 00 	lea    0x8521a0(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8076:	48 8d 35 18 d3 95 00 	lea    0x95d318(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f807d:	ba 0e 10 00 00       	mov    $0x100e,%edx
ffffffff8b3f8082:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8084:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f8087:	89 c3                	mov    %eax,%ebx
ffffffff8b3f8089:	31 c0                	xor    %eax,%eax
ffffffff8b3f808b:	e8 80 53 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8090:	83 fb 06             	cmp    $0x6,%ebx
ffffffff8b3f8093:	41 bd 13 00 00 00    	mov    $0x13,%r13d
ffffffff8b3f8099:	44 0f 45 eb          	cmovne %ebx,%r13d
ffffffff8b3f809d:	e9 ae 09 00 00       	jmp    ffffffff8b3f8a50 <frame_candidate_a37f00+0xb50>
ffffffff8b3f80a2:	83 bb 10 04 00 00 00 	cmpl   $0x0,0x410(%rbx)
ffffffff8b3f80a9:	4c 89 7d b8          	mov    %r15,-0x48(%rbp)
ffffffff8b3f80ad:	0f 88 f8 02 00 00    	js     ffffffff8b3f83ab <frame_candidate_a37f00+0x4ab>
ffffffff8b3f80b3:	48 83 bb 68 08 00 00 	cmpq   $0x0,0x868(%rbx)
ffffffff8b3f80ba:	00 
ffffffff8b3f80bb:	0f 84 26 01 00 00    	je     ffffffff8b3f81e7 <frame_candidate_a37f00+0x2e7>
ffffffff8b3f80c1:	48 8b 83 d8 00 00 00 	mov    0xd8(%rbx),%rax
ffffffff8b3f80c8:	4c 89 75 b0          	mov    %r14,-0x50(%rbp)
ffffffff8b3f80cc:	4c 8b 60 10          	mov    0x10(%rax),%r12
ffffffff8b3f80d0:	49 8b 44 24 18       	mov    0x18(%r12),%rax
ffffffff8b3f80d5:	4c 8b b0 c8 08 00 00 	mov    0x8c8(%rax),%r14
ffffffff8b3f80dc:	48 8d 05 a5 53 82 ff 	lea    -0x7dac5b(%rip),%rax        # ffffffff8ac1d488 <handler_619_body-0x7da1c8>
ffffffff8b3f80e3:	4c 29 f0             	sub    %r14,%rax
ffffffff8b3f80e6:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f80ea:	48 83 f8 05          	cmp    $0x5,%rax
ffffffff8b3f80ee:	0f 87 a6 09 00 00    	ja     ffffffff8b3f8a9a <frame_candidate_a37f00+0xb9a>
ffffffff8b3f80f4:	4c 8b 7d c0          	mov    -0x40(%rbp),%r15
ffffffff8b3f80f8:	4c 8d 45 c8          	lea    -0x38(%rbp),%r8
ffffffff8b3f80fc:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f80ff:	31 f6                	xor    %esi,%esi
ffffffff8b3f8101:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8103:	44 89 fa             	mov    %r15d,%edx
ffffffff8b3f8106:	41 ff d6             	call   *%r14
ffffffff8b3f8109:	85 c0                	test   %eax,%eax
ffffffff8b3f810b:	74 6d                	je     ffffffff8b3f817a <frame_candidate_a37f00+0x27a>
ffffffff8b3f810d:	48 8d 3d 02 21 85 00 	lea    0x852102(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8114:	48 8d 35 7a d2 95 00 	lea    0x95d27a(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f811b:	ba 22 10 00 00       	mov    $0x1022,%edx
ffffffff8b3f8120:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8122:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f8125:	41 89 c6             	mov    %eax,%r14d
ffffffff8b3f8128:	31 c0                	xor    %eax,%eax
ffffffff8b3f812a:	e8 e1 52 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f812f:	48 8b bb 68 08 00 00 	mov    0x868(%rbx),%rdi
ffffffff8b3f8136:	41 83 fe 06          	cmp    $0x6,%r14d
ffffffff8b3f813a:	41 bd 13 00 00 00    	mov    $0x13,%r13d
ffffffff8b3f8140:	ba 00 01 00 00       	mov    $0x100,%edx
ffffffff8b3f8145:	45 0f 45 ee          	cmovne %r14d,%r13d
ffffffff8b3f8149:	31 f6                	xor    %esi,%esi
ffffffff8b3f814b:	e8 40 88 e3 ff       	call   ffffffff8b230990 <handler_619_body-0x1c6cc0>
ffffffff8b3f8150:	48 8b bb 68 08 00 00 	mov    0x868(%rbx),%rdi
ffffffff8b3f8157:	48 8d 35 c2 06 b3 01 	lea    0x1b306c2(%rip),%rsi        # ffffffff8cf28820 <frame_candidate_a39640+0x1b2f1e0>
ffffffff8b3f815e:	e8 8d 0c 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f8163:	4c 8d 25 a6 41 ee 02 	lea    0x2ee41a6(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f816a:	48 c7 83 68 08 00 00 	movq   $0x0,0x868(%rbx)
ffffffff8b3f8171:	00 00 00 00 
ffffffff8b3f8175:	e9 d6 08 00 00       	jmp    ffffffff8b3f8a50 <frame_candidate_a37f00+0xb50>
ffffffff8b3f817a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f817e:	48 8b b3 68 08 00 00 	mov    0x868(%rbx),%rsi
ffffffff8b3f8185:	48 8b 40 18          	mov    0x18(%rax),%rax
ffffffff8b3f8189:	4a 8d bc 38 e0 eb ff 	lea    -0x1420(%rax,%r15,1),%rdi
ffffffff8b3f8190:	ff 
ffffffff8b3f8191:	e8 9a 65 12 00       	call   ffffffff8b51e730 <frame_candidate_a39640+0x1250f0>
ffffffff8b3f8196:	48 8b bb 68 08 00 00 	mov    0x868(%rbx),%rdi
ffffffff8b3f819d:	ba 00 01 00 00       	mov    $0x100,%edx
ffffffff8b3f81a2:	31 f6                	xor    %esi,%esi
ffffffff8b3f81a4:	41 89 c6             	mov    %eax,%r14d
ffffffff8b3f81a7:	e8 e4 87 e3 ff       	call   ffffffff8b230990 <handler_619_body-0x1c6cc0>
ffffffff8b3f81ac:	48 8b bb 68 08 00 00 	mov    0x868(%rbx),%rdi
ffffffff8b3f81b3:	48 8d 35 66 06 b3 01 	lea    0x1b30666(%rip),%rsi        # ffffffff8cf28820 <frame_candidate_a39640+0x1b2f1e0>
ffffffff8b3f81ba:	e8 31 0c 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f81bf:	48 c7 83 68 08 00 00 	movq   $0x0,0x868(%rbx)
ffffffff8b3f81c6:	00 00 00 00 
ffffffff8b3f81ca:	45 85 f6             	test   %r14d,%r14d
ffffffff8b3f81cd:	0f 84 e2 00 00 00    	je     ffffffff8b3f82b5 <frame_candidate_a37f00+0x3b5>
ffffffff8b3f81d3:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f81d7:	e8 b4 54 06 00       	call   ffffffff8b45d690 <frame_candidate_a39640+0x64050>
ffffffff8b3f81dc:	4c 8d 25 2d 41 ee 02 	lea    0x2ee412d(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f81e3:	4c 8b 75 b0          	mov    -0x50(%rbp),%r14
ffffffff8b3f81e7:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f81ea:	e8 d1 00 f1 ff       	call   ffffffff8b3082c0 <handler_619_body-0xef390>
ffffffff8b3f81ef:	85 c0                	test   %eax,%eax
ffffffff8b3f81f1:	74 32                	je     ffffffff8b3f8225 <frame_candidate_a37f00+0x325>
ffffffff8b3f81f3:	83 f8 06             	cmp    $0x6,%eax
ffffffff8b3f81f6:	41 bd 13 00 00 00    	mov    $0x13,%r13d
ffffffff8b3f81fc:	48 8d 3d 13 20 85 00 	lea    0x852013(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8203:	48 8d 35 8b d1 95 00 	lea    0x95d18b(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f820a:	ba 54 10 00 00       	mov    $0x1054,%edx
ffffffff8b3f820f:	44 0f 45 e8          	cmovne %eax,%r13d
ffffffff8b3f8213:	44 89 e9             	mov    %r13d,%ecx
ffffffff8b3f8216:	45 89 e8             	mov    %r13d,%r8d
ffffffff8b3f8219:	31 c0                	xor    %eax,%eax
ffffffff8b3f821b:	e8 f0 51 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8220:	e9 2b 08 00 00       	jmp    ffffffff8b3f8a50 <frame_candidate_a37f00+0xb50>
ffffffff8b3f8225:	f6 83 13 04 00 00 10 	testb  $0x10,0x413(%rbx)
ffffffff8b3f822c:	74 18                	je     ffffffff8b3f8246 <frame_candidate_a37f00+0x346>
ffffffff8b3f822e:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f8231:	e8 2a d5 f0 ff       	call   ffffffff8b305760 <handler_619_body-0xf1ef0>
ffffffff8b3f8236:	48 8b 83 48 03 00 00 	mov    0x348(%rbx),%rax
ffffffff8b3f823d:	48 8b 78 10          	mov    0x10(%rax),%rdi
ffffffff8b3f8241:	e8 9a c7 ef ff       	call   ffffffff8b2f49e0 <handler_619_body-0x102c70>
ffffffff8b3f8246:	48 8b 7b 20          	mov    0x20(%rbx),%rdi
ffffffff8b3f824a:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b3f824e:	4c 8b 7d c0          	mov    -0x40(%rbp),%r15
ffffffff8b3f8252:	48 8d 45 c8          	lea    -0x38(%rbp),%rax
ffffffff8b3f8256:	31 f6                	xor    %esi,%esi
ffffffff8b3f8258:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f825a:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f825d:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f8260:	44 89 fa             	mov    %r15d,%edx
ffffffff8b3f8263:	50                   	push   %rax
ffffffff8b3f8264:	6a 00                	push   $0x0
ffffffff8b3f8266:	6a 00                	push   $0x0
ffffffff8b3f8268:	e8 23 59 06 00       	call   ffffffff8b45db90 <frame_candidate_a39640+0x64550>
ffffffff8b3f826d:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b3f8271:	85 c0                	test   %eax,%eax
ffffffff8b3f8273:	0f 84 a1 00 00 00    	je     ffffffff8b3f831a <frame_candidate_a37f00+0x41a>
ffffffff8b3f8279:	48 8d 3d 96 1f 85 00 	lea    0x851f96(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8280:	48 8d 35 0e d1 95 00 	lea    0x95d10e(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f8287:	ba 60 10 00 00       	mov    $0x1060,%edx
ffffffff8b3f828c:	89 c1                	mov    %eax,%ecx
ffffffff8b3f828e:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f8291:	89 c3                	mov    %eax,%ebx
ffffffff8b3f8293:	31 c0                	xor    %eax,%eax
ffffffff8b3f8295:	e8 76 51 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f829a:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f829e:	83 fb 06             	cmp    $0x6,%ebx
ffffffff8b3f82a1:	41 bd 13 00 00 00    	mov    $0x13,%r13d
ffffffff8b3f82a7:	44 0f 45 eb          	cmovne %ebx,%r13d
ffffffff8b3f82ab:	e8 e0 53 06 00       	call   ffffffff8b45d690 <frame_candidate_a39640+0x64050>
ffffffff8b3f82b0:	e9 9b 07 00 00       	jmp    ffffffff8b3f8a50 <frame_candidate_a37f00+0xb50>
ffffffff8b3f82b5:	49 8b 44 24 18       	mov    0x18(%r12),%rax
ffffffff8b3f82ba:	4c 8b b0 d8 08 00 00 	mov    0x8d8(%rax),%r14
ffffffff8b3f82c1:	48 8d 05 38 1c 83 ff 	lea    -0x7ce3c8(%rip),%rax        # ffffffff8ac29f00 <handler_619_body-0x7cd750>
ffffffff8b3f82c8:	4c 29 f0             	sub    %r14,%rax
ffffffff8b3f82cb:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f82cf:	48 83 f8 16          	cmp    $0x16,%rax
ffffffff8b3f82d3:	0f 87 39 08 00 00    	ja     ffffffff8b3f8b12 <frame_candidate_a37f00+0xc12>
ffffffff8b3f82d9:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
ffffffff8b3f82dd:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f82e0:	31 d2                	xor    %edx,%edx
ffffffff8b3f82e2:	41 ff d6             	call   *%r14
ffffffff8b3f82e5:	85 c0                	test   %eax,%eax
ffffffff8b3f82e7:	0f 84 7f 07 00 00    	je     ffffffff8b3f8a6c <frame_candidate_a37f00+0xb6c>
ffffffff8b3f82ed:	48 8d 3d 22 1f 85 00 	lea    0x851f22(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f82f4:	48 8d 35 9a d0 95 00 	lea    0x95d09a(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f82fb:	ba 3d 10 00 00       	mov    $0x103d,%edx
ffffffff8b3f8300:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8302:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f8305:	89 c3                	mov    %eax,%ebx
ffffffff8b3f8307:	31 c0                	xor    %eax,%eax
ffffffff8b3f8309:	e8 02 51 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f830e:	4c 8d 25 fb 3f ee 02 	lea    0x2ee3ffb(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f8315:	e9 76 fd ff ff       	jmp    ffffffff8b3f8090 <frame_candidate_a37f00+0x190>
ffffffff8b3f831a:	48 8b 43 30          	mov    0x30(%rbx),%rax
ffffffff8b3f831e:	80 60 18 80          	andb   $0x80,0x18(%rax)
ffffffff8b3f8322:	f6 83 10 04 00 00 01 	testb  $0x1,0x410(%rbx)
ffffffff8b3f8329:	74 08                	je     ffffffff8b3f8333 <frame_candidate_a37f00+0x433>
ffffffff8b3f832b:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f832e:	e8 7d ff ef ff       	call   ffffffff8b2f82b0 <handler_619_body-0xff3a0>
ffffffff8b3f8333:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f8337:	48 8b 7b 30          	mov    0x30(%rbx),%rdi
ffffffff8b3f833b:	ba a0 05 00 00       	mov    $0x5a0,%edx
ffffffff8b3f8340:	48 8b 70 18          	mov    0x18(%rax),%rsi
ffffffff8b3f8344:	e8 97 18 82 ff       	call   ffffffff8ac19be0 <handler_619_body-0x7dda70>
ffffffff8b3f8349:	83 bb 50 04 00 00 03 	cmpl   $0x3,0x450(%rbx)
ffffffff8b3f8350:	75 50                	jne    ffffffff8b3f83a2 <frame_candidate_a37f00+0x4a2>
ffffffff8b3f8352:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f8356:	be 80 03 00 00       	mov    $0x380,%esi
ffffffff8b3f835b:	48 03 73 30          	add    0x30(%rbx),%rsi
ffffffff8b3f835f:	48 8b 40 18          	mov    0x18(%rax),%rax
ffffffff8b3f8363:	4a 8d 7c 38 90       	lea    -0x70(%rax,%r15,1),%rdi
ffffffff8b3f8368:	e8 73 66 12 00       	call   ffffffff8b51e9e0 <frame_candidate_a39640+0x1253a0>
ffffffff8b3f836d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f8371:	be a0 05 00 00       	mov    $0x5a0,%esi
ffffffff8b3f8376:	48 8b 78 18          	mov    0x18(%rax),%rdi
ffffffff8b3f837a:	e8 71 06 85 ff       	call   ffffffff8ac489f0 <handler_619_body-0x7aec60>
ffffffff8b3f837f:	85 c0                	test   %eax,%eax
ffffffff8b3f8381:	74 1f                	je     ffffffff8b3f83a2 <frame_candidate_a37f00+0x4a2>
ffffffff8b3f8383:	48 8d 3d 8c 1e 85 00 	lea    0x851e8c(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f838a:	48 8d 35 04 d0 95 00 	lea    0x95d004(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f8391:	ba 7f 10 00 00       	mov    $0x107f,%edx
ffffffff8b3f8396:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8398:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f839b:	31 c0                	xor    %eax,%eax
ffffffff8b3f839d:	e8 6e 50 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f83a2:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f83a6:	e8 45 66 00 00       	call   ffffffff8b3fe9f0 <frame_candidate_a39640+0x53b0>
ffffffff8b3f83ab:	83 bb 50 04 00 00 01 	cmpl   $0x1,0x450(%rbx)
ffffffff8b3f83b2:	75 5a                	jne    ffffffff8b3f840e <frame_candidate_a37f00+0x50e>
ffffffff8b3f83b4:	83 bb 84 07 00 00 ff 	cmpl   $0xffffffff,0x784(%rbx)
ffffffff8b3f83bb:	74 51                	je     ffffffff8b3f840e <frame_candidate_a37f00+0x50e>
ffffffff8b3f83bd:	4d 89 f7             	mov    %r14,%r15
ffffffff8b3f83c0:	4c 8d 35 81 30 b7 02 	lea    0x2b73081(%rip),%r14        # ffffffff8df6b448 <frame_candidate_a39640+0x2b71e08>
ffffffff8b3f83c7:	31 f6                	xor    %esi,%esi
ffffffff8b3f83c9:	31 d2                	xor    %edx,%edx
ffffffff8b3f83cb:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f83cd:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f83d0:	e8 2b e6 a8 ff       	call   ffffffff8ae86a00 <handler_619_body-0x570c50>
ffffffff8b3f83d5:	48 63 83 84 07 00 00 	movslq 0x784(%rbx),%rax
ffffffff8b3f83dc:	48 8d 3d 9d 30 b7 02 	lea    0x2b7309d(%rip),%rdi        # ffffffff8df6b480 <frame_candidate_a39640+0x2b71e40>
ffffffff8b3f83e3:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
ffffffff8b3f83e7:	48 c1 e0 06          	shl    $0x6,%rax
ffffffff8b3f83eb:	48 01 c7             	add    %rax,%rdi
ffffffff8b3f83ee:	e8 6d 6f fe ff       	call   ffffffff8b3df360 <handler_619_body-0x182f0>
ffffffff8b3f83f3:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f83f6:	4d 89 fe             	mov    %r15,%r14
ffffffff8b3f83f9:	31 f6                	xor    %esi,%esi
ffffffff8b3f83fb:	31 d2                	xor    %edx,%edx
ffffffff8b3f83fd:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f83ff:	e8 9c eb a8 ff       	call   ffffffff8ae86fa0 <handler_619_body-0x5706b0>
ffffffff8b3f8404:	c7 83 84 07 00 00 ff 	movl   $0xffffffff,0x784(%rbx)
ffffffff8b3f840b:	ff ff ff 
ffffffff8b3f840e:	8b 83 10 04 00 00    	mov    0x410(%rbx),%eax
ffffffff8b3f8414:	a8 01                	test   $0x1,%al
ffffffff8b3f8416:	74 42                	je     ffffffff8b3f845a <frame_candidate_a37f00+0x55a>
ffffffff8b3f8418:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f841b:	4d 89 f7             	mov    %r14,%r15
ffffffff8b3f841e:	45 89 ee             	mov    %r13d,%r14d
ffffffff8b3f8421:	e8 2a b4 15 00       	call   ffffffff8b553850 <frame_candidate_a39640+0x15a210>
ffffffff8b3f8426:	85 c0                	test   %eax,%eax
ffffffff8b3f8428:	74 24                	je     ffffffff8b3f844e <frame_candidate_a37f00+0x54e>
ffffffff8b3f842a:	48 8d 3d 50 0d 8b 00 	lea    0x8b0d50(%rip),%rdi        # ffffffff8bca9181 <frame_candidate_a39640+0x8afb41>
ffffffff8b3f8431:	48 8d 35 5d cf 95 00 	lea    0x95cf5d(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f8438:	ba 9e 10 00 00       	mov    $0x109e,%edx
ffffffff8b3f843d:	89 c1                	mov    %eax,%ecx
ffffffff8b3f843f:	41 89 c5             	mov    %eax,%r13d
ffffffff8b3f8442:	31 c0                	xor    %eax,%eax
ffffffff8b3f8444:	e8 c7 4f 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8449:	e9 02 06 00 00       	jmp    ffffffff8b3f8a50 <frame_candidate_a37f00+0xb50>
ffffffff8b3f844e:	8b 83 10 04 00 00    	mov    0x410(%rbx),%eax
ffffffff8b3f8454:	45 89 f5             	mov    %r14d,%r13d
ffffffff8b3f8457:	4d 89 fe             	mov    %r15,%r14
ffffffff8b3f845a:	8b 8b 50 04 00 00    	mov    0x450(%rbx),%ecx
ffffffff8b3f8460:	a8 01                	test   $0x1,%al
ffffffff8b3f8462:	0f 85 31 01 00 00    	jne    ffffffff8b3f8599 <frame_candidate_a37f00+0x699>
ffffffff8b3f8468:	83 f9 01             	cmp    $0x1,%ecx
ffffffff8b3f846b:	0f 85 75 02 00 00    	jne    ffffffff8b3f86e6 <frame_candidate_a37f00+0x7e6>
ffffffff8b3f8471:	48 8d b3 f8 05 00 00 	lea    0x5f8(%rbx),%rsi
ffffffff8b3f8478:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f847b:	e8 50 25 f1 ff       	call   ffffffff8b30a9d0 <handler_619_body-0xecc80>
ffffffff8b3f8480:	48 8b bb f8 06 00 00 	mov    0x6f8(%rbx),%rdi
ffffffff8b3f8487:	48 85 ff             	test   %rdi,%rdi
ffffffff8b3f848a:	74 65                	je     ffffffff8b3f84f1 <frame_candidate_a37f00+0x5f1>
ffffffff8b3f848c:	48 81 c7 b0 00 00 00 	add    $0xb0,%rdi
ffffffff8b3f8493:	31 f6                	xor    %esi,%esi
ffffffff8b3f8495:	31 d2                	xor    %edx,%edx
ffffffff8b3f8497:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8499:	e8 62 e5 a8 ff       	call   ffffffff8ae86a00 <handler_619_body-0x570c50>
ffffffff8b3f849e:	48 8b bb f8 06 00 00 	mov    0x6f8(%rbx),%rdi
ffffffff8b3f84a5:	f6 87 c4 01 00 00 80 	testb  $0x80,0x1c4(%rdi)
ffffffff8b3f84ac:	75 1a                	jne    ffffffff8b3f84c8 <frame_candidate_a37f00+0x5c8>
ffffffff8b3f84ae:	48 8b 47 10          	mov    0x10(%rdi),%rax
ffffffff8b3f84b2:	48 8b 40 18          	mov    0x18(%rax),%rax
ffffffff8b3f84b6:	48 c7 80 10 07 00 00 	movq   $0x0,0x710(%rax)
ffffffff8b3f84bd:	00 00 00 00 
ffffffff8b3f84c1:	48 8b bb f8 06 00 00 	mov    0x6f8(%rbx),%rdi
ffffffff8b3f84c8:	48 81 c7 b0 00 00 00 	add    $0xb0,%rdi
ffffffff8b3f84cf:	31 f6                	xor    %esi,%esi
ffffffff8b3f84d1:	31 d2                	xor    %edx,%edx
ffffffff8b3f84d3:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f84d5:	e8 c6 ea a8 ff       	call   ffffffff8ae86fa0 <handler_619_body-0x5706b0>
ffffffff8b3f84da:	48 8b bb f8 06 00 00 	mov    0x6f8(%rbx),%rdi
ffffffff8b3f84e1:	48 c7 83 f8 06 00 00 	movq   $0x0,0x6f8(%rbx)
ffffffff8b3f84e8:	00 00 00 00 
ffffffff8b3f84ec:	e8 2f 1c b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f84f1:	48 8b bb b0 06 00 00 	mov    0x6b0(%rbx),%rdi
ffffffff8b3f84f8:	48 83 c7 48          	add    $0x48,%rdi
ffffffff8b3f84fc:	e8 4f f9 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8501:	bf f0 00 00 00       	mov    $0xf0,%edi
ffffffff8b3f8506:	48 03 bb b0 06 00 00 	add    0x6b0(%rbx),%rdi
ffffffff8b3f850d:	e8 3e f9 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8512:	bf 98 01 00 00       	mov    $0x198,%edi
ffffffff8b3f8517:	48 03 bb b0 06 00 00 	add    0x6b0(%rbx),%rdi
ffffffff8b3f851e:	e8 2d f9 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8523:	bf 40 02 00 00       	mov    $0x240,%edi
ffffffff8b3f8528:	48 03 bb b0 06 00 00 	add    0x6b0(%rbx),%rdi
ffffffff8b3f852f:	e8 1c f9 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8534:	48 8b bb b0 06 00 00 	mov    0x6b0(%rbx),%rdi
ffffffff8b3f853b:	4d 89 f7             	mov    %r14,%r15
ffffffff8b3f853e:	4c 8d 35 db 02 b3 01 	lea    0x1b302db(%rip),%r14        # ffffffff8cf28820 <frame_candidate_a39640+0x1b2f1e0>
ffffffff8b3f8545:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8548:	e8 a3 08 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f854d:	48 8d bb 18 06 00 00 	lea    0x618(%rbx),%rdi
ffffffff8b3f8554:	e8 f7 f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8559:	48 8d bb 60 06 00 00 	lea    0x660(%rbx),%rdi
ffffffff8b3f8560:	e8 eb f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8565:	48 8d bb d0 06 00 00 	lea    0x6d0(%rbx),%rdi
ffffffff8b3f856c:	e8 df f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8571:	48 8d bb f0 06 00 00 	lea    0x6f0(%rbx),%rdi
ffffffff8b3f8578:	e8 d3 f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f857d:	48 8b bb 20 07 00 00 	mov    0x720(%rbx),%rdi
ffffffff8b3f8584:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8587:	4d 89 fe             	mov    %r15,%r14
ffffffff8b3f858a:	e8 61 08 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f858f:	bf 70 07 00 00       	mov    $0x770,%edi
ffffffff8b3f8594:	e9 45 01 00 00       	jmp    ffffffff8b3f86de <frame_candidate_a37f00+0x7de>
ffffffff8b3f8599:	83 f9 01             	cmp    $0x1,%ecx
ffffffff8b3f859c:	74 74                	je     ffffffff8b3f8612 <frame_candidate_a37f00+0x712>
ffffffff8b3f859e:	83 f9 03             	cmp    $0x3,%ecx
ffffffff8b3f85a1:	0f 85 3f 01 00 00    	jne    ffffffff8b3f86e6 <frame_candidate_a37f00+0x7e6>
ffffffff8b3f85a7:	48 8d b3 a8 04 00 00 	lea    0x4a8(%rbx),%rsi
ffffffff8b3f85ae:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f85b1:	e8 5a 23 f1 ff       	call   ffffffff8b30a910 <handler_619_body-0xecd40>
ffffffff8b3f85b6:	48 8d b3 f0 04 00 00 	lea    0x4f0(%rbx),%rsi
ffffffff8b3f85bd:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f85c0:	e8 4b 23 f1 ff       	call   ffffffff8b30a910 <handler_619_body-0xecd40>
ffffffff8b3f85c5:	48 8b bb b0 05 00 00 	mov    0x5b0(%rbx),%rdi
ffffffff8b3f85cc:	48 8d 35 4d 02 b3 01 	lea    0x1b3024d(%rip),%rsi        # ffffffff8cf28820 <frame_candidate_a39640+0x1b2f1e0>
ffffffff8b3f85d3:	e8 18 08 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f85d8:	48 8d bb c8 04 00 00 	lea    0x4c8(%rbx),%rdi
ffffffff8b3f85df:	e8 6c f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f85e4:	48 8d bb 10 05 00 00 	lea    0x510(%rbx),%rdi
ffffffff8b3f85eb:	e8 60 f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f85f0:	48 8d bb 58 05 00 00 	lea    0x558(%rbx),%rdi
ffffffff8b3f85f7:	e8 54 f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f85fc:	48 8d bb f0 05 00 00 	lea    0x5f0(%rbx),%rdi
ffffffff8b3f8603:	e8 48 f8 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f8608:	bf d0 05 00 00       	mov    $0x5d0,%edi
ffffffff8b3f860d:	e9 cc 00 00 00       	jmp    ffffffff8b3f86de <frame_candidate_a37f00+0x7de>
ffffffff8b3f8612:	48 8d b3 f8 05 00 00 	lea    0x5f8(%rbx),%rsi
ffffffff8b3f8619:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f861c:	4d 89 f7             	mov    %r14,%r15
ffffffff8b3f861f:	e8 ac 23 f1 ff       	call   ffffffff8b30a9d0 <handler_619_body-0xecc80>
ffffffff8b3f8624:	48 8b bb b0 05 00 00 	mov    0x5b0(%rbx),%rdi
ffffffff8b3f862b:	48 8d 35 ee 01 b3 01 	lea    0x1b301ee(%rip),%rsi        # ffffffff8cf28820 <frame_candidate_a39640+0x1b2f1e0>
ffffffff8b3f8632:	e8 b9 07 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f8637:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
ffffffff8b3f863b:	41 be 14 00 00 00    	mov    $0x14,%r14d
ffffffff8b3f8641:	41 bc 48 00 00 00    	mov    $0x48,%r12d
ffffffff8b3f8647:	83 b8 30 03 00 00 01 	cmpl   $0x1,0x330(%rax)
ffffffff8b3f864e:	b8 08 00 00 00       	mov    $0x8,%eax
ffffffff8b3f8653:	4c 0f 44 f0          	cmove  %rax,%r14
ffffffff8b3f8657:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8b3f865e:	00 00 
ffffffff8b3f8660:	48 8b bb b0 06 00 00 	mov    0x6b0(%rbx),%rdi
ffffffff8b3f8667:	4c 01 e7             	add    %r12,%rdi
ffffffff8b3f866a:	e8 e1 f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f866f:	49 81 c4 a8 00 00 00 	add    $0xa8,%r12
ffffffff8b3f8676:	49 ff ce             	dec    %r14
ffffffff8b3f8679:	75 e5                	jne    ffffffff8b3f8660 <frame_candidate_a37f00+0x760>
ffffffff8b3f867b:	48 8b bb b0 06 00 00 	mov    0x6b0(%rbx),%rdi
ffffffff8b3f8682:	48 8d 35 97 01 b3 01 	lea    0x1b30197(%rip),%rsi        # ffffffff8cf28820 <frame_candidate_a39640+0x1b2f1e0>
ffffffff8b3f8689:	e8 62 07 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f868e:	48 8d bb 58 05 00 00 	lea    0x558(%rbx),%rdi
ffffffff8b3f8695:	e8 b6 f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f869a:	48 8d bb f0 05 00 00 	lea    0x5f0(%rbx),%rdi
ffffffff8b3f86a1:	e8 aa f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f86a6:	48 8d bb d0 05 00 00 	lea    0x5d0(%rbx),%rdi
ffffffff8b3f86ad:	e8 9e f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f86b2:	48 8d bb 18 06 00 00 	lea    0x618(%rbx),%rdi
ffffffff8b3f86b9:	e8 92 f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f86be:	48 8d bb 60 06 00 00 	lea    0x660(%rbx),%rdi
ffffffff8b3f86c5:	e8 86 f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f86ca:	48 8d bb d0 06 00 00 	lea    0x6d0(%rbx),%rdi
ffffffff8b3f86d1:	e8 7a f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f86d6:	bf f0 06 00 00       	mov    $0x6f0,%edi
ffffffff8b3f86db:	4d 89 fe             	mov    %r15,%r14
ffffffff8b3f86de:	48 01 df             	add    %rbx,%rdi
ffffffff8b3f86e1:	e8 6a f7 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f86e6:	48 83 bb a8 01 00 00 	cmpq   $0x0,0x1a8(%rbx)
ffffffff8b3f86ed:	00 
ffffffff8b3f86ee:	74 47                	je     ffffffff8b3f8737 <frame_candidate_a37f00+0x837>
ffffffff8b3f86f0:	48 8d bb e0 01 00 00 	lea    0x1e0(%rbx),%rdi
ffffffff8b3f86f7:	e8 64 90 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f86fc:	48 8b bb c8 01 00 00 	mov    0x1c8(%rbx),%rdi
ffffffff8b3f8703:	48 8d 35 c6 ff b2 01 	lea    0x1b2ffc6(%rip),%rsi        # ffffffff8cf286d0 <frame_candidate_a39640+0x1b2f090>
ffffffff8b3f870a:	e8 e1 06 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f870f:	48 8b 83 a8 01 00 00 	mov    0x1a8(%rbx),%rax
ffffffff8b3f8716:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f871d:	ff ff ff 
ffffffff8b3f8720:	48 8b bb a8 01 00 00 	mov    0x1a8(%rbx),%rdi
ffffffff8b3f8727:	e8 f4 19 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f872c:	48 c7 83 a8 01 00 00 	movq   $0x0,0x1a8(%rbx)
ffffffff8b3f8733:	00 00 00 00 
ffffffff8b3f8737:	48 83 bb 40 01 00 00 	cmpq   $0x0,0x140(%rbx)
ffffffff8b3f873e:	00 
ffffffff8b3f873f:	74 47                	je     ffffffff8b3f8788 <frame_candidate_a37f00+0x888>
ffffffff8b3f8741:	48 8d bb 78 01 00 00 	lea    0x178(%rbx),%rdi
ffffffff8b3f8748:	e8 13 90 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f874d:	48 8b bb 60 01 00 00 	mov    0x160(%rbx),%rdi
ffffffff8b3f8754:	48 8d 35 75 ff b2 01 	lea    0x1b2ff75(%rip),%rsi        # ffffffff8cf286d0 <frame_candidate_a39640+0x1b2f090>
ffffffff8b3f875b:	e8 90 06 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f8760:	48 8b 83 40 01 00 00 	mov    0x140(%rbx),%rax
ffffffff8b3f8767:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f876e:	ff ff ff 
ffffffff8b3f8771:	48 8b bb 40 01 00 00 	mov    0x140(%rbx),%rdi
ffffffff8b3f8778:	e8 a3 19 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f877d:	48 c7 83 40 01 00 00 	movq   $0x0,0x140(%rbx)
ffffffff8b3f8784:	00 00 00 00 
ffffffff8b3f8788:	48 83 bb 10 02 00 00 	cmpq   $0x0,0x210(%rbx)
ffffffff8b3f878f:	00 
ffffffff8b3f8790:	74 34                	je     ffffffff8b3f87c6 <frame_candidate_a37f00+0x8c6>
ffffffff8b3f8792:	48 8d bb 48 02 00 00 	lea    0x248(%rbx),%rdi
ffffffff8b3f8799:	e8 c2 8f 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f879e:	48 8b 83 10 02 00 00 	mov    0x210(%rbx),%rax
ffffffff8b3f87a5:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f87ac:	ff ff ff 
ffffffff8b3f87af:	48 8b bb 10 02 00 00 	mov    0x210(%rbx),%rdi
ffffffff8b3f87b6:	e8 65 19 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f87bb:	48 c7 83 10 02 00 00 	movq   $0x0,0x210(%rbx)
ffffffff8b3f87c2:	00 00 00 00 
ffffffff8b3f87c6:	48 83 bb 48 03 00 00 	cmpq   $0x0,0x348(%rbx)
ffffffff8b3f87cd:	00 
ffffffff8b3f87ce:	74 47                	je     ffffffff8b3f8817 <frame_candidate_a37f00+0x917>
ffffffff8b3f87d0:	48 8d bb 80 03 00 00 	lea    0x380(%rbx),%rdi
ffffffff8b3f87d7:	e8 84 8f 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f87dc:	48 8b 83 48 03 00 00 	mov    0x348(%rbx),%rax
ffffffff8b3f87e3:	48 8d 35 e6 fe b2 01 	lea    0x1b2fee6(%rip),%rsi        # ffffffff8cf286d0 <frame_candidate_a39640+0x1b2f090>
ffffffff8b3f87ea:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f87f1:	ff ff ff 
ffffffff8b3f87f4:	48 8b bb 68 03 00 00 	mov    0x368(%rbx),%rdi
ffffffff8b3f87fb:	e8 f0 05 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f8800:	48 8b bb 48 03 00 00 	mov    0x348(%rbx),%rdi
ffffffff8b3f8807:	e8 14 19 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f880c:	48 c7 83 48 03 00 00 	movq   $0x0,0x348(%rbx)
ffffffff8b3f8813:	00 00 00 00 
ffffffff8b3f8817:	48 83 bb 78 02 00 00 	cmpq   $0x0,0x278(%rbx)
ffffffff8b3f881e:	00 
ffffffff8b3f881f:	74 76                	je     ffffffff8b3f8897 <frame_candidate_a37f00+0x997>
ffffffff8b3f8821:	48 8b 43 30          	mov    0x30(%rbx),%rax
ffffffff8b3f8825:	48 83 38 02          	cmpq   $0x2,(%rax)
ffffffff8b3f8829:	75 38                	jne    ffffffff8b3f8863 <frame_candidate_a37f00+0x963>
ffffffff8b3f882b:	4d 89 f7             	mov    %r14,%r15
ffffffff8b3f882e:	4c 8b b3 98 02 00 00 	mov    0x298(%rbx),%r14
ffffffff8b3f8835:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8837:	4c 89 f0             	mov    %r14,%rax
ffffffff8b3f883a:	f0 48 0f b1 8b 98 02 	lock cmpxchg %rcx,0x298(%rbx)
ffffffff8b3f8841:	00 00 
ffffffff8b3f8843:	0f 85 a3 02 00 00    	jne    ffffffff8b3f8aec <frame_candidate_a37f00+0xbec>
ffffffff8b3f8849:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f884c:	e8 ff 00 b3 ff       	call   ffffffff8af28950 <handler_619_body-0x4ced00>
ffffffff8b3f8851:	48 8d 35 38 00 b3 01 	lea    0x1b30038(%rip),%rsi        # ffffffff8cf28890 <frame_candidate_a39640+0x1b2f250>
ffffffff8b3f8858:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f885b:	e8 90 05 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f8860:	4d 89 fe             	mov    %r15,%r14
ffffffff8b3f8863:	48 8d bb b0 02 00 00 	lea    0x2b0(%rbx),%rdi
ffffffff8b3f886a:	e8 f1 8e 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f886f:	48 8b 83 78 02 00 00 	mov    0x278(%rbx),%rax
ffffffff8b3f8876:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f887d:	ff ff ff 
ffffffff8b3f8880:	48 8b bb 78 02 00 00 	mov    0x278(%rbx),%rdi
ffffffff8b3f8887:	e8 94 18 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f888c:	48 c7 83 78 02 00 00 	movq   $0x0,0x278(%rbx)
ffffffff8b3f8893:	00 00 00 00 
ffffffff8b3f8897:	48 83 bb e0 02 00 00 	cmpq   $0x0,0x2e0(%rbx)
ffffffff8b3f889e:	00 
ffffffff8b3f889f:	74 34                	je     ffffffff8b3f88d5 <frame_candidate_a37f00+0x9d5>
ffffffff8b3f88a1:	48 8d bb 18 03 00 00 	lea    0x318(%rbx),%rdi
ffffffff8b3f88a8:	e8 b3 8e 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f88ad:	48 8b 83 e0 02 00 00 	mov    0x2e0(%rbx),%rax
ffffffff8b3f88b4:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f88bb:	ff ff ff 
ffffffff8b3f88be:	48 8b bb e0 02 00 00 	mov    0x2e0(%rbx),%rdi
ffffffff8b3f88c5:	e8 56 18 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f88ca:	48 c7 83 e0 02 00 00 	movq   $0x0,0x2e0(%rbx)
ffffffff8b3f88d1:	00 00 00 00 
ffffffff8b3f88d5:	48 8b 83 d0 00 00 00 	mov    0xd0(%rbx),%rax
ffffffff8b3f88dc:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f88e3:	ff ff ff 
ffffffff8b3f88e6:	48 8b bb d0 00 00 00 	mov    0xd0(%rbx),%rdi
ffffffff8b3f88ed:	e8 2e 18 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f88f2:	48 8b 83 d8 00 00 00 	mov    0xd8(%rbx),%rax
ffffffff8b3f88f9:	81 a0 c8 01 00 00 7f 	andl   $0xffffff7f,0x1c8(%rax)
ffffffff8b3f8900:	ff ff ff 
ffffffff8b3f8903:	48 8b bb d8 00 00 00 	mov    0xd8(%rbx),%rdi
ffffffff8b3f890a:	e8 11 18 b1 ff       	call   ffffffff8af0a120 <handler_619_body-0x4ed530>
ffffffff8b3f890f:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
ffffffff8b3f8913:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b3f8918:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b3f891b:	31 f6                	xor    %esi,%esi
ffffffff8b3f891d:	e8 3e 1b b1 ff       	call   ffffffff8af0a460 <handler_619_body-0x4ed1f0>
ffffffff8b3f8922:	85 c0                	test   %eax,%eax
ffffffff8b3f8924:	74 1c                	je     ffffffff8b3f8942 <frame_candidate_a37f00+0xa42>
ffffffff8b3f8926:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8928:	48 8d 3d b4 d1 96 00 	lea    0x96d1b4(%rip),%rdi        # ffffffff8bd65ae3 <frame_candidate_a39640+0x96c4a3>
ffffffff8b3f892f:	48 8d 35 5f ca 95 00 	lea    0x95ca5f(%rip),%rsi        # ffffffff8bd55395 <frame_candidate_a39640+0x95bd55>
ffffffff8b3f8936:	ba 51 11 00 00       	mov    $0x1151,%edx
ffffffff8b3f893b:	31 c0                	xor    %eax,%eax
ffffffff8b3f893d:	e8 ce 4a 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8942:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f8945:	44 89 6d c0          	mov    %r13d,-0x40(%rbp)
ffffffff8b3f8949:	e8 22 2b 93 ff       	call   ffffffff8ad2b470 <handler_619_body-0x6cc1e0>
ffffffff8b3f894e:	48 8b 7b 20          	mov    0x20(%rbx),%rdi
ffffffff8b3f8952:	48 8d 15 82 28 95 00 	lea    0x952882(%rip),%rdx        # ffffffff8bd4b1db <frame_candidate_a39640+0x951b9b>
ffffffff8b3f8959:	be 00 04 08 00       	mov    $0x80400,%esi
ffffffff8b3f895e:	b9 56 11 00 00       	mov    $0x1156,%ecx
ffffffff8b3f8963:	e8 e8 71 c7 ff       	call   ffffffff8b06fb50 <handler_619_body-0x387b00>
ffffffff8b3f8968:	4c 8d 35 f9 29 ac 02 	lea    0x2ac29f9(%rip),%r14        # ffffffff8debb368 <frame_candidate_a39640+0x2ac1d28>
ffffffff8b3f896f:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b3f8972:	31 f6                	xor    %esi,%esi
ffffffff8b3f8974:	31 d2                	xor    %edx,%edx
ffffffff8b3f8976:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8978:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f897b:	e8 a0 31 21 00       	call   ffffffff8b60bb20 <frame_candidate_a39640+0x2124e0>
ffffffff8b3f8980:	48 8b 7b 10          	mov    0x10(%rbx),%rdi
ffffffff8b3f8984:	e8 f7 90 d0 ff       	call   ffffffff8b101a80 <handler_619_body-0x2f5bd0>
ffffffff8b3f8989:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f898c:	31 f6                	xor    %esi,%esi
ffffffff8b3f898e:	31 d2                	xor    %edx,%edx
ffffffff8b3f8990:	e8 1b 3b 21 00       	call   ffffffff8b60c4b0 <frame_candidate_a39640+0x212e70>
ffffffff8b3f8995:	48 8b 7b 20          	mov    0x20(%rbx),%rdi
ffffffff8b3f8999:	e8 a2 1a b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f899e:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8b3f89a2:	e8 c9 60 ca ff       	call   ffffffff8b09ea70 <handler_619_body-0x358be0>
ffffffff8b3f89a7:	48 8b 7b 30          	mov    0x30(%rbx),%rdi
ffffffff8b3f89ab:	48 89 f8             	mov    %rdi,%rax
ffffffff8b3f89ae:	f0 4c 0f b1 63 30    	lock cmpxchg %r12,0x30(%rbx)
ffffffff8b3f89b4:	0f 85 f4 00 00 00    	jne    ffffffff8b3f8aae <frame_candidate_a37f00+0xbae>
ffffffff8b3f89ba:	48 8d 35 0f fd b2 01 	lea    0x1b2fd0f(%rip),%rsi        # ffffffff8cf286d0 <frame_candidate_a39640+0x1b2f090>
ffffffff8b3f89c1:	e8 2a 04 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f89c6:	48 8d 7b 68          	lea    0x68(%rbx),%rdi
ffffffff8b3f89ca:	e8 91 8d 1b 00       	call   ffffffff8b5b1760 <frame_candidate_a39640+0x1b8120>
ffffffff8b3f89cf:	48 8d bb 30 04 00 00 	lea    0x430(%rbx),%rdi
ffffffff8b3f89d6:	e8 75 f4 a8 ff       	call   ffffffff8ae87e50 <handler_619_body-0x56f800>
ffffffff8b3f89db:	4c 8b 7d b8          	mov    -0x48(%rbp),%r15
ffffffff8b3f89df:	4c 8d 25 2a 39 ee 02 	lea    0x2ee392a(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f89e6:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b3f89e9:	48 89 d8             	mov    %rbx,%rax
ffffffff8b3f89ec:	f0 4d 0f b1 af 98 02 	lock cmpxchg %r13,0x298(%r15)
ffffffff8b3f89f3:	00 00 
ffffffff8b3f89f5:	0f 85 d2 00 00 00    	jne    ffffffff8b3f8acd <frame_candidate_a37f00+0xbcd>
ffffffff8b3f89fb:	48 8d 35 ce fc b2 01 	lea    0x1b2fcce(%rip),%rsi        # ffffffff8cf286d0 <frame_candidate_a39640+0x1b2f090>
ffffffff8b3f8a02:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f8a05:	e8 e6 03 1d 00       	call   ffffffff8b5c8df0 <frame_candidate_a39640+0x1cf7b0>
ffffffff8b3f8a0a:	49 8d 5f 18          	lea    0x18(%r15),%rbx
ffffffff8b3f8a0e:	31 f6                	xor    %esi,%esi
ffffffff8b3f8a10:	31 d2                	xor    %edx,%edx
ffffffff8b3f8a12:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8a14:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f8a17:	e8 e4 df a8 ff       	call   ffffffff8ae86a00 <handler_619_body-0x570c50>
ffffffff8b3f8a1c:	41 80 a7 99 00 00 00 	andb   $0xef,0x99(%r15)
ffffffff8b3f8a23:	ef 
ffffffff8b3f8a24:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f8a27:	31 f6                	xor    %esi,%esi
ffffffff8b3f8a29:	31 d2                	xor    %edx,%edx
ffffffff8b3f8a2b:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8a2d:	e8 6e e5 a8 ff       	call   ffffffff8ae86fa0 <handler_619_body-0x5706b0>
ffffffff8b3f8a32:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8a35:	e8 76 be cd ff       	call   ffffffff8b0d48b0 <handler_619_body-0x322da0>
ffffffff8b3f8a3a:	8b 75 c0             	mov    -0x40(%rbp),%esi
ffffffff8b3f8a3d:	48 89 c2             	mov    %rax,%rdx
ffffffff8b3f8a40:	48 8d 3d 7b 25 97 00 	lea    0x97257b(%rip),%rdi        # ffffffff8bd6afc2 <frame_candidate_a39640+0x971982>
ffffffff8b3f8a47:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8a49:	31 c0                	xor    %eax,%eax
ffffffff8b3f8a4b:	e8 c0 49 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8a50:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8b3f8a54:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b3f8a58:	75 1f                	jne    ffffffff8b3f8a79 <frame_candidate_a37f00+0xb79>
ffffffff8b3f8a5a:	44 89 e8             	mov    %r13d,%eax
ffffffff8b3f8a5d:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8b3f8a61:	5b                   	pop    %rbx
ffffffff8b3f8a62:	41 5c                	pop    %r12
ffffffff8b3f8a64:	41 5d                	pop    %r13
ffffffff8b3f8a66:	41 5e                	pop    %r14
ffffffff8b3f8a68:	41 5f                	pop    %r15
ffffffff8b3f8a6a:	5d                   	pop    %rbp
ffffffff8b3f8a6b:	c3                   	ret
ffffffff8b3f8a6c:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f8a6f:	e8 6c bf ef ff       	call   ffffffff8b2f49e0 <handler_619_body-0x102c70>
ffffffff8b3f8a74:	e9 63 f7 ff ff       	jmp    ffffffff8b3f81dc <frame_candidate_a37f00+0x2dc>
ffffffff8b3f8a79:	e8 32 4c cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f8a7e:	0f 0b                	ud2
ffffffff8b3f8a80:	48 8d 3d 89 03 b3 01 	lea    0x1b30389(%rip),%rdi        # ffffffff8cf28e10 <frame_candidate_a39640+0x1b2f7d0>
ffffffff8b3f8a87:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8a8a:	48 89 cb             	mov    %rcx,%rbx
ffffffff8b3f8a8d:	e8 2e 6e a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f8a92:	48 89 d9             	mov    %rbx,%rcx
ffffffff8b3f8a95:	e9 f1 f4 ff ff       	jmp    ffffffff8b3f7f8b <frame_candidate_a37f00+0x8b>
ffffffff8b3f8a9a:	48 8d 3d 8f 03 b3 01 	lea    0x1b3038f(%rip),%rdi        # ffffffff8cf28e30 <frame_candidate_a39640+0x1b2f7f0>
ffffffff8b3f8aa1:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8aa4:	e8 17 6e a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f8aa9:	e9 46 f6 ff ff       	jmp    ffffffff8b3f80f4 <frame_candidate_a37f00+0x1f4>
ffffffff8b3f8aae:	e8 9d 8e db ff       	call   ffffffff8b1b1950 <handler_619_body-0x245d00>
ffffffff8b3f8ab3:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b3f8aae <frame_candidate_a37f00+0xbae>
ffffffff8b3f8aba:	e8 51 8d db ff       	call   ffffffff8b1b1810 <handler_619_body-0x245e40>
ffffffff8b3f8abf:	48 8d 35 4d 10 94 00 	lea    0x94104d(%rip),%rsi        # ffffffff8bd39b13 <frame_candidate_a39640+0x9404d3>
ffffffff8b3f8ac6:	bf 18 00 00 00       	mov    $0x18,%edi
ffffffff8b3f8acb:	eb 3c                	jmp    ffffffff8b3f8b09 <frame_candidate_a37f00+0xc09>
ffffffff8b3f8acd:	e8 7e 8e db ff       	call   ffffffff8b1b1950 <handler_619_body-0x245d00>
ffffffff8b3f8ad2:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b3f8acd <frame_candidate_a37f00+0xbcd>
ffffffff8b3f8ad9:	e8 32 8d db ff       	call   ffffffff8b1b1810 <handler_619_body-0x245e40>
ffffffff8b3f8ade:	48 8d 35 2e 10 94 00 	lea    0x94102e(%rip),%rsi        # ffffffff8bd39b13 <frame_candidate_a39640+0x9404d3>
ffffffff8b3f8ae5:	bf 1c 00 00 00       	mov    $0x1c,%edi
ffffffff8b3f8aea:	eb 1d                	jmp    ffffffff8b3f8b09 <frame_candidate_a37f00+0xc09>
ffffffff8b3f8aec:	e8 5f 8e db ff       	call   ffffffff8b1b1950 <handler_619_body-0x245d00>
ffffffff8b3f8af1:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b3f8aec <frame_candidate_a37f00+0xbec>
ffffffff8b3f8af8:	e8 13 8d db ff       	call   ffffffff8b1b1810 <handler_619_body-0x245e40>
ffffffff8b3f8afd:	48 8d 35 0f 10 94 00 	lea    0x94100f(%rip),%rsi        # ffffffff8bd39b13 <frame_candidate_a39640+0x9404d3>
ffffffff8b3f8b04:	bf 14 00 00 00       	mov    $0x14,%edi
ffffffff8b3f8b09:	31 c0                	xor    %eax,%eax
ffffffff8b3f8b0b:	e8 00 1f 26 00       	call   ffffffff8b65aa10 <frame_candidate_a39640+0x2613d0>
ffffffff8b3f8b10:	0f 0b                	ud2
ffffffff8b3f8b12:	48 8d 3d 37 03 b3 01 	lea    0x1b30337(%rip),%rdi        # ffffffff8cf28e50 <frame_candidate_a39640+0x1b2f810>
ffffffff8b3f8b19:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8b1c:	e8 9f 6d a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f8b21:	e9 b3 f7 ff ff       	jmp    ffffffff8b3f82d9 <frame_candidate_a37f00+0x3d9>
ffffffff8b3f8b26:	90                   	nop
ffffffff8b3f8b27:	90                   	nop
ffffffff8b3f8b28:	90                   	nop
ffffffff8b3f8b29:	90                   	nop
ffffffff8b3f8b2a:	90                   	nop
ffffffff8b3f8b2b:	90                   	nop
ffffffff8b3f8b2c:	90                   	nop
ffffffff8b3f8b2d:	90                   	nop
ffffffff8b3f8b2e:	90                   	nop
ffffffff8b3f8b2f:	90                   	nop

ffffffff8b3f8b30 <frame_candidate_a38b30>:
ffffffff8b3f8b30:	55                   	push   %rbp
ffffffff8b3f8b31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f8b34:	41 57                	push   %r15
ffffffff8b3f8b36:	41 56                	push   %r14
ffffffff8b3f8b38:	41 55                	push   %r13
ffffffff8b3f8b3a:	41 54                	push   %r12
ffffffff8b3f8b3c:	53                   	push   %rbx
ffffffff8b3f8b3d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b3f8b41:	48 8d 05 c8 37 ee 02 	lea    0x2ee37c8(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f8b48:	48 89 d3             	mov    %rdx,%rbx
ffffffff8b3f8b4b:	41 89 f7             	mov    %esi,%r15d
ffffffff8b3f8b4e:	41 bc ff ff ff ff    	mov    $0xffffffff,%r12d
ffffffff8b3f8b54:	48 8b 00             	mov    (%rax),%rax
ffffffff8b3f8b57:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b3f8b5b:	48 8b 47 40          	mov    0x40(%rdi),%rax
ffffffff8b3f8b5f:	4c 8b b7 98 02 00 00 	mov    0x298(%rdi),%r14
ffffffff8b3f8b66:	8b 40 28             	mov    0x28(%rax),%eax
ffffffff8b3f8b69:	c1 e8 17             	shr    $0x17,%eax
ffffffff8b3f8b6c:	83 e0 02             	and    $0x2,%eax
ffffffff8b3f8b6f:	74 10                	je     ffffffff8b3f8b81 <frame_candidate_a38b30+0x51>
ffffffff8b3f8b71:	49 89 fc             	mov    %rdi,%r12
ffffffff8b3f8b74:	89 c7                	mov    %eax,%edi
ffffffff8b3f8b76:	e8 75 91 b2 ff       	call   ffffffff8af21cf0 <handler_619_body-0x4d5960>
ffffffff8b3f8b7b:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f8b7e:	41 89 c4             	mov    %eax,%r12d
ffffffff8b3f8b81:	48 8b 47 38          	mov    0x38(%rdi),%rax
ffffffff8b3f8b85:	4c 8b 68 38          	mov    0x38(%rax),%r13
ffffffff8b3f8b89:	48 8d 05 48 2f 83 ff 	lea    -0x7cd0b8(%rip),%rax        # ffffffff8ac2bad8 <handler_619_body-0x7cbb78>
ffffffff8b3f8b90:	4c 29 e8             	sub    %r13,%rax
ffffffff8b3f8b93:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f8b97:	48 83 f8 0f          	cmp    $0xf,%rax
ffffffff8b3f8b9b:	0f 87 c2 00 00 00    	ja     ffffffff8b3f8c63 <frame_candidate_a38b30+0x133>
ffffffff8b3f8ba1:	41 8b b6 18 02 00 00 	mov    0x218(%r14),%esi
ffffffff8b3f8ba8:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
ffffffff8b3f8bac:	44 89 fa             	mov    %r15d,%edx
ffffffff8b3f8baf:	41 ff d5             	call   *%r13
ffffffff8b3f8bb2:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f8bb5:	41 83 fc ff          	cmp    $0xffffffff,%r12d
ffffffff8b3f8bb9:	74 08                	je     ffffffff8b3f8bc3 <frame_candidate_a38b30+0x93>
ffffffff8b3f8bbb:	44 89 e7             	mov    %r12d,%edi
ffffffff8b3f8bbe:	e8 1d 92 b2 ff       	call   ffffffff8af21de0 <handler_619_body-0x4d5870>
ffffffff8b3f8bc3:	45 85 ff             	test   %r15d,%r15d
ffffffff8b3f8bc6:	74 22                	je     ffffffff8b3f8bea <frame_candidate_a38b30+0xba>
ffffffff8b3f8bc8:	48 8d 3d 47 16 85 00 	lea    0x851647(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8bcf:	48 8d 35 ef 40 92 00 	lea    0x9240ef(%rip),%rsi        # ffffffff8bd1ccc5 <frame_candidate_a39640+0x923685>
ffffffff8b3f8bd6:	ba 94 11 00 00       	mov    $0x1194,%edx
ffffffff8b3f8bdb:	44 89 f9             	mov    %r15d,%ecx
ffffffff8b3f8bde:	45 89 f8             	mov    %r15d,%r8d
ffffffff8b3f8be1:	31 c0                	xor    %eax,%eax
ffffffff8b3f8be3:	e8 28 48 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8be8:	eb 57                	jmp    ffffffff8b3f8c41 <frame_candidate_a38b30+0x111>
ffffffff8b3f8bea:	49 8b 86 48 04 00 00 	mov    0x448(%r14),%rax
ffffffff8b3f8bf1:	48 3b 05 a8 67 1b 03 	cmp    0x31b67a8(%rip),%rax        # ffffffff8e5af3a0 <frame_candidate_a39640+0x31b5d60>
ffffffff8b3f8bf8:	74 0c                	je     ffffffff8b3f8c06 <frame_candidate_a38b30+0xd6>
ffffffff8b3f8bfa:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f8bfe:	45 31 ff             	xor    %r15d,%r15d
ffffffff8b3f8c01:	48 89 03             	mov    %rax,(%rbx)
ffffffff8b3f8c04:	eb 3b                	jmp    ffffffff8b3f8c41 <frame_candidate_a38b30+0x111>
ffffffff8b3f8c06:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
ffffffff8b3f8c0a:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f8c0d:	e8 2e 24 93 ff       	call   ffffffff8ad2b040 <handler_619_body-0x6cc610>
ffffffff8b3f8c12:	85 c0                	test   %eax,%eax
ffffffff8b3f8c14:	74 e4                	je     ffffffff8b3f8bfa <frame_candidate_a38b30+0xca>
ffffffff8b3f8c16:	48 8d 3d f9 15 85 00 	lea    0x8515f9(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8c1d:	48 8d 35 a1 40 92 00 	lea    0x9240a1(%rip),%rsi        # ffffffff8bd1ccc5 <frame_candidate_a39640+0x923685>
ffffffff8b3f8c24:	ba 9b 11 00 00       	mov    $0x119b,%edx
ffffffff8b3f8c29:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8c2b:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f8c2e:	41 89 c7             	mov    %eax,%r15d
ffffffff8b3f8c31:	31 c0                	xor    %eax,%eax
ffffffff8b3f8c33:	e8 d8 47 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8c38:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f8c3c:	e8 ff 17 b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f8c41:	48 8d 05 c8 36 ee 02 	lea    0x2ee36c8(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f8c48:	48 8b 00             	mov    (%rax),%rax
ffffffff8b3f8c4b:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b3f8c4f:	75 31                	jne    ffffffff8b3f8c82 <frame_candidate_a38b30+0x152>
ffffffff8b3f8c51:	44 89 f8             	mov    %r15d,%eax
ffffffff8b3f8c54:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b3f8c58:	5b                   	pop    %rbx
ffffffff8b3f8c59:	41 5c                	pop    %r12
ffffffff8b3f8c5b:	41 5d                	pop    %r13
ffffffff8b3f8c5d:	41 5e                	pop    %r14
ffffffff8b3f8c5f:	41 5f                	pop    %r15
ffffffff8b3f8c61:	5d                   	pop    %rbp
ffffffff8b3f8c62:	c3                   	ret
ffffffff8b3f8c63:	48 8d 05 26 02 b3 01 	lea    0x1b30226(%rip),%rax        # ffffffff8cf28e90 <frame_candidate_a39640+0x1b2f850>
ffffffff8b3f8c6a:	48 89 7d c0          	mov    %rdi,-0x40(%rbp)
ffffffff8b3f8c6e:	4c 89 ee             	mov    %r13,%rsi
ffffffff8b3f8c71:	48 89 c7             	mov    %rax,%rdi
ffffffff8b3f8c74:	e8 47 6c a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f8c79:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
ffffffff8b3f8c7d:	e9 1f ff ff ff       	jmp    ffffffff8b3f8ba1 <frame_candidate_a38b30+0x71>
ffffffff8b3f8c82:	e8 29 4a cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f8c87:	0f 0b                	ud2
ffffffff8b3f8c89:	90                   	nop
ffffffff8b3f8c8a:	90                   	nop
ffffffff8b3f8c8b:	90                   	nop
ffffffff8b3f8c8c:	90                   	nop
ffffffff8b3f8c8d:	90                   	nop
ffffffff8b3f8c8e:	90                   	nop
ffffffff8b3f8c8f:	90                   	nop

ffffffff8b3f8c90 <frame_candidate_a38c90>:
ffffffff8b3f8c90:	55                   	push   %rbp
ffffffff8b3f8c91:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f8c94:	41 57                	push   %r15
ffffffff8b3f8c96:	41 56                	push   %r14
ffffffff8b3f8c98:	53                   	push   %rbx
ffffffff8b3f8c99:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8b3f8c9d:	4c 8d 3d 6c 36 ee 02 	lea    0x2ee366c(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f8ca4:	48 89 f3             	mov    %rsi,%rbx
ffffffff8b3f8ca7:	49 8b 07             	mov    (%r15),%rax
ffffffff8b3f8caa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8b3f8cae:	48 8b bf 98 02 00 00 	mov    0x298(%rdi),%rdi
ffffffff8b3f8cb5:	48 8b 47 30          	mov    0x30(%rdi),%rax
ffffffff8b3f8cb9:	8b 08                	mov    (%rax),%ecx
ffffffff8b3f8cbb:	89 0e                	mov    %ecx,(%rsi)
ffffffff8b3f8cbd:	8b 48 20             	mov    0x20(%rax),%ecx
ffffffff8b3f8cc0:	48 89 4e 10          	mov    %rcx,0x10(%rsi)
ffffffff8b3f8cc4:	8b 48 20             	mov    0x20(%rax),%ecx
ffffffff8b3f8cc7:	48 89 4e 18          	mov    %rcx,0x18(%rsi)
ffffffff8b3f8ccb:	48 8b 40 38          	mov    0x38(%rax),%rax
ffffffff8b3f8ccf:	48 89 46 20          	mov    %rax,0x20(%rsi)
ffffffff8b3f8cd3:	48 8d 75 d8          	lea    -0x28(%rbp),%rsi
ffffffff8b3f8cd7:	e8 d4 15 ef ff       	call   ffffffff8b2ea2b0 <handler_619_body-0x10d3a0>
ffffffff8b3f8cdc:	41 89 c6             	mov    %eax,%r14d
ffffffff8b3f8cdf:	85 c0                	test   %eax,%eax
ffffffff8b3f8ce1:	74 22                	je     ffffffff8b3f8d05 <frame_candidate_a38c90+0x75>
ffffffff8b3f8ce3:	48 8d 3d c8 7e 97 00 	lea    0x977ec8(%rip),%rdi        # ffffffff8bd70bb2 <frame_candidate_a39640+0x977572>
ffffffff8b3f8cea:	48 8d 35 b8 e3 90 00 	lea    0x90e3b8(%rip),%rsi        # ffffffff8bd070a9 <frame_candidate_a39640+0x90da69>
ffffffff8b3f8cf1:	ba bf 11 00 00       	mov    $0x11bf,%edx
ffffffff8b3f8cf6:	44 89 f1             	mov    %r14d,%ecx
ffffffff8b3f8cf9:	45 89 f0             	mov    %r14d,%r8d
ffffffff8b3f8cfc:	31 c0                	xor    %eax,%eax
ffffffff8b3f8cfe:	e8 0d 47 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8d03:	eb 0c                	jmp    ffffffff8b3f8d11 <frame_candidate_a38c90+0x81>
ffffffff8b3f8d05:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
ffffffff8b3f8d09:	48 89 43 28          	mov    %rax,0x28(%rbx)
ffffffff8b3f8d0d:	48 89 43 30          	mov    %rax,0x30(%rbx)
ffffffff8b3f8d11:	49 8b 07             	mov    (%r15),%rax
ffffffff8b3f8d14:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
ffffffff8b3f8d18:	75 0e                	jne    ffffffff8b3f8d28 <frame_candidate_a38c90+0x98>
ffffffff8b3f8d1a:	44 89 f0             	mov    %r14d,%eax
ffffffff8b3f8d1d:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8b3f8d21:	5b                   	pop    %rbx
ffffffff8b3f8d22:	41 5e                	pop    %r14
ffffffff8b3f8d24:	41 5f                	pop    %r15
ffffffff8b3f8d26:	5d                   	pop    %rbp
ffffffff8b3f8d27:	c3                   	ret
ffffffff8b3f8d28:	e8 83 49 cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f8d2d:	0f 0b                	ud2
ffffffff8b3f8d2f:	90                   	nop

ffffffff8b3f8d30 <frame_candidate_a38d30>:
ffffffff8b3f8d30:	55                   	push   %rbp
ffffffff8b3f8d31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f8d34:	41 57                	push   %r15
ffffffff8b3f8d36:	41 56                	push   %r14
ffffffff8b3f8d38:	41 55                	push   %r13
ffffffff8b3f8d3a:	41 54                	push   %r12
ffffffff8b3f8d3c:	53                   	push   %rbx
ffffffff8b3f8d3d:	48 83 ec 58          	sub    $0x58,%rsp
ffffffff8b3f8d41:	4c 8d 2d c8 35 ee 02 	lea    0x2ee35c8(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f8d48:	89 75 9c             	mov    %esi,-0x64(%rbp)
ffffffff8b3f8d4b:	49 89 fe             	mov    %rdi,%r14
ffffffff8b3f8d4e:	be 00 00 08 00       	mov    $0x80000,%esi
ffffffff8b3f8d53:	31 d2                	xor    %edx,%edx
ffffffff8b3f8d55:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8d57:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f8d5a:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f8d5d:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8b3f8d61:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b3f8d65:	48 8b 9f 98 02 00 00 	mov    0x298(%rdi),%rbx
ffffffff8b3f8d6c:	48 8b 43 30          	mov    0x30(%rbx),%rax
ffffffff8b3f8d70:	4c 8d 7b 68          	lea    0x68(%rbx),%r15
ffffffff8b3f8d74:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8d77:	44 8b 60 20          	mov    0x20(%rax),%r12d
ffffffff8b3f8d7b:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
ffffffff8b3f8d82:	00 00 
ffffffff8b3f8d84:	48 89 45 90          	mov    %rax,-0x70(%rbp)
ffffffff8b3f8d88:	6a 00                	push   $0x0
ffffffff8b3f8d8a:	6a 00                	push   $0x0
ffffffff8b3f8d8c:	e8 df 89 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f8d91:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f8d95:	83 bb 38 04 00 00 00 	cmpl   $0x0,0x438(%rbx)
ffffffff8b3f8d9c:	0f 84 88 00 00 00    	je     ffffffff8b3f8e2a <frame_candidate_a38d30+0xfa>
ffffffff8b3f8da2:	83 bb 10 04 00 00 00 	cmpl   $0x0,0x410(%rbx)
ffffffff8b3f8da9:	0f 88 a8 03 00 00    	js     ffffffff8b3f9157 <frame_candidate_a38d30+0x427>
ffffffff8b3f8daf:	48 8b 7b 20          	mov    0x20(%rbx),%rdi
ffffffff8b3f8db3:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b3f8db7:	48 8d 45 a0          	lea    -0x60(%rbp),%rax
ffffffff8b3f8dbb:	31 f6                	xor    %esi,%esi
ffffffff8b3f8dbd:	44 89 e2             	mov    %r12d,%edx
ffffffff8b3f8dc0:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8dc2:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f8dc5:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f8dc8:	50                   	push   %rax
ffffffff8b3f8dc9:	6a 00                	push   $0x0
ffffffff8b3f8dcb:	6a 00                	push   $0x0
ffffffff8b3f8dcd:	e8 be 4d 06 00       	call   ffffffff8b45db90 <frame_candidate_a39640+0x64550>
ffffffff8b3f8dd2:	48 83 c4 20          	add    $0x20,%rsp
ffffffff8b3f8dd6:	85 c0                	test   %eax,%eax
ffffffff8b3f8dd8:	74 75                	je     ffffffff8b3f8e4f <frame_candidate_a38d30+0x11f>
ffffffff8b3f8dda:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
ffffffff8b3f8dde:	41 89 c4             	mov    %eax,%r12d
ffffffff8b3f8de1:	e8 aa 48 06 00       	call   ffffffff8b45d690 <frame_candidate_a39640+0x64050>
ffffffff8b3f8de6:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8de9:	be 00 00 10 00       	mov    $0x100000,%esi
ffffffff8b3f8dee:	31 d2                	xor    %edx,%edx
ffffffff8b3f8df0:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8df2:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f8df5:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f8df8:	6a 00                	push   $0x0
ffffffff8b3f8dfa:	6a 00                	push   $0x0
ffffffff8b3f8dfc:	e8 6f 89 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f8e01:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f8e05:	48 8d 3d 0a 14 85 00 	lea    0x85140a(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8e0c:	48 8d 35 b9 9c 8d 00 	lea    0x8d9cb9(%rip),%rsi        # ffffffff8bcd2acc <frame_candidate_a39640+0x8d948c>
ffffffff8b3f8e13:	ba e0 11 00 00       	mov    $0x11e0,%edx
ffffffff8b3f8e18:	44 89 e1             	mov    %r12d,%ecx
ffffffff8b3f8e1b:	45 89 e0             	mov    %r12d,%r8d
ffffffff8b3f8e1e:	31 c0                	xor    %eax,%eax
ffffffff8b3f8e20:	e8 eb 45 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8e25:	e9 0a 03 00 00       	jmp    ffffffff8b3f9134 <frame_candidate_a38d30+0x404>
ffffffff8b3f8e2a:	48 89 5d 88          	mov    %rbx,-0x78(%rbp)
ffffffff8b3f8e2e:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8e31:	be 00 00 10 00       	mov    $0x100000,%esi
ffffffff8b3f8e36:	31 d2                	xor    %edx,%edx
ffffffff8b3f8e38:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8e3a:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f8e3d:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f8e40:	6a 00                	push   $0x0
ffffffff8b3f8e42:	6a 00                	push   $0x0
ffffffff8b3f8e44:	e8 27 89 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f8e49:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f8e4d:	eb 6f                	jmp    ffffffff8b3f8ebe <frame_candidate_a38d30+0x18e>
ffffffff8b3f8e4f:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
ffffffff8b3f8e53:	48 8b 7b 30          	mov    0x30(%rbx),%rdi
ffffffff8b3f8e57:	ba a0 05 00 00       	mov    $0x5a0,%edx
ffffffff8b3f8e5c:	48 8b 70 18          	mov    0x18(%rax),%rsi
ffffffff8b3f8e60:	e8 7b 0d 82 ff       	call   ffffffff8ac19be0 <handler_619_body-0x7dda70>
ffffffff8b3f8e65:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8e68:	48 89 5d 88          	mov    %rbx,-0x78(%rbp)
ffffffff8b3f8e6c:	c7 83 38 04 00 00 00 	movl   $0x0,0x438(%rbx)
ffffffff8b3f8e73:	00 00 00 
ffffffff8b3f8e76:	be 00 00 10 00       	mov    $0x100000,%esi
ffffffff8b3f8e7b:	31 d2                	xor    %edx,%edx
ffffffff8b3f8e7d:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8e7f:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f8e82:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f8e85:	6a 00                	push   $0x0
ffffffff8b3f8e87:	6a 00                	push   $0x0
ffffffff8b3f8e89:	e8 e2 88 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f8e8e:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f8e92:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
ffffffff8b3f8e96:	48 8b 07             	mov    (%rdi),%rax
ffffffff8b3f8e99:	48 8b 40 20          	mov    0x20(%rax),%rax
ffffffff8b3f8e9d:	4c 8b 78 08          	mov    0x8(%rax),%r15
ffffffff8b3f8ea1:	48 8d 05 40 7e 82 ff 	lea    -0x7d81c0(%rip),%rax        # ffffffff8ac20ce8 <handler_619_body-0x7d6968>
ffffffff8b3f8ea8:	4c 29 f8             	sub    %r15,%rax
ffffffff8b3f8eab:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8b3f8eaf:	48 3d ff 06 00 00    	cmp    $0x6ff,%rax
ffffffff8b3f8eb5:	0f 87 c2 02 00 00    	ja     ffffffff8b3f917d <frame_candidate_a38d30+0x44d>
ffffffff8b3f8ebb:	41 ff d7             	call   *%r15
ffffffff8b3f8ebe:	8b 4d 9c             	mov    -0x64(%rbp),%ecx
ffffffff8b3f8ec1:	b8 01 00 00 00       	mov    $0x1,%eax
ffffffff8b3f8ec6:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
ffffffff8b3f8eca:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8ecd:	83 f9 04             	cmp    $0x4,%ecx
ffffffff8b3f8ed0:	0f 45 c1             	cmovne %ecx,%eax
ffffffff8b3f8ed3:	45 31 e4             	xor    %r12d,%r12d
ffffffff8b3f8ed6:	83 f8 01             	cmp    $0x1,%eax
ffffffff8b3f8ed9:	89 45 9c             	mov    %eax,-0x64(%rbp)
ffffffff8b3f8edc:	41 0f 95 c7          	setne  %r15b
ffffffff8b3f8ee0:	e8 4b 1b b1 ff       	call   ffffffff8af0aa30 <handler_619_body-0x4ecc20>
ffffffff8b3f8ee5:	48 85 c0             	test   %rax,%rax
ffffffff8b3f8ee8:	0f 84 4c 01 00 00    	je     ffffffff8b3f903a <frame_candidate_a38d30+0x30a>
ffffffff8b3f8eee:	45 88 fc             	mov    %r15b,%r12b
ffffffff8b3f8ef1:	48 89 c3             	mov    %rax,%rbx
ffffffff8b3f8ef4:	4d 8d 6e 18          	lea    0x18(%r14),%r13
ffffffff8b3f8ef8:	4c 8d 7d a8          	lea    -0x58(%rbp),%r15
ffffffff8b3f8efc:	c7 45 98 00 00 00 00 	movl   $0x0,-0x68(%rbp)
ffffffff8b3f8f03:	41 c1 e4 09          	shl    $0x9,%r12d
ffffffff8b3f8f07:	41 81 cc 00 09 08 00 	or     $0x80900,%r12d
ffffffff8b3f8f0e:	eb 4f                	jmp    ffffffff8b3f8f5f <frame_candidate_a38d30+0x22f>
ffffffff8b3f8f10:	48 8d 3d ff 12 85 00 	lea    0x8512ff(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8f17:	48 8d 35 ae 9b 8d 00 	lea    0x8d9bae(%rip),%rsi        # ffffffff8bcd2acc <frame_candidate_a39640+0x8d948c>
ffffffff8b3f8f1e:	ba 0f 12 00 00       	mov    $0x120f,%edx
ffffffff8b3f8f23:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8f25:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f8f28:	31 c0                	xor    %eax,%eax
ffffffff8b3f8f2a:	e8 e1 44 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f8f2f:	4c 89 ef             	mov    %r13,%rdi
ffffffff8b3f8f32:	31 f6                	xor    %esi,%esi
ffffffff8b3f8f34:	31 d2                	xor    %edx,%edx
ffffffff8b3f8f36:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f8f38:	e8 c3 da a8 ff       	call   ffffffff8ae86a00 <handler_619_body-0x570c50>
ffffffff8b3f8f3d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8f40:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8f43:	e8 68 1c b1 ff       	call   ffffffff8af0abb0 <handler_619_body-0x4ecaa0>
ffffffff8b3f8f48:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f8f4b:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f8f4e:	e8 dd 1a b1 ff       	call   ffffffff8af0aa30 <handler_619_body-0x4ecc20>
ffffffff8b3f8f53:	48 89 c3             	mov    %rax,%rbx
ffffffff8b3f8f56:	48 85 c0             	test   %rax,%rax
ffffffff8b3f8f59:	0f 84 e2 00 00 00    	je     ffffffff8b3f9041 <frame_candidate_a38d30+0x311>
ffffffff8b3f8f5f:	83 bb d4 01 00 00 00 	cmpl   $0x0,0x1d4(%rbx)
ffffffff8b3f8f66:	0f 84 a9 00 00 00    	je     ffffffff8b3f9015 <frame_candidate_a38d30+0x2e5>
ffffffff8b3f8f6c:	f6 83 c4 01 00 00 80 	testb  $0x80,0x1c4(%rbx)
ffffffff8b3f8f73:	0f 85 9c 00 00 00    	jne    ffffffff8b3f9015 <frame_candidate_a38d30+0x2e5>
ffffffff8b3f8f79:	48 8b 43 10          	mov    0x10(%rbx),%rax
ffffffff8b3f8f7d:	f6 40 20 0d          	testb  $0xd,0x20(%rax)
ffffffff8b3f8f81:	75 13                	jne    ffffffff8b3f8f96 <frame_candidate_a38d30+0x266>
ffffffff8b3f8f83:	83 7d 9c 03          	cmpl   $0x3,-0x64(%rbp)
ffffffff8b3f8f87:	0f 84 88 00 00 00    	je     ffffffff8b3f9015 <frame_candidate_a38d30+0x2e5>
ffffffff8b3f8f8d:	83 bb 58 01 00 00 00 	cmpl   $0x0,0x158(%rbx)
ffffffff8b3f8f94:	74 7f                	je     ffffffff8b3f9015 <frame_candidate_a38d30+0x2e5>
ffffffff8b3f8f96:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
ffffffff8b3f8f9a:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f8f9d:	44 89 e6             	mov    %r12d,%esi
ffffffff8b3f8fa0:	e8 cb 0d b1 ff       	call   ffffffff8af09d70 <handler_619_body-0x4ed8e0>
ffffffff8b3f8fa5:	83 f8 02             	cmp    $0x2,%eax
ffffffff8b3f8fa8:	0f 84 62 ff ff ff    	je     ffffffff8b3f8f10 <frame_candidate_a38d30+0x1e0>
ffffffff8b3f8fae:	83 f8 4d             	cmp    $0x4d,%eax
ffffffff8b3f8fb1:	0f 84 59 ff ff ff    	je     ffffffff8b3f8f10 <frame_candidate_a38d30+0x1e0>
ffffffff8b3f8fb7:	85 c0                	test   %eax,%eax
ffffffff8b3f8fb9:	75 6f                	jne    ffffffff8b3f902a <frame_candidate_a38d30+0x2fa>
ffffffff8b3f8fbb:	48 8d 05 36 2b 0a 01 	lea    0x10a2b36(%rip),%rax        # ffffffff8c49baf8 <frame_candidate_a39640+0x10a24b8>
ffffffff8b3f8fc2:	8b 4d 9c             	mov    -0x64(%rbp),%ecx
ffffffff8b3f8fc5:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b3f8fc9:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b3f8fcd:	48 8b 45 90          	mov    -0x70(%rbp),%rax
ffffffff8b3f8fd1:	48 89 5d b8          	mov    %rbx,-0x48(%rbp)
ffffffff8b3f8fd5:	89 4d c0             	mov    %ecx,-0x40(%rbp)
ffffffff8b3f8fd8:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8b3f8fdc:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8b3f8fe0:	e8 bb 43 b5 ff       	call   ffffffff8af4d3a0 <handler_619_body-0x4aa2b0>
ffffffff8b3f8fe5:	85 c0                	test   %eax,%eax
ffffffff8b3f8fe7:	74 22                	je     ffffffff8b3f900b <frame_candidate_a38d30+0x2db>
ffffffff8b3f8fe9:	48 8d 3d 26 12 85 00 	lea    0x851226(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f8ff0:	48 8d 35 d5 9a 8d 00 	lea    0x8d9ad5(%rip),%rsi        # ffffffff8bcd2acc <frame_candidate_a39640+0x8d948c>
ffffffff8b3f8ff7:	ba 18 12 00 00       	mov    $0x1218,%edx
ffffffff8b3f8ffc:	89 c1                	mov    %eax,%ecx
ffffffff8b3f8ffe:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f9001:	89 45 98             	mov    %eax,-0x68(%rbp)
ffffffff8b3f9004:	31 c0                	xor    %eax,%eax
ffffffff8b3f9006:	e8 05 44 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f900b:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f900e:	e8 2d 14 b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f9013:	eb 15                	jmp    ffffffff8b3f902a <frame_candidate_a38d30+0x2fa>
ffffffff8b3f9015:	48 81 c3 b0 00 00 00 	add    $0xb0,%rbx
ffffffff8b3f901c:	31 f6                	xor    %esi,%esi
ffffffff8b3f901e:	31 d2                	xor    %edx,%edx
ffffffff8b3f9020:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f9022:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f9025:	e8 76 df a8 ff       	call   ffffffff8ae86fa0 <handler_619_body-0x5706b0>
ffffffff8b3f902a:	4c 89 ff             	mov    %r15,%rdi
ffffffff8b3f902d:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f9030:	e8 ab 1f b1 ff       	call   ffffffff8af0afe0 <handler_619_body-0x4ec670>
ffffffff8b3f9035:	e9 19 ff ff ff       	jmp    ffffffff8b3f8f53 <frame_candidate_a38d30+0x223>
ffffffff8b3f903a:	c7 45 98 00 00 00 00 	movl   $0x0,-0x68(%rbp)
ffffffff8b3f9041:	48 8b 45 88          	mov    -0x78(%rbp),%rax
ffffffff8b3f9045:	31 f6                	xor    %esi,%esi
ffffffff8b3f9047:	31 d2                	xor    %edx,%edx
ffffffff8b3f9049:	48 8b 58 20          	mov    0x20(%rax),%rbx
ffffffff8b3f904d:	4c 8d b3 e8 00 00 00 	lea    0xe8(%rbx),%r14
ffffffff8b3f9054:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f9057:	e8 44 b6 d9 ff       	call   ffffffff8b1946a0 <handler_619_body-0x262fb0>
ffffffff8b3f905c:	83 7d 9c 03          	cmpl   $0x3,-0x64(%rbp)
ffffffff8b3f9060:	75 1c                	jne    ffffffff8b3f907e <frame_candidate_a38d30+0x34e>
ffffffff8b3f9062:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f9065:	31 f6                	xor    %esi,%esi
ffffffff8b3f9067:	31 d2                	xor    %edx,%edx
ffffffff8b3f9069:	e8 42 be d9 ff       	call   ffffffff8b194eb0 <handler_619_body-0x2627a0>
ffffffff8b3f906e:	4c 8d 2d 9b 32 ee 02 	lea    0x2ee329b(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f9075:	44 8b 65 98          	mov    -0x68(%rbp),%r12d
ffffffff8b3f9079:	e9 b6 00 00 00       	jmp    ffffffff8b3f9134 <frame_candidate_a38d30+0x404>
ffffffff8b3f907e:	48 83 bb 60 01 00 00 	cmpq   $0x0,0x160(%rbx)
ffffffff8b3f9085:	00 
ffffffff8b3f9086:	7f 09                	jg     ffffffff8b3f9091 <frame_candidate_a38d30+0x361>
ffffffff8b3f9088:	83 bb 58 01 00 00 00 	cmpl   $0x0,0x158(%rbx)
ffffffff8b3f908f:	7e d1                	jle    ffffffff8b3f9062 <frame_candidate_a38d30+0x332>
ffffffff8b3f9091:	4c 89 f7             	mov    %r14,%rdi
ffffffff8b3f9094:	31 f6                	xor    %esi,%esi
ffffffff8b3f9096:	31 d2                	xor    %edx,%edx
ffffffff8b3f9098:	e8 13 be d9 ff       	call   ffffffff8b194eb0 <handler_619_body-0x2627a0>
ffffffff8b3f909d:	48 8d 15 37 21 95 00 	lea    0x952137(%rip),%rdx        # ffffffff8bd4b1db <frame_candidate_a39640+0x951b9b>
ffffffff8b3f90a4:	48 89 df             	mov    %rbx,%rdi
ffffffff8b3f90a7:	be 00 04 08 00       	mov    $0x80400,%esi
ffffffff8b3f90ac:	b9 2b 12 00 00       	mov    $0x122b,%ecx
ffffffff8b3f90b1:	e8 9a 6a c7 ff       	call   ffffffff8b06fb50 <handler_619_body-0x387b00>
ffffffff8b3f90b6:	48 8d 05 3b 2a 0a 01 	lea    0x10a2a3b(%rip),%rax        # ffffffff8c49baf8 <frame_candidate_a39640+0x10a24b8>
ffffffff8b3f90bd:	8b 4d 9c             	mov    -0x64(%rbp),%ecx
ffffffff8b3f90c0:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b3f90c4:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b3f90c8:	48 8b 45 90          	mov    -0x70(%rbp),%rax
ffffffff8b3f90cc:	48 89 5d b8          	mov    %rbx,-0x48(%rbp)
ffffffff8b3f90d0:	89 4d c0             	mov    %ecx,-0x40(%rbp)
ffffffff8b3f90d3:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8b3f90d7:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8b3f90db:	e8 c0 42 b5 ff       	call   ffffffff8af4d3a0 <handler_619_body-0x4aa2b0>
ffffffff8b3f90e0:	4c 8d 2d 29 32 ee 02 	lea    0x2ee3229(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f90e7:	44 8b 65 98          	mov    -0x68(%rbp),%r12d
ffffffff8b3f90eb:	85 c0                	test   %eax,%eax
ffffffff8b3f90ed:	74 22                	je     ffffffff8b3f9111 <frame_candidate_a38d30+0x3e1>
ffffffff8b3f90ef:	48 8d 3d 20 11 85 00 	lea    0x851120(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f90f6:	48 8d 35 cf 99 8d 00 	lea    0x8d99cf(%rip),%rsi        # ffffffff8bcd2acc <frame_candidate_a39640+0x8d948c>
ffffffff8b3f90fd:	ba 2e 12 00 00       	mov    $0x122e,%edx
ffffffff8b3f9102:	89 c1                	mov    %eax,%ecx
ffffffff8b3f9104:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f9107:	41 89 c4             	mov    %eax,%r12d
ffffffff8b3f910a:	31 c0                	xor    %eax,%eax
ffffffff8b3f910c:	e8 ff 42 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f9111:	48 8d 05 b0 3c 0a 01 	lea    0x10a3cb0(%rip),%rax        # ffffffff8c49cdc8 <frame_candidate_a39640+0x10a3788>
ffffffff8b3f9118:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
ffffffff8b3f911c:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
ffffffff8b3f9120:	48 89 5d b8          	mov    %rbx,-0x48(%rbp)
ffffffff8b3f9124:	c7 45 c0 00 00 00 00 	movl   $0x0,-0x40(%rbp)
ffffffff8b3f912b:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8b3f912f:	e8 5c 59 b5 ff       	call   ffffffff8af4ea90 <handler_619_body-0x4a8bc0>
ffffffff8b3f9134:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8b3f9138:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b3f913c:	75 12                	jne    ffffffff8b3f9150 <frame_candidate_a38d30+0x420>
ffffffff8b3f913e:	44 89 e0             	mov    %r12d,%eax
ffffffff8b3f9141:	48 83 c4 58          	add    $0x58,%rsp
ffffffff8b3f9145:	5b                   	pop    %rbx
ffffffff8b3f9146:	41 5c                	pop    %r12
ffffffff8b3f9148:	41 5d                	pop    %r13
ffffffff8b3f914a:	41 5e                	pop    %r14
ffffffff8b3f914c:	41 5f                	pop    %r15
ffffffff8b3f914e:	5d                   	pop    %rbp
ffffffff8b3f914f:	c3                   	ret
ffffffff8b3f9150:	e8 5b 45 cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f9155:	0f 0b                	ud2
ffffffff8b3f9157:	e8 f4 87 db ff       	call   ffffffff8b1b1950 <handler_619_body-0x245d00>
ffffffff8b3f915c:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8b3f9157 <frame_candidate_a38d30+0x427>
ffffffff8b3f9163:	e8 a8 86 db ff       	call   ffffffff8b1b1810 <handler_619_body-0x245e40>
ffffffff8b3f9168:	48 8d 35 32 3b 92 00 	lea    0x923b32(%rip),%rsi        # ffffffff8bd1cca1 <frame_candidate_a39640+0x923661>
ffffffff8b3f916f:	bf 20 00 00 00       	mov    $0x20,%edi
ffffffff8b3f9174:	31 c0                	xor    %eax,%eax
ffffffff8b3f9176:	e8 95 18 26 00       	call   ffffffff8b65aa10 <frame_candidate_a39640+0x2613d0>
ffffffff8b3f917b:	0f 0b                	ud2
ffffffff8b3f917d:	48 8d 05 ec fc b2 01 	lea    0x1b2fcec(%rip),%rax        # ffffffff8cf28e70 <frame_candidate_a39640+0x1b2f830>
ffffffff8b3f9184:	49 89 fc             	mov    %rdi,%r12
ffffffff8b3f9187:	4c 89 fe             	mov    %r15,%rsi
ffffffff8b3f918a:	48 89 c7             	mov    %rax,%rdi
ffffffff8b3f918d:	e8 2e 67 a1 ff       	call   ffffffff8ae0f8c0 <handler_619_body-0x5e7d90>
ffffffff8b3f9192:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f9195:	e9 21 fd ff ff       	jmp    ffffffff8b3f8ebb <frame_candidate_a38d30+0x18b>
ffffffff8b3f919a:	90                   	nop
ffffffff8b3f919b:	90                   	nop
ffffffff8b3f919c:	90                   	nop
ffffffff8b3f919d:	90                   	nop
ffffffff8b3f919e:	90                   	nop
ffffffff8b3f919f:	90                   	nop

ffffffff8b3f91a0 <frame_candidate_a391a0>:
ffffffff8b3f91a0:	55                   	push   %rbp
ffffffff8b3f91a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f91a4:	41 57                	push   %r15
ffffffff8b3f91a6:	41 56                	push   %r14
ffffffff8b3f91a8:	41 55                	push   %r13
ffffffff8b3f91aa:	41 54                	push   %r12
ffffffff8b3f91ac:	53                   	push   %rbx
ffffffff8b3f91ad:	48 83 ec 48          	sub    $0x48,%rsp
ffffffff8b3f91b1:	48 8d 05 58 31 ee 02 	lea    0x2ee3158(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f91b8:	49 89 cf             	mov    %rcx,%r15
ffffffff8b3f91bb:	41 89 f5             	mov    %esi,%r13d
ffffffff8b3f91be:	48 89 fb             	mov    %rdi,%rbx
ffffffff8b3f91c1:	48 8b 00             	mov    (%rax),%rax
ffffffff8b3f91c4:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8b3f91c8:	65 4c 8b 34 25 00 00 	mov    %gs:0x0,%r14
ffffffff8b3f91cf:	00 00 
ffffffff8b3f91d1:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b3f91d5:	89 55 b8             	mov    %edx,-0x48(%rbp)
ffffffff8b3f91d8:	4c 89 f1             	mov    %r14,%rcx
ffffffff8b3f91db:	4d 89 f8             	mov    %r15,%r8
ffffffff8b3f91de:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f91e1:	6a 00                	push   $0x0
ffffffff8b3f91e3:	e8 88 68 0a 00       	call   ffffffff8b49fa70 <frame_candidate_a39640+0xa6430>
ffffffff8b3f91e8:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f91ec:	85 c0                	test   %eax,%eax
ffffffff8b3f91ee:	74 2a                	je     ffffffff8b3f921a <frame_candidate_a391a0+0x7a>
ffffffff8b3f91f0:	48 8d 3d 1f 10 85 00 	lea    0x85101f(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f91f7:	48 8d 35 88 b6 88 00 	lea    0x88b688(%rip),%rsi        # ffffffff8bc84886 <frame_candidate_a39640+0x88b246>
ffffffff8b3f91fe:	ba 4f 12 00 00       	mov    $0x124f,%edx
ffffffff8b3f9203:	89 c1                	mov    %eax,%ecx
ffffffff8b3f9205:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f9208:	41 89 c4             	mov    %eax,%r12d
ffffffff8b3f920b:	31 c0                	xor    %eax,%eax
ffffffff8b3f920d:	e8 fe 41 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f9212:	45 89 e5             	mov    %r12d,%r13d
ffffffff8b3f9215:	e9 b1 01 00 00       	jmp    ffffffff8b3f93cb <frame_candidate_a391a0+0x22b>
ffffffff8b3f921a:	49 83 3f 00          	cmpq   $0x0,(%r15)
ffffffff8b3f921e:	8b 4d b8             	mov    -0x48(%rbp),%ecx
ffffffff8b3f9221:	44 89 6d c4          	mov    %r13d,-0x3c(%rbp)
ffffffff8b3f9225:	41 bd 00 00 00 00    	mov    $0x0,%r13d
ffffffff8b3f922b:	4c 89 75 98          	mov    %r14,-0x68(%rbp)
ffffffff8b3f922f:	0f 85 96 01 00 00    	jne    ffffffff8b3f93cb <frame_candidate_a391a0+0x22b>
ffffffff8b3f9235:	49 89 de             	mov    %rbx,%r14
ffffffff8b3f9238:	48 8b 9b 98 02 00 00 	mov    0x298(%rbx),%rbx
ffffffff8b3f923f:	89 c8                	mov    %ecx,%eax
ffffffff8b3f9241:	4c 89 7d b0          	mov    %r15,-0x50(%rbp)
ffffffff8b3f9245:	41 89 cf             	mov    %ecx,%r15d
ffffffff8b3f9248:	48 8b 3d 41 61 1b 03 	mov    0x31b6141(%rip),%rdi        # ffffffff8e5af390 <frame_candidate_a39640+0x31b5d50>
ffffffff8b3f924f:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8b3f9254:	41 81 e7 ff ff 00 ff 	and    $0xff00ffff,%r15d
ffffffff8b3f925b:	25 00 00 ff 00       	and    $0xff0000,%eax
ffffffff8b3f9260:	41 81 cf 00 00 08 00 	or     $0x80000,%r15d
ffffffff8b3f9267:	3d 00 00 20 00       	cmp    $0x200000,%eax
ffffffff8b3f926c:	44 0f 45 f9          	cmovne %ecx,%r15d
ffffffff8b3f9270:	31 f6                	xor    %esi,%esi
ffffffff8b3f9272:	48 8b 43 08          	mov    0x8(%rbx),%rax
ffffffff8b3f9276:	48 8b 4b 30          	mov    0x30(%rbx),%rcx
ffffffff8b3f927a:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
ffffffff8b3f927e:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8b3f9282:	e8 f9 25 a0 ff       	call   ffffffff8adfb880 <handler_619_body-0x5fbdd0>
ffffffff8b3f9287:	48 8d 15 72 ae 08 01 	lea    0x108ae72(%rip),%rdx        # ffffffff8c484100 <frame_candidate_a39640+0x108aac0>
ffffffff8b3f928e:	48 8d 3d a4 7d 8d 00 	lea    0x8d7da4(%rip),%rdi        # ffffffff8bcd1039 <frame_candidate_a39640+0x8d79f9>
ffffffff8b3f9295:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
ffffffff8b3f9299:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f929c:	49 89 c4             	mov    %rax,%r12
ffffffff8b3f929f:	e8 bc ec b0 ff       	call   ffffffff8af07f60 <handler_619_body-0x4ef6f0>
ffffffff8b3f92a4:	85 c0                	test   %eax,%eax
ffffffff8b3f92a6:	74 37                	je     ffffffff8b3f92df <frame_candidate_a391a0+0x13f>
ffffffff8b3f92a8:	48 8b 4d b0          	mov    -0x50(%rbp),%rcx
ffffffff8b3f92ac:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b3f92af:	41 89 c5             	mov    %eax,%r13d
ffffffff8b3f92b2:	31 d2                	xor    %edx,%edx
ffffffff8b3f92b4:	48 c7 01 00 00 00 00 	movq   $0x0,(%rcx)
ffffffff8b3f92bb:	48 8b 3d ce 60 1b 03 	mov    0x31b60ce(%rip),%rdi        # ffffffff8e5af390 <frame_candidate_a39640+0x31b5d50>
ffffffff8b3f92c2:	e8 f9 2d a0 ff       	call   ffffffff8adfc0c0 <handler_619_body-0x5fb590>
ffffffff8b3f92c7:	48 8d 3d 48 0f 85 00 	lea    0x850f48(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f92ce:	48 8d 35 b1 b5 88 00 	lea    0x88b5b1(%rip),%rsi        # ffffffff8bc84886 <frame_candidate_a39640+0x88b246>
ffffffff8b3f92d5:	ba 72 12 00 00       	mov    $0x1272,%edx
ffffffff8b3f92da:	e9 df 00 00 00       	jmp    ffffffff8b3f93be <frame_candidate_a391a0+0x21e>
ffffffff8b3f92df:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f92e3:	44 89 7d ac          	mov    %r15d,-0x54(%rbp)
ffffffff8b3f92e7:	be 00 00 08 00       	mov    $0x80000,%esi
ffffffff8b3f92ec:	31 d2                	xor    %edx,%edx
ffffffff8b3f92ee:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f92f0:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f92f3:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f92f6:	48 8b b8 b8 00 00 00 	mov    0xb8(%rax),%rdi
ffffffff8b3f92fd:	6a 00                	push   $0x0
ffffffff8b3f92ff:	6a 00                	push   $0x0
ffffffff8b3f9301:	e8 6a 84 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f9306:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f930a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f930e:	48 8b b8 b8 00 00 00 	mov    0xb8(%rax),%rdi
ffffffff8b3f9315:	e8 26 84 1b 00       	call   ffffffff8b5b1740 <frame_candidate_a39640+0x1b8100>
ffffffff8b3f931a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f931e:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
ffffffff8b3f9322:	44 8b 7d c4          	mov    -0x3c(%rbp),%r15d
ffffffff8b3f9326:	4c 89 f6             	mov    %r14,%rsi
ffffffff8b3f9329:	4c 89 60 10          	mov    %r12,0x10(%rax)
ffffffff8b3f932d:	8b 42 20             	mov    0x20(%rdx),%eax
ffffffff8b3f9330:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
ffffffff8b3f9334:	89 81 6c 01 00 00    	mov    %eax,0x16c(%rcx)
ffffffff8b3f933a:	48 8b 4d a0          	mov    -0x60(%rbp),%rcx
ffffffff8b3f933e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f9342:	49 89 44 24 10       	mov    %rax,0x10(%r12)
ffffffff8b3f9347:	49 89 5c 24 18       	mov    %rbx,0x18(%r12)
ffffffff8b3f934c:	49 89 54 24 40       	mov    %rdx,0x40(%r12)
ffffffff8b3f9351:	49 89 4c 24 28       	mov    %rcx,0x28(%r12)
ffffffff8b3f9356:	44 89 f9             	mov    %r15d,%ecx
ffffffff8b3f9359:	48 8d 15 80 f9 b2 01 	lea    0x1b2f980(%rip),%rdx        # ffffffff8cf28ce0 <frame_candidate_a39640+0x1b2f6a0>
ffffffff8b3f9360:	49 89 4c 24 30       	mov    %rcx,0x30(%r12)
ffffffff8b3f9365:	49 c7 84 24 a0 00 00 	movq   $0x0,0xa0(%r12)
ffffffff8b3f936c:	00 00 00 00 00 
ffffffff8b3f9371:	48 89 90 f0 00 00 00 	mov    %rdx,0xf0(%rax)
ffffffff8b3f9378:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f937c:	48 89 bf 10 01 00 00 	mov    %rdi,0x110(%rdi)
ffffffff8b3f9383:	e8 28 f0 b0 ff       	call   ffffffff8af083b0 <handler_619_body-0x4ef2a0>
ffffffff8b3f9388:	85 c0                	test   %eax,%eax
ffffffff8b3f938a:	74 65                	je     ffffffff8b3f93f1 <frame_candidate_a391a0+0x251>
ffffffff8b3f938c:	48 8b 3d fd 5f 1b 03 	mov    0x31b5ffd(%rip),%rdi        # ffffffff8e5af390 <frame_candidate_a39640+0x31b5d50>
ffffffff8b3f9393:	4c 89 e6             	mov    %r12,%rsi
ffffffff8b3f9396:	31 d2                	xor    %edx,%edx
ffffffff8b3f9398:	41 89 c5             	mov    %eax,%r13d
ffffffff8b3f939b:	e8 20 2d a0 ff       	call   ffffffff8adfc0c0 <handler_619_body-0x5fb590>
ffffffff8b3f93a0:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
ffffffff8b3f93a4:	48 8d 3d 6b 0e 85 00 	lea    0x850e6b(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f93ab:	48 8d 35 d4 b4 88 00 	lea    0x88b4d4(%rip),%rsi        # ffffffff8bc84886 <frame_candidate_a39640+0x88b246>
ffffffff8b3f93b2:	ba 8f 12 00 00       	mov    $0x128f,%edx
ffffffff8b3f93b7:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
ffffffff8b3f93be:	44 89 e9             	mov    %r13d,%ecx
ffffffff8b3f93c1:	45 89 e8             	mov    %r13d,%r8d
ffffffff8b3f93c4:	31 c0                	xor    %eax,%eax
ffffffff8b3f93c6:	e8 45 40 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f93cb:	48 8d 05 3e 2f ee 02 	lea    0x2ee2f3e(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_a39640+0x2ee2cd0>
ffffffff8b3f93d2:	48 8b 00             	mov    (%rax),%rax
ffffffff8b3f93d5:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8b3f93d9:	0f 85 4c 02 00 00    	jne    ffffffff8b3f962b <frame_candidate_a391a0+0x48b>
ffffffff8b3f93df:	44 89 e8             	mov    %r13d,%eax
ffffffff8b3f93e2:	48 83 c4 48          	add    $0x48,%rsp
ffffffff8b3f93e6:	5b                   	pop    %rbx
ffffffff8b3f93e7:	41 5c                	pop    %r12
ffffffff8b3f93e9:	41 5d                	pop    %r13
ffffffff8b3f93eb:	41 5e                	pop    %r14
ffffffff8b3f93ed:	41 5f                	pop    %r15
ffffffff8b3f93ef:	5d                   	pop    %rbp
ffffffff8b3f93f0:	c3                   	ret
ffffffff8b3f93f1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f93f5:	81 a0 c8 01 00 00 ff 	andl   $0xffffefff,0x1c8(%rax)
ffffffff8b3f93fc:	ef ff ff 
ffffffff8b3f93ff:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f9403:	48 83 ec 08          	sub    $0x8,%rsp
ffffffff8b3f9407:	44 89 fe             	mov    %r15d,%esi
ffffffff8b3f940a:	4c 8b 7d b0          	mov    -0x50(%rbp),%r15
ffffffff8b3f940e:	8b 55 ac             	mov    -0x54(%rbp),%edx
ffffffff8b3f9411:	48 8b 4d 98          	mov    -0x68(%rbp),%rcx
ffffffff8b3f9415:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b3f9418:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f941b:	4d 89 f8             	mov    %r15,%r8
ffffffff8b3f941e:	6a 00                	push   $0x0
ffffffff8b3f9420:	e8 7b 68 0a 00       	call   ffffffff8b49fca0 <frame_candidate_a39640+0xa6660>
ffffffff8b3f9425:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f9429:	85 c0                	test   %eax,%eax
ffffffff8b3f942b:	74 29                	je     ffffffff8b3f9456 <frame_candidate_a391a0+0x2b6>
ffffffff8b3f942d:	48 8d 3d e2 0d 85 00 	lea    0x850de2(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f9434:	48 8d 35 4b b4 88 00 	lea    0x88b44b(%rip),%rsi        # ffffffff8bc84886 <frame_candidate_a39640+0x88b246>
ffffffff8b3f943b:	ba 99 12 00 00       	mov    $0x1299,%edx
ffffffff8b3f9440:	89 c1                	mov    %eax,%ecx
ffffffff8b3f9442:	41 89 c0             	mov    %eax,%r8d
ffffffff8b3f9445:	89 c3                	mov    %eax,%ebx
ffffffff8b3f9447:	31 c0                	xor    %eax,%eax
ffffffff8b3f9449:	e8 c2 3f 82 ff       	call   ffffffff8ac1d410 <handler_619_body-0x7da240>
ffffffff8b3f944e:	41 89 dd             	mov    %ebx,%r13d
ffffffff8b3f9451:	e9 75 ff ff ff       	jmp    ffffffff8b3f93cb <frame_candidate_a391a0+0x22b>
ffffffff8b3f9456:	49 83 3f 00          	cmpq   $0x0,(%r15)
ffffffff8b3f945a:	0f 85 6b ff ff ff    	jne    ffffffff8b3f93cb <frame_candidate_a391a0+0x22b>
ffffffff8b3f9460:	48 8b bb 48 04 00 00 	mov    0x448(%rbx),%rdi
ffffffff8b3f9467:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8b3f946c:	31 f6                	xor    %esi,%esi
ffffffff8b3f946e:	e8 0d 24 a0 ff       	call   ffffffff8adfb880 <handler_619_body-0x5fbdd0>
ffffffff8b3f9473:	4c 89 e7             	mov    %r12,%rdi
ffffffff8b3f9476:	48 8d 15 5e bc 89 00 	lea    0x89bc5e(%rip),%rdx        # ffffffff8bc950db <frame_candidate_a39640+0x89ba9b>
ffffffff8b3f947d:	49 89 c6             	mov    %rax,%r14
ffffffff8b3f9480:	49 89 84 24 88 00 00 	mov    %rax,0x88(%r12)
ffffffff8b3f9487:	00 
ffffffff8b3f9488:	31 f6                	xor    %esi,%esi
ffffffff8b3f948a:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f948c:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f948f:	48 81 c7 c8 00 00 00 	add    $0xc8,%rdi
ffffffff8b3f9496:	e8 f5 81 1b 00       	call   ffffffff8b5b1690 <frame_candidate_a39640+0x1b8050>
ffffffff8b3f949b:	8b 83 10 04 00 00    	mov    0x410(%rbx),%eax
ffffffff8b3f94a1:	85 c0                	test   %eax,%eax
ffffffff8b3f94a3:	78 26                	js     ffffffff8b3f94cb <frame_candidate_a391a0+0x32b>
ffffffff8b3f94a5:	48 8d 7b 68          	lea    0x68(%rbx),%rdi
ffffffff8b3f94a9:	be 00 00 08 00       	mov    $0x80000,%esi
ffffffff8b3f94ae:	31 d2                	xor    %edx,%edx
ffffffff8b3f94b0:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f94b2:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f94b5:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f94b8:	6a 00                	push   $0x0
ffffffff8b3f94ba:	6a 00                	push   $0x0
ffffffff8b3f94bc:	e8 af 82 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f94c1:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f94c5:	8b 83 10 04 00 00    	mov    0x410(%rbx),%eax
ffffffff8b3f94cb:	a8 01                	test   $0x1,%al
ffffffff8b3f94cd:	75 10                	jne    ffffffff8b3f94df <frame_candidate_a391a0+0x33f>
ffffffff8b3f94cf:	8b 7d c4             	mov    -0x3c(%rbp),%edi
ffffffff8b3f94d2:	48 89 de             	mov    %rbx,%rsi
ffffffff8b3f94d5:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b3f94d8:	e8 23 c8 92 ff       	call   ffffffff8ad25d00 <handler_619_body-0x6d1950>
ffffffff8b3f94dd:	eb 0e                	jmp    ffffffff8b3f94ed <frame_candidate_a391a0+0x34d>
ffffffff8b3f94df:	8b 7d c4             	mov    -0x3c(%rbp),%edi
ffffffff8b3f94e2:	48 89 de             	mov    %rbx,%rsi
ffffffff8b3f94e5:	4c 89 f2             	mov    %r14,%rdx
ffffffff8b3f94e8:	e8 03 d3 92 ff       	call   ffffffff8ad267f0 <handler_619_body-0x6d0e60>
ffffffff8b3f94ed:	83 bb 10 04 00 00 00 	cmpl   $0x0,0x410(%rbx)
ffffffff8b3f94f4:	41 89 c5             	mov    %eax,%r13d
ffffffff8b3f94f7:	78 20                	js     ffffffff8b3f9519 <frame_candidate_a391a0+0x379>
ffffffff8b3f94f9:	48 8d 7b 68          	lea    0x68(%rbx),%rdi
ffffffff8b3f94fd:	be 00 00 10 00       	mov    $0x100000,%esi
ffffffff8b3f9502:	31 d2                	xor    %edx,%edx
ffffffff8b3f9504:	31 c9                	xor    %ecx,%ecx
ffffffff8b3f9506:	45 31 c0             	xor    %r8d,%r8d
ffffffff8b3f9509:	45 31 c9             	xor    %r9d,%r9d
ffffffff8b3f950c:	6a 00                	push   $0x0
ffffffff8b3f950e:	6a 00                	push   $0x0
ffffffff8b3f9510:	e8 5b 82 1b 00       	call   ffffffff8b5b1770 <frame_candidate_a39640+0x1b8130>
ffffffff8b3f9515:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8b3f9519:	45 85 ed             	test   %r13d,%r13d
ffffffff8b3f951c:	74 31                	je     ffffffff8b3f954f <frame_candidate_a391a0+0x3af>
ffffffff8b3f951e:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f9522:	e8 99 1c b1 ff       	call   ffffffff8af0b1c0 <handler_619_body-0x4ec490>
ffffffff8b3f9527:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
ffffffff8b3f952b:	e8 10 0f b1 ff       	call   ffffffff8af0a440 <handler_619_body-0x4ed210>
ffffffff8b3f9530:	49 c7 07 00 00 00 00 	movq   $0x0,(%r15)
ffffffff8b3f9537:	48 8d 3d d8 0c 85 00 	lea    0x850cd8(%rip),%rdi        # ffffffff8bc4a216 <frame_candidate_a39640+0x850bd6>
ffffffff8b3f953e:	48 8d 35 41 b3 88 00 	lea    0x88b341(%rip),%rsi        # ffffffff8bc84886 <frame_candidate_a39640+0x88b246>
ffffffff8b3f9545:	ba b3 12 00 00       	mov    $0x12b3,%edx
ffffffff8b3f954a:	e9 6f fe ff ff       	jmp    ffffffff8b3f93be <frame_candidate_a391a0+0x21e>
ffffffff8b3f954f:	49 c7 44 24 58 00 00 	movq   $0x0,0x58(%r12)
ffffffff8b3f9556:	00 00 
ffffffff8b3f9558:	48 8d 35 41 ab 09 01 	lea    0x109ab41(%rip),%rsi        # ffffffff8c4940a0 <frame_candidate_a39640+0x109aa60>
ffffffff8b3f955f:	41 0f b7 06          	movzwl (%r14),%eax
ffffffff8b3f9563:	66 41 89 44 24 60    	mov    %ax,0x60(%r12)
ffffffff8b3f9569:	c1 e8 0c             	shr    $0xc,%eax
ffffffff8b3f956c:	41 8b 4e 04          	mov    0x4(%r14),%ecx
ffffffff8b3f9570:	41 89 8c 24 84 00 00 	mov    %ecx,0x84(%r12)
ffffffff8b3f9577:	00 
ffffffff8b3f9578:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8b3f957c:	49 89 4c 24 68       	mov    %rcx,0x68(%r12)
ffffffff8b3f9581:	41 8b 4e 48          	mov    0x48(%r14),%ecx
ffffffff8b3f9585:	41 89 4c 24 7c       	mov    %ecx,0x7c(%r12)
ffffffff8b3f958a:	41 8b 4e 4c          	mov    0x4c(%r14),%ecx
ffffffff8b3f958e:	41 89 8c 24 80 00 00 	mov    %ecx,0x80(%r12)
ffffffff8b3f9595:	00 
ffffffff8b3f9596:	41 0f b7 4e 02       	movzwl 0x2(%r14),%ecx
ffffffff8b3f959b:	66 41 89 4c 24 62    	mov    %cx,0x62(%r12)
ffffffff8b3f95a1:	49 8b 4e 10          	mov    0x10(%r14),%rcx
ffffffff8b3f95a5:	49 89 4c 24 70       	mov    %rcx,0x70(%r12)
ffffffff8b3f95aa:	8b 04 86             	mov    (%rsi,%rax,4),%eax
ffffffff8b3f95ad:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
ffffffff8b3f95b1:	89 82 d4 01 00 00    	mov    %eax,0x1d4(%rdx)
ffffffff8b3f95b7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f95bb:	48 8b b8 b8 00 00 00 	mov    0xb8(%rax),%rdi
ffffffff8b3f95c2:	e8 69 81 1b 00       	call   ffffffff8b5b1730 <frame_candidate_a39640+0x1b80f0>
ffffffff8b3f95c7:	8b 83 18 02 00 00    	mov    0x218(%rbx),%eax
ffffffff8b3f95cd:	49 39 44 24 30       	cmp    %rax,0x30(%r12)
ffffffff8b3f95d2:	75 48                	jne    ffffffff8b3f961c <frame_candidate_a391a0+0x47c>
ffffffff8b3f95d4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f95d8:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
ffffffff8b3f95dc:	83 88 c8 01 00 00 01 	orl    $0x1,0x1c8(%rax)
ffffffff8b3f95e3:	48 83 39 01          	cmpq   $0x1,(%rcx)
ffffffff8b3f95e7:	75 33                	jne    ffffffff8b3f961c <frame_candidate_a391a0+0x47c>
ffffffff8b3f95e9:	48 83 bb 78 02 00 00 	cmpq   $0x0,0x278(%rbx)
ffffffff8b3f95f0:	00 
ffffffff8b3f95f1:	74 29                	je     ffffffff8b3f961c <frame_candidate_a391a0+0x47c>
ffffffff8b3f95f3:	48 8d 35 96 f2 b2 01 	lea    0x1b2f296(%rip),%rsi        # ffffffff8cf28890 <frame_candidate_a39640+0x1b2f250>
ffffffff8b3f95fa:	bf 10 00 00 00       	mov    $0x10,%edi
ffffffff8b3f95ff:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8b3f9604:	e8 47 f5 1c 00       	call   ffffffff8b5c8b50 <frame_candidate_a39640+0x1cf510>
ffffffff8b3f9609:	48 c7 00 01 00 00 00 	movq   $0x1,(%rax)
ffffffff8b3f9610:	c6 40 08 2f          	movb   $0x2f,0x8(%rax)
ffffffff8b3f9614:	49 89 84 24 b8 00 00 	mov    %rax,0xb8(%r12)
ffffffff8b3f961b:	00 
ffffffff8b3f961c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8b3f9620:	45 31 ed             	xor    %r13d,%r13d
ffffffff8b3f9623:	49 89 07             	mov    %rax,(%r15)
ffffffff8b3f9626:	e9 a0 fd ff ff       	jmp    ffffffff8b3f93cb <frame_candidate_a391a0+0x22b>
ffffffff8b3f962b:	e8 80 40 cc ff       	call   ffffffff8b0bd6b0 <handler_619_body-0x339fa0>
ffffffff8b3f9630:	0f 0b                	ud2
ffffffff8b3f9632:	90                   	nop
ffffffff8b3f9633:	90                   	nop
ffffffff8b3f9634:	90                   	nop
ffffffff8b3f9635:	90                   	nop
ffffffff8b3f9636:	90                   	nop
ffffffff8b3f9637:	90                   	nop
ffffffff8b3f9638:	90                   	nop
ffffffff8b3f9639:	90                   	nop
ffffffff8b3f963a:	90                   	nop
ffffffff8b3f963b:	90                   	nop
ffffffff8b3f963c:	90                   	nop
ffffffff8b3f963d:	90                   	nop
ffffffff8b3f963e:	90                   	nop
ffffffff8b3f963f:	90                   	nop

ffffffff8b3f9640 <frame_candidate_a39640>:
ffffffff8b3f9640:	55                   	push   %rbp
ffffffff8b3f9641:	48 89 e5             	mov    %rsp,%rbp
ffffffff8b3f9644:	41 57                	push   %r15
ffffffff8b3f9646:	41 56                	push   %r14
ffffffff8b3f9648:	41 55                	push   %r13
ffffffff8b3f964a:	41 54                	push   %r12
ffffffff8b3f964c:	53                   	push   %rbx
ffffffff8b3f964d:	48                   	rex.W
ffffffff8b3f964e:	83                   	.byte 0x83
ffffffff8b3f964f:	ec                   	in     (%dx),%al
