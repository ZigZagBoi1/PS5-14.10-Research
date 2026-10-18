; REA 6.7.0 full disassembly of handler_632.bin
; SHA256 3db11200355a31619c015d92f992ee36739d19d5e69a350accf4821d84457e2b; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25ee0, kernel RVA 0x265ee0.
; REA inspect_with_objdump Evidence: ev_4e4c1b2485f10408c4ffea4de8b7143a93cd5dbed4608b77e4c12ef5db8eb7ce
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 632; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_632.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25ee0 <handler_632_entry>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266ed8+0x1d1f58>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266ed8+0x1d2198>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266ed8+0x1d2278>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266ed8+0x1d24c8>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266ed8+0x4575f8>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266ed8+0x856a58>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266ed8+0x4576e8>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266ed8+0x457928>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266ed8+0x829f38>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266ed8+0x23bf08>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266ed8+0x856bf8>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266ed8+0x7d0788>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266ed8+0x8572e8>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266ed8+0x8578d8>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266ed8+0x791318>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266ed8+0x982638>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266ed8+0x740e38>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266ed8+0x742688>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266ed8+0x742f38>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266ed8+0x743068>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266ed8+0x694568>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266ed8+0x23c2c8>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266ed8+0x8579d8>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266ed8+0x744318>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266ed8+0x854aa8>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266ed8+0x492408>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266ed8+0x1cdec8>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266ed8+0x1cded8>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266ed8+0x1cdee8>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266ed8+0x1d0eb8>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266ed8+0x1d13a8>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266ed8+0x87f7b8>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266ed8+0x87f6a8>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266ed8+0x1e21f8>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_632_entry-0x1bf120>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266ed8+0x1e3b98>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266ed8+0x74f238>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_632_entry-0x1be870>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_632_entry-0x1be690>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_632_entry-0x1be660>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266ed8+0x1eb168>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266ed8+0x1edde8>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266ed8+0x1f0948>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266ed8+0x207098>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266ed8+0x2071a8>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266ed8+0x20bab8>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266ed8+0x20c4d8>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266ed8+0x20c9d8>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266ed8+0x20d378>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266ed8+0x20ded8>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266ed8+0x216118>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_632_entry-0x47ef0>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266ed8+0x229428>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266ed8+0x229ed8>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266ed8+0x2310d8>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266ed8+0x231108>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266ed8+0x231758>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266ed8+0x231768>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266ed8+0x690ce8>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266ed8+0x68f928>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266ed8+0x690548>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266ed8+0x6930a8>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266ed8+0x378478>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266ed8+0x378948>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266ed8+0x7cde08>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266ed8+0x3815c8>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266ed8+0x691318>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266ed8+0x692538>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266ed8+0x695518>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266ed8+0x68fdb8>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266ed8+0xa4ab38>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266ed8+0x8514c8>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266ed8+0x8514d8>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266ed8+0x6932e8>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266ed8+0x690c68>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266ed8+0x239a88>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266ed8+0x4c28a8>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266ed8+0x4c28b8>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266ed8+0x4c28c8>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266ed8+0x4546b8>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266ed8+0x851ec8>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266ed8+0x693298>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266ed8+0x9181e8>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266ed8+0x918228>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266ed8+0x692e18>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266ed8+0x693868>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266ed8+0x2ebc98>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266ed8+0x2ebd18>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266ed8+0x2ebd78>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266ed8+0x2ebda8>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266ed8+0x2ebdd8>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266ed8+0x2ebe08>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266ed8+0x917928>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266ed8+0x917d08>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266ed8+0x918098>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266ed8+0x99fe58>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266ed8+0x52b7b8>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266ed8+0x381c48>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266ed8+0x2ebe38>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266ed8+0x918288>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266ed8+0x377378>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266ed8+0x7edb58>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266ed8+0x7edb68>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266ed8+0x7edb78>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266ed8+0x7edb88>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266ed8+0x7edba8>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266ed8+0x7edbb8>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266ed8+0x692848>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266ed8+0x7edbd8>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266ed8+0x68f608>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266ed8+0x68f018>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266ed8+0x7edb48>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266ed8+0x7edb98>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266ed8+0x7edbc8>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266ed8+0x47e5f8>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266ed8+0x9185d8>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266ed8+0x5d6788>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266ed8+0x5d68e8>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266ed8+0x5d6bd8>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266ed8+0x5d6fa8>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266ed8+0x692da8>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266ed8+0x693238>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266ed8+0x6922d8>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266ed8+0x693618>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266ed8+0x6911b8>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266ed8+0x694ca8>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266ed8+0x690ca8>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266ed8+0x6909b8>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266ed8+0x6949c8>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266ed8+0x691638>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266ed8+0x691928>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266ed8+0x2341a8>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266ed8+0x2341b8>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266ed8+0x2f8b78>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266ed8+0x9cd998>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266ed8+0x575e18>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266ed8+0x575e28>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266ed8+0x575e38>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266ed8+0x575e48>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266ed8+0x575e58>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266ed8+0x33fdb8>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266ed8+0x340428>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266ed8+0x340738>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266ed8+0x340a28>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266ed8+0xa35958>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266ed8+0x341028>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266ed8+0x341198>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266ed8+0x9815a8>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266ed8+0x2341c8>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266ed8+0x2341e8>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266ed8+0x2341f8>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266ed8+0x234208>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266ed8+0x234218>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266ed8+0x2c9848>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266ed8+0x2ca798>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266ed8+0x692818>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266ed8+0x2ca358>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266ed8+0x59bf18>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266ed8+0x918268>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266ed8+0x87c708>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266ed8+0x287f48>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266ed8+0x693c38>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266ed8+0x693f58>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266ed8+0x762348>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266ed8+0x762228>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266ed8+0x3db438>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266ed8+0x3db948>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266ed8+0x3dc808>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266ed8+0x3dc9f8>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266ed8+0x3dcd88>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266ed8+0x7913b8>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266ed8+0x794c98>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266ed8+0x7de3a8>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266ed8+0xa20dc8>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266ed8+0x798128>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266ed8+0x7998a8>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266ed8+0x799908>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266ed8+0x857958>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266ed8+0x796058>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266ed8+0x38a0e8>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266ed8+0x690518>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266ed8+0x290378>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266ed8+0x796bf8>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266ed8+0x796ed8>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266ed8+0x797038>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266ed8+0x3dd5f8>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266ed8+0x3ea0f8>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266ed8+0x797b58>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266ed8+0x290a68>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266ed8+0x851c08>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266ed8+0x854788>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266ed8+0x797388>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266ed8+0x797608>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266ed8+0x797758>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266ed8+0x531458>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266ed8+0x856128>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_632_entry-0x169650>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266ed8+0x2381b8>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266ed8+0x238328>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266ed8+0x2596b8>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266ed8+0x2596d8>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_632_entry-0x1bcab0>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266ed8+0x263478>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266ed8+0x263b68>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_632_entry-0x1bb9d0>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266ed8+0x26e2f8>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266ed8+0x5aa2d8>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_632_entry-0x24b050>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266ed8+0x289158>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266ed8+0x294cf8>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266ed8+0x2a5ff8>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266ed8+0x2a6008>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266ed8+0x2a6058>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266ed8+0x2a6098>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266ed8+0x2a60d8>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266ed8+0x2a6108>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266ed8+0x2b75f8>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266ed8+0x2b8088>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266ed8+0x2b8128>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266ed8+0x2b81d8>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266ed8+0x2b8408>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266ed8+0x2b8798>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266ed8+0x2b9008>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266ed8+0x2cf528>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266ed8+0x2dddc8>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266ed8+0x2dfa18>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_632_entry-0x1b48b0>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_632_entry-0x1b3f30>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266ed8+0x2f5068>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266ed8+0x2f5158>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266ed8+0x2f5178>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266ed8+0x307328>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266ed8+0x3185c8>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266ed8+0x72d708>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266ed8+0x31ea78>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266ed8+0x332948>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266ed8+0x333508>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266ed8+0x333658>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266ed8+0x333828>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266ed8+0x3338f8>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266ed8+0x333b78>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266ed8+0x333c88>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266ed8+0x333d88>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266ed8+0x374ff8>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266ed8+0x384848>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266ed8+0x385158>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266ed8+0x385bf8>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266ed8+0x386568>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266ed8+0x386c58>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_632_entry-0x117c60>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266ed8+0x38a9d8>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266ed8+0x38bc58>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266ed8+0x3961e8>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266ed8+0x3997a8>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266ed8+0x39a068>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266ed8+0x87f5c8>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266ed8+0x3c6bc8>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266ed8+0x3c93f8>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266ed8+0x3ce038>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266ed8+0x3d8648>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266ed8+0x3f0ad8>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266ed8+0xa40438>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266ed8+0x3fbf98>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266ed8+0x3fbfa8>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266ed8+0x411f38>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266ed8+0x411f88>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266ed8+0x411fe8>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266ed8+0x412088>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266ed8+0x4122b8>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266ed8+0x412488>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266ed8+0x4127a8>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_632_entry-0x232350>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

ffffffff8ac26760 <neighbor_trampoline_266760>:
ffffffff8ac26760:	e9 3b d5 dc ff       	jmp    ffffffff8a9f3ca0 <handler_632_entry-0x232240>
ffffffff8ac26765:	cc                   	int3
ffffffff8ac26766:	cc                   	int3
ffffffff8ac26767:	cc                   	int3

ffffffff8ac26768 <neighbor_trampoline_266768>:
ffffffff8ac26768:	e9 b3 d5 dc ff       	jmp    ffffffff8a9f3d20 <handler_632_entry-0x2321c0>
ffffffff8ac2676d:	cc                   	int3
ffffffff8ac2676e:	cc                   	int3
ffffffff8ac2676f:	cc                   	int3

ffffffff8ac26770 <neighbor_trampoline_266770>:
ffffffff8ac26770:	e9 fb 67 dd ff       	jmp    ffffffff8a9fcf70 <handler_632_entry-0x228f70>
ffffffff8ac26775:	cc                   	int3
ffffffff8ac26776:	cc                   	int3
ffffffff8ac26777:	cc                   	int3

ffffffff8ac26778 <neighbor_trampoline_266778>:
ffffffff8ac26778:	e9 63 69 dd ff       	jmp    ffffffff8a9fd0e0 <handler_632_entry-0x228e00>
ffffffff8ac2677d:	cc                   	int3
ffffffff8ac2677e:	cc                   	int3
ffffffff8ac2677f:	cc                   	int3

ffffffff8ac26780 <neighbor_trampoline_266780>:
ffffffff8ac26780:	e9 db 6e dd ff       	jmp    ffffffff8a9fd660 <handler_632_entry-0x228880>
ffffffff8ac26785:	cc                   	int3
ffffffff8ac26786:	cc                   	int3
ffffffff8ac26787:	cc                   	int3

ffffffff8ac26788 <neighbor_trampoline_266788>:
ffffffff8ac26788:	e9 73 79 dd ff       	jmp    ffffffff8a9fe100 <handler_632_entry-0x227de0>
ffffffff8ac2678d:	cc                   	int3
ffffffff8ac2678e:	cc                   	int3
ffffffff8ac2678f:	cc                   	int3

ffffffff8ac26790 <neighbor_trampoline_266790>:
ffffffff8ac26790:	e9 cb 79 dd ff       	jmp    ffffffff8a9fe160 <handler_632_entry-0x227d80>
ffffffff8ac26795:	cc                   	int3
ffffffff8ac26796:	cc                   	int3
ffffffff8ac26797:	cc                   	int3

ffffffff8ac26798 <neighbor_trampoline_266798>:
ffffffff8ac26798:	e9 23 7a dd ff       	jmp    ffffffff8a9fe1c0 <handler_632_entry-0x227d20>
ffffffff8ac2679d:	cc                   	int3
ffffffff8ac2679e:	cc                   	int3
ffffffff8ac2679f:	cc                   	int3

ffffffff8ac267a0 <neighbor_trampoline_2667a0>:
ffffffff8ac267a0:	e9 cb 88 dd ff       	jmp    ffffffff8a9ff070 <handler_632_entry-0x226e70>
ffffffff8ac267a5:	cc                   	int3
ffffffff8ac267a6:	cc                   	int3
ffffffff8ac267a7:	cc                   	int3

ffffffff8ac267a8 <neighbor_trampoline_2667a8>:
ffffffff8ac267a8:	e9 23 89 dd ff       	jmp    ffffffff8a9ff0d0 <handler_632_entry-0x226e10>
ffffffff8ac267ad:	cc                   	int3
ffffffff8ac267ae:	cc                   	int3
ffffffff8ac267af:	cc                   	int3

ffffffff8ac267b0 <neighbor_trampoline_2667b0>:
ffffffff8ac267b0:	e9 fb 8c dd ff       	jmp    ffffffff8a9ff4b0 <handler_632_entry-0x226a30>
ffffffff8ac267b5:	cc                   	int3
ffffffff8ac267b6:	cc                   	int3
ffffffff8ac267b7:	cc                   	int3

ffffffff8ac267b8 <neighbor_trampoline_2667b8>:
ffffffff8ac267b8:	e9 53 8d dd ff       	jmp    ffffffff8a9ff510 <handler_632_entry-0x2269d0>
ffffffff8ac267bd:	cc                   	int3
ffffffff8ac267be:	cc                   	int3
ffffffff8ac267bf:	cc                   	int3

ffffffff8ac267c0 <neighbor_trampoline_2667c0>:
ffffffff8ac267c0:	e9 ab 8d dd ff       	jmp    ffffffff8a9ff570 <handler_632_entry-0x226970>
ffffffff8ac267c5:	cc                   	int3
ffffffff8ac267c6:	cc                   	int3
ffffffff8ac267c7:	cc                   	int3

ffffffff8ac267c8 <neighbor_trampoline_2667c8>:
ffffffff8ac267c8:	e9 e3 93 dd ff       	jmp    ffffffff8a9ffbb0 <handler_632_entry-0x226330>
ffffffff8ac267cd:	cc                   	int3
ffffffff8ac267ce:	cc                   	int3
ffffffff8ac267cf:	cc                   	int3

ffffffff8ac267d0 <neighbor_trampoline_2667d0>:
ffffffff8ac267d0:	e9 eb 97 dd ff       	jmp    ffffffff8a9fffc0 <handler_632_entry-0x225f20>
ffffffff8ac267d5:	cc                   	int3
ffffffff8ac267d6:	cc                   	int3
ffffffff8ac267d7:	cc                   	int3

ffffffff8ac267d8 <neighbor_trampoline_2667d8>:
ffffffff8ac267d8:	e9 83 a1 dd ff       	jmp    ffffffff8aa00960 <handler_632_entry-0x225580>
ffffffff8ac267dd:	cc                   	int3
ffffffff8ac267de:	cc                   	int3
ffffffff8ac267df:	cc                   	int3

ffffffff8ac267e0 <neighbor_trampoline_2667e0>:
ffffffff8ac267e0:	e9 6b a3 dd ff       	jmp    ffffffff8aa00b50 <handler_632_entry-0x225390>
ffffffff8ac267e5:	cc                   	int3
ffffffff8ac267e6:	cc                   	int3
ffffffff8ac267e7:	cc                   	int3

ffffffff8ac267e8 <neighbor_trampoline_2667e8>:
ffffffff8ac267e8:	e9 43 a4 dd ff       	jmp    ffffffff8aa00c30 <handler_632_entry-0x2252b0>
ffffffff8ac267ed:	cc                   	int3
ffffffff8ac267ee:	cc                   	int3
ffffffff8ac267ef:	cc                   	int3

ffffffff8ac267f0 <neighbor_trampoline_2667f0>:
ffffffff8ac267f0:	e9 3b ae dd ff       	jmp    ffffffff8aa01630 <handler_632_entry-0x2248b0>
ffffffff8ac267f5:	cc                   	int3
ffffffff8ac267f6:	cc                   	int3
ffffffff8ac267f7:	cc                   	int3

ffffffff8ac267f8 <neighbor_trampoline_2667f8>:
ffffffff8ac267f8:	e9 53 af dd ff       	jmp    ffffffff8aa01750 <handler_632_entry-0x224790>
ffffffff8ac267fd:	cc                   	int3
ffffffff8ac267fe:	cc                   	int3
ffffffff8ac267ff:	cc                   	int3

ffffffff8ac26800 <neighbor_trampoline_266800>:
ffffffff8ac26800:	e9 2b b0 dd ff       	jmp    ffffffff8aa01830 <handler_632_entry-0x2246b0>
ffffffff8ac26805:	cc                   	int3
ffffffff8ac26806:	cc                   	int3
ffffffff8ac26807:	cc                   	int3

ffffffff8ac26808 <neighbor_trampoline_266808>:
ffffffff8ac26808:	e9 b3 b0 dd ff       	jmp    ffffffff8aa018c0 <handler_632_entry-0x224620>
ffffffff8ac2680d:	cc                   	int3
ffffffff8ac2680e:	cc                   	int3
ffffffff8ac2680f:	cc                   	int3

ffffffff8ac26810 <neighbor_trampoline_266810>:
ffffffff8ac26810:	e9 4b b8 dd ff       	jmp    ffffffff8aa02060 <handler_632_entry-0x223e80>
ffffffff8ac26815:	cc                   	int3
ffffffff8ac26816:	cc                   	int3
ffffffff8ac26817:	cc                   	int3

ffffffff8ac26818 <neighbor_trampoline_266818>:
ffffffff8ac26818:	e9 b3 bc dd ff       	jmp    ffffffff8aa024d0 <handler_632_entry-0x223a10>
ffffffff8ac2681d:	cc                   	int3
ffffffff8ac2681e:	cc                   	int3
ffffffff8ac2681f:	cc                   	int3

ffffffff8ac26820 <neighbor_trampoline_266820>:
ffffffff8ac26820:	e9 7b bd dd ff       	jmp    ffffffff8aa025a0 <handler_632_entry-0x223940>
ffffffff8ac26825:	cc                   	int3
ffffffff8ac26826:	cc                   	int3
ffffffff8ac26827:	cc                   	int3

ffffffff8ac26828 <neighbor_trampoline_266828>:
ffffffff8ac26828:	e9 d3 bd dd ff       	jmp    ffffffff8aa02600 <handler_632_entry-0x2238e0>
ffffffff8ac2682d:	cc                   	int3
ffffffff8ac2682e:	cc                   	int3
ffffffff8ac2682f:	cc                   	int3

ffffffff8ac26830 <neighbor_trampoline_266830>:
ffffffff8ac26830:	e9 fb 97 42 00       	jmp    ffffffff8b050030 <neighbor_trampoline_266ed8+0x429158>
ffffffff8ac26835:	cc                   	int3
ffffffff8ac26836:	cc                   	int3
ffffffff8ac26837:	cc                   	int3

ffffffff8ac26838 <neighbor_trampoline_266838>:
ffffffff8ac26838:	e9 83 04 43 00       	jmp    ffffffff8b056cc0 <neighbor_trampoline_266ed8+0x42fde8>
ffffffff8ac2683d:	cc                   	int3
ffffffff8ac2683e:	cc                   	int3
ffffffff8ac2683f:	cc                   	int3

ffffffff8ac26840 <neighbor_trampoline_266840>:
ffffffff8ac26840:	e9 8b 1d 43 00       	jmp    ffffffff8b0585d0 <neighbor_trampoline_266ed8+0x4316f8>
ffffffff8ac26845:	cc                   	int3
ffffffff8ac26846:	cc                   	int3
ffffffff8ac26847:	cc                   	int3

ffffffff8ac26848 <neighbor_trampoline_266848>:
ffffffff8ac26848:	e9 03 b8 43 00       	jmp    ffffffff8b062050 <neighbor_trampoline_266ed8+0x43b178>
ffffffff8ac2684d:	cc                   	int3
ffffffff8ac2684e:	cc                   	int3
ffffffff8ac2684f:	cc                   	int3

ffffffff8ac26850 <neighbor_trampoline_266850>:
ffffffff8ac26850:	e9 5b ba 43 00       	jmp    ffffffff8b0622b0 <neighbor_trampoline_266ed8+0x43b3d8>
ffffffff8ac26855:	cc                   	int3
ffffffff8ac26856:	cc                   	int3
ffffffff8ac26857:	cc                   	int3

ffffffff8ac26858 <neighbor_trampoline_266858>:
ffffffff8ac26858:	e9 e3 7d 44 00       	jmp    ffffffff8b06e640 <neighbor_trampoline_266ed8+0x447768>
ffffffff8ac2685d:	cc                   	int3
ffffffff8ac2685e:	cc                   	int3
ffffffff8ac2685f:	cc                   	int3

ffffffff8ac26860 <neighbor_trampoline_266860>:
ffffffff8ac26860:	e9 8b 7f 44 00       	jmp    ffffffff8b06e7f0 <neighbor_trampoline_266ed8+0x447918>
ffffffff8ac26865:	cc                   	int3
ffffffff8ac26866:	cc                   	int3
ffffffff8ac26867:	cc                   	int3

ffffffff8ac26868 <neighbor_trampoline_266868>:
ffffffff8ac26868:	e9 43 ab f1 ff       	jmp    ffffffff8ab413b0 <handler_632_entry-0xe4b30>
ffffffff8ac2686d:	cc                   	int3
ffffffff8ac2686e:	cc                   	int3
ffffffff8ac2686f:	cc                   	int3

ffffffff8ac26870 <neighbor_trampoline_266870>:
ffffffff8ac26870:	e9 2b 87 45 00       	jmp    ffffffff8b07efa0 <neighbor_trampoline_266ed8+0x4580c8>
ffffffff8ac26875:	cc                   	int3
ffffffff8ac26876:	cc                   	int3
ffffffff8ac26877:	cc                   	int3

ffffffff8ac26878 <neighbor_trampoline_266878>:
ffffffff8ac26878:	e9 c3 17 f2 ff       	jmp    ffffffff8ab48040 <handler_632_entry-0xddea0>
ffffffff8ac2687d:	cc                   	int3
ffffffff8ac2687e:	cc                   	int3
ffffffff8ac2687f:	cc                   	int3

ffffffff8ac26880 <neighbor_trampoline_266880>:
ffffffff8ac26880:	e9 7b a2 46 00       	jmp    ffffffff8b090b00 <neighbor_trampoline_266ed8+0x469c28>
ffffffff8ac26885:	cc                   	int3
ffffffff8ac26886:	cc                   	int3
ffffffff8ac26887:	cc                   	int3

ffffffff8ac26888 <neighbor_trampoline_266888>:
ffffffff8ac26888:	e9 73 a8 46 00       	jmp    ffffffff8b091100 <neighbor_trampoline_266ed8+0x46a228>
ffffffff8ac2688d:	cc                   	int3
ffffffff8ac2688e:	cc                   	int3
ffffffff8ac2688f:	cc                   	int3

ffffffff8ac26890 <neighbor_trampoline_266890>:
ffffffff8ac26890:	e9 cb a9 46 00       	jmp    ffffffff8b091260 <neighbor_trampoline_266ed8+0x46a388>
ffffffff8ac26895:	cc                   	int3
ffffffff8ac26896:	cc                   	int3
ffffffff8ac26897:	cc                   	int3

ffffffff8ac26898 <neighbor_trampoline_266898>:
ffffffff8ac26898:	e9 43 ab 46 00       	jmp    ffffffff8b0913e0 <neighbor_trampoline_266ed8+0x46a508>
ffffffff8ac2689d:	cc                   	int3
ffffffff8ac2689e:	cc                   	int3
ffffffff8ac2689f:	cc                   	int3

ffffffff8ac268a0 <neighbor_trampoline_2668a0>:
ffffffff8ac268a0:	e9 7b ac 46 00       	jmp    ffffffff8b091520 <neighbor_trampoline_266ed8+0x46a648>
ffffffff8ac268a5:	cc                   	int3
ffffffff8ac268a6:	cc                   	int3
ffffffff8ac268a7:	cc                   	int3

ffffffff8ac268a8 <neighbor_trampoline_2668a8>:
ffffffff8ac268a8:	e9 93 ad 46 00       	jmp    ffffffff8b091640 <neighbor_trampoline_266ed8+0x46a768>
ffffffff8ac268ad:	cc                   	int3
ffffffff8ac268ae:	cc                   	int3
ffffffff8ac268af:	cc                   	int3

ffffffff8ac268b0 <neighbor_trampoline_2668b0>:
ffffffff8ac268b0:	e9 6b ae 46 00       	jmp    ffffffff8b091720 <neighbor_trampoline_266ed8+0x46a848>
ffffffff8ac268b5:	cc                   	int3
ffffffff8ac268b6:	cc                   	int3
ffffffff8ac268b7:	cc                   	int3

ffffffff8ac268b8 <neighbor_trampoline_2668b8>:
ffffffff8ac268b8:	e9 a3 5d 47 00       	jmp    ffffffff8b09c660 <neighbor_trampoline_266ed8+0x475788>
ffffffff8ac268bd:	cc                   	int3
ffffffff8ac268be:	cc                   	int3
ffffffff8ac268bf:	cc                   	int3

ffffffff8ac268c0 <neighbor_trampoline_2668c0>:
ffffffff8ac268c0:	e9 cb 5d 47 00       	jmp    ffffffff8b09c690 <neighbor_trampoline_266ed8+0x4757b8>
ffffffff8ac268c5:	cc                   	int3
ffffffff8ac268c6:	cc                   	int3
ffffffff8ac268c7:	cc                   	int3

ffffffff8ac268c8 <neighbor_trampoline_2668c8>:
ffffffff8ac268c8:	e9 d3 5d 47 00       	jmp    ffffffff8b09c6a0 <neighbor_trampoline_266ed8+0x4757c8>
ffffffff8ac268cd:	cc                   	int3
ffffffff8ac268ce:	cc                   	int3
ffffffff8ac268cf:	cc                   	int3

ffffffff8ac268d0 <neighbor_trampoline_2668d0>:
ffffffff8ac268d0:	e9 4b a0 47 00       	jmp    ffffffff8b0a0920 <neighbor_trampoline_266ed8+0x479a48>
ffffffff8ac268d5:	cc                   	int3
ffffffff8ac268d6:	cc                   	int3
ffffffff8ac268d7:	cc                   	int3

ffffffff8ac268d8 <neighbor_trampoline_2668d8>:
ffffffff8ac268d8:	e9 63 ab 47 00       	jmp    ffffffff8b0a1440 <neighbor_trampoline_266ed8+0x47a568>
ffffffff8ac268dd:	cc                   	int3
ffffffff8ac268de:	cc                   	int3
ffffffff8ac268df:	cc                   	int3

ffffffff8ac268e0 <neighbor_trampoline_2668e0>:
ffffffff8ac268e0:	e9 6b ab 47 00       	jmp    ffffffff8b0a1450 <neighbor_trampoline_266ed8+0x47a578>
ffffffff8ac268e5:	cc                   	int3
ffffffff8ac268e6:	cc                   	int3
ffffffff8ac268e7:	cc                   	int3

ffffffff8ac268e8 <neighbor_trampoline_2668e8>:
ffffffff8ac268e8:	e9 83 31 f2 ff       	jmp    ffffffff8ab49a70 <handler_632_entry-0xdc470>
ffffffff8ac268ed:	cc                   	int3
ffffffff8ac268ee:	cc                   	int3
ffffffff8ac268ef:	cc                   	int3

ffffffff8ac268f0 <neighbor_trampoline_2668f0>:
ffffffff8ac268f0:	e9 ab a1 f2 ff       	jmp    ffffffff8ab50aa0 <handler_632_entry-0xd5440>
ffffffff8ac268f5:	cc                   	int3
ffffffff8ac268f6:	cc                   	int3
ffffffff8ac268f7:	cc                   	int3

ffffffff8ac268f8 <neighbor_trampoline_2668f8>:
ffffffff8ac268f8:	e9 73 c0 49 00       	jmp    ffffffff8b0c2970 <neighbor_trampoline_266ed8+0x49ba98>
ffffffff8ac268fd:	cc                   	int3
ffffffff8ac268fe:	cc                   	int3
ffffffff8ac268ff:	cc                   	int3

ffffffff8ac26900 <neighbor_trampoline_266900>:
ffffffff8ac26900:	e9 5b c4 49 00       	jmp    ffffffff8b0c2d60 <neighbor_trampoline_266ed8+0x49be88>
ffffffff8ac26905:	cc                   	int3
ffffffff8ac26906:	cc                   	int3
ffffffff8ac26907:	cc                   	int3

ffffffff8ac26908 <neighbor_trampoline_266908>:
ffffffff8ac26908:	e9 63 f8 49 00       	jmp    ffffffff8b0c6170 <neighbor_trampoline_266ed8+0x49f298>
ffffffff8ac2690d:	cc                   	int3
ffffffff8ac2690e:	cc                   	int3
ffffffff8ac2690f:	cc                   	int3

ffffffff8ac26910 <neighbor_trampoline_266910>:
ffffffff8ac26910:	e9 db f8 49 00       	jmp    ffffffff8b0c61f0 <neighbor_trampoline_266ed8+0x49f318>
ffffffff8ac26915:	cc                   	int3
ffffffff8ac26916:	cc                   	int3
ffffffff8ac26917:	cc                   	int3

ffffffff8ac26918 <neighbor_trampoline_266918>:
ffffffff8ac26918:	e9 e3 95 4a 00       	jmp    ffffffff8b0cff00 <neighbor_trampoline_266ed8+0x4a9028>
ffffffff8ac2691d:	cc                   	int3
ffffffff8ac2691e:	cc                   	int3
ffffffff8ac2691f:	cc                   	int3

ffffffff8ac26920 <neighbor_trampoline_266920>:
ffffffff8ac26920:	e9 8b 96 4a 00       	jmp    ffffffff8b0cffb0 <neighbor_trampoline_266ed8+0x4a90d8>
ffffffff8ac26925:	cc                   	int3
ffffffff8ac26926:	cc                   	int3
ffffffff8ac26927:	cc                   	int3

ffffffff8ac26928 <neighbor_trampoline_266928>:
ffffffff8ac26928:	e9 93 98 4a 00       	jmp    ffffffff8b0d01c0 <neighbor_trampoline_266ed8+0x4a92e8>
ffffffff8ac2692d:	cc                   	int3
ffffffff8ac2692e:	cc                   	int3
ffffffff8ac2692f:	cc                   	int3

ffffffff8ac26930 <neighbor_trampoline_266930>:
ffffffff8ac26930:	e9 eb 99 4a 00       	jmp    ffffffff8b0d0320 <neighbor_trampoline_266ed8+0x4a9448>
ffffffff8ac26935:	cc                   	int3
ffffffff8ac26936:	cc                   	int3
ffffffff8ac26937:	cc                   	int3

ffffffff8ac26938 <neighbor_trampoline_266938>:
ffffffff8ac26938:	e9 73 c2 4a 00       	jmp    ffffffff8b0d2bb0 <neighbor_trampoline_266ed8+0x4abcd8>
ffffffff8ac2693d:	cc                   	int3
ffffffff8ac2693e:	cc                   	int3
ffffffff8ac2693f:	cc                   	int3

ffffffff8ac26940 <neighbor_trampoline_266940>:
ffffffff8ac26940:	e9 1b fa 4a 00       	jmp    ffffffff8b0d6360 <neighbor_trampoline_266ed8+0x4af488>
ffffffff8ac26945:	cc                   	int3
ffffffff8ac26946:	cc                   	int3
ffffffff8ac26947:	cc                   	int3

ffffffff8ac26948 <neighbor_trampoline_266948>:
ffffffff8ac26948:	e9 23 90 4c 00       	jmp    ffffffff8b0ef970 <neighbor_trampoline_266ed8+0x4c8a98>
ffffffff8ac2694d:	cc                   	int3
ffffffff8ac2694e:	cc                   	int3
ffffffff8ac2694f:	cc                   	int3

ffffffff8ac26950 <neighbor_trampoline_266950>:
ffffffff8ac26950:	e9 3b 90 4c 00       	jmp    ffffffff8b0ef990 <neighbor_trampoline_266ed8+0x4c8ab8>
ffffffff8ac26955:	cc                   	int3
ffffffff8ac26956:	cc                   	int3
ffffffff8ac26957:	cc                   	int3

ffffffff8ac26958 <neighbor_trampoline_266958>:
ffffffff8ac26958:	e9 c3 90 4c 00       	jmp    ffffffff8b0efa20 <neighbor_trampoline_266ed8+0x4c8b48>
ffffffff8ac2695d:	cc                   	int3
ffffffff8ac2695e:	cc                   	int3
ffffffff8ac2695f:	cc                   	int3

ffffffff8ac26960 <neighbor_trampoline_266960>:
ffffffff8ac26960:	e9 cb 04 fe ff       	jmp    ffffffff8ac06e30 <handler_632_entry-0x1f0b0>
ffffffff8ac26965:	cc                   	int3
ffffffff8ac26966:	cc                   	int3
ffffffff8ac26967:	cc                   	int3

ffffffff8ac26968 <neighbor_trampoline_266968>:
ffffffff8ac26968:	e9 83 de 4f 00       	jmp    ffffffff8b1247f0 <neighbor_trampoline_266ed8+0x4fd918>
ffffffff8ac2696d:	cc                   	int3
ffffffff8ac2696e:	cc                   	int3
ffffffff8ac2696f:	cc                   	int3

ffffffff8ac26970 <neighbor_trampoline_266970>:
ffffffff8ac26970:	e9 9b cd 50 00       	jmp    ffffffff8b133710 <neighbor_trampoline_266ed8+0x50c838>
ffffffff8ac26975:	cc                   	int3
ffffffff8ac26976:	cc                   	int3
ffffffff8ac26977:	cc                   	int3

ffffffff8ac26978 <neighbor_trampoline_266978>:
ffffffff8ac26978:	e9 d3 ef 50 00       	jmp    ffffffff8b135950 <neighbor_trampoline_266ed8+0x50ea78>
ffffffff8ac2697d:	cc                   	int3
ffffffff8ac2697e:	cc                   	int3
ffffffff8ac2697f:	cc                   	int3

ffffffff8ac26980 <neighbor_trampoline_266980>:
ffffffff8ac26980:	e9 0b 35 53 00       	jmp    ffffffff8b159e90 <neighbor_trampoline_266ed8+0x532fb8>
ffffffff8ac26985:	cc                   	int3
ffffffff8ac26986:	cc                   	int3
ffffffff8ac26987:	cc                   	int3

ffffffff8ac26988 <neighbor_trampoline_266988>:
ffffffff8ac26988:	e9 63 c8 54 00       	jmp    ffffffff8b1731f0 <neighbor_trampoline_266ed8+0x54c318>
ffffffff8ac2698d:	cc                   	int3
ffffffff8ac2698e:	cc                   	int3
ffffffff8ac2698f:	cc                   	int3

ffffffff8ac26990 <neighbor_trampoline_266990>:
ffffffff8ac26990:	e9 0b ba 57 00       	jmp    ffffffff8b1a23a0 <neighbor_trampoline_266ed8+0x57b4c8>
ffffffff8ac26995:	cc                   	int3
ffffffff8ac26996:	cc                   	int3
ffffffff8ac26997:	cc                   	int3

ffffffff8ac26998 <neighbor_trampoline_266998>:
ffffffff8ac26998:	e9 43 1a 58 00       	jmp    ffffffff8b1a83e0 <neighbor_trampoline_266ed8+0x581508>
ffffffff8ac2699d:	cc                   	int3
ffffffff8ac2699e:	cc                   	int3
ffffffff8ac2699f:	cc                   	int3

ffffffff8ac269a0 <neighbor_trampoline_2669a0>:
ffffffff8ac269a0:	e9 db 1a 58 00       	jmp    ffffffff8b1a8480 <neighbor_trampoline_266ed8+0x5815a8>
ffffffff8ac269a5:	cc                   	int3
ffffffff8ac269a6:	cc                   	int3
ffffffff8ac269a7:	cc                   	int3

ffffffff8ac269a8 <neighbor_trampoline_2669a8>:
ffffffff8ac269a8:	e9 03 48 9d 00       	jmp    ffffffff8b5fb1b0 <neighbor_trampoline_266ed8+0x9d42d8>
ffffffff8ac269ad:	cc                   	int3
ffffffff8ac269ae:	cc                   	int3
ffffffff8ac269af:	cc                   	int3

ffffffff8ac269b0 <neighbor_trampoline_2669b0>:
ffffffff8ac269b0:	e9 2b 5d 9d 00       	jmp    ffffffff8b5fc6e0 <neighbor_trampoline_266ed8+0x9d5808>
ffffffff8ac269b5:	cc                   	int3
ffffffff8ac269b6:	cc                   	int3
ffffffff8ac269b7:	cc                   	int3

ffffffff8ac269b8 <neighbor_trampoline_2669b8>:
ffffffff8ac269b8:	e9 d3 5c 9d 00       	jmp    ffffffff8b5fc690 <neighbor_trampoline_266ed8+0x9d57b8>
ffffffff8ac269bd:	cc                   	int3
ffffffff8ac269be:	cc                   	int3
ffffffff8ac269bf:	cc                   	int3

ffffffff8ac269c0 <neighbor_trampoline_2669c0>:
ffffffff8ac269c0:	e9 6b 5d 9d 00       	jmp    ffffffff8b5fc730 <neighbor_trampoline_266ed8+0x9d5858>
ffffffff8ac269c5:	cc                   	int3
ffffffff8ac269c6:	cc                   	int3
ffffffff8ac269c7:	cc                   	int3

ffffffff8ac269c8 <neighbor_trampoline_2669c8>:
ffffffff8ac269c8:	e9 53 b8 59 00       	jmp    ffffffff8b1c2220 <neighbor_trampoline_266ed8+0x59b348>
ffffffff8ac269cd:	cc                   	int3
ffffffff8ac269ce:	cc                   	int3
ffffffff8ac269cf:	cc                   	int3

ffffffff8ac269d0 <neighbor_trampoline_2669d0>:
ffffffff8ac269d0:	e9 1b bb 59 00       	jmp    ffffffff8b1c24f0 <neighbor_trampoline_266ed8+0x59b618>
ffffffff8ac269d5:	cc                   	int3
ffffffff8ac269d6:	cc                   	int3
ffffffff8ac269d7:	cc                   	int3

ffffffff8ac269d8 <neighbor_trampoline_2669d8>:
ffffffff8ac269d8:	e9 93 5b 5a 00       	jmp    ffffffff8b1cc570 <neighbor_trampoline_266ed8+0x5a5698>
ffffffff8ac269dd:	cc                   	int3
ffffffff8ac269de:	cc                   	int3
ffffffff8ac269df:	cc                   	int3

ffffffff8ac269e0 <neighbor_trampoline_2669e0>:
ffffffff8ac269e0:	e9 1b 49 5c 00       	jmp    ffffffff8b1eb300 <neighbor_trampoline_266ed8+0x5c4428>
ffffffff8ac269e5:	cc                   	int3
ffffffff8ac269e6:	cc                   	int3
ffffffff8ac269e7:	cc                   	int3

ffffffff8ac269e8 <neighbor_trampoline_2669e8>:
ffffffff8ac269e8:	e9 f3 a4 6b 00       	jmp    ffffffff8b2e0ee0 <neighbor_trampoline_266ed8+0x6ba008>
ffffffff8ac269ed:	cc                   	int3
ffffffff8ac269ee:	cc                   	int3
ffffffff8ac269ef:	cc                   	int3

ffffffff8ac269f0 <neighbor_trampoline_2669f0>:
ffffffff8ac269f0:	e9 9b a1 6b 00       	jmp    ffffffff8b2e0b90 <neighbor_trampoline_266ed8+0x6b9cb8>
ffffffff8ac269f5:	cc                   	int3
ffffffff8ac269f6:	cc                   	int3
ffffffff8ac269f7:	cc                   	int3

ffffffff8ac269f8 <neighbor_trampoline_2669f8>:
ffffffff8ac269f8:	e9 13 9e 5c 00       	jmp    ffffffff8b1f0810 <neighbor_trampoline_266ed8+0x5c9938>
ffffffff8ac269fd:	cc                   	int3
ffffffff8ac269fe:	cc                   	int3
ffffffff8ac269ff:	cc                   	int3

ffffffff8ac26a00 <neighbor_trampoline_266a00>:
ffffffff8ac26a00:	e9 fb a4 5c 00       	jmp    ffffffff8b1f0f00 <neighbor_trampoline_266ed8+0x5ca028>
ffffffff8ac26a05:	cc                   	int3
ffffffff8ac26a06:	cc                   	int3
ffffffff8ac26a07:	cc                   	int3

ffffffff8ac26a08 <neighbor_trampoline_266a08>:
ffffffff8ac26a08:	e9 a3 e8 5c 00       	jmp    ffffffff8b1f52b0 <neighbor_trampoline_266ed8+0x5ce3d8>
ffffffff8ac26a0d:	cc                   	int3
ffffffff8ac26a0e:	cc                   	int3
ffffffff8ac26a0f:	cc                   	int3

ffffffff8ac26a10 <neighbor_trampoline_266a10>:
ffffffff8ac26a10:	e9 ab e8 5c 00       	jmp    ffffffff8b1f52c0 <neighbor_trampoline_266ed8+0x5ce3e8>
ffffffff8ac26a15:	cc                   	int3
ffffffff8ac26a16:	cc                   	int3
ffffffff8ac26a17:	cc                   	int3

ffffffff8ac26a18 <neighbor_trampoline_266a18>:
ffffffff8ac26a18:	e9 b3 e8 5c 00       	jmp    ffffffff8b1f52d0 <neighbor_trampoline_266ed8+0x5ce3f8>
ffffffff8ac26a1d:	cc                   	int3
ffffffff8ac26a1e:	cc                   	int3
ffffffff8ac26a1f:	cc                   	int3

ffffffff8ac26a20 <neighbor_trampoline_266a20>:
ffffffff8ac26a20:	e9 cb e8 5c 00       	jmp    ffffffff8b1f52f0 <neighbor_trampoline_266ed8+0x5ce418>
ffffffff8ac26a25:	cc                   	int3
ffffffff8ac26a26:	cc                   	int3
ffffffff8ac26a27:	cc                   	int3

ffffffff8ac26a28 <neighbor_trampoline_266a28>:
ffffffff8ac26a28:	e9 13 ea 5c 00       	jmp    ffffffff8b1f5440 <neighbor_trampoline_266ed8+0x5ce568>
ffffffff8ac26a2d:	cc                   	int3
ffffffff8ac26a2e:	cc                   	int3
ffffffff8ac26a2f:	cc                   	int3

ffffffff8ac26a30 <neighbor_trampoline_266a30>:
ffffffff8ac26a30:	e9 1b ea 5c 00       	jmp    ffffffff8b1f5450 <neighbor_trampoline_266ed8+0x5ce578>
ffffffff8ac26a35:	cc                   	int3
ffffffff8ac26a36:	cc                   	int3
ffffffff8ac26a37:	cc                   	int3

ffffffff8ac26a38 <neighbor_trampoline_266a38>:
ffffffff8ac26a38:	e9 53 ea 5c 00       	jmp    ffffffff8b1f5490 <neighbor_trampoline_266ed8+0x5ce5b8>
ffffffff8ac26a3d:	cc                   	int3
ffffffff8ac26a3e:	cc                   	int3
ffffffff8ac26a3f:	cc                   	int3

ffffffff8ac26a40 <neighbor_trampoline_266a40>:
ffffffff8ac26a40:	e9 8b f0 5c 00       	jmp    ffffffff8b1f5ad0 <neighbor_trampoline_266ed8+0x5cebf8>
ffffffff8ac26a45:	cc                   	int3
ffffffff8ac26a46:	cc                   	int3
ffffffff8ac26a47:	cc                   	int3

ffffffff8ac26a48 <neighbor_trampoline_266a48>:
ffffffff8ac26a48:	e9 23 9e 5e 00       	jmp    ffffffff8b210870 <neighbor_trampoline_266ed8+0x5e9998>
ffffffff8ac26a4d:	cc                   	int3
ffffffff8ac26a4e:	cc                   	int3
ffffffff8ac26a4f:	cc                   	int3

ffffffff8ac26a50 <neighbor_trampoline_266a50>:
ffffffff8ac26a50:	e9 9b 98 60 00       	jmp    ffffffff8b2302f0 <neighbor_trampoline_266ed8+0x609418>
ffffffff8ac26a55:	cc                   	int3
ffffffff8ac26a56:	cc                   	int3
ffffffff8ac26a57:	cc                   	int3

ffffffff8ac26a58 <neighbor_trampoline_266a58>:
ffffffff8ac26a58:	e9 73 9b 60 00       	jmp    ffffffff8b2305d0 <neighbor_trampoline_266ed8+0x6096f8>
ffffffff8ac26a5d:	cc                   	int3
ffffffff8ac26a5e:	cc                   	int3
ffffffff8ac26a5f:	cc                   	int3

ffffffff8ac26a60 <neighbor_trampoline_266a60>:
ffffffff8ac26a60:	e9 8b c0 60 00       	jmp    ffffffff8b232af0 <neighbor_trampoline_266ed8+0x60bc18>
ffffffff8ac26a65:	cc                   	int3
ffffffff8ac26a66:	cc                   	int3
ffffffff8ac26a67:	cc                   	int3

ffffffff8ac26a68 <neighbor_trampoline_266a68>:
ffffffff8ac26a68:	e9 93 cd 60 00       	jmp    ffffffff8b233800 <neighbor_trampoline_266ed8+0x60c928>
ffffffff8ac26a6d:	cc                   	int3
ffffffff8ac26a6e:	cc                   	int3
ffffffff8ac26a6f:	cc                   	int3

ffffffff8ac26a70 <neighbor_trampoline_266a70>:
ffffffff8ac26a70:	e9 cb cf df ff       	jmp    ffffffff8aa23a40 <handler_632_entry-0x2024a0>
ffffffff8ac26a75:	cc                   	int3
ffffffff8ac26a76:	cc                   	int3
ffffffff8ac26a77:	cc                   	int3

ffffffff8ac26a78 <neighbor_trampoline_266a78>:
ffffffff8ac26a78:	e9 f3 f8 df ff       	jmp    ffffffff8aa26370 <handler_632_entry-0x1ffb70>
ffffffff8ac26a7d:	cc                   	int3
ffffffff8ac26a7e:	cc                   	int3
ffffffff8ac26a7f:	cc                   	int3

ffffffff8ac26a80 <neighbor_trampoline_266a80>:
ffffffff8ac26a80:	e9 0b fb e7 ff       	jmp    ffffffff8aaa6590 <handler_632_entry-0x17f950>
ffffffff8ac26a85:	cc                   	int3
ffffffff8ac26a86:	cc                   	int3
ffffffff8ac26a87:	cc                   	int3

ffffffff8ac26a88 <neighbor_trampoline_266a88>:
ffffffff8ac26a88:	e9 13 fb e7 ff       	jmp    ffffffff8aaa65a0 <handler_632_entry-0x17f940>
ffffffff8ac26a8d:	cc                   	int3
ffffffff8ac26a8e:	cc                   	int3
ffffffff8ac26a8f:	cc                   	int3

ffffffff8ac26a90 <neighbor_trampoline_266a90>:
ffffffff8ac26a90:	e9 cb fc e7 ff       	jmp    ffffffff8aaa6760 <handler_632_entry-0x17f780>
ffffffff8ac26a95:	cc                   	int3
ffffffff8ac26a96:	cc                   	int3
ffffffff8ac26a97:	cc                   	int3

ffffffff8ac26a98 <neighbor_trampoline_266a98>:
ffffffff8ac26a98:	e9 d3 fd e7 ff       	jmp    ffffffff8aaa6870 <handler_632_entry-0x17f670>
ffffffff8ac26a9d:	cc                   	int3
ffffffff8ac26a9e:	cc                   	int3
ffffffff8ac26a9f:	cc                   	int3

ffffffff8ac26aa0 <neighbor_trampoline_266aa0>:
ffffffff8ac26aa0:	e9 eb 14 e8 ff       	jmp    ffffffff8aaa7f90 <handler_632_entry-0x17df50>
ffffffff8ac26aa5:	cc                   	int3
ffffffff8ac26aa6:	cc                   	int3
ffffffff8ac26aa7:	cc                   	int3

ffffffff8ac26aa8 <neighbor_trampoline_266aa8>:
ffffffff8ac26aa8:	e9 f3 34 e8 ff       	jmp    ffffffff8aaa9fa0 <handler_632_entry-0x17bf40>
ffffffff8ac26aad:	cc                   	int3
ffffffff8ac26aae:	cc                   	int3
ffffffff8ac26aaf:	cc                   	int3

ffffffff8ac26ab0 <neighbor_trampoline_266ab0>:
ffffffff8ac26ab0:	e9 bb 3b e8 ff       	jmp    ffffffff8aaaa670 <handler_632_entry-0x17b870>
ffffffff8ac26ab5:	cc                   	int3
ffffffff8ac26ab6:	cc                   	int3
ffffffff8ac26ab7:	cc                   	int3

ffffffff8ac26ab8 <neighbor_trampoline_266ab8>:
ffffffff8ac26ab8:	e9 a3 3c e8 ff       	jmp    ffffffff8aaaa760 <handler_632_entry-0x17b780>
ffffffff8ac26abd:	cc                   	int3
ffffffff8ac26abe:	cc                   	int3
ffffffff8ac26abf:	cc                   	int3

ffffffff8ac26ac0 <neighbor_trampoline_266ac0>:
ffffffff8ac26ac0:	e9 db 45 e8 ff       	jmp    ffffffff8aaab0a0 <handler_632_entry-0x17ae40>
ffffffff8ac26ac5:	cc                   	int3
ffffffff8ac26ac6:	cc                   	int3
ffffffff8ac26ac7:	cc                   	int3

ffffffff8ac26ac8 <neighbor_trampoline_266ac8>:
ffffffff8ac26ac8:	e9 c3 46 e8 ff       	jmp    ffffffff8aaab190 <handler_632_entry-0x17ad50>
ffffffff8ac26acd:	cc                   	int3
ffffffff8ac26ace:	cc                   	int3
ffffffff8ac26acf:	cc                   	int3

ffffffff8ac26ad0 <neighbor_trampoline_266ad0>:
ffffffff8ac26ad0:	e9 2b 65 e8 ff       	jmp    ffffffff8aaad000 <handler_632_entry-0x178ee0>
ffffffff8ac26ad5:	cc                   	int3
ffffffff8ac26ad6:	cc                   	int3
ffffffff8ac26ad7:	cc                   	int3

ffffffff8ac26ad8 <neighbor_trampoline_266ad8>:
ffffffff8ac26ad8:	e9 33 66 e8 ff       	jmp    ffffffff8aaad110 <handler_632_entry-0x178dd0>
ffffffff8ac26add:	cc                   	int3
ffffffff8ac26ade:	cc                   	int3
ffffffff8ac26adf:	cc                   	int3

ffffffff8ac26ae0 <neighbor_trampoline_266ae0>:
ffffffff8ac26ae0:	e9 bb 3d 62 00       	jmp    ffffffff8b24a8a0 <neighbor_trampoline_266ed8+0x6239c8>
ffffffff8ac26ae5:	cc                   	int3
ffffffff8ac26ae6:	cc                   	int3
ffffffff8ac26ae7:	cc                   	int3

ffffffff8ac26ae8 <neighbor_trampoline_266ae8>:
ffffffff8ac26ae8:	e9 03 63 63 00       	jmp    ffffffff8b25cdf0 <neighbor_trampoline_266ed8+0x635f18>
ffffffff8ac26aed:	cc                   	int3
ffffffff8ac26aee:	cc                   	int3
ffffffff8ac26aef:	cc                   	int3

ffffffff8ac26af0 <neighbor_trampoline_266af0>:
ffffffff8ac26af0:	e9 5b 80 e8 ff       	jmp    ffffffff8aaaeb50 <handler_632_entry-0x177390>
ffffffff8ac26af5:	cc                   	int3
ffffffff8ac26af6:	cc                   	int3
ffffffff8ac26af7:	cc                   	int3

ffffffff8ac26af8 <neighbor_trampoline_266af8>:
ffffffff8ac26af8:	e9 53 47 66 00       	jmp    ffffffff8b28b250 <neighbor_trampoline_266ed8+0x664378>
ffffffff8ac26afd:	cc                   	int3
ffffffff8ac26afe:	cc                   	int3
ffffffff8ac26aff:	cc                   	int3

ffffffff8ac26b00 <neighbor_trampoline_266b00>:
ffffffff8ac26b00:	e9 8b 48 66 00       	jmp    ffffffff8b28b390 <neighbor_trampoline_266ed8+0x6644b8>
ffffffff8ac26b05:	cc                   	int3
ffffffff8ac26b06:	cc                   	int3
ffffffff8ac26b07:	cc                   	int3

ffffffff8ac26b08 <neighbor_trampoline_266b08>:
ffffffff8ac26b08:	e9 53 c4 66 00       	jmp    ffffffff8b292f60 <neighbor_trampoline_266ed8+0x66c088>
ffffffff8ac26b0d:	cc                   	int3
ffffffff8ac26b0e:	cc                   	int3
ffffffff8ac26b0f:	cc                   	int3

ffffffff8ac26b10 <neighbor_trampoline_266b10>:
ffffffff8ac26b10:	e9 7b c4 66 00       	jmp    ffffffff8b292f90 <neighbor_trampoline_266ed8+0x66c0b8>
ffffffff8ac26b15:	cc                   	int3
ffffffff8ac26b16:	cc                   	int3
ffffffff8ac26b17:	cc                   	int3

ffffffff8ac26b18 <neighbor_trampoline_266b18>:
ffffffff8ac26b18:	e9 13 17 67 00       	jmp    ffffffff8b298230 <neighbor_trampoline_266ed8+0x671358>
ffffffff8ac26b1d:	cc                   	int3
ffffffff8ac26b1e:	cc                   	int3
ffffffff8ac26b1f:	cc                   	int3

ffffffff8ac26b20 <neighbor_trampoline_266b20>:
ffffffff8ac26b20:	e9 bb 22 67 00       	jmp    ffffffff8b298de0 <neighbor_trampoline_266ed8+0x671f08>
ffffffff8ac26b25:	cc                   	int3
ffffffff8ac26b26:	cc                   	int3
ffffffff8ac26b27:	cc                   	int3

ffffffff8ac26b28 <neighbor_trampoline_266b28>:
ffffffff8ac26b28:	e9 83 2c 67 00       	jmp    ffffffff8b2997b0 <neighbor_trampoline_266ed8+0x6728d8>
ffffffff8ac26b2d:	cc                   	int3
ffffffff8ac26b2e:	cc                   	int3
ffffffff8ac26b2f:	cc                   	int3

ffffffff8ac26b30 <neighbor_trampoline_266b30>:
ffffffff8ac26b30:	e9 db 2d 67 00       	jmp    ffffffff8b299910 <neighbor_trampoline_266ed8+0x672a38>
ffffffff8ac26b35:	cc                   	int3
ffffffff8ac26b36:	cc                   	int3
ffffffff8ac26b37:	cc                   	int3

ffffffff8ac26b38 <neighbor_trampoline_266b38>:
ffffffff8ac26b38:	e9 83 39 67 00       	jmp    ffffffff8b29a4c0 <neighbor_trampoline_266ed8+0x6735e8>
ffffffff8ac26b3d:	cc                   	int3
ffffffff8ac26b3e:	cc                   	int3
ffffffff8ac26b3f:	cc                   	int3

ffffffff8ac26b40 <neighbor_trampoline_266b40>:
ffffffff8ac26b40:	e9 2b 3a 67 00       	jmp    ffffffff8b29a570 <neighbor_trampoline_266ed8+0x673698>
ffffffff8ac26b45:	cc                   	int3
ffffffff8ac26b46:	cc                   	int3
ffffffff8ac26b47:	cc                   	int3

ffffffff8ac26b48 <neighbor_trampoline_266b48>:
ffffffff8ac26b48:	e9 63 3a 67 00       	jmp    ffffffff8b29a5b0 <neighbor_trampoline_266ed8+0x6736d8>
ffffffff8ac26b4d:	cc                   	int3
ffffffff8ac26b4e:	cc                   	int3
ffffffff8ac26b4f:	cc                   	int3

ffffffff8ac26b50 <neighbor_trampoline_266b50>:
ffffffff8ac26b50:	e9 2b e1 69 00       	jmp    ffffffff8b2c4c80 <neighbor_trampoline_266ed8+0x69dda8>
ffffffff8ac26b55:	cc                   	int3
ffffffff8ac26b56:	cc                   	int3
ffffffff8ac26b57:	cc                   	int3

ffffffff8ac26b58 <neighbor_trampoline_266b58>:
ffffffff8ac26b58:	e9 03 e3 69 00       	jmp    ffffffff8b2c4e60 <neighbor_trampoline_266ed8+0x69df88>
ffffffff8ac26b5d:	cc                   	int3
ffffffff8ac26b5e:	cc                   	int3
ffffffff8ac26b5f:	cc                   	int3

ffffffff8ac26b60 <neighbor_trampoline_266b60>:
ffffffff8ac26b60:	e9 9b 68 6b 00       	jmp    ffffffff8b2dd400 <neighbor_trampoline_266ed8+0x6b6528>
ffffffff8ac26b65:	cc                   	int3
ffffffff8ac26b66:	cc                   	int3
ffffffff8ac26b67:	cc                   	int3

ffffffff8ac26b68 <neighbor_trampoline_266b68>:
ffffffff8ac26b68:	e9 33 69 6b 00       	jmp    ffffffff8b2dd4a0 <neighbor_trampoline_266ed8+0x6b65c8>
ffffffff8ac26b6d:	cc                   	int3
ffffffff8ac26b6e:	cc                   	int3
ffffffff8ac26b6f:	cc                   	int3

ffffffff8ac26b70 <neighbor_trampoline_266b70>:
ffffffff8ac26b70:	e9 5b b6 81 00       	jmp    ffffffff8b4421d0 <neighbor_trampoline_266ed8+0x81b2f8>
ffffffff8ac26b75:	cc                   	int3
ffffffff8ac26b76:	cc                   	int3
ffffffff8ac26b77:	cc                   	int3

ffffffff8ac26b78 <neighbor_trampoline_266b78>:
ffffffff8ac26b78:	e9 a3 b5 8d 00       	jmp    ffffffff8b502120 <neighbor_trampoline_266ed8+0x8db248>
ffffffff8ac26b7d:	cc                   	int3
ffffffff8ac26b7e:	cc                   	int3
ffffffff8ac26b7f:	cc                   	int3

ffffffff8ac26b80 <neighbor_trampoline_266b80>:
ffffffff8ac26b80:	e9 ab e3 6f 00       	jmp    ffffffff8b324f30 <neighbor_trampoline_266ed8+0x6fe058>
ffffffff8ac26b85:	cc                   	int3
ffffffff8ac26b86:	cc                   	int3
ffffffff8ac26b87:	cc                   	int3

ffffffff8ac26b88 <neighbor_trampoline_266b88>:
ffffffff8ac26b88:	e9 c3 f3 70 00       	jmp    ffffffff8b335f50 <neighbor_trampoline_266ed8+0x70f078>
ffffffff8ac26b8d:	cc                   	int3
ffffffff8ac26b8e:	cc                   	int3
ffffffff8ac26b8f:	cc                   	int3

ffffffff8ac26b90 <neighbor_trampoline_266b90>:
ffffffff8ac26b90:	e9 6b f6 70 00       	jmp    ffffffff8b336200 <neighbor_trampoline_266ed8+0x70f328>
ffffffff8ac26b95:	cc                   	int3
ffffffff8ac26b96:	cc                   	int3
ffffffff8ac26b97:	cc                   	int3

ffffffff8ac26b98 <neighbor_trampoline_266b98>:
ffffffff8ac26b98:	e9 b3 5d 72 00       	jmp    ffffffff8b34c950 <neighbor_trampoline_266ed8+0x725a78>
ffffffff8ac26b9d:	cc                   	int3
ffffffff8ac26b9e:	cc                   	int3
ffffffff8ac26b9f:	cc                   	int3

ffffffff8ac26ba0 <neighbor_trampoline_266ba0>:
ffffffff8ac26ba0:	e9 8b 60 72 00       	jmp    ffffffff8b34cc30 <neighbor_trampoline_266ed8+0x725d58>
ffffffff8ac26ba5:	cc                   	int3
ffffffff8ac26ba6:	cc                   	int3
ffffffff8ac26ba7:	cc                   	int3

ffffffff8ac26ba8 <neighbor_trampoline_266ba8>:
ffffffff8ac26ba8:	e9 83 63 72 00       	jmp    ffffffff8b34cf30 <neighbor_trampoline_266ed8+0x726058>
ffffffff8ac26bad:	cc                   	int3
ffffffff8ac26bae:	cc                   	int3
ffffffff8ac26baf:	cc                   	int3

ffffffff8ac26bb0 <neighbor_trampoline_266bb0>:
ffffffff8ac26bb0:	e9 2b 6b 72 00       	jmp    ffffffff8b34d6e0 <neighbor_trampoline_266ed8+0x726808>
ffffffff8ac26bb5:	cc                   	int3
ffffffff8ac26bb6:	cc                   	int3
ffffffff8ac26bb7:	cc                   	int3

ffffffff8ac26bb8 <neighbor_trampoline_266bb8>:
ffffffff8ac26bb8:	e9 13 7a 72 00       	jmp    ffffffff8b34e5d0 <neighbor_trampoline_266ed8+0x7276f8>
ffffffff8ac26bbd:	cc                   	int3
ffffffff8ac26bbe:	cc                   	int3
ffffffff8ac26bbf:	cc                   	int3

ffffffff8ac26bc0 <neighbor_trampoline_266bc0>:
ffffffff8ac26bc0:	e9 3b 7b 72 00       	jmp    ffffffff8b34e700 <neighbor_trampoline_266ed8+0x727828>
ffffffff8ac26bc5:	cc                   	int3
ffffffff8ac26bc6:	cc                   	int3
ffffffff8ac26bc7:	cc                   	int3

ffffffff8ac26bc8 <neighbor_trampoline_266bc8>:
ffffffff8ac26bc8:	e9 a3 b5 72 00       	jmp    ffffffff8b352170 <neighbor_trampoline_266ed8+0x72b298>
ffffffff8ac26bcd:	cc                   	int3
ffffffff8ac26bce:	cc                   	int3
ffffffff8ac26bcf:	cc                   	int3

ffffffff8ac26bd0 <neighbor_trampoline_266bd0>:
ffffffff8ac26bd0:	e9 6b b6 72 00       	jmp    ffffffff8b352240 <neighbor_trampoline_266ed8+0x72b368>
ffffffff8ac26bd5:	cc                   	int3
ffffffff8ac26bd6:	cc                   	int3
ffffffff8ac26bd7:	cc                   	int3

ffffffff8ac26bd8 <neighbor_trampoline_266bd8>:
ffffffff8ac26bd8:	e9 23 e8 e8 ff       	jmp    ffffffff8aab5400 <handler_632_entry-0x170ae0>
ffffffff8ac26bdd:	cc                   	int3
ffffffff8ac26bde:	cc                   	int3
ffffffff8ac26bdf:	cc                   	int3

ffffffff8ac26be0 <neighbor_trampoline_266be0>:
ffffffff8ac26be0:	e9 3b b7 73 00       	jmp    ffffffff8b362320 <neighbor_trampoline_266ed8+0x73b448>
ffffffff8ac26be5:	cc                   	int3
ffffffff8ac26be6:	cc                   	int3
ffffffff8ac26be7:	cc                   	int3

ffffffff8ac26be8 <neighbor_trampoline_266be8>:
ffffffff8ac26be8:	e9 33 eb 73 00       	jmp    ffffffff8b365720 <neighbor_trampoline_266ed8+0x73e848>
ffffffff8ac26bed:	cc                   	int3
ffffffff8ac26bee:	cc                   	int3
ffffffff8ac26bef:	cc                   	int3

ffffffff8ac26bf0 <neighbor_trampoline_266bf0>:
ffffffff8ac26bf0:	e9 ab 5d 74 00       	jmp    ffffffff8b36c9a0 <neighbor_trampoline_266ed8+0x745ac8>
ffffffff8ac26bf5:	cc                   	int3
ffffffff8ac26bf6:	cc                   	int3
ffffffff8ac26bf7:	cc                   	int3

ffffffff8ac26bf8 <neighbor_trampoline_266bf8>:
ffffffff8ac26bf8:	e9 23 5e 74 00       	jmp    ffffffff8b36ca20 <neighbor_trampoline_266ed8+0x745b48>
ffffffff8ac26bfd:	cc                   	int3
ffffffff8ac26bfe:	cc                   	int3
ffffffff8ac26bff:	cc                   	int3

ffffffff8ac26c00 <neighbor_trampoline_266c00>:
ffffffff8ac26c00:	e9 3b 7a f5 ff       	jmp    ffffffff8ab7e640 <handler_632_entry-0xa78a0>
ffffffff8ac26c05:	cc                   	int3
ffffffff8ac26c06:	cc                   	int3
ffffffff8ac26c07:	cc                   	int3

ffffffff8ac26c08 <neighbor_trampoline_266c08>:
ffffffff8ac26c08:	e9 13 81 75 00       	jmp    ffffffff8b37ed20 <neighbor_trampoline_266ed8+0x757e48>
ffffffff8ac26c0d:	cc                   	int3
ffffffff8ac26c0e:	cc                   	int3
ffffffff8ac26c0f:	cc                   	int3

ffffffff8ac26c10 <neighbor_trampoline_266c10>:
ffffffff8ac26c10:	e9 3b f4 75 00       	jmp    ffffffff8b386050 <neighbor_trampoline_266ed8+0x75f178>
ffffffff8ac26c15:	cc                   	int3
ffffffff8ac26c16:	cc                   	int3
ffffffff8ac26c17:	cc                   	int3

ffffffff8ac26c18 <neighbor_trampoline_266c18>:
ffffffff8ac26c18:	e9 b3 f4 75 00       	jmp    ffffffff8b3860d0 <neighbor_trampoline_266ed8+0x75f1f8>
ffffffff8ac26c1d:	cc                   	int3
ffffffff8ac26c1e:	cc                   	int3
ffffffff8ac26c1f:	cc                   	int3

ffffffff8ac26c20 <neighbor_trampoline_266c20>:
ffffffff8ac26c20:	e9 5b f6 75 00       	jmp    ffffffff8b386280 <neighbor_trampoline_266ed8+0x75f3a8>
ffffffff8ac26c25:	cc                   	int3
ffffffff8ac26c26:	cc                   	int3
ffffffff8ac26c27:	cc                   	int3

ffffffff8ac26c28 <neighbor_trampoline_266c28>:
ffffffff8ac26c28:	e9 e3 f6 75 00       	jmp    ffffffff8b386310 <neighbor_trampoline_266ed8+0x75f438>
ffffffff8ac26c2d:	cc                   	int3
ffffffff8ac26c2e:	cc                   	int3
ffffffff8ac26c2f:	cc                   	int3

ffffffff8ac26c30 <neighbor_trampoline_266c30>:
ffffffff8ac26c30:	e9 5b f8 75 00       	jmp    ffffffff8b386490 <neighbor_trampoline_266ed8+0x75f5b8>
ffffffff8ac26c35:	cc                   	int3
ffffffff8ac26c36:	cc                   	int3
ffffffff8ac26c37:	cc                   	int3

ffffffff8ac26c38 <neighbor_trampoline_266c38>:
ffffffff8ac26c38:	e9 73 f9 75 00       	jmp    ffffffff8b3865b0 <neighbor_trampoline_266ed8+0x75f6d8>
ffffffff8ac26c3d:	cc                   	int3
ffffffff8ac26c3e:	cc                   	int3
ffffffff8ac26c3f:	cc                   	int3

ffffffff8ac26c40 <neighbor_trampoline_266c40>:
ffffffff8ac26c40:	e9 4b fc 75 00       	jmp    ffffffff8b386890 <neighbor_trampoline_266ed8+0x75f9b8>
ffffffff8ac26c45:	cc                   	int3
ffffffff8ac26c46:	cc                   	int3
ffffffff8ac26c47:	cc                   	int3

ffffffff8ac26c48 <neighbor_trampoline_266c48>:
ffffffff8ac26c48:	e9 f3 26 76 00       	jmp    ffffffff8b389340 <neighbor_trampoline_266ed8+0x762468>
ffffffff8ac26c4d:	cc                   	int3
ffffffff8ac26c4e:	cc                   	int3
ffffffff8ac26c4f:	cc                   	int3

ffffffff8ac26c50 <neighbor_trampoline_266c50>:
ffffffff8ac26c50:	e9 0b 27 76 00       	jmp    ffffffff8b389360 <neighbor_trampoline_266ed8+0x762488>
ffffffff8ac26c55:	cc                   	int3
ffffffff8ac26c56:	cc                   	int3
ffffffff8ac26c57:	cc                   	int3

ffffffff8ac26c58 <neighbor_trampoline_266c58>:
ffffffff8ac26c58:	e9 13 27 76 00       	jmp    ffffffff8b389370 <neighbor_trampoline_266ed8+0x762498>
ffffffff8ac26c5d:	cc                   	int3
ffffffff8ac26c5e:	cc                   	int3
ffffffff8ac26c5f:	cc                   	int3

ffffffff8ac26c60 <neighbor_trampoline_266c60>:
ffffffff8ac26c60:	e9 1b 27 76 00       	jmp    ffffffff8b389380 <neighbor_trampoline_266ed8+0x7624a8>
ffffffff8ac26c65:	cc                   	int3
ffffffff8ac26c66:	cc                   	int3
ffffffff8ac26c67:	cc                   	int3

ffffffff8ac26c68 <neighbor_trampoline_266c68>:
ffffffff8ac26c68:	e9 43 41 77 00       	jmp    ffffffff8b39adb0 <neighbor_trampoline_266ed8+0x773ed8>
ffffffff8ac26c6d:	cc                   	int3
ffffffff8ac26c6e:	cc                   	int3
ffffffff8ac26c6f:	cc                   	int3

ffffffff8ac26c70 <neighbor_trampoline_266c70>:
ffffffff8ac26c70:	e9 2b 43 77 00       	jmp    ffffffff8b39afa0 <neighbor_trampoline_266ed8+0x7740c8>
ffffffff8ac26c75:	cc                   	int3
ffffffff8ac26c76:	cc                   	int3
ffffffff8ac26c77:	cc                   	int3

ffffffff8ac26c78 <neighbor_trampoline_266c78>:
ffffffff8ac26c78:	e9 e3 5b 77 00       	jmp    ffffffff8b39c860 <neighbor_trampoline_266ed8+0x775988>
ffffffff8ac26c7d:	cc                   	int3
ffffffff8ac26c7e:	cc                   	int3
ffffffff8ac26c7f:	cc                   	int3

ffffffff8ac26c80 <neighbor_trampoline_266c80>:
ffffffff8ac26c80:	e9 bb 5f 77 00       	jmp    ffffffff8b39cc40 <neighbor_trampoline_266ed8+0x775d68>
ffffffff8ac26c85:	cc                   	int3
ffffffff8ac26c86:	cc                   	int3
ffffffff8ac26c87:	cc                   	int3

ffffffff8ac26c88 <neighbor_trampoline_266c88>:
ffffffff8ac26c88:	e9 f3 61 77 00       	jmp    ffffffff8b39ce80 <neighbor_trampoline_266ed8+0x775fa8>
ffffffff8ac26c8d:	cc                   	int3
ffffffff8ac26c8e:	cc                   	int3
ffffffff8ac26c8f:	cc                   	int3

ffffffff8ac26c90 <neighbor_trampoline_266c90>:
ffffffff8ac26c90:	e9 6b 68 77 00       	jmp    ffffffff8b39d500 <neighbor_trampoline_266ed8+0x776628>
ffffffff8ac26c95:	cc                   	int3
ffffffff8ac26c96:	cc                   	int3
ffffffff8ac26c97:	cc                   	int3

ffffffff8ac26c98 <neighbor_trampoline_266c98>:
ffffffff8ac26c98:	e9 33 40 a4 00       	jmp    ffffffff8b66acd0 <neighbor_trampoline_266ed8+0xa43df8>
ffffffff8ac26c9d:	cc                   	int3
ffffffff8ac26c9e:	cc                   	int3
ffffffff8ac26c9f:	cc                   	int3

ffffffff8ac26ca0 <neighbor_trampoline_266ca0>:
ffffffff8ac26ca0:	e9 2b 6b 77 00       	jmp    ffffffff8b39d7d0 <neighbor_trampoline_266ed8+0x7768f8>
ffffffff8ac26ca5:	cc                   	int3
ffffffff8ac26ca6:	cc                   	int3
ffffffff8ac26ca7:	cc                   	int3

ffffffff8ac26ca8 <neighbor_trampoline_266ca8>:
ffffffff8ac26ca8:	e9 e3 6c 77 00       	jmp    ffffffff8b39d990 <neighbor_trampoline_266ed8+0x776ab8>
ffffffff8ac26cad:	cc                   	int3
ffffffff8ac26cae:	cc                   	int3
ffffffff8ac26caf:	cc                   	int3

ffffffff8ac26cb0 <neighbor_trampoline_266cb0>:
ffffffff8ac26cb0:	e9 eb 6e 77 00       	jmp    ffffffff8b39dba0 <neighbor_trampoline_266ed8+0x776cc8>
ffffffff8ac26cb5:	cc                   	int3
ffffffff8ac26cb6:	cc                   	int3
ffffffff8ac26cb7:	cc                   	int3

ffffffff8ac26cb8 <neighbor_trampoline_266cb8>:
ffffffff8ac26cb8:	e9 43 6f 77 00       	jmp    ffffffff8b39dc00 <neighbor_trampoline_266ed8+0x776d28>
ffffffff8ac26cbd:	cc                   	int3
ffffffff8ac26cbe:	cc                   	int3
ffffffff8ac26cbf:	cc                   	int3

ffffffff8ac26cc0 <neighbor_trampoline_266cc0>:
ffffffff8ac26cc0:	e9 8b 71 77 00       	jmp    ffffffff8b39de50 <neighbor_trampoline_266ed8+0x776f78>
ffffffff8ac26cc5:	cc                   	int3
ffffffff8ac26cc6:	cc                   	int3
ffffffff8ac26cc7:	cc                   	int3

ffffffff8ac26cc8 <neighbor_trampoline_266cc8>:
ffffffff8ac26cc8:	e9 e3 71 77 00       	jmp    ffffffff8b39deb0 <neighbor_trampoline_266ed8+0x776fd8>
ffffffff8ac26ccd:	cc                   	int3
ffffffff8ac26cce:	cc                   	int3
ffffffff8ac26ccf:	cc                   	int3

ffffffff8ac26cd0 <neighbor_trampoline_266cd0>:
ffffffff8ac26cd0:	e9 1b 73 77 00       	jmp    ffffffff8b39dff0 <neighbor_trampoline_266ed8+0x777118>
ffffffff8ac26cd5:	cc                   	int3
ffffffff8ac26cd6:	cc                   	int3
ffffffff8ac26cd7:	cc                   	int3

ffffffff8ac26cd8 <neighbor_trampoline_266cd8>:
ffffffff8ac26cd8:	e9 93 73 77 00       	jmp    ffffffff8b39e070 <neighbor_trampoline_266ed8+0x777198>
ffffffff8ac26cdd:	cc                   	int3
ffffffff8ac26cde:	cc                   	int3
ffffffff8ac26cdf:	cc                   	int3

ffffffff8ac26ce0 <neighbor_trampoline_266ce0>:
ffffffff8ac26ce0:	e9 0b 74 77 00       	jmp    ffffffff8b39e0f0 <neighbor_trampoline_266ed8+0x777218>
ffffffff8ac26ce5:	cc                   	int3
ffffffff8ac26ce6:	cc                   	int3
ffffffff8ac26ce7:	cc                   	int3

ffffffff8ac26ce8 <neighbor_trampoline_266ce8>:
ffffffff8ac26ce8:	e9 a3 9e 77 00       	jmp    ffffffff8b3a0b90 <neighbor_trampoline_266ed8+0x779cb8>
ffffffff8ac26ced:	cc                   	int3
ffffffff8ac26cee:	cc                   	int3
ffffffff8ac26cef:	cc                   	int3

ffffffff8ac26cf0 <neighbor_trampoline_266cf0>:
ffffffff8ac26cf0:	e9 db 9f 77 00       	jmp    ffffffff8b3a0cd0 <neighbor_trampoline_266ed8+0x779df8>
ffffffff8ac26cf5:	cc                   	int3
ffffffff8ac26cf6:	cc                   	int3
ffffffff8ac26cf7:	cc                   	int3

ffffffff8ac26cf8 <neighbor_trampoline_266cf8>:
ffffffff8ac26cf8:	e9 73 a0 77 00       	jmp    ffffffff8b3a0d70 <neighbor_trampoline_266ed8+0x779e98>
ffffffff8ac26cfd:	cc                   	int3
ffffffff8ac26cfe:	cc                   	int3
ffffffff8ac26cff:	cc                   	int3

ffffffff8ac26d00 <neighbor_trampoline_266d00>:
ffffffff8ac26d00:	e9 eb a1 77 00       	jmp    ffffffff8b3a0ef0 <neighbor_trampoline_266ed8+0x77a018>
ffffffff8ac26d05:	cc                   	int3
ffffffff8ac26d06:	cc                   	int3
ffffffff8ac26d07:	cc                   	int3

ffffffff8ac26d08 <neighbor_trampoline_266d08>:
ffffffff8ac26d08:	e9 43 a3 77 00       	jmp    ffffffff8b3a1050 <neighbor_trampoline_266ed8+0x77a178>
ffffffff8ac26d0d:	cc                   	int3
ffffffff8ac26d0e:	cc                   	int3
ffffffff8ac26d0f:	cc                   	int3

ffffffff8ac26d10 <neighbor_trampoline_266d10>:
ffffffff8ac26d10:	e9 7b a7 77 00       	jmp    ffffffff8b3a1490 <neighbor_trampoline_266ed8+0x77a5b8>
ffffffff8ac26d15:	cc                   	int3
ffffffff8ac26d16:	cc                   	int3
ffffffff8ac26d17:	cc                   	int3

ffffffff8ac26d18 <neighbor_trampoline_266d18>:
ffffffff8ac26d18:	e9 c3 f8 79 00       	jmp    ffffffff8b3c65e0 <neighbor_trampoline_266ed8+0x79f708>
ffffffff8ac26d1d:	cc                   	int3
ffffffff8ac26d1e:	cc                   	int3
ffffffff8ac26d1f:	cc                   	int3

ffffffff8ac26d20 <neighbor_trampoline_266d20>:
ffffffff8ac26d20:	e9 1b a6 e9 ff       	jmp    ffffffff8aac1340 <handler_632_entry-0x164ba0>
ffffffff8ac26d25:	cc                   	int3
ffffffff8ac26d26:	cc                   	int3
ffffffff8ac26d27:	cc                   	int3

ffffffff8ac26d28 <neighbor_trampoline_266d28>:
ffffffff8ac26d28:	e9 03 c2 7c 00       	jmp    ffffffff8b3f2f30 <neighbor_trampoline_266ed8+0x7cc058>
ffffffff8ac26d2d:	cc                   	int3
ffffffff8ac26d2e:	cc                   	int3
ffffffff8ac26d2f:	cc                   	int3

ffffffff8ac26d30 <neighbor_trampoline_266d30>:
ffffffff8ac26d30:	e9 8b c9 7c 00       	jmp    ffffffff8b3f36c0 <neighbor_trampoline_266ed8+0x7cc7e8>
ffffffff8ac26d35:	cc                   	int3
ffffffff8ac26d36:	cc                   	int3
ffffffff8ac26d37:	cc                   	int3

ffffffff8ac26d38 <neighbor_trampoline_266d38>:
ffffffff8ac26d38:	e9 53 1f 7d 00       	jmp    ffffffff8b3f8c90 <neighbor_trampoline_266ed8+0x7d1db8>
ffffffff8ac26d3d:	cc                   	int3
ffffffff8ac26d3e:	cc                   	int3
ffffffff8ac26d3f:	cc                   	int3

ffffffff8ac26d40 <neighbor_trampoline_266d40>:
ffffffff8ac26d40:	e9 bb 3d 80 00       	jmp    ffffffff8b42ab00 <neighbor_trampoline_266ed8+0x803c28>
ffffffff8ac26d45:	cc                   	int3
ffffffff8ac26d46:	cc                   	int3
ffffffff8ac26d47:	cc                   	int3

ffffffff8ac26d48 <neighbor_trampoline_266d48>:
ffffffff8ac26d48:	e9 63 3e 80 00       	jmp    ffffffff8b42abb0 <neighbor_trampoline_266ed8+0x803cd8>
ffffffff8ac26d4d:	cc                   	int3
ffffffff8ac26d4e:	cc                   	int3
ffffffff8ac26d4f:	cc                   	int3

ffffffff8ac26d50 <neighbor_trampoline_266d50>:
ffffffff8ac26d50:	e9 bb 7e 82 00       	jmp    ffffffff8b44ec10 <neighbor_trampoline_266ed8+0x827d38>
ffffffff8ac26d55:	cc                   	int3
ffffffff8ac26d56:	cc                   	int3
ffffffff8ac26d57:	cc                   	int3

ffffffff8ac26d58 <neighbor_trampoline_266d58>:
ffffffff8ac26d58:	e9 a3 80 82 00       	jmp    ffffffff8b44ee00 <neighbor_trampoline_266ed8+0x827f28>
ffffffff8ac26d5d:	cc                   	int3
ffffffff8ac26d5e:	cc                   	int3
ffffffff8ac26d5f:	cc                   	int3

ffffffff8ac26d60 <neighbor_trampoline_266d60>:
ffffffff8ac26d60:	e9 4b aa 84 00       	jmp    ffffffff8b4717b0 <neighbor_trampoline_266ed8+0x84a8d8>
ffffffff8ac26d65:	cc                   	int3
ffffffff8ac26d66:	cc                   	int3
ffffffff8ac26d67:	cc                   	int3

ffffffff8ac26d68 <neighbor_trampoline_266d68>:
ffffffff8ac26d68:	e9 43 9a 85 00       	jmp    ffffffff8b4807b0 <neighbor_trampoline_266ed8+0x8598d8>
ffffffff8ac26d6d:	cc                   	int3
ffffffff8ac26d6e:	cc                   	int3
ffffffff8ac26d6f:	cc                   	int3

ffffffff8ac26d70 <neighbor_trampoline_266d70>:
ffffffff8ac26d70:	e9 7b bd 85 00       	jmp    ffffffff8b482af0 <neighbor_trampoline_266ed8+0x85bc18>
ffffffff8ac26d75:	cc                   	int3
ffffffff8ac26d76:	cc                   	int3
ffffffff8ac26d77:	cc                   	int3

ffffffff8ac26d78 <neighbor_trampoline_266d78>:
ffffffff8ac26d78:	e9 d3 39 eb ff       	jmp    ffffffff8aada750 <handler_632_entry-0x14b790>
ffffffff8ac26d7d:	cc                   	int3
ffffffff8ac26d7e:	cc                   	int3
ffffffff8ac26d7f:	cc                   	int3

ffffffff8ac26d80 <neighbor_trampoline_266d80>:
ffffffff8ac26d80:	e9 1b a5 87 00       	jmp    ffffffff8b4a12a0 <neighbor_trampoline_266ed8+0x87a3c8>
ffffffff8ac26d85:	cc                   	int3
ffffffff8ac26d86:	cc                   	int3
ffffffff8ac26d87:	cc                   	int3

ffffffff8ac26d88 <neighbor_trampoline_266d88>:
ffffffff8ac26d88:	e9 73 c6 87 00       	jmp    ffffffff8b4a3400 <neighbor_trampoline_266ed8+0x87c528>
ffffffff8ac26d8d:	cc                   	int3
ffffffff8ac26d8e:	cc                   	int3
ffffffff8ac26d8f:	cc                   	int3

ffffffff8ac26d90 <neighbor_trampoline_266d90>:
ffffffff8ac26d90:	e9 9b c7 87 00       	jmp    ffffffff8b4a3530 <neighbor_trampoline_266ed8+0x87c658>
ffffffff8ac26d95:	cc                   	int3
ffffffff8ac26d96:	cc                   	int3
ffffffff8ac26d97:	cc                   	int3

ffffffff8ac26d98 <neighbor_trampoline_266d98>:
ffffffff8ac26d98:	e9 23 f6 87 00       	jmp    ffffffff8b4a63c0 <neighbor_trampoline_266ed8+0x87f4e8>
ffffffff8ac26d9d:	cc                   	int3
ffffffff8ac26d9e:	cc                   	int3
ffffffff8ac26d9f:	cc                   	int3

ffffffff8ac26da0 <neighbor_trampoline_266da0>:
ffffffff8ac26da0:	e9 3b 11 8a 00       	jmp    ffffffff8b4c7ee0 <neighbor_trampoline_266ed8+0x8a1008>
ffffffff8ac26da5:	cc                   	int3
ffffffff8ac26da6:	cc                   	int3
ffffffff8ac26da7:	cc                   	int3

ffffffff8ac26da8 <neighbor_trampoline_266da8>:
ffffffff8ac26da8:	e9 e3 13 8a 00       	jmp    ffffffff8b4c8190 <neighbor_trampoline_266ed8+0x8a12b8>
ffffffff8ac26dad:	cc                   	int3
ffffffff8ac26dae:	cc                   	int3
ffffffff8ac26daf:	cc                   	int3

ffffffff8ac26db0 <neighbor_trampoline_266db0>:
ffffffff8ac26db0:	e9 7b 17 8a 00       	jmp    ffffffff8b4c8530 <neighbor_trampoline_266ed8+0x8a1658>
ffffffff8ac26db5:	cc                   	int3
ffffffff8ac26db6:	cc                   	int3
ffffffff8ac26db7:	cc                   	int3

ffffffff8ac26db8 <neighbor_trampoline_266db8>:
ffffffff8ac26db8:	e9 53 1a 8a 00       	jmp    ffffffff8b4c8810 <neighbor_trampoline_266ed8+0x8a1938>
ffffffff8ac26dbd:	cc                   	int3
ffffffff8ac26dbe:	cc                   	int3
ffffffff8ac26dbf:	cc                   	int3

ffffffff8ac26dc0 <neighbor_trampoline_266dc0>:
ffffffff8ac26dc0:	e9 db 28 8a 00       	jmp    ffffffff8b4c96a0 <neighbor_trampoline_266ed8+0x8a27c8>
ffffffff8ac26dc5:	cc                   	int3
ffffffff8ac26dc6:	cc                   	int3
ffffffff8ac26dc7:	cc                   	int3

ffffffff8ac26dc8 <neighbor_trampoline_266dc8>:
ffffffff8ac26dc8:	e9 23 47 8a 00       	jmp    ffffffff8b4cb4f0 <neighbor_trampoline_266ed8+0x8a4618>
ffffffff8ac26dcd:	cc                   	int3
ffffffff8ac26dce:	cc                   	int3
ffffffff8ac26dcf:	cc                   	int3

ffffffff8ac26dd0 <neighbor_trampoline_266dd0>:
ffffffff8ac26dd0:	e9 1b 83 f8 ff       	jmp    ffffffff8abaf0f0 <handler_632_entry-0x76df0>
ffffffff8ac26dd5:	cc                   	int3
ffffffff8ac26dd6:	cc                   	int3
ffffffff8ac26dd7:	cc                   	int3

ffffffff8ac26dd8 <neighbor_trampoline_266dd8>:
ffffffff8ac26dd8:	e9 83 92 f8 ff       	jmp    ffffffff8abb0060 <handler_632_entry-0x75e80>
ffffffff8ac26ddd:	cc                   	int3
ffffffff8ac26dde:	cc                   	int3
ffffffff8ac26ddf:	cc                   	int3

ffffffff8ac26de0 <neighbor_trampoline_266de0>:
ffffffff8ac26de0:	e9 cb 4b eb ff       	jmp    ffffffff8aadb9b0 <handler_632_entry-0x14a530>
ffffffff8ac26de5:	cc                   	int3
ffffffff8ac26de6:	cc                   	int3
ffffffff8ac26de7:	cc                   	int3

ffffffff8ac26de8 <neighbor_trampoline_266de8>:
ffffffff8ac26de8:	e9 43 43 8d 00       	jmp    ffffffff8b4fb130 <neighbor_trampoline_266ed8+0x8d4258>
ffffffff8ac26ded:	cc                   	int3
ffffffff8ac26dee:	cc                   	int3
ffffffff8ac26def:	cc                   	int3

ffffffff8ac26df0 <neighbor_trampoline_266df0>:
ffffffff8ac26df0:	e9 4b 0c 8e 00       	jmp    ffffffff8b507a40 <neighbor_trampoline_266ed8+0x8e0b68>
ffffffff8ac26df5:	cc                   	int3
ffffffff8ac26df6:	cc                   	int3
ffffffff8ac26df7:	cc                   	int3

ffffffff8ac26df8 <neighbor_trampoline_266df8>:
ffffffff8ac26df8:	e9 c3 95 8e 00       	jmp    ffffffff8b5103c0 <neighbor_trampoline_266ed8+0x8e94e8>
ffffffff8ac26dfd:	cc                   	int3
ffffffff8ac26dfe:	cc                   	int3
ffffffff8ac26dff:	cc                   	int3

ffffffff8ac26e00 <neighbor_trampoline_266e00>:
ffffffff8ac26e00:	e9 0b a1 8e 00       	jmp    ffffffff8b510f10 <neighbor_trampoline_266ed8+0x8ea038>
ffffffff8ac26e05:	cc                   	int3
ffffffff8ac26e06:	cc                   	int3
ffffffff8ac26e07:	cc                   	int3

ffffffff8ac26e08 <neighbor_trampoline_266e08>:
ffffffff8ac26e08:	e9 a3 a1 8e 00       	jmp    ffffffff8b510fb0 <neighbor_trampoline_266ed8+0x8ea0d8>
ffffffff8ac26e0d:	cc                   	int3
ffffffff8ac26e0e:	cc                   	int3
ffffffff8ac26e0f:	cc                   	int3

ffffffff8ac26e10 <neighbor_trampoline_266e10>:
ffffffff8ac26e10:	e9 9b a2 8e 00       	jmp    ffffffff8b5110b0 <neighbor_trampoline_266ed8+0x8ea1d8>
ffffffff8ac26e15:	cc                   	int3
ffffffff8ac26e16:	cc                   	int3
ffffffff8ac26e17:	cc                   	int3

ffffffff8ac26e18 <neighbor_trampoline_266e18>:
ffffffff8ac26e18:	e9 73 a3 8e 00       	jmp    ffffffff8b511190 <neighbor_trampoline_266ed8+0x8ea2b8>
ffffffff8ac26e1d:	cc                   	int3
ffffffff8ac26e1e:	cc                   	int3
ffffffff8ac26e1f:	cc                   	int3

ffffffff8ac26e20 <neighbor_trampoline_266e20>:
ffffffff8ac26e20:	e9 6b a4 8e 00       	jmp    ffffffff8b511290 <neighbor_trampoline_266ed8+0x8ea3b8>
ffffffff8ac26e25:	cc                   	int3
ffffffff8ac26e26:	cc                   	int3
ffffffff8ac26e27:	cc                   	int3

ffffffff8ac26e28 <neighbor_trampoline_266e28>:
ffffffff8ac26e28:	e9 a3 a4 8e 00       	jmp    ffffffff8b5112d0 <neighbor_trampoline_266ed8+0x8ea3f8>
ffffffff8ac26e2d:	cc                   	int3
ffffffff8ac26e2e:	cc                   	int3
ffffffff8ac26e2f:	cc                   	int3

ffffffff8ac26e30 <neighbor_trampoline_266e30>:
ffffffff8ac26e30:	e9 eb a4 8e 00       	jmp    ffffffff8b511320 <neighbor_trampoline_266ed8+0x8ea448>
ffffffff8ac26e35:	cc                   	int3
ffffffff8ac26e36:	cc                   	int3
ffffffff8ac26e37:	cc                   	int3

ffffffff8ac26e38 <neighbor_trampoline_266e38>:
ffffffff8ac26e38:	e9 63 fa 8e 00       	jmp    ffffffff8b5168a0 <neighbor_trampoline_266ed8+0x8ef9c8>
ffffffff8ac26e3d:	cc                   	int3
ffffffff8ac26e3e:	cc                   	int3
ffffffff8ac26e3f:	cc                   	int3

ffffffff8ac26e40 <neighbor_trampoline_266e40>:
ffffffff8ac26e40:	e9 9b 32 e3 ff       	jmp    ffffffff8aa5a0e0 <handler_632_entry-0x1cbe00>
ffffffff8ac26e45:	cc                   	int3
ffffffff8ac26e46:	cc                   	int3
ffffffff8ac26e47:	cc                   	int3

ffffffff8ac26e48 <neighbor_trampoline_266e48>:
ffffffff8ac26e48:	e9 23 40 90 00       	jmp    ffffffff8b52ae70 <neighbor_trampoline_266ed8+0x903f98>
ffffffff8ac26e4d:	cc                   	int3
ffffffff8ac26e4e:	cc                   	int3
ffffffff8ac26e4f:	cc                   	int3

ffffffff8ac26e50 <neighbor_trampoline_266e50>:
ffffffff8ac26e50:	e9 3b 4d 90 00       	jmp    ffffffff8b52bb90 <neighbor_trampoline_266ed8+0x904cb8>
ffffffff8ac26e55:	cc                   	int3
ffffffff8ac26e56:	cc                   	int3
ffffffff8ac26e57:	cc                   	int3

ffffffff8ac26e58 <neighbor_trampoline_266e58>:
ffffffff8ac26e58:	e9 23 6b 90 00       	jmp    ffffffff8b52d980 <neighbor_trampoline_266ed8+0x906aa8>
ffffffff8ac26e5d:	cc                   	int3
ffffffff8ac26e5e:	cc                   	int3
ffffffff8ac26e5f:	cc                   	int3

ffffffff8ac26e60 <neighbor_trampoline_266e60>:
ffffffff8ac26e60:	e9 3b 6c 90 00       	jmp    ffffffff8b52daa0 <neighbor_trampoline_266ed8+0x906bc8>
ffffffff8ac26e65:	cc                   	int3
ffffffff8ac26e66:	cc                   	int3
ffffffff8ac26e67:	cc                   	int3

ffffffff8ac26e68 <neighbor_trampoline_266e68>:
ffffffff8ac26e68:	e9 13 73 90 00       	jmp    ffffffff8b52e180 <neighbor_trampoline_266ed8+0x9072a8>
ffffffff8ac26e6d:	cc                   	int3
ffffffff8ac26e6e:	cc                   	int3
ffffffff8ac26e6f:	cc                   	int3

ffffffff8ac26e70 <neighbor_trampoline_266e70>:
ffffffff8ac26e70:	e9 ab a4 90 00       	jmp    ffffffff8b531320 <neighbor_trampoline_266ed8+0x90a448>
ffffffff8ac26e75:	cc                   	int3
ffffffff8ac26e76:	cc                   	int3
ffffffff8ac26e77:	cc                   	int3

ffffffff8ac26e78 <neighbor_trampoline_266e78>:
ffffffff8ac26e78:	e9 f3 a4 90 00       	jmp    ffffffff8b531370 <neighbor_trampoline_266ed8+0x90a498>
ffffffff8ac26e7d:	cc                   	int3
ffffffff8ac26e7e:	cc                   	int3
ffffffff8ac26e7f:	cc                   	int3

ffffffff8ac26e80 <neighbor_trampoline_266e80>:
ffffffff8ac26e80:	e9 3b a5 90 00       	jmp    ffffffff8b5313c0 <neighbor_trampoline_266ed8+0x90a4e8>
ffffffff8ac26e85:	cc                   	int3
ffffffff8ac26e86:	cc                   	int3
ffffffff8ac26e87:	cc                   	int3

ffffffff8ac26e88 <neighbor_trampoline_266e88>:
ffffffff8ac26e88:	e9 83 a5 90 00       	jmp    ffffffff8b531410 <neighbor_trampoline_266ed8+0x90a538>
ffffffff8ac26e8d:	cc                   	int3
ffffffff8ac26e8e:	cc                   	int3
ffffffff8ac26e8f:	cc                   	int3

ffffffff8ac26e90 <neighbor_trampoline_266e90>:
ffffffff8ac26e90:	e9 cb aa 90 00       	jmp    ffffffff8b531960 <neighbor_trampoline_266ed8+0x90aa88>
ffffffff8ac26e95:	cc                   	int3
ffffffff8ac26e96:	cc                   	int3
ffffffff8ac26e97:	cc                   	int3

ffffffff8ac26e98 <neighbor_trampoline_266e98>:
ffffffff8ac26e98:	e9 33 ab 90 00       	jmp    ffffffff8b5319d0 <neighbor_trampoline_266ed8+0x90aaf8>
ffffffff8ac26e9d:	cc                   	int3
ffffffff8ac26e9e:	cc                   	int3
ffffffff8ac26e9f:	cc                   	int3

ffffffff8ac26ea0 <neighbor_trampoline_266ea0>:
ffffffff8ac26ea0:	e9 9b ab 90 00       	jmp    ffffffff8b531a40 <neighbor_trampoline_266ed8+0x90ab68>
ffffffff8ac26ea5:	cc                   	int3
ffffffff8ac26ea6:	cc                   	int3
ffffffff8ac26ea7:	cc                   	int3

ffffffff8ac26ea8 <neighbor_trampoline_266ea8>:
ffffffff8ac26ea8:	e9 03 ac 90 00       	jmp    ffffffff8b531ab0 <neighbor_trampoline_266ed8+0x90abd8>
ffffffff8ac26ead:	cc                   	int3
ffffffff8ac26eae:	cc                   	int3
ffffffff8ac26eaf:	cc                   	int3

ffffffff8ac26eb0 <neighbor_trampoline_266eb0>:
ffffffff8ac26eb0:	e9 6b b7 90 00       	jmp    ffffffff8b532620 <neighbor_trampoline_266ed8+0x90b748>
ffffffff8ac26eb5:	cc                   	int3
ffffffff8ac26eb6:	cc                   	int3
ffffffff8ac26eb7:	cc                   	int3

ffffffff8ac26eb8 <neighbor_trampoline_266eb8>:
ffffffff8ac26eb8:	e9 a3 b9 90 00       	jmp    ffffffff8b532860 <neighbor_trampoline_266ed8+0x90b988>
ffffffff8ac26ebd:	cc                   	int3
ffffffff8ac26ebe:	cc                   	int3
ffffffff8ac26ebf:	cc                   	int3

ffffffff8ac26ec0 <neighbor_trampoline_266ec0>:
ffffffff8ac26ec0:	e9 0b 23 91 00       	jmp    ffffffff8b5391d0 <neighbor_trampoline_266ed8+0x9122f8>
ffffffff8ac26ec5:	cc                   	int3
ffffffff8ac26ec6:	cc                   	int3
ffffffff8ac26ec7:	cc                   	int3

ffffffff8ac26ec8 <neighbor_trampoline_266ec8>:
ffffffff8ac26ec8:	e9 c3 23 91 00       	jmp    ffffffff8b539290 <neighbor_trampoline_266ed8+0x9123b8>
ffffffff8ac26ecd:	cc                   	int3
ffffffff8ac26ece:	cc                   	int3
ffffffff8ac26ecf:	cc                   	int3

ffffffff8ac26ed0 <neighbor_trampoline_266ed0>:
ffffffff8ac26ed0:	e9 1b 25 91 00       	jmp    ffffffff8b5393f0 <neighbor_trampoline_266ed8+0x912518>
ffffffff8ac26ed5:	cc                   	int3
ffffffff8ac26ed6:	cc                   	int3
ffffffff8ac26ed7:	cc                   	int3

ffffffff8ac26ed8 <neighbor_trampoline_266ed8>:
ffffffff8ac26ed8:	e9 43 25 91 00       	jmp    ffffffff8b539420 <neighbor_trampoline_266ed8+0x912548>
ffffffff8ac26edd:	cc                   	int3
ffffffff8ac26ede:	cc                   	int3
ffffffff8ac26edf:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8adf8e30, handler_body_632; REA Evidence ev_618ceb8b7bacc084c18a73b70c9c507d6f32d2d9b94d7cf7213db143f9a78184
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8adf8e30", "end": "0xffffffff8adf9061"}], "total_bytes": 562, "span_bytes": 562, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_632:
0xffffffff8adf8e30: PUSH RBP
0xffffffff8adf8e31: MOV RBP, RSP
0xffffffff8adf8e34: PUSH R15
0xffffffff8adf8e36: PUSH R14
0xffffffff8adf8e38: PUSH R13
0xffffffff8adf8e3a: PUSH R12
0xffffffff8adf8e3c: PUSH RBX
0xffffffff8adf8e3d: PUSH RAX
0xffffffff8adf8e3e: MOV R12, RDI
0xffffffff8adf8e41: MOV RDI, qword ptr [RSI]
0xffffffff8adf8e44: MOV EBX, 0xb
0xffffffff8adf8e49: MOVSXD RAX, dword ptr [R12 + 0x9c]
0xffffffff8adf8e51: CMP RDI, RAX
0xffffffff8adf8e54: JZ 0xffffffff8adf9014
loc_ffffffff8adf8e5a:
0xffffffff8adf8e5a: MOV RAX, qword ptr [R12 + 0x8]
0xffffffff8adf8e5f: MOV R15, RSI
0xffffffff8adf8e62: MOV ESI, dword ptr [RAX + 0xbc]
0xffffffff8adf8e68: CALL 0xffffffff8b552420
0xffffffff8adf8e6d: MOV EBX, 0x3
0xffffffff8adf8e72: TEST RAX, RAX
0xffffffff8adf8e75: JZ 0xffffffff8adf9014
loc_ffffffff8adf8e7b:
0xffffffff8adf8e7b: LEA RDX, [-0x7432e4f9]
0xffffffff8adf8e82: MOV RDI, RAX
0xffffffff8adf8e85: MOV ECX, 0x32f
0xffffffff8adf8e8a: XOR ESI, ESI
0xffffffff8adf8e8c: MOV R14, RAX
0xffffffff8adf8e8f: CALL 0xffffffff8ae878b0
0xffffffff8adf8e94: MOV EAX, dword ptr [R14 + 0xe8]
0xffffffff8adf8e9b: TEST AL, 0x20
0xffffffff8adf8e9d: JNZ 0xffffffff8adf8fe2
loc_ffffffff8adf8ea3:
0xffffffff8adf8ea3: MOV ECX, dword ptr [R14 + 0xe4]
0xffffffff8adf8eaa: TEST ECX, ECX
0xffffffff8adf8eac: JS 0xffffffff8adf8fe2
loc_ffffffff8adf8eb2:
0xffffffff8adf8eb2: TEST AL, 0x2
0xffffffff8adf8eb4: SETZ DL
0xffffffff8adf8eb7: TEST CL, 0x8
0xffffffff8adf8eba: SETZ SIL
0xffffffff8adf8ebe: OR SIL, DL
0xffffffff8adf8ec1: JZ 0xffffffff8adf9025
loc_ffffffff8adf8ec7:
0xffffffff8adf8ec7: OR ECX, 0x80000800
0xffffffff8adf8ecd: MOV dword ptr [R14 + 0xe4], ECX
0xffffffff8adf8ed4: CMP dword ptr [R14 + 0x400], 0x4
0xffffffff8adf8edc: JNZ 0xffffffff8adf8ee6
loc_ffffffff8adf8ede:
0xffffffff8adf8ede: MOV RDI, R14
0xffffffff8adf8ee1: CALL 0xffffffff8b4c35d0
loc_ffffffff8adf8ee6:
0xffffffff8adf8ee6: LEA R13, [R14 + 0x8]
0xffffffff8adf8eea: NOP word ptr [RAX + RAX*0x1]
loc_ffffffff8adf8ef0:
0xffffffff8adf8ef0: MOV EAX, dword ptr [R14 + 0x400]
0xffffffff8adf8ef7: ADD EAX, -0x3
0xffffffff8adf8efa: CMP EAX, 0x2
0xffffffff8adf8efd: JC 0xffffffff8adf8f0d
loc_ffffffff8adf8eff:
0xffffffff8adf8eff: TEST byte ptr [R14 + 0xe8], 0x8
0xffffffff8adf8f07: JZ 0xffffffff8adf8fcc
loc_ffffffff8adf8f0d:
0xffffffff8adf8f0d: MOV RDI, qword ptr [R14]
0xffffffff8adf8f10: XOR ESI, ESI
0xffffffff8adf8f12: XOR EDX, EDX
0xffffffff8adf8f14: XOR ECX, ECX
0xffffffff8adf8f16: ADD RDI, 0x18
0xffffffff8adf8f1a: CALL 0xffffffff8ae87520
0xffffffff8adf8f1f: MOV RDI, qword ptr [R14 + 0x8]
0xffffffff8adf8f23: MOV EAX, 0x148
0xffffffff8adf8f28: XOR ESI, ESI
0xffffffff8adf8f2a: XOR EDX, EDX
0xffffffff8adf8f2c: XOR ECX, ECX
0xffffffff8adf8f2e: ADD RDI, RAX
0xffffffff8adf8f31: CALL 0xffffffff8ae86fa0
0xffffffff8adf8f36: MOV RSI, qword ptr [0xffffffff8e2e03d0]
0xffffffff8adf8f3d: LEA RDI, [-0x7438b934]
0xffffffff8adf8f44: MOV ECX, 0x100
0xffffffff8adf8f49: XOR EDX, EDX
0xffffffff8adf8f4b: CALL 0xffffffff8b5c6830
0xffffffff8adf8f50: MOV RAX, qword ptr [R12 + 0x8]
0xffffffff8adf8f55: MOV EDI, dword ptr [R15]
0xffffffff8adf8f58: MOV ESI, dword ptr [RAX + 0xbc]
0xffffffff8adf8f5e: CALL 0xffffffff8b552420
0xffffffff8adf8f63: TEST RAX, RAX
0xffffffff8adf8f66: JZ 0xffffffff8adf9014
loc_ffffffff8adf8f6c:
0xffffffff8adf8f6c: CMP R14, RAX
0xffffffff8adf8f6f: JNZ 0xffffffff8adf9054
loc_ffffffff8adf8f75:
0xffffffff8adf8f75: MOV RDI, R14
0xffffffff8adf8f78: LEA RDX, [-0x7432e4f9]
0xffffffff8adf8f7f: MOV ECX, 0x34f
0xffffffff8adf8f84: XOR ESI, ESI
0xffffffff8adf8f86: CALL 0xffffffff8ae878b0
0xffffffff8adf8f8b: MOV EAX, dword ptr [R14 + 0xe8]
0xffffffff8adf8f92: TEST AL, 0x2
0xffffffff8adf8f94: JZ 0xffffffff8adf8ef0
loc_ffffffff8adf8f9a:
0xffffffff8adf8f9a: MOV ECX, dword ptr [R14 + 0xe4]
0xffffffff8adf8fa1: TEST CL, 0x8
0xffffffff8adf8fa4: JZ 0xffffffff8adf8ef0
loc_ffffffff8adf8faa:
0xffffffff8adf8faa: AND ECX, 0x7ffff7ff
0xffffffff8adf8fb0: OR EAX, 0x20
0xffffffff8adf8fb3: MOV dword ptr [R14 + 0xe4], ECX
0xffffffff8adf8fba: MOV dword ptr [R14 + 0x400], 0x1
0xffffffff8adf8fc5: MOV dword ptr [R14 + 0xe8], EAX
loc_ffffffff8adf8fcc:
0xffffffff8adf8fcc: MOV RDI, qword ptr [R14]
0xffffffff8adf8fcf: XOR EBX, EBX
0xffffffff8adf8fd1: XOR ESI, ESI
0xffffffff8adf8fd3: XOR EDX, EDX
0xffffffff8adf8fd5: XOR ECX, ECX
0xffffffff8adf8fd7: ADD RDI, 0x18
0xffffffff8adf8fdb: CALL 0xffffffff8ae87520
0xffffffff8adf8fe0: JMP 0xffffffff8adf9000
loc_ffffffff8adf8fe2:
0xffffffff8adf8fe2: MOV RDI, qword ptr [R14]
0xffffffff8adf8fe5: XOR ESI, ESI
0xffffffff8adf8fe7: XOR EDX, EDX
0xffffffff8adf8fe9: XOR ECX, ECX
0xffffffff8adf8feb: ADD RDI, 0x18
0xffffffff8adf8fef: CALL 0xffffffff8ae87520
0xffffffff8adf8ff4: ADD R14, 0x8
0xffffffff8adf8ff8: MOV EBX, 0x16
loc_ffffffff8adf8ffd:
0xffffffff8adf8ffd: MOV R13, R14
loc_ffffffff8adf9000:
0xffffffff8adf9000: MOV EDI, 0x148
0xffffffff8adf9005: ADD RDI, qword ptr [R13]
0xffffffff8adf9009: XOR ESI, ESI
0xffffffff8adf900b: XOR EDX, EDX
0xffffffff8adf900d: XOR ECX, ECX
0xffffffff8adf900f: CALL 0xffffffff8ae86fa0
loc_ffffffff8adf9014:
0xffffffff8adf9014: MOV EAX, EBX
0xffffffff8adf9016: ADD RSP, 0x8
0xffffffff8adf901a: POP RBX
0xffffffff8adf901b: POP R12
0xffffffff8adf901d: POP R13
0xffffffff8adf901f: POP R14
0xffffffff8adf9021: POP R15
0xffffffff8adf9023: POP RBP
0xffffffff8adf9024: RET
loc_ffffffff8adf9025:
0xffffffff8adf9025: OR EAX, 0x20
0xffffffff8adf9028: MOV dword ptr [R14 + 0x400], 0x1
0xffffffff8adf9033: XOR EBX, EBX
0xffffffff8adf9035: XOR ESI, ESI
0xffffffff8adf9037: XOR EDX, EDX
0xffffffff8adf9039: XOR ECX, ECX
0xffffffff8adf903b: MOV dword ptr [R14 + 0xe8], EAX
0xffffffff8adf9042: MOV RDI, qword ptr [R14]
0xffffffff8adf9045: ADD RDI, 0x18
0xffffffff8adf9049: CALL 0xffffffff8ae87520
0xffffffff8adf904e: ADD R14, 0x8
0xffffffff8adf9052: JMP 0xffffffff8adf8ffd
loc_ffffffff8adf9054:
0xffffffff8adf9054: ADD RAX, 0x8
0xffffffff8adf9058: MOV EBX, 0x3
0xffffffff8adf905d: MOV R13, RAX
0xffffffff8adf9060: JMP 0xffffffff8adf9000
; END FUNCTION handler_body_632

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_d8dc44cc6275d654225f48063fc2c3c37a7abbcd7c1498d38404461a3a484537
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_632.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8adf8e30 <handler_632_body>:
ffffffff8adf8e30:	55                   	push   %rbp
ffffffff8adf8e31:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf8e34:	41 57                	push   %r15
ffffffff8adf8e36:	41 56                	push   %r14
ffffffff8adf8e38:	41 55                	push   %r13
ffffffff8adf8e3a:	41 54                	push   %r12
ffffffff8adf8e3c:	53                   	push   %rbx
ffffffff8adf8e3d:	50                   	push   %rax
ffffffff8adf8e3e:	49 89 fc             	mov    %rdi,%r12
ffffffff8adf8e41:	48 8b 3e             	mov    (%rsi),%rdi
ffffffff8adf8e44:	bb 0b 00 00 00       	mov    $0xb,%ebx
ffffffff8adf8e49:	49 63 84 24 9c 00 00 	movslq 0x9c(%r12),%rax
ffffffff8adf8e50:	00 
ffffffff8adf8e51:	48 39 c7             	cmp    %rax,%rdi
ffffffff8adf8e54:	0f 84 ba 01 00 00    	je     ffffffff8adf9014 <handler_632_body+0x1e4>
ffffffff8adf8e5a:	49 8b 44 24 08       	mov    0x8(%r12),%rax
ffffffff8adf8e5f:	49 89 f7             	mov    %rsi,%r15
ffffffff8adf8e62:	8b b0 bc 00 00 00    	mov    0xbc(%rax),%esi
ffffffff8adf8e68:	e8 b3 95 75 00       	call   ffffffff8b552420 <frame_candidate_43a930+0x757af0>
ffffffff8adf8e6d:	bb 03 00 00 00       	mov    $0x3,%ebx
ffffffff8adf8e72:	48 85 c0             	test   %rax,%rax
ffffffff8adf8e75:	0f 84 99 01 00 00    	je     ffffffff8adf9014 <handler_632_body+0x1e4>
ffffffff8adf8e7b:	48 8d 15 85 8c ed 00 	lea    0xed8c85(%rip),%rdx        # ffffffff8bcd1b07 <frame_candidate_43a930+0xed71d7>
ffffffff8adf8e82:	48 89 c7             	mov    %rax,%rdi
ffffffff8adf8e85:	b9 2f 03 00 00       	mov    $0x32f,%ecx
ffffffff8adf8e8a:	31 f6                	xor    %esi,%esi
ffffffff8adf8e8c:	49 89 c6             	mov    %rax,%r14
ffffffff8adf8e8f:	e8 1c ea 08 00       	call   ffffffff8ae878b0 <frame_candidate_43a930+0x8cf80>
ffffffff8adf8e94:	41 8b 86 e8 00 00 00 	mov    0xe8(%r14),%eax
ffffffff8adf8e9b:	a8 20                	test   $0x20,%al
ffffffff8adf8e9d:	0f 85 3f 01 00 00    	jne    ffffffff8adf8fe2 <handler_632_body+0x1b2>
ffffffff8adf8ea3:	41 8b 8e e4 00 00 00 	mov    0xe4(%r14),%ecx
ffffffff8adf8eaa:	85 c9                	test   %ecx,%ecx
ffffffff8adf8eac:	0f 88 30 01 00 00    	js     ffffffff8adf8fe2 <handler_632_body+0x1b2>
ffffffff8adf8eb2:	a8 02                	test   $0x2,%al
ffffffff8adf8eb4:	0f 94 c2             	sete   %dl
ffffffff8adf8eb7:	f6 c1 08             	test   $0x8,%cl
ffffffff8adf8eba:	40 0f 94 c6          	sete   %sil
ffffffff8adf8ebe:	40 08 d6             	or     %dl,%sil
ffffffff8adf8ec1:	0f 84 5e 01 00 00    	je     ffffffff8adf9025 <handler_632_body+0x1f5>
ffffffff8adf8ec7:	81 c9 00 08 00 80    	or     $0x80000800,%ecx
ffffffff8adf8ecd:	41 89 8e e4 00 00 00 	mov    %ecx,0xe4(%r14)
ffffffff8adf8ed4:	41 83 be 00 04 00 00 	cmpl   $0x4,0x400(%r14)
ffffffff8adf8edb:	04 
ffffffff8adf8edc:	75 08                	jne    ffffffff8adf8ee6 <handler_632_body+0xb6>
ffffffff8adf8ede:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf8ee1:	e8 ea a6 6c 00       	call   ffffffff8b4c35d0 <frame_candidate_43a930+0x6c8ca0>
ffffffff8adf8ee6:	4d 8d 6e 08          	lea    0x8(%r14),%r13
ffffffff8adf8eea:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
ffffffff8adf8ef0:	41 8b 86 00 04 00 00 	mov    0x400(%r14),%eax
ffffffff8adf8ef7:	83 c0 fd             	add    $0xfffffffd,%eax
ffffffff8adf8efa:	83 f8 02             	cmp    $0x2,%eax
ffffffff8adf8efd:	72 0e                	jb     ffffffff8adf8f0d <handler_632_body+0xdd>
ffffffff8adf8eff:	41 f6 86 e8 00 00 00 	testb  $0x8,0xe8(%r14)
ffffffff8adf8f06:	08 
ffffffff8adf8f07:	0f 84 bf 00 00 00    	je     ffffffff8adf8fcc <handler_632_body+0x19c>
ffffffff8adf8f0d:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf8f10:	31 f6                	xor    %esi,%esi
ffffffff8adf8f12:	31 d2                	xor    %edx,%edx
ffffffff8adf8f14:	31 c9                	xor    %ecx,%ecx
ffffffff8adf8f16:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf8f1a:	e8 01 e6 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf8f1f:	49 8b 7e 08          	mov    0x8(%r14),%rdi
ffffffff8adf8f23:	b8 48 01 00 00       	mov    $0x148,%eax
ffffffff8adf8f28:	31 f6                	xor    %esi,%esi
ffffffff8adf8f2a:	31 d2                	xor    %edx,%edx
ffffffff8adf8f2c:	31 c9                	xor    %ecx,%ecx
ffffffff8adf8f2e:	48 01 c7             	add    %rax,%rdi
ffffffff8adf8f31:	e8 6a e0 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf8f36:	48 8b 35 93 74 4e 03 	mov    0x34e7493(%rip),%rsi        # ffffffff8e2e03d0 <frame_candidate_43a930+0x34e5aa0>
ffffffff8adf8f3d:	48 8d 3d 88 b7 e7 00 	lea    0xe7b788(%rip),%rdi        # ffffffff8bc746cc <frame_candidate_43a930+0xe79d9c>
ffffffff8adf8f44:	b9 00 01 00 00       	mov    $0x100,%ecx
ffffffff8adf8f49:	31 d2                	xor    %edx,%edx
ffffffff8adf8f4b:	e8 e0 d8 7c 00       	call   ffffffff8b5c6830 <frame_candidate_43a930+0x7cbf00>
ffffffff8adf8f50:	49 8b 44 24 08       	mov    0x8(%r12),%rax
ffffffff8adf8f55:	41 8b 3f             	mov    (%r15),%edi
ffffffff8adf8f58:	8b b0 bc 00 00 00    	mov    0xbc(%rax),%esi
ffffffff8adf8f5e:	e8 bd 94 75 00       	call   ffffffff8b552420 <frame_candidate_43a930+0x757af0>
ffffffff8adf8f63:	48 85 c0             	test   %rax,%rax
ffffffff8adf8f66:	0f 84 a8 00 00 00    	je     ffffffff8adf9014 <handler_632_body+0x1e4>
ffffffff8adf8f6c:	49 39 c6             	cmp    %rax,%r14
ffffffff8adf8f6f:	0f 85 df 00 00 00    	jne    ffffffff8adf9054 <handler_632_body+0x224>
ffffffff8adf8f75:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf8f78:	48 8d 15 88 8b ed 00 	lea    0xed8b88(%rip),%rdx        # ffffffff8bcd1b07 <frame_candidate_43a930+0xed71d7>
ffffffff8adf8f7f:	b9 4f 03 00 00       	mov    $0x34f,%ecx
ffffffff8adf8f84:	31 f6                	xor    %esi,%esi
ffffffff8adf8f86:	e8 25 e9 08 00       	call   ffffffff8ae878b0 <frame_candidate_43a930+0x8cf80>
ffffffff8adf8f8b:	41 8b 86 e8 00 00 00 	mov    0xe8(%r14),%eax
ffffffff8adf8f92:	a8 02                	test   $0x2,%al
ffffffff8adf8f94:	0f 84 56 ff ff ff    	je     ffffffff8adf8ef0 <handler_632_body+0xc0>
ffffffff8adf8f9a:	41 8b 8e e4 00 00 00 	mov    0xe4(%r14),%ecx
ffffffff8adf8fa1:	f6 c1 08             	test   $0x8,%cl
ffffffff8adf8fa4:	0f 84 46 ff ff ff    	je     ffffffff8adf8ef0 <handler_632_body+0xc0>
ffffffff8adf8faa:	81 e1 ff f7 ff 7f    	and    $0x7ffff7ff,%ecx
ffffffff8adf8fb0:	83 c8 20             	or     $0x20,%eax
ffffffff8adf8fb3:	41 89 8e e4 00 00 00 	mov    %ecx,0xe4(%r14)
ffffffff8adf8fba:	41 c7 86 00 04 00 00 	movl   $0x1,0x400(%r14)
ffffffff8adf8fc1:	01 00 00 00 
ffffffff8adf8fc5:	41 89 86 e8 00 00 00 	mov    %eax,0xe8(%r14)
ffffffff8adf8fcc:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf8fcf:	31 db                	xor    %ebx,%ebx
ffffffff8adf8fd1:	31 f6                	xor    %esi,%esi
ffffffff8adf8fd3:	31 d2                	xor    %edx,%edx
ffffffff8adf8fd5:	31 c9                	xor    %ecx,%ecx
ffffffff8adf8fd7:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf8fdb:	e8 40 e5 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf8fe0:	eb 1e                	jmp    ffffffff8adf9000 <handler_632_body+0x1d0>
ffffffff8adf8fe2:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf8fe5:	31 f6                	xor    %esi,%esi
ffffffff8adf8fe7:	31 d2                	xor    %edx,%edx
ffffffff8adf8fe9:	31 c9                	xor    %ecx,%ecx
ffffffff8adf8feb:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf8fef:	e8 2c e5 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf8ff4:	49 83 c6 08          	add    $0x8,%r14
ffffffff8adf8ff8:	bb 16 00 00 00       	mov    $0x16,%ebx
ffffffff8adf8ffd:	4d 89 f5             	mov    %r14,%r13
ffffffff8adf9000:	bf 48 01 00 00       	mov    $0x148,%edi
ffffffff8adf9005:	49 03 7d 00          	add    0x0(%r13),%rdi
ffffffff8adf9009:	31 f6                	xor    %esi,%esi
ffffffff8adf900b:	31 d2                	xor    %edx,%edx
ffffffff8adf900d:	31 c9                	xor    %ecx,%ecx
ffffffff8adf900f:	e8 8c df 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf9014:	89 d8                	mov    %ebx,%eax
ffffffff8adf9016:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8adf901a:	5b                   	pop    %rbx
ffffffff8adf901b:	41 5c                	pop    %r12
ffffffff8adf901d:	41 5d                	pop    %r13
ffffffff8adf901f:	41 5e                	pop    %r14
ffffffff8adf9021:	41 5f                	pop    %r15
ffffffff8adf9023:	5d                   	pop    %rbp
ffffffff8adf9024:	c3                   	ret
ffffffff8adf9025:	83 c8 20             	or     $0x20,%eax
ffffffff8adf9028:	41 c7 86 00 04 00 00 	movl   $0x1,0x400(%r14)
ffffffff8adf902f:	01 00 00 00 
ffffffff8adf9033:	31 db                	xor    %ebx,%ebx
ffffffff8adf9035:	31 f6                	xor    %esi,%esi
ffffffff8adf9037:	31 d2                	xor    %edx,%edx
ffffffff8adf9039:	31 c9                	xor    %ecx,%ecx
ffffffff8adf903b:	41 89 86 e8 00 00 00 	mov    %eax,0xe8(%r14)
ffffffff8adf9042:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf9045:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf9049:	e8 d2 e4 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf904e:	49 83 c6 08          	add    $0x8,%r14
ffffffff8adf9052:	eb a9                	jmp    ffffffff8adf8ffd <handler_632_body+0x1cd>
ffffffff8adf9054:	48 83 c0 08          	add    $0x8,%rax
ffffffff8adf9058:	bb 03 00 00 00       	mov    $0x3,%ebx
ffffffff8adf905d:	49 89 c5             	mov    %rax,%r13
ffffffff8adf9060:	eb 9e                	jmp    ffffffff8adf9000 <handler_632_body+0x1d0>
ffffffff8adf9062:	90                   	nop
ffffffff8adf9063:	90                   	nop
ffffffff8adf9064:	90                   	nop
ffffffff8adf9065:	90                   	nop
ffffffff8adf9066:	90                   	nop
ffffffff8adf9067:	90                   	nop
ffffffff8adf9068:	90                   	nop
ffffffff8adf9069:	90                   	nop
ffffffff8adf906a:	90                   	nop
ffffffff8adf906b:	90                   	nop
ffffffff8adf906c:	90                   	nop
ffffffff8adf906d:	90                   	nop
ffffffff8adf906e:	90                   	nop
ffffffff8adf906f:	90                   	nop
ffffffff8adf9070:	48 89 f9             	mov    %rdi,%rcx
ffffffff8adf9073:	48 8b 3e             	mov    (%rsi),%rdi
ffffffff8adf9076:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8adf907b:	48 63 91 9c 00 00 00 	movslq 0x9c(%rcx),%rdx
ffffffff8adf9082:	48 39 d7             	cmp    %rdx,%rdi
ffffffff8adf9085:	0f 84 b7 00 00 00    	je     ffffffff8adf9142 <frame_candidate_43908b+0xb7>

ffffffff8adf908b <frame_candidate_43908b>:
ffffffff8adf908b:	55                   	push   %rbp
ffffffff8adf908c:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf908f:	41 56                	push   %r14
ffffffff8adf9091:	53                   	push   %rbx
ffffffff8adf9092:	48 8b 41 08          	mov    0x8(%rcx),%rax
ffffffff8adf9096:	8b b0 bc 00 00 00    	mov    0xbc(%rax),%esi
ffffffff8adf909c:	e8 7f 93 75 00       	call   ffffffff8b552420 <frame_candidate_43a930+0x757af0>
ffffffff8adf90a1:	48 85 c0             	test   %rax,%rax
ffffffff8adf90a4:	74 34                	je     ffffffff8adf90da <frame_candidate_43908b+0x4f>
ffffffff8adf90a6:	48 8d 15 5a 8a ed 00 	lea    0xed8a5a(%rip),%rdx        # ffffffff8bcd1b07 <frame_candidate_43a930+0xed71d7>
ffffffff8adf90ad:	48 89 c7             	mov    %rax,%rdi
ffffffff8adf90b0:	b9 6c 03 00 00       	mov    $0x36c,%ecx
ffffffff8adf90b5:	31 f6                	xor    %esi,%esi
ffffffff8adf90b7:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf90ba:	e8 f1 e7 08 00       	call   ffffffff8ae878b0 <frame_candidate_43a930+0x8cf80>
ffffffff8adf90bf:	8b 8b e4 00 00 00    	mov    0xe4(%rbx),%ecx
ffffffff8adf90c5:	8b 83 e8 00 00 00    	mov    0xe8(%rbx),%eax
ffffffff8adf90cb:	a8 20                	test   $0x20,%al
ffffffff8adf90cd:	75 12                	jne    ffffffff8adf90e1 <frame_candidate_43908b+0x56>
ffffffff8adf90cf:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8adf90d4:	85 c9                	test   %ecx,%ecx
ffffffff8adf90d6:	79 3a                	jns    ffffffff8adf9112 <frame_candidate_43908b+0x87>
ffffffff8adf90d8:	eb 2a                	jmp    ffffffff8adf9104 <frame_candidate_43908b+0x79>
ffffffff8adf90da:	b8 03 00 00 00       	mov    $0x3,%eax
ffffffff8adf90df:	eb 5d                	jmp    ffffffff8adf913e <frame_candidate_43908b+0xb3>
ffffffff8adf90e1:	85 c9                	test   %ecx,%ecx
ffffffff8adf90e3:	78 1f                	js     ffffffff8adf9104 <frame_candidate_43908b+0x79>
ffffffff8adf90e5:	83 e0 df             	and    $0xffffffdf,%eax
ffffffff8adf90e8:	89 83 e8 00 00 00    	mov    %eax,0xe8(%rbx)
ffffffff8adf90ee:	75 0a                	jne    ffffffff8adf90fa <frame_candidate_43908b+0x6f>
ffffffff8adf90f0:	c7 83 00 04 00 00 02 	movl   $0x2,0x400(%rbx)
ffffffff8adf90f7:	00 00 00 
ffffffff8adf90fa:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf90fd:	e8 1e da 7c 00       	call   ffffffff8b5c6b20 <frame_candidate_43a930+0x7cc1f0>
ffffffff8adf9102:	eb 0c                	jmp    ffffffff8adf9110 <frame_candidate_43908b+0x85>
ffffffff8adf9104:	81 e1 ff ff ff 7f    	and    $0x7fffffff,%ecx
ffffffff8adf910a:	89 8b e4 00 00 00    	mov    %ecx,0xe4(%rbx)
ffffffff8adf9110:	31 c0                	xor    %eax,%eax
ffffffff8adf9112:	48 8b 3b             	mov    (%rbx),%rdi
ffffffff8adf9115:	31 f6                	xor    %esi,%esi
ffffffff8adf9117:	31 d2                	xor    %edx,%edx
ffffffff8adf9119:	31 c9                	xor    %ecx,%ecx
ffffffff8adf911b:	41 89 c6             	mov    %eax,%r14d
ffffffff8adf911e:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf9122:	e8 f9 e3 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf9127:	bf 48 01 00 00       	mov    $0x148,%edi
ffffffff8adf912c:	48 03 7b 08          	add    0x8(%rbx),%rdi
ffffffff8adf9130:	31 f6                	xor    %esi,%esi
ffffffff8adf9132:	31 d2                	xor    %edx,%edx
ffffffff8adf9134:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9136:	e8 65 de 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf913b:	44 89 f0             	mov    %r14d,%eax
ffffffff8adf913e:	5b                   	pop    %rbx
ffffffff8adf913f:	41 5e                	pop    %r14
ffffffff8adf9141:	5d                   	pop    %rbp
ffffffff8adf9142:	c3                   	ret
ffffffff8adf9143:	90                   	nop
ffffffff8adf9144:	90                   	nop
ffffffff8adf9145:	90                   	nop
ffffffff8adf9146:	90                   	nop
ffffffff8adf9147:	90                   	nop
ffffffff8adf9148:	90                   	nop
ffffffff8adf9149:	90                   	nop
ffffffff8adf914a:	90                   	nop
ffffffff8adf914b:	90                   	nop
ffffffff8adf914c:	90                   	nop
ffffffff8adf914d:	90                   	nop
ffffffff8adf914e:	90                   	nop
ffffffff8adf914f:	90                   	nop

ffffffff8adf9150 <frame_candidate_439150>:
ffffffff8adf9150:	55                   	push   %rbp
ffffffff8adf9151:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf9154:	41 57                	push   %r15
ffffffff8adf9156:	41 56                	push   %r14
ffffffff8adf9158:	41 55                	push   %r13
ffffffff8adf915a:	41 54                	push   %r12
ffffffff8adf915c:	53                   	push   %rbx
ffffffff8adf915d:	48 81 ec 08 05 00 00 	sub    $0x508,%rsp
ffffffff8adf9164:	4c 8d 3d a5 31 4e 03 	lea    0x34e31a5(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adf916b:	49 89 fc             	mov    %rdi,%r12
ffffffff8adf916e:	48 89 f3             	mov    %rsi,%rbx
ffffffff8adf9171:	49 8b 07             	mov    (%r15),%rax
ffffffff8adf9174:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8adf9178:	49 8b 44 24 08       	mov    0x8(%r12),%rax
ffffffff8adf917d:	8b 3e                	mov    (%rsi),%edi
ffffffff8adf917f:	8b b0 bc 00 00 00    	mov    0xbc(%rax),%esi
ffffffff8adf9185:	e8 96 92 75 00       	call   ffffffff8b552420 <frame_candidate_43a930+0x757af0>
ffffffff8adf918a:	49 89 c6             	mov    %rax,%r14
ffffffff8adf918d:	b8 03 00 00 00       	mov    $0x3,%eax
ffffffff8adf9192:	4d 85 f6             	test   %r14,%r14
ffffffff8adf9195:	0f 84 a6 01 00 00    	je     ffffffff8adf9341 <frame_candidate_439150+0x1f1>
ffffffff8adf919b:	4c 8d 2d 65 89 ed 00 	lea    0xed8965(%rip),%r13        # ffffffff8bcd1b07 <frame_candidate_43a930+0xed71d7>
ffffffff8adf91a2:	4c 8d 3d 23 b5 e7 00 	lea    0xe7b523(%rip),%r15        # ffffffff8bc746cc <frame_candidate_43a930+0xe79d9c>
ffffffff8adf91a9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8adf91b0:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf91b3:	4c 89 ea             	mov    %r13,%rdx
ffffffff8adf91b6:	b9 90 03 00 00       	mov    $0x390,%ecx
ffffffff8adf91bb:	31 f6                	xor    %esi,%esi
ffffffff8adf91bd:	e8 ee e6 08 00       	call   ffffffff8ae878b0 <frame_candidate_43a930+0x8cf80>
ffffffff8adf91c2:	41 f6 84 24 29 05 00 	testb  $0x1,0x529(%r12)
ffffffff8adf91c9:	00 01 
ffffffff8adf91cb:	75 18                	jne    ffffffff8adf91e5 <frame_candidate_439150+0x95>
ffffffff8adf91cd:	41 f6 86 e8 00 00 00 	testb  $0x20,0xe8(%r14)
ffffffff8adf91d4:	20 
ffffffff8adf91d5:	75 0e                	jne    ffffffff8adf91e5 <frame_candidate_439150+0x95>
ffffffff8adf91d7:	41 83 be e4 00 00 00 	cmpl   $0x0,0xe4(%r14)
ffffffff8adf91de:	00 
ffffffff8adf91df:	0f 89 2a 01 00 00    	jns    ffffffff8adf930f <frame_candidate_439150+0x1bf>
ffffffff8adf91e5:	41 8b 86 00 04 00 00 	mov    0x400(%r14),%eax
ffffffff8adf91ec:	8d 48 fe             	lea    -0x2(%rax),%ecx
ffffffff8adf91ef:	83 f9 03             	cmp    $0x3,%ecx
ffffffff8adf91f2:	73 5f                	jae    ffffffff8adf9253 <frame_candidate_439150+0x103>
ffffffff8adf91f4:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf91f7:	31 f6                	xor    %esi,%esi
ffffffff8adf91f9:	31 d2                	xor    %edx,%edx
ffffffff8adf91fb:	31 c9                	xor    %ecx,%ecx
ffffffff8adf91fd:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf9201:	e8 1a e3 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf9206:	49 8b 7e 08          	mov    0x8(%r14),%rdi
ffffffff8adf920a:	b8 48 01 00 00       	mov    $0x148,%eax
ffffffff8adf920f:	31 f6                	xor    %esi,%esi
ffffffff8adf9211:	31 d2                	xor    %edx,%edx
ffffffff8adf9213:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9215:	48 01 c7             	add    %rax,%rdi
ffffffff8adf9218:	e8 83 dd 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf921d:	48 8b 35 ac 71 4e 03 	mov    0x34e71ac(%rip),%rsi        # ffffffff8e2e03d0 <frame_candidate_43a930+0x34e5aa0>
ffffffff8adf9224:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf9227:	b9 00 01 00 00       	mov    $0x100,%ecx
ffffffff8adf922c:	31 d2                	xor    %edx,%edx
ffffffff8adf922e:	e8 fd d5 7c 00       	call   ffffffff8b5c6830 <frame_candidate_43a930+0x7cbf00>
ffffffff8adf9233:	49 8b 44 24 08       	mov    0x8(%r12),%rax
ffffffff8adf9238:	8b 3b                	mov    (%rbx),%edi
ffffffff8adf923a:	8b b0 bc 00 00 00    	mov    0xbc(%rax),%esi
ffffffff8adf9240:	e8 db 91 75 00       	call   ffffffff8b552420 <frame_candidate_43a930+0x757af0>
ffffffff8adf9245:	49 89 c6             	mov    %rax,%r14
ffffffff8adf9248:	48 85 c0             	test   %rax,%rax
ffffffff8adf924b:	0f 85 5f ff ff ff    	jne    ffffffff8adf91b0 <frame_candidate_439150+0x60>
ffffffff8adf9251:	eb 33                	jmp    ffffffff8adf9286 <frame_candidate_439150+0x136>
ffffffff8adf9253:	83 f8 01             	cmp    $0x1,%eax
ffffffff8adf9256:	74 3f                	je     ffffffff8adf9297 <frame_candidate_439150+0x147>
ffffffff8adf9258:	85 c0                	test   %eax,%eax
ffffffff8adf925a:	0f 85 fc 00 00 00    	jne    ffffffff8adf935c <frame_candidate_439150+0x20c>
ffffffff8adf9260:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf9263:	31 f6                	xor    %esi,%esi
ffffffff8adf9265:	31 d2                	xor    %edx,%edx
ffffffff8adf9267:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9269:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf926d:	e8 ae e2 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf9272:	bf 48 01 00 00       	mov    $0x148,%edi
ffffffff8adf9277:	49 03 7e 08          	add    0x8(%r14),%rdi
ffffffff8adf927b:	31 f6                	xor    %esi,%esi
ffffffff8adf927d:	31 d2                	xor    %edx,%edx
ffffffff8adf927f:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9281:	e8 1a dd 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf9286:	4c 8d 3d 83 30 4e 03 	lea    0x34e3083(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adf928d:	b8 03 00 00 00       	mov    $0x3,%eax
ffffffff8adf9292:	e9 aa 00 00 00       	jmp    ffffffff8adf9341 <frame_candidate_439150+0x1f1>
ffffffff8adf9297:	4c 8d bd d0 fa ff ff 	lea    -0x530(%rbp),%r15
ffffffff8adf929e:	be 00 05 00 00       	mov    $0x500,%esi
ffffffff8adf92a3:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf92a6:	e8 45 fd e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf92ab:	48 8d b5 10 fb ff ff 	lea    -0x4f0(%rbp),%rsi
ffffffff8adf92b2:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf92b5:	31 d2                	xor    %edx,%edx
ffffffff8adf92b7:	e8 a4 28 5d 00       	call   ffffffff8b3cbb60 <frame_candidate_43a930+0x5d1230>
ffffffff8adf92bc:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf92bf:	31 f6                	xor    %esi,%esi
ffffffff8adf92c1:	31 d2                	xor    %edx,%edx
ffffffff8adf92c3:	31 c9                	xor    %ecx,%ecx
ffffffff8adf92c5:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf92c9:	e8 52 e2 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf92ce:	bf 48 01 00 00       	mov    $0x148,%edi
ffffffff8adf92d3:	49 03 7e 08          	add    0x8(%r14),%rdi
ffffffff8adf92d7:	31 f6                	xor    %esi,%esi
ffffffff8adf92d9:	31 d2                	xor    %edx,%edx
ffffffff8adf92db:	31 c9                	xor    %ecx,%ecx
ffffffff8adf92dd:	e8 be dc 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf92e2:	48 8b 5b 08          	mov    0x8(%rbx),%rbx
ffffffff8adf92e6:	65 48 8b 3c 25 00 00 	mov    %gs:0x0,%rdi
ffffffff8adf92ed:	00 00 
ffffffff8adf92ef:	48 8d 35 a1 5f f1 00 	lea    0xf15fa1(%rip),%rsi        # ffffffff8bd0f297 <frame_candidate_43a930+0xf14967>
ffffffff8adf92f6:	31 d2                	xor    %edx,%edx
ffffffff8adf92f8:	e8 e3 10 7e 00       	call   ffffffff8b5da3e0 <frame_candidate_43a930+0x7dfab0>
ffffffff8adf92fd:	ba c0 04 00 00       	mov    $0x4c0,%edx
ffffffff8adf9302:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf9305:	48 89 de             	mov    %rbx,%rsi
ffffffff8adf9308:	e8 c3 fe e1 ff       	call   ffffffff8ac191d0 <handler_632_body-0x1dfc60>
ffffffff8adf930d:	eb 2b                	jmp    ffffffff8adf933a <frame_candidate_439150+0x1ea>
ffffffff8adf930f:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adf9312:	31 f6                	xor    %esi,%esi
ffffffff8adf9314:	31 d2                	xor    %edx,%edx
ffffffff8adf9316:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9318:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf931c:	e8 ff e1 08 00       	call   ffffffff8ae87520 <frame_candidate_43a930+0x8cbf0>
ffffffff8adf9321:	bf 48 01 00 00       	mov    $0x148,%edi
ffffffff8adf9326:	49 03 7e 08          	add    0x8(%r14),%rdi
ffffffff8adf932a:	31 f6                	xor    %esi,%esi
ffffffff8adf932c:	31 d2                	xor    %edx,%edx
ffffffff8adf932e:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9330:	e8 6b dc 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf9335:	b8 16 00 00 00       	mov    $0x16,%eax
ffffffff8adf933a:	4c 8d 3d cf 2f 4e 03 	lea    0x34e2fcf(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adf9341:	49 8b 0f             	mov    (%r15),%rcx
ffffffff8adf9344:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8adf9348:	75 46                	jne    ffffffff8adf9390 <frame_candidate_439150+0x240>
ffffffff8adf934a:	48 81 c4 08 05 00 00 	add    $0x508,%rsp
ffffffff8adf9351:	5b                   	pop    %rbx
ffffffff8adf9352:	41 5c                	pop    %r12
ffffffff8adf9354:	41 5d                	pop    %r13
ffffffff8adf9356:	41 5e                	pop    %r14
ffffffff8adf9358:	41 5f                	pop    %r15
ffffffff8adf935a:	5d                   	pop    %rbp
ffffffff8adf935b:	c3                   	ret
ffffffff8adf935c:	e8 ef 85 3b 00       	call   ffffffff8b1b1950 <frame_candidate_43a930+0x3b7020>
ffffffff8adf9361:	41 8b b6 00 04 00 00 	mov    0x400(%r14),%esi
ffffffff8adf9368:	48 8d 3d ed ff ff ff 	lea    -0x13(%rip),%rdi        # ffffffff8adf935c <frame_candidate_439150+0x20c>
ffffffff8adf936f:	e8 2c 85 3b 00       	call   ffffffff8b1b18a0 <frame_candidate_43a930+0x3b6f70>
ffffffff8adf9374:	41 8b 96 00 04 00 00 	mov    0x400(%r14),%edx
ffffffff8adf937b:	48 8d 35 ed de ec 00 	lea    0xecdeed(%rip),%rsi        # ffffffff8bcc726f <frame_candidate_43a930+0xecc93f>
ffffffff8adf9382:	bf 03 00 00 00       	mov    $0x3,%edi
ffffffff8adf9387:	31 c0                	xor    %eax,%eax
ffffffff8adf9389:	e8 82 16 86 00       	call   ffffffff8b65aa10 <frame_candidate_43a930+0x8600e0>
ffffffff8adf938e:	0f 0b                	ud2
ffffffff8adf9390:	e8 1b 43 2c 00       	call   ffffffff8b0bd6b0 <frame_candidate_43a930+0x2c2d80>
ffffffff8adf9395:	0f 0b                	ud2
ffffffff8adf9397:	90                   	nop
ffffffff8adf9398:	90                   	nop
ffffffff8adf9399:	90                   	nop
ffffffff8adf939a:	90                   	nop
ffffffff8adf939b:	90                   	nop
ffffffff8adf939c:	90                   	nop
ffffffff8adf939d:	90                   	nop
ffffffff8adf939e:	90                   	nop
ffffffff8adf939f:	90                   	nop

ffffffff8adf93a0 <frame_candidate_4393a0>:
ffffffff8adf93a0:	55                   	push   %rbp
ffffffff8adf93a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf93a4:	b8 4e 00 00 00       	mov    $0x4e,%eax
ffffffff8adf93a9:	5d                   	pop    %rbp
ffffffff8adf93aa:	c3                   	ret
ffffffff8adf93ab:	90                   	nop
ffffffff8adf93ac:	90                   	nop
ffffffff8adf93ad:	90                   	nop
ffffffff8adf93ae:	90                   	nop
ffffffff8adf93af:	90                   	nop

ffffffff8adf93b0 <frame_candidate_4393b0>:
ffffffff8adf93b0:	55                   	push   %rbp
ffffffff8adf93b1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf93b4:	41 57                	push   %r15
ffffffff8adf93b6:	41 56                	push   %r14
ffffffff8adf93b8:	41 55                	push   %r13
ffffffff8adf93ba:	41 54                	push   %r12
ffffffff8adf93bc:	53                   	push   %rbx
ffffffff8adf93bd:	50                   	push   %rax
ffffffff8adf93be:	48 85 ff             	test   %rdi,%rdi
ffffffff8adf93c1:	0f 84 92 00 00 00    	je     ffffffff8adf9459 <frame_candidate_4393b0+0xa9>
ffffffff8adf93c7:	44 8b 27             	mov    (%rdi),%r12d
ffffffff8adf93ca:	31 db                	xor    %ebx,%ebx
ffffffff8adf93cc:	45 85 e4             	test   %r12d,%r12d
ffffffff8adf93cf:	0f 8e 8e 00 00 00    	jle    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf93d5:	48 8b 47 10          	mov    0x10(%rdi),%rax
ffffffff8adf93d9:	a8 08                	test   $0x8,%al
ffffffff8adf93db:	0f 85 7d 00 00 00    	jne    ffffffff8adf945e <frame_candidate_4393b0+0xae>
ffffffff8adf93e1:	48 8b 47 08          	mov    0x8(%rdi),%rax
ffffffff8adf93e5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8adf93ec:	00 00 00 00 
ffffffff8adf93f0:	44 89 e1             	mov    %r12d,%ecx
ffffffff8adf93f3:	80 7c 08 ff 00       	cmpb   $0x0,-0x1(%rax,%rcx,1)
ffffffff8adf93f8:	75 11                	jne    ffffffff8adf940b <frame_candidate_4393b0+0x5b>
ffffffff8adf93fa:	41 8d 4c 24 ff       	lea    -0x1(%r12),%ecx
ffffffff8adf93ff:	41 83 fc 01          	cmp    $0x1,%r12d
ffffffff8adf9403:	41 89 cc             	mov    %ecx,%r12d
ffffffff8adf9406:	7f e8                	jg     ffffffff8adf93f0 <frame_candidate_4393b0+0x40>
ffffffff8adf9408:	45 31 e4             	xor    %r12d,%r12d
ffffffff8adf940b:	44 89 e1             	mov    %r12d,%ecx
ffffffff8adf940e:	0f b6 44 08 ff       	movzbl -0x1(%rax,%rcx,1),%eax
ffffffff8adf9413:	a8 01                	test   $0x1,%al
ffffffff8adf9415:	75 4c                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf9417:	bb 01 00 00 00       	mov    $0x1,%ebx
ffffffff8adf941c:	a8 02                	test   $0x2,%al
ffffffff8adf941e:	75 43                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf9420:	bb 02 00 00 00       	mov    $0x2,%ebx
ffffffff8adf9425:	a8 04                	test   $0x4,%al
ffffffff8adf9427:	75 3a                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf9429:	bb 03 00 00 00       	mov    $0x3,%ebx
ffffffff8adf942e:	a8 08                	test   $0x8,%al
ffffffff8adf9430:	75 31                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf9432:	bb 04 00 00 00       	mov    $0x4,%ebx
ffffffff8adf9437:	a8 10                	test   $0x10,%al
ffffffff8adf9439:	75 28                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf943b:	bb 05 00 00 00       	mov    $0x5,%ebx
ffffffff8adf9440:	a8 20                	test   $0x20,%al
ffffffff8adf9442:	75 1f                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf9444:	bb 06 00 00 00       	mov    $0x6,%ebx
ffffffff8adf9449:	a8 40                	test   $0x40,%al
ffffffff8adf944b:	75 16                	jne    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf944d:	85 c0                	test   %eax,%eax
ffffffff8adf944f:	bb 07 00 00 00       	mov    $0x7,%ebx
ffffffff8adf9454:	0f 44 d8             	cmove  %eax,%ebx
ffffffff8adf9457:	eb 0a                	jmp    ffffffff8adf9463 <frame_candidate_4393b0+0xb3>
ffffffff8adf9459:	45 31 f6             	xor    %r14d,%r14d
ffffffff8adf945c:	eb 4e                	jmp    ffffffff8adf94ac <frame_candidate_4393b0+0xfc>
ffffffff8adf945e:	83 e0 07             	and    $0x7,%eax
ffffffff8adf9461:	89 c3                	mov    %eax,%ebx
ffffffff8adf9463:	45 8d 74 24 01       	lea    0x1(%r12),%r14d
ffffffff8adf9468:	48 85 f6             	test   %rsi,%rsi
ffffffff8adf946b:	74 3f                	je     ffffffff8adf94ac <frame_candidate_4393b0+0xfc>
ffffffff8adf946d:	4c 8b 2e             	mov    (%rsi),%r13
ffffffff8adf9470:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
ffffffff8adf9474:	4d 63 fc             	movslq %r12d,%r15
ffffffff8adf9477:	4c 89 fa             	mov    %r15,%rdx
ffffffff8adf947a:	41 88 5d 00          	mov    %bl,0x0(%r13)
ffffffff8adf947e:	49 8d 45 01          	lea    0x1(%r13),%rax
ffffffff8adf9482:	48 8b 77 08          	mov    0x8(%rdi),%rsi
ffffffff8adf9486:	48 89 c7             	mov    %rax,%rdi
ffffffff8adf9489:	e8 22 fc e1 ff       	call   ffffffff8ac190b0 <handler_632_body-0x1dfd80>
ffffffff8adf948e:	4b 8d 44 3d 01       	lea    0x1(%r13,%r15,1),%rax
ffffffff8adf9493:	45 85 e4             	test   %r12d,%r12d
ffffffff8adf9496:	7e 0d                	jle    ffffffff8adf94a5 <frame_candidate_4393b0+0xf5>
ffffffff8adf9498:	b9 ff 00 00 00       	mov    $0xff,%ecx
ffffffff8adf949d:	c4 e2 61 f7 c9       	shlx   %ebx,%ecx,%ecx
ffffffff8adf94a2:	20 48 ff             	and    %cl,-0x1(%rax)
ffffffff8adf94a5:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
ffffffff8adf94a9:	48 89 01             	mov    %rax,(%rcx)
ffffffff8adf94ac:	44 89 f0             	mov    %r14d,%eax
ffffffff8adf94af:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8adf94b3:	5b                   	pop    %rbx
ffffffff8adf94b4:	41 5c                	pop    %r12
ffffffff8adf94b6:	41 5d                	pop    %r13
ffffffff8adf94b8:	41 5e                	pop    %r14
ffffffff8adf94ba:	41 5f                	pop    %r15
ffffffff8adf94bc:	5d                   	pop    %rbp
ffffffff8adf94bd:	c3                   	ret
ffffffff8adf94be:	90                   	nop
ffffffff8adf94bf:	90                   	nop

ffffffff8adf94c0 <frame_candidate_4394c0>:
ffffffff8adf94c0:	55                   	push   %rbp
ffffffff8adf94c1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf94c4:	41 57                	push   %r15
ffffffff8adf94c6:	41 56                	push   %r14
ffffffff8adf94c8:	41 55                	push   %r13
ffffffff8adf94ca:	41 54                	push   %r12
ffffffff8adf94cc:	53                   	push   %rbx
ffffffff8adf94cd:	48 83 ec 28          	sub    $0x28,%rsp
ffffffff8adf94d1:	48 85 d2             	test   %rdx,%rdx
ffffffff8adf94d4:	7e 65                	jle    ffffffff8adf953b <frame_candidate_4394c0+0x7b>
ffffffff8adf94d6:	49 89 d4             	mov    %rdx,%r12
ffffffff8adf94d9:	49 89 f7             	mov    %rsi,%r15
ffffffff8adf94dc:	49 89 fe             	mov    %rdi,%r14
ffffffff8adf94df:	48 85 ff             	test   %rdi,%rdi
ffffffff8adf94e2:	74 08                	je     ffffffff8adf94ec <frame_candidate_4394c0+0x2c>
ffffffff8adf94e4:	49 8b 1e             	mov    (%r14),%rbx
ffffffff8adf94e7:	48 85 db             	test   %rbx,%rbx
ffffffff8adf94ea:	75 11                	jne    ffffffff8adf94fd <frame_candidate_4394c0+0x3d>
ffffffff8adf94ec:	e8 5f 9f 6f 00       	call   ffffffff8b4f3450 <frame_candidate_43a930+0x6f8b20>
ffffffff8adf94f1:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf94f4:	48 85 c0             	test   %rax,%rax
ffffffff8adf94f7:	0f 84 f2 00 00 00    	je     ffffffff8adf95ef <frame_candidate_4394c0+0x12f>
ffffffff8adf94fd:	4d 8b 2f             	mov    (%r15),%r13
ffffffff8adf9500:	4c 89 7d b8          	mov    %r15,-0x48(%rbp)
ffffffff8adf9504:	49 8d 45 01          	lea    0x1(%r13),%rax
ffffffff8adf9508:	41 0f b6 55 00       	movzbl 0x0(%r13),%edx
ffffffff8adf950d:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8adf9511:	48 8b 43 10          	mov    0x10(%rbx),%rax
ffffffff8adf9515:	89 d1                	mov    %edx,%ecx
ffffffff8adf9517:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
ffffffff8adf951b:	83 e1 07             	and    $0x7,%ecx
ffffffff8adf951e:	48 8d 44 01 08       	lea    0x8(%rcx,%rax,1),%rax
ffffffff8adf9523:	48 89 43 10          	mov    %rax,0x10(%rbx)
ffffffff8adf9527:	49 8d 44 24 ff       	lea    -0x1(%r12),%rax
ffffffff8adf952c:	49 83 fc 01          	cmp    $0x1,%r12
ffffffff8adf9530:	75 29                	jne    ffffffff8adf955b <frame_candidate_4394c0+0x9b>
ffffffff8adf9532:	4c 8b 6d c8          	mov    -0x38(%rbp),%r13
ffffffff8adf9536:	45 31 ff             	xor    %r15d,%r15d
ffffffff8adf9539:	eb 62                	jmp    ffffffff8adf959d <frame_candidate_4394c0+0xdd>
ffffffff8adf953b:	bf 0d 00 00 00       	mov    $0xd,%edi
ffffffff8adf9540:	be ff 0f 00 00       	mov    $0xfff,%esi
ffffffff8adf9545:	ba 98 00 00 00       	mov    $0x98,%edx
ffffffff8adf954a:	31 db                	xor    %ebx,%ebx
ffffffff8adf954c:	31 c9                	xor    %ecx,%ecx
ffffffff8adf954e:	45 31 c0             	xor    %r8d,%r8d
ffffffff8adf9551:	e8 ea 3d ea ff       	call   ffffffff8ac9d340 <handler_632_body-0x15baf0>
ffffffff8adf9556:	e9 96 00 00 00       	jmp    ffffffff8adf95f1 <frame_candidate_4394c0+0x131>
ffffffff8adf955b:	48 89 c7             	mov    %rax,%rdi
ffffffff8adf955e:	48 89 55 c0          	mov    %rdx,-0x40(%rbp)
ffffffff8adf9562:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8adf9566:	e8 55 03 56 00       	call   ffffffff8b3598c0 <frame_candidate_43a930+0x55ef90>
ffffffff8adf956b:	48 85 c0             	test   %rax,%rax
ffffffff8adf956e:	74 54                	je     ffffffff8adf95c4 <frame_candidate_4394c0+0x104>
ffffffff8adf9570:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
ffffffff8adf9574:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
ffffffff8adf9578:	48 89 c7             	mov    %rax,%rdi
ffffffff8adf957b:	49 89 c7             	mov    %rax,%r15
ffffffff8adf957e:	e8 2d fb e1 ff       	call   ffffffff8ac190b0 <handler_632_body-0x1dfd80>
ffffffff8adf9583:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
ffffffff8adf9587:	b8 ff 00 00 00       	mov    $0xff,%eax
ffffffff8adf958c:	4d 01 e5             	add    %r12,%r13
ffffffff8adf958f:	c4 e2 71 f7 c0       	shlx   %ecx,%eax,%eax
ffffffff8adf9594:	43 20 44 27 fe       	and    %al,-0x2(%r15,%r12,1)
ffffffff8adf9599:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
ffffffff8adf959d:	89 03                	mov    %eax,(%rbx)
ffffffff8adf959f:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
ffffffff8adf95a3:	e8 38 03 56 00       	call   ffffffff8b3598e0 <frame_candidate_43a930+0x55efb0>
ffffffff8adf95a8:	4c 89 7b 08          	mov    %r15,0x8(%rbx)
ffffffff8adf95ac:	c7 43 04 03 00 00 00 	movl   $0x3,0x4(%rbx)
ffffffff8adf95b3:	4d 85 f6             	test   %r14,%r14
ffffffff8adf95b6:	74 03                	je     ffffffff8adf95bb <frame_candidate_4394c0+0xfb>
ffffffff8adf95b8:	49 89 1e             	mov    %rbx,(%r14)
ffffffff8adf95bb:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
ffffffff8adf95bf:	4c 89 28             	mov    %r13,(%rax)
ffffffff8adf95c2:	eb 2d                	jmp    ffffffff8adf95f1 <frame_candidate_4394c0+0x131>
ffffffff8adf95c4:	bf 0d 00 00 00       	mov    $0xd,%edi
ffffffff8adf95c9:	be ff 0f 00 00       	mov    $0xfff,%esi
ffffffff8adf95ce:	ba 41 00 00 00       	mov    $0x41,%edx
ffffffff8adf95d3:	31 c9                	xor    %ecx,%ecx
ffffffff8adf95d5:	45 31 c0             	xor    %r8d,%r8d
ffffffff8adf95d8:	e8 63 3d ea ff       	call   ffffffff8ac9d340 <handler_632_body-0x15baf0>
ffffffff8adf95dd:	4d 85 f6             	test   %r14,%r14
ffffffff8adf95e0:	74 05                	je     ffffffff8adf95e7 <frame_candidate_4394c0+0x127>
ffffffff8adf95e2:	49 39 1e             	cmp    %rbx,(%r14)
ffffffff8adf95e5:	74 08                	je     ffffffff8adf95ef <frame_candidate_4394c0+0x12f>
ffffffff8adf95e7:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf95ea:	e8 81 9e 6f 00       	call   ffffffff8b4f3470 <frame_candidate_43a930+0x6f8b40>
ffffffff8adf95ef:	31 db                	xor    %ebx,%ebx
ffffffff8adf95f1:	48 89 d8             	mov    %rbx,%rax
ffffffff8adf95f4:	48 83 c4 28          	add    $0x28,%rsp
ffffffff8adf95f8:	5b                   	pop    %rbx
ffffffff8adf95f9:	41 5c                	pop    %r12
ffffffff8adf95fb:	41 5d                	pop    %r13
ffffffff8adf95fd:	41 5e                	pop    %r14
ffffffff8adf95ff:	41 5f                	pop    %r15
ffffffff8adf9601:	5d                   	pop    %rbp
ffffffff8adf9602:	c3                   	ret
ffffffff8adf9603:	90                   	nop
ffffffff8adf9604:	90                   	nop
ffffffff8adf9605:	90                   	nop
ffffffff8adf9606:	90                   	nop
ffffffff8adf9607:	90                   	nop
ffffffff8adf9608:	90                   	nop
ffffffff8adf9609:	90                   	nop
ffffffff8adf960a:	90                   	nop
ffffffff8adf960b:	90                   	nop
ffffffff8adf960c:	90                   	nop
ffffffff8adf960d:	90                   	nop
ffffffff8adf960e:	90                   	nop
ffffffff8adf960f:	90                   	nop

ffffffff8adf9610 <frame_candidate_439610>:
ffffffff8adf9610:	55                   	push   %rbp
ffffffff8adf9611:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf9614:	41 56                	push   %r14
ffffffff8adf9616:	53                   	push   %rbx
ffffffff8adf9617:	49 89 fe             	mov    %rdi,%r14
ffffffff8adf961a:	48 8b 7f 40          	mov    0x40(%rdi),%rdi
ffffffff8adf961e:	48 89 f3             	mov    %rsi,%rbx
ffffffff8adf9621:	31 f6                	xor    %esi,%esi
ffffffff8adf9623:	31 d2                	xor    %edx,%edx
ffffffff8adf9625:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9627:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf962b:	e8 d0 d3 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adf9630:	49 89 9e 70 01 00 00 	mov    %rbx,0x170(%r14)
ffffffff8adf9637:	31 f6                	xor    %esi,%esi
ffffffff8adf9639:	31 d2                	xor    %edx,%edx
ffffffff8adf963b:	31 c9                	xor    %ecx,%ecx
ffffffff8adf963d:	49 8b 7e 40          	mov    0x40(%r14),%rdi
ffffffff8adf9641:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf9645:	5b                   	pop    %rbx
ffffffff8adf9646:	41 5e                	pop    %r14
ffffffff8adf9648:	5d                   	pop    %rbp
ffffffff8adf9649:	e9 52 d9 08 00       	jmp    ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf964e:	90                   	nop
ffffffff8adf964f:	90                   	nop

ffffffff8adf9650 <frame_candidate_439650>:
ffffffff8adf9650:	55                   	push   %rbp
ffffffff8adf9651:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf9654:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8adf9659:	5d                   	pop    %rbp
ffffffff8adf965a:	e9 01 00 00 00       	jmp    ffffffff8adf9660 <frame_candidate_439660>
ffffffff8adf965f:	90                   	nop

ffffffff8adf9660 <frame_candidate_439660>:
ffffffff8adf9660:	55                   	push   %rbp
ffffffff8adf9661:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf9664:	41 56                	push   %r14
ffffffff8adf9666:	53                   	push   %rbx
ffffffff8adf9667:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8adf966b:	48 89 fb             	mov    %rdi,%rbx
ffffffff8adf966e:	48 8b 7f 40          	mov    0x40(%rdi),%rdi
ffffffff8adf9672:	41 89 f6             	mov    %esi,%r14d
ffffffff8adf9675:	31 f6                	xor    %esi,%esi
ffffffff8adf9677:	31 d2                	xor    %edx,%edx
ffffffff8adf9679:	31 c9                	xor    %ecx,%ecx
ffffffff8adf967b:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf967f:	e8 7c d3 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adf9684:	8b 83 c8 00 00 00    	mov    0xc8(%rbx),%eax
ffffffff8adf968a:	a9 00 00 00 08       	test   $0x8000000,%eax
ffffffff8adf968f:	74 51                	je     ffffffff8adf96e2 <frame_candidate_439660+0x82>
ffffffff8adf9691:	41 83 fe 01          	cmp    $0x1,%r14d
ffffffff8adf9695:	0f 84 b8 00 00 00    	je     ffffffff8adf9753 <frame_candidate_439660+0xf3>
ffffffff8adf969b:	4c 8d 35 83 7b e4 00 	lea    0xe47b83(%rip),%r14        # ffffffff8bc41225 <frame_candidate_43a930+0xe468f5>
ffffffff8adf96a2:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8adf96a9:	1f 84 00 00 00 00 00 
ffffffff8adf96b0:	48 8b 73 40          	mov    0x40(%rbx),%rsi
ffffffff8adf96b4:	4c 8b 05 15 6d 4e 03 	mov    0x34e6d15(%rip),%r8        # ffffffff8e2e03d0 <frame_candidate_43a930+0x34e5aa0>
ffffffff8adf96bb:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf96be:	ba 44 00 00 00       	mov    $0x44,%edx
ffffffff8adf96c3:	4c 89 f1             	mov    %r14,%rcx
ffffffff8adf96c6:	45 31 c9             	xor    %r9d,%r9d
ffffffff8adf96c9:	c7 04 24 00 01 00 00 	movl   $0x100,(%rsp)
ffffffff8adf96d0:	e8 8b cb 7c 00       	call   ffffffff8b5c6260 <frame_candidate_43a930+0x7cb930>
ffffffff8adf96d5:	8b 83 c8 00 00 00    	mov    0xc8(%rbx),%eax
ffffffff8adf96db:	a9 00 00 00 08       	test   $0x8000000,%eax
ffffffff8adf96e0:	75 ce                	jne    ffffffff8adf96b0 <frame_candidate_439660+0x50>
ffffffff8adf96e2:	0d 00 00 00 08       	or     $0x8000000,%eax
ffffffff8adf96e7:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf96ea:	89 83 c8 00 00 00    	mov    %eax,0xc8(%rbx)
ffffffff8adf96f0:	e8 ab 59 00 00       	call   ffffffff8adff0a0 <frame_candidate_43a930+0x4770>
ffffffff8adf96f5:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adf96f9:	31 f6                	xor    %esi,%esi
ffffffff8adf96fb:	31 d2                	xor    %edx,%edx
ffffffff8adf96fd:	31 c9                	xor    %ecx,%ecx
ffffffff8adf96ff:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf9703:	e8 98 d8 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf9708:	4c 8b 73 68          	mov    0x68(%rbx),%r14
ffffffff8adf970c:	4d 85 f6             	test   %r14,%r14
ffffffff8adf970f:	74 20                	je     ffffffff8adf9731 <frame_candidate_439660+0xd1>
ffffffff8adf9711:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8adf9718:	0f 1f 84 00 00 00 00 
ffffffff8adf971f:	00 
ffffffff8adf9720:	49 8b 7e 10          	mov    0x10(%r14),%rdi
ffffffff8adf9724:	e8 d7 5b 00 00       	call   ffffffff8adff300 <frame_candidate_43a930+0x49d0>
ffffffff8adf9729:	4d 8b 36             	mov    (%r14),%r14
ffffffff8adf972c:	4d 85 f6             	test   %r14,%r14
ffffffff8adf972f:	75 ef                	jne    ffffffff8adf9720 <frame_candidate_439660+0xc0>
ffffffff8adf9731:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adf9735:	31 f6                	xor    %esi,%esi
ffffffff8adf9737:	31 d2                	xor    %edx,%edx
ffffffff8adf9739:	31 c9                	xor    %ecx,%ecx
ffffffff8adf973b:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf973f:	e8 bc d2 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adf9744:	80 a3 cb 00 00 00 f7 	andb   $0xf7,0xcb(%rbx)
ffffffff8adf974b:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf974e:	e8 bd d1 7c 00       	call   ffffffff8b5c6910 <frame_candidate_43a930+0x7cbfe0>
ffffffff8adf9753:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adf9757:	31 f6                	xor    %esi,%esi
ffffffff8adf9759:	31 d2                	xor    %edx,%edx
ffffffff8adf975b:	31 c9                	xor    %ecx,%ecx
ffffffff8adf975d:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adf9761:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8adf9765:	5b                   	pop    %rbx
ffffffff8adf9766:	41 5e                	pop    %r14
ffffffff8adf9768:	5d                   	pop    %rbp
ffffffff8adf9769:	e9 32 d8 08 00       	jmp    ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adf976e:	90                   	nop
ffffffff8adf976f:	90                   	nop

ffffffff8adf9770 <frame_candidate_439770>:
ffffffff8adf9770:	55                   	push   %rbp
ffffffff8adf9771:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf9774:	41 57                	push   %r15
ffffffff8adf9776:	41 56                	push   %r14
ffffffff8adf9778:	41 55                	push   %r13
ffffffff8adf977a:	41 54                	push   %r12
ffffffff8adf977c:	53                   	push   %rbx
ffffffff8adf977d:	48 81 ec b8 00 00 00 	sub    $0xb8,%rsp
ffffffff8adf9784:	48 8d 05 85 2b 4e 03 	lea    0x34e2b85(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adf978b:	41 89 f6             	mov    %esi,%r14d
ffffffff8adf978e:	48 89 fb             	mov    %rdi,%rbx
ffffffff8adf9791:	48 8d 3d 80 0f 0c 03 	lea    0x30c0f80(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adf9798:	48 8d 35 7b b2 f6 00 	lea    0xf6b27b(%rip),%rsi        # ffffffff8bd64a1a <frame_candidate_43a930+0xf6a0ea>
ffffffff8adf979f:	31 d2                	xor    %edx,%edx
ffffffff8adf97a1:	48 8b 00             	mov    (%rax),%rax
ffffffff8adf97a4:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8adf97a8:	e8 83 ad 39 00       	call   ffffffff8b194530 <frame_candidate_43a930+0x399c00>
ffffffff8adf97ad:	4c 8d bd 20 ff ff ff 	lea    -0xe0(%rbp),%r15
ffffffff8adf97b4:	be 58 00 00 00       	mov    $0x58,%esi
ffffffff8adf97b9:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf97bc:	e8 2f f8 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf97c1:	48 8d 05 2d e8 ea 00 	lea    0xeae82d(%rip),%rax        # ffffffff8bca7ff5 <frame_candidate_43a930+0xead6c5>
ffffffff8adf97c8:	48 8d 3d 19 f5 e2 ff 	lea    -0x1d0ae7(%rip),%rdi        # ffffffff8ac28ce8 <handler_632_body-0x1d0148>
ffffffff8adf97cf:	48 8d 15 9a 55 e3 ff 	lea    -0x1caa66(%rip),%rdx        # ffffffff8ac2ed70 <handler_632_body-0x1ca0c0>
ffffffff8adf97d6:	4c 8d 25 83 d8 e2 ff 	lea    -0x1d277d(%rip),%r12        # ffffffff8ac27060 <handler_632_body-0x1d1dd0>
ffffffff8adf97dd:	49 bd 1f 00 00 00 00 	movabs $0x200004000000001f,%r13
ffffffff8adf97e4:	04 00 20 
ffffffff8adf97e7:	be c0 01 00 00       	mov    $0x1c0,%esi
ffffffff8adf97ec:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
ffffffff8adf97f3:	48 c7 85 28 ff ff ff 	movq   $0x100,-0xd8(%rbp)
ffffffff8adf97fa:	00 01 00 00 
ffffffff8adf97fe:	48 89 bd 30 ff ff ff 	mov    %rdi,-0xd0(%rbp)
ffffffff8adf9805:	48 89 95 38 ff ff ff 	mov    %rdx,-0xc8(%rbp)
ffffffff8adf980c:	48 8d 05 2d 0f 0c 03 	lea    0x30c0f2d(%rip),%rax        # ffffffff8deba740 <frame_candidate_43a930+0x30bfe10>
ffffffff8adf9813:	48 8d 3d 26 15 0c 03 	lea    0x30c1526(%rip),%rdi        # ffffffff8debad40 <frame_candidate_43a930+0x30c0410>
ffffffff8adf981a:	4c 89 fa             	mov    %r15,%rdx
ffffffff8adf981d:	4c 89 a5 40 ff ff ff 	mov    %r12,-0xc0(%rbp)
ffffffff8adf9824:	48 c7 85 48 ff ff ff 	movq   $0x0,-0xb8(%rbp)
ffffffff8adf982b:	00 00 00 00 
ffffffff8adf982f:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
ffffffff8adf9836:	4c 89 ad 70 ff ff ff 	mov    %r13,-0x90(%rbp)
ffffffff8adf983d:	e8 ee 0b 00 00       	call   ffffffff8adfa430 <frame_candidate_43a430>
ffffffff8adf9842:	45 85 f6             	test   %r14d,%r14d
ffffffff8adf9845:	7e 5d                	jle    ffffffff8adf98a4 <frame_candidate_439770+0x134>
ffffffff8adf9847:	44 89 f0             	mov    %r14d,%eax
ffffffff8adf984a:	48 8d 15 ef 0f 0c 03 	lea    0x30c0fef(%rip),%rdx        # ffffffff8deba840 <frame_candidate_43a930+0x30bff10>
ffffffff8adf9851:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9853:	48 c1 e0 0e          	shl    $0xe,%rax
ffffffff8adf9857:	eb 1e                	jmp    ffffffff8adf9877 <frame_candidate_439770+0x107>
ffffffff8adf9859:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
ffffffff8adf9860:	48 81 c1 00 40 00 00 	add    $0x4000,%rcx
ffffffff8adf9867:	48 89 35 d2 0f 0c 03 	mov    %rsi,0x30c0fd2(%rip)        # ffffffff8deba840 <frame_candidate_43a930+0x30bff10>
ffffffff8adf986e:	48 89 56 10          	mov    %rdx,0x10(%rsi)
ffffffff8adf9872:	48 39 c8             	cmp    %rcx,%rax
ffffffff8adf9875:	74 2d                	je     ffffffff8adf98a4 <frame_candidate_439770+0x134>
ffffffff8adf9877:	48 63 f9             	movslq %ecx,%rdi
ffffffff8adf987a:	48 8d 34 3b          	lea    (%rbx,%rdi,1),%rsi
ffffffff8adf987e:	48 89 74 3b 20       	mov    %rsi,0x20(%rbx,%rdi,1)
ffffffff8adf9883:	c6 44 3b 4a 01       	movb   $0x1,0x4a(%rbx,%rdi,1)
ffffffff8adf9888:	4c 8b 05 b1 0f 0c 03 	mov    0x30c0fb1(%rip),%r8        # ffffffff8deba840 <frame_candidate_43a930+0x30bff10>
ffffffff8adf988f:	4c 89 44 3b 08       	mov    %r8,0x8(%rbx,%rdi,1)
ffffffff8adf9894:	4d 85 c0             	test   %r8,%r8
ffffffff8adf9897:	74 c7                	je     ffffffff8adf9860 <frame_candidate_439770+0xf0>
ffffffff8adf9899:	48 8d 7c 3b 08       	lea    0x8(%rbx,%rdi,1),%rdi
ffffffff8adf989e:	49 89 78 10          	mov    %rdi,0x10(%r8)
ffffffff8adf98a2:	eb bc                	jmp    ffffffff8adf9860 <frame_candidate_439770+0xf0>
ffffffff8adf98a4:	48 8d 3d ed 0f 0c 03 	lea    0x30c0fed(%rip),%rdi        # ffffffff8deba898 <frame_candidate_43a930+0x30bff68>
ffffffff8adf98ab:	48 8d 35 2b c4 f0 00 	lea    0xf0c42b(%rip),%rsi        # ffffffff8bd05cdd <frame_candidate_43a930+0xf0b3ad>
ffffffff8adf98b2:	31 d2                	xor    %edx,%edx
ffffffff8adf98b4:	31 c9                	xor    %ecx,%ecx
ffffffff8adf98b6:	e8 15 e5 08 00       	call   ffffffff8ae87dd0 <frame_candidate_43a930+0x8d4a0>
ffffffff8adf98bb:	48 8d 05 e2 33 ec 00 	lea    0xec33e2(%rip),%rax        # ffffffff8bcbcca4 <frame_candidate_43a930+0xec2374>
ffffffff8adf98c2:	48 8d 15 27 f4 e2 ff 	lea    -0x1d0bd9(%rip),%rdx        # ffffffff8ac28cf0 <handler_632_body-0x1d0140>
ffffffff8adf98c9:	48 8d 3d 70 16 0c 03 	lea    0x30c1670(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf98d0:	be c0 01 00 00       	mov    $0x1c0,%esi
ffffffff8adf98d5:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
ffffffff8adf98dc:	8b 05 d6 4f 8d 03    	mov    0x38d4fd6(%rip),%eax        # ffffffff8e6ce8b8 <frame_candidate_43a930+0x38d3f88>
ffffffff8adf98e2:	ff c0                	inc    %eax
ffffffff8adf98e4:	48 c1 e0 06          	shl    $0x6,%rax
ffffffff8adf98e8:	48 05 c0 01 00 00    	add    $0x1c0,%rax
ffffffff8adf98ee:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
ffffffff8adf98f5:	48 89 95 30 ff ff ff 	mov    %rdx,-0xd0(%rbp)
ffffffff8adf98fc:	48 8d 05 75 54 e3 ff 	lea    -0x1cab8b(%rip),%rax        # ffffffff8ac2ed78 <handler_632_body-0x1ca0b8>
ffffffff8adf9903:	48 8d 95 20 ff ff ff 	lea    -0xe0(%rbp),%rdx
ffffffff8adf990a:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
ffffffff8adf9911:	4c 89 a5 40 ff ff ff 	mov    %r12,-0xc0(%rbp)
ffffffff8adf9918:	48 c7 85 48 ff ff ff 	movq   $0x0,-0xb8(%rbp)
ffffffff8adf991f:	00 00 00 00 
ffffffff8adf9923:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
ffffffff8adf992a:	00 00 00 00 
ffffffff8adf992e:	4c 89 ad 70 ff ff ff 	mov    %r13,-0x90(%rbp)
ffffffff8adf9935:	e8 f6 0a 00 00       	call   ffffffff8adfa430 <frame_candidate_43a430>
ffffffff8adf993a:	48 8d bd 78 ff ff ff 	lea    -0x88(%rbp),%rdi
ffffffff8adf9941:	be 58 00 00 00       	mov    $0x58,%esi
ffffffff8adf9946:	e8 a5 f6 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf994b:	83 3d a2 0d 0c 03 01 	cmpl   $0x1,0x30c0da2(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adf9952:	48 8d 05 9e 5e f7 00 	lea    0xf75e9e(%rip),%rax        # ffffffff8bd6f7f7 <frame_candidate_43a930+0xf74ec7>
ffffffff8adf9959:	49 bf 07 00 00 00 00 	movabs $0x2000040000000007,%r15
ffffffff8adf9960:	04 00 20 
ffffffff8adf9963:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
ffffffff8adf996a:	48 c7 45 80 50 00 00 	movq   $0x50,-0x80(%rbp)
ffffffff8adf9971:	00 
ffffffff8adf9972:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8adf9979:	00 
ffffffff8adf997a:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8adf9981:	00 
ffffffff8adf9982:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8adf9989:	00 
ffffffff8adf998a:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8adf9991:	00 
ffffffff8adf9992:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
ffffffff8adf9996:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8adf999d:	00 
ffffffff8adf999e:	7e 3e                	jle    ffffffff8adf99de <frame_candidate_439770+0x26e>
ffffffff8adf99a0:	4c 8d 35 29 0f 0c 03 	lea    0x30c0f29(%rip),%r14        # ffffffff8deba8d0 <frame_candidate_43a930+0x30bffa0>
ffffffff8adf99a7:	31 f6                	xor    %esi,%esi
ffffffff8adf99a9:	31 d2                	xor    %edx,%edx
ffffffff8adf99ab:	31 c9                	xor    %ecx,%ecx
ffffffff8adf99ad:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf99b0:	e8 9b 19 81 00       	call   ffffffff8b60b350 <frame_candidate_43a930+0x810a20>
ffffffff8adf99b5:	48 8d 3d 84 15 0c 03 	lea    0x30c1584(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf99bc:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8adf99c3:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf99c8:	e8 93 18 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf99cd:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf99d0:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf99d3:	31 f6                	xor    %esi,%esi
ffffffff8adf99d5:	31 d2                	xor    %edx,%edx
ffffffff8adf99d7:	e8 24 29 81 00       	call   ffffffff8b60c300 <frame_candidate_43a930+0x8119d0>
ffffffff8adf99dc:	eb 1b                	jmp    ffffffff8adf99f9 <frame_candidate_439770+0x289>
ffffffff8adf99de:	48 8d 3d 5b 15 0c 03 	lea    0x30c155b(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf99e5:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8adf99ec:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf99f1:	e8 6a 18 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf99f6:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf99f9:	48 8d bd 78 ff ff ff 	lea    -0x88(%rbp),%rdi
ffffffff8adf9a00:	be 58 00 00 00       	mov    $0x58,%esi
ffffffff8adf9a05:	48 89 1d b4 0e 0c 03 	mov    %rbx,0x30c0eb4(%rip)        # ffffffff8deba8c0 <frame_candidate_43a930+0x30bff90>
ffffffff8adf9a0c:	e8 df f5 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf9a11:	83 3d dc 0c 0c 03 01 	cmpl   $0x1,0x30c0cdc(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adf9a18:	48 8d 05 cd c2 f0 00 	lea    0xf0c2cd(%rip),%rax        # ffffffff8bd05cec <frame_candidate_43a930+0xf0b3bc>
ffffffff8adf9a1f:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
ffffffff8adf9a26:	48 c7 45 80 00 01 00 	movq   $0x100,-0x80(%rbp)
ffffffff8adf9a2d:	00 
ffffffff8adf9a2e:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8adf9a35:	00 
ffffffff8adf9a36:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8adf9a3d:	00 
ffffffff8adf9a3e:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8adf9a45:	00 
ffffffff8adf9a46:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8adf9a4d:	00 
ffffffff8adf9a4e:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
ffffffff8adf9a52:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8adf9a59:	00 
ffffffff8adf9a5a:	7e 3e                	jle    ffffffff8adf9a9a <frame_candidate_439770+0x32a>
ffffffff8adf9a5c:	4c 8d 35 6d 0e 0c 03 	lea    0x30c0e6d(%rip),%r14        # ffffffff8deba8d0 <frame_candidate_43a930+0x30bffa0>
ffffffff8adf9a63:	31 f6                	xor    %esi,%esi
ffffffff8adf9a65:	31 d2                	xor    %edx,%edx
ffffffff8adf9a67:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9a69:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9a6c:	e8 df 18 81 00       	call   ffffffff8b60b350 <frame_candidate_43a930+0x810a20>
ffffffff8adf9a71:	48 8d 3d c8 14 0c 03 	lea    0x30c14c8(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf9a78:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8adf9a7f:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9a84:	e8 d7 17 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9a89:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9a8c:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf9a8f:	31 f6                	xor    %esi,%esi
ffffffff8adf9a91:	31 d2                	xor    %edx,%edx
ffffffff8adf9a93:	e8 68 28 81 00       	call   ffffffff8b60c300 <frame_candidate_43a930+0x8119d0>
ffffffff8adf9a98:	eb 1b                	jmp    ffffffff8adf9ab5 <frame_candidate_439770+0x345>
ffffffff8adf9a9a:	48 8d 3d 9f 14 0c 03 	lea    0x30c149f(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf9aa1:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8adf9aa8:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9aad:	e8 ae 17 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9ab2:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf9ab5:	8b 05 15 7c 68 01    	mov    0x1687c15(%rip),%eax        # ffffffff8c4816d0 <frame_candidate_43a930+0x1686da0>
ffffffff8adf9abb:	48 89 1d 06 0e 0c 03 	mov    %rbx,0x30c0e06(%rip)        # ffffffff8deba8c8 <frame_candidate_43a930+0x30bff98>
ffffffff8adf9ac2:	85 c0                	test   %eax,%eax
ffffffff8adf9ac4:	0f 84 ef 00 00 00    	je     ffffffff8adf9bb9 <frame_candidate_439770+0x449>
ffffffff8adf9aca:	4c 8d 2d ef 7b 68 01 	lea    0x1687bef(%rip),%r13        # ffffffff8c4816c0 <frame_candidate_43a930+0x1686d90>
ffffffff8adf9ad1:	48 8d 9d 78 ff ff ff 	lea    -0x88(%rbp),%rbx
ffffffff8adf9ad8:	4c 8d 3d 61 14 0c 03 	lea    0x30c1461(%rip),%r15        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf9adf:	eb 57                	jmp    ffffffff8adf9b38 <frame_candidate_439770+0x3c8>
ffffffff8adf9ae1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8adf9ae8:	0f 1f 84 00 00 00 00 
ffffffff8adf9aef:	00 
ffffffff8adf9af0:	4c 8d 35 d9 0d 0c 03 	lea    0x30c0dd9(%rip),%r14        # ffffffff8deba8d0 <frame_candidate_43a930+0x30bffa0>
ffffffff8adf9af7:	31 f6                	xor    %esi,%esi
ffffffff8adf9af9:	31 d2                	xor    %edx,%edx
ffffffff8adf9afb:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9afd:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9b00:	e8 4b 18 81 00       	call   ffffffff8b60b350 <frame_candidate_43a930+0x810a20>
ffffffff8adf9b05:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf9b08:	48 89 de             	mov    %rbx,%rsi
ffffffff8adf9b0b:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9b10:	e8 4b 17 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9b15:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9b18:	49 89 c4             	mov    %rax,%r12
ffffffff8adf9b1b:	31 f6                	xor    %esi,%esi
ffffffff8adf9b1d:	31 d2                	xor    %edx,%edx
ffffffff8adf9b1f:	e8 dc 27 81 00       	call   ffffffff8b60c300 <frame_candidate_43a930+0x8119d0>
ffffffff8adf9b24:	4d 89 65 00          	mov    %r12,0x0(%r13)
ffffffff8adf9b28:	41 8b 45 28          	mov    0x28(%r13),%eax
ffffffff8adf9b2c:	49 83 c5 18          	add    $0x18,%r13
ffffffff8adf9b30:	85 c0                	test   %eax,%eax
ffffffff8adf9b32:	0f 84 81 00 00 00    	je     ffffffff8adf9bb9 <frame_candidate_439770+0x449>
ffffffff8adf9b38:	4d 8b 65 08          	mov    0x8(%r13),%r12
ffffffff8adf9b3c:	8d 04 c5 18 00 00 00 	lea    0x18(,%rax,8),%eax
ffffffff8adf9b43:	be 58 00 00 00       	mov    $0x58,%esi
ffffffff8adf9b48:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf9b4b:	4c 63 f0             	movslq %eax,%r14
ffffffff8adf9b4e:	e8 9d f4 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf9b53:	83 3d 9a 0b 0c 03 01 	cmpl   $0x1,0x30c0b9a(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adf9b5a:	48 b8 07 00 00 00 40 	movabs $0x1000044000000007,%rax
ffffffff8adf9b61:	04 00 10 
ffffffff8adf9b64:	4c 89 a5 78 ff ff ff 	mov    %r12,-0x88(%rbp)
ffffffff8adf9b6b:	4c 89 75 80          	mov    %r14,-0x80(%rbp)
ffffffff8adf9b6f:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8adf9b76:	00 
ffffffff8adf9b77:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8adf9b7e:	00 
ffffffff8adf9b7f:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8adf9b86:	00 
ffffffff8adf9b87:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8adf9b8e:	00 
ffffffff8adf9b8f:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8adf9b93:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8adf9b9a:	00 
ffffffff8adf9b9b:	0f 8f 4f ff ff ff    	jg     ffffffff8adf9af0 <frame_candidate_439770+0x380>
ffffffff8adf9ba1:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf9ba4:	48 89 de             	mov    %rbx,%rsi
ffffffff8adf9ba7:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9bac:	e8 af 16 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9bb1:	49 89 c4             	mov    %rax,%r12
ffffffff8adf9bb4:	e9 6b ff ff ff       	jmp    ffffffff8adf9b24 <frame_candidate_439770+0x3b4>
ffffffff8adf9bb9:	0f b7 05 b0 7e 68 01 	movzwl 0x1687eb0(%rip),%eax        # ffffffff8c481a70 <frame_candidate_43a930+0x1687140>
ffffffff8adf9bc0:	66 85 c0             	test   %ax,%ax
ffffffff8adf9bc3:	0f 84 e3 00 00 00    	je     ffffffff8adf9cac <frame_candidate_439770+0x53c>
ffffffff8adf9bc9:	4c 8d 2d 90 7e 68 01 	lea    0x1687e90(%rip),%r13        # ffffffff8c481a60 <frame_candidate_43a930+0x1687130>
ffffffff8adf9bd0:	48 8d 9d 78 ff ff ff 	lea    -0x88(%rbp),%rbx
ffffffff8adf9bd7:	4c 8d 3d 62 13 0c 03 	lea    0x30c1362(%rip),%r15        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf9bde:	eb 4a                	jmp    ffffffff8adf9c2a <frame_candidate_439770+0x4ba>
ffffffff8adf9be0:	4c 8d 35 e9 0c 0c 03 	lea    0x30c0ce9(%rip),%r14        # ffffffff8deba8d0 <frame_candidate_43a930+0x30bffa0>
ffffffff8adf9be7:	31 f6                	xor    %esi,%esi
ffffffff8adf9be9:	31 d2                	xor    %edx,%edx
ffffffff8adf9beb:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9bed:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9bf0:	e8 5b 17 81 00       	call   ffffffff8b60b350 <frame_candidate_43a930+0x810a20>
ffffffff8adf9bf5:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf9bf8:	48 89 de             	mov    %rbx,%rsi
ffffffff8adf9bfb:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9c00:	e8 5b 16 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9c05:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9c08:	49 89 c4             	mov    %rax,%r12
ffffffff8adf9c0b:	31 f6                	xor    %esi,%esi
ffffffff8adf9c0d:	31 d2                	xor    %edx,%edx
ffffffff8adf9c0f:	e8 ec 26 81 00       	call   ffffffff8b60c300 <frame_candidate_43a930+0x8119d0>
ffffffff8adf9c14:	4d 89 65 00          	mov    %r12,0x0(%r13)
ffffffff8adf9c18:	41 0f b7 45 28       	movzwl 0x28(%r13),%eax
ffffffff8adf9c1d:	49 83 c5 18          	add    $0x18,%r13
ffffffff8adf9c21:	66 85 c0             	test   %ax,%ax
ffffffff8adf9c24:	0f 84 82 00 00 00    	je     ffffffff8adf9cac <frame_candidate_439770+0x53c>
ffffffff8adf9c2a:	4d 8b 75 08          	mov    0x8(%r13),%r14
ffffffff8adf9c2e:	0f b7 c0             	movzwl %ax,%eax
ffffffff8adf9c31:	be 58 00 00 00       	mov    $0x58,%esi
ffffffff8adf9c36:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf9c39:	4c 8d 24 c5 10 00 00 	lea    0x10(,%rax,8),%r12
ffffffff8adf9c40:	00 
ffffffff8adf9c41:	e8 aa f3 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf9c46:	83 3d a7 0a 0c 03 01 	cmpl   $0x1,0x30c0aa7(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adf9c4d:	48 b8 07 00 00 00 40 	movabs $0x1000044000000007,%rax
ffffffff8adf9c54:	04 00 10 
ffffffff8adf9c57:	4c 89 b5 78 ff ff ff 	mov    %r14,-0x88(%rbp)
ffffffff8adf9c5e:	4c 89 65 80          	mov    %r12,-0x80(%rbp)
ffffffff8adf9c62:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8adf9c69:	00 
ffffffff8adf9c6a:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8adf9c71:	00 
ffffffff8adf9c72:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8adf9c79:	00 
ffffffff8adf9c7a:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8adf9c81:	00 
ffffffff8adf9c82:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8adf9c86:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8adf9c8d:	00 
ffffffff8adf9c8e:	0f 8f 4c ff ff ff    	jg     ffffffff8adf9be0 <frame_candidate_439770+0x470>
ffffffff8adf9c94:	4c 89 ff             	mov    %r15,%rdi
ffffffff8adf9c97:	48 89 de             	mov    %rbx,%rsi
ffffffff8adf9c9a:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9c9f:	e8 bc 15 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9ca4:	49 89 c4             	mov    %rax,%r12
ffffffff8adf9ca7:	e9 68 ff ff ff       	jmp    ffffffff8adf9c14 <frame_candidate_439770+0x4a4>
ffffffff8adf9cac:	48 8d bd 78 ff ff ff 	lea    -0x88(%rbp),%rdi
ffffffff8adf9cb3:	be 58 00 00 00       	mov    $0x58,%esi
ffffffff8adf9cb8:	e8 33 f3 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf9cbd:	83 3d 30 0a 0c 03 01 	cmpl   $0x1,0x30c0a30(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adf9cc4:	48 8d 05 af 72 f1 00 	lea    0xf172af(%rip),%rax        # ffffffff8bd10f7a <frame_candidate_43a930+0xf1664a>
ffffffff8adf9ccb:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
ffffffff8adf9cd2:	48 b8 07 00 00 00 40 	movabs $0x1000044000000007,%rax
ffffffff8adf9cd9:	04 00 10 
ffffffff8adf9cdc:	48 c7 45 80 90 01 00 	movq   $0x190,-0x80(%rbp)
ffffffff8adf9ce3:	00 
ffffffff8adf9ce4:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
ffffffff8adf9ceb:	00 
ffffffff8adf9cec:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
ffffffff8adf9cf3:	00 
ffffffff8adf9cf4:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
ffffffff8adf9cfb:	00 
ffffffff8adf9cfc:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
ffffffff8adf9d03:	00 
ffffffff8adf9d04:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8adf9d08:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
ffffffff8adf9d0f:	00 
ffffffff8adf9d10:	7e 3e                	jle    ffffffff8adf9d50 <frame_candidate_439770+0x5e0>
ffffffff8adf9d12:	4c 8d 35 b7 0b 0c 03 	lea    0x30c0bb7(%rip),%r14        # ffffffff8deba8d0 <frame_candidate_43a930+0x30bffa0>
ffffffff8adf9d19:	31 f6                	xor    %esi,%esi
ffffffff8adf9d1b:	31 d2                	xor    %edx,%edx
ffffffff8adf9d1d:	31 c9                	xor    %ecx,%ecx
ffffffff8adf9d1f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9d22:	e8 29 16 81 00       	call   ffffffff8b60b350 <frame_candidate_43a930+0x810a20>
ffffffff8adf9d27:	48 8d 3d 12 12 0c 03 	lea    0x30c1212(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf9d2e:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8adf9d35:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9d3a:	e8 21 15 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9d3f:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9d42:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf9d45:	31 f6                	xor    %esi,%esi
ffffffff8adf9d47:	31 d2                	xor    %edx,%edx
ffffffff8adf9d49:	e8 b2 25 81 00       	call   ffffffff8b60c300 <frame_candidate_43a930+0x8119d0>
ffffffff8adf9d4e:	eb 1b                	jmp    ffffffff8adf9d6b <frame_candidate_439770+0x5fb>
ffffffff8adf9d50:	48 8d 3d e9 11 0c 03 	lea    0x30c11e9(%rip),%rdi        # ffffffff8debaf40 <frame_candidate_43a930+0x30c0610>
ffffffff8adf9d57:	48 8d b5 78 ff ff ff 	lea    -0x88(%rbp),%rsi
ffffffff8adf9d5e:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adf9d63:	e8 f8 14 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adf9d68:	48 89 c3             	mov    %rax,%rbx
ffffffff8adf9d6b:	48 89 1d 8e 11 0c 03 	mov    %rbx,0x30c118e(%rip)        # ffffffff8debaf00 <frame_candidate_43a930+0x30c05d0>
ffffffff8adf9d72:	49 c7 c7 f0 ff ff ff 	mov    $0xfffffffffffffff0,%r15
ffffffff8adf9d79:	48 8d 1d e5 0b 0c 03 	lea    0x30c0be5(%rip),%rbx        # ffffffff8deba965 <frame_candidate_43a930+0x30c0035>
ffffffff8adf9d80:	4c 8d 35 d5 23 62 01 	lea    0x16223d5(%rip),%r14        # ffffffff8c41c15c <frame_candidate_43a930+0x162182c>
ffffffff8adf9d87:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8adf9d8e:	00 00 
ffffffff8adf9d90:	41 8d 47 14          	lea    0x14(%r15),%eax
ffffffff8adf9d94:	c7 43 ec 46 4c 52 47 	movl   $0x47524c46,-0x14(%rbx)
ffffffff8adf9d9b:	be 14 00 00 00       	mov    $0x14,%esi
ffffffff8adf9da0:	48 89 df             	mov    %rbx,%rdi
ffffffff8adf9da3:	88 43 f0             	mov    %al,-0x10(%rbx)
ffffffff8adf9da6:	41 8d 47 15          	lea    0x15(%r15),%eax
ffffffff8adf9daa:	88 43 f1             	mov    %al,-0xf(%rbx)
ffffffff8adf9dad:	41 8d 47 16          	lea    0x16(%r15),%eax
ffffffff8adf9db1:	88 43 f2             	mov    %al,-0xe(%rbx)
ffffffff8adf9db4:	41 8d 47 17          	lea    0x17(%r15),%eax
ffffffff8adf9db8:	88 43 f3             	mov    %al,-0xd(%rbx)
ffffffff8adf9dbb:	41 8d 47 18          	lea    0x18(%r15),%eax
ffffffff8adf9dbf:	88 43 f4             	mov    %al,-0xc(%rbx)
ffffffff8adf9dc2:	41 8d 47 19          	lea    0x19(%r15),%eax
ffffffff8adf9dc6:	88 43 f5             	mov    %al,-0xb(%rbx)
ffffffff8adf9dc9:	e8 22 f2 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf9dce:	ba 04 00 00 00       	mov    $0x4,%edx
ffffffff8adf9dd3:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adf9dd6:	48 89 de             	mov    %rbx,%rsi
ffffffff8adf9dd9:	e8 02 fe e1 ff       	call   ffffffff8ac19be0 <handler_632_body-0x1df250>
ffffffff8adf9dde:	c6 43 eb 00          	movb   $0x0,-0x15(%rbx)
ffffffff8adf9de2:	48 83 c3 3d          	add    $0x3d,%rbx
ffffffff8adf9de6:	49 ff c7             	inc    %r15
ffffffff8adf9de9:	75 a5                	jne    ffffffff8adf9d90 <frame_candidate_439770+0x620>
ffffffff8adf9deb:	48 8d 05 1e 25 4e 03 	lea    0x34e251e(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adf9df2:	c7 05 f8 08 0c 03 01 	movl   $0x1,0x30c08f8(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adf9df9:	00 00 00 
ffffffff8adf9dfc:	48 8b 00             	mov    (%rax),%rax
ffffffff8adf9dff:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8adf9e03:	75 12                	jne    ffffffff8adf9e17 <frame_candidate_439770+0x6a7>
ffffffff8adf9e05:	48 81 c4 b8 00 00 00 	add    $0xb8,%rsp
ffffffff8adf9e0c:	5b                   	pop    %rbx
ffffffff8adf9e0d:	41 5c                	pop    %r12
ffffffff8adf9e0f:	41 5d                	pop    %r13
ffffffff8adf9e11:	41 5e                	pop    %r14
ffffffff8adf9e13:	41 5f                	pop    %r15
ffffffff8adf9e15:	5d                   	pop    %rbp
ffffffff8adf9e16:	c3                   	ret
ffffffff8adf9e17:	e8 94 38 2c 00       	call   ffffffff8b0bd6b0 <frame_candidate_43a930+0x2c2d80>
ffffffff8adf9e1c:	0f 0b                	ud2
ffffffff8adf9e1e:	90                   	nop
ffffffff8adf9e1f:	90                   	nop

ffffffff8adf9e20 <frame_candidate_439e20>:
ffffffff8adf9e20:	55                   	push   %rbp
ffffffff8adf9e21:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adf9e24:	41 57                	push   %r15
ffffffff8adf9e26:	41 56                	push   %r14
ffffffff8adf9e28:	53                   	push   %rbx
ffffffff8adf9e29:	50                   	push   %rax
ffffffff8adf9e2a:	48 63 f6             	movslq %esi,%rsi
ffffffff8adf9e2d:	49 89 d6             	mov    %rdx,%r14
ffffffff8adf9e30:	48 89 fb             	mov    %rdi,%rbx
ffffffff8adf9e33:	e8 b8 f1 e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adf9e38:	45 8b 4e 08          	mov    0x8(%r14),%r9d
ffffffff8adf9e3c:	48 8d 0d 55 1b e3 ff 	lea    -0x1ce4ab(%rip),%rcx        # ffffffff8ac2b998 <handler_632_body-0x1cd498>
ffffffff8adf9e43:	44 89 8b 80 00 00 00 	mov    %r9d,0x80(%rbx)
ffffffff8adf9e4a:	49 8b 46 10          	mov    0x10(%r14),%rax
ffffffff8adf9e4e:	48 89 83 90 00 00 00 	mov    %rax,0x90(%rbx)
ffffffff8adf9e55:	49 8b 46 18          	mov    0x18(%r14),%rax
ffffffff8adf9e59:	48 89 83 98 00 00 00 	mov    %rax,0x98(%rbx)
ffffffff8adf9e60:	41 8b 46 20          	mov    0x20(%r14),%eax
ffffffff8adf9e64:	89 43 70             	mov    %eax,0x70(%rbx)
ffffffff8adf9e67:	c7 43 7c 00 00 00 00 	movl   $0x0,0x7c(%rbx)
ffffffff8adf9e6e:	48 c7 43 74 00 00 00 	movq   $0x0,0x74(%rbx)
ffffffff8adf9e75:	00 
ffffffff8adf9e76:	45 8b 46 24          	mov    0x24(%r14),%r8d
ffffffff8adf9e7a:	44 89 83 d0 00 00 00 	mov    %r8d,0xd0(%rbx)
ffffffff8adf9e81:	48 89 8b a0 00 00 00 	mov    %rcx,0xa0(%rbx)
ffffffff8adf9e88:	48 8d 0d c9 69 e3 ff 	lea    -0x1c9637(%rip),%rcx        # ffffffff8ac30858 <handler_632_body-0x1c85d8>
ffffffff8adf9e8f:	48 89 8b a8 00 00 00 	mov    %rcx,0xa8(%rbx)
ffffffff8adf9e96:	48 c7 83 c0 00 00 00 	movq   $0x0,0xc0(%rbx)
ffffffff8adf9e9d:	00 00 00 00 
ffffffff8adf9ea1:	4d 8b 3e             	mov    (%r14),%r15
ffffffff8adf9ea4:	49 8b 77 48          	mov    0x48(%r15),%rsi
ffffffff8adf9ea8:	48 89 b3 d8 00 00 00 	mov    %rsi,0xd8(%rbx)
ffffffff8adf9eaf:	41 8b 4e 24          	mov    0x24(%r14),%ecx
ffffffff8adf9eb3:	84 c9                	test   %cl,%cl
ffffffff8adf9eb5:	0f 88 b2 00 00 00    	js     ffffffff8adf9f6d <frame_candidate_439e20+0x14d>
ffffffff8adf9ebb:	f6 c1 02             	test   $0x2,%cl
ffffffff8adf9ebe:	0f 85 c4 00 00 00    	jne    ffffffff8adf9f88 <frame_candidate_439e20+0x168>
ffffffff8adf9ec4:	f6 c1 10             	test   $0x10,%cl
ffffffff8adf9ec7:	0f 85 d6 00 00 00    	jne    ffffffff8adf9fa3 <frame_candidate_439e20+0x183>
ffffffff8adf9ecd:	66 85 c9             	test   %cx,%cx
ffffffff8adf9ed0:	0f 88 e8 00 00 00    	js     ffffffff8adf9fbe <frame_candidate_439e20+0x19e>
ffffffff8adf9ed6:	f7 c1 00 00 02 00    	test   $0x20000,%ecx
ffffffff8adf9edc:	0f 85 f7 00 00 00    	jne    ffffffff8adf9fd9 <frame_candidate_439e20+0x1b9>
ffffffff8adf9ee2:	41 f7 c0 00 10 00 00 	test   $0x1000,%r8d
ffffffff8adf9ee9:	0f 85 05 01 00 00    	jne    ffffffff8adf9ff4 <frame_candidate_439e20+0x1d4>
ffffffff8adf9eef:	41 8d 89 51 c0 ff ff 	lea    -0x3faf(%r9),%ecx
ffffffff8adf9ef6:	81 f9 4e c0 ff ff    	cmp    $0xffffc04e,%ecx
ffffffff8adf9efc:	0f 87 52 02 00 00    	ja     ffffffff8adfa154 <frame_candidate_439e20+0x334>
ffffffff8adf9f02:	41 81 f9 ff ff 00 00 	cmp    $0xffff,%r9d
ffffffff8adf9f09:	0f 92 c0             	setb   %al
ffffffff8adf9f0c:	41 f7 c0 00 00 04 00 	test   $0x40000,%r8d
ffffffff8adf9f13:	0f 94 c1             	sete   %cl
ffffffff8adf9f16:	20 c1                	and    %al,%cl
ffffffff8adf9f18:	41 8d 41 02          	lea    0x2(%r9),%eax
ffffffff8adf9f1c:	0f b6 d1             	movzbl %cl,%edx
ffffffff8adf9f1f:	41 8d bc 51 ff 3f 00 	lea    0x3fff(%r9,%rdx,2),%edi
ffffffff8adf9f26:	00 
ffffffff8adf9f27:	84 d2                	test   %dl,%dl
ffffffff8adf9f29:	41 0f 44 c1          	cmove  %r9d,%eax
ffffffff8adf9f2d:	89 f9                	mov    %edi,%ecx
ffffffff8adf9f2f:	81 e7 00 c0 00 00    	and    $0xc000,%edi
ffffffff8adf9f35:	c1 e9 0e             	shr    $0xe,%ecx
ffffffff8adf9f38:	66 89 8b cc 00 00 00 	mov    %cx,0xcc(%rbx)
ffffffff8adf9f3f:	89 83 84 00 00 00    	mov    %eax,0x84(%rbx)
ffffffff8adf9f45:	88 93 d4 00 00 00    	mov    %dl,0xd4(%rbx)
ffffffff8adf9f4b:	66 89 bb c8 00 00 00 	mov    %di,0xc8(%rbx)
ffffffff8adf9f52:	66 c7 83 ce 00 00 00 	movw   $0x1,0xce(%rbx)
ffffffff8adf9f59:	01 00 
ffffffff8adf9f5b:	41 f7 c0 00 00 00 20 	test   $0x20000000,%r8d
ffffffff8adf9f62:	0f 84 6e 03 00 00    	je     ffffffff8adfa2d6 <frame_candidate_439e20+0x4b6>
ffffffff8adf9f68:	e9 4e 03 00 00       	jmp    ffffffff8adfa2bb <frame_candidate_439e20+0x49b>
ffffffff8adf9f6d:	41 81 c8 00 00 00 80 	or     $0x80000000,%r8d
ffffffff8adf9f74:	44 89 83 d0 00 00 00 	mov    %r8d,0xd0(%rbx)
ffffffff8adf9f7b:	41 8b 4e 24          	mov    0x24(%r14),%ecx
ffffffff8adf9f7f:	f6 c1 02             	test   $0x2,%cl
ffffffff8adf9f82:	0f 84 3c ff ff ff    	je     ffffffff8adf9ec4 <frame_candidate_439e20+0xa4>
ffffffff8adf9f88:	48 8d 0d d1 d0 e2 ff 	lea    -0x1d2f2f(%rip),%rcx        # ffffffff8ac27060 <handler_632_body-0x1d1dd0>
ffffffff8adf9f8f:	48 89 8b 90 00 00 00 	mov    %rcx,0x90(%rbx)
ffffffff8adf9f96:	41 8b 4e 24          	mov    0x24(%r14),%ecx
ffffffff8adf9f9a:	f6 c1 10             	test   $0x10,%cl
ffffffff8adf9f9d:	0f 84 2a ff ff ff    	je     ffffffff8adf9ecd <frame_candidate_439e20+0xad>
ffffffff8adf9fa3:	41 81 c8 00 20 00 00 	or     $0x2000,%r8d
ffffffff8adf9faa:	44 89 83 d0 00 00 00 	mov    %r8d,0xd0(%rbx)
ffffffff8adf9fb1:	41 8b 4e 24          	mov    0x24(%r14),%ecx
ffffffff8adf9fb5:	66 85 c9             	test   %cx,%cx
ffffffff8adf9fb8:	0f 89 18 ff ff ff    	jns    ffffffff8adf9ed6 <frame_candidate_439e20+0xb6>
ffffffff8adf9fbe:	41 83 c8 08          	or     $0x8,%r8d
ffffffff8adf9fc2:	44 89 83 d0 00 00 00 	mov    %r8d,0xd0(%rbx)
ffffffff8adf9fc9:	41 8b 4e 24          	mov    0x24(%r14),%ecx
ffffffff8adf9fcd:	f7 c1 00 00 02 00    	test   $0x20000,%ecx
ffffffff8adf9fd3:	0f 84 09 ff ff ff    	je     ffffffff8adf9ee2 <frame_candidate_439e20+0xc2>
ffffffff8adf9fd9:	41 81 c8 00 00 02 00 	or     $0x20000,%r8d
ffffffff8adf9fe0:	44 89 83 d0 00 00 00 	mov    %r8d,0xd0(%rbx)
ffffffff8adf9fe7:	41 f7 c0 00 10 00 00 	test   $0x1000,%r8d
ffffffff8adf9fee:	0f 84 fb fe ff ff    	je     ffffffff8adf9eef <frame_candidate_439e20+0xcf>
ffffffff8adf9ff4:	41 8d 49 02          	lea    0x2(%r9),%ecx
ffffffff8adf9ff8:	81 f9 01 00 01 00    	cmp    $0x10001,%ecx
ffffffff8adf9ffe:	0f 92 c2             	setb   %dl
ffffffff8adfa001:	41 f7 c0 00 00 04 00 	test   $0x40000,%r8d
ffffffff8adfa008:	40 0f 94 c7          	sete   %dil
ffffffff8adfa00c:	40 20 d7             	and    %dl,%dil
ffffffff8adfa00f:	44 0f 45 c9          	cmovne %ecx,%r9d
ffffffff8adfa013:	8d 48 01             	lea    0x1(%rax),%ecx
ffffffff8adfa016:	40 88 bb d4 00 00 00 	mov    %dil,0xd4(%rbx)
ffffffff8adfa01d:	c4 c2 78 f2 d1       	andn   %r9d,%eax,%edx
ffffffff8adfa022:	41 85 c1             	test   %eax,%r9d
ffffffff8adfa025:	8d 44 02 01          	lea    0x1(%rdx,%rax,1),%eax
ffffffff8adfa029:	41 0f 44 c1          	cmove  %r9d,%eax
ffffffff8adfa02d:	31 ff                	xor    %edi,%edi
ffffffff8adfa02f:	85 c8                	test   %ecx,%eax
ffffffff8adfa031:	0f 44 f9             	cmove  %ecx,%edi
ffffffff8adfa034:	31 d2                	xor    %edx,%edx
ffffffff8adfa036:	01 c7                	add    %eax,%edi
ffffffff8adfa038:	b8 00 40 00 00       	mov    $0x4000,%eax
ffffffff8adfa03d:	f7 f9                	idiv   %ecx
ffffffff8adfa03f:	41 89 fa             	mov    %edi,%r10d
ffffffff8adfa042:	89 bb 84 00 00 00    	mov    %edi,0x84(%rbx)
ffffffff8adfa048:	45 29 ca             	sub    %r9d,%r10d
ffffffff8adfa04b:	89 c1                	mov    %eax,%ecx
ffffffff8adfa04d:	0f af cf             	imul   %edi,%ecx
ffffffff8adfa050:	8d 81 ff 3f 00 00    	lea    0x3fff(%rcx),%eax
ffffffff8adfa056:	85 c9                	test   %ecx,%ecx
ffffffff8adfa058:	0f 48 c8             	cmovs  %eax,%ecx
ffffffff8adfa05b:	b8 08 00 00 00       	mov    $0x8,%eax
ffffffff8adfa060:	c1 f9 0e             	sar    $0xe,%ecx
ffffffff8adfa063:	83 f9 08             	cmp    $0x8,%ecx
ffffffff8adfa066:	0f 4d c8             	cmovge %eax,%ecx
ffffffff8adfa069:	89 c8                	mov    %ecx,%eax
ffffffff8adfa06b:	66 89 8b cc 00 00 00 	mov    %cx,0xcc(%rbx)
ffffffff8adfa072:	66 c7 83 c8 00 00 00 	movw   $0x4000,0xc8(%rbx)
ffffffff8adfa079:	00 40 
ffffffff8adfa07b:	c1 e0 0e             	shl    $0xe,%eax
ffffffff8adfa07e:	44 01 d0             	add    %r10d,%eax
ffffffff8adfa081:	99                   	cltd
ffffffff8adfa082:	f7 ff                	idiv   %edi
ffffffff8adfa084:	ba 08 20 00 00       	mov    $0x2008,%edx
ffffffff8adfa089:	66 89 83 ce 00 00 00 	mov    %ax,0xce(%rbx)
ffffffff8adfa090:	44 09 c2             	or     %r8d,%edx
ffffffff8adfa093:	89 d0                	mov    %edx,%eax
ffffffff8adfa095:	89 93 d0 00 00 00    	mov    %edx,0xd0(%rbx)
ffffffff8adfa09b:	a8 08                	test   $0x8,%al
ffffffff8adfa09d:	0f 84 59 02 00 00    	je     ffffffff8adfa2fc <frame_candidate_439e20+0x4dc>
ffffffff8adfa0a3:	48 8b 15 16 08 0c 03 	mov    0x30c0816(%rip),%rdx        # ffffffff8deba8c0 <frame_candidate_43a930+0x30bff90>
ffffffff8adfa0aa:	48 89 93 c0 00 00 00 	mov    %rdx,0xc0(%rbx)
ffffffff8adfa0b1:	66 83 f9 01          	cmp    $0x1,%cx
ffffffff8adfa0b5:	0f 84 4b 02 00 00    	je     ffffffff8adfa306 <frame_candidate_439e20+0x4e6>
ffffffff8adfa0bb:	a9 00 00 00 20       	test   $0x20000000,%eax
ffffffff8adfa0c0:	74 17                	je     ffffffff8adfa0d9 <frame_candidate_439e20+0x2b9>
ffffffff8adfa0c2:	83 3d 2b 06 0c 03 01 	cmpl   $0x1,0x30c062b(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adfa0c9:	7f 0e                	jg     ffffffff8adfa0d9 <frame_candidate_439e20+0x2b9>
ffffffff8adfa0cb:	48 8d 05 ce 18 e3 ff 	lea    -0x1ce732(%rip),%rax        # ffffffff8ac2b9a0 <handler_632_body-0x1cd490>
ffffffff8adfa0d2:	48 89 83 a0 00 00 00 	mov    %rax,0xa0(%rbx)
ffffffff8adfa0d9:	41 8b 46 24          	mov    0x24(%r14),%eax
ffffffff8adfa0dd:	48 8d 15 fd c0 f2 00 	lea    0xf2c0fd(%rip),%rdx        # ffffffff8bd261e1 <frame_candidate_43a930+0xf2b8b1>
ffffffff8adfa0e4:	48 8d 7b 18          	lea    0x18(%rbx),%rdi
ffffffff8adfa0e8:	b9 10 00 00 00       	mov    $0x10,%ecx
ffffffff8adfa0ed:	a8 40                	test   $0x40,%al
ffffffff8adfa0ef:	48 0f 45 d6          	cmovne %rsi,%rdx
ffffffff8adfa0f3:	e8 d8 dc 08 00       	call   ffffffff8ae87dd0 <frame_candidate_43a930+0x8d4a0>
ffffffff8adfa0f8:	8b 83 d0 00 00 00    	mov    0xd0(%rbx),%eax
ffffffff8adfa0fe:	a8 08                	test   $0x8,%al
ffffffff8adfa100:	75 22                	jne    ffffffff8adfa124 <frame_candidate_439e20+0x304>
ffffffff8adfa102:	0f b7 8b cc 00 00 00 	movzwl 0xcc(%rbx),%ecx
ffffffff8adfa109:	c1 e1 0e             	shl    $0xe,%ecx
ffffffff8adfa10c:	8d 51 b0             	lea    -0x50(%rcx),%edx
ffffffff8adfa10f:	66 89 93 ca 00 00 00 	mov    %dx,0xca(%rbx)
ffffffff8adfa116:	0f b7 d2             	movzwl %dx,%edx
ffffffff8adfa119:	83 c2 50             	add    $0x50,%edx
ffffffff8adfa11c:	39 ca                	cmp    %ecx,%edx
ffffffff8adfa11e:	0f 87 10 02 00 00    	ja     ffffffff8adfa334 <frame_candidate_439e20+0x514>
ffffffff8adfa124:	a9 00 01 00 00       	test   $0x100,%eax
ffffffff8adfa129:	74 7c                	je     ffffffff8adfa1a7 <frame_candidate_439e20+0x387>
ffffffff8adfa12b:	8b 43 48             	mov    0x48(%rbx),%eax
ffffffff8adfa12e:	85 c0                	test   %eax,%eax
ffffffff8adfa130:	74 39                	je     ffffffff8adfa16b <frame_candidate_439e20+0x34b>
ffffffff8adfa132:	8d 0c 00             	lea    (%rax,%rax,1),%ecx
ffffffff8adfa135:	c1 e0 04             	shl    $0x4,%eax
ffffffff8adfa138:	48 8d 35 11 78 68 01 	lea    0x1687811(%rip),%rsi        # ffffffff8c481950 <frame_candidate_43a930+0x1687020>
ffffffff8adfa13f:	ba 01 00 00 00       	mov    $0x1,%edx
ffffffff8adfa144:	4c 63 f0             	movslq %eax,%r14
ffffffff8adfa147:	89 4b 48             	mov    %ecx,0x48(%rbx)
ffffffff8adfa14a:	4c 89 f7             	mov    %r14,%rdi
ffffffff8adfa14d:	e8 fe e9 7c 00       	call   ffffffff8b5c8b50 <frame_candidate_43a930+0x7ce220>
ffffffff8adfa152:	eb 37                	jmp    ffffffff8adfa18b <frame_candidate_439e20+0x36b>
ffffffff8adfa154:	66 45 85 c0          	test   %r8w,%r8w
ffffffff8adfa158:	0f 88 d1 00 00 00    	js     ffffffff8adfa22f <frame_candidate_439e20+0x40f>
ffffffff8adfa15e:	66 b9 01 00          	mov    $0x1,%cx
ffffffff8adfa162:	66 ba 00 40          	mov    $0x4000,%dx
ffffffff8adfa166:	e9 ea 00 00 00       	jmp    ffffffff8adfa255 <frame_candidate_439e20+0x435>
ffffffff8adfa16b:	48 8b 3d 56 07 0c 03 	mov    0x30c0756(%rip),%rdi        # ffffffff8deba8c8 <frame_candidate_43a930+0x30bff98>
ffffffff8adfa172:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adfa177:	31 f6                	xor    %esi,%esi
ffffffff8adfa179:	e8 e2 10 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adfa17e:	41 be 00 01 00 00    	mov    $0x100,%r14d
ffffffff8adfa184:	c7 43 48 20 00 00 00 	movl   $0x20,0x48(%rbx)
ffffffff8adfa18b:	48 89 43 40          	mov    %rax,0x40(%rbx)
ffffffff8adfa18f:	48 85 c0             	test   %rax,%rax
ffffffff8adfa192:	74 13                	je     ffffffff8adfa1a7 <frame_candidate_439e20+0x387>
ffffffff8adfa194:	48 89 c7             	mov    %rax,%rdi
ffffffff8adfa197:	4c 89 f6             	mov    %r14,%rsi
ffffffff8adfa19a:	e8 51 ee e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adfa19f:	8b 43 48             	mov    0x48(%rbx),%eax
ffffffff8adfa1a2:	ff c8                	dec    %eax
ffffffff8adfa1a4:	89 43 4c             	mov    %eax,0x4c(%rbx)
ffffffff8adfa1a7:	49 89 5f 40          	mov    %rbx,0x40(%r15)
ffffffff8adfa1ab:	48 8d 43 50          	lea    0x50(%rbx),%rax
ffffffff8adfa1af:	48 8b 4b 50          	mov    0x50(%rbx),%rcx
ffffffff8adfa1b3:	49 89 4f 50          	mov    %rcx,0x50(%r15)
ffffffff8adfa1b7:	48 85 c9             	test   %rcx,%rcx
ffffffff8adfa1ba:	74 08                	je     ffffffff8adfa1c4 <frame_candidate_439e20+0x3a4>
ffffffff8adfa1bc:	49 8d 57 50          	lea    0x50(%r15),%rdx
ffffffff8adfa1c0:	48 89 51 58          	mov    %rdx,0x58(%rcx)
ffffffff8adfa1c4:	48 8d 3d 4d 05 0c 03 	lea    0x30c054d(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfa1cb:	4c 89 7b 50          	mov    %r15,0x50(%rbx)
ffffffff8adfa1cf:	49 89 47 58          	mov    %rax,0x58(%r15)
ffffffff8adfa1d3:	31 f6                	xor    %esi,%esi
ffffffff8adfa1d5:	31 d2                	xor    %edx,%edx
ffffffff8adfa1d7:	e8 c4 a4 39 00       	call   ffffffff8b1946a0 <frame_candidate_43a930+0x399d70>
ffffffff8adfa1dc:	48 8b 05 15 07 0c 03 	mov    0x30c0715(%rip),%rax        # ffffffff8deba8f8 <frame_candidate_43a930+0x30bffc8>
ffffffff8adfa1e3:	48 89 83 e0 00 00 00 	mov    %rax,0xe0(%rbx)
ffffffff8adfa1ea:	48 85 c0             	test   %rax,%rax
ffffffff8adfa1ed:	74 0e                	je     ffffffff8adfa1fd <frame_candidate_439e20+0x3dd>
ffffffff8adfa1ef:	48 8d 8b e0 00 00 00 	lea    0xe0(%rbx),%rcx
ffffffff8adfa1f6:	48 89 88 e8 00 00 00 	mov    %rcx,0xe8(%rax)
ffffffff8adfa1fd:	48 8d 05 f4 06 0c 03 	lea    0x30c06f4(%rip),%rax        # ffffffff8deba8f8 <frame_candidate_43a930+0x30bffc8>
ffffffff8adfa204:	48 8d 3d 0d 05 0c 03 	lea    0x30c050d(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfa20b:	48 89 1d e6 06 0c 03 	mov    %rbx,0x30c06e6(%rip)        # ffffffff8deba8f8 <frame_candidate_43a930+0x30bffc8>
ffffffff8adfa212:	31 f6                	xor    %esi,%esi
ffffffff8adfa214:	31 d2                	xor    %edx,%edx
ffffffff8adfa216:	48 89 83 e8 00 00 00 	mov    %rax,0xe8(%rbx)
ffffffff8adfa21d:	e8 8e ac 39 00       	call   ffffffff8b194eb0 <frame_candidate_43a930+0x39a580>
ffffffff8adfa222:	31 c0                	xor    %eax,%eax
ffffffff8adfa224:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8adfa228:	5b                   	pop    %rbx
ffffffff8adfa229:	41 5e                	pop    %r14
ffffffff8adfa22b:	41 5f                	pop    %r15
ffffffff8adfa22d:	5d                   	pop    %rbp
ffffffff8adfa22e:	c3                   	ret
ffffffff8adfa22f:	8b 0d 83 46 8d 03    	mov    0x38d4683(%rip),%ecx        # ffffffff8e6ce8b8 <frame_candidate_43a930+0x38d3f88>
ffffffff8adfa235:	8d 51 01             	lea    0x1(%rcx),%edx
ffffffff8adfa238:	69 d2 80 09 00 00    	imul   $0x980,%edx,%edx
ffffffff8adfa23e:	81 c2 ff 3f 00 00    	add    $0x3fff,%edx
ffffffff8adfa244:	c1 ea 0e             	shr    $0xe,%edx
ffffffff8adfa247:	ff c1                	inc    %ecx
ffffffff8adfa249:	b9 0a 00 00 00       	mov    $0xa,%ecx
ffffffff8adfa24e:	0f 45 ca             	cmovne %edx,%ecx
ffffffff8adfa251:	66 ba 80 09          	mov    $0x980,%dx
ffffffff8adfa255:	66 89 93 c8 00 00 00 	mov    %dx,0xc8(%rbx)
ffffffff8adfa25c:	0f b7 fa             	movzwl %dx,%edi
ffffffff8adfa25f:	41 8d 51 02          	lea    0x2(%r9),%edx
ffffffff8adfa263:	41 f7 c0 00 00 04 00 	test   $0x40000,%r8d
ffffffff8adfa26a:	66 89 8b cc 00 00 00 	mov    %cx,0xcc(%rbx)
ffffffff8adfa271:	41 0f 45 d1          	cmovne %r9d,%edx
ffffffff8adfa275:	41 89 f9             	mov    %edi,%r9d
ffffffff8adfa278:	0f 94 83 d4 00 00 00 	sete   0xd4(%rbx)
ffffffff8adfa27f:	41 c1 e9 08          	shr    $0x8,%r9d
ffffffff8adfa283:	44 39 ca             	cmp    %r9d,%edx
ffffffff8adfa286:	44 0f 47 ca          	cmova  %edx,%r9d
ffffffff8adfa28a:	41 85 c1             	test   %eax,%r9d
ffffffff8adfa28d:	74 06                	je     ffffffff8adfa295 <frame_candidate_439e20+0x475>
ffffffff8adfa28f:	41 09 c1             	or     %eax,%r9d
ffffffff8adfa292:	41 ff c1             	inc    %r9d
ffffffff8adfa295:	8d 47 b0             	lea    -0x50(%rdi),%eax
ffffffff8adfa298:	41 f6 c0 08          	test   $0x8,%r8b
ffffffff8adfa29c:	44 89 8b 84 00 00 00 	mov    %r9d,0x84(%rbx)
ffffffff8adfa2a3:	0f 45 c7             	cmovne %edi,%eax
ffffffff8adfa2a6:	31 d2                	xor    %edx,%edx
ffffffff8adfa2a8:	41 f7 f1             	div    %r9d
ffffffff8adfa2ab:	66 89 83 ce 00 00 00 	mov    %ax,0xce(%rbx)
ffffffff8adfa2b2:	41 f7 c0 00 00 00 a0 	test   $0xa0000000,%r8d
ffffffff8adfa2b9:	74 0d                	je     ffffffff8adfa2c8 <frame_candidate_439e20+0x4a8>
ffffffff8adfa2bb:	44 89 c0             	mov    %r8d,%eax
ffffffff8adfa2be:	a8 08                	test   $0x8,%al
ffffffff8adfa2c0:	0f 85 dd fd ff ff    	jne    ffffffff8adfa0a3 <frame_candidate_439e20+0x283>
ffffffff8adfa2c6:	eb 34                	jmp    ffffffff8adfa2fc <frame_candidate_439e20+0x4dc>
ffffffff8adfa2c8:	89 f8                	mov    %edi,%eax
ffffffff8adfa2ca:	31 d2                	xor    %edx,%edx
ffffffff8adfa2cc:	41 f7 f1             	div    %r9d
ffffffff8adfa2cf:	66 89 83 ce 00 00 00 	mov    %ax,0xce(%rbx)
ffffffff8adfa2d6:	44 89 c0             	mov    %r8d,%eax
ffffffff8adfa2d9:	ba 08 01 00 00       	mov    $0x108,%edx
ffffffff8adfa2de:	83 c8 08             	or     $0x8,%eax
ffffffff8adfa2e1:	89 83 d0 00 00 00    	mov    %eax,0xd0(%rbx)
ffffffff8adfa2e7:	41 f7 c0 00 20 00 00 	test   $0x2000,%r8d
ffffffff8adfa2ee:	0f 84 9c fd ff ff    	je     ffffffff8adfa090 <frame_candidate_439e20+0x270>
ffffffff8adfa2f4:	a8 08                	test   $0x8,%al
ffffffff8adfa2f6:	0f 85 a7 fd ff ff    	jne    ffffffff8adfa0a3 <frame_candidate_439e20+0x283>
ffffffff8adfa2fc:	66 83 f9 01          	cmp    $0x1,%cx
ffffffff8adfa300:	0f 85 b5 fd ff ff    	jne    ffffffff8adfa0bb <frame_candidate_439e20+0x29b>
ffffffff8adfa306:	48 8d 05 73 16 e3 ff 	lea    -0x1ce98d(%rip),%rax        # ffffffff8ac2b980 <handler_632_body-0x1cd4b0>
ffffffff8adfa30d:	48 8d 0d 3c 65 e3 ff 	lea    -0x1c9ac4(%rip),%rcx        # ffffffff8ac30850 <handler_632_body-0x1c85e0>
ffffffff8adfa314:	48 89 83 a0 00 00 00 	mov    %rax,0xa0(%rbx)
ffffffff8adfa31b:	48 89 8b a8 00 00 00 	mov    %rcx,0xa8(%rbx)
ffffffff8adfa322:	83 3d cb 03 0c 03 00 	cmpl   $0x0,0x30c03cb(%rip)        # ffffffff8deba6f4 <frame_candidate_43a930+0x30bfdc4>
ffffffff8adfa329:	0f 8f aa fd ff ff    	jg     ffffffff8adfa0d9 <frame_candidate_439e20+0x2b9>
ffffffff8adfa32f:	e9 97 fd ff ff       	jmp    ffffffff8adfa0cb <frame_candidate_439e20+0x2ab>
ffffffff8adfa334:	49 8b 77 48          	mov    0x48(%r15),%rsi
ffffffff8adfa338:	0f b7 93 ce 00 00 00 	movzwl 0xce(%rbx),%edx
ffffffff8adfa33f:	44 8b 83 80 00 00 00 	mov    0x80(%rbx),%r8d
ffffffff8adfa346:	8b 8b 84 00 00 00    	mov    0x84(%rbx),%ecx
ffffffff8adfa34c:	48 8d 3d 66 83 eb 00 	lea    0xeb8366(%rip),%rdi        # ffffffff8bcb26b9 <frame_candidate_43a930+0xeb7d89>
ffffffff8adfa353:	31 c0                	xor    %eax,%eax
ffffffff8adfa355:	e8 b6 30 e2 ff       	call   ffffffff8ac1d410 <handler_632_body-0x1dba20>
ffffffff8adfa35a:	e8 f1 75 3b 00       	call   ffffffff8b1b1950 <frame_candidate_43a930+0x3b7020>
ffffffff8adfa35f:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8adfa35a <frame_candidate_439e20+0x53a>
ffffffff8adfa366:	e8 a5 74 3b 00       	call   ffffffff8b1b1810 <frame_candidate_43a930+0x3b6ee0>
ffffffff8adfa36b:	48 8d 35 bc a6 f6 00 	lea    0xf6a6bc(%rip),%rsi        # ffffffff8bd64a2e <frame_candidate_43a930+0xf6a0fe>
ffffffff8adfa372:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8adfa377:	31 c0                	xor    %eax,%eax
ffffffff8adfa379:	e8 92 06 86 00       	call   ffffffff8b65aa10 <frame_candidate_43a930+0x8600e0>
ffffffff8adfa37e:	0f 0b                	ud2

ffffffff8adfa380 <frame_candidate_43a380>:
ffffffff8adfa380:	55                   	push   %rbp
ffffffff8adfa381:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adfa384:	41 56                	push   %r14
ffffffff8adfa386:	53                   	push   %rbx
ffffffff8adfa387:	48 8d 5f 18          	lea    0x18(%rdi),%rbx
ffffffff8adfa38b:	49 89 fe             	mov    %rdi,%r14
ffffffff8adfa38e:	31 f6                	xor    %esi,%esi
ffffffff8adfa390:	31 d2                	xor    %edx,%edx
ffffffff8adfa392:	31 c9                	xor    %ecx,%ecx
ffffffff8adfa394:	48 89 df             	mov    %rbx,%rdi
ffffffff8adfa397:	e8 64 c6 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adfa39c:	41 8b 56 78          	mov    0x78(%r14),%edx
ffffffff8adfa3a0:	85 d2                	test   %edx,%edx
ffffffff8adfa3a2:	74 27                	je     ffffffff8adfa3cb <frame_candidate_43a380+0x4b>
ffffffff8adfa3a4:	49 8b 86 d8 00 00 00 	mov    0xd8(%r14),%rax
ffffffff8adfa3ab:	41 8b 4e 74          	mov    0x74(%r14),%ecx
ffffffff8adfa3af:	48 8d 35 ef 88 e7 00 	lea    0xe788ef(%rip),%rsi        # ffffffff8bc72ca5 <frame_candidate_43a930+0xe78375>
ffffffff8adfa3b6:	48 8d 3d 4b 54 f7 00 	lea    0xf7544b(%rip),%rdi        # ffffffff8bd6f808 <frame_candidate_43a930+0xf74ed8>
ffffffff8adfa3bd:	48 85 c0             	test   %rax,%rax
ffffffff8adfa3c0:	48 0f 45 f0          	cmovne %rax,%rsi
ffffffff8adfa3c4:	31 c0                	xor    %eax,%eax
ffffffff8adfa3c6:	e8 45 30 e2 ff       	call   ffffffff8ac1d410 <handler_632_body-0x1dba20>
ffffffff8adfa3cb:	48 89 df             	mov    %rbx,%rdi
ffffffff8adfa3ce:	31 f6                	xor    %esi,%esi
ffffffff8adfa3d0:	31 d2                	xor    %edx,%edx
ffffffff8adfa3d2:	31 c9                	xor    %ecx,%ecx
ffffffff8adfa3d4:	e8 c7 cb 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adfa3d9:	49 8b 46 40          	mov    0x40(%r14),%rax
ffffffff8adfa3dd:	48 85 c0             	test   %rax,%rax
ffffffff8adfa3e0:	74 27                	je     ffffffff8adfa409 <frame_candidate_43a380+0x89>
ffffffff8adfa3e2:	41 83 7e 48 20       	cmpl   $0x20,0x48(%r14)
ffffffff8adfa3e7:	75 11                	jne    ffffffff8adfa3fa <frame_candidate_43a380+0x7a>
ffffffff8adfa3e9:	48 8b 3d d8 04 0c 03 	mov    0x30c04d8(%rip),%rdi        # ffffffff8deba8c8 <frame_candidate_43a930+0x30bff98>
ffffffff8adfa3f0:	48 89 c6             	mov    %rax,%rsi
ffffffff8adfa3f3:	e8 68 13 00 00       	call   ffffffff8adfb760 <frame_candidate_43a930+0xe30>
ffffffff8adfa3f8:	eb 0f                	jmp    ffffffff8adfa409 <frame_candidate_43a380+0x89>
ffffffff8adfa3fa:	48 8d 35 4f 75 68 01 	lea    0x168754f(%rip),%rsi        # ffffffff8c481950 <frame_candidate_43a930+0x1687020>
ffffffff8adfa401:	48 89 c7             	mov    %rax,%rdi
ffffffff8adfa404:	e8 e7 e9 7c 00       	call   ffffffff8b5c8df0 <frame_candidate_43a930+0x7ce4c0>
ffffffff8adfa409:	48 89 df             	mov    %rbx,%rdi
ffffffff8adfa40c:	5b                   	pop    %rbx
ffffffff8adfa40d:	41 5e                	pop    %r14
ffffffff8adfa40f:	5d                   	pop    %rbp
ffffffff8adfa410:	e9 3b da 08 00       	jmp    ffffffff8ae87e50 <frame_candidate_43a930+0x8d520>
ffffffff8adfa415:	90                   	nop
ffffffff8adfa416:	90                   	nop
ffffffff8adfa417:	90                   	nop
ffffffff8adfa418:	90                   	nop
ffffffff8adfa419:	90                   	nop
ffffffff8adfa41a:	90                   	nop
ffffffff8adfa41b:	90                   	nop
ffffffff8adfa41c:	90                   	nop
ffffffff8adfa41d:	90                   	nop
ffffffff8adfa41e:	90                   	nop
ffffffff8adfa41f:	90                   	nop

ffffffff8adfa420 <frame_candidate_43a420>:
ffffffff8adfa420:	55                   	push   %rbp
ffffffff8adfa421:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adfa424:	48 63 f6             	movslq %esi,%rsi
ffffffff8adfa427:	e8 c4 eb e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adfa42c:	31 c0                	xor    %eax,%eax
ffffffff8adfa42e:	5d                   	pop    %rbp
ffffffff8adfa42f:	c3                   	ret

ffffffff8adfa430 <frame_candidate_43a430>:
ffffffff8adfa430:	55                   	push   %rbp
ffffffff8adfa431:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adfa434:	41 57                	push   %r15
ffffffff8adfa436:	41 56                	push   %r14
ffffffff8adfa438:	41 55                	push   %r13
ffffffff8adfa43a:	41 54                	push   %r12
ffffffff8adfa43c:	53                   	push   %rbx
ffffffff8adfa43d:	48 83 ec 38          	sub    $0x38,%rsp
ffffffff8adfa441:	4c 8d 25 c8 1e 4e 03 	lea    0x34e1ec8(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adfa448:	48 63 f6             	movslq %esi,%rsi
ffffffff8adfa44b:	49 89 d6             	mov    %rdx,%r14
ffffffff8adfa44e:	48 89 fb             	mov    %rdi,%rbx
ffffffff8adfa451:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8adfa455:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8adfa459:	e8 92 eb e1 ff       	call   ffffffff8ac18ff0 <handler_632_body-0x1dfe40>
ffffffff8adfa45e:	49 8b 36             	mov    (%r14),%rsi
ffffffff8adfa461:	48 8d 15 79 bd f2 00 	lea    0xf2bd79(%rip),%rdx        # ffffffff8bd261e1 <frame_candidate_43a930+0xf2b8b1>
ffffffff8adfa468:	48 8d 7b 18          	lea    0x18(%rbx),%rdi
ffffffff8adfa46c:	b9 10 00 00 00       	mov    $0x10,%ecx
ffffffff8adfa471:	48 89 73 48          	mov    %rsi,0x48(%rbx)
ffffffff8adfa475:	49 8b 46 10          	mov    0x10(%r14),%rax
ffffffff8adfa479:	48 89 83 90 00 00 00 	mov    %rax,0x90(%rbx)
ffffffff8adfa480:	49 8b 46 18          	mov    0x18(%r14),%rax
ffffffff8adfa484:	48 89 83 98 00 00 00 	mov    %rax,0x98(%rbx)
ffffffff8adfa48b:	48 8d 05 ae 16 e3 ff 	lea    -0x1ce952(%rip),%rax        # ffffffff8ac2bb40 <handler_632_body-0x1cd2f0>
ffffffff8adfa492:	48 89 83 88 00 00 00 	mov    %rax,0x88(%rbx)
ffffffff8adfa499:	48 c7 83 a0 00 00 00 	movq   $0x0,0xa0(%rbx)
ffffffff8adfa4a0:	00 00 00 00 
ffffffff8adfa4a4:	48 c7 83 a8 00 00 00 	movq   $0x0,0xa8(%rbx)
ffffffff8adfa4ab:	00 00 00 00 
ffffffff8adfa4af:	48 c7 83 00 01 00 00 	movq   $0x0,0x100(%rbx)
ffffffff8adfa4b6:	00 00 00 00 
ffffffff8adfa4ba:	48 c7 83 10 01 00 00 	movq   $0x0,0x110(%rbx)
ffffffff8adfa4c1:	00 00 00 00 
ffffffff8adfa4c5:	48 c7 83 08 01 00 00 	movq   $0x0,0x108(%rbx)
ffffffff8adfa4cc:	00 00 00 00 
ffffffff8adfa4d0:	48 c7 83 18 01 00 00 	movq   $0x0,0x118(%rbx)
ffffffff8adfa4d7:	00 00 00 00 
ffffffff8adfa4db:	c7 83 20 01 00 00 00 	movl   $0x0,0x120(%rbx)
ffffffff8adfa4e2:	00 00 00 
ffffffff8adfa4e5:	c7 83 c8 00 00 00 00 	movl   $0x0,0xc8(%rbx)
ffffffff8adfa4ec:	00 00 00 
ffffffff8adfa4ef:	48 c7 83 38 01 00 00 	movq   $0x0,0x138(%rbx)
ffffffff8adfa4f6:	00 00 00 00 
ffffffff8adfa4fa:	48 c7 83 48 01 00 00 	movq   $0x0,0x148(%rbx)
ffffffff8adfa501:	00 00 00 00 
ffffffff8adfa505:	48 c7 83 40 01 00 00 	movq   $0x0,0x140(%rbx)
ffffffff8adfa50c:	00 00 00 00 
ffffffff8adfa510:	41 8b 46 54          	mov    0x54(%r14),%eax
ffffffff8adfa514:	4d 8b 7e 48          	mov    0x48(%r14),%r15
ffffffff8adfa518:	a8 40                	test   $0x40,%al
ffffffff8adfa51a:	48 0f 45 d6          	cmovne %rsi,%rdx
ffffffff8adfa51e:	e8 ad d8 08 00       	call   ffffffff8ae87dd0 <frame_candidate_43a930+0x8d4a0>
ffffffff8adfa523:	49 83 7e 30 00       	cmpq   $0x0,0x30(%r14)
ffffffff8adfa528:	0f 84 95 00 00 00    	je     ffffffff8adfa5c3 <frame_candidate_43a430+0x193>
ffffffff8adfa52e:	41 8b 46 54          	mov    0x54(%r14),%eax
ffffffff8adfa532:	84 c0                	test   %al,%al
ffffffff8adfa534:	79 09                	jns    ffffffff8adfa53f <frame_candidate_43a430+0x10f>
ffffffff8adfa536:	0d 00 00 00 80       	or     $0x80000000,%eax
ffffffff8adfa53b:	41 89 46 54          	mov    %eax,0x54(%r14)
ffffffff8adfa53f:	89 83 c8 00 00 00    	mov    %eax,0xc8(%rbx)
ffffffff8adfa545:	48 8d 3d cc 01 0c 03 	lea    0x30c01cc(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfa54c:	31 f6                	xor    %esi,%esi
ffffffff8adfa54e:	31 d2                	xor    %edx,%edx
ffffffff8adfa550:	41 8b 46 08          	mov    0x8(%r14),%eax
ffffffff8adfa554:	89 83 cc 00 00 00    	mov    %eax,0xcc(%rbx)
ffffffff8adfa55a:	49 8b 46 30          	mov    0x30(%r14),%rax
ffffffff8adfa55e:	48 89 83 b0 00 00 00 	mov    %rax,0xb0(%rbx)
ffffffff8adfa565:	49 8b 46 38          	mov    0x38(%r14),%rax
ffffffff8adfa569:	48 89 83 b8 00 00 00 	mov    %rax,0xb8(%rbx)
ffffffff8adfa570:	49 8b 46 40          	mov    0x40(%r14),%rax
ffffffff8adfa574:	48 89 83 c0 00 00 00 	mov    %rax,0xc0(%rbx)
ffffffff8adfa57b:	48 89 5b 40          	mov    %rbx,0x40(%rbx)
ffffffff8adfa57f:	e8 1c a1 39 00       	call   ffffffff8b1946a0 <frame_candidate_43a930+0x399d70>
ffffffff8adfa584:	48 8b 05 b5 03 0c 03 	mov    0x30c03b5(%rip),%rax        # ffffffff8deba940 <frame_candidate_43a930+0x30c0010>
ffffffff8adfa58b:	48 89 43 50          	mov    %rax,0x50(%rbx)
ffffffff8adfa58f:	48 85 c0             	test   %rax,%rax
ffffffff8adfa592:	74 08                	je     ffffffff8adfa59c <frame_candidate_43a430+0x16c>
ffffffff8adfa594:	48 8d 4b 50          	lea    0x50(%rbx),%rcx
ffffffff8adfa598:	48 89 48 58          	mov    %rcx,0x58(%rax)
ffffffff8adfa59c:	48 8d 05 9d 03 0c 03 	lea    0x30c039d(%rip),%rax        # ffffffff8deba940 <frame_candidate_43a930+0x30c0010>
ffffffff8adfa5a3:	48 8d 3d 6e 01 0c 03 	lea    0x30c016e(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfa5aa:	48 89 1d 8f 03 0c 03 	mov    %rbx,0x30c038f(%rip)        # ffffffff8deba940 <frame_candidate_43a930+0x30c0010>
ffffffff8adfa5b1:	31 f6                	xor    %esi,%esi
ffffffff8adfa5b3:	31 d2                	xor    %edx,%edx
ffffffff8adfa5b5:	48 89 43 58          	mov    %rax,0x58(%rbx)
ffffffff8adfa5b9:	e8 f2 a8 39 00       	call   ffffffff8b194eb0 <frame_candidate_43a930+0x39a580>
ffffffff8adfa5be:	e9 69 02 00 00       	jmp    ffffffff8adfa82c <frame_candidate_43a430+0x3fc>
ffffffff8adfa5c3:	48 8d 05 36 01 e3 ff 	lea    -0x1cfeca(%rip),%rax        # ffffffff8ac2a700 <handler_632_body-0x1ce730>
ffffffff8adfa5ca:	48 89 83 b0 00 00 00 	mov    %rax,0xb0(%rbx)
ffffffff8adfa5d1:	48 8d 05 70 db e2 ff 	lea    -0x1d2490(%rip),%rax        # ffffffff8ac28148 <handler_632_body-0x1d0ce8>
ffffffff8adfa5d8:	48 89 83 b8 00 00 00 	mov    %rax,0xb8(%rbx)
ffffffff8adfa5df:	48 89 9b c0 00 00 00 	mov    %rbx,0xc0(%rbx)
ffffffff8adfa5e6:	41 8b 46 54          	mov    0x54(%r14),%eax
ffffffff8adfa5ea:	a9 00 02 00 00       	test   $0x200,%eax
ffffffff8adfa5ef:	75 46                	jne    ffffffff8adfa637 <frame_candidate_43a430+0x207>
ffffffff8adfa5f1:	4d 85 ff             	test   %r15,%r15
ffffffff8adfa5f4:	0f 84 a3 02 00 00    	je     ffffffff8adfa89d <frame_candidate_43a430+0x46d>
ffffffff8adfa5fa:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8adfa5fe:	48 8d 55 a8          	lea    -0x58(%rbp),%rdx
ffffffff8adfa602:	be 00 01 00 00       	mov    $0x100,%esi
ffffffff8adfa607:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8adfa60b:	49 8b 4e 20          	mov    0x20(%r14),%rcx
ffffffff8adfa60f:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
ffffffff8adfa613:	49 8b 4e 28          	mov    0x28(%r14),%rcx
ffffffff8adfa617:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
ffffffff8adfa61b:	41 8b 4e 50          	mov    0x50(%r14),%ecx
ffffffff8adfa61f:	89 4d c8             	mov    %ecx,-0x38(%rbp)
ffffffff8adfa622:	89 45 cc             	mov    %eax,-0x34(%rbp)
ffffffff8adfa625:	48 89 5d a8          	mov    %rbx,-0x58(%rbp)
ffffffff8adfa629:	49 8b 7e 48          	mov    0x48(%r14),%rdi
ffffffff8adfa62d:	e8 ee f7 ff ff       	call   ffffffff8adf9e20 <frame_candidate_439e20>
ffffffff8adfa632:	e9 91 00 00 00       	jmp    ffffffff8adfa6c8 <frame_candidate_43a430+0x298>
ffffffff8adfa637:	49 8b 46 20          	mov    0x20(%r14),%rax
ffffffff8adfa63b:	48 8d 3d d6 00 0c 03 	lea    0x30c00d6(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfa642:	31 f6                	xor    %esi,%esi
ffffffff8adfa644:	31 d2                	xor    %edx,%edx
ffffffff8adfa646:	48 89 83 a0 00 00 00 	mov    %rax,0xa0(%rbx)
ffffffff8adfa64d:	49 8b 46 28          	mov    0x28(%r14),%rax
ffffffff8adfa651:	48 89 83 a8 00 00 00 	mov    %rax,0xa8(%rbx)
ffffffff8adfa658:	4c 89 7b 40          	mov    %r15,0x40(%rbx)
ffffffff8adfa65c:	80 8b c9 00 00 00 02 	orb    $0x2,0xc9(%rbx)
ffffffff8adfa663:	e8 38 a0 39 00       	call   ffffffff8b1946a0 <frame_candidate_43a930+0x399d70>
ffffffff8adfa668:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfa66c:	31 f6                	xor    %esi,%esi
ffffffff8adfa66e:	31 d2                	xor    %edx,%edx
ffffffff8adfa670:	31 c9                	xor    %ecx,%ecx
ffffffff8adfa672:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfa676:	e8 85 c3 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adfa67b:	49 8b 4f 50          	mov    0x50(%r15),%rcx
ffffffff8adfa67f:	90                   	nop
ffffffff8adfa680:	48 85 c9             	test   %rcx,%rcx
ffffffff8adfa683:	74 20                	je     ffffffff8adfa6a5 <frame_candidate_43a430+0x275>
ffffffff8adfa685:	48 89 c8             	mov    %rcx,%rax
ffffffff8adfa688:	48 8b 49 50          	mov    0x50(%rcx),%rcx
ffffffff8adfa68c:	48 85 c9             	test   %rcx,%rcx
ffffffff8adfa68f:	75 ef                	jne    ffffffff8adfa680 <frame_candidate_43a430+0x250>
ffffffff8adfa691:	48 c7 43 50 00 00 00 	movq   $0x0,0x50(%rbx)
ffffffff8adfa698:	00 
ffffffff8adfa699:	48 89 58 50          	mov    %rbx,0x50(%rax)
ffffffff8adfa69d:	48 83 c0 50          	add    $0x50,%rax
ffffffff8adfa6a1:	48 89 43 58          	mov    %rax,0x58(%rbx)
ffffffff8adfa6a5:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfa6a9:	31 f6                	xor    %esi,%esi
ffffffff8adfa6ab:	31 d2                	xor    %edx,%edx
ffffffff8adfa6ad:	31 c9                	xor    %ecx,%ecx
ffffffff8adfa6af:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfa6b3:	e8 e8 c8 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adfa6b8:	48 8d 3d 59 00 0c 03 	lea    0x30c0059(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfa6bf:	31 f6                	xor    %esi,%esi
ffffffff8adfa6c1:	31 d2                	xor    %edx,%edx
ffffffff8adfa6c3:	e8 e8 a7 39 00       	call   ffffffff8b194eb0 <frame_candidate_43a930+0x39a580>
ffffffff8adfa6c8:	4c 89 bb 80 00 00 00 	mov    %r15,0x80(%rbx)
ffffffff8adfa6cf:	48 8d 43 70          	lea    0x70(%rbx),%rax
ffffffff8adfa6d3:	48 8d 4b 68          	lea    0x68(%rbx),%rcx
ffffffff8adfa6d7:	48 8b 53 68          	mov    0x68(%rbx),%rdx
ffffffff8adfa6db:	48 89 53 70          	mov    %rdx,0x70(%rbx)
ffffffff8adfa6df:	48 85 d2             	test   %rdx,%rdx
ffffffff8adfa6e2:	74 04                	je     ffffffff8adfa6e8 <frame_candidate_43a430+0x2b8>
ffffffff8adfa6e4:	48 89 42 08          	mov    %rax,0x8(%rdx)
ffffffff8adfa6e8:	48 89 43 68          	mov    %rax,0x68(%rbx)
ffffffff8adfa6ec:	48 89 4b 78          	mov    %rcx,0x78(%rbx)
ffffffff8adfa6f0:	41 8b 87 80 00 00 00 	mov    0x80(%r15),%eax
ffffffff8adfa6f7:	89 83 cc 00 00 00    	mov    %eax,0xcc(%rbx)
ffffffff8adfa6fd:	b8 38 a5 2b b0       	mov    $0xb02ba538,%eax
ffffffff8adfa702:	41 23 87 d0 00 00 00 	and    0xd0(%r15),%eax
ffffffff8adfa709:	09 83 c8 00 00 00    	or     %eax,0xc8(%rbx)
ffffffff8adfa70f:	41 0f b6 87 d4 00 00 	movzbl 0xd4(%r15),%eax
ffffffff8adfa716:	00 
ffffffff8adfa717:	88 83 26 01 00 00    	mov    %al,0x126(%rbx)
ffffffff8adfa71d:	84 c0                	test   %al,%al
ffffffff8adfa71f:	0f 84 dc 00 00 00    	je     ffffffff8adfa801 <frame_candidate_43a430+0x3d1>
ffffffff8adfa725:	e8 06 7f 26 00       	call   ffffffff8b062630 <frame_candidate_43a930+0x267d00>
ffffffff8adfa72a:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8adfa731:	00 
ffffffff8adfa732:	89 c0                	mov    %eax,%eax
ffffffff8adfa734:	4c 8d 2d 15 02 0c 03 	lea    0x30c0215(%rip),%r13        # ffffffff8deba950 <frame_candidate_43a930+0x30c0020>
ffffffff8adfa73b:	48 6b c0 3d          	imul   $0x3d,%rax,%rax
ffffffff8adfa73f:	4d 8d 64 05 00       	lea    0x0(%r13,%rax,1),%r12
ffffffff8adfa744:	42 0f b6 04 28       	movzbl (%rax,%r13,1),%eax
ffffffff8adfa749:	84 c0                	test   %al,%al
ffffffff8adfa74b:	75 19                	jne    ffffffff8adfa766 <frame_candidate_43a430+0x336>
ffffffff8adfa74d:	49 8d 7c 24 29       	lea    0x29(%r12),%rdi
ffffffff8adfa752:	49 8d 74 24 01       	lea    0x1(%r12),%rsi
ffffffff8adfa757:	49 8d 54 24 15       	lea    0x15(%r12),%rdx
ffffffff8adfa75c:	e8 af 97 7a 00       	call   ffffffff8b5a3f10 <frame_candidate_43a930+0x7a95e0>
ffffffff8adfa761:	41 0f b6 04 24       	movzbl (%r12),%eax
ffffffff8adfa766:	0f b6 c0             	movzbl %al,%eax
ffffffff8adfa769:	8d 48 01             	lea    0x1(%rax),%ecx
ffffffff8adfa76c:	69 d1 cd 0c 00 00    	imul   $0xccd,%ecx,%edx
ffffffff8adfa772:	c1 ea 10             	shr    $0x10,%edx
ffffffff8adfa775:	c1 e2 02             	shl    $0x2,%edx
ffffffff8adfa778:	8d 14 92             	lea    (%rdx,%rdx,4),%edx
ffffffff8adfa77b:	29 d1                	sub    %edx,%ecx
ffffffff8adfa77d:	41 88 0c 24          	mov    %cl,(%r12)
ffffffff8adfa781:	45 0f b6 64 04 29    	movzbl 0x29(%r12,%rax,1),%r12d
ffffffff8adfa787:	e8 c4 7e 26 00       	call   ffffffff8b062650 <frame_candidate_43a930+0x267d20>
ffffffff8adfa78c:	44 88 a3 24 01 00 00 	mov    %r12b,0x124(%rbx)
ffffffff8adfa793:	e8 98 7e 26 00       	call   ffffffff8b062630 <frame_candidate_43a930+0x267d00>
ffffffff8adfa798:	65 8b 04 25 34 00 00 	mov    %gs:0x34,%eax
ffffffff8adfa79f:	00 
ffffffff8adfa7a0:	89 c0                	mov    %eax,%eax
ffffffff8adfa7a2:	48 6b c0 3d          	imul   $0x3d,%rax,%rax
ffffffff8adfa7a6:	4d 8d 64 05 00       	lea    0x0(%r13,%rax,1),%r12
ffffffff8adfa7ab:	42 0f b6 04 28       	movzbl (%rax,%r13,1),%eax
ffffffff8adfa7b0:	84 c0                	test   %al,%al
ffffffff8adfa7b2:	75 19                	jne    ffffffff8adfa7cd <frame_candidate_43a430+0x39d>
ffffffff8adfa7b4:	49 8d 7c 24 29       	lea    0x29(%r12),%rdi
ffffffff8adfa7b9:	49 8d 74 24 01       	lea    0x1(%r12),%rsi
ffffffff8adfa7be:	49 8d 54 24 15       	lea    0x15(%r12),%rdx
ffffffff8adfa7c3:	e8 48 97 7a 00       	call   ffffffff8b5a3f10 <frame_candidate_43a930+0x7a95e0>
ffffffff8adfa7c8:	41 0f b6 04 24       	movzbl (%r12),%eax
ffffffff8adfa7cd:	0f b6 c0             	movzbl %al,%eax
ffffffff8adfa7d0:	8d 48 01             	lea    0x1(%rax),%ecx
ffffffff8adfa7d3:	69 d1 cd 0c 00 00    	imul   $0xccd,%ecx,%edx
ffffffff8adfa7d9:	c1 ea 10             	shr    $0x10,%edx
ffffffff8adfa7dc:	c1 e2 02             	shl    $0x2,%edx
ffffffff8adfa7df:	8d 14 92             	lea    (%rdx,%rdx,4),%edx
ffffffff8adfa7e2:	29 d1                	sub    %edx,%ecx
ffffffff8adfa7e4:	41 88 0c 24          	mov    %cl,(%r12)
ffffffff8adfa7e8:	45 0f b6 64 04 29    	movzbl 0x29(%r12,%rax,1),%r12d
ffffffff8adfa7ee:	e8 5d 7e 26 00       	call   ffffffff8b062650 <frame_candidate_43a930+0x267d20>
ffffffff8adfa7f3:	44 88 a3 25 01 00 00 	mov    %r12b,0x125(%rbx)
ffffffff8adfa7fa:	4c 8d 25 0f 1b 4e 03 	lea    0x34e1b0f(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_43a930+0x34e19e0>
ffffffff8adfa801:	66 c7 83 28 01 00 00 	movw   $0xffff,0x128(%rbx)
ffffffff8adfa808:	ff ff 
ffffffff8adfa80a:	c6 83 2a 01 00 00 00 	movb   $0x0,0x12a(%rbx)
ffffffff8adfa811:	48 c7 83 30 01 00 00 	movq   $0x0,0x130(%rbx)
ffffffff8adfa818:	00 00 00 00 
ffffffff8adfa81c:	31 c0                	xor    %eax,%eax
ffffffff8adfa81e:	41 f6 87 d3 00 00 00 	testb  $0x20,0xd3(%r15)
ffffffff8adfa825:	20 
ffffffff8adfa826:	0f 85 e0 00 00 00    	jne    ffffffff8adfa90c <frame_candidate_43a430+0x4dc>
ffffffff8adfa82c:	41 f6 46 55 08       	testb  $0x8,0x55(%r14)
ffffffff8adfa831:	66 b9 fd 00          	mov    $0xfd,%cx
ffffffff8adfa835:	0f 85 c1 00 00 00    	jne    ffffffff8adfa8fc <frame_candidate_43a430+0x4cc>
ffffffff8adfa83b:	8b 8b cc 00 00 00    	mov    0xcc(%rbx),%ecx
ffffffff8adfa841:	8b 15 8d 6e 68 01    	mov    0x1686e8d(%rip),%edx        # ffffffff8c4816d4 <frame_candidate_43a930+0x1686da4>
ffffffff8adfa847:	8b 05 83 6e 68 01    	mov    0x1686e83(%rip),%eax        # ffffffff8c4816d0 <frame_candidate_43a930+0x1686da0>
ffffffff8adfa84d:	39 d1                	cmp    %edx,%ecx
ffffffff8adfa84f:	7e 16                	jle    ffffffff8adfa867 <frame_candidate_43a430+0x437>
ffffffff8adfa851:	0f af c2             	imul   %edx,%eax
ffffffff8adfa854:	99                   	cltd
ffffffff8adfa855:	f7 f9                	idiv   %ecx
ffffffff8adfa857:	b9 01 00 00 00       	mov    $0x1,%ecx
ffffffff8adfa85c:	83 f8 02             	cmp    $0x2,%eax
ffffffff8adfa85f:	0f 4d c8             	cmovge %eax,%ecx
ffffffff8adfa862:	e9 95 00 00 00       	jmp    ffffffff8adfa8fc <frame_candidate_43a430+0x4cc>
ffffffff8adfa867:	85 c0                	test   %eax,%eax
ffffffff8adfa869:	74 29                	je     ffffffff8adfa894 <frame_candidate_43a430+0x464>
ffffffff8adfa86b:	48 8d 05 4e 6e 68 01 	lea    0x1686e4e(%rip),%rax        # ffffffff8c4816c0 <frame_candidate_43a930+0x1686d90>
ffffffff8adfa872:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8adfa879:	1f 84 00 00 00 00 00 
ffffffff8adfa880:	39 48 14             	cmp    %ecx,0x14(%rax)
ffffffff8adfa883:	7c 71                	jl     ffffffff8adfa8f6 <frame_candidate_43a430+0x4c6>
ffffffff8adfa885:	83 78 28 00          	cmpl   $0x0,0x28(%rax)
ffffffff8adfa889:	48 8d 50 18          	lea    0x18(%rax),%rdx
ffffffff8adfa88d:	48 89 d0             	mov    %rdx,%rax
ffffffff8adfa890:	75 ee                	jne    ffffffff8adfa880 <frame_candidate_43a430+0x450>
ffffffff8adfa892:	eb 65                	jmp    ffffffff8adfa8f9 <frame_candidate_43a430+0x4c9>
ffffffff8adfa894:	48 8d 15 25 6e 68 01 	lea    0x1686e25(%rip),%rdx        # ffffffff8c4816c0 <frame_candidate_43a930+0x1686d90>
ffffffff8adfa89b:	eb 5c                	jmp    ffffffff8adfa8f9 <frame_candidate_43a430+0x4c9>
ffffffff8adfa89d:	41 8b 7e 50          	mov    0x50(%r14),%edi
ffffffff8adfa8a1:	49 8b 4e 08          	mov    0x8(%r14),%rcx
ffffffff8adfa8a5:	49 8b 56 20          	mov    0x20(%r14),%rdx
ffffffff8adfa8a9:	49 8b 76 28          	mov    0x28(%r14),%rsi
ffffffff8adfa8ad:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
ffffffff8adfa8b1:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
ffffffff8adfa8b5:	83 ff ff             	cmp    $0xffffffff,%edi
ffffffff8adfa8b8:	ba 3f 00 00 00       	mov    $0x3f,%edx
ffffffff8adfa8bd:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
ffffffff8adfa8c1:	48 8d 75 a8          	lea    -0x58(%rbp),%rsi
ffffffff8adfa8c5:	0f 45 d7             	cmovne %edi,%edx
ffffffff8adfa8c8:	48 8d 3d 71 04 0c 03 	lea    0x30c0471(%rip),%rdi        # ffffffff8debad40 <frame_candidate_43a930+0x30c0410>
ffffffff8adfa8cf:	89 55 c8             	mov    %edx,-0x38(%rbp)
ffffffff8adfa8d2:	ba 02 00 00 00       	mov    $0x2,%edx
ffffffff8adfa8d7:	89 45 cc             	mov    %eax,-0x34(%rbp)
ffffffff8adfa8da:	48 89 5d a8          	mov    %rbx,-0x58(%rbp)
ffffffff8adfa8de:	e8 7d 09 00 00       	call   ffffffff8adfb260 <frame_candidate_43a930+0x930>
ffffffff8adfa8e3:	49 89 c7             	mov    %rax,%r15
ffffffff8adfa8e6:	48 85 c0             	test   %rax,%rax
ffffffff8adfa8e9:	0f 85 d9 fd ff ff    	jne    ffffffff8adfa6c8 <frame_candidate_43a430+0x298>
ffffffff8adfa8ef:	b8 0c 00 00 00       	mov    $0xc,%eax
ffffffff8adfa8f4:	eb 16                	jmp    ffffffff8adfa90c <frame_candidate_43a430+0x4dc>
ffffffff8adfa8f6:	48 89 c2             	mov    %rax,%rdx
ffffffff8adfa8f9:	8b 4a f8             	mov    -0x8(%rdx),%ecx
ffffffff8adfa8fc:	66 89 8b 20 01 00 00 	mov    %cx,0x120(%rbx)
ffffffff8adfa903:	31 c0                	xor    %eax,%eax
ffffffff8adfa905:	66 89 8b 22 01 00 00 	mov    %cx,0x122(%rbx)
ffffffff8adfa90c:	49 8b 0c 24          	mov    (%r12),%rcx
ffffffff8adfa910:	48 3b 4d d0          	cmp    -0x30(%rbp),%rcx
ffffffff8adfa914:	75 0f                	jne    ffffffff8adfa925 <frame_candidate_43a430+0x4f5>
ffffffff8adfa916:	48 83 c4 38          	add    $0x38,%rsp
ffffffff8adfa91a:	5b                   	pop    %rbx
ffffffff8adfa91b:	41 5c                	pop    %r12
ffffffff8adfa91d:	41 5d                	pop    %r13
ffffffff8adfa91f:	41 5e                	pop    %r14
ffffffff8adfa921:	41 5f                	pop    %r15
ffffffff8adfa923:	5d                   	pop    %rbp
ffffffff8adfa924:	c3                   	ret
ffffffff8adfa925:	e8 86 2d 2c 00       	call   ffffffff8b0bd6b0 <frame_candidate_43a930+0x2c2d80>
ffffffff8adfa92a:	0f 0b                	ud2
ffffffff8adfa92c:	90                   	nop
ffffffff8adfa92d:	90                   	nop
ffffffff8adfa92e:	90                   	nop
ffffffff8adfa92f:	90                   	nop

ffffffff8adfa930 <frame_candidate_43a930>:
ffffffff8adfa930:	55                   	push   %rbp
ffffffff8adfa931:	48 89 e5             	mov    %rsp,%rbp
ffffffff8adfa934:	41 57                	push   %r15
ffffffff8adfa936:	41 56                	push   %r14
ffffffff8adfa938:	41 55                	push   %r13
ffffffff8adfa93a:	41 54                	push   %r12
ffffffff8adfa93c:	53                   	push   %rbx
ffffffff8adfa93d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8adfa941:	48 8b 47 68          	mov    0x68(%rdi),%rax
ffffffff8adfa945:	48 89 fb             	mov    %rdi,%rbx
ffffffff8adfa948:	48 85 c0             	test   %rax,%rax
ffffffff8adfa94b:	74 06                	je     ffffffff8adfa953 <frame_candidate_43a930+0x23>
ffffffff8adfa94d:	48 8b 40 10          	mov    0x10(%rax),%rax
ffffffff8adfa951:	eb 02                	jmp    ffffffff8adfa955 <frame_candidate_43a930+0x25>
ffffffff8adfa953:	31 c0                	xor    %eax,%eax
ffffffff8adfa955:	f6 83 cb 00 00 00 20 	testb  $0x20,0xcb(%rbx)
ffffffff8adfa95c:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
ffffffff8adfa960:	0f 85 41 04 00 00    	jne    ffffffff8adfada7 <frame_candidate_43a930+0x477>
ffffffff8adfa966:	48 8d 83 80 01 00 00 	lea    0x180(%rbx),%rax
ffffffff8adfa96d:	45 31 ff             	xor    %r15d,%r15d
ffffffff8adfa970:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
ffffffff8adfa974:	48 8b 05 6d 3f 8d 03 	mov    0x38d3f6d(%rip),%rax        # ffffffff8e6ce8e8 <frame_candidate_43a930+0x38d3fb8>
ffffffff8adfa97b:	eb 3b                	jmp    ffffffff8adfa9b8 <frame_candidate_43a930+0x88>
ffffffff8adfa97d:	0f 1f 00             	nopl   (%rax)
ffffffff8adfa980:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adfa983:	4c 89 e6             	mov    %r12,%rsi
ffffffff8adfa986:	4c 89 ea             	mov    %r13,%rdx
ffffffff8adfa989:	e8 32 17 00 00       	call   ffffffff8adfc0c0 <frame_candidate_43a930+0x1790>
ffffffff8adfa98e:	4c 8b 75 d0          	mov    -0x30(%rbp),%r14
ffffffff8adfa992:	49 c7 46 08 00 00 00 	movq   $0x0,0x8(%r14)
ffffffff8adfa999:	00 
ffffffff8adfa99a:	49 c7 06 00 00 00 00 	movq   $0x0,(%r14)
ffffffff8adfa9a1:	48 8b 05 40 3f 8d 03 	mov    0x38d3f40(%rip),%rax        # ffffffff8e6ce8e8 <frame_candidate_43a930+0x38d3fb8>
ffffffff8adfa9a8:	41 ff c7             	inc    %r15d
ffffffff8adfa9ab:	44 3b 3d 06 3f 8d 03 	cmp    0x38d3f06(%rip),%r15d        # ffffffff8e6ce8b8 <frame_candidate_43a930+0x38d3f88>
ffffffff8adfa9b2:	0f 87 7f 02 00 00    	ja     ffffffff8adfac37 <frame_candidate_43a930+0x307>
ffffffff8adfa9b8:	4c 0f a3 f8          	bt     %r15,%rax
ffffffff8adfa9bc:	73 ea                	jae    ffffffff8adfa9a8 <frame_candidate_43a930+0x78>
ffffffff8adfa9be:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
ffffffff8adfa9c2:	4d 63 f7             	movslq %r15d,%r14
ffffffff8adfa9c5:	49 c1 e6 06          	shl    $0x6,%r14
ffffffff8adfa9c9:	4e 8b 6c 30 08       	mov    0x8(%rax,%r14,1),%r13
ffffffff8adfa9ce:	4d 85 ed             	test   %r13,%r13
ffffffff8adfa9d1:	0f 84 a6 00 00 00    	je     ffffffff8adfaa7d <frame_candidate_43a930+0x14d>
ffffffff8adfa9d7:	48 83 bb a8 00 00 00 	cmpq   $0x0,0xa8(%rbx)
ffffffff8adfa9de:	00 
ffffffff8adfa9df:	4c 89 75 d0          	mov    %r14,-0x30(%rbp)
ffffffff8adfa9e3:	74 5b                	je     ffffffff8adfaa40 <frame_candidate_43a930+0x110>
ffffffff8adfa9e5:	66 41 83 7d 10 00    	cmpw   $0x0,0x10(%r13)
ffffffff8adfa9eb:	7e 53                	jle    ffffffff8adfaa40 <frame_candidate_43a930+0x110>
ffffffff8adfa9ed:	45 31 f6             	xor    %r14d,%r14d
ffffffff8adfa9f0:	4c 8b a3 a8 00 00 00 	mov    0xa8(%rbx),%r12
ffffffff8adfa9f7:	48 8d 05 6a 05 e3 ff 	lea    -0x1cfa96(%rip),%rax        # ffffffff8ac2af68 <handler_632_body-0x1cdec8>
ffffffff8adfa9fe:	4c 29 e0             	sub    %r12,%rax
ffffffff8adfaa01:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8adfaa05:	48 3d 0b 01 00 00    	cmp    $0x10b,%rax
ffffffff8adfaa0b:	77 1d                	ja     ffffffff8adfaa2a <frame_candidate_43a930+0xfa>
ffffffff8adfaa0d:	4b 8b 7c f5 18       	mov    0x18(%r13,%r14,8),%rdi
ffffffff8adfaa12:	8b b3 cc 00 00 00    	mov    0xcc(%rbx),%esi
ffffffff8adfaa18:	41 ff d4             	call   *%r12
ffffffff8adfaa1b:	49 0f bf 45 10       	movswq 0x10(%r13),%rax
ffffffff8adfaa20:	49 ff c6             	inc    %r14
ffffffff8adfaa23:	49 39 c6             	cmp    %rax,%r14
ffffffff8adfaa26:	7c c8                	jl     ffffffff8adfa9f0 <frame_candidate_43a930+0xc0>
ffffffff8adfaa28:	eb 16                	jmp    ffffffff8adfaa40 <frame_candidate_43a930+0x110>
ffffffff8adfaa2a:	48 8d 3d 4f 6f 68 01 	lea    0x1686f4f(%rip),%rdi        # ffffffff8c481980 <frame_candidate_43a930+0x1687050>
ffffffff8adfaa31:	4c 89 e6             	mov    %r12,%rsi
ffffffff8adfaa34:	e8 87 4e 01 00       	call   ffffffff8ae0f8c0 <frame_candidate_43a930+0x14f90>
ffffffff8adfaa39:	eb d2                	jmp    ffffffff8adfaa0d <frame_candidate_43a930+0xdd>
ffffffff8adfaa3b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8adfaa40:	4c 8b a3 b8 00 00 00 	mov    0xb8(%rbx),%r12
ffffffff8adfaa47:	48 8d 05 8a d7 e2 ff 	lea    -0x1d2876(%rip),%rax        # ffffffff8ac281d8 <handler_632_body-0x1d0c58>
ffffffff8adfaa4e:	4c 29 e0             	sub    %r12,%rax
ffffffff8adfaa51:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8adfaa55:	48 83 f8 13          	cmp    $0x13,%rax
ffffffff8adfaa59:	0f 87 ab 01 00 00    	ja     ffffffff8adfac0a <frame_candidate_43a930+0x2da>
ffffffff8adfaa5f:	48 8b bb c0 00 00 00 	mov    0xc0(%rbx),%rdi
ffffffff8adfaa66:	41 0f bf 55 10       	movswl 0x10(%r13),%edx
ffffffff8adfaa6b:	49 8d 75 18          	lea    0x18(%r13),%rsi
ffffffff8adfaa6f:	41 ff d4             	call   *%r12
ffffffff8adfaa72:	4c 8b 75 d0          	mov    -0x30(%rbp),%r14
ffffffff8adfaa76:	66 41 c7 45 10 00 00 	movw   $0x0,0x10(%r13)
ffffffff8adfaa7d:	4c 03 75 c8          	add    -0x38(%rbp),%r14
ffffffff8adfaa81:	4d 8b 2e             	mov    (%r14),%r13
ffffffff8adfaa84:	4d 85 ed             	test   %r13,%r13
ffffffff8adfaa87:	0f 84 a9 00 00 00    	je     ffffffff8adfab36 <frame_candidate_43a930+0x206>
ffffffff8adfaa8d:	41 0f b7 45 02       	movzwl 0x2(%r13),%eax
ffffffff8adfaa92:	66 85 c0             	test   %ax,%ax
ffffffff8adfaa95:	0f 84 9b 00 00 00    	je     ffffffff8adfab36 <frame_candidate_43a930+0x206>
ffffffff8adfaa9b:	48 83 bb a8 00 00 00 	cmpq   $0x0,0xa8(%rbx)
ffffffff8adfaaa2:	00 
ffffffff8adfaaa3:	74 5a                	je     ffffffff8adfaaff <frame_candidate_43a930+0x1cf>
ffffffff8adfaaa5:	4c 89 75 d0          	mov    %r14,-0x30(%rbp)
ffffffff8adfaaa9:	45 31 f6             	xor    %r14d,%r14d
ffffffff8adfaaac:	0f 1f 40 00          	nopl   0x0(%rax)
ffffffff8adfaab0:	4c 8b a3 a8 00 00 00 	mov    0xa8(%rbx),%r12
ffffffff8adfaab7:	48 8d 05 aa 04 e3 ff 	lea    -0x1cfb56(%rip),%rax        # ffffffff8ac2af68 <handler_632_body-0x1cdec8>
ffffffff8adfaabe:	4c 29 e0             	sub    %r12,%rax
ffffffff8adfaac1:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8adfaac5:	48 3d 0b 01 00 00    	cmp    $0x10b,%rax
ffffffff8adfaacb:	77 1d                	ja     ffffffff8adfaaea <frame_candidate_43a930+0x1ba>
ffffffff8adfaacd:	4b 8b 7c f5 10       	mov    0x10(%r13,%r14,8),%rdi
ffffffff8adfaad2:	8b b3 cc 00 00 00    	mov    0xcc(%rbx),%esi
ffffffff8adfaad8:	41 ff d4             	call   *%r12
ffffffff8adfaadb:	41 0f b7 45 02       	movzwl 0x2(%r13),%eax
ffffffff8adfaae0:	49 ff c6             	inc    %r14
ffffffff8adfaae3:	49 39 c6             	cmp    %rax,%r14
ffffffff8adfaae6:	72 c8                	jb     ffffffff8adfaab0 <frame_candidate_43a930+0x180>
ffffffff8adfaae8:	eb 11                	jmp    ffffffff8adfaafb <frame_candidate_43a930+0x1cb>
ffffffff8adfaaea:	48 8d 3d 2f 6f 68 01 	lea    0x1686f2f(%rip),%rdi        # ffffffff8c481a20 <frame_candidate_43a930+0x16870f0>
ffffffff8adfaaf1:	4c 89 e6             	mov    %r12,%rsi
ffffffff8adfaaf4:	e8 c7 4d 01 00       	call   ffffffff8ae0f8c0 <frame_candidate_43a930+0x14f90>
ffffffff8adfaaf9:	eb d2                	jmp    ffffffff8adfaacd <frame_candidate_43a930+0x19d>
ffffffff8adfaafb:	4c 8b 75 d0          	mov    -0x30(%rbp),%r14
ffffffff8adfaaff:	4c 8b a3 b8 00 00 00 	mov    0xb8(%rbx),%r12
ffffffff8adfab06:	48 8d 0d cb d6 e2 ff 	lea    -0x1d2935(%rip),%rcx        # ffffffff8ac281d8 <handler_632_body-0x1d0c58>
ffffffff8adfab0d:	4c 29 e1             	sub    %r12,%rcx
ffffffff8adfab10:	48 c1 c9 03          	ror    $0x3,%rcx
ffffffff8adfab14:	48 83 f9 13          	cmp    $0x13,%rcx
ffffffff8adfab18:	0f 87 00 01 00 00    	ja     ffffffff8adfac1e <frame_candidate_43a930+0x2ee>
ffffffff8adfab1e:	48 8b bb c0 00 00 00 	mov    0xc0(%rbx),%rdi
ffffffff8adfab25:	49 8d 75 10          	lea    0x10(%r13),%rsi
ffffffff8adfab29:	0f b7 d0             	movzwl %ax,%edx
ffffffff8adfab2c:	41 ff d4             	call   *%r12
ffffffff8adfab2f:	66 41 c7 45 02 00 00 	movw   $0x0,0x2(%r13)
ffffffff8adfab36:	49 8b 76 08          	mov    0x8(%r14),%rsi
ffffffff8adfab3a:	48 85 f6             	test   %rsi,%rsi
ffffffff8adfab3d:	74 51                	je     ffffffff8adfab90 <frame_candidate_43a930+0x260>
ffffffff8adfab3f:	8b 0d 8b 6b 68 01    	mov    0x1686b8b(%rip),%ecx        # ffffffff8c4816d0 <frame_candidate_43a930+0x1686da0>
ffffffff8adfab45:	48 8d 05 74 6b 68 01 	lea    0x1686b74(%rip),%rax        # ffffffff8c4816c0 <frame_candidate_43a930+0x1686d90>
ffffffff8adfab4c:	85 c9                	test   %ecx,%ecx
ffffffff8adfab4e:	74 1f                	je     ffffffff8adfab6f <frame_candidate_43a930+0x23f>
ffffffff8adfab50:	0f bf 56 12          	movswl 0x12(%rsi),%edx
ffffffff8adfab54:	48 8d 05 65 6b 68 01 	lea    0x1686b65(%rip),%rax        # ffffffff8c4816c0 <frame_candidate_43a930+0x1686d90>
ffffffff8adfab5b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
ffffffff8adfab60:	39 d1                	cmp    %edx,%ecx
ffffffff8adfab62:	7d 0f                	jge    ffffffff8adfab73 <frame_candidate_43a930+0x243>
ffffffff8adfab64:	8b 48 28             	mov    0x28(%rax),%ecx
ffffffff8adfab67:	48 83 c0 18          	add    $0x18,%rax
ffffffff8adfab6b:	85 c9                	test   %ecx,%ecx
ffffffff8adfab6d:	75 f1                	jne    ffffffff8adfab60 <frame_candidate_43a930+0x230>
ffffffff8adfab6f:	48 83 c0 e8          	add    $0xffffffffffffffe8,%rax
ffffffff8adfab73:	8b 93 c8 00 00 00    	mov    0xc8(%rbx),%edx
ffffffff8adfab79:	48 8b 38             	mov    (%rax),%rdi
ffffffff8adfab7c:	b9 00 00 00 00       	mov    $0x0,%ecx
ffffffff8adfab81:	f7 c2 00 00 00 10    	test   $0x10000000,%edx
ffffffff8adfab87:	48 0f 45 d1          	cmovne %rcx,%rdx
ffffffff8adfab8b:	e8 30 15 00 00       	call   ffffffff8adfc0c0 <frame_candidate_43a930+0x1790>
ffffffff8adfab90:	4d 8b 26             	mov    (%r14),%r12
ffffffff8adfab93:	4d 85 e4             	test   %r12,%r12
ffffffff8adfab96:	0f 84 f6 fd ff ff    	je     ffffffff8adfa992 <frame_candidate_43a930+0x62>
ffffffff8adfab9c:	44 8b ab c8 00 00 00 	mov    0xc8(%rbx),%r13d
ffffffff8adfaba3:	41 0f b7 04 24       	movzwl (%r12),%eax
ffffffff8adfaba8:	4c 89 75 d0          	mov    %r14,-0x30(%rbp)
ffffffff8adfabac:	4c 8d 35 95 6e 68 01 	lea    0x1686e95(%rip),%r14        # ffffffff8c481a48 <frame_candidate_43a930+0x1687118>
ffffffff8adfabb3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8adfabba:	84 00 00 00 00 00 
ffffffff8adfabc0:	41 0f b7 4e 28       	movzwl 0x28(%r14),%ecx
ffffffff8adfabc5:	49 83 c6 18          	add    $0x18,%r14
ffffffff8adfabc9:	66 85 c9             	test   %cx,%cx
ffffffff8adfabcc:	74 05                	je     ffffffff8adfabd3 <frame_candidate_43a930+0x2a3>
ffffffff8adfabce:	66 39 c8             	cmp    %cx,%ax
ffffffff8adfabd1:	75 ed                	jne    ffffffff8adfabc0 <frame_candidate_43a930+0x290>
ffffffff8adfabd3:	49 8b 74 24 08       	mov    0x8(%r12),%rsi
ffffffff8adfabd8:	41 f7 c5 00 00 00 10 	test   $0x10000000,%r13d
ffffffff8adfabdf:	b8 00 00 00 00       	mov    $0x0,%eax
ffffffff8adfabe4:	4c 0f 45 e8          	cmovne %rax,%r13
ffffffff8adfabe8:	48 85 f6             	test   %rsi,%rsi
ffffffff8adfabeb:	0f 84 8f fd ff ff    	je     ffffffff8adfa980 <frame_candidate_43a930+0x50>
ffffffff8adfabf1:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8adfabf4:	4c 89 ea             	mov    %r13,%rdx
ffffffff8adfabf7:	e8 c4 14 00 00       	call   ffffffff8adfc0c0 <frame_candidate_43a930+0x1790>
ffffffff8adfabfc:	49 c7 44 24 08 00 00 	movq   $0x0,0x8(%r12)
ffffffff8adfac03:	00 00 
ffffffff8adfac05:	e9 76 fd ff ff       	jmp    ffffffff8adfa980 <frame_candidate_43a930+0x50>
ffffffff8adfac0a:	48 8d 3d 8f 6d 68 01 	lea    0x1686d8f(%rip),%rdi        # ffffffff8c4819a0 <frame_candidate_43a930+0x1687070>
ffffffff8adfac11:	4c 89 e6             	mov    %r12,%rsi
ffffffff8adfac14:	e8 a7 4c 01 00       	call   ffffffff8ae0f8c0 <frame_candidate_43a930+0x14f90>
ffffffff8adfac19:	e9 41 fe ff ff       	jmp    ffffffff8adfaa5f <frame_candidate_43a930+0x12f>
ffffffff8adfac1e:	48 8d 3d 1b 6e 68 01 	lea    0x1686e1b(%rip),%rdi        # ffffffff8c481a40 <frame_candidate_43a930+0x1687110>
ffffffff8adfac25:	4c 89 e6             	mov    %r12,%rsi
ffffffff8adfac28:	e8 93 4c 01 00       	call   ffffffff8ae0f8c0 <frame_candidate_43a930+0x14f90>
ffffffff8adfac2d:	41 0f b7 45 02       	movzwl 0x2(%r13),%eax
ffffffff8adfac32:	e9 e7 fe ff ff       	jmp    ffffffff8adfab1e <frame_candidate_43a930+0x1ee>
ffffffff8adfac37:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfac3b:	31 f6                	xor    %esi,%esi
ffffffff8adfac3d:	31 d2                	xor    %edx,%edx
ffffffff8adfac3f:	31 c9                	xor    %ecx,%ecx
ffffffff8adfac41:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfac45:	e8 b6 bd 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adfac4a:	48 89 df             	mov    %rbx,%rdi
ffffffff8adfac4d:	e8 4e 44 00 00       	call   ffffffff8adff0a0 <frame_candidate_43a930+0x4770>
ffffffff8adfac52:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfac56:	31 f6                	xor    %esi,%esi
ffffffff8adfac58:	31 d2                	xor    %edx,%edx
ffffffff8adfac5a:	31 c9                	xor    %ecx,%ecx
ffffffff8adfac5c:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfac60:	e8 3b c3 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adfac65:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfac69:	31 f6                	xor    %esi,%esi
ffffffff8adfac6b:	31 d2                	xor    %edx,%edx
ffffffff8adfac6d:	31 c9                	xor    %ecx,%ecx
ffffffff8adfac6f:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfac73:	e8 88 bd 08 00       	call   ffffffff8ae86a00 <frame_candidate_43a930+0x8c0d0>
ffffffff8adfac78:	4c 8b bb 30 01 00 00 	mov    0x130(%rbx),%r15
ffffffff8adfac7f:	4d 85 ff             	test   %r15,%r15
ffffffff8adfac82:	0f 84 0c 01 00 00    	je     ffffffff8adfad94 <frame_candidate_43a930+0x464>
ffffffff8adfac88:	48 c7 83 30 01 00 00 	movq   $0x0,0x130(%rbx)
ffffffff8adfac8f:	00 00 00 00 
ffffffff8adfac93:	c6 83 2a 01 00 00 00 	movb   $0x0,0x12a(%rbx)
ffffffff8adfac9a:	31 f6                	xor    %esi,%esi
ffffffff8adfac9c:	31 d2                	xor    %edx,%edx
ffffffff8adfac9e:	31 c9                	xor    %ecx,%ecx
ffffffff8adfaca0:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfaca4:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfaca8:	e8 f3 c2 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adfacad:	41 0f b7 47 02       	movzwl 0x2(%r15),%eax
ffffffff8adfacb2:	66 85 c0             	test   %ax,%ax
ffffffff8adfacb5:	0f 84 93 00 00 00    	je     ffffffff8adfad4e <frame_candidate_43a930+0x41e>
ffffffff8adfacbb:	48 83 bb a8 00 00 00 	cmpq   $0x0,0xa8(%rbx)
ffffffff8adfacc2:	00 
ffffffff8adfacc3:	74 52                	je     ffffffff8adfad17 <frame_candidate_43a930+0x3e7>
ffffffff8adfacc5:	4c 8d 25 54 6d 68 01 	lea    0x1686d54(%rip),%r12        # ffffffff8c481a20 <frame_candidate_43a930+0x16870f0>
ffffffff8adfaccc:	45 31 f6             	xor    %r14d,%r14d
ffffffff8adfaccf:	90                   	nop
ffffffff8adfacd0:	4c 8b ab a8 00 00 00 	mov    0xa8(%rbx),%r13
ffffffff8adfacd7:	48 8d 05 8a 02 e3 ff 	lea    -0x1cfd76(%rip),%rax        # ffffffff8ac2af68 <handler_632_body-0x1cdec8>
ffffffff8adfacde:	4c 29 e8             	sub    %r13,%rax
ffffffff8adface1:	48 c1 c8 03          	ror    $0x3,%rax
ffffffff8adface5:	48 3d 0b 01 00 00    	cmp    $0x10b,%rax
ffffffff8adfaceb:	77 1d                	ja     ffffffff8adfad0a <frame_candidate_43a930+0x3da>
ffffffff8adfaced:	4b 8b 7c f7 10       	mov    0x10(%r15,%r14,8),%rdi
ffffffff8adfacf2:	8b b3 cc 00 00 00    	mov    0xcc(%rbx),%esi
ffffffff8adfacf8:	41 ff d5             	call   *%r13
ffffffff8adfacfb:	41 0f b7 47 02       	movzwl 0x2(%r15),%eax
ffffffff8adfad00:	49 ff c6             	inc    %r14
ffffffff8adfad03:	49 39 c6             	cmp    %rax,%r14
ffffffff8adfad06:	72 c8                	jb     ffffffff8adfacd0 <frame_candidate_43a930+0x3a0>
ffffffff8adfad08:	eb 0d                	jmp    ffffffff8adfad17 <frame_candidate_43a930+0x3e7>
ffffffff8adfad0a:	4c 89 e7             	mov    %r12,%rdi
ffffffff8adfad0d:	4c 89 ee             	mov    %r13,%rsi
ffffffff8adfad10:	e8 ab 4b 01 00       	call   ffffffff8ae0f8c0 <frame_candidate_43a930+0x14f90>
ffffffff8adfad15:	eb d6                	jmp    ffffffff8adfaced <frame_candidate_43a930+0x3bd>
ffffffff8adfad17:	4c 8b a3 b8 00 00 00 	mov    0xb8(%rbx),%r12
ffffffff8adfad1e:	48 8d 0d b3 d4 e2 ff 	lea    -0x1d2b4d(%rip),%rcx        # ffffffff8ac281d8 <handler_632_body-0x1d0c58>
ffffffff8adfad25:	4c 29 e1             	sub    %r12,%rcx
ffffffff8adfad28:	48 c1 c9 03          	ror    $0x3,%rcx
ffffffff8adfad2c:	48 83 f9 13          	cmp    $0x13,%rcx
ffffffff8adfad30:	0f 87 3e 03 00 00    	ja     ffffffff8adfb074 <frame_candidate_43a930+0x744>
ffffffff8adfad36:	48 8b bb c0 00 00 00 	mov    0xc0(%rbx),%rdi
ffffffff8adfad3d:	49 8d 77 10          	lea    0x10(%r15),%rsi
ffffffff8adfad41:	0f b7 d0             	movzwl %ax,%edx
ffffffff8adfad44:	41 ff d4             	call   *%r12
ffffffff8adfad47:	66 41 c7 47 02 00 00 	movw   $0x0,0x2(%r15)
ffffffff8adfad4e:	8b 83 c8 00 00 00    	mov    0xc8(%rbx),%eax
ffffffff8adfad54:	49 8b 77 08          	mov    0x8(%r15),%rsi
ffffffff8adfad58:	45 31 e4             	xor    %r12d,%r12d
ffffffff8adfad5b:	a9 00 00 00 10       	test   $0x10000000,%eax
ffffffff8adfad60:	4c 0f 44 e0          	cmove  %rax,%r12
ffffffff8adfad64:	48 85 f6             	test   %rsi,%rsi
ffffffff8adfad67:	74 17                	je     ffffffff8adfad80 <frame_candidate_43a930+0x450>
ffffffff8adfad69:	48 8b 3d 90 01 0c 03 	mov    0x30c0190(%rip),%rdi        # ffffffff8debaf00 <frame_candidate_43a930+0x30c05d0>
ffffffff8adfad70:	4c 89 e2             	mov    %r12,%rdx
ffffffff8adfad73:	e8 48 13 00 00       	call   ffffffff8adfc0c0 <frame_candidate_43a930+0x1790>
ffffffff8adfad78:	49 c7 47 08 00 00 00 	movq   $0x0,0x8(%r15)
ffffffff8adfad7f:	00 
ffffffff8adfad80:	48 8b 3d 79 01 0c 03 	mov    0x30c0179(%rip),%rdi        # ffffffff8debaf00 <frame_candidate_43a930+0x30c05d0>
ffffffff8adfad87:	4c 89 fe             	mov    %r15,%rsi
ffffffff8adfad8a:	4c 89 e2             	mov    %r12,%rdx
ffffffff8adfad8d:	e8 2e 13 00 00       	call   ffffffff8adfc0c0 <frame_candidate_43a930+0x1790>
ffffffff8adfad92:	eb 13                	jmp    ffffffff8adfada7 <frame_candidate_43a930+0x477>
ffffffff8adfad94:	48 8b 7b 40          	mov    0x40(%rbx),%rdi
ffffffff8adfad98:	31 f6                	xor    %esi,%esi
ffffffff8adfad9a:	31 d2                	xor    %edx,%edx
ffffffff8adfad9c:	31 c9                	xor    %ecx,%ecx
ffffffff8adfad9e:	48 83 c7 18          	add    $0x18,%rdi
ffffffff8adfada2:	e8 f9 c1 08 00       	call   ffffffff8ae86fa0 <frame_candidate_43a930+0x8c670>
ffffffff8adfada7:	48 8d 3d 6a f9 0b 03 	lea    0x30bf96a(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfadae:	31 f6                	xor    %esi,%esi
ffffffff8adfadb0:	31 d2                	xor    %edx,%edx
ffffffff8adfadb2:	e8 e9 98 39 00       	call   ffffffff8b1946a0 <frame_candidate_43a930+0x399d70>
ffffffff8adfadb7:	48 8b 43 50          	mov    0x50(%rbx),%rax
ffffffff8adfadbb:	48 85 c0             	test   %rax,%rax
ffffffff8adfadbe:	74 29                	je     ffffffff8adfade9 <frame_candidate_43a930+0x4b9>
ffffffff8adfadc0:	4c 8d 7b 50          	lea    0x50(%rbx),%r15
ffffffff8adfadc4:	4c 39 78 58          	cmp    %r15,0x58(%rax)
ffffffff8adfadc8:	0f 85 2f 02 00 00    	jne    ffffffff8adfaffd <frame_candidate_43a930+0x6cd>
ffffffff8adfadce:	48 8b 4b 58          	mov    0x58(%rbx),%rcx
ffffffff8adfadd2:	48 39 19             	cmp    %rbx,(%rcx)
ffffffff8adfadd5:	0f 85 f5 01 00 00    	jne    ffffffff8adfafd0 <frame_candidate_43a930+0x6a0>
ffffffff8adfaddb:	48 89 48 58          	mov    %rcx,0x58(%rax)
ffffffff8adfaddf:	48 8b 4b 50          	mov    0x50(%rbx),%rcx
ffffffff8adfade3:	48 8b 43 58          	mov    0x58(%rbx),%rax
ffffffff8adfade7:	eb 0f                	jmp    ffffffff8adfadf8 <frame_candidate_43a930+0x4c8>
ffffffff8adfade9:	48 8b 43 58          	mov    0x58(%rbx),%rax
ffffffff8adfaded:	48 39 18             	cmp    %rbx,(%rax)
ffffffff8adfadf0:	0f 85 da 01 00 00    	jne    ffffffff8adfafd0 <frame_candidate_43a930+0x6a0>
ffffffff8adfadf6:	31 c9                	xor    %ecx,%ecx
ffffffff8adfadf8:	48 8d 3d 19 f9 0b 03 	lea    0x30bf919(%rip),%rdi        # ffffffff8deba718 <frame_candidate_43a930+0x30bfde8>
ffffffff8adfadff:	48 89 08             	mov    %rcx,(%rax)
ffffffff8adfae02:	31 f6                	xor    %esi,%esi
ffffffff8adfae04:	31 d2                	xor    %edx,%edx
ffffffff8adfae06:	e8 a5 a0 39 00       	call   ffffffff8b194eb0 <frame_candidate_43a930+0x39a580>
ffffffff8adfae0b:	48 89 df             	mov    %rbx,%rdi
ffffffff8adfae0e:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8adfae13:	e8 48 e8 ff ff       	call   ffffffff8adf9660 <frame_candidate_439660>
ffffffff8adfae18:	48 8b 7b 68          	mov    0x68(%rbx),%rdi
ffffffff8adfae1c:	48 85 ff             	test   %rdi,%rdi
ffffffff8adfae1f:	74 70                	je     ffffffff8adfae91 <frame_candidate_43a930+0x561>
ffffffff8adfae21:	4c 8d 3d 58 12 7c 02 	lea    0x27c1258(%rip),%r15        # ffffffff8d5bc080 <frame_candidate_43a930+0x27c1750>
ffffffff8adfae28:	4c 8d 73 70          	lea    0x70(%rbx),%r14
ffffffff8adfae2c:	eb 0b                	jmp    ffffffff8adfae39 <frame_candidate_43a930+0x509>
ffffffff8adfae2e:	66 90                	xchg   %ax,%ax
