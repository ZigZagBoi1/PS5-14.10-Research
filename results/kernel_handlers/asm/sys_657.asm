; Handler 657; REA/Ghidra function-aware assembly with supplemental original-byte disassembly.
; RVAs, not rebased absolute VAs. Static analysis only.
; COMPLETE ORIGINAL INPUT WINDOW: handler_657.bin, 4096 bytes
; SHA256 7d576be693fd7630d871724e32c49d9e9c8e53c01957cd07d432e840f6255c1a; file offset zero = kernel RVA 0x265f78.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265f78 [0x265f78, 0x265f7c] | file +0x0 | ev_bcf43827b5c2e17a463acbcf525c45f60b468982552d619865a6bfe7665a37ba
thunk_265f78:
0x265f78: JMP 0x009a9f40
; END FUNCTION thunk_265f78
0x265f7d: INT3 ; original byte CC, padding
0x265f7e: INT3 ; original byte CC, padding
0x265f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f80 [0x265f80, 0x265f84] | file +0x8 | ev_dd33df4d2f9001ee6ac780697739b18182526436a92e50b0414b4999641f292f
thunk_265f80:
0x265f80: JMP 0x008fb440
; END FUNCTION thunk_265f80
0x265f85: INT3 ; original byte CC, padding
0x265f86: INT3 ; original byte CC, padding
0x265f87: INT3 ; original byte CC, padding

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0x10 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0x18 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0x20 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x28 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x30 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x38 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x40 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x48 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x50 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x58 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x60 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x68 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0x70 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0x78 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0x80 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0x88 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0x90 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0x98 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0xa0 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0xa8 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0xb0 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0xb8 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0xc0 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0xc8 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0xd0 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0xd8 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0xe0 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0xe8 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0xf0 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0xf8 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0x100 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0x108 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0x110 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0x118 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0x120 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0x128 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x130 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x138 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x140 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x148 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x150 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x158 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x160 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x168 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x170 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x178 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x180 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x188 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0x190 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0x198 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0x1a0 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0x1a8 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0x1b0 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0x1b8 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0x1c0 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0x1c8 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0x1d0 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0x1d8 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0x1e0 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0x1e8 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0x1f0 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0x1f8 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0x200 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0x208 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0x210 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0x218 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0x220 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0x228 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0x230 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0x238 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0x240 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0x248 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0x250 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0x258 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0x260 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0x268 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0x270 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0x278 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0x280 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0x288 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0x290 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0x298 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0x2a0 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0x2a8 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0x2b0 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0x2b8 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0x2c0 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0x2c8 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0x2d0 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0x2d8 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0x2e0 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0x2e8 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0x2f0 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0x2f8 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0x300 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0x308 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0x310 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0x318 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0x320 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0x328 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0x330 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0x338 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0x340 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0x348 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0x350 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0x358 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0x360 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0x368 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0x370 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0x378 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0x380 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0x388 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0x390 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0x398 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0x3a0 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0x3a8 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0x3b0 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0x3b8 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0x3c0 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0x3c8 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0x3d0 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0x3d8 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0x3e0 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0x3e8 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0x3f0 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0x3f8 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0x400 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0x408 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0x410 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0x418 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0x420 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0x428 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0x430 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0x438 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0x440 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0x448 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0x450 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0x458 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0x460 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0x468 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0x470 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0x478 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0x480 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0x488 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0x490 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0x498 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0x4a0 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0x4a8 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0x4b0 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0x4b8 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0x4c0 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0x4c8 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0x4d0 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0x4d8 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0x4e0 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0x4e8 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0x4f0 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0x4f8 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0x500 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0x508 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0x510 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0x518 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0x520 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0x528 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0x530 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0x538 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0x540 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0x548 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0x550 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0x558 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0x560 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0x568 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0x570 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0x578 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0x580 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0x588 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0x590 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0x598 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0x5a0 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0x5a8 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0x5b0 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0x5b8 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0x5c0 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0x5c8 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0x5d0 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0x5d8 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0x5e0 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0x5e8 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0x5f0 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0x5f8 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0x600 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0x608 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0x610 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0x618 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0x620 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0x628 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0x630 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0x638 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0x640 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0x648 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0x650 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0x658 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0x660 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0x668 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0x670 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0x678 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0x680 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0x688 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0x690 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0x698 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0x6a0 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0x6a8 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0x6b0 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0x6b8 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0x6c0 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0x6c8 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0x6d0 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0x6d8 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0x6e0 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0x6e8 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0x6f0 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0x6f8 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0x700 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0x708 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0x710 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0x718 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0x720 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0x728 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0x730 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0x738 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0x740 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0x748 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0x750 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0x758 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0x760 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0x768 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0x770 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0x778 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0x780 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0x788 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding

; FUNCTION thunk_266708 [0x266708, 0x26670c] | file +0x790 | ev_a1b1ecfb69ddcde3ab328e54879b2647bb27553f41929ae5021b46edd03a8fd6
thunk_266708:
0x266708: JMP 0x00ca7310
; END FUNCTION thunk_266708
0x26670d: INT3 ; original byte CC, padding
0x26670e: INT3 ; original byte CC, padding
0x26670f: INT3 ; original byte CC, padding

; FUNCTION thunk_266710 [0x266710, 0x266714] | file +0x798 | ev_91a5d5c52dbb1d6be7f635bc2e634aa41a9d00a7b8b5d2ae096ecbfdcbfa2641
thunk_266710:
0x266710: JMP 0x00662e70
; END FUNCTION thunk_266710
0x266715: INT3 ; original byte CC, padding
0x266716: INT3 ; original byte CC, padding
0x266717: INT3 ; original byte CC, padding

; FUNCTION thunk_266718 [0x266718, 0x26671c] | file +0x7a0 | ev_5d49490e833cb75f11ae327b52e57d63c8562abf36102eae069cd3b6103363e9
thunk_266718:
0x266718: JMP 0x00662e80
; END FUNCTION thunk_266718
0x26671d: INT3 ; original byte CC, padding
0x26671e: INT3 ; original byte CC, padding
0x26671f: INT3 ; original byte CC, padding

; FUNCTION thunk_266720 [0x266720, 0x266724] | file +0x7a8 | ev_1dbafec98e5478d51b8103829bfa1a72f4bc438e9f77ede71f00176b6c65fa7a
thunk_266720:
0x266720: JMP 0x00678e10
; END FUNCTION thunk_266720
0x266725: INT3 ; original byte CC, padding
0x266726: INT3 ; original byte CC, padding
0x266727: INT3 ; original byte CC, padding

; FUNCTION thunk_266728 [0x266728, 0x26672c] | file +0x7b0 | ev_38fac9adf6535b05ba585c6e1016cc470c98cfb56fa25e1502404b81f2326987
thunk_266728:
0x266728: JMP 0x00678e60
; END FUNCTION thunk_266728
0x26672d: INT3 ; original byte CC, padding
0x26672e: INT3 ; original byte CC, padding
0x26672f: INT3 ; original byte CC, padding

; FUNCTION thunk_266730 [0x266730, 0x266734] | file +0x7b8 | ev_890d87fa71c13e41992835bde9ad1d367d67a4a8cd4b5428bd46706c8a2a3c01
thunk_266730:
0x266730: JMP 0x00678ec0
; END FUNCTION thunk_266730
0x266735: INT3 ; original byte CC, padding
0x266736: INT3 ; original byte CC, padding
0x266737: INT3 ; original byte CC, padding

; FUNCTION thunk_266738 [0x266738, 0x26673c] | file +0x7c0 | ev_aa0a18be2618fe163ef3124d4793e4ee4faac93cc616ec748a395327ab897d78
thunk_266738:
0x266738: JMP 0x00678f60
; END FUNCTION thunk_266738
0x26673d: INT3 ; original byte CC, padding
0x26673e: INT3 ; original byte CC, padding
0x26673f: INT3 ; original byte CC, padding

; FUNCTION thunk_266740 [0x266740, 0x266744] | file +0x7c8 | ev_b940e85d2293130cc12912d0f406f051de5e7b6c738a54b3296b9ad18e7da334
thunk_266740:
0x266740: JMP 0x00679190
; END FUNCTION thunk_266740
0x266745: INT3 ; original byte CC, padding
0x266746: INT3 ; original byte CC, padding
0x266747: INT3 ; original byte CC, padding

; FUNCTION thunk_266748 [0x266748, 0x26674c] | file +0x7d0 | ev_2d90ddd75a522af0bb29971ceb6fb5ba61df5fe33fe120ca3b3e5d7785d2fb67
thunk_266748:
0x266748: JMP 0x00679360
; END FUNCTION thunk_266748
0x26674d: INT3 ; original byte CC, padding
0x26674e: INT3 ; original byte CC, padding
0x26674f: INT3 ; original byte CC, padding

; FUNCTION thunk_266750 [0x266750, 0x266754] | file +0x7d8 | ev_01b9ec000cc30925ba3559e6be67c9cb23e822ed3521b44b10cf40b142115d81
thunk_266750:
0x266750: JMP 0x00679680
; END FUNCTION thunk_266750
0x266755: INT3 ; original byte CC, padding
0x266756: INT3 ; original byte CC, padding
0x266757: INT3 ; original byte CC, padding

; FUNCTION thunk_266758 [0x266758, 0x26675c] | file +0x7e0 | ev_d990bd8c7113bb7f5350f7d2dd0da9a70e1e61ae3bdc2023b324d40d54fd0556
thunk_266758:
0x266758: JMP 0x00033b90
; END FUNCTION thunk_266758
0x26675d: INT3 ; original byte CC, padding
0x26675e: INT3 ; original byte CC, padding
0x26675f: INT3 ; original byte CC, padding

; FUNCTION thunk_266760 [0x266760, 0x266764] | file +0x7e8 | ev_9c2f05162ca519881e4051f776fb4d5698dc9a1dbb6d322ee6281af4ba5e8feb
thunk_266760:
0x266760: JMP 0x00033ca0
; END FUNCTION thunk_266760
0x266765: INT3 ; original byte CC, padding
0x266766: INT3 ; original byte CC, padding
0x266767: INT3 ; original byte CC, padding

; FUNCTION thunk_266768 [0x266768, 0x26676c] | file +0x7f0 | ev_8a1b5cf7031b91c6ae6c5ebe0fffd22f6fa2246fe2869a1a78fd5b400a6b359e
thunk_266768:
0x266768: JMP 0x00033d20
; END FUNCTION thunk_266768
0x26676d: INT3 ; original byte CC, padding
0x26676e: INT3 ; original byte CC, padding
0x26676f: INT3 ; original byte CC, padding

; FUNCTION thunk_266770 [0x266770, 0x266774] | file +0x7f8 | ev_1f25b3b15b6f767ce17fc6cd00f20709a3a70504cb1eab6250b3a9d8f5df543a
thunk_266770:
0x266770: JMP 0x0003cf70
; END FUNCTION thunk_266770
0x266775: INT3 ; original byte CC, padding
0x266776: INT3 ; original byte CC, padding
0x266777: INT3 ; original byte CC, padding

; FUNCTION thunk_266778 [0x266778, 0x26677c] | file +0x800 | ev_1abd2480771bd0dfc44ad78a0ad8b9e76496fd5a3103f04dbfb5001838054042
thunk_266778:
0x266778: JMP 0x0003d0e0
; END FUNCTION thunk_266778
0x26677d: INT3 ; original byte CC, padding
0x26677e: INT3 ; original byte CC, padding
0x26677f: INT3 ; original byte CC, padding

; FUNCTION thunk_266780 [0x266780, 0x266784] | file +0x808 | ev_c505cc9a86f7ae4149f1e64b36bc59f5f40aa963623ba2974583c5d3e37dcf6c
thunk_266780:
0x266780: JMP 0x0003d660
; END FUNCTION thunk_266780
0x266785: INT3 ; original byte CC, padding
0x266786: INT3 ; original byte CC, padding
0x266787: INT3 ; original byte CC, padding

; FUNCTION thunk_266788 [0x266788, 0x26678c] | file +0x810 | ev_9ed81726a9363e9abf06ebf384044590c774b49373b1aff9cce434caec79de73
thunk_266788:
0x266788: JMP 0x0003e100
; END FUNCTION thunk_266788
0x26678d: INT3 ; original byte CC, padding
0x26678e: INT3 ; original byte CC, padding
0x26678f: INT3 ; original byte CC, padding

; FUNCTION thunk_266790 [0x266790, 0x266794] | file +0x818 | ev_b6d70feab26a69b46d1e60bf65b7ac8ff9e8af0f14e58083f5ca2104e00b4a77
thunk_266790:
0x266790: JMP 0x0003e160
; END FUNCTION thunk_266790
0x266795: INT3 ; original byte CC, padding
0x266796: INT3 ; original byte CC, padding
0x266797: INT3 ; original byte CC, padding

; FUNCTION thunk_266798 [0x266798, 0x26679c] | file +0x820 | ev_3a4fe1aed4181c9b36fc2d107277e19a007843c58dbc34a1b90c6b5364c25a1f
thunk_266798:
0x266798: JMP 0x0003e1c0
; END FUNCTION thunk_266798
0x26679d: INT3 ; original byte CC, padding
0x26679e: INT3 ; original byte CC, padding
0x26679f: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a0 [0x2667a0, 0x2667a4] | file +0x828 | ev_4e9ef9ebcbe1c81642627453beab0cf815cbe6b323c761944902a2e3a594e35e
thunk_2667a0:
0x2667a0: JMP 0x0003f070
; END FUNCTION thunk_2667a0
0x2667a5: INT3 ; original byte CC, padding
0x2667a6: INT3 ; original byte CC, padding
0x2667a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a8 [0x2667a8, 0x2667ac] | file +0x830 | ev_1e8d18696b5a66f44717599dfe66fa3f5647bfd731e90f4213ba0fb583230b36
thunk_2667a8:
0x2667a8: JMP 0x0003f0d0
; END FUNCTION thunk_2667a8
0x2667ad: INT3 ; original byte CC, padding
0x2667ae: INT3 ; original byte CC, padding
0x2667af: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b0 [0x2667b0, 0x2667b4] | file +0x838 | ev_694c8a603d68e5c334d648ccab1a33dedcffe9fe58ccd66f93a0e0e9f55a0532
thunk_2667b0:
0x2667b0: JMP 0x0003f4b0
; END FUNCTION thunk_2667b0
0x2667b5: INT3 ; original byte CC, padding
0x2667b6: INT3 ; original byte CC, padding
0x2667b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b8 [0x2667b8, 0x2667bc] | file +0x840 | ev_a433f0ca544c9e14c9ccf44b4ee4f0234100e7f292134e31ff932a3f92aa68ce
thunk_2667b8:
0x2667b8: JMP 0x0003f510
; END FUNCTION thunk_2667b8
0x2667bd: INT3 ; original byte CC, padding
0x2667be: INT3 ; original byte CC, padding
0x2667bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c0 [0x2667c0, 0x2667c4] | file +0x848 | ev_bea5624da2f134f28923630943d28c30f396fee0e2b4c2add7748798a411e200
thunk_2667c0:
0x2667c0: JMP 0x0003f570
; END FUNCTION thunk_2667c0
0x2667c5: INT3 ; original byte CC, padding
0x2667c6: INT3 ; original byte CC, padding
0x2667c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c8 [0x2667c8, 0x2667cc] | file +0x850 | ev_873e539dd587ac5fcd71faab8b5f3475b0c0c95679ce352316e553e65785df80
thunk_2667c8:
0x2667c8: JMP 0x0003fbb0
; END FUNCTION thunk_2667c8
0x2667cd: INT3 ; original byte CC, padding
0x2667ce: INT3 ; original byte CC, padding
0x2667cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d0 [0x2667d0, 0x2667d4] | file +0x858 | ev_d081b0d8d4dc0ccacf69699e5595f0544f500d0276055e7bf09413150e1224dd
thunk_2667d0:
0x2667d0: JMP 0x0003ffc0
; END FUNCTION thunk_2667d0
0x2667d5: INT3 ; original byte CC, padding
0x2667d6: INT3 ; original byte CC, padding
0x2667d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d8 [0x2667d8, 0x2667dc] | file +0x860 | ev_96e92b8e3e99b79413f154cc9eb3d60a8a7d646aa4515fb8fb5de63dd6d7c917
thunk_2667d8:
0x2667d8: JMP 0x00040960
; END FUNCTION thunk_2667d8
0x2667dd: INT3 ; original byte CC, padding
0x2667de: INT3 ; original byte CC, padding
0x2667df: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e0 [0x2667e0, 0x2667e4] | file +0x868 | ev_a1b1802795532978974ffc776896ea0d7761845d22797ef90473038e62d47faa
thunk_2667e0:
0x2667e0: JMP 0x00040b50
; END FUNCTION thunk_2667e0
0x2667e5: INT3 ; original byte CC, padding
0x2667e6: INT3 ; original byte CC, padding
0x2667e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e8 [0x2667e8, 0x2667ec] | file +0x870 | ev_83007fa2af45028f40282ddb2608364e94f80e2ce94687cd3f80e2b37d9e04ae
thunk_2667e8:
0x2667e8: JMP 0x00040c30
; END FUNCTION thunk_2667e8
0x2667ed: INT3 ; original byte CC, padding
0x2667ee: INT3 ; original byte CC, padding
0x2667ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f0 [0x2667f0, 0x2667f4] | file +0x878 | ev_2caf01d6b7d2a840a5c899ea1ade478a1167a6d2432c06185f6657a466a24521
thunk_2667f0:
0x2667f0: JMP 0x00041630
; END FUNCTION thunk_2667f0
0x2667f5: INT3 ; original byte CC, padding
0x2667f6: INT3 ; original byte CC, padding
0x2667f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f8 [0x2667f8, 0x2667fc] | file +0x880 | ev_2e9a02026a32f4d3595a1c8ea3741317c463c48293ad9967d64bb0c842c16bcf
thunk_2667f8:
0x2667f8: JMP 0x00041750
; END FUNCTION thunk_2667f8
0x2667fd: INT3 ; original byte CC, padding
0x2667fe: INT3 ; original byte CC, padding
0x2667ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266800 [0x266800, 0x266804] | file +0x888 | ev_b5a4bcb1d6c941a3f6d70e0062d3c0463382b61c6d39e75f8ad4575154058329
thunk_266800:
0x266800: JMP 0x00041830
; END FUNCTION thunk_266800
0x266805: INT3 ; original byte CC, padding
0x266806: INT3 ; original byte CC, padding
0x266807: INT3 ; original byte CC, padding

; FUNCTION thunk_266808 [0x266808, 0x26680c] | file +0x890 | ev_f1b081b3b9ac7495b8be40ee086537bb185a297b65b7ef087083c600fbb85b61
thunk_266808:
0x266808: JMP 0x000418c0
; END FUNCTION thunk_266808
0x26680d: INT3 ; original byte CC, padding
0x26680e: INT3 ; original byte CC, padding
0x26680f: INT3 ; original byte CC, padding

; FUNCTION thunk_266810 [0x266810, 0x266814] | file +0x898 | ev_286fd1ef6a141f6a83604ef9198646a69f86d2b579ec17a23ae6cebb467e5061
thunk_266810:
0x266810: JMP 0x00042060
; END FUNCTION thunk_266810
0x266815: INT3 ; original byte CC, padding
0x266816: INT3 ; original byte CC, padding
0x266817: INT3 ; original byte CC, padding

; FUNCTION thunk_266818 [0x266818, 0x26681c] | file +0x8a0 | ev_47935a2775d41df4f9b4c5a7174f7ec66edf37c497c637165652e966d455c6c2
thunk_266818:
0x266818: JMP 0x000424d0
; END FUNCTION thunk_266818
0x26681d: INT3 ; original byte CC, padding
0x26681e: INT3 ; original byte CC, padding
0x26681f: INT3 ; original byte CC, padding

; FUNCTION thunk_266820 [0x266820, 0x266824] | file +0x8a8 | ev_ec6ae96b47da7790af52eef03b6d449d9601b42b60ff5781510b83d5eed62146
thunk_266820:
0x266820: JMP 0x000425a0
; END FUNCTION thunk_266820
0x266825: INT3 ; original byte CC, padding
0x266826: INT3 ; original byte CC, padding
0x266827: INT3 ; original byte CC, padding

; FUNCTION thunk_266828 [0x266828, 0x26682c] | file +0x8b0 | ev_62e5f7ba42bcfbb4e746143fb9a9e26ec7bd4a12c0fbf516331bb1dba6d35663
thunk_266828:
0x266828: JMP 0x00042600
; END FUNCTION thunk_266828
0x26682d: INT3 ; original byte CC, padding
0x26682e: INT3 ; original byte CC, padding
0x26682f: INT3 ; original byte CC, padding

; FUNCTION thunk_266830 [0x266830, 0x266834] | file +0x8b8 | ev_5adad97b5e16134fb3c507782f4939f93bf7446e42819870836ccff91d30b7eb
thunk_266830:
0x266830: JMP 0x00690030
; END FUNCTION thunk_266830
0x266835: INT3 ; original byte CC, padding
0x266836: INT3 ; original byte CC, padding
0x266837: INT3 ; original byte CC, padding

; FUNCTION thunk_266838 [0x266838, 0x26683c] | file +0x8c0 | ev_816d78169618a36f8b32f4a02e164b67743d4a889459642185f582989c4af5e2
thunk_266838:
0x266838: JMP 0x00696cc0
; END FUNCTION thunk_266838
0x26683d: INT3 ; original byte CC, padding
0x26683e: INT3 ; original byte CC, padding
0x26683f: INT3 ; original byte CC, padding

; FUNCTION thunk_266840 [0x266840, 0x266844] | file +0x8c8 | ev_ac0488f3239f358372c3fe2efa4f19fad41d472d5150f8744654236f12971a58
thunk_266840:
0x266840: JMP 0x006985d0
; END FUNCTION thunk_266840
0x266845: INT3 ; original byte CC, padding
0x266846: INT3 ; original byte CC, padding
0x266847: INT3 ; original byte CC, padding

; FUNCTION thunk_266848 [0x266848, 0x26684c] | file +0x8d0 | ev_93973c149c06bf5ab4e689d9c5e3a621a45fdb016a490bd5f873537571699dde
thunk_266848:
0x266848: JMP 0x006a2050
; END FUNCTION thunk_266848
0x26684d: INT3 ; original byte CC, padding
0x26684e: INT3 ; original byte CC, padding
0x26684f: INT3 ; original byte CC, padding

; FUNCTION thunk_266850 [0x266850, 0x266854] | file +0x8d8 | ev_0384ec62f16c1b55f37f6e139cd5b347f936b71ac6d322c07912104d15839704
thunk_266850:
0x266850: JMP 0x006a22b0
; END FUNCTION thunk_266850
0x266855: INT3 ; original byte CC, padding
0x266856: INT3 ; original byte CC, padding
0x266857: INT3 ; original byte CC, padding

; FUNCTION thunk_266858 [0x266858, 0x26685c] | file +0x8e0 | ev_df166f83af68846c8787a22b60db92858c5297f11c0e5021462d71dc3a774fa4
thunk_266858:
0x266858: JMP 0x006ae640
; END FUNCTION thunk_266858
0x26685d: INT3 ; original byte CC, padding
0x26685e: INT3 ; original byte CC, padding
0x26685f: INT3 ; original byte CC, padding

; FUNCTION thunk_266860 [0x266860, 0x266864] | file +0x8e8 | ev_0fdd27d74cd24b4f8db75581de4388713e3597d065d3842c8af4f054c455ff46
thunk_266860:
0x266860: JMP 0x006ae7f0
; END FUNCTION thunk_266860
0x266865: INT3 ; original byte CC, padding
0x266866: INT3 ; original byte CC, padding
0x266867: INT3 ; original byte CC, padding

; FUNCTION thunk_266868 [0x266868, 0x26686c] | file +0x8f0 | ev_fc62fcbabf14463ab5445229b64c21674fbb7a0e14b7c8d18f89f180b63d1a35
thunk_266868:
0x266868: JMP 0x001813b0
; END FUNCTION thunk_266868
0x26686d: INT3 ; original byte CC, padding
0x26686e: INT3 ; original byte CC, padding
0x26686f: INT3 ; original byte CC, padding

; FUNCTION thunk_266870 [0x266870, 0x266874] | file +0x8f8 | ev_e2d4aad35945259cea115215ff1ab977a4b05020f234b4e2d5529ecfaf679d6c
thunk_266870:
0x266870: JMP 0x006befa0
; END FUNCTION thunk_266870
0x266875: INT3 ; original byte CC, padding
0x266876: INT3 ; original byte CC, padding
0x266877: INT3 ; original byte CC, padding

; FUNCTION thunk_266878 [0x266878, 0x26687c] | file +0x900 | ev_a3fad9735b44d843a7b2df48591f3fdd19bcad9229cd6cc9fa12ae57295fafdb
thunk_266878:
0x266878: JMP 0x00188040
; END FUNCTION thunk_266878
0x26687d: INT3 ; original byte CC, padding
0x26687e: INT3 ; original byte CC, padding
0x26687f: INT3 ; original byte CC, padding

; FUNCTION thunk_266880 [0x266880, 0x266884] | file +0x908 | ev_cb5c5a617a74303d22c2870604c190a2c74691cea1254e2590feb42cebc14908
thunk_266880:
0x266880: JMP 0x006d0b00
; END FUNCTION thunk_266880
0x266885: INT3 ; original byte CC, padding
0x266886: INT3 ; original byte CC, padding
0x266887: INT3 ; original byte CC, padding

; FUNCTION thunk_266888 [0x266888, 0x26688c] | file +0x910 | ev_0c3c38a29d01d8bdd25da4829b302df5d6745d42fe41808735ca9a72b6b3ecc5
thunk_266888:
0x266888: JMP 0x006d1100
; END FUNCTION thunk_266888
0x26688d: INT3 ; original byte CC, padding
0x26688e: INT3 ; original byte CC, padding
0x26688f: INT3 ; original byte CC, padding

; FUNCTION thunk_266890 [0x266890, 0x266894] | file +0x918 | ev_6b973f5fb069a1d3cbe8d7d4aabeb6bcee863c0240424f8a6914cece654d8dc4
thunk_266890:
0x266890: JMP 0x006d1260
; END FUNCTION thunk_266890
0x266895: INT3 ; original byte CC, padding
0x266896: INT3 ; original byte CC, padding
0x266897: INT3 ; original byte CC, padding

; FUNCTION thunk_266898 [0x266898, 0x26689c] | file +0x920 | ev_8b28ef61b7456567df4642cc9116b8671bba7aa5b95ff4372db799c6ba25dc2d
thunk_266898:
0x266898: JMP 0x006d13e0
; END FUNCTION thunk_266898
0x26689d: INT3 ; original byte CC, padding
0x26689e: INT3 ; original byte CC, padding
0x26689f: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a0 [0x2668a0, 0x2668a4] | file +0x928 | ev_fa00b3d0152f45a894b8ec075f6bf10efe75850a819b491d29e92959b6b8731f
thunk_2668a0:
0x2668a0: JMP 0x006d1520
; END FUNCTION thunk_2668a0
0x2668a5: INT3 ; original byte CC, padding
0x2668a6: INT3 ; original byte CC, padding
0x2668a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a8 [0x2668a8, 0x2668ac] | file +0x930 | ev_d78f08e03b31ffa2b2efe42a6cfb4536afb928a6c7f119a024a22b05f40899ff
thunk_2668a8:
0x2668a8: JMP 0x006d1640
; END FUNCTION thunk_2668a8
0x2668ad: INT3 ; original byte CC, padding
0x2668ae: INT3 ; original byte CC, padding
0x2668af: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b0 [0x2668b0, 0x2668b4] | file +0x938 | ev_3ed67d6c97c92967a395908a8a040edb330be148f28e2c64059b679195b59eae
thunk_2668b0:
0x2668b0: JMP 0x006d1720
; END FUNCTION thunk_2668b0
0x2668b5: INT3 ; original byte CC, padding
0x2668b6: INT3 ; original byte CC, padding
0x2668b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b8 [0x2668b8, 0x2668bc] | file +0x940 | ev_de93f54afb23cbd9b4b3762b6edbec96ba6addd3a7c90c972215bce85e5605f8
thunk_2668b8:
0x2668b8: JMP 0x006dc660
; END FUNCTION thunk_2668b8
0x2668bd: INT3 ; original byte CC, padding
0x2668be: INT3 ; original byte CC, padding
0x2668bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c0 [0x2668c0, 0x2668c4] | file +0x948 | ev_3e530c546d978a4cde1ea40098241ece409f40b0be36a2293bc70eb3a70892d2
thunk_2668c0:
0x2668c0: JMP 0x006dc690
; END FUNCTION thunk_2668c0
0x2668c5: INT3 ; original byte CC, padding
0x2668c6: INT3 ; original byte CC, padding
0x2668c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c8 [0x2668c8, 0x2668cc] | file +0x950 | ev_4029b49e23f105d9fd959b8d0e79ee611fff70d5deb5b25c1ec32f063cdbf7d2
thunk_2668c8:
0x2668c8: JMP 0x006dc6a0
; END FUNCTION thunk_2668c8
0x2668cd: INT3 ; original byte CC, padding
0x2668ce: INT3 ; original byte CC, padding
0x2668cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d0 [0x2668d0, 0x2668d4] | file +0x958 | ev_28820dcd9e75794b371215f8085c8fc2e919e52036eb5b329b5618bbecaa8502
thunk_2668d0:
0x2668d0: JMP 0x006e0920
; END FUNCTION thunk_2668d0
0x2668d5: INT3 ; original byte CC, padding
0x2668d6: INT3 ; original byte CC, padding
0x2668d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d8 [0x2668d8, 0x2668dc] | file +0x960 | ev_48d27fa99d4bfbfd01b9c0cfc4e1983ac381df090d15929fd844727932ef39f8
thunk_2668d8:
0x2668d8: JMP 0x006e1440
; END FUNCTION thunk_2668d8
0x2668dd: INT3 ; original byte CC, padding
0x2668de: INT3 ; original byte CC, padding
0x2668df: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e0 [0x2668e0, 0x2668e4] | file +0x968 | ev_7aa82add6e61823b6e8626df3d716de65e3fdba037ff334b9a282990cc834fcc
thunk_2668e0:
0x2668e0: JMP 0x006e1450
; END FUNCTION thunk_2668e0
0x2668e5: INT3 ; original byte CC, padding
0x2668e6: INT3 ; original byte CC, padding
0x2668e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e8 [0x2668e8, 0x2668ec] | file +0x970 | ev_7366c86f363f041f011d7a626d3635808a0a7efc1961a826359904110403c080
thunk_2668e8:
0x2668e8: JMP 0x00189a70
; END FUNCTION thunk_2668e8
0x2668ed: INT3 ; original byte CC, padding
0x2668ee: INT3 ; original byte CC, padding
0x2668ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f0 [0x2668f0, 0x2668f4] | file +0x978 | ev_d35c35a0ef27616e2538e5e78e8eb0d78e896dedfca6d619b3ac2c0ce3a0f144
thunk_2668f0:
0x2668f0: JMP 0x00190aa0
; END FUNCTION thunk_2668f0
0x2668f5: INT3 ; original byte CC, padding
0x2668f6: INT3 ; original byte CC, padding
0x2668f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f8 [0x2668f8, 0x2668fc] | file +0x980 | ev_285a07576ea147e47d5a4f684fda3d98049a70bc491220a6859a2ff207cf32a2
thunk_2668f8:
0x2668f8: JMP 0x00702970
; END FUNCTION thunk_2668f8
0x2668fd: INT3 ; original byte CC, padding
0x2668fe: INT3 ; original byte CC, padding
0x2668ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266900 [0x266900, 0x266904] | file +0x988 | ev_79a39a11fc3f4350741dfbe92dbb3ee9d03d1f0038ac550efcf3abe6aa034267
thunk_266900:
0x266900: JMP 0x00702d60
; END FUNCTION thunk_266900
0x266905: INT3 ; original byte CC, padding
0x266906: INT3 ; original byte CC, padding
0x266907: INT3 ; original byte CC, padding

; FUNCTION thunk_266908 [0x266908, 0x26690c] | file +0x990 | ev_c465dba0b2d910dc7e883d6f859825f028af61a03af466d233c429a1c3437066
thunk_266908:
0x266908: JMP 0x00706170
; END FUNCTION thunk_266908
0x26690d: INT3 ; original byte CC, padding
0x26690e: INT3 ; original byte CC, padding
0x26690f: INT3 ; original byte CC, padding

; FUNCTION thunk_266910 [0x266910, 0x266914] | file +0x998 | ev_ef9fedeb9e387dbcb7d3290bec8b7689777232b05d6c3bb1b117ce64c18f2c5d
thunk_266910:
0x266910: JMP 0x007061f0
; END FUNCTION thunk_266910
0x266915: INT3 ; original byte CC, padding
0x266916: INT3 ; original byte CC, padding
0x266917: INT3 ; original byte CC, padding

; FUNCTION thunk_266918 [0x266918, 0x26691c] | file +0x9a0 | ev_2af3c5ed42b89ca47470939543fcc7eb737ab28171a4cd5c8133946d4bffebc8
thunk_266918:
0x266918: JMP 0x0070ff00
; END FUNCTION thunk_266918
0x26691d: INT3 ; original byte CC, padding
0x26691e: INT3 ; original byte CC, padding
0x26691f: INT3 ; original byte CC, padding

; FUNCTION thunk_266920 [0x266920, 0x266924] | file +0x9a8 | ev_8ba8242e089252d99a8cc8a7db165be4787cdc73249a67a9d3de406b2f92243b
thunk_266920:
0x266920: JMP 0x0070ffb0
; END FUNCTION thunk_266920
0x266925: INT3 ; original byte CC, padding
0x266926: INT3 ; original byte CC, padding
0x266927: INT3 ; original byte CC, padding

; FUNCTION thunk_266928 [0x266928, 0x26692c] | file +0x9b0 | ev_bde685656623cf261c8d2a68eb1a624c013d1f1b4b0e9c0e93f302aab6068365
thunk_266928:
0x266928: JMP 0x007101c0
; END FUNCTION thunk_266928
0x26692d: INT3 ; original byte CC, padding
0x26692e: INT3 ; original byte CC, padding
0x26692f: INT3 ; original byte CC, padding

; FUNCTION thunk_266930 [0x266930, 0x266934] | file +0x9b8 | ev_b7ffb8877836166a4a685c022bc96bc3e0ab506a2439a5c6dee2f66a6ca82322
thunk_266930:
0x266930: JMP 0x00710320
; END FUNCTION thunk_266930
0x266935: INT3 ; original byte CC, padding
0x266936: INT3 ; original byte CC, padding
0x266937: INT3 ; original byte CC, padding

; FUNCTION thunk_266938 [0x266938, 0x26693c] | file +0x9c0 | ev_7f6f171a1627ab6995130bf2a96eb88ad7d18a6c294863cb2a05e16007aee4b8
thunk_266938:
0x266938: JMP 0x00712bb0
; END FUNCTION thunk_266938
0x26693d: INT3 ; original byte CC, padding
0x26693e: INT3 ; original byte CC, padding
0x26693f: INT3 ; original byte CC, padding

; FUNCTION thunk_266940 [0x266940, 0x266944] | file +0x9c8 | ev_dddfee7d6fc78e04fc2e8b6de476d83bd91928a276a0e49b68df7ca11e341a36
thunk_266940:
0x266940: JMP 0x00716360
; END FUNCTION thunk_266940
0x266945: INT3 ; original byte CC, padding
0x266946: INT3 ; original byte CC, padding
0x266947: INT3 ; original byte CC, padding

; FUNCTION thunk_266948 [0x266948, 0x26694c] | file +0x9d0 | ev_810262db33bcfe19b9125a9a40bfbc0dcf0ca1d8f07ea1083aa8eb64c2683ed7
thunk_266948:
0x266948: JMP 0x0072f970
; END FUNCTION thunk_266948
0x26694d: INT3 ; original byte CC, padding
0x26694e: INT3 ; original byte CC, padding
0x26694f: INT3 ; original byte CC, padding

; FUNCTION thunk_266950 [0x266950, 0x266954] | file +0x9d8 | ev_bb75578d2158f4a93fd8ad186335b68f4e86e611e1046b5612d66d40e6f42c05
thunk_266950:
0x266950: JMP 0x0072f990
; END FUNCTION thunk_266950
0x266955: INT3 ; original byte CC, padding
0x266956: INT3 ; original byte CC, padding
0x266957: INT3 ; original byte CC, padding

; FUNCTION thunk_266958 [0x266958, 0x26695c] | file +0x9e0 | ev_cc7869a755aa94e9948250e267657fb3484ae5d84c3939e93ee81e25a17c6658
thunk_266958:
0x266958: JMP 0x0072fa20
; END FUNCTION thunk_266958
0x26695d: INT3 ; original byte CC, padding
0x26695e: INT3 ; original byte CC, padding
0x26695f: INT3 ; original byte CC, padding

; FUNCTION thunk_266960 [0x266960, 0x266964] | file +0x9e8 | ev_d41be3a77fe7d970714413a2db7362e7378afaf1c234aca1fb495459da2981f4
thunk_266960:
0x266960: JMP 0x00246e30
; END FUNCTION thunk_266960
0x266965: INT3 ; original byte CC, padding
0x266966: INT3 ; original byte CC, padding
0x266967: INT3 ; original byte CC, padding

; FUNCTION thunk_266968 [0x266968, 0x26696c] | file +0x9f0 | ev_86447051030d85af30d27f1ae658d2b53230586b68e795e6877819c143272823
thunk_266968:
0x266968: JMP 0x007647f0
; END FUNCTION thunk_266968
0x26696d: INT3 ; original byte CC, padding
0x26696e: INT3 ; original byte CC, padding
0x26696f: INT3 ; original byte CC, padding

; FUNCTION thunk_266970 [0x266970, 0x266974] | file +0x9f8 | ev_8f35ce01a7e76f246111c0713a73ab48052fb3758ed42ddf08dadd78f3ee8b2e
thunk_266970:
0x266970: JMP 0x00773710
; END FUNCTION thunk_266970
0x266975: INT3 ; original byte CC, padding
0x266976: INT3 ; original byte CC, padding
0x266977: INT3 ; original byte CC, padding

; FUNCTION thunk_266978 [0x266978, 0x26697c] | file +0xa00 | ev_67777dd4e1619b577951547dcecfe4e41541a70e9352d9f4fd8e4c18c15e790e
thunk_266978:
0x266978: JMP 0x00775950
; END FUNCTION thunk_266978
0x26697d: INT3 ; original byte CC, padding
0x26697e: INT3 ; original byte CC, padding
0x26697f: INT3 ; original byte CC, padding

; FUNCTION thunk_266980 [0x266980, 0x266984] | file +0xa08 | ev_cc4f8e212f24a3d2a05a7ecfa0364795c5246f50343e1d895d0b927b5e9acbd9
thunk_266980:
0x266980: JMP 0x00799e90
; END FUNCTION thunk_266980
0x266985: INT3 ; original byte CC, padding
0x266986: INT3 ; original byte CC, padding
0x266987: INT3 ; original byte CC, padding

; FUNCTION thunk_266988 [0x266988, 0x26698c] | file +0xa10 | ev_18e241da46f5f68857625524ec967ff69786cb909ac6fa9f4ea3613ff4a373f6
thunk_266988:
0x266988: JMP 0x007b31f0
; END FUNCTION thunk_266988
0x26698d: INT3 ; original byte CC, padding
0x26698e: INT3 ; original byte CC, padding
0x26698f: INT3 ; original byte CC, padding

; FUNCTION thunk_266990 [0x266990, 0x266994] | file +0xa18 | ev_146209dccae72ac346c363a14fb22c9ebcf1badb24f205149cd1c2a71f73eb10
thunk_266990:
0x266990: JMP 0x007e23a0
; END FUNCTION thunk_266990
0x266995: INT3 ; original byte CC, padding
0x266996: INT3 ; original byte CC, padding
0x266997: INT3 ; original byte CC, padding

; FUNCTION thunk_266998 [0x266998, 0x26699c] | file +0xa20 | ev_07c806b885fdfad9a042087c47d941e3e27815570df71456554ae5f777e04f8a
thunk_266998:
0x266998: JMP 0x007e83e0
; END FUNCTION thunk_266998
0x26699d: INT3 ; original byte CC, padding
0x26699e: INT3 ; original byte CC, padding
0x26699f: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a0 [0x2669a0, 0x2669a4] | file +0xa28 | ev_be089efb1d3a783630ff9eb8e152388777867284e2e50833db979df30666a4fd
thunk_2669a0:
0x2669a0: JMP 0x007e8480
; END FUNCTION thunk_2669a0
0x2669a5: INT3 ; original byte CC, padding
0x2669a6: INT3 ; original byte CC, padding
0x2669a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a8 [0x2669a8, 0x2669ac] | file +0xa30 | ev_7a3ddf208002c5329e2906aceffed7dd3678f5bd7961d84302be0c17c52ea09f
thunk_2669a8:
0x2669a8: JMP 0x00c3b1b0
; END FUNCTION thunk_2669a8
0x2669ad: INT3 ; original byte CC, padding
0x2669ae: INT3 ; original byte CC, padding
0x2669af: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b0 [0x2669b0, 0x2669b4] | file +0xa38 | ev_bdb5f83bfc4dba4e75e19a3eef1d072394dabaa2ee2f9f656e038f3f43a9e595
thunk_2669b0:
0x2669b0: JMP 0x00c3c6e0
; END FUNCTION thunk_2669b0
0x2669b5: INT3 ; original byte CC, padding
0x2669b6: INT3 ; original byte CC, padding
0x2669b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b8 [0x2669b8, 0x2669bc] | file +0xa40 | ev_646a44996bac41d97d6bd466d9d89c6be5622fab00f3833056200cf520b54fe4
thunk_2669b8:
0x2669b8: JMP 0x00c3c690
; END FUNCTION thunk_2669b8
0x2669bd: INT3 ; original byte CC, padding
0x2669be: INT3 ; original byte CC, padding
0x2669bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c0 [0x2669c0, 0x2669c4] | file +0xa48 | ev_4362cb7f40b9eb146fac45118d165bc73bbc51e4d24d0134492add8ca5631b95
thunk_2669c0:
0x2669c0: JMP 0x00c3c730
; END FUNCTION thunk_2669c0
0x2669c5: INT3 ; original byte CC, padding
0x2669c6: INT3 ; original byte CC, padding
0x2669c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c8 [0x2669c8, 0x2669cc] | file +0xa50 | ev_a2defbb92015ed92c0ef482352ca69c0fb501a1cbddcc98ea3de49ae7ad35628
thunk_2669c8:
0x2669c8: JMP 0x00802220
; END FUNCTION thunk_2669c8
0x2669cd: INT3 ; original byte CC, padding
0x2669ce: INT3 ; original byte CC, padding
0x2669cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d0 [0x2669d0, 0x2669d4] | file +0xa58 | ev_8b0d6c0754c0b3b0f5920be4785507c6b59ae0d16e34c3c88580ef5102aa7c09
thunk_2669d0:
0x2669d0: JMP 0x008024f0
; END FUNCTION thunk_2669d0
0x2669d5: INT3 ; original byte CC, padding
0x2669d6: INT3 ; original byte CC, padding
0x2669d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d8 [0x2669d8, 0x2669dc] | file +0xa60 | ev_ad2127f94361c94e9ea3ce28f07b62b5f86902733f265d7410b1b50d7c2dcf34
thunk_2669d8:
0x2669d8: JMP 0x0080c570
; END FUNCTION thunk_2669d8
0x2669dd: INT3 ; original byte CC, padding
0x2669de: INT3 ; original byte CC, padding
0x2669df: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e0 [0x2669e0, 0x2669e4] | file +0xa68 | ev_107ae0a63c11b3b92fc64c7be5323a3eb435cad4abf4cfab408f51f081534354
thunk_2669e0:
0x2669e0: JMP 0x0082b300
; END FUNCTION thunk_2669e0
0x2669e5: INT3 ; original byte CC, padding
0x2669e6: INT3 ; original byte CC, padding
0x2669e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e8 [0x2669e8, 0x2669ec] | file +0xa70 | ev_9ad5a3b6afeb0b6f0b925f04a856e87601c2bf950f8d2fb50a65e0136f58057a
thunk_2669e8:
0x2669e8: JMP 0x00920ee0
; END FUNCTION thunk_2669e8
0x2669ed: INT3 ; original byte CC, padding
0x2669ee: INT3 ; original byte CC, padding
0x2669ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f0 [0x2669f0, 0x2669f4] | file +0xa78 | ev_a480cb6ab7d531f1320cc8242e87145c1c91b7d7a84222faf523f1c010f50494
thunk_2669f0:
0x2669f0: JMP 0x00920b90
; END FUNCTION thunk_2669f0
0x2669f5: INT3 ; original byte CC, padding
0x2669f6: INT3 ; original byte CC, padding
0x2669f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f8 [0x2669f8, 0x2669fc] | file +0xa80 | ev_063eb2665a5427fcd2306892c374cdbc281c7ad6593802712bc6c4b1efb017b7
thunk_2669f8:
0x2669f8: JMP 0x00830810
; END FUNCTION thunk_2669f8
0x2669fd: INT3 ; original byte CC, padding
0x2669fe: INT3 ; original byte CC, padding
0x2669ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266a00 [0x266a00, 0x266a04] | file +0xa88 | ev_29198ce2df122b645034527b9bb21acb52264c59b9daf0884f26625cd53e0086
thunk_266a00:
0x266a00: JMP 0x00830f00
; END FUNCTION thunk_266a00
0x266a05: INT3 ; original byte CC, padding
0x266a06: INT3 ; original byte CC, padding
0x266a07: INT3 ; original byte CC, padding

; FUNCTION thunk_266a08 [0x266a08, 0x266a0c] | file +0xa90 | ev_177dd7dc7b53ab81c2013acc266639880dbc8de7da863168a12b7fafb05569d0
thunk_266a08:
0x266a08: JMP 0x008352b0
; END FUNCTION thunk_266a08
0x266a0d: INT3 ; original byte CC, padding
0x266a0e: INT3 ; original byte CC, padding
0x266a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a10 [0x266a10, 0x266a14] | file +0xa98 | ev_0d5315ab6a16e41f21449cd36ebc5a3310ea3b201b5c2822cc1967b87fc5175d
thunk_266a10:
0x266a10: JMP 0x008352c0
; END FUNCTION thunk_266a10
0x266a15: INT3 ; original byte CC, padding
0x266a16: INT3 ; original byte CC, padding
0x266a17: INT3 ; original byte CC, padding

; FUNCTION thunk_266a18 [0x266a18, 0x266a1c] | file +0xaa0 | ev_ec8c18935f45a48774dc5e604617b4fa54ed540c1146049e3259786a4611c0fe
thunk_266a18:
0x266a18: JMP 0x008352d0
; END FUNCTION thunk_266a18
0x266a1d: INT3 ; original byte CC, padding
0x266a1e: INT3 ; original byte CC, padding
0x266a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a20 [0x266a20, 0x266a24] | file +0xaa8 | ev_67ccf19ae6261c26c1b465c290344d75286d87b8463b67ce27a2a00d373f25e1
thunk_266a20:
0x266a20: JMP 0x008352f0
; END FUNCTION thunk_266a20
0x266a25: INT3 ; original byte CC, padding
0x266a26: INT3 ; original byte CC, padding
0x266a27: INT3 ; original byte CC, padding

; FUNCTION thunk_266a28 [0x266a28, 0x266a2c] | file +0xab0 | ev_0fc4c28b309099d4fef2aa0441aada55fdb833e87dd6e611d54d6ce100ee2603
thunk_266a28:
0x266a28: JMP 0x00835440
; END FUNCTION thunk_266a28
0x266a2d: INT3 ; original byte CC, padding
0x266a2e: INT3 ; original byte CC, padding
0x266a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a30 [0x266a30, 0x266a34] | file +0xab8 | ev_b30b9cb2f6b10209ccef36a80c6226dec9100c5cdf04f409483c5df6c8d721cb
thunk_266a30:
0x266a30: JMP 0x00835450
; END FUNCTION thunk_266a30
0x266a35: INT3 ; original byte CC, padding
0x266a36: INT3 ; original byte CC, padding
0x266a37: INT3 ; original byte CC, padding

; FUNCTION thunk_266a38 [0x266a38, 0x266a3c] | file +0xac0 | ev_1c89747d1cc419c82f65552dd5e9f398d08b9dd3c158550837d6d077fe5f1f9a
thunk_266a38:
0x266a38: JMP 0x00835490
; END FUNCTION thunk_266a38
0x266a3d: INT3 ; original byte CC, padding
0x266a3e: INT3 ; original byte CC, padding
0x266a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a40 [0x266a40, 0x266a44] | file +0xac8 | ev_86c79d8831758bb566d4330365abf0f4f2fdd5f6cecd088a67fe9b63cbdb7eb7
thunk_266a40:
0x266a40: JMP 0x00835ad0
; END FUNCTION thunk_266a40
0x266a45: INT3 ; original byte CC, padding
0x266a46: INT3 ; original byte CC, padding
0x266a47: INT3 ; original byte CC, padding

; FUNCTION thunk_266a48 [0x266a48, 0x266a4c] | file +0xad0 | ev_995c50dcb18c9069c8f14612d6a1455003ea69b54876567c1e823ec636e9aa48
thunk_266a48:
0x266a48: JMP 0x00850870
; END FUNCTION thunk_266a48
0x266a4d: INT3 ; original byte CC, padding
0x266a4e: INT3 ; original byte CC, padding
0x266a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a50 [0x266a50, 0x266a54] | file +0xad8 | ev_5e329a7f38c7891bcb76d5475bccd7ac8a8253c93b2384eb3199eed3c1d6eb2c
thunk_266a50:
0x266a50: JMP 0x008702f0
; END FUNCTION thunk_266a50
0x266a55: INT3 ; original byte CC, padding
0x266a56: INT3 ; original byte CC, padding
0x266a57: INT3 ; original byte CC, padding

; FUNCTION thunk_266a58 [0x266a58, 0x266a5c] | file +0xae0 | ev_e0a5532f5aff1a4a2ee764559daee4f819665087f4630c432530d3cf5486f063
thunk_266a58:
0x266a58: JMP 0x008705d0
; END FUNCTION thunk_266a58
0x266a5d: INT3 ; original byte CC, padding
0x266a5e: INT3 ; original byte CC, padding
0x266a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a60 [0x266a60, 0x266a64] | file +0xae8 | ev_80548a6b40dfc2aeef643069f1ecbfbcaa660deb693d6dfc073b9d3e218c7cb8
thunk_266a60:
0x266a60: JMP 0x00872af0
; END FUNCTION thunk_266a60
0x266a65: INT3 ; original byte CC, padding
0x266a66: INT3 ; original byte CC, padding
0x266a67: INT3 ; original byte CC, padding

; FUNCTION thunk_266a68 [0x266a68, 0x266a6c] | file +0xaf0 | ev_8a91bd014432af5bccf4cd9785804c8daa7551ec5454259f0d263e139613a20a
thunk_266a68:
0x266a68: JMP 0x00873800
; END FUNCTION thunk_266a68
0x266a6d: INT3 ; original byte CC, padding
0x266a6e: INT3 ; original byte CC, padding
0x266a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a70 [0x266a70, 0x266a74] | file +0xaf8 | ev_ace7e386aef97a8938bc5277da2304ae349721e0be6629dfaab82c91e9879fe3
thunk_266a70:
0x266a70: JMP 0x00063a40
; END FUNCTION thunk_266a70
0x266a75: INT3 ; original byte CC, padding
0x266a76: INT3 ; original byte CC, padding
0x266a77: INT3 ; original byte CC, padding

; FUNCTION thunk_266a78 [0x266a78, 0x266a7c] | file +0xb00 | ev_4f9cbc3755ffa00d9bc90c78dd059443d243871133d78ad726b0b8a1fa8c59f1
thunk_266a78:
0x266a78: JMP 0x00066370
; END FUNCTION thunk_266a78
0x266a7d: INT3 ; original byte CC, padding
0x266a7e: INT3 ; original byte CC, padding
0x266a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a80 [0x266a80, 0x266a84] | file +0xb08 | ev_d1253b2b6a410cdb32f733044e199ff7bc1b88e3fa164e1a9321bfe29d2701a4
thunk_266a80:
0x266a80: JMP 0x000e6590
; END FUNCTION thunk_266a80
0x266a85: INT3 ; original byte CC, padding
0x266a86: INT3 ; original byte CC, padding
0x266a87: INT3 ; original byte CC, padding

; FUNCTION thunk_266a88 [0x266a88, 0x266a8c] | file +0xb10 | ev_a70131a343e30187fec4ee4ddd3e10432a8d5db8f7b758eaf398ef0ff9545c41
thunk_266a88:
0x266a88: JMP 0x000e65a0
; END FUNCTION thunk_266a88
0x266a8d: INT3 ; original byte CC, padding
0x266a8e: INT3 ; original byte CC, padding
0x266a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a90 [0x266a90, 0x266a94] | file +0xb18 | ev_580401ac889df9a5a5a73e71f8edea677b42be167a238dc2dff457a9c9f336ff
thunk_266a90:
0x266a90: JMP 0x000e6760
; END FUNCTION thunk_266a90
0x266a95: INT3 ; original byte CC, padding
0x266a96: INT3 ; original byte CC, padding
0x266a97: INT3 ; original byte CC, padding

; FUNCTION thunk_266a98 [0x266a98, 0x266a9c] | file +0xb20 | ev_172618d9f6bde68af37706eabeedff3f52d26fe1bfb0328d5fe417c3de8cfab0
thunk_266a98:
0x266a98: JMP 0x000e6870
; END FUNCTION thunk_266a98
0x266a9d: INT3 ; original byte CC, padding
0x266a9e: INT3 ; original byte CC, padding
0x266a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa0 [0x266aa0, 0x266aa4] | file +0xb28 | ev_b1e956b19177c725cc5b0de3abaf0d87a3b82bb14d6e9f4ec8831e2d91b54c47
thunk_266aa0:
0x266aa0: JMP 0x000e7f90
; END FUNCTION thunk_266aa0
0x266aa5: INT3 ; original byte CC, padding
0x266aa6: INT3 ; original byte CC, padding
0x266aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa8 [0x266aa8, 0x266aac] | file +0xb30 | ev_cb2f12ba0838083ded8dec004c46678be74c9abcc86c76566af579016dba3da5
thunk_266aa8:
0x266aa8: JMP 0x000e9fa0
; END FUNCTION thunk_266aa8
0x266aad: INT3 ; original byte CC, padding
0x266aae: INT3 ; original byte CC, padding
0x266aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab0 [0x266ab0, 0x266ab4] | file +0xb38 | ev_a3052214a521cc3208409e021fa100a76d9261caf5a168a1b72d321750d2b45b
thunk_266ab0:
0x266ab0: JMP 0x000ea670
; END FUNCTION thunk_266ab0
0x266ab5: INT3 ; original byte CC, padding
0x266ab6: INT3 ; original byte CC, padding
0x266ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab8 [0x266ab8, 0x266abc] | file +0xb40 | ev_ab5d43e0a40ba98e026fe8788b90cb6bded3dbb9083f30de951f5b55b6611259
thunk_266ab8:
0x266ab8: JMP 0x000ea760
; END FUNCTION thunk_266ab8
0x266abd: INT3 ; original byte CC, padding
0x266abe: INT3 ; original byte CC, padding
0x266abf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac0 [0x266ac0, 0x266ac4] | file +0xb48 | ev_dfd025dd38eb834c1c4d4e37cf5c20a054f6b368c99fd5c1fcf91a2b04bdb89b
thunk_266ac0:
0x266ac0: JMP 0x000eb0a0
; END FUNCTION thunk_266ac0
0x266ac5: INT3 ; original byte CC, padding
0x266ac6: INT3 ; original byte CC, padding
0x266ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac8 [0x266ac8, 0x266acc] | file +0xb50 | ev_0ba290f61e689c4ddfbc0e9dcd74c90382de6a3844dbe481dd4b5f0c00a605c2
thunk_266ac8:
0x266ac8: JMP 0x000eb190
; END FUNCTION thunk_266ac8
0x266acd: INT3 ; original byte CC, padding
0x266ace: INT3 ; original byte CC, padding
0x266acf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad0 [0x266ad0, 0x266ad4] | file +0xb58 | ev_c7f735b31597949f8b3d8f12d6282e1f65af64f8d580a8b0a79e0b9dc7e33794
thunk_266ad0:
0x266ad0: JMP 0x000ed000
; END FUNCTION thunk_266ad0
0x266ad5: INT3 ; original byte CC, padding
0x266ad6: INT3 ; original byte CC, padding
0x266ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad8 [0x266ad8, 0x266adc] | file +0xb60 | ev_3696ca577c07d3cd8b4dd4f5e7485fc4ccec33eea40a7e33578374e1d59a95f4
thunk_266ad8:
0x266ad8: JMP 0x000ed110
; END FUNCTION thunk_266ad8
0x266add: INT3 ; original byte CC, padding
0x266ade: INT3 ; original byte CC, padding
0x266adf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae0 [0x266ae0, 0x266ae4] | file +0xb68 | ev_3540435ffca26bbb8b563d995bb2524984e42644dbbb93606680668159825e87
thunk_266ae0:
0x266ae0: JMP 0x0088a8a0
; END FUNCTION thunk_266ae0
0x266ae5: INT3 ; original byte CC, padding
0x266ae6: INT3 ; original byte CC, padding
0x266ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae8 [0x266ae8, 0x266aec] | file +0xb70 | ev_54ff9ea03fe46568160ea2de9f8a562e1d312294a5ade2a6b4bdcdada49b1f8c
thunk_266ae8:
0x266ae8: JMP 0x0089cdf0
; END FUNCTION thunk_266ae8
0x266aed: INT3 ; original byte CC, padding
0x266aee: INT3 ; original byte CC, padding
0x266aef: INT3 ; original byte CC, padding

; FUNCTION thunk_266af0 [0x266af0, 0x266af4] | file +0xb78 | ev_e99f643f0db2c0d24db4fcaf3b5de144991b1adc450c03f6d71331e88d5c9524
thunk_266af0:
0x266af0: JMP 0x000eeb50
; END FUNCTION thunk_266af0
0x266af5: INT3 ; original byte CC, padding
0x266af6: INT3 ; original byte CC, padding
0x266af7: INT3 ; original byte CC, padding

; FUNCTION thunk_266af8 [0x266af8, 0x266afc] | file +0xb80 | ev_7e7fe8b4dde4de2281a4f4bd9bdf5add95be25e22ea62e2e3998fb3936a080ff
thunk_266af8:
0x266af8: JMP 0x008cb250
; END FUNCTION thunk_266af8
0x266afd: INT3 ; original byte CC, padding
0x266afe: INT3 ; original byte CC, padding
0x266aff: INT3 ; original byte CC, padding

; FUNCTION thunk_266b00 [0x266b00, 0x266b04] | file +0xb88 | ev_253a16e4058f7de88d51b504ce6a1bacc5be58252642dbbbeee6505711d0648a
thunk_266b00:
0x266b00: JMP 0x008cb390
; END FUNCTION thunk_266b00
0x266b05: INT3 ; original byte CC, padding
0x266b06: INT3 ; original byte CC, padding
0x266b07: INT3 ; original byte CC, padding

; FUNCTION thunk_266b08 [0x266b08, 0x266b0c] | file +0xb90 | ev_fea9d8ff31d0c4fdadf83b22e249aee209225d68e062e0fa46b431c0c49c6dd8
thunk_266b08:
0x266b08: JMP 0x008d2f60
; END FUNCTION thunk_266b08
0x266b0d: INT3 ; original byte CC, padding
0x266b0e: INT3 ; original byte CC, padding
0x266b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b10 [0x266b10, 0x266b14] | file +0xb98 | ev_135119e632a722801f99ad8c2796d9c5d57282defcf1d58fc48cdc7c8e74cb29
thunk_266b10:
0x266b10: JMP 0x008d2f90
; END FUNCTION thunk_266b10
0x266b15: INT3 ; original byte CC, padding
0x266b16: INT3 ; original byte CC, padding
0x266b17: INT3 ; original byte CC, padding

; FUNCTION thunk_266b18 [0x266b18, 0x266b1c] | file +0xba0 | ev_1c2fdbeb60f49688af5703a743188a25b5530b226b89c34973c7416c1b14c502
thunk_266b18:
0x266b18: JMP 0x008d8230
; END FUNCTION thunk_266b18
0x266b1d: INT3 ; original byte CC, padding
0x266b1e: INT3 ; original byte CC, padding
0x266b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b20 [0x266b20, 0x266b24] | file +0xba8 | ev_05e0040e1f1449251377c771031f3d1467b9cea3be2dbb969252562a3d9c6a4b
thunk_266b20:
0x266b20: JMP 0x008d8de0
; END FUNCTION thunk_266b20
0x266b25: INT3 ; original byte CC, padding
0x266b26: INT3 ; original byte CC, padding
0x266b27: INT3 ; original byte CC, padding

; FUNCTION thunk_266b28 [0x266b28, 0x266b2c] | file +0xbb0 | ev_3d84d0e832dea1f4393c51cf621401b1efd43c186c59c97d0e1290835b35a0cb
thunk_266b28:
0x266b28: JMP 0x008d97b0
; END FUNCTION thunk_266b28
0x266b2d: INT3 ; original byte CC, padding
0x266b2e: INT3 ; original byte CC, padding
0x266b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b30 [0x266b30, 0x266b34] | file +0xbb8 | ev_867be95cdeb3d9b186a680fcb42dc2eef398f6ee5999819b185940e385522a2c
thunk_266b30:
0x266b30: JMP 0x008d9910
; END FUNCTION thunk_266b30
0x266b35: INT3 ; original byte CC, padding
0x266b36: INT3 ; original byte CC, padding
0x266b37: INT3 ; original byte CC, padding

; FUNCTION thunk_266b38 [0x266b38, 0x266b3c] | file +0xbc0 | ev_98a6115dac41b7f98acf672e285af4338aa06739dcba52f9d8b424b8b65ba3c3
thunk_266b38:
0x266b38: JMP 0x008da4c0
; END FUNCTION thunk_266b38
0x266b3d: INT3 ; original byte CC, padding
0x266b3e: INT3 ; original byte CC, padding
0x266b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b40 [0x266b40, 0x266b44] | file +0xbc8 | ev_28661288bbd93c64c4601ab505454f1242fe1271953adf1d17cfaa755a4dffd0
thunk_266b40:
0x266b40: JMP 0x008da570
; END FUNCTION thunk_266b40
0x266b45: INT3 ; original byte CC, padding
0x266b46: INT3 ; original byte CC, padding
0x266b47: INT3 ; original byte CC, padding

; FUNCTION thunk_266b48 [0x266b48, 0x266b4c] | file +0xbd0 | ev_bd344f0bd9ec7d067a0cb4c8208d913f749af95b11793f5da2827e74faf79109
thunk_266b48:
0x266b48: JMP 0x008da5b0
; END FUNCTION thunk_266b48
0x266b4d: INT3 ; original byte CC, padding
0x266b4e: INT3 ; original byte CC, padding
0x266b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b50 [0x266b50, 0x266b54] | file +0xbd8 | ev_f8a42572829c10ec77ab49408e31d2ffb005a17eb5e53f6695770add06be8082
thunk_266b50:
0x266b50: JMP 0x00904c80
; END FUNCTION thunk_266b50
0x266b55: INT3 ; original byte CC, padding
0x266b56: INT3 ; original byte CC, padding
0x266b57: INT3 ; original byte CC, padding

; FUNCTION thunk_266b58 [0x266b58, 0x266b5c] | file +0xbe0 | ev_8a13f5a851e775e80be452193fbd4d590b6d04ccbc7dff49f1656f50ed85ff91
thunk_266b58:
0x266b58: JMP 0x00904e60
; END FUNCTION thunk_266b58
0x266b5d: INT3 ; original byte CC, padding
0x266b5e: INT3 ; original byte CC, padding
0x266b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b60 [0x266b60, 0x266b64] | file +0xbe8 | ev_55a50802f4a0a58d620581bdf6d487bbdbf788f27ea4ebade9bcf71add39a1dc
thunk_266b60:
0x266b60: JMP 0x0091d400
; END FUNCTION thunk_266b60
0x266b65: INT3 ; original byte CC, padding
0x266b66: INT3 ; original byte CC, padding
0x266b67: INT3 ; original byte CC, padding

; FUNCTION thunk_266b68 [0x266b68, 0x266b6c] | file +0xbf0 | ev_a3b427a4474839c0c8a0e35e824e29e550bf1ee74d21c07a0abcdaee31a56056
thunk_266b68:
0x266b68: JMP 0x0091d4a0
; END FUNCTION thunk_266b68
0x266b6d: INT3 ; original byte CC, padding
0x266b6e: INT3 ; original byte CC, padding
0x266b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b70 [0x266b70, 0x266b74] | file +0xbf8 | ev_e8467fac24f549ccc576dbf816d0d2d2ccd83f5700eb06faa6c91121b928fdd0
thunk_266b70:
0x266b70: JMP 0x00a821d0
; END FUNCTION thunk_266b70
0x266b75: INT3 ; original byte CC, padding
0x266b76: INT3 ; original byte CC, padding
0x266b77: INT3 ; original byte CC, padding

; FUNCTION thunk_266b78 [0x266b78, 0x266b7c] | file +0xc00 | ev_8f47985372645d0671a737f6dfdc8c8ebd02beaa2f6b203fa63da2a5b8f22e7b
thunk_266b78:
0x266b78: JMP 0x00b42120
; END FUNCTION thunk_266b78
0x266b7d: INT3 ; original byte CC, padding
0x266b7e: INT3 ; original byte CC, padding
0x266b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b80 [0x266b80, 0x266b84] | file +0xc08 | ev_fd684889e15d4b26e0ee82dee8ba632bc13425741ac010622add8dae7219815d
thunk_266b80:
0x266b80: JMP 0x00964f30
; END FUNCTION thunk_266b80
0x266b85: INT3 ; original byte CC, padding
0x266b86: INT3 ; original byte CC, padding
0x266b87: INT3 ; original byte CC, padding

; FUNCTION thunk_266b88 [0x266b88, 0x266b8c] | file +0xc10 | ev_f2df38026d5491e448e5063aac5789ad983601c453d578988858f92b6d03ae2c
thunk_266b88:
0x266b88: JMP 0x00975f50
; END FUNCTION thunk_266b88
0x266b8d: INT3 ; original byte CC, padding
0x266b8e: INT3 ; original byte CC, padding
0x266b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b90 [0x266b90, 0x266b94] | file +0xc18 | ev_10d8a996d05141151a80648eaa04914a17d0858789d77b5b14476705981530fe
thunk_266b90:
0x266b90: JMP 0x00976200
; END FUNCTION thunk_266b90
0x266b95: INT3 ; original byte CC, padding
0x266b96: INT3 ; original byte CC, padding
0x266b97: INT3 ; original byte CC, padding

; FUNCTION thunk_266b98 [0x266b98, 0x266b9c] | file +0xc20 | ev_c3116b49143e9b6ff94c37355177e2bdb67bb1b2e76d75c69776fb7bb325b566
thunk_266b98:
0x266b98: JMP 0x0098c950
; END FUNCTION thunk_266b98
0x266b9d: INT3 ; original byte CC, padding
0x266b9e: INT3 ; original byte CC, padding
0x266b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba0 [0x266ba0, 0x266ba4] | file +0xc28 | ev_d5357955364e0302a1c35a09ecc6540c8689b4e80dfafeb3e3bdcbaf003676e0
thunk_266ba0:
0x266ba0: JMP 0x0098cc30
; END FUNCTION thunk_266ba0
0x266ba5: INT3 ; original byte CC, padding
0x266ba6: INT3 ; original byte CC, padding
0x266ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba8 [0x266ba8, 0x266bac] | file +0xc30 | ev_7eb181636e2cdb2333dd763ae4894fc17222923d697e92963d6ba4b611dcda21
thunk_266ba8:
0x266ba8: JMP 0x0098cf30
; END FUNCTION thunk_266ba8
0x266bad: INT3 ; original byte CC, padding
0x266bae: INT3 ; original byte CC, padding
0x266baf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb0 [0x266bb0, 0x266bb4] | file +0xc38 | ev_2f19404c650e0b9290f01b624e2d3247ddfabf77eef32e16a5484806b710f012
thunk_266bb0:
0x266bb0: JMP 0x0098d6e0
; END FUNCTION thunk_266bb0
0x266bb5: INT3 ; original byte CC, padding
0x266bb6: INT3 ; original byte CC, padding
0x266bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb8 [0x266bb8, 0x266bbc] | file +0xc40 | ev_b05bb4840cd18187e9cfeab82d33fe5e27867653043f55bd77bb02218ee6fb15
thunk_266bb8:
0x266bb8: JMP 0x0098e5d0
; END FUNCTION thunk_266bb8
0x266bbd: INT3 ; original byte CC, padding
0x266bbe: INT3 ; original byte CC, padding
0x266bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc0 [0x266bc0, 0x266bc4] | file +0xc48 | ev_79af95be2d186c085c2c3aeced8a2aeeb8b6718f7d34419ecbb36bf6ed2a29e6
thunk_266bc0:
0x266bc0: JMP 0x0098e700
; END FUNCTION thunk_266bc0
0x266bc5: INT3 ; original byte CC, padding
0x266bc6: INT3 ; original byte CC, padding
0x266bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc8 [0x266bc8, 0x266bcc] | file +0xc50 | ev_8341b535cc158bc64ba7d262cb376e3cec41502b7caeb9d18b2601d189b8c5c3
thunk_266bc8:
0x266bc8: JMP 0x00992170
; END FUNCTION thunk_266bc8
0x266bcd: INT3 ; original byte CC, padding
0x266bce: INT3 ; original byte CC, padding
0x266bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd0 [0x266bd0, 0x266bd4] | file +0xc58 | ev_e166acea8ad67d05799944a6f7fdd59ec5f3b1ac8764a5c1c9aab83775552d58
thunk_266bd0:
0x266bd0: JMP 0x00992240
; END FUNCTION thunk_266bd0
0x266bd5: INT3 ; original byte CC, padding
0x266bd6: INT3 ; original byte CC, padding
0x266bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd8 [0x266bd8, 0x266bdc] | file +0xc60 | ev_85e73f067c4170bb5b3458130fd57a6af13915d7b31859b4fc64c3f06ed82bac
thunk_266bd8:
0x266bd8: JMP 0x000f5400
; END FUNCTION thunk_266bd8
0x266bdd: INT3 ; original byte CC, padding
0x266bde: INT3 ; original byte CC, padding
0x266bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266be0 [0x266be0, 0x266be4] | file +0xc68 | ev_842b4c5c42c065668d984eae4c9142db76b388ac3869191a2e6774a1dd29092b
thunk_266be0:
0x266be0: JMP 0x009a2320
; END FUNCTION thunk_266be0
0x266be5: INT3 ; original byte CC, padding
0x266be6: INT3 ; original byte CC, padding
0x266be7: INT3 ; original byte CC, padding

; FUNCTION thunk_266be8 [0x266be8, 0x266bec] | file +0xc70 | ev_030a86c722bd8b0115511456a8e9c167e2fcee9c0bc3fef7480f00c92d243c2a
thunk_266be8:
0x266be8: JMP 0x009a5720
; END FUNCTION thunk_266be8
0x266bed: INT3 ; original byte CC, padding
0x266bee: INT3 ; original byte CC, padding
0x266bef: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf0 [0x266bf0, 0x266bf4] | file +0xc78 | ev_b7ba618ae2aa9e42f6dc5f460eacabc57ff16a7d0aa334b8901473386f810008
thunk_266bf0:
0x266bf0: JMP 0x009ac9a0
; END FUNCTION thunk_266bf0
0x266bf5: INT3 ; original byte CC, padding
0x266bf6: INT3 ; original byte CC, padding
0x266bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf8 [0x266bf8, 0x266bfc] | file +0xc80 | ev_7b6dffa6d17e048eb0c5c66d7ff1892a62f7829978e4d399fec5e56368c85598
thunk_266bf8:
0x266bf8: JMP 0x009aca20
; END FUNCTION thunk_266bf8
0x266bfd: INT3 ; original byte CC, padding
0x266bfe: INT3 ; original byte CC, padding
0x266bff: INT3 ; original byte CC, padding

; FUNCTION thunk_266c00 [0x266c00, 0x266c04] | file +0xc88 | ev_37e32afc32cbfcefa497814dc4c10dc93a73d1b39133f84aeeb295f99deb9227
thunk_266c00:
0x266c00: JMP 0x001be640
; END FUNCTION thunk_266c00
0x266c05: INT3 ; original byte CC, padding
0x266c06: INT3 ; original byte CC, padding
0x266c07: INT3 ; original byte CC, padding

; FUNCTION thunk_266c08 [0x266c08, 0x266c0c] | file +0xc90 | ev_8dcbff7b878d9c7260555fdb740b8c9f57eb3ce3f0cd403b4e34d3dc8444893d
thunk_266c08:
0x266c08: JMP 0x009bed20
; END FUNCTION thunk_266c08
0x266c0d: INT3 ; original byte CC, padding
0x266c0e: INT3 ; original byte CC, padding
0x266c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c10 [0x266c10, 0x266c14] | file +0xc98 | ev_5609616af12540e3f21ffdb1c4ee50798b97a80d28d9e70d0e40685b3d52ea7b
thunk_266c10:
0x266c10: JMP 0x009c6050
; END FUNCTION thunk_266c10
0x266c15: INT3 ; original byte CC, padding
0x266c16: INT3 ; original byte CC, padding
0x266c17: INT3 ; original byte CC, padding

; FUNCTION thunk_266c18 [0x266c18, 0x266c1c] | file +0xca0 | ev_8fbdeb0835724f32a8b17a3c5d39a5e952abf35119874527c7bf6b3d2f410f4d
thunk_266c18:
0x266c18: JMP 0x009c60d0
; END FUNCTION thunk_266c18
0x266c1d: INT3 ; original byte CC, padding
0x266c1e: INT3 ; original byte CC, padding
0x266c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c20 [0x266c20, 0x266c24] | file +0xca8 | ev_ace2b7677c241f86357c44b9f6ffb12c616d9a72f498b23035be4fb0262a687f
thunk_266c20:
0x266c20: JMP 0x009c6280
; END FUNCTION thunk_266c20
0x266c25: INT3 ; original byte CC, padding
0x266c26: INT3 ; original byte CC, padding
0x266c27: INT3 ; original byte CC, padding

; FUNCTION thunk_266c28 [0x266c28, 0x266c2c] | file +0xcb0 | ev_7a3062ecd30b0df2a6122e8f59b5953527a185a8647d27426de7edb4c906b7d7
thunk_266c28:
0x266c28: JMP 0x009c6310
; END FUNCTION thunk_266c28
0x266c2d: INT3 ; original byte CC, padding
0x266c2e: INT3 ; original byte CC, padding
0x266c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c30 [0x266c30, 0x266c34] | file +0xcb8 | ev_dfe29f719b7475feed102705faecbfb48a5fb5cabcf650e8b213eddc01c64181
thunk_266c30:
0x266c30: JMP 0x009c6490
; END FUNCTION thunk_266c30
0x266c35: INT3 ; original byte CC, padding
0x266c36: INT3 ; original byte CC, padding
0x266c37: INT3 ; original byte CC, padding

; FUNCTION thunk_266c38 [0x266c38, 0x266c3c] | file +0xcc0 | ev_f2fead07eb766b1364e16b243079bc9aa5d3876480b0d12b25b3c132c3754268
thunk_266c38:
0x266c38: JMP 0x009c65b0
; END FUNCTION thunk_266c38
0x266c3d: INT3 ; original byte CC, padding
0x266c3e: INT3 ; original byte CC, padding
0x266c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c40 [0x266c40, 0x266c44] | file +0xcc8 | ev_c68ed7ba26444d1752bf6058fc28ab01a6bf926027464b2ea5e375f261cacff4
thunk_266c40:
0x266c40: JMP 0x009c6890
; END FUNCTION thunk_266c40
0x266c45: INT3 ; original byte CC, padding
0x266c46: INT3 ; original byte CC, padding
0x266c47: INT3 ; original byte CC, padding

; FUNCTION thunk_266c48 [0x266c48, 0x266c4c] | file +0xcd0 | ev_67de297adfeed209dfc647b55bf4d003699078a117d7be29f97231507d06648d
thunk_266c48:
0x266c48: JMP 0x009c9340
; END FUNCTION thunk_266c48
0x266c4d: INT3 ; original byte CC, padding
0x266c4e: INT3 ; original byte CC, padding
0x266c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c50 [0x266c50, 0x266c54] | file +0xcd8 | ev_f5735fce676e82d52e4f585386bb91ed4c135c29aa338a4a56a193e57e3bc696
thunk_266c50:
0x266c50: JMP 0x009c9360
; END FUNCTION thunk_266c50
0x266c55: INT3 ; original byte CC, padding
0x266c56: INT3 ; original byte CC, padding
0x266c57: INT3 ; original byte CC, padding

; FUNCTION thunk_266c58 [0x266c58, 0x266c5c] | file +0xce0 | ev_e91b99d64f4c78087780aed0abccebaa4e78e410a865688b3acac1c9d9dbc662
thunk_266c58:
0x266c58: JMP 0x009c9370
; END FUNCTION thunk_266c58
0x266c5d: INT3 ; original byte CC, padding
0x266c5e: INT3 ; original byte CC, padding
0x266c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c60 [0x266c60, 0x266c64] | file +0xce8 | ev_b3f6589bf2526d456f9760f6654606024f8576bc26a4405284d36ac742be9973
thunk_266c60:
0x266c60: JMP 0x009c9380
; END FUNCTION thunk_266c60
0x266c65: INT3 ; original byte CC, padding
0x266c66: INT3 ; original byte CC, padding
0x266c67: INT3 ; original byte CC, padding

; FUNCTION thunk_266c68 [0x266c68, 0x266c6c] | file +0xcf0 | ev_18322b16d894e20a403d727376dae134cc622455f406447df0dcce4b12631368
thunk_266c68:
0x266c68: JMP 0x009dadb0
; END FUNCTION thunk_266c68
0x266c6d: INT3 ; original byte CC, padding
0x266c6e: INT3 ; original byte CC, padding
0x266c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c70 [0x266c70, 0x266c74] | file +0xcf8 | ev_02cfdafda2a13e9bce9c188e0d3d2ff158067964ff4148e08d6c71ef28462e5b
thunk_266c70:
0x266c70: JMP 0x009dafa0
; END FUNCTION thunk_266c70
0x266c75: INT3 ; original byte CC, padding
0x266c76: INT3 ; original byte CC, padding
0x266c77: INT3 ; original byte CC, padding

; FUNCTION thunk_266c78 [0x266c78, 0x266c7c] | file +0xd00 | ev_e8c329046ada8dfcbb218a69d95ad166cea9026c2e371cb78043976fdb141791
thunk_266c78:
0x266c78: JMP 0x009dc860
; END FUNCTION thunk_266c78
0x266c7d: INT3 ; original byte CC, padding
0x266c7e: INT3 ; original byte CC, padding
0x266c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c80 [0x266c80, 0x266c84] | file +0xd08 | ev_951c7632d5f7ac048641f115f7f022df0067f8be7557f92bc19817ba1f69dce3
thunk_266c80:
0x266c80: JMP 0x009dcc40
; END FUNCTION thunk_266c80
0x266c85: INT3 ; original byte CC, padding
0x266c86: INT3 ; original byte CC, padding
0x266c87: INT3 ; original byte CC, padding

; FUNCTION thunk_266c88 [0x266c88, 0x266c8c] | file +0xd10 | ev_cb36009f9bfc136ec5ce961b8bfce675e1359e0ba638916fd42ff816e5a29426
thunk_266c88:
0x266c88: JMP 0x009dce80
; END FUNCTION thunk_266c88
0x266c8d: INT3 ; original byte CC, padding
0x266c8e: INT3 ; original byte CC, padding
0x266c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c90 [0x266c90, 0x266c94] | file +0xd18 | ev_6cd39531681fde08c31a8a78d17c026d60656b4a04d4df9cf32e35b4ad3233b6
thunk_266c90:
0x266c90: JMP 0x009dd500
; END FUNCTION thunk_266c90
0x266c95: INT3 ; original byte CC, padding
0x266c96: INT3 ; original byte CC, padding
0x266c97: INT3 ; original byte CC, padding

; FUNCTION thunk_266c98 [0x266c98, 0x266c9c] | file +0xd20 | ev_082dedda124d393d2915851f9fde3e738185206a07e4537279f0f861e5e538ed
thunk_266c98:
0x266c98: JMP 0x00caacd0
; END FUNCTION thunk_266c98
0x266c9d: INT3 ; original byte CC, padding
0x266c9e: INT3 ; original byte CC, padding
0x266c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca0 [0x266ca0, 0x266ca4] | file +0xd28 | ev_9bc1d8d5795bb013c77f16ef99873037745952b9b9c7afd3662bb4d086d7ead5
thunk_266ca0:
0x266ca0: JMP 0x009dd7d0
; END FUNCTION thunk_266ca0
0x266ca5: INT3 ; original byte CC, padding
0x266ca6: INT3 ; original byte CC, padding
0x266ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca8 [0x266ca8, 0x266cac] | file +0xd30 | ev_17560178ac1bf83794f7f4280d1fb3fc2375e475a18a6fac6d799778c6f8ebbf
thunk_266ca8:
0x266ca8: JMP 0x009dd990
; END FUNCTION thunk_266ca8
0x266cad: INT3 ; original byte CC, padding
0x266cae: INT3 ; original byte CC, padding
0x266caf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb0 [0x266cb0, 0x266cb4] | file +0xd38 | ev_93b9cede683a5db69b3564125f37c3e108fee90298840a1378e784896a40b21a
thunk_266cb0:
0x266cb0: JMP 0x009ddba0
; END FUNCTION thunk_266cb0
0x266cb5: INT3 ; original byte CC, padding
0x266cb6: INT3 ; original byte CC, padding
0x266cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb8 [0x266cb8, 0x266cbc] | file +0xd40 | ev_17e04c234b75b5bb4b975f60d1dfe50a320d9680c9f216bf121bb91243acdb38
thunk_266cb8:
0x266cb8: JMP 0x009ddc00
; END FUNCTION thunk_266cb8
0x266cbd: INT3 ; original byte CC, padding
0x266cbe: INT3 ; original byte CC, padding
0x266cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc0 [0x266cc0, 0x266cc4] | file +0xd48 | ev_b6c802572264316e90ed3345f2a81557c2bd489791b15076650e3be79e08ff47
thunk_266cc0:
0x266cc0: JMP 0x009dde50
; END FUNCTION thunk_266cc0
0x266cc5: INT3 ; original byte CC, padding
0x266cc6: INT3 ; original byte CC, padding
0x266cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc8 [0x266cc8, 0x266ccc] | file +0xd50 | ev_f94c0066909ed11a39e16e7896cd502d8724b3a73c0764f2f50f547302dc33d5
thunk_266cc8:
0x266cc8: JMP 0x009ddeb0
; END FUNCTION thunk_266cc8
0x266ccd: INT3 ; original byte CC, padding
0x266cce: INT3 ; original byte CC, padding
0x266ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd0 [0x266cd0, 0x266cd4] | file +0xd58 | ev_348cb7baeed000a9d33e2e381076de9fb9b8615b007f637a8eb38169607b542e
thunk_266cd0:
0x266cd0: JMP 0x009ddff0
; END FUNCTION thunk_266cd0
0x266cd5: INT3 ; original byte CC, padding
0x266cd6: INT3 ; original byte CC, padding
0x266cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd8 [0x266cd8, 0x266cdc] | file +0xd60 | ev_fc58a66b8aa11327158592a2683a5409b088dbfa3e73c567d2114c597deb93bc
thunk_266cd8:
0x266cd8: JMP 0x009de070
; END FUNCTION thunk_266cd8
0x266cdd: INT3 ; original byte CC, padding
0x266cde: INT3 ; original byte CC, padding
0x266cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce0 [0x266ce0, 0x266ce4] | file +0xd68 | ev_5475722fc4118f733e9a73ddbd7446a54dc4ad626a95e9c9f0448cc18e9f996e
thunk_266ce0:
0x266ce0: JMP 0x009de0f0
; END FUNCTION thunk_266ce0
0x266ce5: INT3 ; original byte CC, padding
0x266ce6: INT3 ; original byte CC, padding
0x266ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce8 [0x266ce8, 0x266cec] | file +0xd70 | ev_fdafddb450a802d82260ceae9a715e28314e8881a70b3d59b8493179b1961500
thunk_266ce8:
0x266ce8: JMP 0x009e0b90
; END FUNCTION thunk_266ce8
0x266ced: INT3 ; original byte CC, padding
0x266cee: INT3 ; original byte CC, padding
0x266cef: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf0 [0x266cf0, 0x266cf4] | file +0xd78 | ev_8cefa82a89b7b4b45c99217e6cd0bee8439d24511d15edc5beb5541815716e5c
thunk_266cf0:
0x266cf0: JMP 0x009e0cd0
; END FUNCTION thunk_266cf0
0x266cf5: INT3 ; original byte CC, padding
0x266cf6: INT3 ; original byte CC, padding
0x266cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf8 [0x266cf8, 0x266cfc] | file +0xd80 | ev_0fe31e9a802c16bff487f3ffa6fe768146a74631329f957dd9bc3dca74021aca
thunk_266cf8:
0x266cf8: JMP 0x009e0d70
; END FUNCTION thunk_266cf8
0x266cfd: INT3 ; original byte CC, padding
0x266cfe: INT3 ; original byte CC, padding
0x266cff: INT3 ; original byte CC, padding

; FUNCTION thunk_266d00 [0x266d00, 0x266d04] | file +0xd88 | ev_e5cce5cafece25832e81d202bbaf98d746251944792d147620e609bdc88a079b
thunk_266d00:
0x266d00: JMP 0x009e0ef0
; END FUNCTION thunk_266d00
0x266d05: INT3 ; original byte CC, padding
0x266d06: INT3 ; original byte CC, padding
0x266d07: INT3 ; original byte CC, padding

; FUNCTION thunk_266d08 [0x266d08, 0x266d0c] | file +0xd90 | ev_a5c6e76db2b06ad96ad752996fbb0d43af1311a603e951d09dc0718da26264e1
thunk_266d08:
0x266d08: JMP 0x009e1050
; END FUNCTION thunk_266d08
0x266d0d: INT3 ; original byte CC, padding
0x266d0e: INT3 ; original byte CC, padding
0x266d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d10 [0x266d10, 0x266d14] | file +0xd98 | ev_2ff4d8779640ec27c7a42ba2bd832a1062c3067640217eabf3eafa58a6ac14c7
thunk_266d10:
0x266d10: JMP 0x009e1490
; END FUNCTION thunk_266d10
0x266d15: INT3 ; original byte CC, padding
0x266d16: INT3 ; original byte CC, padding
0x266d17: INT3 ; original byte CC, padding

; FUNCTION thunk_266d18 [0x266d18, 0x266d1c] | file +0xda0 | ev_b7780a59bec1d8f90378ae9653e3982c89c7992f914096c62690d8fcc0b31a94
thunk_266d18:
0x266d18: JMP 0x00a065e0
; END FUNCTION thunk_266d18
0x266d1d: INT3 ; original byte CC, padding
0x266d1e: INT3 ; original byte CC, padding
0x266d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d20 [0x266d20, 0x266d24] | file +0xda8 | ev_d10f566f8d9de96267472087c1f37a7479708a48744751f0d311c1c622dd3904
thunk_266d20:
0x266d20: JMP 0x00101340
; END FUNCTION thunk_266d20
0x266d25: INT3 ; original byte CC, padding
0x266d26: INT3 ; original byte CC, padding
0x266d27: INT3 ; original byte CC, padding

; FUNCTION thunk_266d28 [0x266d28, 0x266d2c] | file +0xdb0 | ev_b14ed9d81a695319fa6e7c6ebdc5b570f764a5554a4fc0c40148baafde815686
thunk_266d28:
0x266d28: JMP 0x00a32f30
; END FUNCTION thunk_266d28
0x266d2d: INT3 ; original byte CC, padding
0x266d2e: INT3 ; original byte CC, padding
0x266d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d30 [0x266d30, 0x266d34] | file +0xdb8 | ev_6ceedf1cd0b694a6020d0489577c66021b95c6e6acf4a93dbeabde86d9f6d391
thunk_266d30:
0x266d30: JMP 0x00a336c0
; END FUNCTION thunk_266d30
0x266d35: INT3 ; original byte CC, padding
0x266d36: INT3 ; original byte CC, padding
0x266d37: INT3 ; original byte CC, padding

; FUNCTION thunk_266d38 [0x266d38, 0x266d3c] | file +0xdc0 | ev_f404fb3364f869a944ee99aeb16bd33ff7e315fa9ba80c315a591d04d77c5cd9
thunk_266d38:
0x266d38: JMP 0x00a38c90
; END FUNCTION thunk_266d38
0x266d3d: INT3 ; original byte CC, padding
0x266d3e: INT3 ; original byte CC, padding
0x266d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d40 [0x266d40, 0x266d44] | file +0xdc8 | ev_78ce9ed99aaf60ae3f7ddffd51b979932236ff54bce8de0b8b30a669f28d85da
thunk_266d40:
0x266d40: JMP 0x00a6ab00
; END FUNCTION thunk_266d40
0x266d45: INT3 ; original byte CC, padding
0x266d46: INT3 ; original byte CC, padding
0x266d47: INT3 ; original byte CC, padding

; FUNCTION thunk_266d48 [0x266d48, 0x266d4c] | file +0xdd0 | ev_b5a719e3051b394916925482ba873b496bcb34a1988407017a610457c6c23429
thunk_266d48:
0x266d48: JMP 0x00a6abb0
; END FUNCTION thunk_266d48
0x266d4d: INT3 ; original byte CC, padding
0x266d4e: INT3 ; original byte CC, padding
0x266d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d50 [0x266d50, 0x266d54] | file +0xdd8 | ev_66a8e1394f6126ff166804a7b4117339bcc651d2b89fb684b756a8507994bdcf
thunk_266d50:
0x266d50: JMP 0x00a8ec10
; END FUNCTION thunk_266d50
0x266d55: INT3 ; original byte CC, padding
0x266d56: INT3 ; original byte CC, padding
0x266d57: INT3 ; original byte CC, padding

; FUNCTION thunk_266d58 [0x266d58, 0x266d5c] | file +0xde0 | ev_8d5fb3fe87100ad2ba04f2e7e973447e53c90e2e406a2a38099b02122b3e9869
thunk_266d58:
0x266d58: JMP 0x00a8ee00
; END FUNCTION thunk_266d58
0x266d5d: INT3 ; original byte CC, padding
0x266d5e: INT3 ; original byte CC, padding
0x266d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d60 [0x266d60, 0x266d64] | file +0xde8 | ev_5c2e94bdbf3948c0843d6ef9b29810c9a403493954312eb1180300ffe4515545
thunk_266d60:
0x266d60: JMP 0x00ab17b0
; END FUNCTION thunk_266d60
0x266d65: INT3 ; original byte CC, padding
0x266d66: INT3 ; original byte CC, padding
0x266d67: INT3 ; original byte CC, padding

; FUNCTION thunk_266d68 [0x266d68, 0x266d6c] | file +0xdf0 | ev_6b4bef6b5f4bc828de6f53ae7485814885aa93b10e589f519b41bb23e3162800
thunk_266d68:
0x266d68: JMP 0x00ac07b0
; END FUNCTION thunk_266d68
0x266d6d: INT3 ; original byte CC, padding
0x266d6e: INT3 ; original byte CC, padding
0x266d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d70 [0x266d70, 0x266d74] | file +0xdf8 | ev_bdce12fae65c55b0c7513e875b769c11d4280239f3d72373aaab9e9766afbaac
thunk_266d70:
0x266d70: JMP 0x00ac2af0
; END FUNCTION thunk_266d70
0x266d75: INT3 ; original byte CC, padding
0x266d76: INT3 ; original byte CC, padding
0x266d77: INT3 ; original byte CC, padding

; FUNCTION thunk_266d78 [0x266d78, 0x266d7c] | file +0xe00 | ev_2680b60f9cb23d12b0b0ecaabdc08d843be220023793fdb28f8eee6ca7229a5d
thunk_266d78:
0x266d78: JMP 0x0011a750
; END FUNCTION thunk_266d78
0x266d7d: INT3 ; original byte CC, padding
0x266d7e: INT3 ; original byte CC, padding
0x266d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d80 [0x266d80, 0x266d84] | file +0xe08 | ev_9af6b1d5b9f45778621c3ee062e58fca2c11a641863e209779c6d2054ed827fb
thunk_266d80:
0x266d80: JMP 0x00ae12a0
; END FUNCTION thunk_266d80
0x266d85: INT3 ; original byte CC, padding
0x266d86: INT3 ; original byte CC, padding
0x266d87: INT3 ; original byte CC, padding

; FUNCTION thunk_266d88 [0x266d88, 0x266d8c] | file +0xe10 | ev_8646eab0650b71883c11f7cdbab5c072bb7067fc4b651fe6d4ff533834d1400e
thunk_266d88:
0x266d88: JMP 0x00ae3400
; END FUNCTION thunk_266d88
0x266d8d: INT3 ; original byte CC, padding
0x266d8e: INT3 ; original byte CC, padding
0x266d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d90 [0x266d90, 0x266d94] | file +0xe18 | ev_ce1d8c6ab3f2ba46d018490e9359180b1341e43b3fbb4718438a184c713f0e55
thunk_266d90:
0x266d90: JMP 0x00ae3530
; END FUNCTION thunk_266d90
0x266d95: INT3 ; original byte CC, padding
0x266d96: INT3 ; original byte CC, padding
0x266d97: INT3 ; original byte CC, padding

; FUNCTION thunk_266d98 [0x266d98, 0x266d9c] | file +0xe20 | ev_bee1965f99007cbadf8a23a84f31148a5140aa1948ea011f5abff7a1602a8ffc
thunk_266d98:
0x266d98: JMP 0x00ae63c0
; END FUNCTION thunk_266d98
0x266d9d: INT3 ; original byte CC, padding
0x266d9e: INT3 ; original byte CC, padding
0x266d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266da0 [0x266da0, 0x266da4] | file +0xe28 | ev_021586ff9f269dedbb283491c1f5fef34dda25f2b408fa051a6134e2f95edd7d
thunk_266da0:
0x266da0: JMP 0x00b07ee0
; END FUNCTION thunk_266da0
0x266da5: INT3 ; original byte CC, padding
0x266da6: INT3 ; original byte CC, padding
0x266da7: INT3 ; original byte CC, padding

; FUNCTION thunk_266da8 [0x266da8, 0x266dac] | file +0xe30 | ev_661897bcc4d7235e95c9ece8b99683b3005da66501d8fb0d0dec17557ed248b7
thunk_266da8:
0x266da8: JMP 0x00b08190
; END FUNCTION thunk_266da8
0x266dad: INT3 ; original byte CC, padding
0x266dae: INT3 ; original byte CC, padding
0x266daf: INT3 ; original byte CC, padding

; FUNCTION thunk_266db0 [0x266db0, 0x266db4] | file +0xe38 | ev_a51657bb9adaf2b46acb636dab82aea2afbd24344b38ec9fc62f4a5cb75b4c3f
thunk_266db0:
0x266db0: JMP 0x00b08530
; END FUNCTION thunk_266db0
0x266db5: INT3 ; original byte CC, padding
0x266db6: INT3 ; original byte CC, padding
0x266db7: INT3 ; original byte CC, padding

; FUNCTION thunk_266db8 [0x266db8, 0x266dbc] | file +0xe40 | ev_7bd6608e24ea1d58427542d7fe6b513031f58af19140f4dc92741a8a3df9ee06
thunk_266db8:
0x266db8: JMP 0x00b08810
; END FUNCTION thunk_266db8
0x266dbd: INT3 ; original byte CC, padding
0x266dbe: INT3 ; original byte CC, padding
0x266dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc0 [0x266dc0, 0x266dc4] | file +0xe48 | ev_f09ac987114e244788a375bb4fcf7afd7ce4c964fa2b7bf4a6afafeb24830e03
thunk_266dc0:
0x266dc0: JMP 0x00b096a0
; END FUNCTION thunk_266dc0
0x266dc5: INT3 ; original byte CC, padding
0x266dc6: INT3 ; original byte CC, padding
0x266dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc8 [0x266dc8, 0x266dcc] | file +0xe50 | ev_dfc611f60173bd5832d71e5b7ec488439560cad77e88931e8d7c64545c725a45
thunk_266dc8:
0x266dc8: JMP 0x00b0b4f0
; END FUNCTION thunk_266dc8
0x266dcd: INT3 ; original byte CC, padding
0x266dce: INT3 ; original byte CC, padding
0x266dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd0 [0x266dd0, 0x266dd4] | file +0xe58 | ev_7ddaa2bd15e3b28548a4a9c293e73ca9bc9385206edec45703a1cbcbdfd80bbe
thunk_266dd0:
0x266dd0: JMP 0x001ef0f0
; END FUNCTION thunk_266dd0
0x266dd5: INT3 ; original byte CC, padding
0x266dd6: INT3 ; original byte CC, padding
0x266dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd8 [0x266dd8, 0x266ddc] | file +0xe60 | ev_0fd6893fc896b88e9e684bdcf1f2df886f46d9b79d06e9e8e6ac0024f32f3aed
thunk_266dd8:
0x266dd8: JMP 0x001f0060
; END FUNCTION thunk_266dd8
0x266ddd: INT3 ; original byte CC, padding
0x266dde: INT3 ; original byte CC, padding
0x266ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_266de0 [0x266de0, 0x266de4] | file +0xe68 | ev_f3e343791d1960e5d9ab7af96634393b0613d3a4f218256929e2f8033104ac7d
thunk_266de0:
0x266de0: JMP 0x0011b9b0
; END FUNCTION thunk_266de0
0x266de5: INT3 ; original byte CC, padding
0x266de6: INT3 ; original byte CC, padding
0x266de7: INT3 ; original byte CC, padding

; FUNCTION thunk_266de8 [0x266de8, 0x266dec] | file +0xe70 | ev_3256847e0571f12a26c9637636d3c4e54696270caa3cb68eeaae5a004b6a850f
thunk_266de8:
0x266de8: JMP 0x00b3b130
; END FUNCTION thunk_266de8
0x266ded: INT3 ; original byte CC, padding
0x266dee: INT3 ; original byte CC, padding
0x266def: INT3 ; original byte CC, padding

; FUNCTION thunk_266df0 [0x266df0, 0x266df4] | file +0xe78 | ev_a4d5a58087cc50f89a43a0c946224b55c585f59dde0dbe33701b96ad42036a63
thunk_266df0:
0x266df0: JMP 0x00b47a40
; END FUNCTION thunk_266df0
0x266df5: INT3 ; original byte CC, padding
0x266df6: INT3 ; original byte CC, padding
0x266df7: INT3 ; original byte CC, padding

; FUNCTION thunk_266df8 [0x266df8, 0x266dfc] | file +0xe80 | ev_6f9f553619e79fa117711aa664214bf407cb896470edfaed2fa80b975c20998e
thunk_266df8:
0x266df8: JMP 0x00b503c0
; END FUNCTION thunk_266df8
0x266dfd: INT3 ; original byte CC, padding
0x266dfe: INT3 ; original byte CC, padding
0x266dff: INT3 ; original byte CC, padding

; FUNCTION thunk_266e00 [0x266e00, 0x266e04] | file +0xe88 | ev_5bb72f86362afb6f491fa4944eac459ad974d898a733bc1701ce28ccee3366a3
thunk_266e00:
0x266e00: JMP 0x00b50f10
; END FUNCTION thunk_266e00
0x266e05: INT3 ; original byte CC, padding
0x266e06: INT3 ; original byte CC, padding
0x266e07: INT3 ; original byte CC, padding

; FUNCTION thunk_266e08 [0x266e08, 0x266e0c] | file +0xe90 | ev_4626fe3df4c069cb8aaac5384079b00f151bec62d68c9553e9ed7c8a4fd75c42
thunk_266e08:
0x266e08: JMP 0x00b50fb0
; END FUNCTION thunk_266e08
0x266e0d: INT3 ; original byte CC, padding
0x266e0e: INT3 ; original byte CC, padding
0x266e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e10 [0x266e10, 0x266e14] | file +0xe98 | ev_6d4603bdb31502b309b8835180f360ba961490d6273d111b6f01a175e50b17af
thunk_266e10:
0x266e10: JMP 0x00b510b0
; END FUNCTION thunk_266e10
0x266e15: INT3 ; original byte CC, padding
0x266e16: INT3 ; original byte CC, padding
0x266e17: INT3 ; original byte CC, padding

; FUNCTION thunk_266e18 [0x266e18, 0x266e1c] | file +0xea0 | ev_396af73daa982841b9f11dfa441c9e266f5a927b17b979985cd9ca8a0a5fdb68
thunk_266e18:
0x266e18: JMP 0x00b51190
; END FUNCTION thunk_266e18
0x266e1d: INT3 ; original byte CC, padding
0x266e1e: INT3 ; original byte CC, padding
0x266e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e20 [0x266e20, 0x266e24] | file +0xea8 | ev_fffc298efdf0b5e0e2e4378571521024ffa8e4aca9043008d1e61ce816203c66
thunk_266e20:
0x266e20: JMP 0x00b51290
; END FUNCTION thunk_266e20
0x266e25: INT3 ; original byte CC, padding
0x266e26: INT3 ; original byte CC, padding
0x266e27: INT3 ; original byte CC, padding

; FUNCTION thunk_266e28 [0x266e28, 0x266e2c] | file +0xeb0 | ev_e8ef76577eaac3fab3c793b7168e9da12dc1aca576c7a71fa3f557e237c2e4e6
thunk_266e28:
0x266e28: JMP 0x00b512d0
; END FUNCTION thunk_266e28
0x266e2d: INT3 ; original byte CC, padding
0x266e2e: INT3 ; original byte CC, padding
0x266e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e30 [0x266e30, 0x266e34] | file +0xeb8 | ev_4db31287f09e0ae97956058a96dfe8fd3e5528ddc6f25d486a7433aaa211b322
thunk_266e30:
0x266e30: JMP 0x00b51320
; END FUNCTION thunk_266e30
0x266e35: INT3 ; original byte CC, padding
0x266e36: INT3 ; original byte CC, padding
0x266e37: INT3 ; original byte CC, padding

; FUNCTION thunk_266e38 [0x266e38, 0x266e3c] | file +0xec0 | ev_8ecf5e88ea4bb913a7d602178eeaa9d978ee9a7b5cd012aa8894b369ad41550d
thunk_266e38:
0x266e38: JMP 0x00b568a0
; END FUNCTION thunk_266e38
0x266e3d: INT3 ; original byte CC, padding
0x266e3e: INT3 ; original byte CC, padding
0x266e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e40 [0x266e40, 0x266e44] | file +0xec8 | ev_8e75b68ffdcee668e3cc8060cc48f0eec1a2ba00367b0ea233f6c43f8765a777
thunk_266e40:
0x266e40: JMP 0x0009a0e0
; END FUNCTION thunk_266e40
0x266e45: INT3 ; original byte CC, padding
0x266e46: INT3 ; original byte CC, padding
0x266e47: INT3 ; original byte CC, padding

; FUNCTION thunk_266e48 [0x266e48, 0x266e4c] | file +0xed0 | ev_1449cb43daa60b62cab63d755b2a2ddd18efb47331cc52035ef5c3a04310475e
thunk_266e48:
0x266e48: JMP 0x00b6ae70
; END FUNCTION thunk_266e48
0x266e4d: INT3 ; original byte CC, padding
0x266e4e: INT3 ; original byte CC, padding
0x266e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e50 [0x266e50, 0x266e54] | file +0xed8 | ev_e5c757c666e1090a3ec377473f91b1bae5a6549c03db2270345898d87c0b067e
thunk_266e50:
0x266e50: JMP 0x00b6bb90
; END FUNCTION thunk_266e50
0x266e55: INT3 ; original byte CC, padding
0x266e56: INT3 ; original byte CC, padding
0x266e57: INT3 ; original byte CC, padding

; FUNCTION thunk_266e58 [0x266e58, 0x266e5c] | file +0xee0 | ev_8bf126f87d6604a0a94aed580fc13864f2b4286b1b4f03fb9394afeb53816a34
thunk_266e58:
0x266e58: JMP 0x00b6d980
; END FUNCTION thunk_266e58
0x266e5d: INT3 ; original byte CC, padding
0x266e5e: INT3 ; original byte CC, padding
0x266e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e60 [0x266e60, 0x266e64] | file +0xee8 | ev_7ca6cb21dc0b6f25698862493a2d6b95a19babe9efefa4bd242d6e79af31bb98
thunk_266e60:
0x266e60: JMP 0x00b6daa0
; END FUNCTION thunk_266e60
0x266e65: INT3 ; original byte CC, padding
0x266e66: INT3 ; original byte CC, padding
0x266e67: INT3 ; original byte CC, padding

; FUNCTION thunk_266e68 [0x266e68, 0x266e6c] | file +0xef0 | ev_d64bbe0b19de218b1913ecc94394fde4fbf612ee3092f588edf5fd97efaed577
thunk_266e68:
0x266e68: JMP 0x00b6e180
; END FUNCTION thunk_266e68
0x266e6d: INT3 ; original byte CC, padding
0x266e6e: INT3 ; original byte CC, padding
0x266e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e70 [0x266e70, 0x266e74] | file +0xef8 | ev_f2be95566a6f3f55ffa0867891aa84abb05e686b116e083938852c5ad30c9053
thunk_266e70:
0x266e70: JMP 0x00b71320
; END FUNCTION thunk_266e70
0x266e75: INT3 ; original byte CC, padding
0x266e76: INT3 ; original byte CC, padding
0x266e77: INT3 ; original byte CC, padding

; FUNCTION thunk_266e78 [0x266e78, 0x266e7c] | file +0xf00 | ev_ea30d5c8cc955f26bc1887e696b4cdd9d0f470d328a1f7fcff151a10e904bf5b
thunk_266e78:
0x266e78: JMP 0x00b71370
; END FUNCTION thunk_266e78
0x266e7d: INT3 ; original byte CC, padding
0x266e7e: INT3 ; original byte CC, padding
0x266e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e80 [0x266e80, 0x266e84] | file +0xf08 | ev_c63e3871926c8e72b579d264e85f38382d783da0d0b04d4be00b01031822fb25
thunk_266e80:
0x266e80: JMP 0x00b713c0
; END FUNCTION thunk_266e80
0x266e85: INT3 ; original byte CC, padding
0x266e86: INT3 ; original byte CC, padding
0x266e87: INT3 ; original byte CC, padding

; FUNCTION thunk_266e88 [0x266e88, 0x266e8c] | file +0xf10 | ev_197d591bf203fc30e38d796f069d211a923ba60199a8f018b65658b3f5f32eb8
thunk_266e88:
0x266e88: JMP 0x00b71410
; END FUNCTION thunk_266e88
0x266e8d: INT3 ; original byte CC, padding
0x266e8e: INT3 ; original byte CC, padding
0x266e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e90 [0x266e90, 0x266e94] | file +0xf18 | ev_06c505a8945df64cf395d995cbc9ef4d39ffbb334ac8940eaf15b821d76a2e1f
thunk_266e90:
0x266e90: JMP 0x00b71960
; END FUNCTION thunk_266e90
0x266e95: INT3 ; original byte CC, padding
0x266e96: INT3 ; original byte CC, padding
0x266e97: INT3 ; original byte CC, padding

; FUNCTION thunk_266e98 [0x266e98, 0x266e9c] | file +0xf20 | ev_92cf65c6497d81c189072201bc92b6d001023852b15682c6e7045a41c5b4996f
thunk_266e98:
0x266e98: JMP 0x00b719d0
; END FUNCTION thunk_266e98
0x266e9d: INT3 ; original byte CC, padding
0x266e9e: INT3 ; original byte CC, padding
0x266e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea0 [0x266ea0, 0x266ea4] | file +0xf28 | ev_645a6b9f18cf77202c1f3379a167a483992f1abe64ade57cf4679057b81f8132
thunk_266ea0:
0x266ea0: JMP 0x00b71a40
; END FUNCTION thunk_266ea0
0x266ea5: INT3 ; original byte CC, padding
0x266ea6: INT3 ; original byte CC, padding
0x266ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea8 [0x266ea8, 0x266eac] | file +0xf30 | ev_92f8a51544605bc7f4dfb2d3f45f27341d959314143b088056208c2ce0daf354
thunk_266ea8:
0x266ea8: JMP 0x00b71ab0
; END FUNCTION thunk_266ea8
0x266ead: INT3 ; original byte CC, padding
0x266eae: INT3 ; original byte CC, padding
0x266eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb0 [0x266eb0, 0x266eb4] | file +0xf38 | ev_86e42877162f49237f5ee3cc1fa9b5e7317d73fd40d6536966932f7792fb38d9
thunk_266eb0:
0x266eb0: JMP 0x00b72620
; END FUNCTION thunk_266eb0
0x266eb5: INT3 ; original byte CC, padding
0x266eb6: INT3 ; original byte CC, padding
0x266eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb8 [0x266eb8, 0x266ebc] | file +0xf40 | ev_001011f1bff1e10ce4ca0cb454363095736c0cef7656de7f95cc7986ab85c6f4
thunk_266eb8:
0x266eb8: JMP 0x00b72860
; END FUNCTION thunk_266eb8
0x266ebd: INT3 ; original byte CC, padding
0x266ebe: INT3 ; original byte CC, padding
0x266ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec0 [0x266ec0, 0x266ec4] | file +0xf48 | ev_a62bc6806ab674d0ae71f374d1e8ebd1b76781dbf590ebc9087c31322e2462e2
thunk_266ec0:
0x266ec0: JMP 0x00b791d0
; END FUNCTION thunk_266ec0
0x266ec5: INT3 ; original byte CC, padding
0x266ec6: INT3 ; original byte CC, padding
0x266ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec8 [0x266ec8, 0x266ecc] | file +0xf50 | ev_b52289221c273125b1dbccaf11fa3a6fd7e6246284d8522934c98ec91d8d206e
thunk_266ec8:
0x266ec8: JMP 0x00b79290
; END FUNCTION thunk_266ec8
0x266ecd: INT3 ; original byte CC, padding
0x266ece: INT3 ; original byte CC, padding
0x266ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed0 [0x266ed0, 0x266ed4] | file +0xf58 | ev_4047cbc663795c1289163dbe21ac08af15171a76058b17f7e22314c363bc8a5c
thunk_266ed0:
0x266ed0: JMP 0x00b793f0
; END FUNCTION thunk_266ed0
0x266ed5: INT3 ; original byte CC, padding
0x266ed6: INT3 ; original byte CC, padding
0x266ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed8 [0x266ed8, 0x266edc] | file +0xf60 | ev_d40229b3fb879733cf4bb36ba96438639d574a7aaaf01b902462653bec434bc0
thunk_266ed8:
0x266ed8: JMP 0x00b79420
; END FUNCTION thunk_266ed8
0x266edd: INT3 ; original byte CC, padding
0x266ede: INT3 ; original byte CC, padding
0x266edf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee0 [0x266ee0, 0x266ee4] | file +0xf68 | ev_9c460fc45aabe04141735909271220fd15d8255d47b0abc66e0f74511b093105
thunk_266ee0:
0x266ee0: JMP 0x00b79460
; END FUNCTION thunk_266ee0
0x266ee5: INT3 ; original byte CC, padding
0x266ee6: INT3 ; original byte CC, padding
0x266ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee8 [0x266ee8, 0x266eec] | file +0xf70 | ev_140eeb12e1434a7dc0c137ae75e06af03c16e376698cbc46dfa3d10d190ea107
thunk_266ee8:
0x266ee8: JMP 0x00b79480
; END FUNCTION thunk_266ee8
0x266eed: INT3 ; original byte CC, padding
0x266eee: INT3 ; original byte CC, padding
0x266eef: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef0 [0x266ef0, 0x266ef4] | file +0xf78 | ev_43ad813f5b2b8f40c57dc086f2c412e940abf4ceca224978018e13b0f33a7820
thunk_266ef0:
0x266ef0: JMP 0x00b79490
; END FUNCTION thunk_266ef0
0x266ef5: INT3 ; original byte CC, padding
0x266ef6: INT3 ; original byte CC, padding
0x266ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef8 [0x266ef8, 0x266efc] | file +0xf80 | ev_bfec69b84024565b47c924a86acddbcc1709c8816cf063cd4839f05a0efb3a66
thunk_266ef8:
0x266ef8: JMP 0x00b794b0
; END FUNCTION thunk_266ef8
0x266efd: INT3 ; original byte CC, padding
0x266efe: INT3 ; original byte CC, padding
0x266eff: INT3 ; original byte CC, padding

; FUNCTION thunk_266f00 [0x266f00, 0x266f04] | file +0xf88 | ev_c1e937b17f609327e5a32dc651db69965da91c36afed6b6cab4eeb2ddbc66ade
thunk_266f00:
0x266f00: JMP 0x00b795f0
; END FUNCTION thunk_266f00
0x266f05: INT3 ; original byte CC, padding
0x266f06: INT3 ; original byte CC, padding
0x266f07: INT3 ; original byte CC, padding

; FUNCTION thunk_266f08 [0x266f08, 0x266f0c] | file +0xf90 | ev_54cd41ab36c1d893c67c9e91dd3bac8054c2a093aa3ff842a2b4ac493f1af467
thunk_266f08:
0x266f08: JMP 0x00b79620
; END FUNCTION thunk_266f08
0x266f0d: INT3 ; original byte CC, padding
0x266f0e: INT3 ; original byte CC, padding
0x266f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f10 [0x266f10, 0x266f14] | file +0xf98 | ev_5f150108a282e0acbbf087f0447711d5f934b501ef033bcb4651c0a0bff06097
thunk_266f10:
0x266f10: JMP 0x00b79830
; END FUNCTION thunk_266f10
0x266f15: INT3 ; original byte CC, padding
0x266f16: INT3 ; original byte CC, padding
0x266f17: INT3 ; original byte CC, padding

; FUNCTION thunk_266f18 [0x266f18, 0x266f1c] | file +0xfa0 | ev_2da7c7533a24f08c54a5ec5ef15fbab9a37ad41832c00dd6f045c392f203f1ab
thunk_266f18:
0x266f18: JMP 0x00b80e90
; END FUNCTION thunk_266f18
0x266f1d: INT3 ; original byte CC, padding
0x266f1e: INT3 ; original byte CC, padding
0x266f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f20 [0x266f20, 0x266f24] | file +0xfa8 | ev_05007cf428f229f9acad957f05bfd0d915fc31a6bd8f53b6d71023441c636a5b
thunk_266f20:
0x266f20: JMP 0x00b80f20
; END FUNCTION thunk_266f20
0x266f25: INT3 ; original byte CC, padding
0x266f26: INT3 ; original byte CC, padding
0x266f27: INT3 ; original byte CC, padding

; FUNCTION thunk_266f28 [0x266f28, 0x266f2c] | file +0xfb0 | ev_4af2057d7b385aba4d6285ec88eaf49753f05817a916e45e8dad4635faa00a15
thunk_266f28:
0x266f28: JMP 0x00b99520
; END FUNCTION thunk_266f28
0x266f2d: INT3 ; original byte CC, padding
0x266f2e: INT3 ; original byte CC, padding
0x266f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f30 [0x266f30, 0x266f34] | file +0xfb8 | ev_7031656535bffe683040d3e65d44680a84556f146e6c8250261208dfd70560bd
thunk_266f30:
0x266f30: JMP 0x00b99600
; END FUNCTION thunk_266f30
0x266f35: INT3 ; original byte CC, padding
0x266f36: INT3 ; original byte CC, padding
0x266f37: INT3 ; original byte CC, padding

; FUNCTION thunk_266f38 [0x266f38, 0x266f3c] | file +0xfc0 | ev_1c665d019d7d1f2e53f07e261e031cb899f97da44155def954621c2a02570d06
thunk_266f38:
0x266f38: JMP 0x00b9ce30
; END FUNCTION thunk_266f38
0x266f3d: INT3 ; original byte CC, padding
0x266f3e: INT3 ; original byte CC, padding
0x266f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f40 [0x266f40, 0x266f44] | file +0xfc8 | ev_712648e7bb521b61edaa5cabe0db3056f43183e8708033b54aa034674b67ec39
thunk_266f40:
0x266f40: JMP 0x00bf5c40
; END FUNCTION thunk_266f40
0x266f45: INT3 ; original byte CC, padding
0x266f46: INT3 ; original byte CC, padding
0x266f47: INT3 ; original byte CC, padding

; FUNCTION thunk_266f48 [0x266f48, 0x266f4c] | file +0xfd0 | ev_ecc803a493b1fccc01b711533b2c9a2508d39c49fd905d6689592f58ab23fd2e
thunk_266f48:
0x266f48: JMP 0x00bfe620
; END FUNCTION thunk_266f48
0x266f4d: INT3 ; original byte CC, padding
0x266f4e: INT3 ; original byte CC, padding
0x266f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f50 [0x266f50, 0x266f54] | file +0xfd8 | ev_03cc54ab31ccc520062b136e5769020cebdfb08c0270e94138249b5af9660c5b
thunk_266f50:
0x266f50: JMP 0x00bfef50
; END FUNCTION thunk_266f50
0x266f55: INT3 ; original byte CC, padding
0x266f56: INT3 ; original byte CC, padding
0x266f57: INT3 ; original byte CC, padding

; FUNCTION thunk_266f58 [0x266f58, 0x266f5c] | file +0xfe0 | ev_98503194680b5b3c8554d5b9cf932e290985606a681d50620a2ec04984c2ec5c
thunk_266f58:
0x266f58: JMP 0x00bfefa0
; END FUNCTION thunk_266f58
0x266f5d: INT3 ; original byte CC, padding
0x266f5e: INT3 ; original byte CC, padding
0x266f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f60 [0x266f60, 0x266f64] | file +0xfe8 | ev_b59c9075b71bcf6d9e1b7028c4325ca035da423d9c7567967949cb9421601b48
thunk_266f60:
0x266f60: JMP 0x00bff050
; END FUNCTION thunk_266f60
0x266f65: INT3 ; original byte CC, padding
0x266f66: INT3 ; original byte CC, padding
0x266f67: INT3 ; original byte CC, padding

; FUNCTION thunk_266f68 [0x266f68, 0x266f6c] | file +0xff0 | ev_8365df9cf079d90dcca0b3cc08c697935064c4c8ed974c3515e1b4fa381c7611
thunk_266f68:
0x266f68: JMP 0x00c0d180
; END FUNCTION thunk_266f68
0x266f6d: INT3 ; original byte CC, padding
0x266f6e: INT3 ; original byte CC, padding
0x266f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f70 [0x266f70, 0x266f74] | file +0xff8 | ev_ccee922592c335279de79cd9aa606fdbcd9169a04fe4fa1dd80e272430eeba58
thunk_266f70:
0x266f70: JMP 0x00c327f0
; END FUNCTION thunk_266f70
0x266f75: INT3 ; original byte CC, padding
0x266f76: INT3 ; original byte CC, padding
0x266f77: INT3 ; original byte CC, padding


; ===== REA recovered target/context/helper functions =====

; original syscall trampoline; evidence ev_da7f3ede978ec0f8913a8bc6ab90ee670e3f279fdce9453c39d875b397f798b4; body [{"start": "0x265f78", "end": "0x265f7c"}]
<EXTERNAL>::thunk_EXT_FUN_009a9f40: ; RVA 0x265f78
0x265f78: JMP 0x009a9f40

; target syscall body; evidence ev_8b7aa19c6f28267cdcee0d8eac6492d5c6a1207c5f01c4041040eb1005ecd217; body [{"start": "0x9a9f40", "end": "0x9aa0d3"}, {"start": "0x9aa1b9", "end": "0x9aa222"}, {"start": "0x9aa228", "end": "0x9aa24e"}]
handler_657_body: ; RVA 0x9a9f40
0x9a9f40: PUSH RBP
0x9a9f41: MOV RBP, RSP
0x9a9f44: PUSH R15
0x9a9f46: PUSH R14
0x9a9f48: PUSH R13
0x9a9f4a: PUSH R12
0x9a9f4c: PUSH RBX
0x9a9f4d: SUB RSP, 0x68
0x9a9f51: LEA RCX, [0x391c310]
0x9a9f58: MOV R12D, 0x16
0x9a9f5e: MOV RAX, qword ptr [RCX]
0x9a9f61: MOV qword ptr [RBP + -0x30], RAX
0x9a9f65: CMP dword ptr [RSI + 0x18], 0x0
0x9a9f69: MOV RBX, qword ptr [RSI]
0x9a9f6c: JZ 0x009a9fae
0x9a9f6e: MOV R15, RBX
0x9a9f71: MOV RDI, qword ptr [RSI + 0x10]
0x9a9f75: TEST RDI, RDI
0x9a9f78: JZ 0x009a9f8f
0x9a9f7a: SUB R15, RBX
0x9a9f7d: MOV RBX, RCX
0x9a9f80: SHR R15, 0x5
0x9a9f84: MOV ESI, R15D
0x9a9f87: CALL 0x00259790
0x9a9f8c: MOV RCX, RBX
0x9a9f8f: MOV RAX, qword ptr [RCX]
0x9a9f92: CMP RAX, qword ptr [RBP + -0x30]
0x9a9f96: JNZ 0x009aa237
0x9a9f9c: MOV EAX, R12D
0x9a9f9f: ADD RSP, 0x68
0x9a9fa3: POP RBX
0x9a9fa4: POP R12
0x9a9fa6: POP R13
0x9a9fa8: POP R14
0x9a9faa: POP R15
0x9a9fac: POP RBP
0x9a9fad: RET
0x9a9fae: MOVSXD R13, dword ptr [RSI + 0x8]
0x9a9fb2: MOV R15, RBX
0x9a9fb5: TEST R13, R13
0x9a9fb8: JS 0x009a9f71
0x9a9fba: TEST R13D, R13D
0x9a9fbd: JZ 0x009aa1b9
0x9a9fc3: MOV RAX, qword ptr [RDI + 0x8]
0x9a9fc7: LEA RCX, [0x1397f3d]
0x9a9fce: XOR EDX, EDX
0x9a9fd0: MOV R14, qword ptr [RAX + 0x200]
0x9a9fd7: MOV RAX, qword ptr GS:[0x0]
0x9a9fe0: MOV qword ptr [RBP + -0x80], RDI
0x9a9fe4: MOV qword ptr [RBP + -0x88], RSI
0x9a9feb: MOV RDI, RAX
0x9a9fee: MOV RSI, RCX
0x9a9ff1: CALL 0x00c1a3e0
0x9a9ff6: LEA RSI, [RBP + -0x58]
0x9a9ffa: MOV EDX, 0x20
0x9a9fff: MOV RDI, RBX
0x9aa002: CALL 0x00259280
0x9aa007: LEA RCX, [0x391c310]
0x9aa00e: MOV RSI, qword ptr [RBP + -0x88]
0x9aa015: MOV R12D, EAX
0x9aa018: MOV R15, RBX
0x9aa01b: TEST EAX, EAX
0x9aa01d: JNZ 0x009a9f71
0x9aa023: MOV RDI, R14
0x9aa026: XOR ESI, ESI
0x9aa028: XOR EDX, EDX
0x9aa02a: CALL 0x002c6820
0x9aa02f: MOV RSI, qword ptr [RBP + -0x50]
0x9aa033: LEA RDX, [RBP + -0x60]
0x9aa037: MOV RDI, R14
0x9aa03a: CALL 0x002c6c40
0x9aa03f: MOV R12D, 0x16
0x9aa045: MOV qword ptr [RBP + -0x68], R14
0x9aa049: TEST EAX, EAX
0x9aa04b: JZ 0x009aa1c1
0x9aa051: MOV RAX, qword ptr [RBP + -0x60]
0x9aa055: MOV RCX, qword ptr [RBP + -0x80]
0x9aa059: TEST byte ptr [RAX + 0x60], 0x2
0x9aa05d: JNZ 0x009aa1c5
0x9aa063: MOV R14, qword ptr [RAX + 0x50]
0x9aa067: TEST R14, R14
0x9aa06a: JZ 0x009aa1c5
0x9aa070: CMP byte ptr [R14 + 0x9d], 0xb
0x9aa078: MOV R15, RBX
0x9aa07b: JNZ 0x009aa1c8
0x9aa081: MOV RAX, qword ptr [RBP + -0x68]
0x9aa085: ADD.LOCK dword ptr [RAX + 0x1c4], 0x1
0x9aa08d: SHL R13, 0x5
0x9aa091: MOV RAX, qword ptr [RBP + -0x60]
0x9aa095: MOV R15, R13
0x9aa098: MOV R13, RBX
0x9aa09b: ADD R15, RBX
0x9aa09e: MOV RDX, qword ptr [RAX + 0x20]
0x9aa0a2: MOV RAX, qword ptr [RAX + 0x28]
0x9aa0a6: MOV qword ptr [RBP + -0x78], RDX
0x9aa0aa: MOV qword ptr [RBP + -0x70], RAX
0x9aa0ae: MOV EAX, dword ptr [RBP + -0x58]
0x9aa0b1: ADD R13, 0x20
0x9aa0b5: MOV qword ptr [RBP + -0x38], R13
0x9aa0b9: DEC EAX
0x9aa0bb: CMP EAX, 0x4
0x9aa0be: JA 0x009aa228
0x9aa0c4: LEA RCX, [0x18cdb30]
0x9aa0cb: MOVSXD RAX, dword ptr [RCX + RAX*0x4]
0x9aa0cf: ADD RAX, RCX
0x9aa0d2: JMP RAX
0x9aa1b9: XOR R12D, R12D
0x9aa1bc: JMP 0x009a9f6e
0x9aa1c1: MOV RCX, qword ptr [RBP + -0x80]
0x9aa1c5: MOV R15, RBX
0x9aa1c8: CMP byte ptr [RCX + 0x117], 0x0
0x9aa1cf: JZ 0x009aa203
0x9aa1d1: LEA RAX, [0x1a962e8]
0x9aa1d8: MOV byte ptr [RCX + 0x117], 0x0
0x9aa1df: MOV RAX, qword ptr [RAX]
0x9aa1e2: MOV R13, qword ptr [RAX + 0x40]
0x9aa1e6: LEA RAX, [0x260ce8]
0x9aa1ed: SUB RAX, R13
0x9aa1f0: ROR RAX, 0x3
0x9aa1f4: CMP RAX, 0x6ff
0x9aa1fa: JA 0x009aa23e
0x9aa1fc: MOV RDI, qword ptr [RBP + -0x68]
0x9aa200: CALL R13
0x9aa203: MOV RDI, qword ptr [RBP + -0x68]
0x9aa207: XOR ESI, ESI
0x9aa209: XOR EDX, EDX
0x9aa20b: CALL 0x002c6870
0x9aa210: MOV RSI, qword ptr [RBP + -0x88]
0x9aa217: LEA RCX, [0x391c310]
0x9aa21e: JMP 0x009a9f71
0x9aa228: MOV R12D, 0x2d
0x9aa22e: ADD R13, -0x20
0x9aa232: MOV R15, R13
0x9aa235: JMP 0x009aa1c8
0x9aa237: CALL 0x006fd6b0
0x9aa23c: UD2
0x9aa23e: LEA RDI, [0x255fe80]
0x9aa245: MOV RSI, R13
0x9aa248: CALL 0x0044f8c0
0x9aa24d: JMP 0x009aa1fc

; local helper / adjacent context (reachability below); evidence ev_747fad2e57d10789f44c61590316037646abcbf92c9696fa8bb0c039f4e58c82; body [{"start": "0x9aa250", "end": "0x9aa371"}]
sub_9aa250: ; RVA 0x9aa250
0x9aa250: PUSH RBP
0x9aa251: MOV RBP, RSP
0x9aa254: PUSH R15
0x9aa256: PUSH R14
0x9aa258: PUSH R13
0x9aa25a: PUSH R12
0x9aa25c: PUSH RBX
0x9aa25d: SUB RSP, 0x18
0x9aa261: CMP dword ptr [R8 + 0x4], 0x0
0x9aa266: MOV EAX, 0x16
0x9aa26b: JNZ 0x009aa35f
0x9aa271: MOV RBX, qword ptr [R8 + 0x8]
0x9aa275: MOVZX R9D, BX
0x9aa279: TEST R9, R9
0x9aa27c: JNZ 0x009aa35f
0x9aa282: MOV R15, qword ptr [R8 + 0x10]
0x9aa286: MOVZX R9D, R15W
0x9aa28a: TEST R9, R9
0x9aa28d: JNZ 0x009aa35f
0x9aa293: CMP RDX, RBX
0x9aa296: JA 0x009aa35f
0x9aa29c: CMP RCX, RBX
0x9aa29f: JBE 0x009aa35f
0x9aa2a5: SUB RCX, RBX
0x9aa2a8: CMP RCX, R15
0x9aa2ab: JC 0x009aa35f
0x9aa2b1: MOVZX R14D, byte ptr [R8 + 0x18]
0x9aa2b6: MOV ECX, R14D
0x9aa2b9: AND ECX, 0xffffffcc
0x9aa2bc: JNZ 0x009aa35f
0x9aa2c2: MOVZX R8D, byte ptr [R8 + 0x19]
0x9aa2c7: MOVZX ECX, byte ptr [RDI + 0x244]
0x9aa2ce: CMP R8D, 0xa
0x9aa2d2: JA 0x009aa32b
0x9aa2d4: MOV R9D, 0x409
0x9aa2da: BT R9D, R8D
0x9aa2de: JNC 0x009aa32b
0x9aa2e0: TEST CL, 0x2
0x9aa2e3: JZ 0x009aa2fe
0x9aa2e5: CMP R8D, 0xa
0x9aa2e9: SETZ AL
0x9aa2ec: TEST R14B, 0x22
0x9aa2f0: SETNZ CL
0x9aa2f3: TEST AL, CL
0x9aa2f5: JZ 0x009aa33a
0x9aa2f7: MOV EAX, 0xd
0x9aa2fc: JMP 0x009aa35f
0x9aa2fe: MOV qword ptr [RBP + -0x30], RDI
0x9aa302: MOV EDI, R8D
0x9aa305: MOV R13, RDX
0x9aa308: MOV R12, RSI
0x9aa30b: CALL 0x009acc10
0x9aa310: XOR ECX, ECX
0x9aa312: TEST EAX, EAX
0x9aa314: MOV RDI, qword ptr [RBP + -0x30]
0x9aa318: MOV RSI, R12
0x9aa31b: MOV RDX, R13
0x9aa31e: SETZ CL
0x9aa321: LEA R8D, [0xf + RCX*0x4]
0x9aa329: JMP 0x009aa33a
0x9aa32b: LEA R9D, [R8 + -0x15]
0x9aa32f: CMP R9D, -0xa
0x9aa333: JC 0x009aa35f
0x9aa335: AND CL, 0x2
0x9aa338: JNZ 0x009aa35f
0x9aa33a: TEST R15, R15
0x9aa33d: JZ 0x009aa36e
0x9aa33f: SUB RBX, RDX
0x9aa342: MOV dword ptr [RSP], R8D
0x9aa346: MOV R9D, R14D
0x9aa349: MOV RCX, RBX
0x9aa34c: ADD RBX, R15
0x9aa34f: SHR RBX, 0x10
0x9aa353: SHR RCX, 0x10
0x9aa357: MOV R8D, EBX
0x9aa35a: CALL 0x009a97a0
0x9aa35f: ADD RSP, 0x18
0x9aa363: POP RBX
0x9aa364: POP R12
0x9aa366: POP R13
0x9aa368: POP R14
0x9aa36a: POP R15
0x9aa36c: POP RBP
0x9aa36d: RET
0x9aa36e: XOR EAX, EAX
0x9aa370: JMP 0x009aa35f

; local helper / adjacent context (reachability below); evidence ev_581e2217d83757fdbd3f80a6f4ce7e563271fb02c8a5bd6d475c156a0c70a1cd; body [{"start": "0x9aa380", "end": "0x9aa85a"}]
sub_9aa380: ; RVA 0x9aa380
0x9aa380: PUSH RBP
0x9aa381: MOV RBP, RSP
0x9aa384: PUSH R15
0x9aa386: PUSH R14
0x9aa388: PUSH R13
0x9aa38a: PUSH R12
0x9aa38c: PUSH RBX
0x9aa38d: SUB RSP, 0x88
0x9aa394: LEA RAX, [0x391c310]
0x9aa39b: MOV qword ptr [RBP + -0xa8], RCX
0x9aa3a2: MOV qword ptr [RBP + -0x60], RDX
0x9aa3a6: MOV qword ptr [RBP + -0x50], RSI
0x9aa3aa: MOV qword ptr [RBP + -0x48], RDI
0x9aa3ae: LEA RDI, [0x3ba5e78]
0x9aa3b5: MOV RBX, R8
0x9aa3b8: XOR ESI, ESI
0x9aa3ba: XOR EDX, EDX
0x9aa3bc: XOR ECX, ECX
0x9aa3be: MOV RAX, qword ptr [RAX]
0x9aa3c1: MOV qword ptr [RBP + -0x30], RAX
0x9aa3c5: MOV RAX, qword ptr GS:[0x0]
0x9aa3ce: MOV R13, qword ptr [R9]
0x9aa3d1: MOV qword ptr [RBP + -0x68], RAX
0x9aa3d5: MOV qword ptr [RBP + -0x98], R9
0x9aa3dc: CALL 0x004c6a00
0x9aa3e1: MOV RAX, qword ptr [0x03ba5ed8]
0x9aa3e8: TEST RAX, RAX
0x9aa3eb: JNZ 0x009aa43c
0x9aa3ed: LEA R14, [0x3ba5ed8]
0x9aa3f4: LEA R15, [0x3ba5e60]
0x9aa3fb: LEA R12, [0x1272dc0]
0x9aa402: NOP word ptr CS:[RAX + RAX*0x1]
0x9aa410: MOV RDI, R14
0x9aa413: MOV RSI, R15
0x9aa416: MOV EDX, 0x44
0x9aa41b: MOV RCX, R12
0x9aa41e: MOV dword ptr [RSP], 0x100
0x9aa425: XOR R8D, R8D
0x9aa428: XOR R9D, R9D
0x9aa42b: CALL 0x00c06260
0x9aa430: MOV RAX, qword ptr [0x03ba5ed8]
0x9aa437: TEST RAX, RAX
0x9aa43a: JZ 0x009aa410
0x9aa43c: TZCNT R14, RAX
0x9aa441: BLSR RAX, RAX
0x9aa446: LEA RDI, [0x3ba5e78]
0x9aa44d: XOR ESI, ESI
0x9aa44f: XOR EDX, EDX
0x9aa451: XOR ECX, ECX
0x9aa453: MOV qword ptr [0x03ba5ed8], RAX
0x9aa45a: CALL 0x004c6fa0
0x9aa45f: MOV RAX, qword ptr [0x03ba5ee0]
0x9aa466: MOV RSI, qword ptr [RBP + -0x50]
0x9aa46a: SHL R14D, 0xd
0x9aa46e: MOV qword ptr [RBP + -0x40], 0x0
0x9aa476: LEA RCX, [RAX + R14*0x1]
0x9aa47a: LEA RAX, [RAX + R14*0x1 + 0x2000]
0x9aa482: LEA RDX, [RSI + 0x18]
0x9aa486: MOV qword ptr [RBP + -0x58], RCX
0x9aa48a: MOV qword ptr [RBP + -0x38], RCX
0x9aa48e: LEA RCX, [RSI + 0x168]
0x9aa495: MOV qword ptr [RBP + -0x90], RDX
0x9aa49c: MOV qword ptr [RBP + -0xa0], RAX
0x9aa4a3: LEA RAX, [RSI + 0x198]
0x9aa4aa: MOV qword ptr [RBP + -0x80], RCX
0x9aa4ae: MOV qword ptr [RBP + -0x78], RAX
0x9aa4b2: NOP word ptr CS:[RAX + RAX*0x1]
0x9aa4c0: CMP dword ptr [RBX + 0x4], 0x0
0x9aa4c4: MOV R12D, 0x16
0x9aa4ca: JNZ 0x009aa743
0x9aa4d0: MOV R15, qword ptr [RBX + 0x8]
0x9aa4d4: MOVZX EAX, R15W
0x9aa4d8: TEST RAX, RAX
0x9aa4db: JNZ 0x009aa743
0x9aa4e1: MOV RAX, qword ptr [RBX + 0x10]
0x9aa4e5: MOVZX ECX, AX
0x9aa4e8: TEST RCX, RCX
0x9aa4eb: JNZ 0x009aa743
0x9aa4f1: CMP qword ptr [RBP + -0x60], R15
0x9aa4f5: JA 0x009aa743
0x9aa4fb: MOV RCX, qword ptr [RBP + -0xa8]
0x9aa502: CMP RCX, R15
0x9aa505: JBE 0x009aa743
0x9aa50b: SUB RCX, R15
0x9aa50e: CMP RCX, RAX
0x9aa511: JC 0x009aa743
0x9aa517: TEST RAX, RAX
0x9aa51a: JZ 0x009aa5fe
0x9aa520: SUB R15, qword ptr [RBP + -0x60]
0x9aa524: MOV R14, qword ptr [RBP + -0x38]
0x9aa528: MOV qword ptr [RBP + -0x88], R13
0x9aa52f: MOV R12, R15
0x9aa532: ADD R15, RAX
0x9aa535: SHR R12, 0x10
0x9aa539: SHR R15, 0x10
0x9aa53d: CMP qword ptr [RBP + -0x58], R14
0x9aa541: JZ 0x009aa64c
0x9aa547: MOV RAX, qword ptr [RBP + -0xa0]
0x9aa54e: MOV R13, R15
0x9aa551: SUB R13, R12
0x9aa554: MOVSXD RCX, R13D
0x9aa557: SUB RAX, R14
0x9aa55a: SAR RAX, 0x2
0x9aa55e: CMP RAX, RCX
0x9aa561: JL 0x009aa677
0x9aa567: TEST R13D, 0xfffff800
0x9aa56e: JNZ 0x009aa657
0x9aa574: MOV R13, qword ptr [RBP + -0x50]
0x9aa578: MOV ESI, R12D
0x9aa57b: MOV EDX, R15D
0x9aa57e: MOV RDI, R13
0x9aa581: CALL 0x009a8080
0x9aa586: MOV RDI, qword ptr [RBP + -0x48]
0x9aa58a: MOV RDX, qword ptr [RBP + -0x60]
0x9aa58e: MOV R14D, EAX
0x9aa591: LEA RAX, [RBP + -0x38]
0x9aa595: MOV RSI, R13
0x9aa598: MOV ECX, R12D
0x9aa59b: MOV R8D, R15D
0x9aa59e: LEA R9, [RBP + -0x40]
0x9aa5a2: MOV qword ptr [RSP], RAX
0x9aa5a6: CALL 0x009a8570
0x9aa5ab: MOV RDI, qword ptr [RBP + -0x90]
0x9aa5b2: MOV EAX, R14D
0x9aa5b5: XOR ESI, ESI
0x9aa5b7: XOR EDX, EDX
0x9aa5b9: LEA R14, [RAX + RAX*0x2]
0x9aa5bd: CALL 0x007d46a0
0x9aa5c2: MOV RAX, qword ptr [RBP + -0x80]
0x9aa5c6: MOV dword ptr [RAX + R14*0x4], 0xffffffff
0x9aa5ce: CMP dword ptr [RAX + R14*0x4 + 0x8], 0x0
0x9aa5d4: JNZ 0x009aa6f9
0x9aa5da: MOV RAX, qword ptr [RBP + -0x78]
0x9aa5de: MOV R13, qword ptr [RBP + -0x88]
0x9aa5e5: CMP dword ptr [RAX], 0x0
0x9aa5e8: JNZ 0x009aa712
0x9aa5ee: MOV RDI, qword ptr [RBP + -0x90]
0x9aa5f5: XOR ESI, ESI
0x9aa5f7: XOR EDX, EDX
0x9aa5f9: CALL 0x007d4eb0
0x9aa5fe: XOR R12D, R12D
0x9aa601: CMP R13, qword ptr [RBP + 0x10]
0x9aa605: JZ 0x009aa743
0x9aa60b: MOV RDI, qword ptr GS:[0x0]
0x9aa614: LEA RSI, [0x1397f3d]
0x9aa61b: XOR EDX, EDX
0x9aa61d: CALL 0x00c1a3e0
0x9aa622: MOV EDX, 0x20
0x9aa627: MOV RDI, R13
0x9aa62a: MOV RSI, RBX
0x9aa62d: CALL 0x00259280
0x9aa632: TEST EAX, EAX
0x9aa634: JNZ 0x009aa740
0x9aa63a: CMP dword ptr [RBX], 0x2
0x9aa63d: JNZ 0x009aa743
0x9aa643: ADD R13, 0x20
0x9aa647: JMP 0x009aa4c0
0x9aa64c: MOV R13, R15
0x9aa64f: SUB R13, R12
0x9aa652: JMP 0x009aa567
0x9aa657: MOV RDI, qword ptr [RBP + -0x48]
0x9aa65b: MOV RSI, qword ptr [RBP + -0x50]
0x9aa65f: MOV RDX, qword ptr [RBP + -0x60]
0x9aa663: MOV ECX, R12D
0x9aa666: MOV R8D, R15D
0x9aa669: CALL 0x009a8260
0x9aa66e: MOV R13, qword ptr [RBP + -0x88]
0x9aa675: JMP 0x009aa5fe
0x9aa677: MOV RAX, qword ptr [RBP + -0x48]
0x9aa67b: MOV RSI, qword ptr [RBP + -0x40]
0x9aa67f: MOV RDI, qword ptr [RAX + 0x1d8]
0x9aa686: CALL 0x008ef340
0x9aa68b: MOV RAX, qword ptr [RBP + -0x68]
0x9aa68f: MOV qword ptr [RBP + -0x40], 0x0
0x9aa697: CMP byte ptr [RAX + 0x117], 0x0
0x9aa69e: JZ 0x009aa6d5
0x9aa6a0: MOV RAX, qword ptr [RBP + -0x68]
0x9aa6a4: LEA RCX, [0x1a962e8]
0x9aa6ab: MOV byte ptr [RAX + 0x117], 0x0
0x9aa6b2: MOV RAX, qword ptr [RCX]
0x9aa6b5: MOV RCX, qword ptr [RAX + 0x40]
0x9aa6b9: LEA RAX, [0x260ce8]
0x9aa6c0: SUB RAX, RCX
0x9aa6c3: ROR RAX, 0x3
0x9aa6c7: CMP RAX, 0x6ff
0x9aa6cd: JA 0x009aa726
0x9aa6cf: MOV RDI, qword ptr [RBP + -0x48]
0x9aa6d3: CALL RCX
0x9aa6d5: MOV RSI, qword ptr [RBP + -0x58]
0x9aa6d9: MOV RDI, qword ptr [RBP + -0x50]
0x9aa6dd: SUB R14, RSI
0x9aa6e0: SHR R14, 0x2
0x9aa6e4: MOV EDX, R14D
0x9aa6e7: CALL 0x009a86c0
0x9aa6ec: MOV RAX, qword ptr [RBP + -0x58]
0x9aa6f0: MOV qword ptr [RBP + -0x38], RAX
0x9aa6f4: JMP 0x009aa567
0x9aa6f9: MOV RAX, qword ptr [RBP + -0x80]
0x9aa6fd: LEA RDI, [RAX + R14*0x4 + 0x8]
0x9aa702: MOV dword ptr [RDI], 0x0
0x9aa708: CALL 0x00c06910
0x9aa70d: JMP 0x009aa5da
0x9aa712: MOV RDI, qword ptr [RBP + -0x78]
0x9aa716: MOV dword ptr [RDI], 0x0
0x9aa71c: CALL 0x00c06910
0x9aa721: JMP 0x009aa5ee
0x9aa726: MOV qword ptr [RBP + -0x70], RCX
0x9aa72a: LEA RDI, [0x255ff90]
0x9aa731: MOV RSI, qword ptr [RBP + -0x70]
0x9aa735: CALL 0x0044f8c0
0x9aa73a: MOV RCX, qword ptr [RBP + -0x70]
0x9aa73e: JMP 0x009aa6cf
0x9aa740: MOV R12D, EAX
0x9aa743: MOV RBX, qword ptr [RBP + -0x38]
0x9aa747: MOV R15, qword ptr [RBP + -0x58]
0x9aa74b: CMP R15, RBX
0x9aa74e: JZ 0x009aa7bc
0x9aa750: MOV RAX, qword ptr [RBP + -0x48]
0x9aa754: MOV RSI, qword ptr [RBP + -0x40]
0x9aa758: MOV RDI, qword ptr [RAX + 0x1d8]
0x9aa75f: CALL 0x008ef340
0x9aa764: MOV RAX, qword ptr [RBP + -0x68]
0x9aa768: CMP byte ptr [RAX + 0x117], 0x0
0x9aa76f: JZ 0x009aa7a7
0x9aa771: LEA RCX, [0x1a962e8]
0x9aa778: MOV byte ptr [RAX + 0x117], 0x0
0x9aa77f: MOV RAX, qword ptr [RCX]
0x9aa782: MOV R14, qword ptr [RAX + 0x40]
0x9aa786: LEA RAX, [0x260ce8]
0x9aa78d: SUB RAX, R14
0x9aa790: ROR RAX, 0x3
0x9aa794: CMP RAX, 0x6ff
0x9aa79a: JA 0x009aa847
0x9aa7a0: MOV RDI, qword ptr [RBP + -0x48]
0x9aa7a4: CALL R14
0x9aa7a7: MOV RDI, qword ptr [RBP + -0x50]
0x9aa7ab: SUB RBX, R15
0x9aa7ae: MOV RSI, R15
0x9aa7b1: SHR RBX, 0x2
0x9aa7b5: MOV EDX, EBX
0x9aa7b7: CALL 0x009a86c0
0x9aa7bc: LEA RDI, [0x3ba5e78]
0x9aa7c3: XOR ESI, ESI
0x9aa7c5: XOR EDX, EDX
0x9aa7c7: XOR ECX, ECX
0x9aa7c9: CALL 0x004c6a00
0x9aa7ce: SUB R15D, dword ptr [0x03ba5ee0]
0x9aa7d5: MOV RAX, qword ptr [0x03ba5ed8]
0x9aa7dc: MOV RCX, RAX
0x9aa7df: SHR R15D, 0xd
0x9aa7e3: BTS RCX, R15
0x9aa7e7: MOV qword ptr [0x03ba5ed8], RCX
0x9aa7ee: TEST RAX, RAX
0x9aa7f1: JNZ 0x009aa7ff
0x9aa7f3: LEA RDI, [0x3ba5ed8]
0x9aa7fa: CALL 0x00c06910
0x9aa7ff: LEA RDI, [0x3ba5e78]
0x9aa806: XOR ESI, ESI
0x9aa808: XOR EDX, EDX
0x9aa80a: XOR ECX, ECX
0x9aa80c: CALL 0x004c6fa0
0x9aa811: MOV RAX, qword ptr [RBP + -0x98]
0x9aa818: LEA RCX, [0x391c310]
0x9aa81f: MOV qword ptr [RAX], R13
0x9aa822: MOV RAX, qword ptr [RCX]
0x9aa825: CMP RAX, qword ptr [RBP + -0x30]
0x9aa829: JNZ 0x009aa840
0x9aa82b: MOV EAX, R12D
0x9aa82e: ADD RSP, 0x88
0x9aa835: POP RBX
0x9aa836: POP R12
0x9aa838: POP R13
0x9aa83a: POP R14
0x9aa83c: POP R15
0x9aa83e: POP RBP
0x9aa83f: RET
0x9aa840: CALL 0x006fd6b0
0x9aa845: UD2
0x9aa847: LEA RDI, [0x255ffb0]
0x9aa84e: MOV RSI, R14
0x9aa851: CALL 0x0044f8c0
0x9aa856: JMP 0x009aa7a0

; local helper / adjacent context (reachability below); evidence ev_4ae66b92d54f5fd899cf283dce150abde5ebe29d4dc8a02e4dbd7f135da24e9e; body [{"start": "0x9aa860", "end": "0x9aa8cb"}]
sub_9aa860: ; RVA 0x9aa860
0x9aa860: PUSH RBP
0x9aa861: MOV RBP, RSP
0x9aa864: CMP dword ptr [R8 + 0x4], 0x0
0x9aa869: MOV EAX, 0x16
0x9aa86e: JNZ 0x009aa8ca
0x9aa870: MOV R9, R8
0x9aa873: MOV R8, qword ptr [R8 + 0x8]
0x9aa877: MOVZX R10D, R8W
0x9aa87b: TEST R10, R10
0x9aa87e: JNZ 0x009aa8ca
0x9aa880: MOV R10, qword ptr [R9 + 0x10]
0x9aa884: MOVZX R11D, R10W
0x9aa888: TEST R11, R11
0x9aa88b: JNZ 0x009aa8ca
0x9aa88d: CMP RDX, R8
0x9aa890: JA 0x009aa8ca
0x9aa892: CMP RCX, R8
0x9aa895: JBE 0x009aa8ca
0x9aa897: SUB RCX, R8
0x9aa89a: CMP RCX, R10
0x9aa89d: JC 0x009aa8ca
0x9aa89f: MOVZX R9D, byte ptr [R9 + 0x18]
0x9aa8a4: MOV ECX, R9D
0x9aa8a7: AND ECX, 0xffffffcc
0x9aa8aa: JNZ 0x009aa8ca
0x9aa8ac: TEST R10, R10
0x9aa8af: JZ 0x009aa8c8
0x9aa8b1: SUB R8, RDX
0x9aa8b4: MOV RCX, R8
0x9aa8b7: ADD R8, R10
0x9aa8ba: SHR RCX, 0x10
0x9aa8be: SHR R8, 0x10
0x9aa8c2: POP RBP
0x9aa8c3: JMP 0x009a87d0
0x9aa8c8: XOR EAX, EAX
0x9aa8ca: POP RBP
0x9aa8cb: RET

; local helper / adjacent context (reachability below); evidence ev_64ea9a7a212d6a383a464ec3c7a2aaabe5c375c7cf85c7f638818d22edb3c59c; body [{"start": "0x9aa8d0", "end": "0x9aaa06"}, {"start": "0x9aaa10", "end": "0x9aabd2"}, {"start": "0x9aabe0", "end": "0x9aac28"}, {"start": "0x9aac30", "end": "0x9aad8a"}, {"start": "0x9aad90", "end": "0x9aadd1"}, {"start": "0x9aade0", "end": "0x9aae8d"}, {"start": "0x9aae90", "end": "0x9aaf3e"}, {"start": "0x9aaf40", "end": "0x9ab034"}, {"start": "0x9ab040", "end": "0x9ab07e"}, {"start": "0x9ab080", "end": "0x9ab0c6"}, {"start": "0x9ab0d0", "end": "0x9ab15b"}]
sub_9aa8d0: ; RVA 0x9aa8d0
0x9aa8d0: PUSH RBP
0x9aa8d1: MOV RBP, RSP
0x9aa8d4: PUSH R15
0x9aa8d6: PUSH R14
0x9aa8d8: PUSH R13
0x9aa8da: PUSH R12
0x9aa8dc: PUSH RBX
0x9aa8dd: SUB RSP, 0x498
0x9aa8e4: LEA RAX, [0x391c310]
0x9aa8eb: MOV qword ptr [RBP + -0x468], RDX
0x9aa8f2: MOV R15, R8
0x9aa8f5: LEA R12, [RBP + -0x410]
0x9aa8fc: MOV RAX, qword ptr [RAX]
0x9aa8ff: MOV qword ptr [RBP + -0x30], RAX
0x9aa903: MOV qword ptr [RBP + -0x490], RSI
0x9aa90a: MOV qword ptr [RBP + -0x4a0], RDI
0x9aa911: MOV qword ptr [RBP + -0x4a8], R9
0x9aa918: MOV qword ptr [RBP + -0x450], -0x1
0x9aa923: MOV qword ptr [RBP + -0x448], 0x0
0x9aa92e: MOV qword ptr [RBP + -0x478], RCX
0x9aa935: MOV RDX, qword ptr [RSI + 0xe8]
0x9aa93c: MOVZX EAX, byte ptr [RDI + 0x244]
0x9aa943: MOV RSI, qword ptr [R9]
0x9aa946: MOV qword ptr [RBP + -0x470], RDX
0x9aa94d: LEA RDX, [RBP + -0x430]
0x9aa954: MOV byte ptr [RBP + -0x439], AL
0x9aa95a: MOV qword ptr [RBP + -0x460], RSI
0x9aa961: MOV qword ptr [RBP + -0x458], RDX
0x9aa968: CMP dword ptr [R15 + 0x4], 0x0
0x9aa96d: JNZ 0x009aab0a
0x9aa973: NOP dword ptr CS:[RAX + RAX*0x1]
0x9aa980: MOV R13, qword ptr [R15 + 0x8]
0x9aa984: MOVZX EAX, R13W
0x9aa988: TEST RAX, RAX
0x9aa98b: JNZ 0x009aab0a
0x9aa991: MOV R14, qword ptr [R15 + 0x10]
0x9aa995: MOVZX EAX, R14W
0x9aa999: TEST RAX, RAX
0x9aa99c: JNZ 0x009aab0a
0x9aa9a2: CMP qword ptr [RBP + -0x468], R13
0x9aa9a9: JA 0x009aab0a
0x9aa9af: CMP RCX, R13
0x9aa9b2: JBE 0x009aab0a
0x9aa9b8: MOV RAX, RCX
0x9aa9bb: SUB RAX, R13
0x9aa9be: CMP RAX, R14
0x9aa9c1: JC 0x009aab0a
0x9aa9c7: MOVZX EBX, byte ptr [R15 + 0x18]
0x9aa9cc: MOV EAX, EBX
0x9aa9ce: AND AL, 0xcc
0x9aa9d0: JNZ 0x009aab0a
0x9aa9d6: MOVZX EAX, byte ptr [R15 + 0x19]
0x9aa9db: MOVZX EDI, AL
0x9aa9de: CMP EDI, 0xa
0x9aa9e1: JA 0x009aaa10
0x9aa9e3: MOV ECX, 0x409
0x9aa9e8: BT ECX, EDI
0x9aa9eb: JNC 0x009aaa10
0x9aa9ed: TEST byte ptr [RBP + -0x439], 0x2
0x9aa9f4: JNZ 0x009aaa33
0x9aa9f6: CALL 0x009acc10
0x9aa9fb: TEST EAX, EAX
0x9aa9fd: SETZ AL
0x9aaa00: SHL AL, 0x2
0x9aaa03: ADD AL, 0xf
0x9aaa05: JMP 0x009aaa33
0x9aaa10: TEST byte ptr [RBP + -0x439], 0x2
0x9aaa17: MOV dword ptr [RBP + -0x440], 0x16
0x9aaa21: JNZ 0x009aab1f
0x9aaa27: ADD EDI, -0x15
0x9aaa2a: CMP EDI, -0xa
0x9aaa2d: JC 0x009aab1f
0x9aaa33: MOV RDX, qword ptr [RBP + -0x450]
0x9aaa3a: MOV RCX, R13
0x9aaa3d: ADD qword ptr [RBP + -0x458], 0x20
0x9aaa45: MOV qword ptr [R12 + -0x18], R13
0x9aaa4a: MOV qword ptr [R12 + -0x10], R14
0x9aaa4f: MOV byte ptr [R12 + -0x8], BL
0x9aaa54: MOV byte ptr [R12 + -0x7], AL
0x9aaa59: LEA RAX, [R14 + R13*0x1]
0x9aaa5d: AND RCX, -0x200000
0x9aaa64: CMP RDX, R13
0x9aaa67: CMOVA RDX, RCX
0x9aaa6b: MOV qword ptr [RBP + -0x450], RDX
0x9aaa72: LEA RDX, [R14 + R13*0x1 + 0x1fffff]
0x9aaa7a: MOV R13, qword ptr [RBP + -0x448]
0x9aaa81: AND RDX, -0x200000
0x9aaa88: CMP R13, RAX
0x9aaa8b: LEA RAX, [RBP + -0x30]
0x9aaa8f: CMOVC R13, RDX
0x9aaa93: CMP RAX, R12
0x9aaa96: JBE 0x009aab42
0x9aaa9c: MOV RBX, qword ptr [RBP + -0x460]
0x9aaaa3: CMP RBX, qword ptr [RBP + 0x10]
0x9aaaa7: JZ 0x009aab49
0x9aaaad: MOV RDI, qword ptr GS:[0x0]
0x9aaab6: LEA RSI, [0x1397f3d]
0x9aaabd: XOR EDX, EDX
0x9aaabf: CALL 0x00c1a3e0
0x9aaac4: MOV EDX, 0x20
0x9aaac9: MOV RDI, RBX
0x9aaacc: MOV RSI, R15
0x9aaacf: CALL 0x00259280
0x9aaad4: TEST EAX, EAX
0x9aaad6: JNZ 0x009ab10e
0x9aaadc: CMP dword ptr [R15], 0x4
0x9aaae0: JNZ 0x009aab2f
0x9aaae2: MOV RCX, qword ptr [RBP + -0x478]
0x9aaae9: ADD RBX, 0x20
0x9aaaed: MOV qword ptr [RBP + -0x448], R13
0x9aaaf4: ADD R12, 0x20
0x9aaaf8: MOV qword ptr [RBP + -0x460], RBX
0x9aaaff: CMP dword ptr [R15 + 0x4], 0x0
0x9aab04: JZ 0x009aa980
0x9aab0a: ADD R12, -0x20
0x9aab0e: MOV dword ptr [RBP + -0x440], 0x16
0x9aab18: MOV qword ptr [RBP + -0x458], R12
0x9aab1f: MOV RBX, qword ptr [RBP + -0x460]
0x9aab26: MOV R13, qword ptr [RBP + -0x448]
0x9aab2d: JMP 0x009aab53
0x9aab2f: MOV dword ptr [RBP + -0x440], 0x0
0x9aab39: MOV qword ptr [RBP + -0x458], R12
0x9aab40: JMP 0x009aab53
0x9aab42: MOV RBX, qword ptr [RBP + -0x460]
0x9aab49: MOV dword ptr [RBP + -0x440], 0x0
0x9aab53: MOV RSI, qword ptr [RBP + -0x450]
0x9aab5a: MOV R14, qword ptr [RBP + -0x490]
0x9aab61: CMP R13, RSI
0x9aab64: JBE 0x009aafff
0x9aab6a: MOV RAX, qword ptr [RBP + -0x468]
0x9aab71: MOV RDI, R14
0x9aab74: SUB R13, RAX
0x9aab77: SUB RSI, RAX
0x9aab7a: SHR R13, 0x10
0x9aab7e: SHR RSI, 0x10
0x9aab82: MOV EDX, R13D
0x9aab85: CALL 0x009a8080
0x9aab8a: MOV RCX, qword ptr [RBP + -0x4a0]
0x9aab91: MOV dword ptr [RBP + -0x484], EAX
0x9aab97: MOV R15, qword ptr [R14 + 0x160]
0x9aab9e: MOV RAX, qword ptr [RCX + 0x1d8]
0x9aaba5: LEA RCX, [RBP + -0x430]
0x9aabac: MOV qword ptr [RBP + -0x438], 0x0
0x9aabb7: MOV qword ptr [RBP + -0x480], RAX
0x9aabbe: CMP RCX, qword ptr [RBP + -0x458]
0x9aabc5: JZ 0x009aad04
0x9aabcb: XOR R8D, R8D
0x9aabce: XOR R13D, R13D
0x9aabd1: JMP 0x009aabff
0x9aabe0: MOV R8, qword ptr [RBP + -0x450]
0x9aabe7: MOV RCX, qword ptr [RBP + -0x448]
0x9aabee: ADD RCX, 0x20
0x9aabf2: CMP RCX, qword ptr [RBP + -0x458]
0x9aabf9: JZ 0x009aaced
0x9aabff: TEST byte ptr [RBP + -0x439], 0x2
0x9aac06: MOVZX EAX, byte ptr [RCX + 0x19]
0x9aac0a: MOV qword ptr [RBP + -0x450], R8
0x9aac11: JZ 0x009aac30
0x9aac13: XOR EBX, EBX
0x9aac15: CMP AL, 0xa
0x9aac17: MOV EDX, 0xc00000
0x9aac1c: SETZ BL
0x9aac1f: SHL EBX, 0x17
0x9aac22: TEST AL, AL
0x9aac24: CMOVZ EBX, EDX
0x9aac27: JMP 0x009aac45
0x9aac30: ADD AL, 0xf5
0x9aac32: XOR EBX, EBX
0x9aac34: CMP AL, 0x9
0x9aac36: JA 0x009aac45
0x9aac38: MOVZX EAX, AL
0x9aac3b: LEA RDX, [0x18cdb8c]
0x9aac42: MOV EBX, dword ptr [RDX + RAX*0x4]
0x9aac45: MOV RSI, qword ptr [RCX + 0x8]
0x9aac49: MOV RDX, qword ptr [RCX + 0x10]
0x9aac4d: MOV RAX, qword ptr [RBP + -0x468]
0x9aac54: MOV RDI, qword ptr [RBP + -0x480]
0x9aac5b: MOV qword ptr [RBP + -0x448], RCX
0x9aac62: LEA RCX, [RBP + -0x438]
0x9aac69: ADD RDX, RSI
0x9aac6c: MOV R14, RSI
0x9aac6f: MOV R12, RDX
0x9aac72: SUB R14, RAX
0x9aac75: SUB R12, RAX
0x9aac78: SHR R14, 0x10
0x9aac7c: SHR R12, 0x10
0x9aac80: CALL 0x008ee780
0x9aac85: CMP R14D, R12D
0x9aac88: JGE 0x009aabe0
0x9aac8e: MOV R8, qword ptr [RBP + -0x450]
0x9aac95: MOV EAX, EBX
0x9aac97: MOVSXD RCX, R14D
0x9aac9a: MOVSXD RDX, R12D
0x9aac9d: AND EAX, 0x800000
0x9aaca2: JMP 0x009aacca
0x9aaca4: DEC R8D
0x9aaca7: LEA RDI, [R13 + 0x10000]
0x9aacae: TEST ESI, ESI
0x9aacb0: CMOVZ RDI, R13
0x9aacb4: CMP EBX, 0xc00000
0x9aacba: CMOVNZ R13, RDI
0x9aacbe: INC RCX
0x9aacc1: CMP RDX, RCX
0x9aacc4: JZ 0x009aabe7
0x9aacca: MOV ESI, dword ptr [R15 + RCX*0x4]
0x9aacce: MOV EDI, ESI
0x9aacd0: AND EDI, 0xf00000
0x9aacd6: CMP EBX, EDI
0x9aacd8: JZ 0x009aacbe
0x9aacda: AND ESI, 0x800000
0x9aace0: CMP ESI, EAX
0x9aace2: JZ 0x009aaca7
0x9aace4: TEST EAX, EAX
0x9aace6: JZ 0x009aaca4
0x9aace8: INC R8D
0x9aaceb: JMP 0x009aaca7
0x9aaced: MOV RSI, qword ptr [RBP + -0x438]
0x9aacf4: CMP R13, 0x200000
0x9aacfb: MOV R13, R8
0x9aacfe: SETNC R12B
0x9aad02: JMP 0x009aad0c
0x9aad04: XOR ESI, ESI
0x9aad06: XOR R12D, R12D
0x9aad09: XOR R13D, R13D
0x9aad0c: MOV RDI, qword ptr [RBP + -0x480]
0x9aad13: CALL 0x008ef340
0x9aad18: MOV R14, qword ptr [RBP + -0x470]
0x9aad1f: XOR ESI, ESI
0x9aad21: XOR EDX, EDX
0x9aad23: XOR ECX, ECX
0x9aad25: LEA RBX, [R14 + 0x28]
0x9aad29: MOV RDI, RBX
0x9aad2c: CALL 0x004c6a00
0x9aad31: ADD dword ptr [R14 + 0x50], R13D
0x9aad35: SUB dword ptr [R14 + 0x54], R13D
0x9aad39: TEST R12B, R12B
0x9aad3c: JZ 0x009aaf65
0x9aad42: MOV RDI, R14
0x9aad45: CALL 0x009ac450
0x9aad4a: MOV RDI, RBX
0x9aad4d: XOR ESI, ESI
0x9aad4f: XOR EDX, EDX
0x9aad51: XOR ECX, ECX
0x9aad53: CALL 0x004c6fa0
0x9aad58: LEA RCX, [RBP + -0x430]
0x9aad5f: MOV qword ptr [RBP + -0x438], 0x0
0x9aad6a: CMP RCX, qword ptr [RBP + -0x458]
0x9aad71: JZ 0x009aaf92
0x9aad77: MOV RAX, qword ptr [RBP + -0x470]
0x9aad7e: MOV RDX, qword ptr [RAX + 0x30]
0x9aad82: MOV qword ptr [RBP + -0x4b0], RDX
0x9aad89: JMP 0x009aada8
0x9aad90: MOV RCX, qword ptr [RBP + -0x498]
0x9aad97: ADD RCX, 0x20
0x9aad9b: CMP RCX, qword ptr [RBP + -0x458]
0x9aada2: JZ 0x009aaf92
0x9aada8: TEST byte ptr [RBP + -0x439], 0x2
0x9aadaf: MOVZX EAX, byte ptr [RCX + 0x19]
0x9aadb3: JZ 0x009aade0
0x9aadb5: XOR ESI, ESI
0x9aadb7: CMP AL, 0xa
0x9aadb9: MOV EDI, 0xc00000
0x9aadbe: SETZ SIL
0x9aadc2: SHL ESI, 0x17
0x9aadc5: TEST AL, AL
0x9aadc7: CMOVZ ESI, EDI
0x9aadca: MOV dword ptr [RBP + -0x448], ESI
0x9aadd0: JMP 0x009aae03
0x9aade0: ADD AL, 0xf5
0x9aade2: MOV dword ptr [RBP + -0x448], 0x0
0x9aadec: CMP AL, 0x9
0x9aadee: JA 0x009aae03
0x9aadf0: MOVZX EAX, AL
0x9aadf3: LEA RSI, [0x18cdb8c]
0x9aadfa: MOV EAX, dword ptr [RSI + RAX*0x4]
0x9aadfd: MOV dword ptr [RBP + -0x448], EAX
0x9aae03: MOV RAX, qword ptr [RCX + 0x8]
0x9aae07: SUB RAX, qword ptr [RBP + -0x468]
0x9aae0e: MOV qword ptr [RBP + -0x498], RCX
0x9aae15: MOV RSI, RAX
0x9aae18: ADD RAX, qword ptr [RCX + 0x10]
0x9aae1c: SHR RSI, 0x10
0x9aae20: SHR RAX, 0x10
0x9aae24: MOV qword ptr [RBP + -0x478], RAX
0x9aae2b: CMP ESI, EAX
0x9aae2d: JGE 0x009aad90
0x9aae33: MOV RAX, qword ptr [RBP + -0x498]
0x9aae3a: MOVSXD RDI, dword ptr [RBP + -0x478]
0x9aae41: MOVZX ECX, byte ptr [RAX + 0x18]
0x9aae45: MOV EAX, 0x101
0x9aae4a: MOV qword ptr [RBP + -0x4b8], RDI
0x9aae51: BEXTR EAX, ECX, EAX
0x9aae56: OR EAX, ECX
0x9aae58: AND ECX, 0x30
0x9aae5b: AND EAX, 0x3
0x9aae5e: SHL ECX, 0x16
0x9aae61: SHL EAX, 0x18
0x9aae64: OR ECX, EAX
0x9aae66: MOV EAX, ESI
0x9aae68: INC EAX
0x9aae6a: MOV R13D, ECX
0x9aae6d: MOV qword ptr [RBP + -0x4c0], RCX
0x9aae74: CDQE
0x9aae76: ADD RAX, 0x1f
0x9aae7a: AND RAX, -0x20
0x9aae7e: CMP RDI, RAX
0x9aae81: CMOVC RAX, RDI
0x9aae85: OR R13D, dword ptr [RBP + -0x448]
0x9aae8c: JMP 0x009aaef2
0x9aae90: MOV RSI, RBX
0x9aae93: MOV RBX, qword ptr [RBP + -0x4b0]
0x9aae9a: MOV RDI, qword ptr [RBP + -0x480]
0x9aaea1: MOV R8, qword ptr [RBP + -0x450]
0x9aaea8: MOV R9D, dword ptr [RBP + -0x448]
0x9aaeaf: LEA RAX, [RBP + -0x438]
0x9aaeb6: MOV RDX, RBX
0x9aaeb9: PUSH RAX
0x9aaeba: PUSH qword ptr [RBP + -0x4c0]
0x9aaec0: CALL 0x008eeaa0
0x9aaec5: MOV RDX, RBX
0x9aaec8: ADD RSP, 0x10
0x9aaecc: MOV RCX, qword ptr [RBP + -0x4b8]
0x9aaed3: MOV RSI, qword ptr [RBP + -0x470]
0x9aaeda: LEA RAX, [R14 + 0x20]
0x9aaede: CMP RCX, RAX
0x9aaee1: CMOVC RAX, RCX
0x9aaee5: CMP R14D, dword ptr [RBP + -0x478]
0x9aaeec: JGE 0x009aad90
0x9aaef2: MOVSXD R12, ESI
0x9aaef5: MOV RDI, qword ptr [RBP + -0x4a0]
0x9aaefc: MOV ECX, EAX
0x9aaefe: MOV R9D, R13D
0x9aaf01: MOV R14D, EAX
0x9aaf04: MOV RBX, R12
0x9aaf07: LEA R8, [R15 + R12*0x4]
0x9aaf0b: SUB ECX, R12D
0x9aaf0e: SHL RBX, 0x10
0x9aaf12: ADD RBX, qword ptr [RBP + -0x468]
0x9aaf19: MOV qword ptr [RBP + -0x450], R8
0x9aaf20: MOV RSI, RBX
0x9aaf23: CALL 0x009ed630
0x9aaf28: MOV ECX, R14D
0x9aaf2b: MOV qword ptr [RBP + -0x470], R14
0x9aaf32: MOVSXD R14, R14D
0x9aaf35: SUB ECX, R12D
0x9aaf38: JG 0x009aaf4c
0x9aaf3a: JMP 0x009aae90
0x9aaf40: INC R12
0x9aaf43: CMP R14, R12
0x9aaf46: JZ 0x009aae90
0x9aaf4c: MOV EAX, dword ptr [R15 + R12*0x4]
0x9aaf50: TEST EAX, 0x30000000
0x9aaf55: JZ 0x009aaf40
0x9aaf57: AND EAX, 0xf00fffff
0x9aaf5c: OR EAX, R13D
0x9aaf5f: MOV dword ptr [R15 + R12*0x4], EAX
0x9aaf63: JMP 0x009aaf40
0x9aaf65: MOV RDI, RBX
0x9aaf68: XOR ESI, ESI
0x9aaf6a: XOR EDX, EDX
0x9aaf6c: XOR ECX, ECX
0x9aaf6e: CALL 0x004c6fa0
0x9aaf73: LEA RCX, [RBP + -0x430]
0x9aaf7a: CMP RCX, qword ptr [RBP + -0x458]
0x9aaf81: JNZ 0x009ab058
0x9aaf87: MOV qword ptr [RBP + -0x438], 0x0
0x9aaf92: MOV R15, qword ptr [RBP + -0x490]
0x9aaf99: MOV EAX, dword ptr [RBP + -0x484]
0x9aaf9f: XOR ESI, ESI
0x9aafa1: XOR EDX, EDX
0x9aafa3: LEA RBX, [R15 + 0x18]
0x9aafa7: LEA R14, [RAX + RAX*0x2]
0x9aafab: MOV RDI, RBX
0x9aafae: CALL 0x007d46a0
0x9aafb3: MOV dword ptr [R15 + R14*0x4 + 0x168], 0xffffffff
0x9aafbf: CMP dword ptr [R15 + R14*0x4 + 0x170], 0x0
0x9aafc8: JNZ 0x009ab119
0x9aafce: CMP dword ptr [R15 + 0x198], 0x0
0x9aafd6: JNZ 0x009ab13a
0x9aafdc: MOV RDI, RBX
0x9aafdf: XOR ESI, ESI
0x9aafe1: XOR EDX, EDX
0x9aafe3: CALL 0x007d4eb0
0x9aafe8: MOV RAX, qword ptr GS:[0x0]
0x9aaff1: MOV RBX, qword ptr [RBP + -0x460]
0x9aaff8: MOV byte ptr [RAX + 0x117], 0x1
0x9aafff: MOV RAX, qword ptr [RBP + -0x4a8]
0x9ab006: LEA RCX, [0x391c310]
0x9ab00d: MOV qword ptr [RAX], RBX
0x9ab010: MOV RAX, qword ptr [RCX]
0x9ab013: CMP RAX, qword ptr [RBP + -0x30]
0x9ab017: JNZ 0x009ab155
0x9ab01d: MOV EAX, dword ptr [RBP + -0x440]
0x9ab023: ADD RSP, 0x498
0x9ab02a: POP RBX
0x9ab02b: POP R12
0x9ab02d: POP R13
0x9ab02f: POP R14
0x9ab031: POP R15
0x9ab033: POP RBP
0x9ab034: RET
0x9ab040: MOV RCX, qword ptr [RBP + -0x450]
0x9ab047: ADD RCX, 0x20
0x9ab04b: CMP RCX, qword ptr [RBP + -0x458]
0x9ab052: JZ 0x009aad58
0x9ab058: TEST byte ptr [RBP + -0x439], 0x2
0x9ab05f: MOVZX EAX, byte ptr [RCX + 0x19]
0x9ab063: JZ 0x009ab080
0x9ab065: XOR R13D, R13D
0x9ab068: CMP AL, 0xa
0x9ab06a: MOV EDX, 0xc00000
0x9ab06f: SETZ R13B
0x9ab073: SHL R13D, 0x17
0x9ab077: TEST AL, AL
0x9ab079: CMOVZ R13D, EDX
0x9ab07d: JMP 0x009ab097
0x9ab080: ADD AL, 0xf5
0x9ab082: XOR R13D, R13D
0x9ab085: CMP AL, 0x9
0x9ab087: JA 0x009ab097
0x9ab089: MOVZX EAX, AL
0x9ab08c: LEA RDX, [0x18cdb8c]
0x9ab093: MOV R13D, dword ptr [RDX + RAX*0x4]
0x9ab097: MOV R12, qword ptr [RCX + 0x8]
0x9ab09b: SUB R12, qword ptr [RBP + -0x468]
0x9ab0a2: MOV qword ptr [RBP + -0x450], RCX
0x9ab0a9: MOV RAX, R12
0x9ab0ac: ADD R12, qword ptr [RCX + 0x10]
0x9ab0b0: SHR RAX, 0x10
0x9ab0b4: SHR R12, 0x10
0x9ab0b8: SUB R12D, EAX
0x9ab0bb: JLE 0x009ab040
0x9ab0bd: CDQE
0x9ab0bf: XOR EBX, EBX
0x9ab0c1: LEA R14, [R15 + RAX*0x4]
0x9ab0c5: JMP 0x009ab0dc
0x9ab0d0: INC RBX
0x9ab0d3: CMP R12D, EBX
0x9ab0d6: JZ 0x009ab040
0x9ab0dc: MOV ESI, dword ptr [R14 + RBX*0x4]
0x9ab0e0: MOV EAX, ESI
0x9ab0e2: AND EAX, 0x30800000
0x9ab0e7: CMP EAX, 0x10800000
0x9ab0ec: JNZ 0x009ab0d0
0x9ab0ee: MOV EAX, ESI
0x9ab0f0: AND EAX, 0xf00000
0x9ab0f5: CMP EAX, R13D
0x9ab0f8: JZ 0x009ab0d0
0x9ab0fa: MOV RDI, qword ptr [RBP + -0x470]
0x9ab101: AND ESI, 0xfffff
0x9ab107: CALL 0x009ac500
0x9ab10c: JMP 0x009ab0d0
0x9ab10e: MOV dword ptr [RBP + -0x440], EAX
0x9ab114: JMP 0x009aab53
0x9ab119: LEA RDI, [R15 + R14*0x4 + 0x170]
0x9ab121: MOV dword ptr [RDI], 0x0
0x9ab127: CALL 0x00c06910
0x9ab12c: CMP dword ptr [R15 + 0x198], 0x0
0x9ab134: JZ 0x009aafdc
0x9ab13a: ADD R15, 0x198
0x9ab141: MOV RDI, R15
0x9ab144: MOV dword ptr [R15], 0x0
0x9ab14b: CALL 0x00c06910
0x9ab150: JMP 0x009aafdc
0x9ab155: CALL 0x006fd6b0
0x9ab15a: UD2

; local helper / adjacent context (reachability below); evidence ev_64e75cc322d0d3307e7e56ecc4d3eb852116fb8e045f5b00997ad3145300b7e8; body [{"start": "0x9ab160", "end": "0x9ab1e9"}]
sub_9ab160: ; RVA 0x9ab160
0x9ab160: PUSH RBP
0x9ab161: MOV RBP, RSP
0x9ab164: CMP dword ptr [R8 + 0x4], 0x0
0x9ab169: MOV EAX, 0x16
0x9ab16e: JNZ 0x009ab1e8
0x9ab170: MOV R10, RCX
0x9ab173: MOV RCX, qword ptr [R8 + 0x8]
0x9ab177: MOV R9, R8
0x9ab17a: MOVZX R8D, CX
0x9ab17e: TEST R8, R8
0x9ab181: JNZ 0x009ab1e8
0x9ab183: MOV R8, qword ptr [R9 + 0x10]
0x9ab187: MOVZX R11D, R8W
0x9ab18b: TEST R11, R11
0x9ab18e: JNZ 0x009ab1e8
0x9ab190: MOV R9, qword ptr [R9 + 0x18]
0x9ab194: MOVZX R11D, R9W
0x9ab198: TEST R11, R11
0x9ab19b: JNZ 0x009ab1e8
0x9ab19d: CMP RDX, RCX
0x9ab1a0: JA 0x009ab1e8
0x9ab1a2: CMP R10, RCX
0x9ab1a5: JBE 0x009ab1e8
0x9ab1a7: MOV R11, R10
0x9ab1aa: SUB R11, RCX
0x9ab1ad: CMP R11, R9
0x9ab1b0: JC 0x009ab1e8
0x9ab1b2: CMP RDX, R8
0x9ab1b5: JA 0x009ab1e8
0x9ab1b7: CMP R10, R8
0x9ab1ba: JBE 0x009ab1e8
0x9ab1bc: SUB R10, R8
0x9ab1bf: CMP R10, R9
0x9ab1c2: JC 0x009ab1e8
0x9ab1c4: XOR EAX, EAX
0x9ab1c6: TEST R9, R9
0x9ab1c9: JZ 0x009ab1e8
0x9ab1cb: CMP R8, RCX
0x9ab1ce: JZ 0x009ab1e8
0x9ab1d0: SUB RCX, RDX
0x9ab1d3: SUB R8, RDX
0x9ab1d6: SHR R9, 0x10
0x9ab1da: SHR RCX, 0x10
0x9ab1de: SHR R8, 0x10
0x9ab1e2: POP RBP
0x9ab1e3: JMP 0x009ab370
0x9ab1e8: POP RBP
0x9ab1e9: RET

; local helper / adjacent context (reachability below); evidence ev_94e672233a4dc9bbea4212ea6e1c79296c6db475bf1230afb53e78aac411970b; body [{"start": "0x9ab1f0", "end": "0x9ab368"}]
sys_673: ; RVA 0x9ab1f0
0x9ab1f0: PUSH RBP
0x9ab1f1: MOV RBP, RSP
0x9ab1f4: PUSH R15
0x9ab1f6: PUSH R14
0x9ab1f8: PUSH R13
0x9ab1fa: PUSH R12
0x9ab1fc: PUSH RBX
0x9ab1fd: SUB RSP, 0x18
0x9ab201: LEA R13, [0x391c310]
0x9ab208: MOV RAX, qword ptr [R13]
0x9ab20c: MOV qword ptr [RBP + -0x30], RAX
0x9ab210: MOV RAX, qword ptr [RDI + 0x8]
0x9ab214: MOV R14, qword ptr [RSI]
0x9ab217: MOV RBX, qword ptr [RAX + 0x200]
0x9ab21e: MOV EAX, 0x16
0x9ab223: MOV RDI, qword ptr [RBX + 0x20]
0x9ab227: CMP RDI, R14
0x9ab22a: JA 0x009ab255
0x9ab22c: MOV RCX, qword ptr [RBX + 0x28]
0x9ab230: MOV R15, qword ptr [RSI + 0x8]
0x9ab234: MOV RDX, RCX
0x9ab237: SUB RDX, R14
0x9ab23a: SETBE R8B
0x9ab23e: TEST R14W, R14W
0x9ab242: SETNZ R9B
0x9ab246: OR R9B, R8B
0x9ab249: CMP RDI, R15
0x9ab24c: SETA DIL
0x9ab250: OR DIL, R9B
0x9ab253: JZ 0x009ab272
0x9ab255: MOV RCX, qword ptr [R13]
0x9ab259: CMP RCX, qword ptr [RBP + -0x30]
0x9ab25d: JNZ 0x009ab362
0x9ab263: ADD RSP, 0x18
0x9ab267: POP RBX
0x9ab268: POP R12
0x9ab26a: POP R13
0x9ab26c: POP R14
0x9ab26e: POP R15
0x9ab270: POP RBP
0x9ab271: RET
0x9ab272: TEST R15W, R15W
0x9ab276: JNZ 0x009ab255
0x9ab278: SUB RCX, R15
0x9ab27b: JBE 0x009ab255
0x9ab27d: MOV R12, qword ptr [RSI + 0x10]
0x9ab281: MOVZX EDI, R12W
0x9ab285: TEST RDI, RDI
0x9ab288: JNZ 0x009ab255
0x9ab28a: CMP RDX, R12
0x9ab28d: JC 0x009ab255
0x9ab28f: CMP RCX, R12
0x9ab292: JC 0x009ab255
0x9ab294: CMP dword ptr [RSI + 0x18], 0x0
0x9ab298: JNZ 0x009ab255
0x9ab29a: MOV RDI, RBX
0x9ab29d: XOR ESI, ESI
0x9ab29f: XOR EDX, EDX
0x9ab2a1: CALL 0x002c6820
0x9ab2a6: LEA RDX, [RBP + -0x38]
0x9ab2aa: MOV RDI, RBX
0x9ab2ad: MOV RSI, R14
0x9ab2b0: CALL 0x002c6c40
0x9ab2b5: MOV ECX, EAX
0x9ab2b7: MOV EAX, 0x16
0x9ab2bc: TEST ECX, ECX
0x9ab2be: JZ 0x009ab34d
0x9ab2c4: MOV RCX, qword ptr [RBP + -0x38]
0x9ab2c8: TEST byte ptr [RCX + 0x60], 0x2
0x9ab2cc: JNZ 0x009ab34d
0x9ab2ce: MOV RSI, qword ptr [RCX + 0x50]
0x9ab2d2: TEST RSI, RSI
0x9ab2d5: JZ 0x009ab34d
0x9ab2d7: CMP byte ptr [RSI + 0x9d], 0xb
0x9ab2de: JNZ 0x009ab34d
0x9ab2e0: MOV RDI, qword ptr [RCX + 0x28]
0x9ab2e4: MOV RDX, RDI
0x9ab2e7: SUB RDX, R14
0x9ab2ea: CMP RDX, R12
0x9ab2ed: JC 0x009ab34d
0x9ab2ef: MOV RDX, qword ptr [RCX + 0x20]
0x9ab2f3: CMP RDX, R15
0x9ab2f6: SETA CL
0x9ab2f9: SUB RDI, R15
0x9ab2fc: SETBE R8B
0x9ab300: OR R8B, CL
0x9ab303: CMP RDI, R12
0x9ab306: SETC CL
0x9ab309: OR CL, R8B
0x9ab30c: JNZ 0x009ab34d
0x9ab30e: TEST R12, R12
0x9ab311: SETZ CL
0x9ab314: CMP R15, R14
0x9ab317: SETZ DIL
0x9ab31b: XOR EAX, EAX
0x9ab31d: OR DIL, CL
0x9ab320: JNZ 0x009ab34d
0x9ab322: SUB R14, RDX
0x9ab325: SUB R15, RDX
0x9ab328: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x9ab330: SHR R12, 0x10
0x9ab334: MOV RDI, RBX
0x9ab337: SHR R14, 0x10
0x9ab33b: SHR R15, 0x10
0x9ab33f: MOV R9D, R12D
0x9ab342: MOV ECX, R14D
0x9ab345: MOV R8D, R15D
0x9ab348: CALL 0x009ab370
0x9ab34d: MOV RDI, RBX
0x9ab350: XOR ESI, ESI
0x9ab352: XOR EDX, EDX
0x9ab354: MOV EBX, EAX
0x9ab356: CALL 0x002c6870
0x9ab35b: MOV EAX, EBX
0x9ab35d: JMP 0x009ab255
0x9ab362: CALL 0x006fd6b0
0x9ab367: UD2

; local helper / adjacent context (reachability below); evidence ev_fde9b1a22ddae48c16fab7a4f8ff7b9f871b69079fe96236d0dd1be07e2376c5; body [{"start": "0x9ab370", "end": "0x9ab4d2"}, {"start": "0x9ab4e0", "end": "0x9ab815"}, {"start": "0x9ab820", "end": "0x9ab890"}, {"start": "0x9ab8a0", "end": "0x9ab9a3"}, {"start": "0x9ab9b0", "end": "0x9abc92"}]
sub_9ab370: ; RVA 0x9ab370
0x9ab370: PUSH RBP
0x9ab371: MOV RBP, RSP
0x9ab374: PUSH R15
0x9ab376: PUSH R14
0x9ab378: PUSH R13
0x9ab37a: PUSH R12
0x9ab37c: PUSH RBX
0x9ab37d: SUB RSP, 0xa8
0x9ab384: LEA RAX, [0x391c310]
0x9ab38b: MOV qword ptr [RBP + -0xc0], RDX
0x9ab392: MOV qword ptr [RBP + -0x90], RDI
0x9ab399: MOV R15D, ECX
0x9ab39c: MOV R13, RSI
0x9ab39f: MOV EDX, R8D
0x9ab3a2: LEA EDI, [R9 + R8*0x1 + 0x1f]
0x9ab3a7: MOV R14D, ECX
0x9ab3aa: AND EDX, 0xffffffe0
0x9ab3ad: MOV RAX, qword ptr [RAX]
0x9ab3b0: MOV qword ptr [RBP + -0x30], RAX
0x9ab3b4: MOV qword ptr [RBP + -0xa8], R9
0x9ab3bb: MOV qword ptr [RBP + -0x48], R13
0x9ab3bf: MOV qword ptr [RBP + -0xa0], R8
0x9ab3c6: MOV RAX, qword ptr [RSI + 0xe8]
0x9ab3cd: LEA ESI, [R9 + R15*0x1 + 0x1f]
0x9ab3d2: MOV R12, qword ptr [R13 + 0x160]
0x9ab3d9: MOV RBX, qword ptr [R13 + 0x190]
0x9ab3e0: MOV qword ptr [RBP + -0x40], 0x0
0x9ab3e8: AND ESI, 0xffffffe0
0x9ab3eb: CMP EDX, ESI
0x9ab3ed: MOV qword ptr [RBP + -0x88], RAX
0x9ab3f4: SETGE AL
0x9ab3f7: AND R14D, 0xffffffe0
0x9ab3fb: AND EDI, 0xffffffe0
0x9ab3fe: CMP R14D, EDI
0x9ab401: SETGE CL
0x9ab404: OR CL, AL
0x9ab406: LEA ECX, [R9 + R15*0x1]
0x9ab40a: LEA EAX, [R9 + R8*0x1]
0x9ab40e: MOV dword ptr [RBP + -0x58], ECX
0x9ab411: MOV dword ptr [RBP + -0x54], EAX
0x9ab414: JNZ 0x009ab447
0x9ab416: CMP R15D, R8D
0x9ab419: MOV ESI, R8D
0x9ab41c: MOV EDX, EAX
0x9ab41e: MOV RDI, R13
0x9ab421: MOV R14, R8
0x9ab424: MOV R13D, EAX
0x9ab427: CMOVL ESI, R15D
0x9ab42b: CMP ECX, EAX
0x9ab42d: CMOVG EDX, ECX
0x9ab430: CALL 0x009a8080
0x9ab435: MOV qword ptr [RBP + -0x80], RAX
0x9ab439: MOV EAX, 0xffffffff
0x9ab43e: MOV qword ptr [RBP + -0x68], RAX
0x9ab442: JMP 0x009ab73a
0x9ab447: MOV dword ptr [RBP + -0x70], EDI
0x9ab44a: LEA RDI, [R13 + 0x18]
0x9ab44e: MOV dword ptr [RBP + -0x68], ESI
0x9ab451: MOV dword ptr [RBP + -0x78], EDX
0x9ab454: MOV qword ptr [RBP + -0x50], 0x0
0x9ab45c: XOR ESI, ESI
0x9ab45e: XOR EDX, EDX
0x9ab460: MOV qword ptr [RBP + -0x98], RDI
0x9ab467: CALL 0x007d46a0
0x9ab46c: LEA R9, [R13 + 0x168]
0x9ab473: LEA R10, [R13 + 0x198]
0x9ab47a: LEA R11, [R13 + 0x174]
0x9ab481: LEA RDX, [R13 + 0x180]
0x9ab488: MOV EAX, dword ptr [R9]
0x9ab48b: MOV R8D, dword ptr [RBP + -0x68]
0x9ab48f: TEST EAX, EAX
0x9ab491: JNS 0x009ab597
0x9ab497: MOV RSI, qword ptr [RBP + -0x50]
0x9ab49b: CMP ESI, 0x1
0x9ab49e: JG 0x009ab4e0
0x9ab4a0: MOV EAX, ESI
0x9ab4a2: INC ESI
0x9ab4a4: MOV dword ptr [RBP + RAX*0x4 + -0x38], 0x0
0x9ab4ac: MOV EAX, dword ptr [R11]
0x9ab4af: TEST EAX, EAX
0x9ab4b1: JNS 0x009ab5c4
0x9ab4b7: MOV R13D, 0x2
0x9ab4bd: CMP ESI, 0x1
0x9ab4c0: JG 0x009ab4f6
0x9ab4c2: MOV EAX, ESI
0x9ab4c4: INC ESI
0x9ab4c6: MOV dword ptr [RBP + RAX*0x4 + -0x38], 0x1
0x9ab4ce: MOV R13D, ESI
0x9ab4d1: JMP 0x009ab4f6
0x9ab4e0: MOV EAX, dword ptr [R11]
0x9ab4e3: MOV ESI, 0x2
0x9ab4e8: MOV R13D, 0x2
0x9ab4ee: TEST EAX, EAX
0x9ab4f0: JNS 0x009ab5c4
0x9ab4f6: MOV EAX, dword ptr [RDX]
0x9ab4f8: TEST EAX, EAX
0x9ab4fa: JNS 0x009ab5f6
0x9ab500: CMP R13D, 0x1
0x9ab504: JG 0x009ab6dd
0x9ab50a: MOV EAX, R13D
0x9ab50d: INC R13D
0x9ab510: MOV dword ptr [RBP + RAX*0x4 + -0x38], 0x2
0x9ab518: CMP R13D, 0x2
0x9ab51c: JZ 0x009ab6dd
0x9ab522: MOV qword ptr [RBP + -0x60], RDX
0x9ab526: MOV qword ptr [RBP + -0xb0], R11
0x9ab52d: MOV qword ptr [RBP + -0xb8], R9
0x9ab534: MOV dword ptr [R10], 0x1
0x9ab53b: MOV qword ptr [RBP + -0x80], R10
0x9ab53f: MOV RSI, qword ptr [RBP + -0x48]
0x9ab543: MOV RDI, R10
0x9ab546: MOV EDX, 0x44
0x9ab54b: LEA RCX, [0x1394bd1]
0x9ab552: MOV dword ptr [RSP], 0x100
0x9ab559: XOR R8D, R8D
0x9ab55c: XOR R9D, R9D
0x9ab55f: CALL 0x00c06260
0x9ab564: MOV RAX, qword ptr [RBP + -0x48]
0x9ab568: MOV R10, qword ptr [RBP + -0x80]
0x9ab56c: CMP dword ptr [RAX + 0x198], 0x0
0x9ab573: JNZ 0x009ab53f
0x9ab575: MOV EAX, R13D
0x9ab578: MOV R13, qword ptr [RBP + -0x48]
0x9ab57c: MOV R9, qword ptr [RBP + -0xb8]
0x9ab583: MOV R11, qword ptr [RBP + -0xb0]
0x9ab58a: MOV RDX, qword ptr [RBP + -0x60]
0x9ab58e: MOV qword ptr [RBP + -0x50], RAX
0x9ab592: JMP 0x009ab488
0x9ab597: MOV ECX, dword ptr [R13 + 0x16c]
0x9ab59e: MOV qword ptr [RBP + -0x60], RDX
0x9ab5a2: CMP R14D, ECX
0x9ab5a5: SETL DL
0x9ab5a8: CMP EAX, R8D
0x9ab5ab: SETL SIL
0x9ab5af: TEST SIL, DL
0x9ab5b2: JZ 0x009ab61d
0x9ab5b4: MOV RDX, qword ptr [RBP + -0x60]
0x9ab5b8: MOV RSI, qword ptr [RBP + -0x50]
0x9ab5bc: MOV RDI, R9
0x9ab5bf: JMP 0x009ab678
0x9ab5c4: MOV RCX, qword ptr [RBP + -0x48]
0x9ab5c8: MOV qword ptr [RBP + -0x60], RDX
0x9ab5cc: MOV R13, RSI
0x9ab5cf: MOV ECX, dword ptr [RCX + 0x178]
0x9ab5d5: CMP R14D, ECX
0x9ab5d8: SETL DL
0x9ab5db: CMP EAX, R8D
0x9ab5de: SETL SIL
0x9ab5e2: TEST SIL, DL
0x9ab5e5: JZ 0x009ab63e
0x9ab5e7: MOV RDX, qword ptr [RBP + -0x60]
0x9ab5eb: MOV RDI, R11
0x9ab5ee: MOV RSI, R13
0x9ab5f1: JMP 0x009ab678
0x9ab5f6: MOV RCX, qword ptr [RBP + -0x48]
0x9ab5fa: MOV RDI, RDX
0x9ab5fd: MOV ECX, dword ptr [RCX + 0x184]
0x9ab603: CMP R14D, ECX
0x9ab606: SETL DL
0x9ab609: CMP EAX, R8D
0x9ab60c: SETL SIL
0x9ab610: TEST SIL, DL
0x9ab613: JZ 0x009ab65e
0x9ab615: MOV ESI, R13D
0x9ab618: MOV RDX, RDI
0x9ab61b: JMP 0x009ab678
0x9ab61d: CMP dword ptr [RBP + -0x78], ECX
0x9ab620: MOV RDX, qword ptr [RBP + -0x60]
0x9ab624: MOV RSI, qword ptr [RBP + -0x50]
0x9ab628: MOV RDI, R9
0x9ab62b: SETGE CL
0x9ab62e: CMP EAX, dword ptr [RBP + -0x70]
0x9ab631: SETGE AL
0x9ab634: OR AL, CL
0x9ab636: JNZ 0x009ab4ac
0x9ab63c: JMP 0x009ab678
0x9ab63e: CMP dword ptr [RBP + -0x78], ECX
0x9ab641: MOV RDX, qword ptr [RBP + -0x60]
0x9ab645: MOV RDI, R11
0x9ab648: MOV RSI, R13
0x9ab64b: SETL CL
0x9ab64e: CMP EAX, dword ptr [RBP + -0x70]
0x9ab651: SETL AL
0x9ab654: TEST AL, CL
0x9ab656: JZ 0x009ab4f6
0x9ab65c: JMP 0x009ab678
0x9ab65e: CMP dword ptr [RBP + -0x78], ECX
0x9ab661: MOV ESI, R13D
0x9ab664: MOV RDX, RDI
0x9ab667: SETL CL
0x9ab66a: CMP EAX, dword ptr [RBP + -0x70]
0x9ab66d: SETL AL
0x9ab670: TEST AL, CL
0x9ab672: JZ 0x009ab518
0x9ab678: MOV R13, qword ptr [RBP + -0x48]
0x9ab67c: MOV dword ptr [RDI + 0x8], 0x1
0x9ab683: MOV qword ptr [RBP + -0x50], RSI
0x9ab687: MOV qword ptr [RBP + -0x60], RDX
0x9ab68b: ADD RDI, 0x8
0x9ab68f: MOV EDX, 0x44
0x9ab694: LEA RCX, [0x1375e9b]
0x9ab69b: MOV qword ptr [RBP + -0xb8], R9
0x9ab6a2: MOV dword ptr [RSP], 0x100
0x9ab6a9: XOR R8D, R8D
0x9ab6ac: XOR R9D, R9D
0x9ab6af: MOV qword ptr [RBP + -0x80], R10
0x9ab6b3: MOV qword ptr [RBP + -0xb0], R11
0x9ab6ba: MOV RSI, R13
0x9ab6bd: CALL 0x00c06260
0x9ab6c2: MOV RDX, qword ptr [RBP + -0x60]
0x9ab6c6: MOV R11, qword ptr [RBP + -0xb0]
0x9ab6cd: MOV R10, qword ptr [RBP + -0x80]
0x9ab6d1: MOV R9, qword ptr [RBP + -0xb8]
0x9ab6d8: JMP 0x009ab488
0x9ab6dd: MOVSXD RAX, dword ptr [RBP + -0x38]
0x9ab6e1: MOV ECX, dword ptr [RBP + -0x78]
0x9ab6e4: MOV EDI, dword ptr [RBP + -0x70]
0x9ab6e7: XOR ESI, ESI
0x9ab6e9: XOR EDX, EDX
0x9ab6eb: MOV qword ptr [RBP + -0x80], RAX
0x9ab6ef: LEA RAX, [RAX + RAX*0x2]
0x9ab6f3: MOV dword ptr [R9 + RAX*0x4], R14D
0x9ab6f7: MOV dword ptr [R9 + RAX*0x4 + 0x4], R8D
0x9ab6fc: MOV dword ptr [R9 + RAX*0x4 + 0x8], 0x0
0x9ab705: MOVSXD RAX, dword ptr [RBP + -0x34]
0x9ab709: MOV qword ptr [RBP + -0x68], RAX
0x9ab70d: LEA RAX, [RAX + RAX*0x2]
0x9ab711: MOV dword ptr [R9 + RAX*0x4], ECX
0x9ab715: MOV dword ptr [R9 + RAX*0x4 + 0x4], EDI
0x9ab71a: MOV RDI, qword ptr [RBP + -0x98]
0x9ab721: MOV dword ptr [R9 + RAX*0x4 + 0x8], 0x0
0x9ab72a: CALL 0x007d4eb0
0x9ab72f: MOV R14, qword ptr [RBP + -0xa0]
0x9ab736: MOV R13D, dword ptr [RBP + -0x54]
0x9ab73a: MOVSXD RAX, R15D
0x9ab73d: MOVSXD R9, R13D
0x9ab740: MOV R8, R14
0x9ab743: MOV qword ptr [RBP + -0x50], RAX
0x9ab747: CMP R15D, R14D
0x9ab74a: JGE 0x009ab796
0x9ab74c: MOV ESI, dword ptr [RBP + -0x58]
0x9ab74f: MOV R13, qword ptr [RBP + -0xa8]
0x9ab756: MOV RDI, qword ptr [RBP + -0x90]
0x9ab75d: MOV R10, qword ptr [RBP + -0x88]
0x9ab764: CMP ESI, R15D
0x9ab767: JLE 0x009ab7f2
0x9ab76d: MOV RCX, qword ptr [RBP + -0x50]
0x9ab771: CMP ESI, R8D
0x9ab774: MOV EAX, R8D
0x9ab777: CMOVL EAX, ESI
0x9ab77a: CDQE
0x9ab77c: NOP dword ptr [RAX]
0x9ab780: TEST byte ptr [R12 + RCX*0x4 + 0x3], 0x30
0x9ab786: JNZ 0x009aba41
0x9ab78c: INC RCX
0x9ab78f: CMP RCX, RAX
0x9ab792: JL 0x009ab780
0x9ab794: JMP 0x009ab7f2
0x9ab796: CMP R13D, R15D
0x9ab799: MOV EDX, R15D
0x9ab79c: MOV ESI, dword ptr [RBP + -0x58]
0x9ab79f: MOV RDI, qword ptr [RBP + -0x90]
0x9ab7a6: MOV R10, qword ptr [RBP + -0x88]
0x9ab7ad: CMOVG EDX, R13D
0x9ab7b1: MOV R13, qword ptr [RBP + -0xa8]
0x9ab7b8: CMP EDX, ESI
0x9ab7ba: JGE 0x009ab7f2
0x9ab7bc: MOV RCX, qword ptr [RBP + -0x50]
0x9ab7c0: MOV RAX, R9
0x9ab7c3: CMP RCX, R9
0x9ab7c6: CMOVG RAX, RCX
0x9ab7ca: MOV ECX, ESI
0x9ab7cc: SUB ECX, EDX
0x9ab7ce: LEA RAX, [R12 + RAX*0x4]
0x9ab7d2: XOR EDX, EDX
0x9ab7d4: NOP word ptr CS:[RAX + RAX*0x1]
0x9ab7e0: TEST byte ptr [RAX + RDX*0x4 + 0x3], 0x30
0x9ab7e5: JNZ 0x009aba41
0x9ab7eb: INC RDX
0x9ab7ee: CMP ECX, EDX
0x9ab7f0: JNZ 0x009ab7e0
0x9ab7f2: MOV qword ptr [RBP + -0x78], R9
0x9ab7f6: XOR R14D, R14D
0x9ab7f9: CMP R15D, ESI
0x9ab7fc: JGE 0x009ab869
0x9ab7fe: MOVSXD RAX, dword ptr [RBP + -0x58]
0x9ab802: SUB RAX, qword ptr [RBP + -0x50]
0x9ab806: MOV ECX, 0x30000000
0x9ab80b: MOV EDX, R8D
0x9ab80e: MOV ESI, R15D
0x9ab811: XOR R14D, R14D
0x9ab814: JMP 0x009ab829
0x9ab820: INC ESI
0x9ab822: INC EDX
0x9ab824: DEC RAX
0x9ab827: JZ 0x009ab869
0x9ab829: MOVSXD R9, EDX
0x9ab82c: MOV R9D, dword ptr [R12 + R9*0x4]
0x9ab830: AND R9D, ECX
0x9ab833: CMP R9D, 0x10000000
0x9ab83a: JNZ 0x009ab820
0x9ab83c: MOV EDI, ESI
0x9ab83e: SAR EDI, 0x5
0x9ab841: MOVSXD RDI, EDI
0x9ab844: MOVZX R10D, byte ptr [RBX + RDI*0x1]
0x9ab849: LEA R9D, [R10 + 0x1]
0x9ab84d: CMP R10B, 0x1
0x9ab851: MOV R10, qword ptr [RBP + -0x88]
0x9ab858: MOV byte ptr [RBX + RDI*0x1], R9B
0x9ab85c: MOV RDI, qword ptr [RBP + -0x90]
0x9ab863: ADC R14D, 0x0
0x9ab867: JMP 0x009ab820
0x9ab869: MOVSXD RDX, R8D
0x9ab86c: MOV R11, R13
0x9ab86f: MOV qword ptr [RBP + -0x70], RDX
0x9ab873: CMP R8D, dword ptr [RBP + -0x54]
0x9ab877: JGE 0x009ab8e1
0x9ab879: MOV RAX, qword ptr [RBP + -0x78]
0x9ab87d: MOV ECX, R8D
0x9ab880: MOV R13D, 0x30000000
0x9ab886: XOR ESI, ESI
0x9ab888: SUB RAX, RDX
0x9ab88b: LEA RDX, [R12 + RDX*0x4]
0x9ab88f: JMP 0x009ab8a8
0x9ab8a0: INC RSI
0x9ab8a3: CMP RAX, RSI
0x9ab8a6: JZ 0x009ab8e1
0x9ab8a8: MOV R9D, dword ptr [RDX + RSI*0x4]
0x9ab8ac: AND R9D, R13D
0x9ab8af: CMP R9D, 0x10000000
0x9ab8b6: JNZ 0x009ab8a0
0x9ab8b8: LEA R9D, [RCX + RSI*0x1]
0x9ab8bc: MOV RDI, qword ptr [RBP + -0x90]
0x9ab8c3: SAR R9D, 0x5
0x9ab8c7: MOVSXD R10, R9D
0x9ab8ca: XOR R9D, R9D
0x9ab8cd: DEC byte ptr [RBX + R10*0x1]
0x9ab8d1: MOV R10, qword ptr [RBP + -0x88]
0x9ab8d8: SETZ R9B
0x9ab8dc: SUB R14D, R9D
0x9ab8df: JMP 0x009ab8a0
0x9ab8e1: TEST R14D, R14D
0x9ab8e4: JLE 0x009ab91b
0x9ab8e6: MOV RAX, qword ptr [RBP + -0x48]
0x9ab8ea: MOV ESI, R14D
0x9ab8ed: MOV R13, R8
0x9ab8f0: MOVZX EDI, byte ptr [RAX + 0x19c]
0x9ab8f7: CALL 0x008ed550
0x9ab8fc: MOV R10, qword ptr [RBP + -0x88]
0x9ab903: MOV RDI, qword ptr [RBP + -0x90]
0x9ab90a: MOV R11, qword ptr [RBP + -0xa8]
0x9ab911: MOV R8, R13
0x9ab914: MOV R13D, EAX
0x9ab917: TEST EAX, EAX
0x9ab919: JNZ 0x009ab985
0x9ab91b: MOV RSI, qword ptr [R10 + 0x30]
0x9ab91f: MOV RAX, qword ptr GS:[0x0]
0x9ab928: XOR ECX, ECX
0x9ab92a: CMP byte ptr [RAX + 0x116], 0x0
0x9ab931: MOV R13, qword ptr [RBP + -0xc0]
0x9ab938: MOV R9, R12
0x9ab93b: MOV dword ptr [RSP], R11D
0x9ab93f: MOV RDX, R13
0x9ab942: SETZ CL
0x9ab945: MOV dword ptr [RSP + 0x8], ECX
0x9ab949: MOV ECX, R15D
0x9ab94c: CALL 0x009edec0
0x9ab951: MOV dword ptr [RBP + -0x98], EAX
0x9ab957: TEST EAX, EAX
0x9ab959: JZ 0x009aba53
0x9ab95f: TEST R14D, R14D
0x9ab962: JLE 0x009ab977
0x9ab964: MOV RAX, qword ptr [RBP + -0x48]
0x9ab968: MOV ESI, R14D
0x9ab96b: MOVZX EDI, byte ptr [RAX + 0x19c]
0x9ab972: CALL 0x008ed5d0
0x9ab977: MOV R8, qword ptr [RBP + -0xa0]
0x9ab97e: MOV R13D, dword ptr [RBP + -0x98]
0x9ab985: MOV EAX, dword ptr [RBP + -0x58]
0x9ab988: MOV EDI, dword ptr [RBP + -0x54]
0x9ab98b: MOV R9, qword ptr [RBP + -0x78]
0x9ab98f: CMP R15D, EAX
0x9ab992: JGE 0x009ab9d9
0x9ab994: CDQE
0x9ab996: SUB RAX, qword ptr [RBP + -0x50]
0x9ab99a: MOV ECX, 0x30000000
0x9ab99f: MOV EDX, R8D
0x9ab9a2: JMP 0x009ab9ba
0x9ab9b0: INC R15D
0x9ab9b3: INC EDX
0x9ab9b5: DEC RAX
0x9ab9b8: JZ 0x009ab9d9
0x9ab9ba: MOVSXD RSI, EDX
0x9ab9bd: MOV ESI, dword ptr [R12 + RSI*0x4]
0x9ab9c1: AND ESI, ECX
0x9ab9c3: CMP ESI, 0x10000000
0x9ab9c9: JNZ 0x009ab9b0
0x9ab9cb: MOV ESI, R15D
0x9ab9ce: SAR ESI, 0x5
0x9ab9d1: MOVSXD RSI, ESI
0x9ab9d4: INC byte ptr [RBX + RSI*0x1]
0x9ab9d7: JMP 0x009ab9b0
0x9ab9d9: CMP R8D, EDI
0x9ab9dc: JGE 0x009aba23
0x9ab9de: MOV RCX, qword ptr [RBP + -0x70]
0x9ab9e2: MOV EAX, R8D
0x9ab9e5: LEA R15, [0x391c310]
0x9ab9ec: MOV R8, qword ptr [RBP + -0x68]
0x9ab9f0: MOV ESI, 0x30000000
0x9ab9f5: XOR EDX, EDX
0x9ab9f7: SUB R9, RCX
0x9ab9fa: LEA RCX, [R12 + RCX*0x4]
0x9ab9fe: JMP 0x009aba08
0x9aba00: INC RDX
0x9aba03: CMP R9, RDX
0x9aba06: JZ 0x009aba2f
0x9aba08: MOV EDI, dword ptr [RCX + RDX*0x4]
0x9aba0b: AND EDI, ESI
0x9aba0d: CMP EDI, 0x10000000
0x9aba13: JNZ 0x009aba00
0x9aba15: LEA EDI, [RAX + RDX*0x1]
0x9aba18: SAR EDI, 0x5
0x9aba1b: MOVSXD RDI, EDI
0x9aba1e: INC byte ptr [RBX + RDI*0x1]
0x9aba21: JMP 0x009aba00
0x9aba23: LEA R15, [0x391c310]
0x9aba2a: JMP 0x009abb37
0x9aba2f: MOV R12, qword ptr [RBP + -0x48]
0x9aba33: TEST R8D, R8D
0x9aba36: JNS 0x009abb44
0x9aba3c: JMP 0x009abb92
0x9aba41: LEA R15, [0x391c310]
0x9aba48: MOV R13D, 0x10
0x9aba4e: JMP 0x009abb37
0x9aba53: MOV RSI, qword ptr [RBP + -0x70]
0x9aba57: MOV RDX, qword ptr [RBP + -0x78]
0x9aba5b: MOV RBX, qword ptr [RBP + -0x50]
0x9aba5f: LEA RCX, [RBP + -0x40]
0x9aba63: SHL RSI, 0x10
0x9aba67: SHL RDX, 0x10
0x9aba6b: SHL RBX, 0x10
0x9aba6f: ADD RSI, R13
0x9aba72: ADD RDX, R13
0x9aba75: ADD RBX, R13
0x9aba78: MOV R13, qword ptr [RBP + -0x90]
0x9aba7f: MOV RDI, qword ptr [R13 + 0x1d8]
0x9aba86: CALL 0x008ee780
0x9aba8b: MOV RDI, qword ptr [R13 + 0x1d8]
0x9aba92: MOV RSI, qword ptr [RBP + -0x40]
0x9aba96: CALL 0x008ef340
0x9aba9b: MOV RAX, qword ptr [RBP + -0x88]
0x9abaa2: MOV RDI, qword ptr [R13 + 0x1d8]
0x9abaa9: MOV R13, qword ptr [RBP + -0xa8]
0x9abab0: MOV RDX, RBX
0x9abab3: MOV RSI, qword ptr [RAX + 0x30]
0x9abab7: MOV RAX, qword ptr [RBP + -0x70]
0x9ababb: MOV R8D, R13D
0x9ababe: LEA RAX, [R12 + RAX*0x4]
0x9abac2: MOV RCX, RAX
0x9abac5: MOV RBX, RAX
0x9abac8: CALL 0x008e4d70
0x9abacd: MOV RAX, qword ptr [RBP + -0x50]
0x9abad1: MOVSXD RDX, R13D
0x9abad4: MOV RDI, RBX
0x9abad7: SHL RDX, 0x2
0x9abadb: LEA RSI, [R12 + RAX*0x4]
0x9abadf: CALL 0x00259be0
0x9abae4: MOV RAX, qword ptr [RBP + -0xa0]
0x9abaeb: CMP R15D, EAX
0x9abaee: JGE 0x009abb05
0x9abaf0: MOV ECX, dword ptr [RBP + -0x58]
0x9abaf3: CMP ECX, EAX
0x9abaf5: CMOVG EAX, ECX
0x9abaf8: MOV ECX, dword ptr [RBP + -0x54]
0x9abafb: CDQE
0x9abafd: LEA RBX, [R12 + RAX*0x4]
0x9abb01: SUB ECX, EAX
0x9abb03: JMP 0x009abb15
0x9abb05: MOV ECX, dword ptr [RBP + -0x54]
0x9abb08: CMP ECX, R15D
0x9abb0b: CMOVL R15D, ECX
0x9abb0f: SUB R15D, EAX
0x9abb12: MOV ECX, R15D
0x9abb15: LEA R15, [0x391c310]
0x9abb1c: MOVSXD RSI, ECX
0x9abb1f: MOV RDI, RBX
0x9abb22: SHL RSI, 0x2
0x9abb26: CALL 0x00258ff0
0x9abb2b: XOR R13D, R13D
0x9abb2e: TEST R14D, R14D
0x9abb31: JS 0x009abbfb
0x9abb37: MOV R12, qword ptr [RBP + -0x48]
0x9abb3b: MOV R8, qword ptr [RBP + -0x68]
0x9abb3f: TEST R8D, R8D
0x9abb42: JS 0x009abb92
0x9abb44: LEA R14, [R12 + 0x18]
0x9abb49: MOV EAX, R8D
0x9abb4c: XOR ESI, ESI
0x9abb4e: XOR EDX, EDX
0x9abb50: MOV RDI, R14
0x9abb53: LEA RBX, [RAX + RAX*0x2]
0x9abb57: CALL 0x007d46a0
0x9abb5c: MOV dword ptr [R12 + RBX*0x4 + 0x168], 0xffffffff
0x9abb68: CMP dword ptr [R12 + RBX*0x4 + 0x170], 0x0
0x9abb71: JNZ 0x009abc52
0x9abb77: CMP dword ptr [R12 + 0x198], 0x0
0x9abb80: JNZ 0x009abc74
0x9abb86: MOV RDI, R14
0x9abb89: XOR ESI, ESI
0x9abb8b: XOR EDX, EDX
0x9abb8d: CALL 0x007d4eb0
0x9abb92: MOVSXD RAX, dword ptr [RBP + -0x80]
0x9abb96: LEA R14, [R12 + 0x18]
0x9abb9b: XOR ESI, ESI
0x9abb9d: XOR EDX, EDX
0x9abb9f: MOV RDI, R14
0x9abba2: LEA RBX, [RAX + RAX*0x2]
0x9abba6: CALL 0x007d46a0
0x9abbab: MOV dword ptr [R12 + RBX*0x4 + 0x168], 0xffffffff
0x9abbb7: CMP dword ptr [R12 + RBX*0x4 + 0x170], 0x0
0x9abbc0: JNZ 0x009abc18
0x9abbc2: CMP dword ptr [R12 + 0x198], 0x0
0x9abbcb: JNZ 0x009abc36
0x9abbcd: MOV RDI, R14
0x9abbd0: XOR ESI, ESI
0x9abbd2: XOR EDX, EDX
0x9abbd4: CALL 0x007d4eb0
0x9abbd9: MOV RAX, qword ptr [R15]
0x9abbdc: CMP RAX, qword ptr [RBP + -0x30]
0x9abbe0: JNZ 0x009abc8c
0x9abbe6: MOV EAX, R13D
0x9abbe9: ADD RSP, 0xa8
0x9abbf0: POP RBX
0x9abbf1: POP R12
0x9abbf3: POP R13
0x9abbf5: POP R14
0x9abbf7: POP R15
0x9abbf9: POP RBP
0x9abbfa: RET
0x9abbfb: MOV R12, qword ptr [RBP + -0x48]
0x9abbff: NEG R14D
0x9abc02: MOV ESI, R14D
0x9abc05: MOVZX EDI, byte ptr [R12 + 0x19c]
0x9abc0e: CALL 0x008ed5d0
0x9abc13: JMP 0x009abb3b
0x9abc18: LEA RDI, [R12 + RBX*0x4 + 0x170]
0x9abc20: MOV dword ptr [RDI], 0x0
0x9abc26: CALL 0x00c06910
0x9abc2b: CMP dword ptr [R12 + 0x198], 0x0
0x9abc34: JZ 0x009abbcd
0x9abc36: ADD R12, 0x198
0x9abc3d: MOV RDI, R12
0x9abc40: MOV dword ptr [R12], 0x0
0x9abc48: CALL 0x00c06910
0x9abc4d: JMP 0x009abbcd
0x9abc52: LEA RDI, [R12 + RBX*0x4 + 0x170]
0x9abc5a: MOV dword ptr [RDI], 0x0
0x9abc60: CALL 0x00c06910
0x9abc65: CMP dword ptr [R12 + 0x198], 0x0
0x9abc6e: JZ 0x009abb86
0x9abc74: LEA RDI, [R12 + 0x198]
0x9abc7c: MOV dword ptr [RDI], 0x0
0x9abc82: CALL 0x00c06910
0x9abc87: JMP 0x009abb86
0x9abc8c: CALL 0x006fd6b0
0x9abc91: UD2

; local helper / adjacent context (reachability below); evidence ev_4174179a2f30bd0a0e1fba71c675625d71b19c47c49f871acfaf2277dbac8c08; body [{"start": "0x9abca0", "end": "0x9abd7c"}, {"start": "0x9abd80", "end": "0x9abe73"}, {"start": "0x9abe80", "end": "0x9abf6b"}, {"start": "0x9abf70", "end": "0x9ac08b"}, {"start": "0x9ac090", "end": "0x9ac1a3"}, {"start": "0x9ac1b0", "end": "0x9ac295"}, {"start": "0x9ac2a0", "end": "0x9ac449"}]
sub_9abca0: ; RVA 0x9abca0
0x9abca0: PUSH RBP
0x9abca1: MOV RBP, RSP
0x9abca4: PUSH R15
0x9abca6: PUSH R14
0x9abca8: PUSH R13
0x9abcaa: PUSH R12
0x9abcac: PUSH RBX
0x9abcad: SUB RSP, 0x38
0x9abcb1: MOV R14, RDI
0x9abcb4: ADD RDI, 0x28
0x9abcb8: MOV dword ptr [RBP + -0x34], ECX
0x9abcbb: MOV R15D, EDX
0x9abcbe: MOV R13D, ESI
0x9abcc1: MOV qword ptr [RBP + -0x40], R8
0x9abcc5: XOR ESI, ESI
0x9abcc7: XOR EDX, EDX
0x9abcc9: XOR ECX, ECX
0x9abccb: MOV qword ptr [RBP + -0x48], RDI
0x9abccf: CALL 0x004c6a00
0x9abcd4: MOV EAX, dword ptr [R14 + 0x4c]
0x9abcd8: MOV R12D, dword ptr [R14 + 0x48]
0x9abcdc: MOV qword ptr [RBP + -0x30], RAX
0x9abce0: ADD EAX, R12D
0x9abce3: CMP EAX, R13D
0x9abce6: JNC 0x009abd01
0x9abce8: MOV RDI, qword ptr [RBP + -0x48]
0x9abcec: XOR ESI, ESI
0x9abcee: XOR EDX, EDX
0x9abcf0: XOR ECX, ECX
0x9abcf2: CALL 0x004c6fa0
0x9abcf7: MOV EBX, 0xc
0x9abcfc: JMP 0x009ac439
0x9abd01: LEA RAX, [R14 + 0x10]
0x9abd05: MOV ECX, R12D
0x9abd08: MOV qword ptr [RBP + -0x50], RAX
0x9abd0c: MOV RAX, qword ptr [RBP + -0x30]
0x9abd10: TEST R15D, R15D
0x9abd13: MOV EDX, ECX
0x9abd15: SETZ SIL
0x9abd19: SUB EDX, R13D
0x9abd1c: SETC DIL
0x9abd20: OR DIL, SIL
0x9abd23: JZ 0x009abd5a
0x9abd25: TEST R15D, R15D
0x9abd28: JNZ 0x009abe56
0x9abd2e: CMP R13D, EAX
0x9abd31: JBE 0x009ac069
0x9abd37: CMP ECX, 0x1f
0x9abd3a: JBE 0x009ac17d
0x9abd40: MOV RDI, R14
0x9abd43: CALL 0x009ac450
0x9abd48: MOV ECX, dword ptr [R14 + 0x48]
0x9abd4c: MOV EAX, dword ptr [R14 + 0x4c]
0x9abd50: LEA EDX, [RCX + RAX*0x1]
0x9abd53: CMP EDX, R13D
0x9abd56: JNC 0x009abd10
0x9abd58: JMP 0x009abce8
0x9abd5a: MOV RSI, qword ptr [RBP + -0x40]
0x9abd5e: MOV R12D, dword ptr [RBP + -0x34]
0x9abd62: TEST R13D, R13D
0x9abd65: JZ 0x009abe48
0x9abd6b: MOV R9D, 0x2
0x9abd71: LEA RCX, [0x13b9ed0]
0x9abd78: MOV EDI, R13D
0x9abd7b: JMP 0x009abd8a
0x9abd80: CMP R10D, 0x1
0x9abd84: JZ 0x009abe48
0x9abd8a: XOR R11D, R11D
0x9abd8d: NOP dword ptr [RAX]
0x9abd90: MOV R10D, R11D
0x9abd93: ADD R11D, dword ptr [RCX + R9*0x4]
0x9abd97: SHL R10D, 0x6
0x9abd9b: ADD R10D, -0x40
0x9abd9f: NOP
0x9abda0: MOVSXD R11, R11D
0x9abda3: ADD R10D, 0x40
0x9abda7: MOV R8, qword ptr [R14 + R11*0x8 + 0x70]
0x9abdac: INC R11D
0x9abdaf: TEST R8, R8
0x9abdb2: JZ 0x009abda0
0x9abdb4: TZCNT R8, R8
0x9abdb9: DEC R9
0x9abdbc: LEA R11D, [R8 + R10*0x1]
0x9abdc0: JNZ 0x009abd90
0x9abdc2: ADD R8D, R10D
0x9abdc5: MOVSXD R9, R8D
0x9abdc8: MOV R11, qword ptr [R14 + R9*0x8 + 0x70]
0x9abdcd: MOV R15D, R9D
0x9abdd0: SHL R15D, 0x6
0x9abdd4: NOP word ptr CS:[RAX + RAX*0x1]
0x9abde0: MOV R10D, EDI
0x9abde3: TZCNT RDI, R11
0x9abde8: OR EDI, R15D
0x9abdeb: MOV dword ptr [RSI], EDI
0x9abded: ADD RSI, 0x4
0x9abdf1: BLSR R11, R11
0x9abdf6: LEA EDI, [R10 + -0x1]
0x9abdfa: JZ 0x009abe02
0x9abdfc: CMP R10D, 0x1
0x9abe00: JNZ 0x009abde0
0x9abe02: MOV qword ptr [R14 + R9*0x8 + 0x70], R11
0x9abe07: TEST R11, R11
0x9abe0a: JNZ 0x009abe48
0x9abe0c: XOR R9D, R9D
0x9abe0f: NOP
0x9abe10: MOV R11D, dword ptr [RCX + R9*0x4 + 0x4]
0x9abe15: MOV EBX, R8D
0x9abe18: SAR R8D, 0x6
0x9abe1c: ADD R11D, R8D
0x9abe1f: MOVSXD R15, R11D
0x9abe22: MOV R11, qword ptr [R14 + R15*0x8 + 0x70]
0x9abe27: BTR R11, RBX
0x9abe2b: MOV qword ptr [R14 + R15*0x8 + 0x70], R11
0x9abe30: CMP R9, 0x1
0x9abe34: LEA R9, [R9 + 0x1]
0x9abe38: JZ 0x009abd80
0x9abe3e: TEST R11, R11
0x9abe41: JZ 0x009abe10
0x9abe43: JMP 0x009abd80
0x9abe48: XOR ESI, ESI
0x9abe4a: MOV dword ptr [RBP + -0x30], 0x0
0x9abe51: JMP 0x009ac38b
0x9abe56: TEST R12D, R12D
0x9abe59: JZ 0x009abf47
0x9abe5f: MOV RCX, qword ptr [RBP + -0x40]
0x9abe63: MOV EDI, 0x2
0x9abe68: LEA RAX, [0x13b9ed0]
0x9abe6f: MOV EDX, R12D
0x9abe72: JMP 0x009abe8a
0x9abe80: CMP R8D, 0x1
0x9abe84: JZ 0x009abf47
0x9abe8a: XOR R9D, R9D
0x9abe8d: NOP dword ptr [RAX]
0x9abe90: MOV R8D, R9D
0x9abe93: ADD R9D, dword ptr [RAX + RDI*0x4]
0x9abe97: SHL R8D, 0x6
0x9abe9b: ADD R8D, -0x40
0x9abe9f: NOP
0x9abea0: MOVSXD R9, R9D
0x9abea3: ADD R8D, 0x40
0x9abea7: MOV RSI, qword ptr [R14 + R9*0x8 + 0x70]
0x9abeac: INC R9D
0x9abeaf: TEST RSI, RSI
0x9abeb2: JZ 0x009abea0
0x9abeb4: TZCNT RSI, RSI
0x9abeb9: DEC RDI
0x9abebc: LEA R9D, [RSI + R8*0x1]
0x9abec0: JNZ 0x009abe90
0x9abec2: ADD ESI, R8D
0x9abec5: MOVSXD RDI, ESI
0x9abec8: MOV R9, qword ptr [R14 + RDI*0x8 + 0x70]
0x9abecd: MOV R10D, EDI
0x9abed0: SHL R10D, 0x6
0x9abed4: NOP word ptr CS:[RAX + RAX*0x1]
0x9abee0: MOV R8D, EDX
0x9abee3: TZCNT RDX, R9
0x9abee8: OR EDX, R10D
0x9abeeb: MOV dword ptr [RCX], EDX
0x9abeed: ADD RCX, 0x4
0x9abef1: BLSR R9, R9
0x9abef6: LEA EDX, [R8 + -0x1]
0x9abefa: JZ 0x009abf02
0x9abefc: CMP R8D, 0x1
0x9abf00: JNZ 0x009abee0
0x9abf02: MOV qword ptr [R14 + RDI*0x8 + 0x70], R9
0x9abf07: TEST R9, R9
0x9abf0a: JNZ 0x009abf47
0x9abf0c: XOR EDI, EDI
0x9abf0e: NOP
0x9abf10: MOV R9D, dword ptr [RAX + RDI*0x4 + 0x4]
0x9abf15: MOV R10D, ESI
0x9abf18: SAR ESI, 0x6
0x9abf1b: ADD R9D, ESI
0x9abf1e: MOVSXD R11, R9D
0x9abf21: MOV R9, qword ptr [R14 + R11*0x8 + 0x70]
0x9abf26: BTR R9, R10
0x9abf2a: MOV qword ptr [R14 + R11*0x8 + 0x70], R9
0x9abf2f: CMP RDI, 0x1
0x9abf33: LEA RDI, [RDI + 0x1]
0x9abf37: JZ 0x009abe80
0x9abf3d: TEST R9, R9
0x9abf40: JZ 0x009abf10
0x9abf42: JMP 0x009abe80
0x9abf47: MOV EAX, R13D
0x9abf4a: SUB EAX, R12D
0x9abf4d: JZ 0x009ac04d
0x9abf53: MOV RCX, qword ptr [RBP + -0x40]
0x9abf57: MOV R8D, 0x2
0x9abf5d: LEA RDX, [0x13b9ed0]
0x9abf64: MOV ESI, EAX
0x9abf66: LEA RCX, [RCX + R12*0x4]
0x9abf6a: JMP 0x009abf7a
0x9abf70: CMP R9D, 0x1
0x9abf74: JZ 0x009ac04d
0x9abf7a: XOR R10D, R10D
0x9abf7d: NOP dword ptr [RAX]
0x9abf80: MOV R9D, R10D
0x9abf83: ADD R10D, dword ptr [RDX + R8*0x4]
0x9abf87: SHL R9D, 0x6
0x9abf8b: ADD R9D, -0x40
0x9abf8f: NOP
0x9abf90: MOVSXD R10, R10D
0x9abf93: ADD R9D, 0x40
0x9abf97: MOV RDI, qword ptr [R14 + R10*0x8 + 0x20890]
0x9abf9f: INC R10D
0x9abfa2: TEST RDI, RDI
0x9abfa5: JZ 0x009abf90
0x9abfa7: TZCNT RDI, RDI
0x9abfac: DEC R8
0x9abfaf: LEA R10D, [RDI + R9*0x1]
0x9abfb3: JNZ 0x009abf80
0x9abfb5: ADD EDI, R9D
0x9abfb8: MOVSXD R8, EDI
0x9abfbb: MOV R10, qword ptr [R14 + R8*0x8 + 0x20890]
0x9abfc3: MOV R11D, R8D
0x9abfc6: SHL R11D, 0x6
0x9abfca: NOP word ptr [RAX + RAX*0x1]
0x9abfd0: MOV R9D, ESI
0x9abfd3: TZCNT RSI, R10
0x9abfd8: OR ESI, R11D
0x9abfdb: MOV dword ptr [RCX], ESI
0x9abfdd: ADD RCX, 0x4
0x9abfe1: BLSR R10, R10
0x9abfe6: LEA ESI, [R9 + -0x1]
0x9abfea: JZ 0x009abff2
0x9abfec: CMP R9D, 0x1
0x9abff0: JNZ 0x009abfd0
0x9abff2: MOV qword ptr [R14 + R8*0x8 + 0x20890], R10
0x9abffa: TEST R10, R10
0x9abffd: JNZ 0x009ac04d
0x9abfff: XOR R8D, R8D
0x9ac002: NOP word ptr CS:[RAX + RAX*0x1]
0x9ac010: MOV R10D, dword ptr [RDX + R8*0x4 + 0x4]
0x9ac015: MOV R11D, EDI
0x9ac018: SAR EDI, 0x6
0x9ac01b: ADD R10D, EDI
0x9ac01e: MOVSXD RBX, R10D
0x9ac021: MOV R10, qword ptr [R14 + RBX*0x8 + 0x20890]
0x9ac029: BTR R10, R11
0x9ac02d: MOV qword ptr [R14 + RBX*0x8 + 0x20890], R10
0x9ac035: CMP R8, 0x1
0x9ac039: LEA R8, [R8 + 0x1]
0x9ac03d: JZ 0x009abf70
0x9ac043: TEST R10, R10
0x9ac046: JZ 0x009ac010
0x9ac048: JMP 0x009abf70
0x9ac04d: MOV RCX, qword ptr [RBP + -0x30]
0x9ac051: MOV R12D, dword ptr [RBP + -0x34]
0x9ac055: XOR ESI, ESI
0x9ac057: MOV dword ptr [RBP + -0x30], 0x0
0x9ac05e: XOR EDX, EDX
0x9ac060: SUB ECX, EAX
0x9ac062: MOV EAX, ECX
0x9ac064: JMP 0x009ac38b
0x9ac069: MOV RSI, qword ptr [RBP + -0x40]
0x9ac06d: MOV R12D, dword ptr [RBP + -0x34]
0x9ac071: TEST R13D, R13D
0x9ac074: JZ 0x009ac16e
0x9ac07a: MOV R9D, 0x2
0x9ac080: LEA RDX, [0x13b9ed0]
0x9ac087: MOV EDI, R13D
0x9ac08a: JMP 0x009ac09a
0x9ac090: CMP R10D, 0x1
0x9ac094: JZ 0x009ac16e
0x9ac09a: XOR R11D, R11D
0x9ac09d: NOP dword ptr [RAX]
0x9ac0a0: MOV R10D, R11D
0x9ac0a3: ADD R11D, dword ptr [RDX + R9*0x4]
0x9ac0a7: SHL R10D, 0x6
0x9ac0ab: ADD R10D, -0x40
0x9ac0af: NOP
0x9ac0b0: MOVSXD R11, R11D
0x9ac0b3: ADD R10D, 0x40
0x9ac0b7: MOV R8, qword ptr [R14 + R11*0x8 + 0x20890]
0x9ac0bf: INC R11D
0x9ac0c2: TEST R8, R8
0x9ac0c5: JZ 0x009ac0b0
0x9ac0c7: TZCNT R8, R8
0x9ac0cc: DEC R9
0x9ac0cf: LEA R11D, [R8 + R10*0x1]
0x9ac0d3: JNZ 0x009ac0a0
0x9ac0d5: ADD R8D, R10D
0x9ac0d8: MOVSXD R9, R8D
0x9ac0db: MOV R11, qword ptr [R14 + R9*0x8 + 0x20890]
0x9ac0e3: MOV R15D, R9D
0x9ac0e6: SHL R15D, 0x6
0x9ac0ea: NOP word ptr [RAX + RAX*0x1]
0x9ac0f0: MOV R10D, EDI
0x9ac0f3: TZCNT RDI, R11
0x9ac0f8: OR EDI, R15D
0x9ac0fb: MOV dword ptr [RSI], EDI
0x9ac0fd: ADD RSI, 0x4
0x9ac101: BLSR R11, R11
0x9ac106: LEA EDI, [R10 + -0x1]
0x9ac10a: JZ 0x009ac112
0x9ac10c: CMP R10D, 0x1
0x9ac110: JNZ 0x009ac0f0
0x9ac112: MOV qword ptr [R14 + R9*0x8 + 0x20890], R11
0x9ac11a: TEST R11, R11
0x9ac11d: JNZ 0x009ac16e
0x9ac11f: XOR R9D, R9D
0x9ac122: NOP word ptr CS:[RAX + RAX*0x1]
0x9ac130: MOV R11D, dword ptr [RDX + R9*0x4 + 0x4]
0x9ac135: MOV EBX, R8D
0x9ac138: SAR R8D, 0x6
0x9ac13c: ADD R11D, R8D
0x9ac13f: MOVSXD R15, R11D
0x9ac142: MOV R11, qword ptr [R14 + R15*0x8 + 0x20890]
0x9ac14a: BTR R11, RBX
0x9ac14e: MOV qword ptr [R14 + R15*0x8 + 0x20890], R11
0x9ac156: CMP R9, 0x1
0x9ac15a: LEA R9, [R9 + 0x1]
0x9ac15e: JZ 0x009ac090
0x9ac164: TEST R11, R11
0x9ac167: JZ 0x009ac130
0x9ac169: JMP 0x009ac090
0x9ac16e: SUB EAX, R13D
0x9ac171: MOV dword ptr [RBP + -0x30], 0x0
0x9ac178: JMP 0x009ac386
0x9ac17d: MOV R12, qword ptr [RBP + -0x40]
0x9ac181: MOV EDX, R13D
0x9ac184: SUB EDX, EAX
0x9ac186: MOV dword ptr [RBP + -0x30], EDX
0x9ac189: JZ 0x009ac278
0x9ac18f: MOV EDI, dword ptr [RBP + -0x30]
0x9ac192: MOV R9D, 0x2
0x9ac198: LEA RDX, [0x13b9ed0]
0x9ac19f: MOV RSI, R12
0x9ac1a2: JMP 0x009ac1ba
0x9ac1b0: CMP R10D, 0x1
0x9ac1b4: JZ 0x009ac278
0x9ac1ba: XOR R11D, R11D
0x9ac1bd: NOP dword ptr [RAX]
0x9ac1c0: MOV R10D, R11D
0x9ac1c3: ADD R11D, dword ptr [RDX + R9*0x4]
0x9ac1c7: SHL R10D, 0x6
0x9ac1cb: ADD R10D, -0x40
0x9ac1cf: NOP
0x9ac1d0: MOVSXD R11, R11D
0x9ac1d3: ADD R10D, 0x40
0x9ac1d7: MOV R8, qword ptr [R14 + R11*0x8 + 0x70]
0x9ac1dc: INC R11D
0x9ac1df: TEST R8, R8
0x9ac1e2: JZ 0x009ac1d0
0x9ac1e4: TZCNT R8, R8
0x9ac1e9: DEC R9
0x9ac1ec: LEA R11D, [R8 + R10*0x1]
0x9ac1f0: JNZ 0x009ac1c0
0x9ac1f2: ADD R8D, R10D
0x9ac1f5: MOVSXD R9, R8D
0x9ac1f8: MOV R11, qword ptr [R14 + R9*0x8 + 0x70]
0x9ac1fd: MOV R15D, R9D
0x9ac200: SHL R15D, 0x6
0x9ac204: NOP word ptr CS:[RAX + RAX*0x1]
0x9ac210: MOV R10D, EDI
0x9ac213: TZCNT RDI, R11
0x9ac218: OR EDI, R15D
0x9ac21b: MOV dword ptr [RSI], EDI
0x9ac21d: ADD RSI, 0x4
0x9ac221: BLSR R11, R11
0x9ac226: LEA EDI, [R10 + -0x1]
0x9ac22a: JZ 0x009ac232
0x9ac22c: CMP R10D, 0x1
0x9ac230: JNZ 0x009ac210
0x9ac232: MOV qword ptr [R14 + R9*0x8 + 0x70], R11
0x9ac237: TEST R11, R11
0x9ac23a: JNZ 0x009ac278
0x9ac23c: XOR R9D, R9D
0x9ac23f: NOP
0x9ac240: MOV R11D, dword ptr [RDX + R9*0x4 + 0x4]
0x9ac245: MOV EBX, R8D
0x9ac248: SAR R8D, 0x6
0x9ac24c: ADD R11D, R8D
0x9ac24f: MOVSXD R15, R11D
0x9ac252: MOV R11, qword ptr [R14 + R15*0x8 + 0x70]
0x9ac257: BTR R11, RBX
0x9ac25b: MOV qword ptr [R14 + R15*0x8 + 0x70], R11
0x9ac260: CMP R9, 0x1
0x9ac264: LEA R9, [R9 + 0x1]
0x9ac268: JZ 0x009ac1b0
0x9ac26e: TEST R11, R11
0x9ac271: JZ 0x009ac240
0x9ac273: JMP 0x009ac1b0
0x9ac278: TEST EAX, EAX
0x9ac27a: JZ 0x009ac37d
0x9ac280: MOV EDX, dword ptr [RBP + -0x30]
0x9ac283: MOV R8D, 0x2
0x9ac289: LEA RSI, [0x13b9ed0]
0x9ac290: LEA RDX, [R12 + RDX*0x4]
0x9ac294: JMP 0x009ac2aa
0x9ac2a0: CMP R9D, 0x1
0x9ac2a4: JZ 0x009ac37d
0x9ac2aa: XOR R10D, R10D
0x9ac2ad: NOP dword ptr [RAX]
0x9ac2b0: MOV R9D, R10D
0x9ac2b3: ADD R10D, dword ptr [RSI + R8*0x4]
0x9ac2b7: SHL R9D, 0x6
0x9ac2bb: ADD R9D, -0x40
0x9ac2bf: NOP
0x9ac2c0: MOVSXD R10, R10D
0x9ac2c3: ADD R9D, 0x40
0x9ac2c7: MOV RDI, qword ptr [R14 + R10*0x8 + 0x20890]
0x9ac2cf: INC R10D
0x9ac2d2: TEST RDI, RDI
0x9ac2d5: JZ 0x009ac2c0
0x9ac2d7: TZCNT RDI, RDI
0x9ac2dc: DEC R8
0x9ac2df: LEA R10D, [RDI + R9*0x1]
0x9ac2e3: JNZ 0x009ac2b0
0x9ac2e5: ADD EDI, R9D
0x9ac2e8: MOVSXD R8, EDI
0x9ac2eb: MOV R10, qword ptr [R14 + R8*0x8 + 0x20890]
0x9ac2f3: MOV R11D, R8D
0x9ac2f6: SHL R11D, 0x6
0x9ac2fa: NOP word ptr [RAX + RAX*0x1]
0x9ac300: MOV R9D, EAX
0x9ac303: TZCNT RAX, R10
0x9ac308: OR EAX, R11D
0x9ac30b: MOV dword ptr [RDX], EAX
0x9ac30d: ADD RDX, 0x4
0x9ac311: BLSR R10, R10
0x9ac316: LEA EAX, [R9 + -0x1]
0x9ac31a: JZ 0x009ac322
0x9ac31c: CMP R9D, 0x1
0x9ac320: JNZ 0x009ac300
0x9ac322: MOV qword ptr [R14 + R8*0x8 + 0x20890], R10
0x9ac32a: TEST R10, R10
0x9ac32d: JNZ 0x009ac37d
0x9ac32f: XOR R8D, R8D
0x9ac332: NOP word ptr CS:[RAX + RAX*0x1]
0x9ac340: MOV R10D, dword ptr [RSI + R8*0x4 + 0x4]
0x9ac345: MOV R11D, EDI
0x9ac348: SAR EDI, 0x6
0x9ac34b: ADD R10D, EDI
0x9ac34e: MOVSXD RBX, R10D
0x9ac351: MOV R10, qword ptr [R14 + RBX*0x8 + 0x20890]
0x9ac359: BTR R10, R11
0x9ac35d: MOV qword ptr [R14 + RBX*0x8 + 0x20890], R10
0x9ac365: CMP R8, 0x1
0x9ac369: LEA R8, [R8 + 0x1]
0x9ac36d: JZ 0x009ac2a0
0x9ac373: TEST R10, R10
0x9ac376: JZ 0x009ac340
0x9ac378: JMP 0x009ac2a0
0x9ac37d: SUB ECX, dword ptr [RBP + -0x30]
0x9ac380: MOV R12D, dword ptr [RBP + -0x34]
0x9ac384: XOR EAX, EAX
0x9ac386: MOV SIL, 0x1
0x9ac389: MOV EDX, ECX
0x9ac38b: MOV dword ptr [R14 + 0x48], EDX
0x9ac38f: MOV dword ptr [R14 + 0x4c], EAX
0x9ac393: TEST R12D, R12D
0x9ac396: JZ 0x009ac39e
0x9ac398: ADD dword ptr [R14 + 0x50], R13D
0x9ac39c: JMP 0x009ac3a2
0x9ac39e: ADD dword ptr [R14 + 0x54], R13D
0x9ac3a2: MOV RBX, qword ptr [RBP + -0x50]
0x9ac3a6: TEST SIL, SIL
0x9ac3a9: JZ 0x009ac3f5
0x9ac3ab: MOVZX EAX, byte ptr [R14 + 0x68]
0x9ac3b0: TEST AL, 0x1
0x9ac3b2: JZ 0x009ac3f5
0x9ac3b4: MOV R12D, dword ptr [R14 + 0x5c]
0x9ac3b8: OR AL, 0x2
0x9ac3ba: LEA R15, [R14 + 0x5c]
0x9ac3be: LEA R13, [0x132208a]
0x9ac3c5: MOV byte ptr [R14 + 0x68], AL
0x9ac3c9: NOP dword ptr [RAX]
0x9ac3d0: MOV RDI, R15
0x9ac3d3: MOV RSI, RBX
0x9ac3d6: MOV EDX, 0x44
0x9ac3db: MOV RCX, R13
0x9ac3de: MOV dword ptr [RSP], 0x100
0x9ac3e5: XOR R8D, R8D
0x9ac3e8: XOR R9D, R9D
0x9ac3eb: CALL 0x00c06260
0x9ac3f0: CMP R12D, dword ptr [R15]
0x9ac3f3: JZ 0x009ac3d0
0x9ac3f5: MOV RDI, qword ptr [RBP + -0x48]
0x9ac3f9: XOR EBX, EBX
0x9ac3fb: XOR ESI, ESI
0x9ac3fd: XOR EDX, EDX
0x9ac3ff: XOR ECX, ECX
0x9ac401: CALL 0x004c6fa0
0x9ac406: MOV EAX, dword ptr [RBP + -0x30]
0x9ac409: TEST EAX, EAX
0x9ac40b: JLE 0x009ac439
0x9ac40d: MOV R15, qword ptr [RBP + -0x40]
0x9ac411: MOV R12D, EAX
0x9ac414: MOV R13D, 0xfffff
0x9ac41a: XOR EBX, EBX
0x9ac41c: NOP dword ptr [RAX]
0x9ac420: MOV ESI, dword ptr [R15 + RBX*0x4]
0x9ac424: MOV RDI, R14
0x9ac427: AND ESI, R13D
0x9ac42a: CALL 0x009ac500
0x9ac42f: INC RBX
0x9ac432: CMP R12, RBX
0x9ac435: JNZ 0x009ac420
0x9ac437: XOR EBX, EBX
0x9ac439: MOV EAX, EBX
0x9ac43b: ADD RSP, 0x38
0x9ac43f: POP RBX
0x9ac440: POP R12
0x9ac442: POP R13
0x9ac444: POP R14
0x9ac446: POP R15
0x9ac448: POP RBP
0x9ac449: RET

; local helper / adjacent context (reachability below); evidence ev_af5a550ba0c26f24a48ec79fe9243aa24f049b8fe68b60e647524b2f9cf75248; body [{"start": "0x9ac450", "end": "0x9ac4f4"}]
sub_9ac450: ; RVA 0x9ac450
0x9ac450: PUSH RBP
0x9ac451: MOV RBP, RSP
0x9ac454: PUSH R14
0x9ac456: PUSH RBX
0x9ac457: MOV RBX, RDI
0x9ac45a: MOV RAX, -0x20820
0x9ac461: NOP dword ptr CS:[RAX + RAX*0x1]
0x9ac470: MOV RCX, qword ptr [RBX + RAX*0x1 + 0x20890]
0x9ac478: OR qword ptr [RBX + RAX*0x1 + 0x410b0], RCX
0x9ac480: MOV qword ptr [RBX + RAX*0x1 + 0x20890], 0x0
0x9ac48c: ADD RAX, 0x8
0x9ac490: JNZ 0x009ac470
0x9ac492: MOV EAX, dword ptr [RBX + 0x48]
0x9ac495: LEA R14, [RBX + 0x28]
0x9ac499: XOR ESI, ESI
0x9ac49b: XOR EDX, EDX
0x9ac49d: XOR ECX, ECX
0x9ac49f: MOV RDI, R14
0x9ac4a2: ADD dword ptr [RBX + 0x4c], EAX
0x9ac4a5: MOV dword ptr [RBX + 0x48], 0x0
0x9ac4ac: OR byte ptr [RBX + 0x68], 0x1
0x9ac4b0: CALL 0x004c6fa0
0x9ac4b5: CALL 0x008de020
0x9ac4ba: MOV RDI, R14
0x9ac4bd: XOR ESI, ESI
0x9ac4bf: XOR EDX, EDX
0x9ac4c1: XOR ECX, ECX
0x9ac4c3: CALL 0x004c6a00
0x9ac4c8: MOVZX EAX, byte ptr [RBX + 0x68]
0x9ac4cc: MOV ECX, EAX
0x9ac4ce: AND CL, 0xfe
0x9ac4d1: MOV byte ptr [RBX + 0x68], CL
0x9ac4d4: TEST AL, 0x2
0x9ac4d6: JNZ 0x009ac4dd
0x9ac4d8: POP RBX
0x9ac4d9: POP R14
0x9ac4db: POP RBP
0x9ac4dc: RET
0x9ac4dd: AND AL, 0xfc
0x9ac4df: MOV byte ptr [RBX + 0x68], AL
0x9ac4e2: INC dword ptr [RBX + 0x5c]
0x9ac4e5: ADD RBX, 0x5c
0x9ac4e9: MOV RDI, RBX
0x9ac4ec: POP RBX
0x9ac4ed: POP R14
0x9ac4ef: POP RBP
0x9ac4f0: JMP 0x00c06910

; local helper / adjacent context (reachability below); evidence ev_25a3c187a09e194d4d70656bc6049e7545cf31f7fef1b066e04bce8397953ecc; body [{"start": "0x9ac500", "end": "0x9ac655"}]
sub_9ac500: ; RVA 0x9ac500
0x9ac500: PUSH RBP
0x9ac501: MOV RBP, RSP
0x9ac504: PUSH R15
0x9ac506: PUSH R14
0x9ac508: PUSH R13
0x9ac50a: PUSH R12
0x9ac50c: PUSH RBX
0x9ac50d: SUB RSP, 0x28
0x9ac511: MOV RAX, qword ptr [RDI + 0x30]
0x9ac515: MOV R15D, ESI
0x9ac518: MOV R13D, dword ptr [0x025567e0]
0x9ac51f: MOV EDX, 0x1
0x9ac524: SHL R15, 0x10
0x9ac528: MOV qword ptr [RBP + -0x38], RAX
0x9ac52c: LEA RSI, [RAX + R15*0x1]
0x9ac530: MOV RAX, qword ptr GS:[0x0]
0x9ac539: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x9ac541: MOV R12, qword ptr [0x03ba5eb8]
0x9ac548: MOV qword ptr [RBP + -0x30], R12
0x9ac54c: MOV R14D, dword ptr GS:[0x34]
0x9ac555: SHL R14D, 0x10
0x9ac559: LEA RBX, [R12 + R14*0x1]
0x9ac55d: MOV RDI, RBX
0x9ac560: CALL 0x008de9e0
0x9ac565: LEA RDI, [R12 + R14*0x1 + 0x4000]
0x9ac56d: MOV R12, qword ptr [RBP + -0x38]
0x9ac571: MOV EDX, 0x1
0x9ac576: MOV qword ptr [RBP + -0x48], RDI
0x9ac57a: LEA RSI, [R12 + R15*0x1 + 0x4000]
0x9ac582: CALL 0x008de9e0
0x9ac587: MOV RAX, qword ptr [RBP + -0x30]
0x9ac58b: LEA RSI, [R12 + R15*0x1 + 0x8000]
0x9ac593: MOV EDX, 0x1
0x9ac598: LEA RDI, [RAX + R14*0x1 + 0x8000]
0x9ac5a0: MOV qword ptr [RBP + -0x40], RDI
0x9ac5a4: CALL 0x008de9e0
0x9ac5a9: MOV RAX, qword ptr [RBP + -0x30]
0x9ac5ad: LEA RSI, [R12 + R15*0x1 + 0xc000]
0x9ac5b5: MOV EDX, 0x1
0x9ac5ba: LEA R14, [RAX + R14*0x1 + 0xc000]
0x9ac5c2: MOV RDI, R14
0x9ac5c5: CALL 0x008de9e0
0x9ac5ca: MFENCE
0x9ac5cd: XOR EAX, EAX
0x9ac5cf: NOP
0x9ac5d0: CLFLUSH byte ptr [RBX + RAX*0x1]
0x9ac5d4: ADD RAX, R13
0x9ac5d7: CMP RAX, 0x10000
0x9ac5dd: JC 0x009ac5d0
0x9ac5df: MFENCE
0x9ac5e2: MOV RDI, RBX
0x9ac5e5: CALL 0x008deb20
0x9ac5ea: MOV RDI, qword ptr [RBP + -0x48]
0x9ac5ee: CALL 0x008deb20
0x9ac5f3: MOV RDI, qword ptr [RBP + -0x40]
0x9ac5f7: CALL 0x008deb20
0x9ac5fc: MOV RDI, R14
0x9ac5ff: CALL 0x008deb20
0x9ac604: LEA RDX, [RBX + 0x10000]
0x9ac60b: LEA RDI, [0x3b48ff8]
0x9ac612: MOV RSI, RBX
0x9ac615: CALL 0x008ddbf0
0x9ac61a: MOV RAX, qword ptr GS:[0x0]
0x9ac623: MOV ECX, 0xffffffff
0x9ac628: XADD.LOCK dword ptr [RAX + 0x5a8], ECX
0x9ac630: ADD RSP, 0x28
0x9ac634: CMP ECX, 0x80000001
0x9ac63a: JNZ 0x009ac64b
0x9ac63c: POP RBX
0x9ac63d: POP R12
0x9ac63f: POP R13
0x9ac641: POP R14
0x9ac643: POP R15
0x9ac645: POP RBP
0x9ac646: JMP 0x006b7af0
0x9ac64b: POP RBX
0x9ac64c: POP R12
0x9ac64e: POP R13
0x9ac650: POP R14
0x9ac652: POP R15
0x9ac654: POP RBP
0x9ac655: RET

; local helper / adjacent context (reachability below); evidence ev_e385e32af382cdd5185505ae92f300c512542cc0e3fa6a3d5abfc0ba59bfd258; body [{"start": "0x9ac660", "end": "0x9ac66a"}]
sub_9ac660: ; RVA 0x9ac660
0x9ac660: PUSH RBP
0x9ac661: MOV RBP, RSP
0x9ac664: MOV EAX, 0x6
0x9ac669: POP RBP
0x9ac66a: RET

; local helper / adjacent context (reachability below); evidence ev_c37e81d7fea037c866f57dbf8816f4c513b4e58163fcb9c2dd7d770aed413ad5; body [{"start": "0x9ac670", "end": "0x9ac67a"}]
sub_9ac670: ; RVA 0x9ac670
0x9ac670: PUSH RBP
0x9ac671: MOV RBP, RSP
0x9ac674: MOV EAX, 0x6
0x9ac679: POP RBP
0x9ac67a: RET

; local helper / adjacent context (reachability below); evidence ev_83900ca412c6f0d826b55504188b5a27e52625580075f57e4dbb45ecaf8f2483; body [{"start": "0x9ac680", "end": "0x9ac987"}]
sub_9ac680: ; RVA 0x9ac680
0x9ac680: PUSH RBP
0x9ac681: MOV RBP, RSP
0x9ac684: PUSH R15
0x9ac686: PUSH R14
0x9ac688: PUSH R13
0x9ac68a: PUSH R12
0x9ac68c: PUSH RBX
0x9ac68d: SUB RSP, 0x28
0x9ac691: LEA R15, [0x391c310]
0x9ac698: MOV RAX, qword ptr [R15]
0x9ac69b: MOV qword ptr [RBP + -0x30], RAX
0x9ac69f: MOV R12, qword ptr [RDI]
0x9ac6a2: CMP RSI, 0x4010a802
0x9ac6a9: JZ 0x009ac79b
0x9ac6af: MOV R14D, 0x19
0x9ac6b5: MOV EAX, 0xc020a801
0x9ac6ba: CMP RSI, RAX
0x9ac6bd: JNZ 0x009ac7e6
0x9ac6c3: MOV R13, qword ptr [RDX]
0x9ac6c6: MOV EAX, dword ptr [RDX + 0x18]
0x9ac6c9: MOV R14D, 0x16
0x9ac6cf: TEST R13W, R13W
0x9ac6d3: SETNZ CL
0x9ac6d6: TEST EAX, 0xffffff
0x9ac6db: SETNZ SIL
0x9ac6df: OR SIL, CL
0x9ac6e2: JNZ 0x009ac7e6
0x9ac6e8: MOV R8, qword ptr [RDX + 0x8]
0x9ac6ec: MOV R9, qword ptr [RDX + 0x10]
0x9ac6f0: TEST EAX, EAX
0x9ac6f2: JZ 0x009ac805
0x9ac6f8: SAR EAX, 0x18
0x9ac6fb: CMP EAX, 0x10
0x9ac6fe: JL 0x009ac7e6
0x9ac704: TEST R13, R13
0x9ac707: JZ 0x009ac813
0x9ac70d: JS 0x009ac818
0x9ac713: MOV RCX, qword ptr [R12 + 0x38]
0x9ac718: MOV qword ptr [RBP + -0x48], RDX
0x9ac71c: MOV RDX, qword ptr [R12 + 0x40]
0x9ac721: MOV EDI, dword ptr [R12 + 0x60]
0x9ac726: MOV ESI, 0x1
0x9ac72b: SHLX RAX, RSI, RAX
0x9ac730: CMP RCX, R8
0x9ac733: CMOVG R8, RCX
0x9ac737: CMP RDX, R9
0x9ac73a: CMOVL R9, RDX
0x9ac73e: MOV EDX, dword ptr [R12 + 0x64]
0x9ac743: MOV RCX, qword ptr GS:[0x0]
0x9ac74c: MOV RCX, qword ptr [RCX + 0x8]
0x9ac750: XOR ESI, ESI
0x9ac752: TEST byte ptr [RCX + 0x588], 0x1
0x9ac759: SETZ SIL
0x9ac75d: LEA R10D, [0x3 + RSI*0x8]
0x9ac765: SUB RSP, 0x8
0x9ac769: LEA R11, [RBP + -0x38]
0x9ac76d: XOR ESI, ESI
0x9ac76f: PUSH R11
0x9ac771: PUSH 0x20000000
0x9ac776: PUSH R10
0x9ac778: PUSH RAX
0x9ac779: PUSH R13
0x9ac77b: CALL 0x003c3950
0x9ac780: ADD RSP, 0x30
0x9ac784: TEST EAX, EAX
0x9ac786: JZ 0x009ac820
0x9ac78c: CMP EAX, 0x23
0x9ac78f: MOV R14D, 0xc
0x9ac795: CMOVNZ R14D, EAX
0x9ac799: JMP 0x009ac7e6
0x9ac79b: LEA RBX, [R12 + 0x28]
0x9ac7a0: MOV R13, RDX
0x9ac7a3: XOR R14D, R14D
0x9ac7a6: XOR ESI, ESI
0x9ac7a8: XOR EDX, EDX
0x9ac7aa: XOR ECX, ECX
0x9ac7ac: MOV RDI, RBX
0x9ac7af: CALL 0x004c6a00
0x9ac7b4: MOV EAX, dword ptr [R12 + 0x4c]
0x9ac7b9: MOV RDI, RBX
0x9ac7bc: XOR ESI, ESI
0x9ac7be: XOR EDX, EDX
0x9ac7c0: XOR ECX, ECX
0x9ac7c2: MOV dword ptr [R13], EAX
0x9ac7c6: MOV EAX, dword ptr [R12 + 0x48]
0x9ac7cb: MOV dword ptr [R13 + 0x4], EAX
0x9ac7cf: MOV EAX, dword ptr [R12 + 0x54]
0x9ac7d4: MOV dword ptr [R13 + 0x8], EAX
0x9ac7d8: MOV EAX, dword ptr [R12 + 0x50]
0x9ac7dd: MOV dword ptr [R13 + 0xc], EAX
0x9ac7e1: CALL 0x004c6fa0
0x9ac7e6: MOV RAX, qword ptr [R15]
0x9ac7e9: CMP RAX, qword ptr [RBP + -0x30]
0x9ac7ed: JNZ 0x009ac981
0x9ac7f3: MOV EAX, R14D
0x9ac7f6: ADD RSP, 0x28
0x9ac7fa: POP RBX
0x9ac7fb: POP R12
0x9ac7fd: POP R13
0x9ac7ff: POP R14
0x9ac801: POP R15
0x9ac803: POP RBP
0x9ac804: RET
0x9ac805: MOV EAX, 0x10
0x9ac80a: TEST R13, R13
0x9ac80d: JNZ 0x009ac70d
0x9ac813: XOR R14D, R14D
0x9ac816: JMP 0x009ac7e6
0x9ac818: MOV R14D, 0xc
0x9ac81e: JMP 0x009ac7e6
0x9ac820: LEA RDI, [R12 + 0x28]
0x9ac825: XOR R14D, R14D
0x9ac828: XOR ESI, ESI
0x9ac82a: XOR EDX, EDX
0x9ac82c: XOR ECX, ECX
0x9ac82e: MOV qword ptr [RBP + -0x40], RDI
0x9ac832: CALL 0x004c6a00
0x9ac837: MOV RAX, R13
0x9ac83a: MOV RCX, 0xffffffff0000
0x9ac844: LEA RDX, [R12 + 0x20890]
0x9ac84c: LEA RDI, [0x13b9ed0]
0x9ac853: MOV RBX, -0x1
0x9ac85a: SHR RAX, 0x10
0x9ac85e: ADD RCX, R13
0x9ac861: ADD dword ptr [R12 + 0x4c], EAX
0x9ac866: MOV RAX, qword ptr [RBP + -0x38]
0x9ac86a: SUB RAX, qword ptr [R12 + 0x38]
0x9ac86f: ADD R12, 0x20898
0x9ac876: ADD RCX, RAX
0x9ac879: SHR RAX, 0x10
0x9ac87d: SHR RCX, 0x10
0x9ac881: NOP dword ptr CS:[RAX + RAX*0x1]
0x9ac890: MOVSXD R11, dword ptr [RDI + R14*0x4]
0x9ac894: MOV ESI, ECX
0x9ac896: MOV R9D, EAX
0x9ac899: SAR EAX, 0x6
0x9ac89c: SAR ECX, 0x6
0x9ac89f: NOT SIL
0x9ac8a2: CMP EAX, ECX
0x9ac8a4: MOVSXD R13, EAX
0x9ac8a7: SHRX R10, RBX, RSI
0x9ac8ac: MOV RSI, -0x1
0x9ac8b3: CMOVZ RSI, R10
0x9ac8b7: LEA R8, [RDX + R11*0x8]
0x9ac8bb: SHRX RSI, RSI, R9
0x9ac8c0: SHLX RSI, RSI, R9
0x9ac8c5: MOV R9, qword ptr [R8 + R13*0x8]
0x9ac8c9: OR RSI, R9
0x9ac8cc: TEST R9, R9
0x9ac8cf: SETZ R9B
0x9ac8d3: MOV qword ptr [R8 + R13*0x8], RSI
0x9ac8d7: CMP R13D, ECX
0x9ac8da: JZ 0x009ac94a
0x9ac8dc: LEA ESI, [RAX + 0x1]
0x9ac8df: CMP ESI, ECX
0x9ac8e1: JGE 0x009ac92b
0x9ac8e3: MOVSXD RBX, ECX
0x9ac8e6: LEA R11, [R12 + R11*0x8]
0x9ac8ea: MOV R15, RDX
0x9ac8ed: MOV RDX, RDI
0x9ac8f0: LEA RSI, [RBX + -0x1]
0x9ac8f4: NOP word ptr CS:[RAX + RAX*0x1]
0x9ac900: CMP qword ptr [R11 + R13*0x8], 0x0
0x9ac905: MOV qword ptr [R11 + R13*0x8], -0x1
0x9ac90d: SETZ DIL
0x9ac911: INC R13
0x9ac914: OR R9B, DIL
0x9ac917: CMP RSI, R13
0x9ac91a: JNZ 0x009ac900
0x9ac91c: MOV RDI, RDX
0x9ac91f: MOV RDX, R15
0x9ac922: LEA R15, [0x391c310]
0x9ac929: JMP 0x009ac92e
0x9ac92b: MOVSXD RBX, ECX
0x9ac92e: MOV RSI, qword ptr [R8 + RBX*0x8]
0x9ac932: OR R10, RSI
0x9ac935: TEST RSI, RSI
0x9ac938: SETZ SIL
0x9ac93c: MOV qword ptr [R8 + RBX*0x8], R10
0x9ac940: MOV RBX, -0x1
0x9ac947: OR R9B, SIL
0x9ac94a: TEST R9B, 0x1
0x9ac94e: JZ 0x009ac95e
0x9ac950: CMP R14, 0x2
0x9ac954: LEA R14, [R14 + 0x1]
0x9ac958: JC 0x009ac890
0x9ac95e: MOV RDI, qword ptr [RBP + -0x40]
0x9ac962: XOR R14D, R14D
0x9ac965: XOR ESI, ESI
0x9ac967: XOR EDX, EDX
0x9ac969: XOR ECX, ECX
0x9ac96b: CALL 0x004c6fa0
0x9ac970: MOV RCX, qword ptr [RBP + -0x38]
0x9ac974: MOV RAX, qword ptr [RBP + -0x48]
0x9ac978: MOV qword ptr [RAX + 0x8], RCX
0x9ac97c: JMP 0x009ac7e6
0x9ac981: CALL 0x006fd6b0
0x9ac986: UD2

; local helper / adjacent context (reachability below); evidence ev_bb79ccd73cc66626fbcdf8871f286f666a53f4420aa876a83953926d684bc1a9; body [{"start": "0x9ac990", "end": "0x9ac99a"}]
sub_9ac990: ; RVA 0x9ac990
0x9ac990: PUSH RBP
0x9ac991: MOV RBP, RSP
0x9ac994: MOV EAX, 0x2d
0x9ac999: POP RBP
0x9ac99a: RET

; local helper / adjacent context (reachability below); evidence ev_512b588d15e6bd12acd5192a4abcb091d4c414869d3d5b8fb4b34b00ef55cea8; body [{"start": "0x9ac9a0", "end": "0x9ac9aa"}]
sub_9ac9a0: ; RVA 0x9ac9a0
0x9ac9a0: PUSH RBP
0x9ac9a1: MOV RBP, RSP
0x9ac9a4: MOV EAX, 0x2d
0x9ac9a9: POP RBP
0x9ac9aa: RET

; local helper / adjacent context (reachability below); evidence ev_44348483c051260b0e4ee34b50c8da4e96a3f70db3f944db8aafe503f61433b3; body [{"start": "0x9ac9b0", "end": "0x9aca13"}]
sub_9ac9b0: ; RVA 0x9ac9b0
0x9ac9b0: PUSH RBP
0x9ac9b1: MOV RBP, RSP
0x9ac9b4: PUSH R15
0x9ac9b6: PUSH R14
0x9ac9b8: PUSH RBX
0x9ac9b9: PUSH RAX
0x9ac9ba: MOV RBX, RSI
0x9ac9bd: MOV R14, RDI
0x9ac9c0: MOV ESI, 0x78
0x9ac9c5: MOV RDI, RBX
0x9ac9c8: CALL 0x00258ff0
0x9ac9cd: MOV R15, qword ptr [R14]
0x9ac9d0: MOV dword ptr [RBX + 0x58], 0x10000
0x9ac9d7: MOV word ptr [RBX + 0x8], 0xb000
0x9ac9dd: XOR ESI, ESI
0x9ac9df: XOR EDX, EDX
0x9ac9e1: XOR ECX, ECX
0x9ac9e3: LEA R14, [R15 + 0x28]
0x9ac9e7: MOV RDI, R14
0x9ac9ea: CALL 0x004c6a00
0x9ac9ef: MOV EAX, dword ptr [R15 + 0x48]
0x9ac9f3: MOV RDI, R14
0x9ac9f6: XOR ESI, ESI
0x9ac9f8: XOR EDX, EDX
0x9ac9fa: XOR ECX, ECX
0x9ac9fc: ADD EAX, EAX
0x9ac9fe: MOV qword ptr [RBX + 0x50], RAX
0x9aca02: CALL 0x004c6fa0
0x9aca07: XOR EAX, EAX
0x9aca09: ADD RSP, 0x8
0x9aca0d: POP RBX
0x9aca0e: POP R14
0x9aca10: POP R15
0x9aca12: POP RBP
0x9aca13: RET

; local helper / adjacent context (reachability below); evidence ev_b570df485c486958df7236d440d367729297c9d3de732b99819d71f90b9cfc60; body [{"start": "0x9aca3c", "end": "0x9aca48"}]
sub_9aca3c: ; RVA 0x9aca3c
0x9aca3c: PUSH RBP
0x9aca3d: MOV RBP, RSP
0x9aca40: CALL 0x009a7c00
0x9aca45: POP RBP
0x9aca46: XOR EAX, EAX
0x9aca48: RET

; local helper / adjacent context (reachability below); evidence ev_f65959489d0f99043ec878ca7f9209822476a606f748b7768497a9f7ceeea0e2; body [{"start": "0x9aca50", "end": "0x9aca5e"}]
sub_9aca50: ; RVA 0x9aca50
0x9aca50: PUSH RBP
0x9aca51: MOV RBP, RSP
0x9aca54: MOV dword ptr [RSI + 0x4], 0xff
0x9aca5b: XOR EAX, EAX
0x9aca5d: POP RBP
0x9aca5e: RET

; local helper / adjacent context (reachability below); evidence ev_d7e543bf38af22b885b98dec514492c214282fbbb917cb5ef52f896df6fdeec1; body [{"start": "0x9aca60", "end": "0x9acc0b"}]
sub_9aca60: ; RVA 0x9aca60
0x9aca60: PUSH RBP
0x9aca61: MOV RBP, RSP
0x9aca64: PUSH R15
0x9aca66: PUSH R14
0x9aca68: PUSH R13
0x9aca6a: PUSH R12
0x9aca6c: PUSH RBX
0x9aca6d: SUB RSP, 0x18
0x9aca71: CMP qword ptr [RBP + 0x18], 0x0
0x9aca76: MOV EAX, 0x16
0x9aca7b: JZ 0x009aca8c
0x9aca7d: ADD RSP, 0x18
0x9aca81: POP RBX
0x9aca82: POP R12
0x9aca84: POP R13
0x9aca86: POP R14
0x9aca88: POP R15
0x9aca8a: POP RBP
0x9aca8b: RET
0x9aca8c: MOV R15, qword ptr [RBP + 0x20]
0x9aca90: MOV EBX, dword ptr [RBP + 0x10]
0x9aca93: MOV R10, qword ptr [RDI]
0x9aca96: MOV RDI, qword ptr [R15 + 0x8]
0x9aca9a: MOV R11D, EBX
0x9aca9d: AND R11D, 0xff000000
0x9acaa4: JZ 0x009acab1
0x9acaa6: CMP R11D, 0x15000000
0x9acaad: JL 0x009aca7d
0x9acaaf: JMP 0x009acab7
0x9acab1: OR EBX, 0x15000000
0x9acab7: MOV R11D, EBX
0x9acaba: AND R11D, 0x3
0x9acabe: CMP R11D, 0x1
0x9acac2: SETNZ R11B
0x9acac6: AND R9D, R8D
0x9acac9: NOT R9D
0x9acacc: TEST R9B, 0x33
0x9acad0: SETNZ R9B
0x9acad4: OR R9B, R11B
0x9acad7: JNZ 0x009aca7d
0x9acad9: TEST BL, 0x10
0x9acadc: JNZ 0x009acae9
0x9acade: MOV R9, RCX
0x9acae1: SHL R9, 0x2b
0x9acae5: JNZ 0x009aca7d
0x9acae7: JMP 0x009acb29
0x9acae9: MOV R9, qword ptr [RDX]
0x9acaec: TEST R9D, 0x1fffff
0x9acaf3: JNZ 0x009aca7d
0x9acaf5: LEA R11, [R9 + RCX*0x1]
0x9acaf9: SHR R11, 0x1c
0x9acafd: CMP R11, 0x7f
0x9acb01: SETC R11B
0x9acb05: SHR R9, 0x1c
0x9acb09: CMP R9, 0xff
0x9acb10: SETNC R9B
0x9acb14: TEST ECX, 0x1fffff
0x9acb1a: JNZ 0x009aca7d
0x9acb20: OR R9B, R11B
0x9acb23: JZ 0x009aca7d
0x9acb29: MOV EAX, dword ptr [RDI + 0x5c0]
0x9acb2f: MOV R11D, dword ptr [RDI + 0x5d0]
0x9acb36: MOV R9, qword ptr [R15 + 0x140]
0x9acb3d: MOV R13, RSI
0x9acb40: MOV R12D, R8D
0x9acb43: MOV qword ptr [RBP + -0x38], RDX
0x9acb47: MOV EDI, 0xb
0x9acb4c: MOV RSI, R10
0x9acb4f: MOV qword ptr [RBP + -0x30], RCX
0x9acb53: MOV RDX, RCX
0x9acb56: MOV ECX, 0x33
0x9acb5b: XOR R8D, R8D
0x9acb5e: PUSH R11
0x9acb60: PUSH RAX
0x9acb61: CALL 0x0045da60
0x9acb66: ADD RSP, 0x10
0x9acb6a: TEST RAX, RAX
0x9acb6d: JZ 0x009acbaf
0x9acb6f: MOV RSI, qword ptr [RBP + -0x38]
0x9acb73: MOV RDX, qword ptr [RBP + -0x30]
0x9acb77: MOV R14, RAX
0x9acb7a: MOVZX ECX, R12W
0x9acb7e: MOV RDI, R13
0x9acb81: MOV R8D, 0x33
0x9acb87: MOV R9D, EBX
0x9acb8a: PUSH R15
0x9acb8c: PUSH 0x0
0x9acb8e: PUSH 0x0
0x9acb90: PUSH RAX
0x9acb91: CALL 0x00ab9f30
0x9acb96: ADD RSP, 0x20
0x9acb9a: TEST EAX, EAX
0x9acb9c: JZ 0x009acbb9
0x9acb9e: MOV RDI, R14
0x9acba1: MOV EBX, EAX
0x9acba3: CALL 0x00461ba0
0x9acba8: MOV EAX, EBX
0x9acbaa: JMP 0x009aca7d
0x9acbaf: MOV EAX, 0xc
0x9acbb4: JMP 0x009aca7d
0x9acbb9: MOV RAX, qword ptr [RBP + -0x38]
0x9acbbd: MOV RAX, qword ptr [RAX]
0x9acbc0: MOV RCX, RAX
0x9acbc3: SHR RCX, 0x1c
0x9acbc7: CMP RCX, 0xfe
0x9acbce: JA 0x009acbea
0x9acbd0: ADD RAX, qword ptr [RBP + -0x30]
0x9acbd4: MOV RCX, 0x7f0000000
0x9acbde: INC RCX
0x9acbe1: CMP RAX, RCX
0x9acbe4: JC 0x009acbea
0x9acbe6: XOR EAX, EAX
0x9acbe8: JMP 0x009acbfe
0x9acbea: MOV RAX, qword ptr GS:[0x0]
0x9acbf3: MOV RAX, qword ptr [RAX + 0x8]
0x9acbf7: MOVZX EAX, byte ptr [RAX + 0x5c0]
0x9acbfe: MOV byte ptr [R14 + 0x19c], AL
0x9acc05: XOR EAX, EAX
0x9acc07: JMP 0x009aca7d

; local helper / adjacent context (reachability below); evidence ev_dd7f854ea45e03982acbdfd7a35d82a08efe81bb4d02facc9f6611a94100e570; body [{"start": "0x9acc10", "end": "0x9acc21"}]
FUN_009acc10: ; RVA 0x9acc10
0x9acc10: CMP EDI, 0x15
0x9acc13: JNC 0x009acc22
0x9acc15: MOV EAX, EDI
0x9acc17: LEA RCX, [0x18cdbb4]
0x9acc1e: MOV EAX, dword ptr [RCX + RAX*0x4]
0x9acc21: RET

; local helper / adjacent context (reachability below); evidence ev_9a32cdabb18d359c9028e92022253f47585128f2cb0c3fbb76d2123f4d5d658b; body [{"start": "0x9acc22", "end": "0x9acc54"}]
sub_9acc22: ; RVA 0x9acc22
0x9acc22: PUSH RBP
0x9acc23: MOV RBP, RSP
0x9acc26: PUSH RBX
0x9acc27: PUSH RAX
0x9acc28: MOV EBX, EDI
0x9acc2a: CALL 0x007f1950
0x9acc2f: MOVSXD RSI, EBX
0x9acc32: LEA RDI, [0x9acc22]
0x9acc39: CALL 0x007f18a0
0x9acc3e: LEA RSI, [0x12947a2]
0x9acc45: MOV EDI, 0x7
0x9acc4a: MOV EDX, EBX
0x9acc4c: XOR EAX, EAX
0x9acc4e: CALL 0x00c9aa10
0x9acc53: UD2

; local helper / adjacent context (reachability below); evidence ev_8d74b53b1f263902b57715a372fb6c1d119a443247bee1bb6b0457e4b94908b1; body [{"start": "0x9acc60", "end": "0x9accd2"}]
sub_9acc60: ; RVA 0x9acc60
0x9acc60: PUSH RBP
0x9acc61: MOV RBP, RSP
0x9acc64: MOV EDI, 0x400000
0x9acc69: LEA RAX, [0x3ba5e80]
0x9acc70: MOV qword ptr [0x03ba5e80], 0x0
0x9acc7b: MOV qword ptr [0x03ba5e88], RAX
0x9acc82: CALL 0x005033b0
0x9acc87: LEA RSI, [0x2bfb810]
0x9acc8e: MOV qword ptr [0x03ba5eb8], RAX
0x9acc95: MOV RAX, 0x400000004
0x9acc9f: MOV EDI, 0x8000
0x9acca4: MOV EDX, 0x8002
0x9acca9: MOV qword ptr [0x03ba5ec0], RAX
0x9accb0: MOV dword ptr [0x03ba5ec8], 0x80
0x9accba: CALL 0x00c08b50
0x9accbf: MOV qword ptr [0x03ba5ee0], RAX
0x9accc6: MOV qword ptr [0x03ba5ed8], 0xf
0x9accd1: POP RBP
0x9accd2: RET

; local helper / adjacent context (reachability below); evidence ev_2878e5d36ed85b4e0b2456ec14a540b6e4b58ea3ff6295b0679406de2234a871; body [{"start": "0x9accec", "end": "0x9acd37"}]
sub_9accec: ; RVA 0x9accec
0x9accec: PUSH RBP
0x9acced: MOV RBP, RSP
0x9accf0: CALL 0x00b07940
0x9accf5: MOV ECX, EAX
0x9accf7: MOV EAX, 0x1
0x9accfc: TEST ECX, ECX
0x9accfe: JNZ 0x009acd30
0x9acd00: CALL 0x00b07960
0x9acd05: MOV ECX, EAX
0x9acd07: MOV EAX, 0x1
0x9acd0c: TEST ECX, ECX
0x9acd0e: JNZ 0x009acd30
0x9acd10: CALL 0x00b07920
0x9acd15: TEST EAX, EAX
0x9acd17: JZ 0x009acd2e
0x9acd19: MOV EDI, 0x6e
0x9acd1e: CALL 0x00acc9a0
0x9acd23: MOV ECX, EAX
0x9acd25: XOR EAX, EAX
0x9acd27: TEST ECX, ECX
0x9acd29: SETNZ AL
0x9acd2c: JMP 0x009acd30
0x9acd2e: XOR EAX, EAX
0x9acd30: MOV dword ptr [0x02560040], EAX
0x9acd36: POP RBP
0x9acd37: RET

; local helper / adjacent context (reachability below); evidence ev_75c4f3fdb18891ab2e24f2a2d33dbca3dabb5a18978f7870f3ba069afc4a8923; body [{"start": "0x9acd40", "end": "0x9acddf"}]
sub_9acd40: ; RVA 0x9acd40
0x9acd40: PUSH RBP
0x9acd41: MOV RBP, RSP
0x9acd44: PUSH R14
0x9acd46: PUSH RBX
0x9acd47: MOV RBX, RDI
0x9acd4a: CMP ESI, -0x1
0x9acd4d: JZ 0x009acda4
0x9acd4f: MOV RDI, RBX
0x9acd52: MOV R14D, ESI
0x9acd55: CALL 0x009ad320
0x9acd5a: TEST EAX, EAX
0x9acd5c: JZ 0x009acdaa
0x9acd5e: LEA RDI, [0x3ba5f00]
0x9acd65: XOR ESI, ESI
0x9acd67: XOR EDX, EDX
0x9acd69: XOR ECX, ECX
0x9acd6b: CALL 0x004c6a00
0x9acd70: DEC dword ptr [0x03ba5f08]
0x9acd76: JNZ 0x009acd90
0x9acd78: MOV EAX, dword ptr [0x03ba5f0c]
0x9acd7e: TEST EAX, EAX
0x9acd80: JZ 0x009acd90
0x9acd82: LEA RDI, [0x3ba5f10]
0x9acd89: XOR ESI, ESI
0x9acd8b: CALL 0x0073f010
0x9acd90: LEA RDI, [0x3ba5f00]
0x9acd97: XOR ESI, ESI
0x9acd99: XOR EDX, EDX
0x9acd9b: XOR ECX, ECX
0x9acd9d: CALL 0x004c6fa0
0x9acda2: JMP 0x009acdaa
0x9acda4: MOV R14D, 0x23
0x9acdaa: MOV RDI, qword ptr [RBX + 0x68]
0x9acdae: TEST RDI, RDI
0x9acdb1: JZ 0x009acdc7
0x9acdb3: LEA RSI, [0x255ffd0]
0x9acdba: MOV qword ptr [RBX + 0x68], 0x0
0x9acdc2: CALL 0x00c08df0
0x9acdc7: TEST R14D, R14D
0x9acdca: JZ 0x009acdd4
0x9acdcc: MOV dword ptr [RBX + 0x48], R14D
0x9acdd0: OR byte ptr [RBX + 0x2], 0x1
0x9acdd4: MOV RDI, RBX
0x9acdd7: POP RBX
0x9acdd8: POP R14
0x9acdda: POP RBP
0x9acddb: JMP 0x00aa0240

; local helper / adjacent context (reachability below); evidence ev_f47811b4315f3af5690222a545616c760bc22c34e9b3ea9d03181ce9da3b40cd; body [{"start": "0x9acde0", "end": "0x9ad02b"}]
sub_9acde0: ; RVA 0x9acde0
0x9acde0: PUSH RBP
0x9acde1: MOV RBP, RSP
0x9acde4: PUSH R15
0x9acde6: PUSH R14
0x9acde8: PUSH R13
0x9acdea: PUSH R12
0x9acdec: PUSH RBX
0x9acded: SUB RSP, 0x38
0x9acdf1: LEA RAX, [0x391c310]
0x9acdf8: MOV qword ptr [RBP + -0x50], RDX
0x9acdfc: MOV qword ptr [RBP + -0x58], RSI
0x9ace00: MOV R12, RDI
0x9ace03: MOV RAX, qword ptr [RAX]
0x9ace06: MOV qword ptr [RBP + -0x30], RAX
0x9ace0a: MOV R14, qword ptr [RDI + 0x130]
0x9ace11: ADD R14, qword ptr [RDI + 0x20]
0x9ace15: MOV RBX, qword ptr [RDI + 0x30]
0x9ace19: MOV R15D, dword ptr [0x02560040]
0x9ace20: CMP R15D, -0x1
0x9ace24: JZ 0x009ace30
0x9ace26: TEST R15D, R15D
0x9ace29: JNZ 0x009ace75
0x9ace2b: JMP 0x009acec9
0x9ace30: CALL 0x00b07940
0x9ace35: MOV R15D, 0x1
0x9ace3b: TEST EAX, EAX
0x9ace3d: JNZ 0x009ace69
0x9ace3f: CALL 0x00b07960
0x9ace44: TEST EAX, EAX
0x9ace46: JNZ 0x009ace69
0x9ace48: CALL 0x00b07920
0x9ace4d: TEST EAX, EAX
0x9ace4f: JZ 0x009ace66
0x9ace51: MOV EDI, 0x6e
0x9ace56: CALL 0x00acc9a0
0x9ace5b: XOR R15D, R15D
0x9ace5e: TEST EAX, EAX
0x9ace60: SETNZ R15B
0x9ace64: JMP 0x009ace69
0x9ace66: XOR R15D, R15D
0x9ace69: MOV dword ptr [0x02560040], R15D
0x9ace70: TEST R15D, R15D
0x9ace73: JZ 0x009acec9
0x9ace75: LEA RSI, [RBP + -0x38]
0x9ace79: LEA RDX, [RBP + -0x40]
0x9ace7d: MOV EDI, 0x10003
0x9ace82: MOV qword ptr [RBP + -0x40], 0x0
0x9ace8a: CALL 0x003d6df0
0x9ace8f: TEST EAX, EAX
0x9ace91: JZ 0x009aceac
0x9ace93: MOV EDX, EAX
0x9ace95: LEA RDI, [0x127c65f]
0x9ace9c: LEA RSI, [0x12af557]
0x9acea3: XOR EAX, EAX
0x9acea5: CALL 0x0025d410
0x9aceaa: JMP 0x009acec9
0x9aceac: MOV RAX, R14
0x9aceaf: SHR RAX, 0x10
0x9aceb3: SUB RAX, qword ptr [RBP + -0x38]
0x9aceb7: JL 0x009acec9
0x9aceb9: CMP RAX, qword ptr [RBP + -0x40]
0x9acebd: JGE 0x009acec9
0x9acebf: XOR EDX, EDX
0x9acec1: MOV R13D, 0x3
0x9acec7: JMP 0x009acf23
0x9acec9: MOV R15D, dword ptr [0x02560040]
0x9aced0: CMP R15D, -0x1
0x9aced4: JNZ 0x009acf16
0x9aced6: CALL 0x00b07940
0x9acedb: MOV R15D, 0x1
0x9acee1: TEST EAX, EAX
0x9acee3: JNZ 0x009acf0f
0x9acee5: CALL 0x00b07960
0x9aceea: TEST EAX, EAX
0x9aceec: JNZ 0x009acf0f
0x9aceee: CALL 0x00b07920
0x9acef3: TEST EAX, EAX
0x9acef5: JZ 0x009acf0c
0x9acef7: MOV EDI, 0x6e
0x9acefc: CALL 0x00acc9a0
0x9acf01: XOR R15D, R15D
0x9acf04: TEST EAX, EAX
0x9acf06: SETNZ R15B
0x9acf0a: JMP 0x009acf0f
0x9acf0c: XOR R15D, R15D
0x9acf0f: MOV dword ptr [0x02560040], R15D
0x9acf16: XOR R13D, R13D
0x9acf19: CMP R15D, 0x1
0x9acf1d: MOV DL, 0x1
0x9acf1f: ADC R13D, 0x1
0x9acf23: MOV RAX, qword ptr [R12 + 0x130]
0x9acf2b: MOV R15, R14
0x9acf2e: MOV qword ptr [RBP + -0x48], R12
0x9acf32: SHR R15, 0x9
0x9acf36: TEST R14W, R14W
0x9acf3a: JNZ 0x009acf55
0x9acf3c: MOV RCX, qword ptr [R12 + 0x128]
0x9acf44: SUB RCX, RAX
0x9acf47: CMP RCX, 0xffff
0x9acf4e: JBE 0x009acf55
0x9acf50: XOR R12D, R12D
0x9acf53: JMP 0x009acf8a
0x9acf55: TEST RAX, RAX
0x9acf58: JZ 0x009acf6a
0x9acf5a: MOV RAX, qword ptr [RBP + -0x48]
0x9acf5e: MOV R12, qword ptr [RAX + 0x68]
0x9acf62: MOV RBX, R12
0x9acf65: TEST R12, R12
0x9acf68: JNZ 0x009acf8a
0x9acf6a: MOV EBX, EDX
0x9acf6c: LEA RSI, [0x255ffd0]
0x9acf73: MOV EDI, 0x10000
0x9acf78: MOV EDX, 0x102
0x9acf7d: CALL 0x00c08b50
0x9acf82: MOV EDX, EBX
0x9acf84: MOV R12, RAX
0x9acf87: MOV RBX, RAX
0x9acf8a: MOV RAX, qword ptr [RBP + -0x48]
0x9acf8e: AND R15, -0x80
0x9acf92: MOV ECX, 0x20010401
0x9acf97: MOV R14D, 0x80010500
0x9acf9d: MOV qword ptr [RAX + 0x68], R12
0x9acfa1: TEST DL, DL
0x9acfa3: CMOVNZ R14D, ECX
0x9acfa7: JNZ 0x009acfb4
0x9acfa9: MOV RDI, R15
0x9acfac: CALL 0x009e1f40
0x9acfb1: MOV R15, RAX
0x9acfb4: MOV RAX, qword ptr [RBP + -0x50]
0x9acfb8: MOV RCX, qword ptr [RBP + -0x58]
0x9acfbc: MOV RSI, 0x400000000000
0x9acfc6: MOV EDI, R13D
0x9acfc9: MOV RDX, RBX
0x9acfcc: MOV R9D, R14D
0x9acfcf: XOR R8D, R8D
0x9acfd2: OR RSI, R15
0x9acfd5: MOV qword ptr [RSP], RAX
0x9acfd9: CALL 0x00689b00
0x9acfde: TEST R12, R12
0x9acfe1: JZ 0x009ad006
0x9acfe3: TEST EAX, EAX
0x9acfe5: JZ 0x009ad006
0x9acfe7: MOV RCX, qword ptr [RBP + -0x48]
0x9acfeb: LEA RSI, [0x255ffd0]
0x9acff2: MOV RDI, R12
0x9acff5: MOV EBX, EAX
0x9acff7: MOV qword ptr [RCX + 0x68], 0x0
0x9acfff: CALL 0x00c08df0
0x9ad004: MOV EAX, EBX
0x9ad006: LEA RCX, [0x391c310]
0x9ad00d: MOV RCX, qword ptr [RCX]
0x9ad010: CMP RCX, qword ptr [RBP + -0x30]
0x9ad014: JNZ 0x009ad025
0x9ad016: ADD RSP, 0x38
0x9ad01a: POP RBX
0x9ad01b: POP R12
0x9ad01d: POP R13
0x9ad01f: POP R14
0x9ad021: POP R15
0x9ad023: POP RBP
0x9ad024: RET
0x9ad025: CALL 0x006fd6b0
0x9ad02a: UD2

; local helper / adjacent context (reachability below); evidence ev_fb4f0c706b760e03583754e1b0cc91bf84cd7ab2afbdde9515bdbac9d978f5cd; body [{"start": "0x9ad030", "end": "0x9ad318"}]
sub_9ad030: ; RVA 0x9ad030
0x9ad030: PUSH RBP
0x9ad031: MOV RBP, RSP
0x9ad034: PUSH R15
0x9ad036: PUSH R14
0x9ad038: PUSH R13
0x9ad03a: PUSH R12
0x9ad03c: PUSH RBX
0x9ad03d: SUB RSP, 0x28
0x9ad041: LEA RAX, [0x391c310]
0x9ad048: MOV RBX, RDI
0x9ad04b: MOV R13D, ESI
0x9ad04e: MOV RAX, qword ptr [RAX]
0x9ad051: MOV qword ptr [RBP + -0x30], RAX
0x9ad055: MOV R14, qword ptr [RDI]
0x9ad058: MOV RAX, qword ptr [RDI + 0x8]
0x9ad05c: MOV EDI, 0x21c1
0x9ad061: MOV qword ptr [RBP + -0x48], RAX
0x9ad065: MOVZX EAX, word ptr [R14 + 0x20]
0x9ad06a: MOV R12, qword ptr [R14 + 0x68]
0x9ad06e: MOV word ptr [RBP + -0x36], 0x0
0x9ad074: MOV dword ptr [RBP + -0x3c], 0x0
0x9ad07b: MOV qword ptr [RBP + -0x50], RAX
0x9ad07f: MOV EAX, dword ptr [R14 + 0x198]
0x9ad086: TEST EAX, EAX
0x9ad088: CMOVNZ EDI, EAX
0x9ad08b: CALL 0x005f0f70
0x9ad090: LEA RSI, [RBP + -0x36]
0x9ad094: LEA RDX, [RBP + -0x3c]
0x9ad098: MOV EDI, R13D
0x9ad09b: XOR ECX, ECX
0x9ad09d: MOV dword ptr [RBP + -0x40], EAX
0x9ad0a0: CALL 0x0068e1a0
0x9ad0a5: TEST EAX, EAX
0x9ad0a7: JZ 0x009ad0c1
0x9ad0a9: MOV R15D, EAX
0x9ad0ac: LEA RDI, [0x1384734]
0x9ad0b3: LEA RSI, [0x12edd61]
0x9ad0ba: MOV EDX, EAX
0x9ad0bc: MOV ECX, R13D
0x9ad0bf: JMP 0x009ad0f2
0x9ad0c1: MOV R13, qword ptr [RBP + -0x50]
0x9ad0c5: LEA RSI, [0x255ffd0]
0x9ad0cc: MOV RDI, RBX
0x9ad0cf: CALL 0x00c08df0
0x9ad0d4: MOVZX R15D, word ptr [RBP + -0x36]
0x9ad0d9: TEST R15D, R15D
0x9ad0dc: JZ 0x009ad13a
0x9ad0de: MOV ECX, dword ptr [RBP + -0x3c]
0x9ad0e1: LEA RDI, [0x13079f2]
0x9ad0e8: LEA RSI, [0x13b0051]
0x9ad0ef: MOV EDX, R15D
0x9ad0f2: XOR EAX, EAX
0x9ad0f4: CALL 0x0025d410
0x9ad0f9: MOV RAX, qword ptr [R14 + 0x128]
0x9ad100: MOV RDI, R14
0x9ad103: MOV ESI, R15D
0x9ad106: MOV qword ptr [R14 + 0x50], RAX
0x9ad10a: CALL 0x009acd40
0x9ad10f: MOV EDI, dword ptr [RBP + -0x40]
0x9ad112: CALL 0x005f0f70
0x9ad117: LEA RAX, [0x391c310]
0x9ad11e: MOV RAX, qword ptr [RAX]
0x9ad121: CMP RAX, qword ptr [RBP + -0x30]
0x9ad125: JNZ 0x009ad312
0x9ad12b: ADD RSP, 0x28
0x9ad12f: POP RBX
0x9ad130: POP R12
0x9ad132: POP R13
0x9ad134: POP R14
0x9ad136: POP R15
0x9ad138: POP RBP
0x9ad139: RET
0x9ad13a: TEST R12, R12
0x9ad13d: JZ 0x009ad16e
0x9ad13f: MOV RDX, qword ptr [R14 + 0x128]
0x9ad146: MOV RSI, qword ptr [R14 + 0x30]
0x9ad14a: MOV R15D, 0x10000
0x9ad150: ADD R12, R13
0x9ad153: SUB R15, R13
0x9ad156: MOV RDI, R12
0x9ad159: LEA RAX, [RDX + R13*0x1]
0x9ad15d: CMP RAX, 0x10001
0x9ad163: CMOVNC RDX, R15
0x9ad167: CALL 0x00259be0
0x9ad16c: JMP 0x009ad177
0x9ad16e: MOV R15D, 0x10000
0x9ad174: SUB R15, R13
0x9ad177: MOV RDX, qword ptr [R14 + 0x128]
0x9ad17e: MOV RBX, qword ptr [RBP + -0x48]
0x9ad182: MOV RAX, RDX
0x9ad185: SUB RAX, R15
0x9ad188: JBE 0x009ad22d
0x9ad18e: MOV qword ptr [R14 + 0x130], R15
0x9ad195: MOV qword ptr [R14 + 0x50], RAX
0x9ad199: MOV RAX, qword ptr [R14 + 0x20]
0x9ad19d: MOV ECX, EAX
0x9ad19f: ADD CX, R15W
0x9ad1a3: JZ 0x009ad1ce
0x9ad1a5: MOV RDX, RAX
0x9ad1a8: LEA RDI, [0x1394bd8]
0x9ad1af: LEA RSI, [0x12b97ff]
0x9ad1b6: MOV RCX, R15
0x9ad1b9: XOR EAX, EAX
0x9ad1bb: CALL 0x0025d410
0x9ad1c0: MOV RDX, qword ptr [R14 + 0x128]
0x9ad1c7: MOV R15, qword ptr [R14 + 0x130]
0x9ad1ce: CMP RDX, R15
0x9ad1d1: JLE 0x009ad23e
0x9ad1d3: LEA RSI, [0x255ffd0]
0x9ad1da: MOV EDI, 0x20
0x9ad1df: MOV EDX, 0x2
0x9ad1e4: CALL 0x00c08b50
0x9ad1e9: MOV R15, RAX
0x9ad1ec: MOV qword ptr [RAX], R14
0x9ad1ef: TEST RBX, RBX
0x9ad1f2: JZ 0x009ad26a
0x9ad1f4: MOV R12, qword ptr [R14 + 0x130]
0x9ad1fb: ADD R12, qword ptr [R14 + 0x20]
0x9ad1ff: MOV RBX, R15
0x9ad202: ADD RBX, 0x10
0x9ad206: MOV RDI, R12
0x9ad209: CALL 0x003d6f60
0x9ad20e: MOV dword ptr [R15 + 0x14], EAX
0x9ad212: CMP EAX, -0x1
0x9ad215: JZ 0x009ad227
0x9ad217: SHR R12, 0x10
0x9ad21b: MOV qword ptr [R15 + 0x18], R12
0x9ad21f: MOV dword ptr [R15 + 0x10], 0xc
0x9ad227: MOV qword ptr [R15 + 0x8], RBX
0x9ad22b: JMP 0x009ad27c
0x9ad22d: MOV qword ptr [R14 + 0x130], RDX
0x9ad234: XOR EAX, EAX
0x9ad236: XOR R15D, R15D
0x9ad239: JMP 0x009ad100
0x9ad23e: LEA RDI, [0x13aa80b]
0x9ad245: LEA RSI, [0x12b97ff]
0x9ad24c: MOV RCX, R15
0x9ad24f: XOR EAX, EAX
0x9ad251: CALL 0x0025d410
0x9ad256: MOV RAX, qword ptr [R14 + 0x128]
0x9ad25d: MOV RDI, R14
0x9ad260: MOV ESI, 0x16
0x9ad265: JMP 0x009ad106
0x9ad26a: MOV qword ptr [R15 + 0x8], 0x0
0x9ad272: XOR EBX, EBX
0x9ad274: MOV dword ptr [R15 + 0x14], 0xffffffff
0x9ad27c: LEA RDX, [RBP + -0x34]
0x9ad280: MOV RDI, R14
0x9ad283: MOV RSI, RBX
0x9ad286: CALL 0x009acde0
0x9ad28b: TEST EAX, EAX
0x9ad28d: JZ 0x009ad2c8
0x9ad28f: LEA RDI, [0x134550c]
0x9ad296: LEA RSI, [0x12b97ff]
0x9ad29d: MOV EDX, EAX
0x9ad29f: MOV EBX, EAX
0x9ad2a1: XOR EAX, EAX
0x9ad2a3: CALL 0x0025d410
0x9ad2a8: LEA RSI, [0x255ffd0]
0x9ad2af: MOV RDI, R15
0x9ad2b2: CALL 0x00c08df0
0x9ad2b7: MOV RAX, qword ptr [R14 + 0x128]
0x9ad2be: MOV RDI, R14
0x9ad2c1: MOV ESI, EBX
0x9ad2c3: JMP 0x009ad106
0x9ad2c8: LEA RDI, [0x26a580]
0x9ad2cf: LEA RDX, [RBP + -0x34]
0x9ad2d3: MOV RSI, R15
0x9ad2d6: MOV ECX, 0x1
0x9ad2db: CALL 0x005b01d0
0x9ad2e0: TEST EAX, EAX
0x9ad2e2: JZ 0x009ad10f
0x9ad2e8: MOV ECX, dword ptr [RBP + -0x34]
0x9ad2eb: MOV EDX, EAX
0x9ad2ed: LEA RDI, [0x12d95db]
0x9ad2f4: LEA RSI, [0x12b97ff]
0x9ad2fb: XOR EAX, EAX
0x9ad2fd: CALL 0x0025d410
0x9ad302: MOV ESI, dword ptr [RBP + -0x34]
0x9ad305: MOV RDI, R15
0x9ad308: CALL 0x009ad490
0x9ad30d: JMP 0x009ad10f
0x9ad312: CALL 0x006fd6b0
0x9ad317: UD2

; local helper / adjacent context (reachability below); evidence ev_2d43bafcd07ed8dcc86251ad307a5e95345e0abaa5d5dbd83ed14eeb683d1332; body [{"start": "0x9ad320", "end": "0x9ad483"}]
sub_9ad320: ; RVA 0x9ad320
0x9ad320: PUSH RBP
0x9ad321: MOV RBP, RSP
0x9ad324: PUSH R15
0x9ad326: PUSH R14
0x9ad328: PUSH RBX
0x9ad329: PUSH RAX
0x9ad32a: MOV R15D, dword ptr [0x025600d0]
0x9ad331: MOV RBX, RDI
0x9ad334: CMP R15D, -0x1
0x9ad338: JNZ 0x009ad36c
0x9ad33a: CALL 0x00b07940
0x9ad33f: MOV R15D, 0x1
0x9ad345: TEST EAX, EAX
0x9ad347: JNZ 0x009ad365
0x9ad349: CALL 0x00b07960
0x9ad34e: TEST EAX, EAX
0x9ad350: JNZ 0x009ad365
0x9ad352: MOV EDI, 0x6d
0x9ad357: CALL 0x00acc9a0
0x9ad35c: XOR R15D, R15D
0x9ad35f: TEST EAX, EAX
0x9ad361: SETNZ R15B
0x9ad365: MOV dword ptr [0x025600d0], R15D
0x9ad36c: XOR R14D, R14D
0x9ad36f: TEST R15D, R15D
0x9ad372: JZ 0x009ad46a
0x9ad378: MOV R15D, dword ptr [0x02560040]
0x9ad37f: CMP R15D, -0x1
0x9ad383: JNZ 0x009ad3c5
0x9ad385: CALL 0x00b07940
0x9ad38a: MOV R15D, 0x1
0x9ad390: TEST EAX, EAX
0x9ad392: JNZ 0x009ad3be
0x9ad394: CALL 0x00b07960
0x9ad399: TEST EAX, EAX
0x9ad39b: JNZ 0x009ad3be
0x9ad39d: CALL 0x00b07920
0x9ad3a2: TEST EAX, EAX
0x9ad3a4: JZ 0x009ad3bb
0x9ad3a6: MOV EDI, 0x6e
0x9ad3ab: CALL 0x00acc9a0
0x9ad3b0: XOR R15D, R15D
0x9ad3b3: TEST EAX, EAX
0x9ad3b5: SETNZ R15B
0x9ad3b9: JMP 0x009ad3be
0x9ad3bb: XOR R15D, R15D
0x9ad3be: MOV dword ptr [0x02560040], R15D
0x9ad3c5: TEST R15D, R15D
0x9ad3c8: JZ 0x009ad46a
0x9ad3ce: CMP byte ptr [0x03ba5f20], 0x0
0x9ad3d5: JZ 0x009ad418
0x9ad3d7: MOV RAX, qword ptr [RBX + 0x20]
0x9ad3db: MOV RCX, RAX
0x9ad3de: SHR RCX, 0x10
0x9ad3e2: CMP RCX, qword ptr [0x03ba5f28]
0x9ad3e9: JL 0x009ad46a
0x9ad3eb: MOV RCX, qword ptr [RBX + 0x128]
0x9ad3f2: MOV RDX, qword ptr [0x03ba5f40]
0x9ad3f9: ADD RDX, qword ptr [0x03ba5f38]
0x9ad400: XOR R14D, R14D
0x9ad403: LEA RAX, [RAX + RCX*0x1 + 0xffff]
0x9ad40b: SHR RAX, 0x10
0x9ad40f: CMP RAX, RDX
0x9ad412: SETLE R14B
0x9ad416: JMP 0x009ad46a
0x9ad418: LEA RSI, [0x3ba5f28]
0x9ad41f: LEA RDX, [0x3ba5f30]
0x9ad426: MOV EDI, 0x10009
0x9ad42b: CALL 0x003d6df0
0x9ad430: TEST EAX, EAX
0x9ad432: JNZ 0x009ad450
0x9ad434: LEA RSI, [0x3ba5f38]
0x9ad43b: LEA RDX, [0x3ba5f40]
0x9ad442: MOV EDI, 0x10010
0x9ad447: CALL 0x003d6df0
0x9ad44c: TEST EAX, EAX
0x9ad44e: JZ 0x009ad478
0x9ad450: MOV EDX, EAX
0x9ad452: LEA RDI, [0x132c55b]
0x9ad459: LEA RSI, [0x138a7c2]
0x9ad460: XOR EAX, EAX
0x9ad462: XOR R14D, R14D
0x9ad465: CALL 0x0025d410
0x9ad46a: MOV EAX, R14D
0x9ad46d: ADD RSP, 0x8
0x9ad471: POP RBX
0x9ad472: POP R14
0x9ad474: POP R15
0x9ad476: POP RBP
0x9ad477: RET
0x9ad478: MOV byte ptr [0x03ba5f20], 0x1
0x9ad47f: JMP 0x009ad3d7

; local helper / adjacent context (reachability below); evidence ev_402b5ecd2eb04db901d1027ea5edee1eb227a63c10ebfeb9cdb1e667840b3a6d; body [{"start": "0x9ad490", "end": "0x9ad63d"}]
sub_9ad490: ; RVA 0x9ad490
0x9ad490: PUSH RBP
0x9ad491: MOV RBP, RSP
0x9ad494: PUSH R15
0x9ad496: PUSH R14
0x9ad498: PUSH R13
0x9ad49a: PUSH R12
0x9ad49c: PUSH RBX
0x9ad49d: SUB RSP, 0x18
0x9ad4a1: LEA RAX, [0x391c310]
0x9ad4a8: MOV R14, RDI
0x9ad4ab: MOV R13D, ESI
0x9ad4ae: MOV RAX, qword ptr [RAX]
0x9ad4b1: MOV qword ptr [RBP + -0x30], RAX
0x9ad4b5: MOV RBX, qword ptr [RDI]
0x9ad4b8: MOV EDI, 0x21c1
0x9ad4bd: MOV R12, qword ptr [RBX + 0x68]
0x9ad4c1: MOV word ptr [RBP + -0x32], 0x0
0x9ad4c7: MOV dword ptr [RBP + -0x38], 0x0
0x9ad4ce: MOV EAX, dword ptr [RBX + 0x198]
0x9ad4d4: TEST EAX, EAX
0x9ad4d6: CMOVNZ EDI, EAX
0x9ad4d9: CALL 0x005f0f70
0x9ad4de: LEA RSI, [RBP + -0x32]
0x9ad4e2: LEA RDX, [RBP + -0x38]
0x9ad4e6: MOV EDI, R13D
0x9ad4e9: XOR ECX, ECX
0x9ad4eb: MOV dword ptr [RBP + -0x3c], EAX
0x9ad4ee: CALL 0x0068e1a0
0x9ad4f3: TEST EAX, EAX
0x9ad4f5: JZ 0x009ad50f
0x9ad4f7: MOV R15D, EAX
0x9ad4fa: LEA RDI, [0x1384734]
0x9ad501: LEA RSI, [0x132c586]
0x9ad508: MOV EDX, EAX
0x9ad50a: MOV ECX, R13D
0x9ad50d: JMP 0x009ad540
0x9ad50f: LEA RSI, [0x255ffd0]
0x9ad516: MOV RDI, R14
0x9ad519: CALL 0x00c08df0
0x9ad51e: MOVZX R15D, word ptr [RBP + -0x32]
0x9ad523: TEST R15D, R15D
0x9ad526: JZ 0x009ad5af
0x9ad52c: MOV ECX, dword ptr [RBP + -0x38]
0x9ad52f: LEA RDI, [0x13079f2]
0x9ad536: LEA RSI, [0x13b0051]
0x9ad53d: MOV EDX, R15D
0x9ad540: XOR EAX, EAX
0x9ad542: CALL 0x0025d410
0x9ad547: MOV R8, qword ptr [RBX + 0x128]
0x9ad54e: MOV qword ptr [RBX + 0x50], R8
0x9ad552: TEST R8, R8
0x9ad555: JZ 0x009ad579
0x9ad557: MOV RCX, qword ptr [RBX + 0x130]
0x9ad55e: LEA RDI, [0x12f7bcb]
0x9ad565: LEA RSI, [0x132c586]
0x9ad56c: MOV RDX, RBX
0x9ad56f: MOV R9D, R15D
0x9ad572: XOR EAX, EAX
0x9ad574: CALL 0x0025d410
0x9ad579: MOV RDI, RBX
0x9ad57c: MOV ESI, R15D
0x9ad57f: CALL 0x009acd40
0x9ad584: MOV EDI, dword ptr [RBP + -0x3c]
0x9ad587: CALL 0x005f0f70
0x9ad58c: LEA RAX, [0x391c310]
0x9ad593: MOV RAX, qword ptr [RAX]
0x9ad596: CMP RAX, qword ptr [RBP + -0x30]
0x9ad59a: JNZ 0x009ad637
0x9ad5a0: ADD RSP, 0x18
0x9ad5a4: POP RBX
0x9ad5a5: POP R12
0x9ad5a7: POP R13
0x9ad5a9: POP R14
0x9ad5ab: POP R15
0x9ad5ad: POP RBP
0x9ad5ae: RET
0x9ad5af: TEST R12, R12
0x9ad5b2: JZ 0x009ad5e3
0x9ad5b4: MOV RAX, qword ptr [RBX + 0x128]
0x9ad5bb: MOV RCX, qword ptr [RBX + 0x130]
0x9ad5c2: MOV RSI, qword ptr [RBX + 0x30]
0x9ad5c6: MOV EDX, 0x10000
0x9ad5cb: MOV RDI, R12
0x9ad5ce: SUB RAX, RCX
0x9ad5d1: ADD RSI, RCX
0x9ad5d4: CMP RAX, 0x10000
0x9ad5da: CMOVC RDX, RAX
0x9ad5de: CALL 0x00259be0
0x9ad5e3: MOV RCX, qword ptr [RBX + 0x128]
0x9ad5ea: MOV RAX, qword ptr [RBX + 0x130]
0x9ad5f1: MOV RDX, RCX
0x9ad5f4: SUB RDX, RAX
0x9ad5f7: CMP RDX, 0x10001
0x9ad5fe: JC 0x009ad620
0x9ad600: ADD RAX, 0x10000
0x9ad606: MOV R8, -0x10000
0x9ad60d: XOR R15D, R15D
0x9ad610: MOV qword ptr [RBX + 0x130], RAX
0x9ad617: ADD R8, qword ptr [RBX + 0x50]
0x9ad61b: JMP 0x009ad54e
0x9ad620: MOV qword ptr [RBX + 0x130], RCX
0x9ad627: MOV qword ptr [RBX + 0x50], 0x0
0x9ad62f: XOR R15D, R15D
0x9ad632: JMP 0x009ad579
0x9ad637: CALL 0x006fd6b0
0x9ad63c: UD2

; local helper / adjacent context (reachability below); evidence ev_9f58077e9501e65365f71eaa6a11384be00a5817dd699e832c373e7191465c88; body [{"start": "0x9ad640", "end": "0x9ad740"}]
sub_9ad640: ; RVA 0x9ad640
0x9ad640: PUSH RBP
0x9ad641: MOV RBP, RSP
0x9ad644: PUSH R15
0x9ad646: PUSH R14
0x9ad648: PUSH R13
0x9ad64a: PUSH R12
0x9ad64c: PUSH RBX
0x9ad64d: SUB RSP, 0x18
0x9ad651: LEA R13, [0x391c310]
0x9ad658: MOV RBX, RDI
0x9ad65b: MOV R12D, ESI
0x9ad65e: MOV RAX, qword ptr [R13]
0x9ad662: MOV qword ptr [RBP + -0x30], RAX
0x9ad666: MOV EAX, dword ptr [RDI + 0x198]
0x9ad66c: MOV EDI, 0x21c1
0x9ad671: TEST EAX, EAX
0x9ad673: CMOVNZ EDI, EAX
0x9ad676: CALL 0x005f0f70
0x9ad67b: LEA RSI, [RBP + -0x32]
0x9ad67f: LEA RDX, [RBP + -0x38]
0x9ad683: MOV EDI, R12D
0x9ad686: XOR ECX, ECX
0x9ad688: MOV R14D, EAX
0x9ad68b: MOV word ptr [RBP + -0x32], 0x0
0x9ad691: MOV dword ptr [RBP + -0x38], 0x0
0x9ad698: CALL 0x0068e1a0
0x9ad69d: TEST EAX, EAX
0x9ad69f: JZ 0x009ad6d6
0x9ad6a1: LEA RDI, [0x1384734]
0x9ad6a8: LEA RSI, [0x132c5a6]
0x9ad6af: MOV EDX, EAX
0x9ad6b1: MOV ECX, R12D
0x9ad6b4: MOV R15D, EAX
0x9ad6b7: XOR EAX, EAX
0x9ad6b9: CALL 0x0025d410
0x9ad6be: MOV RAX, qword ptr [RBX + 0x128]
0x9ad6c5: MOV RDI, RBX
0x9ad6c8: MOV ESI, R15D
0x9ad6cb: MOV qword ptr [RBX + 0x50], RAX
0x9ad6cf: CALL 0x009acd40
0x9ad6d4: JMP 0x009ad719
0x9ad6d6: MOVZX R15D, word ptr [RBP + -0x32]
0x9ad6db: TEST R15D, R15D
0x9ad6de: JZ 0x009ad70f
0x9ad6e0: MOV ECX, dword ptr [RBP + -0x38]
0x9ad6e3: LEA RDI, [0x13079f2]
0x9ad6ea: LEA RSI, [0x13b0051]
0x9ad6f1: MOV EDX, R15D
0x9ad6f4: XOR EAX, EAX
0x9ad6f6: CALL 0x0025d410
0x9ad6fb: CMP R15D, 0x5
0x9ad6ff: JNZ 0x009ad6be
0x9ad701: MOV RDI, qword ptr [RBX + 0x68]
0x9ad705: MOV ESI, 0x10000
0x9ad70a: CALL 0x00258ff0
0x9ad70f: MOV RDI, RBX
0x9ad712: XOR ESI, ESI
0x9ad714: CALL 0x009ad750
0x9ad719: MOV EDI, R14D
0x9ad71c: CALL 0x005f0f70
0x9ad721: MOV RAX, qword ptr [R13]
0x9ad725: CMP RAX, qword ptr [RBP + -0x30]
0x9ad729: JNZ 0x009ad73a
0x9ad72b: ADD RSP, 0x18
0x9ad72f: POP RBX
0x9ad730: POP R12
0x9ad732: POP R13
0x9ad734: POP R14
0x9ad736: POP R15
0x9ad738: POP RBP
0x9ad739: RET
0x9ad73a: CALL 0x006fd6b0
0x9ad73f: UD2

; local helper / adjacent context (reachability below); evidence ev_8977da5ee7adefdfde81902f197b5c40c41f3888ca5ea53e665edb363b83e3e9; body [{"start": "0x9ad750", "end": "0x9ad89b"}]
sub_9ad750: ; RVA 0x9ad750
0x9ad750: PUSH RBP
0x9ad751: MOV RBP, RSP
0x9ad754: PUSH R15
0x9ad756: PUSH R14
0x9ad758: PUSH R12
0x9ad75a: PUSH RBX
0x9ad75b: SUB RSP, 0x10
0x9ad75f: LEA R12, [0x391c310]
0x9ad766: MOV RBX, RDI
0x9ad769: MOV R15, RSI
0x9ad76c: MOV EDX, 0x10000
0x9ad771: MOV RAX, qword ptr [R12]
0x9ad775: MOV qword ptr [RBP + -0x28], RAX
0x9ad779: MOVZX EAX, word ptr [RDI + 0x20]
0x9ad77d: MOV RCX, qword ptr [RBX + 0x128]
0x9ad784: MOV RSI, qword ptr [RDI + 0x68]
0x9ad788: MOV RDI, qword ptr [RDI + 0x30]
0x9ad78c: LEA R8, [RCX + RAX*0x1]
0x9ad790: ADD RSI, RAX
0x9ad793: SUB RDX, RAX
0x9ad796: CMP R8, 0x10001
0x9ad79d: CMOVC RDX, RCX
0x9ad7a1: CALL 0x00259be0
0x9ad7a6: LEA RSI, [0x255ffd0]
0x9ad7ad: MOV EDI, 0x20
0x9ad7b2: MOV EDX, 0x2
0x9ad7b7: CALL 0x00c08b50
0x9ad7bc: MOV R14, RAX
0x9ad7bf: MOV qword ptr [RAX], RBX
0x9ad7c2: TEST R15, R15
0x9ad7c5: JZ 0x009ad7e6
0x9ad7c7: CMP dword ptr [R15 + 0x4], -0x1
0x9ad7cc: JZ 0x009ad7e6
0x9ad7ce: MOV RAX, qword ptr [R15]
0x9ad7d1: MOV RCX, qword ptr [R15 + 0x8]
0x9ad7d5: MOV RSI, R14
0x9ad7d8: ADD RSI, 0x10
0x9ad7dc: MOV qword ptr [R14 + 0x18], RCX
0x9ad7e0: MOV qword ptr [R14 + 0x10], RAX
0x9ad7e4: JMP 0x009ad7e8
0x9ad7e6: XOR ESI, ESI
0x9ad7e8: LEA RDX, [RBP + -0x2c]
0x9ad7ec: MOV RDI, RBX
0x9ad7ef: MOV qword ptr [R14 + 0x8], RSI
0x9ad7f3: CALL 0x009ad8a0
0x9ad7f8: TEST EAX, EAX
0x9ad7fa: JZ 0x009ad83d
0x9ad7fc: LEA RDI, [0x12c877d]
0x9ad803: LEA RSI, [0x12d9617]
0x9ad80a: MOV EDX, EAX
0x9ad80c: MOV R15D, EAX
0x9ad80f: XOR EAX, EAX
0x9ad811: CALL 0x0025d410
0x9ad816: LEA RSI, [0x255ffd0]
0x9ad81d: MOV RDI, R14
0x9ad820: CALL 0x00c08df0
0x9ad825: MOV RAX, qword ptr [RBX + 0x128]
0x9ad82c: MOV RDI, RBX
0x9ad82f: MOV ESI, R15D
0x9ad832: MOV qword ptr [RBX + 0x50], RAX
0x9ad836: CALL 0x009acd40
0x9ad83b: JMP 0x009ad87e
0x9ad83d: LEA RDI, [0x26a590]
0x9ad844: LEA RDX, [RBP + -0x2c]
0x9ad848: MOV RSI, R14
0x9ad84b: MOV ECX, 0x1
0x9ad850: CALL 0x005b01d0
0x9ad855: TEST EAX, EAX
0x9ad857: JZ 0x009ad87e
0x9ad859: MOV ECX, dword ptr [RBP + -0x2c]
0x9ad85c: MOV EDX, EAX
0x9ad85e: LEA RDI, [0x12d95db]
0x9ad865: LEA RSI, [0x12d9617]
0x9ad86c: XOR EAX, EAX
0x9ad86e: CALL 0x0025d410
0x9ad873: MOV ESI, dword ptr [RBP + -0x2c]
0x9ad876: MOV RDI, R14
0x9ad879: CALL 0x009ada30
0x9ad87e: MOV RAX, qword ptr [R12]
0x9ad882: CMP RAX, qword ptr [RBP + -0x28]
0x9ad886: JNZ 0x009ad895
0x9ad888: ADD RSP, 0x10
0x9ad88c: POP RBX
0x9ad88d: POP R12
0x9ad88f: POP R14
0x9ad891: POP R15
0x9ad893: POP RBP
0x9ad894: RET
0x9ad895: CALL 0x006fd6b0
0x9ad89a: UD2

; local helper / adjacent context (reachability below); evidence ev_ae69703104ef703c7c338f2b4109aaec322b8548cc53761a8bd4cef27af4fea1; body [{"start": "0x9ad8a0", "end": "0x9ada2b"}]
sub_9ad8a0: ; RVA 0x9ad8a0
0x9ad8a0: PUSH RBP
0x9ad8a1: MOV RBP, RSP
0x9ad8a4: PUSH R15
0x9ad8a6: PUSH R14
0x9ad8a8: PUSH R13
0x9ad8aa: PUSH R12
0x9ad8ac: PUSH RBX
0x9ad8ad: SUB RSP, 0x28
0x9ad8b1: LEA RAX, [0x391c310]
0x9ad8b8: MOV qword ptr [RBP + -0x48], RSI
0x9ad8bc: MOV R14, RDX
0x9ad8bf: MOV RAX, qword ptr [RAX]
0x9ad8c2: MOV qword ptr [RBP + -0x30], RAX
0x9ad8c6: MOV R12, qword ptr [RDI + 0x130]
0x9ad8cd: ADD R12, qword ptr [RDI + 0x20]
0x9ad8d1: MOV R15, qword ptr [RDI + 0x68]
0x9ad8d5: TEST R15, R15
0x9ad8d8: JNZ 0x009ad8de
0x9ad8da: MOV R15, qword ptr [RDI + 0x30]
0x9ad8de: MOV EBX, dword ptr [0x02560040]
0x9ad8e4: MOV R13, R12
0x9ad8e7: SHR R13, 0x9
0x9ad8eb: CMP EBX, -0x1
0x9ad8ee: JNZ 0x009ad92b
0x9ad8f0: CALL 0x00b07940
0x9ad8f5: MOV EBX, 0x1
0x9ad8fa: TEST EAX, EAX
0x9ad8fc: JNZ 0x009ad925
0x9ad8fe: CALL 0x00b07960
0x9ad903: TEST EAX, EAX
0x9ad905: JNZ 0x009ad925
0x9ad907: CALL 0x00b07920
0x9ad90c: TEST EAX, EAX
0x9ad90e: JZ 0x009ad923
0x9ad910: MOV EDI, 0x6e
0x9ad915: CALL 0x00acc9a0
0x9ad91a: XOR EBX, EBX
0x9ad91c: TEST EAX, EAX
0x9ad91e: SETNZ BL
0x9ad921: JMP 0x009ad925
0x9ad923: XOR EBX, EBX
0x9ad925: MOV dword ptr [0x02560040], EBX
0x9ad92b: AND R13, -0x80
0x9ad92f: TEST EBX, EBX
0x9ad931: JZ 0x009ad992
0x9ad933: LEA RSI, [RBP + -0x38]
0x9ad937: LEA RDX, [RBP + -0x40]
0x9ad93b: MOV EDI, 0x10003
0x9ad940: MOV qword ptr [RBP + -0x40], 0x0
0x9ad948: CALL 0x003d6df0
0x9ad94d: TEST EAX, EAX
0x9ad94f: JZ 0x009ad96a
0x9ad951: MOV EDX, EAX
0x9ad953: LEA RDI, [0x127c65f]
0x9ad95a: LEA RSI, [0x12af557]
0x9ad961: XOR EAX, EAX
0x9ad963: CALL 0x0025d410
0x9ad968: JMP 0x009ad992
0x9ad96a: SHR R12, 0x10
0x9ad96e: SUB R12, qword ptr [RBP + -0x38]
0x9ad972: JL 0x009ad992
0x9ad974: CMP R12, qword ptr [RBP + -0x40]
0x9ad978: JGE 0x009ad992
0x9ad97a: MOV RDI, R13
0x9ad97d: CALL 0x009e1f40
0x9ad982: MOV R13, RAX
0x9ad985: MOV R9D, 0x80010500
0x9ad98b: MOV EDI, 0x3
0x9ad990: JMP 0x009ad9e6
0x9ad992: MOV EBX, dword ptr [0x02560040]
0x9ad998: CMP EBX, -0x1
0x9ad99b: JNZ 0x009ad9d8
0x9ad99d: CALL 0x00b07940
0x9ad9a2: MOV EBX, 0x1
0x9ad9a7: TEST EAX, EAX
0x9ad9a9: JNZ 0x009ad9d2
0x9ad9ab: CALL 0x00b07960
0x9ad9b0: TEST EAX, EAX
0x9ad9b2: JNZ 0x009ad9d2
0x9ad9b4: CALL 0x00b07920
0x9ad9b9: TEST EAX, EAX
0x9ad9bb: JZ 0x009ad9d0
0x9ad9bd: MOV EDI, 0x6e
0x9ad9c2: CALL 0x00acc9a0
0x9ad9c7: XOR EBX, EBX
0x9ad9c9: TEST EAX, EAX
0x9ad9cb: SETNZ BL
0x9ad9ce: JMP 0x009ad9d2
0x9ad9d0: XOR EBX, EBX
0x9ad9d2: MOV dword ptr [0x02560040], EBX
0x9ad9d8: XOR EDI, EDI
0x9ad9da: CMP EBX, 0x1
0x9ad9dd: MOV R9D, 0x20010001
0x9ad9e3: ADC EDI, 0x1
0x9ad9e6: MOV RCX, qword ptr [RBP + -0x48]
0x9ad9ea: MOV RSI, 0x400000000000
0x9ad9f4: MOV RDX, R15
0x9ad9f7: MOV qword ptr [RSP], R14
0x9ad9fb: XOR R8D, R8D
0x9ad9fe: OR RSI, R13
0x9ada01: CALL 0x0068a090
0x9ada06: LEA RCX, [0x391c310]
0x9ada0d: MOV RCX, qword ptr [RCX]
0x9ada10: CMP RCX, qword ptr [RBP + -0x30]
0x9ada14: JNZ 0x009ada25
0x9ada16: ADD RSP, 0x28
0x9ada1a: POP RBX
0x9ada1b: POP R12
0x9ada1d: POP R13
0x9ada1f: POP R14
0x9ada21: POP R15
0x9ada23: POP RBP
0x9ada24: RET
0x9ada25: CALL 0x006fd6b0
0x9ada2a: UD2

; local helper / adjacent context (reachability below); evidence ev_dfea233ea818303c36a73306de6f6911dec267a60b6c06a45a582b429ec2240e; body [{"start": "0x9ada30", "end": "0x9adb82"}]
sub_9ada30: ; RVA 0x9ada30
0x9ada30: PUSH RBP
0x9ada31: MOV RBP, RSP
0x9ada34: PUSH R15
0x9ada36: PUSH R14
0x9ada38: PUSH R13
0x9ada3a: PUSH R12
0x9ada3c: PUSH RBX
0x9ada3d: SUB RSP, 0x28
0x9ada41: LEA RAX, [0x391c310]
0x9ada48: MOV R15, RDI
0x9ada4b: MOV R13D, ESI
0x9ada4e: MOV RAX, qword ptr [RAX]
0x9ada51: MOV qword ptr [RBP + -0x30], RAX
0x9ada55: MOV RBX, qword ptr [RDI]
0x9ada58: CMP qword ptr [RDI + 0x8], 0x0
0x9ada5d: MOV EDI, 0x21c1
0x9ada62: MOVZX EAX, word ptr [RBX + 0x20]
0x9ada66: MOV word ptr [RBP + -0x32], 0x0
0x9ada6c: MOV dword ptr [RBP + -0x38], 0x0
0x9ada73: SETNZ R14B
0x9ada77: MOV qword ptr [RBP + -0x48], RAX
0x9ada7b: MOV EAX, dword ptr [RBX + 0x198]
0x9ada81: TEST EAX, EAX
0x9ada83: CMOVNZ EDI, EAX
0x9ada86: CALL 0x005f0f70
0x9ada8b: LEA RSI, [RBP + -0x32]
0x9ada8f: LEA RDX, [RBP + -0x38]
0x9ada93: MOV EDI, R13D
0x9ada96: XOR ECX, ECX
0x9ada98: MOV dword ptr [RBP + -0x3c], EAX
0x9ada9b: CALL 0x0068e1a0
0x9adaa0: TEST EAX, EAX
0x9adaa2: JZ 0x009adabc
0x9adaa4: MOV R12D, EAX
0x9adaa7: LEA RDI, [0x1384734]
0x9adaae: LEA RSI, [0x1375eb2]
0x9adab5: MOV EDX, EAX
0x9adab7: MOV ECX, R13D
0x9adaba: JMP 0x009adaed
0x9adabc: MOV R13, qword ptr [RBP + -0x48]
0x9adac0: LEA RSI, [0x255ffd0]
0x9adac7: MOV RDI, R15
0x9adaca: CALL 0x00c08df0
0x9adacf: MOVZX R12D, word ptr [RBP + -0x32]
0x9adad4: TEST R12D, R12D
0x9adad7: JZ 0x009adb31
0x9adad9: MOV ECX, dword ptr [RBP + -0x38]
0x9adadc: LEA RDI, [0x13079f2]
0x9adae3: LEA RSI, [0x13b0051]
0x9adaea: MOV EDX, R12D
0x9adaed: XOR EAX, EAX
0x9adaef: CALL 0x0025d410
0x9adaf4: MOV RAX, qword ptr [RBX + 0x128]
0x9adafb: MOV RDI, RBX
0x9adafe: MOV ESI, R12D
0x9adb01: MOV qword ptr [RBX + 0x50], RAX
0x9adb05: CALL 0x009acd40
0x9adb0a: MOV EDI, dword ptr [RBP + -0x3c]
0x9adb0d: CALL 0x005f0f70
0x9adb12: LEA RAX, [0x391c310]
0x9adb19: MOV RAX, qword ptr [RAX]
0x9adb1c: CMP RAX, qword ptr [RBP + -0x30]
0x9adb20: JNZ 0x009adb7c
0x9adb22: ADD RSP, 0x28
0x9adb26: POP RBX
0x9adb27: POP R12
0x9adb29: POP R13
0x9adb2b: POP R14
0x9adb2d: POP R15
0x9adb2f: POP RBP
0x9adb30: RET
0x9adb31: MOV RDX, qword ptr [RBX + 0x128]
0x9adb38: MOV EAX, 0x10000
0x9adb3d: SUB RAX, R13
0x9adb40: MOV RCX, RDX
0x9adb43: SUB RCX, RAX
0x9adb46: JBE 0x009adb67
0x9adb48: XOR ESI, ESI
0x9adb4a: MOV SIL, R14B
0x9adb4d: MOV RDI, RBX
0x9adb50: MOV qword ptr [RBX + 0x130], RAX
0x9adb57: MOV qword ptr [RBX + 0x50], RCX
0x9adb5b: TEST CX, CX
0x9adb5e: JZ 0x009adb75
0x9adb60: CALL 0x009adb90
0x9adb65: JMP 0x009adb0a
0x9adb67: MOV qword ptr [RBX + 0x130], RDX
0x9adb6e: XOR EAX, EAX
0x9adb70: XOR R12D, R12D
0x9adb73: JMP 0x009adafb
0x9adb75: CALL 0x009add90
0x9adb7a: JMP 0x009adb0a
0x9adb7c: CALL 0x006fd6b0
0x9adb81: UD2

; local helper / adjacent context (reachability below); evidence ev_a543d2869603ad2cda3ecb485c3835915d6dca7471c5b6017218ad188c611ab7; body [{"start": "0x9adb90", "end": "0x9add81"}]
sub_9adb90: ; RVA 0x9adb90
0x9adb90: PUSH RBP
0x9adb91: MOV RBP, RSP
0x9adb94: PUSH R15
0x9adb96: PUSH R14
0x9adb98: PUSH R13
0x9adb9a: PUSH R12
0x9adb9c: PUSH RBX
0x9adb9d: SUB RSP, 0x18
0x9adba1: LEA R13, [0x391c310]
0x9adba8: MOV R15D, ESI
0x9adbab: MOV RBX, RDI
0x9adbae: MOV RAX, qword ptr [R13]
0x9adbb2: MOV qword ptr [RBP + -0x30], RAX
0x9adbb6: MOV RDX, qword ptr [RDI + 0x20]
0x9adbba: MOV RCX, qword ptr [RDI + 0x130]
0x9adbc1: TEST RCX, RCX
0x9adbc4: JZ 0x009adbd1
0x9adbc6: LEA EAX, [RCX + RDX*0x1]
0x9adbc9: MOVZX EAX, AX
0x9adbcc: TEST RAX, RAX
0x9adbcf: JZ 0x009adbed
0x9adbd1: LEA RDI, [0x1394bd8]
0x9adbd8: LEA RSI, [0x1394c0e]
0x9adbdf: XOR EAX, EAX
0x9adbe1: CALL 0x0025d410
0x9adbe6: MOV RCX, qword ptr [RBX + 0x130]
0x9adbed: MOV RDX, qword ptr [RBX + 0x128]
0x9adbf4: CMP RDX, RCX
0x9adbf7: JLE 0x009adc71
0x9adbf9: CMP DX, CX
0x9adbfc: JNZ 0x009adc13
0x9adbfe: LEA RDI, [0x13aa80b]
0x9adc05: LEA RSI, [0x1394c0e]
0x9adc0c: XOR EAX, EAX
0x9adc0e: CALL 0x0025d410
0x9adc13: LEA RSI, [0x255ffd0]
0x9adc1a: MOV EDI, 0x20
0x9adc1f: MOV EDX, 0x2
0x9adc24: CALL 0x00c08b50
0x9adc29: MOV R14, RAX
0x9adc2c: MOV qword ptr [RAX], RBX
0x9adc2f: TEST R15D, R15D
0x9adc32: JZ 0x009adcba
0x9adc38: MOV R12, qword ptr [RBX + 0x130]
0x9adc3f: ADD R12, qword ptr [RBX + 0x20]
0x9adc43: MOV R15, R14
0x9adc46: ADD R15, 0x10
0x9adc4a: MOV RDI, R12
0x9adc4d: CALL 0x003d6f60
0x9adc52: MOV dword ptr [R14 + 0x14], EAX
0x9adc56: CMP EAX, -0x1
0x9adc59: JZ 0x009adc6b
0x9adc5b: SHR R12, 0x10
0x9adc5f: MOV qword ptr [R14 + 0x18], R12
0x9adc63: MOV dword ptr [R14 + 0x10], 0xc
0x9adc6b: MOV qword ptr [R14 + 0x8], R15
0x9adc6f: JMP 0x009adccd
0x9adc71: LEA RDI, [0x13aa80b]
0x9adc78: LEA RSI, [0x1394c0e]
0x9adc7f: XOR EAX, EAX
0x9adc81: CALL 0x0025d410
0x9adc86: MOV RAX, qword ptr [RBX + 0x128]
0x9adc8d: MOV qword ptr [RBX + 0x50], RAX
0x9adc91: MOV RAX, qword ptr [R13]
0x9adc95: CMP RAX, qword ptr [RBP + -0x30]
0x9adc99: JNZ 0x009add7b
0x9adc9f: MOV RDI, RBX
0x9adca2: MOV ESI, 0x16
0x9adca7: ADD RSP, 0x18
0x9adcab: POP RBX
0x9adcac: POP R12
0x9adcae: POP R13
0x9adcb0: POP R14
0x9adcb2: POP R15
0x9adcb4: POP RBP
0x9adcb5: JMP 0x009acd40
0x9adcba: MOV qword ptr [R14 + 0x8], 0x0
0x9adcc2: XOR R15D, R15D
0x9adcc5: MOV dword ptr [R14 + 0x14], 0xffffffff
0x9adccd: LEA RDX, [RBP + -0x34]
0x9adcd1: MOV RDI, RBX
0x9adcd4: MOV RSI, R15
0x9adcd7: CALL 0x009acde0
0x9adcdc: TEST EAX, EAX
0x9adcde: JZ 0x009add21
0x9adce0: LEA RDI, [0x134550c]
0x9adce7: LEA RSI, [0x1394c0e]
0x9adcee: MOV EDX, EAX
0x9adcf0: MOV R15D, EAX
0x9adcf3: XOR EAX, EAX
0x9adcf5: CALL 0x0025d410
0x9adcfa: LEA RSI, [0x255ffd0]
0x9add01: MOV RDI, R14
0x9add04: CALL 0x00c08df0
0x9add09: MOV RAX, qword ptr [RBX + 0x128]
0x9add10: MOV RDI, RBX
0x9add13: MOV ESI, R15D
0x9add16: MOV qword ptr [RBX + 0x50], RAX
0x9add1a: CALL 0x009acd40
0x9add1f: JMP 0x009add62
0x9add21: LEA RDI, [0x26a598]
0x9add28: LEA RDX, [RBP + -0x34]
0x9add2c: MOV RSI, R14
0x9add2f: MOV ECX, 0x1
0x9add34: CALL 0x005b01d0
0x9add39: TEST EAX, EAX
0x9add3b: JZ 0x009add62
0x9add3d: MOV ECX, dword ptr [RBP + -0x34]
0x9add40: MOV EDX, EAX
0x9add42: LEA RDI, [0x12d95db]
0x9add49: LEA RSI, [0x1394c0e]
0x9add50: XOR EAX, EAX
0x9add52: CALL 0x0025d410
0x9add57: MOV ESI, dword ptr [RBP + -0x34]
0x9add5a: MOV RDI, R14
0x9add5d: CALL 0x009adeb0
0x9add62: MOV RAX, qword ptr [R13]
0x9add66: CMP RAX, qword ptr [RBP + -0x30]
0x9add6a: JNZ 0x009add7b
0x9add6c: ADD RSP, 0x18
0x9add70: POP RBX
0x9add71: POP R12
0x9add73: POP R13
0x9add75: POP R14
0x9add77: POP R15
0x9add79: POP RBP
0x9add7a: RET
0x9add7b: CALL 0x006fd6b0
0x9add80: UD2

; local helper / adjacent context (reachability below); evidence ev_bf68724c716f17815ceed775ece343c17656e4ed344fa5da5f0d80155ae05bee; body [{"start": "0x9add90", "end": "0x9adeaf"}]
sub_9add90: ; RVA 0x9add90
0x9add90: PUSH RBP
0x9add91: MOV RBP, RSP
0x9add94: PUSH R15
0x9add96: PUSH R14
0x9add98: PUSH R12
0x9add9a: PUSH RBX
0x9add9b: MOV RDX, qword ptr [RDI + 0x20]
0x9add9f: MOV RCX, qword ptr [RDI + 0x130]
0x9adda6: MOV R14D, ESI
0x9adda9: MOV RBX, RDI
0x9addac: TEST RCX, RCX
0x9addaf: JZ 0x009addbc
0x9addb1: LEA EAX, [RCX + RDX*0x1]
0x9addb4: MOVZX EAX, AX
0x9addb7: TEST RAX, RAX
0x9addba: JZ 0x009addd8
0x9addbc: LEA RDI, [0x1394bd8]
0x9addc3: LEA RSI, [0x13613bd]
0x9addca: XOR EAX, EAX
0x9addcc: CALL 0x0025d410
0x9addd1: MOV RCX, qword ptr [RBX + 0x130]
0x9addd8: MOV RDX, qword ptr [RBX + 0x128]
0x9adddf: CMP RDX, RCX
0x9adde2: JLE 0x009ade58
0x9adde4: CMP DX, CX
0x9adde7: JZ 0x009addfe
0x9adde9: LEA RDI, [0x13aa80b]
0x9addf0: LEA RSI, [0x13613bd]
0x9addf7: XOR EAX, EAX
0x9addf9: CALL 0x0025d410
0x9addfe: LEA RSI, [0x255ffd0]
0x9ade05: MOV EDI, 0x20
0x9ade0a: MOV EDX, 0x2
0x9ade0f: CALL 0x00c08b50
0x9ade14: MOV R15, RAX
0x9ade17: MOV qword ptr [RAX], RBX
0x9ade1a: TEST R14D, R14D
0x9ade1d: JZ 0x009ade8d
0x9ade1f: MOV R14, qword ptr [RBX + 0x130]
0x9ade26: ADD R14, qword ptr [RBX + 0x20]
0x9ade2a: MOV R12, R15
0x9ade2d: ADD R12, 0x10
0x9ade31: MOV RDI, R14
0x9ade34: CALL 0x003d6f60
0x9ade39: MOV dword ptr [R15 + 0x14], EAX
0x9ade3d: CMP EAX, -0x1
0x9ade40: JZ 0x009ade52
0x9ade42: SHR R14, 0x10
0x9ade46: MOV qword ptr [R15 + 0x18], R14
0x9ade4a: MOV dword ptr [R15 + 0x10], 0x8c
0x9ade52: MOV qword ptr [R15 + 0x8], R12
0x9ade56: JMP 0x009ade9d
0x9ade58: LEA RDI, [0x13aa80b]
0x9ade5f: LEA RSI, [0x13613bd]
0x9ade66: XOR EAX, EAX
0x9ade68: CALL 0x0025d410
0x9ade6d: MOV RAX, qword ptr [RBX + 0x128]
0x9ade74: MOV RDI, RBX
0x9ade77: MOV ESI, 0x16
0x9ade7c: MOV qword ptr [RBX + 0x50], RAX
0x9ade80: POP RBX
0x9ade81: POP R12
0x9ade83: POP R14
0x9ade85: POP R15
0x9ade87: POP RBP
0x9ade88: JMP 0x009acd40
0x9ade8d: MOV qword ptr [R15 + 0x8], 0x0
0x9ade95: MOV dword ptr [R15 + 0x14], 0xffffffff
0x9ade9d: MOV RDI, RBX
0x9adea0: MOV RSI, R15
0x9adea3: POP RBX
0x9adea4: POP R12
0x9adea6: POP R14
0x9adea8: POP R15
0x9adeaa: POP RBP
0x9adeab: JMP 0x009ae010

; local helper / adjacent context (reachability below); evidence ev_dcf48bb156bcfe2bf28ccbf764da4fcc54381238080f793ff4501498b3c60b5f; body [{"start": "0x9adeb0", "end": "0x9adf3e"}]
sub_9adeb0: ; RVA 0x9adeb0
0x9adeb0: PUSH RBP
0x9adeb1: MOV RBP, RSP
0x9adeb4: PUSH R15
0x9adeb6: PUSH R14
0x9adeb8: PUSH R13
0x9adeba: PUSH R12
0x9adebc: PUSH RBX
0x9adebd: SUB RSP, 0x18
0x9adec1: LEA RAX, [0x391c310]
0x9adec8: MOV R15, RDI
0x9adecb: MOV R13D, ESI
0x9adece: MOV RAX, qword ptr [RAX]
0x9aded1: MOV qword ptr [RBP + -0x30], RAX
0x9aded5: MOV R14, qword ptr [RDI]
0x9aded8: MOV EDI, 0x21c1
0x9adedd: MOV EAX, dword ptr [R14 + 0x198]
0x9adee4: TEST EAX, EAX
0x9adee6: CMOVNZ EDI, EAX
0x9adee9: CALL 0x005f0f70
0x9adeee: LEA RSI, [RBP + -0x32]
0x9adef2: LEA RDX, [RBP + -0x38]
0x9adef6: MOV EDI, R13D
0x9adef9: XOR ECX, ECX
0x9adefb: MOV EBX, EAX
0x9adefd: MOV word ptr [RBP + -0x32], 0x0
0x9adf03: MOV dword ptr [RBP + -0x38], 0x0
0x9adf0a: CALL 0x0068e1a0
0x9adf0f: TEST EAX, EAX
0x9adf11: JZ 0x009adf5a
0x9adf13: LEA RDI, [0x1384734]
0x9adf1a: LEA RSI, [0x132c5a6]
0x9adf21: MOV EDX, EAX
0x9adf23: MOV ECX, R13D
0x9adf26: MOV R12D, EAX
0x9adf29: XOR EAX, EAX
0x9adf2b: CALL 0x0025d410
0x9adf30: LEA RSI, [0x255ffd0]
0x9adf37: MOV RDI, R15
0x9adf3a: CALL 0x00c08df0

; local helper / adjacent context (reachability below); evidence ev_9f715f53ca8e7945dcf5dd090a09697d620766198f5ec9c1ad147fd5676b3ea0; body [{"start": "0x258ff0", "end": "0x259031"}]
zero_fill_helper: ; RVA 0x258ff0
0x258ff0: PUSH RBP
0x258ff1: MOV RBP, RSP
0x258ff4: MOV R10, RDI
0x258ff7: ADD R10, RSI
0x258ffa: JC 0x00259015
0x258ffc: CMP R10, RSP
0x258fff: JBE 0x0025901a
0x259001: LEA R10, [RBP + 0x10]
0x259005: CMP RDI, R10
0x259008: JGE 0x0025901a
0x25900a: MOV RDI, RDI
0x25900d: MOV RSI, RSI
0x259010: CALL 0x00258fd0
0x259015: CALL 0x00258fe0
0x25901a: MOV RCX, RSI
0x25901d: XOR EAX, EAX
0x25901f: SHR RCX, 0x3
0x259023: CLD
0x259024: STOSQ.REP RDI
0x259027: MOV RCX, RSI
0x25902a: AND RCX, 0x7
0x25902e: STOSB.REP RDI
0x259030: POP RBP
0x259031: RET

; local helper / adjacent context (reachability below); evidence ev_71486184be245b984abbb9be576981c38f613a7db64a834e00ab1b4e60ea2113; body [{"start": "0x2591d0", "end": "0x259258"}, {"start": "0x259260", "end": "0x25927f"}]
copyout_candidate: ; RVA 0x2591d0
0x2591d0: PUSH RBP
0x2591d1: MOV RBP, RSP
0x2591d4: MOV RAX, qword ptr GS:[0x20]
0x2591dd: LEA R11, [0x259260]
0x2591e4: MOV qword ptr [RAX + 0x108], R11
0x2591eb: TEST RDX, RDX
0x2591ee: JZ 0x00259245
0x2591f0: MOV RAX, RSI
0x2591f3: ADD RAX, RDX
0x2591f6: JC 0x00259260
0x2591f8: MOV RCX, 0x800000000000
0x259202: CMP RAX, RCX
0x259205: JA 0x00259260
0x259207: MOV RAX, qword ptr GS:[0x0]
0x259210: MOV RAX, qword ptr [RAX + 0x8]
0x259214: CMP byte ptr [RAX + 0x591], 0x0
0x25921b: JNZ 0x00259260
0x25921d: MOV RAX, 0x7fffffffffff
0x259227: AND RSI, RAX
0x25922a: XCHG RDI, RSI
0x25922d: MOV RCX, RDX
0x259230: SHR RCX, 0x3
0x259234: CLD
0x259235: STAC
0x259238: MOVSQ.REP RDI, RSI
0x25923b: MOV CL, DL
0x25923d: AND CL, 0x7
0x259240: MOVSB.REP RDI, RSI
0x259242: CLAC
0x259245: XOR EAX, EAX
0x259247: MOV RDX, qword ptr GS:[0x20]
0x259250: MOV qword ptr [RDX + 0x108], RAX
0x259257: POP RBP
0x259258: RET
0x259260: CLAC
0x259263: MOV RDX, qword ptr GS:[0x20]
0x25926c: MOV qword ptr [RDX + 0x108], 0x0
0x259277: MOV RAX, 0xe
0x25927e: POP RBP
0x25927f: RET

; local helper / adjacent context (reachability below); evidence ev_5d07d221cf60ecec155e82677b4906065788d1c1d1f1444ffffeccc565bd92ad; body [{"start": "0x259280", "end": "0x25932f"}]
copyin_candidate: ; RVA 0x259280
0x259280: PUSH RBP
0x259281: MOV RBP, RSP
0x259284: MOV R10, RSI
0x259287: ADD R10, RDX
0x25928a: JC 0x002592a5
0x25928c: CMP R10, RSP
0x25928f: JBE 0x002592aa
0x259291: LEA R10, [RBP + 0x10]
0x259295: CMP RSI, R10
0x259298: JGE 0x002592aa
0x25929a: MOV RDI, RSI
0x25929d: MOV RSI, RDX
0x2592a0: CALL 0x00258fd0
0x2592a5: CALL 0x00258fe0
0x2592aa: MOV RAX, qword ptr GS:[0x20]
0x2592b3: LEA R11, [0x259340]
0x2592ba: MOV qword ptr [RAX + 0x108], R11
0x2592c1: TEST RDX, RDX
0x2592c4: JZ 0x0025931d
0x2592c6: MOV RAX, RDI
0x2592c9: ADD RAX, RDX
0x2592cc: JC 0x00259340
0x2592ce: MOV RCX, 0x800000000000
0x2592d8: CMP RAX, RCX
0x2592db: JA 0x00259340
0x2592dd: MOV RAX, qword ptr GS:[0x0]
0x2592e6: MOV RAX, qword ptr [RAX + 0x8]
0x2592ea: CMP byte ptr [RAX + 0x591], 0x0
0x2592f1: JNZ 0x00259340
0x2592f3: MOV RAX, 0x7fffffffffff
0x2592fd: AND RDI, RAX
0x259300: XCHG RDI, RSI
0x259303: MOV RCX, RDX
0x259306: MOV AL, CL
0x259308: SHR RCX, 0x3
0x25930c: CLD
0x25930d: STAC
0x259310: MOVSQ.REP RDI, RSI
0x259313: MOV CL, AL
0x259315: AND CL, 0x7
0x259318: MOVSB.REP RDI, RSI
0x25931a: CLAC
0x25931d: XOR EAX, EAX
0x25931f: MOV RDX, qword ptr GS:[0x20]
0x259328: MOV qword ptr [RDX + 0x108], RAX
0x25932f: POP RBP

; ===== SUPPLEMENTAL FULL CARRIER GNU objdump: handler_657.body.bin; not REA output =====

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_657.body.bin:     file format binary


Disassembly of section .data:

00000000009a9f40 <.data>:
  9a9f40:	55                   	push   rbp
  9a9f41:	48 89 e5             	mov    rbp,rsp
  9a9f44:	41 57                	push   r15
  9a9f46:	41 56                	push   r14
  9a9f48:	41 55                	push   r13
  9a9f4a:	41 54                	push   r12
  9a9f4c:	53                   	push   rbx
  9a9f4d:	48 83 ec 68          	sub    rsp,0x68
  9a9f51:	48 8d 0d b8 23 f7 02 	lea    rcx,[rip+0x2f723b8]        # 0x391c310
  9a9f58:	41 bc 16 00 00 00    	mov    r12d,0x16
  9a9f5e:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  9a9f61:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9a9f65:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  9a9f69:	48 8b 1e             	mov    rbx,QWORD PTR [rsi]
  9a9f6c:	74 40                	je     0x9a9fae
  9a9f6e:	49 89 df             	mov    r15,rbx
  9a9f71:	48 8b 7e 10          	mov    rdi,QWORD PTR [rsi+0x10]
  9a9f75:	48 85 ff             	test   rdi,rdi
  9a9f78:	74 15                	je     0x9a9f8f
  9a9f7a:	49 29 df             	sub    r15,rbx
  9a9f7d:	48 89 cb             	mov    rbx,rcx
  9a9f80:	49 c1 ef 05          	shr    r15,0x5
  9a9f84:	44 89 fe             	mov    esi,r15d
  9a9f87:	e8 04 f8 8a ff       	call   0x259790
  9a9f8c:	48 89 d9             	mov    rcx,rbx
  9a9f8f:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  9a9f92:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9a9f96:	0f 85 9b 02 00 00    	jne    0x9aa237
  9a9f9c:	44 89 e0             	mov    eax,r12d
  9a9f9f:	48 83 c4 68          	add    rsp,0x68
  9a9fa3:	5b                   	pop    rbx
  9a9fa4:	41 5c                	pop    r12
  9a9fa6:	41 5d                	pop    r13
  9a9fa8:	41 5e                	pop    r14
  9a9faa:	41 5f                	pop    r15
  9a9fac:	5d                   	pop    rbp
  9a9fad:	c3                   	ret
  9a9fae:	4c 63 6e 08          	movsxd r13,DWORD PTR [rsi+0x8]
  9a9fb2:	49 89 df             	mov    r15,rbx
  9a9fb5:	4d 85 ed             	test   r13,r13
  9a9fb8:	78 b7                	js     0x9a9f71
  9a9fba:	45 85 ed             	test   r13d,r13d
  9a9fbd:	0f 84 f6 01 00 00    	je     0x9aa1b9
  9a9fc3:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  9a9fc7:	48 8d 0d 6f df 9e 00 	lea    rcx,[rip+0x9edf6f]        # 0x1397f3d
  9a9fce:	31 d2                	xor    edx,edx
  9a9fd0:	4c 8b b0 00 02 00 00 	mov    r14,QWORD PTR [rax+0x200]
  9a9fd7:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9a9fde:	00 00 
  9a9fe0:	48 89 7d 80          	mov    QWORD PTR [rbp-0x80],rdi
  9a9fe4:	48 89 b5 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rsi
  9a9feb:	48 89 c7             	mov    rdi,rax
  9a9fee:	48 89 ce             	mov    rsi,rcx
  9a9ff1:	e8 ea 03 27 00       	call   0xc1a3e0
  9a9ff6:	48 8d 75 a8          	lea    rsi,[rbp-0x58]
  9a9ffa:	ba 20 00 00 00       	mov    edx,0x20
  9a9fff:	48 89 df             	mov    rdi,rbx
  9aa002:	e8 79 f2 8a ff       	call   0x259280
  9aa007:	48 8d 0d 02 23 f7 02 	lea    rcx,[rip+0x2f72302]        # 0x391c310
  9aa00e:	48 8b b5 78 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x88]
  9aa015:	41 89 c4             	mov    r12d,eax
  9aa018:	49 89 df             	mov    r15,rbx
  9aa01b:	85 c0                	test   eax,eax
  9aa01d:	0f 85 4e ff ff ff    	jne    0x9a9f71
  9aa023:	4c 89 f7             	mov    rdi,r14
  9aa026:	31 f6                	xor    esi,esi
  9aa028:	31 d2                	xor    edx,edx
  9aa02a:	e8 f1 c7 91 ff       	call   0x2c6820
  9aa02f:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  9aa033:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
  9aa037:	4c 89 f7             	mov    rdi,r14
  9aa03a:	e8 01 cc 91 ff       	call   0x2c6c40
  9aa03f:	41 bc 16 00 00 00    	mov    r12d,0x16
  9aa045:	4c 89 75 98          	mov    QWORD PTR [rbp-0x68],r14
  9aa049:	85 c0                	test   eax,eax
  9aa04b:	0f 84 70 01 00 00    	je     0x9aa1c1
  9aa051:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
  9aa055:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  9aa059:	f6 40 60 02          	test   BYTE PTR [rax+0x60],0x2
  9aa05d:	0f 85 62 01 00 00    	jne    0x9aa1c5
  9aa063:	4c 8b 70 50          	mov    r14,QWORD PTR [rax+0x50]
  9aa067:	4d 85 f6             	test   r14,r14
  9aa06a:	0f 84 55 01 00 00    	je     0x9aa1c5
  9aa070:	41 80 be 9d 00 00 00 	cmp    BYTE PTR [r14+0x9d],0xb
  9aa077:	0b 
  9aa078:	49 89 df             	mov    r15,rbx
  9aa07b:	0f 85 47 01 00 00    	jne    0x9aa1c8
  9aa081:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  9aa085:	f0 83 80 c4 01 00 00 	lock add DWORD PTR [rax+0x1c4],0x1
  9aa08c:	01 
  9aa08d:	49 c1 e5 05          	shl    r13,0x5
  9aa091:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
  9aa095:	4d 89 ef             	mov    r15,r13
  9aa098:	49 89 dd             	mov    r13,rbx
  9aa09b:	49 01 df             	add    r15,rbx
  9aa09e:	48 8b 50 20          	mov    rdx,QWORD PTR [rax+0x20]
  9aa0a2:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  9aa0a6:	48 89 55 88          	mov    QWORD PTR [rbp-0x78],rdx
  9aa0aa:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  9aa0ae:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
  9aa0b1:	49 83 c5 20          	add    r13,0x20
  9aa0b5:	4c 89 6d c8          	mov    QWORD PTR [rbp-0x38],r13
  9aa0b9:	ff c8                	dec    eax
  9aa0bb:	83 f8 04             	cmp    eax,0x4
  9aa0be:	0f 87 64 01 00 00    	ja     0x9aa228
  9aa0c4:	48 8d 0d 65 3a f2 00 	lea    rcx,[rip+0xf23a65]        # 0x18cdb30
  9aa0cb:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
  9aa0cf:	48 01 c8             	add    rax,rcx
  9aa0d2:	ff e0                	jmp    rax
  9aa0d4:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa0d8:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  9aa0dc:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9aa0e0:	4c 89 f6             	mov    rsi,r14
  9aa0e3:	4c 8d 45 a8          	lea    r8,[rbp-0x58]
  9aa0e7:	e8 64 01 00 00       	call   0x9aa250
  9aa0ec:	eb 76                	jmp    0x9aa164
  9aa0ee:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa0f2:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  9aa0f6:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9aa0fa:	4c 89 f6             	mov    rsi,r14
  9aa0fd:	4c 8d 45 a8          	lea    r8,[rbp-0x58]
  9aa101:	e8 5a 10 00 00       	call   0x9ab160
  9aa106:	eb 5c                	jmp    0x9aa164
  9aa108:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa10c:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  9aa110:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9aa114:	4c 89 f6             	mov    rsi,r14
  9aa117:	4c 8d 45 a8          	lea    r8,[rbp-0x58]
  9aa11b:	e8 40 07 00 00       	call   0x9aa860
  9aa120:	eb 42                	jmp    0x9aa164
  9aa122:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa126:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  9aa12a:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9aa12e:	4c 89 f6             	mov    rsi,r14
  9aa131:	4c 8d 45 a8          	lea    r8,[rbp-0x58]
  9aa135:	4c 8d 4d c8          	lea    r9,[rbp-0x38]
  9aa139:	4c 89 3c 24          	mov    QWORD PTR [rsp],r15
  9aa13d:	e8 8e 07 00 00       	call   0x9aa8d0
  9aa142:	eb 20                	jmp    0x9aa164
  9aa144:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa148:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  9aa14c:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9aa150:	4c 89 f6             	mov    rsi,r14
  9aa153:	4c 8d 45 a8          	lea    r8,[rbp-0x58]
  9aa157:	4c 8d 4d c8          	lea    r9,[rbp-0x38]
  9aa15b:	4c 89 3c 24          	mov    QWORD PTR [rsp],r15
  9aa15f:	e8 1c 02 00 00       	call   0x9aa380
  9aa164:	4c 8b 6d c8          	mov    r13,QWORD PTR [rbp-0x38]
  9aa168:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  9aa16c:	41 89 c4             	mov    r12d,eax
  9aa16f:	85 c0                	test   eax,eax
  9aa171:	0f 85 b7 00 00 00    	jne    0x9aa22e
  9aa177:	4d 39 fd             	cmp    r13,r15
  9aa17a:	0f 84 a3 00 00 00    	je     0x9aa223
  9aa180:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  9aa187:	00 00 
  9aa189:	48 8d 35 ad dd 9e 00 	lea    rsi,[rip+0x9eddad]        # 0x1397f3d
  9aa190:	31 d2                	xor    edx,edx
  9aa192:	e8 49 02 27 00       	call   0xc1a3e0
  9aa197:	ba 20 00 00 00       	mov    edx,0x20
  9aa19c:	4c 89 ef             	mov    rdi,r13
  9aa19f:	48 8d 75 a8          	lea    rsi,[rbp-0x58]
  9aa1a3:	e8 d8 f0 8a ff       	call   0x259280
  9aa1a8:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  9aa1ac:	85 c0                	test   eax,eax
  9aa1ae:	0f 84 fa fe ff ff    	je     0x9aa0ae
  9aa1b4:	41 89 c4             	mov    r12d,eax
  9aa1b7:	eb 79                	jmp    0x9aa232
  9aa1b9:	45 31 e4             	xor    r12d,r12d
  9aa1bc:	e9 ad fd ff ff       	jmp    0x9a9f6e
  9aa1c1:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  9aa1c5:	49 89 df             	mov    r15,rbx
  9aa1c8:	80 b9 17 01 00 00 00 	cmp    BYTE PTR [rcx+0x117],0x0
  9aa1cf:	74 32                	je     0x9aa203
  9aa1d1:	48 8d 05 10 c1 0e 01 	lea    rax,[rip+0x10ec110]        # 0x1a962e8
  9aa1d8:	c6 81 17 01 00 00 00 	mov    BYTE PTR [rcx+0x117],0x0
  9aa1df:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9aa1e2:	4c 8b 68 40          	mov    r13,QWORD PTR [rax+0x40]
  9aa1e6:	48 8d 05 fb 6a 8b ff 	lea    rax,[rip+0xffffffffff8b6afb]        # 0x260ce8
  9aa1ed:	4c 29 e8             	sub    rax,r13
  9aa1f0:	48 c1 c8 03          	ror    rax,0x3
  9aa1f4:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  9aa1fa:	77 42                	ja     0x9aa23e
  9aa1fc:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa200:	41 ff d5             	call   r13
  9aa203:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  9aa207:	31 f6                	xor    esi,esi
  9aa209:	31 d2                	xor    edx,edx
  9aa20b:	e8 60 c6 91 ff       	call   0x2c6870
  9aa210:	48 8b b5 78 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x88]
  9aa217:	48 8d 0d f2 20 f7 02 	lea    rcx,[rip+0x2f720f2]        # 0x391c310
  9aa21e:	e9 4e fd ff ff       	jmp    0x9a9f71
  9aa223:	45 31 e4             	xor    r12d,r12d
  9aa226:	eb a0                	jmp    0x9aa1c8
  9aa228:	41 bc 2d 00 00 00    	mov    r12d,0x2d
  9aa22e:	49 83 c5 e0          	add    r13,0xffffffffffffffe0
  9aa232:	4d 89 ef             	mov    r15,r13
  9aa235:	eb 91                	jmp    0x9aa1c8
  9aa237:	e8 74 34 d5 ff       	call   0x6fd6b0
  9aa23c:	0f 0b                	ud2
  9aa23e:	48 8d 3d 3b 5c bb 01 	lea    rdi,[rip+0x1bb5c3b]        # 0x255fe80
  9aa245:	4c 89 ee             	mov    rsi,r13
  9aa248:	e8 73 56 aa ff       	call   0x44f8c0
  9aa24d:	eb ad                	jmp    0x9aa1fc
  9aa24f:	90                   	nop
  9aa250:	55                   	push   rbp
  9aa251:	48 89 e5             	mov    rbp,rsp
  9aa254:	41 57                	push   r15
  9aa256:	41 56                	push   r14
  9aa258:	41 55                	push   r13
  9aa25a:	41 54                	push   r12
  9aa25c:	53                   	push   rbx
  9aa25d:	48 83 ec 18          	sub    rsp,0x18
  9aa261:	41 83 78 04 00       	cmp    DWORD PTR [r8+0x4],0x0
  9aa266:	b8 16 00 00 00       	mov    eax,0x16
  9aa26b:	0f 85 ee 00 00 00    	jne    0x9aa35f
  9aa271:	49 8b 58 08          	mov    rbx,QWORD PTR [r8+0x8]
  9aa275:	44 0f b7 cb          	movzx  r9d,bx
  9aa279:	4d 85 c9             	test   r9,r9
  9aa27c:	0f 85 dd 00 00 00    	jne    0x9aa35f
  9aa282:	4d 8b 78 10          	mov    r15,QWORD PTR [r8+0x10]
  9aa286:	45 0f b7 cf          	movzx  r9d,r15w
  9aa28a:	4d 85 c9             	test   r9,r9
  9aa28d:	0f 85 cc 00 00 00    	jne    0x9aa35f
  9aa293:	48 39 da             	cmp    rdx,rbx
  9aa296:	0f 87 c3 00 00 00    	ja     0x9aa35f
  9aa29c:	48 39 d9             	cmp    rcx,rbx
  9aa29f:	0f 86 ba 00 00 00    	jbe    0x9aa35f
  9aa2a5:	48 29 d9             	sub    rcx,rbx
  9aa2a8:	4c 39 f9             	cmp    rcx,r15
  9aa2ab:	0f 82 ae 00 00 00    	jb     0x9aa35f
  9aa2b1:	45 0f b6 70 18       	movzx  r14d,BYTE PTR [r8+0x18]
  9aa2b6:	44 89 f1             	mov    ecx,r14d
  9aa2b9:	83 e1 cc             	and    ecx,0xffffffcc
  9aa2bc:	0f 85 9d 00 00 00    	jne    0x9aa35f
  9aa2c2:	45 0f b6 40 19       	movzx  r8d,BYTE PTR [r8+0x19]
  9aa2c7:	0f b6 8f 44 02 00 00 	movzx  ecx,BYTE PTR [rdi+0x244]
  9aa2ce:	41 83 f8 0a          	cmp    r8d,0xa
  9aa2d2:	77 57                	ja     0x9aa32b
  9aa2d4:	41 b9 09 04 00 00    	mov    r9d,0x409
  9aa2da:	45 0f a3 c1          	bt     r9d,r8d
  9aa2de:	73 4b                	jae    0x9aa32b
  9aa2e0:	f6 c1 02             	test   cl,0x2
  9aa2e3:	74 19                	je     0x9aa2fe
  9aa2e5:	41 83 f8 0a          	cmp    r8d,0xa
  9aa2e9:	0f 94 c0             	sete   al
  9aa2ec:	41 f6 c6 22          	test   r14b,0x22
  9aa2f0:	0f 95 c1             	setne  cl
  9aa2f3:	84 c8                	test   al,cl
  9aa2f5:	74 43                	je     0x9aa33a
  9aa2f7:	b8 0d 00 00 00       	mov    eax,0xd
  9aa2fc:	eb 61                	jmp    0x9aa35f
  9aa2fe:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  9aa302:	44 89 c7             	mov    edi,r8d
  9aa305:	49 89 d5             	mov    r13,rdx
  9aa308:	49 89 f4             	mov    r12,rsi
  9aa30b:	e8 00 29 00 00       	call   0x9acc10
  9aa310:	31 c9                	xor    ecx,ecx
  9aa312:	85 c0                	test   eax,eax
  9aa314:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  9aa318:	4c 89 e6             	mov    rsi,r12
  9aa31b:	4c 89 ea             	mov    rdx,r13
  9aa31e:	0f 94 c1             	sete   cl
  9aa321:	44 8d 04 8d 0f 00 00 	lea    r8d,[rcx*4+0xf]
  9aa328:	00 
  9aa329:	eb 0f                	jmp    0x9aa33a
  9aa32b:	45 8d 48 eb          	lea    r9d,[r8-0x15]
  9aa32f:	41 83 f9 f6          	cmp    r9d,0xfffffff6
  9aa333:	72 2a                	jb     0x9aa35f
  9aa335:	80 e1 02             	and    cl,0x2
  9aa338:	75 25                	jne    0x9aa35f
  9aa33a:	4d 85 ff             	test   r15,r15
  9aa33d:	74 2f                	je     0x9aa36e
  9aa33f:	48 29 d3             	sub    rbx,rdx
  9aa342:	44 89 04 24          	mov    DWORD PTR [rsp],r8d
  9aa346:	45 89 f1             	mov    r9d,r14d
  9aa349:	48 89 d9             	mov    rcx,rbx
  9aa34c:	4c 01 fb             	add    rbx,r15
  9aa34f:	48 c1 eb 10          	shr    rbx,0x10
  9aa353:	48 c1 e9 10          	shr    rcx,0x10
  9aa357:	41 89 d8             	mov    r8d,ebx
  9aa35a:	e8 41 f4 ff ff       	call   0x9a97a0
  9aa35f:	48 83 c4 18          	add    rsp,0x18
  9aa363:	5b                   	pop    rbx
  9aa364:	41 5c                	pop    r12
  9aa366:	41 5d                	pop    r13
  9aa368:	41 5e                	pop    r14
  9aa36a:	41 5f                	pop    r15
  9aa36c:	5d                   	pop    rbp
  9aa36d:	c3                   	ret
  9aa36e:	31 c0                	xor    eax,eax
  9aa370:	eb ed                	jmp    0x9aa35f
  9aa372:	90                   	nop
  9aa373:	90                   	nop
  9aa374:	90                   	nop
  9aa375:	90                   	nop
  9aa376:	90                   	nop
  9aa377:	90                   	nop
  9aa378:	90                   	nop
  9aa379:	90                   	nop
  9aa37a:	90                   	nop
  9aa37b:	90                   	nop
  9aa37c:	90                   	nop
  9aa37d:	90                   	nop
  9aa37e:	90                   	nop
  9aa37f:	90                   	nop
  9aa380:	55                   	push   rbp
  9aa381:	48 89 e5             	mov    rbp,rsp
  9aa384:	41 57                	push   r15
  9aa386:	41 56                	push   r14
  9aa388:	41 55                	push   r13
  9aa38a:	41 54                	push   r12
  9aa38c:	53                   	push   rbx
  9aa38d:	48 81 ec 88 00 00 00 	sub    rsp,0x88
  9aa394:	48 8d 05 75 1f f7 02 	lea    rax,[rip+0x2f71f75]        # 0x391c310
  9aa39b:	48 89 8d 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rcx
  9aa3a2:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  9aa3a6:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
  9aa3aa:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  9aa3ae:	48 8d 3d c3 ba 1f 03 	lea    rdi,[rip+0x31fbac3]        # 0x3ba5e78
  9aa3b5:	4c 89 c3             	mov    rbx,r8
  9aa3b8:	31 f6                	xor    esi,esi
  9aa3ba:	31 d2                	xor    edx,edx
  9aa3bc:	31 c9                	xor    ecx,ecx
  9aa3be:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9aa3c1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9aa3c5:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9aa3cc:	00 00 
  9aa3ce:	4d 8b 29             	mov    r13,QWORD PTR [r9]
  9aa3d1:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  9aa3d5:	4c 89 8d 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],r9
  9aa3dc:	e8 1f c6 b1 ff       	call   0x4c6a00
  9aa3e1:	48 8b 05 f0 ba 1f 03 	mov    rax,QWORD PTR [rip+0x31fbaf0]        # 0x3ba5ed8
  9aa3e8:	48 85 c0             	test   rax,rax
  9aa3eb:	75 4f                	jne    0x9aa43c
  9aa3ed:	4c 8d 35 e4 ba 1f 03 	lea    r14,[rip+0x31fbae4]        # 0x3ba5ed8
  9aa3f4:	4c 8d 3d 65 ba 1f 03 	lea    r15,[rip+0x31fba65]        # 0x3ba5e60
  9aa3fb:	4c 8d 25 be 89 8c 00 	lea    r12,[rip+0x8c89be]        # 0x1272dc0
  9aa402:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9aa409:	1f 84 00 00 00 00 00 
  9aa410:	4c 89 f7             	mov    rdi,r14
  9aa413:	4c 89 fe             	mov    rsi,r15
  9aa416:	ba 44 00 00 00       	mov    edx,0x44
  9aa41b:	4c 89 e1             	mov    rcx,r12
  9aa41e:	c7 04 24 00 01 00 00 	mov    DWORD PTR [rsp],0x100
  9aa425:	45 31 c0             	xor    r8d,r8d
  9aa428:	45 31 c9             	xor    r9d,r9d
  9aa42b:	e8 30 be 25 00       	call   0xc06260
  9aa430:	48 8b 05 a1 ba 1f 03 	mov    rax,QWORD PTR [rip+0x31fbaa1]        # 0x3ba5ed8
  9aa437:	48 85 c0             	test   rax,rax
  9aa43a:	74 d4                	je     0x9aa410
  9aa43c:	f3 4c 0f bc f0       	tzcnt  r14,rax
  9aa441:	c4 e2 f8 f3 c8       	blsr   rax,rax
  9aa446:	48 8d 3d 2b ba 1f 03 	lea    rdi,[rip+0x31fba2b]        # 0x3ba5e78
  9aa44d:	31 f6                	xor    esi,esi
  9aa44f:	31 d2                	xor    edx,edx
  9aa451:	31 c9                	xor    ecx,ecx
  9aa453:	48 89 05 7e ba 1f 03 	mov    QWORD PTR [rip+0x31fba7e],rax        # 0x3ba5ed8
  9aa45a:	e8 41 cb b1 ff       	call   0x4c6fa0
  9aa45f:	48 8b 05 7a ba 1f 03 	mov    rax,QWORD PTR [rip+0x31fba7a]        # 0x3ba5ee0
  9aa466:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  9aa46a:	41 c1 e6 0d          	shl    r14d,0xd
  9aa46e:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  9aa475:	00 
  9aa476:	4a 8d 0c 30          	lea    rcx,[rax+r14*1]
  9aa47a:	4a 8d 84 30 00 20 00 	lea    rax,[rax+r14*1+0x2000]
  9aa481:	00 
  9aa482:	48 8d 56 18          	lea    rdx,[rsi+0x18]
  9aa486:	48 89 4d a8          	mov    QWORD PTR [rbp-0x58],rcx
  9aa48a:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
  9aa48e:	48 8d 8e 68 01 00 00 	lea    rcx,[rsi+0x168]
  9aa495:	48 89 95 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rdx
  9aa49c:	48 89 85 60 ff ff ff 	mov    QWORD PTR [rbp-0xa0],rax
  9aa4a3:	48 8d 86 98 01 00 00 	lea    rax,[rsi+0x198]
  9aa4aa:	48 89 4d 80          	mov    QWORD PTR [rbp-0x80],rcx
  9aa4ae:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  9aa4b2:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9aa4b9:	1f 84 00 00 00 00 00 
  9aa4c0:	83 7b 04 00          	cmp    DWORD PTR [rbx+0x4],0x0
  9aa4c4:	41 bc 16 00 00 00    	mov    r12d,0x16
  9aa4ca:	0f 85 73 02 00 00    	jne    0x9aa743
  9aa4d0:	4c 8b 7b 08          	mov    r15,QWORD PTR [rbx+0x8]
  9aa4d4:	41 0f b7 c7          	movzx  eax,r15w
  9aa4d8:	48 85 c0             	test   rax,rax
  9aa4db:	0f 85 62 02 00 00    	jne    0x9aa743
  9aa4e1:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  9aa4e5:	0f b7 c8             	movzx  ecx,ax
  9aa4e8:	48 85 c9             	test   rcx,rcx
  9aa4eb:	0f 85 52 02 00 00    	jne    0x9aa743
  9aa4f1:	4c 39 7d a0          	cmp    QWORD PTR [rbp-0x60],r15
  9aa4f5:	0f 87 48 02 00 00    	ja     0x9aa743
  9aa4fb:	48 8b 8d 58 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xa8]
  9aa502:	4c 39 f9             	cmp    rcx,r15
  9aa505:	0f 86 38 02 00 00    	jbe    0x9aa743
  9aa50b:	4c 29 f9             	sub    rcx,r15
  9aa50e:	48 39 c1             	cmp    rcx,rax
  9aa511:	0f 82 2c 02 00 00    	jb     0x9aa743
  9aa517:	48 85 c0             	test   rax,rax
  9aa51a:	0f 84 de 00 00 00    	je     0x9aa5fe
  9aa520:	4c 2b 7d a0          	sub    r15,QWORD PTR [rbp-0x60]
  9aa524:	4c 8b 75 c8          	mov    r14,QWORD PTR [rbp-0x38]
  9aa528:	4c 89 ad 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r13
  9aa52f:	4d 89 fc             	mov    r12,r15
  9aa532:	49 01 c7             	add    r15,rax
  9aa535:	49 c1 ec 10          	shr    r12,0x10
  9aa539:	49 c1 ef 10          	shr    r15,0x10
  9aa53d:	4c 39 75 a8          	cmp    QWORD PTR [rbp-0x58],r14
  9aa541:	0f 84 05 01 00 00    	je     0x9aa64c
  9aa547:	48 8b 85 60 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa0]
  9aa54e:	4d 89 fd             	mov    r13,r15
  9aa551:	4d 29 e5             	sub    r13,r12
  9aa554:	49 63 cd             	movsxd rcx,r13d
  9aa557:	4c 29 f0             	sub    rax,r14
  9aa55a:	48 c1 f8 02          	sar    rax,0x2
  9aa55e:	48 39 c8             	cmp    rax,rcx
  9aa561:	0f 8c 10 01 00 00    	jl     0x9aa677
  9aa567:	41 f7 c5 00 f8 ff ff 	test   r13d,0xfffff800
  9aa56e:	0f 85 e3 00 00 00    	jne    0x9aa657
  9aa574:	4c 8b 6d b0          	mov    r13,QWORD PTR [rbp-0x50]
  9aa578:	44 89 e6             	mov    esi,r12d
  9aa57b:	44 89 fa             	mov    edx,r15d
  9aa57e:	4c 89 ef             	mov    rdi,r13
  9aa581:	e8 fa da ff ff       	call   0x9a8080
  9aa586:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9aa58a:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9aa58e:	41 89 c6             	mov    r14d,eax
  9aa591:	48 8d 45 c8          	lea    rax,[rbp-0x38]
  9aa595:	4c 89 ee             	mov    rsi,r13
  9aa598:	44 89 e1             	mov    ecx,r12d
  9aa59b:	45 89 f8             	mov    r8d,r15d
  9aa59e:	4c 8d 4d c0          	lea    r9,[rbp-0x40]
  9aa5a2:	48 89 04 24          	mov    QWORD PTR [rsp],rax
  9aa5a6:	e8 c5 df ff ff       	call   0x9a8570
  9aa5ab:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9aa5b2:	44 89 f0             	mov    eax,r14d
  9aa5b5:	31 f6                	xor    esi,esi
  9aa5b7:	31 d2                	xor    edx,edx
  9aa5b9:	4c 8d 34 40          	lea    r14,[rax+rax*2]
  9aa5bd:	e8 de a0 e2 ff       	call   0x7d46a0
  9aa5c2:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  9aa5c6:	42 c7 04 b0 ff ff ff 	mov    DWORD PTR [rax+r14*4],0xffffffff
  9aa5cd:	ff 
  9aa5ce:	42 83 7c b0 08 00    	cmp    DWORD PTR [rax+r14*4+0x8],0x0
  9aa5d4:	0f 85 1f 01 00 00    	jne    0x9aa6f9
  9aa5da:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
  9aa5de:	4c 8b ad 78 ff ff ff 	mov    r13,QWORD PTR [rbp-0x88]
  9aa5e5:	83 38 00             	cmp    DWORD PTR [rax],0x0
  9aa5e8:	0f 85 24 01 00 00    	jne    0x9aa712
  9aa5ee:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9aa5f5:	31 f6                	xor    esi,esi
  9aa5f7:	31 d2                	xor    edx,edx
  9aa5f9:	e8 b2 a8 e2 ff       	call   0x7d4eb0
  9aa5fe:	45 31 e4             	xor    r12d,r12d
  9aa601:	4c 3b 6d 10          	cmp    r13,QWORD PTR [rbp+0x10]
  9aa605:	0f 84 38 01 00 00    	je     0x9aa743
  9aa60b:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  9aa612:	00 00 
  9aa614:	48 8d 35 22 d9 9e 00 	lea    rsi,[rip+0x9ed922]        # 0x1397f3d
  9aa61b:	31 d2                	xor    edx,edx
  9aa61d:	e8 be fd 26 00       	call   0xc1a3e0
  9aa622:	ba 20 00 00 00       	mov    edx,0x20
  9aa627:	4c 89 ef             	mov    rdi,r13
  9aa62a:	48 89 de             	mov    rsi,rbx
  9aa62d:	e8 4e ec 8a ff       	call   0x259280
  9aa632:	85 c0                	test   eax,eax
  9aa634:	0f 85 06 01 00 00    	jne    0x9aa740
  9aa63a:	83 3b 02             	cmp    DWORD PTR [rbx],0x2
  9aa63d:	0f 85 00 01 00 00    	jne    0x9aa743
  9aa643:	49 83 c5 20          	add    r13,0x20
  9aa647:	e9 74 fe ff ff       	jmp    0x9aa4c0
  9aa64c:	4d 89 fd             	mov    r13,r15
  9aa64f:	4d 29 e5             	sub    r13,r12
  9aa652:	e9 10 ff ff ff       	jmp    0x9aa567
  9aa657:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9aa65b:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  9aa65f:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9aa663:	44 89 e1             	mov    ecx,r12d
  9aa666:	45 89 f8             	mov    r8d,r15d
  9aa669:	e8 f2 db ff ff       	call   0x9a8260
  9aa66e:	4c 8b ad 78 ff ff ff 	mov    r13,QWORD PTR [rbp-0x88]
  9aa675:	eb 87                	jmp    0x9aa5fe
  9aa677:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9aa67b:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  9aa67f:	48 8b b8 d8 01 00 00 	mov    rdi,QWORD PTR [rax+0x1d8]
  9aa686:	e8 b5 4c f4 ff       	call   0x8ef340
  9aa68b:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  9aa68f:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  9aa696:	00 
  9aa697:	80 b8 17 01 00 00 00 	cmp    BYTE PTR [rax+0x117],0x0
  9aa69e:	74 35                	je     0x9aa6d5
  9aa6a0:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  9aa6a4:	48 8d 0d 3d bc 0e 01 	lea    rcx,[rip+0x10ebc3d]        # 0x1a962e8
  9aa6ab:	c6 80 17 01 00 00 00 	mov    BYTE PTR [rax+0x117],0x0
  9aa6b2:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  9aa6b5:	48 8b 48 40          	mov    rcx,QWORD PTR [rax+0x40]
  9aa6b9:	48 8d 05 28 66 8b ff 	lea    rax,[rip+0xffffffffff8b6628]        # 0x260ce8
  9aa6c0:	48 29 c8             	sub    rax,rcx
  9aa6c3:	48 c1 c8 03          	ror    rax,0x3
  9aa6c7:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  9aa6cd:	77 57                	ja     0x9aa726
  9aa6cf:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9aa6d3:	ff d1                	call   rcx
  9aa6d5:	48 8b 75 a8          	mov    rsi,QWORD PTR [rbp-0x58]
  9aa6d9:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  9aa6dd:	49 29 f6             	sub    r14,rsi
  9aa6e0:	49 c1 ee 02          	shr    r14,0x2
  9aa6e4:	44 89 f2             	mov    edx,r14d
  9aa6e7:	e8 d4 df ff ff       	call   0x9a86c0
  9aa6ec:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
  9aa6f0:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  9aa6f4:	e9 6e fe ff ff       	jmp    0x9aa567
  9aa6f9:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  9aa6fd:	4a 8d 7c b0 08       	lea    rdi,[rax+r14*4+0x8]
  9aa702:	c7 07 00 00 00 00    	mov    DWORD PTR [rdi],0x0
  9aa708:	e8 03 c2 25 00       	call   0xc06910
  9aa70d:	e9 c8 fe ff ff       	jmp    0x9aa5da
  9aa712:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  9aa716:	c7 07 00 00 00 00    	mov    DWORD PTR [rdi],0x0
  9aa71c:	e8 ef c1 25 00       	call   0xc06910
  9aa721:	e9 c8 fe ff ff       	jmp    0x9aa5ee
  9aa726:	48 89 4d 90          	mov    QWORD PTR [rbp-0x70],rcx
  9aa72a:	48 8d 3d 5f 58 bb 01 	lea    rdi,[rip+0x1bb585f]        # 0x255ff90
  9aa731:	48 8b 75 90          	mov    rsi,QWORD PTR [rbp-0x70]
  9aa735:	e8 86 51 aa ff       	call   0x44f8c0
  9aa73a:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9aa73e:	eb 8f                	jmp    0x9aa6cf
  9aa740:	41 89 c4             	mov    r12d,eax
  9aa743:	48 8b 5d c8          	mov    rbx,QWORD PTR [rbp-0x38]
  9aa747:	4c 8b 7d a8          	mov    r15,QWORD PTR [rbp-0x58]
  9aa74b:	49 39 df             	cmp    r15,rbx
  9aa74e:	74 6c                	je     0x9aa7bc
  9aa750:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9aa754:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  9aa758:	48 8b b8 d8 01 00 00 	mov    rdi,QWORD PTR [rax+0x1d8]
  9aa75f:	e8 dc 4b f4 ff       	call   0x8ef340
  9aa764:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  9aa768:	80 b8 17 01 00 00 00 	cmp    BYTE PTR [rax+0x117],0x0
  9aa76f:	74 36                	je     0x9aa7a7
  9aa771:	48 8d 0d 70 bb 0e 01 	lea    rcx,[rip+0x10ebb70]        # 0x1a962e8
  9aa778:	c6 80 17 01 00 00 00 	mov    BYTE PTR [rax+0x117],0x0
  9aa77f:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  9aa782:	4c 8b 70 40          	mov    r14,QWORD PTR [rax+0x40]
  9aa786:	48 8d 05 5b 65 8b ff 	lea    rax,[rip+0xffffffffff8b655b]        # 0x260ce8
  9aa78d:	4c 29 f0             	sub    rax,r14
  9aa790:	48 c1 c8 03          	ror    rax,0x3
  9aa794:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  9aa79a:	0f 87 a7 00 00 00    	ja     0x9aa847
  9aa7a0:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9aa7a4:	41 ff d6             	call   r14
  9aa7a7:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  9aa7ab:	4c 29 fb             	sub    rbx,r15
  9aa7ae:	4c 89 fe             	mov    rsi,r15
  9aa7b1:	48 c1 eb 02          	shr    rbx,0x2
  9aa7b5:	89 da                	mov    edx,ebx
  9aa7b7:	e8 04 df ff ff       	call   0x9a86c0
  9aa7bc:	48 8d 3d b5 b6 1f 03 	lea    rdi,[rip+0x31fb6b5]        # 0x3ba5e78
  9aa7c3:	31 f6                	xor    esi,esi
  9aa7c5:	31 d2                	xor    edx,edx
  9aa7c7:	31 c9                	xor    ecx,ecx
  9aa7c9:	e8 32 c2 b1 ff       	call   0x4c6a00
  9aa7ce:	44 2b 3d 0b b7 1f 03 	sub    r15d,DWORD PTR [rip+0x31fb70b]        # 0x3ba5ee0
  9aa7d5:	48 8b 05 fc b6 1f 03 	mov    rax,QWORD PTR [rip+0x31fb6fc]        # 0x3ba5ed8
  9aa7dc:	48 89 c1             	mov    rcx,rax
  9aa7df:	41 c1 ef 0d          	shr    r15d,0xd
  9aa7e3:	4c 0f ab f9          	bts    rcx,r15
  9aa7e7:	48 89 0d ea b6 1f 03 	mov    QWORD PTR [rip+0x31fb6ea],rcx        # 0x3ba5ed8
  9aa7ee:	48 85 c0             	test   rax,rax
  9aa7f1:	75 0c                	jne    0x9aa7ff
  9aa7f3:	48 8d 3d de b6 1f 03 	lea    rdi,[rip+0x31fb6de]        # 0x3ba5ed8
  9aa7fa:	e8 11 c1 25 00       	call   0xc06910
  9aa7ff:	48 8d 3d 72 b6 1f 03 	lea    rdi,[rip+0x31fb672]        # 0x3ba5e78
  9aa806:	31 f6                	xor    esi,esi
  9aa808:	31 d2                	xor    edx,edx
  9aa80a:	31 c9                	xor    ecx,ecx
  9aa80c:	e8 8f c7 b1 ff       	call   0x4c6fa0
  9aa811:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
  9aa818:	48 8d 0d f1 1a f7 02 	lea    rcx,[rip+0x2f71af1]        # 0x391c310
  9aa81f:	4c 89 28             	mov    QWORD PTR [rax],r13
  9aa822:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  9aa825:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9aa829:	75 15                	jne    0x9aa840
  9aa82b:	44 89 e0             	mov    eax,r12d
  9aa82e:	48 81 c4 88 00 00 00 	add    rsp,0x88
  9aa835:	5b                   	pop    rbx
  9aa836:	41 5c                	pop    r12
  9aa838:	41 5d                	pop    r13
  9aa83a:	41 5e                	pop    r14
  9aa83c:	41 5f                	pop    r15
  9aa83e:	5d                   	pop    rbp
  9aa83f:	c3                   	ret
  9aa840:	e8 6b 2e d5 ff       	call   0x6fd6b0
  9aa845:	0f 0b                	ud2
  9aa847:	48 8d 3d 62 57 bb 01 	lea    rdi,[rip+0x1bb5762]        # 0x255ffb0
  9aa84e:	4c 89 f6             	mov    rsi,r14
  9aa851:	e8 6a 50 aa ff       	call   0x44f8c0
  9aa856:	e9 45 ff ff ff       	jmp    0x9aa7a0
  9aa85b:	90                   	nop
  9aa85c:	90                   	nop
  9aa85d:	90                   	nop
  9aa85e:	90                   	nop
  9aa85f:	90                   	nop
  9aa860:	55                   	push   rbp
  9aa861:	48 89 e5             	mov    rbp,rsp
  9aa864:	41 83 78 04 00       	cmp    DWORD PTR [r8+0x4],0x0
  9aa869:	b8 16 00 00 00       	mov    eax,0x16
  9aa86e:	75 5a                	jne    0x9aa8ca
  9aa870:	4d 89 c1             	mov    r9,r8
  9aa873:	4d 8b 40 08          	mov    r8,QWORD PTR [r8+0x8]
  9aa877:	45 0f b7 d0          	movzx  r10d,r8w
  9aa87b:	4d 85 d2             	test   r10,r10
  9aa87e:	75 4a                	jne    0x9aa8ca
  9aa880:	4d 8b 51 10          	mov    r10,QWORD PTR [r9+0x10]
  9aa884:	45 0f b7 da          	movzx  r11d,r10w
  9aa888:	4d 85 db             	test   r11,r11
  9aa88b:	75 3d                	jne    0x9aa8ca
  9aa88d:	4c 39 c2             	cmp    rdx,r8
  9aa890:	77 38                	ja     0x9aa8ca
  9aa892:	4c 39 c1             	cmp    rcx,r8
  9aa895:	76 33                	jbe    0x9aa8ca
  9aa897:	4c 29 c1             	sub    rcx,r8
  9aa89a:	4c 39 d1             	cmp    rcx,r10
  9aa89d:	72 2b                	jb     0x9aa8ca
  9aa89f:	45 0f b6 49 18       	movzx  r9d,BYTE PTR [r9+0x18]
  9aa8a4:	44 89 c9             	mov    ecx,r9d
  9aa8a7:	83 e1 cc             	and    ecx,0xffffffcc
  9aa8aa:	75 1e                	jne    0x9aa8ca
  9aa8ac:	4d 85 d2             	test   r10,r10
  9aa8af:	74 17                	je     0x9aa8c8
  9aa8b1:	49 29 d0             	sub    r8,rdx
  9aa8b4:	4c 89 c1             	mov    rcx,r8
  9aa8b7:	4d 01 d0             	add    r8,r10
  9aa8ba:	48 c1 e9 10          	shr    rcx,0x10
  9aa8be:	49 c1 e8 10          	shr    r8,0x10
  9aa8c2:	5d                   	pop    rbp
  9aa8c3:	e9 08 df ff ff       	jmp    0x9a87d0
  9aa8c8:	31 c0                	xor    eax,eax
  9aa8ca:	5d                   	pop    rbp
  9aa8cb:	c3                   	ret
  9aa8cc:	90                   	nop
  9aa8cd:	90                   	nop
  9aa8ce:	90                   	nop
  9aa8cf:	90                   	nop
  9aa8d0:	55                   	push   rbp
  9aa8d1:	48 89 e5             	mov    rbp,rsp
  9aa8d4:	41 57                	push   r15
  9aa8d6:	41 56                	push   r14
  9aa8d8:	41 55                	push   r13
  9aa8da:	41 54                	push   r12
  9aa8dc:	53                   	push   rbx
  9aa8dd:	48 81 ec 98 04 00 00 	sub    rsp,0x498
  9aa8e4:	48 8d 05 25 1a f7 02 	lea    rax,[rip+0x2f71a25]        # 0x391c310
  9aa8eb:	48 89 95 98 fb ff ff 	mov    QWORD PTR [rbp-0x468],rdx
  9aa8f2:	4d 89 c7             	mov    r15,r8
  9aa8f5:	4c 8d a5 f0 fb ff ff 	lea    r12,[rbp-0x410]
  9aa8fc:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9aa8ff:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9aa903:	48 89 b5 70 fb ff ff 	mov    QWORD PTR [rbp-0x490],rsi
  9aa90a:	48 89 bd 60 fb ff ff 	mov    QWORD PTR [rbp-0x4a0],rdi
  9aa911:	4c 89 8d 58 fb ff ff 	mov    QWORD PTR [rbp-0x4a8],r9
  9aa918:	48 c7 85 b0 fb ff ff 	mov    QWORD PTR [rbp-0x450],0xffffffffffffffff
  9aa91f:	ff ff ff ff 
  9aa923:	48 c7 85 b8 fb ff ff 	mov    QWORD PTR [rbp-0x448],0x0
  9aa92a:	00 00 00 00 
  9aa92e:	48 89 8d 88 fb ff ff 	mov    QWORD PTR [rbp-0x478],rcx
  9aa935:	48 8b 96 e8 00 00 00 	mov    rdx,QWORD PTR [rsi+0xe8]
  9aa93c:	0f b6 87 44 02 00 00 	movzx  eax,BYTE PTR [rdi+0x244]
  9aa943:	49 8b 31             	mov    rsi,QWORD PTR [r9]
  9aa946:	48 89 95 90 fb ff ff 	mov    QWORD PTR [rbp-0x470],rdx
  9aa94d:	48 8d 95 d0 fb ff ff 	lea    rdx,[rbp-0x430]
  9aa954:	88 85 c7 fb ff ff    	mov    BYTE PTR [rbp-0x439],al
  9aa95a:	48 89 b5 a0 fb ff ff 	mov    QWORD PTR [rbp-0x460],rsi
  9aa961:	48 89 95 a8 fb ff ff 	mov    QWORD PTR [rbp-0x458],rdx
  9aa968:	41 83 7f 04 00       	cmp    DWORD PTR [r15+0x4],0x0
  9aa96d:	0f 85 97 01 00 00    	jne    0x9aab0a
  9aa973:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9aa97a:	84 00 00 00 00 00 
  9aa980:	4d 8b 6f 08          	mov    r13,QWORD PTR [r15+0x8]
  9aa984:	41 0f b7 c5          	movzx  eax,r13w
  9aa988:	48 85 c0             	test   rax,rax
  9aa98b:	0f 85 79 01 00 00    	jne    0x9aab0a
  9aa991:	4d 8b 77 10          	mov    r14,QWORD PTR [r15+0x10]
  9aa995:	41 0f b7 c6          	movzx  eax,r14w
  9aa999:	48 85 c0             	test   rax,rax
  9aa99c:	0f 85 68 01 00 00    	jne    0x9aab0a
  9aa9a2:	4c 39 ad 98 fb ff ff 	cmp    QWORD PTR [rbp-0x468],r13
  9aa9a9:	0f 87 5b 01 00 00    	ja     0x9aab0a
  9aa9af:	4c 39 e9             	cmp    rcx,r13
  9aa9b2:	0f 86 52 01 00 00    	jbe    0x9aab0a
  9aa9b8:	48 89 c8             	mov    rax,rcx
  9aa9bb:	4c 29 e8             	sub    rax,r13
  9aa9be:	4c 39 f0             	cmp    rax,r14
  9aa9c1:	0f 82 43 01 00 00    	jb     0x9aab0a
  9aa9c7:	41 0f b6 5f 18       	movzx  ebx,BYTE PTR [r15+0x18]
  9aa9cc:	89 d8                	mov    eax,ebx
  9aa9ce:	24 cc                	and    al,0xcc
  9aa9d0:	0f 85 34 01 00 00    	jne    0x9aab0a
  9aa9d6:	41 0f b6 47 19       	movzx  eax,BYTE PTR [r15+0x19]
  9aa9db:	0f b6 f8             	movzx  edi,al
  9aa9de:	83 ff 0a             	cmp    edi,0xa
  9aa9e1:	77 2d                	ja     0x9aaa10
  9aa9e3:	b9 09 04 00 00       	mov    ecx,0x409
  9aa9e8:	0f a3 f9             	bt     ecx,edi
  9aa9eb:	73 23                	jae    0x9aaa10
  9aa9ed:	f6 85 c7 fb ff ff 02 	test   BYTE PTR [rbp-0x439],0x2
  9aa9f4:	75 3d                	jne    0x9aaa33
  9aa9f6:	e8 15 22 00 00       	call   0x9acc10
  9aa9fb:	85 c0                	test   eax,eax
  9aa9fd:	0f 94 c0             	sete   al
  9aaa00:	c0 e0 02             	shl    al,0x2
  9aaa03:	04 0f                	add    al,0xf
  9aaa05:	eb 2c                	jmp    0x9aaa33
  9aaa07:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  9aaa0e:	00 00 
  9aaa10:	f6 85 c7 fb ff ff 02 	test   BYTE PTR [rbp-0x439],0x2
  9aaa17:	c7 85 c0 fb ff ff 16 	mov    DWORD PTR [rbp-0x440],0x16
  9aaa1e:	00 00 00 
  9aaa21:	0f 85 f8 00 00 00    	jne    0x9aab1f
  9aaa27:	83 c7 eb             	add    edi,0xffffffeb
  9aaa2a:	83 ff f6             	cmp    edi,0xfffffff6
  9aaa2d:	0f 82 ec 00 00 00    	jb     0x9aab1f
  9aaa33:	48 8b 95 b0 fb ff ff 	mov    rdx,QWORD PTR [rbp-0x450]
  9aaa3a:	4c 89 e9             	mov    rcx,r13
  9aaa3d:	48 83 85 a8 fb ff ff 	add    QWORD PTR [rbp-0x458],0x20
  9aaa44:	20 
  9aaa45:	4d 89 6c 24 e8       	mov    QWORD PTR [r12-0x18],r13
  9aaa4a:	4d 89 74 24 f0       	mov    QWORD PTR [r12-0x10],r14
  9aaa4f:	41 88 5c 24 f8       	mov    BYTE PTR [r12-0x8],bl
  9aaa54:	41 88 44 24 f9       	mov    BYTE PTR [r12-0x7],al
  9aaa59:	4b 8d 04 2e          	lea    rax,[r14+r13*1]
  9aaa5d:	48 81 e1 00 00 e0 ff 	and    rcx,0xffffffffffe00000
  9aaa64:	4c 39 ea             	cmp    rdx,r13
  9aaa67:	48 0f 47 d1          	cmova  rdx,rcx
  9aaa6b:	48 89 95 b0 fb ff ff 	mov    QWORD PTR [rbp-0x450],rdx
  9aaa72:	4b 8d 94 2e ff ff 1f 	lea    rdx,[r14+r13*1+0x1fffff]
  9aaa79:	00 
  9aaa7a:	4c 8b ad b8 fb ff ff 	mov    r13,QWORD PTR [rbp-0x448]
  9aaa81:	48 81 e2 00 00 e0 ff 	and    rdx,0xffffffffffe00000
  9aaa88:	49 39 c5             	cmp    r13,rax
  9aaa8b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
  9aaa8f:	4c 0f 42 ea          	cmovb  r13,rdx
  9aaa93:	4c 39 e0             	cmp    rax,r12
  9aaa96:	0f 86 a6 00 00 00    	jbe    0x9aab42
  9aaa9c:	48 8b 9d a0 fb ff ff 	mov    rbx,QWORD PTR [rbp-0x460]
  9aaaa3:	48 3b 5d 10          	cmp    rbx,QWORD PTR [rbp+0x10]
  9aaaa7:	0f 84 9c 00 00 00    	je     0x9aab49
  9aaaad:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  9aaab4:	00 00 
  9aaab6:	48 8d 35 80 d4 9e 00 	lea    rsi,[rip+0x9ed480]        # 0x1397f3d
  9aaabd:	31 d2                	xor    edx,edx
  9aaabf:	e8 1c f9 26 00       	call   0xc1a3e0
  9aaac4:	ba 20 00 00 00       	mov    edx,0x20
  9aaac9:	48 89 df             	mov    rdi,rbx
  9aaacc:	4c 89 fe             	mov    rsi,r15
  9aaacf:	e8 ac e7 8a ff       	call   0x259280
  9aaad4:	85 c0                	test   eax,eax
  9aaad6:	0f 85 32 06 00 00    	jne    0x9ab10e
  9aaadc:	41 83 3f 04          	cmp    DWORD PTR [r15],0x4
  9aaae0:	75 4d                	jne    0x9aab2f
  9aaae2:	48 8b 8d 88 fb ff ff 	mov    rcx,QWORD PTR [rbp-0x478]
  9aaae9:	48 83 c3 20          	add    rbx,0x20
  9aaaed:	4c 89 ad b8 fb ff ff 	mov    QWORD PTR [rbp-0x448],r13
  9aaaf4:	49 83 c4 20          	add    r12,0x20
  9aaaf8:	48 89 9d a0 fb ff ff 	mov    QWORD PTR [rbp-0x460],rbx
  9aaaff:	41 83 7f 04 00       	cmp    DWORD PTR [r15+0x4],0x0
  9aab04:	0f 84 76 fe ff ff    	je     0x9aa980
  9aab0a:	49 83 c4 e0          	add    r12,0xffffffffffffffe0
  9aab0e:	c7 85 c0 fb ff ff 16 	mov    DWORD PTR [rbp-0x440],0x16
  9aab15:	00 00 00 
  9aab18:	4c 89 a5 a8 fb ff ff 	mov    QWORD PTR [rbp-0x458],r12
  9aab1f:	48 8b 9d a0 fb ff ff 	mov    rbx,QWORD PTR [rbp-0x460]
  9aab26:	4c 8b ad b8 fb ff ff 	mov    r13,QWORD PTR [rbp-0x448]
  9aab2d:	eb 24                	jmp    0x9aab53
  9aab2f:	c7 85 c0 fb ff ff 00 	mov    DWORD PTR [rbp-0x440],0x0
  9aab36:	00 00 00 
  9aab39:	4c 89 a5 a8 fb ff ff 	mov    QWORD PTR [rbp-0x458],r12
  9aab40:	eb 11                	jmp    0x9aab53
  9aab42:	48 8b 9d a0 fb ff ff 	mov    rbx,QWORD PTR [rbp-0x460]
  9aab49:	c7 85 c0 fb ff ff 00 	mov    DWORD PTR [rbp-0x440],0x0
  9aab50:	00 00 00 
  9aab53:	48 8b b5 b0 fb ff ff 	mov    rsi,QWORD PTR [rbp-0x450]
  9aab5a:	4c 8b b5 70 fb ff ff 	mov    r14,QWORD PTR [rbp-0x490]
  9aab61:	49 39 f5             	cmp    r13,rsi
  9aab64:	0f 86 95 04 00 00    	jbe    0x9aafff
  9aab6a:	48 8b 85 98 fb ff ff 	mov    rax,QWORD PTR [rbp-0x468]
  9aab71:	4c 89 f7             	mov    rdi,r14
  9aab74:	49 29 c5             	sub    r13,rax
  9aab77:	48 29 c6             	sub    rsi,rax
  9aab7a:	49 c1 ed 10          	shr    r13,0x10
  9aab7e:	48 c1 ee 10          	shr    rsi,0x10
  9aab82:	44 89 ea             	mov    edx,r13d
  9aab85:	e8 f6 d4 ff ff       	call   0x9a8080
  9aab8a:	48 8b 8d 60 fb ff ff 	mov    rcx,QWORD PTR [rbp-0x4a0]
  9aab91:	89 85 7c fb ff ff    	mov    DWORD PTR [rbp-0x484],eax
  9aab97:	4d 8b be 60 01 00 00 	mov    r15,QWORD PTR [r14+0x160]
  9aab9e:	48 8b 81 d8 01 00 00 	mov    rax,QWORD PTR [rcx+0x1d8]
  9aaba5:	48 8d 8d d0 fb ff ff 	lea    rcx,[rbp-0x430]
  9aabac:	48 c7 85 c8 fb ff ff 	mov    QWORD PTR [rbp-0x438],0x0
  9aabb3:	00 00 00 00 
  9aabb7:	48 89 85 80 fb ff ff 	mov    QWORD PTR [rbp-0x480],rax
  9aabbe:	48 3b 8d a8 fb ff ff 	cmp    rcx,QWORD PTR [rbp-0x458]
  9aabc5:	0f 84 39 01 00 00    	je     0x9aad04
  9aabcb:	45 31 c0             	xor    r8d,r8d
  9aabce:	45 31 ed             	xor    r13d,r13d
  9aabd1:	eb 2c                	jmp    0x9aabff
  9aabd3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9aabda:	84 00 00 00 00 00 
  9aabe0:	4c 8b 85 b0 fb ff ff 	mov    r8,QWORD PTR [rbp-0x450]
  9aabe7:	48 8b 8d b8 fb ff ff 	mov    rcx,QWORD PTR [rbp-0x448]
  9aabee:	48 83 c1 20          	add    rcx,0x20
  9aabf2:	48 3b 8d a8 fb ff ff 	cmp    rcx,QWORD PTR [rbp-0x458]
  9aabf9:	0f 84 ee 00 00 00    	je     0x9aaced
  9aabff:	f6 85 c7 fb ff ff 02 	test   BYTE PTR [rbp-0x439],0x2
  9aac06:	0f b6 41 19          	movzx  eax,BYTE PTR [rcx+0x19]
  9aac0a:	4c 89 85 b0 fb ff ff 	mov    QWORD PTR [rbp-0x450],r8
  9aac11:	74 1d                	je     0x9aac30
  9aac13:	31 db                	xor    ebx,ebx
  9aac15:	3c 0a                	cmp    al,0xa
  9aac17:	ba 00 00 c0 00       	mov    edx,0xc00000
  9aac1c:	0f 94 c3             	sete   bl
  9aac1f:	c1 e3 17             	shl    ebx,0x17
  9aac22:	84 c0                	test   al,al
  9aac24:	0f 44 da             	cmove  ebx,edx
  9aac27:	eb 1c                	jmp    0x9aac45
  9aac29:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  9aac30:	04 f5                	add    al,0xf5
  9aac32:	31 db                	xor    ebx,ebx
  9aac34:	3c 09                	cmp    al,0x9
  9aac36:	77 0d                	ja     0x9aac45
  9aac38:	0f b6 c0             	movzx  eax,al
  9aac3b:	48 8d 15 4a 2f f2 00 	lea    rdx,[rip+0xf22f4a]        # 0x18cdb8c
  9aac42:	8b 1c 82             	mov    ebx,DWORD PTR [rdx+rax*4]
  9aac45:	48 8b 71 08          	mov    rsi,QWORD PTR [rcx+0x8]
  9aac49:	48 8b 51 10          	mov    rdx,QWORD PTR [rcx+0x10]
  9aac4d:	48 8b 85 98 fb ff ff 	mov    rax,QWORD PTR [rbp-0x468]
  9aac54:	48 8b bd 80 fb ff ff 	mov    rdi,QWORD PTR [rbp-0x480]
  9aac5b:	48 89 8d b8 fb ff ff 	mov    QWORD PTR [rbp-0x448],rcx
  9aac62:	48 8d 8d c8 fb ff ff 	lea    rcx,[rbp-0x438]
  9aac69:	48 01 f2             	add    rdx,rsi
  9aac6c:	49 89 f6             	mov    r14,rsi
  9aac6f:	49 89 d4             	mov    r12,rdx
  9aac72:	49 29 c6             	sub    r14,rax
  9aac75:	49 29 c4             	sub    r12,rax
  9aac78:	49 c1 ee 10          	shr    r14,0x10
  9aac7c:	49 c1 ec 10          	shr    r12,0x10
  9aac80:	e8 fb 3a f4 ff       	call   0x8ee780
  9aac85:	45 39 e6             	cmp    r14d,r12d
  9aac88:	0f 8d 52 ff ff ff    	jge    0x9aabe0
  9aac8e:	4c 8b 85 b0 fb ff ff 	mov    r8,QWORD PTR [rbp-0x450]
  9aac95:	89 d8                	mov    eax,ebx
  9aac97:	49 63 ce             	movsxd rcx,r14d
  9aac9a:	49 63 d4             	movsxd rdx,r12d
  9aac9d:	25 00 00 80 00       	and    eax,0x800000
  9aaca2:	eb 26                	jmp    0x9aacca
  9aaca4:	41 ff c8             	dec    r8d
  9aaca7:	49 8d bd 00 00 01 00 	lea    rdi,[r13+0x10000]
  9aacae:	85 f6                	test   esi,esi
  9aacb0:	49 0f 44 fd          	cmove  rdi,r13
  9aacb4:	81 fb 00 00 c0 00    	cmp    ebx,0xc00000
  9aacba:	4c 0f 45 ef          	cmovne r13,rdi
  9aacbe:	48 ff c1             	inc    rcx
  9aacc1:	48 39 ca             	cmp    rdx,rcx
  9aacc4:	0f 84 1d ff ff ff    	je     0x9aabe7
  9aacca:	41 8b 34 8f          	mov    esi,DWORD PTR [r15+rcx*4]
  9aacce:	89 f7                	mov    edi,esi
  9aacd0:	81 e7 00 00 f0 00    	and    edi,0xf00000
  9aacd6:	39 fb                	cmp    ebx,edi
  9aacd8:	74 e4                	je     0x9aacbe
  9aacda:	81 e6 00 00 80 00    	and    esi,0x800000
  9aace0:	39 c6                	cmp    esi,eax
  9aace2:	74 c3                	je     0x9aaca7
  9aace4:	85 c0                	test   eax,eax
  9aace6:	74 bc                	je     0x9aaca4
  9aace8:	41 ff c0             	inc    r8d
  9aaceb:	eb ba                	jmp    0x9aaca7
  9aaced:	48 8b b5 c8 fb ff ff 	mov    rsi,QWORD PTR [rbp-0x438]
  9aacf4:	49 81 fd 00 00 20 00 	cmp    r13,0x200000
  9aacfb:	4d 89 c5             	mov    r13,r8
  9aacfe:	41 0f 93 c4          	setae  r12b
  9aad02:	eb 08                	jmp    0x9aad0c
  9aad04:	31 f6                	xor    esi,esi
  9aad06:	45 31 e4             	xor    r12d,r12d
  9aad09:	45 31 ed             	xor    r13d,r13d
  9aad0c:	48 8b bd 80 fb ff ff 	mov    rdi,QWORD PTR [rbp-0x480]
  9aad13:	e8 28 46 f4 ff       	call   0x8ef340
  9aad18:	4c 8b b5 90 fb ff ff 	mov    r14,QWORD PTR [rbp-0x470]
  9aad1f:	31 f6                	xor    esi,esi
  9aad21:	31 d2                	xor    edx,edx
  9aad23:	31 c9                	xor    ecx,ecx
  9aad25:	49 8d 5e 28          	lea    rbx,[r14+0x28]
  9aad29:	48 89 df             	mov    rdi,rbx
  9aad2c:	e8 cf bc b1 ff       	call   0x4c6a00
  9aad31:	45 01 6e 50          	add    DWORD PTR [r14+0x50],r13d
  9aad35:	45 29 6e 54          	sub    DWORD PTR [r14+0x54],r13d
  9aad39:	45 84 e4             	test   r12b,r12b
  9aad3c:	0f 84 23 02 00 00    	je     0x9aaf65
  9aad42:	4c 89 f7             	mov    rdi,r14
  9aad45:	e8 06 17 00 00       	call   0x9ac450
  9aad4a:	48 89 df             	mov    rdi,rbx
  9aad4d:	31 f6                	xor    esi,esi
  9aad4f:	31 d2                	xor    edx,edx
  9aad51:	31 c9                	xor    ecx,ecx
  9aad53:	e8 48 c2 b1 ff       	call   0x4c6fa0
  9aad58:	48 8d 8d d0 fb ff ff 	lea    rcx,[rbp-0x430]
  9aad5f:	48 c7 85 c8 fb ff ff 	mov    QWORD PTR [rbp-0x438],0x0
  9aad66:	00 00 00 00 
  9aad6a:	48 3b 8d a8 fb ff ff 	cmp    rcx,QWORD PTR [rbp-0x458]
  9aad71:	0f 84 1b 02 00 00    	je     0x9aaf92
  9aad77:	48 8b 85 90 fb ff ff 	mov    rax,QWORD PTR [rbp-0x470]
  9aad7e:	48 8b 50 30          	mov    rdx,QWORD PTR [rax+0x30]
  9aad82:	48 89 95 50 fb ff ff 	mov    QWORD PTR [rbp-0x4b0],rdx
  9aad89:	eb 1d                	jmp    0x9aada8
  9aad8b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  9aad90:	48 8b 8d 68 fb ff ff 	mov    rcx,QWORD PTR [rbp-0x498]
  9aad97:	48 83 c1 20          	add    rcx,0x20
  9aad9b:	48 3b 8d a8 fb ff ff 	cmp    rcx,QWORD PTR [rbp-0x458]
  9aada2:	0f 84 ea 01 00 00    	je     0x9aaf92
  9aada8:	f6 85 c7 fb ff ff 02 	test   BYTE PTR [rbp-0x439],0x2
  9aadaf:	0f b6 41 19          	movzx  eax,BYTE PTR [rcx+0x19]
  9aadb3:	74 2b                	je     0x9aade0
  9aadb5:	31 f6                	xor    esi,esi
  9aadb7:	3c 0a                	cmp    al,0xa
  9aadb9:	bf 00 00 c0 00       	mov    edi,0xc00000
  9aadbe:	40 0f 94 c6          	sete   sil
  9aadc2:	c1 e6 17             	shl    esi,0x17
  9aadc5:	84 c0                	test   al,al
  9aadc7:	0f 44 f7             	cmove  esi,edi
  9aadca:	89 b5 b8 fb ff ff    	mov    DWORD PTR [rbp-0x448],esi
  9aadd0:	eb 31                	jmp    0x9aae03
  9aadd2:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9aadd9:	1f 84 00 00 00 00 00 
  9aade0:	04 f5                	add    al,0xf5
  9aade2:	c7 85 b8 fb ff ff 00 	mov    DWORD PTR [rbp-0x448],0x0
  9aade9:	00 00 00 
  9aadec:	3c 09                	cmp    al,0x9
  9aadee:	77 13                	ja     0x9aae03
  9aadf0:	0f b6 c0             	movzx  eax,al
  9aadf3:	48 8d 35 92 2d f2 00 	lea    rsi,[rip+0xf22d92]        # 0x18cdb8c
  9aadfa:	8b 04 86             	mov    eax,DWORD PTR [rsi+rax*4]
  9aadfd:	89 85 b8 fb ff ff    	mov    DWORD PTR [rbp-0x448],eax
  9aae03:	48 8b 41 08          	mov    rax,QWORD PTR [rcx+0x8]
  9aae07:	48 2b 85 98 fb ff ff 	sub    rax,QWORD PTR [rbp-0x468]
  9aae0e:	48 89 8d 68 fb ff ff 	mov    QWORD PTR [rbp-0x498],rcx
  9aae15:	48 89 c6             	mov    rsi,rax
  9aae18:	48 03 41 10          	add    rax,QWORD PTR [rcx+0x10]
  9aae1c:	48 c1 ee 10          	shr    rsi,0x10
  9aae20:	48 c1 e8 10          	shr    rax,0x10
  9aae24:	48 89 85 88 fb ff ff 	mov    QWORD PTR [rbp-0x478],rax
  9aae2b:	39 c6                	cmp    esi,eax
  9aae2d:	0f 8d 5d ff ff ff    	jge    0x9aad90
  9aae33:	48 8b 85 68 fb ff ff 	mov    rax,QWORD PTR [rbp-0x498]
  9aae3a:	48 63 bd 88 fb ff ff 	movsxd rdi,DWORD PTR [rbp-0x478]
  9aae41:	0f b6 48 18          	movzx  ecx,BYTE PTR [rax+0x18]
  9aae45:	b8 01 01 00 00       	mov    eax,0x101
  9aae4a:	48 89 bd 48 fb ff ff 	mov    QWORD PTR [rbp-0x4b8],rdi
  9aae51:	c4 e2 78 f7 c1       	bextr  eax,ecx,eax
  9aae56:	09 c8                	or     eax,ecx
  9aae58:	83 e1 30             	and    ecx,0x30
  9aae5b:	83 e0 03             	and    eax,0x3
  9aae5e:	c1 e1 16             	shl    ecx,0x16
  9aae61:	c1 e0 18             	shl    eax,0x18
  9aae64:	09 c1                	or     ecx,eax
  9aae66:	89 f0                	mov    eax,esi
  9aae68:	ff c0                	inc    eax
  9aae6a:	41 89 cd             	mov    r13d,ecx
  9aae6d:	48 89 8d 40 fb ff ff 	mov    QWORD PTR [rbp-0x4c0],rcx
  9aae74:	48 98                	cdqe
  9aae76:	48 83 c0 1f          	add    rax,0x1f
  9aae7a:	48 83 e0 e0          	and    rax,0xffffffffffffffe0
  9aae7e:	48 39 c7             	cmp    rdi,rax
  9aae81:	48 0f 42 c7          	cmovb  rax,rdi
  9aae85:	44 0b ad b8 fb ff ff 	or     r13d,DWORD PTR [rbp-0x448]
  9aae8c:	eb 64                	jmp    0x9aaef2
  9aae8e:	66 90                	xchg   ax,ax
  9aae90:	48 89 de             	mov    rsi,rbx
  9aae93:	48 8b 9d 50 fb ff ff 	mov    rbx,QWORD PTR [rbp-0x4b0]
  9aae9a:	48 8b bd 80 fb ff ff 	mov    rdi,QWORD PTR [rbp-0x480]
  9aaea1:	4c 8b 85 b0 fb ff ff 	mov    r8,QWORD PTR [rbp-0x450]
  9aaea8:	44 8b 8d b8 fb ff ff 	mov    r9d,DWORD PTR [rbp-0x448]
  9aaeaf:	48 8d 85 c8 fb ff ff 	lea    rax,[rbp-0x438]
  9aaeb6:	48 89 da             	mov    rdx,rbx
  9aaeb9:	50                   	push   rax
  9aaeba:	ff b5 40 fb ff ff    	push   QWORD PTR [rbp-0x4c0]
  9aaec0:	e8 db 3b f4 ff       	call   0x8eeaa0
  9aaec5:	48 89 da             	mov    rdx,rbx
  9aaec8:	48 83 c4 10          	add    rsp,0x10
  9aaecc:	48 8b 8d 48 fb ff ff 	mov    rcx,QWORD PTR [rbp-0x4b8]
  9aaed3:	48 8b b5 90 fb ff ff 	mov    rsi,QWORD PTR [rbp-0x470]
  9aaeda:	49 8d 46 20          	lea    rax,[r14+0x20]
  9aaede:	48 39 c1             	cmp    rcx,rax
  9aaee1:	48 0f 42 c1          	cmovb  rax,rcx
  9aaee5:	44 3b b5 88 fb ff ff 	cmp    r14d,DWORD PTR [rbp-0x478]
  9aaeec:	0f 8d 9e fe ff ff    	jge    0x9aad90
  9aaef2:	4c 63 e6             	movsxd r12,esi
  9aaef5:	48 8b bd 60 fb ff ff 	mov    rdi,QWORD PTR [rbp-0x4a0]
  9aaefc:	89 c1                	mov    ecx,eax
  9aaefe:	45 89 e9             	mov    r9d,r13d
  9aaf01:	41 89 c6             	mov    r14d,eax
  9aaf04:	4c 89 e3             	mov    rbx,r12
  9aaf07:	4f 8d 04 a7          	lea    r8,[r15+r12*4]
  9aaf0b:	44 29 e1             	sub    ecx,r12d
  9aaf0e:	48 c1 e3 10          	shl    rbx,0x10
  9aaf12:	48 03 9d 98 fb ff ff 	add    rbx,QWORD PTR [rbp-0x468]
  9aaf19:	4c 89 85 b0 fb ff ff 	mov    QWORD PTR [rbp-0x450],r8
  9aaf20:	48 89 de             	mov    rsi,rbx
  9aaf23:	e8 08 27 04 00       	call   0x9ed630
  9aaf28:	44 89 f1             	mov    ecx,r14d
  9aaf2b:	4c 89 b5 90 fb ff ff 	mov    QWORD PTR [rbp-0x470],r14
  9aaf32:	4d 63 f6             	movsxd r14,r14d
  9aaf35:	44 29 e1             	sub    ecx,r12d
  9aaf38:	7f 12                	jg     0x9aaf4c
  9aaf3a:	e9 51 ff ff ff       	jmp    0x9aae90
  9aaf3f:	90                   	nop
  9aaf40:	49 ff c4             	inc    r12
  9aaf43:	4d 39 e6             	cmp    r14,r12
  9aaf46:	0f 84 44 ff ff ff    	je     0x9aae90
  9aaf4c:	43 8b 04 a7          	mov    eax,DWORD PTR [r15+r12*4]
  9aaf50:	a9 00 00 00 30       	test   eax,0x30000000
  9aaf55:	74 e9                	je     0x9aaf40
  9aaf57:	25 ff ff 0f f0       	and    eax,0xf00fffff
  9aaf5c:	44 09 e8             	or     eax,r13d
  9aaf5f:	43 89 04 a7          	mov    DWORD PTR [r15+r12*4],eax
  9aaf63:	eb db                	jmp    0x9aaf40
  9aaf65:	48 89 df             	mov    rdi,rbx
  9aaf68:	31 f6                	xor    esi,esi
  9aaf6a:	31 d2                	xor    edx,edx
  9aaf6c:	31 c9                	xor    ecx,ecx
  9aaf6e:	e8 2d c0 b1 ff       	call   0x4c6fa0
  9aaf73:	48 8d 8d d0 fb ff ff 	lea    rcx,[rbp-0x430]
  9aaf7a:	48 3b 8d a8 fb ff ff 	cmp    rcx,QWORD PTR [rbp-0x458]
  9aaf81:	0f 85 d1 00 00 00    	jne    0x9ab058
  9aaf87:	48 c7 85 c8 fb ff ff 	mov    QWORD PTR [rbp-0x438],0x0
  9aaf8e:	00 00 00 00 
  9aaf92:	4c 8b bd 70 fb ff ff 	mov    r15,QWORD PTR [rbp-0x490]
  9aaf99:	8b 85 7c fb ff ff    	mov    eax,DWORD PTR [rbp-0x484]
  9aaf9f:	31 f6                	xor    esi,esi
  9aafa1:	31 d2                	xor    edx,edx
  9aafa3:	49 8d 5f 18          	lea    rbx,[r15+0x18]
  9aafa7:	4c 8d 34 40          	lea    r14,[rax+rax*2]
  9aafab:	48 89 df             	mov    rdi,rbx
  9aafae:	e8 ed 96 e2 ff       	call   0x7d46a0
  9aafb3:	43 c7 84 b7 68 01 00 	mov    DWORD PTR [r15+r14*4+0x168],0xffffffff
  9aafba:	00 ff ff ff ff 
  9aafbf:	43 83 bc b7 70 01 00 	cmp    DWORD PTR [r15+r14*4+0x170],0x0
  9aafc6:	00 00 
  9aafc8:	0f 85 4b 01 00 00    	jne    0x9ab119
  9aafce:	41 83 bf 98 01 00 00 	cmp    DWORD PTR [r15+0x198],0x0
  9aafd5:	00 
  9aafd6:	0f 85 5e 01 00 00    	jne    0x9ab13a
  9aafdc:	48 89 df             	mov    rdi,rbx
  9aafdf:	31 f6                	xor    esi,esi
  9aafe1:	31 d2                	xor    edx,edx
  9aafe3:	e8 c8 9e e2 ff       	call   0x7d4eb0
  9aafe8:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9aafef:	00 00 
  9aaff1:	48 8b 9d a0 fb ff ff 	mov    rbx,QWORD PTR [rbp-0x460]
  9aaff8:	c6 80 17 01 00 00 01 	mov    BYTE PTR [rax+0x117],0x1
  9aafff:	48 8b 85 58 fb ff ff 	mov    rax,QWORD PTR [rbp-0x4a8]
  9ab006:	48 8d 0d 03 13 f7 02 	lea    rcx,[rip+0x2f71303]        # 0x391c310
  9ab00d:	48 89 18             	mov    QWORD PTR [rax],rbx
  9ab010:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  9ab013:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9ab017:	0f 85 38 01 00 00    	jne    0x9ab155
  9ab01d:	8b 85 c0 fb ff ff    	mov    eax,DWORD PTR [rbp-0x440]
  9ab023:	48 81 c4 98 04 00 00 	add    rsp,0x498
  9ab02a:	5b                   	pop    rbx
  9ab02b:	41 5c                	pop    r12
  9ab02d:	41 5d                	pop    r13
  9ab02f:	41 5e                	pop    r14
  9ab031:	41 5f                	pop    r15
  9ab033:	5d                   	pop    rbp
  9ab034:	c3                   	ret
  9ab035:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ab03c:	00 00 00 00 
  9ab040:	48 8b 8d b0 fb ff ff 	mov    rcx,QWORD PTR [rbp-0x450]
  9ab047:	48 83 c1 20          	add    rcx,0x20
  9ab04b:	48 3b 8d a8 fb ff ff 	cmp    rcx,QWORD PTR [rbp-0x458]
  9ab052:	0f 84 00 fd ff ff    	je     0x9aad58
  9ab058:	f6 85 c7 fb ff ff 02 	test   BYTE PTR [rbp-0x439],0x2
  9ab05f:	0f b6 41 19          	movzx  eax,BYTE PTR [rcx+0x19]
  9ab063:	74 1b                	je     0x9ab080
  9ab065:	45 31 ed             	xor    r13d,r13d
  9ab068:	3c 0a                	cmp    al,0xa
  9ab06a:	ba 00 00 c0 00       	mov    edx,0xc00000
  9ab06f:	41 0f 94 c5          	sete   r13b
  9ab073:	41 c1 e5 17          	shl    r13d,0x17
  9ab077:	84 c0                	test   al,al
  9ab079:	44 0f 44 ea          	cmove  r13d,edx
  9ab07d:	eb 18                	jmp    0x9ab097
  9ab07f:	90                   	nop
  9ab080:	04 f5                	add    al,0xf5
  9ab082:	45 31 ed             	xor    r13d,r13d
  9ab085:	3c 09                	cmp    al,0x9
  9ab087:	77 0e                	ja     0x9ab097
  9ab089:	0f b6 c0             	movzx  eax,al
  9ab08c:	48 8d 15 f9 2a f2 00 	lea    rdx,[rip+0xf22af9]        # 0x18cdb8c
  9ab093:	44 8b 2c 82          	mov    r13d,DWORD PTR [rdx+rax*4]
  9ab097:	4c 8b 61 08          	mov    r12,QWORD PTR [rcx+0x8]
  9ab09b:	4c 2b a5 98 fb ff ff 	sub    r12,QWORD PTR [rbp-0x468]
  9ab0a2:	48 89 8d b0 fb ff ff 	mov    QWORD PTR [rbp-0x450],rcx
  9ab0a9:	4c 89 e0             	mov    rax,r12
  9ab0ac:	4c 03 61 10          	add    r12,QWORD PTR [rcx+0x10]
  9ab0b0:	48 c1 e8 10          	shr    rax,0x10
  9ab0b4:	49 c1 ec 10          	shr    r12,0x10
  9ab0b8:	41 29 c4             	sub    r12d,eax
  9ab0bb:	7e 83                	jle    0x9ab040
  9ab0bd:	48 98                	cdqe
  9ab0bf:	31 db                	xor    ebx,ebx
  9ab0c1:	4d 8d 34 87          	lea    r14,[r15+rax*4]
  9ab0c5:	eb 15                	jmp    0x9ab0dc
  9ab0c7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  9ab0ce:	00 00 
  9ab0d0:	48 ff c3             	inc    rbx
  9ab0d3:	41 39 dc             	cmp    r12d,ebx
  9ab0d6:	0f 84 64 ff ff ff    	je     0x9ab040
  9ab0dc:	41 8b 34 9e          	mov    esi,DWORD PTR [r14+rbx*4]
  9ab0e0:	89 f0                	mov    eax,esi
  9ab0e2:	25 00 00 80 30       	and    eax,0x30800000
  9ab0e7:	3d 00 00 80 10       	cmp    eax,0x10800000
  9ab0ec:	75 e2                	jne    0x9ab0d0
  9ab0ee:	89 f0                	mov    eax,esi
  9ab0f0:	25 00 00 f0 00       	and    eax,0xf00000
  9ab0f5:	44 39 e8             	cmp    eax,r13d
  9ab0f8:	74 d6                	je     0x9ab0d0
  9ab0fa:	48 8b bd 90 fb ff ff 	mov    rdi,QWORD PTR [rbp-0x470]
  9ab101:	81 e6 ff ff 0f 00    	and    esi,0xfffff
  9ab107:	e8 f4 13 00 00       	call   0x9ac500
  9ab10c:	eb c2                	jmp    0x9ab0d0
  9ab10e:	89 85 c0 fb ff ff    	mov    DWORD PTR [rbp-0x440],eax
  9ab114:	e9 3a fa ff ff       	jmp    0x9aab53
  9ab119:	4b 8d bc b7 70 01 00 	lea    rdi,[r15+r14*4+0x170]
  9ab120:	00 
  9ab121:	c7 07 00 00 00 00    	mov    DWORD PTR [rdi],0x0
  9ab127:	e8 e4 b7 25 00       	call   0xc06910
  9ab12c:	41 83 bf 98 01 00 00 	cmp    DWORD PTR [r15+0x198],0x0
  9ab133:	00 
  9ab134:	0f 84 a2 fe ff ff    	je     0x9aafdc
  9ab13a:	49 81 c7 98 01 00 00 	add    r15,0x198
  9ab141:	4c 89 ff             	mov    rdi,r15
  9ab144:	41 c7 07 00 00 00 00 	mov    DWORD PTR [r15],0x0
  9ab14b:	e8 c0 b7 25 00       	call   0xc06910
  9ab150:	e9 87 fe ff ff       	jmp    0x9aafdc
  9ab155:	e8 56 25 d5 ff       	call   0x6fd6b0
  9ab15a:	0f 0b                	ud2
  9ab15c:	90                   	nop
  9ab15d:	90                   	nop
  9ab15e:	90                   	nop
  9ab15f:	90                   	nop
  9ab160:	55                   	push   rbp
  9ab161:	48 89 e5             	mov    rbp,rsp
  9ab164:	41 83 78 04 00       	cmp    DWORD PTR [r8+0x4],0x0
  9ab169:	b8 16 00 00 00       	mov    eax,0x16
  9ab16e:	75 78                	jne    0x9ab1e8
  9ab170:	49 89 ca             	mov    r10,rcx
  9ab173:	49 8b 48 08          	mov    rcx,QWORD PTR [r8+0x8]
  9ab177:	4d 89 c1             	mov    r9,r8
  9ab17a:	44 0f b7 c1          	movzx  r8d,cx
  9ab17e:	4d 85 c0             	test   r8,r8
  9ab181:	75 65                	jne    0x9ab1e8
  9ab183:	4d 8b 41 10          	mov    r8,QWORD PTR [r9+0x10]
  9ab187:	45 0f b7 d8          	movzx  r11d,r8w
  9ab18b:	4d 85 db             	test   r11,r11
  9ab18e:	75 58                	jne    0x9ab1e8
  9ab190:	4d 8b 49 18          	mov    r9,QWORD PTR [r9+0x18]
  9ab194:	45 0f b7 d9          	movzx  r11d,r9w
  9ab198:	4d 85 db             	test   r11,r11
  9ab19b:	75 4b                	jne    0x9ab1e8
  9ab19d:	48 39 ca             	cmp    rdx,rcx
  9ab1a0:	77 46                	ja     0x9ab1e8
  9ab1a2:	49 39 ca             	cmp    r10,rcx
  9ab1a5:	76 41                	jbe    0x9ab1e8
  9ab1a7:	4d 89 d3             	mov    r11,r10
  9ab1aa:	49 29 cb             	sub    r11,rcx
  9ab1ad:	4d 39 cb             	cmp    r11,r9
  9ab1b0:	72 36                	jb     0x9ab1e8
  9ab1b2:	4c 39 c2             	cmp    rdx,r8
  9ab1b5:	77 31                	ja     0x9ab1e8
  9ab1b7:	4d 39 c2             	cmp    r10,r8
  9ab1ba:	76 2c                	jbe    0x9ab1e8
  9ab1bc:	4d 29 c2             	sub    r10,r8
  9ab1bf:	4d 39 ca             	cmp    r10,r9
  9ab1c2:	72 24                	jb     0x9ab1e8
  9ab1c4:	31 c0                	xor    eax,eax
  9ab1c6:	4d 85 c9             	test   r9,r9
  9ab1c9:	74 1d                	je     0x9ab1e8
  9ab1cb:	49 39 c8             	cmp    r8,rcx
  9ab1ce:	74 18                	je     0x9ab1e8
  9ab1d0:	48 29 d1             	sub    rcx,rdx
  9ab1d3:	49 29 d0             	sub    r8,rdx
  9ab1d6:	49 c1 e9 10          	shr    r9,0x10
  9ab1da:	48 c1 e9 10          	shr    rcx,0x10
  9ab1de:	49 c1 e8 10          	shr    r8,0x10
  9ab1e2:	5d                   	pop    rbp
  9ab1e3:	e9 88 01 00 00       	jmp    0x9ab370
  9ab1e8:	5d                   	pop    rbp
  9ab1e9:	c3                   	ret
  9ab1ea:	90                   	nop
  9ab1eb:	90                   	nop
  9ab1ec:	90                   	nop
  9ab1ed:	90                   	nop
  9ab1ee:	90                   	nop
  9ab1ef:	90                   	nop
  9ab1f0:	55                   	push   rbp
  9ab1f1:	48 89 e5             	mov    rbp,rsp
  9ab1f4:	41 57                	push   r15
  9ab1f6:	41 56                	push   r14
  9ab1f8:	41 55                	push   r13
  9ab1fa:	41 54                	push   r12
  9ab1fc:	53                   	push   rbx
  9ab1fd:	48 83 ec 18          	sub    rsp,0x18
  9ab201:	4c 8d 2d 08 11 f7 02 	lea    r13,[rip+0x2f71108]        # 0x391c310
  9ab208:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  9ab20c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ab210:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  9ab214:	4c 8b 36             	mov    r14,QWORD PTR [rsi]
  9ab217:	48 8b 98 00 02 00 00 	mov    rbx,QWORD PTR [rax+0x200]
  9ab21e:	b8 16 00 00 00       	mov    eax,0x16
  9ab223:	48 8b 7b 20          	mov    rdi,QWORD PTR [rbx+0x20]
  9ab227:	4c 39 f7             	cmp    rdi,r14
  9ab22a:	77 29                	ja     0x9ab255
  9ab22c:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  9ab230:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
  9ab234:	48 89 ca             	mov    rdx,rcx
  9ab237:	4c 29 f2             	sub    rdx,r14
  9ab23a:	41 0f 96 c0          	setbe  r8b
  9ab23e:	66 45 85 f6          	test   r14w,r14w
  9ab242:	41 0f 95 c1          	setne  r9b
  9ab246:	45 08 c1             	or     r9b,r8b
  9ab249:	4c 39 ff             	cmp    rdi,r15
  9ab24c:	40 0f 97 c7          	seta   dil
  9ab250:	44 08 cf             	or     dil,r9b
  9ab253:	74 1d                	je     0x9ab272
  9ab255:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  9ab259:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  9ab25d:	0f 85 ff 00 00 00    	jne    0x9ab362
  9ab263:	48 83 c4 18          	add    rsp,0x18
  9ab267:	5b                   	pop    rbx
  9ab268:	41 5c                	pop    r12
  9ab26a:	41 5d                	pop    r13
  9ab26c:	41 5e                	pop    r14
  9ab26e:	41 5f                	pop    r15
  9ab270:	5d                   	pop    rbp
  9ab271:	c3                   	ret
  9ab272:	66 45 85 ff          	test   r15w,r15w
  9ab276:	75 dd                	jne    0x9ab255
  9ab278:	4c 29 f9             	sub    rcx,r15
  9ab27b:	76 d8                	jbe    0x9ab255
  9ab27d:	4c 8b 66 10          	mov    r12,QWORD PTR [rsi+0x10]
  9ab281:	41 0f b7 fc          	movzx  edi,r12w
  9ab285:	48 85 ff             	test   rdi,rdi
  9ab288:	75 cb                	jne    0x9ab255
  9ab28a:	4c 39 e2             	cmp    rdx,r12
  9ab28d:	72 c6                	jb     0x9ab255
  9ab28f:	4c 39 e1             	cmp    rcx,r12
  9ab292:	72 c1                	jb     0x9ab255
  9ab294:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  9ab298:	75 bb                	jne    0x9ab255
  9ab29a:	48 89 df             	mov    rdi,rbx
  9ab29d:	31 f6                	xor    esi,esi
  9ab29f:	31 d2                	xor    edx,edx
  9ab2a1:	e8 7a b5 91 ff       	call   0x2c6820
  9ab2a6:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  9ab2aa:	48 89 df             	mov    rdi,rbx
  9ab2ad:	4c 89 f6             	mov    rsi,r14
  9ab2b0:	e8 8b b9 91 ff       	call   0x2c6c40
  9ab2b5:	89 c1                	mov    ecx,eax
  9ab2b7:	b8 16 00 00 00       	mov    eax,0x16
  9ab2bc:	85 c9                	test   ecx,ecx
  9ab2be:	0f 84 89 00 00 00    	je     0x9ab34d
  9ab2c4:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
  9ab2c8:	f6 41 60 02          	test   BYTE PTR [rcx+0x60],0x2
  9ab2cc:	75 7f                	jne    0x9ab34d
  9ab2ce:	48 8b 71 50          	mov    rsi,QWORD PTR [rcx+0x50]
  9ab2d2:	48 85 f6             	test   rsi,rsi
  9ab2d5:	74 76                	je     0x9ab34d
  9ab2d7:	80 be 9d 00 00 00 0b 	cmp    BYTE PTR [rsi+0x9d],0xb
  9ab2de:	75 6d                	jne    0x9ab34d
  9ab2e0:	48 8b 79 28          	mov    rdi,QWORD PTR [rcx+0x28]
  9ab2e4:	48 89 fa             	mov    rdx,rdi
  9ab2e7:	4c 29 f2             	sub    rdx,r14
  9ab2ea:	4c 39 e2             	cmp    rdx,r12
  9ab2ed:	72 5e                	jb     0x9ab34d
  9ab2ef:	48 8b 51 20          	mov    rdx,QWORD PTR [rcx+0x20]
  9ab2f3:	4c 39 fa             	cmp    rdx,r15
  9ab2f6:	0f 97 c1             	seta   cl
  9ab2f9:	4c 29 ff             	sub    rdi,r15
  9ab2fc:	41 0f 96 c0          	setbe  r8b
  9ab300:	41 08 c8             	or     r8b,cl
  9ab303:	4c 39 e7             	cmp    rdi,r12
  9ab306:	0f 92 c1             	setb   cl
  9ab309:	44 08 c1             	or     cl,r8b
  9ab30c:	75 3f                	jne    0x9ab34d
  9ab30e:	4d 85 e4             	test   r12,r12
  9ab311:	0f 94 c1             	sete   cl
  9ab314:	4d 39 f7             	cmp    r15,r14
  9ab317:	40 0f 94 c7          	sete   dil
  9ab31b:	31 c0                	xor    eax,eax
  9ab31d:	40 08 cf             	or     dil,cl
  9ab320:	75 2b                	jne    0x9ab34d
  9ab322:	49 29 d6             	sub    r14,rdx
  9ab325:	49 29 d7             	sub    r15,rdx
  9ab328:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  9ab32f:	01 
  9ab330:	49 c1 ec 10          	shr    r12,0x10
  9ab334:	48 89 df             	mov    rdi,rbx
  9ab337:	49 c1 ee 10          	shr    r14,0x10
  9ab33b:	49 c1 ef 10          	shr    r15,0x10
  9ab33f:	45 89 e1             	mov    r9d,r12d
  9ab342:	44 89 f1             	mov    ecx,r14d
  9ab345:	45 89 f8             	mov    r8d,r15d
  9ab348:	e8 23 00 00 00       	call   0x9ab370
  9ab34d:	48 89 df             	mov    rdi,rbx
  9ab350:	31 f6                	xor    esi,esi
  9ab352:	31 d2                	xor    edx,edx
  9ab354:	89 c3                	mov    ebx,eax
  9ab356:	e8 15 b5 91 ff       	call   0x2c6870
  9ab35b:	89 d8                	mov    eax,ebx
  9ab35d:	e9 f3 fe ff ff       	jmp    0x9ab255
  9ab362:	e8 49 23 d5 ff       	call   0x6fd6b0
  9ab367:	0f 0b                	ud2
  9ab369:	90                   	nop
  9ab36a:	90                   	nop
  9ab36b:	90                   	nop
  9ab36c:	90                   	nop
  9ab36d:	90                   	nop
  9ab36e:	90                   	nop
  9ab36f:	90                   	nop
  9ab370:	55                   	push   rbp
  9ab371:	48 89 e5             	mov    rbp,rsp
  9ab374:	41 57                	push   r15
  9ab376:	41 56                	push   r14
  9ab378:	41 55                	push   r13
  9ab37a:	41 54                	push   r12
  9ab37c:	53                   	push   rbx
  9ab37d:	48 81 ec a8 00 00 00 	sub    rsp,0xa8
  9ab384:	48 8d 05 85 0f f7 02 	lea    rax,[rip+0x2f70f85]        # 0x391c310
  9ab38b:	48 89 95 40 ff ff ff 	mov    QWORD PTR [rbp-0xc0],rdx
  9ab392:	48 89 bd 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rdi
  9ab399:	41 89 cf             	mov    r15d,ecx
  9ab39c:	49 89 f5             	mov    r13,rsi
  9ab39f:	44 89 c2             	mov    edx,r8d
  9ab3a2:	43 8d 7c 01 1f       	lea    edi,[r9+r8*1+0x1f]
  9ab3a7:	41 89 ce             	mov    r14d,ecx
  9ab3aa:	83 e2 e0             	and    edx,0xffffffe0
  9ab3ad:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ab3b0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ab3b4:	4c 89 8d 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],r9
  9ab3bb:	4c 89 6d b8          	mov    QWORD PTR [rbp-0x48],r13
  9ab3bf:	4c 89 85 60 ff ff ff 	mov    QWORD PTR [rbp-0xa0],r8
  9ab3c6:	48 8b 86 e8 00 00 00 	mov    rax,QWORD PTR [rsi+0xe8]
  9ab3cd:	43 8d 74 39 1f       	lea    esi,[r9+r15*1+0x1f]
  9ab3d2:	4d 8b a5 60 01 00 00 	mov    r12,QWORD PTR [r13+0x160]
  9ab3d9:	49 8b 9d 90 01 00 00 	mov    rbx,QWORD PTR [r13+0x190]
  9ab3e0:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  9ab3e7:	00 
  9ab3e8:	83 e6 e0             	and    esi,0xffffffe0
  9ab3eb:	39 f2                	cmp    edx,esi
  9ab3ed:	48 89 85 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rax
  9ab3f4:	0f 9d c0             	setge  al
  9ab3f7:	41 83 e6 e0          	and    r14d,0xffffffe0
  9ab3fb:	83 e7 e0             	and    edi,0xffffffe0
  9ab3fe:	41 39 fe             	cmp    r14d,edi
  9ab401:	0f 9d c1             	setge  cl
  9ab404:	08 c1                	or     cl,al
  9ab406:	43 8d 0c 39          	lea    ecx,[r9+r15*1]
  9ab40a:	43 8d 04 01          	lea    eax,[r9+r8*1]
  9ab40e:	89 4d a8             	mov    DWORD PTR [rbp-0x58],ecx
  9ab411:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
  9ab414:	75 31                	jne    0x9ab447
  9ab416:	45 39 c7             	cmp    r15d,r8d
  9ab419:	44 89 c6             	mov    esi,r8d
  9ab41c:	89 c2                	mov    edx,eax
  9ab41e:	4c 89 ef             	mov    rdi,r13
  9ab421:	4d 89 c6             	mov    r14,r8
  9ab424:	41 89 c5             	mov    r13d,eax
  9ab427:	41 0f 4c f7          	cmovl  esi,r15d
  9ab42b:	39 c1                	cmp    ecx,eax
  9ab42d:	0f 4f d1             	cmovg  edx,ecx
  9ab430:	e8 4b cc ff ff       	call   0x9a8080
  9ab435:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
  9ab439:	b8 ff ff ff ff       	mov    eax,0xffffffff
  9ab43e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  9ab442:	e9 f3 02 00 00       	jmp    0x9ab73a
  9ab447:	89 7d 90             	mov    DWORD PTR [rbp-0x70],edi
  9ab44a:	49 8d 7d 18          	lea    rdi,[r13+0x18]
  9ab44e:	89 75 98             	mov    DWORD PTR [rbp-0x68],esi
  9ab451:	89 55 88             	mov    DWORD PTR [rbp-0x78],edx
  9ab454:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
  9ab45b:	00 
  9ab45c:	31 f6                	xor    esi,esi
  9ab45e:	31 d2                	xor    edx,edx
  9ab460:	48 89 bd 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rdi
  9ab467:	e8 34 92 e2 ff       	call   0x7d46a0
  9ab46c:	4d 8d 8d 68 01 00 00 	lea    r9,[r13+0x168]
  9ab473:	4d 8d 95 98 01 00 00 	lea    r10,[r13+0x198]
  9ab47a:	4d 8d 9d 74 01 00 00 	lea    r11,[r13+0x174]
  9ab481:	49 8d 95 80 01 00 00 	lea    rdx,[r13+0x180]
  9ab488:	41 8b 01             	mov    eax,DWORD PTR [r9]
  9ab48b:	44 8b 45 98          	mov    r8d,DWORD PTR [rbp-0x68]
  9ab48f:	85 c0                	test   eax,eax
  9ab491:	0f 89 00 01 00 00    	jns    0x9ab597
  9ab497:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  9ab49b:	83 fe 01             	cmp    esi,0x1
  9ab49e:	7f 40                	jg     0x9ab4e0
  9ab4a0:	89 f0                	mov    eax,esi
  9ab4a2:	ff c6                	inc    esi
  9ab4a4:	c7 44 85 c8 00 00 00 	mov    DWORD PTR [rbp+rax*4-0x38],0x0
  9ab4ab:	00 
  9ab4ac:	41 8b 03             	mov    eax,DWORD PTR [r11]
  9ab4af:	85 c0                	test   eax,eax
  9ab4b1:	0f 89 0d 01 00 00    	jns    0x9ab5c4
  9ab4b7:	41 bd 02 00 00 00    	mov    r13d,0x2
  9ab4bd:	83 fe 01             	cmp    esi,0x1
  9ab4c0:	7f 34                	jg     0x9ab4f6
  9ab4c2:	89 f0                	mov    eax,esi
  9ab4c4:	ff c6                	inc    esi
  9ab4c6:	c7 44 85 c8 01 00 00 	mov    DWORD PTR [rbp+rax*4-0x38],0x1
  9ab4cd:	00 
  9ab4ce:	41 89 f5             	mov    r13d,esi
  9ab4d1:	eb 23                	jmp    0x9ab4f6
  9ab4d3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ab4da:	84 00 00 00 00 00 
  9ab4e0:	41 8b 03             	mov    eax,DWORD PTR [r11]
  9ab4e3:	be 02 00 00 00       	mov    esi,0x2
  9ab4e8:	41 bd 02 00 00 00    	mov    r13d,0x2
  9ab4ee:	85 c0                	test   eax,eax
  9ab4f0:	0f 89 ce 00 00 00    	jns    0x9ab5c4
  9ab4f6:	8b 02                	mov    eax,DWORD PTR [rdx]
  9ab4f8:	85 c0                	test   eax,eax
  9ab4fa:	0f 89 f6 00 00 00    	jns    0x9ab5f6
  9ab500:	41 83 fd 01          	cmp    r13d,0x1
  9ab504:	0f 8f d3 01 00 00    	jg     0x9ab6dd
  9ab50a:	44 89 e8             	mov    eax,r13d
  9ab50d:	41 ff c5             	inc    r13d
  9ab510:	c7 44 85 c8 02 00 00 	mov    DWORD PTR [rbp+rax*4-0x38],0x2
  9ab517:	00 
  9ab518:	41 83 fd 02          	cmp    r13d,0x2
  9ab51c:	0f 84 bb 01 00 00    	je     0x9ab6dd
  9ab522:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  9ab526:	4c 89 9d 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],r11
  9ab52d:	4c 89 8d 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],r9
  9ab534:	41 c7 02 01 00 00 00 	mov    DWORD PTR [r10],0x1
  9ab53b:	4c 89 55 80          	mov    QWORD PTR [rbp-0x80],r10
  9ab53f:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  9ab543:	4c 89 d7             	mov    rdi,r10
  9ab546:	ba 44 00 00 00       	mov    edx,0x44
  9ab54b:	48 8d 0d 7f 96 9e 00 	lea    rcx,[rip+0x9e967f]        # 0x1394bd1
  9ab552:	c7 04 24 00 01 00 00 	mov    DWORD PTR [rsp],0x100
  9ab559:	45 31 c0             	xor    r8d,r8d
  9ab55c:	45 31 c9             	xor    r9d,r9d
  9ab55f:	e8 fc ac 25 00       	call   0xc06260
  9ab564:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9ab568:	4c 8b 55 80          	mov    r10,QWORD PTR [rbp-0x80]
  9ab56c:	83 b8 98 01 00 00 00 	cmp    DWORD PTR [rax+0x198],0x0
  9ab573:	75 ca                	jne    0x9ab53f
  9ab575:	44 89 e8             	mov    eax,r13d
  9ab578:	4c 8b 6d b8          	mov    r13,QWORD PTR [rbp-0x48]
  9ab57c:	4c 8b 8d 48 ff ff ff 	mov    r9,QWORD PTR [rbp-0xb8]
  9ab583:	4c 8b 9d 50 ff ff ff 	mov    r11,QWORD PTR [rbp-0xb0]
  9ab58a:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9ab58e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  9ab592:	e9 f1 fe ff ff       	jmp    0x9ab488
  9ab597:	41 8b 8d 6c 01 00 00 	mov    ecx,DWORD PTR [r13+0x16c]
  9ab59e:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  9ab5a2:	41 39 ce             	cmp    r14d,ecx
  9ab5a5:	0f 9c c2             	setl   dl
  9ab5a8:	44 39 c0             	cmp    eax,r8d
  9ab5ab:	40 0f 9c c6          	setl   sil
  9ab5af:	40 84 d6             	test   sil,dl
  9ab5b2:	74 69                	je     0x9ab61d
  9ab5b4:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9ab5b8:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  9ab5bc:	4c 89 cf             	mov    rdi,r9
  9ab5bf:	e9 b4 00 00 00       	jmp    0x9ab678
  9ab5c4:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  9ab5c8:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  9ab5cc:	49 89 f5             	mov    r13,rsi
  9ab5cf:	8b 89 78 01 00 00    	mov    ecx,DWORD PTR [rcx+0x178]
  9ab5d5:	41 39 ce             	cmp    r14d,ecx
  9ab5d8:	0f 9c c2             	setl   dl
  9ab5db:	44 39 c0             	cmp    eax,r8d
  9ab5de:	40 0f 9c c6          	setl   sil
  9ab5e2:	40 84 d6             	test   sil,dl
  9ab5e5:	74 57                	je     0x9ab63e
  9ab5e7:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9ab5eb:	4c 89 df             	mov    rdi,r11
  9ab5ee:	4c 89 ee             	mov    rsi,r13
  9ab5f1:	e9 82 00 00 00       	jmp    0x9ab678
  9ab5f6:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  9ab5fa:	48 89 d7             	mov    rdi,rdx
  9ab5fd:	8b 89 84 01 00 00    	mov    ecx,DWORD PTR [rcx+0x184]
  9ab603:	41 39 ce             	cmp    r14d,ecx
  9ab606:	0f 9c c2             	setl   dl
  9ab609:	44 39 c0             	cmp    eax,r8d
  9ab60c:	40 0f 9c c6          	setl   sil
  9ab610:	40 84 d6             	test   sil,dl
  9ab613:	74 49                	je     0x9ab65e
  9ab615:	44 89 ee             	mov    esi,r13d
  9ab618:	48 89 fa             	mov    rdx,rdi
  9ab61b:	eb 5b                	jmp    0x9ab678
  9ab61d:	39 4d 88             	cmp    DWORD PTR [rbp-0x78],ecx
  9ab620:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9ab624:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  9ab628:	4c 89 cf             	mov    rdi,r9
  9ab62b:	0f 9d c1             	setge  cl
  9ab62e:	3b 45 90             	cmp    eax,DWORD PTR [rbp-0x70]
  9ab631:	0f 9d c0             	setge  al
  9ab634:	08 c8                	or     al,cl
  9ab636:	0f 85 70 fe ff ff    	jne    0x9ab4ac
  9ab63c:	eb 3a                	jmp    0x9ab678
  9ab63e:	39 4d 88             	cmp    DWORD PTR [rbp-0x78],ecx
  9ab641:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9ab645:	4c 89 df             	mov    rdi,r11
  9ab648:	4c 89 ee             	mov    rsi,r13
  9ab64b:	0f 9c c1             	setl   cl
  9ab64e:	3b 45 90             	cmp    eax,DWORD PTR [rbp-0x70]
  9ab651:	0f 9c c0             	setl   al
  9ab654:	84 c8                	test   al,cl
  9ab656:	0f 84 9a fe ff ff    	je     0x9ab4f6
  9ab65c:	eb 1a                	jmp    0x9ab678
  9ab65e:	39 4d 88             	cmp    DWORD PTR [rbp-0x78],ecx
  9ab661:	44 89 ee             	mov    esi,r13d
  9ab664:	48 89 fa             	mov    rdx,rdi
  9ab667:	0f 9c c1             	setl   cl
  9ab66a:	3b 45 90             	cmp    eax,DWORD PTR [rbp-0x70]
  9ab66d:	0f 9c c0             	setl   al
  9ab670:	84 c8                	test   al,cl
  9ab672:	0f 84 a0 fe ff ff    	je     0x9ab518
  9ab678:	4c 8b 6d b8          	mov    r13,QWORD PTR [rbp-0x48]
  9ab67c:	c7 47 08 01 00 00 00 	mov    DWORD PTR [rdi+0x8],0x1
  9ab683:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
  9ab687:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  9ab68b:	48 83 c7 08          	add    rdi,0x8
  9ab68f:	ba 44 00 00 00       	mov    edx,0x44
  9ab694:	48 8d 0d 00 a8 9c 00 	lea    rcx,[rip+0x9ca800]        # 0x1375e9b
  9ab69b:	4c 89 8d 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],r9
  9ab6a2:	c7 04 24 00 01 00 00 	mov    DWORD PTR [rsp],0x100
  9ab6a9:	45 31 c0             	xor    r8d,r8d
  9ab6ac:	45 31 c9             	xor    r9d,r9d
  9ab6af:	4c 89 55 80          	mov    QWORD PTR [rbp-0x80],r10
  9ab6b3:	4c 89 9d 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],r11
  9ab6ba:	4c 89 ee             	mov    rsi,r13
  9ab6bd:	e8 9e ab 25 00       	call   0xc06260
  9ab6c2:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  9ab6c6:	4c 8b 9d 50 ff ff ff 	mov    r11,QWORD PTR [rbp-0xb0]
  9ab6cd:	4c 8b 55 80          	mov    r10,QWORD PTR [rbp-0x80]
  9ab6d1:	4c 8b 8d 48 ff ff ff 	mov    r9,QWORD PTR [rbp-0xb8]
  9ab6d8:	e9 ab fd ff ff       	jmp    0x9ab488
  9ab6dd:	48 63 45 c8          	movsxd rax,DWORD PTR [rbp-0x38]
  9ab6e1:	8b 4d 88             	mov    ecx,DWORD PTR [rbp-0x78]
  9ab6e4:	8b 7d 90             	mov    edi,DWORD PTR [rbp-0x70]
  9ab6e7:	31 f6                	xor    esi,esi
  9ab6e9:	31 d2                	xor    edx,edx
  9ab6eb:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
  9ab6ef:	48 8d 04 40          	lea    rax,[rax+rax*2]
  9ab6f3:	45 89 34 81          	mov    DWORD PTR [r9+rax*4],r14d
  9ab6f7:	45 89 44 81 04       	mov    DWORD PTR [r9+rax*4+0x4],r8d
  9ab6fc:	41 c7 44 81 08 00 00 	mov    DWORD PTR [r9+rax*4+0x8],0x0
  9ab703:	00 00 
  9ab705:	48 63 45 cc          	movsxd rax,DWORD PTR [rbp-0x34]
  9ab709:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  9ab70d:	48 8d 04 40          	lea    rax,[rax+rax*2]
  9ab711:	41 89 0c 81          	mov    DWORD PTR [r9+rax*4],ecx
  9ab715:	41 89 7c 81 04       	mov    DWORD PTR [r9+rax*4+0x4],edi
  9ab71a:	48 8b bd 68 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x98]
  9ab721:	41 c7 44 81 08 00 00 	mov    DWORD PTR [r9+rax*4+0x8],0x0
  9ab728:	00 00 
  9ab72a:	e8 81 97 e2 ff       	call   0x7d4eb0
  9ab72f:	4c 8b b5 60 ff ff ff 	mov    r14,QWORD PTR [rbp-0xa0]
  9ab736:	44 8b 6d ac          	mov    r13d,DWORD PTR [rbp-0x54]
  9ab73a:	49 63 c7             	movsxd rax,r15d
  9ab73d:	4d 63 cd             	movsxd r9,r13d
  9ab740:	4d 89 f0             	mov    r8,r14
  9ab743:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  9ab747:	45 39 f7             	cmp    r15d,r14d
  9ab74a:	7d 4a                	jge    0x9ab796
  9ab74c:	8b 75 a8             	mov    esi,DWORD PTR [rbp-0x58]
  9ab74f:	4c 8b ad 58 ff ff ff 	mov    r13,QWORD PTR [rbp-0xa8]
  9ab756:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9ab75d:	4c 8b 95 78 ff ff ff 	mov    r10,QWORD PTR [rbp-0x88]
  9ab764:	44 39 fe             	cmp    esi,r15d
  9ab767:	0f 8e 85 00 00 00    	jle    0x9ab7f2
  9ab76d:	48 8b 4d b0          	mov    rcx,QWORD PTR [rbp-0x50]
  9ab771:	44 39 c6             	cmp    esi,r8d
  9ab774:	44 89 c0             	mov    eax,r8d
  9ab777:	0f 4c c6             	cmovl  eax,esi
  9ab77a:	48 98                	cdqe
  9ab77c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  9ab780:	41 f6 44 8c 03 30    	test   BYTE PTR [r12+rcx*4+0x3],0x30
  9ab786:	0f 85 b5 02 00 00    	jne    0x9aba41
  9ab78c:	48 ff c1             	inc    rcx
  9ab78f:	48 39 c1             	cmp    rcx,rax
  9ab792:	7c ec                	jl     0x9ab780
  9ab794:	eb 5c                	jmp    0x9ab7f2
  9ab796:	45 39 fd             	cmp    r13d,r15d
  9ab799:	44 89 fa             	mov    edx,r15d
  9ab79c:	8b 75 a8             	mov    esi,DWORD PTR [rbp-0x58]
  9ab79f:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9ab7a6:	4c 8b 95 78 ff ff ff 	mov    r10,QWORD PTR [rbp-0x88]
  9ab7ad:	41 0f 4f d5          	cmovg  edx,r13d
  9ab7b1:	4c 8b ad 58 ff ff ff 	mov    r13,QWORD PTR [rbp-0xa8]
  9ab7b8:	39 f2                	cmp    edx,esi
  9ab7ba:	7d 36                	jge    0x9ab7f2
  9ab7bc:	48 8b 4d b0          	mov    rcx,QWORD PTR [rbp-0x50]
  9ab7c0:	4c 89 c8             	mov    rax,r9
  9ab7c3:	4c 39 c9             	cmp    rcx,r9
  9ab7c6:	48 0f 4f c1          	cmovg  rax,rcx
  9ab7ca:	89 f1                	mov    ecx,esi
  9ab7cc:	29 d1                	sub    ecx,edx
  9ab7ce:	49 8d 04 84          	lea    rax,[r12+rax*4]
  9ab7d2:	31 d2                	xor    edx,edx
  9ab7d4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ab7db:	00 00 00 00 00 
  9ab7e0:	f6 44 90 03 30       	test   BYTE PTR [rax+rdx*4+0x3],0x30
  9ab7e5:	0f 85 56 02 00 00    	jne    0x9aba41
  9ab7eb:	48 ff c2             	inc    rdx
  9ab7ee:	39 d1                	cmp    ecx,edx
  9ab7f0:	75 ee                	jne    0x9ab7e0
  9ab7f2:	4c 89 4d 88          	mov    QWORD PTR [rbp-0x78],r9
  9ab7f6:	45 31 f6             	xor    r14d,r14d
  9ab7f9:	41 39 f7             	cmp    r15d,esi
  9ab7fc:	7d 6b                	jge    0x9ab869
  9ab7fe:	48 63 45 a8          	movsxd rax,DWORD PTR [rbp-0x58]
  9ab802:	48 2b 45 b0          	sub    rax,QWORD PTR [rbp-0x50]
  9ab806:	b9 00 00 00 30       	mov    ecx,0x30000000
  9ab80b:	44 89 c2             	mov    edx,r8d
  9ab80e:	44 89 fe             	mov    esi,r15d
  9ab811:	45 31 f6             	xor    r14d,r14d
  9ab814:	eb 13                	jmp    0x9ab829
  9ab816:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  9ab81d:	00 00 00 
  9ab820:	ff c6                	inc    esi
  9ab822:	ff c2                	inc    edx
  9ab824:	48 ff c8             	dec    rax
  9ab827:	74 40                	je     0x9ab869
  9ab829:	4c 63 ca             	movsxd r9,edx
  9ab82c:	47 8b 0c 8c          	mov    r9d,DWORD PTR [r12+r9*4]
  9ab830:	41 21 c9             	and    r9d,ecx
  9ab833:	41 81 f9 00 00 00 10 	cmp    r9d,0x10000000
  9ab83a:	75 e4                	jne    0x9ab820
  9ab83c:	89 f7                	mov    edi,esi
  9ab83e:	c1 ff 05             	sar    edi,0x5
  9ab841:	48 63 ff             	movsxd rdi,edi
  9ab844:	44 0f b6 14 3b       	movzx  r10d,BYTE PTR [rbx+rdi*1]
  9ab849:	45 8d 4a 01          	lea    r9d,[r10+0x1]
  9ab84d:	41 80 fa 01          	cmp    r10b,0x1
  9ab851:	4c 8b 95 78 ff ff ff 	mov    r10,QWORD PTR [rbp-0x88]
  9ab858:	44 88 0c 3b          	mov    BYTE PTR [rbx+rdi*1],r9b
  9ab85c:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9ab863:	41 83 d6 00          	adc    r14d,0x0
  9ab867:	eb b7                	jmp    0x9ab820
  9ab869:	49 63 d0             	movsxd rdx,r8d
  9ab86c:	4d 89 eb             	mov    r11,r13
  9ab86f:	48 89 55 90          	mov    QWORD PTR [rbp-0x70],rdx
  9ab873:	44 3b 45 ac          	cmp    r8d,DWORD PTR [rbp-0x54]
  9ab877:	7d 68                	jge    0x9ab8e1
  9ab879:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
  9ab87d:	44 89 c1             	mov    ecx,r8d
  9ab880:	41 bd 00 00 00 30    	mov    r13d,0x30000000
  9ab886:	31 f6                	xor    esi,esi
  9ab888:	48 29 d0             	sub    rax,rdx
  9ab88b:	49 8d 14 94          	lea    rdx,[r12+rdx*4]
  9ab88f:	eb 17                	jmp    0x9ab8a8
  9ab891:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ab898:	0f 1f 84 00 00 00 00 
  9ab89f:	00 
  9ab8a0:	48 ff c6             	inc    rsi
  9ab8a3:	48 39 f0             	cmp    rax,rsi
  9ab8a6:	74 39                	je     0x9ab8e1
  9ab8a8:	44 8b 0c b2          	mov    r9d,DWORD PTR [rdx+rsi*4]
  9ab8ac:	45 21 e9             	and    r9d,r13d
  9ab8af:	41 81 f9 00 00 00 10 	cmp    r9d,0x10000000
  9ab8b6:	75 e8                	jne    0x9ab8a0
  9ab8b8:	44 8d 0c 31          	lea    r9d,[rcx+rsi*1]
  9ab8bc:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9ab8c3:	41 c1 f9 05          	sar    r9d,0x5
  9ab8c7:	4d 63 d1             	movsxd r10,r9d
  9ab8ca:	45 31 c9             	xor    r9d,r9d
  9ab8cd:	42 fe 0c 13          	dec    BYTE PTR [rbx+r10*1]
  9ab8d1:	4c 8b 95 78 ff ff ff 	mov    r10,QWORD PTR [rbp-0x88]
  9ab8d8:	41 0f 94 c1          	sete   r9b
  9ab8dc:	45 29 ce             	sub    r14d,r9d
  9ab8df:	eb bf                	jmp    0x9ab8a0
  9ab8e1:	45 85 f6             	test   r14d,r14d
  9ab8e4:	7e 35                	jle    0x9ab91b
  9ab8e6:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9ab8ea:	44 89 f6             	mov    esi,r14d
  9ab8ed:	4d 89 c5             	mov    r13,r8
  9ab8f0:	0f b6 b8 9c 01 00 00 	movzx  edi,BYTE PTR [rax+0x19c]
  9ab8f7:	e8 54 1c f4 ff       	call   0x8ed550
  9ab8fc:	4c 8b 95 78 ff ff ff 	mov    r10,QWORD PTR [rbp-0x88]
  9ab903:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  9ab90a:	4c 8b 9d 58 ff ff ff 	mov    r11,QWORD PTR [rbp-0xa8]
  9ab911:	4d 89 e8             	mov    r8,r13
  9ab914:	41 89 c5             	mov    r13d,eax
  9ab917:	85 c0                	test   eax,eax
  9ab919:	75 6a                	jne    0x9ab985
  9ab91b:	49 8b 72 30          	mov    rsi,QWORD PTR [r10+0x30]
  9ab91f:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9ab926:	00 00 
  9ab928:	31 c9                	xor    ecx,ecx
  9ab92a:	80 b8 16 01 00 00 00 	cmp    BYTE PTR [rax+0x116],0x0
  9ab931:	4c 8b ad 40 ff ff ff 	mov    r13,QWORD PTR [rbp-0xc0]
  9ab938:	4d 89 e1             	mov    r9,r12
  9ab93b:	44 89 1c 24          	mov    DWORD PTR [rsp],r11d
  9ab93f:	4c 89 ea             	mov    rdx,r13
  9ab942:	0f 94 c1             	sete   cl
  9ab945:	89 4c 24 08          	mov    DWORD PTR [rsp+0x8],ecx
  9ab949:	44 89 f9             	mov    ecx,r15d
  9ab94c:	e8 6f 25 04 00       	call   0x9edec0
  9ab951:	89 85 68 ff ff ff    	mov    DWORD PTR [rbp-0x98],eax
  9ab957:	85 c0                	test   eax,eax
  9ab959:	0f 84 f4 00 00 00    	je     0x9aba53
  9ab95f:	45 85 f6             	test   r14d,r14d
  9ab962:	7e 13                	jle    0x9ab977
  9ab964:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9ab968:	44 89 f6             	mov    esi,r14d
  9ab96b:	0f b6 b8 9c 01 00 00 	movzx  edi,BYTE PTR [rax+0x19c]
  9ab972:	e8 59 1c f4 ff       	call   0x8ed5d0
  9ab977:	4c 8b 85 60 ff ff ff 	mov    r8,QWORD PTR [rbp-0xa0]
  9ab97e:	44 8b ad 68 ff ff ff 	mov    r13d,DWORD PTR [rbp-0x98]
  9ab985:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
  9ab988:	8b 7d ac             	mov    edi,DWORD PTR [rbp-0x54]
  9ab98b:	4c 8b 4d 88          	mov    r9,QWORD PTR [rbp-0x78]
  9ab98f:	41 39 c7             	cmp    r15d,eax
  9ab992:	7d 45                	jge    0x9ab9d9
  9ab994:	48 98                	cdqe
  9ab996:	48 2b 45 b0          	sub    rax,QWORD PTR [rbp-0x50]
  9ab99a:	b9 00 00 00 30       	mov    ecx,0x30000000
  9ab99f:	44 89 c2             	mov    edx,r8d
  9ab9a2:	eb 16                	jmp    0x9ab9ba
  9ab9a4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ab9ab:	00 00 00 00 00 
  9ab9b0:	41 ff c7             	inc    r15d
  9ab9b3:	ff c2                	inc    edx
  9ab9b5:	48 ff c8             	dec    rax
  9ab9b8:	74 1f                	je     0x9ab9d9
  9ab9ba:	48 63 f2             	movsxd rsi,edx
  9ab9bd:	41 8b 34 b4          	mov    esi,DWORD PTR [r12+rsi*4]
  9ab9c1:	21 ce                	and    esi,ecx
  9ab9c3:	81 fe 00 00 00 10    	cmp    esi,0x10000000
  9ab9c9:	75 e5                	jne    0x9ab9b0
  9ab9cb:	44 89 fe             	mov    esi,r15d
  9ab9ce:	c1 fe 05             	sar    esi,0x5
  9ab9d1:	48 63 f6             	movsxd rsi,esi
  9ab9d4:	fe 04 33             	inc    BYTE PTR [rbx+rsi*1]
  9ab9d7:	eb d7                	jmp    0x9ab9b0
  9ab9d9:	41 39 f8             	cmp    r8d,edi
  9ab9dc:	7d 45                	jge    0x9aba23
  9ab9de:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  9ab9e2:	44 89 c0             	mov    eax,r8d
  9ab9e5:	4c 8d 3d 24 09 f7 02 	lea    r15,[rip+0x2f70924]        # 0x391c310
  9ab9ec:	4c 8b 45 98          	mov    r8,QWORD PTR [rbp-0x68]
  9ab9f0:	be 00 00 00 30       	mov    esi,0x30000000
  9ab9f5:	31 d2                	xor    edx,edx
  9ab9f7:	49 29 c9             	sub    r9,rcx
  9ab9fa:	49 8d 0c 8c          	lea    rcx,[r12+rcx*4]
  9ab9fe:	eb 08                	jmp    0x9aba08
  9aba00:	48 ff c2             	inc    rdx
  9aba03:	49 39 d1             	cmp    r9,rdx
  9aba06:	74 27                	je     0x9aba2f
  9aba08:	8b 3c 91             	mov    edi,DWORD PTR [rcx+rdx*4]
  9aba0b:	21 f7                	and    edi,esi
  9aba0d:	81 ff 00 00 00 10    	cmp    edi,0x10000000
  9aba13:	75 eb                	jne    0x9aba00
  9aba15:	8d 3c 10             	lea    edi,[rax+rdx*1]
  9aba18:	c1 ff 05             	sar    edi,0x5
  9aba1b:	48 63 ff             	movsxd rdi,edi
  9aba1e:	fe 04 3b             	inc    BYTE PTR [rbx+rdi*1]
  9aba21:	eb dd                	jmp    0x9aba00
  9aba23:	4c 8d 3d e6 08 f7 02 	lea    r15,[rip+0x2f708e6]        # 0x391c310
  9aba2a:	e9 08 01 00 00       	jmp    0x9abb37
  9aba2f:	4c 8b 65 b8          	mov    r12,QWORD PTR [rbp-0x48]
  9aba33:	45 85 c0             	test   r8d,r8d
  9aba36:	0f 89 08 01 00 00    	jns    0x9abb44
  9aba3c:	e9 51 01 00 00       	jmp    0x9abb92
  9aba41:	4c 8d 3d c8 08 f7 02 	lea    r15,[rip+0x2f708c8]        # 0x391c310
  9aba48:	41 bd 10 00 00 00    	mov    r13d,0x10
  9aba4e:	e9 e4 00 00 00       	jmp    0x9abb37
  9aba53:	48 8b 75 90          	mov    rsi,QWORD PTR [rbp-0x70]
  9aba57:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  9aba5b:	48 8b 5d b0          	mov    rbx,QWORD PTR [rbp-0x50]
  9aba5f:	48 8d 4d c0          	lea    rcx,[rbp-0x40]
  9aba63:	48 c1 e6 10          	shl    rsi,0x10
  9aba67:	48 c1 e2 10          	shl    rdx,0x10
  9aba6b:	48 c1 e3 10          	shl    rbx,0x10
  9aba6f:	4c 01 ee             	add    rsi,r13
  9aba72:	4c 01 ea             	add    rdx,r13
  9aba75:	4c 01 eb             	add    rbx,r13
  9aba78:	4c 8b ad 70 ff ff ff 	mov    r13,QWORD PTR [rbp-0x90]
  9aba7f:	49 8b bd d8 01 00 00 	mov    rdi,QWORD PTR [r13+0x1d8]
  9aba86:	e8 f5 2c f4 ff       	call   0x8ee780
  9aba8b:	49 8b bd d8 01 00 00 	mov    rdi,QWORD PTR [r13+0x1d8]
  9aba92:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  9aba96:	e8 a5 38 f4 ff       	call   0x8ef340
  9aba9b:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
  9abaa2:	49 8b bd d8 01 00 00 	mov    rdi,QWORD PTR [r13+0x1d8]
  9abaa9:	4c 8b ad 58 ff ff ff 	mov    r13,QWORD PTR [rbp-0xa8]
  9abab0:	48 89 da             	mov    rdx,rbx
  9abab3:	48 8b 70 30          	mov    rsi,QWORD PTR [rax+0x30]
  9abab7:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
  9ababb:	45 89 e8             	mov    r8d,r13d
  9ababe:	49 8d 04 84          	lea    rax,[r12+rax*4]
  9abac2:	48 89 c1             	mov    rcx,rax
  9abac5:	48 89 c3             	mov    rbx,rax
  9abac8:	e8 a3 92 f3 ff       	call   0x8e4d70
  9abacd:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
  9abad1:	49 63 d5             	movsxd rdx,r13d
  9abad4:	48 89 df             	mov    rdi,rbx
  9abad7:	48 c1 e2 02          	shl    rdx,0x2
  9abadb:	49 8d 34 84          	lea    rsi,[r12+rax*4]
  9abadf:	e8 fc e0 8a ff       	call   0x259be0
  9abae4:	48 8b 85 60 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa0]
  9abaeb:	41 39 c7             	cmp    r15d,eax
  9abaee:	7d 15                	jge    0x9abb05
  9abaf0:	8b 4d a8             	mov    ecx,DWORD PTR [rbp-0x58]
  9abaf3:	39 c1                	cmp    ecx,eax
  9abaf5:	0f 4f c1             	cmovg  eax,ecx
  9abaf8:	8b 4d ac             	mov    ecx,DWORD PTR [rbp-0x54]
  9abafb:	48 98                	cdqe
  9abafd:	49 8d 1c 84          	lea    rbx,[r12+rax*4]
  9abb01:	29 c1                	sub    ecx,eax
  9abb03:	eb 10                	jmp    0x9abb15
  9abb05:	8b 4d ac             	mov    ecx,DWORD PTR [rbp-0x54]
  9abb08:	44 39 f9             	cmp    ecx,r15d
  9abb0b:	44 0f 4c f9          	cmovl  r15d,ecx
  9abb0f:	41 29 c7             	sub    r15d,eax
  9abb12:	44 89 f9             	mov    ecx,r15d
  9abb15:	4c 8d 3d f4 07 f7 02 	lea    r15,[rip+0x2f707f4]        # 0x391c310
  9abb1c:	48 63 f1             	movsxd rsi,ecx
  9abb1f:	48 89 df             	mov    rdi,rbx
  9abb22:	48 c1 e6 02          	shl    rsi,0x2
  9abb26:	e8 c5 d4 8a ff       	call   0x258ff0
  9abb2b:	45 31 ed             	xor    r13d,r13d
  9abb2e:	45 85 f6             	test   r14d,r14d
  9abb31:	0f 88 c4 00 00 00    	js     0x9abbfb
  9abb37:	4c 8b 65 b8          	mov    r12,QWORD PTR [rbp-0x48]
  9abb3b:	4c 8b 45 98          	mov    r8,QWORD PTR [rbp-0x68]
  9abb3f:	45 85 c0             	test   r8d,r8d
  9abb42:	78 4e                	js     0x9abb92
  9abb44:	4d 8d 74 24 18       	lea    r14,[r12+0x18]
  9abb49:	44 89 c0             	mov    eax,r8d
  9abb4c:	31 f6                	xor    esi,esi
  9abb4e:	31 d2                	xor    edx,edx
  9abb50:	4c 89 f7             	mov    rdi,r14
  9abb53:	48 8d 1c 40          	lea    rbx,[rax+rax*2]
  9abb57:	e8 44 8b e2 ff       	call   0x7d46a0
  9abb5c:	41 c7 84 9c 68 01 00 	mov    DWORD PTR [r12+rbx*4+0x168],0xffffffff
  9abb63:	00 ff ff ff ff 
  9abb68:	41 83 bc 9c 70 01 00 	cmp    DWORD PTR [r12+rbx*4+0x170],0x0
  9abb6f:	00 00 
  9abb71:	0f 85 db 00 00 00    	jne    0x9abc52
  9abb77:	41 83 bc 24 98 01 00 	cmp    DWORD PTR [r12+0x198],0x0
  9abb7e:	00 00 
  9abb80:	0f 85 ee 00 00 00    	jne    0x9abc74
  9abb86:	4c 89 f7             	mov    rdi,r14
  9abb89:	31 f6                	xor    esi,esi
  9abb8b:	31 d2                	xor    edx,edx
  9abb8d:	e8 1e 93 e2 ff       	call   0x7d4eb0
  9abb92:	48 63 45 80          	movsxd rax,DWORD PTR [rbp-0x80]
  9abb96:	4d 8d 74 24 18       	lea    r14,[r12+0x18]
  9abb9b:	31 f6                	xor    esi,esi
  9abb9d:	31 d2                	xor    edx,edx
  9abb9f:	4c 89 f7             	mov    rdi,r14
  9abba2:	48 8d 1c 40          	lea    rbx,[rax+rax*2]
  9abba6:	e8 f5 8a e2 ff       	call   0x7d46a0
  9abbab:	41 c7 84 9c 68 01 00 	mov    DWORD PTR [r12+rbx*4+0x168],0xffffffff
  9abbb2:	00 ff ff ff ff 
  9abbb7:	41 83 bc 9c 70 01 00 	cmp    DWORD PTR [r12+rbx*4+0x170],0x0
  9abbbe:	00 00 
  9abbc0:	75 56                	jne    0x9abc18
  9abbc2:	41 83 bc 24 98 01 00 	cmp    DWORD PTR [r12+0x198],0x0
  9abbc9:	00 00 
  9abbcb:	75 69                	jne    0x9abc36
  9abbcd:	4c 89 f7             	mov    rdi,r14
  9abbd0:	31 f6                	xor    esi,esi
  9abbd2:	31 d2                	xor    edx,edx
  9abbd4:	e8 d7 92 e2 ff       	call   0x7d4eb0
  9abbd9:	49 8b 07             	mov    rax,QWORD PTR [r15]
  9abbdc:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9abbe0:	0f 85 a6 00 00 00    	jne    0x9abc8c
  9abbe6:	44 89 e8             	mov    eax,r13d
  9abbe9:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  9abbf0:	5b                   	pop    rbx
  9abbf1:	41 5c                	pop    r12
  9abbf3:	41 5d                	pop    r13
  9abbf5:	41 5e                	pop    r14
  9abbf7:	41 5f                	pop    r15
  9abbf9:	5d                   	pop    rbp
  9abbfa:	c3                   	ret
  9abbfb:	4c 8b 65 b8          	mov    r12,QWORD PTR [rbp-0x48]
  9abbff:	41 f7 de             	neg    r14d
  9abc02:	44 89 f6             	mov    esi,r14d
  9abc05:	41 0f b6 bc 24 9c 01 	movzx  edi,BYTE PTR [r12+0x19c]
  9abc0c:	00 00 
  9abc0e:	e8 bd 19 f4 ff       	call   0x8ed5d0
  9abc13:	e9 23 ff ff ff       	jmp    0x9abb3b
  9abc18:	49 8d bc 9c 70 01 00 	lea    rdi,[r12+rbx*4+0x170]
  9abc1f:	00 
  9abc20:	c7 07 00 00 00 00    	mov    DWORD PTR [rdi],0x0
  9abc26:	e8 e5 ac 25 00       	call   0xc06910
  9abc2b:	41 83 bc 24 98 01 00 	cmp    DWORD PTR [r12+0x198],0x0
  9abc32:	00 00 
  9abc34:	74 97                	je     0x9abbcd
  9abc36:	49 81 c4 98 01 00 00 	add    r12,0x198
  9abc3d:	4c 89 e7             	mov    rdi,r12
  9abc40:	41 c7 04 24 00 00 00 	mov    DWORD PTR [r12],0x0
  9abc47:	00 
  9abc48:	e8 c3 ac 25 00       	call   0xc06910
  9abc4d:	e9 7b ff ff ff       	jmp    0x9abbcd
  9abc52:	49 8d bc 9c 70 01 00 	lea    rdi,[r12+rbx*4+0x170]
  9abc59:	00 
  9abc5a:	c7 07 00 00 00 00    	mov    DWORD PTR [rdi],0x0
  9abc60:	e8 ab ac 25 00       	call   0xc06910
  9abc65:	41 83 bc 24 98 01 00 	cmp    DWORD PTR [r12+0x198],0x0
  9abc6c:	00 00 
  9abc6e:	0f 84 12 ff ff ff    	je     0x9abb86
  9abc74:	49 8d bc 24 98 01 00 	lea    rdi,[r12+0x198]
  9abc7b:	00 
  9abc7c:	c7 07 00 00 00 00    	mov    DWORD PTR [rdi],0x0
  9abc82:	e8 89 ac 25 00       	call   0xc06910
  9abc87:	e9 fa fe ff ff       	jmp    0x9abb86
  9abc8c:	e8 1f 1a d5 ff       	call   0x6fd6b0
  9abc91:	0f 0b                	ud2
  9abc93:	90                   	nop
  9abc94:	90                   	nop
  9abc95:	90                   	nop
  9abc96:	90                   	nop
  9abc97:	90                   	nop
  9abc98:	90                   	nop
  9abc99:	90                   	nop
  9abc9a:	90                   	nop
  9abc9b:	90                   	nop
  9abc9c:	90                   	nop
  9abc9d:	90                   	nop
  9abc9e:	90                   	nop
  9abc9f:	90                   	nop
  9abca0:	55                   	push   rbp
  9abca1:	48 89 e5             	mov    rbp,rsp
  9abca4:	41 57                	push   r15
  9abca6:	41 56                	push   r14
  9abca8:	41 55                	push   r13
  9abcaa:	41 54                	push   r12
  9abcac:	53                   	push   rbx
  9abcad:	48 83 ec 38          	sub    rsp,0x38
  9abcb1:	49 89 fe             	mov    r14,rdi
  9abcb4:	48 83 c7 28          	add    rdi,0x28
  9abcb8:	89 4d cc             	mov    DWORD PTR [rbp-0x34],ecx
  9abcbb:	41 89 d7             	mov    r15d,edx
  9abcbe:	41 89 f5             	mov    r13d,esi
  9abcc1:	4c 89 45 c0          	mov    QWORD PTR [rbp-0x40],r8
  9abcc5:	31 f6                	xor    esi,esi
  9abcc7:	31 d2                	xor    edx,edx
  9abcc9:	31 c9                	xor    ecx,ecx
  9abccb:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  9abccf:	e8 2c ad b1 ff       	call   0x4c6a00
  9abcd4:	41 8b 46 4c          	mov    eax,DWORD PTR [r14+0x4c]
  9abcd8:	45 8b 66 48          	mov    r12d,DWORD PTR [r14+0x48]
  9abcdc:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9abce0:	44 01 e0             	add    eax,r12d
  9abce3:	44 39 e8             	cmp    eax,r13d
  9abce6:	73 19                	jae    0x9abd01
  9abce8:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9abcec:	31 f6                	xor    esi,esi
  9abcee:	31 d2                	xor    edx,edx
  9abcf0:	31 c9                	xor    ecx,ecx
  9abcf2:	e8 a9 b2 b1 ff       	call   0x4c6fa0
  9abcf7:	bb 0c 00 00 00       	mov    ebx,0xc
  9abcfc:	e9 38 07 00 00       	jmp    0x9ac439
  9abd01:	49 8d 46 10          	lea    rax,[r14+0x10]
  9abd05:	44 89 e1             	mov    ecx,r12d
  9abd08:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  9abd0c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  9abd10:	45 85 ff             	test   r15d,r15d
  9abd13:	89 ca                	mov    edx,ecx
  9abd15:	40 0f 94 c6          	sete   sil
  9abd19:	44 29 ea             	sub    edx,r13d
  9abd1c:	40 0f 92 c7          	setb   dil
  9abd20:	40 08 f7             	or     dil,sil
  9abd23:	74 35                	je     0x9abd5a
  9abd25:	45 85 ff             	test   r15d,r15d
  9abd28:	0f 85 28 01 00 00    	jne    0x9abe56
  9abd2e:	41 39 c5             	cmp    r13d,eax
  9abd31:	0f 86 32 03 00 00    	jbe    0x9ac069
  9abd37:	83 f9 1f             	cmp    ecx,0x1f
  9abd3a:	0f 86 3d 04 00 00    	jbe    0x9ac17d
  9abd40:	4c 89 f7             	mov    rdi,r14
  9abd43:	e8 08 07 00 00       	call   0x9ac450
  9abd48:	41 8b 4e 48          	mov    ecx,DWORD PTR [r14+0x48]
  9abd4c:	41 8b 46 4c          	mov    eax,DWORD PTR [r14+0x4c]
  9abd50:	8d 14 01             	lea    edx,[rcx+rax*1]
  9abd53:	44 39 ea             	cmp    edx,r13d
  9abd56:	73 b8                	jae    0x9abd10
  9abd58:	eb 8e                	jmp    0x9abce8
  9abd5a:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  9abd5e:	44 8b 65 cc          	mov    r12d,DWORD PTR [rbp-0x34]
  9abd62:	45 85 ed             	test   r13d,r13d
  9abd65:	0f 84 dd 00 00 00    	je     0x9abe48
  9abd6b:	41 b9 02 00 00 00    	mov    r9d,0x2
  9abd71:	48 8d 0d 58 e1 a0 00 	lea    rcx,[rip+0xa0e158]        # 0x13b9ed0
  9abd78:	44 89 ef             	mov    edi,r13d
  9abd7b:	eb 0d                	jmp    0x9abd8a
  9abd7d:	0f 1f 00             	nop    DWORD PTR [rax]
  9abd80:	41 83 fa 01          	cmp    r10d,0x1
  9abd84:	0f 84 be 00 00 00    	je     0x9abe48
  9abd8a:	45 31 db             	xor    r11d,r11d
  9abd8d:	0f 1f 00             	nop    DWORD PTR [rax]
  9abd90:	45 89 da             	mov    r10d,r11d
  9abd93:	46 03 1c 89          	add    r11d,DWORD PTR [rcx+r9*4]
  9abd97:	41 c1 e2 06          	shl    r10d,0x6
  9abd9b:	41 83 c2 c0          	add    r10d,0xffffffc0
  9abd9f:	90                   	nop
  9abda0:	4d 63 db             	movsxd r11,r11d
  9abda3:	41 83 c2 40          	add    r10d,0x40
  9abda7:	4f 8b 44 de 70       	mov    r8,QWORD PTR [r14+r11*8+0x70]
  9abdac:	41 ff c3             	inc    r11d
  9abdaf:	4d 85 c0             	test   r8,r8
  9abdb2:	74 ec                	je     0x9abda0
  9abdb4:	f3 4d 0f bc c0       	tzcnt  r8,r8
  9abdb9:	49 ff c9             	dec    r9
  9abdbc:	47 8d 1c 10          	lea    r11d,[r8+r10*1]
  9abdc0:	75 ce                	jne    0x9abd90
  9abdc2:	45 01 d0             	add    r8d,r10d
  9abdc5:	4d 63 c8             	movsxd r9,r8d
  9abdc8:	4f 8b 5c ce 70       	mov    r11,QWORD PTR [r14+r9*8+0x70]
  9abdcd:	45 89 cf             	mov    r15d,r9d
  9abdd0:	41 c1 e7 06          	shl    r15d,0x6
  9abdd4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9abddb:	00 00 00 00 00 
  9abde0:	41 89 fa             	mov    r10d,edi
  9abde3:	f3 49 0f bc fb       	tzcnt  rdi,r11
  9abde8:	44 09 ff             	or     edi,r15d
  9abdeb:	89 3e                	mov    DWORD PTR [rsi],edi
  9abded:	48 83 c6 04          	add    rsi,0x4
  9abdf1:	c4 c2 a0 f3 cb       	blsr   r11,r11
  9abdf6:	41 8d 7a ff          	lea    edi,[r10-0x1]
  9abdfa:	74 06                	je     0x9abe02
  9abdfc:	41 83 fa 01          	cmp    r10d,0x1
  9abe00:	75 de                	jne    0x9abde0
  9abe02:	4f 89 5c ce 70       	mov    QWORD PTR [r14+r9*8+0x70],r11
  9abe07:	4d 85 db             	test   r11,r11
  9abe0a:	75 3c                	jne    0x9abe48
  9abe0c:	45 31 c9             	xor    r9d,r9d
  9abe0f:	90                   	nop
  9abe10:	46 8b 5c 89 04       	mov    r11d,DWORD PTR [rcx+r9*4+0x4]
  9abe15:	44 89 c3             	mov    ebx,r8d
  9abe18:	41 c1 f8 06          	sar    r8d,0x6
  9abe1c:	45 01 c3             	add    r11d,r8d
  9abe1f:	4d 63 fb             	movsxd r15,r11d
  9abe22:	4f 8b 5c fe 70       	mov    r11,QWORD PTR [r14+r15*8+0x70]
  9abe27:	49 0f b3 db          	btr    r11,rbx
  9abe2b:	4f 89 5c fe 70       	mov    QWORD PTR [r14+r15*8+0x70],r11
  9abe30:	49 83 f9 01          	cmp    r9,0x1
  9abe34:	4d 8d 49 01          	lea    r9,[r9+0x1]
  9abe38:	0f 84 42 ff ff ff    	je     0x9abd80
  9abe3e:	4d 85 db             	test   r11,r11
  9abe41:	74 cd                	je     0x9abe10
  9abe43:	e9 38 ff ff ff       	jmp    0x9abd80
  9abe48:	31 f6                	xor    esi,esi
  9abe4a:	c7 45 d0 00 00 00 00 	mov    DWORD PTR [rbp-0x30],0x0
  9abe51:	e9 35 05 00 00       	jmp    0x9ac38b
  9abe56:	45 85 e4             	test   r12d,r12d
  9abe59:	0f 84 e8 00 00 00    	je     0x9abf47
  9abe5f:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  9abe63:	bf 02 00 00 00       	mov    edi,0x2
  9abe68:	48 8d 05 61 e0 a0 00 	lea    rax,[rip+0xa0e061]        # 0x13b9ed0
  9abe6f:	44 89 e2             	mov    edx,r12d
  9abe72:	eb 16                	jmp    0x9abe8a
  9abe74:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9abe7b:	00 00 00 00 00 
  9abe80:	41 83 f8 01          	cmp    r8d,0x1
  9abe84:	0f 84 bd 00 00 00    	je     0x9abf47
  9abe8a:	45 31 c9             	xor    r9d,r9d
  9abe8d:	0f 1f 00             	nop    DWORD PTR [rax]
  9abe90:	45 89 c8             	mov    r8d,r9d
  9abe93:	44 03 0c b8          	add    r9d,DWORD PTR [rax+rdi*4]
  9abe97:	41 c1 e0 06          	shl    r8d,0x6
  9abe9b:	41 83 c0 c0          	add    r8d,0xffffffc0
  9abe9f:	90                   	nop
  9abea0:	4d 63 c9             	movsxd r9,r9d
  9abea3:	41 83 c0 40          	add    r8d,0x40
  9abea7:	4b 8b 74 ce 70       	mov    rsi,QWORD PTR [r14+r9*8+0x70]
  9abeac:	41 ff c1             	inc    r9d
  9abeaf:	48 85 f6             	test   rsi,rsi
  9abeb2:	74 ec                	je     0x9abea0
  9abeb4:	f3 48 0f bc f6       	tzcnt  rsi,rsi
  9abeb9:	48 ff cf             	dec    rdi
  9abebc:	46 8d 0c 06          	lea    r9d,[rsi+r8*1]
  9abec0:	75 ce                	jne    0x9abe90
  9abec2:	44 01 c6             	add    esi,r8d
  9abec5:	48 63 fe             	movsxd rdi,esi
  9abec8:	4d 8b 4c fe 70       	mov    r9,QWORD PTR [r14+rdi*8+0x70]
  9abecd:	41 89 fa             	mov    r10d,edi
  9abed0:	41 c1 e2 06          	shl    r10d,0x6
  9abed4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9abedb:	00 00 00 00 00 
  9abee0:	41 89 d0             	mov    r8d,edx
  9abee3:	f3 49 0f bc d1       	tzcnt  rdx,r9
  9abee8:	44 09 d2             	or     edx,r10d
  9abeeb:	89 11                	mov    DWORD PTR [rcx],edx
  9abeed:	48 83 c1 04          	add    rcx,0x4
  9abef1:	c4 c2 b0 f3 c9       	blsr   r9,r9
  9abef6:	41 8d 50 ff          	lea    edx,[r8-0x1]
  9abefa:	74 06                	je     0x9abf02
  9abefc:	41 83 f8 01          	cmp    r8d,0x1
  9abf00:	75 de                	jne    0x9abee0
  9abf02:	4d 89 4c fe 70       	mov    QWORD PTR [r14+rdi*8+0x70],r9
  9abf07:	4d 85 c9             	test   r9,r9
  9abf0a:	75 3b                	jne    0x9abf47
  9abf0c:	31 ff                	xor    edi,edi
  9abf0e:	66 90                	xchg   ax,ax
  9abf10:	44 8b 4c b8 04       	mov    r9d,DWORD PTR [rax+rdi*4+0x4]
  9abf15:	41 89 f2             	mov    r10d,esi
  9abf18:	c1 fe 06             	sar    esi,0x6
  9abf1b:	41 01 f1             	add    r9d,esi
  9abf1e:	4d 63 d9             	movsxd r11,r9d
  9abf21:	4f 8b 4c de 70       	mov    r9,QWORD PTR [r14+r11*8+0x70]
  9abf26:	4d 0f b3 d1          	btr    r9,r10
  9abf2a:	4f 89 4c de 70       	mov    QWORD PTR [r14+r11*8+0x70],r9
  9abf2f:	48 83 ff 01          	cmp    rdi,0x1
  9abf33:	48 8d 7f 01          	lea    rdi,[rdi+0x1]
  9abf37:	0f 84 43 ff ff ff    	je     0x9abe80
  9abf3d:	4d 85 c9             	test   r9,r9
  9abf40:	74 ce                	je     0x9abf10
  9abf42:	e9 39 ff ff ff       	jmp    0x9abe80
  9abf47:	44 89 e8             	mov    eax,r13d
  9abf4a:	44 29 e0             	sub    eax,r12d
  9abf4d:	0f 84 fa 00 00 00    	je     0x9ac04d
  9abf53:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  9abf57:	41 b8 02 00 00 00    	mov    r8d,0x2
  9abf5d:	48 8d 15 6c df a0 00 	lea    rdx,[rip+0xa0df6c]        # 0x13b9ed0
  9abf64:	89 c6                	mov    esi,eax
  9abf66:	4a 8d 0c a1          	lea    rcx,[rcx+r12*4]
  9abf6a:	eb 0e                	jmp    0x9abf7a
  9abf6c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  9abf70:	41 83 f9 01          	cmp    r9d,0x1
  9abf74:	0f 84 d3 00 00 00    	je     0x9ac04d
  9abf7a:	45 31 d2             	xor    r10d,r10d
  9abf7d:	0f 1f 00             	nop    DWORD PTR [rax]
  9abf80:	45 89 d1             	mov    r9d,r10d
  9abf83:	46 03 14 82          	add    r10d,DWORD PTR [rdx+r8*4]
  9abf87:	41 c1 e1 06          	shl    r9d,0x6
  9abf8b:	41 83 c1 c0          	add    r9d,0xffffffc0
  9abf8f:	90                   	nop
  9abf90:	4d 63 d2             	movsxd r10,r10d
  9abf93:	41 83 c1 40          	add    r9d,0x40
  9abf97:	4b 8b bc d6 90 08 02 	mov    rdi,QWORD PTR [r14+r10*8+0x20890]
  9abf9e:	00 
  9abf9f:	41 ff c2             	inc    r10d
  9abfa2:	48 85 ff             	test   rdi,rdi
  9abfa5:	74 e9                	je     0x9abf90
  9abfa7:	f3 48 0f bc ff       	tzcnt  rdi,rdi
  9abfac:	49 ff c8             	dec    r8
  9abfaf:	46 8d 14 0f          	lea    r10d,[rdi+r9*1]
  9abfb3:	75 cb                	jne    0x9abf80
  9abfb5:	44 01 cf             	add    edi,r9d
  9abfb8:	4c 63 c7             	movsxd r8,edi
  9abfbb:	4f 8b 94 c6 90 08 02 	mov    r10,QWORD PTR [r14+r8*8+0x20890]
  9abfc2:	00 
  9abfc3:	45 89 c3             	mov    r11d,r8d
  9abfc6:	41 c1 e3 06          	shl    r11d,0x6
  9abfca:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  9abfd0:	41 89 f1             	mov    r9d,esi
  9abfd3:	f3 49 0f bc f2       	tzcnt  rsi,r10
  9abfd8:	44 09 de             	or     esi,r11d
  9abfdb:	89 31                	mov    DWORD PTR [rcx],esi
  9abfdd:	48 83 c1 04          	add    rcx,0x4
  9abfe1:	c4 c2 a8 f3 ca       	blsr   r10,r10
  9abfe6:	41 8d 71 ff          	lea    esi,[r9-0x1]
  9abfea:	74 06                	je     0x9abff2
  9abfec:	41 83 f9 01          	cmp    r9d,0x1
  9abff0:	75 de                	jne    0x9abfd0
  9abff2:	4f 89 94 c6 90 08 02 	mov    QWORD PTR [r14+r8*8+0x20890],r10
  9abff9:	00 
  9abffa:	4d 85 d2             	test   r10,r10
  9abffd:	75 4e                	jne    0x9ac04d
  9abfff:	45 31 c0             	xor    r8d,r8d
  9ac002:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac009:	1f 84 00 00 00 00 00 
  9ac010:	46 8b 54 82 04       	mov    r10d,DWORD PTR [rdx+r8*4+0x4]
  9ac015:	41 89 fb             	mov    r11d,edi
  9ac018:	c1 ff 06             	sar    edi,0x6
  9ac01b:	41 01 fa             	add    r10d,edi
  9ac01e:	49 63 da             	movsxd rbx,r10d
  9ac021:	4d 8b 94 de 90 08 02 	mov    r10,QWORD PTR [r14+rbx*8+0x20890]
  9ac028:	00 
  9ac029:	4d 0f b3 da          	btr    r10,r11
  9ac02d:	4d 89 94 de 90 08 02 	mov    QWORD PTR [r14+rbx*8+0x20890],r10
  9ac034:	00 
  9ac035:	49 83 f8 01          	cmp    r8,0x1
  9ac039:	4d 8d 40 01          	lea    r8,[r8+0x1]
  9ac03d:	0f 84 2d ff ff ff    	je     0x9abf70
  9ac043:	4d 85 d2             	test   r10,r10
  9ac046:	74 c8                	je     0x9ac010
  9ac048:	e9 23 ff ff ff       	jmp    0x9abf70
  9ac04d:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
  9ac051:	44 8b 65 cc          	mov    r12d,DWORD PTR [rbp-0x34]
  9ac055:	31 f6                	xor    esi,esi
  9ac057:	c7 45 d0 00 00 00 00 	mov    DWORD PTR [rbp-0x30],0x0
  9ac05e:	31 d2                	xor    edx,edx
  9ac060:	29 c1                	sub    ecx,eax
  9ac062:	89 c8                	mov    eax,ecx
  9ac064:	e9 22 03 00 00       	jmp    0x9ac38b
  9ac069:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  9ac06d:	44 8b 65 cc          	mov    r12d,DWORD PTR [rbp-0x34]
  9ac071:	45 85 ed             	test   r13d,r13d
  9ac074:	0f 84 f4 00 00 00    	je     0x9ac16e
  9ac07a:	41 b9 02 00 00 00    	mov    r9d,0x2
  9ac080:	48 8d 15 49 de a0 00 	lea    rdx,[rip+0xa0de49]        # 0x13b9ed0
  9ac087:	44 89 ef             	mov    edi,r13d
  9ac08a:	eb 0e                	jmp    0x9ac09a
  9ac08c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  9ac090:	41 83 fa 01          	cmp    r10d,0x1
  9ac094:	0f 84 d4 00 00 00    	je     0x9ac16e
  9ac09a:	45 31 db             	xor    r11d,r11d
  9ac09d:	0f 1f 00             	nop    DWORD PTR [rax]
  9ac0a0:	45 89 da             	mov    r10d,r11d
  9ac0a3:	46 03 1c 8a          	add    r11d,DWORD PTR [rdx+r9*4]
  9ac0a7:	41 c1 e2 06          	shl    r10d,0x6
  9ac0ab:	41 83 c2 c0          	add    r10d,0xffffffc0
  9ac0af:	90                   	nop
  9ac0b0:	4d 63 db             	movsxd r11,r11d
  9ac0b3:	41 83 c2 40          	add    r10d,0x40
  9ac0b7:	4f 8b 84 de 90 08 02 	mov    r8,QWORD PTR [r14+r11*8+0x20890]
  9ac0be:	00 
  9ac0bf:	41 ff c3             	inc    r11d
  9ac0c2:	4d 85 c0             	test   r8,r8
  9ac0c5:	74 e9                	je     0x9ac0b0
  9ac0c7:	f3 4d 0f bc c0       	tzcnt  r8,r8
  9ac0cc:	49 ff c9             	dec    r9
  9ac0cf:	47 8d 1c 10          	lea    r11d,[r8+r10*1]
  9ac0d3:	75 cb                	jne    0x9ac0a0
  9ac0d5:	45 01 d0             	add    r8d,r10d
  9ac0d8:	4d 63 c8             	movsxd r9,r8d
  9ac0db:	4f 8b 9c ce 90 08 02 	mov    r11,QWORD PTR [r14+r9*8+0x20890]
  9ac0e2:	00 
  9ac0e3:	45 89 cf             	mov    r15d,r9d
  9ac0e6:	41 c1 e7 06          	shl    r15d,0x6
  9ac0ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  9ac0f0:	41 89 fa             	mov    r10d,edi
  9ac0f3:	f3 49 0f bc fb       	tzcnt  rdi,r11
  9ac0f8:	44 09 ff             	or     edi,r15d
  9ac0fb:	89 3e                	mov    DWORD PTR [rsi],edi
  9ac0fd:	48 83 c6 04          	add    rsi,0x4
  9ac101:	c4 c2 a0 f3 cb       	blsr   r11,r11
  9ac106:	41 8d 7a ff          	lea    edi,[r10-0x1]
  9ac10a:	74 06                	je     0x9ac112
  9ac10c:	41 83 fa 01          	cmp    r10d,0x1
  9ac110:	75 de                	jne    0x9ac0f0
  9ac112:	4f 89 9c ce 90 08 02 	mov    QWORD PTR [r14+r9*8+0x20890],r11
  9ac119:	00 
  9ac11a:	4d 85 db             	test   r11,r11
  9ac11d:	75 4f                	jne    0x9ac16e
  9ac11f:	45 31 c9             	xor    r9d,r9d
  9ac122:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac129:	1f 84 00 00 00 00 00 
  9ac130:	46 8b 5c 8a 04       	mov    r11d,DWORD PTR [rdx+r9*4+0x4]
  9ac135:	44 89 c3             	mov    ebx,r8d
  9ac138:	41 c1 f8 06          	sar    r8d,0x6
  9ac13c:	45 01 c3             	add    r11d,r8d
  9ac13f:	4d 63 fb             	movsxd r15,r11d
  9ac142:	4f 8b 9c fe 90 08 02 	mov    r11,QWORD PTR [r14+r15*8+0x20890]
  9ac149:	00 
  9ac14a:	49 0f b3 db          	btr    r11,rbx
  9ac14e:	4f 89 9c fe 90 08 02 	mov    QWORD PTR [r14+r15*8+0x20890],r11
  9ac155:	00 
  9ac156:	49 83 f9 01          	cmp    r9,0x1
  9ac15a:	4d 8d 49 01          	lea    r9,[r9+0x1]
  9ac15e:	0f 84 2c ff ff ff    	je     0x9ac090
  9ac164:	4d 85 db             	test   r11,r11
  9ac167:	74 c7                	je     0x9ac130
  9ac169:	e9 22 ff ff ff       	jmp    0x9ac090
  9ac16e:	44 29 e8             	sub    eax,r13d
  9ac171:	c7 45 d0 00 00 00 00 	mov    DWORD PTR [rbp-0x30],0x0
  9ac178:	e9 09 02 00 00       	jmp    0x9ac386
  9ac17d:	4c 8b 65 c0          	mov    r12,QWORD PTR [rbp-0x40]
  9ac181:	44 89 ea             	mov    edx,r13d
  9ac184:	29 c2                	sub    edx,eax
  9ac186:	89 55 d0             	mov    DWORD PTR [rbp-0x30],edx
  9ac189:	0f 84 e9 00 00 00    	je     0x9ac278
  9ac18f:	8b 7d d0             	mov    edi,DWORD PTR [rbp-0x30]
  9ac192:	41 b9 02 00 00 00    	mov    r9d,0x2
  9ac198:	48 8d 15 31 dd a0 00 	lea    rdx,[rip+0xa0dd31]        # 0x13b9ed0
  9ac19f:	4c 89 e6             	mov    rsi,r12
  9ac1a2:	eb 16                	jmp    0x9ac1ba
  9ac1a4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac1ab:	00 00 00 00 00 
  9ac1b0:	41 83 fa 01          	cmp    r10d,0x1
  9ac1b4:	0f 84 be 00 00 00    	je     0x9ac278
  9ac1ba:	45 31 db             	xor    r11d,r11d
  9ac1bd:	0f 1f 00             	nop    DWORD PTR [rax]
  9ac1c0:	45 89 da             	mov    r10d,r11d
  9ac1c3:	46 03 1c 8a          	add    r11d,DWORD PTR [rdx+r9*4]
  9ac1c7:	41 c1 e2 06          	shl    r10d,0x6
  9ac1cb:	41 83 c2 c0          	add    r10d,0xffffffc0
  9ac1cf:	90                   	nop
  9ac1d0:	4d 63 db             	movsxd r11,r11d
  9ac1d3:	41 83 c2 40          	add    r10d,0x40
  9ac1d7:	4f 8b 44 de 70       	mov    r8,QWORD PTR [r14+r11*8+0x70]
  9ac1dc:	41 ff c3             	inc    r11d
  9ac1df:	4d 85 c0             	test   r8,r8
  9ac1e2:	74 ec                	je     0x9ac1d0
  9ac1e4:	f3 4d 0f bc c0       	tzcnt  r8,r8
  9ac1e9:	49 ff c9             	dec    r9
  9ac1ec:	47 8d 1c 10          	lea    r11d,[r8+r10*1]
  9ac1f0:	75 ce                	jne    0x9ac1c0
  9ac1f2:	45 01 d0             	add    r8d,r10d
  9ac1f5:	4d 63 c8             	movsxd r9,r8d
  9ac1f8:	4f 8b 5c ce 70       	mov    r11,QWORD PTR [r14+r9*8+0x70]
  9ac1fd:	45 89 cf             	mov    r15d,r9d
  9ac200:	41 c1 e7 06          	shl    r15d,0x6
  9ac204:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac20b:	00 00 00 00 00 
  9ac210:	41 89 fa             	mov    r10d,edi
  9ac213:	f3 49 0f bc fb       	tzcnt  rdi,r11
  9ac218:	44 09 ff             	or     edi,r15d
  9ac21b:	89 3e                	mov    DWORD PTR [rsi],edi
  9ac21d:	48 83 c6 04          	add    rsi,0x4
  9ac221:	c4 c2 a0 f3 cb       	blsr   r11,r11
  9ac226:	41 8d 7a ff          	lea    edi,[r10-0x1]
  9ac22a:	74 06                	je     0x9ac232
  9ac22c:	41 83 fa 01          	cmp    r10d,0x1
  9ac230:	75 de                	jne    0x9ac210
  9ac232:	4f 89 5c ce 70       	mov    QWORD PTR [r14+r9*8+0x70],r11
  9ac237:	4d 85 db             	test   r11,r11
  9ac23a:	75 3c                	jne    0x9ac278
  9ac23c:	45 31 c9             	xor    r9d,r9d
  9ac23f:	90                   	nop
  9ac240:	46 8b 5c 8a 04       	mov    r11d,DWORD PTR [rdx+r9*4+0x4]
  9ac245:	44 89 c3             	mov    ebx,r8d
  9ac248:	41 c1 f8 06          	sar    r8d,0x6
  9ac24c:	45 01 c3             	add    r11d,r8d
  9ac24f:	4d 63 fb             	movsxd r15,r11d
  9ac252:	4f 8b 5c fe 70       	mov    r11,QWORD PTR [r14+r15*8+0x70]
  9ac257:	49 0f b3 db          	btr    r11,rbx
  9ac25b:	4f 89 5c fe 70       	mov    QWORD PTR [r14+r15*8+0x70],r11
  9ac260:	49 83 f9 01          	cmp    r9,0x1
  9ac264:	4d 8d 49 01          	lea    r9,[r9+0x1]
  9ac268:	0f 84 42 ff ff ff    	je     0x9ac1b0
  9ac26e:	4d 85 db             	test   r11,r11
  9ac271:	74 cd                	je     0x9ac240
  9ac273:	e9 38 ff ff ff       	jmp    0x9ac1b0
  9ac278:	85 c0                	test   eax,eax
  9ac27a:	0f 84 fd 00 00 00    	je     0x9ac37d
  9ac280:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
  9ac283:	41 b8 02 00 00 00    	mov    r8d,0x2
  9ac289:	48 8d 35 40 dc a0 00 	lea    rsi,[rip+0xa0dc40]        # 0x13b9ed0
  9ac290:	49 8d 14 94          	lea    rdx,[r12+rdx*4]
  9ac294:	eb 14                	jmp    0x9ac2aa
  9ac296:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  9ac29d:	00 00 00 
  9ac2a0:	41 83 f9 01          	cmp    r9d,0x1
  9ac2a4:	0f 84 d3 00 00 00    	je     0x9ac37d
  9ac2aa:	45 31 d2             	xor    r10d,r10d
  9ac2ad:	0f 1f 00             	nop    DWORD PTR [rax]
  9ac2b0:	45 89 d1             	mov    r9d,r10d
  9ac2b3:	46 03 14 86          	add    r10d,DWORD PTR [rsi+r8*4]
  9ac2b7:	41 c1 e1 06          	shl    r9d,0x6
  9ac2bb:	41 83 c1 c0          	add    r9d,0xffffffc0
  9ac2bf:	90                   	nop
  9ac2c0:	4d 63 d2             	movsxd r10,r10d
  9ac2c3:	41 83 c1 40          	add    r9d,0x40
  9ac2c7:	4b 8b bc d6 90 08 02 	mov    rdi,QWORD PTR [r14+r10*8+0x20890]
  9ac2ce:	00 
  9ac2cf:	41 ff c2             	inc    r10d
  9ac2d2:	48 85 ff             	test   rdi,rdi
  9ac2d5:	74 e9                	je     0x9ac2c0
  9ac2d7:	f3 48 0f bc ff       	tzcnt  rdi,rdi
  9ac2dc:	49 ff c8             	dec    r8
  9ac2df:	46 8d 14 0f          	lea    r10d,[rdi+r9*1]
  9ac2e3:	75 cb                	jne    0x9ac2b0
  9ac2e5:	44 01 cf             	add    edi,r9d
  9ac2e8:	4c 63 c7             	movsxd r8,edi
  9ac2eb:	4f 8b 94 c6 90 08 02 	mov    r10,QWORD PTR [r14+r8*8+0x20890]
  9ac2f2:	00 
  9ac2f3:	45 89 c3             	mov    r11d,r8d
  9ac2f6:	41 c1 e3 06          	shl    r11d,0x6
  9ac2fa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  9ac300:	41 89 c1             	mov    r9d,eax
  9ac303:	f3 49 0f bc c2       	tzcnt  rax,r10
  9ac308:	44 09 d8             	or     eax,r11d
  9ac30b:	89 02                	mov    DWORD PTR [rdx],eax
  9ac30d:	48 83 c2 04          	add    rdx,0x4
  9ac311:	c4 c2 a8 f3 ca       	blsr   r10,r10
  9ac316:	41 8d 41 ff          	lea    eax,[r9-0x1]
  9ac31a:	74 06                	je     0x9ac322
  9ac31c:	41 83 f9 01          	cmp    r9d,0x1
  9ac320:	75 de                	jne    0x9ac300
  9ac322:	4f 89 94 c6 90 08 02 	mov    QWORD PTR [r14+r8*8+0x20890],r10
  9ac329:	00 
  9ac32a:	4d 85 d2             	test   r10,r10
  9ac32d:	75 4e                	jne    0x9ac37d
  9ac32f:	45 31 c0             	xor    r8d,r8d
  9ac332:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac339:	1f 84 00 00 00 00 00 
  9ac340:	46 8b 54 86 04       	mov    r10d,DWORD PTR [rsi+r8*4+0x4]
  9ac345:	41 89 fb             	mov    r11d,edi
  9ac348:	c1 ff 06             	sar    edi,0x6
  9ac34b:	41 01 fa             	add    r10d,edi
  9ac34e:	49 63 da             	movsxd rbx,r10d
  9ac351:	4d 8b 94 de 90 08 02 	mov    r10,QWORD PTR [r14+rbx*8+0x20890]
  9ac358:	00 
  9ac359:	4d 0f b3 da          	btr    r10,r11
  9ac35d:	4d 89 94 de 90 08 02 	mov    QWORD PTR [r14+rbx*8+0x20890],r10
  9ac364:	00 
  9ac365:	49 83 f8 01          	cmp    r8,0x1
  9ac369:	4d 8d 40 01          	lea    r8,[r8+0x1]
  9ac36d:	0f 84 2d ff ff ff    	je     0x9ac2a0
  9ac373:	4d 85 d2             	test   r10,r10
  9ac376:	74 c8                	je     0x9ac340
  9ac378:	e9 23 ff ff ff       	jmp    0x9ac2a0
  9ac37d:	2b 4d d0             	sub    ecx,DWORD PTR [rbp-0x30]
  9ac380:	44 8b 65 cc          	mov    r12d,DWORD PTR [rbp-0x34]
  9ac384:	31 c0                	xor    eax,eax
  9ac386:	40 b6 01             	mov    sil,0x1
  9ac389:	89 ca                	mov    edx,ecx
  9ac38b:	41 89 56 48          	mov    DWORD PTR [r14+0x48],edx
  9ac38f:	41 89 46 4c          	mov    DWORD PTR [r14+0x4c],eax
  9ac393:	45 85 e4             	test   r12d,r12d
  9ac396:	74 06                	je     0x9ac39e
  9ac398:	45 01 6e 50          	add    DWORD PTR [r14+0x50],r13d
  9ac39c:	eb 04                	jmp    0x9ac3a2
  9ac39e:	45 01 6e 54          	add    DWORD PTR [r14+0x54],r13d
  9ac3a2:	48 8b 5d b0          	mov    rbx,QWORD PTR [rbp-0x50]
  9ac3a6:	40 84 f6             	test   sil,sil
  9ac3a9:	74 4a                	je     0x9ac3f5
  9ac3ab:	41 0f b6 46 68       	movzx  eax,BYTE PTR [r14+0x68]
  9ac3b0:	a8 01                	test   al,0x1
  9ac3b2:	74 41                	je     0x9ac3f5
  9ac3b4:	45 8b 66 5c          	mov    r12d,DWORD PTR [r14+0x5c]
  9ac3b8:	0c 02                	or     al,0x2
  9ac3ba:	4d 8d 7e 5c          	lea    r15,[r14+0x5c]
  9ac3be:	4c 8d 2d c5 5c 97 00 	lea    r13,[rip+0x975cc5]        # 0x132208a
  9ac3c5:	41 88 46 68          	mov    BYTE PTR [r14+0x68],al
  9ac3c9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  9ac3d0:	4c 89 ff             	mov    rdi,r15
  9ac3d3:	48 89 de             	mov    rsi,rbx
  9ac3d6:	ba 44 00 00 00       	mov    edx,0x44
  9ac3db:	4c 89 e9             	mov    rcx,r13
  9ac3de:	c7 04 24 00 01 00 00 	mov    DWORD PTR [rsp],0x100
  9ac3e5:	45 31 c0             	xor    r8d,r8d
  9ac3e8:	45 31 c9             	xor    r9d,r9d
  9ac3eb:	e8 70 9e 25 00       	call   0xc06260
  9ac3f0:	45 3b 27             	cmp    r12d,DWORD PTR [r15]
  9ac3f3:	74 db                	je     0x9ac3d0
  9ac3f5:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9ac3f9:	31 db                	xor    ebx,ebx
  9ac3fb:	31 f6                	xor    esi,esi
  9ac3fd:	31 d2                	xor    edx,edx
  9ac3ff:	31 c9                	xor    ecx,ecx
  9ac401:	e8 9a ab b1 ff       	call   0x4c6fa0
  9ac406:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
  9ac409:	85 c0                	test   eax,eax
  9ac40b:	7e 2c                	jle    0x9ac439
  9ac40d:	4c 8b 7d c0          	mov    r15,QWORD PTR [rbp-0x40]
  9ac411:	41 89 c4             	mov    r12d,eax
  9ac414:	41 bd ff ff 0f 00    	mov    r13d,0xfffff
  9ac41a:	31 db                	xor    ebx,ebx
  9ac41c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  9ac420:	41 8b 34 9f          	mov    esi,DWORD PTR [r15+rbx*4]
  9ac424:	4c 89 f7             	mov    rdi,r14
  9ac427:	44 21 ee             	and    esi,r13d
  9ac42a:	e8 d1 00 00 00       	call   0x9ac500
  9ac42f:	48 ff c3             	inc    rbx
  9ac432:	49 39 dc             	cmp    r12,rbx
  9ac435:	75 e9                	jne    0x9ac420
  9ac437:	31 db                	xor    ebx,ebx
  9ac439:	89 d8                	mov    eax,ebx
  9ac43b:	48 83 c4 38          	add    rsp,0x38
  9ac43f:	5b                   	pop    rbx
  9ac440:	41 5c                	pop    r12
  9ac442:	41 5d                	pop    r13
  9ac444:	41 5e                	pop    r14
  9ac446:	41 5f                	pop    r15
  9ac448:	5d                   	pop    rbp
  9ac449:	c3                   	ret
  9ac44a:	90                   	nop
  9ac44b:	90                   	nop
  9ac44c:	90                   	nop
  9ac44d:	90                   	nop
  9ac44e:	90                   	nop
  9ac44f:	90                   	nop
  9ac450:	55                   	push   rbp
  9ac451:	48 89 e5             	mov    rbp,rsp
  9ac454:	41 56                	push   r14
  9ac456:	53                   	push   rbx
  9ac457:	48 89 fb             	mov    rbx,rdi
  9ac45a:	48 c7 c0 e0 f7 fd ff 	mov    rax,0xfffffffffffdf7e0
  9ac461:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac468:	0f 1f 84 00 00 00 00 
  9ac46f:	00 
  9ac470:	48 8b 8c 03 90 08 02 	mov    rcx,QWORD PTR [rbx+rax*1+0x20890]
  9ac477:	00 
  9ac478:	48 09 8c 03 b0 10 04 	or     QWORD PTR [rbx+rax*1+0x410b0],rcx
  9ac47f:	00 
  9ac480:	48 c7 84 03 90 08 02 	mov    QWORD PTR [rbx+rax*1+0x20890],0x0
  9ac487:	00 00 00 00 00 
  9ac48c:	48 83 c0 08          	add    rax,0x8
  9ac490:	75 de                	jne    0x9ac470
  9ac492:	8b 43 48             	mov    eax,DWORD PTR [rbx+0x48]
  9ac495:	4c 8d 73 28          	lea    r14,[rbx+0x28]
  9ac499:	31 f6                	xor    esi,esi
  9ac49b:	31 d2                	xor    edx,edx
  9ac49d:	31 c9                	xor    ecx,ecx
  9ac49f:	4c 89 f7             	mov    rdi,r14
  9ac4a2:	01 43 4c             	add    DWORD PTR [rbx+0x4c],eax
  9ac4a5:	c7 43 48 00 00 00 00 	mov    DWORD PTR [rbx+0x48],0x0
  9ac4ac:	80 4b 68 01          	or     BYTE PTR [rbx+0x68],0x1
  9ac4b0:	e8 eb aa b1 ff       	call   0x4c6fa0
  9ac4b5:	e8 66 1b f3 ff       	call   0x8de020
  9ac4ba:	4c 89 f7             	mov    rdi,r14
  9ac4bd:	31 f6                	xor    esi,esi
  9ac4bf:	31 d2                	xor    edx,edx
  9ac4c1:	31 c9                	xor    ecx,ecx
  9ac4c3:	e8 38 a5 b1 ff       	call   0x4c6a00
  9ac4c8:	0f b6 43 68          	movzx  eax,BYTE PTR [rbx+0x68]
  9ac4cc:	89 c1                	mov    ecx,eax
  9ac4ce:	80 e1 fe             	and    cl,0xfe
  9ac4d1:	88 4b 68             	mov    BYTE PTR [rbx+0x68],cl
  9ac4d4:	a8 02                	test   al,0x2
  9ac4d6:	75 05                	jne    0x9ac4dd
  9ac4d8:	5b                   	pop    rbx
  9ac4d9:	41 5e                	pop    r14
  9ac4db:	5d                   	pop    rbp
  9ac4dc:	c3                   	ret
  9ac4dd:	24 fc                	and    al,0xfc
  9ac4df:	88 43 68             	mov    BYTE PTR [rbx+0x68],al
  9ac4e2:	ff 43 5c             	inc    DWORD PTR [rbx+0x5c]
  9ac4e5:	48 83 c3 5c          	add    rbx,0x5c
  9ac4e9:	48 89 df             	mov    rdi,rbx
  9ac4ec:	5b                   	pop    rbx
  9ac4ed:	41 5e                	pop    r14
  9ac4ef:	5d                   	pop    rbp
  9ac4f0:	e9 1b a4 25 00       	jmp    0xc06910
  9ac4f5:	90                   	nop
  9ac4f6:	90                   	nop
  9ac4f7:	90                   	nop
  9ac4f8:	90                   	nop
  9ac4f9:	90                   	nop
  9ac4fa:	90                   	nop
  9ac4fb:	90                   	nop
  9ac4fc:	90                   	nop
  9ac4fd:	90                   	nop
  9ac4fe:	90                   	nop
  9ac4ff:	90                   	nop
  9ac500:	55                   	push   rbp
  9ac501:	48 89 e5             	mov    rbp,rsp
  9ac504:	41 57                	push   r15
  9ac506:	41 56                	push   r14
  9ac508:	41 55                	push   r13
  9ac50a:	41 54                	push   r12
  9ac50c:	53                   	push   rbx
  9ac50d:	48 83 ec 28          	sub    rsp,0x28
  9ac511:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
  9ac515:	41 89 f7             	mov    r15d,esi
  9ac518:	44 8b 2d c1 a2 ba 01 	mov    r13d,DWORD PTR [rip+0x1baa2c1]        # 0x25567e0
  9ac51f:	ba 01 00 00 00       	mov    edx,0x1
  9ac524:	49 c1 e7 10          	shl    r15,0x10
  9ac528:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  9ac52c:	4a 8d 34 38          	lea    rsi,[rax+r15*1]
  9ac530:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9ac537:	00 00 
  9ac539:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  9ac540:	01 
  9ac541:	4c 8b 25 70 99 1f 03 	mov    r12,QWORD PTR [rip+0x31f9970]        # 0x3ba5eb8
  9ac548:	4c 89 65 d0          	mov    QWORD PTR [rbp-0x30],r12
  9ac54c:	65 44 8b 34 25 34 00 	mov    r14d,DWORD PTR gs:0x34
  9ac553:	00 00 
  9ac555:	41 c1 e6 10          	shl    r14d,0x10
  9ac559:	4b 8d 1c 34          	lea    rbx,[r12+r14*1]
  9ac55d:	48 89 df             	mov    rdi,rbx
  9ac560:	e8 7b 24 f3 ff       	call   0x8de9e0
  9ac565:	4b 8d bc 34 00 40 00 	lea    rdi,[r12+r14*1+0x4000]
  9ac56c:	00 
  9ac56d:	4c 8b 65 c8          	mov    r12,QWORD PTR [rbp-0x38]
  9ac571:	ba 01 00 00 00       	mov    edx,0x1
  9ac576:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  9ac57a:	4b 8d b4 3c 00 40 00 	lea    rsi,[r12+r15*1+0x4000]
  9ac581:	00 
  9ac582:	e8 59 24 f3 ff       	call   0x8de9e0
  9ac587:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  9ac58b:	4b 8d b4 3c 00 80 00 	lea    rsi,[r12+r15*1+0x8000]
  9ac592:	00 
  9ac593:	ba 01 00 00 00       	mov    edx,0x1
  9ac598:	4a 8d bc 30 00 80 00 	lea    rdi,[rax+r14*1+0x8000]
  9ac59f:	00 
  9ac5a0:	48 89 7d c0          	mov    QWORD PTR [rbp-0x40],rdi
  9ac5a4:	e8 37 24 f3 ff       	call   0x8de9e0
  9ac5a9:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  9ac5ad:	4b 8d b4 3c 00 c0 00 	lea    rsi,[r12+r15*1+0xc000]
  9ac5b4:	00 
  9ac5b5:	ba 01 00 00 00       	mov    edx,0x1
  9ac5ba:	4e 8d b4 30 00 c0 00 	lea    r14,[rax+r14*1+0xc000]
  9ac5c1:	00 
  9ac5c2:	4c 89 f7             	mov    rdi,r14
  9ac5c5:	e8 16 24 f3 ff       	call   0x8de9e0
  9ac5ca:	0f ae f0             	mfence
  9ac5cd:	31 c0                	xor    eax,eax
  9ac5cf:	90                   	nop
  9ac5d0:	0f ae 3c 03          	clflush BYTE PTR [rbx+rax*1]
  9ac5d4:	4c 01 e8             	add    rax,r13
  9ac5d7:	48 3d 00 00 01 00    	cmp    rax,0x10000
  9ac5dd:	72 f1                	jb     0x9ac5d0
  9ac5df:	0f ae f0             	mfence
  9ac5e2:	48 89 df             	mov    rdi,rbx
  9ac5e5:	e8 36 25 f3 ff       	call   0x8deb20
  9ac5ea:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  9ac5ee:	e8 2d 25 f3 ff       	call   0x8deb20
  9ac5f3:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  9ac5f7:	e8 24 25 f3 ff       	call   0x8deb20
  9ac5fc:	4c 89 f7             	mov    rdi,r14
  9ac5ff:	e8 1c 25 f3 ff       	call   0x8deb20
  9ac604:	48 8d 93 00 00 01 00 	lea    rdx,[rbx+0x10000]
  9ac60b:	48 8d 3d e6 c9 19 03 	lea    rdi,[rip+0x319c9e6]        # 0x3b48ff8
  9ac612:	48 89 de             	mov    rsi,rbx
  9ac615:	e8 d6 15 f3 ff       	call   0x8ddbf0
  9ac61a:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9ac621:	00 00 
  9ac623:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  9ac628:	f0 0f c1 88 a8 05 00 	lock xadd DWORD PTR [rax+0x5a8],ecx
  9ac62f:	00 
  9ac630:	48 83 c4 28          	add    rsp,0x28
  9ac634:	81 f9 01 00 00 80    	cmp    ecx,0x80000001
  9ac63a:	75 0f                	jne    0x9ac64b
  9ac63c:	5b                   	pop    rbx
  9ac63d:	41 5c                	pop    r12
  9ac63f:	41 5d                	pop    r13
  9ac641:	41 5e                	pop    r14
  9ac643:	41 5f                	pop    r15
  9ac645:	5d                   	pop    rbp
  9ac646:	e9 a5 b4 d0 ff       	jmp    0x6b7af0
  9ac64b:	5b                   	pop    rbx
  9ac64c:	41 5c                	pop    r12
  9ac64e:	41 5d                	pop    r13
  9ac650:	41 5e                	pop    r14
  9ac652:	41 5f                	pop    r15
  9ac654:	5d                   	pop    rbp
  9ac655:	c3                   	ret
  9ac656:	90                   	nop
  9ac657:	90                   	nop
  9ac658:	90                   	nop
  9ac659:	90                   	nop
  9ac65a:	90                   	nop
  9ac65b:	90                   	nop
  9ac65c:	90                   	nop
  9ac65d:	90                   	nop
  9ac65e:	90                   	nop
  9ac65f:	90                   	nop
  9ac660:	55                   	push   rbp
  9ac661:	48 89 e5             	mov    rbp,rsp
  9ac664:	b8 06 00 00 00       	mov    eax,0x6
  9ac669:	5d                   	pop    rbp
  9ac66a:	c3                   	ret
  9ac66b:	90                   	nop
  9ac66c:	90                   	nop
  9ac66d:	90                   	nop
  9ac66e:	90                   	nop
  9ac66f:	90                   	nop
  9ac670:	55                   	push   rbp
  9ac671:	48 89 e5             	mov    rbp,rsp
  9ac674:	b8 06 00 00 00       	mov    eax,0x6
  9ac679:	5d                   	pop    rbp
  9ac67a:	c3                   	ret
  9ac67b:	90                   	nop
  9ac67c:	90                   	nop
  9ac67d:	90                   	nop
  9ac67e:	90                   	nop
  9ac67f:	90                   	nop
  9ac680:	55                   	push   rbp
  9ac681:	48 89 e5             	mov    rbp,rsp
  9ac684:	41 57                	push   r15
  9ac686:	41 56                	push   r14
  9ac688:	41 55                	push   r13
  9ac68a:	41 54                	push   r12
  9ac68c:	53                   	push   rbx
  9ac68d:	48 83 ec 28          	sub    rsp,0x28
  9ac691:	4c 8d 3d 78 fc f6 02 	lea    r15,[rip+0x2f6fc78]        # 0x391c310
  9ac698:	49 8b 07             	mov    rax,QWORD PTR [r15]
  9ac69b:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ac69f:	4c 8b 27             	mov    r12,QWORD PTR [rdi]
  9ac6a2:	48 81 fe 02 a8 10 40 	cmp    rsi,0x4010a802
  9ac6a9:	0f 84 ec 00 00 00    	je     0x9ac79b
  9ac6af:	41 be 19 00 00 00    	mov    r14d,0x19
  9ac6b5:	b8 01 a8 20 c0       	mov    eax,0xc020a801
  9ac6ba:	48 39 c6             	cmp    rsi,rax
  9ac6bd:	0f 85 23 01 00 00    	jne    0x9ac7e6
  9ac6c3:	4c 8b 2a             	mov    r13,QWORD PTR [rdx]
  9ac6c6:	8b 42 18             	mov    eax,DWORD PTR [rdx+0x18]
  9ac6c9:	41 be 16 00 00 00    	mov    r14d,0x16
  9ac6cf:	66 45 85 ed          	test   r13w,r13w
  9ac6d3:	0f 95 c1             	setne  cl
  9ac6d6:	a9 ff ff ff 00       	test   eax,0xffffff
  9ac6db:	40 0f 95 c6          	setne  sil
  9ac6df:	40 08 ce             	or     sil,cl
  9ac6e2:	0f 85 fe 00 00 00    	jne    0x9ac7e6
  9ac6e8:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  9ac6ec:	4c 8b 4a 10          	mov    r9,QWORD PTR [rdx+0x10]
  9ac6f0:	85 c0                	test   eax,eax
  9ac6f2:	0f 84 0d 01 00 00    	je     0x9ac805
  9ac6f8:	c1 f8 18             	sar    eax,0x18
  9ac6fb:	83 f8 10             	cmp    eax,0x10
  9ac6fe:	0f 8c e2 00 00 00    	jl     0x9ac7e6
  9ac704:	4d 85 ed             	test   r13,r13
  9ac707:	0f 84 06 01 00 00    	je     0x9ac813
  9ac70d:	0f 88 05 01 00 00    	js     0x9ac818
  9ac713:	49 8b 4c 24 38       	mov    rcx,QWORD PTR [r12+0x38]
  9ac718:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  9ac71c:	49 8b 54 24 40       	mov    rdx,QWORD PTR [r12+0x40]
  9ac721:	41 8b 7c 24 60       	mov    edi,DWORD PTR [r12+0x60]
  9ac726:	be 01 00 00 00       	mov    esi,0x1
  9ac72b:	c4 e2 f9 f7 c6       	shlx   rax,rsi,rax
  9ac730:	4c 39 c1             	cmp    rcx,r8
  9ac733:	4c 0f 4f c1          	cmovg  r8,rcx
  9ac737:	4c 39 ca             	cmp    rdx,r9
  9ac73a:	4c 0f 4c ca          	cmovl  r9,rdx
  9ac73e:	41 8b 54 24 64       	mov    edx,DWORD PTR [r12+0x64]
  9ac743:	65 48 8b 0c 25 00 00 	mov    rcx,QWORD PTR gs:0x0
  9ac74a:	00 00 
  9ac74c:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  9ac750:	31 f6                	xor    esi,esi
  9ac752:	f6 81 88 05 00 00 01 	test   BYTE PTR [rcx+0x588],0x1
  9ac759:	40 0f 94 c6          	sete   sil
  9ac75d:	44 8d 14 f5 03 00 00 	lea    r10d,[rsi*8+0x3]
  9ac764:	00 
  9ac765:	48 83 ec 08          	sub    rsp,0x8
  9ac769:	4c 8d 5d c8          	lea    r11,[rbp-0x38]
  9ac76d:	31 f6                	xor    esi,esi
  9ac76f:	41 53                	push   r11
  9ac771:	68 00 00 00 20       	push   0x20000000
  9ac776:	41 52                	push   r10
  9ac778:	50                   	push   rax
  9ac779:	41 55                	push   r13
  9ac77b:	e8 d0 71 a1 ff       	call   0x3c3950
  9ac780:	48 83 c4 30          	add    rsp,0x30
  9ac784:	85 c0                	test   eax,eax
  9ac786:	0f 84 94 00 00 00    	je     0x9ac820
  9ac78c:	83 f8 23             	cmp    eax,0x23
  9ac78f:	41 be 0c 00 00 00    	mov    r14d,0xc
  9ac795:	44 0f 45 f0          	cmovne r14d,eax
  9ac799:	eb 4b                	jmp    0x9ac7e6
  9ac79b:	49 8d 5c 24 28       	lea    rbx,[r12+0x28]
  9ac7a0:	49 89 d5             	mov    r13,rdx
  9ac7a3:	45 31 f6             	xor    r14d,r14d
  9ac7a6:	31 f6                	xor    esi,esi
  9ac7a8:	31 d2                	xor    edx,edx
  9ac7aa:	31 c9                	xor    ecx,ecx
  9ac7ac:	48 89 df             	mov    rdi,rbx
  9ac7af:	e8 4c a2 b1 ff       	call   0x4c6a00
  9ac7b4:	41 8b 44 24 4c       	mov    eax,DWORD PTR [r12+0x4c]
  9ac7b9:	48 89 df             	mov    rdi,rbx
  9ac7bc:	31 f6                	xor    esi,esi
  9ac7be:	31 d2                	xor    edx,edx
  9ac7c0:	31 c9                	xor    ecx,ecx
  9ac7c2:	41 89 45 00          	mov    DWORD PTR [r13+0x0],eax
  9ac7c6:	41 8b 44 24 48       	mov    eax,DWORD PTR [r12+0x48]
  9ac7cb:	41 89 45 04          	mov    DWORD PTR [r13+0x4],eax
  9ac7cf:	41 8b 44 24 54       	mov    eax,DWORD PTR [r12+0x54]
  9ac7d4:	41 89 45 08          	mov    DWORD PTR [r13+0x8],eax
  9ac7d8:	41 8b 44 24 50       	mov    eax,DWORD PTR [r12+0x50]
  9ac7dd:	41 89 45 0c          	mov    DWORD PTR [r13+0xc],eax
  9ac7e1:	e8 ba a7 b1 ff       	call   0x4c6fa0
  9ac7e6:	49 8b 07             	mov    rax,QWORD PTR [r15]
  9ac7e9:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9ac7ed:	0f 85 8e 01 00 00    	jne    0x9ac981
  9ac7f3:	44 89 f0             	mov    eax,r14d
  9ac7f6:	48 83 c4 28          	add    rsp,0x28
  9ac7fa:	5b                   	pop    rbx
  9ac7fb:	41 5c                	pop    r12
  9ac7fd:	41 5d                	pop    r13
  9ac7ff:	41 5e                	pop    r14
  9ac801:	41 5f                	pop    r15
  9ac803:	5d                   	pop    rbp
  9ac804:	c3                   	ret
  9ac805:	b8 10 00 00 00       	mov    eax,0x10
  9ac80a:	4d 85 ed             	test   r13,r13
  9ac80d:	0f 85 fa fe ff ff    	jne    0x9ac70d
  9ac813:	45 31 f6             	xor    r14d,r14d
  9ac816:	eb ce                	jmp    0x9ac7e6
  9ac818:	41 be 0c 00 00 00    	mov    r14d,0xc
  9ac81e:	eb c6                	jmp    0x9ac7e6
  9ac820:	49 8d 7c 24 28       	lea    rdi,[r12+0x28]
  9ac825:	45 31 f6             	xor    r14d,r14d
  9ac828:	31 f6                	xor    esi,esi
  9ac82a:	31 d2                	xor    edx,edx
  9ac82c:	31 c9                	xor    ecx,ecx
  9ac82e:	48 89 7d c0          	mov    QWORD PTR [rbp-0x40],rdi
  9ac832:	e8 c9 a1 b1 ff       	call   0x4c6a00
  9ac837:	4c 89 e8             	mov    rax,r13
  9ac83a:	48 b9 00 00 ff ff ff 	movabs rcx,0xffffffff0000
  9ac841:	ff 00 00 
  9ac844:	49 8d 94 24 90 08 02 	lea    rdx,[r12+0x20890]
  9ac84b:	00 
  9ac84c:	48 8d 3d 7d d6 a0 00 	lea    rdi,[rip+0xa0d67d]        # 0x13b9ed0
  9ac853:	48 c7 c3 ff ff ff ff 	mov    rbx,0xffffffffffffffff
  9ac85a:	48 c1 e8 10          	shr    rax,0x10
  9ac85e:	4c 01 e9             	add    rcx,r13
  9ac861:	41 01 44 24 4c       	add    DWORD PTR [r12+0x4c],eax
  9ac866:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  9ac86a:	49 2b 44 24 38       	sub    rax,QWORD PTR [r12+0x38]
  9ac86f:	49 81 c4 98 08 02 00 	add    r12,0x20898
  9ac876:	48 01 c1             	add    rcx,rax
  9ac879:	48 c1 e8 10          	shr    rax,0x10
  9ac87d:	48 c1 e9 10          	shr    rcx,0x10
  9ac881:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac888:	0f 1f 84 00 00 00 00 
  9ac88f:	00 
  9ac890:	4e 63 1c b7          	movsxd r11,DWORD PTR [rdi+r14*4]
  9ac894:	89 ce                	mov    esi,ecx
  9ac896:	41 89 c1             	mov    r9d,eax
  9ac899:	c1 f8 06             	sar    eax,0x6
  9ac89c:	c1 f9 06             	sar    ecx,0x6
  9ac89f:	40 f6 d6             	not    sil
  9ac8a2:	39 c8                	cmp    eax,ecx
  9ac8a4:	4c 63 e8             	movsxd r13,eax
  9ac8a7:	c4 62 cb f7 d3       	shrx   r10,rbx,rsi
  9ac8ac:	48 c7 c6 ff ff ff ff 	mov    rsi,0xffffffffffffffff
  9ac8b3:	49 0f 44 f2          	cmove  rsi,r10
  9ac8b7:	4e 8d 04 da          	lea    r8,[rdx+r11*8]
  9ac8bb:	c4 e2 b3 f7 f6       	shrx   rsi,rsi,r9
  9ac8c0:	c4 e2 b1 f7 f6       	shlx   rsi,rsi,r9
  9ac8c5:	4f 8b 0c e8          	mov    r9,QWORD PTR [r8+r13*8]
  9ac8c9:	4c 09 ce             	or     rsi,r9
  9ac8cc:	4d 85 c9             	test   r9,r9
  9ac8cf:	41 0f 94 c1          	sete   r9b
  9ac8d3:	4b 89 34 e8          	mov    QWORD PTR [r8+r13*8],rsi
  9ac8d7:	41 39 cd             	cmp    r13d,ecx
  9ac8da:	74 6e                	je     0x9ac94a
  9ac8dc:	8d 70 01             	lea    esi,[rax+0x1]
  9ac8df:	39 ce                	cmp    esi,ecx
  9ac8e1:	7d 48                	jge    0x9ac92b
  9ac8e3:	48 63 d9             	movsxd rbx,ecx
  9ac8e6:	4f 8d 1c dc          	lea    r11,[r12+r11*8]
  9ac8ea:	49 89 d7             	mov    r15,rdx
  9ac8ed:	48 89 fa             	mov    rdx,rdi
  9ac8f0:	48 8d 73 ff          	lea    rsi,[rbx-0x1]
  9ac8f4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9ac8fb:	00 00 00 00 00 
  9ac900:	4b 83 3c eb 00       	cmp    QWORD PTR [r11+r13*8],0x0
  9ac905:	4b c7 04 eb ff ff ff 	mov    QWORD PTR [r11+r13*8],0xffffffffffffffff
  9ac90c:	ff 
  9ac90d:	40 0f 94 c7          	sete   dil
  9ac911:	49 ff c5             	inc    r13
  9ac914:	41 08 f9             	or     r9b,dil
  9ac917:	4c 39 ee             	cmp    rsi,r13
  9ac91a:	75 e4                	jne    0x9ac900
  9ac91c:	48 89 d7             	mov    rdi,rdx
  9ac91f:	4c 89 fa             	mov    rdx,r15
  9ac922:	4c 8d 3d e7 f9 f6 02 	lea    r15,[rip+0x2f6f9e7]        # 0x391c310
  9ac929:	eb 03                	jmp    0x9ac92e
  9ac92b:	48 63 d9             	movsxd rbx,ecx
  9ac92e:	49 8b 34 d8          	mov    rsi,QWORD PTR [r8+rbx*8]
  9ac932:	49 09 f2             	or     r10,rsi
  9ac935:	48 85 f6             	test   rsi,rsi
  9ac938:	40 0f 94 c6          	sete   sil
  9ac93c:	4d 89 14 d8          	mov    QWORD PTR [r8+rbx*8],r10
  9ac940:	48 c7 c3 ff ff ff ff 	mov    rbx,0xffffffffffffffff
  9ac947:	41 08 f1             	or     r9b,sil
  9ac94a:	41 f6 c1 01          	test   r9b,0x1
  9ac94e:	74 0e                	je     0x9ac95e
  9ac950:	49 83 fe 02          	cmp    r14,0x2
  9ac954:	4d 8d 76 01          	lea    r14,[r14+0x1]
  9ac958:	0f 82 32 ff ff ff    	jb     0x9ac890
  9ac95e:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  9ac962:	45 31 f6             	xor    r14d,r14d
  9ac965:	31 f6                	xor    esi,esi
  9ac967:	31 d2                	xor    edx,edx
  9ac969:	31 c9                	xor    ecx,ecx
  9ac96b:	e8 30 a6 b1 ff       	call   0x4c6fa0
  9ac970:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
  9ac974:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9ac978:	48 89 48 08          	mov    QWORD PTR [rax+0x8],rcx
  9ac97c:	e9 65 fe ff ff       	jmp    0x9ac7e6
  9ac981:	e8 2a 0d d5 ff       	call   0x6fd6b0
  9ac986:	0f 0b                	ud2
  9ac988:	90                   	nop
  9ac989:	90                   	nop
  9ac98a:	90                   	nop
  9ac98b:	90                   	nop
  9ac98c:	90                   	nop
  9ac98d:	90                   	nop
  9ac98e:	90                   	nop
  9ac98f:	90                   	nop
  9ac990:	55                   	push   rbp
  9ac991:	48 89 e5             	mov    rbp,rsp
  9ac994:	b8 2d 00 00 00       	mov    eax,0x2d
  9ac999:	5d                   	pop    rbp
  9ac99a:	c3                   	ret
  9ac99b:	90                   	nop
  9ac99c:	90                   	nop
  9ac99d:	90                   	nop
  9ac99e:	90                   	nop
  9ac99f:	90                   	nop
  9ac9a0:	55                   	push   rbp
  9ac9a1:	48 89 e5             	mov    rbp,rsp
  9ac9a4:	b8 2d 00 00 00       	mov    eax,0x2d
  9ac9a9:	5d                   	pop    rbp
  9ac9aa:	c3                   	ret
  9ac9ab:	90                   	nop
  9ac9ac:	90                   	nop
  9ac9ad:	90                   	nop
  9ac9ae:	90                   	nop
  9ac9af:	90                   	nop
  9ac9b0:	55                   	push   rbp
  9ac9b1:	48 89 e5             	mov    rbp,rsp
  9ac9b4:	41 57                	push   r15
  9ac9b6:	41 56                	push   r14
  9ac9b8:	53                   	push   rbx
  9ac9b9:	50                   	push   rax
  9ac9ba:	48 89 f3             	mov    rbx,rsi
  9ac9bd:	49 89 fe             	mov    r14,rdi
  9ac9c0:	be 78 00 00 00       	mov    esi,0x78
  9ac9c5:	48 89 df             	mov    rdi,rbx
  9ac9c8:	e8 23 c6 8a ff       	call   0x258ff0
  9ac9cd:	4d 8b 3e             	mov    r15,QWORD PTR [r14]
  9ac9d0:	c7 43 58 00 00 01 00 	mov    DWORD PTR [rbx+0x58],0x10000
  9ac9d7:	66 c7 43 08 00 b0    	mov    WORD PTR [rbx+0x8],0xb000
  9ac9dd:	31 f6                	xor    esi,esi
  9ac9df:	31 d2                	xor    edx,edx
  9ac9e1:	31 c9                	xor    ecx,ecx
  9ac9e3:	4d 8d 77 28          	lea    r14,[r15+0x28]
  9ac9e7:	4c 89 f7             	mov    rdi,r14
  9ac9ea:	e8 11 a0 b1 ff       	call   0x4c6a00
  9ac9ef:	41 8b 47 48          	mov    eax,DWORD PTR [r15+0x48]
  9ac9f3:	4c 89 f7             	mov    rdi,r14
  9ac9f6:	31 f6                	xor    esi,esi
  9ac9f8:	31 d2                	xor    edx,edx
  9ac9fa:	31 c9                	xor    ecx,ecx
  9ac9fc:	01 c0                	add    eax,eax
  9ac9fe:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9aca02:	e8 99 a5 b1 ff       	call   0x4c6fa0
  9aca07:	31 c0                	xor    eax,eax
  9aca09:	48 83 c4 08          	add    rsp,0x8
  9aca0d:	5b                   	pop    rbx
  9aca0e:	41 5e                	pop    r14
  9aca10:	41 5f                	pop    r15
  9aca12:	5d                   	pop    rbp
  9aca13:	c3                   	ret
  9aca14:	90                   	nop
  9aca15:	90                   	nop
  9aca16:	90                   	nop
  9aca17:	90                   	nop
  9aca18:	90                   	nop
  9aca19:	90                   	nop
  9aca1a:	90                   	nop
  9aca1b:	90                   	nop
  9aca1c:	90                   	nop
  9aca1d:	90                   	nop
  9aca1e:	90                   	nop
  9aca1f:	90                   	nop
  9aca20:	48 89 f8             	mov    rax,rdi
  9aca23:	48 8b 3f             	mov    rdi,QWORD PTR [rdi]
  9aca26:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
  9aca2d:	b8 ff ff ff ff       	mov    eax,0xffffffff
  9aca32:	f0 0f c1 47 58       	lock xadd DWORD PTR [rdi+0x58],eax
  9aca37:	83 f8 01             	cmp    eax,0x1
  9aca3a:	75 0a                	jne    0x9aca46
  9aca3c:	55                   	push   rbp
  9aca3d:	48 89 e5             	mov    rbp,rsp
  9aca40:	e8 bb b1 ff ff       	call   0x9a7c00
  9aca45:	5d                   	pop    rbp
  9aca46:	31 c0                	xor    eax,eax
  9aca48:	c3                   	ret
  9aca49:	90                   	nop
  9aca4a:	90                   	nop
  9aca4b:	90                   	nop
  9aca4c:	90                   	nop
  9aca4d:	90                   	nop
  9aca4e:	90                   	nop
  9aca4f:	90                   	nop
  9aca50:	55                   	push   rbp
  9aca51:	48 89 e5             	mov    rbp,rsp
  9aca54:	c7 46 04 ff 00 00 00 	mov    DWORD PTR [rsi+0x4],0xff
  9aca5b:	31 c0                	xor    eax,eax
  9aca5d:	5d                   	pop    rbp
  9aca5e:	c3                   	ret
  9aca5f:	90                   	nop
  9aca60:	55                   	push   rbp
  9aca61:	48 89 e5             	mov    rbp,rsp
  9aca64:	41 57                	push   r15
  9aca66:	41 56                	push   r14
  9aca68:	41 55                	push   r13
  9aca6a:	41 54                	push   r12
  9aca6c:	53                   	push   rbx
  9aca6d:	48 83 ec 18          	sub    rsp,0x18
  9aca71:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
  9aca76:	b8 16 00 00 00       	mov    eax,0x16
  9aca7b:	74 0f                	je     0x9aca8c
  9aca7d:	48 83 c4 18          	add    rsp,0x18
  9aca81:	5b                   	pop    rbx
  9aca82:	41 5c                	pop    r12
  9aca84:	41 5d                	pop    r13
  9aca86:	41 5e                	pop    r14
  9aca88:	41 5f                	pop    r15
  9aca8a:	5d                   	pop    rbp
  9aca8b:	c3                   	ret
  9aca8c:	4c 8b 7d 20          	mov    r15,QWORD PTR [rbp+0x20]
  9aca90:	8b 5d 10             	mov    ebx,DWORD PTR [rbp+0x10]
  9aca93:	4c 8b 17             	mov    r10,QWORD PTR [rdi]
  9aca96:	49 8b 7f 08          	mov    rdi,QWORD PTR [r15+0x8]
  9aca9a:	41 89 db             	mov    r11d,ebx
  9aca9d:	41 81 e3 00 00 00 ff 	and    r11d,0xff000000
  9acaa4:	74 0b                	je     0x9acab1
  9acaa6:	41 81 fb 00 00 00 15 	cmp    r11d,0x15000000
  9acaad:	7c ce                	jl     0x9aca7d
  9acaaf:	eb 06                	jmp    0x9acab7
  9acab1:	81 cb 00 00 00 15    	or     ebx,0x15000000
  9acab7:	41 89 db             	mov    r11d,ebx
  9acaba:	41 83 e3 03          	and    r11d,0x3
  9acabe:	41 83 fb 01          	cmp    r11d,0x1
  9acac2:	41 0f 95 c3          	setne  r11b
  9acac6:	45 21 c1             	and    r9d,r8d
  9acac9:	41 f7 d1             	not    r9d
  9acacc:	41 f6 c1 33          	test   r9b,0x33
  9acad0:	41 0f 95 c1          	setne  r9b
  9acad4:	45 08 d9             	or     r9b,r11b
  9acad7:	75 a4                	jne    0x9aca7d
  9acad9:	f6 c3 10             	test   bl,0x10
  9acadc:	75 0b                	jne    0x9acae9
  9acade:	49 89 c9             	mov    r9,rcx
  9acae1:	49 c1 e1 2b          	shl    r9,0x2b
  9acae5:	75 96                	jne    0x9aca7d
  9acae7:	eb 40                	jmp    0x9acb29
  9acae9:	4c 8b 0a             	mov    r9,QWORD PTR [rdx]
  9acaec:	41 f7 c1 ff ff 1f 00 	test   r9d,0x1fffff
  9acaf3:	75 88                	jne    0x9aca7d
  9acaf5:	4d 8d 1c 09          	lea    r11,[r9+rcx*1]
  9acaf9:	49 c1 eb 1c          	shr    r11,0x1c
  9acafd:	49 83 fb 7f          	cmp    r11,0x7f
  9acb01:	41 0f 92 c3          	setb   r11b
  9acb05:	49 c1 e9 1c          	shr    r9,0x1c
  9acb09:	49 81 f9 ff 00 00 00 	cmp    r9,0xff
  9acb10:	41 0f 93 c1          	setae  r9b
  9acb14:	f7 c1 ff ff 1f 00    	test   ecx,0x1fffff
  9acb1a:	0f 85 5d ff ff ff    	jne    0x9aca7d
  9acb20:	45 08 d9             	or     r9b,r11b
  9acb23:	0f 84 54 ff ff ff    	je     0x9aca7d
  9acb29:	8b 87 c0 05 00 00    	mov    eax,DWORD PTR [rdi+0x5c0]
  9acb2f:	44 8b 9f d0 05 00 00 	mov    r11d,DWORD PTR [rdi+0x5d0]
  9acb36:	4d 8b 8f 40 01 00 00 	mov    r9,QWORD PTR [r15+0x140]
  9acb3d:	49 89 f5             	mov    r13,rsi
  9acb40:	45 89 c4             	mov    r12d,r8d
  9acb43:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  9acb47:	bf 0b 00 00 00       	mov    edi,0xb
  9acb4c:	4c 89 d6             	mov    rsi,r10
  9acb4f:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  9acb53:	48 89 ca             	mov    rdx,rcx
  9acb56:	b9 33 00 00 00       	mov    ecx,0x33
  9acb5b:	45 31 c0             	xor    r8d,r8d
  9acb5e:	41 53                	push   r11
  9acb60:	50                   	push   rax
  9acb61:	e8 fa 0e ab ff       	call   0x45da60
  9acb66:	48 83 c4 10          	add    rsp,0x10
  9acb6a:	48 85 c0             	test   rax,rax
  9acb6d:	74 40                	je     0x9acbaf
  9acb6f:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  9acb73:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
  9acb77:	49 89 c6             	mov    r14,rax
  9acb7a:	41 0f b7 cc          	movzx  ecx,r12w
  9acb7e:	4c 89 ef             	mov    rdi,r13
  9acb81:	41 b8 33 00 00 00    	mov    r8d,0x33
  9acb87:	41 89 d9             	mov    r9d,ebx
  9acb8a:	41 57                	push   r15
  9acb8c:	6a 00                	push   0x0
  9acb8e:	6a 00                	push   0x0
  9acb90:	50                   	push   rax
  9acb91:	e8 9a d3 10 00       	call   0xab9f30
  9acb96:	48 83 c4 20          	add    rsp,0x20
  9acb9a:	85 c0                	test   eax,eax
  9acb9c:	74 1b                	je     0x9acbb9
  9acb9e:	4c 89 f7             	mov    rdi,r14
  9acba1:	89 c3                	mov    ebx,eax
  9acba3:	e8 f8 4f ab ff       	call   0x461ba0
  9acba8:	89 d8                	mov    eax,ebx
  9acbaa:	e9 ce fe ff ff       	jmp    0x9aca7d
  9acbaf:	b8 0c 00 00 00       	mov    eax,0xc
  9acbb4:	e9 c4 fe ff ff       	jmp    0x9aca7d
  9acbb9:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  9acbbd:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9acbc0:	48 89 c1             	mov    rcx,rax
  9acbc3:	48 c1 e9 1c          	shr    rcx,0x1c
  9acbc7:	48 81 f9 fe 00 00 00 	cmp    rcx,0xfe
  9acbce:	77 1a                	ja     0x9acbea
  9acbd0:	48 03 45 d0          	add    rax,QWORD PTR [rbp-0x30]
  9acbd4:	48 b9 00 00 00 f0 07 	movabs rcx,0x7f0000000
  9acbdb:	00 00 00 
  9acbde:	48 ff c1             	inc    rcx
  9acbe1:	48 39 c8             	cmp    rax,rcx
  9acbe4:	72 04                	jb     0x9acbea
  9acbe6:	31 c0                	xor    eax,eax
  9acbe8:	eb 14                	jmp    0x9acbfe
  9acbea:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  9acbf1:	00 00 
  9acbf3:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  9acbf7:	0f b6 80 c0 05 00 00 	movzx  eax,BYTE PTR [rax+0x5c0]
  9acbfe:	41 88 86 9c 01 00 00 	mov    BYTE PTR [r14+0x19c],al
  9acc05:	31 c0                	xor    eax,eax
  9acc07:	e9 71 fe ff ff       	jmp    0x9aca7d
  9acc0c:	90                   	nop
  9acc0d:	90                   	nop
  9acc0e:	90                   	nop
  9acc0f:	90                   	nop
  9acc10:	83 ff 15             	cmp    edi,0x15
  9acc13:	73 0d                	jae    0x9acc22
  9acc15:	89 f8                	mov    eax,edi
  9acc17:	48 8d 0d 96 0f f2 00 	lea    rcx,[rip+0xf20f96]        # 0x18cdbb4
  9acc1e:	8b 04 81             	mov    eax,DWORD PTR [rcx+rax*4]
  9acc21:	c3                   	ret
  9acc22:	55                   	push   rbp
  9acc23:	48 89 e5             	mov    rbp,rsp
  9acc26:	53                   	push   rbx
  9acc27:	50                   	push   rax
  9acc28:	89 fb                	mov    ebx,edi
  9acc2a:	e8 21 4d e4 ff       	call   0x7f1950
  9acc2f:	48 63 f3             	movsxd rsi,ebx
  9acc32:	48 8d 3d e9 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe9]        # 0x9acc22
  9acc39:	e8 62 4c e4 ff       	call   0x7f18a0
  9acc3e:	48 8d 35 5d 7b 8e 00 	lea    rsi,[rip+0x8e7b5d]        # 0x12947a2
  9acc45:	bf 07 00 00 00       	mov    edi,0x7
  9acc4a:	89 da                	mov    edx,ebx
  9acc4c:	31 c0                	xor    eax,eax
  9acc4e:	e8 bd dd 2e 00       	call   0xc9aa10
  9acc53:	0f 0b                	ud2
  9acc55:	90                   	nop
  9acc56:	90                   	nop
  9acc57:	90                   	nop
  9acc58:	90                   	nop
  9acc59:	90                   	nop
  9acc5a:	90                   	nop
  9acc5b:	90                   	nop
  9acc5c:	90                   	nop
  9acc5d:	90                   	nop
  9acc5e:	90                   	nop
  9acc5f:	90                   	nop
  9acc60:	55                   	push   rbp
  9acc61:	48 89 e5             	mov    rbp,rsp
  9acc64:	bf 00 00 40 00       	mov    edi,0x400000
  9acc69:	48 8d 05 10 92 1f 03 	lea    rax,[rip+0x31f9210]        # 0x3ba5e80
  9acc70:	48 c7 05 05 92 1f 03 	mov    QWORD PTR [rip+0x31f9205],0x0        # 0x3ba5e80
  9acc77:	00 00 00 00 
  9acc7b:	48 89 05 06 92 1f 03 	mov    QWORD PTR [rip+0x31f9206],rax        # 0x3ba5e88
  9acc82:	e8 29 67 b5 ff       	call   0x5033b0
  9acc87:	48 8d 35 82 eb 24 02 	lea    rsi,[rip+0x224eb82]        # 0x2bfb810
  9acc8e:	48 89 05 23 92 1f 03 	mov    QWORD PTR [rip+0x31f9223],rax        # 0x3ba5eb8
  9acc95:	48 b8 04 00 00 00 04 	movabs rax,0x400000004
  9acc9c:	00 00 00 
  9acc9f:	bf 00 80 00 00       	mov    edi,0x8000
  9acca4:	ba 02 80 00 00       	mov    edx,0x8002
  9acca9:	48 89 05 10 92 1f 03 	mov    QWORD PTR [rip+0x31f9210],rax        # 0x3ba5ec0
  9accb0:	c7 05 0e 92 1f 03 80 	mov    DWORD PTR [rip+0x31f920e],0x80        # 0x3ba5ec8
  9accb7:	00 00 00 
  9accba:	e8 91 be 25 00       	call   0xc08b50
  9accbf:	48 89 05 1a 92 1f 03 	mov    QWORD PTR [rip+0x31f921a],rax        # 0x3ba5ee0
  9accc6:	48 c7 05 07 92 1f 03 	mov    QWORD PTR [rip+0x31f9207],0xf        # 0x3ba5ed8
  9acccd:	0f 00 00 00 
  9accd1:	5d                   	pop    rbp
  9accd2:	c3                   	ret
  9accd3:	90                   	nop
  9accd4:	90                   	nop
  9accd5:	90                   	nop
  9accd6:	90                   	nop
  9accd7:	90                   	nop
  9accd8:	90                   	nop
  9accd9:	90                   	nop
  9accda:	90                   	nop
  9accdb:	90                   	nop
  9accdc:	90                   	nop
  9accdd:	90                   	nop
  9accde:	90                   	nop
  9accdf:	90                   	nop
  9acce0:	8b 05 5a 33 bb 01    	mov    eax,DWORD PTR [rip+0x1bb335a]        # 0x2560040
  9acce6:	83 f8 ff             	cmp    eax,0xffffffff
  9acce9:	74 01                	je     0x9accec
  9acceb:	c3                   	ret
  9accec:	55                   	push   rbp
  9acced:	48 89 e5             	mov    rbp,rsp
  9accf0:	e8 4b ac 15 00       	call   0xb07940
  9accf5:	89 c1                	mov    ecx,eax
  9accf7:	b8 01 00 00 00       	mov    eax,0x1
  9accfc:	85 c9                	test   ecx,ecx
  9accfe:	75 30                	jne    0x9acd30
  9acd00:	e8 5b ac 15 00       	call   0xb07960
  9acd05:	89 c1                	mov    ecx,eax
  9acd07:	b8 01 00 00 00       	mov    eax,0x1
  9acd0c:	85 c9                	test   ecx,ecx
  9acd0e:	75 20                	jne    0x9acd30
  9acd10:	e8 0b ac 15 00       	call   0xb07920
  9acd15:	85 c0                	test   eax,eax
  9acd17:	74 15                	je     0x9acd2e
  9acd19:	bf 6e 00 00 00       	mov    edi,0x6e
  9acd1e:	e8 7d fc 11 00       	call   0xacc9a0
  9acd23:	89 c1                	mov    ecx,eax
  9acd25:	31 c0                	xor    eax,eax
  9acd27:	85 c9                	test   ecx,ecx
  9acd29:	0f 95 c0             	setne  al
  9acd2c:	eb 02                	jmp    0x9acd30
  9acd2e:	31 c0                	xor    eax,eax
  9acd30:	89 05 0a 33 bb 01    	mov    DWORD PTR [rip+0x1bb330a],eax        # 0x2560040
  9acd36:	5d                   	pop    rbp
  9acd37:	c3                   	ret
  9acd38:	90                   	nop
  9acd39:	90                   	nop
  9acd3a:	90                   	nop
  9acd3b:	90                   	nop
  9acd3c:	90                   	nop
  9acd3d:	90                   	nop
  9acd3e:	90                   	nop
  9acd3f:	90                   	nop
  9acd40:	55                   	push   rbp
  9acd41:	48 89 e5             	mov    rbp,rsp
  9acd44:	41 56                	push   r14
  9acd46:	53                   	push   rbx
  9acd47:	48 89 fb             	mov    rbx,rdi
  9acd4a:	83 fe ff             	cmp    esi,0xffffffff
  9acd4d:	74 55                	je     0x9acda4
  9acd4f:	48 89 df             	mov    rdi,rbx
  9acd52:	41 89 f6             	mov    r14d,esi
  9acd55:	e8 c6 05 00 00       	call   0x9ad320
  9acd5a:	85 c0                	test   eax,eax
  9acd5c:	74 4c                	je     0x9acdaa
  9acd5e:	48 8d 3d 9b 91 1f 03 	lea    rdi,[rip+0x31f919b]        # 0x3ba5f00
  9acd65:	31 f6                	xor    esi,esi
  9acd67:	31 d2                	xor    edx,edx
  9acd69:	31 c9                	xor    ecx,ecx
  9acd6b:	e8 90 9c b1 ff       	call   0x4c6a00
  9acd70:	ff 0d 92 91 1f 03    	dec    DWORD PTR [rip+0x31f9192]        # 0x3ba5f08
  9acd76:	75 18                	jne    0x9acd90
  9acd78:	8b 05 8e 91 1f 03    	mov    eax,DWORD PTR [rip+0x31f918e]        # 0x3ba5f0c
  9acd7e:	85 c0                	test   eax,eax
  9acd80:	74 0e                	je     0x9acd90
  9acd82:	48 8d 3d 87 91 1f 03 	lea    rdi,[rip+0x31f9187]        # 0x3ba5f10
  9acd89:	31 f6                	xor    esi,esi
  9acd8b:	e8 80 22 d9 ff       	call   0x73f010
  9acd90:	48 8d 3d 69 91 1f 03 	lea    rdi,[rip+0x31f9169]        # 0x3ba5f00
  9acd97:	31 f6                	xor    esi,esi
  9acd99:	31 d2                	xor    edx,edx
  9acd9b:	31 c9                	xor    ecx,ecx
  9acd9d:	e8 fe a1 b1 ff       	call   0x4c6fa0
  9acda2:	eb 06                	jmp    0x9acdaa
  9acda4:	41 be 23 00 00 00    	mov    r14d,0x23
  9acdaa:	48 8b 7b 68          	mov    rdi,QWORD PTR [rbx+0x68]
  9acdae:	48 85 ff             	test   rdi,rdi
  9acdb1:	74 14                	je     0x9acdc7
  9acdb3:	48 8d 35 16 32 bb 01 	lea    rsi,[rip+0x1bb3216]        # 0x255ffd0
  9acdba:	48 c7 43 68 00 00 00 	mov    QWORD PTR [rbx+0x68],0x0
  9acdc1:	00 
  9acdc2:	e8 29 c0 25 00       	call   0xc08df0
  9acdc7:	45 85 f6             	test   r14d,r14d
  9acdca:	74 08                	je     0x9acdd4
  9acdcc:	44 89 73 48          	mov    DWORD PTR [rbx+0x48],r14d
  9acdd0:	80 4b 02 01          	or     BYTE PTR [rbx+0x2],0x1
  9acdd4:	48 89 df             	mov    rdi,rbx
  9acdd7:	5b                   	pop    rbx
  9acdd8:	41 5e                	pop    r14
  9acdda:	5d                   	pop    rbp
  9acddb:	e9 60 34 0f 00       	jmp    0xaa0240
  9acde0:	55                   	push   rbp
  9acde1:	48 89 e5             	mov    rbp,rsp
  9acde4:	41 57                	push   r15
  9acde6:	41 56                	push   r14
  9acde8:	41 55                	push   r13
  9acdea:	41 54                	push   r12
  9acdec:	53                   	push   rbx
  9acded:	48 83 ec 38          	sub    rsp,0x38
  9acdf1:	48 8d 05 18 f5 f6 02 	lea    rax,[rip+0x2f6f518]        # 0x391c310
  9acdf8:	48 89 55 b0          	mov    QWORD PTR [rbp-0x50],rdx
  9acdfc:	48 89 75 a8          	mov    QWORD PTR [rbp-0x58],rsi
  9ace00:	49 89 fc             	mov    r12,rdi
  9ace03:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ace06:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ace0a:	4c 8b b7 30 01 00 00 	mov    r14,QWORD PTR [rdi+0x130]
  9ace11:	4c 03 77 20          	add    r14,QWORD PTR [rdi+0x20]
  9ace15:	48 8b 5f 30          	mov    rbx,QWORD PTR [rdi+0x30]
  9ace19:	44 8b 3d 20 32 bb 01 	mov    r15d,DWORD PTR [rip+0x1bb3220]        # 0x2560040
  9ace20:	41 83 ff ff          	cmp    r15d,0xffffffff
  9ace24:	74 0a                	je     0x9ace30
  9ace26:	45 85 ff             	test   r15d,r15d
  9ace29:	75 4a                	jne    0x9ace75
  9ace2b:	e9 99 00 00 00       	jmp    0x9acec9
  9ace30:	e8 0b ab 15 00       	call   0xb07940
  9ace35:	41 bf 01 00 00 00    	mov    r15d,0x1
  9ace3b:	85 c0                	test   eax,eax
  9ace3d:	75 2a                	jne    0x9ace69
  9ace3f:	e8 1c ab 15 00       	call   0xb07960
  9ace44:	85 c0                	test   eax,eax
  9ace46:	75 21                	jne    0x9ace69
  9ace48:	e8 d3 aa 15 00       	call   0xb07920
  9ace4d:	85 c0                	test   eax,eax
  9ace4f:	74 15                	je     0x9ace66
  9ace51:	bf 6e 00 00 00       	mov    edi,0x6e
  9ace56:	e8 45 fb 11 00       	call   0xacc9a0
  9ace5b:	45 31 ff             	xor    r15d,r15d
  9ace5e:	85 c0                	test   eax,eax
  9ace60:	41 0f 95 c7          	setne  r15b
  9ace64:	eb 03                	jmp    0x9ace69
  9ace66:	45 31 ff             	xor    r15d,r15d
  9ace69:	44 89 3d d0 31 bb 01 	mov    DWORD PTR [rip+0x1bb31d0],r15d        # 0x2560040
  9ace70:	45 85 ff             	test   r15d,r15d
  9ace73:	74 54                	je     0x9acec9
  9ace75:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  9ace79:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
  9ace7d:	bf 03 00 01 00       	mov    edi,0x10003
  9ace82:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  9ace89:	00 
  9ace8a:	e8 61 9f a2 ff       	call   0x3d6df0
  9ace8f:	85 c0                	test   eax,eax
  9ace91:	74 19                	je     0x9aceac
  9ace93:	89 c2                	mov    edx,eax
  9ace95:	48 8d 3d c3 f7 8c 00 	lea    rdi,[rip+0x8cf7c3]        # 0x127c65f
  9ace9c:	48 8d 35 b4 26 90 00 	lea    rsi,[rip+0x9026b4]        # 0x12af557
  9acea3:	31 c0                	xor    eax,eax
  9acea5:	e8 66 05 8b ff       	call   0x25d410
  9aceaa:	eb 1d                	jmp    0x9acec9
  9aceac:	4c 89 f0             	mov    rax,r14
  9aceaf:	48 c1 e8 10          	shr    rax,0x10
  9aceb3:	48 2b 45 c8          	sub    rax,QWORD PTR [rbp-0x38]
  9aceb7:	7c 10                	jl     0x9acec9
  9aceb9:	48 3b 45 c0          	cmp    rax,QWORD PTR [rbp-0x40]
  9acebd:	7d 0a                	jge    0x9acec9
  9acebf:	31 d2                	xor    edx,edx
  9acec1:	41 bd 03 00 00 00    	mov    r13d,0x3
  9acec7:	eb 5a                	jmp    0x9acf23
  9acec9:	44 8b 3d 70 31 bb 01 	mov    r15d,DWORD PTR [rip+0x1bb3170]        # 0x2560040
  9aced0:	41 83 ff ff          	cmp    r15d,0xffffffff
  9aced4:	75 40                	jne    0x9acf16
  9aced6:	e8 65 aa 15 00       	call   0xb07940
  9acedb:	41 bf 01 00 00 00    	mov    r15d,0x1
  9acee1:	85 c0                	test   eax,eax
  9acee3:	75 2a                	jne    0x9acf0f
  9acee5:	e8 76 aa 15 00       	call   0xb07960
  9aceea:	85 c0                	test   eax,eax
  9aceec:	75 21                	jne    0x9acf0f
  9aceee:	e8 2d aa 15 00       	call   0xb07920
  9acef3:	85 c0                	test   eax,eax
  9acef5:	74 15                	je     0x9acf0c
  9acef7:	bf 6e 00 00 00       	mov    edi,0x6e
  9acefc:	e8 9f fa 11 00       	call   0xacc9a0
  9acf01:	45 31 ff             	xor    r15d,r15d
  9acf04:	85 c0                	test   eax,eax
  9acf06:	41 0f 95 c7          	setne  r15b
  9acf0a:	eb 03                	jmp    0x9acf0f
  9acf0c:	45 31 ff             	xor    r15d,r15d
  9acf0f:	44 89 3d 2a 31 bb 01 	mov    DWORD PTR [rip+0x1bb312a],r15d        # 0x2560040
  9acf16:	45 31 ed             	xor    r13d,r13d
  9acf19:	41 83 ff 01          	cmp    r15d,0x1
  9acf1d:	b2 01                	mov    dl,0x1
  9acf1f:	41 83 d5 01          	adc    r13d,0x1
  9acf23:	49 8b 84 24 30 01 00 	mov    rax,QWORD PTR [r12+0x130]
  9acf2a:	00 
  9acf2b:	4d 89 f7             	mov    r15,r14
  9acf2e:	4c 89 65 b8          	mov    QWORD PTR [rbp-0x48],r12
  9acf32:	49 c1 ef 09          	shr    r15,0x9
  9acf36:	66 45 85 f6          	test   r14w,r14w
  9acf3a:	75 19                	jne    0x9acf55
  9acf3c:	49 8b 8c 24 28 01 00 	mov    rcx,QWORD PTR [r12+0x128]
  9acf43:	00 
  9acf44:	48 29 c1             	sub    rcx,rax
  9acf47:	48 81 f9 ff ff 00 00 	cmp    rcx,0xffff
  9acf4e:	76 05                	jbe    0x9acf55
  9acf50:	45 31 e4             	xor    r12d,r12d
  9acf53:	eb 35                	jmp    0x9acf8a
  9acf55:	48 85 c0             	test   rax,rax
  9acf58:	74 10                	je     0x9acf6a
  9acf5a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9acf5e:	4c 8b 60 68          	mov    r12,QWORD PTR [rax+0x68]
  9acf62:	4c 89 e3             	mov    rbx,r12
  9acf65:	4d 85 e4             	test   r12,r12
  9acf68:	75 20                	jne    0x9acf8a
  9acf6a:	89 d3                	mov    ebx,edx
  9acf6c:	48 8d 35 5d 30 bb 01 	lea    rsi,[rip+0x1bb305d]        # 0x255ffd0
  9acf73:	bf 00 00 01 00       	mov    edi,0x10000
  9acf78:	ba 02 01 00 00       	mov    edx,0x102
  9acf7d:	e8 ce bb 25 00       	call   0xc08b50
  9acf82:	89 da                	mov    edx,ebx
  9acf84:	49 89 c4             	mov    r12,rax
  9acf87:	48 89 c3             	mov    rbx,rax
  9acf8a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  9acf8e:	49 83 e7 80          	and    r15,0xffffffffffffff80
  9acf92:	b9 01 04 01 20       	mov    ecx,0x20010401
  9acf97:	41 be 00 05 01 80    	mov    r14d,0x80010500
  9acf9d:	4c 89 60 68          	mov    QWORD PTR [rax+0x68],r12
  9acfa1:	84 d2                	test   dl,dl
  9acfa3:	44 0f 45 f1          	cmovne r14d,ecx
  9acfa7:	75 0b                	jne    0x9acfb4
  9acfa9:	4c 89 ff             	mov    rdi,r15
  9acfac:	e8 8f 4f 03 00       	call   0x9e1f40
  9acfb1:	49 89 c7             	mov    r15,rax
  9acfb4:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
  9acfb8:	48 8b 4d a8          	mov    rcx,QWORD PTR [rbp-0x58]
  9acfbc:	48 be 00 00 00 00 00 	movabs rsi,0x400000000000
  9acfc3:	40 00 00 
  9acfc6:	44 89 ef             	mov    edi,r13d
  9acfc9:	48 89 da             	mov    rdx,rbx
  9acfcc:	45 89 f1             	mov    r9d,r14d
  9acfcf:	45 31 c0             	xor    r8d,r8d
  9acfd2:	4c 09 fe             	or     rsi,r15
  9acfd5:	48 89 04 24          	mov    QWORD PTR [rsp],rax
  9acfd9:	e8 22 cb cd ff       	call   0x689b00
  9acfde:	4d 85 e4             	test   r12,r12
  9acfe1:	74 23                	je     0x9ad006
  9acfe3:	85 c0                	test   eax,eax
  9acfe5:	74 1f                	je     0x9ad006
  9acfe7:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  9acfeb:	48 8d 35 de 2f bb 01 	lea    rsi,[rip+0x1bb2fde]        # 0x255ffd0
  9acff2:	4c 89 e7             	mov    rdi,r12
  9acff5:	89 c3                	mov    ebx,eax
  9acff7:	48 c7 41 68 00 00 00 	mov    QWORD PTR [rcx+0x68],0x0
  9acffe:	00 
  9acfff:	e8 ec bd 25 00       	call   0xc08df0
  9ad004:	89 d8                	mov    eax,ebx
  9ad006:	48 8d 0d 03 f3 f6 02 	lea    rcx,[rip+0x2f6f303]        # 0x391c310
  9ad00d:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  9ad010:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  9ad014:	75 0f                	jne    0x9ad025
  9ad016:	48 83 c4 38          	add    rsp,0x38
  9ad01a:	5b                   	pop    rbx
  9ad01b:	41 5c                	pop    r12
  9ad01d:	41 5d                	pop    r13
  9ad01f:	41 5e                	pop    r14
  9ad021:	41 5f                	pop    r15
  9ad023:	5d                   	pop    rbp
  9ad024:	c3                   	ret
  9ad025:	e8 86 06 d5 ff       	call   0x6fd6b0
  9ad02a:	0f 0b                	ud2
  9ad02c:	90                   	nop
  9ad02d:	90                   	nop
  9ad02e:	90                   	nop
  9ad02f:	90                   	nop
  9ad030:	55                   	push   rbp
  9ad031:	48 89 e5             	mov    rbp,rsp
  9ad034:	41 57                	push   r15
  9ad036:	41 56                	push   r14
  9ad038:	41 55                	push   r13
  9ad03a:	41 54                	push   r12
  9ad03c:	53                   	push   rbx
  9ad03d:	48 83 ec 28          	sub    rsp,0x28
  9ad041:	48 8d 05 c8 f2 f6 02 	lea    rax,[rip+0x2f6f2c8]        # 0x391c310
  9ad048:	48 89 fb             	mov    rbx,rdi
  9ad04b:	41 89 f5             	mov    r13d,esi
  9ad04e:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ad051:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ad055:	4c 8b 37             	mov    r14,QWORD PTR [rdi]
  9ad058:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  9ad05c:	bf c1 21 00 00       	mov    edi,0x21c1
  9ad061:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  9ad065:	41 0f b7 46 20       	movzx  eax,WORD PTR [r14+0x20]
  9ad06a:	4d 8b 66 68          	mov    r12,QWORD PTR [r14+0x68]
  9ad06e:	66 c7 45 ca 00 00    	mov    WORD PTR [rbp-0x36],0x0
  9ad074:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
  9ad07b:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  9ad07f:	41 8b 86 98 01 00 00 	mov    eax,DWORD PTR [r14+0x198]
  9ad086:	85 c0                	test   eax,eax
  9ad088:	0f 45 f8             	cmovne edi,eax
  9ad08b:	e8 e0 3e c4 ff       	call   0x5f0f70
  9ad090:	48 8d 75 ca          	lea    rsi,[rbp-0x36]
  9ad094:	48 8d 55 c4          	lea    rdx,[rbp-0x3c]
  9ad098:	44 89 ef             	mov    edi,r13d
  9ad09b:	31 c9                	xor    ecx,ecx
  9ad09d:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
  9ad0a0:	e8 fb 10 ce ff       	call   0x68e1a0
  9ad0a5:	85 c0                	test   eax,eax
  9ad0a7:	74 18                	je     0x9ad0c1
  9ad0a9:	41 89 c7             	mov    r15d,eax
  9ad0ac:	48 8d 3d 81 76 9d 00 	lea    rdi,[rip+0x9d7681]        # 0x1384734
  9ad0b3:	48 8d 35 a7 0c 94 00 	lea    rsi,[rip+0x940ca7]        # 0x12edd61
  9ad0ba:	89 c2                	mov    edx,eax
  9ad0bc:	44 89 e9             	mov    ecx,r13d
  9ad0bf:	eb 31                	jmp    0x9ad0f2
  9ad0c1:	4c 8b 6d b0          	mov    r13,QWORD PTR [rbp-0x50]
  9ad0c5:	48 8d 35 04 2f bb 01 	lea    rsi,[rip+0x1bb2f04]        # 0x255ffd0
  9ad0cc:	48 89 df             	mov    rdi,rbx
  9ad0cf:	e8 1c bd 25 00       	call   0xc08df0
  9ad0d4:	44 0f b7 7d ca       	movzx  r15d,WORD PTR [rbp-0x36]
  9ad0d9:	45 85 ff             	test   r15d,r15d
  9ad0dc:	74 5c                	je     0x9ad13a
  9ad0de:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
  9ad0e1:	48 8d 3d 0a a9 95 00 	lea    rdi,[rip+0x95a90a]        # 0x13079f2
  9ad0e8:	48 8d 35 62 2f a0 00 	lea    rsi,[rip+0xa02f62]        # 0x13b0051
  9ad0ef:	44 89 fa             	mov    edx,r15d
  9ad0f2:	31 c0                	xor    eax,eax
  9ad0f4:	e8 17 03 8b ff       	call   0x25d410
  9ad0f9:	49 8b 86 28 01 00 00 	mov    rax,QWORD PTR [r14+0x128]
  9ad100:	4c 89 f7             	mov    rdi,r14
  9ad103:	44 89 fe             	mov    esi,r15d
  9ad106:	49 89 46 50          	mov    QWORD PTR [r14+0x50],rax
  9ad10a:	e8 31 fc ff ff       	call   0x9acd40
  9ad10f:	8b 7d c0             	mov    edi,DWORD PTR [rbp-0x40]
  9ad112:	e8 59 3e c4 ff       	call   0x5f0f70
  9ad117:	48 8d 05 f2 f1 f6 02 	lea    rax,[rip+0x2f6f1f2]        # 0x391c310
  9ad11e:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ad121:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9ad125:	0f 85 e7 01 00 00    	jne    0x9ad312
  9ad12b:	48 83 c4 28          	add    rsp,0x28
  9ad12f:	5b                   	pop    rbx
  9ad130:	41 5c                	pop    r12
  9ad132:	41 5d                	pop    r13
  9ad134:	41 5e                	pop    r14
  9ad136:	41 5f                	pop    r15
  9ad138:	5d                   	pop    rbp
  9ad139:	c3                   	ret
  9ad13a:	4d 85 e4             	test   r12,r12
  9ad13d:	74 2f                	je     0x9ad16e
  9ad13f:	49 8b 96 28 01 00 00 	mov    rdx,QWORD PTR [r14+0x128]
  9ad146:	49 8b 76 30          	mov    rsi,QWORD PTR [r14+0x30]
  9ad14a:	41 bf 00 00 01 00    	mov    r15d,0x10000
  9ad150:	4d 01 ec             	add    r12,r13
  9ad153:	4d 29 ef             	sub    r15,r13
  9ad156:	4c 89 e7             	mov    rdi,r12
  9ad159:	4a 8d 04 2a          	lea    rax,[rdx+r13*1]
  9ad15d:	48 3d 01 00 01 00    	cmp    rax,0x10001
  9ad163:	49 0f 43 d7          	cmovae rdx,r15
  9ad167:	e8 74 ca 8a ff       	call   0x259be0
  9ad16c:	eb 09                	jmp    0x9ad177
  9ad16e:	41 bf 00 00 01 00    	mov    r15d,0x10000
  9ad174:	4d 29 ef             	sub    r15,r13
  9ad177:	49 8b 96 28 01 00 00 	mov    rdx,QWORD PTR [r14+0x128]
  9ad17e:	48 8b 5d b8          	mov    rbx,QWORD PTR [rbp-0x48]
  9ad182:	48 89 d0             	mov    rax,rdx
  9ad185:	4c 29 f8             	sub    rax,r15
  9ad188:	0f 86 9f 00 00 00    	jbe    0x9ad22d
  9ad18e:	4d 89 be 30 01 00 00 	mov    QWORD PTR [r14+0x130],r15
  9ad195:	49 89 46 50          	mov    QWORD PTR [r14+0x50],rax
  9ad199:	49 8b 46 20          	mov    rax,QWORD PTR [r14+0x20]
  9ad19d:	89 c1                	mov    ecx,eax
  9ad19f:	66 44 01 f9          	add    cx,r15w
  9ad1a3:	74 29                	je     0x9ad1ce
  9ad1a5:	48 89 c2             	mov    rdx,rax
  9ad1a8:	48 8d 3d 29 7a 9e 00 	lea    rdi,[rip+0x9e7a29]        # 0x1394bd8
  9ad1af:	48 8d 35 49 c6 90 00 	lea    rsi,[rip+0x90c649]        # 0x12b97ff
  9ad1b6:	4c 89 f9             	mov    rcx,r15
  9ad1b9:	31 c0                	xor    eax,eax
  9ad1bb:	e8 50 02 8b ff       	call   0x25d410
  9ad1c0:	49 8b 96 28 01 00 00 	mov    rdx,QWORD PTR [r14+0x128]
  9ad1c7:	4d 8b be 30 01 00 00 	mov    r15,QWORD PTR [r14+0x130]
  9ad1ce:	4c 39 fa             	cmp    rdx,r15
  9ad1d1:	7e 6b                	jle    0x9ad23e
  9ad1d3:	48 8d 35 f6 2d bb 01 	lea    rsi,[rip+0x1bb2df6]        # 0x255ffd0
  9ad1da:	bf 20 00 00 00       	mov    edi,0x20
  9ad1df:	ba 02 00 00 00       	mov    edx,0x2
  9ad1e4:	e8 67 b9 25 00       	call   0xc08b50
  9ad1e9:	49 89 c7             	mov    r15,rax
  9ad1ec:	4c 89 30             	mov    QWORD PTR [rax],r14
  9ad1ef:	48 85 db             	test   rbx,rbx
  9ad1f2:	74 76                	je     0x9ad26a
  9ad1f4:	4d 8b a6 30 01 00 00 	mov    r12,QWORD PTR [r14+0x130]
  9ad1fb:	4d 03 66 20          	add    r12,QWORD PTR [r14+0x20]
  9ad1ff:	4c 89 fb             	mov    rbx,r15
  9ad202:	48 83 c3 10          	add    rbx,0x10
  9ad206:	4c 89 e7             	mov    rdi,r12
  9ad209:	e8 52 9d a2 ff       	call   0x3d6f60
  9ad20e:	41 89 47 14          	mov    DWORD PTR [r15+0x14],eax
  9ad212:	83 f8 ff             	cmp    eax,0xffffffff
  9ad215:	74 10                	je     0x9ad227
  9ad217:	49 c1 ec 10          	shr    r12,0x10
  9ad21b:	4d 89 67 18          	mov    QWORD PTR [r15+0x18],r12
  9ad21f:	41 c7 47 10 0c 00 00 	mov    DWORD PTR [r15+0x10],0xc
  9ad226:	00 
  9ad227:	49 89 5f 08          	mov    QWORD PTR [r15+0x8],rbx
  9ad22b:	eb 4f                	jmp    0x9ad27c
  9ad22d:	49 89 96 30 01 00 00 	mov    QWORD PTR [r14+0x130],rdx
  9ad234:	31 c0                	xor    eax,eax
  9ad236:	45 31 ff             	xor    r15d,r15d
  9ad239:	e9 c2 fe ff ff       	jmp    0x9ad100
  9ad23e:	48 8d 3d c6 d5 9f 00 	lea    rdi,[rip+0x9fd5c6]        # 0x13aa80b
  9ad245:	48 8d 35 b3 c5 90 00 	lea    rsi,[rip+0x90c5b3]        # 0x12b97ff
  9ad24c:	4c 89 f9             	mov    rcx,r15
  9ad24f:	31 c0                	xor    eax,eax
  9ad251:	e8 ba 01 8b ff       	call   0x25d410
  9ad256:	49 8b 86 28 01 00 00 	mov    rax,QWORD PTR [r14+0x128]
  9ad25d:	4c 89 f7             	mov    rdi,r14
  9ad260:	be 16 00 00 00       	mov    esi,0x16
  9ad265:	e9 9c fe ff ff       	jmp    0x9ad106
  9ad26a:	49 c7 47 08 00 00 00 	mov    QWORD PTR [r15+0x8],0x0
  9ad271:	00 
  9ad272:	31 db                	xor    ebx,ebx
  9ad274:	41 c7 47 14 ff ff ff 	mov    DWORD PTR [r15+0x14],0xffffffff
  9ad27b:	ff 
  9ad27c:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
  9ad280:	4c 89 f7             	mov    rdi,r14
  9ad283:	48 89 de             	mov    rsi,rbx
  9ad286:	e8 55 fb ff ff       	call   0x9acde0
  9ad28b:	85 c0                	test   eax,eax
  9ad28d:	74 39                	je     0x9ad2c8
  9ad28f:	48 8d 3d 76 82 99 00 	lea    rdi,[rip+0x998276]        # 0x134550c
  9ad296:	48 8d 35 62 c5 90 00 	lea    rsi,[rip+0x90c562]        # 0x12b97ff
  9ad29d:	89 c2                	mov    edx,eax
  9ad29f:	89 c3                	mov    ebx,eax
  9ad2a1:	31 c0                	xor    eax,eax
  9ad2a3:	e8 68 01 8b ff       	call   0x25d410
  9ad2a8:	48 8d 35 21 2d bb 01 	lea    rsi,[rip+0x1bb2d21]        # 0x255ffd0
  9ad2af:	4c 89 ff             	mov    rdi,r15
  9ad2b2:	e8 39 bb 25 00       	call   0xc08df0
  9ad2b7:	49 8b 86 28 01 00 00 	mov    rax,QWORD PTR [r14+0x128]
  9ad2be:	4c 89 f7             	mov    rdi,r14
  9ad2c1:	89 de                	mov    esi,ebx
  9ad2c3:	e9 3e fe ff ff       	jmp    0x9ad106
  9ad2c8:	48 8d 3d b1 d2 8b ff 	lea    rdi,[rip+0xffffffffff8bd2b1]        # 0x26a580
  9ad2cf:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
  9ad2d3:	4c 89 fe             	mov    rsi,r15
  9ad2d6:	b9 01 00 00 00       	mov    ecx,0x1
  9ad2db:	e8 f0 2e c0 ff       	call   0x5b01d0
  9ad2e0:	85 c0                	test   eax,eax
  9ad2e2:	0f 84 27 fe ff ff    	je     0x9ad10f
  9ad2e8:	8b 4d cc             	mov    ecx,DWORD PTR [rbp-0x34]
  9ad2eb:	89 c2                	mov    edx,eax
  9ad2ed:	48 8d 3d e7 c2 92 00 	lea    rdi,[rip+0x92c2e7]        # 0x12d95db
  9ad2f4:	48 8d 35 04 c5 90 00 	lea    rsi,[rip+0x90c504]        # 0x12b97ff
  9ad2fb:	31 c0                	xor    eax,eax
  9ad2fd:	e8 0e 01 8b ff       	call   0x25d410
  9ad302:	8b 75 cc             	mov    esi,DWORD PTR [rbp-0x34]
  9ad305:	4c 89 ff             	mov    rdi,r15
  9ad308:	e8 83 01 00 00       	call   0x9ad490
  9ad30d:	e9 fd fd ff ff       	jmp    0x9ad10f
  9ad312:	e8 99 03 d5 ff       	call   0x6fd6b0
  9ad317:	0f 0b                	ud2
  9ad319:	90                   	nop
  9ad31a:	90                   	nop
  9ad31b:	90                   	nop
  9ad31c:	90                   	nop
  9ad31d:	90                   	nop
  9ad31e:	90                   	nop
  9ad31f:	90                   	nop
  9ad320:	55                   	push   rbp
  9ad321:	48 89 e5             	mov    rbp,rsp
  9ad324:	41 57                	push   r15
  9ad326:	41 56                	push   r14
  9ad328:	53                   	push   rbx
  9ad329:	50                   	push   rax
  9ad32a:	44 8b 3d 9f 2d bb 01 	mov    r15d,DWORD PTR [rip+0x1bb2d9f]        # 0x25600d0
  9ad331:	48 89 fb             	mov    rbx,rdi
  9ad334:	41 83 ff ff          	cmp    r15d,0xffffffff
  9ad338:	75 32                	jne    0x9ad36c
  9ad33a:	e8 01 a6 15 00       	call   0xb07940
  9ad33f:	41 bf 01 00 00 00    	mov    r15d,0x1
  9ad345:	85 c0                	test   eax,eax
  9ad347:	75 1c                	jne    0x9ad365
  9ad349:	e8 12 a6 15 00       	call   0xb07960
  9ad34e:	85 c0                	test   eax,eax
  9ad350:	75 13                	jne    0x9ad365
  9ad352:	bf 6d 00 00 00       	mov    edi,0x6d
  9ad357:	e8 44 f6 11 00       	call   0xacc9a0
  9ad35c:	45 31 ff             	xor    r15d,r15d
  9ad35f:	85 c0                	test   eax,eax
  9ad361:	41 0f 95 c7          	setne  r15b
  9ad365:	44 89 3d 64 2d bb 01 	mov    DWORD PTR [rip+0x1bb2d64],r15d        # 0x25600d0
  9ad36c:	45 31 f6             	xor    r14d,r14d
  9ad36f:	45 85 ff             	test   r15d,r15d
  9ad372:	0f 84 f2 00 00 00    	je     0x9ad46a
  9ad378:	44 8b 3d c1 2c bb 01 	mov    r15d,DWORD PTR [rip+0x1bb2cc1]        # 0x2560040
  9ad37f:	41 83 ff ff          	cmp    r15d,0xffffffff
  9ad383:	75 40                	jne    0x9ad3c5
  9ad385:	e8 b6 a5 15 00       	call   0xb07940
  9ad38a:	41 bf 01 00 00 00    	mov    r15d,0x1
  9ad390:	85 c0                	test   eax,eax
  9ad392:	75 2a                	jne    0x9ad3be
  9ad394:	e8 c7 a5 15 00       	call   0xb07960
  9ad399:	85 c0                	test   eax,eax
  9ad39b:	75 21                	jne    0x9ad3be
  9ad39d:	e8 7e a5 15 00       	call   0xb07920
  9ad3a2:	85 c0                	test   eax,eax
  9ad3a4:	74 15                	je     0x9ad3bb
  9ad3a6:	bf 6e 00 00 00       	mov    edi,0x6e
  9ad3ab:	e8 f0 f5 11 00       	call   0xacc9a0
  9ad3b0:	45 31 ff             	xor    r15d,r15d
  9ad3b3:	85 c0                	test   eax,eax
  9ad3b5:	41 0f 95 c7          	setne  r15b
  9ad3b9:	eb 03                	jmp    0x9ad3be
  9ad3bb:	45 31 ff             	xor    r15d,r15d
  9ad3be:	44 89 3d 7b 2c bb 01 	mov    DWORD PTR [rip+0x1bb2c7b],r15d        # 0x2560040
  9ad3c5:	45 85 ff             	test   r15d,r15d
  9ad3c8:	0f 84 9c 00 00 00    	je     0x9ad46a
  9ad3ce:	80 3d 4b 8b 1f 03 00 	cmp    BYTE PTR [rip+0x31f8b4b],0x0        # 0x3ba5f20
  9ad3d5:	74 41                	je     0x9ad418
  9ad3d7:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  9ad3db:	48 89 c1             	mov    rcx,rax
  9ad3de:	48 c1 e9 10          	shr    rcx,0x10
  9ad3e2:	48 3b 0d 3f 8b 1f 03 	cmp    rcx,QWORD PTR [rip+0x31f8b3f]        # 0x3ba5f28
  9ad3e9:	7c 7f                	jl     0x9ad46a
  9ad3eb:	48 8b 8b 28 01 00 00 	mov    rcx,QWORD PTR [rbx+0x128]
  9ad3f2:	48 8b 15 47 8b 1f 03 	mov    rdx,QWORD PTR [rip+0x31f8b47]        # 0x3ba5f40
  9ad3f9:	48 03 15 38 8b 1f 03 	add    rdx,QWORD PTR [rip+0x31f8b38]        # 0x3ba5f38
  9ad400:	45 31 f6             	xor    r14d,r14d
  9ad403:	48 8d 84 08 ff ff 00 	lea    rax,[rax+rcx*1+0xffff]
  9ad40a:	00 
  9ad40b:	48 c1 e8 10          	shr    rax,0x10
  9ad40f:	48 39 d0             	cmp    rax,rdx
  9ad412:	41 0f 9e c6          	setle  r14b
  9ad416:	eb 52                	jmp    0x9ad46a
  9ad418:	48 8d 35 09 8b 1f 03 	lea    rsi,[rip+0x31f8b09]        # 0x3ba5f28
  9ad41f:	48 8d 15 0a 8b 1f 03 	lea    rdx,[rip+0x31f8b0a]        # 0x3ba5f30
  9ad426:	bf 09 00 01 00       	mov    edi,0x10009
  9ad42b:	e8 c0 99 a2 ff       	call   0x3d6df0
  9ad430:	85 c0                	test   eax,eax
  9ad432:	75 1c                	jne    0x9ad450
  9ad434:	48 8d 35 fd 8a 1f 03 	lea    rsi,[rip+0x31f8afd]        # 0x3ba5f38
  9ad43b:	48 8d 15 fe 8a 1f 03 	lea    rdx,[rip+0x31f8afe]        # 0x3ba5f40
  9ad442:	bf 10 00 01 00       	mov    edi,0x10010
  9ad447:	e8 a4 99 a2 ff       	call   0x3d6df0
  9ad44c:	85 c0                	test   eax,eax
  9ad44e:	74 28                	je     0x9ad478
  9ad450:	89 c2                	mov    edx,eax
  9ad452:	48 8d 3d 02 f1 97 00 	lea    rdi,[rip+0x97f102]        # 0x132c55b
  9ad459:	48 8d 35 62 d3 9d 00 	lea    rsi,[rip+0x9dd362]        # 0x138a7c2
  9ad460:	31 c0                	xor    eax,eax
  9ad462:	45 31 f6             	xor    r14d,r14d
  9ad465:	e8 a6 ff 8a ff       	call   0x25d410
  9ad46a:	44 89 f0             	mov    eax,r14d
  9ad46d:	48 83 c4 08          	add    rsp,0x8
  9ad471:	5b                   	pop    rbx
  9ad472:	41 5e                	pop    r14
  9ad474:	41 5f                	pop    r15
  9ad476:	5d                   	pop    rbp
  9ad477:	c3                   	ret
  9ad478:	c6 05 a1 8a 1f 03 01 	mov    BYTE PTR [rip+0x31f8aa1],0x1        # 0x3ba5f20
  9ad47f:	e9 53 ff ff ff       	jmp    0x9ad3d7
  9ad484:	90                   	nop
  9ad485:	90                   	nop
  9ad486:	90                   	nop
  9ad487:	90                   	nop
  9ad488:	90                   	nop
  9ad489:	90                   	nop
  9ad48a:	90                   	nop
  9ad48b:	90                   	nop
  9ad48c:	90                   	nop
  9ad48d:	90                   	nop
  9ad48e:	90                   	nop
  9ad48f:	90                   	nop
  9ad490:	55                   	push   rbp
  9ad491:	48 89 e5             	mov    rbp,rsp
  9ad494:	41 57                	push   r15
  9ad496:	41 56                	push   r14
  9ad498:	41 55                	push   r13
  9ad49a:	41 54                	push   r12
  9ad49c:	53                   	push   rbx
  9ad49d:	48 83 ec 18          	sub    rsp,0x18
  9ad4a1:	48 8d 05 68 ee f6 02 	lea    rax,[rip+0x2f6ee68]        # 0x391c310
  9ad4a8:	49 89 fe             	mov    r14,rdi
  9ad4ab:	41 89 f5             	mov    r13d,esi
  9ad4ae:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ad4b1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ad4b5:	48 8b 1f             	mov    rbx,QWORD PTR [rdi]
  9ad4b8:	bf c1 21 00 00       	mov    edi,0x21c1
  9ad4bd:	4c 8b 63 68          	mov    r12,QWORD PTR [rbx+0x68]
  9ad4c1:	66 c7 45 ce 00 00    	mov    WORD PTR [rbp-0x32],0x0
  9ad4c7:	c7 45 c8 00 00 00 00 	mov    DWORD PTR [rbp-0x38],0x0
  9ad4ce:	8b 83 98 01 00 00    	mov    eax,DWORD PTR [rbx+0x198]
  9ad4d4:	85 c0                	test   eax,eax
  9ad4d6:	0f 45 f8             	cmovne edi,eax
  9ad4d9:	e8 92 3a c4 ff       	call   0x5f0f70
  9ad4de:	48 8d 75 ce          	lea    rsi,[rbp-0x32]
  9ad4e2:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  9ad4e6:	44 89 ef             	mov    edi,r13d
  9ad4e9:	31 c9                	xor    ecx,ecx
  9ad4eb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
  9ad4ee:	e8 ad 0c ce ff       	call   0x68e1a0
  9ad4f3:	85 c0                	test   eax,eax
  9ad4f5:	74 18                	je     0x9ad50f
  9ad4f7:	41 89 c7             	mov    r15d,eax
  9ad4fa:	48 8d 3d 33 72 9d 00 	lea    rdi,[rip+0x9d7233]        # 0x1384734
  9ad501:	48 8d 35 7e f0 97 00 	lea    rsi,[rip+0x97f07e]        # 0x132c586
  9ad508:	89 c2                	mov    edx,eax
  9ad50a:	44 89 e9             	mov    ecx,r13d
  9ad50d:	eb 31                	jmp    0x9ad540
  9ad50f:	48 8d 35 ba 2a bb 01 	lea    rsi,[rip+0x1bb2aba]        # 0x255ffd0
  9ad516:	4c 89 f7             	mov    rdi,r14
  9ad519:	e8 d2 b8 25 00       	call   0xc08df0
  9ad51e:	44 0f b7 7d ce       	movzx  r15d,WORD PTR [rbp-0x32]
  9ad523:	45 85 ff             	test   r15d,r15d
  9ad526:	0f 84 83 00 00 00    	je     0x9ad5af
  9ad52c:	8b 4d c8             	mov    ecx,DWORD PTR [rbp-0x38]
  9ad52f:	48 8d 3d bc a4 95 00 	lea    rdi,[rip+0x95a4bc]        # 0x13079f2
  9ad536:	48 8d 35 14 2b a0 00 	lea    rsi,[rip+0xa02b14]        # 0x13b0051
  9ad53d:	44 89 fa             	mov    edx,r15d
  9ad540:	31 c0                	xor    eax,eax
  9ad542:	e8 c9 fe 8a ff       	call   0x25d410
  9ad547:	4c 8b 83 28 01 00 00 	mov    r8,QWORD PTR [rbx+0x128]
  9ad54e:	4c 89 43 50          	mov    QWORD PTR [rbx+0x50],r8
  9ad552:	4d 85 c0             	test   r8,r8
  9ad555:	74 22                	je     0x9ad579
  9ad557:	48 8b 8b 30 01 00 00 	mov    rcx,QWORD PTR [rbx+0x130]
  9ad55e:	48 8d 3d 66 a6 94 00 	lea    rdi,[rip+0x94a666]        # 0x12f7bcb
  9ad565:	48 8d 35 1a f0 97 00 	lea    rsi,[rip+0x97f01a]        # 0x132c586
  9ad56c:	48 89 da             	mov    rdx,rbx
  9ad56f:	45 89 f9             	mov    r9d,r15d
  9ad572:	31 c0                	xor    eax,eax
  9ad574:	e8 97 fe 8a ff       	call   0x25d410
  9ad579:	48 89 df             	mov    rdi,rbx
  9ad57c:	44 89 fe             	mov    esi,r15d
  9ad57f:	e8 bc f7 ff ff       	call   0x9acd40
  9ad584:	8b 7d c4             	mov    edi,DWORD PTR [rbp-0x3c]
  9ad587:	e8 e4 39 c4 ff       	call   0x5f0f70
  9ad58c:	48 8d 05 7d ed f6 02 	lea    rax,[rip+0x2f6ed7d]        # 0x391c310
  9ad593:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ad596:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9ad59a:	0f 85 97 00 00 00    	jne    0x9ad637
  9ad5a0:	48 83 c4 18          	add    rsp,0x18
  9ad5a4:	5b                   	pop    rbx
  9ad5a5:	41 5c                	pop    r12
  9ad5a7:	41 5d                	pop    r13
  9ad5a9:	41 5e                	pop    r14
  9ad5ab:	41 5f                	pop    r15
  9ad5ad:	5d                   	pop    rbp
  9ad5ae:	c3                   	ret
  9ad5af:	4d 85 e4             	test   r12,r12
  9ad5b2:	74 2f                	je     0x9ad5e3
  9ad5b4:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9ad5bb:	48 8b 8b 30 01 00 00 	mov    rcx,QWORD PTR [rbx+0x130]
  9ad5c2:	48 8b 73 30          	mov    rsi,QWORD PTR [rbx+0x30]
  9ad5c6:	ba 00 00 01 00       	mov    edx,0x10000
  9ad5cb:	4c 89 e7             	mov    rdi,r12
  9ad5ce:	48 29 c8             	sub    rax,rcx
  9ad5d1:	48 01 ce             	add    rsi,rcx
  9ad5d4:	48 3d 00 00 01 00    	cmp    rax,0x10000
  9ad5da:	48 0f 42 d0          	cmovb  rdx,rax
  9ad5de:	e8 fd c5 8a ff       	call   0x259be0
  9ad5e3:	48 8b 8b 28 01 00 00 	mov    rcx,QWORD PTR [rbx+0x128]
  9ad5ea:	48 8b 83 30 01 00 00 	mov    rax,QWORD PTR [rbx+0x130]
  9ad5f1:	48 89 ca             	mov    rdx,rcx
  9ad5f4:	48 29 c2             	sub    rdx,rax
  9ad5f7:	48 81 fa 01 00 01 00 	cmp    rdx,0x10001
  9ad5fe:	72 20                	jb     0x9ad620
  9ad600:	48 05 00 00 01 00    	add    rax,0x10000
  9ad606:	49 c7 c0 00 00 ff ff 	mov    r8,0xffffffffffff0000
  9ad60d:	45 31 ff             	xor    r15d,r15d
  9ad610:	48 89 83 30 01 00 00 	mov    QWORD PTR [rbx+0x130],rax
  9ad617:	4c 03 43 50          	add    r8,QWORD PTR [rbx+0x50]
  9ad61b:	e9 2e ff ff ff       	jmp    0x9ad54e
  9ad620:	48 89 8b 30 01 00 00 	mov    QWORD PTR [rbx+0x130],rcx
  9ad627:	48 c7 43 50 00 00 00 	mov    QWORD PTR [rbx+0x50],0x0
  9ad62e:	00 
  9ad62f:	45 31 ff             	xor    r15d,r15d
  9ad632:	e9 42 ff ff ff       	jmp    0x9ad579
  9ad637:	e8 74 00 d5 ff       	call   0x6fd6b0
  9ad63c:	0f 0b                	ud2
  9ad63e:	90                   	nop
  9ad63f:	90                   	nop
  9ad640:	55                   	push   rbp
  9ad641:	48 89 e5             	mov    rbp,rsp
  9ad644:	41 57                	push   r15
  9ad646:	41 56                	push   r14
  9ad648:	41 55                	push   r13
  9ad64a:	41 54                	push   r12
  9ad64c:	53                   	push   rbx
  9ad64d:	48 83 ec 18          	sub    rsp,0x18
  9ad651:	4c 8d 2d b8 ec f6 02 	lea    r13,[rip+0x2f6ecb8]        # 0x391c310
  9ad658:	48 89 fb             	mov    rbx,rdi
  9ad65b:	41 89 f4             	mov    r12d,esi
  9ad65e:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  9ad662:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ad666:	8b 87 98 01 00 00    	mov    eax,DWORD PTR [rdi+0x198]
  9ad66c:	bf c1 21 00 00       	mov    edi,0x21c1
  9ad671:	85 c0                	test   eax,eax
  9ad673:	0f 45 f8             	cmovne edi,eax
  9ad676:	e8 f5 38 c4 ff       	call   0x5f0f70
  9ad67b:	48 8d 75 ce          	lea    rsi,[rbp-0x32]
  9ad67f:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  9ad683:	44 89 e7             	mov    edi,r12d
  9ad686:	31 c9                	xor    ecx,ecx
  9ad688:	41 89 c6             	mov    r14d,eax
  9ad68b:	66 c7 45 ce 00 00    	mov    WORD PTR [rbp-0x32],0x0
  9ad691:	c7 45 c8 00 00 00 00 	mov    DWORD PTR [rbp-0x38],0x0
  9ad698:	e8 03 0b ce ff       	call   0x68e1a0
  9ad69d:	85 c0                	test   eax,eax
  9ad69f:	74 35                	je     0x9ad6d6
  9ad6a1:	48 8d 3d 8c 70 9d 00 	lea    rdi,[rip+0x9d708c]        # 0x1384734
  9ad6a8:	48 8d 35 f7 ee 97 00 	lea    rsi,[rip+0x97eef7]        # 0x132c5a6
  9ad6af:	89 c2                	mov    edx,eax
  9ad6b1:	44 89 e1             	mov    ecx,r12d
  9ad6b4:	41 89 c7             	mov    r15d,eax
  9ad6b7:	31 c0                	xor    eax,eax
  9ad6b9:	e8 52 fd 8a ff       	call   0x25d410
  9ad6be:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9ad6c5:	48 89 df             	mov    rdi,rbx
  9ad6c8:	44 89 fe             	mov    esi,r15d
  9ad6cb:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9ad6cf:	e8 6c f6 ff ff       	call   0x9acd40
  9ad6d4:	eb 43                	jmp    0x9ad719
  9ad6d6:	44 0f b7 7d ce       	movzx  r15d,WORD PTR [rbp-0x32]
  9ad6db:	45 85 ff             	test   r15d,r15d
  9ad6de:	74 2f                	je     0x9ad70f
  9ad6e0:	8b 4d c8             	mov    ecx,DWORD PTR [rbp-0x38]
  9ad6e3:	48 8d 3d 08 a3 95 00 	lea    rdi,[rip+0x95a308]        # 0x13079f2
  9ad6ea:	48 8d 35 60 29 a0 00 	lea    rsi,[rip+0xa02960]        # 0x13b0051
  9ad6f1:	44 89 fa             	mov    edx,r15d
  9ad6f4:	31 c0                	xor    eax,eax
  9ad6f6:	e8 15 fd 8a ff       	call   0x25d410
  9ad6fb:	41 83 ff 05          	cmp    r15d,0x5
  9ad6ff:	75 bd                	jne    0x9ad6be
  9ad701:	48 8b 7b 68          	mov    rdi,QWORD PTR [rbx+0x68]
  9ad705:	be 00 00 01 00       	mov    esi,0x10000
  9ad70a:	e8 e1 b8 8a ff       	call   0x258ff0
  9ad70f:	48 89 df             	mov    rdi,rbx
  9ad712:	31 f6                	xor    esi,esi
  9ad714:	e8 37 00 00 00       	call   0x9ad750
  9ad719:	44 89 f7             	mov    edi,r14d
  9ad71c:	e8 4f 38 c4 ff       	call   0x5f0f70
  9ad721:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  9ad725:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9ad729:	75 0f                	jne    0x9ad73a
  9ad72b:	48 83 c4 18          	add    rsp,0x18
  9ad72f:	5b                   	pop    rbx
  9ad730:	41 5c                	pop    r12
  9ad732:	41 5d                	pop    r13
  9ad734:	41 5e                	pop    r14
  9ad736:	41 5f                	pop    r15
  9ad738:	5d                   	pop    rbp
  9ad739:	c3                   	ret
  9ad73a:	e8 71 ff d4 ff       	call   0x6fd6b0
  9ad73f:	0f 0b                	ud2
  9ad741:	90                   	nop
  9ad742:	90                   	nop
  9ad743:	90                   	nop
  9ad744:	90                   	nop
  9ad745:	90                   	nop
  9ad746:	90                   	nop
  9ad747:	90                   	nop
  9ad748:	90                   	nop
  9ad749:	90                   	nop
  9ad74a:	90                   	nop
  9ad74b:	90                   	nop
  9ad74c:	90                   	nop
  9ad74d:	90                   	nop
  9ad74e:	90                   	nop
  9ad74f:	90                   	nop
  9ad750:	55                   	push   rbp
  9ad751:	48 89 e5             	mov    rbp,rsp
  9ad754:	41 57                	push   r15
  9ad756:	41 56                	push   r14
  9ad758:	41 54                	push   r12
  9ad75a:	53                   	push   rbx
  9ad75b:	48 83 ec 10          	sub    rsp,0x10
  9ad75f:	4c 8d 25 aa eb f6 02 	lea    r12,[rip+0x2f6ebaa]        # 0x391c310
  9ad766:	48 89 fb             	mov    rbx,rdi
  9ad769:	49 89 f7             	mov    r15,rsi
  9ad76c:	ba 00 00 01 00       	mov    edx,0x10000
  9ad771:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  9ad775:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  9ad779:	0f b7 47 20          	movzx  eax,WORD PTR [rdi+0x20]
  9ad77d:	48 8b 8b 28 01 00 00 	mov    rcx,QWORD PTR [rbx+0x128]
  9ad784:	48 8b 77 68          	mov    rsi,QWORD PTR [rdi+0x68]
  9ad788:	48 8b 7f 30          	mov    rdi,QWORD PTR [rdi+0x30]
  9ad78c:	4c 8d 04 01          	lea    r8,[rcx+rax*1]
  9ad790:	48 01 c6             	add    rsi,rax
  9ad793:	48 29 c2             	sub    rdx,rax
  9ad796:	49 81 f8 01 00 01 00 	cmp    r8,0x10001
  9ad79d:	48 0f 42 d1          	cmovb  rdx,rcx
  9ad7a1:	e8 3a c4 8a ff       	call   0x259be0
  9ad7a6:	48 8d 35 23 28 bb 01 	lea    rsi,[rip+0x1bb2823]        # 0x255ffd0
  9ad7ad:	bf 20 00 00 00       	mov    edi,0x20
  9ad7b2:	ba 02 00 00 00       	mov    edx,0x2
  9ad7b7:	e8 94 b3 25 00       	call   0xc08b50
  9ad7bc:	49 89 c6             	mov    r14,rax
  9ad7bf:	48 89 18             	mov    QWORD PTR [rax],rbx
  9ad7c2:	4d 85 ff             	test   r15,r15
  9ad7c5:	74 1f                	je     0x9ad7e6
  9ad7c7:	41 83 7f 04 ff       	cmp    DWORD PTR [r15+0x4],0xffffffff
  9ad7cc:	74 18                	je     0x9ad7e6
  9ad7ce:	49 8b 07             	mov    rax,QWORD PTR [r15]
  9ad7d1:	49 8b 4f 08          	mov    rcx,QWORD PTR [r15+0x8]
  9ad7d5:	4c 89 f6             	mov    rsi,r14
  9ad7d8:	48 83 c6 10          	add    rsi,0x10
  9ad7dc:	49 89 4e 18          	mov    QWORD PTR [r14+0x18],rcx
  9ad7e0:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
  9ad7e4:	eb 02                	jmp    0x9ad7e8
  9ad7e6:	31 f6                	xor    esi,esi
  9ad7e8:	48 8d 55 d4          	lea    rdx,[rbp-0x2c]
  9ad7ec:	48 89 df             	mov    rdi,rbx
  9ad7ef:	49 89 76 08          	mov    QWORD PTR [r14+0x8],rsi
  9ad7f3:	e8 a8 00 00 00       	call   0x9ad8a0
  9ad7f8:	85 c0                	test   eax,eax
  9ad7fa:	74 41                	je     0x9ad83d
  9ad7fc:	48 8d 3d 7a af 91 00 	lea    rdi,[rip+0x91af7a]        # 0x12c877d
  9ad803:	48 8d 35 0d be 92 00 	lea    rsi,[rip+0x92be0d]        # 0x12d9617
  9ad80a:	89 c2                	mov    edx,eax
  9ad80c:	41 89 c7             	mov    r15d,eax
  9ad80f:	31 c0                	xor    eax,eax
  9ad811:	e8 fa fb 8a ff       	call   0x25d410
  9ad816:	48 8d 35 b3 27 bb 01 	lea    rsi,[rip+0x1bb27b3]        # 0x255ffd0
  9ad81d:	4c 89 f7             	mov    rdi,r14
  9ad820:	e8 cb b5 25 00       	call   0xc08df0
  9ad825:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9ad82c:	48 89 df             	mov    rdi,rbx
  9ad82f:	44 89 fe             	mov    esi,r15d
  9ad832:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9ad836:	e8 05 f5 ff ff       	call   0x9acd40
  9ad83b:	eb 41                	jmp    0x9ad87e
  9ad83d:	48 8d 3d 4c cd 8b ff 	lea    rdi,[rip+0xffffffffff8bcd4c]        # 0x26a590
  9ad844:	48 8d 55 d4          	lea    rdx,[rbp-0x2c]
  9ad848:	4c 89 f6             	mov    rsi,r14
  9ad84b:	b9 01 00 00 00       	mov    ecx,0x1
  9ad850:	e8 7b 29 c0 ff       	call   0x5b01d0
  9ad855:	85 c0                	test   eax,eax
  9ad857:	74 25                	je     0x9ad87e
  9ad859:	8b 4d d4             	mov    ecx,DWORD PTR [rbp-0x2c]
  9ad85c:	89 c2                	mov    edx,eax
  9ad85e:	48 8d 3d 76 bd 92 00 	lea    rdi,[rip+0x92bd76]        # 0x12d95db
  9ad865:	48 8d 35 ab bd 92 00 	lea    rsi,[rip+0x92bdab]        # 0x12d9617
  9ad86c:	31 c0                	xor    eax,eax
  9ad86e:	e8 9d fb 8a ff       	call   0x25d410
  9ad873:	8b 75 d4             	mov    esi,DWORD PTR [rbp-0x2c]
  9ad876:	4c 89 f7             	mov    rdi,r14
  9ad879:	e8 b2 01 00 00       	call   0x9ada30
  9ad87e:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  9ad882:	48 3b 45 d8          	cmp    rax,QWORD PTR [rbp-0x28]
  9ad886:	75 0d                	jne    0x9ad895
  9ad888:	48 83 c4 10          	add    rsp,0x10
  9ad88c:	5b                   	pop    rbx
  9ad88d:	41 5c                	pop    r12
  9ad88f:	41 5e                	pop    r14
  9ad891:	41 5f                	pop    r15
  9ad893:	5d                   	pop    rbp
  9ad894:	c3                   	ret
  9ad895:	e8 16 fe d4 ff       	call   0x6fd6b0
  9ad89a:	0f 0b                	ud2
  9ad89c:	90                   	nop
  9ad89d:	90                   	nop
  9ad89e:	90                   	nop
  9ad89f:	90                   	nop
  9ad8a0:	55                   	push   rbp
  9ad8a1:	48 89 e5             	mov    rbp,rsp
  9ad8a4:	41 57                	push   r15
  9ad8a6:	41 56                	push   r14
  9ad8a8:	41 55                	push   r13
  9ad8aa:	41 54                	push   r12
  9ad8ac:	53                   	push   rbx
  9ad8ad:	48 83 ec 28          	sub    rsp,0x28
  9ad8b1:	48 8d 05 58 ea f6 02 	lea    rax,[rip+0x2f6ea58]        # 0x391c310
  9ad8b8:	48 89 75 b8          	mov    QWORD PTR [rbp-0x48],rsi
  9ad8bc:	49 89 d6             	mov    r14,rdx
  9ad8bf:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ad8c2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ad8c6:	4c 8b a7 30 01 00 00 	mov    r12,QWORD PTR [rdi+0x130]
  9ad8cd:	4c 03 67 20          	add    r12,QWORD PTR [rdi+0x20]
  9ad8d1:	4c 8b 7f 68          	mov    r15,QWORD PTR [rdi+0x68]
  9ad8d5:	4d 85 ff             	test   r15,r15
  9ad8d8:	75 04                	jne    0x9ad8de
  9ad8da:	4c 8b 7f 30          	mov    r15,QWORD PTR [rdi+0x30]
  9ad8de:	8b 1d 5c 27 bb 01    	mov    ebx,DWORD PTR [rip+0x1bb275c]        # 0x2560040
  9ad8e4:	4d 89 e5             	mov    r13,r12
  9ad8e7:	49 c1 ed 09          	shr    r13,0x9
  9ad8eb:	83 fb ff             	cmp    ebx,0xffffffff
  9ad8ee:	75 3b                	jne    0x9ad92b
  9ad8f0:	e8 4b a0 15 00       	call   0xb07940
  9ad8f5:	bb 01 00 00 00       	mov    ebx,0x1
  9ad8fa:	85 c0                	test   eax,eax
  9ad8fc:	75 27                	jne    0x9ad925
  9ad8fe:	e8 5d a0 15 00       	call   0xb07960
  9ad903:	85 c0                	test   eax,eax
  9ad905:	75 1e                	jne    0x9ad925
  9ad907:	e8 14 a0 15 00       	call   0xb07920
  9ad90c:	85 c0                	test   eax,eax
  9ad90e:	74 13                	je     0x9ad923
  9ad910:	bf 6e 00 00 00       	mov    edi,0x6e
  9ad915:	e8 86 f0 11 00       	call   0xacc9a0
  9ad91a:	31 db                	xor    ebx,ebx
  9ad91c:	85 c0                	test   eax,eax
  9ad91e:	0f 95 c3             	setne  bl
  9ad921:	eb 02                	jmp    0x9ad925
  9ad923:	31 db                	xor    ebx,ebx
  9ad925:	89 1d 15 27 bb 01    	mov    DWORD PTR [rip+0x1bb2715],ebx        # 0x2560040
  9ad92b:	49 83 e5 80          	and    r13,0xffffffffffffff80
  9ad92f:	85 db                	test   ebx,ebx
  9ad931:	74 5f                	je     0x9ad992
  9ad933:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  9ad937:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
  9ad93b:	bf 03 00 01 00       	mov    edi,0x10003
  9ad940:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  9ad947:	00 
  9ad948:	e8 a3 94 a2 ff       	call   0x3d6df0
  9ad94d:	85 c0                	test   eax,eax
  9ad94f:	74 19                	je     0x9ad96a
  9ad951:	89 c2                	mov    edx,eax
  9ad953:	48 8d 3d 05 ed 8c 00 	lea    rdi,[rip+0x8ced05]        # 0x127c65f
  9ad95a:	48 8d 35 f6 1b 90 00 	lea    rsi,[rip+0x901bf6]        # 0x12af557
  9ad961:	31 c0                	xor    eax,eax
  9ad963:	e8 a8 fa 8a ff       	call   0x25d410
  9ad968:	eb 28                	jmp    0x9ad992
  9ad96a:	49 c1 ec 10          	shr    r12,0x10
  9ad96e:	4c 2b 65 c8          	sub    r12,QWORD PTR [rbp-0x38]
  9ad972:	7c 1e                	jl     0x9ad992
  9ad974:	4c 3b 65 c0          	cmp    r12,QWORD PTR [rbp-0x40]
  9ad978:	7d 18                	jge    0x9ad992
  9ad97a:	4c 89 ef             	mov    rdi,r13
  9ad97d:	e8 be 45 03 00       	call   0x9e1f40
  9ad982:	49 89 c5             	mov    r13,rax
  9ad985:	41 b9 00 05 01 80    	mov    r9d,0x80010500
  9ad98b:	bf 03 00 00 00       	mov    edi,0x3
  9ad990:	eb 54                	jmp    0x9ad9e6
  9ad992:	8b 1d a8 26 bb 01    	mov    ebx,DWORD PTR [rip+0x1bb26a8]        # 0x2560040
  9ad998:	83 fb ff             	cmp    ebx,0xffffffff
  9ad99b:	75 3b                	jne    0x9ad9d8
  9ad99d:	e8 9e 9f 15 00       	call   0xb07940
  9ad9a2:	bb 01 00 00 00       	mov    ebx,0x1
  9ad9a7:	85 c0                	test   eax,eax
  9ad9a9:	75 27                	jne    0x9ad9d2
  9ad9ab:	e8 b0 9f 15 00       	call   0xb07960
  9ad9b0:	85 c0                	test   eax,eax
  9ad9b2:	75 1e                	jne    0x9ad9d2
  9ad9b4:	e8 67 9f 15 00       	call   0xb07920
  9ad9b9:	85 c0                	test   eax,eax
  9ad9bb:	74 13                	je     0x9ad9d0
  9ad9bd:	bf 6e 00 00 00       	mov    edi,0x6e
  9ad9c2:	e8 d9 ef 11 00       	call   0xacc9a0
  9ad9c7:	31 db                	xor    ebx,ebx
  9ad9c9:	85 c0                	test   eax,eax
  9ad9cb:	0f 95 c3             	setne  bl
  9ad9ce:	eb 02                	jmp    0x9ad9d2
  9ad9d0:	31 db                	xor    ebx,ebx
  9ad9d2:	89 1d 68 26 bb 01    	mov    DWORD PTR [rip+0x1bb2668],ebx        # 0x2560040
  9ad9d8:	31 ff                	xor    edi,edi
  9ad9da:	83 fb 01             	cmp    ebx,0x1
  9ad9dd:	41 b9 01 00 01 20    	mov    r9d,0x20010001
  9ad9e3:	83 d7 01             	adc    edi,0x1
  9ad9e6:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  9ad9ea:	48 be 00 00 00 00 00 	movabs rsi,0x400000000000
  9ad9f1:	40 00 00 
  9ad9f4:	4c 89 fa             	mov    rdx,r15
  9ad9f7:	4c 89 34 24          	mov    QWORD PTR [rsp],r14
  9ad9fb:	45 31 c0             	xor    r8d,r8d
  9ad9fe:	4c 09 ee             	or     rsi,r13
  9ada01:	e8 8a c6 cd ff       	call   0x68a090
  9ada06:	48 8d 0d 03 e9 f6 02 	lea    rcx,[rip+0x2f6e903]        # 0x391c310
  9ada0d:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  9ada10:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  9ada14:	75 0f                	jne    0x9ada25
  9ada16:	48 83 c4 28          	add    rsp,0x28
  9ada1a:	5b                   	pop    rbx
  9ada1b:	41 5c                	pop    r12
  9ada1d:	41 5d                	pop    r13
  9ada1f:	41 5e                	pop    r14
  9ada21:	41 5f                	pop    r15
  9ada23:	5d                   	pop    rbp
  9ada24:	c3                   	ret
  9ada25:	e8 86 fc d4 ff       	call   0x6fd6b0
  9ada2a:	0f 0b                	ud2
  9ada2c:	90                   	nop
  9ada2d:	90                   	nop
  9ada2e:	90                   	nop
  9ada2f:	90                   	nop
  9ada30:	55                   	push   rbp
  9ada31:	48 89 e5             	mov    rbp,rsp
  9ada34:	41 57                	push   r15
  9ada36:	41 56                	push   r14
  9ada38:	41 55                	push   r13
  9ada3a:	41 54                	push   r12
  9ada3c:	53                   	push   rbx
  9ada3d:	48 83 ec 28          	sub    rsp,0x28
  9ada41:	48 8d 05 c8 e8 f6 02 	lea    rax,[rip+0x2f6e8c8]        # 0x391c310
  9ada48:	49 89 ff             	mov    r15,rdi
  9ada4b:	41 89 f5             	mov    r13d,esi
  9ada4e:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9ada51:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9ada55:	48 8b 1f             	mov    rbx,QWORD PTR [rdi]
  9ada58:	48 83 7f 08 00       	cmp    QWORD PTR [rdi+0x8],0x0
  9ada5d:	bf c1 21 00 00       	mov    edi,0x21c1
  9ada62:	0f b7 43 20          	movzx  eax,WORD PTR [rbx+0x20]
  9ada66:	66 c7 45 ce 00 00    	mov    WORD PTR [rbp-0x32],0x0
  9ada6c:	c7 45 c8 00 00 00 00 	mov    DWORD PTR [rbp-0x38],0x0
  9ada73:	41 0f 95 c6          	setne  r14b
  9ada77:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  9ada7b:	8b 83 98 01 00 00    	mov    eax,DWORD PTR [rbx+0x198]
  9ada81:	85 c0                	test   eax,eax
  9ada83:	0f 45 f8             	cmovne edi,eax
  9ada86:	e8 e5 34 c4 ff       	call   0x5f0f70
  9ada8b:	48 8d 75 ce          	lea    rsi,[rbp-0x32]
  9ada8f:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  9ada93:	44 89 ef             	mov    edi,r13d
  9ada96:	31 c9                	xor    ecx,ecx
  9ada98:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
  9ada9b:	e8 00 07 ce ff       	call   0x68e1a0
  9adaa0:	85 c0                	test   eax,eax
  9adaa2:	74 18                	je     0x9adabc
  9adaa4:	41 89 c4             	mov    r12d,eax
  9adaa7:	48 8d 3d 86 6c 9d 00 	lea    rdi,[rip+0x9d6c86]        # 0x1384734
  9adaae:	48 8d 35 fd 83 9c 00 	lea    rsi,[rip+0x9c83fd]        # 0x1375eb2
  9adab5:	89 c2                	mov    edx,eax
  9adab7:	44 89 e9             	mov    ecx,r13d
  9adaba:	eb 31                	jmp    0x9adaed
  9adabc:	4c 8b 6d b8          	mov    r13,QWORD PTR [rbp-0x48]
  9adac0:	48 8d 35 09 25 bb 01 	lea    rsi,[rip+0x1bb2509]        # 0x255ffd0
  9adac7:	4c 89 ff             	mov    rdi,r15
  9adaca:	e8 21 b3 25 00       	call   0xc08df0
  9adacf:	44 0f b7 65 ce       	movzx  r12d,WORD PTR [rbp-0x32]
  9adad4:	45 85 e4             	test   r12d,r12d
  9adad7:	74 58                	je     0x9adb31
  9adad9:	8b 4d c8             	mov    ecx,DWORD PTR [rbp-0x38]
  9adadc:	48 8d 3d 0f 9f 95 00 	lea    rdi,[rip+0x959f0f]        # 0x13079f2
  9adae3:	48 8d 35 67 25 a0 00 	lea    rsi,[rip+0xa02567]        # 0x13b0051
  9adaea:	44 89 e2             	mov    edx,r12d
  9adaed:	31 c0                	xor    eax,eax
  9adaef:	e8 1c f9 8a ff       	call   0x25d410
  9adaf4:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9adafb:	48 89 df             	mov    rdi,rbx
  9adafe:	44 89 e6             	mov    esi,r12d
  9adb01:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9adb05:	e8 36 f2 ff ff       	call   0x9acd40
  9adb0a:	8b 7d c4             	mov    edi,DWORD PTR [rbp-0x3c]
  9adb0d:	e8 5e 34 c4 ff       	call   0x5f0f70
  9adb12:	48 8d 05 f7 e7 f6 02 	lea    rax,[rip+0x2f6e7f7]        # 0x391c310
  9adb19:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9adb1c:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9adb20:	75 5a                	jne    0x9adb7c
  9adb22:	48 83 c4 28          	add    rsp,0x28
  9adb26:	5b                   	pop    rbx
  9adb27:	41 5c                	pop    r12
  9adb29:	41 5d                	pop    r13
  9adb2b:	41 5e                	pop    r14
  9adb2d:	41 5f                	pop    r15
  9adb2f:	5d                   	pop    rbp
  9adb30:	c3                   	ret
  9adb31:	48 8b 93 28 01 00 00 	mov    rdx,QWORD PTR [rbx+0x128]
  9adb38:	b8 00 00 01 00       	mov    eax,0x10000
  9adb3d:	4c 29 e8             	sub    rax,r13
  9adb40:	48 89 d1             	mov    rcx,rdx
  9adb43:	48 29 c1             	sub    rcx,rax
  9adb46:	76 1f                	jbe    0x9adb67
  9adb48:	31 f6                	xor    esi,esi
  9adb4a:	44 88 f6             	mov    sil,r14b
  9adb4d:	48 89 df             	mov    rdi,rbx
  9adb50:	48 89 83 30 01 00 00 	mov    QWORD PTR [rbx+0x130],rax
  9adb57:	48 89 4b 50          	mov    QWORD PTR [rbx+0x50],rcx
  9adb5b:	66 85 c9             	test   cx,cx
  9adb5e:	74 15                	je     0x9adb75
  9adb60:	e8 2b 00 00 00       	call   0x9adb90
  9adb65:	eb a3                	jmp    0x9adb0a
  9adb67:	48 89 93 30 01 00 00 	mov    QWORD PTR [rbx+0x130],rdx
  9adb6e:	31 c0                	xor    eax,eax
  9adb70:	45 31 e4             	xor    r12d,r12d
  9adb73:	eb 86                	jmp    0x9adafb
  9adb75:	e8 16 02 00 00       	call   0x9add90
  9adb7a:	eb 8e                	jmp    0x9adb0a
  9adb7c:	e8 2f fb d4 ff       	call   0x6fd6b0
  9adb81:	0f 0b                	ud2
  9adb83:	90                   	nop
  9adb84:	90                   	nop
  9adb85:	90                   	nop
  9adb86:	90                   	nop
  9adb87:	90                   	nop
  9adb88:	90                   	nop
  9adb89:	90                   	nop
  9adb8a:	90                   	nop
  9adb8b:	90                   	nop
  9adb8c:	90                   	nop
  9adb8d:	90                   	nop
  9adb8e:	90                   	nop
  9adb8f:	90                   	nop
  9adb90:	55                   	push   rbp
  9adb91:	48 89 e5             	mov    rbp,rsp
  9adb94:	41 57                	push   r15
  9adb96:	41 56                	push   r14
  9adb98:	41 55                	push   r13
  9adb9a:	41 54                	push   r12
  9adb9c:	53                   	push   rbx
  9adb9d:	48 83 ec 18          	sub    rsp,0x18
  9adba1:	4c 8d 2d 68 e7 f6 02 	lea    r13,[rip+0x2f6e768]        # 0x391c310
  9adba8:	41 89 f7             	mov    r15d,esi
  9adbab:	48 89 fb             	mov    rbx,rdi
  9adbae:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  9adbb2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9adbb6:	48 8b 57 20          	mov    rdx,QWORD PTR [rdi+0x20]
  9adbba:	48 8b 8f 30 01 00 00 	mov    rcx,QWORD PTR [rdi+0x130]
  9adbc1:	48 85 c9             	test   rcx,rcx
  9adbc4:	74 0b                	je     0x9adbd1
  9adbc6:	8d 04 11             	lea    eax,[rcx+rdx*1]
  9adbc9:	0f b7 c0             	movzx  eax,ax
  9adbcc:	48 85 c0             	test   rax,rax
  9adbcf:	74 1c                	je     0x9adbed
  9adbd1:	48 8d 3d 00 70 9e 00 	lea    rdi,[rip+0x9e7000]        # 0x1394bd8
  9adbd8:	48 8d 35 2f 70 9e 00 	lea    rsi,[rip+0x9e702f]        # 0x1394c0e
  9adbdf:	31 c0                	xor    eax,eax
  9adbe1:	e8 2a f8 8a ff       	call   0x25d410
  9adbe6:	48 8b 8b 30 01 00 00 	mov    rcx,QWORD PTR [rbx+0x130]
  9adbed:	48 8b 93 28 01 00 00 	mov    rdx,QWORD PTR [rbx+0x128]
  9adbf4:	48 39 ca             	cmp    rdx,rcx
  9adbf7:	7e 78                	jle    0x9adc71
  9adbf9:	66 39 ca             	cmp    dx,cx
  9adbfc:	75 15                	jne    0x9adc13
  9adbfe:	48 8d 3d 06 cc 9f 00 	lea    rdi,[rip+0x9fcc06]        # 0x13aa80b
  9adc05:	48 8d 35 02 70 9e 00 	lea    rsi,[rip+0x9e7002]        # 0x1394c0e
  9adc0c:	31 c0                	xor    eax,eax
  9adc0e:	e8 fd f7 8a ff       	call   0x25d410
  9adc13:	48 8d 35 b6 23 bb 01 	lea    rsi,[rip+0x1bb23b6]        # 0x255ffd0
  9adc1a:	bf 20 00 00 00       	mov    edi,0x20
  9adc1f:	ba 02 00 00 00       	mov    edx,0x2
  9adc24:	e8 27 af 25 00       	call   0xc08b50
  9adc29:	49 89 c6             	mov    r14,rax
  9adc2c:	48 89 18             	mov    QWORD PTR [rax],rbx
  9adc2f:	45 85 ff             	test   r15d,r15d
  9adc32:	0f 84 82 00 00 00    	je     0x9adcba
  9adc38:	4c 8b a3 30 01 00 00 	mov    r12,QWORD PTR [rbx+0x130]
  9adc3f:	4c 03 63 20          	add    r12,QWORD PTR [rbx+0x20]
  9adc43:	4d 89 f7             	mov    r15,r14
  9adc46:	49 83 c7 10          	add    r15,0x10
  9adc4a:	4c 89 e7             	mov    rdi,r12
  9adc4d:	e8 0e 93 a2 ff       	call   0x3d6f60
  9adc52:	41 89 46 14          	mov    DWORD PTR [r14+0x14],eax
  9adc56:	83 f8 ff             	cmp    eax,0xffffffff
  9adc59:	74 10                	je     0x9adc6b
  9adc5b:	49 c1 ec 10          	shr    r12,0x10
  9adc5f:	4d 89 66 18          	mov    QWORD PTR [r14+0x18],r12
  9adc63:	41 c7 46 10 0c 00 00 	mov    DWORD PTR [r14+0x10],0xc
  9adc6a:	00 
  9adc6b:	4d 89 7e 08          	mov    QWORD PTR [r14+0x8],r15
  9adc6f:	eb 5c                	jmp    0x9adccd
  9adc71:	48 8d 3d 93 cb 9f 00 	lea    rdi,[rip+0x9fcb93]        # 0x13aa80b
  9adc78:	48 8d 35 8f 6f 9e 00 	lea    rsi,[rip+0x9e6f8f]        # 0x1394c0e
  9adc7f:	31 c0                	xor    eax,eax
  9adc81:	e8 8a f7 8a ff       	call   0x25d410
  9adc86:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9adc8d:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9adc91:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  9adc95:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9adc99:	0f 85 dc 00 00 00    	jne    0x9add7b
  9adc9f:	48 89 df             	mov    rdi,rbx
  9adca2:	be 16 00 00 00       	mov    esi,0x16
  9adca7:	48 83 c4 18          	add    rsp,0x18
  9adcab:	5b                   	pop    rbx
  9adcac:	41 5c                	pop    r12
  9adcae:	41 5d                	pop    r13
  9adcb0:	41 5e                	pop    r14
  9adcb2:	41 5f                	pop    r15
  9adcb4:	5d                   	pop    rbp
  9adcb5:	e9 86 f0 ff ff       	jmp    0x9acd40
  9adcba:	49 c7 46 08 00 00 00 	mov    QWORD PTR [r14+0x8],0x0
  9adcc1:	00 
  9adcc2:	45 31 ff             	xor    r15d,r15d
  9adcc5:	41 c7 46 14 ff ff ff 	mov    DWORD PTR [r14+0x14],0xffffffff
  9adccc:	ff 
  9adccd:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
  9adcd1:	48 89 df             	mov    rdi,rbx
  9adcd4:	4c 89 fe             	mov    rsi,r15
  9adcd7:	e8 04 f1 ff ff       	call   0x9acde0
  9adcdc:	85 c0                	test   eax,eax
  9adcde:	74 41                	je     0x9add21
  9adce0:	48 8d 3d 25 78 99 00 	lea    rdi,[rip+0x997825]        # 0x134550c
  9adce7:	48 8d 35 20 6f 9e 00 	lea    rsi,[rip+0x9e6f20]        # 0x1394c0e
  9adcee:	89 c2                	mov    edx,eax
  9adcf0:	41 89 c7             	mov    r15d,eax
  9adcf3:	31 c0                	xor    eax,eax
  9adcf5:	e8 16 f7 8a ff       	call   0x25d410
  9adcfa:	48 8d 35 cf 22 bb 01 	lea    rsi,[rip+0x1bb22cf]        # 0x255ffd0
  9add01:	4c 89 f7             	mov    rdi,r14
  9add04:	e8 e7 b0 25 00       	call   0xc08df0
  9add09:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9add10:	48 89 df             	mov    rdi,rbx
  9add13:	44 89 fe             	mov    esi,r15d
  9add16:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9add1a:	e8 21 f0 ff ff       	call   0x9acd40
  9add1f:	eb 41                	jmp    0x9add62
  9add21:	48 8d 3d 70 c8 8b ff 	lea    rdi,[rip+0xffffffffff8bc870]        # 0x26a598
  9add28:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
  9add2c:	4c 89 f6             	mov    rsi,r14
  9add2f:	b9 01 00 00 00       	mov    ecx,0x1
  9add34:	e8 97 24 c0 ff       	call   0x5b01d0
  9add39:	85 c0                	test   eax,eax
  9add3b:	74 25                	je     0x9add62
  9add3d:	8b 4d cc             	mov    ecx,DWORD PTR [rbp-0x34]
  9add40:	89 c2                	mov    edx,eax
  9add42:	48 8d 3d 92 b8 92 00 	lea    rdi,[rip+0x92b892]        # 0x12d95db
  9add49:	48 8d 35 be 6e 9e 00 	lea    rsi,[rip+0x9e6ebe]        # 0x1394c0e
  9add50:	31 c0                	xor    eax,eax
  9add52:	e8 b9 f6 8a ff       	call   0x25d410
  9add57:	8b 75 cc             	mov    esi,DWORD PTR [rbp-0x34]
  9add5a:	4c 89 f7             	mov    rdi,r14
  9add5d:	e8 4e 01 00 00       	call   0x9adeb0
  9add62:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  9add66:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  9add6a:	75 0f                	jne    0x9add7b
  9add6c:	48 83 c4 18          	add    rsp,0x18
  9add70:	5b                   	pop    rbx
  9add71:	41 5c                	pop    r12
  9add73:	41 5d                	pop    r13
  9add75:	41 5e                	pop    r14
  9add77:	41 5f                	pop    r15
  9add79:	5d                   	pop    rbp
  9add7a:	c3                   	ret
  9add7b:	e8 30 f9 d4 ff       	call   0x6fd6b0
  9add80:	0f 0b                	ud2
  9add82:	90                   	nop
  9add83:	90                   	nop
  9add84:	90                   	nop
  9add85:	90                   	nop
  9add86:	90                   	nop
  9add87:	90                   	nop
  9add88:	90                   	nop
  9add89:	90                   	nop
  9add8a:	90                   	nop
  9add8b:	90                   	nop
  9add8c:	90                   	nop
  9add8d:	90                   	nop
  9add8e:	90                   	nop
  9add8f:	90                   	nop
  9add90:	55                   	push   rbp
  9add91:	48 89 e5             	mov    rbp,rsp
  9add94:	41 57                	push   r15
  9add96:	41 56                	push   r14
  9add98:	41 54                	push   r12
  9add9a:	53                   	push   rbx
  9add9b:	48 8b 57 20          	mov    rdx,QWORD PTR [rdi+0x20]
  9add9f:	48 8b 8f 30 01 00 00 	mov    rcx,QWORD PTR [rdi+0x130]
  9adda6:	41 89 f6             	mov    r14d,esi
  9adda9:	48 89 fb             	mov    rbx,rdi
  9addac:	48 85 c9             	test   rcx,rcx
  9addaf:	74 0b                	je     0x9addbc
  9addb1:	8d 04 11             	lea    eax,[rcx+rdx*1]
  9addb4:	0f b7 c0             	movzx  eax,ax
  9addb7:	48 85 c0             	test   rax,rax
  9addba:	74 1c                	je     0x9addd8
  9addbc:	48 8d 3d 15 6e 9e 00 	lea    rdi,[rip+0x9e6e15]        # 0x1394bd8
  9addc3:	48 8d 35 f3 35 9b 00 	lea    rsi,[rip+0x9b35f3]        # 0x13613bd
  9addca:	31 c0                	xor    eax,eax
  9addcc:	e8 3f f6 8a ff       	call   0x25d410
  9addd1:	48 8b 8b 30 01 00 00 	mov    rcx,QWORD PTR [rbx+0x130]
  9addd8:	48 8b 93 28 01 00 00 	mov    rdx,QWORD PTR [rbx+0x128]
  9adddf:	48 39 ca             	cmp    rdx,rcx
  9adde2:	7e 74                	jle    0x9ade58
  9adde4:	66 39 ca             	cmp    dx,cx
  9adde7:	74 15                	je     0x9addfe
  9adde9:	48 8d 3d 1b ca 9f 00 	lea    rdi,[rip+0x9fca1b]        # 0x13aa80b
  9addf0:	48 8d 35 c6 35 9b 00 	lea    rsi,[rip+0x9b35c6]        # 0x13613bd
  9addf7:	31 c0                	xor    eax,eax
  9addf9:	e8 12 f6 8a ff       	call   0x25d410
  9addfe:	48 8d 35 cb 21 bb 01 	lea    rsi,[rip+0x1bb21cb]        # 0x255ffd0
  9ade05:	bf 20 00 00 00       	mov    edi,0x20
  9ade0a:	ba 02 00 00 00       	mov    edx,0x2
  9ade0f:	e8 3c ad 25 00       	call   0xc08b50
  9ade14:	49 89 c7             	mov    r15,rax
  9ade17:	48 89 18             	mov    QWORD PTR [rax],rbx
  9ade1a:	45 85 f6             	test   r14d,r14d
  9ade1d:	74 6e                	je     0x9ade8d
  9ade1f:	4c 8b b3 30 01 00 00 	mov    r14,QWORD PTR [rbx+0x130]
  9ade26:	4c 03 73 20          	add    r14,QWORD PTR [rbx+0x20]
  9ade2a:	4d 89 fc             	mov    r12,r15
  9ade2d:	49 83 c4 10          	add    r12,0x10
  9ade31:	4c 89 f7             	mov    rdi,r14
  9ade34:	e8 27 91 a2 ff       	call   0x3d6f60
  9ade39:	41 89 47 14          	mov    DWORD PTR [r15+0x14],eax
  9ade3d:	83 f8 ff             	cmp    eax,0xffffffff
  9ade40:	74 10                	je     0x9ade52
  9ade42:	49 c1 ee 10          	shr    r14,0x10
  9ade46:	4d 89 77 18          	mov    QWORD PTR [r15+0x18],r14
  9ade4a:	41 c7 47 10 8c 00 00 	mov    DWORD PTR [r15+0x10],0x8c
  9ade51:	00 
  9ade52:	4d 89 67 08          	mov    QWORD PTR [r15+0x8],r12
  9ade56:	eb 45                	jmp    0x9ade9d
  9ade58:	48 8d 3d ac c9 9f 00 	lea    rdi,[rip+0x9fc9ac]        # 0x13aa80b
  9ade5f:	48 8d 35 57 35 9b 00 	lea    rsi,[rip+0x9b3557]        # 0x13613bd
  9ade66:	31 c0                	xor    eax,eax
  9ade68:	e8 a3 f5 8a ff       	call   0x25d410
  9ade6d:	48 8b 83 28 01 00 00 	mov    rax,QWORD PTR [rbx+0x128]
  9ade74:	48 89 df             	mov    rdi,rbx
  9ade77:	be 16 00 00 00       	mov    esi,0x16
  9ade7c:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  9ade80:	5b                   	pop    rbx
  9ade81:	41 5c                	pop    r12
  9ade83:	41 5e                	pop    r14
  9ade85:	41 5f                	pop    r15
  9ade87:	5d                   	pop    rbp
  9ade88:	e9 b3 ee ff ff       	jmp    0x9acd40
  9ade8d:	49 c7 47 08 00 00 00 	mov    QWORD PTR [r15+0x8],0x0
  9ade94:	00 
  9ade95:	41 c7 47 14 ff ff ff 	mov    DWORD PTR [r15+0x14],0xffffffff
  9ade9c:	ff 
  9ade9d:	48 89 df             	mov    rdi,rbx
  9adea0:	4c 89 fe             	mov    rsi,r15
  9adea3:	5b                   	pop    rbx
  9adea4:	41 5c                	pop    r12
  9adea6:	41 5e                	pop    r14
  9adea8:	41 5f                	pop    r15
  9adeaa:	5d                   	pop    rbp
  9adeab:	e9 60 01 00 00       	jmp    0x9ae010
  9adeb0:	55                   	push   rbp
  9adeb1:	48 89 e5             	mov    rbp,rsp
  9adeb4:	41 57                	push   r15
  9adeb6:	41 56                	push   r14
  9adeb8:	41 55                	push   r13
  9adeba:	41 54                	push   r12
  9adebc:	53                   	push   rbx
  9adebd:	48 83 ec 18          	sub    rsp,0x18
  9adec1:	48 8d 05 48 e4 f6 02 	lea    rax,[rip+0x2f6e448]        # 0x391c310
  9adec8:	49 89 ff             	mov    r15,rdi
  9adecb:	41 89 f5             	mov    r13d,esi
  9adece:	48 8b 00             	mov    rax,QWORD PTR [rax]
  9aded1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  9aded5:	4c 8b 37             	mov    r14,QWORD PTR [rdi]
  9aded8:	bf c1 21 00 00       	mov    edi,0x21c1
  9adedd:	41 8b 86 98 01 00 00 	mov    eax,DWORD PTR [r14+0x198]
  9adee4:	85 c0                	test   eax,eax
  9adee6:	0f 45 f8             	cmovne edi,eax
  9adee9:	e8 82 30 c4 ff       	call   0x5f0f70
  9adeee:	48 8d 75 ce          	lea    rsi,[rbp-0x32]
  9adef2:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  9adef6:	44 89 ef             	mov    edi,r13d
  9adef9:	31 c9                	xor    ecx,ecx
  9adefb:	89 c3                	mov    ebx,eax
  9adefd:	66 c7 45 ce 00 00    	mov    WORD PTR [rbp-0x32],0x0
  9adf03:	c7 45 c8 00 00 00 00 	mov    DWORD PTR [rbp-0x38],0x0
  9adf0a:	e8 91 02 ce ff       	call   0x68e1a0
  9adf0f:	85 c0                	test   eax,eax
  9adf11:	74 47                	je     0x9adf5a
  9adf13:	48 8d 3d 1a 68 9d 00 	lea    rdi,[rip+0x9d681a]        # 0x1384734
  9adf1a:	48 8d 35 85 e6 97 00 	lea    rsi,[rip+0x97e685]        # 0x132c5a6
  9adf21:	89 c2                	mov    edx,eax
  9adf23:	44 89 e9             	mov    ecx,r13d
  9adf26:	41 89 c4             	mov    r12d,eax
  9adf29:	31 c0                	xor    eax,eax
  9adf2b:	e8 e0 f4 8a ff       	call   0x25d410
  9adf30:	48 8d 35 99 20 bb 01 	lea    rsi,[rip+0x1bb2099]        # 0x255ffd0
  9adf37:	4c 89 ff             	mov    rdi,r15
  9adf3a:	e8 b1 ae 25 00       	call   0xc08df0
  9adf3f:	49                   	rex.WB

; ===== SUPPLEMENTAL GNU objdump linear disassembly: ALL 4096 ORIGINAL BYTES =====
; This section is not REA output. It includes CC padding as decoded INT3.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_657.bin:     file format binary


Disassembly of section .data:

0000000000265f78 <.data>:
  265f78:	e9 c3 3f 74 00       	jmp    0x9a9f40
  265f7d:	cc                   	int3
  265f7e:	cc                   	int3
  265f7f:	cc                   	int3
  265f80:	e9 bb 54 69 00       	jmp    0x8fb440
  265f85:	cc                   	int3
  265f86:	cc                   	int3
  265f87:	cc                   	int3
  265f88:	e9 13 d2 23 00       	jmp    0x4a31a0
  265f8d:	cc                   	int3
  265f8e:	cc                   	int3
  265f8f:	cc                   	int3
  265f90:	e9 1b 89 85 00       	jmp    0xabe8b0
  265f95:	cc                   	int3
  265f96:	cc                   	int3
  265f97:	cc                   	int3
  265f98:	e9 53 52 74 00       	jmp    0x9ab1f0
  265f9d:	cc                   	int3
  265f9e:	cc                   	int3
  265f9f:	cc                   	int3
  265fa0:	e9 db 59 85 00       	jmp    0xabb980
  265fa5:	cc                   	int3
  265fa6:	cc                   	int3
  265fa7:	cc                   	int3
  265fa8:	e9 33 33 49 00       	jmp    0x6f92e0
  265fad:	cc                   	int3
  265fae:	cc                   	int3
  265faf:	cc                   	int3
  265fb0:	e9 eb ed 1c 00       	jmp    0x434da0
  265fb5:	cc                   	int3
  265fb6:	cc                   	int3
  265fb7:	cc                   	int3
  265fb8:	e9 f3 ed 1c 00       	jmp    0x434db0
  265fbd:	cc                   	int3
  265fbe:	cc                   	int3
  265fbf:	cc                   	int3
  265fc0:	e9 fb ed 1c 00       	jmp    0x434dc0
  265fc5:	cc                   	int3
  265fc6:	cc                   	int3
  265fc7:	cc                   	int3
  265fc8:	e9 c3 1d 1d 00       	jmp    0x437d90
  265fcd:	cc                   	int3
  265fce:	cc                   	int3
  265fcf:	cc                   	int3
  265fd0:	e9 ab 22 1d 00       	jmp    0x438280
  265fd5:	cc                   	int3
  265fd6:	cc                   	int3
  265fd7:	cc                   	int3
  265fd8:	e9 b3 06 88 00       	jmp    0xae6690
  265fdd:	cc                   	int3
  265fde:	cc                   	int3
  265fdf:	cc                   	int3
  265fe0:	e9 9b 05 88 00       	jmp    0xae6580
  265fe5:	cc                   	int3
  265fe6:	cc                   	int3
  265fe7:	cc                   	int3
  265fe8:	e9 e3 30 1e 00       	jmp    0x4490d0
  265fed:	cc                   	int3
  265fee:	cc                   	int3
  265fef:	cc                   	int3
  265ff0:	e9 cb 0d e4 ff       	jmp    0xa6dc0
  265ff5:	cc                   	int3
  265ff6:	cc                   	int3
  265ff7:	cc                   	int3
  265ff8:	e9 73 4a 1e 00       	jmp    0x44aa70
  265ffd:	cc                   	int3
  265ffe:	cc                   	int3
  265fff:	cc                   	int3
  266000:	e9 0b 01 75 00       	jmp    0x9b6110
  266005:	cc                   	int3
  266006:	cc                   	int3
  266007:	cc                   	int3
  266008:	e9 63 16 e4 ff       	jmp    0xa7670
  26600d:	cc                   	int3
  26600e:	cc                   	int3
  26600f:	cc                   	int3
  266010:	e9 3b 18 e4 ff       	jmp    0xa7850
  266015:	cc                   	int3
  266016:	cc                   	int3
  266017:	cc                   	int3
  266018:	e9 63 18 e4 ff       	jmp    0xa7880
  26601d:	cc                   	int3
  26601e:	cc                   	int3
  26601f:	cc                   	int3
  266020:	e9 1b c0 1e 00       	jmp    0x452040
  266025:	cc                   	int3
  266026:	cc                   	int3
  266027:	cc                   	int3
  266028:	e9 93 ec 1e 00       	jmp    0x454cc0
  26602d:	cc                   	int3
  26602e:	cc                   	int3
  26602f:	cc                   	int3
  266030:	e9 eb 17 1f 00       	jmp    0x457820
  266035:	cc                   	int3
  266036:	cc                   	int3
  266037:	cc                   	int3
  266038:	e9 33 7f 20 00       	jmp    0x46df70
  26603d:	cc                   	int3
  26603e:	cc                   	int3
  26603f:	cc                   	int3
  266040:	e9 3b 80 20 00       	jmp    0x46e080
  266045:	cc                   	int3
  266046:	cc                   	int3
  266047:	cc                   	int3
  266048:	e9 43 c9 20 00       	jmp    0x472990
  26604d:	cc                   	int3
  26604e:	cc                   	int3
  26604f:	cc                   	int3
  266050:	e9 5b d3 20 00       	jmp    0x4733b0
  266055:	cc                   	int3
  266056:	cc                   	int3
  266057:	cc                   	int3
  266058:	e9 53 d8 20 00       	jmp    0x4738b0
  26605d:	cc                   	int3
  26605e:	cc                   	int3
  26605f:	cc                   	int3
  266060:	e9 eb e1 20 00       	jmp    0x474250
  266065:	cc                   	int3
  266066:	cc                   	int3
  266067:	cc                   	int3
  266068:	e9 43 ed 20 00       	jmp    0x474db0
  26606d:	cc                   	int3
  26606e:	cc                   	int3
  26606f:	cc                   	int3
  266070:	e9 7b 6f 21 00       	jmp    0x47cff0
  266075:	cc                   	int3
  266076:	cc                   	int3
  266077:	cc                   	int3
  266078:	e9 73 7f fb ff       	jmp    0x21dff0
  26607d:	cc                   	int3
  26607e:	cc                   	int3
  26607f:	cc                   	int3
  266080:	e9 7b a2 22 00       	jmp    0x490300
  266085:	cc                   	int3
  266086:	cc                   	int3
  266087:	cc                   	int3
  266088:	e9 23 ad 22 00       	jmp    0x490db0
  26608d:	cc                   	int3
  26608e:	cc                   	int3
  26608f:	cc                   	int3
  266090:	e9 1b 1f 23 00       	jmp    0x497fb0
  266095:	cc                   	int3
  266096:	cc                   	int3
  266097:	cc                   	int3
  266098:	e9 43 1f 23 00       	jmp    0x497fe0
  26609d:	cc                   	int3
  26609e:	cc                   	int3
  26609f:	cc                   	int3
  2660a0:	e9 8b 25 23 00       	jmp    0x498630
  2660a5:	cc                   	int3
  2660a6:	cc                   	int3
  2660a7:	cc                   	int3
  2660a8:	e9 93 25 23 00       	jmp    0x498640
  2660ad:	cc                   	int3
  2660ae:	cc                   	int3
  2660af:	cc                   	int3
  2660b0:	e9 0b 1b 69 00       	jmp    0x8f7bc0
  2660b5:	cc                   	int3
  2660b6:	cc                   	int3
  2660b7:	cc                   	int3
  2660b8:	e9 43 07 69 00       	jmp    0x8f6800
  2660bd:	cc                   	int3
  2660be:	cc                   	int3
  2660bf:	cc                   	int3
  2660c0:	e9 5b 13 69 00       	jmp    0x8f7420
  2660c5:	cc                   	int3
  2660c6:	cc                   	int3
  2660c7:	cc                   	int3
  2660c8:	e9 b3 3e 69 00       	jmp    0x8f9f80
  2660cd:	cc                   	int3
  2660ce:	cc                   	int3
  2660cf:	cc                   	int3
  2660d0:	e9 7b 92 37 00       	jmp    0x5df350
  2660d5:	cc                   	int3
  2660d6:	cc                   	int3
  2660d7:	cc                   	int3
  2660d8:	e9 43 97 37 00       	jmp    0x5df820
  2660dd:	cc                   	int3
  2660de:	cc                   	int3
  2660df:	cc                   	int3
  2660e0:	e9 fb eb 7c 00       	jmp    0xa34ce0
  2660e5:	cc                   	int3
  2660e6:	cc                   	int3
  2660e7:	cc                   	int3
  2660e8:	e9 b3 23 38 00       	jmp    0x5e84a0
  2660ed:	cc                   	int3
  2660ee:	cc                   	int3
  2660ef:	cc                   	int3
  2660f0:	e9 fb 20 69 00       	jmp    0x8f81f0
  2660f5:	cc                   	int3
  2660f6:	cc                   	int3
  2660f7:	cc                   	int3
  2660f8:	e9 13 33 69 00       	jmp    0x8f9410
  2660fd:	cc                   	int3
  2660fe:	cc                   	int3
  2660ff:	cc                   	int3
  266100:	e9 eb 62 69 00       	jmp    0x8fc3f0
  266105:	cc                   	int3
  266106:	cc                   	int3
  266107:	cc                   	int3
  266108:	e9 83 0b 69 00       	jmp    0x8f6c90
  26610d:	cc                   	int3
  26610e:	cc                   	int3
  26610f:	cc                   	int3
  266110:	e9 fb b8 a4 00       	jmp    0xcb1a10
  266115:	cc                   	int3
  266116:	cc                   	int3
  266117:	cc                   	int3
  266118:	e9 83 22 85 00       	jmp    0xab83a0
  26611d:	cc                   	int3
  26611e:	cc                   	int3
  26611f:	cc                   	int3
  266120:	e9 8b 22 85 00       	jmp    0xab83b0
  266125:	cc                   	int3
  266126:	cc                   	int3
  266127:	cc                   	int3
  266128:	e9 93 40 69 00       	jmp    0x8fa1c0
  26612d:	cc                   	int3
  26612e:	cc                   	int3
  26612f:	cc                   	int3
  266130:	e9 0b 1a 69 00       	jmp    0x8f7b40
  266135:	cc                   	int3
  266136:	cc                   	int3
  266137:	cc                   	int3
  266138:	e9 23 a8 23 00       	jmp    0x4a0960
  26613d:	cc                   	int3
  26613e:	cc                   	int3
  26613f:	cc                   	int3
  266140:	e9 3b 36 4c 00       	jmp    0x729780
  266145:	cc                   	int3
  266146:	cc                   	int3
  266147:	cc                   	int3
  266148:	e9 43 36 4c 00       	jmp    0x729790
  26614d:	cc                   	int3
  26614e:	cc                   	int3
  26614f:	cc                   	int3
  266150:	e9 4b 36 4c 00       	jmp    0x7297a0
  266155:	cc                   	int3
  266156:	cc                   	int3
  266157:	cc                   	int3
  266158:	e9 33 54 45 00       	jmp    0x6bb590
  26615d:	cc                   	int3
  26615e:	cc                   	int3
  26615f:	cc                   	int3
  266160:	e9 3b 2c 85 00       	jmp    0xab8da0
  266165:	cc                   	int3
  266166:	cc                   	int3
  266167:	cc                   	int3
  266168:	e9 03 40 69 00       	jmp    0x8fa170
  26616d:	cc                   	int3
  26616e:	cc                   	int3
  26616f:	cc                   	int3
  266170:	e9 4b 8f 91 00       	jmp    0xb7f0c0
  266175:	cc                   	int3
  266176:	cc                   	int3
  266177:	cc                   	int3
  266178:	e9 83 8f 91 00       	jmp    0xb7f100
  26617d:	cc                   	int3
  26617e:	cc                   	int3
  26617f:	cc                   	int3
  266180:	e9 6b 3b 69 00       	jmp    0x8f9cf0
  266185:	cc                   	int3
  266186:	cc                   	int3
  266187:	cc                   	int3
  266188:	e9 b3 45 69 00       	jmp    0x8fa740
  26618d:	cc                   	int3
  26618e:	cc                   	int3
  26618f:	cc                   	int3
  266190:	e9 db c9 2e 00       	jmp    0x552b70
  266195:	cc                   	int3
  266196:	cc                   	int3
  266197:	cc                   	int3
  266198:	e9 53 ca 2e 00       	jmp    0x552bf0
  26619d:	cc                   	int3
  26619e:	cc                   	int3
  26619f:	cc                   	int3
  2661a0:	e9 ab ca 2e 00       	jmp    0x552c50
  2661a5:	cc                   	int3
  2661a6:	cc                   	int3
  2661a7:	cc                   	int3
  2661a8:	e9 d3 ca 2e 00       	jmp    0x552c80
  2661ad:	cc                   	int3
  2661ae:	cc                   	int3
  2661af:	cc                   	int3
  2661b0:	e9 fb ca 2e 00       	jmp    0x552cb0
  2661b5:	cc                   	int3
  2661b6:	cc                   	int3
  2661b7:	cc                   	int3
  2661b8:	e9 23 cb 2e 00       	jmp    0x552ce0
  2661bd:	cc                   	int3
  2661be:	cc                   	int3
  2661bf:	cc                   	int3
  2661c0:	e9 3b 86 91 00       	jmp    0xb7e800
  2661c5:	cc                   	int3
  2661c6:	cc                   	int3
  2661c7:	cc                   	int3
  2661c8:	e9 13 8a 91 00       	jmp    0xb7ebe0
  2661cd:	cc                   	int3
  2661ce:	cc                   	int3
  2661cf:	cc                   	int3
  2661d0:	e9 9b 8d 91 00       	jmp    0xb7ef70
  2661d5:	cc                   	int3
  2661d6:	cc                   	int3
  2661d7:	cc                   	int3
  2661d8:	e9 53 0b 9a 00       	jmp    0xc06d30
  2661dd:	cc                   	int3
  2661de:	cc                   	int3
  2661df:	cc                   	int3
  2661e0:	e9 ab c4 52 00       	jmp    0x792690
  2661e5:	cc                   	int3
  2661e6:	cc                   	int3
  2661e7:	cc                   	int3
  2661e8:	e9 33 29 38 00       	jmp    0x5e8b20
  2661ed:	cc                   	int3
  2661ee:	cc                   	int3
  2661ef:	cc                   	int3
  2661f0:	e9 1b cb 2e 00       	jmp    0x552d10
  2661f5:	cc                   	int3
  2661f6:	cc                   	int3
  2661f7:	cc                   	int3
  2661f8:	e9 63 8f 91 00       	jmp    0xb7f160
  2661fd:	cc                   	int3
  2661fe:	cc                   	int3
  2661ff:	cc                   	int3
  266200:	e9 4b 80 37 00       	jmp    0x5de250
  266205:	cc                   	int3
  266206:	cc                   	int3
  266207:	cc                   	int3
  266208:	e9 23 e8 7e 00       	jmp    0xa54a30
  26620d:	cc                   	int3
  26620e:	cc                   	int3
  26620f:	cc                   	int3
  266210:	e9 2b e8 7e 00       	jmp    0xa54a40
  266215:	cc                   	int3
  266216:	cc                   	int3
  266217:	cc                   	int3
  266218:	e9 33 e8 7e 00       	jmp    0xa54a50
  26621d:	cc                   	int3
  26621e:	cc                   	int3
  26621f:	cc                   	int3
  266220:	e9 3b e8 7e 00       	jmp    0xa54a60
  266225:	cc                   	int3
  266226:	cc                   	int3
  266227:	cc                   	int3
  266228:	e9 53 e8 7e 00       	jmp    0xa54a80
  26622d:	cc                   	int3
  26622e:	cc                   	int3
  26622f:	cc                   	int3
  266230:	e9 5b e8 7e 00       	jmp    0xa54a90
  266235:	cc                   	int3
  266236:	cc                   	int3
  266237:	cc                   	int3
  266238:	e9 e3 34 69 00       	jmp    0x8f9720
  26623d:	cc                   	int3
  26623e:	cc                   	int3
  26623f:	cc                   	int3
  266240:	e9 6b e8 7e 00       	jmp    0xa54ab0
  266245:	cc                   	int3
  266246:	cc                   	int3
  266247:	cc                   	int3
  266248:	e9 93 02 69 00       	jmp    0x8f64e0
  26624d:	cc                   	int3
  26624e:	cc                   	int3
  26624f:	cc                   	int3
  266250:	e9 9b fc 68 00       	jmp    0x8f5ef0
  266255:	cc                   	int3
  266256:	cc                   	int3
  266257:	cc                   	int3
  266258:	e9 c3 e7 7e 00       	jmp    0xa54a20
  26625d:	cc                   	int3
  26625e:	cc                   	int3
  26625f:	cc                   	int3
  266260:	e9 0b e8 7e 00       	jmp    0xa54a70
  266265:	cc                   	int3
  266266:	cc                   	int3
  266267:	cc                   	int3
  266268:	e9 33 e8 7e 00       	jmp    0xa54aa0
  26626d:	cc                   	int3
  26626e:	cc                   	int3
  26626f:	cc                   	int3
  266270:	e9 5b f2 47 00       	jmp    0x6e54d0
  266275:	cc                   	int3
  266276:	cc                   	int3
  266277:	cc                   	int3
  266278:	e9 33 92 91 00       	jmp    0xb7f4b0
  26627d:	cc                   	int3
  26627e:	cc                   	int3
  26627f:	cc                   	int3
  266280:	e9 db 73 5d 00       	jmp    0x83d660
  266285:	cc                   	int3
  266286:	cc                   	int3
  266287:	cc                   	int3
  266288:	e9 33 75 5d 00       	jmp    0x83d7c0
  26628d:	cc                   	int3
  26628e:	cc                   	int3
  26628f:	cc                   	int3
  266290:	e9 1b 78 5d 00       	jmp    0x83dab0
  266295:	cc                   	int3
  266296:	cc                   	int3
  266297:	cc                   	int3
  266298:	e9 e3 7b 5d 00       	jmp    0x83de80
  26629d:	cc                   	int3
  26629e:	cc                   	int3
  26629f:	cc                   	int3
  2662a0:	e9 db 39 69 00       	jmp    0x8f9c80
  2662a5:	cc                   	int3
  2662a6:	cc                   	int3
  2662a7:	cc                   	int3
  2662a8:	e9 63 3e 69 00       	jmp    0x8fa110
  2662ad:	cc                   	int3
  2662ae:	cc                   	int3
  2662af:	cc                   	int3
  2662b0:	e9 fb 2e 69 00       	jmp    0x8f91b0
  2662b5:	cc                   	int3
  2662b6:	cc                   	int3
  2662b7:	cc                   	int3
  2662b8:	e9 33 42 69 00       	jmp    0x8fa4f0
  2662bd:	cc                   	int3
  2662be:	cc                   	int3
  2662bf:	cc                   	int3
  2662c0:	e9 cb 1d 69 00       	jmp    0x8f8090
  2662c5:	cc                   	int3
  2662c6:	cc                   	int3
  2662c7:	cc                   	int3
  2662c8:	e9 b3 58 69 00       	jmp    0x8fbb80
  2662cd:	cc                   	int3
  2662ce:	cc                   	int3
  2662cf:	cc                   	int3
  2662d0:	e9 ab 18 69 00       	jmp    0x8f7b80
  2662d5:	cc                   	int3
  2662d6:	cc                   	int3
  2662d7:	cc                   	int3
  2662d8:	e9 b3 15 69 00       	jmp    0x8f7890
  2662dd:	cc                   	int3
  2662de:	cc                   	int3
  2662df:	cc                   	int3
  2662e0:	e9 bb 55 69 00       	jmp    0x8fb8a0
  2662e5:	cc                   	int3
  2662e6:	cc                   	int3
  2662e7:	cc                   	int3
  2662e8:	e9 23 22 69 00       	jmp    0x8f8510
  2662ed:	cc                   	int3
  2662ee:	cc                   	int3
  2662ef:	cc                   	int3
  2662f0:	e9 0b 25 69 00       	jmp    0x8f8800
  2662f5:	cc                   	int3
  2662f6:	cc                   	int3
  2662f7:	cc                   	int3
  2662f8:	e9 83 4d 23 00       	jmp    0x49b080
  2662fd:	cc                   	int3
  2662fe:	cc                   	int3
  2662ff:	cc                   	int3
  266300:	e9 8b 4d 23 00       	jmp    0x49b090
  266305:	cc                   	int3
  266306:	cc                   	int3
  266307:	cc                   	int3
  266308:	e9 43 97 2f 00       	jmp    0x55fa50
  26630d:	cc                   	int3
  26630e:	cc                   	int3
  26630f:	cc                   	int3
  266310:	e9 5b e5 9c 00       	jmp    0xc34870
  266315:	cc                   	int3
  266316:	cc                   	int3
  266317:	cc                   	int3
  266318:	e9 d3 69 57 00       	jmp    0x7dccf0
  26631d:	cc                   	int3
  26631e:	cc                   	int3
  26631f:	cc                   	int3
  266320:	e9 db 69 57 00       	jmp    0x7dcd00
  266325:	cc                   	int3
  266326:	cc                   	int3
  266327:	cc                   	int3
  266328:	e9 e3 69 57 00       	jmp    0x7dcd10
  26632d:	cc                   	int3
  26632e:	cc                   	int3
  26632f:	cc                   	int3
  266330:	e9 eb 69 57 00       	jmp    0x7dcd20
  266335:	cc                   	int3
  266336:	cc                   	int3
  266337:	cc                   	int3
  266338:	e9 f3 69 57 00       	jmp    0x7dcd30
  26633d:	cc                   	int3
  26633e:	cc                   	int3
  26633f:	cc                   	int3
  266340:	e9 4b 09 34 00       	jmp    0x5a6c90
  266345:	cc                   	int3
  266346:	cc                   	int3
  266347:	cc                   	int3
  266348:	e9 b3 0f 34 00       	jmp    0x5a7300
  26634d:	cc                   	int3
  26634e:	cc                   	int3
  26634f:	cc                   	int3
  266350:	e9 bb 12 34 00       	jmp    0x5a7610
  266355:	cc                   	int3
  266356:	cc                   	int3
  266357:	cc                   	int3
  266358:	e9 a3 15 34 00       	jmp    0x5a7900
  26635d:	cc                   	int3
  26635e:	cc                   	int3
  26635f:	cc                   	int3
  266360:	e9 cb 64 a3 00       	jmp    0xc9c830
  266365:	cc                   	int3
  266366:	cc                   	int3
  266367:	cc                   	int3
  266368:	e9 93 1b 34 00       	jmp    0x5a7f00
  26636d:	cc                   	int3
  26636e:	cc                   	int3
  26636f:	cc                   	int3
  266370:	e9 fb 1c 34 00       	jmp    0x5a8070
  266375:	cc                   	int3
  266376:	cc                   	int3
  266377:	cc                   	int3
  266378:	e9 03 21 98 00       	jmp    0xbe8480
  26637d:	cc                   	int3
  26637e:	cc                   	int3
  26637f:	cc                   	int3
  266380:	e9 1b 4d 23 00       	jmp    0x49b0a0
  266385:	cc                   	int3
  266386:	cc                   	int3
  266387:	cc                   	int3
  266388:	e9 33 4d 23 00       	jmp    0x49b0c0
  26638d:	cc                   	int3
  26638e:	cc                   	int3
  26638f:	cc                   	int3
  266390:	e9 3b 4d 23 00       	jmp    0x49b0d0
  266395:	cc                   	int3
  266396:	cc                   	int3
  266397:	cc                   	int3
  266398:	e9 43 4d 23 00       	jmp    0x49b0e0
  26639d:	cc                   	int3
  26639e:	cc                   	int3
  26639f:	cc                   	int3
  2663a0:	e9 4b 4d 23 00       	jmp    0x49b0f0
  2663a5:	cc                   	int3
  2663a6:	cc                   	int3
  2663a7:	cc                   	int3
  2663a8:	e9 73 a3 2c 00       	jmp    0x530720
  2663ad:	cc                   	int3
  2663ae:	cc                   	int3
  2663af:	cc                   	int3
  2663b0:	e9 bb b2 2c 00       	jmp    0x531670
  2663b5:	cc                   	int3
  2663b6:	cc                   	int3
  2663b7:	cc                   	int3
  2663b8:	e9 33 33 69 00       	jmp    0x8f96f0
  2663bd:	cc                   	int3
  2663be:	cc                   	int3
  2663bf:	cc                   	int3
  2663c0:	e9 6b ae 2c 00       	jmp    0x531230
  2663c5:	cc                   	int3
  2663c6:	cc                   	int3
  2663c7:	cc                   	int3
  2663c8:	e9 23 ca 59 00       	jmp    0x802df0
  2663cd:	cc                   	int3
  2663ce:	cc                   	int3
  2663cf:	cc                   	int3
  2663d0:	e9 6b 8d 91 00       	jmp    0xb7f140
  2663d5:	cc                   	int3
  2663d6:	cc                   	int3
  2663d7:	cc                   	int3
  2663d8:	e9 03 d2 87 00       	jmp    0xae35e0
  2663dd:	cc                   	int3
  2663de:	cc                   	int3
  2663df:	cc                   	int3
  2663e0:	e9 3b 8a 28 00       	jmp    0x4eee20
  2663e5:	cc                   	int3
  2663e6:	cc                   	int3
  2663e7:	cc                   	int3
  2663e8:	e9 23 47 69 00       	jmp    0x8fab10
  2663ed:	cc                   	int3
  2663ee:	cc                   	int3
  2663ef:	cc                   	int3
  2663f0:	e9 3b 4a 69 00       	jmp    0x8fae30
  2663f5:	cc                   	int3
  2663f6:	cc                   	int3
  2663f7:	cc                   	int3
  2663f8:	e9 23 2e 76 00       	jmp    0x9c9220
  2663fd:	cc                   	int3
  2663fe:	cc                   	int3
  2663ff:	cc                   	int3
  266400:	e9 fb 2c 76 00       	jmp    0x9c9100
  266405:	cc                   	int3
  266406:	cc                   	int3
  266407:	cc                   	int3
  266408:	e9 03 bf 3d 00       	jmp    0x642310
  26640d:	cc                   	int3
  26640e:	cc                   	int3
  26640f:	cc                   	int3
  266410:	e9 0b c4 3d 00       	jmp    0x642820
  266415:	cc                   	int3
  266416:	cc                   	int3
  266417:	cc                   	int3
  266418:	e9 c3 d2 3d 00       	jmp    0x6436e0
  26641d:	cc                   	int3
  26641e:	cc                   	int3
  26641f:	cc                   	int3
  266420:	e9 ab d4 3d 00       	jmp    0x6438d0
  266425:	cc                   	int3
  266426:	cc                   	int3
  266427:	cc                   	int3
  266428:	e9 33 d8 3d 00       	jmp    0x643c60
  26642d:	cc                   	int3
  26642e:	cc                   	int3
  26642f:	cc                   	int3
  266430:	e9 5b 1e 79 00       	jmp    0x9f8290
  266435:	cc                   	int3
  266436:	cc                   	int3
  266437:	cc                   	int3
  266438:	e9 33 57 79 00       	jmp    0x9fbb70
  26643d:	cc                   	int3
  26643e:	cc                   	int3
  26643f:	cc                   	int3
  266440:	e9 3b ee 7d 00       	jmp    0xa45280
  266445:	cc                   	int3
  266446:	cc                   	int3
  266447:	cc                   	int3
  266448:	e9 53 18 a2 00       	jmp    0xc87ca0
  26644d:	cc                   	int3
  26644e:	cc                   	int3
  26644f:	cc                   	int3
  266450:	e9 ab 8b 79 00       	jmp    0x9ff000
  266455:	cc                   	int3
  266456:	cc                   	int3
  266457:	cc                   	int3
  266458:	e9 23 a3 79 00       	jmp    0xa00780
  26645d:	cc                   	int3
  26645e:	cc                   	int3
  26645f:	cc                   	int3
  266460:	e9 7b a3 79 00       	jmp    0xa007e0
  266465:	cc                   	int3
  266466:	cc                   	int3
  266467:	cc                   	int3
  266468:	e9 c3 83 85 00       	jmp    0xabe830
  26646d:	cc                   	int3
  26646e:	cc                   	int3
  26646f:	cc                   	int3
  266470:	e9 bb 6a 79 00       	jmp    0x9fcf30
  266475:	cc                   	int3
  266476:	cc                   	int3
  266477:	cc                   	int3
  266478:	e9 43 ab 38 00       	jmp    0x5f0fc0
  26647d:	cc                   	int3
  26647e:	cc                   	int3
  26647f:	cc                   	int3
  266480:	e9 6b 0f 69 00       	jmp    0x8f73f0
  266485:	cc                   	int3
  266486:	cc                   	int3
  266487:	cc                   	int3
  266488:	e9 c3 0d 29 00       	jmp    0x4f7250
  26648d:	cc                   	int3
  26648e:	cc                   	int3
  26648f:	cc                   	int3
  266490:	e9 3b 76 79 00       	jmp    0x9fdad0
  266495:	cc                   	int3
  266496:	cc                   	int3
  266497:	cc                   	int3
  266498:	e9 13 79 79 00       	jmp    0x9fddb0
  26649d:	cc                   	int3
  26649e:	cc                   	int3
  26649f:	cc                   	int3
  2664a0:	e9 6b 7a 79 00       	jmp    0x9fdf10
  2664a5:	cc                   	int3
  2664a6:	cc                   	int3
  2664a7:	cc                   	int3
  2664a8:	e9 23 e0 3d 00       	jmp    0x6444d0
  2664ad:	cc                   	int3
  2664ae:	cc                   	int3
  2664af:	cc                   	int3
  2664b0:	e9 1b ab 3e 00       	jmp    0x650fd0
  2664b5:	cc                   	int3
  2664b6:	cc                   	int3
  2664b7:	cc                   	int3
  2664b8:	e9 73 85 79 00       	jmp    0x9fea30
  2664bd:	cc                   	int3
  2664be:	cc                   	int3
  2664bf:	cc                   	int3
  2664c0:	e9 7b 14 29 00       	jmp    0x4f7940
  2664c5:	cc                   	int3
  2664c6:	cc                   	int3
  2664c7:	cc                   	int3
  2664c8:	e9 13 26 85 00       	jmp    0xab8ae0
  2664cd:	cc                   	int3
  2664ce:	cc                   	int3
  2664cf:	cc                   	int3
  2664d0:	e9 8b 51 85 00       	jmp    0xabb660
  2664d5:	cc                   	int3
  2664d6:	cc                   	int3
  2664d7:	cc                   	int3
  2664d8:	e9 83 7d 79 00       	jmp    0x9fe260
  2664dd:	cc                   	int3
  2664de:	cc                   	int3
  2664df:	cc                   	int3
  2664e0:	e9 fb 7f 79 00       	jmp    0x9fe4e0
  2664e5:	cc                   	int3
  2664e6:	cc                   	int3
  2664e7:	cc                   	int3
  2664e8:	e9 43 81 79 00       	jmp    0x9fe630
  2664ed:	cc                   	int3
  2664ee:	cc                   	int3
  2664ef:	cc                   	int3
  2664f0:	e9 3b 1e 53 00       	jmp    0x798330
  2664f5:	cc                   	int3
  2664f6:	cc                   	int3
  2664f7:	cc                   	int3
  2664f8:	e9 03 6b 85 00       	jmp    0xabd000
  2664fd:	cc                   	int3
  2664fe:	cc                   	int3
  2664ff:	cc                   	int3
  266500:	e9 8b 63 e9 ff       	jmp    0xfc890
  266505:	cc                   	int3
  266506:	cc                   	int3
  266507:	cc                   	int3
  266508:	e9 83 8b 23 00       	jmp    0x49f090
  26650d:	cc                   	int3
  26650e:	cc                   	int3
  26650f:	cc                   	int3
  266510:	e9 eb 8c 23 00       	jmp    0x49f200
  266515:	cc                   	int3
  266516:	cc                   	int3
  266517:	cc                   	int3
  266518:	e9 73 a0 25 00       	jmp    0x4c0590
  26651d:	cc                   	int3
  26651e:	cc                   	int3
  26651f:	cc                   	int3
  266520:	e9 8b a0 25 00       	jmp    0x4c05b0
  266525:	cc                   	int3
  266526:	cc                   	int3
  266527:	cc                   	int3
  266528:	e9 03 2f e4 ff       	jmp    0xa9430
  26652d:	cc                   	int3
  26652e:	cc                   	int3
  26652f:	cc                   	int3
  266530:	e9 1b 3e 26 00       	jmp    0x4ca350
  266535:	cc                   	int3
  266536:	cc                   	int3
  266537:	cc                   	int3
  266538:	e9 03 45 26 00       	jmp    0x4caa40
  26653d:	cc                   	int3
  26653e:	cc                   	int3
  26653f:	cc                   	int3
  266540:	e9 cb 3f e4 ff       	jmp    0xaa510
  266545:	cc                   	int3
  266546:	cc                   	int3
  266547:	cc                   	int3
  266548:	e9 83 ec 26 00       	jmp    0x4d51d0
  26654d:	cc                   	int3
  26654e:	cc                   	int3
  26654f:	cc                   	int3
  266550:	e9 5b ac 5a 00       	jmp    0x8111b0
  266555:	cc                   	int3
  266556:	cc                   	int3
  266557:	cc                   	int3
  266558:	e9 33 49 db ff       	jmp    0x1ae90
  26655d:	cc                   	int3
  26655e:	cc                   	int3
  26655f:	cc                   	int3
  266560:	e9 cb 9a 28 00       	jmp    0x4f0030
  266565:	cc                   	int3
  266566:	cc                   	int3
  266567:	cc                   	int3
  266568:	e9 63 56 29 00       	jmp    0x4fbbd0
  26656d:	cc                   	int3
  26656e:	cc                   	int3
  26656f:	cc                   	int3
  266570:	e9 5b 69 2a 00       	jmp    0x50ced0
  266575:	cc                   	int3
  266576:	cc                   	int3
  266577:	cc                   	int3
  266578:	e9 63 69 2a 00       	jmp    0x50cee0
  26657d:	cc                   	int3
  26657e:	cc                   	int3
  26657f:	cc                   	int3
  266580:	e9 ab 69 2a 00       	jmp    0x50cf30
  266585:	cc                   	int3
  266586:	cc                   	int3
  266587:	cc                   	int3
  266588:	e9 e3 69 2a 00       	jmp    0x50cf70
  26658d:	cc                   	int3
  26658e:	cc                   	int3
  26658f:	cc                   	int3
  266590:	e9 1b 6a 2a 00       	jmp    0x50cfb0
  266595:	cc                   	int3
  266596:	cc                   	int3
  266597:	cc                   	int3
  266598:	e9 43 6a 2a 00       	jmp    0x50cfe0
  26659d:	cc                   	int3
  26659e:	cc                   	int3
  26659f:	cc                   	int3
  2665a0:	e9 2b 7f 2b 00       	jmp    0x51e4d0
  2665a5:	cc                   	int3
  2665a6:	cc                   	int3
  2665a7:	cc                   	int3
  2665a8:	e9 b3 89 2b 00       	jmp    0x51ef60
  2665ad:	cc                   	int3
  2665ae:	cc                   	int3
  2665af:	cc                   	int3
  2665b0:	e9 4b 8a 2b 00       	jmp    0x51f000
  2665b5:	cc                   	int3
  2665b6:	cc                   	int3
  2665b7:	cc                   	int3
  2665b8:	e9 f3 8a 2b 00       	jmp    0x51f0b0
  2665bd:	cc                   	int3
  2665be:	cc                   	int3
  2665bf:	cc                   	int3
  2665c0:	e9 1b 8d 2b 00       	jmp    0x51f2e0
  2665c5:	cc                   	int3
  2665c6:	cc                   	int3
  2665c7:	cc                   	int3
  2665c8:	e9 a3 90 2b 00       	jmp    0x51f670
  2665cd:	cc                   	int3
  2665ce:	cc                   	int3
  2665cf:	cc                   	int3
  2665d0:	e9 0b 99 2b 00       	jmp    0x51fee0
  2665d5:	cc                   	int3
  2665d6:	cc                   	int3
  2665d7:	cc                   	int3
  2665d8:	e9 23 fe 2c 00       	jmp    0x536400
  2665dd:	cc                   	int3
  2665de:	cc                   	int3
  2665df:	cc                   	int3
  2665e0:	e9 bb e6 2d 00       	jmp    0x544ca0
  2665e5:	cc                   	int3
  2665e6:	cc                   	int3
  2665e7:	cc                   	int3
  2665e8:	e9 03 03 2e 00       	jmp    0x5468f0
  2665ed:	cc                   	int3
  2665ee:	cc                   	int3
  2665ef:	cc                   	int3
  2665f0:	e9 3b b0 e4 ff       	jmp    0xb1630
  2665f5:	cc                   	int3
  2665f6:	cc                   	int3
  2665f7:	cc                   	int3
  2665f8:	e9 b3 b9 e4 ff       	jmp    0xb1fb0
  2665fd:	cc                   	int3
  2665fe:	cc                   	int3
  2665ff:	cc                   	int3
  266600:	e9 3b 59 2f 00       	jmp    0x55bf40
  266605:	cc                   	int3
  266606:	cc                   	int3
  266607:	cc                   	int3
  266608:	e9 23 5a 2f 00       	jmp    0x55c030
  26660d:	cc                   	int3
  26660e:	cc                   	int3
  26660f:	cc                   	int3
  266610:	e9 3b 5a 2f 00       	jmp    0x55c050
  266615:	cc                   	int3
  266616:	cc                   	int3
  266617:	cc                   	int3
  266618:	e9 e3 7b 30 00       	jmp    0x56e200
  26661d:	cc                   	int3
  26661e:	cc                   	int3
  26661f:	cc                   	int3
  266620:	e9 7b 8e 31 00       	jmp    0x57f4a0
  266625:	cc                   	int3
  266626:	cc                   	int3
  266627:	cc                   	int3
  266628:	e9 b3 df 72 00       	jmp    0x9945e0
  26662d:	cc                   	int3
  26662e:	cc                   	int3
  26662f:	cc                   	int3
  266630:	e9 1b f3 31 00       	jmp    0x585950
  266635:	cc                   	int3
  266636:	cc                   	int3
  266637:	cc                   	int3
  266638:	e9 e3 31 33 00       	jmp    0x599820
  26663d:	cc                   	int3
  26663e:	cc                   	int3
  26663f:	cc                   	int3
  266640:	e9 9b 3d 33 00       	jmp    0x59a3e0
  266645:	cc                   	int3
  266646:	cc                   	int3
  266647:	cc                   	int3
  266648:	e9 e3 3e 33 00       	jmp    0x59a530
  26664d:	cc                   	int3
  26664e:	cc                   	int3
  26664f:	cc                   	int3
  266650:	e9 ab 40 33 00       	jmp    0x59a700
  266655:	cc                   	int3
  266656:	cc                   	int3
  266657:	cc                   	int3
  266658:	e9 73 41 33 00       	jmp    0x59a7d0
  26665d:	cc                   	int3
  26665e:	cc                   	int3
  26665f:	cc                   	int3
  266660:	e9 eb 43 33 00       	jmp    0x59aa50
  266665:	cc                   	int3
  266666:	cc                   	int3
  266667:	cc                   	int3
  266668:	e9 f3 44 33 00       	jmp    0x59ab60
  26666d:	cc                   	int3
  26666e:	cc                   	int3
  26666f:	cc                   	int3
  266670:	e9 eb 45 33 00       	jmp    0x59ac60
  266675:	cc                   	int3
  266676:	cc                   	int3
  266677:	cc                   	int3
  266678:	e9 53 58 37 00       	jmp    0x5dbed0
  26667d:	cc                   	int3
  26667e:	cc                   	int3
  26667f:	cc                   	int3
  266680:	e9 9b 50 38 00       	jmp    0x5eb720
  266685:	cc                   	int3
  266686:	cc                   	int3
  266687:	cc                   	int3
  266688:	e9 a3 59 38 00       	jmp    0x5ec030
  26668d:	cc                   	int3
  26668e:	cc                   	int3
  26668f:	cc                   	int3
  266690:	e9 3b 64 38 00       	jmp    0x5ecad0
  266695:	cc                   	int3
  266696:	cc                   	int3
  266697:	cc                   	int3
  266698:	e9 a3 6d 38 00       	jmp    0x5ed440
  26669d:	cc                   	int3
  26669e:	cc                   	int3
  26669f:	cc                   	int3
  2666a0:	e9 8b 74 38 00       	jmp    0x5edb30
  2666a5:	cc                   	int3
  2666a6:	cc                   	int3
  2666a7:	cc                   	int3
  2666a8:	e9 d3 7b ee ff       	jmp    0x14e280
  2666ad:	cc                   	int3
  2666ae:	cc                   	int3
  2666af:	cc                   	int3
  2666b0:	e9 fb b1 38 00       	jmp    0x5f18b0
  2666b5:	cc                   	int3
  2666b6:	cc                   	int3
  2666b7:	cc                   	int3
  2666b8:	e9 73 c4 38 00       	jmp    0x5f2b30
  2666bd:	cc                   	int3
  2666be:	cc                   	int3
  2666bf:	cc                   	int3
  2666c0:	e9 fb 69 39 00       	jmp    0x5fd0c0
  2666c5:	cc                   	int3
  2666c6:	cc                   	int3
  2666c7:	cc                   	int3
  2666c8:	e9 b3 9f 39 00       	jmp    0x600680
  2666cd:	cc                   	int3
  2666ce:	cc                   	int3
  2666cf:	cc                   	int3
  2666d0:	e9 6b a8 39 00       	jmp    0x600f40
  2666d5:	cc                   	int3
  2666d6:	cc                   	int3
  2666d7:	cc                   	int3
  2666d8:	e9 c3 fd 87 00       	jmp    0xae64a0
  2666dd:	cc                   	int3
  2666de:	cc                   	int3
  2666df:	cc                   	int3
  2666e0:	e9 bb 73 3c 00       	jmp    0x62daa0
  2666e5:	cc                   	int3
  2666e6:	cc                   	int3
  2666e7:	cc                   	int3
  2666e8:	e9 e3 9b 3c 00       	jmp    0x6302d0
  2666ed:	cc                   	int3
  2666ee:	cc                   	int3
  2666ef:	cc                   	int3
  2666f0:	e9 1b e8 3c 00       	jmp    0x634f10
  2666f5:	cc                   	int3
  2666f6:	cc                   	int3
  2666f7:	cc                   	int3
  2666f8:	e9 23 8e 3d 00       	jmp    0x63f520
  2666fd:	cc                   	int3
  2666fe:	cc                   	int3
  2666ff:	cc                   	int3
  266700:	e9 ab 12 3f 00       	jmp    0x6579b0
  266705:	cc                   	int3
  266706:	cc                   	int3
  266707:	cc                   	int3
  266708:	e9 03 0c a4 00       	jmp    0xca7310
  26670d:	cc                   	int3
  26670e:	cc                   	int3
  26670f:	cc                   	int3
  266710:	e9 5b c7 3f 00       	jmp    0x662e70
  266715:	cc                   	int3
  266716:	cc                   	int3
  266717:	cc                   	int3
  266718:	e9 63 c7 3f 00       	jmp    0x662e80
  26671d:	cc                   	int3
  26671e:	cc                   	int3
  26671f:	cc                   	int3
  266720:	e9 eb 26 41 00       	jmp    0x678e10
  266725:	cc                   	int3
  266726:	cc                   	int3
  266727:	cc                   	int3
  266728:	e9 33 27 41 00       	jmp    0x678e60
  26672d:	cc                   	int3
  26672e:	cc                   	int3
  26672f:	cc                   	int3
  266730:	e9 8b 27 41 00       	jmp    0x678ec0
  266735:	cc                   	int3
  266736:	cc                   	int3
  266737:	cc                   	int3
  266738:	e9 23 28 41 00       	jmp    0x678f60
  26673d:	cc                   	int3
  26673e:	cc                   	int3
  26673f:	cc                   	int3
  266740:	e9 4b 2a 41 00       	jmp    0x679190
  266745:	cc                   	int3
  266746:	cc                   	int3
  266747:	cc                   	int3
  266748:	e9 13 2c 41 00       	jmp    0x679360
  26674d:	cc                   	int3
  26674e:	cc                   	int3
  26674f:	cc                   	int3
  266750:	e9 2b 2f 41 00       	jmp    0x679680
  266755:	cc                   	int3
  266756:	cc                   	int3
  266757:	cc                   	int3
  266758:	e9 33 d4 dc ff       	jmp    0x33b90
  26675d:	cc                   	int3
  26675e:	cc                   	int3
  26675f:	cc                   	int3
  266760:	e9 3b d5 dc ff       	jmp    0x33ca0
  266765:	cc                   	int3
  266766:	cc                   	int3
  266767:	cc                   	int3
  266768:	e9 b3 d5 dc ff       	jmp    0x33d20
  26676d:	cc                   	int3
  26676e:	cc                   	int3
  26676f:	cc                   	int3
  266770:	e9 fb 67 dd ff       	jmp    0x3cf70
  266775:	cc                   	int3
  266776:	cc                   	int3
  266777:	cc                   	int3
  266778:	e9 63 69 dd ff       	jmp    0x3d0e0
  26677d:	cc                   	int3
  26677e:	cc                   	int3
  26677f:	cc                   	int3
  266780:	e9 db 6e dd ff       	jmp    0x3d660
  266785:	cc                   	int3
  266786:	cc                   	int3
  266787:	cc                   	int3
  266788:	e9 73 79 dd ff       	jmp    0x3e100
  26678d:	cc                   	int3
  26678e:	cc                   	int3
  26678f:	cc                   	int3
  266790:	e9 cb 79 dd ff       	jmp    0x3e160
  266795:	cc                   	int3
  266796:	cc                   	int3
  266797:	cc                   	int3
  266798:	e9 23 7a dd ff       	jmp    0x3e1c0
  26679d:	cc                   	int3
  26679e:	cc                   	int3
  26679f:	cc                   	int3
  2667a0:	e9 cb 88 dd ff       	jmp    0x3f070
  2667a5:	cc                   	int3
  2667a6:	cc                   	int3
  2667a7:	cc                   	int3
  2667a8:	e9 23 89 dd ff       	jmp    0x3f0d0
  2667ad:	cc                   	int3
  2667ae:	cc                   	int3
  2667af:	cc                   	int3
  2667b0:	e9 fb 8c dd ff       	jmp    0x3f4b0
  2667b5:	cc                   	int3
  2667b6:	cc                   	int3
  2667b7:	cc                   	int3
  2667b8:	e9 53 8d dd ff       	jmp    0x3f510
  2667bd:	cc                   	int3
  2667be:	cc                   	int3
  2667bf:	cc                   	int3
  2667c0:	e9 ab 8d dd ff       	jmp    0x3f570
  2667c5:	cc                   	int3
  2667c6:	cc                   	int3
  2667c7:	cc                   	int3
  2667c8:	e9 e3 93 dd ff       	jmp    0x3fbb0
  2667cd:	cc                   	int3
  2667ce:	cc                   	int3
  2667cf:	cc                   	int3
  2667d0:	e9 eb 97 dd ff       	jmp    0x3ffc0
  2667d5:	cc                   	int3
  2667d6:	cc                   	int3
  2667d7:	cc                   	int3
  2667d8:	e9 83 a1 dd ff       	jmp    0x40960
  2667dd:	cc                   	int3
  2667de:	cc                   	int3
  2667df:	cc                   	int3
  2667e0:	e9 6b a3 dd ff       	jmp    0x40b50
  2667e5:	cc                   	int3
  2667e6:	cc                   	int3
  2667e7:	cc                   	int3
  2667e8:	e9 43 a4 dd ff       	jmp    0x40c30
  2667ed:	cc                   	int3
  2667ee:	cc                   	int3
  2667ef:	cc                   	int3
  2667f0:	e9 3b ae dd ff       	jmp    0x41630
  2667f5:	cc                   	int3
  2667f6:	cc                   	int3
  2667f7:	cc                   	int3
  2667f8:	e9 53 af dd ff       	jmp    0x41750
  2667fd:	cc                   	int3
  2667fe:	cc                   	int3
  2667ff:	cc                   	int3
  266800:	e9 2b b0 dd ff       	jmp    0x41830
  266805:	cc                   	int3
  266806:	cc                   	int3
  266807:	cc                   	int3
  266808:	e9 b3 b0 dd ff       	jmp    0x418c0
  26680d:	cc                   	int3
  26680e:	cc                   	int3
  26680f:	cc                   	int3
  266810:	e9 4b b8 dd ff       	jmp    0x42060
  266815:	cc                   	int3
  266816:	cc                   	int3
  266817:	cc                   	int3
  266818:	e9 b3 bc dd ff       	jmp    0x424d0
  26681d:	cc                   	int3
  26681e:	cc                   	int3
  26681f:	cc                   	int3
  266820:	e9 7b bd dd ff       	jmp    0x425a0
  266825:	cc                   	int3
  266826:	cc                   	int3
  266827:	cc                   	int3
  266828:	e9 d3 bd dd ff       	jmp    0x42600
  26682d:	cc                   	int3
  26682e:	cc                   	int3
  26682f:	cc                   	int3
  266830:	e9 fb 97 42 00       	jmp    0x690030
  266835:	cc                   	int3
  266836:	cc                   	int3
  266837:	cc                   	int3
  266838:	e9 83 04 43 00       	jmp    0x696cc0
  26683d:	cc                   	int3
  26683e:	cc                   	int3
  26683f:	cc                   	int3
  266840:	e9 8b 1d 43 00       	jmp    0x6985d0
  266845:	cc                   	int3
  266846:	cc                   	int3
  266847:	cc                   	int3
  266848:	e9 03 b8 43 00       	jmp    0x6a2050
  26684d:	cc                   	int3
  26684e:	cc                   	int3
  26684f:	cc                   	int3
  266850:	e9 5b ba 43 00       	jmp    0x6a22b0
  266855:	cc                   	int3
  266856:	cc                   	int3
  266857:	cc                   	int3
  266858:	e9 e3 7d 44 00       	jmp    0x6ae640
  26685d:	cc                   	int3
  26685e:	cc                   	int3
  26685f:	cc                   	int3
  266860:	e9 8b 7f 44 00       	jmp    0x6ae7f0
  266865:	cc                   	int3
  266866:	cc                   	int3
  266867:	cc                   	int3
  266868:	e9 43 ab f1 ff       	jmp    0x1813b0
  26686d:	cc                   	int3
  26686e:	cc                   	int3
  26686f:	cc                   	int3
  266870:	e9 2b 87 45 00       	jmp    0x6befa0
  266875:	cc                   	int3
  266876:	cc                   	int3
  266877:	cc                   	int3
  266878:	e9 c3 17 f2 ff       	jmp    0x188040
  26687d:	cc                   	int3
  26687e:	cc                   	int3
  26687f:	cc                   	int3
  266880:	e9 7b a2 46 00       	jmp    0x6d0b00
  266885:	cc                   	int3
  266886:	cc                   	int3
  266887:	cc                   	int3
  266888:	e9 73 a8 46 00       	jmp    0x6d1100
  26688d:	cc                   	int3
  26688e:	cc                   	int3
  26688f:	cc                   	int3
  266890:	e9 cb a9 46 00       	jmp    0x6d1260
  266895:	cc                   	int3
  266896:	cc                   	int3
  266897:	cc                   	int3
  266898:	e9 43 ab 46 00       	jmp    0x6d13e0
  26689d:	cc                   	int3
  26689e:	cc                   	int3
  26689f:	cc                   	int3
  2668a0:	e9 7b ac 46 00       	jmp    0x6d1520
  2668a5:	cc                   	int3
  2668a6:	cc                   	int3
  2668a7:	cc                   	int3
  2668a8:	e9 93 ad 46 00       	jmp    0x6d1640
  2668ad:	cc                   	int3
  2668ae:	cc                   	int3
  2668af:	cc                   	int3
  2668b0:	e9 6b ae 46 00       	jmp    0x6d1720
  2668b5:	cc                   	int3
  2668b6:	cc                   	int3
  2668b7:	cc                   	int3
  2668b8:	e9 a3 5d 47 00       	jmp    0x6dc660
  2668bd:	cc                   	int3
  2668be:	cc                   	int3
  2668bf:	cc                   	int3
  2668c0:	e9 cb 5d 47 00       	jmp    0x6dc690
  2668c5:	cc                   	int3
  2668c6:	cc                   	int3
  2668c7:	cc                   	int3
  2668c8:	e9 d3 5d 47 00       	jmp    0x6dc6a0
  2668cd:	cc                   	int3
  2668ce:	cc                   	int3
  2668cf:	cc                   	int3
  2668d0:	e9 4b a0 47 00       	jmp    0x6e0920
  2668d5:	cc                   	int3
  2668d6:	cc                   	int3
  2668d7:	cc                   	int3
  2668d8:	e9 63 ab 47 00       	jmp    0x6e1440
  2668dd:	cc                   	int3
  2668de:	cc                   	int3
  2668df:	cc                   	int3
  2668e0:	e9 6b ab 47 00       	jmp    0x6e1450
  2668e5:	cc                   	int3
  2668e6:	cc                   	int3
  2668e7:	cc                   	int3
  2668e8:	e9 83 31 f2 ff       	jmp    0x189a70
  2668ed:	cc                   	int3
  2668ee:	cc                   	int3
  2668ef:	cc                   	int3
  2668f0:	e9 ab a1 f2 ff       	jmp    0x190aa0
  2668f5:	cc                   	int3
  2668f6:	cc                   	int3
  2668f7:	cc                   	int3
  2668f8:	e9 73 c0 49 00       	jmp    0x702970
  2668fd:	cc                   	int3
  2668fe:	cc                   	int3
  2668ff:	cc                   	int3
  266900:	e9 5b c4 49 00       	jmp    0x702d60
  266905:	cc                   	int3
  266906:	cc                   	int3
  266907:	cc                   	int3
  266908:	e9 63 f8 49 00       	jmp    0x706170
  26690d:	cc                   	int3
  26690e:	cc                   	int3
  26690f:	cc                   	int3
  266910:	e9 db f8 49 00       	jmp    0x7061f0
  266915:	cc                   	int3
  266916:	cc                   	int3
  266917:	cc                   	int3
  266918:	e9 e3 95 4a 00       	jmp    0x70ff00
  26691d:	cc                   	int3
  26691e:	cc                   	int3
  26691f:	cc                   	int3
  266920:	e9 8b 96 4a 00       	jmp    0x70ffb0
  266925:	cc                   	int3
  266926:	cc                   	int3
  266927:	cc                   	int3
  266928:	e9 93 98 4a 00       	jmp    0x7101c0
  26692d:	cc                   	int3
  26692e:	cc                   	int3
  26692f:	cc                   	int3
  266930:	e9 eb 99 4a 00       	jmp    0x710320
  266935:	cc                   	int3
  266936:	cc                   	int3
  266937:	cc                   	int3
  266938:	e9 73 c2 4a 00       	jmp    0x712bb0
  26693d:	cc                   	int3
  26693e:	cc                   	int3
  26693f:	cc                   	int3
  266940:	e9 1b fa 4a 00       	jmp    0x716360
  266945:	cc                   	int3
  266946:	cc                   	int3
  266947:	cc                   	int3
  266948:	e9 23 90 4c 00       	jmp    0x72f970
  26694d:	cc                   	int3
  26694e:	cc                   	int3
  26694f:	cc                   	int3
  266950:	e9 3b 90 4c 00       	jmp    0x72f990
  266955:	cc                   	int3
  266956:	cc                   	int3
  266957:	cc                   	int3
  266958:	e9 c3 90 4c 00       	jmp    0x72fa20
  26695d:	cc                   	int3
  26695e:	cc                   	int3
  26695f:	cc                   	int3
  266960:	e9 cb 04 fe ff       	jmp    0x246e30
  266965:	cc                   	int3
  266966:	cc                   	int3
  266967:	cc                   	int3
  266968:	e9 83 de 4f 00       	jmp    0x7647f0
  26696d:	cc                   	int3
  26696e:	cc                   	int3
  26696f:	cc                   	int3
  266970:	e9 9b cd 50 00       	jmp    0x773710
  266975:	cc                   	int3
  266976:	cc                   	int3
  266977:	cc                   	int3
  266978:	e9 d3 ef 50 00       	jmp    0x775950
  26697d:	cc                   	int3
  26697e:	cc                   	int3
  26697f:	cc                   	int3
  266980:	e9 0b 35 53 00       	jmp    0x799e90
  266985:	cc                   	int3
  266986:	cc                   	int3
  266987:	cc                   	int3
  266988:	e9 63 c8 54 00       	jmp    0x7b31f0
  26698d:	cc                   	int3
  26698e:	cc                   	int3
  26698f:	cc                   	int3
  266990:	e9 0b ba 57 00       	jmp    0x7e23a0
  266995:	cc                   	int3
  266996:	cc                   	int3
  266997:	cc                   	int3
  266998:	e9 43 1a 58 00       	jmp    0x7e83e0
  26699d:	cc                   	int3
  26699e:	cc                   	int3
  26699f:	cc                   	int3
  2669a0:	e9 db 1a 58 00       	jmp    0x7e8480
  2669a5:	cc                   	int3
  2669a6:	cc                   	int3
  2669a7:	cc                   	int3
  2669a8:	e9 03 48 9d 00       	jmp    0xc3b1b0
  2669ad:	cc                   	int3
  2669ae:	cc                   	int3
  2669af:	cc                   	int3
  2669b0:	e9 2b 5d 9d 00       	jmp    0xc3c6e0
  2669b5:	cc                   	int3
  2669b6:	cc                   	int3
  2669b7:	cc                   	int3
  2669b8:	e9 d3 5c 9d 00       	jmp    0xc3c690
  2669bd:	cc                   	int3
  2669be:	cc                   	int3
  2669bf:	cc                   	int3
  2669c0:	e9 6b 5d 9d 00       	jmp    0xc3c730
  2669c5:	cc                   	int3
  2669c6:	cc                   	int3
  2669c7:	cc                   	int3
  2669c8:	e9 53 b8 59 00       	jmp    0x802220
  2669cd:	cc                   	int3
  2669ce:	cc                   	int3
  2669cf:	cc                   	int3
  2669d0:	e9 1b bb 59 00       	jmp    0x8024f0
  2669d5:	cc                   	int3
  2669d6:	cc                   	int3
  2669d7:	cc                   	int3
  2669d8:	e9 93 5b 5a 00       	jmp    0x80c570
  2669dd:	cc                   	int3
  2669de:	cc                   	int3
  2669df:	cc                   	int3
  2669e0:	e9 1b 49 5c 00       	jmp    0x82b300
  2669e5:	cc                   	int3
  2669e6:	cc                   	int3
  2669e7:	cc                   	int3
  2669e8:	e9 f3 a4 6b 00       	jmp    0x920ee0
  2669ed:	cc                   	int3
  2669ee:	cc                   	int3
  2669ef:	cc                   	int3
  2669f0:	e9 9b a1 6b 00       	jmp    0x920b90
  2669f5:	cc                   	int3
  2669f6:	cc                   	int3
  2669f7:	cc                   	int3
  2669f8:	e9 13 9e 5c 00       	jmp    0x830810
  2669fd:	cc                   	int3
  2669fe:	cc                   	int3
  2669ff:	cc                   	int3
  266a00:	e9 fb a4 5c 00       	jmp    0x830f00
  266a05:	cc                   	int3
  266a06:	cc                   	int3
  266a07:	cc                   	int3
  266a08:	e9 a3 e8 5c 00       	jmp    0x8352b0
  266a0d:	cc                   	int3
  266a0e:	cc                   	int3
  266a0f:	cc                   	int3
  266a10:	e9 ab e8 5c 00       	jmp    0x8352c0
  266a15:	cc                   	int3
  266a16:	cc                   	int3
  266a17:	cc                   	int3
  266a18:	e9 b3 e8 5c 00       	jmp    0x8352d0
  266a1d:	cc                   	int3
  266a1e:	cc                   	int3
  266a1f:	cc                   	int3
  266a20:	e9 cb e8 5c 00       	jmp    0x8352f0
  266a25:	cc                   	int3
  266a26:	cc                   	int3
  266a27:	cc                   	int3
  266a28:	e9 13 ea 5c 00       	jmp    0x835440
  266a2d:	cc                   	int3
  266a2e:	cc                   	int3
  266a2f:	cc                   	int3
  266a30:	e9 1b ea 5c 00       	jmp    0x835450
  266a35:	cc                   	int3
  266a36:	cc                   	int3
  266a37:	cc                   	int3
  266a38:	e9 53 ea 5c 00       	jmp    0x835490
  266a3d:	cc                   	int3
  266a3e:	cc                   	int3
  266a3f:	cc                   	int3
  266a40:	e9 8b f0 5c 00       	jmp    0x835ad0
  266a45:	cc                   	int3
  266a46:	cc                   	int3
  266a47:	cc                   	int3
  266a48:	e9 23 9e 5e 00       	jmp    0x850870
  266a4d:	cc                   	int3
  266a4e:	cc                   	int3
  266a4f:	cc                   	int3
  266a50:	e9 9b 98 60 00       	jmp    0x8702f0
  266a55:	cc                   	int3
  266a56:	cc                   	int3
  266a57:	cc                   	int3
  266a58:	e9 73 9b 60 00       	jmp    0x8705d0
  266a5d:	cc                   	int3
  266a5e:	cc                   	int3
  266a5f:	cc                   	int3
  266a60:	e9 8b c0 60 00       	jmp    0x872af0
  266a65:	cc                   	int3
  266a66:	cc                   	int3
  266a67:	cc                   	int3
  266a68:	e9 93 cd 60 00       	jmp    0x873800
  266a6d:	cc                   	int3
  266a6e:	cc                   	int3
  266a6f:	cc                   	int3
  266a70:	e9 cb cf df ff       	jmp    0x63a40
  266a75:	cc                   	int3
  266a76:	cc                   	int3
  266a77:	cc                   	int3
  266a78:	e9 f3 f8 df ff       	jmp    0x66370
  266a7d:	cc                   	int3
  266a7e:	cc                   	int3
  266a7f:	cc                   	int3
  266a80:	e9 0b fb e7 ff       	jmp    0xe6590
  266a85:	cc                   	int3
  266a86:	cc                   	int3
  266a87:	cc                   	int3
  266a88:	e9 13 fb e7 ff       	jmp    0xe65a0
  266a8d:	cc                   	int3
  266a8e:	cc                   	int3
  266a8f:	cc                   	int3
  266a90:	e9 cb fc e7 ff       	jmp    0xe6760
  266a95:	cc                   	int3
  266a96:	cc                   	int3
  266a97:	cc                   	int3
  266a98:	e9 d3 fd e7 ff       	jmp    0xe6870
  266a9d:	cc                   	int3
  266a9e:	cc                   	int3
  266a9f:	cc                   	int3
  266aa0:	e9 eb 14 e8 ff       	jmp    0xe7f90
  266aa5:	cc                   	int3
  266aa6:	cc                   	int3
  266aa7:	cc                   	int3
  266aa8:	e9 f3 34 e8 ff       	jmp    0xe9fa0
  266aad:	cc                   	int3
  266aae:	cc                   	int3
  266aaf:	cc                   	int3
  266ab0:	e9 bb 3b e8 ff       	jmp    0xea670
  266ab5:	cc                   	int3
  266ab6:	cc                   	int3
  266ab7:	cc                   	int3
  266ab8:	e9 a3 3c e8 ff       	jmp    0xea760
  266abd:	cc                   	int3
  266abe:	cc                   	int3
  266abf:	cc                   	int3
  266ac0:	e9 db 45 e8 ff       	jmp    0xeb0a0
  266ac5:	cc                   	int3
  266ac6:	cc                   	int3
  266ac7:	cc                   	int3
  266ac8:	e9 c3 46 e8 ff       	jmp    0xeb190
  266acd:	cc                   	int3
  266ace:	cc                   	int3
  266acf:	cc                   	int3
  266ad0:	e9 2b 65 e8 ff       	jmp    0xed000
  266ad5:	cc                   	int3
  266ad6:	cc                   	int3
  266ad7:	cc                   	int3
  266ad8:	e9 33 66 e8 ff       	jmp    0xed110
  266add:	cc                   	int3
  266ade:	cc                   	int3
  266adf:	cc                   	int3
  266ae0:	e9 bb 3d 62 00       	jmp    0x88a8a0
  266ae5:	cc                   	int3
  266ae6:	cc                   	int3
  266ae7:	cc                   	int3
  266ae8:	e9 03 63 63 00       	jmp    0x89cdf0
  266aed:	cc                   	int3
  266aee:	cc                   	int3
  266aef:	cc                   	int3
  266af0:	e9 5b 80 e8 ff       	jmp    0xeeb50
  266af5:	cc                   	int3
  266af6:	cc                   	int3
  266af7:	cc                   	int3
  266af8:	e9 53 47 66 00       	jmp    0x8cb250
  266afd:	cc                   	int3
  266afe:	cc                   	int3
  266aff:	cc                   	int3
  266b00:	e9 8b 48 66 00       	jmp    0x8cb390
  266b05:	cc                   	int3
  266b06:	cc                   	int3
  266b07:	cc                   	int3
  266b08:	e9 53 c4 66 00       	jmp    0x8d2f60
  266b0d:	cc                   	int3
  266b0e:	cc                   	int3
  266b0f:	cc                   	int3
  266b10:	e9 7b c4 66 00       	jmp    0x8d2f90
  266b15:	cc                   	int3
  266b16:	cc                   	int3
  266b17:	cc                   	int3
  266b18:	e9 13 17 67 00       	jmp    0x8d8230
  266b1d:	cc                   	int3
  266b1e:	cc                   	int3
  266b1f:	cc                   	int3
  266b20:	e9 bb 22 67 00       	jmp    0x8d8de0
  266b25:	cc                   	int3
  266b26:	cc                   	int3
  266b27:	cc                   	int3
  266b28:	e9 83 2c 67 00       	jmp    0x8d97b0
  266b2d:	cc                   	int3
  266b2e:	cc                   	int3
  266b2f:	cc                   	int3
  266b30:	e9 db 2d 67 00       	jmp    0x8d9910
  266b35:	cc                   	int3
  266b36:	cc                   	int3
  266b37:	cc                   	int3
  266b38:	e9 83 39 67 00       	jmp    0x8da4c0
  266b3d:	cc                   	int3
  266b3e:	cc                   	int3
  266b3f:	cc                   	int3
  266b40:	e9 2b 3a 67 00       	jmp    0x8da570
  266b45:	cc                   	int3
  266b46:	cc                   	int3
  266b47:	cc                   	int3
  266b48:	e9 63 3a 67 00       	jmp    0x8da5b0
  266b4d:	cc                   	int3
  266b4e:	cc                   	int3
  266b4f:	cc                   	int3
  266b50:	e9 2b e1 69 00       	jmp    0x904c80
  266b55:	cc                   	int3
  266b56:	cc                   	int3
  266b57:	cc                   	int3
  266b58:	e9 03 e3 69 00       	jmp    0x904e60
  266b5d:	cc                   	int3
  266b5e:	cc                   	int3
  266b5f:	cc                   	int3
  266b60:	e9 9b 68 6b 00       	jmp    0x91d400
  266b65:	cc                   	int3
  266b66:	cc                   	int3
  266b67:	cc                   	int3
  266b68:	e9 33 69 6b 00       	jmp    0x91d4a0
  266b6d:	cc                   	int3
  266b6e:	cc                   	int3
  266b6f:	cc                   	int3
  266b70:	e9 5b b6 81 00       	jmp    0xa821d0
  266b75:	cc                   	int3
  266b76:	cc                   	int3
  266b77:	cc                   	int3
  266b78:	e9 a3 b5 8d 00       	jmp    0xb42120
  266b7d:	cc                   	int3
  266b7e:	cc                   	int3
  266b7f:	cc                   	int3
  266b80:	e9 ab e3 6f 00       	jmp    0x964f30
  266b85:	cc                   	int3
  266b86:	cc                   	int3
  266b87:	cc                   	int3
  266b88:	e9 c3 f3 70 00       	jmp    0x975f50
  266b8d:	cc                   	int3
  266b8e:	cc                   	int3
  266b8f:	cc                   	int3
  266b90:	e9 6b f6 70 00       	jmp    0x976200
  266b95:	cc                   	int3
  266b96:	cc                   	int3
  266b97:	cc                   	int3
  266b98:	e9 b3 5d 72 00       	jmp    0x98c950
  266b9d:	cc                   	int3
  266b9e:	cc                   	int3
  266b9f:	cc                   	int3
  266ba0:	e9 8b 60 72 00       	jmp    0x98cc30
  266ba5:	cc                   	int3
  266ba6:	cc                   	int3
  266ba7:	cc                   	int3
  266ba8:	e9 83 63 72 00       	jmp    0x98cf30
  266bad:	cc                   	int3
  266bae:	cc                   	int3
  266baf:	cc                   	int3
  266bb0:	e9 2b 6b 72 00       	jmp    0x98d6e0
  266bb5:	cc                   	int3
  266bb6:	cc                   	int3
  266bb7:	cc                   	int3
  266bb8:	e9 13 7a 72 00       	jmp    0x98e5d0
  266bbd:	cc                   	int3
  266bbe:	cc                   	int3
  266bbf:	cc                   	int3
  266bc0:	e9 3b 7b 72 00       	jmp    0x98e700
  266bc5:	cc                   	int3
  266bc6:	cc                   	int3
  266bc7:	cc                   	int3
  266bc8:	e9 a3 b5 72 00       	jmp    0x992170
  266bcd:	cc                   	int3
  266bce:	cc                   	int3
  266bcf:	cc                   	int3
  266bd0:	e9 6b b6 72 00       	jmp    0x992240
  266bd5:	cc                   	int3
  266bd6:	cc                   	int3
  266bd7:	cc                   	int3
  266bd8:	e9 23 e8 e8 ff       	jmp    0xf5400
  266bdd:	cc                   	int3
  266bde:	cc                   	int3
  266bdf:	cc                   	int3
  266be0:	e9 3b b7 73 00       	jmp    0x9a2320
  266be5:	cc                   	int3
  266be6:	cc                   	int3
  266be7:	cc                   	int3
  266be8:	e9 33 eb 73 00       	jmp    0x9a5720
  266bed:	cc                   	int3
  266bee:	cc                   	int3
  266bef:	cc                   	int3
  266bf0:	e9 ab 5d 74 00       	jmp    0x9ac9a0
  266bf5:	cc                   	int3
  266bf6:	cc                   	int3
  266bf7:	cc                   	int3
  266bf8:	e9 23 5e 74 00       	jmp    0x9aca20
  266bfd:	cc                   	int3
  266bfe:	cc                   	int3
  266bff:	cc                   	int3
  266c00:	e9 3b 7a f5 ff       	jmp    0x1be640
  266c05:	cc                   	int3
  266c06:	cc                   	int3
  266c07:	cc                   	int3
  266c08:	e9 13 81 75 00       	jmp    0x9bed20
  266c0d:	cc                   	int3
  266c0e:	cc                   	int3
  266c0f:	cc                   	int3
  266c10:	e9 3b f4 75 00       	jmp    0x9c6050
  266c15:	cc                   	int3
  266c16:	cc                   	int3
  266c17:	cc                   	int3
  266c18:	e9 b3 f4 75 00       	jmp    0x9c60d0
  266c1d:	cc                   	int3
  266c1e:	cc                   	int3
  266c1f:	cc                   	int3
  266c20:	e9 5b f6 75 00       	jmp    0x9c6280
  266c25:	cc                   	int3
  266c26:	cc                   	int3
  266c27:	cc                   	int3
  266c28:	e9 e3 f6 75 00       	jmp    0x9c6310
  266c2d:	cc                   	int3
  266c2e:	cc                   	int3
  266c2f:	cc                   	int3
  266c30:	e9 5b f8 75 00       	jmp    0x9c6490
  266c35:	cc                   	int3
  266c36:	cc                   	int3
  266c37:	cc                   	int3
  266c38:	e9 73 f9 75 00       	jmp    0x9c65b0
  266c3d:	cc                   	int3
  266c3e:	cc                   	int3
  266c3f:	cc                   	int3
  266c40:	e9 4b fc 75 00       	jmp    0x9c6890
  266c45:	cc                   	int3
  266c46:	cc                   	int3
  266c47:	cc                   	int3
  266c48:	e9 f3 26 76 00       	jmp    0x9c9340
  266c4d:	cc                   	int3
  266c4e:	cc                   	int3
  266c4f:	cc                   	int3
  266c50:	e9 0b 27 76 00       	jmp    0x9c9360
  266c55:	cc                   	int3
  266c56:	cc                   	int3
  266c57:	cc                   	int3
  266c58:	e9 13 27 76 00       	jmp    0x9c9370
  266c5d:	cc                   	int3
  266c5e:	cc                   	int3
  266c5f:	cc                   	int3
  266c60:	e9 1b 27 76 00       	jmp    0x9c9380
  266c65:	cc                   	int3
  266c66:	cc                   	int3
  266c67:	cc                   	int3
  266c68:	e9 43 41 77 00       	jmp    0x9dadb0
  266c6d:	cc                   	int3
  266c6e:	cc                   	int3
  266c6f:	cc                   	int3
  266c70:	e9 2b 43 77 00       	jmp    0x9dafa0
  266c75:	cc                   	int3
  266c76:	cc                   	int3
  266c77:	cc                   	int3
  266c78:	e9 e3 5b 77 00       	jmp    0x9dc860
  266c7d:	cc                   	int3
  266c7e:	cc                   	int3
  266c7f:	cc                   	int3
  266c80:	e9 bb 5f 77 00       	jmp    0x9dcc40
  266c85:	cc                   	int3
  266c86:	cc                   	int3
  266c87:	cc                   	int3
  266c88:	e9 f3 61 77 00       	jmp    0x9dce80
  266c8d:	cc                   	int3
  266c8e:	cc                   	int3
  266c8f:	cc                   	int3
  266c90:	e9 6b 68 77 00       	jmp    0x9dd500
  266c95:	cc                   	int3
  266c96:	cc                   	int3
  266c97:	cc                   	int3
  266c98:	e9 33 40 a4 00       	jmp    0xcaacd0
  266c9d:	cc                   	int3
  266c9e:	cc                   	int3
  266c9f:	cc                   	int3
  266ca0:	e9 2b 6b 77 00       	jmp    0x9dd7d0
  266ca5:	cc                   	int3
  266ca6:	cc                   	int3
  266ca7:	cc                   	int3
  266ca8:	e9 e3 6c 77 00       	jmp    0x9dd990
  266cad:	cc                   	int3
  266cae:	cc                   	int3
  266caf:	cc                   	int3
  266cb0:	e9 eb 6e 77 00       	jmp    0x9ddba0
  266cb5:	cc                   	int3
  266cb6:	cc                   	int3
  266cb7:	cc                   	int3
  266cb8:	e9 43 6f 77 00       	jmp    0x9ddc00
  266cbd:	cc                   	int3
  266cbe:	cc                   	int3
  266cbf:	cc                   	int3
  266cc0:	e9 8b 71 77 00       	jmp    0x9dde50
  266cc5:	cc                   	int3
  266cc6:	cc                   	int3
  266cc7:	cc                   	int3
  266cc8:	e9 e3 71 77 00       	jmp    0x9ddeb0
  266ccd:	cc                   	int3
  266cce:	cc                   	int3
  266ccf:	cc                   	int3
  266cd0:	e9 1b 73 77 00       	jmp    0x9ddff0
  266cd5:	cc                   	int3
  266cd6:	cc                   	int3
  266cd7:	cc                   	int3
  266cd8:	e9 93 73 77 00       	jmp    0x9de070
  266cdd:	cc                   	int3
  266cde:	cc                   	int3
  266cdf:	cc                   	int3
  266ce0:	e9 0b 74 77 00       	jmp    0x9de0f0
  266ce5:	cc                   	int3
  266ce6:	cc                   	int3
  266ce7:	cc                   	int3
  266ce8:	e9 a3 9e 77 00       	jmp    0x9e0b90
  266ced:	cc                   	int3
  266cee:	cc                   	int3
  266cef:	cc                   	int3
  266cf0:	e9 db 9f 77 00       	jmp    0x9e0cd0
  266cf5:	cc                   	int3
  266cf6:	cc                   	int3
  266cf7:	cc                   	int3
  266cf8:	e9 73 a0 77 00       	jmp    0x9e0d70
  266cfd:	cc                   	int3
  266cfe:	cc                   	int3
  266cff:	cc                   	int3
  266d00:	e9 eb a1 77 00       	jmp    0x9e0ef0
  266d05:	cc                   	int3
  266d06:	cc                   	int3
  266d07:	cc                   	int3
  266d08:	e9 43 a3 77 00       	jmp    0x9e1050
  266d0d:	cc                   	int3
  266d0e:	cc                   	int3
  266d0f:	cc                   	int3
  266d10:	e9 7b a7 77 00       	jmp    0x9e1490
  266d15:	cc                   	int3
  266d16:	cc                   	int3
  266d17:	cc                   	int3
  266d18:	e9 c3 f8 79 00       	jmp    0xa065e0
  266d1d:	cc                   	int3
  266d1e:	cc                   	int3
  266d1f:	cc                   	int3
  266d20:	e9 1b a6 e9 ff       	jmp    0x101340
  266d25:	cc                   	int3
  266d26:	cc                   	int3
  266d27:	cc                   	int3
  266d28:	e9 03 c2 7c 00       	jmp    0xa32f30
  266d2d:	cc                   	int3
  266d2e:	cc                   	int3
  266d2f:	cc                   	int3
  266d30:	e9 8b c9 7c 00       	jmp    0xa336c0
  266d35:	cc                   	int3
  266d36:	cc                   	int3
  266d37:	cc                   	int3
  266d38:	e9 53 1f 7d 00       	jmp    0xa38c90
  266d3d:	cc                   	int3
  266d3e:	cc                   	int3
  266d3f:	cc                   	int3
  266d40:	e9 bb 3d 80 00       	jmp    0xa6ab00
  266d45:	cc                   	int3
  266d46:	cc                   	int3
  266d47:	cc                   	int3
  266d48:	e9 63 3e 80 00       	jmp    0xa6abb0
  266d4d:	cc                   	int3
  266d4e:	cc                   	int3
  266d4f:	cc                   	int3
  266d50:	e9 bb 7e 82 00       	jmp    0xa8ec10
  266d55:	cc                   	int3
  266d56:	cc                   	int3
  266d57:	cc                   	int3
  266d58:	e9 a3 80 82 00       	jmp    0xa8ee00
  266d5d:	cc                   	int3
  266d5e:	cc                   	int3
  266d5f:	cc                   	int3
  266d60:	e9 4b aa 84 00       	jmp    0xab17b0
  266d65:	cc                   	int3
  266d66:	cc                   	int3
  266d67:	cc                   	int3
  266d68:	e9 43 9a 85 00       	jmp    0xac07b0
  266d6d:	cc                   	int3
  266d6e:	cc                   	int3
  266d6f:	cc                   	int3
  266d70:	e9 7b bd 85 00       	jmp    0xac2af0
  266d75:	cc                   	int3
  266d76:	cc                   	int3
  266d77:	cc                   	int3
  266d78:	e9 d3 39 eb ff       	jmp    0x11a750
  266d7d:	cc                   	int3
  266d7e:	cc                   	int3
  266d7f:	cc                   	int3
  266d80:	e9 1b a5 87 00       	jmp    0xae12a0
  266d85:	cc                   	int3
  266d86:	cc                   	int3
  266d87:	cc                   	int3
  266d88:	e9 73 c6 87 00       	jmp    0xae3400
  266d8d:	cc                   	int3
  266d8e:	cc                   	int3
  266d8f:	cc                   	int3
  266d90:	e9 9b c7 87 00       	jmp    0xae3530
  266d95:	cc                   	int3
  266d96:	cc                   	int3
  266d97:	cc                   	int3
  266d98:	e9 23 f6 87 00       	jmp    0xae63c0
  266d9d:	cc                   	int3
  266d9e:	cc                   	int3
  266d9f:	cc                   	int3
  266da0:	e9 3b 11 8a 00       	jmp    0xb07ee0
  266da5:	cc                   	int3
  266da6:	cc                   	int3
  266da7:	cc                   	int3
  266da8:	e9 e3 13 8a 00       	jmp    0xb08190
  266dad:	cc                   	int3
  266dae:	cc                   	int3
  266daf:	cc                   	int3
  266db0:	e9 7b 17 8a 00       	jmp    0xb08530
  266db5:	cc                   	int3
  266db6:	cc                   	int3
  266db7:	cc                   	int3
  266db8:	e9 53 1a 8a 00       	jmp    0xb08810
  266dbd:	cc                   	int3
  266dbe:	cc                   	int3
  266dbf:	cc                   	int3
  266dc0:	e9 db 28 8a 00       	jmp    0xb096a0
  266dc5:	cc                   	int3
  266dc6:	cc                   	int3
  266dc7:	cc                   	int3
  266dc8:	e9 23 47 8a 00       	jmp    0xb0b4f0
  266dcd:	cc                   	int3
  266dce:	cc                   	int3
  266dcf:	cc                   	int3
  266dd0:	e9 1b 83 f8 ff       	jmp    0x1ef0f0
  266dd5:	cc                   	int3
  266dd6:	cc                   	int3
  266dd7:	cc                   	int3
  266dd8:	e9 83 92 f8 ff       	jmp    0x1f0060
  266ddd:	cc                   	int3
  266dde:	cc                   	int3
  266ddf:	cc                   	int3
  266de0:	e9 cb 4b eb ff       	jmp    0x11b9b0
  266de5:	cc                   	int3
  266de6:	cc                   	int3
  266de7:	cc                   	int3
  266de8:	e9 43 43 8d 00       	jmp    0xb3b130
  266ded:	cc                   	int3
  266dee:	cc                   	int3
  266def:	cc                   	int3
  266df0:	e9 4b 0c 8e 00       	jmp    0xb47a40
  266df5:	cc                   	int3
  266df6:	cc                   	int3
  266df7:	cc                   	int3
  266df8:	e9 c3 95 8e 00       	jmp    0xb503c0
  266dfd:	cc                   	int3
  266dfe:	cc                   	int3
  266dff:	cc                   	int3
  266e00:	e9 0b a1 8e 00       	jmp    0xb50f10
  266e05:	cc                   	int3
  266e06:	cc                   	int3
  266e07:	cc                   	int3
  266e08:	e9 a3 a1 8e 00       	jmp    0xb50fb0
  266e0d:	cc                   	int3
  266e0e:	cc                   	int3
  266e0f:	cc                   	int3
  266e10:	e9 9b a2 8e 00       	jmp    0xb510b0
  266e15:	cc                   	int3
  266e16:	cc                   	int3
  266e17:	cc                   	int3
  266e18:	e9 73 a3 8e 00       	jmp    0xb51190
  266e1d:	cc                   	int3
  266e1e:	cc                   	int3
  266e1f:	cc                   	int3
  266e20:	e9 6b a4 8e 00       	jmp    0xb51290
  266e25:	cc                   	int3
  266e26:	cc                   	int3
  266e27:	cc                   	int3
  266e28:	e9 a3 a4 8e 00       	jmp    0xb512d0
  266e2d:	cc                   	int3
  266e2e:	cc                   	int3
  266e2f:	cc                   	int3
  266e30:	e9 eb a4 8e 00       	jmp    0xb51320
  266e35:	cc                   	int3
  266e36:	cc                   	int3
  266e37:	cc                   	int3
  266e38:	e9 63 fa 8e 00       	jmp    0xb568a0
  266e3d:	cc                   	int3
  266e3e:	cc                   	int3
  266e3f:	cc                   	int3
  266e40:	e9 9b 32 e3 ff       	jmp    0x9a0e0
  266e45:	cc                   	int3
  266e46:	cc                   	int3
  266e47:	cc                   	int3
  266e48:	e9 23 40 90 00       	jmp    0xb6ae70
  266e4d:	cc                   	int3
  266e4e:	cc                   	int3
  266e4f:	cc                   	int3
  266e50:	e9 3b 4d 90 00       	jmp    0xb6bb90
  266e55:	cc                   	int3
  266e56:	cc                   	int3
  266e57:	cc                   	int3
  266e58:	e9 23 6b 90 00       	jmp    0xb6d980
  266e5d:	cc                   	int3
  266e5e:	cc                   	int3
  266e5f:	cc                   	int3
  266e60:	e9 3b 6c 90 00       	jmp    0xb6daa0
  266e65:	cc                   	int3
  266e66:	cc                   	int3
  266e67:	cc                   	int3
  266e68:	e9 13 73 90 00       	jmp    0xb6e180
  266e6d:	cc                   	int3
  266e6e:	cc                   	int3
  266e6f:	cc                   	int3
  266e70:	e9 ab a4 90 00       	jmp    0xb71320
  266e75:	cc                   	int3
  266e76:	cc                   	int3
  266e77:	cc                   	int3
  266e78:	e9 f3 a4 90 00       	jmp    0xb71370
  266e7d:	cc                   	int3
  266e7e:	cc                   	int3
  266e7f:	cc                   	int3
  266e80:	e9 3b a5 90 00       	jmp    0xb713c0
  266e85:	cc                   	int3
  266e86:	cc                   	int3
  266e87:	cc                   	int3
  266e88:	e9 83 a5 90 00       	jmp    0xb71410
  266e8d:	cc                   	int3
  266e8e:	cc                   	int3
  266e8f:	cc                   	int3
  266e90:	e9 cb aa 90 00       	jmp    0xb71960
  266e95:	cc                   	int3
  266e96:	cc                   	int3
  266e97:	cc                   	int3
  266e98:	e9 33 ab 90 00       	jmp    0xb719d0
  266e9d:	cc                   	int3
  266e9e:	cc                   	int3
  266e9f:	cc                   	int3
  266ea0:	e9 9b ab 90 00       	jmp    0xb71a40
  266ea5:	cc                   	int3
  266ea6:	cc                   	int3
  266ea7:	cc                   	int3
  266ea8:	e9 03 ac 90 00       	jmp    0xb71ab0
  266ead:	cc                   	int3
  266eae:	cc                   	int3
  266eaf:	cc                   	int3
  266eb0:	e9 6b b7 90 00       	jmp    0xb72620
  266eb5:	cc                   	int3
  266eb6:	cc                   	int3
  266eb7:	cc                   	int3
  266eb8:	e9 a3 b9 90 00       	jmp    0xb72860
  266ebd:	cc                   	int3
  266ebe:	cc                   	int3
  266ebf:	cc                   	int3
  266ec0:	e9 0b 23 91 00       	jmp    0xb791d0
  266ec5:	cc                   	int3
  266ec6:	cc                   	int3
  266ec7:	cc                   	int3
  266ec8:	e9 c3 23 91 00       	jmp    0xb79290
  266ecd:	cc                   	int3
  266ece:	cc                   	int3
  266ecf:	cc                   	int3
  266ed0:	e9 1b 25 91 00       	jmp    0xb793f0
  266ed5:	cc                   	int3
  266ed6:	cc                   	int3
  266ed7:	cc                   	int3
  266ed8:	e9 43 25 91 00       	jmp    0xb79420
  266edd:	cc                   	int3
  266ede:	cc                   	int3
  266edf:	cc                   	int3
  266ee0:	e9 7b 25 91 00       	jmp    0xb79460
  266ee5:	cc                   	int3
  266ee6:	cc                   	int3
  266ee7:	cc                   	int3
  266ee8:	e9 93 25 91 00       	jmp    0xb79480
  266eed:	cc                   	int3
  266eee:	cc                   	int3
  266eef:	cc                   	int3
  266ef0:	e9 9b 25 91 00       	jmp    0xb79490
  266ef5:	cc                   	int3
  266ef6:	cc                   	int3
  266ef7:	cc                   	int3
  266ef8:	e9 b3 25 91 00       	jmp    0xb794b0
  266efd:	cc                   	int3
  266efe:	cc                   	int3
  266eff:	cc                   	int3
  266f00:	e9 eb 26 91 00       	jmp    0xb795f0
  266f05:	cc                   	int3
  266f06:	cc                   	int3
  266f07:	cc                   	int3
  266f08:	e9 13 27 91 00       	jmp    0xb79620
  266f0d:	cc                   	int3
  266f0e:	cc                   	int3
  266f0f:	cc                   	int3
  266f10:	e9 1b 29 91 00       	jmp    0xb79830
  266f15:	cc                   	int3
  266f16:	cc                   	int3
  266f17:	cc                   	int3
  266f18:	e9 73 9f 91 00       	jmp    0xb80e90
  266f1d:	cc                   	int3
  266f1e:	cc                   	int3
  266f1f:	cc                   	int3
  266f20:	e9 fb 9f 91 00       	jmp    0xb80f20
  266f25:	cc                   	int3
  266f26:	cc                   	int3
  266f27:	cc                   	int3
  266f28:	e9 f3 25 93 00       	jmp    0xb99520
  266f2d:	cc                   	int3
  266f2e:	cc                   	int3
  266f2f:	cc                   	int3
  266f30:	e9 cb 26 93 00       	jmp    0xb99600
  266f35:	cc                   	int3
  266f36:	cc                   	int3
  266f37:	cc                   	int3
  266f38:	e9 f3 5e 93 00       	jmp    0xb9ce30
  266f3d:	cc                   	int3
  266f3e:	cc                   	int3
  266f3f:	cc                   	int3
  266f40:	e9 fb ec 98 00       	jmp    0xbf5c40
  266f45:	cc                   	int3
  266f46:	cc                   	int3
  266f47:	cc                   	int3
  266f48:	e9 d3 76 99 00       	jmp    0xbfe620
  266f4d:	cc                   	int3
  266f4e:	cc                   	int3
  266f4f:	cc                   	int3
  266f50:	e9 fb 7f 99 00       	jmp    0xbfef50
  266f55:	cc                   	int3
  266f56:	cc                   	int3
  266f57:	cc                   	int3
  266f58:	e9 43 80 99 00       	jmp    0xbfefa0
  266f5d:	cc                   	int3
  266f5e:	cc                   	int3
  266f5f:	cc                   	int3
  266f60:	e9 eb 80 99 00       	jmp    0xbff050
  266f65:	cc                   	int3
  266f66:	cc                   	int3
  266f67:	cc                   	int3
  266f68:	e9 13 62 9a 00       	jmp    0xc0d180
  266f6d:	cc                   	int3
  266f6e:	cc                   	int3
  266f6f:	cc                   	int3
  266f70:	e9 7b b8 9c 00       	jmp    0xc327f0
  266f75:	cc                   	int3
  266f76:	cc                   	int3
  266f77:	cc                   	int3
