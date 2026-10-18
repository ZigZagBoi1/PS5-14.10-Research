; Handler 667: REA6.7.0 / Ghidra12.1.4 static function-aware assembly.
; All addresses are kernel RVAs; runtime VA = 0xffffffff8a9c0000 + RVA.
; Original 4096-byte input SHA256 76916c6277404292f362d87da356811c8f660568d17f97536b15041696d3b53d.
; Actual target RVA 0x4a31a0; adjacent recovered functions are context.

; ===== REA full original-window trampoline functions and verified padding =====
; COMPLETE ORIGINAL INPUT WINDOW: handler_667.bin, 4096 bytes
; SHA256 76916c6277404292f362d87da356811c8f660568d17f97536b15041696d3b53d; file offset zero = kernel RVA 0x265f88.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0x0 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0x8 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0x10 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x18 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x20 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x28 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x30 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x38 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x40 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x48 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x50 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x58 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0x60 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0x68 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0x70 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0x78 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0x80 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0x88 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0x90 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0x98 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0xa0 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0xa8 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0xb0 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0xb8 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0xc0 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0xc8 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0xd0 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0xd8 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0xe0 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0xe8 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0xf0 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0xf8 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0x100 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0x108 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0x110 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0x118 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x120 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x128 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x130 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x138 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x140 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x148 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x150 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x158 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x160 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x168 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x170 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x178 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0x180 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0x188 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0x190 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0x198 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0x1a0 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0x1a8 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0x1b0 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0x1b8 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0x1c0 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0x1c8 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0x1d0 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0x1d8 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0x1e0 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0x1e8 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0x1f0 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0x1f8 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0x200 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0x208 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0x210 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0x218 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0x220 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0x228 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0x230 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0x238 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0x240 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0x248 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0x250 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0x258 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0x260 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0x268 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0x270 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0x278 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0x280 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0x288 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0x290 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0x298 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0x2a0 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0x2a8 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0x2b0 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0x2b8 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0x2c0 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0x2c8 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0x2d0 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0x2d8 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0x2e0 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0x2e8 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0x2f0 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0x2f8 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0x300 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0x308 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0x310 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0x318 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0x320 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0x328 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0x330 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0x338 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0x340 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0x348 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0x350 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0x358 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0x360 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0x368 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0x370 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0x378 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0x380 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0x388 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0x390 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0x398 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0x3a0 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0x3a8 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0x3b0 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0x3b8 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0x3c0 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0x3c8 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0x3d0 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0x3d8 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0x3e0 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0x3e8 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0x3f0 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0x3f8 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0x400 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0x408 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0x410 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0x418 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0x420 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0x428 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0x430 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0x438 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0x440 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0x448 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0x450 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0x458 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0x460 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0x468 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0x470 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0x478 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0x480 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0x488 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0x490 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0x498 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0x4a0 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0x4a8 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0x4b0 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0x4b8 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0x4c0 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0x4c8 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0x4d0 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0x4d8 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0x4e0 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0x4e8 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0x4f0 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0x4f8 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0x500 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0x508 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0x510 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0x518 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0x520 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0x528 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0x530 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0x538 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0x540 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0x548 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0x550 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0x558 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0x560 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0x568 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0x570 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0x578 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0x580 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0x588 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0x590 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0x598 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0x5a0 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0x5a8 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0x5b0 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0x5b8 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0x5c0 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0x5c8 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0x5d0 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0x5d8 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0x5e0 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0x5e8 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0x5f0 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0x5f8 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0x600 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0x608 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0x610 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0x618 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0x620 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0x628 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0x630 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0x638 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0x640 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0x648 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0x650 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0x658 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0x660 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0x668 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0x670 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0x678 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0x680 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0x688 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0x690 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0x698 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0x6a0 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0x6a8 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0x6b0 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0x6b8 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0x6c0 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0x6c8 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0x6d0 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0x6d8 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0x6e0 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0x6e8 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0x6f0 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0x6f8 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0x700 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0x708 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0x710 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0x718 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0x720 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0x728 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0x730 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0x738 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0x740 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0x748 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0x750 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0x758 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0x760 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0x768 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0x770 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0x778 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding

; FUNCTION thunk_266708 [0x266708, 0x26670c] | file +0x780 | ev_a1b1ecfb69ddcde3ab328e54879b2647bb27553f41929ae5021b46edd03a8fd6
thunk_266708:
0x266708: JMP 0x00ca7310
; END FUNCTION thunk_266708
0x26670d: INT3 ; original byte CC, padding
0x26670e: INT3 ; original byte CC, padding
0x26670f: INT3 ; original byte CC, padding

; FUNCTION thunk_266710 [0x266710, 0x266714] | file +0x788 | ev_91a5d5c52dbb1d6be7f635bc2e634aa41a9d00a7b8b5d2ae096ecbfdcbfa2641
thunk_266710:
0x266710: JMP 0x00662e70
; END FUNCTION thunk_266710
0x266715: INT3 ; original byte CC, padding
0x266716: INT3 ; original byte CC, padding
0x266717: INT3 ; original byte CC, padding

; FUNCTION thunk_266718 [0x266718, 0x26671c] | file +0x790 | ev_5d49490e833cb75f11ae327b52e57d63c8562abf36102eae069cd3b6103363e9
thunk_266718:
0x266718: JMP 0x00662e80
; END FUNCTION thunk_266718
0x26671d: INT3 ; original byte CC, padding
0x26671e: INT3 ; original byte CC, padding
0x26671f: INT3 ; original byte CC, padding

; FUNCTION thunk_266720 [0x266720, 0x266724] | file +0x798 | ev_1dbafec98e5478d51b8103829bfa1a72f4bc438e9f77ede71f00176b6c65fa7a
thunk_266720:
0x266720: JMP 0x00678e10
; END FUNCTION thunk_266720
0x266725: INT3 ; original byte CC, padding
0x266726: INT3 ; original byte CC, padding
0x266727: INT3 ; original byte CC, padding

; FUNCTION thunk_266728 [0x266728, 0x26672c] | file +0x7a0 | ev_38fac9adf6535b05ba585c6e1016cc470c98cfb56fa25e1502404b81f2326987
thunk_266728:
0x266728: JMP 0x00678e60
; END FUNCTION thunk_266728
0x26672d: INT3 ; original byte CC, padding
0x26672e: INT3 ; original byte CC, padding
0x26672f: INT3 ; original byte CC, padding

; FUNCTION thunk_266730 [0x266730, 0x266734] | file +0x7a8 | ev_890d87fa71c13e41992835bde9ad1d367d67a4a8cd4b5428bd46706c8a2a3c01
thunk_266730:
0x266730: JMP 0x00678ec0
; END FUNCTION thunk_266730
0x266735: INT3 ; original byte CC, padding
0x266736: INT3 ; original byte CC, padding
0x266737: INT3 ; original byte CC, padding

; FUNCTION thunk_266738 [0x266738, 0x26673c] | file +0x7b0 | ev_aa0a18be2618fe163ef3124d4793e4ee4faac93cc616ec748a395327ab897d78
thunk_266738:
0x266738: JMP 0x00678f60
; END FUNCTION thunk_266738
0x26673d: INT3 ; original byte CC, padding
0x26673e: INT3 ; original byte CC, padding
0x26673f: INT3 ; original byte CC, padding

; FUNCTION thunk_266740 [0x266740, 0x266744] | file +0x7b8 | ev_b940e85d2293130cc12912d0f406f051de5e7b6c738a54b3296b9ad18e7da334
thunk_266740:
0x266740: JMP 0x00679190
; END FUNCTION thunk_266740
0x266745: INT3 ; original byte CC, padding
0x266746: INT3 ; original byte CC, padding
0x266747: INT3 ; original byte CC, padding

; FUNCTION thunk_266748 [0x266748, 0x26674c] | file +0x7c0 | ev_2d90ddd75a522af0bb29971ceb6fb5ba61df5fe33fe120ca3b3e5d7785d2fb67
thunk_266748:
0x266748: JMP 0x00679360
; END FUNCTION thunk_266748
0x26674d: INT3 ; original byte CC, padding
0x26674e: INT3 ; original byte CC, padding
0x26674f: INT3 ; original byte CC, padding

; FUNCTION thunk_266750 [0x266750, 0x266754] | file +0x7c8 | ev_01b9ec000cc30925ba3559e6be67c9cb23e822ed3521b44b10cf40b142115d81
thunk_266750:
0x266750: JMP 0x00679680
; END FUNCTION thunk_266750
0x266755: INT3 ; original byte CC, padding
0x266756: INT3 ; original byte CC, padding
0x266757: INT3 ; original byte CC, padding

; FUNCTION thunk_266758 [0x266758, 0x26675c] | file +0x7d0 | ev_d990bd8c7113bb7f5350f7d2dd0da9a70e1e61ae3bdc2023b324d40d54fd0556
thunk_266758:
0x266758: JMP 0x00033b90
; END FUNCTION thunk_266758
0x26675d: INT3 ; original byte CC, padding
0x26675e: INT3 ; original byte CC, padding
0x26675f: INT3 ; original byte CC, padding

; FUNCTION thunk_266760 [0x266760, 0x266764] | file +0x7d8 | ev_9c2f05162ca519881e4051f776fb4d5698dc9a1dbb6d322ee6281af4ba5e8feb
thunk_266760:
0x266760: JMP 0x00033ca0
; END FUNCTION thunk_266760
0x266765: INT3 ; original byte CC, padding
0x266766: INT3 ; original byte CC, padding
0x266767: INT3 ; original byte CC, padding

; FUNCTION thunk_266768 [0x266768, 0x26676c] | file +0x7e0 | ev_8a1b5cf7031b91c6ae6c5ebe0fffd22f6fa2246fe2869a1a78fd5b400a6b359e
thunk_266768:
0x266768: JMP 0x00033d20
; END FUNCTION thunk_266768
0x26676d: INT3 ; original byte CC, padding
0x26676e: INT3 ; original byte CC, padding
0x26676f: INT3 ; original byte CC, padding

; FUNCTION thunk_266770 [0x266770, 0x266774] | file +0x7e8 | ev_1f25b3b15b6f767ce17fc6cd00f20709a3a70504cb1eab6250b3a9d8f5df543a
thunk_266770:
0x266770: JMP 0x0003cf70
; END FUNCTION thunk_266770
0x266775: INT3 ; original byte CC, padding
0x266776: INT3 ; original byte CC, padding
0x266777: INT3 ; original byte CC, padding

; FUNCTION thunk_266778 [0x266778, 0x26677c] | file +0x7f0 | ev_1abd2480771bd0dfc44ad78a0ad8b9e76496fd5a3103f04dbfb5001838054042
thunk_266778:
0x266778: JMP 0x0003d0e0
; END FUNCTION thunk_266778
0x26677d: INT3 ; original byte CC, padding
0x26677e: INT3 ; original byte CC, padding
0x26677f: INT3 ; original byte CC, padding

; FUNCTION thunk_266780 [0x266780, 0x266784] | file +0x7f8 | ev_c505cc9a86f7ae4149f1e64b36bc59f5f40aa963623ba2974583c5d3e37dcf6c
thunk_266780:
0x266780: JMP 0x0003d660
; END FUNCTION thunk_266780
0x266785: INT3 ; original byte CC, padding
0x266786: INT3 ; original byte CC, padding
0x266787: INT3 ; original byte CC, padding

; FUNCTION thunk_266788 [0x266788, 0x26678c] | file +0x800 | ev_9ed81726a9363e9abf06ebf384044590c774b49373b1aff9cce434caec79de73
thunk_266788:
0x266788: JMP 0x0003e100
; END FUNCTION thunk_266788
0x26678d: INT3 ; original byte CC, padding
0x26678e: INT3 ; original byte CC, padding
0x26678f: INT3 ; original byte CC, padding

; FUNCTION thunk_266790 [0x266790, 0x266794] | file +0x808 | ev_b6d70feab26a69b46d1e60bf65b7ac8ff9e8af0f14e58083f5ca2104e00b4a77
thunk_266790:
0x266790: JMP 0x0003e160
; END FUNCTION thunk_266790
0x266795: INT3 ; original byte CC, padding
0x266796: INT3 ; original byte CC, padding
0x266797: INT3 ; original byte CC, padding

; FUNCTION thunk_266798 [0x266798, 0x26679c] | file +0x810 | ev_3a4fe1aed4181c9b36fc2d107277e19a007843c58dbc34a1b90c6b5364c25a1f
thunk_266798:
0x266798: JMP 0x0003e1c0
; END FUNCTION thunk_266798
0x26679d: INT3 ; original byte CC, padding
0x26679e: INT3 ; original byte CC, padding
0x26679f: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a0 [0x2667a0, 0x2667a4] | file +0x818 | ev_4e9ef9ebcbe1c81642627453beab0cf815cbe6b323c761944902a2e3a594e35e
thunk_2667a0:
0x2667a0: JMP 0x0003f070
; END FUNCTION thunk_2667a0
0x2667a5: INT3 ; original byte CC, padding
0x2667a6: INT3 ; original byte CC, padding
0x2667a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a8 [0x2667a8, 0x2667ac] | file +0x820 | ev_1e8d18696b5a66f44717599dfe66fa3f5647bfd731e90f4213ba0fb583230b36
thunk_2667a8:
0x2667a8: JMP 0x0003f0d0
; END FUNCTION thunk_2667a8
0x2667ad: INT3 ; original byte CC, padding
0x2667ae: INT3 ; original byte CC, padding
0x2667af: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b0 [0x2667b0, 0x2667b4] | file +0x828 | ev_694c8a603d68e5c334d648ccab1a33dedcffe9fe58ccd66f93a0e0e9f55a0532
thunk_2667b0:
0x2667b0: JMP 0x0003f4b0
; END FUNCTION thunk_2667b0
0x2667b5: INT3 ; original byte CC, padding
0x2667b6: INT3 ; original byte CC, padding
0x2667b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b8 [0x2667b8, 0x2667bc] | file +0x830 | ev_a433f0ca544c9e14c9ccf44b4ee4f0234100e7f292134e31ff932a3f92aa68ce
thunk_2667b8:
0x2667b8: JMP 0x0003f510
; END FUNCTION thunk_2667b8
0x2667bd: INT3 ; original byte CC, padding
0x2667be: INT3 ; original byte CC, padding
0x2667bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c0 [0x2667c0, 0x2667c4] | file +0x838 | ev_bea5624da2f134f28923630943d28c30f396fee0e2b4c2add7748798a411e200
thunk_2667c0:
0x2667c0: JMP 0x0003f570
; END FUNCTION thunk_2667c0
0x2667c5: INT3 ; original byte CC, padding
0x2667c6: INT3 ; original byte CC, padding
0x2667c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c8 [0x2667c8, 0x2667cc] | file +0x840 | ev_873e539dd587ac5fcd71faab8b5f3475b0c0c95679ce352316e553e65785df80
thunk_2667c8:
0x2667c8: JMP 0x0003fbb0
; END FUNCTION thunk_2667c8
0x2667cd: INT3 ; original byte CC, padding
0x2667ce: INT3 ; original byte CC, padding
0x2667cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d0 [0x2667d0, 0x2667d4] | file +0x848 | ev_d081b0d8d4dc0ccacf69699e5595f0544f500d0276055e7bf09413150e1224dd
thunk_2667d0:
0x2667d0: JMP 0x0003ffc0
; END FUNCTION thunk_2667d0
0x2667d5: INT3 ; original byte CC, padding
0x2667d6: INT3 ; original byte CC, padding
0x2667d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d8 [0x2667d8, 0x2667dc] | file +0x850 | ev_96e92b8e3e99b79413f154cc9eb3d60a8a7d646aa4515fb8fb5de63dd6d7c917
thunk_2667d8:
0x2667d8: JMP 0x00040960
; END FUNCTION thunk_2667d8
0x2667dd: INT3 ; original byte CC, padding
0x2667de: INT3 ; original byte CC, padding
0x2667df: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e0 [0x2667e0, 0x2667e4] | file +0x858 | ev_a1b1802795532978974ffc776896ea0d7761845d22797ef90473038e62d47faa
thunk_2667e0:
0x2667e0: JMP 0x00040b50
; END FUNCTION thunk_2667e0
0x2667e5: INT3 ; original byte CC, padding
0x2667e6: INT3 ; original byte CC, padding
0x2667e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e8 [0x2667e8, 0x2667ec] | file +0x860 | ev_83007fa2af45028f40282ddb2608364e94f80e2ce94687cd3f80e2b37d9e04ae
thunk_2667e8:
0x2667e8: JMP 0x00040c30
; END FUNCTION thunk_2667e8
0x2667ed: INT3 ; original byte CC, padding
0x2667ee: INT3 ; original byte CC, padding
0x2667ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f0 [0x2667f0, 0x2667f4] | file +0x868 | ev_2caf01d6b7d2a840a5c899ea1ade478a1167a6d2432c06185f6657a466a24521
thunk_2667f0:
0x2667f0: JMP 0x00041630
; END FUNCTION thunk_2667f0
0x2667f5: INT3 ; original byte CC, padding
0x2667f6: INT3 ; original byte CC, padding
0x2667f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f8 [0x2667f8, 0x2667fc] | file +0x870 | ev_2e9a02026a32f4d3595a1c8ea3741317c463c48293ad9967d64bb0c842c16bcf
thunk_2667f8:
0x2667f8: JMP 0x00041750
; END FUNCTION thunk_2667f8
0x2667fd: INT3 ; original byte CC, padding
0x2667fe: INT3 ; original byte CC, padding
0x2667ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266800 [0x266800, 0x266804] | file +0x878 | ev_b5a4bcb1d6c941a3f6d70e0062d3c0463382b61c6d39e75f8ad4575154058329
thunk_266800:
0x266800: JMP 0x00041830
; END FUNCTION thunk_266800
0x266805: INT3 ; original byte CC, padding
0x266806: INT3 ; original byte CC, padding
0x266807: INT3 ; original byte CC, padding

; FUNCTION thunk_266808 [0x266808, 0x26680c] | file +0x880 | ev_f1b081b3b9ac7495b8be40ee086537bb185a297b65b7ef087083c600fbb85b61
thunk_266808:
0x266808: JMP 0x000418c0
; END FUNCTION thunk_266808
0x26680d: INT3 ; original byte CC, padding
0x26680e: INT3 ; original byte CC, padding
0x26680f: INT3 ; original byte CC, padding

; FUNCTION thunk_266810 [0x266810, 0x266814] | file +0x888 | ev_286fd1ef6a141f6a83604ef9198646a69f86d2b579ec17a23ae6cebb467e5061
thunk_266810:
0x266810: JMP 0x00042060
; END FUNCTION thunk_266810
0x266815: INT3 ; original byte CC, padding
0x266816: INT3 ; original byte CC, padding
0x266817: INT3 ; original byte CC, padding

; FUNCTION thunk_266818 [0x266818, 0x26681c] | file +0x890 | ev_47935a2775d41df4f9b4c5a7174f7ec66edf37c497c637165652e966d455c6c2
thunk_266818:
0x266818: JMP 0x000424d0
; END FUNCTION thunk_266818
0x26681d: INT3 ; original byte CC, padding
0x26681e: INT3 ; original byte CC, padding
0x26681f: INT3 ; original byte CC, padding

; FUNCTION thunk_266820 [0x266820, 0x266824] | file +0x898 | ev_ec6ae96b47da7790af52eef03b6d449d9601b42b60ff5781510b83d5eed62146
thunk_266820:
0x266820: JMP 0x000425a0
; END FUNCTION thunk_266820
0x266825: INT3 ; original byte CC, padding
0x266826: INT3 ; original byte CC, padding
0x266827: INT3 ; original byte CC, padding

; FUNCTION thunk_266828 [0x266828, 0x26682c] | file +0x8a0 | ev_62e5f7ba42bcfbb4e746143fb9a9e26ec7bd4a12c0fbf516331bb1dba6d35663
thunk_266828:
0x266828: JMP 0x00042600
; END FUNCTION thunk_266828
0x26682d: INT3 ; original byte CC, padding
0x26682e: INT3 ; original byte CC, padding
0x26682f: INT3 ; original byte CC, padding

; FUNCTION thunk_266830 [0x266830, 0x266834] | file +0x8a8 | ev_5adad97b5e16134fb3c507782f4939f93bf7446e42819870836ccff91d30b7eb
thunk_266830:
0x266830: JMP 0x00690030
; END FUNCTION thunk_266830
0x266835: INT3 ; original byte CC, padding
0x266836: INT3 ; original byte CC, padding
0x266837: INT3 ; original byte CC, padding

; FUNCTION thunk_266838 [0x266838, 0x26683c] | file +0x8b0 | ev_816d78169618a36f8b32f4a02e164b67743d4a889459642185f582989c4af5e2
thunk_266838:
0x266838: JMP 0x00696cc0
; END FUNCTION thunk_266838
0x26683d: INT3 ; original byte CC, padding
0x26683e: INT3 ; original byte CC, padding
0x26683f: INT3 ; original byte CC, padding

; FUNCTION thunk_266840 [0x266840, 0x266844] | file +0x8b8 | ev_ac0488f3239f358372c3fe2efa4f19fad41d472d5150f8744654236f12971a58
thunk_266840:
0x266840: JMP 0x006985d0
; END FUNCTION thunk_266840
0x266845: INT3 ; original byte CC, padding
0x266846: INT3 ; original byte CC, padding
0x266847: INT3 ; original byte CC, padding

; FUNCTION thunk_266848 [0x266848, 0x26684c] | file +0x8c0 | ev_93973c149c06bf5ab4e689d9c5e3a621a45fdb016a490bd5f873537571699dde
thunk_266848:
0x266848: JMP 0x006a2050
; END FUNCTION thunk_266848
0x26684d: INT3 ; original byte CC, padding
0x26684e: INT3 ; original byte CC, padding
0x26684f: INT3 ; original byte CC, padding

; FUNCTION thunk_266850 [0x266850, 0x266854] | file +0x8c8 | ev_0384ec62f16c1b55f37f6e139cd5b347f936b71ac6d322c07912104d15839704
thunk_266850:
0x266850: JMP 0x006a22b0
; END FUNCTION thunk_266850
0x266855: INT3 ; original byte CC, padding
0x266856: INT3 ; original byte CC, padding
0x266857: INT3 ; original byte CC, padding

; FUNCTION thunk_266858 [0x266858, 0x26685c] | file +0x8d0 | ev_df166f83af68846c8787a22b60db92858c5297f11c0e5021462d71dc3a774fa4
thunk_266858:
0x266858: JMP 0x006ae640
; END FUNCTION thunk_266858
0x26685d: INT3 ; original byte CC, padding
0x26685e: INT3 ; original byte CC, padding
0x26685f: INT3 ; original byte CC, padding

; FUNCTION thunk_266860 [0x266860, 0x266864] | file +0x8d8 | ev_0fdd27d74cd24b4f8db75581de4388713e3597d065d3842c8af4f054c455ff46
thunk_266860:
0x266860: JMP 0x006ae7f0
; END FUNCTION thunk_266860
0x266865: INT3 ; original byte CC, padding
0x266866: INT3 ; original byte CC, padding
0x266867: INT3 ; original byte CC, padding

; FUNCTION thunk_266868 [0x266868, 0x26686c] | file +0x8e0 | ev_fc62fcbabf14463ab5445229b64c21674fbb7a0e14b7c8d18f89f180b63d1a35
thunk_266868:
0x266868: JMP 0x001813b0
; END FUNCTION thunk_266868
0x26686d: INT3 ; original byte CC, padding
0x26686e: INT3 ; original byte CC, padding
0x26686f: INT3 ; original byte CC, padding

; FUNCTION thunk_266870 [0x266870, 0x266874] | file +0x8e8 | ev_e2d4aad35945259cea115215ff1ab977a4b05020f234b4e2d5529ecfaf679d6c
thunk_266870:
0x266870: JMP 0x006befa0
; END FUNCTION thunk_266870
0x266875: INT3 ; original byte CC, padding
0x266876: INT3 ; original byte CC, padding
0x266877: INT3 ; original byte CC, padding

; FUNCTION thunk_266878 [0x266878, 0x26687c] | file +0x8f0 | ev_a3fad9735b44d843a7b2df48591f3fdd19bcad9229cd6cc9fa12ae57295fafdb
thunk_266878:
0x266878: JMP 0x00188040
; END FUNCTION thunk_266878
0x26687d: INT3 ; original byte CC, padding
0x26687e: INT3 ; original byte CC, padding
0x26687f: INT3 ; original byte CC, padding

; FUNCTION thunk_266880 [0x266880, 0x266884] | file +0x8f8 | ev_cb5c5a617a74303d22c2870604c190a2c74691cea1254e2590feb42cebc14908
thunk_266880:
0x266880: JMP 0x006d0b00
; END FUNCTION thunk_266880
0x266885: INT3 ; original byte CC, padding
0x266886: INT3 ; original byte CC, padding
0x266887: INT3 ; original byte CC, padding

; FUNCTION thunk_266888 [0x266888, 0x26688c] | file +0x900 | ev_0c3c38a29d01d8bdd25da4829b302df5d6745d42fe41808735ca9a72b6b3ecc5
thunk_266888:
0x266888: JMP 0x006d1100
; END FUNCTION thunk_266888
0x26688d: INT3 ; original byte CC, padding
0x26688e: INT3 ; original byte CC, padding
0x26688f: INT3 ; original byte CC, padding

; FUNCTION thunk_266890 [0x266890, 0x266894] | file +0x908 | ev_6b973f5fb069a1d3cbe8d7d4aabeb6bcee863c0240424f8a6914cece654d8dc4
thunk_266890:
0x266890: JMP 0x006d1260
; END FUNCTION thunk_266890
0x266895: INT3 ; original byte CC, padding
0x266896: INT3 ; original byte CC, padding
0x266897: INT3 ; original byte CC, padding

; FUNCTION thunk_266898 [0x266898, 0x26689c] | file +0x910 | ev_8b28ef61b7456567df4642cc9116b8671bba7aa5b95ff4372db799c6ba25dc2d
thunk_266898:
0x266898: JMP 0x006d13e0
; END FUNCTION thunk_266898
0x26689d: INT3 ; original byte CC, padding
0x26689e: INT3 ; original byte CC, padding
0x26689f: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a0 [0x2668a0, 0x2668a4] | file +0x918 | ev_fa00b3d0152f45a894b8ec075f6bf10efe75850a819b491d29e92959b6b8731f
thunk_2668a0:
0x2668a0: JMP 0x006d1520
; END FUNCTION thunk_2668a0
0x2668a5: INT3 ; original byte CC, padding
0x2668a6: INT3 ; original byte CC, padding
0x2668a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a8 [0x2668a8, 0x2668ac] | file +0x920 | ev_d78f08e03b31ffa2b2efe42a6cfb4536afb928a6c7f119a024a22b05f40899ff
thunk_2668a8:
0x2668a8: JMP 0x006d1640
; END FUNCTION thunk_2668a8
0x2668ad: INT3 ; original byte CC, padding
0x2668ae: INT3 ; original byte CC, padding
0x2668af: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b0 [0x2668b0, 0x2668b4] | file +0x928 | ev_3ed67d6c97c92967a395908a8a040edb330be148f28e2c64059b679195b59eae
thunk_2668b0:
0x2668b0: JMP 0x006d1720
; END FUNCTION thunk_2668b0
0x2668b5: INT3 ; original byte CC, padding
0x2668b6: INT3 ; original byte CC, padding
0x2668b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b8 [0x2668b8, 0x2668bc] | file +0x930 | ev_de93f54afb23cbd9b4b3762b6edbec96ba6addd3a7c90c972215bce85e5605f8
thunk_2668b8:
0x2668b8: JMP 0x006dc660
; END FUNCTION thunk_2668b8
0x2668bd: INT3 ; original byte CC, padding
0x2668be: INT3 ; original byte CC, padding
0x2668bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c0 [0x2668c0, 0x2668c4] | file +0x938 | ev_3e530c546d978a4cde1ea40098241ece409f40b0be36a2293bc70eb3a70892d2
thunk_2668c0:
0x2668c0: JMP 0x006dc690
; END FUNCTION thunk_2668c0
0x2668c5: INT3 ; original byte CC, padding
0x2668c6: INT3 ; original byte CC, padding
0x2668c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c8 [0x2668c8, 0x2668cc] | file +0x940 | ev_4029b49e23f105d9fd959b8d0e79ee611fff70d5deb5b25c1ec32f063cdbf7d2
thunk_2668c8:
0x2668c8: JMP 0x006dc6a0
; END FUNCTION thunk_2668c8
0x2668cd: INT3 ; original byte CC, padding
0x2668ce: INT3 ; original byte CC, padding
0x2668cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d0 [0x2668d0, 0x2668d4] | file +0x948 | ev_28820dcd9e75794b371215f8085c8fc2e919e52036eb5b329b5618bbecaa8502
thunk_2668d0:
0x2668d0: JMP 0x006e0920
; END FUNCTION thunk_2668d0
0x2668d5: INT3 ; original byte CC, padding
0x2668d6: INT3 ; original byte CC, padding
0x2668d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d8 [0x2668d8, 0x2668dc] | file +0x950 | ev_48d27fa99d4bfbfd01b9c0cfc4e1983ac381df090d15929fd844727932ef39f8
thunk_2668d8:
0x2668d8: JMP 0x006e1440
; END FUNCTION thunk_2668d8
0x2668dd: INT3 ; original byte CC, padding
0x2668de: INT3 ; original byte CC, padding
0x2668df: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e0 [0x2668e0, 0x2668e4] | file +0x958 | ev_7aa82add6e61823b6e8626df3d716de65e3fdba037ff334b9a282990cc834fcc
thunk_2668e0:
0x2668e0: JMP 0x006e1450
; END FUNCTION thunk_2668e0
0x2668e5: INT3 ; original byte CC, padding
0x2668e6: INT3 ; original byte CC, padding
0x2668e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e8 [0x2668e8, 0x2668ec] | file +0x960 | ev_7366c86f363f041f011d7a626d3635808a0a7efc1961a826359904110403c080
thunk_2668e8:
0x2668e8: JMP 0x00189a70
; END FUNCTION thunk_2668e8
0x2668ed: INT3 ; original byte CC, padding
0x2668ee: INT3 ; original byte CC, padding
0x2668ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f0 [0x2668f0, 0x2668f4] | file +0x968 | ev_d35c35a0ef27616e2538e5e78e8eb0d78e896dedfca6d619b3ac2c0ce3a0f144
thunk_2668f0:
0x2668f0: JMP 0x00190aa0
; END FUNCTION thunk_2668f0
0x2668f5: INT3 ; original byte CC, padding
0x2668f6: INT3 ; original byte CC, padding
0x2668f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f8 [0x2668f8, 0x2668fc] | file +0x970 | ev_285a07576ea147e47d5a4f684fda3d98049a70bc491220a6859a2ff207cf32a2
thunk_2668f8:
0x2668f8: JMP 0x00702970
; END FUNCTION thunk_2668f8
0x2668fd: INT3 ; original byte CC, padding
0x2668fe: INT3 ; original byte CC, padding
0x2668ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266900 [0x266900, 0x266904] | file +0x978 | ev_79a39a11fc3f4350741dfbe92dbb3ee9d03d1f0038ac550efcf3abe6aa034267
thunk_266900:
0x266900: JMP 0x00702d60
; END FUNCTION thunk_266900
0x266905: INT3 ; original byte CC, padding
0x266906: INT3 ; original byte CC, padding
0x266907: INT3 ; original byte CC, padding

; FUNCTION thunk_266908 [0x266908, 0x26690c] | file +0x980 | ev_c465dba0b2d910dc7e883d6f859825f028af61a03af466d233c429a1c3437066
thunk_266908:
0x266908: JMP 0x00706170
; END FUNCTION thunk_266908
0x26690d: INT3 ; original byte CC, padding
0x26690e: INT3 ; original byte CC, padding
0x26690f: INT3 ; original byte CC, padding

; FUNCTION thunk_266910 [0x266910, 0x266914] | file +0x988 | ev_ef9fedeb9e387dbcb7d3290bec8b7689777232b05d6c3bb1b117ce64c18f2c5d
thunk_266910:
0x266910: JMP 0x007061f0
; END FUNCTION thunk_266910
0x266915: INT3 ; original byte CC, padding
0x266916: INT3 ; original byte CC, padding
0x266917: INT3 ; original byte CC, padding

; FUNCTION thunk_266918 [0x266918, 0x26691c] | file +0x990 | ev_2af3c5ed42b89ca47470939543fcc7eb737ab28171a4cd5c8133946d4bffebc8
thunk_266918:
0x266918: JMP 0x0070ff00
; END FUNCTION thunk_266918
0x26691d: INT3 ; original byte CC, padding
0x26691e: INT3 ; original byte CC, padding
0x26691f: INT3 ; original byte CC, padding

; FUNCTION thunk_266920 [0x266920, 0x266924] | file +0x998 | ev_8ba8242e089252d99a8cc8a7db165be4787cdc73249a67a9d3de406b2f92243b
thunk_266920:
0x266920: JMP 0x0070ffb0
; END FUNCTION thunk_266920
0x266925: INT3 ; original byte CC, padding
0x266926: INT3 ; original byte CC, padding
0x266927: INT3 ; original byte CC, padding

; FUNCTION thunk_266928 [0x266928, 0x26692c] | file +0x9a0 | ev_bde685656623cf261c8d2a68eb1a624c013d1f1b4b0e9c0e93f302aab6068365
thunk_266928:
0x266928: JMP 0x007101c0
; END FUNCTION thunk_266928
0x26692d: INT3 ; original byte CC, padding
0x26692e: INT3 ; original byte CC, padding
0x26692f: INT3 ; original byte CC, padding

; FUNCTION thunk_266930 [0x266930, 0x266934] | file +0x9a8 | ev_b7ffb8877836166a4a685c022bc96bc3e0ab506a2439a5c6dee2f66a6ca82322
thunk_266930:
0x266930: JMP 0x00710320
; END FUNCTION thunk_266930
0x266935: INT3 ; original byte CC, padding
0x266936: INT3 ; original byte CC, padding
0x266937: INT3 ; original byte CC, padding

; FUNCTION thunk_266938 [0x266938, 0x26693c] | file +0x9b0 | ev_7f6f171a1627ab6995130bf2a96eb88ad7d18a6c294863cb2a05e16007aee4b8
thunk_266938:
0x266938: JMP 0x00712bb0
; END FUNCTION thunk_266938
0x26693d: INT3 ; original byte CC, padding
0x26693e: INT3 ; original byte CC, padding
0x26693f: INT3 ; original byte CC, padding

; FUNCTION thunk_266940 [0x266940, 0x266944] | file +0x9b8 | ev_dddfee7d6fc78e04fc2e8b6de476d83bd91928a276a0e49b68df7ca11e341a36
thunk_266940:
0x266940: JMP 0x00716360
; END FUNCTION thunk_266940
0x266945: INT3 ; original byte CC, padding
0x266946: INT3 ; original byte CC, padding
0x266947: INT3 ; original byte CC, padding

; FUNCTION thunk_266948 [0x266948, 0x26694c] | file +0x9c0 | ev_810262db33bcfe19b9125a9a40bfbc0dcf0ca1d8f07ea1083aa8eb64c2683ed7
thunk_266948:
0x266948: JMP 0x0072f970
; END FUNCTION thunk_266948
0x26694d: INT3 ; original byte CC, padding
0x26694e: INT3 ; original byte CC, padding
0x26694f: INT3 ; original byte CC, padding

; FUNCTION thunk_266950 [0x266950, 0x266954] | file +0x9c8 | ev_bb75578d2158f4a93fd8ad186335b68f4e86e611e1046b5612d66d40e6f42c05
thunk_266950:
0x266950: JMP 0x0072f990
; END FUNCTION thunk_266950
0x266955: INT3 ; original byte CC, padding
0x266956: INT3 ; original byte CC, padding
0x266957: INT3 ; original byte CC, padding

; FUNCTION thunk_266958 [0x266958, 0x26695c] | file +0x9d0 | ev_cc7869a755aa94e9948250e267657fb3484ae5d84c3939e93ee81e25a17c6658
thunk_266958:
0x266958: JMP 0x0072fa20
; END FUNCTION thunk_266958
0x26695d: INT3 ; original byte CC, padding
0x26695e: INT3 ; original byte CC, padding
0x26695f: INT3 ; original byte CC, padding

; FUNCTION thunk_266960 [0x266960, 0x266964] | file +0x9d8 | ev_d41be3a77fe7d970714413a2db7362e7378afaf1c234aca1fb495459da2981f4
thunk_266960:
0x266960: JMP 0x00246e30
; END FUNCTION thunk_266960
0x266965: INT3 ; original byte CC, padding
0x266966: INT3 ; original byte CC, padding
0x266967: INT3 ; original byte CC, padding

; FUNCTION thunk_266968 [0x266968, 0x26696c] | file +0x9e0 | ev_86447051030d85af30d27f1ae658d2b53230586b68e795e6877819c143272823
thunk_266968:
0x266968: JMP 0x007647f0
; END FUNCTION thunk_266968
0x26696d: INT3 ; original byte CC, padding
0x26696e: INT3 ; original byte CC, padding
0x26696f: INT3 ; original byte CC, padding

; FUNCTION thunk_266970 [0x266970, 0x266974] | file +0x9e8 | ev_8f35ce01a7e76f246111c0713a73ab48052fb3758ed42ddf08dadd78f3ee8b2e
thunk_266970:
0x266970: JMP 0x00773710
; END FUNCTION thunk_266970
0x266975: INT3 ; original byte CC, padding
0x266976: INT3 ; original byte CC, padding
0x266977: INT3 ; original byte CC, padding

; FUNCTION thunk_266978 [0x266978, 0x26697c] | file +0x9f0 | ev_67777dd4e1619b577951547dcecfe4e41541a70e9352d9f4fd8e4c18c15e790e
thunk_266978:
0x266978: JMP 0x00775950
; END FUNCTION thunk_266978
0x26697d: INT3 ; original byte CC, padding
0x26697e: INT3 ; original byte CC, padding
0x26697f: INT3 ; original byte CC, padding

; FUNCTION thunk_266980 [0x266980, 0x266984] | file +0x9f8 | ev_cc4f8e212f24a3d2a05a7ecfa0364795c5246f50343e1d895d0b927b5e9acbd9
thunk_266980:
0x266980: JMP 0x00799e90
; END FUNCTION thunk_266980
0x266985: INT3 ; original byte CC, padding
0x266986: INT3 ; original byte CC, padding
0x266987: INT3 ; original byte CC, padding

; FUNCTION thunk_266988 [0x266988, 0x26698c] | file +0xa00 | ev_18e241da46f5f68857625524ec967ff69786cb909ac6fa9f4ea3613ff4a373f6
thunk_266988:
0x266988: JMP 0x007b31f0
; END FUNCTION thunk_266988
0x26698d: INT3 ; original byte CC, padding
0x26698e: INT3 ; original byte CC, padding
0x26698f: INT3 ; original byte CC, padding

; FUNCTION thunk_266990 [0x266990, 0x266994] | file +0xa08 | ev_146209dccae72ac346c363a14fb22c9ebcf1badb24f205149cd1c2a71f73eb10
thunk_266990:
0x266990: JMP 0x007e23a0
; END FUNCTION thunk_266990
0x266995: INT3 ; original byte CC, padding
0x266996: INT3 ; original byte CC, padding
0x266997: INT3 ; original byte CC, padding

; FUNCTION thunk_266998 [0x266998, 0x26699c] | file +0xa10 | ev_07c806b885fdfad9a042087c47d941e3e27815570df71456554ae5f777e04f8a
thunk_266998:
0x266998: JMP 0x007e83e0
; END FUNCTION thunk_266998
0x26699d: INT3 ; original byte CC, padding
0x26699e: INT3 ; original byte CC, padding
0x26699f: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a0 [0x2669a0, 0x2669a4] | file +0xa18 | ev_be089efb1d3a783630ff9eb8e152388777867284e2e50833db979df30666a4fd
thunk_2669a0:
0x2669a0: JMP 0x007e8480
; END FUNCTION thunk_2669a0
0x2669a5: INT3 ; original byte CC, padding
0x2669a6: INT3 ; original byte CC, padding
0x2669a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a8 [0x2669a8, 0x2669ac] | file +0xa20 | ev_7a3ddf208002c5329e2906aceffed7dd3678f5bd7961d84302be0c17c52ea09f
thunk_2669a8:
0x2669a8: JMP 0x00c3b1b0
; END FUNCTION thunk_2669a8
0x2669ad: INT3 ; original byte CC, padding
0x2669ae: INT3 ; original byte CC, padding
0x2669af: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b0 [0x2669b0, 0x2669b4] | file +0xa28 | ev_bdb5f83bfc4dba4e75e19a3eef1d072394dabaa2ee2f9f656e038f3f43a9e595
thunk_2669b0:
0x2669b0: JMP 0x00c3c6e0
; END FUNCTION thunk_2669b0
0x2669b5: INT3 ; original byte CC, padding
0x2669b6: INT3 ; original byte CC, padding
0x2669b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b8 [0x2669b8, 0x2669bc] | file +0xa30 | ev_646a44996bac41d97d6bd466d9d89c6be5622fab00f3833056200cf520b54fe4
thunk_2669b8:
0x2669b8: JMP 0x00c3c690
; END FUNCTION thunk_2669b8
0x2669bd: INT3 ; original byte CC, padding
0x2669be: INT3 ; original byte CC, padding
0x2669bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c0 [0x2669c0, 0x2669c4] | file +0xa38 | ev_4362cb7f40b9eb146fac45118d165bc73bbc51e4d24d0134492add8ca5631b95
thunk_2669c0:
0x2669c0: JMP 0x00c3c730
; END FUNCTION thunk_2669c0
0x2669c5: INT3 ; original byte CC, padding
0x2669c6: INT3 ; original byte CC, padding
0x2669c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c8 [0x2669c8, 0x2669cc] | file +0xa40 | ev_a2defbb92015ed92c0ef482352ca69c0fb501a1cbddcc98ea3de49ae7ad35628
thunk_2669c8:
0x2669c8: JMP 0x00802220
; END FUNCTION thunk_2669c8
0x2669cd: INT3 ; original byte CC, padding
0x2669ce: INT3 ; original byte CC, padding
0x2669cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d0 [0x2669d0, 0x2669d4] | file +0xa48 | ev_8b0d6c0754c0b3b0f5920be4785507c6b59ae0d16e34c3c88580ef5102aa7c09
thunk_2669d0:
0x2669d0: JMP 0x008024f0
; END FUNCTION thunk_2669d0
0x2669d5: INT3 ; original byte CC, padding
0x2669d6: INT3 ; original byte CC, padding
0x2669d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d8 [0x2669d8, 0x2669dc] | file +0xa50 | ev_ad2127f94361c94e9ea3ce28f07b62b5f86902733f265d7410b1b50d7c2dcf34
thunk_2669d8:
0x2669d8: JMP 0x0080c570
; END FUNCTION thunk_2669d8
0x2669dd: INT3 ; original byte CC, padding
0x2669de: INT3 ; original byte CC, padding
0x2669df: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e0 [0x2669e0, 0x2669e4] | file +0xa58 | ev_107ae0a63c11b3b92fc64c7be5323a3eb435cad4abf4cfab408f51f081534354
thunk_2669e0:
0x2669e0: JMP 0x0082b300
; END FUNCTION thunk_2669e0
0x2669e5: INT3 ; original byte CC, padding
0x2669e6: INT3 ; original byte CC, padding
0x2669e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e8 [0x2669e8, 0x2669ec] | file +0xa60 | ev_9ad5a3b6afeb0b6f0b925f04a856e87601c2bf950f8d2fb50a65e0136f58057a
thunk_2669e8:
0x2669e8: JMP 0x00920ee0
; END FUNCTION thunk_2669e8
0x2669ed: INT3 ; original byte CC, padding
0x2669ee: INT3 ; original byte CC, padding
0x2669ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f0 [0x2669f0, 0x2669f4] | file +0xa68 | ev_a480cb6ab7d531f1320cc8242e87145c1c91b7d7a84222faf523f1c010f50494
thunk_2669f0:
0x2669f0: JMP 0x00920b90
; END FUNCTION thunk_2669f0
0x2669f5: INT3 ; original byte CC, padding
0x2669f6: INT3 ; original byte CC, padding
0x2669f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f8 [0x2669f8, 0x2669fc] | file +0xa70 | ev_063eb2665a5427fcd2306892c374cdbc281c7ad6593802712bc6c4b1efb017b7
thunk_2669f8:
0x2669f8: JMP 0x00830810
; END FUNCTION thunk_2669f8
0x2669fd: INT3 ; original byte CC, padding
0x2669fe: INT3 ; original byte CC, padding
0x2669ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266a00 [0x266a00, 0x266a04] | file +0xa78 | ev_29198ce2df122b645034527b9bb21acb52264c59b9daf0884f26625cd53e0086
thunk_266a00:
0x266a00: JMP 0x00830f00
; END FUNCTION thunk_266a00
0x266a05: INT3 ; original byte CC, padding
0x266a06: INT3 ; original byte CC, padding
0x266a07: INT3 ; original byte CC, padding

; FUNCTION thunk_266a08 [0x266a08, 0x266a0c] | file +0xa80 | ev_177dd7dc7b53ab81c2013acc266639880dbc8de7da863168a12b7fafb05569d0
thunk_266a08:
0x266a08: JMP 0x008352b0
; END FUNCTION thunk_266a08
0x266a0d: INT3 ; original byte CC, padding
0x266a0e: INT3 ; original byte CC, padding
0x266a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a10 [0x266a10, 0x266a14] | file +0xa88 | ev_0d5315ab6a16e41f21449cd36ebc5a3310ea3b201b5c2822cc1967b87fc5175d
thunk_266a10:
0x266a10: JMP 0x008352c0
; END FUNCTION thunk_266a10
0x266a15: INT3 ; original byte CC, padding
0x266a16: INT3 ; original byte CC, padding
0x266a17: INT3 ; original byte CC, padding

; FUNCTION thunk_266a18 [0x266a18, 0x266a1c] | file +0xa90 | ev_ec8c18935f45a48774dc5e604617b4fa54ed540c1146049e3259786a4611c0fe
thunk_266a18:
0x266a18: JMP 0x008352d0
; END FUNCTION thunk_266a18
0x266a1d: INT3 ; original byte CC, padding
0x266a1e: INT3 ; original byte CC, padding
0x266a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a20 [0x266a20, 0x266a24] | file +0xa98 | ev_67ccf19ae6261c26c1b465c290344d75286d87b8463b67ce27a2a00d373f25e1
thunk_266a20:
0x266a20: JMP 0x008352f0
; END FUNCTION thunk_266a20
0x266a25: INT3 ; original byte CC, padding
0x266a26: INT3 ; original byte CC, padding
0x266a27: INT3 ; original byte CC, padding

; FUNCTION thunk_266a28 [0x266a28, 0x266a2c] | file +0xaa0 | ev_0fc4c28b309099d4fef2aa0441aada55fdb833e87dd6e611d54d6ce100ee2603
thunk_266a28:
0x266a28: JMP 0x00835440
; END FUNCTION thunk_266a28
0x266a2d: INT3 ; original byte CC, padding
0x266a2e: INT3 ; original byte CC, padding
0x266a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a30 [0x266a30, 0x266a34] | file +0xaa8 | ev_b30b9cb2f6b10209ccef36a80c6226dec9100c5cdf04f409483c5df6c8d721cb
thunk_266a30:
0x266a30: JMP 0x00835450
; END FUNCTION thunk_266a30
0x266a35: INT3 ; original byte CC, padding
0x266a36: INT3 ; original byte CC, padding
0x266a37: INT3 ; original byte CC, padding

; FUNCTION thunk_266a38 [0x266a38, 0x266a3c] | file +0xab0 | ev_1c89747d1cc419c82f65552dd5e9f398d08b9dd3c158550837d6d077fe5f1f9a
thunk_266a38:
0x266a38: JMP 0x00835490
; END FUNCTION thunk_266a38
0x266a3d: INT3 ; original byte CC, padding
0x266a3e: INT3 ; original byte CC, padding
0x266a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a40 [0x266a40, 0x266a44] | file +0xab8 | ev_86c79d8831758bb566d4330365abf0f4f2fdd5f6cecd088a67fe9b63cbdb7eb7
thunk_266a40:
0x266a40: JMP 0x00835ad0
; END FUNCTION thunk_266a40
0x266a45: INT3 ; original byte CC, padding
0x266a46: INT3 ; original byte CC, padding
0x266a47: INT3 ; original byte CC, padding

; FUNCTION thunk_266a48 [0x266a48, 0x266a4c] | file +0xac0 | ev_995c50dcb18c9069c8f14612d6a1455003ea69b54876567c1e823ec636e9aa48
thunk_266a48:
0x266a48: JMP 0x00850870
; END FUNCTION thunk_266a48
0x266a4d: INT3 ; original byte CC, padding
0x266a4e: INT3 ; original byte CC, padding
0x266a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a50 [0x266a50, 0x266a54] | file +0xac8 | ev_5e329a7f38c7891bcb76d5475bccd7ac8a8253c93b2384eb3199eed3c1d6eb2c
thunk_266a50:
0x266a50: JMP 0x008702f0
; END FUNCTION thunk_266a50
0x266a55: INT3 ; original byte CC, padding
0x266a56: INT3 ; original byte CC, padding
0x266a57: INT3 ; original byte CC, padding

; FUNCTION thunk_266a58 [0x266a58, 0x266a5c] | file +0xad0 | ev_e0a5532f5aff1a4a2ee764559daee4f819665087f4630c432530d3cf5486f063
thunk_266a58:
0x266a58: JMP 0x008705d0
; END FUNCTION thunk_266a58
0x266a5d: INT3 ; original byte CC, padding
0x266a5e: INT3 ; original byte CC, padding
0x266a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a60 [0x266a60, 0x266a64] | file +0xad8 | ev_80548a6b40dfc2aeef643069f1ecbfbcaa660deb693d6dfc073b9d3e218c7cb8
thunk_266a60:
0x266a60: JMP 0x00872af0
; END FUNCTION thunk_266a60
0x266a65: INT3 ; original byte CC, padding
0x266a66: INT3 ; original byte CC, padding
0x266a67: INT3 ; original byte CC, padding

; FUNCTION thunk_266a68 [0x266a68, 0x266a6c] | file +0xae0 | ev_8a91bd014432af5bccf4cd9785804c8daa7551ec5454259f0d263e139613a20a
thunk_266a68:
0x266a68: JMP 0x00873800
; END FUNCTION thunk_266a68
0x266a6d: INT3 ; original byte CC, padding
0x266a6e: INT3 ; original byte CC, padding
0x266a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a70 [0x266a70, 0x266a74] | file +0xae8 | ev_ace7e386aef97a8938bc5277da2304ae349721e0be6629dfaab82c91e9879fe3
thunk_266a70:
0x266a70: JMP 0x00063a40
; END FUNCTION thunk_266a70
0x266a75: INT3 ; original byte CC, padding
0x266a76: INT3 ; original byte CC, padding
0x266a77: INT3 ; original byte CC, padding

; FUNCTION thunk_266a78 [0x266a78, 0x266a7c] | file +0xaf0 | ev_4f9cbc3755ffa00d9bc90c78dd059443d243871133d78ad726b0b8a1fa8c59f1
thunk_266a78:
0x266a78: JMP 0x00066370
; END FUNCTION thunk_266a78
0x266a7d: INT3 ; original byte CC, padding
0x266a7e: INT3 ; original byte CC, padding
0x266a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a80 [0x266a80, 0x266a84] | file +0xaf8 | ev_d1253b2b6a410cdb32f733044e199ff7bc1b88e3fa164e1a9321bfe29d2701a4
thunk_266a80:
0x266a80: JMP 0x000e6590
; END FUNCTION thunk_266a80
0x266a85: INT3 ; original byte CC, padding
0x266a86: INT3 ; original byte CC, padding
0x266a87: INT3 ; original byte CC, padding

; FUNCTION thunk_266a88 [0x266a88, 0x266a8c] | file +0xb00 | ev_a70131a343e30187fec4ee4ddd3e10432a8d5db8f7b758eaf398ef0ff9545c41
thunk_266a88:
0x266a88: JMP 0x000e65a0
; END FUNCTION thunk_266a88
0x266a8d: INT3 ; original byte CC, padding
0x266a8e: INT3 ; original byte CC, padding
0x266a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a90 [0x266a90, 0x266a94] | file +0xb08 | ev_580401ac889df9a5a5a73e71f8edea677b42be167a238dc2dff457a9c9f336ff
thunk_266a90:
0x266a90: JMP 0x000e6760
; END FUNCTION thunk_266a90
0x266a95: INT3 ; original byte CC, padding
0x266a96: INT3 ; original byte CC, padding
0x266a97: INT3 ; original byte CC, padding

; FUNCTION thunk_266a98 [0x266a98, 0x266a9c] | file +0xb10 | ev_172618d9f6bde68af37706eabeedff3f52d26fe1bfb0328d5fe417c3de8cfab0
thunk_266a98:
0x266a98: JMP 0x000e6870
; END FUNCTION thunk_266a98
0x266a9d: INT3 ; original byte CC, padding
0x266a9e: INT3 ; original byte CC, padding
0x266a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa0 [0x266aa0, 0x266aa4] | file +0xb18 | ev_b1e956b19177c725cc5b0de3abaf0d87a3b82bb14d6e9f4ec8831e2d91b54c47
thunk_266aa0:
0x266aa0: JMP 0x000e7f90
; END FUNCTION thunk_266aa0
0x266aa5: INT3 ; original byte CC, padding
0x266aa6: INT3 ; original byte CC, padding
0x266aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa8 [0x266aa8, 0x266aac] | file +0xb20 | ev_cb2f12ba0838083ded8dec004c46678be74c9abcc86c76566af579016dba3da5
thunk_266aa8:
0x266aa8: JMP 0x000e9fa0
; END FUNCTION thunk_266aa8
0x266aad: INT3 ; original byte CC, padding
0x266aae: INT3 ; original byte CC, padding
0x266aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab0 [0x266ab0, 0x266ab4] | file +0xb28 | ev_a3052214a521cc3208409e021fa100a76d9261caf5a168a1b72d321750d2b45b
thunk_266ab0:
0x266ab0: JMP 0x000ea670
; END FUNCTION thunk_266ab0
0x266ab5: INT3 ; original byte CC, padding
0x266ab6: INT3 ; original byte CC, padding
0x266ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab8 [0x266ab8, 0x266abc] | file +0xb30 | ev_ab5d43e0a40ba98e026fe8788b90cb6bded3dbb9083f30de951f5b55b6611259
thunk_266ab8:
0x266ab8: JMP 0x000ea760
; END FUNCTION thunk_266ab8
0x266abd: INT3 ; original byte CC, padding
0x266abe: INT3 ; original byte CC, padding
0x266abf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac0 [0x266ac0, 0x266ac4] | file +0xb38 | ev_dfd025dd38eb834c1c4d4e37cf5c20a054f6b368c99fd5c1fcf91a2b04bdb89b
thunk_266ac0:
0x266ac0: JMP 0x000eb0a0
; END FUNCTION thunk_266ac0
0x266ac5: INT3 ; original byte CC, padding
0x266ac6: INT3 ; original byte CC, padding
0x266ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac8 [0x266ac8, 0x266acc] | file +0xb40 | ev_0ba290f61e689c4ddfbc0e9dcd74c90382de6a3844dbe481dd4b5f0c00a605c2
thunk_266ac8:
0x266ac8: JMP 0x000eb190
; END FUNCTION thunk_266ac8
0x266acd: INT3 ; original byte CC, padding
0x266ace: INT3 ; original byte CC, padding
0x266acf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad0 [0x266ad0, 0x266ad4] | file +0xb48 | ev_c7f735b31597949f8b3d8f12d6282e1f65af64f8d580a8b0a79e0b9dc7e33794
thunk_266ad0:
0x266ad0: JMP 0x000ed000
; END FUNCTION thunk_266ad0
0x266ad5: INT3 ; original byte CC, padding
0x266ad6: INT3 ; original byte CC, padding
0x266ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad8 [0x266ad8, 0x266adc] | file +0xb50 | ev_3696ca577c07d3cd8b4dd4f5e7485fc4ccec33eea40a7e33578374e1d59a95f4
thunk_266ad8:
0x266ad8: JMP 0x000ed110
; END FUNCTION thunk_266ad8
0x266add: INT3 ; original byte CC, padding
0x266ade: INT3 ; original byte CC, padding
0x266adf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae0 [0x266ae0, 0x266ae4] | file +0xb58 | ev_3540435ffca26bbb8b563d995bb2524984e42644dbbb93606680668159825e87
thunk_266ae0:
0x266ae0: JMP 0x0088a8a0
; END FUNCTION thunk_266ae0
0x266ae5: INT3 ; original byte CC, padding
0x266ae6: INT3 ; original byte CC, padding
0x266ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae8 [0x266ae8, 0x266aec] | file +0xb60 | ev_54ff9ea03fe46568160ea2de9f8a562e1d312294a5ade2a6b4bdcdada49b1f8c
thunk_266ae8:
0x266ae8: JMP 0x0089cdf0
; END FUNCTION thunk_266ae8
0x266aed: INT3 ; original byte CC, padding
0x266aee: INT3 ; original byte CC, padding
0x266aef: INT3 ; original byte CC, padding

; FUNCTION thunk_266af0 [0x266af0, 0x266af4] | file +0xb68 | ev_e99f643f0db2c0d24db4fcaf3b5de144991b1adc450c03f6d71331e88d5c9524
thunk_266af0:
0x266af0: JMP 0x000eeb50
; END FUNCTION thunk_266af0
0x266af5: INT3 ; original byte CC, padding
0x266af6: INT3 ; original byte CC, padding
0x266af7: INT3 ; original byte CC, padding

; FUNCTION thunk_266af8 [0x266af8, 0x266afc] | file +0xb70 | ev_7e7fe8b4dde4de2281a4f4bd9bdf5add95be25e22ea62e2e3998fb3936a080ff
thunk_266af8:
0x266af8: JMP 0x008cb250
; END FUNCTION thunk_266af8
0x266afd: INT3 ; original byte CC, padding
0x266afe: INT3 ; original byte CC, padding
0x266aff: INT3 ; original byte CC, padding

; FUNCTION thunk_266b00 [0x266b00, 0x266b04] | file +0xb78 | ev_253a16e4058f7de88d51b504ce6a1bacc5be58252642dbbbeee6505711d0648a
thunk_266b00:
0x266b00: JMP 0x008cb390
; END FUNCTION thunk_266b00
0x266b05: INT3 ; original byte CC, padding
0x266b06: INT3 ; original byte CC, padding
0x266b07: INT3 ; original byte CC, padding

; FUNCTION thunk_266b08 [0x266b08, 0x266b0c] | file +0xb80 | ev_fea9d8ff31d0c4fdadf83b22e249aee209225d68e062e0fa46b431c0c49c6dd8
thunk_266b08:
0x266b08: JMP 0x008d2f60
; END FUNCTION thunk_266b08
0x266b0d: INT3 ; original byte CC, padding
0x266b0e: INT3 ; original byte CC, padding
0x266b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b10 [0x266b10, 0x266b14] | file +0xb88 | ev_135119e632a722801f99ad8c2796d9c5d57282defcf1d58fc48cdc7c8e74cb29
thunk_266b10:
0x266b10: JMP 0x008d2f90
; END FUNCTION thunk_266b10
0x266b15: INT3 ; original byte CC, padding
0x266b16: INT3 ; original byte CC, padding
0x266b17: INT3 ; original byte CC, padding

; FUNCTION thunk_266b18 [0x266b18, 0x266b1c] | file +0xb90 | ev_1c2fdbeb60f49688af5703a743188a25b5530b226b89c34973c7416c1b14c502
thunk_266b18:
0x266b18: JMP 0x008d8230
; END FUNCTION thunk_266b18
0x266b1d: INT3 ; original byte CC, padding
0x266b1e: INT3 ; original byte CC, padding
0x266b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b20 [0x266b20, 0x266b24] | file +0xb98 | ev_05e0040e1f1449251377c771031f3d1467b9cea3be2dbb969252562a3d9c6a4b
thunk_266b20:
0x266b20: JMP 0x008d8de0
; END FUNCTION thunk_266b20
0x266b25: INT3 ; original byte CC, padding
0x266b26: INT3 ; original byte CC, padding
0x266b27: INT3 ; original byte CC, padding

; FUNCTION thunk_266b28 [0x266b28, 0x266b2c] | file +0xba0 | ev_3d84d0e832dea1f4393c51cf621401b1efd43c186c59c97d0e1290835b35a0cb
thunk_266b28:
0x266b28: JMP 0x008d97b0
; END FUNCTION thunk_266b28
0x266b2d: INT3 ; original byte CC, padding
0x266b2e: INT3 ; original byte CC, padding
0x266b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b30 [0x266b30, 0x266b34] | file +0xba8 | ev_867be95cdeb3d9b186a680fcb42dc2eef398f6ee5999819b185940e385522a2c
thunk_266b30:
0x266b30: JMP 0x008d9910
; END FUNCTION thunk_266b30
0x266b35: INT3 ; original byte CC, padding
0x266b36: INT3 ; original byte CC, padding
0x266b37: INT3 ; original byte CC, padding

; FUNCTION thunk_266b38 [0x266b38, 0x266b3c] | file +0xbb0 | ev_98a6115dac41b7f98acf672e285af4338aa06739dcba52f9d8b424b8b65ba3c3
thunk_266b38:
0x266b38: JMP 0x008da4c0
; END FUNCTION thunk_266b38
0x266b3d: INT3 ; original byte CC, padding
0x266b3e: INT3 ; original byte CC, padding
0x266b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b40 [0x266b40, 0x266b44] | file +0xbb8 | ev_28661288bbd93c64c4601ab505454f1242fe1271953adf1d17cfaa755a4dffd0
thunk_266b40:
0x266b40: JMP 0x008da570
; END FUNCTION thunk_266b40
0x266b45: INT3 ; original byte CC, padding
0x266b46: INT3 ; original byte CC, padding
0x266b47: INT3 ; original byte CC, padding

; FUNCTION thunk_266b48 [0x266b48, 0x266b4c] | file +0xbc0 | ev_bd344f0bd9ec7d067a0cb4c8208d913f749af95b11793f5da2827e74faf79109
thunk_266b48:
0x266b48: JMP 0x008da5b0
; END FUNCTION thunk_266b48
0x266b4d: INT3 ; original byte CC, padding
0x266b4e: INT3 ; original byte CC, padding
0x266b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b50 [0x266b50, 0x266b54] | file +0xbc8 | ev_f8a42572829c10ec77ab49408e31d2ffb005a17eb5e53f6695770add06be8082
thunk_266b50:
0x266b50: JMP 0x00904c80
; END FUNCTION thunk_266b50
0x266b55: INT3 ; original byte CC, padding
0x266b56: INT3 ; original byte CC, padding
0x266b57: INT3 ; original byte CC, padding

; FUNCTION thunk_266b58 [0x266b58, 0x266b5c] | file +0xbd0 | ev_8a13f5a851e775e80be452193fbd4d590b6d04ccbc7dff49f1656f50ed85ff91
thunk_266b58:
0x266b58: JMP 0x00904e60
; END FUNCTION thunk_266b58
0x266b5d: INT3 ; original byte CC, padding
0x266b5e: INT3 ; original byte CC, padding
0x266b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b60 [0x266b60, 0x266b64] | file +0xbd8 | ev_55a50802f4a0a58d620581bdf6d487bbdbf788f27ea4ebade9bcf71add39a1dc
thunk_266b60:
0x266b60: JMP 0x0091d400
; END FUNCTION thunk_266b60
0x266b65: INT3 ; original byte CC, padding
0x266b66: INT3 ; original byte CC, padding
0x266b67: INT3 ; original byte CC, padding

; FUNCTION thunk_266b68 [0x266b68, 0x266b6c] | file +0xbe0 | ev_a3b427a4474839c0c8a0e35e824e29e550bf1ee74d21c07a0abcdaee31a56056
thunk_266b68:
0x266b68: JMP 0x0091d4a0
; END FUNCTION thunk_266b68
0x266b6d: INT3 ; original byte CC, padding
0x266b6e: INT3 ; original byte CC, padding
0x266b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b70 [0x266b70, 0x266b74] | file +0xbe8 | ev_e8467fac24f549ccc576dbf816d0d2d2ccd83f5700eb06faa6c91121b928fdd0
thunk_266b70:
0x266b70: JMP 0x00a821d0
; END FUNCTION thunk_266b70
0x266b75: INT3 ; original byte CC, padding
0x266b76: INT3 ; original byte CC, padding
0x266b77: INT3 ; original byte CC, padding

; FUNCTION thunk_266b78 [0x266b78, 0x266b7c] | file +0xbf0 | ev_8f47985372645d0671a737f6dfdc8c8ebd02beaa2f6b203fa63da2a5b8f22e7b
thunk_266b78:
0x266b78: JMP 0x00b42120
; END FUNCTION thunk_266b78
0x266b7d: INT3 ; original byte CC, padding
0x266b7e: INT3 ; original byte CC, padding
0x266b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b80 [0x266b80, 0x266b84] | file +0xbf8 | ev_fd684889e15d4b26e0ee82dee8ba632bc13425741ac010622add8dae7219815d
thunk_266b80:
0x266b80: JMP 0x00964f30
; END FUNCTION thunk_266b80
0x266b85: INT3 ; original byte CC, padding
0x266b86: INT3 ; original byte CC, padding
0x266b87: INT3 ; original byte CC, padding

; FUNCTION thunk_266b88 [0x266b88, 0x266b8c] | file +0xc00 | ev_f2df38026d5491e448e5063aac5789ad983601c453d578988858f92b6d03ae2c
thunk_266b88:
0x266b88: JMP 0x00975f50
; END FUNCTION thunk_266b88
0x266b8d: INT3 ; original byte CC, padding
0x266b8e: INT3 ; original byte CC, padding
0x266b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b90 [0x266b90, 0x266b94] | file +0xc08 | ev_10d8a996d05141151a80648eaa04914a17d0858789d77b5b14476705981530fe
thunk_266b90:
0x266b90: JMP 0x00976200
; END FUNCTION thunk_266b90
0x266b95: INT3 ; original byte CC, padding
0x266b96: INT3 ; original byte CC, padding
0x266b97: INT3 ; original byte CC, padding

; FUNCTION thunk_266b98 [0x266b98, 0x266b9c] | file +0xc10 | ev_c3116b49143e9b6ff94c37355177e2bdb67bb1b2e76d75c69776fb7bb325b566
thunk_266b98:
0x266b98: JMP 0x0098c950
; END FUNCTION thunk_266b98
0x266b9d: INT3 ; original byte CC, padding
0x266b9e: INT3 ; original byte CC, padding
0x266b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba0 [0x266ba0, 0x266ba4] | file +0xc18 | ev_d5357955364e0302a1c35a09ecc6540c8689b4e80dfafeb3e3bdcbaf003676e0
thunk_266ba0:
0x266ba0: JMP 0x0098cc30
; END FUNCTION thunk_266ba0
0x266ba5: INT3 ; original byte CC, padding
0x266ba6: INT3 ; original byte CC, padding
0x266ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba8 [0x266ba8, 0x266bac] | file +0xc20 | ev_7eb181636e2cdb2333dd763ae4894fc17222923d697e92963d6ba4b611dcda21
thunk_266ba8:
0x266ba8: JMP 0x0098cf30
; END FUNCTION thunk_266ba8
0x266bad: INT3 ; original byte CC, padding
0x266bae: INT3 ; original byte CC, padding
0x266baf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb0 [0x266bb0, 0x266bb4] | file +0xc28 | ev_2f19404c650e0b9290f01b624e2d3247ddfabf77eef32e16a5484806b710f012
thunk_266bb0:
0x266bb0: JMP 0x0098d6e0
; END FUNCTION thunk_266bb0
0x266bb5: INT3 ; original byte CC, padding
0x266bb6: INT3 ; original byte CC, padding
0x266bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb8 [0x266bb8, 0x266bbc] | file +0xc30 | ev_b05bb4840cd18187e9cfeab82d33fe5e27867653043f55bd77bb02218ee6fb15
thunk_266bb8:
0x266bb8: JMP 0x0098e5d0
; END FUNCTION thunk_266bb8
0x266bbd: INT3 ; original byte CC, padding
0x266bbe: INT3 ; original byte CC, padding
0x266bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc0 [0x266bc0, 0x266bc4] | file +0xc38 | ev_79af95be2d186c085c2c3aeced8a2aeeb8b6718f7d34419ecbb36bf6ed2a29e6
thunk_266bc0:
0x266bc0: JMP 0x0098e700
; END FUNCTION thunk_266bc0
0x266bc5: INT3 ; original byte CC, padding
0x266bc6: INT3 ; original byte CC, padding
0x266bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc8 [0x266bc8, 0x266bcc] | file +0xc40 | ev_8341b535cc158bc64ba7d262cb376e3cec41502b7caeb9d18b2601d189b8c5c3
thunk_266bc8:
0x266bc8: JMP 0x00992170
; END FUNCTION thunk_266bc8
0x266bcd: INT3 ; original byte CC, padding
0x266bce: INT3 ; original byte CC, padding
0x266bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd0 [0x266bd0, 0x266bd4] | file +0xc48 | ev_e166acea8ad67d05799944a6f7fdd59ec5f3b1ac8764a5c1c9aab83775552d58
thunk_266bd0:
0x266bd0: JMP 0x00992240
; END FUNCTION thunk_266bd0
0x266bd5: INT3 ; original byte CC, padding
0x266bd6: INT3 ; original byte CC, padding
0x266bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd8 [0x266bd8, 0x266bdc] | file +0xc50 | ev_85e73f067c4170bb5b3458130fd57a6af13915d7b31859b4fc64c3f06ed82bac
thunk_266bd8:
0x266bd8: JMP 0x000f5400
; END FUNCTION thunk_266bd8
0x266bdd: INT3 ; original byte CC, padding
0x266bde: INT3 ; original byte CC, padding
0x266bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266be0 [0x266be0, 0x266be4] | file +0xc58 | ev_842b4c5c42c065668d984eae4c9142db76b388ac3869191a2e6774a1dd29092b
thunk_266be0:
0x266be0: JMP 0x009a2320
; END FUNCTION thunk_266be0
0x266be5: INT3 ; original byte CC, padding
0x266be6: INT3 ; original byte CC, padding
0x266be7: INT3 ; original byte CC, padding

; FUNCTION thunk_266be8 [0x266be8, 0x266bec] | file +0xc60 | ev_030a86c722bd8b0115511456a8e9c167e2fcee9c0bc3fef7480f00c92d243c2a
thunk_266be8:
0x266be8: JMP 0x009a5720
; END FUNCTION thunk_266be8
0x266bed: INT3 ; original byte CC, padding
0x266bee: INT3 ; original byte CC, padding
0x266bef: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf0 [0x266bf0, 0x266bf4] | file +0xc68 | ev_b7ba618ae2aa9e42f6dc5f460eacabc57ff16a7d0aa334b8901473386f810008
thunk_266bf0:
0x266bf0: JMP 0x009ac9a0
; END FUNCTION thunk_266bf0
0x266bf5: INT3 ; original byte CC, padding
0x266bf6: INT3 ; original byte CC, padding
0x266bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf8 [0x266bf8, 0x266bfc] | file +0xc70 | ev_7b6dffa6d17e048eb0c5c66d7ff1892a62f7829978e4d399fec5e56368c85598
thunk_266bf8:
0x266bf8: JMP 0x009aca20
; END FUNCTION thunk_266bf8
0x266bfd: INT3 ; original byte CC, padding
0x266bfe: INT3 ; original byte CC, padding
0x266bff: INT3 ; original byte CC, padding

; FUNCTION thunk_266c00 [0x266c00, 0x266c04] | file +0xc78 | ev_37e32afc32cbfcefa497814dc4c10dc93a73d1b39133f84aeeb295f99deb9227
thunk_266c00:
0x266c00: JMP 0x001be640
; END FUNCTION thunk_266c00
0x266c05: INT3 ; original byte CC, padding
0x266c06: INT3 ; original byte CC, padding
0x266c07: INT3 ; original byte CC, padding

; FUNCTION thunk_266c08 [0x266c08, 0x266c0c] | file +0xc80 | ev_8dcbff7b878d9c7260555fdb740b8c9f57eb3ce3f0cd403b4e34d3dc8444893d
thunk_266c08:
0x266c08: JMP 0x009bed20
; END FUNCTION thunk_266c08
0x266c0d: INT3 ; original byte CC, padding
0x266c0e: INT3 ; original byte CC, padding
0x266c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c10 [0x266c10, 0x266c14] | file +0xc88 | ev_5609616af12540e3f21ffdb1c4ee50798b97a80d28d9e70d0e40685b3d52ea7b
thunk_266c10:
0x266c10: JMP 0x009c6050
; END FUNCTION thunk_266c10
0x266c15: INT3 ; original byte CC, padding
0x266c16: INT3 ; original byte CC, padding
0x266c17: INT3 ; original byte CC, padding

; FUNCTION thunk_266c18 [0x266c18, 0x266c1c] | file +0xc90 | ev_8fbdeb0835724f32a8b17a3c5d39a5e952abf35119874527c7bf6b3d2f410f4d
thunk_266c18:
0x266c18: JMP 0x009c60d0
; END FUNCTION thunk_266c18
0x266c1d: INT3 ; original byte CC, padding
0x266c1e: INT3 ; original byte CC, padding
0x266c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c20 [0x266c20, 0x266c24] | file +0xc98 | ev_ace2b7677c241f86357c44b9f6ffb12c616d9a72f498b23035be4fb0262a687f
thunk_266c20:
0x266c20: JMP 0x009c6280
; END FUNCTION thunk_266c20
0x266c25: INT3 ; original byte CC, padding
0x266c26: INT3 ; original byte CC, padding
0x266c27: INT3 ; original byte CC, padding

; FUNCTION thunk_266c28 [0x266c28, 0x266c2c] | file +0xca0 | ev_7a3062ecd30b0df2a6122e8f59b5953527a185a8647d27426de7edb4c906b7d7
thunk_266c28:
0x266c28: JMP 0x009c6310
; END FUNCTION thunk_266c28
0x266c2d: INT3 ; original byte CC, padding
0x266c2e: INT3 ; original byte CC, padding
0x266c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c30 [0x266c30, 0x266c34] | file +0xca8 | ev_dfe29f719b7475feed102705faecbfb48a5fb5cabcf650e8b213eddc01c64181
thunk_266c30:
0x266c30: JMP 0x009c6490
; END FUNCTION thunk_266c30
0x266c35: INT3 ; original byte CC, padding
0x266c36: INT3 ; original byte CC, padding
0x266c37: INT3 ; original byte CC, padding

; FUNCTION thunk_266c38 [0x266c38, 0x266c3c] | file +0xcb0 | ev_f2fead07eb766b1364e16b243079bc9aa5d3876480b0d12b25b3c132c3754268
thunk_266c38:
0x266c38: JMP 0x009c65b0
; END FUNCTION thunk_266c38
0x266c3d: INT3 ; original byte CC, padding
0x266c3e: INT3 ; original byte CC, padding
0x266c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c40 [0x266c40, 0x266c44] | file +0xcb8 | ev_c68ed7ba26444d1752bf6058fc28ab01a6bf926027464b2ea5e375f261cacff4
thunk_266c40:
0x266c40: JMP 0x009c6890
; END FUNCTION thunk_266c40
0x266c45: INT3 ; original byte CC, padding
0x266c46: INT3 ; original byte CC, padding
0x266c47: INT3 ; original byte CC, padding

; FUNCTION thunk_266c48 [0x266c48, 0x266c4c] | file +0xcc0 | ev_67de297adfeed209dfc647b55bf4d003699078a117d7be29f97231507d06648d
thunk_266c48:
0x266c48: JMP 0x009c9340
; END FUNCTION thunk_266c48
0x266c4d: INT3 ; original byte CC, padding
0x266c4e: INT3 ; original byte CC, padding
0x266c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c50 [0x266c50, 0x266c54] | file +0xcc8 | ev_f5735fce676e82d52e4f585386bb91ed4c135c29aa338a4a56a193e57e3bc696
thunk_266c50:
0x266c50: JMP 0x009c9360
; END FUNCTION thunk_266c50
0x266c55: INT3 ; original byte CC, padding
0x266c56: INT3 ; original byte CC, padding
0x266c57: INT3 ; original byte CC, padding

; FUNCTION thunk_266c58 [0x266c58, 0x266c5c] | file +0xcd0 | ev_e91b99d64f4c78087780aed0abccebaa4e78e410a865688b3acac1c9d9dbc662
thunk_266c58:
0x266c58: JMP 0x009c9370
; END FUNCTION thunk_266c58
0x266c5d: INT3 ; original byte CC, padding
0x266c5e: INT3 ; original byte CC, padding
0x266c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c60 [0x266c60, 0x266c64] | file +0xcd8 | ev_b3f6589bf2526d456f9760f6654606024f8576bc26a4405284d36ac742be9973
thunk_266c60:
0x266c60: JMP 0x009c9380
; END FUNCTION thunk_266c60
0x266c65: INT3 ; original byte CC, padding
0x266c66: INT3 ; original byte CC, padding
0x266c67: INT3 ; original byte CC, padding

; FUNCTION thunk_266c68 [0x266c68, 0x266c6c] | file +0xce0 | ev_18322b16d894e20a403d727376dae134cc622455f406447df0dcce4b12631368
thunk_266c68:
0x266c68: JMP 0x009dadb0
; END FUNCTION thunk_266c68
0x266c6d: INT3 ; original byte CC, padding
0x266c6e: INT3 ; original byte CC, padding
0x266c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c70 [0x266c70, 0x266c74] | file +0xce8 | ev_02cfdafda2a13e9bce9c188e0d3d2ff158067964ff4148e08d6c71ef28462e5b
thunk_266c70:
0x266c70: JMP 0x009dafa0
; END FUNCTION thunk_266c70
0x266c75: INT3 ; original byte CC, padding
0x266c76: INT3 ; original byte CC, padding
0x266c77: INT3 ; original byte CC, padding

; FUNCTION thunk_266c78 [0x266c78, 0x266c7c] | file +0xcf0 | ev_e8c329046ada8dfcbb218a69d95ad166cea9026c2e371cb78043976fdb141791
thunk_266c78:
0x266c78: JMP 0x009dc860
; END FUNCTION thunk_266c78
0x266c7d: INT3 ; original byte CC, padding
0x266c7e: INT3 ; original byte CC, padding
0x266c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c80 [0x266c80, 0x266c84] | file +0xcf8 | ev_951c7632d5f7ac048641f115f7f022df0067f8be7557f92bc19817ba1f69dce3
thunk_266c80:
0x266c80: JMP 0x009dcc40
; END FUNCTION thunk_266c80
0x266c85: INT3 ; original byte CC, padding
0x266c86: INT3 ; original byte CC, padding
0x266c87: INT3 ; original byte CC, padding

; FUNCTION thunk_266c88 [0x266c88, 0x266c8c] | file +0xd00 | ev_cb36009f9bfc136ec5ce961b8bfce675e1359e0ba638916fd42ff816e5a29426
thunk_266c88:
0x266c88: JMP 0x009dce80
; END FUNCTION thunk_266c88
0x266c8d: INT3 ; original byte CC, padding
0x266c8e: INT3 ; original byte CC, padding
0x266c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c90 [0x266c90, 0x266c94] | file +0xd08 | ev_6cd39531681fde08c31a8a78d17c026d60656b4a04d4df9cf32e35b4ad3233b6
thunk_266c90:
0x266c90: JMP 0x009dd500
; END FUNCTION thunk_266c90
0x266c95: INT3 ; original byte CC, padding
0x266c96: INT3 ; original byte CC, padding
0x266c97: INT3 ; original byte CC, padding

; FUNCTION thunk_266c98 [0x266c98, 0x266c9c] | file +0xd10 | ev_082dedda124d393d2915851f9fde3e738185206a07e4537279f0f861e5e538ed
thunk_266c98:
0x266c98: JMP 0x00caacd0
; END FUNCTION thunk_266c98
0x266c9d: INT3 ; original byte CC, padding
0x266c9e: INT3 ; original byte CC, padding
0x266c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca0 [0x266ca0, 0x266ca4] | file +0xd18 | ev_9bc1d8d5795bb013c77f16ef99873037745952b9b9c7afd3662bb4d086d7ead5
thunk_266ca0:
0x266ca0: JMP 0x009dd7d0
; END FUNCTION thunk_266ca0
0x266ca5: INT3 ; original byte CC, padding
0x266ca6: INT3 ; original byte CC, padding
0x266ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca8 [0x266ca8, 0x266cac] | file +0xd20 | ev_17560178ac1bf83794f7f4280d1fb3fc2375e475a18a6fac6d799778c6f8ebbf
thunk_266ca8:
0x266ca8: JMP 0x009dd990
; END FUNCTION thunk_266ca8
0x266cad: INT3 ; original byte CC, padding
0x266cae: INT3 ; original byte CC, padding
0x266caf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb0 [0x266cb0, 0x266cb4] | file +0xd28 | ev_93b9cede683a5db69b3564125f37c3e108fee90298840a1378e784896a40b21a
thunk_266cb0:
0x266cb0: JMP 0x009ddba0
; END FUNCTION thunk_266cb0
0x266cb5: INT3 ; original byte CC, padding
0x266cb6: INT3 ; original byte CC, padding
0x266cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb8 [0x266cb8, 0x266cbc] | file +0xd30 | ev_17e04c234b75b5bb4b975f60d1dfe50a320d9680c9f216bf121bb91243acdb38
thunk_266cb8:
0x266cb8: JMP 0x009ddc00
; END FUNCTION thunk_266cb8
0x266cbd: INT3 ; original byte CC, padding
0x266cbe: INT3 ; original byte CC, padding
0x266cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc0 [0x266cc0, 0x266cc4] | file +0xd38 | ev_b6c802572264316e90ed3345f2a81557c2bd489791b15076650e3be79e08ff47
thunk_266cc0:
0x266cc0: JMP 0x009dde50
; END FUNCTION thunk_266cc0
0x266cc5: INT3 ; original byte CC, padding
0x266cc6: INT3 ; original byte CC, padding
0x266cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc8 [0x266cc8, 0x266ccc] | file +0xd40 | ev_f94c0066909ed11a39e16e7896cd502d8724b3a73c0764f2f50f547302dc33d5
thunk_266cc8:
0x266cc8: JMP 0x009ddeb0
; END FUNCTION thunk_266cc8
0x266ccd: INT3 ; original byte CC, padding
0x266cce: INT3 ; original byte CC, padding
0x266ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd0 [0x266cd0, 0x266cd4] | file +0xd48 | ev_348cb7baeed000a9d33e2e381076de9fb9b8615b007f637a8eb38169607b542e
thunk_266cd0:
0x266cd0: JMP 0x009ddff0
; END FUNCTION thunk_266cd0
0x266cd5: INT3 ; original byte CC, padding
0x266cd6: INT3 ; original byte CC, padding
0x266cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd8 [0x266cd8, 0x266cdc] | file +0xd50 | ev_fc58a66b8aa11327158592a2683a5409b088dbfa3e73c567d2114c597deb93bc
thunk_266cd8:
0x266cd8: JMP 0x009de070
; END FUNCTION thunk_266cd8
0x266cdd: INT3 ; original byte CC, padding
0x266cde: INT3 ; original byte CC, padding
0x266cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce0 [0x266ce0, 0x266ce4] | file +0xd58 | ev_5475722fc4118f733e9a73ddbd7446a54dc4ad626a95e9c9f0448cc18e9f996e
thunk_266ce0:
0x266ce0: JMP 0x009de0f0
; END FUNCTION thunk_266ce0
0x266ce5: INT3 ; original byte CC, padding
0x266ce6: INT3 ; original byte CC, padding
0x266ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce8 [0x266ce8, 0x266cec] | file +0xd60 | ev_fdafddb450a802d82260ceae9a715e28314e8881a70b3d59b8493179b1961500
thunk_266ce8:
0x266ce8: JMP 0x009e0b90
; END FUNCTION thunk_266ce8
0x266ced: INT3 ; original byte CC, padding
0x266cee: INT3 ; original byte CC, padding
0x266cef: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf0 [0x266cf0, 0x266cf4] | file +0xd68 | ev_8cefa82a89b7b4b45c99217e6cd0bee8439d24511d15edc5beb5541815716e5c
thunk_266cf0:
0x266cf0: JMP 0x009e0cd0
; END FUNCTION thunk_266cf0
0x266cf5: INT3 ; original byte CC, padding
0x266cf6: INT3 ; original byte CC, padding
0x266cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf8 [0x266cf8, 0x266cfc] | file +0xd70 | ev_0fe31e9a802c16bff487f3ffa6fe768146a74631329f957dd9bc3dca74021aca
thunk_266cf8:
0x266cf8: JMP 0x009e0d70
; END FUNCTION thunk_266cf8
0x266cfd: INT3 ; original byte CC, padding
0x266cfe: INT3 ; original byte CC, padding
0x266cff: INT3 ; original byte CC, padding

; FUNCTION thunk_266d00 [0x266d00, 0x266d04] | file +0xd78 | ev_e5cce5cafece25832e81d202bbaf98d746251944792d147620e609bdc88a079b
thunk_266d00:
0x266d00: JMP 0x009e0ef0
; END FUNCTION thunk_266d00
0x266d05: INT3 ; original byte CC, padding
0x266d06: INT3 ; original byte CC, padding
0x266d07: INT3 ; original byte CC, padding

; FUNCTION thunk_266d08 [0x266d08, 0x266d0c] | file +0xd80 | ev_a5c6e76db2b06ad96ad752996fbb0d43af1311a603e951d09dc0718da26264e1
thunk_266d08:
0x266d08: JMP 0x009e1050
; END FUNCTION thunk_266d08
0x266d0d: INT3 ; original byte CC, padding
0x266d0e: INT3 ; original byte CC, padding
0x266d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d10 [0x266d10, 0x266d14] | file +0xd88 | ev_2ff4d8779640ec27c7a42ba2bd832a1062c3067640217eabf3eafa58a6ac14c7
thunk_266d10:
0x266d10: JMP 0x009e1490
; END FUNCTION thunk_266d10
0x266d15: INT3 ; original byte CC, padding
0x266d16: INT3 ; original byte CC, padding
0x266d17: INT3 ; original byte CC, padding

; FUNCTION thunk_266d18 [0x266d18, 0x266d1c] | file +0xd90 | ev_b7780a59bec1d8f90378ae9653e3982c89c7992f914096c62690d8fcc0b31a94
thunk_266d18:
0x266d18: JMP 0x00a065e0
; END FUNCTION thunk_266d18
0x266d1d: INT3 ; original byte CC, padding
0x266d1e: INT3 ; original byte CC, padding
0x266d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d20 [0x266d20, 0x266d24] | file +0xd98 | ev_d10f566f8d9de96267472087c1f37a7479708a48744751f0d311c1c622dd3904
thunk_266d20:
0x266d20: JMP 0x00101340
; END FUNCTION thunk_266d20
0x266d25: INT3 ; original byte CC, padding
0x266d26: INT3 ; original byte CC, padding
0x266d27: INT3 ; original byte CC, padding

; FUNCTION thunk_266d28 [0x266d28, 0x266d2c] | file +0xda0 | ev_b14ed9d81a695319fa6e7c6ebdc5b570f764a5554a4fc0c40148baafde815686
thunk_266d28:
0x266d28: JMP 0x00a32f30
; END FUNCTION thunk_266d28
0x266d2d: INT3 ; original byte CC, padding
0x266d2e: INT3 ; original byte CC, padding
0x266d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d30 [0x266d30, 0x266d34] | file +0xda8 | ev_6ceedf1cd0b694a6020d0489577c66021b95c6e6acf4a93dbeabde86d9f6d391
thunk_266d30:
0x266d30: JMP 0x00a336c0
; END FUNCTION thunk_266d30
0x266d35: INT3 ; original byte CC, padding
0x266d36: INT3 ; original byte CC, padding
0x266d37: INT3 ; original byte CC, padding

; FUNCTION thunk_266d38 [0x266d38, 0x266d3c] | file +0xdb0 | ev_f404fb3364f869a944ee99aeb16bd33ff7e315fa9ba80c315a591d04d77c5cd9
thunk_266d38:
0x266d38: JMP 0x00a38c90
; END FUNCTION thunk_266d38
0x266d3d: INT3 ; original byte CC, padding
0x266d3e: INT3 ; original byte CC, padding
0x266d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d40 [0x266d40, 0x266d44] | file +0xdb8 | ev_78ce9ed99aaf60ae3f7ddffd51b979932236ff54bce8de0b8b30a669f28d85da
thunk_266d40:
0x266d40: JMP 0x00a6ab00
; END FUNCTION thunk_266d40
0x266d45: INT3 ; original byte CC, padding
0x266d46: INT3 ; original byte CC, padding
0x266d47: INT3 ; original byte CC, padding

; FUNCTION thunk_266d48 [0x266d48, 0x266d4c] | file +0xdc0 | ev_b5a719e3051b394916925482ba873b496bcb34a1988407017a610457c6c23429
thunk_266d48:
0x266d48: JMP 0x00a6abb0
; END FUNCTION thunk_266d48
0x266d4d: INT3 ; original byte CC, padding
0x266d4e: INT3 ; original byte CC, padding
0x266d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d50 [0x266d50, 0x266d54] | file +0xdc8 | ev_66a8e1394f6126ff166804a7b4117339bcc651d2b89fb684b756a8507994bdcf
thunk_266d50:
0x266d50: JMP 0x00a8ec10
; END FUNCTION thunk_266d50
0x266d55: INT3 ; original byte CC, padding
0x266d56: INT3 ; original byte CC, padding
0x266d57: INT3 ; original byte CC, padding

; FUNCTION thunk_266d58 [0x266d58, 0x266d5c] | file +0xdd0 | ev_8d5fb3fe87100ad2ba04f2e7e973447e53c90e2e406a2a38099b02122b3e9869
thunk_266d58:
0x266d58: JMP 0x00a8ee00
; END FUNCTION thunk_266d58
0x266d5d: INT3 ; original byte CC, padding
0x266d5e: INT3 ; original byte CC, padding
0x266d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d60 [0x266d60, 0x266d64] | file +0xdd8 | ev_5c2e94bdbf3948c0843d6ef9b29810c9a403493954312eb1180300ffe4515545
thunk_266d60:
0x266d60: JMP 0x00ab17b0
; END FUNCTION thunk_266d60
0x266d65: INT3 ; original byte CC, padding
0x266d66: INT3 ; original byte CC, padding
0x266d67: INT3 ; original byte CC, padding

; FUNCTION thunk_266d68 [0x266d68, 0x266d6c] | file +0xde0 | ev_6b4bef6b5f4bc828de6f53ae7485814885aa93b10e589f519b41bb23e3162800
thunk_266d68:
0x266d68: JMP 0x00ac07b0
; END FUNCTION thunk_266d68
0x266d6d: INT3 ; original byte CC, padding
0x266d6e: INT3 ; original byte CC, padding
0x266d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d70 [0x266d70, 0x266d74] | file +0xde8 | ev_bdce12fae65c55b0c7513e875b769c11d4280239f3d72373aaab9e9766afbaac
thunk_266d70:
0x266d70: JMP 0x00ac2af0
; END FUNCTION thunk_266d70
0x266d75: INT3 ; original byte CC, padding
0x266d76: INT3 ; original byte CC, padding
0x266d77: INT3 ; original byte CC, padding

; FUNCTION thunk_266d78 [0x266d78, 0x266d7c] | file +0xdf0 | ev_2680b60f9cb23d12b0b0ecaabdc08d843be220023793fdb28f8eee6ca7229a5d
thunk_266d78:
0x266d78: JMP 0x0011a750
; END FUNCTION thunk_266d78
0x266d7d: INT3 ; original byte CC, padding
0x266d7e: INT3 ; original byte CC, padding
0x266d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d80 [0x266d80, 0x266d84] | file +0xdf8 | ev_9af6b1d5b9f45778621c3ee062e58fca2c11a641863e209779c6d2054ed827fb
thunk_266d80:
0x266d80: JMP 0x00ae12a0
; END FUNCTION thunk_266d80
0x266d85: INT3 ; original byte CC, padding
0x266d86: INT3 ; original byte CC, padding
0x266d87: INT3 ; original byte CC, padding

; FUNCTION thunk_266d88 [0x266d88, 0x266d8c] | file +0xe00 | ev_8646eab0650b71883c11f7cdbab5c072bb7067fc4b651fe6d4ff533834d1400e
thunk_266d88:
0x266d88: JMP 0x00ae3400
; END FUNCTION thunk_266d88
0x266d8d: INT3 ; original byte CC, padding
0x266d8e: INT3 ; original byte CC, padding
0x266d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d90 [0x266d90, 0x266d94] | file +0xe08 | ev_ce1d8c6ab3f2ba46d018490e9359180b1341e43b3fbb4718438a184c713f0e55
thunk_266d90:
0x266d90: JMP 0x00ae3530
; END FUNCTION thunk_266d90
0x266d95: INT3 ; original byte CC, padding
0x266d96: INT3 ; original byte CC, padding
0x266d97: INT3 ; original byte CC, padding

; FUNCTION thunk_266d98 [0x266d98, 0x266d9c] | file +0xe10 | ev_bee1965f99007cbadf8a23a84f31148a5140aa1948ea011f5abff7a1602a8ffc
thunk_266d98:
0x266d98: JMP 0x00ae63c0
; END FUNCTION thunk_266d98
0x266d9d: INT3 ; original byte CC, padding
0x266d9e: INT3 ; original byte CC, padding
0x266d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266da0 [0x266da0, 0x266da4] | file +0xe18 | ev_021586ff9f269dedbb283491c1f5fef34dda25f2b408fa051a6134e2f95edd7d
thunk_266da0:
0x266da0: JMP 0x00b07ee0
; END FUNCTION thunk_266da0
0x266da5: INT3 ; original byte CC, padding
0x266da6: INT3 ; original byte CC, padding
0x266da7: INT3 ; original byte CC, padding

; FUNCTION thunk_266da8 [0x266da8, 0x266dac] | file +0xe20 | ev_661897bcc4d7235e95c9ece8b99683b3005da66501d8fb0d0dec17557ed248b7
thunk_266da8:
0x266da8: JMP 0x00b08190
; END FUNCTION thunk_266da8
0x266dad: INT3 ; original byte CC, padding
0x266dae: INT3 ; original byte CC, padding
0x266daf: INT3 ; original byte CC, padding

; FUNCTION thunk_266db0 [0x266db0, 0x266db4] | file +0xe28 | ev_a51657bb9adaf2b46acb636dab82aea2afbd24344b38ec9fc62f4a5cb75b4c3f
thunk_266db0:
0x266db0: JMP 0x00b08530
; END FUNCTION thunk_266db0
0x266db5: INT3 ; original byte CC, padding
0x266db6: INT3 ; original byte CC, padding
0x266db7: INT3 ; original byte CC, padding

; FUNCTION thunk_266db8 [0x266db8, 0x266dbc] | file +0xe30 | ev_7bd6608e24ea1d58427542d7fe6b513031f58af19140f4dc92741a8a3df9ee06
thunk_266db8:
0x266db8: JMP 0x00b08810
; END FUNCTION thunk_266db8
0x266dbd: INT3 ; original byte CC, padding
0x266dbe: INT3 ; original byte CC, padding
0x266dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc0 [0x266dc0, 0x266dc4] | file +0xe38 | ev_f09ac987114e244788a375bb4fcf7afd7ce4c964fa2b7bf4a6afafeb24830e03
thunk_266dc0:
0x266dc0: JMP 0x00b096a0
; END FUNCTION thunk_266dc0
0x266dc5: INT3 ; original byte CC, padding
0x266dc6: INT3 ; original byte CC, padding
0x266dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc8 [0x266dc8, 0x266dcc] | file +0xe40 | ev_dfc611f60173bd5832d71e5b7ec488439560cad77e88931e8d7c64545c725a45
thunk_266dc8:
0x266dc8: JMP 0x00b0b4f0
; END FUNCTION thunk_266dc8
0x266dcd: INT3 ; original byte CC, padding
0x266dce: INT3 ; original byte CC, padding
0x266dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd0 [0x266dd0, 0x266dd4] | file +0xe48 | ev_7ddaa2bd15e3b28548a4a9c293e73ca9bc9385206edec45703a1cbcbdfd80bbe
thunk_266dd0:
0x266dd0: JMP 0x001ef0f0
; END FUNCTION thunk_266dd0
0x266dd5: INT3 ; original byte CC, padding
0x266dd6: INT3 ; original byte CC, padding
0x266dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd8 [0x266dd8, 0x266ddc] | file +0xe50 | ev_0fd6893fc896b88e9e684bdcf1f2df886f46d9b79d06e9e8e6ac0024f32f3aed
thunk_266dd8:
0x266dd8: JMP 0x001f0060
; END FUNCTION thunk_266dd8
0x266ddd: INT3 ; original byte CC, padding
0x266dde: INT3 ; original byte CC, padding
0x266ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_266de0 [0x266de0, 0x266de4] | file +0xe58 | ev_f3e343791d1960e5d9ab7af96634393b0613d3a4f218256929e2f8033104ac7d
thunk_266de0:
0x266de0: JMP 0x0011b9b0
; END FUNCTION thunk_266de0
0x266de5: INT3 ; original byte CC, padding
0x266de6: INT3 ; original byte CC, padding
0x266de7: INT3 ; original byte CC, padding

; FUNCTION thunk_266de8 [0x266de8, 0x266dec] | file +0xe60 | ev_3256847e0571f12a26c9637636d3c4e54696270caa3cb68eeaae5a004b6a850f
thunk_266de8:
0x266de8: JMP 0x00b3b130
; END FUNCTION thunk_266de8
0x266ded: INT3 ; original byte CC, padding
0x266dee: INT3 ; original byte CC, padding
0x266def: INT3 ; original byte CC, padding

; FUNCTION thunk_266df0 [0x266df0, 0x266df4] | file +0xe68 | ev_a4d5a58087cc50f89a43a0c946224b55c585f59dde0dbe33701b96ad42036a63
thunk_266df0:
0x266df0: JMP 0x00b47a40
; END FUNCTION thunk_266df0
0x266df5: INT3 ; original byte CC, padding
0x266df6: INT3 ; original byte CC, padding
0x266df7: INT3 ; original byte CC, padding

; FUNCTION thunk_266df8 [0x266df8, 0x266dfc] | file +0xe70 | ev_6f9f553619e79fa117711aa664214bf407cb896470edfaed2fa80b975c20998e
thunk_266df8:
0x266df8: JMP 0x00b503c0
; END FUNCTION thunk_266df8
0x266dfd: INT3 ; original byte CC, padding
0x266dfe: INT3 ; original byte CC, padding
0x266dff: INT3 ; original byte CC, padding

; FUNCTION thunk_266e00 [0x266e00, 0x266e04] | file +0xe78 | ev_5bb72f86362afb6f491fa4944eac459ad974d898a733bc1701ce28ccee3366a3
thunk_266e00:
0x266e00: JMP 0x00b50f10
; END FUNCTION thunk_266e00
0x266e05: INT3 ; original byte CC, padding
0x266e06: INT3 ; original byte CC, padding
0x266e07: INT3 ; original byte CC, padding

; FUNCTION thunk_266e08 [0x266e08, 0x266e0c] | file +0xe80 | ev_4626fe3df4c069cb8aaac5384079b00f151bec62d68c9553e9ed7c8a4fd75c42
thunk_266e08:
0x266e08: JMP 0x00b50fb0
; END FUNCTION thunk_266e08
0x266e0d: INT3 ; original byte CC, padding
0x266e0e: INT3 ; original byte CC, padding
0x266e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e10 [0x266e10, 0x266e14] | file +0xe88 | ev_6d4603bdb31502b309b8835180f360ba961490d6273d111b6f01a175e50b17af
thunk_266e10:
0x266e10: JMP 0x00b510b0
; END FUNCTION thunk_266e10
0x266e15: INT3 ; original byte CC, padding
0x266e16: INT3 ; original byte CC, padding
0x266e17: INT3 ; original byte CC, padding

; FUNCTION thunk_266e18 [0x266e18, 0x266e1c] | file +0xe90 | ev_396af73daa982841b9f11dfa441c9e266f5a927b17b979985cd9ca8a0a5fdb68
thunk_266e18:
0x266e18: JMP 0x00b51190
; END FUNCTION thunk_266e18
0x266e1d: INT3 ; original byte CC, padding
0x266e1e: INT3 ; original byte CC, padding
0x266e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e20 [0x266e20, 0x266e24] | file +0xe98 | ev_fffc298efdf0b5e0e2e4378571521024ffa8e4aca9043008d1e61ce816203c66
thunk_266e20:
0x266e20: JMP 0x00b51290
; END FUNCTION thunk_266e20
0x266e25: INT3 ; original byte CC, padding
0x266e26: INT3 ; original byte CC, padding
0x266e27: INT3 ; original byte CC, padding

; FUNCTION thunk_266e28 [0x266e28, 0x266e2c] | file +0xea0 | ev_e8ef76577eaac3fab3c793b7168e9da12dc1aca576c7a71fa3f557e237c2e4e6
thunk_266e28:
0x266e28: JMP 0x00b512d0
; END FUNCTION thunk_266e28
0x266e2d: INT3 ; original byte CC, padding
0x266e2e: INT3 ; original byte CC, padding
0x266e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e30 [0x266e30, 0x266e34] | file +0xea8 | ev_4db31287f09e0ae97956058a96dfe8fd3e5528ddc6f25d486a7433aaa211b322
thunk_266e30:
0x266e30: JMP 0x00b51320
; END FUNCTION thunk_266e30
0x266e35: INT3 ; original byte CC, padding
0x266e36: INT3 ; original byte CC, padding
0x266e37: INT3 ; original byte CC, padding

; FUNCTION thunk_266e38 [0x266e38, 0x266e3c] | file +0xeb0 | ev_8ecf5e88ea4bb913a7d602178eeaa9d978ee9a7b5cd012aa8894b369ad41550d
thunk_266e38:
0x266e38: JMP 0x00b568a0
; END FUNCTION thunk_266e38
0x266e3d: INT3 ; original byte CC, padding
0x266e3e: INT3 ; original byte CC, padding
0x266e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e40 [0x266e40, 0x266e44] | file +0xeb8 | ev_8e75b68ffdcee668e3cc8060cc48f0eec1a2ba00367b0ea233f6c43f8765a777
thunk_266e40:
0x266e40: JMP 0x0009a0e0
; END FUNCTION thunk_266e40
0x266e45: INT3 ; original byte CC, padding
0x266e46: INT3 ; original byte CC, padding
0x266e47: INT3 ; original byte CC, padding

; FUNCTION thunk_266e48 [0x266e48, 0x266e4c] | file +0xec0 | ev_1449cb43daa60b62cab63d755b2a2ddd18efb47331cc52035ef5c3a04310475e
thunk_266e48:
0x266e48: JMP 0x00b6ae70
; END FUNCTION thunk_266e48
0x266e4d: INT3 ; original byte CC, padding
0x266e4e: INT3 ; original byte CC, padding
0x266e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e50 [0x266e50, 0x266e54] | file +0xec8 | ev_e5c757c666e1090a3ec377473f91b1bae5a6549c03db2270345898d87c0b067e
thunk_266e50:
0x266e50: JMP 0x00b6bb90
; END FUNCTION thunk_266e50
0x266e55: INT3 ; original byte CC, padding
0x266e56: INT3 ; original byte CC, padding
0x266e57: INT3 ; original byte CC, padding

; FUNCTION thunk_266e58 [0x266e58, 0x266e5c] | file +0xed0 | ev_8bf126f87d6604a0a94aed580fc13864f2b4286b1b4f03fb9394afeb53816a34
thunk_266e58:
0x266e58: JMP 0x00b6d980
; END FUNCTION thunk_266e58
0x266e5d: INT3 ; original byte CC, padding
0x266e5e: INT3 ; original byte CC, padding
0x266e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e60 [0x266e60, 0x266e64] | file +0xed8 | ev_7ca6cb21dc0b6f25698862493a2d6b95a19babe9efefa4bd242d6e79af31bb98
thunk_266e60:
0x266e60: JMP 0x00b6daa0
; END FUNCTION thunk_266e60
0x266e65: INT3 ; original byte CC, padding
0x266e66: INT3 ; original byte CC, padding
0x266e67: INT3 ; original byte CC, padding

; FUNCTION thunk_266e68 [0x266e68, 0x266e6c] | file +0xee0 | ev_d64bbe0b19de218b1913ecc94394fde4fbf612ee3092f588edf5fd97efaed577
thunk_266e68:
0x266e68: JMP 0x00b6e180
; END FUNCTION thunk_266e68
0x266e6d: INT3 ; original byte CC, padding
0x266e6e: INT3 ; original byte CC, padding
0x266e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e70 [0x266e70, 0x266e74] | file +0xee8 | ev_f2be95566a6f3f55ffa0867891aa84abb05e686b116e083938852c5ad30c9053
thunk_266e70:
0x266e70: JMP 0x00b71320
; END FUNCTION thunk_266e70
0x266e75: INT3 ; original byte CC, padding
0x266e76: INT3 ; original byte CC, padding
0x266e77: INT3 ; original byte CC, padding

; FUNCTION thunk_266e78 [0x266e78, 0x266e7c] | file +0xef0 | ev_ea30d5c8cc955f26bc1887e696b4cdd9d0f470d328a1f7fcff151a10e904bf5b
thunk_266e78:
0x266e78: JMP 0x00b71370
; END FUNCTION thunk_266e78
0x266e7d: INT3 ; original byte CC, padding
0x266e7e: INT3 ; original byte CC, padding
0x266e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e80 [0x266e80, 0x266e84] | file +0xef8 | ev_c63e3871926c8e72b579d264e85f38382d783da0d0b04d4be00b01031822fb25
thunk_266e80:
0x266e80: JMP 0x00b713c0
; END FUNCTION thunk_266e80
0x266e85: INT3 ; original byte CC, padding
0x266e86: INT3 ; original byte CC, padding
0x266e87: INT3 ; original byte CC, padding

; FUNCTION thunk_266e88 [0x266e88, 0x266e8c] | file +0xf00 | ev_197d591bf203fc30e38d796f069d211a923ba60199a8f018b65658b3f5f32eb8
thunk_266e88:
0x266e88: JMP 0x00b71410
; END FUNCTION thunk_266e88
0x266e8d: INT3 ; original byte CC, padding
0x266e8e: INT3 ; original byte CC, padding
0x266e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e90 [0x266e90, 0x266e94] | file +0xf08 | ev_06c505a8945df64cf395d995cbc9ef4d39ffbb334ac8940eaf15b821d76a2e1f
thunk_266e90:
0x266e90: JMP 0x00b71960
; END FUNCTION thunk_266e90
0x266e95: INT3 ; original byte CC, padding
0x266e96: INT3 ; original byte CC, padding
0x266e97: INT3 ; original byte CC, padding

; FUNCTION thunk_266e98 [0x266e98, 0x266e9c] | file +0xf10 | ev_92cf65c6497d81c189072201bc92b6d001023852b15682c6e7045a41c5b4996f
thunk_266e98:
0x266e98: JMP 0x00b719d0
; END FUNCTION thunk_266e98
0x266e9d: INT3 ; original byte CC, padding
0x266e9e: INT3 ; original byte CC, padding
0x266e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea0 [0x266ea0, 0x266ea4] | file +0xf18 | ev_645a6b9f18cf77202c1f3379a167a483992f1abe64ade57cf4679057b81f8132
thunk_266ea0:
0x266ea0: JMP 0x00b71a40
; END FUNCTION thunk_266ea0
0x266ea5: INT3 ; original byte CC, padding
0x266ea6: INT3 ; original byte CC, padding
0x266ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea8 [0x266ea8, 0x266eac] | file +0xf20 | ev_92f8a51544605bc7f4dfb2d3f45f27341d959314143b088056208c2ce0daf354
thunk_266ea8:
0x266ea8: JMP 0x00b71ab0
; END FUNCTION thunk_266ea8
0x266ead: INT3 ; original byte CC, padding
0x266eae: INT3 ; original byte CC, padding
0x266eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb0 [0x266eb0, 0x266eb4] | file +0xf28 | ev_86e42877162f49237f5ee3cc1fa9b5e7317d73fd40d6536966932f7792fb38d9
thunk_266eb0:
0x266eb0: JMP 0x00b72620
; END FUNCTION thunk_266eb0
0x266eb5: INT3 ; original byte CC, padding
0x266eb6: INT3 ; original byte CC, padding
0x266eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb8 [0x266eb8, 0x266ebc] | file +0xf30 | ev_001011f1bff1e10ce4ca0cb454363095736c0cef7656de7f95cc7986ab85c6f4
thunk_266eb8:
0x266eb8: JMP 0x00b72860
; END FUNCTION thunk_266eb8
0x266ebd: INT3 ; original byte CC, padding
0x266ebe: INT3 ; original byte CC, padding
0x266ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec0 [0x266ec0, 0x266ec4] | file +0xf38 | ev_a62bc6806ab674d0ae71f374d1e8ebd1b76781dbf590ebc9087c31322e2462e2
thunk_266ec0:
0x266ec0: JMP 0x00b791d0
; END FUNCTION thunk_266ec0
0x266ec5: INT3 ; original byte CC, padding
0x266ec6: INT3 ; original byte CC, padding
0x266ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec8 [0x266ec8, 0x266ecc] | file +0xf40 | ev_b52289221c273125b1dbccaf11fa3a6fd7e6246284d8522934c98ec91d8d206e
thunk_266ec8:
0x266ec8: JMP 0x00b79290
; END FUNCTION thunk_266ec8
0x266ecd: INT3 ; original byte CC, padding
0x266ece: INT3 ; original byte CC, padding
0x266ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed0 [0x266ed0, 0x266ed4] | file +0xf48 | ev_4047cbc663795c1289163dbe21ac08af15171a76058b17f7e22314c363bc8a5c
thunk_266ed0:
0x266ed0: JMP 0x00b793f0
; END FUNCTION thunk_266ed0
0x266ed5: INT3 ; original byte CC, padding
0x266ed6: INT3 ; original byte CC, padding
0x266ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed8 [0x266ed8, 0x266edc] | file +0xf50 | ev_d40229b3fb879733cf4bb36ba96438639d574a7aaaf01b902462653bec434bc0
thunk_266ed8:
0x266ed8: JMP 0x00b79420
; END FUNCTION thunk_266ed8
0x266edd: INT3 ; original byte CC, padding
0x266ede: INT3 ; original byte CC, padding
0x266edf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee0 [0x266ee0, 0x266ee4] | file +0xf58 | ev_9c460fc45aabe04141735909271220fd15d8255d47b0abc66e0f74511b093105
thunk_266ee0:
0x266ee0: JMP 0x00b79460
; END FUNCTION thunk_266ee0
0x266ee5: INT3 ; original byte CC, padding
0x266ee6: INT3 ; original byte CC, padding
0x266ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee8 [0x266ee8, 0x266eec] | file +0xf60 | ev_140eeb12e1434a7dc0c137ae75e06af03c16e376698cbc46dfa3d10d190ea107
thunk_266ee8:
0x266ee8: JMP 0x00b79480
; END FUNCTION thunk_266ee8
0x266eed: INT3 ; original byte CC, padding
0x266eee: INT3 ; original byte CC, padding
0x266eef: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef0 [0x266ef0, 0x266ef4] | file +0xf68 | ev_43ad813f5b2b8f40c57dc086f2c412e940abf4ceca224978018e13b0f33a7820
thunk_266ef0:
0x266ef0: JMP 0x00b79490
; END FUNCTION thunk_266ef0
0x266ef5: INT3 ; original byte CC, padding
0x266ef6: INT3 ; original byte CC, padding
0x266ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef8 [0x266ef8, 0x266efc] | file +0xf70 | ev_bfec69b84024565b47c924a86acddbcc1709c8816cf063cd4839f05a0efb3a66
thunk_266ef8:
0x266ef8: JMP 0x00b794b0
; END FUNCTION thunk_266ef8
0x266efd: INT3 ; original byte CC, padding
0x266efe: INT3 ; original byte CC, padding
0x266eff: INT3 ; original byte CC, padding

; FUNCTION thunk_266f00 [0x266f00, 0x266f04] | file +0xf78 | ev_c1e937b17f609327e5a32dc651db69965da91c36afed6b6cab4eeb2ddbc66ade
thunk_266f00:
0x266f00: JMP 0x00b795f0
; END FUNCTION thunk_266f00
0x266f05: INT3 ; original byte CC, padding
0x266f06: INT3 ; original byte CC, padding
0x266f07: INT3 ; original byte CC, padding

; FUNCTION thunk_266f08 [0x266f08, 0x266f0c] | file +0xf80 | ev_54cd41ab36c1d893c67c9e91dd3bac8054c2a093aa3ff842a2b4ac493f1af467
thunk_266f08:
0x266f08: JMP 0x00b79620
; END FUNCTION thunk_266f08
0x266f0d: INT3 ; original byte CC, padding
0x266f0e: INT3 ; original byte CC, padding
0x266f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f10 [0x266f10, 0x266f14] | file +0xf88 | ev_5f150108a282e0acbbf087f0447711d5f934b501ef033bcb4651c0a0bff06097
thunk_266f10:
0x266f10: JMP 0x00b79830
; END FUNCTION thunk_266f10
0x266f15: INT3 ; original byte CC, padding
0x266f16: INT3 ; original byte CC, padding
0x266f17: INT3 ; original byte CC, padding

; FUNCTION thunk_266f18 [0x266f18, 0x266f1c] | file +0xf90 | ev_2da7c7533a24f08c54a5ec5ef15fbab9a37ad41832c00dd6f045c392f203f1ab
thunk_266f18:
0x266f18: JMP 0x00b80e90
; END FUNCTION thunk_266f18
0x266f1d: INT3 ; original byte CC, padding
0x266f1e: INT3 ; original byte CC, padding
0x266f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f20 [0x266f20, 0x266f24] | file +0xf98 | ev_05007cf428f229f9acad957f05bfd0d915fc31a6bd8f53b6d71023441c636a5b
thunk_266f20:
0x266f20: JMP 0x00b80f20
; END FUNCTION thunk_266f20
0x266f25: INT3 ; original byte CC, padding
0x266f26: INT3 ; original byte CC, padding
0x266f27: INT3 ; original byte CC, padding

; FUNCTION thunk_266f28 [0x266f28, 0x266f2c] | file +0xfa0 | ev_4af2057d7b385aba4d6285ec88eaf49753f05817a916e45e8dad4635faa00a15
thunk_266f28:
0x266f28: JMP 0x00b99520
; END FUNCTION thunk_266f28
0x266f2d: INT3 ; original byte CC, padding
0x266f2e: INT3 ; original byte CC, padding
0x266f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f30 [0x266f30, 0x266f34] | file +0xfa8 | ev_7031656535bffe683040d3e65d44680a84556f146e6c8250261208dfd70560bd
thunk_266f30:
0x266f30: JMP 0x00b99600
; END FUNCTION thunk_266f30
0x266f35: INT3 ; original byte CC, padding
0x266f36: INT3 ; original byte CC, padding
0x266f37: INT3 ; original byte CC, padding

; FUNCTION thunk_266f38 [0x266f38, 0x266f3c] | file +0xfb0 | ev_1c665d019d7d1f2e53f07e261e031cb899f97da44155def954621c2a02570d06
thunk_266f38:
0x266f38: JMP 0x00b9ce30
; END FUNCTION thunk_266f38
0x266f3d: INT3 ; original byte CC, padding
0x266f3e: INT3 ; original byte CC, padding
0x266f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f40 [0x266f40, 0x266f44] | file +0xfb8 | ev_712648e7bb521b61edaa5cabe0db3056f43183e8708033b54aa034674b67ec39
thunk_266f40:
0x266f40: JMP 0x00bf5c40
; END FUNCTION thunk_266f40
0x266f45: INT3 ; original byte CC, padding
0x266f46: INT3 ; original byte CC, padding
0x266f47: INT3 ; original byte CC, padding

; FUNCTION thunk_266f48 [0x266f48, 0x266f4c] | file +0xfc0 | ev_ecc803a493b1fccc01b711533b2c9a2508d39c49fd905d6689592f58ab23fd2e
thunk_266f48:
0x266f48: JMP 0x00bfe620
; END FUNCTION thunk_266f48
0x266f4d: INT3 ; original byte CC, padding
0x266f4e: INT3 ; original byte CC, padding
0x266f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f50 [0x266f50, 0x266f54] | file +0xfc8 | ev_03cc54ab31ccc520062b136e5769020cebdfb08c0270e94138249b5af9660c5b
thunk_266f50:
0x266f50: JMP 0x00bfef50
; END FUNCTION thunk_266f50
0x266f55: INT3 ; original byte CC, padding
0x266f56: INT3 ; original byte CC, padding
0x266f57: INT3 ; original byte CC, padding

; FUNCTION thunk_266f58 [0x266f58, 0x266f5c] | file +0xfd0 | ev_98503194680b5b3c8554d5b9cf932e290985606a681d50620a2ec04984c2ec5c
thunk_266f58:
0x266f58: JMP 0x00bfefa0
; END FUNCTION thunk_266f58
0x266f5d: INT3 ; original byte CC, padding
0x266f5e: INT3 ; original byte CC, padding
0x266f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f60 [0x266f60, 0x266f64] | file +0xfd8 | ev_b59c9075b71bcf6d9e1b7028c4325ca035da423d9c7567967949cb9421601b48
thunk_266f60:
0x266f60: JMP 0x00bff050
; END FUNCTION thunk_266f60
0x266f65: INT3 ; original byte CC, padding
0x266f66: INT3 ; original byte CC, padding
0x266f67: INT3 ; original byte CC, padding

; FUNCTION thunk_266f68 [0x266f68, 0x266f6c] | file +0xfe0 | ev_8365df9cf079d90dcca0b3cc08c697935064c4c8ed974c3515e1b4fa381c7611
thunk_266f68:
0x266f68: JMP 0x00c0d180
; END FUNCTION thunk_266f68
0x266f6d: INT3 ; original byte CC, padding
0x266f6e: INT3 ; original byte CC, padding
0x266f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f70 [0x266f70, 0x266f74] | file +0xfe8 | ev_ccee922592c335279de79cd9aa606fdbcd9169a04fe4fa1dd80e272430eeba58
thunk_266f70:
0x266f70: JMP 0x00c327f0
; END FUNCTION thunk_266f70
0x266f75: INT3 ; original byte CC, padding
0x266f76: INT3 ; original byte CC, padding
0x266f77: INT3 ; original byte CC, padding

; FUNCTION thunk_266f78 [0x266f78, 0x266f7c] | file +0xff0 | ev_adf5b626a55425949b3e14eb88a6b151c2d534648b904e1b408b9d640aa34a9a
thunk_266f78:
0x266f78: JMP 0x00c32c70
; END FUNCTION thunk_266f78
0x266f7d: INT3 ; original byte CC, padding
0x266f7e: INT3 ; original byte CC, padding
0x266f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f80 [0x266f80, 0x266f84] | file +0xff8 | ev_23a75b00a0d112a651e95c44dd54487f36c7f2b35308b90ea97aa3cd0c987b02
thunk_266f80:
0x266f80: JMP 0x00c34c70
; END FUNCTION thunk_266f80
0x266f85: INT3 ; original byte CC, padding
0x266f86: INT3 ; original byte CC, padding
0x266f87: INT3 ; original byte CC, padding



; ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_004a31a0 RVA 0x265f88 | Evidence ev_945b3fa14b1db0a237666aa1ef10aca1f595f78b99b753ebbabe64580e66fdd9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
<EXTERNAL>::thunk_EXT_FUN_004a31a0:
0x265f88: JMP 0x004a31a0


; ===== TARGET: handler_667_body RVA 0x4a31a0 | Evidence ev_5c6f3d82be891f04e277b0b9855430becdd8c003a447b3ae38846b1f3d033af1 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
handler_667_body:
0x4a31a0: PUSH RBP
0x4a31a1: MOV RBP, RSP
0x4a31a4: PUSH R15
0x4a31a6: PUSH R14
0x4a31a8: PUSH R13
0x4a31aa: PUSH R12
0x4a31ac: PUSH RBX
0x4a31ad: SUB RSP, 0x68
0x4a31b1: LEA R14, [0x391c310]
0x4a31b8: MOV RBX, RDI
0x4a31bb: MOV R15, RSI
0x4a31be: MOV RAX, qword ptr [R14]
0x4a31c1: MOV qword ptr [RBP + -0x30], RAX
0x4a31c5: MOV RDI, qword ptr [RDI + 0x140]
0x4a31cc: CALL 0x00608f90
0x4a31d1: TEST EAX, EAX
0x4a31d3: JZ 0x004a34c7
0x4a31d9: CMP qword ptr [R15], 0x0
0x4a31dd: JZ 0x004a34d1
0x4a31e3: MOV RDI, qword ptr [R15 + 0x8]
0x4a31e7: CALL 0x00782a40
0x4a31ec: CMP EAX, -0x1
0x4a31ef: JZ 0x004a35c4
0x4a31f5: MOV ECX, EAX
0x4a31f7: MOV EAX, 0x16
0x4a31fc: LEA EDX, [RCX + -0x2711]
0x4a3202: CMP EDX, 0xffffd8f0
0x4a3208: JC 0x004a3602
0x4a320e: MOV RAX, qword ptr [R15]
0x4a3211: SHL ECX, 0x3
0x4a3214: LEA RDI, [0x3589e60]
0x4a321b: MOV qword ptr [RBP + -0x88], R15
0x4a3222: MOV qword ptr [RBP + -0x80], 0x0
0x4a322a: XOR ESI, ESI
0x4a322c: XOR EDX, EDX
0x4a322e: MOV qword ptr [RBP + -0x70], RAX
0x4a3232: LEA EAX, [RCX + RCX*0x4]
0x4a3235: LEA RCX, [RBP + -0x70]
0x4a3239: MOV qword ptr [RBP + -0x60], RCX
0x4a323d: MOV dword ptr [RBP + -0x58], 0x1
0x4a3244: MOV qword ptr [RBP + -0x50], 0x0
0x4a324c: XOR ECX, ECX
0x4a324e: MOV qword ptr [RBP + -0x48], RAX
0x4a3252: MOV qword ptr [RBP + -0x40], 0x0
0x4a325a: MOV qword ptr [RBP + -0x68], RAX
0x4a325e: MOV qword ptr [RBP + -0x38], RBX
0x4a3262: CALL 0x00c4b350
0x4a3267: MOV R15, qword ptr [0x03589e80]
0x4a326e: TEST R15, R15
0x4a3271: JZ 0x004a35cb
0x4a3277: LEA R13, [0x1ac8120]
0x4a327e: MOV qword ptr [RBP + -0x80], 0x0
0x4a3286: JMP 0x004a32aa
0x4a3290: MOV RDI, R12
0x4a3293: XOR ESI, ESI
0x4a3295: XOR EDX, EDX
0x4a3297: XOR ECX, ECX
0x4a3299: CALL 0x004c6fa0
0x4a329e: MOV R15, qword ptr [R15]
0x4a32a1: TEST R15, R15
0x4a32a4: JZ 0x004a35cb
0x4a32aa: LEA R12, [R15 + 0x148]
0x4a32b1: XOR ESI, ESI
0x4a32b3: XOR EDX, EDX
0x4a32b5: XOR ECX, ECX
0x4a32b7: MOV RDI, R12
0x4a32ba: CALL 0x004c6a00
0x4a32bf: CMP dword ptr [R15 + 0x5d0], 0x2
0x4a32c7: JC 0x004a3290
0x4a32c9: NOP dword ptr [RAX]
0x4a32d0: CMP dword ptr [R15 + 0xb8], 0x1
0x4a32d8: JNZ 0x004a3290
0x4a32da: MOVSXD RBX, dword ptr [R15 + 0xb48]
0x4a32e1: MOV RDI, R12
0x4a32e4: XOR ESI, ESI
0x4a32e6: XOR EDX, EDX
0x4a32e8: XOR ECX, ECX
0x4a32ea: CALL 0x004c6fa0
0x4a32ef: MOV RAX, RBX
0x4a32f2: MOV RSI, R13
0x4a32f5: MOV EDX, 0x102
0x4a32fa: SHL RAX, 0x3
0x4a32fe: LEA RDI, [RAX + RAX*0x4]
0x4a3302: CALL 0x00c08b50
0x4a3307: MOV RDI, R12
0x4a330a: MOV R14, RAX
0x4a330d: XOR ESI, ESI
0x4a330f: XOR EDX, EDX
0x4a3311: XOR ECX, ECX
0x4a3313: CALL 0x004c6a00
0x4a3318: CMP EBX, dword ptr [R15 + 0xb48]
0x4a331f: JGE 0x004a3357
0x4a3321: MOV RDI, R12
0x4a3324: XOR ESI, ESI
0x4a3326: XOR EDX, EDX
0x4a3328: XOR ECX, ECX
0x4a332a: CALL 0x004c6fa0
0x4a332f: MOV RDI, R14
0x4a3332: MOV RSI, R13
0x4a3335: CALL 0x00c08df0
0x4a333a: MOV RDI, R12
0x4a333d: XOR ESI, ESI
0x4a333f: XOR EDX, EDX
0x4a3341: XOR ECX, ECX
0x4a3343: CALL 0x004c6a00
0x4a3348: CMP dword ptr [R15 + 0xb8], 0x1
0x4a3350: JZ 0x004a32da
0x4a3352: JMP 0x004a3290
0x4a3357: LEA RBX, [R15 + 0x38]
0x4a335b: XOR ESI, ESI
0x4a335d: XOR EDX, EDX
0x4a335f: XOR ECX, ECX
0x4a3361: MOV RDI, RBX
0x4a3364: CALL 0x004c7190
0x4a3369: MOV R13, qword ptr [R15 + 0x10]
0x4a336d: TEST R13, R13
0x4a3370: JZ 0x004a3458
0x4a3376: MOV qword ptr [RBP + -0x90], RBX
0x4a337d: MOV RBX, R14
0x4a3380: MOV dword ptr [RBP + -0x74], 0x0
0x4a3387: JMP 0x004a33fc
0x4a3390: MOV EAX, dword ptr [R15 + 0xbc]
0x4a3397: XOR ESI, ESI
0x4a3399: XOR EDX, EDX
0x4a339b: XOR ECX, ECX
0x4a339d: MOV dword ptr [RBX], EAX
0x4a339f: MOV EAX, dword ptr [R13 + 0x9c]
0x4a33a6: MOV dword ptr [RBX + 0x4], EAX
0x4a33a9: MOV RAX, qword ptr [R13 + 0x5b0]
0x4a33b0: MOV qword ptr [RBX + 0x8], RAX
0x4a33b4: MOV RAX, qword ptr [R13 + 0x5b8]
0x4a33bb: MOV qword ptr [RBX + 0x10], RAX
0x4a33bf: MOV RAX, qword ptr [R13 + 0x5c0]
0x4a33c6: MOV qword ptr [RBX + 0x18], RAX
0x4a33ca: MOV RAX, qword ptr [R13 + 0x5c8]
0x4a33d1: MOV qword ptr [RBX + 0x20], RAX
0x4a33d5: MOV RDI, qword ptr [R13]
0x4a33d9: ADD RDI, 0x18
0x4a33dd: CALL 0x004c7520
0x4a33e2: INC dword ptr [RBP + -0x74]
0x4a33e5: MOV RAX, qword ptr [RBP + -0x80]
0x4a33e9: ADD RBX, 0x28
0x4a33ed: INC EAX
0x4a33ef: MOV qword ptr [RBP + -0x80], RAX
0x4a33f3: MOV R13, qword ptr [R13 + 0x10]
0x4a33f7: TEST R13, R13
0x4a33fa: JZ 0x004a3443
0x4a33fc: MOV RDI, R13
0x4a33ff: LEA RDX, [0x12aa1cd]
0x4a3406: MOV ECX, 0x72f
0x4a340b: XOR ESI, ESI
0x4a340d: CALL 0x004c78b0
0x4a3412: CMP qword ptr [R13 + 0x5b0], 0x0
0x4a341a: JNZ 0x004a3390
0x4a3420: CMP qword ptr [R13 + 0x5c0], 0x0
0x4a3428: JNZ 0x004a3390
0x4a342e: MOV RDI, qword ptr [R13]
0x4a3432: XOR ESI, ESI
0x4a3434: XOR EDX, EDX
0x4a3436: XOR ECX, ECX
0x4a3438: ADD RDI, 0x18
0x4a343c: CALL 0x004c7520
0x4a3441: JMP 0x004a33f3
0x4a3443: MOVSXD RAX, dword ptr [RBP + -0x74]
0x4a3447: MOV RBX, qword ptr [RBP + -0x90]
0x4a344e: SHL RAX, 0x3
0x4a3452: LEA R13, [RAX + RAX*0x4]
0x4a3456: JMP 0x004a345b
0x4a3458: XOR R13D, R13D
0x4a345b: MOV RDI, RBX
0x4a345e: XOR ESI, ESI
0x4a3460: XOR EDX, EDX
0x4a3462: XOR ECX, ECX
0x4a3464: CALL 0x004c7520
0x4a3469: MOV RDI, R12
0x4a346c: XOR ESI, ESI
0x4a346e: XOR EDX, EDX
0x4a3470: XOR ECX, ECX
0x4a3472: CALL 0x004c6fa0
0x4a3477: MOV RAX, qword ptr [RBP + -0x48]
0x4a347b: MOV RDI, R14
0x4a347e: LEA RDX, [RBP + -0x60]
0x4a3482: CMP RAX, R13
0x4a3485: CMOVC R13, RAX
0x4a3489: MOV ESI, R13D
0x4a348c: CALL 0x00782520
0x4a3491: LEA R13, [0x1ac8120]
0x4a3498: MOV RDI, R14
0x4a349b: MOV R12D, EAX
0x4a349e: MOV RSI, R13
0x4a34a1: CALL 0x00c08df0
0x4a34a6: TEST R12D, R12D
0x4a34a9: JZ 0x004a329e
0x4a34af: LEA RDI, [0x3589e60]
0x4a34b6: XOR ESI, ESI
0x4a34b8: XOR EDX, EDX
0x4a34ba: CALL 0x00c4c300
0x4a34bf: MOV EAX, R12D
0x4a34c2: JMP 0x004a35fb
0x4a34c7: MOV EAX, 0x4e
0x4a34cc: JMP 0x004a3602
0x4a34d1: LEA RDI, [0x3589e60]
0x4a34d8: MOV qword ptr [RBP + -0x88], R15
0x4a34df: XOR EBX, EBX
0x4a34e1: XOR ESI, ESI
0x4a34e3: XOR EDX, EDX
0x4a34e5: XOR ECX, ECX
0x4a34e7: CALL 0x00c4b350
0x4a34ec: MOV R13, qword ptr [0x03589e80]
0x4a34f3: TEST R13, R13
0x4a34f6: JZ 0x004a35a9
0x4a34fc: LEA R14, [0x12aa1cd]
0x4a3503: XOR EBX, EBX
0x4a3505: JMP 0x004a352b
0x4a3510: MOV RDI, R15
0x4a3513: XOR ESI, ESI
0x4a3515: XOR EDX, EDX
0x4a3517: XOR ECX, ECX
0x4a3519: CALL 0x004c6fa0
0x4a351e: MOV R13, qword ptr [R13]
0x4a3522: TEST R13, R13
0x4a3525: JZ 0x004a35a9
0x4a352b: LEA R15, [R13 + 0x148]
0x4a3532: XOR ESI, ESI
0x4a3534: XOR EDX, EDX
0x4a3536: XOR ECX, ECX
0x4a3538: MOV RDI, R15
0x4a353b: CALL 0x004c6a00
0x4a3540: CMP dword ptr [R13 + 0x5d0], 0x2
0x4a3548: JC 0x004a3510
0x4a354a: CMP dword ptr [R13 + 0xb8], 0x1
0x4a3552: JNZ 0x004a3510
0x4a3554: MOV R12, qword ptr [R13 + 0x10]
0x4a3558: JMP 0x004a357a
0x4a3560: INC EBX
0x4a3562: MOV RDI, qword ptr [R12]
0x4a3566: XOR ESI, ESI
0x4a3568: XOR EDX, EDX
0x4a356a: XOR ECX, ECX
0x4a356c: ADD RDI, 0x18
0x4a3570: CALL 0x004c7520
0x4a3575: MOV R12, qword ptr [R12 + 0x10]
0x4a357a: TEST R12, R12
0x4a357d: JZ 0x004a3510
0x4a357f: MOV RDI, R12
0x4a3582: MOV RDX, R14
0x4a3585: MOV ECX, 0x6ed
0x4a358a: XOR ESI, ESI
0x4a358c: CALL 0x004c78b0
0x4a3591: CMP qword ptr [R12 + 0x5b0], 0x0
0x4a359a: JNZ 0x004a3560
0x4a359c: CMP qword ptr [R12 + 0x5c0], 0x0
0x4a35a5: JNZ 0x004a3560
0x4a35a7: JMP 0x004a3562
0x4a35a9: LEA RDI, [0x3589e60]
0x4a35b0: XOR ESI, ESI
0x4a35b2: XOR EDX, EDX
0x4a35b4: CALL 0x00c4c300
0x4a35b9: MOV RAX, qword ptr [RBP + -0x88]
0x4a35c0: MOV ESI, EBX
0x4a35c2: JMP 0x004a35e6
0x4a35c4: MOV EAX, 0xe
0x4a35c9: JMP 0x004a3602
0x4a35cb: LEA RDI, [0x3589e60]
0x4a35d2: XOR ESI, ESI
0x4a35d4: XOR EDX, EDX
0x4a35d6: CALL 0x00c4c300
0x4a35db: MOV RAX, qword ptr [RBP + -0x88]
0x4a35e2: MOV RSI, qword ptr [RBP + -0x80]
0x4a35e6: MOV RDI, qword ptr [RAX + 0x8]
0x4a35ea: CALL 0x00259790
0x4a35ef: MOV ECX, EAX
0x4a35f1: TEST EAX, EAX
0x4a35f3: MOV EAX, 0xe
0x4a35f8: CMOVZ EAX, ECX
0x4a35fb: LEA R14, [0x391c310]
0x4a3602: MOV RCX, qword ptr [R14]
0x4a3605: CMP RCX, qword ptr [RBP + -0x30]
0x4a3609: JNZ 0x004a361a
0x4a360b: ADD RSP, 0x68
0x4a360f: POP RBX
0x4a3610: POP R12
0x4a3612: POP R13
0x4a3614: POP R14
0x4a3616: POP R15
0x4a3618: POP RBP
0x4a3619: RET
0x4a361a: CALL 0x006fd6b0
0x4a361f: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3630 RVA 0x4a3630 | Evidence ev_1f2eb6ebfb7f6cd0b7f2115c5232ee01e5c81e30f370e816985f23c6a15cc824 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3630:
0x4a3630: PUSH RBP
0x4a3631: MOV RBP, RSP
0x4a3634: POP RBP
0x4a3635: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3640 RVA 0x4a3640 | Evidence ev_19188f123cd393ef691d3b4b12fec0cb2cfa3a6206f54f072cf7edf687e0622d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3640:
0x4a3640: PUSH RBP
0x4a3641: MOV RBP, RSP
0x4a3644: PUSH R15
0x4a3646: PUSH R14
0x4a3648: PUSH RBX
0x4a3649: SUB RSP, 0x18
0x4a364d: LEA R15, [0x391c310]
0x4a3654: MOV RBX, RDI
0x4a3657: MOV RAX, qword ptr [R15]
0x4a365a: MOV qword ptr [RBP + -0x20], RAX
0x4a365e: MOV qword ptr [RBP + -0x30], 0x0
0x4a3666: MOV RAX, qword ptr [RDI + 0x340]
0x4a366d: MOV word ptr [RAX + 0xc], 0x0
0x4a3673: TEST RSI, RSI
0x4a3676: JZ 0x004a36b1
0x4a3678: LEA RDI, [RBP + -0x28]
0x4a367c: MOV RSI, RBX
0x4a367f: CALL 0x00b56140
0x4a3684: TEST EAX, EAX
0x4a3686: JZ 0x004a3719
0x4a368c: LEA RDI, [0x1593014]
0x4a3693: LEA RCX, [0x13afe9f]
0x4a369a: MOV ESI, 0x6f
0x4a369f: MOV EDX, EAX
0x4a36a1: MOV EBX, EAX
0x4a36a3: XOR EAX, EAX
0x4a36a5: CALL 0x006f7a90
0x4a36aa: MOV EAX, EBX
0x4a36ac: JMP 0x004a37d8
0x4a36b1: MOV RSI, qword ptr [RBX + 0x378]
0x4a36b8: MOV RDI, RBX
0x4a36bb: XOR EDX, EDX
0x4a36bd: CALL 0x005aafb0
0x4a36c2: TEST EAX, EAX
0x4a36c4: JNZ 0x004a37d8
0x4a36ca: LEA R14, [RBX + 0x2e0]
0x4a36d1: MOV RSI, RBX
0x4a36d4: MOV RDI, R14
0x4a36d7: CALL 0x00593190
0x4a36dc: TEST EAX, EAX
0x4a36de: JNZ 0x004a37d8
0x4a36e4: MOV RDI, qword ptr [R14]
0x4a36e7: MOV qword ptr [RBP + -0x28], RDI
0x4a36eb: TEST RDI, RDI
0x4a36ee: JNZ 0x004a3722
0x4a36f0: LEA RDI, [0x1593014]
0x4a36f7: LEA RDX, [0x1351368]
0x4a36fe: MOV ESI, 0x88
0x4a3703: MOV R8, RBX
0x4a3706: XOR ECX, ECX
0x4a3708: XOR EAX, EAX
0x4a370a: CALL 0x006f79f0
0x4a370f: MOV EAX, 0x3002
0x4a3714: JMP 0x004a37d8
0x4a3719: MOV RDI, qword ptr [RBP + -0x28]
0x4a371d: TEST RDI, RDI
0x4a3720: JZ 0x004a36f0
0x4a3722: LEA RSI, [RBP + -0x30]
0x4a3726: MOV EDX, 0x10
0x4a372b: CALL 0x0032b460
0x4a3730: MOV R14D, EAX
0x4a3733: TEST EAX, EAX
0x4a3735: JNZ 0x004a37aa
0x4a3737: MOV RDI, qword ptr [RBP + -0x30]
0x4a373b: CMP byte ptr [RDI + 0x9], 0x1
0x4a373f: JNZ 0x004a377e
0x4a3741: CALL 0x009bd8b0
0x4a3746: MOV RAX, qword ptr [RBP + -0x30]
0x4a374a: XOR ECX, ECX
0x4a374c: XOR EDX, EDX
0x4a374e: MOV R14D, 0x4005
0x4a3754: MOV RSI, RBX
0x4a3757: CMP qword ptr [RAX + 0x10], 0x0
0x4a375c: MOV RAX, qword ptr [RBX + 0x340]
0x4a3763: SETNZ DL
0x4a3766: CMOVNZ R14D, ECX
0x4a376a: MOV word ptr [RAX + 0xa], DX
0x4a376e: MOV EDX, 0x1
0x4a3773: MOV RDI, qword ptr [RBP + -0x30]
0x4a3777: CALL 0x005aaca0
0x4a377c: JMP 0x004a37aa
0x4a377e: MOV RCX, qword ptr [RBP + -0x28]
0x4a3782: LEA RDI, [0x1593014]
0x4a3789: LEA RDX, [0x13667db]
0x4a3790: MOV ESI, 0x9b
0x4a3795: MOV R8, RBX
0x4a3798: XOR EAX, EAX
0x4a379a: MOVZX R9D, byte ptr [RCX + 0x9]
0x4a379f: CALL 0x006f79f0
0x4a37a4: MOV R14D, 0x3003
0x4a37aa: MOV RAX, qword ptr [RBP + -0x30]
0x4a37ae: MOV RDI, qword ptr [RBP + -0x28]
0x4a37b2: CMP RAX, RDI
0x4a37b5: JZ 0x004a37c3
0x4a37b7: MOV RDI, RAX
0x4a37ba: CALL 0x00b4a4c0
0x4a37bf: MOV RDI, qword ptr [RBP + -0x28]
0x4a37c3: CALL 0x00b4a4c0
0x4a37c8: MOV RAX, qword ptr [RBX + 0x340]
0x4a37cf: MOV word ptr [RAX + 0xc], 0xc0
0x4a37d5: MOV EAX, R14D
0x4a37d8: MOV RCX, qword ptr [R15]
0x4a37db: CMP RCX, qword ptr [RBP + -0x20]
0x4a37df: JNZ 0x004a37ec
0x4a37e1: ADD RSP, 0x18
0x4a37e5: POP RBX
0x4a37e6: POP R14
0x4a37e8: POP R15
0x4a37ea: POP RBP
0x4a37eb: RET
0x4a37ec: CALL 0x006fd6b0
0x4a37f1: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3800 RVA 0x4a3800 | Evidence ev_2f870266df1e881129aa7d3033b1f1858c4380272d1dce85d7add9363d93af32 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3800:
0x4a3800: PUSH RBP
0x4a3801: MOV RBP, RSP
0x4a3804: PUSH R15
0x4a3806: PUSH R14
0x4a3808: PUSH RBX
0x4a3809: PUSH RAX
0x4a380a: MOV R14, qword ptr [RDI + 0x378]
0x4a3811: MOV R15, RSI
0x4a3814: MOV RBX, RDI
0x4a3817: TEST R14, R14
0x4a381a: JZ 0x004a388c
0x4a381c: CMP R14, qword ptr [RBX + 0x388]
0x4a3823: JZ 0x004a38af
0x4a3829: MOV RAX, qword ptr [RBX + 0x340]
0x4a3830: TEST RAX, RAX
0x4a3833: JZ 0x004a384e
0x4a3835: CMP word ptr [RAX + 0xc], 0xc1
0x4a383b: JNZ 0x004a384e
0x4a383d: MOV word ptr [RAX + 0xc], 0xc2
0x4a3843: MOV RAX, qword ptr [RBX + 0x340]
0x4a384a: MOV qword ptr [RAX + 0x10], R14
0x4a384e: MOV RCX, qword ptr [RBX + 0x380]
0x4a3855: MOVZX EAX, word ptr [R14 + 0xa]
0x4a385a: MOVZX EDX, byte ptr [RCX + 0xb]
0x4a385e: CMP AX, 0x2d
0x4a3862: MOV ECX, 0x3
0x4a3867: CMOVNZ ECX, EDX
0x4a386a: CMP CL, 0x3
0x4a386d: JZ 0x004a38b9
0x4a386f: MOVZX EAX, CL
0x4a3872: CMP EAX, 0x4
0x4a3875: JNZ 0x004a38bf
0x4a3877: MOV RDI, RBX
0x4a387a: MOV RSI, R14
0x4a387d: ADD RSP, 0x8
0x4a3881: POP RBX
0x4a3882: POP R14
0x4a3884: POP R15
0x4a3886: POP RBP
0x4a3887: JMP 0x0074d4a0
0x4a388c: MOV RDI, RBX
0x4a388f: MOV RSI, R15
0x4a3892: CALL 0x0026f208
0x4a3897: TEST EAX, EAX
0x4a3899: JZ 0x004a38cc
0x4a389b: MOV EDI, EAX
0x4a389d: MOV RSI, RBX
0x4a38a0: ADD RSP, 0x8
0x4a38a4: POP RBX
0x4a38a5: POP R14
0x4a38a7: POP R15
0x4a38a9: POP RBP
0x4a38aa: JMP 0x004f1c00
0x4a38af: TEST R15, R15
0x4a38b2: JZ 0x004a38bf
0x4a38b4: MOV qword ptr [R15], R14
0x4a38b7: JMP 0x004a38bf
0x4a38b9: TEST byte ptr [RBX + 0x9], 0x1
0x4a38bd: JNZ 0x004a390d
0x4a38bf: XOR EAX, EAX
0x4a38c1: ADD RSP, 0x8
0x4a38c5: POP RBX
0x4a38c6: POP R14
0x4a38c8: POP R15
0x4a38ca: POP RBP
0x4a38cb: RET
0x4a38cc: MOV R14, qword ptr [R15]
0x4a38cf: MOV qword ptr [RBX + 0x378], R14
0x4a38d6: MOVZX EDI, word ptr [R14 + 0xa]
0x4a38db: MOV word ptr [RBX + 0xa], DI
0x4a38df: CALL 0x00bb3d10
0x4a38e4: MOV qword ptr [RBX + 0x380], RAX
0x4a38eb: MOVZX EDI, byte ptr [RAX + 0xa]
0x4a38ef: CALL 0x00ac6eb0
0x4a38f4: TEST EAX, EAX
0x4a38f6: JZ 0x004a381c
0x4a38fc: MOV RDI, RBX
0x4a38ff: CALL 0x007ffd00
0x4a3904: TEST EAX, EAX
0x4a3906: JNZ 0x004a389b
0x4a3908: JMP 0x004a381c
0x4a390d: CMP AX, 0x10
0x4a3911: JNZ 0x004a392d
0x4a3913: MOV RDI, qword ptr [R14 + 0x20]
0x4a3917: MOV RDX, RBX
0x4a391a: MOVZX ESI, byte ptr [RDI + 0x9]
0x4a391e: ADD RSP, 0x8
0x4a3922: POP RBX
0x4a3923: POP R14
0x4a3925: POP R15
0x4a3927: POP RBP
0x4a3928: JMP 0x007ffc50
0x4a392d: MOV RDI, RBX
0x4a3930: XOR ESI, ESI
0x4a3932: ADD RSP, 0x8
0x4a3936: POP RBX
0x4a3937: POP R14
0x4a3939: POP R15
0x4a393b: POP RBP
0x4a393c: JMP 0x0026f208


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3950 RVA 0x4a3950 | Evidence ev_89522e11c87561c0959626e768a735e724dd456d16f0e4093c791206d4049710 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3950:
0x4a3950: PUSH RBP
0x4a3951: MOV RBP, RSP
0x4a3954: PUSH R15
0x4a3956: PUSH R14
0x4a3958: PUSH R12
0x4a395a: PUSH RBX
0x4a395b: SUB RSP, 0x10
0x4a395f: MOV RAX, qword ptr [RDI + 0x380]
0x4a3966: MOV R14, qword ptr [RDI + 0x378]
0x4a396d: MOVZX ECX, byte ptr [RAX + 0xb]
0x4a3971: CMP ECX, 0xa
0x4a3974: JNZ 0x004a399f
0x4a3976: MOVZX ECX, word ptr [R14 + 0xa]
0x4a397b: LEA RDI, [0x1593014]
0x4a3982: LEA RDX, [0x12779d2]
0x4a3989: MOV ESI, 0x199
0x4a398e: XOR EAX, EAX
0x4a3990: CALL 0x006f79f0
0x4a3995: MOV EAX, 0xe
0x4a399a: JMP 0x004a3db2
0x4a399f: MOVZX R12D, byte ptr [RAX + 0xc]
0x4a39a4: MOV RSI, qword ptr [R14 + 0x28]
0x4a39a8: MOV RBX, RDI
0x4a39ab: MOV word ptr [RDI + 0xd], 0x0
0x4a39b1: MOV qword ptr [RDI + 0x3a0], 0x0
0x4a39bc: MOV qword ptr [RDI + 0x390], 0x0
0x4a39c7: TEST ECX, ECX
0x4a39c9: JZ 0x004a39ec
0x4a39cb: CMP ECX, 0x2
0x4a39ce: JNZ 0x004a3a00
0x4a39d0: CMP word ptr [RBX + 0xa], 0x2d
0x4a39d5: JNZ 0x004a3ca2
0x4a39db: MOV RDI, RBX
0x4a39de: CALL 0x005ab320
0x4a39e3: TEST EAX, EAX
0x4a39e5: JNZ 0x004a39f8
0x4a39e7: JMP 0x004a3ca2
0x4a39ec: MOV RDI, RBX
0x4a39ef: CALL 0x005ab210
0x4a39f4: TEST EAX, EAX
0x4a39f6: JZ 0x004a3a36
0x4a39f8: MOV R15D, EAX
0x4a39fb: JMP 0x004a3d83
0x4a3a00: LEA EAX, [R12 + -0x10]
0x4a3a05: CMP EAX, 0xa
0x4a3a08: JA 0x004a3b56
0x4a3a0e: LEA RDX, [0x1592fe8]
0x4a3a15: MOVSXD RAX, dword ptr [RDX + RAX*0x4]
0x4a3a19: ADD RAX, RDX
0x4a3a1c: JMP RAX
0x4a3a36: MOV RAX, qword ptr [RBX + 0x380]
0x4a3a3d: TEST byte ptr [RAX + 0x9], 0x40
0x4a3a41: JNZ 0x004a3acf
0x4a3a47: MOVZX EAX, byte ptr [RBX + 0xd]
0x4a3a4b: MOVZX EDI, word ptr [RBX + 0xa]
0x4a3a4f: MOV RDX, RBX
0x4a3a52: LEA RSI, [RBX + RAX*0x8 + 0x2d8]
0x4a3a5a: CALL 0x00ab7700
0x4a3a5f: TEST EAX, EAX
0x4a3a61: JZ 0x004a3acf
0x4a3a63: MOV R15D, EAX
0x4a3a66: CMP EAX, 0x3005
0x4a3a6b: JNZ 0x004a3c48
0x4a3a71: MOVZX EAX, word ptr [RBX + 0xa]
0x4a3a75: CMP AX, 0x70
0x4a3a79: JNZ 0x004a3c4c
0x4a3a7f: LEA RAX, [RBX + 0x2e0]
0x4a3a86: MOV RCX, qword ptr [RAX]
0x4a3a89: MOV AX, 0x70
0x4a3a8d: CMP byte ptr [RCX + 0x9], 0x14
0x4a3a91: JNZ 0x004a3c4c
0x4a3a97: MOV RDX, qword ptr [RBX + 0x2e8]
0x4a3a9e: CMP byte ptr [RDX + 0x9], 0x14
0x4a3aa2: JNZ 0x004a3c4c
0x4a3aa8: MOVZX ESI, byte ptr [RCX + 0xd]
0x4a3aac: CMP SIL, byte ptr [RDX + 0xd]
0x4a3ab0: JNZ 0x004a3c4c
0x4a3ab6: MOV ECX, dword ptr [RCX + 0x30]
0x4a3ab9: CMP ECX, dword ptr [RDX + 0x30]
0x4a3abc: JNZ 0x004a3c4c
0x4a3ac2: MOV RDI, RBX
0x4a3ac5: CALL 0x005aaf60
0x4a3aca: JMP 0x004a3c92
0x4a3acf: LEA RAX, [0xe7f820]
0x4a3ad6: MOV R15, qword ptr [RAX + R12*0x8]
0x4a3ada: LEA RAX, [0x269d78]
0x4a3ae1: SUB RAX, R15
0x4a3ae4: ROR RAX, 0x3
0x4a3ae8: CMP RAX, 0x37
0x4a3aec: JA 0x004a3dc6
0x4a3af2: MOV RDI, RBX
0x4a3af5: CALL R15
0x4a3af8: MOV R15D, EAX
0x4a3afb: JMP 0x004a3c74
0x4a3b56: MOVZX R9D, word ptr [R14 + 0xa]
0x4a3b5b: LEA RDI, [0x1593014]
0x4a3b62: LEA RDX, [0x128b6f8]
0x4a3b69: MOV ESI, 0x2d3
0x4a3b6e: MOV R8D, R12D
0x4a3b71: XOR EAX, EAX
0x4a3b73: MOV qword ptr [RSP], R14
0x4a3b77: CALL 0x006f79f0
0x4a3b7c: MOV R15D, 0xe
0x4a3b82: JMP 0x004a3c81
0x4a3c48: MOVZX EAX, word ptr [RBX + 0xa]
0x4a3c4c: MOVZX EDI, AX
0x4a3c4f: CALL 0x00bb3d60
0x4a3c54: MOV R8, RAX
0x4a3c57: LEA RDI, [0x1593014]
0x4a3c5e: LEA RCX, [0x12779e6]
0x4a3c65: MOV ESI, 0x1f1
0x4a3c6a: MOV EDX, R15D
0x4a3c6d: XOR EAX, EAX
0x4a3c6f: CALL 0x006f7a90
0x4a3c74: MOV RDI, RBX
0x4a3c77: CALL 0x005aaf60
0x4a3c7c: TEST R15D, R15D
0x4a3c7f: JZ 0x004a3c92
0x4a3c81: MOV RDI, qword ptr [RBX + 0x390]
0x4a3c88: CALL 0x009bd8b0
0x4a3c8d: JMP 0x004a3d83
0x4a3c92: MOV RDI, qword ptr [RBX + 0x390]
0x4a3c99: TEST RDI, RDI
0x4a3c9c: JNZ 0x004a3d63
0x4a3ca2: MOV RDI, qword ptr [RBX + 0x390]
0x4a3ca9: CALL 0x009bd8b0
0x4a3cae: MOV RAX, qword ptr [RBX + 0x340]
0x4a3cb5: XOR R15D, R15D
0x4a3cb8: TEST RAX, RAX
0x4a3cbb: JZ 0x004a3d83
0x4a3cc1: CMP word ptr [RAX + 0xc], 0xc2
0x4a3cc7: JNZ 0x004a3d83
0x4a3ccd: CMP qword ptr [RAX + 0x10], R14
0x4a3cd1: JNZ 0x004a3d83
0x4a3cd7: MOV RSI, qword ptr [RBX + 0x390]
0x4a3cde: MOV RDI, RBX
0x4a3ce1: CALL 0x004a3640
0x4a3ce6: MOV R15D, EAX
0x4a3ce9: MOV qword ptr [RBX + 0x390], 0x0
0x4a3cf4: JMP 0x004a3d9a
0x4a3d63: MOV RSI, RBX
0x4a3d66: CALL 0x00b56250
0x4a3d6b: MOV R15D, EAX
0x4a3d6e: MOV RDI, qword ptr [RBX + 0x390]
0x4a3d75: CALL 0x009bd8b0
0x4a3d7a: TEST R15D, R15D
0x4a3d7d: JZ 0x004a3cae
0x4a3d83: MOV RSI, qword ptr [RBX + 0x390]
0x4a3d8a: TEST RSI, RSI
0x4a3d8d: JZ 0x004a3d9a
0x4a3d8f: MOV RDI, R14
0x4a3d92: MOV RDX, RBX
0x4a3d95: CALL 0x005aae70
0x4a3d9a: TEST R15D, R15D
0x4a3d9d: JZ 0x004a3dac
0x4a3d9f: MOV EDI, R15D
0x4a3da2: MOV RSI, RBX
0x4a3da5: CALL 0x004f1c00
0x4a3daa: JMP 0x004a3dae
0x4a3dac: XOR EAX, EAX
0x4a3dae: MOV byte ptr [RBX + 0xd], 0x0
0x4a3db2: ADD RSP, 0x10
0x4a3db6: POP RBX
0x4a3db7: POP R12
0x4a3db9: POP R14
0x4a3dbb: POP R15
0x4a3dbd: POP RBP
0x4a3dbe: RET
0x4a3dc6: LEA RDI, [0x1ac8160]
0x4a3dcd: MOV RSI, R15
0x4a3dd0: CALL 0x0044f8c0
0x4a3dd5: JMP 0x004a3af2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3de0 RVA 0x4a3de0 | Evidence ev_46f1e5f06488afbfe0e706522d68c729f59bc5b8e4580a6f5bdd939236ff3543 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3de0:
0x4a3de0: PUSH RBP
0x4a3de1: MOV RBP, RSP
0x4a3de4: TEST RSI, RSI
0x4a3de7: JZ 0x004a3e25
0x4a3de9: XOR EAX, EAX
0x4a3deb: NOP dword ptr [RAX + RAX*0x1]
0x4a3df0: MOV ECX, dword ptr [RDI + RAX*0x4]
0x4a3df3: INC RAX
0x4a3df6: IMUL R8D, ECX, -0x3361d2af
0x4a3dfd: IMUL ECX, ECX, 0x16a88000
0x4a3e03: SHR R8D, 0x11
0x4a3e07: OR R8D, ECX
0x4a3e0a: IMUL ECX, R8D, 0x1b873593
0x4a3e11: XOR ECX, EDX
0x4a3e13: RORX ECX, ECX, 0x13
0x4a3e19: LEA EDX, [RCX + RCX*0x4 + -0x19ab949c]
0x4a3e20: CMP RSI, RAX
0x4a3e23: JNZ 0x004a3df0
0x4a3e25: XOR ESI, EDX
0x4a3e27: MOV EAX, ESI
0x4a3e29: SHR EAX, 0x10
0x4a3e2c: XOR EAX, ESI
0x4a3e2e: IMUL EAX, EAX, -0x7a143595
0x4a3e34: MOV ECX, EAX
0x4a3e36: SHR ECX, 0xd
0x4a3e39: XOR ECX, EAX
0x4a3e3b: IMUL ECX, ECX, -0x3d4d51cb
0x4a3e41: MOV EAX, ECX
0x4a3e43: SHR EAX, 0x10
0x4a3e46: XOR EAX, ECX
0x4a3e48: POP RBP
0x4a3e49: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3e50 RVA 0x4a3e50 | Evidence ev_aba9ed87a218b14ac7690431cb062731e5b0f5f81c212fa9ba3b07917a089031 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3e50:
0x4a3e50: PUSH RBP
0x4a3e51: MOV RBP, RSP
0x4a3e54: VMOVQ RAX, XMM0
0x4a3e59: MOV RCX, RAX
0x4a3e5c: SHR RCX, 0x20
0x4a3e60: MOV EDX, ECX
0x4a3e62: AND EDX, 0x7fffffff
0x4a3e68: CMP EDX, 0x40900000
0x4a3e6e: JC 0x004a3e9d
0x4a3e70: CMP EDX, 0x7ff00000
0x4a3e76: JC 0x004a3eaf
0x4a3e78: VADDSD XMM0, XMM0, XMM0
0x4a3e7c: AND ECX, 0xfffff
0x4a3e82: OR ECX, EAX
0x4a3e84: VMOVAPD XMM1, XMM0
0x4a3e88: JNZ 0x004a3e8e
0x4a3e8a: VXORPD XMM1, XMM1, XMM1
0x4a3e8e: TEST RAX, RAX
0x4a3e91: JNS 0x004a3fb4
0x4a3e97: VMOVAPD XMM0, XMM1
0x4a3e9b: POP RBP
0x4a3e9c: RET
0x4a3e9d: CMP EDX, 0x3c8fffff
0x4a3ea3: JA 0x004a3ecf
0x4a3ea5: VADDSD XMM0, XMM0, qword ptr [0x013ba6e0]
0x4a3ead: POP RBP
0x4a3eae: RET
0x4a3eaf: VUCOMISD XMM0, qword ptr [0x013bab30]
0x4a3eb7: JNC 0x004a3f94
0x4a3ebd: VMOVSD XMM1, qword ptr [0x013bab00]
0x4a3ec5: VUCOMISD XMM1, XMM0
0x4a3ec9: JNC 0x004a3fa4
0x4a3ecf: VADDSD XMM1, XMM0, qword ptr [0x013bacf0]
0x4a3ed7: LEA RDX, [0x1593030]
0x4a3ede: VMOVQ RAX, XMM1
0x4a3ee3: VADDSD XMM1, XMM1, qword ptr [0x013bac60]
0x4a3eeb: SUB EAX, -0x80
0x4a3eee: MOVZX ECX, AL
0x4a3ef1: SHL EAX, 0xc
0x4a3ef4: SHL ECX, 0x4
0x4a3ef7: AND EAX, 0xfff00000
0x4a3efc: VSUBSD XMM1, XMM0, XMM1
0x4a3f00: VSUBSD XMM1, XMM1, qword ptr [RDX + RCX*0x1 + 0x8]
0x4a3f06: VMOVSD XMM0, qword ptr [RCX + RDX*0x1]
0x4a3f0b: CMP EAX, 0xc0300000
0x4a3f10: JL 0x004a3f23
0x4a3f12: LEA ECX, [RAX + 0x3ff00000]
0x4a3f18: SHL RCX, 0x20
0x4a3f1c: VMOVQ XMM2, RCX
0x4a3f21: JMP 0x004a3f32
0x4a3f23: LEA ECX, [RAX + 0x7e700000]
0x4a3f29: SHL RCX, 0x20
0x4a3f2d: VMOVQ XMM3, RCX
0x4a3f32: VMULSD XMM5, XMM1, qword ptr [0x013ba4d8]
0x4a3f3a: VMULSD XMM4, XMM0, XMM1
0x4a3f3e: VADDSD XMM5, XMM5, qword ptr [0x013bacf8]
0x4a3f46: VMULSD XMM5, XMM1, XMM5
0x4a3f4a: VADDSD XMM5, XMM5, qword ptr [0x013ba590]
0x4a3f52: VMULSD XMM5, XMM1, XMM5
0x4a3f56: VADDSD XMM5, XMM5, qword ptr [0x013ba670]
0x4a3f5e: VMULSD XMM1, XMM1, XMM5
0x4a3f62: VADDSD XMM1, XMM1, qword ptr [0x013baaa0]
0x4a3f6a: VMULSD XMM1, XMM4, XMM1
0x4a3f6e: VADDSD XMM0, XMM0, XMM1
0x4a3f72: CMP EAX, 0xc0300000
0x4a3f77: JL 0x004a3f8e
0x4a3f79: CMP EAX, 0x40000000
0x4a3f7e: JNZ 0x004a3f9e
0x4a3f80: VADDSD XMM0, XMM0, XMM0
0x4a3f84: VMULSD XMM0, XMM0, qword ptr [0x013ba8a0]
0x4a3f8c: POP RBP
0x4a3f8d: RET
0x4a3f8e: VMULSD XMM0, XMM0, XMM3
0x4a3f92: JMP 0x004a3fac
0x4a3f94: VMOVSD XMM0, qword ptr [0x013ba588]
0x4a3f9c: POP RBP
0x4a3f9d: RET
0x4a3f9e: VMULSD XMM0, XMM0, XMM2
0x4a3fa2: POP RBP
0x4a3fa3: RET
0x4a3fa4: VMOVSD XMM0, qword ptr [0x01ac8180]
0x4a3fac: VMULSD XMM0, XMM0, qword ptr [0x01ac8180]
0x4a3fb4: POP RBP
0x4a3fb5: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3fc0 RVA 0x4a3fc0 | Evidence ev_9e33f6283fc4e31bd266d29b808c698c63d163cd1ef6ccdcc1da3a48b398de60 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a3fc0:
0x4a3fc0: PUSH RBP
0x4a3fc1: MOV RBP, RSP
0x4a3fc4: PUSH R15
0x4a3fc6: PUSH R14
0x4a3fc8: PUSH R13
0x4a3fca: PUSH R12
0x4a3fcc: PUSH RBX
0x4a3fcd: SUB RSP, 0x28
0x4a3fd1: LEA R13, [0x391c310]
0x4a3fd8: MOV R14, RDI
0x4a3fdb: MOV RBX, RSI
0x4a3fde: MOV RAX, qword ptr [R13]
0x4a3fe2: MOV qword ptr [RBP + -0x30], RAX
0x4a3fe6: MOV R15, qword ptr [RDI + 0x48]
0x4a3fea: MOV R12D, dword ptr [RDI + 0x78]
0x4a3fee: LEA RDI, [RBP + -0x48]
0x4a3ff2: CALL 0x00acf740
0x4a3ff7: TEST byte ptr [R14 + 0x78], 0x1
0x4a3ffc: JZ 0x004a4020
0x4a3ffe: MOV EDX, dword ptr [R15 + 0x84]
0x4a4005: ADD EDX, dword ptr [RBX + 0x30]
0x4a4008: MOV RDI, R14
0x4a400b: MOV ESI, 0x5
0x4a4010: CALL 0x004bbf00
0x4a4015: MOV RAX, qword ptr [RBP + -0x48]
0x4a4019: MOV qword ptr [R15 + 0xf0], RAX
0x4a4020: MOV EDX, dword ptr [RBX + 0x30]
0x4a4023: CMP EDX, 0x4
0x4a4026: JA 0x004a4083
0x4a4028: LEA RSI, [R14 + 0x60]
0x4a402c: LEA RDI, [0x12c958b]
0x4a4033: XOR EAX, EAX
0x4a4035: CALL 0x0025d410
0x4a403a: MOV EDX, 0x1
0x4a403f: MOV RDI, R14
0x4a4042: MOV ESI, 0x1
0x4a4047: CALL 0x004bbf00
0x4a404c: MOV EDX, 0x1
0x4a4051: MOV RDI, R14
0x4a4054: MOV ESI, 0x9
0x4a4059: CALL 0x004bbf00
0x4a405e: MOV RDI, RBX
0x4a4061: CALL 0x0042a850
0x4a4066: MOV RAX, qword ptr [R13]
0x4a406a: CMP RAX, qword ptr [RBP + -0x30]
0x4a406e: JNZ 0x004a4422
0x4a4074: ADD RSP, 0x28
0x4a4078: POP RBX
0x4a4079: POP R12
0x4a407b: POP R13
0x4a407d: POP R14
0x4a407f: POP R15
0x4a4081: POP RBP
0x4a4082: RET
0x4a4083: CMP dword ptr [RBX + 0x18], EDX
0x4a4086: JGE 0x004a409a
0x4a4088: MOV RDI, RBX
0x4a408b: MOV ESI, EDX
0x4a408d: CALL 0x00a19150
0x4a4092: MOV RBX, RAX
0x4a4095: TEST RAX, RAX
0x4a4098: JZ 0x004a4066
0x4a409a: TEST byte ptr [R15 + 0x80], 0x20
0x4a40a2: MOV R13, qword ptr [RBX + 0x10]
0x4a40a6: JNZ 0x004a4113
0x4a40a8: LEA RAX, [R13 + 0x2]
0x4a40ac: MOV RDI, RBX
0x4a40af: MOV ESI, 0x4
0x4a40b4: MOV qword ptr [RBP + -0x50], RAX
0x4a40b8: CALL 0x00a19060
0x4a40bd: MOVZX EDX, byte ptr [R13]
0x4a40c2: CMP EDX, 0xf
0x4a40c5: JZ 0x004a4197
0x4a40cb: CMP EDX, 0x8f
0x4a40d1: JZ 0x004a4197
0x4a40d7: CMP EDX, 0xff
0x4a40dd: JNZ 0x004a439f
0x4a40e3: CMP byte ptr [R13 + 0x1], 0x3
0x4a40e8: MOV DL, 0xff
0x4a40ea: JNZ 0x004a439f
0x4a40f0: TEST byte ptr [R15 + 0x80], 0x2
0x4a40f8: JNZ 0x004a43d0
0x4a40fe: MOV R12, qword ptr [RBP + -0x50]
0x4a4102: MOVZX EAX, word ptr [R12]
0x4a4107: MOVBE word ptr [RBP + -0x32], AX
0x4a410d: ROL AX, 0x8
0x4a4111: JMP 0x004a4143
0x4a4113: LEA RDI, [RBP + -0x32]
0x4a4117: MOV EDX, 0x2
0x4a411c: MOV RSI, R13
0x4a411f: CALL 0x002590b0
0x4a4124: MOVZX EAX, word ptr [RBP + -0x32]
0x4a4128: MOV RDI, RBX
0x4a412b: MOV ESI, 0x2
0x4a4130: MOVBE word ptr [RBP + -0x32], AX
0x4a4136: MOV R12, qword ptr [RBX + 0x10]
0x4a413a: CALL 0x00a19060
0x4a413f: MOVZX EAX, word ptr [RBP + -0x32]
0x4a4143: LEA R13, [0x391c310]
0x4a414a: MOVZX ECX, AX
0x4a414d: CMP ECX, 0xc020
0x4a4153: JLE 0x004a41c7
0x4a4155: CMP ECX, 0xc021
0x4a415b: JZ 0x004a4233
0x4a4161: CMP ECX, 0xc023
0x4a4167: JZ 0x004a424a
0x4a416d: CMP ECX, 0xc223
0x4a4173: JNZ 0x004a429d
0x4a4179: CMP dword ptr [R15 + 0x118], 0x3
0x4a4181: JL 0x004a405e
0x4a4187: MOV RDI, R15
0x4a418a: MOV RSI, RBX
0x4a418d: CALL 0x004a63b0
0x4a4192: JMP 0x004a405e
0x4a4197: TEST byte ptr [R15 + 0x80], 0x2
0x4a419f: JNZ 0x004a41f3
0x4a41a1: TEST R12B, 0x4
0x4a41a5: JZ 0x004a4291
0x4a41ab: MOVBE AX, word ptr [R13 + 0x2]
0x4a41b2: MOVZX ECX, byte ptr [R13 + 0x1]
0x4a41b7: LEA RSI, [R14 + 0x60]
0x4a41bb: LEA RDI, [0x12e86c3]
0x4a41c2: JMP 0x004a43b9
0x4a41c7: CMP ECX, 0x21
0x4a41ca: JZ 0x004a4268
0x4a41d0: CMP ECX, 0x8021
0x4a41d6: JNZ 0x004a429d
0x4a41dc: CMP dword ptr [R15 + 0x118], 0x4
0x4a41e4: JNZ 0x004a405e
0x4a41ea: LEA RDI, [0xe7fa90]
0x4a41f1: JMP 0x004a423a
0x4a41f3: MOV RAX, qword ptr [RBP + -0x50]
0x4a41f7: MOVBE AX, word ptr [RAX]
0x4a41fc: CMP AX, 0x800
0x4a4200: JZ 0x004a428a
0x4a4206: MOVZX EAX, AX
0x4a4209: CMP EAX, 0x8035
0x4a420e: JNZ 0x004a4388
0x4a4214: MOV RDI, R14
0x4a4217: MOV RSI, RBX
0x4a421a: CALL 0x004a4430
0x4a421f: MOV RDI, RBX
0x4a4222: CALL 0x0042a850
0x4a4227: LEA R13, [0x391c310]
0x4a422e: JMP 0x004a4066
0x4a4233: LEA RDI, [0xe7f880]
0x4a423a: MOV RSI, R15
0x4a423d: MOV RDX, RBX
0x4a4240: CALL 0x004a4a40
0x4a4245: JMP 0x004a405e
0x4a424a: CMP dword ptr [R15 + 0x118], 0x3
0x4a4252: JL 0x004a405e
0x4a4258: MOV RDI, R15
0x4a425b: MOV RSI, RBX
0x4a425e: CALL 0x004a5d70
0x4a4263: JMP 0x004a405e
0x4a4268: LEA RDI, [RBP + -0x48]
0x4a426c: CALL 0x00acf740
0x4a4271: CMP dword ptr [R15 + 0x130], 0x9
0x4a4279: JNZ 0x004a403a
0x4a427f: MOV RAX, qword ptr [RBP + -0x48]
0x4a4283: MOV qword ptr [R15 + 0x100], RAX
0x4a428a: TEST byte ptr [R14 + 0x78], 0x1
0x4a428f: JNZ 0x004a430e
0x4a4291: LEA R13, [0x391c310]
0x4a4298: JMP 0x004a403a
0x4a429d: CMP dword ptr [R15 + 0x12c], 0x9
0x4a42a5: JNZ 0x004a42de
0x4a42a7: MOV RAX, qword ptr [R15 + 0x98]
0x4a42ae: MOV RDI, R15
0x4a42b1: MOV ESI, 0xc021
0x4a42b6: MOV R9, R12
0x4a42b9: INC RAX
0x4a42bc: MOV qword ptr [R15 + 0x98], RAX
0x4a42c3: MOVZX ECX, AL
0x4a42c6: MOV EDX, dword ptr [RBX + 0x30]
0x4a42c9: ADD EDX, 0x2
0x4a42cc: MOVZX R8D, DX
0x4a42d0: MOV EDX, 0x8
0x4a42d5: CALL 0x004a4650
0x4a42da: MOVZX EAX, word ptr [RBP + -0x32]
0x4a42de: ROL AX, 0x8
0x4a42e2: LEA RSI, [R14 + 0x60]
0x4a42e6: LEA RDI, [0x131cc1b]
0x4a42ed: MOVZX EDX, AX
0x4a42f0: XOR EAX, EAX
0x4a42f2: CALL 0x0025d410
0x4a42f7: MOV EDX, 0x1
0x4a42fc: MOV RDI, R14
0x4a42ff: MOV ESI, 0xb
0x4a4304: CALL 0x004bbf00
0x4a4309: JMP 0x004a403a
0x4a430e: ADD R15, 0x188
0x4a4315: XOR ESI, ESI
0x4a4317: XOR EDX, EDX
0x4a4319: XOR ECX, ECX
0x4a431b: MOV RDI, R15
0x4a431e: CALL 0x004c6a00
0x4a4323: MOV EDI, 0x1
0x4a4328: MOV RSI, RBX
0x4a432b: CALL 0x002f82c0
0x4a4330: LEA R13, [0x391c310]
0x4a4337: TEST EAX, EAX
0x4a4339: JZ 0x004a440f
0x4a433f: LEA RSI, [R14 + 0x60]
0x4a4343: LEA RDI, [0x1277a08]
0x4a434a: XOR EAX, EAX
0x4a434c: CALL 0x0025d410
0x4a4351: MOV RDI, R15
0x4a4354: XOR ESI, ESI
0x4a4356: XOR EDX, EDX
0x4a4358: XOR ECX, ECX
0x4a435a: CALL 0x004c6fa0
0x4a435f: MOV EDX, 0x1
0x4a4364: MOV RDI, R14
0x4a4367: MOV ESI, 0x1
0x4a436c: CALL 0x004bbf00
0x4a4371: MOV EDX, 0x1
0x4a4376: MOV RDI, R14
0x4a4379: MOV ESI, 0x9
0x4a437e: CALL 0x004bbf00
0x4a4383: JMP 0x004a4066
0x4a4388: MOV EDX, 0x1
0x4a438d: MOV RDI, R14
0x4a4390: MOV ESI, 0xb
0x4a4395: CALL 0x004bbf00
0x4a439a: MOVZX EDX, byte ptr [R13]
0x4a439f: MOVBE AX, word ptr [R13 + 0x2]
0x4a43a6: MOVZX ECX, byte ptr [R13 + 0x1]
0x4a43ab: LEA RSI, [R14 + 0x60]
0x4a43af: MOVZX EDX, DL
0x4a43b2: LEA RDI, [0x1366818]
0x4a43b9: MOVZX R8D, AX
0x4a43bd: XOR EAX, EAX
0x4a43bf: CALL 0x0025d410
0x4a43c4: LEA R13, [0x391c310]
0x4a43cb: JMP 0x004a403a
0x4a43d0: LEA R13, [0x391c310]
0x4a43d7: TEST R12B, 0x4
0x4a43db: JZ 0x004a403a
0x4a43e1: MOV RAX, qword ptr [RBP + -0x50]
0x4a43e5: LEA RSI, [R14 + 0x60]
0x4a43e9: LEA RDI, [0x12aa20d]
0x4a43f0: MOV EDX, 0xff
0x4a43f5: MOV ECX, 0x3
0x4a43fa: MOVBE AX, word ptr [RAX]
0x4a43ff: MOVZX R8D, AX
0x4a4403: XOR EAX, EAX
0x4a4405: CALL 0x0025d410
0x4a440a: JMP 0x004a403a
0x4a440f: MOV RDI, R15
0x4a4412: XOR ESI, ESI
0x4a4414: XOR EDX, EDX
0x4a4416: XOR ECX, ECX
0x4a4418: CALL 0x004c6fa0
0x4a441d: JMP 0x004a4066
0x4a4422: CALL 0x006fd6b0
0x4a4427: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a4430 RVA 0x4a4430 | Evidence ev_8d3fec92029b9eba5e0e1ede84e7772918e9c7927dc651b505b92f70ed7cb55f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a4430:
0x4a4430: PUSH RBP
0x4a4431: MOV RBP, RSP
0x4a4434: PUSH R15
0x4a4436: PUSH R14
0x4a4438: PUSH R13
0x4a443a: PUSH R12
0x4a443c: PUSH RBX
0x4a443d: PUSH RAX
0x4a443e: MOV R14, qword ptr [RDI]
0x4a4441: MOV EDX, dword ptr [RSI + 0x30]
0x4a4444: CMP EDX, 0x11
0x4a4447: JG 0x004a446c
0x4a4449: ADD R14, 0x60
0x4a444d: LEA RDI, [0x1351421]
0x4a4454: MOV RSI, R14
0x4a4457: XOR EAX, EAX
0x4a4459: ADD RSP, 0x8
0x4a445d: POP RBX
0x4a445e: POP R12
0x4a4460: POP R13
0x4a4462: POP R14
0x4a4464: POP R15
0x4a4466: POP RBP
0x4a4467: JMP 0x0025d410
0x4a446c: MOV R15D, dword ptr [R14 + 0x78]
0x4a4470: MOV R12, qword ptr [RSI + 0x10]
0x4a4474: MOV RBX, RDI
0x4a4477: TEST R15B, 0x4
0x4a447b: JZ 0x004a44bf
0x4a447d: MOVBE ECX, dword ptr [R12]
0x4a4483: MOV R8D, dword ptr [R12 + 0x4]
0x4a4488: MOV R9D, dword ptr [R12 + 0x8]
0x4a448d: MOVZX R10D, word ptr [R12 + 0xc]
0x4a4493: MOVZX R11D, word ptr [R12 + 0xe]
0x4a4499: MOVZX R13D, word ptr [R12 + 0x10]
0x4a449f: LEA RSI, [R14 + 0x60]
0x4a44a3: SUB RSP, 0x8
0x4a44a7: LEA RDI, [0x12a05cd]
0x4a44ae: XOR EAX, EAX
0x4a44b0: PUSH R13
0x4a44b2: PUSH R11
0x4a44b4: PUSH R10
0x4a44b6: CALL 0x0025d410
0x4a44bb: ADD RSP, 0x20
0x4a44bf: MOVBE EDX, dword ptr [R12]
0x4a44c5: TEST EDX, EDX
0x4a44c7: JZ 0x004a454d
0x4a44cd: CMP EDX, 0x1
0x4a44d0: JZ 0x004a45eb
0x4a44d6: CMP EDX, 0x2
0x4a44d9: JNZ 0x004a4574
0x4a44df: MOV dword ptr [RBX + 0x88], 0x0
0x4a44e9: MOVBE EAX, dword ptr [R12 + 0x4]
0x4a44f0: MOV qword ptr [RBX + 0xc0], RAX
0x4a44f7: CMP qword ptr [RBX + 0x98], RAX
0x4a44fe: JNZ 0x004a458a
0x4a4504: CMP dword ptr [RBX + 0x8c], 0x3
0x4a450b: JC 0x004a4534
0x4a450d: LEA RSI, [R14 + 0x60]
0x4a4511: LEA RDI, [0x12a054b]
0x4a4518: XOR EAX, EAX
0x4a451a: CALL 0x0025d410
0x4a451f: MOV dword ptr [RBX + 0x8c], 0x0
0x4a4529: TEST byte ptr [R14 + 0x78], 0x1
0x4a452e: JNZ 0x004a45fa
0x4a4534: INC dword ptr [RBX + 0x8c]
0x4a453a: CALL 0x00992cd0
0x4a453f: MOV EAX, EAX
0x4a4541: MOV qword ptr [RBX + 0x98], RAX
0x4a4548: JMP 0x004a45eb
0x4a454d: MOV RAX, qword ptr [RBX]
0x4a4550: XOR EDX, EDX
0x4a4552: MOV RAX, qword ptr [RAX + 0x280]
0x4a4559: TEST RAX, RAX
0x4a455c: JZ 0x004a45ca
0x4a455e: NOP
0x4a4560: MOV RCX, qword ptr [RAX]
0x4a4563: CMP byte ptr [RCX + 0x1], 0x2
0x4a4567: JZ 0x004a45b6
0x4a4569: MOV RAX, qword ptr [RAX + 0x28]
0x4a456d: TEST RAX, RAX
0x4a4570: JNZ 0x004a4560
0x4a4572: JMP 0x004a45ca
0x4a4574: TEST R15B, 0x4
0x4a4578: JZ 0x004a45eb
0x4a457a: ADD R14, 0x60
0x4a457e: LEA RDI, [0x138fc70]
0x4a4585: JMP 0x004a4454
0x4a458a: MOV dword ptr [RBX + 0x8c], 0x0
0x4a4594: MOV EAX, dword ptr [R14 + 0x78]
0x4a4598: AND EAX, 0x41
0x4a459b: CMP EAX, 0x40
0x4a459e: JNZ 0x004a45eb
0x4a45a0: MOV RDI, R14
0x4a45a3: ADD RSP, 0x8
0x4a45a7: POP RBX
0x4a45a8: POP R12
0x4a45aa: POP R13
0x4a45ac: POP R14
0x4a45ae: POP R15
0x4a45b0: POP RBP
0x4a45b1: JMP 0x004bd2a0
0x4a45b6: MOV ESI, dword ptr [RCX + 0x4]
0x4a45b9: TEST ESI, ESI
0x4a45bb: JZ 0x004a45ca
0x4a45bd: MOV RAX, qword ptr [RAX + 0x10]
0x4a45c1: MOV EDX, ESI
0x4a45c3: MOVBE ECX, dword ptr [RAX + 0x4]
0x4a45c8: JMP 0x004a45ca
0x4a45ca: BSWAP EDX
0x4a45cc: TEST EDX, EDX
0x4a45ce: JZ 0x004a45eb
0x4a45d0: MOV RDI, RBX
0x4a45d3: MOV ESI, 0x1
0x4a45d8: ADD RSP, 0x8
0x4a45dc: POP RBX
0x4a45dd: POP R12
0x4a45df: POP R13
0x4a45e1: POP R14
0x4a45e3: POP R15
0x4a45e5: POP RBP
0x4a45e6: JMP 0x004ad1c0
0x4a45eb: ADD RSP, 0x8
0x4a45ef: POP RBX
0x4a45f0: POP R12
0x4a45f2: POP R13
0x4a45f4: POP R14
0x4a45f6: POP R15
0x4a45f8: POP RBP
0x4a45f9: RET
0x4a45fa: MOV RDI, R14
0x4a45fd: CALL 0x004bd120
0x4a4602: JMP 0x004a4620
0x4a4610: MOV qword ptr [RDI + 0x8], 0x0
0x4a4618: DEC dword ptr [RBX + 0x50]
0x4a461b: CALL 0x0042a850
0x4a4620: MOV RDI, qword ptr [RBX + 0x40]
0x4a4624: TEST RDI, RDI
0x4a4627: JZ 0x004a4534
0x4a462d: MOV RAX, qword ptr [RDI + 0x8]
0x4a4631: MOV qword ptr [RBX + 0x40], RAX
0x4a4635: TEST RAX, RAX
0x4a4638: JNZ 0x004a4610
0x4a463a: MOV qword ptr [RBX + 0x48], 0x0
0x4a4642: JMP 0x004a4610


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a4650 RVA 0x4a4650 | Evidence ev_aaf9e4f999f984677ad334d89d6ca364779db1c046a72dd447ccc96d1e980e8a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a4650:
0x4a4650: PUSH RBP
0x4a4651: MOV RBP, RSP
0x4a4654: PUSH R15
0x4a4656: PUSH R14
0x4a4658: PUSH R13
0x4a465a: PUSH R12
0x4a465c: PUSH RBX
0x4a465d: SUB RSP, 0x48
0x4a4661: LEA RAX, [0x391c310]
0x4a4668: MOV dword ptr [RBP + -0x3c], EDX
0x4a466b: MOV qword ptr [RBP + -0x70], R9
0x4a466f: MOV dword ptr [RBP + -0x40], ECX
0x4a4672: XOR R13D, R13D
0x4a4675: MOV R14D, ESI
0x4a4678: LEA RSI, [RBP + -0x38]
0x4a467c: MOV EDX, 0x1
0x4a4681: MOV RAX, qword ptr [RAX]
0x4a4684: MOV qword ptr [RBP + -0x30], RAX
0x4a4688: MOV qword ptr [RBP + -0x60], RDI
0x4a468c: MOV dword ptr [RBP + -0x44], R8D
0x4a4690: MOV RAX, qword ptr [RDI]
0x4a4693: MOV qword ptr [RBP + -0x58], RAX
0x4a4697: MOV EAX, dword ptr [RAX + 0x78]
0x4a469a: MOV dword ptr [RBP + -0x50], EAX
0x4a469d: MOV EAX, dword ptr [RDI + 0x80]
0x4a46a3: MOV RDI, qword ptr [0x034f5020]
0x4a46aa: MOV dword ptr [RBP + -0x38], 0x2
0x4a46b1: MOV word ptr [RBP + -0x34], 0x1
0x4a46b7: TEST AL, 0x20
0x4a46b9: MOV EAX, R8D
0x4a46bc: SETZ R13B
0x4a46c0: ADD R13D, R13D
0x4a46c3: MOV R12, R13
0x4a46c6: XOR R12, 0x82
0x4a46cd: CMP R12, RAX
0x4a46d0: CMOVNC R12, RAX
0x4a46d4: CALL 0x0043b880
0x4a46d9: LEA RBX, [0x2566c10]
0x4a46e0: MOV R15, RAX
0x4a46e3: MOV RDI, qword ptr [RBX + 0x48]
0x4a46e7: TEST RDI, RDI
0x4a46ea: JNZ 0x004a49bf
0x4a46f0: TEST R15, R15
0x4a46f3: JZ 0x004a49a0
0x4a46f9: MOV RCX, qword ptr [RBP + -0x60]
0x4a46fd: ADD R13, 0x2
0x4a4701: LEA RAX, [R12 + 0x4]
0x4a4706: ADD R13D, EAX
0x4a4709: MOV dword ptr [R15 + 0x18], R13D
0x4a470d: MOV dword ptr [R15 + 0x30], R13D
0x4a4711: MOV qword ptr [R15 + 0x20], 0x0
0x4a4719: TEST byte ptr [RCX + 0x80], 0x20
0x4a4720: JNZ 0x004a473a
0x4a4722: MOV R13, qword ptr [R15 + 0x10]
0x4a4726: MOV word ptr [R13], 0x3ff
0x4a472d: MOVBE word ptr [R13 + 0x2], R14W
0x4a4734: ADD R13, 0x4
0x4a4738: JMP 0x004a474c
0x4a473a: MOV RCX, qword ptr [R15 + 0x10]
0x4a473e: MOVBE word ptr [RCX], R14W
0x4a4744: MOV R13, qword ptr [R15 + 0x10]
0x4a4748: ADD R13, 0x2
0x4a474c: CMP word ptr [RBP + -0x44], 0x0
0x4a4751: MOV EDX, dword ptr [RBP + -0x3c]
0x4a4754: MOV EBX, dword ptr [RBP + -0x50]
0x4a4757: MOV ECX, dword ptr [RBP + -0x40]
0x4a475a: MOV byte ptr [R13], DL
0x4a475e: MOV byte ptr [R13 + 0x1], CL
0x4a4762: MOVBE word ptr [R13 + 0x2], AX
0x4a4769: JZ 0x004a477b
0x4a476b: MOV RDI, qword ptr [RBP + -0x70]
0x4a476f: LEA RSI, [R13 + 0x4]
0x4a4773: MOV RDX, R12
0x4a4776: CALL 0x00259be0
0x4a477b: TEST BL, 0x4
0x4a477e: JZ 0x004a48d7
0x4a4784: MOVZX ECX, R14W
0x4a4788: CMP ECX, 0xc020
0x4a478e: JLE 0x004a47b1
0x4a4790: CMP ECX, 0xc021
0x4a4796: JZ 0x004a47ca
0x4a4798: CMP ECX, 0xc023
0x4a479e: JZ 0x004a47d3
0x4a47a0: CMP ECX, 0xc223
0x4a47a6: JNZ 0x004a47e5
0x4a47a8: LEA R14, [0x131cc44]
0x4a47af: JMP 0x004a4802
0x4a47b1: CMP ECX, 0x8021
0x4a47b7: JZ 0x004a47dc
0x4a47b9: CMP ECX, 0x8057
0x4a47bf: JNZ 0x004a47e5
0x4a47c1: LEA R14, [0x131cc49]
0x4a47c8: JMP 0x004a4802
0x4a47ca: LEA R14, [0x137098a]
0x4a47d1: JMP 0x004a4802
0x4a47d3: LEA R14, [0x12be8f2]
0x4a47da: JMP 0x004a4802
0x4a47dc: LEA R14, [0x12b4b50]
0x4a47e3: JMP 0x004a4802
0x4a47e5: LEA R14, [0x35365d4]
0x4a47ec: LEA RDX, [0x1383910]
0x4a47f3: MOV ESI, 0xc
0x4a47f8: XOR EAX, EAX
0x4a47fa: MOV RDI, R14
0x4a47fd: CALL 0x004aee40
0x4a4802: MOV RAX, qword ptr [RBP + -0x58]
0x4a4806: MOVZX ECX, byte ptr [R13]
0x4a480b: LEA RSI, [RAX + 0x60]
0x4a480f: LEA EAX, [RCX + -0x1]
0x4a4812: CMP AL, 0xb
0x4a4814: JNC 0x004a4826
0x4a4816: MOVZX EAX, AL
0x4a4819: LEA RCX, [0xe7fb60]
0x4a4820: MOV RBX, qword ptr [RCX + RAX*0x8]
0x4a4824: JMP 0x004a4851
0x4a4826: LEA RBX, [0x3536610]
0x4a482d: MOV qword ptr [RBP + -0x50], R14
0x4a4831: MOV R14, RSI
0x4a4834: LEA RDX, [0x1383910]
0x4a483b: MOV ESI, 0xc
0x4a4840: XOR EAX, EAX
0x4a4842: MOV RDI, RBX
0x4a4845: CALL 0x004aee40
0x4a484a: MOV RSI, R14
0x4a484d: MOV R14, qword ptr [RBP + -0x50]
0x4a4851: MOVBE AX, word ptr [R13 + 0x2]
0x4a4858: MOVZX R8D, byte ptr [R13 + 0x1]
0x4a485d: LEA RDI, [0x12fd358]
0x4a4864: MOV RDX, R14
0x4a4867: MOV RCX, RBX
0x4a486a: MOVZX R9D, AX
0x4a486e: XOR EAX, EAX
0x4a4870: CALL 0x0025d410
0x4a4875: CMP word ptr [RBP + -0x44], 0x0
0x4a487a: JZ 0x004a48c9
0x4a487c: MOVZX ESI, byte ptr [R13 + 0x4]
0x4a4881: LEA RDI, [0x13af03e]
0x4a4888: XOR EAX, EAX
0x4a488a: CALL 0x0025d410
0x4a488f: CMP R12W, 0x1
0x4a4894: JZ 0x004a48c9
0x4a4896: DEC R12
0x4a4899: LEA RBX, [0x131cc50]
0x4a48a0: XOR R14D, R14D
0x4a48a3: NOP dword ptr CS:[RAX + RAX*0x1]
0x4a48b0: MOVZX ESI, byte ptr [R13 + R14*0x1 + 0x5]
0x4a48b6: MOV RDI, RBX
0x4a48b9: XOR EAX, EAX
0x4a48bb: CALL 0x0025d410
0x4a48c0: INC R14
0x4a48c3: CMP R12W, R14W
0x4a48c7: JNZ 0x004a48b0
0x4a48c9: LEA RDI, [0x135c29e]
0x4a48d0: XOR EAX, EAX
0x4a48d2: CALL 0x0025d410
0x4a48d7: MOV R13, qword ptr [RBP + -0x60]
0x4a48db: MOV EAX, dword ptr [R13 + 0x50]
0x4a48df: CMP EAX, dword ptr [R13 + 0x54]
0x4a48e3: JGE 0x004a4912
0x4a48e5: LEA RBX, [R13 + 0x70]
0x4a48e9: XOR ESI, ESI
0x4a48eb: XOR EDX, EDX
0x4a48ed: XOR ECX, ECX
0x4a48ef: MOV RDI, RBX
0x4a48f2: CALL 0x004c6a00
0x4a48f7: MOV qword ptr [R15 + 0x8], 0x0
0x4a48ff: MOV R12, qword ptr [RBP + -0x58]
0x4a4903: MOV RAX, qword ptr [R13 + 0x48]
0x4a4907: TEST RAX, RAX
0x4a490a: JZ 0x004a493f
0x4a490c: MOV qword ptr [RAX + 0x8], R15
0x4a4910: JMP 0x004a4943
0x4a4912: MOV RBX, qword ptr [RBP + -0x58]
0x4a4916: MOV EDX, 0x1
0x4a491b: MOV ESI, 0xa
0x4a4920: MOV RDI, RBX
0x4a4923: CALL 0x004bbf00
0x4a4928: MOV RDI, R15
0x4a492b: CALL 0x0042a850
0x4a4930: MOV EDX, 0x1
0x4a4935: MOV RDI, RBX
0x4a4938: MOV ESI, 0x3
0x4a493d: JMP 0x004a499b
0x4a493f: MOV qword ptr [R13 + 0x40], R15
0x4a4943: MOV qword ptr [R13 + 0x48], R15
0x4a4947: INC dword ptr [R13 + 0x50]
0x4a494b: MOV RDI, RBX
0x4a494e: XOR ESI, ESI
0x4a4950: XOR EDX, EDX
0x4a4952: XOR ECX, ECX
0x4a4954: CALL 0x004c6fa0
0x4a4959: TEST byte ptr [R12 + 0x79], 0x4
0x4a495f: JNZ 0x004a4988
0x4a4961: MOV RBX, qword ptr [R12 + 0x498]
0x4a4969: LEA RAX, [0x2652d0]
0x4a4970: SUB RAX, RBX
0x4a4973: ROR RAX, 0x3
0x4a4977: CMP RAX, 0x8bc
0x4a497d: JA 0x004a4a05
0x4a4983: MOV RDI, R12
0x4a4986: CALL RBX
0x4a4988: MOV EDX, dword ptr [R13 + 0x84]
0x4a498f: ADD EDX, dword ptr [R15 + 0x30]
0x4a4993: MOV RDI, R12
0x4a4996: MOV ESI, 0x6
0x4a499b: CALL 0x004bbf00
0x4a49a0: LEA RAX, [0x391c310]
0x4a49a7: MOV RAX, qword ptr [RAX]
0x4a49aa: CMP RAX, qword ptr [RBP + -0x30]
0x4a49ae: JNZ 0x004a49fe
0x4a49b0: ADD RSP, 0x48
0x4a49b4: POP RBX
0x4a49b5: POP R12
0x4a49b7: POP R13
0x4a49b9: POP R14
0x4a49bb: POP R15
0x4a49bd: POP RBP
0x4a49be: RET
0x4a49bf: LEA RAX, [0x1a9bf28]
0x4a49c6: MOV R10, qword ptr [RAX]
0x4a49c9: LEA RAX, [0x2681e8]
0x4a49d0: SUB RAX, R10
0x4a49d3: ROR RAX, 0x3
0x4a49d7: CMP RAX, 0x1
0x4a49db: JA 0x004a4a19
0x4a49dd: MOV ESI, 0x1
0x4a49e2: MOV EDX, 0x1
0x4a49e7: MOV RCX, R15
0x4a49ea: XOR R8D, R8D
0x4a49ed: XOR R9D, R9D
0x4a49f0: CALL R10
0x4a49f3: TEST R15, R15
0x4a49f6: JNZ 0x004a46f9
0x4a49fc: JMP 0x004a49a0
0x4a49fe: CALL 0x006fd6b0
0x4a4a03: UD2
0x4a4a05: LEA RDI, [0x1ac8570]
0x4a4a0c: MOV RSI, RBX
0x4a4a0f: CALL 0x0044f8c0
0x4a4a14: JMP 0x004a4983
0x4a4a19: LEA RDI, [0x1ac8450]
0x4a4a20: MOV RSI, R10
0x4a4a23: MOV qword ptr [RBP + -0x68], R10
0x4a4a27: CALL 0x0044f8c0
0x4a4a2c: MOV R10, qword ptr [RBP + -0x68]
0x4a4a30: MOV RDI, qword ptr [RBX + 0x48]
0x4a4a34: JMP 0x004a49dd


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a4a40 RVA 0x4a4a40 | Evidence ev_4a09755eb126d85ce01a2919371ab12252d9ea52fe11fd5cacbdd6ffb9c940be | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a4a40:
0x4a4a40: PUSH RBP
0x4a4a41: MOV RBP, RSP
0x4a4a44: PUSH R15
0x4a4a46: PUSH R14
0x4a4a48: PUSH R13
0x4a4a4a: PUSH R12
0x4a4a4c: PUSH RBX
0x4a4a4d: SUB RSP, 0x48
0x4a4a51: LEA R15, [0x391c310]
0x4a4a58: MOV R10, RDI
0x4a4a5b: MOV RAX, qword ptr [R15]
0x4a4a5e: MOV qword ptr [RBP + -0x30], RAX
0x4a4a62: MOV RBX, qword ptr [RSI]
0x4a4a65: MOV R13D, dword ptr [RDX + 0x30]
0x4a4a69: CMP R13D, 0x3
0x4a4a6d: JG 0x004a4aa6
0x4a4a6f: MOV RDX, qword ptr [R10 + 0x8]
0x4a4a73: MOV RAX, qword ptr [R15]
0x4a4a76: CMP RAX, qword ptr [RBP + -0x30]
0x4a4a7a: JNZ 0x004a5c20
0x4a4a80: ADD RBX, 0x60
0x4a4a84: LEA RDI, [0x12c95cb]
0x4a4a8b: MOV ECX, R13D
0x4a4a8e: XOR EAX, EAX
0x4a4a90: MOV RSI, RBX
0x4a4a93: ADD RSP, 0x48
0x4a4a97: POP RBX
0x4a4a98: POP R12
0x4a4a9a: POP R13
0x4a4a9c: POP R14
0x4a4a9e: POP R15
0x4a4aa0: POP RBP
0x4a4aa1: JMP 0x0025d410
0x4a4aa6: MOV R11D, dword ptr [RBX + 0x78]
0x4a4aaa: MOV R12, qword ptr [RDX + 0x10]
0x4a4aae: MOV R14, RSI
0x4a4ab1: TEST R11B, 0x4
0x4a4ab5: JZ 0x004a4bf1
0x4a4abb: MOVZX EAX, byte ptr [R10 + 0x2]
0x4a4ac0: MOV qword ptr [RBP + -0x58], R14
0x4a4ac4: MOV EAX, dword ptr [R14 + RAX*0x4 + 0x12c]
0x4a4acc: CMP RAX, 0x9
0x4a4ad0: JA 0x004a4adf
0x4a4ad2: LEA RCX, [0xe7fbb8]
0x4a4ad9: MOV R8, qword ptr [RCX + RAX*0x8]
0x4a4add: JMP 0x004a4ae6
0x4a4adf: LEA R8, [0x139a485]
0x4a4ae6: MOVZX ECX, byte ptr [R12]
0x4a4aeb: MOV R15, qword ptr [R10 + 0x8]
0x4a4aef: LEA RSI, [RBX + 0x60]
0x4a4af3: MOV qword ptr [RBP + -0x40], RBX
0x4a4af7: MOV qword ptr [RBP + -0x68], RDX
0x4a4afb: MOV qword ptr [RBP + -0x50], R10
0x4a4aff: MOV dword ptr [RBP + -0x48], R11D
0x4a4b03: LEA EAX, [RCX + -0x1]
0x4a4b06: CMP AL, 0xb
0x4a4b08: JNC 0x004a4b1a
0x4a4b0a: MOVZX EAX, AL
0x4a4b0d: LEA RCX, [0xe7fb60]
0x4a4b14: MOV RBX, qword ptr [RCX + RAX*0x8]
0x4a4b18: JMP 0x004a4b45
0x4a4b1a: LEA RBX, [0x3536610]
0x4a4b21: MOV qword ptr [RBP + -0x60], RSI
0x4a4b25: LEA RDX, [0x1383910]
0x4a4b2c: MOV ESI, 0xc
0x4a4b31: XOR EAX, EAX
0x4a4b33: MOV R14, R8
0x4a4b36: MOV RDI, RBX
0x4a4b39: CALL 0x004aee40
0x4a4b3e: MOV RSI, qword ptr [RBP + -0x60]
0x4a4b42: MOV R8, R14
0x4a4b45: MOVBE AX, word ptr [R12 + 0x2]
0x4a4b4d: MOVZX R9D, byte ptr [R12 + 0x1]
0x4a4b53: MOVZX R10D, AX
0x4a4b57: SUB RSP, 0x8
0x4a4b5b: MOV RCX, R8
0x4a4b5e: LEA RDI, [0x12a0608]
0x4a4b65: MOV RDX, R15
0x4a4b68: MOV R8, RBX
0x4a4b6b: XOR EAX, EAX
0x4a4b6d: PUSH R10
0x4a4b6f: CALL 0x0025d410
0x4a4b74: ADD RSP, 0x10
0x4a4b78: CMP R13D, 0x4
0x4a4b7c: JZ 0x004a4bc8
0x4a4b7e: MOVZX ESI, byte ptr [R12 + 0x4]
0x4a4b84: LEA RDI, [0x13af03e]
0x4a4b8b: XOR EAX, EAX
0x4a4b8d: CALL 0x0025d410
0x4a4b92: CMP R13W, 0x5
0x4a4b97: JZ 0x004a4bc8
0x4a4b99: MOV R14D, 0x5
0x4a4b9f: LEA RBX, [0x131cc50]
0x4a4ba6: NOP word ptr CS:[RAX + RAX*0x1]
0x4a4bb0: MOVZX ESI, byte ptr [R12 + R14*0x1]
0x4a4bb5: MOV RDI, RBX
0x4a4bb8: XOR EAX, EAX
0x4a4bba: CALL 0x0025d410
0x4a4bbf: INC R14
0x4a4bc2: CMP R13W, R14W
0x4a4bc6: JNZ 0x004a4bb0
0x4a4bc8: LEA RDI, [0x135c29e]
0x4a4bcf: XOR EAX, EAX
0x4a4bd1: CALL 0x0025d410
0x4a4bd6: MOV RDX, qword ptr [RBP + -0x68]
0x4a4bda: LEA R15, [0x391c310]
0x4a4be1: MOV R14, qword ptr [RBP + -0x58]
0x4a4be5: MOV RBX, qword ptr [RBP + -0x40]
0x4a4be9: MOV R10, qword ptr [RBP + -0x50]
0x4a4bed: MOV R11D, dword ptr [RBP + -0x48]
0x4a4bf1: MOVBE CX, word ptr [R12 + 0x2]
0x4a4bf9: MOV RAX, RDX
0x4a4bfc: MOVZX EDX, CX
0x4a4bff: MOVZX ECX, byte ptr [R12]
0x4a4c04: CMP R13D, EDX
0x4a4c07: CMOVC EDX, R13D
0x4a4c0b: LEA ESI, [RCX + -0x1]
0x4a4c0e: CMP ESI, 0xa
0x4a4c11: JA 0x004a4f51
0x4a4c17: LEA RDI, [0x1594030]
0x4a4c1e: LEA R13, [R12 + 0x4]
0x4a4c23: MOVSXD RSI, dword ptr [RDI + RSI*0x4]
0x4a4c27: ADD RSI, RDI
0x4a4c2a: JMP RSI
0x4a4f51: TEST R11B, 0x4
0x4a4f55: JZ 0x004a4f8d
0x4a4f57: MOV RDX, qword ptr [R10 + 0x8]
0x4a4f5b: LEA RSI, [RBX + 0x60]
0x4a4f5f: LEA RDI, [0x1351482]
0x4a4f66: MOV qword ptr [RBP + -0x40], RBX
0x4a4f6a: MOV RBX, RAX
0x4a4f6d: MOV R13, R14
0x4a4f70: MOV R14, R15
0x4a4f73: XOR EAX, EAX
0x4a4f75: MOV R15, R10
0x4a4f78: CALL 0x0025d410
0x4a4f7d: MOV RAX, RBX
0x4a4f80: MOV RBX, qword ptr [RBP + -0x40]
0x4a4f84: MOV R10, R15
0x4a4f87: MOV R15, R14
0x4a4f8a: MOV R14, R13
0x4a4f8d: MOVZX ECX, byte ptr [R10 + 0x2]
0x4a4f92: MOVZX ESI, word ptr [R10]
0x4a4f96: MOV RDI, R14
0x4a4f99: MOV R9, R12
0x4a4f9c: MOV RDX, qword ptr [R14 + RCX*0x8 + 0x98]
0x4a4fa4: INC RDX
0x4a4fa7: MOV qword ptr [R14 + RCX*0x8 + 0x98], RDX
0x4a4faf: MOVZX ECX, DL
0x4a4fb2: MOV EDX, 0x7
0x4a4fb7: MOVZX R8D, word ptr [RAX + 0x30]
0x4a4fbc: CALL 0x004a4650
0x4a4fc1: JMP 0x004a50a4
0x4a50a4: MOV RAX, qword ptr [R15]
0x4a50a7: CMP RAX, qword ptr [RBP + -0x30]
0x4a50ab: JNZ 0x004a5c20
0x4a50b1: MOV EDX, 0x1
0x4a50b6: MOV RDI, RBX
0x4a50b9: MOV ESI, 0x1
0x4a50be: ADD RSP, 0x48
0x4a50c2: POP RBX
0x4a50c3: POP R12
0x4a50c5: POP R13
0x4a50c7: POP R14
0x4a50c9: POP R15
0x4a50cb: POP RBP
0x4a50cc: JMP 0x004bbf00
0x4a5c20: CALL 0x006fd6b0
0x4a5c25: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a5d70 RVA 0x4a5d70 | Evidence ev_397b63a58cb9d2f84c59998fc61ffe22caa3b0042a072e6a2a62aa221c2bff1b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a5d70:
0x4a5d70: PUSH RBP
0x4a5d71: MOV RBP, RSP
0x4a5d74: PUSH R15
0x4a5d76: PUSH R14
0x4a5d78: PUSH R13
0x4a5d7a: PUSH R12
0x4a5d7c: PUSH RBX
0x4a5d7d: SUB RSP, 0x28
0x4a5d81: MOV R14, RDI
0x4a5d84: LEA RDI, [0x391c310]
0x4a5d8b: MOV RAX, RSI
0x4a5d8e: MOV RCX, qword ptr [RDI]
0x4a5d91: MOV qword ptr [RBP + -0x30], RCX
0x4a5d95: MOV RSI, qword ptr [R14]
0x4a5d98: MOV R12D, dword ptr [RAX + 0x30]
0x4a5d9c: CMP R12D, 0x4
0x4a5da0: JG 0x004a5dd2
0x4a5da2: MOV RAX, qword ptr [RDI]
0x4a5da5: CMP RAX, qword ptr [RBP + -0x30]
0x4a5da9: JNZ 0x004a63a9
0x4a5daf: ADD RSI, 0x60
0x4a5db3: LEA RDI, [0x12de68f]
0x4a5dba: MOV EDX, R12D
0x4a5dbd: XOR EAX, EAX
0x4a5dbf: ADD RSP, 0x28
0x4a5dc3: POP RBX
0x4a5dc4: POP R12
0x4a5dc6: POP R13
0x4a5dc8: POP R14
0x4a5dca: POP R15
0x4a5dcc: POP RBP
0x4a5dcd: JMP 0x0025d410
0x4a5dd2: MOV RBX, qword ptr [RAX + 0x10]
0x4a5dd6: MOV R8D, dword ptr [RSI + 0x78]
0x4a5dda: MOVBE AX, word ptr [RBX + 0x2]
0x4a5de0: MOVZX EDX, byte ptr [RBX]
0x4a5de3: MOVZX R15D, AX
0x4a5de7: CMP R12D, R15D
0x4a5dea: MOV R13D, R15D
0x4a5ded: CMOVC R13D, R12D
0x4a5df1: CMP EDX, 0x3
0x4a5df4: JZ 0x004a5f3d
0x4a5dfa: CMP EDX, 0x2
0x4a5dfd: JZ 0x004a5e8e
0x4a5e03: CMP EDX, 0x1
0x4a5e06: JNZ 0x004a5f8b
0x4a5e0c: CMP qword ptr [R14 + 0x3b8], 0x0
0x4a5e14: JZ 0x004a6018
0x4a5e1a: CMP qword ptr [R14 + 0x3c0], 0x0
0x4a5e22: JZ 0x004a6018
0x4a5e28: MOVSX R12, byte ptr [RBX + 0x4]
0x4a5e2d: LEA EAX, [R13 + -0x6]
0x4a5e31: SUB EAX, R12D
0x4a5e34: JL 0x004a5e49
0x4a5e36: LEA RCX, [RBX + R12*0x1 + 0x5]
0x4a5e3b: MOVSX ECX, byte ptr [RCX]
0x4a5e3e: MOV dword ptr [RBP + -0x40], ECX
0x4a5e41: CMP EAX, ECX
0x4a5e43: JGE 0x004a61df
0x4a5e49: MOVZX ECX, byte ptr [RBX + 0x1]
0x4a5e4d: MOV R14, RDI
0x4a5e50: ADD RSI, 0x60
0x4a5e54: LEA RDI, [0x13277b8]
0x4a5e5b: LEA RDX, [0x128b74c]
0x4a5e62: MOV R8D, R15D
0x4a5e65: XOR EAX, EAX
0x4a5e67: CALL 0x0025d410
0x4a5e6c: CMP R13D, 0x5
0x4a5e70: JC 0x004a5e86
0x4a5e72: ADD R13D, -0x4
0x4a5e76: ADD RBX, 0x4
0x4a5e7a: MOVZX ESI, R13W
0x4a5e7e: MOV RDI, RBX
0x4a5e81: CALL 0x004ab850
0x4a5e86: MOV RAX, qword ptr [R14]
0x4a5e89: JMP 0x004a6002
0x4a5e8e: LEA RDI, [R14 + 0x2d0]
0x4a5e95: MOV qword ptr [RBP + -0x40], RSI
0x4a5e99: XOR ESI, ESI
0x4a5e9b: XOR EDX, EDX
0x4a5e9d: MOV R15D, R8D
0x4a5ea0: CALL 0x00b9afd0
0x4a5ea5: TEST R15B, 0x4
0x4a5ea9: JZ 0x004a6043
0x4a5eaf: MOV RAX, qword ptr [RBP + -0x40]
0x4a5eb3: LEA RDI, [0x1307926]
0x4a5eba: LEA RSI, [RAX + 0x60]
0x4a5ebe: XOR EAX, EAX
0x4a5ec0: CALL 0x0025d410
0x4a5ec5: MOVZX EAX, byte ptr [RBX]
0x4a5ec8: CMP R13D, 0x6
0x4a5ecc: SETNC CL
0x4a5ecf: TEST AL, AL
0x4a5ed1: SETNZ DL
0x4a5ed4: AND DL, CL
0x4a5ed6: CMP DL, 0x1
0x4a5ed9: JNZ 0x004a6035
0x4a5edf: LEA RDI, [0x138fc95]
0x4a5ee6: MOVSX R15D, AL
0x4a5eea: XOR EAX, EAX
0x4a5eec: CALL 0x0025d410
0x4a5ef1: MOVZX R12D, R15W
0x4a5ef5: LEA R13, [0x131cc6d]
0x4a5efc: XOR R15D, R15D
0x4a5eff: JMP 0x004a5f24
0x4a5f10: XOR EAX, EAX
0x4a5f12: CALL 0x0025d410
0x4a5f17: INC R15
0x4a5f1a: CMP R12W, R15W
0x4a5f1e: JZ 0x004a6035
0x4a5f24: MOVZX ESI, byte ptr [RBX + R15*0x1 + 0x4]
0x4a5f2a: MOV RDI, R13
0x4a5f2d: LEA EAX, [RSI + -0x7f]
0x4a5f30: CMP AL, 0xa1
0x4a5f32: JC 0x004a5f10
0x4a5f34: LEA RDI, [0x132ff89]
0x4a5f3b: JMP 0x004a5f10
0x4a5f3d: LEA RDI, [R14 + 0x2d0]
0x4a5f44: MOV R15, RSI
0x4a5f47: XOR ESI, ESI
0x4a5f49: XOR EDX, EDX
0x4a5f4b: MOV R12D, R8D
0x4a5f4e: CALL 0x00b9afd0
0x4a5f53: INC dword ptr [R14 + 0x110]
0x4a5f5a: MOV RSI, R15
0x4a5f5d: ADD RSI, 0x60
0x4a5f61: TEST R12B, 0x4
0x4a5f65: JNZ 0x004a610f
0x4a5f6b: LEA RAX, [0x391c310]
0x4a5f72: MOV RAX, qword ptr [RAX]
0x4a5f75: CMP RAX, qword ptr [RBP + -0x30]
0x4a5f79: JNZ 0x004a63a9
0x4a5f7f: LEA RDI, [0x139a52c]
0x4a5f86: JMP 0x004a60fa
0x4a5f8b: MOVZX ECX, byte ptr [RBX + 0x1]
0x4a5f8f: ADD RSI, 0x60
0x4a5f93: LEA RDI, [0x1277a78]
0x4a5f9a: MOV R8D, R15D
0x4a5f9d: XOR EAX, EAX
0x4a5f9f: CALL 0x0025d410
0x4a5fa4: CMP R13D, 0x5
0x4a5fa8: JC 0x004a5ff8
0x4a5faa: MOVZX ESI, byte ptr [RBX + 0x4]
0x4a5fae: LEA RDI, [0x13af03e]
0x4a5fb5: XOR EAX, EAX
0x4a5fb7: CALL 0x0025d410
0x4a5fbc: CMP R13W, 0x5
0x4a5fc1: JZ 0x004a5ff8
0x4a5fc3: MOV EAX, R15D
0x4a5fc6: MOV R15D, 0x5
0x4a5fcc: LEA R14, [0x131cc50]
0x4a5fd3: CMP RAX, R12
0x4a5fd6: CMOVC R12, RAX
0x4a5fda: NOP word ptr [RAX + RAX*0x1]
0x4a5fe0: MOVZX ESI, byte ptr [RBX + R15*0x1]
0x4a5fe5: MOV RDI, R14
0x4a5fe8: XOR EAX, EAX
0x4a5fea: CALL 0x0025d410
0x4a5fef: INC R15
0x4a5ff2: CMP R12W, R15W
0x4a5ff6: JNZ 0x004a5fe0
0x4a5ff8: LEA RAX, [0x391c310]
0x4a5fff: MOV RAX, qword ptr [RAX]
0x4a6002: CMP RAX, qword ptr [RBP + -0x30]
0x4a6006: JNZ 0x004a63a9
0x4a600c: LEA RDI, [0x135c29e]
0x4a6013: JMP 0x004a61a0
0x4a6018: MOV RAX, qword ptr [RDI]
0x4a601b: CMP RAX, qword ptr [RBP + -0x30]
0x4a601f: JNZ 0x004a63a9
0x4a6025: ADD RSI, 0x60
0x4a6029: LEA RDI, [0x138fc98]
0x4a6030: JMP 0x004a60fa
0x4a6035: LEA RDI, [0x1339b17]
0x4a603c: XOR EAX, EAX
0x4a603e: CALL 0x0025d410
0x4a6043: LEA RBX, [R14 + 0x188]
0x4a604a: XOR ESI, ESI
0x4a604c: XOR EDX, EDX
0x4a604e: XOR ECX, ECX
0x4a6050: MOV RDI, RBX
0x4a6053: CALL 0x004c6a00
0x4a6058: MOV dword ptr [R14 + 0x110], 0x0
0x4a6063: AND byte ptr [R14 + 0x80], 0xef
0x4a606b: CMP word ptr [R14 + 0x380], 0xc023
0x4a6075: JNZ 0x004a60bb
0x4a6077: TEST byte ptr [R14 + 0x310], 0x8
0x4a607f: JZ 0x004a60bb
0x4a6081: TEST byte ptr [R14 + 0x330], 0x8
0x4a6089: JNZ 0x004a60bb
0x4a608b: LEA RAX, [0x391c310]
0x4a6092: MOV RAX, qword ptr [RAX]
0x4a6095: CMP RAX, qword ptr [RBP + -0x30]
0x4a6099: JNZ 0x004a63a9
0x4a609f: MOV RDI, RBX
0x4a60a2: XOR ESI, ESI
0x4a60a4: XOR EDX, EDX
0x4a60a6: XOR ECX, ECX
0x4a60a8: ADD RSP, 0x28
0x4a60ac: POP RBX
0x4a60ad: POP R12
0x4a60af: POP R13
0x4a60b1: POP R14
0x4a60b3: POP R15
0x4a60b5: POP RBP
0x4a60b6: JMP 0x004c6fa0
0x4a60bb: MOV RDI, RBX
0x4a60be: XOR ESI, ESI
0x4a60c0: XOR EDX, EDX
0x4a60c2: XOR ECX, ECX
0x4a60c4: CALL 0x004c6fa0
0x4a60c9: CMP dword ptr [R14 + 0x118], 0x4
0x4a60d1: JNZ 0x004a61b5
0x4a60d7: LEA RAX, [0x391c310]
0x4a60de: MOV RAX, qword ptr [RAX]
0x4a60e1: CMP RAX, qword ptr [RBP + -0x30]
0x4a60e5: MOV RSI, qword ptr [RBP + -0x40]
0x4a60e9: JNZ 0x004a63a9
0x4a60ef: ADD RSI, 0x60
0x4a60f3: LEA RDI, [0x135150a]
0x4a60fa: XOR EAX, EAX
0x4a60fc: ADD RSP, 0x28
0x4a6100: POP RBX
0x4a6101: POP R12
0x4a6103: POP R13
0x4a6105: POP R14
0x4a6107: POP R15
0x4a6109: POP RBP
0x4a610a: JMP 0x0025d410
0x4a610f: LEA RDI, [0x126e359]
0x4a6116: XOR EAX, EAX
0x4a6118: CALL 0x0025d410
0x4a611d: MOVZX EAX, byte ptr [RBX]
0x4a6120: CMP R13D, 0x6
0x4a6124: SETNC CL
0x4a6127: TEST AL, AL
0x4a6129: SETNZ DL
0x4a612c: AND DL, CL
0x4a612e: CMP DL, 0x1
0x4a6131: JNZ 0x004a6185
0x4a6133: LEA RDI, [0x138fc95]
0x4a613a: MOVSX R14D, AL
0x4a613e: XOR EAX, EAX
0x4a6140: CALL 0x0025d410
0x4a6145: MOVZX R14D, R14W
0x4a6149: LEA R15, [0x131cc6d]
0x4a6150: LEA R12, [0x132ff89]
0x4a6157: XOR R13D, R13D
0x4a615a: JMP 0x004a6170
0x4a6160: XOR EAX, EAX
0x4a6162: CALL 0x0025d410
0x4a6167: INC R13
0x4a616a: CMP R14W, R13W
0x4a616e: JZ 0x004a6185
0x4a6170: MOVZX ESI, byte ptr [RBX + R13*0x1 + 0x4]
0x4a6176: MOV RDI, R15
0x4a6179: LEA EAX, [RSI + -0x7f]
0x4a617c: CMP AL, 0xa1
0x4a617e: JC 0x004a6160
0x4a6180: MOV RDI, R12
0x4a6183: JMP 0x004a6160
0x4a6185: LEA RAX, [0x391c310]
0x4a618c: MOV RAX, qword ptr [RAX]
0x4a618f: CMP RAX, qword ptr [RBP + -0x30]
0x4a6193: JNZ 0x004a63a9
0x4a6199: LEA RDI, [0x1339b17]
0x4a61a0: XOR EAX, EAX
0x4a61a2: ADD RSP, 0x28
0x4a61a6: POP RBX
0x4a61a7: POP R12
0x4a61a9: POP R13
0x4a61ab: POP R14
0x4a61ad: POP R15
0x4a61af: POP RBP
0x4a61b0: JMP 0x0025d410
0x4a61b5: LEA RAX, [0x391c310]
0x4a61bc: MOV RAX, qword ptr [RAX]
0x4a61bf: CMP RAX, qword ptr [RBP + -0x30]
0x4a61c3: JNZ 0x004a63a9
0x4a61c9: MOV RDI, R14
0x4a61cc: ADD RSP, 0x28
0x4a61d0: POP RBX
0x4a61d1: POP R12
0x4a61d3: POP R13
0x4a61d5: POP R14
0x4a61d7: POP R15
0x4a61d9: POP RBP
0x4a61da: JMP 0x004ab270
0x4a61df: LEA RCX, [RBX + R12*0x1 + 0x6]
0x4a61e4: LEA RAX, [RBX + 0x5]
0x4a61e8: MOV qword ptr [RBP + -0x50], RAX
0x4a61ec: MOV qword ptr [RBP + -0x48], RCX
0x4a61f0: TEST R8B, 0x4
0x4a61f4: JZ 0x004a6274
0x4a61f6: MOV EAX, dword ptr [R14 + 0x138]
0x4a61fd: ADD RSI, 0x60
0x4a6201: MOV R13, RDI
0x4a6204: CMP RAX, 0x9
0x4a6208: JA 0x004a6217
0x4a620a: LEA RCX, [0xe7fbb8]
0x4a6211: MOV RDX, qword ptr [RCX + RAX*0x8]
0x4a6215: JMP 0x004a621e
0x4a6217: LEA RDX, [0x139a485]
0x4a621e: MOVZX R8D, byte ptr [RBX + 0x1]
0x4a6223: LEA RDI, [0x12fd379]
0x4a622a: LEA RCX, [0x128b74c]
0x4a6231: MOV R9D, R15D
0x4a6234: XOR EAX, EAX
0x4a6236: CALL 0x0025d410
0x4a623b: MOV RDI, qword ptr [RBP + -0x50]
0x4a623f: MOVZX ESI, R12W
0x4a6243: CALL 0x004ad490
0x4a6248: LEA RDI, [0x12f2c11]
0x4a624f: XOR EAX, EAX
0x4a6251: CALL 0x0025d410
0x4a6256: MOVZX ESI, word ptr [RBP + -0x40]
0x4a625a: MOV RDI, qword ptr [RBP + -0x48]
0x4a625e: CALL 0x004ad490
0x4a6263: LEA RDI, [0x135c29e]
0x4a626a: XOR EAX, EAX
0x4a626c: CALL 0x0025d410
0x4a6271: MOV RDI, R13
0x4a6274: MOVZX EAX, byte ptr [R14 + 0x3c8]
0x4a627c: MOV R15, RDI
0x4a627f: CMP R12D, EAX
0x4a6282: JNZ 0x004a62bf
0x4a6284: MOVZX EAX, byte ptr [R14 + 0x3c9]
0x4a628c: CMP dword ptr [RBP + -0x40], EAX
0x4a628f: JNZ 0x004a62bf
0x4a6291: MOV RSI, qword ptr [R14 + 0x3b8]
0x4a6298: MOV RDI, qword ptr [RBP + -0x50]
0x4a629c: MOV RDX, R12
0x4a629f: CALL 0x00339bd0
0x4a62a4: TEST EAX, EAX
0x4a62a6: JNZ 0x004a62bf
0x4a62a8: MOV RSI, qword ptr [R14 + 0x3c0]
0x4a62af: MOV EDX, dword ptr [RBP + -0x40]
0x4a62b2: MOV RDI, qword ptr [RBP + -0x48]
0x4a62b6: CALL 0x00339bd0
0x4a62bb: TEST EAX, EAX
0x4a62bd: JZ 0x004a6327
0x4a62bf: INC dword ptr [R14 + 0x110]
0x4a62c6: MOV byte ptr [RBP + -0x31], 0x9
0x4a62ca: MOVZX ECX, byte ptr [RBX + 0x1]
0x4a62ce: SUB RSP, 0x8
0x4a62d2: LEA R10, [0x13aff38]
0x4a62d9: LEA RDI, [0xe7f9a0]
0x4a62e0: LEA R9, [RBP + -0x31]
0x4a62e4: MOV R8D, 0x1
0x4a62ea: MOV RSI, R14
0x4a62ed: MOV EDX, 0x3
0x4a62f2: XOR EAX, EAX
0x4a62f4: PUSH 0x0
0x4a62f6: PUSH R10
0x4a62f8: PUSH 0x9
0x4a62fa: CALL 0x004ab310
0x4a62ff: ADD RSP, 0x20
0x4a6303: MOV RDI, R14
0x4a6306: CALL 0x004ab0c0
0x4a630b: MOV RAX, qword ptr [R15]
0x4a630e: CMP RAX, qword ptr [RBP + -0x30]
0x4a6312: JNZ 0x004a63a9
0x4a6318: ADD RSP, 0x28
0x4a631c: POP RBX
0x4a631d: POP R12
0x4a631f: POP R13
0x4a6321: POP R14
0x4a6323: POP R15
0x4a6325: POP RBP
0x4a6326: RET
0x4a6327: MOV EAX, dword ptr [R14 + 0x138]
0x4a632e: CMP EAX, 0x9
0x4a6331: JZ 0x004a6338
0x4a6333: CMP EAX, 0x6
0x4a6336: JNZ 0x004a637c
0x4a6338: MOV byte ptr [RBP + -0x31], 0x8
0x4a633c: MOVZX ECX, byte ptr [RBX + 0x1]
0x4a6340: SUB RSP, 0x8
0x4a6344: XOR EAX, EAX
0x4a6346: LEA R10, [0x1277a6f]
0x4a634d: LEA RDI, [0xe7f9a0]
0x4a6354: LEA R9, [RBP + -0x31]
0x4a6358: MOV R8D, 0x1
0x4a635e: MOV RSI, R14
0x4a6361: MOV EDX, 0x2
0x4a6366: PUSH 0x0
0x4a6368: PUSH R10
0x4a636a: PUSH 0x8
0x4a636c: CALL 0x004ab310
0x4a6371: ADD RSP, 0x20
0x4a6375: MOV EAX, dword ptr [R14 + 0x138]
0x4a637c: CMP EAX, 0x6
0x4a637f: JNZ 0x004a630b
0x4a6381: LEA RDI, [R14 + 0x250]
0x4a6388: MOV dword ptr [R14 + 0x138], 0x9
0x4a6393: XOR ESI, ESI
0x4a6395: XOR EDX, EDX
0x4a6397: CALL 0x00b9afd0
0x4a639c: MOV RDI, R14
0x4a639f: CALL 0x004ab020
0x4a63a4: JMP 0x004a630b
0x4a63a9: CALL 0x006fd6b0
0x4a63ae: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a63b0 RVA 0x4a63b0 | Evidence ev_58db8d422962e5bb71fa7d528a07a1796d4aecd3dae0f2f99fac98ff6a40c5d4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a63b0:
0x4a63b0: PUSH RBP
0x4a63b1: MOV RBP, RSP
0x4a63b4: PUSH R15
0x4a63b6: PUSH R14
0x4a63b8: PUSH R13
0x4a63ba: PUSH R12
0x4a63bc: PUSH RBX
0x4a63bd: SUB RSP, 0xa8
0x4a63c4: LEA R12, [0x391c310]
0x4a63cb: MOV RAX, RSI
0x4a63ce: MOV RCX, qword ptr [R12]
0x4a63d2: MOV qword ptr [RBP + -0x30], RCX
0x4a63d6: MOV RSI, qword ptr [RDI]
0x4a63d9: MOV R14D, dword ptr [RAX + 0x30]
0x4a63dd: CMP R14D, 0x3
0x4a63e1: JG 0x004a6417
0x4a63e3: MOV RAX, qword ptr [R12]
0x4a63e7: CMP RAX, qword ptr [RBP + -0x30]
0x4a63eb: JNZ 0x004a6e6a
0x4a63f1: ADD RSI, 0x60
0x4a63f5: LEA RDI, [0x13514a1]
0x4a63fc: MOV EDX, R14D
0x4a63ff: XOR EAX, EAX
0x4a6401: ADD RSP, 0xa8
0x4a6408: POP RBX
0x4a6409: POP R12
0x4a640b: POP R13
0x4a640d: POP R14
0x4a640f: POP R15
0x4a6411: POP RBP
0x4a6412: JMP 0x0025d410
0x4a6417: MOV RBX, qword ptr [RAX + 0x10]
0x4a641b: MOVBE AX, word ptr [RBX + 0x2]
0x4a6421: MOVZX ECX, byte ptr [RBX]
0x4a6424: MOVZX R13D, AX
0x4a6428: LEA EAX, [RCX + -0x1]
0x4a642b: CMP R14D, R13D
0x4a642e: MOV R15D, R13D
0x4a6431: CMOVC R15D, R14D
0x4a6435: CMP EAX, 0x3
0x4a6438: JA 0x004a669b
0x4a643e: LEA RCX, [0x15940d8]
0x4a6445: MOV R8D, dword ptr [RSI + 0x78]
0x4a6449: MOVSXD RAX, dword ptr [RCX + RAX*0x4]
0x4a644d: ADD RAX, RCX
0x4a6450: JMP RAX
0x4a669b: MOV EAX, dword ptr [RDI + 0x13c]
0x4a66a1: ADD RSI, 0x60
0x4a66a5: CMP RAX, 0x9
0x4a66a9: JA 0x004a6814
0x4a66af: LEA RDX, [0xe7fbb8]
0x4a66b6: MOV RDX, qword ptr [RDX + RAX*0x8]
0x4a66ba: JMP 0x004a681b
0x4a6814: LEA RDX, [0x139a485]
0x4a681b: MOVZX R8D, byte ptr [RBX + 0x1]
0x4a6820: LEA RDI, [0x139a4fb]
0x4a6827: MOV R9D, R13D
0x4a682a: XOR EAX, EAX
0x4a682c: CALL 0x0025d410
0x4a6831: CMP R15D, 0x5
0x4a6835: JC 0x004a6888
0x4a6837: MOVZX ESI, byte ptr [RBX + 0x4]
0x4a683b: LEA RDI, [0x13af03e]
0x4a6842: XOR EAX, EAX
0x4a6844: CALL 0x0025d410
0x4a6849: CMP R15W, 0x5
0x4a684e: JZ 0x004a6888
0x4a6850: MOV EAX, R13D
0x4a6853: MOV R12D, 0x5
0x4a6859: LEA R15, [0x131cc50]
0x4a6860: CMP RAX, R14
0x4a6863: CMOVC R14, RAX
0x4a6867: NOP word ptr [RAX + RAX*0x1]
0x4a6870: MOVZX ESI, byte ptr [RBX + R12*0x1]
0x4a6875: MOV RDI, R15
0x4a6878: XOR EAX, EAX
0x4a687a: CALL 0x0025d410
0x4a687f: INC R12
0x4a6882: CMP R14W, R12W
0x4a6886: JNZ 0x004a6870
0x4a6888: LEA RAX, [0x391c310]
0x4a688f: MOV RAX, qword ptr [RAX]
0x4a6892: CMP RAX, qword ptr [RBP + -0x30]
0x4a6896: JNZ 0x004a6e6a
0x4a689c: LEA RDI, [0x135c29e]
0x4a68a3: XOR EAX, EAX
0x4a68a5: ADD RSP, 0xa8
0x4a68ac: POP RBX
0x4a68ad: POP R12
0x4a68af: POP R13
0x4a68b1: POP R14
0x4a68b3: POP R15
0x4a68b5: POP RBP
0x4a68b6: JMP 0x0025d410
0x4a6e6a: CALL 0x006fd6b0
0x4a6e6f: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a6e80 RVA 0x4a6e80 | Evidence ev_86068867b9b139429704cbcb8b074e85b6393456e2a71baaf995f23e9600e779 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
sub_4a6e80:
0x4a6e80: PUSH RBP
0x4a6e81: MOV RBP, RSP
0x4a6e84: PUSH R14
0x4a6e86: PUSH RBX
0x4a6e87: SUB RSP, 0x10
0x4a6e8b: MOV R14, qword ptr [RDI + 0x48]
0x4a6e8f: LEA RSI, [0x1277a25]
0x4a6e96: LEA RDX, [0x132590a]
0x4a6e9d: MOV ECX, 0x4
0x4a6ea2: LEA RDI, [R14 + 0x188]
0x4a6ea9: CALL 0x004c7dd0
0x4a6eae: MOV RAX, qword ptr [0x03536580]
0x4a6eb5: TEST RAX, RAX
0x4a6eb8: JNZ 0x004a6f0c
0x4a6eba: LEA RBX, [0x3536588]
0x4a6ec1: MOV ESI, 0x8
0x4a6ec6: MOV RDI, RBX
0x4a6ec9: CALL 0x00b9b640
0x4a6ece: MOV EAX, dword ptr [0x03920440]
0x4a6ed4: LEA RCX, [0x261eb0]
0x4a6edb: MOV RDI, RBX
0x4a6ede: MOV R9D, 0xffffffff
0x4a6ee4: MOV dword ptr [RSP], 0x100
0x4a6eeb: XOR EDX, EDX
0x4a6eed: XOR R8D, R8D
0x4a6ef0: ADD EAX, EAX
0x4a6ef2: LEA EAX, [RAX + RAX*0x4]
0x4a6ef5: MOVSXD RSI, EAX
0x4a6ef8: IMUL RSI, qword ptr [0x039203d0]
0x4a6f00: CALL 0x00b9aa40
0x4a6f05: MOV RAX, qword ptr [0x03536580]
0x4a6f0c: MOV qword ptr [R14 + 0x78], RAX
0x4a6f10: MOV qword ptr [0x03536580], R14
0x4a6f17: LEA RCX, [0x26f418]
0x4a6f1e: LEA RDI, [R14 + 0x98]
0x4a6f25: MOV ESI, 0x28
0x4a6f2a: MOV RAX, qword ptr [R14]
0x4a6f2d: MOV byte ptr [RAX + 0x9c], 0x17
0x4a6f34: MOV RAX, qword ptr [R14]
0x4a6f37: MOV qword ptr [RAX + 0x488], RCX
0x4a6f3e: MOV dword ptr [R14 + 0x1c], 0x20
0x4a6f46: MOV dword ptr [R14 + 0x54], 0x14
0x4a6f4e: MOV qword ptr [R14 + 0x88], 0x0
0x4a6f59: MOV qword ptr [R14 + 0x100], 0x0
0x4a6f64: MOV qword ptr [R14 + 0xf0], 0x0
0x4a6f6f: MOV dword ptr [R14 + 0x90], 0x3
0x4a6f7a: MOV qword ptr [R14 + 0xf8], 0xf
0x4a6f85: MOV qword ptr [R14 + 0x108], 0x0
0x4a6f90: CALL 0x00258ff0
0x4a6f95: LEA RDI, [R14 + 0xc0]
0x4a6f9c: MOV ESI, 0x28
0x4a6fa1: CALL 0x00258ff0
0x4a6fa6: MOV RAX, 0x500000000
0x4a6fb0: LEA RDX, [0x261eb8]
0x4a6fb7: LEA RCX, [0x261ec0]
0x4a6fbe: MOV qword ptr [R14 + 0x110], RAX
0x4a6fc5: MOV dword ptr [R14 + 0x118], 0x0
0x4a6fd0: MOV qword ptr [R14 + 0x3e0], RDX
0x4a6fd7: MOV qword ptr [R14 + 0x3e8], RCX
0x4a6fde: TEST byte ptr [R14 + 0x62], 0x1
0x4a6fe3: JNZ 0x004a6ff9
0x4a6fe5: LEA RDI, [R14 + 0x70]
0x4a6fe9: LEA RSI, [0x12e8702]
0x4a6ff0: XOR EDX, EDX
0x4a6ff2: XOR ECX, ECX
0x4a6ff4: CALL 0x004c7dd0
0x4a6ff9: TEST byte ptr [R14 + 0x2a], 0x1
0x4a6ffe: JNZ 0x004a7014
0x4a7000: LEA RDI, [R14 + 0x38]
0x4a7004: LEA RSI, [0x129637f]
0x4a700b: XOR EDX, EDX
0x4a700d: XOR ECX, ECX
0x4a700f: CALL 0x004c7dd0
0x4a7014: LEA RDI, [R14 + 0x380]
0x4a701b: MOV ESI, 0x30
0x4a7020: CALL 0x00258ff0
0x4a7025: LEA RDI, [R14 + 0x3b0]
0x4a702c: MOV ESI, 0x30
0x4a7031: CALL 0x00258ff0
0x4a7036: MOV qword ptr [R14 + 0x310], 0x20
0x4a7041: MOV qword ptr [R14 + 0x318], 0x0
0x4a704c: MOV dword ptr [R14 + 0x12c], 0x0
0x4a7057: MOV dword ptr [R14 + 0x15c], 0x0
0x4a7062: MOV qword ptr [R14 + 0x98], 0x0
0x4a706d: MOV qword ptr [R14 + 0xc0], 0x0
0x4a7078: MOV qword ptr [R14 + 0x330], 0x0
0x4a7083: MOV qword ptr [R14 + 0x328], 0x5dc
0x4a708e: MOV qword ptr [R14 + 0x320], 0x5dc
0x4a7099: MOV RCX, 0xa00000002
0x4a70a3: LEA RDI, [R14 + 0x190]
0x4a70aa: MOV ESI, 0x8
0x4a70af: MOV EAX, dword ptr [0x03920440]
0x4a70b5: MOV dword ptr [R14 + 0x33c], EAX
0x4a70bc: MOV qword ptr [R14 + 0x340], RCX
0x4a70c3: MOV dword ptr [R14 + 0x348], 0xa
0x4a70ce: CALL 0x00b9b640
0x4a70d3: LEA RDI, [R14 + 0x1d0]
0x4a70da: MOV ESI, 0x8
0x4a70df: MOV qword ptr [R14 + 0x350], 0x0
0x4a70ea: MOV dword ptr [R14 + 0x358], 0x0
0x4a70f5: MOV dword ptr [R14 + 0x130], 0x0
0x4a7100: MOV dword ptr [R14 + 0x160], 0x0
0x4a710b: MOV qword ptr [R14 + 0xa0], 0x0
0x4a7116: MOV qword ptr [R14 + 0xc8], 0x0
0x4a7121: CALL 0x00b9b640
0x4a7126: LEA RDI, [R14 + 0x250]
0x4a712d: MOV ESI, 0x8
0x4a7132: MOV dword ptr [R14 + 0x138], 0x2
0x4a713d: MOV dword ptr [R14 + 0x168], 0x0
0x4a7148: MOV qword ptr [R14 + 0xb0], 0x0
0x4a7153: MOV qword ptr [R14 + 0xd8], 0x0
0x4a715e: CALL 0x00b9b640
0x4a7163: LEA RDI, [R14 + 0x2d0]
0x4a716a: MOV ESI, 0x8
0x4a716f: CALL 0x00b9b640
0x4a7174: LEA RDI, [R14 + 0x290]
0x4a717b: MOV ESI, 0x8
0x4a7180: MOV dword ptr [R14 + 0x13c], 0x2
0x4a718b: MOV dword ptr [R14 + 0x16c], 0x0


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): credential_bit62_predicate RVA 0x608f90 | Evidence ev_d868091f9a6f6b9f04dcc2affd8e4028a0950346d4f8cbeccee7c2384b5c3673 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.functions/0x608f90.json | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.elf SHA256 843fa164383f956095dc4042a013c49d64f59c358ea7f43c10f0d9923485fd5a =====
credential_bit62_predicate:
0x608f90: PUSH RBP
0x608f91: MOV RBP, RSP
0x608f94: MOV RAX, qword ptr [RDI + 0x60]
0x608f98: SHR RAX, 0x3e
0x608f9c: AND EAX, 0x1
0x608f9f: POP RBP
0x608fa0: RET


; ===== SUPPLEMENTAL GNU objdump full linear disassembly of every original4096 input byte =====
; Source raw file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_667.bin
; This is independent linear decoding, not REA function discovery; padding/data may decode as instructions.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_667.bin:     file format binary


Disassembly of section .data:

0000000000265f88 <.data>:
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
  266f78:	e9 f3 bc 9c 00       	jmp    0xc32c70
  266f7d:	cc                   	int3
  266f7e:	cc                   	int3
  266f7f:	cc                   	int3
  266f80:	e9 eb dc 9c 00       	jmp    0xc34c70
  266f85:	cc                   	int3
  266f86:	cc                   	int3
  266f87:	cc                   	int3


; ===== SUPPLEMENTAL GNU objdump FULL original target-window bytes =====
; Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9
; RVA 0x4a31a0; size16384 bytes. This linear decode may include adjacent code/data and is not a REA boundary claim.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin:     file format binary


Disassembly of section .data:

00000000004a31a0 <.data>:
  4a31a0:	55                   	push   rbp
  4a31a1:	48 89 e5             	mov    rbp,rsp
  4a31a4:	41 57                	push   r15
  4a31a6:	41 56                	push   r14
  4a31a8:	41 55                	push   r13
  4a31aa:	41 54                	push   r12
  4a31ac:	53                   	push   rbx
  4a31ad:	48 83 ec 68          	sub    rsp,0x68
  4a31b1:	4c 8d 35 58 91 47 03 	lea    r14,[rip+0x3479158]        # 0x391c310
  4a31b8:	48 89 fb             	mov    rbx,rdi
  4a31bb:	49 89 f7             	mov    r15,rsi
  4a31be:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a31c1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  4a31c5:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  4a31cc:	e8 bf 5d 16 00       	call   0x608f90
  4a31d1:	85 c0                	test   eax,eax
  4a31d3:	0f 84 ee 02 00 00    	je     0x4a34c7
  4a31d9:	49 83 3f 00          	cmp    QWORD PTR [r15],0x0
  4a31dd:	0f 84 ee 02 00 00    	je     0x4a34d1
  4a31e3:	49 8b 7f 08          	mov    rdi,QWORD PTR [r15+0x8]
  4a31e7:	e8 54 f8 2d 00       	call   0x782a40
  4a31ec:	83 f8 ff             	cmp    eax,0xffffffff
  4a31ef:	0f 84 cf 03 00 00    	je     0x4a35c4
  4a31f5:	89 c1                	mov    ecx,eax
  4a31f7:	b8 16 00 00 00       	mov    eax,0x16
  4a31fc:	8d 91 ef d8 ff ff    	lea    edx,[rcx-0x2711]
  4a3202:	81 fa f0 d8 ff ff    	cmp    edx,0xffffd8f0
  4a3208:	0f 82 f4 03 00 00    	jb     0x4a3602
  4a320e:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a3211:	c1 e1 03             	shl    ecx,0x3
  4a3214:	48 8d 3d 45 6c 0e 03 	lea    rdi,[rip+0x30e6c45]        # 0x3589e60
  4a321b:	4c 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r15
  4a3222:	48 c7 45 80 00 00 00 	mov    QWORD PTR [rbp-0x80],0x0
  4a3229:	00 
  4a322a:	31 f6                	xor    esi,esi
  4a322c:	31 d2                	xor    edx,edx
  4a322e:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  4a3232:	8d 04 89             	lea    eax,[rcx+rcx*4]
  4a3235:	48 8d 4d 90          	lea    rcx,[rbp-0x70]
  4a3239:	48 89 4d a0          	mov    QWORD PTR [rbp-0x60],rcx
  4a323d:	c7 45 a8 01 00 00 00 	mov    DWORD PTR [rbp-0x58],0x1
  4a3244:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
  4a324b:	00 
  4a324c:	31 c9                	xor    ecx,ecx
  4a324e:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  4a3252:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  4a3259:	00 
  4a325a:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  4a325e:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  4a3262:	e8 e9 80 7a 00       	call   0xc4b350
  4a3267:	4c 8b 3d 12 6c 0e 03 	mov    r15,QWORD PTR [rip+0x30e6c12]        # 0x3589e80
  4a326e:	4d 85 ff             	test   r15,r15
  4a3271:	0f 84 54 03 00 00    	je     0x4a35cb
  4a3277:	4c 8d 2d a2 4e 62 01 	lea    r13,[rip+0x1624ea2]        # 0x1ac8120
  4a327e:	48 c7 45 80 00 00 00 	mov    QWORD PTR [rbp-0x80],0x0
  4a3285:	00 
  4a3286:	eb 22                	jmp    0x4a32aa
  4a3288:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  4a328f:	00 
  4a3290:	4c 89 e7             	mov    rdi,r12
  4a3293:	31 f6                	xor    esi,esi
  4a3295:	31 d2                	xor    edx,edx
  4a3297:	31 c9                	xor    ecx,ecx
  4a3299:	e8 02 3d 02 00       	call   0x4c6fa0
  4a329e:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  4a32a1:	4d 85 ff             	test   r15,r15
  4a32a4:	0f 84 21 03 00 00    	je     0x4a35cb
  4a32aa:	4d 8d a7 48 01 00 00 	lea    r12,[r15+0x148]
  4a32b1:	31 f6                	xor    esi,esi
  4a32b3:	31 d2                	xor    edx,edx
  4a32b5:	31 c9                	xor    ecx,ecx
  4a32b7:	4c 89 e7             	mov    rdi,r12
  4a32ba:	e8 41 37 02 00       	call   0x4c6a00
  4a32bf:	41 83 bf d0 05 00 00 	cmp    DWORD PTR [r15+0x5d0],0x2
  4a32c6:	02 
  4a32c7:	72 c7                	jb     0x4a3290
  4a32c9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  4a32d0:	41 83 bf b8 00 00 00 	cmp    DWORD PTR [r15+0xb8],0x1
  4a32d7:	01 
  4a32d8:	75 b6                	jne    0x4a3290
  4a32da:	49 63 9f 48 0b 00 00 	movsxd rbx,DWORD PTR [r15+0xb48]
  4a32e1:	4c 89 e7             	mov    rdi,r12
  4a32e4:	31 f6                	xor    esi,esi
  4a32e6:	31 d2                	xor    edx,edx
  4a32e8:	31 c9                	xor    ecx,ecx
  4a32ea:	e8 b1 3c 02 00       	call   0x4c6fa0
  4a32ef:	48 89 d8             	mov    rax,rbx
  4a32f2:	4c 89 ee             	mov    rsi,r13
  4a32f5:	ba 02 01 00 00       	mov    edx,0x102
  4a32fa:	48 c1 e0 03          	shl    rax,0x3
  4a32fe:	48 8d 3c 80          	lea    rdi,[rax+rax*4]
  4a3302:	e8 49 58 76 00       	call   0xc08b50
  4a3307:	4c 89 e7             	mov    rdi,r12
  4a330a:	49 89 c6             	mov    r14,rax
  4a330d:	31 f6                	xor    esi,esi
  4a330f:	31 d2                	xor    edx,edx
  4a3311:	31 c9                	xor    ecx,ecx
  4a3313:	e8 e8 36 02 00       	call   0x4c6a00
  4a3318:	41 3b 9f 48 0b 00 00 	cmp    ebx,DWORD PTR [r15+0xb48]
  4a331f:	7d 36                	jge    0x4a3357
  4a3321:	4c 89 e7             	mov    rdi,r12
  4a3324:	31 f6                	xor    esi,esi
  4a3326:	31 d2                	xor    edx,edx
  4a3328:	31 c9                	xor    ecx,ecx
  4a332a:	e8 71 3c 02 00       	call   0x4c6fa0
  4a332f:	4c 89 f7             	mov    rdi,r14
  4a3332:	4c 89 ee             	mov    rsi,r13
  4a3335:	e8 b6 5a 76 00       	call   0xc08df0
  4a333a:	4c 89 e7             	mov    rdi,r12
  4a333d:	31 f6                	xor    esi,esi
  4a333f:	31 d2                	xor    edx,edx
  4a3341:	31 c9                	xor    ecx,ecx
  4a3343:	e8 b8 36 02 00       	call   0x4c6a00
  4a3348:	41 83 bf b8 00 00 00 	cmp    DWORD PTR [r15+0xb8],0x1
  4a334f:	01 
  4a3350:	74 88                	je     0x4a32da
  4a3352:	e9 39 ff ff ff       	jmp    0x4a3290
  4a3357:	49 8d 5f 38          	lea    rbx,[r15+0x38]
  4a335b:	31 f6                	xor    esi,esi
  4a335d:	31 d2                	xor    edx,edx
  4a335f:	31 c9                	xor    ecx,ecx
  4a3361:	48 89 df             	mov    rdi,rbx
  4a3364:	e8 27 3e 02 00       	call   0x4c7190
  4a3369:	4d 8b 6f 10          	mov    r13,QWORD PTR [r15+0x10]
  4a336d:	4d 85 ed             	test   r13,r13
  4a3370:	0f 84 e2 00 00 00    	je     0x4a3458
  4a3376:	48 89 9d 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rbx
  4a337d:	4c 89 f3             	mov    rbx,r14
  4a3380:	c7 45 8c 00 00 00 00 	mov    DWORD PTR [rbp-0x74],0x0
  4a3387:	eb 73                	jmp    0x4a33fc
  4a3389:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  4a3390:	41 8b 87 bc 00 00 00 	mov    eax,DWORD PTR [r15+0xbc]
  4a3397:	31 f6                	xor    esi,esi
  4a3399:	31 d2                	xor    edx,edx
  4a339b:	31 c9                	xor    ecx,ecx
  4a339d:	89 03                	mov    DWORD PTR [rbx],eax
  4a339f:	41 8b 85 9c 00 00 00 	mov    eax,DWORD PTR [r13+0x9c]
  4a33a6:	89 43 04             	mov    DWORD PTR [rbx+0x4],eax
  4a33a9:	49 8b 85 b0 05 00 00 	mov    rax,QWORD PTR [r13+0x5b0]
  4a33b0:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
  4a33b4:	49 8b 85 b8 05 00 00 	mov    rax,QWORD PTR [r13+0x5b8]
  4a33bb:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
  4a33bf:	49 8b 85 c0 05 00 00 	mov    rax,QWORD PTR [r13+0x5c0]
  4a33c6:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
  4a33ca:	49 8b 85 c8 05 00 00 	mov    rax,QWORD PTR [r13+0x5c8]
  4a33d1:	48 89 43 20          	mov    QWORD PTR [rbx+0x20],rax
  4a33d5:	49 8b 7d 00          	mov    rdi,QWORD PTR [r13+0x0]
  4a33d9:	48 83 c7 18          	add    rdi,0x18
  4a33dd:	e8 3e 41 02 00       	call   0x4c7520
  4a33e2:	ff 45 8c             	inc    DWORD PTR [rbp-0x74]
  4a33e5:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  4a33e9:	48 83 c3 28          	add    rbx,0x28
  4a33ed:	ff c0                	inc    eax
  4a33ef:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
  4a33f3:	4d 8b 6d 10          	mov    r13,QWORD PTR [r13+0x10]
  4a33f7:	4d 85 ed             	test   r13,r13
  4a33fa:	74 47                	je     0x4a3443
  4a33fc:	4c 89 ef             	mov    rdi,r13
  4a33ff:	48 8d 15 c7 6d e0 00 	lea    rdx,[rip+0xe06dc7]        # 0x12aa1cd
  4a3406:	b9 2f 07 00 00       	mov    ecx,0x72f
  4a340b:	31 f6                	xor    esi,esi
  4a340d:	e8 9e 44 02 00       	call   0x4c78b0
  4a3412:	49 83 bd b0 05 00 00 	cmp    QWORD PTR [r13+0x5b0],0x0
  4a3419:	00 
  4a341a:	0f 85 70 ff ff ff    	jne    0x4a3390
  4a3420:	49 83 bd c0 05 00 00 	cmp    QWORD PTR [r13+0x5c0],0x0
  4a3427:	00 
  4a3428:	0f 85 62 ff ff ff    	jne    0x4a3390
  4a342e:	49 8b 7d 00          	mov    rdi,QWORD PTR [r13+0x0]
  4a3432:	31 f6                	xor    esi,esi
  4a3434:	31 d2                	xor    edx,edx
  4a3436:	31 c9                	xor    ecx,ecx
  4a3438:	48 83 c7 18          	add    rdi,0x18
  4a343c:	e8 df 40 02 00       	call   0x4c7520
  4a3441:	eb b0                	jmp    0x4a33f3
  4a3443:	48 63 45 8c          	movsxd rax,DWORD PTR [rbp-0x74]
  4a3447:	48 8b 9d 70 ff ff ff 	mov    rbx,QWORD PTR [rbp-0x90]
  4a344e:	48 c1 e0 03          	shl    rax,0x3
  4a3452:	4c 8d 2c 80          	lea    r13,[rax+rax*4]
  4a3456:	eb 03                	jmp    0x4a345b
  4a3458:	45 31 ed             	xor    r13d,r13d
  4a345b:	48 89 df             	mov    rdi,rbx
  4a345e:	31 f6                	xor    esi,esi
  4a3460:	31 d2                	xor    edx,edx
  4a3462:	31 c9                	xor    ecx,ecx
  4a3464:	e8 b7 40 02 00       	call   0x4c7520
  4a3469:	4c 89 e7             	mov    rdi,r12
  4a346c:	31 f6                	xor    esi,esi
  4a346e:	31 d2                	xor    edx,edx
  4a3470:	31 c9                	xor    ecx,ecx
  4a3472:	e8 29 3b 02 00       	call   0x4c6fa0
  4a3477:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  4a347b:	4c 89 f7             	mov    rdi,r14
  4a347e:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
  4a3482:	4c 39 e8             	cmp    rax,r13
  4a3485:	4c 0f 42 e8          	cmovb  r13,rax
  4a3489:	44 89 ee             	mov    esi,r13d
  4a348c:	e8 8f f0 2d 00       	call   0x782520
  4a3491:	4c 8d 2d 88 4c 62 01 	lea    r13,[rip+0x1624c88]        # 0x1ac8120
  4a3498:	4c 89 f7             	mov    rdi,r14
  4a349b:	41 89 c4             	mov    r12d,eax
  4a349e:	4c 89 ee             	mov    rsi,r13
  4a34a1:	e8 4a 59 76 00       	call   0xc08df0
  4a34a6:	45 85 e4             	test   r12d,r12d
  4a34a9:	0f 84 ef fd ff ff    	je     0x4a329e
  4a34af:	48 8d 3d aa 69 0e 03 	lea    rdi,[rip+0x30e69aa]        # 0x3589e60
  4a34b6:	31 f6                	xor    esi,esi
  4a34b8:	31 d2                	xor    edx,edx
  4a34ba:	e8 41 8e 7a 00       	call   0xc4c300
  4a34bf:	44 89 e0             	mov    eax,r12d
  4a34c2:	e9 34 01 00 00       	jmp    0x4a35fb
  4a34c7:	b8 4e 00 00 00       	mov    eax,0x4e
  4a34cc:	e9 31 01 00 00       	jmp    0x4a3602
  4a34d1:	48 8d 3d 88 69 0e 03 	lea    rdi,[rip+0x30e6988]        # 0x3589e60
  4a34d8:	4c 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r15
  4a34df:	31 db                	xor    ebx,ebx
  4a34e1:	31 f6                	xor    esi,esi
  4a34e3:	31 d2                	xor    edx,edx
  4a34e5:	31 c9                	xor    ecx,ecx
  4a34e7:	e8 64 7e 7a 00       	call   0xc4b350
  4a34ec:	4c 8b 2d 8d 69 0e 03 	mov    r13,QWORD PTR [rip+0x30e698d]        # 0x3589e80
  4a34f3:	4d 85 ed             	test   r13,r13
  4a34f6:	0f 84 ad 00 00 00    	je     0x4a35a9
  4a34fc:	4c 8d 35 ca 6c e0 00 	lea    r14,[rip+0xe06cca]        # 0x12aa1cd
  4a3503:	31 db                	xor    ebx,ebx
  4a3505:	eb 24                	jmp    0x4a352b
  4a3507:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  4a350e:	00 00 
  4a3510:	4c 89 ff             	mov    rdi,r15
  4a3513:	31 f6                	xor    esi,esi
  4a3515:	31 d2                	xor    edx,edx
  4a3517:	31 c9                	xor    ecx,ecx
  4a3519:	e8 82 3a 02 00       	call   0x4c6fa0
  4a351e:	4d 8b 6d 00          	mov    r13,QWORD PTR [r13+0x0]
  4a3522:	4d 85 ed             	test   r13,r13
  4a3525:	0f 84 7e 00 00 00    	je     0x4a35a9
  4a352b:	4d 8d bd 48 01 00 00 	lea    r15,[r13+0x148]
  4a3532:	31 f6                	xor    esi,esi
  4a3534:	31 d2                	xor    edx,edx
  4a3536:	31 c9                	xor    ecx,ecx
  4a3538:	4c 89 ff             	mov    rdi,r15
  4a353b:	e8 c0 34 02 00       	call   0x4c6a00
  4a3540:	41 83 bd d0 05 00 00 	cmp    DWORD PTR [r13+0x5d0],0x2
  4a3547:	02 
  4a3548:	72 c6                	jb     0x4a3510
  4a354a:	41 83 bd b8 00 00 00 	cmp    DWORD PTR [r13+0xb8],0x1
  4a3551:	01 
  4a3552:	75 bc                	jne    0x4a3510
  4a3554:	4d 8b 65 10          	mov    r12,QWORD PTR [r13+0x10]
  4a3558:	eb 20                	jmp    0x4a357a
  4a355a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4a3560:	ff c3                	inc    ebx
  4a3562:	49 8b 3c 24          	mov    rdi,QWORD PTR [r12]
  4a3566:	31 f6                	xor    esi,esi
  4a3568:	31 d2                	xor    edx,edx
  4a356a:	31 c9                	xor    ecx,ecx
  4a356c:	48 83 c7 18          	add    rdi,0x18
  4a3570:	e8 ab 3f 02 00       	call   0x4c7520
  4a3575:	4d 8b 64 24 10       	mov    r12,QWORD PTR [r12+0x10]
  4a357a:	4d 85 e4             	test   r12,r12
  4a357d:	74 91                	je     0x4a3510
  4a357f:	4c 89 e7             	mov    rdi,r12
  4a3582:	4c 89 f2             	mov    rdx,r14
  4a3585:	b9 ed 06 00 00       	mov    ecx,0x6ed
  4a358a:	31 f6                	xor    esi,esi
  4a358c:	e8 1f 43 02 00       	call   0x4c78b0
  4a3591:	49 83 bc 24 b0 05 00 	cmp    QWORD PTR [r12+0x5b0],0x0
  4a3598:	00 00 
  4a359a:	75 c4                	jne    0x4a3560
  4a359c:	49 83 bc 24 c0 05 00 	cmp    QWORD PTR [r12+0x5c0],0x0
  4a35a3:	00 00 
  4a35a5:	75 b9                	jne    0x4a3560
  4a35a7:	eb b9                	jmp    0x4a3562
  4a35a9:	48 8d 3d b0 68 0e 03 	lea    rdi,[rip+0x30e68b0]        # 0x3589e60
  4a35b0:	31 f6                	xor    esi,esi
  4a35b2:	31 d2                	xor    edx,edx
  4a35b4:	e8 47 8d 7a 00       	call   0xc4c300
  4a35b9:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
  4a35c0:	89 de                	mov    esi,ebx
  4a35c2:	eb 22                	jmp    0x4a35e6
  4a35c4:	b8 0e 00 00 00       	mov    eax,0xe
  4a35c9:	eb 37                	jmp    0x4a3602
  4a35cb:	48 8d 3d 8e 68 0e 03 	lea    rdi,[rip+0x30e688e]        # 0x3589e60
  4a35d2:	31 f6                	xor    esi,esi
  4a35d4:	31 d2                	xor    edx,edx
  4a35d6:	e8 25 8d 7a 00       	call   0xc4c300
  4a35db:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
  4a35e2:	48 8b 75 80          	mov    rsi,QWORD PTR [rbp-0x80]
  4a35e6:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  4a35ea:	e8 a1 61 db ff       	call   0x259790
  4a35ef:	89 c1                	mov    ecx,eax
  4a35f1:	85 c0                	test   eax,eax
  4a35f3:	b8 0e 00 00 00       	mov    eax,0xe
  4a35f8:	0f 44 c1             	cmove  eax,ecx
  4a35fb:	4c 8d 35 0e 8d 47 03 	lea    r14,[rip+0x3478d0e]        # 0x391c310
  4a3602:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  4a3605:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  4a3609:	75 0f                	jne    0x4a361a
  4a360b:	48 83 c4 68          	add    rsp,0x68
  4a360f:	5b                   	pop    rbx
  4a3610:	41 5c                	pop    r12
  4a3612:	41 5d                	pop    r13
  4a3614:	41 5e                	pop    r14
  4a3616:	41 5f                	pop    r15
  4a3618:	5d                   	pop    rbp
  4a3619:	c3                   	ret
  4a361a:	e8 91 a0 25 00       	call   0x6fd6b0
  4a361f:	0f 0b                	ud2
  4a3621:	90                   	nop
  4a3622:	90                   	nop
  4a3623:	90                   	nop
  4a3624:	90                   	nop
  4a3625:	90                   	nop
  4a3626:	90                   	nop
  4a3627:	90                   	nop
  4a3628:	90                   	nop
  4a3629:	90                   	nop
  4a362a:	90                   	nop
  4a362b:	90                   	nop
  4a362c:	90                   	nop
  4a362d:	90                   	nop
  4a362e:	90                   	nop
  4a362f:	90                   	nop
  4a3630:	55                   	push   rbp
  4a3631:	48 89 e5             	mov    rbp,rsp
  4a3634:	5d                   	pop    rbp
  4a3635:	c3                   	ret
  4a3636:	90                   	nop
  4a3637:	90                   	nop
  4a3638:	90                   	nop
  4a3639:	90                   	nop
  4a363a:	90                   	nop
  4a363b:	90                   	nop
  4a363c:	90                   	nop
  4a363d:	90                   	nop
  4a363e:	90                   	nop
  4a363f:	90                   	nop
  4a3640:	55                   	push   rbp
  4a3641:	48 89 e5             	mov    rbp,rsp
  4a3644:	41 57                	push   r15
  4a3646:	41 56                	push   r14
  4a3648:	53                   	push   rbx
  4a3649:	48 83 ec 18          	sub    rsp,0x18
  4a364d:	4c 8d 3d bc 8c 47 03 	lea    r15,[rip+0x3478cbc]        # 0x391c310
  4a3654:	48 89 fb             	mov    rbx,rdi
  4a3657:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a365a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  4a365e:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
  4a3665:	00 
  4a3666:	48 8b 87 40 03 00 00 	mov    rax,QWORD PTR [rdi+0x340]
  4a366d:	66 c7 40 0c 00 00    	mov    WORD PTR [rax+0xc],0x0
  4a3673:	48 85 f6             	test   rsi,rsi
  4a3676:	74 39                	je     0x4a36b1
  4a3678:	48 8d 7d d8          	lea    rdi,[rbp-0x28]
  4a367c:	48 89 de             	mov    rsi,rbx
  4a367f:	e8 bc 2a 6b 00       	call   0xb56140
  4a3684:	85 c0                	test   eax,eax
  4a3686:	0f 84 8d 00 00 00    	je     0x4a3719
  4a368c:	48 8d 3d 81 f9 0e 01 	lea    rdi,[rip+0x10ef981]        # 0x1593014
  4a3693:	48 8d 0d 05 c8 f0 00 	lea    rcx,[rip+0xf0c805]        # 0x13afe9f
  4a369a:	be 6f 00 00 00       	mov    esi,0x6f
  4a369f:	89 c2                	mov    edx,eax
  4a36a1:	89 c3                	mov    ebx,eax
  4a36a3:	31 c0                	xor    eax,eax
  4a36a5:	e8 e6 43 25 00       	call   0x6f7a90
  4a36aa:	89 d8                	mov    eax,ebx
  4a36ac:	e9 27 01 00 00       	jmp    0x4a37d8
  4a36b1:	48 8b b3 78 03 00 00 	mov    rsi,QWORD PTR [rbx+0x378]
  4a36b8:	48 89 df             	mov    rdi,rbx
  4a36bb:	31 d2                	xor    edx,edx
  4a36bd:	e8 ee 78 10 00       	call   0x5aafb0
  4a36c2:	85 c0                	test   eax,eax
  4a36c4:	0f 85 0e 01 00 00    	jne    0x4a37d8
  4a36ca:	4c 8d b3 e0 02 00 00 	lea    r14,[rbx+0x2e0]
  4a36d1:	48 89 de             	mov    rsi,rbx
  4a36d4:	4c 89 f7             	mov    rdi,r14
  4a36d7:	e8 b4 fa 0e 00       	call   0x593190
  4a36dc:	85 c0                	test   eax,eax
  4a36de:	0f 85 f4 00 00 00    	jne    0x4a37d8
  4a36e4:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  4a36e7:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
  4a36eb:	48 85 ff             	test   rdi,rdi
  4a36ee:	75 32                	jne    0x4a3722
  4a36f0:	48 8d 3d 1d f9 0e 01 	lea    rdi,[rip+0x10ef91d]        # 0x1593014
  4a36f7:	48 8d 15 6a dc ea 00 	lea    rdx,[rip+0xeadc6a]        # 0x1351368
  4a36fe:	be 88 00 00 00       	mov    esi,0x88
  4a3703:	49 89 d8             	mov    r8,rbx
  4a3706:	31 c9                	xor    ecx,ecx
  4a3708:	31 c0                	xor    eax,eax
  4a370a:	e8 e1 42 25 00       	call   0x6f79f0
  4a370f:	b8 02 30 00 00       	mov    eax,0x3002
  4a3714:	e9 bf 00 00 00       	jmp    0x4a37d8
  4a3719:	48 8b 7d d8          	mov    rdi,QWORD PTR [rbp-0x28]
  4a371d:	48 85 ff             	test   rdi,rdi
  4a3720:	74 ce                	je     0x4a36f0
  4a3722:	48 8d 75 d0          	lea    rsi,[rbp-0x30]
  4a3726:	ba 10 00 00 00       	mov    edx,0x10
  4a372b:	e8 30 7d e8 ff       	call   0x32b460
  4a3730:	41 89 c6             	mov    r14d,eax
  4a3733:	85 c0                	test   eax,eax
  4a3735:	75 73                	jne    0x4a37aa
  4a3737:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  4a373b:	80 7f 09 01          	cmp    BYTE PTR [rdi+0x9],0x1
  4a373f:	75 3d                	jne    0x4a377e
  4a3741:	e8 6a a1 51 00       	call   0x9bd8b0
  4a3746:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  4a374a:	31 c9                	xor    ecx,ecx
  4a374c:	31 d2                	xor    edx,edx
  4a374e:	41 be 05 40 00 00    	mov    r14d,0x4005
  4a3754:	48 89 de             	mov    rsi,rbx
  4a3757:	48 83 78 10 00       	cmp    QWORD PTR [rax+0x10],0x0
  4a375c:	48 8b 83 40 03 00 00 	mov    rax,QWORD PTR [rbx+0x340]
  4a3763:	0f 95 c2             	setne  dl
  4a3766:	44 0f 45 f1          	cmovne r14d,ecx
  4a376a:	66 89 50 0a          	mov    WORD PTR [rax+0xa],dx
  4a376e:	ba 01 00 00 00       	mov    edx,0x1
  4a3773:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  4a3777:	e8 24 75 10 00       	call   0x5aaca0
  4a377c:	eb 2c                	jmp    0x4a37aa
  4a377e:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
  4a3782:	48 8d 3d 8b f8 0e 01 	lea    rdi,[rip+0x10ef88b]        # 0x1593014
  4a3789:	48 8d 15 4b 30 ec 00 	lea    rdx,[rip+0xec304b]        # 0x13667db
  4a3790:	be 9b 00 00 00       	mov    esi,0x9b
  4a3795:	49 89 d8             	mov    r8,rbx
  4a3798:	31 c0                	xor    eax,eax
  4a379a:	44 0f b6 49 09       	movzx  r9d,BYTE PTR [rcx+0x9]
  4a379f:	e8 4c 42 25 00       	call   0x6f79f0
  4a37a4:	41 be 03 30 00 00    	mov    r14d,0x3003
  4a37aa:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  4a37ae:	48 8b 7d d8          	mov    rdi,QWORD PTR [rbp-0x28]
  4a37b2:	48 39 f8             	cmp    rax,rdi
  4a37b5:	74 0c                	je     0x4a37c3
  4a37b7:	48 89 c7             	mov    rdi,rax
  4a37ba:	e8 01 6d 6a 00       	call   0xb4a4c0
  4a37bf:	48 8b 7d d8          	mov    rdi,QWORD PTR [rbp-0x28]
  4a37c3:	e8 f8 6c 6a 00       	call   0xb4a4c0
  4a37c8:	48 8b 83 40 03 00 00 	mov    rax,QWORD PTR [rbx+0x340]
  4a37cf:	66 c7 40 0c c0 00    	mov    WORD PTR [rax+0xc],0xc0
  4a37d5:	44 89 f0             	mov    eax,r14d
  4a37d8:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  4a37db:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  4a37df:	75 0b                	jne    0x4a37ec
  4a37e1:	48 83 c4 18          	add    rsp,0x18
  4a37e5:	5b                   	pop    rbx
  4a37e6:	41 5e                	pop    r14
  4a37e8:	41 5f                	pop    r15
  4a37ea:	5d                   	pop    rbp
  4a37eb:	c3                   	ret
  4a37ec:	e8 bf 9e 25 00       	call   0x6fd6b0
  4a37f1:	0f 0b                	ud2
  4a37f3:	90                   	nop
  4a37f4:	90                   	nop
  4a37f5:	90                   	nop
  4a37f6:	90                   	nop
  4a37f7:	90                   	nop
  4a37f8:	90                   	nop
  4a37f9:	90                   	nop
  4a37fa:	90                   	nop
  4a37fb:	90                   	nop
  4a37fc:	90                   	nop
  4a37fd:	90                   	nop
  4a37fe:	90                   	nop
  4a37ff:	90                   	nop
  4a3800:	55                   	push   rbp
  4a3801:	48 89 e5             	mov    rbp,rsp
  4a3804:	41 57                	push   r15
  4a3806:	41 56                	push   r14
  4a3808:	53                   	push   rbx
  4a3809:	50                   	push   rax
  4a380a:	4c 8b b7 78 03 00 00 	mov    r14,QWORD PTR [rdi+0x378]
  4a3811:	49 89 f7             	mov    r15,rsi
  4a3814:	48 89 fb             	mov    rbx,rdi
  4a3817:	4d 85 f6             	test   r14,r14
  4a381a:	74 70                	je     0x4a388c
  4a381c:	4c 3b b3 88 03 00 00 	cmp    r14,QWORD PTR [rbx+0x388]
  4a3823:	0f 84 86 00 00 00    	je     0x4a38af
  4a3829:	48 8b 83 40 03 00 00 	mov    rax,QWORD PTR [rbx+0x340]
  4a3830:	48 85 c0             	test   rax,rax
  4a3833:	74 19                	je     0x4a384e
  4a3835:	66 81 78 0c c1 00    	cmp    WORD PTR [rax+0xc],0xc1
  4a383b:	75 11                	jne    0x4a384e
  4a383d:	66 c7 40 0c c2 00    	mov    WORD PTR [rax+0xc],0xc2
  4a3843:	48 8b 83 40 03 00 00 	mov    rax,QWORD PTR [rbx+0x340]
  4a384a:	4c 89 70 10          	mov    QWORD PTR [rax+0x10],r14
  4a384e:	48 8b 8b 80 03 00 00 	mov    rcx,QWORD PTR [rbx+0x380]
  4a3855:	41 0f b7 46 0a       	movzx  eax,WORD PTR [r14+0xa]
  4a385a:	0f b6 51 0b          	movzx  edx,BYTE PTR [rcx+0xb]
  4a385e:	66 83 f8 2d          	cmp    ax,0x2d
  4a3862:	b9 03 00 00 00       	mov    ecx,0x3
  4a3867:	0f 45 ca             	cmovne ecx,edx
  4a386a:	80 f9 03             	cmp    cl,0x3
  4a386d:	74 4a                	je     0x4a38b9
  4a386f:	0f b6 c1             	movzx  eax,cl
  4a3872:	83 f8 04             	cmp    eax,0x4
  4a3875:	75 48                	jne    0x4a38bf
  4a3877:	48 89 df             	mov    rdi,rbx
  4a387a:	4c 89 f6             	mov    rsi,r14
  4a387d:	48 83 c4 08          	add    rsp,0x8
  4a3881:	5b                   	pop    rbx
  4a3882:	41 5e                	pop    r14
  4a3884:	41 5f                	pop    r15
  4a3886:	5d                   	pop    rbp
  4a3887:	e9 14 9c 2a 00       	jmp    0x74d4a0
  4a388c:	48 89 df             	mov    rdi,rbx
  4a388f:	4c 89 fe             	mov    rsi,r15
  4a3892:	e8 71 b9 dc ff       	call   0x26f208
  4a3897:	85 c0                	test   eax,eax
  4a3899:	74 31                	je     0x4a38cc
  4a389b:	89 c7                	mov    edi,eax
  4a389d:	48 89 de             	mov    rsi,rbx
  4a38a0:	48 83 c4 08          	add    rsp,0x8
  4a38a4:	5b                   	pop    rbx
  4a38a5:	41 5e                	pop    r14
  4a38a7:	41 5f                	pop    r15
  4a38a9:	5d                   	pop    rbp
  4a38aa:	e9 51 e3 04 00       	jmp    0x4f1c00
  4a38af:	4d 85 ff             	test   r15,r15
  4a38b2:	74 0b                	je     0x4a38bf
  4a38b4:	4d 89 37             	mov    QWORD PTR [r15],r14
  4a38b7:	eb 06                	jmp    0x4a38bf
  4a38b9:	f6 43 09 01          	test   BYTE PTR [rbx+0x9],0x1
  4a38bd:	75 4e                	jne    0x4a390d
  4a38bf:	31 c0                	xor    eax,eax
  4a38c1:	48 83 c4 08          	add    rsp,0x8
  4a38c5:	5b                   	pop    rbx
  4a38c6:	41 5e                	pop    r14
  4a38c8:	41 5f                	pop    r15
  4a38ca:	5d                   	pop    rbp
  4a38cb:	c3                   	ret
  4a38cc:	4d 8b 37             	mov    r14,QWORD PTR [r15]
  4a38cf:	4c 89 b3 78 03 00 00 	mov    QWORD PTR [rbx+0x378],r14
  4a38d6:	41 0f b7 7e 0a       	movzx  edi,WORD PTR [r14+0xa]
  4a38db:	66 89 7b 0a          	mov    WORD PTR [rbx+0xa],di
  4a38df:	e8 2c 04 71 00       	call   0xbb3d10
  4a38e4:	48 89 83 80 03 00 00 	mov    QWORD PTR [rbx+0x380],rax
  4a38eb:	0f b6 78 0a          	movzx  edi,BYTE PTR [rax+0xa]
  4a38ef:	e8 bc 35 62 00       	call   0xac6eb0
  4a38f4:	85 c0                	test   eax,eax
  4a38f6:	0f 84 20 ff ff ff    	je     0x4a381c
  4a38fc:	48 89 df             	mov    rdi,rbx
  4a38ff:	e8 fc c3 35 00       	call   0x7ffd00
  4a3904:	85 c0                	test   eax,eax
  4a3906:	75 93                	jne    0x4a389b
  4a3908:	e9 0f ff ff ff       	jmp    0x4a381c
  4a390d:	66 83 f8 10          	cmp    ax,0x10
  4a3911:	75 1a                	jne    0x4a392d
  4a3913:	49 8b 7e 20          	mov    rdi,QWORD PTR [r14+0x20]
  4a3917:	48 89 da             	mov    rdx,rbx
  4a391a:	0f b6 77 09          	movzx  esi,BYTE PTR [rdi+0x9]
  4a391e:	48 83 c4 08          	add    rsp,0x8
  4a3922:	5b                   	pop    rbx
  4a3923:	41 5e                	pop    r14
  4a3925:	41 5f                	pop    r15
  4a3927:	5d                   	pop    rbp
  4a3928:	e9 23 c3 35 00       	jmp    0x7ffc50
  4a392d:	48 89 df             	mov    rdi,rbx
  4a3930:	31 f6                	xor    esi,esi
  4a3932:	48 83 c4 08          	add    rsp,0x8
  4a3936:	5b                   	pop    rbx
  4a3937:	41 5e                	pop    r14
  4a3939:	41 5f                	pop    r15
  4a393b:	5d                   	pop    rbp
  4a393c:	e9 c7 b8 dc ff       	jmp    0x26f208
  4a3941:	90                   	nop
  4a3942:	90                   	nop
  4a3943:	90                   	nop
  4a3944:	90                   	nop
  4a3945:	90                   	nop
  4a3946:	90                   	nop
  4a3947:	90                   	nop
  4a3948:	90                   	nop
  4a3949:	90                   	nop
  4a394a:	90                   	nop
  4a394b:	90                   	nop
  4a394c:	90                   	nop
  4a394d:	90                   	nop
  4a394e:	90                   	nop
  4a394f:	90                   	nop
  4a3950:	55                   	push   rbp
  4a3951:	48 89 e5             	mov    rbp,rsp
  4a3954:	41 57                	push   r15
  4a3956:	41 56                	push   r14
  4a3958:	41 54                	push   r12
  4a395a:	53                   	push   rbx
  4a395b:	48 83 ec 10          	sub    rsp,0x10
  4a395f:	48 8b 87 80 03 00 00 	mov    rax,QWORD PTR [rdi+0x380]
  4a3966:	4c 8b b7 78 03 00 00 	mov    r14,QWORD PTR [rdi+0x378]
  4a396d:	0f b6 48 0b          	movzx  ecx,BYTE PTR [rax+0xb]
  4a3971:	83 f9 0a             	cmp    ecx,0xa
  4a3974:	75 29                	jne    0x4a399f
  4a3976:	41 0f b7 4e 0a       	movzx  ecx,WORD PTR [r14+0xa]
  4a397b:	48 8d 3d 92 f6 0e 01 	lea    rdi,[rip+0x10ef692]        # 0x1593014
  4a3982:	48 8d 15 49 40 dd 00 	lea    rdx,[rip+0xdd4049]        # 0x12779d2
  4a3989:	be 99 01 00 00       	mov    esi,0x199
  4a398e:	31 c0                	xor    eax,eax
  4a3990:	e8 5b 40 25 00       	call   0x6f79f0
  4a3995:	b8 0e 00 00 00       	mov    eax,0xe
  4a399a:	e9 13 04 00 00       	jmp    0x4a3db2
  4a399f:	44 0f b6 60 0c       	movzx  r12d,BYTE PTR [rax+0xc]
  4a39a4:	49 8b 76 28          	mov    rsi,QWORD PTR [r14+0x28]
  4a39a8:	48 89 fb             	mov    rbx,rdi
  4a39ab:	66 c7 47 0d 00 00    	mov    WORD PTR [rdi+0xd],0x0
  4a39b1:	48 c7 87 a0 03 00 00 	mov    QWORD PTR [rdi+0x3a0],0x0
  4a39b8:	00 00 00 00 
  4a39bc:	48 c7 87 90 03 00 00 	mov    QWORD PTR [rdi+0x390],0x0
  4a39c3:	00 00 00 00 
  4a39c7:	85 c9                	test   ecx,ecx
  4a39c9:	74 21                	je     0x4a39ec
  4a39cb:	83 f9 02             	cmp    ecx,0x2
  4a39ce:	75 30                	jne    0x4a3a00
  4a39d0:	66 83 7b 0a 2d       	cmp    WORD PTR [rbx+0xa],0x2d
  4a39d5:	0f 85 c7 02 00 00    	jne    0x4a3ca2
  4a39db:	48 89 df             	mov    rdi,rbx
  4a39de:	e8 3d 79 10 00       	call   0x5ab320
  4a39e3:	85 c0                	test   eax,eax
  4a39e5:	75 11                	jne    0x4a39f8
  4a39e7:	e9 b6 02 00 00       	jmp    0x4a3ca2
  4a39ec:	48 89 df             	mov    rdi,rbx
  4a39ef:	e8 1c 78 10 00       	call   0x5ab210
  4a39f4:	85 c0                	test   eax,eax
  4a39f6:	74 3e                	je     0x4a3a36
  4a39f8:	41 89 c7             	mov    r15d,eax
  4a39fb:	e9 83 03 00 00       	jmp    0x4a3d83
  4a3a00:	41 8d 44 24 f0       	lea    eax,[r12-0x10]
  4a3a05:	83 f8 0a             	cmp    eax,0xa
  4a3a08:	0f 87 48 01 00 00    	ja     0x4a3b56
  4a3a0e:	48 8d 15 d3 f5 0e 01 	lea    rdx,[rip+0x10ef5d3]        # 0x1592fe8
  4a3a15:	48 63 04 82          	movsxd rax,DWORD PTR [rdx+rax*4]
  4a3a19:	48 01 d0             	add    rax,rdx
  4a3a1c:	ff e0                	jmp    rax
  4a3a1e:	48 89 df             	mov    rdi,rbx
  4a3a21:	e8 f2 61 dc ff       	call   0x269c18
  4a3a26:	85 c0                	test   eax,eax
  4a3a28:	0f 84 d2 00 00 00    	je     0x4a3b00
  4a3a2e:	41 89 c7             	mov    r15d,eax
  4a3a31:	e9 4b 02 00 00       	jmp    0x4a3c81
  4a3a36:	48 8b 83 80 03 00 00 	mov    rax,QWORD PTR [rbx+0x380]
  4a3a3d:	f6 40 09 40          	test   BYTE PTR [rax+0x9],0x40
  4a3a41:	0f 85 88 00 00 00    	jne    0x4a3acf
  4a3a47:	0f b6 43 0d          	movzx  eax,BYTE PTR [rbx+0xd]
  4a3a4b:	0f b7 7b 0a          	movzx  edi,WORD PTR [rbx+0xa]
  4a3a4f:	48 89 da             	mov    rdx,rbx
  4a3a52:	48 8d b4 c3 d8 02 00 	lea    rsi,[rbx+rax*8+0x2d8]
  4a3a59:	00 
  4a3a5a:	e8 a1 3c 61 00       	call   0xab7700
  4a3a5f:	85 c0                	test   eax,eax
  4a3a61:	74 6c                	je     0x4a3acf
  4a3a63:	41 89 c7             	mov    r15d,eax
  4a3a66:	3d 05 30 00 00       	cmp    eax,0x3005
  4a3a6b:	0f 85 d7 01 00 00    	jne    0x4a3c48
  4a3a71:	0f b7 43 0a          	movzx  eax,WORD PTR [rbx+0xa]
  4a3a75:	66 83 f8 70          	cmp    ax,0x70
  4a3a79:	0f 85 cd 01 00 00    	jne    0x4a3c4c
  4a3a7f:	48 8d 83 e0 02 00 00 	lea    rax,[rbx+0x2e0]
  4a3a86:	48 8b 08             	mov    rcx,QWORD PTR [rax]
  4a3a89:	66 b8 70 00          	mov    ax,0x70
  4a3a8d:	80 79 09 14          	cmp    BYTE PTR [rcx+0x9],0x14
  4a3a91:	0f 85 b5 01 00 00    	jne    0x4a3c4c
  4a3a97:	48 8b 93 e8 02 00 00 	mov    rdx,QWORD PTR [rbx+0x2e8]
  4a3a9e:	80 7a 09 14          	cmp    BYTE PTR [rdx+0x9],0x14
  4a3aa2:	0f 85 a4 01 00 00    	jne    0x4a3c4c
  4a3aa8:	0f b6 71 0d          	movzx  esi,BYTE PTR [rcx+0xd]
  4a3aac:	40 3a 72 0d          	cmp    sil,BYTE PTR [rdx+0xd]
  4a3ab0:	0f 85 96 01 00 00    	jne    0x4a3c4c
  4a3ab6:	8b 49 30             	mov    ecx,DWORD PTR [rcx+0x30]
  4a3ab9:	3b 4a 30             	cmp    ecx,DWORD PTR [rdx+0x30]
  4a3abc:	0f 85 8a 01 00 00    	jne    0x4a3c4c
  4a3ac2:	48 89 df             	mov    rdi,rbx
  4a3ac5:	e8 96 74 10 00       	call   0x5aaf60
  4a3aca:	e9 c3 01 00 00       	jmp    0x4a3c92
  4a3acf:	48 8d 05 4a bd 9d 00 	lea    rax,[rip+0x9dbd4a]        # 0xe7f820
  4a3ad6:	4e 8b 3c e0          	mov    r15,QWORD PTR [rax+r12*8]
  4a3ada:	48 8d 05 97 62 dc ff 	lea    rax,[rip+0xffffffffffdc6297]        # 0x269d78
  4a3ae1:	4c 29 f8             	sub    rax,r15
  4a3ae4:	48 c1 c8 03          	ror    rax,0x3
  4a3ae8:	48 83 f8 37          	cmp    rax,0x37
  4a3aec:	0f 87 d4 02 00 00    	ja     0x4a3dc6
  4a3af2:	48 89 df             	mov    rdi,rbx
  4a3af5:	41 ff d7             	call   r15
  4a3af8:	41 89 c7             	mov    r15d,eax
  4a3afb:	e9 74 01 00 00       	jmp    0x4a3c74
  4a3b00:	41 0f b7 46 0a       	movzx  eax,WORD PTR [r14+0xa]
  4a3b05:	3d 88 5b 00 00       	cmp    eax,0x5b88
  4a3b0a:	0f 84 2a 02 00 00    	je     0x4a3d3a
  4a3b10:	3d 87 5b 00 00       	cmp    eax,0x5b87
  4a3b15:	0f 84 12 02 00 00    	je     0x4a3d2d
  4a3b1b:	3d 80 5b 00 00       	cmp    eax,0x5b80
  4a3b20:	0f 85 7c 01 00 00    	jne    0x4a3ca2
  4a3b26:	48 89 df             	mov    rdi,rbx
  4a3b29:	4c 89 f6             	mov    rsi,r14
  4a3b2c:	e8 9f 6c 69 00       	call   0xb3a7d0
  4a3b31:	e9 35 02 00 00       	jmp    0x4a3d6b
  4a3b36:	48 89 df             	mov    rdi,rbx
  4a3b39:	e8 da 60 dc ff       	call   0x269c18
  4a3b3e:	85 c0                	test   eax,eax
  4a3b40:	0f 85 e8 fe ff ff    	jne    0x4a3a2e
  4a3b46:	48 89 df             	mov    rdi,rbx
  4a3b49:	4c 89 f6             	mov    rsi,r14
  4a3b4c:	e8 6f 69 69 00       	call   0xb3a4c0
  4a3b51:	e9 15 02 00 00       	jmp    0x4a3d6b
  4a3b56:	45 0f b7 4e 0a       	movzx  r9d,WORD PTR [r14+0xa]
  4a3b5b:	48 8d 3d b2 f4 0e 01 	lea    rdi,[rip+0x10ef4b2]        # 0x1593014
  4a3b62:	48 8d 15 8f 7b de 00 	lea    rdx,[rip+0xde7b8f]        # 0x128b6f8
  4a3b69:	be d3 02 00 00       	mov    esi,0x2d3
  4a3b6e:	45 89 e0             	mov    r8d,r12d
  4a3b71:	31 c0                	xor    eax,eax
  4a3b73:	4c 89 34 24          	mov    QWORD PTR [rsp],r14
  4a3b77:	e8 74 3e 25 00       	call   0x6f79f0
  4a3b7c:	41 bf 0e 00 00 00    	mov    r15d,0xe
  4a3b82:	e9 fa 00 00 00       	jmp    0x4a3c81
  4a3b87:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a3b8a:	48 85 c0             	test   rax,rax
  4a3b8d:	0f 84 66 01 00 00    	je     0x4a3cf9
  4a3b93:	0f b7 40 0a          	movzx  eax,WORD PTR [rax+0xa]
  4a3b97:	83 e0 fe             	and    eax,0xfffffffe
  4a3b9a:	66 83 f8 12          	cmp    ax,0x12
  4a3b9e:	0f 85 55 01 00 00    	jne    0x4a3cf9
  4a3ba4:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  4a3ba8:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
  4a3bac:	49 89 46 20          	mov    QWORD PTR [r14+0x20],rax
  4a3bb0:	48 8b 38             	mov    rdi,QWORD PTR [rax]
  4a3bb3:	e8 f8 6e 6a 00       	call   0xb4aab0
  4a3bb8:	31 c0                	xor    eax,eax
  4a3bba:	e9 f3 01 00 00       	jmp    0x4a3db2
  4a3bbf:	48 8d 3d 4e f4 0e 01 	lea    rdi,[rip+0x10ef44e]        # 0x1593014
  4a3bc6:	48 8d 15 75 14 f0 00 	lea    rdx,[rip+0xf01475]        # 0x13a5042
  4a3bcd:	be c6 02 00 00       	mov    esi,0x2c6
  4a3bd2:	4c 89 f1             	mov    rcx,r14
  4a3bd5:	31 c0                	xor    eax,eax
  4a3bd7:	e8 14 3e 25 00       	call   0x6f79f0
  4a3bdc:	b8 0e 00 00 00       	mov    eax,0xe
  4a3be1:	e9 cc 01 00 00       	jmp    0x4a3db2
  4a3be6:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a3be9:	0f b7 48 0a          	movzx  ecx,WORD PTR [rax+0xa]
  4a3bed:	83 f9 37             	cmp    ecx,0x37
  4a3bf0:	74 35                	je     0x4a3c27
  4a3bf2:	83 f9 08             	cmp    ecx,0x8
  4a3bf5:	0f 85 4c 01 00 00    	jne    0x4a3d47
  4a3bfb:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
  4a3bff:	48 89 df             	mov    rdi,rbx
  4a3c02:	48 89 83 e0 02 00 00 	mov    QWORD PTR [rbx+0x2e0],rax
  4a3c09:	c6 43 0d 01          	mov    BYTE PTR [rbx+0xd],0x1
  4a3c0d:	49 8b 16             	mov    rdx,QWORD PTR [r14]
  4a3c10:	48 8b 72 20          	mov    rsi,QWORD PTR [rdx+0x20]
  4a3c14:	e8 17 86 66 00       	call   0xb0c230
  4a3c19:	41 89 c7             	mov    r15d,eax
  4a3c1c:	85 c0                	test   eax,eax
  4a3c1e:	0f 85 33 01 00 00    	jne    0x4a3d57
  4a3c24:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a3c27:	48 8b 78 20          	mov    rdi,QWORD PTR [rax+0x20]
  4a3c2b:	e8 90 55 13 00       	call   0x5d91c0
  4a3c30:	48 89 c2             	mov    rdx,rax
  4a3c33:	e9 11 01 00 00       	jmp    0x4a3d49
  4a3c38:	48 89 df             	mov    rdi,rbx
  4a3c3b:	4c 89 f6             	mov    rsi,r14
  4a3c3e:	e8 0d 99 2a 00       	call   0x74d550
  4a3c43:	e9 23 01 00 00       	jmp    0x4a3d6b
  4a3c48:	0f b7 43 0a          	movzx  eax,WORD PTR [rbx+0xa]
  4a3c4c:	0f b7 f8             	movzx  edi,ax
  4a3c4f:	e8 0c 01 71 00       	call   0xbb3d60
  4a3c54:	49 89 c0             	mov    r8,rax
  4a3c57:	48 8d 3d b6 f3 0e 01 	lea    rdi,[rip+0x10ef3b6]        # 0x1593014
  4a3c5e:	48 8d 0d 81 3d dd 00 	lea    rcx,[rip+0xdd3d81]        # 0x12779e6
  4a3c65:	be f1 01 00 00       	mov    esi,0x1f1
  4a3c6a:	44 89 fa             	mov    edx,r15d
  4a3c6d:	31 c0                	xor    eax,eax
  4a3c6f:	e8 1c 3e 25 00       	call   0x6f7a90
  4a3c74:	48 89 df             	mov    rdi,rbx
  4a3c77:	e8 e4 72 10 00       	call   0x5aaf60
  4a3c7c:	45 85 ff             	test   r15d,r15d
  4a3c7f:	74 11                	je     0x4a3c92
  4a3c81:	48 8b bb 90 03 00 00 	mov    rdi,QWORD PTR [rbx+0x390]
  4a3c88:	e8 23 9c 51 00       	call   0x9bd8b0
  4a3c8d:	e9 f1 00 00 00       	jmp    0x4a3d83
  4a3c92:	48 8b bb 90 03 00 00 	mov    rdi,QWORD PTR [rbx+0x390]
  4a3c99:	48 85 ff             	test   rdi,rdi
  4a3c9c:	0f 85 c1 00 00 00    	jne    0x4a3d63
  4a3ca2:	48 8b bb 90 03 00 00 	mov    rdi,QWORD PTR [rbx+0x390]
  4a3ca9:	e8 02 9c 51 00       	call   0x9bd8b0
  4a3cae:	48 8b 83 40 03 00 00 	mov    rax,QWORD PTR [rbx+0x340]
  4a3cb5:	45 31 ff             	xor    r15d,r15d
  4a3cb8:	48 85 c0             	test   rax,rax
  4a3cbb:	0f 84 c2 00 00 00    	je     0x4a3d83
  4a3cc1:	66 81 78 0c c2 00    	cmp    WORD PTR [rax+0xc],0xc2
  4a3cc7:	0f 85 b6 00 00 00    	jne    0x4a3d83
  4a3ccd:	4c 39 70 10          	cmp    QWORD PTR [rax+0x10],r14
  4a3cd1:	0f 85 ac 00 00 00    	jne    0x4a3d83
  4a3cd7:	48 8b b3 90 03 00 00 	mov    rsi,QWORD PTR [rbx+0x390]
  4a3cde:	48 89 df             	mov    rdi,rbx
  4a3ce1:	e8 5a f9 ff ff       	call   0x4a3640
  4a3ce6:	41 89 c7             	mov    r15d,eax
  4a3ce9:	48 c7 83 90 03 00 00 	mov    QWORD PTR [rbx+0x390],0x0
  4a3cf0:	00 00 00 00 
  4a3cf4:	e9 a1 00 00 00       	jmp    0x4a3d9a
  4a3cf9:	48 8b 76 18          	mov    rsi,QWORD PTR [rsi+0x18]
  4a3cfd:	48 89 df             	mov    rdi,rbx
  4a3d00:	e8 0b 75 10 00       	call   0x5ab210
  4a3d05:	85 c0                	test   eax,eax
  4a3d07:	0f 85 21 fd ff ff    	jne    0x4a3a2e
  4a3d0d:	48 89 df             	mov    rdi,rbx
  4a3d10:	e8 fb 71 10 00       	call   0x5aaf10
  4a3d15:	85 c0                	test   eax,eax
  4a3d17:	0f 84 a2 00 00 00    	je     0x4a3dbf
  4a3d1d:	48 89 df             	mov    rdi,rbx
  4a3d20:	41 89 c7             	mov    r15d,eax
  4a3d23:	e8 38 72 10 00       	call   0x5aaf60
  4a3d28:	e9 54 ff ff ff       	jmp    0x4a3c81
  4a3d2d:	48 89 df             	mov    rdi,rbx
  4a3d30:	4c 89 f6             	mov    rsi,r14
  4a3d33:	e8 c8 6d 69 00       	call   0xb3ab00
  4a3d38:	eb 31                	jmp    0x4a3d6b
  4a3d3a:	48 89 df             	mov    rdi,rbx
  4a3d3d:	4c 89 f6             	mov    rsi,r14
  4a3d40:	e8 2b 6b 69 00       	call   0xb3a870
  4a3d45:	eb 24                	jmp    0x4a3d6b
  4a3d47:	31 d2                	xor    edx,edx
  4a3d49:	48 89 df             	mov    rdi,rbx
  4a3d4c:	4c 89 f6             	mov    rsi,r14
  4a3d4f:	e8 8c 6c 69 00       	call   0xb3a9e0
  4a3d54:	41 89 c7             	mov    r15d,eax
  4a3d57:	48 8b bb 90 03 00 00 	mov    rdi,QWORD PTR [rbx+0x390]
  4a3d5e:	48 85 ff             	test   rdi,rdi
  4a3d61:	74 0b                	je     0x4a3d6e
  4a3d63:	48 89 de             	mov    rsi,rbx
  4a3d66:	e8 e5 24 6b 00       	call   0xb56250
  4a3d6b:	41 89 c7             	mov    r15d,eax
  4a3d6e:	48 8b bb 90 03 00 00 	mov    rdi,QWORD PTR [rbx+0x390]
  4a3d75:	e8 36 9b 51 00       	call   0x9bd8b0
  4a3d7a:	45 85 ff             	test   r15d,r15d
  4a3d7d:	0f 84 2b ff ff ff    	je     0x4a3cae
  4a3d83:	48 8b b3 90 03 00 00 	mov    rsi,QWORD PTR [rbx+0x390]
  4a3d8a:	48 85 f6             	test   rsi,rsi
  4a3d8d:	74 0b                	je     0x4a3d9a
  4a3d8f:	4c 89 f7             	mov    rdi,r14
  4a3d92:	48 89 da             	mov    rdx,rbx
  4a3d95:	e8 d6 70 10 00       	call   0x5aae70
  4a3d9a:	45 85 ff             	test   r15d,r15d
  4a3d9d:	74 0d                	je     0x4a3dac
  4a3d9f:	44 89 ff             	mov    edi,r15d
  4a3da2:	48 89 de             	mov    rsi,rbx
  4a3da5:	e8 56 de 04 00       	call   0x4f1c00
  4a3daa:	eb 02                	jmp    0x4a3dae
  4a3dac:	31 c0                	xor    eax,eax
  4a3dae:	c6 43 0d 00          	mov    BYTE PTR [rbx+0xd],0x0
  4a3db2:	48 83 c4 10          	add    rsp,0x10
  4a3db6:	5b                   	pop    rbx
  4a3db7:	41 5c                	pop    r12
  4a3db9:	41 5e                	pop    r14
  4a3dbb:	41 5f                	pop    r15
  4a3dbd:	5d                   	pop    rbp
  4a3dbe:	c3                   	ret
  4a3dbf:	b8 08 40 00 00       	mov    eax,0x4008
  4a3dc4:	eb ec                	jmp    0x4a3db2
  4a3dc6:	48 8d 3d 93 43 62 01 	lea    rdi,[rip+0x1624393]        # 0x1ac8160
  4a3dcd:	4c 89 fe             	mov    rsi,r15
  4a3dd0:	e8 eb ba fa ff       	call   0x44f8c0
  4a3dd5:	e9 18 fd ff ff       	jmp    0x4a3af2
  4a3dda:	90                   	nop
  4a3ddb:	90                   	nop
  4a3ddc:	90                   	nop
  4a3ddd:	90                   	nop
  4a3dde:	90                   	nop
  4a3ddf:	90                   	nop
  4a3de0:	55                   	push   rbp
  4a3de1:	48 89 e5             	mov    rbp,rsp
  4a3de4:	48 85 f6             	test   rsi,rsi
  4a3de7:	74 3c                	je     0x4a3e25
  4a3de9:	31 c0                	xor    eax,eax
  4a3deb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  4a3df0:	8b 0c 87             	mov    ecx,DWORD PTR [rdi+rax*4]
  4a3df3:	48 ff c0             	inc    rax
  4a3df6:	44 69 c1 51 2d 9e cc 	imul   r8d,ecx,0xcc9e2d51
  4a3dfd:	69 c9 00 80 a8 16    	imul   ecx,ecx,0x16a88000
  4a3e03:	41 c1 e8 11          	shr    r8d,0x11
  4a3e07:	41 09 c8             	or     r8d,ecx
  4a3e0a:	41 69 c8 93 35 87 1b 	imul   ecx,r8d,0x1b873593
  4a3e11:	31 d1                	xor    ecx,edx
  4a3e13:	c4 e3 7b f0 c9 13    	rorx   ecx,ecx,0x13
  4a3e19:	8d 94 89 64 6b 54 e6 	lea    edx,[rcx+rcx*4-0x19ab949c]
  4a3e20:	48 39 c6             	cmp    rsi,rax
  4a3e23:	75 cb                	jne    0x4a3df0
  4a3e25:	31 d6                	xor    esi,edx
  4a3e27:	89 f0                	mov    eax,esi
  4a3e29:	c1 e8 10             	shr    eax,0x10
  4a3e2c:	31 f0                	xor    eax,esi
  4a3e2e:	69 c0 6b ca eb 85    	imul   eax,eax,0x85ebca6b
  4a3e34:	89 c1                	mov    ecx,eax
  4a3e36:	c1 e9 0d             	shr    ecx,0xd
  4a3e39:	31 c1                	xor    ecx,eax
  4a3e3b:	69 c9 35 ae b2 c2    	imul   ecx,ecx,0xc2b2ae35
  4a3e41:	89 c8                	mov    eax,ecx
  4a3e43:	c1 e8 10             	shr    eax,0x10
  4a3e46:	31 c8                	xor    eax,ecx
  4a3e48:	5d                   	pop    rbp
  4a3e49:	c3                   	ret
  4a3e4a:	90                   	nop
  4a3e4b:	90                   	nop
  4a3e4c:	90                   	nop
  4a3e4d:	90                   	nop
  4a3e4e:	90                   	nop
  4a3e4f:	90                   	nop
  4a3e50:	55                   	push   rbp
  4a3e51:	48 89 e5             	mov    rbp,rsp
  4a3e54:	c4 e1 f9 7e c0       	vmovq  rax,xmm0
  4a3e59:	48 89 c1             	mov    rcx,rax
  4a3e5c:	48 c1 e9 20          	shr    rcx,0x20
  4a3e60:	89 ca                	mov    edx,ecx
  4a3e62:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
  4a3e68:	81 fa 00 00 90 40    	cmp    edx,0x40900000
  4a3e6e:	72 2d                	jb     0x4a3e9d
  4a3e70:	81 fa 00 00 f0 7f    	cmp    edx,0x7ff00000
  4a3e76:	72 37                	jb     0x4a3eaf
  4a3e78:	c5 fb 58 c0          	vaddsd xmm0,xmm0,xmm0
  4a3e7c:	81 e1 ff ff 0f 00    	and    ecx,0xfffff
  4a3e82:	09 c1                	or     ecx,eax
  4a3e84:	c5 f9 28 c8          	vmovapd xmm1,xmm0
  4a3e88:	75 04                	jne    0x4a3e8e
  4a3e8a:	c5 f1 57 c9          	vxorpd xmm1,xmm1,xmm1
  4a3e8e:	48 85 c0             	test   rax,rax
  4a3e91:	0f 89 1d 01 00 00    	jns    0x4a3fb4
  4a3e97:	c5 f9 28 c1          	vmovapd xmm0,xmm1
  4a3e9b:	5d                   	pop    rbp
  4a3e9c:	c3                   	ret
  4a3e9d:	81 fa ff ff 8f 3c    	cmp    edx,0x3c8fffff
  4a3ea3:	77 2a                	ja     0x4a3ecf
  4a3ea5:	c5 fb 58 05 33 68 f1 	vaddsd xmm0,xmm0,QWORD PTR [rip+0xf16833]        # 0x13ba6e0
  4a3eac:	00 
  4a3ead:	5d                   	pop    rbp
  4a3eae:	c3                   	ret
  4a3eaf:	c5 f9 2e 05 79 6c f1 	vucomisd xmm0,QWORD PTR [rip+0xf16c79]        # 0x13bab30
  4a3eb6:	00 
  4a3eb7:	0f 83 d7 00 00 00    	jae    0x4a3f94
  4a3ebd:	c5 fb 10 0d 3b 6c f1 	vmovsd xmm1,QWORD PTR [rip+0xf16c3b]        # 0x13bab00
  4a3ec4:	00 
  4a3ec5:	c5 f9 2e c8          	vucomisd xmm1,xmm0
  4a3ec9:	0f 83 d5 00 00 00    	jae    0x4a3fa4
  4a3ecf:	c5 fb 58 0d 19 6e f1 	vaddsd xmm1,xmm0,QWORD PTR [rip+0xf16e19]        # 0x13bacf0
  4a3ed6:	00 
  4a3ed7:	48 8d 15 52 f1 0e 01 	lea    rdx,[rip+0x10ef152]        # 0x1593030
  4a3ede:	c4 e1 f9 7e c8       	vmovq  rax,xmm1
  4a3ee3:	c5 f3 58 0d 75 6d f1 	vaddsd xmm1,xmm1,QWORD PTR [rip+0xf16d75]        # 0x13bac60
  4a3eea:	00 
  4a3eeb:	83 e8 80             	sub    eax,0xffffff80
  4a3eee:	0f b6 c8             	movzx  ecx,al
  4a3ef1:	c1 e0 0c             	shl    eax,0xc
  4a3ef4:	c1 e1 04             	shl    ecx,0x4
  4a3ef7:	25 00 00 f0 ff       	and    eax,0xfff00000
  4a3efc:	c5 fb 5c c9          	vsubsd xmm1,xmm0,xmm1
  4a3f00:	c5 f3 5c 4c 0a 08    	vsubsd xmm1,xmm1,QWORD PTR [rdx+rcx*1+0x8]
  4a3f06:	c5 fb 10 04 11       	vmovsd xmm0,QWORD PTR [rcx+rdx*1]
  4a3f0b:	3d 00 00 30 c0       	cmp    eax,0xc0300000
  4a3f10:	7c 11                	jl     0x4a3f23
  4a3f12:	8d 88 00 00 f0 3f    	lea    ecx,[rax+0x3ff00000]
  4a3f18:	48 c1 e1 20          	shl    rcx,0x20
  4a3f1c:	c4 e1 f9 6e d1       	vmovq  xmm2,rcx
  4a3f21:	eb 0f                	jmp    0x4a3f32
  4a3f23:	8d 88 00 00 70 7e    	lea    ecx,[rax+0x7e700000]
  4a3f29:	48 c1 e1 20          	shl    rcx,0x20
  4a3f2d:	c4 e1 f9 6e d9       	vmovq  xmm3,rcx
  4a3f32:	c5 f3 59 2d 9e 65 f1 	vmulsd xmm5,xmm1,QWORD PTR [rip+0xf1659e]        # 0x13ba4d8
  4a3f39:	00 
  4a3f3a:	c5 fb 59 e1          	vmulsd xmm4,xmm0,xmm1
  4a3f3e:	c5 d3 58 2d b2 6d f1 	vaddsd xmm5,xmm5,QWORD PTR [rip+0xf16db2]        # 0x13bacf8
  4a3f45:	00 
  4a3f46:	c5 f3 59 ed          	vmulsd xmm5,xmm1,xmm5
  4a3f4a:	c5 d3 58 2d 3e 66 f1 	vaddsd xmm5,xmm5,QWORD PTR [rip+0xf1663e]        # 0x13ba590
  4a3f51:	00 
  4a3f52:	c5 f3 59 ed          	vmulsd xmm5,xmm1,xmm5
  4a3f56:	c5 d3 58 2d 12 67 f1 	vaddsd xmm5,xmm5,QWORD PTR [rip+0xf16712]        # 0x13ba670
  4a3f5d:	00 
  4a3f5e:	c5 f3 59 cd          	vmulsd xmm1,xmm1,xmm5
  4a3f62:	c5 f3 58 0d 36 6b f1 	vaddsd xmm1,xmm1,QWORD PTR [rip+0xf16b36]        # 0x13baaa0
  4a3f69:	00 
  4a3f6a:	c5 db 59 c9          	vmulsd xmm1,xmm4,xmm1
  4a3f6e:	c5 fb 58 c1          	vaddsd xmm0,xmm0,xmm1
  4a3f72:	3d 00 00 30 c0       	cmp    eax,0xc0300000
  4a3f77:	7c 15                	jl     0x4a3f8e
  4a3f79:	3d 00 00 00 40       	cmp    eax,0x40000000
  4a3f7e:	75 1e                	jne    0x4a3f9e
  4a3f80:	c5 fb 58 c0          	vaddsd xmm0,xmm0,xmm0
  4a3f84:	c5 fb 59 05 14 69 f1 	vmulsd xmm0,xmm0,QWORD PTR [rip+0xf16914]        # 0x13ba8a0
  4a3f8b:	00 
  4a3f8c:	5d                   	pop    rbp
  4a3f8d:	c3                   	ret
  4a3f8e:	c5 fb 59 c3          	vmulsd xmm0,xmm0,xmm3
  4a3f92:	eb 18                	jmp    0x4a3fac
  4a3f94:	c5 fb 10 05 ec 65 f1 	vmovsd xmm0,QWORD PTR [rip+0xf165ec]        # 0x13ba588
  4a3f9b:	00 
  4a3f9c:	5d                   	pop    rbp
  4a3f9d:	c3                   	ret
  4a3f9e:	c5 fb 59 c2          	vmulsd xmm0,xmm0,xmm2
  4a3fa2:	5d                   	pop    rbp
  4a3fa3:	c3                   	ret
  4a3fa4:	c5 fb 10 05 d4 41 62 	vmovsd xmm0,QWORD PTR [rip+0x16241d4]        # 0x1ac8180
  4a3fab:	01 
  4a3fac:	c5 fb 59 05 cc 41 62 	vmulsd xmm0,xmm0,QWORD PTR [rip+0x16241cc]        # 0x1ac8180
  4a3fb3:	01 
  4a3fb4:	5d                   	pop    rbp
  4a3fb5:	c3                   	ret
  4a3fb6:	90                   	nop
  4a3fb7:	90                   	nop
  4a3fb8:	90                   	nop
  4a3fb9:	90                   	nop
  4a3fba:	90                   	nop
  4a3fbb:	90                   	nop
  4a3fbc:	90                   	nop
  4a3fbd:	90                   	nop
  4a3fbe:	90                   	nop
  4a3fbf:	90                   	nop
  4a3fc0:	55                   	push   rbp
  4a3fc1:	48 89 e5             	mov    rbp,rsp
  4a3fc4:	41 57                	push   r15
  4a3fc6:	41 56                	push   r14
  4a3fc8:	41 55                	push   r13
  4a3fca:	41 54                	push   r12
  4a3fcc:	53                   	push   rbx
  4a3fcd:	48 83 ec 28          	sub    rsp,0x28
  4a3fd1:	4c 8d 2d 38 83 47 03 	lea    r13,[rip+0x3478338]        # 0x391c310
  4a3fd8:	49 89 fe             	mov    r14,rdi
  4a3fdb:	48 89 f3             	mov    rbx,rsi
  4a3fde:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  4a3fe2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  4a3fe6:	4c 8b 7f 48          	mov    r15,QWORD PTR [rdi+0x48]
  4a3fea:	44 8b 67 78          	mov    r12d,DWORD PTR [rdi+0x78]
  4a3fee:	48 8d 7d b8          	lea    rdi,[rbp-0x48]
  4a3ff2:	e8 49 b7 62 00       	call   0xacf740
  4a3ff7:	41 f6 46 78 01       	test   BYTE PTR [r14+0x78],0x1
  4a3ffc:	74 22                	je     0x4a4020
  4a3ffe:	41 8b 97 84 00 00 00 	mov    edx,DWORD PTR [r15+0x84]
  4a4005:	03 53 30             	add    edx,DWORD PTR [rbx+0x30]
  4a4008:	4c 89 f7             	mov    rdi,r14
  4a400b:	be 05 00 00 00       	mov    esi,0x5
  4a4010:	e8 eb 7e 01 00       	call   0x4bbf00
  4a4015:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  4a4019:	49 89 87 f0 00 00 00 	mov    QWORD PTR [r15+0xf0],rax
  4a4020:	8b 53 30             	mov    edx,DWORD PTR [rbx+0x30]
  4a4023:	83 fa 04             	cmp    edx,0x4
  4a4026:	77 5b                	ja     0x4a4083
  4a4028:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a402c:	48 8d 3d 58 55 e2 00 	lea    rdi,[rip+0xe25558]        # 0x12c958b
  4a4033:	31 c0                	xor    eax,eax
  4a4035:	e8 d6 93 db ff       	call   0x25d410
  4a403a:	ba 01 00 00 00       	mov    edx,0x1
  4a403f:	4c 89 f7             	mov    rdi,r14
  4a4042:	be 01 00 00 00       	mov    esi,0x1
  4a4047:	e8 b4 7e 01 00       	call   0x4bbf00
  4a404c:	ba 01 00 00 00       	mov    edx,0x1
  4a4051:	4c 89 f7             	mov    rdi,r14
  4a4054:	be 09 00 00 00       	mov    esi,0x9
  4a4059:	e8 a2 7e 01 00       	call   0x4bbf00
  4a405e:	48 89 df             	mov    rdi,rbx
  4a4061:	e8 ea 67 f8 ff       	call   0x42a850
  4a4066:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  4a406a:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a406e:	0f 85 ae 03 00 00    	jne    0x4a4422
  4a4074:	48 83 c4 28          	add    rsp,0x28
  4a4078:	5b                   	pop    rbx
  4a4079:	41 5c                	pop    r12
  4a407b:	41 5d                	pop    r13
  4a407d:	41 5e                	pop    r14
  4a407f:	41 5f                	pop    r15
  4a4081:	5d                   	pop    rbp
  4a4082:	c3                   	ret
  4a4083:	39 53 18             	cmp    DWORD PTR [rbx+0x18],edx
  4a4086:	7d 12                	jge    0x4a409a
  4a4088:	48 89 df             	mov    rdi,rbx
  4a408b:	89 d6                	mov    esi,edx
  4a408d:	e8 be 50 57 00       	call   0xa19150
  4a4092:	48 89 c3             	mov    rbx,rax
  4a4095:	48 85 c0             	test   rax,rax
  4a4098:	74 cc                	je     0x4a4066
  4a409a:	41 f6 87 80 00 00 00 	test   BYTE PTR [r15+0x80],0x20
  4a40a1:	20 
  4a40a2:	4c 8b 6b 10          	mov    r13,QWORD PTR [rbx+0x10]
  4a40a6:	75 6b                	jne    0x4a4113
  4a40a8:	49 8d 45 02          	lea    rax,[r13+0x2]
  4a40ac:	48 89 df             	mov    rdi,rbx
  4a40af:	be 04 00 00 00       	mov    esi,0x4
  4a40b4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  4a40b8:	e8 a3 4f 57 00       	call   0xa19060
  4a40bd:	41 0f b6 55 00       	movzx  edx,BYTE PTR [r13+0x0]
  4a40c2:	83 fa 0f             	cmp    edx,0xf
  4a40c5:	0f 84 cc 00 00 00    	je     0x4a4197
  4a40cb:	81 fa 8f 00 00 00    	cmp    edx,0x8f
  4a40d1:	0f 84 c0 00 00 00    	je     0x4a4197
  4a40d7:	81 fa ff 00 00 00    	cmp    edx,0xff
  4a40dd:	0f 85 bc 02 00 00    	jne    0x4a439f
  4a40e3:	41 80 7d 01 03       	cmp    BYTE PTR [r13+0x1],0x3
  4a40e8:	b2 ff                	mov    dl,0xff
  4a40ea:	0f 85 af 02 00 00    	jne    0x4a439f
  4a40f0:	41 f6 87 80 00 00 00 	test   BYTE PTR [r15+0x80],0x2
  4a40f7:	02 
  4a40f8:	0f 85 d2 02 00 00    	jne    0x4a43d0
  4a40fe:	4c 8b 65 b0          	mov    r12,QWORD PTR [rbp-0x50]
  4a4102:	41 0f b7 04 24       	movzx  eax,WORD PTR [r12]
  4a4107:	66 0f 38 f1 45 ce    	movbe  WORD PTR [rbp-0x32],ax
  4a410d:	66 c1 c0 08          	rol    ax,0x8
  4a4111:	eb 30                	jmp    0x4a4143
  4a4113:	48 8d 7d ce          	lea    rdi,[rbp-0x32]
  4a4117:	ba 02 00 00 00       	mov    edx,0x2
  4a411c:	4c 89 ee             	mov    rsi,r13
  4a411f:	e8 8c 4f db ff       	call   0x2590b0
  4a4124:	0f b7 45 ce          	movzx  eax,WORD PTR [rbp-0x32]
  4a4128:	48 89 df             	mov    rdi,rbx
  4a412b:	be 02 00 00 00       	mov    esi,0x2
  4a4130:	66 0f 38 f1 45 ce    	movbe  WORD PTR [rbp-0x32],ax
  4a4136:	4c 8b 63 10          	mov    r12,QWORD PTR [rbx+0x10]
  4a413a:	e8 21 4f 57 00       	call   0xa19060
  4a413f:	0f b7 45 ce          	movzx  eax,WORD PTR [rbp-0x32]
  4a4143:	4c 8d 2d c6 81 47 03 	lea    r13,[rip+0x34781c6]        # 0x391c310
  4a414a:	0f b7 c8             	movzx  ecx,ax
  4a414d:	81 f9 20 c0 00 00    	cmp    ecx,0xc020
  4a4153:	7e 72                	jle    0x4a41c7
  4a4155:	81 f9 21 c0 00 00    	cmp    ecx,0xc021
  4a415b:	0f 84 d2 00 00 00    	je     0x4a4233
  4a4161:	81 f9 23 c0 00 00    	cmp    ecx,0xc023
  4a4167:	0f 84 dd 00 00 00    	je     0x4a424a
  4a416d:	81 f9 23 c2 00 00    	cmp    ecx,0xc223
  4a4173:	0f 85 24 01 00 00    	jne    0x4a429d
  4a4179:	41 83 bf 18 01 00 00 	cmp    DWORD PTR [r15+0x118],0x3
  4a4180:	03 
  4a4181:	0f 8c d7 fe ff ff    	jl     0x4a405e
  4a4187:	4c 89 ff             	mov    rdi,r15
  4a418a:	48 89 de             	mov    rsi,rbx
  4a418d:	e8 1e 22 00 00       	call   0x4a63b0
  4a4192:	e9 c7 fe ff ff       	jmp    0x4a405e
  4a4197:	41 f6 87 80 00 00 00 	test   BYTE PTR [r15+0x80],0x2
  4a419e:	02 
  4a419f:	75 52                	jne    0x4a41f3
  4a41a1:	41 f6 c4 04          	test   r12b,0x4
  4a41a5:	0f 84 e6 00 00 00    	je     0x4a4291
  4a41ab:	66 41 0f 38 f0 45 02 	movbe  ax,WORD PTR [r13+0x2]
  4a41b2:	41 0f b6 4d 01       	movzx  ecx,BYTE PTR [r13+0x1]
  4a41b7:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a41bb:	48 8d 3d 01 45 e4 00 	lea    rdi,[rip+0xe44501]        # 0x12e86c3
  4a41c2:	e9 f2 01 00 00       	jmp    0x4a43b9
  4a41c7:	83 f9 21             	cmp    ecx,0x21
  4a41ca:	0f 84 98 00 00 00    	je     0x4a4268
  4a41d0:	81 f9 21 80 00 00    	cmp    ecx,0x8021
  4a41d6:	0f 85 c1 00 00 00    	jne    0x4a429d
  4a41dc:	41 83 bf 18 01 00 00 	cmp    DWORD PTR [r15+0x118],0x4
  4a41e3:	04 
  4a41e4:	0f 85 74 fe ff ff    	jne    0x4a405e
  4a41ea:	48 8d 3d 9f b8 9d 00 	lea    rdi,[rip+0x9db89f]        # 0xe7fa90
  4a41f1:	eb 47                	jmp    0x4a423a
  4a41f3:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
  4a41f7:	66 0f 38 f0 00       	movbe  ax,WORD PTR [rax]
  4a41fc:	66 3d 00 08          	cmp    ax,0x800
  4a4200:	0f 84 84 00 00 00    	je     0x4a428a
  4a4206:	0f b7 c0             	movzx  eax,ax
  4a4209:	3d 35 80 00 00       	cmp    eax,0x8035
  4a420e:	0f 85 74 01 00 00    	jne    0x4a4388
  4a4214:	4c 89 f7             	mov    rdi,r14
  4a4217:	48 89 de             	mov    rsi,rbx
  4a421a:	e8 11 02 00 00       	call   0x4a4430
  4a421f:	48 89 df             	mov    rdi,rbx
  4a4222:	e8 29 66 f8 ff       	call   0x42a850
  4a4227:	4c 8d 2d e2 80 47 03 	lea    r13,[rip+0x34780e2]        # 0x391c310
  4a422e:	e9 33 fe ff ff       	jmp    0x4a4066
  4a4233:	48 8d 3d 46 b6 9d 00 	lea    rdi,[rip+0x9db646]        # 0xe7f880
  4a423a:	4c 89 fe             	mov    rsi,r15
  4a423d:	48 89 da             	mov    rdx,rbx
  4a4240:	e8 fb 07 00 00       	call   0x4a4a40
  4a4245:	e9 14 fe ff ff       	jmp    0x4a405e
  4a424a:	41 83 bf 18 01 00 00 	cmp    DWORD PTR [r15+0x118],0x3
  4a4251:	03 
  4a4252:	0f 8c 06 fe ff ff    	jl     0x4a405e
  4a4258:	4c 89 ff             	mov    rdi,r15
  4a425b:	48 89 de             	mov    rsi,rbx
  4a425e:	e8 0d 1b 00 00       	call   0x4a5d70
  4a4263:	e9 f6 fd ff ff       	jmp    0x4a405e
  4a4268:	48 8d 7d b8          	lea    rdi,[rbp-0x48]
  4a426c:	e8 cf b4 62 00       	call   0xacf740
  4a4271:	41 83 bf 30 01 00 00 	cmp    DWORD PTR [r15+0x130],0x9
  4a4278:	09 
  4a4279:	0f 85 bb fd ff ff    	jne    0x4a403a
  4a427f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  4a4283:	49 89 87 00 01 00 00 	mov    QWORD PTR [r15+0x100],rax
  4a428a:	41 f6 46 78 01       	test   BYTE PTR [r14+0x78],0x1
  4a428f:	75 7d                	jne    0x4a430e
  4a4291:	4c 8d 2d 78 80 47 03 	lea    r13,[rip+0x3478078]        # 0x391c310
  4a4298:	e9 9d fd ff ff       	jmp    0x4a403a
  4a429d:	41 83 bf 2c 01 00 00 	cmp    DWORD PTR [r15+0x12c],0x9
  4a42a4:	09 
  4a42a5:	75 37                	jne    0x4a42de
  4a42a7:	49 8b 87 98 00 00 00 	mov    rax,QWORD PTR [r15+0x98]
  4a42ae:	4c 89 ff             	mov    rdi,r15
  4a42b1:	be 21 c0 00 00       	mov    esi,0xc021
  4a42b6:	4d 89 e1             	mov    r9,r12
  4a42b9:	48 ff c0             	inc    rax
  4a42bc:	49 89 87 98 00 00 00 	mov    QWORD PTR [r15+0x98],rax
  4a42c3:	0f b6 c8             	movzx  ecx,al
  4a42c6:	8b 53 30             	mov    edx,DWORD PTR [rbx+0x30]
  4a42c9:	83 c2 02             	add    edx,0x2
  4a42cc:	44 0f b7 c2          	movzx  r8d,dx
  4a42d0:	ba 08 00 00 00       	mov    edx,0x8
  4a42d5:	e8 76 03 00 00       	call   0x4a4650
  4a42da:	0f b7 45 ce          	movzx  eax,WORD PTR [rbp-0x32]
  4a42de:	66 c1 c0 08          	rol    ax,0x8
  4a42e2:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a42e6:	48 8d 3d 2e 89 e7 00 	lea    rdi,[rip+0xe7892e]        # 0x131cc1b
  4a42ed:	0f b7 d0             	movzx  edx,ax
  4a42f0:	31 c0                	xor    eax,eax
  4a42f2:	e8 19 91 db ff       	call   0x25d410
  4a42f7:	ba 01 00 00 00       	mov    edx,0x1
  4a42fc:	4c 89 f7             	mov    rdi,r14
  4a42ff:	be 0b 00 00 00       	mov    esi,0xb
  4a4304:	e8 f7 7b 01 00       	call   0x4bbf00
  4a4309:	e9 2c fd ff ff       	jmp    0x4a403a
  4a430e:	49 81 c7 88 01 00 00 	add    r15,0x188
  4a4315:	31 f6                	xor    esi,esi
  4a4317:	31 d2                	xor    edx,edx
  4a4319:	31 c9                	xor    ecx,ecx
  4a431b:	4c 89 ff             	mov    rdi,r15
  4a431e:	e8 dd 26 02 00       	call   0x4c6a00
  4a4323:	bf 01 00 00 00       	mov    edi,0x1
  4a4328:	48 89 de             	mov    rsi,rbx
  4a432b:	e8 90 3f e5 ff       	call   0x2f82c0
  4a4330:	4c 8d 2d d9 7f 47 03 	lea    r13,[rip+0x3477fd9]        # 0x391c310
  4a4337:	85 c0                	test   eax,eax
  4a4339:	0f 84 d0 00 00 00    	je     0x4a440f
  4a433f:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a4343:	48 8d 3d be 36 dd 00 	lea    rdi,[rip+0xdd36be]        # 0x1277a08
  4a434a:	31 c0                	xor    eax,eax
  4a434c:	e8 bf 90 db ff       	call   0x25d410
  4a4351:	4c 89 ff             	mov    rdi,r15
  4a4354:	31 f6                	xor    esi,esi
  4a4356:	31 d2                	xor    edx,edx
  4a4358:	31 c9                	xor    ecx,ecx
  4a435a:	e8 41 2c 02 00       	call   0x4c6fa0
  4a435f:	ba 01 00 00 00       	mov    edx,0x1
  4a4364:	4c 89 f7             	mov    rdi,r14
  4a4367:	be 01 00 00 00       	mov    esi,0x1
  4a436c:	e8 8f 7b 01 00       	call   0x4bbf00
  4a4371:	ba 01 00 00 00       	mov    edx,0x1
  4a4376:	4c 89 f7             	mov    rdi,r14
  4a4379:	be 09 00 00 00       	mov    esi,0x9
  4a437e:	e8 7d 7b 01 00       	call   0x4bbf00
  4a4383:	e9 de fc ff ff       	jmp    0x4a4066
  4a4388:	ba 01 00 00 00       	mov    edx,0x1
  4a438d:	4c 89 f7             	mov    rdi,r14
  4a4390:	be 0b 00 00 00       	mov    esi,0xb
  4a4395:	e8 66 7b 01 00       	call   0x4bbf00
  4a439a:	41 0f b6 55 00       	movzx  edx,BYTE PTR [r13+0x0]
  4a439f:	66 41 0f 38 f0 45 02 	movbe  ax,WORD PTR [r13+0x2]
  4a43a6:	41 0f b6 4d 01       	movzx  ecx,BYTE PTR [r13+0x1]
  4a43ab:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a43af:	0f b6 d2             	movzx  edx,dl
  4a43b2:	48 8d 3d 5f 24 ec 00 	lea    rdi,[rip+0xec245f]        # 0x1366818
  4a43b9:	44 0f b7 c0          	movzx  r8d,ax
  4a43bd:	31 c0                	xor    eax,eax
  4a43bf:	e8 4c 90 db ff       	call   0x25d410
  4a43c4:	4c 8d 2d 45 7f 47 03 	lea    r13,[rip+0x3477f45]        # 0x391c310
  4a43cb:	e9 6a fc ff ff       	jmp    0x4a403a
  4a43d0:	4c 8d 2d 39 7f 47 03 	lea    r13,[rip+0x3477f39]        # 0x391c310
  4a43d7:	41 f6 c4 04          	test   r12b,0x4
  4a43db:	0f 84 59 fc ff ff    	je     0x4a403a
  4a43e1:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
  4a43e5:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a43e9:	48 8d 3d 1d 5e e0 00 	lea    rdi,[rip+0xe05e1d]        # 0x12aa20d
  4a43f0:	ba ff 00 00 00       	mov    edx,0xff
  4a43f5:	b9 03 00 00 00       	mov    ecx,0x3
  4a43fa:	66 0f 38 f0 00       	movbe  ax,WORD PTR [rax]
  4a43ff:	44 0f b7 c0          	movzx  r8d,ax
  4a4403:	31 c0                	xor    eax,eax
  4a4405:	e8 06 90 db ff       	call   0x25d410
  4a440a:	e9 2b fc ff ff       	jmp    0x4a403a
  4a440f:	4c 89 ff             	mov    rdi,r15
  4a4412:	31 f6                	xor    esi,esi
  4a4414:	31 d2                	xor    edx,edx
  4a4416:	31 c9                	xor    ecx,ecx
  4a4418:	e8 83 2b 02 00       	call   0x4c6fa0
  4a441d:	e9 44 fc ff ff       	jmp    0x4a4066
  4a4422:	e8 89 92 25 00       	call   0x6fd6b0
  4a4427:	0f 0b                	ud2
  4a4429:	90                   	nop
  4a442a:	90                   	nop
  4a442b:	90                   	nop
  4a442c:	90                   	nop
  4a442d:	90                   	nop
  4a442e:	90                   	nop
  4a442f:	90                   	nop
  4a4430:	55                   	push   rbp
  4a4431:	48 89 e5             	mov    rbp,rsp
  4a4434:	41 57                	push   r15
  4a4436:	41 56                	push   r14
  4a4438:	41 55                	push   r13
  4a443a:	41 54                	push   r12
  4a443c:	53                   	push   rbx
  4a443d:	50                   	push   rax
  4a443e:	4c 8b 37             	mov    r14,QWORD PTR [rdi]
  4a4441:	8b 56 30             	mov    edx,DWORD PTR [rsi+0x30]
  4a4444:	83 fa 11             	cmp    edx,0x11
  4a4447:	7f 23                	jg     0x4a446c
  4a4449:	49 83 c6 60          	add    r14,0x60
  4a444d:	48 8d 3d cd cf ea 00 	lea    rdi,[rip+0xeacfcd]        # 0x1351421
  4a4454:	4c 89 f6             	mov    rsi,r14
  4a4457:	31 c0                	xor    eax,eax
  4a4459:	48 83 c4 08          	add    rsp,0x8
  4a445d:	5b                   	pop    rbx
  4a445e:	41 5c                	pop    r12
  4a4460:	41 5d                	pop    r13
  4a4462:	41 5e                	pop    r14
  4a4464:	41 5f                	pop    r15
  4a4466:	5d                   	pop    rbp
  4a4467:	e9 a4 8f db ff       	jmp    0x25d410
  4a446c:	45 8b 7e 78          	mov    r15d,DWORD PTR [r14+0x78]
  4a4470:	4c 8b 66 10          	mov    r12,QWORD PTR [rsi+0x10]
  4a4474:	48 89 fb             	mov    rbx,rdi
  4a4477:	41 f6 c7 04          	test   r15b,0x4
  4a447b:	74 42                	je     0x4a44bf
  4a447d:	41 0f 38 f0 0c 24    	movbe  ecx,DWORD PTR [r12]
  4a4483:	45 8b 44 24 04       	mov    r8d,DWORD PTR [r12+0x4]
  4a4488:	45 8b 4c 24 08       	mov    r9d,DWORD PTR [r12+0x8]
  4a448d:	45 0f b7 54 24 0c    	movzx  r10d,WORD PTR [r12+0xc]
  4a4493:	45 0f b7 5c 24 0e    	movzx  r11d,WORD PTR [r12+0xe]
  4a4499:	45 0f b7 6c 24 10    	movzx  r13d,WORD PTR [r12+0x10]
  4a449f:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a44a3:	48 83 ec 08          	sub    rsp,0x8
  4a44a7:	48 8d 3d 1f c1 df 00 	lea    rdi,[rip+0xdfc11f]        # 0x12a05cd
  4a44ae:	31 c0                	xor    eax,eax
  4a44b0:	41 55                	push   r13
  4a44b2:	41 53                	push   r11
  4a44b4:	41 52                	push   r10
  4a44b6:	e8 55 8f db ff       	call   0x25d410
  4a44bb:	48 83 c4 20          	add    rsp,0x20
  4a44bf:	41 0f 38 f0 14 24    	movbe  edx,DWORD PTR [r12]
  4a44c5:	85 d2                	test   edx,edx
  4a44c7:	0f 84 80 00 00 00    	je     0x4a454d
  4a44cd:	83 fa 01             	cmp    edx,0x1
  4a44d0:	0f 84 15 01 00 00    	je     0x4a45eb
  4a44d6:	83 fa 02             	cmp    edx,0x2
  4a44d9:	0f 85 95 00 00 00    	jne    0x4a4574
  4a44df:	c7 83 88 00 00 00 00 	mov    DWORD PTR [rbx+0x88],0x0
  4a44e6:	00 00 00 
  4a44e9:	41 0f 38 f0 44 24 04 	movbe  eax,DWORD PTR [r12+0x4]
  4a44f0:	48 89 83 c0 00 00 00 	mov    QWORD PTR [rbx+0xc0],rax
  4a44f7:	48 39 83 98 00 00 00 	cmp    QWORD PTR [rbx+0x98],rax
  4a44fe:	0f 85 86 00 00 00    	jne    0x4a458a
  4a4504:	83 bb 8c 00 00 00 03 	cmp    DWORD PTR [rbx+0x8c],0x3
  4a450b:	72 27                	jb     0x4a4534
  4a450d:	49 8d 76 60          	lea    rsi,[r14+0x60]
  4a4511:	48 8d 3d 33 c0 df 00 	lea    rdi,[rip+0xdfc033]        # 0x12a054b
  4a4518:	31 c0                	xor    eax,eax
  4a451a:	e8 f1 8e db ff       	call   0x25d410
  4a451f:	c7 83 8c 00 00 00 00 	mov    DWORD PTR [rbx+0x8c],0x0
  4a4526:	00 00 00 
  4a4529:	41 f6 46 78 01       	test   BYTE PTR [r14+0x78],0x1
  4a452e:	0f 85 c6 00 00 00    	jne    0x4a45fa
  4a4534:	ff 83 8c 00 00 00    	inc    DWORD PTR [rbx+0x8c]
  4a453a:	e8 91 e7 4e 00       	call   0x992cd0
  4a453f:	89 c0                	mov    eax,eax
  4a4541:	48 89 83 98 00 00 00 	mov    QWORD PTR [rbx+0x98],rax
  4a4548:	e9 9e 00 00 00       	jmp    0x4a45eb
  4a454d:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  4a4550:	31 d2                	xor    edx,edx
  4a4552:	48 8b 80 80 02 00 00 	mov    rax,QWORD PTR [rax+0x280]
  4a4559:	48 85 c0             	test   rax,rax
  4a455c:	74 6c                	je     0x4a45ca
  4a455e:	66 90                	xchg   ax,ax
  4a4560:	48 8b 08             	mov    rcx,QWORD PTR [rax]
  4a4563:	80 79 01 02          	cmp    BYTE PTR [rcx+0x1],0x2
  4a4567:	74 4d                	je     0x4a45b6
  4a4569:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  4a456d:	48 85 c0             	test   rax,rax
  4a4570:	75 ee                	jne    0x4a4560
  4a4572:	eb 56                	jmp    0x4a45ca
  4a4574:	41 f6 c7 04          	test   r15b,0x4
  4a4578:	74 71                	je     0x4a45eb
  4a457a:	49 83 c6 60          	add    r14,0x60
  4a457e:	48 8d 3d eb b6 ee 00 	lea    rdi,[rip+0xeeb6eb]        # 0x138fc70
  4a4585:	e9 ca fe ff ff       	jmp    0x4a4454
  4a458a:	c7 83 8c 00 00 00 00 	mov    DWORD PTR [rbx+0x8c],0x0
  4a4591:	00 00 00 
  4a4594:	41 8b 46 78          	mov    eax,DWORD PTR [r14+0x78]
  4a4598:	83 e0 41             	and    eax,0x41
  4a459b:	83 f8 40             	cmp    eax,0x40
  4a459e:	75 4b                	jne    0x4a45eb
  4a45a0:	4c 89 f7             	mov    rdi,r14
  4a45a3:	48 83 c4 08          	add    rsp,0x8
  4a45a7:	5b                   	pop    rbx
  4a45a8:	41 5c                	pop    r12
  4a45aa:	41 5d                	pop    r13
  4a45ac:	41 5e                	pop    r14
  4a45ae:	41 5f                	pop    r15
  4a45b0:	5d                   	pop    rbp
  4a45b1:	e9 ea 8c 01 00       	jmp    0x4bd2a0
  4a45b6:	8b 71 04             	mov    esi,DWORD PTR [rcx+0x4]
  4a45b9:	85 f6                	test   esi,esi
  4a45bb:	74 0d                	je     0x4a45ca
  4a45bd:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  4a45c1:	89 f2                	mov    edx,esi
  4a45c3:	0f 38 f0 48 04       	movbe  ecx,DWORD PTR [rax+0x4]
  4a45c8:	eb 00                	jmp    0x4a45ca
  4a45ca:	0f ca                	bswap  edx
  4a45cc:	85 d2                	test   edx,edx
  4a45ce:	74 1b                	je     0x4a45eb
  4a45d0:	48 89 df             	mov    rdi,rbx
  4a45d3:	be 01 00 00 00       	mov    esi,0x1
  4a45d8:	48 83 c4 08          	add    rsp,0x8
  4a45dc:	5b                   	pop    rbx
  4a45dd:	41 5c                	pop    r12
  4a45df:	41 5d                	pop    r13
  4a45e1:	41 5e                	pop    r14
  4a45e3:	41 5f                	pop    r15
  4a45e5:	5d                   	pop    rbp
  4a45e6:	e9 d5 8b 00 00       	jmp    0x4ad1c0
  4a45eb:	48 83 c4 08          	add    rsp,0x8
  4a45ef:	5b                   	pop    rbx
  4a45f0:	41 5c                	pop    r12
  4a45f2:	41 5d                	pop    r13
  4a45f4:	41 5e                	pop    r14
  4a45f6:	41 5f                	pop    r15
  4a45f8:	5d                   	pop    rbp
  4a45f9:	c3                   	ret
  4a45fa:	4c 89 f7             	mov    rdi,r14
  4a45fd:	e8 1e 8b 01 00       	call   0x4bd120
  4a4602:	eb 1c                	jmp    0x4a4620
  4a4604:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  4a460b:	00 00 00 00 00 
  4a4610:	48 c7 47 08 00 00 00 	mov    QWORD PTR [rdi+0x8],0x0
  4a4617:	00 
  4a4618:	ff 4b 50             	dec    DWORD PTR [rbx+0x50]
  4a461b:	e8 30 62 f8 ff       	call   0x42a850
  4a4620:	48 8b 7b 40          	mov    rdi,QWORD PTR [rbx+0x40]
  4a4624:	48 85 ff             	test   rdi,rdi
  4a4627:	0f 84 07 ff ff ff    	je     0x4a4534
  4a462d:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  4a4631:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
  4a4635:	48 85 c0             	test   rax,rax
  4a4638:	75 d6                	jne    0x4a4610
  4a463a:	48 c7 43 48 00 00 00 	mov    QWORD PTR [rbx+0x48],0x0
  4a4641:	00 
  4a4642:	eb cc                	jmp    0x4a4610
  4a4644:	90                   	nop
  4a4645:	90                   	nop
  4a4646:	90                   	nop
  4a4647:	90                   	nop
  4a4648:	90                   	nop
  4a4649:	90                   	nop
  4a464a:	90                   	nop
  4a464b:	90                   	nop
  4a464c:	90                   	nop
  4a464d:	90                   	nop
  4a464e:	90                   	nop
  4a464f:	90                   	nop
  4a4650:	55                   	push   rbp
  4a4651:	48 89 e5             	mov    rbp,rsp
  4a4654:	41 57                	push   r15
  4a4656:	41 56                	push   r14
  4a4658:	41 55                	push   r13
  4a465a:	41 54                	push   r12
  4a465c:	53                   	push   rbx
  4a465d:	48 83 ec 48          	sub    rsp,0x48
  4a4661:	48 8d 05 a8 7c 47 03 	lea    rax,[rip+0x3477ca8]        # 0x391c310
  4a4668:	89 55 c4             	mov    DWORD PTR [rbp-0x3c],edx
  4a466b:	4c 89 4d 90          	mov    QWORD PTR [rbp-0x70],r9
  4a466f:	89 4d c0             	mov    DWORD PTR [rbp-0x40],ecx
  4a4672:	45 31 ed             	xor    r13d,r13d
  4a4675:	41 89 f6             	mov    r14d,esi
  4a4678:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  4a467c:	ba 01 00 00 00       	mov    edx,0x1
  4a4681:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a4684:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  4a4688:	48 89 7d a0          	mov    QWORD PTR [rbp-0x60],rdi
  4a468c:	44 89 45 bc          	mov    DWORD PTR [rbp-0x44],r8d
  4a4690:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  4a4693:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  4a4697:	8b 40 78             	mov    eax,DWORD PTR [rax+0x78]
  4a469a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
  4a469d:	8b 87 80 00 00 00    	mov    eax,DWORD PTR [rdi+0x80]
  4a46a3:	48 8b 3d 76 09 05 03 	mov    rdi,QWORD PTR [rip+0x3050976]        # 0x34f5020
  4a46aa:	c7 45 c8 02 00 00 00 	mov    DWORD PTR [rbp-0x38],0x2
  4a46b1:	66 c7 45 cc 01 00    	mov    WORD PTR [rbp-0x34],0x1
  4a46b7:	a8 20                	test   al,0x20
  4a46b9:	44 89 c0             	mov    eax,r8d
  4a46bc:	41 0f 94 c5          	sete   r13b
  4a46c0:	45 01 ed             	add    r13d,r13d
  4a46c3:	4d 89 ec             	mov    r12,r13
  4a46c6:	49 81 f4 82 00 00 00 	xor    r12,0x82
  4a46cd:	49 39 c4             	cmp    r12,rax
  4a46d0:	4c 0f 43 e0          	cmovae r12,rax
  4a46d4:	e8 a7 71 f9 ff       	call   0x43b880
  4a46d9:	48 8d 1d 30 25 0c 02 	lea    rbx,[rip+0x20c2530]        # 0x2566c10
  4a46e0:	49 89 c7             	mov    r15,rax
  4a46e3:	48 8b 7b 48          	mov    rdi,QWORD PTR [rbx+0x48]
  4a46e7:	48 85 ff             	test   rdi,rdi
  4a46ea:	0f 85 cf 02 00 00    	jne    0x4a49bf
  4a46f0:	4d 85 ff             	test   r15,r15
  4a46f3:	0f 84 a7 02 00 00    	je     0x4a49a0
  4a46f9:	48 8b 4d a0          	mov    rcx,QWORD PTR [rbp-0x60]
  4a46fd:	49 83 c5 02          	add    r13,0x2
  4a4701:	49 8d 44 24 04       	lea    rax,[r12+0x4]
  4a4706:	41 01 c5             	add    r13d,eax
  4a4709:	45 89 6f 18          	mov    DWORD PTR [r15+0x18],r13d
  4a470d:	45 89 6f 30          	mov    DWORD PTR [r15+0x30],r13d
  4a4711:	49 c7 47 20 00 00 00 	mov    QWORD PTR [r15+0x20],0x0
  4a4718:	00 
  4a4719:	f6 81 80 00 00 00 20 	test   BYTE PTR [rcx+0x80],0x20
  4a4720:	75 18                	jne    0x4a473a
  4a4722:	4d 8b 6f 10          	mov    r13,QWORD PTR [r15+0x10]
  4a4726:	66 41 c7 45 00 ff 03 	mov    WORD PTR [r13+0x0],0x3ff
  4a472d:	66 45 0f 38 f1 75 02 	movbe  WORD PTR [r13+0x2],r14w
  4a4734:	49 83 c5 04          	add    r13,0x4
  4a4738:	eb 12                	jmp    0x4a474c
  4a473a:	49 8b 4f 10          	mov    rcx,QWORD PTR [r15+0x10]
  4a473e:	66 44 0f 38 f1 31    	movbe  WORD PTR [rcx],r14w
  4a4744:	4d 8b 6f 10          	mov    r13,QWORD PTR [r15+0x10]
  4a4748:	49 83 c5 02          	add    r13,0x2
  4a474c:	66 83 7d bc 00       	cmp    WORD PTR [rbp-0x44],0x0
  4a4751:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
  4a4754:	8b 5d b0             	mov    ebx,DWORD PTR [rbp-0x50]
  4a4757:	8b 4d c0             	mov    ecx,DWORD PTR [rbp-0x40]
  4a475a:	41 88 55 00          	mov    BYTE PTR [r13+0x0],dl
  4a475e:	41 88 4d 01          	mov    BYTE PTR [r13+0x1],cl
  4a4762:	66 41 0f 38 f1 45 02 	movbe  WORD PTR [r13+0x2],ax
  4a4769:	74 10                	je     0x4a477b
  4a476b:	48 8b 7d 90          	mov    rdi,QWORD PTR [rbp-0x70]
  4a476f:	49 8d 75 04          	lea    rsi,[r13+0x4]
  4a4773:	4c 89 e2             	mov    rdx,r12
  4a4776:	e8 65 54 db ff       	call   0x259be0
  4a477b:	f6 c3 04             	test   bl,0x4
  4a477e:	0f 84 53 01 00 00    	je     0x4a48d7
  4a4784:	41 0f b7 ce          	movzx  ecx,r14w
  4a4788:	81 f9 20 c0 00 00    	cmp    ecx,0xc020
  4a478e:	7e 21                	jle    0x4a47b1
  4a4790:	81 f9 21 c0 00 00    	cmp    ecx,0xc021
  4a4796:	74 32                	je     0x4a47ca
  4a4798:	81 f9 23 c0 00 00    	cmp    ecx,0xc023
  4a479e:	74 33                	je     0x4a47d3
  4a47a0:	81 f9 23 c2 00 00    	cmp    ecx,0xc223
  4a47a6:	75 3d                	jne    0x4a47e5
  4a47a8:	4c 8d 35 95 84 e7 00 	lea    r14,[rip+0xe78495]        # 0x131cc44
  4a47af:	eb 51                	jmp    0x4a4802
  4a47b1:	81 f9 21 80 00 00    	cmp    ecx,0x8021
  4a47b7:	74 23                	je     0x4a47dc
  4a47b9:	81 f9 57 80 00 00    	cmp    ecx,0x8057
  4a47bf:	75 24                	jne    0x4a47e5
  4a47c1:	4c 8d 35 81 84 e7 00 	lea    r14,[rip+0xe78481]        # 0x131cc49
  4a47c8:	eb 38                	jmp    0x4a4802
  4a47ca:	4c 8d 35 b9 c1 ec 00 	lea    r14,[rip+0xecc1b9]        # 0x137098a
  4a47d1:	eb 2f                	jmp    0x4a4802
  4a47d3:	4c 8d 35 18 a1 e1 00 	lea    r14,[rip+0xe1a118]        # 0x12be8f2
  4a47da:	eb 26                	jmp    0x4a4802
  4a47dc:	4c 8d 35 6d 03 e1 00 	lea    r14,[rip+0xe1036d]        # 0x12b4b50
  4a47e3:	eb 1d                	jmp    0x4a4802
  4a47e5:	4c 8d 35 e8 1d 09 03 	lea    r14,[rip+0x3091de8]        # 0x35365d4
  4a47ec:	48 8d 15 1d f1 ed 00 	lea    rdx,[rip+0xedf11d]        # 0x1383910
  4a47f3:	be 0c 00 00 00       	mov    esi,0xc
  4a47f8:	31 c0                	xor    eax,eax
  4a47fa:	4c 89 f7             	mov    rdi,r14
  4a47fd:	e8 3e a6 00 00       	call   0x4aee40
  4a4802:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
  4a4806:	41 0f b6 4d 00       	movzx  ecx,BYTE PTR [r13+0x0]
  4a480b:	48 8d 70 60          	lea    rsi,[rax+0x60]
  4a480f:	8d 41 ff             	lea    eax,[rcx-0x1]
  4a4812:	3c 0b                	cmp    al,0xb
  4a4814:	73 10                	jae    0x4a4826
  4a4816:	0f b6 c0             	movzx  eax,al
  4a4819:	48 8d 0d 40 b3 9d 00 	lea    rcx,[rip+0x9db340]        # 0xe7fb60
  4a4820:	48 8b 1c c1          	mov    rbx,QWORD PTR [rcx+rax*8]
  4a4824:	eb 2b                	jmp    0x4a4851
  4a4826:	48 8d 1d e3 1d 09 03 	lea    rbx,[rip+0x3091de3]        # 0x3536610
  4a482d:	4c 89 75 b0          	mov    QWORD PTR [rbp-0x50],r14
  4a4831:	49 89 f6             	mov    r14,rsi
  4a4834:	48 8d 15 d5 f0 ed 00 	lea    rdx,[rip+0xedf0d5]        # 0x1383910
  4a483b:	be 0c 00 00 00       	mov    esi,0xc
  4a4840:	31 c0                	xor    eax,eax
  4a4842:	48 89 df             	mov    rdi,rbx
  4a4845:	e8 f6 a5 00 00       	call   0x4aee40
  4a484a:	4c 89 f6             	mov    rsi,r14
  4a484d:	4c 8b 75 b0          	mov    r14,QWORD PTR [rbp-0x50]
  4a4851:	66 41 0f 38 f0 45 02 	movbe  ax,WORD PTR [r13+0x2]
  4a4858:	45 0f b6 45 01       	movzx  r8d,BYTE PTR [r13+0x1]
  4a485d:	48 8d 3d f4 8a e5 00 	lea    rdi,[rip+0xe58af4]        # 0x12fd358
  4a4864:	4c 89 f2             	mov    rdx,r14
  4a4867:	48 89 d9             	mov    rcx,rbx
  4a486a:	44 0f b7 c8          	movzx  r9d,ax
  4a486e:	31 c0                	xor    eax,eax
  4a4870:	e8 9b 8b db ff       	call   0x25d410
  4a4875:	66 83 7d bc 00       	cmp    WORD PTR [rbp-0x44],0x0
  4a487a:	74 4d                	je     0x4a48c9
  4a487c:	41 0f b6 75 04       	movzx  esi,BYTE PTR [r13+0x4]
  4a4881:	48 8d 3d b6 a7 f0 00 	lea    rdi,[rip+0xf0a7b6]        # 0x13af03e
  4a4888:	31 c0                	xor    eax,eax
  4a488a:	e8 81 8b db ff       	call   0x25d410
  4a488f:	66 41 83 fc 01       	cmp    r12w,0x1
  4a4894:	74 33                	je     0x4a48c9
  4a4896:	49 ff cc             	dec    r12
  4a4899:	48 8d 1d b0 83 e7 00 	lea    rbx,[rip+0xe783b0]        # 0x131cc50
  4a48a0:	45 31 f6             	xor    r14d,r14d
  4a48a3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  4a48aa:	84 00 00 00 00 00 
  4a48b0:	43 0f b6 74 35 05    	movzx  esi,BYTE PTR [r13+r14*1+0x5]
  4a48b6:	48 89 df             	mov    rdi,rbx
  4a48b9:	31 c0                	xor    eax,eax
  4a48bb:	e8 50 8b db ff       	call   0x25d410
  4a48c0:	49 ff c6             	inc    r14
  4a48c3:	66 45 39 f4          	cmp    r12w,r14w
  4a48c7:	75 e7                	jne    0x4a48b0
  4a48c9:	48 8d 3d ce 79 eb 00 	lea    rdi,[rip+0xeb79ce]        # 0x135c29e
  4a48d0:	31 c0                	xor    eax,eax
  4a48d2:	e8 39 8b db ff       	call   0x25d410
  4a48d7:	4c 8b 6d a0          	mov    r13,QWORD PTR [rbp-0x60]
  4a48db:	41 8b 45 50          	mov    eax,DWORD PTR [r13+0x50]
  4a48df:	41 3b 45 54          	cmp    eax,DWORD PTR [r13+0x54]
  4a48e3:	7d 2d                	jge    0x4a4912
  4a48e5:	49 8d 5d 70          	lea    rbx,[r13+0x70]
  4a48e9:	31 f6                	xor    esi,esi
  4a48eb:	31 d2                	xor    edx,edx
  4a48ed:	31 c9                	xor    ecx,ecx
  4a48ef:	48 89 df             	mov    rdi,rbx
  4a48f2:	e8 09 21 02 00       	call   0x4c6a00
  4a48f7:	49 c7 47 08 00 00 00 	mov    QWORD PTR [r15+0x8],0x0
  4a48fe:	00 
  4a48ff:	4c 8b 65 a8          	mov    r12,QWORD PTR [rbp-0x58]
  4a4903:	49 8b 45 48          	mov    rax,QWORD PTR [r13+0x48]
  4a4907:	48 85 c0             	test   rax,rax
  4a490a:	74 33                	je     0x4a493f
  4a490c:	4c 89 78 08          	mov    QWORD PTR [rax+0x8],r15
  4a4910:	eb 31                	jmp    0x4a4943
  4a4912:	48 8b 5d a8          	mov    rbx,QWORD PTR [rbp-0x58]
  4a4916:	ba 01 00 00 00       	mov    edx,0x1
  4a491b:	be 0a 00 00 00       	mov    esi,0xa
  4a4920:	48 89 df             	mov    rdi,rbx
  4a4923:	e8 d8 75 01 00       	call   0x4bbf00
  4a4928:	4c 89 ff             	mov    rdi,r15
  4a492b:	e8 20 5f f8 ff       	call   0x42a850
  4a4930:	ba 01 00 00 00       	mov    edx,0x1
  4a4935:	48 89 df             	mov    rdi,rbx
  4a4938:	be 03 00 00 00       	mov    esi,0x3
  4a493d:	eb 5c                	jmp    0x4a499b
  4a493f:	4d 89 7d 40          	mov    QWORD PTR [r13+0x40],r15
  4a4943:	4d 89 7d 48          	mov    QWORD PTR [r13+0x48],r15
  4a4947:	41 ff 45 50          	inc    DWORD PTR [r13+0x50]
  4a494b:	48 89 df             	mov    rdi,rbx
  4a494e:	31 f6                	xor    esi,esi
  4a4950:	31 d2                	xor    edx,edx
  4a4952:	31 c9                	xor    ecx,ecx
  4a4954:	e8 47 26 02 00       	call   0x4c6fa0
  4a4959:	41 f6 44 24 79 04    	test   BYTE PTR [r12+0x79],0x4
  4a495f:	75 27                	jne    0x4a4988
  4a4961:	49 8b 9c 24 98 04 00 	mov    rbx,QWORD PTR [r12+0x498]
  4a4968:	00 
  4a4969:	48 8d 05 60 09 dc ff 	lea    rax,[rip+0xffffffffffdc0960]        # 0x2652d0
  4a4970:	48 29 d8             	sub    rax,rbx
  4a4973:	48 c1 c8 03          	ror    rax,0x3
  4a4977:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a497d:	0f 87 82 00 00 00    	ja     0x4a4a05
  4a4983:	4c 89 e7             	mov    rdi,r12
  4a4986:	ff d3                	call   rbx
  4a4988:	41 8b 95 84 00 00 00 	mov    edx,DWORD PTR [r13+0x84]
  4a498f:	41 03 57 30          	add    edx,DWORD PTR [r15+0x30]
  4a4993:	4c 89 e7             	mov    rdi,r12
  4a4996:	be 06 00 00 00       	mov    esi,0x6
  4a499b:	e8 60 75 01 00       	call   0x4bbf00
  4a49a0:	48 8d 05 69 79 47 03 	lea    rax,[rip+0x3477969]        # 0x391c310
  4a49a7:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a49aa:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a49ae:	75 4e                	jne    0x4a49fe
  4a49b0:	48 83 c4 48          	add    rsp,0x48
  4a49b4:	5b                   	pop    rbx
  4a49b5:	41 5c                	pop    r12
  4a49b7:	41 5d                	pop    r13
  4a49b9:	41 5e                	pop    r14
  4a49bb:	41 5f                	pop    r15
  4a49bd:	5d                   	pop    rbp
  4a49be:	c3                   	ret
  4a49bf:	48 8d 05 62 75 5f 01 	lea    rax,[rip+0x15f7562]        # 0x1a9bf28
  4a49c6:	4c 8b 10             	mov    r10,QWORD PTR [rax]
  4a49c9:	48 8d 05 18 38 dc ff 	lea    rax,[rip+0xffffffffffdc3818]        # 0x2681e8
  4a49d0:	4c 29 d0             	sub    rax,r10
  4a49d3:	48 c1 c8 03          	ror    rax,0x3
  4a49d7:	48 83 f8 01          	cmp    rax,0x1
  4a49db:	77 3c                	ja     0x4a4a19
  4a49dd:	be 01 00 00 00       	mov    esi,0x1
  4a49e2:	ba 01 00 00 00       	mov    edx,0x1
  4a49e7:	4c 89 f9             	mov    rcx,r15
  4a49ea:	45 31 c0             	xor    r8d,r8d
  4a49ed:	45 31 c9             	xor    r9d,r9d
  4a49f0:	41 ff d2             	call   r10
  4a49f3:	4d 85 ff             	test   r15,r15
  4a49f6:	0f 85 fd fc ff ff    	jne    0x4a46f9
  4a49fc:	eb a2                	jmp    0x4a49a0
  4a49fe:	e8 ad 8c 25 00       	call   0x6fd6b0
  4a4a03:	0f 0b                	ud2
  4a4a05:	48 8d 3d 64 3b 62 01 	lea    rdi,[rip+0x1623b64]        # 0x1ac8570
  4a4a0c:	48 89 de             	mov    rsi,rbx
  4a4a0f:	e8 ac ae fa ff       	call   0x44f8c0
  4a4a14:	e9 6a ff ff ff       	jmp    0x4a4983
  4a4a19:	48 8d 3d 30 3a 62 01 	lea    rdi,[rip+0x1623a30]        # 0x1ac8450
  4a4a20:	4c 89 d6             	mov    rsi,r10
  4a4a23:	4c 89 55 98          	mov    QWORD PTR [rbp-0x68],r10
  4a4a27:	e8 94 ae fa ff       	call   0x44f8c0
  4a4a2c:	4c 8b 55 98          	mov    r10,QWORD PTR [rbp-0x68]
  4a4a30:	48 8b 7b 48          	mov    rdi,QWORD PTR [rbx+0x48]
  4a4a34:	eb a7                	jmp    0x4a49dd
  4a4a36:	90                   	nop
  4a4a37:	90                   	nop
  4a4a38:	90                   	nop
  4a4a39:	90                   	nop
  4a4a3a:	90                   	nop
  4a4a3b:	90                   	nop
  4a4a3c:	90                   	nop
  4a4a3d:	90                   	nop
  4a4a3e:	90                   	nop
  4a4a3f:	90                   	nop
  4a4a40:	55                   	push   rbp
  4a4a41:	48 89 e5             	mov    rbp,rsp
  4a4a44:	41 57                	push   r15
  4a4a46:	41 56                	push   r14
  4a4a48:	41 55                	push   r13
  4a4a4a:	41 54                	push   r12
  4a4a4c:	53                   	push   rbx
  4a4a4d:	48 83 ec 48          	sub    rsp,0x48
  4a4a51:	4c 8d 3d b8 78 47 03 	lea    r15,[rip+0x34778b8]        # 0x391c310
  4a4a58:	49 89 fa             	mov    r10,rdi
  4a4a5b:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a4a5e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  4a4a62:	48 8b 1e             	mov    rbx,QWORD PTR [rsi]
  4a4a65:	44 8b 6a 30          	mov    r13d,DWORD PTR [rdx+0x30]
  4a4a69:	41 83 fd 03          	cmp    r13d,0x3
  4a4a6d:	7f 37                	jg     0x4a4aa6
  4a4a6f:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a4a73:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a4a76:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a4a7a:	0f 85 a0 11 00 00    	jne    0x4a5c20
  4a4a80:	48 83 c3 60          	add    rbx,0x60
  4a4a84:	48 8d 3d 40 4b e2 00 	lea    rdi,[rip+0xe24b40]        # 0x12c95cb
  4a4a8b:	44 89 e9             	mov    ecx,r13d
  4a4a8e:	31 c0                	xor    eax,eax
  4a4a90:	48 89 de             	mov    rsi,rbx
  4a4a93:	48 83 c4 48          	add    rsp,0x48
  4a4a97:	5b                   	pop    rbx
  4a4a98:	41 5c                	pop    r12
  4a4a9a:	41 5d                	pop    r13
  4a4a9c:	41 5e                	pop    r14
  4a4a9e:	41 5f                	pop    r15
  4a4aa0:	5d                   	pop    rbp
  4a4aa1:	e9 6a 89 db ff       	jmp    0x25d410
  4a4aa6:	44 8b 5b 78          	mov    r11d,DWORD PTR [rbx+0x78]
  4a4aaa:	4c 8b 62 10          	mov    r12,QWORD PTR [rdx+0x10]
  4a4aae:	49 89 f6             	mov    r14,rsi
  4a4ab1:	41 f6 c3 04          	test   r11b,0x4
  4a4ab5:	0f 84 36 01 00 00    	je     0x4a4bf1
  4a4abb:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a4ac0:	4c 89 75 a8          	mov    QWORD PTR [rbp-0x58],r14
  4a4ac4:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a4acb:	00 
  4a4acc:	48 83 f8 09          	cmp    rax,0x9
  4a4ad0:	77 0d                	ja     0x4a4adf
  4a4ad2:	48 8d 0d df b0 9d 00 	lea    rcx,[rip+0x9db0df]        # 0xe7fbb8
  4a4ad9:	4c 8b 04 c1          	mov    r8,QWORD PTR [rcx+rax*8]
  4a4add:	eb 07                	jmp    0x4a4ae6
  4a4adf:	4c 8d 05 9f 59 ef 00 	lea    r8,[rip+0xef599f]        # 0x139a485
  4a4ae6:	41 0f b6 0c 24       	movzx  ecx,BYTE PTR [r12]
  4a4aeb:	4d 8b 7a 08          	mov    r15,QWORD PTR [r10+0x8]
  4a4aef:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a4af3:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a4af7:	48 89 55 98          	mov    QWORD PTR [rbp-0x68],rdx
  4a4afb:	4c 89 55 b0          	mov    QWORD PTR [rbp-0x50],r10
  4a4aff:	44 89 5d b8          	mov    DWORD PTR [rbp-0x48],r11d
  4a4b03:	8d 41 ff             	lea    eax,[rcx-0x1]
  4a4b06:	3c 0b                	cmp    al,0xb
  4a4b08:	73 10                	jae    0x4a4b1a
  4a4b0a:	0f b6 c0             	movzx  eax,al
  4a4b0d:	48 8d 0d 4c b0 9d 00 	lea    rcx,[rip+0x9db04c]        # 0xe7fb60
  4a4b14:	48 8b 1c c1          	mov    rbx,QWORD PTR [rcx+rax*8]
  4a4b18:	eb 2b                	jmp    0x4a4b45
  4a4b1a:	48 8d 1d ef 1a 09 03 	lea    rbx,[rip+0x3091aef]        # 0x3536610
  4a4b21:	48 89 75 a0          	mov    QWORD PTR [rbp-0x60],rsi
  4a4b25:	48 8d 15 e4 ed ed 00 	lea    rdx,[rip+0xedede4]        # 0x1383910
  4a4b2c:	be 0c 00 00 00       	mov    esi,0xc
  4a4b31:	31 c0                	xor    eax,eax
  4a4b33:	4d 89 c6             	mov    r14,r8
  4a4b36:	48 89 df             	mov    rdi,rbx
  4a4b39:	e8 02 a3 00 00       	call   0x4aee40
  4a4b3e:	48 8b 75 a0          	mov    rsi,QWORD PTR [rbp-0x60]
  4a4b42:	4d 89 f0             	mov    r8,r14
  4a4b45:	66 41 0f 38 f0 44 24 	movbe  ax,WORD PTR [r12+0x2]
  4a4b4c:	02 
  4a4b4d:	45 0f b6 4c 24 01    	movzx  r9d,BYTE PTR [r12+0x1]
  4a4b53:	44 0f b7 d0          	movzx  r10d,ax
  4a4b57:	48 83 ec 08          	sub    rsp,0x8
  4a4b5b:	4c 89 c1             	mov    rcx,r8
  4a4b5e:	48 8d 3d a3 ba df 00 	lea    rdi,[rip+0xdfbaa3]        # 0x12a0608
  4a4b65:	4c 89 fa             	mov    rdx,r15
  4a4b68:	49 89 d8             	mov    r8,rbx
  4a4b6b:	31 c0                	xor    eax,eax
  4a4b6d:	41 52                	push   r10
  4a4b6f:	e8 9c 88 db ff       	call   0x25d410
  4a4b74:	48 83 c4 10          	add    rsp,0x10
  4a4b78:	41 83 fd 04          	cmp    r13d,0x4
  4a4b7c:	74 4a                	je     0x4a4bc8
  4a4b7e:	41 0f b6 74 24 04    	movzx  esi,BYTE PTR [r12+0x4]
  4a4b84:	48 8d 3d b3 a4 f0 00 	lea    rdi,[rip+0xf0a4b3]        # 0x13af03e
  4a4b8b:	31 c0                	xor    eax,eax
  4a4b8d:	e8 7e 88 db ff       	call   0x25d410
  4a4b92:	66 41 83 fd 05       	cmp    r13w,0x5
  4a4b97:	74 2f                	je     0x4a4bc8
  4a4b99:	41 be 05 00 00 00    	mov    r14d,0x5
  4a4b9f:	48 8d 1d aa 80 e7 00 	lea    rbx,[rip+0xe780aa]        # 0x131cc50
  4a4ba6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4a4bad:	00 00 00 
  4a4bb0:	43 0f b6 34 34       	movzx  esi,BYTE PTR [r12+r14*1]
  4a4bb5:	48 89 df             	mov    rdi,rbx
  4a4bb8:	31 c0                	xor    eax,eax
  4a4bba:	e8 51 88 db ff       	call   0x25d410
  4a4bbf:	49 ff c6             	inc    r14
  4a4bc2:	66 45 39 f5          	cmp    r13w,r14w
  4a4bc6:	75 e8                	jne    0x4a4bb0
  4a4bc8:	48 8d 3d cf 76 eb 00 	lea    rdi,[rip+0xeb76cf]        # 0x135c29e
  4a4bcf:	31 c0                	xor    eax,eax
  4a4bd1:	e8 3a 88 db ff       	call   0x25d410
  4a4bd6:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
  4a4bda:	4c 8d 3d 2f 77 47 03 	lea    r15,[rip+0x347772f]        # 0x391c310
  4a4be1:	4c 8b 75 a8          	mov    r14,QWORD PTR [rbp-0x58]
  4a4be5:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  4a4be9:	4c 8b 55 b0          	mov    r10,QWORD PTR [rbp-0x50]
  4a4bed:	44 8b 5d b8          	mov    r11d,DWORD PTR [rbp-0x48]
  4a4bf1:	66 41 0f 38 f0 4c 24 	movbe  cx,WORD PTR [r12+0x2]
  4a4bf8:	02 
  4a4bf9:	48 89 d0             	mov    rax,rdx
  4a4bfc:	0f b7 d1             	movzx  edx,cx
  4a4bff:	41 0f b6 0c 24       	movzx  ecx,BYTE PTR [r12]
  4a4c04:	41 39 d5             	cmp    r13d,edx
  4a4c07:	41 0f 42 d5          	cmovb  edx,r13d
  4a4c0b:	8d 71 ff             	lea    esi,[rcx-0x1]
  4a4c0e:	83 fe 0a             	cmp    esi,0xa
  4a4c11:	0f 87 3a 03 00 00    	ja     0x4a4f51
  4a4c17:	48 8d 3d 12 f4 0e 01 	lea    rdi,[rip+0x10ef412]        # 0x1594030
  4a4c1e:	4d 8d 6c 24 04       	lea    r13,[r12+0x4]
  4a4c23:	48 63 34 b7          	movsxd rsi,DWORD PTR [rdi+rsi*4]
  4a4c27:	48 01 fe             	add    rsi,rdi
  4a4c2a:	ff e6                	jmp    rsi
  4a4c2c:	41 0f b6 72 02       	movzx  esi,BYTE PTR [r10+0x2]
  4a4c31:	41 0f b6 44 24 01    	movzx  eax,BYTE PTR [r12+0x1]
  4a4c37:	45 0f b6 84 36 40 01 	movzx  r8d,BYTE PTR [r14+rsi*1+0x140]
  4a4c3e:	00 00 
  4a4c40:	44 38 c0             	cmp    al,r8b
  4a4c43:	0f 85 53 01 00 00    	jne    0x4a4d9c
  4a4c49:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a4c4d:	83 f9 03             	cmp    ecx,0x3
  4a4c50:	0f 85 70 03 00 00    	jne    0x4a4fc6
  4a4c56:	49 8b 5a 48          	mov    rbx,QWORD PTR [r10+0x48]
  4a4c5a:	48 8d 05 77 35 dc ff 	lea    rax,[rip+0xffffffffffdc3577]        # 0x2681d8
  4a4c61:	4d 89 d5             	mov    r13,r10
  4a4c64:	48 29 d8             	sub    rax,rbx
  4a4c67:	48 c1 c8 03          	ror    rax,0x3
  4a4c6b:	48 83 f8 13          	cmp    rax,0x13
  4a4c6f:	0f 86 70 03 00 00    	jbe    0x4a4fe5
  4a4c75:	48 8d 3d 14 3a 62 01 	lea    rdi,[rip+0x1623a14]        # 0x1ac8690
  4a4c7c:	48 89 de             	mov    rsi,rbx
  4a4c7f:	4c 89 75 a8          	mov    QWORD PTR [rbp-0x58],r14
  4a4c83:	41 89 d6             	mov    r14d,edx
  4a4c86:	e8 35 ac fa ff       	call   0x44f8c0
  4a4c8b:	e9 ad 0f 00 00       	jmp    0x4a5c3d
  4a4c90:	41 0f b7 0a          	movzx  ecx,WORD PTR [r10]
  4a4c94:	81 f9 20 c0 00 00    	cmp    ecx,0xc020
  4a4c9a:	0f 8e 31 04 00 00    	jle    0x4a50d1
  4a4ca0:	81 f9 21 c0 00 00    	cmp    ecx,0xc021
  4a4ca6:	0f 84 81 04 00 00    	je     0x4a512d
  4a4cac:	81 f9 23 c0 00 00    	cmp    ecx,0xc023
  4a4cb2:	0f 84 7e 04 00 00    	je     0x4a5136
  4a4cb8:	81 f9 23 c2 00 00    	cmp    ecx,0xc223
  4a4cbe:	0f 85 84 04 00 00    	jne    0x4a5148
  4a4cc4:	48 8d 0d 79 7f e7 00 	lea    rcx,[rip+0xe77f79]        # 0x131cc44
  4a4ccb:	e9 ad 04 00 00       	jmp    0x4a517d
  4a4cd0:	66 41 81 3a 21 c0    	cmp    WORD PTR [r10],0xc021
  4a4cd6:	0f 85 75 02 00 00    	jne    0x4a4f51
  4a4cdc:	41 0f b6 44 24 01    	movzx  eax,BYTE PTR [r12+0x1]
  4a4ce2:	41 3a 86 38 03 00 00 	cmp    al,BYTE PTR [r14+0x338]
  4a4ce9:	0f 85 b5 03 00 00    	jne    0x4a50a4
  4a4cef:	83 fa 07             	cmp    edx,0x7
  4a4cf2:	0f 87 b0 05 00 00    	ja     0x4a52a8
  4a4cf8:	41 f6 c3 04          	test   r11b,0x4
  4a4cfc:	0f 84 63 0b 00 00    	je     0x4a5865
  4a4d02:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a4d05:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a4d09:	0f 85 11 0f 00 00    	jne    0x4a5c20
  4a4d0f:	48 83 c3 60          	add    rbx,0x60
  4a4d13:	48 8d 3d ad 57 ef 00 	lea    rdi,[rip+0xef57ad]        # 0x139a4c7
  4a4d1a:	e9 1a 02 00 00       	jmp    0x4a4f39
  4a4d1f:	83 fa 03             	cmp    edx,0x3
  4a4d22:	0f 87 35 03 00 00    	ja     0x4a505d
  4a4d28:	41 f6 c3 04          	test   r11b,0x4
  4a4d2c:	0f 84 72 03 00 00    	je     0x4a50a4
  4a4d32:	49 8b 42 08          	mov    rax,QWORD PTR [r10+0x8]
  4a4d36:	89 d1                	mov    ecx,edx
  4a4d38:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a4d3c:	48 8d 3d 16 6a de 00 	lea    rdi,[rip+0xde6a16]        # 0x128b759
  4a4d43:	48 89 c2             	mov    rdx,rax
  4a4d46:	31 c0                	xor    eax,eax
  4a4d48:	e8 c3 86 db ff       	call   0x25d410
  4a4d4d:	e9 52 03 00 00       	jmp    0x4a50a4
  4a4d52:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a4d57:	41 0f b6 4c 24 01    	movzx  ecx,BYTE PTR [r12+0x1]
  4a4d5d:	45 0f b6 84 06 40 01 	movzx  r8d,BYTE PTR [r14+rax*1+0x140]
  4a4d64:	00 00 
  4a4d66:	44 38 c1             	cmp    cl,r8b
  4a4d69:	0f 85 19 03 00 00    	jne    0x4a5088
  4a4d6f:	41 8b bc 86 2c 01 00 	mov    edi,DWORD PTR [r14+rax*4+0x12c]
  4a4d76:	00 
  4a4d77:	8d 57 fe             	lea    edx,[rdi-0x2]
  4a4d7a:	83 fa 07             	cmp    edx,0x7
  4a4d7d:	0f 87 aa 0c 00 00    	ja     0x4a5a2d
  4a4d83:	48 8d 35 12 f3 0e 01 	lea    rsi,[rip+0x10ef312]        # 0x159409c
  4a4d8a:	48 63 14 96          	movsxd rdx,DWORD PTR [rsi+rdx*4]
  4a4d8e:	48 01 f2             	add    rdx,rsi
  4a4d91:	ff e2                	jmp    rdx
  4a4d93:	41 0f b7 32          	movzx  esi,WORD PTR [r10]
  4a4d97:	e9 de 04 00 00       	jmp    0x4a527a
  4a4d9c:	41 f6 c3 04          	test   r11b,0x4
  4a4da0:	0f 84 fe 02 00 00    	je     0x4a50a4
  4a4da6:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a4daa:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a4dae:	48 8d 3d f3 54 e0 00 	lea    rdi,[rip+0xe054f3]        # 0x12aa2a8
  4a4db5:	89 c1                	mov    ecx,eax
  4a4db7:	e9 e1 02 00 00       	jmp    0x4a509d
  4a4dbc:	83 fa 06             	cmp    edx,0x6
  4a4dbf:	0f 82 a0 0a 00 00    	jb     0x4a5865
  4a4dc5:	66 41 0f 38 f0 44 24 	movbe  ax,WORD PTR [r12+0x4]
  4a4dcc:	04 
  4a4dcd:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a4dd1:	44 0f b7 c8          	movzx  r9d,ax
  4a4dd5:	41 81 f9 20 c0 00 00 	cmp    r9d,0xc020
  4a4ddc:	0f 8e 25 03 00 00    	jle    0x4a5107
  4a4de2:	41 81 f9 21 c0 00 00 	cmp    r9d,0xc021
  4a4de9:	0f 84 99 08 00 00    	je     0x4a5688
  4a4def:	41 81 f9 23 c0 00 00 	cmp    r9d,0xc023
  4a4df6:	0f 84 95 08 00 00    	je     0x4a5691
  4a4dfc:	41 81 f9 23 c2 00 00 	cmp    r9d,0xc223
  4a4e03:	0f 85 4c 09 00 00    	jne    0x4a5755
  4a4e09:	48 8d 1d 08 ac 9d 00 	lea    rbx,[rip+0x9dac08]        # 0xe7fa18
  4a4e10:	e9 8c 08 00 00       	jmp    0x4a56a1
  4a4e15:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a4e1a:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a4e21:	00 
  4a4e22:	8d 48 fe             	lea    ecx,[rax-0x2]
  4a4e25:	83 f9 07             	cmp    ecx,0x7
  4a4e28:	0f 87 39 08 00 00    	ja     0x4a5667
  4a4e2e:	48 8d 05 27 f2 0e 01 	lea    rax,[rip+0x10ef227]        # 0x159405c
  4a4e35:	48 63 0c 88          	movsxd rcx,DWORD PTR [rax+rcx*4]
  4a4e39:	48 01 c1             	add    rcx,rax
  4a4e3c:	ff e1                	jmp    rcx
  4a4e3e:	49 8b 5a 68          	mov    rbx,QWORD PTR [r10+0x68]
  4a4e42:	48 8d 05 87 04 dc ff 	lea    rax,[rip+0xffffffffffdc0487]        # 0x2652d0
  4a4e49:	4d 89 d4             	mov    r12,r10
  4a4e4c:	48 29 d8             	sub    rax,rbx
  4a4e4f:	48 c1 c8 03          	ror    rax,0x3
  4a4e53:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a4e59:	0f 87 0c 0e 00 00    	ja     0x4a5c6b
  4a4e5f:	4c 89 f7             	mov    rdi,r14
  4a4e62:	ff d3                	call   rbx
  4a4e64:	41 0f b6 44 24 02    	movzx  eax,BYTE PTR [r12+0x2]
  4a4e6a:	41 c7 84 86 2c 01 00 	mov    DWORD PTR [r14+rax*4+0x12c],0x2
  4a4e71:	00 02 00 00 00 
  4a4e76:	e9 8c 07 00 00       	jmp    0x4a5607
  4a4e7b:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a4e7f:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a4e83:	48 8d 3d a9 9a e1 00 	lea    rdi,[rip+0xe19aa9]        # 0x12be933
  4a4e8a:	48 8d 0d af 5d ed 00 	lea    rcx,[rip+0xed5daf]        # 0x137ac40
  4a4e91:	31 c0                	xor    eax,eax
  4a4e93:	4d 89 d5             	mov    r13,r10
  4a4e96:	48 89 75 b8          	mov    QWORD PTR [rbp-0x48],rsi
  4a4e9a:	e8 71 85 db ff       	call   0x25d410
  4a4e9f:	41 0f b6 45 02       	movzx  eax,BYTE PTR [r13+0x2]
  4a4ea4:	4c 89 ea             	mov    rdx,r13
  4a4ea7:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a4eae:	00 
  4a4eaf:	83 f8 09             	cmp    eax,0x9
  4a4eb2:	0f 87 2b 06 00 00    	ja     0x4a54e3
  4a4eb8:	b9 7c 03 00 00       	mov    ecx,0x37c
  4a4ebd:	0f a3 c1             	bt     ecx,eax
  4a4ec0:	0f 82 9f 09 00 00    	jb     0x4a5865
  4a4ec6:	83 f8 07             	cmp    eax,0x7
  4a4ec9:	0f 85 14 06 00 00    	jne    0x4a54e3
  4a4ecf:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a4ed2:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a4ed6:	0f 85 44 0d 00 00    	jne    0x4a5c20
  4a4edc:	48 89 d7             	mov    rdi,rdx
  4a4edf:	e9 55 0a 00 00       	jmp    0x4a5939
  4a4ee4:	66 41 81 3a 21 c0    	cmp    WORD PTR [r10],0xc021
  4a4eea:	0f 84 75 09 00 00    	je     0x4a5865
  4a4ef0:	eb 5f                	jmp    0x4a4f51
  4a4ef2:	66 41 81 3a 21 c0    	cmp    WORD PTR [r10],0xc021
  4a4ef8:	75 57                	jne    0x4a4f51
  4a4efa:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a4eff:	41 83 bc 86 2c 01 00 	cmp    DWORD PTR [r14+rax*4+0x12c],0x9
  4a4f06:	00 09 
  4a4f08:	0f 85 df 01 00 00    	jne    0x4a50ed
  4a4f0e:	83 fa 07             	cmp    edx,0x7
  4a4f11:	0f 87 9e 04 00 00    	ja     0x4a53b5
  4a4f17:	41 f6 c3 04          	test   r11b,0x4
  4a4f1b:	0f 84 44 09 00 00    	je     0x4a5865
  4a4f21:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a4f24:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a4f28:	0f 85 f2 0c 00 00    	jne    0x4a5c20
  4a4f2e:	48 83 c3 60          	add    rbx,0x60
  4a4f32:	48 8d 3d 13 c5 ea 00 	lea    rdi,[rip+0xeac513]        # 0x135144c
  4a4f39:	48 89 de             	mov    rsi,rbx
  4a4f3c:	31 c0                	xor    eax,eax
  4a4f3e:	48 83 c4 48          	add    rsp,0x48
  4a4f42:	5b                   	pop    rbx
  4a4f43:	41 5c                	pop    r12
  4a4f45:	41 5d                	pop    r13
  4a4f47:	41 5e                	pop    r14
  4a4f49:	41 5f                	pop    r15
  4a4f4b:	5d                   	pop    rbp
  4a4f4c:	e9 bf 84 db ff       	jmp    0x25d410
  4a4f51:	41 f6 c3 04          	test   r11b,0x4
  4a4f55:	74 36                	je     0x4a4f8d
  4a4f57:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a4f5b:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a4f5f:	48 8d 3d 1c c5 ea 00 	lea    rdi,[rip+0xeac51c]        # 0x1351482
  4a4f66:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a4f6a:	48 89 c3             	mov    rbx,rax
  4a4f6d:	4d 89 f5             	mov    r13,r14
  4a4f70:	4d 89 fe             	mov    r14,r15
  4a4f73:	31 c0                	xor    eax,eax
  4a4f75:	4d 89 d7             	mov    r15,r10
  4a4f78:	e8 93 84 db ff       	call   0x25d410
  4a4f7d:	48 89 d8             	mov    rax,rbx
  4a4f80:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  4a4f84:	4d 89 fa             	mov    r10,r15
  4a4f87:	4d 89 f7             	mov    r15,r14
  4a4f8a:	4d 89 ee             	mov    r14,r13
  4a4f8d:	41 0f b6 4a 02       	movzx  ecx,BYTE PTR [r10+0x2]
  4a4f92:	41 0f b7 32          	movzx  esi,WORD PTR [r10]
  4a4f96:	4c 89 f7             	mov    rdi,r14
  4a4f99:	4d 89 e1             	mov    r9,r12
  4a4f9c:	49 8b 94 ce 98 00 00 	mov    rdx,QWORD PTR [r14+rcx*8+0x98]
  4a4fa3:	00 
  4a4fa4:	48 ff c2             	inc    rdx
  4a4fa7:	49 89 94 ce 98 00 00 	mov    QWORD PTR [r14+rcx*8+0x98],rdx
  4a4fae:	00 
  4a4faf:	0f b6 ca             	movzx  ecx,dl
  4a4fb2:	ba 07 00 00 00       	mov    edx,0x7
  4a4fb7:	44 0f b7 40 30       	movzx  r8d,WORD PTR [rax+0x30]
  4a4fbc:	e8 8f f6 ff ff       	call   0x4a4650
  4a4fc1:	e9 de 00 00 00       	jmp    0x4a50a4
  4a4fc6:	49 8b 5a 40          	mov    rbx,QWORD PTR [r10+0x40]
  4a4fca:	48 8d 05 07 32 dc ff 	lea    rax,[rip+0xffffffffffdc3207]        # 0x2681d8
  4a4fd1:	4d 89 d5             	mov    r13,r10
  4a4fd4:	48 29 d8             	sub    rax,rbx
  4a4fd7:	48 c1 c8 03          	ror    rax,0x3
  4a4fdb:	48 83 f8 13          	cmp    rax,0x13
  4a4fdf:	0f 87 42 0c 00 00    	ja     0x4a5c27
  4a4fe5:	4c 89 f7             	mov    rdi,r14
  4a4fe8:	4c 89 e6             	mov    rsi,r12
  4a4feb:	ff d3                	call   rbx
  4a4fed:	41 0f b6 45 02       	movzx  eax,BYTE PTR [r13+0x2]
  4a4ff2:	4d 89 e8             	mov    r8,r13
  4a4ff5:	41 8b 8c 86 2c 01 00 	mov    ecx,DWORD PTR [r14+rax*4+0x12c]
  4a4ffc:	00 
  4a4ffd:	83 c1 fe             	add    ecx,0xfffffffe
  4a5000:	83 f9 07             	cmp    ecx,0x7
  4a5003:	0f 87 7f 05 00 00    	ja     0x4a5588
  4a5009:	48 8d 15 6c f0 0e 01 	lea    rdx,[rip+0x10ef06c]        # 0x159407c
  4a5010:	48 63 0c 8a          	movsxd rcx,DWORD PTR [rdx+rcx*4]
  4a5014:	48 01 d1             	add    rcx,rdx
  4a5017:	ff e1                	jmp    rcx
  4a5019:	41 8b 8e 44 03 00 00 	mov    ecx,DWORD PTR [r14+0x344]
  4a5020:	41 89 8c 86 48 01 00 	mov    DWORD PTR [r14+rax*4+0x148],ecx
  4a5027:	00 
  4a5028:	48 8d 05 a1 02 dc ff 	lea    rax,[rip+0xffffffffffdc02a1]        # 0x2652d0
  4a502f:	49 8b 48 70          	mov    rcx,QWORD PTR [r8+0x70]
  4a5033:	48 29 c8             	sub    rax,rcx
  4a5036:	48 c1 c8 03          	ror    rax,0x3
  4a503a:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5040:	0f 86 c7 09 00 00    	jbe    0x4a5a0d
  4a5046:	48 8d 3d 83 36 62 01 	lea    rdi,[rip+0x1623683]        # 0x1ac86d0
  4a504d:	48 89 ce             	mov    rsi,rcx
  4a5050:	48 89 cb             	mov    rbx,rcx
  4a5053:	e8 68 a8 fa ff       	call   0x44f8c0
  4a5058:	e9 c0 0c 00 00       	jmp    0x4a5d1d
  4a505d:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a5062:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a5069:	00 
  4a506a:	8d 48 fc             	lea    ecx,[rax-0x4]
  4a506d:	83 f9 02             	cmp    ecx,0x2
  4a5070:	0f 82 ef 07 00 00    	jb     0x4a5865
  4a5076:	83 f8 02             	cmp    eax,0x2
  4a5079:	0f 85 77 02 00 00    	jne    0x4a52f6
  4a507f:	41 0f b7 32          	movzx  esi,WORD PTR [r10]
  4a5083:	e9 ec 01 00 00       	jmp    0x4a5274
  4a5088:	41 f6 c3 04          	test   r11b,0x4
  4a508c:	74 16                	je     0x4a50a4
  4a508e:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a5092:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a5096:	48 8d 3d 0b 52 e0 00 	lea    rdi,[rip+0xe0520b]        # 0x12aa2a8
  4a509d:	31 c0                	xor    eax,eax
  4a509f:	e8 6c 83 db ff       	call   0x25d410
  4a50a4:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a50a7:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a50ab:	0f 85 6f 0b 00 00    	jne    0x4a5c20
  4a50b1:	ba 01 00 00 00       	mov    edx,0x1
  4a50b6:	48 89 df             	mov    rdi,rbx
  4a50b9:	be 01 00 00 00       	mov    esi,0x1
  4a50be:	48 83 c4 48          	add    rsp,0x48
  4a50c2:	5b                   	pop    rbx
  4a50c3:	41 5c                	pop    r12
  4a50c5:	41 5d                	pop    r13
  4a50c7:	41 5e                	pop    r14
  4a50c9:	41 5f                	pop    r15
  4a50cb:	5d                   	pop    rbp
  4a50cc:	e9 2f 6e 01 00       	jmp    0x4bbf00
  4a50d1:	81 f9 21 80 00 00    	cmp    ecx,0x8021
  4a50d7:	74 66                	je     0x4a513f
  4a50d9:	81 f9 57 80 00 00    	cmp    ecx,0x8057
  4a50df:	75 67                	jne    0x4a5148
  4a50e1:	48 8d 0d 61 7b e7 00 	lea    rcx,[rip+0xe77b61]        # 0x131cc49
  4a50e8:	e9 90 00 00 00       	jmp    0x4a517d
  4a50ed:	41 f6 c3 04          	test   r11b,0x4
  4a50f1:	74 b1                	je     0x4a50a4
  4a50f3:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a50f7:	48 8d 3d 69 17 ec 00 	lea    rdi,[rip+0xec1769]        # 0x1366867
  4a50fe:	31 c0                	xor    eax,eax
  4a5100:	e8 0b 83 db ff       	call   0x25d410
  4a5105:	eb 9d                	jmp    0x4a50a4
  4a5107:	41 81 f9 21 80 00 00 	cmp    r9d,0x8021
  4a510e:	0f 84 86 05 00 00    	je     0x4a569a
  4a5114:	41 81 f9 57 80 00 00 	cmp    r9d,0x8057
  4a511b:	0f 85 34 06 00 00    	jne    0x4a5755
  4a5121:	48 8d 1d 00 a8 9d 00 	lea    rbx,[rip+0x9da800]        # 0xe7f928
  4a5128:	e9 74 05 00 00       	jmp    0x4a56a1
  4a512d:	48 8d 0d 56 b8 ec 00 	lea    rcx,[rip+0xecb856]        # 0x137098a
  4a5134:	eb 47                	jmp    0x4a517d
  4a5136:	48 8d 0d b5 97 e1 00 	lea    rcx,[rip+0xe197b5]        # 0x12be8f2
  4a513d:	eb 3e                	jmp    0x4a517d
  4a513f:	48 8d 0d 0a fa e0 00 	lea    rcx,[rip+0xe0fa0a]        # 0x12b4b50
  4a5146:	eb 35                	jmp    0x4a517d
  4a5148:	48 8d 3d 85 14 09 03 	lea    rdi,[rip+0x3091485]        # 0x35365d4
  4a514f:	48 8d 15 ba e7 ed 00 	lea    rdx,[rip+0xede7ba]        # 0x1383910
  4a5156:	be 0c 00 00 00       	mov    esi,0xc
  4a515b:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a515f:	31 c0                	xor    eax,eax
  4a5161:	4c 89 d3             	mov    rbx,r10
  4a5164:	45 89 dd             	mov    r13d,r11d
  4a5167:	e8 d4 9c 00 00       	call   0x4aee40
  4a516c:	49 89 da             	mov    r10,rbx
  4a516f:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  4a5173:	45 89 eb             	mov    r11d,r13d
  4a5176:	48 8d 0d 57 14 09 03 	lea    rcx,[rip+0x3091457]        # 0x35365d4
  4a517d:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a5182:	4d 89 d5             	mov    r13,r10
  4a5185:	44 89 5d b8          	mov    DWORD PTR [rbp-0x48],r11d
  4a5189:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a5190:	00 
  4a5191:	48 83 f8 09          	cmp    rax,0x9
  4a5195:	77 0d                	ja     0x4a51a4
  4a5197:	48 8d 15 1a aa 9d 00 	lea    rdx,[rip+0x9daa1a]        # 0xe7fbb8
  4a519e:	4c 8b 04 c2          	mov    r8,QWORD PTR [rdx+rax*8]
  4a51a2:	eb 07                	jmp    0x4a51ab
  4a51a4:	4c 8d 05 da 52 ef 00 	lea    r8,[rip+0xef52da]        # 0x139a485
  4a51ab:	48 8d 3d 7b b4 df 00 	lea    rdi,[rip+0xdfb47b]        # 0x12a062d
  4a51b2:	48 8d 35 e5 f1 e2 00 	lea    rsi,[rip+0xe2f1e5]        # 0x12d439e
  4a51b9:	ba 5a 08 00 00       	mov    edx,0x85a
  4a51be:	31 c0                	xor    eax,eax
  4a51c0:	e8 4b 82 db ff       	call   0x25d410
  4a51c5:	41 0f b6 45 02       	movzx  eax,BYTE PTR [r13+0x2]
  4a51ca:	4d 89 e8             	mov    r8,r13
  4a51cd:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a51d4:	00 
  4a51d5:	8d 48 fe             	lea    ecx,[rax-0x2]
  4a51d8:	83 f9 05             	cmp    ecx,0x5
  4a51db:	72 6e                	jb     0x4a524b
  4a51dd:	ba 06 00 00 00       	mov    edx,0x6
  4a51e2:	8d 48 f9             	lea    ecx,[rax-0x7]
  4a51e5:	83 f9 02             	cmp    ecx,0x2
  4a51e8:	72 50                	jb     0x4a523a
  4a51ea:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a51ee:	83 f8 09             	cmp    eax,0x9
  4a51f1:	0f 85 3c 02 00 00    	jne    0x4a5433
  4a51f7:	49 8b 58 58          	mov    rbx,QWORD PTR [r8+0x58]
  4a51fb:	48 8d 05 ce 00 dc ff 	lea    rax,[rip+0xffffffffffdc00ce]        # 0x2652d0
  4a5202:	4d 89 c5             	mov    r13,r8
  4a5205:	48 29 d8             	sub    rax,rbx
  4a5208:	48 c1 c8 03          	ror    rax,0x3
  4a520c:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5212:	0f 87 67 0a 00 00    	ja     0x4a5c7f
  4a5218:	4c 89 f7             	mov    rdi,r14
  4a521b:	ff d3                	call   rbx
  4a521d:	41 0f b6 45 02       	movzx  eax,BYTE PTR [r13+0x2]
  4a5222:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  4a5226:	ba 05 00 00 00       	mov    edx,0x5
  4a522b:	4d 89 e8             	mov    r8,r13
  4a522e:	41 c7 84 86 48 01 00 	mov    DWORD PTR [r14+rax*4+0x148],0x0
  4a5235:	00 00 00 00 00 
  4a523a:	4c 89 c7             	mov    rdi,r8
  4a523d:	4c 89 f6             	mov    rsi,r14
  4a5240:	4d 89 c5             	mov    r13,r8
  4a5243:	e8 28 52 00 00       	call   0x4aa470
  4a5248:	4d 89 e8             	mov    r8,r13
  4a524b:	f6 45 b8 04          	test   BYTE PTR [rbp-0x48],0x4
  4a524f:	74 1f                	je     0x4a5270
  4a5251:	49 8b 50 08          	mov    rdx,QWORD PTR [r8+0x8]
  4a5255:	48 83 c3 60          	add    rbx,0x60
  4a5259:	48 8d 3d b8 96 e1 00 	lea    rdi,[rip+0xe196b8]        # 0x12be918
  4a5260:	31 c0                	xor    eax,eax
  4a5262:	48 89 de             	mov    rsi,rbx
  4a5265:	4c 89 c3             	mov    rbx,r8
  4a5268:	e8 a3 81 db ff       	call   0x25d410
  4a526d:	49 89 d8             	mov    r8,rbx
  4a5270:	41 0f b7 30          	movzx  esi,WORD PTR [r8]
  4a5274:	41 0f b6 4c 24 01    	movzx  ecx,BYTE PTR [r12+0x1]
  4a527a:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a527d:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5281:	0f 85 99 09 00 00    	jne    0x4a5c20
  4a5287:	4c 89 f7             	mov    rdi,r14
  4a528a:	ba 06 00 00 00       	mov    edx,0x6
  4a528f:	45 31 c0             	xor    r8d,r8d
  4a5292:	45 31 c9             	xor    r9d,r9d
  4a5295:	48 83 c4 48          	add    rsp,0x48
  4a5299:	5b                   	pop    rbx
  4a529a:	41 5c                	pop    r12
  4a529c:	41 5d                	pop    r13
  4a529e:	41 5e                	pop    r14
  4a52a0:	41 5f                	pop    r15
  4a52a2:	5d                   	pop    rbp
  4a52a3:	e9 a8 f3 ff ff       	jmp    0x4a4650
  4a52a8:	41 f6 c3 04          	test   r11b,0x4
  4a52ac:	74 15                	je     0x4a52c3
  4a52ae:	48 83 c3 60          	add    rbx,0x60
  4a52b2:	48 8d 3d e9 24 e8 00 	lea    rdi,[rip+0xe824e9]        # 0x13277a2
  4a52b9:	31 c0                	xor    eax,eax
  4a52bb:	48 89 de             	mov    rsi,rbx
  4a52be:	e8 4d 81 db ff       	call   0x25d410
  4a52c3:	48 8d 7d cc          	lea    rdi,[rbp-0x34]
  4a52c7:	ba 04 00 00 00       	mov    edx,0x4
  4a52cc:	4c 89 ee             	mov    rsi,r13
  4a52cf:	e8 dc 3d db ff       	call   0x2590b0
  4a52d4:	0f 38 f0 45 cc       	movbe  eax,DWORD PTR [rbp-0x34]
  4a52d9:	49 39 86 18 03 00 00 	cmp    QWORD PTR [r14+0x318],rax
  4a52e0:	0f 84 7f 05 00 00    	je     0x4a5865
  4a52e6:	41 c7 86 88 00 00 00 	mov    DWORD PTR [r14+0x88],0x0
  4a52ed:	00 00 00 00 
  4a52f1:	e9 6f 05 00 00       	jmp    0x4a5865
  4a52f6:	44 89 5d b8          	mov    DWORD PTR [rbp-0x48],r11d
  4a52fa:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a52fe:	49 8b 5a 38          	mov    rbx,QWORD PTR [r10+0x38]
  4a5302:	48 8d 05 47 62 dc ff 	lea    rax,[rip+0xffffffffffdc6247]        # 0x26b550
  4a5309:	4d 89 d5             	mov    r13,r10
  4a530c:	48 29 d8             	sub    rax,rbx
  4a530f:	48 c1 c8 03          	ror    rax,0x3
  4a5313:	48 3d a4 00 00 00    	cmp    rax,0xa4
  4a5319:	0f 87 2a 09 00 00    	ja     0x4a5c49
  4a531f:	4c 89 f7             	mov    rdi,r14
  4a5322:	4c 89 e6             	mov    rsi,r12
  4a5325:	ff d3                	call   rbx
  4a5327:	41 0f b6 4d 02       	movzx  ecx,BYTE PTR [r13+0x2]
  4a532c:	4c 89 ef             	mov    rdi,r13
  4a532f:	41 8b 94 8e 2c 01 00 	mov    edx,DWORD PTR [r14+rcx*4+0x12c]
  4a5336:	00 
  4a5337:	83 c2 fd             	add    edx,0xfffffffd
  4a533a:	83 fa 06             	cmp    edx,0x6
  4a533d:	0f 87 82 07 00 00    	ja     0x4a5ac5
  4a5343:	48 8d 35 72 ed 0e 01 	lea    rsi,[rip+0x10eed72]        # 0x15940bc
  4a534a:	48 63 14 96          	movsxd rdx,DWORD PTR [rsi+rdx*4]
  4a534e:	48 01 f2             	add    rdx,rsi
  4a5351:	ff e2                	jmp    rdx
  4a5353:	4d 89 f4             	mov    r12,r14
  4a5356:	41 89 c6             	mov    r14d,eax
  4a5359:	49 89 fd             	mov    r13,rdi
  4a535c:	41 8b 84 24 44 03 00 	mov    eax,DWORD PTR [r12+0x344]
  4a5363:	00 
  4a5364:	41 89 84 8c 48 01 00 	mov    DWORD PTR [r12+rcx*4+0x148],eax
  4a536b:	00 
  4a536c:	48 8d 05 5d ff db ff 	lea    rax,[rip+0xffffffffffdbff5d]        # 0x2652d0
  4a5373:	48 8b 5f 70          	mov    rbx,QWORD PTR [rdi+0x70]
  4a5377:	48 29 d8             	sub    rax,rbx
  4a537a:	48 c1 c8 03          	ror    rax,0x3
  4a537e:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5384:	0f 87 9b 09 00 00    	ja     0x4a5d25
  4a538a:	4c 89 e7             	mov    rdi,r12
  4a538d:	ff d3                	call   rbx
  4a538f:	31 c0                	xor    eax,eax
  4a5391:	45 85 f6             	test   r14d,r14d
  4a5394:	49 8b 17             	mov    rdx,QWORD PTR [r15]
  4a5397:	0f 95 c1             	setne  cl
  4a539a:	48 3b 55 d0          	cmp    rdx,QWORD PTR [rbp-0x30]
  4a539e:	0f 85 7c 08 00 00    	jne    0x4a5c20
  4a53a4:	88 c8                	mov    al,cl
  4a53a6:	4c 89 ef             	mov    rdi,r13
  4a53a9:	4c 89 e6             	mov    rsi,r12
  4a53ac:	8d 54 00 06          	lea    edx,[rax+rax*1+0x6]
  4a53b0:	e9 8c 05 00 00       	jmp    0x4a5941
  4a53b5:	44 89 5d b8          	mov    DWORD PTR [rbp-0x48],r11d
  4a53b9:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
  4a53bc:	48 8d 7d cc          	lea    rdi,[rbp-0x34]
  4a53c0:	ba 04 00 00 00       	mov    edx,0x4
  4a53c5:	4c 89 ee             	mov    rsi,r13
  4a53c8:	e8 e3 3c db ff       	call   0x2590b0
  4a53cd:	0f 38 f0 4d cc       	movbe  ecx,DWORD PTR [rbp-0x34]
  4a53d2:	49 8b 86 18 03 00 00 	mov    rax,QWORD PTR [r14+0x318]
  4a53d9:	48 39 c8             	cmp    rax,rcx
  4a53dc:	0f 85 1b 04 00 00    	jne    0x4a57fd
  4a53e2:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a53e6:	48 8d 3d 5e b1 df 00 	lea    rdi,[rip+0xdfb15e]        # 0x12a054b
  4a53ed:	31 c0                	xor    eax,eax
  4a53ef:	e8 1c 80 db ff       	call   0x25d410
  4a53f4:	48 89 df             	mov    rdi,rbx
  4a53f7:	e8 24 7d 01 00       	call   0x4bd120
  4a53fc:	eb 11                	jmp    0x4a540f
  4a53fe:	48 c7 47 08 00 00 00 	mov    QWORD PTR [rdi+0x8],0x0
  4a5405:	00 
  4a5406:	41 ff 4e 50          	dec    DWORD PTR [r14+0x50]
  4a540a:	e8 41 54 f8 ff       	call   0x42a850
  4a540f:	49 8b 7e 40          	mov    rdi,QWORD PTR [r14+0x40]
  4a5413:	48 85 ff             	test   rdi,rdi
  4a5416:	0f 84 39 04 00 00    	je     0x4a5855
  4a541c:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  4a5420:	49 89 46 40          	mov    QWORD PTR [r14+0x40],rax
  4a5424:	48 85 c0             	test   rax,rax
  4a5427:	75 d5                	jne    0x4a53fe
  4a5429:	49 c7 46 48 00 00 00 	mov    QWORD PTR [r14+0x48],0x0
  4a5430:	00 
  4a5431:	eb cb                	jmp    0x4a53fe
  4a5433:	41 0f b6 3c 24       	movzx  edi,BYTE PTR [r12]
  4a5438:	4d 89 f5             	mov    r13,r14
  4a543b:	4d 8b 70 08          	mov    r14,QWORD PTR [r8+0x8]
  4a543f:	48 83 c3 60          	add    rbx,0x60
  4a5443:	4d 89 c7             	mov    r15,r8
  4a5446:	e8 f5 7f 00 00       	call   0x4ad440
  4a544b:	41 0f b6 4f 02       	movzx  ecx,BYTE PTR [r15+0x2]
  4a5450:	41 8b 8c 8d 2c 01 00 	mov    ecx,DWORD PTR [r13+rcx*4+0x12c]
  4a5457:	00 
  4a5458:	48 83 f9 09          	cmp    rcx,0x9
  4a545c:	0f 87 4b 04 00 00    	ja     0x4a58ad
  4a5462:	48 8d 15 4f a7 9d 00 	lea    rdx,[rip+0x9da74f]        # 0xe7fbb8
  4a5469:	4c 8b 04 ca          	mov    r8,QWORD PTR [rdx+rcx*8]
  4a546d:	e9 42 04 00 00       	jmp    0x4a58b4
  4a5472:	49 8b 58 58          	mov    rbx,QWORD PTR [r8+0x58]
  4a5476:	48 8d 05 53 fe db ff 	lea    rax,[rip+0xffffffffffdbfe53]        # 0x2652d0
  4a547d:	4d 89 c4             	mov    r12,r8
  4a5480:	48 29 d8             	sub    rax,rbx
  4a5483:	48 c1 c8 03          	ror    rax,0x3
  4a5487:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a548d:	0f 87 00 08 00 00    	ja     0x4a5c93
  4a5493:	4c 89 f7             	mov    rdi,r14
  4a5496:	ff d3                	call   rbx
  4a5498:	4d 89 e0             	mov    r8,r12
  4a549b:	4c 89 c7             	mov    rdi,r8
  4a549e:	4c 89 f6             	mov    rsi,r14
  4a54a1:	ba 08 00 00 00       	mov    edx,0x8
  4a54a6:	4c 89 c3             	mov    rbx,r8
  4a54a9:	e8 c2 4f 00 00       	call   0x4aa470
  4a54ae:	48 8b 4b 70          	mov    rcx,QWORD PTR [rbx+0x70]
  4a54b2:	48 8d 05 17 fe db ff 	lea    rax,[rip+0xffffffffffdbfe17]        # 0x2652d0
  4a54b9:	48 29 c8             	sub    rax,rcx
  4a54bc:	48 c1 c8 03          	ror    rax,0x3
  4a54c0:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a54c6:	0f 86 41 05 00 00    	jbe    0x4a5a0d
  4a54cc:	48 8d 3d 3d 32 62 01 	lea    rdi,[rip+0x162323d]        # 0x1ac8710
  4a54d3:	48 89 ce             	mov    rsi,rcx
  4a54d6:	48 89 cb             	mov    rbx,rcx
  4a54d9:	e8 e2 a3 fa ff       	call   0x44f8c0
  4a54de:	e9 3a 08 00 00       	jmp    0x4a5d1d
  4a54e3:	41 0f b6 3c 24       	movzx  edi,BYTE PTR [r12]
  4a54e8:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  4a54ec:	48 8b 5a 08          	mov    rbx,QWORD PTR [rdx+0x8]
  4a54f0:	4d 89 fd             	mov    r13,r15
  4a54f3:	49 89 d7             	mov    r15,rdx
  4a54f6:	e8 45 7f 00 00       	call   0x4ad440
  4a54fb:	41 0f b6 4f 02       	movzx  ecx,BYTE PTR [r15+0x2]
  4a5500:	41 8b 8c 8e 2c 01 00 	mov    ecx,DWORD PTR [r14+rcx*4+0x12c]
  4a5507:	00 
  4a5508:	48 83 f9 09          	cmp    rcx,0x9
  4a550c:	0f 87 42 04 00 00    	ja     0x4a5954
  4a5512:	48 8d 15 9f a6 9d 00 	lea    rdx,[rip+0x9da69f]        # 0xe7fbb8
  4a5519:	4c 8b 04 ca          	mov    r8,QWORD PTR [rdx+rcx*8]
  4a551d:	e9 39 04 00 00       	jmp    0x4a595b
  4a5522:	49 8b 5a 58          	mov    rbx,QWORD PTR [r10+0x58]
  4a5526:	4d 89 f4             	mov    r12,r14
  4a5529:	4c 8d 35 a0 fd db ff 	lea    r14,[rip+0xffffffffffdbfda0]        # 0x2652d0
  4a5530:	4d 89 d5             	mov    r13,r10
  4a5533:	4c 89 f0             	mov    rax,r14
  4a5536:	48 29 d8             	sub    rax,rbx
  4a5539:	48 c1 c8 03          	ror    rax,0x3
  4a553d:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5543:	0f 87 5e 07 00 00    	ja     0x4a5ca7
  4a5549:	4c 89 e7             	mov    rdi,r12
  4a554c:	ff d3                	call   rbx
  4a554e:	49 8b 5d 70          	mov    rbx,QWORD PTR [r13+0x70]
  4a5552:	4c 89 6d b0          	mov    QWORD PTR [rbp-0x50],r13
  4a5556:	49 29 de             	sub    r14,rbx
  4a5559:	49 c1 ce 03          	ror    r14,0x3
  4a555d:	49 81 fe bc 08 00 00 	cmp    r14,0x8bc
  4a5564:	0f 87 51 07 00 00    	ja     0x4a5cbb
  4a556a:	4c 89 e7             	mov    rdi,r12
  4a556d:	ff d3                	call   rbx
  4a556f:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a5572:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5576:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  4a557a:	0f 85 a0 06 00 00    	jne    0x4a5c20
  4a5580:	4c 89 e6             	mov    rsi,r12
  4a5583:	e9 1b 03 00 00       	jmp    0x4a58a3
  4a5588:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  4a558c:	49 8b 48 08          	mov    rcx,QWORD PTR [r8+0x8]
  4a5590:	41 0f b6 3c 24       	movzx  edi,BYTE PTR [r12]
  4a5595:	4d 89 fd             	mov    r13,r15
  4a5598:	4d 89 c7             	mov    r15,r8
  4a559b:	48 8d 58 60          	lea    rbx,[rax+0x60]
  4a559f:	48 89 4d b8          	mov    QWORD PTR [rbp-0x48],rcx
  4a55a3:	e8 98 7e 00 00       	call   0x4ad440
  4a55a8:	41 0f b6 4f 02       	movzx  ecx,BYTE PTR [r15+0x2]
  4a55ad:	41 8b 8c 8e 2c 01 00 	mov    ecx,DWORD PTR [r14+rcx*4+0x12c]
  4a55b4:	00 
  4a55b5:	48 83 f9 09          	cmp    rcx,0x9
  4a55b9:	0f 87 24 02 00 00    	ja     0x4a57e3
  4a55bf:	48 8d 15 f2 a5 9d 00 	lea    rdx,[rip+0x9da5f2]        # 0xe7fbb8
  4a55c6:	4c 8b 04 ca          	mov    r8,QWORD PTR [rdx+rcx*8]
  4a55ca:	e9 1b 02 00 00       	jmp    0x4a57ea
  4a55cf:	49 8b 5a 68          	mov    rbx,QWORD PTR [r10+0x68]
  4a55d3:	48 8d 05 f6 fc db ff 	lea    rax,[rip+0xffffffffffdbfcf6]        # 0x2652d0
  4a55da:	4d 89 d4             	mov    r12,r10
  4a55dd:	48 29 d8             	sub    rax,rbx
  4a55e0:	48 c1 c8 03          	ror    rax,0x3
  4a55e4:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a55ea:	0f 87 df 06 00 00    	ja     0x4a5ccf
  4a55f0:	4c 89 f7             	mov    rdi,r14
  4a55f3:	ff d3                	call   rbx
  4a55f5:	41 0f b6 44 24 02    	movzx  eax,BYTE PTR [r12+0x2]
  4a55fb:	41 c7 84 86 2c 01 00 	mov    DWORD PTR [r14+rax*4+0x12c],0x3
  4a5602:	00 03 00 00 00 
  4a5607:	41 0f b6 44 24 02    	movzx  eax,BYTE PTR [r12+0x2]
  4a560d:	31 f6                	xor    esi,esi
  4a560f:	31 d2                	xor    edx,edx
  4a5611:	c1 e0 06             	shl    eax,0x6
  4a5614:	49 8d bc 06 90 01 00 	lea    rdi,[r14+rax*1+0x190]
  4a561b:	00 
  4a561c:	e8 af 59 6f 00       	call   0xb9afd0
  4a5621:	41 83 be 18 01 00 00 	cmp    DWORD PTR [r14+0x118],0x4
  4a5628:	04 
  4a5629:	0f 8c 36 02 00 00    	jl     0x4a5865
  4a562f:	41 f6 86 30 03 00 00 	test   BYTE PTR [r14+0x330],0x2
  4a5636:	02 
  4a5637:	0f 85 28 02 00 00    	jne    0x4a5865
  4a563d:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a5640:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5644:	0f 85 d6 05 00 00    	jne    0x4a5c20
  4a564a:	48 8d 3d 2f a2 9d 00 	lea    rdi,[rip+0x9da22f]        # 0xe7f880
  4a5651:	4c 89 f6             	mov    rsi,r14
  4a5654:	48 83 c4 48          	add    rsp,0x48
  4a5658:	5b                   	pop    rbx
  4a5659:	41 5c                	pop    r12
  4a565b:	41 5d                	pop    r13
  4a565d:	41 5e                	pop    r14
  4a565f:	41 5f                	pop    r15
  4a5661:	5d                   	pop    rbp
  4a5662:	e9 a9 51 00 00       	jmp    0x4aa810
  4a5667:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a566b:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a566f:	83 f8 09             	cmp    eax,0x9
  4a5672:	0f 87 cf 03 00 00    	ja     0x4a5a47
  4a5678:	48 8d 0d 39 a5 9d 00 	lea    rcx,[rip+0x9da539]        # 0xe7fbb8
  4a567f:	4c 8b 04 c1          	mov    r8,QWORD PTR [rcx+rax*8]
  4a5683:	e9 c6 03 00 00       	jmp    0x4a5a4e
  4a5688:	48 8d 1d f1 a1 9d 00 	lea    rbx,[rip+0x9da1f1]        # 0xe7f880
  4a568f:	eb 10                	jmp    0x4a56a1
  4a5691:	48 8d 1d 08 a3 9d 00 	lea    rbx,[rip+0x9da308]        # 0xe7f9a0
  4a5698:	eb 07                	jmp    0x4a56a1
  4a569a:	48 8d 1d ef a3 9d 00 	lea    rbx,[rip+0x9da3ef]        # 0xe7fa90
  4a56a1:	4d 89 f5             	mov    r13,r14
  4a56a4:	41 f6 c3 04          	test   r11b,0x4
  4a56a8:	75 07                	jne    0x4a56b1
  4a56aa:	44 0f b6 73 02       	movzx  r14d,BYTE PTR [rbx+0x2]
  4a56af:	eb 61                	jmp    0x4a5712
  4a56b1:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  4a56b5:	44 0f b6 73 02       	movzx  r14d,BYTE PTR [rbx+0x2]
  4a56ba:	4c 89 55 b0          	mov    QWORD PTR [rbp-0x50],r10
  4a56be:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a56c2:	4c 8b 53 08          	mov    r10,QWORD PTR [rbx+0x8]
  4a56c6:	48 8d 70 60          	lea    rsi,[rax+0x60]
  4a56ca:	43 8b 84 b5 2c 01 00 	mov    eax,DWORD PTR [r13+r14*4+0x12c]
  4a56d1:	00 
  4a56d2:	48 83 f8 09          	cmp    rax,0x9
  4a56d6:	77 0d                	ja     0x4a56e5
  4a56d8:	48 8d 0d d9 a4 9d 00 	lea    rcx,[rip+0x9da4d9]        # 0xe7fbb8
  4a56df:	4c 8b 1c c1          	mov    r11,QWORD PTR [rcx+rax*8]
  4a56e3:	eb 07                	jmp    0x4a56ec
  4a56e5:	4c 8d 1d 99 4d ef 00 	lea    r11,[rip+0xef4d99]        # 0x139a485
  4a56ec:	48 8d 3d f3 d4 e4 00 	lea    rdi,[rip+0xe4d4f3]        # 0x12f2be6
  4a56f3:	4c 8d 05 c3 4d ef 00 	lea    r8,[rip+0xef4dc3]        # 0x139a4bd
  4a56fa:	b9 2b 00 00 00       	mov    ecx,0x2b
  4a56ff:	31 c0                	xor    eax,eax
  4a5701:	41 53                	push   r11
  4a5703:	41 52                	push   r10
  4a5705:	e8 06 7d db ff       	call   0x25d410
  4a570a:	48 83 c4 10          	add    rsp,0x10
  4a570e:	4c 8b 55 b0          	mov    r10,QWORD PTR [rbp-0x50]
  4a5712:	43 83 bc b5 2c 01 00 	cmp    DWORD PTR [r13+r14*4+0x12c],0x6
  4a5719:	00 06 
  4a571b:	4d 89 ee             	mov    r14,r13
  4a571e:	75 7d                	jne    0x4a579d
  4a5720:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  4a5724:	48 8d 05 a5 fb db ff 	lea    rax,[rip+0xffffffffffdbfba5]        # 0x2652d0
  4a572b:	48 29 c8             	sub    rax,rcx
  4a572e:	48 c1 c8 03          	ror    rax,0x3
  4a5732:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5738:	0f 86 cf 02 00 00    	jbe    0x4a5a0d
  4a573e:	48 8d 3d 8b 30 62 01 	lea    rdi,[rip+0x162308b]        # 0x1ac87d0
  4a5745:	48 89 ce             	mov    rsi,rcx
  4a5748:	48 89 cb             	mov    rbx,rcx
  4a574b:	e8 70 a1 fa ff       	call   0x44f8c0
  4a5750:	e9 c8 05 00 00       	jmp    0x4a5d1d
  4a5755:	41 f6 c3 04          	test   r11b,0x4
  4a5759:	74 42                	je     0x4a579d
  4a575b:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  4a575f:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a5763:	4c 89 d3             	mov    rbx,r10
  4a5766:	4c 8d 15 71 44 de 00 	lea    r10,[rip+0xde4471]        # 0x1289bde
  4a576d:	4c 8d 1d 8d d8 e0 00 	lea    r11,[rip+0xe0d88d]        # 0x12b3001
  4a5774:	48 8d 3d 6b d4 e4 00 	lea    rdi,[rip+0xe4d46b]        # 0x12f2be6
  4a577b:	4c 8d 05 3b 4d ef 00 	lea    r8,[rip+0xef4d3b]        # 0x139a4bd
  4a5782:	b9 2d 00 00 00       	mov    ecx,0x2d
  4a5787:	48 8d 70 60          	lea    rsi,[rax+0x60]
  4a578b:	31 c0                	xor    eax,eax
  4a578d:	41 52                	push   r10
  4a578f:	41 53                	push   r11
  4a5791:	e8 7a 7c db ff       	call   0x25d410
  4a5796:	49 89 da             	mov    r10,rbx
  4a5799:	48 83 c4 10          	add    rsp,0x10
  4a579d:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a57a2:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
  4a57a6:	41 8b 84 86 2c 01 00 	mov    eax,DWORD PTR [r14+rax*4+0x12c]
  4a57ad:	00 
  4a57ae:	83 f8 09             	cmp    eax,0x9
  4a57b1:	0f 87 a7 02 00 00    	ja     0x4a5a5e
  4a57b7:	b9 7c 03 00 00       	mov    ecx,0x37c
  4a57bc:	0f a3 c1             	bt     ecx,eax
  4a57bf:	0f 82 a0 00 00 00    	jb     0x4a5865
  4a57c5:	83 f8 07             	cmp    eax,0x7
  4a57c8:	0f 85 90 02 00 00    	jne    0x4a5a5e
  4a57ce:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a57d1:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a57d5:	0f 85 45 04 00 00    	jne    0x4a5c20
  4a57db:	4c 89 d7             	mov    rdi,r10
  4a57de:	e9 56 01 00 00       	jmp    0x4a5939
  4a57e3:	4c 8d 05 9b 4c ef 00 	lea    r8,[rip+0xef4c9b]        # 0x139a485
  4a57ea:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
  4a57ee:	48 8d 3d b9 b1 ec 00 	lea    rdi,[rip+0xecb1b9]        # 0x13709ae
  4a57f5:	48 89 de             	mov    rsi,rbx
  4a57f8:	e9 6c 01 00 00       	jmp    0x4a5969
  4a57fd:	48 8d 75 cc          	lea    rsi,[rbp-0x34]
  4a5801:	ba 04 00 00 00       	mov    edx,0x4
  4a5806:	4c 89 ef             	mov    rdi,r13
  4a5809:	0f 38 f1 45 cc       	movbe  DWORD PTR [rbp-0x34],eax
  4a580e:	e8 9d 38 db ff       	call   0x2590b0
  4a5813:	f6 45 b8 04          	test   BYTE PTR [rbp-0x48],0x4
  4a5817:	74 15                	je     0x4a582e
  4a5819:	48 83 c3 60          	add    rbx,0x60
  4a581d:	48 8d 3d a8 0b df 00 	lea    rdi,[rip+0xdf0ba8]        # 0x12963cc
  4a5824:	31 c0                	xor    eax,eax
  4a5826:	48 89 de             	mov    rsi,rbx
  4a5829:	e8 e2 7b db ff       	call   0x25d410
  4a582e:	8b 5d b0             	mov    ebx,DWORD PTR [rbp-0x50]
  4a5831:	41 0f b6 4c 24 01    	movzx  ecx,BYTE PTR [r12+0x1]
  4a5837:	4c 89 f7             	mov    rdi,r14
  4a583a:	be 21 c0 00 00       	mov    esi,0xc021
  4a583f:	ba 0a 00 00 00       	mov    edx,0xa
  4a5844:	4d 89 e9             	mov    r9,r13
  4a5847:	83 c3 fc             	add    ebx,0xfffffffc
  4a584a:	44 0f b7 c3          	movzx  r8d,bx
  4a584e:	e8 fd ed ff ff       	call   0x4a4650
  4a5853:	eb 10                	jmp    0x4a5865
  4a5855:	4c 89 f7             	mov    rdi,r14
  4a5858:	e8 93 37 00 00       	call   0x4a8ff0
  4a585d:	4c 89 f7             	mov    rdi,r14
  4a5860:	e8 db 35 00 00       	call   0x4a8e40
  4a5865:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a5868:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a586c:	0f 85 ae 03 00 00    	jne    0x4a5c20
  4a5872:	48 83 c4 48          	add    rsp,0x48
  4a5876:	5b                   	pop    rbx
  4a5877:	41 5c                	pop    r12
  4a5879:	41 5d                	pop    r13
  4a587b:	41 5e                	pop    r14
  4a587d:	41 5f                	pop    r15
  4a587f:	5d                   	pop    rbp
  4a5880:	c3                   	ret
  4a5881:	41 8b 8e 44 03 00 00 	mov    ecx,DWORD PTR [r14+0x344]
  4a5888:	41 89 8c 86 48 01 00 	mov    DWORD PTR [r14+rax*4+0x148],ecx
  4a588f:	00 
  4a5890:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a5893:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5897:	0f 85 83 03 00 00    	jne    0x4a5c20
  4a589d:	4c 89 d7             	mov    rdi,r10
  4a58a0:	4c 89 f6             	mov    rsi,r14
  4a58a3:	ba 07 00 00 00       	mov    edx,0x7
  4a58a8:	e9 94 00 00 00       	jmp    0x4a5941
  4a58ad:	4c 8d 05 d1 4b ef 00 	lea    r8,[rip+0xef4bd1]        # 0x139a485
  4a58b4:	4c 8d 3d 55 6a 47 03 	lea    r15,[rip+0x3476a55]        # 0x391c310
  4a58bb:	48 89 c1             	mov    rcx,rax
  4a58be:	48 8d 3d e9 b0 ec 00 	lea    rdi,[rip+0xecb0e9]        # 0x13709ae
  4a58c5:	48 89 de             	mov    rsi,rbx
  4a58c8:	4c 89 f2             	mov    rdx,r14
  4a58cb:	31 c0                	xor    eax,eax
  4a58cd:	e8 3e 7b db ff       	call   0x25d410
  4a58d2:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a58d5:	e9 9d 00 00 00       	jmp    0x4a5977
  4a58da:	49 8b 5a 58          	mov    rbx,QWORD PTR [r10+0x58]
  4a58de:	48 8d 05 eb f9 db ff 	lea    rax,[rip+0xffffffffffdbf9eb]        # 0x2652d0
  4a58e5:	4d 89 d4             	mov    r12,r10
  4a58e8:	48 29 d8             	sub    rax,rbx
  4a58eb:	48 c1 c8 03          	ror    rax,0x3
  4a58ef:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a58f5:	0f 87 fc 03 00 00    	ja     0x4a5cf7
  4a58fb:	4c 89 f7             	mov    rdi,r14
  4a58fe:	ff d3                	call   rbx
  4a5900:	4d 89 e2             	mov    r10,r12
  4a5903:	49 8b 5a 70          	mov    rbx,QWORD PTR [r10+0x70]
  4a5907:	48 8d 05 c2 f9 db ff 	lea    rax,[rip+0xffffffffffdbf9c2]        # 0x2652d0
  4a590e:	4d 89 d4             	mov    r12,r10
  4a5911:	48 29 d8             	sub    rax,rbx
  4a5914:	48 c1 c8 03          	ror    rax,0x3
  4a5918:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a591e:	0f 87 bf 03 00 00    	ja     0x4a5ce3
  4a5924:	4c 89 f7             	mov    rdi,r14
  4a5927:	ff d3                	call   rbx
  4a5929:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a592c:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5930:	0f 85 ea 02 00 00    	jne    0x4a5c20
  4a5936:	4c 89 e7             	mov    rdi,r12
  4a5939:	4c 89 f6             	mov    rsi,r14
  4a593c:	ba 06 00 00 00       	mov    edx,0x6
  4a5941:	48 83 c4 48          	add    rsp,0x48
  4a5945:	5b                   	pop    rbx
  4a5946:	41 5c                	pop    r12
  4a5948:	41 5d                	pop    r13
  4a594a:	41 5e                	pop    r14
  4a594c:	41 5f                	pop    r15
  4a594e:	5d                   	pop    rbp
  4a594f:	e9 1c 4b 00 00       	jmp    0x4aa470
  4a5954:	4c 8d 05 2a 4b ef 00 	lea    r8,[rip+0xef4b2a]        # 0x139a485
  4a595b:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  4a595f:	48 8d 3d 48 b0 ec 00 	lea    rdi,[rip+0xecb048]        # 0x13709ae
  4a5966:	48 89 da             	mov    rdx,rbx
  4a5969:	48 89 c1             	mov    rcx,rax
  4a596c:	31 c0                	xor    eax,eax
  4a596e:	e8 9d 7a db ff       	call   0x25d410
  4a5973:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  4a5977:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a597b:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  4a597f:	0f 85 9b 02 00 00    	jne    0x4a5c20
  4a5985:	ba 01 00 00 00       	mov    edx,0x1
  4a598a:	e9 2a f7 ff ff       	jmp    0x4a50b9
  4a598f:	41 8b 8e 44 03 00 00 	mov    ecx,DWORD PTR [r14+0x344]
  4a5996:	31 f6                	xor    esi,esi
  4a5998:	31 d2                	xor    edx,edx
  4a599a:	4d 89 d4             	mov    r12,r10
  4a599d:	45 89 dd             	mov    r13d,r11d
  4a59a0:	41 89 8c 86 48 01 00 	mov    DWORD PTR [r14+rax*4+0x148],ecx
  4a59a7:	00 
  4a59a8:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a59ad:	41 c7 84 86 2c 01 00 	mov    DWORD PTR [r14+rax*4+0x12c],0x9
  4a59b4:	00 09 00 00 00 
  4a59b9:	41 0f b6 42 02       	movzx  eax,BYTE PTR [r10+0x2]
  4a59be:	c1 e0 06             	shl    eax,0x6
  4a59c1:	49 8d bc 06 90 01 00 	lea    rdi,[r14+rax*1+0x190]
  4a59c8:	00 
  4a59c9:	e8 02 56 6f 00       	call   0xb9afd0
  4a59ce:	41 f6 c5 04          	test   r13b,0x4
  4a59d2:	74 1a                	je     0x4a59ee
  4a59d4:	49 8b 54 24 08       	mov    rdx,QWORD PTR [r12+0x8]
  4a59d9:	48 83 c3 60          	add    rbx,0x60
  4a59dd:	48 8d 3d 87 48 e0 00 	lea    rdi,[rip+0xe04887]        # 0x12aa26b
  4a59e4:	31 c0                	xor    eax,eax
  4a59e6:	48 89 de             	mov    rsi,rbx
  4a59e9:	e8 22 7a db ff       	call   0x25d410
  4a59ee:	49 8b 4c 24 50       	mov    rcx,QWORD PTR [r12+0x50]
  4a59f3:	48 8d 05 d6 f8 db ff 	lea    rax,[rip+0xffffffffffdbf8d6]        # 0x2652d0
  4a59fa:	48 29 c8             	sub    rax,rcx
  4a59fd:	48 c1 c8 03          	ror    rax,0x3
  4a5a01:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5a07:	0f 87 fe 02 00 00    	ja     0x4a5d0b
  4a5a0d:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a5a10:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5a14:	0f 85 06 02 00 00    	jne    0x4a5c20
  4a5a1a:	4c 89 f7             	mov    rdi,r14
  4a5a1d:	48 83 c4 48          	add    rsp,0x48
  4a5a21:	5b                   	pop    rbx
  4a5a22:	41 5c                	pop    r12
  4a5a24:	41 5d                	pop    r13
  4a5a26:	41 5e                	pop    r14
  4a5a28:	41 5f                	pop    r15
  4a5a2a:	5d                   	pop    rbp
  4a5a2b:	ff e1                	jmp    rcx
  4a5a2d:	49 8b 52 08          	mov    rdx,QWORD PTR [r10+0x8]
  4a5a31:	48 8d 73 60          	lea    rsi,[rbx+0x60]
  4a5a35:	83 ff 09             	cmp    edi,0x9
  4a5a38:	77 6a                	ja     0x4a5aa4
  4a5a3a:	48 8d 05 77 a1 9d 00 	lea    rax,[rip+0x9da177]        # 0xe7fbb8
  4a5a41:	4c 8b 04 f8          	mov    r8,QWORD PTR [rax+rdi*8]
  4a5a45:	eb 64                	jmp    0x4a5aab
  4a5a47:	4c 8d 05 37 4a ef 00 	lea    r8,[rip+0xef4a37]        # 0x139a485
  4a5a4e:	48 8d 3d 59 af ec 00 	lea    rdi,[rip+0xecaf59]        # 0x13709ae
  4a5a55:	48 8d 0d f4 5c de 00 	lea    rcx,[rip+0xde5cf4]        # 0x128b750
  4a5a5c:	eb 5b                	jmp    0x4a5ab9
  4a5a5e:	41 0f b6 3c 24       	movzx  edi,BYTE PTR [r12]
  4a5a63:	4d 89 f5             	mov    r13,r14
  4a5a66:	4d 8b 72 08          	mov    r14,QWORD PTR [r10+0x8]
  4a5a6a:	48 8d 42 60          	lea    rax,[rdx+0x60]
  4a5a6e:	4c 89 fb             	mov    rbx,r15
  4a5a71:	4d 89 d7             	mov    r15,r10
  4a5a74:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  4a5a78:	e8 c3 79 00 00       	call   0x4ad440
  4a5a7d:	41 0f b6 4f 02       	movzx  ecx,BYTE PTR [r15+0x2]
  4a5a82:	41 8b 8c 8d 2c 01 00 	mov    ecx,DWORD PTR [r13+rcx*4+0x12c]
  4a5a89:	00 
  4a5a8a:	48 83 f9 09          	cmp    rcx,0x9
  4a5a8e:	0f 87 58 01 00 00    	ja     0x4a5bec
  4a5a94:	48 8d 15 1d a1 9d 00 	lea    rdx,[rip+0x9da11d]        # 0xe7fbb8
  4a5a9b:	4c 8b 04 ca          	mov    r8,QWORD PTR [rdx+rcx*8]
  4a5a9f:	e9 4f 01 00 00       	jmp    0x4a5bf3
  4a5aa4:	4c 8d 05 da 49 ef 00 	lea    r8,[rip+0xef49da]        # 0x139a485
  4a5aab:	48 8d 3d fc ae ec 00 	lea    rdi,[rip+0xecaefc]        # 0x13709ae
  4a5ab2:	48 8d 0d ec ae ec 00 	lea    rcx,[rip+0xecaeec]        # 0x13709a5
  4a5ab9:	31 c0                	xor    eax,eax
  4a5abb:	e8 50 79 db ff       	call   0x25d410
  4a5ac0:	e9 df f5 ff ff       	jmp    0x4a50a4
  4a5ac5:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  4a5ac9:	48 8b 57 08          	mov    rdx,QWORD PTR [rdi+0x8]
  4a5acd:	48 89 f9             	mov    rcx,rdi
  4a5ad0:	41 0f b6 3c 24       	movzx  edi,BYTE PTR [r12]
  4a5ad5:	4d 89 fd             	mov    r13,r15
  4a5ad8:	49 89 cf             	mov    r15,rcx
  4a5adb:	48 8d 58 60          	lea    rbx,[rax+0x60]
  4a5adf:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  4a5ae3:	e9 bb fa ff ff       	jmp    0x4a55a3
  4a5ae8:	85 c0                	test   eax,eax
  4a5aea:	0f 84 23 01 00 00    	je     0x4a5c13
  4a5af0:	41 c7 84 8e 2c 01 00 	mov    DWORD PTR [r14+rcx*4+0x12c],0x9
  4a5af7:	00 09 00 00 00 
  4a5afc:	48 89 fb             	mov    rbx,rdi
  4a5aff:	31 f6                	xor    esi,esi
  4a5b01:	31 d2                	xor    edx,edx
  4a5b03:	0f b6 47 02          	movzx  eax,BYTE PTR [rdi+0x2]
  4a5b07:	c1 e0 06             	shl    eax,0x6
  4a5b0a:	49 8d bc 06 90 01 00 	lea    rdi,[r14+rax*1+0x190]
  4a5b11:	00 
  4a5b12:	e8 b9 54 6f 00       	call   0xb9afd0
  4a5b17:	f6 45 b8 04          	test   BYTE PTR [rbp-0x48],0x4
  4a5b1b:	74 1a                	je     0x4a5b37
  4a5b1d:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  4a5b21:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  4a5b25:	48 8d 3d 3f 47 e0 00 	lea    rdi,[rip+0xe0473f]        # 0x12aa26b
  4a5b2c:	31 c0                	xor    eax,eax
  4a5b2e:	48 83 c6 60          	add    rsi,0x60
  4a5b32:	e8 d9 78 db ff       	call   0x25d410
  4a5b37:	48 8b 4b 50          	mov    rcx,QWORD PTR [rbx+0x50]
  4a5b3b:	48 8d 05 8e f7 db ff 	lea    rax,[rip+0xffffffffffdbf78e]        # 0x2652d0
  4a5b42:	48 29 c8             	sub    rax,rcx
  4a5b45:	48 c1 c8 03          	ror    rax,0x3
  4a5b49:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5b4f:	0f 86 b8 fe ff ff    	jbe    0x4a5a0d
  4a5b55:	48 8d 3d b4 2a 62 01 	lea    rdi,[rip+0x1622ab4]        # 0x1ac8610
  4a5b5c:	48 89 ce             	mov    rsi,rcx
  4a5b5f:	48 89 cb             	mov    rbx,rcx
  4a5b62:	e8 59 9d fa ff       	call   0x44f8c0
  4a5b67:	e9 b1 01 00 00       	jmp    0x4a5d1d
  4a5b6c:	48 8b 5f 58          	mov    rbx,QWORD PTR [rdi+0x58]
  4a5b70:	4c 8d 3d 59 f7 db ff 	lea    r15,[rip+0xffffffffffdbf759]        # 0x2652d0
  4a5b77:	4d 89 f5             	mov    r13,r14
  4a5b7a:	41 89 c6             	mov    r14d,eax
  4a5b7d:	49 89 fc             	mov    r12,rdi
  4a5b80:	4c 89 f8             	mov    rax,r15
  4a5b83:	48 29 d8             	sub    rax,rbx
  4a5b86:	48 c1 c8 03          	ror    rax,0x3
  4a5b8a:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  4a5b90:	0f 87 a3 01 00 00    	ja     0x4a5d39
  4a5b96:	4c 89 ef             	mov    rdi,r13
  4a5b99:	ff d3                	call   rbx
  4a5b9b:	49 8b 5c 24 70       	mov    rbx,QWORD PTR [r12+0x70]
  4a5ba0:	4c 89 65 b0          	mov    QWORD PTR [rbp-0x50],r12
  4a5ba4:	49 29 df             	sub    r15,rbx
  4a5ba7:	49 c1 cf 03          	ror    r15,0x3
  4a5bab:	49 81 ff bc 08 00 00 	cmp    r15,0x8bc
  4a5bb2:	0f 87 95 01 00 00    	ja     0x4a5d4d
  4a5bb8:	4c 89 ef             	mov    rdi,r13
  4a5bbb:	ff d3                	call   rbx
  4a5bbd:	4c 8d 3d 4c 67 47 03 	lea    r15,[rip+0x347674c]        # 0x391c310
  4a5bc4:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  4a5bc8:	44 89 f0             	mov    eax,r14d
  4a5bcb:	4d 89 ee             	mov    r14,r13
  4a5bce:	31 c9                	xor    ecx,ecx
  4a5bd0:	85 c0                	test   eax,eax
  4a5bd2:	49 8b 17             	mov    rdx,QWORD PTR [r15]
  4a5bd5:	0f 95 c0             	setne  al
  4a5bd8:	48 3b 55 d0          	cmp    rdx,QWORD PTR [rbp-0x30]
  4a5bdc:	75 42                	jne    0x4a5c20
  4a5bde:	88 c1                	mov    cl,al
  4a5be0:	4c 89 f6             	mov    rsi,r14
  4a5be3:	8d 54 09 06          	lea    edx,[rcx+rcx*1+0x6]
  4a5be7:	e9 55 fd ff ff       	jmp    0x4a5941
  4a5bec:	4c 8d 05 92 48 ef 00 	lea    r8,[rip+0xef4892]        # 0x139a485
  4a5bf3:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  4a5bf7:	48 89 c1             	mov    rcx,rax
  4a5bfa:	48 8d 3d ad ad ec 00 	lea    rdi,[rip+0xecadad]        # 0x13709ae
  4a5c01:	4c 89 f2             	mov    rdx,r14
  4a5c04:	31 c0                	xor    eax,eax
  4a5c06:	e8 05 78 db ff       	call   0x25d410
  4a5c0b:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  4a5c0e:	e9 64 fd ff ff       	jmp    0x4a5977
  4a5c13:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a5c16:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5c1a:	0f 84 80 fc ff ff    	je     0x4a58a0
  4a5c20:	e8 8b 7a 25 00       	call   0x6fd6b0
  4a5c25:	0f 0b                	ud2
  4a5c27:	48 8d 3d 82 2a 62 01 	lea    rdi,[rip+0x1622a82]        # 0x1ac86b0
  4a5c2e:	48 89 de             	mov    rsi,rbx
  4a5c31:	4c 89 75 a8          	mov    QWORD PTR [rbp-0x58],r14
  4a5c35:	41 89 d6             	mov    r14d,edx
  4a5c38:	e8 83 9c fa ff       	call   0x44f8c0
  4a5c3d:	44 89 f2             	mov    edx,r14d
  4a5c40:	4c 8b 75 a8          	mov    r14,QWORD PTR [rbp-0x58]
  4a5c44:	e9 9c f3 ff ff       	jmp    0x4a4fe5
  4a5c49:	48 8d 3d 40 29 62 01 	lea    rdi,[rip+0x1622940]        # 0x1ac8590
  4a5c50:	48 89 de             	mov    rsi,rbx
  4a5c53:	4c 89 75 a8          	mov    QWORD PTR [rbp-0x58],r14
  4a5c57:	41 89 d6             	mov    r14d,edx
  4a5c5a:	e8 61 9c fa ff       	call   0x44f8c0
  4a5c5f:	44 89 f2             	mov    edx,r14d
  4a5c62:	4c 8b 75 a8          	mov    r14,QWORD PTR [rbp-0x58]
  4a5c66:	e9 b4 f6 ff ff       	jmp    0x4a531f
  4a5c6b:	48 8d 3d de 2a 62 01 	lea    rdi,[rip+0x1622ade]        # 0x1ac8750
  4a5c72:	48 89 de             	mov    rsi,rbx
  4a5c75:	e8 46 9c fa ff       	call   0x44f8c0
  4a5c7a:	e9 e0 f1 ff ff       	jmp    0x4a4e5f
  4a5c7f:	48 8d 3d aa 2a 62 01 	lea    rdi,[rip+0x1622aaa]        # 0x1ac8730
  4a5c86:	48 89 de             	mov    rsi,rbx
  4a5c89:	e8 32 9c fa ff       	call   0x44f8c0
  4a5c8e:	e9 85 f5 ff ff       	jmp    0x4a5218
  4a5c93:	48 8d 3d 56 2a 62 01 	lea    rdi,[rip+0x1622a56]        # 0x1ac86f0
  4a5c9a:	48 89 de             	mov    rsi,rbx
  4a5c9d:	e8 1e 9c fa ff       	call   0x44f8c0
  4a5ca2:	e9 ec f7 ff ff       	jmp    0x4a5493
  4a5ca7:	48 8d 3d e2 2a 62 01 	lea    rdi,[rip+0x1622ae2]        # 0x1ac8790
  4a5cae:	48 89 de             	mov    rsi,rbx
  4a5cb1:	e8 0a 9c fa ff       	call   0x44f8c0
  4a5cb6:	e9 8e f8 ff ff       	jmp    0x4a5549
  4a5cbb:	48 8d 3d ee 2a 62 01 	lea    rdi,[rip+0x1622aee]        # 0x1ac87b0
  4a5cc2:	48 89 de             	mov    rsi,rbx
  4a5cc5:	e8 f6 9b fa ff       	call   0x44f8c0
  4a5cca:	e9 9b f8 ff ff       	jmp    0x4a556a
  4a5ccf:	48 8d 3d 9a 2a 62 01 	lea    rdi,[rip+0x1622a9a]        # 0x1ac8770
  4a5cd6:	48 89 de             	mov    rsi,rbx
  4a5cd9:	e8 e2 9b fa ff       	call   0x44f8c0
  4a5cde:	e9 0d f9 ff ff       	jmp    0x4a55f0
  4a5ce3:	48 8d 3d 66 29 62 01 	lea    rdi,[rip+0x1622966]        # 0x1ac8650
  4a5cea:	48 89 de             	mov    rsi,rbx
  4a5ced:	e8 ce 9b fa ff       	call   0x44f8c0
  4a5cf2:	e9 2d fc ff ff       	jmp    0x4a5924
  4a5cf7:	48 8d 3d 32 29 62 01 	lea    rdi,[rip+0x1622932]        # 0x1ac8630
  4a5cfe:	48 89 de             	mov    rsi,rbx
  4a5d01:	e8 ba 9b fa ff       	call   0x44f8c0
  4a5d06:	e9 f0 fb ff ff       	jmp    0x4a58fb
  4a5d0b:	48 8d 3d 5e 29 62 01 	lea    rdi,[rip+0x162295e]        # 0x1ac8670
  4a5d12:	48 89 ce             	mov    rsi,rcx
  4a5d15:	48 89 cb             	mov    rbx,rcx
  4a5d18:	e8 a3 9b fa ff       	call   0x44f8c0
  4a5d1d:	48 89 d9             	mov    rcx,rbx
  4a5d20:	e9 e8 fc ff ff       	jmp    0x4a5a0d
  4a5d25:	48 8d 3d c4 28 62 01 	lea    rdi,[rip+0x16228c4]        # 0x1ac85f0
  4a5d2c:	48 89 de             	mov    rsi,rbx
  4a5d2f:	e8 8c 9b fa ff       	call   0x44f8c0
  4a5d34:	e9 51 f6 ff ff       	jmp    0x4a538a
  4a5d39:	48 8d 3d 70 28 62 01 	lea    rdi,[rip+0x1622870]        # 0x1ac85b0
  4a5d40:	48 89 de             	mov    rsi,rbx
  4a5d43:	e8 78 9b fa ff       	call   0x44f8c0
  4a5d48:	e9 49 fe ff ff       	jmp    0x4a5b96
  4a5d4d:	48 8d 3d 7c 28 62 01 	lea    rdi,[rip+0x162287c]        # 0x1ac85d0
  4a5d54:	48 89 de             	mov    rsi,rbx
  4a5d57:	e8 64 9b fa ff       	call   0x44f8c0
  4a5d5c:	e9 57 fe ff ff       	jmp    0x4a5bb8
  4a5d61:	90                   	nop
  4a5d62:	90                   	nop
  4a5d63:	90                   	nop
  4a5d64:	90                   	nop
  4a5d65:	90                   	nop
  4a5d66:	90                   	nop
  4a5d67:	90                   	nop
  4a5d68:	90                   	nop
  4a5d69:	90                   	nop
  4a5d6a:	90                   	nop
  4a5d6b:	90                   	nop
  4a5d6c:	90                   	nop
  4a5d6d:	90                   	nop
  4a5d6e:	90                   	nop
  4a5d6f:	90                   	nop
  4a5d70:	55                   	push   rbp
  4a5d71:	48 89 e5             	mov    rbp,rsp
  4a5d74:	41 57                	push   r15
  4a5d76:	41 56                	push   r14
  4a5d78:	41 55                	push   r13
  4a5d7a:	41 54                	push   r12
  4a5d7c:	53                   	push   rbx
  4a5d7d:	48 83 ec 28          	sub    rsp,0x28
  4a5d81:	49 89 fe             	mov    r14,rdi
  4a5d84:	48 8d 3d 85 65 47 03 	lea    rdi,[rip+0x3476585]        # 0x391c310
  4a5d8b:	48 89 f0             	mov    rax,rsi
  4a5d8e:	48 8b 0f             	mov    rcx,QWORD PTR [rdi]
  4a5d91:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  4a5d95:	49 8b 36             	mov    rsi,QWORD PTR [r14]
  4a5d98:	44 8b 60 30          	mov    r12d,DWORD PTR [rax+0x30]
  4a5d9c:	41 83 fc 04          	cmp    r12d,0x4
  4a5da0:	7f 30                	jg     0x4a5dd2
  4a5da2:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  4a5da5:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5da9:	0f 85 fa 05 00 00    	jne    0x4a63a9
  4a5daf:	48 83 c6 60          	add    rsi,0x60
  4a5db3:	48 8d 3d d5 88 e3 00 	lea    rdi,[rip+0xe388d5]        # 0x12de68f
  4a5dba:	44 89 e2             	mov    edx,r12d
  4a5dbd:	31 c0                	xor    eax,eax
  4a5dbf:	48 83 c4 28          	add    rsp,0x28
  4a5dc3:	5b                   	pop    rbx
  4a5dc4:	41 5c                	pop    r12
  4a5dc6:	41 5d                	pop    r13
  4a5dc8:	41 5e                	pop    r14
  4a5dca:	41 5f                	pop    r15
  4a5dcc:	5d                   	pop    rbp
  4a5dcd:	e9 3e 76 db ff       	jmp    0x25d410
  4a5dd2:	48 8b 58 10          	mov    rbx,QWORD PTR [rax+0x10]
  4a5dd6:	44 8b 46 78          	mov    r8d,DWORD PTR [rsi+0x78]
  4a5dda:	66 0f 38 f0 43 02    	movbe  ax,WORD PTR [rbx+0x2]
  4a5de0:	0f b6 13             	movzx  edx,BYTE PTR [rbx]
  4a5de3:	44 0f b7 f8          	movzx  r15d,ax
  4a5de7:	45 39 fc             	cmp    r12d,r15d
  4a5dea:	45 89 fd             	mov    r13d,r15d
  4a5ded:	45 0f 42 ec          	cmovb  r13d,r12d
  4a5df1:	83 fa 03             	cmp    edx,0x3
  4a5df4:	0f 84 43 01 00 00    	je     0x4a5f3d
  4a5dfa:	83 fa 02             	cmp    edx,0x2
  4a5dfd:	0f 84 8b 00 00 00    	je     0x4a5e8e
  4a5e03:	83 fa 01             	cmp    edx,0x1
  4a5e06:	0f 85 7f 01 00 00    	jne    0x4a5f8b
  4a5e0c:	49 83 be b8 03 00 00 	cmp    QWORD PTR [r14+0x3b8],0x0
  4a5e13:	00 
  4a5e14:	0f 84 fe 01 00 00    	je     0x4a6018
  4a5e1a:	49 83 be c0 03 00 00 	cmp    QWORD PTR [r14+0x3c0],0x0
  4a5e21:	00 
  4a5e22:	0f 84 f0 01 00 00    	je     0x4a6018
  4a5e28:	4c 0f be 63 04       	movsx  r12,BYTE PTR [rbx+0x4]
  4a5e2d:	41 8d 45 fa          	lea    eax,[r13-0x6]
  4a5e31:	44 29 e0             	sub    eax,r12d
  4a5e34:	7c 13                	jl     0x4a5e49
  4a5e36:	4a 8d 4c 23 05       	lea    rcx,[rbx+r12*1+0x5]
  4a5e3b:	0f be 09             	movsx  ecx,BYTE PTR [rcx]
  4a5e3e:	89 4d c0             	mov    DWORD PTR [rbp-0x40],ecx
  4a5e41:	39 c8                	cmp    eax,ecx
  4a5e43:	0f 8d 96 03 00 00    	jge    0x4a61df
  4a5e49:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a5e4d:	49 89 fe             	mov    r14,rdi
  4a5e50:	48 83 c6 60          	add    rsi,0x60
  4a5e54:	48 8d 3d 5d 19 e8 00 	lea    rdi,[rip+0xe8195d]        # 0x13277b8
  4a5e5b:	48 8d 15 ea 58 de 00 	lea    rdx,[rip+0xde58ea]        # 0x128b74c
  4a5e62:	45 89 f8             	mov    r8d,r15d
  4a5e65:	31 c0                	xor    eax,eax
  4a5e67:	e8 a4 75 db ff       	call   0x25d410
  4a5e6c:	41 83 fd 05          	cmp    r13d,0x5
  4a5e70:	72 14                	jb     0x4a5e86
  4a5e72:	41 83 c5 fc          	add    r13d,0xfffffffc
  4a5e76:	48 83 c3 04          	add    rbx,0x4
  4a5e7a:	41 0f b7 f5          	movzx  esi,r13w
  4a5e7e:	48 89 df             	mov    rdi,rbx
  4a5e81:	e8 ca 59 00 00       	call   0x4ab850
  4a5e86:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a5e89:	e9 74 01 00 00       	jmp    0x4a6002
  4a5e8e:	49 8d be d0 02 00 00 	lea    rdi,[r14+0x2d0]
  4a5e95:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
  4a5e99:	31 f6                	xor    esi,esi
  4a5e9b:	31 d2                	xor    edx,edx
  4a5e9d:	45 89 c7             	mov    r15d,r8d
  4a5ea0:	e8 2b 51 6f 00       	call   0xb9afd0
  4a5ea5:	41 f6 c7 04          	test   r15b,0x4
  4a5ea9:	0f 84 94 01 00 00    	je     0x4a6043
  4a5eaf:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  4a5eb3:	48 8d 3d 6c 1a e6 00 	lea    rdi,[rip+0xe61a6c]        # 0x1307926
  4a5eba:	48 8d 70 60          	lea    rsi,[rax+0x60]
  4a5ebe:	31 c0                	xor    eax,eax
  4a5ec0:	e8 4b 75 db ff       	call   0x25d410
  4a5ec5:	0f b6 03             	movzx  eax,BYTE PTR [rbx]
  4a5ec8:	41 83 fd 06          	cmp    r13d,0x6
  4a5ecc:	0f 93 c1             	setae  cl
  4a5ecf:	84 c0                	test   al,al
  4a5ed1:	0f 95 c2             	setne  dl
  4a5ed4:	20 ca                	and    dl,cl
  4a5ed6:	80 fa 01             	cmp    dl,0x1
  4a5ed9:	0f 85 56 01 00 00    	jne    0x4a6035
  4a5edf:	48 8d 3d af 9d ee 00 	lea    rdi,[rip+0xee9daf]        # 0x138fc95
  4a5ee6:	44 0f be f8          	movsx  r15d,al
  4a5eea:	31 c0                	xor    eax,eax
  4a5eec:	e8 1f 75 db ff       	call   0x25d410
  4a5ef1:	45 0f b7 e7          	movzx  r12d,r15w
  4a5ef5:	4c 8d 2d 71 6d e7 00 	lea    r13,[rip+0xe76d71]        # 0x131cc6d
  4a5efc:	45 31 ff             	xor    r15d,r15d
  4a5eff:	eb 23                	jmp    0x4a5f24
  4a5f01:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  4a5f08:	0f 1f 84 00 00 00 00 
  4a5f0f:	00 
  4a5f10:	31 c0                	xor    eax,eax
  4a5f12:	e8 f9 74 db ff       	call   0x25d410
  4a5f17:	49 ff c7             	inc    r15
  4a5f1a:	66 45 39 fc          	cmp    r12w,r15w
  4a5f1e:	0f 84 11 01 00 00    	je     0x4a6035
  4a5f24:	42 0f b6 74 3b 04    	movzx  esi,BYTE PTR [rbx+r15*1+0x4]
  4a5f2a:	4c 89 ef             	mov    rdi,r13
  4a5f2d:	8d 46 81             	lea    eax,[rsi-0x7f]
  4a5f30:	3c a1                	cmp    al,0xa1
  4a5f32:	72 dc                	jb     0x4a5f10
  4a5f34:	48 8d 3d 4e a0 e8 00 	lea    rdi,[rip+0xe8a04e]        # 0x132ff89
  4a5f3b:	eb d3                	jmp    0x4a5f10
  4a5f3d:	49 8d be d0 02 00 00 	lea    rdi,[r14+0x2d0]
  4a5f44:	49 89 f7             	mov    r15,rsi
  4a5f47:	31 f6                	xor    esi,esi
  4a5f49:	31 d2                	xor    edx,edx
  4a5f4b:	45 89 c4             	mov    r12d,r8d
  4a5f4e:	e8 7d 50 6f 00       	call   0xb9afd0
  4a5f53:	41 ff 86 10 01 00 00 	inc    DWORD PTR [r14+0x110]
  4a5f5a:	4c 89 fe             	mov    rsi,r15
  4a5f5d:	48 83 c6 60          	add    rsi,0x60
  4a5f61:	41 f6 c4 04          	test   r12b,0x4
  4a5f65:	0f 85 a4 01 00 00    	jne    0x4a610f
  4a5f6b:	48 8d 05 9e 63 47 03 	lea    rax,[rip+0x347639e]        # 0x391c310
  4a5f72:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a5f75:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a5f79:	0f 85 2a 04 00 00    	jne    0x4a63a9
  4a5f7f:	48 8d 3d a6 45 ef 00 	lea    rdi,[rip+0xef45a6]        # 0x139a52c
  4a5f86:	e9 6f 01 00 00       	jmp    0x4a60fa
  4a5f8b:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a5f8f:	48 83 c6 60          	add    rsi,0x60
  4a5f93:	48 8d 3d de 1a dd 00 	lea    rdi,[rip+0xdd1ade]        # 0x1277a78
  4a5f9a:	45 89 f8             	mov    r8d,r15d
  4a5f9d:	31 c0                	xor    eax,eax
  4a5f9f:	e8 6c 74 db ff       	call   0x25d410
  4a5fa4:	41 83 fd 05          	cmp    r13d,0x5
  4a5fa8:	72 4e                	jb     0x4a5ff8
  4a5faa:	0f b6 73 04          	movzx  esi,BYTE PTR [rbx+0x4]
  4a5fae:	48 8d 3d 89 90 f0 00 	lea    rdi,[rip+0xf09089]        # 0x13af03e
  4a5fb5:	31 c0                	xor    eax,eax
  4a5fb7:	e8 54 74 db ff       	call   0x25d410
  4a5fbc:	66 41 83 fd 05       	cmp    r13w,0x5
  4a5fc1:	74 35                	je     0x4a5ff8
  4a5fc3:	44 89 f8             	mov    eax,r15d
  4a5fc6:	41 bf 05 00 00 00    	mov    r15d,0x5
  4a5fcc:	4c 8d 35 7d 6c e7 00 	lea    r14,[rip+0xe76c7d]        # 0x131cc50
  4a5fd3:	4c 39 e0             	cmp    rax,r12
  4a5fd6:	4c 0f 42 e0          	cmovb  r12,rax
  4a5fda:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4a5fe0:	42 0f b6 34 3b       	movzx  esi,BYTE PTR [rbx+r15*1]
  4a5fe5:	4c 89 f7             	mov    rdi,r14
  4a5fe8:	31 c0                	xor    eax,eax
  4a5fea:	e8 21 74 db ff       	call   0x25d410
  4a5fef:	49 ff c7             	inc    r15
  4a5ff2:	66 45 39 fc          	cmp    r12w,r15w
  4a5ff6:	75 e8                	jne    0x4a5fe0
  4a5ff8:	48 8d 05 11 63 47 03 	lea    rax,[rip+0x3476311]        # 0x391c310
  4a5fff:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a6002:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6006:	0f 85 9d 03 00 00    	jne    0x4a63a9
  4a600c:	48 8d 3d 8b 62 eb 00 	lea    rdi,[rip+0xeb628b]        # 0x135c29e
  4a6013:	e9 88 01 00 00       	jmp    0x4a61a0
  4a6018:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  4a601b:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a601f:	0f 85 84 03 00 00    	jne    0x4a63a9
  4a6025:	48 83 c6 60          	add    rsi,0x60
  4a6029:	48 8d 3d 68 9c ee 00 	lea    rdi,[rip+0xee9c68]        # 0x138fc98
  4a6030:	e9 c5 00 00 00       	jmp    0x4a60fa
  4a6035:	48 8d 3d db 3a e9 00 	lea    rdi,[rip+0xe93adb]        # 0x1339b17
  4a603c:	31 c0                	xor    eax,eax
  4a603e:	e8 cd 73 db ff       	call   0x25d410
  4a6043:	49 8d 9e 88 01 00 00 	lea    rbx,[r14+0x188]
  4a604a:	31 f6                	xor    esi,esi
  4a604c:	31 d2                	xor    edx,edx
  4a604e:	31 c9                	xor    ecx,ecx
  4a6050:	48 89 df             	mov    rdi,rbx
  4a6053:	e8 a8 09 02 00       	call   0x4c6a00
  4a6058:	41 c7 86 10 01 00 00 	mov    DWORD PTR [r14+0x110],0x0
  4a605f:	00 00 00 00 
  4a6063:	41 80 a6 80 00 00 00 	and    BYTE PTR [r14+0x80],0xef
  4a606a:	ef 
  4a606b:	66 41 81 be 80 03 00 	cmp    WORD PTR [r14+0x380],0xc023
  4a6072:	00 23 c0 
  4a6075:	75 44                	jne    0x4a60bb
  4a6077:	41 f6 86 10 03 00 00 	test   BYTE PTR [r14+0x310],0x8
  4a607e:	08 
  4a607f:	74 3a                	je     0x4a60bb
  4a6081:	41 f6 86 30 03 00 00 	test   BYTE PTR [r14+0x330],0x8
  4a6088:	08 
  4a6089:	75 30                	jne    0x4a60bb
  4a608b:	48 8d 05 7e 62 47 03 	lea    rax,[rip+0x347627e]        # 0x391c310
  4a6092:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a6095:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6099:	0f 85 0a 03 00 00    	jne    0x4a63a9
  4a609f:	48 89 df             	mov    rdi,rbx
  4a60a2:	31 f6                	xor    esi,esi
  4a60a4:	31 d2                	xor    edx,edx
  4a60a6:	31 c9                	xor    ecx,ecx
  4a60a8:	48 83 c4 28          	add    rsp,0x28
  4a60ac:	5b                   	pop    rbx
  4a60ad:	41 5c                	pop    r12
  4a60af:	41 5d                	pop    r13
  4a60b1:	41 5e                	pop    r14
  4a60b3:	41 5f                	pop    r15
  4a60b5:	5d                   	pop    rbp
  4a60b6:	e9 e5 0e 02 00       	jmp    0x4c6fa0
  4a60bb:	48 89 df             	mov    rdi,rbx
  4a60be:	31 f6                	xor    esi,esi
  4a60c0:	31 d2                	xor    edx,edx
  4a60c2:	31 c9                	xor    ecx,ecx
  4a60c4:	e8 d7 0e 02 00       	call   0x4c6fa0
  4a60c9:	41 83 be 18 01 00 00 	cmp    DWORD PTR [r14+0x118],0x4
  4a60d0:	04 
  4a60d1:	0f 85 de 00 00 00    	jne    0x4a61b5
  4a60d7:	48 8d 05 32 62 47 03 	lea    rax,[rip+0x3476232]        # 0x391c310
  4a60de:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a60e1:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a60e5:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  4a60e9:	0f 85 ba 02 00 00    	jne    0x4a63a9
  4a60ef:	48 83 c6 60          	add    rsi,0x60
  4a60f3:	48 8d 3d 10 b4 ea 00 	lea    rdi,[rip+0xeab410]        # 0x135150a
  4a60fa:	31 c0                	xor    eax,eax
  4a60fc:	48 83 c4 28          	add    rsp,0x28
  4a6100:	5b                   	pop    rbx
  4a6101:	41 5c                	pop    r12
  4a6103:	41 5d                	pop    r13
  4a6105:	41 5e                	pop    r14
  4a6107:	41 5f                	pop    r15
  4a6109:	5d                   	pop    rbp
  4a610a:	e9 01 73 db ff       	jmp    0x25d410
  4a610f:	48 8d 3d 43 82 dc 00 	lea    rdi,[rip+0xdc8243]        # 0x126e359
  4a6116:	31 c0                	xor    eax,eax
  4a6118:	e8 f3 72 db ff       	call   0x25d410
  4a611d:	0f b6 03             	movzx  eax,BYTE PTR [rbx]
  4a6120:	41 83 fd 06          	cmp    r13d,0x6
  4a6124:	0f 93 c1             	setae  cl
  4a6127:	84 c0                	test   al,al
  4a6129:	0f 95 c2             	setne  dl
  4a612c:	20 ca                	and    dl,cl
  4a612e:	80 fa 01             	cmp    dl,0x1
  4a6131:	75 52                	jne    0x4a6185
  4a6133:	48 8d 3d 5b 9b ee 00 	lea    rdi,[rip+0xee9b5b]        # 0x138fc95
  4a613a:	44 0f be f0          	movsx  r14d,al
  4a613e:	31 c0                	xor    eax,eax
  4a6140:	e8 cb 72 db ff       	call   0x25d410
  4a6145:	45 0f b7 f6          	movzx  r14d,r14w
  4a6149:	4c 8d 3d 1d 6b e7 00 	lea    r15,[rip+0xe76b1d]        # 0x131cc6d
  4a6150:	4c 8d 25 32 9e e8 00 	lea    r12,[rip+0xe89e32]        # 0x132ff89
  4a6157:	45 31 ed             	xor    r13d,r13d
  4a615a:	eb 14                	jmp    0x4a6170
  4a615c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  4a6160:	31 c0                	xor    eax,eax
  4a6162:	e8 a9 72 db ff       	call   0x25d410
  4a6167:	49 ff c5             	inc    r13
  4a616a:	66 45 39 ee          	cmp    r14w,r13w
  4a616e:	74 15                	je     0x4a6185
  4a6170:	42 0f b6 74 2b 04    	movzx  esi,BYTE PTR [rbx+r13*1+0x4]
  4a6176:	4c 89 ff             	mov    rdi,r15
  4a6179:	8d 46 81             	lea    eax,[rsi-0x7f]
  4a617c:	3c a1                	cmp    al,0xa1
  4a617e:	72 e0                	jb     0x4a6160
  4a6180:	4c 89 e7             	mov    rdi,r12
  4a6183:	eb db                	jmp    0x4a6160
  4a6185:	48 8d 05 84 61 47 03 	lea    rax,[rip+0x3476184]        # 0x391c310
  4a618c:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a618f:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6193:	0f 85 10 02 00 00    	jne    0x4a63a9
  4a6199:	48 8d 3d 77 39 e9 00 	lea    rdi,[rip+0xe93977]        # 0x1339b17
  4a61a0:	31 c0                	xor    eax,eax
  4a61a2:	48 83 c4 28          	add    rsp,0x28
  4a61a6:	5b                   	pop    rbx
  4a61a7:	41 5c                	pop    r12
  4a61a9:	41 5d                	pop    r13
  4a61ab:	41 5e                	pop    r14
  4a61ad:	41 5f                	pop    r15
  4a61af:	5d                   	pop    rbp
  4a61b0:	e9 5b 72 db ff       	jmp    0x25d410
  4a61b5:	48 8d 05 54 61 47 03 	lea    rax,[rip+0x3476154]        # 0x391c310
  4a61bc:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a61bf:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a61c3:	0f 85 e0 01 00 00    	jne    0x4a63a9
  4a61c9:	4c 89 f7             	mov    rdi,r14
  4a61cc:	48 83 c4 28          	add    rsp,0x28
  4a61d0:	5b                   	pop    rbx
  4a61d1:	41 5c                	pop    r12
  4a61d3:	41 5d                	pop    r13
  4a61d5:	41 5e                	pop    r14
  4a61d7:	41 5f                	pop    r15
  4a61d9:	5d                   	pop    rbp
  4a61da:	e9 91 50 00 00       	jmp    0x4ab270
  4a61df:	4a 8d 4c 23 06       	lea    rcx,[rbx+r12*1+0x6]
  4a61e4:	48 8d 43 05          	lea    rax,[rbx+0x5]
  4a61e8:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  4a61ec:	48 89 4d b8          	mov    QWORD PTR [rbp-0x48],rcx
  4a61f0:	41 f6 c0 04          	test   r8b,0x4
  4a61f4:	74 7e                	je     0x4a6274
  4a61f6:	41 8b 86 38 01 00 00 	mov    eax,DWORD PTR [r14+0x138]
  4a61fd:	48 83 c6 60          	add    rsi,0x60
  4a6201:	49 89 fd             	mov    r13,rdi
  4a6204:	48 83 f8 09          	cmp    rax,0x9
  4a6208:	77 0d                	ja     0x4a6217
  4a620a:	48 8d 0d a7 99 9d 00 	lea    rcx,[rip+0x9d99a7]        # 0xe7fbb8
  4a6211:	48 8b 14 c1          	mov    rdx,QWORD PTR [rcx+rax*8]
  4a6215:	eb 07                	jmp    0x4a621e
  4a6217:	48 8d 15 67 42 ef 00 	lea    rdx,[rip+0xef4267]        # 0x139a485
  4a621e:	44 0f b6 43 01       	movzx  r8d,BYTE PTR [rbx+0x1]
  4a6223:	48 8d 3d 4f 71 e5 00 	lea    rdi,[rip+0xe5714f]        # 0x12fd379
  4a622a:	48 8d 0d 1b 55 de 00 	lea    rcx,[rip+0xde551b]        # 0x128b74c
  4a6231:	45 89 f9             	mov    r9d,r15d
  4a6234:	31 c0                	xor    eax,eax
  4a6236:	e8 d5 71 db ff       	call   0x25d410
  4a623b:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  4a623f:	41 0f b7 f4          	movzx  esi,r12w
  4a6243:	e8 48 72 00 00       	call   0x4ad490
  4a6248:	48 8d 3d c2 c9 e4 00 	lea    rdi,[rip+0xe4c9c2]        # 0x12f2c11
  4a624f:	31 c0                	xor    eax,eax
  4a6251:	e8 ba 71 db ff       	call   0x25d410
  4a6256:	0f b7 75 c0          	movzx  esi,WORD PTR [rbp-0x40]
  4a625a:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  4a625e:	e8 2d 72 00 00       	call   0x4ad490
  4a6263:	48 8d 3d 34 60 eb 00 	lea    rdi,[rip+0xeb6034]        # 0x135c29e
  4a626a:	31 c0                	xor    eax,eax
  4a626c:	e8 9f 71 db ff       	call   0x25d410
  4a6271:	4c 89 ef             	mov    rdi,r13
  4a6274:	41 0f b6 86 c8 03 00 	movzx  eax,BYTE PTR [r14+0x3c8]
  4a627b:	00 
  4a627c:	49 89 ff             	mov    r15,rdi
  4a627f:	41 39 c4             	cmp    r12d,eax
  4a6282:	75 3b                	jne    0x4a62bf
  4a6284:	41 0f b6 86 c9 03 00 	movzx  eax,BYTE PTR [r14+0x3c9]
  4a628b:	00 
  4a628c:	39 45 c0             	cmp    DWORD PTR [rbp-0x40],eax
  4a628f:	75 2e                	jne    0x4a62bf
  4a6291:	49 8b b6 b8 03 00 00 	mov    rsi,QWORD PTR [r14+0x3b8]
  4a6298:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  4a629c:	4c 89 e2             	mov    rdx,r12
  4a629f:	e8 2c 39 e9 ff       	call   0x339bd0
  4a62a4:	85 c0                	test   eax,eax
  4a62a6:	75 17                	jne    0x4a62bf
  4a62a8:	49 8b b6 c0 03 00 00 	mov    rsi,QWORD PTR [r14+0x3c0]
  4a62af:	8b 55 c0             	mov    edx,DWORD PTR [rbp-0x40]
  4a62b2:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  4a62b6:	e8 15 39 e9 ff       	call   0x339bd0
  4a62bb:	85 c0                	test   eax,eax
  4a62bd:	74 68                	je     0x4a6327
  4a62bf:	41 ff 86 10 01 00 00 	inc    DWORD PTR [r14+0x110]
  4a62c6:	c6 45 cf 09          	mov    BYTE PTR [rbp-0x31],0x9
  4a62ca:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a62ce:	48 83 ec 08          	sub    rsp,0x8
  4a62d2:	4c 8d 15 5f 9c f0 00 	lea    r10,[rip+0xf09c5f]        # 0x13aff38
  4a62d9:	48 8d 3d c0 96 9d 00 	lea    rdi,[rip+0x9d96c0]        # 0xe7f9a0
  4a62e0:	4c 8d 4d cf          	lea    r9,[rbp-0x31]
  4a62e4:	41 b8 01 00 00 00    	mov    r8d,0x1
  4a62ea:	4c 89 f6             	mov    rsi,r14
  4a62ed:	ba 03 00 00 00       	mov    edx,0x3
  4a62f2:	31 c0                	xor    eax,eax
  4a62f4:	6a 00                	push   0x0
  4a62f6:	41 52                	push   r10
  4a62f8:	6a 09                	push   0x9
  4a62fa:	e8 11 50 00 00       	call   0x4ab310
  4a62ff:	48 83 c4 20          	add    rsp,0x20
  4a6303:	4c 89 f7             	mov    rdi,r14
  4a6306:	e8 b5 4d 00 00       	call   0x4ab0c0
  4a630b:	49 8b 07             	mov    rax,QWORD PTR [r15]
  4a630e:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6312:	0f 85 91 00 00 00    	jne    0x4a63a9
  4a6318:	48 83 c4 28          	add    rsp,0x28
  4a631c:	5b                   	pop    rbx
  4a631d:	41 5c                	pop    r12
  4a631f:	41 5d                	pop    r13
  4a6321:	41 5e                	pop    r14
  4a6323:	41 5f                	pop    r15
  4a6325:	5d                   	pop    rbp
  4a6326:	c3                   	ret
  4a6327:	41 8b 86 38 01 00 00 	mov    eax,DWORD PTR [r14+0x138]
  4a632e:	83 f8 09             	cmp    eax,0x9
  4a6331:	74 05                	je     0x4a6338
  4a6333:	83 f8 06             	cmp    eax,0x6
  4a6336:	75 44                	jne    0x4a637c
  4a6338:	c6 45 cf 08          	mov    BYTE PTR [rbp-0x31],0x8
  4a633c:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a6340:	48 83 ec 08          	sub    rsp,0x8
  4a6344:	31 c0                	xor    eax,eax
  4a6346:	4c 8d 15 22 17 dd 00 	lea    r10,[rip+0xdd1722]        # 0x1277a6f
  4a634d:	48 8d 3d 4c 96 9d 00 	lea    rdi,[rip+0x9d964c]        # 0xe7f9a0
  4a6354:	4c 8d 4d cf          	lea    r9,[rbp-0x31]
  4a6358:	41 b8 01 00 00 00    	mov    r8d,0x1
  4a635e:	4c 89 f6             	mov    rsi,r14
  4a6361:	ba 02 00 00 00       	mov    edx,0x2
  4a6366:	6a 00                	push   0x0
  4a6368:	41 52                	push   r10
  4a636a:	6a 08                	push   0x8
  4a636c:	e8 9f 4f 00 00       	call   0x4ab310
  4a6371:	48 83 c4 20          	add    rsp,0x20
  4a6375:	41 8b 86 38 01 00 00 	mov    eax,DWORD PTR [r14+0x138]
  4a637c:	83 f8 06             	cmp    eax,0x6
  4a637f:	75 8a                	jne    0x4a630b
  4a6381:	49 8d be 50 02 00 00 	lea    rdi,[r14+0x250]
  4a6388:	41 c7 86 38 01 00 00 	mov    DWORD PTR [r14+0x138],0x9
  4a638f:	09 00 00 00 
  4a6393:	31 f6                	xor    esi,esi
  4a6395:	31 d2                	xor    edx,edx
  4a6397:	e8 34 4c 6f 00       	call   0xb9afd0
  4a639c:	4c 89 f7             	mov    rdi,r14
  4a639f:	e8 7c 4c 00 00       	call   0x4ab020
  4a63a4:	e9 62 ff ff ff       	jmp    0x4a630b
  4a63a9:	e8 02 73 25 00       	call   0x6fd6b0
  4a63ae:	0f 0b                	ud2
  4a63b0:	55                   	push   rbp
  4a63b1:	48 89 e5             	mov    rbp,rsp
  4a63b4:	41 57                	push   r15
  4a63b6:	41 56                	push   r14
  4a63b8:	41 55                	push   r13
  4a63ba:	41 54                	push   r12
  4a63bc:	53                   	push   rbx
  4a63bd:	48 81 ec a8 00 00 00 	sub    rsp,0xa8
  4a63c4:	4c 8d 25 45 5f 47 03 	lea    r12,[rip+0x3475f45]        # 0x391c310
  4a63cb:	48 89 f0             	mov    rax,rsi
  4a63ce:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  4a63d2:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  4a63d6:	48 8b 37             	mov    rsi,QWORD PTR [rdi]
  4a63d9:	44 8b 70 30          	mov    r14d,DWORD PTR [rax+0x30]
  4a63dd:	41 83 fe 03          	cmp    r14d,0x3
  4a63e1:	7f 34                	jg     0x4a6417
  4a63e3:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a63e7:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a63eb:	0f 85 79 0a 00 00    	jne    0x4a6e6a
  4a63f1:	48 83 c6 60          	add    rsi,0x60
  4a63f5:	48 8d 3d a5 b0 ea 00 	lea    rdi,[rip+0xeab0a5]        # 0x13514a1
  4a63fc:	44 89 f2             	mov    edx,r14d
  4a63ff:	31 c0                	xor    eax,eax
  4a6401:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a6408:	5b                   	pop    rbx
  4a6409:	41 5c                	pop    r12
  4a640b:	41 5d                	pop    r13
  4a640d:	41 5e                	pop    r14
  4a640f:	41 5f                	pop    r15
  4a6411:	5d                   	pop    rbp
  4a6412:	e9 f9 6f db ff       	jmp    0x25d410
  4a6417:	48 8b 58 10          	mov    rbx,QWORD PTR [rax+0x10]
  4a641b:	66 0f 38 f0 43 02    	movbe  ax,WORD PTR [rbx+0x2]
  4a6421:	0f b6 0b             	movzx  ecx,BYTE PTR [rbx]
  4a6424:	44 0f b7 e8          	movzx  r13d,ax
  4a6428:	8d 41 ff             	lea    eax,[rcx-0x1]
  4a642b:	45 39 ee             	cmp    r14d,r13d
  4a642e:	45 89 ef             	mov    r15d,r13d
  4a6431:	45 0f 42 fe          	cmovb  r15d,r14d
  4a6435:	83 f8 03             	cmp    eax,0x3
  4a6438:	0f 87 5d 02 00 00    	ja     0x4a669b
  4a643e:	48 8d 0d 93 dc 0e 01 	lea    rcx,[rip+0x10edc93]        # 0x15940d8
  4a6445:	44 8b 46 78          	mov    r8d,DWORD PTR [rsi+0x78]
  4a6449:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
  4a644d:	48 01 c8             	add    rax,rcx
  4a6450:	ff e0                	jmp    rax
  4a6452:	41 83 ff 05          	cmp    r15d,0x5
  4a6456:	0f 82 f2 09 00 00    	jb     0x4a6e4e
  4a645c:	48 8d 87 88 01 00 00 	lea    rax,[rdi+0x188]
  4a6463:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
  4a646a:	49 89 f5             	mov    r13,rsi
  4a646d:	45 89 c6             	mov    r14d,r8d
  4a6470:	31 f6                	xor    esi,esi
  4a6472:	31 d2                	xor    edx,edx
  4a6474:	31 c9                	xor    ecx,ecx
  4a6476:	48 89 c7             	mov    rdi,rax
  4a6479:	48 89 85 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],rax
  4a6480:	e8 7b 05 02 00       	call   0x4c6a00
  4a6485:	48 8b 85 58 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa8]
  4a648c:	48 83 b8 88 03 00 00 	cmp    QWORD PTR [rax+0x388],0x0
  4a6493:	00 
  4a6494:	0f 84 79 04 00 00    	je     0x4a6913
  4a649a:	0f b6 43 04          	movzx  eax,BYTE PTR [rbx+0x4]
  4a649e:	45 89 fc             	mov    r12d,r15d
  4a64a1:	41 29 c4             	sub    r12d,eax
  4a64a4:	48 89 85 40 ff ff ff 	mov    QWORD PTR [rbp-0xc0],rax
  4a64ab:	41 83 fc 04          	cmp    r12d,0x4
  4a64af:	0f 8f aa 04 00 00    	jg     0x4a695f
  4a64b5:	0f b6 33             	movzx  esi,BYTE PTR [rbx]
  4a64b8:	bf 23 c2 00 00       	mov    edi,0xc223
  4a64bd:	4c 8d 73 04          	lea    r14,[rbx+0x4]
  4a64c1:	49 83 c5 60          	add    r13,0x60
  4a64c5:	e8 16 53 00 00       	call   0x4ab7e0
  4a64ca:	66 0f 38 f0 53 02    	movbe  dx,WORD PTR [rbx+0x2]
  4a64d0:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a64d4:	48 8d 3d 2b f0 ed 00 	lea    rdi,[rip+0xedf02b]        # 0x1385506
  4a64db:	4c 89 ee             	mov    rsi,r13
  4a64de:	44 0f b7 c2          	movzx  r8d,dx
  4a64e2:	48 89 c2             	mov    rdx,rax
  4a64e5:	31 c0                	xor    eax,eax
  4a64e7:	e8 24 6f db ff       	call   0x25d410
  4a64ec:	41 83 c7 fc          	add    r15d,0xfffffffc
  4a64f0:	4c 89 f7             	mov    rdi,r14
  4a64f3:	41 0f b7 f7          	movzx  esi,r15w
  4a64f7:	e8 54 53 00 00       	call   0x4ab850
  4a64fc:	48 8d 3d 9b 5d eb 00 	lea    rdi,[rip+0xeb5d9b]        # 0x135c29e
  4a6503:	31 c0                	xor    eax,eax
  4a6505:	e8 06 6f db ff       	call   0x25d410
  4a650a:	48 8d 05 ff 5d 47 03 	lea    rax,[rip+0x3475dff]        # 0x391c310
  4a6511:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a6514:	e9 19 04 00 00       	jmp    0x4a6932
  4a6519:	48 89 b5 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],rsi
  4a6520:	41 f6 c0 04          	test   r8b,0x4
  4a6524:	0f 84 b1 01 00 00    	je     0x4a66db
  4a652a:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
  4a6531:	48 8d 3d 37 ff e9 00 	lea    rdi,[rip+0xe9ff37]        # 0x134646f
  4a6538:	48 8b 85 48 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb8]
  4a653f:	48 8d 70 60          	lea    rsi,[rax+0x60]
  4a6543:	31 c0                	xor    eax,eax
  4a6545:	e8 c6 6e db ff       	call   0x25d410
  4a654a:	41 83 ff 05          	cmp    r15d,0x5
  4a654e:	0f 82 6b 01 00 00    	jb     0x4a66bf
  4a6554:	48 8d 3d 3a 97 ee 00 	lea    rdi,[rip+0xee973a]        # 0x138fc95
  4a655b:	31 c0                	xor    eax,eax
  4a655d:	e8 ae 6e db ff       	call   0x25d410
  4a6562:	44 89 e8             	mov    eax,r13d
  4a6565:	41 bf 04 00 00 00    	mov    r15d,0x4
  4a656b:	4c 8d 2d fb 66 e7 00 	lea    r13,[rip+0xe766fb]        # 0x131cc6d
  4a6572:	4c 8d 25 10 9a e8 00 	lea    r12,[rip+0xe89a10]        # 0x132ff89
  4a6579:	4c 39 f0             	cmp    rax,r14
  4a657c:	4c 0f 42 f0          	cmovb  r14,rax
  4a6580:	eb 22                	jmp    0x4a65a4
  4a6582:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  4a6589:	1f 84 00 00 00 00 00 
  4a6590:	31 c0                	xor    eax,eax
  4a6592:	e8 79 6e db ff       	call   0x25d410
  4a6597:	49 ff c7             	inc    r15
  4a659a:	66 45 39 fe          	cmp    r14w,r15w
  4a659e:	0f 84 1b 01 00 00    	je     0x4a66bf
  4a65a4:	42 0f b6 34 3b       	movzx  esi,BYTE PTR [rbx+r15*1]
  4a65a9:	4c 89 ef             	mov    rdi,r13
  4a65ac:	8d 46 81             	lea    eax,[rsi-0x7f]
  4a65af:	3c a1                	cmp    al,0xa1
  4a65b1:	72 dd                	jb     0x4a6590
  4a65b3:	4c 89 e7             	mov    rdi,r12
  4a65b6:	eb d8                	jmp    0x4a6590
  4a65b8:	4c 8d a7 88 01 00 00 	lea    r12,[rdi+0x188]
  4a65bf:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
  4a65c6:	48 89 b5 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],rsi
  4a65cd:	31 f6                	xor    esi,esi
  4a65cf:	31 d2                	xor    edx,edx
  4a65d1:	31 c9                	xor    ecx,ecx
  4a65d3:	44 89 85 50 ff ff ff 	mov    DWORD PTR [rbp-0xb0],r8d
  4a65da:	4c 89 e7             	mov    rdi,r12
  4a65dd:	e8 1e 04 02 00       	call   0x4c6a00
  4a65e2:	48 8b 85 58 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa8]
  4a65e9:	4c 89 e7             	mov    rdi,r12
  4a65ec:	31 f6                	xor    esi,esi
  4a65ee:	31 d2                	xor    edx,edx
  4a65f0:	31 c9                	xor    ecx,ecx
  4a65f2:	ff 80 10 01 00 00    	inc    DWORD PTR [rax+0x110]
  4a65f8:	e8 a3 09 02 00       	call   0x4c6fa0
  4a65fd:	48 8b b5 48 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xb8]
  4a6604:	48 83 c6 60          	add    rsi,0x60
  4a6608:	f6 85 50 ff ff ff 04 	test   BYTE PTR [rbp-0xb0],0x4
  4a660f:	0f 85 6a 01 00 00    	jne    0x4a677f
  4a6615:	48 8d 05 f4 5c 47 03 	lea    rax,[rip+0x3475cf4]        # 0x391c310
  4a661c:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a661f:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6623:	0f 85 41 08 00 00    	jne    0x4a6e6a
  4a6629:	48 8d 3d 9b ae ea 00 	lea    rdi,[rip+0xeaae9b]        # 0x13514cb
  4a6630:	e9 c6 02 00 00       	jmp    0x4a68fb
  4a6635:	48 83 bf c0 03 00 00 	cmp    QWORD PTR [rdi+0x3c0],0x0
  4a663c:	00 
  4a663d:	0f 84 9f 02 00 00    	je     0x4a68e2
  4a6643:	41 83 ff 05          	cmp    r15d,0x5
  4a6647:	0f 82 01 08 00 00    	jb     0x4a6e4e
  4a664d:	44 0f b6 63 04       	movzx  r12d,BYTE PTR [rbx+0x4]
  4a6652:	45 89 fe             	mov    r14d,r15d
  4a6655:	45 29 e6             	sub    r14d,r12d
  4a6658:	41 83 fe 04          	cmp    r14d,0x4
  4a665c:	0f 8f 60 04 00 00    	jg     0x4a6ac2
  4a6662:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a6666:	48 83 c6 60          	add    rsi,0x60
  4a666a:	48 8d 3d 39 5c eb 00 	lea    rdi,[rip+0xeb5c39]        # 0x135c2aa
  4a6671:	48 8d 15 a7 b8 e6 00 	lea    rdx,[rip+0xe6b8a7]        # 0x1311f1f
  4a6678:	45 89 e8             	mov    r8d,r13d
  4a667b:	31 c0                	xor    eax,eax
  4a667d:	48 83 c3 04          	add    rbx,0x4
  4a6681:	e8 8a 6d db ff       	call   0x25d410
  4a6686:	41 83 c7 fc          	add    r15d,0xfffffffc
  4a668a:	48 89 df             	mov    rdi,rbx
  4a668d:	41 0f b7 f7          	movzx  esi,r15w
  4a6691:	e8 ba 51 00 00       	call   0x4ab850
  4a6696:	e9 ed 01 00 00       	jmp    0x4a6888
  4a669b:	8b 87 3c 01 00 00    	mov    eax,DWORD PTR [rdi+0x13c]
  4a66a1:	48 83 c6 60          	add    rsi,0x60
  4a66a5:	48 83 f8 09          	cmp    rax,0x9
  4a66a9:	0f 87 65 01 00 00    	ja     0x4a6814
  4a66af:	48 8d 15 02 95 9d 00 	lea    rdx,[rip+0x9d9502]        # 0xe7fbb8
  4a66b6:	48 8b 14 c2          	mov    rdx,QWORD PTR [rdx+rax*8]
  4a66ba:	e9 5c 01 00 00       	jmp    0x4a681b
  4a66bf:	48 8d 3d 51 34 e9 00 	lea    rdi,[rip+0xe93451]        # 0x1339b17
  4a66c6:	31 c0                	xor    eax,eax
  4a66c8:	e8 43 6d db ff       	call   0x25d410
  4a66cd:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  4a66d4:	4c 8d 25 35 5c 47 03 	lea    r12,[rip+0x3475c35]        # 0x391c310
  4a66db:	48 8d 9f 88 01 00 00 	lea    rbx,[rdi+0x188]
  4a66e2:	49 89 fe             	mov    r14,rdi
  4a66e5:	31 f6                	xor    esi,esi
  4a66e7:	31 d2                	xor    edx,edx
  4a66e9:	31 c9                	xor    ecx,ecx
  4a66eb:	48 89 df             	mov    rdi,rbx
  4a66ee:	e8 0d 03 02 00       	call   0x4c6a00
  4a66f3:	41 c7 86 10 01 00 00 	mov    DWORD PTR [r14+0x110],0x0
  4a66fa:	00 00 00 00 
  4a66fe:	41 80 a6 80 00 00 00 	and    BYTE PTR [r14+0x80],0xef
  4a6705:	ef 
  4a6706:	66 41 81 be 80 03 00 	cmp    WORD PTR [r14+0x380],0xc223
  4a670d:	00 23 c2 
  4a6710:	75 2c                	jne    0x4a673e
  4a6712:	41 f6 86 10 03 00 00 	test   BYTE PTR [r14+0x310],0x8
  4a6719:	08 
  4a671a:	4c 89 f0             	mov    rax,r14
  4a671d:	74 1f                	je     0x4a673e
  4a671f:	f6 80 30 03 00 00 10 	test   BYTE PTR [rax+0x330],0x10
  4a6726:	75 16                	jne    0x4a673e
  4a6728:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a672c:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6730:	0f 85 34 07 00 00    	jne    0x4a6e6a
  4a6736:	48 89 df             	mov    rdi,rbx
  4a6739:	e9 05 02 00 00       	jmp    0x4a6943
  4a673e:	48 89 df             	mov    rdi,rbx
  4a6741:	31 f6                	xor    esi,esi
  4a6743:	31 d2                	xor    edx,edx
  4a6745:	31 c9                	xor    ecx,ecx
  4a6747:	e8 54 08 02 00       	call   0x4c6fa0
  4a674c:	41 83 be 18 01 00 00 	cmp    DWORD PTR [r14+0x118],0x4
  4a6753:	04 
  4a6754:	0f 85 61 01 00 00    	jne    0x4a68bb
  4a675a:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a675e:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6762:	48 8b b5 48 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xb8]
  4a6769:	0f 85 fb 06 00 00    	jne    0x4a6e6a
  4a676f:	48 83 c6 60          	add    rsi,0x60
  4a6773:	48 8d 3d fc b1 e8 00 	lea    rdi,[rip+0xe8b1fc]        # 0x1331976
  4a677a:	e9 7c 01 00 00       	jmp    0x4a68fb
  4a677f:	48 8d 3d fa fc e9 00 	lea    rdi,[rip+0xe9fcfa]        # 0x1346480
  4a6786:	31 c0                	xor    eax,eax
  4a6788:	e8 83 6c db ff       	call   0x25d410
  4a678d:	41 83 ff 05          	cmp    r15d,0x5
  4a6791:	72 61                	jb     0x4a67f4
  4a6793:	48 8d 3d fb 94 ee 00 	lea    rdi,[rip+0xee94fb]        # 0x138fc95
  4a679a:	31 c0                	xor    eax,eax
  4a679c:	e8 6f 6c db ff       	call   0x25d410
  4a67a1:	44 89 e8             	mov    eax,r13d
  4a67a4:	41 bf 04 00 00 00    	mov    r15d,0x4
  4a67aa:	4c 8d 25 bc 64 e7 00 	lea    r12,[rip+0xe764bc]        # 0x131cc6d
  4a67b1:	4c 8d 2d d1 97 e8 00 	lea    r13,[rip+0xe897d1]        # 0x132ff89
  4a67b8:	4c 39 f0             	cmp    rax,r14
  4a67bb:	4c 0f 42 f0          	cmovb  r14,rax
  4a67bf:	eb 1f                	jmp    0x4a67e0
  4a67c1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  4a67c8:	0f 1f 84 00 00 00 00 
  4a67cf:	00 
  4a67d0:	31 c0                	xor    eax,eax
  4a67d2:	e8 39 6c db ff       	call   0x25d410
  4a67d7:	49 ff c7             	inc    r15
  4a67da:	66 45 39 fe          	cmp    r14w,r15w
  4a67de:	74 14                	je     0x4a67f4
  4a67e0:	42 0f b6 34 3b       	movzx  esi,BYTE PTR [rbx+r15*1]
  4a67e5:	4c 89 e7             	mov    rdi,r12
  4a67e8:	8d 46 81             	lea    eax,[rsi-0x7f]
  4a67eb:	3c a1                	cmp    al,0xa1
  4a67ed:	72 e1                	jb     0x4a67d0
  4a67ef:	4c 89 ef             	mov    rdi,r13
  4a67f2:	eb dc                	jmp    0x4a67d0
  4a67f4:	48 8d 05 15 5b 47 03 	lea    rax,[rip+0x3475b15]        # 0x391c310
  4a67fb:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a67fe:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6802:	0f 85 62 06 00 00    	jne    0x4a6e6a
  4a6808:	48 8d 3d 08 33 e9 00 	lea    rdi,[rip+0xe93308]        # 0x1339b17
  4a680f:	e9 8f 00 00 00       	jmp    0x4a68a3
  4a6814:	48 8d 15 6a 3c ef 00 	lea    rdx,[rip+0xef3c6a]        # 0x139a485
  4a681b:	44 0f b6 43 01       	movzx  r8d,BYTE PTR [rbx+0x1]
  4a6820:	48 8d 3d d4 3c ef 00 	lea    rdi,[rip+0xef3cd4]        # 0x139a4fb
  4a6827:	45 89 e9             	mov    r9d,r13d
  4a682a:	31 c0                	xor    eax,eax
  4a682c:	e8 df 6b db ff       	call   0x25d410
  4a6831:	41 83 ff 05          	cmp    r15d,0x5
  4a6835:	72 51                	jb     0x4a6888
  4a6837:	0f b6 73 04          	movzx  esi,BYTE PTR [rbx+0x4]
  4a683b:	48 8d 3d fc 87 f0 00 	lea    rdi,[rip+0xf087fc]        # 0x13af03e
  4a6842:	31 c0                	xor    eax,eax
  4a6844:	e8 c7 6b db ff       	call   0x25d410
  4a6849:	66 41 83 ff 05       	cmp    r15w,0x5
  4a684e:	74 38                	je     0x4a6888
  4a6850:	44 89 e8             	mov    eax,r13d
  4a6853:	41 bc 05 00 00 00    	mov    r12d,0x5
  4a6859:	4c 8d 3d f0 63 e7 00 	lea    r15,[rip+0xe763f0]        # 0x131cc50
  4a6860:	4c 39 f0             	cmp    rax,r14
  4a6863:	4c 0f 42 f0          	cmovb  r14,rax
  4a6867:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  4a686e:	00 00 
  4a6870:	42 0f b6 34 23       	movzx  esi,BYTE PTR [rbx+r12*1]
  4a6875:	4c 89 ff             	mov    rdi,r15
  4a6878:	31 c0                	xor    eax,eax
  4a687a:	e8 91 6b db ff       	call   0x25d410
  4a687f:	49 ff c4             	inc    r12
  4a6882:	66 45 39 e6          	cmp    r14w,r12w
  4a6886:	75 e8                	jne    0x4a6870
  4a6888:	48 8d 05 81 5a 47 03 	lea    rax,[rip+0x3475a81]        # 0x391c310
  4a688f:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a6892:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6896:	0f 85 ce 05 00 00    	jne    0x4a6e6a
  4a689c:	48 8d 3d fb 59 eb 00 	lea    rdi,[rip+0xeb59fb]        # 0x135c29e
  4a68a3:	31 c0                	xor    eax,eax
  4a68a5:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a68ac:	5b                   	pop    rbx
  4a68ad:	41 5c                	pop    r12
  4a68af:	41 5d                	pop    r13
  4a68b1:	41 5e                	pop    r14
  4a68b3:	41 5f                	pop    r15
  4a68b5:	5d                   	pop    rbp
  4a68b6:	e9 55 6b db ff       	jmp    0x25d410
  4a68bb:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a68bf:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a68c3:	0f 85 a1 05 00 00    	jne    0x4a6e6a
  4a68c9:	4c 89 f7             	mov    rdi,r14
  4a68cc:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a68d3:	5b                   	pop    rbx
  4a68d4:	41 5c                	pop    r12
  4a68d6:	41 5d                	pop    r13
  4a68d8:	41 5e                	pop    r14
  4a68da:	41 5f                	pop    r15
  4a68dc:	5d                   	pop    rbp
  4a68dd:	e9 8e 49 00 00       	jmp    0x4ab270
  4a68e2:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a68e6:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a68ea:	0f 85 7a 05 00 00    	jne    0x4a6e6a
  4a68f0:	48 83 c6 60          	add    rsi,0x60
  4a68f4:	48 8d 3d e2 ab ea 00 	lea    rdi,[rip+0xeaabe2]        # 0x13514dd
  4a68fb:	31 c0                	xor    eax,eax
  4a68fd:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a6904:	5b                   	pop    rbx
  4a6905:	41 5c                	pop    r12
  4a6907:	41 5d                	pop    r13
  4a6909:	41 5e                	pop    r14
  4a690b:	41 5f                	pop    r15
  4a690d:	5d                   	pop    rbp
  4a690e:	e9 fd 6a db ff       	jmp    0x25d410
  4a6913:	ff 80 10 01 00 00    	inc    DWORD PTR [rax+0x110]
  4a6919:	49 83 c5 60          	add    r13,0x60
  4a691d:	48 8d 3d cf 2c e2 00 	lea    rdi,[rip+0xe22ccf]        # 0x12c95f3
  4a6924:	31 c0                	xor    eax,eax
  4a6926:	4c 89 ee             	mov    rsi,r13
  4a6929:	e8 e2 6a db ff       	call   0x25d410
  4a692e:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a6932:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6936:	0f 85 2e 05 00 00    	jne    0x4a6e6a
  4a693c:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  4a6943:	31 f6                	xor    esi,esi
  4a6945:	31 d2                	xor    edx,edx
  4a6947:	31 c9                	xor    ecx,ecx
  4a6949:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a6950:	5b                   	pop    rbx
  4a6951:	41 5c                	pop    r12
  4a6953:	41 5d                	pop    r13
  4a6955:	41 5e                	pop    r14
  4a6957:	41 5f                	pop    r15
  4a6959:	5d                   	pop    rbp
  4a695a:	e9 41 06 02 00       	jmp    0x4c6fa0
  4a695f:	4c 8d 7b 05          	lea    r15,[rbx+0x5]
  4a6963:	41 f6 c6 04          	test   r14b,0x4
  4a6967:	0f 84 92 00 00 00    	je     0x4a69ff
  4a696d:	4c 8b b5 40 ff ff ff 	mov    r14,QWORD PTR [rbp-0xc0]
  4a6974:	0f b6 33             	movzx  esi,BYTE PTR [rbx]
  4a6977:	bf 23 c2 00 00       	mov    edi,0xc223
  4a697c:	49 83 c5 60          	add    r13,0x60
  4a6980:	4a 8d 44 33 05       	lea    rax,[rbx+r14*1+0x5]
  4a6985:	48 89 85 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rax
  4a698c:	4c 89 bd 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],r15
  4a6993:	e8 48 4e 00 00       	call   0x4ab7e0
  4a6998:	66 0f 38 f0 53 02    	movbe  dx,WORD PTR [rbx+0x2]
  4a699e:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a69a2:	4c 8b bd 48 ff ff ff 	mov    r15,QWORD PTR [rbp-0xb8]
  4a69a9:	48 8d 3d 60 95 f0 00 	lea    rdi,[rip+0xf09560]        # 0x13aff10
  4a69b0:	4c 89 ee             	mov    rsi,r13
  4a69b3:	44 0f b7 c2          	movzx  r8d,dx
  4a69b7:	48 89 c2             	mov    rdx,rax
  4a69ba:	31 c0                	xor    eax,eax
  4a69bc:	e8 4f 6a db ff       	call   0x25d410
  4a69c1:	48 8b bd 38 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xc8]
  4a69c8:	41 83 c4 fb          	add    r12d,0xfffffffb
  4a69cc:	41 0f b7 f4          	movzx  esi,r12w
  4a69d0:	e8 bb 6a 00 00       	call   0x4ad490
  4a69d5:	48 8d 3d 13 51 e9 00 	lea    rdi,[rip+0xe95113]        # 0x133baef
  4a69dc:	44 89 f6             	mov    esi,r14d
  4a69df:	31 c0                	xor    eax,eax
  4a69e1:	e8 2a 6a db ff       	call   0x25d410
  4a69e6:	4c 89 ff             	mov    rdi,r15
  4a69e9:	44 89 f6             	mov    esi,r14d
  4a69ec:	e8 5f 4e 00 00       	call   0x4ab850
  4a69f1:	48 8d 3d a6 58 eb 00 	lea    rdi,[rip+0xeb58a6]        # 0x135c29e
  4a69f8:	31 c0                	xor    eax,eax
  4a69fa:	e8 11 6a db ff       	call   0x25d410
  4a69ff:	4c 8d a5 68 ff ff ff 	lea    r12,[rbp-0x98]
  4a6a06:	4c 89 e7             	mov    rdi,r12
  4a6a09:	e8 72 19 81 00       	call   0xcb8380
  4a6a0e:	48 8d 73 01          	lea    rsi,[rbx+0x1]
  4a6a12:	4c 89 e7             	mov    rdi,r12
  4a6a15:	ba 01 00 00 00       	mov    edx,0x1
  4a6a1a:	e8 91 19 81 00       	call   0xcb83b0
  4a6a1f:	4c 8b b5 58 ff ff ff 	mov    r14,QWORD PTR [rbp-0xa8]
  4a6a26:	4c 89 e7             	mov    rdi,r12
  4a6a29:	49 8b b6 90 03 00 00 	mov    rsi,QWORD PTR [r14+0x390]
  4a6a30:	41 0f b6 96 99 03 00 	movzx  edx,BYTE PTR [r14+0x399]
  4a6a37:	00 
  4a6a38:	e8 73 19 81 00       	call   0xcb83b0
  4a6a3d:	4c 89 e7             	mov    rdi,r12
  4a6a40:	4c 89 fe             	mov    rsi,r15
  4a6a43:	48 8b 95 40 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xc0]
  4a6a4a:	e8 61 19 81 00       	call   0xcb83b0
  4a6a4f:	4c 8d 7d c0          	lea    r15,[rbp-0x40]
  4a6a53:	4c 89 e6             	mov    rsi,r12
  4a6a56:	4c 89 ff             	mov    rdi,r15
  4a6a59:	e8 92 22 81 00       	call   0xcb8cf0
  4a6a5e:	c6 85 67 ff ff ff 10 	mov    BYTE PTR [rbp-0x99],0x10
  4a6a65:	0f b6 4b 01          	movzx  ecx,BYTE PTR [rbx+0x1]
  4a6a69:	45 0f b6 96 98 03 00 	movzx  r10d,BYTE PTR [r14+0x398]
  4a6a70:	00 
  4a6a71:	48 83 ec 08          	sub    rsp,0x8
  4a6a75:	48 8d 3d 9c 8f 9d 00 	lea    rdi,[rip+0x9d8f9c]        # 0xe7fa18
  4a6a7c:	4c 8d 8d 67 ff ff ff 	lea    r9,[rbp-0x99]
  4a6a83:	41 b8 01 00 00 00    	mov    r8d,0x1
  4a6a89:	4c 89 f6             	mov    rsi,r14
  4a6a8c:	ba 02 00 00 00       	mov    edx,0x2
  4a6a91:	31 c0                	xor    eax,eax
  4a6a93:	6a 00                	push   0x0
  4a6a95:	41 ff b6 88 03 00 00 	push   QWORD PTR [r14+0x388]
  4a6a9c:	41 52                	push   r10
  4a6a9e:	41 57                	push   r15
  4a6aa0:	6a 10                	push   0x10
  4a6aa2:	e8 69 48 00 00       	call   0x4ab310
  4a6aa7:	48 83 c4 30          	add    rsp,0x30
  4a6aab:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  4a6ab2:	31 f6                	xor    esi,esi
  4a6ab4:	31 d2                	xor    edx,edx
  4a6ab6:	31 c9                	xor    ecx,ecx
  4a6ab8:	e8 e3 04 02 00       	call   0x4c6fa0
  4a6abd:	e9 85 03 00 00       	jmp    0x4a6e47
  4a6ac2:	0f b6 53 01          	movzx  edx,BYTE PTR [rbx+0x1]
  4a6ac6:	0f b6 8f 44 01 00 00 	movzx  ecx,BYTE PTR [rdi+0x144]
  4a6acd:	38 ca                	cmp    dl,cl
  4a6acf:	0f 85 d1 00 00 00    	jne    0x4a6ba6
  4a6ad5:	4a 8d 44 23 05       	lea    rax,[rbx+r12*1+0x5]
  4a6ada:	41 83 c6 fb          	add    r14d,0xfffffffb
  4a6ade:	4c 8d 6b 01          	lea    r13,[rbx+0x1]
  4a6ae2:	48 89 85 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],rax
  4a6ae9:	48 8b 87 b8 03 00 00 	mov    rax,QWORD PTR [rdi+0x3b8]
  4a6af0:	48 85 c0             	test   rax,rax
  4a6af3:	0f 84 e4 00 00 00    	je     0x4a6bdd
  4a6af9:	0f b6 8f c8 03 00 00 	movzx  ecx,BYTE PTR [rdi+0x3c8]
  4a6b00:	41 39 ce             	cmp    r14d,ecx
  4a6b03:	75 42                	jne    0x4a6b47
  4a6b05:	4c 89 ad 40 ff ff ff 	mov    QWORD PTR [rbp-0xc0],r13
  4a6b0c:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
  4a6b13:	49 89 f7             	mov    r15,rsi
  4a6b16:	44 89 f2             	mov    edx,r14d
  4a6b19:	48 89 c6             	mov    rsi,rax
  4a6b1c:	45 89 c5             	mov    r13d,r8d
  4a6b1f:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  4a6b26:	e8 a5 30 e9 ff       	call   0x339bd0
  4a6b2b:	45 89 e8             	mov    r8d,r13d
  4a6b2e:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  4a6b35:	4c 8b ad 40 ff ff ff 	mov    r13,QWORD PTR [rbp-0xc0]
  4a6b3c:	4c 89 fe             	mov    rsi,r15
  4a6b3f:	85 c0                	test   eax,eax
  4a6b41:	0f 84 96 00 00 00    	je     0x4a6bdd
  4a6b47:	48 8d 05 e8 e9 ed 00 	lea    rax,[rip+0xede9e8]        # 0x1385536
  4a6b4e:	49 89 ff             	mov    r15,rdi
  4a6b51:	48 83 c6 60          	add    rsi,0x60
  4a6b55:	48 89 c7             	mov    rdi,rax
  4a6b58:	31 c0                	xor    eax,eax
  4a6b5a:	e8 b1 68 db ff       	call   0x25d410
  4a6b5f:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  4a6b66:	44 89 f6             	mov    esi,r14d
  4a6b69:	e8 22 69 00 00       	call   0x4ad490
  4a6b6e:	48 8d 3d 91 37 e0 00 	lea    rdi,[rip+0xe03791]        # 0x12aa306
  4a6b75:	31 c0                	xor    eax,eax
  4a6b77:	e8 94 68 db ff       	call   0x25d410
  4a6b7c:	49 8b bf b8 03 00 00 	mov    rdi,QWORD PTR [r15+0x3b8]
  4a6b83:	41 0f b6 b7 c8 03 00 	movzx  esi,BYTE PTR [r15+0x3c8]
  4a6b8a:	00 
  4a6b8b:	4c 89 fb             	mov    rbx,r15
  4a6b8e:	e8 fd 68 00 00       	call   0x4ad490
  4a6b93:	48 8d 3d 7d 2f e9 00 	lea    rdi,[rip+0xe92f7d]        # 0x1339b17
  4a6b9a:	31 c0                	xor    eax,eax
  4a6b9c:	e8 6f 68 db ff       	call   0x25d410
  4a6ba1:	e9 3e 02 00 00       	jmp    0x4a6de4
  4a6ba6:	48 8d 05 63 57 47 03 	lea    rax,[rip+0x3475763]        # 0x391c310
  4a6bad:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4a6bb0:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6bb4:	0f 85 b0 02 00 00    	jne    0x4a6e6a
  4a6bba:	48 83 c6 60          	add    rsi,0x60
  4a6bbe:	48 8d 3d 04 37 e0 00 	lea    rdi,[rip+0xe03704]        # 0x12aa2c9
  4a6bc5:	31 c0                	xor    eax,eax
  4a6bc7:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a6bce:	5b                   	pop    rbx
  4a6bcf:	41 5c                	pop    r12
  4a6bd1:	41 5d                	pop    r13
  4a6bd3:	41 5e                	pop    r14
  4a6bd5:	41 5f                	pop    r15
  4a6bd7:	5d                   	pop    rbp
  4a6bd8:	e9 33 68 db ff       	jmp    0x25d410
  4a6bdd:	48 8d 43 05          	lea    rax,[rbx+0x5]
  4a6be1:	48 89 85 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rax
  4a6be8:	41 f6 c0 04          	test   r8b,0x4
  4a6bec:	0f 84 c5 00 00 00    	je     0x4a6cb7
  4a6bf2:	48 8d 46 60          	lea    rax,[rsi+0x60]
  4a6bf6:	4d 89 ef             	mov    r15,r13
  4a6bf9:	49 89 fd             	mov    r13,rdi
  4a6bfc:	48 89 85 40 ff ff ff 	mov    QWORD PTR [rbp-0xc0],rax
  4a6c03:	8b 87 3c 01 00 00    	mov    eax,DWORD PTR [rdi+0x13c]
  4a6c09:	48 89 b5 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],rsi
  4a6c10:	48 83 f8 09          	cmp    rax,0x9
  4a6c14:	77 0d                	ja     0x4a6c23
  4a6c16:	48 8d 0d 9b 8f 9d 00 	lea    rcx,[rip+0x9d8f9b]        # 0xe7fbb8
  4a6c1d:	48 8b 04 c1          	mov    rax,QWORD PTR [rcx+rax*8]
  4a6c21:	eb 07                	jmp    0x4a6c2a
  4a6c23:	48 8d 05 5b 38 ef 00 	lea    rax,[rip+0xef385b]        # 0x139a485
  4a6c2a:	0f b6 33             	movzx  esi,BYTE PTR [rbx]
  4a6c2d:	bf 23 c2 00 00       	mov    edi,0xc223
  4a6c32:	48 89 85 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rax
  4a6c39:	e8 a2 4b 00 00       	call   0x4ab7e0
  4a6c3e:	66 0f 38 f0 4b 02    	movbe  cx,WORD PTR [rbx+0x2]
  4a6c44:	44 0f b6 43 01       	movzx  r8d,BYTE PTR [rbx+0x1]
  4a6c49:	48 8b b5 40 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xc0]
  4a6c50:	48 8b 95 38 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xc8]
  4a6c57:	48 8d 3d 78 e4 ef 00 	lea    rdi,[rip+0xefe478]        # 0x13a50d6
  4a6c5e:	44 0f b7 c9          	movzx  r9d,cx
  4a6c62:	48 89 c1             	mov    rcx,rax
  4a6c65:	31 c0                	xor    eax,eax
  4a6c67:	e8 a4 67 db ff       	call   0x25d410
  4a6c6c:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  4a6c73:	44 89 f6             	mov    esi,r14d
  4a6c76:	e8 15 68 00 00       	call   0x4ad490
  4a6c7b:	48 8d 3d 6d 4e e9 00 	lea    rdi,[rip+0xe94e6d]        # 0x133baef
  4a6c82:	44 89 e6             	mov    esi,r12d
  4a6c85:	31 c0                	xor    eax,eax
  4a6c87:	e8 84 67 db ff       	call   0x25d410
  4a6c8c:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  4a6c93:	41 0f b7 f4          	movzx  esi,r12w
  4a6c97:	e8 b4 4b 00 00       	call   0x4ab850
  4a6c9c:	48 8d 3d fb 55 eb 00 	lea    rdi,[rip+0xeb55fb]        # 0x135c29e
  4a6ca3:	31 c0                	xor    eax,eax
  4a6ca5:	e8 66 67 db ff       	call   0x25d410
  4a6caa:	48 8b b5 48 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xb8]
  4a6cb1:	4c 89 ef             	mov    rdi,r13
  4a6cb4:	4d 89 fd             	mov    r13,r15
  4a6cb7:	48 89 fb             	mov    rbx,rdi
  4a6cba:	41 83 fc 10          	cmp    r12d,0x10
  4a6cbe:	0f 85 06 01 00 00    	jne    0x4a6dca
  4a6cc4:	4c 8d b5 68 ff ff ff 	lea    r14,[rbp-0x98]
  4a6ccb:	4c 89 f7             	mov    rdi,r14
  4a6cce:	e8 ad 16 81 00       	call   0xcb8380
  4a6cd3:	4c 89 f7             	mov    rdi,r14
  4a6cd6:	4c 89 ee             	mov    rsi,r13
  4a6cd9:	ba 01 00 00 00       	mov    edx,0x1
  4a6cde:	e8 cd 16 81 00       	call   0xcb83b0
  4a6ce3:	48 8b b3 c0 03 00 00 	mov    rsi,QWORD PTR [rbx+0x3c0]
  4a6cea:	0f b6 93 c9 03 00 00 	movzx  edx,BYTE PTR [rbx+0x3c9]
  4a6cf1:	4c 89 f7             	mov    rdi,r14
  4a6cf4:	e8 b7 16 81 00       	call   0xcb83b0
  4a6cf9:	48 8d b3 9a 03 00 00 	lea    rsi,[rbx+0x39a]
  4a6d00:	4c 89 f7             	mov    rdi,r14
  4a6d03:	ba 10 00 00 00       	mov    edx,0x10
  4a6d08:	e8 a3 16 81 00       	call   0xcb83b0
  4a6d0d:	4c 8d 7d c0          	lea    r15,[rbp-0x40]
  4a6d11:	4c 89 f6             	mov    rsi,r14
  4a6d14:	4c 89 ff             	mov    rdi,r15
  4a6d17:	e8 d4 1f 81 00       	call   0xcb8cf0
  4a6d1c:	48 8b b5 58 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xa8]
  4a6d23:	ba 10 00 00 00       	mov    edx,0x10
  4a6d28:	4c 89 ff             	mov    rdi,r15
  4a6d2b:	e8 a0 2e e9 ff       	call   0x339bd0
  4a6d30:	85 c0                	test   eax,eax
  4a6d32:	0f 85 ac 00 00 00    	jne    0x4a6de4
  4a6d38:	c7 83 10 01 00 00 00 	mov    DWORD PTR [rbx+0x110],0x0
  4a6d3f:	00 00 00 
  4a6d42:	4c 8d 25 c7 55 47 03 	lea    r12,[rip+0x34755c7]        # 0x391c310
  4a6d49:	8b 8b 3c 01 00 00    	mov    ecx,DWORD PTR [rbx+0x13c]
  4a6d4f:	83 f9 09             	cmp    ecx,0x9
  4a6d52:	74 08                	je     0x4a6d5c
  4a6d54:	48 89 d8             	mov    rax,rbx
  4a6d57:	83 f9 06             	cmp    ecx,0x6
  4a6d5a:	75 3b                	jne    0x4a6d97
  4a6d5c:	41 0f b6 4d 00       	movzx  ecx,BYTE PTR [r13+0x0]
  4a6d61:	48 83 ec 08          	sub    rsp,0x8
  4a6d65:	31 c0                	xor    eax,eax
  4a6d67:	48 8d 3d aa 8c 9d 00 	lea    rdi,[rip+0x9d8caa]        # 0xe7fa18
  4a6d6e:	4c 8d 0d fa 0c dd 00 	lea    r9,[rip+0xdd0cfa]        # 0x1277a6f
  4a6d75:	41 b8 08 00 00 00    	mov    r8d,0x8
  4a6d7b:	48 89 de             	mov    rsi,rbx
  4a6d7e:	ba 03 00 00 00       	mov    edx,0x3
  4a6d83:	6a 00                	push   0x0
  4a6d85:	e8 86 45 00 00       	call   0x4ab310
  4a6d8a:	48 89 d8             	mov    rax,rbx
  4a6d8d:	48 83 c4 10          	add    rsp,0x10
  4a6d91:	8b 8b 3c 01 00 00    	mov    ecx,DWORD PTR [rbx+0x13c]
  4a6d97:	83 f9 06             	cmp    ecx,0x6
  4a6d9a:	0f 85 ae 00 00 00    	jne    0x4a6e4e
  4a6da0:	48 8d b8 90 02 00 00 	lea    rdi,[rax+0x290]
  4a6da7:	c7 80 3c 01 00 00 09 	mov    DWORD PTR [rax+0x13c],0x9
  4a6dae:	00 00 00 
  4a6db1:	48 89 c3             	mov    rbx,rax
  4a6db4:	31 f6                	xor    esi,esi
  4a6db6:	31 d2                	xor    edx,edx
  4a6db8:	e8 13 42 6f 00       	call   0xb9afd0
  4a6dbd:	48 89 df             	mov    rdi,rbx
  4a6dc0:	e8 1b 4d 00 00       	call   0x4abae0
  4a6dc5:	e9 84 00 00 00       	jmp    0x4a6e4e
  4a6dca:	48 83 c6 60          	add    rsi,0x60
  4a6dce:	48 8d 3d 3f 35 e0 00 	lea    rdi,[rip+0xe0353f]        # 0x12aa314
  4a6dd5:	b9 10 00 00 00       	mov    ecx,0x10
  4a6dda:	44 89 e2             	mov    edx,r12d
  4a6ddd:	31 c0                	xor    eax,eax
  4a6ddf:	e8 2c 66 db ff       	call   0x25d410
  4a6de4:	4c 8d b3 88 01 00 00 	lea    r14,[rbx+0x188]
  4a6deb:	31 f6                	xor    esi,esi
  4a6ded:	31 d2                	xor    edx,edx
  4a6def:	31 c9                	xor    ecx,ecx
  4a6df1:	4c 89 f7             	mov    rdi,r14
  4a6df4:	e8 07 fc 01 00       	call   0x4c6a00
  4a6df9:	ff 83 10 01 00 00    	inc    DWORD PTR [rbx+0x110]
  4a6dff:	4c 89 f7             	mov    rdi,r14
  4a6e02:	31 f6                	xor    esi,esi
  4a6e04:	31 d2                	xor    edx,edx
  4a6e06:	31 c9                	xor    ecx,ecx
  4a6e08:	e8 93 01 02 00       	call   0x4c6fa0
  4a6e0d:	41 0f b6 4d 00       	movzx  ecx,BYTE PTR [r13+0x0]
  4a6e12:	48 83 ec 08          	sub    rsp,0x8
  4a6e16:	48 8d 3d fb 8b 9d 00 	lea    rdi,[rip+0x9d8bfb]        # 0xe7fa18
  4a6e1d:	4c 8d 0d 14 91 f0 00 	lea    r9,[rip+0xf09114]        # 0x13aff38
  4a6e24:	41 b8 09 00 00 00    	mov    r8d,0x9
  4a6e2a:	48 89 de             	mov    rsi,rbx
  4a6e2d:	ba 04 00 00 00       	mov    edx,0x4
  4a6e32:	31 c0                	xor    eax,eax
  4a6e34:	6a 00                	push   0x0
  4a6e36:	e8 d5 44 00 00       	call   0x4ab310
  4a6e3b:	48 83 c4 10          	add    rsp,0x10
  4a6e3f:	48 89 df             	mov    rdi,rbx
  4a6e42:	e8 e9 4d 00 00       	call   0x4abc30
  4a6e47:	4c 8d 25 c2 54 47 03 	lea    r12,[rip+0x34754c2]        # 0x391c310
  4a6e4e:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  4a6e52:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  4a6e56:	75 12                	jne    0x4a6e6a
  4a6e58:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  4a6e5f:	5b                   	pop    rbx
  4a6e60:	41 5c                	pop    r12
  4a6e62:	41 5d                	pop    r13
  4a6e64:	41 5e                	pop    r14
  4a6e66:	41 5f                	pop    r15
  4a6e68:	5d                   	pop    rbp
  4a6e69:	c3                   	ret
  4a6e6a:	e8 41 68 25 00       	call   0x6fd6b0
  4a6e6f:	0f 0b                	ud2
  4a6e71:	90                   	nop
  4a6e72:	90                   	nop
  4a6e73:	90                   	nop
  4a6e74:	90                   	nop
  4a6e75:	90                   	nop
  4a6e76:	90                   	nop
  4a6e77:	90                   	nop
  4a6e78:	90                   	nop
  4a6e79:	90                   	nop
  4a6e7a:	90                   	nop
  4a6e7b:	90                   	nop
  4a6e7c:	90                   	nop
  4a6e7d:	90                   	nop
  4a6e7e:	90                   	nop
  4a6e7f:	90                   	nop
  4a6e80:	55                   	push   rbp
  4a6e81:	48 89 e5             	mov    rbp,rsp
  4a6e84:	41 56                	push   r14
  4a6e86:	53                   	push   rbx
  4a6e87:	48 83 ec 10          	sub    rsp,0x10
  4a6e8b:	4c 8b 77 48          	mov    r14,QWORD PTR [rdi+0x48]
  4a6e8f:	48 8d 35 8f 0b dd 00 	lea    rsi,[rip+0xdd0b8f]        # 0x1277a25
  4a6e96:	48 8d 15 6d ea e7 00 	lea    rdx,[rip+0xe7ea6d]        # 0x132590a
  4a6e9d:	b9 04 00 00 00       	mov    ecx,0x4
  4a6ea2:	49 8d be 88 01 00 00 	lea    rdi,[r14+0x188]
  4a6ea9:	e8 22 0f 02 00       	call   0x4c7dd0
  4a6eae:	48 8b 05 cb f6 08 03 	mov    rax,QWORD PTR [rip+0x308f6cb]        # 0x3536580
  4a6eb5:	48 85 c0             	test   rax,rax
  4a6eb8:	75 52                	jne    0x4a6f0c
  4a6eba:	48 8d 1d c7 f6 08 03 	lea    rbx,[rip+0x308f6c7]        # 0x3536588
  4a6ec1:	be 08 00 00 00       	mov    esi,0x8
  4a6ec6:	48 89 df             	mov    rdi,rbx
  4a6ec9:	e8 72 47 6f 00       	call   0xb9b640
  4a6ece:	8b 05 6c 95 47 03    	mov    eax,DWORD PTR [rip+0x347956c]        # 0x3920440
  4a6ed4:	48 8d 0d d5 af db ff 	lea    rcx,[rip+0xffffffffffdbafd5]        # 0x261eb0
  4a6edb:	48 89 df             	mov    rdi,rbx
  4a6ede:	41 b9 ff ff ff ff    	mov    r9d,0xffffffff
  4a6ee4:	c7 04 24 00 01 00 00 	mov    DWORD PTR [rsp],0x100
  4a6eeb:	31 d2                	xor    edx,edx
  4a6eed:	45 31 c0             	xor    r8d,r8d
  4a6ef0:	01 c0                	add    eax,eax
  4a6ef2:	8d 04 80             	lea    eax,[rax+rax*4]
  4a6ef5:	48 63 f0             	movsxd rsi,eax
  4a6ef8:	48 0f af 35 d0 94 47 	imul   rsi,QWORD PTR [rip+0x34794d0]        # 0x39203d0
  4a6eff:	03 
  4a6f00:	e8 3b 3b 6f 00       	call   0xb9aa40
  4a6f05:	48 8b 05 74 f6 08 03 	mov    rax,QWORD PTR [rip+0x308f674]        # 0x3536580
  4a6f0c:	49 89 46 78          	mov    QWORD PTR [r14+0x78],rax
  4a6f10:	4c 89 35 69 f6 08 03 	mov    QWORD PTR [rip+0x308f669],r14        # 0x3536580
  4a6f17:	48 8d 0d fa 84 dc ff 	lea    rcx,[rip+0xffffffffffdc84fa]        # 0x26f418
  4a6f1e:	49 8d be 98 00 00 00 	lea    rdi,[r14+0x98]
  4a6f25:	be 28 00 00 00       	mov    esi,0x28
  4a6f2a:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a6f2d:	c6 80 9c 00 00 00 17 	mov    BYTE PTR [rax+0x9c],0x17
  4a6f34:	49 8b 06             	mov    rax,QWORD PTR [r14]
  4a6f37:	48 89 88 88 04 00 00 	mov    QWORD PTR [rax+0x488],rcx
  4a6f3e:	41 c7 46 1c 20 00 00 	mov    DWORD PTR [r14+0x1c],0x20
  4a6f45:	00 
  4a6f46:	41 c7 46 54 14 00 00 	mov    DWORD PTR [r14+0x54],0x14
  4a6f4d:	00 
  4a6f4e:	49 c7 86 88 00 00 00 	mov    QWORD PTR [r14+0x88],0x0
  4a6f55:	00 00 00 00 
  4a6f59:	49 c7 86 00 01 00 00 	mov    QWORD PTR [r14+0x100],0x0
  4a6f60:	00 00 00 00 
  4a6f64:	49 c7 86 f0 00 00 00 	mov    QWORD PTR [r14+0xf0],0x0
  4a6f6b:	00 00 00 00 
  4a6f6f:	41 c7 86 90 00 00 00 	mov    DWORD PTR [r14+0x90],0x3
  4a6f76:	03 00 00 00 
  4a6f7a:	49 c7 86 f8 00 00 00 	mov    QWORD PTR [r14+0xf8],0xf
  4a6f81:	0f 00 00 00 
  4a6f85:	49 c7 86 08 01 00 00 	mov    QWORD PTR [r14+0x108],0x0
  4a6f8c:	00 00 00 00 
  4a6f90:	e8 5b 20 db ff       	call   0x258ff0
  4a6f95:	49 8d be c0 00 00 00 	lea    rdi,[r14+0xc0]
  4a6f9c:	be 28 00 00 00       	mov    esi,0x28
  4a6fa1:	e8 4a 20 db ff       	call   0x258ff0
  4a6fa6:	48 b8 00 00 00 00 05 	movabs rax,0x500000000
  4a6fad:	00 00 00 
  4a6fb0:	48 8d 15 01 af db ff 	lea    rdx,[rip+0xffffffffffdbaf01]        # 0x261eb8
  4a6fb7:	48 8d 0d 02 af db ff 	lea    rcx,[rip+0xffffffffffdbaf02]        # 0x261ec0
  4a6fbe:	49 89 86 10 01 00 00 	mov    QWORD PTR [r14+0x110],rax
  4a6fc5:	41 c7 86 18 01 00 00 	mov    DWORD PTR [r14+0x118],0x0
  4a6fcc:	00 00 00 00 
  4a6fd0:	49 89 96 e0 03 00 00 	mov    QWORD PTR [r14+0x3e0],rdx
  4a6fd7:	49 89 8e e8 03 00 00 	mov    QWORD PTR [r14+0x3e8],rcx
  4a6fde:	41 f6 46 62 01       	test   BYTE PTR [r14+0x62],0x1
  4a6fe3:	75 14                	jne    0x4a6ff9
  4a6fe5:	49 8d 7e 70          	lea    rdi,[r14+0x70]
  4a6fe9:	48 8d 35 12 17 e4 00 	lea    rsi,[rip+0xe41712]        # 0x12e8702
  4a6ff0:	31 d2                	xor    edx,edx
  4a6ff2:	31 c9                	xor    ecx,ecx
  4a6ff4:	e8 d7 0d 02 00       	call   0x4c7dd0
  4a6ff9:	41 f6 46 2a 01       	test   BYTE PTR [r14+0x2a],0x1
  4a6ffe:	75 14                	jne    0x4a7014
  4a7000:	49 8d 7e 38          	lea    rdi,[r14+0x38]
  4a7004:	48 8d 35 74 f3 de 00 	lea    rsi,[rip+0xdef374]        # 0x129637f
  4a700b:	31 d2                	xor    edx,edx
  4a700d:	31 c9                	xor    ecx,ecx
  4a700f:	e8 bc 0d 02 00       	call   0x4c7dd0
  4a7014:	49 8d be 80 03 00 00 	lea    rdi,[r14+0x380]
  4a701b:	be 30 00 00 00       	mov    esi,0x30
  4a7020:	e8 cb 1f db ff       	call   0x258ff0
  4a7025:	49 8d be b0 03 00 00 	lea    rdi,[r14+0x3b0]
  4a702c:	be 30 00 00 00       	mov    esi,0x30
  4a7031:	e8 ba 1f db ff       	call   0x258ff0
  4a7036:	49 c7 86 10 03 00 00 	mov    QWORD PTR [r14+0x310],0x20
  4a703d:	20 00 00 00 
  4a7041:	49 c7 86 18 03 00 00 	mov    QWORD PTR [r14+0x318],0x0
  4a7048:	00 00 00 00 
  4a704c:	41 c7 86 2c 01 00 00 	mov    DWORD PTR [r14+0x12c],0x0
  4a7053:	00 00 00 00 
  4a7057:	41 c7 86 5c 01 00 00 	mov    DWORD PTR [r14+0x15c],0x0
  4a705e:	00 00 00 00 
  4a7062:	49 c7 86 98 00 00 00 	mov    QWORD PTR [r14+0x98],0x0
  4a7069:	00 00 00 00 
  4a706d:	49 c7 86 c0 00 00 00 	mov    QWORD PTR [r14+0xc0],0x0
  4a7074:	00 00 00 00 
  4a7078:	49 c7 86 30 03 00 00 	mov    QWORD PTR [r14+0x330],0x0
  4a707f:	00 00 00 00 
  4a7083:	49 c7 86 28 03 00 00 	mov    QWORD PTR [r14+0x328],0x5dc
  4a708a:	dc 05 00 00 
  4a708e:	49 c7 86 20 03 00 00 	mov    QWORD PTR [r14+0x320],0x5dc
  4a7095:	dc 05 00 00 
  4a7099:	48 b9 02 00 00 00 0a 	movabs rcx,0xa00000002
  4a70a0:	00 00 00 
  4a70a3:	49 8d be 90 01 00 00 	lea    rdi,[r14+0x190]
  4a70aa:	be 08 00 00 00       	mov    esi,0x8
  4a70af:	8b 05 8b 93 47 03    	mov    eax,DWORD PTR [rip+0x347938b]        # 0x3920440
  4a70b5:	41 89 86 3c 03 00 00 	mov    DWORD PTR [r14+0x33c],eax
  4a70bc:	49 89 8e 40 03 00 00 	mov    QWORD PTR [r14+0x340],rcx
  4a70c3:	41 c7 86 48 03 00 00 	mov    DWORD PTR [r14+0x348],0xa
  4a70ca:	0a 00 00 00 
  4a70ce:	e8 6d 45 6f 00       	call   0xb9b640
  4a70d3:	49 8d be d0 01 00 00 	lea    rdi,[r14+0x1d0]
  4a70da:	be 08 00 00 00       	mov    esi,0x8
  4a70df:	49 c7 86 50 03 00 00 	mov    QWORD PTR [r14+0x350],0x0
  4a70e6:	00 00 00 00 
  4a70ea:	41 c7 86 58 03 00 00 	mov    DWORD PTR [r14+0x358],0x0
  4a70f1:	00 00 00 00 
  4a70f5:	41 c7 86 30 01 00 00 	mov    DWORD PTR [r14+0x130],0x0
  4a70fc:	00 00 00 00 
  4a7100:	41 c7 86 60 01 00 00 	mov    DWORD PTR [r14+0x160],0x0
  4a7107:	00 00 00 00 
  4a710b:	49 c7 86 a0 00 00 00 	mov    QWORD PTR [r14+0xa0],0x0
  4a7112:	00 00 00 00 
  4a7116:	49 c7 86 c8 00 00 00 	mov    QWORD PTR [r14+0xc8],0x0
  4a711d:	00 00 00 00 
  4a7121:	e8 1a 45 6f 00       	call   0xb9b640
  4a7126:	49 8d be 50 02 00 00 	lea    rdi,[r14+0x250]
  4a712d:	be 08 00 00 00       	mov    esi,0x8
  4a7132:	41 c7 86 38 01 00 00 	mov    DWORD PTR [r14+0x138],0x2
  4a7139:	02 00 00 00 
  4a713d:	41 c7 86 68 01 00 00 	mov    DWORD PTR [r14+0x168],0x0
  4a7144:	00 00 00 00 
  4a7148:	49 c7 86 b0 00 00 00 	mov    QWORD PTR [r14+0xb0],0x0
  4a714f:	00 00 00 00 
  4a7153:	49 c7 86 d8 00 00 00 	mov    QWORD PTR [r14+0xd8],0x0
  4a715a:	00 00 00 00 
  4a715e:	e8 dd 44 6f 00       	call   0xb9b640
  4a7163:	49 8d be d0 02 00 00 	lea    rdi,[r14+0x2d0]
  4a716a:	be 08 00 00 00       	mov    esi,0x8
  4a716f:	e8 cc 44 6f 00       	call   0xb9b640
  4a7174:	49 8d be 90 02 00 00 	lea    rdi,[r14+0x290]
  4a717b:	be 08 00 00 00       	mov    esi,0x8
  4a7180:	41 c7 86 3c 01 00 00 	mov    DWORD PTR [r14+0x13c],0x2
  4a7187:	02 00 00 00 
  4a718b:	41 c7 86 6c 01 00 00 	mov    DWORD PTR [r14+0x16c],0x0
  4a7192:	00 00 00 00 
  4a7196:	49                   	rex.WB
  4a7197:	c7                   	.byte 0xc7
  4a7198:	86 b8 00 00 00 00    	xchg   BYTE PTR [rax+0x0],bh
  4a719e:	00 00                	add    BYTE PTR [rax],al
