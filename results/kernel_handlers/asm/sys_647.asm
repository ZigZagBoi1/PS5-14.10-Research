; Handler 647: Credential-gated executable ORBI metadata query
; REA6.7.0/Ghidra12.1.4, static analysis; RVAs, not runtime addresses.
; Original4KB SHA256 0fee3622e3402963caeacc8d1a8ea7abfef979eae3ff2b0325b83fb905516a54, entry 0x265f48, tail target0xabe7b0.
; Runtime VA=0xffffffff8a9c0000+RVA. Analyst-inferred names/types are not original source.

; COMPLETE ORIGINAL INPUT WINDOW: handler_647.bin, 4096 bytes
; SHA256 0fee3622e3402963caeacc8d1a8ea7abfef979eae3ff2b0325b83fb905516a54; file offset zero = kernel RVA 0x265f48.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265f48 [0x265f48, 0x265f4c] | file +0x0 | ev_90e30bd2294293ce2a3416705c0cd745a1d6ba504f8bf45f007ccdacd3dfae05
thunk_265f48:
0x265f48: JMP 0x00abe7b0
; END FUNCTION thunk_265f48
0x265f4d: INT3 ; original byte CC, padding
0x265f4e: INT3 ; original byte CC, padding
0x265f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f50 [0x265f50, 0x265f54] | file +0x8 | ev_7a6c201331064d4f27c60fe9598670d33c09a953fe0624a08f78c3e1d95d47ae
thunk_265f50:
0x265f50: JMP 0x009f81f0
; END FUNCTION thunk_265f50
0x265f55: INT3 ; original byte CC, padding
0x265f56: INT3 ; original byte CC, padding
0x265f57: INT3 ; original byte CC, padding

; FUNCTION thunk_265f58 [0x265f58, 0x265f5c] | file +0x10 | ev_a1eb78dbbdea733c5de2d066d4df609278988e5e0cd5eb75ce20ed31a730dfcc
thunk_265f58:
0x265f58: JMP 0x00be9510
; END FUNCTION thunk_265f58
0x265f5d: INT3 ; original byte CC, padding
0x265f5e: INT3 ; original byte CC, padding
0x265f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f60 [0x265f60, 0x265f64] | file +0x18 | ev_3ce5dde8008e04c265e5bf4d50b808fd7dde164f1b953bc506e8957fea941364
thunk_265f60:
0x265f60: JMP 0x009a7d10
; END FUNCTION thunk_265f60
0x265f65: INT3 ; original byte CC, padding
0x265f66: INT3 ; original byte CC, padding
0x265f67: INT3 ; original byte CC, padding

; FUNCTION thunk_265f68 [0x265f68, 0x265f6c] | file +0x20 | ev_30fb1503914bfcc9ed442526904c06863c13c21f71c813cb207a809a8b26e288
thunk_265f68:
0x265f68: JMP 0x009a9560
; END FUNCTION thunk_265f68
0x265f6d: INT3 ; original byte CC, padding
0x265f6e: INT3 ; original byte CC, padding
0x265f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f70 [0x265f70, 0x265f74] | file +0x28 | ev_5a722f62fadb8a29429713bcc4bb02986a139904c60356d3956a39654cd442c6
thunk_265f70:
0x265f70: JMP 0x009a9e10
; END FUNCTION thunk_265f70
0x265f75: INT3 ; original byte CC, padding
0x265f76: INT3 ; original byte CC, padding
0x265f77: INT3 ; original byte CC, padding

; FUNCTION thunk_265f78 [0x265f78, 0x265f7c] | file +0x30 | ev_bcf43827b5c2e17a463acbcf525c45f60b468982552d619865a6bfe7665a37ba
thunk_265f78:
0x265f78: JMP 0x009a9f40
; END FUNCTION thunk_265f78
0x265f7d: INT3 ; original byte CC, padding
0x265f7e: INT3 ; original byte CC, padding
0x265f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f80 [0x265f80, 0x265f84] | file +0x38 | ev_dd33df4d2f9001ee6ac780697739b18182526436a92e50b0414b4999641f292f
thunk_265f80:
0x265f80: JMP 0x008fb440
; END FUNCTION thunk_265f80
0x265f85: INT3 ; original byte CC, padding
0x265f86: INT3 ; original byte CC, padding
0x265f87: INT3 ; original byte CC, padding

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0x40 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0x48 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0x50 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x58 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x60 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x68 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x70 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x78 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x80 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x88 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x90 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x98 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0xa0 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0xa8 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0xb0 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0xb8 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0xc0 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0xc8 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0xd0 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0xd8 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0xe0 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0xe8 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0xf0 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0xf8 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0x100 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0x108 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0x110 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0x118 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0x120 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0x128 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0x130 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0x138 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0x140 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0x148 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0x150 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0x158 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x160 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x168 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x170 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x178 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x180 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x188 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x190 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x198 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x1a0 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x1a8 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x1b0 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x1b8 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0x1c0 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0x1c8 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0x1d0 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0x1d8 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0x1e0 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0x1e8 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0x1f0 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0x1f8 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0x200 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0x208 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0x210 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0x218 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0x220 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0x228 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0x230 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0x238 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0x240 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0x248 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0x250 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0x258 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0x260 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0x268 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0x270 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0x278 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0x280 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0x288 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0x290 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0x298 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0x2a0 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0x2a8 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0x2b0 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0x2b8 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0x2c0 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0x2c8 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0x2d0 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0x2d8 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0x2e0 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0x2e8 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0x2f0 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0x2f8 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0x300 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0x308 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0x310 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0x318 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0x320 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0x328 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0x330 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0x338 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0x340 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0x348 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0x350 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0x358 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0x360 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0x368 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0x370 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0x378 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0x380 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0x388 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0x390 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0x398 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0x3a0 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0x3a8 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0x3b0 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0x3b8 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0x3c0 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0x3c8 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0x3d0 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0x3d8 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0x3e0 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0x3e8 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0x3f0 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0x3f8 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0x400 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0x408 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0x410 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0x418 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0x420 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0x428 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0x430 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0x438 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0x440 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0x448 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0x450 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0x458 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0x460 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0x468 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0x470 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0x478 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0x480 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0x488 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0x490 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0x498 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0x4a0 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0x4a8 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0x4b0 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0x4b8 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0x4c0 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0x4c8 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0x4d0 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0x4d8 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0x4e0 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0x4e8 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0x4f0 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0x4f8 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0x500 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0x508 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0x510 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0x518 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0x520 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0x528 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0x530 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0x538 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0x540 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0x548 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0x550 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0x558 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0x560 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0x568 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0x570 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0x578 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0x580 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0x588 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0x590 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0x598 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0x5a0 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0x5a8 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0x5b0 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0x5b8 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0x5c0 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0x5c8 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0x5d0 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0x5d8 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0x5e0 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0x5e8 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0x5f0 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0x5f8 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0x600 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0x608 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0x610 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0x618 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0x620 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0x628 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0x630 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0x638 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0x640 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0x648 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0x650 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0x658 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0x660 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0x668 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0x670 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0x678 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0x680 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0x688 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0x690 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0x698 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0x6a0 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0x6a8 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0x6b0 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0x6b8 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0x6c0 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0x6c8 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0x6d0 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0x6d8 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0x6e0 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0x6e8 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0x6f0 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0x6f8 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0x700 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0x708 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0x710 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0x718 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0x720 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0x728 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0x730 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0x738 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0x740 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0x748 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0x750 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0x758 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0x760 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0x768 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0x770 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0x778 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0x780 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0x788 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0x790 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0x798 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0x7a0 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0x7a8 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0x7b0 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0x7b8 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding

; FUNCTION thunk_266708 [0x266708, 0x26670c] | file +0x7c0 | ev_a1b1ecfb69ddcde3ab328e54879b2647bb27553f41929ae5021b46edd03a8fd6
thunk_266708:
0x266708: JMP 0x00ca7310
; END FUNCTION thunk_266708
0x26670d: INT3 ; original byte CC, padding
0x26670e: INT3 ; original byte CC, padding
0x26670f: INT3 ; original byte CC, padding

; FUNCTION thunk_266710 [0x266710, 0x266714] | file +0x7c8 | ev_91a5d5c52dbb1d6be7f635bc2e634aa41a9d00a7b8b5d2ae096ecbfdcbfa2641
thunk_266710:
0x266710: JMP 0x00662e70
; END FUNCTION thunk_266710
0x266715: INT3 ; original byte CC, padding
0x266716: INT3 ; original byte CC, padding
0x266717: INT3 ; original byte CC, padding

; FUNCTION thunk_266718 [0x266718, 0x26671c] | file +0x7d0 | ev_5d49490e833cb75f11ae327b52e57d63c8562abf36102eae069cd3b6103363e9
thunk_266718:
0x266718: JMP 0x00662e80
; END FUNCTION thunk_266718
0x26671d: INT3 ; original byte CC, padding
0x26671e: INT3 ; original byte CC, padding
0x26671f: INT3 ; original byte CC, padding

; FUNCTION thunk_266720 [0x266720, 0x266724] | file +0x7d8 | ev_1dbafec98e5478d51b8103829bfa1a72f4bc438e9f77ede71f00176b6c65fa7a
thunk_266720:
0x266720: JMP 0x00678e10
; END FUNCTION thunk_266720
0x266725: INT3 ; original byte CC, padding
0x266726: INT3 ; original byte CC, padding
0x266727: INT3 ; original byte CC, padding

; FUNCTION thunk_266728 [0x266728, 0x26672c] | file +0x7e0 | ev_38fac9adf6535b05ba585c6e1016cc470c98cfb56fa25e1502404b81f2326987
thunk_266728:
0x266728: JMP 0x00678e60
; END FUNCTION thunk_266728
0x26672d: INT3 ; original byte CC, padding
0x26672e: INT3 ; original byte CC, padding
0x26672f: INT3 ; original byte CC, padding

; FUNCTION thunk_266730 [0x266730, 0x266734] | file +0x7e8 | ev_890d87fa71c13e41992835bde9ad1d367d67a4a8cd4b5428bd46706c8a2a3c01
thunk_266730:
0x266730: JMP 0x00678ec0
; END FUNCTION thunk_266730
0x266735: INT3 ; original byte CC, padding
0x266736: INT3 ; original byte CC, padding
0x266737: INT3 ; original byte CC, padding

; FUNCTION thunk_266738 [0x266738, 0x26673c] | file +0x7f0 | ev_aa0a18be2618fe163ef3124d4793e4ee4faac93cc616ec748a395327ab897d78
thunk_266738:
0x266738: JMP 0x00678f60
; END FUNCTION thunk_266738
0x26673d: INT3 ; original byte CC, padding
0x26673e: INT3 ; original byte CC, padding
0x26673f: INT3 ; original byte CC, padding

; FUNCTION thunk_266740 [0x266740, 0x266744] | file +0x7f8 | ev_b940e85d2293130cc12912d0f406f051de5e7b6c738a54b3296b9ad18e7da334
thunk_266740:
0x266740: JMP 0x00679190
; END FUNCTION thunk_266740
0x266745: INT3 ; original byte CC, padding
0x266746: INT3 ; original byte CC, padding
0x266747: INT3 ; original byte CC, padding

; FUNCTION thunk_266748 [0x266748, 0x26674c] | file +0x800 | ev_2d90ddd75a522af0bb29971ceb6fb5ba61df5fe33fe120ca3b3e5d7785d2fb67
thunk_266748:
0x266748: JMP 0x00679360
; END FUNCTION thunk_266748
0x26674d: INT3 ; original byte CC, padding
0x26674e: INT3 ; original byte CC, padding
0x26674f: INT3 ; original byte CC, padding

; FUNCTION thunk_266750 [0x266750, 0x266754] | file +0x808 | ev_01b9ec000cc30925ba3559e6be67c9cb23e822ed3521b44b10cf40b142115d81
thunk_266750:
0x266750: JMP 0x00679680
; END FUNCTION thunk_266750
0x266755: INT3 ; original byte CC, padding
0x266756: INT3 ; original byte CC, padding
0x266757: INT3 ; original byte CC, padding

; FUNCTION thunk_266758 [0x266758, 0x26675c] | file +0x810 | ev_d990bd8c7113bb7f5350f7d2dd0da9a70e1e61ae3bdc2023b324d40d54fd0556
thunk_266758:
0x266758: JMP 0x00033b90
; END FUNCTION thunk_266758
0x26675d: INT3 ; original byte CC, padding
0x26675e: INT3 ; original byte CC, padding
0x26675f: INT3 ; original byte CC, padding

; FUNCTION thunk_266760 [0x266760, 0x266764] | file +0x818 | ev_9c2f05162ca519881e4051f776fb4d5698dc9a1dbb6d322ee6281af4ba5e8feb
thunk_266760:
0x266760: JMP 0x00033ca0
; END FUNCTION thunk_266760
0x266765: INT3 ; original byte CC, padding
0x266766: INT3 ; original byte CC, padding
0x266767: INT3 ; original byte CC, padding

; FUNCTION thunk_266768 [0x266768, 0x26676c] | file +0x820 | ev_8a1b5cf7031b91c6ae6c5ebe0fffd22f6fa2246fe2869a1a78fd5b400a6b359e
thunk_266768:
0x266768: JMP 0x00033d20
; END FUNCTION thunk_266768
0x26676d: INT3 ; original byte CC, padding
0x26676e: INT3 ; original byte CC, padding
0x26676f: INT3 ; original byte CC, padding

; FUNCTION thunk_266770 [0x266770, 0x266774] | file +0x828 | ev_1f25b3b15b6f767ce17fc6cd00f20709a3a70504cb1eab6250b3a9d8f5df543a
thunk_266770:
0x266770: JMP 0x0003cf70
; END FUNCTION thunk_266770
0x266775: INT3 ; original byte CC, padding
0x266776: INT3 ; original byte CC, padding
0x266777: INT3 ; original byte CC, padding

; FUNCTION thunk_266778 [0x266778, 0x26677c] | file +0x830 | ev_1abd2480771bd0dfc44ad78a0ad8b9e76496fd5a3103f04dbfb5001838054042
thunk_266778:
0x266778: JMP 0x0003d0e0
; END FUNCTION thunk_266778
0x26677d: INT3 ; original byte CC, padding
0x26677e: INT3 ; original byte CC, padding
0x26677f: INT3 ; original byte CC, padding

; FUNCTION thunk_266780 [0x266780, 0x266784] | file +0x838 | ev_c505cc9a86f7ae4149f1e64b36bc59f5f40aa963623ba2974583c5d3e37dcf6c
thunk_266780:
0x266780: JMP 0x0003d660
; END FUNCTION thunk_266780
0x266785: INT3 ; original byte CC, padding
0x266786: INT3 ; original byte CC, padding
0x266787: INT3 ; original byte CC, padding

; FUNCTION thunk_266788 [0x266788, 0x26678c] | file +0x840 | ev_9ed81726a9363e9abf06ebf384044590c774b49373b1aff9cce434caec79de73
thunk_266788:
0x266788: JMP 0x0003e100
; END FUNCTION thunk_266788
0x26678d: INT3 ; original byte CC, padding
0x26678e: INT3 ; original byte CC, padding
0x26678f: INT3 ; original byte CC, padding

; FUNCTION thunk_266790 [0x266790, 0x266794] | file +0x848 | ev_b6d70feab26a69b46d1e60bf65b7ac8ff9e8af0f14e58083f5ca2104e00b4a77
thunk_266790:
0x266790: JMP 0x0003e160
; END FUNCTION thunk_266790
0x266795: INT3 ; original byte CC, padding
0x266796: INT3 ; original byte CC, padding
0x266797: INT3 ; original byte CC, padding

; FUNCTION thunk_266798 [0x266798, 0x26679c] | file +0x850 | ev_3a4fe1aed4181c9b36fc2d107277e19a007843c58dbc34a1b90c6b5364c25a1f
thunk_266798:
0x266798: JMP 0x0003e1c0
; END FUNCTION thunk_266798
0x26679d: INT3 ; original byte CC, padding
0x26679e: INT3 ; original byte CC, padding
0x26679f: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a0 [0x2667a0, 0x2667a4] | file +0x858 | ev_4e9ef9ebcbe1c81642627453beab0cf815cbe6b323c761944902a2e3a594e35e
thunk_2667a0:
0x2667a0: JMP 0x0003f070
; END FUNCTION thunk_2667a0
0x2667a5: INT3 ; original byte CC, padding
0x2667a6: INT3 ; original byte CC, padding
0x2667a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a8 [0x2667a8, 0x2667ac] | file +0x860 | ev_1e8d18696b5a66f44717599dfe66fa3f5647bfd731e90f4213ba0fb583230b36
thunk_2667a8:
0x2667a8: JMP 0x0003f0d0
; END FUNCTION thunk_2667a8
0x2667ad: INT3 ; original byte CC, padding
0x2667ae: INT3 ; original byte CC, padding
0x2667af: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b0 [0x2667b0, 0x2667b4] | file +0x868 | ev_694c8a603d68e5c334d648ccab1a33dedcffe9fe58ccd66f93a0e0e9f55a0532
thunk_2667b0:
0x2667b0: JMP 0x0003f4b0
; END FUNCTION thunk_2667b0
0x2667b5: INT3 ; original byte CC, padding
0x2667b6: INT3 ; original byte CC, padding
0x2667b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b8 [0x2667b8, 0x2667bc] | file +0x870 | ev_a433f0ca544c9e14c9ccf44b4ee4f0234100e7f292134e31ff932a3f92aa68ce
thunk_2667b8:
0x2667b8: JMP 0x0003f510
; END FUNCTION thunk_2667b8
0x2667bd: INT3 ; original byte CC, padding
0x2667be: INT3 ; original byte CC, padding
0x2667bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c0 [0x2667c0, 0x2667c4] | file +0x878 | ev_bea5624da2f134f28923630943d28c30f396fee0e2b4c2add7748798a411e200
thunk_2667c0:
0x2667c0: JMP 0x0003f570
; END FUNCTION thunk_2667c0
0x2667c5: INT3 ; original byte CC, padding
0x2667c6: INT3 ; original byte CC, padding
0x2667c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c8 [0x2667c8, 0x2667cc] | file +0x880 | ev_873e539dd587ac5fcd71faab8b5f3475b0c0c95679ce352316e553e65785df80
thunk_2667c8:
0x2667c8: JMP 0x0003fbb0
; END FUNCTION thunk_2667c8
0x2667cd: INT3 ; original byte CC, padding
0x2667ce: INT3 ; original byte CC, padding
0x2667cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d0 [0x2667d0, 0x2667d4] | file +0x888 | ev_d081b0d8d4dc0ccacf69699e5595f0544f500d0276055e7bf09413150e1224dd
thunk_2667d0:
0x2667d0: JMP 0x0003ffc0
; END FUNCTION thunk_2667d0
0x2667d5: INT3 ; original byte CC, padding
0x2667d6: INT3 ; original byte CC, padding
0x2667d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d8 [0x2667d8, 0x2667dc] | file +0x890 | ev_96e92b8e3e99b79413f154cc9eb3d60a8a7d646aa4515fb8fb5de63dd6d7c917
thunk_2667d8:
0x2667d8: JMP 0x00040960
; END FUNCTION thunk_2667d8
0x2667dd: INT3 ; original byte CC, padding
0x2667de: INT3 ; original byte CC, padding
0x2667df: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e0 [0x2667e0, 0x2667e4] | file +0x898 | ev_a1b1802795532978974ffc776896ea0d7761845d22797ef90473038e62d47faa
thunk_2667e0:
0x2667e0: JMP 0x00040b50
; END FUNCTION thunk_2667e0
0x2667e5: INT3 ; original byte CC, padding
0x2667e6: INT3 ; original byte CC, padding
0x2667e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e8 [0x2667e8, 0x2667ec] | file +0x8a0 | ev_83007fa2af45028f40282ddb2608364e94f80e2ce94687cd3f80e2b37d9e04ae
thunk_2667e8:
0x2667e8: JMP 0x00040c30
; END FUNCTION thunk_2667e8
0x2667ed: INT3 ; original byte CC, padding
0x2667ee: INT3 ; original byte CC, padding
0x2667ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f0 [0x2667f0, 0x2667f4] | file +0x8a8 | ev_2caf01d6b7d2a840a5c899ea1ade478a1167a6d2432c06185f6657a466a24521
thunk_2667f0:
0x2667f0: JMP 0x00041630
; END FUNCTION thunk_2667f0
0x2667f5: INT3 ; original byte CC, padding
0x2667f6: INT3 ; original byte CC, padding
0x2667f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f8 [0x2667f8, 0x2667fc] | file +0x8b0 | ev_2e9a02026a32f4d3595a1c8ea3741317c463c48293ad9967d64bb0c842c16bcf
thunk_2667f8:
0x2667f8: JMP 0x00041750
; END FUNCTION thunk_2667f8
0x2667fd: INT3 ; original byte CC, padding
0x2667fe: INT3 ; original byte CC, padding
0x2667ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266800 [0x266800, 0x266804] | file +0x8b8 | ev_b5a4bcb1d6c941a3f6d70e0062d3c0463382b61c6d39e75f8ad4575154058329
thunk_266800:
0x266800: JMP 0x00041830
; END FUNCTION thunk_266800
0x266805: INT3 ; original byte CC, padding
0x266806: INT3 ; original byte CC, padding
0x266807: INT3 ; original byte CC, padding

; FUNCTION thunk_266808 [0x266808, 0x26680c] | file +0x8c0 | ev_f1b081b3b9ac7495b8be40ee086537bb185a297b65b7ef087083c600fbb85b61
thunk_266808:
0x266808: JMP 0x000418c0
; END FUNCTION thunk_266808
0x26680d: INT3 ; original byte CC, padding
0x26680e: INT3 ; original byte CC, padding
0x26680f: INT3 ; original byte CC, padding

; FUNCTION thunk_266810 [0x266810, 0x266814] | file +0x8c8 | ev_286fd1ef6a141f6a83604ef9198646a69f86d2b579ec17a23ae6cebb467e5061
thunk_266810:
0x266810: JMP 0x00042060
; END FUNCTION thunk_266810
0x266815: INT3 ; original byte CC, padding
0x266816: INT3 ; original byte CC, padding
0x266817: INT3 ; original byte CC, padding

; FUNCTION thunk_266818 [0x266818, 0x26681c] | file +0x8d0 | ev_47935a2775d41df4f9b4c5a7174f7ec66edf37c497c637165652e966d455c6c2
thunk_266818:
0x266818: JMP 0x000424d0
; END FUNCTION thunk_266818
0x26681d: INT3 ; original byte CC, padding
0x26681e: INT3 ; original byte CC, padding
0x26681f: INT3 ; original byte CC, padding

; FUNCTION thunk_266820 [0x266820, 0x266824] | file +0x8d8 | ev_ec6ae96b47da7790af52eef03b6d449d9601b42b60ff5781510b83d5eed62146
thunk_266820:
0x266820: JMP 0x000425a0
; END FUNCTION thunk_266820
0x266825: INT3 ; original byte CC, padding
0x266826: INT3 ; original byte CC, padding
0x266827: INT3 ; original byte CC, padding

; FUNCTION thunk_266828 [0x266828, 0x26682c] | file +0x8e0 | ev_62e5f7ba42bcfbb4e746143fb9a9e26ec7bd4a12c0fbf516331bb1dba6d35663
thunk_266828:
0x266828: JMP 0x00042600
; END FUNCTION thunk_266828
0x26682d: INT3 ; original byte CC, padding
0x26682e: INT3 ; original byte CC, padding
0x26682f: INT3 ; original byte CC, padding

; FUNCTION thunk_266830 [0x266830, 0x266834] | file +0x8e8 | ev_5adad97b5e16134fb3c507782f4939f93bf7446e42819870836ccff91d30b7eb
thunk_266830:
0x266830: JMP 0x00690030
; END FUNCTION thunk_266830
0x266835: INT3 ; original byte CC, padding
0x266836: INT3 ; original byte CC, padding
0x266837: INT3 ; original byte CC, padding

; FUNCTION thunk_266838 [0x266838, 0x26683c] | file +0x8f0 | ev_816d78169618a36f8b32f4a02e164b67743d4a889459642185f582989c4af5e2
thunk_266838:
0x266838: JMP 0x00696cc0
; END FUNCTION thunk_266838
0x26683d: INT3 ; original byte CC, padding
0x26683e: INT3 ; original byte CC, padding
0x26683f: INT3 ; original byte CC, padding

; FUNCTION thunk_266840 [0x266840, 0x266844] | file +0x8f8 | ev_ac0488f3239f358372c3fe2efa4f19fad41d472d5150f8744654236f12971a58
thunk_266840:
0x266840: JMP 0x006985d0
; END FUNCTION thunk_266840
0x266845: INT3 ; original byte CC, padding
0x266846: INT3 ; original byte CC, padding
0x266847: INT3 ; original byte CC, padding

; FUNCTION thunk_266848 [0x266848, 0x26684c] | file +0x900 | ev_93973c149c06bf5ab4e689d9c5e3a621a45fdb016a490bd5f873537571699dde
thunk_266848:
0x266848: JMP 0x006a2050
; END FUNCTION thunk_266848
0x26684d: INT3 ; original byte CC, padding
0x26684e: INT3 ; original byte CC, padding
0x26684f: INT3 ; original byte CC, padding

; FUNCTION thunk_266850 [0x266850, 0x266854] | file +0x908 | ev_0384ec62f16c1b55f37f6e139cd5b347f936b71ac6d322c07912104d15839704
thunk_266850:
0x266850: JMP 0x006a22b0
; END FUNCTION thunk_266850
0x266855: INT3 ; original byte CC, padding
0x266856: INT3 ; original byte CC, padding
0x266857: INT3 ; original byte CC, padding

; FUNCTION thunk_266858 [0x266858, 0x26685c] | file +0x910 | ev_df166f83af68846c8787a22b60db92858c5297f11c0e5021462d71dc3a774fa4
thunk_266858:
0x266858: JMP 0x006ae640
; END FUNCTION thunk_266858
0x26685d: INT3 ; original byte CC, padding
0x26685e: INT3 ; original byte CC, padding
0x26685f: INT3 ; original byte CC, padding

; FUNCTION thunk_266860 [0x266860, 0x266864] | file +0x918 | ev_0fdd27d74cd24b4f8db75581de4388713e3597d065d3842c8af4f054c455ff46
thunk_266860:
0x266860: JMP 0x006ae7f0
; END FUNCTION thunk_266860
0x266865: INT3 ; original byte CC, padding
0x266866: INT3 ; original byte CC, padding
0x266867: INT3 ; original byte CC, padding

; FUNCTION thunk_266868 [0x266868, 0x26686c] | file +0x920 | ev_fc62fcbabf14463ab5445229b64c21674fbb7a0e14b7c8d18f89f180b63d1a35
thunk_266868:
0x266868: JMP 0x001813b0
; END FUNCTION thunk_266868
0x26686d: INT3 ; original byte CC, padding
0x26686e: INT3 ; original byte CC, padding
0x26686f: INT3 ; original byte CC, padding

; FUNCTION thunk_266870 [0x266870, 0x266874] | file +0x928 | ev_e2d4aad35945259cea115215ff1ab977a4b05020f234b4e2d5529ecfaf679d6c
thunk_266870:
0x266870: JMP 0x006befa0
; END FUNCTION thunk_266870
0x266875: INT3 ; original byte CC, padding
0x266876: INT3 ; original byte CC, padding
0x266877: INT3 ; original byte CC, padding

; FUNCTION thunk_266878 [0x266878, 0x26687c] | file +0x930 | ev_a3fad9735b44d843a7b2df48591f3fdd19bcad9229cd6cc9fa12ae57295fafdb
thunk_266878:
0x266878: JMP 0x00188040
; END FUNCTION thunk_266878
0x26687d: INT3 ; original byte CC, padding
0x26687e: INT3 ; original byte CC, padding
0x26687f: INT3 ; original byte CC, padding

; FUNCTION thunk_266880 [0x266880, 0x266884] | file +0x938 | ev_cb5c5a617a74303d22c2870604c190a2c74691cea1254e2590feb42cebc14908
thunk_266880:
0x266880: JMP 0x006d0b00
; END FUNCTION thunk_266880
0x266885: INT3 ; original byte CC, padding
0x266886: INT3 ; original byte CC, padding
0x266887: INT3 ; original byte CC, padding

; FUNCTION thunk_266888 [0x266888, 0x26688c] | file +0x940 | ev_0c3c38a29d01d8bdd25da4829b302df5d6745d42fe41808735ca9a72b6b3ecc5
thunk_266888:
0x266888: JMP 0x006d1100
; END FUNCTION thunk_266888
0x26688d: INT3 ; original byte CC, padding
0x26688e: INT3 ; original byte CC, padding
0x26688f: INT3 ; original byte CC, padding

; FUNCTION thunk_266890 [0x266890, 0x266894] | file +0x948 | ev_6b973f5fb069a1d3cbe8d7d4aabeb6bcee863c0240424f8a6914cece654d8dc4
thunk_266890:
0x266890: JMP 0x006d1260
; END FUNCTION thunk_266890
0x266895: INT3 ; original byte CC, padding
0x266896: INT3 ; original byte CC, padding
0x266897: INT3 ; original byte CC, padding

; FUNCTION thunk_266898 [0x266898, 0x26689c] | file +0x950 | ev_8b28ef61b7456567df4642cc9116b8671bba7aa5b95ff4372db799c6ba25dc2d
thunk_266898:
0x266898: JMP 0x006d13e0
; END FUNCTION thunk_266898
0x26689d: INT3 ; original byte CC, padding
0x26689e: INT3 ; original byte CC, padding
0x26689f: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a0 [0x2668a0, 0x2668a4] | file +0x958 | ev_fa00b3d0152f45a894b8ec075f6bf10efe75850a819b491d29e92959b6b8731f
thunk_2668a0:
0x2668a0: JMP 0x006d1520
; END FUNCTION thunk_2668a0
0x2668a5: INT3 ; original byte CC, padding
0x2668a6: INT3 ; original byte CC, padding
0x2668a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a8 [0x2668a8, 0x2668ac] | file +0x960 | ev_d78f08e03b31ffa2b2efe42a6cfb4536afb928a6c7f119a024a22b05f40899ff
thunk_2668a8:
0x2668a8: JMP 0x006d1640
; END FUNCTION thunk_2668a8
0x2668ad: INT3 ; original byte CC, padding
0x2668ae: INT3 ; original byte CC, padding
0x2668af: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b0 [0x2668b0, 0x2668b4] | file +0x968 | ev_3ed67d6c97c92967a395908a8a040edb330be148f28e2c64059b679195b59eae
thunk_2668b0:
0x2668b0: JMP 0x006d1720
; END FUNCTION thunk_2668b0
0x2668b5: INT3 ; original byte CC, padding
0x2668b6: INT3 ; original byte CC, padding
0x2668b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b8 [0x2668b8, 0x2668bc] | file +0x970 | ev_de93f54afb23cbd9b4b3762b6edbec96ba6addd3a7c90c972215bce85e5605f8
thunk_2668b8:
0x2668b8: JMP 0x006dc660
; END FUNCTION thunk_2668b8
0x2668bd: INT3 ; original byte CC, padding
0x2668be: INT3 ; original byte CC, padding
0x2668bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c0 [0x2668c0, 0x2668c4] | file +0x978 | ev_3e530c546d978a4cde1ea40098241ece409f40b0be36a2293bc70eb3a70892d2
thunk_2668c0:
0x2668c0: JMP 0x006dc690
; END FUNCTION thunk_2668c0
0x2668c5: INT3 ; original byte CC, padding
0x2668c6: INT3 ; original byte CC, padding
0x2668c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c8 [0x2668c8, 0x2668cc] | file +0x980 | ev_4029b49e23f105d9fd959b8d0e79ee611fff70d5deb5b25c1ec32f063cdbf7d2
thunk_2668c8:
0x2668c8: JMP 0x006dc6a0
; END FUNCTION thunk_2668c8
0x2668cd: INT3 ; original byte CC, padding
0x2668ce: INT3 ; original byte CC, padding
0x2668cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d0 [0x2668d0, 0x2668d4] | file +0x988 | ev_28820dcd9e75794b371215f8085c8fc2e919e52036eb5b329b5618bbecaa8502
thunk_2668d0:
0x2668d0: JMP 0x006e0920
; END FUNCTION thunk_2668d0
0x2668d5: INT3 ; original byte CC, padding
0x2668d6: INT3 ; original byte CC, padding
0x2668d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d8 [0x2668d8, 0x2668dc] | file +0x990 | ev_48d27fa99d4bfbfd01b9c0cfc4e1983ac381df090d15929fd844727932ef39f8
thunk_2668d8:
0x2668d8: JMP 0x006e1440
; END FUNCTION thunk_2668d8
0x2668dd: INT3 ; original byte CC, padding
0x2668de: INT3 ; original byte CC, padding
0x2668df: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e0 [0x2668e0, 0x2668e4] | file +0x998 | ev_7aa82add6e61823b6e8626df3d716de65e3fdba037ff334b9a282990cc834fcc
thunk_2668e0:
0x2668e0: JMP 0x006e1450
; END FUNCTION thunk_2668e0
0x2668e5: INT3 ; original byte CC, padding
0x2668e6: INT3 ; original byte CC, padding
0x2668e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e8 [0x2668e8, 0x2668ec] | file +0x9a0 | ev_7366c86f363f041f011d7a626d3635808a0a7efc1961a826359904110403c080
thunk_2668e8:
0x2668e8: JMP 0x00189a70
; END FUNCTION thunk_2668e8
0x2668ed: INT3 ; original byte CC, padding
0x2668ee: INT3 ; original byte CC, padding
0x2668ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f0 [0x2668f0, 0x2668f4] | file +0x9a8 | ev_d35c35a0ef27616e2538e5e78e8eb0d78e896dedfca6d619b3ac2c0ce3a0f144
thunk_2668f0:
0x2668f0: JMP 0x00190aa0
; END FUNCTION thunk_2668f0
0x2668f5: INT3 ; original byte CC, padding
0x2668f6: INT3 ; original byte CC, padding
0x2668f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f8 [0x2668f8, 0x2668fc] | file +0x9b0 | ev_285a07576ea147e47d5a4f684fda3d98049a70bc491220a6859a2ff207cf32a2
thunk_2668f8:
0x2668f8: JMP 0x00702970
; END FUNCTION thunk_2668f8
0x2668fd: INT3 ; original byte CC, padding
0x2668fe: INT3 ; original byte CC, padding
0x2668ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266900 [0x266900, 0x266904] | file +0x9b8 | ev_79a39a11fc3f4350741dfbe92dbb3ee9d03d1f0038ac550efcf3abe6aa034267
thunk_266900:
0x266900: JMP 0x00702d60
; END FUNCTION thunk_266900
0x266905: INT3 ; original byte CC, padding
0x266906: INT3 ; original byte CC, padding
0x266907: INT3 ; original byte CC, padding

; FUNCTION thunk_266908 [0x266908, 0x26690c] | file +0x9c0 | ev_c465dba0b2d910dc7e883d6f859825f028af61a03af466d233c429a1c3437066
thunk_266908:
0x266908: JMP 0x00706170
; END FUNCTION thunk_266908
0x26690d: INT3 ; original byte CC, padding
0x26690e: INT3 ; original byte CC, padding
0x26690f: INT3 ; original byte CC, padding

; FUNCTION thunk_266910 [0x266910, 0x266914] | file +0x9c8 | ev_ef9fedeb9e387dbcb7d3290bec8b7689777232b05d6c3bb1b117ce64c18f2c5d
thunk_266910:
0x266910: JMP 0x007061f0
; END FUNCTION thunk_266910
0x266915: INT3 ; original byte CC, padding
0x266916: INT3 ; original byte CC, padding
0x266917: INT3 ; original byte CC, padding

; FUNCTION thunk_266918 [0x266918, 0x26691c] | file +0x9d0 | ev_2af3c5ed42b89ca47470939543fcc7eb737ab28171a4cd5c8133946d4bffebc8
thunk_266918:
0x266918: JMP 0x0070ff00
; END FUNCTION thunk_266918
0x26691d: INT3 ; original byte CC, padding
0x26691e: INT3 ; original byte CC, padding
0x26691f: INT3 ; original byte CC, padding

; FUNCTION thunk_266920 [0x266920, 0x266924] | file +0x9d8 | ev_8ba8242e089252d99a8cc8a7db165be4787cdc73249a67a9d3de406b2f92243b
thunk_266920:
0x266920: JMP 0x0070ffb0
; END FUNCTION thunk_266920
0x266925: INT3 ; original byte CC, padding
0x266926: INT3 ; original byte CC, padding
0x266927: INT3 ; original byte CC, padding

; FUNCTION thunk_266928 [0x266928, 0x26692c] | file +0x9e0 | ev_bde685656623cf261c8d2a68eb1a624c013d1f1b4b0e9c0e93f302aab6068365
thunk_266928:
0x266928: JMP 0x007101c0
; END FUNCTION thunk_266928
0x26692d: INT3 ; original byte CC, padding
0x26692e: INT3 ; original byte CC, padding
0x26692f: INT3 ; original byte CC, padding

; FUNCTION thunk_266930 [0x266930, 0x266934] | file +0x9e8 | ev_b7ffb8877836166a4a685c022bc96bc3e0ab506a2439a5c6dee2f66a6ca82322
thunk_266930:
0x266930: JMP 0x00710320
; END FUNCTION thunk_266930
0x266935: INT3 ; original byte CC, padding
0x266936: INT3 ; original byte CC, padding
0x266937: INT3 ; original byte CC, padding

; FUNCTION thunk_266938 [0x266938, 0x26693c] | file +0x9f0 | ev_7f6f171a1627ab6995130bf2a96eb88ad7d18a6c294863cb2a05e16007aee4b8
thunk_266938:
0x266938: JMP 0x00712bb0
; END FUNCTION thunk_266938
0x26693d: INT3 ; original byte CC, padding
0x26693e: INT3 ; original byte CC, padding
0x26693f: INT3 ; original byte CC, padding

; FUNCTION thunk_266940 [0x266940, 0x266944] | file +0x9f8 | ev_dddfee7d6fc78e04fc2e8b6de476d83bd91928a276a0e49b68df7ca11e341a36
thunk_266940:
0x266940: JMP 0x00716360
; END FUNCTION thunk_266940
0x266945: INT3 ; original byte CC, padding
0x266946: INT3 ; original byte CC, padding
0x266947: INT3 ; original byte CC, padding

; FUNCTION thunk_266948 [0x266948, 0x26694c] | file +0xa00 | ev_810262db33bcfe19b9125a9a40bfbc0dcf0ca1d8f07ea1083aa8eb64c2683ed7
thunk_266948:
0x266948: JMP 0x0072f970
; END FUNCTION thunk_266948
0x26694d: INT3 ; original byte CC, padding
0x26694e: INT3 ; original byte CC, padding
0x26694f: INT3 ; original byte CC, padding

; FUNCTION thunk_266950 [0x266950, 0x266954] | file +0xa08 | ev_bb75578d2158f4a93fd8ad186335b68f4e86e611e1046b5612d66d40e6f42c05
thunk_266950:
0x266950: JMP 0x0072f990
; END FUNCTION thunk_266950
0x266955: INT3 ; original byte CC, padding
0x266956: INT3 ; original byte CC, padding
0x266957: INT3 ; original byte CC, padding

; FUNCTION thunk_266958 [0x266958, 0x26695c] | file +0xa10 | ev_cc7869a755aa94e9948250e267657fb3484ae5d84c3939e93ee81e25a17c6658
thunk_266958:
0x266958: JMP 0x0072fa20
; END FUNCTION thunk_266958
0x26695d: INT3 ; original byte CC, padding
0x26695e: INT3 ; original byte CC, padding
0x26695f: INT3 ; original byte CC, padding

; FUNCTION thunk_266960 [0x266960, 0x266964] | file +0xa18 | ev_d41be3a77fe7d970714413a2db7362e7378afaf1c234aca1fb495459da2981f4
thunk_266960:
0x266960: JMP 0x00246e30
; END FUNCTION thunk_266960
0x266965: INT3 ; original byte CC, padding
0x266966: INT3 ; original byte CC, padding
0x266967: INT3 ; original byte CC, padding

; FUNCTION thunk_266968 [0x266968, 0x26696c] | file +0xa20 | ev_86447051030d85af30d27f1ae658d2b53230586b68e795e6877819c143272823
thunk_266968:
0x266968: JMP 0x007647f0
; END FUNCTION thunk_266968
0x26696d: INT3 ; original byte CC, padding
0x26696e: INT3 ; original byte CC, padding
0x26696f: INT3 ; original byte CC, padding

; FUNCTION thunk_266970 [0x266970, 0x266974] | file +0xa28 | ev_8f35ce01a7e76f246111c0713a73ab48052fb3758ed42ddf08dadd78f3ee8b2e
thunk_266970:
0x266970: JMP 0x00773710
; END FUNCTION thunk_266970
0x266975: INT3 ; original byte CC, padding
0x266976: INT3 ; original byte CC, padding
0x266977: INT3 ; original byte CC, padding

; FUNCTION thunk_266978 [0x266978, 0x26697c] | file +0xa30 | ev_67777dd4e1619b577951547dcecfe4e41541a70e9352d9f4fd8e4c18c15e790e
thunk_266978:
0x266978: JMP 0x00775950
; END FUNCTION thunk_266978
0x26697d: INT3 ; original byte CC, padding
0x26697e: INT3 ; original byte CC, padding
0x26697f: INT3 ; original byte CC, padding

; FUNCTION thunk_266980 [0x266980, 0x266984] | file +0xa38 | ev_cc4f8e212f24a3d2a05a7ecfa0364795c5246f50343e1d895d0b927b5e9acbd9
thunk_266980:
0x266980: JMP 0x00799e90
; END FUNCTION thunk_266980
0x266985: INT3 ; original byte CC, padding
0x266986: INT3 ; original byte CC, padding
0x266987: INT3 ; original byte CC, padding

; FUNCTION thunk_266988 [0x266988, 0x26698c] | file +0xa40 | ev_18e241da46f5f68857625524ec967ff69786cb909ac6fa9f4ea3613ff4a373f6
thunk_266988:
0x266988: JMP 0x007b31f0
; END FUNCTION thunk_266988
0x26698d: INT3 ; original byte CC, padding
0x26698e: INT3 ; original byte CC, padding
0x26698f: INT3 ; original byte CC, padding

; FUNCTION thunk_266990 [0x266990, 0x266994] | file +0xa48 | ev_146209dccae72ac346c363a14fb22c9ebcf1badb24f205149cd1c2a71f73eb10
thunk_266990:
0x266990: JMP 0x007e23a0
; END FUNCTION thunk_266990
0x266995: INT3 ; original byte CC, padding
0x266996: INT3 ; original byte CC, padding
0x266997: INT3 ; original byte CC, padding

; FUNCTION thunk_266998 [0x266998, 0x26699c] | file +0xa50 | ev_07c806b885fdfad9a042087c47d941e3e27815570df71456554ae5f777e04f8a
thunk_266998:
0x266998: JMP 0x007e83e0
; END FUNCTION thunk_266998
0x26699d: INT3 ; original byte CC, padding
0x26699e: INT3 ; original byte CC, padding
0x26699f: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a0 [0x2669a0, 0x2669a4] | file +0xa58 | ev_be089efb1d3a783630ff9eb8e152388777867284e2e50833db979df30666a4fd
thunk_2669a0:
0x2669a0: JMP 0x007e8480
; END FUNCTION thunk_2669a0
0x2669a5: INT3 ; original byte CC, padding
0x2669a6: INT3 ; original byte CC, padding
0x2669a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a8 [0x2669a8, 0x2669ac] | file +0xa60 | ev_7a3ddf208002c5329e2906aceffed7dd3678f5bd7961d84302be0c17c52ea09f
thunk_2669a8:
0x2669a8: JMP 0x00c3b1b0
; END FUNCTION thunk_2669a8
0x2669ad: INT3 ; original byte CC, padding
0x2669ae: INT3 ; original byte CC, padding
0x2669af: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b0 [0x2669b0, 0x2669b4] | file +0xa68 | ev_bdb5f83bfc4dba4e75e19a3eef1d072394dabaa2ee2f9f656e038f3f43a9e595
thunk_2669b0:
0x2669b0: JMP 0x00c3c6e0
; END FUNCTION thunk_2669b0
0x2669b5: INT3 ; original byte CC, padding
0x2669b6: INT3 ; original byte CC, padding
0x2669b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b8 [0x2669b8, 0x2669bc] | file +0xa70 | ev_646a44996bac41d97d6bd466d9d89c6be5622fab00f3833056200cf520b54fe4
thunk_2669b8:
0x2669b8: JMP 0x00c3c690
; END FUNCTION thunk_2669b8
0x2669bd: INT3 ; original byte CC, padding
0x2669be: INT3 ; original byte CC, padding
0x2669bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c0 [0x2669c0, 0x2669c4] | file +0xa78 | ev_4362cb7f40b9eb146fac45118d165bc73bbc51e4d24d0134492add8ca5631b95
thunk_2669c0:
0x2669c0: JMP 0x00c3c730
; END FUNCTION thunk_2669c0
0x2669c5: INT3 ; original byte CC, padding
0x2669c6: INT3 ; original byte CC, padding
0x2669c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c8 [0x2669c8, 0x2669cc] | file +0xa80 | ev_a2defbb92015ed92c0ef482352ca69c0fb501a1cbddcc98ea3de49ae7ad35628
thunk_2669c8:
0x2669c8: JMP 0x00802220
; END FUNCTION thunk_2669c8
0x2669cd: INT3 ; original byte CC, padding
0x2669ce: INT3 ; original byte CC, padding
0x2669cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d0 [0x2669d0, 0x2669d4] | file +0xa88 | ev_8b0d6c0754c0b3b0f5920be4785507c6b59ae0d16e34c3c88580ef5102aa7c09
thunk_2669d0:
0x2669d0: JMP 0x008024f0
; END FUNCTION thunk_2669d0
0x2669d5: INT3 ; original byte CC, padding
0x2669d6: INT3 ; original byte CC, padding
0x2669d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d8 [0x2669d8, 0x2669dc] | file +0xa90 | ev_ad2127f94361c94e9ea3ce28f07b62b5f86902733f265d7410b1b50d7c2dcf34
thunk_2669d8:
0x2669d8: JMP 0x0080c570
; END FUNCTION thunk_2669d8
0x2669dd: INT3 ; original byte CC, padding
0x2669de: INT3 ; original byte CC, padding
0x2669df: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e0 [0x2669e0, 0x2669e4] | file +0xa98 | ev_107ae0a63c11b3b92fc64c7be5323a3eb435cad4abf4cfab408f51f081534354
thunk_2669e0:
0x2669e0: JMP 0x0082b300
; END FUNCTION thunk_2669e0
0x2669e5: INT3 ; original byte CC, padding
0x2669e6: INT3 ; original byte CC, padding
0x2669e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e8 [0x2669e8, 0x2669ec] | file +0xaa0 | ev_9ad5a3b6afeb0b6f0b925f04a856e87601c2bf950f8d2fb50a65e0136f58057a
thunk_2669e8:
0x2669e8: JMP 0x00920ee0
; END FUNCTION thunk_2669e8
0x2669ed: INT3 ; original byte CC, padding
0x2669ee: INT3 ; original byte CC, padding
0x2669ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f0 [0x2669f0, 0x2669f4] | file +0xaa8 | ev_a480cb6ab7d531f1320cc8242e87145c1c91b7d7a84222faf523f1c010f50494
thunk_2669f0:
0x2669f0: JMP 0x00920b90
; END FUNCTION thunk_2669f0
0x2669f5: INT3 ; original byte CC, padding
0x2669f6: INT3 ; original byte CC, padding
0x2669f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f8 [0x2669f8, 0x2669fc] | file +0xab0 | ev_063eb2665a5427fcd2306892c374cdbc281c7ad6593802712bc6c4b1efb017b7
thunk_2669f8:
0x2669f8: JMP 0x00830810
; END FUNCTION thunk_2669f8
0x2669fd: INT3 ; original byte CC, padding
0x2669fe: INT3 ; original byte CC, padding
0x2669ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266a00 [0x266a00, 0x266a04] | file +0xab8 | ev_29198ce2df122b645034527b9bb21acb52264c59b9daf0884f26625cd53e0086
thunk_266a00:
0x266a00: JMP 0x00830f00
; END FUNCTION thunk_266a00
0x266a05: INT3 ; original byte CC, padding
0x266a06: INT3 ; original byte CC, padding
0x266a07: INT3 ; original byte CC, padding

; FUNCTION thunk_266a08 [0x266a08, 0x266a0c] | file +0xac0 | ev_177dd7dc7b53ab81c2013acc266639880dbc8de7da863168a12b7fafb05569d0
thunk_266a08:
0x266a08: JMP 0x008352b0
; END FUNCTION thunk_266a08
0x266a0d: INT3 ; original byte CC, padding
0x266a0e: INT3 ; original byte CC, padding
0x266a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a10 [0x266a10, 0x266a14] | file +0xac8 | ev_0d5315ab6a16e41f21449cd36ebc5a3310ea3b201b5c2822cc1967b87fc5175d
thunk_266a10:
0x266a10: JMP 0x008352c0
; END FUNCTION thunk_266a10
0x266a15: INT3 ; original byte CC, padding
0x266a16: INT3 ; original byte CC, padding
0x266a17: INT3 ; original byte CC, padding

; FUNCTION thunk_266a18 [0x266a18, 0x266a1c] | file +0xad0 | ev_ec8c18935f45a48774dc5e604617b4fa54ed540c1146049e3259786a4611c0fe
thunk_266a18:
0x266a18: JMP 0x008352d0
; END FUNCTION thunk_266a18
0x266a1d: INT3 ; original byte CC, padding
0x266a1e: INT3 ; original byte CC, padding
0x266a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a20 [0x266a20, 0x266a24] | file +0xad8 | ev_67ccf19ae6261c26c1b465c290344d75286d87b8463b67ce27a2a00d373f25e1
thunk_266a20:
0x266a20: JMP 0x008352f0
; END FUNCTION thunk_266a20
0x266a25: INT3 ; original byte CC, padding
0x266a26: INT3 ; original byte CC, padding
0x266a27: INT3 ; original byte CC, padding

; FUNCTION thunk_266a28 [0x266a28, 0x266a2c] | file +0xae0 | ev_0fc4c28b309099d4fef2aa0441aada55fdb833e87dd6e611d54d6ce100ee2603
thunk_266a28:
0x266a28: JMP 0x00835440
; END FUNCTION thunk_266a28
0x266a2d: INT3 ; original byte CC, padding
0x266a2e: INT3 ; original byte CC, padding
0x266a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a30 [0x266a30, 0x266a34] | file +0xae8 | ev_b30b9cb2f6b10209ccef36a80c6226dec9100c5cdf04f409483c5df6c8d721cb
thunk_266a30:
0x266a30: JMP 0x00835450
; END FUNCTION thunk_266a30
0x266a35: INT3 ; original byte CC, padding
0x266a36: INT3 ; original byte CC, padding
0x266a37: INT3 ; original byte CC, padding

; FUNCTION thunk_266a38 [0x266a38, 0x266a3c] | file +0xaf0 | ev_1c89747d1cc419c82f65552dd5e9f398d08b9dd3c158550837d6d077fe5f1f9a
thunk_266a38:
0x266a38: JMP 0x00835490
; END FUNCTION thunk_266a38
0x266a3d: INT3 ; original byte CC, padding
0x266a3e: INT3 ; original byte CC, padding
0x266a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a40 [0x266a40, 0x266a44] | file +0xaf8 | ev_86c79d8831758bb566d4330365abf0f4f2fdd5f6cecd088a67fe9b63cbdb7eb7
thunk_266a40:
0x266a40: JMP 0x00835ad0
; END FUNCTION thunk_266a40
0x266a45: INT3 ; original byte CC, padding
0x266a46: INT3 ; original byte CC, padding
0x266a47: INT3 ; original byte CC, padding

; FUNCTION thunk_266a48 [0x266a48, 0x266a4c] | file +0xb00 | ev_995c50dcb18c9069c8f14612d6a1455003ea69b54876567c1e823ec636e9aa48
thunk_266a48:
0x266a48: JMP 0x00850870
; END FUNCTION thunk_266a48
0x266a4d: INT3 ; original byte CC, padding
0x266a4e: INT3 ; original byte CC, padding
0x266a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a50 [0x266a50, 0x266a54] | file +0xb08 | ev_5e329a7f38c7891bcb76d5475bccd7ac8a8253c93b2384eb3199eed3c1d6eb2c
thunk_266a50:
0x266a50: JMP 0x008702f0
; END FUNCTION thunk_266a50
0x266a55: INT3 ; original byte CC, padding
0x266a56: INT3 ; original byte CC, padding
0x266a57: INT3 ; original byte CC, padding

; FUNCTION thunk_266a58 [0x266a58, 0x266a5c] | file +0xb10 | ev_e0a5532f5aff1a4a2ee764559daee4f819665087f4630c432530d3cf5486f063
thunk_266a58:
0x266a58: JMP 0x008705d0
; END FUNCTION thunk_266a58
0x266a5d: INT3 ; original byte CC, padding
0x266a5e: INT3 ; original byte CC, padding
0x266a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a60 [0x266a60, 0x266a64] | file +0xb18 | ev_80548a6b40dfc2aeef643069f1ecbfbcaa660deb693d6dfc073b9d3e218c7cb8
thunk_266a60:
0x266a60: JMP 0x00872af0
; END FUNCTION thunk_266a60
0x266a65: INT3 ; original byte CC, padding
0x266a66: INT3 ; original byte CC, padding
0x266a67: INT3 ; original byte CC, padding

; FUNCTION thunk_266a68 [0x266a68, 0x266a6c] | file +0xb20 | ev_8a91bd014432af5bccf4cd9785804c8daa7551ec5454259f0d263e139613a20a
thunk_266a68:
0x266a68: JMP 0x00873800
; END FUNCTION thunk_266a68
0x266a6d: INT3 ; original byte CC, padding
0x266a6e: INT3 ; original byte CC, padding
0x266a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a70 [0x266a70, 0x266a74] | file +0xb28 | ev_ace7e386aef97a8938bc5277da2304ae349721e0be6629dfaab82c91e9879fe3
thunk_266a70:
0x266a70: JMP 0x00063a40
; END FUNCTION thunk_266a70
0x266a75: INT3 ; original byte CC, padding
0x266a76: INT3 ; original byte CC, padding
0x266a77: INT3 ; original byte CC, padding

; FUNCTION thunk_266a78 [0x266a78, 0x266a7c] | file +0xb30 | ev_4f9cbc3755ffa00d9bc90c78dd059443d243871133d78ad726b0b8a1fa8c59f1
thunk_266a78:
0x266a78: JMP 0x00066370
; END FUNCTION thunk_266a78
0x266a7d: INT3 ; original byte CC, padding
0x266a7e: INT3 ; original byte CC, padding
0x266a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a80 [0x266a80, 0x266a84] | file +0xb38 | ev_d1253b2b6a410cdb32f733044e199ff7bc1b88e3fa164e1a9321bfe29d2701a4
thunk_266a80:
0x266a80: JMP 0x000e6590
; END FUNCTION thunk_266a80
0x266a85: INT3 ; original byte CC, padding
0x266a86: INT3 ; original byte CC, padding
0x266a87: INT3 ; original byte CC, padding

; FUNCTION thunk_266a88 [0x266a88, 0x266a8c] | file +0xb40 | ev_a70131a343e30187fec4ee4ddd3e10432a8d5db8f7b758eaf398ef0ff9545c41
thunk_266a88:
0x266a88: JMP 0x000e65a0
; END FUNCTION thunk_266a88
0x266a8d: INT3 ; original byte CC, padding
0x266a8e: INT3 ; original byte CC, padding
0x266a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a90 [0x266a90, 0x266a94] | file +0xb48 | ev_580401ac889df9a5a5a73e71f8edea677b42be167a238dc2dff457a9c9f336ff
thunk_266a90:
0x266a90: JMP 0x000e6760
; END FUNCTION thunk_266a90
0x266a95: INT3 ; original byte CC, padding
0x266a96: INT3 ; original byte CC, padding
0x266a97: INT3 ; original byte CC, padding

; FUNCTION thunk_266a98 [0x266a98, 0x266a9c] | file +0xb50 | ev_172618d9f6bde68af37706eabeedff3f52d26fe1bfb0328d5fe417c3de8cfab0
thunk_266a98:
0x266a98: JMP 0x000e6870
; END FUNCTION thunk_266a98
0x266a9d: INT3 ; original byte CC, padding
0x266a9e: INT3 ; original byte CC, padding
0x266a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa0 [0x266aa0, 0x266aa4] | file +0xb58 | ev_b1e956b19177c725cc5b0de3abaf0d87a3b82bb14d6e9f4ec8831e2d91b54c47
thunk_266aa0:
0x266aa0: JMP 0x000e7f90
; END FUNCTION thunk_266aa0
0x266aa5: INT3 ; original byte CC, padding
0x266aa6: INT3 ; original byte CC, padding
0x266aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa8 [0x266aa8, 0x266aac] | file +0xb60 | ev_cb2f12ba0838083ded8dec004c46678be74c9abcc86c76566af579016dba3da5
thunk_266aa8:
0x266aa8: JMP 0x000e9fa0
; END FUNCTION thunk_266aa8
0x266aad: INT3 ; original byte CC, padding
0x266aae: INT3 ; original byte CC, padding
0x266aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab0 [0x266ab0, 0x266ab4] | file +0xb68 | ev_a3052214a521cc3208409e021fa100a76d9261caf5a168a1b72d321750d2b45b
thunk_266ab0:
0x266ab0: JMP 0x000ea670
; END FUNCTION thunk_266ab0
0x266ab5: INT3 ; original byte CC, padding
0x266ab6: INT3 ; original byte CC, padding
0x266ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab8 [0x266ab8, 0x266abc] | file +0xb70 | ev_ab5d43e0a40ba98e026fe8788b90cb6bded3dbb9083f30de951f5b55b6611259
thunk_266ab8:
0x266ab8: JMP 0x000ea760
; END FUNCTION thunk_266ab8
0x266abd: INT3 ; original byte CC, padding
0x266abe: INT3 ; original byte CC, padding
0x266abf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac0 [0x266ac0, 0x266ac4] | file +0xb78 | ev_dfd025dd38eb834c1c4d4e37cf5c20a054f6b368c99fd5c1fcf91a2b04bdb89b
thunk_266ac0:
0x266ac0: JMP 0x000eb0a0
; END FUNCTION thunk_266ac0
0x266ac5: INT3 ; original byte CC, padding
0x266ac6: INT3 ; original byte CC, padding
0x266ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac8 [0x266ac8, 0x266acc] | file +0xb80 | ev_0ba290f61e689c4ddfbc0e9dcd74c90382de6a3844dbe481dd4b5f0c00a605c2
thunk_266ac8:
0x266ac8: JMP 0x000eb190
; END FUNCTION thunk_266ac8
0x266acd: INT3 ; original byte CC, padding
0x266ace: INT3 ; original byte CC, padding
0x266acf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad0 [0x266ad0, 0x266ad4] | file +0xb88 | ev_c7f735b31597949f8b3d8f12d6282e1f65af64f8d580a8b0a79e0b9dc7e33794
thunk_266ad0:
0x266ad0: JMP 0x000ed000
; END FUNCTION thunk_266ad0
0x266ad5: INT3 ; original byte CC, padding
0x266ad6: INT3 ; original byte CC, padding
0x266ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad8 [0x266ad8, 0x266adc] | file +0xb90 | ev_3696ca577c07d3cd8b4dd4f5e7485fc4ccec33eea40a7e33578374e1d59a95f4
thunk_266ad8:
0x266ad8: JMP 0x000ed110
; END FUNCTION thunk_266ad8
0x266add: INT3 ; original byte CC, padding
0x266ade: INT3 ; original byte CC, padding
0x266adf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae0 [0x266ae0, 0x266ae4] | file +0xb98 | ev_3540435ffca26bbb8b563d995bb2524984e42644dbbb93606680668159825e87
thunk_266ae0:
0x266ae0: JMP 0x0088a8a0
; END FUNCTION thunk_266ae0
0x266ae5: INT3 ; original byte CC, padding
0x266ae6: INT3 ; original byte CC, padding
0x266ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae8 [0x266ae8, 0x266aec] | file +0xba0 | ev_54ff9ea03fe46568160ea2de9f8a562e1d312294a5ade2a6b4bdcdada49b1f8c
thunk_266ae8:
0x266ae8: JMP 0x0089cdf0
; END FUNCTION thunk_266ae8
0x266aed: INT3 ; original byte CC, padding
0x266aee: INT3 ; original byte CC, padding
0x266aef: INT3 ; original byte CC, padding

; FUNCTION thunk_266af0 [0x266af0, 0x266af4] | file +0xba8 | ev_e99f643f0db2c0d24db4fcaf3b5de144991b1adc450c03f6d71331e88d5c9524
thunk_266af0:
0x266af0: JMP 0x000eeb50
; END FUNCTION thunk_266af0
0x266af5: INT3 ; original byte CC, padding
0x266af6: INT3 ; original byte CC, padding
0x266af7: INT3 ; original byte CC, padding

; FUNCTION thunk_266af8 [0x266af8, 0x266afc] | file +0xbb0 | ev_7e7fe8b4dde4de2281a4f4bd9bdf5add95be25e22ea62e2e3998fb3936a080ff
thunk_266af8:
0x266af8: JMP 0x008cb250
; END FUNCTION thunk_266af8
0x266afd: INT3 ; original byte CC, padding
0x266afe: INT3 ; original byte CC, padding
0x266aff: INT3 ; original byte CC, padding

; FUNCTION thunk_266b00 [0x266b00, 0x266b04] | file +0xbb8 | ev_253a16e4058f7de88d51b504ce6a1bacc5be58252642dbbbeee6505711d0648a
thunk_266b00:
0x266b00: JMP 0x008cb390
; END FUNCTION thunk_266b00
0x266b05: INT3 ; original byte CC, padding
0x266b06: INT3 ; original byte CC, padding
0x266b07: INT3 ; original byte CC, padding

; FUNCTION thunk_266b08 [0x266b08, 0x266b0c] | file +0xbc0 | ev_fea9d8ff31d0c4fdadf83b22e249aee209225d68e062e0fa46b431c0c49c6dd8
thunk_266b08:
0x266b08: JMP 0x008d2f60
; END FUNCTION thunk_266b08
0x266b0d: INT3 ; original byte CC, padding
0x266b0e: INT3 ; original byte CC, padding
0x266b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b10 [0x266b10, 0x266b14] | file +0xbc8 | ev_135119e632a722801f99ad8c2796d9c5d57282defcf1d58fc48cdc7c8e74cb29
thunk_266b10:
0x266b10: JMP 0x008d2f90
; END FUNCTION thunk_266b10
0x266b15: INT3 ; original byte CC, padding
0x266b16: INT3 ; original byte CC, padding
0x266b17: INT3 ; original byte CC, padding

; FUNCTION thunk_266b18 [0x266b18, 0x266b1c] | file +0xbd0 | ev_1c2fdbeb60f49688af5703a743188a25b5530b226b89c34973c7416c1b14c502
thunk_266b18:
0x266b18: JMP 0x008d8230
; END FUNCTION thunk_266b18
0x266b1d: INT3 ; original byte CC, padding
0x266b1e: INT3 ; original byte CC, padding
0x266b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b20 [0x266b20, 0x266b24] | file +0xbd8 | ev_05e0040e1f1449251377c771031f3d1467b9cea3be2dbb969252562a3d9c6a4b
thunk_266b20:
0x266b20: JMP 0x008d8de0
; END FUNCTION thunk_266b20
0x266b25: INT3 ; original byte CC, padding
0x266b26: INT3 ; original byte CC, padding
0x266b27: INT3 ; original byte CC, padding

; FUNCTION thunk_266b28 [0x266b28, 0x266b2c] | file +0xbe0 | ev_3d84d0e832dea1f4393c51cf621401b1efd43c186c59c97d0e1290835b35a0cb
thunk_266b28:
0x266b28: JMP 0x008d97b0
; END FUNCTION thunk_266b28
0x266b2d: INT3 ; original byte CC, padding
0x266b2e: INT3 ; original byte CC, padding
0x266b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b30 [0x266b30, 0x266b34] | file +0xbe8 | ev_867be95cdeb3d9b186a680fcb42dc2eef398f6ee5999819b185940e385522a2c
thunk_266b30:
0x266b30: JMP 0x008d9910
; END FUNCTION thunk_266b30
0x266b35: INT3 ; original byte CC, padding
0x266b36: INT3 ; original byte CC, padding
0x266b37: INT3 ; original byte CC, padding

; FUNCTION thunk_266b38 [0x266b38, 0x266b3c] | file +0xbf0 | ev_98a6115dac41b7f98acf672e285af4338aa06739dcba52f9d8b424b8b65ba3c3
thunk_266b38:
0x266b38: JMP 0x008da4c0
; END FUNCTION thunk_266b38
0x266b3d: INT3 ; original byte CC, padding
0x266b3e: INT3 ; original byte CC, padding
0x266b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b40 [0x266b40, 0x266b44] | file +0xbf8 | ev_28661288bbd93c64c4601ab505454f1242fe1271953adf1d17cfaa755a4dffd0
thunk_266b40:
0x266b40: JMP 0x008da570
; END FUNCTION thunk_266b40
0x266b45: INT3 ; original byte CC, padding
0x266b46: INT3 ; original byte CC, padding
0x266b47: INT3 ; original byte CC, padding

; FUNCTION thunk_266b48 [0x266b48, 0x266b4c] | file +0xc00 | ev_bd344f0bd9ec7d067a0cb4c8208d913f749af95b11793f5da2827e74faf79109
thunk_266b48:
0x266b48: JMP 0x008da5b0
; END FUNCTION thunk_266b48
0x266b4d: INT3 ; original byte CC, padding
0x266b4e: INT3 ; original byte CC, padding
0x266b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b50 [0x266b50, 0x266b54] | file +0xc08 | ev_f8a42572829c10ec77ab49408e31d2ffb005a17eb5e53f6695770add06be8082
thunk_266b50:
0x266b50: JMP 0x00904c80
; END FUNCTION thunk_266b50
0x266b55: INT3 ; original byte CC, padding
0x266b56: INT3 ; original byte CC, padding
0x266b57: INT3 ; original byte CC, padding

; FUNCTION thunk_266b58 [0x266b58, 0x266b5c] | file +0xc10 | ev_8a13f5a851e775e80be452193fbd4d590b6d04ccbc7dff49f1656f50ed85ff91
thunk_266b58:
0x266b58: JMP 0x00904e60
; END FUNCTION thunk_266b58
0x266b5d: INT3 ; original byte CC, padding
0x266b5e: INT3 ; original byte CC, padding
0x266b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b60 [0x266b60, 0x266b64] | file +0xc18 | ev_55a50802f4a0a58d620581bdf6d487bbdbf788f27ea4ebade9bcf71add39a1dc
thunk_266b60:
0x266b60: JMP 0x0091d400
; END FUNCTION thunk_266b60
0x266b65: INT3 ; original byte CC, padding
0x266b66: INT3 ; original byte CC, padding
0x266b67: INT3 ; original byte CC, padding

; FUNCTION thunk_266b68 [0x266b68, 0x266b6c] | file +0xc20 | ev_a3b427a4474839c0c8a0e35e824e29e550bf1ee74d21c07a0abcdaee31a56056
thunk_266b68:
0x266b68: JMP 0x0091d4a0
; END FUNCTION thunk_266b68
0x266b6d: INT3 ; original byte CC, padding
0x266b6e: INT3 ; original byte CC, padding
0x266b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b70 [0x266b70, 0x266b74] | file +0xc28 | ev_e8467fac24f549ccc576dbf816d0d2d2ccd83f5700eb06faa6c91121b928fdd0
thunk_266b70:
0x266b70: JMP 0x00a821d0
; END FUNCTION thunk_266b70
0x266b75: INT3 ; original byte CC, padding
0x266b76: INT3 ; original byte CC, padding
0x266b77: INT3 ; original byte CC, padding

; FUNCTION thunk_266b78 [0x266b78, 0x266b7c] | file +0xc30 | ev_8f47985372645d0671a737f6dfdc8c8ebd02beaa2f6b203fa63da2a5b8f22e7b
thunk_266b78:
0x266b78: JMP 0x00b42120
; END FUNCTION thunk_266b78
0x266b7d: INT3 ; original byte CC, padding
0x266b7e: INT3 ; original byte CC, padding
0x266b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b80 [0x266b80, 0x266b84] | file +0xc38 | ev_fd684889e15d4b26e0ee82dee8ba632bc13425741ac010622add8dae7219815d
thunk_266b80:
0x266b80: JMP 0x00964f30
; END FUNCTION thunk_266b80
0x266b85: INT3 ; original byte CC, padding
0x266b86: INT3 ; original byte CC, padding
0x266b87: INT3 ; original byte CC, padding

; FUNCTION thunk_266b88 [0x266b88, 0x266b8c] | file +0xc40 | ev_f2df38026d5491e448e5063aac5789ad983601c453d578988858f92b6d03ae2c
thunk_266b88:
0x266b88: JMP 0x00975f50
; END FUNCTION thunk_266b88
0x266b8d: INT3 ; original byte CC, padding
0x266b8e: INT3 ; original byte CC, padding
0x266b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b90 [0x266b90, 0x266b94] | file +0xc48 | ev_10d8a996d05141151a80648eaa04914a17d0858789d77b5b14476705981530fe
thunk_266b90:
0x266b90: JMP 0x00976200
; END FUNCTION thunk_266b90
0x266b95: INT3 ; original byte CC, padding
0x266b96: INT3 ; original byte CC, padding
0x266b97: INT3 ; original byte CC, padding

; FUNCTION thunk_266b98 [0x266b98, 0x266b9c] | file +0xc50 | ev_c3116b49143e9b6ff94c37355177e2bdb67bb1b2e76d75c69776fb7bb325b566
thunk_266b98:
0x266b98: JMP 0x0098c950
; END FUNCTION thunk_266b98
0x266b9d: INT3 ; original byte CC, padding
0x266b9e: INT3 ; original byte CC, padding
0x266b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba0 [0x266ba0, 0x266ba4] | file +0xc58 | ev_d5357955364e0302a1c35a09ecc6540c8689b4e80dfafeb3e3bdcbaf003676e0
thunk_266ba0:
0x266ba0: JMP 0x0098cc30
; END FUNCTION thunk_266ba0
0x266ba5: INT3 ; original byte CC, padding
0x266ba6: INT3 ; original byte CC, padding
0x266ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba8 [0x266ba8, 0x266bac] | file +0xc60 | ev_7eb181636e2cdb2333dd763ae4894fc17222923d697e92963d6ba4b611dcda21
thunk_266ba8:
0x266ba8: JMP 0x0098cf30
; END FUNCTION thunk_266ba8
0x266bad: INT3 ; original byte CC, padding
0x266bae: INT3 ; original byte CC, padding
0x266baf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb0 [0x266bb0, 0x266bb4] | file +0xc68 | ev_2f19404c650e0b9290f01b624e2d3247ddfabf77eef32e16a5484806b710f012
thunk_266bb0:
0x266bb0: JMP 0x0098d6e0
; END FUNCTION thunk_266bb0
0x266bb5: INT3 ; original byte CC, padding
0x266bb6: INT3 ; original byte CC, padding
0x266bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb8 [0x266bb8, 0x266bbc] | file +0xc70 | ev_b05bb4840cd18187e9cfeab82d33fe5e27867653043f55bd77bb02218ee6fb15
thunk_266bb8:
0x266bb8: JMP 0x0098e5d0
; END FUNCTION thunk_266bb8
0x266bbd: INT3 ; original byte CC, padding
0x266bbe: INT3 ; original byte CC, padding
0x266bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc0 [0x266bc0, 0x266bc4] | file +0xc78 | ev_79af95be2d186c085c2c3aeced8a2aeeb8b6718f7d34419ecbb36bf6ed2a29e6
thunk_266bc0:
0x266bc0: JMP 0x0098e700
; END FUNCTION thunk_266bc0
0x266bc5: INT3 ; original byte CC, padding
0x266bc6: INT3 ; original byte CC, padding
0x266bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc8 [0x266bc8, 0x266bcc] | file +0xc80 | ev_8341b535cc158bc64ba7d262cb376e3cec41502b7caeb9d18b2601d189b8c5c3
thunk_266bc8:
0x266bc8: JMP 0x00992170
; END FUNCTION thunk_266bc8
0x266bcd: INT3 ; original byte CC, padding
0x266bce: INT3 ; original byte CC, padding
0x266bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd0 [0x266bd0, 0x266bd4] | file +0xc88 | ev_e166acea8ad67d05799944a6f7fdd59ec5f3b1ac8764a5c1c9aab83775552d58
thunk_266bd0:
0x266bd0: JMP 0x00992240
; END FUNCTION thunk_266bd0
0x266bd5: INT3 ; original byte CC, padding
0x266bd6: INT3 ; original byte CC, padding
0x266bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd8 [0x266bd8, 0x266bdc] | file +0xc90 | ev_85e73f067c4170bb5b3458130fd57a6af13915d7b31859b4fc64c3f06ed82bac
thunk_266bd8:
0x266bd8: JMP 0x000f5400
; END FUNCTION thunk_266bd8
0x266bdd: INT3 ; original byte CC, padding
0x266bde: INT3 ; original byte CC, padding
0x266bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266be0 [0x266be0, 0x266be4] | file +0xc98 | ev_842b4c5c42c065668d984eae4c9142db76b388ac3869191a2e6774a1dd29092b
thunk_266be0:
0x266be0: JMP 0x009a2320
; END FUNCTION thunk_266be0
0x266be5: INT3 ; original byte CC, padding
0x266be6: INT3 ; original byte CC, padding
0x266be7: INT3 ; original byte CC, padding

; FUNCTION thunk_266be8 [0x266be8, 0x266bec] | file +0xca0 | ev_030a86c722bd8b0115511456a8e9c167e2fcee9c0bc3fef7480f00c92d243c2a
thunk_266be8:
0x266be8: JMP 0x009a5720
; END FUNCTION thunk_266be8
0x266bed: INT3 ; original byte CC, padding
0x266bee: INT3 ; original byte CC, padding
0x266bef: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf0 [0x266bf0, 0x266bf4] | file +0xca8 | ev_b7ba618ae2aa9e42f6dc5f460eacabc57ff16a7d0aa334b8901473386f810008
thunk_266bf0:
0x266bf0: JMP 0x009ac9a0
; END FUNCTION thunk_266bf0
0x266bf5: INT3 ; original byte CC, padding
0x266bf6: INT3 ; original byte CC, padding
0x266bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf8 [0x266bf8, 0x266bfc] | file +0xcb0 | ev_7b6dffa6d17e048eb0c5c66d7ff1892a62f7829978e4d399fec5e56368c85598
thunk_266bf8:
0x266bf8: JMP 0x009aca20
; END FUNCTION thunk_266bf8
0x266bfd: INT3 ; original byte CC, padding
0x266bfe: INT3 ; original byte CC, padding
0x266bff: INT3 ; original byte CC, padding

; FUNCTION thunk_266c00 [0x266c00, 0x266c04] | file +0xcb8 | ev_37e32afc32cbfcefa497814dc4c10dc93a73d1b39133f84aeeb295f99deb9227
thunk_266c00:
0x266c00: JMP 0x001be640
; END FUNCTION thunk_266c00
0x266c05: INT3 ; original byte CC, padding
0x266c06: INT3 ; original byte CC, padding
0x266c07: INT3 ; original byte CC, padding

; FUNCTION thunk_266c08 [0x266c08, 0x266c0c] | file +0xcc0 | ev_8dcbff7b878d9c7260555fdb740b8c9f57eb3ce3f0cd403b4e34d3dc8444893d
thunk_266c08:
0x266c08: JMP 0x009bed20
; END FUNCTION thunk_266c08
0x266c0d: INT3 ; original byte CC, padding
0x266c0e: INT3 ; original byte CC, padding
0x266c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c10 [0x266c10, 0x266c14] | file +0xcc8 | ev_5609616af12540e3f21ffdb1c4ee50798b97a80d28d9e70d0e40685b3d52ea7b
thunk_266c10:
0x266c10: JMP 0x009c6050
; END FUNCTION thunk_266c10
0x266c15: INT3 ; original byte CC, padding
0x266c16: INT3 ; original byte CC, padding
0x266c17: INT3 ; original byte CC, padding

; FUNCTION thunk_266c18 [0x266c18, 0x266c1c] | file +0xcd0 | ev_8fbdeb0835724f32a8b17a3c5d39a5e952abf35119874527c7bf6b3d2f410f4d
thunk_266c18:
0x266c18: JMP 0x009c60d0
; END FUNCTION thunk_266c18
0x266c1d: INT3 ; original byte CC, padding
0x266c1e: INT3 ; original byte CC, padding
0x266c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c20 [0x266c20, 0x266c24] | file +0xcd8 | ev_ace2b7677c241f86357c44b9f6ffb12c616d9a72f498b23035be4fb0262a687f
thunk_266c20:
0x266c20: JMP 0x009c6280
; END FUNCTION thunk_266c20
0x266c25: INT3 ; original byte CC, padding
0x266c26: INT3 ; original byte CC, padding
0x266c27: INT3 ; original byte CC, padding

; FUNCTION thunk_266c28 [0x266c28, 0x266c2c] | file +0xce0 | ev_7a3062ecd30b0df2a6122e8f59b5953527a185a8647d27426de7edb4c906b7d7
thunk_266c28:
0x266c28: JMP 0x009c6310
; END FUNCTION thunk_266c28
0x266c2d: INT3 ; original byte CC, padding
0x266c2e: INT3 ; original byte CC, padding
0x266c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c30 [0x266c30, 0x266c34] | file +0xce8 | ev_dfe29f719b7475feed102705faecbfb48a5fb5cabcf650e8b213eddc01c64181
thunk_266c30:
0x266c30: JMP 0x009c6490
; END FUNCTION thunk_266c30
0x266c35: INT3 ; original byte CC, padding
0x266c36: INT3 ; original byte CC, padding
0x266c37: INT3 ; original byte CC, padding

; FUNCTION thunk_266c38 [0x266c38, 0x266c3c] | file +0xcf0 | ev_f2fead07eb766b1364e16b243079bc9aa5d3876480b0d12b25b3c132c3754268
thunk_266c38:
0x266c38: JMP 0x009c65b0
; END FUNCTION thunk_266c38
0x266c3d: INT3 ; original byte CC, padding
0x266c3e: INT3 ; original byte CC, padding
0x266c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c40 [0x266c40, 0x266c44] | file +0xcf8 | ev_c68ed7ba26444d1752bf6058fc28ab01a6bf926027464b2ea5e375f261cacff4
thunk_266c40:
0x266c40: JMP 0x009c6890
; END FUNCTION thunk_266c40
0x266c45: INT3 ; original byte CC, padding
0x266c46: INT3 ; original byte CC, padding
0x266c47: INT3 ; original byte CC, padding

; FUNCTION thunk_266c48 [0x266c48, 0x266c4c] | file +0xd00 | ev_67de297adfeed209dfc647b55bf4d003699078a117d7be29f97231507d06648d
thunk_266c48:
0x266c48: JMP 0x009c9340
; END FUNCTION thunk_266c48
0x266c4d: INT3 ; original byte CC, padding
0x266c4e: INT3 ; original byte CC, padding
0x266c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c50 [0x266c50, 0x266c54] | file +0xd08 | ev_f5735fce676e82d52e4f585386bb91ed4c135c29aa338a4a56a193e57e3bc696
thunk_266c50:
0x266c50: JMP 0x009c9360
; END FUNCTION thunk_266c50
0x266c55: INT3 ; original byte CC, padding
0x266c56: INT3 ; original byte CC, padding
0x266c57: INT3 ; original byte CC, padding

; FUNCTION thunk_266c58 [0x266c58, 0x266c5c] | file +0xd10 | ev_e91b99d64f4c78087780aed0abccebaa4e78e410a865688b3acac1c9d9dbc662
thunk_266c58:
0x266c58: JMP 0x009c9370
; END FUNCTION thunk_266c58
0x266c5d: INT3 ; original byte CC, padding
0x266c5e: INT3 ; original byte CC, padding
0x266c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c60 [0x266c60, 0x266c64] | file +0xd18 | ev_b3f6589bf2526d456f9760f6654606024f8576bc26a4405284d36ac742be9973
thunk_266c60:
0x266c60: JMP 0x009c9380
; END FUNCTION thunk_266c60
0x266c65: INT3 ; original byte CC, padding
0x266c66: INT3 ; original byte CC, padding
0x266c67: INT3 ; original byte CC, padding

; FUNCTION thunk_266c68 [0x266c68, 0x266c6c] | file +0xd20 | ev_18322b16d894e20a403d727376dae134cc622455f406447df0dcce4b12631368
thunk_266c68:
0x266c68: JMP 0x009dadb0
; END FUNCTION thunk_266c68
0x266c6d: INT3 ; original byte CC, padding
0x266c6e: INT3 ; original byte CC, padding
0x266c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c70 [0x266c70, 0x266c74] | file +0xd28 | ev_02cfdafda2a13e9bce9c188e0d3d2ff158067964ff4148e08d6c71ef28462e5b
thunk_266c70:
0x266c70: JMP 0x009dafa0
; END FUNCTION thunk_266c70
0x266c75: INT3 ; original byte CC, padding
0x266c76: INT3 ; original byte CC, padding
0x266c77: INT3 ; original byte CC, padding

; FUNCTION thunk_266c78 [0x266c78, 0x266c7c] | file +0xd30 | ev_e8c329046ada8dfcbb218a69d95ad166cea9026c2e371cb78043976fdb141791
thunk_266c78:
0x266c78: JMP 0x009dc860
; END FUNCTION thunk_266c78
0x266c7d: INT3 ; original byte CC, padding
0x266c7e: INT3 ; original byte CC, padding
0x266c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c80 [0x266c80, 0x266c84] | file +0xd38 | ev_951c7632d5f7ac048641f115f7f022df0067f8be7557f92bc19817ba1f69dce3
thunk_266c80:
0x266c80: JMP 0x009dcc40
; END FUNCTION thunk_266c80
0x266c85: INT3 ; original byte CC, padding
0x266c86: INT3 ; original byte CC, padding
0x266c87: INT3 ; original byte CC, padding

; FUNCTION thunk_266c88 [0x266c88, 0x266c8c] | file +0xd40 | ev_cb36009f9bfc136ec5ce961b8bfce675e1359e0ba638916fd42ff816e5a29426
thunk_266c88:
0x266c88: JMP 0x009dce80
; END FUNCTION thunk_266c88
0x266c8d: INT3 ; original byte CC, padding
0x266c8e: INT3 ; original byte CC, padding
0x266c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c90 [0x266c90, 0x266c94] | file +0xd48 | ev_6cd39531681fde08c31a8a78d17c026d60656b4a04d4df9cf32e35b4ad3233b6
thunk_266c90:
0x266c90: JMP 0x009dd500
; END FUNCTION thunk_266c90
0x266c95: INT3 ; original byte CC, padding
0x266c96: INT3 ; original byte CC, padding
0x266c97: INT3 ; original byte CC, padding

; FUNCTION thunk_266c98 [0x266c98, 0x266c9c] | file +0xd50 | ev_082dedda124d393d2915851f9fde3e738185206a07e4537279f0f861e5e538ed
thunk_266c98:
0x266c98: JMP 0x00caacd0
; END FUNCTION thunk_266c98
0x266c9d: INT3 ; original byte CC, padding
0x266c9e: INT3 ; original byte CC, padding
0x266c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca0 [0x266ca0, 0x266ca4] | file +0xd58 | ev_9bc1d8d5795bb013c77f16ef99873037745952b9b9c7afd3662bb4d086d7ead5
thunk_266ca0:
0x266ca0: JMP 0x009dd7d0
; END FUNCTION thunk_266ca0
0x266ca5: INT3 ; original byte CC, padding
0x266ca6: INT3 ; original byte CC, padding
0x266ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca8 [0x266ca8, 0x266cac] | file +0xd60 | ev_17560178ac1bf83794f7f4280d1fb3fc2375e475a18a6fac6d799778c6f8ebbf
thunk_266ca8:
0x266ca8: JMP 0x009dd990
; END FUNCTION thunk_266ca8
0x266cad: INT3 ; original byte CC, padding
0x266cae: INT3 ; original byte CC, padding
0x266caf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb0 [0x266cb0, 0x266cb4] | file +0xd68 | ev_93b9cede683a5db69b3564125f37c3e108fee90298840a1378e784896a40b21a
thunk_266cb0:
0x266cb0: JMP 0x009ddba0
; END FUNCTION thunk_266cb0
0x266cb5: INT3 ; original byte CC, padding
0x266cb6: INT3 ; original byte CC, padding
0x266cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb8 [0x266cb8, 0x266cbc] | file +0xd70 | ev_17e04c234b75b5bb4b975f60d1dfe50a320d9680c9f216bf121bb91243acdb38
thunk_266cb8:
0x266cb8: JMP 0x009ddc00
; END FUNCTION thunk_266cb8
0x266cbd: INT3 ; original byte CC, padding
0x266cbe: INT3 ; original byte CC, padding
0x266cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc0 [0x266cc0, 0x266cc4] | file +0xd78 | ev_b6c802572264316e90ed3345f2a81557c2bd489791b15076650e3be79e08ff47
thunk_266cc0:
0x266cc0: JMP 0x009dde50
; END FUNCTION thunk_266cc0
0x266cc5: INT3 ; original byte CC, padding
0x266cc6: INT3 ; original byte CC, padding
0x266cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc8 [0x266cc8, 0x266ccc] | file +0xd80 | ev_f94c0066909ed11a39e16e7896cd502d8724b3a73c0764f2f50f547302dc33d5
thunk_266cc8:
0x266cc8: JMP 0x009ddeb0
; END FUNCTION thunk_266cc8
0x266ccd: INT3 ; original byte CC, padding
0x266cce: INT3 ; original byte CC, padding
0x266ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd0 [0x266cd0, 0x266cd4] | file +0xd88 | ev_348cb7baeed000a9d33e2e381076de9fb9b8615b007f637a8eb38169607b542e
thunk_266cd0:
0x266cd0: JMP 0x009ddff0
; END FUNCTION thunk_266cd0
0x266cd5: INT3 ; original byte CC, padding
0x266cd6: INT3 ; original byte CC, padding
0x266cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd8 [0x266cd8, 0x266cdc] | file +0xd90 | ev_fc58a66b8aa11327158592a2683a5409b088dbfa3e73c567d2114c597deb93bc
thunk_266cd8:
0x266cd8: JMP 0x009de070
; END FUNCTION thunk_266cd8
0x266cdd: INT3 ; original byte CC, padding
0x266cde: INT3 ; original byte CC, padding
0x266cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce0 [0x266ce0, 0x266ce4] | file +0xd98 | ev_5475722fc4118f733e9a73ddbd7446a54dc4ad626a95e9c9f0448cc18e9f996e
thunk_266ce0:
0x266ce0: JMP 0x009de0f0
; END FUNCTION thunk_266ce0
0x266ce5: INT3 ; original byte CC, padding
0x266ce6: INT3 ; original byte CC, padding
0x266ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce8 [0x266ce8, 0x266cec] | file +0xda0 | ev_fdafddb450a802d82260ceae9a715e28314e8881a70b3d59b8493179b1961500
thunk_266ce8:
0x266ce8: JMP 0x009e0b90
; END FUNCTION thunk_266ce8
0x266ced: INT3 ; original byte CC, padding
0x266cee: INT3 ; original byte CC, padding
0x266cef: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf0 [0x266cf0, 0x266cf4] | file +0xda8 | ev_8cefa82a89b7b4b45c99217e6cd0bee8439d24511d15edc5beb5541815716e5c
thunk_266cf0:
0x266cf0: JMP 0x009e0cd0
; END FUNCTION thunk_266cf0
0x266cf5: INT3 ; original byte CC, padding
0x266cf6: INT3 ; original byte CC, padding
0x266cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf8 [0x266cf8, 0x266cfc] | file +0xdb0 | ev_0fe31e9a802c16bff487f3ffa6fe768146a74631329f957dd9bc3dca74021aca
thunk_266cf8:
0x266cf8: JMP 0x009e0d70
; END FUNCTION thunk_266cf8
0x266cfd: INT3 ; original byte CC, padding
0x266cfe: INT3 ; original byte CC, padding
0x266cff: INT3 ; original byte CC, padding

; FUNCTION thunk_266d00 [0x266d00, 0x266d04] | file +0xdb8 | ev_e5cce5cafece25832e81d202bbaf98d746251944792d147620e609bdc88a079b
thunk_266d00:
0x266d00: JMP 0x009e0ef0
; END FUNCTION thunk_266d00
0x266d05: INT3 ; original byte CC, padding
0x266d06: INT3 ; original byte CC, padding
0x266d07: INT3 ; original byte CC, padding

; FUNCTION thunk_266d08 [0x266d08, 0x266d0c] | file +0xdc0 | ev_a5c6e76db2b06ad96ad752996fbb0d43af1311a603e951d09dc0718da26264e1
thunk_266d08:
0x266d08: JMP 0x009e1050
; END FUNCTION thunk_266d08
0x266d0d: INT3 ; original byte CC, padding
0x266d0e: INT3 ; original byte CC, padding
0x266d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d10 [0x266d10, 0x266d14] | file +0xdc8 | ev_2ff4d8779640ec27c7a42ba2bd832a1062c3067640217eabf3eafa58a6ac14c7
thunk_266d10:
0x266d10: JMP 0x009e1490
; END FUNCTION thunk_266d10
0x266d15: INT3 ; original byte CC, padding
0x266d16: INT3 ; original byte CC, padding
0x266d17: INT3 ; original byte CC, padding

; FUNCTION thunk_266d18 [0x266d18, 0x266d1c] | file +0xdd0 | ev_b7780a59bec1d8f90378ae9653e3982c89c7992f914096c62690d8fcc0b31a94
thunk_266d18:
0x266d18: JMP 0x00a065e0
; END FUNCTION thunk_266d18
0x266d1d: INT3 ; original byte CC, padding
0x266d1e: INT3 ; original byte CC, padding
0x266d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d20 [0x266d20, 0x266d24] | file +0xdd8 | ev_d10f566f8d9de96267472087c1f37a7479708a48744751f0d311c1c622dd3904
thunk_266d20:
0x266d20: JMP 0x00101340
; END FUNCTION thunk_266d20
0x266d25: INT3 ; original byte CC, padding
0x266d26: INT3 ; original byte CC, padding
0x266d27: INT3 ; original byte CC, padding

; FUNCTION thunk_266d28 [0x266d28, 0x266d2c] | file +0xde0 | ev_b14ed9d81a695319fa6e7c6ebdc5b570f764a5554a4fc0c40148baafde815686
thunk_266d28:
0x266d28: JMP 0x00a32f30
; END FUNCTION thunk_266d28
0x266d2d: INT3 ; original byte CC, padding
0x266d2e: INT3 ; original byte CC, padding
0x266d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d30 [0x266d30, 0x266d34] | file +0xde8 | ev_6ceedf1cd0b694a6020d0489577c66021b95c6e6acf4a93dbeabde86d9f6d391
thunk_266d30:
0x266d30: JMP 0x00a336c0
; END FUNCTION thunk_266d30
0x266d35: INT3 ; original byte CC, padding
0x266d36: INT3 ; original byte CC, padding
0x266d37: INT3 ; original byte CC, padding

; FUNCTION thunk_266d38 [0x266d38, 0x266d3c] | file +0xdf0 | ev_f404fb3364f869a944ee99aeb16bd33ff7e315fa9ba80c315a591d04d77c5cd9
thunk_266d38:
0x266d38: JMP 0x00a38c90
; END FUNCTION thunk_266d38
0x266d3d: INT3 ; original byte CC, padding
0x266d3e: INT3 ; original byte CC, padding
0x266d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d40 [0x266d40, 0x266d44] | file +0xdf8 | ev_78ce9ed99aaf60ae3f7ddffd51b979932236ff54bce8de0b8b30a669f28d85da
thunk_266d40:
0x266d40: JMP 0x00a6ab00
; END FUNCTION thunk_266d40
0x266d45: INT3 ; original byte CC, padding
0x266d46: INT3 ; original byte CC, padding
0x266d47: INT3 ; original byte CC, padding

; FUNCTION thunk_266d48 [0x266d48, 0x266d4c] | file +0xe00 | ev_b5a719e3051b394916925482ba873b496bcb34a1988407017a610457c6c23429
thunk_266d48:
0x266d48: JMP 0x00a6abb0
; END FUNCTION thunk_266d48
0x266d4d: INT3 ; original byte CC, padding
0x266d4e: INT3 ; original byte CC, padding
0x266d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d50 [0x266d50, 0x266d54] | file +0xe08 | ev_66a8e1394f6126ff166804a7b4117339bcc651d2b89fb684b756a8507994bdcf
thunk_266d50:
0x266d50: JMP 0x00a8ec10
; END FUNCTION thunk_266d50
0x266d55: INT3 ; original byte CC, padding
0x266d56: INT3 ; original byte CC, padding
0x266d57: INT3 ; original byte CC, padding

; FUNCTION thunk_266d58 [0x266d58, 0x266d5c] | file +0xe10 | ev_8d5fb3fe87100ad2ba04f2e7e973447e53c90e2e406a2a38099b02122b3e9869
thunk_266d58:
0x266d58: JMP 0x00a8ee00
; END FUNCTION thunk_266d58
0x266d5d: INT3 ; original byte CC, padding
0x266d5e: INT3 ; original byte CC, padding
0x266d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d60 [0x266d60, 0x266d64] | file +0xe18 | ev_5c2e94bdbf3948c0843d6ef9b29810c9a403493954312eb1180300ffe4515545
thunk_266d60:
0x266d60: JMP 0x00ab17b0
; END FUNCTION thunk_266d60
0x266d65: INT3 ; original byte CC, padding
0x266d66: INT3 ; original byte CC, padding
0x266d67: INT3 ; original byte CC, padding

; FUNCTION thunk_266d68 [0x266d68, 0x266d6c] | file +0xe20 | ev_6b4bef6b5f4bc828de6f53ae7485814885aa93b10e589f519b41bb23e3162800
thunk_266d68:
0x266d68: JMP 0x00ac07b0
; END FUNCTION thunk_266d68
0x266d6d: INT3 ; original byte CC, padding
0x266d6e: INT3 ; original byte CC, padding
0x266d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d70 [0x266d70, 0x266d74] | file +0xe28 | ev_bdce12fae65c55b0c7513e875b769c11d4280239f3d72373aaab9e9766afbaac
thunk_266d70:
0x266d70: JMP 0x00ac2af0
; END FUNCTION thunk_266d70
0x266d75: INT3 ; original byte CC, padding
0x266d76: INT3 ; original byte CC, padding
0x266d77: INT3 ; original byte CC, padding

; FUNCTION thunk_266d78 [0x266d78, 0x266d7c] | file +0xe30 | ev_2680b60f9cb23d12b0b0ecaabdc08d843be220023793fdb28f8eee6ca7229a5d
thunk_266d78:
0x266d78: JMP 0x0011a750
; END FUNCTION thunk_266d78
0x266d7d: INT3 ; original byte CC, padding
0x266d7e: INT3 ; original byte CC, padding
0x266d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d80 [0x266d80, 0x266d84] | file +0xe38 | ev_9af6b1d5b9f45778621c3ee062e58fca2c11a641863e209779c6d2054ed827fb
thunk_266d80:
0x266d80: JMP 0x00ae12a0
; END FUNCTION thunk_266d80
0x266d85: INT3 ; original byte CC, padding
0x266d86: INT3 ; original byte CC, padding
0x266d87: INT3 ; original byte CC, padding

; FUNCTION thunk_266d88 [0x266d88, 0x266d8c] | file +0xe40 | ev_8646eab0650b71883c11f7cdbab5c072bb7067fc4b651fe6d4ff533834d1400e
thunk_266d88:
0x266d88: JMP 0x00ae3400
; END FUNCTION thunk_266d88
0x266d8d: INT3 ; original byte CC, padding
0x266d8e: INT3 ; original byte CC, padding
0x266d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d90 [0x266d90, 0x266d94] | file +0xe48 | ev_ce1d8c6ab3f2ba46d018490e9359180b1341e43b3fbb4718438a184c713f0e55
thunk_266d90:
0x266d90: JMP 0x00ae3530
; END FUNCTION thunk_266d90
0x266d95: INT3 ; original byte CC, padding
0x266d96: INT3 ; original byte CC, padding
0x266d97: INT3 ; original byte CC, padding

; FUNCTION thunk_266d98 [0x266d98, 0x266d9c] | file +0xe50 | ev_bee1965f99007cbadf8a23a84f31148a5140aa1948ea011f5abff7a1602a8ffc
thunk_266d98:
0x266d98: JMP 0x00ae63c0
; END FUNCTION thunk_266d98
0x266d9d: INT3 ; original byte CC, padding
0x266d9e: INT3 ; original byte CC, padding
0x266d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266da0 [0x266da0, 0x266da4] | file +0xe58 | ev_021586ff9f269dedbb283491c1f5fef34dda25f2b408fa051a6134e2f95edd7d
thunk_266da0:
0x266da0: JMP 0x00b07ee0
; END FUNCTION thunk_266da0
0x266da5: INT3 ; original byte CC, padding
0x266da6: INT3 ; original byte CC, padding
0x266da7: INT3 ; original byte CC, padding

; FUNCTION thunk_266da8 [0x266da8, 0x266dac] | file +0xe60 | ev_661897bcc4d7235e95c9ece8b99683b3005da66501d8fb0d0dec17557ed248b7
thunk_266da8:
0x266da8: JMP 0x00b08190
; END FUNCTION thunk_266da8
0x266dad: INT3 ; original byte CC, padding
0x266dae: INT3 ; original byte CC, padding
0x266daf: INT3 ; original byte CC, padding

; FUNCTION thunk_266db0 [0x266db0, 0x266db4] | file +0xe68 | ev_a51657bb9adaf2b46acb636dab82aea2afbd24344b38ec9fc62f4a5cb75b4c3f
thunk_266db0:
0x266db0: JMP 0x00b08530
; END FUNCTION thunk_266db0
0x266db5: INT3 ; original byte CC, padding
0x266db6: INT3 ; original byte CC, padding
0x266db7: INT3 ; original byte CC, padding

; FUNCTION thunk_266db8 [0x266db8, 0x266dbc] | file +0xe70 | ev_7bd6608e24ea1d58427542d7fe6b513031f58af19140f4dc92741a8a3df9ee06
thunk_266db8:
0x266db8: JMP 0x00b08810
; END FUNCTION thunk_266db8
0x266dbd: INT3 ; original byte CC, padding
0x266dbe: INT3 ; original byte CC, padding
0x266dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc0 [0x266dc0, 0x266dc4] | file +0xe78 | ev_f09ac987114e244788a375bb4fcf7afd7ce4c964fa2b7bf4a6afafeb24830e03
thunk_266dc0:
0x266dc0: JMP 0x00b096a0
; END FUNCTION thunk_266dc0
0x266dc5: INT3 ; original byte CC, padding
0x266dc6: INT3 ; original byte CC, padding
0x266dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc8 [0x266dc8, 0x266dcc] | file +0xe80 | ev_dfc611f60173bd5832d71e5b7ec488439560cad77e88931e8d7c64545c725a45
thunk_266dc8:
0x266dc8: JMP 0x00b0b4f0
; END FUNCTION thunk_266dc8
0x266dcd: INT3 ; original byte CC, padding
0x266dce: INT3 ; original byte CC, padding
0x266dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd0 [0x266dd0, 0x266dd4] | file +0xe88 | ev_7ddaa2bd15e3b28548a4a9c293e73ca9bc9385206edec45703a1cbcbdfd80bbe
thunk_266dd0:
0x266dd0: JMP 0x001ef0f0
; END FUNCTION thunk_266dd0
0x266dd5: INT3 ; original byte CC, padding
0x266dd6: INT3 ; original byte CC, padding
0x266dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd8 [0x266dd8, 0x266ddc] | file +0xe90 | ev_0fd6893fc896b88e9e684bdcf1f2df886f46d9b79d06e9e8e6ac0024f32f3aed
thunk_266dd8:
0x266dd8: JMP 0x001f0060
; END FUNCTION thunk_266dd8
0x266ddd: INT3 ; original byte CC, padding
0x266dde: INT3 ; original byte CC, padding
0x266ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_266de0 [0x266de0, 0x266de4] | file +0xe98 | ev_f3e343791d1960e5d9ab7af96634393b0613d3a4f218256929e2f8033104ac7d
thunk_266de0:
0x266de0: JMP 0x0011b9b0
; END FUNCTION thunk_266de0
0x266de5: INT3 ; original byte CC, padding
0x266de6: INT3 ; original byte CC, padding
0x266de7: INT3 ; original byte CC, padding

; FUNCTION thunk_266de8 [0x266de8, 0x266dec] | file +0xea0 | ev_3256847e0571f12a26c9637636d3c4e54696270caa3cb68eeaae5a004b6a850f
thunk_266de8:
0x266de8: JMP 0x00b3b130
; END FUNCTION thunk_266de8
0x266ded: INT3 ; original byte CC, padding
0x266dee: INT3 ; original byte CC, padding
0x266def: INT3 ; original byte CC, padding

; FUNCTION thunk_266df0 [0x266df0, 0x266df4] | file +0xea8 | ev_a4d5a58087cc50f89a43a0c946224b55c585f59dde0dbe33701b96ad42036a63
thunk_266df0:
0x266df0: JMP 0x00b47a40
; END FUNCTION thunk_266df0
0x266df5: INT3 ; original byte CC, padding
0x266df6: INT3 ; original byte CC, padding
0x266df7: INT3 ; original byte CC, padding

; FUNCTION thunk_266df8 [0x266df8, 0x266dfc] | file +0xeb0 | ev_6f9f553619e79fa117711aa664214bf407cb896470edfaed2fa80b975c20998e
thunk_266df8:
0x266df8: JMP 0x00b503c0
; END FUNCTION thunk_266df8
0x266dfd: INT3 ; original byte CC, padding
0x266dfe: INT3 ; original byte CC, padding
0x266dff: INT3 ; original byte CC, padding

; FUNCTION thunk_266e00 [0x266e00, 0x266e04] | file +0xeb8 | ev_5bb72f86362afb6f491fa4944eac459ad974d898a733bc1701ce28ccee3366a3
thunk_266e00:
0x266e00: JMP 0x00b50f10
; END FUNCTION thunk_266e00
0x266e05: INT3 ; original byte CC, padding
0x266e06: INT3 ; original byte CC, padding
0x266e07: INT3 ; original byte CC, padding

; FUNCTION thunk_266e08 [0x266e08, 0x266e0c] | file +0xec0 | ev_4626fe3df4c069cb8aaac5384079b00f151bec62d68c9553e9ed7c8a4fd75c42
thunk_266e08:
0x266e08: JMP 0x00b50fb0
; END FUNCTION thunk_266e08
0x266e0d: INT3 ; original byte CC, padding
0x266e0e: INT3 ; original byte CC, padding
0x266e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e10 [0x266e10, 0x266e14] | file +0xec8 | ev_6d4603bdb31502b309b8835180f360ba961490d6273d111b6f01a175e50b17af
thunk_266e10:
0x266e10: JMP 0x00b510b0
; END FUNCTION thunk_266e10
0x266e15: INT3 ; original byte CC, padding
0x266e16: INT3 ; original byte CC, padding
0x266e17: INT3 ; original byte CC, padding

; FUNCTION thunk_266e18 [0x266e18, 0x266e1c] | file +0xed0 | ev_396af73daa982841b9f11dfa441c9e266f5a927b17b979985cd9ca8a0a5fdb68
thunk_266e18:
0x266e18: JMP 0x00b51190
; END FUNCTION thunk_266e18
0x266e1d: INT3 ; original byte CC, padding
0x266e1e: INT3 ; original byte CC, padding
0x266e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e20 [0x266e20, 0x266e24] | file +0xed8 | ev_fffc298efdf0b5e0e2e4378571521024ffa8e4aca9043008d1e61ce816203c66
thunk_266e20:
0x266e20: JMP 0x00b51290
; END FUNCTION thunk_266e20
0x266e25: INT3 ; original byte CC, padding
0x266e26: INT3 ; original byte CC, padding
0x266e27: INT3 ; original byte CC, padding

; FUNCTION thunk_266e28 [0x266e28, 0x266e2c] | file +0xee0 | ev_e8ef76577eaac3fab3c793b7168e9da12dc1aca576c7a71fa3f557e237c2e4e6
thunk_266e28:
0x266e28: JMP 0x00b512d0
; END FUNCTION thunk_266e28
0x266e2d: INT3 ; original byte CC, padding
0x266e2e: INT3 ; original byte CC, padding
0x266e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e30 [0x266e30, 0x266e34] | file +0xee8 | ev_4db31287f09e0ae97956058a96dfe8fd3e5528ddc6f25d486a7433aaa211b322
thunk_266e30:
0x266e30: JMP 0x00b51320
; END FUNCTION thunk_266e30
0x266e35: INT3 ; original byte CC, padding
0x266e36: INT3 ; original byte CC, padding
0x266e37: INT3 ; original byte CC, padding

; FUNCTION thunk_266e38 [0x266e38, 0x266e3c] | file +0xef0 | ev_8ecf5e88ea4bb913a7d602178eeaa9d978ee9a7b5cd012aa8894b369ad41550d
thunk_266e38:
0x266e38: JMP 0x00b568a0
; END FUNCTION thunk_266e38
0x266e3d: INT3 ; original byte CC, padding
0x266e3e: INT3 ; original byte CC, padding
0x266e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e40 [0x266e40, 0x266e44] | file +0xef8 | ev_8e75b68ffdcee668e3cc8060cc48f0eec1a2ba00367b0ea233f6c43f8765a777
thunk_266e40:
0x266e40: JMP 0x0009a0e0
; END FUNCTION thunk_266e40
0x266e45: INT3 ; original byte CC, padding
0x266e46: INT3 ; original byte CC, padding
0x266e47: INT3 ; original byte CC, padding

; FUNCTION thunk_266e48 [0x266e48, 0x266e4c] | file +0xf00 | ev_1449cb43daa60b62cab63d755b2a2ddd18efb47331cc52035ef5c3a04310475e
thunk_266e48:
0x266e48: JMP 0x00b6ae70
; END FUNCTION thunk_266e48
0x266e4d: INT3 ; original byte CC, padding
0x266e4e: INT3 ; original byte CC, padding
0x266e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e50 [0x266e50, 0x266e54] | file +0xf08 | ev_e5c757c666e1090a3ec377473f91b1bae5a6549c03db2270345898d87c0b067e
thunk_266e50:
0x266e50: JMP 0x00b6bb90
; END FUNCTION thunk_266e50
0x266e55: INT3 ; original byte CC, padding
0x266e56: INT3 ; original byte CC, padding
0x266e57: INT3 ; original byte CC, padding

; FUNCTION thunk_266e58 [0x266e58, 0x266e5c] | file +0xf10 | ev_8bf126f87d6604a0a94aed580fc13864f2b4286b1b4f03fb9394afeb53816a34
thunk_266e58:
0x266e58: JMP 0x00b6d980
; END FUNCTION thunk_266e58
0x266e5d: INT3 ; original byte CC, padding
0x266e5e: INT3 ; original byte CC, padding
0x266e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e60 [0x266e60, 0x266e64] | file +0xf18 | ev_7ca6cb21dc0b6f25698862493a2d6b95a19babe9efefa4bd242d6e79af31bb98
thunk_266e60:
0x266e60: JMP 0x00b6daa0
; END FUNCTION thunk_266e60
0x266e65: INT3 ; original byte CC, padding
0x266e66: INT3 ; original byte CC, padding
0x266e67: INT3 ; original byte CC, padding

; FUNCTION thunk_266e68 [0x266e68, 0x266e6c] | file +0xf20 | ev_d64bbe0b19de218b1913ecc94394fde4fbf612ee3092f588edf5fd97efaed577
thunk_266e68:
0x266e68: JMP 0x00b6e180
; END FUNCTION thunk_266e68
0x266e6d: INT3 ; original byte CC, padding
0x266e6e: INT3 ; original byte CC, padding
0x266e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e70 [0x266e70, 0x266e74] | file +0xf28 | ev_f2be95566a6f3f55ffa0867891aa84abb05e686b116e083938852c5ad30c9053
thunk_266e70:
0x266e70: JMP 0x00b71320
; END FUNCTION thunk_266e70
0x266e75: INT3 ; original byte CC, padding
0x266e76: INT3 ; original byte CC, padding
0x266e77: INT3 ; original byte CC, padding

; FUNCTION thunk_266e78 [0x266e78, 0x266e7c] | file +0xf30 | ev_ea30d5c8cc955f26bc1887e696b4cdd9d0f470d328a1f7fcff151a10e904bf5b
thunk_266e78:
0x266e78: JMP 0x00b71370
; END FUNCTION thunk_266e78
0x266e7d: INT3 ; original byte CC, padding
0x266e7e: INT3 ; original byte CC, padding
0x266e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e80 [0x266e80, 0x266e84] | file +0xf38 | ev_c63e3871926c8e72b579d264e85f38382d783da0d0b04d4be00b01031822fb25
thunk_266e80:
0x266e80: JMP 0x00b713c0
; END FUNCTION thunk_266e80
0x266e85: INT3 ; original byte CC, padding
0x266e86: INT3 ; original byte CC, padding
0x266e87: INT3 ; original byte CC, padding

; FUNCTION thunk_266e88 [0x266e88, 0x266e8c] | file +0xf40 | ev_197d591bf203fc30e38d796f069d211a923ba60199a8f018b65658b3f5f32eb8
thunk_266e88:
0x266e88: JMP 0x00b71410
; END FUNCTION thunk_266e88
0x266e8d: INT3 ; original byte CC, padding
0x266e8e: INT3 ; original byte CC, padding
0x266e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e90 [0x266e90, 0x266e94] | file +0xf48 | ev_06c505a8945df64cf395d995cbc9ef4d39ffbb334ac8940eaf15b821d76a2e1f
thunk_266e90:
0x266e90: JMP 0x00b71960
; END FUNCTION thunk_266e90
0x266e95: INT3 ; original byte CC, padding
0x266e96: INT3 ; original byte CC, padding
0x266e97: INT3 ; original byte CC, padding

; FUNCTION thunk_266e98 [0x266e98, 0x266e9c] | file +0xf50 | ev_92cf65c6497d81c189072201bc92b6d001023852b15682c6e7045a41c5b4996f
thunk_266e98:
0x266e98: JMP 0x00b719d0
; END FUNCTION thunk_266e98
0x266e9d: INT3 ; original byte CC, padding
0x266e9e: INT3 ; original byte CC, padding
0x266e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea0 [0x266ea0, 0x266ea4] | file +0xf58 | ev_645a6b9f18cf77202c1f3379a167a483992f1abe64ade57cf4679057b81f8132
thunk_266ea0:
0x266ea0: JMP 0x00b71a40
; END FUNCTION thunk_266ea0
0x266ea5: INT3 ; original byte CC, padding
0x266ea6: INT3 ; original byte CC, padding
0x266ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea8 [0x266ea8, 0x266eac] | file +0xf60 | ev_92f8a51544605bc7f4dfb2d3f45f27341d959314143b088056208c2ce0daf354
thunk_266ea8:
0x266ea8: JMP 0x00b71ab0
; END FUNCTION thunk_266ea8
0x266ead: INT3 ; original byte CC, padding
0x266eae: INT3 ; original byte CC, padding
0x266eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb0 [0x266eb0, 0x266eb4] | file +0xf68 | ev_86e42877162f49237f5ee3cc1fa9b5e7317d73fd40d6536966932f7792fb38d9
thunk_266eb0:
0x266eb0: JMP 0x00b72620
; END FUNCTION thunk_266eb0
0x266eb5: INT3 ; original byte CC, padding
0x266eb6: INT3 ; original byte CC, padding
0x266eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb8 [0x266eb8, 0x266ebc] | file +0xf70 | ev_001011f1bff1e10ce4ca0cb454363095736c0cef7656de7f95cc7986ab85c6f4
thunk_266eb8:
0x266eb8: JMP 0x00b72860
; END FUNCTION thunk_266eb8
0x266ebd: INT3 ; original byte CC, padding
0x266ebe: INT3 ; original byte CC, padding
0x266ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec0 [0x266ec0, 0x266ec4] | file +0xf78 | ev_a62bc6806ab674d0ae71f374d1e8ebd1b76781dbf590ebc9087c31322e2462e2
thunk_266ec0:
0x266ec0: JMP 0x00b791d0
; END FUNCTION thunk_266ec0
0x266ec5: INT3 ; original byte CC, padding
0x266ec6: INT3 ; original byte CC, padding
0x266ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec8 [0x266ec8, 0x266ecc] | file +0xf80 | ev_b52289221c273125b1dbccaf11fa3a6fd7e6246284d8522934c98ec91d8d206e
thunk_266ec8:
0x266ec8: JMP 0x00b79290
; END FUNCTION thunk_266ec8
0x266ecd: INT3 ; original byte CC, padding
0x266ece: INT3 ; original byte CC, padding
0x266ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed0 [0x266ed0, 0x266ed4] | file +0xf88 | ev_4047cbc663795c1289163dbe21ac08af15171a76058b17f7e22314c363bc8a5c
thunk_266ed0:
0x266ed0: JMP 0x00b793f0
; END FUNCTION thunk_266ed0
0x266ed5: INT3 ; original byte CC, padding
0x266ed6: INT3 ; original byte CC, padding
0x266ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed8 [0x266ed8, 0x266edc] | file +0xf90 | ev_d40229b3fb879733cf4bb36ba96438639d574a7aaaf01b902462653bec434bc0
thunk_266ed8:
0x266ed8: JMP 0x00b79420
; END FUNCTION thunk_266ed8
0x266edd: INT3 ; original byte CC, padding
0x266ede: INT3 ; original byte CC, padding
0x266edf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee0 [0x266ee0, 0x266ee4] | file +0xf98 | ev_9c460fc45aabe04141735909271220fd15d8255d47b0abc66e0f74511b093105
thunk_266ee0:
0x266ee0: JMP 0x00b79460
; END FUNCTION thunk_266ee0
0x266ee5: INT3 ; original byte CC, padding
0x266ee6: INT3 ; original byte CC, padding
0x266ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee8 [0x266ee8, 0x266eec] | file +0xfa0 | ev_140eeb12e1434a7dc0c137ae75e06af03c16e376698cbc46dfa3d10d190ea107
thunk_266ee8:
0x266ee8: JMP 0x00b79480
; END FUNCTION thunk_266ee8
0x266eed: INT3 ; original byte CC, padding
0x266eee: INT3 ; original byte CC, padding
0x266eef: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef0 [0x266ef0, 0x266ef4] | file +0xfa8 | ev_43ad813f5b2b8f40c57dc086f2c412e940abf4ceca224978018e13b0f33a7820
thunk_266ef0:
0x266ef0: JMP 0x00b79490
; END FUNCTION thunk_266ef0
0x266ef5: INT3 ; original byte CC, padding
0x266ef6: INT3 ; original byte CC, padding
0x266ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef8 [0x266ef8, 0x266efc] | file +0xfb0 | ev_bfec69b84024565b47c924a86acddbcc1709c8816cf063cd4839f05a0efb3a66
thunk_266ef8:
0x266ef8: JMP 0x00b794b0
; END FUNCTION thunk_266ef8
0x266efd: INT3 ; original byte CC, padding
0x266efe: INT3 ; original byte CC, padding
0x266eff: INT3 ; original byte CC, padding

; FUNCTION thunk_266f00 [0x266f00, 0x266f04] | file +0xfb8 | ev_c1e937b17f609327e5a32dc651db69965da91c36afed6b6cab4eeb2ddbc66ade
thunk_266f00:
0x266f00: JMP 0x00b795f0
; END FUNCTION thunk_266f00
0x266f05: INT3 ; original byte CC, padding
0x266f06: INT3 ; original byte CC, padding
0x266f07: INT3 ; original byte CC, padding

; FUNCTION thunk_266f08 [0x266f08, 0x266f0c] | file +0xfc0 | ev_54cd41ab36c1d893c67c9e91dd3bac8054c2a093aa3ff842a2b4ac493f1af467
thunk_266f08:
0x266f08: JMP 0x00b79620
; END FUNCTION thunk_266f08
0x266f0d: INT3 ; original byte CC, padding
0x266f0e: INT3 ; original byte CC, padding
0x266f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f10 [0x266f10, 0x266f14] | file +0xfc8 | ev_5f150108a282e0acbbf087f0447711d5f934b501ef033bcb4651c0a0bff06097
thunk_266f10:
0x266f10: JMP 0x00b79830
; END FUNCTION thunk_266f10
0x266f15: INT3 ; original byte CC, padding
0x266f16: INT3 ; original byte CC, padding
0x266f17: INT3 ; original byte CC, padding

; FUNCTION thunk_266f18 [0x266f18, 0x266f1c] | file +0xfd0 | ev_2da7c7533a24f08c54a5ec5ef15fbab9a37ad41832c00dd6f045c392f203f1ab
thunk_266f18:
0x266f18: JMP 0x00b80e90
; END FUNCTION thunk_266f18
0x266f1d: INT3 ; original byte CC, padding
0x266f1e: INT3 ; original byte CC, padding
0x266f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f20 [0x266f20, 0x266f24] | file +0xfd8 | ev_05007cf428f229f9acad957f05bfd0d915fc31a6bd8f53b6d71023441c636a5b
thunk_266f20:
0x266f20: JMP 0x00b80f20
; END FUNCTION thunk_266f20
0x266f25: INT3 ; original byte CC, padding
0x266f26: INT3 ; original byte CC, padding
0x266f27: INT3 ; original byte CC, padding

; FUNCTION thunk_266f28 [0x266f28, 0x266f2c] | file +0xfe0 | ev_4af2057d7b385aba4d6285ec88eaf49753f05817a916e45e8dad4635faa00a15
thunk_266f28:
0x266f28: JMP 0x00b99520
; END FUNCTION thunk_266f28
0x266f2d: INT3 ; original byte CC, padding
0x266f2e: INT3 ; original byte CC, padding
0x266f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f30 [0x266f30, 0x266f34] | file +0xfe8 | ev_7031656535bffe683040d3e65d44680a84556f146e6c8250261208dfd70560bd
thunk_266f30:
0x266f30: JMP 0x00b99600
; END FUNCTION thunk_266f30
0x266f35: INT3 ; original byte CC, padding
0x266f36: INT3 ; original byte CC, padding
0x266f37: INT3 ; original byte CC, padding

; FUNCTION thunk_266f38 [0x266f38, 0x266f3c] | file +0xff0 | ev_1c665d019d7d1f2e53f07e261e031cb899f97da44155def954621c2a02570d06
thunk_266f38:
0x266f38: JMP 0x00b9ce30
; END FUNCTION thunk_266f38
0x266f3d: INT3 ; original byte CC, padding
0x266f3e: INT3 ; original byte CC, padding
0x266f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f40 [0x266f40, 0x266f44] | file +0xff8 | ev_712648e7bb521b61edaa5cabe0db3056f43183e8708033b54aa034674b67ec39
thunk_266f40:
0x266f40: JMP 0x00bf5c40
; END FUNCTION thunk_266f40
0x266f45: INT3 ; original byte CC, padding
0x266f46: INT3 ; original byte CC, padding
0x266f47: INT3 ; original byte CC, padding


; REA RECOVERED BODY AND ANALYSIS-CARRIER CONTEXT
; Every following boundary is Ghidra function-body data; adjacent funcs are not automatically target callees.

; FUNCTION handler_646_body CONTEXT / separate function | ev_90404a2d8c14d83869dc6ffc7739053f76cef6b4f44b6707a45f2a4ba2cb893a
; Ghidra body: 0xabe1c0..0xabe253
handler_646_body:
0xabe1c0: PUSH RBP
0xabe1c1: MOV RBP, RSP
0xabe1c4: PUSH R15
0xabe1c6: PUSH R14
0xabe1c8: PUSH RBX
0xabe1c9: SUB RSP, 0x408
0xabe1d0: LEA R15, [0x391c310]
0xabe1d7: MOV RBX, RSI
0xabe1da: MOV RAX, qword ptr [R15]
0xabe1dd: MOV qword ptr [RBP + -0x20], RAX
0xabe1e1: MOV RDI, qword ptr [RDI + 0x140]
0xabe1e8: CALL 0x00608f90
0xabe1ed: TEST EAX, EAX
0xabe1ef: JZ 0x00abe231
0xabe1f1: LEA R14, [RBP + -0x418]
0xabe1f8: MOV ESI, 0x3f8
0xabe1fd: MOV RDI, R14
0xabe200: CALL 0x00258ff0
0xabe205: MOV RBX, qword ptr [RBX]
0xabe208: MOV RDI, qword ptr GS:[0x0]
0xabe211: LEA RSI, [0x134f297]
0xabe218: XOR EDX, EDX
0xabe21a: CALL 0x00c1a3e0
0xabe21f: MOV EDX, 0x3f8
0xabe224: MOV RDI, R14
0xabe227: MOV RSI, RBX
0xabe22a: CALL 0x002591d0
0xabe22f: JMP 0x00abe236
0xabe231: MOV EAX, 0x1
0xabe236: MOV RCX, qword ptr [R15]
0xabe239: CMP RCX, qword ptr [RBP + -0x20]
0xabe23d: JNZ 0x00abe24d
0xabe23f: ADD RSP, 0x408
0xabe246: POP RBX
0xabe247: POP R14
0xabe249: POP R15
0xabe24b: POP RBP
0xabe24c: RET
0xabe24d: CALL 0x006fd6b0
0xabe252: UD2
; END FUNCTION handler_646_body

; FUNCTION sub_abe260 CONTEXT / separate function | ev_4110655df9682c517e32e34ee79e212cd239c54b429b09ede610881342578c97
; Ghidra body: 0xabe260..0xabe7a8
sub_abe260:
0xabe260: PUSH RBP
0xabe261: MOV RBP, RSP
0xabe264: PUSH R15
0xabe266: PUSH R14
0xabe268: PUSH R13
0xabe26a: PUSH R12
0xabe26c: PUSH RBX
0xabe26d: SUB RSP, 0x1d8
0xabe274: LEA RAX, [0x391c310]
0xabe27b: MOV qword ptr [RBP + -0x1f8], RDI
0xabe282: LEA RBX, [RBP + -0x1a8]
0xabe289: MOV R12, RSI
0xabe28c: MOV ESI, 0x60
0xabe291: MOV R13, RCX
0xabe294: MOV R14D, EDX
0xabe297: MOV RDI, RBX
0xabe29a: MOV RAX, qword ptr [RAX]
0xabe29d: MOV qword ptr [RBP + -0x30], RAX
0xabe2a1: CALL 0x00258ff0
0xabe2a6: MOV RDI, qword ptr [0x036d15e0]
0xabe2ad: MOV EDX, 0x2
0xabe2b2: XOR ESI, ESI
0xabe2b4: CALL 0x0043b880
0xabe2b9: MOV RDI, qword ptr GS:[0x0]
0xabe2c2: LEA RSI, [0x135a084]
0xabe2c9: XOR EDX, EDX
0xabe2cb: MOV R15, RAX
0xabe2ce: CALL 0x00c1a3e0
0xabe2d3: MOV EDX, 0x400
0xabe2d8: MOV RDI, R12
0xabe2db: MOV RSI, R15
0xabe2de: XOR ECX, ECX
0xabe2e0: CALL 0x00259900
0xabe2e5: TEST EAX, EAX
0xabe2e7: JZ 0x00abe2f4
0xabe2e9: MOV R12D, EAX
0xabe2ec: MOV RSI, R15
0xabe2ef: JMP 0x00abe3e4
0xabe2f4: MOV qword ptr [RBP + -0x1c8], R13
0xabe2fb: SUB RSP, 0x8
0xabe2ff: MOV R13, R15
0xabe302: MOV R8, R15
0xabe305: MOV R15, qword ptr [RBP + -0x1f8]
0xabe30c: LEA R12, [RBP + -0x118]
0xabe313: MOV EDX, 0x144
0xabe318: XOR ESI, ESI
0xabe31a: MOV ECX, 0x1
0xabe31f: MOV R9D, 0xffffff9c
0xabe325: MOV RDI, R12
0xabe328: PUSH R15
0xabe32a: PUSH 0x0
0xabe32c: PUSH 0x0
0xabe32e: CALL 0x005fa6e0
0xabe333: ADD RSP, 0x20
0xabe337: MOV RDI, R12
0xabe33a: CALL 0x005f8c20
0xabe33f: TEST EAX, EAX
0xabe341: JZ 0x00abe34b
0xabe343: MOV R12D, EAX
0xabe346: JMP 0x00abe3e1
0xabe34b: MOV R12, qword ptr [RBP + -0xb8]
0xabe352: LEA RDI, [RBP + -0x118]
0xabe359: MOV ESI, 0xc
0xabe35e: CALL 0x005fa780
0xabe363: MOV RDX, R12
0xabe366: MOV R12D, 0x16
0xabe36c: CMP dword ptr [RDX + 0x1d4], 0x1
0xabe373: JNZ 0x00abe3d9
0xabe375: MOV RAX, qword ptr [R15 + 0x140]
0xabe37c: LEA RCX, [0x1ada7f8]
0xabe383: LEA RSI, [RBP + -0x148]
0xabe38a: MOV qword ptr [RBP + -0x1d8], RDX
0xabe391: MOV qword ptr [RBP + -0x148], RCX
0xabe398: MOV qword ptr [RBP + -0x140], RDX
0xabe39f: MOV dword ptr [RBP + -0x138], 0x1
0xabe3a9: MOV qword ptr [RBP + -0x130], RAX
0xabe3b0: MOV qword ptr [RBP + -0x128], R15
0xabe3b7: MOV qword ptr [RBP + -0x120], 0x0
0xabe3c2: MOV RDI, qword ptr [RDX + 0x8]
0xabe3c6: CALL 0x0058bb00
0xabe3cb: MOV RDX, qword ptr [RBP + -0x1d8]
0xabe3d2: MOV R12D, EAX
0xabe3d5: TEST EAX, EAX
0xabe3d7: JZ 0x00abe41b
0xabe3d9: MOV RDI, RDX
0xabe3dc: CALL 0x0054a440
0xabe3e1: MOV RSI, R13
0xabe3e4: MOV RDI, qword ptr [0x036d15e0]
0xabe3eb: XOR EDX, EDX
0xabe3ed: CALL 0x0043c0c0
0xabe3f2: LEA RAX, [0x391c310]
0xabe3f9: MOV RAX, qword ptr [RAX]
0xabe3fc: CMP RAX, qword ptr [RBP + -0x30]
0xabe400: JNZ 0x00abe7a2
0xabe406: MOV EAX, R12D
0xabe409: ADD RSP, 0x1d8
0xabe410: POP RBX
0xabe411: POP R12
0xabe413: POP R13
0xabe415: POP R14
0xabe417: POP R15
0xabe419: POP RBP
0xabe41a: RET
0xabe41b: MOV R9, qword ptr [R15 + 0x140]
0xabe422: MOV RSI, RDX
0xabe425: MOV EDI, 0x7
0xabe42a: MOV ECX, 0x1
0xabe42f: XOR EDX, EDX
0xabe431: XOR R8D, R8D
0xabe434: CALL 0x0045d9c0
0xabe439: MOV qword ptr [RBP + -0x1b0], RAX
0xabe440: TEST RAX, RAX
0xabe443: JZ 0x00abe486
0xabe445: LEA RDI, [RAX + 0x18]
0xabe449: MOV R12, RAX
0xabe44c: XOR ESI, ESI
0xabe44e: XOR EDX, EDX
0xabe450: CALL 0x007d46a0
0xabe455: MOV RDI, R12
0xabe458: CALL 0x00631850
0xabe45d: TEST EAX, EAX
0xabe45f: JZ 0x00abe494
0xabe461: MOV EDX, EAX
0xabe463: LEA RDI, [0x132d3cb]
0xabe46a: LEA RSI, [0x1380bd0]
0xabe471: XOR EAX, EAX
0xabe473: CALL 0x0025d410
0xabe478: MOV R12D, 0x8
0xabe47e: MOV R14, R15
0xabe481: JMP 0x00abe6e4
0xabe486: MOV R12D, 0xc
0xabe48c: MOV R14, R15
0xabe48f: JMP 0x00abe6e4
0xabe494: MOV RDI, R12
0xabe497: CALL 0x006322a0
0xabe49c: MOVZX EDX, word ptr [RAX + 0x10]
0xabe4a0: LEA ECX, [RDX + -0xfe00]
0xabe4a6: CMP ECX, 0x10
0xabe4a9: JA 0x00abe4b5
0xabe4ab: MOV ESI, 0x10003
0xabe4b0: BT ESI, ECX
0xabe4b3: JC 0x00abe4be
0xabe4b5: CMP EDX, 0x2
0xabe4b8: JNZ 0x00abe6ba
0xabe4be: MOVZX ECX, word ptr [RAX + 0x38]
0xabe4c2: TEST RCX, RCX
0xabe4c5: JZ 0x00abe6a3
0xabe4cb: MOV RDX, RAX
0xabe4ce: IMUL RSI, RCX, 0x38
0xabe4d2: XOR EDI, EDI
0xabe4d4: ADD RDX, 0x40
0xabe4d8: CMP dword ptr [RAX + RDI*0x1 + 0x40], 0x61000001
0xabe4e0: JZ 0x00abe4f0
0xabe4e2: ADD RDI, 0x38
0xabe4e6: CMP RSI, RDI
0xabe4e9: JNZ 0x00abe4d8
0xabe4eb: JMP 0x00abe6a3
0xabe4f0: MOV R8, qword ptr [RAX + RDI*0x1 + 0x60]
0xabe4f5: TEST R8, R8
0xabe4f8: JZ 0x00abe6a3
0xabe4fe: MOV RAX, qword ptr [RAX + RDI*0x1 + 0x50]
0xabe503: XOR ESI, ESI
0xabe505: JMP 0x00abe517
0xabe507: INC RSI
0xabe50a: ADD RDX, 0x38
0xabe50e: CMP RCX, RSI
0xabe511: JZ 0x00abe6a3
0xabe517: MOV EDI, dword ptr [RDX]
0xabe519: CMP EDI, 0x61000010
0xabe51f: JZ 0x00abe526
0xabe521: CMP EDI, 0x1
0xabe524: JNZ 0x00abe507
0xabe526: MOV R12, RAX
0xabe529: SUB R12, qword ptr [RDX + 0x10]
0xabe52d: JC 0x00abe507
0xabe52f: MOV RDI, qword ptr [RDX + 0x28]
0xabe533: SUB RDI, R8
0xabe536: JC 0x00abe507
0xabe538: CMP R12, RDI
0xabe53b: JA 0x00abe507
0xabe53d: CMP R8, 0x60
0xabe541: MOV EAX, 0x60
0xabe546: MOV RCX, R12
0xabe549: MOV RDX, R12
0xabe54c: MOV qword ptr [RBP + -0x1e0], RSI
0xabe553: CMOVC RAX, R8
0xabe557: AND RCX, -0x4000
0xabe55e: AND RDX, -0x4000
0xabe565: NEG RCX
0xabe568: MOV qword ptr [RBP + -0x1b8], RAX
0xabe56f: MOV qword ptr [RBP + -0x1c0], RDX
0xabe576: MOV qword ptr [RBP + -0x1d0], RCX
0xabe57d: MOV RDI, qword ptr [RBP + -0x1b0]
0xabe584: MOV RDX, qword ptr [RBP + -0x1c0]
0xabe58b: CALL 0x00630b70
0xabe590: MOV RDI, qword ptr [RBP + -0x1b0]
0xabe597: MOV RSI, RAX
0xabe59a: CALL 0x0053a3d0
0xabe59f: TEST RAX, RAX
0xabe5a2: JZ 0x00abe751
0xabe5a8: MOV RCX, qword ptr [RBP + -0x1c0]
0xabe5af: MOV EDI, dword ptr [0x03b49298]
0xabe5b5: MOV RSI, -0x800000000000
0xabe5bf: MOV qword ptr [RBP + -0x1e8], RAX
0xabe5c6: ADD RCX, 0x4000
0xabe5cd: MOV RDX, RCX
0xabe5d0: MOV qword ptr [RBP + -0x1c0], RCX
0xabe5d7: MOV ECX, dword ptr [RBP + -0x1b8]
0xabe5dd: SUB RDX, R12
0xabe5e0: CMP RDX, RCX
0xabe5e3: CMOVGE RDX, RCX
0xabe5e7: MOV ECX, dword ptr [0x03b49294]
0xabe5ed: SHL RDI, 0x1e
0xabe5f1: MOVSXD RDX, EDX
0xabe5f4: MOV qword ptr [RBP + -0x1f0], RDX
0xabe5fb: SHL RCX, 0x27
0xabe5ff: OR RDI, RCX
0xabe602: MOV RCX, qword ptr [RBP + -0x1d0]
0xabe609: OR RDI, RSI
0xabe60c: ADD RDI, qword ptr [RAX + 0x30]
0xabe610: MOV RSI, RBX
0xabe613: ADD RCX, R12
0xabe616: ADD RDI, RCX
0xabe619: CALL 0x00259be0
0xabe61e: MOV RDI, qword ptr [RBP + -0x1e8]
0xabe625: CALL 0x0053a410
0xabe62a: ADD qword ptr [RBP + -0x1d0], -0x4000
0xabe635: MOV RCX, qword ptr [RBP + -0x1f0]
0xabe63c: MOV RAX, qword ptr [RBP + -0x1b8]
0xabe643: MOV RSI, qword ptr [RBP + -0x1e0]
0xabe64a: SUB EAX, ECX
0xabe64c: ADD RBX, RCX
0xabe64f: ADD R12, RCX
0xabe652: MOV qword ptr [RBP + -0x1b8], RAX
0xabe659: TEST EAX, EAX
0xabe65b: JG 0x00abe57d
0xabe661: MOV EDX, dword ptr [RBP + -0x1a0]
0xabe667: MOV RCX, qword ptr [RBP + -0x1a8]
0xabe66e: CMP EDX, 0x4942524f
0xabe674: SETNZ AL
0xabe677: CMP RCX, 0x14
0xabe67b: SETC SIL
0xabe67f: OR SIL, AL
0xabe682: CMP SIL, 0x1
0xabe686: JNZ 0x00abe75c
0xabe68c: LEA RDI, [0x1287656]
0xabe693: LEA RSI, [0x1380bd0]
0xabe69a: XOR EAX, EAX
0xabe69c: CALL 0x0025d410
0xabe6a1: JMP 0x00abe6cf
0xabe6a3: LEA RDI, [0x134cc6a]
0xabe6aa: LEA RSI, [0x1380bd0]
0xabe6b1: XOR EAX, EAX
0xabe6b3: CALL 0x0025d410
0xabe6b8: JMP 0x00abe6cf
0xabe6ba: LEA RDI, [0x1376c4c]
0xabe6c1: LEA RSI, [0x1380bd0]
0xabe6c8: XOR EAX, EAX
0xabe6ca: CALL 0x0025d410
0xabe6cf: MOV R12D, 0x8
0xabe6d5: MOV RDI, qword ptr [RBP + -0x1b0]
0xabe6dc: MOV R14, R15
0xabe6df: CALL 0x006321f0
0xabe6e4: MOV RAX, qword ptr [R14 + 0x140]
0xabe6eb: LEA RCX, [0x1ada8f8]
0xabe6f2: MOV R15, qword ptr [RBP + -0x1d8]
0xabe6f9: LEA RSI, [RBP + -0x148]
0xabe700: MOV qword ptr [RBP + -0x148], RCX
0xabe707: MOV qword ptr [RBP + -0x140], R15
0xabe70e: MOV dword ptr [RBP + -0x138], 0x1
0xabe718: MOV qword ptr [RBP + -0x130], RAX
0xabe71f: MOV qword ptr [RBP + -0x128], R14
0xabe726: MOV RDI, qword ptr [R15 + 0x8]
0xabe72a: CALL 0x0058bce0
0xabe72f: MOV RDI, R15
0xabe732: CALL 0x0054a440
0xabe737: MOV RDI, qword ptr [RBP + -0x1b0]
0xabe73e: TEST RDI, RDI
0xabe741: JZ 0x00abe3e1
0xabe747: CALL 0x00461ba0
0xabe74c: JMP 0x00abe3e1
0xabe751: MOV R12D, 0x5
0xabe757: JMP 0x00abe6d5
0xabe75c: CMP R14D, 0x4
0xabe760: JNZ 0x00abe76a
0xabe762: MOV EAX, dword ptr [RBP + -0x198]
0xabe768: JMP 0x00abe779
0xabe76a: CMP dword ptr [RBP + -0x19c], 0x4
0xabe771: JC 0x00abe78a
0xabe773: MOV EAX, dword ptr [RBP + -0x194]
0xabe779: MOV RCX, qword ptr [RBP + -0x1c8]
0xabe780: XOR R12D, R12D
0xabe783: MOV dword ptr [RCX], EAX
0xabe785: JMP 0x00abe6d5
0xabe78a: MOV RAX, qword ptr [RBP + -0x1c8]
0xabe791: MOV R12D, 0x16
0xabe797: MOV dword ptr [RAX], 0x0
0xabe79d: JMP 0x00abe6d5
0xabe7a2: CALL 0x006fd6b0
0xabe7a7: UD2
; END FUNCTION sub_abe260

; FUNCTION sys_647 TARGET | ev_ace04d2de80b412de6f87925f7f80febbe9335a916a4a7b5240605a1ad898cb5
; Ghidra body: 0xabe7b0..0xabe828
sys_647:
0xabe7b0: PUSH RBP
0xabe7b1: MOV RBP, RSP
0xabe7b4: PUSH R15
0xabe7b6: PUSH R14
0xabe7b8: PUSH RBX
0xabe7b9: SUB RSP, 0x18
0xabe7bd: LEA R15, [0x391c310]
0xabe7c4: MOV RBX, RDI
0xabe7c7: MOV R14, RSI
0xabe7ca: MOV RAX, qword ptr [R15]
0xabe7cd: MOV qword ptr [RBP + -0x20], RAX
0xabe7d1: MOV RDI, qword ptr [RDI + 0x140]
0xabe7d8: CALL 0x00608f90
0xabe7dd: TEST EAX, EAX
0xabe7df: JZ 0x00abe809
0xabe7e1: MOV dword ptr [RBP + -0x24], 0x0
0xabe7e8: LEA RCX, [RBP + -0x24]
0xabe7ec: MOV RDI, RBX
0xabe7ef: MOV EDX, 0x4
0xabe7f4: MOV RSI, qword ptr [R14]
0xabe7f7: CALL 0x00abe260
0xabe7fc: MOVSXD RCX, dword ptr [RBP + -0x24]
0xabe800: MOV qword ptr [RBX + 0x408], RCX
0xabe807: JMP 0x00abe80e
0xabe809: MOV EAX, 0x1
0xabe80e: MOV RCX, qword ptr [R15]
0xabe811: CMP RCX, qword ptr [RBP + -0x20]
0xabe815: JNZ 0x00abe822
0xabe817: ADD RSP, 0x18
0xabe81b: POP RBX
0xabe81c: POP R14
0xabe81e: POP R15
0xabe820: POP RBP
0xabe821: RET
0xabe822: CALL 0x006fd6b0
0xabe827: UD2
; END FUNCTION sys_647

; FUNCTION sub_abe830 CONTEXT / separate function | ev_611e4cac96f8926a51e3eff6cd3ee321642225a5316d66fa01895e4738f665a7
; Ghidra body: 0xabe830..0xabe8a8
sub_abe830:
0xabe830: PUSH RBP
0xabe831: MOV RBP, RSP
0xabe834: PUSH R15
0xabe836: PUSH R14
0xabe838: PUSH RBX
0xabe839: SUB RSP, 0x18
0xabe83d: LEA R15, [0x391c310]
0xabe844: MOV RBX, RDI
0xabe847: MOV R14, RSI
0xabe84a: MOV RAX, qword ptr [R15]
0xabe84d: MOV qword ptr [RBP + -0x20], RAX
0xabe851: MOV RDI, qword ptr [RDI + 0x140]
0xabe858: CALL 0x00608f90
0xabe85d: TEST EAX, EAX
0xabe85f: JZ 0x00abe889
0xabe861: MOV dword ptr [RBP + -0x24], 0x0
0xabe868: LEA RCX, [RBP + -0x24]
0xabe86c: MOV RDI, RBX
0xabe86f: MOV EDX, 0x5
0xabe874: MOV RSI, qword ptr [R14]
0xabe877: CALL 0x00abe260
0xabe87c: MOVSXD RCX, dword ptr [RBP + -0x24]
0xabe880: MOV qword ptr [RBX + 0x408], RCX
0xabe887: JMP 0x00abe88e
0xabe889: MOV EAX, 0x1
0xabe88e: MOV RCX, qword ptr [R15]
0xabe891: CMP RCX, qword ptr [RBP + -0x20]
0xabe895: JNZ 0x00abe8a2
0xabe897: ADD RSP, 0x18
0xabe89b: POP RBX
0xabe89c: POP R14
0xabe89e: POP R15
0xabe8a0: POP RBP
0xabe8a1: RET
0xabe8a2: CALL 0x006fd6b0
0xabe8a7: UD2
; END FUNCTION sub_abe830

; FUNCTION sys_671 CONTEXT / separate function | ev_ceb688e7b424412f6cfdcd564b10481cf024d5d334084a8625739add83e347d2
; Ghidra body: 0xabe8b0..0xabea17
sys_671:
0xabe8b0: PUSH RBP
0xabe8b1: MOV RBP, RSP
0xabe8b4: PUSH R15
0xabe8b6: PUSH R14
0xabe8b8: PUSH R13
0xabe8ba: PUSH R12
0xabe8bc: PUSH RBX
0xabe8bd: SUB RSP, 0x18
0xabe8c1: LEA R13, [0x391c310]
0xabe8c8: MOV R15, RDI
0xabe8cb: XOR EDI, EDI
0xabe8cd: MOV RAX, qword ptr [R13]
0xabe8d1: MOV qword ptr [RBP + -0x30], RAX
0xabe8d5: MOV RAX, qword ptr [RSI + 0x18]
0xabe8d9: MOV R12D, dword ptr [RSI]
0xabe8dc: MOV EBX, dword ptr [RSI + 0x8]
0xabe8df: MOV R14, qword ptr [RSI + 0x10]
0xabe8e3: MOV qword ptr [RBP + -0x40], RAX
0xabe8e7: CALL 0x00acc9a0
0xabe8ec: TEST EAX, EAX
0xabe8ee: JNZ 0x00abe912
0xabe8f0: MOV RAX, qword ptr GS:[0x0]
0xabe8f9: MOV RCX, qword ptr [RAX + 0x8]
0xabe8fd: MOV EAX, 0x2
0xabe902: CMP dword ptr [RCX + 0x5d4], 0x5000000
0xabe90c: JC 0x00abe9f8
0xabe912: CMP R12D, -0x1
0xabe916: JZ 0x00abe932
0xabe918: MOV RDI, qword ptr [R15 + 0x140]
0xabe91f: CALL 0x00608f90
0xabe924: TEST EAX, EAX
0xabe926: JNZ 0x00abe93d
0xabe928: MOV EAX, 0x1
0xabe92d: JMP 0x00abe9f8
0xabe932: MOV RAX, qword ptr [R15 + 0x8]
0xabe936: MOV R12D, dword ptr [RAX + 0x5c0]
0xabe93d: MOV EAX, 0x16
0xabe942: CMP R12D, 0xa
0xabe946: JA 0x00abe9f8
0xabe94c: CMP EBX, 0x2
0xabe94f: JZ 0x00abe96f
0xabe951: CMP EBX, 0x1
0xabe954: JNZ 0x00abe9f8
0xabe95a: LEA RSI, [RBP + -0x34]
0xabe95e: LEA RDX, [RBP + -0x38]
0xabe962: MOV EDI, R12D
0xabe965: CALL 0x008ed4e0
0xabe96a: MOV EAX, dword ptr [RBP + -0x34]
0xabe96d: JMP 0x00abe9b7
0xabe96f: LEA RSI, [RBP + -0x34]
0xabe973: LEA RDX, [RBP + -0x38]
0xabe977: MOV EDI, R12D
0xabe97a: CALL 0x009e3650
0xabe97f: MOV RAX, qword ptr [R15 + 0x8]
0xabe983: MOV RAX, qword ptr [RAX + 0x200]
0xabe98a: TEST byte ptr [RAX + 0x244], 0x2
0xabe991: MOV EAX, dword ptr [RBP + -0x34]
0xabe994: JZ 0x00abe9b7
0xabe996: LEA ECX, [RAX + 0x3]
0xabe999: TEST EAX, EAX
0xabe99b: CMOVNS ECX, EAX
0xabe99e: MOV EAX, dword ptr [RBP + -0x38]
0xabe9a1: SAR ECX, 0x2
0xabe9a4: MOV dword ptr [RBP + -0x34], ECX
0xabe9a7: LEA EDX, [RAX + 0x3]
0xabe9aa: TEST EAX, EAX
0xabe9ac: CMOVNS EDX, EAX
0xabe9af: MOV EAX, ECX
0xabe9b1: SAR EDX, 0x2
0xabe9b4: MOV dword ptr [RBP + -0x38], EDX
0xabe9b7: MOV ECX, EAX
0xabe9b9: MOV RDI, R14
0xabe9bc: SAR ECX, 0x1f
0xabe9bf: ANDN ESI, ECX, EAX
0xabe9c4: CALL 0x00259790
0xabe9c9: CMP EAX, -0x1
0xabe9cc: JZ 0x00abe9f3
0xabe9ce: MOV EAX, dword ptr [RBP + -0x38]
0xabe9d1: MOV RDI, qword ptr [RBP + -0x40]
0xabe9d5: MOV ECX, EAX
0xabe9d7: SAR ECX, 0x1f
0xabe9da: ANDN ESI, ECX, EAX
0xabe9df: CALL 0x00259790
0xabe9e4: XOR ECX, ECX
0xabe9e6: CMP EAX, -0x1
0xabe9e9: MOV EAX, 0xe
0xabe9ee: CMOVNZ EAX, ECX
0xabe9f1: JMP 0x00abe9f8
0xabe9f3: MOV EAX, 0xe
0xabe9f8: MOV RCX, qword ptr [R13]
0xabe9fc: CMP RCX, qword ptr [RBP + -0x30]
0xabea00: JNZ 0x00abea11
0xabea02: ADD RSP, 0x18
0xabea06: POP RBX
0xabea07: POP R12
0xabea09: POP R13
0xabea0b: POP R14
0xabea0d: POP R15
0xabea0f: POP RBP
0xabea10: RET
0xabea11: CALL 0x006fd6b0
0xabea16: UD2
; END FUNCTION sys_671

; FUNCTION FUN_00abea41 CONTEXT / separate function | ev_9dddfe4927a9cc2bf45d85a8ec5d5a13d811c1132fa63268fd3de3d264e3ca0c
; Ghidra body: 0xabea41..0xabea4b
FUN_00abea41:
0xabea41: MOVZX R8D, R8W
0xabea45: MOVZX R9D, R9W
0xabea49: JMP R11
; END FUNCTION FUN_00abea41

; FUNCTION sub_abea52 CONTEXT / separate function | ev_118caa65931cd5179d1d4c8718010f594e293f29fba414fb9454ad9301bb4c03
; Ghidra body: 0xabea52..0xabeab2
sub_abea52:
0xabea52: PUSH RBP
0xabea53: MOV RBP, RSP
0xabea56: PUSH R15
0xabea58: PUSH R14
0xabea5a: PUSH R13
0xabea5c: PUSH R12
0xabea5e: PUSH RBX
0xabea5f: SUB RSP, 0x18
0xabea63: LEA RAX, [0x2888d40]
0xabea6a: MOV qword ptr [RBP + -0x38], RDI
0xabea6e: MOV qword ptr [RBP + -0x30], RSI
0xabea72: MOV RSI, R11
0xabea75: MOV R15, RCX
0xabea78: MOV RBX, RDX
0xabea7b: MOV R12D, R9D
0xabea7e: MOV R13D, R8D
0xabea81: MOV R14, R11
0xabea84: MOV RDI, RAX
0xabea87: CALL 0x0044f8c0
0xabea8c: MOV RDI, qword ptr [RBP + -0x38]
0xabea90: MOV RSI, qword ptr [RBP + -0x30]
0xabea94: MOV R11, R14
0xabea97: MOV R8D, R13D
0xabea9a: MOV R9D, R12D
0xabea9d: MOV RDX, RBX
0xabeaa0: MOV RCX, R15
0xabeaa3: ADD RSP, 0x18
0xabeaa7: POP RBX
0xabeaa8: POP R12
0xabeaaa: POP R13
0xabeaac: POP R14
0xabeaae: POP R15
0xabeab0: POP RBP
0xabeab1: JMP 0x00abea41
; END FUNCTION sub_abea52

; FUNCTION sub_abeac0 CONTEXT / separate function | ev_1b48bbb82deb4a451672f6b60e961a8b72ee920c538a78f9c454d5d0eba36da6
; Ghidra body: 0xabeac0..0xabeaef
sub_abeac0:
0xabeac0: PUSH RBP
0xabeac1: MOV RBP, RSP
0xabeac4: LEA RDI, [0x129bd39]
0xabeacb: MOV ESI, 0x28
0xabead0: XOR EDX, EDX
0xabead2: XOR ECX, ECX
0xabead4: XOR R8D, R8D
0xabead7: XOR R9D, R9D
0xabeada: PUSH 0x0
0xabeadc: PUSH 0x7
0xabeade: CALL 0x0043b0e0
0xabeae3: ADD RSP, 0x10
0xabeae7: MOV qword ptr [0x03bf6e18], RAX
0xabeaee: POP RBP
0xabeaef: RET
; END FUNCTION sub_abeac0

; FUNCTION sub_abeaf0 CONTEXT / separate function | ev_9a8a7ca53ef953966bc22c18d280329276daf0a13b1e343c11f92a761f5f24e9
; Ghidra body: 0xabeaf0..0xabeb98
sub_abeaf0:
0xabeaf0: PUSH RBP
0xabeaf1: MOV RBP, RSP
0xabeaf4: PUSH R15
0xabeaf6: PUSH R14
0xabeaf8: PUSH R12
0xabeafa: PUSH RBX
0xabeafb: MOV EBX, EDI
0xabeafd: CALL 0x00ae8360
0xabeb02: MOV R15D, EAX
0xabeb05: TEST EAX, EAX
0xabeb07: JS 0x00abeb0e
0xabeb09: MOV R12D, R15D
0xabeb0c: JMP 0x00abeb31
0xabeb0e: MOV RAX, qword ptr GS:[0x0]
0xabeb17: MOV RDI, qword ptr [RAX + 0x140]
0xabeb1e: CALL 0x00609910
0xabeb23: MOV R14D, 0x0
0xabeb29: XOR R12D, R12D
0xabeb2c: CMP EAX, 0x1
0xabeb2f: JNZ 0x00abeb4c
0xabeb31: MOV R14D, 0x5
0xabeb37: CMP EBX, 0x2
0xabeb3a: JZ 0x00abeb49
0xabeb3c: CALL 0x00aec390
0xabeb41: XOR R14D, R14D
0xabeb44: CMP EAX, 0x1
0xabeb47: JNZ 0x00abeb60
0xabeb49: MOV R15D, R12D
0xabeb4c: MOV EDI, R15D
0xabeb4f: CALL 0x00ae8440
0xabeb54: MOV EAX, R14D
0xabeb57: POP RBX
0xabeb58: POP R12
0xabeb5a: POP R14
0xabeb5c: POP R15
0xabeb5e: POP RBP
0xabeb5f: RET
0xabeb60: TEST EBX, EBX
0xabeb62: JZ 0x00abeb7e
0xabeb64: CMP EBX, 0x4
0xabeb67: JZ 0x00abeb76
0xabeb69: CMP EBX, 0x3
0xabeb6c: JNZ 0x00abeb86
0xabeb6e: MOV R14D, 0x4
0xabeb74: JMP 0x00abeb49
0xabeb76: MOV R14D, 0xa
0xabeb7c: JMP 0x00abeb49
0xabeb7e: MOV R14D, 0x3
0xabeb84: JMP 0x00abeb49
0xabeb86: CALL 0x00aecc30
0xabeb8b: XOR ECX, ECX
0xabeb8d: CMP EAX, 0x1
0xabeb90: SETZ CL
0xabeb93: LEA R14D, [RCX + RCX*0x4]
0xabeb97: JMP 0x00abeb49
; END FUNCTION sub_abeaf0

; FUNCTION sub_abeba0 CONTEXT / separate function | ev_fafb0be859cf3600b89601fc4e4a966b6ac8e75c76cb44943ae9082bc50068f0
; Ghidra body: 0xabeba0..0xabec23
sub_abeba0:
0xabeba0: PUSH RBP
0xabeba1: MOV RBP, RSP
0xabeba4: PUSH R15
0xabeba6: PUSH R14
0xabeba8: PUSH R13
0xabebaa: PUSH R12
0xabebac: PUSH RBX
0xabebad: PUSH RAX
0xabebae: MOV R14, RDX
0xabebb1: MOV R15, RSI
0xabebb4: MOV R13D, EDI
0xabebb7: CALL 0x00ae8360
0xabebbc: MOV EBX, EAX
0xabebbe: MOV R12D, EAX
0xabebc1: TEST EAX, EAX
0xabebc3: JS 0x00abec0b
0xabebc5: MOV RDI, R15
0xabebc8: CALL 0x00aec770
0xabebcd: MOV R12D, EAX
0xabebd0: TEST EAX, EAX
0xabebd2: JNZ 0x00abec0b
0xabebd4: MOV R12D, 0x800d0202
0xabebda: CMP R13D, 0x4
0xabebde: JA 0x00abec0b
0xabebe0: MOV EAX, R13D
0xabebe3: LEA RCX, [0xe91430]
0xabebea: LEA RAX, [RAX + RAX*0x2]
0xabebee: CMP R14, qword ptr [RCX + RAX*0x8 + 0x8]
0xabebf3: JC 0x00abec0b
0xabebf5: LEA RAX, [RCX + RAX*0x8]
0xabebf9: MOV RDI, R15
0xabebfc: MOV RDX, R14
0xabebff: MOV RSI, qword ptr [RAX + 0x10]
0xabec03: CALL 0x00ae92f0
0xabec08: XOR R12D, R12D
0xabec0b: MOV EDI, EBX
0xabec0d: CALL 0x00ae8440
0xabec12: MOV EAX, R12D
0xabec15: ADD RSP, 0x8
0xabec19: POP RBX
0xabec1a: POP R12
0xabec1c: POP R13
0xabec1e: POP R14
0xabec20: POP R15
0xabec22: POP RBP
0xabec23: RET
; END FUNCTION sub_abeba0

; FUNCTION sub_abec30 CONTEXT / separate function | ev_647d8d4bc66343afd4ebf90b3ea14b1eac2290f68e14f83164de48a5f27b4b1b
; Ghidra body: 0xabec30..0xabecb3
sub_abec30:
0xabec30: PUSH RBP
0xabec31: MOV RBP, RSP
0xabec34: PUSH R15
0xabec36: PUSH R14
0xabec38: PUSH R13
0xabec3a: PUSH R12
0xabec3c: PUSH RBX
0xabec3d: PUSH RAX
0xabec3e: MOV R14, RDX
0xabec41: MOV R15, RSI
0xabec44: MOV R13D, EDI
0xabec47: CALL 0x00ae8360
0xabec4c: MOV EBX, EAX
0xabec4e: MOV R12D, EAX
0xabec51: TEST EAX, EAX
0xabec53: JS 0x00abec9b
0xabec55: MOV RDI, R15
0xabec58: CALL 0x00aec770
0xabec5d: MOV R12D, EAX
0xabec60: TEST EAX, EAX
0xabec62: JNZ 0x00abec9b
0xabec64: MOV R12D, 0x800d0202
0xabec6a: CMP R13D, 0x3
0xabec6e: JA 0x00abec9b
0xabec70: MOV EAX, R13D
0xabec73: LEA RCX, [0xe914d0]
0xabec7a: LEA RAX, [RAX + RAX*0x2]
0xabec7e: CMP R14, qword ptr [RCX + RAX*0x8 + 0x8]
0xabec83: JC 0x00abec9b
0xabec85: LEA RAX, [RCX + RAX*0x8]
0xabec89: MOV RDI, R15
0xabec8c: MOV RDX, R14
0xabec8f: MOV RSI, qword ptr [RAX + 0x10]
0xabec93: CALL 0x00ae92f0
0xabec98: XOR R12D, R12D
0xabec9b: MOV EDI, EBX
0xabec9d: CALL 0x00ae8440
0xabeca2: MOV EAX, R12D
0xabeca5: ADD RSP, 0x8
0xabeca9: POP RBX
0xabecaa: POP R12
0xabecac: POP R13
0xabecae: POP R14
0xabecb0: POP R15
0xabecb2: POP RBP
0xabecb3: RET
; END FUNCTION sub_abec30

; FUNCTION sub_abecc0 CONTEXT / separate function | ev_f877ee1b2ecca63e3c8dadab11b19cd0e9eca494437b836b2e911d2e7d94fa50
; Ghidra body: 0xabecc0..0xabed43
sub_abecc0:
0xabecc0: PUSH RBP
0xabecc1: MOV RBP, RSP
0xabecc4: PUSH R15
0xabecc6: PUSH R14
0xabecc8: PUSH R13
0xabecca: PUSH R12
0xabeccc: PUSH RBX
0xabeccd: PUSH RAX
0xabecce: MOV R14, RDX
0xabecd1: MOV R15, RSI
0xabecd4: MOV R13D, EDI
0xabecd7: CALL 0x00ae8360
0xabecdc: MOV EBX, EAX
0xabecde: MOV R12D, EAX
0xabece1: TEST EAX, EAX
0xabece3: JS 0x00abed2b
0xabece5: MOV RDI, R15
0xabece8: CALL 0x00aec770
0xabeced: MOV R12D, EAX
0xabecf0: TEST EAX, EAX
0xabecf2: JNZ 0x00abed2b
0xabecf4: MOV R12D, 0x800d0202
0xabecfa: CMP R13D, 0x9
0xabecfe: JA 0x00abed2b
0xabed00: MOV EAX, R13D
0xabed03: LEA RCX, [0xe91530]
0xabed0a: LEA RAX, [RAX + RAX*0x2]
0xabed0e: CMP R14, qword ptr [RCX + RAX*0x8 + 0x8]
0xabed13: JC 0x00abed2b
0xabed15: LEA RAX, [RCX + RAX*0x8]
0xabed19: MOV RDI, R15
0xabed1c: MOV RDX, R14
0xabed1f: MOV RSI, qword ptr [RAX + 0x10]
0xabed23: CALL 0x00ae92f0
0xabed28: XOR R12D, R12D
0xabed2b: MOV EDI, EBX
0xabed2d: CALL 0x00ae8440
0xabed32: MOV EAX, R12D
0xabed35: ADD RSP, 0x8
0xabed39: POP RBX
0xabed3a: POP R12
0xabed3c: POP R13
0xabed3e: POP R14
0xabed40: POP R15
0xabed42: POP RBP
0xabed43: RET
; END FUNCTION sub_abecc0

; FUNCTION sub_abed50 CONTEXT / separate function | ev_7d94c05d9388f72ac506a8912f4de067090409bd1f2a9654c9ab5313a647c0d9
; Ghidra body: 0xabed50..0xabedc8
sub_abed50:
0xabed50: PUSH RBP
0xabed51: MOV RBP, RSP
0xabed54: PUSH R15
0xabed56: PUSH R14
0xabed58: PUSH R13
0xabed5a: PUSH R12
0xabed5c: PUSH RBX
0xabed5d: PUSH RAX
0xabed5e: MOV R14, RDX
0xabed61: MOV R15, RSI
0xabed64: MOV R12D, EDI
0xabed67: CALL 0x00ae8360
0xabed6c: MOV EBX, EAX
0xabed6e: MOV R13D, EAX
0xabed71: TEST EAX, EAX
0xabed73: JS 0x00abedb0
0xabed75: MOV RDI, R15
0xabed78: CALL 0x00aec770
0xabed7d: MOV R13D, EAX
0xabed80: TEST EAX, EAX
0xabed82: JNZ 0x00abedb0
0xabed84: TEST R12D, R12D
0xabed87: MOV R13D, 0x800d0202
0xabed8d: SETNZ AL
0xabed90: CMP R14, 0x21
0xabed94: SETC CL
0xabed97: OR CL, AL
0xabed99: JNZ 0x00abedb0
0xabed9b: LEA RSI, [0x18dc0e0]
0xabeda2: MOV RDI, R15
0xabeda5: MOV RDX, R14
0xabeda8: CALL 0x00ae92f0
0xabedad: XOR R13D, R13D
0xabedb0: MOV EDI, EBX
0xabedb2: CALL 0x00ae8440
0xabedb7: MOV EAX, R13D
0xabedba: ADD RSP, 0x8
0xabedbe: POP RBX
0xabedbf: POP R12
0xabedc1: POP R13
0xabedc3: POP R14
0xabedc5: POP R15
0xabedc7: POP RBP
0xabedc8: RET
; END FUNCTION sub_abed50

; FUNCTION sub_abedd0 CONTEXT / separate function | ev_5f07383220be45e82fc69862448ff790f8f6fa1cdf8bdc05bb43d95219ce4863
; Ghidra body: 0xabedd0..0xabee1a
sub_abedd0:
0xabedd0: PUSH RBP
0xabedd1: MOV RBP, RSP
0xabedd4: PUSH RBX
0xabedd5: PUSH RAX
0xabedd6: MOV EBX, EDI
0xabedd8: CALL 0x00ae8360
0xabeddd: TEST EAX, EAX
0xabeddf: SETS CL
0xabede2: CMP EBX, 0x5
0xabede5: SETNC DL
0xabede8: OR DL, CL
0xabedea: JZ 0x00abedf0
0xabedec: XOR EBX, EBX
0xabedee: JMP 0x00abee0a
0xabedf0: MOV ECX, EBX
0xabedf2: LEA RDX, [0xe91430]
0xabedf9: LEA RCX, [RCX + RCX*0x2]
0xabedfd: MOV ECX, dword ptr [RDX + RCX*0x8]
0xabee00: MOV EDX, ECX
0xabee02: SAR EDX, 0x1f
0xabee05: ANDN EBX, EDX, ECX
0xabee0a: MOV EDI, EAX
0xabee0c: CALL 0x00ae8440
0xabee11: MOV RAX, RBX
0xabee14: ADD RSP, 0x8
0xabee18: POP RBX
0xabee19: POP RBP
0xabee1a: RET
; END FUNCTION sub_abedd0

; FUNCTION sub_abee20 CONTEXT / separate function | ev_6d779a560be1b58576dfa1817031863973bf309cac3981ff08e1b7ed54be5435
; Ghidra body: 0xabee20..0xabeee3, 0xabef2f..0xabef60
sub_abee20:
0xabee20: PUSH RBP
0xabee21: MOV RBP, RSP
0xabee24: PUSH R15
0xabee26: PUSH R14
0xabee28: PUSH R13
0xabee2a: PUSH R12
0xabee2c: PUSH RBX
0xabee2d: PUSH RAX
0xabee2e: MOV R14, RDX
0xabee31: MOV R15, RSI
0xabee34: MOV R13D, EDI
0xabee37: CALL 0x00ae8360
0xabee3c: MOV EBX, EAX
0xabee3e: MOV R12D, EAX
0xabee41: TEST EAX, EAX
0xabee43: JS 0x00abef48
0xabee49: CALL 0x00aee710
0xabee4e: TEST EAX, EAX
0xabee50: JZ 0x00abee5a
0xabee52: MOV R12D, EAX
0xabee55: JMP 0x00abef48
0xabee5a: CMP byte ptr [0x03bf6e24], 0x1
0xabee61: MOV R12D, 0x800d0603
0xabee67: JNZ 0x00abef48
0xabee6d: MOV RDI, R15
0xabee70: CALL 0x00aec770
0xabee75: TEST EAX, EAX
0xabee77: JNZ 0x00abee52
0xabee79: CMP R13D, 0x4
0xabee7d: JBE 0x00abee8a
0xabee7f: MOV R12D, 0x800d0202
0xabee85: JMP 0x00abef48
0xabee8a: MOV ECX, R13D
0xabee8d: LEA RAX, [0x3bf6e30]
0xabee94: MOV RDI, qword ptr [RAX + RCX*0x8]
0xabee98: MOV qword ptr [RBP + -0x30], RCX
0xabee9c: CALL 0x00aec770
0xabeea1: MOV RDX, qword ptr [RBP + -0x30]
0xabeea5: TEST EAX, EAX
0xabeea7: JNZ 0x00abef48
0xabeead: LEA RAX, [RDX + RDX*0x2]
0xabeeb1: LEA RCX, [0xe91430]
0xabeeb8: MOV R12D, 0x800d0202
0xabeebe: CMP R14, qword ptr [RCX + RAX*0x8]
0xabeec2: JA 0x00abef48
0xabeec8: CMP R13D, 0x4
0xabeecc: JA 0x00abef2f
0xabeece: LEA RAX, [0x18dbfdc]
0xabeed5: MOV R13D, 0xc
0xabeedb: MOVSXD RCX, dword ptr [RAX + RDX*0x4]
0xabeedf: ADD RCX, RAX
0xabeee2: JMP RCX
0xabef2f: LEA RAX, [0x3bf6e30]
0xabef36: MOV RSI, R15
0xabef39: MOV RDI, qword ptr [RAX + RDX*0x8]
0xabef3d: MOV RDX, R14
0xabef40: CALL 0x002590b0
0xabef45: XOR R12D, R12D
0xabef48: MOV EDI, EBX
0xabef4a: CALL 0x00ae8440
0xabef4f: MOV EAX, R12D
0xabef52: ADD RSP, 0x8
0xabef56: POP RBX
0xabef57: POP R12
0xabef59: POP R13
0xabef5b: POP R14
0xabef5d: POP R15
0xabef5f: POP RBP
0xabef60: RET
; END FUNCTION sub_abee20

; FUNCTION FUN_00abef70 CONTEXT / separate function | ev_72fb96bf768cdc3ffb4b31b9a6eb20b3e8c8d886f58ef4c85b69fec778a10ee5
; Ghidra body: 0xabef70..0xabefa3
FUN_00abef70:
0xabef70: TEST RDI, RDI
0xabef73: SETZ AL
0xabef76: TEST RSI, RSI
0xabef79: SETZ CL
0xabef7c: OR CL, AL
0xabef7e: TEST RDX, RDX
0xabef81: SETZ AL
0xabef84: OR AL, CL
0xabef86: JNZ 0x00abeff7
0xabef88: MOV RAX, RDX
0xabef8b: OR RAX, RSI
0xabef8e: SHR RAX, 0x20
0xabef92: JZ 0x00abef9e
0xabef94: MOV RAX, RDX
0xabef97: XOR EDX, EDX
0xabef99: DIV RSI
0xabef9c: JMP 0x00abefa4
0xabef9e: MOV EAX, EDX
0xabefa0: XOR EDX, EDX
0xabefa2: DIV ESI
; END FUNCTION FUN_00abef70

; FUNCTION sub_abefa4 CONTEXT / separate function | ev_6b9876a7c77c55e9d41b74c6e955e3edab5e4fc722ff2be7a71d4b7750e8fc8a
; Ghidra body: 0xabefa4..0xabefbe, 0xabefc0..0xabeff7
sub_abefa4:
0xabefa4: PUSH RBP
0xabefa5: MOV RBP, RSP
0xabefa8: PUSH RBX
0xabefa9: MOVZX EAX, byte ptr [RDI + RDX*0x1]
0xabefad: LEA R9, [0x13ba300]
0xabefb4: XOR R8D, R8D
0xabefb7: XOR R10D, R10D
0xabefba: MOVZX ECX, AL
0xabefbd: JMP 0x00abefc8
0xabefc0: INC R10
0xabefc3: CMP RSI, R10
0xabefc6: JZ 0x00abeff2
0xabefc8: MOVZX R11D, byte ptr [RDI + R10*0x1]
0xabefcd: TEST R11B, R11B
0xabefd0: JZ 0x00abefc0
0xabefd2: LEA EBX, [RCX + R10*0x1]
0xabefd6: AND EBX, 0xf
0xabefd9: MOVZX EBX, byte ptr [RBX + R9*0x1]
0xabefde: CMP R11B, BL
0xabefe1: MOVZX R11D, R11B
0xabefe5: CMOVZ R11D, R8D
0xabefe9: XOR R11B, BL
0xabefec: MOV byte ptr [RDI + R10*0x1], R11B
0xabeff0: JMP 0x00abefc0
0xabeff2: MOV byte ptr [RDI + RDX*0x1], AL
0xabeff5: POP RBX
0xabeff6: POP RBP
0xabeff7: RET
; END FUNCTION sub_abefa4

; FUNCTION sub_abf000 CONTEXT / separate function | ev_f929e6176f35ef28bc3a342d729b90ea481007b3299825d2e749010ec7f13b2e
; Ghidra body: 0xabf000..0xabf0f1
sub_abf000:
0xabf000: PUSH RBP
0xabf001: MOV RBP, RSP
0xabf004: PUSH R15
0xabf006: PUSH R14
0xabf008: PUSH R13
0xabf00a: PUSH R12
0xabf00c: PUSH RBX
0xabf00d: PUSH RAX
0xabf00e: MOV R14, RDX
0xabf011: MOV R15, RSI
0xabf014: MOV R12D, EDI
0xabf017: CALL 0x00ae8360
0xabf01c: MOV EBX, EAX
0xabf01e: MOV R13D, EAX
0xabf021: TEST EAX, EAX
0xabf023: JS 0x00abf0d9
0xabf029: CALL 0x00aee710
0xabf02e: TEST EAX, EAX
0xabf030: JZ 0x00abf03a
0xabf032: MOV R13D, EAX
0xabf035: JMP 0x00abf0d9
0xabf03a: CMP byte ptr [0x03bf6e24], 0x1
0xabf041: MOV R13D, 0x800d0603
0xabf047: JNZ 0x00abf0d9
0xabf04d: MOV RDI, R15
0xabf050: CALL 0x00aec770
0xabf055: TEST EAX, EAX
0xabf057: JNZ 0x00abf032
0xabf059: MOV R13D, 0x800d0202
0xabf05f: CMP R12D, 0x4
0xabf063: JA 0x00abf0d9
0xabf065: MOV EDX, R12D
0xabf068: LEA RCX, [0xe91430]
0xabf06f: LEA RAX, [RDX + RDX*0x2]
0xabf073: CMP R14, qword ptr [RCX + RAX*0x8]
0xabf077: JA 0x00abf0d9
0xabf079: MOV EDI, R12D
0xabf07c: MOV R13, RDX
0xabf07f: CALL 0x00aef140
0xabf084: MOV EAX, 0x17
0xabf089: BT EAX, R12D
0xabf08d: JNC 0x00abf0c0
0xabf08f: LEA RCX, [0x3bf6e30]
0xabf096: LEA RAX, [0x18dc208]
0xabf09d: MOV RDI, R15
0xabf0a0: MOV RDX, R14
0xabf0a3: MOV RSI, qword ptr [RCX + R13*0x8]
0xabf0a7: MOV R12, qword ptr [RAX + R13*0x8]
0xabf0ab: CALL 0x002590b0
0xabf0b0: MOV RDI, R15
0xabf0b3: MOV RSI, R14
0xabf0b6: MOV RDX, R12
0xabf0b9: CALL 0x00abef70
0xabf0be: JMP 0x00abf0d6
0xabf0c0: LEA RAX, [0x3bf6e30]
0xabf0c7: MOV RDI, R15
0xabf0ca: MOV RDX, R14
0xabf0cd: MOV RSI, qword ptr [RAX + R13*0x8]
0xabf0d1: CALL 0x002590b0
0xabf0d6: XOR R13D, R13D
0xabf0d9: MOV EDI, EBX
0xabf0db: CALL 0x00ae8440
0xabf0e0: MOV EAX, R13D
0xabf0e3: ADD RSP, 0x8
0xabf0e7: POP RBX
0xabf0e8: POP R12
0xabf0ea: POP R13
0xabf0ec: POP R14
0xabf0ee: POP R15
0xabf0f0: POP RBP
0xabf0f1: RET
; END FUNCTION sub_abf000

; FUNCTION sub_abf100 CONTEXT / separate function | ev_bd9017cf0e3300e852f7e26c7183d531eda8ea77a79672aa8d09817d0b5167a9
; Ghidra body: 0xabf100..0xabf138
sub_abf100:
0xabf100: PUSH RBP
0xabf101: MOV RBP, RSP
0xabf104: PUSH R14
0xabf106: PUSH RBX
0xabf107: CALL 0x00ae8360
0xabf10c: MOV EBX, EAX
0xabf10e: MOV R14D, EAX
0xabf111: TEST EAX, EAX
0xabf113: JS 0x00abf12a
0xabf115: CALL 0x00aec390
0xabf11a: MOV R14D, EBX
0xabf11d: CMP EAX, 0x1
0xabf120: JZ 0x00abf12a
0xabf122: CALL 0x00abf140
0xabf127: MOV R14D, EAX
0xabf12a: MOV EDI, EBX
0xabf12c: CALL 0x00ae8440
0xabf131: MOV EAX, R14D
0xabf134: POP RBX
0xabf135: POP R14
0xabf137: POP RBP
0xabf138: RET
; END FUNCTION sub_abf100

; FUNCTION sub_abf140 CONTEXT / separate function | ev_a1e8e7a871e69abc48556d9438149a39ceec84a7a39b7087d638d29a62f531e7
; Ghidra body: 0xabf140..0xabf1a6
sub_abf140:
0xabf140: PUSH RBP
0xabf141: MOV RBP, RSP
0xabf144: MOV byte ptr [0x03bf6e58], 0x1
0xabf14b: CALL 0x004c6580
0xabf150: TEST EAX, EAX
0xabf152: JNZ 0x00abf167
0xabf154: MOV EDI, 0x1
0xabf159: CALL 0x0056a1c0
0xabf15e: CALL 0x00ae9350
0xabf163: TEST EAX, EAX
0xabf165: JS 0x00abf19f
0xabf167: MOV EDI, 0x2
0xabf16c: CALL 0x0056a1c0
0xabf171: TEST EAX, EAX
0xabf173: JNZ 0x00abf19f
0xabf175: MOV EDI, 0x3
0xabf17a: CALL 0x0056a1c0
0xabf17f: TEST EAX, EAX
0xabf181: JNZ 0x00abf19f
0xabf183: MOV EDI, 0x4
0xabf188: CALL 0x0056a1c0
0xabf18d: TEST EAX, EAX
0xabf18f: JNZ 0x00abf19f
0xabf191: MOV EDI, 0x5
0xabf196: CALL 0x0056a1c0
0xabf19b: TEST EAX, EAX
0xabf19d: JZ 0x00abf1a1
0xabf19f: POP RBP
0xabf1a0: RET
0xabf1a1: POP RBP
0xabf1a2: JMP 0x00aeae80
; END FUNCTION sub_abf140

; FUNCTION sub_abf1b0 CONTEXT / separate function | ev_091f7c1ba1881a5935a2bbf551bbd4067f9627fedf80ef688ec5af2689b4ffde
; Ghidra body: 0xabf1b0..0xabf1db
sub_abf1b0:
0xabf1b0: PUSH RBP
0xabf1b1: MOV RBP, RSP
0xabf1b4: PUSH R14
0xabf1b6: PUSH RBX
0xabf1b7: CALL 0x00ae8360
0xabf1bc: MOV EBX, EAX
0xabf1be: MOV R14D, EAX
0xabf1c1: TEST EAX, EAX
0xabf1c3: JS 0x00abf1cd
0xabf1c5: CALL 0x00aeccd0
0xabf1ca: MOV R14D, EAX
0xabf1cd: MOV EDI, EBX
0xabf1cf: CALL 0x00ae8440
0xabf1d4: MOV EAX, R14D
0xabf1d7: POP RBX
0xabf1d8: POP R14
0xabf1da: POP RBP
0xabf1db: RET
; END FUNCTION sub_abf1b0

; FUNCTION sub_abf1e0 CONTEXT / separate function | ev_d4507ba70eba482176817a813c2e0d5ec517c93a44237738d59237988889bf6c
; Ghidra body: 0xabf1e0..0xabf217
sub_abf1e0:
0xabf1e0: PUSH RBP
0xabf1e1: MOV RBP, RSP
0xabf1e4: PUSH R14
0xabf1e6: PUSH RBX
0xabf1e7: CALL 0x00ae8360
0xabf1ec: MOV EBX, EAX
0xabf1ee: TEST EAX, EAX
0xabf1f0: JS 0x00abf206
0xabf1f2: CALL 0x00aec390
0xabf1f7: XOR R14D, R14D
0xabf1fa: CMP EAX, 0x1
0xabf1fd: SETNZ R14B
0xabf201: ADD R14D, R14D
0xabf204: JMP 0x00abf209
0xabf206: XOR R14D, R14D
0xabf209: MOV EDI, EBX
0xabf20b: CALL 0x00ae8440
0xabf210: MOV EAX, R14D
0xabf213: POP RBX
0xabf214: POP R14
0xabf216: POP RBP
0xabf217: RET
; END FUNCTION sub_abf1e0

; FUNCTION sub_abf220 CONTEXT / separate function | ev_a38ba7d3152be64ad51867140d880d617ec5945ffda4b8ada39e7280913fffb0
; Ghidra body: 0xabf220..0xabf23b
sub_abf220:
0xabf220: PUSH RBP
0xabf221: MOV RBP, RSP
0xabf224: MOV EAX, 0x1
0xabf229: CMP EDI, 0x4
0xabf22c: JA 0x00abf23a
0xabf22e: MOV EAX, EDI
0xabf230: LEA RCX, [0x18dc230]
0xabf237: MOV EAX, dword ptr [RCX + RAX*0x4]
0xabf23a: POP RBP
0xabf23b: RET
; END FUNCTION sub_abf220

; FUNCTION sub_abf240 CONTEXT / separate function | ev_a052d73d7b0edac7aeae6a0cbcd28c418de306b71ebfb8810f4b549f2a596b08
; Ghidra body: 0xabf240..0xabf2c4
sub_abf240:
0xabf240: PUSH RBP
0xabf241: MOV RBP, RSP
0xabf244: PUSH R15
0xabf246: PUSH R14
0xabf248: PUSH R13
0xabf24a: PUSH R12
0xabf24c: PUSH RBX
0xabf24d: PUSH RAX
0xabf24e: MOV R14, RDX
0xabf251: MOV R15, RSI
0xabf254: MOV R13D, EDI
0xabf257: CALL 0x00ae8360
0xabf25c: MOV EBX, EAX
0xabf25e: MOV R12D, EAX
0xabf261: TEST EAX, EAX
0xabf263: JS 0x00abf2ac
0xabf265: MOV RDI, R15
0xabf268: CALL 0x00aec770
0xabf26d: MOV R12D, EAX
0xabf270: TEST EAX, EAX
0xabf272: JNZ 0x00abf2ac
0xabf274: MOV R12D, 0x800d0202
0xabf27a: CMP R13D, 0x1
0xabf27e: JA 0x00abf2ac
0xabf280: MOV EAX, R13D
0xabf283: LEA RCX, [0xe914b0]
0xabf28a: SHL RAX, 0x4
0xabf28e: MOVSXD RDX, dword ptr [RAX + RCX*0x1 + 0x8]
0xabf293: CMP R14, RDX
0xabf296: JC 0x00abf2ac
0xabf298: ADD RCX, RAX
0xabf29b: MOV RDI, R15
0xabf29e: MOV RDX, R14
0xabf2a1: MOV RSI, qword ptr [RCX]
0xabf2a4: CALL 0x00ae92f0
0xabf2a9: XOR R12D, R12D
0xabf2ac: MOV EDI, EBX
0xabf2ae: CALL 0x00ae8440
0xabf2b3: MOV EAX, R12D
0xabf2b6: ADD RSP, 0x8
0xabf2ba: POP RBX
0xabf2bb: POP R12
0xabf2bd: POP R13
0xabf2bf: POP R14
0xabf2c1: POP R15
0xabf2c3: POP RBP
0xabf2c4: RET
; END FUNCTION sub_abf240

; FUNCTION sub_abf2d0 CONTEXT / separate function | ev_5c7fce3683125b0e6e760fac0927f9774b3068660e1181da834c9eefa1b41285
; Ghidra body: 0xabf2d0..0xabf310
sub_abf2d0:
0xabf2d0: PUSH RBP
0xabf2d1: MOV RBP, RSP
0xabf2d4: PUSH R14
0xabf2d6: PUSH RBX
0xabf2d7: MOV EBX, EDI
0xabf2d9: CALL 0x00ae8360
0xabf2de: MOV R14D, EAX
0xabf2e1: TEST EAX, EAX
0xabf2e3: JS 0x00abf302
0xabf2e5: MOV R14D, 0x800d0202
0xabf2eb: CMP EBX, 0x1
0xabf2ee: JA 0x00abf302
0xabf2f0: MOV ECX, EBX
0xabf2f2: LEA RDX, [0xe914b0]
0xabf2f9: SHL RCX, 0x4
0xabf2fd: MOV R14D, dword ptr [RCX + RDX*0x1 + 0xc]
0xabf302: MOV EDI, EAX
0xabf304: CALL 0x00ae8440
0xabf309: MOV EAX, R14D
0xabf30c: POP RBX
0xabf30d: POP R14
0xabf30f: POP RBP
0xabf310: RET
; END FUNCTION sub_abf2d0

; FUNCTION sub_abf33f CONTEXT / separate function | ev_dc34029e867c0f248a09693778ab3d4d33ef3e3bd66046bd53d6177165bbd93d
; Ghidra body: 0xabf33f..0xabf455
sub_abf33f:
0xabf33f: PUSH RBP
0xabf340: MOV RBP, RSP
0xabf343: LEA RSI, [0x28cdfe0]
0xabf34a: MOV EDI, 0xc00
0xabf34f: MOV EDX, 0x101
0xabf354: CALL 0x00c08b50
0xabf359: MOV RDI, RAX
0xabf35c: MOV EAX, 0x800d0211
0xabf361: TEST RDI, RDI
0xabf364: JZ 0x00abf454
0xabf36a: MOV ESI, 0xc00
0xabf36f: MOV qword ptr [0x03bf6e30], RDI
0xabf376: CALL 0x00258ff0
0xabf37b: LEA RSI, [0x28cdfe0]
0xabf382: MOV EDI, 0xa0000
0xabf387: MOV EDX, 0x101
0xabf38c: CALL 0x00c08b50
0xabf391: TEST RAX, RAX
0xabf394: JZ 0x00abf44f
0xabf39a: MOV ESI, 0xa0000
0xabf39f: MOV RDI, RAX
0xabf3a2: MOV qword ptr [0x03bf6e38], RAX
0xabf3a9: CALL 0x00258ff0
0xabf3ae: LEA RSI, [0x28cdfe0]
0xabf3b5: MOV EDI, 0x28000
0xabf3ba: MOV EDX, 0x101
0xabf3bf: CALL 0x00c08b50
0xabf3c4: TEST RAX, RAX
0xabf3c7: JZ 0x00abf44f
0xabf3cd: MOV ESI, 0x28000
0xabf3d2: MOV RDI, RAX
0xabf3d5: MOV qword ptr [0x03bf6e40], RAX
0xabf3dc: CALL 0x00258ff0
0xabf3e1: LEA RSI, [0x28cdfe0]
0xabf3e8: MOV EDI, 0x14000
0xabf3ed: MOV EDX, 0x101
0xabf3f2: CALL 0x00c08b50
0xabf3f7: TEST RAX, RAX
0xabf3fa: JZ 0x00abf44f
0xabf3fc: MOV ESI, 0x14000
0xabf401: MOV RDI, RAX
0xabf404: MOV qword ptr [0x03bf6e48], RAX
0xabf40b: CALL 0x00258ff0
0xabf410: LEA RSI, [0x28cdfe0]
0xabf417: MOV EDI, 0x1800
0xabf41c: MOV EDX, 0x101
0xabf421: CALL 0x00c08b50
0xabf426: MOV RDI, RAX
0xabf429: TEST RAX, RAX
0xabf42c: MOV EAX, 0x800d0211
0xabf431: JZ 0x00abf454
0xabf433: MOV ESI, 0x1800
0xabf438: MOV qword ptr [0x03bf6e50], RDI
0xabf43f: CALL 0x00258ff0
0xabf444: XOR EAX, EAX
0xabf446: MOV byte ptr [0x03bf6e24], 0x1
0xabf44d: JMP 0x00abf454
0xabf44f: MOV EAX, 0x800d0211
0xabf454: POP RBP
0xabf455: RET
; END FUNCTION sub_abf33f

; FUNCTION sub_abf460 CONTEXT / separate function | ev_c0132e7eeb3339c4f2a4273c3d2fb0b8c662156d51082b3c6d7cc9a888705c9d
; Ghidra body: 0xabf460..0xabf505
sub_abf460:
0xabf460: PUSH RBP
0xabf461: MOV RBP, RSP
0xabf464: PUSH RBX
0xabf465: PUSH RAX
0xabf466: LEA RBX, [0x28cdfe0]
0xabf46d: MOV RDI, qword ptr [0x03bf6e30]
0xabf474: MOV RSI, RBX
0xabf477: CALL 0x00c08df0
0xabf47c: MOV qword ptr [0x03bf6e30], 0x0
0xabf487: MOV RSI, RBX
0xabf48a: MOV RDI, qword ptr [0x03bf6e38]
0xabf491: CALL 0x00c08df0
0xabf496: MOV qword ptr [0x03bf6e38], 0x0
0xabf4a1: MOV RSI, RBX
0xabf4a4: MOV RDI, qword ptr [0x03bf6e40]
0xabf4ab: CALL 0x00c08df0
0xabf4b0: MOV qword ptr [0x03bf6e40], 0x0
0xabf4bb: MOV RSI, RBX
0xabf4be: MOV RDI, qword ptr [0x03bf6e48]
0xabf4c5: CALL 0x00c08df0
0xabf4ca: MOV qword ptr [0x03bf6e48], 0x0
0xabf4d5: MOV RSI, RBX
0xabf4d8: MOV RDI, qword ptr [0x03bf6e50]
0xabf4df: CALL 0x00c08df0
0xabf4e4: MOV qword ptr [0x03bf6e50], 0x0
0xabf4ef: MOV byte ptr [0x03bf6e24], 0x0
0xabf4f6: MOV byte ptr [0x03bf6e58], 0x0
0xabf4fd: XOR EAX, EAX
0xabf4ff: ADD RSP, 0x8
0xabf503: POP RBX
0xabf504: POP RBP
0xabf505: RET
; END FUNCTION sub_abf460

; FUNCTION sub_abf510 CONTEXT / separate function | ev_f74c945c0abb0cbff0e9803aa21325069da303c804d74288b49c23b35c3ea030
; Ghidra body: 0xabf510..0xabf53c
sub_abf510:
0xabf510: PUSH RBP
0xabf511: MOV RBP, RSP
0xabf514: CMP EDI, 0x4
0xabf517: JA 0x00abf539
0xabf519: MOV EAX, EDI
0xabf51b: LEA RDX, [0xe91430]
0xabf522: LEA RCX, [RAX + RAX*0x2]
0xabf526: CMP RSI, qword ptr [RDX + RCX*0x8]
0xabf52a: JNZ 0x00abf539
0xabf52c: LEA RCX, [0x3bf6e30]
0xabf533: MOV RAX, qword ptr [RCX + RAX*0x8]
0xabf537: POP RBP
0xabf538: RET
0xabf539: XOR EAX, EAX
0xabf53b: POP RBP
0xabf53c: RET
; END FUNCTION sub_abf510

; FUNCTION sub_abf540 CONTEXT / separate function | ev_add398792b09443468197e805bd4023ccdaa9d295b01f636f844826a3eafa143
; Ghidra body: 0xabf540..0xabf565
sub_abf540:
0xabf540: PUSH RBP
0xabf541: MOV RBP, RSP
0xabf544: DEC EDI
0xabf546: CMP EDI, 0x2d
0xabf549: JA 0x00abf55d
0xabf54b: MOV EAX, EDI
0xabf54d: LEA RCX, [0x18dc304]
0xabf554: MOVSXD RAX, dword ptr [RCX + RAX*0x4]
0xabf558: ADD RAX, RCX
0xabf55b: POP RBP
0xabf55c: RET
0xabf55d: LEA RAX, [0x13185be]
0xabf564: POP RBP
0xabf565: RET
; END FUNCTION sub_abf540

; FUNCTION sub_abf570 CONTEXT / separate function | ev_5981fe9e5b0483bedaa829c93c51b51707a01e5a8c482fb50c2456f836fdb1ae
; Ghidra body: 0xabf570..0xabf58b, 0xabf595..0xabf5ae
sub_abf570:
0xabf570: PUSH RBP
0xabf571: MOV RBP, RSP
0xabf574: LEA EAX, [RDI + -0xa]
0xabf577: CMP EAX, 0x2f
0xabf57a: JA 0x00abf595
0xabf57c: LEA RCX, [0x18dc244]
0xabf583: MOVSXD RAX, dword ptr [RCX + RAX*0x4]
0xabf587: ADD RAX, RCX
0xabf58a: JMP RAX
0xabf595: CMP EDI, 0x9b
0xabf59b: JNZ 0x00abf5a6
0xabf59d: LEA RAX, [0x132304e]
0xabf5a4: POP RBP
0xabf5a5: RET
0xabf5a6: LEA RAX, [0x127d64c]
0xabf5ad: POP RBP
0xabf5ae: RET
; END FUNCTION sub_abf570

; FUNCTION sub_abf5e0 CONTEXT / separate function | ev_8e5a37a7c8ecfd831603b228b3c5dc4c4d4259e8c571f9ea4d5ea70fa0cfc9cc
; Ghidra body: 0xabf5e0..0xabf8d6
sub_abf5e0:
0xabf5e0: PUSH RBP
0xabf5e1: MOV RBP, RSP
0xabf5e4: PUSH R15
0xabf5e6: PUSH R14
0xabf5e8: PUSH RBX
0xabf5e9: PUSH RAX
0xabf5ea: MOV EDX, dword ptr [RDI + 0x3c]
0xabf5ed: LEA R14, [0x13376dc]
0xabf5f4: MOV RBX, RDI
0xabf5f7: LEA RDI, [0x127d65c]
0xabf5fe: XOR EAX, EAX
0xabf600: MOV RSI, R14
0xabf603: CALL 0x0025d410
0xabf608: MOV EDX, dword ptr [RBX + 0x40]
0xabf60b: LEA RDI, [0x13376f9]
0xabf612: MOV RSI, R14
0xabf615: XOR EAX, EAX
0xabf617: CALL 0x0025d410
0xabf61c: MOV EDX, dword ptr [RBX + 0x44]
0xabf61f: LEA RDI, [0x13579a8]
0xabf626: MOV RSI, R14
0xabf629: XOR EAX, EAX
0xabf62b: CALL 0x0025d410
0xabf630: MOV EDX, dword ptr [RBX + 0x48]
0xabf633: LEA RDI, [0x13ab7c6]
0xabf63a: MOV RSI, R14
0xabf63d: XOR EAX, EAX
0xabf63f: CALL 0x0025d410
0xabf644: MOV EDX, dword ptr [RBX + 0x4c]
0xabf647: LEA RDI, [0x13620fd]
0xabf64e: MOV RSI, R14
0xabf651: XOR EAX, EAX
0xabf653: CALL 0x0025d410
0xabf658: MOV EDX, dword ptr [RBX + 0x50]
0xabf65b: LEA RDI, [0x1380c08]
0xabf662: MOV RSI, R14
0xabf665: XOR EAX, EAX
0xabf667: CALL 0x0025d410
0xabf66c: MOV EDX, dword ptr [RBX + 0x34]
0xabf66f: LEA RDI, [0x12e448e]
0xabf676: MOV RSI, R14
0xabf679: XOR EAX, EAX
0xabf67b: CALL 0x0025d410
0xabf680: MOV EDX, dword ptr [RBX + 0x30]
0xabf683: LEA RDI, [0x12da46c]
0xabf68a: MOV RSI, R14
0xabf68d: XOR EAX, EAX
0xabf68f: CALL 0x0025d410
0xabf694: MOV EDX, dword ptr [RBX + 0x38]
0xabf697: LEA RDI, [0x13185ee]
0xabf69e: MOV RSI, R14
0xabf6a1: XOR EAX, EAX
0xabf6a3: CALL 0x0025d410
0xabf6a8: MOV EDX, dword ptr [RBX + 0x54]
0xabf6ab: LEA RDI, [0x127d684]
0xabf6b2: MOV RSI, R14
0xabf6b5: XOR EAX, EAX
0xabf6b7: CALL 0x0025d410
0xabf6bc: MOV EDX, dword ptr [RBX + 0x58]
0xabf6bf: LEA RDI, [0x13ab7ee]
0xabf6c6: MOV RSI, R14
0xabf6c9: XOR EAX, EAX
0xabf6cb: CALL 0x0025d410
0xabf6d0: MOV EDX, dword ptr [RBX + 0x5c]
0xabf6d3: LEA RDI, [0x12cfbcd]
0xabf6da: MOV RSI, R14
0xabf6dd: XOR EAX, EAX
0xabf6df: CALL 0x0025d410
0xabf6e4: MOV EDX, dword ptr [RBX + 0x60]
0xabf6e7: LEA RDI, [0x132d3e9]
0xabf6ee: MOV RSI, R14
0xabf6f1: XOR EAX, EAX
0xabf6f3: CALL 0x0025d410
0xabf6f8: MOV EDX, dword ptr [RBX + 0x64]
0xabf6fb: LEA RDI, [0x1287691]
0xabf702: MOV RSI, R14
0xabf705: XOR EAX, EAX
0xabf707: CALL 0x0025d410
0xabf70c: MOV EDX, dword ptr [RBX + 0x68]
0xabf70f: LEA RDI, [0x13579d0]
0xabf716: MOV RSI, R14
0xabf719: XOR EAX, EAX
0xabf71b: CALL 0x0025d410
0xabf720: MOV EDX, dword ptr [RBX + 0x6c]
0xabf723: LEA RDI, [0x1291be6]
0xabf72a: MOV RSI, R14
0xabf72d: XOR EAX, EAX
0xabf72f: CALL 0x0025d410
0xabf734: MOV EDX, dword ptr [RBX + 0x70]
0xabf737: LEA RDI, [0x12cfbf5]
0xabf73e: MOV RSI, R14
0xabf741: XOR EAX, EAX
0xabf743: CALL 0x0025d410
0xabf748: MOV EDX, dword ptr [RBX + 0x74]
0xabf74b: LEA RDI, [0x1273bea]
0xabf752: MOV RSI, R14
0xabf755: XOR EAX, EAX
0xabf757: CALL 0x0025d410
0xabf75c: MOV EDX, dword ptr [RBX + 0x78]
0xabf75f: LEA RDI, [0x12a62e3]
0xabf766: MOV RSI, R14
0xabf769: XOR EAX, EAX
0xabf76b: CALL 0x0025d410
0xabf770: MOV EDX, dword ptr [RBX + 0x7c]
0xabf773: LEA RDI, [0x1380c30]
0xabf77a: MOV RSI, R14
0xabf77d: XOR EAX, EAX
0xabf77f: CALL 0x0025d410
0xabf784: MOV EDX, dword ptr [RBX + 0x80]
0xabf78a: LEA RDI, [0x1376c9a]
0xabf791: MOV RSI, R14
0xabf794: XOR EAX, EAX
0xabf796: CALL 0x0025d410
0xabf79b: MOV EDX, dword ptr [RBX + 0x84]
0xabf7a1: LEA RDI, [0x12f8bfc]
0xabf7a8: MOV RSI, R14
0xabf7ab: XOR EAX, EAX
0xabf7ad: CALL 0x0025d410
0xabf7b2: MOV EDX, dword ptr [RBX + 0x88]
0xabf7b8: LEA RDI, [0x134ccd3]
0xabf7bf: MOV RSI, R14
0xabf7c2: XOR EAX, EAX
0xabf7c4: CALL 0x0025d410
0xabf7c9: MOV EDX, dword ptr [RBX + 0x8c]
0xabf7cf: LEA RDI, [0x1318616]
0xabf7d6: MOV RSI, R14
0xabf7d9: XOR EAX, EAX
0xabf7db: CALL 0x0025d410
0xabf7e0: MOV EDX, dword ptr [RBX + 0x90]
0xabf7e6: LEA RDI, [0x12eec51]
0xabf7ed: MOV RSI, R14
0xabf7f0: XOR EAX, EAX
0xabf7f2: CALL 0x0025d410
0xabf7f7: MOV EDX, dword ptr [RBX + 0x94]
0xabf7fd: LEA RDI, [0x13b610d]
0xabf804: MOV RSI, R14
0xabf807: XOR EAX, EAX
0xabf809: CALL 0x0025d410
0xabf80e: MOV EDX, dword ptr [RBX + 0x1c]
0xabf811: LEA RDI, [0x12cfc1d]
0xabf818: MOV RSI, R14
0xabf81b: XOR EAX, EAX
0xabf81d: CALL 0x0025d410
0xabf822: MOV EDX, dword ptr [RBX + 0x18]
0xabf825: LEA RDI, [0x12cfc47]
0xabf82c: MOV RSI, R14
0xabf82f: XOR EAX, EAX
0xabf831: CALL 0x0025d410
0xabf836: MOV EDX, dword ptr [RBX + 0x20]
0xabf839: LEA RDI, [0x12876b9]
0xabf840: MOV RSI, R14
0xabf843: XOR EAX, EAX
0xabf845: CALL 0x0025d410
0xabf84a: MOV EDX, dword ptr [RBX + 0x24]
0xabf84d: LEA RDI, [0x1341f2b]
0xabf854: MOV RSI, R14
0xabf857: XOR EAX, EAX
0xabf859: CALL 0x0025d410
0xabf85e: MOV EDX, dword ptr [RBX + 0x28]
0xabf861: LEA RDI, [0x12da494]
0xabf868: MOV RSI, R14
0xabf86b: XOR EAX, EAX
0xabf86d: CALL 0x0025d410
0xabf872: MOV EDX, dword ptr [RBX + 0x2c]
0xabf875: LEA RDI, [0x12876e6]
0xabf87c: MOV RSI, R14
0xabf87f: XOR EAX, EAX
0xabf881: CALL 0x0025d410
0xabf886: MOV EDX, dword ptr [RBX + 0x8]
0xabf889: LEA R15, [0x12ba75f]
0xabf890: MOV RSI, R14
0xabf893: XOR EAX, EAX
0xabf895: MOV RDI, R15
0xabf898: CALL 0x0025d410
0xabf89d: MOV EDX, dword ptr [RBX + 0xc]
0xabf8a0: MOV RDI, R15
0xabf8a3: MOV RSI, R14
0xabf8a6: XOR EAX, EAX
0xabf8a8: CALL 0x0025d410
0xabf8ad: MOV EDX, dword ptr [RBX + 0x10]
0xabf8b0: MOV RDI, R15
0xabf8b3: MOV RSI, R14
0xabf8b6: XOR EAX, EAX
0xabf8b8: CALL 0x0025d410
0xabf8bd: MOV EDX, dword ptr [RBX + 0x14]
0xabf8c0: MOV RDI, R15
0xabf8c3: MOV RSI, R14
0xabf8c6: XOR EAX, EAX
0xabf8c8: ADD RSP, 0x8
0xabf8cc: POP RBX
0xabf8cd: POP R14
0xabf8cf: POP R15
0xabf8d1: POP RBP
0xabf8d2: JMP 0x0025d410
; END FUNCTION sub_abf5e0

; FUNCTION sub_abf8e0 CONTEXT / separate function | ev_91d5480ce3eebd6a6f8c47300a831d22c43123693610425b2a239bc885362609
; Ghidra body: 0xabf8e0..0xabfbfa
sub_abf8e0:
0xabf8e0: PUSH RBP
0xabf8e1: MOV RBP, RSP
0xabf8e4: PUSH R15
0xabf8e6: PUSH R14
0xabf8e8: PUSH R13
0xabf8ea: PUSH R12
0xabf8ec: PUSH RBX
0xabf8ed: PUSH RAX
0xabf8ee: MOV EDX, dword ptr [RDI + 0x8]
0xabf8f1: LEA R14, [0x129bd7c]
0xabf8f8: MOV RBX, RDI
0xabf8fb: LEA RDI, [0x1291c0e]
0xabf902: XOR EAX, EAX
0xabf904: MOV RSI, R14
0xabf907: CALL 0x0025d410
0xabf90c: MOV EDX, dword ptr [RBX + 0xc]
0xabf90f: LEA RDI, [0x1362125]
0xabf916: MOV RSI, R14
0xabf919: XOR EAX, EAX
0xabf91b: CALL 0x0025d410
0xabf920: MOV EDX, dword ptr [RBX + 0x10]
0xabf923: LEA RDI, [0x1380c58]
0xabf92a: MOV RSI, R14
0xabf92d: XOR EAX, EAX
0xabf92f: CALL 0x0025d410
0xabf934: MOV EDX, dword ptr [RBX + 0x14]
0xabf937: LEA RDI, [0x1273c12]
0xabf93e: MOV RSI, R14
0xabf941: XOR EAX, EAX
0xabf943: CALL 0x0025d410
0xabf948: MOV EDX, dword ptr [RBX + 0x18]
0xabf94b: LEA RDI, [0x12a630b]
0xabf952: MOV RSI, R14
0xabf955: XOR EAX, EAX
0xabf957: CALL 0x0025d410
0xabf95c: MOV ECX, dword ptr [RBX + 0x1c]
0xabf95f: LEA R15, [0x131863e]
0xabf966: MOV RSI, R14
0xabf969: XOR EDX, EDX
0xabf96b: XOR EAX, EAX
0xabf96d: MOV RDI, R15
0xabf970: CALL 0x0025d410
0xabf975: MOV ECX, dword ptr [RBX + 0x44]
0xabf978: LEA R12, [0x12ba782]
0xabf97f: MOV RSI, R14
0xabf982: XOR EDX, EDX
0xabf984: XOR EAX, EAX
0xabf986: MOV RDI, R12
0xabf989: CALL 0x0025d410
0xabf98e: MOV ECX, dword ptr [RBX + 0x6c]
0xabf991: LEA R13, [0x129bd99]
0xabf998: MOV RSI, R14
0xabf99b: XOR EDX, EDX
0xabf99d: XOR EAX, EAX
0xabf99f: MOV RDI, R13
0xabf9a2: CALL 0x0025d410
0xabf9a7: MOV ECX, dword ptr [RBX + 0x20]
0xabf9aa: MOV RDI, R15
0xabf9ad: MOV RSI, R14
0xabf9b0: MOV EDX, 0x1
0xabf9b5: XOR EAX, EAX
0xabf9b7: CALL 0x0025d410
0xabf9bc: MOV ECX, dword ptr [RBX + 0x48]
0xabf9bf: MOV RDI, R12
0xabf9c2: MOV RSI, R14
0xabf9c5: MOV EDX, 0x1
0xabf9ca: XOR EAX, EAX
0xabf9cc: CALL 0x0025d410
0xabf9d1: MOV ECX, dword ptr [RBX + 0x70]
0xabf9d4: MOV RDI, R13
0xabf9d7: MOV RSI, R14
0xabf9da: MOV EDX, 0x1
0xabf9df: XOR EAX, EAX
0xabf9e1: CALL 0x0025d410
0xabf9e6: MOV ECX, dword ptr [RBX + 0x24]
0xabf9e9: MOV RDI, R15
0xabf9ec: MOV RSI, R14
0xabf9ef: MOV EDX, 0x2
0xabf9f4: XOR EAX, EAX
0xabf9f6: CALL 0x0025d410
0xabf9fb: MOV ECX, dword ptr [RBX + 0x4c]
0xabf9fe: MOV RDI, R12
0xabfa01: MOV RSI, R14
0xabfa04: MOV EDX, 0x2
0xabfa09: XOR EAX, EAX
0xabfa0b: CALL 0x0025d410
0xabfa10: MOV ECX, dword ptr [RBX + 0x74]
0xabfa13: MOV RDI, R13
0xabfa16: MOV RSI, R14
0xabfa19: MOV EDX, 0x2
0xabfa1e: XOR EAX, EAX
0xabfa20: CALL 0x0025d410
0xabfa25: MOV ECX, dword ptr [RBX + 0x28]
0xabfa28: MOV RDI, R15
0xabfa2b: MOV RSI, R14
0xabfa2e: MOV EDX, 0x3
0xabfa33: XOR EAX, EAX
0xabfa35: CALL 0x0025d410
0xabfa3a: MOV ECX, dword ptr [RBX + 0x50]
0xabfa3d: MOV RDI, R12
0xabfa40: MOV RSI, R14
0xabfa43: MOV EDX, 0x3
0xabfa48: XOR EAX, EAX
0xabfa4a: CALL 0x0025d410
0xabfa4f: MOV ECX, dword ptr [RBX + 0x78]
0xabfa52: MOV RDI, R13
0xabfa55: MOV RSI, R14
0xabfa58: MOV EDX, 0x3
0xabfa5d: XOR EAX, EAX
0xabfa5f: CALL 0x0025d410
0xabfa64: MOV ECX, dword ptr [RBX + 0x2c]
0xabfa67: MOV RDI, R15
0xabfa6a: MOV RSI, R14
0xabfa6d: MOV EDX, 0x4
0xabfa72: XOR EAX, EAX
0xabfa74: CALL 0x0025d410
0xabfa79: MOV ECX, dword ptr [RBX + 0x54]
0xabfa7c: MOV RDI, R12
0xabfa7f: MOV RSI, R14
0xabfa82: MOV EDX, 0x4
0xabfa87: XOR EAX, EAX
0xabfa89: CALL 0x0025d410
0xabfa8e: MOV ECX, dword ptr [RBX + 0x7c]
0xabfa91: MOV RDI, R13
0xabfa94: MOV RSI, R14
0xabfa97: MOV EDX, 0x4
0xabfa9c: XOR EAX, EAX
0xabfa9e: CALL 0x0025d410
0xabfaa3: MOV ECX, dword ptr [RBX + 0x30]
0xabfaa6: MOV RDI, R15
0xabfaa9: MOV RSI, R14
0xabfaac: MOV EDX, 0x5
0xabfab1: XOR EAX, EAX
0xabfab3: CALL 0x0025d410
0xabfab8: MOV ECX, dword ptr [RBX + 0x58]
0xabfabb: MOV RDI, R12
0xabfabe: MOV RSI, R14
0xabfac1: MOV EDX, 0x5
0xabfac6: XOR EAX, EAX
0xabfac8: CALL 0x0025d410
0xabfacd: MOV ECX, dword ptr [RBX + 0x80]
0xabfad3: MOV RDI, R13
0xabfad6: MOV RSI, R14
0xabfad9: MOV EDX, 0x5
0xabfade: XOR EAX, EAX
0xabfae0: CALL 0x0025d410
0xabfae5: MOV ECX, dword ptr [RBX + 0x34]
0xabfae8: MOV RDI, R15
0xabfaeb: MOV RSI, R14
0xabfaee: MOV EDX, 0x6
0xabfaf3: XOR EAX, EAX
0xabfaf5: CALL 0x0025d410
0xabfafa: MOV ECX, dword ptr [RBX + 0x5c]
0xabfafd: MOV RDI, R12
0xabfb00: MOV RSI, R14
0xabfb03: MOV EDX, 0x6
0xabfb08: XOR EAX, EAX
0xabfb0a: CALL 0x0025d410
0xabfb0f: MOV ECX, dword ptr [RBX + 0x84]
0xabfb15: MOV RDI, R13
0xabfb18: MOV RSI, R14
0xabfb1b: MOV EDX, 0x6
0xabfb20: XOR EAX, EAX
0xabfb22: CALL 0x0025d410
0xabfb27: MOV ECX, dword ptr [RBX + 0x38]
0xabfb2a: MOV RDI, R15
0xabfb2d: MOV RSI, R14
0xabfb30: MOV EDX, 0x7
0xabfb35: XOR EAX, EAX
0xabfb37: CALL 0x0025d410
0xabfb3c: MOV ECX, dword ptr [RBX + 0x60]
0xabfb3f: MOV RDI, R12
0xabfb42: MOV RSI, R14
0xabfb45: MOV EDX, 0x7
0xabfb4a: XOR EAX, EAX
0xabfb4c: CALL 0x0025d410
0xabfb51: MOV ECX, dword ptr [RBX + 0x88]
0xabfb57: MOV RDI, R13
0xabfb5a: MOV RSI, R14
0xabfb5d: MOV EDX, 0x7
0xabfb62: XOR EAX, EAX
0xabfb64: CALL 0x0025d410
0xabfb69: MOV ECX, dword ptr [RBX + 0x3c]
0xabfb6c: MOV RDI, R15
0xabfb6f: MOV RSI, R14
0xabfb72: MOV EDX, 0x8
0xabfb77: XOR EAX, EAX
0xabfb79: CALL 0x0025d410
0xabfb7e: MOV ECX, dword ptr [RBX + 0x64]
0xabfb81: MOV RDI, R12
0xabfb84: MOV RSI, R14
0xabfb87: MOV EDX, 0x8
0xabfb8c: XOR EAX, EAX
0xabfb8e: CALL 0x0025d410
0xabfb93: MOV ECX, dword ptr [RBX + 0x8c]
0xabfb99: MOV RDI, R13
0xabfb9c: MOV RSI, R14
0xabfb9f: MOV EDX, 0x8
0xabfba4: XOR EAX, EAX
0xabfba6: CALL 0x0025d410
0xabfbab: MOV ECX, dword ptr [RBX + 0x40]
0xabfbae: MOV RDI, R15
0xabfbb1: MOV RSI, R14
0xabfbb4: MOV EDX, 0x9
0xabfbb9: XOR EAX, EAX
0xabfbbb: CALL 0x0025d410
0xabfbc0: MOV ECX, dword ptr [RBX + 0x68]
0xabfbc3: MOV RDI, R12
0xabfbc6: MOV RSI, R14
0xabfbc9: MOV EDX, 0x9
0xabfbce: XOR EAX, EAX
0xabfbd0: CALL 0x0025d410
0xabfbd5: MOV ECX, dword ptr [RBX + 0x90]
0xabfbdb: MOV RDI, R13
0xabfbde: MOV RSI, R14
0xabfbe1: MOV EDX, 0x9
0xabfbe6: XOR EAX, EAX
0xabfbe8: ADD RSP, 0x8
0xabfbec: POP RBX
0xabfbed: POP R12
0xabfbef: POP R13
0xabfbf1: POP R14
0xabfbf3: POP R15
0xabfbf5: POP RBP
0xabfbf6: JMP 0x0025d410
; END FUNCTION sub_abf8e0

; FUNCTION sub_abfc00 CONTEXT / separate function | ev_720d5ad0d03ceed06ab457c0da9a00b61b8da9b7a38fefd773b0ec24d8147d14
; Ghidra body: 0xabfc00..0xabfc7b
sub_abfc00:
0xabfc00: PUSH RBP
0xabfc01: MOV RBP, RSP
0xabfc04: PUSH R15
0xabfc06: PUSH R14
0xabfc08: PUSH R12
0xabfc0a: PUSH RBX
0xabfc0b: MOV RAX, qword ptr [0x03bf6e60]
0xabfc12: MOV R14D, ESI
0xabfc15: MOV RBX, RDI
0xabfc18: AND R14D, 0x1
0xabfc1c: LEA ESI, [R14 + R14*0x1 + 0x1]
0xabfc21: MOV R15, qword ptr [RAX + 0x30]
0xabfc25: LEA RAX, [0x2690e0]
0xabfc2c: SUB RAX, R15
0xabfc2f: ROR RAX, 0x3
0xabfc33: CMP RAX, 0x72
0xabfc37: JA 0x00abfc65
0xabfc39: MOV RDI, RBX
0xabfc3c: CALL R15
0xabfc3f: OR R14D, EAX
0xabfc42: JZ 0x00abfc4d
0xabfc44: POP RBX
0xabfc45: POP R12
0xabfc47: POP R14
0xabfc49: POP R15
0xabfc4b: POP RBP
0xabfc4c: RET
0xabfc4d: MOV RDI, RBX
0xabfc50: CALL 0x00a11630
0xabfc55: MOV RDI, RBX
0xabfc58: POP RBX
0xabfc59: POP R12
0xabfc5b: POP R14
0xabfc5d: POP R15
0xabfc5f: POP RBP
0xabfc60: JMP 0x00a112d0
0xabfc65: MOV R12D, ESI
0xabfc68: LEA RDI, [0x2888ef0]
0xabfc6f: MOV RSI, R15
0xabfc72: CALL 0x0044f8c0
0xabfc77: MOV ESI, R12D
0xabfc7a: JMP 0x00abfc39
; END FUNCTION sub_abfc00

; FUNCTION sub_abfca1 CONTEXT / separate function | ev_13b9c9c64434b883951f6e93ab7e011a2cc83d4dc550ddba3af23259ea93a753
; Ghidra body: 0xabfca1..0xabfcda
sub_abfca1:
0xabfca1: PUSH RBP
0xabfca2: MOV RBP, RSP
0xabfca5: PUSH R15
0xabfca7: PUSH R14
0xabfca9: PUSH RBX
0xabfcaa: PUSH RAX
0xabfcab: LEA RAX, [0x2888ef0]
0xabfcb2: MOV RBX, RDI
0xabfcb5: MOV R14D, ESI
0xabfcb8: MOV RSI, RCX
0xabfcbb: MOV R15, RCX
0xabfcbe: MOV RDI, RAX
0xabfcc1: CALL 0x0044f8c0
0xabfcc6: MOV RCX, R15
0xabfcc9: MOV RDI, RBX
0xabfccc: MOV ESI, R14D
0xabfccf: ADD RSP, 0x8
0xabfcd3: POP RBX
0xabfcd4: POP R14
0xabfcd6: POP R15
0xabfcd8: POP RBP
0xabfcd9: JMP RCX
; END FUNCTION sub_abfca1

; FUNCTION sub_abfce0 CONTEXT / separate function | ev_4e7b496bfb9d472111d2cde322121ab46a8efa0ce80d0177a50ddb6b1cd362c0
; Ghidra body: 0xabfce0..0xabfd0a
sub_abfce0:
0xabfce0: PUSH RBP
0xabfce1: MOV RBP, RSP
0xabfce4: PUSH R14
0xabfce6: PUSH RBX
0xabfce7: MOV R14D, ESI
0xabfcea: MOV RBX, RDI
0xabfced: CALL 0x00a11630
0xabfcf2: TEST R14B, 0x4
0xabfcf6: JNZ 0x00abfd04
0xabfcf8: MOV RDI, RBX
0xabfcfb: POP RBX
0xabfcfc: POP R14
0xabfcfe: POP RBP
0xabfcff: JMP 0x00a112d0
0xabfd04: XOR EAX, EAX
0xabfd06: POP RBX
0xabfd07: POP R14
0xabfd09: POP RBP
0xabfd0a: RET
; END FUNCTION sub_abfce0

; FUNCTION sub_abfd10 CONTEXT / separate function | ev_cbba08a0d8fbc31ac9e3e332b34f64badc2ef6aa06ea794da4954e7ffc7f923a
; Ghidra body: 0xabfd10..0xac0561
sub_abfd10:
0xabfd10: PUSH RBP
0xabfd11: MOV RBP, RSP
0xabfd14: PUSH R15
0xabfd16: PUSH R14
0xabfd18: PUSH R13
0xabfd1a: PUSH R12
0xabfd1c: PUSH RBX
0xabfd1d: SUB RSP, 0x138
0xabfd24: LEA R13, [0x391c310]
0xabfd2b: MOV RBX, RDI
0xabfd2e: LEA RSI, [0x12d50c7]
0xabfd35: LEA RDX, [RBP + -0x150]
0xabfd3c: MOV RAX, qword ptr [R13]
0xabfd40: MOV qword ptr [RBP + -0x30], RAX
0xabfd44: MOV dword ptr [RBP + -0x150], 0x0
0xabfd4e: MOV RDI, qword ptr [RDI + 0xa8]
0xabfd55: CALL 0x005e11d0
0xabfd5a: TEST RAX, RAX
0xabfd5d: JZ 0x00abfd93
0xabfd5f: LEA RSI, [0x1296dec]
0xabfd66: MOV EDX, 0x7
0xabfd6b: MOV RDI, RAX
0xabfd6e: CALL 0x008d1a30
0xabfd73: MOV RDI, qword ptr [RBX + 0xa8]
0xabfd7a: TEST EAX, EAX
0xabfd7c: LEA RSI, [0x12d50c7]
0xabfd83: SETZ AL
0xabfd86: MOV dword ptr [RBP + -0x15c], EAX
0xabfd8c: CALL 0x005ddca0
0xabfd91: JMP 0x00abfd9d
0xabfd93: MOV dword ptr [RBP + -0x15c], 0x0
0xabfd9d: MOV R15, qword ptr GS:[0x0]
0xabfda6: MOV RDI, qword ptr [RBX + 0xa8]
0xabfdad: LEA RSI, [0x12b2da1]
0xabfdb4: LEA RDX, [RBP + -0x130]
0xabfdbb: CALL 0x005e11d0
0xabfdc0: LEA RSI, [0x2bfc080]
0xabfdc7: MOV EDI, 0x400
0xabfdcc: MOV EDX, 0x102
0xabfdd1: MOV R12, RAX
0xabfdd4: CALL 0x00c08b50
0xabfdd9: LEA RDX, [0x12911f3]
0xabfde0: MOV ESI, 0x400
0xabfde5: MOV RDI, RAX
0xabfde8: MOV RCX, R12
0xabfdeb: MOV R14, RAX
0xabfdee: XOR EAX, EAX
0xabfdf0: CALL 0x004aee40
0xabfdf5: CMP EAX, 0x400
0xabfdfa: JL 0x00abff68
0xabfe00: LEA RSI, [0x2bfc080]
0xabfe07: MOV RDI, R14
0xabfe0a: CALL 0x00c08df0
0xabfe0f: CMP qword ptr [0x03bf6e60], 0x0
0xabfe17: JNZ 0x00abfec8
0xabfe1d: LEA RDI, [0x13507c2]
0xabfe24: CALL 0x0066b580
0xabfe29: LEA RCX, [0x2203080]
0xabfe30: LEA RSI, [0x2565e48]
0xabfe37: MOV RDX, qword ptr [RCX + 0x150]
0xabfe3e: MOV R8, qword ptr [RCX + 0x118]
0xabfe45: MOV RDI, qword ptr [RCX + 0x128]
0xabfe4c: MOV R9, qword ptr [RCX + 0x10]
0xabfe50: MOV qword ptr [RSI + 0x150], RDX
0xabfe57: MOV qword ptr [RSI + 0x118], R8
0xabfe5e: MOV qword ptr [RSI + 0x128], RDI
0xabfe65: MOV RDI, qword ptr [RCX + 0xf8]
0xabfe6c: MOV R8, qword ptr [RCX + 0x130]
0xabfe73: MOV qword ptr [RSI + 0xf8], RDI
0xabfe7a: MOV RDI, qword ptr [RCX + 0x1c8]
0xabfe81: MOV qword ptr [RSI + 0x10], R9
0xabfe85: MOV qword ptr [RSI + 0x130], R8
0xabfe8c: MOV R8, qword ptr [RCX + 0x220]
0xabfe93: MOV qword ptr [RSI + 0x1c8], RDI
0xabfe9a: MOV RDI, qword ptr [RCX + 0x228]
0xabfea1: MOV RCX, qword ptr [RCX + 0x230]
0xabfea8: MOV qword ptr [RSI + 0x220], R8
0xabfeaf: MOV qword ptr [RSI + 0x228], RDI
0xabfeb6: MOV qword ptr [RSI + 0x230], RCX
0xabfebd: MOV RAX, qword ptr [RAX + 0x18]
0xabfec1: MOV qword ptr [0x03bf6e60], RAX
0xabfec8: MOV R14, qword ptr GS:[0x0]
0xabfed1: MOV RDI, qword ptr [R14 + 0x140]
0xabfed8: MOV ESI, 0x100
0xabfedd: CALL 0x00be9b90
0xabfee2: TEST EAX, EAX
0xabfee4: JZ 0x00ac000f
0xabfeea: MOV RCX, qword ptr [RBX + 0x98]
0xabfef1: MOV EAX, 0x2d
0xabfef6: TEST ECX, 0x4000
0xabfefc: JNZ 0x00ac031f
0xabff02: MOV RDI, qword ptr [RBX + 0xa8]
0xabff09: TEST ECX, 0x10000
0xabff0f: JNZ 0x00ac00ac
0xabff15: LEA RSI, [0x136e89e]
0xabff1c: LEA RDX, [RBP + -0x148]
0xabff23: LEA RCX, [RBP + -0x14c]
0xabff2a: CALL 0x005defd0
0xabff2f: TEST EAX, EAX
0xabff31: JZ 0x00ac012c
0xabff37: MOV RDI, qword ptr [RBX + 0xa8]
0xabff3e: LEA RSI, [0x12b2da1]
0xabff45: LEA RDX, [RBP + -0x148]
0xabff4c: LEA RCX, [RBP + -0x14c]
0xabff53: CALL 0x005defd0
0xabff58: TEST EAX, EAX
0xabff5a: MOV dword ptr [RBP + -0x134], EAX
0xabff60: SETNZ AL
0xabff63: JMP 0x00ac012e
0xabff68: MOV qword ptr [RBP + -0x158], RBX
0xabff6f: SUB RSP, 0x8
0xabff73: LEA RBX, [RBP + -0x118]
0xabff7a: XOR R13D, R13D
0xabff7d: MOV EDX, 0x4000064
0xabff82: XOR ESI, ESI
0xabff84: MOV ECX, 0x1
0xabff89: MOV R8, R14
0xabff8c: MOV R9D, 0xffffff9c
0xabff92: MOV RDI, RBX
0xabff95: PUSH R15
0xabff97: PUSH 0x0
0xabff99: PUSH 0x0
0xabff9b: CALL 0x005fa6e0
0xabffa0: ADD RSP, 0x20
0xabffa4: MOV RDI, RBX
0xabffa7: CALL 0x005f8c20
0xabffac: TEST EAX, EAX
0xabffae: JZ 0x00ac0019
0xabffb0: CMP EAX, 0x2
0xabffb3: JNZ 0x00ac0051
0xabffb9: LEA RDX, [0x13035f7]
0xabffc0: MOV ESI, 0x400
0xabffc5: MOV RDI, R14
0xabffc8: MOV RCX, R12
0xabffcb: XOR EAX, EAX
0xabffcd: CALL 0x004aee40
0xabffd2: MOV RBX, qword ptr [RBP + -0x158]
0xabffd9: CMP EAX, 0x3ff
0xabffde: JG 0x00abfff4
0xabffe0: MOV RDI, R14
0xabffe3: MOV RSI, R15
0xabffe6: CALL 0x00a10b30
0xabffeb: CMP EAX, 0x11
0xabffee: JNZ 0x00ac0245
0xabfff4: LEA RSI, [0x2bfc080]
0xabfffb: MOV RDI, R14
0xabfffe: CALL 0x00c08df0
0xac0003: LEA R13, [0x391c310]
0xac000a: JMP 0x00abfe0f
0xac000f: MOV EAX, 0x1
0xac0014: JMP 0x00ac031f
0xac0019: MOV RDI, qword ptr [RBP + -0xb8]
0xac0020: TEST RDI, RDI
0xac0023: JZ 0x00ac003e
0xac0025: XOR EAX, EAX
0xac0027: CMP dword ptr [RDI + 0x1d4], 0x2
0xac002e: SETZ AL
0xac0031: LEA R13D, [0x11 + RAX*0x4]
0xac0039: CALL 0x0054a440
0xac003e: LEA RDI, [RBP + -0x118]
0xac0045: MOV ESI, 0xffffffdf
0xac004a: CALL 0x005fa780
0xac004f: JMP 0x00ac0054
0xac0051: MOV R13D, EAX
0xac0054: MOV RBX, qword ptr [RBP + -0x158]
0xac005b: LEA RSI, [0x2bfc080]
0xac0062: MOV RDI, R14
0xac0065: CALL 0x00c08df0
0xac006a: OR R13D, 0x4
0xac006e: CMP R13D, 0x15
0xac0072: LEA R13, [0x391c310]
0xac0079: JNZ 0x00abfe0f
0xac007f: MOV ECX, dword ptr [RBP + -0x15c]
0xac0085: OR CL, byte ptr [RBX + 0x98]
0xac008b: MOV EAX, 0x1
0xac0090: TEST CL, 0x1
0xac0093: JZ 0x00ac031f
0xac0099: LEA RDI, [0x12eec79]
0xac00a0: XOR EAX, EAX
0xac00a2: CALL 0x0025d410
0xac00a7: JMP 0x00abfe0f
0xac00ac: LEA RSI, [0x1339b78]
0xac00b3: XOR EDX, EDX
0xac00b5: XOR ECX, ECX
0xac00b7: CALL 0x005e1250
0xac00bc: MOV ECX, EAX
0xac00be: MOV EAX, 0x2d
0xac00c3: TEST ECX, ECX
0xac00c5: JZ 0x00ac031f
0xac00cb: MOV dword ptr [RBP + -0x150], 0x0
0xac00d5: MOV RDI, RBX
0xac00d8: MOV RBX, qword ptr [RBX + 0x298]
0xac00df: MOV qword ptr [RBX + 0x40], -0x1
0xac00e7: MOV qword ptr [RBX + 0x50], 0x0
0xac00ef: MOV qword ptr [RBX + 0x48], 0x0
0xac00f7: MOV RAX, qword ptr GS:[0x0]
0xac0100: MOV qword ptr [RBX + 0x28], RAX
0xac0104: MOV qword ptr [RBX + 0x30], 0x0
0xac010c: MOV qword ptr [RBX + 0x38], 0x0
0xac0114: CALL 0x00a10d30
0xac0119: MOV qword ptr [RBX + 0x28], 0x0
0xac0121: MOV EAX, dword ptr [RBP + -0x150]
0xac0127: JMP 0x00ac031f
0xac012c: XOR EAX, EAX
0xac012e: MOV R8, qword ptr [RBP + -0x148]
0xac0135: MOV ECX, dword ptr [RBP + -0x14c]
0xac013b: TEST R8, R8
0xac013e: SETZ DL
0xac0141: OR DL, AL
0xac0143: TEST ECX, ECX
0xac0145: SETZ AL
0xac0148: OR AL, DL
0xac014a: MOV EAX, 0x16
0xac014f: JNZ 0x00ac031f
0xac0155: DEC ECX
0xac0157: MOVSXD RCX, ECX
0xac015a: CMP byte ptr [R8 + RCX*0x1], 0x0
0xac015f: JNZ 0x00ac031f
0xac0165: MOV RAX, qword ptr [RBX + 0x48]
0xac0169: MOV RCX, qword ptr [RAX + 0x8]
0xac016d: CMP RCX, qword ptr [0x01a5d458]
0xac0174: JNZ 0x00ac0254
0xac017a: LEA RCX, [0x1ad9ef8]
0xac0181: LEA RDI, [0x2203080]
0xac0188: LEA RSI, [RBP + -0x130]
0xac018f: MOV qword ptr [RBP + -0x130], RCX
0xac0196: MOV qword ptr [RBP + -0x128], RAX
0xac019d: CALL 0x0058afc0
0xac01a2: CMP EAX, 0x80000
0xac01a7: JNZ 0x00ac024d
0xac01ad: MOV RAX, qword ptr [RBX + 0x48]
0xac01b1: LEA RCX, [0x1adcdc8]
0xac01b8: LEA RSI, [RBP + -0x130]
0xac01bf: MOV qword ptr [RBP + -0x130], RCX
0xac01c6: MOV qword ptr [RBP + -0x128], RAX
0xac01cd: MOV dword ptr [RBP + -0x120], 0x0
0xac01d7: MOV RDI, qword ptr [RAX + 0x8]
0xac01db: CALL 0x0058ea90
0xac01e0: MOV R8, qword ptr [RBP + -0x148]
0xac01e7: SUB RSP, 0x8
0xac01eb: MOV R12, RBX
0xac01ee: LEA RBX, [RBP + -0x118]
0xac01f5: MOV EDX, 0x44
0xac01fa: XOR ESI, ESI
0xac01fc: MOV ECX, 0x1
0xac0201: MOV R9D, 0xffffff9c
0xac0207: MOV RDI, RBX
0xac020a: PUSH R14
0xac020c: PUSH 0x0
0xac020e: PUSH 0x0
0xac0210: CALL 0x005fa6e0
0xac0215: ADD RSP, 0x20
0xac0219: MOV RDI, RBX
0xac021c: CALL 0x005f8c20
0xac0221: MOV RDI, qword ptr [R12 + 0x48]
0xac0226: LEA RDX, [0x134ccfb]
0xac022d: MOV ESI, 0x80400
0xac0232: MOV ECX, 0x87
0xac0237: MOV EBX, EAX
0xac0239: MOV R15, R12
0xac023c: CALL 0x006afb50
0xac0241: MOV EAX, EBX
0xac0243: JMP 0x00ac028e
0xac0245: MOV R13D, EAX
0xac0248: JMP 0x00ac005b
0xac024d: MOV R8, qword ptr [RBP + -0x148]
0xac0254: MOV R15, RBX
0xac0257: SUB RSP, 0x8
0xac025b: LEA RBX, [RBP + -0x118]
0xac0262: MOV EDX, 0x44
0xac0267: XOR ESI, ESI
0xac0269: MOV ECX, 0x1
0xac026e: MOV R9D, 0xffffff9c
0xac0274: MOV RDI, RBX
0xac0277: PUSH R14
0xac0279: PUSH 0x0
0xac027b: PUSH 0x0
0xac027d: CALL 0x005fa6e0
0xac0282: ADD RSP, 0x20
0xac0286: MOV RDI, RBX
0xac0289: CALL 0x005f8c20
0xac028e: TEST EAX, EAX
0xac0290: JNZ 0x00ac031f
0xac0296: LEA RDI, [RBP + -0x118]
0xac029d: MOV ESI, 0xffffffdf
0xac02a2: MOV RBX, R15
0xac02a5: CALL 0x005fa780
0xac02aa: MOV R15, qword ptr [RBP + -0xb8]
0xac02b1: LEA RSI, [0x2888ed0]
0xac02b8: MOV EDI, 0x58
0xac02bd: MOV EDX, 0x102
0xac02c2: CALL 0x00c08b50
0xac02c7: MOV qword ptr [RAX + 0x20], 0x0
0xac02cf: MOV R14, RAX
0xac02d2: LEA RDX, [RBP + -0x140]
0xac02d9: MOV RDI, RBX
0xac02dc: MOV RSI, R15
0xac02df: MOV RAX, qword ptr [R15 + 0x18]
0xac02e3: MOV qword ptr [R14], RAX
0xac02e6: CALL 0x00592ca0
0xac02eb: MOV dword ptr [RBP + -0x134], EAX
0xac02f1: TEST EAX, EAX
0xac02f3: JZ 0x00ac033f
0xac02f5: LEA RDI, [0x12a6333]
0xac02fc: LEA RSI, [0x13ab816]
0xac0303: MOV EDX, EAX
0xac0305: MOV EBX, EAX
0xac0307: XOR EAX, EAX
0xac0309: CALL 0x0025d410
0xac030e: LEA RSI, [0x2888ed0]
0xac0315: MOV RDI, R14
0xac0318: CALL 0x00c08df0
0xac031d: MOV EAX, EBX
0xac031f: MOV RCX, qword ptr [R13]
0xac0323: CMP RCX, qword ptr [RBP + -0x30]
0xac0327: JNZ 0x00ac055b
0xac032d: ADD RSP, 0x138
0xac0334: POP RBX
0xac0335: POP R12
0xac0337: POP R13
0xac0339: POP R14
0xac033b: POP R15
0xac033d: POP RBP
0xac033e: RET
0xac033f: MOV RAX, qword ptr [RBP + -0x140]
0xac0346: LEA RSI, [0x126d195]
0xac034d: LEA RDX, [RBP + -0x134]
0xac0354: OR dword ptr [RAX + 0x1c8], 0x80
0xac035e: MOV RAX, RBX
0xac0361: MOV RBX, qword ptr [RBP + -0x140]
0xac0368: MOV qword ptr [RBP + -0x158], RAX
0xac036f: OR dword ptr [RBX + 0x1c8], 0x1
0xac0376: MOV qword ptr [R14 + 0x8], RBX
0xac037a: MOV qword ptr [R14 + 0x18], 0x0
0xac0382: MOV RDI, qword ptr [RAX + 0xa8]
0xac0389: CALL 0x005e11d0
0xac038e: MOV ECX, dword ptr [RBP + -0x134]
0xac0394: CMP ECX, 0x2
0xac0397: JNZ 0x00ac03a5
0xac0399: MOV dword ptr [RBP + -0x134], 0x0
0xac03a3: JMP 0x00ac03d4
0xac03a5: TEST ECX, ECX
0xac03a7: SETZ CL
0xac03aa: TEST RAX, RAX
0xac03ad: SETNZ DL
0xac03b0: AND DL, CL
0xac03b2: CMP DL, 0x1
0xac03b5: JNZ 0x00ac03d4
0xac03b7: LEA RSI, [0x1379884]
0xac03be: MOV EDX, 0x5
0xac03c3: MOV RDI, RAX
0xac03c6: CALL 0x008d1a30
0xac03cb: TEST EAX, EAX
0xac03cd: JNZ 0x00ac03d4
0xac03cf: OR byte ptr [R14 + 0x1b], 0x1
0xac03d4: MOV RAX, qword ptr [RBP + -0x140]
0xac03db: MOV RAX, qword ptr [RAX + 0x10]
0xac03df: MOV qword ptr [RAX + 0x28], R14
0xac03e3: MOV RDI, qword ptr [RBP + -0x140]
0xac03ea: CALL 0x0054a060
0xac03ef: LEA RCX, [0x1adcdc8]
0xac03f6: MOV RAX, qword ptr [RBP + -0x140]
0xac03fd: LEA RSI, [RBP + -0x130]
0xac0404: MOV qword ptr [RBP + -0x130], RCX
0xac040b: MOV qword ptr [RBP + -0x128], RAX
0xac0412: MOV dword ptr [RBP + -0x120], 0x0
0xac041c: MOV RDI, qword ptr [RAX + 0x8]
0xac0420: CALL 0x0058ea90
0xac0425: MOV RAX, qword ptr [RBX + 0x10]
0xac0429: MOV RAX, qword ptr [RAX + 0x10]
0xac042d: MOV RAX, qword ptr [RAX + 0x18]
0xac0431: TEST byte ptr [RAX + 0x99], 0x10
0xac0438: JZ 0x00ac046b
0xac043a: MOV R12, qword ptr [RBP + -0x158]
0xac0441: XOR ESI, ESI
0xac0443: XOR EDX, EDX
0xac0445: XOR ECX, ECX
0xac0447: LEA RBX, [R12 + 0x18]
0xac044c: MOV RDI, RBX
0xac044f: CALL 0x004c6a00
0xac0454: OR byte ptr [R12 + 0x99], 0x10
0xac045d: MOV RDI, RBX
0xac0460: XOR ESI, ESI
0xac0462: XOR EDX, EDX
0xac0464: XOR ECX, ECX
0xac0466: CALL 0x004c6fa0
0xac046b: MOV RBX, qword ptr [RBP + -0x158]
0xac0472: AND byte ptr [R14 + 0x10], 0xfe
0xac0477: XOR ESI, ESI
0xac0479: XOR EDX, EDX
0xac047b: XOR ECX, ECX
0xac047d: LEA R12, [RBX + 0x18]
0xac0481: MOV RDI, R12
0xac0484: CALL 0x004c6a00
0xac0489: TEST byte ptr [R14 + 0x10], 0x1
0xac048e: JNZ 0x00ac0498
0xac0490: MOV EAX, dword ptr [RBX + 0x90]
0xac0496: JMP 0x00ac04ad
0xac0498: MOV RCX, qword ptr [R15 + 0x18]
0xac049c: MOV EAX, 0x400000c0
0xac04a1: AND EAX, dword ptr [RCX + 0x90]
0xac04a7: OR EAX, dword ptr [RBX + 0x90]
0xac04ad: OR EAX, 0x800
0xac04b2: MOV EDX, 0x6100
0xac04b7: MOV RDI, R12
0xac04ba: XOR ESI, ESI
0xac04bc: MOV dword ptr [RBX + 0x90], EAX
0xac04c2: MOV RCX, qword ptr [R15 + 0x18]
0xac04c6: AND EDX, dword ptr [RCX + 0x90]
0xac04cc: XOR ECX, ECX
0xac04ce: OR EDX, EAX
0xac04d0: MOV dword ptr [RBX + 0x90], EDX
0xac04d6: XOR EDX, EDX
0xac04d8: CALL 0x004c6fa0
0xac04dd: MOV RDI, RBX
0xac04e0: MOV qword ptr [RBX + 0x298], R14
0xac04e7: CALL 0x005479c0
0xac04ec: TEST byte ptr [R14 + 0x10], 0x1
0xac04f1: JZ 0x00ac0547
0xac04f3: MOV RDI, qword ptr [R14]
0xac04f6: XOR ESI, ESI
0xac04f8: XOR EDX, EDX
0xac04fa: XOR ECX, ECX
0xac04fc: ADD RDI, 0x18
0xac0500: CALL 0x004c6a00
0xac0505: MOV qword ptr [RBX + 0x310], 0x0
0xac0510: LEA RAX, [RBX + 0x310]
0xac0517: XOR ESI, ESI
0xac0519: XOR EDX, EDX
0xac051b: MOV RCX, qword ptr [R14]
0xac051e: MOV RCX, qword ptr [RCX + 0x328]
0xac0525: MOV qword ptr [RBX + 0x318], RCX
0xac052c: MOV qword ptr [RCX], RBX
0xac052f: MOV RCX, qword ptr [R14]
0xac0532: MOV qword ptr [RCX + 0x328], RAX
0xac0539: XOR ECX, ECX
0xac053b: MOV RDI, qword ptr [R14]
0xac053e: ADD RDI, 0x18
0xac0542: CALL 0x004c6fa0
0xac0547: MOV RSI, qword ptr [RBP + -0x148]
0xac054e: MOV RDI, RBX
0xac0551: CALL 0x005e1420
0xac0556: JMP 0x00ac00cb
0xac055b: CALL 0x006fd6b0
0xac0560: UD2
; END FUNCTION sub_abfd10

; FUNCTION sub_ac0570 CONTEXT / separate function | ev_1f40c276051aa40cfff8c59ef3d6a9647216b4015014f30f8986bd6a59d192cc
; Ghidra body: 0xac0570..0xac0598
sub_ac0570:
0xac0570: PUSH RBP
0xac0571: MOV RBP, RSP
0xac0574: MOV R8, RDX
0xac0577: MOV RCX, RSI
0xac057a: MOV RDX, RDI
0xac057d: LEA RDI, [0x132d411]
0xac0584: LEA RSI, [0x130e040]
0xac058b: XOR EAX, EAX
0xac058d: CALL 0x0025d410
0xac0592: MOV EAX, 0x2d
0xac0597: POP RBP
0xac0598: RET
; END FUNCTION sub_ac0570

; FUNCTION sub_ac05a0 CONTEXT / separate function | ev_775026f73469df0da153d260001567bf4d4b3e9ae84136a83041491050b18b4d
; Ghidra body: 0xac05a0..0xac06bf
sub_ac05a0:
0xac05a0: PUSH RBP
0xac05a1: MOV RBP, RSP
0xac05a4: PUSH R15
0xac05a6: PUSH R14
0xac05a8: PUSH R12
0xac05aa: PUSH RBX
0xac05ab: MOV R12, qword ptr [RDI + 0x298]
0xac05b2: MOV R14D, ESI
0xac05b5: MOV RBX, RDI
0xac05b8: MOV RAX, qword ptr [R12 + 0x40]
0xac05bd: CMP RAX, -0x1
0xac05c1: JZ 0x00ac0625
0xac05c3: MOV EAX, 0x10
0xac05c8: TEST R14D, 0x80000
0xac05cf: JZ 0x00ac0695
0xac05d5: MOV R15, qword ptr [R12 + 0x40]
0xac05da: MOV ESI, 0x4
0xac05df: MOV RDI, R15
0xac05e2: CALL 0x0095c490
0xac05e7: TEST EAX, EAX
0xac05e9: JZ 0x00ac0602
0xac05eb: MOV EDX, EAX
0xac05ed: LEA RDI, [0x132d434]
0xac05f4: LEA RSI, [0x12c4fff]
0xac05fb: XOR EAX, EAX
0xac05fd: CALL 0x0025d410
0xac0602: MOV RDI, R15
0xac0605: CALL 0x0095c2e0
0xac060a: TEST EAX, EAX
0xac060c: JZ 0x00ac0625
0xac060e: MOV EDX, EAX
0xac0610: LEA RDI, [0x12e44b6]
0xac0617: LEA RSI, [0x12c4fff]
0xac061e: XOR EAX, EAX
0xac0620: CALL 0x0025d410
0xac0625: SHR R14D, 0x12
0xac0629: MOV R15, qword ptr GS:[0x0]
0xac0632: MOV RDI, RBX
0xac0635: MOV RCX, R15
0xac0638: XOR ESI, ESI
0xac063a: AND R14D, 0x2
0xac063e: LEA EDX, [R14 + 0x1]
0xac0642: CALL 0x0054a460
0xac0647: TEST EAX, EAX
0xac0649: JZ 0x00ac0654
0xac064b: LEA RDI, [0x13a0929]
0xac0652: JMP 0x00ac0681
0xac0654: MOV RDI, qword ptr [R12 + 0x20]
0xac0659: TEST RDI, RDI
0xac065c: JZ 0x00ac0663
0xac065e: CALL 0x0054a120
0xac0663: MOV RDI, RBX
0xac0666: MOV ESI, 0x1
0xac066b: MOV EDX, R14D
0xac066e: MOV RCX, R15
0xac0671: CALL 0x0054a460
0xac0676: TEST EAX, EAX
0xac0678: JZ 0x00ac069e
0xac067a: LEA RDI, [0x12cfc72]
0xac0681: LEA RSI, [0x12c4fff]
0xac0688: MOV EDX, EAX
0xac068a: MOV EBX, EAX
0xac068c: XOR EAX, EAX
0xac068e: CALL 0x0025d410
0xac0693: MOV EAX, EBX
0xac0695: POP RBX
0xac0696: POP R12
0xac0698: POP R14
0xac069a: POP R15
0xac069c: POP RBP
0xac069d: RET
0xac069e: MOV RDI, qword ptr [RBX + 0x298]
0xac06a5: LEA RSI, [0x2888ed0]
0xac06ac: MOV qword ptr [RBX + 0x298], 0x0
0xac06b7: CALL 0x00c08df0
0xac06bc: XOR EAX, EAX
0xac06be: JMP 0x00ac0695
; END FUNCTION sub_ac05a0

; FUNCTION sub_ac06ea CONTEXT / separate function | ev_0031d521db2c70b56d92cde5f19fafc25c01383a85b75b54c8f3c78ded5ebe85
; Ghidra body: 0xac06ea..0xac0728
sub_ac06ea:
0xac06ea: PUSH RBP
0xac06eb: MOV RBP, RSP
0xac06ee: PUSH R15
0xac06f0: PUSH R14
0xac06f2: PUSH R12
0xac06f4: PUSH RBX
0xac06f5: LEA RAX, [0x2889050]
0xac06fc: MOV RBX, RDI
0xac06ff: MOV R14D, ESI
0xac0702: MOV RSI, RCX
0xac0705: MOV R15, RDX
0xac0708: MOV R12, RCX
0xac070b: MOV RDI, RAX
0xac070e: CALL 0x0044f8c0
0xac0713: MOV RCX, R12
0xac0716: MOV RDI, RBX
0xac0719: MOV ESI, R14D
0xac071c: MOV RDX, R15
0xac071f: POP RBX
0xac0720: POP R12
0xac0722: POP R14
0xac0724: POP R15
0xac0726: POP RBP
0xac0727: JMP RCX
; END FUNCTION sub_ac06ea

; FUNCTION sub_ac0752 CONTEXT / separate function | ev_fd79dc75b2adfe7f52ddc5b572617b6f16a172b91fe2b74e2ac926614682963a
; Ghidra body: 0xac0752..0xac07a0
sub_ac0752:
0xac0752: PUSH RBP
0xac0753: MOV RBP, RSP
0xac0756: PUSH R15
0xac0758: PUSH R14
0xac075a: PUSH R13
0xac075c: PUSH R12
0xac075e: PUSH RBX
0xac075f: PUSH RAX
0xac0760: LEA RAX, [0x2889070]
0xac0767: MOV RBX, RDI
0xac076a: MOV R14D, ESI
0xac076d: MOV RSI, R8
0xac0770: MOV R15, RCX
0xac0773: MOV R12D, EDX
0xac0776: MOV R13, R8
0xac0779: MOV RDI, RAX
0xac077c: CALL 0x0044f8c0
0xac0781: MOV R8, R13
0xac0784: MOV RDI, RBX
0xac0787: MOV ESI, R14D
0xac078a: MOV EDX, R12D
0xac078d: MOV RCX, R15
0xac0790: ADD RSP, 0x8
0xac0794: POP RBX
0xac0795: POP R12
0xac0797: POP R13
0xac0799: POP R14
0xac079b: POP R15
0xac079d: POP RBP
0xac079e: JMP R8
; END FUNCTION sub_ac0752

; FUNCTION sub_ac07d3 CONTEXT / separate function | ev_aa5e64284564ca4f3c6f4541ad5575e519481d217ae25ab4d739fd53f8150cac
; Ghidra body: 0xac07d3..0xac080c
sub_ac07d3:
0xac07d3: PUSH RBP
0xac07d4: MOV RBP, RSP
0xac07d7: PUSH R15
0xac07d9: PUSH R14
0xac07db: PUSH RBX
0xac07dc: PUSH RAX
0xac07dd: LEA RAX, [0x2889090]
0xac07e4: MOV RBX, RDI
0xac07e7: MOV R14, RSI
0xac07ea: MOV RSI, RCX
0xac07ed: MOV R15, RCX
0xac07f0: MOV RDI, RAX
0xac07f3: CALL 0x0044f8c0
0xac07f8: MOV RCX, R15
0xac07fb: MOV RDI, RBX
0xac07fe: MOV RSI, R14
0xac0801: ADD RSP, 0x8
0xac0805: POP RBX
0xac0806: POP R14
0xac0808: POP R15
0xac080a: POP RBP
0xac080b: JMP RCX
; END FUNCTION sub_ac07d3

; FUNCTION sub_ac0810 CONTEXT / separate function | ev_c4441d0a5e52a84ccb5a461b8e58692491f94151b36ab1456f588937b57dbdd3
; Ghidra body: 0xac0810..0xac08f6
sub_ac0810:
0xac0810: PUSH RBP
0xac0811: MOV RBP, RSP
0xac0814: PUSH R15
0xac0816: PUSH R14
0xac0818: PUSH R13
0xac081a: PUSH R12
0xac081c: PUSH RBX
0xac081d: PUSH RAX
0xac081e: MOV qword ptr [RCX], 0x0
0xac0825: MOV R14, RDI
0xac0828: MOV RBX, RCX
0xac082b: MOV R15D, 0xffffffff
0xac0831: MOV RAX, qword ptr [RDI + 0x298]
0xac0838: MOV RDI, qword ptr [RAX]
0xac083b: MOV RAX, qword ptr [RDI + 0x40]
0xac083f: MOV EAX, dword ptr [RAX + 0x28]
0xac0842: SHR EAX, 0x17
0xac0845: AND EAX, 0x2
0xac0848: JZ 0x00ac086a
0xac084a: MOV EDI, EAX
0xac084c: MOV R15D, EDX
0xac084f: MOV R12D, ESI
0xac0852: CALL 0x00561cf0
0xac0857: MOV RCX, qword ptr [R14 + 0x298]
0xac085e: MOV EDX, R15D
0xac0861: MOV ESI, R12D
0xac0864: MOV R15D, EAX
0xac0867: MOV RDI, qword ptr [RCX]
0xac086a: MOV RAX, qword ptr [RDI + 0x38]
0xac086e: MOV R12, qword ptr [RAX + 0x38]
0xac0872: LEA RAX, [0x26bad8]
0xac0879: SUB RAX, R12
0xac087c: ROR RAX, 0x3
0xac0880: CMP RAX, 0xf
0xac0884: JA 0x00ac08d0
0xac0886: MOV RCX, RBX
0xac0889: CALL R12
0xac088c: MOV R12D, EAX
0xac088f: CMP R15D, -0x1
0xac0893: JZ 0x00ac089d
0xac0895: MOV EDI, R15D
0xac0898: CALL 0x00561de0
0xac089d: TEST R12D, R12D
0xac08a0: JZ 0x00ac08b4
0xac08a2: MOV EAX, R12D
0xac08a5: ADD RSP, 0x8
0xac08a9: POP RBX
0xac08aa: POP R12
0xac08ac: POP R13
0xac08ae: POP R14
0xac08b0: POP R15
0xac08b2: POP RBP
0xac08b3: RET
0xac08b4: MOV RSI, qword ptr [RBX]
0xac08b7: MOV RDI, R14
0xac08ba: MOV RDX, RBX
0xac08bd: ADD RSP, 0x8
0xac08c1: POP RBX
0xac08c2: POP R12
0xac08c4: POP R13
0xac08c6: POP R14
0xac08c8: POP R15
0xac08ca: POP RBP
0xac08cb: JMP 0x00592ca0
0xac08d0: MOV dword ptr [RBP + -0x2c], ESI
0xac08d3: LEA RDI, [0x28890b0]
0xac08da: MOV RSI, R12
0xac08dd: MOV R13D, EDX
0xac08e0: CALL 0x0044f8c0
0xac08e5: MOV RAX, qword ptr [R14 + 0x298]
0xac08ec: MOV ESI, dword ptr [RBP + -0x2c]
0xac08ef: MOV EDX, R13D
0xac08f2: MOV RDI, qword ptr [RAX]
0xac08f5: JMP 0x00ac0886
; END FUNCTION sub_ac0810

; FUNCTION sub_ac0900 CONTEXT / separate function | ev_5abbd66bf813d9765aff3520457b4f6013bcb0792a16ba0735f5013b6127bef8
; Ghidra body: 0xac0900..0xac09e8
sub_ac0900:
0xac0900: PUSH RBP
0xac0901: MOV RBP, RSP
0xac0904: PUSH R15
0xac0906: PUSH R14
0xac0908: PUSH R13
0xac090a: PUSH R12
0xac090c: PUSH RBX
0xac090d: PUSH RAX
0xac090e: MOV qword ptr [RCX], 0x0
0xac0915: MOV R14, RDI
0xac0918: MOV RBX, RCX
0xac091b: MOV R15D, 0xffffffff
0xac0921: MOV RAX, qword ptr [RDI + 0x298]
0xac0928: MOV RDI, qword ptr [RAX]
0xac092b: MOV RAX, qword ptr [RDI + 0x40]
0xac092f: MOV EAX, dword ptr [RAX + 0x28]
0xac0932: SHR EAX, 0x17
0xac0935: AND EAX, 0x2
0xac0938: JZ 0x00ac095a
0xac093a: MOV EDI, EAX
0xac093c: MOV R15D, EDX
0xac093f: MOV R12, RSI
0xac0942: CALL 0x00561cf0
0xac0947: MOV RCX, qword ptr [R14 + 0x298]
0xac094e: MOV EDX, R15D
0xac0951: MOV RSI, R12
0xac0954: MOV R15D, EAX
0xac0957: MOV RDI, qword ptr [RCX]
0xac095a: MOV RAX, qword ptr [RDI + 0x38]
0xac095e: MOV R12, qword ptr [RAX + 0x40]
0xac0962: LEA RAX, [0x268068]
0xac0969: SUB RAX, R12
0xac096c: ROR RAX, 0x3
0xac0970: CMP RAX, 0x3b
0xac0974: JA 0x00ac09c0
0xac0976: MOV RCX, RBX
0xac0979: CALL R12
0xac097c: MOV R12D, EAX
0xac097f: CMP R15D, -0x1
0xac0983: JZ 0x00ac098d
0xac0985: MOV EDI, R15D
0xac0988: CALL 0x00561de0
0xac098d: TEST R12D, R12D
0xac0990: JZ 0x00ac09a4
0xac0992: MOV EAX, R12D
0xac0995: ADD RSP, 0x8
0xac0999: POP RBX
0xac099a: POP R12
0xac099c: POP R13
0xac099e: POP R14
0xac09a0: POP R15
0xac09a2: POP RBP
0xac09a3: RET
0xac09a4: MOV RSI, qword ptr [RBX]
0xac09a7: MOV RDI, R14
0xac09aa: MOV RDX, RBX
0xac09ad: ADD RSP, 0x8
0xac09b1: POP RBX
0xac09b2: POP R12
0xac09b4: POP R13
0xac09b6: POP R14
0xac09b8: POP R15
0xac09ba: POP RBP
0xac09bb: JMP 0x00592ca0
0xac09c0: MOV qword ptr [RBP + -0x30], RSI
0xac09c4: LEA RDI, [0x28890d0]
0xac09cb: MOV RSI, R12
0xac09ce: MOV R13D, EDX
0xac09d1: CALL 0x0044f8c0
0xac09d6: MOV RAX, qword ptr [R14 + 0x298]
0xac09dd: MOV RSI, qword ptr [RBP + -0x30]
0xac09e1: MOV EDX, R13D
0xac09e4: MOV RDI, qword ptr [RAX]
0xac09e7: JMP 0x00ac0976
; END FUNCTION sub_ac0900

; FUNCTION sub_ac09f0 CONTEXT / separate function | ev_29672938896fd3a999a0aaea4bea048ea5085d159b5fd61c39396c1e5baf768f
; Ghidra body: 0xac09f0..0xac0a29
sub_ac09f0:
0xac09f0: PUSH RBP
0xac09f1: MOV RBP, RSP
0xac09f4: MOV R10, R9
0xac09f7: MOV R11, R8
0xac09fa: MOV R9, RCX
0xac09fd: MOV R8, RDX
0xac0a00: MOV RCX, RSI
0xac0a03: MOV RDX, RDI
0xac0a06: LEA RDI, [0x12b066d]
0xac0a0d: LEA RSI, [0x1395b05]
0xac0a14: XOR EAX, EAX
0xac0a16: PUSH R10
0xac0a18: PUSH R11
0xac0a1a: CALL 0x0025d410
0xac0a1f: ADD RSP, 0x10
0xac0a23: MOV EAX, 0x2d
0xac0a28: POP RBP
0xac0a29: RET
; END FUNCTION sub_ac09f0

; FUNCTION sub_ac0a30 CONTEXT / separate function | ev_2bf825eb0244e5fc0ac49d60a81f4c4b60989fa483890ed5342884a14a76cf9d
; Ghidra body: 0xac0a30..0xac0a39
sub_ac0a30:
0xac0a30: PUSH RBP
0xac0a31: MOV RBP, RSP
0xac0a34: POP RBP
0xac0a35: JMP 0x00592c30
; END FUNCTION sub_ac0a30

; FUNCTION sub_ac0a40 CONTEXT / separate function | ev_d3e5d84c9495186a823be767a56d09a7d3a7e9fb430897f340de6070db2dac62
; Ghidra body: 0xac0a40..0xac0a5b
sub_ac0a40:
0xac0a40: PUSH RBP
0xac0a41: MOV RBP, RSP
0xac0a44: CALL 0x00592c70
0xac0a49: TEST EAX, EAX
0xac0a4b: JZ 0x00ac0a4f
0xac0a4d: POP RBP
0xac0a4e: RET
0xac0a4f: MOV qword ptr [0x03bf6e60], 0x0
0xac0a5a: POP RBP
0xac0a5b: RET
; END FUNCTION sub_ac0a40

; FUNCTION sub_ac0a82 CONTEXT / separate function | ev_8b8aaa33f54595422f021f72df6a75a717f18571321bf6db7935781abb2b0439
; Ghidra body: 0xac0a82..0xac0ad8
sub_ac0a82:
0xac0a82: PUSH RBP
0xac0a83: MOV RBP, RSP
0xac0a86: PUSH R15
0xac0a88: PUSH R14
0xac0a8a: PUSH R13
0xac0a8c: PUSH R12
0xac0a8e: PUSH RBX
0xac0a8f: PUSH RAX
0xac0a90: LEA RAX, [0x28890f0]
0xac0a97: MOV qword ptr [RBP + -0x30], RDI
0xac0a9b: MOV R14D, ESI
0xac0a9e: MOV RSI, R9
0xac0aa1: MOV R15, R8
0xac0aa4: MOV R13D, ECX
0xac0aa7: MOV R12, RDX
0xac0aaa: MOV RBX, R9
0xac0aad: MOV RDI, RAX
0xac0ab0: CALL 0x0044f8c0
0xac0ab5: MOV RDI, qword ptr [RBP + -0x30]
0xac0ab9: MOV R9, RBX
0xac0abc: MOV ESI, R14D
0xac0abf: MOV RDX, R12
0xac0ac2: MOV ECX, R13D
0xac0ac5: MOV R8, R15
0xac0ac8: ADD RSP, 0x8
0xac0acc: POP RBX
0xac0acd: POP R12
0xac0acf: POP R13
0xac0ad1: POP R14
0xac0ad3: POP R15
0xac0ad5: POP RBP
0xac0ad6: JMP R9
; END FUNCTION sub_ac0a82

; FUNCTION sub_ac0ae0 CONTEXT / separate function | ev_2ab86079917bc54c431221b7bea5ad840b82989e0746456198a0c2453d6b1d37
; Ghidra body: 0xac0ae0..0xac0b07
sub_ac0ae0:
0xac0ae0: PUSH RBP
0xac0ae1: MOV RBP, RSP
0xac0ae4: MOV R8, RDX
0xac0ae7: MOV ECX, ESI
0xac0ae9: MOV RDX, RDI
0xac0aec: LEA RDI, [0x12da4c1]
0xac0af3: LEA RSI, [0x130e055]
0xac0afa: XOR EAX, EAX
0xac0afc: CALL 0x0025d410
0xac0b01: MOV EAX, 0x2d
0xac0b06: POP RBP
0xac0b07: RET
; END FUNCTION sub_ac0ae0

; FUNCTION sub_ac0b10 CONTEXT / separate function | ev_fc4cc091063f7876d411626113efb260406520184320299277133add1005766f
; Ghidra body: 0xac0b10..0xac0b2c
sub_ac0b10:
0xac0b10: PUSH RBP
0xac0b11: MOV RBP, RSP
0xac0b14: MOV RDX, RDI
0xac0b17: LEA RDI, [0x13ab82c]
0xac0b1e: LEA RSI, [0x1395b1c]
0xac0b25: XOR EAX, EAX
0xac0b27: POP RBP
0xac0b28: JMP 0x0025d410
; END FUNCTION sub_ac0b10

; FUNCTION sub_ac0b53 CONTEXT / separate function | ev_8521ebd93b9ba9d01f20ef642d50652d163e59e6a7e473bfb6394d7340d46608
; Ghidra body: 0xac0b53..0xac0b8c
sub_ac0b53:
0xac0b53: PUSH RBP
0xac0b54: MOV RBP, RSP
0xac0b57: PUSH R15
0xac0b59: PUSH R14
0xac0b5b: PUSH RBX
0xac0b5c: PUSH RAX
0xac0b5d: LEA RAX, [0x2889110]
0xac0b64: MOV RBX, RDI
0xac0b67: MOV R14, RSI
0xac0b6a: MOV RSI, RCX
0xac0b6d: MOV R15, RCX
0xac0b70: MOV RDI, RAX
0xac0b73: CALL 0x0044f8c0
0xac0b78: MOV RCX, R15
0xac0b7b: MOV RDI, RBX
0xac0b7e: MOV RSI, R14
0xac0b81: ADD RSP, 0x8
0xac0b85: POP RBX
0xac0b86: POP R14
0xac0b88: POP R15
0xac0b8a: POP RBP
0xac0b8b: JMP RCX
; END FUNCTION sub_ac0b53

; FUNCTION sub_ac0bb6 CONTEXT / separate function | ev_d31c90bfa42c47490e4e2896fe4defd58bbc915b7b3c32454b3a99222d4ad42f
; Ghidra body: 0xac0bb6..0xac0bef
sub_ac0bb6:
0xac0bb6: PUSH RBP
0xac0bb7: MOV RBP, RSP
0xac0bba: PUSH R15
0xac0bbc: PUSH R14
0xac0bbe: PUSH RBX
0xac0bbf: PUSH RAX
0xac0bc0: LEA RAX, [0x2889130]
0xac0bc7: MOV RBX, RDI
0xac0bca: MOV R14, RSI
0xac0bcd: MOV RSI, RCX
0xac0bd0: MOV R15, RCX
0xac0bd3: MOV RDI, RAX
0xac0bd6: CALL 0x0044f8c0
0xac0bdb: MOV RCX, R15
0xac0bde: MOV RDI, RBX
0xac0be1: MOV RSI, R14
0xac0be4: ADD RSP, 0x8
0xac0be8: POP RBX
0xac0be9: POP R14
0xac0beb: POP R15
0xac0bed: POP RBP
0xac0bee: JMP RCX
; END FUNCTION sub_ac0bb6

; FUNCTION sub_ac0bf0 CONTEXT / separate function | ev_5d703cec4290258ad5bb88c524bf308f7851b3a2f073ac09b9777a5ba3e6aa38
; Ghidra body: 0xac0bf0..0xac0bf5
sub_ac0bf0:
0xac0bf0: PUSH RBP
0xac0bf1: MOV RBP, RSP
0xac0bf4: POP RBP
0xac0bf5: RET
; END FUNCTION sub_ac0bf0

; FUNCTION sub_ac0c00 CONTEXT / separate function | ev_9d2203c55c5cdbfbb1eb54471b9b9a5c25d44384659ecb13a044db6ab77d01f8
; Ghidra body: 0xac0c00..0xac0c05
sub_ac0c00:
0xac0c00: PUSH RBP
0xac0c01: MOV RBP, RSP
0xac0c04: POP RBP
0xac0c05: RET
; END FUNCTION sub_ac0c00

; FUNCTION sub_ac0c10 CONTEXT / separate function | ev_73aa32b7bcea1e901f8413ebe581962d6c389ffcb7cca43c7b836d51c7a1962e
; Ghidra body: 0xac0c10..0xac0c6a
sub_ac0c10:
0xac0c10: PUSH RBP
0xac0c11: MOV RBP, RSP
0xac0c14: PUSH R14
0xac0c16: PUSH RBX
0xac0c17: MOV R14, qword ptr GS:[0x0]
0xac0c20: MOVZX EAX, word ptr [R14 + 0x114]
0xac0c28: MOV RBX, RDI
0xac0c2b: TEST RSI, RSI
0xac0c2e: JZ 0x00ac0c4b
0xac0c30: TEST AX, AX
0xac0c33: JNZ 0x00ac0c66
0xac0c35: MOV RDI, RBX
0xac0c38: XOR EDX, EDX
0xac0c3a: CALL 0x00ac0f60
0xac0c3f: TEST EAX, EAX
0xac0c41: JZ 0x00ac0c66
0xac0c43: TEST byte ptr [RBX + 0xa], 0x10
0xac0c47: JZ 0x00ac0c5e
0xac0c49: JMP 0x00ac0c66
0xac0c4b: TEST AX, AX
0xac0c4e: JNZ 0x00ac0c66
0xac0c50: MOV RDI, RBX
0xac0c53: CALL 0x00ac14e0
0xac0c58: TEST byte ptr [RBX + 0xa], 0x10
0xac0c5c: JNZ 0x00ac0c66
0xac0c5e: INC word ptr [R14 + 0x10a]
0xac0c66: POP RBX
0xac0c67: POP R14
0xac0c69: POP RBP
0xac0c6a: RET
; END FUNCTION sub_ac0c10

; FUNCTION sub_ac0ca0 CONTEXT / separate function | ev_72363299ae0919d928b342f3a241ba466dcf7178e3468da583a9b5a1ba16d87d
; Ghidra body: 0xac0ca0..0xac0cdd
sub_ac0ca0:
0xac0ca0: PUSH RBP
0xac0ca1: MOV RBP, RSP
0xac0ca4: PUSH R15
0xac0ca6: PUSH R14
0xac0ca8: PUSH RBX
0xac0ca9: PUSH RAX
0xac0caa: LEA RAX, [0x2889210]
0xac0cb1: MOV RBX, RDI
0xac0cb4: MOV R14, RSI
0xac0cb7: MOV RSI, RCX
0xac0cba: MOV R15, RCX
0xac0cbd: MOV RDI, RAX
0xac0cc0: CALL 0x0044f8c0
0xac0cc5: MOV RCX, R15
0xac0cc8: MOV RDI, RBX
0xac0ccb: MOV RSI, R14
0xac0cce: ADD RSP, 0x8
0xac0cd2: POP RBX
0xac0cd3: POP R14
0xac0cd5: POP R15
0xac0cd7: POP RBP
0xac0cd8: ADD RDI, 0x28
0xac0cdc: JMP RCX
; END FUNCTION sub_ac0ca0

; FUNCTION sub_ac0ce0 CONTEXT / separate function | ev_3231e5f1a100f55492ce27da63df933fb0f9f3d53037811ad0dd794705d8a397
; Ghidra body: 0xac0ce0..0xac0d5a, 0xac0d60..0xac0d95
sub_ac0ce0:
0xac0ce0: PUSH RBP
0xac0ce1: MOV RBP, RSP
0xac0ce4: PUSH R15
0xac0ce6: PUSH R14
0xac0ce8: PUSH R12
0xac0cea: PUSH RBX
0xac0ceb: TEST dword ptr [RDI + 0x8], 0x100000
0xac0cf2: MOV RAX, -0x8
0xac0cf9: MOV RCX, -0xf
0xac0d00: MOV RBX, RDI
0xac0d03: CMOVZ RCX, RAX
0xac0d07: AND RCX, qword ptr [RDI + 0x40]
0xac0d0b: MOV RAX, qword ptr GS:[0x0]
0xac0d14: CMP RCX, RAX
0xac0d17: JNZ 0x00ac0d26
0xac0d19: MOV RDI, RBX
0xac0d1c: CALL 0x00ac1700
0xac0d21: XOR R14D, R14D
0xac0d24: JMP 0x00ac0d8a
0xac0d26: CALL 0x006a2630
0xac0d2b: MOV R12, qword ptr GS:[0x0]
0xac0d34: MOV EDI, dword ptr GS:[0x34]
0xac0d3c: CALL 0x004c8230
0xac0d41: MOV RCX, qword ptr [RAX + 0x6a0]
0xac0d48: ADD RAX, 0x6a0
0xac0d4e: XOR R14D, R14D
0xac0d51: CMP RCX, RAX
0xac0d54: JNZ 0x00ac0d68
0xac0d56: XOR R15D, R15D
0xac0d59: JMP 0x00ac0d7a
0xac0d60: MOV RCX, qword ptr [R15]
0xac0d63: CMP RCX, RAX
0xac0d66: JZ 0x00ac0d7a
0xac0d68: MOV R15, RCX
0xac0d6b: CMP qword ptr [RCX + 0x10], RBX
0xac0d6f: JNZ 0x00ac0d60
0xac0d71: CMP qword ptr [R15 + 0x18], R12
0xac0d75: JNZ 0x00ac0d60
0xac0d77: MOV R14, R15
0xac0d7a: CALL 0x006a2650
0xac0d7f: MOV RDI, RBX
0xac0d82: MOV RSI, R15
0xac0d85: CALL 0x00ac1870
0xac0d8a: MOV RAX, R14
0xac0d8d: POP RBX
0xac0d8e: POP R12
0xac0d90: POP R14
0xac0d92: POP R15
0xac0d94: POP RBP
0xac0d95: RET
; END FUNCTION sub_ac0ce0

; FUNCTION sub_ac0da0 CONTEXT / separate function | ev_2bd74c0c28fe61c169ab09cf5fa897251424f3795ff0e37bcf6910b009b9f9c3
; Ghidra body: 0xac0da0..0xac0e51
sub_ac0da0:
0xac0da0: PUSH RBP
0xac0da1: MOV RBP, RSP
0xac0da4: PUSH R15
0xac0da6: PUSH R14
0xac0da8: PUSH RBX
0xac0da9: PUSH RAX
0xac0daa: MOV EAX, EDX
0xac0dac: MOV ECX, EDX
0xac0dae: MOV RBX, RSI
0xac0db1: MOV RSI, qword ptr [0x03d0e8e8]
0xac0db8: MOV R14, RDI
0xac0dbb: AND EAX, 0x1
0xac0dbe: AND ECX, 0x2
0xac0dc1: SHL EAX, 0x11
0xac0dc4: SHL ECX, 0x12
0xac0dc7: OR ECX, EAX
0xac0dc9: MOV EAX, EDX
0xac0dcb: AND EAX, 0x8
0xac0dce: MOV qword ptr [RDI + 0x18], RSI
0xac0dd2: MOV qword ptr [RDI + 0x20], 0x0
0xac0dda: MOV R15D, EAX
0xac0ddd: SHL R15D, 0x1a
0xac0de1: OR R15D, ECX
0xac0de4: XOR R15D, 0x20000
0xac0deb: TEST DL, 0x4
0xac0dee: JNZ 0x00ac0e13
0xac0df0: LEA ECX, [0x8 + RAX*0x8]
0xac0df7: LEA RDI, [R14 + 0x40]
0xac0dfb: LEA RDX, [0x1323069]
0xac0e02: MOV RSI, RBX
0xac0e05: CALL 0x004c7dd0
0xac0e0a: LEA RSI, [0x2889150]
0xac0e11: JMP 0x00ac0e38
0xac0e13: LEA EDX, [0x4 + RAX*0x8]
0xac0e1a: LEA RDI, [R14 + 0x28]
0xac0e1e: LEA RSI, [0x13a0950]
0xac0e25: OR R15D, 0x100000
0xac0e2c: CALL 0x00c4b290
0xac0e31: LEA RSI, [0x2889188]
0xac0e38: MOV RDI, R14
0xac0e3b: MOV RDX, RBX
0xac0e3e: XOR ECX, ECX
0xac0e40: MOV R8D, R15D
0xac0e43: ADD RSP, 0x8
0xac0e47: POP RBX
0xac0e48: POP R14
0xac0e4a: POP R15
0xac0e4c: POP RBP
0xac0e4d: JMP 0x00a2e8d0
; END FUNCTION sub_ac0da0

; FUNCTION sub_ac0e60 CONTEXT / separate function | ev_337c8f6469d151a1caea4170495e4fe1572333762e83269fecd6f7ee6590c57b
; Ghidra body: 0xac0e60..0xac0eb2
sub_ac0e60:
0xac0e60: PUSH RBP
0xac0e61: MOV RBP, RSP
0xac0e64: PUSH R14
0xac0e66: PUSH RBX
0xac0e67: MOV RAX, qword ptr [0x03d0e8e8]
0xac0e6e: MOV R14, RDI
0xac0e71: LEA RDX, [0x1323069]
0xac0e78: MOV ECX, 0x8
0xac0e7d: MOV RBX, RSI
0xac0e80: MOV qword ptr [RDI + 0x18], RAX
0xac0e84: MOV qword ptr [RDI + 0x20], 0x0
0xac0e8c: ADD RDI, 0x40
0xac0e90: CALL 0x004c7dd0
0xac0e95: LEA RSI, [0x2889150]
0xac0e9c: MOV RDI, R14
0xac0e9f: MOV RDX, RBX
0xac0ea2: XOR ECX, ECX
0xac0ea4: MOV R8D, 0x20000
0xac0eaa: POP RBX
0xac0eab: POP R14
0xac0ead: POP RBP
0xac0eae: JMP 0x00a2e8d0
; END FUNCTION sub_ac0e60

; FUNCTION sub_ac0ec0 CONTEXT / separate function | ev_78dd9e6bac72d7b8cfd402514527fff445e4bc72f240f625d30bfdb91554ae7c
; Ghidra body: 0xac0ec0..0xac0ef8
sub_ac0ec0:
0xac0ec0: PUSH RBP
0xac0ec1: MOV RBP, RSP
0xac0ec4: PUSH RBX
0xac0ec5: PUSH RAX
0xac0ec6: MOV qword ptr [RDI + 0x20], 0xdead
0xac0ece: MOV RBX, RDI
0xac0ed1: TEST byte ptr [RDI + 0xa], 0x10
0xac0ed5: JNZ 0x00ac0ee2
0xac0ed7: LEA RDI, [RBX + 0x40]
0xac0edb: CALL 0x004c7e50
0xac0ee0: JMP 0x00ac0eeb
0xac0ee2: LEA RDI, [RBX + 0x28]
0xac0ee6: CALL 0x00261090
0xac0eeb: MOV RDI, RBX
0xac0eee: ADD RSP, 0x8
0xac0ef2: POP RBX
0xac0ef3: POP RBP
0xac0ef4: JMP 0x00a2ea10
; END FUNCTION sub_ac0ec0

; FUNCTION sub_ac0f00 CONTEXT / separate function | ev_c143e483f1c31f7b09ad30b70905e0448f603a868f6332f96a55e3e7b4fe2485
; Ghidra body: 0xac0f00..0xac0f56
sub_ac0f00:
0xac0f00: PUSH RBP
0xac0f01: MOV RBP, RSP
0xac0f04: PUSH R14
0xac0f06: PUSH RBX
0xac0f07: MOV R14, qword ptr [RDI + 0x8]
0xac0f0b: MOV RBX, qword ptr [RDI]
0xac0f0e: MOV RAX, qword ptr [0x03d0e8e8]
0xac0f15: LEA RDX, [0x1323069]
0xac0f1c: MOV ECX, 0x8
0xac0f21: LEA RDI, [RBX + 0x40]
0xac0f25: MOV RSI, R14
0xac0f28: MOV qword ptr [RBX + 0x18], RAX
0xac0f2c: MOV qword ptr [RBX + 0x20], 0x0
0xac0f34: CALL 0x004c7dd0
0xac0f39: LEA RSI, [0x2889150]
0xac0f40: MOV RDI, RBX
0xac0f43: MOV RDX, R14
0xac0f46: XOR ECX, ECX
0xac0f48: MOV R8D, 0x20000
0xac0f4e: POP RBX
0xac0f4f: POP R14
0xac0f51: POP RBP
0xac0f52: JMP 0x00a2e8d0
; END FUNCTION sub_ac0f00

; FUNCTION sub_ac0f60 CONTEXT / separate function | ev_941647831fcd70e91387baaf87fe914b2f4b7aa213af9df6f298c060a338dc02
; Ghidra body: 0xac0f60..0xac10e9, 0xac10f0..0xac12c5
sub_ac0f60:
0xac0f60: PUSH RBP
0xac0f61: MOV RBP, RSP
0xac0f64: PUSH R15
0xac0f66: PUSH R14
0xac0f68: PUSH R13
0xac0f6a: PUSH R12
0xac0f6c: PUSH RBX
0xac0f6d: PUSH RAX
0xac0f6e: MOV R13, qword ptr GS:[0x0]
0xac0f77: CMP word ptr [R13 + 0x114], 0x0
0xac0f80: MOV R12D, 0x1
0xac0f86: JNZ 0x00ac10a6
0xac0f8c: MOV dword ptr [RSI + 0x20], 0x0
0xac0f93: MOV qword ptr [RSI + 0x18], R13
0xac0f97: MOV qword ptr [RSI + 0x10], RDI
0xac0f9b: MOV R14, RSI
0xac0f9e: MOV RBX, RDI
0xac0fa1: MOV dword ptr [RBP + -0x2c], EDX
0xac0fa4: TEST byte ptr [RDI + 0xa], 0x10
0xac0fa8: JZ 0x00ac0fb1
0xac0faa: INC dword ptr [R13 + 0x370]
0xac0fb1: INC dword ptr [R13 + 0x47c]
0xac0fb8: LEA RCX, [0x3538920]
0xac0fbf: MOVSXD RAX, dword ptr [R13 + 0x524]
0xac0fc6: MOV R15, qword ptr [RCX + RAX*0x8]
0xac0fca: LEA RAX, [R15 + 0x6a0]
0xac0fd1: MOV qword ptr [R14 + 0x8], RAX
0xac0fd5: MOV RAX, qword ptr [R15 + 0x6a0]
0xac0fdc: MOV qword ptr [R14], RAX
0xac0fdf: MOV qword ptr [RAX + 0x8], R14
0xac0fe3: MOV qword ptr [R15 + 0x6a0], R14
0xac0fea: MOV RAX, qword ptr GS:[0x0]
0xac0ff3: INC word ptr [RAX + 0x10e]
0xac0ffa: MOV RAX, qword ptr GS:[0x0]
0xac1003: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0xac100b: CALL 0x006b7940
0xac1010: DEC dword ptr [R13 + 0x47c]
0xac1017: MOVZX EAX, byte ptr [R13 + 0x108]
0xac101f: MOV RCX, qword ptr [RBX + 0x18]
0xac1023: MOVZX EDX, byte ptr [R15 + 0x34]
0xac1028: SHRX RCX, RCX, RDX
0xac102d: OR ECX, EAX
0xac102f: TEST CL, 0x1
0xac1032: JZ 0x00ac10a6
0xac1034: CALL 0x006a2630
0xac1039: MOV EDI, dword ptr GS:[0x34]
0xac1041: CALL 0x004c8230
0xac1046: MOV R12, RAX
0xac1049: MOV RAX, qword ptr [RBX + 0x18]
0xac104d: MOV ECX, dword ptr [R12 + 0x34]
0xac1052: BT RAX, RCX
0xac1056: JNC 0x00ac109b
0xac1058: MOV RDI, R14
0xac105b: CALL 0x00ac12d0
0xac1060: CMP dword ptr [R14 + 0x20], 0x0
0xac1065: JZ 0x00ac10b8
0xac1067: MOV RAX, R12
0xac106a: ADD RAX, 0x6a0
0xac1070: MOV qword ptr [R14 + 0x8], RAX
0xac1074: MOV RAX, qword ptr [R12 + 0x6a0]
0xac107c: MOV qword ptr [R14], RAX
0xac107f: MOV qword ptr [RAX + 0x8], R14
0xac1083: MOV qword ptr [R12 + 0x6a0], R14
0xac108b: MOV RAX, qword ptr GS:[0x0]
0xac1094: INC word ptr [RAX + 0x10e]
0xac109b: CALL 0x006a2650
0xac10a0: MOV R12D, 0x1
0xac10a6: MOV EAX, R12D
0xac10a9: ADD RSP, 0x8
0xac10ad: POP RBX
0xac10ae: POP R12
0xac10b0: POP R13
0xac10b2: POP R14
0xac10b4: POP R15
0xac10b6: POP RBP
0xac10b7: RET
0xac10b8: TEST byte ptr [RBX + 0xa], 0x8
0xac10bc: JZ 0x00ac117d
0xac10c2: MOV RAX, qword ptr GS:[0x0]
0xac10cb: MOV RCX, qword ptr [R12 + 0x6a0]
0xac10d3: MOV R13, R12
0xac10d6: ADD R13, 0x6a0
0xac10dd: CMP RCX, R13
0xac10e0: JZ 0x00ac117d
0xac10e6: XOR EDX, EDX
0xac10e8: JMP 0x00ac10f8
0xac10f0: MOV RCX, qword ptr [RCX]
0xac10f3: CMP RCX, R13
0xac10f6: JZ 0x00ac110c
0xac10f8: CMP qword ptr [RCX + 0x10], RBX
0xac10fc: JNZ 0x00ac10f0
0xac10fe: XOR ESI, ESI
0xac1100: CMP qword ptr [RCX + 0x18], RAX
0xac1104: SETZ SIL
0xac1108: ADD EDX, ESI
0xac110a: JMP 0x00ac10f0
0xac110c: TEST EDX, EDX
0xac110e: JZ 0x00ac117d
0xac1110: LEA RDI, [0x3bf6e80]
0xac1117: XOR ESI, ESI
0xac1119: XOR EDX, EDX
0xac111b: XOR ECX, ECX
0xac111d: CALL 0x004c7190
0xac1122: MOV RAX, qword ptr [RBX + 0x20]
0xac1126: ADD RBX, 0x20
0xac112a: MOV qword ptr [R14 + 0x28], RAX
0xac112e: TEST RAX, RAX
0xac1131: JZ 0x00ac113b
0xac1133: LEA RCX, [R14 + 0x28]
0xac1137: MOV qword ptr [RAX + 0x30], RCX
0xac113b: LEA RDI, [0x3bf6e80]
0xac1142: MOV qword ptr [RBX], R14
0xac1145: MOV qword ptr [R14 + 0x30], RBX
0xac1149: MOV dword ptr [R14 + 0x20], 0x1
0xac1151: XOR ESI, ESI
0xac1153: XOR EDX, EDX
0xac1155: XOR ECX, ECX
0xac1157: CALL 0x004c7520
0xac115c: MOV qword ptr [R14 + 0x8], R13
0xac1160: MOV RAX, qword ptr [R13]
0xac1164: MOV qword ptr [R14], RAX
0xac1167: MOV qword ptr [RAX + 0x8], R14
0xac116b: MOV qword ptr [R13], R14
0xac116f: MOV RAX, qword ptr GS:[0x0]
0xac1178: JMP 0x00ac1094
0xac117d: CALL 0x006b7960
0xac1182: MOV RAX, qword ptr GS:[0x0]
0xac118b: MOV ECX, 0xffffffff
0xac1190: XADD.LOCK dword ptr [RAX + 0x5a8], ECX
0xac1198: CMP ECX, 0x80000001
0xac119e: JNZ 0x00ac11a5
0xac11a0: CALL 0x006b7af0
0xac11a5: CALL 0x006a2650
0xac11aa: CMP dword ptr [RBP + -0x2c], 0x0
0xac11ae: MOV EAX, dword ptr [RBX + 0x8]
0xac11b1: JZ 0x00ac11ce
0xac11b3: TEST EAX, 0x100000
0xac11b8: JNZ 0x00ac11e6
0xac11ba: LEA RDI, [RBX + 0x40]
0xac11be: XOR R12D, R12D
0xac11c1: XOR ESI, ESI
0xac11c3: XOR EDX, EDX
0xac11c5: XOR ECX, ECX
0xac11c7: CALL 0x004c76a0
0xac11cc: JMP 0x00ac11f6
0xac11ce: TEST EAX, 0x100000
0xac11d3: JNZ 0x00ac11ff
0xac11d5: LEA RDI, [RBX + 0x40]
0xac11d9: XOR ESI, ESI
0xac11db: XOR EDX, EDX
0xac11dd: XOR ECX, ECX
0xac11df: CALL 0x004c6a00
0xac11e4: JMP 0x00ac1225
0xac11e6: LEA RDI, [RBX + 0x28]
0xac11ea: XOR R12D, R12D
0xac11ed: XOR ESI, ESI
0xac11ef: XOR EDX, EDX
0xac11f1: CALL 0x00c4c210
0xac11f6: TEST EAX, EAX
0xac11f8: JNZ 0x00ac1225
0xac11fa: JMP 0x00ac10a6
0xac11ff: MOV R15, qword ptr GS:[0x0]
0xac1208: DEC dword ptr [R15 + 0x370]
0xac120f: LEA RDI, [RBX + 0x28]
0xac1213: XOR ESI, ESI
0xac1215: XOR EDX, EDX
0xac1217: XOR ECX, ECX
0xac1219: CALL 0x00c4bb20
0xac121e: INC dword ptr [R15 + 0x370]
0xac1225: CALL 0x006a2630
0xac122a: MOV EDI, dword ptr GS:[0x34]
0xac1232: CALL 0x004c8230
0xac1237: MOVZX ECX, byte ptr [RAX + 0x34]
0xac123b: MOV RDX, -0x2
0xac1242: ROL RDX, CL
0xac1245: AND qword ptr [RBX + 0x18], RDX
0xac1249: LEA RDX, [RAX + 0x6a0]
0xac1250: MOV qword ptr [R14 + 0x8], RDX
0xac1254: MOV RCX, qword ptr [RAX + 0x6a0]
0xac125b: MOV qword ptr [R14], RCX
0xac125e: MOV qword ptr [RCX + 0x8], R14
0xac1262: MOV qword ptr [RAX + 0x6a0], R14
0xac1269: MOV RAX, qword ptr GS:[0x0]
0xac1272: INC word ptr [RAX + 0x10e]
0xac1279: MOV RAX, qword ptr GS:[0x0]
0xac1282: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0xac128a: CALL 0x006b7940
0xac128f: CALL 0x006a2650
0xac1294: TEST byte ptr [RBX + 0xa], 0x10
0xac1298: JNZ 0x00ac12b1
0xac129a: ADD RBX, 0x40
0xac129e: XOR ESI, ESI
0xac12a0: XOR EDX, EDX
0xac12a2: XOR ECX, ECX
0xac12a4: MOV RDI, RBX
0xac12a7: CALL 0x004c6fa0
0xac12ac: JMP 0x00ac10a0
0xac12b1: ADD RBX, 0x28
0xac12b5: XOR ESI, ESI
0xac12b7: XOR EDX, EDX
0xac12b9: MOV RDI, RBX
0xac12bc: CALL 0x00c4c4b0
0xac12c1: JMP 0x00ac10a0
; END FUNCTION sub_ac0f60

; FUNCTION FUN_00ac12d0 CONTEXT / separate function | ev_638e08421bcde18ecb3ba6b2b6a6416ce37525755c3e79166d7a5662fe30fe80
; Ghidra body: 0xac12d0..0xac1327
FUN_00ac12d0:
0xac12d0: MOV RAX, qword ptr [RDI]
0xac12d3: MOV RCX, qword ptr [RDI + 0x8]
0xac12d7: MOV qword ptr [RAX + 0x8], RCX
0xac12db: MOV qword ptr [RCX], RAX
0xac12de: MOV RDI, qword ptr GS:[0x0]
0xac12e7: MOVZX EAX, word ptr [RDI + 0x10e]
0xac12ee: MOV ECX, EAX
0xac12f0: DEC CX
0xac12f3: MOV word ptr [RDI + 0x10e], CX
0xac12fa: JS 0x00ac1328
0xac12fc: TEST byte ptr [RDI + 0x108], 0x4
0xac1303: JZ 0x00ac1327
0xac1305: MOVSX ECX, word ptr [RDI + 0x10a]
0xac130c: MOVSX EDX, word ptr [RDI + 0x10c]
0xac1313: ADD EDX, ECX
0xac1315: MOV ECX, 0x1
0xac131a: SUB ECX, EAX
0xac131c: MOVSX EAX, CX
0xac131f: CMP EDX, EAX
0xac1321: JZ 0x006b6cf0
0xac1327: RET
; END FUNCTION FUN_00ac12d0

; FUNCTION sub_ac1328 CONTEXT / separate function | ev_a9e07b859718a71e1c7f607a2ff910d5d0c6a21b5fba6d82c936f9cd26bcb16a
; Ghidra body: 0xac1328..0xac1374
sub_ac1328:
0xac1328: PUSH RBP
0xac1329: MOV RBP, RSP
0xac132c: PUSH R14
0xac132e: PUSH RBX
0xac132f: MOV R14, RDI
0xac1332: CALL 0x007f1950
0xac1337: MOVSX RDX, word ptr [R14 + 0x10e]
0xac133f: LEA RBX, [0x132d45a]
0xac1346: LEA RDI, [0xac1328]
0xac134d: MOV RSI, RBX
0xac1350: CALL 0x007f2010
0xac1355: MOVSX ECX, word ptr [R14 + 0x10e]
0xac135d: LEA RSI, [0x130e06a]
0xac1364: MOV EDI, 0x3
0xac1369: MOV RDX, RBX
0xac136c: XOR EAX, EAX
0xac136e: CALL 0x00c9aa10
0xac1373: UD2
; END FUNCTION sub_ac1328

; FUNCTION sub_ac1380 CONTEXT / separate function | ev_f2423811d10deb2def4ef5858d8262b46b71ef7a8230325822886e5b100597d2
; Ghidra body: 0xac1380..0xac14db
sub_ac1380:
0xac1380: PUSH RBP
0xac1381: MOV RBP, RSP
0xac1384: PUSH R14
0xac1386: PUSH RBX
0xac1387: TEST byte ptr [RDI + 0x108], 0x1
0xac138e: MOV RBX, RSI
0xac1391: JZ 0x00ac139e
0xac1393: INC dword ptr [RDI + 0x47c]
0xac1399: CALL 0x006a2650
0xac139e: CMP dword ptr [RBX + 0x20], 0x0
0xac13a2: JZ 0x00ac13e8
0xac13a4: LEA RDI, [0x3bf6e80]
0xac13ab: XOR ESI, ESI
0xac13ad: XOR EDX, EDX
0xac13af: XOR ECX, ECX
0xac13b1: CALL 0x004c7190
0xac13b6: MOV RAX, qword ptr [RBX + 0x28]
0xac13ba: TEST RAX, RAX
0xac13bd: JZ 0x00ac13ed
0xac13bf: LEA R14, [RBX + 0x28]
0xac13c3: CMP qword ptr [RAX + 0x30], R14
0xac13c7: JNZ 0x00ac149a
0xac13cd: MOV RCX, qword ptr [RBX + 0x30]
0xac13d1: CMP qword ptr [RCX], RBX
0xac13d4: JNZ 0x00ac1460
0xac13da: MOV qword ptr [RAX + 0x30], RCX
0xac13de: MOV RCX, qword ptr [RBX + 0x28]
0xac13e2: MOV RAX, qword ptr [RBX + 0x30]
0xac13e6: JMP 0x00ac13f8
0xac13e8: POP RBX
0xac13e9: POP R14
0xac13eb: POP RBP
0xac13ec: RET
0xac13ed: MOV RAX, qword ptr [RBX + 0x30]
0xac13f1: CMP qword ptr [RAX], RBX
0xac13f4: JNZ 0x00ac1460
0xac13f6: XOR ECX, ECX
0xac13f8: MOV qword ptr [RAX], RCX
0xac13fb: TEST byte ptr [RBX + 0x20], 0x2
0xac13ff: JNZ 0x00ac1417
0xac1401: LEA RDI, [0x3bf6e80]
0xac1408: XOR ESI, ESI
0xac140a: XOR EDX, EDX
0xac140c: XOR ECX, ECX
0xac140e: POP RBX
0xac140f: POP R14
0xac1411: POP RBP
0xac1412: JMP 0x004c7520
0xac1417: MOV RBX, qword ptr [RBX + 0x10]
0xac141b: MOV RDI, RBX
0xac141e: CALL 0x0042d560
0xac1423: LEA RDI, [0x3bf6e80]
0xac142a: XOR ESI, ESI
0xac142c: XOR EDX, EDX
0xac142e: XOR ECX, ECX
0xac1430: CALL 0x004c7520
0xac1435: MOV RDI, RBX
0xac1438: CALL 0x0042d680
0xac143d: MOV RDI, RAX
0xac1440: XOR ESI, ESI
0xac1442: MOV R14, RAX
0xac1445: CALL 0x0042db50
0xac144a: MOV RDI, R14
0xac144d: XOR ESI, ESI
0xac144f: CALL 0x0042deb0
0xac1454: MOV RDI, RBX
0xac1457: POP RBX
0xac1458: POP R14
0xac145a: POP RBP
0xac145b: JMP 0x0042d6f0
0xac1460: CALL 0x007f1950
0xac1465: MOV RDX, qword ptr [RBX + 0x30]
0xac1469: LEA RDI, [0xac1460]
0xac1470: MOV RSI, RBX
0xac1473: MOV RCX, qword ptr [RDX]
0xac1476: CALL 0x007f20c0
0xac147b: MOV RCX, qword ptr [RBX + 0x30]
0xac147f: LEA RSI, [0x12da4df]
0xac1486: MOV EDI, 0xb
0xac148b: MOV RDX, RBX
0xac148e: XOR EAX, EAX
0xac1490: MOV R8, qword ptr [RCX]
0xac1493: CALL 0x00c9aa10
0xac1498: UD2
0xac149a: CALL 0x007f1950
0xac149f: MOV RDX, qword ptr [RBX + 0x28]
0xac14a3: LEA RDI, [0xac149a]
0xac14aa: MOV RSI, RBX
0xac14ad: MOV R8, R14
0xac14b0: MOV RCX, qword ptr [RDX + 0x30]
0xac14b4: CALL 0x007f2180
0xac14b9: MOV RCX, qword ptr [RBX + 0x28]
0xac14bd: LEA RSI, [0x130e07f]
0xac14c4: MOV EDI, 0x7
0xac14c9: MOV RDX, RBX
0xac14cc: MOV R9, R14
0xac14cf: XOR EAX, EAX
0xac14d1: MOV R8, qword ptr [RCX + 0x30]
0xac14d5: CALL 0x00c9aa10
0xac14da: UD2
; END FUNCTION sub_ac1380

; FUNCTION sub_ac14e0 CONTEXT / separate function | ev_88a051db72d73b0dc46f29b61cfb59e14331e08e30a2ccce2751eac50d77142c
; Ghidra body: 0xac14e0..0xac15f1
sub_ac14e0:
0xac14e0: PUSH RBP
0xac14e1: MOV RBP, RSP
0xac14e4: PUSH R15
0xac14e6: PUSH R14
0xac14e8: PUSH R12
0xac14ea: PUSH RBX
0xac14eb: MOV RAX, qword ptr GS:[0x0]
0xac14f4: CMP word ptr [RAX + 0x114], 0x0
0xac14fc: JNZ 0x00ac1534
0xac14fe: TEST byte ptr [RDI + 0xa], 0x10
0xac1502: MOV RBX, RDI
0xac1505: JNZ 0x00ac1518
0xac1507: LEA RDI, [RBX + 0x40]
0xac150b: XOR ESI, ESI
0xac150d: XOR EDX, EDX
0xac150f: XOR ECX, ECX
0xac1511: CALL 0x004c6a00
0xac1516: JMP 0x00ac1527
0xac1518: LEA RDI, [RBX + 0x28]
0xac151c: XOR ESI, ESI
0xac151e: XOR EDX, EDX
0xac1520: XOR ECX, ECX
0xac1522: CALL 0x00c4bb20
0xac1527: MOV RAX, qword ptr [0x03d0e8e8]
0xac152e: CMP RAX, qword ptr [RBX + 0x18]
0xac1532: JNZ 0x00ac153d
0xac1534: POP RBX
0xac1535: POP R12
0xac1537: POP R14
0xac1539: POP R15
0xac153b: POP RBP
0xac153c: RET
0xac153d: MOV RDX, qword ptr [RBX + 0x18]
0xac1541: LEA RCX, [RBX + 0x18]
0xac1545: MOV R8, RBX
0xac1548: ANDN RDI, RDX, RAX
0xac154d: MOV RDX, qword ptr [0x03d0e8e8]
0xac1554: MOV qword ptr [RCX], RDX
0xac1557: LEA RCX, [0x261e08]
0xac155e: LEA RDX, [0x264840]
0xac1565: MOV RSI, RCX
0xac1568: CALL 0x00b03970
0xac156d: LEA RDI, [0x3bf6e80]
0xac1574: XOR ESI, ESI
0xac1576: XOR EDX, EDX
0xac1578: XOR ECX, ECX
0xac157a: CALL 0x004c7190
0xac157f: MOV R12, qword ptr [RBX + 0x20]
0xac1583: TEST R12, R12
0xac1586: JZ 0x00ac15d8
0xac1588: LEA R14, [0x3bf6e80]
0xac158f: NOP
0xac1590: MOV RDI, RBX
0xac1593: CALL 0x0042d590
0xac1598: MOV RDI, R14
0xac159b: MOV R15, RAX
0xac159e: MOV dword ptr [R12 + 0x20], 0x3
0xac15a7: XOR ESI, ESI
0xac15a9: XOR EDX, EDX
0xac15ab: XOR ECX, ECX
0xac15ad: CALL 0x004c7520
0xac15b2: MOV RSI, qword ptr [R12 + 0x18]
0xac15b7: MOV RDI, R15
0xac15ba: XOR EDX, EDX
0xac15bc: CALL 0x0042d840
0xac15c1: MOV RDI, R14
0xac15c4: XOR ESI, ESI
0xac15c6: XOR EDX, EDX
0xac15c8: XOR ECX, ECX
0xac15ca: CALL 0x004c7190
0xac15cf: MOV R12, qword ptr [RBX + 0x20]
0xac15d3: TEST R12, R12
0xac15d6: JNZ 0x00ac1590
0xac15d8: LEA RDI, [0x3bf6e80]
0xac15df: XOR ESI, ESI
0xac15e1: XOR EDX, EDX
0xac15e3: XOR ECX, ECX
0xac15e5: POP RBX
0xac15e6: POP R12
0xac15e8: POP R14
0xac15ea: POP R15
0xac15ec: POP RBP
0xac15ed: JMP 0x004c7520
; END FUNCTION sub_ac14e0

; FUNCTION sub_ac1600 CONTEXT / separate function | ev_61be6079fecfc2cda574be07fa26c58f3a800c2797db91adfc918dad1e7dc3d3
; Ghidra body: 0xac1600..0xac16b6
sub_ac1600:
0xac1600: PUSH RBP
0xac1601: MOV RBP, RSP
0xac1604: PUSH R15
0xac1606: PUSH R14
0xac1608: PUSH R13
0xac160a: PUSH R12
0xac160c: PUSH RBX
0xac160d: PUSH RAX
0xac160e: MOV RBX, RDI
0xac1611: MOV EDI, dword ptr GS:[0x34]
0xac1619: CALL 0x004c8230
0xac161e: MOV R12, qword ptr [RAX + 0x6a0]
0xac1625: MOV R14, RAX
0xac1628: ADD R14, 0x6a0
0xac162f: CMP R12, R14
0xac1632: JZ 0x00ac16a8
0xac1634: LEA R13, [RBX + 0x20]
0xac1638: LEA R15, [0x3bf6e80]
0xac163f: JMP 0x00ac1669
0xac1641: MOV RDI, R15
0xac1644: MOV qword ptr [R13], R12
0xac1648: MOV qword ptr [R12 + 0x30], R13
0xac164d: XOR ESI, ESI
0xac164f: XOR EDX, EDX
0xac1651: XOR ECX, ECX
0xac1653: CALL 0x004c7520
0xac1658: NOP dword ptr [RAX + RAX*0x1]
0xac1660: MOV R12, qword ptr [R12]
0xac1664: CMP R12, R14
0xac1667: JZ 0x00ac16a8
0xac1669: CMP qword ptr [R12 + 0x10], RBX
0xac166e: JNZ 0x00ac1660
0xac1670: CMP dword ptr [R12 + 0x20], 0x0
0xac1676: JNZ 0x00ac1660
0xac1678: MOV RDI, R15
0xac167b: MOV dword ptr [R12 + 0x20], 0x1
0xac1684: XOR ESI, ESI
0xac1686: XOR EDX, EDX
0xac1688: XOR ECX, ECX
0xac168a: CALL 0x004c7190
0xac168f: MOV RAX, qword ptr [R13]
0xac1693: MOV qword ptr [R12 + 0x28], RAX
0xac1698: TEST RAX, RAX
0xac169b: JZ 0x00ac1641
0xac169d: LEA RCX, [R12 + 0x28]
0xac16a2: MOV qword ptr [RAX + 0x30], RCX
0xac16a6: JMP 0x00ac1641
0xac16a8: ADD RSP, 0x8
0xac16ac: POP RBX
0xac16ad: POP R12
0xac16af: POP R13
0xac16b1: POP R14
0xac16b3: POP R15
0xac16b5: POP RBP
0xac16b6: RET
; END FUNCTION sub_ac1600

; FUNCTION sub_ac16c0 CONTEXT / separate function | ev_3246e6e7b2572d7eafb76039907710d6527bdc4ea0e622f7d9b6e5e6d81d77b7
; Ghidra body: 0xac16c0..0xac16f5
sub_ac16c0:
0xac16c0: PUSH RBP
0xac16c1: MOV RBP, RSP
0xac16c4: PUSH R14
0xac16c6: PUSH RBX
0xac16c7: MOV R14, qword ptr GS:[0x0]
0xac16d0: CMP word ptr [R14 + 0x114], 0x0
0xac16d9: JNZ 0x00ac16f1
0xac16db: MOV RBX, RDI
0xac16de: CALL 0x00ac14e0
0xac16e3: TEST byte ptr [RBX + 0xa], 0x10
0xac16e7: JNZ 0x00ac16f1
0xac16e9: INC word ptr [R14 + 0x10a]
0xac16f1: POP RBX
0xac16f2: POP R14
0xac16f4: POP RBP
0xac16f5: RET
; END FUNCTION sub_ac16c0

; FUNCTION sub_ac1700 CONTEXT / separate function | ev_5639547d0cf2abcb2d026b8c71352915e6911df8fc7fc3384513acec7d3f56f4
; Ghidra body: 0xac1700..0xac1812
sub_ac1700:
0xac1700: PUSH RBP
0xac1701: MOV RBP, RSP
0xac1704: PUSH R14
0xac1706: PUSH RBX
0xac1707: MOV RBX, qword ptr GS:[0x0]
0xac1710: CMP word ptr [RBX + 0x114], 0x0
0xac1718: JNZ 0x00ac1794
0xac171a: TEST byte ptr [RDI + 0xa], 0x10
0xac171e: MOV R14, RDI
0xac1721: JNZ 0x00ac173b
0xac1723: LEA RDI, [R14 + 0x40]
0xac1727: XOR ESI, ESI
0xac1729: XOR EDX, EDX
0xac172b: XOR ECX, ECX
0xac172d: CALL 0x004c6fa0
0xac1732: TEST byte ptr [R14 + 0xa], 0x10
0xac1737: JZ 0x00ac174f
0xac1739: JMP 0x00ac178a
0xac173b: LEA RDI, [R14 + 0x28]
0xac173f: XOR ESI, ESI
0xac1741: XOR EDX, EDX
0xac1743: CALL 0x00c4c4b0
0xac1748: TEST byte ptr [R14 + 0xa], 0x10
0xac174d: JNZ 0x00ac178a
0xac174f: MOVZX EAX, word ptr [RBX + 0x10a]
0xac1756: DEC EAX
0xac1758: MOV word ptr [RBX + 0x10a], AX
0xac175f: TEST AX, AX
0xac1762: JS 0x00ac17d1
0xac1764: TEST byte ptr [RBX + 0x108], 0x4
0xac176b: JZ 0x00ac178a
0xac176d: MOVSX ECX, word ptr [RBX + 0x10c]
0xac1774: MOVSX EDX, word ptr [RBX + 0x10e]
0xac177b: CWDE
0xac177c: ADD ECX, EAX
0xac177e: ADD EDX, ECX
0xac1780: JNZ 0x00ac178a
0xac1782: MOV RDI, RBX
0xac1785: CALL 0x006b6cf0
0xac178a: CMP word ptr [RBX + 0x10a], 0x0
0xac1792: JS 0x00ac1799
0xac1794: POP RBX
0xac1795: POP R14
0xac1797: POP RBP
0xac1798: RET
0xac1799: CALL 0x007f1950
0xac179e: MOVSX RDX, word ptr [RBX + 0x10a]
0xac17a6: LEA R14, [0x1337721]
0xac17ad: LEA RDI, [0xac1799]
0xac17b4: MOV RSI, R14
0xac17b7: CALL 0x007f2010
0xac17bc: MOVSX ECX, word ptr [RBX + 0x10a]
0xac17c3: LEA RSI, [0x134661a]
0xac17ca: MOV EDI, 0x13
0xac17cf: JMP 0x00ac1807
0xac17d1: CALL 0x007f1950
0xac17d6: MOVSX RDX, word ptr [RBX + 0x10a]
0xac17de: LEA R14, [0x1337721]
0xac17e5: LEA RDI, [0xac17d1]
0xac17ec: MOV RSI, R14
0xac17ef: CALL 0x007f2010
0xac17f4: MOVSX ECX, word ptr [RBX + 0x10a]
0xac17fb: LEA RSI, [0x134661a]
0xac1802: MOV EDI, 0xf
0xac1807: MOV RDX, R14
0xac180a: XOR EAX, EAX
0xac180c: CALL 0x00c9aa10
0xac1811: UD2
; END FUNCTION sub_ac1700

; FUNCTION sub_ac1820 CONTEXT / separate function | ev_593c2a44869b0e2856682997dcff42eb2ad17fcc102bb67cdd191a154b637fe9
; Ghidra body: 0xac1820..0xac186e
sub_ac1820:
0xac1820: PUSH RBP
0xac1821: MOV RBP, RSP
0xac1824: PUSH R15
0xac1826: PUSH R14
0xac1828: PUSH RBX
0xac1829: PUSH RAX
0xac182a: MOV R15, qword ptr GS:[0x0]
0xac1833: CMP word ptr [R15 + 0x114], 0x0
0xac183c: MOV EBX, 0x1
0xac1841: JNZ 0x00ac1862
0xac1843: MOV R14, RDI
0xac1846: CALL 0x00ac0f60
0xac184b: TEST EAX, EAX
0xac184d: JZ 0x00ac1860
0xac184f: TEST byte ptr [R14 + 0xa], 0x10
0xac1854: JNZ 0x00ac1862
0xac1856: INC word ptr [R15 + 0x10a]
0xac185e: JMP 0x00ac1862
0xac1860: XOR EBX, EBX
0xac1862: MOV EAX, EBX
0xac1864: ADD RSP, 0x8
0xac1868: POP RBX
0xac1869: POP R14
0xac186b: POP R15
0xac186d: POP RBP
0xac186e: RET
; END FUNCTION sub_ac1820

; FUNCTION sub_ac1870 CONTEXT / separate function | ev_ab68bdcbcb10aeeaf1a5d166ecf573f5e09cdb68e452eef421eeeb0aaf2fdd0b
; Ghidra body: 0xac1870..0xac19d4
sub_ac1870:
0xac1870: PUSH RBP
0xac1871: MOV RBP, RSP
0xac1874: PUSH R15
0xac1876: PUSH R14
0xac1878: PUSH R12
0xac187a: PUSH RBX
0xac187b: MOV RBX, qword ptr GS:[0x0]
0xac1884: CMP word ptr [RBX + 0x114], 0x0
0xac188c: JNZ 0x00ac1952
0xac1892: MOV R12, qword ptr [RSI + 0x18]
0xac1896: MOV R14, RDI
0xac1899: MOV RDI, RSI
0xac189c: MOV R15, RSI
0xac189f: INC dword ptr [R12 + 0x47c]
0xac18a7: CALL 0x00ac12d0
0xac18ac: DEC dword ptr [R12 + 0x47c]
0xac18b4: CALL 0x006b7960
0xac18b9: MOV RAX, qword ptr GS:[0x0]
0xac18c2: MOV ECX, 0xffffffff
0xac18c7: XADD.LOCK dword ptr [RAX + 0x5a8], ECX
0xac18cf: CMP ECX, 0x80000001
0xac18d5: JNZ 0x00ac18dc
0xac18d7: CALL 0x006b7af0
0xac18dc: TEST byte ptr [R14 + 0xa], 0x10
0xac18e1: JZ 0x00ac18e9
0xac18e3: DEC dword ptr [RBX + 0x370]
0xac18e9: MOVZX EAX, byte ptr [R12 + 0x108]
0xac18f2: AND EAX, 0x1
0xac18f5: OR EAX, dword ptr [R15 + 0x20]
0xac18f9: JZ 0x00ac1906
0xac18fb: MOV RDI, R12
0xac18fe: MOV RSI, R15
0xac1901: CALL 0x00ac1380
0xac1906: TEST byte ptr [R14 + 0xa], 0x10
0xac190b: JNZ 0x00ac1948
0xac190d: MOVZX EAX, word ptr [RBX + 0x10a]
0xac1914: DEC EAX
0xac1916: MOV word ptr [RBX + 0x10a], AX
0xac191d: TEST AX, AX
0xac1920: JS 0x00ac1993
0xac1922: TEST byte ptr [RBX + 0x108], 0x4
0xac1929: JZ 0x00ac1948
0xac192b: MOVSX ECX, word ptr [RBX + 0x10c]
0xac1932: MOVSX EDX, word ptr [RBX + 0x10e]
0xac1939: CWDE
0xac193a: ADD ECX, EAX
0xac193c: ADD EDX, ECX
0xac193e: JNZ 0x00ac1948
0xac1940: MOV RDI, RBX
0xac1943: CALL 0x006b6cf0
0xac1948: CMP word ptr [RBX + 0x10a], 0x0
0xac1950: JS 0x00ac195b
0xac1952: POP RBX
0xac1953: POP R12
0xac1955: POP R14
0xac1957: POP R15
0xac1959: POP RBP
0xac195a: RET
0xac195b: CALL 0x007f1950
0xac1960: MOVSX RDX, word ptr [RBX + 0x10a]
0xac1968: LEA R14, [0x1341f58]
0xac196f: LEA RDI, [0xac195b]
0xac1976: MOV RSI, R14
0xac1979: CALL 0x007f2010
0xac197e: MOVSX ECX, word ptr [RBX + 0x10a]
0xac1985: LEA RSI, [0x134661a]
0xac198c: MOV EDI, 0x1b
0xac1991: JMP 0x00ac19c9
0xac1993: CALL 0x007f1950
0xac1998: MOVSX RDX, word ptr [RBX + 0x10a]
0xac19a0: LEA R14, [0x1341f58]
0xac19a7: LEA RDI, [0xac1993]
0xac19ae: MOV RSI, R14
0xac19b1: CALL 0x007f2010
0xac19b6: MOVSX ECX, word ptr [RBX + 0x10a]
0xac19bd: LEA RSI, [0x134661a]
0xac19c4: MOV EDI, 0x17
0xac19c9: MOV RDX, R14
0xac19cc: XOR EAX, EAX
0xac19ce: CALL 0x00c9aa10
0xac19d3: UD2
; END FUNCTION sub_ac1870

; FUNCTION sub_ac19e0 CONTEXT / separate function | ev_d27f17df768454d9f970bdcc2ea40b02a68606747a3375f09456b39b3ed6cfae
; Ghidra body: 0xac19e0..0xac19f1
sub_ac19e0:
0xac19e0: PUSH RBP
0xac19e1: MOV RBP, RSP
0xac19e4: CALL 0x00ac1a00
0xac19e9: LEA RAX, [0x3cba190]
0xac19f0: POP RBP
0xac19f1: RET
; END FUNCTION sub_ac19e0

; FUNCTION sub_ac1a00 CONTEXT / separate function | ev_e2839777497ff58943c72985ef9b0381ab21f81e9c74f26663594e603363dea9
; Ghidra body: 0xac1a00..0xac1bce
sub_ac1a00:
0xac1a00: PUSH RBP
0xac1a01: MOV RBP, RSP
0xac1a04: PUSH R15
0xac1a06: PUSH R14
0xac1a08: PUSH RBX
0xac1a09: PUSH RAX
0xac1a0a: LEA R14, [0x3cba190]
0xac1a11: MOV EBX, ESI
0xac1a13: MOV R15D, EDI
0xac1a16: MOV ESI, 0x3dc8
0xac1a1b: MOV RDI, R14
0xac1a1e: CALL 0x00258ff0
0xac1a23: MOV RAX, 0x10500003dc8
0xac1a2d: MOV RDX, 0xbc000000b4
0xac1a37: MOV RCX, 0xd800000002
0xac1a41: MOV RDI, R14
0xac1a44: MOV qword ptr [0x03cba190], RAX
0xac1a4b: MOV qword ptr [0x03cba198], RDX
0xac1a52: MOV dword ptr [0x03cba1a8], 0x13c
0xac1a5c: MOV qword ptr [0x03cba1a0], RCX
0xac1a63: MOV RDX, 0x3d2000003d10
0xac1a6d: MOV RCX, 0x3d0000000003
0xac1a77: MOV RAX, 0x368000003538
0xac1a81: MOV qword ptr [0x03cba1b4], RDX
0xac1a88: MOV qword ptr [0x03cba1ac], RCX
0xac1a8f: MOV RDX, 0x3d6000003d48
0xac1a99: MOV RCX, 0x3d9000003d78
0xac1aa3: MOV qword ptr [0x03cba1c4], RDX
0xac1aaa: MOV qword ptr [0x03cba1cc], RCX
0xac1ab1: MOV RDX, 0x3d3000000005
0xac1abb: MOV RCX, 0x1e0000001a0
0xac1ac5: MOV qword ptr [0x03cba1bc], RDX
0xac1acc: MOV qword ptr [0x03cba1d8], RCX
0xac1ad3: MOV RDX, 0x700000005b8
0xac1add: MOV RCX, 0xd8000000c88
0xac1ae7: MOV qword ptr [0x03cba1e0], RDX
0xac1aee: MOV qword ptr [0x03cba1e8], RCX
0xac1af5: MOV RDX, 0x119800000dc0
0xac1aff: MOV RCX, 0x1868000012e0
0xac1b09: MOV qword ptr [0x03cba1f0], RDX
0xac1b10: MOV qword ptr [0x03cba1f8], RCX
0xac1b17: MOV RDX, 0x19a000001960
0xac1b21: MOV RCX, 0x1ec000001d78
0xac1b2b: MOV qword ptr [0x03cba200], RDX
0xac1b32: MOV qword ptr [0x03cba208], RCX
0xac1b39: MOV RDX, 0x254000002448
0xac1b43: MOV RCX, 0x295800002580
0xac1b4d: MOV qword ptr [0x03cba210], RDX
0xac1b54: MOV qword ptr [0x03cba218], RCX
0xac1b5b: MOV RDX, 0x302800002aa0
0xac1b65: MOV RCX, 0x316000003120
0xac1b6f: MOV qword ptr [0x03cba220], RDX
0xac1b76: MOV qword ptr [0x03cba228], RCX
0xac1b7d: MOV qword ptr [0x03cba230], RAX
0xac1b84: MOV dword ptr [0x03cba238], 0x3c08
0xac1b8e: MOV dword ptr [0x03cba1d4], 0x5
0xac1b98: CALL 0x0027f080
0xac1b9d: LEA RDI, [0x3cba24c]
0xac1ba4: MOV dword ptr [0x03cba24c], 0x1c
0xac1bae: CALL 0x009a0640
0xac1bb3: MOV EDI, R15D
0xac1bb6: MOV ESI, EBX
0xac1bb8: CALL 0x00ac1cd0
0xac1bbd: MOV RDI, R14
0xac1bc0: ADD RSP, 0x8
0xac1bc4: POP RBX
0xac1bc5: POP R14
0xac1bc7: POP R15
0xac1bc9: POP RBP
0xac1bca: JMP 0x004ff760
; END FUNCTION sub_ac1a00

; FUNCTION sub_ac1bd0 CONTEXT / separate function | ev_65383cdee2d6a9ee0d703683d5b82b420109c1b99a053ef1b2c806f9103dc74c
; Ghidra body: 0xac1bd0..0xac1ccd
sub_ac1bd0:
0xac1bd0: PUSH RBP
0xac1bd1: MOV RBP, RSP
0xac1bd4: PUSH R15
0xac1bd6: PUSH R14
0xac1bd8: PUSH RBX
0xac1bd9: SUB RSP, 0x28
0xac1bdd: LEA R15, [0x391c310]
0xac1be4: LEA RSI, [RBP + -0x28]
0xac1be8: LEA RDX, [RBP + -0x30]
0xac1bec: LEA RCX, [RBP + -0x38]
0xac1bf0: LEA R8, [RBP + -0x40]
0xac1bf4: MOV EBX, EDI
0xac1bf6: MOV RAX, qword ptr [R15]
0xac1bf9: MOV qword ptr [RBP + -0x20], RAX
0xac1bfd: CALL 0x00c9fe80
0xac1c02: TEST EAX, EAX
0xac1c04: JNZ 0x00ac1cb3
0xac1c0a: CMP qword ptr [RBP + -0x30], 0xc9248
0xac1c12: JC 0x00ac1cb3
0xac1c18: MOV EDI, 0x18
0xac1c1d: MOV ESI, 0xb2
0xac1c22: CALL 0x00b7b1e0
0xac1c27: MOV EDI, EBX
0xac1c29: MOV ESI, 0xffffffff
0xac1c2e: CALL 0x00ac1a00
0xac1c33: MOV EDI, 0x18
0xac1c38: MOV ESI, 0xb6
0xac1c3d: CALL 0x00b7b1c0
0xac1c42: LEA R14, [0x3bf6e88]
0xac1c49: MOV ESI, 0x4
0xac1c4e: MOV RDI, R14
0xac1c51: CALL 0x00258ff0
0xac1c56: MOV RSI, qword ptr [RBP + -0x28]
0xac1c5a: MOV EDI, EBX
0xac1c5c: MOV RDX, R14
0xac1c5f: MOV ECX, 0x4
0xac1c64: MOV dword ptr [0x03bf6e88], 0x11d
0xac1c6e: CALL 0x007a90f0
0xac1c73: TEST EAX, EAX
0xac1c75: JZ 0x00ac1c97
0xac1c77: MOV EDI, 0x18
0xac1c7c: MOV ESI, 0xc1
0xac1c81: CALL 0x00b7b1e0
0xac1c86: MOV EDI, 0x18
0xac1c8b: MOV ESI, 0xc2
0xac1c90: CALL 0x00b7b1c0
0xac1c95: JMP 0x00ac1cb3
0xac1c97: MOV ESI, 0xc3308
0xac1c9c: ADD RSI, qword ptr [RBP + -0x28]
0xac1ca0: LEA RDX, [0x3cba190]
0xac1ca7: MOV EDI, EBX
0xac1ca9: MOV ECX, 0x3dc8
0xac1cae: CALL 0x007a90f0
0xac1cb3: MOV RAX, qword ptr [R15]
0xac1cb6: CMP RAX, qword ptr [RBP + -0x20]
0xac1cba: JNZ 0x00ac1cc7
0xac1cbc: ADD RSP, 0x28
0xac1cc0: POP RBX
0xac1cc1: POP R14
0xac1cc3: POP R15
0xac1cc5: POP RBP
0xac1cc6: RET
0xac1cc7: CALL 0x006fd6b0
0xac1ccc: UD2
; END FUNCTION sub_ac1bd0

; FUNCTION sub_ac1cd0 CONTEXT / separate function | ev_1629a90a98102909f6834c26f57dc3a0c1a72268d52b9127a686bf0533a09e65
; Ghidra body: 0xac1cd0..0xac1d0e, 0xac1d10..0xac1e69
sub_ac1cd0:
0xac1cd0: PUSH RBP
0xac1cd1: MOV RBP, RSP
0xac1cd4: PUSH R15
0xac1cd6: PUSH R14
0xac1cd8: PUSH R13
0xac1cda: PUSH R12
0xac1cdc: PUSH RBX
0xac1cdd: SUB RSP, 0x18
0xac1ce1: MOV EBX, ESI
0xac1ce3: CALL 0x008647c0
0xac1ce8: MOV qword ptr [RBP + -0x38], RAX
0xac1cec: TEST RAX, RAX
0xac1cef: JZ 0x00ac1de8
0xac1cf5: XOR EAX, EAX
0xac1cf7: TEST EBX, EBX
0xac1cf9: MOV ECX, 0x6
0xac1cfe: CMOVNS ECX, EBX
0xac1d01: CMOVLE EBX, EAX
0xac1d04: XOR R15D, R15D
0xac1d07: XOR R12D, R12D
0xac1d0a: MOV dword ptr [RBP + -0x2c], ECX
0xac1d0d: JMP 0x00ac1d5c
0xac1d10: MOVSXD RAX, R15D
0xac1d13: LEA RCX, [0x3bf6e88]
0xac1d1a: MOV RDI, R14
0xac1d1d: MOV EDX, R12D
0xac1d20: LEA R13D, [R12 + 0x1]
0xac1d25: IMUL RAX, RAX, 0xbe0
0xac1d2c: LEA RSI, [RAX + RCX*0x1 + 0xc34a8]
0xac1d34: CALL 0x004ddb00
0xac1d39: MOV RDI, R14
0xac1d3c: MOV ESI, 0x18
0xac1d41: MOV EDX, 0x60
0xac1d46: CALL 0x004da8d0
0xac1d4b: INC R15D
0xac1d4e: MOV R12D, R13D
0xac1d51: INC EBX
0xac1d53: CMP EBX, dword ptr [RBP + -0x2c]
0xac1d56: JG 0x00ac1de8
0xac1d5c: MOV RDI, qword ptr [RBP + -0x38]
0xac1d60: MOV ESI, EBX
0xac1d62: MOV EDX, 0x2
0xac1d67: MOV ECX, 0x18
0xac1d6c: MOV R8D, 0x53
0xac1d72: CALL 0x004d8060
0xac1d77: TEST RAX, RAX
0xac1d7a: JZ 0x00ac1d51
0xac1d7c: MOV RDI, RAX
0xac1d7f: MOV R14, RAX
0xac1d82: CALL 0x004d7ed0
0xac1d87: MOV R13D, EAX
0xac1d8a: TEST EAX, EAX
0xac1d8c: JS 0x00ac1df7
0xac1d8e: CMP R15D, 0x5
0xac1d92: JL 0x00ac1d10
0xac1d98: MOV RAX, qword ptr GS:[0x0]
0xac1da1: MOV RAX, qword ptr [RAX + 0x8]
0xac1da5: LEA RDX, [0x18dc3f0]
0xac1dac: LEA RCX, [0x12ba7b7]
0xac1db3: MOV R8D, 0x5a
0xac1db9: XOR EDI, EDI
0xac1dbb: XOR ESI, ESI
0xac1dbd: MOV R9D, dword ptr [RAX + 0xbc]
0xac1dc4: XOR EAX, EAX
0xac1dc6: CALL 0x00b044d0
0xac1dcb: LEA RDX, [0x18dc400]
0xac1dd2: MOV ECX, R13D
0xac1dd5: MOV R8D, R15D
0xac1dd8: XOR EDI, EDI
0xac1dda: XOR ESI, ESI
0xac1ddc: XOR EAX, EAX
0xac1dde: CALL 0x00b044d0
0xac1de3: JMP 0x00ac1d51
0xac1de8: ADD RSP, 0x18
0xac1dec: POP RBX
0xac1ded: POP R12
0xac1def: POP R13
0xac1df1: POP R14
0xac1df3: POP R15
0xac1df5: POP RBP
0xac1df6: RET
0xac1df7: LEA RDX, [0x18dc3ce]
0xac1dfe: LEA RCX, [0x12ba7b7]
0xac1e05: MOV R8D, 0x58
0xac1e0b: XOR EDI, EDI
0xac1e0d: XOR ESI, ESI
0xac1e0f: XOR EAX, EAX
0xac1e11: CALL 0x00b044d0
0xac1e16: LEA RDX, [0x18dc3dc]
0xac1e1d: MOV ECX, EBX
0xac1e1f: MOV R8D, R13D
0xac1e22: XOR EDI, EDI
0xac1e24: XOR ESI, ESI
0xac1e26: XOR EAX, EAX
0xac1e28: CALL 0x00b044d0
0xac1e2d: CALL 0x007f1950
0xac1e32: LEA RBX, [0x12ba7b7]
0xac1e39: LEA RDI, [0xac1e2d]
0xac1e40: MOV EDX, 0x58
0xac1e45: MOV RSI, RBX
0xac1e48: CALL 0x007f2010
0xac1e4d: LEA RSI, [0x128989e]
0xac1e54: MOV EDI, 0x5
0xac1e59: MOV RDX, RBX
0xac1e5c: MOV ECX, 0x58
0xac1e61: XOR EAX, EAX
0xac1e63: CALL 0x00c9aa10
0xac1e68: UD2
; END FUNCTION sub_ac1cd0

; FUNCTION sub_ac1e70 CONTEXT / separate function | ev_d18857b8b3e9caed80498a2b0c0318ccdda745a4fbaa56ad7cb5e068a8f01134
; Ghidra body: 0xac1e70..0xac21be
sub_ac1e70:
0xac1e70: PUSH RBP
0xac1e71: MOV RBP, RSP
0xac1e74: PUSH R15
0xac1e76: PUSH R14
0xac1e78: PUSH R13
0xac1e7a: PUSH R12
0xac1e7c: PUSH RBX
0xac1e7d: SUB RSP, 0x228
0xac1e84: LEA R15, [0x391c310]
0xac1e8b: MOV RAX, qword ptr [R15]
0xac1e8e: MOV qword ptr [RBP + -0x30], RAX
0xac1e92: MOV R14, qword ptr GS:[0x0]
0xac1e9b: MOV RAX, qword ptr [RDI + 0x98]
0xac1ea2: TEST EAX, 0x4000
0xac1ea7: JNZ 0x00ac1f0b
0xac1ea9: TEST EAX, 0x10000
0xac1eae: JNZ 0x00ac1f14
0xac1eb0: MOV qword ptr [RBP + -0x200], RDI
0xac1eb7: MOV RDI, qword ptr [RDI + 0xa8]
0xac1ebe: LEA RSI, [0x136e89e]
0xac1ec5: LEA RDX, [RBP + -0x138]
0xac1ecc: LEA RCX, [RBP + -0x14c]
0xac1ed3: CALL 0x005defd0
0xac1ed8: TEST EAX, EAX
0xac1eda: JZ 0x00ac1f2a
0xac1edc: MOV RAX, qword ptr [RBP + -0x200]
0xac1ee3: LEA RSI, [0x12b2da1]
0xac1eea: LEA RDX, [RBP + -0x138]
0xac1ef1: LEA RCX, [RBP + -0x14c]
0xac1ef8: MOV RDI, qword ptr [RAX + 0xa8]
0xac1eff: CALL 0x005defd0
0xac1f04: TEST EAX, EAX
0xac1f06: SETNZ AL
0xac1f09: JMP 0x00ac1f2c
0xac1f0b: LEA RSI, [0x1380c9c]
0xac1f12: JMP 0x00ac1f1b
0xac1f14: LEA RSI, [0x1395b35]
0xac1f1b: XOR EAX, EAX
0xac1f1d: CALL 0x005e0bd0
0xac1f22: MOV R13D, 0x2d
0xac1f28: JMP 0x00ac1f66
0xac1f2a: XOR EAX, EAX
0xac1f2c: MOV ECX, dword ptr [RBP + -0x14c]
0xac1f32: TEST ECX, ECX
0xac1f34: SETLE DL
0xac1f37: OR DL, AL
0xac1f39: JNZ 0x00ac1f4b
0xac1f3b: MOV RDX, qword ptr [RBP + -0x138]
0xac1f42: MOV EAX, ECX
0xac1f44: CMP byte ptr [RDX + RAX*0x1 + -0x1], 0x0
0xac1f49: JZ 0x00ac1f88
0xac1f4b: LEA RSI, [0x13579f8]
0xac1f52: MOV RDI, qword ptr [RBP + -0x200]
0xac1f59: XOR EAX, EAX
0xac1f5b: CALL 0x005e0bd0
0xac1f60: MOV R13D, 0x16
0xac1f66: MOV RAX, qword ptr [R15]
0xac1f69: CMP RAX, qword ptr [RBP + -0x30]
0xac1f6d: JNZ 0x00ac2933
0xac1f73: MOV EAX, R13D
0xac1f76: ADD RSP, 0x228
0xac1f7d: POP RBX
0xac1f7e: POP R12
0xac1f80: POP R13
0xac1f82: POP R14
0xac1f84: POP R15
0xac1f86: POP RBP
0xac1f87: RET
0xac1f88: MOV R12, qword ptr [RBP + -0x200]
0xac1f8f: LEA RSI, [0x1318673]
0xac1f96: XOR R13D, R13D
0xac1f99: XOR EDX, EDX
0xac1f9b: XOR ECX, ECX
0xac1f9d: MOV RDI, qword ptr [R12 + 0xa8]
0xac1fa5: CALL 0x005defd0
0xac1faa: MOV RDI, qword ptr [R12 + 0xa8]
0xac1fb2: LEA RSI, [0x12c5015]
0xac1fb9: LEA RDX, [RBP + -0x140]
0xac1fc0: XOR ECX, ECX
0xac1fc2: MOV EBX, EAX
0xac1fc4: CALL 0x005defd0
0xac1fc9: TEST EAX, EAX
0xac1fcb: JZ 0x00ac212c
0xac1fd1: MOV RAX, qword ptr [RBP + -0x200]
0xac1fd8: LEA RSI, [0x130e0df]
0xac1fdf: LEA RDX, [RBP + -0x140]
0xac1fe6: XOR R12D, R12D
0xac1fe9: XOR ECX, ECX
0xac1feb: MOV RDI, qword ptr [RAX + 0xa8]
0xac1ff2: CALL 0x005defd0
0xac1ff7: TEST EAX, EAX
0xac1ff9: JZ 0x00ac2172
0xac1fff: MOV dword ptr [RBP + -0x22c], EBX
0xac2005: MOV RBX, qword ptr [RBP + -0x200]
0xac200c: LEA RSI, [0x1305bf6]
0xac2013: LEA RDX, [RBP + -0x140]
0xac201a: MOV qword ptr [RBP + -0x220], R13
0xac2021: MOV qword ptr [RBP + -0x218], 0x0
0xac202c: XOR ECX, ECX
0xac202e: MOV RDI, qword ptr [RBX + 0xa8]
0xac2035: CALL 0x005defd0
0xac203a: MOV RDI, qword ptr [RBX + 0xa8]
0xac2041: LEA RSI, [0x1275d61]
0xac2048: LEA RDX, [RBP + -0x140]
0xac204f: XOR ECX, ECX
0xac2051: MOV R13D, EAX
0xac2054: CALL 0x005defd0
0xac2059: MOV ECX, EAX
0xac205b: OR ECX, R13D
0xac205e: JZ 0x00ac21b8
0xac2064: MOV dword ptr [RBP + -0x228], EAX
0xac206a: MOV RAX, qword ptr [RBP + -0x220]
0xac2071: MOV RBX, qword ptr [RBP + -0x200]
0xac2078: MOV RCX, R12
0xac207b: MOV qword ptr [RBP + -0x210], R14
0xac2082: LEA RDX, [0x134cd6e]
0xac2089: MOV ESI, 0x200400
0xac208e: MOV dword ptr [RBP + -0x224], R13D
0xac2095: TEST CX, CX
0xac2098: MOV R14D, ECX
0xac209b: MOV R12D, EAX
0xac209e: MOV RDI, qword ptr [RBX + 0x48]
0xac20a2: CMOVNZ R12D, ECX
0xac20a6: TEST AX, AX
0xac20a9: CMOVNZ R12D, EAX
0xac20ad: TEST R12W, R12W
0xac20b1: CMOVNZ R14D, EAX
0xac20b5: TEST CX, CX
0xac20b8: CMOVNZ R14D, ECX
0xac20bc: MOV ECX, 0xb9
0xac20c1: CALL 0x006afb50
0xac20c6: MOV RAX, qword ptr [RBX + 0x48]
0xac20ca: MOV RCX, qword ptr [RBX + 0x290]
0xac20d1: LEA RDX, [0x1adad78]
0xac20d8: LEA RSI, [RBP + -0x1f8]
0xac20df: MOV qword ptr [RBP + -0x118], RDX
0xac20e6: MOV qword ptr [RBP + -0x110], RAX
0xac20ed: MOV qword ptr [RBP + -0x108], RSI
0xac20f4: MOV qword ptr [RBP + -0x100], RCX
0xac20fb: LEA RSI, [RBP + -0x118]
0xac2102: MOV RDI, qword ptr [RAX + 0x8]
0xac2106: CALL 0x0058c1c0
0xac210b: MOV R13D, EAX
0xac210e: TEST EAX, EAX
0xac2110: JZ 0x00ac21d7
0xac2116: MOV dword ptr [RBP + -0x220], R12D
0xac211d: MOV dword ptr [RBP + -0x208], R14D
0xac2124: XOR R12D, R12D
0xac2127: JMP 0x00ac220f
0xac212c: MOV RDI, qword ptr [RBP + -0x140]
0xac2133: TEST RDI, RDI
0xac2136: JZ 0x00ac2166
0xac2138: LEA RSI, [RBP + -0x148]
0xac213f: MOV EDX, 0x8
0xac2144: CALL 0x007c4e40
0xac2149: CMP qword ptr [RBP + -0x140], 0x0
0xac2151: JZ 0x00ac2166
0xac2153: MOV RCX, qword ptr [RBP + -0x148]
0xac215a: MOV R13, RAX
0xac215d: CMP byte ptr [RCX], 0x0
0xac2160: JZ 0x00ac22d7
0xac2166: LEA RSI, [0x1291c35]
0xac216d: JMP 0x00ac1f52
0xac2172: MOV RDI, qword ptr [RBP + -0x140]
0xac2179: TEST RDI, RDI
0xac217c: JZ 0x00ac21ac
0xac217e: LEA RSI, [RBP + -0x148]
0xac2185: MOV EDX, 0x8
0xac218a: CALL 0x007c4e40
0xac218f: CMP qword ptr [RBP + -0x140], 0x0
0xac2197: JZ 0x00ac21ac
0xac2199: MOV RCX, qword ptr [RBP + -0x148]
0xac21a0: MOV R12, RAX
0xac21a3: CMP byte ptr [RCX], 0x0
0xac21a6: JZ 0x00ac23e0
0xac21ac: LEA RSI, [0x1287716]
0xac21b3: JMP 0x00ac1f52
0xac21b8: LEA RDI, [0x1305bfd]
; END FUNCTION sub_ac1e70

; FUNCTION credential_bit62_predicate CONTEXT / separate function | ev_d868091f9a6f6b9f04dcc2affd8e4028a0950346d4f8cbeccee7c2384b5c3673
; Ghidra body: 0x608f90..0x608fa0
credential_bit62_predicate:
0x608f90: PUSH RBP
0x608f91: MOV RBP, RSP
0x608f94: MOV RAX, qword ptr [RDI + 0x60]
0x608f98: SHR RAX, 0x3e
0x608f9c: AND EAX, 0x1
0x608f9f: POP RBP
0x608fa0: RET
; END FUNCTION credential_bit62_predicate

; FUNCTION zero_fill_helper CONTEXT / separate function | ev_9f715f53ca8e7945dcf5dd090a09697d620766198f5ec9c1ad147fd5676b3ea0
; Ghidra body: 0x258ff0..0x259031
zero_fill_helper:
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
; END FUNCTION zero_fill_helper

; SUPPLEMENTAL GNU OBJDUMP FULL ORIGINAL4096BYTES
; Independent linear decode, not REA pseudocode/function recovery. INT3 bytes are padding.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_647.bin:     file format binary


Disassembly of section .data:

0000000000265f48 <.data>:
  265f48:	e9 63 88 85 00       	jmp    0xabe7b0
  265f4d:	cc                   	int3
  265f4e:	cc                   	int3
  265f4f:	cc                   	int3
  265f50:	e9 9b 22 79 00       	jmp    0x9f81f0
  265f55:	cc                   	int3
  265f56:	cc                   	int3
  265f57:	cc                   	int3
  265f58:	e9 b3 35 98 00       	jmp    0xbe9510
  265f5d:	cc                   	int3
  265f5e:	cc                   	int3
  265f5f:	cc                   	int3
  265f60:	e9 ab 1d 74 00       	jmp    0x9a7d10
  265f65:	cc                   	int3
  265f66:	cc                   	int3
  265f67:	cc                   	int3
  265f68:	e9 f3 35 74 00       	jmp    0x9a9560
  265f6d:	cc                   	int3
  265f6e:	cc                   	int3
  265f6f:	cc                   	int3
  265f70:	e9 9b 3e 74 00       	jmp    0x9a9e10
  265f75:	cc                   	int3
  265f76:	cc                   	int3
  265f77:	cc                   	int3
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

; SUPPLEMENTAL FULL BODY/CARRIER LINEAR DECODE: GNU objdump.
; Code versus data uncertain outside REA body ranges; these are not added function claims.

; Source kernel_text.bin RVA0xabe1c0 length0x4000,SHA256b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_linear_abe1c0_4000.bin:     file format binary


Disassembly of section .data:

0000000000abe1c0 <.data>:
  abe1c0:	55                   	push   rbp
  abe1c1:	48 89 e5             	mov    rbp,rsp
  abe1c4:	41 57                	push   r15
  abe1c6:	41 56                	push   r14
  abe1c8:	53                   	push   rbx
  abe1c9:	48 81 ec 08 04 00 00 	sub    rsp,0x408
  abe1d0:	4c 8d 3d 39 e1 e5 02 	lea    r15,[rip+0x2e5e139]        # 0x391c310
  abe1d7:	48 89 f3             	mov    rbx,rsi
  abe1da:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abe1dd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  abe1e1:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abe1e8:	e8 a3 ad b4 ff       	call   0x608f90
  abe1ed:	85 c0                	test   eax,eax
  abe1ef:	74 40                	je     0xabe231
  abe1f1:	4c 8d b5 e8 fb ff ff 	lea    r14,[rbp-0x418]
  abe1f8:	be f8 03 00 00       	mov    esi,0x3f8
  abe1fd:	4c 89 f7             	mov    rdi,r14
  abe200:	e8 eb ad 79 ff       	call   0x258ff0
  abe205:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  abe208:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abe20f:	00 00 
  abe211:	48 8d 35 7f 10 89 00 	lea    rsi,[rip+0x89107f]        # 0x134f297
  abe218:	31 d2                	xor    edx,edx
  abe21a:	e8 c1 c1 15 00       	call   0xc1a3e0
  abe21f:	ba f8 03 00 00       	mov    edx,0x3f8
  abe224:	4c 89 f7             	mov    rdi,r14
  abe227:	48 89 de             	mov    rsi,rbx
  abe22a:	e8 a1 af 79 ff       	call   0x2591d0
  abe22f:	eb 05                	jmp    0xabe236
  abe231:	b8 01 00 00 00       	mov    eax,0x1
  abe236:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  abe239:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  abe23d:	75 0e                	jne    0xabe24d
  abe23f:	48 81 c4 08 04 00 00 	add    rsp,0x408
  abe246:	5b                   	pop    rbx
  abe247:	41 5e                	pop    r14
  abe249:	41 5f                	pop    r15
  abe24b:	5d                   	pop    rbp
  abe24c:	c3                   	ret
  abe24d:	e8 5e f4 c3 ff       	call   0x6fd6b0
  abe252:	0f 0b                	ud2
  abe254:	90                   	nop
  abe255:	90                   	nop
  abe256:	90                   	nop
  abe257:	90                   	nop
  abe258:	90                   	nop
  abe259:	90                   	nop
  abe25a:	90                   	nop
  abe25b:	90                   	nop
  abe25c:	90                   	nop
  abe25d:	90                   	nop
  abe25e:	90                   	nop
  abe25f:	90                   	nop
  abe260:	55                   	push   rbp
  abe261:	48 89 e5             	mov    rbp,rsp
  abe264:	41 57                	push   r15
  abe266:	41 56                	push   r14
  abe268:	41 55                	push   r13
  abe26a:	41 54                	push   r12
  abe26c:	53                   	push   rbx
  abe26d:	48 81 ec d8 01 00 00 	sub    rsp,0x1d8
  abe274:	48 8d 05 95 e0 e5 02 	lea    rax,[rip+0x2e5e095]        # 0x391c310
  abe27b:	48 89 bd 08 fe ff ff 	mov    QWORD PTR [rbp-0x1f8],rdi
  abe282:	48 8d 9d 58 fe ff ff 	lea    rbx,[rbp-0x1a8]
  abe289:	49 89 f4             	mov    r12,rsi
  abe28c:	be 60 00 00 00       	mov    esi,0x60
  abe291:	49 89 cd             	mov    r13,rcx
  abe294:	41 89 d6             	mov    r14d,edx
  abe297:	48 89 df             	mov    rdi,rbx
  abe29a:	48 8b 00             	mov    rax,QWORD PTR [rax]
  abe29d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abe2a1:	e8 4a ad 79 ff       	call   0x258ff0
  abe2a6:	48 8b 3d 33 33 c1 02 	mov    rdi,QWORD PTR [rip+0x2c13333]        # 0x36d15e0
  abe2ad:	ba 02 00 00 00       	mov    edx,0x2
  abe2b2:	31 f6                	xor    esi,esi
  abe2b4:	e8 c7 d5 97 ff       	call   0x43b880
  abe2b9:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abe2c0:	00 00 
  abe2c2:	48 8d 35 bb bd 89 00 	lea    rsi,[rip+0x89bdbb]        # 0x135a084
  abe2c9:	31 d2                	xor    edx,edx
  abe2cb:	49 89 c7             	mov    r15,rax
  abe2ce:	e8 0d c1 15 00       	call   0xc1a3e0
  abe2d3:	ba 00 04 00 00       	mov    edx,0x400
  abe2d8:	4c 89 e7             	mov    rdi,r12
  abe2db:	4c 89 fe             	mov    rsi,r15
  abe2de:	31 c9                	xor    ecx,ecx
  abe2e0:	e8 1b b6 79 ff       	call   0x259900
  abe2e5:	85 c0                	test   eax,eax
  abe2e7:	74 0b                	je     0xabe2f4
  abe2e9:	41 89 c4             	mov    r12d,eax
  abe2ec:	4c 89 fe             	mov    rsi,r15
  abe2ef:	e9 f0 00 00 00       	jmp    0xabe3e4
  abe2f4:	4c 89 ad 38 fe ff ff 	mov    QWORD PTR [rbp-0x1c8],r13
  abe2fb:	48 83 ec 08          	sub    rsp,0x8
  abe2ff:	4d 89 fd             	mov    r13,r15
  abe302:	4d 89 f8             	mov    r8,r15
  abe305:	4c 8b bd 08 fe ff ff 	mov    r15,QWORD PTR [rbp-0x1f8]
  abe30c:	4c 8d a5 e8 fe ff ff 	lea    r12,[rbp-0x118]
  abe313:	ba 44 01 00 00       	mov    edx,0x144
  abe318:	31 f6                	xor    esi,esi
  abe31a:	b9 01 00 00 00       	mov    ecx,0x1
  abe31f:	41 b9 9c ff ff ff    	mov    r9d,0xffffff9c
  abe325:	4c 89 e7             	mov    rdi,r12
  abe328:	41 57                	push   r15
  abe32a:	6a 00                	push   0x0
  abe32c:	6a 00                	push   0x0
  abe32e:	e8 ad c3 b3 ff       	call   0x5fa6e0
  abe333:	48 83 c4 20          	add    rsp,0x20
  abe337:	4c 89 e7             	mov    rdi,r12
  abe33a:	e8 e1 a8 b3 ff       	call   0x5f8c20
  abe33f:	85 c0                	test   eax,eax
  abe341:	74 08                	je     0xabe34b
  abe343:	41 89 c4             	mov    r12d,eax
  abe346:	e9 96 00 00 00       	jmp    0xabe3e1
  abe34b:	4c 8b a5 48 ff ff ff 	mov    r12,QWORD PTR [rbp-0xb8]
  abe352:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  abe359:	be 0c 00 00 00       	mov    esi,0xc
  abe35e:	e8 1d c4 b3 ff       	call   0x5fa780
  abe363:	4c 89 e2             	mov    rdx,r12
  abe366:	41 bc 16 00 00 00    	mov    r12d,0x16
  abe36c:	83 ba d4 01 00 00 01 	cmp    DWORD PTR [rdx+0x1d4],0x1
  abe373:	75 64                	jne    0xabe3d9
  abe375:	49 8b 87 40 01 00 00 	mov    rax,QWORD PTR [r15+0x140]
  abe37c:	48 8d 0d 75 c4 01 01 	lea    rcx,[rip+0x101c475]        # 0x1ada7f8
  abe383:	48 8d b5 b8 fe ff ff 	lea    rsi,[rbp-0x148]
  abe38a:	48 89 95 28 fe ff ff 	mov    QWORD PTR [rbp-0x1d8],rdx
  abe391:	48 89 8d b8 fe ff ff 	mov    QWORD PTR [rbp-0x148],rcx
  abe398:	48 89 95 c0 fe ff ff 	mov    QWORD PTR [rbp-0x140],rdx
  abe39f:	c7 85 c8 fe ff ff 01 	mov    DWORD PTR [rbp-0x138],0x1
  abe3a6:	00 00 00 
  abe3a9:	48 89 85 d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rax
  abe3b0:	4c 89 bd d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],r15
  abe3b7:	48 c7 85 e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],0x0
  abe3be:	00 00 00 00 
  abe3c2:	48 8b 7a 08          	mov    rdi,QWORD PTR [rdx+0x8]
  abe3c6:	e8 35 d7 ac ff       	call   0x58bb00
  abe3cb:	48 8b 95 28 fe ff ff 	mov    rdx,QWORD PTR [rbp-0x1d8]
  abe3d2:	41 89 c4             	mov    r12d,eax
  abe3d5:	85 c0                	test   eax,eax
  abe3d7:	74 42                	je     0xabe41b
  abe3d9:	48 89 d7             	mov    rdi,rdx
  abe3dc:	e8 5f c0 a8 ff       	call   0x54a440
  abe3e1:	4c 89 ee             	mov    rsi,r13
  abe3e4:	48 8b 3d f5 31 c1 02 	mov    rdi,QWORD PTR [rip+0x2c131f5]        # 0x36d15e0
  abe3eb:	31 d2                	xor    edx,edx
  abe3ed:	e8 ce dc 97 ff       	call   0x43c0c0
  abe3f2:	48 8d 05 17 df e5 02 	lea    rax,[rip+0x2e5df17]        # 0x391c310
  abe3f9:	48 8b 00             	mov    rax,QWORD PTR [rax]
  abe3fc:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  abe400:	0f 85 9c 03 00 00    	jne    0xabe7a2
  abe406:	44 89 e0             	mov    eax,r12d
  abe409:	48 81 c4 d8 01 00 00 	add    rsp,0x1d8
  abe410:	5b                   	pop    rbx
  abe411:	41 5c                	pop    r12
  abe413:	41 5d                	pop    r13
  abe415:	41 5e                	pop    r14
  abe417:	41 5f                	pop    r15
  abe419:	5d                   	pop    rbp
  abe41a:	c3                   	ret
  abe41b:	4d 8b 8f 40 01 00 00 	mov    r9,QWORD PTR [r15+0x140]
  abe422:	48 89 d6             	mov    rsi,rdx
  abe425:	bf 07 00 00 00       	mov    edi,0x7
  abe42a:	b9 01 00 00 00       	mov    ecx,0x1
  abe42f:	31 d2                	xor    edx,edx
  abe431:	45 31 c0             	xor    r8d,r8d
  abe434:	e8 87 f5 99 ff       	call   0x45d9c0
  abe439:	48 89 85 50 fe ff ff 	mov    QWORD PTR [rbp-0x1b0],rax
  abe440:	48 85 c0             	test   rax,rax
  abe443:	74 41                	je     0xabe486
  abe445:	48 8d 78 18          	lea    rdi,[rax+0x18]
  abe449:	49 89 c4             	mov    r12,rax
  abe44c:	31 f6                	xor    esi,esi
  abe44e:	31 d2                	xor    edx,edx
  abe450:	e8 4b 62 d1 ff       	call   0x7d46a0
  abe455:	4c 89 e7             	mov    rdi,r12
  abe458:	e8 f3 33 b7 ff       	call   0x631850
  abe45d:	85 c0                	test   eax,eax
  abe45f:	74 33                	je     0xabe494
  abe461:	89 c2                	mov    edx,eax
  abe463:	48 8d 3d 61 ef 86 00 	lea    rdi,[rip+0x86ef61]        # 0x132d3cb
  abe46a:	48 8d 35 5f 27 8c 00 	lea    rsi,[rip+0x8c275f]        # 0x1380bd0
  abe471:	31 c0                	xor    eax,eax
  abe473:	e8 98 ef 79 ff       	call   0x25d410
  abe478:	41 bc 08 00 00 00    	mov    r12d,0x8
  abe47e:	4d 89 fe             	mov    r14,r15
  abe481:	e9 5e 02 00 00       	jmp    0xabe6e4
  abe486:	41 bc 0c 00 00 00    	mov    r12d,0xc
  abe48c:	4d 89 fe             	mov    r14,r15
  abe48f:	e9 50 02 00 00       	jmp    0xabe6e4
  abe494:	4c 89 e7             	mov    rdi,r12
  abe497:	e8 04 3e b7 ff       	call   0x6322a0
  abe49c:	0f b7 50 10          	movzx  edx,WORD PTR [rax+0x10]
  abe4a0:	8d 8a 00 02 ff ff    	lea    ecx,[rdx-0xfe00]
  abe4a6:	83 f9 10             	cmp    ecx,0x10
  abe4a9:	77 0a                	ja     0xabe4b5
  abe4ab:	be 03 00 01 00       	mov    esi,0x10003
  abe4b0:	0f a3 ce             	bt     esi,ecx
  abe4b3:	72 09                	jb     0xabe4be
  abe4b5:	83 fa 02             	cmp    edx,0x2
  abe4b8:	0f 85 fc 01 00 00    	jne    0xabe6ba
  abe4be:	0f b7 48 38          	movzx  ecx,WORD PTR [rax+0x38]
  abe4c2:	48 85 c9             	test   rcx,rcx
  abe4c5:	0f 84 d8 01 00 00    	je     0xabe6a3
  abe4cb:	48 89 c2             	mov    rdx,rax
  abe4ce:	48 6b f1 38          	imul   rsi,rcx,0x38
  abe4d2:	31 ff                	xor    edi,edi
  abe4d4:	48 83 c2 40          	add    rdx,0x40
  abe4d8:	81 7c 38 40 01 00 00 	cmp    DWORD PTR [rax+rdi*1+0x40],0x61000001
  abe4df:	61 
  abe4e0:	74 0e                	je     0xabe4f0
  abe4e2:	48 83 c7 38          	add    rdi,0x38
  abe4e6:	48 39 fe             	cmp    rsi,rdi
  abe4e9:	75 ed                	jne    0xabe4d8
  abe4eb:	e9 b3 01 00 00       	jmp    0xabe6a3
  abe4f0:	4c 8b 44 38 60       	mov    r8,QWORD PTR [rax+rdi*1+0x60]
  abe4f5:	4d 85 c0             	test   r8,r8
  abe4f8:	0f 84 a5 01 00 00    	je     0xabe6a3
  abe4fe:	48 8b 44 38 50       	mov    rax,QWORD PTR [rax+rdi*1+0x50]
  abe503:	31 f6                	xor    esi,esi
  abe505:	eb 10                	jmp    0xabe517
  abe507:	48 ff c6             	inc    rsi
  abe50a:	48 83 c2 38          	add    rdx,0x38
  abe50e:	48 39 f1             	cmp    rcx,rsi
  abe511:	0f 84 8c 01 00 00    	je     0xabe6a3
  abe517:	8b 3a                	mov    edi,DWORD PTR [rdx]
  abe519:	81 ff 10 00 00 61    	cmp    edi,0x61000010
  abe51f:	74 05                	je     0xabe526
  abe521:	83 ff 01             	cmp    edi,0x1
  abe524:	75 e1                	jne    0xabe507
  abe526:	49 89 c4             	mov    r12,rax
  abe529:	4c 2b 62 10          	sub    r12,QWORD PTR [rdx+0x10]
  abe52d:	72 d8                	jb     0xabe507
  abe52f:	48 8b 7a 28          	mov    rdi,QWORD PTR [rdx+0x28]
  abe533:	4c 29 c7             	sub    rdi,r8
  abe536:	72 cf                	jb     0xabe507
  abe538:	49 39 fc             	cmp    r12,rdi
  abe53b:	77 ca                	ja     0xabe507
  abe53d:	49 83 f8 60          	cmp    r8,0x60
  abe541:	b8 60 00 00 00       	mov    eax,0x60
  abe546:	4c 89 e1             	mov    rcx,r12
  abe549:	4c 89 e2             	mov    rdx,r12
  abe54c:	48 89 b5 20 fe ff ff 	mov    QWORD PTR [rbp-0x1e0],rsi
  abe553:	49 0f 42 c0          	cmovb  rax,r8
  abe557:	48 81 e1 00 c0 ff ff 	and    rcx,0xffffffffffffc000
  abe55e:	48 81 e2 00 c0 ff ff 	and    rdx,0xffffffffffffc000
  abe565:	48 f7 d9             	neg    rcx
  abe568:	48 89 85 48 fe ff ff 	mov    QWORD PTR [rbp-0x1b8],rax
  abe56f:	48 89 95 40 fe ff ff 	mov    QWORD PTR [rbp-0x1c0],rdx
  abe576:	48 89 8d 30 fe ff ff 	mov    QWORD PTR [rbp-0x1d0],rcx
  abe57d:	48 8b bd 50 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1b0]
  abe584:	48 8b 95 40 fe ff ff 	mov    rdx,QWORD PTR [rbp-0x1c0]
  abe58b:	e8 e0 25 b7 ff       	call   0x630b70
  abe590:	48 8b bd 50 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1b0]
  abe597:	48 89 c6             	mov    rsi,rax
  abe59a:	e8 31 be a7 ff       	call   0x53a3d0
  abe59f:	48 85 c0             	test   rax,rax
  abe5a2:	0f 84 a9 01 00 00    	je     0xabe751
  abe5a8:	48 8b 8d 40 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x1c0]
  abe5af:	8b 3d e3 ac 08 03    	mov    edi,DWORD PTR [rip+0x308ace3]        # 0x3b49298
  abe5b5:	48 be 00 00 00 00 00 	movabs rsi,0xffff800000000000
  abe5bc:	80 ff ff 
  abe5bf:	48 89 85 18 fe ff ff 	mov    QWORD PTR [rbp-0x1e8],rax
  abe5c6:	48 81 c1 00 40 00 00 	add    rcx,0x4000
  abe5cd:	48 89 ca             	mov    rdx,rcx
  abe5d0:	48 89 8d 40 fe ff ff 	mov    QWORD PTR [rbp-0x1c0],rcx
  abe5d7:	8b 8d 48 fe ff ff    	mov    ecx,DWORD PTR [rbp-0x1b8]
  abe5dd:	4c 29 e2             	sub    rdx,r12
  abe5e0:	48 39 ca             	cmp    rdx,rcx
  abe5e3:	48 0f 4d d1          	cmovge rdx,rcx
  abe5e7:	8b 0d a7 ac 08 03    	mov    ecx,DWORD PTR [rip+0x308aca7]        # 0x3b49294
  abe5ed:	48 c1 e7 1e          	shl    rdi,0x1e
  abe5f1:	48 63 d2             	movsxd rdx,edx
  abe5f4:	48 89 95 10 fe ff ff 	mov    QWORD PTR [rbp-0x1f0],rdx
  abe5fb:	48 c1 e1 27          	shl    rcx,0x27
  abe5ff:	48 09 cf             	or     rdi,rcx
  abe602:	48 8b 8d 30 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x1d0]
  abe609:	48 09 f7             	or     rdi,rsi
  abe60c:	48 03 78 30          	add    rdi,QWORD PTR [rax+0x30]
  abe610:	48 89 de             	mov    rsi,rbx
  abe613:	4c 01 e1             	add    rcx,r12
  abe616:	48 01 cf             	add    rdi,rcx
  abe619:	e8 c2 b5 79 ff       	call   0x259be0
  abe61e:	48 8b bd 18 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1e8]
  abe625:	e8 e6 bd a7 ff       	call   0x53a410
  abe62a:	48 81 85 30 fe ff ff 	add    QWORD PTR [rbp-0x1d0],0xffffffffffffc000
  abe631:	00 c0 ff ff 
  abe635:	48 8b 8d 10 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x1f0]
  abe63c:	48 8b 85 48 fe ff ff 	mov    rax,QWORD PTR [rbp-0x1b8]
  abe643:	48 8b b5 20 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x1e0]
  abe64a:	29 c8                	sub    eax,ecx
  abe64c:	48 01 cb             	add    rbx,rcx
  abe64f:	49 01 cc             	add    r12,rcx
  abe652:	48 89 85 48 fe ff ff 	mov    QWORD PTR [rbp-0x1b8],rax
  abe659:	85 c0                	test   eax,eax
  abe65b:	0f 8f 1c ff ff ff    	jg     0xabe57d
  abe661:	8b 95 60 fe ff ff    	mov    edx,DWORD PTR [rbp-0x1a0]
  abe667:	48 8b 8d 58 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x1a8]
  abe66e:	81 fa 4f 52 42 49    	cmp    edx,0x4942524f
  abe674:	0f 95 c0             	setne  al
  abe677:	48 83 f9 14          	cmp    rcx,0x14
  abe67b:	40 0f 92 c6          	setb   sil
  abe67f:	40 08 c6             	or     sil,al
  abe682:	40 80 fe 01          	cmp    sil,0x1
  abe686:	0f 85 d0 00 00 00    	jne    0xabe75c
  abe68c:	48 8d 3d c3 8f 7c 00 	lea    rdi,[rip+0x7c8fc3]        # 0x1287656
  abe693:	48 8d 35 36 25 8c 00 	lea    rsi,[rip+0x8c2536]        # 0x1380bd0
  abe69a:	31 c0                	xor    eax,eax
  abe69c:	e8 6f ed 79 ff       	call   0x25d410
  abe6a1:	eb 2c                	jmp    0xabe6cf
  abe6a3:	48 8d 3d c0 e5 88 00 	lea    rdi,[rip+0x88e5c0]        # 0x134cc6a
  abe6aa:	48 8d 35 1f 25 8c 00 	lea    rsi,[rip+0x8c251f]        # 0x1380bd0
  abe6b1:	31 c0                	xor    eax,eax
  abe6b3:	e8 58 ed 79 ff       	call   0x25d410
  abe6b8:	eb 15                	jmp    0xabe6cf
  abe6ba:	48 8d 3d 8b 85 8b 00 	lea    rdi,[rip+0x8b858b]        # 0x1376c4c
  abe6c1:	48 8d 35 08 25 8c 00 	lea    rsi,[rip+0x8c2508]        # 0x1380bd0
  abe6c8:	31 c0                	xor    eax,eax
  abe6ca:	e8 41 ed 79 ff       	call   0x25d410
  abe6cf:	41 bc 08 00 00 00    	mov    r12d,0x8
  abe6d5:	48 8b bd 50 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1b0]
  abe6dc:	4d 89 fe             	mov    r14,r15
  abe6df:	e8 0c 3b b7 ff       	call   0x6321f0
  abe6e4:	49 8b 86 40 01 00 00 	mov    rax,QWORD PTR [r14+0x140]
  abe6eb:	48 8d 0d 06 c2 01 01 	lea    rcx,[rip+0x101c206]        # 0x1ada8f8
  abe6f2:	4c 8b bd 28 fe ff ff 	mov    r15,QWORD PTR [rbp-0x1d8]
  abe6f9:	48 8d b5 b8 fe ff ff 	lea    rsi,[rbp-0x148]
  abe700:	48 89 8d b8 fe ff ff 	mov    QWORD PTR [rbp-0x148],rcx
  abe707:	4c 89 bd c0 fe ff ff 	mov    QWORD PTR [rbp-0x140],r15
  abe70e:	c7 85 c8 fe ff ff 01 	mov    DWORD PTR [rbp-0x138],0x1
  abe715:	00 00 00 
  abe718:	48 89 85 d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rax
  abe71f:	4c 89 b5 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],r14
  abe726:	49 8b 7f 08          	mov    rdi,QWORD PTR [r15+0x8]
  abe72a:	e8 b1 d5 ac ff       	call   0x58bce0
  abe72f:	4c 89 ff             	mov    rdi,r15
  abe732:	e8 09 bd a8 ff       	call   0x54a440
  abe737:	48 8b bd 50 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1b0]
  abe73e:	48 85 ff             	test   rdi,rdi
  abe741:	0f 84 9a fc ff ff    	je     0xabe3e1
  abe747:	e8 54 34 9a ff       	call   0x461ba0
  abe74c:	e9 90 fc ff ff       	jmp    0xabe3e1
  abe751:	41 bc 05 00 00 00    	mov    r12d,0x5
  abe757:	e9 79 ff ff ff       	jmp    0xabe6d5
  abe75c:	41 83 fe 04          	cmp    r14d,0x4
  abe760:	75 08                	jne    0xabe76a
  abe762:	8b 85 68 fe ff ff    	mov    eax,DWORD PTR [rbp-0x198]
  abe768:	eb 0f                	jmp    0xabe779
  abe76a:	83 bd 64 fe ff ff 04 	cmp    DWORD PTR [rbp-0x19c],0x4
  abe771:	72 17                	jb     0xabe78a
  abe773:	8b 85 6c fe ff ff    	mov    eax,DWORD PTR [rbp-0x194]
  abe779:	48 8b 8d 38 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x1c8]
  abe780:	45 31 e4             	xor    r12d,r12d
  abe783:	89 01                	mov    DWORD PTR [rcx],eax
  abe785:	e9 4b ff ff ff       	jmp    0xabe6d5
  abe78a:	48 8b 85 38 fe ff ff 	mov    rax,QWORD PTR [rbp-0x1c8]
  abe791:	41 bc 16 00 00 00    	mov    r12d,0x16
  abe797:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
  abe79d:	e9 33 ff ff ff       	jmp    0xabe6d5
  abe7a2:	e8 09 ef c3 ff       	call   0x6fd6b0
  abe7a7:	0f 0b                	ud2
  abe7a9:	90                   	nop
  abe7aa:	90                   	nop
  abe7ab:	90                   	nop
  abe7ac:	90                   	nop
  abe7ad:	90                   	nop
  abe7ae:	90                   	nop
  abe7af:	90                   	nop
  abe7b0:	55                   	push   rbp
  abe7b1:	48 89 e5             	mov    rbp,rsp
  abe7b4:	41 57                	push   r15
  abe7b6:	41 56                	push   r14
  abe7b8:	53                   	push   rbx
  abe7b9:	48 83 ec 18          	sub    rsp,0x18
  abe7bd:	4c 8d 3d 4c db e5 02 	lea    r15,[rip+0x2e5db4c]        # 0x391c310
  abe7c4:	48 89 fb             	mov    rbx,rdi
  abe7c7:	49 89 f6             	mov    r14,rsi
  abe7ca:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abe7cd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  abe7d1:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abe7d8:	e8 b3 a7 b4 ff       	call   0x608f90
  abe7dd:	85 c0                	test   eax,eax
  abe7df:	74 28                	je     0xabe809
  abe7e1:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
  abe7e8:	48 8d 4d dc          	lea    rcx,[rbp-0x24]
  abe7ec:	48 89 df             	mov    rdi,rbx
  abe7ef:	ba 04 00 00 00       	mov    edx,0x4
  abe7f4:	49 8b 36             	mov    rsi,QWORD PTR [r14]
  abe7f7:	e8 64 fa ff ff       	call   0xabe260
  abe7fc:	48 63 4d dc          	movsxd rcx,DWORD PTR [rbp-0x24]
  abe800:	48 89 8b 08 04 00 00 	mov    QWORD PTR [rbx+0x408],rcx
  abe807:	eb 05                	jmp    0xabe80e
  abe809:	b8 01 00 00 00       	mov    eax,0x1
  abe80e:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  abe811:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  abe815:	75 0b                	jne    0xabe822
  abe817:	48 83 c4 18          	add    rsp,0x18
  abe81b:	5b                   	pop    rbx
  abe81c:	41 5e                	pop    r14
  abe81e:	41 5f                	pop    r15
  abe820:	5d                   	pop    rbp
  abe821:	c3                   	ret
  abe822:	e8 89 ee c3 ff       	call   0x6fd6b0
  abe827:	0f 0b                	ud2
  abe829:	90                   	nop
  abe82a:	90                   	nop
  abe82b:	90                   	nop
  abe82c:	90                   	nop
  abe82d:	90                   	nop
  abe82e:	90                   	nop
  abe82f:	90                   	nop
  abe830:	55                   	push   rbp
  abe831:	48 89 e5             	mov    rbp,rsp
  abe834:	41 57                	push   r15
  abe836:	41 56                	push   r14
  abe838:	53                   	push   rbx
  abe839:	48 83 ec 18          	sub    rsp,0x18
  abe83d:	4c 8d 3d cc da e5 02 	lea    r15,[rip+0x2e5dacc]        # 0x391c310
  abe844:	48 89 fb             	mov    rbx,rdi
  abe847:	49 89 f6             	mov    r14,rsi
  abe84a:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abe84d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  abe851:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abe858:	e8 33 a7 b4 ff       	call   0x608f90
  abe85d:	85 c0                	test   eax,eax
  abe85f:	74 28                	je     0xabe889
  abe861:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
  abe868:	48 8d 4d dc          	lea    rcx,[rbp-0x24]
  abe86c:	48 89 df             	mov    rdi,rbx
  abe86f:	ba 05 00 00 00       	mov    edx,0x5
  abe874:	49 8b 36             	mov    rsi,QWORD PTR [r14]
  abe877:	e8 e4 f9 ff ff       	call   0xabe260
  abe87c:	48 63 4d dc          	movsxd rcx,DWORD PTR [rbp-0x24]
  abe880:	48 89 8b 08 04 00 00 	mov    QWORD PTR [rbx+0x408],rcx
  abe887:	eb 05                	jmp    0xabe88e
  abe889:	b8 01 00 00 00       	mov    eax,0x1
  abe88e:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  abe891:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  abe895:	75 0b                	jne    0xabe8a2
  abe897:	48 83 c4 18          	add    rsp,0x18
  abe89b:	5b                   	pop    rbx
  abe89c:	41 5e                	pop    r14
  abe89e:	41 5f                	pop    r15
  abe8a0:	5d                   	pop    rbp
  abe8a1:	c3                   	ret
  abe8a2:	e8 09 ee c3 ff       	call   0x6fd6b0
  abe8a7:	0f 0b                	ud2
  abe8a9:	90                   	nop
  abe8aa:	90                   	nop
  abe8ab:	90                   	nop
  abe8ac:	90                   	nop
  abe8ad:	90                   	nop
  abe8ae:	90                   	nop
  abe8af:	90                   	nop
  abe8b0:	55                   	push   rbp
  abe8b1:	48 89 e5             	mov    rbp,rsp
  abe8b4:	41 57                	push   r15
  abe8b6:	41 56                	push   r14
  abe8b8:	41 55                	push   r13
  abe8ba:	41 54                	push   r12
  abe8bc:	53                   	push   rbx
  abe8bd:	48 83 ec 18          	sub    rsp,0x18
  abe8c1:	4c 8d 2d 48 da e5 02 	lea    r13,[rip+0x2e5da48]        # 0x391c310
  abe8c8:	49 89 ff             	mov    r15,rdi
  abe8cb:	31 ff                	xor    edi,edi
  abe8cd:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  abe8d1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abe8d5:	48 8b 46 18          	mov    rax,QWORD PTR [rsi+0x18]
  abe8d9:	44 8b 26             	mov    r12d,DWORD PTR [rsi]
  abe8dc:	8b 5e 08             	mov    ebx,DWORD PTR [rsi+0x8]
  abe8df:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
  abe8e3:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  abe8e7:	e8 b4 e0 00 00       	call   0xacc9a0
  abe8ec:	85 c0                	test   eax,eax
  abe8ee:	75 22                	jne    0xabe912
  abe8f0:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  abe8f7:	00 00 
  abe8f9:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
  abe8fd:	b8 02 00 00 00       	mov    eax,0x2
  abe902:	81 b9 d4 05 00 00 00 	cmp    DWORD PTR [rcx+0x5d4],0x5000000
  abe909:	00 00 05 
  abe90c:	0f 82 e6 00 00 00    	jb     0xabe9f8
  abe912:	41 83 fc ff          	cmp    r12d,0xffffffff
  abe916:	74 1a                	je     0xabe932
  abe918:	49 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [r15+0x140]
  abe91f:	e8 6c a6 b4 ff       	call   0x608f90
  abe924:	85 c0                	test   eax,eax
  abe926:	75 15                	jne    0xabe93d
  abe928:	b8 01 00 00 00       	mov    eax,0x1
  abe92d:	e9 c6 00 00 00       	jmp    0xabe9f8
  abe932:	49 8b 47 08          	mov    rax,QWORD PTR [r15+0x8]
  abe936:	44 8b a0 c0 05 00 00 	mov    r12d,DWORD PTR [rax+0x5c0]
  abe93d:	b8 16 00 00 00       	mov    eax,0x16
  abe942:	41 83 fc 0a          	cmp    r12d,0xa
  abe946:	0f 87 ac 00 00 00    	ja     0xabe9f8
  abe94c:	83 fb 02             	cmp    ebx,0x2
  abe94f:	74 1e                	je     0xabe96f
  abe951:	83 fb 01             	cmp    ebx,0x1
  abe954:	0f 85 9e 00 00 00    	jne    0xabe9f8
  abe95a:	48 8d 75 cc          	lea    rsi,[rbp-0x34]
  abe95e:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  abe962:	44 89 e7             	mov    edi,r12d
  abe965:	e8 76 eb e2 ff       	call   0x8ed4e0
  abe96a:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
  abe96d:	eb 48                	jmp    0xabe9b7
  abe96f:	48 8d 75 cc          	lea    rsi,[rbp-0x34]
  abe973:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  abe977:	44 89 e7             	mov    edi,r12d
  abe97a:	e8 d1 4c f2 ff       	call   0x9e3650
  abe97f:	49 8b 47 08          	mov    rax,QWORD PTR [r15+0x8]
  abe983:	48 8b 80 00 02 00 00 	mov    rax,QWORD PTR [rax+0x200]
  abe98a:	f6 80 44 02 00 00 02 	test   BYTE PTR [rax+0x244],0x2
  abe991:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
  abe994:	74 21                	je     0xabe9b7
  abe996:	8d 48 03             	lea    ecx,[rax+0x3]
  abe999:	85 c0                	test   eax,eax
  abe99b:	0f 49 c8             	cmovns ecx,eax
  abe99e:	8b 45 c8             	mov    eax,DWORD PTR [rbp-0x38]
  abe9a1:	c1 f9 02             	sar    ecx,0x2
  abe9a4:	89 4d cc             	mov    DWORD PTR [rbp-0x34],ecx
  abe9a7:	8d 50 03             	lea    edx,[rax+0x3]
  abe9aa:	85 c0                	test   eax,eax
  abe9ac:	0f 49 d0             	cmovns edx,eax
  abe9af:	89 c8                	mov    eax,ecx
  abe9b1:	c1 fa 02             	sar    edx,0x2
  abe9b4:	89 55 c8             	mov    DWORD PTR [rbp-0x38],edx
  abe9b7:	89 c1                	mov    ecx,eax
  abe9b9:	4c 89 f7             	mov    rdi,r14
  abe9bc:	c1 f9 1f             	sar    ecx,0x1f
  abe9bf:	c4 e2 70 f2 f0       	andn   esi,ecx,eax
  abe9c4:	e8 c7 ad 79 ff       	call   0x259790
  abe9c9:	83 f8 ff             	cmp    eax,0xffffffff
  abe9cc:	74 25                	je     0xabe9f3
  abe9ce:	8b 45 c8             	mov    eax,DWORD PTR [rbp-0x38]
  abe9d1:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  abe9d5:	89 c1                	mov    ecx,eax
  abe9d7:	c1 f9 1f             	sar    ecx,0x1f
  abe9da:	c4 e2 70 f2 f0       	andn   esi,ecx,eax
  abe9df:	e8 ac ad 79 ff       	call   0x259790
  abe9e4:	31 c9                	xor    ecx,ecx
  abe9e6:	83 f8 ff             	cmp    eax,0xffffffff
  abe9e9:	b8 0e 00 00 00       	mov    eax,0xe
  abe9ee:	0f 45 c1             	cmovne eax,ecx
  abe9f1:	eb 05                	jmp    0xabe9f8
  abe9f3:	b8 0e 00 00 00       	mov    eax,0xe
  abe9f8:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  abe9fc:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  abea00:	75 0f                	jne    0xabea11
  abea02:	48 83 c4 18          	add    rsp,0x18
  abea06:	5b                   	pop    rbx
  abea07:	41 5c                	pop    r12
  abea09:	41 5d                	pop    r13
  abea0b:	41 5e                	pop    r14
  abea0d:	41 5f                	pop    r15
  abea0f:	5d                   	pop    rbp
  abea10:	c3                   	ret
  abea11:	e8 9a ec c3 ff       	call   0x6fd6b0
  abea16:	0f 0b                	ud2
  abea18:	90                   	nop
  abea19:	90                   	nop
  abea1a:	90                   	nop
  abea1b:	90                   	nop
  abea1c:	90                   	nop
  abea1d:	90                   	nop
  abea1e:	90                   	nop
  abea1f:	90                   	nop
  abea20:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  abea24:	4c 8b 58 68          	mov    r11,QWORD PTR [rax+0x68]
  abea28:	4d 85 db             	test   r11,r11
  abea2b:	74 1f                	je     0xabea4c
  abea2d:	48 8d 05 94 2e 7b ff 	lea    rax,[rip+0xffffffffff7b2e94]        # 0x2718c8
  abea34:	4c 29 d8             	sub    rax,r11
  abea37:	48 c1 c8 03          	ror    rax,0x3
  abea3b:	48 83 f8 05          	cmp    rax,0x5
  abea3f:	77 11                	ja     0xabea52
  abea41:	45 0f b7 c0          	movzx  r8d,r8w
  abea45:	45 0f b7 c9          	movzx  r9d,r9w
  abea49:	41 ff e3             	jmp    r11
  abea4c:	b8 13 00 00 00       	mov    eax,0x13
  abea51:	c3                   	ret
  abea52:	55                   	push   rbp
  abea53:	48 89 e5             	mov    rbp,rsp
  abea56:	41 57                	push   r15
  abea58:	41 56                	push   r14
  abea5a:	41 55                	push   r13
  abea5c:	41 54                	push   r12
  abea5e:	53                   	push   rbx
  abea5f:	48 83 ec 18          	sub    rsp,0x18
  abea63:	48 8d 05 d6 a2 dc 01 	lea    rax,[rip+0x1dca2d6]        # 0x2888d40
  abea6a:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
  abea6e:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
  abea72:	4c 89 de             	mov    rsi,r11
  abea75:	49 89 cf             	mov    r15,rcx
  abea78:	48 89 d3             	mov    rbx,rdx
  abea7b:	45 89 cc             	mov    r12d,r9d
  abea7e:	45 89 c5             	mov    r13d,r8d
  abea81:	4d 89 de             	mov    r14,r11
  abea84:	48 89 c7             	mov    rdi,rax
  abea87:	e8 34 0e 99 ff       	call   0x44f8c0
  abea8c:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  abea90:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
  abea94:	4d 89 f3             	mov    r11,r14
  abea97:	45 89 e8             	mov    r8d,r13d
  abea9a:	45 89 e1             	mov    r9d,r12d
  abea9d:	48 89 da             	mov    rdx,rbx
  abeaa0:	4c 89 f9             	mov    rcx,r15
  abeaa3:	48 83 c4 18          	add    rsp,0x18
  abeaa7:	5b                   	pop    rbx
  abeaa8:	41 5c                	pop    r12
  abeaaa:	41 5d                	pop    r13
  abeaac:	41 5e                	pop    r14
  abeaae:	41 5f                	pop    r15
  abeab0:	5d                   	pop    rbp
  abeab1:	eb 8e                	jmp    0xabea41
  abeab3:	90                   	nop
  abeab4:	90                   	nop
  abeab5:	90                   	nop
  abeab6:	90                   	nop
  abeab7:	90                   	nop
  abeab8:	90                   	nop
  abeab9:	90                   	nop
  abeaba:	90                   	nop
  abeabb:	90                   	nop
  abeabc:	90                   	nop
  abeabd:	90                   	nop
  abeabe:	90                   	nop
  abeabf:	90                   	nop
  abeac0:	55                   	push   rbp
  abeac1:	48 89 e5             	mov    rbp,rsp
  abeac4:	48 8d 3d 6e d2 7d 00 	lea    rdi,[rip+0x7dd26e]        # 0x129bd39
  abeacb:	be 28 00 00 00       	mov    esi,0x28
  abead0:	31 d2                	xor    edx,edx
  abead2:	31 c9                	xor    ecx,ecx
  abead4:	45 31 c0             	xor    r8d,r8d
  abead7:	45 31 c9             	xor    r9d,r9d
  abeada:	6a 00                	push   0x0
  abeadc:	6a 07                	push   0x7
  abeade:	e8 fd c5 97 ff       	call   0x43b0e0
  abeae3:	48 83 c4 10          	add    rsp,0x10
  abeae7:	48 89 05 2a 83 13 03 	mov    QWORD PTR [rip+0x313832a],rax        # 0x3bf6e18
  abeaee:	5d                   	pop    rbp
  abeaef:	c3                   	ret
  abeaf0:	55                   	push   rbp
  abeaf1:	48 89 e5             	mov    rbp,rsp
  abeaf4:	41 57                	push   r15
  abeaf6:	41 56                	push   r14
  abeaf8:	41 54                	push   r12
  abeafa:	53                   	push   rbx
  abeafb:	89 fb                	mov    ebx,edi
  abeafd:	e8 5e 98 02 00       	call   0xae8360
  abeb02:	41 89 c7             	mov    r15d,eax
  abeb05:	85 c0                	test   eax,eax
  abeb07:	78 05                	js     0xabeb0e
  abeb09:	45 89 fc             	mov    r12d,r15d
  abeb0c:	eb 23                	jmp    0xabeb31
  abeb0e:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  abeb15:	00 00 
  abeb17:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  abeb1e:	e8 ed ad b4 ff       	call   0x609910
  abeb23:	41 be 00 00 00 00    	mov    r14d,0x0
  abeb29:	45 31 e4             	xor    r12d,r12d
  abeb2c:	83 f8 01             	cmp    eax,0x1
  abeb2f:	75 1b                	jne    0xabeb4c
  abeb31:	41 be 05 00 00 00    	mov    r14d,0x5
  abeb37:	83 fb 02             	cmp    ebx,0x2
  abeb3a:	74 0d                	je     0xabeb49
  abeb3c:	e8 4f d8 02 00       	call   0xaec390
  abeb41:	45 31 f6             	xor    r14d,r14d
  abeb44:	83 f8 01             	cmp    eax,0x1
  abeb47:	75 17                	jne    0xabeb60
  abeb49:	45 89 e7             	mov    r15d,r12d
  abeb4c:	44 89 ff             	mov    edi,r15d
  abeb4f:	e8 ec 98 02 00       	call   0xae8440
  abeb54:	44 89 f0             	mov    eax,r14d
  abeb57:	5b                   	pop    rbx
  abeb58:	41 5c                	pop    r12
  abeb5a:	41 5e                	pop    r14
  abeb5c:	41 5f                	pop    r15
  abeb5e:	5d                   	pop    rbp
  abeb5f:	c3                   	ret
  abeb60:	85 db                	test   ebx,ebx
  abeb62:	74 1a                	je     0xabeb7e
  abeb64:	83 fb 04             	cmp    ebx,0x4
  abeb67:	74 0d                	je     0xabeb76
  abeb69:	83 fb 03             	cmp    ebx,0x3
  abeb6c:	75 18                	jne    0xabeb86
  abeb6e:	41 be 04 00 00 00    	mov    r14d,0x4
  abeb74:	eb d3                	jmp    0xabeb49
  abeb76:	41 be 0a 00 00 00    	mov    r14d,0xa
  abeb7c:	eb cb                	jmp    0xabeb49
  abeb7e:	41 be 03 00 00 00    	mov    r14d,0x3
  abeb84:	eb c3                	jmp    0xabeb49
  abeb86:	e8 a5 e0 02 00       	call   0xaecc30
  abeb8b:	31 c9                	xor    ecx,ecx
  abeb8d:	83 f8 01             	cmp    eax,0x1
  abeb90:	0f 94 c1             	sete   cl
  abeb93:	44 8d 34 89          	lea    r14d,[rcx+rcx*4]
  abeb97:	eb b0                	jmp    0xabeb49
  abeb99:	90                   	nop
  abeb9a:	90                   	nop
  abeb9b:	90                   	nop
  abeb9c:	90                   	nop
  abeb9d:	90                   	nop
  abeb9e:	90                   	nop
  abeb9f:	90                   	nop
  abeba0:	55                   	push   rbp
  abeba1:	48 89 e5             	mov    rbp,rsp
  abeba4:	41 57                	push   r15
  abeba6:	41 56                	push   r14
  abeba8:	41 55                	push   r13
  abebaa:	41 54                	push   r12
  abebac:	53                   	push   rbx
  abebad:	50                   	push   rax
  abebae:	49 89 d6             	mov    r14,rdx
  abebb1:	49 89 f7             	mov    r15,rsi
  abebb4:	41 89 fd             	mov    r13d,edi
  abebb7:	e8 a4 97 02 00       	call   0xae8360
  abebbc:	89 c3                	mov    ebx,eax
  abebbe:	41 89 c4             	mov    r12d,eax
  abebc1:	85 c0                	test   eax,eax
  abebc3:	78 46                	js     0xabec0b
  abebc5:	4c 89 ff             	mov    rdi,r15
  abebc8:	e8 a3 db 02 00       	call   0xaec770
  abebcd:	41 89 c4             	mov    r12d,eax
  abebd0:	85 c0                	test   eax,eax
  abebd2:	75 37                	jne    0xabec0b
  abebd4:	41 bc 02 02 0d 80    	mov    r12d,0x800d0202
  abebda:	41 83 fd 04          	cmp    r13d,0x4
  abebde:	77 2b                	ja     0xabec0b
  abebe0:	44 89 e8             	mov    eax,r13d
  abebe3:	48 8d 0d 46 28 3d 00 	lea    rcx,[rip+0x3d2846]        # 0xe91430
  abebea:	48 8d 04 40          	lea    rax,[rax+rax*2]
  abebee:	4c 3b 74 c1 08       	cmp    r14,QWORD PTR [rcx+rax*8+0x8]
  abebf3:	72 16                	jb     0xabec0b
  abebf5:	48 8d 04 c1          	lea    rax,[rcx+rax*8]
  abebf9:	4c 89 ff             	mov    rdi,r15
  abebfc:	4c 89 f2             	mov    rdx,r14
  abebff:	48 8b 70 10          	mov    rsi,QWORD PTR [rax+0x10]
  abec03:	e8 e8 a6 02 00       	call   0xae92f0
  abec08:	45 31 e4             	xor    r12d,r12d
  abec0b:	89 df                	mov    edi,ebx
  abec0d:	e8 2e 98 02 00       	call   0xae8440
  abec12:	44 89 e0             	mov    eax,r12d
  abec15:	48 83 c4 08          	add    rsp,0x8
  abec19:	5b                   	pop    rbx
  abec1a:	41 5c                	pop    r12
  abec1c:	41 5d                	pop    r13
  abec1e:	41 5e                	pop    r14
  abec20:	41 5f                	pop    r15
  abec22:	5d                   	pop    rbp
  abec23:	c3                   	ret
  abec24:	90                   	nop
  abec25:	90                   	nop
  abec26:	90                   	nop
  abec27:	90                   	nop
  abec28:	90                   	nop
  abec29:	90                   	nop
  abec2a:	90                   	nop
  abec2b:	90                   	nop
  abec2c:	90                   	nop
  abec2d:	90                   	nop
  abec2e:	90                   	nop
  abec2f:	90                   	nop
  abec30:	55                   	push   rbp
  abec31:	48 89 e5             	mov    rbp,rsp
  abec34:	41 57                	push   r15
  abec36:	41 56                	push   r14
  abec38:	41 55                	push   r13
  abec3a:	41 54                	push   r12
  abec3c:	53                   	push   rbx
  abec3d:	50                   	push   rax
  abec3e:	49 89 d6             	mov    r14,rdx
  abec41:	49 89 f7             	mov    r15,rsi
  abec44:	41 89 fd             	mov    r13d,edi
  abec47:	e8 14 97 02 00       	call   0xae8360
  abec4c:	89 c3                	mov    ebx,eax
  abec4e:	41 89 c4             	mov    r12d,eax
  abec51:	85 c0                	test   eax,eax
  abec53:	78 46                	js     0xabec9b
  abec55:	4c 89 ff             	mov    rdi,r15
  abec58:	e8 13 db 02 00       	call   0xaec770
  abec5d:	41 89 c4             	mov    r12d,eax
  abec60:	85 c0                	test   eax,eax
  abec62:	75 37                	jne    0xabec9b
  abec64:	41 bc 02 02 0d 80    	mov    r12d,0x800d0202
  abec6a:	41 83 fd 03          	cmp    r13d,0x3
  abec6e:	77 2b                	ja     0xabec9b
  abec70:	44 89 e8             	mov    eax,r13d
  abec73:	48 8d 0d 56 28 3d 00 	lea    rcx,[rip+0x3d2856]        # 0xe914d0
  abec7a:	48 8d 04 40          	lea    rax,[rax+rax*2]
  abec7e:	4c 3b 74 c1 08       	cmp    r14,QWORD PTR [rcx+rax*8+0x8]
  abec83:	72 16                	jb     0xabec9b
  abec85:	48 8d 04 c1          	lea    rax,[rcx+rax*8]
  abec89:	4c 89 ff             	mov    rdi,r15
  abec8c:	4c 89 f2             	mov    rdx,r14
  abec8f:	48 8b 70 10          	mov    rsi,QWORD PTR [rax+0x10]
  abec93:	e8 58 a6 02 00       	call   0xae92f0
  abec98:	45 31 e4             	xor    r12d,r12d
  abec9b:	89 df                	mov    edi,ebx
  abec9d:	e8 9e 97 02 00       	call   0xae8440
  abeca2:	44 89 e0             	mov    eax,r12d
  abeca5:	48 83 c4 08          	add    rsp,0x8
  abeca9:	5b                   	pop    rbx
  abecaa:	41 5c                	pop    r12
  abecac:	41 5d                	pop    r13
  abecae:	41 5e                	pop    r14
  abecb0:	41 5f                	pop    r15
  abecb2:	5d                   	pop    rbp
  abecb3:	c3                   	ret
  abecb4:	90                   	nop
  abecb5:	90                   	nop
  abecb6:	90                   	nop
  abecb7:	90                   	nop
  abecb8:	90                   	nop
  abecb9:	90                   	nop
  abecba:	90                   	nop
  abecbb:	90                   	nop
  abecbc:	90                   	nop
  abecbd:	90                   	nop
  abecbe:	90                   	nop
  abecbf:	90                   	nop
  abecc0:	55                   	push   rbp
  abecc1:	48 89 e5             	mov    rbp,rsp
  abecc4:	41 57                	push   r15
  abecc6:	41 56                	push   r14
  abecc8:	41 55                	push   r13
  abecca:	41 54                	push   r12
  abeccc:	53                   	push   rbx
  abeccd:	50                   	push   rax
  abecce:	49 89 d6             	mov    r14,rdx
  abecd1:	49 89 f7             	mov    r15,rsi
  abecd4:	41 89 fd             	mov    r13d,edi
  abecd7:	e8 84 96 02 00       	call   0xae8360
  abecdc:	89 c3                	mov    ebx,eax
  abecde:	41 89 c4             	mov    r12d,eax
  abece1:	85 c0                	test   eax,eax
  abece3:	78 46                	js     0xabed2b
  abece5:	4c 89 ff             	mov    rdi,r15
  abece8:	e8 83 da 02 00       	call   0xaec770
  abeced:	41 89 c4             	mov    r12d,eax
  abecf0:	85 c0                	test   eax,eax
  abecf2:	75 37                	jne    0xabed2b
  abecf4:	41 bc 02 02 0d 80    	mov    r12d,0x800d0202
  abecfa:	41 83 fd 09          	cmp    r13d,0x9
  abecfe:	77 2b                	ja     0xabed2b
  abed00:	44 89 e8             	mov    eax,r13d
  abed03:	48 8d 0d 26 28 3d 00 	lea    rcx,[rip+0x3d2826]        # 0xe91530
  abed0a:	48 8d 04 40          	lea    rax,[rax+rax*2]
  abed0e:	4c 3b 74 c1 08       	cmp    r14,QWORD PTR [rcx+rax*8+0x8]
  abed13:	72 16                	jb     0xabed2b
  abed15:	48 8d 04 c1          	lea    rax,[rcx+rax*8]
  abed19:	4c 89 ff             	mov    rdi,r15
  abed1c:	4c 89 f2             	mov    rdx,r14
  abed1f:	48 8b 70 10          	mov    rsi,QWORD PTR [rax+0x10]
  abed23:	e8 c8 a5 02 00       	call   0xae92f0
  abed28:	45 31 e4             	xor    r12d,r12d
  abed2b:	89 df                	mov    edi,ebx
  abed2d:	e8 0e 97 02 00       	call   0xae8440
  abed32:	44 89 e0             	mov    eax,r12d
  abed35:	48 83 c4 08          	add    rsp,0x8
  abed39:	5b                   	pop    rbx
  abed3a:	41 5c                	pop    r12
  abed3c:	41 5d                	pop    r13
  abed3e:	41 5e                	pop    r14
  abed40:	41 5f                	pop    r15
  abed42:	5d                   	pop    rbp
  abed43:	c3                   	ret
  abed44:	90                   	nop
  abed45:	90                   	nop
  abed46:	90                   	nop
  abed47:	90                   	nop
  abed48:	90                   	nop
  abed49:	90                   	nop
  abed4a:	90                   	nop
  abed4b:	90                   	nop
  abed4c:	90                   	nop
  abed4d:	90                   	nop
  abed4e:	90                   	nop
  abed4f:	90                   	nop
  abed50:	55                   	push   rbp
  abed51:	48 89 e5             	mov    rbp,rsp
  abed54:	41 57                	push   r15
  abed56:	41 56                	push   r14
  abed58:	41 55                	push   r13
  abed5a:	41 54                	push   r12
  abed5c:	53                   	push   rbx
  abed5d:	50                   	push   rax
  abed5e:	49 89 d6             	mov    r14,rdx
  abed61:	49 89 f7             	mov    r15,rsi
  abed64:	41 89 fc             	mov    r12d,edi
  abed67:	e8 f4 95 02 00       	call   0xae8360
  abed6c:	89 c3                	mov    ebx,eax
  abed6e:	41 89 c5             	mov    r13d,eax
  abed71:	85 c0                	test   eax,eax
  abed73:	78 3b                	js     0xabedb0
  abed75:	4c 89 ff             	mov    rdi,r15
  abed78:	e8 f3 d9 02 00       	call   0xaec770
  abed7d:	41 89 c5             	mov    r13d,eax
  abed80:	85 c0                	test   eax,eax
  abed82:	75 2c                	jne    0xabedb0
  abed84:	45 85 e4             	test   r12d,r12d
  abed87:	41 bd 02 02 0d 80    	mov    r13d,0x800d0202
  abed8d:	0f 95 c0             	setne  al
  abed90:	49 83 fe 21          	cmp    r14,0x21
  abed94:	0f 92 c1             	setb   cl
  abed97:	08 c1                	or     cl,al
  abed99:	75 15                	jne    0xabedb0
  abed9b:	48 8d 35 3e d3 e1 00 	lea    rsi,[rip+0xe1d33e]        # 0x18dc0e0
  abeda2:	4c 89 ff             	mov    rdi,r15
  abeda5:	4c 89 f2             	mov    rdx,r14
  abeda8:	e8 43 a5 02 00       	call   0xae92f0
  abedad:	45 31 ed             	xor    r13d,r13d
  abedb0:	89 df                	mov    edi,ebx
  abedb2:	e8 89 96 02 00       	call   0xae8440
  abedb7:	44 89 e8             	mov    eax,r13d
  abedba:	48 83 c4 08          	add    rsp,0x8
  abedbe:	5b                   	pop    rbx
  abedbf:	41 5c                	pop    r12
  abedc1:	41 5d                	pop    r13
  abedc3:	41 5e                	pop    r14
  abedc5:	41 5f                	pop    r15
  abedc7:	5d                   	pop    rbp
  abedc8:	c3                   	ret
  abedc9:	90                   	nop
  abedca:	90                   	nop
  abedcb:	90                   	nop
  abedcc:	90                   	nop
  abedcd:	90                   	nop
  abedce:	90                   	nop
  abedcf:	90                   	nop
  abedd0:	55                   	push   rbp
  abedd1:	48 89 e5             	mov    rbp,rsp
  abedd4:	53                   	push   rbx
  abedd5:	50                   	push   rax
  abedd6:	89 fb                	mov    ebx,edi
  abedd8:	e8 83 95 02 00       	call   0xae8360
  abeddd:	85 c0                	test   eax,eax
  abeddf:	0f 98 c1             	sets   cl
  abede2:	83 fb 05             	cmp    ebx,0x5
  abede5:	0f 93 c2             	setae  dl
  abede8:	08 ca                	or     dl,cl
  abedea:	74 04                	je     0xabedf0
  abedec:	31 db                	xor    ebx,ebx
  abedee:	eb 1a                	jmp    0xabee0a
  abedf0:	89 d9                	mov    ecx,ebx
  abedf2:	48 8d 15 37 26 3d 00 	lea    rdx,[rip+0x3d2637]        # 0xe91430
  abedf9:	48 8d 0c 49          	lea    rcx,[rcx+rcx*2]
  abedfd:	8b 0c ca             	mov    ecx,DWORD PTR [rdx+rcx*8]
  abee00:	89 ca                	mov    edx,ecx
  abee02:	c1 fa 1f             	sar    edx,0x1f
  abee05:	c4 e2 68 f2 d9       	andn   ebx,edx,ecx
  abee0a:	89 c7                	mov    edi,eax
  abee0c:	e8 2f 96 02 00       	call   0xae8440
  abee11:	48 89 d8             	mov    rax,rbx
  abee14:	48 83 c4 08          	add    rsp,0x8
  abee18:	5b                   	pop    rbx
  abee19:	5d                   	pop    rbp
  abee1a:	c3                   	ret
  abee1b:	90                   	nop
  abee1c:	90                   	nop
  abee1d:	90                   	nop
  abee1e:	90                   	nop
  abee1f:	90                   	nop
  abee20:	55                   	push   rbp
  abee21:	48 89 e5             	mov    rbp,rsp
  abee24:	41 57                	push   r15
  abee26:	41 56                	push   r14
  abee28:	41 55                	push   r13
  abee2a:	41 54                	push   r12
  abee2c:	53                   	push   rbx
  abee2d:	50                   	push   rax
  abee2e:	49 89 d6             	mov    r14,rdx
  abee31:	49 89 f7             	mov    r15,rsi
  abee34:	41 89 fd             	mov    r13d,edi
  abee37:	e8 24 95 02 00       	call   0xae8360
  abee3c:	89 c3                	mov    ebx,eax
  abee3e:	41 89 c4             	mov    r12d,eax
  abee41:	85 c0                	test   eax,eax
  abee43:	0f 88 ff 00 00 00    	js     0xabef48
  abee49:	e8 c2 f8 02 00       	call   0xaee710
  abee4e:	85 c0                	test   eax,eax
  abee50:	74 08                	je     0xabee5a
  abee52:	41 89 c4             	mov    r12d,eax
  abee55:	e9 ee 00 00 00       	jmp    0xabef48
  abee5a:	80 3d c3 7f 13 03 01 	cmp    BYTE PTR [rip+0x3137fc3],0x1        # 0x3bf6e24
  abee61:	41 bc 03 06 0d 80    	mov    r12d,0x800d0603
  abee67:	0f 85 db 00 00 00    	jne    0xabef48
  abee6d:	4c 89 ff             	mov    rdi,r15
  abee70:	e8 fb d8 02 00       	call   0xaec770
  abee75:	85 c0                	test   eax,eax
  abee77:	75 d9                	jne    0xabee52
  abee79:	41 83 fd 04          	cmp    r13d,0x4
  abee7d:	76 0b                	jbe    0xabee8a
  abee7f:	41 bc 02 02 0d 80    	mov    r12d,0x800d0202
  abee85:	e9 be 00 00 00       	jmp    0xabef48
  abee8a:	44 89 e9             	mov    ecx,r13d
  abee8d:	48 8d 05 9c 7f 13 03 	lea    rax,[rip+0x3137f9c]        # 0x3bf6e30
  abee94:	48 8b 3c c8          	mov    rdi,QWORD PTR [rax+rcx*8]
  abee98:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  abee9c:	e8 cf d8 02 00       	call   0xaec770
  abeea1:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
  abeea5:	85 c0                	test   eax,eax
  abeea7:	0f 85 9b 00 00 00    	jne    0xabef48
  abeead:	48 8d 04 52          	lea    rax,[rdx+rdx*2]
  abeeb1:	48 8d 0d 78 25 3d 00 	lea    rcx,[rip+0x3d2578]        # 0xe91430
  abeeb8:	41 bc 02 02 0d 80    	mov    r12d,0x800d0202
  abeebe:	4c 3b 34 c1          	cmp    r14,QWORD PTR [rcx+rax*8]
  abeec2:	0f 87 80 00 00 00    	ja     0xabef48
  abeec8:	41 83 fd 04          	cmp    r13d,0x4
  abeecc:	77 61                	ja     0xabef2f
  abeece:	48 8d 05 07 d1 e1 00 	lea    rax,[rip+0xe1d107]        # 0x18dbfdc
  abeed5:	41 bd 0c 00 00 00    	mov    r13d,0xc
  abeedb:	48 63 0c 90          	movsxd rcx,DWORD PTR [rax+rdx*4]
  abeedf:	48 01 c1             	add    rcx,rax
  abeee2:	ff e1                	jmp    rcx
  abeee4:	49 89 d4             	mov    r12,rdx
  abeee7:	e8 94 76 a0 ff       	call   0x4c6580
  abeeec:	4c 89 e2             	mov    rdx,r12
  abeeef:	41 bd 10 00 00 00    	mov    r13d,0x10
  abeef5:	45 31 e4             	xor    r12d,r12d
  abeef8:	83 f8 01             	cmp    eax,0x1
  abeefb:	75 08                	jne    0xabef05
  abeefd:	eb 49                	jmp    0xabef48
  abeeff:	41 bd 04 00 00 00    	mov    r13d,0x4
  abef05:	4c 8d 25 24 7f 13 03 	lea    r12,[rip+0x3137f24]        # 0x3bf6e30
  abef0c:	4c 89 fe             	mov    rsi,r15
  abef0f:	49 89 d7             	mov    r15,rdx
  abef12:	49 8b 3c d4          	mov    rdi,QWORD PTR [r12+rdx*8]
  abef16:	4c 89 f2             	mov    rdx,r14
  abef19:	e8 92 a1 79 ff       	call   0x2590b0
  abef1e:	4b 8b 3c fc          	mov    rdi,QWORD PTR [r12+r15*8]
  abef22:	4c 89 f6             	mov    rsi,r14
  abef25:	4c 89 ea             	mov    rdx,r13
  abef28:	e8 43 00 00 00       	call   0xabef70
  abef2d:	eb 16                	jmp    0xabef45
  abef2f:	48 8d 05 fa 7e 13 03 	lea    rax,[rip+0x3137efa]        # 0x3bf6e30
  abef36:	4c 89 fe             	mov    rsi,r15
  abef39:	48 8b 3c d0          	mov    rdi,QWORD PTR [rax+rdx*8]
  abef3d:	4c 89 f2             	mov    rdx,r14
  abef40:	e8 6b a1 79 ff       	call   0x2590b0
  abef45:	45 31 e4             	xor    r12d,r12d
  abef48:	89 df                	mov    edi,ebx
  abef4a:	e8 f1 94 02 00       	call   0xae8440
  abef4f:	44 89 e0             	mov    eax,r12d
  abef52:	48 83 c4 08          	add    rsp,0x8
  abef56:	5b                   	pop    rbx
  abef57:	41 5c                	pop    r12
  abef59:	41 5d                	pop    r13
  abef5b:	41 5e                	pop    r14
  abef5d:	41 5f                	pop    r15
  abef5f:	5d                   	pop    rbp
  abef60:	c3                   	ret
  abef61:	90                   	nop
  abef62:	90                   	nop
  abef63:	90                   	nop
  abef64:	90                   	nop
  abef65:	90                   	nop
  abef66:	90                   	nop
  abef67:	90                   	nop
  abef68:	90                   	nop
  abef69:	90                   	nop
  abef6a:	90                   	nop
  abef6b:	90                   	nop
  abef6c:	90                   	nop
  abef6d:	90                   	nop
  abef6e:	90                   	nop
  abef6f:	90                   	nop
  abef70:	48 85 ff             	test   rdi,rdi
  abef73:	0f 94 c0             	sete   al
  abef76:	48 85 f6             	test   rsi,rsi
  abef79:	0f 94 c1             	sete   cl
  abef7c:	08 c1                	or     cl,al
  abef7e:	48 85 d2             	test   rdx,rdx
  abef81:	0f 94 c0             	sete   al
  abef84:	08 c8                	or     al,cl
  abef86:	75 6f                	jne    0xabeff7
  abef88:	48 89 d0             	mov    rax,rdx
  abef8b:	48 09 f0             	or     rax,rsi
  abef8e:	48 c1 e8 20          	shr    rax,0x20
  abef92:	74 0a                	je     0xabef9e
  abef94:	48 89 d0             	mov    rax,rdx
  abef97:	31 d2                	xor    edx,edx
  abef99:	48 f7 f6             	div    rsi
  abef9c:	eb 06                	jmp    0xabefa4
  abef9e:	89 d0                	mov    eax,edx
  abefa0:	31 d2                	xor    edx,edx
  abefa2:	f7 f6                	div    esi
  abefa4:	55                   	push   rbp
  abefa5:	48 89 e5             	mov    rbp,rsp
  abefa8:	53                   	push   rbx
  abefa9:	0f b6 04 17          	movzx  eax,BYTE PTR [rdi+rdx*1]
  abefad:	4c 8d 0d 4c b3 8f 00 	lea    r9,[rip+0x8fb34c]        # 0x13ba300
  abefb4:	45 31 c0             	xor    r8d,r8d
  abefb7:	45 31 d2             	xor    r10d,r10d
  abefba:	0f b6 c8             	movzx  ecx,al
  abefbd:	eb 09                	jmp    0xabefc8
  abefbf:	90                   	nop
  abefc0:	49 ff c2             	inc    r10
  abefc3:	4c 39 d6             	cmp    rsi,r10
  abefc6:	74 2a                	je     0xabeff2
  abefc8:	46 0f b6 1c 17       	movzx  r11d,BYTE PTR [rdi+r10*1]
  abefcd:	45 84 db             	test   r11b,r11b
  abefd0:	74 ee                	je     0xabefc0
  abefd2:	42 8d 1c 11          	lea    ebx,[rcx+r10*1]
  abefd6:	83 e3 0f             	and    ebx,0xf
  abefd9:	42 0f b6 1c 0b       	movzx  ebx,BYTE PTR [rbx+r9*1]
  abefde:	41 38 db             	cmp    r11b,bl
  abefe1:	45 0f b6 db          	movzx  r11d,r11b
  abefe5:	45 0f 44 d8          	cmove  r11d,r8d
  abefe9:	41 30 db             	xor    r11b,bl
  abefec:	46 88 1c 17          	mov    BYTE PTR [rdi+r10*1],r11b
  abeff0:	eb ce                	jmp    0xabefc0
  abeff2:	88 04 17             	mov    BYTE PTR [rdi+rdx*1],al
  abeff5:	5b                   	pop    rbx
  abeff6:	5d                   	pop    rbp
  abeff7:	c3                   	ret
  abeff8:	90                   	nop
  abeff9:	90                   	nop
  abeffa:	90                   	nop
  abeffb:	90                   	nop
  abeffc:	90                   	nop
  abeffd:	90                   	nop
  abeffe:	90                   	nop
  abefff:	90                   	nop
  abf000:	55                   	push   rbp
  abf001:	48 89 e5             	mov    rbp,rsp
  abf004:	41 57                	push   r15
  abf006:	41 56                	push   r14
  abf008:	41 55                	push   r13
  abf00a:	41 54                	push   r12
  abf00c:	53                   	push   rbx
  abf00d:	50                   	push   rax
  abf00e:	49 89 d6             	mov    r14,rdx
  abf011:	49 89 f7             	mov    r15,rsi
  abf014:	41 89 fc             	mov    r12d,edi
  abf017:	e8 44 93 02 00       	call   0xae8360
  abf01c:	89 c3                	mov    ebx,eax
  abf01e:	41 89 c5             	mov    r13d,eax
  abf021:	85 c0                	test   eax,eax
  abf023:	0f 88 b0 00 00 00    	js     0xabf0d9
  abf029:	e8 e2 f6 02 00       	call   0xaee710
  abf02e:	85 c0                	test   eax,eax
  abf030:	74 08                	je     0xabf03a
  abf032:	41 89 c5             	mov    r13d,eax
  abf035:	e9 9f 00 00 00       	jmp    0xabf0d9
  abf03a:	80 3d e3 7d 13 03 01 	cmp    BYTE PTR [rip+0x3137de3],0x1        # 0x3bf6e24
  abf041:	41 bd 03 06 0d 80    	mov    r13d,0x800d0603
  abf047:	0f 85 8c 00 00 00    	jne    0xabf0d9
  abf04d:	4c 89 ff             	mov    rdi,r15
  abf050:	e8 1b d7 02 00       	call   0xaec770
  abf055:	85 c0                	test   eax,eax
  abf057:	75 d9                	jne    0xabf032
  abf059:	41 bd 02 02 0d 80    	mov    r13d,0x800d0202
  abf05f:	41 83 fc 04          	cmp    r12d,0x4
  abf063:	77 74                	ja     0xabf0d9
  abf065:	44 89 e2             	mov    edx,r12d
  abf068:	48 8d 0d c1 23 3d 00 	lea    rcx,[rip+0x3d23c1]        # 0xe91430
  abf06f:	48 8d 04 52          	lea    rax,[rdx+rdx*2]
  abf073:	4c 3b 34 c1          	cmp    r14,QWORD PTR [rcx+rax*8]
  abf077:	77 60                	ja     0xabf0d9
  abf079:	44 89 e7             	mov    edi,r12d
  abf07c:	49 89 d5             	mov    r13,rdx
  abf07f:	e8 bc 00 03 00       	call   0xaef140
  abf084:	b8 17 00 00 00       	mov    eax,0x17
  abf089:	44 0f a3 e0          	bt     eax,r12d
  abf08d:	73 31                	jae    0xabf0c0
  abf08f:	48 8d 0d 9a 7d 13 03 	lea    rcx,[rip+0x3137d9a]        # 0x3bf6e30
  abf096:	48 8d 05 6b d1 e1 00 	lea    rax,[rip+0xe1d16b]        # 0x18dc208
  abf09d:	4c 89 ff             	mov    rdi,r15
  abf0a0:	4c 89 f2             	mov    rdx,r14
  abf0a3:	4a 8b 34 e9          	mov    rsi,QWORD PTR [rcx+r13*8]
  abf0a7:	4e 8b 24 e8          	mov    r12,QWORD PTR [rax+r13*8]
  abf0ab:	e8 00 a0 79 ff       	call   0x2590b0
  abf0b0:	4c 89 ff             	mov    rdi,r15
  abf0b3:	4c 89 f6             	mov    rsi,r14
  abf0b6:	4c 89 e2             	mov    rdx,r12
  abf0b9:	e8 b2 fe ff ff       	call   0xabef70
  abf0be:	eb 16                	jmp    0xabf0d6
  abf0c0:	48 8d 05 69 7d 13 03 	lea    rax,[rip+0x3137d69]        # 0x3bf6e30
  abf0c7:	4c 89 ff             	mov    rdi,r15
  abf0ca:	4c 89 f2             	mov    rdx,r14
  abf0cd:	4a 8b 34 e8          	mov    rsi,QWORD PTR [rax+r13*8]
  abf0d1:	e8 da 9f 79 ff       	call   0x2590b0
  abf0d6:	45 31 ed             	xor    r13d,r13d
  abf0d9:	89 df                	mov    edi,ebx
  abf0db:	e8 60 93 02 00       	call   0xae8440
  abf0e0:	44 89 e8             	mov    eax,r13d
  abf0e3:	48 83 c4 08          	add    rsp,0x8
  abf0e7:	5b                   	pop    rbx
  abf0e8:	41 5c                	pop    r12
  abf0ea:	41 5d                	pop    r13
  abf0ec:	41 5e                	pop    r14
  abf0ee:	41 5f                	pop    r15
  abf0f0:	5d                   	pop    rbp
  abf0f1:	c3                   	ret
  abf0f2:	90                   	nop
  abf0f3:	90                   	nop
  abf0f4:	90                   	nop
  abf0f5:	90                   	nop
  abf0f6:	90                   	nop
  abf0f7:	90                   	nop
  abf0f8:	90                   	nop
  abf0f9:	90                   	nop
  abf0fa:	90                   	nop
  abf0fb:	90                   	nop
  abf0fc:	90                   	nop
  abf0fd:	90                   	nop
  abf0fe:	90                   	nop
  abf0ff:	90                   	nop
  abf100:	55                   	push   rbp
  abf101:	48 89 e5             	mov    rbp,rsp
  abf104:	41 56                	push   r14
  abf106:	53                   	push   rbx
  abf107:	e8 54 92 02 00       	call   0xae8360
  abf10c:	89 c3                	mov    ebx,eax
  abf10e:	41 89 c6             	mov    r14d,eax
  abf111:	85 c0                	test   eax,eax
  abf113:	78 15                	js     0xabf12a
  abf115:	e8 76 d2 02 00       	call   0xaec390
  abf11a:	41 89 de             	mov    r14d,ebx
  abf11d:	83 f8 01             	cmp    eax,0x1
  abf120:	74 08                	je     0xabf12a
  abf122:	e8 19 00 00 00       	call   0xabf140
  abf127:	41 89 c6             	mov    r14d,eax
  abf12a:	89 df                	mov    edi,ebx
  abf12c:	e8 0f 93 02 00       	call   0xae8440
  abf131:	44 89 f0             	mov    eax,r14d
  abf134:	5b                   	pop    rbx
  abf135:	41 5e                	pop    r14
  abf137:	5d                   	pop    rbp
  abf138:	c3                   	ret
  abf139:	90                   	nop
  abf13a:	90                   	nop
  abf13b:	90                   	nop
  abf13c:	90                   	nop
  abf13d:	90                   	nop
  abf13e:	90                   	nop
  abf13f:	90                   	nop
  abf140:	55                   	push   rbp
  abf141:	48 89 e5             	mov    rbp,rsp
  abf144:	c6 05 0d 7d 13 03 01 	mov    BYTE PTR [rip+0x3137d0d],0x1        # 0x3bf6e58
  abf14b:	e8 30 74 a0 ff       	call   0x4c6580
  abf150:	85 c0                	test   eax,eax
  abf152:	75 13                	jne    0xabf167
  abf154:	bf 01 00 00 00       	mov    edi,0x1
  abf159:	e8 62 b0 aa ff       	call   0x56a1c0
  abf15e:	e8 ed a1 02 00       	call   0xae9350
  abf163:	85 c0                	test   eax,eax
  abf165:	78 38                	js     0xabf19f
  abf167:	bf 02 00 00 00       	mov    edi,0x2
  abf16c:	e8 4f b0 aa ff       	call   0x56a1c0
  abf171:	85 c0                	test   eax,eax
  abf173:	75 2a                	jne    0xabf19f
  abf175:	bf 03 00 00 00       	mov    edi,0x3
  abf17a:	e8 41 b0 aa ff       	call   0x56a1c0
  abf17f:	85 c0                	test   eax,eax
  abf181:	75 1c                	jne    0xabf19f
  abf183:	bf 04 00 00 00       	mov    edi,0x4
  abf188:	e8 33 b0 aa ff       	call   0x56a1c0
  abf18d:	85 c0                	test   eax,eax
  abf18f:	75 0e                	jne    0xabf19f
  abf191:	bf 05 00 00 00       	mov    edi,0x5
  abf196:	e8 25 b0 aa ff       	call   0x56a1c0
  abf19b:	85 c0                	test   eax,eax
  abf19d:	74 02                	je     0xabf1a1
  abf19f:	5d                   	pop    rbp
  abf1a0:	c3                   	ret
  abf1a1:	5d                   	pop    rbp
  abf1a2:	e9 d9 bc 02 00       	jmp    0xaeae80
  abf1a7:	90                   	nop
  abf1a8:	90                   	nop
  abf1a9:	90                   	nop
  abf1aa:	90                   	nop
  abf1ab:	90                   	nop
  abf1ac:	90                   	nop
  abf1ad:	90                   	nop
  abf1ae:	90                   	nop
  abf1af:	90                   	nop
  abf1b0:	55                   	push   rbp
  abf1b1:	48 89 e5             	mov    rbp,rsp
  abf1b4:	41 56                	push   r14
  abf1b6:	53                   	push   rbx
  abf1b7:	e8 a4 91 02 00       	call   0xae8360
  abf1bc:	89 c3                	mov    ebx,eax
  abf1be:	41 89 c6             	mov    r14d,eax
  abf1c1:	85 c0                	test   eax,eax
  abf1c3:	78 08                	js     0xabf1cd
  abf1c5:	e8 06 db 02 00       	call   0xaeccd0
  abf1ca:	41 89 c6             	mov    r14d,eax
  abf1cd:	89 df                	mov    edi,ebx
  abf1cf:	e8 6c 92 02 00       	call   0xae8440
  abf1d4:	44 89 f0             	mov    eax,r14d
  abf1d7:	5b                   	pop    rbx
  abf1d8:	41 5e                	pop    r14
  abf1da:	5d                   	pop    rbp
  abf1db:	c3                   	ret
  abf1dc:	90                   	nop
  abf1dd:	90                   	nop
  abf1de:	90                   	nop
  abf1df:	90                   	nop
  abf1e0:	55                   	push   rbp
  abf1e1:	48 89 e5             	mov    rbp,rsp
  abf1e4:	41 56                	push   r14
  abf1e6:	53                   	push   rbx
  abf1e7:	e8 74 91 02 00       	call   0xae8360
  abf1ec:	89 c3                	mov    ebx,eax
  abf1ee:	85 c0                	test   eax,eax
  abf1f0:	78 14                	js     0xabf206
  abf1f2:	e8 99 d1 02 00       	call   0xaec390
  abf1f7:	45 31 f6             	xor    r14d,r14d
  abf1fa:	83 f8 01             	cmp    eax,0x1
  abf1fd:	41 0f 95 c6          	setne  r14b
  abf201:	45 01 f6             	add    r14d,r14d
  abf204:	eb 03                	jmp    0xabf209
  abf206:	45 31 f6             	xor    r14d,r14d
  abf209:	89 df                	mov    edi,ebx
  abf20b:	e8 30 92 02 00       	call   0xae8440
  abf210:	44 89 f0             	mov    eax,r14d
  abf213:	5b                   	pop    rbx
  abf214:	41 5e                	pop    r14
  abf216:	5d                   	pop    rbp
  abf217:	c3                   	ret
  abf218:	90                   	nop
  abf219:	90                   	nop
  abf21a:	90                   	nop
  abf21b:	90                   	nop
  abf21c:	90                   	nop
  abf21d:	90                   	nop
  abf21e:	90                   	nop
  abf21f:	90                   	nop
  abf220:	55                   	push   rbp
  abf221:	48 89 e5             	mov    rbp,rsp
  abf224:	b8 01 00 00 00       	mov    eax,0x1
  abf229:	83 ff 04             	cmp    edi,0x4
  abf22c:	77 0c                	ja     0xabf23a
  abf22e:	89 f8                	mov    eax,edi
  abf230:	48 8d 0d f9 cf e1 00 	lea    rcx,[rip+0xe1cff9]        # 0x18dc230
  abf237:	8b 04 81             	mov    eax,DWORD PTR [rcx+rax*4]
  abf23a:	5d                   	pop    rbp
  abf23b:	c3                   	ret
  abf23c:	90                   	nop
  abf23d:	90                   	nop
  abf23e:	90                   	nop
  abf23f:	90                   	nop
  abf240:	55                   	push   rbp
  abf241:	48 89 e5             	mov    rbp,rsp
  abf244:	41 57                	push   r15
  abf246:	41 56                	push   r14
  abf248:	41 55                	push   r13
  abf24a:	41 54                	push   r12
  abf24c:	53                   	push   rbx
  abf24d:	50                   	push   rax
  abf24e:	49 89 d6             	mov    r14,rdx
  abf251:	49 89 f7             	mov    r15,rsi
  abf254:	41 89 fd             	mov    r13d,edi
  abf257:	e8 04 91 02 00       	call   0xae8360
  abf25c:	89 c3                	mov    ebx,eax
  abf25e:	41 89 c4             	mov    r12d,eax
  abf261:	85 c0                	test   eax,eax
  abf263:	78 47                	js     0xabf2ac
  abf265:	4c 89 ff             	mov    rdi,r15
  abf268:	e8 03 d5 02 00       	call   0xaec770
  abf26d:	41 89 c4             	mov    r12d,eax
  abf270:	85 c0                	test   eax,eax
  abf272:	75 38                	jne    0xabf2ac
  abf274:	41 bc 02 02 0d 80    	mov    r12d,0x800d0202
  abf27a:	41 83 fd 01          	cmp    r13d,0x1
  abf27e:	77 2c                	ja     0xabf2ac
  abf280:	44 89 e8             	mov    eax,r13d
  abf283:	48 8d 0d 26 22 3d 00 	lea    rcx,[rip+0x3d2226]        # 0xe914b0
  abf28a:	48 c1 e0 04          	shl    rax,0x4
  abf28e:	48 63 54 08 08       	movsxd rdx,DWORD PTR [rax+rcx*1+0x8]
  abf293:	49 39 d6             	cmp    r14,rdx
  abf296:	72 14                	jb     0xabf2ac
  abf298:	48 01 c1             	add    rcx,rax
  abf29b:	4c 89 ff             	mov    rdi,r15
  abf29e:	4c 89 f2             	mov    rdx,r14
  abf2a1:	48 8b 31             	mov    rsi,QWORD PTR [rcx]
  abf2a4:	e8 47 a0 02 00       	call   0xae92f0
  abf2a9:	45 31 e4             	xor    r12d,r12d
  abf2ac:	89 df                	mov    edi,ebx
  abf2ae:	e8 8d 91 02 00       	call   0xae8440
  abf2b3:	44 89 e0             	mov    eax,r12d
  abf2b6:	48 83 c4 08          	add    rsp,0x8
  abf2ba:	5b                   	pop    rbx
  abf2bb:	41 5c                	pop    r12
  abf2bd:	41 5d                	pop    r13
  abf2bf:	41 5e                	pop    r14
  abf2c1:	41 5f                	pop    r15
  abf2c3:	5d                   	pop    rbp
  abf2c4:	c3                   	ret
  abf2c5:	90                   	nop
  abf2c6:	90                   	nop
  abf2c7:	90                   	nop
  abf2c8:	90                   	nop
  abf2c9:	90                   	nop
  abf2ca:	90                   	nop
  abf2cb:	90                   	nop
  abf2cc:	90                   	nop
  abf2cd:	90                   	nop
  abf2ce:	90                   	nop
  abf2cf:	90                   	nop
  abf2d0:	55                   	push   rbp
  abf2d1:	48 89 e5             	mov    rbp,rsp
  abf2d4:	41 56                	push   r14
  abf2d6:	53                   	push   rbx
  abf2d7:	89 fb                	mov    ebx,edi
  abf2d9:	e8 82 90 02 00       	call   0xae8360
  abf2de:	41 89 c6             	mov    r14d,eax
  abf2e1:	85 c0                	test   eax,eax
  abf2e3:	78 1d                	js     0xabf302
  abf2e5:	41 be 02 02 0d 80    	mov    r14d,0x800d0202
  abf2eb:	83 fb 01             	cmp    ebx,0x1
  abf2ee:	77 12                	ja     0xabf302
  abf2f0:	89 d9                	mov    ecx,ebx
  abf2f2:	48 8d 15 b7 21 3d 00 	lea    rdx,[rip+0x3d21b7]        # 0xe914b0
  abf2f9:	48 c1 e1 04          	shl    rcx,0x4
  abf2fd:	44 8b 74 11 0c       	mov    r14d,DWORD PTR [rcx+rdx*1+0xc]
  abf302:	89 c7                	mov    edi,eax
  abf304:	e8 37 91 02 00       	call   0xae8440
  abf309:	44 89 f0             	mov    eax,r14d
  abf30c:	5b                   	pop    rbx
  abf30d:	41 5e                	pop    r14
  abf30f:	5d                   	pop    rbp
  abf310:	c3                   	ret
  abf311:	90                   	nop
  abf312:	90                   	nop
  abf313:	90                   	nop
  abf314:	90                   	nop
  abf315:	90                   	nop
  abf316:	90                   	nop
  abf317:	90                   	nop
  abf318:	90                   	nop
  abf319:	90                   	nop
  abf31a:	90                   	nop
  abf31b:	90                   	nop
  abf31c:	90                   	nop
  abf31d:	90                   	nop
  abf31e:	90                   	nop
  abf31f:	90                   	nop
  abf320:	80 3d fd 7a 13 03 00 	cmp    BYTE PTR [rip+0x3137afd],0x0        # 0x3bf6e24
  abf327:	b8 01 06 0d 80       	mov    eax,0x800d0601
  abf32c:	0f 85 23 01 00 00    	jne    0xabf455
  abf332:	f6 05 1f 7b 13 03 01 	test   BYTE PTR [rip+0x3137b1f],0x1        # 0x3bf6e58
  abf339:	0f 85 16 01 00 00    	jne    0xabf455
  abf33f:	55                   	push   rbp
  abf340:	48 89 e5             	mov    rbp,rsp
  abf343:	48 8d 35 96 ec e0 01 	lea    rsi,[rip+0x1e0ec96]        # 0x28cdfe0
  abf34a:	bf 00 0c 00 00       	mov    edi,0xc00
  abf34f:	ba 01 01 00 00       	mov    edx,0x101
  abf354:	e8 f7 97 14 00       	call   0xc08b50
  abf359:	48 89 c7             	mov    rdi,rax
  abf35c:	b8 11 02 0d 80       	mov    eax,0x800d0211
  abf361:	48 85 ff             	test   rdi,rdi
  abf364:	0f 84 ea 00 00 00    	je     0xabf454
  abf36a:	be 00 0c 00 00       	mov    esi,0xc00
  abf36f:	48 89 3d ba 7a 13 03 	mov    QWORD PTR [rip+0x3137aba],rdi        # 0x3bf6e30
  abf376:	e8 75 9c 79 ff       	call   0x258ff0
  abf37b:	48 8d 35 5e ec e0 01 	lea    rsi,[rip+0x1e0ec5e]        # 0x28cdfe0
  abf382:	bf 00 00 0a 00       	mov    edi,0xa0000
  abf387:	ba 01 01 00 00       	mov    edx,0x101
  abf38c:	e8 bf 97 14 00       	call   0xc08b50
  abf391:	48 85 c0             	test   rax,rax
  abf394:	0f 84 b5 00 00 00    	je     0xabf44f
  abf39a:	be 00 00 0a 00       	mov    esi,0xa0000
  abf39f:	48 89 c7             	mov    rdi,rax
  abf3a2:	48 89 05 8f 7a 13 03 	mov    QWORD PTR [rip+0x3137a8f],rax        # 0x3bf6e38
  abf3a9:	e8 42 9c 79 ff       	call   0x258ff0
  abf3ae:	48 8d 35 2b ec e0 01 	lea    rsi,[rip+0x1e0ec2b]        # 0x28cdfe0
  abf3b5:	bf 00 80 02 00       	mov    edi,0x28000
  abf3ba:	ba 01 01 00 00       	mov    edx,0x101
  abf3bf:	e8 8c 97 14 00       	call   0xc08b50
  abf3c4:	48 85 c0             	test   rax,rax
  abf3c7:	0f 84 82 00 00 00    	je     0xabf44f
  abf3cd:	be 00 80 02 00       	mov    esi,0x28000
  abf3d2:	48 89 c7             	mov    rdi,rax
  abf3d5:	48 89 05 64 7a 13 03 	mov    QWORD PTR [rip+0x3137a64],rax        # 0x3bf6e40
  abf3dc:	e8 0f 9c 79 ff       	call   0x258ff0
  abf3e1:	48 8d 35 f8 eb e0 01 	lea    rsi,[rip+0x1e0ebf8]        # 0x28cdfe0
  abf3e8:	bf 00 40 01 00       	mov    edi,0x14000
  abf3ed:	ba 01 01 00 00       	mov    edx,0x101
  abf3f2:	e8 59 97 14 00       	call   0xc08b50
  abf3f7:	48 85 c0             	test   rax,rax
  abf3fa:	74 53                	je     0xabf44f
  abf3fc:	be 00 40 01 00       	mov    esi,0x14000
  abf401:	48 89 c7             	mov    rdi,rax
  abf404:	48 89 05 3d 7a 13 03 	mov    QWORD PTR [rip+0x3137a3d],rax        # 0x3bf6e48
  abf40b:	e8 e0 9b 79 ff       	call   0x258ff0
  abf410:	48 8d 35 c9 eb e0 01 	lea    rsi,[rip+0x1e0ebc9]        # 0x28cdfe0
  abf417:	bf 00 18 00 00       	mov    edi,0x1800
  abf41c:	ba 01 01 00 00       	mov    edx,0x101
  abf421:	e8 2a 97 14 00       	call   0xc08b50
  abf426:	48 89 c7             	mov    rdi,rax
  abf429:	48 85 c0             	test   rax,rax
  abf42c:	b8 11 02 0d 80       	mov    eax,0x800d0211
  abf431:	74 21                	je     0xabf454
  abf433:	be 00 18 00 00       	mov    esi,0x1800
  abf438:	48 89 3d 11 7a 13 03 	mov    QWORD PTR [rip+0x3137a11],rdi        # 0x3bf6e50
  abf43f:	e8 ac 9b 79 ff       	call   0x258ff0
  abf444:	31 c0                	xor    eax,eax
  abf446:	c6 05 d7 79 13 03 01 	mov    BYTE PTR [rip+0x31379d7],0x1        # 0x3bf6e24
  abf44d:	eb 05                	jmp    0xabf454
  abf44f:	b8 11 02 0d 80       	mov    eax,0x800d0211
  abf454:	5d                   	pop    rbp
  abf455:	c3                   	ret
  abf456:	90                   	nop
  abf457:	90                   	nop
  abf458:	90                   	nop
  abf459:	90                   	nop
  abf45a:	90                   	nop
  abf45b:	90                   	nop
  abf45c:	90                   	nop
  abf45d:	90                   	nop
  abf45e:	90                   	nop
  abf45f:	90                   	nop
  abf460:	55                   	push   rbp
  abf461:	48 89 e5             	mov    rbp,rsp
  abf464:	53                   	push   rbx
  abf465:	50                   	push   rax
  abf466:	48 8d 1d 73 eb e0 01 	lea    rbx,[rip+0x1e0eb73]        # 0x28cdfe0
  abf46d:	48 8b 3d bc 79 13 03 	mov    rdi,QWORD PTR [rip+0x31379bc]        # 0x3bf6e30
  abf474:	48 89 de             	mov    rsi,rbx
  abf477:	e8 74 99 14 00       	call   0xc08df0
  abf47c:	48 c7 05 a9 79 13 03 	mov    QWORD PTR [rip+0x31379a9],0x0        # 0x3bf6e30
  abf483:	00 00 00 00 
  abf487:	48 89 de             	mov    rsi,rbx
  abf48a:	48 8b 3d a7 79 13 03 	mov    rdi,QWORD PTR [rip+0x31379a7]        # 0x3bf6e38
  abf491:	e8 5a 99 14 00       	call   0xc08df0
  abf496:	48 c7 05 97 79 13 03 	mov    QWORD PTR [rip+0x3137997],0x0        # 0x3bf6e38
  abf49d:	00 00 00 00 
  abf4a1:	48 89 de             	mov    rsi,rbx
  abf4a4:	48 8b 3d 95 79 13 03 	mov    rdi,QWORD PTR [rip+0x3137995]        # 0x3bf6e40
  abf4ab:	e8 40 99 14 00       	call   0xc08df0
  abf4b0:	48 c7 05 85 79 13 03 	mov    QWORD PTR [rip+0x3137985],0x0        # 0x3bf6e40
  abf4b7:	00 00 00 00 
  abf4bb:	48 89 de             	mov    rsi,rbx
  abf4be:	48 8b 3d 83 79 13 03 	mov    rdi,QWORD PTR [rip+0x3137983]        # 0x3bf6e48
  abf4c5:	e8 26 99 14 00       	call   0xc08df0
  abf4ca:	48 c7 05 73 79 13 03 	mov    QWORD PTR [rip+0x3137973],0x0        # 0x3bf6e48
  abf4d1:	00 00 00 00 
  abf4d5:	48 89 de             	mov    rsi,rbx
  abf4d8:	48 8b 3d 71 79 13 03 	mov    rdi,QWORD PTR [rip+0x3137971]        # 0x3bf6e50
  abf4df:	e8 0c 99 14 00       	call   0xc08df0
  abf4e4:	48 c7 05 61 79 13 03 	mov    QWORD PTR [rip+0x3137961],0x0        # 0x3bf6e50
  abf4eb:	00 00 00 00 
  abf4ef:	c6 05 2e 79 13 03 00 	mov    BYTE PTR [rip+0x313792e],0x0        # 0x3bf6e24
  abf4f6:	c6 05 5b 79 13 03 00 	mov    BYTE PTR [rip+0x313795b],0x0        # 0x3bf6e58
  abf4fd:	31 c0                	xor    eax,eax
  abf4ff:	48 83 c4 08          	add    rsp,0x8
  abf503:	5b                   	pop    rbx
  abf504:	5d                   	pop    rbp
  abf505:	c3                   	ret
  abf506:	90                   	nop
  abf507:	90                   	nop
  abf508:	90                   	nop
  abf509:	90                   	nop
  abf50a:	90                   	nop
  abf50b:	90                   	nop
  abf50c:	90                   	nop
  abf50d:	90                   	nop
  abf50e:	90                   	nop
  abf50f:	90                   	nop
  abf510:	55                   	push   rbp
  abf511:	48 89 e5             	mov    rbp,rsp
  abf514:	83 ff 04             	cmp    edi,0x4
  abf517:	77 20                	ja     0xabf539
  abf519:	89 f8                	mov    eax,edi
  abf51b:	48 8d 15 0e 1f 3d 00 	lea    rdx,[rip+0x3d1f0e]        # 0xe91430
  abf522:	48 8d 0c 40          	lea    rcx,[rax+rax*2]
  abf526:	48 3b 34 ca          	cmp    rsi,QWORD PTR [rdx+rcx*8]
  abf52a:	75 0d                	jne    0xabf539
  abf52c:	48 8d 0d fd 78 13 03 	lea    rcx,[rip+0x31378fd]        # 0x3bf6e30
  abf533:	48 8b 04 c1          	mov    rax,QWORD PTR [rcx+rax*8]
  abf537:	5d                   	pop    rbp
  abf538:	c3                   	ret
  abf539:	31 c0                	xor    eax,eax
  abf53b:	5d                   	pop    rbp
  abf53c:	c3                   	ret
  abf53d:	90                   	nop
  abf53e:	90                   	nop
  abf53f:	90                   	nop
  abf540:	55                   	push   rbp
  abf541:	48 89 e5             	mov    rbp,rsp
  abf544:	ff cf                	dec    edi
  abf546:	83 ff 2d             	cmp    edi,0x2d
  abf549:	77 12                	ja     0xabf55d
  abf54b:	89 f8                	mov    eax,edi
  abf54d:	48 8d 0d b0 cd e1 00 	lea    rcx,[rip+0xe1cdb0]        # 0x18dc304
  abf554:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
  abf558:	48 01 c8             	add    rax,rcx
  abf55b:	5d                   	pop    rbp
  abf55c:	c3                   	ret
  abf55d:	48 8d 05 5a 90 85 00 	lea    rax,[rip+0x85905a]        # 0x13185be
  abf564:	5d                   	pop    rbp
  abf565:	c3                   	ret
  abf566:	90                   	nop
  abf567:	90                   	nop
  abf568:	90                   	nop
  abf569:	90                   	nop
  abf56a:	90                   	nop
  abf56b:	90                   	nop
  abf56c:	90                   	nop
  abf56d:	90                   	nop
  abf56e:	90                   	nop
  abf56f:	90                   	nop
  abf570:	55                   	push   rbp
  abf571:	48 89 e5             	mov    rbp,rsp
  abf574:	8d 47 f6             	lea    eax,[rdi-0xa]
  abf577:	83 f8 2f             	cmp    eax,0x2f
  abf57a:	77 19                	ja     0xabf595
  abf57c:	48 8d 0d c1 cc e1 00 	lea    rcx,[rip+0xe1ccc1]        # 0x18dc244
  abf583:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
  abf587:	48 01 c8             	add    rax,rcx
  abf58a:	ff e0                	jmp    rax
  abf58c:	48 8d 05 98 e0 7b 00 	lea    rax,[rip+0x7be098]        # 0x127d62b
  abf593:	5d                   	pop    rbp
  abf594:	c3                   	ret
  abf595:	81 ff 9b 00 00 00    	cmp    edi,0x9b
  abf59b:	75 09                	jne    0xabf5a6
  abf59d:	48 8d 05 aa 3a 86 00 	lea    rax,[rip+0x863aaa]        # 0x132304e
  abf5a4:	5d                   	pop    rbp
  abf5a5:	c3                   	ret
  abf5a6:	48 8d 05 9f e0 7b 00 	lea    rax,[rip+0x7be09f]        # 0x127d64c
  abf5ad:	5d                   	pop    rbp
  abf5ae:	c3                   	ret
  abf5af:	48 8d 05 36 6b 8f 00 	lea    rax,[rip+0x8f6b36]        # 0x13b60ec
  abf5b6:	5d                   	pop    rbp
  abf5b7:	c3                   	ret
  abf5b8:	48 8d 05 f0 d6 88 00 	lea    rax,[rip+0x88d6f0]        # 0x134ccaf
  abf5bf:	5d                   	pop    rbp
  abf5c0:	c3                   	ret
  abf5c1:	48 8d 05 04 90 85 00 	lea    rax,[rip+0x859004]        # 0x13185cc
  abf5c8:	5d                   	pop    rbp
  abf5c9:	c3                   	ret
  abf5ca:	48 8d 05 60 f6 82 00 	lea    rax,[rip+0x82f660]        # 0x12eec31
  abf5d1:	5d                   	pop    rbp
  abf5d2:	c3                   	ret
  abf5d3:	48 8d 05 6f 10 7f 00 	lea    rax,[rip+0x7f106f]        # 0x12b0649
  abf5da:	5d                   	pop    rbp
  abf5db:	c3                   	ret
  abf5dc:	90                   	nop
  abf5dd:	90                   	nop
  abf5de:	90                   	nop
  abf5df:	90                   	nop
  abf5e0:	55                   	push   rbp
  abf5e1:	48 89 e5             	mov    rbp,rsp
  abf5e4:	41 57                	push   r15
  abf5e6:	41 56                	push   r14
  abf5e8:	53                   	push   rbx
  abf5e9:	50                   	push   rax
  abf5ea:	8b 57 3c             	mov    edx,DWORD PTR [rdi+0x3c]
  abf5ed:	4c 8d 35 e8 80 87 00 	lea    r14,[rip+0x8780e8]        # 0x13376dc
  abf5f4:	48 89 fb             	mov    rbx,rdi
  abf5f7:	48 8d 3d 5e e0 7b 00 	lea    rdi,[rip+0x7be05e]        # 0x127d65c
  abf5fe:	31 c0                	xor    eax,eax
  abf600:	4c 89 f6             	mov    rsi,r14
  abf603:	e8 08 de 79 ff       	call   0x25d410
  abf608:	8b 53 40             	mov    edx,DWORD PTR [rbx+0x40]
  abf60b:	48 8d 3d e7 80 87 00 	lea    rdi,[rip+0x8780e7]        # 0x13376f9
  abf612:	4c 89 f6             	mov    rsi,r14
  abf615:	31 c0                	xor    eax,eax
  abf617:	e8 f4 dd 79 ff       	call   0x25d410
  abf61c:	8b 53 44             	mov    edx,DWORD PTR [rbx+0x44]
  abf61f:	48 8d 3d 82 83 89 00 	lea    rdi,[rip+0x898382]        # 0x13579a8
  abf626:	4c 89 f6             	mov    rsi,r14
  abf629:	31 c0                	xor    eax,eax
  abf62b:	e8 e0 dd 79 ff       	call   0x25d410
  abf630:	8b 53 48             	mov    edx,DWORD PTR [rbx+0x48]
  abf633:	48 8d 3d 8c c1 8e 00 	lea    rdi,[rip+0x8ec18c]        # 0x13ab7c6
  abf63a:	4c 89 f6             	mov    rsi,r14
  abf63d:	31 c0                	xor    eax,eax
  abf63f:	e8 cc dd 79 ff       	call   0x25d410
  abf644:	8b 53 4c             	mov    edx,DWORD PTR [rbx+0x4c]
  abf647:	48 8d 3d af 2a 8a 00 	lea    rdi,[rip+0x8a2aaf]        # 0x13620fd
  abf64e:	4c 89 f6             	mov    rsi,r14
  abf651:	31 c0                	xor    eax,eax
  abf653:	e8 b8 dd 79 ff       	call   0x25d410
  abf658:	8b 53 50             	mov    edx,DWORD PTR [rbx+0x50]
  abf65b:	48 8d 3d a6 15 8c 00 	lea    rdi,[rip+0x8c15a6]        # 0x1380c08
  abf662:	4c 89 f6             	mov    rsi,r14
  abf665:	31 c0                	xor    eax,eax
  abf667:	e8 a4 dd 79 ff       	call   0x25d410
  abf66c:	8b 53 34             	mov    edx,DWORD PTR [rbx+0x34]
  abf66f:	48 8d 3d 18 4e 82 00 	lea    rdi,[rip+0x824e18]        # 0x12e448e
  abf676:	4c 89 f6             	mov    rsi,r14
  abf679:	31 c0                	xor    eax,eax
  abf67b:	e8 90 dd 79 ff       	call   0x25d410
  abf680:	8b 53 30             	mov    edx,DWORD PTR [rbx+0x30]
  abf683:	48 8d 3d e2 ad 81 00 	lea    rdi,[rip+0x81ade2]        # 0x12da46c
  abf68a:	4c 89 f6             	mov    rsi,r14
  abf68d:	31 c0                	xor    eax,eax
  abf68f:	e8 7c dd 79 ff       	call   0x25d410
  abf694:	8b 53 38             	mov    edx,DWORD PTR [rbx+0x38]
  abf697:	48 8d 3d 50 8f 85 00 	lea    rdi,[rip+0x858f50]        # 0x13185ee
  abf69e:	4c 89 f6             	mov    rsi,r14
  abf6a1:	31 c0                	xor    eax,eax
  abf6a3:	e8 68 dd 79 ff       	call   0x25d410
  abf6a8:	8b 53 54             	mov    edx,DWORD PTR [rbx+0x54]
  abf6ab:	48 8d 3d d2 df 7b 00 	lea    rdi,[rip+0x7bdfd2]        # 0x127d684
  abf6b2:	4c 89 f6             	mov    rsi,r14
  abf6b5:	31 c0                	xor    eax,eax
  abf6b7:	e8 54 dd 79 ff       	call   0x25d410
  abf6bc:	8b 53 58             	mov    edx,DWORD PTR [rbx+0x58]
  abf6bf:	48 8d 3d 28 c1 8e 00 	lea    rdi,[rip+0x8ec128]        # 0x13ab7ee
  abf6c6:	4c 89 f6             	mov    rsi,r14
  abf6c9:	31 c0                	xor    eax,eax
  abf6cb:	e8 40 dd 79 ff       	call   0x25d410
  abf6d0:	8b 53 5c             	mov    edx,DWORD PTR [rbx+0x5c]
  abf6d3:	48 8d 3d f3 04 81 00 	lea    rdi,[rip+0x8104f3]        # 0x12cfbcd
  abf6da:	4c 89 f6             	mov    rsi,r14
  abf6dd:	31 c0                	xor    eax,eax
  abf6df:	e8 2c dd 79 ff       	call   0x25d410
  abf6e4:	8b 53 60             	mov    edx,DWORD PTR [rbx+0x60]
  abf6e7:	48 8d 3d fb dc 86 00 	lea    rdi,[rip+0x86dcfb]        # 0x132d3e9
  abf6ee:	4c 89 f6             	mov    rsi,r14
  abf6f1:	31 c0                	xor    eax,eax
  abf6f3:	e8 18 dd 79 ff       	call   0x25d410
  abf6f8:	8b 53 64             	mov    edx,DWORD PTR [rbx+0x64]
  abf6fb:	48 8d 3d 8f 7f 7c 00 	lea    rdi,[rip+0x7c7f8f]        # 0x1287691
  abf702:	4c 89 f6             	mov    rsi,r14
  abf705:	31 c0                	xor    eax,eax
  abf707:	e8 04 dd 79 ff       	call   0x25d410
  abf70c:	8b 53 68             	mov    edx,DWORD PTR [rbx+0x68]
  abf70f:	48 8d 3d ba 82 89 00 	lea    rdi,[rip+0x8982ba]        # 0x13579d0
  abf716:	4c 89 f6             	mov    rsi,r14
  abf719:	31 c0                	xor    eax,eax
  abf71b:	e8 f0 dc 79 ff       	call   0x25d410
  abf720:	8b 53 6c             	mov    edx,DWORD PTR [rbx+0x6c]
  abf723:	48 8d 3d bc 24 7d 00 	lea    rdi,[rip+0x7d24bc]        # 0x1291be6
  abf72a:	4c 89 f6             	mov    rsi,r14
  abf72d:	31 c0                	xor    eax,eax
  abf72f:	e8 dc dc 79 ff       	call   0x25d410
  abf734:	8b 53 70             	mov    edx,DWORD PTR [rbx+0x70]
  abf737:	48 8d 3d b7 04 81 00 	lea    rdi,[rip+0x8104b7]        # 0x12cfbf5
  abf73e:	4c 89 f6             	mov    rsi,r14
  abf741:	31 c0                	xor    eax,eax
  abf743:	e8 c8 dc 79 ff       	call   0x25d410
  abf748:	8b 53 74             	mov    edx,DWORD PTR [rbx+0x74]
  abf74b:	48 8d 3d 98 44 7b 00 	lea    rdi,[rip+0x7b4498]        # 0x1273bea
  abf752:	4c 89 f6             	mov    rsi,r14
  abf755:	31 c0                	xor    eax,eax
  abf757:	e8 b4 dc 79 ff       	call   0x25d410
  abf75c:	8b 53 78             	mov    edx,DWORD PTR [rbx+0x78]
  abf75f:	48 8d 3d 7d 6b 7e 00 	lea    rdi,[rip+0x7e6b7d]        # 0x12a62e3
  abf766:	4c 89 f6             	mov    rsi,r14
  abf769:	31 c0                	xor    eax,eax
  abf76b:	e8 a0 dc 79 ff       	call   0x25d410
  abf770:	8b 53 7c             	mov    edx,DWORD PTR [rbx+0x7c]
  abf773:	48 8d 3d b6 14 8c 00 	lea    rdi,[rip+0x8c14b6]        # 0x1380c30
  abf77a:	4c 89 f6             	mov    rsi,r14
  abf77d:	31 c0                	xor    eax,eax
  abf77f:	e8 8c dc 79 ff       	call   0x25d410
  abf784:	8b 93 80 00 00 00    	mov    edx,DWORD PTR [rbx+0x80]
  abf78a:	48 8d 3d 09 75 8b 00 	lea    rdi,[rip+0x8b7509]        # 0x1376c9a
  abf791:	4c 89 f6             	mov    rsi,r14
  abf794:	31 c0                	xor    eax,eax
  abf796:	e8 75 dc 79 ff       	call   0x25d410
  abf79b:	8b 93 84 00 00 00    	mov    edx,DWORD PTR [rbx+0x84]
  abf7a1:	48 8d 3d 54 94 83 00 	lea    rdi,[rip+0x839454]        # 0x12f8bfc
  abf7a8:	4c 89 f6             	mov    rsi,r14
  abf7ab:	31 c0                	xor    eax,eax
  abf7ad:	e8 5e dc 79 ff       	call   0x25d410
  abf7b2:	8b 93 88 00 00 00    	mov    edx,DWORD PTR [rbx+0x88]
  abf7b8:	48 8d 3d 14 d5 88 00 	lea    rdi,[rip+0x88d514]        # 0x134ccd3
  abf7bf:	4c 89 f6             	mov    rsi,r14
  abf7c2:	31 c0                	xor    eax,eax
  abf7c4:	e8 47 dc 79 ff       	call   0x25d410
  abf7c9:	8b 93 8c 00 00 00    	mov    edx,DWORD PTR [rbx+0x8c]
  abf7cf:	48 8d 3d 40 8e 85 00 	lea    rdi,[rip+0x858e40]        # 0x1318616
  abf7d6:	4c 89 f6             	mov    rsi,r14
  abf7d9:	31 c0                	xor    eax,eax
  abf7db:	e8 30 dc 79 ff       	call   0x25d410
  abf7e0:	8b 93 90 00 00 00    	mov    edx,DWORD PTR [rbx+0x90]
  abf7e6:	48 8d 3d 64 f4 82 00 	lea    rdi,[rip+0x82f464]        # 0x12eec51
  abf7ed:	4c 89 f6             	mov    rsi,r14
  abf7f0:	31 c0                	xor    eax,eax
  abf7f2:	e8 19 dc 79 ff       	call   0x25d410
  abf7f7:	8b 93 94 00 00 00    	mov    edx,DWORD PTR [rbx+0x94]
  abf7fd:	48 8d 3d 09 69 8f 00 	lea    rdi,[rip+0x8f6909]        # 0x13b610d
  abf804:	4c 89 f6             	mov    rsi,r14
  abf807:	31 c0                	xor    eax,eax
  abf809:	e8 02 dc 79 ff       	call   0x25d410
  abf80e:	8b 53 1c             	mov    edx,DWORD PTR [rbx+0x1c]
  abf811:	48 8d 3d 05 04 81 00 	lea    rdi,[rip+0x810405]        # 0x12cfc1d
  abf818:	4c 89 f6             	mov    rsi,r14
  abf81b:	31 c0                	xor    eax,eax
  abf81d:	e8 ee db 79 ff       	call   0x25d410
  abf822:	8b 53 18             	mov    edx,DWORD PTR [rbx+0x18]
  abf825:	48 8d 3d 1b 04 81 00 	lea    rdi,[rip+0x81041b]        # 0x12cfc47
  abf82c:	4c 89 f6             	mov    rsi,r14
  abf82f:	31 c0                	xor    eax,eax
  abf831:	e8 da db 79 ff       	call   0x25d410
  abf836:	8b 53 20             	mov    edx,DWORD PTR [rbx+0x20]
  abf839:	48 8d 3d 79 7e 7c 00 	lea    rdi,[rip+0x7c7e79]        # 0x12876b9
  abf840:	4c 89 f6             	mov    rsi,r14
  abf843:	31 c0                	xor    eax,eax
  abf845:	e8 c6 db 79 ff       	call   0x25d410
  abf84a:	8b 53 24             	mov    edx,DWORD PTR [rbx+0x24]
  abf84d:	48 8d 3d d7 26 88 00 	lea    rdi,[rip+0x8826d7]        # 0x1341f2b
  abf854:	4c 89 f6             	mov    rsi,r14
  abf857:	31 c0                	xor    eax,eax
  abf859:	e8 b2 db 79 ff       	call   0x25d410
  abf85e:	8b 53 28             	mov    edx,DWORD PTR [rbx+0x28]
  abf861:	48 8d 3d 2c ac 81 00 	lea    rdi,[rip+0x81ac2c]        # 0x12da494
  abf868:	4c 89 f6             	mov    rsi,r14
  abf86b:	31 c0                	xor    eax,eax
  abf86d:	e8 9e db 79 ff       	call   0x25d410
  abf872:	8b 53 2c             	mov    edx,DWORD PTR [rbx+0x2c]
  abf875:	48 8d 3d 6a 7e 7c 00 	lea    rdi,[rip+0x7c7e6a]        # 0x12876e6
  abf87c:	4c 89 f6             	mov    rsi,r14
  abf87f:	31 c0                	xor    eax,eax
  abf881:	e8 8a db 79 ff       	call   0x25d410
  abf886:	8b 53 08             	mov    edx,DWORD PTR [rbx+0x8]
  abf889:	4c 8d 3d cf ae 7f 00 	lea    r15,[rip+0x7faecf]        # 0x12ba75f
  abf890:	4c 89 f6             	mov    rsi,r14
  abf893:	31 c0                	xor    eax,eax
  abf895:	4c 89 ff             	mov    rdi,r15
  abf898:	e8 73 db 79 ff       	call   0x25d410
  abf89d:	8b 53 0c             	mov    edx,DWORD PTR [rbx+0xc]
  abf8a0:	4c 89 ff             	mov    rdi,r15
  abf8a3:	4c 89 f6             	mov    rsi,r14
  abf8a6:	31 c0                	xor    eax,eax
  abf8a8:	e8 63 db 79 ff       	call   0x25d410
  abf8ad:	8b 53 10             	mov    edx,DWORD PTR [rbx+0x10]
  abf8b0:	4c 89 ff             	mov    rdi,r15
  abf8b3:	4c 89 f6             	mov    rsi,r14
  abf8b6:	31 c0                	xor    eax,eax
  abf8b8:	e8 53 db 79 ff       	call   0x25d410
  abf8bd:	8b 53 14             	mov    edx,DWORD PTR [rbx+0x14]
  abf8c0:	4c 89 ff             	mov    rdi,r15
  abf8c3:	4c 89 f6             	mov    rsi,r14
  abf8c6:	31 c0                	xor    eax,eax
  abf8c8:	48 83 c4 08          	add    rsp,0x8
  abf8cc:	5b                   	pop    rbx
  abf8cd:	41 5e                	pop    r14
  abf8cf:	41 5f                	pop    r15
  abf8d1:	5d                   	pop    rbp
  abf8d2:	e9 39 db 79 ff       	jmp    0x25d410
  abf8d7:	90                   	nop
  abf8d8:	90                   	nop
  abf8d9:	90                   	nop
  abf8da:	90                   	nop
  abf8db:	90                   	nop
  abf8dc:	90                   	nop
  abf8dd:	90                   	nop
  abf8de:	90                   	nop
  abf8df:	90                   	nop
  abf8e0:	55                   	push   rbp
  abf8e1:	48 89 e5             	mov    rbp,rsp
  abf8e4:	41 57                	push   r15
  abf8e6:	41 56                	push   r14
  abf8e8:	41 55                	push   r13
  abf8ea:	41 54                	push   r12
  abf8ec:	53                   	push   rbx
  abf8ed:	50                   	push   rax
  abf8ee:	8b 57 08             	mov    edx,DWORD PTR [rdi+0x8]
  abf8f1:	4c 8d 35 84 c4 7d 00 	lea    r14,[rip+0x7dc484]        # 0x129bd7c
  abf8f8:	48 89 fb             	mov    rbx,rdi
  abf8fb:	48 8d 3d 0c 23 7d 00 	lea    rdi,[rip+0x7d230c]        # 0x1291c0e
  abf902:	31 c0                	xor    eax,eax
  abf904:	4c 89 f6             	mov    rsi,r14
  abf907:	e8 04 db 79 ff       	call   0x25d410
  abf90c:	8b 53 0c             	mov    edx,DWORD PTR [rbx+0xc]
  abf90f:	48 8d 3d 0f 28 8a 00 	lea    rdi,[rip+0x8a280f]        # 0x1362125
  abf916:	4c 89 f6             	mov    rsi,r14
  abf919:	31 c0                	xor    eax,eax
  abf91b:	e8 f0 da 79 ff       	call   0x25d410
  abf920:	8b 53 10             	mov    edx,DWORD PTR [rbx+0x10]
  abf923:	48 8d 3d 2e 13 8c 00 	lea    rdi,[rip+0x8c132e]        # 0x1380c58
  abf92a:	4c 89 f6             	mov    rsi,r14
  abf92d:	31 c0                	xor    eax,eax
  abf92f:	e8 dc da 79 ff       	call   0x25d410
  abf934:	8b 53 14             	mov    edx,DWORD PTR [rbx+0x14]
  abf937:	48 8d 3d d4 42 7b 00 	lea    rdi,[rip+0x7b42d4]        # 0x1273c12
  abf93e:	4c 89 f6             	mov    rsi,r14
  abf941:	31 c0                	xor    eax,eax
  abf943:	e8 c8 da 79 ff       	call   0x25d410
  abf948:	8b 53 18             	mov    edx,DWORD PTR [rbx+0x18]
  abf94b:	48 8d 3d b9 69 7e 00 	lea    rdi,[rip+0x7e69b9]        # 0x12a630b
  abf952:	4c 89 f6             	mov    rsi,r14
  abf955:	31 c0                	xor    eax,eax
  abf957:	e8 b4 da 79 ff       	call   0x25d410
  abf95c:	8b 4b 1c             	mov    ecx,DWORD PTR [rbx+0x1c]
  abf95f:	4c 8d 3d d8 8c 85 00 	lea    r15,[rip+0x858cd8]        # 0x131863e
  abf966:	4c 89 f6             	mov    rsi,r14
  abf969:	31 d2                	xor    edx,edx
  abf96b:	31 c0                	xor    eax,eax
  abf96d:	4c 89 ff             	mov    rdi,r15
  abf970:	e8 9b da 79 ff       	call   0x25d410
  abf975:	8b 4b 44             	mov    ecx,DWORD PTR [rbx+0x44]
  abf978:	4c 8d 25 03 ae 7f 00 	lea    r12,[rip+0x7fae03]        # 0x12ba782
  abf97f:	4c 89 f6             	mov    rsi,r14
  abf982:	31 d2                	xor    edx,edx
  abf984:	31 c0                	xor    eax,eax
  abf986:	4c 89 e7             	mov    rdi,r12
  abf989:	e8 82 da 79 ff       	call   0x25d410
  abf98e:	8b 4b 6c             	mov    ecx,DWORD PTR [rbx+0x6c]
  abf991:	4c 8d 2d 01 c4 7d 00 	lea    r13,[rip+0x7dc401]        # 0x129bd99
  abf998:	4c 89 f6             	mov    rsi,r14
  abf99b:	31 d2                	xor    edx,edx
  abf99d:	31 c0                	xor    eax,eax
  abf99f:	4c 89 ef             	mov    rdi,r13
  abf9a2:	e8 69 da 79 ff       	call   0x25d410
  abf9a7:	8b 4b 20             	mov    ecx,DWORD PTR [rbx+0x20]
  abf9aa:	4c 89 ff             	mov    rdi,r15
  abf9ad:	4c 89 f6             	mov    rsi,r14
  abf9b0:	ba 01 00 00 00       	mov    edx,0x1
  abf9b5:	31 c0                	xor    eax,eax
  abf9b7:	e8 54 da 79 ff       	call   0x25d410
  abf9bc:	8b 4b 48             	mov    ecx,DWORD PTR [rbx+0x48]
  abf9bf:	4c 89 e7             	mov    rdi,r12
  abf9c2:	4c 89 f6             	mov    rsi,r14
  abf9c5:	ba 01 00 00 00       	mov    edx,0x1
  abf9ca:	31 c0                	xor    eax,eax
  abf9cc:	e8 3f da 79 ff       	call   0x25d410
  abf9d1:	8b 4b 70             	mov    ecx,DWORD PTR [rbx+0x70]
  abf9d4:	4c 89 ef             	mov    rdi,r13
  abf9d7:	4c 89 f6             	mov    rsi,r14
  abf9da:	ba 01 00 00 00       	mov    edx,0x1
  abf9df:	31 c0                	xor    eax,eax
  abf9e1:	e8 2a da 79 ff       	call   0x25d410
  abf9e6:	8b 4b 24             	mov    ecx,DWORD PTR [rbx+0x24]
  abf9e9:	4c 89 ff             	mov    rdi,r15
  abf9ec:	4c 89 f6             	mov    rsi,r14
  abf9ef:	ba 02 00 00 00       	mov    edx,0x2
  abf9f4:	31 c0                	xor    eax,eax
  abf9f6:	e8 15 da 79 ff       	call   0x25d410
  abf9fb:	8b 4b 4c             	mov    ecx,DWORD PTR [rbx+0x4c]
  abf9fe:	4c 89 e7             	mov    rdi,r12
  abfa01:	4c 89 f6             	mov    rsi,r14
  abfa04:	ba 02 00 00 00       	mov    edx,0x2
  abfa09:	31 c0                	xor    eax,eax
  abfa0b:	e8 00 da 79 ff       	call   0x25d410
  abfa10:	8b 4b 74             	mov    ecx,DWORD PTR [rbx+0x74]
  abfa13:	4c 89 ef             	mov    rdi,r13
  abfa16:	4c 89 f6             	mov    rsi,r14
  abfa19:	ba 02 00 00 00       	mov    edx,0x2
  abfa1e:	31 c0                	xor    eax,eax
  abfa20:	e8 eb d9 79 ff       	call   0x25d410
  abfa25:	8b 4b 28             	mov    ecx,DWORD PTR [rbx+0x28]
  abfa28:	4c 89 ff             	mov    rdi,r15
  abfa2b:	4c 89 f6             	mov    rsi,r14
  abfa2e:	ba 03 00 00 00       	mov    edx,0x3
  abfa33:	31 c0                	xor    eax,eax
  abfa35:	e8 d6 d9 79 ff       	call   0x25d410
  abfa3a:	8b 4b 50             	mov    ecx,DWORD PTR [rbx+0x50]
  abfa3d:	4c 89 e7             	mov    rdi,r12
  abfa40:	4c 89 f6             	mov    rsi,r14
  abfa43:	ba 03 00 00 00       	mov    edx,0x3
  abfa48:	31 c0                	xor    eax,eax
  abfa4a:	e8 c1 d9 79 ff       	call   0x25d410
  abfa4f:	8b 4b 78             	mov    ecx,DWORD PTR [rbx+0x78]
  abfa52:	4c 89 ef             	mov    rdi,r13
  abfa55:	4c 89 f6             	mov    rsi,r14
  abfa58:	ba 03 00 00 00       	mov    edx,0x3
  abfa5d:	31 c0                	xor    eax,eax
  abfa5f:	e8 ac d9 79 ff       	call   0x25d410
  abfa64:	8b 4b 2c             	mov    ecx,DWORD PTR [rbx+0x2c]
  abfa67:	4c 89 ff             	mov    rdi,r15
  abfa6a:	4c 89 f6             	mov    rsi,r14
  abfa6d:	ba 04 00 00 00       	mov    edx,0x4
  abfa72:	31 c0                	xor    eax,eax
  abfa74:	e8 97 d9 79 ff       	call   0x25d410
  abfa79:	8b 4b 54             	mov    ecx,DWORD PTR [rbx+0x54]
  abfa7c:	4c 89 e7             	mov    rdi,r12
  abfa7f:	4c 89 f6             	mov    rsi,r14
  abfa82:	ba 04 00 00 00       	mov    edx,0x4
  abfa87:	31 c0                	xor    eax,eax
  abfa89:	e8 82 d9 79 ff       	call   0x25d410
  abfa8e:	8b 4b 7c             	mov    ecx,DWORD PTR [rbx+0x7c]
  abfa91:	4c 89 ef             	mov    rdi,r13
  abfa94:	4c 89 f6             	mov    rsi,r14
  abfa97:	ba 04 00 00 00       	mov    edx,0x4
  abfa9c:	31 c0                	xor    eax,eax
  abfa9e:	e8 6d d9 79 ff       	call   0x25d410
  abfaa3:	8b 4b 30             	mov    ecx,DWORD PTR [rbx+0x30]
  abfaa6:	4c 89 ff             	mov    rdi,r15
  abfaa9:	4c 89 f6             	mov    rsi,r14
  abfaac:	ba 05 00 00 00       	mov    edx,0x5
  abfab1:	31 c0                	xor    eax,eax
  abfab3:	e8 58 d9 79 ff       	call   0x25d410
  abfab8:	8b 4b 58             	mov    ecx,DWORD PTR [rbx+0x58]
  abfabb:	4c 89 e7             	mov    rdi,r12
  abfabe:	4c 89 f6             	mov    rsi,r14
  abfac1:	ba 05 00 00 00       	mov    edx,0x5
  abfac6:	31 c0                	xor    eax,eax
  abfac8:	e8 43 d9 79 ff       	call   0x25d410
  abfacd:	8b 8b 80 00 00 00    	mov    ecx,DWORD PTR [rbx+0x80]
  abfad3:	4c 89 ef             	mov    rdi,r13
  abfad6:	4c 89 f6             	mov    rsi,r14
  abfad9:	ba 05 00 00 00       	mov    edx,0x5
  abfade:	31 c0                	xor    eax,eax
  abfae0:	e8 2b d9 79 ff       	call   0x25d410
  abfae5:	8b 4b 34             	mov    ecx,DWORD PTR [rbx+0x34]
  abfae8:	4c 89 ff             	mov    rdi,r15
  abfaeb:	4c 89 f6             	mov    rsi,r14
  abfaee:	ba 06 00 00 00       	mov    edx,0x6
  abfaf3:	31 c0                	xor    eax,eax
  abfaf5:	e8 16 d9 79 ff       	call   0x25d410
  abfafa:	8b 4b 5c             	mov    ecx,DWORD PTR [rbx+0x5c]
  abfafd:	4c 89 e7             	mov    rdi,r12
  abfb00:	4c 89 f6             	mov    rsi,r14
  abfb03:	ba 06 00 00 00       	mov    edx,0x6
  abfb08:	31 c0                	xor    eax,eax
  abfb0a:	e8 01 d9 79 ff       	call   0x25d410
  abfb0f:	8b 8b 84 00 00 00    	mov    ecx,DWORD PTR [rbx+0x84]
  abfb15:	4c 89 ef             	mov    rdi,r13
  abfb18:	4c 89 f6             	mov    rsi,r14
  abfb1b:	ba 06 00 00 00       	mov    edx,0x6
  abfb20:	31 c0                	xor    eax,eax
  abfb22:	e8 e9 d8 79 ff       	call   0x25d410
  abfb27:	8b 4b 38             	mov    ecx,DWORD PTR [rbx+0x38]
  abfb2a:	4c 89 ff             	mov    rdi,r15
  abfb2d:	4c 89 f6             	mov    rsi,r14
  abfb30:	ba 07 00 00 00       	mov    edx,0x7
  abfb35:	31 c0                	xor    eax,eax
  abfb37:	e8 d4 d8 79 ff       	call   0x25d410
  abfb3c:	8b 4b 60             	mov    ecx,DWORD PTR [rbx+0x60]
  abfb3f:	4c 89 e7             	mov    rdi,r12
  abfb42:	4c 89 f6             	mov    rsi,r14
  abfb45:	ba 07 00 00 00       	mov    edx,0x7
  abfb4a:	31 c0                	xor    eax,eax
  abfb4c:	e8 bf d8 79 ff       	call   0x25d410
  abfb51:	8b 8b 88 00 00 00    	mov    ecx,DWORD PTR [rbx+0x88]
  abfb57:	4c 89 ef             	mov    rdi,r13
  abfb5a:	4c 89 f6             	mov    rsi,r14
  abfb5d:	ba 07 00 00 00       	mov    edx,0x7
  abfb62:	31 c0                	xor    eax,eax
  abfb64:	e8 a7 d8 79 ff       	call   0x25d410
  abfb69:	8b 4b 3c             	mov    ecx,DWORD PTR [rbx+0x3c]
  abfb6c:	4c 89 ff             	mov    rdi,r15
  abfb6f:	4c 89 f6             	mov    rsi,r14
  abfb72:	ba 08 00 00 00       	mov    edx,0x8
  abfb77:	31 c0                	xor    eax,eax
  abfb79:	e8 92 d8 79 ff       	call   0x25d410
  abfb7e:	8b 4b 64             	mov    ecx,DWORD PTR [rbx+0x64]
  abfb81:	4c 89 e7             	mov    rdi,r12
  abfb84:	4c 89 f6             	mov    rsi,r14
  abfb87:	ba 08 00 00 00       	mov    edx,0x8
  abfb8c:	31 c0                	xor    eax,eax
  abfb8e:	e8 7d d8 79 ff       	call   0x25d410
  abfb93:	8b 8b 8c 00 00 00    	mov    ecx,DWORD PTR [rbx+0x8c]
  abfb99:	4c 89 ef             	mov    rdi,r13
  abfb9c:	4c 89 f6             	mov    rsi,r14
  abfb9f:	ba 08 00 00 00       	mov    edx,0x8
  abfba4:	31 c0                	xor    eax,eax
  abfba6:	e8 65 d8 79 ff       	call   0x25d410
  abfbab:	8b 4b 40             	mov    ecx,DWORD PTR [rbx+0x40]
  abfbae:	4c 89 ff             	mov    rdi,r15
  abfbb1:	4c 89 f6             	mov    rsi,r14
  abfbb4:	ba 09 00 00 00       	mov    edx,0x9
  abfbb9:	31 c0                	xor    eax,eax
  abfbbb:	e8 50 d8 79 ff       	call   0x25d410
  abfbc0:	8b 4b 68             	mov    ecx,DWORD PTR [rbx+0x68]
  abfbc3:	4c 89 e7             	mov    rdi,r12
  abfbc6:	4c 89 f6             	mov    rsi,r14
  abfbc9:	ba 09 00 00 00       	mov    edx,0x9
  abfbce:	31 c0                	xor    eax,eax
  abfbd0:	e8 3b d8 79 ff       	call   0x25d410
  abfbd5:	8b 8b 90 00 00 00    	mov    ecx,DWORD PTR [rbx+0x90]
  abfbdb:	4c 89 ef             	mov    rdi,r13
  abfbde:	4c 89 f6             	mov    rsi,r14
  abfbe1:	ba 09 00 00 00       	mov    edx,0x9
  abfbe6:	31 c0                	xor    eax,eax
  abfbe8:	48 83 c4 08          	add    rsp,0x8
  abfbec:	5b                   	pop    rbx
  abfbed:	41 5c                	pop    r12
  abfbef:	41 5d                	pop    r13
  abfbf1:	41 5e                	pop    r14
  abfbf3:	41 5f                	pop    r15
  abfbf5:	5d                   	pop    rbp
  abfbf6:	e9 15 d8 79 ff       	jmp    0x25d410
  abfbfb:	90                   	nop
  abfbfc:	90                   	nop
  abfbfd:	90                   	nop
  abfbfe:	90                   	nop
  abfbff:	90                   	nop
  abfc00:	55                   	push   rbp
  abfc01:	48 89 e5             	mov    rbp,rsp
  abfc04:	41 57                	push   r15
  abfc06:	41 56                	push   r14
  abfc08:	41 54                	push   r12
  abfc0a:	53                   	push   rbx
  abfc0b:	48 8b 05 4e 72 13 03 	mov    rax,QWORD PTR [rip+0x313724e]        # 0x3bf6e60
  abfc12:	41 89 f6             	mov    r14d,esi
  abfc15:	48 89 fb             	mov    rbx,rdi
  abfc18:	41 83 e6 01          	and    r14d,0x1
  abfc1c:	43 8d 74 36 01       	lea    esi,[r14+r14*1+0x1]
  abfc21:	4c 8b 78 30          	mov    r15,QWORD PTR [rax+0x30]
  abfc25:	48 8d 05 b4 94 7a ff 	lea    rax,[rip+0xffffffffff7a94b4]        # 0x2690e0
  abfc2c:	4c 29 f8             	sub    rax,r15
  abfc2f:	48 c1 c8 03          	ror    rax,0x3
  abfc33:	48 83 f8 72          	cmp    rax,0x72
  abfc37:	77 2c                	ja     0xabfc65
  abfc39:	48 89 df             	mov    rdi,rbx
  abfc3c:	41 ff d7             	call   r15
  abfc3f:	41 09 c6             	or     r14d,eax
  abfc42:	74 09                	je     0xabfc4d
  abfc44:	5b                   	pop    rbx
  abfc45:	41 5c                	pop    r12
  abfc47:	41 5e                	pop    r14
  abfc49:	41 5f                	pop    r15
  abfc4b:	5d                   	pop    rbp
  abfc4c:	c3                   	ret
  abfc4d:	48 89 df             	mov    rdi,rbx
  abfc50:	e8 db 19 f5 ff       	call   0xa11630
  abfc55:	48 89 df             	mov    rdi,rbx
  abfc58:	5b                   	pop    rbx
  abfc59:	41 5c                	pop    r12
  abfc5b:	41 5e                	pop    r14
  abfc5d:	41 5f                	pop    r15
  abfc5f:	5d                   	pop    rbp
  abfc60:	e9 6b 16 f5 ff       	jmp    0xa112d0
  abfc65:	41 89 f4             	mov    r12d,esi
  abfc68:	48 8d 3d 81 92 dc 01 	lea    rdi,[rip+0x1dc9281]        # 0x2888ef0
  abfc6f:	4c 89 fe             	mov    rsi,r15
  abfc72:	e8 49 fc 98 ff       	call   0x44f8c0
  abfc77:	44 89 e6             	mov    esi,r12d
  abfc7a:	eb bd                	jmp    0xabfc39
  abfc7c:	90                   	nop
  abfc7d:	90                   	nop
  abfc7e:	90                   	nop
  abfc7f:	90                   	nop
  abfc80:	48 8b 05 d9 71 13 03 	mov    rax,QWORD PTR [rip+0x31371d9]        # 0x3bf6e60
  abfc87:	48 8b 48 30          	mov    rcx,QWORD PTR [rax+0x30]
  abfc8b:	48 8d 05 4e 94 7a ff 	lea    rax,[rip+0xffffffffff7a944e]        # 0x2690e0
  abfc92:	48 29 c8             	sub    rax,rcx
  abfc95:	48 c1 c8 03          	ror    rax,0x3
  abfc99:	48 83 f8 72          	cmp    rax,0x72
  abfc9d:	77 02                	ja     0xabfca1
  abfc9f:	ff e1                	jmp    rcx
  abfca1:	55                   	push   rbp
  abfca2:	48 89 e5             	mov    rbp,rsp
  abfca5:	41 57                	push   r15
  abfca7:	41 56                	push   r14
  abfca9:	53                   	push   rbx
  abfcaa:	50                   	push   rax
  abfcab:	48 8d 05 3e 92 dc 01 	lea    rax,[rip+0x1dc923e]        # 0x2888ef0
  abfcb2:	48 89 fb             	mov    rbx,rdi
  abfcb5:	41 89 f6             	mov    r14d,esi
  abfcb8:	48 89 ce             	mov    rsi,rcx
  abfcbb:	49 89 cf             	mov    r15,rcx
  abfcbe:	48 89 c7             	mov    rdi,rax
  abfcc1:	e8 fa fb 98 ff       	call   0x44f8c0
  abfcc6:	4c 89 f9             	mov    rcx,r15
  abfcc9:	48 89 df             	mov    rdi,rbx
  abfccc:	44 89 f6             	mov    esi,r14d
  abfccf:	48 83 c4 08          	add    rsp,0x8
  abfcd3:	5b                   	pop    rbx
  abfcd4:	41 5e                	pop    r14
  abfcd6:	41 5f                	pop    r15
  abfcd8:	5d                   	pop    rbp
  abfcd9:	ff e1                	jmp    rcx
  abfcdb:	90                   	nop
  abfcdc:	90                   	nop
  abfcdd:	90                   	nop
  abfcde:	90                   	nop
  abfcdf:	90                   	nop
  abfce0:	55                   	push   rbp
  abfce1:	48 89 e5             	mov    rbp,rsp
  abfce4:	41 56                	push   r14
  abfce6:	53                   	push   rbx
  abfce7:	41 89 f6             	mov    r14d,esi
  abfcea:	48 89 fb             	mov    rbx,rdi
  abfced:	e8 3e 19 f5 ff       	call   0xa11630
  abfcf2:	41 f6 c6 04          	test   r14b,0x4
  abfcf6:	75 0c                	jne    0xabfd04
  abfcf8:	48 89 df             	mov    rdi,rbx
  abfcfb:	5b                   	pop    rbx
  abfcfc:	41 5e                	pop    r14
  abfcfe:	5d                   	pop    rbp
  abfcff:	e9 cc 15 f5 ff       	jmp    0xa112d0
  abfd04:	31 c0                	xor    eax,eax
  abfd06:	5b                   	pop    rbx
  abfd07:	41 5e                	pop    r14
  abfd09:	5d                   	pop    rbp
  abfd0a:	c3                   	ret
  abfd0b:	90                   	nop
  abfd0c:	90                   	nop
  abfd0d:	90                   	nop
  abfd0e:	90                   	nop
  abfd0f:	90                   	nop
  abfd10:	55                   	push   rbp
  abfd11:	48 89 e5             	mov    rbp,rsp
  abfd14:	41 57                	push   r15
  abfd16:	41 56                	push   r14
  abfd18:	41 55                	push   r13
  abfd1a:	41 54                	push   r12
  abfd1c:	53                   	push   rbx
  abfd1d:	48 81 ec 38 01 00 00 	sub    rsp,0x138
  abfd24:	4c 8d 2d e5 c5 e5 02 	lea    r13,[rip+0x2e5c5e5]        # 0x391c310
  abfd2b:	48 89 fb             	mov    rbx,rdi
  abfd2e:	48 8d 35 92 53 81 00 	lea    rsi,[rip+0x815392]        # 0x12d50c7
  abfd35:	48 8d 95 b0 fe ff ff 	lea    rdx,[rbp-0x150]
  abfd3c:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  abfd40:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abfd44:	c7 85 b0 fe ff ff 00 	mov    DWORD PTR [rbp-0x150],0x0
  abfd4b:	00 00 00 
  abfd4e:	48 8b bf a8 00 00 00 	mov    rdi,QWORD PTR [rdi+0xa8]
  abfd55:	e8 76 14 b2 ff       	call   0x5e11d0
  abfd5a:	48 85 c0             	test   rax,rax
  abfd5d:	74 34                	je     0xabfd93
  abfd5f:	48 8d 35 86 70 7d 00 	lea    rsi,[rip+0x7d7086]        # 0x1296dec
  abfd66:	ba 07 00 00 00       	mov    edx,0x7
  abfd6b:	48 89 c7             	mov    rdi,rax
  abfd6e:	e8 bd 1c e1 ff       	call   0x8d1a30
  abfd73:	48 8b bb a8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa8]
  abfd7a:	85 c0                	test   eax,eax
  abfd7c:	48 8d 35 44 53 81 00 	lea    rsi,[rip+0x815344]        # 0x12d50c7
  abfd83:	0f 94 c0             	sete   al
  abfd86:	89 85 a4 fe ff ff    	mov    DWORD PTR [rbp-0x15c],eax
  abfd8c:	e8 0f df b1 ff       	call   0x5ddca0
  abfd91:	eb 0a                	jmp    0xabfd9d
  abfd93:	c7 85 a4 fe ff ff 00 	mov    DWORD PTR [rbp-0x15c],0x0
  abfd9a:	00 00 00 
  abfd9d:	65 4c 8b 3c 25 00 00 	mov    r15,QWORD PTR gs:0x0
  abfda4:	00 00 
  abfda6:	48 8b bb a8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa8]
  abfdad:	48 8d 35 ed 2f 7f 00 	lea    rsi,[rip+0x7f2fed]        # 0x12b2da1
  abfdb4:	48 8d 95 d0 fe ff ff 	lea    rdx,[rbp-0x130]
  abfdbb:	e8 10 14 b2 ff       	call   0x5e11d0
  abfdc0:	48 8d 35 b9 c2 13 02 	lea    rsi,[rip+0x213c2b9]        # 0x2bfc080
  abfdc7:	bf 00 04 00 00       	mov    edi,0x400
  abfdcc:	ba 02 01 00 00       	mov    edx,0x102
  abfdd1:	49 89 c4             	mov    r12,rax
  abfdd4:	e8 77 8d 14 00       	call   0xc08b50
  abfdd9:	48 8d 15 13 14 7d 00 	lea    rdx,[rip+0x7d1413]        # 0x12911f3
  abfde0:	be 00 04 00 00       	mov    esi,0x400
  abfde5:	48 89 c7             	mov    rdi,rax
  abfde8:	4c 89 e1             	mov    rcx,r12
  abfdeb:	49 89 c6             	mov    r14,rax
  abfdee:	31 c0                	xor    eax,eax
  abfdf0:	e8 4b f0 9e ff       	call   0x4aee40
  abfdf5:	3d 00 04 00 00       	cmp    eax,0x400
  abfdfa:	0f 8c 68 01 00 00    	jl     0xabff68
  abfe00:	48 8d 35 79 c2 13 02 	lea    rsi,[rip+0x213c279]        # 0x2bfc080
  abfe07:	4c 89 f7             	mov    rdi,r14
  abfe0a:	e8 e1 8f 14 00       	call   0xc08df0
  abfe0f:	48 83 3d 49 70 13 03 	cmp    QWORD PTR [rip+0x3137049],0x0        # 0x3bf6e60
  abfe16:	00 
  abfe17:	0f 85 ab 00 00 00    	jne    0xabfec8
  abfe1d:	48 8d 3d 9e 09 89 00 	lea    rdi,[rip+0x89099e]        # 0x13507c2
  abfe24:	e8 57 b7 ba ff       	call   0x66b580
  abfe29:	48 8d 0d 50 32 74 01 	lea    rcx,[rip+0x1743250]        # 0x2203080
  abfe30:	48 8d 35 11 60 aa 01 	lea    rsi,[rip+0x1aa6011]        # 0x2565e48
  abfe37:	48 8b 91 50 01 00 00 	mov    rdx,QWORD PTR [rcx+0x150]
  abfe3e:	4c 8b 81 18 01 00 00 	mov    r8,QWORD PTR [rcx+0x118]
  abfe45:	48 8b b9 28 01 00 00 	mov    rdi,QWORD PTR [rcx+0x128]
  abfe4c:	4c 8b 49 10          	mov    r9,QWORD PTR [rcx+0x10]
  abfe50:	48 89 96 50 01 00 00 	mov    QWORD PTR [rsi+0x150],rdx
  abfe57:	4c 89 86 18 01 00 00 	mov    QWORD PTR [rsi+0x118],r8
  abfe5e:	48 89 be 28 01 00 00 	mov    QWORD PTR [rsi+0x128],rdi
  abfe65:	48 8b b9 f8 00 00 00 	mov    rdi,QWORD PTR [rcx+0xf8]
  abfe6c:	4c 8b 81 30 01 00 00 	mov    r8,QWORD PTR [rcx+0x130]
  abfe73:	48 89 be f8 00 00 00 	mov    QWORD PTR [rsi+0xf8],rdi
  abfe7a:	48 8b b9 c8 01 00 00 	mov    rdi,QWORD PTR [rcx+0x1c8]
  abfe81:	4c 89 4e 10          	mov    QWORD PTR [rsi+0x10],r9
  abfe85:	4c 89 86 30 01 00 00 	mov    QWORD PTR [rsi+0x130],r8
  abfe8c:	4c 8b 81 20 02 00 00 	mov    r8,QWORD PTR [rcx+0x220]
  abfe93:	48 89 be c8 01 00 00 	mov    QWORD PTR [rsi+0x1c8],rdi
  abfe9a:	48 8b b9 28 02 00 00 	mov    rdi,QWORD PTR [rcx+0x228]
  abfea1:	48 8b 89 30 02 00 00 	mov    rcx,QWORD PTR [rcx+0x230]
  abfea8:	4c 89 86 20 02 00 00 	mov    QWORD PTR [rsi+0x220],r8
  abfeaf:	48 89 be 28 02 00 00 	mov    QWORD PTR [rsi+0x228],rdi
  abfeb6:	48 89 8e 30 02 00 00 	mov    QWORD PTR [rsi+0x230],rcx
  abfebd:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
  abfec1:	48 89 05 98 6f 13 03 	mov    QWORD PTR [rip+0x3136f98],rax        # 0x3bf6e60
  abfec8:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  abfecf:	00 00 
  abfed1:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  abfed8:	be 00 01 00 00       	mov    esi,0x100
  abfedd:	e8 ae 9c 12 00       	call   0xbe9b90
  abfee2:	85 c0                	test   eax,eax
  abfee4:	0f 84 25 01 00 00    	je     0xac000f
  abfeea:	48 8b 8b 98 00 00 00 	mov    rcx,QWORD PTR [rbx+0x98]
  abfef1:	b8 2d 00 00 00       	mov    eax,0x2d
  abfef6:	f7 c1 00 40 00 00    	test   ecx,0x4000
  abfefc:	0f 85 1d 04 00 00    	jne    0xac031f
  abff02:	48 8b bb a8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa8]
  abff09:	f7 c1 00 00 01 00    	test   ecx,0x10000
  abff0f:	0f 85 97 01 00 00    	jne    0xac00ac
  abff15:	48 8d 35 82 e9 8a 00 	lea    rsi,[rip+0x8ae982]        # 0x136e89e
  abff1c:	48 8d 95 b8 fe ff ff 	lea    rdx,[rbp-0x148]
  abff23:	48 8d 8d b4 fe ff ff 	lea    rcx,[rbp-0x14c]
  abff2a:	e8 a1 f0 b1 ff       	call   0x5defd0
  abff2f:	85 c0                	test   eax,eax
  abff31:	0f 84 f5 01 00 00    	je     0xac012c
  abff37:	48 8b bb a8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa8]
  abff3e:	48 8d 35 5c 2e 7f 00 	lea    rsi,[rip+0x7f2e5c]        # 0x12b2da1
  abff45:	48 8d 95 b8 fe ff ff 	lea    rdx,[rbp-0x148]
  abff4c:	48 8d 8d b4 fe ff ff 	lea    rcx,[rbp-0x14c]
  abff53:	e8 78 f0 b1 ff       	call   0x5defd0
  abff58:	85 c0                	test   eax,eax
  abff5a:	89 85 cc fe ff ff    	mov    DWORD PTR [rbp-0x134],eax
  abff60:	0f 95 c0             	setne  al
  abff63:	e9 c6 01 00 00       	jmp    0xac012e
  abff68:	48 89 9d a8 fe ff ff 	mov    QWORD PTR [rbp-0x158],rbx
  abff6f:	48 83 ec 08          	sub    rsp,0x8
  abff73:	48 8d 9d e8 fe ff ff 	lea    rbx,[rbp-0x118]
  abff7a:	45 31 ed             	xor    r13d,r13d
  abff7d:	ba 64 00 00 04       	mov    edx,0x4000064
  abff82:	31 f6                	xor    esi,esi
  abff84:	b9 01 00 00 00       	mov    ecx,0x1
  abff89:	4d 89 f0             	mov    r8,r14
  abff8c:	41 b9 9c ff ff ff    	mov    r9d,0xffffff9c
  abff92:	48 89 df             	mov    rdi,rbx
  abff95:	41 57                	push   r15
  abff97:	6a 00                	push   0x0
  abff99:	6a 00                	push   0x0
  abff9b:	e8 40 a7 b3 ff       	call   0x5fa6e0
  abffa0:	48 83 c4 20          	add    rsp,0x20
  abffa4:	48 89 df             	mov    rdi,rbx
  abffa7:	e8 74 8c b3 ff       	call   0x5f8c20
  abffac:	85 c0                	test   eax,eax
  abffae:	74 69                	je     0xac0019
  abffb0:	83 f8 02             	cmp    eax,0x2
  abffb3:	0f 85 98 00 00 00    	jne    0xac0051
  abffb9:	48 8d 15 37 36 84 00 	lea    rdx,[rip+0x843637]        # 0x13035f7
  abffc0:	be 00 04 00 00       	mov    esi,0x400
  abffc5:	4c 89 f7             	mov    rdi,r14
  abffc8:	4c 89 e1             	mov    rcx,r12
  abffcb:	31 c0                	xor    eax,eax
  abffcd:	e8 6e ee 9e ff       	call   0x4aee40
  abffd2:	48 8b 9d a8 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x158]
  abffd9:	3d ff 03 00 00       	cmp    eax,0x3ff
  abffde:	7f 14                	jg     0xabfff4
  abffe0:	4c 89 f7             	mov    rdi,r14
  abffe3:	4c 89 fe             	mov    rsi,r15
  abffe6:	e8 45 0b f5 ff       	call   0xa10b30
  abffeb:	83 f8 11             	cmp    eax,0x11
  abffee:	0f 85 51 02 00 00    	jne    0xac0245
  abfff4:	48 8d 35 85 c0 13 02 	lea    rsi,[rip+0x213c085]        # 0x2bfc080
  abfffb:	4c 89 f7             	mov    rdi,r14
  abfffe:	e8 ed 8d 14 00       	call   0xc08df0
  ac0003:	4c 8d 2d 06 c3 e5 02 	lea    r13,[rip+0x2e5c306]        # 0x391c310
  ac000a:	e9 00 fe ff ff       	jmp    0xabfe0f
  ac000f:	b8 01 00 00 00       	mov    eax,0x1
  ac0014:	e9 06 03 00 00       	jmp    0xac031f
  ac0019:	48 8b bd 48 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb8]
  ac0020:	48 85 ff             	test   rdi,rdi
  ac0023:	74 19                	je     0xac003e
  ac0025:	31 c0                	xor    eax,eax
  ac0027:	83 bf d4 01 00 00 02 	cmp    DWORD PTR [rdi+0x1d4],0x2
  ac002e:	0f 94 c0             	sete   al
  ac0031:	44 8d 2c 85 11 00 00 	lea    r13d,[rax*4+0x11]
  ac0038:	00 
  ac0039:	e8 02 a4 a8 ff       	call   0x54a440
  ac003e:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  ac0045:	be df ff ff ff       	mov    esi,0xffffffdf
  ac004a:	e8 31 a7 b3 ff       	call   0x5fa780
  ac004f:	eb 03                	jmp    0xac0054
  ac0051:	41 89 c5             	mov    r13d,eax
  ac0054:	48 8b 9d a8 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x158]
  ac005b:	48 8d 35 1e c0 13 02 	lea    rsi,[rip+0x213c01e]        # 0x2bfc080
  ac0062:	4c 89 f7             	mov    rdi,r14
  ac0065:	e8 86 8d 14 00       	call   0xc08df0
  ac006a:	41 83 cd 04          	or     r13d,0x4
  ac006e:	41 83 fd 15          	cmp    r13d,0x15
  ac0072:	4c 8d 2d 97 c2 e5 02 	lea    r13,[rip+0x2e5c297]        # 0x391c310
  ac0079:	0f 85 90 fd ff ff    	jne    0xabfe0f
  ac007f:	8b 8d a4 fe ff ff    	mov    ecx,DWORD PTR [rbp-0x15c]
  ac0085:	0a 8b 98 00 00 00    	or     cl,BYTE PTR [rbx+0x98]
  ac008b:	b8 01 00 00 00       	mov    eax,0x1
  ac0090:	f6 c1 01             	test   cl,0x1
  ac0093:	0f 84 86 02 00 00    	je     0xac031f
  ac0099:	48 8d 3d d9 eb 82 00 	lea    rdi,[rip+0x82ebd9]        # 0x12eec79
  ac00a0:	31 c0                	xor    eax,eax
  ac00a2:	e8 69 d3 79 ff       	call   0x25d410
  ac00a7:	e9 63 fd ff ff       	jmp    0xabfe0f
  ac00ac:	48 8d 35 c5 9a 87 00 	lea    rsi,[rip+0x879ac5]        # 0x1339b78
  ac00b3:	31 d2                	xor    edx,edx
  ac00b5:	31 c9                	xor    ecx,ecx
  ac00b7:	e8 94 11 b2 ff       	call   0x5e1250
  ac00bc:	89 c1                	mov    ecx,eax
  ac00be:	b8 2d 00 00 00       	mov    eax,0x2d
  ac00c3:	85 c9                	test   ecx,ecx
  ac00c5:	0f 84 54 02 00 00    	je     0xac031f
  ac00cb:	c7 85 b0 fe ff ff 00 	mov    DWORD PTR [rbp-0x150],0x0
  ac00d2:	00 00 00 
  ac00d5:	48 89 df             	mov    rdi,rbx
  ac00d8:	48 8b 9b 98 02 00 00 	mov    rbx,QWORD PTR [rbx+0x298]
  ac00df:	48 c7 43 40 ff ff ff 	mov    QWORD PTR [rbx+0x40],0xffffffffffffffff
  ac00e6:	ff 
  ac00e7:	48 c7 43 50 00 00 00 	mov    QWORD PTR [rbx+0x50],0x0
  ac00ee:	00 
  ac00ef:	48 c7 43 48 00 00 00 	mov    QWORD PTR [rbx+0x48],0x0
  ac00f6:	00 
  ac00f7:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac00fe:	00 00 
  ac0100:	48 89 43 28          	mov    QWORD PTR [rbx+0x28],rax
  ac0104:	48 c7 43 30 00 00 00 	mov    QWORD PTR [rbx+0x30],0x0
  ac010b:	00 
  ac010c:	48 c7 43 38 00 00 00 	mov    QWORD PTR [rbx+0x38],0x0
  ac0113:	00 
  ac0114:	e8 17 0c f5 ff       	call   0xa10d30
  ac0119:	48 c7 43 28 00 00 00 	mov    QWORD PTR [rbx+0x28],0x0
  ac0120:	00 
  ac0121:	8b 85 b0 fe ff ff    	mov    eax,DWORD PTR [rbp-0x150]
  ac0127:	e9 f3 01 00 00       	jmp    0xac031f
  ac012c:	31 c0                	xor    eax,eax
  ac012e:	4c 8b 85 b8 fe ff ff 	mov    r8,QWORD PTR [rbp-0x148]
  ac0135:	8b 8d b4 fe ff ff    	mov    ecx,DWORD PTR [rbp-0x14c]
  ac013b:	4d 85 c0             	test   r8,r8
  ac013e:	0f 94 c2             	sete   dl
  ac0141:	08 c2                	or     dl,al
  ac0143:	85 c9                	test   ecx,ecx
  ac0145:	0f 94 c0             	sete   al
  ac0148:	08 d0                	or     al,dl
  ac014a:	b8 16 00 00 00       	mov    eax,0x16
  ac014f:	0f 85 ca 01 00 00    	jne    0xac031f
  ac0155:	ff c9                	dec    ecx
  ac0157:	48 63 c9             	movsxd rcx,ecx
  ac015a:	41 80 3c 08 00       	cmp    BYTE PTR [r8+rcx*1],0x0
  ac015f:	0f 85 ba 01 00 00    	jne    0xac031f
  ac0165:	48 8b 43 48          	mov    rax,QWORD PTR [rbx+0x48]
  ac0169:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
  ac016d:	48 3b 0d e4 d2 f9 00 	cmp    rcx,QWORD PTR [rip+0xf9d2e4]        # 0x1a5d458
  ac0174:	0f 85 da 00 00 00    	jne    0xac0254
  ac017a:	48 8d 0d 77 9d 01 01 	lea    rcx,[rip+0x1019d77]        # 0x1ad9ef8
  ac0181:	48 8d 3d f8 2e 74 01 	lea    rdi,[rip+0x1742ef8]        # 0x2203080
  ac0188:	48 8d b5 d0 fe ff ff 	lea    rsi,[rbp-0x130]
  ac018f:	48 89 8d d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rcx
  ac0196:	48 89 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rax
  ac019d:	e8 1e ae ac ff       	call   0x58afc0
  ac01a2:	3d 00 00 08 00       	cmp    eax,0x80000
  ac01a7:	0f 85 a0 00 00 00    	jne    0xac024d
  ac01ad:	48 8b 43 48          	mov    rax,QWORD PTR [rbx+0x48]
  ac01b1:	48 8d 0d 10 cc 01 01 	lea    rcx,[rip+0x101cc10]        # 0x1adcdc8
  ac01b8:	48 8d b5 d0 fe ff ff 	lea    rsi,[rbp-0x130]
  ac01bf:	48 89 8d d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rcx
  ac01c6:	48 89 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rax
  ac01cd:	c7 85 e0 fe ff ff 00 	mov    DWORD PTR [rbp-0x120],0x0
  ac01d4:	00 00 00 
  ac01d7:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  ac01db:	e8 b0 e8 ac ff       	call   0x58ea90
  ac01e0:	4c 8b 85 b8 fe ff ff 	mov    r8,QWORD PTR [rbp-0x148]
  ac01e7:	48 83 ec 08          	sub    rsp,0x8
  ac01eb:	49 89 dc             	mov    r12,rbx
  ac01ee:	48 8d 9d e8 fe ff ff 	lea    rbx,[rbp-0x118]
  ac01f5:	ba 44 00 00 00       	mov    edx,0x44
  ac01fa:	31 f6                	xor    esi,esi
  ac01fc:	b9 01 00 00 00       	mov    ecx,0x1
  ac0201:	41 b9 9c ff ff ff    	mov    r9d,0xffffff9c
  ac0207:	48 89 df             	mov    rdi,rbx
  ac020a:	41 56                	push   r14
  ac020c:	6a 00                	push   0x0
  ac020e:	6a 00                	push   0x0
  ac0210:	e8 cb a4 b3 ff       	call   0x5fa6e0
  ac0215:	48 83 c4 20          	add    rsp,0x20
  ac0219:	48 89 df             	mov    rdi,rbx
  ac021c:	e8 ff 89 b3 ff       	call   0x5f8c20
  ac0221:	49 8b 7c 24 48       	mov    rdi,QWORD PTR [r12+0x48]
  ac0226:	48 8d 15 ce ca 88 00 	lea    rdx,[rip+0x88cace]        # 0x134ccfb
  ac022d:	be 00 04 08 00       	mov    esi,0x80400
  ac0232:	b9 87 00 00 00       	mov    ecx,0x87
  ac0237:	89 c3                	mov    ebx,eax
  ac0239:	4d 89 e7             	mov    r15,r12
  ac023c:	e8 0f f9 be ff       	call   0x6afb50
  ac0241:	89 d8                	mov    eax,ebx
  ac0243:	eb 49                	jmp    0xac028e
  ac0245:	41 89 c5             	mov    r13d,eax
  ac0248:	e9 0e fe ff ff       	jmp    0xac005b
  ac024d:	4c 8b 85 b8 fe ff ff 	mov    r8,QWORD PTR [rbp-0x148]
  ac0254:	49 89 df             	mov    r15,rbx
  ac0257:	48 83 ec 08          	sub    rsp,0x8
  ac025b:	48 8d 9d e8 fe ff ff 	lea    rbx,[rbp-0x118]
  ac0262:	ba 44 00 00 00       	mov    edx,0x44
  ac0267:	31 f6                	xor    esi,esi
  ac0269:	b9 01 00 00 00       	mov    ecx,0x1
  ac026e:	41 b9 9c ff ff ff    	mov    r9d,0xffffff9c
  ac0274:	48 89 df             	mov    rdi,rbx
  ac0277:	41 56                	push   r14
  ac0279:	6a 00                	push   0x0
  ac027b:	6a 00                	push   0x0
  ac027d:	e8 5e a4 b3 ff       	call   0x5fa6e0
  ac0282:	48 83 c4 20          	add    rsp,0x20
  ac0286:	48 89 df             	mov    rdi,rbx
  ac0289:	e8 92 89 b3 ff       	call   0x5f8c20
  ac028e:	85 c0                	test   eax,eax
  ac0290:	0f 85 89 00 00 00    	jne    0xac031f
  ac0296:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  ac029d:	be df ff ff ff       	mov    esi,0xffffffdf
  ac02a2:	4c 89 fb             	mov    rbx,r15
  ac02a5:	e8 d6 a4 b3 ff       	call   0x5fa780
  ac02aa:	4c 8b bd 48 ff ff ff 	mov    r15,QWORD PTR [rbp-0xb8]
  ac02b1:	48 8d 35 18 8c dc 01 	lea    rsi,[rip+0x1dc8c18]        # 0x2888ed0
  ac02b8:	bf 58 00 00 00       	mov    edi,0x58
  ac02bd:	ba 02 01 00 00       	mov    edx,0x102
  ac02c2:	e8 89 88 14 00       	call   0xc08b50
  ac02c7:	48 c7 40 20 00 00 00 	mov    QWORD PTR [rax+0x20],0x0
  ac02ce:	00 
  ac02cf:	49 89 c6             	mov    r14,rax
  ac02d2:	48 8d 95 c0 fe ff ff 	lea    rdx,[rbp-0x140]
  ac02d9:	48 89 df             	mov    rdi,rbx
  ac02dc:	4c 89 fe             	mov    rsi,r15
  ac02df:	49 8b 47 18          	mov    rax,QWORD PTR [r15+0x18]
  ac02e3:	49 89 06             	mov    QWORD PTR [r14],rax
  ac02e6:	e8 b5 29 ad ff       	call   0x592ca0
  ac02eb:	89 85 cc fe ff ff    	mov    DWORD PTR [rbp-0x134],eax
  ac02f1:	85 c0                	test   eax,eax
  ac02f3:	74 4a                	je     0xac033f
  ac02f5:	48 8d 3d 37 60 7e 00 	lea    rdi,[rip+0x7e6037]        # 0x12a6333
  ac02fc:	48 8d 35 13 b5 8e 00 	lea    rsi,[rip+0x8eb513]        # 0x13ab816
  ac0303:	89 c2                	mov    edx,eax
  ac0305:	89 c3                	mov    ebx,eax
  ac0307:	31 c0                	xor    eax,eax
  ac0309:	e8 02 d1 79 ff       	call   0x25d410
  ac030e:	48 8d 35 bb 8b dc 01 	lea    rsi,[rip+0x1dc8bbb]        # 0x2888ed0
  ac0315:	4c 89 f7             	mov    rdi,r14
  ac0318:	e8 d3 8a 14 00       	call   0xc08df0
  ac031d:	89 d8                	mov    eax,ebx
  ac031f:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  ac0323:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  ac0327:	0f 85 2e 02 00 00    	jne    0xac055b
  ac032d:	48 81 c4 38 01 00 00 	add    rsp,0x138
  ac0334:	5b                   	pop    rbx
  ac0335:	41 5c                	pop    r12
  ac0337:	41 5d                	pop    r13
  ac0339:	41 5e                	pop    r14
  ac033b:	41 5f                	pop    r15
  ac033d:	5d                   	pop    rbp
  ac033e:	c3                   	ret
  ac033f:	48 8b 85 c0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x140]
  ac0346:	48 8d 35 48 ce 7a 00 	lea    rsi,[rip+0x7ace48]        # 0x126d195
  ac034d:	48 8d 95 cc fe ff ff 	lea    rdx,[rbp-0x134]
  ac0354:	81 88 c8 01 00 00 80 	or     DWORD PTR [rax+0x1c8],0x80
  ac035b:	00 00 00 
  ac035e:	48 89 d8             	mov    rax,rbx
  ac0361:	48 8b 9d c0 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x140]
  ac0368:	48 89 85 a8 fe ff ff 	mov    QWORD PTR [rbp-0x158],rax
  ac036f:	83 8b c8 01 00 00 01 	or     DWORD PTR [rbx+0x1c8],0x1
  ac0376:	49 89 5e 08          	mov    QWORD PTR [r14+0x8],rbx
  ac037a:	49 c7 46 18 00 00 00 	mov    QWORD PTR [r14+0x18],0x0
  ac0381:	00 
  ac0382:	48 8b b8 a8 00 00 00 	mov    rdi,QWORD PTR [rax+0xa8]
  ac0389:	e8 42 0e b2 ff       	call   0x5e11d0
  ac038e:	8b 8d cc fe ff ff    	mov    ecx,DWORD PTR [rbp-0x134]
  ac0394:	83 f9 02             	cmp    ecx,0x2
  ac0397:	75 0c                	jne    0xac03a5
  ac0399:	c7 85 cc fe ff ff 00 	mov    DWORD PTR [rbp-0x134],0x0
  ac03a0:	00 00 00 
  ac03a3:	eb 2f                	jmp    0xac03d4
  ac03a5:	85 c9                	test   ecx,ecx
  ac03a7:	0f 94 c1             	sete   cl
  ac03aa:	48 85 c0             	test   rax,rax
  ac03ad:	0f 95 c2             	setne  dl
  ac03b0:	20 ca                	and    dl,cl
  ac03b2:	80 fa 01             	cmp    dl,0x1
  ac03b5:	75 1d                	jne    0xac03d4
  ac03b7:	48 8d 35 c6 94 8b 00 	lea    rsi,[rip+0x8b94c6]        # 0x1379884
  ac03be:	ba 05 00 00 00       	mov    edx,0x5
  ac03c3:	48 89 c7             	mov    rdi,rax
  ac03c6:	e8 65 16 e1 ff       	call   0x8d1a30
  ac03cb:	85 c0                	test   eax,eax
  ac03cd:	75 05                	jne    0xac03d4
  ac03cf:	41 80 4e 1b 01       	or     BYTE PTR [r14+0x1b],0x1
  ac03d4:	48 8b 85 c0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x140]
  ac03db:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  ac03df:	4c 89 70 28          	mov    QWORD PTR [rax+0x28],r14
  ac03e3:	48 8b bd c0 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x140]
  ac03ea:	e8 71 9c a8 ff       	call   0x54a060
  ac03ef:	48 8d 0d d2 c9 01 01 	lea    rcx,[rip+0x101c9d2]        # 0x1adcdc8
  ac03f6:	48 8b 85 c0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x140]
  ac03fd:	48 8d b5 d0 fe ff ff 	lea    rsi,[rbp-0x130]
  ac0404:	48 89 8d d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rcx
  ac040b:	48 89 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rax
  ac0412:	c7 85 e0 fe ff ff 00 	mov    DWORD PTR [rbp-0x120],0x0
  ac0419:	00 00 00 
  ac041c:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  ac0420:	e8 6b e6 ac ff       	call   0x58ea90
  ac0425:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  ac0429:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  ac042d:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
  ac0431:	f6 80 99 00 00 00 10 	test   BYTE PTR [rax+0x99],0x10
  ac0438:	74 31                	je     0xac046b
  ac043a:	4c 8b a5 a8 fe ff ff 	mov    r12,QWORD PTR [rbp-0x158]
  ac0441:	31 f6                	xor    esi,esi
  ac0443:	31 d2                	xor    edx,edx
  ac0445:	31 c9                	xor    ecx,ecx
  ac0447:	49 8d 5c 24 18       	lea    rbx,[r12+0x18]
  ac044c:	48 89 df             	mov    rdi,rbx
  ac044f:	e8 ac 65 a0 ff       	call   0x4c6a00
  ac0454:	41 80 8c 24 99 00 00 	or     BYTE PTR [r12+0x99],0x10
  ac045b:	00 10 
  ac045d:	48 89 df             	mov    rdi,rbx
  ac0460:	31 f6                	xor    esi,esi
  ac0462:	31 d2                	xor    edx,edx
  ac0464:	31 c9                	xor    ecx,ecx
  ac0466:	e8 35 6b a0 ff       	call   0x4c6fa0
  ac046b:	48 8b 9d a8 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x158]
  ac0472:	41 80 66 10 fe       	and    BYTE PTR [r14+0x10],0xfe
  ac0477:	31 f6                	xor    esi,esi
  ac0479:	31 d2                	xor    edx,edx
  ac047b:	31 c9                	xor    ecx,ecx
  ac047d:	4c 8d 63 18          	lea    r12,[rbx+0x18]
  ac0481:	4c 89 e7             	mov    rdi,r12
  ac0484:	e8 77 65 a0 ff       	call   0x4c6a00
  ac0489:	41 f6 46 10 01       	test   BYTE PTR [r14+0x10],0x1
  ac048e:	75 08                	jne    0xac0498
  ac0490:	8b 83 90 00 00 00    	mov    eax,DWORD PTR [rbx+0x90]
  ac0496:	eb 15                	jmp    0xac04ad
  ac0498:	49 8b 4f 18          	mov    rcx,QWORD PTR [r15+0x18]
  ac049c:	b8 c0 00 00 40       	mov    eax,0x400000c0
  ac04a1:	23 81 90 00 00 00    	and    eax,DWORD PTR [rcx+0x90]
  ac04a7:	0b 83 90 00 00 00    	or     eax,DWORD PTR [rbx+0x90]
  ac04ad:	0d 00 08 00 00       	or     eax,0x800
  ac04b2:	ba 00 61 00 00       	mov    edx,0x6100
  ac04b7:	4c 89 e7             	mov    rdi,r12
  ac04ba:	31 f6                	xor    esi,esi
  ac04bc:	89 83 90 00 00 00    	mov    DWORD PTR [rbx+0x90],eax
  ac04c2:	49 8b 4f 18          	mov    rcx,QWORD PTR [r15+0x18]
  ac04c6:	23 91 90 00 00 00    	and    edx,DWORD PTR [rcx+0x90]
  ac04cc:	31 c9                	xor    ecx,ecx
  ac04ce:	09 c2                	or     edx,eax
  ac04d0:	89 93 90 00 00 00    	mov    DWORD PTR [rbx+0x90],edx
  ac04d6:	31 d2                	xor    edx,edx
  ac04d8:	e8 c3 6a a0 ff       	call   0x4c6fa0
  ac04dd:	48 89 df             	mov    rdi,rbx
  ac04e0:	4c 89 b3 98 02 00 00 	mov    QWORD PTR [rbx+0x298],r14
  ac04e7:	e8 d4 74 a8 ff       	call   0x5479c0
  ac04ec:	41 f6 46 10 01       	test   BYTE PTR [r14+0x10],0x1
  ac04f1:	74 54                	je     0xac0547
  ac04f3:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  ac04f6:	31 f6                	xor    esi,esi
  ac04f8:	31 d2                	xor    edx,edx
  ac04fa:	31 c9                	xor    ecx,ecx
  ac04fc:	48 83 c7 18          	add    rdi,0x18
  ac0500:	e8 fb 64 a0 ff       	call   0x4c6a00
  ac0505:	48 c7 83 10 03 00 00 	mov    QWORD PTR [rbx+0x310],0x0
  ac050c:	00 00 00 00 
  ac0510:	48 8d 83 10 03 00 00 	lea    rax,[rbx+0x310]
  ac0517:	31 f6                	xor    esi,esi
  ac0519:	31 d2                	xor    edx,edx
  ac051b:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  ac051e:	48 8b 89 28 03 00 00 	mov    rcx,QWORD PTR [rcx+0x328]
  ac0525:	48 89 8b 18 03 00 00 	mov    QWORD PTR [rbx+0x318],rcx
  ac052c:	48 89 19             	mov    QWORD PTR [rcx],rbx
  ac052f:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  ac0532:	48 89 81 28 03 00 00 	mov    QWORD PTR [rcx+0x328],rax
  ac0539:	31 c9                	xor    ecx,ecx
  ac053b:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  ac053e:	48 83 c7 18          	add    rdi,0x18
  ac0542:	e8 59 6a a0 ff       	call   0x4c6fa0
  ac0547:	48 8b b5 b8 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x148]
  ac054e:	48 89 df             	mov    rdi,rbx
  ac0551:	e8 ca 0e b2 ff       	call   0x5e1420
  ac0556:	e9 70 fb ff ff       	jmp    0xac00cb
  ac055b:	e8 50 d1 c3 ff       	call   0x6fd6b0
  ac0560:	0f 0b                	ud2
  ac0562:	90                   	nop
  ac0563:	90                   	nop
  ac0564:	90                   	nop
  ac0565:	90                   	nop
  ac0566:	90                   	nop
  ac0567:	90                   	nop
  ac0568:	90                   	nop
  ac0569:	90                   	nop
  ac056a:	90                   	nop
  ac056b:	90                   	nop
  ac056c:	90                   	nop
  ac056d:	90                   	nop
  ac056e:	90                   	nop
  ac056f:	90                   	nop
  ac0570:	55                   	push   rbp
  ac0571:	48 89 e5             	mov    rbp,rsp
  ac0574:	49 89 d0             	mov    r8,rdx
  ac0577:	48 89 f1             	mov    rcx,rsi
  ac057a:	48 89 fa             	mov    rdx,rdi
  ac057d:	48 8d 3d 8d ce 86 00 	lea    rdi,[rip+0x86ce8d]        # 0x132d411
  ac0584:	48 8d 35 b5 da 84 00 	lea    rsi,[rip+0x84dab5]        # 0x130e040
  ac058b:	31 c0                	xor    eax,eax
  ac058d:	e8 7e ce 79 ff       	call   0x25d410
  ac0592:	b8 2d 00 00 00       	mov    eax,0x2d
  ac0597:	5d                   	pop    rbp
  ac0598:	c3                   	ret
  ac0599:	90                   	nop
  ac059a:	90                   	nop
  ac059b:	90                   	nop
  ac059c:	90                   	nop
  ac059d:	90                   	nop
  ac059e:	90                   	nop
  ac059f:	90                   	nop
  ac05a0:	55                   	push   rbp
  ac05a1:	48 89 e5             	mov    rbp,rsp
  ac05a4:	41 57                	push   r15
  ac05a6:	41 56                	push   r14
  ac05a8:	41 54                	push   r12
  ac05aa:	53                   	push   rbx
  ac05ab:	4c 8b a7 98 02 00 00 	mov    r12,QWORD PTR [rdi+0x298]
  ac05b2:	41 89 f6             	mov    r14d,esi
  ac05b5:	48 89 fb             	mov    rbx,rdi
  ac05b8:	49 8b 44 24 40       	mov    rax,QWORD PTR [r12+0x40]
  ac05bd:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
  ac05c1:	74 62                	je     0xac0625
  ac05c3:	b8 10 00 00 00       	mov    eax,0x10
  ac05c8:	41 f7 c6 00 00 08 00 	test   r14d,0x80000
  ac05cf:	0f 84 c0 00 00 00    	je     0xac0695
  ac05d5:	4d 8b 7c 24 40       	mov    r15,QWORD PTR [r12+0x40]
  ac05da:	be 04 00 00 00       	mov    esi,0x4
  ac05df:	4c 89 ff             	mov    rdi,r15
  ac05e2:	e8 a9 be e9 ff       	call   0x95c490
  ac05e7:	85 c0                	test   eax,eax
  ac05e9:	74 17                	je     0xac0602
  ac05eb:	89 c2                	mov    edx,eax
  ac05ed:	48 8d 3d 40 ce 86 00 	lea    rdi,[rip+0x86ce40]        # 0x132d434
  ac05f4:	48 8d 35 04 4a 80 00 	lea    rsi,[rip+0x804a04]        # 0x12c4fff
  ac05fb:	31 c0                	xor    eax,eax
  ac05fd:	e8 0e ce 79 ff       	call   0x25d410
  ac0602:	4c 89 ff             	mov    rdi,r15
  ac0605:	e8 d6 bc e9 ff       	call   0x95c2e0
  ac060a:	85 c0                	test   eax,eax
  ac060c:	74 17                	je     0xac0625
  ac060e:	89 c2                	mov    edx,eax
  ac0610:	48 8d 3d 9f 3e 82 00 	lea    rdi,[rip+0x823e9f]        # 0x12e44b6
  ac0617:	48 8d 35 e1 49 80 00 	lea    rsi,[rip+0x8049e1]        # 0x12c4fff
  ac061e:	31 c0                	xor    eax,eax
  ac0620:	e8 eb cd 79 ff       	call   0x25d410
  ac0625:	41 c1 ee 12          	shr    r14d,0x12
  ac0629:	65 4c 8b 3c 25 00 00 	mov    r15,QWORD PTR gs:0x0
  ac0630:	00 00 
  ac0632:	48 89 df             	mov    rdi,rbx
  ac0635:	4c 89 f9             	mov    rcx,r15
  ac0638:	31 f6                	xor    esi,esi
  ac063a:	41 83 e6 02          	and    r14d,0x2
  ac063e:	41 8d 56 01          	lea    edx,[r14+0x1]
  ac0642:	e8 19 9e a8 ff       	call   0x54a460
  ac0647:	85 c0                	test   eax,eax
  ac0649:	74 09                	je     0xac0654
  ac064b:	48 8d 3d d7 02 8e 00 	lea    rdi,[rip+0x8e02d7]        # 0x13a0929
  ac0652:	eb 2d                	jmp    0xac0681
  ac0654:	49 8b 7c 24 20       	mov    rdi,QWORD PTR [r12+0x20]
  ac0659:	48 85 ff             	test   rdi,rdi
  ac065c:	74 05                	je     0xac0663
  ac065e:	e8 bd 9a a8 ff       	call   0x54a120
  ac0663:	48 89 df             	mov    rdi,rbx
  ac0666:	be 01 00 00 00       	mov    esi,0x1
  ac066b:	44 89 f2             	mov    edx,r14d
  ac066e:	4c 89 f9             	mov    rcx,r15
  ac0671:	e8 ea 9d a8 ff       	call   0x54a460
  ac0676:	85 c0                	test   eax,eax
  ac0678:	74 24                	je     0xac069e
  ac067a:	48 8d 3d f1 f5 80 00 	lea    rdi,[rip+0x80f5f1]        # 0x12cfc72
  ac0681:	48 8d 35 77 49 80 00 	lea    rsi,[rip+0x804977]        # 0x12c4fff
  ac0688:	89 c2                	mov    edx,eax
  ac068a:	89 c3                	mov    ebx,eax
  ac068c:	31 c0                	xor    eax,eax
  ac068e:	e8 7d cd 79 ff       	call   0x25d410
  ac0693:	89 d8                	mov    eax,ebx
  ac0695:	5b                   	pop    rbx
  ac0696:	41 5c                	pop    r12
  ac0698:	41 5e                	pop    r14
  ac069a:	41 5f                	pop    r15
  ac069c:	5d                   	pop    rbp
  ac069d:	c3                   	ret
  ac069e:	48 8b bb 98 02 00 00 	mov    rdi,QWORD PTR [rbx+0x298]
  ac06a5:	48 8d 35 24 88 dc 01 	lea    rsi,[rip+0x1dc8824]        # 0x2888ed0
  ac06ac:	48 c7 83 98 02 00 00 	mov    QWORD PTR [rbx+0x298],0x0
  ac06b3:	00 00 00 00 
  ac06b7:	e8 34 87 14 00       	call   0xc08df0
  ac06bc:	31 c0                	xor    eax,eax
  ac06be:	eb d5                	jmp    0xac0695
  ac06c0:	48 c7 02 00 00 00 00 	mov    QWORD PTR [rdx],0x0
  ac06c7:	48 8b 05 92 67 13 03 	mov    rax,QWORD PTR [rip+0x3136792]        # 0x3bf6e60
  ac06ce:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
  ac06d2:	48 8d 05 df 85 7a ff 	lea    rax,[rip+0xffffffffff7a85df]        # 0x268cb8
  ac06d9:	48 29 c8             	sub    rax,rcx
  ac06dc:	48 c1 c8 03          	ror    rax,0x3
  ac06e0:	48 3d f1 00 00 00    	cmp    rax,0xf1
  ac06e6:	77 02                	ja     0xac06ea
  ac06e8:	ff e1                	jmp    rcx
  ac06ea:	55                   	push   rbp
  ac06eb:	48 89 e5             	mov    rbp,rsp
  ac06ee:	41 57                	push   r15
  ac06f0:	41 56                	push   r14
  ac06f2:	41 54                	push   r12
  ac06f4:	53                   	push   rbx
  ac06f5:	48 8d 05 54 89 dc 01 	lea    rax,[rip+0x1dc8954]        # 0x2889050
  ac06fc:	48 89 fb             	mov    rbx,rdi
  ac06ff:	41 89 f6             	mov    r14d,esi
  ac0702:	48 89 ce             	mov    rsi,rcx
  ac0705:	49 89 d7             	mov    r15,rdx
  ac0708:	49 89 cc             	mov    r12,rcx
  ac070b:	48 89 c7             	mov    rdi,rax
  ac070e:	e8 ad f1 98 ff       	call   0x44f8c0
  ac0713:	4c 89 e1             	mov    rcx,r12
  ac0716:	48 89 df             	mov    rdi,rbx
  ac0719:	44 89 f6             	mov    esi,r14d
  ac071c:	4c 89 fa             	mov    rdx,r15
  ac071f:	5b                   	pop    rbx
  ac0720:	41 5c                	pop    r12
  ac0722:	41 5e                	pop    r14
  ac0724:	41 5f                	pop    r15
  ac0726:	5d                   	pop    rbp
  ac0727:	ff e1                	jmp    rcx
  ac0729:	90                   	nop
  ac072a:	90                   	nop
  ac072b:	90                   	nop
  ac072c:	90                   	nop
  ac072d:	90                   	nop
  ac072e:	90                   	nop
  ac072f:	90                   	nop
  ac0730:	48 8b 05 29 67 13 03 	mov    rax,QWORD PTR [rip+0x3136729]        # 0x3bf6e60
  ac0737:	4c 8b 40 20          	mov    r8,QWORD PTR [rax+0x20]
  ac073b:	48 8d 05 be b1 7a ff 	lea    rax,[rip+0xffffffffff7ab1be]        # 0x26b900
  ac0742:	4c 29 c0             	sub    rax,r8
  ac0745:	48 c1 c8 03          	ror    rax,0x3
  ac0749:	48 83 f8 06          	cmp    rax,0x6
  ac074d:	77 03                	ja     0xac0752
  ac074f:	41 ff e0             	jmp    r8
  ac0752:	55                   	push   rbp
  ac0753:	48 89 e5             	mov    rbp,rsp
  ac0756:	41 57                	push   r15
  ac0758:	41 56                	push   r14
  ac075a:	41 55                	push   r13
  ac075c:	41 54                	push   r12
  ac075e:	53                   	push   rbx
  ac075f:	50                   	push   rax
  ac0760:	48 8d 05 09 89 dc 01 	lea    rax,[rip+0x1dc8909]        # 0x2889070
  ac0767:	48 89 fb             	mov    rbx,rdi
  ac076a:	41 89 f6             	mov    r14d,esi
  ac076d:	4c 89 c6             	mov    rsi,r8
  ac0770:	49 89 cf             	mov    r15,rcx
  ac0773:	41 89 d4             	mov    r12d,edx
  ac0776:	4d 89 c5             	mov    r13,r8
  ac0779:	48 89 c7             	mov    rdi,rax
  ac077c:	e8 3f f1 98 ff       	call   0x44f8c0
  ac0781:	4d 89 e8             	mov    r8,r13
  ac0784:	48 89 df             	mov    rdi,rbx
  ac0787:	44 89 f6             	mov    esi,r14d
  ac078a:	44 89 e2             	mov    edx,r12d
  ac078d:	4c 89 f9             	mov    rcx,r15
  ac0790:	48 83 c4 08          	add    rsp,0x8
  ac0794:	5b                   	pop    rbx
  ac0795:	41 5c                	pop    r12
  ac0797:	41 5d                	pop    r13
  ac0799:	41 5e                	pop    r14
  ac079b:	41 5f                	pop    r15
  ac079d:	5d                   	pop    rbp
  ac079e:	41 ff e0             	jmp    r8
  ac07a1:	90                   	nop
  ac07a2:	90                   	nop
  ac07a3:	90                   	nop
  ac07a4:	90                   	nop
  ac07a5:	90                   	nop
  ac07a6:	90                   	nop
  ac07a7:	90                   	nop
  ac07a8:	90                   	nop
  ac07a9:	90                   	nop
  ac07aa:	90                   	nop
  ac07ab:	90                   	nop
  ac07ac:	90                   	nop
  ac07ad:	90                   	nop
  ac07ae:	90                   	nop
  ac07af:	90                   	nop
  ac07b0:	48 8b 05 a9 66 13 03 	mov    rax,QWORD PTR [rip+0x31366a9]        # 0x3bf6e60
  ac07b7:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
  ac07bb:	48 8d 05 46 68 7a ff 	lea    rax,[rip+0xffffffffff7a6846]        # 0x267008
  ac07c2:	48 29 c8             	sub    rax,rcx
  ac07c5:	48 c1 c8 03          	ror    rax,0x3
  ac07c9:	48 3d a5 03 00 00    	cmp    rax,0x3a5
  ac07cf:	77 02                	ja     0xac07d3
  ac07d1:	ff e1                	jmp    rcx
  ac07d3:	55                   	push   rbp
  ac07d4:	48 89 e5             	mov    rbp,rsp
  ac07d7:	41 57                	push   r15
  ac07d9:	41 56                	push   r14
  ac07db:	53                   	push   rbx
  ac07dc:	50                   	push   rax
  ac07dd:	48 8d 05 ac 88 dc 01 	lea    rax,[rip+0x1dc88ac]        # 0x2889090
  ac07e4:	48 89 fb             	mov    rbx,rdi
  ac07e7:	49 89 f6             	mov    r14,rsi
  ac07ea:	48 89 ce             	mov    rsi,rcx
  ac07ed:	49 89 cf             	mov    r15,rcx
  ac07f0:	48 89 c7             	mov    rdi,rax
  ac07f3:	e8 c8 f0 98 ff       	call   0x44f8c0
  ac07f8:	4c 89 f9             	mov    rcx,r15
  ac07fb:	48 89 df             	mov    rdi,rbx
  ac07fe:	4c 89 f6             	mov    rsi,r14
  ac0801:	48 83 c4 08          	add    rsp,0x8
  ac0805:	5b                   	pop    rbx
  ac0806:	41 5e                	pop    r14
  ac0808:	41 5f                	pop    r15
  ac080a:	5d                   	pop    rbp
  ac080b:	ff e1                	jmp    rcx
  ac080d:	90                   	nop
  ac080e:	90                   	nop
  ac080f:	90                   	nop
  ac0810:	55                   	push   rbp
  ac0811:	48 89 e5             	mov    rbp,rsp
  ac0814:	41 57                	push   r15
  ac0816:	41 56                	push   r14
  ac0818:	41 55                	push   r13
  ac081a:	41 54                	push   r12
  ac081c:	53                   	push   rbx
  ac081d:	50                   	push   rax
  ac081e:	48 c7 01 00 00 00 00 	mov    QWORD PTR [rcx],0x0
  ac0825:	49 89 fe             	mov    r14,rdi
  ac0828:	48 89 cb             	mov    rbx,rcx
  ac082b:	41 bf ff ff ff ff    	mov    r15d,0xffffffff
  ac0831:	48 8b 87 98 02 00 00 	mov    rax,QWORD PTR [rdi+0x298]
  ac0838:	48 8b 38             	mov    rdi,QWORD PTR [rax]
  ac083b:	48 8b 47 40          	mov    rax,QWORD PTR [rdi+0x40]
  ac083f:	8b 40 28             	mov    eax,DWORD PTR [rax+0x28]
  ac0842:	c1 e8 17             	shr    eax,0x17
  ac0845:	83 e0 02             	and    eax,0x2
  ac0848:	74 20                	je     0xac086a
  ac084a:	89 c7                	mov    edi,eax
  ac084c:	41 89 d7             	mov    r15d,edx
  ac084f:	41 89 f4             	mov    r12d,esi
  ac0852:	e8 99 14 aa ff       	call   0x561cf0
  ac0857:	49 8b 8e 98 02 00 00 	mov    rcx,QWORD PTR [r14+0x298]
  ac085e:	44 89 fa             	mov    edx,r15d
  ac0861:	44 89 e6             	mov    esi,r12d
  ac0864:	41 89 c7             	mov    r15d,eax
  ac0867:	48 8b 39             	mov    rdi,QWORD PTR [rcx]
  ac086a:	48 8b 47 38          	mov    rax,QWORD PTR [rdi+0x38]
  ac086e:	4c 8b 60 38          	mov    r12,QWORD PTR [rax+0x38]
  ac0872:	48 8d 05 5f b2 7a ff 	lea    rax,[rip+0xffffffffff7ab25f]        # 0x26bad8
  ac0879:	4c 29 e0             	sub    rax,r12
  ac087c:	48 c1 c8 03          	ror    rax,0x3
  ac0880:	48 83 f8 0f          	cmp    rax,0xf
  ac0884:	77 4a                	ja     0xac08d0
  ac0886:	48 89 d9             	mov    rcx,rbx
  ac0889:	41 ff d4             	call   r12
  ac088c:	41 89 c4             	mov    r12d,eax
  ac088f:	41 83 ff ff          	cmp    r15d,0xffffffff
  ac0893:	74 08                	je     0xac089d
  ac0895:	44 89 ff             	mov    edi,r15d
  ac0898:	e8 43 15 aa ff       	call   0x561de0
  ac089d:	45 85 e4             	test   r12d,r12d
  ac08a0:	74 12                	je     0xac08b4
  ac08a2:	44 89 e0             	mov    eax,r12d
  ac08a5:	48 83 c4 08          	add    rsp,0x8
  ac08a9:	5b                   	pop    rbx
  ac08aa:	41 5c                	pop    r12
  ac08ac:	41 5d                	pop    r13
  ac08ae:	41 5e                	pop    r14
  ac08b0:	41 5f                	pop    r15
  ac08b2:	5d                   	pop    rbp
  ac08b3:	c3                   	ret
  ac08b4:	48 8b 33             	mov    rsi,QWORD PTR [rbx]
  ac08b7:	4c 89 f7             	mov    rdi,r14
  ac08ba:	48 89 da             	mov    rdx,rbx
  ac08bd:	48 83 c4 08          	add    rsp,0x8
  ac08c1:	5b                   	pop    rbx
  ac08c2:	41 5c                	pop    r12
  ac08c4:	41 5d                	pop    r13
  ac08c6:	41 5e                	pop    r14
  ac08c8:	41 5f                	pop    r15
  ac08ca:	5d                   	pop    rbp
  ac08cb:	e9 d0 23 ad ff       	jmp    0x592ca0
  ac08d0:	89 75 d4             	mov    DWORD PTR [rbp-0x2c],esi
  ac08d3:	48 8d 3d d6 87 dc 01 	lea    rdi,[rip+0x1dc87d6]        # 0x28890b0
  ac08da:	4c 89 e6             	mov    rsi,r12
  ac08dd:	41 89 d5             	mov    r13d,edx
  ac08e0:	e8 db ef 98 ff       	call   0x44f8c0
  ac08e5:	49 8b 86 98 02 00 00 	mov    rax,QWORD PTR [r14+0x298]
  ac08ec:	8b 75 d4             	mov    esi,DWORD PTR [rbp-0x2c]
  ac08ef:	44 89 ea             	mov    edx,r13d
  ac08f2:	48 8b 38             	mov    rdi,QWORD PTR [rax]
  ac08f5:	eb 8f                	jmp    0xac0886
  ac08f7:	90                   	nop
  ac08f8:	90                   	nop
  ac08f9:	90                   	nop
  ac08fa:	90                   	nop
  ac08fb:	90                   	nop
  ac08fc:	90                   	nop
  ac08fd:	90                   	nop
  ac08fe:	90                   	nop
  ac08ff:	90                   	nop
  ac0900:	55                   	push   rbp
  ac0901:	48 89 e5             	mov    rbp,rsp
  ac0904:	41 57                	push   r15
  ac0906:	41 56                	push   r14
  ac0908:	41 55                	push   r13
  ac090a:	41 54                	push   r12
  ac090c:	53                   	push   rbx
  ac090d:	50                   	push   rax
  ac090e:	48 c7 01 00 00 00 00 	mov    QWORD PTR [rcx],0x0
  ac0915:	49 89 fe             	mov    r14,rdi
  ac0918:	48 89 cb             	mov    rbx,rcx
  ac091b:	41 bf ff ff ff ff    	mov    r15d,0xffffffff
  ac0921:	48 8b 87 98 02 00 00 	mov    rax,QWORD PTR [rdi+0x298]
  ac0928:	48 8b 38             	mov    rdi,QWORD PTR [rax]
  ac092b:	48 8b 47 40          	mov    rax,QWORD PTR [rdi+0x40]
  ac092f:	8b 40 28             	mov    eax,DWORD PTR [rax+0x28]
  ac0932:	c1 e8 17             	shr    eax,0x17
  ac0935:	83 e0 02             	and    eax,0x2
  ac0938:	74 20                	je     0xac095a
  ac093a:	89 c7                	mov    edi,eax
  ac093c:	41 89 d7             	mov    r15d,edx
  ac093f:	49 89 f4             	mov    r12,rsi
  ac0942:	e8 a9 13 aa ff       	call   0x561cf0
  ac0947:	49 8b 8e 98 02 00 00 	mov    rcx,QWORD PTR [r14+0x298]
  ac094e:	44 89 fa             	mov    edx,r15d
  ac0951:	4c 89 e6             	mov    rsi,r12
  ac0954:	41 89 c7             	mov    r15d,eax
  ac0957:	48 8b 39             	mov    rdi,QWORD PTR [rcx]
  ac095a:	48 8b 47 38          	mov    rax,QWORD PTR [rdi+0x38]
  ac095e:	4c 8b 60 40          	mov    r12,QWORD PTR [rax+0x40]
  ac0962:	48 8d 05 ff 76 7a ff 	lea    rax,[rip+0xffffffffff7a76ff]        # 0x268068
  ac0969:	4c 29 e0             	sub    rax,r12
  ac096c:	48 c1 c8 03          	ror    rax,0x3
  ac0970:	48 83 f8 3b          	cmp    rax,0x3b
  ac0974:	77 4a                	ja     0xac09c0
  ac0976:	48 89 d9             	mov    rcx,rbx
  ac0979:	41 ff d4             	call   r12
  ac097c:	41 89 c4             	mov    r12d,eax
  ac097f:	41 83 ff ff          	cmp    r15d,0xffffffff
  ac0983:	74 08                	je     0xac098d
  ac0985:	44 89 ff             	mov    edi,r15d
  ac0988:	e8 53 14 aa ff       	call   0x561de0
  ac098d:	45 85 e4             	test   r12d,r12d
  ac0990:	74 12                	je     0xac09a4
  ac0992:	44 89 e0             	mov    eax,r12d
  ac0995:	48 83 c4 08          	add    rsp,0x8
  ac0999:	5b                   	pop    rbx
  ac099a:	41 5c                	pop    r12
  ac099c:	41 5d                	pop    r13
  ac099e:	41 5e                	pop    r14
  ac09a0:	41 5f                	pop    r15
  ac09a2:	5d                   	pop    rbp
  ac09a3:	c3                   	ret
  ac09a4:	48 8b 33             	mov    rsi,QWORD PTR [rbx]
  ac09a7:	4c 89 f7             	mov    rdi,r14
  ac09aa:	48 89 da             	mov    rdx,rbx
  ac09ad:	48 83 c4 08          	add    rsp,0x8
  ac09b1:	5b                   	pop    rbx
  ac09b2:	41 5c                	pop    r12
  ac09b4:	41 5d                	pop    r13
  ac09b6:	41 5e                	pop    r14
  ac09b8:	41 5f                	pop    r15
  ac09ba:	5d                   	pop    rbp
  ac09bb:	e9 e0 22 ad ff       	jmp    0x592ca0
  ac09c0:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
  ac09c4:	48 8d 3d 05 87 dc 01 	lea    rdi,[rip+0x1dc8705]        # 0x28890d0
  ac09cb:	4c 89 e6             	mov    rsi,r12
  ac09ce:	41 89 d5             	mov    r13d,edx
  ac09d1:	e8 ea ee 98 ff       	call   0x44f8c0
  ac09d6:	49 8b 86 98 02 00 00 	mov    rax,QWORD PTR [r14+0x298]
  ac09dd:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
  ac09e1:	44 89 ea             	mov    edx,r13d
  ac09e4:	48 8b 38             	mov    rdi,QWORD PTR [rax]
  ac09e7:	eb 8d                	jmp    0xac0976
  ac09e9:	90                   	nop
  ac09ea:	90                   	nop
  ac09eb:	90                   	nop
  ac09ec:	90                   	nop
  ac09ed:	90                   	nop
  ac09ee:	90                   	nop
  ac09ef:	90                   	nop
  ac09f0:	55                   	push   rbp
  ac09f1:	48 89 e5             	mov    rbp,rsp
  ac09f4:	4d 89 ca             	mov    r10,r9
  ac09f7:	4d 89 c3             	mov    r11,r8
  ac09fa:	49 89 c9             	mov    r9,rcx
  ac09fd:	49 89 d0             	mov    r8,rdx
  ac0a00:	48 89 f1             	mov    rcx,rsi
  ac0a03:	48 89 fa             	mov    rdx,rdi
  ac0a06:	48 8d 3d 60 fc 7e 00 	lea    rdi,[rip+0x7efc60]        # 0x12b066d
  ac0a0d:	48 8d 35 f1 50 8d 00 	lea    rsi,[rip+0x8d50f1]        # 0x1395b05
  ac0a14:	31 c0                	xor    eax,eax
  ac0a16:	41 52                	push   r10
  ac0a18:	41 53                	push   r11
  ac0a1a:	e8 f1 c9 79 ff       	call   0x25d410
  ac0a1f:	48 83 c4 10          	add    rsp,0x10
  ac0a23:	b8 2d 00 00 00       	mov    eax,0x2d
  ac0a28:	5d                   	pop    rbp
  ac0a29:	c3                   	ret
  ac0a2a:	90                   	nop
  ac0a2b:	90                   	nop
  ac0a2c:	90                   	nop
  ac0a2d:	90                   	nop
  ac0a2e:	90                   	nop
  ac0a2f:	90                   	nop
  ac0a30:	55                   	push   rbp
  ac0a31:	48 89 e5             	mov    rbp,rsp
  ac0a34:	5d                   	pop    rbp
  ac0a35:	e9 f6 21 ad ff       	jmp    0x592c30
  ac0a3a:	90                   	nop
  ac0a3b:	90                   	nop
  ac0a3c:	90                   	nop
  ac0a3d:	90                   	nop
  ac0a3e:	90                   	nop
  ac0a3f:	90                   	nop
  ac0a40:	55                   	push   rbp
  ac0a41:	48 89 e5             	mov    rbp,rsp
  ac0a44:	e8 27 22 ad ff       	call   0x592c70
  ac0a49:	85 c0                	test   eax,eax
  ac0a4b:	74 02                	je     0xac0a4f
  ac0a4d:	5d                   	pop    rbp
  ac0a4e:	c3                   	ret
  ac0a4f:	48 c7 05 06 64 13 03 	mov    QWORD PTR [rip+0x3136406],0x0        # 0x3bf6e60
  ac0a56:	00 00 00 00 
  ac0a5a:	5d                   	pop    rbp
  ac0a5b:	c3                   	ret
  ac0a5c:	90                   	nop
  ac0a5d:	90                   	nop
  ac0a5e:	90                   	nop
  ac0a5f:	90                   	nop
  ac0a60:	48 8b 05 f9 63 13 03 	mov    rax,QWORD PTR [rip+0x31363f9]        # 0x3bf6e60
  ac0a67:	4c 8b 48 60          	mov    r9,QWORD PTR [rax+0x60]
  ac0a6b:	48 8d 05 8e d1 7a ff 	lea    rax,[rip+0xffffffffff7ad18e]        # 0x26dc00
  ac0a72:	4c 29 c8             	sub    rax,r9
  ac0a75:	48 c1 c8 03          	ror    rax,0x3
  ac0a79:	48 83 f8 06          	cmp    rax,0x6
  ac0a7d:	77 03                	ja     0xac0a82
  ac0a7f:	41 ff e1             	jmp    r9
  ac0a82:	55                   	push   rbp
  ac0a83:	48 89 e5             	mov    rbp,rsp
  ac0a86:	41 57                	push   r15
  ac0a88:	41 56                	push   r14
  ac0a8a:	41 55                	push   r13
  ac0a8c:	41 54                	push   r12
  ac0a8e:	53                   	push   rbx
  ac0a8f:	50                   	push   rax
  ac0a90:	48 8d 05 59 86 dc 01 	lea    rax,[rip+0x1dc8659]        # 0x28890f0
  ac0a97:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  ac0a9b:	41 89 f6             	mov    r14d,esi
  ac0a9e:	4c 89 ce             	mov    rsi,r9
  ac0aa1:	4d 89 c7             	mov    r15,r8
  ac0aa4:	41 89 cd             	mov    r13d,ecx
  ac0aa7:	49 89 d4             	mov    r12,rdx
  ac0aaa:	4c 89 cb             	mov    rbx,r9
  ac0aad:	48 89 c7             	mov    rdi,rax
  ac0ab0:	e8 0b ee 98 ff       	call   0x44f8c0
  ac0ab5:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  ac0ab9:	49 89 d9             	mov    r9,rbx
  ac0abc:	44 89 f6             	mov    esi,r14d
  ac0abf:	4c 89 e2             	mov    rdx,r12
  ac0ac2:	44 89 e9             	mov    ecx,r13d
  ac0ac5:	4d 89 f8             	mov    r8,r15
  ac0ac8:	48 83 c4 08          	add    rsp,0x8
  ac0acc:	5b                   	pop    rbx
  ac0acd:	41 5c                	pop    r12
  ac0acf:	41 5d                	pop    r13
  ac0ad1:	41 5e                	pop    r14
  ac0ad3:	41 5f                	pop    r15
  ac0ad5:	5d                   	pop    rbp
  ac0ad6:	41 ff e1             	jmp    r9
  ac0ad9:	90                   	nop
  ac0ada:	90                   	nop
  ac0adb:	90                   	nop
  ac0adc:	90                   	nop
  ac0add:	90                   	nop
  ac0ade:	90                   	nop
  ac0adf:	90                   	nop
  ac0ae0:	55                   	push   rbp
  ac0ae1:	48 89 e5             	mov    rbp,rsp
  ac0ae4:	49 89 d0             	mov    r8,rdx
  ac0ae7:	89 f1                	mov    ecx,esi
  ac0ae9:	48 89 fa             	mov    rdx,rdi
  ac0aec:	48 8d 3d ce 99 81 00 	lea    rdi,[rip+0x8199ce]        # 0x12da4c1
  ac0af3:	48 8d 35 5b d5 84 00 	lea    rsi,[rip+0x84d55b]        # 0x130e055
  ac0afa:	31 c0                	xor    eax,eax
  ac0afc:	e8 0f c9 79 ff       	call   0x25d410
  ac0b01:	b8 2d 00 00 00       	mov    eax,0x2d
  ac0b06:	5d                   	pop    rbp
  ac0b07:	c3                   	ret
  ac0b08:	90                   	nop
  ac0b09:	90                   	nop
  ac0b0a:	90                   	nop
  ac0b0b:	90                   	nop
  ac0b0c:	90                   	nop
  ac0b0d:	90                   	nop
  ac0b0e:	90                   	nop
  ac0b0f:	90                   	nop
  ac0b10:	55                   	push   rbp
  ac0b11:	48 89 e5             	mov    rbp,rsp
  ac0b14:	48 89 fa             	mov    rdx,rdi
  ac0b17:	48 8d 3d 0e ad 8e 00 	lea    rdi,[rip+0x8ead0e]        # 0x13ab82c
  ac0b1e:	48 8d 35 f7 4f 8d 00 	lea    rsi,[rip+0x8d4ff7]        # 0x1395b1c
  ac0b25:	31 c0                	xor    eax,eax
  ac0b27:	5d                   	pop    rbp
  ac0b28:	e9 e3 c8 79 ff       	jmp    0x25d410
  ac0b2d:	90                   	nop
  ac0b2e:	90                   	nop
  ac0b2f:	90                   	nop
  ac0b30:	48 8b 05 29 63 13 03 	mov    rax,QWORD PTR [rip+0x3136329]        # 0x3bf6e60
  ac0b37:	48 8b 48 78          	mov    rcx,QWORD PTR [rax+0x78]
  ac0b3b:	48 8d 05 46 73 7a ff 	lea    rax,[rip+0xffffffffff7a7346]        # 0x267e88
  ac0b42:	48 29 c8             	sub    rax,rcx
  ac0b45:	48 c1 c8 03          	ror    rax,0x3
  ac0b49:	48 3d 97 01 00 00    	cmp    rax,0x197
  ac0b4f:	77 02                	ja     0xac0b53
  ac0b51:	ff e1                	jmp    rcx
  ac0b53:	55                   	push   rbp
  ac0b54:	48 89 e5             	mov    rbp,rsp
  ac0b57:	41 57                	push   r15
  ac0b59:	41 56                	push   r14
  ac0b5b:	53                   	push   rbx
  ac0b5c:	50                   	push   rax
  ac0b5d:	48 8d 05 ac 85 dc 01 	lea    rax,[rip+0x1dc85ac]        # 0x2889110
  ac0b64:	48 89 fb             	mov    rbx,rdi
  ac0b67:	49 89 f6             	mov    r14,rsi
  ac0b6a:	48 89 ce             	mov    rsi,rcx
  ac0b6d:	49 89 cf             	mov    r15,rcx
  ac0b70:	48 89 c7             	mov    rdi,rax
  ac0b73:	e8 48 ed 98 ff       	call   0x44f8c0
  ac0b78:	4c 89 f9             	mov    rcx,r15
  ac0b7b:	48 89 df             	mov    rdi,rbx
  ac0b7e:	4c 89 f6             	mov    rsi,r14
  ac0b81:	48 83 c4 08          	add    rsp,0x8
  ac0b85:	5b                   	pop    rbx
  ac0b86:	41 5e                	pop    r14
  ac0b88:	41 5f                	pop    r15
  ac0b8a:	5d                   	pop    rbp
  ac0b8b:	ff e1                	jmp    rcx
  ac0b8d:	90                   	nop
  ac0b8e:	90                   	nop
  ac0b8f:	90                   	nop
  ac0b90:	48 8b 05 c9 62 13 03 	mov    rax,QWORD PTR [rip+0x31362c9]        # 0x3bf6e60
  ac0b97:	48 8b 88 80 00 00 00 	mov    rcx,QWORD PTR [rax+0x80]
  ac0b9e:	48 8d 05 e3 72 7a ff 	lea    rax,[rip+0xffffffffff7a72e3]        # 0x267e88
  ac0ba5:	48 29 c8             	sub    rax,rcx
  ac0ba8:	48 c1 c8 03          	ror    rax,0x3
  ac0bac:	48 3d 97 01 00 00    	cmp    rax,0x197
  ac0bb2:	77 02                	ja     0xac0bb6
  ac0bb4:	ff e1                	jmp    rcx
  ac0bb6:	55                   	push   rbp
  ac0bb7:	48 89 e5             	mov    rbp,rsp
  ac0bba:	41 57                	push   r15
  ac0bbc:	41 56                	push   r14
  ac0bbe:	53                   	push   rbx
  ac0bbf:	50                   	push   rax
  ac0bc0:	48 8d 05 69 85 dc 01 	lea    rax,[rip+0x1dc8569]        # 0x2889130
  ac0bc7:	48 89 fb             	mov    rbx,rdi
  ac0bca:	49 89 f6             	mov    r14,rsi
  ac0bcd:	48 89 ce             	mov    rsi,rcx
  ac0bd0:	49 89 cf             	mov    r15,rcx
  ac0bd3:	48 89 c7             	mov    rdi,rax
  ac0bd6:	e8 e5 ec 98 ff       	call   0x44f8c0
  ac0bdb:	4c 89 f9             	mov    rcx,r15
  ac0bde:	48 89 df             	mov    rdi,rbx
  ac0be1:	4c 89 f6             	mov    rsi,r14
  ac0be4:	48 83 c4 08          	add    rsp,0x8
  ac0be8:	5b                   	pop    rbx
  ac0be9:	41 5e                	pop    r14
  ac0beb:	41 5f                	pop    r15
  ac0bed:	5d                   	pop    rbp
  ac0bee:	ff e1                	jmp    rcx
  ac0bf0:	55                   	push   rbp
  ac0bf1:	48 89 e5             	mov    rbp,rsp
  ac0bf4:	5d                   	pop    rbp
  ac0bf5:	c3                   	ret
  ac0bf6:	90                   	nop
  ac0bf7:	90                   	nop
  ac0bf8:	90                   	nop
  ac0bf9:	90                   	nop
  ac0bfa:	90                   	nop
  ac0bfb:	90                   	nop
  ac0bfc:	90                   	nop
  ac0bfd:	90                   	nop
  ac0bfe:	90                   	nop
  ac0bff:	90                   	nop
  ac0c00:	55                   	push   rbp
  ac0c01:	48 89 e5             	mov    rbp,rsp
  ac0c04:	5d                   	pop    rbp
  ac0c05:	c3                   	ret
  ac0c06:	90                   	nop
  ac0c07:	90                   	nop
  ac0c08:	90                   	nop
  ac0c09:	90                   	nop
  ac0c0a:	90                   	nop
  ac0c0b:	90                   	nop
  ac0c0c:	90                   	nop
  ac0c0d:	90                   	nop
  ac0c0e:	90                   	nop
  ac0c0f:	90                   	nop
  ac0c10:	55                   	push   rbp
  ac0c11:	48 89 e5             	mov    rbp,rsp
  ac0c14:	41 56                	push   r14
  ac0c16:	53                   	push   rbx
  ac0c17:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  ac0c1e:	00 00 
  ac0c20:	41 0f b7 86 14 01 00 	movzx  eax,WORD PTR [r14+0x114]
  ac0c27:	00 
  ac0c28:	48 89 fb             	mov    rbx,rdi
  ac0c2b:	48 85 f6             	test   rsi,rsi
  ac0c2e:	74 1b                	je     0xac0c4b
  ac0c30:	66 85 c0             	test   ax,ax
  ac0c33:	75 31                	jne    0xac0c66
  ac0c35:	48 89 df             	mov    rdi,rbx
  ac0c38:	31 d2                	xor    edx,edx
  ac0c3a:	e8 21 03 00 00       	call   0xac0f60
  ac0c3f:	85 c0                	test   eax,eax
  ac0c41:	74 23                	je     0xac0c66
  ac0c43:	f6 43 0a 10          	test   BYTE PTR [rbx+0xa],0x10
  ac0c47:	74 15                	je     0xac0c5e
  ac0c49:	eb 1b                	jmp    0xac0c66
  ac0c4b:	66 85 c0             	test   ax,ax
  ac0c4e:	75 16                	jne    0xac0c66
  ac0c50:	48 89 df             	mov    rdi,rbx
  ac0c53:	e8 88 08 00 00       	call   0xac14e0
  ac0c58:	f6 43 0a 10          	test   BYTE PTR [rbx+0xa],0x10
  ac0c5c:	75 08                	jne    0xac0c66
  ac0c5e:	66 41 ff 86 0a 01 00 	inc    WORD PTR [r14+0x10a]
  ac0c65:	00 
  ac0c66:	5b                   	pop    rbx
  ac0c67:	41 5e                	pop    r14
  ac0c69:	5d                   	pop    rbp
  ac0c6a:	c3                   	ret
  ac0c6b:	90                   	nop
  ac0c6c:	90                   	nop
  ac0c6d:	90                   	nop
  ac0c6e:	90                   	nop
  ac0c6f:	90                   	nop
  ac0c70:	0f b6 47 33          	movzx  eax,BYTE PTR [rdi+0x33]
  ac0c74:	48 8d 0d 45 77 aa 01 	lea    rcx,[rip+0x1aa7745]        # 0x25683c0
  ac0c7b:	83 e0 0f             	and    eax,0xf
  ac0c7e:	48 8b 04 c1          	mov    rax,QWORD PTR [rcx+rax*8]
  ac0c82:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
  ac0c86:	48 8d 05 a3 de 7a ff 	lea    rax,[rip+0xffffffffff7adea3]        # 0x26eb30
  ac0c8d:	48 29 c8             	sub    rax,rcx
  ac0c90:	48 c1 c8 03          	ror    rax,0x3
  ac0c94:	48 83 f8 0e          	cmp    rax,0xe
  ac0c98:	77 06                	ja     0xac0ca0
  ac0c9a:	48 83 c7 28          	add    rdi,0x28
  ac0c9e:	ff e1                	jmp    rcx
  ac0ca0:	55                   	push   rbp
  ac0ca1:	48 89 e5             	mov    rbp,rsp
  ac0ca4:	41 57                	push   r15
  ac0ca6:	41 56                	push   r14
  ac0ca8:	53                   	push   rbx
  ac0ca9:	50                   	push   rax
  ac0caa:	48 8d 05 5f 85 dc 01 	lea    rax,[rip+0x1dc855f]        # 0x2889210
  ac0cb1:	48 89 fb             	mov    rbx,rdi
  ac0cb4:	49 89 f6             	mov    r14,rsi
  ac0cb7:	48 89 ce             	mov    rsi,rcx
  ac0cba:	49 89 cf             	mov    r15,rcx
  ac0cbd:	48 89 c7             	mov    rdi,rax
  ac0cc0:	e8 fb eb 98 ff       	call   0x44f8c0
  ac0cc5:	4c 89 f9             	mov    rcx,r15
  ac0cc8:	48 89 df             	mov    rdi,rbx
  ac0ccb:	4c 89 f6             	mov    rsi,r14
  ac0cce:	48 83 c4 08          	add    rsp,0x8
  ac0cd2:	5b                   	pop    rbx
  ac0cd3:	41 5e                	pop    r14
  ac0cd5:	41 5f                	pop    r15
  ac0cd7:	5d                   	pop    rbp
  ac0cd8:	48 83 c7 28          	add    rdi,0x28
  ac0cdc:	ff e1                	jmp    rcx
  ac0cde:	90                   	nop
  ac0cdf:	90                   	nop
  ac0ce0:	55                   	push   rbp
  ac0ce1:	48 89 e5             	mov    rbp,rsp
  ac0ce4:	41 57                	push   r15
  ac0ce6:	41 56                	push   r14
  ac0ce8:	41 54                	push   r12
  ac0cea:	53                   	push   rbx
  ac0ceb:	f7 47 08 00 00 10 00 	test   DWORD PTR [rdi+0x8],0x100000
  ac0cf2:	48 c7 c0 f8 ff ff ff 	mov    rax,0xfffffffffffffff8
  ac0cf9:	48 c7 c1 f1 ff ff ff 	mov    rcx,0xfffffffffffffff1
  ac0d00:	48 89 fb             	mov    rbx,rdi
  ac0d03:	48 0f 44 c8          	cmove  rcx,rax
  ac0d07:	48 23 4f 40          	and    rcx,QWORD PTR [rdi+0x40]
  ac0d0b:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac0d12:	00 00 
  ac0d14:	48 39 c1             	cmp    rcx,rax
  ac0d17:	75 0d                	jne    0xac0d26
  ac0d19:	48 89 df             	mov    rdi,rbx
  ac0d1c:	e8 df 09 00 00       	call   0xac1700
  ac0d21:	45 31 f6             	xor    r14d,r14d
  ac0d24:	eb 64                	jmp    0xac0d8a
  ac0d26:	e8 05 19 be ff       	call   0x6a2630
  ac0d2b:	65 4c 8b 24 25 00 00 	mov    r12,QWORD PTR gs:0x0
  ac0d32:	00 00 
  ac0d34:	65 8b 3c 25 34 00 00 	mov    edi,DWORD PTR gs:0x34
  ac0d3b:	00 
  ac0d3c:	e8 ef 74 a0 ff       	call   0x4c8230
  ac0d41:	48 8b 88 a0 06 00 00 	mov    rcx,QWORD PTR [rax+0x6a0]
  ac0d48:	48 05 a0 06 00 00    	add    rax,0x6a0
  ac0d4e:	45 31 f6             	xor    r14d,r14d
  ac0d51:	48 39 c1             	cmp    rcx,rax
  ac0d54:	75 12                	jne    0xac0d68
  ac0d56:	45 31 ff             	xor    r15d,r15d
  ac0d59:	eb 1f                	jmp    0xac0d7a
  ac0d5b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  ac0d60:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  ac0d63:	48 39 c1             	cmp    rcx,rax
  ac0d66:	74 12                	je     0xac0d7a
  ac0d68:	49 89 cf             	mov    r15,rcx
  ac0d6b:	48 39 59 10          	cmp    QWORD PTR [rcx+0x10],rbx
  ac0d6f:	75 ef                	jne    0xac0d60
  ac0d71:	4d 39 67 18          	cmp    QWORD PTR [r15+0x18],r12
  ac0d75:	75 e9                	jne    0xac0d60
  ac0d77:	4d 89 fe             	mov    r14,r15
  ac0d7a:	e8 d1 18 be ff       	call   0x6a2650
  ac0d7f:	48 89 df             	mov    rdi,rbx
  ac0d82:	4c 89 fe             	mov    rsi,r15
  ac0d85:	e8 e6 0a 00 00       	call   0xac1870
  ac0d8a:	4c 89 f0             	mov    rax,r14
  ac0d8d:	5b                   	pop    rbx
  ac0d8e:	41 5c                	pop    r12
  ac0d90:	41 5e                	pop    r14
  ac0d92:	41 5f                	pop    r15
  ac0d94:	5d                   	pop    rbp
  ac0d95:	c3                   	ret
  ac0d96:	90                   	nop
  ac0d97:	90                   	nop
  ac0d98:	90                   	nop
  ac0d99:	90                   	nop
  ac0d9a:	90                   	nop
  ac0d9b:	90                   	nop
  ac0d9c:	90                   	nop
  ac0d9d:	90                   	nop
  ac0d9e:	90                   	nop
  ac0d9f:	90                   	nop
  ac0da0:	55                   	push   rbp
  ac0da1:	48 89 e5             	mov    rbp,rsp
  ac0da4:	41 57                	push   r15
  ac0da6:	41 56                	push   r14
  ac0da8:	53                   	push   rbx
  ac0da9:	50                   	push   rax
  ac0daa:	89 d0                	mov    eax,edx
  ac0dac:	89 d1                	mov    ecx,edx
  ac0dae:	48 89 f3             	mov    rbx,rsi
  ac0db1:	48 8b 35 30 db 24 03 	mov    rsi,QWORD PTR [rip+0x324db30]        # 0x3d0e8e8
  ac0db8:	49 89 fe             	mov    r14,rdi
  ac0dbb:	83 e0 01             	and    eax,0x1
  ac0dbe:	83 e1 02             	and    ecx,0x2
  ac0dc1:	c1 e0 11             	shl    eax,0x11
  ac0dc4:	c1 e1 12             	shl    ecx,0x12
  ac0dc7:	09 c1                	or     ecx,eax
  ac0dc9:	89 d0                	mov    eax,edx
  ac0dcb:	83 e0 08             	and    eax,0x8
  ac0dce:	48 89 77 18          	mov    QWORD PTR [rdi+0x18],rsi
  ac0dd2:	48 c7 47 20 00 00 00 	mov    QWORD PTR [rdi+0x20],0x0
  ac0dd9:	00 
  ac0dda:	41 89 c7             	mov    r15d,eax
  ac0ddd:	41 c1 e7 1a          	shl    r15d,0x1a
  ac0de1:	41 09 cf             	or     r15d,ecx
  ac0de4:	41 81 f7 00 00 02 00 	xor    r15d,0x20000
  ac0deb:	f6 c2 04             	test   dl,0x4
  ac0dee:	75 23                	jne    0xac0e13
  ac0df0:	8d 0c c5 08 00 00 00 	lea    ecx,[rax*8+0x8]
  ac0df7:	49 8d 7e 40          	lea    rdi,[r14+0x40]
  ac0dfb:	48 8d 15 67 22 86 00 	lea    rdx,[rip+0x862267]        # 0x1323069
  ac0e02:	48 89 de             	mov    rsi,rbx
  ac0e05:	e8 c6 6f a0 ff       	call   0x4c7dd0
  ac0e0a:	48 8d 35 3f 83 dc 01 	lea    rsi,[rip+0x1dc833f]        # 0x2889150
  ac0e11:	eb 25                	jmp    0xac0e38
  ac0e13:	8d 14 c5 04 00 00 00 	lea    edx,[rax*8+0x4]
  ac0e1a:	49 8d 7e 28          	lea    rdi,[r14+0x28]
  ac0e1e:	48 8d 35 2b fb 8d 00 	lea    rsi,[rip+0x8dfb2b]        # 0x13a0950
  ac0e25:	41 81 cf 00 00 10 00 	or     r15d,0x100000
  ac0e2c:	e8 5f a4 18 00       	call   0xc4b290
  ac0e31:	48 8d 35 50 83 dc 01 	lea    rsi,[rip+0x1dc8350]        # 0x2889188
  ac0e38:	4c 89 f7             	mov    rdi,r14
  ac0e3b:	48 89 da             	mov    rdx,rbx
  ac0e3e:	31 c9                	xor    ecx,ecx
  ac0e40:	45 89 f8             	mov    r8d,r15d
  ac0e43:	48 83 c4 08          	add    rsp,0x8
  ac0e47:	5b                   	pop    rbx
  ac0e48:	41 5e                	pop    r14
  ac0e4a:	41 5f                	pop    r15
  ac0e4c:	5d                   	pop    rbp
  ac0e4d:	e9 7e da f6 ff       	jmp    0xa2e8d0
  ac0e52:	90                   	nop
  ac0e53:	90                   	nop
  ac0e54:	90                   	nop
  ac0e55:	90                   	nop
  ac0e56:	90                   	nop
  ac0e57:	90                   	nop
  ac0e58:	90                   	nop
  ac0e59:	90                   	nop
  ac0e5a:	90                   	nop
  ac0e5b:	90                   	nop
  ac0e5c:	90                   	nop
  ac0e5d:	90                   	nop
  ac0e5e:	90                   	nop
  ac0e5f:	90                   	nop
  ac0e60:	55                   	push   rbp
  ac0e61:	48 89 e5             	mov    rbp,rsp
  ac0e64:	41 56                	push   r14
  ac0e66:	53                   	push   rbx
  ac0e67:	48 8b 05 7a da 24 03 	mov    rax,QWORD PTR [rip+0x324da7a]        # 0x3d0e8e8
  ac0e6e:	49 89 fe             	mov    r14,rdi
  ac0e71:	48 8d 15 f1 21 86 00 	lea    rdx,[rip+0x8621f1]        # 0x1323069
  ac0e78:	b9 08 00 00 00       	mov    ecx,0x8
  ac0e7d:	48 89 f3             	mov    rbx,rsi
  ac0e80:	48 89 47 18          	mov    QWORD PTR [rdi+0x18],rax
  ac0e84:	48 c7 47 20 00 00 00 	mov    QWORD PTR [rdi+0x20],0x0
  ac0e8b:	00 
  ac0e8c:	48 83 c7 40          	add    rdi,0x40
  ac0e90:	e8 3b 6f a0 ff       	call   0x4c7dd0
  ac0e95:	48 8d 35 b4 82 dc 01 	lea    rsi,[rip+0x1dc82b4]        # 0x2889150
  ac0e9c:	4c 89 f7             	mov    rdi,r14
  ac0e9f:	48 89 da             	mov    rdx,rbx
  ac0ea2:	31 c9                	xor    ecx,ecx
  ac0ea4:	41 b8 00 00 02 00    	mov    r8d,0x20000
  ac0eaa:	5b                   	pop    rbx
  ac0eab:	41 5e                	pop    r14
  ac0ead:	5d                   	pop    rbp
  ac0eae:	e9 1d da f6 ff       	jmp    0xa2e8d0
  ac0eb3:	90                   	nop
  ac0eb4:	90                   	nop
  ac0eb5:	90                   	nop
  ac0eb6:	90                   	nop
  ac0eb7:	90                   	nop
  ac0eb8:	90                   	nop
  ac0eb9:	90                   	nop
  ac0eba:	90                   	nop
  ac0ebb:	90                   	nop
  ac0ebc:	90                   	nop
  ac0ebd:	90                   	nop
  ac0ebe:	90                   	nop
  ac0ebf:	90                   	nop
  ac0ec0:	55                   	push   rbp
  ac0ec1:	48 89 e5             	mov    rbp,rsp
  ac0ec4:	53                   	push   rbx
  ac0ec5:	50                   	push   rax
  ac0ec6:	48 c7 47 20 ad de 00 	mov    QWORD PTR [rdi+0x20],0xdead
  ac0ecd:	00 
  ac0ece:	48 89 fb             	mov    rbx,rdi
  ac0ed1:	f6 47 0a 10          	test   BYTE PTR [rdi+0xa],0x10
  ac0ed5:	75 0b                	jne    0xac0ee2
  ac0ed7:	48 8d 7b 40          	lea    rdi,[rbx+0x40]
  ac0edb:	e8 70 6f a0 ff       	call   0x4c7e50
  ac0ee0:	eb 09                	jmp    0xac0eeb
  ac0ee2:	48 8d 7b 28          	lea    rdi,[rbx+0x28]
  ac0ee6:	e8 a5 01 7a ff       	call   0x261090
  ac0eeb:	48 89 df             	mov    rdi,rbx
  ac0eee:	48 83 c4 08          	add    rsp,0x8
  ac0ef2:	5b                   	pop    rbx
  ac0ef3:	5d                   	pop    rbp
  ac0ef4:	e9 17 db f6 ff       	jmp    0xa2ea10
  ac0ef9:	90                   	nop
  ac0efa:	90                   	nop
  ac0efb:	90                   	nop
  ac0efc:	90                   	nop
  ac0efd:	90                   	nop
  ac0efe:	90                   	nop
  ac0eff:	90                   	nop
  ac0f00:	55                   	push   rbp
  ac0f01:	48 89 e5             	mov    rbp,rsp
  ac0f04:	41 56                	push   r14
  ac0f06:	53                   	push   rbx
  ac0f07:	4c 8b 77 08          	mov    r14,QWORD PTR [rdi+0x8]
  ac0f0b:	48 8b 1f             	mov    rbx,QWORD PTR [rdi]
  ac0f0e:	48 8b 05 d3 d9 24 03 	mov    rax,QWORD PTR [rip+0x324d9d3]        # 0x3d0e8e8
  ac0f15:	48 8d 15 4d 21 86 00 	lea    rdx,[rip+0x86214d]        # 0x1323069
  ac0f1c:	b9 08 00 00 00       	mov    ecx,0x8
  ac0f21:	48 8d 7b 40          	lea    rdi,[rbx+0x40]
  ac0f25:	4c 89 f6             	mov    rsi,r14
  ac0f28:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
  ac0f2c:	48 c7 43 20 00 00 00 	mov    QWORD PTR [rbx+0x20],0x0
  ac0f33:	00 
  ac0f34:	e8 97 6e a0 ff       	call   0x4c7dd0
  ac0f39:	48 8d 35 10 82 dc 01 	lea    rsi,[rip+0x1dc8210]        # 0x2889150
  ac0f40:	48 89 df             	mov    rdi,rbx
  ac0f43:	4c 89 f2             	mov    rdx,r14
  ac0f46:	31 c9                	xor    ecx,ecx
  ac0f48:	41 b8 00 00 02 00    	mov    r8d,0x20000
  ac0f4e:	5b                   	pop    rbx
  ac0f4f:	41 5e                	pop    r14
  ac0f51:	5d                   	pop    rbp
  ac0f52:	e9 79 d9 f6 ff       	jmp    0xa2e8d0
  ac0f57:	90                   	nop
  ac0f58:	90                   	nop
  ac0f59:	90                   	nop
  ac0f5a:	90                   	nop
  ac0f5b:	90                   	nop
  ac0f5c:	90                   	nop
  ac0f5d:	90                   	nop
  ac0f5e:	90                   	nop
  ac0f5f:	90                   	nop
  ac0f60:	55                   	push   rbp
  ac0f61:	48 89 e5             	mov    rbp,rsp
  ac0f64:	41 57                	push   r15
  ac0f66:	41 56                	push   r14
  ac0f68:	41 55                	push   r13
  ac0f6a:	41 54                	push   r12
  ac0f6c:	53                   	push   rbx
  ac0f6d:	50                   	push   rax
  ac0f6e:	65 4c 8b 2c 25 00 00 	mov    r13,QWORD PTR gs:0x0
  ac0f75:	00 00 
  ac0f77:	66 41 83 bd 14 01 00 	cmp    WORD PTR [r13+0x114],0x0
  ac0f7e:	00 00 
  ac0f80:	41 bc 01 00 00 00    	mov    r12d,0x1
  ac0f86:	0f 85 1a 01 00 00    	jne    0xac10a6
  ac0f8c:	c7 46 20 00 00 00 00 	mov    DWORD PTR [rsi+0x20],0x0
  ac0f93:	4c 89 6e 18          	mov    QWORD PTR [rsi+0x18],r13
  ac0f97:	48 89 7e 10          	mov    QWORD PTR [rsi+0x10],rdi
  ac0f9b:	49 89 f6             	mov    r14,rsi
  ac0f9e:	48 89 fb             	mov    rbx,rdi
  ac0fa1:	89 55 d4             	mov    DWORD PTR [rbp-0x2c],edx
  ac0fa4:	f6 47 0a 10          	test   BYTE PTR [rdi+0xa],0x10
  ac0fa8:	74 07                	je     0xac0fb1
  ac0faa:	41 ff 85 70 03 00 00 	inc    DWORD PTR [r13+0x370]
  ac0fb1:	41 ff 85 7c 04 00 00 	inc    DWORD PTR [r13+0x47c]
  ac0fb8:	48 8d 0d 61 79 a7 02 	lea    rcx,[rip+0x2a77961]        # 0x3538920
  ac0fbf:	49 63 85 24 05 00 00 	movsxd rax,DWORD PTR [r13+0x524]
  ac0fc6:	4c 8b 3c c1          	mov    r15,QWORD PTR [rcx+rax*8]
  ac0fca:	49 8d 87 a0 06 00 00 	lea    rax,[r15+0x6a0]
  ac0fd1:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
  ac0fd5:	49 8b 87 a0 06 00 00 	mov    rax,QWORD PTR [r15+0x6a0]
  ac0fdc:	49 89 06             	mov    QWORD PTR [r14],rax
  ac0fdf:	4c 89 70 08          	mov    QWORD PTR [rax+0x8],r14
  ac0fe3:	4d 89 b7 a0 06 00 00 	mov    QWORD PTR [r15+0x6a0],r14
  ac0fea:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac0ff1:	00 00 
  ac0ff3:	66 ff 80 0e 01 00 00 	inc    WORD PTR [rax+0x10e]
  ac0ffa:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1001:	00 00 
  ac1003:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  ac100a:	01 
  ac100b:	e8 30 69 bf ff       	call   0x6b7940
  ac1010:	41 ff 8d 7c 04 00 00 	dec    DWORD PTR [r13+0x47c]
  ac1017:	41 0f b6 85 08 01 00 	movzx  eax,BYTE PTR [r13+0x108]
  ac101e:	00 
  ac101f:	48 8b 4b 18          	mov    rcx,QWORD PTR [rbx+0x18]
  ac1023:	41 0f b6 57 34       	movzx  edx,BYTE PTR [r15+0x34]
  ac1028:	c4 e2 eb f7 c9       	shrx   rcx,rcx,rdx
  ac102d:	09 c1                	or     ecx,eax
  ac102f:	f6 c1 01             	test   cl,0x1
  ac1032:	74 72                	je     0xac10a6
  ac1034:	e8 f7 15 be ff       	call   0x6a2630
  ac1039:	65 8b 3c 25 34 00 00 	mov    edi,DWORD PTR gs:0x34
  ac1040:	00 
  ac1041:	e8 ea 71 a0 ff       	call   0x4c8230
  ac1046:	49 89 c4             	mov    r12,rax
  ac1049:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  ac104d:	41 8b 4c 24 34       	mov    ecx,DWORD PTR [r12+0x34]
  ac1052:	48 0f a3 c8          	bt     rax,rcx
  ac1056:	73 43                	jae    0xac109b
  ac1058:	4c 89 f7             	mov    rdi,r14
  ac105b:	e8 70 02 00 00       	call   0xac12d0
  ac1060:	41 83 7e 20 00       	cmp    DWORD PTR [r14+0x20],0x0
  ac1065:	74 51                	je     0xac10b8
  ac1067:	4c 89 e0             	mov    rax,r12
  ac106a:	48 05 a0 06 00 00    	add    rax,0x6a0
  ac1070:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
  ac1074:	49 8b 84 24 a0 06 00 	mov    rax,QWORD PTR [r12+0x6a0]
  ac107b:	00 
  ac107c:	49 89 06             	mov    QWORD PTR [r14],rax
  ac107f:	4c 89 70 08          	mov    QWORD PTR [rax+0x8],r14
  ac1083:	4d 89 b4 24 a0 06 00 	mov    QWORD PTR [r12+0x6a0],r14
  ac108a:	00 
  ac108b:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1092:	00 00 
  ac1094:	66 ff 80 0e 01 00 00 	inc    WORD PTR [rax+0x10e]
  ac109b:	e8 b0 15 be ff       	call   0x6a2650
  ac10a0:	41 bc 01 00 00 00    	mov    r12d,0x1
  ac10a6:	44 89 e0             	mov    eax,r12d
  ac10a9:	48 83 c4 08          	add    rsp,0x8
  ac10ad:	5b                   	pop    rbx
  ac10ae:	41 5c                	pop    r12
  ac10b0:	41 5d                	pop    r13
  ac10b2:	41 5e                	pop    r14
  ac10b4:	41 5f                	pop    r15
  ac10b6:	5d                   	pop    rbp
  ac10b7:	c3                   	ret
  ac10b8:	f6 43 0a 08          	test   BYTE PTR [rbx+0xa],0x8
  ac10bc:	0f 84 bb 00 00 00    	je     0xac117d
  ac10c2:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac10c9:	00 00 
  ac10cb:	49 8b 8c 24 a0 06 00 	mov    rcx,QWORD PTR [r12+0x6a0]
  ac10d2:	00 
  ac10d3:	4d 89 e5             	mov    r13,r12
  ac10d6:	49 81 c5 a0 06 00 00 	add    r13,0x6a0
  ac10dd:	4c 39 e9             	cmp    rcx,r13
  ac10e0:	0f 84 97 00 00 00    	je     0xac117d
  ac10e6:	31 d2                	xor    edx,edx
  ac10e8:	eb 0e                	jmp    0xac10f8
  ac10ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  ac10f0:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  ac10f3:	4c 39 e9             	cmp    rcx,r13
  ac10f6:	74 14                	je     0xac110c
  ac10f8:	48 39 59 10          	cmp    QWORD PTR [rcx+0x10],rbx
  ac10fc:	75 f2                	jne    0xac10f0
  ac10fe:	31 f6                	xor    esi,esi
  ac1100:	48 39 41 18          	cmp    QWORD PTR [rcx+0x18],rax
  ac1104:	40 0f 94 c6          	sete   sil
  ac1108:	01 f2                	add    edx,esi
  ac110a:	eb e4                	jmp    0xac10f0
  ac110c:	85 d2                	test   edx,edx
  ac110e:	74 6d                	je     0xac117d
  ac1110:	48 8d 3d 69 5d 13 03 	lea    rdi,[rip+0x3135d69]        # 0x3bf6e80
  ac1117:	31 f6                	xor    esi,esi
  ac1119:	31 d2                	xor    edx,edx
  ac111b:	31 c9                	xor    ecx,ecx
  ac111d:	e8 6e 60 a0 ff       	call   0x4c7190
  ac1122:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  ac1126:	48 83 c3 20          	add    rbx,0x20
  ac112a:	49 89 46 28          	mov    QWORD PTR [r14+0x28],rax
  ac112e:	48 85 c0             	test   rax,rax
  ac1131:	74 08                	je     0xac113b
  ac1133:	49 8d 4e 28          	lea    rcx,[r14+0x28]
  ac1137:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
  ac113b:	48 8d 3d 3e 5d 13 03 	lea    rdi,[rip+0x3135d3e]        # 0x3bf6e80
  ac1142:	4c 89 33             	mov    QWORD PTR [rbx],r14
  ac1145:	49 89 5e 30          	mov    QWORD PTR [r14+0x30],rbx
  ac1149:	41 c7 46 20 01 00 00 	mov    DWORD PTR [r14+0x20],0x1
  ac1150:	00 
  ac1151:	31 f6                	xor    esi,esi
  ac1153:	31 d2                	xor    edx,edx
  ac1155:	31 c9                	xor    ecx,ecx
  ac1157:	e8 c4 63 a0 ff       	call   0x4c7520
  ac115c:	4d 89 6e 08          	mov    QWORD PTR [r14+0x8],r13
  ac1160:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  ac1164:	49 89 06             	mov    QWORD PTR [r14],rax
  ac1167:	4c 89 70 08          	mov    QWORD PTR [rax+0x8],r14
  ac116b:	4d 89 75 00          	mov    QWORD PTR [r13+0x0],r14
  ac116f:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1176:	00 00 
  ac1178:	e9 17 ff ff ff       	jmp    0xac1094
  ac117d:	e8 de 67 bf ff       	call   0x6b7960
  ac1182:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1189:	00 00 
  ac118b:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  ac1190:	f0 0f c1 88 a8 05 00 	lock xadd DWORD PTR [rax+0x5a8],ecx
  ac1197:	00 
  ac1198:	81 f9 01 00 00 80    	cmp    ecx,0x80000001
  ac119e:	75 05                	jne    0xac11a5
  ac11a0:	e8 4b 69 bf ff       	call   0x6b7af0
  ac11a5:	e8 a6 14 be ff       	call   0x6a2650
  ac11aa:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
  ac11ae:	8b 43 08             	mov    eax,DWORD PTR [rbx+0x8]
  ac11b1:	74 1b                	je     0xac11ce
  ac11b3:	a9 00 00 10 00       	test   eax,0x100000
  ac11b8:	75 2c                	jne    0xac11e6
  ac11ba:	48 8d 7b 40          	lea    rdi,[rbx+0x40]
  ac11be:	45 31 e4             	xor    r12d,r12d
  ac11c1:	31 f6                	xor    esi,esi
  ac11c3:	31 d2                	xor    edx,edx
  ac11c5:	31 c9                	xor    ecx,ecx
  ac11c7:	e8 d4 64 a0 ff       	call   0x4c76a0
  ac11cc:	eb 28                	jmp    0xac11f6
  ac11ce:	a9 00 00 10 00       	test   eax,0x100000
  ac11d3:	75 2a                	jne    0xac11ff
  ac11d5:	48 8d 7b 40          	lea    rdi,[rbx+0x40]
  ac11d9:	31 f6                	xor    esi,esi
  ac11db:	31 d2                	xor    edx,edx
  ac11dd:	31 c9                	xor    ecx,ecx
  ac11df:	e8 1c 58 a0 ff       	call   0x4c6a00
  ac11e4:	eb 3f                	jmp    0xac1225
  ac11e6:	48 8d 7b 28          	lea    rdi,[rbx+0x28]
  ac11ea:	45 31 e4             	xor    r12d,r12d
  ac11ed:	31 f6                	xor    esi,esi
  ac11ef:	31 d2                	xor    edx,edx
  ac11f1:	e8 1a b0 18 00       	call   0xc4c210
  ac11f6:	85 c0                	test   eax,eax
  ac11f8:	75 2b                	jne    0xac1225
  ac11fa:	e9 a7 fe ff ff       	jmp    0xac10a6
  ac11ff:	65 4c 8b 3c 25 00 00 	mov    r15,QWORD PTR gs:0x0
  ac1206:	00 00 
  ac1208:	41 ff 8f 70 03 00 00 	dec    DWORD PTR [r15+0x370]
  ac120f:	48 8d 7b 28          	lea    rdi,[rbx+0x28]
  ac1213:	31 f6                	xor    esi,esi
  ac1215:	31 d2                	xor    edx,edx
  ac1217:	31 c9                	xor    ecx,ecx
  ac1219:	e8 02 a9 18 00       	call   0xc4bb20
  ac121e:	41 ff 87 70 03 00 00 	inc    DWORD PTR [r15+0x370]
  ac1225:	e8 06 14 be ff       	call   0x6a2630
  ac122a:	65 8b 3c 25 34 00 00 	mov    edi,DWORD PTR gs:0x34
  ac1231:	00 
  ac1232:	e8 f9 6f a0 ff       	call   0x4c8230
  ac1237:	0f b6 48 34          	movzx  ecx,BYTE PTR [rax+0x34]
  ac123b:	48 c7 c2 fe ff ff ff 	mov    rdx,0xfffffffffffffffe
  ac1242:	48 d3 c2             	rol    rdx,cl
  ac1245:	48 21 53 18          	and    QWORD PTR [rbx+0x18],rdx
  ac1249:	48 8d 90 a0 06 00 00 	lea    rdx,[rax+0x6a0]
  ac1250:	49 89 56 08          	mov    QWORD PTR [r14+0x8],rdx
  ac1254:	48 8b 88 a0 06 00 00 	mov    rcx,QWORD PTR [rax+0x6a0]
  ac125b:	49 89 0e             	mov    QWORD PTR [r14],rcx
  ac125e:	4c 89 71 08          	mov    QWORD PTR [rcx+0x8],r14
  ac1262:	4c 89 b0 a0 06 00 00 	mov    QWORD PTR [rax+0x6a0],r14
  ac1269:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1270:	00 00 
  ac1272:	66 ff 80 0e 01 00 00 	inc    WORD PTR [rax+0x10e]
  ac1279:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1280:	00 00 
  ac1282:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  ac1289:	01 
  ac128a:	e8 b1 66 bf ff       	call   0x6b7940
  ac128f:	e8 bc 13 be ff       	call   0x6a2650
  ac1294:	f6 43 0a 10          	test   BYTE PTR [rbx+0xa],0x10
  ac1298:	75 17                	jne    0xac12b1
  ac129a:	48 83 c3 40          	add    rbx,0x40
  ac129e:	31 f6                	xor    esi,esi
  ac12a0:	31 d2                	xor    edx,edx
  ac12a2:	31 c9                	xor    ecx,ecx
  ac12a4:	48 89 df             	mov    rdi,rbx
  ac12a7:	e8 f4 5c a0 ff       	call   0x4c6fa0
  ac12ac:	e9 ef fd ff ff       	jmp    0xac10a0
  ac12b1:	48 83 c3 28          	add    rbx,0x28
  ac12b5:	31 f6                	xor    esi,esi
  ac12b7:	31 d2                	xor    edx,edx
  ac12b9:	48 89 df             	mov    rdi,rbx
  ac12bc:	e8 ef b1 18 00       	call   0xc4c4b0
  ac12c1:	e9 da fd ff ff       	jmp    0xac10a0
  ac12c6:	90                   	nop
  ac12c7:	90                   	nop
  ac12c8:	90                   	nop
  ac12c9:	90                   	nop
  ac12ca:	90                   	nop
  ac12cb:	90                   	nop
  ac12cc:	90                   	nop
  ac12cd:	90                   	nop
  ac12ce:	90                   	nop
  ac12cf:	90                   	nop
  ac12d0:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  ac12d3:	48 8b 4f 08          	mov    rcx,QWORD PTR [rdi+0x8]
  ac12d7:	48 89 48 08          	mov    QWORD PTR [rax+0x8],rcx
  ac12db:	48 89 01             	mov    QWORD PTR [rcx],rax
  ac12de:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  ac12e5:	00 00 
  ac12e7:	0f b7 87 0e 01 00 00 	movzx  eax,WORD PTR [rdi+0x10e]
  ac12ee:	89 c1                	mov    ecx,eax
  ac12f0:	66 ff c9             	dec    cx
  ac12f3:	66 89 8f 0e 01 00 00 	mov    WORD PTR [rdi+0x10e],cx
  ac12fa:	78 2c                	js     0xac1328
  ac12fc:	f6 87 08 01 00 00 04 	test   BYTE PTR [rdi+0x108],0x4
  ac1303:	74 22                	je     0xac1327
  ac1305:	0f bf 8f 0a 01 00 00 	movsx  ecx,WORD PTR [rdi+0x10a]
  ac130c:	0f bf 97 0c 01 00 00 	movsx  edx,WORD PTR [rdi+0x10c]
  ac1313:	01 ca                	add    edx,ecx
  ac1315:	b9 01 00 00 00       	mov    ecx,0x1
  ac131a:	29 c1                	sub    ecx,eax
  ac131c:	0f bf c1             	movsx  eax,cx
  ac131f:	39 c2                	cmp    edx,eax
  ac1321:	0f 84 c9 59 bf ff    	je     0x6b6cf0
  ac1327:	c3                   	ret
  ac1328:	55                   	push   rbp
  ac1329:	48 89 e5             	mov    rbp,rsp
  ac132c:	41 56                	push   r14
  ac132e:	53                   	push   rbx
  ac132f:	49 89 fe             	mov    r14,rdi
  ac1332:	e8 19 06 d3 ff       	call   0x7f1950
  ac1337:	49 0f bf 96 0e 01 00 	movsx  rdx,WORD PTR [r14+0x10e]
  ac133e:	00 
  ac133f:	48 8d 1d 14 c1 86 00 	lea    rbx,[rip+0x86c114]        # 0x132d45a
  ac1346:	48 8d 3d db ff ff ff 	lea    rdi,[rip+0xffffffffffffffdb]        # 0xac1328
  ac134d:	48 89 de             	mov    rsi,rbx
  ac1350:	e8 bb 0c d3 ff       	call   0x7f2010
  ac1355:	41 0f bf 8e 0e 01 00 	movsx  ecx,WORD PTR [r14+0x10e]
  ac135c:	00 
  ac135d:	48 8d 35 06 cd 84 00 	lea    rsi,[rip+0x84cd06]        # 0x130e06a
  ac1364:	bf 03 00 00 00       	mov    edi,0x3
  ac1369:	48 89 da             	mov    rdx,rbx
  ac136c:	31 c0                	xor    eax,eax
  ac136e:	e8 9d 96 1d 00       	call   0xc9aa10
  ac1373:	0f 0b                	ud2
  ac1375:	90                   	nop
  ac1376:	90                   	nop
  ac1377:	90                   	nop
  ac1378:	90                   	nop
  ac1379:	90                   	nop
  ac137a:	90                   	nop
  ac137b:	90                   	nop
  ac137c:	90                   	nop
  ac137d:	90                   	nop
  ac137e:	90                   	nop
  ac137f:	90                   	nop
  ac1380:	55                   	push   rbp
  ac1381:	48 89 e5             	mov    rbp,rsp
  ac1384:	41 56                	push   r14
  ac1386:	53                   	push   rbx
  ac1387:	f6 87 08 01 00 00 01 	test   BYTE PTR [rdi+0x108],0x1
  ac138e:	48 89 f3             	mov    rbx,rsi
  ac1391:	74 0b                	je     0xac139e
  ac1393:	ff 87 7c 04 00 00    	inc    DWORD PTR [rdi+0x47c]
  ac1399:	e8 b2 12 be ff       	call   0x6a2650
  ac139e:	83 7b 20 00          	cmp    DWORD PTR [rbx+0x20],0x0
  ac13a2:	74 44                	je     0xac13e8
  ac13a4:	48 8d 3d d5 5a 13 03 	lea    rdi,[rip+0x3135ad5]        # 0x3bf6e80
  ac13ab:	31 f6                	xor    esi,esi
  ac13ad:	31 d2                	xor    edx,edx
  ac13af:	31 c9                	xor    ecx,ecx
  ac13b1:	e8 da 5d a0 ff       	call   0x4c7190
  ac13b6:	48 8b 43 28          	mov    rax,QWORD PTR [rbx+0x28]
  ac13ba:	48 85 c0             	test   rax,rax
  ac13bd:	74 2e                	je     0xac13ed
  ac13bf:	4c 8d 73 28          	lea    r14,[rbx+0x28]
  ac13c3:	4c 39 70 30          	cmp    QWORD PTR [rax+0x30],r14
  ac13c7:	0f 85 cd 00 00 00    	jne    0xac149a
  ac13cd:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  ac13d1:	48 39 19             	cmp    QWORD PTR [rcx],rbx
  ac13d4:	0f 85 86 00 00 00    	jne    0xac1460
  ac13da:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
  ac13de:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  ac13e2:	48 8b 43 30          	mov    rax,QWORD PTR [rbx+0x30]
  ac13e6:	eb 10                	jmp    0xac13f8
  ac13e8:	5b                   	pop    rbx
  ac13e9:	41 5e                	pop    r14
  ac13eb:	5d                   	pop    rbp
  ac13ec:	c3                   	ret
  ac13ed:	48 8b 43 30          	mov    rax,QWORD PTR [rbx+0x30]
  ac13f1:	48 39 18             	cmp    QWORD PTR [rax],rbx
  ac13f4:	75 6a                	jne    0xac1460
  ac13f6:	31 c9                	xor    ecx,ecx
  ac13f8:	48 89 08             	mov    QWORD PTR [rax],rcx
  ac13fb:	f6 43 20 02          	test   BYTE PTR [rbx+0x20],0x2
  ac13ff:	75 16                	jne    0xac1417
  ac1401:	48 8d 3d 78 5a 13 03 	lea    rdi,[rip+0x3135a78]        # 0x3bf6e80
  ac1408:	31 f6                	xor    esi,esi
  ac140a:	31 d2                	xor    edx,edx
  ac140c:	31 c9                	xor    ecx,ecx
  ac140e:	5b                   	pop    rbx
  ac140f:	41 5e                	pop    r14
  ac1411:	5d                   	pop    rbp
  ac1412:	e9 09 61 a0 ff       	jmp    0x4c7520
  ac1417:	48 8b 5b 10          	mov    rbx,QWORD PTR [rbx+0x10]
  ac141b:	48 89 df             	mov    rdi,rbx
  ac141e:	e8 3d c1 96 ff       	call   0x42d560
  ac1423:	48 8d 3d 56 5a 13 03 	lea    rdi,[rip+0x3135a56]        # 0x3bf6e80
  ac142a:	31 f6                	xor    esi,esi
  ac142c:	31 d2                	xor    edx,edx
  ac142e:	31 c9                	xor    ecx,ecx
  ac1430:	e8 eb 60 a0 ff       	call   0x4c7520
  ac1435:	48 89 df             	mov    rdi,rbx
  ac1438:	e8 43 c2 96 ff       	call   0x42d680
  ac143d:	48 89 c7             	mov    rdi,rax
  ac1440:	31 f6                	xor    esi,esi
  ac1442:	49 89 c6             	mov    r14,rax
  ac1445:	e8 06 c7 96 ff       	call   0x42db50
  ac144a:	4c 89 f7             	mov    rdi,r14
  ac144d:	31 f6                	xor    esi,esi
  ac144f:	e8 5c ca 96 ff       	call   0x42deb0
  ac1454:	48 89 df             	mov    rdi,rbx
  ac1457:	5b                   	pop    rbx
  ac1458:	41 5e                	pop    r14
  ac145a:	5d                   	pop    rbp
  ac145b:	e9 90 c2 96 ff       	jmp    0x42d6f0
  ac1460:	e8 eb 04 d3 ff       	call   0x7f1950
  ac1465:	48 8b 53 30          	mov    rdx,QWORD PTR [rbx+0x30]
  ac1469:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac1460
  ac1470:	48 89 de             	mov    rsi,rbx
  ac1473:	48 8b 0a             	mov    rcx,QWORD PTR [rdx]
  ac1476:	e8 45 0c d3 ff       	call   0x7f20c0
  ac147b:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  ac147f:	48 8d 35 59 90 81 00 	lea    rsi,[rip+0x819059]        # 0x12da4df
  ac1486:	bf 0b 00 00 00       	mov    edi,0xb
  ac148b:	48 89 da             	mov    rdx,rbx
  ac148e:	31 c0                	xor    eax,eax
  ac1490:	4c 8b 01             	mov    r8,QWORD PTR [rcx]
  ac1493:	e8 78 95 1d 00       	call   0xc9aa10
  ac1498:	0f 0b                	ud2
  ac149a:	e8 b1 04 d3 ff       	call   0x7f1950
  ac149f:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  ac14a3:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac149a
  ac14aa:	48 89 de             	mov    rsi,rbx
  ac14ad:	4d 89 f0             	mov    r8,r14
  ac14b0:	48 8b 4a 30          	mov    rcx,QWORD PTR [rdx+0x30]
  ac14b4:	e8 c7 0c d3 ff       	call   0x7f2180
  ac14b9:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  ac14bd:	48 8d 35 bb cb 84 00 	lea    rsi,[rip+0x84cbbb]        # 0x130e07f
  ac14c4:	bf 07 00 00 00       	mov    edi,0x7
  ac14c9:	48 89 da             	mov    rdx,rbx
  ac14cc:	4d 89 f1             	mov    r9,r14
  ac14cf:	31 c0                	xor    eax,eax
  ac14d1:	4c 8b 41 30          	mov    r8,QWORD PTR [rcx+0x30]
  ac14d5:	e8 36 95 1d 00       	call   0xc9aa10
  ac14da:	0f 0b                	ud2
  ac14dc:	90                   	nop
  ac14dd:	90                   	nop
  ac14de:	90                   	nop
  ac14df:	90                   	nop
  ac14e0:	55                   	push   rbp
  ac14e1:	48 89 e5             	mov    rbp,rsp
  ac14e4:	41 57                	push   r15
  ac14e6:	41 56                	push   r14
  ac14e8:	41 54                	push   r12
  ac14ea:	53                   	push   rbx
  ac14eb:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac14f2:	00 00 
  ac14f4:	66 83 b8 14 01 00 00 	cmp    WORD PTR [rax+0x114],0x0
  ac14fb:	00 
  ac14fc:	75 36                	jne    0xac1534
  ac14fe:	f6 47 0a 10          	test   BYTE PTR [rdi+0xa],0x10
  ac1502:	48 89 fb             	mov    rbx,rdi
  ac1505:	75 11                	jne    0xac1518
  ac1507:	48 8d 7b 40          	lea    rdi,[rbx+0x40]
  ac150b:	31 f6                	xor    esi,esi
  ac150d:	31 d2                	xor    edx,edx
  ac150f:	31 c9                	xor    ecx,ecx
  ac1511:	e8 ea 54 a0 ff       	call   0x4c6a00
  ac1516:	eb 0f                	jmp    0xac1527
  ac1518:	48 8d 7b 28          	lea    rdi,[rbx+0x28]
  ac151c:	31 f6                	xor    esi,esi
  ac151e:	31 d2                	xor    edx,edx
  ac1520:	31 c9                	xor    ecx,ecx
  ac1522:	e8 f9 a5 18 00       	call   0xc4bb20
  ac1527:	48 8b 05 ba d3 24 03 	mov    rax,QWORD PTR [rip+0x324d3ba]        # 0x3d0e8e8
  ac152e:	48 3b 43 18          	cmp    rax,QWORD PTR [rbx+0x18]
  ac1532:	75 09                	jne    0xac153d
  ac1534:	5b                   	pop    rbx
  ac1535:	41 5c                	pop    r12
  ac1537:	41 5e                	pop    r14
  ac1539:	41 5f                	pop    r15
  ac153b:	5d                   	pop    rbp
  ac153c:	c3                   	ret
  ac153d:	48 8b 53 18          	mov    rdx,QWORD PTR [rbx+0x18]
  ac1541:	48 8d 4b 18          	lea    rcx,[rbx+0x18]
  ac1545:	49 89 d8             	mov    r8,rbx
  ac1548:	c4 e2 e8 f2 f8       	andn   rdi,rdx,rax
  ac154d:	48 8b 15 94 d3 24 03 	mov    rdx,QWORD PTR [rip+0x324d394]        # 0x3d0e8e8
  ac1554:	48 89 11             	mov    QWORD PTR [rcx],rdx
  ac1557:	48 8d 0d aa 08 7a ff 	lea    rcx,[rip+0xffffffffff7a08aa]        # 0x261e08
  ac155e:	48 8d 15 db 32 7a ff 	lea    rdx,[rip+0xffffffffff7a32db]        # 0x264840
  ac1565:	48 89 ce             	mov    rsi,rcx
  ac1568:	e8 03 24 04 00       	call   0xb03970
  ac156d:	48 8d 3d 0c 59 13 03 	lea    rdi,[rip+0x313590c]        # 0x3bf6e80
  ac1574:	31 f6                	xor    esi,esi
  ac1576:	31 d2                	xor    edx,edx
  ac1578:	31 c9                	xor    ecx,ecx
  ac157a:	e8 11 5c a0 ff       	call   0x4c7190
  ac157f:	4c 8b 63 20          	mov    r12,QWORD PTR [rbx+0x20]
  ac1583:	4d 85 e4             	test   r12,r12
  ac1586:	74 50                	je     0xac15d8
  ac1588:	4c 8d 35 f1 58 13 03 	lea    r14,[rip+0x31358f1]        # 0x3bf6e80
  ac158f:	90                   	nop
  ac1590:	48 89 df             	mov    rdi,rbx
  ac1593:	e8 f8 bf 96 ff       	call   0x42d590
  ac1598:	4c 89 f7             	mov    rdi,r14
  ac159b:	49 89 c7             	mov    r15,rax
  ac159e:	41 c7 44 24 20 03 00 	mov    DWORD PTR [r12+0x20],0x3
  ac15a5:	00 00 
  ac15a7:	31 f6                	xor    esi,esi
  ac15a9:	31 d2                	xor    edx,edx
  ac15ab:	31 c9                	xor    ecx,ecx
  ac15ad:	e8 6e 5f a0 ff       	call   0x4c7520
  ac15b2:	49 8b 74 24 18       	mov    rsi,QWORD PTR [r12+0x18]
  ac15b7:	4c 89 ff             	mov    rdi,r15
  ac15ba:	31 d2                	xor    edx,edx
  ac15bc:	e8 7f c2 96 ff       	call   0x42d840
  ac15c1:	4c 89 f7             	mov    rdi,r14
  ac15c4:	31 f6                	xor    esi,esi
  ac15c6:	31 d2                	xor    edx,edx
  ac15c8:	31 c9                	xor    ecx,ecx
  ac15ca:	e8 c1 5b a0 ff       	call   0x4c7190
  ac15cf:	4c 8b 63 20          	mov    r12,QWORD PTR [rbx+0x20]
  ac15d3:	4d 85 e4             	test   r12,r12
  ac15d6:	75 b8                	jne    0xac1590
  ac15d8:	48 8d 3d a1 58 13 03 	lea    rdi,[rip+0x31358a1]        # 0x3bf6e80
  ac15df:	31 f6                	xor    esi,esi
  ac15e1:	31 d2                	xor    edx,edx
  ac15e3:	31 c9                	xor    ecx,ecx
  ac15e5:	5b                   	pop    rbx
  ac15e6:	41 5c                	pop    r12
  ac15e8:	41 5e                	pop    r14
  ac15ea:	41 5f                	pop    r15
  ac15ec:	5d                   	pop    rbp
  ac15ed:	e9 2e 5f a0 ff       	jmp    0x4c7520
  ac15f2:	90                   	nop
  ac15f3:	90                   	nop
  ac15f4:	90                   	nop
  ac15f5:	90                   	nop
  ac15f6:	90                   	nop
  ac15f7:	90                   	nop
  ac15f8:	90                   	nop
  ac15f9:	90                   	nop
  ac15fa:	90                   	nop
  ac15fb:	90                   	nop
  ac15fc:	90                   	nop
  ac15fd:	90                   	nop
  ac15fe:	90                   	nop
  ac15ff:	90                   	nop
  ac1600:	55                   	push   rbp
  ac1601:	48 89 e5             	mov    rbp,rsp
  ac1604:	41 57                	push   r15
  ac1606:	41 56                	push   r14
  ac1608:	41 55                	push   r13
  ac160a:	41 54                	push   r12
  ac160c:	53                   	push   rbx
  ac160d:	50                   	push   rax
  ac160e:	48 89 fb             	mov    rbx,rdi
  ac1611:	65 8b 3c 25 34 00 00 	mov    edi,DWORD PTR gs:0x34
  ac1618:	00 
  ac1619:	e8 12 6c a0 ff       	call   0x4c8230
  ac161e:	4c 8b a0 a0 06 00 00 	mov    r12,QWORD PTR [rax+0x6a0]
  ac1625:	49 89 c6             	mov    r14,rax
  ac1628:	49 81 c6 a0 06 00 00 	add    r14,0x6a0
  ac162f:	4d 39 f4             	cmp    r12,r14
  ac1632:	74 74                	je     0xac16a8
  ac1634:	4c 8d 6b 20          	lea    r13,[rbx+0x20]
  ac1638:	4c 8d 3d 41 58 13 03 	lea    r15,[rip+0x3135841]        # 0x3bf6e80
  ac163f:	eb 28                	jmp    0xac1669
  ac1641:	4c 89 ff             	mov    rdi,r15
  ac1644:	4d 89 65 00          	mov    QWORD PTR [r13+0x0],r12
  ac1648:	4d 89 6c 24 30       	mov    QWORD PTR [r12+0x30],r13
  ac164d:	31 f6                	xor    esi,esi
  ac164f:	31 d2                	xor    edx,edx
  ac1651:	31 c9                	xor    ecx,ecx
  ac1653:	e8 c8 5e a0 ff       	call   0x4c7520
  ac1658:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  ac165f:	00 
  ac1660:	4d 8b 24 24          	mov    r12,QWORD PTR [r12]
  ac1664:	4d 39 f4             	cmp    r12,r14
  ac1667:	74 3f                	je     0xac16a8
  ac1669:	49 39 5c 24 10       	cmp    QWORD PTR [r12+0x10],rbx
  ac166e:	75 f0                	jne    0xac1660
  ac1670:	41 83 7c 24 20 00    	cmp    DWORD PTR [r12+0x20],0x0
  ac1676:	75 e8                	jne    0xac1660
  ac1678:	4c 89 ff             	mov    rdi,r15
  ac167b:	41 c7 44 24 20 01 00 	mov    DWORD PTR [r12+0x20],0x1
  ac1682:	00 00 
  ac1684:	31 f6                	xor    esi,esi
  ac1686:	31 d2                	xor    edx,edx
  ac1688:	31 c9                	xor    ecx,ecx
  ac168a:	e8 01 5b a0 ff       	call   0x4c7190
  ac168f:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  ac1693:	49 89 44 24 28       	mov    QWORD PTR [r12+0x28],rax
  ac1698:	48 85 c0             	test   rax,rax
  ac169b:	74 a4                	je     0xac1641
  ac169d:	49 8d 4c 24 28       	lea    rcx,[r12+0x28]
  ac16a2:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
  ac16a6:	eb 99                	jmp    0xac1641
  ac16a8:	48 83 c4 08          	add    rsp,0x8
  ac16ac:	5b                   	pop    rbx
  ac16ad:	41 5c                	pop    r12
  ac16af:	41 5d                	pop    r13
  ac16b1:	41 5e                	pop    r14
  ac16b3:	41 5f                	pop    r15
  ac16b5:	5d                   	pop    rbp
  ac16b6:	c3                   	ret
  ac16b7:	90                   	nop
  ac16b8:	90                   	nop
  ac16b9:	90                   	nop
  ac16ba:	90                   	nop
  ac16bb:	90                   	nop
  ac16bc:	90                   	nop
  ac16bd:	90                   	nop
  ac16be:	90                   	nop
  ac16bf:	90                   	nop
  ac16c0:	55                   	push   rbp
  ac16c1:	48 89 e5             	mov    rbp,rsp
  ac16c4:	41 56                	push   r14
  ac16c6:	53                   	push   rbx
  ac16c7:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  ac16ce:	00 00 
  ac16d0:	66 41 83 be 14 01 00 	cmp    WORD PTR [r14+0x114],0x0
  ac16d7:	00 00 
  ac16d9:	75 16                	jne    0xac16f1
  ac16db:	48 89 fb             	mov    rbx,rdi
  ac16de:	e8 fd fd ff ff       	call   0xac14e0
  ac16e3:	f6 43 0a 10          	test   BYTE PTR [rbx+0xa],0x10
  ac16e7:	75 08                	jne    0xac16f1
  ac16e9:	66 41 ff 86 0a 01 00 	inc    WORD PTR [r14+0x10a]
  ac16f0:	00 
  ac16f1:	5b                   	pop    rbx
  ac16f2:	41 5e                	pop    r14
  ac16f4:	5d                   	pop    rbp
  ac16f5:	c3                   	ret
  ac16f6:	90                   	nop
  ac16f7:	90                   	nop
  ac16f8:	90                   	nop
  ac16f9:	90                   	nop
  ac16fa:	90                   	nop
  ac16fb:	90                   	nop
  ac16fc:	90                   	nop
  ac16fd:	90                   	nop
  ac16fe:	90                   	nop
  ac16ff:	90                   	nop
  ac1700:	55                   	push   rbp
  ac1701:	48 89 e5             	mov    rbp,rsp
  ac1704:	41 56                	push   r14
  ac1706:	53                   	push   rbx
  ac1707:	65 48 8b 1c 25 00 00 	mov    rbx,QWORD PTR gs:0x0
  ac170e:	00 00 
  ac1710:	66 83 bb 14 01 00 00 	cmp    WORD PTR [rbx+0x114],0x0
  ac1717:	00 
  ac1718:	75 7a                	jne    0xac1794
  ac171a:	f6 47 0a 10          	test   BYTE PTR [rdi+0xa],0x10
  ac171e:	49 89 fe             	mov    r14,rdi
  ac1721:	75 18                	jne    0xac173b
  ac1723:	49 8d 7e 40          	lea    rdi,[r14+0x40]
  ac1727:	31 f6                	xor    esi,esi
  ac1729:	31 d2                	xor    edx,edx
  ac172b:	31 c9                	xor    ecx,ecx
  ac172d:	e8 6e 58 a0 ff       	call   0x4c6fa0
  ac1732:	41 f6 46 0a 10       	test   BYTE PTR [r14+0xa],0x10
  ac1737:	74 16                	je     0xac174f
  ac1739:	eb 4f                	jmp    0xac178a
  ac173b:	49 8d 7e 28          	lea    rdi,[r14+0x28]
  ac173f:	31 f6                	xor    esi,esi
  ac1741:	31 d2                	xor    edx,edx
  ac1743:	e8 68 ad 18 00       	call   0xc4c4b0
  ac1748:	41 f6 46 0a 10       	test   BYTE PTR [r14+0xa],0x10
  ac174d:	75 3b                	jne    0xac178a
  ac174f:	0f b7 83 0a 01 00 00 	movzx  eax,WORD PTR [rbx+0x10a]
  ac1756:	ff c8                	dec    eax
  ac1758:	66 89 83 0a 01 00 00 	mov    WORD PTR [rbx+0x10a],ax
  ac175f:	66 85 c0             	test   ax,ax
  ac1762:	78 6d                	js     0xac17d1
  ac1764:	f6 83 08 01 00 00 04 	test   BYTE PTR [rbx+0x108],0x4
  ac176b:	74 1d                	je     0xac178a
  ac176d:	0f bf 8b 0c 01 00 00 	movsx  ecx,WORD PTR [rbx+0x10c]
  ac1774:	0f bf 93 0e 01 00 00 	movsx  edx,WORD PTR [rbx+0x10e]
  ac177b:	98                   	cwde
  ac177c:	01 c1                	add    ecx,eax
  ac177e:	01 ca                	add    edx,ecx
  ac1780:	75 08                	jne    0xac178a
  ac1782:	48 89 df             	mov    rdi,rbx
  ac1785:	e8 66 55 bf ff       	call   0x6b6cf0
  ac178a:	66 83 bb 0a 01 00 00 	cmp    WORD PTR [rbx+0x10a],0x0
  ac1791:	00 
  ac1792:	78 05                	js     0xac1799
  ac1794:	5b                   	pop    rbx
  ac1795:	41 5e                	pop    r14
  ac1797:	5d                   	pop    rbp
  ac1798:	c3                   	ret
  ac1799:	e8 b2 01 d3 ff       	call   0x7f1950
  ac179e:	48 0f bf 93 0a 01 00 	movsx  rdx,WORD PTR [rbx+0x10a]
  ac17a5:	00 
  ac17a6:	4c 8d 35 74 5f 87 00 	lea    r14,[rip+0x875f74]        # 0x1337721
  ac17ad:	48 8d 3d e5 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe5]        # 0xac1799
  ac17b4:	4c 89 f6             	mov    rsi,r14
  ac17b7:	e8 54 08 d3 ff       	call   0x7f2010
  ac17bc:	0f bf 8b 0a 01 00 00 	movsx  ecx,WORD PTR [rbx+0x10a]
  ac17c3:	48 8d 35 50 4e 88 00 	lea    rsi,[rip+0x884e50]        # 0x134661a
  ac17ca:	bf 13 00 00 00       	mov    edi,0x13
  ac17cf:	eb 36                	jmp    0xac1807
  ac17d1:	e8 7a 01 d3 ff       	call   0x7f1950
  ac17d6:	48 0f bf 93 0a 01 00 	movsx  rdx,WORD PTR [rbx+0x10a]
  ac17dd:	00 
  ac17de:	4c 8d 35 3c 5f 87 00 	lea    r14,[rip+0x875f3c]        # 0x1337721
  ac17e5:	48 8d 3d e5 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe5]        # 0xac17d1
  ac17ec:	4c 89 f6             	mov    rsi,r14
  ac17ef:	e8 1c 08 d3 ff       	call   0x7f2010
  ac17f4:	0f bf 8b 0a 01 00 00 	movsx  ecx,WORD PTR [rbx+0x10a]
  ac17fb:	48 8d 35 18 4e 88 00 	lea    rsi,[rip+0x884e18]        # 0x134661a
  ac1802:	bf 0f 00 00 00       	mov    edi,0xf
  ac1807:	4c 89 f2             	mov    rdx,r14
  ac180a:	31 c0                	xor    eax,eax
  ac180c:	e8 ff 91 1d 00       	call   0xc9aa10
  ac1811:	0f 0b                	ud2
  ac1813:	90                   	nop
  ac1814:	90                   	nop
  ac1815:	90                   	nop
  ac1816:	90                   	nop
  ac1817:	90                   	nop
  ac1818:	90                   	nop
  ac1819:	90                   	nop
  ac181a:	90                   	nop
  ac181b:	90                   	nop
  ac181c:	90                   	nop
  ac181d:	90                   	nop
  ac181e:	90                   	nop
  ac181f:	90                   	nop
  ac1820:	55                   	push   rbp
  ac1821:	48 89 e5             	mov    rbp,rsp
  ac1824:	41 57                	push   r15
  ac1826:	41 56                	push   r14
  ac1828:	53                   	push   rbx
  ac1829:	50                   	push   rax
  ac182a:	65 4c 8b 3c 25 00 00 	mov    r15,QWORD PTR gs:0x0
  ac1831:	00 00 
  ac1833:	66 41 83 bf 14 01 00 	cmp    WORD PTR [r15+0x114],0x0
  ac183a:	00 00 
  ac183c:	bb 01 00 00 00       	mov    ebx,0x1
  ac1841:	75 1f                	jne    0xac1862
  ac1843:	49 89 fe             	mov    r14,rdi
  ac1846:	e8 15 f7 ff ff       	call   0xac0f60
  ac184b:	85 c0                	test   eax,eax
  ac184d:	74 11                	je     0xac1860
  ac184f:	41 f6 46 0a 10       	test   BYTE PTR [r14+0xa],0x10
  ac1854:	75 0c                	jne    0xac1862
  ac1856:	66 41 ff 87 0a 01 00 	inc    WORD PTR [r15+0x10a]
  ac185d:	00 
  ac185e:	eb 02                	jmp    0xac1862
  ac1860:	31 db                	xor    ebx,ebx
  ac1862:	89 d8                	mov    eax,ebx
  ac1864:	48 83 c4 08          	add    rsp,0x8
  ac1868:	5b                   	pop    rbx
  ac1869:	41 5e                	pop    r14
  ac186b:	41 5f                	pop    r15
  ac186d:	5d                   	pop    rbp
  ac186e:	c3                   	ret
  ac186f:	90                   	nop
  ac1870:	55                   	push   rbp
  ac1871:	48 89 e5             	mov    rbp,rsp
  ac1874:	41 57                	push   r15
  ac1876:	41 56                	push   r14
  ac1878:	41 54                	push   r12
  ac187a:	53                   	push   rbx
  ac187b:	65 48 8b 1c 25 00 00 	mov    rbx,QWORD PTR gs:0x0
  ac1882:	00 00 
  ac1884:	66 83 bb 14 01 00 00 	cmp    WORD PTR [rbx+0x114],0x0
  ac188b:	00 
  ac188c:	0f 85 c0 00 00 00    	jne    0xac1952
  ac1892:	4c 8b 66 18          	mov    r12,QWORD PTR [rsi+0x18]
  ac1896:	49 89 fe             	mov    r14,rdi
  ac1899:	48 89 f7             	mov    rdi,rsi
  ac189c:	49 89 f7             	mov    r15,rsi
  ac189f:	41 ff 84 24 7c 04 00 	inc    DWORD PTR [r12+0x47c]
  ac18a6:	00 
  ac18a7:	e8 24 fa ff ff       	call   0xac12d0
  ac18ac:	41 ff 8c 24 7c 04 00 	dec    DWORD PTR [r12+0x47c]
  ac18b3:	00 
  ac18b4:	e8 a7 60 bf ff       	call   0x6b7960
  ac18b9:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac18c0:	00 00 
  ac18c2:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  ac18c7:	f0 0f c1 88 a8 05 00 	lock xadd DWORD PTR [rax+0x5a8],ecx
  ac18ce:	00 
  ac18cf:	81 f9 01 00 00 80    	cmp    ecx,0x80000001
  ac18d5:	75 05                	jne    0xac18dc
  ac18d7:	e8 14 62 bf ff       	call   0x6b7af0
  ac18dc:	41 f6 46 0a 10       	test   BYTE PTR [r14+0xa],0x10
  ac18e1:	74 06                	je     0xac18e9
  ac18e3:	ff 8b 70 03 00 00    	dec    DWORD PTR [rbx+0x370]
  ac18e9:	41 0f b6 84 24 08 01 	movzx  eax,BYTE PTR [r12+0x108]
  ac18f0:	00 00 
  ac18f2:	83 e0 01             	and    eax,0x1
  ac18f5:	41 0b 47 20          	or     eax,DWORD PTR [r15+0x20]
  ac18f9:	74 0b                	je     0xac1906
  ac18fb:	4c 89 e7             	mov    rdi,r12
  ac18fe:	4c 89 fe             	mov    rsi,r15
  ac1901:	e8 7a fa ff ff       	call   0xac1380
  ac1906:	41 f6 46 0a 10       	test   BYTE PTR [r14+0xa],0x10
  ac190b:	75 3b                	jne    0xac1948
  ac190d:	0f b7 83 0a 01 00 00 	movzx  eax,WORD PTR [rbx+0x10a]
  ac1914:	ff c8                	dec    eax
  ac1916:	66 89 83 0a 01 00 00 	mov    WORD PTR [rbx+0x10a],ax
  ac191d:	66 85 c0             	test   ax,ax
  ac1920:	78 71                	js     0xac1993
  ac1922:	f6 83 08 01 00 00 04 	test   BYTE PTR [rbx+0x108],0x4
  ac1929:	74 1d                	je     0xac1948
  ac192b:	0f bf 8b 0c 01 00 00 	movsx  ecx,WORD PTR [rbx+0x10c]
  ac1932:	0f bf 93 0e 01 00 00 	movsx  edx,WORD PTR [rbx+0x10e]
  ac1939:	98                   	cwde
  ac193a:	01 c1                	add    ecx,eax
  ac193c:	01 ca                	add    edx,ecx
  ac193e:	75 08                	jne    0xac1948
  ac1940:	48 89 df             	mov    rdi,rbx
  ac1943:	e8 a8 53 bf ff       	call   0x6b6cf0
  ac1948:	66 83 bb 0a 01 00 00 	cmp    WORD PTR [rbx+0x10a],0x0
  ac194f:	00 
  ac1950:	78 09                	js     0xac195b
  ac1952:	5b                   	pop    rbx
  ac1953:	41 5c                	pop    r12
  ac1955:	41 5e                	pop    r14
  ac1957:	41 5f                	pop    r15
  ac1959:	5d                   	pop    rbp
  ac195a:	c3                   	ret
  ac195b:	e8 f0 ff d2 ff       	call   0x7f1950
  ac1960:	48 0f bf 93 0a 01 00 	movsx  rdx,WORD PTR [rbx+0x10a]
  ac1967:	00 
  ac1968:	4c 8d 35 e9 05 88 00 	lea    r14,[rip+0x8805e9]        # 0x1341f58
  ac196f:	48 8d 3d e5 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe5]        # 0xac195b
  ac1976:	4c 89 f6             	mov    rsi,r14
  ac1979:	e8 92 06 d3 ff       	call   0x7f2010
  ac197e:	0f bf 8b 0a 01 00 00 	movsx  ecx,WORD PTR [rbx+0x10a]
  ac1985:	48 8d 35 8e 4c 88 00 	lea    rsi,[rip+0x884c8e]        # 0x134661a
  ac198c:	bf 1b 00 00 00       	mov    edi,0x1b
  ac1991:	eb 36                	jmp    0xac19c9
  ac1993:	e8 b8 ff d2 ff       	call   0x7f1950
  ac1998:	48 0f bf 93 0a 01 00 	movsx  rdx,WORD PTR [rbx+0x10a]
  ac199f:	00 
  ac19a0:	4c 8d 35 b1 05 88 00 	lea    r14,[rip+0x8805b1]        # 0x1341f58
  ac19a7:	48 8d 3d e5 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe5]        # 0xac1993
  ac19ae:	4c 89 f6             	mov    rsi,r14
  ac19b1:	e8 5a 06 d3 ff       	call   0x7f2010
  ac19b6:	0f bf 8b 0a 01 00 00 	movsx  ecx,WORD PTR [rbx+0x10a]
  ac19bd:	48 8d 35 56 4c 88 00 	lea    rsi,[rip+0x884c56]        # 0x134661a
  ac19c4:	bf 17 00 00 00       	mov    edi,0x17
  ac19c9:	4c 89 f2             	mov    rdx,r14
  ac19cc:	31 c0                	xor    eax,eax
  ac19ce:	e8 3d 90 1d 00       	call   0xc9aa10
  ac19d3:	0f 0b                	ud2
  ac19d5:	90                   	nop
  ac19d6:	90                   	nop
  ac19d7:	90                   	nop
  ac19d8:	90                   	nop
  ac19d9:	90                   	nop
  ac19da:	90                   	nop
  ac19db:	90                   	nop
  ac19dc:	90                   	nop
  ac19dd:	90                   	nop
  ac19de:	90                   	nop
  ac19df:	90                   	nop
  ac19e0:	55                   	push   rbp
  ac19e1:	48 89 e5             	mov    rbp,rsp
  ac19e4:	e8 17 00 00 00       	call   0xac1a00
  ac19e9:	48 8d 05 a0 87 1f 03 	lea    rax,[rip+0x31f87a0]        # 0x3cba190
  ac19f0:	5d                   	pop    rbp
  ac19f1:	c3                   	ret
  ac19f2:	90                   	nop
  ac19f3:	90                   	nop
  ac19f4:	90                   	nop
  ac19f5:	90                   	nop
  ac19f6:	90                   	nop
  ac19f7:	90                   	nop
  ac19f8:	90                   	nop
  ac19f9:	90                   	nop
  ac19fa:	90                   	nop
  ac19fb:	90                   	nop
  ac19fc:	90                   	nop
  ac19fd:	90                   	nop
  ac19fe:	90                   	nop
  ac19ff:	90                   	nop
  ac1a00:	55                   	push   rbp
  ac1a01:	48 89 e5             	mov    rbp,rsp
  ac1a04:	41 57                	push   r15
  ac1a06:	41 56                	push   r14
  ac1a08:	53                   	push   rbx
  ac1a09:	50                   	push   rax
  ac1a0a:	4c 8d 35 7f 87 1f 03 	lea    r14,[rip+0x31f877f]        # 0x3cba190
  ac1a11:	89 f3                	mov    ebx,esi
  ac1a13:	41 89 ff             	mov    r15d,edi
  ac1a16:	be c8 3d 00 00       	mov    esi,0x3dc8
  ac1a1b:	4c 89 f7             	mov    rdi,r14
  ac1a1e:	e8 cd 75 79 ff       	call   0x258ff0
  ac1a23:	48 b8 c8 3d 00 00 05 	movabs rax,0x10500003dc8
  ac1a2a:	01 00 00 
  ac1a2d:	48 ba b4 00 00 00 bc 	movabs rdx,0xbc000000b4
  ac1a34:	00 00 00 
  ac1a37:	48 b9 02 00 00 00 d8 	movabs rcx,0xd800000002
  ac1a3e:	00 00 00 
  ac1a41:	4c 89 f7             	mov    rdi,r14
  ac1a44:	48 89 05 45 87 1f 03 	mov    QWORD PTR [rip+0x31f8745],rax        # 0x3cba190
  ac1a4b:	48 89 15 46 87 1f 03 	mov    QWORD PTR [rip+0x31f8746],rdx        # 0x3cba198
  ac1a52:	c7 05 4c 87 1f 03 3c 	mov    DWORD PTR [rip+0x31f874c],0x13c        # 0x3cba1a8
  ac1a59:	01 00 00 
  ac1a5c:	48 89 0d 3d 87 1f 03 	mov    QWORD PTR [rip+0x31f873d],rcx        # 0x3cba1a0
  ac1a63:	48 ba 10 3d 00 00 20 	movabs rdx,0x3d2000003d10
  ac1a6a:	3d 00 00 
  ac1a6d:	48 b9 03 00 00 00 00 	movabs rcx,0x3d0000000003
  ac1a74:	3d 00 00 
  ac1a77:	48 b8 38 35 00 00 80 	movabs rax,0x368000003538
  ac1a7e:	36 00 00 
  ac1a81:	48 89 15 2c 87 1f 03 	mov    QWORD PTR [rip+0x31f872c],rdx        # 0x3cba1b4
  ac1a88:	48 89 0d 1d 87 1f 03 	mov    QWORD PTR [rip+0x31f871d],rcx        # 0x3cba1ac
  ac1a8f:	48 ba 48 3d 00 00 60 	movabs rdx,0x3d6000003d48
  ac1a96:	3d 00 00 
  ac1a99:	48 b9 78 3d 00 00 90 	movabs rcx,0x3d9000003d78
  ac1aa0:	3d 00 00 
  ac1aa3:	48 89 15 1a 87 1f 03 	mov    QWORD PTR [rip+0x31f871a],rdx        # 0x3cba1c4
  ac1aaa:	48 89 0d 1b 87 1f 03 	mov    QWORD PTR [rip+0x31f871b],rcx        # 0x3cba1cc
  ac1ab1:	48 ba 05 00 00 00 30 	movabs rdx,0x3d3000000005
  ac1ab8:	3d 00 00 
  ac1abb:	48 b9 a0 01 00 00 e0 	movabs rcx,0x1e0000001a0
  ac1ac2:	01 00 00 
  ac1ac5:	48 89 15 f0 86 1f 03 	mov    QWORD PTR [rip+0x31f86f0],rdx        # 0x3cba1bc
  ac1acc:	48 89 0d 05 87 1f 03 	mov    QWORD PTR [rip+0x31f8705],rcx        # 0x3cba1d8
  ac1ad3:	48 ba b8 05 00 00 00 	movabs rdx,0x700000005b8
  ac1ada:	07 00 00 
  ac1add:	48 b9 88 0c 00 00 80 	movabs rcx,0xd8000000c88
  ac1ae4:	0d 00 00 
  ac1ae7:	48 89 15 f2 86 1f 03 	mov    QWORD PTR [rip+0x31f86f2],rdx        # 0x3cba1e0
  ac1aee:	48 89 0d f3 86 1f 03 	mov    QWORD PTR [rip+0x31f86f3],rcx        # 0x3cba1e8
  ac1af5:	48 ba c0 0d 00 00 98 	movabs rdx,0x119800000dc0
  ac1afc:	11 00 00 
  ac1aff:	48 b9 e0 12 00 00 68 	movabs rcx,0x1868000012e0
  ac1b06:	18 00 00 
  ac1b09:	48 89 15 e0 86 1f 03 	mov    QWORD PTR [rip+0x31f86e0],rdx        # 0x3cba1f0
  ac1b10:	48 89 0d e1 86 1f 03 	mov    QWORD PTR [rip+0x31f86e1],rcx        # 0x3cba1f8
  ac1b17:	48 ba 60 19 00 00 a0 	movabs rdx,0x19a000001960
  ac1b1e:	19 00 00 
  ac1b21:	48 b9 78 1d 00 00 c0 	movabs rcx,0x1ec000001d78
  ac1b28:	1e 00 00 
  ac1b2b:	48 89 15 ce 86 1f 03 	mov    QWORD PTR [rip+0x31f86ce],rdx        # 0x3cba200
  ac1b32:	48 89 0d cf 86 1f 03 	mov    QWORD PTR [rip+0x31f86cf],rcx        # 0x3cba208
  ac1b39:	48 ba 48 24 00 00 40 	movabs rdx,0x254000002448
  ac1b40:	25 00 00 
  ac1b43:	48 b9 80 25 00 00 58 	movabs rcx,0x295800002580
  ac1b4a:	29 00 00 
  ac1b4d:	48 89 15 bc 86 1f 03 	mov    QWORD PTR [rip+0x31f86bc],rdx        # 0x3cba210
  ac1b54:	48 89 0d bd 86 1f 03 	mov    QWORD PTR [rip+0x31f86bd],rcx        # 0x3cba218
  ac1b5b:	48 ba a0 2a 00 00 28 	movabs rdx,0x302800002aa0
  ac1b62:	30 00 00 
  ac1b65:	48 b9 20 31 00 00 60 	movabs rcx,0x316000003120
  ac1b6c:	31 00 00 
  ac1b6f:	48 89 15 aa 86 1f 03 	mov    QWORD PTR [rip+0x31f86aa],rdx        # 0x3cba220
  ac1b76:	48 89 0d ab 86 1f 03 	mov    QWORD PTR [rip+0x31f86ab],rcx        # 0x3cba228
  ac1b7d:	48 89 05 ac 86 1f 03 	mov    QWORD PTR [rip+0x31f86ac],rax        # 0x3cba230
  ac1b84:	c7 05 aa 86 1f 03 08 	mov    DWORD PTR [rip+0x31f86aa],0x3c08        # 0x3cba238
  ac1b8b:	3c 00 00 
  ac1b8e:	c7 05 3c 86 1f 03 05 	mov    DWORD PTR [rip+0x31f863c],0x5        # 0x3cba1d4
  ac1b95:	00 00 00 
  ac1b98:	e8 e3 d4 7b ff       	call   0x27f080
  ac1b9d:	48 8d 3d a8 86 1f 03 	lea    rdi,[rip+0x31f86a8]        # 0x3cba24c
  ac1ba4:	c7 05 9e 86 1f 03 1c 	mov    DWORD PTR [rip+0x31f869e],0x1c        # 0x3cba24c
  ac1bab:	00 00 00 
  ac1bae:	e8 8d ea ed ff       	call   0x9a0640
  ac1bb3:	44 89 ff             	mov    edi,r15d
  ac1bb6:	89 de                	mov    esi,ebx
  ac1bb8:	e8 13 01 00 00       	call   0xac1cd0
  ac1bbd:	4c 89 f7             	mov    rdi,r14
  ac1bc0:	48 83 c4 08          	add    rsp,0x8
  ac1bc4:	5b                   	pop    rbx
  ac1bc5:	41 5e                	pop    r14
  ac1bc7:	41 5f                	pop    r15
  ac1bc9:	5d                   	pop    rbp
  ac1bca:	e9 91 db a3 ff       	jmp    0x4ff760
  ac1bcf:	90                   	nop
  ac1bd0:	55                   	push   rbp
  ac1bd1:	48 89 e5             	mov    rbp,rsp
  ac1bd4:	41 57                	push   r15
  ac1bd6:	41 56                	push   r14
  ac1bd8:	53                   	push   rbx
  ac1bd9:	48 83 ec 28          	sub    rsp,0x28
  ac1bdd:	4c 8d 3d 2c a7 e5 02 	lea    r15,[rip+0x2e5a72c]        # 0x391c310
  ac1be4:	48 8d 75 d8          	lea    rsi,[rbp-0x28]
  ac1be8:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
  ac1bec:	48 8d 4d c8          	lea    rcx,[rbp-0x38]
  ac1bf0:	4c 8d 45 c0          	lea    r8,[rbp-0x40]
  ac1bf4:	89 fb                	mov    ebx,edi
  ac1bf6:	49 8b 07             	mov    rax,QWORD PTR [r15]
  ac1bf9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  ac1bfd:	e8 7e e2 1d 00       	call   0xc9fe80
  ac1c02:	85 c0                	test   eax,eax
  ac1c04:	0f 85 a9 00 00 00    	jne    0xac1cb3
  ac1c0a:	48 81 7d d0 48 92 0c 	cmp    QWORD PTR [rbp-0x30],0xc9248
  ac1c11:	00 
  ac1c12:	0f 82 9b 00 00 00    	jb     0xac1cb3
  ac1c18:	bf 18 00 00 00       	mov    edi,0x18
  ac1c1d:	be b2 00 00 00       	mov    esi,0xb2
  ac1c22:	e8 b9 95 0b 00       	call   0xb7b1e0
  ac1c27:	89 df                	mov    edi,ebx
  ac1c29:	be ff ff ff ff       	mov    esi,0xffffffff
  ac1c2e:	e8 cd fd ff ff       	call   0xac1a00
  ac1c33:	bf 18 00 00 00       	mov    edi,0x18
  ac1c38:	be b6 00 00 00       	mov    esi,0xb6
  ac1c3d:	e8 7e 95 0b 00       	call   0xb7b1c0
  ac1c42:	4c 8d 35 3f 52 13 03 	lea    r14,[rip+0x313523f]        # 0x3bf6e88
  ac1c49:	be 04 00 00 00       	mov    esi,0x4
  ac1c4e:	4c 89 f7             	mov    rdi,r14
  ac1c51:	e8 9a 73 79 ff       	call   0x258ff0
  ac1c56:	48 8b 75 d8          	mov    rsi,QWORD PTR [rbp-0x28]
  ac1c5a:	89 df                	mov    edi,ebx
  ac1c5c:	4c 89 f2             	mov    rdx,r14
  ac1c5f:	b9 04 00 00 00       	mov    ecx,0x4
  ac1c64:	c7 05 1a 52 13 03 1d 	mov    DWORD PTR [rip+0x313521a],0x11d        # 0x3bf6e88
  ac1c6b:	01 00 00 
  ac1c6e:	e8 7d 74 ce ff       	call   0x7a90f0
  ac1c73:	85 c0                	test   eax,eax
  ac1c75:	74 20                	je     0xac1c97
  ac1c77:	bf 18 00 00 00       	mov    edi,0x18
  ac1c7c:	be c1 00 00 00       	mov    esi,0xc1
  ac1c81:	e8 5a 95 0b 00       	call   0xb7b1e0
  ac1c86:	bf 18 00 00 00       	mov    edi,0x18
  ac1c8b:	be c2 00 00 00       	mov    esi,0xc2
  ac1c90:	e8 2b 95 0b 00       	call   0xb7b1c0
  ac1c95:	eb 1c                	jmp    0xac1cb3
  ac1c97:	be 08 33 0c 00       	mov    esi,0xc3308
  ac1c9c:	48 03 75 d8          	add    rsi,QWORD PTR [rbp-0x28]
  ac1ca0:	48 8d 15 e9 84 1f 03 	lea    rdx,[rip+0x31f84e9]        # 0x3cba190
  ac1ca7:	89 df                	mov    edi,ebx
  ac1ca9:	b9 c8 3d 00 00       	mov    ecx,0x3dc8
  ac1cae:	e8 3d 74 ce ff       	call   0x7a90f0
  ac1cb3:	49 8b 07             	mov    rax,QWORD PTR [r15]
  ac1cb6:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  ac1cba:	75 0b                	jne    0xac1cc7
  ac1cbc:	48 83 c4 28          	add    rsp,0x28
  ac1cc0:	5b                   	pop    rbx
  ac1cc1:	41 5e                	pop    r14
  ac1cc3:	41 5f                	pop    r15
  ac1cc5:	5d                   	pop    rbp
  ac1cc6:	c3                   	ret
  ac1cc7:	e8 e4 b9 c3 ff       	call   0x6fd6b0
  ac1ccc:	0f 0b                	ud2
  ac1cce:	90                   	nop
  ac1ccf:	90                   	nop
  ac1cd0:	55                   	push   rbp
  ac1cd1:	48 89 e5             	mov    rbp,rsp
  ac1cd4:	41 57                	push   r15
  ac1cd6:	41 56                	push   r14
  ac1cd8:	41 55                	push   r13
  ac1cda:	41 54                	push   r12
  ac1cdc:	53                   	push   rbx
  ac1cdd:	48 83 ec 18          	sub    rsp,0x18
  ac1ce1:	89 f3                	mov    ebx,esi
  ac1ce3:	e8 d8 2a da ff       	call   0x8647c0
  ac1ce8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  ac1cec:	48 85 c0             	test   rax,rax
  ac1cef:	0f 84 f3 00 00 00    	je     0xac1de8
  ac1cf5:	31 c0                	xor    eax,eax
  ac1cf7:	85 db                	test   ebx,ebx
  ac1cf9:	b9 06 00 00 00       	mov    ecx,0x6
  ac1cfe:	0f 49 cb             	cmovns ecx,ebx
  ac1d01:	0f 4e d8             	cmovle ebx,eax
  ac1d04:	45 31 ff             	xor    r15d,r15d
  ac1d07:	45 31 e4             	xor    r12d,r12d
  ac1d0a:	89 4d d4             	mov    DWORD PTR [rbp-0x2c],ecx
  ac1d0d:	eb 4d                	jmp    0xac1d5c
  ac1d0f:	90                   	nop
  ac1d10:	49 63 c7             	movsxd rax,r15d
  ac1d13:	48 8d 0d 6e 51 13 03 	lea    rcx,[rip+0x313516e]        # 0x3bf6e88
  ac1d1a:	4c 89 f7             	mov    rdi,r14
  ac1d1d:	44 89 e2             	mov    edx,r12d
  ac1d20:	45 8d 6c 24 01       	lea    r13d,[r12+0x1]
  ac1d25:	48 69 c0 e0 0b 00 00 	imul   rax,rax,0xbe0
  ac1d2c:	48 8d b4 08 a8 34 0c 	lea    rsi,[rax+rcx*1+0xc34a8]
  ac1d33:	00 
  ac1d34:	e8 c7 bd a1 ff       	call   0x4ddb00
  ac1d39:	4c 89 f7             	mov    rdi,r14
  ac1d3c:	be 18 00 00 00       	mov    esi,0x18
  ac1d41:	ba 60 00 00 00       	mov    edx,0x60
  ac1d46:	e8 85 8b a1 ff       	call   0x4da8d0
  ac1d4b:	41 ff c7             	inc    r15d
  ac1d4e:	45 89 ec             	mov    r12d,r13d
  ac1d51:	ff c3                	inc    ebx
  ac1d53:	3b 5d d4             	cmp    ebx,DWORD PTR [rbp-0x2c]
  ac1d56:	0f 8f 8c 00 00 00    	jg     0xac1de8
  ac1d5c:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  ac1d60:	89 de                	mov    esi,ebx
  ac1d62:	ba 02 00 00 00       	mov    edx,0x2
  ac1d67:	b9 18 00 00 00       	mov    ecx,0x18
  ac1d6c:	41 b8 53 00 00 00    	mov    r8d,0x53
  ac1d72:	e8 e9 62 a1 ff       	call   0x4d8060
  ac1d77:	48 85 c0             	test   rax,rax
  ac1d7a:	74 d5                	je     0xac1d51
  ac1d7c:	48 89 c7             	mov    rdi,rax
  ac1d7f:	49 89 c6             	mov    r14,rax
  ac1d82:	e8 49 61 a1 ff       	call   0x4d7ed0
  ac1d87:	41 89 c5             	mov    r13d,eax
  ac1d8a:	85 c0                	test   eax,eax
  ac1d8c:	78 69                	js     0xac1df7
  ac1d8e:	41 83 ff 05          	cmp    r15d,0x5
  ac1d92:	0f 8c 78 ff ff ff    	jl     0xac1d10
  ac1d98:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  ac1d9f:	00 00 
  ac1da1:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  ac1da5:	48 8d 15 44 a6 e1 00 	lea    rdx,[rip+0xe1a644]        # 0x18dc3f0
  ac1dac:	48 8d 0d 04 8a 7f 00 	lea    rcx,[rip+0x7f8a04]        # 0x12ba7b7
  ac1db3:	41 b8 5a 00 00 00    	mov    r8d,0x5a
  ac1db9:	31 ff                	xor    edi,edi
  ac1dbb:	31 f6                	xor    esi,esi
  ac1dbd:	44 8b 88 bc 00 00 00 	mov    r9d,DWORD PTR [rax+0xbc]
  ac1dc4:	31 c0                	xor    eax,eax
  ac1dc6:	e8 05 27 04 00       	call   0xb044d0
  ac1dcb:	48 8d 15 2e a6 e1 00 	lea    rdx,[rip+0xe1a62e]        # 0x18dc400
  ac1dd2:	44 89 e9             	mov    ecx,r13d
  ac1dd5:	45 89 f8             	mov    r8d,r15d
  ac1dd8:	31 ff                	xor    edi,edi
  ac1dda:	31 f6                	xor    esi,esi
  ac1ddc:	31 c0                	xor    eax,eax
  ac1dde:	e8 ed 26 04 00       	call   0xb044d0
  ac1de3:	e9 69 ff ff ff       	jmp    0xac1d51
  ac1de8:	48 83 c4 18          	add    rsp,0x18
  ac1dec:	5b                   	pop    rbx
  ac1ded:	41 5c                	pop    r12
  ac1def:	41 5d                	pop    r13
  ac1df1:	41 5e                	pop    r14
  ac1df3:	41 5f                	pop    r15
  ac1df5:	5d                   	pop    rbp
  ac1df6:	c3                   	ret
  ac1df7:	48 8d 15 d0 a5 e1 00 	lea    rdx,[rip+0xe1a5d0]        # 0x18dc3ce
  ac1dfe:	48 8d 0d b2 89 7f 00 	lea    rcx,[rip+0x7f89b2]        # 0x12ba7b7
  ac1e05:	41 b8 58 00 00 00    	mov    r8d,0x58
  ac1e0b:	31 ff                	xor    edi,edi
  ac1e0d:	31 f6                	xor    esi,esi
  ac1e0f:	31 c0                	xor    eax,eax
  ac1e11:	e8 ba 26 04 00       	call   0xb044d0
  ac1e16:	48 8d 15 bf a5 e1 00 	lea    rdx,[rip+0xe1a5bf]        # 0x18dc3dc
  ac1e1d:	89 d9                	mov    ecx,ebx
  ac1e1f:	45 89 e8             	mov    r8d,r13d
  ac1e22:	31 ff                	xor    edi,edi
  ac1e24:	31 f6                	xor    esi,esi
  ac1e26:	31 c0                	xor    eax,eax
  ac1e28:	e8 a3 26 04 00       	call   0xb044d0
  ac1e2d:	e8 1e fb d2 ff       	call   0x7f1950
  ac1e32:	48 8d 1d 7e 89 7f 00 	lea    rbx,[rip+0x7f897e]        # 0x12ba7b7
  ac1e39:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0xac1e2d
  ac1e40:	ba 58 00 00 00       	mov    edx,0x58
  ac1e45:	48 89 de             	mov    rsi,rbx
  ac1e48:	e8 c3 01 d3 ff       	call   0x7f2010
  ac1e4d:	48 8d 35 4a 7a 7c 00 	lea    rsi,[rip+0x7c7a4a]        # 0x128989e
  ac1e54:	bf 05 00 00 00       	mov    edi,0x5
  ac1e59:	48 89 da             	mov    rdx,rbx
  ac1e5c:	b9 58 00 00 00       	mov    ecx,0x58
  ac1e61:	31 c0                	xor    eax,eax
  ac1e63:	e8 a8 8b 1d 00       	call   0xc9aa10
  ac1e68:	0f 0b                	ud2
  ac1e6a:	90                   	nop
  ac1e6b:	90                   	nop
  ac1e6c:	90                   	nop
  ac1e6d:	90                   	nop
  ac1e6e:	90                   	nop
  ac1e6f:	90                   	nop
  ac1e70:	55                   	push   rbp
  ac1e71:	48 89 e5             	mov    rbp,rsp
  ac1e74:	41 57                	push   r15
  ac1e76:	41 56                	push   r14
  ac1e78:	41 55                	push   r13
  ac1e7a:	41 54                	push   r12
  ac1e7c:	53                   	push   rbx
  ac1e7d:	48 81 ec 28 02 00 00 	sub    rsp,0x228
  ac1e84:	4c 8d 3d 85 a4 e5 02 	lea    r15,[rip+0x2e5a485]        # 0x391c310
  ac1e8b:	49 8b 07             	mov    rax,QWORD PTR [r15]
  ac1e8e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  ac1e92:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  ac1e99:	00 00 
  ac1e9b:	48 8b 87 98 00 00 00 	mov    rax,QWORD PTR [rdi+0x98]
  ac1ea2:	a9 00 40 00 00       	test   eax,0x4000
  ac1ea7:	75 62                	jne    0xac1f0b
  ac1ea9:	a9 00 00 01 00       	test   eax,0x10000
  ac1eae:	75 64                	jne    0xac1f14
  ac1eb0:	48 89 bd 00 fe ff ff 	mov    QWORD PTR [rbp-0x200],rdi
  ac1eb7:	48 8b bf a8 00 00 00 	mov    rdi,QWORD PTR [rdi+0xa8]
  ac1ebe:	48 8d 35 d9 c9 8a 00 	lea    rsi,[rip+0x8ac9d9]        # 0x136e89e
  ac1ec5:	48 8d 95 c8 fe ff ff 	lea    rdx,[rbp-0x138]
  ac1ecc:	48 8d 8d b4 fe ff ff 	lea    rcx,[rbp-0x14c]
  ac1ed3:	e8 f8 d0 b1 ff       	call   0x5defd0
  ac1ed8:	85 c0                	test   eax,eax
  ac1eda:	74 4e                	je     0xac1f2a
  ac1edc:	48 8b 85 00 fe ff ff 	mov    rax,QWORD PTR [rbp-0x200]
  ac1ee3:	48 8d 35 b7 0e 7f 00 	lea    rsi,[rip+0x7f0eb7]        # 0x12b2da1
  ac1eea:	48 8d 95 c8 fe ff ff 	lea    rdx,[rbp-0x138]
  ac1ef1:	48 8d 8d b4 fe ff ff 	lea    rcx,[rbp-0x14c]
  ac1ef8:	48 8b b8 a8 00 00 00 	mov    rdi,QWORD PTR [rax+0xa8]
  ac1eff:	e8 cc d0 b1 ff       	call   0x5defd0
  ac1f04:	85 c0                	test   eax,eax
  ac1f06:	0f 95 c0             	setne  al
  ac1f09:	eb 21                	jmp    0xac1f2c
  ac1f0b:	48 8d 35 8a ed 8b 00 	lea    rsi,[rip+0x8bed8a]        # 0x1380c9c
  ac1f12:	eb 07                	jmp    0xac1f1b
  ac1f14:	48 8d 35 1a 3c 8d 00 	lea    rsi,[rip+0x8d3c1a]        # 0x1395b35
  ac1f1b:	31 c0                	xor    eax,eax
  ac1f1d:	e8 ae ec b1 ff       	call   0x5e0bd0
  ac1f22:	41 bd 2d 00 00 00    	mov    r13d,0x2d
  ac1f28:	eb 3c                	jmp    0xac1f66
  ac1f2a:	31 c0                	xor    eax,eax
  ac1f2c:	8b 8d b4 fe ff ff    	mov    ecx,DWORD PTR [rbp-0x14c]
  ac1f32:	85 c9                	test   ecx,ecx
  ac1f34:	0f 9e c2             	setle  dl
  ac1f37:	08 c2                	or     dl,al
  ac1f39:	75 10                	jne    0xac1f4b
  ac1f3b:	48 8b 95 c8 fe ff ff 	mov    rdx,QWORD PTR [rbp-0x138]
  ac1f42:	89 c8                	mov    eax,ecx
  ac1f44:	80 7c 02 ff 00       	cmp    BYTE PTR [rdx+rax*1-0x1],0x0
  ac1f49:	74 3d                	je     0xac1f88
  ac1f4b:	48 8d 35 a6 5a 89 00 	lea    rsi,[rip+0x895aa6]        # 0x13579f8
  ac1f52:	48 8b bd 00 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x200]
  ac1f59:	31 c0                	xor    eax,eax
  ac1f5b:	e8 70 ec b1 ff       	call   0x5e0bd0
  ac1f60:	41 bd 16 00 00 00    	mov    r13d,0x16
  ac1f66:	49 8b 07             	mov    rax,QWORD PTR [r15]
  ac1f69:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  ac1f6d:	0f 85 c0 09 00 00    	jne    0xac2933
  ac1f73:	44 89 e8             	mov    eax,r13d
  ac1f76:	48 81 c4 28 02 00 00 	add    rsp,0x228
  ac1f7d:	5b                   	pop    rbx
  ac1f7e:	41 5c                	pop    r12
  ac1f80:	41 5d                	pop    r13
  ac1f82:	41 5e                	pop    r14
  ac1f84:	41 5f                	pop    r15
  ac1f86:	5d                   	pop    rbp
  ac1f87:	c3                   	ret
  ac1f88:	4c 8b a5 00 fe ff ff 	mov    r12,QWORD PTR [rbp-0x200]
  ac1f8f:	48 8d 35 dd 66 85 00 	lea    rsi,[rip+0x8566dd]        # 0x1318673
  ac1f96:	45 31 ed             	xor    r13d,r13d
  ac1f99:	31 d2                	xor    edx,edx
  ac1f9b:	31 c9                	xor    ecx,ecx
  ac1f9d:	49 8b bc 24 a8 00 00 	mov    rdi,QWORD PTR [r12+0xa8]
  ac1fa4:	00 
  ac1fa5:	e8 26 d0 b1 ff       	call   0x5defd0
  ac1faa:	49 8b bc 24 a8 00 00 	mov    rdi,QWORD PTR [r12+0xa8]
  ac1fb1:	00 
  ac1fb2:	48 8d 35 5c 30 80 00 	lea    rsi,[rip+0x80305c]        # 0x12c5015
  ac1fb9:	48 8d 95 c0 fe ff ff 	lea    rdx,[rbp-0x140]
  ac1fc0:	31 c9                	xor    ecx,ecx
  ac1fc2:	89 c3                	mov    ebx,eax
  ac1fc4:	e8 07 d0 b1 ff       	call   0x5defd0
  ac1fc9:	85 c0                	test   eax,eax
  ac1fcb:	0f 84 5b 01 00 00    	je     0xac212c
  ac1fd1:	48 8b 85 00 fe ff ff 	mov    rax,QWORD PTR [rbp-0x200]
  ac1fd8:	48 8d 35 00 c1 84 00 	lea    rsi,[rip+0x84c100]        # 0x130e0df
  ac1fdf:	48 8d 95 c0 fe ff ff 	lea    rdx,[rbp-0x140]
  ac1fe6:	45 31 e4             	xor    r12d,r12d
  ac1fe9:	31 c9                	xor    ecx,ecx
  ac1feb:	48 8b b8 a8 00 00 00 	mov    rdi,QWORD PTR [rax+0xa8]
  ac1ff2:	e8 d9 cf b1 ff       	call   0x5defd0
  ac1ff7:	85 c0                	test   eax,eax
  ac1ff9:	0f 84 73 01 00 00    	je     0xac2172
  ac1fff:	89 9d d4 fd ff ff    	mov    DWORD PTR [rbp-0x22c],ebx
  ac2005:	48 8b 9d 00 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x200]
  ac200c:	48 8d 35 e3 3b 84 00 	lea    rsi,[rip+0x843be3]        # 0x1305bf6
  ac2013:	48 8d 95 c0 fe ff ff 	lea    rdx,[rbp-0x140]
  ac201a:	4c 89 ad e0 fd ff ff 	mov    QWORD PTR [rbp-0x220],r13
  ac2021:	48 c7 85 e8 fd ff ff 	mov    QWORD PTR [rbp-0x218],0x0
  ac2028:	00 00 00 00 
  ac202c:	31 c9                	xor    ecx,ecx
  ac202e:	48 8b bb a8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa8]
  ac2035:	e8 96 cf b1 ff       	call   0x5defd0
  ac203a:	48 8b bb a8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa8]
  ac2041:	48 8d 35 19 3d 7b 00 	lea    rsi,[rip+0x7b3d19]        # 0x1275d61
  ac2048:	48 8d 95 c0 fe ff ff 	lea    rdx,[rbp-0x140]
  ac204f:	31 c9                	xor    ecx,ecx
  ac2051:	41 89 c5             	mov    r13d,eax
  ac2054:	e8 77 cf b1 ff       	call   0x5defd0
  ac2059:	89 c1                	mov    ecx,eax
  ac205b:	44 09 e9             	or     ecx,r13d
  ac205e:	0f 84 54 01 00 00    	je     0xac21b8
  ac2064:	89 85 d8 fd ff ff    	mov    DWORD PTR [rbp-0x228],eax
  ac206a:	48 8b 85 e0 fd ff ff 	mov    rax,QWORD PTR [rbp-0x220]
  ac2071:	48 8b 9d 00 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x200]
  ac2078:	4c 89 e1             	mov    rcx,r12
  ac207b:	4c 89 b5 f0 fd ff ff 	mov    QWORD PTR [rbp-0x210],r14
  ac2082:	48 8d 15 e5 ac 88 00 	lea    rdx,[rip+0x88ace5]        # 0x134cd6e
  ac2089:	be 00 04 20 00       	mov    esi,0x200400
  ac208e:	44 89 ad dc fd ff ff 	mov    DWORD PTR [rbp-0x224],r13d
  ac2095:	66 85 c9             	test   cx,cx
  ac2098:	41 89 ce             	mov    r14d,ecx
  ac209b:	41 89 c4             	mov    r12d,eax
  ac209e:	48 8b 7b 48          	mov    rdi,QWORD PTR [rbx+0x48]
  ac20a2:	44 0f 45 e1          	cmovne r12d,ecx
  ac20a6:	66 85 c0             	test   ax,ax
  ac20a9:	44 0f 45 e0          	cmovne r12d,eax
  ac20ad:	66 45 85 e4          	test   r12w,r12w
  ac20b1:	44 0f 45 f0          	cmovne r14d,eax
  ac20b5:	66 85 c9             	test   cx,cx
  ac20b8:	44 0f 45 f1          	cmovne r14d,ecx
  ac20bc:	b9 b9 00 00 00       	mov    ecx,0xb9
  ac20c1:	e8 8a da be ff       	call   0x6afb50
  ac20c6:	48 8b 43 48          	mov    rax,QWORD PTR [rbx+0x48]
  ac20ca:	48 8b 8b 90 02 00 00 	mov    rcx,QWORD PTR [rbx+0x290]
  ac20d1:	48 8d 15 a0 8c 01 01 	lea    rdx,[rip+0x1018ca0]        # 0x1adad78
  ac20d8:	48 8d b5 08 fe ff ff 	lea    rsi,[rbp-0x1f8]
  ac20df:	48 89 95 e8 fe ff ff 	mov    QWORD PTR [rbp-0x118],rdx
  ac20e6:	48 89 85 f0 fe ff ff 	mov    QWORD PTR [rbp-0x110],rax
  ac20ed:	48 89 b5 f8 fe ff ff 	mov    QWORD PTR [rbp-0x108],rsi
  ac20f4:	48 89 8d 00 ff ff ff 	mov    QWORD PTR [rbp-0x100],rcx
  ac20fb:	48 8d b5 e8 fe ff ff 	lea    rsi,[rbp-0x118]
  ac2102:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  ac2106:	e8 b5 a0 ac ff       	call   0x58c1c0
  ac210b:	41 89 c5             	mov    r13d,eax
  ac210e:	85 c0                	test   eax,eax
  ac2110:	0f 84 c1 00 00 00    	je     0xac21d7
  ac2116:	44 89 a5 e0 fd ff ff 	mov    DWORD PTR [rbp-0x220],r12d
  ac211d:	44 89 b5 f8 fd ff ff 	mov    DWORD PTR [rbp-0x208],r14d
  ac2124:	45 31 e4             	xor    r12d,r12d
  ac2127:	e9 e3 00 00 00       	jmp    0xac220f
  ac212c:	48 8b bd c0 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x140]
  ac2133:	48 85 ff             	test   rdi,rdi
  ac2136:	74 2e                	je     0xac2166
  ac2138:	48 8d b5 b8 fe ff ff 	lea    rsi,[rbp-0x148]
  ac213f:	ba 08 00 00 00       	mov    edx,0x8
  ac2144:	e8 f7 2c d0 ff       	call   0x7c4e40
  ac2149:	48 83 bd c0 fe ff ff 	cmp    QWORD PTR [rbp-0x140],0x0
  ac2150:	00 
  ac2151:	74 13                	je     0xac2166
  ac2153:	48 8b 8d b8 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x148]
  ac215a:	49 89 c5             	mov    r13,rax
  ac215d:	80 39 00             	cmp    BYTE PTR [rcx],0x0
  ac2160:	0f 84 71 01 00 00    	je     0xac22d7
  ac2166:	48 8d 35 c8 fa 7c 00 	lea    rsi,[rip+0x7cfac8]        # 0x1291c35
  ac216d:	e9 e0 fd ff ff       	jmp    0xac1f52
  ac2172:	48 8b bd c0 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x140]
  ac2179:	48 85 ff             	test   rdi,rdi
  ac217c:	74 2e                	je     0xac21ac
  ac217e:	48 8d b5 b8 fe ff ff 	lea    rsi,[rbp-0x148]
  ac2185:	ba 08 00 00 00       	mov    edx,0x8
  ac218a:	e8 b1 2c d0 ff       	call   0x7c4e40
  ac218f:	48 83 bd c0 fe ff ff 	cmp    QWORD PTR [rbp-0x140],0x0
  ac2196:	00 
  ac2197:	74 13                	je     0xac21ac
  ac2199:	48 8b 8d b8 fe ff ff 	mov    rcx,QWORD PTR [rbp-0x148]
  ac21a0:	49 89 c4             	mov    r12,rax
  ac21a3:	80 39 00             	cmp    BYTE PTR [rcx],0x0
  ac21a6:	0f 84 34 02 00 00    	je     0xac23e0
  ac21ac:	48 8d 35 63 55 7c 00 	lea    rsi,[rip+0x7c5563]        # 0x1287716
  ac21b3:	e9 9a fd ff ff       	jmp    0xac1f52
  ac21b8:	48 8d 3d 3e 3a 84 00 	lea    rdi,[rip+0x843a3e]        # 0x1305bfd
  ac21bf:	48                   	rex.W

; SUPPLEMENTAL ORIGINAL KERNEL HELPER BYTES; GNU objdump, not REA.

; zero, source kernel_text.bin[0x258ff0:0x259032]

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_helper_258ff0.bin:     file format binary


Disassembly of section .data:

0000000000258ff0 <.data>:
  258ff0:	55                   	push   rbp
  258ff1:	48 89 e5             	mov    rbp,rsp
  258ff4:	49 89 fa             	mov    r10,rdi
  258ff7:	49 01 f2             	add    r10,rsi
  258ffa:	72 19                	jb     0x259015
  258ffc:	49 39 e2             	cmp    r10,rsp
  258fff:	76 19                	jbe    0x25901a
  259001:	4c 8d 55 10          	lea    r10,[rbp+0x10]
  259005:	4c 39 d7             	cmp    rdi,r10
  259008:	7d 10                	jge    0x25901a
  25900a:	48 89 ff             	mov    rdi,rdi
  25900d:	48 89 f6             	mov    rsi,rsi
  259010:	e8 bb ff ff ff       	call   0x258fd0
  259015:	e8 c6 ff ff ff       	call   0x258fe0
  25901a:	48 89 f1             	mov    rcx,rsi
  25901d:	31 c0                	xor    eax,eax
  25901f:	48 c1 e9 03          	shr    rcx,0x3
  259023:	fc                   	cld
  259024:	f3 48 ab             	rep stos QWORD PTR [rdi],rax
  259027:	48 89 f1             	mov    rcx,rsi
  25902a:	48 83 e1 07          	and    rcx,0x7
  25902e:	f3 aa                	rep stos BYTE PTR [rdi],al
  259030:	5d                   	pop    rbp
  259031:	c3                   	ret

; copyout, source kernel_text.bin[0x2591d0:0x259280]

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_helper_2591d0.bin:     file format binary


Disassembly of section .data:

00000000002591d0 <.data>:
  2591d0:	55                   	push   rbp
  2591d1:	48 89 e5             	mov    rbp,rsp
  2591d4:	65 48 8b 04 25 20 00 	mov    rax,QWORD PTR gs:0x20
  2591db:	00 00 
  2591dd:	4c 8d 1d 7c 00 00 00 	lea    r11,[rip+0x7c]        # 0x259260
  2591e4:	4c 89 98 08 01 00 00 	mov    QWORD PTR [rax+0x108],r11
  2591eb:	48 85 d2             	test   rdx,rdx
  2591ee:	74 55                	je     0x259245
  2591f0:	48 89 f0             	mov    rax,rsi
  2591f3:	48 01 d0             	add    rax,rdx
  2591f6:	72 68                	jb     0x259260
  2591f8:	48 b9 00 00 00 00 00 	movabs rcx,0x800000000000
  2591ff:	80 00 00 
  259202:	48 39 c8             	cmp    rax,rcx
  259205:	77 59                	ja     0x259260
  259207:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  25920e:	00 00 
  259210:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  259214:	80 b8 91 05 00 00 00 	cmp    BYTE PTR [rax+0x591],0x0
  25921b:	75 43                	jne    0x259260
  25921d:	48 b8 ff ff ff ff ff 	movabs rax,0x7fffffffffff
  259224:	7f 00 00 
  259227:	48 21 c6             	and    rsi,rax
  25922a:	48 87 f7             	xchg   rdi,rsi
  25922d:	48 89 d1             	mov    rcx,rdx
  259230:	48 c1 e9 03          	shr    rcx,0x3
  259234:	fc                   	cld
  259235:	0f 01 cb             	stac
  259238:	f3 48 a5             	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  25923b:	88 d1                	mov    cl,dl
  25923d:	80 e1 07             	and    cl,0x7
  259240:	f3 a4                	rep movs BYTE PTR [rdi],BYTE PTR [rsi]
  259242:	0f 01 ca             	clac
  259245:	31 c0                	xor    eax,eax
  259247:	65 48 8b 14 25 20 00 	mov    rdx,QWORD PTR gs:0x20
  25924e:	00 00 
  259250:	48 89 82 08 01 00 00 	mov    QWORD PTR [rdx+0x108],rax
  259257:	5d                   	pop    rbp
  259258:	c3                   	ret
  259259:	90                   	nop
  25925a:	90                   	nop
  25925b:	90                   	nop
  25925c:	90                   	nop
  25925d:	90                   	nop
  25925e:	90                   	nop
  25925f:	90                   	nop
  259260:	0f 01 ca             	clac
  259263:	65 48 8b 14 25 20 00 	mov    rdx,QWORD PTR gs:0x20
  25926a:	00 00 
  25926c:	48 c7 82 08 01 00 00 	mov    QWORD PTR [rdx+0x108],0x0
  259273:	00 00 00 00 
  259277:	48 c7 c0 0e 00 00 00 	mov    rax,0xe
  25927e:	5d                   	pop    rbp
  25927f:	c3                   	ret

; copyin, source kernel_text.bin[0x259280:0x259360]

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_helper_259280.bin:     file format binary


Disassembly of section .data:

0000000000259280 <.data>:
  259280:	55                   	push   rbp
  259281:	48 89 e5             	mov    rbp,rsp
  259284:	49 89 f2             	mov    r10,rsi
  259287:	49 01 d2             	add    r10,rdx
  25928a:	72 19                	jb     0x2592a5
  25928c:	49 39 e2             	cmp    r10,rsp
  25928f:	76 19                	jbe    0x2592aa
  259291:	4c 8d 55 10          	lea    r10,[rbp+0x10]
  259295:	4c 39 d6             	cmp    rsi,r10
  259298:	7d 10                	jge    0x2592aa
  25929a:	48 89 f7             	mov    rdi,rsi
  25929d:	48 89 d6             	mov    rsi,rdx
  2592a0:	e8 2b fd ff ff       	call   0x258fd0
  2592a5:	e8 36 fd ff ff       	call   0x258fe0
  2592aa:	65 48 8b 04 25 20 00 	mov    rax,QWORD PTR gs:0x20
  2592b1:	00 00 
  2592b3:	4c 8d 1d 86 00 00 00 	lea    r11,[rip+0x86]        # 0x259340
  2592ba:	4c 89 98 08 01 00 00 	mov    QWORD PTR [rax+0x108],r11
  2592c1:	48 85 d2             	test   rdx,rdx
  2592c4:	74 57                	je     0x25931d
  2592c6:	48 89 f8             	mov    rax,rdi
  2592c9:	48 01 d0             	add    rax,rdx
  2592cc:	72 72                	jb     0x259340
  2592ce:	48 b9 00 00 00 00 00 	movabs rcx,0x800000000000
  2592d5:	80 00 00 
  2592d8:	48 39 c8             	cmp    rax,rcx
  2592db:	77 63                	ja     0x259340
  2592dd:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2592e4:	00 00 
  2592e6:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  2592ea:	80 b8 91 05 00 00 00 	cmp    BYTE PTR [rax+0x591],0x0
  2592f1:	75 4d                	jne    0x259340
  2592f3:	48 b8 ff ff ff ff ff 	movabs rax,0x7fffffffffff
  2592fa:	7f 00 00 
  2592fd:	48 21 c7             	and    rdi,rax
  259300:	48 87 f7             	xchg   rdi,rsi
  259303:	48 89 d1             	mov    rcx,rdx
  259306:	88 c8                	mov    al,cl
  259308:	48 c1 e9 03          	shr    rcx,0x3
  25930c:	fc                   	cld
  25930d:	0f 01 cb             	stac
  259310:	f3 48 a5             	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  259313:	88 c1                	mov    cl,al
  259315:	80 e1 07             	and    cl,0x7
  259318:	f3 a4                	rep movs BYTE PTR [rdi],BYTE PTR [rsi]
  25931a:	0f 01 ca             	clac
  25931d:	31 c0                	xor    eax,eax
  25931f:	65 48 8b 14 25 20 00 	mov    rdx,QWORD PTR gs:0x20
  259326:	00 00 
  259328:	48 89 82 08 01 00 00 	mov    QWORD PTR [rdx+0x108],rax
  25932f:	5d                   	pop    rbp
  259330:	c3                   	ret
  259331:	90                   	nop
  259332:	90                   	nop
  259333:	90                   	nop
  259334:	90                   	nop
  259335:	90                   	nop
  259336:	90                   	nop
  259337:	90                   	nop
  259338:	90                   	nop
  259339:	90                   	nop
  25933a:	90                   	nop
  25933b:	90                   	nop
  25933c:	90                   	nop
  25933d:	90                   	nop
  25933e:	90                   	nop
  25933f:	90                   	nop
  259340:	0f 01 ca             	clac
  259343:	65 48 8b 14 25 20 00 	mov    rdx,QWORD PTR gs:0x20
  25934a:	00 00 
  25934c:	48 c7 82 08 01 00 00 	mov    QWORD PTR [rdx+0x108],0x0
  259353:	00 00 00 00 
  259357:	48 c7 c0 0e 00 00 00 	mov    rax,0xe
  25935e:	5d                   	pop    rbp
  25935f:	c3                   	ret

; credential_bit62, source kernel_text.bin[0x608f90:0x608fa1]

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_helper_608f90.bin:     file format binary


Disassembly of section .data:

0000000000608f90 <.data>:
  608f90:	55                   	push   rbp
  608f91:	48 89 e5             	mov    rbp,rsp
  608f94:	48 8b 47 60          	mov    rax,QWORD PTR [rdi+0x60]
  608f98:	48 c1 e8 3e          	shr    rax,0x3e
  608f9c:	83 e0 01             	and    eax,0x1
  608f9f:	5d                   	pop    rbp
  608fa0:	c3                   	ret

; credential_authid_allowlist, source kernel_text.bin[0x6090d0:0x60910e]

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_helper_6090d0.bin:     file format binary


Disassembly of section .data:

00000000006090d0 <.data>:
  6090d0:	55                   	push   rbp
  6090d1:	48 89 e5             	mov    rbp,rsp
  6090d4:	48 8b 4f 58          	mov    rcx,QWORD PTR [rdi+0x58]
  6090d8:	b8 01 00 00 00       	mov    eax,0x1
  6090dd:	48 ba 22 00 00 00 00 	movabs rdx,0x4800000000000022
  6090e4:	00 00 48 
  6090e7:	48 39 d1             	cmp    rcx,rdx
  6090ea:	74 20                	je     0x60910c
  6090ec:	48 ba 2e 00 00 00 00 	movabs rdx,0x480000000000002e
  6090f3:	00 00 48 
  6090f6:	48 39 d1             	cmp    rcx,rdx
  6090f9:	74 11                	je     0x60910c
  6090fb:	48 ba 1f 10 00 00 00 	movabs rdx,0x480000000000101f
  609102:	00 00 48 
  609105:	48 39 d1             	cmp    rcx,rdx
  609108:	74 02                	je     0x60910c
  60910a:	31 c0                	xor    eax,eax
  60910c:	5d                   	pop    rbp
  60910d:	c3                   	ret

; module_query_gates, source kernel_text.bin[0xacce10:0xacce84]

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_helper_acce10.bin:     file format binary


Disassembly of section .data:

0000000000acce10 <.data>:
  acce10:	55                   	push   rbp
  acce11:	48 89 e5             	mov    rbp,rsp
  acce14:	53                   	push   rbx
  acce15:	50                   	push   rax
  acce16:	e8 85 5f b1 ff       	call   0x5e2da0
  acce1b:	31 db                	xor    ebx,ebx
  acce1d:	85 c0                	test   eax,eax
  acce1f:	75 1d                	jne    0xacce3e
  acce21:	e8 9a 5e b1 ff       	call   0x5e2cc0
  acce26:	85 c0                	test   eax,eax
  acce28:	75 09                	jne    0xacce33
  acce2a:	e8 91 62 b1 ff       	call   0x5e30c0
  acce2f:	85 c0                	test   eax,eax
  acce31:	74 0b                	je     0xacce3e
  acce33:	8b 1d 57 45 1f 03    	mov    ebx,DWORD PTR [rip+0x31f4557]        # 0x3cc1390
  acce39:	f7 d3                	not    ebx
  acce3b:	83 e3 01             	and    ebx,0x1
  acce3e:	89 d8                	mov    eax,ebx
  acce40:	48 83 c4 08          	add    rsp,0x8
  acce44:	5b                   	pop    rbx
  acce45:	5d                   	pop    rbp
  acce46:	c3                   	ret
  acce47:	90                   	nop
  acce48:	90                   	nop
  acce49:	90                   	nop
  acce4a:	90                   	nop
  acce4b:	90                   	nop
  acce4c:	90                   	nop
  acce4d:	90                   	nop
  acce4e:	90                   	nop
  acce4f:	90                   	nop
  acce50:	55                   	push   rbp
  acce51:	48 89 e5             	mov    rbp,rsp
  acce54:	e8 47 5f b1 ff       	call   0x5e2da0
  acce59:	85 c0                	test   eax,eax
  acce5b:	75 12                	jne    0xacce6f
  acce5d:	e8 5e 5e b1 ff       	call   0x5e2cc0
  acce62:	85 c0                	test   eax,eax
  acce64:	75 09                	jne    0xacce6f
  acce66:	e8 55 62 b1 ff       	call   0x5e30c0
  acce6b:	85 c0                	test   eax,eax
  acce6d:	74 11                	je     0xacce80
  acce6f:	0f b6 0d 1a 45 1f 03 	movzx  ecx,BYTE PTR [rip+0x31f451a]        # 0x3cc1390
  acce76:	31 c0                	xor    eax,eax
  acce78:	f6 c1 04             	test   cl,0x4
  acce7b:	0f 94 c0             	sete   al
  acce7e:	5d                   	pop    rbp
  acce7f:	c3                   	ret
  acce80:	31 c0                	xor    eax,eax
  acce82:	5d                   	pop    rbp
  acce83:	c3                   	ret
