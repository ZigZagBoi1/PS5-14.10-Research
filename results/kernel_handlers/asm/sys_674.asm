; Handler 674: REA6.7.0 / Ghidra12.1.4 static function-aware assembly.
; All addresses are kernel RVAs; runtime VA = 0xffffffff8a9c0000 + RVA.
; Original 4096-byte input SHA256 2b296f8bf9a7d2c0b88b3664570faeb6bf0325d743aacf1c8c7c5114280302f0.
; Actual target RVA 0xabb980; adjacent recovered functions are context.

; ===== REA full original-window trampoline functions and verified padding =====
; COMPLETE ORIGINAL INPUT WINDOW: handler_674.bin, 4096 bytes
; SHA256 2b296f8bf9a7d2c0b88b3664570faeb6bf0325d743aacf1c8c7c5114280302f0; file offset zero = kernel RVA 0x265fa0.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x0 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x8 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x10 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x18 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x20 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x28 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x30 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x38 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x40 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0x48 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0x50 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0x58 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0x60 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0x68 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0x70 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0x78 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0x80 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0x88 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0x90 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0x98 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0xa0 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0xa8 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0xb0 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0xb8 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0xc0 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0xc8 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0xd0 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0xd8 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0xe0 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0xe8 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0xf0 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0xf8 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0x100 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x108 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x110 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x118 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x120 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x128 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x130 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x138 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x140 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x148 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x150 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x158 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x160 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0x168 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0x170 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0x178 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0x180 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0x188 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0x190 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0x198 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0x1a0 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0x1a8 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0x1b0 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0x1b8 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0x1c0 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0x1c8 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0x1d0 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0x1d8 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0x1e0 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0x1e8 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0x1f0 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0x1f8 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0x200 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0x208 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0x210 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0x218 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0x220 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0x228 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0x230 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0x238 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0x240 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0x248 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0x250 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0x258 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0x260 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0x268 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0x270 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0x278 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0x280 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0x288 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0x290 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0x298 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0x2a0 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0x2a8 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0x2b0 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0x2b8 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0x2c0 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0x2c8 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0x2d0 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0x2d8 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0x2e0 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0x2e8 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0x2f0 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0x2f8 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0x300 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0x308 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0x310 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0x318 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0x320 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0x328 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0x330 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0x338 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0x340 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0x348 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0x350 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0x358 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0x360 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0x368 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0x370 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0x378 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0x380 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0x388 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0x390 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0x398 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0x3a0 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0x3a8 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0x3b0 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0x3b8 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0x3c0 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0x3c8 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0x3d0 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0x3d8 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0x3e0 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0x3e8 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0x3f0 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0x3f8 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0x400 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0x408 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0x410 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0x418 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0x420 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0x428 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0x430 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0x438 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0x440 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0x448 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0x450 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0x458 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0x460 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0x468 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0x470 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0x478 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0x480 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0x488 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0x490 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0x498 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0x4a0 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0x4a8 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0x4b0 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0x4b8 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0x4c0 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0x4c8 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0x4d0 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0x4d8 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0x4e0 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0x4e8 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0x4f0 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0x4f8 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0x500 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0x508 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0x510 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0x518 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0x520 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0x528 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0x530 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0x538 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0x540 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0x548 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0x550 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0x558 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0x560 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0x568 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0x570 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0x578 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0x580 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0x588 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0x590 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0x598 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0x5a0 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0x5a8 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0x5b0 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0x5b8 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0x5c0 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0x5c8 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0x5d0 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0x5d8 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0x5e0 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0x5e8 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0x5f0 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0x5f8 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0x600 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0x608 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0x610 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0x618 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0x620 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0x628 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0x630 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0x638 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0x640 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0x648 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0x650 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0x658 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0x660 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0x668 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0x670 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0x678 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0x680 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0x688 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0x690 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0x698 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0x6a0 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0x6a8 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0x6b0 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0x6b8 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0x6c0 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0x6c8 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0x6d0 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0x6d8 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0x6e0 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0x6e8 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0x6f0 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0x6f8 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0x700 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0x708 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0x710 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0x718 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0x720 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0x728 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0x730 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0x738 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0x740 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0x748 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0x750 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0x758 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0x760 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding

; FUNCTION thunk_266708 [0x266708, 0x26670c] | file +0x768 | ev_a1b1ecfb69ddcde3ab328e54879b2647bb27553f41929ae5021b46edd03a8fd6
thunk_266708:
0x266708: JMP 0x00ca7310
; END FUNCTION thunk_266708
0x26670d: INT3 ; original byte CC, padding
0x26670e: INT3 ; original byte CC, padding
0x26670f: INT3 ; original byte CC, padding

; FUNCTION thunk_266710 [0x266710, 0x266714] | file +0x770 | ev_91a5d5c52dbb1d6be7f635bc2e634aa41a9d00a7b8b5d2ae096ecbfdcbfa2641
thunk_266710:
0x266710: JMP 0x00662e70
; END FUNCTION thunk_266710
0x266715: INT3 ; original byte CC, padding
0x266716: INT3 ; original byte CC, padding
0x266717: INT3 ; original byte CC, padding

; FUNCTION thunk_266718 [0x266718, 0x26671c] | file +0x778 | ev_5d49490e833cb75f11ae327b52e57d63c8562abf36102eae069cd3b6103363e9
thunk_266718:
0x266718: JMP 0x00662e80
; END FUNCTION thunk_266718
0x26671d: INT3 ; original byte CC, padding
0x26671e: INT3 ; original byte CC, padding
0x26671f: INT3 ; original byte CC, padding

; FUNCTION thunk_266720 [0x266720, 0x266724] | file +0x780 | ev_1dbafec98e5478d51b8103829bfa1a72f4bc438e9f77ede71f00176b6c65fa7a
thunk_266720:
0x266720: JMP 0x00678e10
; END FUNCTION thunk_266720
0x266725: INT3 ; original byte CC, padding
0x266726: INT3 ; original byte CC, padding
0x266727: INT3 ; original byte CC, padding

; FUNCTION thunk_266728 [0x266728, 0x26672c] | file +0x788 | ev_38fac9adf6535b05ba585c6e1016cc470c98cfb56fa25e1502404b81f2326987
thunk_266728:
0x266728: JMP 0x00678e60
; END FUNCTION thunk_266728
0x26672d: INT3 ; original byte CC, padding
0x26672e: INT3 ; original byte CC, padding
0x26672f: INT3 ; original byte CC, padding

; FUNCTION thunk_266730 [0x266730, 0x266734] | file +0x790 | ev_890d87fa71c13e41992835bde9ad1d367d67a4a8cd4b5428bd46706c8a2a3c01
thunk_266730:
0x266730: JMP 0x00678ec0
; END FUNCTION thunk_266730
0x266735: INT3 ; original byte CC, padding
0x266736: INT3 ; original byte CC, padding
0x266737: INT3 ; original byte CC, padding

; FUNCTION thunk_266738 [0x266738, 0x26673c] | file +0x798 | ev_aa0a18be2618fe163ef3124d4793e4ee4faac93cc616ec748a395327ab897d78
thunk_266738:
0x266738: JMP 0x00678f60
; END FUNCTION thunk_266738
0x26673d: INT3 ; original byte CC, padding
0x26673e: INT3 ; original byte CC, padding
0x26673f: INT3 ; original byte CC, padding

; FUNCTION thunk_266740 [0x266740, 0x266744] | file +0x7a0 | ev_b940e85d2293130cc12912d0f406f051de5e7b6c738a54b3296b9ad18e7da334
thunk_266740:
0x266740: JMP 0x00679190
; END FUNCTION thunk_266740
0x266745: INT3 ; original byte CC, padding
0x266746: INT3 ; original byte CC, padding
0x266747: INT3 ; original byte CC, padding

; FUNCTION thunk_266748 [0x266748, 0x26674c] | file +0x7a8 | ev_2d90ddd75a522af0bb29971ceb6fb5ba61df5fe33fe120ca3b3e5d7785d2fb67
thunk_266748:
0x266748: JMP 0x00679360
; END FUNCTION thunk_266748
0x26674d: INT3 ; original byte CC, padding
0x26674e: INT3 ; original byte CC, padding
0x26674f: INT3 ; original byte CC, padding

; FUNCTION thunk_266750 [0x266750, 0x266754] | file +0x7b0 | ev_01b9ec000cc30925ba3559e6be67c9cb23e822ed3521b44b10cf40b142115d81
thunk_266750:
0x266750: JMP 0x00679680
; END FUNCTION thunk_266750
0x266755: INT3 ; original byte CC, padding
0x266756: INT3 ; original byte CC, padding
0x266757: INT3 ; original byte CC, padding

; FUNCTION thunk_266758 [0x266758, 0x26675c] | file +0x7b8 | ev_d990bd8c7113bb7f5350f7d2dd0da9a70e1e61ae3bdc2023b324d40d54fd0556
thunk_266758:
0x266758: JMP 0x00033b90
; END FUNCTION thunk_266758
0x26675d: INT3 ; original byte CC, padding
0x26675e: INT3 ; original byte CC, padding
0x26675f: INT3 ; original byte CC, padding

; FUNCTION thunk_266760 [0x266760, 0x266764] | file +0x7c0 | ev_9c2f05162ca519881e4051f776fb4d5698dc9a1dbb6d322ee6281af4ba5e8feb
thunk_266760:
0x266760: JMP 0x00033ca0
; END FUNCTION thunk_266760
0x266765: INT3 ; original byte CC, padding
0x266766: INT3 ; original byte CC, padding
0x266767: INT3 ; original byte CC, padding

; FUNCTION thunk_266768 [0x266768, 0x26676c] | file +0x7c8 | ev_8a1b5cf7031b91c6ae6c5ebe0fffd22f6fa2246fe2869a1a78fd5b400a6b359e
thunk_266768:
0x266768: JMP 0x00033d20
; END FUNCTION thunk_266768
0x26676d: INT3 ; original byte CC, padding
0x26676e: INT3 ; original byte CC, padding
0x26676f: INT3 ; original byte CC, padding

; FUNCTION thunk_266770 [0x266770, 0x266774] | file +0x7d0 | ev_1f25b3b15b6f767ce17fc6cd00f20709a3a70504cb1eab6250b3a9d8f5df543a
thunk_266770:
0x266770: JMP 0x0003cf70
; END FUNCTION thunk_266770
0x266775: INT3 ; original byte CC, padding
0x266776: INT3 ; original byte CC, padding
0x266777: INT3 ; original byte CC, padding

; FUNCTION thunk_266778 [0x266778, 0x26677c] | file +0x7d8 | ev_1abd2480771bd0dfc44ad78a0ad8b9e76496fd5a3103f04dbfb5001838054042
thunk_266778:
0x266778: JMP 0x0003d0e0
; END FUNCTION thunk_266778
0x26677d: INT3 ; original byte CC, padding
0x26677e: INT3 ; original byte CC, padding
0x26677f: INT3 ; original byte CC, padding

; FUNCTION thunk_266780 [0x266780, 0x266784] | file +0x7e0 | ev_c505cc9a86f7ae4149f1e64b36bc59f5f40aa963623ba2974583c5d3e37dcf6c
thunk_266780:
0x266780: JMP 0x0003d660
; END FUNCTION thunk_266780
0x266785: INT3 ; original byte CC, padding
0x266786: INT3 ; original byte CC, padding
0x266787: INT3 ; original byte CC, padding

; FUNCTION thunk_266788 [0x266788, 0x26678c] | file +0x7e8 | ev_9ed81726a9363e9abf06ebf384044590c774b49373b1aff9cce434caec79de73
thunk_266788:
0x266788: JMP 0x0003e100
; END FUNCTION thunk_266788
0x26678d: INT3 ; original byte CC, padding
0x26678e: INT3 ; original byte CC, padding
0x26678f: INT3 ; original byte CC, padding

; FUNCTION thunk_266790 [0x266790, 0x266794] | file +0x7f0 | ev_b6d70feab26a69b46d1e60bf65b7ac8ff9e8af0f14e58083f5ca2104e00b4a77
thunk_266790:
0x266790: JMP 0x0003e160
; END FUNCTION thunk_266790
0x266795: INT3 ; original byte CC, padding
0x266796: INT3 ; original byte CC, padding
0x266797: INT3 ; original byte CC, padding

; FUNCTION thunk_266798 [0x266798, 0x26679c] | file +0x7f8 | ev_3a4fe1aed4181c9b36fc2d107277e19a007843c58dbc34a1b90c6b5364c25a1f
thunk_266798:
0x266798: JMP 0x0003e1c0
; END FUNCTION thunk_266798
0x26679d: INT3 ; original byte CC, padding
0x26679e: INT3 ; original byte CC, padding
0x26679f: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a0 [0x2667a0, 0x2667a4] | file +0x800 | ev_4e9ef9ebcbe1c81642627453beab0cf815cbe6b323c761944902a2e3a594e35e
thunk_2667a0:
0x2667a0: JMP 0x0003f070
; END FUNCTION thunk_2667a0
0x2667a5: INT3 ; original byte CC, padding
0x2667a6: INT3 ; original byte CC, padding
0x2667a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a8 [0x2667a8, 0x2667ac] | file +0x808 | ev_1e8d18696b5a66f44717599dfe66fa3f5647bfd731e90f4213ba0fb583230b36
thunk_2667a8:
0x2667a8: JMP 0x0003f0d0
; END FUNCTION thunk_2667a8
0x2667ad: INT3 ; original byte CC, padding
0x2667ae: INT3 ; original byte CC, padding
0x2667af: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b0 [0x2667b0, 0x2667b4] | file +0x810 | ev_694c8a603d68e5c334d648ccab1a33dedcffe9fe58ccd66f93a0e0e9f55a0532
thunk_2667b0:
0x2667b0: JMP 0x0003f4b0
; END FUNCTION thunk_2667b0
0x2667b5: INT3 ; original byte CC, padding
0x2667b6: INT3 ; original byte CC, padding
0x2667b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b8 [0x2667b8, 0x2667bc] | file +0x818 | ev_a433f0ca544c9e14c9ccf44b4ee4f0234100e7f292134e31ff932a3f92aa68ce
thunk_2667b8:
0x2667b8: JMP 0x0003f510
; END FUNCTION thunk_2667b8
0x2667bd: INT3 ; original byte CC, padding
0x2667be: INT3 ; original byte CC, padding
0x2667bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c0 [0x2667c0, 0x2667c4] | file +0x820 | ev_bea5624da2f134f28923630943d28c30f396fee0e2b4c2add7748798a411e200
thunk_2667c0:
0x2667c0: JMP 0x0003f570
; END FUNCTION thunk_2667c0
0x2667c5: INT3 ; original byte CC, padding
0x2667c6: INT3 ; original byte CC, padding
0x2667c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c8 [0x2667c8, 0x2667cc] | file +0x828 | ev_873e539dd587ac5fcd71faab8b5f3475b0c0c95679ce352316e553e65785df80
thunk_2667c8:
0x2667c8: JMP 0x0003fbb0
; END FUNCTION thunk_2667c8
0x2667cd: INT3 ; original byte CC, padding
0x2667ce: INT3 ; original byte CC, padding
0x2667cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d0 [0x2667d0, 0x2667d4] | file +0x830 | ev_d081b0d8d4dc0ccacf69699e5595f0544f500d0276055e7bf09413150e1224dd
thunk_2667d0:
0x2667d0: JMP 0x0003ffc0
; END FUNCTION thunk_2667d0
0x2667d5: INT3 ; original byte CC, padding
0x2667d6: INT3 ; original byte CC, padding
0x2667d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d8 [0x2667d8, 0x2667dc] | file +0x838 | ev_96e92b8e3e99b79413f154cc9eb3d60a8a7d646aa4515fb8fb5de63dd6d7c917
thunk_2667d8:
0x2667d8: JMP 0x00040960
; END FUNCTION thunk_2667d8
0x2667dd: INT3 ; original byte CC, padding
0x2667de: INT3 ; original byte CC, padding
0x2667df: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e0 [0x2667e0, 0x2667e4] | file +0x840 | ev_a1b1802795532978974ffc776896ea0d7761845d22797ef90473038e62d47faa
thunk_2667e0:
0x2667e0: JMP 0x00040b50
; END FUNCTION thunk_2667e0
0x2667e5: INT3 ; original byte CC, padding
0x2667e6: INT3 ; original byte CC, padding
0x2667e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e8 [0x2667e8, 0x2667ec] | file +0x848 | ev_83007fa2af45028f40282ddb2608364e94f80e2ce94687cd3f80e2b37d9e04ae
thunk_2667e8:
0x2667e8: JMP 0x00040c30
; END FUNCTION thunk_2667e8
0x2667ed: INT3 ; original byte CC, padding
0x2667ee: INT3 ; original byte CC, padding
0x2667ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f0 [0x2667f0, 0x2667f4] | file +0x850 | ev_2caf01d6b7d2a840a5c899ea1ade478a1167a6d2432c06185f6657a466a24521
thunk_2667f0:
0x2667f0: JMP 0x00041630
; END FUNCTION thunk_2667f0
0x2667f5: INT3 ; original byte CC, padding
0x2667f6: INT3 ; original byte CC, padding
0x2667f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f8 [0x2667f8, 0x2667fc] | file +0x858 | ev_2e9a02026a32f4d3595a1c8ea3741317c463c48293ad9967d64bb0c842c16bcf
thunk_2667f8:
0x2667f8: JMP 0x00041750
; END FUNCTION thunk_2667f8
0x2667fd: INT3 ; original byte CC, padding
0x2667fe: INT3 ; original byte CC, padding
0x2667ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266800 [0x266800, 0x266804] | file +0x860 | ev_b5a4bcb1d6c941a3f6d70e0062d3c0463382b61c6d39e75f8ad4575154058329
thunk_266800:
0x266800: JMP 0x00041830
; END FUNCTION thunk_266800
0x266805: INT3 ; original byte CC, padding
0x266806: INT3 ; original byte CC, padding
0x266807: INT3 ; original byte CC, padding

; FUNCTION thunk_266808 [0x266808, 0x26680c] | file +0x868 | ev_f1b081b3b9ac7495b8be40ee086537bb185a297b65b7ef087083c600fbb85b61
thunk_266808:
0x266808: JMP 0x000418c0
; END FUNCTION thunk_266808
0x26680d: INT3 ; original byte CC, padding
0x26680e: INT3 ; original byte CC, padding
0x26680f: INT3 ; original byte CC, padding

; FUNCTION thunk_266810 [0x266810, 0x266814] | file +0x870 | ev_286fd1ef6a141f6a83604ef9198646a69f86d2b579ec17a23ae6cebb467e5061
thunk_266810:
0x266810: JMP 0x00042060
; END FUNCTION thunk_266810
0x266815: INT3 ; original byte CC, padding
0x266816: INT3 ; original byte CC, padding
0x266817: INT3 ; original byte CC, padding

; FUNCTION thunk_266818 [0x266818, 0x26681c] | file +0x878 | ev_47935a2775d41df4f9b4c5a7174f7ec66edf37c497c637165652e966d455c6c2
thunk_266818:
0x266818: JMP 0x000424d0
; END FUNCTION thunk_266818
0x26681d: INT3 ; original byte CC, padding
0x26681e: INT3 ; original byte CC, padding
0x26681f: INT3 ; original byte CC, padding

; FUNCTION thunk_266820 [0x266820, 0x266824] | file +0x880 | ev_ec6ae96b47da7790af52eef03b6d449d9601b42b60ff5781510b83d5eed62146
thunk_266820:
0x266820: JMP 0x000425a0
; END FUNCTION thunk_266820
0x266825: INT3 ; original byte CC, padding
0x266826: INT3 ; original byte CC, padding
0x266827: INT3 ; original byte CC, padding

; FUNCTION thunk_266828 [0x266828, 0x26682c] | file +0x888 | ev_62e5f7ba42bcfbb4e746143fb9a9e26ec7bd4a12c0fbf516331bb1dba6d35663
thunk_266828:
0x266828: JMP 0x00042600
; END FUNCTION thunk_266828
0x26682d: INT3 ; original byte CC, padding
0x26682e: INT3 ; original byte CC, padding
0x26682f: INT3 ; original byte CC, padding

; FUNCTION thunk_266830 [0x266830, 0x266834] | file +0x890 | ev_5adad97b5e16134fb3c507782f4939f93bf7446e42819870836ccff91d30b7eb
thunk_266830:
0x266830: JMP 0x00690030
; END FUNCTION thunk_266830
0x266835: INT3 ; original byte CC, padding
0x266836: INT3 ; original byte CC, padding
0x266837: INT3 ; original byte CC, padding

; FUNCTION thunk_266838 [0x266838, 0x26683c] | file +0x898 | ev_816d78169618a36f8b32f4a02e164b67743d4a889459642185f582989c4af5e2
thunk_266838:
0x266838: JMP 0x00696cc0
; END FUNCTION thunk_266838
0x26683d: INT3 ; original byte CC, padding
0x26683e: INT3 ; original byte CC, padding
0x26683f: INT3 ; original byte CC, padding

; FUNCTION thunk_266840 [0x266840, 0x266844] | file +0x8a0 | ev_ac0488f3239f358372c3fe2efa4f19fad41d472d5150f8744654236f12971a58
thunk_266840:
0x266840: JMP 0x006985d0
; END FUNCTION thunk_266840
0x266845: INT3 ; original byte CC, padding
0x266846: INT3 ; original byte CC, padding
0x266847: INT3 ; original byte CC, padding

; FUNCTION thunk_266848 [0x266848, 0x26684c] | file +0x8a8 | ev_93973c149c06bf5ab4e689d9c5e3a621a45fdb016a490bd5f873537571699dde
thunk_266848:
0x266848: JMP 0x006a2050
; END FUNCTION thunk_266848
0x26684d: INT3 ; original byte CC, padding
0x26684e: INT3 ; original byte CC, padding
0x26684f: INT3 ; original byte CC, padding

; FUNCTION thunk_266850 [0x266850, 0x266854] | file +0x8b0 | ev_0384ec62f16c1b55f37f6e139cd5b347f936b71ac6d322c07912104d15839704
thunk_266850:
0x266850: JMP 0x006a22b0
; END FUNCTION thunk_266850
0x266855: INT3 ; original byte CC, padding
0x266856: INT3 ; original byte CC, padding
0x266857: INT3 ; original byte CC, padding

; FUNCTION thunk_266858 [0x266858, 0x26685c] | file +0x8b8 | ev_df166f83af68846c8787a22b60db92858c5297f11c0e5021462d71dc3a774fa4
thunk_266858:
0x266858: JMP 0x006ae640
; END FUNCTION thunk_266858
0x26685d: INT3 ; original byte CC, padding
0x26685e: INT3 ; original byte CC, padding
0x26685f: INT3 ; original byte CC, padding

; FUNCTION thunk_266860 [0x266860, 0x266864] | file +0x8c0 | ev_0fdd27d74cd24b4f8db75581de4388713e3597d065d3842c8af4f054c455ff46
thunk_266860:
0x266860: JMP 0x006ae7f0
; END FUNCTION thunk_266860
0x266865: INT3 ; original byte CC, padding
0x266866: INT3 ; original byte CC, padding
0x266867: INT3 ; original byte CC, padding

; FUNCTION thunk_266868 [0x266868, 0x26686c] | file +0x8c8 | ev_fc62fcbabf14463ab5445229b64c21674fbb7a0e14b7c8d18f89f180b63d1a35
thunk_266868:
0x266868: JMP 0x001813b0
; END FUNCTION thunk_266868
0x26686d: INT3 ; original byte CC, padding
0x26686e: INT3 ; original byte CC, padding
0x26686f: INT3 ; original byte CC, padding

; FUNCTION thunk_266870 [0x266870, 0x266874] | file +0x8d0 | ev_e2d4aad35945259cea115215ff1ab977a4b05020f234b4e2d5529ecfaf679d6c
thunk_266870:
0x266870: JMP 0x006befa0
; END FUNCTION thunk_266870
0x266875: INT3 ; original byte CC, padding
0x266876: INT3 ; original byte CC, padding
0x266877: INT3 ; original byte CC, padding

; FUNCTION thunk_266878 [0x266878, 0x26687c] | file +0x8d8 | ev_a3fad9735b44d843a7b2df48591f3fdd19bcad9229cd6cc9fa12ae57295fafdb
thunk_266878:
0x266878: JMP 0x00188040
; END FUNCTION thunk_266878
0x26687d: INT3 ; original byte CC, padding
0x26687e: INT3 ; original byte CC, padding
0x26687f: INT3 ; original byte CC, padding

; FUNCTION thunk_266880 [0x266880, 0x266884] | file +0x8e0 | ev_cb5c5a617a74303d22c2870604c190a2c74691cea1254e2590feb42cebc14908
thunk_266880:
0x266880: JMP 0x006d0b00
; END FUNCTION thunk_266880
0x266885: INT3 ; original byte CC, padding
0x266886: INT3 ; original byte CC, padding
0x266887: INT3 ; original byte CC, padding

; FUNCTION thunk_266888 [0x266888, 0x26688c] | file +0x8e8 | ev_0c3c38a29d01d8bdd25da4829b302df5d6745d42fe41808735ca9a72b6b3ecc5
thunk_266888:
0x266888: JMP 0x006d1100
; END FUNCTION thunk_266888
0x26688d: INT3 ; original byte CC, padding
0x26688e: INT3 ; original byte CC, padding
0x26688f: INT3 ; original byte CC, padding

; FUNCTION thunk_266890 [0x266890, 0x266894] | file +0x8f0 | ev_6b973f5fb069a1d3cbe8d7d4aabeb6bcee863c0240424f8a6914cece654d8dc4
thunk_266890:
0x266890: JMP 0x006d1260
; END FUNCTION thunk_266890
0x266895: INT3 ; original byte CC, padding
0x266896: INT3 ; original byte CC, padding
0x266897: INT3 ; original byte CC, padding

; FUNCTION thunk_266898 [0x266898, 0x26689c] | file +0x8f8 | ev_8b28ef61b7456567df4642cc9116b8671bba7aa5b95ff4372db799c6ba25dc2d
thunk_266898:
0x266898: JMP 0x006d13e0
; END FUNCTION thunk_266898
0x26689d: INT3 ; original byte CC, padding
0x26689e: INT3 ; original byte CC, padding
0x26689f: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a0 [0x2668a0, 0x2668a4] | file +0x900 | ev_fa00b3d0152f45a894b8ec075f6bf10efe75850a819b491d29e92959b6b8731f
thunk_2668a0:
0x2668a0: JMP 0x006d1520
; END FUNCTION thunk_2668a0
0x2668a5: INT3 ; original byte CC, padding
0x2668a6: INT3 ; original byte CC, padding
0x2668a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a8 [0x2668a8, 0x2668ac] | file +0x908 | ev_d78f08e03b31ffa2b2efe42a6cfb4536afb928a6c7f119a024a22b05f40899ff
thunk_2668a8:
0x2668a8: JMP 0x006d1640
; END FUNCTION thunk_2668a8
0x2668ad: INT3 ; original byte CC, padding
0x2668ae: INT3 ; original byte CC, padding
0x2668af: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b0 [0x2668b0, 0x2668b4] | file +0x910 | ev_3ed67d6c97c92967a395908a8a040edb330be148f28e2c64059b679195b59eae
thunk_2668b0:
0x2668b0: JMP 0x006d1720
; END FUNCTION thunk_2668b0
0x2668b5: INT3 ; original byte CC, padding
0x2668b6: INT3 ; original byte CC, padding
0x2668b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b8 [0x2668b8, 0x2668bc] | file +0x918 | ev_de93f54afb23cbd9b4b3762b6edbec96ba6addd3a7c90c972215bce85e5605f8
thunk_2668b8:
0x2668b8: JMP 0x006dc660
; END FUNCTION thunk_2668b8
0x2668bd: INT3 ; original byte CC, padding
0x2668be: INT3 ; original byte CC, padding
0x2668bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c0 [0x2668c0, 0x2668c4] | file +0x920 | ev_3e530c546d978a4cde1ea40098241ece409f40b0be36a2293bc70eb3a70892d2
thunk_2668c0:
0x2668c0: JMP 0x006dc690
; END FUNCTION thunk_2668c0
0x2668c5: INT3 ; original byte CC, padding
0x2668c6: INT3 ; original byte CC, padding
0x2668c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c8 [0x2668c8, 0x2668cc] | file +0x928 | ev_4029b49e23f105d9fd959b8d0e79ee611fff70d5deb5b25c1ec32f063cdbf7d2
thunk_2668c8:
0x2668c8: JMP 0x006dc6a0
; END FUNCTION thunk_2668c8
0x2668cd: INT3 ; original byte CC, padding
0x2668ce: INT3 ; original byte CC, padding
0x2668cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d0 [0x2668d0, 0x2668d4] | file +0x930 | ev_28820dcd9e75794b371215f8085c8fc2e919e52036eb5b329b5618bbecaa8502
thunk_2668d0:
0x2668d0: JMP 0x006e0920
; END FUNCTION thunk_2668d0
0x2668d5: INT3 ; original byte CC, padding
0x2668d6: INT3 ; original byte CC, padding
0x2668d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d8 [0x2668d8, 0x2668dc] | file +0x938 | ev_48d27fa99d4bfbfd01b9c0cfc4e1983ac381df090d15929fd844727932ef39f8
thunk_2668d8:
0x2668d8: JMP 0x006e1440
; END FUNCTION thunk_2668d8
0x2668dd: INT3 ; original byte CC, padding
0x2668de: INT3 ; original byte CC, padding
0x2668df: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e0 [0x2668e0, 0x2668e4] | file +0x940 | ev_7aa82add6e61823b6e8626df3d716de65e3fdba037ff334b9a282990cc834fcc
thunk_2668e0:
0x2668e0: JMP 0x006e1450
; END FUNCTION thunk_2668e0
0x2668e5: INT3 ; original byte CC, padding
0x2668e6: INT3 ; original byte CC, padding
0x2668e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e8 [0x2668e8, 0x2668ec] | file +0x948 | ev_7366c86f363f041f011d7a626d3635808a0a7efc1961a826359904110403c080
thunk_2668e8:
0x2668e8: JMP 0x00189a70
; END FUNCTION thunk_2668e8
0x2668ed: INT3 ; original byte CC, padding
0x2668ee: INT3 ; original byte CC, padding
0x2668ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f0 [0x2668f0, 0x2668f4] | file +0x950 | ev_d35c35a0ef27616e2538e5e78e8eb0d78e896dedfca6d619b3ac2c0ce3a0f144
thunk_2668f0:
0x2668f0: JMP 0x00190aa0
; END FUNCTION thunk_2668f0
0x2668f5: INT3 ; original byte CC, padding
0x2668f6: INT3 ; original byte CC, padding
0x2668f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f8 [0x2668f8, 0x2668fc] | file +0x958 | ev_285a07576ea147e47d5a4f684fda3d98049a70bc491220a6859a2ff207cf32a2
thunk_2668f8:
0x2668f8: JMP 0x00702970
; END FUNCTION thunk_2668f8
0x2668fd: INT3 ; original byte CC, padding
0x2668fe: INT3 ; original byte CC, padding
0x2668ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266900 [0x266900, 0x266904] | file +0x960 | ev_79a39a11fc3f4350741dfbe92dbb3ee9d03d1f0038ac550efcf3abe6aa034267
thunk_266900:
0x266900: JMP 0x00702d60
; END FUNCTION thunk_266900
0x266905: INT3 ; original byte CC, padding
0x266906: INT3 ; original byte CC, padding
0x266907: INT3 ; original byte CC, padding

; FUNCTION thunk_266908 [0x266908, 0x26690c] | file +0x968 | ev_c465dba0b2d910dc7e883d6f859825f028af61a03af466d233c429a1c3437066
thunk_266908:
0x266908: JMP 0x00706170
; END FUNCTION thunk_266908
0x26690d: INT3 ; original byte CC, padding
0x26690e: INT3 ; original byte CC, padding
0x26690f: INT3 ; original byte CC, padding

; FUNCTION thunk_266910 [0x266910, 0x266914] | file +0x970 | ev_ef9fedeb9e387dbcb7d3290bec8b7689777232b05d6c3bb1b117ce64c18f2c5d
thunk_266910:
0x266910: JMP 0x007061f0
; END FUNCTION thunk_266910
0x266915: INT3 ; original byte CC, padding
0x266916: INT3 ; original byte CC, padding
0x266917: INT3 ; original byte CC, padding

; FUNCTION thunk_266918 [0x266918, 0x26691c] | file +0x978 | ev_2af3c5ed42b89ca47470939543fcc7eb737ab28171a4cd5c8133946d4bffebc8
thunk_266918:
0x266918: JMP 0x0070ff00
; END FUNCTION thunk_266918
0x26691d: INT3 ; original byte CC, padding
0x26691e: INT3 ; original byte CC, padding
0x26691f: INT3 ; original byte CC, padding

; FUNCTION thunk_266920 [0x266920, 0x266924] | file +0x980 | ev_8ba8242e089252d99a8cc8a7db165be4787cdc73249a67a9d3de406b2f92243b
thunk_266920:
0x266920: JMP 0x0070ffb0
; END FUNCTION thunk_266920
0x266925: INT3 ; original byte CC, padding
0x266926: INT3 ; original byte CC, padding
0x266927: INT3 ; original byte CC, padding

; FUNCTION thunk_266928 [0x266928, 0x26692c] | file +0x988 | ev_bde685656623cf261c8d2a68eb1a624c013d1f1b4b0e9c0e93f302aab6068365
thunk_266928:
0x266928: JMP 0x007101c0
; END FUNCTION thunk_266928
0x26692d: INT3 ; original byte CC, padding
0x26692e: INT3 ; original byte CC, padding
0x26692f: INT3 ; original byte CC, padding

; FUNCTION thunk_266930 [0x266930, 0x266934] | file +0x990 | ev_b7ffb8877836166a4a685c022bc96bc3e0ab506a2439a5c6dee2f66a6ca82322
thunk_266930:
0x266930: JMP 0x00710320
; END FUNCTION thunk_266930
0x266935: INT3 ; original byte CC, padding
0x266936: INT3 ; original byte CC, padding
0x266937: INT3 ; original byte CC, padding

; FUNCTION thunk_266938 [0x266938, 0x26693c] | file +0x998 | ev_7f6f171a1627ab6995130bf2a96eb88ad7d18a6c294863cb2a05e16007aee4b8
thunk_266938:
0x266938: JMP 0x00712bb0
; END FUNCTION thunk_266938
0x26693d: INT3 ; original byte CC, padding
0x26693e: INT3 ; original byte CC, padding
0x26693f: INT3 ; original byte CC, padding

; FUNCTION thunk_266940 [0x266940, 0x266944] | file +0x9a0 | ev_dddfee7d6fc78e04fc2e8b6de476d83bd91928a276a0e49b68df7ca11e341a36
thunk_266940:
0x266940: JMP 0x00716360
; END FUNCTION thunk_266940
0x266945: INT3 ; original byte CC, padding
0x266946: INT3 ; original byte CC, padding
0x266947: INT3 ; original byte CC, padding

; FUNCTION thunk_266948 [0x266948, 0x26694c] | file +0x9a8 | ev_810262db33bcfe19b9125a9a40bfbc0dcf0ca1d8f07ea1083aa8eb64c2683ed7
thunk_266948:
0x266948: JMP 0x0072f970
; END FUNCTION thunk_266948
0x26694d: INT3 ; original byte CC, padding
0x26694e: INT3 ; original byte CC, padding
0x26694f: INT3 ; original byte CC, padding

; FUNCTION thunk_266950 [0x266950, 0x266954] | file +0x9b0 | ev_bb75578d2158f4a93fd8ad186335b68f4e86e611e1046b5612d66d40e6f42c05
thunk_266950:
0x266950: JMP 0x0072f990
; END FUNCTION thunk_266950
0x266955: INT3 ; original byte CC, padding
0x266956: INT3 ; original byte CC, padding
0x266957: INT3 ; original byte CC, padding

; FUNCTION thunk_266958 [0x266958, 0x26695c] | file +0x9b8 | ev_cc7869a755aa94e9948250e267657fb3484ae5d84c3939e93ee81e25a17c6658
thunk_266958:
0x266958: JMP 0x0072fa20
; END FUNCTION thunk_266958
0x26695d: INT3 ; original byte CC, padding
0x26695e: INT3 ; original byte CC, padding
0x26695f: INT3 ; original byte CC, padding

; FUNCTION thunk_266960 [0x266960, 0x266964] | file +0x9c0 | ev_d41be3a77fe7d970714413a2db7362e7378afaf1c234aca1fb495459da2981f4
thunk_266960:
0x266960: JMP 0x00246e30
; END FUNCTION thunk_266960
0x266965: INT3 ; original byte CC, padding
0x266966: INT3 ; original byte CC, padding
0x266967: INT3 ; original byte CC, padding

; FUNCTION thunk_266968 [0x266968, 0x26696c] | file +0x9c8 | ev_86447051030d85af30d27f1ae658d2b53230586b68e795e6877819c143272823
thunk_266968:
0x266968: JMP 0x007647f0
; END FUNCTION thunk_266968
0x26696d: INT3 ; original byte CC, padding
0x26696e: INT3 ; original byte CC, padding
0x26696f: INT3 ; original byte CC, padding

; FUNCTION thunk_266970 [0x266970, 0x266974] | file +0x9d0 | ev_8f35ce01a7e76f246111c0713a73ab48052fb3758ed42ddf08dadd78f3ee8b2e
thunk_266970:
0x266970: JMP 0x00773710
; END FUNCTION thunk_266970
0x266975: INT3 ; original byte CC, padding
0x266976: INT3 ; original byte CC, padding
0x266977: INT3 ; original byte CC, padding

; FUNCTION thunk_266978 [0x266978, 0x26697c] | file +0x9d8 | ev_67777dd4e1619b577951547dcecfe4e41541a70e9352d9f4fd8e4c18c15e790e
thunk_266978:
0x266978: JMP 0x00775950
; END FUNCTION thunk_266978
0x26697d: INT3 ; original byte CC, padding
0x26697e: INT3 ; original byte CC, padding
0x26697f: INT3 ; original byte CC, padding

; FUNCTION thunk_266980 [0x266980, 0x266984] | file +0x9e0 | ev_cc4f8e212f24a3d2a05a7ecfa0364795c5246f50343e1d895d0b927b5e9acbd9
thunk_266980:
0x266980: JMP 0x00799e90
; END FUNCTION thunk_266980
0x266985: INT3 ; original byte CC, padding
0x266986: INT3 ; original byte CC, padding
0x266987: INT3 ; original byte CC, padding

; FUNCTION thunk_266988 [0x266988, 0x26698c] | file +0x9e8 | ev_18e241da46f5f68857625524ec967ff69786cb909ac6fa9f4ea3613ff4a373f6
thunk_266988:
0x266988: JMP 0x007b31f0
; END FUNCTION thunk_266988
0x26698d: INT3 ; original byte CC, padding
0x26698e: INT3 ; original byte CC, padding
0x26698f: INT3 ; original byte CC, padding

; FUNCTION thunk_266990 [0x266990, 0x266994] | file +0x9f0 | ev_146209dccae72ac346c363a14fb22c9ebcf1badb24f205149cd1c2a71f73eb10
thunk_266990:
0x266990: JMP 0x007e23a0
; END FUNCTION thunk_266990
0x266995: INT3 ; original byte CC, padding
0x266996: INT3 ; original byte CC, padding
0x266997: INT3 ; original byte CC, padding

; FUNCTION thunk_266998 [0x266998, 0x26699c] | file +0x9f8 | ev_07c806b885fdfad9a042087c47d941e3e27815570df71456554ae5f777e04f8a
thunk_266998:
0x266998: JMP 0x007e83e0
; END FUNCTION thunk_266998
0x26699d: INT3 ; original byte CC, padding
0x26699e: INT3 ; original byte CC, padding
0x26699f: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a0 [0x2669a0, 0x2669a4] | file +0xa00 | ev_be089efb1d3a783630ff9eb8e152388777867284e2e50833db979df30666a4fd
thunk_2669a0:
0x2669a0: JMP 0x007e8480
; END FUNCTION thunk_2669a0
0x2669a5: INT3 ; original byte CC, padding
0x2669a6: INT3 ; original byte CC, padding
0x2669a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a8 [0x2669a8, 0x2669ac] | file +0xa08 | ev_7a3ddf208002c5329e2906aceffed7dd3678f5bd7961d84302be0c17c52ea09f
thunk_2669a8:
0x2669a8: JMP 0x00c3b1b0
; END FUNCTION thunk_2669a8
0x2669ad: INT3 ; original byte CC, padding
0x2669ae: INT3 ; original byte CC, padding
0x2669af: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b0 [0x2669b0, 0x2669b4] | file +0xa10 | ev_bdb5f83bfc4dba4e75e19a3eef1d072394dabaa2ee2f9f656e038f3f43a9e595
thunk_2669b0:
0x2669b0: JMP 0x00c3c6e0
; END FUNCTION thunk_2669b0
0x2669b5: INT3 ; original byte CC, padding
0x2669b6: INT3 ; original byte CC, padding
0x2669b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b8 [0x2669b8, 0x2669bc] | file +0xa18 | ev_646a44996bac41d97d6bd466d9d89c6be5622fab00f3833056200cf520b54fe4
thunk_2669b8:
0x2669b8: JMP 0x00c3c690
; END FUNCTION thunk_2669b8
0x2669bd: INT3 ; original byte CC, padding
0x2669be: INT3 ; original byte CC, padding
0x2669bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c0 [0x2669c0, 0x2669c4] | file +0xa20 | ev_4362cb7f40b9eb146fac45118d165bc73bbc51e4d24d0134492add8ca5631b95
thunk_2669c0:
0x2669c0: JMP 0x00c3c730
; END FUNCTION thunk_2669c0
0x2669c5: INT3 ; original byte CC, padding
0x2669c6: INT3 ; original byte CC, padding
0x2669c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c8 [0x2669c8, 0x2669cc] | file +0xa28 | ev_a2defbb92015ed92c0ef482352ca69c0fb501a1cbddcc98ea3de49ae7ad35628
thunk_2669c8:
0x2669c8: JMP 0x00802220
; END FUNCTION thunk_2669c8
0x2669cd: INT3 ; original byte CC, padding
0x2669ce: INT3 ; original byte CC, padding
0x2669cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d0 [0x2669d0, 0x2669d4] | file +0xa30 | ev_8b0d6c0754c0b3b0f5920be4785507c6b59ae0d16e34c3c88580ef5102aa7c09
thunk_2669d0:
0x2669d0: JMP 0x008024f0
; END FUNCTION thunk_2669d0
0x2669d5: INT3 ; original byte CC, padding
0x2669d6: INT3 ; original byte CC, padding
0x2669d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d8 [0x2669d8, 0x2669dc] | file +0xa38 | ev_ad2127f94361c94e9ea3ce28f07b62b5f86902733f265d7410b1b50d7c2dcf34
thunk_2669d8:
0x2669d8: JMP 0x0080c570
; END FUNCTION thunk_2669d8
0x2669dd: INT3 ; original byte CC, padding
0x2669de: INT3 ; original byte CC, padding
0x2669df: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e0 [0x2669e0, 0x2669e4] | file +0xa40 | ev_107ae0a63c11b3b92fc64c7be5323a3eb435cad4abf4cfab408f51f081534354
thunk_2669e0:
0x2669e0: JMP 0x0082b300
; END FUNCTION thunk_2669e0
0x2669e5: INT3 ; original byte CC, padding
0x2669e6: INT3 ; original byte CC, padding
0x2669e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e8 [0x2669e8, 0x2669ec] | file +0xa48 | ev_9ad5a3b6afeb0b6f0b925f04a856e87601c2bf950f8d2fb50a65e0136f58057a
thunk_2669e8:
0x2669e8: JMP 0x00920ee0
; END FUNCTION thunk_2669e8
0x2669ed: INT3 ; original byte CC, padding
0x2669ee: INT3 ; original byte CC, padding
0x2669ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f0 [0x2669f0, 0x2669f4] | file +0xa50 | ev_a480cb6ab7d531f1320cc8242e87145c1c91b7d7a84222faf523f1c010f50494
thunk_2669f0:
0x2669f0: JMP 0x00920b90
; END FUNCTION thunk_2669f0
0x2669f5: INT3 ; original byte CC, padding
0x2669f6: INT3 ; original byte CC, padding
0x2669f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f8 [0x2669f8, 0x2669fc] | file +0xa58 | ev_063eb2665a5427fcd2306892c374cdbc281c7ad6593802712bc6c4b1efb017b7
thunk_2669f8:
0x2669f8: JMP 0x00830810
; END FUNCTION thunk_2669f8
0x2669fd: INT3 ; original byte CC, padding
0x2669fe: INT3 ; original byte CC, padding
0x2669ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266a00 [0x266a00, 0x266a04] | file +0xa60 | ev_29198ce2df122b645034527b9bb21acb52264c59b9daf0884f26625cd53e0086
thunk_266a00:
0x266a00: JMP 0x00830f00
; END FUNCTION thunk_266a00
0x266a05: INT3 ; original byte CC, padding
0x266a06: INT3 ; original byte CC, padding
0x266a07: INT3 ; original byte CC, padding

; FUNCTION thunk_266a08 [0x266a08, 0x266a0c] | file +0xa68 | ev_177dd7dc7b53ab81c2013acc266639880dbc8de7da863168a12b7fafb05569d0
thunk_266a08:
0x266a08: JMP 0x008352b0
; END FUNCTION thunk_266a08
0x266a0d: INT3 ; original byte CC, padding
0x266a0e: INT3 ; original byte CC, padding
0x266a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a10 [0x266a10, 0x266a14] | file +0xa70 | ev_0d5315ab6a16e41f21449cd36ebc5a3310ea3b201b5c2822cc1967b87fc5175d
thunk_266a10:
0x266a10: JMP 0x008352c0
; END FUNCTION thunk_266a10
0x266a15: INT3 ; original byte CC, padding
0x266a16: INT3 ; original byte CC, padding
0x266a17: INT3 ; original byte CC, padding

; FUNCTION thunk_266a18 [0x266a18, 0x266a1c] | file +0xa78 | ev_ec8c18935f45a48774dc5e604617b4fa54ed540c1146049e3259786a4611c0fe
thunk_266a18:
0x266a18: JMP 0x008352d0
; END FUNCTION thunk_266a18
0x266a1d: INT3 ; original byte CC, padding
0x266a1e: INT3 ; original byte CC, padding
0x266a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a20 [0x266a20, 0x266a24] | file +0xa80 | ev_67ccf19ae6261c26c1b465c290344d75286d87b8463b67ce27a2a00d373f25e1
thunk_266a20:
0x266a20: JMP 0x008352f0
; END FUNCTION thunk_266a20
0x266a25: INT3 ; original byte CC, padding
0x266a26: INT3 ; original byte CC, padding
0x266a27: INT3 ; original byte CC, padding

; FUNCTION thunk_266a28 [0x266a28, 0x266a2c] | file +0xa88 | ev_0fc4c28b309099d4fef2aa0441aada55fdb833e87dd6e611d54d6ce100ee2603
thunk_266a28:
0x266a28: JMP 0x00835440
; END FUNCTION thunk_266a28
0x266a2d: INT3 ; original byte CC, padding
0x266a2e: INT3 ; original byte CC, padding
0x266a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a30 [0x266a30, 0x266a34] | file +0xa90 | ev_b30b9cb2f6b10209ccef36a80c6226dec9100c5cdf04f409483c5df6c8d721cb
thunk_266a30:
0x266a30: JMP 0x00835450
; END FUNCTION thunk_266a30
0x266a35: INT3 ; original byte CC, padding
0x266a36: INT3 ; original byte CC, padding
0x266a37: INT3 ; original byte CC, padding

; FUNCTION thunk_266a38 [0x266a38, 0x266a3c] | file +0xa98 | ev_1c89747d1cc419c82f65552dd5e9f398d08b9dd3c158550837d6d077fe5f1f9a
thunk_266a38:
0x266a38: JMP 0x00835490
; END FUNCTION thunk_266a38
0x266a3d: INT3 ; original byte CC, padding
0x266a3e: INT3 ; original byte CC, padding
0x266a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a40 [0x266a40, 0x266a44] | file +0xaa0 | ev_86c79d8831758bb566d4330365abf0f4f2fdd5f6cecd088a67fe9b63cbdb7eb7
thunk_266a40:
0x266a40: JMP 0x00835ad0
; END FUNCTION thunk_266a40
0x266a45: INT3 ; original byte CC, padding
0x266a46: INT3 ; original byte CC, padding
0x266a47: INT3 ; original byte CC, padding

; FUNCTION thunk_266a48 [0x266a48, 0x266a4c] | file +0xaa8 | ev_995c50dcb18c9069c8f14612d6a1455003ea69b54876567c1e823ec636e9aa48
thunk_266a48:
0x266a48: JMP 0x00850870
; END FUNCTION thunk_266a48
0x266a4d: INT3 ; original byte CC, padding
0x266a4e: INT3 ; original byte CC, padding
0x266a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a50 [0x266a50, 0x266a54] | file +0xab0 | ev_5e329a7f38c7891bcb76d5475bccd7ac8a8253c93b2384eb3199eed3c1d6eb2c
thunk_266a50:
0x266a50: JMP 0x008702f0
; END FUNCTION thunk_266a50
0x266a55: INT3 ; original byte CC, padding
0x266a56: INT3 ; original byte CC, padding
0x266a57: INT3 ; original byte CC, padding

; FUNCTION thunk_266a58 [0x266a58, 0x266a5c] | file +0xab8 | ev_e0a5532f5aff1a4a2ee764559daee4f819665087f4630c432530d3cf5486f063
thunk_266a58:
0x266a58: JMP 0x008705d0
; END FUNCTION thunk_266a58
0x266a5d: INT3 ; original byte CC, padding
0x266a5e: INT3 ; original byte CC, padding
0x266a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a60 [0x266a60, 0x266a64] | file +0xac0 | ev_80548a6b40dfc2aeef643069f1ecbfbcaa660deb693d6dfc073b9d3e218c7cb8
thunk_266a60:
0x266a60: JMP 0x00872af0
; END FUNCTION thunk_266a60
0x266a65: INT3 ; original byte CC, padding
0x266a66: INT3 ; original byte CC, padding
0x266a67: INT3 ; original byte CC, padding

; FUNCTION thunk_266a68 [0x266a68, 0x266a6c] | file +0xac8 | ev_8a91bd014432af5bccf4cd9785804c8daa7551ec5454259f0d263e139613a20a
thunk_266a68:
0x266a68: JMP 0x00873800
; END FUNCTION thunk_266a68
0x266a6d: INT3 ; original byte CC, padding
0x266a6e: INT3 ; original byte CC, padding
0x266a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a70 [0x266a70, 0x266a74] | file +0xad0 | ev_ace7e386aef97a8938bc5277da2304ae349721e0be6629dfaab82c91e9879fe3
thunk_266a70:
0x266a70: JMP 0x00063a40
; END FUNCTION thunk_266a70
0x266a75: INT3 ; original byte CC, padding
0x266a76: INT3 ; original byte CC, padding
0x266a77: INT3 ; original byte CC, padding

; FUNCTION thunk_266a78 [0x266a78, 0x266a7c] | file +0xad8 | ev_4f9cbc3755ffa00d9bc90c78dd059443d243871133d78ad726b0b8a1fa8c59f1
thunk_266a78:
0x266a78: JMP 0x00066370
; END FUNCTION thunk_266a78
0x266a7d: INT3 ; original byte CC, padding
0x266a7e: INT3 ; original byte CC, padding
0x266a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a80 [0x266a80, 0x266a84] | file +0xae0 | ev_d1253b2b6a410cdb32f733044e199ff7bc1b88e3fa164e1a9321bfe29d2701a4
thunk_266a80:
0x266a80: JMP 0x000e6590
; END FUNCTION thunk_266a80
0x266a85: INT3 ; original byte CC, padding
0x266a86: INT3 ; original byte CC, padding
0x266a87: INT3 ; original byte CC, padding

; FUNCTION thunk_266a88 [0x266a88, 0x266a8c] | file +0xae8 | ev_a70131a343e30187fec4ee4ddd3e10432a8d5db8f7b758eaf398ef0ff9545c41
thunk_266a88:
0x266a88: JMP 0x000e65a0
; END FUNCTION thunk_266a88
0x266a8d: INT3 ; original byte CC, padding
0x266a8e: INT3 ; original byte CC, padding
0x266a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a90 [0x266a90, 0x266a94] | file +0xaf0 | ev_580401ac889df9a5a5a73e71f8edea677b42be167a238dc2dff457a9c9f336ff
thunk_266a90:
0x266a90: JMP 0x000e6760
; END FUNCTION thunk_266a90
0x266a95: INT3 ; original byte CC, padding
0x266a96: INT3 ; original byte CC, padding
0x266a97: INT3 ; original byte CC, padding

; FUNCTION thunk_266a98 [0x266a98, 0x266a9c] | file +0xaf8 | ev_172618d9f6bde68af37706eabeedff3f52d26fe1bfb0328d5fe417c3de8cfab0
thunk_266a98:
0x266a98: JMP 0x000e6870
; END FUNCTION thunk_266a98
0x266a9d: INT3 ; original byte CC, padding
0x266a9e: INT3 ; original byte CC, padding
0x266a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa0 [0x266aa0, 0x266aa4] | file +0xb00 | ev_b1e956b19177c725cc5b0de3abaf0d87a3b82bb14d6e9f4ec8831e2d91b54c47
thunk_266aa0:
0x266aa0: JMP 0x000e7f90
; END FUNCTION thunk_266aa0
0x266aa5: INT3 ; original byte CC, padding
0x266aa6: INT3 ; original byte CC, padding
0x266aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa8 [0x266aa8, 0x266aac] | file +0xb08 | ev_cb2f12ba0838083ded8dec004c46678be74c9abcc86c76566af579016dba3da5
thunk_266aa8:
0x266aa8: JMP 0x000e9fa0
; END FUNCTION thunk_266aa8
0x266aad: INT3 ; original byte CC, padding
0x266aae: INT3 ; original byte CC, padding
0x266aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab0 [0x266ab0, 0x266ab4] | file +0xb10 | ev_a3052214a521cc3208409e021fa100a76d9261caf5a168a1b72d321750d2b45b
thunk_266ab0:
0x266ab0: JMP 0x000ea670
; END FUNCTION thunk_266ab0
0x266ab5: INT3 ; original byte CC, padding
0x266ab6: INT3 ; original byte CC, padding
0x266ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab8 [0x266ab8, 0x266abc] | file +0xb18 | ev_ab5d43e0a40ba98e026fe8788b90cb6bded3dbb9083f30de951f5b55b6611259
thunk_266ab8:
0x266ab8: JMP 0x000ea760
; END FUNCTION thunk_266ab8
0x266abd: INT3 ; original byte CC, padding
0x266abe: INT3 ; original byte CC, padding
0x266abf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac0 [0x266ac0, 0x266ac4] | file +0xb20 | ev_dfd025dd38eb834c1c4d4e37cf5c20a054f6b368c99fd5c1fcf91a2b04bdb89b
thunk_266ac0:
0x266ac0: JMP 0x000eb0a0
; END FUNCTION thunk_266ac0
0x266ac5: INT3 ; original byte CC, padding
0x266ac6: INT3 ; original byte CC, padding
0x266ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac8 [0x266ac8, 0x266acc] | file +0xb28 | ev_0ba290f61e689c4ddfbc0e9dcd74c90382de6a3844dbe481dd4b5f0c00a605c2
thunk_266ac8:
0x266ac8: JMP 0x000eb190
; END FUNCTION thunk_266ac8
0x266acd: INT3 ; original byte CC, padding
0x266ace: INT3 ; original byte CC, padding
0x266acf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad0 [0x266ad0, 0x266ad4] | file +0xb30 | ev_c7f735b31597949f8b3d8f12d6282e1f65af64f8d580a8b0a79e0b9dc7e33794
thunk_266ad0:
0x266ad0: JMP 0x000ed000
; END FUNCTION thunk_266ad0
0x266ad5: INT3 ; original byte CC, padding
0x266ad6: INT3 ; original byte CC, padding
0x266ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad8 [0x266ad8, 0x266adc] | file +0xb38 | ev_3696ca577c07d3cd8b4dd4f5e7485fc4ccec33eea40a7e33578374e1d59a95f4
thunk_266ad8:
0x266ad8: JMP 0x000ed110
; END FUNCTION thunk_266ad8
0x266add: INT3 ; original byte CC, padding
0x266ade: INT3 ; original byte CC, padding
0x266adf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae0 [0x266ae0, 0x266ae4] | file +0xb40 | ev_3540435ffca26bbb8b563d995bb2524984e42644dbbb93606680668159825e87
thunk_266ae0:
0x266ae0: JMP 0x0088a8a0
; END FUNCTION thunk_266ae0
0x266ae5: INT3 ; original byte CC, padding
0x266ae6: INT3 ; original byte CC, padding
0x266ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae8 [0x266ae8, 0x266aec] | file +0xb48 | ev_54ff9ea03fe46568160ea2de9f8a562e1d312294a5ade2a6b4bdcdada49b1f8c
thunk_266ae8:
0x266ae8: JMP 0x0089cdf0
; END FUNCTION thunk_266ae8
0x266aed: INT3 ; original byte CC, padding
0x266aee: INT3 ; original byte CC, padding
0x266aef: INT3 ; original byte CC, padding

; FUNCTION thunk_266af0 [0x266af0, 0x266af4] | file +0xb50 | ev_e99f643f0db2c0d24db4fcaf3b5de144991b1adc450c03f6d71331e88d5c9524
thunk_266af0:
0x266af0: JMP 0x000eeb50
; END FUNCTION thunk_266af0
0x266af5: INT3 ; original byte CC, padding
0x266af6: INT3 ; original byte CC, padding
0x266af7: INT3 ; original byte CC, padding

; FUNCTION thunk_266af8 [0x266af8, 0x266afc] | file +0xb58 | ev_7e7fe8b4dde4de2281a4f4bd9bdf5add95be25e22ea62e2e3998fb3936a080ff
thunk_266af8:
0x266af8: JMP 0x008cb250
; END FUNCTION thunk_266af8
0x266afd: INT3 ; original byte CC, padding
0x266afe: INT3 ; original byte CC, padding
0x266aff: INT3 ; original byte CC, padding

; FUNCTION thunk_266b00 [0x266b00, 0x266b04] | file +0xb60 | ev_253a16e4058f7de88d51b504ce6a1bacc5be58252642dbbbeee6505711d0648a
thunk_266b00:
0x266b00: JMP 0x008cb390
; END FUNCTION thunk_266b00
0x266b05: INT3 ; original byte CC, padding
0x266b06: INT3 ; original byte CC, padding
0x266b07: INT3 ; original byte CC, padding

; FUNCTION thunk_266b08 [0x266b08, 0x266b0c] | file +0xb68 | ev_fea9d8ff31d0c4fdadf83b22e249aee209225d68e062e0fa46b431c0c49c6dd8
thunk_266b08:
0x266b08: JMP 0x008d2f60
; END FUNCTION thunk_266b08
0x266b0d: INT3 ; original byte CC, padding
0x266b0e: INT3 ; original byte CC, padding
0x266b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b10 [0x266b10, 0x266b14] | file +0xb70 | ev_135119e632a722801f99ad8c2796d9c5d57282defcf1d58fc48cdc7c8e74cb29
thunk_266b10:
0x266b10: JMP 0x008d2f90
; END FUNCTION thunk_266b10
0x266b15: INT3 ; original byte CC, padding
0x266b16: INT3 ; original byte CC, padding
0x266b17: INT3 ; original byte CC, padding

; FUNCTION thunk_266b18 [0x266b18, 0x266b1c] | file +0xb78 | ev_1c2fdbeb60f49688af5703a743188a25b5530b226b89c34973c7416c1b14c502
thunk_266b18:
0x266b18: JMP 0x008d8230
; END FUNCTION thunk_266b18
0x266b1d: INT3 ; original byte CC, padding
0x266b1e: INT3 ; original byte CC, padding
0x266b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b20 [0x266b20, 0x266b24] | file +0xb80 | ev_05e0040e1f1449251377c771031f3d1467b9cea3be2dbb969252562a3d9c6a4b
thunk_266b20:
0x266b20: JMP 0x008d8de0
; END FUNCTION thunk_266b20
0x266b25: INT3 ; original byte CC, padding
0x266b26: INT3 ; original byte CC, padding
0x266b27: INT3 ; original byte CC, padding

; FUNCTION thunk_266b28 [0x266b28, 0x266b2c] | file +0xb88 | ev_3d84d0e832dea1f4393c51cf621401b1efd43c186c59c97d0e1290835b35a0cb
thunk_266b28:
0x266b28: JMP 0x008d97b0
; END FUNCTION thunk_266b28
0x266b2d: INT3 ; original byte CC, padding
0x266b2e: INT3 ; original byte CC, padding
0x266b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b30 [0x266b30, 0x266b34] | file +0xb90 | ev_867be95cdeb3d9b186a680fcb42dc2eef398f6ee5999819b185940e385522a2c
thunk_266b30:
0x266b30: JMP 0x008d9910
; END FUNCTION thunk_266b30
0x266b35: INT3 ; original byte CC, padding
0x266b36: INT3 ; original byte CC, padding
0x266b37: INT3 ; original byte CC, padding

; FUNCTION thunk_266b38 [0x266b38, 0x266b3c] | file +0xb98 | ev_98a6115dac41b7f98acf672e285af4338aa06739dcba52f9d8b424b8b65ba3c3
thunk_266b38:
0x266b38: JMP 0x008da4c0
; END FUNCTION thunk_266b38
0x266b3d: INT3 ; original byte CC, padding
0x266b3e: INT3 ; original byte CC, padding
0x266b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b40 [0x266b40, 0x266b44] | file +0xba0 | ev_28661288bbd93c64c4601ab505454f1242fe1271953adf1d17cfaa755a4dffd0
thunk_266b40:
0x266b40: JMP 0x008da570
; END FUNCTION thunk_266b40
0x266b45: INT3 ; original byte CC, padding
0x266b46: INT3 ; original byte CC, padding
0x266b47: INT3 ; original byte CC, padding

; FUNCTION thunk_266b48 [0x266b48, 0x266b4c] | file +0xba8 | ev_bd344f0bd9ec7d067a0cb4c8208d913f749af95b11793f5da2827e74faf79109
thunk_266b48:
0x266b48: JMP 0x008da5b0
; END FUNCTION thunk_266b48
0x266b4d: INT3 ; original byte CC, padding
0x266b4e: INT3 ; original byte CC, padding
0x266b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b50 [0x266b50, 0x266b54] | file +0xbb0 | ev_f8a42572829c10ec77ab49408e31d2ffb005a17eb5e53f6695770add06be8082
thunk_266b50:
0x266b50: JMP 0x00904c80
; END FUNCTION thunk_266b50
0x266b55: INT3 ; original byte CC, padding
0x266b56: INT3 ; original byte CC, padding
0x266b57: INT3 ; original byte CC, padding

; FUNCTION thunk_266b58 [0x266b58, 0x266b5c] | file +0xbb8 | ev_8a13f5a851e775e80be452193fbd4d590b6d04ccbc7dff49f1656f50ed85ff91
thunk_266b58:
0x266b58: JMP 0x00904e60
; END FUNCTION thunk_266b58
0x266b5d: INT3 ; original byte CC, padding
0x266b5e: INT3 ; original byte CC, padding
0x266b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b60 [0x266b60, 0x266b64] | file +0xbc0 | ev_55a50802f4a0a58d620581bdf6d487bbdbf788f27ea4ebade9bcf71add39a1dc
thunk_266b60:
0x266b60: JMP 0x0091d400
; END FUNCTION thunk_266b60
0x266b65: INT3 ; original byte CC, padding
0x266b66: INT3 ; original byte CC, padding
0x266b67: INT3 ; original byte CC, padding

; FUNCTION thunk_266b68 [0x266b68, 0x266b6c] | file +0xbc8 | ev_a3b427a4474839c0c8a0e35e824e29e550bf1ee74d21c07a0abcdaee31a56056
thunk_266b68:
0x266b68: JMP 0x0091d4a0
; END FUNCTION thunk_266b68
0x266b6d: INT3 ; original byte CC, padding
0x266b6e: INT3 ; original byte CC, padding
0x266b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b70 [0x266b70, 0x266b74] | file +0xbd0 | ev_e8467fac24f549ccc576dbf816d0d2d2ccd83f5700eb06faa6c91121b928fdd0
thunk_266b70:
0x266b70: JMP 0x00a821d0
; END FUNCTION thunk_266b70
0x266b75: INT3 ; original byte CC, padding
0x266b76: INT3 ; original byte CC, padding
0x266b77: INT3 ; original byte CC, padding

; FUNCTION thunk_266b78 [0x266b78, 0x266b7c] | file +0xbd8 | ev_8f47985372645d0671a737f6dfdc8c8ebd02beaa2f6b203fa63da2a5b8f22e7b
thunk_266b78:
0x266b78: JMP 0x00b42120
; END FUNCTION thunk_266b78
0x266b7d: INT3 ; original byte CC, padding
0x266b7e: INT3 ; original byte CC, padding
0x266b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b80 [0x266b80, 0x266b84] | file +0xbe0 | ev_fd684889e15d4b26e0ee82dee8ba632bc13425741ac010622add8dae7219815d
thunk_266b80:
0x266b80: JMP 0x00964f30
; END FUNCTION thunk_266b80
0x266b85: INT3 ; original byte CC, padding
0x266b86: INT3 ; original byte CC, padding
0x266b87: INT3 ; original byte CC, padding

; FUNCTION thunk_266b88 [0x266b88, 0x266b8c] | file +0xbe8 | ev_f2df38026d5491e448e5063aac5789ad983601c453d578988858f92b6d03ae2c
thunk_266b88:
0x266b88: JMP 0x00975f50
; END FUNCTION thunk_266b88
0x266b8d: INT3 ; original byte CC, padding
0x266b8e: INT3 ; original byte CC, padding
0x266b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b90 [0x266b90, 0x266b94] | file +0xbf0 | ev_10d8a996d05141151a80648eaa04914a17d0858789d77b5b14476705981530fe
thunk_266b90:
0x266b90: JMP 0x00976200
; END FUNCTION thunk_266b90
0x266b95: INT3 ; original byte CC, padding
0x266b96: INT3 ; original byte CC, padding
0x266b97: INT3 ; original byte CC, padding

; FUNCTION thunk_266b98 [0x266b98, 0x266b9c] | file +0xbf8 | ev_c3116b49143e9b6ff94c37355177e2bdb67bb1b2e76d75c69776fb7bb325b566
thunk_266b98:
0x266b98: JMP 0x0098c950
; END FUNCTION thunk_266b98
0x266b9d: INT3 ; original byte CC, padding
0x266b9e: INT3 ; original byte CC, padding
0x266b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba0 [0x266ba0, 0x266ba4] | file +0xc00 | ev_d5357955364e0302a1c35a09ecc6540c8689b4e80dfafeb3e3bdcbaf003676e0
thunk_266ba0:
0x266ba0: JMP 0x0098cc30
; END FUNCTION thunk_266ba0
0x266ba5: INT3 ; original byte CC, padding
0x266ba6: INT3 ; original byte CC, padding
0x266ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba8 [0x266ba8, 0x266bac] | file +0xc08 | ev_7eb181636e2cdb2333dd763ae4894fc17222923d697e92963d6ba4b611dcda21
thunk_266ba8:
0x266ba8: JMP 0x0098cf30
; END FUNCTION thunk_266ba8
0x266bad: INT3 ; original byte CC, padding
0x266bae: INT3 ; original byte CC, padding
0x266baf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb0 [0x266bb0, 0x266bb4] | file +0xc10 | ev_2f19404c650e0b9290f01b624e2d3247ddfabf77eef32e16a5484806b710f012
thunk_266bb0:
0x266bb0: JMP 0x0098d6e0
; END FUNCTION thunk_266bb0
0x266bb5: INT3 ; original byte CC, padding
0x266bb6: INT3 ; original byte CC, padding
0x266bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb8 [0x266bb8, 0x266bbc] | file +0xc18 | ev_b05bb4840cd18187e9cfeab82d33fe5e27867653043f55bd77bb02218ee6fb15
thunk_266bb8:
0x266bb8: JMP 0x0098e5d0
; END FUNCTION thunk_266bb8
0x266bbd: INT3 ; original byte CC, padding
0x266bbe: INT3 ; original byte CC, padding
0x266bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc0 [0x266bc0, 0x266bc4] | file +0xc20 | ev_79af95be2d186c085c2c3aeced8a2aeeb8b6718f7d34419ecbb36bf6ed2a29e6
thunk_266bc0:
0x266bc0: JMP 0x0098e700
; END FUNCTION thunk_266bc0
0x266bc5: INT3 ; original byte CC, padding
0x266bc6: INT3 ; original byte CC, padding
0x266bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc8 [0x266bc8, 0x266bcc] | file +0xc28 | ev_8341b535cc158bc64ba7d262cb376e3cec41502b7caeb9d18b2601d189b8c5c3
thunk_266bc8:
0x266bc8: JMP 0x00992170
; END FUNCTION thunk_266bc8
0x266bcd: INT3 ; original byte CC, padding
0x266bce: INT3 ; original byte CC, padding
0x266bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd0 [0x266bd0, 0x266bd4] | file +0xc30 | ev_e166acea8ad67d05799944a6f7fdd59ec5f3b1ac8764a5c1c9aab83775552d58
thunk_266bd0:
0x266bd0: JMP 0x00992240
; END FUNCTION thunk_266bd0
0x266bd5: INT3 ; original byte CC, padding
0x266bd6: INT3 ; original byte CC, padding
0x266bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd8 [0x266bd8, 0x266bdc] | file +0xc38 | ev_85e73f067c4170bb5b3458130fd57a6af13915d7b31859b4fc64c3f06ed82bac
thunk_266bd8:
0x266bd8: JMP 0x000f5400
; END FUNCTION thunk_266bd8
0x266bdd: INT3 ; original byte CC, padding
0x266bde: INT3 ; original byte CC, padding
0x266bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266be0 [0x266be0, 0x266be4] | file +0xc40 | ev_842b4c5c42c065668d984eae4c9142db76b388ac3869191a2e6774a1dd29092b
thunk_266be0:
0x266be0: JMP 0x009a2320
; END FUNCTION thunk_266be0
0x266be5: INT3 ; original byte CC, padding
0x266be6: INT3 ; original byte CC, padding
0x266be7: INT3 ; original byte CC, padding

; FUNCTION thunk_266be8 [0x266be8, 0x266bec] | file +0xc48 | ev_030a86c722bd8b0115511456a8e9c167e2fcee9c0bc3fef7480f00c92d243c2a
thunk_266be8:
0x266be8: JMP 0x009a5720
; END FUNCTION thunk_266be8
0x266bed: INT3 ; original byte CC, padding
0x266bee: INT3 ; original byte CC, padding
0x266bef: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf0 [0x266bf0, 0x266bf4] | file +0xc50 | ev_b7ba618ae2aa9e42f6dc5f460eacabc57ff16a7d0aa334b8901473386f810008
thunk_266bf0:
0x266bf0: JMP 0x009ac9a0
; END FUNCTION thunk_266bf0
0x266bf5: INT3 ; original byte CC, padding
0x266bf6: INT3 ; original byte CC, padding
0x266bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf8 [0x266bf8, 0x266bfc] | file +0xc58 | ev_7b6dffa6d17e048eb0c5c66d7ff1892a62f7829978e4d399fec5e56368c85598
thunk_266bf8:
0x266bf8: JMP 0x009aca20
; END FUNCTION thunk_266bf8
0x266bfd: INT3 ; original byte CC, padding
0x266bfe: INT3 ; original byte CC, padding
0x266bff: INT3 ; original byte CC, padding

; FUNCTION thunk_266c00 [0x266c00, 0x266c04] | file +0xc60 | ev_37e32afc32cbfcefa497814dc4c10dc93a73d1b39133f84aeeb295f99deb9227
thunk_266c00:
0x266c00: JMP 0x001be640
; END FUNCTION thunk_266c00
0x266c05: INT3 ; original byte CC, padding
0x266c06: INT3 ; original byte CC, padding
0x266c07: INT3 ; original byte CC, padding

; FUNCTION thunk_266c08 [0x266c08, 0x266c0c] | file +0xc68 | ev_8dcbff7b878d9c7260555fdb740b8c9f57eb3ce3f0cd403b4e34d3dc8444893d
thunk_266c08:
0x266c08: JMP 0x009bed20
; END FUNCTION thunk_266c08
0x266c0d: INT3 ; original byte CC, padding
0x266c0e: INT3 ; original byte CC, padding
0x266c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c10 [0x266c10, 0x266c14] | file +0xc70 | ev_5609616af12540e3f21ffdb1c4ee50798b97a80d28d9e70d0e40685b3d52ea7b
thunk_266c10:
0x266c10: JMP 0x009c6050
; END FUNCTION thunk_266c10
0x266c15: INT3 ; original byte CC, padding
0x266c16: INT3 ; original byte CC, padding
0x266c17: INT3 ; original byte CC, padding

; FUNCTION thunk_266c18 [0x266c18, 0x266c1c] | file +0xc78 | ev_8fbdeb0835724f32a8b17a3c5d39a5e952abf35119874527c7bf6b3d2f410f4d
thunk_266c18:
0x266c18: JMP 0x009c60d0
; END FUNCTION thunk_266c18
0x266c1d: INT3 ; original byte CC, padding
0x266c1e: INT3 ; original byte CC, padding
0x266c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c20 [0x266c20, 0x266c24] | file +0xc80 | ev_ace2b7677c241f86357c44b9f6ffb12c616d9a72f498b23035be4fb0262a687f
thunk_266c20:
0x266c20: JMP 0x009c6280
; END FUNCTION thunk_266c20
0x266c25: INT3 ; original byte CC, padding
0x266c26: INT3 ; original byte CC, padding
0x266c27: INT3 ; original byte CC, padding

; FUNCTION thunk_266c28 [0x266c28, 0x266c2c] | file +0xc88 | ev_7a3062ecd30b0df2a6122e8f59b5953527a185a8647d27426de7edb4c906b7d7
thunk_266c28:
0x266c28: JMP 0x009c6310
; END FUNCTION thunk_266c28
0x266c2d: INT3 ; original byte CC, padding
0x266c2e: INT3 ; original byte CC, padding
0x266c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c30 [0x266c30, 0x266c34] | file +0xc90 | ev_dfe29f719b7475feed102705faecbfb48a5fb5cabcf650e8b213eddc01c64181
thunk_266c30:
0x266c30: JMP 0x009c6490
; END FUNCTION thunk_266c30
0x266c35: INT3 ; original byte CC, padding
0x266c36: INT3 ; original byte CC, padding
0x266c37: INT3 ; original byte CC, padding

; FUNCTION thunk_266c38 [0x266c38, 0x266c3c] | file +0xc98 | ev_f2fead07eb766b1364e16b243079bc9aa5d3876480b0d12b25b3c132c3754268
thunk_266c38:
0x266c38: JMP 0x009c65b0
; END FUNCTION thunk_266c38
0x266c3d: INT3 ; original byte CC, padding
0x266c3e: INT3 ; original byte CC, padding
0x266c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c40 [0x266c40, 0x266c44] | file +0xca0 | ev_c68ed7ba26444d1752bf6058fc28ab01a6bf926027464b2ea5e375f261cacff4
thunk_266c40:
0x266c40: JMP 0x009c6890
; END FUNCTION thunk_266c40
0x266c45: INT3 ; original byte CC, padding
0x266c46: INT3 ; original byte CC, padding
0x266c47: INT3 ; original byte CC, padding

; FUNCTION thunk_266c48 [0x266c48, 0x266c4c] | file +0xca8 | ev_67de297adfeed209dfc647b55bf4d003699078a117d7be29f97231507d06648d
thunk_266c48:
0x266c48: JMP 0x009c9340
; END FUNCTION thunk_266c48
0x266c4d: INT3 ; original byte CC, padding
0x266c4e: INT3 ; original byte CC, padding
0x266c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c50 [0x266c50, 0x266c54] | file +0xcb0 | ev_f5735fce676e82d52e4f585386bb91ed4c135c29aa338a4a56a193e57e3bc696
thunk_266c50:
0x266c50: JMP 0x009c9360
; END FUNCTION thunk_266c50
0x266c55: INT3 ; original byte CC, padding
0x266c56: INT3 ; original byte CC, padding
0x266c57: INT3 ; original byte CC, padding

; FUNCTION thunk_266c58 [0x266c58, 0x266c5c] | file +0xcb8 | ev_e91b99d64f4c78087780aed0abccebaa4e78e410a865688b3acac1c9d9dbc662
thunk_266c58:
0x266c58: JMP 0x009c9370
; END FUNCTION thunk_266c58
0x266c5d: INT3 ; original byte CC, padding
0x266c5e: INT3 ; original byte CC, padding
0x266c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c60 [0x266c60, 0x266c64] | file +0xcc0 | ev_b3f6589bf2526d456f9760f6654606024f8576bc26a4405284d36ac742be9973
thunk_266c60:
0x266c60: JMP 0x009c9380
; END FUNCTION thunk_266c60
0x266c65: INT3 ; original byte CC, padding
0x266c66: INT3 ; original byte CC, padding
0x266c67: INT3 ; original byte CC, padding

; FUNCTION thunk_266c68 [0x266c68, 0x266c6c] | file +0xcc8 | ev_18322b16d894e20a403d727376dae134cc622455f406447df0dcce4b12631368
thunk_266c68:
0x266c68: JMP 0x009dadb0
; END FUNCTION thunk_266c68
0x266c6d: INT3 ; original byte CC, padding
0x266c6e: INT3 ; original byte CC, padding
0x266c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c70 [0x266c70, 0x266c74] | file +0xcd0 | ev_02cfdafda2a13e9bce9c188e0d3d2ff158067964ff4148e08d6c71ef28462e5b
thunk_266c70:
0x266c70: JMP 0x009dafa0
; END FUNCTION thunk_266c70
0x266c75: INT3 ; original byte CC, padding
0x266c76: INT3 ; original byte CC, padding
0x266c77: INT3 ; original byte CC, padding

; FUNCTION thunk_266c78 [0x266c78, 0x266c7c] | file +0xcd8 | ev_e8c329046ada8dfcbb218a69d95ad166cea9026c2e371cb78043976fdb141791
thunk_266c78:
0x266c78: JMP 0x009dc860
; END FUNCTION thunk_266c78
0x266c7d: INT3 ; original byte CC, padding
0x266c7e: INT3 ; original byte CC, padding
0x266c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c80 [0x266c80, 0x266c84] | file +0xce0 | ev_951c7632d5f7ac048641f115f7f022df0067f8be7557f92bc19817ba1f69dce3
thunk_266c80:
0x266c80: JMP 0x009dcc40
; END FUNCTION thunk_266c80
0x266c85: INT3 ; original byte CC, padding
0x266c86: INT3 ; original byte CC, padding
0x266c87: INT3 ; original byte CC, padding

; FUNCTION thunk_266c88 [0x266c88, 0x266c8c] | file +0xce8 | ev_cb36009f9bfc136ec5ce961b8bfce675e1359e0ba638916fd42ff816e5a29426
thunk_266c88:
0x266c88: JMP 0x009dce80
; END FUNCTION thunk_266c88
0x266c8d: INT3 ; original byte CC, padding
0x266c8e: INT3 ; original byte CC, padding
0x266c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c90 [0x266c90, 0x266c94] | file +0xcf0 | ev_6cd39531681fde08c31a8a78d17c026d60656b4a04d4df9cf32e35b4ad3233b6
thunk_266c90:
0x266c90: JMP 0x009dd500
; END FUNCTION thunk_266c90
0x266c95: INT3 ; original byte CC, padding
0x266c96: INT3 ; original byte CC, padding
0x266c97: INT3 ; original byte CC, padding

; FUNCTION thunk_266c98 [0x266c98, 0x266c9c] | file +0xcf8 | ev_082dedda124d393d2915851f9fde3e738185206a07e4537279f0f861e5e538ed
thunk_266c98:
0x266c98: JMP 0x00caacd0
; END FUNCTION thunk_266c98
0x266c9d: INT3 ; original byte CC, padding
0x266c9e: INT3 ; original byte CC, padding
0x266c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca0 [0x266ca0, 0x266ca4] | file +0xd00 | ev_9bc1d8d5795bb013c77f16ef99873037745952b9b9c7afd3662bb4d086d7ead5
thunk_266ca0:
0x266ca0: JMP 0x009dd7d0
; END FUNCTION thunk_266ca0
0x266ca5: INT3 ; original byte CC, padding
0x266ca6: INT3 ; original byte CC, padding
0x266ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca8 [0x266ca8, 0x266cac] | file +0xd08 | ev_17560178ac1bf83794f7f4280d1fb3fc2375e475a18a6fac6d799778c6f8ebbf
thunk_266ca8:
0x266ca8: JMP 0x009dd990
; END FUNCTION thunk_266ca8
0x266cad: INT3 ; original byte CC, padding
0x266cae: INT3 ; original byte CC, padding
0x266caf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb0 [0x266cb0, 0x266cb4] | file +0xd10 | ev_93b9cede683a5db69b3564125f37c3e108fee90298840a1378e784896a40b21a
thunk_266cb0:
0x266cb0: JMP 0x009ddba0
; END FUNCTION thunk_266cb0
0x266cb5: INT3 ; original byte CC, padding
0x266cb6: INT3 ; original byte CC, padding
0x266cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb8 [0x266cb8, 0x266cbc] | file +0xd18 | ev_17e04c234b75b5bb4b975f60d1dfe50a320d9680c9f216bf121bb91243acdb38
thunk_266cb8:
0x266cb8: JMP 0x009ddc00
; END FUNCTION thunk_266cb8
0x266cbd: INT3 ; original byte CC, padding
0x266cbe: INT3 ; original byte CC, padding
0x266cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc0 [0x266cc0, 0x266cc4] | file +0xd20 | ev_b6c802572264316e90ed3345f2a81557c2bd489791b15076650e3be79e08ff47
thunk_266cc0:
0x266cc0: JMP 0x009dde50
; END FUNCTION thunk_266cc0
0x266cc5: INT3 ; original byte CC, padding
0x266cc6: INT3 ; original byte CC, padding
0x266cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc8 [0x266cc8, 0x266ccc] | file +0xd28 | ev_f94c0066909ed11a39e16e7896cd502d8724b3a73c0764f2f50f547302dc33d5
thunk_266cc8:
0x266cc8: JMP 0x009ddeb0
; END FUNCTION thunk_266cc8
0x266ccd: INT3 ; original byte CC, padding
0x266cce: INT3 ; original byte CC, padding
0x266ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd0 [0x266cd0, 0x266cd4] | file +0xd30 | ev_348cb7baeed000a9d33e2e381076de9fb9b8615b007f637a8eb38169607b542e
thunk_266cd0:
0x266cd0: JMP 0x009ddff0
; END FUNCTION thunk_266cd0
0x266cd5: INT3 ; original byte CC, padding
0x266cd6: INT3 ; original byte CC, padding
0x266cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd8 [0x266cd8, 0x266cdc] | file +0xd38 | ev_fc58a66b8aa11327158592a2683a5409b088dbfa3e73c567d2114c597deb93bc
thunk_266cd8:
0x266cd8: JMP 0x009de070
; END FUNCTION thunk_266cd8
0x266cdd: INT3 ; original byte CC, padding
0x266cde: INT3 ; original byte CC, padding
0x266cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce0 [0x266ce0, 0x266ce4] | file +0xd40 | ev_5475722fc4118f733e9a73ddbd7446a54dc4ad626a95e9c9f0448cc18e9f996e
thunk_266ce0:
0x266ce0: JMP 0x009de0f0
; END FUNCTION thunk_266ce0
0x266ce5: INT3 ; original byte CC, padding
0x266ce6: INT3 ; original byte CC, padding
0x266ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce8 [0x266ce8, 0x266cec] | file +0xd48 | ev_fdafddb450a802d82260ceae9a715e28314e8881a70b3d59b8493179b1961500
thunk_266ce8:
0x266ce8: JMP 0x009e0b90
; END FUNCTION thunk_266ce8
0x266ced: INT3 ; original byte CC, padding
0x266cee: INT3 ; original byte CC, padding
0x266cef: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf0 [0x266cf0, 0x266cf4] | file +0xd50 | ev_8cefa82a89b7b4b45c99217e6cd0bee8439d24511d15edc5beb5541815716e5c
thunk_266cf0:
0x266cf0: JMP 0x009e0cd0
; END FUNCTION thunk_266cf0
0x266cf5: INT3 ; original byte CC, padding
0x266cf6: INT3 ; original byte CC, padding
0x266cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf8 [0x266cf8, 0x266cfc] | file +0xd58 | ev_0fe31e9a802c16bff487f3ffa6fe768146a74631329f957dd9bc3dca74021aca
thunk_266cf8:
0x266cf8: JMP 0x009e0d70
; END FUNCTION thunk_266cf8
0x266cfd: INT3 ; original byte CC, padding
0x266cfe: INT3 ; original byte CC, padding
0x266cff: INT3 ; original byte CC, padding

; FUNCTION thunk_266d00 [0x266d00, 0x266d04] | file +0xd60 | ev_e5cce5cafece25832e81d202bbaf98d746251944792d147620e609bdc88a079b
thunk_266d00:
0x266d00: JMP 0x009e0ef0
; END FUNCTION thunk_266d00
0x266d05: INT3 ; original byte CC, padding
0x266d06: INT3 ; original byte CC, padding
0x266d07: INT3 ; original byte CC, padding

; FUNCTION thunk_266d08 [0x266d08, 0x266d0c] | file +0xd68 | ev_a5c6e76db2b06ad96ad752996fbb0d43af1311a603e951d09dc0718da26264e1
thunk_266d08:
0x266d08: JMP 0x009e1050
; END FUNCTION thunk_266d08
0x266d0d: INT3 ; original byte CC, padding
0x266d0e: INT3 ; original byte CC, padding
0x266d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d10 [0x266d10, 0x266d14] | file +0xd70 | ev_2ff4d8779640ec27c7a42ba2bd832a1062c3067640217eabf3eafa58a6ac14c7
thunk_266d10:
0x266d10: JMP 0x009e1490
; END FUNCTION thunk_266d10
0x266d15: INT3 ; original byte CC, padding
0x266d16: INT3 ; original byte CC, padding
0x266d17: INT3 ; original byte CC, padding

; FUNCTION thunk_266d18 [0x266d18, 0x266d1c] | file +0xd78 | ev_b7780a59bec1d8f90378ae9653e3982c89c7992f914096c62690d8fcc0b31a94
thunk_266d18:
0x266d18: JMP 0x00a065e0
; END FUNCTION thunk_266d18
0x266d1d: INT3 ; original byte CC, padding
0x266d1e: INT3 ; original byte CC, padding
0x266d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d20 [0x266d20, 0x266d24] | file +0xd80 | ev_d10f566f8d9de96267472087c1f37a7479708a48744751f0d311c1c622dd3904
thunk_266d20:
0x266d20: JMP 0x00101340
; END FUNCTION thunk_266d20
0x266d25: INT3 ; original byte CC, padding
0x266d26: INT3 ; original byte CC, padding
0x266d27: INT3 ; original byte CC, padding

; FUNCTION thunk_266d28 [0x266d28, 0x266d2c] | file +0xd88 | ev_b14ed9d81a695319fa6e7c6ebdc5b570f764a5554a4fc0c40148baafde815686
thunk_266d28:
0x266d28: JMP 0x00a32f30
; END FUNCTION thunk_266d28
0x266d2d: INT3 ; original byte CC, padding
0x266d2e: INT3 ; original byte CC, padding
0x266d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d30 [0x266d30, 0x266d34] | file +0xd90 | ev_6ceedf1cd0b694a6020d0489577c66021b95c6e6acf4a93dbeabde86d9f6d391
thunk_266d30:
0x266d30: JMP 0x00a336c0
; END FUNCTION thunk_266d30
0x266d35: INT3 ; original byte CC, padding
0x266d36: INT3 ; original byte CC, padding
0x266d37: INT3 ; original byte CC, padding

; FUNCTION thunk_266d38 [0x266d38, 0x266d3c] | file +0xd98 | ev_f404fb3364f869a944ee99aeb16bd33ff7e315fa9ba80c315a591d04d77c5cd9
thunk_266d38:
0x266d38: JMP 0x00a38c90
; END FUNCTION thunk_266d38
0x266d3d: INT3 ; original byte CC, padding
0x266d3e: INT3 ; original byte CC, padding
0x266d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d40 [0x266d40, 0x266d44] | file +0xda0 | ev_78ce9ed99aaf60ae3f7ddffd51b979932236ff54bce8de0b8b30a669f28d85da
thunk_266d40:
0x266d40: JMP 0x00a6ab00
; END FUNCTION thunk_266d40
0x266d45: INT3 ; original byte CC, padding
0x266d46: INT3 ; original byte CC, padding
0x266d47: INT3 ; original byte CC, padding

; FUNCTION thunk_266d48 [0x266d48, 0x266d4c] | file +0xda8 | ev_b5a719e3051b394916925482ba873b496bcb34a1988407017a610457c6c23429
thunk_266d48:
0x266d48: JMP 0x00a6abb0
; END FUNCTION thunk_266d48
0x266d4d: INT3 ; original byte CC, padding
0x266d4e: INT3 ; original byte CC, padding
0x266d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d50 [0x266d50, 0x266d54] | file +0xdb0 | ev_66a8e1394f6126ff166804a7b4117339bcc651d2b89fb684b756a8507994bdcf
thunk_266d50:
0x266d50: JMP 0x00a8ec10
; END FUNCTION thunk_266d50
0x266d55: INT3 ; original byte CC, padding
0x266d56: INT3 ; original byte CC, padding
0x266d57: INT3 ; original byte CC, padding

; FUNCTION thunk_266d58 [0x266d58, 0x266d5c] | file +0xdb8 | ev_8d5fb3fe87100ad2ba04f2e7e973447e53c90e2e406a2a38099b02122b3e9869
thunk_266d58:
0x266d58: JMP 0x00a8ee00
; END FUNCTION thunk_266d58
0x266d5d: INT3 ; original byte CC, padding
0x266d5e: INT3 ; original byte CC, padding
0x266d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d60 [0x266d60, 0x266d64] | file +0xdc0 | ev_5c2e94bdbf3948c0843d6ef9b29810c9a403493954312eb1180300ffe4515545
thunk_266d60:
0x266d60: JMP 0x00ab17b0
; END FUNCTION thunk_266d60
0x266d65: INT3 ; original byte CC, padding
0x266d66: INT3 ; original byte CC, padding
0x266d67: INT3 ; original byte CC, padding

; FUNCTION thunk_266d68 [0x266d68, 0x266d6c] | file +0xdc8 | ev_6b4bef6b5f4bc828de6f53ae7485814885aa93b10e589f519b41bb23e3162800
thunk_266d68:
0x266d68: JMP 0x00ac07b0
; END FUNCTION thunk_266d68
0x266d6d: INT3 ; original byte CC, padding
0x266d6e: INT3 ; original byte CC, padding
0x266d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d70 [0x266d70, 0x266d74] | file +0xdd0 | ev_bdce12fae65c55b0c7513e875b769c11d4280239f3d72373aaab9e9766afbaac
thunk_266d70:
0x266d70: JMP 0x00ac2af0
; END FUNCTION thunk_266d70
0x266d75: INT3 ; original byte CC, padding
0x266d76: INT3 ; original byte CC, padding
0x266d77: INT3 ; original byte CC, padding

; FUNCTION thunk_266d78 [0x266d78, 0x266d7c] | file +0xdd8 | ev_2680b60f9cb23d12b0b0ecaabdc08d843be220023793fdb28f8eee6ca7229a5d
thunk_266d78:
0x266d78: JMP 0x0011a750
; END FUNCTION thunk_266d78
0x266d7d: INT3 ; original byte CC, padding
0x266d7e: INT3 ; original byte CC, padding
0x266d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d80 [0x266d80, 0x266d84] | file +0xde0 | ev_9af6b1d5b9f45778621c3ee062e58fca2c11a641863e209779c6d2054ed827fb
thunk_266d80:
0x266d80: JMP 0x00ae12a0
; END FUNCTION thunk_266d80
0x266d85: INT3 ; original byte CC, padding
0x266d86: INT3 ; original byte CC, padding
0x266d87: INT3 ; original byte CC, padding

; FUNCTION thunk_266d88 [0x266d88, 0x266d8c] | file +0xde8 | ev_8646eab0650b71883c11f7cdbab5c072bb7067fc4b651fe6d4ff533834d1400e
thunk_266d88:
0x266d88: JMP 0x00ae3400
; END FUNCTION thunk_266d88
0x266d8d: INT3 ; original byte CC, padding
0x266d8e: INT3 ; original byte CC, padding
0x266d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d90 [0x266d90, 0x266d94] | file +0xdf0 | ev_ce1d8c6ab3f2ba46d018490e9359180b1341e43b3fbb4718438a184c713f0e55
thunk_266d90:
0x266d90: JMP 0x00ae3530
; END FUNCTION thunk_266d90
0x266d95: INT3 ; original byte CC, padding
0x266d96: INT3 ; original byte CC, padding
0x266d97: INT3 ; original byte CC, padding

; FUNCTION thunk_266d98 [0x266d98, 0x266d9c] | file +0xdf8 | ev_bee1965f99007cbadf8a23a84f31148a5140aa1948ea011f5abff7a1602a8ffc
thunk_266d98:
0x266d98: JMP 0x00ae63c0
; END FUNCTION thunk_266d98
0x266d9d: INT3 ; original byte CC, padding
0x266d9e: INT3 ; original byte CC, padding
0x266d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266da0 [0x266da0, 0x266da4] | file +0xe00 | ev_021586ff9f269dedbb283491c1f5fef34dda25f2b408fa051a6134e2f95edd7d
thunk_266da0:
0x266da0: JMP 0x00b07ee0
; END FUNCTION thunk_266da0
0x266da5: INT3 ; original byte CC, padding
0x266da6: INT3 ; original byte CC, padding
0x266da7: INT3 ; original byte CC, padding

; FUNCTION thunk_266da8 [0x266da8, 0x266dac] | file +0xe08 | ev_661897bcc4d7235e95c9ece8b99683b3005da66501d8fb0d0dec17557ed248b7
thunk_266da8:
0x266da8: JMP 0x00b08190
; END FUNCTION thunk_266da8
0x266dad: INT3 ; original byte CC, padding
0x266dae: INT3 ; original byte CC, padding
0x266daf: INT3 ; original byte CC, padding

; FUNCTION thunk_266db0 [0x266db0, 0x266db4] | file +0xe10 | ev_a51657bb9adaf2b46acb636dab82aea2afbd24344b38ec9fc62f4a5cb75b4c3f
thunk_266db0:
0x266db0: JMP 0x00b08530
; END FUNCTION thunk_266db0
0x266db5: INT3 ; original byte CC, padding
0x266db6: INT3 ; original byte CC, padding
0x266db7: INT3 ; original byte CC, padding

; FUNCTION thunk_266db8 [0x266db8, 0x266dbc] | file +0xe18 | ev_7bd6608e24ea1d58427542d7fe6b513031f58af19140f4dc92741a8a3df9ee06
thunk_266db8:
0x266db8: JMP 0x00b08810
; END FUNCTION thunk_266db8
0x266dbd: INT3 ; original byte CC, padding
0x266dbe: INT3 ; original byte CC, padding
0x266dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc0 [0x266dc0, 0x266dc4] | file +0xe20 | ev_f09ac987114e244788a375bb4fcf7afd7ce4c964fa2b7bf4a6afafeb24830e03
thunk_266dc0:
0x266dc0: JMP 0x00b096a0
; END FUNCTION thunk_266dc0
0x266dc5: INT3 ; original byte CC, padding
0x266dc6: INT3 ; original byte CC, padding
0x266dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc8 [0x266dc8, 0x266dcc] | file +0xe28 | ev_dfc611f60173bd5832d71e5b7ec488439560cad77e88931e8d7c64545c725a45
thunk_266dc8:
0x266dc8: JMP 0x00b0b4f0
; END FUNCTION thunk_266dc8
0x266dcd: INT3 ; original byte CC, padding
0x266dce: INT3 ; original byte CC, padding
0x266dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd0 [0x266dd0, 0x266dd4] | file +0xe30 | ev_7ddaa2bd15e3b28548a4a9c293e73ca9bc9385206edec45703a1cbcbdfd80bbe
thunk_266dd0:
0x266dd0: JMP 0x001ef0f0
; END FUNCTION thunk_266dd0
0x266dd5: INT3 ; original byte CC, padding
0x266dd6: INT3 ; original byte CC, padding
0x266dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd8 [0x266dd8, 0x266ddc] | file +0xe38 | ev_0fd6893fc896b88e9e684bdcf1f2df886f46d9b79d06e9e8e6ac0024f32f3aed
thunk_266dd8:
0x266dd8: JMP 0x001f0060
; END FUNCTION thunk_266dd8
0x266ddd: INT3 ; original byte CC, padding
0x266dde: INT3 ; original byte CC, padding
0x266ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_266de0 [0x266de0, 0x266de4] | file +0xe40 | ev_f3e343791d1960e5d9ab7af96634393b0613d3a4f218256929e2f8033104ac7d
thunk_266de0:
0x266de0: JMP 0x0011b9b0
; END FUNCTION thunk_266de0
0x266de5: INT3 ; original byte CC, padding
0x266de6: INT3 ; original byte CC, padding
0x266de7: INT3 ; original byte CC, padding

; FUNCTION thunk_266de8 [0x266de8, 0x266dec] | file +0xe48 | ev_3256847e0571f12a26c9637636d3c4e54696270caa3cb68eeaae5a004b6a850f
thunk_266de8:
0x266de8: JMP 0x00b3b130
; END FUNCTION thunk_266de8
0x266ded: INT3 ; original byte CC, padding
0x266dee: INT3 ; original byte CC, padding
0x266def: INT3 ; original byte CC, padding

; FUNCTION thunk_266df0 [0x266df0, 0x266df4] | file +0xe50 | ev_a4d5a58087cc50f89a43a0c946224b55c585f59dde0dbe33701b96ad42036a63
thunk_266df0:
0x266df0: JMP 0x00b47a40
; END FUNCTION thunk_266df0
0x266df5: INT3 ; original byte CC, padding
0x266df6: INT3 ; original byte CC, padding
0x266df7: INT3 ; original byte CC, padding

; FUNCTION thunk_266df8 [0x266df8, 0x266dfc] | file +0xe58 | ev_6f9f553619e79fa117711aa664214bf407cb896470edfaed2fa80b975c20998e
thunk_266df8:
0x266df8: JMP 0x00b503c0
; END FUNCTION thunk_266df8
0x266dfd: INT3 ; original byte CC, padding
0x266dfe: INT3 ; original byte CC, padding
0x266dff: INT3 ; original byte CC, padding

; FUNCTION thunk_266e00 [0x266e00, 0x266e04] | file +0xe60 | ev_5bb72f86362afb6f491fa4944eac459ad974d898a733bc1701ce28ccee3366a3
thunk_266e00:
0x266e00: JMP 0x00b50f10
; END FUNCTION thunk_266e00
0x266e05: INT3 ; original byte CC, padding
0x266e06: INT3 ; original byte CC, padding
0x266e07: INT3 ; original byte CC, padding

; FUNCTION thunk_266e08 [0x266e08, 0x266e0c] | file +0xe68 | ev_4626fe3df4c069cb8aaac5384079b00f151bec62d68c9553e9ed7c8a4fd75c42
thunk_266e08:
0x266e08: JMP 0x00b50fb0
; END FUNCTION thunk_266e08
0x266e0d: INT3 ; original byte CC, padding
0x266e0e: INT3 ; original byte CC, padding
0x266e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e10 [0x266e10, 0x266e14] | file +0xe70 | ev_6d4603bdb31502b309b8835180f360ba961490d6273d111b6f01a175e50b17af
thunk_266e10:
0x266e10: JMP 0x00b510b0
; END FUNCTION thunk_266e10
0x266e15: INT3 ; original byte CC, padding
0x266e16: INT3 ; original byte CC, padding
0x266e17: INT3 ; original byte CC, padding

; FUNCTION thunk_266e18 [0x266e18, 0x266e1c] | file +0xe78 | ev_396af73daa982841b9f11dfa441c9e266f5a927b17b979985cd9ca8a0a5fdb68
thunk_266e18:
0x266e18: JMP 0x00b51190
; END FUNCTION thunk_266e18
0x266e1d: INT3 ; original byte CC, padding
0x266e1e: INT3 ; original byte CC, padding
0x266e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e20 [0x266e20, 0x266e24] | file +0xe80 | ev_fffc298efdf0b5e0e2e4378571521024ffa8e4aca9043008d1e61ce816203c66
thunk_266e20:
0x266e20: JMP 0x00b51290
; END FUNCTION thunk_266e20
0x266e25: INT3 ; original byte CC, padding
0x266e26: INT3 ; original byte CC, padding
0x266e27: INT3 ; original byte CC, padding

; FUNCTION thunk_266e28 [0x266e28, 0x266e2c] | file +0xe88 | ev_e8ef76577eaac3fab3c793b7168e9da12dc1aca576c7a71fa3f557e237c2e4e6
thunk_266e28:
0x266e28: JMP 0x00b512d0
; END FUNCTION thunk_266e28
0x266e2d: INT3 ; original byte CC, padding
0x266e2e: INT3 ; original byte CC, padding
0x266e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e30 [0x266e30, 0x266e34] | file +0xe90 | ev_4db31287f09e0ae97956058a96dfe8fd3e5528ddc6f25d486a7433aaa211b322
thunk_266e30:
0x266e30: JMP 0x00b51320
; END FUNCTION thunk_266e30
0x266e35: INT3 ; original byte CC, padding
0x266e36: INT3 ; original byte CC, padding
0x266e37: INT3 ; original byte CC, padding

; FUNCTION thunk_266e38 [0x266e38, 0x266e3c] | file +0xe98 | ev_8ecf5e88ea4bb913a7d602178eeaa9d978ee9a7b5cd012aa8894b369ad41550d
thunk_266e38:
0x266e38: JMP 0x00b568a0
; END FUNCTION thunk_266e38
0x266e3d: INT3 ; original byte CC, padding
0x266e3e: INT3 ; original byte CC, padding
0x266e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e40 [0x266e40, 0x266e44] | file +0xea0 | ev_8e75b68ffdcee668e3cc8060cc48f0eec1a2ba00367b0ea233f6c43f8765a777
thunk_266e40:
0x266e40: JMP 0x0009a0e0
; END FUNCTION thunk_266e40
0x266e45: INT3 ; original byte CC, padding
0x266e46: INT3 ; original byte CC, padding
0x266e47: INT3 ; original byte CC, padding

; FUNCTION thunk_266e48 [0x266e48, 0x266e4c] | file +0xea8 | ev_1449cb43daa60b62cab63d755b2a2ddd18efb47331cc52035ef5c3a04310475e
thunk_266e48:
0x266e48: JMP 0x00b6ae70
; END FUNCTION thunk_266e48
0x266e4d: INT3 ; original byte CC, padding
0x266e4e: INT3 ; original byte CC, padding
0x266e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e50 [0x266e50, 0x266e54] | file +0xeb0 | ev_e5c757c666e1090a3ec377473f91b1bae5a6549c03db2270345898d87c0b067e
thunk_266e50:
0x266e50: JMP 0x00b6bb90
; END FUNCTION thunk_266e50
0x266e55: INT3 ; original byte CC, padding
0x266e56: INT3 ; original byte CC, padding
0x266e57: INT3 ; original byte CC, padding

; FUNCTION thunk_266e58 [0x266e58, 0x266e5c] | file +0xeb8 | ev_8bf126f87d6604a0a94aed580fc13864f2b4286b1b4f03fb9394afeb53816a34
thunk_266e58:
0x266e58: JMP 0x00b6d980
; END FUNCTION thunk_266e58
0x266e5d: INT3 ; original byte CC, padding
0x266e5e: INT3 ; original byte CC, padding
0x266e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e60 [0x266e60, 0x266e64] | file +0xec0 | ev_7ca6cb21dc0b6f25698862493a2d6b95a19babe9efefa4bd242d6e79af31bb98
thunk_266e60:
0x266e60: JMP 0x00b6daa0
; END FUNCTION thunk_266e60
0x266e65: INT3 ; original byte CC, padding
0x266e66: INT3 ; original byte CC, padding
0x266e67: INT3 ; original byte CC, padding

; FUNCTION thunk_266e68 [0x266e68, 0x266e6c] | file +0xec8 | ev_d64bbe0b19de218b1913ecc94394fde4fbf612ee3092f588edf5fd97efaed577
thunk_266e68:
0x266e68: JMP 0x00b6e180
; END FUNCTION thunk_266e68
0x266e6d: INT3 ; original byte CC, padding
0x266e6e: INT3 ; original byte CC, padding
0x266e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e70 [0x266e70, 0x266e74] | file +0xed0 | ev_f2be95566a6f3f55ffa0867891aa84abb05e686b116e083938852c5ad30c9053
thunk_266e70:
0x266e70: JMP 0x00b71320
; END FUNCTION thunk_266e70
0x266e75: INT3 ; original byte CC, padding
0x266e76: INT3 ; original byte CC, padding
0x266e77: INT3 ; original byte CC, padding

; FUNCTION thunk_266e78 [0x266e78, 0x266e7c] | file +0xed8 | ev_ea30d5c8cc955f26bc1887e696b4cdd9d0f470d328a1f7fcff151a10e904bf5b
thunk_266e78:
0x266e78: JMP 0x00b71370
; END FUNCTION thunk_266e78
0x266e7d: INT3 ; original byte CC, padding
0x266e7e: INT3 ; original byte CC, padding
0x266e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e80 [0x266e80, 0x266e84] | file +0xee0 | ev_c63e3871926c8e72b579d264e85f38382d783da0d0b04d4be00b01031822fb25
thunk_266e80:
0x266e80: JMP 0x00b713c0
; END FUNCTION thunk_266e80
0x266e85: INT3 ; original byte CC, padding
0x266e86: INT3 ; original byte CC, padding
0x266e87: INT3 ; original byte CC, padding

; FUNCTION thunk_266e88 [0x266e88, 0x266e8c] | file +0xee8 | ev_197d591bf203fc30e38d796f069d211a923ba60199a8f018b65658b3f5f32eb8
thunk_266e88:
0x266e88: JMP 0x00b71410
; END FUNCTION thunk_266e88
0x266e8d: INT3 ; original byte CC, padding
0x266e8e: INT3 ; original byte CC, padding
0x266e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e90 [0x266e90, 0x266e94] | file +0xef0 | ev_06c505a8945df64cf395d995cbc9ef4d39ffbb334ac8940eaf15b821d76a2e1f
thunk_266e90:
0x266e90: JMP 0x00b71960
; END FUNCTION thunk_266e90
0x266e95: INT3 ; original byte CC, padding
0x266e96: INT3 ; original byte CC, padding
0x266e97: INT3 ; original byte CC, padding

; FUNCTION thunk_266e98 [0x266e98, 0x266e9c] | file +0xef8 | ev_92cf65c6497d81c189072201bc92b6d001023852b15682c6e7045a41c5b4996f
thunk_266e98:
0x266e98: JMP 0x00b719d0
; END FUNCTION thunk_266e98
0x266e9d: INT3 ; original byte CC, padding
0x266e9e: INT3 ; original byte CC, padding
0x266e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea0 [0x266ea0, 0x266ea4] | file +0xf00 | ev_645a6b9f18cf77202c1f3379a167a483992f1abe64ade57cf4679057b81f8132
thunk_266ea0:
0x266ea0: JMP 0x00b71a40
; END FUNCTION thunk_266ea0
0x266ea5: INT3 ; original byte CC, padding
0x266ea6: INT3 ; original byte CC, padding
0x266ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea8 [0x266ea8, 0x266eac] | file +0xf08 | ev_92f8a51544605bc7f4dfb2d3f45f27341d959314143b088056208c2ce0daf354
thunk_266ea8:
0x266ea8: JMP 0x00b71ab0
; END FUNCTION thunk_266ea8
0x266ead: INT3 ; original byte CC, padding
0x266eae: INT3 ; original byte CC, padding
0x266eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb0 [0x266eb0, 0x266eb4] | file +0xf10 | ev_86e42877162f49237f5ee3cc1fa9b5e7317d73fd40d6536966932f7792fb38d9
thunk_266eb0:
0x266eb0: JMP 0x00b72620
; END FUNCTION thunk_266eb0
0x266eb5: INT3 ; original byte CC, padding
0x266eb6: INT3 ; original byte CC, padding
0x266eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb8 [0x266eb8, 0x266ebc] | file +0xf18 | ev_001011f1bff1e10ce4ca0cb454363095736c0cef7656de7f95cc7986ab85c6f4
thunk_266eb8:
0x266eb8: JMP 0x00b72860
; END FUNCTION thunk_266eb8
0x266ebd: INT3 ; original byte CC, padding
0x266ebe: INT3 ; original byte CC, padding
0x266ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec0 [0x266ec0, 0x266ec4] | file +0xf20 | ev_a62bc6806ab674d0ae71f374d1e8ebd1b76781dbf590ebc9087c31322e2462e2
thunk_266ec0:
0x266ec0: JMP 0x00b791d0
; END FUNCTION thunk_266ec0
0x266ec5: INT3 ; original byte CC, padding
0x266ec6: INT3 ; original byte CC, padding
0x266ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec8 [0x266ec8, 0x266ecc] | file +0xf28 | ev_b52289221c273125b1dbccaf11fa3a6fd7e6246284d8522934c98ec91d8d206e
thunk_266ec8:
0x266ec8: JMP 0x00b79290
; END FUNCTION thunk_266ec8
0x266ecd: INT3 ; original byte CC, padding
0x266ece: INT3 ; original byte CC, padding
0x266ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed0 [0x266ed0, 0x266ed4] | file +0xf30 | ev_4047cbc663795c1289163dbe21ac08af15171a76058b17f7e22314c363bc8a5c
thunk_266ed0:
0x266ed0: JMP 0x00b793f0
; END FUNCTION thunk_266ed0
0x266ed5: INT3 ; original byte CC, padding
0x266ed6: INT3 ; original byte CC, padding
0x266ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed8 [0x266ed8, 0x266edc] | file +0xf38 | ev_d40229b3fb879733cf4bb36ba96438639d574a7aaaf01b902462653bec434bc0
thunk_266ed8:
0x266ed8: JMP 0x00b79420
; END FUNCTION thunk_266ed8
0x266edd: INT3 ; original byte CC, padding
0x266ede: INT3 ; original byte CC, padding
0x266edf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee0 [0x266ee0, 0x266ee4] | file +0xf40 | ev_9c460fc45aabe04141735909271220fd15d8255d47b0abc66e0f74511b093105
thunk_266ee0:
0x266ee0: JMP 0x00b79460
; END FUNCTION thunk_266ee0
0x266ee5: INT3 ; original byte CC, padding
0x266ee6: INT3 ; original byte CC, padding
0x266ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee8 [0x266ee8, 0x266eec] | file +0xf48 | ev_140eeb12e1434a7dc0c137ae75e06af03c16e376698cbc46dfa3d10d190ea107
thunk_266ee8:
0x266ee8: JMP 0x00b79480
; END FUNCTION thunk_266ee8
0x266eed: INT3 ; original byte CC, padding
0x266eee: INT3 ; original byte CC, padding
0x266eef: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef0 [0x266ef0, 0x266ef4] | file +0xf50 | ev_43ad813f5b2b8f40c57dc086f2c412e940abf4ceca224978018e13b0f33a7820
thunk_266ef0:
0x266ef0: JMP 0x00b79490
; END FUNCTION thunk_266ef0
0x266ef5: INT3 ; original byte CC, padding
0x266ef6: INT3 ; original byte CC, padding
0x266ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef8 [0x266ef8, 0x266efc] | file +0xf58 | ev_bfec69b84024565b47c924a86acddbcc1709c8816cf063cd4839f05a0efb3a66
thunk_266ef8:
0x266ef8: JMP 0x00b794b0
; END FUNCTION thunk_266ef8
0x266efd: INT3 ; original byte CC, padding
0x266efe: INT3 ; original byte CC, padding
0x266eff: INT3 ; original byte CC, padding

; FUNCTION thunk_266f00 [0x266f00, 0x266f04] | file +0xf60 | ev_c1e937b17f609327e5a32dc651db69965da91c36afed6b6cab4eeb2ddbc66ade
thunk_266f00:
0x266f00: JMP 0x00b795f0
; END FUNCTION thunk_266f00
0x266f05: INT3 ; original byte CC, padding
0x266f06: INT3 ; original byte CC, padding
0x266f07: INT3 ; original byte CC, padding

; FUNCTION thunk_266f08 [0x266f08, 0x266f0c] | file +0xf68 | ev_54cd41ab36c1d893c67c9e91dd3bac8054c2a093aa3ff842a2b4ac493f1af467
thunk_266f08:
0x266f08: JMP 0x00b79620
; END FUNCTION thunk_266f08
0x266f0d: INT3 ; original byte CC, padding
0x266f0e: INT3 ; original byte CC, padding
0x266f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f10 [0x266f10, 0x266f14] | file +0xf70 | ev_5f150108a282e0acbbf087f0447711d5f934b501ef033bcb4651c0a0bff06097
thunk_266f10:
0x266f10: JMP 0x00b79830
; END FUNCTION thunk_266f10
0x266f15: INT3 ; original byte CC, padding
0x266f16: INT3 ; original byte CC, padding
0x266f17: INT3 ; original byte CC, padding

; FUNCTION thunk_266f18 [0x266f18, 0x266f1c] | file +0xf78 | ev_2da7c7533a24f08c54a5ec5ef15fbab9a37ad41832c00dd6f045c392f203f1ab
thunk_266f18:
0x266f18: JMP 0x00b80e90
; END FUNCTION thunk_266f18
0x266f1d: INT3 ; original byte CC, padding
0x266f1e: INT3 ; original byte CC, padding
0x266f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f20 [0x266f20, 0x266f24] | file +0xf80 | ev_05007cf428f229f9acad957f05bfd0d915fc31a6bd8f53b6d71023441c636a5b
thunk_266f20:
0x266f20: JMP 0x00b80f20
; END FUNCTION thunk_266f20
0x266f25: INT3 ; original byte CC, padding
0x266f26: INT3 ; original byte CC, padding
0x266f27: INT3 ; original byte CC, padding

; FUNCTION thunk_266f28 [0x266f28, 0x266f2c] | file +0xf88 | ev_4af2057d7b385aba4d6285ec88eaf49753f05817a916e45e8dad4635faa00a15
thunk_266f28:
0x266f28: JMP 0x00b99520
; END FUNCTION thunk_266f28
0x266f2d: INT3 ; original byte CC, padding
0x266f2e: INT3 ; original byte CC, padding
0x266f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f30 [0x266f30, 0x266f34] | file +0xf90 | ev_7031656535bffe683040d3e65d44680a84556f146e6c8250261208dfd70560bd
thunk_266f30:
0x266f30: JMP 0x00b99600
; END FUNCTION thunk_266f30
0x266f35: INT3 ; original byte CC, padding
0x266f36: INT3 ; original byte CC, padding
0x266f37: INT3 ; original byte CC, padding

; FUNCTION thunk_266f38 [0x266f38, 0x266f3c] | file +0xf98 | ev_1c665d019d7d1f2e53f07e261e031cb899f97da44155def954621c2a02570d06
thunk_266f38:
0x266f38: JMP 0x00b9ce30
; END FUNCTION thunk_266f38
0x266f3d: INT3 ; original byte CC, padding
0x266f3e: INT3 ; original byte CC, padding
0x266f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f40 [0x266f40, 0x266f44] | file +0xfa0 | ev_712648e7bb521b61edaa5cabe0db3056f43183e8708033b54aa034674b67ec39
thunk_266f40:
0x266f40: JMP 0x00bf5c40
; END FUNCTION thunk_266f40
0x266f45: INT3 ; original byte CC, padding
0x266f46: INT3 ; original byte CC, padding
0x266f47: INT3 ; original byte CC, padding

; FUNCTION thunk_266f48 [0x266f48, 0x266f4c] | file +0xfa8 | ev_ecc803a493b1fccc01b711533b2c9a2508d39c49fd905d6689592f58ab23fd2e
thunk_266f48:
0x266f48: JMP 0x00bfe620
; END FUNCTION thunk_266f48
0x266f4d: INT3 ; original byte CC, padding
0x266f4e: INT3 ; original byte CC, padding
0x266f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f50 [0x266f50, 0x266f54] | file +0xfb0 | ev_03cc54ab31ccc520062b136e5769020cebdfb08c0270e94138249b5af9660c5b
thunk_266f50:
0x266f50: JMP 0x00bfef50
; END FUNCTION thunk_266f50
0x266f55: INT3 ; original byte CC, padding
0x266f56: INT3 ; original byte CC, padding
0x266f57: INT3 ; original byte CC, padding

; FUNCTION thunk_266f58 [0x266f58, 0x266f5c] | file +0xfb8 | ev_98503194680b5b3c8554d5b9cf932e290985606a681d50620a2ec04984c2ec5c
thunk_266f58:
0x266f58: JMP 0x00bfefa0
; END FUNCTION thunk_266f58
0x266f5d: INT3 ; original byte CC, padding
0x266f5e: INT3 ; original byte CC, padding
0x266f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f60 [0x266f60, 0x266f64] | file +0xfc0 | ev_b59c9075b71bcf6d9e1b7028c4325ca035da423d9c7567967949cb9421601b48
thunk_266f60:
0x266f60: JMP 0x00bff050
; END FUNCTION thunk_266f60
0x266f65: INT3 ; original byte CC, padding
0x266f66: INT3 ; original byte CC, padding
0x266f67: INT3 ; original byte CC, padding

; FUNCTION thunk_266f68 [0x266f68, 0x266f6c] | file +0xfc8 | ev_8365df9cf079d90dcca0b3cc08c697935064c4c8ed974c3515e1b4fa381c7611
thunk_266f68:
0x266f68: JMP 0x00c0d180
; END FUNCTION thunk_266f68
0x266f6d: INT3 ; original byte CC, padding
0x266f6e: INT3 ; original byte CC, padding
0x266f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f70 [0x266f70, 0x266f74] | file +0xfd0 | ev_ccee922592c335279de79cd9aa606fdbcd9169a04fe4fa1dd80e272430eeba58
thunk_266f70:
0x266f70: JMP 0x00c327f0
; END FUNCTION thunk_266f70
0x266f75: INT3 ; original byte CC, padding
0x266f76: INT3 ; original byte CC, padding
0x266f77: INT3 ; original byte CC, padding

; FUNCTION thunk_266f78 [0x266f78, 0x266f7c] | file +0xfd8 | ev_adf5b626a55425949b3e14eb88a6b151c2d534648b904e1b408b9d640aa34a9a
thunk_266f78:
0x266f78: JMP 0x00c32c70
; END FUNCTION thunk_266f78
0x266f7d: INT3 ; original byte CC, padding
0x266f7e: INT3 ; original byte CC, padding
0x266f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f80 [0x266f80, 0x266f84] | file +0xfe0 | ev_23a75b00a0d112a651e95c44dd54487f36c7f2b35308b90ea97aa3cd0c987b02
thunk_266f80:
0x266f80: JMP 0x00c34c70
; END FUNCTION thunk_266f80
0x266f85: INT3 ; original byte CC, padding
0x266f86: INT3 ; original byte CC, padding
0x266f87: INT3 ; original byte CC, padding

; FUNCTION thunk_266f88 [0x266f88, 0x266f8c] | file +0xfe8 | ev_eafa2e51eddea43a0ada57d0319d1511ea788cff8d813d79adea309a0bd72f97
thunk_266f88:
0x266f88: JMP 0x00c34df0
; END FUNCTION thunk_266f88
0x266f8d: INT3 ; original byte CC, padding
0x266f8e: INT3 ; original byte CC, padding
0x266f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f90 [0x266f90, 0x266f94] | file +0xff0 | ev_2377b4ca217eb2330c4ef066a1a50005f948c448bc9dec9fe0e517a224fc25ee
thunk_266f90:
0x266f90: JMP 0x00c39770
; END FUNCTION thunk_266f90
0x266f95: INT3 ; original byte CC, padding
0x266f96: INT3 ; original byte CC, padding
0x266f97: INT3 ; original byte CC, padding

; FUNCTION thunk_266f98 [0x266f98, 0x266f9c] | file +0xff8 | ev_a487275cdbdcbe32b12e5bec8dfb5826280a3e448a871934facafb54b9d2a18c
thunk_266f98:
0x266f98: JMP 0x00c43a20
; END FUNCTION thunk_266f98
0x266f9d: INT3 ; original byte CC, padding
0x266f9e: INT3 ; original byte CC, padding
0x266f9f: INT3 ; original byte CC, padding



; ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_00abb980 RVA 0x265fa0 | Evidence ev_bd8233e8f8316684c7e215791837e94c470911b6f244cbbafe614212f710232e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
<EXTERNAL>::thunk_EXT_FUN_00abb980:
0x265fa0: JMP 0x00abb980


; ===== TARGET: handler_674_body RVA 0xabb980 | Evidence ev_9af19f4187e845ef82e2ef8a5df3a31b0c4b6e3ff177e9680333fc6166e25c1d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
handler_674_body:
0xabb980: PUSH RBP
0xabb981: MOV RBP, RSP
0xabb984: PUSH R15
0xabb986: PUSH R14
0xabb988: PUSH R13
0xabb98a: PUSH R12
0xabb98c: PUSH RBX
0xabb98d: SUB RSP, 0xf8
0xabb994: LEA RBX, [0x391c310]
0xabb99b: MOV R13, RDI
0xabb99e: MOV EDI, 0x4
0xabb9a3: MOV R14, RSI
0xabb9a6: MOV RAX, qword ptr [RBX]
0xabb9a9: MOV qword ptr [RBP + -0x30], RAX
0xabb9ad: CALL 0x00b2bb00
0xabb9b2: MOV R12D, 0x16
0xabb9b8: TEST EAX, EAX
0xabb9ba: JNZ 0x00abbd2d
0xabb9c0: MOV RCX, qword ptr [R14]
0xabb9c3: TEST RCX, RCX
0xabb9c6: JZ 0x00abb9e2
0xabb9c8: MOV RAX, qword ptr [R14 + 0x10]
0xabb9cc: MOV qword ptr [RBP + -0xf0], RAX
0xabb9d3: CMP dword ptr [R14 + 0x20], 0x40000000
0xabb9db: JZ 0x00abb9fb
0xabb9dd: JMP 0x00abbd2d
0xabb9e2: MOV qword ptr [RBP + -0xf0], 0x0
0xabb9ed: CMP dword ptr [R14 + 0x20], 0x40000000
0xabb9f5: JNZ 0x00abbd2d
0xabb9fb: MOV RAX, qword ptr [R13 + 0x8]
0xabb9ff: MOV R12, qword ptr [R14 + 0x8]
0xabba03: MOV qword ptr [RBP + -0xd8], RCX
0xabba0a: MOV qword ptr [RBP + -0x118], R14
0xabba11: MOV qword ptr [RBP + -0x100], R13
0xabba18: MOV EDI, dword ptr [RAX + 0xbc]
0xabba1e: MOV RBX, qword ptr [RAX + 0x200]
0xabba25: CALL 0x00ab54e0
0xabba2a: MOV RDI, RBX
0xabba2d: MOV dword ptr [RBP + -0xdc], EAX
0xabba33: XOR R14D, R14D
0xabba36: XOR ESI, ESI
0xabba38: XOR EDX, EDX
0xabba3a: CALL 0x002c6820
0xabba3f: MOV RDI, RBX
0xabba42: MOV RBX, qword ptr [RBX + 0x8]
0xabba46: CMP R12, 0x48
0xabba4a: MOV EAX, 0x48
0xabba4f: LEA R15, [RBP + -0x78]
0xabba53: MOV qword ptr [RBP + -0x110], R12
0xabba5a: MOV qword ptr [RBP + -0xf8], -0x1
0xabba65: CMOVC RAX, R12
0xabba69: XOR R13D, R13D
0xabba6c: MOV qword ptr [RBP + -0xe8], RDI
0xabba73: MOV qword ptr [RBP + -0x108], RAX
0xabba7a: JMP 0x00abba9a
0xabba80: MOV RAX, 0x80000000000
0xabba8a: INC R13
0xabba8d: DEC RAX
0xabba90: CMP qword ptr [RBX + 0x20], RAX
0xabba94: JA 0x00abbb46
0xabba9a: XOR R12D, R12D
0xabba9d: CMP RBX, RDI
0xabbaa0: JZ 0x00abbb46
0xabbaa6: MOV RAX, qword ptr [RBX + 0x20]
0xabbaaa: MOV RSI, RBX
0xabbaad: MOV RCX, R15
0xabbab0: MOV R8D, 0x1
0xabbab6: MOV R9D, 0x1
0xabbabc: CMP R14, RAX
0xabbabf: CMOVBE R14, RAX
0xabbac3: MOV RDX, R14
0xabbac6: CALL 0x00aba710
0xabbacb: CMP R13, qword ptr [RBP + -0xf0]
0xabbad2: JNC 0x00abbb16
0xabbad4: MOV RDI, qword ptr GS:[0x0]
0xabbadd: LEA RSI, [0x134f297]
0xabbae4: XOR EDX, EDX
0xabbae6: CALL 0x00c1a3e0
0xabbaeb: MOV RDI, R15
0xabbaee: MOV R15, qword ptr [RBP + -0xd8]
0xabbaf5: MOV RDX, qword ptr [RBP + -0x108]
0xabbafc: MOV RSI, R15
0xabbaff: CALL 0x002591d0
0xabbb04: TEST EAX, EAX
0xabbb06: JNZ 0x00abbb38
0xabbb08: ADD R15, qword ptr [RBP + -0x110]
0xabbb0f: MOV qword ptr [RBP + -0xd8], R15
0xabbb16: MOV RDI, qword ptr [RBP + -0xe8]
0xabbb1d: MOV R14, qword ptr [RBP + -0x70]
0xabbb21: LEA R15, [RBP + -0x78]
0xabbb25: CMP qword ptr [RBX + 0x28], R14
0xabbb29: JA 0x00abba80
0xabbb2f: MOV RBX, qword ptr [RBX + 0x8]
0xabbb33: JMP 0x00abba80
0xabbb38: MOV RDI, qword ptr [RBP + -0xe8]
0xabbb3f: MOV R12D, EAX
0xabbb42: LEA R15, [RBP + -0x78]
0xabbb46: CMP dword ptr [RBP + -0xdc], 0x0
0xabbb4d: JNZ 0x00abbb97
0xabbb4f: MOV R14, 0x80000000000
0xabbb59: TEST R12D, R12D
0xabbb5c: JZ 0x00abbbc2
0xabbb5e: MOV R15, qword ptr [RBP + -0xd8]
0xabbb65: MOV RAX, qword ptr [RBP + -0x100]
0xabbb6c: MOV qword ptr [RBP + -0xd8], R15
0xabbb73: MOV RAX, qword ptr [RAX + 0x8]
0xabbb77: MOV EDI, dword ptr [RAX + 0xbc]
0xabbb7d: CALL 0x00ab5690
0xabbb82: MOV RDI, qword ptr [RBP + -0xe8]
0xabbb89: LEA R15, [RBP + -0x78]
0xabbb8d: MOV dword ptr [RBP + -0xdc], 0xffffffff
0xabbb97: TEST R12D, R12D
0xabbb9a: JNZ 0x00abbceb
0xabbba0: CMP RBX, RDI
0xabbba3: JZ 0x00abbceb
0xabbba9: CMP R14, qword ptr [RBP + -0xf8]
0xabbbb0: MOV qword ptr [RBP + -0xf8], R14
0xabbbb7: JNZ 0x00abba9a
0xabbbbd: JMP 0x00abbd4b
0xabbbc2: MOV R15, qword ptr [RBP + -0xd8]
0xabbbc9: JMP 0x00abbbf1
0xabbbd0: MOV R14, qword ptr [RBP + -0xc8]
0xabbbd7: ADD R15, qword ptr [RBP + -0x110]
0xabbbde: INC R13
0xabbbe1: MOV RAX, R14
0xabbbe4: SHR RAX, 0x28
0xabbbe8: CMP EAX, 0xf
0xabbbeb: JNC 0x00abbb65
0xabbbf1: MOV RAX, qword ptr [RBP + -0x100]
0xabbbf8: MOV RSI, R14
0xabbbfb: MOV EDX, 0x1
0xabbc00: LEA RCX, [RBP + -0xd0]
0xabbc07: MOV RAX, qword ptr [RAX + 0x8]
0xabbc0b: MOV EDI, dword ptr [RAX + 0xbc]
0xabbc11: CALL 0x00ab67c0
0xabbc16: XOR R12D, R12D
0xabbc19: TEST EAX, EAX
0xabbc1b: JNZ 0x00abbb65
0xabbc21: MOV ESI, 0x48
0xabbc26: LEA RDI, [RBP + -0x78]
0xabbc2a: CALL 0x00258ff0
0xabbc2f: MOV RAX, qword ptr [RBP + -0xd0]
0xabbc36: MOV RCX, qword ptr [RBP + -0xc8]
0xabbc3d: MOV RSI, qword ptr [RBP + -0xc0]
0xabbc44: MOVZX EDX, byte ptr [RBP + -0xb0]
0xabbc4b: LEA RDI, [RBP + -0x57]
0xabbc4f: MOV qword ptr [RBP + -0x78], RAX
0xabbc53: RORX RAX, qword ptr [RBP + -0xb8], 0x20
0xabbc5d: MOV qword ptr [RBP + -0x70], RCX
0xabbc61: MOV qword ptr [RBP + -0x68], RSI
0xabbc65: SHL DL, 0x6
0xabbc68: LEA RSI, [RBP + -0x9b]
0xabbc6f: AND DL, 0x40
0xabbc72: MOV qword ptr [RBP + -0x60], RAX
0xabbc76: MOVZX EAX, byte ptr [RBP + -0xa0]
0xabbc7d: MOVZX ECX, byte ptr [RBP + -0x58]
0xabbc81: SHL AL, 0x5
0xabbc84: AND AL, 0x20
0xabbc86: AND CL, 0x9f
0xabbc89: OR CL, AL
0xabbc8b: OR DL, CL
0xabbc8d: MOVZX ECX, byte ptr [RBP + -0x9c]
0xabbc94: MOV byte ptr [RBP + -0x58], DL
0xabbc97: MOV EDX, 0x20
0xabbc9c: MOV byte ptr [RBP + -0x37], CL
0xabbc9f: CALL 0x00957b70
0xabbca4: CMP R13, qword ptr [RBP + -0xf0]
0xabbcab: JNC 0x00abbbd0
0xabbcb1: MOV RDI, qword ptr GS:[0x0]
0xabbcba: LEA RSI, [0x134f297]
0xabbcc1: XOR EDX, EDX
0xabbcc3: CALL 0x00c1a3e0
0xabbcc8: MOV RDX, qword ptr [RBP + -0x108]
0xabbccf: LEA RDI, [RBP + -0x78]
0xabbcd3: MOV RSI, R15
0xabbcd6: CALL 0x002591d0
0xabbcdb: TEST EAX, EAX
0xabbcdd: JZ 0x00abbbd0
0xabbce3: MOV R12D, EAX
0xabbce6: JMP 0x00abbb65
0xabbceb: XOR ESI, ESI
0xabbced: XOR EDX, EDX
0xabbcef: CALL 0x002c6870
0xabbcf4: LEA RBX, [0x391c310]
0xabbcfb: MOV RAX, qword ptr [RBP + -0x118]
0xabbd02: TEST R12D, R12D
0xabbd05: JNZ 0x00abbd2d
0xabbd07: MOV RDI, qword ptr [RAX + 0x18]
0xabbd0b: MOV R12D, 0x0
0xabbd11: TEST RDI, RDI
0xabbd14: JZ 0x00abbd2d
0xabbd16: MOV RSI, R13
0xabbd19: CALL 0x00259720
0xabbd1e: XOR ECX, ECX
0xabbd20: CMP EAX, -0x1
0xabbd23: MOV R12D, 0xe
0xabbd29: CMOVNZ R12D, ECX
0xabbd2d: MOV RAX, qword ptr [RBX]
0xabbd30: CMP RAX, qword ptr [RBP + -0x30]
0xabbd34: JNZ 0x00abbd71
0xabbd36: MOV EAX, R12D
0xabbd39: ADD RSP, 0xf8
0xabbd40: POP RBX
0xabbd41: POP R12
0xabbd43: POP R13
0xabbd45: POP R14
0xabbd47: POP R15
0xabbd49: POP RBP
0xabbd4a: RET
0xabbd4b: CALL 0x007f1950
0xabbd50: LEA RDI, [0xabbd4b]
0xabbd57: CALL 0x007f1810
0xabbd5c: LEA RSI, [0x1395a92]
0xabbd63: MOV EDI, 0x17
0xabbd68: XOR EAX, EAX
0xabbd6a: CALL 0x00c9aa10
0xabbd6f: UD2
0xabbd71: CALL 0x006fd6b0
0xabbd76: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abbd80 RVA 0xabbd80 | Evidence ev_4b38709f0844b2b81b7c96c48d75a703ae14ea1dce65bda1e85cf421cacdadf8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sub_abbd80:
0xabbd80: PUSH RBP
0xabbd81: MOV RBP, RSP
0xabbd84: PUSH R15
0xabbd86: PUSH R14
0xabbd88: PUSH R13
0xabbd8a: PUSH R12
0xabbd8c: PUSH RBX
0xabbd8d: PUSH RAX
0xabbd8e: MOV RBX, qword ptr [RSI]
0xabbd91: MOV RCX, qword ptr [RSI + 0x8]
0xabbd95: MOV EAX, 0x16
0xabbd9a: ADD RCX, RBX
0xabbd9d: JC 0x00abbe44
0xabbda3: LEA R14, [RCX + 0x3fff]
0xabbdaa: AND R14, -0x4000
0xabbdb1: CMP R14, RCX
0xabbdb4: JC 0x00abbe44
0xabbdba: MOV R15D, dword ptr [RSI + 0x10]
0xabbdbe: MOV R12, RSI
0xabbdc1: MOV RSI, qword ptr [RDI + 0x8]
0xabbdc5: MOV R13, RDI
0xabbdc8: MOV EDI, R15D
0xabbdcb: CALL 0x003c33e0
0xabbdd0: TEST EAX, EAX
0xabbdd2: JZ 0x00abbdf5
0xabbdd4: MOV RCX, qword ptr [R13 + 0x8]
0xabbdd8: MOV EDX, dword ptr [R12 + 0x18]
0xabbddd: MOV EAX, 0x16
0xabbde2: CMP byte ptr [RCX + 0xc81], 0x0
0xabbde9: JZ 0x00abbdfc
0xabbdeb: TEST EDX, 0xfc08
0xabbdf1: JNZ 0x00abbe44
0xabbdf3: JMP 0x00abbe01
0xabbdf5: MOV EAX, 0x16
0xabbdfa: JMP 0x00abbe44
0xabbdfc: TEST DL, 0x8
0xabbdff: JNZ 0x00abbe44
0xabbe01: MOV EAX, EDX
0xabbe03: MOV RDI, qword ptr [RCX + 0x200]
0xabbe0a: AND RBX, -0x4000
0xabbe11: MOV ECX, R15D
0xabbe14: SHR EAX, 0x1
0xabbe16: MOV RSI, RBX
0xabbe19: AND EAX, 0x141
0xabbe1e: OR EAX, EDX
0xabbe20: MOV RDX, R14
0xabbe23: MOVZX R8D, AX
0xabbe27: CALL 0x002cd3c0
0xabbe2c: MOV ECX, EAX
0xabbe2e: MOV EAX, 0x16
0xabbe33: CMP ECX, 0x9
0xabbe36: JA 0x00abbe44
0xabbe38: MOV EAX, ECX
0xabbe3a: LEA RDX, [0x18dbfb4]
0xabbe41: MOV EAX, dword ptr [RDX + RAX*0x4]
0xabbe44: ADD RSP, 0x8
0xabbe48: POP RBX
0xabbe49: POP R12
0xabbe4b: POP R13
0xabbe4d: POP R14
0xabbe4f: POP R15
0xabbe51: POP RBP
0xabbe52: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_548 RVA 0xabbe60 | Evidence ev_ab5c89413b5a43b7f0ae9fc855df45b95a38cd06053a20c03453748b732e079c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_548:
0xabbe60: PUSH RBP
0xabbe61: MOV RBP, RSP
0xabbe64: PUSH R15
0xabbe66: PUSH R14
0xabbe68: PUSH R13
0xabbe6a: PUSH R12
0xabbe6c: PUSH RBX
0xabbe6d: SUB RSP, 0x88
0xabbe74: LEA R14, [0x391c310]
0xabbe7b: MOV RBX, RSI
0xabbe7e: MOV RAX, qword ptr [R14]
0xabbe81: MOV qword ptr [RBP + -0x30], RAX
0xabbe85: MOV R13D, dword ptr [RSI + 0x18]
0xabbe89: TEST R13D, R13D
0xabbe8c: JS 0x00abbef7
0xabbe8e: MOV RAX, qword ptr [RDI + 0x8]
0xabbe92: XOR ECX, ECX
0xabbe94: CMP byte ptr [RAX + 0xc81], 0x0
0xabbe9b: MOV EAX, 0x16
0xabbea0: SETNZ CL
0xabbea3: SHL ECX, 0x1d
0xabbea6: ADD ECX, 0xe0bffb6f
0xabbeac: TEST dword ptr [RBX + 0x8], ECX
0xabbeaf: JNZ 0x00abc371
0xabbeb5: LEA RAX, [RBP + -0x78]
0xabbeb9: MOV word ptr [RDI + 0x116], 0x1
0xabbec2: MOV byte ptr [RDI + 0x5f0], 0x0
0xabbec9: MOV qword ptr [RBP + -0x78], 0x0
0xabbed1: MOV qword ptr [RBP + -0xa8], RDI
0xabbed8: MOV qword ptr [RBP + -0x70], RAX
0xabbedc: TEST R13, R13
0xabbedf: JZ 0x00abc24d
0xabbee5: MOV dword ptr [RBP + -0x9c], 0xffffffff
0xabbeef: XOR R14D, R14D
0xabbef2: XOR R15D, R15D
0xabbef5: JMP 0x00abbf68
0xabbef7: MOV RDI, qword ptr [RBX + 0x20]
0xabbefb: MOV EAX, 0x16
0xabbf00: TEST RDI, RDI
0xabbf03: JZ 0x00abc371
0xabbf09: XOR ESI, ESI
0xabbf0b: CALL 0x00259790
0xabbf10: MOV EAX, 0x16
0xabbf15: JMP 0x00abc371
0xabbf68: MOV R12, qword ptr [RBX + 0x10]
0xabbf6c: MOV RDI, qword ptr GS:[0x0]
0xabbf75: LEA RSI, [0x1397f3d]
0xabbf7c: XOR EDX, EDX
0xabbf7e: ADD R12, R14
0xabbf81: CALL 0x00c1a3e0
0xabbf86: MOV EDX, 0x20
0xabbf8b: MOV RDI, R12
0xabbf8e: LEA RSI, [RBP + -0x98]
0xabbf95: CALL 0x00259280
0xabbf9a: TEST EAX, EAX
0xabbf9c: JNZ 0x00abc2b8
0xabbfa2: MOV ECX, dword ptr [RBP + -0x7c]
0xabbfa5: CMP ECX, 0x4
0xabbfa8: JZ 0x00abbfd3
0xabbfaa: CMP qword ptr [RBP + -0x78], 0x0
0xabbfaf: JZ 0x00abbfd3
0xabbfb1: LEA RDI, [RBP + -0x78]
0xabbfb5: LEA RSI, [RBP + -0x68]
0xabbfb9: CALL 0x00abc3b0
0xabbfbe: TEST EAX, EAX
0xabbfc0: JNZ 0x00abc29e
0xabbfc6: MOV ECX, dword ptr [RBP + -0x7c]
0xabbfc9: MOV dword ptr [RBP + -0x9c], 0xffffffff
0xabbfd3: MOV EAX, 0x16
0xabbfd8: CMP ECX, 0x4
0xabbfdb: JA 0x00abc2b8
0xabbfe1: MOV ECX, ECX
0xabbfe3: LEA RDX, [0x18dbf54]
0xabbfea: MOVSXD RCX, dword ptr [RDX + RCX*0x4]
0xabbfee: ADD RCX, RDX
0xabbff1: JMP RCX
0xabc24d: XOR EAX, EAX
0xabc24f: XOR R15D, R15D
0xabc252: JMP 0x00abc2ec
0xabc29e: MOV ECX, dword ptr [RBP + -0x9c]
0xabc2a4: ADD ECX, dword ptr [RBP + -0x68]
0xabc2a7: MOV R15D, ECX
0xabc2aa: JMP 0x00abc2b8
0xabc2b8: MOV RSI, qword ptr [RBP + -0x78]
0xabc2bc: TEST RSI, RSI
0xabc2bf: JZ 0x00abc2ec
0xabc2c1: MOV R14D, EAX
0xabc2c4: NOP word ptr CS:[RAX + RAX*0x1]
0xabc2d0: MOV RDI, qword ptr [0x03bf6e18]
0xabc2d7: MOV R12, qword ptr [RSI]
0xabc2da: XOR EDX, EDX
0xabc2dc: CALL 0x0043c0c0
0xabc2e1: MOV RSI, R12
0xabc2e4: TEST R12, R12
0xabc2e7: JNZ 0x00abc2d0
0xabc2e9: MOV EAX, R14D
0xabc2ec: MOV RCX, qword ptr [RBP + -0xa8]
0xabc2f3: MOV byte ptr [RCX + 0x116], 0x0
0xabc2fa: CMP byte ptr [RCX + 0x117], 0x0
0xabc301: JZ 0x00abc355
0xabc303: LEA RCX, [0x1a962e8]
0xabc30a: MOV R14D, EAX
0xabc30d: MOV RAX, qword ptr [RCX]
0xabc310: MOV R12, qword ptr [RAX + 0x40]
0xabc314: LEA RAX, [0x260ce8]
0xabc31b: SUB RAX, R12
0xabc31e: ROR RAX, 0x3
0xabc322: CMP RAX, 0x6ff
0xabc328: JA 0x00abc393
0xabc32a: MOV R13, qword ptr [RBP + -0xa8]
0xabc331: MOV RAX, qword ptr [R13 + 0x8]
0xabc335: MOV RDI, qword ptr [RAX + 0x200]
0xabc33c: CALL R12
0xabc33f: CMP byte ptr [R13 + 0x5f0], 0x0
0xabc347: MOV EAX, R14D
0xabc34a: JZ 0x00abc355
0xabc34c: SUB.LOCK qword ptr [0x02d616c0], 0x1
0xabc355: MOV RDI, qword ptr [RBX + 0x20]
0xabc359: TEST RDI, RDI
0xabc35c: JZ 0x00abc36a
0xabc35e: MOV ESI, R15D
0xabc361: MOV EBX, EAX
0xabc363: CALL 0x00259790
0xabc368: MOV EAX, EBX
0xabc36a: LEA R14, [0x391c310]
0xabc371: MOV RCX, qword ptr [R14]
0xabc374: CMP RCX, qword ptr [RBP + -0x30]
0xabc378: JNZ 0x00abc38c
0xabc37a: ADD RSP, 0x88
0xabc381: POP RBX
0xabc382: POP R12
0xabc384: POP R13
0xabc386: POP R14
0xabc388: POP R15
0xabc38a: POP RBP
0xabc38b: RET
0xabc38c: CALL 0x006fd6b0
0xabc391: UD2
0xabc393: LEA RDI, [0x2888cf0]
0xabc39a: MOV RSI, R12
0xabc39d: CALL 0x0044f8c0
0xabc3a2: JMP 0x00abc32a


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abc3b0 RVA 0xabc3b0 | Evidence ev_862e7c7e53da059d7a77bdd62498f2bc0b4fc7d6778b5ed856e02961e4e75cbf | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sub_abc3b0:
0xabc3b0: PUSH RBP
0xabc3b1: MOV RBP, RSP
0xabc3b4: PUSH R15
0xabc3b6: PUSH R14
0xabc3b8: PUSH R13
0xabc3ba: PUSH R12
0xabc3bc: PUSH RBX
0xabc3bd: SUB RSP, 0x18
0xabc3c1: LEA RBX, [0x391c310]
0xabc3c8: MOV R14, RDI
0xabc3cb: MOV R12, RSI
0xabc3ce: MOV RAX, qword ptr [RBX]
0xabc3d1: MOV qword ptr [RBP + -0x30], RAX
0xabc3d5: MOV R13, qword ptr GS:[0x0]
0xabc3de: MOV RDI, qword ptr [R13 + 0x140]
0xabc3e5: CALL 0x00609560
0xabc3ea: MOV R15D, 0x1
0xabc3f0: TEST EAX, EAX
0xabc3f2: JNZ 0x00abc4e4
0xabc3f8: MOV RDI, qword ptr [R13 + 0x140]
0xabc3ff: CALL 0x006095a0
0xabc404: TEST EAX, EAX
0xabc406: JNZ 0x00abc4e4
0xabc40c: MOV dword ptr [RBP + -0x34], 0x0
0xabc413: MOV qword ptr [RBP + -0x40], R12
0xabc417: MOV RBX, qword ptr [R14]
0xabc41a: TEST RBX, RBX
0xabc41d: JZ 0x00abc473
0xabc41f: MOV R12D, 0x1
0xabc425: MOV R15D, 0x16
0xabc42b: NOP dword ptr [RAX + RAX*0x1]
0xabc430: MOV RAX, qword ptr [RBX + 0x18]
0xabc434: ADD RAX, qword ptr [RBX + 0x8]
0xabc438: JC 0x00abc4a2
0xabc43a: LEA RCX, [RAX + 0x3fff]
0xabc441: AND RCX, -0x4000
0xabc448: CMP RCX, RAX
0xabc44b: JC 0x00abc4a2
0xabc44d: MOVSX EDI, byte ptr [RBX + 0x21]
0xabc451: MOV RSI, qword ptr [R13 + 0x8]
0xabc455: CALL 0x003c33e0
0xabc45a: TEST EAX, EAX
0xabc45c: JZ 0x00abc4a2
0xabc45e: TEST byte ptr [RBX + 0x20], 0x8
0xabc462: JNZ 0x00abc4a2
0xabc464: MOV dword ptr [RBP + -0x34], R12D
0xabc468: INC R12D
0xabc46b: MOV RBX, qword ptr [RBX]
0xabc46e: TEST RBX, RBX
0xabc471: JNZ 0x00abc430
0xabc473: MOV RAX, qword ptr [R13 + 0x8]
0xabc477: LEA RDX, [RBP + -0x34]
0xabc47b: MOV RSI, R14
0xabc47e: MOV RDI, qword ptr [RAX + 0x200]
0xabc485: CALL 0x002cdc10
0xabc48a: MOV R15D, 0x16
0xabc490: CMP EAX, 0x9
0xabc493: JA 0x00abc4a2
0xabc495: MOV EAX, EAX
0xabc497: LEA RCX, [0x18dbfb4]
0xabc49e: MOV R15D, dword ptr [RCX + RAX*0x4]
0xabc4a2: MOV RSI, qword ptr [R14]
0xabc4a5: TEST RSI, RSI
0xabc4a8: JZ 0x00abc4c9
0xabc4aa: NOP word ptr [RAX + RAX*0x1]
0xabc4b0: MOV RDI, qword ptr [0x03bf6e18]
0xabc4b7: MOV RBX, qword ptr [RSI]
0xabc4ba: XOR EDX, EDX
0xabc4bc: CALL 0x0043c0c0
0xabc4c1: MOV RSI, RBX
0xabc4c4: TEST RBX, RBX
0xabc4c7: JNZ 0x00abc4b0
0xabc4c9: MOV qword ptr [R14], 0x0
0xabc4d0: MOV qword ptr [R14 + 0x8], R14
0xabc4d4: LEA RBX, [0x391c310]
0xabc4db: MOV RCX, qword ptr [RBP + -0x40]
0xabc4df: MOV EAX, dword ptr [RBP + -0x34]
0xabc4e2: MOV dword ptr [RCX], EAX
0xabc4e4: MOV RAX, qword ptr [RBX]
0xabc4e7: CMP RAX, qword ptr [RBP + -0x30]
0xabc4eb: JNZ 0x00abc4ff
0xabc4ed: MOV EAX, R15D
0xabc4f0: ADD RSP, 0x18
0xabc4f4: POP RBX
0xabc4f5: POP R12
0xabc4f7: POP R13
0xabc4f9: POP R14
0xabc4fb: POP R15
0xabc4fd: POP RBP
0xabc4fe: RET
0xabc4ff: CALL 0x006fd6b0
0xabc504: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_559 RVA 0xabc510 | Evidence ev_fce39945524d3a5c1b09e9564a7c639882765fa755ebf5f4a2435f50b43dbc3a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_559:
0xabc510: PUSH RBP
0xabc511: MOV RBP, RSP
0xabc514: PUSH R15
0xabc516: PUSH R14
0xabc518: PUSH R12
0xabc51a: PUSH RBX
0xabc51b: MOV RBX, qword ptr GS:[0x0]
0xabc524: MOV RAX, qword ptr [RBX + 0x8]
0xabc528: MOV ECX, 0x16
0xabc52d: MOV R14D, dword ptr [RAX + 0x5c0]
0xabc534: MOV EAX, 0x16
0xabc539: LEA EDX, [R14 + -0x2]
0xabc53d: CMP EDX, -0x3
0xabc540: JC 0x00abc581
0xabc542: CMP R14D, -0x1
0xabc546: JZ 0x00abc57c
0xabc548: MOV R15, RDI
0xabc54b: MOV R12, RSI
0xabc54e: MOV RDI, RBX
0xabc551: MOV ESI, 0x2ad
0xabc556: CALL 0x00adfa30
0xabc55b: MOV ECX, EAX
0xabc55d: MOV RSI, R12
0xabc560: MOV RDI, R15
0xabc563: MOV EAX, 0x16
0xabc568: TEST ECX, ECX
0xabc56a: JNZ 0x00abc581
0xabc56c: MOV RCX, qword ptr [RBX + 0x8]
0xabc570: MOV dword ptr [RCX + 0x5c0], R14D
0xabc577: MOV ECX, R14D
0xabc57a: JMP 0x00abc581
0xabc57c: MOV ECX, 0xffffffff
0xabc581: MOVSXD RCX, ECX
0xabc584: MOV qword ptr [RDI + 0x408], RCX
0xabc58b: MOV R14D, dword ptr [RSI]
0xabc58e: LEA ECX, [R14 + -0x2]
0xabc592: CMP ECX, -0x3
0xabc595: JC 0x00abc5d8
0xabc597: XOR EAX, EAX
0xabc599: CMP R14D, -0x1
0xabc59d: JZ 0x00abc5d8
0xabc59f: MOV ESI, 0x2ad
0xabc5a4: CALL 0x00adfa30
0xabc5a9: TEST EAX, EAX
0xabc5ab: JNZ 0x00abc5d8
0xabc5ad: MOV RAX, R14
0xabc5b0: LEA RCX, [0x3535ea0]
0xabc5b7: SHL RAX, 0x7
0xabc5bb: LEA RAX, [RAX + R14*0x8]
0xabc5bf: CMP dword ptr [RCX + RAX*0x1 + 0x70], 0x0
0xabc5c4: MOV EAX, 0x16
0xabc5c9: JZ 0x00abc5d8
0xabc5cb: MOV RAX, qword ptr [RBX + 0x8]
0xabc5cf: MOV dword ptr [RAX + 0x5c0], R14D
0xabc5d6: XOR EAX, EAX
0xabc5d8: POP RBX
0xabc5d9: POP R12
0xabc5db: POP R14
0xabc5dd: POP R15
0xabc5df: POP RBP
0xabc5e0: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_588 RVA 0xabc5f0 | Evidence ev_1230a6df00feef96e6b74390f2018bebeeed24a4a4636478bbc2901671ef49a5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_588:
0xabc5f0: PUSH RBP
0xabc5f1: MOV RBP, RSP
0xabc5f4: PUSH R15
0xabc5f6: PUSH R14
0xabc5f8: PUSH R13
0xabc5fa: PUSH R12
0xabc5fc: PUSH RBX
0xabc5fd: SUB RSP, 0x38
0xabc601: LEA R12, [0x391c310]
0xabc608: MOV RAX, qword ptr [R12]
0xabc60c: MOV qword ptr [RBP + -0x30], RAX
0xabc610: MOV RAX, qword ptr [RDI + 0x8]
0xabc614: MOV R13, qword ptr [RSI]
0xabc617: MOV RBX, qword ptr [RAX + 0x200]
0xabc61e: MOV EAX, 0x16
0xabc623: CMP qword ptr [RBX + 0x20], R13
0xabc627: JA 0x00abc6ee
0xabc62d: MOV RCX, qword ptr [RBX + 0x28]
0xabc631: MOV R15, qword ptr [RSI + 0x8]
0xabc635: SUB RCX, R13
0xabc638: SETBE DL
0xabc63b: CMP RCX, R15
0xabc63e: SETC CL
0xabc641: OR CL, DL
0xabc643: JNZ 0x00abc6ee
0xabc649: MOV qword ptr [RBP + -0x58], RDI
0xabc64d: MOV R14, qword ptr [RSI + 0x10]
0xabc651: LEA RSI, [0x135a084]
0xabc658: XOR EDX, EDX
0xabc65a: MOV RDI, qword ptr GS:[0x0]
0xabc663: CALL 0x00c1a3e0
0xabc668: LEA RSI, [RBP + -0x50]
0xabc66c: MOV EDX, 0x20
0xabc671: MOV RDI, R14
0xabc674: XOR ECX, ECX
0xabc676: CALL 0x00259900
0xabc67b: TEST EAX, EAX
0xabc67d: JNZ 0x00abc6ee
0xabc67f: MOV EAX, R13D
0xabc682: MOV R14, R13
0xabc685: SHR R13, 0x28
0xabc689: AND EAX, 0x3fff
0xabc68e: AND R14, -0x4000
0xabc695: LEA RDX, [R15 + RAX*0x1 + 0x3fff]
0xabc69d: AND RDX, -0x4000
0xabc6a4: LEA R15, [RDX + R14*0x1]
0xabc6a8: CMP R13D, 0xe
0xabc6ac: JA 0x00abc6da
0xabc6ae: MOV RAX, 0x80000000001
0xabc6b8: CMP R15, RAX
0xabc6bb: JC 0x00abc6da
0xabc6bd: MOV RAX, qword ptr [RBP + -0x58]
0xabc6c1: LEA RCX, [RBP + -0x50]
0xabc6c5: MOV RSI, R14
0xabc6c8: MOV RDI, qword ptr [RAX + 0x8]
0xabc6cc: CALL 0x0081f770
0xabc6d1: CMP EAX, 0xd
0xabc6d4: JZ 0x00abc6da
0xabc6d6: TEST EAX, EAX
0xabc6d8: JNZ 0x00abc6ee
0xabc6da: LEA RCX, [RBP + -0x50]
0xabc6de: MOV RDI, RBX
0xabc6e1: MOV RSI, R14
0xabc6e4: MOV RDX, R15
0xabc6e7: CALL 0x002d2e50
0xabc6ec: XOR EAX, EAX
0xabc6ee: MOV RCX, qword ptr [R12]
0xabc6f2: CMP RCX, qword ptr [RBP + -0x30]
0xabc6f6: JNZ 0x00abc707
0xabc6f8: ADD RSP, 0x38
0xabc6fc: POP RBX
0xabc6fd: POP R12
0xabc6ff: POP R13
0xabc701: POP R14
0xabc703: POP R15
0xabc705: POP RBP
0xabc706: RET
0xabc707: CALL 0x006fd6b0
0xabc70c: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_607 RVA 0xabc710 | Evidence ev_f46d1c40bc8a04c4e5503a98663bf84f2d49756a4b709a8b4590f337dda0f907 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_607:
0xabc710: PUSH RBP
0xabc711: MOV RBP, RSP
0xabc714: PUSH R15
0xabc716: PUSH R14
0xabc718: PUSH R13
0xabc71a: PUSH R12
0xabc71c: PUSH RBX
0xabc71d: SUB RSP, 0x1b8
0xabc724: LEA RAX, [0x391c310]
0xabc72b: MOV R15, RDI
0xabc72e: MOV EDX, 0x2
0xabc733: MOV RBX, RSI
0xabc736: MOV RAX, qword ptr [RAX]
0xabc739: MOV qword ptr [RBP + -0x30], RAX
0xabc73d: MOV RDI, qword ptr [0x036d15e0]
0xabc744: MOV R12, qword ptr [RSI]
0xabc747: XOR ESI, ESI
0xabc749: CALL 0x0043b880
0xabc74e: MOV RDI, qword ptr GS:[0x0]
0xabc757: LEA RSI, [0x135a084]
0xabc75e: XOR EDX, EDX
0xabc760: MOV R14, RAX
0xabc763: CALL 0x00c1a3e0
0xabc768: MOV EDX, 0x400
0xabc76d: MOV RDI, R12
0xabc770: MOV RSI, R14
0xabc773: XOR ECX, ECX
0xabc775: CALL 0x00259900
0xabc77a: TEST EAX, EAX
0xabc77c: JZ 0x00abc786
0xabc77e: MOV R13D, EAX
0xabc781: JMP 0x00abc858
0xabc786: MOV qword ptr [RBP + -0x1d8], RBX
0xabc78d: SUB RSP, 0x8
0xabc791: MOV RBX, R15
0xabc794: LEA R15, [RBP + -0x118]
0xabc79b: MOV EDX, 0x144
0xabc7a0: XOR ESI, ESI
0xabc7a2: MOV ECX, 0x1
0xabc7a7: MOV R8, R14
0xabc7aa: MOV R9D, 0xffffff9c
0xabc7b0: MOV RDI, R15
0xabc7b3: PUSH RBX
0xabc7b4: PUSH 0x0
0xabc7b6: PUSH 0x0
0xabc7b8: CALL 0x005fa6e0
0xabc7bd: ADD RSP, 0x20
0xabc7c1: MOV RDI, R15
0xabc7c4: CALL 0x005f8c20
0xabc7c9: MOV R12, qword ptr [RBP + -0xb8]
0xabc7d0: MOV RDI, R15
0xabc7d3: MOV ESI, 0xc
0xabc7d8: MOV R13D, EAX
0xabc7db: CALL 0x005fa780
0xabc7e0: TEST R13D, R13D
0xabc7e3: JNZ 0x00abc858
0xabc7e5: CMP dword ptr [R12 + 0x1d4], 0x1
0xabc7ee: MOV R13D, 0x16
0xabc7f4: JNZ 0x00abc850
0xabc7f6: MOV RAX, qword ptr [RBX + 0x140]
0xabc7fd: LEA RCX, [0x1ada7f8]
0xabc804: LEA RSI, [RBP + -0x1a0]
0xabc80b: MOV R15, RBX
0xabc80e: MOV qword ptr [RBP + -0x1a0], RCX
0xabc815: MOV qword ptr [RBP + -0x198], R12
0xabc81c: MOV dword ptr [RBP + -0x190], 0x1
0xabc826: MOV qword ptr [RBP + -0x188], RAX
0xabc82d: MOV qword ptr [RBP + -0x180], RBX
0xabc834: MOV qword ptr [RBP + -0x178], 0x0
0xabc83f: MOV RDI, qword ptr [R12 + 0x8]
0xabc844: CALL 0x0058bb00
0xabc849: MOV R13D, EAX
0xabc84c: TEST EAX, EAX
0xabc84e: JZ 0x00abc892
0xabc850: MOV RDI, R12
0xabc853: CALL 0x0054a440
0xabc858: MOV RDI, qword ptr [0x036d15e0]
0xabc85f: MOV RSI, R14
0xabc862: XOR EDX, EDX
0xabc864: CALL 0x0043c0c0
0xabc869: LEA RAX, [0x391c310]
0xabc870: MOV RAX, qword ptr [RAX]
0xabc873: CMP RAX, qword ptr [RBP + -0x30]
0xabc877: JNZ 0x00abc9fe
0xabc87d: MOV EAX, R13D
0xabc880: ADD RSP, 0x1b8
0xabc887: POP RBX
0xabc888: POP R12
0xabc88a: POP R13
0xabc88c: POP R14
0xabc88e: POP R15
0xabc890: POP RBP
0xabc891: RET
0xabc892: MOV R9, qword ptr [R15 + 0x140]
0xabc899: MOV EDI, 0x7
0xabc89e: MOV RSI, R12
0xabc8a1: MOV ECX, 0x1
0xabc8a6: XOR EDX, EDX
0xabc8a8: XOR R8D, R8D
0xabc8ab: CALL 0x0045d9c0
0xabc8b0: MOV qword ptr [RBP + -0x1d0], RAX
0xabc8b7: TEST RAX, RAX
0xabc8ba: JZ 0x00abc8f7
0xabc8bc: LEA RDI, [RAX + 0x18]
0xabc8c0: XOR ESI, ESI
0xabc8c2: XOR EDX, EDX
0xabc8c4: MOV RBX, RAX
0xabc8c7: CALL 0x007d46a0
0xabc8cc: MOV RDI, RBX
0xabc8cf: CALL 0x00631850
0xabc8d4: TEST EAX, EAX
0xabc8d6: JZ 0x00abc8ff
0xabc8d8: MOV EDX, EAX
0xabc8da: LEA RDI, [0x132d3cb]
0xabc8e1: LEA RSI, [0x1318557]
0xabc8e8: XOR EAX, EAX
0xabc8ea: CALL 0x0025d410
0xabc8ef: MOV R13D, 0x8
0xabc8f5: JMP 0x00abc923
0xabc8f7: MOV R13D, 0xc
0xabc8fd: JMP 0x00abc923
0xabc8ff: MOV RDX, qword ptr [R15 + 0x140]
0xabc906: LEA RCX, [RBP + -0x1a0]
0xabc90d: MOV RDI, RBX
0xabc910: MOV RSI, R14
0xabc913: CALL 0x00632330
0xabc918: MOV RDI, RBX
0xabc91b: MOV R13D, EAX
0xabc91e: CALL 0x006321f0
0xabc923: MOV RAX, qword ptr [R15 + 0x140]
0xabc92a: LEA RCX, [0x1ada8f8]
0xabc931: LEA RSI, [RBP + -0x1c8]
0xabc938: MOV qword ptr [RBP + -0x1c8], RCX
0xabc93f: MOV qword ptr [RBP + -0x1c0], R12
0xabc946: MOV dword ptr [RBP + -0x1b8], 0x1
0xabc950: MOV qword ptr [RBP + -0x1b0], RAX
0xabc957: MOV qword ptr [RBP + -0x1a8], R15
0xabc95e: MOV RDI, qword ptr [R12 + 0x8]
0xabc963: CALL 0x0058bce0
0xabc968: MOV RDI, R12
0xabc96b: CALL 0x0054a440
0xabc970: MOV RDI, qword ptr [RBP + -0x1d0]
0xabc977: TEST RDI, RDI
0xabc97a: JZ 0x00abc981
0xabc97c: CALL 0x00461ba0
0xabc981: MOV RDI, qword ptr [0x036d15e0]
0xabc988: MOV RSI, R14
0xabc98b: XOR EDX, EDX
0xabc98d: CALL 0x0043c0c0
0xabc992: TEST R13D, R13D
0xabc995: JNZ 0x00abc869
0xabc99b: MOV RDI, qword ptr [R15 + 0x140]
0xabc9a2: LEA RSI, [RBP + -0x1a0]
0xabc9a9: ADD RDI, 0x58
0xabc9ad: CALL 0x00609c00
0xabc9b2: MOV R13D, 0x1
0xabc9b8: TEST EAX, EAX
0xabc9ba: JNZ 0x00abc869
0xabc9c0: MOV RAX, qword ptr [RBP + -0x1d8]
0xabc9c7: LEA RSI, [0x134f297]
0xabc9ce: XOR EDX, EDX
0xabc9d0: MOV RBX, qword ptr [RAX + 0x8]
0xabc9d4: MOV RDI, qword ptr GS:[0x0]
0xabc9dd: CALL 0x00c1a3e0
0xabc9e2: LEA RDI, [RBP + -0x1a0]
0xabc9e9: MOV EDX, 0x88
0xabc9ee: MOV RSI, RBX
0xabc9f1: CALL 0x002591d0
0xabc9f6: MOV R13D, EAX
0xabc9f9: JMP 0x00abc869
0xabc9fe: CALL 0x006fd6b0
0xabca03: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_613 RVA 0xabca10 | Evidence ev_a9e82d21b81c47e495a8c135c15d78b1a9e7235a580afa4cbe18b16396036028 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_613:
0xabca10: PUSH RBP
0xabca11: MOV RBP, RSP
0xabca14: PUSH R15
0xabca16: PUSH R14
0xabca18: PUSH R13
0xabca1a: PUSH R12
0xabca1c: PUSH RBX
0xabca1d: SUB RSP, 0x18
0xabca21: LEA R13, [0x391c310]
0xabca28: MOV RBX, RSI
0xabca2b: MOV RAX, qword ptr [R13]
0xabca2f: MOV qword ptr [RBP + -0x30], RAX
0xabca33: MOV RDI, qword ptr [RDI + 0x140]
0xabca3a: CALL 0x00608f90
0xabca3f: TEST EAX, EAX
0xabca41: JZ 0x00abcbb3
0xabca47: MOV EDI, dword ptr [RBX]
0xabca49: CALL 0x0053c170
0xabca4e: MOV R14, RAX
0xabca51: MOV EAX, 0x3
0xabca56: TEST R14, R14
0xabca59: JZ 0x00abcbd4
0xabca5f: MOV EAX, dword ptr [R14 + 0xb0]
0xabca66: TEST EAX, 0x2000
0xabca6b: JNZ 0x00abcbba
0xabca71: INC dword ptr [R14 + 0x358]
0xabca78: TEST EAX, 0x10000000
0xabca7d: JNZ 0x00abca87
0xabca7f: MOV RDI, R14
0xabca82: CALL 0x0053aa10
0xabca87: LEA R15, [R14 + 0x148]
0xabca8e: XOR ESI, ESI
0xabca90: XOR EDX, EDX
0xabca92: XOR ECX, ECX
0xabca94: MOV RDI, R15
0xabca97: CALL 0x004c6fa0
0xabca9c: MOV R12, qword ptr [R14 + 0x200]
0xabcaa3: XOR ESI, ESI
0xabcaa5: XOR EDX, EDX
0xabcaa7: MOV RDI, R12
0xabcaaa: CALL 0x002c6820
0xabcaaf: MOV qword ptr [RBP + -0x38], 0x0
0xabcab7: MOV RDI, qword ptr [R14 + 0x200]
0xabcabe: CALL 0x002c6e90
0xabcac3: MOV qword ptr [RBP + -0x40], RAX
0xabcac7: MOV RAX, qword ptr [R12 + 0x8]
0xabcacc: CMP RAX, R12
0xabcacf: JZ 0x00abcafc
0xabcad1: XOR ECX, ECX
0xabcad3: NOP dword ptr CS:[RAX + RAX*0x1]
0xabcae0: MOV RDX, qword ptr [RAX + 0x28]
0xabcae4: SUB RDX, qword ptr [RAX + 0x20]
0xabcae8: SHR RDX, 0xe
0xabcaec: ADD RCX, RDX
0xabcaef: MOV qword ptr [RBP + -0x38], RCX
0xabcaf3: MOV RAX, qword ptr [RAX + 0x8]
0xabcaf7: CMP RAX, R12
0xabcafa: JNZ 0x00abcae0
0xabcafc: MOV RDI, R12
0xabcaff: XOR ESI, ESI
0xabcb01: XOR EDX, EDX
0xabcb03: CALL 0x002c6870
0xabcb08: MOV RDI, R15
0xabcb0b: XOR ESI, ESI
0xabcb0d: XOR EDX, EDX
0xabcb0f: XOR ECX, ECX
0xabcb11: CALL 0x004c6a00
0xabcb16: MOVZX ECX, byte ptr [R14 + 0xb1]
0xabcb1e: MOV EAX, dword ptr [R14 + 0x358]
0xabcb25: SHR CL, 0x5
0xabcb28: DEC EAX
0xabcb2a: SETZ DL
0xabcb2d: MOV dword ptr [R14 + 0x358], EAX
0xabcb34: TEST CL, DL
0xabcb36: JZ 0x00abcb47
0xabcb38: ADD R14, 0x358
0xabcb3f: MOV RDI, R14
0xabcb42: CALL 0x00c06910
0xabcb47: MOV RDI, R15
0xabcb4a: XOR ESI, ESI
0xabcb4c: XOR EDX, EDX
0xabcb4e: XOR ECX, ECX
0xabcb50: CALL 0x004c6fa0
0xabcb55: MOV R14, qword ptr [RBX + 0x8]
0xabcb59: MOV RDI, qword ptr GS:[0x0]
0xabcb62: LEA RSI, [0x134f297]
0xabcb69: XOR EDX, EDX
0xabcb6b: CALL 0x00c1a3e0
0xabcb70: LEA RDI, [RBP + -0x40]
0xabcb74: MOV EDX, 0x8
0xabcb79: MOV RSI, R14
0xabcb7c: CALL 0x002591d0
0xabcb81: TEST EAX, EAX
0xabcb83: JNZ 0x00abcbd4
0xabcb85: MOV RBX, qword ptr [RBX + 0x10]
0xabcb89: MOV RDI, qword ptr GS:[0x0]
0xabcb92: LEA RSI, [0x134f297]
0xabcb99: XOR EDX, EDX
0xabcb9b: CALL 0x00c1a3e0
0xabcba0: LEA RDI, [RBP + -0x38]
0xabcba4: MOV EDX, 0x8
0xabcba9: MOV RSI, RBX
0xabcbac: CALL 0x002591d0
0xabcbb1: JMP 0x00abcbd4
0xabcbb3: MOV EAX, 0x1
0xabcbb8: JMP 0x00abcbd4
0xabcbba: ADD R14, 0x148
0xabcbc1: XOR ESI, ESI
0xabcbc3: XOR EDX, EDX
0xabcbc5: XOR ECX, ECX
0xabcbc7: MOV RDI, R14
0xabcbca: CALL 0x004c6fa0
0xabcbcf: MOV EAX, 0x3
0xabcbd4: MOV RCX, qword ptr [R13]
0xabcbd8: CMP RCX, qword ptr [RBP + -0x30]
0xabcbdc: JNZ 0x00abcbed
0xabcbde: ADD RSP, 0x18
0xabcbe2: POP RBX
0xabcbe3: POP R12
0xabcbe5: POP R13
0xabcbe7: POP R14
0xabcbe9: POP R15
0xabcbeb: POP RBP
0xabcbec: RET
0xabcbed: CALL 0x006fd6b0
0xabcbf2: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_615 RVA 0xabcc00 | Evidence ev_0a94b4d13de5ac5bccc55ee56b6722c86072cc4791c073bba4c3930bf4a71959 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_615:
0xabcc00: PUSH RBP
0xabcc01: MOV RBP, RSP
0xabcc04: PUSH R15
0xabcc06: PUSH R14
0xabcc08: PUSH RBX
0xabcc09: SUB RSP, 0xb8
0xabcc10: LEA R15, [0x391c310]
0xabcc17: MOV RBX, RSI
0xabcc1a: LEA RDX, [RBP + -0xd0]
0xabcc21: MOV RAX, qword ptr [R15]
0xabcc24: MOV qword ptr [RBP + -0x20], RAX
0xabcc28: MOV ESI, dword ptr [RSI]
0xabcc2a: CALL 0x00abccc0
0xabcc2f: TEST EAX, EAX
0xabcc31: JNZ 0x00abcc98
0xabcc33: MOV R14, qword ptr [RBX + 0x8]
0xabcc37: MOV RDI, qword ptr GS:[0x0]
0xabcc40: LEA RSI, [0x134f297]
0xabcc47: XOR EDX, EDX
0xabcc49: CALL 0x00c1a3e0
0xabcc4e: LEA RDI, [RBP + -0xd0]
0xabcc55: MOV EDX, 0x8
0xabcc5a: MOV RSI, R14
0xabcc5d: CALL 0x002591d0
0xabcc62: TEST EAX, EAX
0xabcc64: JNZ 0x00abcc98
0xabcc66: MOV RBX, qword ptr [RBX + 0x10]
0xabcc6a: MOV RDI, qword ptr GS:[0x0]
0xabcc73: LEA RSI, [0x134f297]
0xabcc7a: XOR EDX, EDX
0xabcc7c: LEA R14, [RBP + -0xc8]
0xabcc83: CALL 0x00c1a3e0
0xabcc88: MOV EDX, 0x8
0xabcc8d: MOV RDI, R14
0xabcc90: MOV RSI, RBX
0xabcc93: CALL 0x002591d0
0xabcc98: MOV RCX, qword ptr [R15]
0xabcc9b: CMP RCX, qword ptr [RBP + -0x20]
0xabcc9f: JNZ 0x00abccaf
0xabcca1: ADD RSP, 0xb8
0xabcca8: POP RBX
0xabcca9: POP R14
0xabccab: POP R15
0xabccad: POP RBP
0xabccae: RET
0xabccaf: CALL 0x006fd6b0
0xabccb4: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abccc0 RVA 0xabccc0 | Evidence ev_f0003a884b2e572eca5232efa48c9adf8c3c77dc5cbbc0143c5e3ccb8fffc32a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sub_abccc0:
0xabccc0: PUSH RBP
0xabccc1: MOV RBP, RSP
0xabccc4: PUSH R15
0xabccc6: PUSH R14
0xabccc8: PUSH R13
0xabccca: PUSH R12
0xabcccc: PUSH RBX
0xabcccd: SUB RSP, 0x38
0xabccd1: LEA R15, [0x391c310]
0xabccd8: MOV qword ptr [RBP + -0x40], RDX
0xabccdc: MOV RAX, qword ptr [R15]
0xabccdf: MOV qword ptr [RBP + -0x30], RAX
0xabcce3: TEST ESI, ESI
0xabcce5: JZ 0x00abcd00
0xabcce7: MOV RAX, qword ptr GS:[0x0]
0xabccf0: MOV RAX, qword ptr [RAX + 0x8]
0xabccf4: CMP ESI, dword ptr [RAX + 0xbc]
0xabccfa: JNZ 0x00abcfa2
0xabcd00: MOV RAX, qword ptr GS:[0x0]
0xabcd09: MOV RBX, qword ptr [RAX + 0x8]
0xabcd0d: XOR ESI, ESI
0xabcd0f: XOR EDX, EDX
0xabcd11: XOR ECX, ECX
0xabcd13: LEA RDI, [RBX + 0x148]
0xabcd1a: CALL 0x004c6a00
0xabcd1f: MOV EAX, dword ptr [RBX + 0xb0]
0xabcd25: TEST EAX, 0x2000
0xabcd2a: JNZ 0x00abcf1b
0xabcd30: INC dword ptr [RBX + 0x358]
0xabcd36: TEST EAX, 0x10000000
0xabcd3b: JNZ 0x00abcd45
0xabcd3d: MOV RDI, RBX
0xabcd40: CALL 0x0053aa10
0xabcd45: LEA RDI, [RBX + 0x148]
0xabcd4c: XOR ESI, ESI
0xabcd4e: XOR EDX, EDX
0xabcd50: XOR ECX, ECX
0xabcd52: MOV qword ptr [RBP + -0x48], RDI
0xabcd56: CALL 0x004c6fa0
0xabcd5b: MOV R12, qword ptr [RBX + 0x200]
0xabcd62: MOV qword ptr [RBP + -0x50], RBX
0xabcd66: XOR ESI, ESI
0xabcd68: XOR EDX, EDX
0xabcd6a: MOV RDI, R12
0xabcd6d: CALL 0x002c6820
0xabcd72: RDTSC
0xabcd74: MOV RDI, qword ptr [RBP + -0x40]
0xabcd78: MOV ESI, 0xb0
0xabcd7d: MOV RBX, RDX
0xabcd80: MOV R15, RAX
0xabcd83: CALL 0x00258ff0
0xabcd88: MOV RAX, qword ptr [R12 + 0x8]
0xabcd8d: MOV qword ptr [RBP + -0x38], RAX
0xabcd91: CMP RAX, R12
0xabcd94: JZ 0x00abcf3b
0xabcd9a: SHL RBX, 0x20
0xabcd9e: LEA R14, [0x1291b82]
0xabcda5: OR R15, RBX
0xabcda8: JMP 0x00abcdd9
0xabcdb0: MOV RDI, qword ptr [RBP + -0x58]
0xabcdb4: XOR ESI, ESI
0xabcdb6: XOR EDX, EDX
0xabcdb8: CALL 0x007d56e0
0xabcdbd: LEA R14, [0x1291b82]
0xabcdc4: MOV RAX, qword ptr [RBP + -0x38]
0xabcdc8: MOV RAX, qword ptr [RAX + 0x8]
0xabcdcc: MOV qword ptr [RBP + -0x38], RAX
0xabcdd0: CMP RAX, R12
0xabcdd3: JZ 0x00abcf3b
0xabcdd9: MOV R13, qword ptr [RAX + 0x20]
0xabcddd: RDTSC
0xabcddf: SHL RDX, 0x20
0xabcde3: OR RDX, RAX
0xabcde6: SUB RDX, R15
0xabcde9: CMP RDX, 0x27101
0xabcdf0: JC 0x00abce60
0xabcdf2: MOV EBX, dword ptr [R12 + 0x1c0]
0xabcdfa: MOV RDI, R12
0xabcdfd: XOR ESI, ESI
0xabcdff: XOR EDX, EDX
0xabce01: CALL 0x002c6870
0xabce06: MOV RSI, qword ptr [0x039203d0]
0xabce0d: MOV RDI, R14
0xabce10: MOV ECX, 0x100
0xabce15: XOR EDX, EDX
0xabce17: CALL 0x00c06830
0xabce1c: MOV RDI, R12
0xabce1f: XOR ESI, ESI
0xabce21: XOR EDX, EDX
0xabce23: CALL 0x002c6820
0xabce28: RDTSC
0xabce2a: MOV R15, RDX
0xabce2d: SHL R15, 0x20
0xabce31: OR R15, RAX
0xabce34: CMP dword ptr [R12 + 0x1c0], EBX
0xabce3c: JZ 0x00abce60
0xabce3e: MOV RDI, R12
0xabce41: MOV RSI, R13
0xabce44: LEA RDX, [RBP + -0x38]
0xabce48: CALL 0x002c6c40
0xabce4d: TEST EAX, EAX
0xabce4f: JZ 0x00abcdc4
0xabce55: NOP dword ptr CS:[RAX + RAX*0x1]
0xabce60: MOV RAX, qword ptr [RBP + -0x38]
0xabce64: TEST byte ptr [RAX + 0x60], 0x2
0xabce68: JNZ 0x00abcdc4
0xabce6e: MOV RBX, qword ptr [RAX + 0x50]
0xabce72: TEST RBX, RBX
0xabce75: JZ 0x00abcdc4
0xabce7b: MOVZX EAX, byte ptr [RBX + 0x9d]
0xabce82: CMP EAX, 0x8
0xabce85: JA 0x00abcdc4
0xabce8b: MOV ECX, 0x187
0xabce90: BT ECX, EAX
0xabce93: JNC 0x00abcdc4
0xabce99: LEA RDI, [RBX + 0x18]
0xabce9d: XOR ESI, ESI
0xabce9f: XOR EDX, EDX
0xabcea1: MOV qword ptr [RBP + -0x58], RDI
0xabcea5: CALL 0x007d50c0
0xabceaa: MOV RAX, qword ptr [RBP + -0x38]
0xabceae: MOV RDX, qword ptr [RBP + -0x40]
0xabceb2: MOV RDI, RBX
0xabceb5: MOV RCX, qword ptr [RAX + 0x28]
0xabceb9: MOVSX R14, byte ptr [RAX + 0x14c]
0xabcec1: SUB RCX, R13
0xabcec4: SHL R14, 0x4
0xabcec8: SHR RCX, 0xe
0xabcecc: ADD qword ptr [RDX + R14*0x1 + 0x8], RCX
0xabced1: MOV RCX, R13
0xabced4: MOV RSI, qword ptr [RAX + 0x58]
0xabced8: MOV R13, RSI
0xabcedb: SAR RSI, 0xe
0xabcedf: SUB R13, RCX
0xabcee2: ADD R13, qword ptr [RAX + 0x28]
0xabcee6: CALL 0x00b897f0
0xabceeb: TEST RAX, RAX
0xabceee: JZ 0x00abcdb0
0xabcef4: ADD R14, qword ptr [RBP + -0x40]
0xabcef8: SAR R13, 0xe
0xabcefc: NOP dword ptr [RAX]
0xabcf00: CMP qword ptr [RAX + 0x28], R13
0xabcf04: JNC 0x00abcdb0
0xabcf0a: INC qword ptr [R14]
0xabcf0d: MOV RAX, qword ptr [RAX + 0x10]
0xabcf11: TEST RAX, RAX
0xabcf14: JNZ 0x00abcf00
0xabcf16: JMP 0x00abcdb0
0xabcf1b: ADD RBX, 0x148
0xabcf22: XOR ESI, ESI
0xabcf24: XOR EDX, EDX
0xabcf26: XOR ECX, ECX
0xabcf28: MOV RDI, RBX
0xabcf2b: CALL 0x004c6fa0
0xabcf30: MOV R14D, 0x3
0xabcf36: JMP 0x00abcfd5
0xabcf3b: MOV RDI, R12
0xabcf3e: XOR R14D, R14D
0xabcf41: XOR ESI, ESI
0xabcf43: XOR EDX, EDX
0xabcf45: CALL 0x002c6870
0xabcf4a: MOV RBX, qword ptr [RBP + -0x48]
0xabcf4e: XOR ESI, ESI
0xabcf50: XOR EDX, EDX
0xabcf52: XOR ECX, ECX
0xabcf54: MOV RDI, RBX
0xabcf57: CALL 0x004c6a00
0xabcf5c: MOV RDI, qword ptr [RBP + -0x50]
0xabcf60: MOVZX ECX, byte ptr [RDI + 0xb1]
0xabcf67: MOV EAX, dword ptr [RDI + 0x358]
0xabcf6d: SHR CL, 0x5
0xabcf70: DEC EAX
0xabcf72: SETZ DL
0xabcf75: MOV dword ptr [RDI + 0x358], EAX
0xabcf7b: TEST CL, DL
0xabcf7d: JZ 0x00abcf8b
0xabcf7f: ADD RDI, 0x358
0xabcf86: CALL 0x00c06910
0xabcf8b: MOV RDI, RBX
0xabcf8e: XOR ESI, ESI
0xabcf90: XOR EDX, EDX
0xabcf92: XOR ECX, ECX
0xabcf94: CALL 0x004c6fa0
0xabcf99: LEA R15, [0x391c310]
0xabcfa0: JMP 0x00abcfd5
0xabcfa2: MOV RDI, qword ptr [RDI + 0x140]
0xabcfa9: MOV EBX, ESI
0xabcfab: CALL 0x00608f90
0xabcfb0: TEST EAX, EAX
0xabcfb2: JZ 0x00abcfcf
0xabcfb4: MOV EDI, EBX
0xabcfb6: CALL 0x0053c170
0xabcfbb: MOV RBX, RAX
0xabcfbe: TEST RAX, RAX
0xabcfc1: JNZ 0x00abcd1f
0xabcfc7: MOV R14D, 0x3
0xabcfcd: JMP 0x00abcfd5
0xabcfcf: MOV R14D, 0x1
0xabcfd5: MOV RAX, qword ptr [R15]
0xabcfd8: CMP RAX, qword ptr [RBP + -0x30]
0xabcfdc: JNZ 0x00abcff0
0xabcfde: MOV EAX, R14D
0xabcfe1: ADD RSP, 0x38
0xabcfe5: POP RBX
0xabcfe6: POP R12
0xabcfe8: POP R13
0xabcfea: POP R14
0xabcfec: POP R15
0xabcfee: POP RBP
0xabcfef: RET
0xabcff0: CALL 0x006fd6b0
0xabcff5: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abd000 RVA 0xabd000 | Evidence ev_a0c048c56652b5f4bbbe2a3ba2fad042f8575d3dc00b99e2875773d407f1f623 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sub_abd000:
0xabd000: PUSH RBP
0xabd001: MOV RBP, RSP
0xabd004: PUSH R15
0xabd006: PUSH R14
0xabd008: PUSH R12
0xabd00a: PUSH RBX
0xabd00b: SUB RSP, 0xc0
0xabd012: LEA R12, [0x391c310]
0xabd019: MOV RBX, RSI
0xabd01c: MOV RAX, qword ptr [R12]
0xabd020: MOV qword ptr [RBP + -0x28], RAX
0xabd024: MOV ECX, dword ptr [RSI + 0x8]
0xabd027: CMP ECX, 0xa
0xabd02a: JZ 0x00abd039
0xabd02c: MOV EAX, 0x16
0xabd031: TEST ECX, ECX
0xabd033: JNZ 0x00abd0c5
0xabd039: MOV ESI, dword ptr [RBX]
0xabd03b: LEA RDX, [RBP + -0xd8]
0xabd042: CALL 0x00abccc0
0xabd047: TEST EAX, EAX
0xabd049: JNZ 0x00abd0c5
0xabd04b: MOVSXD RAX, dword ptr [RBX + 0x8]
0xabd04f: MOV R15, qword ptr [RBX + 0x10]
0xabd053: MOV RDI, qword ptr GS:[0x0]
0xabd05c: LEA RSI, [0x134f297]
0xabd063: XOR EDX, EDX
0xabd065: SHL RAX, 0x4
0xabd069: LEA R14, [RBP + RAX*0x1 + -0xd8]
0xabd071: CALL 0x00c1a3e0
0xabd076: MOV EDX, 0x8
0xabd07b: MOV RDI, R14
0xabd07e: MOV RSI, R15
0xabd081: CALL 0x002591d0
0xabd086: TEST EAX, EAX
0xabd088: JNZ 0x00abd0c5
0xabd08a: MOVSXD RAX, dword ptr [RBX + 0x8]
0xabd08e: MOV RBX, qword ptr [RBX + 0x18]
0xabd092: MOV RDI, qword ptr GS:[0x0]
0xabd09b: LEA RSI, [0x134f297]
0xabd0a2: XOR EDX, EDX
0xabd0a4: SHL RAX, 0x4
0xabd0a8: LEA R14, [RBP + RAX*0x1 + -0xd0]
0xabd0b0: CALL 0x00c1a3e0
0xabd0b5: MOV EDX, 0x8
0xabd0ba: MOV RDI, R14
0xabd0bd: MOV RSI, RBX
0xabd0c0: CALL 0x002591d0
0xabd0c5: MOV RCX, qword ptr [R12]
0xabd0c9: CMP RCX, qword ptr [RBP + -0x28]
0xabd0cd: JNZ 0x00abd0df
0xabd0cf: ADD RSP, 0xc0
0xabd0d6: POP RBX
0xabd0d7: POP R12
0xabd0d9: POP R14
0xabd0db: POP R15
0xabd0dd: POP RBP
0xabd0de: RET
0xabd0df: CALL 0x006fd6b0
0xabd0e4: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_618 RVA 0xabd0f0 | Evidence ev_b0b1b79cbd2ba2c4e61e9f671ca545ec08ea476bba2c7aa3dc70404aa70f0c51 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_618:
0xabd0f0: PUSH RBP
0xabd0f1: MOV RBP, RSP
0xabd0f4: PUSH R15
0xabd0f6: PUSH R14
0xabd0f8: PUSH R13
0xabd0fa: PUSH R12
0xabd0fc: PUSH RBX
0xabd0fd: SUB RSP, 0x68
0xabd101: LEA R14, [0x391c310]
0xabd108: MOV RBX, RDI
0xabd10b: MOV R15, RSI
0xabd10e: MOV RAX, qword ptr [R14]
0xabd111: MOV qword ptr [RBP + -0x30], RAX
0xabd115: MOV RDI, qword ptr [RDI + 0x140]
0xabd11c: CALL 0x00608f90
0xabd121: TEST EAX, EAX
0xabd123: JZ 0x00abd400
0xabd129: MOV RAX, qword ptr [R15]
0xabd12c: LEA R12, [0x2bfc080]
0xabd133: MOV qword ptr [RBP + -0x88], R15
0xabd13a: XOR R14D, R14D
0xabd13d: MOV qword ptr [RBP + -0x70], RAX
0xabd141: LEA RAX, [RBP + -0x70]
0xabd145: MOVSXD RCX, dword ptr [R15 + 0x8]
0xabd149: MOV qword ptr [RBP + -0x60], RAX
0xabd14d: MOV dword ptr [RBP + -0x58], 0x1
0xabd154: MOV qword ptr [RBP + -0x50], 0x0
0xabd15c: MOV qword ptr [RBP + -0x48], RCX
0xabd160: MOV qword ptr [RBP + -0x40], 0x0
0xabd168: MOV qword ptr [RBP + -0x38], RBX
0xabd16c: LEA RBX, [0x351e060]
0xabd173: MOV qword ptr [RBP + -0x68], RCX
0xabd177: MOV qword ptr [RBP + -0x90], RCX
0xabd17e: MOV RDI, RBX
0xabd181: XOR ESI, ESI
0xabd183: XOR EDX, EDX
0xabd185: XOR ECX, ECX
0xabd187: CALL 0x004c6a00
0xabd18c: MOV RAX, qword ptr [0x0351e038]
0xabd193: MOV R15D, 0x0
0xabd199: TEST RAX, RAX
0xabd19c: JZ 0x00abd1bc
0xabd19e: XOR R15D, R15D
0xabd1a1: NOP dword ptr CS:[RAX + RAX*0x1]
0xabd1b0: MOV RAX, qword ptr [RAX + 0x20]
0xabd1b4: INC R15D
0xabd1b7: TEST RAX, RAX
0xabd1ba: JNZ 0x00abd1b0
0xabd1bc: MOV RDI, RBX
0xabd1bf: XOR ESI, ESI
0xabd1c1: XOR EDX, EDX
0xabd1c3: XOR ECX, ECX
0xabd1c5: CALL 0x004c6fa0
0xabd1ca: MOVSXD RAX, R15D
0xabd1cd: MOV RSI, R12
0xabd1d0: MOV EDX, 0x102
0xabd1d5: IMUL RDI, RAX, 0x128
0xabd1dc: CALL 0x00c08b50
0xabd1e1: MOV RDI, RBX
0xabd1e4: MOV qword ptr [RBP + -0x80], RAX
0xabd1e8: XOR ESI, ESI
0xabd1ea: XOR EDX, EDX
0xabd1ec: XOR ECX, ECX
0xabd1ee: CALL 0x004c6a00
0xabd1f3: MOV R12, qword ptr [0x0351e038]
0xabd1fa: TEST R12, R12
0xabd1fd: JZ 0x00abd387
0xabd203: MOV qword ptr [RBP + -0x78], 0x0
0xabd20b: JMP 0x00abd27b
0xabd261: MOV RDI, RBX
0xabd264: XOR ESI, ESI
0xabd266: XOR EDX, EDX
0xabd268: CALL 0x007d4eb0
0xabd26d: MOV R12, qword ptr [R12 + 0x20]
0xabd272: TEST R12, R12
0xabd275: JZ 0x00abd37c
0xabd27b: LEA RBX, [R12 + 0x18]
0xabd280: XOR ESI, ESI
0xabd282: XOR EDX, EDX
0xabd284: MOV RDI, RBX
0xabd287: CALL 0x007d46a0
0xabd28c: MOV EAX, dword ptr [R12 + 0xa0]
0xabd294: TEST AL, 0x8
0xabd296: JNZ 0x00abd261
0xabd298: MOV RCX, qword ptr [RBP + -0x78]
0xabd29c: LEA R13D, [RCX + 0x1]
0xabd2a0: CMP R15D, R13D
0xabd2a3: JL 0x00abd340
0xabd2a9: MOVZX ECX, byte ptr [R12 + 0x9d]
0xabd2b2: CMP RCX, 0x8
0xabd2b6: JA 0x00abd261
0xabd2b8: MOVSXD RDX, dword ptr [RBP + -0x78]
0xabd2bc: LEA RSI, [0x18dbf68]
0xabd2c3: MOVSXD RCX, dword ptr [RSI + RCX*0x4]
0xabd2c7: IMUL R14, RDX, 0x128
0xabd2ce: ADD R14, qword ptr [RBP + -0x80]
0xabd2d2: ADD RCX, RSI
0xabd2d5: JMP RCX
0xabd340: MOV RDI, RBX
0xabd343: XOR ESI, ESI
0xabd345: XOR EDX, EDX
0xabd347: CALL 0x007d4eb0
0xabd34c: LEA RBX, [0x351e060]
0xabd353: XOR ESI, ESI
0xabd355: XOR EDX, EDX
0xabd357: XOR ECX, ECX
0xabd359: MOV RDI, RBX
0xabd35c: CALL 0x004c6fa0
0xabd361: LEA R12, [0x2bfc080]
0xabd368: MOV RDI, qword ptr [RBP + -0x80]
0xabd36c: MOV RSI, R12
0xabd36f: CALL 0x00c08df0
0xabd374: XOR R14D, R14D
0xabd377: JMP 0x00abd17e
0xabd37c: MOVSXD RAX, dword ptr [RBP + -0x78]
0xabd380: IMUL R14, RAX, 0x128
0xabd387: LEA RDI, [0x351e060]
0xabd38e: XOR ESI, ESI
0xabd390: XOR EDX, EDX
0xabd392: XOR ECX, ECX
0xabd394: CALL 0x004c6fa0
0xabd399: MOV RSI, qword ptr [RBP + -0x90]
0xabd3a0: MOV R15, qword ptr [RBP + -0x80]
0xabd3a4: LEA RDX, [RBP + -0x60]
0xabd3a8: CMP RSI, R14
0xabd3ab: MOV RDI, R15
0xabd3ae: CMOVNC RSI, R14
0xabd3b2: CALL 0x00782520
0xabd3b7: LEA RSI, [0x2bfc080]
0xabd3be: MOV RDI, R15
0xabd3c1: MOV EBX, EAX
0xabd3c3: CALL 0x00c08df0
0xabd3c8: MOV EAX, EBX
0xabd3ca: TEST EBX, EBX
0xabd3cc: JNZ 0x00abd3f7
0xabd3ce: MOV RAX, qword ptr [RBP + -0x88]
0xabd3d5: MOV RDI, qword ptr [RAX + 0x10]
0xabd3d9: MOV EAX, 0x0
0xabd3de: TEST RDI, RDI
0xabd3e1: JZ 0x00abd3f7
0xabd3e3: MOV RSI, R14
0xabd3e6: CALL 0x00259720
0xabd3eb: MOV ECX, EAX
0xabd3ed: TEST EAX, EAX
0xabd3ef: MOV EAX, 0xe
0xabd3f4: CMOVZ EAX, ECX
0xabd3f7: LEA R14, [0x391c310]
0xabd3fe: JMP 0x00abd405
0xabd400: MOV EAX, 0x1
0xabd405: MOV RCX, qword ptr [R14]
0xabd408: CMP RCX, qword ptr [RBP + -0x30]
0xabd40c: JNZ 0x00abd41d
0xabd40e: ADD RSP, 0x68
0xabd412: POP RBX
0xabd413: POP R12
0xabd415: POP R13
0xabd417: POP R14
0xabd419: POP R15
0xabd41b: POP RBP
0xabd41c: RET
0xabd41d: CALL 0x006fd6b0
0xabd422: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_620 RVA 0xabd430 | Evidence ev_497d9ca3a51c9cabe5168491267763226ddb46c80642a8942c342d63d95dfb04 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_620:
0xabd430: PUSH RBP
0xabd431: MOV RBP, RSP
0xabd434: PUSH R15
0xabd436: PUSH R14
0xabd438: PUSH RBX
0xabd439: SUB RSP, 0x18
0xabd43d: LEA R15, [0x391c310]
0xabd444: XOR ESI, ESI
0xabd446: XOR EDX, EDX
0xabd448: MOV RAX, qword ptr [R15]
0xabd44b: MOV qword ptr [RBP + -0x20], RAX
0xabd44f: MOV RAX, qword ptr [RDI + 0x8]
0xabd453: MOV RCX, qword ptr [RDI + 0x460]
0xabd45a: MOV R14, qword ptr [RCX + 0x100]
0xabd461: MOV RBX, qword ptr [RAX + 0x200]
0xabd468: ADD R14, -0x80
0xabd46c: MOV RDI, RBX
0xabd46f: AND R14, -0x4000
0xabd476: CALL 0x002c6820
0xabd47b: LEA RDX, [RBP + -0x28]
0xabd47f: MOV RDI, RBX
0xabd482: MOV RSI, R14
0xabd485: CALL 0x002c6c40
0xabd48a: TEST EAX, EAX
0xabd48c: JZ 0x00abd4bf
0xabd48e: MOV RAX, qword ptr [RBP + -0x28]
0xabd492: SUB R14, qword ptr [RAX + 0x20]
0xabd496: SHR R14, 0xe
0xabd49a: TEST R14D, R14D
0xabd49d: JLE 0x00abd4bf
0xabd49f: MOV RSI, qword ptr [RAX + 0x58]
0xabd4a3: MOV RDI, qword ptr [RAX + 0x50]
0xabd4a7: AND R14D, 0x7fffffff
0xabd4ae: MOV ECX, 0x5
0xabd4b3: MOV RDX, R14
0xabd4b6: SAR RSI, 0xe
0xabd4ba: CALL 0x00463610
0xabd4bf: MOV RDI, RBX
0xabd4c2: XOR ESI, ESI
0xabd4c4: XOR EDX, EDX
0xabd4c6: CALL 0x002c6870
0xabd4cb: MOV RAX, qword ptr [R15]
0xabd4ce: CMP RAX, qword ptr [RBP + -0x20]
0xabd4d2: JNZ 0x00abd4e1
0xabd4d4: XOR EAX, EAX
0xabd4d6: ADD RSP, 0x18
0xabd4da: POP RBX
0xabd4db: POP R14
0xabd4dd: POP R15
0xabd4df: POP RBP
0xabd4e0: RET
0xabd4e1: CALL 0x006fd6b0
0xabd4e6: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_624 RVA 0xabd4f0 | Evidence ev_fb8ce107f4e0b0ef2ecf94bc66584bc4eae775ba6c96d1dbc5ee7af3244f5e70 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_624:
0xabd4f0: PUSH RBP
0xabd4f1: MOV RBP, RSP
0xabd4f4: PUSH R14
0xabd4f6: PUSH RBX
0xabd4f7: MOV RAX, qword ptr [RDI + 0x8]
0xabd4fb: MOV RBX, RDI
0xabd4fe: XOR ESI, ESI
0xabd500: XOR EDX, EDX
0xabd502: MOV R14, qword ptr [RAX + 0x200]
0xabd509: MOV RDI, R14
0xabd50c: CALL 0x002c6820
0xabd511: MOV EAX, dword ptr [R14 + 0x1c4]
0xabd518: MOV RDI, R14
0xabd51b: XOR ESI, ESI
0xabd51d: XOR EDX, EDX
0xabd51f: MOV qword ptr [RBX + 0x408], RAX
0xabd526: CALL 0x002c6870
0xabd52b: XOR EAX, EAX
0xabd52d: POP RBX
0xabd52e: POP R14
0xabd530: POP RBP
0xabd531: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_628 RVA 0xabd540 | Evidence ev_f486b8d9b62f02454ea2d880a34eae6d8ff485577fe8c415db5c78d33cfadcfe | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_628:
0xabd540: PUSH RBP
0xabd541: MOV RBP, RSP
0xabd544: PUSH R15
0xabd546: PUSH R14
0xabd548: PUSH R13
0xabd54a: PUSH R12
0xabd54c: PUSH RBX
0xabd54d: SUB RSP, 0x48
0xabd551: LEA RAX, [0x391c310]
0xabd558: MOV R13, RDI
0xabd55b: MOV RAX, qword ptr [RAX]
0xabd55e: MOV qword ptr [RBP + -0x30], RAX
0xabd562: MOV R12, qword ptr [RSI]
0xabd565: MOV qword ptr [RBP + -0x38], R12
0xabd569: MOV RAX, qword ptr [RSI + 0x8]
0xabd56d: MOV ECX, dword ptr [RSI + 0x20]
0xabd570: MOV R15, qword ptr [RSI + 0x28]
0xabd574: MOV qword ptr [RBP + -0x48], RAX
0xabd578: MOV EAX, dword ptr [RSI + 0x10]
0xabd57b: MOV qword ptr [RBP + -0x60], RCX
0xabd57f: MOV qword ptr [RBP + -0x68], RAX
0xabd583: MOV EAX, dword ptr [RSI + 0x18]
0xabd586: MOV R14, qword ptr GS:[0x0]
0xabd58f: MOV RCX, qword ptr [R14 + 0x8]
0xabd593: MOV RDI, qword ptr [RDI + 0x140]
0xabd59a: MOVZX EBX, AL
0xabd59d: CMP dword ptr [RCX + 0x5d4], 0x3000000
0xabd5a7: CMOVNC EBX, EAX
0xabd5aa: CALL 0x00609560
0xabd5af: MOV ECX, 0x1
0xabd5b4: TEST EAX, EAX
0xabd5b6: JZ 0x00abd5c1
0xabd5b8: LEA R15, [0x391c310]
0xabd5bf: JMP 0x00abd60e
0xabd5c1: MOV RDI, qword ptr [R14 + 0x140]
0xabd5c8: MOV dword ptr [RBP + -0x4c], EBX
0xabd5cb: MOV RBX, qword ptr [RBP + -0x68]
0xabd5cf: MOV qword ptr [RBP + -0x58], R15
0xabd5d3: MOV qword ptr [RBP + -0x40], R13
0xabd5d7: CALL 0x006095a0
0xabd5dc: TEST EAX, EAX
0xabd5de: JNZ 0x00abd602
0xabd5e0: MOV RAX, qword ptr [RBP + -0x40]
0xabd5e4: MOV RDI, qword ptr [RAX + 0x140]
0xabd5eb: CALL 0x006092d0
0xabd5f0: TEST EAX, EAX
0xabd5f2: JZ 0x00abd62c
0xabd5f4: LEA RDI, [0x1376c18]
0xabd5fb: XOR EAX, EAX
0xabd5fd: CALL 0x0025d410
0xabd602: LEA R15, [0x391c310]
0xabd609: MOV ECX, 0x1
0xabd60e: MOV RAX, qword ptr [R15]
0xabd611: CMP RAX, qword ptr [RBP + -0x30]
0xabd615: JNZ 0x00abd91c
0xabd61b: MOV EAX, ECX
0xabd61d: ADD RSP, 0x48
0xabd621: POP RBX
0xabd622: POP R12
0xabd624: POP R13
0xabd626: POP R14
0xabd628: POP R15
0xabd62a: POP RBP
0xabd62b: RET
0xabd62c: MOV RAX, R12
0xabd62f: MOV ECX, 0x16
0xabd634: SHL RAX, 0x32
0xabd638: JNZ 0x00abd5b8
0xabd63e: MOV RSI, qword ptr [RBP + -0x48]
0xabd642: TEST ESI, 0x3fff
0xabd648: SETNZ AL
0xabd64b: CMP RSI, 0x4000
0xabd652: SETC DL
0xabd655: OR DL, AL
0xabd657: JNZ 0x00abd5b8
0xabd65d: MOV R13, RBX
0xabd660: CMP R13D, -0x1
0xabd664: JZ 0x00abd698
0xabd666: MOV RAX, qword ptr [RBP + -0x40]
0xabd66a: MOV EDI, R13D
0xabd66d: MOV RSI, qword ptr [RAX + 0x8]
0xabd671: CALL 0x003c33e0
0xabd676: MOV EBX, dword ptr [RBP + -0x4c]
0xabd679: TEST EAX, EAX
0xabd67b: JZ 0x00abd7b3
0xabd681: MOV RSI, qword ptr [RBP + -0x48]
0xabd685: MOV EAX, EBX
0xabd687: MOV ECX, 0x16
0xabd68c: AND EAX, 0xfffffc0c
0xabd691: JZ 0x00abd6a7
0xabd693: JMP 0x00abd5b8
0xabd698: MOV EBX, dword ptr [RBP + -0x4c]
0xabd69b: TEST EBX, 0xfffffc0c
0xabd6a1: JNZ 0x00abd5b8
0xabd6a7: MOV RDI, qword ptr [RBP + -0x60]
0xabd6ab: MOV RDX, qword ptr [RBP + -0x58]
0xabd6af: TEST EDI, 0x9fdf2f
0xabd6b5: SETZ AL
0xabd6b8: SHL RDX, 0x32
0xabd6bc: SETZ DL
0xabd6bf: AND DL, AL
0xabd6c1: CMP DL, 0x1
0xabd6c4: JNZ 0x00abd5b8
0xabd6ca: TEST DIL, 0x40
0xabd6ce: JZ 0x00abd6e8
0xabd6d0: CMP RSI, 0x4000
0xabd6d7: JA 0x00abd5b8
0xabd6dd: MOV EAX, EBX
0xabd6df: AND EAX, 0x3
0xabd6e2: JZ 0x00abd5b8
0xabd6e8: TEST EDI, 0x200000
0xabd6ee: JZ 0x00abd701
0xabd6f0: MOV RDI, qword ptr [R14 + 0x8]
0xabd6f4: CALL 0x00b24300
0xabd6f9: TEST EAX, EAX
0xabd6fb: JZ 0x00abd7b3
0xabd701: MOV RDI, qword ptr [RBP + -0x40]
0xabd705: MOV R15, 0x7efffffff
0xabd70f: CALL 0x00ab8320
0xabd714: MOV RDX, -0x7f0000000
0xabd71e: LEA RDI, [R15 + 0x10000001]
0xabd725: ADD RDX, RAX
0xabd728: CMP RDX, RDI
0xabd72b: JC 0x00abd73f
0xabd72d: CMP EBX, 0x40
0xabd730: JC 0x00abd73f
0xabd732: MOV RCX, qword ptr [R14 + 0x8]
0xabd736: CMP byte ptr [RCX + 0xc81], 0x0
0xabd73d: JZ 0x00abd7b3
0xabd73f: MOV RCX, qword ptr [RBP + -0x40]
0xabd743: MOV R10D, EBX
0xabd746: MOV R11, qword ptr [RBP + -0x60]
0xabd74a: SHR R10D, 0x1
0xabd74d: AND R10D, 0x141
0xabd754: OR R10D, EBX
0xabd757: MOV RCX, qword ptr [RCX + 0x8]
0xabd75b: MOV RSI, qword ptr [RCX + 0x200]
0xabd762: TEST R11B, 0x10
0xabd766: JNZ 0x00abd7c4
0xabd768: TEST R12, R12
0xabd76b: JZ 0x00abd853
0xabd771: MOV R8, R15
0xabd774: LEA R15, [0x391c310]
0xabd77b: CMP RDX, RDI
0xabd77e: JC 0x00abd7ab
0xabd780: MOV RDX, qword ptr [RBP + -0x48]
0xabd784: MOV R9, 0xff0000000
0xabd78e: LEA RDI, [R9 + 0x1]
0xabd792: ADD RDX, R12
0xabd795: CMP RDX, R8
0xabd798: SETBE DL
0xabd79b: CMP R12, RDI
0xabd79e: SETNC DIL
0xabd7a2: OR DIL, DL
0xabd7a5: JZ 0x00abd870
0xabd7ab: MOV R9, R12
0xabd7ae: JMP 0x00abd874
0xabd7b3: LEA R15, [0x391c310]
0xabd7ba: MOV ECX, 0x16
0xabd7bf: JMP 0x00abd60e
0xabd7c4: MOV RBX, R15
0xabd7c7: LEA R15, [0x391c310]
0xabd7ce: TEST R12, R12
0xabd7d1: JZ 0x00abd89e
0xabd7d7: CMP qword ptr [RSI + 0x20], R12
0xabd7db: MOV R8, R12
0xabd7de: SETA CL
0xabd7e1: ADD R8, qword ptr [RBP + -0x48]
0xabd7e5: SETC R9B
0xabd7e9: OR R9B, CL
0xabd7ec: MOV ECX, 0x16
0xabd7f1: JNZ 0x00abd60e
0xabd7f7: CMP qword ptr [RSI + 0x28], R8
0xabd7fb: JC 0x00abd60e
0xabd801: CMP RDX, RDI
0xabd804: JC 0x00abd827
0xabd806: CMP R8, RBX
0xabd809: MOV RDI, R12
0xabd80c: SETA DL
0xabd80f: SHR RDI, 0x1c
0xabd813: CMP RDI, 0xff
0xabd81a: SETC DIL
0xabd81e: TEST DIL, DL
0xabd821: JNZ 0x00abd60e
0xabd827: MOV RCX, qword ptr [R14 + 0x8]
0xabd82b: MOV ECX, dword ptr [RCX + 0x5c4]
0xabd831: SUB RSP, 0x8
0xabd835: MOV RBX, qword ptr [RBP + -0x40]
0xabd839: MOV R8, qword ptr [RBP + -0x58]
0xabd83d: LEA RDX, [RBP + -0x38]
0xabd841: MOV R9, R12
0xabd844: MOV RDI, RBX
0xabd847: PUSH 0x0
0xabd849: PUSH RAX
0xabd84a: PUSH R11
0xabd84c: PUSH 0x0
0xabd84e: JMP 0x00abd8fa
0xabd853: XOR R8D, R8D
0xabd856: CMP RDX, RDI
0xabd859: LEA R15, [0x391c310]
0xabd860: SETC R8B
0xabd864: SHL R8D, 0x4
0xabd868: MOV R9, qword ptr [R8 + RSI*0x1 + 0x1f8]
0xabd870: MOV qword ptr [RBP + -0x38], R9
0xabd874: MOV EDX, R11D
0xabd877: AND EDX, 0xff000000
0xabd87d: JZ 0x00abd8a8
0xabd87f: CMP EDX, 0x1000000
0xabd885: JNZ 0x00abd8ca
0xabd887: MOV RCX, qword ptr [R14 + 0x8]
0xabd88b: XOR EDX, EDX
0xabd88d: CMP byte ptr [RCX + 0xc81], 0x0
0xabd894: SETNZ DL
0xabd897: LEA R11D, [RDX + RDX*0x1 + 0x1]
0xabd89c: JMP 0x00abd8d5
0xabd89e: MOV ECX, 0x16
0xabd8a3: JMP 0x00abd60e
0xabd8a8: TEST byte ptr [RSI + 0x244], 0x2
0xabd8af: MOV R11D, 0x1
0xabd8b5: JNZ 0x00abd8d5
0xabd8b7: XOR R11D, R11D
0xabd8ba: CMP dword ptr [RCX + 0x5d8], 0x1500000
0xabd8c4: ADC R11D, 0x1
0xabd8c8: JMP 0x00abd8d5
0xabd8ca: SAR R11D, 0x10
0xabd8ce: AND R11D, 0xffffff00
0xabd8d5: MOV RCX, qword ptr [R14 + 0x8]
0xabd8d9: MOV ECX, dword ptr [RCX + 0x5c4]
0xabd8df: SUB RSP, 0x8
0xabd8e3: MOV RBX, qword ptr [RBP + -0x40]
0xabd8e7: MOV R8, qword ptr [RBP + -0x58]
0xabd8eb: LEA RDX, [RBP + -0x38]
0xabd8ef: MOV RDI, RBX
0xabd8f2: PUSH 0x0
0xabd8f4: PUSH RAX
0xabd8f5: PUSH qword ptr [RBP + -0x60]
0xabd8f8: PUSH R11
0xabd8fa: PUSH R10
0xabd8fc: PUSH R13
0xabd8fe: PUSH qword ptr [RBP + -0x48]
0xabd901: CALL 0x003cb450
0xabd906: ADD RSP, 0x40
0xabd90a: MOV RDX, qword ptr [RBP + -0x38]
0xabd90e: MOV ECX, EAX
0xabd910: MOV qword ptr [RBX + 0x408], RDX
0xabd917: JMP 0x00abd60e
0xabd91c: CALL 0x006fd6b0
0xabd921: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_637 RVA 0xabd930 | Evidence ev_3afbdf37c73afc1b50e1b4b818ae5ae3a702538591d483250ec5653ed5984a9c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_637:
0xabd930: PUSH RBP
0xabd931: MOV RBP, RSP
0xabd934: PUSH R15
0xabd936: PUSH R14
0xabd938: PUSH R13
0xabd93a: PUSH R12
0xabd93c: PUSH RBX
0xabd93d: PUSH RAX
0xabd93e: CMP qword ptr [RSI + 0x8], 0x11
0xabd943: MOV R14D, 0x16
0xabd949: JL 0x00abda80
0xabd94f: MOV EAX, dword ptr [RSI]
0xabd951: MOV R13, RSI
0xabd954: TEST EAX, EAX
0xabd956: JZ 0x00abd971
0xabd958: MOV RCX, qword ptr GS:[0x0]
0xabd961: MOV RCX, qword ptr [RCX + 0x8]
0xabd965: CMP EAX, dword ptr [RCX + 0xbc]
0xabd96b: JNZ 0x00abda92
0xabd971: MOV RAX, qword ptr GS:[0x0]
0xabd97a: MOV RBX, qword ptr [RAX + 0x8]
0xabd97e: XOR ESI, ESI
0xabd980: XOR EDX, EDX
0xabd982: XOR ECX, ECX
0xabd984: LEA RDI, [RBX + 0x148]
0xabd98b: CALL 0x004c6a00
0xabd990: MOV EAX, dword ptr [RBX + 0xb0]
0xabd996: TEST EAX, 0x2200
0xabd99b: JNZ 0x00abda62
0xabd9a1: CMP dword ptr [RBX + 0xb8], 0x1
0xabd9a8: JNZ 0x00abda62
0xabd9ae: INC dword ptr [RBX + 0x358]
0xabd9b4: TEST EAX, 0x10000000
0xabd9b9: JNZ 0x00abd9c3
0xabd9bb: MOV RDI, RBX
0xabd9be: CALL 0x0053aa10
0xabd9c3: LEA R15, [RBX + 0x148]
0xabd9ca: XOR R14D, R14D
0xabd9cd: XOR ESI, ESI
0xabd9cf: XOR EDX, EDX
0xabd9d1: XOR ECX, ECX
0xabd9d3: MOV RDI, R15
0xabd9d6: CALL 0x004c6fa0
0xabd9db: MOV R12, qword ptr [RBX + 0x200]
0xabd9e2: TEST R12, R12
0xabd9e5: JZ 0x00abda21
0xabd9e7: LEA RDI, [R12 + 0x278]
0xabd9ef: XOR ESI, ESI
0xabd9f1: XOR EDX, EDX
0xabd9f3: XOR ECX, ECX
0xabd9f5: MOV qword ptr [RBP + -0x30], RDI
0xabd9f9: CALL 0x004c6a00
0xabd9fe: MOV RAX, qword ptr [R13 + 0x8]
0xabda02: MOV RDI, qword ptr [RBP + -0x30]
0xabda06: XOR ESI, ESI
0xabda08: XOR EDX, EDX
0xabda0a: XOR ECX, ECX
0xabda0c: MOV qword ptr [R12 + 0x280], RAX
0xabda14: CALL 0x004c6fa0
0xabda19: MOV RDI, R12
0xabda1c: CALL 0x00691c70
0xabda21: MOV RDI, R15
0xabda24: XOR ESI, ESI
0xabda26: XOR EDX, EDX
0xabda28: XOR ECX, ECX
0xabda2a: CALL 0x004c6a00
0xabda2f: MOVZX ECX, byte ptr [RBX + 0xb1]
0xabda36: MOV EAX, dword ptr [RBX + 0x358]
0xabda3c: SHR CL, 0x5
0xabda3f: DEC EAX
0xabda41: SETZ DL
0xabda44: MOV dword ptr [RBX + 0x358], EAX
0xabda4a: AND DL, CL
0xabda4c: CMP DL, 0x1
0xabda4f: JNZ 0x00abda72
0xabda51: ADD RBX, 0x358
0xabda58: MOV RDI, RBX
0xabda5b: CALL 0x00c06910
0xabda60: JMP 0x00abda72
0xabda62: ADD RBX, 0x148
0xabda69: MOV R14D, 0x3
0xabda6f: MOV R15, RBX
0xabda72: MOV RDI, R15
0xabda75: XOR ESI, ESI
0xabda77: XOR EDX, EDX
0xabda79: XOR ECX, ECX
0xabda7b: CALL 0x004c6fa0
0xabda80: MOV EAX, R14D
0xabda83: ADD RSP, 0x8
0xabda87: POP RBX
0xabda88: POP R12
0xabda8a: POP R13
0xabda8c: POP R14
0xabda8e: POP R15
0xabda90: POP RBP
0xabda91: RET
0xabda92: MOV RDI, qword ptr [RDI + 0x140]
0xabda99: CALL 0x00608f90
0xabda9e: TEST EAX, EAX
0xabdaa0: JZ 0x00abdabf
0xabdaa2: MOV EDI, dword ptr [R13]
0xabdaa6: CALL 0x0053c170
0xabdaab: MOV RBX, RAX
0xabdaae: TEST RAX, RAX
0xabdab1: JNZ 0x00abd990
0xabdab7: MOV R14D, 0x3
0xabdabd: JMP 0x00abda80
0xabdabf: MOV R14D, 0x1
0xabdac5: JMP 0x00abda80


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_642 RVA 0xabdad0 | Evidence ev_8a6fc96d4e5aeb69b9415b4a881dbc669248a860eaede24c0193e682745ec773 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_642:
0xabdad0: PUSH RBP
0xabdad1: MOV RBP, RSP
0xabdad4: PUSH R15
0xabdad6: PUSH R14
0xabdad8: PUSH R13
0xabdada: PUSH R12
0xabdadc: PUSH RBX
0xabdadd: SUB RSP, 0xc8
0xabdae4: LEA RBX, [0x391c310]
0xabdaeb: MOV R14, RSI
0xabdaee: MOV RAX, qword ptr [RBX]
0xabdaf1: MOV qword ptr [RBP + -0x30], RAX
0xabdaf5: MOV RDI, qword ptr [RDI + 0x140]
0xabdafc: CALL 0x00608f90
0xabdb01: TEST EAX, EAX
0xabdb03: JZ 0x00abe17c
0xabdb09: MOV EDI, dword ptr [R14]
0xabdb0c: CALL 0x0053c170
0xabdb11: MOV RCX, RAX
0xabdb14: MOV EAX, 0x2
0xabdb19: TEST RCX, RCX
0xabdb1c: JZ 0x00abe19d
0xabdb22: MOV EAX, dword ptr [RCX + 0xb0]
0xabdb28: TEST EAX, 0x2000
0xabdb2d: JNZ 0x00abe183
0xabdb33: INC dword ptr [RCX + 0x358]
0xabdb39: MOV qword ptr [RBP + -0xb8], R14
0xabdb40: MOV qword ptr [RBP + -0xb0], RCX
0xabdb47: TEST EAX, 0x10000000
0xabdb4c: JNZ 0x00abdb61
0xabdb4e: MOV RDI, qword ptr [RBP + -0xb0]
0xabdb55: CALL 0x0053aa10
0xabdb5a: MOV RCX, qword ptr [RBP + -0xb0]
0xabdb61: LEA RDI, [RCX + 0x148]
0xabdb68: MOV RBX, RCX
0xabdb6b: XOR ESI, ESI
0xabdb6d: XOR EDX, EDX
0xabdb6f: XOR ECX, ECX
0xabdb71: MOV qword ptr [RBP + -0xe0], RDI
0xabdb78: CALL 0x004c6fa0
0xabdb7d: MOV R13, qword ptr [RBX + 0x200]
0xabdb84: XOR ESI, ESI
0xabdb86: XOR EDX, EDX
0xabdb88: MOV RDI, R13
0xabdb8b: CALL 0x002c6820
0xabdb90: LEA RDI, [RBP + -0x98]
0xabdb97: MOV ESI, 0x68
0xabdb9c: MOV dword ptr [RBP + -0x9c], 0x0
0xabdba6: CALL 0x00258ff0
0xabdbab: MOV R15, qword ptr [R13 + 0x8]
0xabdbaf: CMP R15, R13
0xabdbb2: JZ 0x00abe0c0
0xabdbb8: MOV qword ptr [RBP + -0xe8], R13
0xabdbbf: JMP 0x00abdbdd
0xabdbc1: INC R14D
0xabdbc4: MOV dword ptr [RBP + -0x9c], R14D
0xabdbcb: NOP dword ptr [RAX + RAX*0x1]
0xabdbd0: MOV R15, qword ptr [R15 + 0x8]
0xabdbd4: CMP R15, R13
0xabdbd7: JZ 0x00abe0c0
0xabdbdd: CMP word ptr [R15 + 0x66], 0x0
0xabdbe3: JZ 0x00abdbd0
0xabdbe5: TEST byte ptr [R15 + 0x60], 0x2
0xabdbea: JNZ 0x00abdbd0
0xabdbec: MOVZX EAX, word ptr [R15 + 0x64]
0xabdbf1: MOV RBX, qword ptr [R15 + 0x50]
0xabdbf5: MOV dword ptr [RBP + -0x60], EAX
0xabdbf8: MOV ECX, dword ptr [R15 + 0x60]
0xabdbfc: TEST CL, 0x20
0xabdbff: JZ 0x00abdc0d
0xabdc01: OR EAX, 0x10000
0xabdc06: MOV dword ptr [RBP + -0x60], EAX
0xabdc09: MOV ECX, dword ptr [R15 + 0x60]
0xabdc0d: TEST ECX, 0x1000
0xabdc13: JZ 0x00abdc1d
0xabdc15: OR EAX, 0x20000
0xabdc1a: MOV dword ptr [RBP + -0x60], EAX
0xabdc1d: MOV RAX, qword ptr [R15 + 0x20]
0xabdc21: MOV qword ptr [RBP + -0x78], RAX
0xabdc25: MOV RAX, qword ptr [R15 + 0x28]
0xabdc29: MOV qword ptr [RBP + -0x70], RAX
0xabdc2d: TEST RBX, RBX
0xabdc30: JZ 0x00abdc51
0xabdc32: MOVZX EAX, byte ptr [RBX + 0x9d]
0xabdc39: CMP EAX, 0xa
0xabdc3c: JA 0x00abdc63
0xabdc3e: MOV ECX, 0x587
0xabdc43: BT ECX, EAX
0xabdc46: JNC 0x00abdc63
0xabdc48: TEST byte ptr [RBX + 0xa2], 0x1
0xabdc4f: JNZ 0x00abdc63
0xabdc51: CMP word ptr [R15 + 0x66], 0x0
0xabdc57: JZ 0x00abdc6c
0xabdc59: MOVSX EAX, byte ptr [R15 + 0x14c]
0xabdc61: JMP 0x00abdc6e
0xabdc63: MOV dword ptr [RBP + -0x34], 0x0
0xabdc6a: JMP 0x00abdc7a
0xabdc6c: XOR EAX, EAX
0xabdc6e: MOV dword ptr [RBP + -0x34], EAX
0xabdc71: TEST RBX, RBX
0xabdc74: JZ 0x00abe02a
0xabdc7a: LEA R12, [RBX + 0x18]
0xabdc7e: XOR ESI, ESI
0xabdc80: XOR EDX, EDX
0xabdc82: MOV RDI, R12
0xabdc85: CALL 0x007d46a0
0xabdc8a: MOVZX EAX, byte ptr [RBX + 0x9d]
0xabdc91: ADD AL, 0xfd
0xabdc93: CMP AL, 0x2
0xabdc95: JNC 0x00abdca8
0xabdc97: MOV RDI, R12
0xabdc9a: XOR ESI, ESI
0xabdc9c: XOR EDX, EDX
0xabdc9e: CALL 0x007d4eb0
0xabdca3: JMP 0x00abdbd0
0xabdca8: MOV EAX, dword ptr [RBX + 0x130]
0xabdcae: MOV RDI, R12
0xabdcb1: MOV qword ptr [RBP + -0xd0], RBX
0xabdcb8: XOR ESI, ESI
0xabdcba: XOR EDX, EDX
0xabdcbc: MOV dword ptr [RBP + -0x5c], EAX
0xabdcbf: MOV EAX, dword ptr [RBX + 0x138]
0xabdcc5: XOR EBX, EBX
0xabdcc7: MOV dword ptr [RBP + -0x58], EAX
0xabdcca: CALL 0x007d4eb0
0xabdccf: MOV R14, qword ptr [R15 + 0x20]
0xabdcd3: MOV qword ptr [RBP + -0xc0], R15
0xabdcda: MOV R15, qword ptr [R15 + 0x28]
0xabdcde: MOV RAX, -0x4000
0xabdce5: AND R14, RAX
0xabdce8: MOV EAX, 0x3fff
0xabdced: ADD R15, RAX
0xabdcf0: AND R15, -0x4000
0xabdcf7: CMP R14, R15
0xabdcfa: JNC 0x00abdd22
0xabdcfc: XOR EBX, EBX
0xabdcfe: NOP
0xabdd00: MOV RDI, qword ptr [R13 + 0x1d8]
0xabdd07: MOV RSI, R14
0xabdd0a: CALL 0x008de3e0
0xabdd0f: CMP RAX, 0x1
0xabdd13: SBB EBX, -0x1
0xabdd16: ADD R14, 0x4000
0xabdd1d: CMP R14, R15
0xabdd20: JC 0x00abdd00
0xabdd22: MOV dword ptr [RBP + -0x54], EBX
0xabdd25: MOV RBX, qword ptr [RBP + -0xd0]
0xabdd2c: LEA RCX, [0x3bf6e18]
0xabdd33: MOV R15, qword ptr [RBP + -0xc0]
0xabdd3a: MOV EAX, EBX
0xabdd3c: XOR EAX, ECX
0xabdd3e: CDQE
0xabdd40: MOV qword ptr [RBP + -0x68], RAX
0xabdd44: MOVZX EAX, byte ptr [RBX + 0x9d]
0xabdd4b: MOV dword ptr [RBP + -0x50], EAX
0xabdd4e: MOV RAX, qword ptr [R15 + 0x28]
0xabdd52: SUB RAX, qword ptr [R15 + 0x20]
0xabdd56: MOV qword ptr [RBP + -0x4c], 0x0
0xabdd5e: MOV qword ptr [RBP + -0x44], 0x0
0xabdd66: MOV qword ptr [RBP + -0x3c], 0x0
0xabdd6e: SHR RAX, 0xe
0xabdd72: MOV qword ptr [RBP + -0xc8], RAX
0xabdd79: TEST EAX, EAX
0xabdd7b: JLE 0x00abe03b
0xabdd81: MOV RAX, qword ptr [RBP + -0xc8]
0xabdd88: MOV qword ptr [RBP + -0xa8], R12
0xabdd8f: AND EAX, 0x7fffffff
0xabdd94: MOV qword ptr [RBP + -0xc8], RAX
0xabdd9b: XOR EAX, EAX
0xabdd9d: JMP 0x00abddd8
0xabdda0: INC dword ptr [RBP + -0x38]
0xabdda3: MOV R12, qword ptr [RBP + -0xa8]
0xabddaa: ADD RBX, 0x18
0xabddae: XOR ESI, ESI
0xabddb0: XOR EDX, EDX
0xabddb2: MOV RDI, RBX
0xabddb5: CALL 0x007d4eb0
0xabddba: MOV RAX, qword ptr [RBP + -0xf0]
0xabddc1: MOV RBX, qword ptr [RBP + -0xd0]
0xabddc8: INC RAX
0xabddcb: CMP RAX, qword ptr [RBP + -0xc8]
0xabddd2: JZ 0x00abe03b
0xabddd8: MOV R15, qword ptr [R15 + 0x58]
0xabdddc: MOV qword ptr [RBP + -0xf0], RAX
0xabdde3: SHL EAX, 0xe
0xabdde6: MOV RDI, R12
0xabdde9: XOR ESI, ESI
0xabddeb: XOR EDX, EDX
0xabdded: MOVSXD R13, EAX
0xabddf0: CALL 0x007d46a0
0xabddf5: LEA R14, [R15 + R13*0x1]
0xabddf9: MOV RDI, RBX
0xabddfc: SAR R14, 0xe
0xabde00: MOV RSI, R14
0xabde03: CALL 0x00b897e0
0xabde08: TEST RAX, RAX
0xabde0b: JNZ 0x00abde76
0xabde0d: MOV qword ptr [RBP + -0xd8], R13
0xabde14: MOV R13, RBX
0xabde17: NOP word ptr [RAX + RAX*0x1]
0xabde20: MOV RBX, qword ptr [R13 + 0xb0]
0xabde27: TEST RBX, RBX
0xabde2a: JZ 0x00abdf34
0xabde30: ADD R15, qword ptr [R13 + 0xb8]
0xabde37: LEA RDI, [RBX + 0x18]
0xabde3b: XOR ESI, ESI
0xabde3d: XOR EDX, EDX
0xabde3f: CALL 0x007d46a0
0xabde44: ADD R13, 0x18
0xabde48: XOR ESI, ESI
0xabde4a: XOR EDX, EDX
0xabde4c: MOV RDI, R13
0xabde4f: CALL 0x007d4eb0
0xabde54: MOV RAX, qword ptr [RBP + -0xd8]
0xabde5b: MOV RDI, RBX
0xabde5e: LEA R14, [R15 + RAX*0x1]
0xabde62: SAR R14, 0xe
0xabde66: MOV RSI, R14
0xabde69: CALL 0x00b897e0
0xabde6e: MOV R13, RBX
0xabde71: TEST RAX, RAX
0xabde74: JZ 0x00abde20
0xabde76: MOV RDI, RAX
0xabde79: MOV R12, RAX
0xabde7c: CALL 0x00b8d8a0
0xabde81: CMP dword ptr [R12 + 0x70], 0x0
0xabde87: MOV R15, qword ptr [RBP + -0xc0]
0xabde8e: JZ 0x00abdf20
0xabde94: INC dword ptr [RBP + -0x44]
0xabde97: CMP byte ptr [R12 + 0x66], 0x1
0xabde9d: JNZ 0x00abdea2
0xabde9f: INC dword ptr [RBP + -0x3c]
0xabdea2: CMP dword ptr [R12 + 0x70], 0x0
0xabdea8: JNZ 0x00abdda3
0xabdeae: MOV RAX, qword ptr [R12 + 0x20]
0xabdeb3: TEST RAX, RAX
0xabdeb6: JZ 0x00abdda0
0xabdebc: CMP byte ptr [RAX + 0x9d], 0x0
0xabdec3: JZ 0x00abdda0
0xabdec9: CMP byte ptr [RBX + 0x9d], 0x1
0xabded0: JNZ 0x00abdda3
0xabded6: LEA RAX, [0x1ac3910]
0xabdedd: MOV RAX, qword ptr [RAX + 0x8]
0xabdee1: MOV R12, qword ptr [RAX + 0x38]
0xabdee5: LEA RAX, [0x26b848]
0xabdeec: SUB RAX, R12
0xabdeef: ROR RAX, 0x3
0xabdef3: CMP RAX, 0xd
0xabdef7: JA 0x00abe016
0xabdefd: MOV RDI, RBX
0xabdf00: MOV RSI, R14
0xabdf03: XOR EDX, EDX
0xabdf05: XOR ECX, ECX
0xabdf07: CALL R12
0xabdf0a: TEST EAX, EAX
0xabdf0c: JNZ 0x00abdda3
0xabdf12: JMP 0x00abdda0
0xabdf20: INC dword ptr [RBP + -0x40]
0xabdf23: CMP byte ptr [R12 + 0x66], 0x1
0xabdf29: JZ 0x00abde9f
0xabdf2f: JMP 0x00abdea2
0xabdf34: ADD R13, 0x18
0xabdf38: XOR ESI, ESI
0xabdf3a: XOR EDX, EDX
0xabdf3c: MOV RDI, R13
0xabdf3f: CALL 0x007d4eb0
0xabdf44: MOV R15, qword ptr [RBP + -0xc0]
0xabdf4b: MOV RDI, qword ptr [RBP + -0xa8]
0xabdf52: XOR ESI, ESI
0xabdf54: XOR EDX, EDX
0xabdf56: MOV R12, qword ptr [R15 + 0x58]
0xabdf5a: CALL 0x007d46a0
0xabdf5f: MOV RBX, qword ptr [RBP + -0xd0]
0xabdf66: CMP byte ptr [RBX + 0x9d], 0x1
0xabdf6d: JNZ 0x00abdfb0
0xabdf6f: NOP
0xabdf70: LEA RAX, [0x1ac3910]
0xabdf77: MOV RAX, qword ptr [RAX + 0x8]
0xabdf7b: MOV R14, qword ptr [RAX + 0x38]
0xabdf7f: LEA RAX, [0x26b848]
0xabdf86: SUB RAX, R14
0xabdf89: ROR RAX, 0x3
0xabdf8d: CMP RAX, 0xd
0xabdf91: MOV RAX, qword ptr [RBP + -0xd8]
0xabdf98: JA 0x00abdfee
0xabdf9a: LEA RSI, [R12 + RAX*0x1]
0xabdf9e: MOV RDI, RBX
0xabdfa1: XOR EDX, EDX
0xabdfa3: XOR ECX, ECX
0xabdfa5: SAR RSI, 0xe
0xabdfa9: CALL R14
0xabdfac: TEST EAX, EAX
0xabdfae: JNZ 0x00abe00e
0xabdfb0: MOV R14, qword ptr [RBX + 0xb0]
0xabdfb7: TEST R14, R14
0xabdfba: JZ 0x00abe006
0xabdfbc: ADD R12, qword ptr [RBX + 0xb8]
0xabdfc3: LEA RDI, [R14 + 0x18]
0xabdfc7: XOR ESI, ESI
0xabdfc9: XOR EDX, EDX
0xabdfcb: CALL 0x007d46a0
0xabdfd0: ADD RBX, 0x18
0xabdfd4: XOR ESI, ESI
0xabdfd6: XOR EDX, EDX
0xabdfd8: MOV RDI, RBX
0xabdfdb: CALL 0x007d4eb0
0xabdfe0: MOV RBX, R14
0xabdfe3: CMP byte ptr [RBX + 0x9d], 0x1
0xabdfea: JZ 0x00abdf70
0xabdfec: JMP 0x00abdfb0
0xabdfee: LEA RDI, [0x2888d60]
0xabdff5: MOV RSI, R14
0xabdff8: CALL 0x0044f8c0
0xabdffd: MOV RAX, qword ptr [RBP + -0xd8]
0xabe004: JMP 0x00abdf9a
0xabe006: INC dword ptr [RBP + -0x4c]
0xabe009: JMP 0x00abdda3
0xabe00e: INC dword ptr [RBP + -0x48]
0xabe011: JMP 0x00abdda3
0xabe016: LEA RDI, [0x2888d60]
0xabe01d: MOV RSI, R12
0xabe020: CALL 0x0044f8c0
0xabe025: JMP 0x00abdefd
0xabe02a: MOV ESI, 0x68
0xabe02f: LEA RDI, [RBP + -0x98]
0xabe036: CALL 0x00258ff0
0xabe03b: LEA RSI, [R15 + 0x150]
0xabe042: MOV EDX, 0x20
0xabe047: LEA RDI, [RBP + -0x98]
0xabe04e: CALL 0x00957b70
0xabe053: MOV RAX, qword ptr [RBP + -0xb8]
0xabe05a: MOVSXD R14, dword ptr [RBP + -0x9c]
0xabe061: MOV R13, qword ptr [RBP + -0xe8]
0xabe068: MOV RBX, qword ptr [RAX + 0x10]
0xabe06c: TEST RBX, RBX
0xabe06f: JZ 0x00abdbc1
0xabe075: MOV RAX, qword ptr [RBP + -0xb8]
0xabe07c: CMP R14D, dword ptr [RAX + 0x8]
0xabe080: JGE 0x00abdbc1
0xabe086: IMUL RAX, R14, 0x68
0xabe08a: MOV RDI, qword ptr GS:[0x0]
0xabe093: LEA RSI, [0x134f297]
0xabe09a: XOR EDX, EDX
0xabe09c: ADD RBX, RAX
0xabe09f: CALL 0x00c1a3e0
0xabe0a4: MOV EDX, 0x68
0xabe0a9: LEA RDI, [RBP + -0x98]
0xabe0b0: MOV RSI, RBX
0xabe0b3: CALL 0x002591d0
0xabe0b8: TEST EAX, EAX
0xabe0ba: JZ 0x00abdbc1
0xabe0c0: MOV RDI, R13
0xabe0c3: XOR ESI, ESI
0xabe0c5: XOR EDX, EDX
0xabe0c7: CALL 0x002c6870
0xabe0cc: MOV RBX, qword ptr [RBP + -0xe0]
0xabe0d3: XOR ESI, ESI
0xabe0d5: XOR EDX, EDX
0xabe0d7: XOR ECX, ECX
0xabe0d9: MOV RDI, RBX
0xabe0dc: CALL 0x004c6a00
0xabe0e1: MOV RDI, qword ptr [RBP + -0xb0]
0xabe0e8: MOVZX ECX, byte ptr [RDI + 0xb1]
0xabe0ef: MOV EAX, dword ptr [RDI + 0x358]
0xabe0f5: SHR CL, 0x5
0xabe0f8: DEC EAX
0xabe0fa: SETZ DL
0xabe0fd: MOV dword ptr [RDI + 0x358], EAX
0xabe103: AND DL, CL
0xabe105: CMP DL, 0x1
0xabe108: JNZ 0x00abe116
0xabe10a: ADD RDI, 0x358
0xabe111: CALL 0x00c06910
0xabe116: MOV RDI, RBX
0xabe119: XOR ESI, ESI
0xabe11b: XOR EDX, EDX
0xabe11d: XOR ECX, ECX
0xabe11f: CALL 0x004c6fa0
0xabe124: MOV R14, qword ptr [RBP + -0xb8]
0xabe12b: LEA RSI, [0x134f297]
0xabe132: XOR EDX, EDX
0xabe134: MOV RBX, qword ptr [R14 + 0x18]
0xabe138: MOV RDI, qword ptr GS:[0x0]
0xabe141: CALL 0x00c1a3e0
0xabe146: LEA RDI, [RBP + -0x9c]
0xabe14d: MOV EDX, 0x4
0xabe152: MOV RSI, RBX
0xabe155: CALL 0x002591d0
0xabe15a: CMP qword ptr [R14 + 0x10], 0x0
0xabe15f: JZ 0x00abe173
0xabe161: MOV ECX, dword ptr [RBP + -0x9c]
0xabe167: CMP ECX, dword ptr [R14 + 0x8]
0xabe16b: MOV ECX, 0xc
0xabe170: CMOVG EAX, ECX
0xabe173: LEA RBX, [0x391c310]
0xabe17a: JMP 0x00abe19d
0xabe17c: MOV EAX, 0x1
0xabe181: JMP 0x00abe19d
0xabe183: ADD RCX, 0x148
0xabe18a: XOR ESI, ESI
0xabe18c: XOR EDX, EDX
0xabe18e: MOV RDI, RCX
0xabe191: XOR ECX, ECX
0xabe193: CALL 0x004c6fa0
0xabe198: MOV EAX, 0x2
0xabe19d: MOV RCX, qword ptr [RBX]
0xabe1a0: CMP RCX, qword ptr [RBP + -0x30]
0xabe1a4: JNZ 0x00abe1b8
0xabe1a6: ADD RSP, 0xc8
0xabe1ad: POP RBX
0xabe1ae: POP R12
0xabe1b0: POP R13
0xabe1b2: POP R14
0xabe1b4: POP R15
0xabe1b6: POP RBP
0xabe1b7: RET
0xabe1b8: CALL 0x006fd6b0
0xabe1bd: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_646 RVA 0xabe1c0 | Evidence ev_6dd8e331a72e689da69e2cc7753a5ea3dbbbaaa6735db7eb8f7956636b0f69e0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
sys_646:
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abe260 RVA 0xabe260 | Evidence ev_e1ec54065c9bdcce5a4467fbd5ff29f804268b4bd587c680f5d7b550fe501fa1 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_647 RVA 0xabe7b0 | Evidence ev_ad2157b997c3b0aa40a8bcb48bc446bd954e1c5c6788107ffac71438d61e19d9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abe830 RVA 0xabe830 | Evidence ev_ae2cea8c19be902aa4e2141e8ec636a21762ad45be069d73a63acd4e387f774c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_671 RVA 0xabe8b0 | Evidence ev_6a0ba9616ee77ccb98dfcd9acca905ff80cf2a82c90f2b8900038d432aa39c9f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00abea41 RVA 0xabea41 | Evidence ev_ea01537287aeb556de8584df4b2f40ba13f34aa3f6adc6d31b99d3f04dc92984 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
FUN_00abea41:
0xabea41: MOVZX R8D, R8W
0xabea45: MOVZX R9D, R9W
0xabea49: JMP R11


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abea52 RVA 0xabea52 | Evidence ev_8ffcde751a32377c9bb727047203cbce16b175ecc691ecd07e879bf668ad1b47 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeac0 RVA 0xabeac0 | Evidence ev_1b2dd65089db4984a5595e6facb2d67d1b90060dbcf1092a6f9159b727c3d85c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeaf0 RVA 0xabeaf0 | Evidence ev_0ac3946f0308b9689a6eafb7811282180ab6d421c233354117674809e8bfb3e8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeba0 RVA 0xabeba0 | Evidence ev_e57310a4c9d5b607b2da89162f63a4be05c0a5bb02322220524b3d0139ba09c5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abec30 RVA 0xabec30 | Evidence ev_8193ff149d38a96c3942e0f42dc1c5c8d82e02066cbf4d730d0f70ddddf31fc2 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abecc0 RVA 0xabecc0 | Evidence ev_e86028d8e8be786027e776c54359b5b8ed03cd55c133e7554bfb3e405bc68be4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abed50 RVA 0xabed50 | Evidence ev_529edab37eb87921384e40ecc8c6d4c92b681bc9905bd37fe0e7c64900e085df | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abedd0 RVA 0xabedd0 | Evidence ev_91310290c354165ea3ad79efda3b29c1916ae83af77e6205f9b5346376eb7715 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abee20 RVA 0xabee20 | Evidence ev_8212aaf2e1553ab7ad9dd1a50b45c2e0d155ac424dd588b3bc7a272ef3d076c7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00abef70 RVA 0xabef70 | Evidence ev_74a8cfc7afe83b1d2d7344b26add4d3375f6a33f1dd3c978dbebbb2f7e948b61 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abefa4 RVA 0xabefa4 | Evidence ev_1cc18d9973341292c5341586098c6b7dedddf8766b6450c1cd13a49da0c2f4e6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf000 RVA 0xabf000 | Evidence ev_72745f7ffa2cba9befc2c36738e4b590737d291edeaead17db1b61f3485f839d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf100 RVA 0xabf100 | Evidence ev_2cc58f92c555f00996c45434240c23e8ed0eb74ea8cec49f03cf3915631a0f3f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf140 RVA 0xabf140 | Evidence ev_d14f764bb12998a552db9511f3b6ad55230f423d84dec99f02eb5d22187e088b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf1b0 RVA 0xabf1b0 | Evidence ev_451e6cd32033d210ef621f1fbb25cac2e0e61daf3da6fb58883bf5b3f33fb236 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf1e0 RVA 0xabf1e0 | Evidence ev_faf45e73336220ea790a8ff7c70ae77a4a0e399b4dd6d5ea058abd596e182d36 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf220 RVA 0xabf220 | Evidence ev_fed1875767baa41d299bb6ffcdd369b4080bb1c5ff42c63f85b913d9f215dba6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf240 RVA 0xabf240 | Evidence ev_ae365cc45b3ad92ac7d8373c9934d5d0c6603d9c46b87bef49ebf82f71b8ed6c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf2d0 RVA 0xabf2d0 | Evidence ev_c276ad7c900dfa94a89f98f8c180dc1595321642d744ae26ed6bf2fe5c6e416d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf33f RVA 0xabf33f | Evidence ev_289690e91e90bcbd74062a539f6d390cfc93192f9e3fbfb61669a403fe5ad0c6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf460 RVA 0xabf460 | Evidence ev_c7fe6e3587bf7f9defe0a7d65b41e26ae6de3720ece1eddb2222be2fc3a842f5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf510 RVA 0xabf510 | Evidence ev_d93df06e0aa0766b8610e6ba614d06f0acb395be773851680d68bddda5f4b65d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf540 RVA 0xabf540 | Evidence ev_918f5feab5e8aadfd8bac1076658fe4bde79dbd34d89d5d4e0e412f387801228 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf570 RVA 0xabf570 | Evidence ev_054a0ea8af0834f949fbd0b838e11c80f4b54303cea77c47ab7bb82156f63489 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf5e0 RVA 0xabf5e0 | Evidence ev_6408a80daa750bd6e5fe4ddea25f72259b6864803d69929d8cf6a64ec96a4a0d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf8e0 RVA 0xabf8e0 | Evidence ev_afedb27937d64eb5d0dfe1ddc3ae082009dbb6b23b1bfb13365216a5ca925195 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): copyout_candidate RVA 0x2591d0 | Evidence ev_71486184be245b984abbb9be576981c38f613a7db64a834e00ab1b4e60ea2113 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.functions/0x2591d0.json | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.elf SHA256 843fa164383f956095dc4042a013c49d64f59c358ea7f43c10f0d9923485fd5a =====
copyout_candidate:
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


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): zero_fill_helper RVA 0x258ff0 | Evidence ev_9f715f53ca8e7945dcf5dd090a09697d620766198f5ec9c1ad147fd5676b3ea0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.functions/0x258ff0.json | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.elf SHA256 843fa164383f956095dc4042a013c49d64f59c358ea7f43c10f0d9923485fd5a =====
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


; ===== SUPPLEMENTAL GNU objdump full linear disassembly of every original4096 input byte =====
; Source raw file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_674.bin
; This is independent linear decoding, not REA function discovery; padding/data may decode as instructions.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_674.bin:     file format binary


Disassembly of section .data:

0000000000265fa0 <.data>:
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
  266f88:	e9 63 de 9c 00       	jmp    0xc34df0
  266f8d:	cc                   	int3
  266f8e:	cc                   	int3
  266f8f:	cc                   	int3
  266f90:	e9 db 27 9d 00       	jmp    0xc39770
  266f95:	cc                   	int3
  266f96:	cc                   	int3
  266f97:	cc                   	int3
  266f98:	e9 83 ca 9d 00       	jmp    0xc43a20
  266f9d:	cc                   	int3
  266f9e:	cc                   	int3
  266f9f:	cc                   	int3


; ===== SUPPLEMENTAL GNU objdump FULL original target-window bytes =====
; Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe
; RVA 0xabb980; size16384 bytes. This linear decode may include adjacent code/data and is not a REA boundary claim.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin:     file format binary


Disassembly of section .data:

0000000000abb980 <.data>:
  abb980:	55                   	push   rbp
  abb981:	48 89 e5             	mov    rbp,rsp
  abb984:	41 57                	push   r15
  abb986:	41 56                	push   r14
  abb988:	41 55                	push   r13
  abb98a:	41 54                	push   r12
  abb98c:	53                   	push   rbx
  abb98d:	48 81 ec f8 00 00 00 	sub    rsp,0xf8
  abb994:	48 8d 1d 75 09 e6 02 	lea    rbx,[rip+0x2e60975]        # 0x391c310
  abb99b:	49 89 fd             	mov    r13,rdi
  abb99e:	bf 04 00 00 00       	mov    edi,0x4
  abb9a3:	49 89 f6             	mov    r14,rsi
  abb9a6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  abb9a9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abb9ad:	e8 4e 01 07 00       	call   0xb2bb00
  abb9b2:	41 bc 16 00 00 00    	mov    r12d,0x16
  abb9b8:	85 c0                	test   eax,eax
  abb9ba:	0f 85 6d 03 00 00    	jne    0xabbd2d
  abb9c0:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  abb9c3:	48 85 c9             	test   rcx,rcx
  abb9c6:	74 1a                	je     0xabb9e2
  abb9c8:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  abb9cc:	48 89 85 10 ff ff ff 	mov    QWORD PTR [rbp-0xf0],rax
  abb9d3:	41 81 7e 20 00 00 00 	cmp    DWORD PTR [r14+0x20],0x40000000
  abb9da:	40 
  abb9db:	74 1e                	je     0xabb9fb
  abb9dd:	e9 4b 03 00 00       	jmp    0xabbd2d
  abb9e2:	48 c7 85 10 ff ff ff 	mov    QWORD PTR [rbp-0xf0],0x0
  abb9e9:	00 00 00 00 
  abb9ed:	41 81 7e 20 00 00 00 	cmp    DWORD PTR [r14+0x20],0x40000000
  abb9f4:	40 
  abb9f5:	0f 85 32 03 00 00    	jne    0xabbd2d
  abb9fb:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  abb9ff:	4d 8b 66 08          	mov    r12,QWORD PTR [r14+0x8]
  abba03:	48 89 8d 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],rcx
  abba0a:	4c 89 b5 e8 fe ff ff 	mov    QWORD PTR [rbp-0x118],r14
  abba11:	4c 89 ad 00 ff ff ff 	mov    QWORD PTR [rbp-0x100],r13
  abba18:	8b b8 bc 00 00 00    	mov    edi,DWORD PTR [rax+0xbc]
  abba1e:	48 8b 98 00 02 00 00 	mov    rbx,QWORD PTR [rax+0x200]
  abba25:	e8 b6 9a ff ff       	call   0xab54e0
  abba2a:	48 89 df             	mov    rdi,rbx
  abba2d:	89 85 24 ff ff ff    	mov    DWORD PTR [rbp-0xdc],eax
  abba33:	45 31 f6             	xor    r14d,r14d
  abba36:	31 f6                	xor    esi,esi
  abba38:	31 d2                	xor    edx,edx
  abba3a:	e8 e1 ad 80 ff       	call   0x2c6820
  abba3f:	48 89 df             	mov    rdi,rbx
  abba42:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
  abba46:	49 83 fc 48          	cmp    r12,0x48
  abba4a:	b8 48 00 00 00       	mov    eax,0x48
  abba4f:	4c 8d 7d 88          	lea    r15,[rbp-0x78]
  abba53:	4c 89 a5 f0 fe ff ff 	mov    QWORD PTR [rbp-0x110],r12
  abba5a:	48 c7 85 08 ff ff ff 	mov    QWORD PTR [rbp-0xf8],0xffffffffffffffff
  abba61:	ff ff ff ff 
  abba65:	49 0f 42 c4          	cmovb  rax,r12
  abba69:	45 31 ed             	xor    r13d,r13d
  abba6c:	48 89 bd 18 ff ff ff 	mov    QWORD PTR [rbp-0xe8],rdi
  abba73:	48 89 85 f8 fe ff ff 	mov    QWORD PTR [rbp-0x108],rax
  abba7a:	eb 1e                	jmp    0xabba9a
  abba7c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  abba80:	48 b8 00 00 00 00 00 	movabs rax,0x80000000000
  abba87:	08 00 00 
  abba8a:	49 ff c5             	inc    r13
  abba8d:	48 ff c8             	dec    rax
  abba90:	48 39 43 20          	cmp    QWORD PTR [rbx+0x20],rax
  abba94:	0f 87 ac 00 00 00    	ja     0xabbb46
  abba9a:	45 31 e4             	xor    r12d,r12d
  abba9d:	48 39 fb             	cmp    rbx,rdi
  abbaa0:	0f 84 a0 00 00 00    	je     0xabbb46
  abbaa6:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  abbaaa:	48 89 de             	mov    rsi,rbx
  abbaad:	4c 89 f9             	mov    rcx,r15
  abbab0:	41 b8 01 00 00 00    	mov    r8d,0x1
  abbab6:	41 b9 01 00 00 00    	mov    r9d,0x1
  abbabc:	49 39 c6             	cmp    r14,rax
  abbabf:	4c 0f 46 f0          	cmovbe r14,rax
  abbac3:	4c 89 f2             	mov    rdx,r14
  abbac6:	e8 45 ec ff ff       	call   0xaba710
  abbacb:	4c 3b ad 10 ff ff ff 	cmp    r13,QWORD PTR [rbp-0xf0]
  abbad2:	73 42                	jae    0xabbb16
  abbad4:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abbadb:	00 00 
  abbadd:	48 8d 35 b3 37 89 00 	lea    rsi,[rip+0x8937b3]        # 0x134f297
  abbae4:	31 d2                	xor    edx,edx
  abbae6:	e8 f5 e8 15 00       	call   0xc1a3e0
  abbaeb:	4c 89 ff             	mov    rdi,r15
  abbaee:	4c 8b bd 28 ff ff ff 	mov    r15,QWORD PTR [rbp-0xd8]
  abbaf5:	48 8b 95 f8 fe ff ff 	mov    rdx,QWORD PTR [rbp-0x108]
  abbafc:	4c 89 fe             	mov    rsi,r15
  abbaff:	e8 cc d6 79 ff       	call   0x2591d0
  abbb04:	85 c0                	test   eax,eax
  abbb06:	75 30                	jne    0xabbb38
  abbb08:	4c 03 bd f0 fe ff ff 	add    r15,QWORD PTR [rbp-0x110]
  abbb0f:	4c 89 bd 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],r15
  abbb16:	48 8b bd 18 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xe8]
  abbb1d:	4c 8b 75 90          	mov    r14,QWORD PTR [rbp-0x70]
  abbb21:	4c 8d 7d 88          	lea    r15,[rbp-0x78]
  abbb25:	4c 39 73 28          	cmp    QWORD PTR [rbx+0x28],r14
  abbb29:	0f 87 51 ff ff ff    	ja     0xabba80
  abbb2f:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
  abbb33:	e9 48 ff ff ff       	jmp    0xabba80
  abbb38:	48 8b bd 18 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xe8]
  abbb3f:	41 89 c4             	mov    r12d,eax
  abbb42:	4c 8d 7d 88          	lea    r15,[rbp-0x78]
  abbb46:	83 bd 24 ff ff ff 00 	cmp    DWORD PTR [rbp-0xdc],0x0
  abbb4d:	75 48                	jne    0xabbb97
  abbb4f:	49 be 00 00 00 00 00 	movabs r14,0x80000000000
  abbb56:	08 00 00 
  abbb59:	45 85 e4             	test   r12d,r12d
  abbb5c:	74 64                	je     0xabbbc2
  abbb5e:	4c 8b bd 28 ff ff ff 	mov    r15,QWORD PTR [rbp-0xd8]
  abbb65:	48 8b 85 00 ff ff ff 	mov    rax,QWORD PTR [rbp-0x100]
  abbb6c:	4c 89 bd 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],r15
  abbb73:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abbb77:	8b b8 bc 00 00 00    	mov    edi,DWORD PTR [rax+0xbc]
  abbb7d:	e8 0e 9b ff ff       	call   0xab5690
  abbb82:	48 8b bd 18 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xe8]
  abbb89:	4c 8d 7d 88          	lea    r15,[rbp-0x78]
  abbb8d:	c7 85 24 ff ff ff ff 	mov    DWORD PTR [rbp-0xdc],0xffffffff
  abbb94:	ff ff ff 
  abbb97:	45 85 e4             	test   r12d,r12d
  abbb9a:	0f 85 4b 01 00 00    	jne    0xabbceb
  abbba0:	48 39 fb             	cmp    rbx,rdi
  abbba3:	0f 84 42 01 00 00    	je     0xabbceb
  abbba9:	4c 3b b5 08 ff ff ff 	cmp    r14,QWORD PTR [rbp-0xf8]
  abbbb0:	4c 89 b5 08 ff ff ff 	mov    QWORD PTR [rbp-0xf8],r14
  abbbb7:	0f 85 dd fe ff ff    	jne    0xabba9a
  abbbbd:	e9 89 01 00 00       	jmp    0xabbd4b
  abbbc2:	4c 8b bd 28 ff ff ff 	mov    r15,QWORD PTR [rbp-0xd8]
  abbbc9:	eb 26                	jmp    0xabbbf1
  abbbcb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  abbbd0:	4c 8b b5 38 ff ff ff 	mov    r14,QWORD PTR [rbp-0xc8]
  abbbd7:	4c 03 bd f0 fe ff ff 	add    r15,QWORD PTR [rbp-0x110]
  abbbde:	49 ff c5             	inc    r13
  abbbe1:	4c 89 f0             	mov    rax,r14
  abbbe4:	48 c1 e8 28          	shr    rax,0x28
  abbbe8:	83 f8 0f             	cmp    eax,0xf
  abbbeb:	0f 83 74 ff ff ff    	jae    0xabbb65
  abbbf1:	48 8b 85 00 ff ff ff 	mov    rax,QWORD PTR [rbp-0x100]
  abbbf8:	4c 89 f6             	mov    rsi,r14
  abbbfb:	ba 01 00 00 00       	mov    edx,0x1
  abbc00:	48 8d 8d 30 ff ff ff 	lea    rcx,[rbp-0xd0]
  abbc07:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abbc0b:	8b b8 bc 00 00 00    	mov    edi,DWORD PTR [rax+0xbc]
  abbc11:	e8 aa ab ff ff       	call   0xab67c0
  abbc16:	45 31 e4             	xor    r12d,r12d
  abbc19:	85 c0                	test   eax,eax
  abbc1b:	0f 85 44 ff ff ff    	jne    0xabbb65
  abbc21:	be 48 00 00 00       	mov    esi,0x48
  abbc26:	48 8d 7d 88          	lea    rdi,[rbp-0x78]
  abbc2a:	e8 c1 d3 79 ff       	call   0x258ff0
  abbc2f:	48 8b 85 30 ff ff ff 	mov    rax,QWORD PTR [rbp-0xd0]
  abbc36:	48 8b 8d 38 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xc8]
  abbc3d:	48 8b b5 40 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xc0]
  abbc44:	0f b6 95 50 ff ff ff 	movzx  edx,BYTE PTR [rbp-0xb0]
  abbc4b:	48 8d 7d a9          	lea    rdi,[rbp-0x57]
  abbc4f:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  abbc53:	c4 e3 fb f0 85 48 ff 	rorx   rax,QWORD PTR [rbp-0xb8],0x20
  abbc5a:	ff ff 20 
  abbc5d:	48 89 4d 90          	mov    QWORD PTR [rbp-0x70],rcx
  abbc61:	48 89 75 98          	mov    QWORD PTR [rbp-0x68],rsi
  abbc65:	c0 e2 06             	shl    dl,0x6
  abbc68:	48 8d b5 65 ff ff ff 	lea    rsi,[rbp-0x9b]
  abbc6f:	80 e2 40             	and    dl,0x40
  abbc72:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  abbc76:	0f b6 85 60 ff ff ff 	movzx  eax,BYTE PTR [rbp-0xa0]
  abbc7d:	0f b6 4d a8          	movzx  ecx,BYTE PTR [rbp-0x58]
  abbc81:	c0 e0 05             	shl    al,0x5
  abbc84:	24 20                	and    al,0x20
  abbc86:	80 e1 9f             	and    cl,0x9f
  abbc89:	08 c1                	or     cl,al
  abbc8b:	08 ca                	or     dl,cl
  abbc8d:	0f b6 8d 64 ff ff ff 	movzx  ecx,BYTE PTR [rbp-0x9c]
  abbc94:	88 55 a8             	mov    BYTE PTR [rbp-0x58],dl
  abbc97:	ba 20 00 00 00       	mov    edx,0x20
  abbc9c:	88 4d c9             	mov    BYTE PTR [rbp-0x37],cl
  abbc9f:	e8 cc be e9 ff       	call   0x957b70
  abbca4:	4c 3b ad 10 ff ff ff 	cmp    r13,QWORD PTR [rbp-0xf0]
  abbcab:	0f 83 1f ff ff ff    	jae    0xabbbd0
  abbcb1:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abbcb8:	00 00 
  abbcba:	48 8d 35 d6 35 89 00 	lea    rsi,[rip+0x8935d6]        # 0x134f297
  abbcc1:	31 d2                	xor    edx,edx
  abbcc3:	e8 18 e7 15 00       	call   0xc1a3e0
  abbcc8:	48 8b 95 f8 fe ff ff 	mov    rdx,QWORD PTR [rbp-0x108]
  abbccf:	48 8d 7d 88          	lea    rdi,[rbp-0x78]
  abbcd3:	4c 89 fe             	mov    rsi,r15
  abbcd6:	e8 f5 d4 79 ff       	call   0x2591d0
  abbcdb:	85 c0                	test   eax,eax
  abbcdd:	0f 84 ed fe ff ff    	je     0xabbbd0
  abbce3:	41 89 c4             	mov    r12d,eax
  abbce6:	e9 7a fe ff ff       	jmp    0xabbb65
  abbceb:	31 f6                	xor    esi,esi
  abbced:	31 d2                	xor    edx,edx
  abbcef:	e8 7c ab 80 ff       	call   0x2c6870
  abbcf4:	48 8d 1d 15 06 e6 02 	lea    rbx,[rip+0x2e60615]        # 0x391c310
  abbcfb:	48 8b 85 e8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x118]
  abbd02:	45 85 e4             	test   r12d,r12d
  abbd05:	75 26                	jne    0xabbd2d
  abbd07:	48 8b 78 18          	mov    rdi,QWORD PTR [rax+0x18]
  abbd0b:	41 bc 00 00 00 00    	mov    r12d,0x0
  abbd11:	48 85 ff             	test   rdi,rdi
  abbd14:	74 17                	je     0xabbd2d
  abbd16:	4c 89 ee             	mov    rsi,r13
  abbd19:	e8 02 da 79 ff       	call   0x259720
  abbd1e:	31 c9                	xor    ecx,ecx
  abbd20:	83 f8 ff             	cmp    eax,0xffffffff
  abbd23:	41 bc 0e 00 00 00    	mov    r12d,0xe
  abbd29:	44 0f 45 e1          	cmovne r12d,ecx
  abbd2d:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  abbd30:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  abbd34:	75 3b                	jne    0xabbd71
  abbd36:	44 89 e0             	mov    eax,r12d
  abbd39:	48 81 c4 f8 00 00 00 	add    rsp,0xf8
  abbd40:	5b                   	pop    rbx
  abbd41:	41 5c                	pop    r12
  abbd43:	41 5d                	pop    r13
  abbd45:	41 5e                	pop    r14
  abbd47:	41 5f                	pop    r15
  abbd49:	5d                   	pop    rbp
  abbd4a:	c3                   	ret
  abbd4b:	e8 00 5c d3 ff       	call   0x7f1950
  abbd50:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0xabbd4b
  abbd57:	e8 b4 5a d3 ff       	call   0x7f1810
  abbd5c:	48 8d 35 2f 9d 8d 00 	lea    rsi,[rip+0x8d9d2f]        # 0x1395a92
  abbd63:	bf 17 00 00 00       	mov    edi,0x17
  abbd68:	31 c0                	xor    eax,eax
  abbd6a:	e8 a1 ec 1d 00       	call   0xc9aa10
  abbd6f:	0f 0b                	ud2
  abbd71:	e8 3a 19 c4 ff       	call   0x6fd6b0
  abbd76:	0f 0b                	ud2
  abbd78:	90                   	nop
  abbd79:	90                   	nop
  abbd7a:	90                   	nop
  abbd7b:	90                   	nop
  abbd7c:	90                   	nop
  abbd7d:	90                   	nop
  abbd7e:	90                   	nop
  abbd7f:	90                   	nop
  abbd80:	55                   	push   rbp
  abbd81:	48 89 e5             	mov    rbp,rsp
  abbd84:	41 57                	push   r15
  abbd86:	41 56                	push   r14
  abbd88:	41 55                	push   r13
  abbd8a:	41 54                	push   r12
  abbd8c:	53                   	push   rbx
  abbd8d:	50                   	push   rax
  abbd8e:	48 8b 1e             	mov    rbx,QWORD PTR [rsi]
  abbd91:	48 8b 4e 08          	mov    rcx,QWORD PTR [rsi+0x8]
  abbd95:	b8 16 00 00 00       	mov    eax,0x16
  abbd9a:	48 01 d9             	add    rcx,rbx
  abbd9d:	0f 82 a1 00 00 00    	jb     0xabbe44
  abbda3:	4c 8d b1 ff 3f 00 00 	lea    r14,[rcx+0x3fff]
  abbdaa:	49 81 e6 00 c0 ff ff 	and    r14,0xffffffffffffc000
  abbdb1:	49 39 ce             	cmp    r14,rcx
  abbdb4:	0f 82 8a 00 00 00    	jb     0xabbe44
  abbdba:	44 8b 7e 10          	mov    r15d,DWORD PTR [rsi+0x10]
  abbdbe:	49 89 f4             	mov    r12,rsi
  abbdc1:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
  abbdc5:	49 89 fd             	mov    r13,rdi
  abbdc8:	44 89 ff             	mov    edi,r15d
  abbdcb:	e8 10 76 90 ff       	call   0x3c33e0
  abbdd0:	85 c0                	test   eax,eax
  abbdd2:	74 21                	je     0xabbdf5
  abbdd4:	49 8b 4d 08          	mov    rcx,QWORD PTR [r13+0x8]
  abbdd8:	41 8b 54 24 18       	mov    edx,DWORD PTR [r12+0x18]
  abbddd:	b8 16 00 00 00       	mov    eax,0x16
  abbde2:	80 b9 81 0c 00 00 00 	cmp    BYTE PTR [rcx+0xc81],0x0
  abbde9:	74 11                	je     0xabbdfc
  abbdeb:	f7 c2 08 fc 00 00    	test   edx,0xfc08
  abbdf1:	75 51                	jne    0xabbe44
  abbdf3:	eb 0c                	jmp    0xabbe01
  abbdf5:	b8 16 00 00 00       	mov    eax,0x16
  abbdfa:	eb 48                	jmp    0xabbe44
  abbdfc:	f6 c2 08             	test   dl,0x8
  abbdff:	75 43                	jne    0xabbe44
  abbe01:	89 d0                	mov    eax,edx
  abbe03:	48 8b b9 00 02 00 00 	mov    rdi,QWORD PTR [rcx+0x200]
  abbe0a:	48 81 e3 00 c0 ff ff 	and    rbx,0xffffffffffffc000
  abbe11:	44 89 f9             	mov    ecx,r15d
  abbe14:	d1 e8                	shr    eax,1
  abbe16:	48 89 de             	mov    rsi,rbx
  abbe19:	25 41 01 00 00       	and    eax,0x141
  abbe1e:	09 d0                	or     eax,edx
  abbe20:	4c 89 f2             	mov    rdx,r14
  abbe23:	44 0f b7 c0          	movzx  r8d,ax
  abbe27:	e8 94 15 81 ff       	call   0x2cd3c0
  abbe2c:	89 c1                	mov    ecx,eax
  abbe2e:	b8 16 00 00 00       	mov    eax,0x16
  abbe33:	83 f9 09             	cmp    ecx,0x9
  abbe36:	77 0c                	ja     0xabbe44
  abbe38:	89 c8                	mov    eax,ecx
  abbe3a:	48 8d 15 73 01 e2 00 	lea    rdx,[rip+0xe20173]        # 0x18dbfb4
  abbe41:	8b 04 82             	mov    eax,DWORD PTR [rdx+rax*4]
  abbe44:	48 83 c4 08          	add    rsp,0x8
  abbe48:	5b                   	pop    rbx
  abbe49:	41 5c                	pop    r12
  abbe4b:	41 5d                	pop    r13
  abbe4d:	41 5e                	pop    r14
  abbe4f:	41 5f                	pop    r15
  abbe51:	5d                   	pop    rbp
  abbe52:	c3                   	ret
  abbe53:	90                   	nop
  abbe54:	90                   	nop
  abbe55:	90                   	nop
  abbe56:	90                   	nop
  abbe57:	90                   	nop
  abbe58:	90                   	nop
  abbe59:	90                   	nop
  abbe5a:	90                   	nop
  abbe5b:	90                   	nop
  abbe5c:	90                   	nop
  abbe5d:	90                   	nop
  abbe5e:	90                   	nop
  abbe5f:	90                   	nop
  abbe60:	55                   	push   rbp
  abbe61:	48 89 e5             	mov    rbp,rsp
  abbe64:	41 57                	push   r15
  abbe66:	41 56                	push   r14
  abbe68:	41 55                	push   r13
  abbe6a:	41 54                	push   r12
  abbe6c:	53                   	push   rbx
  abbe6d:	48 81 ec 88 00 00 00 	sub    rsp,0x88
  abbe74:	4c 8d 35 95 04 e6 02 	lea    r14,[rip+0x2e60495]        # 0x391c310
  abbe7b:	48 89 f3             	mov    rbx,rsi
  abbe7e:	49 8b 06             	mov    rax,QWORD PTR [r14]
  abbe81:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abbe85:	44 8b 6e 18          	mov    r13d,DWORD PTR [rsi+0x18]
  abbe89:	45 85 ed             	test   r13d,r13d
  abbe8c:	78 69                	js     0xabbef7
  abbe8e:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  abbe92:	31 c9                	xor    ecx,ecx
  abbe94:	80 b8 81 0c 00 00 00 	cmp    BYTE PTR [rax+0xc81],0x0
  abbe9b:	b8 16 00 00 00       	mov    eax,0x16
  abbea0:	0f 95 c1             	setne  cl
  abbea3:	c1 e1 1d             	shl    ecx,0x1d
  abbea6:	81 c1 6f fb bf e0    	add    ecx,0xe0bffb6f
  abbeac:	85 4b 08             	test   DWORD PTR [rbx+0x8],ecx
  abbeaf:	0f 85 bc 04 00 00    	jne    0xabc371
  abbeb5:	48 8d 45 88          	lea    rax,[rbp-0x78]
  abbeb9:	66 c7 87 16 01 00 00 	mov    WORD PTR [rdi+0x116],0x1
  abbec0:	01 00 
  abbec2:	c6 87 f0 05 00 00 00 	mov    BYTE PTR [rdi+0x5f0],0x0
  abbec9:	48 c7 45 88 00 00 00 	mov    QWORD PTR [rbp-0x78],0x0
  abbed0:	00 
  abbed1:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
  abbed8:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  abbedc:	4d 85 ed             	test   r13,r13
  abbedf:	0f 84 68 03 00 00    	je     0xabc24d
  abbee5:	c7 85 64 ff ff ff ff 	mov    DWORD PTR [rbp-0x9c],0xffffffff
  abbeec:	ff ff ff 
  abbeef:	45 31 f6             	xor    r14d,r14d
  abbef2:	45 31 ff             	xor    r15d,r15d
  abbef5:	eb 71                	jmp    0xabbf68
  abbef7:	48 8b 7b 20          	mov    rdi,QWORD PTR [rbx+0x20]
  abbefb:	b8 16 00 00 00       	mov    eax,0x16
  abbf00:	48 85 ff             	test   rdi,rdi
  abbf03:	0f 84 68 04 00 00    	je     0xabc371
  abbf09:	31 f6                	xor    esi,esi
  abbf0b:	e8 80 d8 79 ff       	call   0x259790
  abbf10:	b8 16 00 00 00       	mov    eax,0x16
  abbf15:	e9 57 04 00 00       	jmp    0xabc371
  abbf1a:	48 8b 3d f7 ae 13 03 	mov    rdi,QWORD PTR [rip+0x313aef7]        # 0x3bf6e18
  abbf21:	ba 02 00 00 00       	mov    edx,0x2
  abbf26:	31 f6                	xor    esi,esi
  abbf28:	e8 53 f9 97 ff       	call   0x43b880
  abbf2d:	48 8d 70 08          	lea    rsi,[rax+0x8]
  abbf31:	ba 20 00 00 00       	mov    edx,0x20
  abbf36:	48 8d bd 68 ff ff ff 	lea    rdi,[rbp-0x98]
  abbf3d:	49 89 c4             	mov    r12,rax
  abbf40:	e8 9b dc 79 ff       	call   0x259be0
  abbf45:	49 c7 04 24 00 00 00 	mov    QWORD PTR [r12],0x0
  abbf4c:	00 
  abbf4d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
  abbf51:	4c 89 20             	mov    QWORD PTR [rax],r12
  abbf54:	4c 89 65 90          	mov    QWORD PTR [rbp-0x70],r12
  abbf58:	49 ff c7             	inc    r15
  abbf5b:	49 83 c6 20          	add    r14,0x20
  abbf5f:	4d 39 fd             	cmp    r13,r15
  abbf62:	0f 84 ef 02 00 00    	je     0xabc257
  abbf68:	4c 8b 63 10          	mov    r12,QWORD PTR [rbx+0x10]
  abbf6c:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abbf73:	00 00 
  abbf75:	48 8d 35 c1 bf 8d 00 	lea    rsi,[rip+0x8dbfc1]        # 0x1397f3d
  abbf7c:	31 d2                	xor    edx,edx
  abbf7e:	4d 01 f4             	add    r12,r14
  abbf81:	e8 5a e4 15 00       	call   0xc1a3e0
  abbf86:	ba 20 00 00 00       	mov    edx,0x20
  abbf8b:	4c 89 e7             	mov    rdi,r12
  abbf8e:	48 8d b5 68 ff ff ff 	lea    rsi,[rbp-0x98]
  abbf95:	e8 e6 d2 79 ff       	call   0x259280
  abbf9a:	85 c0                	test   eax,eax
  abbf9c:	0f 85 16 03 00 00    	jne    0xabc2b8
  abbfa2:	8b 4d 84             	mov    ecx,DWORD PTR [rbp-0x7c]
  abbfa5:	83 f9 04             	cmp    ecx,0x4
  abbfa8:	74 29                	je     0xabbfd3
  abbfaa:	48 83 7d 88 00       	cmp    QWORD PTR [rbp-0x78],0x0
  abbfaf:	74 22                	je     0xabbfd3
  abbfb1:	48 8d 7d 88          	lea    rdi,[rbp-0x78]
  abbfb5:	48 8d 75 98          	lea    rsi,[rbp-0x68]
  abbfb9:	e8 f2 03 00 00       	call   0xabc3b0
  abbfbe:	85 c0                	test   eax,eax
  abbfc0:	0f 85 d8 02 00 00    	jne    0xabc29e
  abbfc6:	8b 4d 84             	mov    ecx,DWORD PTR [rbp-0x7c]
  abbfc9:	c7 85 64 ff ff ff ff 	mov    DWORD PTR [rbp-0x9c],0xffffffff
  abbfd0:	ff ff ff 
  abbfd3:	b8 16 00 00 00       	mov    eax,0x16
  abbfd8:	83 f9 04             	cmp    ecx,0x4
  abbfdb:	0f 87 d7 02 00 00    	ja     0xabc2b8
  abbfe1:	89 c9                	mov    ecx,ecx
  abbfe3:	48 8d 15 6a ff e1 00 	lea    rdx,[rip+0xe1ff6a]        # 0x18dbf54
  abbfea:	48 63 0c 8a          	movsxd rcx,DWORD PTR [rdx+rcx*4]
  abbfee:	48 01 d1             	add    rcx,rdx
  abbff1:	ff e1                	jmp    rcx
  abbff3:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  abbffa:	8b 33                	mov    esi,DWORD PTR [rbx]
  abbffc:	8b 4b 08             	mov    ecx,DWORD PTR [rbx+0x8]
  abbfff:	0f b6 55 80          	movzx  edx,BYTE PTR [rbp-0x80]
  abc003:	48 8b 7f 08          	mov    rdi,QWORD PTR [rdi+0x8]
  abc007:	4c 8b 87 00 02 00 00 	mov    r8,QWORD PTR [rdi+0x200]
  abc00e:	41 80 b8 c9 01 00 00 	cmp    BYTE PTR [r8+0x1c9],0x2
  abc015:	02 
  abc016:	0f 82 a9 01 00 00    	jb     0xabc1c5
  abc01c:	f6 87 64 04 00 00 02 	test   BYTE PTR [rdi+0x464],0x2
  abc023:	0f 85 9c 01 00 00    	jne    0xabc1c5
  abc029:	f7 c1 00 04 00 00    	test   ecx,0x400
  abc02f:	0f 85 90 01 00 00    	jne    0xabc1c5
  abc035:	81 bf d4 05 00 00 00 	cmp    DWORD PTR [rdi+0x5d4],0x2500000
  abc03c:	00 50 02 
  abc03f:	0f 82 80 01 00 00    	jb     0xabc1c5
  abc045:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
  abc04c:	48 8b b5 70 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x90]
  abc053:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  abc05a:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  abc05e:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
  abc065:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  abc069:	c7 45 a8 ff ff ff ff 	mov    DWORD PTR [rbp-0x58],0xffffffff
  abc070:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
  abc073:	89 4d b8             	mov    DWORD PTR [rbp-0x48],ecx
  abc076:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
  abc07a:	48 8d 75 98          	lea    rsi,[rbp-0x68]
  abc07e:	e8 bd 14 00 00       	call   0xabd540
  abc083:	e9 bb 01 00 00       	jmp    0xabc243
  abc088:	8b 85 64 ff ff ff    	mov    eax,DWORD PTR [rbp-0x9c]
  abc08e:	85 c0                	test   eax,eax
  abc090:	41 0f 48 c7          	cmovs  eax,r15d
  abc094:	89 85 64 ff ff ff    	mov    DWORD PTR [rbp-0x9c],eax
  abc09a:	0f b6 45 80          	movzx  eax,BYTE PTR [rbp-0x80]
  abc09e:	a8 02                	test   al,0x2
  abc0a0:	0f 84 74 fe ff ff    	je     0xabbf1a
  abc0a6:	0c 01                	or     al,0x1
  abc0a8:	88 45 80             	mov    BYTE PTR [rbp-0x80],al
  abc0ab:	e9 6a fe ff ff       	jmp    0xabbf1a
  abc0b0:	48 8b b5 68 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x98]
  abc0b7:	f7 c6 ff 3f 00 00    	test   esi,0x3fff
  abc0bd:	0f 85 f5 01 00 00    	jne    0xabc2b8
  abc0c3:	48 8b 95 78 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x88]
  abc0ca:	f7 c2 ff 3f 00 00    	test   edx,0x3fff
  abc0d0:	0f 85 e2 01 00 00    	jne    0xabc2b8
  abc0d6:	0f b6 7d 80          	movzx  edi,BYTE PTR [rbp-0x80]
  abc0da:	89 f9                	mov    ecx,edi
  abc0dc:	83 e1 08             	and    ecx,0x8
  abc0df:	0f 85 d3 01 00 00    	jne    0xabc2b8
  abc0e5:	48 01 f2             	add    rdx,rsi
  abc0e8:	0f 82 ca 01 00 00    	jb     0xabc2b8
  abc0ee:	48 8b 85 58 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa8]
  abc0f5:	89 f9                	mov    ecx,edi
  abc0f7:	45 31 c0             	xor    r8d,r8d
  abc0fa:	d1 e9                	shr    ecx,1
  abc0fc:	83 e1 c1             	and    ecx,0xffffffc1
  abc0ff:	09 f9                	or     ecx,edi
  abc101:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abc105:	48 8b b8 00 02 00 00 	mov    rdi,QWORD PTR [rax+0x200]
  abc10c:	e8 9f fc 80 ff       	call   0x2cbdb0
  abc111:	85 c0                	test   eax,eax
  abc113:	0f 84 3f fe ff ff    	je     0xabbf58
  abc119:	e9 68 01 00 00       	jmp    0xabc286
  abc11e:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
  abc125:	f7 c1 ff 3f 00 00    	test   ecx,0x3fff
  abc12b:	0f 85 87 01 00 00    	jne    0xabc2b8
  abc131:	48 8b 95 78 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x88]
  abc138:	f7 c2 ff 3f 00 00    	test   edx,0x3fff
  abc13e:	0f 85 74 01 00 00    	jne    0xabc2b8
  abc144:	0f b6 75 80          	movzx  esi,BYTE PTR [rbp-0x80]
  abc148:	89 f7                	mov    edi,esi
  abc14a:	83 e7 08             	and    edi,0x8
  abc14d:	0f 85 65 01 00 00    	jne    0xabc2b8
  abc153:	8b 43 08             	mov    eax,DWORD PTR [rbx+0x8]
  abc156:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
  abc15a:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  abc15e:	89 75 a8             	mov    DWORD PTR [rbp-0x58],esi
  abc161:	0d 00 10 00 00       	or     eax,0x1000
  abc166:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
  abc169:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
  abc170:	00 
  abc171:	c7 45 c0 ff ff ff ff 	mov    DWORD PTR [rbp-0x40],0xffffffff
  abc178:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  abc17f:	00 
  abc180:	e9 ae 00 00 00       	jmp    0xabc233
  abc185:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
  abc18c:	f7 c1 ff 3f 00 00    	test   ecx,0x3fff
  abc192:	0f 85 20 01 00 00    	jne    0xabc2b8
  abc198:	48 8b 95 78 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x88]
  abc19f:	f7 c2 ff 3f 00 00    	test   edx,0x3fff
  abc1a5:	0f 85 0d 01 00 00    	jne    0xabc2b8
  abc1ab:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  abc1b2:	48 8d 75 98          	lea    rsi,[rbp-0x68]
  abc1b6:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
  abc1ba:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  abc1be:	e8 ed c9 ff ff       	call   0xab8bb0
  abc1c3:	eb 7e                	jmp    0xabc243
  abc1c5:	48 8b bd 68 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x98]
  abc1cc:	f7 c7 ff 3f 00 00    	test   edi,0x3fff
  abc1d2:	0f 85 e0 00 00 00    	jne    0xabc2b8
  abc1d8:	4c 8b 85 78 ff ff ff 	mov    r8,QWORD PTR [rbp-0x88]
  abc1df:	41 f7 c0 ff 3f 00 00 	test   r8d,0x3fff
  abc1e6:	0f 85 cc 00 00 00    	jne    0xabc2b8
  abc1ec:	4c 8b 8d 70 ff ff ff 	mov    r9,QWORD PTR [rbp-0x90]
  abc1f3:	49 ba ff 3f 00 00 00 	movabs r10,0x8000000000003fff
  abc1fa:	00 00 80 
  abc1fd:	4d 85 d1             	test   r9,r10
  abc200:	0f 85 b2 00 00 00    	jne    0xabc2b8
  abc206:	41 89 d2             	mov    r10d,edx
  abc209:	41 83 e2 08          	and    r10d,0x8
  abc20d:	0f 85 a5 00 00 00    	jne    0xabc2b8
  abc213:	83 c9 01             	or     ecx,0x1
  abc216:	48 89 7d 98          	mov    QWORD PTR [rbp-0x68],rdi
  abc21a:	4c 89 45 a0          	mov    QWORD PTR [rbp-0x60],r8
  abc21e:	89 55 a8             	mov    DWORD PTR [rbp-0x58],edx
  abc221:	89 4d b0             	mov    DWORD PTR [rbp-0x50],ecx
  abc224:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
  abc22b:	00 
  abc22c:	89 75 c0             	mov    DWORD PTR [rbp-0x40],esi
  abc22f:	4c 89 4d c8          	mov    QWORD PTR [rbp-0x38],r9
  abc233:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  abc23a:	48 8d 75 98          	lea    rsi,[rbp-0x68]
  abc23e:	e8 ed c1 ff ff       	call   0xab8430
  abc243:	85 c0                	test   eax,eax
  abc245:	0f 84 0d fd ff ff    	je     0xabbf58
  abc24b:	eb 6b                	jmp    0xabc2b8
  abc24d:	31 c0                	xor    eax,eax
  abc24f:	45 31 ff             	xor    r15d,r15d
  abc252:	e9 95 00 00 00       	jmp    0xabc2ec
  abc257:	48 83 7d 88 00       	cmp    QWORD PTR [rbp-0x78],0x0
  abc25c:	74 4e                	je     0xabc2ac
  abc25e:	48 8d 7d 88          	lea    rdi,[rbp-0x78]
  abc262:	48 8d 75 98          	lea    rsi,[rbp-0x68]
  abc266:	c7 45 98 00 00 00 00 	mov    DWORD PTR [rbp-0x68],0x0
  abc26d:	e8 3e 01 00 00       	call   0xabc3b0
  abc272:	8b 8d 64 ff ff ff    	mov    ecx,DWORD PTR [rbp-0x9c]
  abc278:	03 4d 98             	add    ecx,DWORD PTR [rbp-0x68]
  abc27b:	85 c0                	test   eax,eax
  abc27d:	41 0f 44 cd          	cmove  ecx,r13d
  abc281:	41 89 cf             	mov    r15d,ecx
  abc284:	eb 66                	jmp    0xabc2ec
  abc286:	83 f8 02             	cmp    eax,0x2
  abc289:	74 28                	je     0xabc2b3
  abc28b:	89 c1                	mov    ecx,eax
  abc28d:	b8 0c 00 00 00       	mov    eax,0xc
  abc292:	83 f9 06             	cmp    ecx,0x6
  abc295:	74 21                	je     0xabc2b8
  abc297:	b8 16 00 00 00       	mov    eax,0x16
  abc29c:	eb 1a                	jmp    0xabc2b8
  abc29e:	8b 8d 64 ff ff ff    	mov    ecx,DWORD PTR [rbp-0x9c]
  abc2a4:	03 4d 98             	add    ecx,DWORD PTR [rbp-0x68]
  abc2a7:	41 89 cf             	mov    r15d,ecx
  abc2aa:	eb 0c                	jmp    0xabc2b8
  abc2ac:	31 c0                	xor    eax,eax
  abc2ae:	45 89 ef             	mov    r15d,r13d
  abc2b1:	eb 39                	jmp    0xabc2ec
  abc2b3:	b8 0d 00 00 00       	mov    eax,0xd
  abc2b8:	48 8b 75 88          	mov    rsi,QWORD PTR [rbp-0x78]
  abc2bc:	48 85 f6             	test   rsi,rsi
  abc2bf:	74 2b                	je     0xabc2ec
  abc2c1:	41 89 c6             	mov    r14d,eax
  abc2c4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  abc2cb:	00 00 00 00 00 
  abc2d0:	48 8b 3d 41 ab 13 03 	mov    rdi,QWORD PTR [rip+0x313ab41]        # 0x3bf6e18
  abc2d7:	4c 8b 26             	mov    r12,QWORD PTR [rsi]
  abc2da:	31 d2                	xor    edx,edx
  abc2dc:	e8 df fd 97 ff       	call   0x43c0c0
  abc2e1:	4c 89 e6             	mov    rsi,r12
  abc2e4:	4d 85 e4             	test   r12,r12
  abc2e7:	75 e7                	jne    0xabc2d0
  abc2e9:	44 89 f0             	mov    eax,r14d
  abc2ec:	48 8b 8d 58 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xa8]
  abc2f3:	c6 81 16 01 00 00 00 	mov    BYTE PTR [rcx+0x116],0x0
  abc2fa:	80 b9 17 01 00 00 00 	cmp    BYTE PTR [rcx+0x117],0x0
  abc301:	74 52                	je     0xabc355
  abc303:	48 8d 0d de 9f fd 00 	lea    rcx,[rip+0xfd9fde]        # 0x1a962e8
  abc30a:	41 89 c6             	mov    r14d,eax
  abc30d:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  abc310:	4c 8b 60 40          	mov    r12,QWORD PTR [rax+0x40]
  abc314:	48 8d 05 cd 49 7a ff 	lea    rax,[rip+0xffffffffff7a49cd]        # 0x260ce8
  abc31b:	4c 29 e0             	sub    rax,r12
  abc31e:	48 c1 c8 03          	ror    rax,0x3
  abc322:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  abc328:	77 69                	ja     0xabc393
  abc32a:	4c 8b ad 58 ff ff ff 	mov    r13,QWORD PTR [rbp-0xa8]
  abc331:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  abc335:	48 8b b8 00 02 00 00 	mov    rdi,QWORD PTR [rax+0x200]
  abc33c:	41 ff d4             	call   r12
  abc33f:	41 80 bd f0 05 00 00 	cmp    BYTE PTR [r13+0x5f0],0x0
  abc346:	00 
  abc347:	44 89 f0             	mov    eax,r14d
  abc34a:	74 09                	je     0xabc355
  abc34c:	f0 48 83 2d 6b 53 2a 	lock sub QWORD PTR [rip+0x22a536b],0x1        # 0x2d616c0
  abc353:	02 01 
  abc355:	48 8b 7b 20          	mov    rdi,QWORD PTR [rbx+0x20]
  abc359:	48 85 ff             	test   rdi,rdi
  abc35c:	74 0c                	je     0xabc36a
  abc35e:	44 89 fe             	mov    esi,r15d
  abc361:	89 c3                	mov    ebx,eax
  abc363:	e8 28 d4 79 ff       	call   0x259790
  abc368:	89 d8                	mov    eax,ebx
  abc36a:	4c 8d 35 9f ff e5 02 	lea    r14,[rip+0x2e5ff9f]        # 0x391c310
  abc371:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  abc374:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  abc378:	75 12                	jne    0xabc38c
  abc37a:	48 81 c4 88 00 00 00 	add    rsp,0x88
  abc381:	5b                   	pop    rbx
  abc382:	41 5c                	pop    r12
  abc384:	41 5d                	pop    r13
  abc386:	41 5e                	pop    r14
  abc388:	41 5f                	pop    r15
  abc38a:	5d                   	pop    rbp
  abc38b:	c3                   	ret
  abc38c:	e8 1f 13 c4 ff       	call   0x6fd6b0
  abc391:	0f 0b                	ud2
  abc393:	48 8d 3d 56 c9 dc 01 	lea    rdi,[rip+0x1dcc956]        # 0x2888cf0
  abc39a:	4c 89 e6             	mov    rsi,r12
  abc39d:	e8 1e 35 99 ff       	call   0x44f8c0
  abc3a2:	eb 86                	jmp    0xabc32a
  abc3a4:	90                   	nop
  abc3a5:	90                   	nop
  abc3a6:	90                   	nop
  abc3a7:	90                   	nop
  abc3a8:	90                   	nop
  abc3a9:	90                   	nop
  abc3aa:	90                   	nop
  abc3ab:	90                   	nop
  abc3ac:	90                   	nop
  abc3ad:	90                   	nop
  abc3ae:	90                   	nop
  abc3af:	90                   	nop
  abc3b0:	55                   	push   rbp
  abc3b1:	48 89 e5             	mov    rbp,rsp
  abc3b4:	41 57                	push   r15
  abc3b6:	41 56                	push   r14
  abc3b8:	41 55                	push   r13
  abc3ba:	41 54                	push   r12
  abc3bc:	53                   	push   rbx
  abc3bd:	48 83 ec 18          	sub    rsp,0x18
  abc3c1:	48 8d 1d 48 ff e5 02 	lea    rbx,[rip+0x2e5ff48]        # 0x391c310
  abc3c8:	49 89 fe             	mov    r14,rdi
  abc3cb:	49 89 f4             	mov    r12,rsi
  abc3ce:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  abc3d1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abc3d5:	65 4c 8b 2c 25 00 00 	mov    r13,QWORD PTR gs:0x0
  abc3dc:	00 00 
  abc3de:	49 8b bd 40 01 00 00 	mov    rdi,QWORD PTR [r13+0x140]
  abc3e5:	e8 76 d1 b4 ff       	call   0x609560
  abc3ea:	41 bf 01 00 00 00    	mov    r15d,0x1
  abc3f0:	85 c0                	test   eax,eax
  abc3f2:	0f 85 ec 00 00 00    	jne    0xabc4e4
  abc3f8:	49 8b bd 40 01 00 00 	mov    rdi,QWORD PTR [r13+0x140]
  abc3ff:	e8 9c d1 b4 ff       	call   0x6095a0
  abc404:	85 c0                	test   eax,eax
  abc406:	0f 85 d8 00 00 00    	jne    0xabc4e4
  abc40c:	c7 45 cc 00 00 00 00 	mov    DWORD PTR [rbp-0x34],0x0
  abc413:	4c 89 65 c0          	mov    QWORD PTR [rbp-0x40],r12
  abc417:	49 8b 1e             	mov    rbx,QWORD PTR [r14]
  abc41a:	48 85 db             	test   rbx,rbx
  abc41d:	74 54                	je     0xabc473
  abc41f:	41 bc 01 00 00 00    	mov    r12d,0x1
  abc425:	41 bf 16 00 00 00    	mov    r15d,0x16
  abc42b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  abc430:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  abc434:	48 03 43 08          	add    rax,QWORD PTR [rbx+0x8]
  abc438:	72 68                	jb     0xabc4a2
  abc43a:	48 8d 88 ff 3f 00 00 	lea    rcx,[rax+0x3fff]
  abc441:	48 81 e1 00 c0 ff ff 	and    rcx,0xffffffffffffc000
  abc448:	48 39 c1             	cmp    rcx,rax
  abc44b:	72 55                	jb     0xabc4a2
  abc44d:	0f be 7b 21          	movsx  edi,BYTE PTR [rbx+0x21]
  abc451:	49 8b 75 08          	mov    rsi,QWORD PTR [r13+0x8]
  abc455:	e8 86 6f 90 ff       	call   0x3c33e0
  abc45a:	85 c0                	test   eax,eax
  abc45c:	74 44                	je     0xabc4a2
  abc45e:	f6 43 20 08          	test   BYTE PTR [rbx+0x20],0x8
  abc462:	75 3e                	jne    0xabc4a2
  abc464:	44 89 65 cc          	mov    DWORD PTR [rbp-0x34],r12d
  abc468:	41 ff c4             	inc    r12d
  abc46b:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  abc46e:	48 85 db             	test   rbx,rbx
  abc471:	75 bd                	jne    0xabc430
  abc473:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  abc477:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
  abc47b:	4c 89 f6             	mov    rsi,r14
  abc47e:	48 8b b8 00 02 00 00 	mov    rdi,QWORD PTR [rax+0x200]
  abc485:	e8 86 17 81 ff       	call   0x2cdc10
  abc48a:	41 bf 16 00 00 00    	mov    r15d,0x16
  abc490:	83 f8 09             	cmp    eax,0x9
  abc493:	77 0d                	ja     0xabc4a2
  abc495:	89 c0                	mov    eax,eax
  abc497:	48 8d 0d 16 fb e1 00 	lea    rcx,[rip+0xe1fb16]        # 0x18dbfb4
  abc49e:	44 8b 3c 81          	mov    r15d,DWORD PTR [rcx+rax*4]
  abc4a2:	49 8b 36             	mov    rsi,QWORD PTR [r14]
  abc4a5:	48 85 f6             	test   rsi,rsi
  abc4a8:	74 1f                	je     0xabc4c9
  abc4aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  abc4b0:	48 8b 3d 61 a9 13 03 	mov    rdi,QWORD PTR [rip+0x313a961]        # 0x3bf6e18
  abc4b7:	48 8b 1e             	mov    rbx,QWORD PTR [rsi]
  abc4ba:	31 d2                	xor    edx,edx
  abc4bc:	e8 ff fb 97 ff       	call   0x43c0c0
  abc4c1:	48 89 de             	mov    rsi,rbx
  abc4c4:	48 85 db             	test   rbx,rbx
  abc4c7:	75 e7                	jne    0xabc4b0
  abc4c9:	49 c7 06 00 00 00 00 	mov    QWORD PTR [r14],0x0
  abc4d0:	4d 89 76 08          	mov    QWORD PTR [r14+0x8],r14
  abc4d4:	48 8d 1d 35 fe e5 02 	lea    rbx,[rip+0x2e5fe35]        # 0x391c310
  abc4db:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  abc4df:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
  abc4e2:	89 01                	mov    DWORD PTR [rcx],eax
  abc4e4:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  abc4e7:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  abc4eb:	75 12                	jne    0xabc4ff
  abc4ed:	44 89 f8             	mov    eax,r15d
  abc4f0:	48 83 c4 18          	add    rsp,0x18
  abc4f4:	5b                   	pop    rbx
  abc4f5:	41 5c                	pop    r12
  abc4f7:	41 5d                	pop    r13
  abc4f9:	41 5e                	pop    r14
  abc4fb:	41 5f                	pop    r15
  abc4fd:	5d                   	pop    rbp
  abc4fe:	c3                   	ret
  abc4ff:	e8 ac 11 c4 ff       	call   0x6fd6b0
  abc504:	0f 0b                	ud2
  abc506:	90                   	nop
  abc507:	90                   	nop
  abc508:	90                   	nop
  abc509:	90                   	nop
  abc50a:	90                   	nop
  abc50b:	90                   	nop
  abc50c:	90                   	nop
  abc50d:	90                   	nop
  abc50e:	90                   	nop
  abc50f:	90                   	nop
  abc510:	55                   	push   rbp
  abc511:	48 89 e5             	mov    rbp,rsp
  abc514:	41 57                	push   r15
  abc516:	41 56                	push   r14
  abc518:	41 54                	push   r12
  abc51a:	53                   	push   rbx
  abc51b:	65 48 8b 1c 25 00 00 	mov    rbx,QWORD PTR gs:0x0
  abc522:	00 00 
  abc524:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
  abc528:	b9 16 00 00 00       	mov    ecx,0x16
  abc52d:	44 8b b0 c0 05 00 00 	mov    r14d,DWORD PTR [rax+0x5c0]
  abc534:	b8 16 00 00 00       	mov    eax,0x16
  abc539:	41 8d 56 fe          	lea    edx,[r14-0x2]
  abc53d:	83 fa fd             	cmp    edx,0xfffffffd
  abc540:	72 3f                	jb     0xabc581
  abc542:	41 83 fe ff          	cmp    r14d,0xffffffff
  abc546:	74 34                	je     0xabc57c
  abc548:	49 89 ff             	mov    r15,rdi
  abc54b:	49 89 f4             	mov    r12,rsi
  abc54e:	48 89 df             	mov    rdi,rbx
  abc551:	be ad 02 00 00       	mov    esi,0x2ad
  abc556:	e8 d5 34 02 00       	call   0xadfa30
  abc55b:	89 c1                	mov    ecx,eax
  abc55d:	4c 89 e6             	mov    rsi,r12
  abc560:	4c 89 ff             	mov    rdi,r15
  abc563:	b8 16 00 00 00       	mov    eax,0x16
  abc568:	85 c9                	test   ecx,ecx
  abc56a:	75 15                	jne    0xabc581
  abc56c:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
  abc570:	44 89 b1 c0 05 00 00 	mov    DWORD PTR [rcx+0x5c0],r14d
  abc577:	44 89 f1             	mov    ecx,r14d
  abc57a:	eb 05                	jmp    0xabc581
  abc57c:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  abc581:	48 63 c9             	movsxd rcx,ecx
  abc584:	48 89 8f 08 04 00 00 	mov    QWORD PTR [rdi+0x408],rcx
  abc58b:	44 8b 36             	mov    r14d,DWORD PTR [rsi]
  abc58e:	41 8d 4e fe          	lea    ecx,[r14-0x2]
  abc592:	83 f9 fd             	cmp    ecx,0xfffffffd
  abc595:	72 41                	jb     0xabc5d8
  abc597:	31 c0                	xor    eax,eax
  abc599:	41 83 fe ff          	cmp    r14d,0xffffffff
  abc59d:	74 39                	je     0xabc5d8
  abc59f:	be ad 02 00 00       	mov    esi,0x2ad
  abc5a4:	e8 87 34 02 00       	call   0xadfa30
  abc5a9:	85 c0                	test   eax,eax
  abc5ab:	75 2b                	jne    0xabc5d8
  abc5ad:	4c 89 f0             	mov    rax,r14
  abc5b0:	48 8d 0d e9 98 a7 02 	lea    rcx,[rip+0x2a798e9]        # 0x3535ea0
  abc5b7:	48 c1 e0 07          	shl    rax,0x7
  abc5bb:	4a 8d 04 f0          	lea    rax,[rax+r14*8]
  abc5bf:	83 7c 01 70 00       	cmp    DWORD PTR [rcx+rax*1+0x70],0x0
  abc5c4:	b8 16 00 00 00       	mov    eax,0x16
  abc5c9:	74 0d                	je     0xabc5d8
  abc5cb:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
  abc5cf:	44 89 b0 c0 05 00 00 	mov    DWORD PTR [rax+0x5c0],r14d
  abc5d6:	31 c0                	xor    eax,eax
  abc5d8:	5b                   	pop    rbx
  abc5d9:	41 5c                	pop    r12
  abc5db:	41 5e                	pop    r14
  abc5dd:	41 5f                	pop    r15
  abc5df:	5d                   	pop    rbp
  abc5e0:	c3                   	ret
  abc5e1:	90                   	nop
  abc5e2:	90                   	nop
  abc5e3:	90                   	nop
  abc5e4:	90                   	nop
  abc5e5:	90                   	nop
  abc5e6:	90                   	nop
  abc5e7:	90                   	nop
  abc5e8:	90                   	nop
  abc5e9:	90                   	nop
  abc5ea:	90                   	nop
  abc5eb:	90                   	nop
  abc5ec:	90                   	nop
  abc5ed:	90                   	nop
  abc5ee:	90                   	nop
  abc5ef:	90                   	nop
  abc5f0:	55                   	push   rbp
  abc5f1:	48 89 e5             	mov    rbp,rsp
  abc5f4:	41 57                	push   r15
  abc5f6:	41 56                	push   r14
  abc5f8:	41 55                	push   r13
  abc5fa:	41 54                	push   r12
  abc5fc:	53                   	push   rbx
  abc5fd:	48 83 ec 38          	sub    rsp,0x38
  abc601:	4c 8d 25 08 fd e5 02 	lea    r12,[rip+0x2e5fd08]        # 0x391c310
  abc608:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  abc60c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abc610:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  abc614:	4c 8b 2e             	mov    r13,QWORD PTR [rsi]
  abc617:	48 8b 98 00 02 00 00 	mov    rbx,QWORD PTR [rax+0x200]
  abc61e:	b8 16 00 00 00       	mov    eax,0x16
  abc623:	4c 39 6b 20          	cmp    QWORD PTR [rbx+0x20],r13
  abc627:	0f 87 c1 00 00 00    	ja     0xabc6ee
  abc62d:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  abc631:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
  abc635:	4c 29 e9             	sub    rcx,r13
  abc638:	0f 96 c2             	setbe  dl
  abc63b:	4c 39 f9             	cmp    rcx,r15
  abc63e:	0f 92 c1             	setb   cl
  abc641:	08 d1                	or     cl,dl
  abc643:	0f 85 a5 00 00 00    	jne    0xabc6ee
  abc649:	48 89 7d a8          	mov    QWORD PTR [rbp-0x58],rdi
  abc64d:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
  abc651:	48 8d 35 2c da 89 00 	lea    rsi,[rip+0x89da2c]        # 0x135a084
  abc658:	31 d2                	xor    edx,edx
  abc65a:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abc661:	00 00 
  abc663:	e8 78 dd 15 00       	call   0xc1a3e0
  abc668:	48 8d 75 b0          	lea    rsi,[rbp-0x50]
  abc66c:	ba 20 00 00 00       	mov    edx,0x20
  abc671:	4c 89 f7             	mov    rdi,r14
  abc674:	31 c9                	xor    ecx,ecx
  abc676:	e8 85 d2 79 ff       	call   0x259900
  abc67b:	85 c0                	test   eax,eax
  abc67d:	75 6f                	jne    0xabc6ee
  abc67f:	44 89 e8             	mov    eax,r13d
  abc682:	4d 89 ee             	mov    r14,r13
  abc685:	49 c1 ed 28          	shr    r13,0x28
  abc689:	25 ff 3f 00 00       	and    eax,0x3fff
  abc68e:	49 81 e6 00 c0 ff ff 	and    r14,0xffffffffffffc000
  abc695:	49 8d 94 07 ff 3f 00 	lea    rdx,[r15+rax*1+0x3fff]
  abc69c:	00 
  abc69d:	48 81 e2 00 c0 ff ff 	and    rdx,0xffffffffffffc000
  abc6a4:	4e 8d 3c 32          	lea    r15,[rdx+r14*1]
  abc6a8:	41 83 fd 0e          	cmp    r13d,0xe
  abc6ac:	77 2c                	ja     0xabc6da
  abc6ae:	48 b8 01 00 00 00 00 	movabs rax,0x80000000001
  abc6b5:	08 00 00 
  abc6b8:	49 39 c7             	cmp    r15,rax
  abc6bb:	72 1d                	jb     0xabc6da
  abc6bd:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
  abc6c1:	48 8d 4d b0          	lea    rcx,[rbp-0x50]
  abc6c5:	4c 89 f6             	mov    rsi,r14
  abc6c8:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  abc6cc:	e8 9f 30 d6 ff       	call   0x81f770
  abc6d1:	83 f8 0d             	cmp    eax,0xd
  abc6d4:	74 04                	je     0xabc6da
  abc6d6:	85 c0                	test   eax,eax
  abc6d8:	75 14                	jne    0xabc6ee
  abc6da:	48 8d 4d b0          	lea    rcx,[rbp-0x50]
  abc6de:	48 89 df             	mov    rdi,rbx
  abc6e1:	4c 89 f6             	mov    rsi,r14
  abc6e4:	4c 89 fa             	mov    rdx,r15
  abc6e7:	e8 64 67 81 ff       	call   0x2d2e50
  abc6ec:	31 c0                	xor    eax,eax
  abc6ee:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  abc6f2:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  abc6f6:	75 0f                	jne    0xabc707
  abc6f8:	48 83 c4 38          	add    rsp,0x38
  abc6fc:	5b                   	pop    rbx
  abc6fd:	41 5c                	pop    r12
  abc6ff:	41 5d                	pop    r13
  abc701:	41 5e                	pop    r14
  abc703:	41 5f                	pop    r15
  abc705:	5d                   	pop    rbp
  abc706:	c3                   	ret
  abc707:	e8 a4 0f c4 ff       	call   0x6fd6b0
  abc70c:	0f 0b                	ud2
  abc70e:	90                   	nop
  abc70f:	90                   	nop
  abc710:	55                   	push   rbp
  abc711:	48 89 e5             	mov    rbp,rsp
  abc714:	41 57                	push   r15
  abc716:	41 56                	push   r14
  abc718:	41 55                	push   r13
  abc71a:	41 54                	push   r12
  abc71c:	53                   	push   rbx
  abc71d:	48 81 ec b8 01 00 00 	sub    rsp,0x1b8
  abc724:	48 8d 05 e5 fb e5 02 	lea    rax,[rip+0x2e5fbe5]        # 0x391c310
  abc72b:	49 89 ff             	mov    r15,rdi
  abc72e:	ba 02 00 00 00       	mov    edx,0x2
  abc733:	48 89 f3             	mov    rbx,rsi
  abc736:	48 8b 00             	mov    rax,QWORD PTR [rax]
  abc739:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abc73d:	48 8b 3d 9c 4e c1 02 	mov    rdi,QWORD PTR [rip+0x2c14e9c]        # 0x36d15e0
  abc744:	4c 8b 26             	mov    r12,QWORD PTR [rsi]
  abc747:	31 f6                	xor    esi,esi
  abc749:	e8 32 f1 97 ff       	call   0x43b880
  abc74e:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abc755:	00 00 
  abc757:	48 8d 35 26 d9 89 00 	lea    rsi,[rip+0x89d926]        # 0x135a084
  abc75e:	31 d2                	xor    edx,edx
  abc760:	49 89 c6             	mov    r14,rax
  abc763:	e8 78 dc 15 00       	call   0xc1a3e0
  abc768:	ba 00 04 00 00       	mov    edx,0x400
  abc76d:	4c 89 e7             	mov    rdi,r12
  abc770:	4c 89 f6             	mov    rsi,r14
  abc773:	31 c9                	xor    ecx,ecx
  abc775:	e8 86 d1 79 ff       	call   0x259900
  abc77a:	85 c0                	test   eax,eax
  abc77c:	74 08                	je     0xabc786
  abc77e:	41 89 c5             	mov    r13d,eax
  abc781:	e9 d2 00 00 00       	jmp    0xabc858
  abc786:	48 89 9d 28 fe ff ff 	mov    QWORD PTR [rbp-0x1d8],rbx
  abc78d:	48 83 ec 08          	sub    rsp,0x8
  abc791:	4c 89 fb             	mov    rbx,r15
  abc794:	4c 8d bd e8 fe ff ff 	lea    r15,[rbp-0x118]
  abc79b:	ba 44 01 00 00       	mov    edx,0x144
  abc7a0:	31 f6                	xor    esi,esi
  abc7a2:	b9 01 00 00 00       	mov    ecx,0x1
  abc7a7:	4d 89 f0             	mov    r8,r14
  abc7aa:	41 b9 9c ff ff ff    	mov    r9d,0xffffff9c
  abc7b0:	4c 89 ff             	mov    rdi,r15
  abc7b3:	53                   	push   rbx
  abc7b4:	6a 00                	push   0x0
  abc7b6:	6a 00                	push   0x0
  abc7b8:	e8 23 df b3 ff       	call   0x5fa6e0
  abc7bd:	48 83 c4 20          	add    rsp,0x20
  abc7c1:	4c 89 ff             	mov    rdi,r15
  abc7c4:	e8 57 c4 b3 ff       	call   0x5f8c20
  abc7c9:	4c 8b a5 48 ff ff ff 	mov    r12,QWORD PTR [rbp-0xb8]
  abc7d0:	4c 89 ff             	mov    rdi,r15
  abc7d3:	be 0c 00 00 00       	mov    esi,0xc
  abc7d8:	41 89 c5             	mov    r13d,eax
  abc7db:	e8 a0 df b3 ff       	call   0x5fa780
  abc7e0:	45 85 ed             	test   r13d,r13d
  abc7e3:	75 73                	jne    0xabc858
  abc7e5:	41 83 bc 24 d4 01 00 	cmp    DWORD PTR [r12+0x1d4],0x1
  abc7ec:	00 01 
  abc7ee:	41 bd 16 00 00 00    	mov    r13d,0x16
  abc7f4:	75 5a                	jne    0xabc850
  abc7f6:	48 8b 83 40 01 00 00 	mov    rax,QWORD PTR [rbx+0x140]
  abc7fd:	48 8d 0d f4 df 01 01 	lea    rcx,[rip+0x101dff4]        # 0x1ada7f8
  abc804:	48 8d b5 60 fe ff ff 	lea    rsi,[rbp-0x1a0]
  abc80b:	49 89 df             	mov    r15,rbx
  abc80e:	48 89 8d 60 fe ff ff 	mov    QWORD PTR [rbp-0x1a0],rcx
  abc815:	4c 89 a5 68 fe ff ff 	mov    QWORD PTR [rbp-0x198],r12
  abc81c:	c7 85 70 fe ff ff 01 	mov    DWORD PTR [rbp-0x190],0x1
  abc823:	00 00 00 
  abc826:	48 89 85 78 fe ff ff 	mov    QWORD PTR [rbp-0x188],rax
  abc82d:	48 89 9d 80 fe ff ff 	mov    QWORD PTR [rbp-0x180],rbx
  abc834:	48 c7 85 88 fe ff ff 	mov    QWORD PTR [rbp-0x178],0x0
  abc83b:	00 00 00 00 
  abc83f:	49 8b 7c 24 08       	mov    rdi,QWORD PTR [r12+0x8]
  abc844:	e8 b7 f2 ac ff       	call   0x58bb00
  abc849:	41 89 c5             	mov    r13d,eax
  abc84c:	85 c0                	test   eax,eax
  abc84e:	74 42                	je     0xabc892
  abc850:	4c 89 e7             	mov    rdi,r12
  abc853:	e8 e8 db a8 ff       	call   0x54a440
  abc858:	48 8b 3d 81 4d c1 02 	mov    rdi,QWORD PTR [rip+0x2c14d81]        # 0x36d15e0
  abc85f:	4c 89 f6             	mov    rsi,r14
  abc862:	31 d2                	xor    edx,edx
  abc864:	e8 57 f8 97 ff       	call   0x43c0c0
  abc869:	48 8d 05 a0 fa e5 02 	lea    rax,[rip+0x2e5faa0]        # 0x391c310
  abc870:	48 8b 00             	mov    rax,QWORD PTR [rax]
  abc873:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  abc877:	0f 85 81 01 00 00    	jne    0xabc9fe
  abc87d:	44 89 e8             	mov    eax,r13d
  abc880:	48 81 c4 b8 01 00 00 	add    rsp,0x1b8
  abc887:	5b                   	pop    rbx
  abc888:	41 5c                	pop    r12
  abc88a:	41 5d                	pop    r13
  abc88c:	41 5e                	pop    r14
  abc88e:	41 5f                	pop    r15
  abc890:	5d                   	pop    rbp
  abc891:	c3                   	ret
  abc892:	4d 8b 8f 40 01 00 00 	mov    r9,QWORD PTR [r15+0x140]
  abc899:	bf 07 00 00 00       	mov    edi,0x7
  abc89e:	4c 89 e6             	mov    rsi,r12
  abc8a1:	b9 01 00 00 00       	mov    ecx,0x1
  abc8a6:	31 d2                	xor    edx,edx
  abc8a8:	45 31 c0             	xor    r8d,r8d
  abc8ab:	e8 10 11 9a ff       	call   0x45d9c0
  abc8b0:	48 89 85 30 fe ff ff 	mov    QWORD PTR [rbp-0x1d0],rax
  abc8b7:	48 85 c0             	test   rax,rax
  abc8ba:	74 3b                	je     0xabc8f7
  abc8bc:	48 8d 78 18          	lea    rdi,[rax+0x18]
  abc8c0:	31 f6                	xor    esi,esi
  abc8c2:	31 d2                	xor    edx,edx
  abc8c4:	48 89 c3             	mov    rbx,rax
  abc8c7:	e8 d4 7d d1 ff       	call   0x7d46a0
  abc8cc:	48 89 df             	mov    rdi,rbx
  abc8cf:	e8 7c 4f b7 ff       	call   0x631850
  abc8d4:	85 c0                	test   eax,eax
  abc8d6:	74 27                	je     0xabc8ff
  abc8d8:	89 c2                	mov    edx,eax
  abc8da:	48 8d 3d ea 0a 87 00 	lea    rdi,[rip+0x870aea]        # 0x132d3cb
  abc8e1:	48 8d 35 6f bc 85 00 	lea    rsi,[rip+0x85bc6f]        # 0x1318557
  abc8e8:	31 c0                	xor    eax,eax
  abc8ea:	e8 21 0b 7a ff       	call   0x25d410
  abc8ef:	41 bd 08 00 00 00    	mov    r13d,0x8
  abc8f5:	eb 2c                	jmp    0xabc923
  abc8f7:	41 bd 0c 00 00 00    	mov    r13d,0xc
  abc8fd:	eb 24                	jmp    0xabc923
  abc8ff:	49 8b 97 40 01 00 00 	mov    rdx,QWORD PTR [r15+0x140]
  abc906:	48 8d 8d 60 fe ff ff 	lea    rcx,[rbp-0x1a0]
  abc90d:	48 89 df             	mov    rdi,rbx
  abc910:	4c 89 f6             	mov    rsi,r14
  abc913:	e8 18 5a b7 ff       	call   0x632330
  abc918:	48 89 df             	mov    rdi,rbx
  abc91b:	41 89 c5             	mov    r13d,eax
  abc91e:	e8 cd 58 b7 ff       	call   0x6321f0
  abc923:	49 8b 87 40 01 00 00 	mov    rax,QWORD PTR [r15+0x140]
  abc92a:	48 8d 0d c7 df 01 01 	lea    rcx,[rip+0x101dfc7]        # 0x1ada8f8
  abc931:	48 8d b5 38 fe ff ff 	lea    rsi,[rbp-0x1c8]
  abc938:	48 89 8d 38 fe ff ff 	mov    QWORD PTR [rbp-0x1c8],rcx
  abc93f:	4c 89 a5 40 fe ff ff 	mov    QWORD PTR [rbp-0x1c0],r12
  abc946:	c7 85 48 fe ff ff 01 	mov    DWORD PTR [rbp-0x1b8],0x1
  abc94d:	00 00 00 
  abc950:	48 89 85 50 fe ff ff 	mov    QWORD PTR [rbp-0x1b0],rax
  abc957:	4c 89 bd 58 fe ff ff 	mov    QWORD PTR [rbp-0x1a8],r15
  abc95e:	49 8b 7c 24 08       	mov    rdi,QWORD PTR [r12+0x8]
  abc963:	e8 78 f3 ac ff       	call   0x58bce0
  abc968:	4c 89 e7             	mov    rdi,r12
  abc96b:	e8 d0 da a8 ff       	call   0x54a440
  abc970:	48 8b bd 30 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1d0]
  abc977:	48 85 ff             	test   rdi,rdi
  abc97a:	74 05                	je     0xabc981
  abc97c:	e8 1f 52 9a ff       	call   0x461ba0
  abc981:	48 8b 3d 58 4c c1 02 	mov    rdi,QWORD PTR [rip+0x2c14c58]        # 0x36d15e0
  abc988:	4c 89 f6             	mov    rsi,r14
  abc98b:	31 d2                	xor    edx,edx
  abc98d:	e8 2e f7 97 ff       	call   0x43c0c0
  abc992:	45 85 ed             	test   r13d,r13d
  abc995:	0f 85 ce fe ff ff    	jne    0xabc869
  abc99b:	49 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [r15+0x140]
  abc9a2:	48 8d b5 60 fe ff ff 	lea    rsi,[rbp-0x1a0]
  abc9a9:	48 83 c7 58          	add    rdi,0x58
  abc9ad:	e8 4e d2 b4 ff       	call   0x609c00
  abc9b2:	41 bd 01 00 00 00    	mov    r13d,0x1
  abc9b8:	85 c0                	test   eax,eax
  abc9ba:	0f 85 a9 fe ff ff    	jne    0xabc869
  abc9c0:	48 8b 85 28 fe ff ff 	mov    rax,QWORD PTR [rbp-0x1d8]
  abc9c7:	48 8d 35 c9 28 89 00 	lea    rsi,[rip+0x8928c9]        # 0x134f297
  abc9ce:	31 d2                	xor    edx,edx
  abc9d0:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
  abc9d4:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abc9db:	00 00 
  abc9dd:	e8 fe d9 15 00       	call   0xc1a3e0
  abc9e2:	48 8d bd 60 fe ff ff 	lea    rdi,[rbp-0x1a0]
  abc9e9:	ba 88 00 00 00       	mov    edx,0x88
  abc9ee:	48 89 de             	mov    rsi,rbx
  abc9f1:	e8 da c7 79 ff       	call   0x2591d0
  abc9f6:	41 89 c5             	mov    r13d,eax
  abc9f9:	e9 6b fe ff ff       	jmp    0xabc869
  abc9fe:	e8 ad 0c c4 ff       	call   0x6fd6b0
  abca03:	0f 0b                	ud2
  abca05:	90                   	nop
  abca06:	90                   	nop
  abca07:	90                   	nop
  abca08:	90                   	nop
  abca09:	90                   	nop
  abca0a:	90                   	nop
  abca0b:	90                   	nop
  abca0c:	90                   	nop
  abca0d:	90                   	nop
  abca0e:	90                   	nop
  abca0f:	90                   	nop
  abca10:	55                   	push   rbp
  abca11:	48 89 e5             	mov    rbp,rsp
  abca14:	41 57                	push   r15
  abca16:	41 56                	push   r14
  abca18:	41 55                	push   r13
  abca1a:	41 54                	push   r12
  abca1c:	53                   	push   rbx
  abca1d:	48 83 ec 18          	sub    rsp,0x18
  abca21:	4c 8d 2d e8 f8 e5 02 	lea    r13,[rip+0x2e5f8e8]        # 0x391c310
  abca28:	48 89 f3             	mov    rbx,rsi
  abca2b:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  abca2f:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abca33:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abca3a:	e8 51 c5 b4 ff       	call   0x608f90
  abca3f:	85 c0                	test   eax,eax
  abca41:	0f 84 6c 01 00 00    	je     0xabcbb3
  abca47:	8b 3b                	mov    edi,DWORD PTR [rbx]
  abca49:	e8 22 f7 a7 ff       	call   0x53c170
  abca4e:	49 89 c6             	mov    r14,rax
  abca51:	b8 03 00 00 00       	mov    eax,0x3
  abca56:	4d 85 f6             	test   r14,r14
  abca59:	0f 84 75 01 00 00    	je     0xabcbd4
  abca5f:	41 8b 86 b0 00 00 00 	mov    eax,DWORD PTR [r14+0xb0]
  abca66:	a9 00 20 00 00       	test   eax,0x2000
  abca6b:	0f 85 49 01 00 00    	jne    0xabcbba
  abca71:	41 ff 86 58 03 00 00 	inc    DWORD PTR [r14+0x358]
  abca78:	a9 00 00 00 10       	test   eax,0x10000000
  abca7d:	75 08                	jne    0xabca87
  abca7f:	4c 89 f7             	mov    rdi,r14
  abca82:	e8 89 df a7 ff       	call   0x53aa10
  abca87:	4d 8d be 48 01 00 00 	lea    r15,[r14+0x148]
  abca8e:	31 f6                	xor    esi,esi
  abca90:	31 d2                	xor    edx,edx
  abca92:	31 c9                	xor    ecx,ecx
  abca94:	4c 89 ff             	mov    rdi,r15
  abca97:	e8 04 a5 a0 ff       	call   0x4c6fa0
  abca9c:	4d 8b a6 00 02 00 00 	mov    r12,QWORD PTR [r14+0x200]
  abcaa3:	31 f6                	xor    esi,esi
  abcaa5:	31 d2                	xor    edx,edx
  abcaa7:	4c 89 e7             	mov    rdi,r12
  abcaaa:	e8 71 9d 80 ff       	call   0x2c6820
  abcaaf:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  abcab6:	00 
  abcab7:	49 8b be 00 02 00 00 	mov    rdi,QWORD PTR [r14+0x200]
  abcabe:	e8 cd a3 80 ff       	call   0x2c6e90
  abcac3:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  abcac7:	49 8b 44 24 08       	mov    rax,QWORD PTR [r12+0x8]
  abcacc:	4c 39 e0             	cmp    rax,r12
  abcacf:	74 2b                	je     0xabcafc
  abcad1:	31 c9                	xor    ecx,ecx
  abcad3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  abcada:	84 00 00 00 00 00 
  abcae0:	48 8b 50 28          	mov    rdx,QWORD PTR [rax+0x28]
  abcae4:	48 2b 50 20          	sub    rdx,QWORD PTR [rax+0x20]
  abcae8:	48 c1 ea 0e          	shr    rdx,0xe
  abcaec:	48 01 d1             	add    rcx,rdx
  abcaef:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
  abcaf3:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abcaf7:	4c 39 e0             	cmp    rax,r12
  abcafa:	75 e4                	jne    0xabcae0
  abcafc:	4c 89 e7             	mov    rdi,r12
  abcaff:	31 f6                	xor    esi,esi
  abcb01:	31 d2                	xor    edx,edx
  abcb03:	e8 68 9d 80 ff       	call   0x2c6870
  abcb08:	4c 89 ff             	mov    rdi,r15
  abcb0b:	31 f6                	xor    esi,esi
  abcb0d:	31 d2                	xor    edx,edx
  abcb0f:	31 c9                	xor    ecx,ecx
  abcb11:	e8 ea 9e a0 ff       	call   0x4c6a00
  abcb16:	41 0f b6 8e b1 00 00 	movzx  ecx,BYTE PTR [r14+0xb1]
  abcb1d:	00 
  abcb1e:	41 8b 86 58 03 00 00 	mov    eax,DWORD PTR [r14+0x358]
  abcb25:	c0 e9 05             	shr    cl,0x5
  abcb28:	ff c8                	dec    eax
  abcb2a:	0f 94 c2             	sete   dl
  abcb2d:	41 89 86 58 03 00 00 	mov    DWORD PTR [r14+0x358],eax
  abcb34:	84 d1                	test   cl,dl
  abcb36:	74 0f                	je     0xabcb47
  abcb38:	49 81 c6 58 03 00 00 	add    r14,0x358
  abcb3f:	4c 89 f7             	mov    rdi,r14
  abcb42:	e8 c9 9d 14 00       	call   0xc06910
  abcb47:	4c 89 ff             	mov    rdi,r15
  abcb4a:	31 f6                	xor    esi,esi
  abcb4c:	31 d2                	xor    edx,edx
  abcb4e:	31 c9                	xor    ecx,ecx
  abcb50:	e8 4b a4 a0 ff       	call   0x4c6fa0
  abcb55:	4c 8b 73 08          	mov    r14,QWORD PTR [rbx+0x8]
  abcb59:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abcb60:	00 00 
  abcb62:	48 8d 35 2e 27 89 00 	lea    rsi,[rip+0x89272e]        # 0x134f297
  abcb69:	31 d2                	xor    edx,edx
  abcb6b:	e8 70 d8 15 00       	call   0xc1a3e0
  abcb70:	48 8d 7d c0          	lea    rdi,[rbp-0x40]
  abcb74:	ba 08 00 00 00       	mov    edx,0x8
  abcb79:	4c 89 f6             	mov    rsi,r14
  abcb7c:	e8 4f c6 79 ff       	call   0x2591d0
  abcb81:	85 c0                	test   eax,eax
  abcb83:	75 4f                	jne    0xabcbd4
  abcb85:	48 8b 5b 10          	mov    rbx,QWORD PTR [rbx+0x10]
  abcb89:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abcb90:	00 00 
  abcb92:	48 8d 35 fe 26 89 00 	lea    rsi,[rip+0x8926fe]        # 0x134f297
  abcb99:	31 d2                	xor    edx,edx
  abcb9b:	e8 40 d8 15 00       	call   0xc1a3e0
  abcba0:	48 8d 7d c8          	lea    rdi,[rbp-0x38]
  abcba4:	ba 08 00 00 00       	mov    edx,0x8
  abcba9:	48 89 de             	mov    rsi,rbx
  abcbac:	e8 1f c6 79 ff       	call   0x2591d0
  abcbb1:	eb 21                	jmp    0xabcbd4
  abcbb3:	b8 01 00 00 00       	mov    eax,0x1
  abcbb8:	eb 1a                	jmp    0xabcbd4
  abcbba:	49 81 c6 48 01 00 00 	add    r14,0x148
  abcbc1:	31 f6                	xor    esi,esi
  abcbc3:	31 d2                	xor    edx,edx
  abcbc5:	31 c9                	xor    ecx,ecx
  abcbc7:	4c 89 f7             	mov    rdi,r14
  abcbca:	e8 d1 a3 a0 ff       	call   0x4c6fa0
  abcbcf:	b8 03 00 00 00       	mov    eax,0x3
  abcbd4:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  abcbd8:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  abcbdc:	75 0f                	jne    0xabcbed
  abcbde:	48 83 c4 18          	add    rsp,0x18
  abcbe2:	5b                   	pop    rbx
  abcbe3:	41 5c                	pop    r12
  abcbe5:	41 5d                	pop    r13
  abcbe7:	41 5e                	pop    r14
  abcbe9:	41 5f                	pop    r15
  abcbeb:	5d                   	pop    rbp
  abcbec:	c3                   	ret
  abcbed:	e8 be 0a c4 ff       	call   0x6fd6b0
  abcbf2:	0f 0b                	ud2
  abcbf4:	90                   	nop
  abcbf5:	90                   	nop
  abcbf6:	90                   	nop
  abcbf7:	90                   	nop
  abcbf8:	90                   	nop
  abcbf9:	90                   	nop
  abcbfa:	90                   	nop
  abcbfb:	90                   	nop
  abcbfc:	90                   	nop
  abcbfd:	90                   	nop
  abcbfe:	90                   	nop
  abcbff:	90                   	nop
  abcc00:	55                   	push   rbp
  abcc01:	48 89 e5             	mov    rbp,rsp
  abcc04:	41 57                	push   r15
  abcc06:	41 56                	push   r14
  abcc08:	53                   	push   rbx
  abcc09:	48 81 ec b8 00 00 00 	sub    rsp,0xb8
  abcc10:	4c 8d 3d f9 f6 e5 02 	lea    r15,[rip+0x2e5f6f9]        # 0x391c310
  abcc17:	48 89 f3             	mov    rbx,rsi
  abcc1a:	48 8d 95 30 ff ff ff 	lea    rdx,[rbp-0xd0]
  abcc21:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abcc24:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  abcc28:	8b 36                	mov    esi,DWORD PTR [rsi]
  abcc2a:	e8 91 00 00 00       	call   0xabccc0
  abcc2f:	85 c0                	test   eax,eax
  abcc31:	75 65                	jne    0xabcc98
  abcc33:	4c 8b 73 08          	mov    r14,QWORD PTR [rbx+0x8]
  abcc37:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abcc3e:	00 00 
  abcc40:	48 8d 35 50 26 89 00 	lea    rsi,[rip+0x892650]        # 0x134f297
  abcc47:	31 d2                	xor    edx,edx
  abcc49:	e8 92 d7 15 00       	call   0xc1a3e0
  abcc4e:	48 8d bd 30 ff ff ff 	lea    rdi,[rbp-0xd0]
  abcc55:	ba 08 00 00 00       	mov    edx,0x8
  abcc5a:	4c 89 f6             	mov    rsi,r14
  abcc5d:	e8 6e c5 79 ff       	call   0x2591d0
  abcc62:	85 c0                	test   eax,eax
  abcc64:	75 32                	jne    0xabcc98
  abcc66:	48 8b 5b 10          	mov    rbx,QWORD PTR [rbx+0x10]
  abcc6a:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abcc71:	00 00 
  abcc73:	48 8d 35 1d 26 89 00 	lea    rsi,[rip+0x89261d]        # 0x134f297
  abcc7a:	31 d2                	xor    edx,edx
  abcc7c:	4c 8d b5 38 ff ff ff 	lea    r14,[rbp-0xc8]
  abcc83:	e8 58 d7 15 00       	call   0xc1a3e0
  abcc88:	ba 08 00 00 00       	mov    edx,0x8
  abcc8d:	4c 89 f7             	mov    rdi,r14
  abcc90:	48 89 de             	mov    rsi,rbx
  abcc93:	e8 38 c5 79 ff       	call   0x2591d0
  abcc98:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  abcc9b:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  abcc9f:	75 0e                	jne    0xabccaf
  abcca1:	48 81 c4 b8 00 00 00 	add    rsp,0xb8
  abcca8:	5b                   	pop    rbx
  abcca9:	41 5e                	pop    r14
  abccab:	41 5f                	pop    r15
  abccad:	5d                   	pop    rbp
  abccae:	c3                   	ret
  abccaf:	e8 fc 09 c4 ff       	call   0x6fd6b0
  abccb4:	0f 0b                	ud2
  abccb6:	90                   	nop
  abccb7:	90                   	nop
  abccb8:	90                   	nop
  abccb9:	90                   	nop
  abccba:	90                   	nop
  abccbb:	90                   	nop
  abccbc:	90                   	nop
  abccbd:	90                   	nop
  abccbe:	90                   	nop
  abccbf:	90                   	nop
  abccc0:	55                   	push   rbp
  abccc1:	48 89 e5             	mov    rbp,rsp
  abccc4:	41 57                	push   r15
  abccc6:	41 56                	push   r14
  abccc8:	41 55                	push   r13
  abccca:	41 54                	push   r12
  abcccc:	53                   	push   rbx
  abcccd:	48 83 ec 38          	sub    rsp,0x38
  abccd1:	4c 8d 3d 38 f6 e5 02 	lea    r15,[rip+0x2e5f638]        # 0x391c310
  abccd8:	48 89 55 c0          	mov    QWORD PTR [rbp-0x40],rdx
  abccdc:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abccdf:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abcce3:	85 f6                	test   esi,esi
  abcce5:	74 19                	je     0xabcd00
  abcce7:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  abccee:	00 00 
  abccf0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abccf4:	3b b0 bc 00 00 00    	cmp    esi,DWORD PTR [rax+0xbc]
  abccfa:	0f 85 a2 02 00 00    	jne    0xabcfa2
  abcd00:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  abcd07:	00 00 
  abcd09:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
  abcd0d:	31 f6                	xor    esi,esi
  abcd0f:	31 d2                	xor    edx,edx
  abcd11:	31 c9                	xor    ecx,ecx
  abcd13:	48 8d bb 48 01 00 00 	lea    rdi,[rbx+0x148]
  abcd1a:	e8 e1 9c a0 ff       	call   0x4c6a00
  abcd1f:	8b 83 b0 00 00 00    	mov    eax,DWORD PTR [rbx+0xb0]
  abcd25:	a9 00 20 00 00       	test   eax,0x2000
  abcd2a:	0f 85 eb 01 00 00    	jne    0xabcf1b
  abcd30:	ff 83 58 03 00 00    	inc    DWORD PTR [rbx+0x358]
  abcd36:	a9 00 00 00 10       	test   eax,0x10000000
  abcd3b:	75 08                	jne    0xabcd45
  abcd3d:	48 89 df             	mov    rdi,rbx
  abcd40:	e8 cb dc a7 ff       	call   0x53aa10
  abcd45:	48 8d bb 48 01 00 00 	lea    rdi,[rbx+0x148]
  abcd4c:	31 f6                	xor    esi,esi
  abcd4e:	31 d2                	xor    edx,edx
  abcd50:	31 c9                	xor    ecx,ecx
  abcd52:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  abcd56:	e8 45 a2 a0 ff       	call   0x4c6fa0
  abcd5b:	4c 8b a3 00 02 00 00 	mov    r12,QWORD PTR [rbx+0x200]
  abcd62:	48 89 5d b0          	mov    QWORD PTR [rbp-0x50],rbx
  abcd66:	31 f6                	xor    esi,esi
  abcd68:	31 d2                	xor    edx,edx
  abcd6a:	4c 89 e7             	mov    rdi,r12
  abcd6d:	e8 ae 9a 80 ff       	call   0x2c6820
  abcd72:	0f 31                	rdtsc
  abcd74:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  abcd78:	be b0 00 00 00       	mov    esi,0xb0
  abcd7d:	48 89 d3             	mov    rbx,rdx
  abcd80:	49 89 c7             	mov    r15,rax
  abcd83:	e8 68 c2 79 ff       	call   0x258ff0
  abcd88:	49 8b 44 24 08       	mov    rax,QWORD PTR [r12+0x8]
  abcd8d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  abcd91:	4c 39 e0             	cmp    rax,r12
  abcd94:	0f 84 a1 01 00 00    	je     0xabcf3b
  abcd9a:	48 c1 e3 20          	shl    rbx,0x20
  abcd9e:	4c 8d 35 dd 4d 7d 00 	lea    r14,[rip+0x7d4ddd]        # 0x1291b82
  abcda5:	49 09 df             	or     r15,rbx
  abcda8:	eb 2f                	jmp    0xabcdd9
  abcdaa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  abcdb0:	48 8b 7d a8          	mov    rdi,QWORD PTR [rbp-0x58]
  abcdb4:	31 f6                	xor    esi,esi
  abcdb6:	31 d2                	xor    edx,edx
  abcdb8:	e8 23 89 d1 ff       	call   0x7d56e0
  abcdbd:	4c 8d 35 be 4d 7d 00 	lea    r14,[rip+0x7d4dbe]        # 0x1291b82
  abcdc4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  abcdc8:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abcdcc:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  abcdd0:	4c 39 e0             	cmp    rax,r12
  abcdd3:	0f 84 62 01 00 00    	je     0xabcf3b
  abcdd9:	4c 8b 68 20          	mov    r13,QWORD PTR [rax+0x20]
  abcddd:	0f 31                	rdtsc
  abcddf:	48 c1 e2 20          	shl    rdx,0x20
  abcde3:	48 09 c2             	or     rdx,rax
  abcde6:	4c 29 fa             	sub    rdx,r15
  abcde9:	48 81 fa 01 71 02 00 	cmp    rdx,0x27101
  abcdf0:	72 6e                	jb     0xabce60
  abcdf2:	41 8b 9c 24 c0 01 00 	mov    ebx,DWORD PTR [r12+0x1c0]
  abcdf9:	00 
  abcdfa:	4c 89 e7             	mov    rdi,r12
  abcdfd:	31 f6                	xor    esi,esi
  abcdff:	31 d2                	xor    edx,edx
  abce01:	e8 6a 9a 80 ff       	call   0x2c6870
  abce06:	48 8b 35 c3 35 e6 02 	mov    rsi,QWORD PTR [rip+0x2e635c3]        # 0x39203d0
  abce0d:	4c 89 f7             	mov    rdi,r14
  abce10:	b9 00 01 00 00       	mov    ecx,0x100
  abce15:	31 d2                	xor    edx,edx
  abce17:	e8 14 9a 14 00       	call   0xc06830
  abce1c:	4c 89 e7             	mov    rdi,r12
  abce1f:	31 f6                	xor    esi,esi
  abce21:	31 d2                	xor    edx,edx
  abce23:	e8 f8 99 80 ff       	call   0x2c6820
  abce28:	0f 31                	rdtsc
  abce2a:	49 89 d7             	mov    r15,rdx
  abce2d:	49 c1 e7 20          	shl    r15,0x20
  abce31:	49 09 c7             	or     r15,rax
  abce34:	41 39 9c 24 c0 01 00 	cmp    DWORD PTR [r12+0x1c0],ebx
  abce3b:	00 
  abce3c:	74 22                	je     0xabce60
  abce3e:	4c 89 e7             	mov    rdi,r12
  abce41:	4c 89 ee             	mov    rsi,r13
  abce44:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  abce48:	e8 f3 9d 80 ff       	call   0x2c6c40
  abce4d:	85 c0                	test   eax,eax
  abce4f:	0f 84 6f ff ff ff    	je     0xabcdc4
  abce55:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  abce5c:	00 00 00 00 
  abce60:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  abce64:	f6 40 60 02          	test   BYTE PTR [rax+0x60],0x2
  abce68:	0f 85 56 ff ff ff    	jne    0xabcdc4
  abce6e:	48 8b 58 50          	mov    rbx,QWORD PTR [rax+0x50]
  abce72:	48 85 db             	test   rbx,rbx
  abce75:	0f 84 49 ff ff ff    	je     0xabcdc4
  abce7b:	0f b6 83 9d 00 00 00 	movzx  eax,BYTE PTR [rbx+0x9d]
  abce82:	83 f8 08             	cmp    eax,0x8
  abce85:	0f 87 39 ff ff ff    	ja     0xabcdc4
  abce8b:	b9 87 01 00 00       	mov    ecx,0x187
  abce90:	0f a3 c1             	bt     ecx,eax
  abce93:	0f 83 2b ff ff ff    	jae    0xabcdc4
  abce99:	48 8d 7b 18          	lea    rdi,[rbx+0x18]
  abce9d:	31 f6                	xor    esi,esi
  abce9f:	31 d2                	xor    edx,edx
  abcea1:	48 89 7d a8          	mov    QWORD PTR [rbp-0x58],rdi
  abcea5:	e8 16 82 d1 ff       	call   0x7d50c0
  abceaa:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  abceae:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
  abceb2:	48 89 df             	mov    rdi,rbx
  abceb5:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
  abceb9:	4c 0f be b0 4c 01 00 	movsx  r14,BYTE PTR [rax+0x14c]
  abcec0:	00 
  abcec1:	4c 29 e9             	sub    rcx,r13
  abcec4:	49 c1 e6 04          	shl    r14,0x4
  abcec8:	48 c1 e9 0e          	shr    rcx,0xe
  abcecc:	4a 01 4c 32 08       	add    QWORD PTR [rdx+r14*1+0x8],rcx
  abced1:	4c 89 e9             	mov    rcx,r13
  abced4:	48 8b 70 58          	mov    rsi,QWORD PTR [rax+0x58]
  abced8:	49 89 f5             	mov    r13,rsi
  abcedb:	48 c1 fe 0e          	sar    rsi,0xe
  abcedf:	49 29 cd             	sub    r13,rcx
  abcee2:	4c 03 68 28          	add    r13,QWORD PTR [rax+0x28]
  abcee6:	e8 05 c9 0c 00       	call   0xb897f0
  abceeb:	48 85 c0             	test   rax,rax
  abceee:	0f 84 bc fe ff ff    	je     0xabcdb0
  abcef4:	4c 03 75 c0          	add    r14,QWORD PTR [rbp-0x40]
  abcef8:	49 c1 fd 0e          	sar    r13,0xe
  abcefc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  abcf00:	4c 39 68 28          	cmp    QWORD PTR [rax+0x28],r13
  abcf04:	0f 83 a6 fe ff ff    	jae    0xabcdb0
  abcf0a:	49 ff 06             	inc    QWORD PTR [r14]
  abcf0d:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  abcf11:	48 85 c0             	test   rax,rax
  abcf14:	75 ea                	jne    0xabcf00
  abcf16:	e9 95 fe ff ff       	jmp    0xabcdb0
  abcf1b:	48 81 c3 48 01 00 00 	add    rbx,0x148
  abcf22:	31 f6                	xor    esi,esi
  abcf24:	31 d2                	xor    edx,edx
  abcf26:	31 c9                	xor    ecx,ecx
  abcf28:	48 89 df             	mov    rdi,rbx
  abcf2b:	e8 70 a0 a0 ff       	call   0x4c6fa0
  abcf30:	41 be 03 00 00 00    	mov    r14d,0x3
  abcf36:	e9 9a 00 00 00       	jmp    0xabcfd5
  abcf3b:	4c 89 e7             	mov    rdi,r12
  abcf3e:	45 31 f6             	xor    r14d,r14d
  abcf41:	31 f6                	xor    esi,esi
  abcf43:	31 d2                	xor    edx,edx
  abcf45:	e8 26 99 80 ff       	call   0x2c6870
  abcf4a:	48 8b 5d b8          	mov    rbx,QWORD PTR [rbp-0x48]
  abcf4e:	31 f6                	xor    esi,esi
  abcf50:	31 d2                	xor    edx,edx
  abcf52:	31 c9                	xor    ecx,ecx
  abcf54:	48 89 df             	mov    rdi,rbx
  abcf57:	e8 a4 9a a0 ff       	call   0x4c6a00
  abcf5c:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  abcf60:	0f b6 8f b1 00 00 00 	movzx  ecx,BYTE PTR [rdi+0xb1]
  abcf67:	8b 87 58 03 00 00    	mov    eax,DWORD PTR [rdi+0x358]
  abcf6d:	c0 e9 05             	shr    cl,0x5
  abcf70:	ff c8                	dec    eax
  abcf72:	0f 94 c2             	sete   dl
  abcf75:	89 87 58 03 00 00    	mov    DWORD PTR [rdi+0x358],eax
  abcf7b:	84 d1                	test   cl,dl
  abcf7d:	74 0c                	je     0xabcf8b
  abcf7f:	48 81 c7 58 03 00 00 	add    rdi,0x358
  abcf86:	e8 85 99 14 00       	call   0xc06910
  abcf8b:	48 89 df             	mov    rdi,rbx
  abcf8e:	31 f6                	xor    esi,esi
  abcf90:	31 d2                	xor    edx,edx
  abcf92:	31 c9                	xor    ecx,ecx
  abcf94:	e8 07 a0 a0 ff       	call   0x4c6fa0
  abcf99:	4c 8d 3d 70 f3 e5 02 	lea    r15,[rip+0x2e5f370]        # 0x391c310
  abcfa0:	eb 33                	jmp    0xabcfd5
  abcfa2:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abcfa9:	89 f3                	mov    ebx,esi
  abcfab:	e8 e0 bf b4 ff       	call   0x608f90
  abcfb0:	85 c0                	test   eax,eax
  abcfb2:	74 1b                	je     0xabcfcf
  abcfb4:	89 df                	mov    edi,ebx
  abcfb6:	e8 b5 f1 a7 ff       	call   0x53c170
  abcfbb:	48 89 c3             	mov    rbx,rax
  abcfbe:	48 85 c0             	test   rax,rax
  abcfc1:	0f 85 58 fd ff ff    	jne    0xabcd1f
  abcfc7:	41 be 03 00 00 00    	mov    r14d,0x3
  abcfcd:	eb 06                	jmp    0xabcfd5
  abcfcf:	41 be 01 00 00 00    	mov    r14d,0x1
  abcfd5:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abcfd8:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  abcfdc:	75 12                	jne    0xabcff0
  abcfde:	44 89 f0             	mov    eax,r14d
  abcfe1:	48 83 c4 38          	add    rsp,0x38
  abcfe5:	5b                   	pop    rbx
  abcfe6:	41 5c                	pop    r12
  abcfe8:	41 5d                	pop    r13
  abcfea:	41 5e                	pop    r14
  abcfec:	41 5f                	pop    r15
  abcfee:	5d                   	pop    rbp
  abcfef:	c3                   	ret
  abcff0:	e8 bb 06 c4 ff       	call   0x6fd6b0
  abcff5:	0f 0b                	ud2
  abcff7:	90                   	nop
  abcff8:	90                   	nop
  abcff9:	90                   	nop
  abcffa:	90                   	nop
  abcffb:	90                   	nop
  abcffc:	90                   	nop
  abcffd:	90                   	nop
  abcffe:	90                   	nop
  abcfff:	90                   	nop
  abd000:	55                   	push   rbp
  abd001:	48 89 e5             	mov    rbp,rsp
  abd004:	41 57                	push   r15
  abd006:	41 56                	push   r14
  abd008:	41 54                	push   r12
  abd00a:	53                   	push   rbx
  abd00b:	48 81 ec c0 00 00 00 	sub    rsp,0xc0
  abd012:	4c 8d 25 f7 f2 e5 02 	lea    r12,[rip+0x2e5f2f7]        # 0x391c310
  abd019:	48 89 f3             	mov    rbx,rsi
  abd01c:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  abd020:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  abd024:	8b 4e 08             	mov    ecx,DWORD PTR [rsi+0x8]
  abd027:	83 f9 0a             	cmp    ecx,0xa
  abd02a:	74 0d                	je     0xabd039
  abd02c:	b8 16 00 00 00       	mov    eax,0x16
  abd031:	85 c9                	test   ecx,ecx
  abd033:	0f 85 8c 00 00 00    	jne    0xabd0c5
  abd039:	8b 33                	mov    esi,DWORD PTR [rbx]
  abd03b:	48 8d 95 28 ff ff ff 	lea    rdx,[rbp-0xd8]
  abd042:	e8 79 fc ff ff       	call   0xabccc0
  abd047:	85 c0                	test   eax,eax
  abd049:	75 7a                	jne    0xabd0c5
  abd04b:	48 63 43 08          	movsxd rax,DWORD PTR [rbx+0x8]
  abd04f:	4c 8b 7b 10          	mov    r15,QWORD PTR [rbx+0x10]
  abd053:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abd05a:	00 00 
  abd05c:	48 8d 35 34 22 89 00 	lea    rsi,[rip+0x892234]        # 0x134f297
  abd063:	31 d2                	xor    edx,edx
  abd065:	48 c1 e0 04          	shl    rax,0x4
  abd069:	4c 8d b4 05 28 ff ff 	lea    r14,[rbp+rax*1-0xd8]
  abd070:	ff 
  abd071:	e8 6a d3 15 00       	call   0xc1a3e0
  abd076:	ba 08 00 00 00       	mov    edx,0x8
  abd07b:	4c 89 f7             	mov    rdi,r14
  abd07e:	4c 89 fe             	mov    rsi,r15
  abd081:	e8 4a c1 79 ff       	call   0x2591d0
  abd086:	85 c0                	test   eax,eax
  abd088:	75 3b                	jne    0xabd0c5
  abd08a:	48 63 43 08          	movsxd rax,DWORD PTR [rbx+0x8]
  abd08e:	48 8b 5b 18          	mov    rbx,QWORD PTR [rbx+0x18]
  abd092:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abd099:	00 00 
  abd09b:	48 8d 35 f5 21 89 00 	lea    rsi,[rip+0x8921f5]        # 0x134f297
  abd0a2:	31 d2                	xor    edx,edx
  abd0a4:	48 c1 e0 04          	shl    rax,0x4
  abd0a8:	4c 8d b4 05 30 ff ff 	lea    r14,[rbp+rax*1-0xd0]
  abd0af:	ff 
  abd0b0:	e8 2b d3 15 00       	call   0xc1a3e0
  abd0b5:	ba 08 00 00 00       	mov    edx,0x8
  abd0ba:	4c 89 f7             	mov    rdi,r14
  abd0bd:	48 89 de             	mov    rsi,rbx
  abd0c0:	e8 0b c1 79 ff       	call   0x2591d0
  abd0c5:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  abd0c9:	48 3b 4d d8          	cmp    rcx,QWORD PTR [rbp-0x28]
  abd0cd:	75 10                	jne    0xabd0df
  abd0cf:	48 81 c4 c0 00 00 00 	add    rsp,0xc0
  abd0d6:	5b                   	pop    rbx
  abd0d7:	41 5c                	pop    r12
  abd0d9:	41 5e                	pop    r14
  abd0db:	41 5f                	pop    r15
  abd0dd:	5d                   	pop    rbp
  abd0de:	c3                   	ret
  abd0df:	e8 cc 05 c4 ff       	call   0x6fd6b0
  abd0e4:	0f 0b                	ud2
  abd0e6:	90                   	nop
  abd0e7:	90                   	nop
  abd0e8:	90                   	nop
  abd0e9:	90                   	nop
  abd0ea:	90                   	nop
  abd0eb:	90                   	nop
  abd0ec:	90                   	nop
  abd0ed:	90                   	nop
  abd0ee:	90                   	nop
  abd0ef:	90                   	nop
  abd0f0:	55                   	push   rbp
  abd0f1:	48 89 e5             	mov    rbp,rsp
  abd0f4:	41 57                	push   r15
  abd0f6:	41 56                	push   r14
  abd0f8:	41 55                	push   r13
  abd0fa:	41 54                	push   r12
  abd0fc:	53                   	push   rbx
  abd0fd:	48 83 ec 68          	sub    rsp,0x68
  abd101:	4c 8d 35 08 f2 e5 02 	lea    r14,[rip+0x2e5f208]        # 0x391c310
  abd108:	48 89 fb             	mov    rbx,rdi
  abd10b:	49 89 f7             	mov    r15,rsi
  abd10e:	49 8b 06             	mov    rax,QWORD PTR [r14]
  abd111:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abd115:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abd11c:	e8 6f be b4 ff       	call   0x608f90
  abd121:	85 c0                	test   eax,eax
  abd123:	0f 84 d7 02 00 00    	je     0xabd400
  abd129:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abd12c:	4c 8d 25 4d ef 13 02 	lea    r12,[rip+0x213ef4d]        # 0x2bfc080
  abd133:	4c 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r15
  abd13a:	45 31 f6             	xor    r14d,r14d
  abd13d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  abd141:	48 8d 45 90          	lea    rax,[rbp-0x70]
  abd145:	49 63 4f 08          	movsxd rcx,DWORD PTR [r15+0x8]
  abd149:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  abd14d:	c7 45 a8 01 00 00 00 	mov    DWORD PTR [rbp-0x58],0x1
  abd154:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
  abd15b:	00 
  abd15c:	48 89 4d b8          	mov    QWORD PTR [rbp-0x48],rcx
  abd160:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  abd167:	00 
  abd168:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  abd16c:	48 8d 1d ed 0e a6 02 	lea    rbx,[rip+0x2a60eed]        # 0x351e060
  abd173:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
  abd177:	48 89 8d 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rcx
  abd17e:	48 89 df             	mov    rdi,rbx
  abd181:	31 f6                	xor    esi,esi
  abd183:	31 d2                	xor    edx,edx
  abd185:	31 c9                	xor    ecx,ecx
  abd187:	e8 74 98 a0 ff       	call   0x4c6a00
  abd18c:	48 8b 05 a5 0e a6 02 	mov    rax,QWORD PTR [rip+0x2a60ea5]        # 0x351e038
  abd193:	41 bf 00 00 00 00    	mov    r15d,0x0
  abd199:	48 85 c0             	test   rax,rax
  abd19c:	74 1e                	je     0xabd1bc
  abd19e:	45 31 ff             	xor    r15d,r15d
  abd1a1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  abd1a8:	0f 1f 84 00 00 00 00 
  abd1af:	00 
  abd1b0:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
  abd1b4:	41 ff c7             	inc    r15d
  abd1b7:	48 85 c0             	test   rax,rax
  abd1ba:	75 f4                	jne    0xabd1b0
  abd1bc:	48 89 df             	mov    rdi,rbx
  abd1bf:	31 f6                	xor    esi,esi
  abd1c1:	31 d2                	xor    edx,edx
  abd1c3:	31 c9                	xor    ecx,ecx
  abd1c5:	e8 d6 9d a0 ff       	call   0x4c6fa0
  abd1ca:	49 63 c7             	movsxd rax,r15d
  abd1cd:	4c 89 e6             	mov    rsi,r12
  abd1d0:	ba 02 01 00 00       	mov    edx,0x102
  abd1d5:	48 69 f8 28 01 00 00 	imul   rdi,rax,0x128
  abd1dc:	e8 6f b9 14 00       	call   0xc08b50
  abd1e1:	48 89 df             	mov    rdi,rbx
  abd1e4:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
  abd1e8:	31 f6                	xor    esi,esi
  abd1ea:	31 d2                	xor    edx,edx
  abd1ec:	31 c9                	xor    ecx,ecx
  abd1ee:	e8 0d 98 a0 ff       	call   0x4c6a00
  abd1f3:	4c 8b 25 3e 0e a6 02 	mov    r12,QWORD PTR [rip+0x2a60e3e]        # 0x351e038
  abd1fa:	4d 85 e4             	test   r12,r12
  abd1fd:	0f 84 84 01 00 00    	je     0xabd387
  abd203:	48 c7 45 88 00 00 00 	mov    QWORD PTR [rbp-0x78],0x0
  abd20a:	00 
  abd20b:	eb 6e                	jmp    0xabd27b
  abd20d:	41 c6 46 24 02       	mov    BYTE PTR [r14+0x24],0x2
  abd212:	49 8b 84 24 30 01 00 	mov    rax,QWORD PTR [r12+0x130]
  abd219:	00 
  abd21a:	49 89 06             	mov    QWORD PTR [r14],rax
  abd21d:	49 8b 84 24 38 01 00 	mov    rax,QWORD PTR [r12+0x138]
  abd224:	00 
  abd225:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
  abd229:	49 8b 84 24 88 00 00 	mov    rax,QWORD PTR [r12+0x88]
  abd230:	00 
  abd231:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
  abd235:	49 63 84 24 a8 00 00 	movsxd rax,DWORD PTR [r12+0xa8]
  abd23c:	00 
  abd23d:	49 89 46 18          	mov    QWORD PTR [r14+0x18],rax
  abd241:	41 8b 84 24 48 01 00 	mov    eax,DWORD PTR [r12+0x148]
  abd248:	00 
  abd249:	41 89 46 20          	mov    DWORD PTR [r14+0x20],eax
  abd24d:	41 0f b6 84 24 51 01 	movzx  eax,BYTE PTR [r12+0x151]
  abd254:	00 00 
  abd256:	41 88 46 25          	mov    BYTE PTR [r14+0x25],al
  abd25a:	44 89 e8             	mov    eax,r13d
  abd25d:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  abd261:	48 89 df             	mov    rdi,rbx
  abd264:	31 f6                	xor    esi,esi
  abd266:	31 d2                	xor    edx,edx
  abd268:	e8 43 7c d1 ff       	call   0x7d4eb0
  abd26d:	4d 8b 64 24 20       	mov    r12,QWORD PTR [r12+0x20]
  abd272:	4d 85 e4             	test   r12,r12
  abd275:	0f 84 01 01 00 00    	je     0xabd37c
  abd27b:	49 8d 5c 24 18       	lea    rbx,[r12+0x18]
  abd280:	31 f6                	xor    esi,esi
  abd282:	31 d2                	xor    edx,edx
  abd284:	48 89 df             	mov    rdi,rbx
  abd287:	e8 14 74 d1 ff       	call   0x7d46a0
  abd28c:	41 8b 84 24 a0 00 00 	mov    eax,DWORD PTR [r12+0xa0]
  abd293:	00 
  abd294:	a8 08                	test   al,0x8
  abd296:	75 c9                	jne    0xabd261
  abd298:	48 8b 4d 88          	mov    rcx,QWORD PTR [rbp-0x78]
  abd29c:	44 8d 69 01          	lea    r13d,[rcx+0x1]
  abd2a0:	45 39 ef             	cmp    r15d,r13d
  abd2a3:	0f 8c 97 00 00 00    	jl     0xabd340
  abd2a9:	41 0f b6 8c 24 9d 00 	movzx  ecx,BYTE PTR [r12+0x9d]
  abd2b0:	00 00 
  abd2b2:	48 83 f9 08          	cmp    rcx,0x8
  abd2b6:	77 a9                	ja     0xabd261
  abd2b8:	48 63 55 88          	movsxd rdx,DWORD PTR [rbp-0x78]
  abd2bc:	48 8d 35 a5 ec e1 00 	lea    rsi,[rip+0xe1eca5]        # 0x18dbf68
  abd2c3:	48 63 0c 8e          	movsxd rcx,DWORD PTR [rsi+rcx*4]
  abd2c7:	4c 69 f2 28 01 00 00 	imul   r14,rdx,0x128
  abd2ce:	4c 03 75 80          	add    r14,QWORD PTR [rbp-0x80]
  abd2d2:	48 01 f1             	add    rcx,rsi
  abd2d5:	ff e1                	jmp    rcx
  abd2d7:	a9 00 00 02 00       	test   eax,0x20000
  abd2dc:	0f 85 2b ff ff ff    	jne    0xabd20d
  abd2e2:	41 c6 46 24 00       	mov    BYTE PTR [r14+0x24],0x0
  abd2e7:	e9 26 ff ff ff       	jmp    0xabd212
  abd2ec:	41 c6 46 24 01       	mov    BYTE PTR [r14+0x24],0x1
  abd2f1:	49 8d 7e 26          	lea    rdi,[r14+0x26]
  abd2f5:	49 8d b4 24 60 01 00 	lea    rsi,[r12+0x160]
  abd2fc:	00 
  abd2fd:	ba ff 00 00 00       	mov    edx,0xff
  abd302:	eb 21                	jmp    0xabd325
  abd304:	49 8d 46 26          	lea    rax,[r14+0x26]
  abd308:	4c 89 e7             	mov    rdi,r12
  abd30b:	41 c6 46 24 04       	mov    BYTE PTR [r14+0x24],0x4
  abd310:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  abd314:	e8 a7 4f b7 ff       	call   0x6322c0
  abd319:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  abd31d:	ba ff 00 00 00       	mov    edx,0xff
  abd322:	48 89 c6             	mov    rsi,rax
  abd325:	e8 46 a8 e9 ff       	call   0x957b70
  abd32a:	e9 e3 fe ff ff       	jmp    0xabd212
  abd32f:	41 c6 46 24 03       	mov    BYTE PTR [r14+0x24],0x3
  abd334:	e9 d9 fe ff ff       	jmp    0xabd212
  abd339:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  abd340:	48 89 df             	mov    rdi,rbx
  abd343:	31 f6                	xor    esi,esi
  abd345:	31 d2                	xor    edx,edx
  abd347:	e8 64 7b d1 ff       	call   0x7d4eb0
  abd34c:	48 8d 1d 0d 0d a6 02 	lea    rbx,[rip+0x2a60d0d]        # 0x351e060
  abd353:	31 f6                	xor    esi,esi
  abd355:	31 d2                	xor    edx,edx
  abd357:	31 c9                	xor    ecx,ecx
  abd359:	48 89 df             	mov    rdi,rbx
  abd35c:	e8 3f 9c a0 ff       	call   0x4c6fa0
  abd361:	4c 8d 25 18 ed 13 02 	lea    r12,[rip+0x213ed18]        # 0x2bfc080
  abd368:	48 8b 7d 80          	mov    rdi,QWORD PTR [rbp-0x80]
  abd36c:	4c 89 e6             	mov    rsi,r12
  abd36f:	e8 7c ba 14 00       	call   0xc08df0
  abd374:	45 31 f6             	xor    r14d,r14d
  abd377:	e9 02 fe ff ff       	jmp    0xabd17e
  abd37c:	48 63 45 88          	movsxd rax,DWORD PTR [rbp-0x78]
  abd380:	4c 69 f0 28 01 00 00 	imul   r14,rax,0x128
  abd387:	48 8d 3d d2 0c a6 02 	lea    rdi,[rip+0x2a60cd2]        # 0x351e060
  abd38e:	31 f6                	xor    esi,esi
  abd390:	31 d2                	xor    edx,edx
  abd392:	31 c9                	xor    ecx,ecx
  abd394:	e8 07 9c a0 ff       	call   0x4c6fa0
  abd399:	48 8b b5 70 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x90]
  abd3a0:	4c 8b 7d 80          	mov    r15,QWORD PTR [rbp-0x80]
  abd3a4:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
  abd3a8:	4c 39 f6             	cmp    rsi,r14
  abd3ab:	4c 89 ff             	mov    rdi,r15
  abd3ae:	49 0f 43 f6          	cmovae rsi,r14
  abd3b2:	e8 69 51 cc ff       	call   0x782520
  abd3b7:	48 8d 35 c2 ec 13 02 	lea    rsi,[rip+0x213ecc2]        # 0x2bfc080
  abd3be:	4c 89 ff             	mov    rdi,r15
  abd3c1:	89 c3                	mov    ebx,eax
  abd3c3:	e8 28 ba 14 00       	call   0xc08df0
  abd3c8:	89 d8                	mov    eax,ebx
  abd3ca:	85 db                	test   ebx,ebx
  abd3cc:	75 29                	jne    0xabd3f7
  abd3ce:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
  abd3d5:	48 8b 78 10          	mov    rdi,QWORD PTR [rax+0x10]
  abd3d9:	b8 00 00 00 00       	mov    eax,0x0
  abd3de:	48 85 ff             	test   rdi,rdi
  abd3e1:	74 14                	je     0xabd3f7
  abd3e3:	4c 89 f6             	mov    rsi,r14
  abd3e6:	e8 35 c3 79 ff       	call   0x259720
  abd3eb:	89 c1                	mov    ecx,eax
  abd3ed:	85 c0                	test   eax,eax
  abd3ef:	b8 0e 00 00 00       	mov    eax,0xe
  abd3f4:	0f 44 c1             	cmove  eax,ecx
  abd3f7:	4c 8d 35 12 ef e5 02 	lea    r14,[rip+0x2e5ef12]        # 0x391c310
  abd3fe:	eb 05                	jmp    0xabd405
  abd400:	b8 01 00 00 00       	mov    eax,0x1
  abd405:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  abd408:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  abd40c:	75 0f                	jne    0xabd41d
  abd40e:	48 83 c4 68          	add    rsp,0x68
  abd412:	5b                   	pop    rbx
  abd413:	41 5c                	pop    r12
  abd415:	41 5d                	pop    r13
  abd417:	41 5e                	pop    r14
  abd419:	41 5f                	pop    r15
  abd41b:	5d                   	pop    rbp
  abd41c:	c3                   	ret
  abd41d:	e8 8e 02 c4 ff       	call   0x6fd6b0
  abd422:	0f 0b                	ud2
  abd424:	90                   	nop
  abd425:	90                   	nop
  abd426:	90                   	nop
  abd427:	90                   	nop
  abd428:	90                   	nop
  abd429:	90                   	nop
  abd42a:	90                   	nop
  abd42b:	90                   	nop
  abd42c:	90                   	nop
  abd42d:	90                   	nop
  abd42e:	90                   	nop
  abd42f:	90                   	nop
  abd430:	55                   	push   rbp
  abd431:	48 89 e5             	mov    rbp,rsp
  abd434:	41 57                	push   r15
  abd436:	41 56                	push   r14
  abd438:	53                   	push   rbx
  abd439:	48 83 ec 18          	sub    rsp,0x18
  abd43d:	4c 8d 3d cc ee e5 02 	lea    r15,[rip+0x2e5eecc]        # 0x391c310
  abd444:	31 f6                	xor    esi,esi
  abd446:	31 d2                	xor    edx,edx
  abd448:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abd44b:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  abd44f:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  abd453:	48 8b 8f 60 04 00 00 	mov    rcx,QWORD PTR [rdi+0x460]
  abd45a:	4c 8b b1 00 01 00 00 	mov    r14,QWORD PTR [rcx+0x100]
  abd461:	48 8b 98 00 02 00 00 	mov    rbx,QWORD PTR [rax+0x200]
  abd468:	49 83 c6 80          	add    r14,0xffffffffffffff80
  abd46c:	48 89 df             	mov    rdi,rbx
  abd46f:	49 81 e6 00 c0 ff ff 	and    r14,0xffffffffffffc000
  abd476:	e8 a5 93 80 ff       	call   0x2c6820
  abd47b:	48 8d 55 d8          	lea    rdx,[rbp-0x28]
  abd47f:	48 89 df             	mov    rdi,rbx
  abd482:	4c 89 f6             	mov    rsi,r14
  abd485:	e8 b6 97 80 ff       	call   0x2c6c40
  abd48a:	85 c0                	test   eax,eax
  abd48c:	74 31                	je     0xabd4bf
  abd48e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
  abd492:	4c 2b 70 20          	sub    r14,QWORD PTR [rax+0x20]
  abd496:	49 c1 ee 0e          	shr    r14,0xe
  abd49a:	45 85 f6             	test   r14d,r14d
  abd49d:	7e 20                	jle    0xabd4bf
  abd49f:	48 8b 70 58          	mov    rsi,QWORD PTR [rax+0x58]
  abd4a3:	48 8b 78 50          	mov    rdi,QWORD PTR [rax+0x50]
  abd4a7:	41 81 e6 ff ff ff 7f 	and    r14d,0x7fffffff
  abd4ae:	b9 05 00 00 00       	mov    ecx,0x5
  abd4b3:	4c 89 f2             	mov    rdx,r14
  abd4b6:	48 c1 fe 0e          	sar    rsi,0xe
  abd4ba:	e8 51 61 9a ff       	call   0x463610
  abd4bf:	48 89 df             	mov    rdi,rbx
  abd4c2:	31 f6                	xor    esi,esi
  abd4c4:	31 d2                	xor    edx,edx
  abd4c6:	e8 a5 93 80 ff       	call   0x2c6870
  abd4cb:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abd4ce:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  abd4d2:	75 0d                	jne    0xabd4e1
  abd4d4:	31 c0                	xor    eax,eax
  abd4d6:	48 83 c4 18          	add    rsp,0x18
  abd4da:	5b                   	pop    rbx
  abd4db:	41 5e                	pop    r14
  abd4dd:	41 5f                	pop    r15
  abd4df:	5d                   	pop    rbp
  abd4e0:	c3                   	ret
  abd4e1:	e8 ca 01 c4 ff       	call   0x6fd6b0
  abd4e6:	0f 0b                	ud2
  abd4e8:	90                   	nop
  abd4e9:	90                   	nop
  abd4ea:	90                   	nop
  abd4eb:	90                   	nop
  abd4ec:	90                   	nop
  abd4ed:	90                   	nop
  abd4ee:	90                   	nop
  abd4ef:	90                   	nop
  abd4f0:	55                   	push   rbp
  abd4f1:	48 89 e5             	mov    rbp,rsp
  abd4f4:	41 56                	push   r14
  abd4f6:	53                   	push   rbx
  abd4f7:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  abd4fb:	48 89 fb             	mov    rbx,rdi
  abd4fe:	31 f6                	xor    esi,esi
  abd500:	31 d2                	xor    edx,edx
  abd502:	4c 8b b0 00 02 00 00 	mov    r14,QWORD PTR [rax+0x200]
  abd509:	4c 89 f7             	mov    rdi,r14
  abd50c:	e8 0f 93 80 ff       	call   0x2c6820
  abd511:	41 8b 86 c4 01 00 00 	mov    eax,DWORD PTR [r14+0x1c4]
  abd518:	4c 89 f7             	mov    rdi,r14
  abd51b:	31 f6                	xor    esi,esi
  abd51d:	31 d2                	xor    edx,edx
  abd51f:	48 89 83 08 04 00 00 	mov    QWORD PTR [rbx+0x408],rax
  abd526:	e8 45 93 80 ff       	call   0x2c6870
  abd52b:	31 c0                	xor    eax,eax
  abd52d:	5b                   	pop    rbx
  abd52e:	41 5e                	pop    r14
  abd530:	5d                   	pop    rbp
  abd531:	c3                   	ret
  abd532:	90                   	nop
  abd533:	90                   	nop
  abd534:	90                   	nop
  abd535:	90                   	nop
  abd536:	90                   	nop
  abd537:	90                   	nop
  abd538:	90                   	nop
  abd539:	90                   	nop
  abd53a:	90                   	nop
  abd53b:	90                   	nop
  abd53c:	90                   	nop
  abd53d:	90                   	nop
  abd53e:	90                   	nop
  abd53f:	90                   	nop
  abd540:	55                   	push   rbp
  abd541:	48 89 e5             	mov    rbp,rsp
  abd544:	41 57                	push   r15
  abd546:	41 56                	push   r14
  abd548:	41 55                	push   r13
  abd54a:	41 54                	push   r12
  abd54c:	53                   	push   rbx
  abd54d:	48 83 ec 48          	sub    rsp,0x48
  abd551:	48 8d 05 b8 ed e5 02 	lea    rax,[rip+0x2e5edb8]        # 0x391c310
  abd558:	49 89 fd             	mov    r13,rdi
  abd55b:	48 8b 00             	mov    rax,QWORD PTR [rax]
  abd55e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abd562:	4c 8b 26             	mov    r12,QWORD PTR [rsi]
  abd565:	4c 89 65 c8          	mov    QWORD PTR [rbp-0x38],r12
  abd569:	48 8b 46 08          	mov    rax,QWORD PTR [rsi+0x8]
  abd56d:	8b 4e 20             	mov    ecx,DWORD PTR [rsi+0x20]
  abd570:	4c 8b 7e 28          	mov    r15,QWORD PTR [rsi+0x28]
  abd574:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  abd578:	8b 46 10             	mov    eax,DWORD PTR [rsi+0x10]
  abd57b:	48 89 4d a0          	mov    QWORD PTR [rbp-0x60],rcx
  abd57f:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  abd583:	8b 46 18             	mov    eax,DWORD PTR [rsi+0x18]
  abd586:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  abd58d:	00 00 
  abd58f:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  abd593:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abd59a:	0f b6 d8             	movzx  ebx,al
  abd59d:	81 b9 d4 05 00 00 00 	cmp    DWORD PTR [rcx+0x5d4],0x3000000
  abd5a4:	00 00 03 
  abd5a7:	0f 43 d8             	cmovae ebx,eax
  abd5aa:	e8 b1 bf b4 ff       	call   0x609560
  abd5af:	b9 01 00 00 00       	mov    ecx,0x1
  abd5b4:	85 c0                	test   eax,eax
  abd5b6:	74 09                	je     0xabd5c1
  abd5b8:	4c 8d 3d 51 ed e5 02 	lea    r15,[rip+0x2e5ed51]        # 0x391c310
  abd5bf:	eb 4d                	jmp    0xabd60e
  abd5c1:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  abd5c8:	89 5d b4             	mov    DWORD PTR [rbp-0x4c],ebx
  abd5cb:	48 8b 5d 98          	mov    rbx,QWORD PTR [rbp-0x68]
  abd5cf:	4c 89 7d a8          	mov    QWORD PTR [rbp-0x58],r15
  abd5d3:	4c 89 6d c0          	mov    QWORD PTR [rbp-0x40],r13
  abd5d7:	e8 c4 bf b4 ff       	call   0x6095a0
  abd5dc:	85 c0                	test   eax,eax
  abd5de:	75 22                	jne    0xabd602
  abd5e0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  abd5e4:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  abd5eb:	e8 e0 bc b4 ff       	call   0x6092d0
  abd5f0:	85 c0                	test   eax,eax
  abd5f2:	74 38                	je     0xabd62c
  abd5f4:	48 8d 3d 1d 96 8b 00 	lea    rdi,[rip+0x8b961d]        # 0x1376c18
  abd5fb:	31 c0                	xor    eax,eax
  abd5fd:	e8 0e fe 79 ff       	call   0x25d410
  abd602:	4c 8d 3d 07 ed e5 02 	lea    r15,[rip+0x2e5ed07]        # 0x391c310
  abd609:	b9 01 00 00 00       	mov    ecx,0x1
  abd60e:	49 8b 07             	mov    rax,QWORD PTR [r15]
  abd611:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  abd615:	0f 85 01 03 00 00    	jne    0xabd91c
  abd61b:	89 c8                	mov    eax,ecx
  abd61d:	48 83 c4 48          	add    rsp,0x48
  abd621:	5b                   	pop    rbx
  abd622:	41 5c                	pop    r12
  abd624:	41 5d                	pop    r13
  abd626:	41 5e                	pop    r14
  abd628:	41 5f                	pop    r15
  abd62a:	5d                   	pop    rbp
  abd62b:	c3                   	ret
  abd62c:	4c 89 e0             	mov    rax,r12
  abd62f:	b9 16 00 00 00       	mov    ecx,0x16
  abd634:	48 c1 e0 32          	shl    rax,0x32
  abd638:	0f 85 7a ff ff ff    	jne    0xabd5b8
  abd63e:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  abd642:	f7 c6 ff 3f 00 00    	test   esi,0x3fff
  abd648:	0f 95 c0             	setne  al
  abd64b:	48 81 fe 00 40 00 00 	cmp    rsi,0x4000
  abd652:	0f 92 c2             	setb   dl
  abd655:	08 c2                	or     dl,al
  abd657:	0f 85 5b ff ff ff    	jne    0xabd5b8
  abd65d:	49 89 dd             	mov    r13,rbx
  abd660:	41 83 fd ff          	cmp    r13d,0xffffffff
  abd664:	74 32                	je     0xabd698
  abd666:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  abd66a:	44 89 ef             	mov    edi,r13d
  abd66d:	48 8b 70 08          	mov    rsi,QWORD PTR [rax+0x8]
  abd671:	e8 6a 5d 90 ff       	call   0x3c33e0
  abd676:	8b 5d b4             	mov    ebx,DWORD PTR [rbp-0x4c]
  abd679:	85 c0                	test   eax,eax
  abd67b:	0f 84 32 01 00 00    	je     0xabd7b3
  abd681:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  abd685:	89 d8                	mov    eax,ebx
  abd687:	b9 16 00 00 00       	mov    ecx,0x16
  abd68c:	25 0c fc ff ff       	and    eax,0xfffffc0c
  abd691:	74 14                	je     0xabd6a7
  abd693:	e9 20 ff ff ff       	jmp    0xabd5b8
  abd698:	8b 5d b4             	mov    ebx,DWORD PTR [rbp-0x4c]
  abd69b:	f7 c3 0c fc ff ff    	test   ebx,0xfffffc0c
  abd6a1:	0f 85 11 ff ff ff    	jne    0xabd5b8
  abd6a7:	48 8b 7d a0          	mov    rdi,QWORD PTR [rbp-0x60]
  abd6ab:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
  abd6af:	f7 c7 2f df 9f 00    	test   edi,0x9fdf2f
  abd6b5:	0f 94 c0             	sete   al
  abd6b8:	48 c1 e2 32          	shl    rdx,0x32
  abd6bc:	0f 94 c2             	sete   dl
  abd6bf:	20 c2                	and    dl,al
  abd6c1:	80 fa 01             	cmp    dl,0x1
  abd6c4:	0f 85 ee fe ff ff    	jne    0xabd5b8
  abd6ca:	40 f6 c7 40          	test   dil,0x40
  abd6ce:	74 18                	je     0xabd6e8
  abd6d0:	48 81 fe 00 40 00 00 	cmp    rsi,0x4000
  abd6d7:	0f 87 db fe ff ff    	ja     0xabd5b8
  abd6dd:	89 d8                	mov    eax,ebx
  abd6df:	83 e0 03             	and    eax,0x3
  abd6e2:	0f 84 d0 fe ff ff    	je     0xabd5b8
  abd6e8:	f7 c7 00 00 20 00    	test   edi,0x200000
  abd6ee:	74 11                	je     0xabd701
  abd6f0:	49 8b 7e 08          	mov    rdi,QWORD PTR [r14+0x8]
  abd6f4:	e8 07 6c 06 00       	call   0xb24300
  abd6f9:	85 c0                	test   eax,eax
  abd6fb:	0f 84 b2 00 00 00    	je     0xabd7b3
  abd701:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  abd705:	49 bf ff ff ff ef 07 	movabs r15,0x7efffffff
  abd70c:	00 00 00 
  abd70f:	e8 0c ac ff ff       	call   0xab8320
  abd714:	48 ba 00 00 00 10 f8 	movabs rdx,0xfffffff810000000
  abd71b:	ff ff ff 
  abd71e:	49 8d bf 01 00 00 10 	lea    rdi,[r15+0x10000001]
  abd725:	48 01 c2             	add    rdx,rax
  abd728:	48 39 fa             	cmp    rdx,rdi
  abd72b:	72 12                	jb     0xabd73f
  abd72d:	83 fb 40             	cmp    ebx,0x40
  abd730:	72 0d                	jb     0xabd73f
  abd732:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  abd736:	80 b9 81 0c 00 00 00 	cmp    BYTE PTR [rcx+0xc81],0x0
  abd73d:	74 74                	je     0xabd7b3
  abd73f:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  abd743:	41 89 da             	mov    r10d,ebx
  abd746:	4c 8b 5d a0          	mov    r11,QWORD PTR [rbp-0x60]
  abd74a:	41 d1 ea             	shr    r10d,1
  abd74d:	41 81 e2 41 01 00 00 	and    r10d,0x141
  abd754:	41 09 da             	or     r10d,ebx
  abd757:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  abd75b:	48 8b b1 00 02 00 00 	mov    rsi,QWORD PTR [rcx+0x200]
  abd762:	41 f6 c3 10          	test   r11b,0x10
  abd766:	75 5c                	jne    0xabd7c4
  abd768:	4d 85 e4             	test   r12,r12
  abd76b:	0f 84 e2 00 00 00    	je     0xabd853
  abd771:	4d 89 f8             	mov    r8,r15
  abd774:	4c 8d 3d 95 eb e5 02 	lea    r15,[rip+0x2e5eb95]        # 0x391c310
  abd77b:	48 39 fa             	cmp    rdx,rdi
  abd77e:	72 2b                	jb     0xabd7ab
  abd780:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
  abd784:	49 b9 00 00 00 f0 0f 	movabs r9,0xff0000000
  abd78b:	00 00 00 
  abd78e:	49 8d 79 01          	lea    rdi,[r9+0x1]
  abd792:	4c 01 e2             	add    rdx,r12
  abd795:	4c 39 c2             	cmp    rdx,r8
  abd798:	0f 96 c2             	setbe  dl
  abd79b:	49 39 fc             	cmp    r12,rdi
  abd79e:	40 0f 93 c7          	setae  dil
  abd7a2:	40 08 d7             	or     dil,dl
  abd7a5:	0f 84 c5 00 00 00    	je     0xabd870
  abd7ab:	4d 89 e1             	mov    r9,r12
  abd7ae:	e9 c1 00 00 00       	jmp    0xabd874
  abd7b3:	4c 8d 3d 56 eb e5 02 	lea    r15,[rip+0x2e5eb56]        # 0x391c310
  abd7ba:	b9 16 00 00 00       	mov    ecx,0x16
  abd7bf:	e9 4a fe ff ff       	jmp    0xabd60e
  abd7c4:	4c 89 fb             	mov    rbx,r15
  abd7c7:	4c 8d 3d 42 eb e5 02 	lea    r15,[rip+0x2e5eb42]        # 0x391c310
  abd7ce:	4d 85 e4             	test   r12,r12
  abd7d1:	0f 84 c7 00 00 00    	je     0xabd89e
  abd7d7:	4c 39 66 20          	cmp    QWORD PTR [rsi+0x20],r12
  abd7db:	4d 89 e0             	mov    r8,r12
  abd7de:	0f 97 c1             	seta   cl
  abd7e1:	4c 03 45 b8          	add    r8,QWORD PTR [rbp-0x48]
  abd7e5:	41 0f 92 c1          	setb   r9b
  abd7e9:	41 08 c9             	or     r9b,cl
  abd7ec:	b9 16 00 00 00       	mov    ecx,0x16
  abd7f1:	0f 85 17 fe ff ff    	jne    0xabd60e
  abd7f7:	4c 39 46 28          	cmp    QWORD PTR [rsi+0x28],r8
  abd7fb:	0f 82 0d fe ff ff    	jb     0xabd60e
  abd801:	48 39 fa             	cmp    rdx,rdi
  abd804:	72 21                	jb     0xabd827
  abd806:	49 39 d8             	cmp    r8,rbx
  abd809:	4c 89 e7             	mov    rdi,r12
  abd80c:	0f 97 c2             	seta   dl
  abd80f:	48 c1 ef 1c          	shr    rdi,0x1c
  abd813:	48 81 ff ff 00 00 00 	cmp    rdi,0xff
  abd81a:	40 0f 92 c7          	setb   dil
  abd81e:	40 84 d7             	test   dil,dl
  abd821:	0f 85 e7 fd ff ff    	jne    0xabd60e
  abd827:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  abd82b:	8b 89 c4 05 00 00    	mov    ecx,DWORD PTR [rcx+0x5c4]
  abd831:	48 83 ec 08          	sub    rsp,0x8
  abd835:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  abd839:	4c 8b 45 a8          	mov    r8,QWORD PTR [rbp-0x58]
  abd83d:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  abd841:	4d 89 e1             	mov    r9,r12
  abd844:	48 89 df             	mov    rdi,rbx
  abd847:	6a 00                	push   0x0
  abd849:	50                   	push   rax
  abd84a:	41 53                	push   r11
  abd84c:	6a 00                	push   0x0
  abd84e:	e9 a7 00 00 00       	jmp    0xabd8fa
  abd853:	45 31 c0             	xor    r8d,r8d
  abd856:	48 39 fa             	cmp    rdx,rdi
  abd859:	4c 8d 3d b0 ea e5 02 	lea    r15,[rip+0x2e5eab0]        # 0x391c310
  abd860:	41 0f 92 c0          	setb   r8b
  abd864:	41 c1 e0 04          	shl    r8d,0x4
  abd868:	4d 8b 8c 30 f8 01 00 	mov    r9,QWORD PTR [r8+rsi*1+0x1f8]
  abd86f:	00 
  abd870:	4c 89 4d c8          	mov    QWORD PTR [rbp-0x38],r9
  abd874:	44 89 da             	mov    edx,r11d
  abd877:	81 e2 00 00 00 ff    	and    edx,0xff000000
  abd87d:	74 29                	je     0xabd8a8
  abd87f:	81 fa 00 00 00 01    	cmp    edx,0x1000000
  abd885:	75 43                	jne    0xabd8ca
  abd887:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  abd88b:	31 d2                	xor    edx,edx
  abd88d:	80 b9 81 0c 00 00 00 	cmp    BYTE PTR [rcx+0xc81],0x0
  abd894:	0f 95 c2             	setne  dl
  abd897:	44 8d 5c 12 01       	lea    r11d,[rdx+rdx*1+0x1]
  abd89c:	eb 37                	jmp    0xabd8d5
  abd89e:	b9 16 00 00 00       	mov    ecx,0x16
  abd8a3:	e9 66 fd ff ff       	jmp    0xabd60e
  abd8a8:	f6 86 44 02 00 00 02 	test   BYTE PTR [rsi+0x244],0x2
  abd8af:	41 bb 01 00 00 00    	mov    r11d,0x1
  abd8b5:	75 1e                	jne    0xabd8d5
  abd8b7:	45 31 db             	xor    r11d,r11d
  abd8ba:	81 b9 d8 05 00 00 00 	cmp    DWORD PTR [rcx+0x5d8],0x1500000
  abd8c1:	00 50 01 
  abd8c4:	41 83 d3 01          	adc    r11d,0x1
  abd8c8:	eb 0b                	jmp    0xabd8d5
  abd8ca:	41 c1 fb 10          	sar    r11d,0x10
  abd8ce:	41 81 e3 00 ff ff ff 	and    r11d,0xffffff00
  abd8d5:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  abd8d9:	8b 89 c4 05 00 00    	mov    ecx,DWORD PTR [rcx+0x5c4]
  abd8df:	48 83 ec 08          	sub    rsp,0x8
  abd8e3:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  abd8e7:	4c 8b 45 a8          	mov    r8,QWORD PTR [rbp-0x58]
  abd8eb:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  abd8ef:	48 89 df             	mov    rdi,rbx
  abd8f2:	6a 00                	push   0x0
  abd8f4:	50                   	push   rax
  abd8f5:	ff 75 a0             	push   QWORD PTR [rbp-0x60]
  abd8f8:	41 53                	push   r11
  abd8fa:	41 52                	push   r10
  abd8fc:	41 55                	push   r13
  abd8fe:	ff 75 b8             	push   QWORD PTR [rbp-0x48]
  abd901:	e8 4a db 90 ff       	call   0x3cb450
  abd906:	48 83 c4 40          	add    rsp,0x40
  abd90a:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
  abd90e:	89 c1                	mov    ecx,eax
  abd910:	48 89 93 08 04 00 00 	mov    QWORD PTR [rbx+0x408],rdx
  abd917:	e9 f2 fc ff ff       	jmp    0xabd60e
  abd91c:	e8 8f fd c3 ff       	call   0x6fd6b0
  abd921:	0f 0b                	ud2
  abd923:	90                   	nop
  abd924:	90                   	nop
  abd925:	90                   	nop
  abd926:	90                   	nop
  abd927:	90                   	nop
  abd928:	90                   	nop
  abd929:	90                   	nop
  abd92a:	90                   	nop
  abd92b:	90                   	nop
  abd92c:	90                   	nop
  abd92d:	90                   	nop
  abd92e:	90                   	nop
  abd92f:	90                   	nop
  abd930:	55                   	push   rbp
  abd931:	48 89 e5             	mov    rbp,rsp
  abd934:	41 57                	push   r15
  abd936:	41 56                	push   r14
  abd938:	41 55                	push   r13
  abd93a:	41 54                	push   r12
  abd93c:	53                   	push   rbx
  abd93d:	50                   	push   rax
  abd93e:	48 83 7e 08 11       	cmp    QWORD PTR [rsi+0x8],0x11
  abd943:	41 be 16 00 00 00    	mov    r14d,0x16
  abd949:	0f 8c 31 01 00 00    	jl     0xabda80
  abd94f:	8b 06                	mov    eax,DWORD PTR [rsi]
  abd951:	49 89 f5             	mov    r13,rsi
  abd954:	85 c0                	test   eax,eax
  abd956:	74 19                	je     0xabd971
  abd958:	65 48 8b 0c 25 00 00 	mov    rcx,QWORD PTR gs:0x0
  abd95f:	00 00 
  abd961:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  abd965:	3b 81 bc 00 00 00    	cmp    eax,DWORD PTR [rcx+0xbc]
  abd96b:	0f 85 21 01 00 00    	jne    0xabda92
  abd971:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  abd978:	00 00 
  abd97a:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
  abd97e:	31 f6                	xor    esi,esi
  abd980:	31 d2                	xor    edx,edx
  abd982:	31 c9                	xor    ecx,ecx
  abd984:	48 8d bb 48 01 00 00 	lea    rdi,[rbx+0x148]
  abd98b:	e8 70 90 a0 ff       	call   0x4c6a00
  abd990:	8b 83 b0 00 00 00    	mov    eax,DWORD PTR [rbx+0xb0]
  abd996:	a9 00 22 00 00       	test   eax,0x2200
  abd99b:	0f 85 c1 00 00 00    	jne    0xabda62
  abd9a1:	83 bb b8 00 00 00 01 	cmp    DWORD PTR [rbx+0xb8],0x1
  abd9a8:	0f 85 b4 00 00 00    	jne    0xabda62
  abd9ae:	ff 83 58 03 00 00    	inc    DWORD PTR [rbx+0x358]
  abd9b4:	a9 00 00 00 10       	test   eax,0x10000000
  abd9b9:	75 08                	jne    0xabd9c3
  abd9bb:	48 89 df             	mov    rdi,rbx
  abd9be:	e8 4d d0 a7 ff       	call   0x53aa10
  abd9c3:	4c 8d bb 48 01 00 00 	lea    r15,[rbx+0x148]
  abd9ca:	45 31 f6             	xor    r14d,r14d
  abd9cd:	31 f6                	xor    esi,esi
  abd9cf:	31 d2                	xor    edx,edx
  abd9d1:	31 c9                	xor    ecx,ecx
  abd9d3:	4c 89 ff             	mov    rdi,r15
  abd9d6:	e8 c5 95 a0 ff       	call   0x4c6fa0
  abd9db:	4c 8b a3 00 02 00 00 	mov    r12,QWORD PTR [rbx+0x200]
  abd9e2:	4d 85 e4             	test   r12,r12
  abd9e5:	74 3a                	je     0xabda21
  abd9e7:	49 8d bc 24 78 02 00 	lea    rdi,[r12+0x278]
  abd9ee:	00 
  abd9ef:	31 f6                	xor    esi,esi
  abd9f1:	31 d2                	xor    edx,edx
  abd9f3:	31 c9                	xor    ecx,ecx
  abd9f5:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  abd9f9:	e8 02 90 a0 ff       	call   0x4c6a00
  abd9fe:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  abda02:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  abda06:	31 f6                	xor    esi,esi
  abda08:	31 d2                	xor    edx,edx
  abda0a:	31 c9                	xor    ecx,ecx
  abda0c:	49 89 84 24 80 02 00 	mov    QWORD PTR [r12+0x280],rax
  abda13:	00 
  abda14:	e8 87 95 a0 ff       	call   0x4c6fa0
  abda19:	4c 89 e7             	mov    rdi,r12
  abda1c:	e8 4f 42 bd ff       	call   0x691c70
  abda21:	4c 89 ff             	mov    rdi,r15
  abda24:	31 f6                	xor    esi,esi
  abda26:	31 d2                	xor    edx,edx
  abda28:	31 c9                	xor    ecx,ecx
  abda2a:	e8 d1 8f a0 ff       	call   0x4c6a00
  abda2f:	0f b6 8b b1 00 00 00 	movzx  ecx,BYTE PTR [rbx+0xb1]
  abda36:	8b 83 58 03 00 00    	mov    eax,DWORD PTR [rbx+0x358]
  abda3c:	c0 e9 05             	shr    cl,0x5
  abda3f:	ff c8                	dec    eax
  abda41:	0f 94 c2             	sete   dl
  abda44:	89 83 58 03 00 00    	mov    DWORD PTR [rbx+0x358],eax
  abda4a:	20 ca                	and    dl,cl
  abda4c:	80 fa 01             	cmp    dl,0x1
  abda4f:	75 21                	jne    0xabda72
  abda51:	48 81 c3 58 03 00 00 	add    rbx,0x358
  abda58:	48 89 df             	mov    rdi,rbx
  abda5b:	e8 b0 8e 14 00       	call   0xc06910
  abda60:	eb 10                	jmp    0xabda72
  abda62:	48 81 c3 48 01 00 00 	add    rbx,0x148
  abda69:	41 be 03 00 00 00    	mov    r14d,0x3
  abda6f:	49 89 df             	mov    r15,rbx
  abda72:	4c 89 ff             	mov    rdi,r15
  abda75:	31 f6                	xor    esi,esi
  abda77:	31 d2                	xor    edx,edx
  abda79:	31 c9                	xor    ecx,ecx
  abda7b:	e8 20 95 a0 ff       	call   0x4c6fa0
  abda80:	44 89 f0             	mov    eax,r14d
  abda83:	48 83 c4 08          	add    rsp,0x8
  abda87:	5b                   	pop    rbx
  abda88:	41 5c                	pop    r12
  abda8a:	41 5d                	pop    r13
  abda8c:	41 5e                	pop    r14
  abda8e:	41 5f                	pop    r15
  abda90:	5d                   	pop    rbp
  abda91:	c3                   	ret
  abda92:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abda99:	e8 f2 b4 b4 ff       	call   0x608f90
  abda9e:	85 c0                	test   eax,eax
  abdaa0:	74 1d                	je     0xabdabf
  abdaa2:	41 8b 7d 00          	mov    edi,DWORD PTR [r13+0x0]
  abdaa6:	e8 c5 e6 a7 ff       	call   0x53c170
  abdaab:	48 89 c3             	mov    rbx,rax
  abdaae:	48 85 c0             	test   rax,rax
  abdab1:	0f 85 d9 fe ff ff    	jne    0xabd990
  abdab7:	41 be 03 00 00 00    	mov    r14d,0x3
  abdabd:	eb c1                	jmp    0xabda80
  abdabf:	41 be 01 00 00 00    	mov    r14d,0x1
  abdac5:	eb b9                	jmp    0xabda80
  abdac7:	90                   	nop
  abdac8:	90                   	nop
  abdac9:	90                   	nop
  abdaca:	90                   	nop
  abdacb:	90                   	nop
  abdacc:	90                   	nop
  abdacd:	90                   	nop
  abdace:	90                   	nop
  abdacf:	90                   	nop
  abdad0:	55                   	push   rbp
  abdad1:	48 89 e5             	mov    rbp,rsp
  abdad4:	41 57                	push   r15
  abdad6:	41 56                	push   r14
  abdad8:	41 55                	push   r13
  abdada:	41 54                	push   r12
  abdadc:	53                   	push   rbx
  abdadd:	48 81 ec c8 00 00 00 	sub    rsp,0xc8
  abdae4:	48 8d 1d 25 e8 e5 02 	lea    rbx,[rip+0x2e5e825]        # 0x391c310
  abdaeb:	49 89 f6             	mov    r14,rsi
  abdaee:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  abdaf1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  abdaf5:	48 8b bf 40 01 00 00 	mov    rdi,QWORD PTR [rdi+0x140]
  abdafc:	e8 8f b4 b4 ff       	call   0x608f90
  abdb01:	85 c0                	test   eax,eax
  abdb03:	0f 84 73 06 00 00    	je     0xabe17c
  abdb09:	41 8b 3e             	mov    edi,DWORD PTR [r14]
  abdb0c:	e8 5f e6 a7 ff       	call   0x53c170
  abdb11:	48 89 c1             	mov    rcx,rax
  abdb14:	b8 02 00 00 00       	mov    eax,0x2
  abdb19:	48 85 c9             	test   rcx,rcx
  abdb1c:	0f 84 7b 06 00 00    	je     0xabe19d
  abdb22:	8b 81 b0 00 00 00    	mov    eax,DWORD PTR [rcx+0xb0]
  abdb28:	a9 00 20 00 00       	test   eax,0x2000
  abdb2d:	0f 85 50 06 00 00    	jne    0xabe183
  abdb33:	ff 81 58 03 00 00    	inc    DWORD PTR [rcx+0x358]
  abdb39:	4c 89 b5 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],r14
  abdb40:	48 89 8d 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],rcx
  abdb47:	a9 00 00 00 10       	test   eax,0x10000000
  abdb4c:	75 13                	jne    0xabdb61
  abdb4e:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  abdb55:	e8 b6 ce a7 ff       	call   0x53aa10
  abdb5a:	48 8b 8d 50 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xb0]
  abdb61:	48 8d b9 48 01 00 00 	lea    rdi,[rcx+0x148]
  abdb68:	48 89 cb             	mov    rbx,rcx
  abdb6b:	31 f6                	xor    esi,esi
  abdb6d:	31 d2                	xor    edx,edx
  abdb6f:	31 c9                	xor    ecx,ecx
  abdb71:	48 89 bd 20 ff ff ff 	mov    QWORD PTR [rbp-0xe0],rdi
  abdb78:	e8 23 94 a0 ff       	call   0x4c6fa0
  abdb7d:	4c 8b ab 00 02 00 00 	mov    r13,QWORD PTR [rbx+0x200]
  abdb84:	31 f6                	xor    esi,esi
  abdb86:	31 d2                	xor    edx,edx
  abdb88:	4c 89 ef             	mov    rdi,r13
  abdb8b:	e8 90 8c 80 ff       	call   0x2c6820
  abdb90:	48 8d bd 68 ff ff ff 	lea    rdi,[rbp-0x98]
  abdb97:	be 68 00 00 00       	mov    esi,0x68
  abdb9c:	c7 85 64 ff ff ff 00 	mov    DWORD PTR [rbp-0x9c],0x0
  abdba3:	00 00 00 
  abdba6:	e8 45 b4 79 ff       	call   0x258ff0
  abdbab:	4d 8b 7d 08          	mov    r15,QWORD PTR [r13+0x8]
  abdbaf:	4d 39 ef             	cmp    r15,r13
  abdbb2:	0f 84 08 05 00 00    	je     0xabe0c0
  abdbb8:	4c 89 ad 18 ff ff ff 	mov    QWORD PTR [rbp-0xe8],r13
  abdbbf:	eb 1c                	jmp    0xabdbdd
  abdbc1:	41 ff c6             	inc    r14d
  abdbc4:	44 89 b5 64 ff ff ff 	mov    DWORD PTR [rbp-0x9c],r14d
  abdbcb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  abdbd0:	4d 8b 7f 08          	mov    r15,QWORD PTR [r15+0x8]
  abdbd4:	4d 39 ef             	cmp    r15,r13
  abdbd7:	0f 84 e3 04 00 00    	je     0xabe0c0
  abdbdd:	66 41 83 7f 66 00    	cmp    WORD PTR [r15+0x66],0x0
  abdbe3:	74 eb                	je     0xabdbd0
  abdbe5:	41 f6 47 60 02       	test   BYTE PTR [r15+0x60],0x2
  abdbea:	75 e4                	jne    0xabdbd0
  abdbec:	41 0f b7 47 64       	movzx  eax,WORD PTR [r15+0x64]
  abdbf1:	49 8b 5f 50          	mov    rbx,QWORD PTR [r15+0x50]
  abdbf5:	89 45 a0             	mov    DWORD PTR [rbp-0x60],eax
  abdbf8:	41 8b 4f 60          	mov    ecx,DWORD PTR [r15+0x60]
  abdbfc:	f6 c1 20             	test   cl,0x20
  abdbff:	74 0c                	je     0xabdc0d
  abdc01:	0d 00 00 01 00       	or     eax,0x10000
  abdc06:	89 45 a0             	mov    DWORD PTR [rbp-0x60],eax
  abdc09:	41 8b 4f 60          	mov    ecx,DWORD PTR [r15+0x60]
  abdc0d:	f7 c1 00 10 00 00    	test   ecx,0x1000
  abdc13:	74 08                	je     0xabdc1d
  abdc15:	0d 00 00 02 00       	or     eax,0x20000
  abdc1a:	89 45 a0             	mov    DWORD PTR [rbp-0x60],eax
  abdc1d:	49 8b 47 20          	mov    rax,QWORD PTR [r15+0x20]
  abdc21:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  abdc25:	49 8b 47 28          	mov    rax,QWORD PTR [r15+0x28]
  abdc29:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  abdc2d:	48 85 db             	test   rbx,rbx
  abdc30:	74 1f                	je     0xabdc51
  abdc32:	0f b6 83 9d 00 00 00 	movzx  eax,BYTE PTR [rbx+0x9d]
  abdc39:	83 f8 0a             	cmp    eax,0xa
  abdc3c:	77 25                	ja     0xabdc63
  abdc3e:	b9 87 05 00 00       	mov    ecx,0x587
  abdc43:	0f a3 c1             	bt     ecx,eax
  abdc46:	73 1b                	jae    0xabdc63
  abdc48:	f6 83 a2 00 00 00 01 	test   BYTE PTR [rbx+0xa2],0x1
  abdc4f:	75 12                	jne    0xabdc63
  abdc51:	66 41 83 7f 66 00    	cmp    WORD PTR [r15+0x66],0x0
  abdc57:	74 13                	je     0xabdc6c
  abdc59:	41 0f be 87 4c 01 00 	movsx  eax,BYTE PTR [r15+0x14c]
  abdc60:	00 
  abdc61:	eb 0b                	jmp    0xabdc6e
  abdc63:	c7 45 cc 00 00 00 00 	mov    DWORD PTR [rbp-0x34],0x0
  abdc6a:	eb 0e                	jmp    0xabdc7a
  abdc6c:	31 c0                	xor    eax,eax
  abdc6e:	89 45 cc             	mov    DWORD PTR [rbp-0x34],eax
  abdc71:	48 85 db             	test   rbx,rbx
  abdc74:	0f 84 b0 03 00 00    	je     0xabe02a
  abdc7a:	4c 8d 63 18          	lea    r12,[rbx+0x18]
  abdc7e:	31 f6                	xor    esi,esi
  abdc80:	31 d2                	xor    edx,edx
  abdc82:	4c 89 e7             	mov    rdi,r12
  abdc85:	e8 16 6a d1 ff       	call   0x7d46a0
  abdc8a:	0f b6 83 9d 00 00 00 	movzx  eax,BYTE PTR [rbx+0x9d]
  abdc91:	04 fd                	add    al,0xfd
  abdc93:	3c 02                	cmp    al,0x2
  abdc95:	73 11                	jae    0xabdca8
  abdc97:	4c 89 e7             	mov    rdi,r12
  abdc9a:	31 f6                	xor    esi,esi
  abdc9c:	31 d2                	xor    edx,edx
  abdc9e:	e8 0d 72 d1 ff       	call   0x7d4eb0
  abdca3:	e9 28 ff ff ff       	jmp    0xabdbd0
  abdca8:	8b 83 30 01 00 00    	mov    eax,DWORD PTR [rbx+0x130]
  abdcae:	4c 89 e7             	mov    rdi,r12
  abdcb1:	48 89 9d 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],rbx
  abdcb8:	31 f6                	xor    esi,esi
  abdcba:	31 d2                	xor    edx,edx
  abdcbc:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
  abdcbf:	8b 83 38 01 00 00    	mov    eax,DWORD PTR [rbx+0x138]
  abdcc5:	31 db                	xor    ebx,ebx
  abdcc7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
  abdcca:	e8 e1 71 d1 ff       	call   0x7d4eb0
  abdccf:	4d 8b 77 20          	mov    r14,QWORD PTR [r15+0x20]
  abdcd3:	4c 89 bd 40 ff ff ff 	mov    QWORD PTR [rbp-0xc0],r15
  abdcda:	4d 8b 7f 28          	mov    r15,QWORD PTR [r15+0x28]
  abdcde:	48 c7 c0 00 c0 ff ff 	mov    rax,0xffffffffffffc000
  abdce5:	49 21 c6             	and    r14,rax
  abdce8:	b8 ff 3f 00 00       	mov    eax,0x3fff
  abdced:	49 01 c7             	add    r15,rax
  abdcf0:	49 81 e7 00 c0 ff ff 	and    r15,0xffffffffffffc000
  abdcf7:	4d 39 fe             	cmp    r14,r15
  abdcfa:	73 26                	jae    0xabdd22
  abdcfc:	31 db                	xor    ebx,ebx
  abdcfe:	66 90                	xchg   ax,ax
  abdd00:	49 8b bd d8 01 00 00 	mov    rdi,QWORD PTR [r13+0x1d8]
  abdd07:	4c 89 f6             	mov    rsi,r14
  abdd0a:	e8 d1 06 e2 ff       	call   0x8de3e0
  abdd0f:	48 83 f8 01          	cmp    rax,0x1
  abdd13:	83 db ff             	sbb    ebx,0xffffffff
  abdd16:	49 81 c6 00 40 00 00 	add    r14,0x4000
  abdd1d:	4d 39 fe             	cmp    r14,r15
  abdd20:	72 de                	jb     0xabdd00
  abdd22:	89 5d ac             	mov    DWORD PTR [rbp-0x54],ebx
  abdd25:	48 8b 9d 30 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xd0]
  abdd2c:	48 8d 0d e5 90 13 03 	lea    rcx,[rip+0x31390e5]        # 0x3bf6e18
  abdd33:	4c 8b bd 40 ff ff ff 	mov    r15,QWORD PTR [rbp-0xc0]
  abdd3a:	89 d8                	mov    eax,ebx
  abdd3c:	31 c8                	xor    eax,ecx
  abdd3e:	48 98                	cdqe
  abdd40:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  abdd44:	0f b6 83 9d 00 00 00 	movzx  eax,BYTE PTR [rbx+0x9d]
  abdd4b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
  abdd4e:	49 8b 47 28          	mov    rax,QWORD PTR [r15+0x28]
  abdd52:	49 2b 47 20          	sub    rax,QWORD PTR [r15+0x20]
  abdd56:	48 c7 45 b4 00 00 00 	mov    QWORD PTR [rbp-0x4c],0x0
  abdd5d:	00 
  abdd5e:	48 c7 45 bc 00 00 00 	mov    QWORD PTR [rbp-0x44],0x0
  abdd65:	00 
  abdd66:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
  abdd6d:	00 
  abdd6e:	48 c1 e8 0e          	shr    rax,0xe
  abdd72:	48 89 85 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rax
  abdd79:	85 c0                	test   eax,eax
  abdd7b:	0f 8e ba 02 00 00    	jle    0xabe03b
  abdd81:	48 8b 85 38 ff ff ff 	mov    rax,QWORD PTR [rbp-0xc8]
  abdd88:	4c 89 a5 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],r12
  abdd8f:	25 ff ff ff 7f       	and    eax,0x7fffffff
  abdd94:	48 89 85 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rax
  abdd9b:	31 c0                	xor    eax,eax
  abdd9d:	eb 39                	jmp    0xabddd8
  abdd9f:	90                   	nop
  abdda0:	ff 45 c8             	inc    DWORD PTR [rbp-0x38]
  abdda3:	4c 8b a5 58 ff ff ff 	mov    r12,QWORD PTR [rbp-0xa8]
  abddaa:	48 83 c3 18          	add    rbx,0x18
  abddae:	31 f6                	xor    esi,esi
  abddb0:	31 d2                	xor    edx,edx
  abddb2:	48 89 df             	mov    rdi,rbx
  abddb5:	e8 f6 70 d1 ff       	call   0x7d4eb0
  abddba:	48 8b 85 10 ff ff ff 	mov    rax,QWORD PTR [rbp-0xf0]
  abddc1:	48 8b 9d 30 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xd0]
  abddc8:	48 ff c0             	inc    rax
  abddcb:	48 3b 85 38 ff ff ff 	cmp    rax,QWORD PTR [rbp-0xc8]
  abddd2:	0f 84 63 02 00 00    	je     0xabe03b
  abddd8:	4d 8b 7f 58          	mov    r15,QWORD PTR [r15+0x58]
  abdddc:	48 89 85 10 ff ff ff 	mov    QWORD PTR [rbp-0xf0],rax
  abdde3:	c1 e0 0e             	shl    eax,0xe
  abdde6:	4c 89 e7             	mov    rdi,r12
  abdde9:	31 f6                	xor    esi,esi
  abddeb:	31 d2                	xor    edx,edx
  abdded:	4c 63 e8             	movsxd r13,eax
  abddf0:	e8 ab 68 d1 ff       	call   0x7d46a0
  abddf5:	4f 8d 34 2f          	lea    r14,[r15+r13*1]
  abddf9:	48 89 df             	mov    rdi,rbx
  abddfc:	49 c1 fe 0e          	sar    r14,0xe
  abde00:	4c 89 f6             	mov    rsi,r14
  abde03:	e8 d8 b9 0c 00       	call   0xb897e0
  abde08:	48 85 c0             	test   rax,rax
  abde0b:	75 69                	jne    0xabde76
  abde0d:	4c 89 ad 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],r13
  abde14:	49 89 dd             	mov    r13,rbx
  abde17:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  abde1e:	00 00 
  abde20:	49 8b 9d b0 00 00 00 	mov    rbx,QWORD PTR [r13+0xb0]
  abde27:	48 85 db             	test   rbx,rbx
  abde2a:	0f 84 04 01 00 00    	je     0xabdf34
  abde30:	4d 03 bd b8 00 00 00 	add    r15,QWORD PTR [r13+0xb8]
  abde37:	48 8d 7b 18          	lea    rdi,[rbx+0x18]
  abde3b:	31 f6                	xor    esi,esi
  abde3d:	31 d2                	xor    edx,edx
  abde3f:	e8 5c 68 d1 ff       	call   0x7d46a0
  abde44:	49 83 c5 18          	add    r13,0x18
  abde48:	31 f6                	xor    esi,esi
  abde4a:	31 d2                	xor    edx,edx
  abde4c:	4c 89 ef             	mov    rdi,r13
  abde4f:	e8 5c 70 d1 ff       	call   0x7d4eb0
  abde54:	48 8b 85 28 ff ff ff 	mov    rax,QWORD PTR [rbp-0xd8]
  abde5b:	48 89 df             	mov    rdi,rbx
  abde5e:	4d 8d 34 07          	lea    r14,[r15+rax*1]
  abde62:	49 c1 fe 0e          	sar    r14,0xe
  abde66:	4c 89 f6             	mov    rsi,r14
  abde69:	e8 72 b9 0c 00       	call   0xb897e0
  abde6e:	49 89 dd             	mov    r13,rbx
  abde71:	48 85 c0             	test   rax,rax
  abde74:	74 aa                	je     0xabde20
  abde76:	48 89 c7             	mov    rdi,rax
  abde79:	49 89 c4             	mov    r12,rax
  abde7c:	e8 1f fa 0c 00       	call   0xb8d8a0
  abde81:	41 83 7c 24 70 00    	cmp    DWORD PTR [r12+0x70],0x0
  abde87:	4c 8b bd 40 ff ff ff 	mov    r15,QWORD PTR [rbp-0xc0]
  abde8e:	0f 84 8c 00 00 00    	je     0xabdf20
  abde94:	ff 45 bc             	inc    DWORD PTR [rbp-0x44]
  abde97:	41 80 7c 24 66 01    	cmp    BYTE PTR [r12+0x66],0x1
  abde9d:	75 03                	jne    0xabdea2
  abde9f:	ff 45 c4             	inc    DWORD PTR [rbp-0x3c]
  abdea2:	41 83 7c 24 70 00    	cmp    DWORD PTR [r12+0x70],0x0
  abdea8:	0f 85 f5 fe ff ff    	jne    0xabdda3
  abdeae:	49 8b 44 24 20       	mov    rax,QWORD PTR [r12+0x20]
  abdeb3:	48 85 c0             	test   rax,rax
  abdeb6:	0f 84 e4 fe ff ff    	je     0xabdda0
  abdebc:	80 b8 9d 00 00 00 00 	cmp    BYTE PTR [rax+0x9d],0x0
  abdec3:	0f 84 d7 fe ff ff    	je     0xabdda0
  abdec9:	80 bb 9d 00 00 00 01 	cmp    BYTE PTR [rbx+0x9d],0x1
  abded0:	0f 85 cd fe ff ff    	jne    0xabdda3
  abded6:	48 8d 05 33 5a 00 01 	lea    rax,[rip+0x1005a33]        # 0x1ac3910
  abdedd:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abdee1:	4c 8b 60 38          	mov    r12,QWORD PTR [rax+0x38]
  abdee5:	48 8d 05 5c d9 7a ff 	lea    rax,[rip+0xffffffffff7ad95c]        # 0x26b848
  abdeec:	4c 29 e0             	sub    rax,r12
  abdeef:	48 c1 c8 03          	ror    rax,0x3
  abdef3:	48 83 f8 0d          	cmp    rax,0xd
  abdef7:	0f 87 19 01 00 00    	ja     0xabe016
  abdefd:	48 89 df             	mov    rdi,rbx
  abdf00:	4c 89 f6             	mov    rsi,r14
  abdf03:	31 d2                	xor    edx,edx
  abdf05:	31 c9                	xor    ecx,ecx
  abdf07:	41 ff d4             	call   r12
  abdf0a:	85 c0                	test   eax,eax
  abdf0c:	0f 85 91 fe ff ff    	jne    0xabdda3
  abdf12:	e9 89 fe ff ff       	jmp    0xabdda0
  abdf17:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  abdf1e:	00 00 
  abdf20:	ff 45 c0             	inc    DWORD PTR [rbp-0x40]
  abdf23:	41 80 7c 24 66 01    	cmp    BYTE PTR [r12+0x66],0x1
  abdf29:	0f 84 70 ff ff ff    	je     0xabde9f
  abdf2f:	e9 6e ff ff ff       	jmp    0xabdea2
  abdf34:	49 83 c5 18          	add    r13,0x18
  abdf38:	31 f6                	xor    esi,esi
  abdf3a:	31 d2                	xor    edx,edx
  abdf3c:	4c 89 ef             	mov    rdi,r13
  abdf3f:	e8 6c 6f d1 ff       	call   0x7d4eb0
  abdf44:	4c 8b bd 40 ff ff ff 	mov    r15,QWORD PTR [rbp-0xc0]
  abdf4b:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  abdf52:	31 f6                	xor    esi,esi
  abdf54:	31 d2                	xor    edx,edx
  abdf56:	4d 8b 67 58          	mov    r12,QWORD PTR [r15+0x58]
  abdf5a:	e8 41 67 d1 ff       	call   0x7d46a0
  abdf5f:	48 8b 9d 30 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xd0]
  abdf66:	80 bb 9d 00 00 00 01 	cmp    BYTE PTR [rbx+0x9d],0x1
  abdf6d:	75 41                	jne    0xabdfb0
  abdf6f:	90                   	nop
  abdf70:	48 8d 05 99 59 00 01 	lea    rax,[rip+0x1005999]        # 0x1ac3910
  abdf77:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  abdf7b:	4c 8b 70 38          	mov    r14,QWORD PTR [rax+0x38]
  abdf7f:	48 8d 05 c2 d8 7a ff 	lea    rax,[rip+0xffffffffff7ad8c2]        # 0x26b848
  abdf86:	4c 29 f0             	sub    rax,r14
  abdf89:	48 c1 c8 03          	ror    rax,0x3
  abdf8d:	48 83 f8 0d          	cmp    rax,0xd
  abdf91:	48 8b 85 28 ff ff ff 	mov    rax,QWORD PTR [rbp-0xd8]
  abdf98:	77 54                	ja     0xabdfee
  abdf9a:	49 8d 34 04          	lea    rsi,[r12+rax*1]
  abdf9e:	48 89 df             	mov    rdi,rbx
  abdfa1:	31 d2                	xor    edx,edx
  abdfa3:	31 c9                	xor    ecx,ecx
  abdfa5:	48 c1 fe 0e          	sar    rsi,0xe
  abdfa9:	41 ff d6             	call   r14
  abdfac:	85 c0                	test   eax,eax
  abdfae:	75 5e                	jne    0xabe00e
  abdfb0:	4c 8b b3 b0 00 00 00 	mov    r14,QWORD PTR [rbx+0xb0]
  abdfb7:	4d 85 f6             	test   r14,r14
  abdfba:	74 4a                	je     0xabe006
  abdfbc:	4c 03 a3 b8 00 00 00 	add    r12,QWORD PTR [rbx+0xb8]
  abdfc3:	49 8d 7e 18          	lea    rdi,[r14+0x18]
  abdfc7:	31 f6                	xor    esi,esi
  abdfc9:	31 d2                	xor    edx,edx
  abdfcb:	e8 d0 66 d1 ff       	call   0x7d46a0
  abdfd0:	48 83 c3 18          	add    rbx,0x18
  abdfd4:	31 f6                	xor    esi,esi
  abdfd6:	31 d2                	xor    edx,edx
  abdfd8:	48 89 df             	mov    rdi,rbx
  abdfdb:	e8 d0 6e d1 ff       	call   0x7d4eb0
  abdfe0:	4c 89 f3             	mov    rbx,r14
  abdfe3:	80 bb 9d 00 00 00 01 	cmp    BYTE PTR [rbx+0x9d],0x1
  abdfea:	74 84                	je     0xabdf70
  abdfec:	eb c2                	jmp    0xabdfb0
  abdfee:	48 8d 3d 6b ad dc 01 	lea    rdi,[rip+0x1dcad6b]        # 0x2888d60
  abdff5:	4c 89 f6             	mov    rsi,r14
  abdff8:	e8 c3 18 99 ff       	call   0x44f8c0
  abdffd:	48 8b 85 28 ff ff ff 	mov    rax,QWORD PTR [rbp-0xd8]
  abe004:	eb 94                	jmp    0xabdf9a
  abe006:	ff 45 b4             	inc    DWORD PTR [rbp-0x4c]
  abe009:	e9 95 fd ff ff       	jmp    0xabdda3
  abe00e:	ff 45 b8             	inc    DWORD PTR [rbp-0x48]
  abe011:	e9 8d fd ff ff       	jmp    0xabdda3
  abe016:	48 8d 3d 43 ad dc 01 	lea    rdi,[rip+0x1dcad43]        # 0x2888d60
  abe01d:	4c 89 e6             	mov    rsi,r12
  abe020:	e8 9b 18 99 ff       	call   0x44f8c0
  abe025:	e9 d3 fe ff ff       	jmp    0xabdefd
  abe02a:	be 68 00 00 00       	mov    esi,0x68
  abe02f:	48 8d bd 68 ff ff ff 	lea    rdi,[rbp-0x98]
  abe036:	e8 b5 af 79 ff       	call   0x258ff0
  abe03b:	49 8d b7 50 01 00 00 	lea    rsi,[r15+0x150]
  abe042:	ba 20 00 00 00       	mov    edx,0x20
  abe047:	48 8d bd 68 ff ff ff 	lea    rdi,[rbp-0x98]
  abe04e:	e8 1d 9b e9 ff       	call   0x957b70
  abe053:	48 8b 85 48 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb8]
  abe05a:	4c 63 b5 64 ff ff ff 	movsxd r14,DWORD PTR [rbp-0x9c]
  abe061:	4c 8b ad 18 ff ff ff 	mov    r13,QWORD PTR [rbp-0xe8]
  abe068:	48 8b 58 10          	mov    rbx,QWORD PTR [rax+0x10]
  abe06c:	48 85 db             	test   rbx,rbx
  abe06f:	0f 84 4c fb ff ff    	je     0xabdbc1
  abe075:	48 8b 85 48 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb8]
  abe07c:	44 3b 70 08          	cmp    r14d,DWORD PTR [rax+0x8]
  abe080:	0f 8d 3b fb ff ff    	jge    0xabdbc1
  abe086:	49 6b c6 68          	imul   rax,r14,0x68
  abe08a:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abe091:	00 00 
  abe093:	48 8d 35 fd 11 89 00 	lea    rsi,[rip+0x8911fd]        # 0x134f297
  abe09a:	31 d2                	xor    edx,edx
  abe09c:	48 01 c3             	add    rbx,rax
  abe09f:	e8 3c c3 15 00       	call   0xc1a3e0
  abe0a4:	ba 68 00 00 00       	mov    edx,0x68
  abe0a9:	48 8d bd 68 ff ff ff 	lea    rdi,[rbp-0x98]
  abe0b0:	48 89 de             	mov    rsi,rbx
  abe0b3:	e8 18 b1 79 ff       	call   0x2591d0
  abe0b8:	85 c0                	test   eax,eax
  abe0ba:	0f 84 01 fb ff ff    	je     0xabdbc1
  abe0c0:	4c 89 ef             	mov    rdi,r13
  abe0c3:	31 f6                	xor    esi,esi
  abe0c5:	31 d2                	xor    edx,edx
  abe0c7:	e8 a4 87 80 ff       	call   0x2c6870
  abe0cc:	48 8b 9d 20 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xe0]
  abe0d3:	31 f6                	xor    esi,esi
  abe0d5:	31 d2                	xor    edx,edx
  abe0d7:	31 c9                	xor    ecx,ecx
  abe0d9:	48 89 df             	mov    rdi,rbx
  abe0dc:	e8 1f 89 a0 ff       	call   0x4c6a00
  abe0e1:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  abe0e8:	0f b6 8f b1 00 00 00 	movzx  ecx,BYTE PTR [rdi+0xb1]
  abe0ef:	8b 87 58 03 00 00    	mov    eax,DWORD PTR [rdi+0x358]
  abe0f5:	c0 e9 05             	shr    cl,0x5
  abe0f8:	ff c8                	dec    eax
  abe0fa:	0f 94 c2             	sete   dl
  abe0fd:	89 87 58 03 00 00    	mov    DWORD PTR [rdi+0x358],eax
  abe103:	20 ca                	and    dl,cl
  abe105:	80 fa 01             	cmp    dl,0x1
  abe108:	75 0c                	jne    0xabe116
  abe10a:	48 81 c7 58 03 00 00 	add    rdi,0x358
  abe111:	e8 fa 87 14 00       	call   0xc06910
  abe116:	48 89 df             	mov    rdi,rbx
  abe119:	31 f6                	xor    esi,esi
  abe11b:	31 d2                	xor    edx,edx
  abe11d:	31 c9                	xor    ecx,ecx
  abe11f:	e8 7c 8e a0 ff       	call   0x4c6fa0
  abe124:	4c 8b b5 48 ff ff ff 	mov    r14,QWORD PTR [rbp-0xb8]
  abe12b:	48 8d 35 65 11 89 00 	lea    rsi,[rip+0x891165]        # 0x134f297
  abe132:	31 d2                	xor    edx,edx
  abe134:	49 8b 5e 18          	mov    rbx,QWORD PTR [r14+0x18]
  abe138:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  abe13f:	00 00 
  abe141:	e8 9a c2 15 00       	call   0xc1a3e0
  abe146:	48 8d bd 64 ff ff ff 	lea    rdi,[rbp-0x9c]
  abe14d:	ba 04 00 00 00       	mov    edx,0x4
  abe152:	48 89 de             	mov    rsi,rbx
  abe155:	e8 76 b0 79 ff       	call   0x2591d0
  abe15a:	49 83 7e 10 00       	cmp    QWORD PTR [r14+0x10],0x0
  abe15f:	74 12                	je     0xabe173
  abe161:	8b 8d 64 ff ff ff    	mov    ecx,DWORD PTR [rbp-0x9c]
  abe167:	41 3b 4e 08          	cmp    ecx,DWORD PTR [r14+0x8]
  abe16b:	b9 0c 00 00 00       	mov    ecx,0xc
  abe170:	0f 4f c1             	cmovg  eax,ecx
  abe173:	48 8d 1d 96 e1 e5 02 	lea    rbx,[rip+0x2e5e196]        # 0x391c310
  abe17a:	eb 21                	jmp    0xabe19d
  abe17c:	b8 01 00 00 00       	mov    eax,0x1
  abe181:	eb 1a                	jmp    0xabe19d
  abe183:	48 81 c1 48 01 00 00 	add    rcx,0x148
  abe18a:	31 f6                	xor    esi,esi
  abe18c:	31 d2                	xor    edx,edx
  abe18e:	48 89 cf             	mov    rdi,rcx
  abe191:	31 c9                	xor    ecx,ecx
  abe193:	e8 08 8e a0 ff       	call   0x4c6fa0
  abe198:	b8 02 00 00 00       	mov    eax,0x2
  abe19d:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
  abe1a0:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  abe1a4:	75 12                	jne    0xabe1b8
  abe1a6:	48 81 c4 c8 00 00 00 	add    rsp,0xc8
  abe1ad:	5b                   	pop    rbx
  abe1ae:	41 5c                	pop    r12
  abe1b0:	41 5d                	pop    r13
  abe1b2:	41 5e                	pop    r14
  abe1b4:	41 5f                	pop    r15
  abe1b6:	5d                   	pop    rbp
  abe1b7:	c3                   	ret
  abe1b8:	e8 f3 f4 c3 ff       	call   0x6fd6b0
  abe1bd:	0f 0b                	ud2
  abe1bf:	90                   	nop
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
  abf97f:	4c                   	rex.WR
