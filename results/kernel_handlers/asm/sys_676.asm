; Handler 676: REA6.7.0 / Ghidra12.1.4 static function-aware assembly.
; All addresses are kernel RVAs; runtime VA = 0xffffffff8a9c0000 + RVA.
; Original 4096-byte input SHA256 c939ff1fe660c65241cbd3bff95bf55fcc29969913e358b6bbc4749c71a13fc3.
; Actual target RVA 0x6f92e0; adjacent recovered functions are context.

; ===== REA full original-window trampoline functions and verified padding =====
; COMPLETE ORIGINAL INPUT WINDOW: handler_676.bin, 4096 bytes
; SHA256 c939ff1fe660c65241cbd3bff95bf55fcc29969913e358b6bbc4749c71a13fc3; file offset zero = kernel RVA 0x265fa8.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x0 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x8 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x10 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x18 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x20 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x28 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x30 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x38 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0x40 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0x48 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0x50 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0x58 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0x60 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0x68 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0x70 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0x78 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0x80 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0x88 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0x90 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0x98 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0xa0 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0xa8 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0xb0 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0xb8 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0xc0 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0xc8 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0xd0 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0xd8 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0xe0 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0xe8 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0xf0 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0xf8 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x100 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x108 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x110 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x118 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x120 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x128 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x130 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x138 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x140 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x148 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x150 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x158 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0x160 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0x168 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0x170 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0x178 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0x180 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0x188 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0x190 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0x198 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0x1a0 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0x1a8 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0x1b0 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0x1b8 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0x1c0 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0x1c8 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0x1d0 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0x1d8 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0x1e0 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0x1e8 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0x1f0 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0x1f8 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0x200 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0x208 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0x210 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0x218 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0x220 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0x228 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0x230 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0x238 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0x240 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0x248 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0x250 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0x258 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0x260 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0x268 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0x270 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0x278 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0x280 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0x288 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0x290 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0x298 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0x2a0 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0x2a8 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0x2b0 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0x2b8 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0x2c0 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0x2c8 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0x2d0 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0x2d8 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0x2e0 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0x2e8 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0x2f0 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0x2f8 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0x300 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0x308 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0x310 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0x318 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0x320 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0x328 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0x330 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0x338 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0x340 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0x348 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0x350 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0x358 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0x360 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0x368 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0x370 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0x378 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0x380 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0x388 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0x390 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0x398 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0x3a0 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0x3a8 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0x3b0 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0x3b8 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0x3c0 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0x3c8 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0x3d0 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0x3d8 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0x3e0 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0x3e8 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0x3f0 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0x3f8 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0x400 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0x408 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0x410 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0x418 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0x420 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0x428 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0x430 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0x438 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0x440 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0x448 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0x450 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0x458 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0x460 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0x468 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0x470 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0x478 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0x480 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0x488 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0x490 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0x498 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0x4a0 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0x4a8 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0x4b0 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0x4b8 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0x4c0 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0x4c8 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0x4d0 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0x4d8 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0x4e0 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0x4e8 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0x4f0 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0x4f8 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0x500 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0x508 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0x510 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0x518 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0x520 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0x528 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0x530 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0x538 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0x540 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0x548 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0x550 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0x558 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0x560 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0x568 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0x570 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0x578 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0x580 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0x588 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0x590 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0x598 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0x5a0 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0x5a8 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0x5b0 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0x5b8 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0x5c0 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0x5c8 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0x5d0 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0x5d8 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0x5e0 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0x5e8 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0x5f0 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0x5f8 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0x600 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0x608 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0x610 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0x618 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0x620 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0x628 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0x630 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0x638 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0x640 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0x648 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0x650 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0x658 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0x660 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0x668 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0x670 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0x678 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0x680 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0x688 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0x690 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0x698 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0x6a0 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0x6a8 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0x6b0 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0x6b8 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0x6c0 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0x6c8 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0x6d0 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0x6d8 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0x6e0 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0x6e8 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0x6f0 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0x6f8 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0x700 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0x708 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0x710 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0x718 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0x720 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0x728 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0x730 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0x738 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0x740 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0x748 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0x750 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0x758 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding

; FUNCTION thunk_266708 [0x266708, 0x26670c] | file +0x760 | ev_a1b1ecfb69ddcde3ab328e54879b2647bb27553f41929ae5021b46edd03a8fd6
thunk_266708:
0x266708: JMP 0x00ca7310
; END FUNCTION thunk_266708
0x26670d: INT3 ; original byte CC, padding
0x26670e: INT3 ; original byte CC, padding
0x26670f: INT3 ; original byte CC, padding

; FUNCTION thunk_266710 [0x266710, 0x266714] | file +0x768 | ev_91a5d5c52dbb1d6be7f635bc2e634aa41a9d00a7b8b5d2ae096ecbfdcbfa2641
thunk_266710:
0x266710: JMP 0x00662e70
; END FUNCTION thunk_266710
0x266715: INT3 ; original byte CC, padding
0x266716: INT3 ; original byte CC, padding
0x266717: INT3 ; original byte CC, padding

; FUNCTION thunk_266718 [0x266718, 0x26671c] | file +0x770 | ev_5d49490e833cb75f11ae327b52e57d63c8562abf36102eae069cd3b6103363e9
thunk_266718:
0x266718: JMP 0x00662e80
; END FUNCTION thunk_266718
0x26671d: INT3 ; original byte CC, padding
0x26671e: INT3 ; original byte CC, padding
0x26671f: INT3 ; original byte CC, padding

; FUNCTION thunk_266720 [0x266720, 0x266724] | file +0x778 | ev_1dbafec98e5478d51b8103829bfa1a72f4bc438e9f77ede71f00176b6c65fa7a
thunk_266720:
0x266720: JMP 0x00678e10
; END FUNCTION thunk_266720
0x266725: INT3 ; original byte CC, padding
0x266726: INT3 ; original byte CC, padding
0x266727: INT3 ; original byte CC, padding

; FUNCTION thunk_266728 [0x266728, 0x26672c] | file +0x780 | ev_38fac9adf6535b05ba585c6e1016cc470c98cfb56fa25e1502404b81f2326987
thunk_266728:
0x266728: JMP 0x00678e60
; END FUNCTION thunk_266728
0x26672d: INT3 ; original byte CC, padding
0x26672e: INT3 ; original byte CC, padding
0x26672f: INT3 ; original byte CC, padding

; FUNCTION thunk_266730 [0x266730, 0x266734] | file +0x788 | ev_890d87fa71c13e41992835bde9ad1d367d67a4a8cd4b5428bd46706c8a2a3c01
thunk_266730:
0x266730: JMP 0x00678ec0
; END FUNCTION thunk_266730
0x266735: INT3 ; original byte CC, padding
0x266736: INT3 ; original byte CC, padding
0x266737: INT3 ; original byte CC, padding

; FUNCTION thunk_266738 [0x266738, 0x26673c] | file +0x790 | ev_aa0a18be2618fe163ef3124d4793e4ee4faac93cc616ec748a395327ab897d78
thunk_266738:
0x266738: JMP 0x00678f60
; END FUNCTION thunk_266738
0x26673d: INT3 ; original byte CC, padding
0x26673e: INT3 ; original byte CC, padding
0x26673f: INT3 ; original byte CC, padding

; FUNCTION thunk_266740 [0x266740, 0x266744] | file +0x798 | ev_b940e85d2293130cc12912d0f406f051de5e7b6c738a54b3296b9ad18e7da334
thunk_266740:
0x266740: JMP 0x00679190
; END FUNCTION thunk_266740
0x266745: INT3 ; original byte CC, padding
0x266746: INT3 ; original byte CC, padding
0x266747: INT3 ; original byte CC, padding

; FUNCTION thunk_266748 [0x266748, 0x26674c] | file +0x7a0 | ev_2d90ddd75a522af0bb29971ceb6fb5ba61df5fe33fe120ca3b3e5d7785d2fb67
thunk_266748:
0x266748: JMP 0x00679360
; END FUNCTION thunk_266748
0x26674d: INT3 ; original byte CC, padding
0x26674e: INT3 ; original byte CC, padding
0x26674f: INT3 ; original byte CC, padding

; FUNCTION thunk_266750 [0x266750, 0x266754] | file +0x7a8 | ev_01b9ec000cc30925ba3559e6be67c9cb23e822ed3521b44b10cf40b142115d81
thunk_266750:
0x266750: JMP 0x00679680
; END FUNCTION thunk_266750
0x266755: INT3 ; original byte CC, padding
0x266756: INT3 ; original byte CC, padding
0x266757: INT3 ; original byte CC, padding

; FUNCTION thunk_266758 [0x266758, 0x26675c] | file +0x7b0 | ev_d990bd8c7113bb7f5350f7d2dd0da9a70e1e61ae3bdc2023b324d40d54fd0556
thunk_266758:
0x266758: JMP 0x00033b90
; END FUNCTION thunk_266758
0x26675d: INT3 ; original byte CC, padding
0x26675e: INT3 ; original byte CC, padding
0x26675f: INT3 ; original byte CC, padding

; FUNCTION thunk_266760 [0x266760, 0x266764] | file +0x7b8 | ev_9c2f05162ca519881e4051f776fb4d5698dc9a1dbb6d322ee6281af4ba5e8feb
thunk_266760:
0x266760: JMP 0x00033ca0
; END FUNCTION thunk_266760
0x266765: INT3 ; original byte CC, padding
0x266766: INT3 ; original byte CC, padding
0x266767: INT3 ; original byte CC, padding

; FUNCTION thunk_266768 [0x266768, 0x26676c] | file +0x7c0 | ev_8a1b5cf7031b91c6ae6c5ebe0fffd22f6fa2246fe2869a1a78fd5b400a6b359e
thunk_266768:
0x266768: JMP 0x00033d20
; END FUNCTION thunk_266768
0x26676d: INT3 ; original byte CC, padding
0x26676e: INT3 ; original byte CC, padding
0x26676f: INT3 ; original byte CC, padding

; FUNCTION thunk_266770 [0x266770, 0x266774] | file +0x7c8 | ev_1f25b3b15b6f767ce17fc6cd00f20709a3a70504cb1eab6250b3a9d8f5df543a
thunk_266770:
0x266770: JMP 0x0003cf70
; END FUNCTION thunk_266770
0x266775: INT3 ; original byte CC, padding
0x266776: INT3 ; original byte CC, padding
0x266777: INT3 ; original byte CC, padding

; FUNCTION thunk_266778 [0x266778, 0x26677c] | file +0x7d0 | ev_1abd2480771bd0dfc44ad78a0ad8b9e76496fd5a3103f04dbfb5001838054042
thunk_266778:
0x266778: JMP 0x0003d0e0
; END FUNCTION thunk_266778
0x26677d: INT3 ; original byte CC, padding
0x26677e: INT3 ; original byte CC, padding
0x26677f: INT3 ; original byte CC, padding

; FUNCTION thunk_266780 [0x266780, 0x266784] | file +0x7d8 | ev_c505cc9a86f7ae4149f1e64b36bc59f5f40aa963623ba2974583c5d3e37dcf6c
thunk_266780:
0x266780: JMP 0x0003d660
; END FUNCTION thunk_266780
0x266785: INT3 ; original byte CC, padding
0x266786: INT3 ; original byte CC, padding
0x266787: INT3 ; original byte CC, padding

; FUNCTION thunk_266788 [0x266788, 0x26678c] | file +0x7e0 | ev_9ed81726a9363e9abf06ebf384044590c774b49373b1aff9cce434caec79de73
thunk_266788:
0x266788: JMP 0x0003e100
; END FUNCTION thunk_266788
0x26678d: INT3 ; original byte CC, padding
0x26678e: INT3 ; original byte CC, padding
0x26678f: INT3 ; original byte CC, padding

; FUNCTION thunk_266790 [0x266790, 0x266794] | file +0x7e8 | ev_b6d70feab26a69b46d1e60bf65b7ac8ff9e8af0f14e58083f5ca2104e00b4a77
thunk_266790:
0x266790: JMP 0x0003e160
; END FUNCTION thunk_266790
0x266795: INT3 ; original byte CC, padding
0x266796: INT3 ; original byte CC, padding
0x266797: INT3 ; original byte CC, padding

; FUNCTION thunk_266798 [0x266798, 0x26679c] | file +0x7f0 | ev_3a4fe1aed4181c9b36fc2d107277e19a007843c58dbc34a1b90c6b5364c25a1f
thunk_266798:
0x266798: JMP 0x0003e1c0
; END FUNCTION thunk_266798
0x26679d: INT3 ; original byte CC, padding
0x26679e: INT3 ; original byte CC, padding
0x26679f: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a0 [0x2667a0, 0x2667a4] | file +0x7f8 | ev_4e9ef9ebcbe1c81642627453beab0cf815cbe6b323c761944902a2e3a594e35e
thunk_2667a0:
0x2667a0: JMP 0x0003f070
; END FUNCTION thunk_2667a0
0x2667a5: INT3 ; original byte CC, padding
0x2667a6: INT3 ; original byte CC, padding
0x2667a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667a8 [0x2667a8, 0x2667ac] | file +0x800 | ev_1e8d18696b5a66f44717599dfe66fa3f5647bfd731e90f4213ba0fb583230b36
thunk_2667a8:
0x2667a8: JMP 0x0003f0d0
; END FUNCTION thunk_2667a8
0x2667ad: INT3 ; original byte CC, padding
0x2667ae: INT3 ; original byte CC, padding
0x2667af: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b0 [0x2667b0, 0x2667b4] | file +0x808 | ev_694c8a603d68e5c334d648ccab1a33dedcffe9fe58ccd66f93a0e0e9f55a0532
thunk_2667b0:
0x2667b0: JMP 0x0003f4b0
; END FUNCTION thunk_2667b0
0x2667b5: INT3 ; original byte CC, padding
0x2667b6: INT3 ; original byte CC, padding
0x2667b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667b8 [0x2667b8, 0x2667bc] | file +0x810 | ev_a433f0ca544c9e14c9ccf44b4ee4f0234100e7f292134e31ff932a3f92aa68ce
thunk_2667b8:
0x2667b8: JMP 0x0003f510
; END FUNCTION thunk_2667b8
0x2667bd: INT3 ; original byte CC, padding
0x2667be: INT3 ; original byte CC, padding
0x2667bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c0 [0x2667c0, 0x2667c4] | file +0x818 | ev_bea5624da2f134f28923630943d28c30f396fee0e2b4c2add7748798a411e200
thunk_2667c0:
0x2667c0: JMP 0x0003f570
; END FUNCTION thunk_2667c0
0x2667c5: INT3 ; original byte CC, padding
0x2667c6: INT3 ; original byte CC, padding
0x2667c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667c8 [0x2667c8, 0x2667cc] | file +0x820 | ev_873e539dd587ac5fcd71faab8b5f3475b0c0c95679ce352316e553e65785df80
thunk_2667c8:
0x2667c8: JMP 0x0003fbb0
; END FUNCTION thunk_2667c8
0x2667cd: INT3 ; original byte CC, padding
0x2667ce: INT3 ; original byte CC, padding
0x2667cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d0 [0x2667d0, 0x2667d4] | file +0x828 | ev_d081b0d8d4dc0ccacf69699e5595f0544f500d0276055e7bf09413150e1224dd
thunk_2667d0:
0x2667d0: JMP 0x0003ffc0
; END FUNCTION thunk_2667d0
0x2667d5: INT3 ; original byte CC, padding
0x2667d6: INT3 ; original byte CC, padding
0x2667d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667d8 [0x2667d8, 0x2667dc] | file +0x830 | ev_96e92b8e3e99b79413f154cc9eb3d60a8a7d646aa4515fb8fb5de63dd6d7c917
thunk_2667d8:
0x2667d8: JMP 0x00040960
; END FUNCTION thunk_2667d8
0x2667dd: INT3 ; original byte CC, padding
0x2667de: INT3 ; original byte CC, padding
0x2667df: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e0 [0x2667e0, 0x2667e4] | file +0x838 | ev_a1b1802795532978974ffc776896ea0d7761845d22797ef90473038e62d47faa
thunk_2667e0:
0x2667e0: JMP 0x00040b50
; END FUNCTION thunk_2667e0
0x2667e5: INT3 ; original byte CC, padding
0x2667e6: INT3 ; original byte CC, padding
0x2667e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667e8 [0x2667e8, 0x2667ec] | file +0x840 | ev_83007fa2af45028f40282ddb2608364e94f80e2ce94687cd3f80e2b37d9e04ae
thunk_2667e8:
0x2667e8: JMP 0x00040c30
; END FUNCTION thunk_2667e8
0x2667ed: INT3 ; original byte CC, padding
0x2667ee: INT3 ; original byte CC, padding
0x2667ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f0 [0x2667f0, 0x2667f4] | file +0x848 | ev_2caf01d6b7d2a840a5c899ea1ade478a1167a6d2432c06185f6657a466a24521
thunk_2667f0:
0x2667f0: JMP 0x00041630
; END FUNCTION thunk_2667f0
0x2667f5: INT3 ; original byte CC, padding
0x2667f6: INT3 ; original byte CC, padding
0x2667f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2667f8 [0x2667f8, 0x2667fc] | file +0x850 | ev_2e9a02026a32f4d3595a1c8ea3741317c463c48293ad9967d64bb0c842c16bcf
thunk_2667f8:
0x2667f8: JMP 0x00041750
; END FUNCTION thunk_2667f8
0x2667fd: INT3 ; original byte CC, padding
0x2667fe: INT3 ; original byte CC, padding
0x2667ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266800 [0x266800, 0x266804] | file +0x858 | ev_b5a4bcb1d6c941a3f6d70e0062d3c0463382b61c6d39e75f8ad4575154058329
thunk_266800:
0x266800: JMP 0x00041830
; END FUNCTION thunk_266800
0x266805: INT3 ; original byte CC, padding
0x266806: INT3 ; original byte CC, padding
0x266807: INT3 ; original byte CC, padding

; FUNCTION thunk_266808 [0x266808, 0x26680c] | file +0x860 | ev_f1b081b3b9ac7495b8be40ee086537bb185a297b65b7ef087083c600fbb85b61
thunk_266808:
0x266808: JMP 0x000418c0
; END FUNCTION thunk_266808
0x26680d: INT3 ; original byte CC, padding
0x26680e: INT3 ; original byte CC, padding
0x26680f: INT3 ; original byte CC, padding

; FUNCTION thunk_266810 [0x266810, 0x266814] | file +0x868 | ev_286fd1ef6a141f6a83604ef9198646a69f86d2b579ec17a23ae6cebb467e5061
thunk_266810:
0x266810: JMP 0x00042060
; END FUNCTION thunk_266810
0x266815: INT3 ; original byte CC, padding
0x266816: INT3 ; original byte CC, padding
0x266817: INT3 ; original byte CC, padding

; FUNCTION thunk_266818 [0x266818, 0x26681c] | file +0x870 | ev_47935a2775d41df4f9b4c5a7174f7ec66edf37c497c637165652e966d455c6c2
thunk_266818:
0x266818: JMP 0x000424d0
; END FUNCTION thunk_266818
0x26681d: INT3 ; original byte CC, padding
0x26681e: INT3 ; original byte CC, padding
0x26681f: INT3 ; original byte CC, padding

; FUNCTION thunk_266820 [0x266820, 0x266824] | file +0x878 | ev_ec6ae96b47da7790af52eef03b6d449d9601b42b60ff5781510b83d5eed62146
thunk_266820:
0x266820: JMP 0x000425a0
; END FUNCTION thunk_266820
0x266825: INT3 ; original byte CC, padding
0x266826: INT3 ; original byte CC, padding
0x266827: INT3 ; original byte CC, padding

; FUNCTION thunk_266828 [0x266828, 0x26682c] | file +0x880 | ev_62e5f7ba42bcfbb4e746143fb9a9e26ec7bd4a12c0fbf516331bb1dba6d35663
thunk_266828:
0x266828: JMP 0x00042600
; END FUNCTION thunk_266828
0x26682d: INT3 ; original byte CC, padding
0x26682e: INT3 ; original byte CC, padding
0x26682f: INT3 ; original byte CC, padding

; FUNCTION thunk_266830 [0x266830, 0x266834] | file +0x888 | ev_5adad97b5e16134fb3c507782f4939f93bf7446e42819870836ccff91d30b7eb
thunk_266830:
0x266830: JMP 0x00690030
; END FUNCTION thunk_266830
0x266835: INT3 ; original byte CC, padding
0x266836: INT3 ; original byte CC, padding
0x266837: INT3 ; original byte CC, padding

; FUNCTION thunk_266838 [0x266838, 0x26683c] | file +0x890 | ev_816d78169618a36f8b32f4a02e164b67743d4a889459642185f582989c4af5e2
thunk_266838:
0x266838: JMP 0x00696cc0
; END FUNCTION thunk_266838
0x26683d: INT3 ; original byte CC, padding
0x26683e: INT3 ; original byte CC, padding
0x26683f: INT3 ; original byte CC, padding

; FUNCTION thunk_266840 [0x266840, 0x266844] | file +0x898 | ev_ac0488f3239f358372c3fe2efa4f19fad41d472d5150f8744654236f12971a58
thunk_266840:
0x266840: JMP 0x006985d0
; END FUNCTION thunk_266840
0x266845: INT3 ; original byte CC, padding
0x266846: INT3 ; original byte CC, padding
0x266847: INT3 ; original byte CC, padding

; FUNCTION thunk_266848 [0x266848, 0x26684c] | file +0x8a0 | ev_93973c149c06bf5ab4e689d9c5e3a621a45fdb016a490bd5f873537571699dde
thunk_266848:
0x266848: JMP 0x006a2050
; END FUNCTION thunk_266848
0x26684d: INT3 ; original byte CC, padding
0x26684e: INT3 ; original byte CC, padding
0x26684f: INT3 ; original byte CC, padding

; FUNCTION thunk_266850 [0x266850, 0x266854] | file +0x8a8 | ev_0384ec62f16c1b55f37f6e139cd5b347f936b71ac6d322c07912104d15839704
thunk_266850:
0x266850: JMP 0x006a22b0
; END FUNCTION thunk_266850
0x266855: INT3 ; original byte CC, padding
0x266856: INT3 ; original byte CC, padding
0x266857: INT3 ; original byte CC, padding

; FUNCTION thunk_266858 [0x266858, 0x26685c] | file +0x8b0 | ev_df166f83af68846c8787a22b60db92858c5297f11c0e5021462d71dc3a774fa4
thunk_266858:
0x266858: JMP 0x006ae640
; END FUNCTION thunk_266858
0x26685d: INT3 ; original byte CC, padding
0x26685e: INT3 ; original byte CC, padding
0x26685f: INT3 ; original byte CC, padding

; FUNCTION thunk_266860 [0x266860, 0x266864] | file +0x8b8 | ev_0fdd27d74cd24b4f8db75581de4388713e3597d065d3842c8af4f054c455ff46
thunk_266860:
0x266860: JMP 0x006ae7f0
; END FUNCTION thunk_266860
0x266865: INT3 ; original byte CC, padding
0x266866: INT3 ; original byte CC, padding
0x266867: INT3 ; original byte CC, padding

; FUNCTION thunk_266868 [0x266868, 0x26686c] | file +0x8c0 | ev_fc62fcbabf14463ab5445229b64c21674fbb7a0e14b7c8d18f89f180b63d1a35
thunk_266868:
0x266868: JMP 0x001813b0
; END FUNCTION thunk_266868
0x26686d: INT3 ; original byte CC, padding
0x26686e: INT3 ; original byte CC, padding
0x26686f: INT3 ; original byte CC, padding

; FUNCTION thunk_266870 [0x266870, 0x266874] | file +0x8c8 | ev_e2d4aad35945259cea115215ff1ab977a4b05020f234b4e2d5529ecfaf679d6c
thunk_266870:
0x266870: JMP 0x006befa0
; END FUNCTION thunk_266870
0x266875: INT3 ; original byte CC, padding
0x266876: INT3 ; original byte CC, padding
0x266877: INT3 ; original byte CC, padding

; FUNCTION thunk_266878 [0x266878, 0x26687c] | file +0x8d0 | ev_a3fad9735b44d843a7b2df48591f3fdd19bcad9229cd6cc9fa12ae57295fafdb
thunk_266878:
0x266878: JMP 0x00188040
; END FUNCTION thunk_266878
0x26687d: INT3 ; original byte CC, padding
0x26687e: INT3 ; original byte CC, padding
0x26687f: INT3 ; original byte CC, padding

; FUNCTION thunk_266880 [0x266880, 0x266884] | file +0x8d8 | ev_cb5c5a617a74303d22c2870604c190a2c74691cea1254e2590feb42cebc14908
thunk_266880:
0x266880: JMP 0x006d0b00
; END FUNCTION thunk_266880
0x266885: INT3 ; original byte CC, padding
0x266886: INT3 ; original byte CC, padding
0x266887: INT3 ; original byte CC, padding

; FUNCTION thunk_266888 [0x266888, 0x26688c] | file +0x8e0 | ev_0c3c38a29d01d8bdd25da4829b302df5d6745d42fe41808735ca9a72b6b3ecc5
thunk_266888:
0x266888: JMP 0x006d1100
; END FUNCTION thunk_266888
0x26688d: INT3 ; original byte CC, padding
0x26688e: INT3 ; original byte CC, padding
0x26688f: INT3 ; original byte CC, padding

; FUNCTION thunk_266890 [0x266890, 0x266894] | file +0x8e8 | ev_6b973f5fb069a1d3cbe8d7d4aabeb6bcee863c0240424f8a6914cece654d8dc4
thunk_266890:
0x266890: JMP 0x006d1260
; END FUNCTION thunk_266890
0x266895: INT3 ; original byte CC, padding
0x266896: INT3 ; original byte CC, padding
0x266897: INT3 ; original byte CC, padding

; FUNCTION thunk_266898 [0x266898, 0x26689c] | file +0x8f0 | ev_8b28ef61b7456567df4642cc9116b8671bba7aa5b95ff4372db799c6ba25dc2d
thunk_266898:
0x266898: JMP 0x006d13e0
; END FUNCTION thunk_266898
0x26689d: INT3 ; original byte CC, padding
0x26689e: INT3 ; original byte CC, padding
0x26689f: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a0 [0x2668a0, 0x2668a4] | file +0x8f8 | ev_fa00b3d0152f45a894b8ec075f6bf10efe75850a819b491d29e92959b6b8731f
thunk_2668a0:
0x2668a0: JMP 0x006d1520
; END FUNCTION thunk_2668a0
0x2668a5: INT3 ; original byte CC, padding
0x2668a6: INT3 ; original byte CC, padding
0x2668a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668a8 [0x2668a8, 0x2668ac] | file +0x900 | ev_d78f08e03b31ffa2b2efe42a6cfb4536afb928a6c7f119a024a22b05f40899ff
thunk_2668a8:
0x2668a8: JMP 0x006d1640
; END FUNCTION thunk_2668a8
0x2668ad: INT3 ; original byte CC, padding
0x2668ae: INT3 ; original byte CC, padding
0x2668af: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b0 [0x2668b0, 0x2668b4] | file +0x908 | ev_3ed67d6c97c92967a395908a8a040edb330be148f28e2c64059b679195b59eae
thunk_2668b0:
0x2668b0: JMP 0x006d1720
; END FUNCTION thunk_2668b0
0x2668b5: INT3 ; original byte CC, padding
0x2668b6: INT3 ; original byte CC, padding
0x2668b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668b8 [0x2668b8, 0x2668bc] | file +0x910 | ev_de93f54afb23cbd9b4b3762b6edbec96ba6addd3a7c90c972215bce85e5605f8
thunk_2668b8:
0x2668b8: JMP 0x006dc660
; END FUNCTION thunk_2668b8
0x2668bd: INT3 ; original byte CC, padding
0x2668be: INT3 ; original byte CC, padding
0x2668bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c0 [0x2668c0, 0x2668c4] | file +0x918 | ev_3e530c546d978a4cde1ea40098241ece409f40b0be36a2293bc70eb3a70892d2
thunk_2668c0:
0x2668c0: JMP 0x006dc690
; END FUNCTION thunk_2668c0
0x2668c5: INT3 ; original byte CC, padding
0x2668c6: INT3 ; original byte CC, padding
0x2668c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668c8 [0x2668c8, 0x2668cc] | file +0x920 | ev_4029b49e23f105d9fd959b8d0e79ee611fff70d5deb5b25c1ec32f063cdbf7d2
thunk_2668c8:
0x2668c8: JMP 0x006dc6a0
; END FUNCTION thunk_2668c8
0x2668cd: INT3 ; original byte CC, padding
0x2668ce: INT3 ; original byte CC, padding
0x2668cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d0 [0x2668d0, 0x2668d4] | file +0x928 | ev_28820dcd9e75794b371215f8085c8fc2e919e52036eb5b329b5618bbecaa8502
thunk_2668d0:
0x2668d0: JMP 0x006e0920
; END FUNCTION thunk_2668d0
0x2668d5: INT3 ; original byte CC, padding
0x2668d6: INT3 ; original byte CC, padding
0x2668d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668d8 [0x2668d8, 0x2668dc] | file +0x930 | ev_48d27fa99d4bfbfd01b9c0cfc4e1983ac381df090d15929fd844727932ef39f8
thunk_2668d8:
0x2668d8: JMP 0x006e1440
; END FUNCTION thunk_2668d8
0x2668dd: INT3 ; original byte CC, padding
0x2668de: INT3 ; original byte CC, padding
0x2668df: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e0 [0x2668e0, 0x2668e4] | file +0x938 | ev_7aa82add6e61823b6e8626df3d716de65e3fdba037ff334b9a282990cc834fcc
thunk_2668e0:
0x2668e0: JMP 0x006e1450
; END FUNCTION thunk_2668e0
0x2668e5: INT3 ; original byte CC, padding
0x2668e6: INT3 ; original byte CC, padding
0x2668e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668e8 [0x2668e8, 0x2668ec] | file +0x940 | ev_7366c86f363f041f011d7a626d3635808a0a7efc1961a826359904110403c080
thunk_2668e8:
0x2668e8: JMP 0x00189a70
; END FUNCTION thunk_2668e8
0x2668ed: INT3 ; original byte CC, padding
0x2668ee: INT3 ; original byte CC, padding
0x2668ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f0 [0x2668f0, 0x2668f4] | file +0x948 | ev_d35c35a0ef27616e2538e5e78e8eb0d78e896dedfca6d619b3ac2c0ce3a0f144
thunk_2668f0:
0x2668f0: JMP 0x00190aa0
; END FUNCTION thunk_2668f0
0x2668f5: INT3 ; original byte CC, padding
0x2668f6: INT3 ; original byte CC, padding
0x2668f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2668f8 [0x2668f8, 0x2668fc] | file +0x950 | ev_285a07576ea147e47d5a4f684fda3d98049a70bc491220a6859a2ff207cf32a2
thunk_2668f8:
0x2668f8: JMP 0x00702970
; END FUNCTION thunk_2668f8
0x2668fd: INT3 ; original byte CC, padding
0x2668fe: INT3 ; original byte CC, padding
0x2668ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266900 [0x266900, 0x266904] | file +0x958 | ev_79a39a11fc3f4350741dfbe92dbb3ee9d03d1f0038ac550efcf3abe6aa034267
thunk_266900:
0x266900: JMP 0x00702d60
; END FUNCTION thunk_266900
0x266905: INT3 ; original byte CC, padding
0x266906: INT3 ; original byte CC, padding
0x266907: INT3 ; original byte CC, padding

; FUNCTION thunk_266908 [0x266908, 0x26690c] | file +0x960 | ev_c465dba0b2d910dc7e883d6f859825f028af61a03af466d233c429a1c3437066
thunk_266908:
0x266908: JMP 0x00706170
; END FUNCTION thunk_266908
0x26690d: INT3 ; original byte CC, padding
0x26690e: INT3 ; original byte CC, padding
0x26690f: INT3 ; original byte CC, padding

; FUNCTION thunk_266910 [0x266910, 0x266914] | file +0x968 | ev_ef9fedeb9e387dbcb7d3290bec8b7689777232b05d6c3bb1b117ce64c18f2c5d
thunk_266910:
0x266910: JMP 0x007061f0
; END FUNCTION thunk_266910
0x266915: INT3 ; original byte CC, padding
0x266916: INT3 ; original byte CC, padding
0x266917: INT3 ; original byte CC, padding

; FUNCTION thunk_266918 [0x266918, 0x26691c] | file +0x970 | ev_2af3c5ed42b89ca47470939543fcc7eb737ab28171a4cd5c8133946d4bffebc8
thunk_266918:
0x266918: JMP 0x0070ff00
; END FUNCTION thunk_266918
0x26691d: INT3 ; original byte CC, padding
0x26691e: INT3 ; original byte CC, padding
0x26691f: INT3 ; original byte CC, padding

; FUNCTION thunk_266920 [0x266920, 0x266924] | file +0x978 | ev_8ba8242e089252d99a8cc8a7db165be4787cdc73249a67a9d3de406b2f92243b
thunk_266920:
0x266920: JMP 0x0070ffb0
; END FUNCTION thunk_266920
0x266925: INT3 ; original byte CC, padding
0x266926: INT3 ; original byte CC, padding
0x266927: INT3 ; original byte CC, padding

; FUNCTION thunk_266928 [0x266928, 0x26692c] | file +0x980 | ev_bde685656623cf261c8d2a68eb1a624c013d1f1b4b0e9c0e93f302aab6068365
thunk_266928:
0x266928: JMP 0x007101c0
; END FUNCTION thunk_266928
0x26692d: INT3 ; original byte CC, padding
0x26692e: INT3 ; original byte CC, padding
0x26692f: INT3 ; original byte CC, padding

; FUNCTION thunk_266930 [0x266930, 0x266934] | file +0x988 | ev_b7ffb8877836166a4a685c022bc96bc3e0ab506a2439a5c6dee2f66a6ca82322
thunk_266930:
0x266930: JMP 0x00710320
; END FUNCTION thunk_266930
0x266935: INT3 ; original byte CC, padding
0x266936: INT3 ; original byte CC, padding
0x266937: INT3 ; original byte CC, padding

; FUNCTION thunk_266938 [0x266938, 0x26693c] | file +0x990 | ev_7f6f171a1627ab6995130bf2a96eb88ad7d18a6c294863cb2a05e16007aee4b8
thunk_266938:
0x266938: JMP 0x00712bb0
; END FUNCTION thunk_266938
0x26693d: INT3 ; original byte CC, padding
0x26693e: INT3 ; original byte CC, padding
0x26693f: INT3 ; original byte CC, padding

; FUNCTION thunk_266940 [0x266940, 0x266944] | file +0x998 | ev_dddfee7d6fc78e04fc2e8b6de476d83bd91928a276a0e49b68df7ca11e341a36
thunk_266940:
0x266940: JMP 0x00716360
; END FUNCTION thunk_266940
0x266945: INT3 ; original byte CC, padding
0x266946: INT3 ; original byte CC, padding
0x266947: INT3 ; original byte CC, padding

; FUNCTION thunk_266948 [0x266948, 0x26694c] | file +0x9a0 | ev_810262db33bcfe19b9125a9a40bfbc0dcf0ca1d8f07ea1083aa8eb64c2683ed7
thunk_266948:
0x266948: JMP 0x0072f970
; END FUNCTION thunk_266948
0x26694d: INT3 ; original byte CC, padding
0x26694e: INT3 ; original byte CC, padding
0x26694f: INT3 ; original byte CC, padding

; FUNCTION thunk_266950 [0x266950, 0x266954] | file +0x9a8 | ev_bb75578d2158f4a93fd8ad186335b68f4e86e611e1046b5612d66d40e6f42c05
thunk_266950:
0x266950: JMP 0x0072f990
; END FUNCTION thunk_266950
0x266955: INT3 ; original byte CC, padding
0x266956: INT3 ; original byte CC, padding
0x266957: INT3 ; original byte CC, padding

; FUNCTION thunk_266958 [0x266958, 0x26695c] | file +0x9b0 | ev_cc7869a755aa94e9948250e267657fb3484ae5d84c3939e93ee81e25a17c6658
thunk_266958:
0x266958: JMP 0x0072fa20
; END FUNCTION thunk_266958
0x26695d: INT3 ; original byte CC, padding
0x26695e: INT3 ; original byte CC, padding
0x26695f: INT3 ; original byte CC, padding

; FUNCTION thunk_266960 [0x266960, 0x266964] | file +0x9b8 | ev_d41be3a77fe7d970714413a2db7362e7378afaf1c234aca1fb495459da2981f4
thunk_266960:
0x266960: JMP 0x00246e30
; END FUNCTION thunk_266960
0x266965: INT3 ; original byte CC, padding
0x266966: INT3 ; original byte CC, padding
0x266967: INT3 ; original byte CC, padding

; FUNCTION thunk_266968 [0x266968, 0x26696c] | file +0x9c0 | ev_86447051030d85af30d27f1ae658d2b53230586b68e795e6877819c143272823
thunk_266968:
0x266968: JMP 0x007647f0
; END FUNCTION thunk_266968
0x26696d: INT3 ; original byte CC, padding
0x26696e: INT3 ; original byte CC, padding
0x26696f: INT3 ; original byte CC, padding

; FUNCTION thunk_266970 [0x266970, 0x266974] | file +0x9c8 | ev_8f35ce01a7e76f246111c0713a73ab48052fb3758ed42ddf08dadd78f3ee8b2e
thunk_266970:
0x266970: JMP 0x00773710
; END FUNCTION thunk_266970
0x266975: INT3 ; original byte CC, padding
0x266976: INT3 ; original byte CC, padding
0x266977: INT3 ; original byte CC, padding

; FUNCTION thunk_266978 [0x266978, 0x26697c] | file +0x9d0 | ev_67777dd4e1619b577951547dcecfe4e41541a70e9352d9f4fd8e4c18c15e790e
thunk_266978:
0x266978: JMP 0x00775950
; END FUNCTION thunk_266978
0x26697d: INT3 ; original byte CC, padding
0x26697e: INT3 ; original byte CC, padding
0x26697f: INT3 ; original byte CC, padding

; FUNCTION thunk_266980 [0x266980, 0x266984] | file +0x9d8 | ev_cc4f8e212f24a3d2a05a7ecfa0364795c5246f50343e1d895d0b927b5e9acbd9
thunk_266980:
0x266980: JMP 0x00799e90
; END FUNCTION thunk_266980
0x266985: INT3 ; original byte CC, padding
0x266986: INT3 ; original byte CC, padding
0x266987: INT3 ; original byte CC, padding

; FUNCTION thunk_266988 [0x266988, 0x26698c] | file +0x9e0 | ev_18e241da46f5f68857625524ec967ff69786cb909ac6fa9f4ea3613ff4a373f6
thunk_266988:
0x266988: JMP 0x007b31f0
; END FUNCTION thunk_266988
0x26698d: INT3 ; original byte CC, padding
0x26698e: INT3 ; original byte CC, padding
0x26698f: INT3 ; original byte CC, padding

; FUNCTION thunk_266990 [0x266990, 0x266994] | file +0x9e8 | ev_146209dccae72ac346c363a14fb22c9ebcf1badb24f205149cd1c2a71f73eb10
thunk_266990:
0x266990: JMP 0x007e23a0
; END FUNCTION thunk_266990
0x266995: INT3 ; original byte CC, padding
0x266996: INT3 ; original byte CC, padding
0x266997: INT3 ; original byte CC, padding

; FUNCTION thunk_266998 [0x266998, 0x26699c] | file +0x9f0 | ev_07c806b885fdfad9a042087c47d941e3e27815570df71456554ae5f777e04f8a
thunk_266998:
0x266998: JMP 0x007e83e0
; END FUNCTION thunk_266998
0x26699d: INT3 ; original byte CC, padding
0x26699e: INT3 ; original byte CC, padding
0x26699f: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a0 [0x2669a0, 0x2669a4] | file +0x9f8 | ev_be089efb1d3a783630ff9eb8e152388777867284e2e50833db979df30666a4fd
thunk_2669a0:
0x2669a0: JMP 0x007e8480
; END FUNCTION thunk_2669a0
0x2669a5: INT3 ; original byte CC, padding
0x2669a6: INT3 ; original byte CC, padding
0x2669a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669a8 [0x2669a8, 0x2669ac] | file +0xa00 | ev_7a3ddf208002c5329e2906aceffed7dd3678f5bd7961d84302be0c17c52ea09f
thunk_2669a8:
0x2669a8: JMP 0x00c3b1b0
; END FUNCTION thunk_2669a8
0x2669ad: INT3 ; original byte CC, padding
0x2669ae: INT3 ; original byte CC, padding
0x2669af: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b0 [0x2669b0, 0x2669b4] | file +0xa08 | ev_bdb5f83bfc4dba4e75e19a3eef1d072394dabaa2ee2f9f656e038f3f43a9e595
thunk_2669b0:
0x2669b0: JMP 0x00c3c6e0
; END FUNCTION thunk_2669b0
0x2669b5: INT3 ; original byte CC, padding
0x2669b6: INT3 ; original byte CC, padding
0x2669b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669b8 [0x2669b8, 0x2669bc] | file +0xa10 | ev_646a44996bac41d97d6bd466d9d89c6be5622fab00f3833056200cf520b54fe4
thunk_2669b8:
0x2669b8: JMP 0x00c3c690
; END FUNCTION thunk_2669b8
0x2669bd: INT3 ; original byte CC, padding
0x2669be: INT3 ; original byte CC, padding
0x2669bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c0 [0x2669c0, 0x2669c4] | file +0xa18 | ev_4362cb7f40b9eb146fac45118d165bc73bbc51e4d24d0134492add8ca5631b95
thunk_2669c0:
0x2669c0: JMP 0x00c3c730
; END FUNCTION thunk_2669c0
0x2669c5: INT3 ; original byte CC, padding
0x2669c6: INT3 ; original byte CC, padding
0x2669c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669c8 [0x2669c8, 0x2669cc] | file +0xa20 | ev_a2defbb92015ed92c0ef482352ca69c0fb501a1cbddcc98ea3de49ae7ad35628
thunk_2669c8:
0x2669c8: JMP 0x00802220
; END FUNCTION thunk_2669c8
0x2669cd: INT3 ; original byte CC, padding
0x2669ce: INT3 ; original byte CC, padding
0x2669cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d0 [0x2669d0, 0x2669d4] | file +0xa28 | ev_8b0d6c0754c0b3b0f5920be4785507c6b59ae0d16e34c3c88580ef5102aa7c09
thunk_2669d0:
0x2669d0: JMP 0x008024f0
; END FUNCTION thunk_2669d0
0x2669d5: INT3 ; original byte CC, padding
0x2669d6: INT3 ; original byte CC, padding
0x2669d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669d8 [0x2669d8, 0x2669dc] | file +0xa30 | ev_ad2127f94361c94e9ea3ce28f07b62b5f86902733f265d7410b1b50d7c2dcf34
thunk_2669d8:
0x2669d8: JMP 0x0080c570
; END FUNCTION thunk_2669d8
0x2669dd: INT3 ; original byte CC, padding
0x2669de: INT3 ; original byte CC, padding
0x2669df: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e0 [0x2669e0, 0x2669e4] | file +0xa38 | ev_107ae0a63c11b3b92fc64c7be5323a3eb435cad4abf4cfab408f51f081534354
thunk_2669e0:
0x2669e0: JMP 0x0082b300
; END FUNCTION thunk_2669e0
0x2669e5: INT3 ; original byte CC, padding
0x2669e6: INT3 ; original byte CC, padding
0x2669e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669e8 [0x2669e8, 0x2669ec] | file +0xa40 | ev_9ad5a3b6afeb0b6f0b925f04a856e87601c2bf950f8d2fb50a65e0136f58057a
thunk_2669e8:
0x2669e8: JMP 0x00920ee0
; END FUNCTION thunk_2669e8
0x2669ed: INT3 ; original byte CC, padding
0x2669ee: INT3 ; original byte CC, padding
0x2669ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f0 [0x2669f0, 0x2669f4] | file +0xa48 | ev_a480cb6ab7d531f1320cc8242e87145c1c91b7d7a84222faf523f1c010f50494
thunk_2669f0:
0x2669f0: JMP 0x00920b90
; END FUNCTION thunk_2669f0
0x2669f5: INT3 ; original byte CC, padding
0x2669f6: INT3 ; original byte CC, padding
0x2669f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2669f8 [0x2669f8, 0x2669fc] | file +0xa50 | ev_063eb2665a5427fcd2306892c374cdbc281c7ad6593802712bc6c4b1efb017b7
thunk_2669f8:
0x2669f8: JMP 0x00830810
; END FUNCTION thunk_2669f8
0x2669fd: INT3 ; original byte CC, padding
0x2669fe: INT3 ; original byte CC, padding
0x2669ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266a00 [0x266a00, 0x266a04] | file +0xa58 | ev_29198ce2df122b645034527b9bb21acb52264c59b9daf0884f26625cd53e0086
thunk_266a00:
0x266a00: JMP 0x00830f00
; END FUNCTION thunk_266a00
0x266a05: INT3 ; original byte CC, padding
0x266a06: INT3 ; original byte CC, padding
0x266a07: INT3 ; original byte CC, padding

; FUNCTION thunk_266a08 [0x266a08, 0x266a0c] | file +0xa60 | ev_177dd7dc7b53ab81c2013acc266639880dbc8de7da863168a12b7fafb05569d0
thunk_266a08:
0x266a08: JMP 0x008352b0
; END FUNCTION thunk_266a08
0x266a0d: INT3 ; original byte CC, padding
0x266a0e: INT3 ; original byte CC, padding
0x266a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a10 [0x266a10, 0x266a14] | file +0xa68 | ev_0d5315ab6a16e41f21449cd36ebc5a3310ea3b201b5c2822cc1967b87fc5175d
thunk_266a10:
0x266a10: JMP 0x008352c0
; END FUNCTION thunk_266a10
0x266a15: INT3 ; original byte CC, padding
0x266a16: INT3 ; original byte CC, padding
0x266a17: INT3 ; original byte CC, padding

; FUNCTION thunk_266a18 [0x266a18, 0x266a1c] | file +0xa70 | ev_ec8c18935f45a48774dc5e604617b4fa54ed540c1146049e3259786a4611c0fe
thunk_266a18:
0x266a18: JMP 0x008352d0
; END FUNCTION thunk_266a18
0x266a1d: INT3 ; original byte CC, padding
0x266a1e: INT3 ; original byte CC, padding
0x266a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a20 [0x266a20, 0x266a24] | file +0xa78 | ev_67ccf19ae6261c26c1b465c290344d75286d87b8463b67ce27a2a00d373f25e1
thunk_266a20:
0x266a20: JMP 0x008352f0
; END FUNCTION thunk_266a20
0x266a25: INT3 ; original byte CC, padding
0x266a26: INT3 ; original byte CC, padding
0x266a27: INT3 ; original byte CC, padding

; FUNCTION thunk_266a28 [0x266a28, 0x266a2c] | file +0xa80 | ev_0fc4c28b309099d4fef2aa0441aada55fdb833e87dd6e611d54d6ce100ee2603
thunk_266a28:
0x266a28: JMP 0x00835440
; END FUNCTION thunk_266a28
0x266a2d: INT3 ; original byte CC, padding
0x266a2e: INT3 ; original byte CC, padding
0x266a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a30 [0x266a30, 0x266a34] | file +0xa88 | ev_b30b9cb2f6b10209ccef36a80c6226dec9100c5cdf04f409483c5df6c8d721cb
thunk_266a30:
0x266a30: JMP 0x00835450
; END FUNCTION thunk_266a30
0x266a35: INT3 ; original byte CC, padding
0x266a36: INT3 ; original byte CC, padding
0x266a37: INT3 ; original byte CC, padding

; FUNCTION thunk_266a38 [0x266a38, 0x266a3c] | file +0xa90 | ev_1c89747d1cc419c82f65552dd5e9f398d08b9dd3c158550837d6d077fe5f1f9a
thunk_266a38:
0x266a38: JMP 0x00835490
; END FUNCTION thunk_266a38
0x266a3d: INT3 ; original byte CC, padding
0x266a3e: INT3 ; original byte CC, padding
0x266a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a40 [0x266a40, 0x266a44] | file +0xa98 | ev_86c79d8831758bb566d4330365abf0f4f2fdd5f6cecd088a67fe9b63cbdb7eb7
thunk_266a40:
0x266a40: JMP 0x00835ad0
; END FUNCTION thunk_266a40
0x266a45: INT3 ; original byte CC, padding
0x266a46: INT3 ; original byte CC, padding
0x266a47: INT3 ; original byte CC, padding

; FUNCTION thunk_266a48 [0x266a48, 0x266a4c] | file +0xaa0 | ev_995c50dcb18c9069c8f14612d6a1455003ea69b54876567c1e823ec636e9aa48
thunk_266a48:
0x266a48: JMP 0x00850870
; END FUNCTION thunk_266a48
0x266a4d: INT3 ; original byte CC, padding
0x266a4e: INT3 ; original byte CC, padding
0x266a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a50 [0x266a50, 0x266a54] | file +0xaa8 | ev_5e329a7f38c7891bcb76d5475bccd7ac8a8253c93b2384eb3199eed3c1d6eb2c
thunk_266a50:
0x266a50: JMP 0x008702f0
; END FUNCTION thunk_266a50
0x266a55: INT3 ; original byte CC, padding
0x266a56: INT3 ; original byte CC, padding
0x266a57: INT3 ; original byte CC, padding

; FUNCTION thunk_266a58 [0x266a58, 0x266a5c] | file +0xab0 | ev_e0a5532f5aff1a4a2ee764559daee4f819665087f4630c432530d3cf5486f063
thunk_266a58:
0x266a58: JMP 0x008705d0
; END FUNCTION thunk_266a58
0x266a5d: INT3 ; original byte CC, padding
0x266a5e: INT3 ; original byte CC, padding
0x266a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a60 [0x266a60, 0x266a64] | file +0xab8 | ev_80548a6b40dfc2aeef643069f1ecbfbcaa660deb693d6dfc073b9d3e218c7cb8
thunk_266a60:
0x266a60: JMP 0x00872af0
; END FUNCTION thunk_266a60
0x266a65: INT3 ; original byte CC, padding
0x266a66: INT3 ; original byte CC, padding
0x266a67: INT3 ; original byte CC, padding

; FUNCTION thunk_266a68 [0x266a68, 0x266a6c] | file +0xac0 | ev_8a91bd014432af5bccf4cd9785804c8daa7551ec5454259f0d263e139613a20a
thunk_266a68:
0x266a68: JMP 0x00873800
; END FUNCTION thunk_266a68
0x266a6d: INT3 ; original byte CC, padding
0x266a6e: INT3 ; original byte CC, padding
0x266a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a70 [0x266a70, 0x266a74] | file +0xac8 | ev_ace7e386aef97a8938bc5277da2304ae349721e0be6629dfaab82c91e9879fe3
thunk_266a70:
0x266a70: JMP 0x00063a40
; END FUNCTION thunk_266a70
0x266a75: INT3 ; original byte CC, padding
0x266a76: INT3 ; original byte CC, padding
0x266a77: INT3 ; original byte CC, padding

; FUNCTION thunk_266a78 [0x266a78, 0x266a7c] | file +0xad0 | ev_4f9cbc3755ffa00d9bc90c78dd059443d243871133d78ad726b0b8a1fa8c59f1
thunk_266a78:
0x266a78: JMP 0x00066370
; END FUNCTION thunk_266a78
0x266a7d: INT3 ; original byte CC, padding
0x266a7e: INT3 ; original byte CC, padding
0x266a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a80 [0x266a80, 0x266a84] | file +0xad8 | ev_d1253b2b6a410cdb32f733044e199ff7bc1b88e3fa164e1a9321bfe29d2701a4
thunk_266a80:
0x266a80: JMP 0x000e6590
; END FUNCTION thunk_266a80
0x266a85: INT3 ; original byte CC, padding
0x266a86: INT3 ; original byte CC, padding
0x266a87: INT3 ; original byte CC, padding

; FUNCTION thunk_266a88 [0x266a88, 0x266a8c] | file +0xae0 | ev_a70131a343e30187fec4ee4ddd3e10432a8d5db8f7b758eaf398ef0ff9545c41
thunk_266a88:
0x266a88: JMP 0x000e65a0
; END FUNCTION thunk_266a88
0x266a8d: INT3 ; original byte CC, padding
0x266a8e: INT3 ; original byte CC, padding
0x266a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266a90 [0x266a90, 0x266a94] | file +0xae8 | ev_580401ac889df9a5a5a73e71f8edea677b42be167a238dc2dff457a9c9f336ff
thunk_266a90:
0x266a90: JMP 0x000e6760
; END FUNCTION thunk_266a90
0x266a95: INT3 ; original byte CC, padding
0x266a96: INT3 ; original byte CC, padding
0x266a97: INT3 ; original byte CC, padding

; FUNCTION thunk_266a98 [0x266a98, 0x266a9c] | file +0xaf0 | ev_172618d9f6bde68af37706eabeedff3f52d26fe1bfb0328d5fe417c3de8cfab0
thunk_266a98:
0x266a98: JMP 0x000e6870
; END FUNCTION thunk_266a98
0x266a9d: INT3 ; original byte CC, padding
0x266a9e: INT3 ; original byte CC, padding
0x266a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa0 [0x266aa0, 0x266aa4] | file +0xaf8 | ev_b1e956b19177c725cc5b0de3abaf0d87a3b82bb14d6e9f4ec8831e2d91b54c47
thunk_266aa0:
0x266aa0: JMP 0x000e7f90
; END FUNCTION thunk_266aa0
0x266aa5: INT3 ; original byte CC, padding
0x266aa6: INT3 ; original byte CC, padding
0x266aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_266aa8 [0x266aa8, 0x266aac] | file +0xb00 | ev_cb2f12ba0838083ded8dec004c46678be74c9abcc86c76566af579016dba3da5
thunk_266aa8:
0x266aa8: JMP 0x000e9fa0
; END FUNCTION thunk_266aa8
0x266aad: INT3 ; original byte CC, padding
0x266aae: INT3 ; original byte CC, padding
0x266aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab0 [0x266ab0, 0x266ab4] | file +0xb08 | ev_a3052214a521cc3208409e021fa100a76d9261caf5a168a1b72d321750d2b45b
thunk_266ab0:
0x266ab0: JMP 0x000ea670
; END FUNCTION thunk_266ab0
0x266ab5: INT3 ; original byte CC, padding
0x266ab6: INT3 ; original byte CC, padding
0x266ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ab8 [0x266ab8, 0x266abc] | file +0xb10 | ev_ab5d43e0a40ba98e026fe8788b90cb6bded3dbb9083f30de951f5b55b6611259
thunk_266ab8:
0x266ab8: JMP 0x000ea760
; END FUNCTION thunk_266ab8
0x266abd: INT3 ; original byte CC, padding
0x266abe: INT3 ; original byte CC, padding
0x266abf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac0 [0x266ac0, 0x266ac4] | file +0xb18 | ev_dfd025dd38eb834c1c4d4e37cf5c20a054f6b368c99fd5c1fcf91a2b04bdb89b
thunk_266ac0:
0x266ac0: JMP 0x000eb0a0
; END FUNCTION thunk_266ac0
0x266ac5: INT3 ; original byte CC, padding
0x266ac6: INT3 ; original byte CC, padding
0x266ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ac8 [0x266ac8, 0x266acc] | file +0xb20 | ev_0ba290f61e689c4ddfbc0e9dcd74c90382de6a3844dbe481dd4b5f0c00a605c2
thunk_266ac8:
0x266ac8: JMP 0x000eb190
; END FUNCTION thunk_266ac8
0x266acd: INT3 ; original byte CC, padding
0x266ace: INT3 ; original byte CC, padding
0x266acf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad0 [0x266ad0, 0x266ad4] | file +0xb28 | ev_c7f735b31597949f8b3d8f12d6282e1f65af64f8d580a8b0a79e0b9dc7e33794
thunk_266ad0:
0x266ad0: JMP 0x000ed000
; END FUNCTION thunk_266ad0
0x266ad5: INT3 ; original byte CC, padding
0x266ad6: INT3 ; original byte CC, padding
0x266ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ad8 [0x266ad8, 0x266adc] | file +0xb30 | ev_3696ca577c07d3cd8b4dd4f5e7485fc4ccec33eea40a7e33578374e1d59a95f4
thunk_266ad8:
0x266ad8: JMP 0x000ed110
; END FUNCTION thunk_266ad8
0x266add: INT3 ; original byte CC, padding
0x266ade: INT3 ; original byte CC, padding
0x266adf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae0 [0x266ae0, 0x266ae4] | file +0xb38 | ev_3540435ffca26bbb8b563d995bb2524984e42644dbbb93606680668159825e87
thunk_266ae0:
0x266ae0: JMP 0x0088a8a0
; END FUNCTION thunk_266ae0
0x266ae5: INT3 ; original byte CC, padding
0x266ae6: INT3 ; original byte CC, padding
0x266ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ae8 [0x266ae8, 0x266aec] | file +0xb40 | ev_54ff9ea03fe46568160ea2de9f8a562e1d312294a5ade2a6b4bdcdada49b1f8c
thunk_266ae8:
0x266ae8: JMP 0x0089cdf0
; END FUNCTION thunk_266ae8
0x266aed: INT3 ; original byte CC, padding
0x266aee: INT3 ; original byte CC, padding
0x266aef: INT3 ; original byte CC, padding

; FUNCTION thunk_266af0 [0x266af0, 0x266af4] | file +0xb48 | ev_e99f643f0db2c0d24db4fcaf3b5de144991b1adc450c03f6d71331e88d5c9524
thunk_266af0:
0x266af0: JMP 0x000eeb50
; END FUNCTION thunk_266af0
0x266af5: INT3 ; original byte CC, padding
0x266af6: INT3 ; original byte CC, padding
0x266af7: INT3 ; original byte CC, padding

; FUNCTION thunk_266af8 [0x266af8, 0x266afc] | file +0xb50 | ev_7e7fe8b4dde4de2281a4f4bd9bdf5add95be25e22ea62e2e3998fb3936a080ff
thunk_266af8:
0x266af8: JMP 0x008cb250
; END FUNCTION thunk_266af8
0x266afd: INT3 ; original byte CC, padding
0x266afe: INT3 ; original byte CC, padding
0x266aff: INT3 ; original byte CC, padding

; FUNCTION thunk_266b00 [0x266b00, 0x266b04] | file +0xb58 | ev_253a16e4058f7de88d51b504ce6a1bacc5be58252642dbbbeee6505711d0648a
thunk_266b00:
0x266b00: JMP 0x008cb390
; END FUNCTION thunk_266b00
0x266b05: INT3 ; original byte CC, padding
0x266b06: INT3 ; original byte CC, padding
0x266b07: INT3 ; original byte CC, padding

; FUNCTION thunk_266b08 [0x266b08, 0x266b0c] | file +0xb60 | ev_fea9d8ff31d0c4fdadf83b22e249aee209225d68e062e0fa46b431c0c49c6dd8
thunk_266b08:
0x266b08: JMP 0x008d2f60
; END FUNCTION thunk_266b08
0x266b0d: INT3 ; original byte CC, padding
0x266b0e: INT3 ; original byte CC, padding
0x266b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b10 [0x266b10, 0x266b14] | file +0xb68 | ev_135119e632a722801f99ad8c2796d9c5d57282defcf1d58fc48cdc7c8e74cb29
thunk_266b10:
0x266b10: JMP 0x008d2f90
; END FUNCTION thunk_266b10
0x266b15: INT3 ; original byte CC, padding
0x266b16: INT3 ; original byte CC, padding
0x266b17: INT3 ; original byte CC, padding

; FUNCTION thunk_266b18 [0x266b18, 0x266b1c] | file +0xb70 | ev_1c2fdbeb60f49688af5703a743188a25b5530b226b89c34973c7416c1b14c502
thunk_266b18:
0x266b18: JMP 0x008d8230
; END FUNCTION thunk_266b18
0x266b1d: INT3 ; original byte CC, padding
0x266b1e: INT3 ; original byte CC, padding
0x266b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b20 [0x266b20, 0x266b24] | file +0xb78 | ev_05e0040e1f1449251377c771031f3d1467b9cea3be2dbb969252562a3d9c6a4b
thunk_266b20:
0x266b20: JMP 0x008d8de0
; END FUNCTION thunk_266b20
0x266b25: INT3 ; original byte CC, padding
0x266b26: INT3 ; original byte CC, padding
0x266b27: INT3 ; original byte CC, padding

; FUNCTION thunk_266b28 [0x266b28, 0x266b2c] | file +0xb80 | ev_3d84d0e832dea1f4393c51cf621401b1efd43c186c59c97d0e1290835b35a0cb
thunk_266b28:
0x266b28: JMP 0x008d97b0
; END FUNCTION thunk_266b28
0x266b2d: INT3 ; original byte CC, padding
0x266b2e: INT3 ; original byte CC, padding
0x266b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b30 [0x266b30, 0x266b34] | file +0xb88 | ev_867be95cdeb3d9b186a680fcb42dc2eef398f6ee5999819b185940e385522a2c
thunk_266b30:
0x266b30: JMP 0x008d9910
; END FUNCTION thunk_266b30
0x266b35: INT3 ; original byte CC, padding
0x266b36: INT3 ; original byte CC, padding
0x266b37: INT3 ; original byte CC, padding

; FUNCTION thunk_266b38 [0x266b38, 0x266b3c] | file +0xb90 | ev_98a6115dac41b7f98acf672e285af4338aa06739dcba52f9d8b424b8b65ba3c3
thunk_266b38:
0x266b38: JMP 0x008da4c0
; END FUNCTION thunk_266b38
0x266b3d: INT3 ; original byte CC, padding
0x266b3e: INT3 ; original byte CC, padding
0x266b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b40 [0x266b40, 0x266b44] | file +0xb98 | ev_28661288bbd93c64c4601ab505454f1242fe1271953adf1d17cfaa755a4dffd0
thunk_266b40:
0x266b40: JMP 0x008da570
; END FUNCTION thunk_266b40
0x266b45: INT3 ; original byte CC, padding
0x266b46: INT3 ; original byte CC, padding
0x266b47: INT3 ; original byte CC, padding

; FUNCTION thunk_266b48 [0x266b48, 0x266b4c] | file +0xba0 | ev_bd344f0bd9ec7d067a0cb4c8208d913f749af95b11793f5da2827e74faf79109
thunk_266b48:
0x266b48: JMP 0x008da5b0
; END FUNCTION thunk_266b48
0x266b4d: INT3 ; original byte CC, padding
0x266b4e: INT3 ; original byte CC, padding
0x266b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b50 [0x266b50, 0x266b54] | file +0xba8 | ev_f8a42572829c10ec77ab49408e31d2ffb005a17eb5e53f6695770add06be8082
thunk_266b50:
0x266b50: JMP 0x00904c80
; END FUNCTION thunk_266b50
0x266b55: INT3 ; original byte CC, padding
0x266b56: INT3 ; original byte CC, padding
0x266b57: INT3 ; original byte CC, padding

; FUNCTION thunk_266b58 [0x266b58, 0x266b5c] | file +0xbb0 | ev_8a13f5a851e775e80be452193fbd4d590b6d04ccbc7dff49f1656f50ed85ff91
thunk_266b58:
0x266b58: JMP 0x00904e60
; END FUNCTION thunk_266b58
0x266b5d: INT3 ; original byte CC, padding
0x266b5e: INT3 ; original byte CC, padding
0x266b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b60 [0x266b60, 0x266b64] | file +0xbb8 | ev_55a50802f4a0a58d620581bdf6d487bbdbf788f27ea4ebade9bcf71add39a1dc
thunk_266b60:
0x266b60: JMP 0x0091d400
; END FUNCTION thunk_266b60
0x266b65: INT3 ; original byte CC, padding
0x266b66: INT3 ; original byte CC, padding
0x266b67: INT3 ; original byte CC, padding

; FUNCTION thunk_266b68 [0x266b68, 0x266b6c] | file +0xbc0 | ev_a3b427a4474839c0c8a0e35e824e29e550bf1ee74d21c07a0abcdaee31a56056
thunk_266b68:
0x266b68: JMP 0x0091d4a0
; END FUNCTION thunk_266b68
0x266b6d: INT3 ; original byte CC, padding
0x266b6e: INT3 ; original byte CC, padding
0x266b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b70 [0x266b70, 0x266b74] | file +0xbc8 | ev_e8467fac24f549ccc576dbf816d0d2d2ccd83f5700eb06faa6c91121b928fdd0
thunk_266b70:
0x266b70: JMP 0x00a821d0
; END FUNCTION thunk_266b70
0x266b75: INT3 ; original byte CC, padding
0x266b76: INT3 ; original byte CC, padding
0x266b77: INT3 ; original byte CC, padding

; FUNCTION thunk_266b78 [0x266b78, 0x266b7c] | file +0xbd0 | ev_8f47985372645d0671a737f6dfdc8c8ebd02beaa2f6b203fa63da2a5b8f22e7b
thunk_266b78:
0x266b78: JMP 0x00b42120
; END FUNCTION thunk_266b78
0x266b7d: INT3 ; original byte CC, padding
0x266b7e: INT3 ; original byte CC, padding
0x266b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b80 [0x266b80, 0x266b84] | file +0xbd8 | ev_fd684889e15d4b26e0ee82dee8ba632bc13425741ac010622add8dae7219815d
thunk_266b80:
0x266b80: JMP 0x00964f30
; END FUNCTION thunk_266b80
0x266b85: INT3 ; original byte CC, padding
0x266b86: INT3 ; original byte CC, padding
0x266b87: INT3 ; original byte CC, padding

; FUNCTION thunk_266b88 [0x266b88, 0x266b8c] | file +0xbe0 | ev_f2df38026d5491e448e5063aac5789ad983601c453d578988858f92b6d03ae2c
thunk_266b88:
0x266b88: JMP 0x00975f50
; END FUNCTION thunk_266b88
0x266b8d: INT3 ; original byte CC, padding
0x266b8e: INT3 ; original byte CC, padding
0x266b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266b90 [0x266b90, 0x266b94] | file +0xbe8 | ev_10d8a996d05141151a80648eaa04914a17d0858789d77b5b14476705981530fe
thunk_266b90:
0x266b90: JMP 0x00976200
; END FUNCTION thunk_266b90
0x266b95: INT3 ; original byte CC, padding
0x266b96: INT3 ; original byte CC, padding
0x266b97: INT3 ; original byte CC, padding

; FUNCTION thunk_266b98 [0x266b98, 0x266b9c] | file +0xbf0 | ev_c3116b49143e9b6ff94c37355177e2bdb67bb1b2e76d75c69776fb7bb325b566
thunk_266b98:
0x266b98: JMP 0x0098c950
; END FUNCTION thunk_266b98
0x266b9d: INT3 ; original byte CC, padding
0x266b9e: INT3 ; original byte CC, padding
0x266b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba0 [0x266ba0, 0x266ba4] | file +0xbf8 | ev_d5357955364e0302a1c35a09ecc6540c8689b4e80dfafeb3e3bdcbaf003676e0
thunk_266ba0:
0x266ba0: JMP 0x0098cc30
; END FUNCTION thunk_266ba0
0x266ba5: INT3 ; original byte CC, padding
0x266ba6: INT3 ; original byte CC, padding
0x266ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ba8 [0x266ba8, 0x266bac] | file +0xc00 | ev_7eb181636e2cdb2333dd763ae4894fc17222923d697e92963d6ba4b611dcda21
thunk_266ba8:
0x266ba8: JMP 0x0098cf30
; END FUNCTION thunk_266ba8
0x266bad: INT3 ; original byte CC, padding
0x266bae: INT3 ; original byte CC, padding
0x266baf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb0 [0x266bb0, 0x266bb4] | file +0xc08 | ev_2f19404c650e0b9290f01b624e2d3247ddfabf77eef32e16a5484806b710f012
thunk_266bb0:
0x266bb0: JMP 0x0098d6e0
; END FUNCTION thunk_266bb0
0x266bb5: INT3 ; original byte CC, padding
0x266bb6: INT3 ; original byte CC, padding
0x266bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bb8 [0x266bb8, 0x266bbc] | file +0xc10 | ev_b05bb4840cd18187e9cfeab82d33fe5e27867653043f55bd77bb02218ee6fb15
thunk_266bb8:
0x266bb8: JMP 0x0098e5d0
; END FUNCTION thunk_266bb8
0x266bbd: INT3 ; original byte CC, padding
0x266bbe: INT3 ; original byte CC, padding
0x266bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc0 [0x266bc0, 0x266bc4] | file +0xc18 | ev_79af95be2d186c085c2c3aeced8a2aeeb8b6718f7d34419ecbb36bf6ed2a29e6
thunk_266bc0:
0x266bc0: JMP 0x0098e700
; END FUNCTION thunk_266bc0
0x266bc5: INT3 ; original byte CC, padding
0x266bc6: INT3 ; original byte CC, padding
0x266bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bc8 [0x266bc8, 0x266bcc] | file +0xc20 | ev_8341b535cc158bc64ba7d262cb376e3cec41502b7caeb9d18b2601d189b8c5c3
thunk_266bc8:
0x266bc8: JMP 0x00992170
; END FUNCTION thunk_266bc8
0x266bcd: INT3 ; original byte CC, padding
0x266bce: INT3 ; original byte CC, padding
0x266bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd0 [0x266bd0, 0x266bd4] | file +0xc28 | ev_e166acea8ad67d05799944a6f7fdd59ec5f3b1ac8764a5c1c9aab83775552d58
thunk_266bd0:
0x266bd0: JMP 0x00992240
; END FUNCTION thunk_266bd0
0x266bd5: INT3 ; original byte CC, padding
0x266bd6: INT3 ; original byte CC, padding
0x266bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bd8 [0x266bd8, 0x266bdc] | file +0xc30 | ev_85e73f067c4170bb5b3458130fd57a6af13915d7b31859b4fc64c3f06ed82bac
thunk_266bd8:
0x266bd8: JMP 0x000f5400
; END FUNCTION thunk_266bd8
0x266bdd: INT3 ; original byte CC, padding
0x266bde: INT3 ; original byte CC, padding
0x266bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266be0 [0x266be0, 0x266be4] | file +0xc38 | ev_842b4c5c42c065668d984eae4c9142db76b388ac3869191a2e6774a1dd29092b
thunk_266be0:
0x266be0: JMP 0x009a2320
; END FUNCTION thunk_266be0
0x266be5: INT3 ; original byte CC, padding
0x266be6: INT3 ; original byte CC, padding
0x266be7: INT3 ; original byte CC, padding

; FUNCTION thunk_266be8 [0x266be8, 0x266bec] | file +0xc40 | ev_030a86c722bd8b0115511456a8e9c167e2fcee9c0bc3fef7480f00c92d243c2a
thunk_266be8:
0x266be8: JMP 0x009a5720
; END FUNCTION thunk_266be8
0x266bed: INT3 ; original byte CC, padding
0x266bee: INT3 ; original byte CC, padding
0x266bef: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf0 [0x266bf0, 0x266bf4] | file +0xc48 | ev_b7ba618ae2aa9e42f6dc5f460eacabc57ff16a7d0aa334b8901473386f810008
thunk_266bf0:
0x266bf0: JMP 0x009ac9a0
; END FUNCTION thunk_266bf0
0x266bf5: INT3 ; original byte CC, padding
0x266bf6: INT3 ; original byte CC, padding
0x266bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266bf8 [0x266bf8, 0x266bfc] | file +0xc50 | ev_7b6dffa6d17e048eb0c5c66d7ff1892a62f7829978e4d399fec5e56368c85598
thunk_266bf8:
0x266bf8: JMP 0x009aca20
; END FUNCTION thunk_266bf8
0x266bfd: INT3 ; original byte CC, padding
0x266bfe: INT3 ; original byte CC, padding
0x266bff: INT3 ; original byte CC, padding

; FUNCTION thunk_266c00 [0x266c00, 0x266c04] | file +0xc58 | ev_37e32afc32cbfcefa497814dc4c10dc93a73d1b39133f84aeeb295f99deb9227
thunk_266c00:
0x266c00: JMP 0x001be640
; END FUNCTION thunk_266c00
0x266c05: INT3 ; original byte CC, padding
0x266c06: INT3 ; original byte CC, padding
0x266c07: INT3 ; original byte CC, padding

; FUNCTION thunk_266c08 [0x266c08, 0x266c0c] | file +0xc60 | ev_8dcbff7b878d9c7260555fdb740b8c9f57eb3ce3f0cd403b4e34d3dc8444893d
thunk_266c08:
0x266c08: JMP 0x009bed20
; END FUNCTION thunk_266c08
0x266c0d: INT3 ; original byte CC, padding
0x266c0e: INT3 ; original byte CC, padding
0x266c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c10 [0x266c10, 0x266c14] | file +0xc68 | ev_5609616af12540e3f21ffdb1c4ee50798b97a80d28d9e70d0e40685b3d52ea7b
thunk_266c10:
0x266c10: JMP 0x009c6050
; END FUNCTION thunk_266c10
0x266c15: INT3 ; original byte CC, padding
0x266c16: INT3 ; original byte CC, padding
0x266c17: INT3 ; original byte CC, padding

; FUNCTION thunk_266c18 [0x266c18, 0x266c1c] | file +0xc70 | ev_8fbdeb0835724f32a8b17a3c5d39a5e952abf35119874527c7bf6b3d2f410f4d
thunk_266c18:
0x266c18: JMP 0x009c60d0
; END FUNCTION thunk_266c18
0x266c1d: INT3 ; original byte CC, padding
0x266c1e: INT3 ; original byte CC, padding
0x266c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c20 [0x266c20, 0x266c24] | file +0xc78 | ev_ace2b7677c241f86357c44b9f6ffb12c616d9a72f498b23035be4fb0262a687f
thunk_266c20:
0x266c20: JMP 0x009c6280
; END FUNCTION thunk_266c20
0x266c25: INT3 ; original byte CC, padding
0x266c26: INT3 ; original byte CC, padding
0x266c27: INT3 ; original byte CC, padding

; FUNCTION thunk_266c28 [0x266c28, 0x266c2c] | file +0xc80 | ev_7a3062ecd30b0df2a6122e8f59b5953527a185a8647d27426de7edb4c906b7d7
thunk_266c28:
0x266c28: JMP 0x009c6310
; END FUNCTION thunk_266c28
0x266c2d: INT3 ; original byte CC, padding
0x266c2e: INT3 ; original byte CC, padding
0x266c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c30 [0x266c30, 0x266c34] | file +0xc88 | ev_dfe29f719b7475feed102705faecbfb48a5fb5cabcf650e8b213eddc01c64181
thunk_266c30:
0x266c30: JMP 0x009c6490
; END FUNCTION thunk_266c30
0x266c35: INT3 ; original byte CC, padding
0x266c36: INT3 ; original byte CC, padding
0x266c37: INT3 ; original byte CC, padding

; FUNCTION thunk_266c38 [0x266c38, 0x266c3c] | file +0xc90 | ev_f2fead07eb766b1364e16b243079bc9aa5d3876480b0d12b25b3c132c3754268
thunk_266c38:
0x266c38: JMP 0x009c65b0
; END FUNCTION thunk_266c38
0x266c3d: INT3 ; original byte CC, padding
0x266c3e: INT3 ; original byte CC, padding
0x266c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c40 [0x266c40, 0x266c44] | file +0xc98 | ev_c68ed7ba26444d1752bf6058fc28ab01a6bf926027464b2ea5e375f261cacff4
thunk_266c40:
0x266c40: JMP 0x009c6890
; END FUNCTION thunk_266c40
0x266c45: INT3 ; original byte CC, padding
0x266c46: INT3 ; original byte CC, padding
0x266c47: INT3 ; original byte CC, padding

; FUNCTION thunk_266c48 [0x266c48, 0x266c4c] | file +0xca0 | ev_67de297adfeed209dfc647b55bf4d003699078a117d7be29f97231507d06648d
thunk_266c48:
0x266c48: JMP 0x009c9340
; END FUNCTION thunk_266c48
0x266c4d: INT3 ; original byte CC, padding
0x266c4e: INT3 ; original byte CC, padding
0x266c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c50 [0x266c50, 0x266c54] | file +0xca8 | ev_f5735fce676e82d52e4f585386bb91ed4c135c29aa338a4a56a193e57e3bc696
thunk_266c50:
0x266c50: JMP 0x009c9360
; END FUNCTION thunk_266c50
0x266c55: INT3 ; original byte CC, padding
0x266c56: INT3 ; original byte CC, padding
0x266c57: INT3 ; original byte CC, padding

; FUNCTION thunk_266c58 [0x266c58, 0x266c5c] | file +0xcb0 | ev_e91b99d64f4c78087780aed0abccebaa4e78e410a865688b3acac1c9d9dbc662
thunk_266c58:
0x266c58: JMP 0x009c9370
; END FUNCTION thunk_266c58
0x266c5d: INT3 ; original byte CC, padding
0x266c5e: INT3 ; original byte CC, padding
0x266c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c60 [0x266c60, 0x266c64] | file +0xcb8 | ev_b3f6589bf2526d456f9760f6654606024f8576bc26a4405284d36ac742be9973
thunk_266c60:
0x266c60: JMP 0x009c9380
; END FUNCTION thunk_266c60
0x266c65: INT3 ; original byte CC, padding
0x266c66: INT3 ; original byte CC, padding
0x266c67: INT3 ; original byte CC, padding

; FUNCTION thunk_266c68 [0x266c68, 0x266c6c] | file +0xcc0 | ev_18322b16d894e20a403d727376dae134cc622455f406447df0dcce4b12631368
thunk_266c68:
0x266c68: JMP 0x009dadb0
; END FUNCTION thunk_266c68
0x266c6d: INT3 ; original byte CC, padding
0x266c6e: INT3 ; original byte CC, padding
0x266c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c70 [0x266c70, 0x266c74] | file +0xcc8 | ev_02cfdafda2a13e9bce9c188e0d3d2ff158067964ff4148e08d6c71ef28462e5b
thunk_266c70:
0x266c70: JMP 0x009dafa0
; END FUNCTION thunk_266c70
0x266c75: INT3 ; original byte CC, padding
0x266c76: INT3 ; original byte CC, padding
0x266c77: INT3 ; original byte CC, padding

; FUNCTION thunk_266c78 [0x266c78, 0x266c7c] | file +0xcd0 | ev_e8c329046ada8dfcbb218a69d95ad166cea9026c2e371cb78043976fdb141791
thunk_266c78:
0x266c78: JMP 0x009dc860
; END FUNCTION thunk_266c78
0x266c7d: INT3 ; original byte CC, padding
0x266c7e: INT3 ; original byte CC, padding
0x266c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c80 [0x266c80, 0x266c84] | file +0xcd8 | ev_951c7632d5f7ac048641f115f7f022df0067f8be7557f92bc19817ba1f69dce3
thunk_266c80:
0x266c80: JMP 0x009dcc40
; END FUNCTION thunk_266c80
0x266c85: INT3 ; original byte CC, padding
0x266c86: INT3 ; original byte CC, padding
0x266c87: INT3 ; original byte CC, padding

; FUNCTION thunk_266c88 [0x266c88, 0x266c8c] | file +0xce0 | ev_cb36009f9bfc136ec5ce961b8bfce675e1359e0ba638916fd42ff816e5a29426
thunk_266c88:
0x266c88: JMP 0x009dce80
; END FUNCTION thunk_266c88
0x266c8d: INT3 ; original byte CC, padding
0x266c8e: INT3 ; original byte CC, padding
0x266c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266c90 [0x266c90, 0x266c94] | file +0xce8 | ev_6cd39531681fde08c31a8a78d17c026d60656b4a04d4df9cf32e35b4ad3233b6
thunk_266c90:
0x266c90: JMP 0x009dd500
; END FUNCTION thunk_266c90
0x266c95: INT3 ; original byte CC, padding
0x266c96: INT3 ; original byte CC, padding
0x266c97: INT3 ; original byte CC, padding

; FUNCTION thunk_266c98 [0x266c98, 0x266c9c] | file +0xcf0 | ev_082dedda124d393d2915851f9fde3e738185206a07e4537279f0f861e5e538ed
thunk_266c98:
0x266c98: JMP 0x00caacd0
; END FUNCTION thunk_266c98
0x266c9d: INT3 ; original byte CC, padding
0x266c9e: INT3 ; original byte CC, padding
0x266c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca0 [0x266ca0, 0x266ca4] | file +0xcf8 | ev_9bc1d8d5795bb013c77f16ef99873037745952b9b9c7afd3662bb4d086d7ead5
thunk_266ca0:
0x266ca0: JMP 0x009dd7d0
; END FUNCTION thunk_266ca0
0x266ca5: INT3 ; original byte CC, padding
0x266ca6: INT3 ; original byte CC, padding
0x266ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ca8 [0x266ca8, 0x266cac] | file +0xd00 | ev_17560178ac1bf83794f7f4280d1fb3fc2375e475a18a6fac6d799778c6f8ebbf
thunk_266ca8:
0x266ca8: JMP 0x009dd990
; END FUNCTION thunk_266ca8
0x266cad: INT3 ; original byte CC, padding
0x266cae: INT3 ; original byte CC, padding
0x266caf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb0 [0x266cb0, 0x266cb4] | file +0xd08 | ev_93b9cede683a5db69b3564125f37c3e108fee90298840a1378e784896a40b21a
thunk_266cb0:
0x266cb0: JMP 0x009ddba0
; END FUNCTION thunk_266cb0
0x266cb5: INT3 ; original byte CC, padding
0x266cb6: INT3 ; original byte CC, padding
0x266cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cb8 [0x266cb8, 0x266cbc] | file +0xd10 | ev_17e04c234b75b5bb4b975f60d1dfe50a320d9680c9f216bf121bb91243acdb38
thunk_266cb8:
0x266cb8: JMP 0x009ddc00
; END FUNCTION thunk_266cb8
0x266cbd: INT3 ; original byte CC, padding
0x266cbe: INT3 ; original byte CC, padding
0x266cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc0 [0x266cc0, 0x266cc4] | file +0xd18 | ev_b6c802572264316e90ed3345f2a81557c2bd489791b15076650e3be79e08ff47
thunk_266cc0:
0x266cc0: JMP 0x009dde50
; END FUNCTION thunk_266cc0
0x266cc5: INT3 ; original byte CC, padding
0x266cc6: INT3 ; original byte CC, padding
0x266cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cc8 [0x266cc8, 0x266ccc] | file +0xd20 | ev_f94c0066909ed11a39e16e7896cd502d8724b3a73c0764f2f50f547302dc33d5
thunk_266cc8:
0x266cc8: JMP 0x009ddeb0
; END FUNCTION thunk_266cc8
0x266ccd: INT3 ; original byte CC, padding
0x266cce: INT3 ; original byte CC, padding
0x266ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd0 [0x266cd0, 0x266cd4] | file +0xd28 | ev_348cb7baeed000a9d33e2e381076de9fb9b8615b007f637a8eb38169607b542e
thunk_266cd0:
0x266cd0: JMP 0x009ddff0
; END FUNCTION thunk_266cd0
0x266cd5: INT3 ; original byte CC, padding
0x266cd6: INT3 ; original byte CC, padding
0x266cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cd8 [0x266cd8, 0x266cdc] | file +0xd30 | ev_fc58a66b8aa11327158592a2683a5409b088dbfa3e73c567d2114c597deb93bc
thunk_266cd8:
0x266cd8: JMP 0x009de070
; END FUNCTION thunk_266cd8
0x266cdd: INT3 ; original byte CC, padding
0x266cde: INT3 ; original byte CC, padding
0x266cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce0 [0x266ce0, 0x266ce4] | file +0xd38 | ev_5475722fc4118f733e9a73ddbd7446a54dc4ad626a95e9c9f0448cc18e9f996e
thunk_266ce0:
0x266ce0: JMP 0x009de0f0
; END FUNCTION thunk_266ce0
0x266ce5: INT3 ; original byte CC, padding
0x266ce6: INT3 ; original byte CC, padding
0x266ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ce8 [0x266ce8, 0x266cec] | file +0xd40 | ev_fdafddb450a802d82260ceae9a715e28314e8881a70b3d59b8493179b1961500
thunk_266ce8:
0x266ce8: JMP 0x009e0b90
; END FUNCTION thunk_266ce8
0x266ced: INT3 ; original byte CC, padding
0x266cee: INT3 ; original byte CC, padding
0x266cef: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf0 [0x266cf0, 0x266cf4] | file +0xd48 | ev_8cefa82a89b7b4b45c99217e6cd0bee8439d24511d15edc5beb5541815716e5c
thunk_266cf0:
0x266cf0: JMP 0x009e0cd0
; END FUNCTION thunk_266cf0
0x266cf5: INT3 ; original byte CC, padding
0x266cf6: INT3 ; original byte CC, padding
0x266cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_266cf8 [0x266cf8, 0x266cfc] | file +0xd50 | ev_0fe31e9a802c16bff487f3ffa6fe768146a74631329f957dd9bc3dca74021aca
thunk_266cf8:
0x266cf8: JMP 0x009e0d70
; END FUNCTION thunk_266cf8
0x266cfd: INT3 ; original byte CC, padding
0x266cfe: INT3 ; original byte CC, padding
0x266cff: INT3 ; original byte CC, padding

; FUNCTION thunk_266d00 [0x266d00, 0x266d04] | file +0xd58 | ev_e5cce5cafece25832e81d202bbaf98d746251944792d147620e609bdc88a079b
thunk_266d00:
0x266d00: JMP 0x009e0ef0
; END FUNCTION thunk_266d00
0x266d05: INT3 ; original byte CC, padding
0x266d06: INT3 ; original byte CC, padding
0x266d07: INT3 ; original byte CC, padding

; FUNCTION thunk_266d08 [0x266d08, 0x266d0c] | file +0xd60 | ev_a5c6e76db2b06ad96ad752996fbb0d43af1311a603e951d09dc0718da26264e1
thunk_266d08:
0x266d08: JMP 0x009e1050
; END FUNCTION thunk_266d08
0x266d0d: INT3 ; original byte CC, padding
0x266d0e: INT3 ; original byte CC, padding
0x266d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d10 [0x266d10, 0x266d14] | file +0xd68 | ev_2ff4d8779640ec27c7a42ba2bd832a1062c3067640217eabf3eafa58a6ac14c7
thunk_266d10:
0x266d10: JMP 0x009e1490
; END FUNCTION thunk_266d10
0x266d15: INT3 ; original byte CC, padding
0x266d16: INT3 ; original byte CC, padding
0x266d17: INT3 ; original byte CC, padding

; FUNCTION thunk_266d18 [0x266d18, 0x266d1c] | file +0xd70 | ev_b7780a59bec1d8f90378ae9653e3982c89c7992f914096c62690d8fcc0b31a94
thunk_266d18:
0x266d18: JMP 0x00a065e0
; END FUNCTION thunk_266d18
0x266d1d: INT3 ; original byte CC, padding
0x266d1e: INT3 ; original byte CC, padding
0x266d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d20 [0x266d20, 0x266d24] | file +0xd78 | ev_d10f566f8d9de96267472087c1f37a7479708a48744751f0d311c1c622dd3904
thunk_266d20:
0x266d20: JMP 0x00101340
; END FUNCTION thunk_266d20
0x266d25: INT3 ; original byte CC, padding
0x266d26: INT3 ; original byte CC, padding
0x266d27: INT3 ; original byte CC, padding

; FUNCTION thunk_266d28 [0x266d28, 0x266d2c] | file +0xd80 | ev_b14ed9d81a695319fa6e7c6ebdc5b570f764a5554a4fc0c40148baafde815686
thunk_266d28:
0x266d28: JMP 0x00a32f30
; END FUNCTION thunk_266d28
0x266d2d: INT3 ; original byte CC, padding
0x266d2e: INT3 ; original byte CC, padding
0x266d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d30 [0x266d30, 0x266d34] | file +0xd88 | ev_6ceedf1cd0b694a6020d0489577c66021b95c6e6acf4a93dbeabde86d9f6d391
thunk_266d30:
0x266d30: JMP 0x00a336c0
; END FUNCTION thunk_266d30
0x266d35: INT3 ; original byte CC, padding
0x266d36: INT3 ; original byte CC, padding
0x266d37: INT3 ; original byte CC, padding

; FUNCTION thunk_266d38 [0x266d38, 0x266d3c] | file +0xd90 | ev_f404fb3364f869a944ee99aeb16bd33ff7e315fa9ba80c315a591d04d77c5cd9
thunk_266d38:
0x266d38: JMP 0x00a38c90
; END FUNCTION thunk_266d38
0x266d3d: INT3 ; original byte CC, padding
0x266d3e: INT3 ; original byte CC, padding
0x266d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d40 [0x266d40, 0x266d44] | file +0xd98 | ev_78ce9ed99aaf60ae3f7ddffd51b979932236ff54bce8de0b8b30a669f28d85da
thunk_266d40:
0x266d40: JMP 0x00a6ab00
; END FUNCTION thunk_266d40
0x266d45: INT3 ; original byte CC, padding
0x266d46: INT3 ; original byte CC, padding
0x266d47: INT3 ; original byte CC, padding

; FUNCTION thunk_266d48 [0x266d48, 0x266d4c] | file +0xda0 | ev_b5a719e3051b394916925482ba873b496bcb34a1988407017a610457c6c23429
thunk_266d48:
0x266d48: JMP 0x00a6abb0
; END FUNCTION thunk_266d48
0x266d4d: INT3 ; original byte CC, padding
0x266d4e: INT3 ; original byte CC, padding
0x266d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d50 [0x266d50, 0x266d54] | file +0xda8 | ev_66a8e1394f6126ff166804a7b4117339bcc651d2b89fb684b756a8507994bdcf
thunk_266d50:
0x266d50: JMP 0x00a8ec10
; END FUNCTION thunk_266d50
0x266d55: INT3 ; original byte CC, padding
0x266d56: INT3 ; original byte CC, padding
0x266d57: INT3 ; original byte CC, padding

; FUNCTION thunk_266d58 [0x266d58, 0x266d5c] | file +0xdb0 | ev_8d5fb3fe87100ad2ba04f2e7e973447e53c90e2e406a2a38099b02122b3e9869
thunk_266d58:
0x266d58: JMP 0x00a8ee00
; END FUNCTION thunk_266d58
0x266d5d: INT3 ; original byte CC, padding
0x266d5e: INT3 ; original byte CC, padding
0x266d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d60 [0x266d60, 0x266d64] | file +0xdb8 | ev_5c2e94bdbf3948c0843d6ef9b29810c9a403493954312eb1180300ffe4515545
thunk_266d60:
0x266d60: JMP 0x00ab17b0
; END FUNCTION thunk_266d60
0x266d65: INT3 ; original byte CC, padding
0x266d66: INT3 ; original byte CC, padding
0x266d67: INT3 ; original byte CC, padding

; FUNCTION thunk_266d68 [0x266d68, 0x266d6c] | file +0xdc0 | ev_6b4bef6b5f4bc828de6f53ae7485814885aa93b10e589f519b41bb23e3162800
thunk_266d68:
0x266d68: JMP 0x00ac07b0
; END FUNCTION thunk_266d68
0x266d6d: INT3 ; original byte CC, padding
0x266d6e: INT3 ; original byte CC, padding
0x266d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d70 [0x266d70, 0x266d74] | file +0xdc8 | ev_bdce12fae65c55b0c7513e875b769c11d4280239f3d72373aaab9e9766afbaac
thunk_266d70:
0x266d70: JMP 0x00ac2af0
; END FUNCTION thunk_266d70
0x266d75: INT3 ; original byte CC, padding
0x266d76: INT3 ; original byte CC, padding
0x266d77: INT3 ; original byte CC, padding

; FUNCTION thunk_266d78 [0x266d78, 0x266d7c] | file +0xdd0 | ev_2680b60f9cb23d12b0b0ecaabdc08d843be220023793fdb28f8eee6ca7229a5d
thunk_266d78:
0x266d78: JMP 0x0011a750
; END FUNCTION thunk_266d78
0x266d7d: INT3 ; original byte CC, padding
0x266d7e: INT3 ; original byte CC, padding
0x266d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d80 [0x266d80, 0x266d84] | file +0xdd8 | ev_9af6b1d5b9f45778621c3ee062e58fca2c11a641863e209779c6d2054ed827fb
thunk_266d80:
0x266d80: JMP 0x00ae12a0
; END FUNCTION thunk_266d80
0x266d85: INT3 ; original byte CC, padding
0x266d86: INT3 ; original byte CC, padding
0x266d87: INT3 ; original byte CC, padding

; FUNCTION thunk_266d88 [0x266d88, 0x266d8c] | file +0xde0 | ev_8646eab0650b71883c11f7cdbab5c072bb7067fc4b651fe6d4ff533834d1400e
thunk_266d88:
0x266d88: JMP 0x00ae3400
; END FUNCTION thunk_266d88
0x266d8d: INT3 ; original byte CC, padding
0x266d8e: INT3 ; original byte CC, padding
0x266d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266d90 [0x266d90, 0x266d94] | file +0xde8 | ev_ce1d8c6ab3f2ba46d018490e9359180b1341e43b3fbb4718438a184c713f0e55
thunk_266d90:
0x266d90: JMP 0x00ae3530
; END FUNCTION thunk_266d90
0x266d95: INT3 ; original byte CC, padding
0x266d96: INT3 ; original byte CC, padding
0x266d97: INT3 ; original byte CC, padding

; FUNCTION thunk_266d98 [0x266d98, 0x266d9c] | file +0xdf0 | ev_bee1965f99007cbadf8a23a84f31148a5140aa1948ea011f5abff7a1602a8ffc
thunk_266d98:
0x266d98: JMP 0x00ae63c0
; END FUNCTION thunk_266d98
0x266d9d: INT3 ; original byte CC, padding
0x266d9e: INT3 ; original byte CC, padding
0x266d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266da0 [0x266da0, 0x266da4] | file +0xdf8 | ev_021586ff9f269dedbb283491c1f5fef34dda25f2b408fa051a6134e2f95edd7d
thunk_266da0:
0x266da0: JMP 0x00b07ee0
; END FUNCTION thunk_266da0
0x266da5: INT3 ; original byte CC, padding
0x266da6: INT3 ; original byte CC, padding
0x266da7: INT3 ; original byte CC, padding

; FUNCTION thunk_266da8 [0x266da8, 0x266dac] | file +0xe00 | ev_661897bcc4d7235e95c9ece8b99683b3005da66501d8fb0d0dec17557ed248b7
thunk_266da8:
0x266da8: JMP 0x00b08190
; END FUNCTION thunk_266da8
0x266dad: INT3 ; original byte CC, padding
0x266dae: INT3 ; original byte CC, padding
0x266daf: INT3 ; original byte CC, padding

; FUNCTION thunk_266db0 [0x266db0, 0x266db4] | file +0xe08 | ev_a51657bb9adaf2b46acb636dab82aea2afbd24344b38ec9fc62f4a5cb75b4c3f
thunk_266db0:
0x266db0: JMP 0x00b08530
; END FUNCTION thunk_266db0
0x266db5: INT3 ; original byte CC, padding
0x266db6: INT3 ; original byte CC, padding
0x266db7: INT3 ; original byte CC, padding

; FUNCTION thunk_266db8 [0x266db8, 0x266dbc] | file +0xe10 | ev_7bd6608e24ea1d58427542d7fe6b513031f58af19140f4dc92741a8a3df9ee06
thunk_266db8:
0x266db8: JMP 0x00b08810
; END FUNCTION thunk_266db8
0x266dbd: INT3 ; original byte CC, padding
0x266dbe: INT3 ; original byte CC, padding
0x266dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc0 [0x266dc0, 0x266dc4] | file +0xe18 | ev_f09ac987114e244788a375bb4fcf7afd7ce4c964fa2b7bf4a6afafeb24830e03
thunk_266dc0:
0x266dc0: JMP 0x00b096a0
; END FUNCTION thunk_266dc0
0x266dc5: INT3 ; original byte CC, padding
0x266dc6: INT3 ; original byte CC, padding
0x266dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dc8 [0x266dc8, 0x266dcc] | file +0xe20 | ev_dfc611f60173bd5832d71e5b7ec488439560cad77e88931e8d7c64545c725a45
thunk_266dc8:
0x266dc8: JMP 0x00b0b4f0
; END FUNCTION thunk_266dc8
0x266dcd: INT3 ; original byte CC, padding
0x266dce: INT3 ; original byte CC, padding
0x266dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd0 [0x266dd0, 0x266dd4] | file +0xe28 | ev_7ddaa2bd15e3b28548a4a9c293e73ca9bc9385206edec45703a1cbcbdfd80bbe
thunk_266dd0:
0x266dd0: JMP 0x001ef0f0
; END FUNCTION thunk_266dd0
0x266dd5: INT3 ; original byte CC, padding
0x266dd6: INT3 ; original byte CC, padding
0x266dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_266dd8 [0x266dd8, 0x266ddc] | file +0xe30 | ev_0fd6893fc896b88e9e684bdcf1f2df886f46d9b79d06e9e8e6ac0024f32f3aed
thunk_266dd8:
0x266dd8: JMP 0x001f0060
; END FUNCTION thunk_266dd8
0x266ddd: INT3 ; original byte CC, padding
0x266dde: INT3 ; original byte CC, padding
0x266ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_266de0 [0x266de0, 0x266de4] | file +0xe38 | ev_f3e343791d1960e5d9ab7af96634393b0613d3a4f218256929e2f8033104ac7d
thunk_266de0:
0x266de0: JMP 0x0011b9b0
; END FUNCTION thunk_266de0
0x266de5: INT3 ; original byte CC, padding
0x266de6: INT3 ; original byte CC, padding
0x266de7: INT3 ; original byte CC, padding

; FUNCTION thunk_266de8 [0x266de8, 0x266dec] | file +0xe40 | ev_3256847e0571f12a26c9637636d3c4e54696270caa3cb68eeaae5a004b6a850f
thunk_266de8:
0x266de8: JMP 0x00b3b130
; END FUNCTION thunk_266de8
0x266ded: INT3 ; original byte CC, padding
0x266dee: INT3 ; original byte CC, padding
0x266def: INT3 ; original byte CC, padding

; FUNCTION thunk_266df0 [0x266df0, 0x266df4] | file +0xe48 | ev_a4d5a58087cc50f89a43a0c946224b55c585f59dde0dbe33701b96ad42036a63
thunk_266df0:
0x266df0: JMP 0x00b47a40
; END FUNCTION thunk_266df0
0x266df5: INT3 ; original byte CC, padding
0x266df6: INT3 ; original byte CC, padding
0x266df7: INT3 ; original byte CC, padding

; FUNCTION thunk_266df8 [0x266df8, 0x266dfc] | file +0xe50 | ev_6f9f553619e79fa117711aa664214bf407cb896470edfaed2fa80b975c20998e
thunk_266df8:
0x266df8: JMP 0x00b503c0
; END FUNCTION thunk_266df8
0x266dfd: INT3 ; original byte CC, padding
0x266dfe: INT3 ; original byte CC, padding
0x266dff: INT3 ; original byte CC, padding

; FUNCTION thunk_266e00 [0x266e00, 0x266e04] | file +0xe58 | ev_5bb72f86362afb6f491fa4944eac459ad974d898a733bc1701ce28ccee3366a3
thunk_266e00:
0x266e00: JMP 0x00b50f10
; END FUNCTION thunk_266e00
0x266e05: INT3 ; original byte CC, padding
0x266e06: INT3 ; original byte CC, padding
0x266e07: INT3 ; original byte CC, padding

; FUNCTION thunk_266e08 [0x266e08, 0x266e0c] | file +0xe60 | ev_4626fe3df4c069cb8aaac5384079b00f151bec62d68c9553e9ed7c8a4fd75c42
thunk_266e08:
0x266e08: JMP 0x00b50fb0
; END FUNCTION thunk_266e08
0x266e0d: INT3 ; original byte CC, padding
0x266e0e: INT3 ; original byte CC, padding
0x266e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e10 [0x266e10, 0x266e14] | file +0xe68 | ev_6d4603bdb31502b309b8835180f360ba961490d6273d111b6f01a175e50b17af
thunk_266e10:
0x266e10: JMP 0x00b510b0
; END FUNCTION thunk_266e10
0x266e15: INT3 ; original byte CC, padding
0x266e16: INT3 ; original byte CC, padding
0x266e17: INT3 ; original byte CC, padding

; FUNCTION thunk_266e18 [0x266e18, 0x266e1c] | file +0xe70 | ev_396af73daa982841b9f11dfa441c9e266f5a927b17b979985cd9ca8a0a5fdb68
thunk_266e18:
0x266e18: JMP 0x00b51190
; END FUNCTION thunk_266e18
0x266e1d: INT3 ; original byte CC, padding
0x266e1e: INT3 ; original byte CC, padding
0x266e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e20 [0x266e20, 0x266e24] | file +0xe78 | ev_fffc298efdf0b5e0e2e4378571521024ffa8e4aca9043008d1e61ce816203c66
thunk_266e20:
0x266e20: JMP 0x00b51290
; END FUNCTION thunk_266e20
0x266e25: INT3 ; original byte CC, padding
0x266e26: INT3 ; original byte CC, padding
0x266e27: INT3 ; original byte CC, padding

; FUNCTION thunk_266e28 [0x266e28, 0x266e2c] | file +0xe80 | ev_e8ef76577eaac3fab3c793b7168e9da12dc1aca576c7a71fa3f557e237c2e4e6
thunk_266e28:
0x266e28: JMP 0x00b512d0
; END FUNCTION thunk_266e28
0x266e2d: INT3 ; original byte CC, padding
0x266e2e: INT3 ; original byte CC, padding
0x266e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e30 [0x266e30, 0x266e34] | file +0xe88 | ev_4db31287f09e0ae97956058a96dfe8fd3e5528ddc6f25d486a7433aaa211b322
thunk_266e30:
0x266e30: JMP 0x00b51320
; END FUNCTION thunk_266e30
0x266e35: INT3 ; original byte CC, padding
0x266e36: INT3 ; original byte CC, padding
0x266e37: INT3 ; original byte CC, padding

; FUNCTION thunk_266e38 [0x266e38, 0x266e3c] | file +0xe90 | ev_8ecf5e88ea4bb913a7d602178eeaa9d978ee9a7b5cd012aa8894b369ad41550d
thunk_266e38:
0x266e38: JMP 0x00b568a0
; END FUNCTION thunk_266e38
0x266e3d: INT3 ; original byte CC, padding
0x266e3e: INT3 ; original byte CC, padding
0x266e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e40 [0x266e40, 0x266e44] | file +0xe98 | ev_8e75b68ffdcee668e3cc8060cc48f0eec1a2ba00367b0ea233f6c43f8765a777
thunk_266e40:
0x266e40: JMP 0x0009a0e0
; END FUNCTION thunk_266e40
0x266e45: INT3 ; original byte CC, padding
0x266e46: INT3 ; original byte CC, padding
0x266e47: INT3 ; original byte CC, padding

; FUNCTION thunk_266e48 [0x266e48, 0x266e4c] | file +0xea0 | ev_1449cb43daa60b62cab63d755b2a2ddd18efb47331cc52035ef5c3a04310475e
thunk_266e48:
0x266e48: JMP 0x00b6ae70
; END FUNCTION thunk_266e48
0x266e4d: INT3 ; original byte CC, padding
0x266e4e: INT3 ; original byte CC, padding
0x266e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e50 [0x266e50, 0x266e54] | file +0xea8 | ev_e5c757c666e1090a3ec377473f91b1bae5a6549c03db2270345898d87c0b067e
thunk_266e50:
0x266e50: JMP 0x00b6bb90
; END FUNCTION thunk_266e50
0x266e55: INT3 ; original byte CC, padding
0x266e56: INT3 ; original byte CC, padding
0x266e57: INT3 ; original byte CC, padding

; FUNCTION thunk_266e58 [0x266e58, 0x266e5c] | file +0xeb0 | ev_8bf126f87d6604a0a94aed580fc13864f2b4286b1b4f03fb9394afeb53816a34
thunk_266e58:
0x266e58: JMP 0x00b6d980
; END FUNCTION thunk_266e58
0x266e5d: INT3 ; original byte CC, padding
0x266e5e: INT3 ; original byte CC, padding
0x266e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e60 [0x266e60, 0x266e64] | file +0xeb8 | ev_7ca6cb21dc0b6f25698862493a2d6b95a19babe9efefa4bd242d6e79af31bb98
thunk_266e60:
0x266e60: JMP 0x00b6daa0
; END FUNCTION thunk_266e60
0x266e65: INT3 ; original byte CC, padding
0x266e66: INT3 ; original byte CC, padding
0x266e67: INT3 ; original byte CC, padding

; FUNCTION thunk_266e68 [0x266e68, 0x266e6c] | file +0xec0 | ev_d64bbe0b19de218b1913ecc94394fde4fbf612ee3092f588edf5fd97efaed577
thunk_266e68:
0x266e68: JMP 0x00b6e180
; END FUNCTION thunk_266e68
0x266e6d: INT3 ; original byte CC, padding
0x266e6e: INT3 ; original byte CC, padding
0x266e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e70 [0x266e70, 0x266e74] | file +0xec8 | ev_f2be95566a6f3f55ffa0867891aa84abb05e686b116e083938852c5ad30c9053
thunk_266e70:
0x266e70: JMP 0x00b71320
; END FUNCTION thunk_266e70
0x266e75: INT3 ; original byte CC, padding
0x266e76: INT3 ; original byte CC, padding
0x266e77: INT3 ; original byte CC, padding

; FUNCTION thunk_266e78 [0x266e78, 0x266e7c] | file +0xed0 | ev_ea30d5c8cc955f26bc1887e696b4cdd9d0f470d328a1f7fcff151a10e904bf5b
thunk_266e78:
0x266e78: JMP 0x00b71370
; END FUNCTION thunk_266e78
0x266e7d: INT3 ; original byte CC, padding
0x266e7e: INT3 ; original byte CC, padding
0x266e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e80 [0x266e80, 0x266e84] | file +0xed8 | ev_c63e3871926c8e72b579d264e85f38382d783da0d0b04d4be00b01031822fb25
thunk_266e80:
0x266e80: JMP 0x00b713c0
; END FUNCTION thunk_266e80
0x266e85: INT3 ; original byte CC, padding
0x266e86: INT3 ; original byte CC, padding
0x266e87: INT3 ; original byte CC, padding

; FUNCTION thunk_266e88 [0x266e88, 0x266e8c] | file +0xee0 | ev_197d591bf203fc30e38d796f069d211a923ba60199a8f018b65658b3f5f32eb8
thunk_266e88:
0x266e88: JMP 0x00b71410
; END FUNCTION thunk_266e88
0x266e8d: INT3 ; original byte CC, padding
0x266e8e: INT3 ; original byte CC, padding
0x266e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266e90 [0x266e90, 0x266e94] | file +0xee8 | ev_06c505a8945df64cf395d995cbc9ef4d39ffbb334ac8940eaf15b821d76a2e1f
thunk_266e90:
0x266e90: JMP 0x00b71960
; END FUNCTION thunk_266e90
0x266e95: INT3 ; original byte CC, padding
0x266e96: INT3 ; original byte CC, padding
0x266e97: INT3 ; original byte CC, padding

; FUNCTION thunk_266e98 [0x266e98, 0x266e9c] | file +0xef0 | ev_92cf65c6497d81c189072201bc92b6d001023852b15682c6e7045a41c5b4996f
thunk_266e98:
0x266e98: JMP 0x00b719d0
; END FUNCTION thunk_266e98
0x266e9d: INT3 ; original byte CC, padding
0x266e9e: INT3 ; original byte CC, padding
0x266e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea0 [0x266ea0, 0x266ea4] | file +0xef8 | ev_645a6b9f18cf77202c1f3379a167a483992f1abe64ade57cf4679057b81f8132
thunk_266ea0:
0x266ea0: JMP 0x00b71a40
; END FUNCTION thunk_266ea0
0x266ea5: INT3 ; original byte CC, padding
0x266ea6: INT3 ; original byte CC, padding
0x266ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ea8 [0x266ea8, 0x266eac] | file +0xf00 | ev_92f8a51544605bc7f4dfb2d3f45f27341d959314143b088056208c2ce0daf354
thunk_266ea8:
0x266ea8: JMP 0x00b71ab0
; END FUNCTION thunk_266ea8
0x266ead: INT3 ; original byte CC, padding
0x266eae: INT3 ; original byte CC, padding
0x266eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb0 [0x266eb0, 0x266eb4] | file +0xf08 | ev_86e42877162f49237f5ee3cc1fa9b5e7317d73fd40d6536966932f7792fb38d9
thunk_266eb0:
0x266eb0: JMP 0x00b72620
; END FUNCTION thunk_266eb0
0x266eb5: INT3 ; original byte CC, padding
0x266eb6: INT3 ; original byte CC, padding
0x266eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_266eb8 [0x266eb8, 0x266ebc] | file +0xf10 | ev_001011f1bff1e10ce4ca0cb454363095736c0cef7656de7f95cc7986ab85c6f4
thunk_266eb8:
0x266eb8: JMP 0x00b72860
; END FUNCTION thunk_266eb8
0x266ebd: INT3 ; original byte CC, padding
0x266ebe: INT3 ; original byte CC, padding
0x266ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec0 [0x266ec0, 0x266ec4] | file +0xf18 | ev_a62bc6806ab674d0ae71f374d1e8ebd1b76781dbf590ebc9087c31322e2462e2
thunk_266ec0:
0x266ec0: JMP 0x00b791d0
; END FUNCTION thunk_266ec0
0x266ec5: INT3 ; original byte CC, padding
0x266ec6: INT3 ; original byte CC, padding
0x266ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ec8 [0x266ec8, 0x266ecc] | file +0xf20 | ev_b52289221c273125b1dbccaf11fa3a6fd7e6246284d8522934c98ec91d8d206e
thunk_266ec8:
0x266ec8: JMP 0x00b79290
; END FUNCTION thunk_266ec8
0x266ecd: INT3 ; original byte CC, padding
0x266ece: INT3 ; original byte CC, padding
0x266ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed0 [0x266ed0, 0x266ed4] | file +0xf28 | ev_4047cbc663795c1289163dbe21ac08af15171a76058b17f7e22314c363bc8a5c
thunk_266ed0:
0x266ed0: JMP 0x00b793f0
; END FUNCTION thunk_266ed0
0x266ed5: INT3 ; original byte CC, padding
0x266ed6: INT3 ; original byte CC, padding
0x266ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ed8 [0x266ed8, 0x266edc] | file +0xf30 | ev_d40229b3fb879733cf4bb36ba96438639d574a7aaaf01b902462653bec434bc0
thunk_266ed8:
0x266ed8: JMP 0x00b79420
; END FUNCTION thunk_266ed8
0x266edd: INT3 ; original byte CC, padding
0x266ede: INT3 ; original byte CC, padding
0x266edf: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee0 [0x266ee0, 0x266ee4] | file +0xf38 | ev_9c460fc45aabe04141735909271220fd15d8255d47b0abc66e0f74511b093105
thunk_266ee0:
0x266ee0: JMP 0x00b79460
; END FUNCTION thunk_266ee0
0x266ee5: INT3 ; original byte CC, padding
0x266ee6: INT3 ; original byte CC, padding
0x266ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ee8 [0x266ee8, 0x266eec] | file +0xf40 | ev_140eeb12e1434a7dc0c137ae75e06af03c16e376698cbc46dfa3d10d190ea107
thunk_266ee8:
0x266ee8: JMP 0x00b79480
; END FUNCTION thunk_266ee8
0x266eed: INT3 ; original byte CC, padding
0x266eee: INT3 ; original byte CC, padding
0x266eef: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef0 [0x266ef0, 0x266ef4] | file +0xf48 | ev_43ad813f5b2b8f40c57dc086f2c412e940abf4ceca224978018e13b0f33a7820
thunk_266ef0:
0x266ef0: JMP 0x00b79490
; END FUNCTION thunk_266ef0
0x266ef5: INT3 ; original byte CC, padding
0x266ef6: INT3 ; original byte CC, padding
0x266ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_266ef8 [0x266ef8, 0x266efc] | file +0xf50 | ev_bfec69b84024565b47c924a86acddbcc1709c8816cf063cd4839f05a0efb3a66
thunk_266ef8:
0x266ef8: JMP 0x00b794b0
; END FUNCTION thunk_266ef8
0x266efd: INT3 ; original byte CC, padding
0x266efe: INT3 ; original byte CC, padding
0x266eff: INT3 ; original byte CC, padding

; FUNCTION thunk_266f00 [0x266f00, 0x266f04] | file +0xf58 | ev_c1e937b17f609327e5a32dc651db69965da91c36afed6b6cab4eeb2ddbc66ade
thunk_266f00:
0x266f00: JMP 0x00b795f0
; END FUNCTION thunk_266f00
0x266f05: INT3 ; original byte CC, padding
0x266f06: INT3 ; original byte CC, padding
0x266f07: INT3 ; original byte CC, padding

; FUNCTION thunk_266f08 [0x266f08, 0x266f0c] | file +0xf60 | ev_54cd41ab36c1d893c67c9e91dd3bac8054c2a093aa3ff842a2b4ac493f1af467
thunk_266f08:
0x266f08: JMP 0x00b79620
; END FUNCTION thunk_266f08
0x266f0d: INT3 ; original byte CC, padding
0x266f0e: INT3 ; original byte CC, padding
0x266f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f10 [0x266f10, 0x266f14] | file +0xf68 | ev_5f150108a282e0acbbf087f0447711d5f934b501ef033bcb4651c0a0bff06097
thunk_266f10:
0x266f10: JMP 0x00b79830
; END FUNCTION thunk_266f10
0x266f15: INT3 ; original byte CC, padding
0x266f16: INT3 ; original byte CC, padding
0x266f17: INT3 ; original byte CC, padding

; FUNCTION thunk_266f18 [0x266f18, 0x266f1c] | file +0xf70 | ev_2da7c7533a24f08c54a5ec5ef15fbab9a37ad41832c00dd6f045c392f203f1ab
thunk_266f18:
0x266f18: JMP 0x00b80e90
; END FUNCTION thunk_266f18
0x266f1d: INT3 ; original byte CC, padding
0x266f1e: INT3 ; original byte CC, padding
0x266f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f20 [0x266f20, 0x266f24] | file +0xf78 | ev_05007cf428f229f9acad957f05bfd0d915fc31a6bd8f53b6d71023441c636a5b
thunk_266f20:
0x266f20: JMP 0x00b80f20
; END FUNCTION thunk_266f20
0x266f25: INT3 ; original byte CC, padding
0x266f26: INT3 ; original byte CC, padding
0x266f27: INT3 ; original byte CC, padding

; FUNCTION thunk_266f28 [0x266f28, 0x266f2c] | file +0xf80 | ev_4af2057d7b385aba4d6285ec88eaf49753f05817a916e45e8dad4635faa00a15
thunk_266f28:
0x266f28: JMP 0x00b99520
; END FUNCTION thunk_266f28
0x266f2d: INT3 ; original byte CC, padding
0x266f2e: INT3 ; original byte CC, padding
0x266f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f30 [0x266f30, 0x266f34] | file +0xf88 | ev_7031656535bffe683040d3e65d44680a84556f146e6c8250261208dfd70560bd
thunk_266f30:
0x266f30: JMP 0x00b99600
; END FUNCTION thunk_266f30
0x266f35: INT3 ; original byte CC, padding
0x266f36: INT3 ; original byte CC, padding
0x266f37: INT3 ; original byte CC, padding

; FUNCTION thunk_266f38 [0x266f38, 0x266f3c] | file +0xf90 | ev_1c665d019d7d1f2e53f07e261e031cb899f97da44155def954621c2a02570d06
thunk_266f38:
0x266f38: JMP 0x00b9ce30
; END FUNCTION thunk_266f38
0x266f3d: INT3 ; original byte CC, padding
0x266f3e: INT3 ; original byte CC, padding
0x266f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f40 [0x266f40, 0x266f44] | file +0xf98 | ev_712648e7bb521b61edaa5cabe0db3056f43183e8708033b54aa034674b67ec39
thunk_266f40:
0x266f40: JMP 0x00bf5c40
; END FUNCTION thunk_266f40
0x266f45: INT3 ; original byte CC, padding
0x266f46: INT3 ; original byte CC, padding
0x266f47: INT3 ; original byte CC, padding

; FUNCTION thunk_266f48 [0x266f48, 0x266f4c] | file +0xfa0 | ev_ecc803a493b1fccc01b711533b2c9a2508d39c49fd905d6689592f58ab23fd2e
thunk_266f48:
0x266f48: JMP 0x00bfe620
; END FUNCTION thunk_266f48
0x266f4d: INT3 ; original byte CC, padding
0x266f4e: INT3 ; original byte CC, padding
0x266f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f50 [0x266f50, 0x266f54] | file +0xfa8 | ev_03cc54ab31ccc520062b136e5769020cebdfb08c0270e94138249b5af9660c5b
thunk_266f50:
0x266f50: JMP 0x00bfef50
; END FUNCTION thunk_266f50
0x266f55: INT3 ; original byte CC, padding
0x266f56: INT3 ; original byte CC, padding
0x266f57: INT3 ; original byte CC, padding

; FUNCTION thunk_266f58 [0x266f58, 0x266f5c] | file +0xfb0 | ev_98503194680b5b3c8554d5b9cf932e290985606a681d50620a2ec04984c2ec5c
thunk_266f58:
0x266f58: JMP 0x00bfefa0
; END FUNCTION thunk_266f58
0x266f5d: INT3 ; original byte CC, padding
0x266f5e: INT3 ; original byte CC, padding
0x266f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f60 [0x266f60, 0x266f64] | file +0xfb8 | ev_b59c9075b71bcf6d9e1b7028c4325ca035da423d9c7567967949cb9421601b48
thunk_266f60:
0x266f60: JMP 0x00bff050
; END FUNCTION thunk_266f60
0x266f65: INT3 ; original byte CC, padding
0x266f66: INT3 ; original byte CC, padding
0x266f67: INT3 ; original byte CC, padding

; FUNCTION thunk_266f68 [0x266f68, 0x266f6c] | file +0xfc0 | ev_8365df9cf079d90dcca0b3cc08c697935064c4c8ed974c3515e1b4fa381c7611
thunk_266f68:
0x266f68: JMP 0x00c0d180
; END FUNCTION thunk_266f68
0x266f6d: INT3 ; original byte CC, padding
0x266f6e: INT3 ; original byte CC, padding
0x266f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f70 [0x266f70, 0x266f74] | file +0xfc8 | ev_ccee922592c335279de79cd9aa606fdbcd9169a04fe4fa1dd80e272430eeba58
thunk_266f70:
0x266f70: JMP 0x00c327f0
; END FUNCTION thunk_266f70
0x266f75: INT3 ; original byte CC, padding
0x266f76: INT3 ; original byte CC, padding
0x266f77: INT3 ; original byte CC, padding

; FUNCTION thunk_266f78 [0x266f78, 0x266f7c] | file +0xfd0 | ev_adf5b626a55425949b3e14eb88a6b151c2d534648b904e1b408b9d640aa34a9a
thunk_266f78:
0x266f78: JMP 0x00c32c70
; END FUNCTION thunk_266f78
0x266f7d: INT3 ; original byte CC, padding
0x266f7e: INT3 ; original byte CC, padding
0x266f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f80 [0x266f80, 0x266f84] | file +0xfd8 | ev_23a75b00a0d112a651e95c44dd54487f36c7f2b35308b90ea97aa3cd0c987b02
thunk_266f80:
0x266f80: JMP 0x00c34c70
; END FUNCTION thunk_266f80
0x266f85: INT3 ; original byte CC, padding
0x266f86: INT3 ; original byte CC, padding
0x266f87: INT3 ; original byte CC, padding

; FUNCTION thunk_266f88 [0x266f88, 0x266f8c] | file +0xfe0 | ev_eafa2e51eddea43a0ada57d0319d1511ea788cff8d813d79adea309a0bd72f97
thunk_266f88:
0x266f88: JMP 0x00c34df0
; END FUNCTION thunk_266f88
0x266f8d: INT3 ; original byte CC, padding
0x266f8e: INT3 ; original byte CC, padding
0x266f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_266f90 [0x266f90, 0x266f94] | file +0xfe8 | ev_2377b4ca217eb2330c4ef066a1a50005f948c448bc9dec9fe0e517a224fc25ee
thunk_266f90:
0x266f90: JMP 0x00c39770
; END FUNCTION thunk_266f90
0x266f95: INT3 ; original byte CC, padding
0x266f96: INT3 ; original byte CC, padding
0x266f97: INT3 ; original byte CC, padding

; FUNCTION thunk_266f98 [0x266f98, 0x266f9c] | file +0xff0 | ev_a487275cdbdcbe32b12e5bec8dfb5826280a3e448a871934facafb54b9d2a18c
thunk_266f98:
0x266f98: JMP 0x00c43a20
; END FUNCTION thunk_266f98
0x266f9d: INT3 ; original byte CC, padding
0x266f9e: INT3 ; original byte CC, padding
0x266f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_266fa0 [0x266fa0, 0x266fa4] | file +0xff8 | ev_ef9ed6673d6b76c8e775846ba74f0680cb24f93bd4a9c65b6fd25fc3c69d2978
thunk_266fa0:
0x266fa0: JMP 0x00c60f90
; END FUNCTION thunk_266fa0
0x266fa5: INT3 ; original byte CC, padding
0x266fa6: INT3 ; original byte CC, padding
0x266fa7: INT3 ; original byte CC, padding



; ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_006f92e0 RVA 0x265fa8 | Evidence ev_c4a74c9ce2fc789cd5d1065d49c1604835bebc3f85fa69c049bfb3c59a201be9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
<EXTERNAL>::thunk_EXT_FUN_006f92e0:
0x265fa8: JMP 0x006f92e0


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): impl_cpumode_6f8910 RVA 0x6f8910 | Evidence ev_eb1b8bb4bf8e3e79e659da66b51aecdfc958f4bdc4c03446588963c83280fcbe | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
impl_cpumode_6f8910:
0x6f8910: PUSH RBP
0x6f8911: MOV RBP, RSP
0x6f8914: PUSH R15
0x6f8916: PUSH R14
0x6f8918: PUSH R13
0x6f891a: PUSH R12
0x6f891c: PUSH RBX
0x6f891d: SUB RSP, 0x28
0x6f8921: LEA R13, [0x391c310]
0x6f8928: MOV EBX, EDI
0x6f892a: MOV RAX, qword ptr [R13]
0x6f892e: MOV qword ptr [RBP + -0x30], RAX
0x6f8932: MOV R14, qword ptr GS:[0x0]
0x6f893b: CMP dword ptr [0x021fb408], 0x0
0x6f8942: JNZ 0x006f920a
0x6f8948: MOV EAX, dword ptr [0x021fb3c4]
0x6f894e: CMP EAX, 0x1
0x6f8951: JNZ 0x006f8960
0x6f8953: CMP dword ptr [0x021fb3d0], 0x0
0x6f895a: JZ 0x006f8bdc
0x6f8960: LEA RDI, [0x391c198]
0x6f8967: XOR R12D, R12D
0x6f896a: XOR ESI, ESI
0x6f896c: XOR EDX, EDX
0x6f896e: XOR ECX, ECX
0x6f8970: CALL 0x004c7190
0x6f8975: LEA RDX, [0x1279d12]
0x6f897c: MOV RDI, R14
0x6f897f: MOV ECX, 0x484
0x6f8984: XOR ESI, ESI
0x6f8986: CALL 0x004c78b0
0x6f898b: CMP EBX, 0x2
0x6f898e: JNZ 0x006f89cc
0x6f8990: CMP byte ptr [0x0391c230], 0x1
0x6f8997: JNZ 0x006f8bad
0x6f899d: CMP dword ptr [0x021fb3c8], 0x0
0x6f89a4: JZ 0x006f8bad
0x6f89aa: MOV EAX, dword ptr GS:[0x34]
0x6f89b2: CMP EAX, 0x3
0x6f89b5: JNZ 0x006f8bad
0x6f89bb: MOV EAX, dword ptr [0x021fb3d0]
0x6f89c1: XOR R12D, R12D
0x6f89c4: XOR R15D, R15D
0x6f89c7: JMP 0x006f8c52
0x6f89cc: MOV EAX, dword ptr [0x021fb3d0]
0x6f89d2: CMP EBX, 0x1
0x6f89d5: SETZ R15B
0x6f89d9: JNZ 0x006f8c52
0x6f89df: MOV ECX, 0x0
0x6f89e4: TEST EAX, EAX
0x6f89e6: JZ 0x006f8c54
0x6f89ec: MOV EAX, dword ptr [0x021fb3d4]
0x6f89f2: CMP EAX, 0x1
0x6f89f5: JNZ 0x006f8a6d
0x6f89f7: LEA RDI, [0x12c0eac]
0x6f89fe: XOR EAX, EAX
0x6f8a00: CALL 0x0025d410
0x6f8a05: XOR EDI, EDI
0x6f8a07: MOV dword ptr [0x021fb3d4], 0x0
0x6f8a11: CALL 0x006b7e80
0x6f8a16: LEA R15, [0x391c1b8]
0x6f8a1d: XOR ESI, ESI
0x6f8a1f: XOR EDX, EDX
0x6f8a21: XOR ECX, ECX
0x6f8a23: MOV RDI, R15
0x6f8a26: CALL 0x004c7190
0x6f8a2b: LEA RDI, [0x391c1e8]
0x6f8a32: CALL 0x00ac7630
0x6f8a37: LEA RDI, [0x21fb3f8]
0x6f8a3e: MOV ESI, 0x10
0x6f8a43: MOV dword ptr [0x021fb3f0], 0x0
0x6f8a4d: CALL 0x00258ff0
0x6f8a52: MOV RDI, R15
0x6f8a55: XOR ESI, ESI
0x6f8a57: XOR EDX, EDX
0x6f8a59: XOR ECX, ECX
0x6f8a5b: CALL 0x004c7520
0x6f8a60: CMP dword ptr [0x021fb408], 0x0
0x6f8a67: JNZ 0x006f9251
0x6f8a6d: LEA R15, [0x391c1b8]
0x6f8a74: XOR ESI, ESI
0x6f8a76: XOR EDX, EDX
0x6f8a78: XOR ECX, ECX
0x6f8a7a: MOV RDI, R15
0x6f8a7d: CALL 0x004c7190
0x6f8a82: MOV RDI, R15
0x6f8a85: MOV dword ptr [0x021fb3f0], 0x1
0x6f8a8f: XOR ESI, ESI
0x6f8a91: XOR EDX, EDX
0x6f8a93: XOR ECX, ECX
0x6f8a95: CALL 0x004c7520
0x6f8a9a: CMP dword ptr [0x021fb408], 0x0
0x6f8aa1: JNZ 0x006f9240
0x6f8aa7: MOV EDI, 0x1
0x6f8aac: CALL 0x006b7e80
0x6f8ab1: MOV dword ptr [0x021fb3d4], 0x1
0x6f8abb: TEST EAX, EAX
0x6f8abd: JNZ 0x006f8b79
0x6f8ac3: MOV R12D, EBX
0x6f8ac6: MOV RBX, 0x116ebd4cfd0842
0x6f8ad0: LEA RDI, [0x391c1b8]
0x6f8ad7: MOV qword ptr [RBP + -0x40], 0x0
0x6f8adf: XOR ESI, ESI
0x6f8ae1: XOR EDX, EDX
0x6f8ae3: XOR ECX, ECX
0x6f8ae5: MOV qword ptr [RBP + -0x38], RBX
0x6f8ae9: CALL 0x004c7190
0x6f8aee: LEA RDI, [0x21fb3f8]
0x6f8af5: CALL 0x00acf200
0x6f8afa: MOV RAX, qword ptr [0x021fb400]
0x6f8b01: MOV RCX, -0x116ebd4cfd0843
0x6f8b0b: XOR EDX, EDX
0x6f8b0d: LEA R15, [0x391c1e8]
0x6f8b14: MOV RDI, R15
0x6f8b17: ADD RBX, RAX
0x6f8b1a: CMP RAX, RCX
0x6f8b1d: SETA DL
0x6f8b20: MOV qword ptr [0x021fb400], RBX
0x6f8b27: ADD qword ptr [0x021fb3f8], RDX
0x6f8b2e: CALL 0x00ac7630
0x6f8b33: LEA RAX, [0x2677d8]
0x6f8b3a: LEA RSI, [RBP + -0x40]
0x6f8b3e: MOV RDI, R15
0x6f8b41: MOV dword ptr [0x0391c228], 0x1
0x6f8b4b: MOV qword ptr [0x0391c218], RAX
0x6f8b52: CALL 0x00ac7470
0x6f8b57: CMP dword ptr [0x021fb408], 0x0
0x6f8b5e: JNZ 0x006f9266
0x6f8b64: LEA RDI, [0x391c1b8]
0x6f8b6b: XOR ESI, ESI
0x6f8b6d: XOR EDX, EDX
0x6f8b6f: XOR ECX, ECX
0x6f8b71: CALL 0x004c7520
0x6f8b76: MOV EBX, R12D
0x6f8b79: MOV EAX, dword ptr [0x021fb3c4]
0x6f8b7f: CMP EAX, 0x1
0x6f8b82: JNZ 0x006f8b93
0x6f8b84: MOV EAX, dword ptr [0x021fb3c0]
0x6f8b8a: CMP EAX, 0x1
0x6f8b8d: JNZ 0x006f8e25
0x6f8b93: MOV ECX, 0x1
0x6f8b98: MOV R15B, 0x1
0x6f8b9b: MOV R12D, 0x1
0x6f8ba1: MOV byte ptr [0x0391c234], 0x1
0x6f8ba8: JMP 0x006f8c54
0x6f8bad: MOV RDI, qword ptr [R14]
0x6f8bb0: XOR ESI, ESI
0x6f8bb2: XOR EDX, EDX
0x6f8bb4: XOR ECX, ECX
0x6f8bb6: ADD RDI, 0x18
0x6f8bba: CALL 0x004c7520
0x6f8bbf: LEA RDI, [0x391c198]
0x6f8bc6: XOR ESI, ESI
0x6f8bc8: XOR EDX, EDX
0x6f8bca: XOR ECX, ECX
0x6f8bcc: CALL 0x004c7520
0x6f8bd1: MOV R15D, 0xffffffff
0x6f8bd7: JMP 0x006f91b1
0x6f8bdc: MOV EAX, dword ptr [0x021fb3c0]
0x6f8be2: CMP EAX, 0x1
0x6f8be5: JNZ 0x006f8e0c
0x6f8beb: CMP byte ptr [0x0391c178], 0x1
0x6f8bf2: JNZ 0x006f8960
0x6f8bf8: CMP EBX, 0x1
0x6f8bfb: JNZ 0x006f8fc9
0x6f8c01: LEA RDX, [0x1279d12]
0x6f8c08: MOV RDI, R14
0x6f8c0b: MOV ECX, 0x471
0x6f8c10: XOR ESI, ESI
0x6f8c12: XOR R15D, R15D
0x6f8c15: CALL 0x004c78b0
0x6f8c1a: CMP dword ptr [0x0391c240], 0x0
0x6f8c21: JZ 0x006f8c36
0x6f8c23: MOV RDI, qword ptr [0x0391c238]
0x6f8c2a: LEA RSI, [0x21fb4b0]
0x6f8c31: CALL 0x004ea9b0
0x6f8c36: MOV RDI, qword ptr [R14]
0x6f8c39: XOR ESI, ESI
0x6f8c3b: XOR EDX, EDX
0x6f8c3d: XOR ECX, ECX
0x6f8c3f: ADD RDI, 0x18
0x6f8c43: CALL 0x004c7520
0x6f8c48: CALL 0x008c4180
0x6f8c4d: JMP 0x006f91b1
0x6f8c52: XOR ECX, ECX
0x6f8c54: CMP dword ptr [0x021fb3c4], 0x0
0x6f8c5b: MOV dword ptr [RBP + -0x48], EBX
0x6f8c5e: JZ 0x006f8c6b
0x6f8c60: MOV EAX, dword ptr [0x021fb3c0]
0x6f8c66: CMP EAX, 0x1
0x6f8c69: JNZ 0x006f8ce7
0x6f8c6b: CMP dword ptr [0x021fb3c8], 0x0
0x6f8c72: JZ 0x006f8cef
0x6f8c74: CMP byte ptr [0x0391c230], 0x0
0x6f8c7b: JZ 0x006f8d53
0x6f8c81: LEA RDI, [0x391c280]
0x6f8c88: MOV dword ptr [0x021fb3c8], 0x0
0x6f8c92: CALL 0x00ac7630
0x6f8c97: MOV EAX, dword ptr [0x021fb3c4]
0x6f8c9d: CMP EAX, 0x1
0x6f8ca0: JNZ 0x006f8e41
0x6f8ca6: MOVSXD RAX, dword ptr [0x021fb3ec]
0x6f8cad: LEA RCX, [0x2677d0]
0x6f8cb4: MOV dword ptr [0x0391c2c0], 0x1
0x6f8cbe: LEA RDI, [0x391c280]
0x6f8cc5: MOV qword ptr [RBP + -0x40], 0x0
0x6f8ccd: MOV qword ptr [0x0391c2b0], RCX
0x6f8cd4: MOV RCX, 0x10c6f7a0b5ed
0x6f8cde: IMUL RCX, RAX
0x6f8ce2: JMP 0x006f8e72
0x6f8ce7: MOV dword ptr [RBP + -0x44], ECX
0x6f8cea: JMP 0x006f905a
0x6f8cef: TEST EBX, EBX
0x6f8cf1: JZ 0x006f8f0f
0x6f8cf7: LEA RDI, [0x391c280]
0x6f8cfe: CALL 0x00ac7630
0x6f8d03: MOV EAX, dword ptr [0x021fb3c4]
0x6f8d09: CMP EAX, 0x1
0x6f8d0c: JNZ 0x006f8f78
0x6f8d12: MOVSXD RAX, dword ptr [0x021fb3ec]
0x6f8d19: LEA RCX, [0x2677d0]
0x6f8d20: MOV dword ptr [0x0391c2c0], 0x1
0x6f8d2a: LEA RDI, [0x391c280]
0x6f8d31: MOV qword ptr [RBP + -0x40], 0x0
0x6f8d39: MOV qword ptr [0x0391c2b0], RCX
0x6f8d40: MOV RCX, 0x10c6f7a0b5ed
0x6f8d4a: IMUL RCX, RAX
0x6f8d4e: JMP 0x006f8fa9
0x6f8d53: LEA RDI, [0x391c280]
0x6f8d5a: MOV dword ptr [RBP + -0x44], ECX
0x6f8d5d: CALL 0x00ac7630
0x6f8d62: CALL 0x00b078d0
0x6f8d67: TEST EAX, EAX
0x6f8d69: JZ 0x006f8da4
0x6f8d6b: CMP dword ptr [0x02cb0000], 0x0
0x6f8d72: JZ 0x006f8da4
0x6f8d74: TEST byte ptr [0x0391c1c0], 0x1
0x6f8d7b: JZ 0x006f8da4
0x6f8d7d: MOV R13, qword ptr [0x03bf68e8]
0x6f8d84: LEA RAX, [0x26b750]
0x6f8d8b: SUB RAX, R13
0x6f8d8e: ROR RAX, 0x3
0x6f8d92: CMP RAX, 0x8
0x6f8d96: JA 0x006f9277
0x6f8d9c: MOV EDI, 0x2
0x6f8da1: CALL R13
0x6f8da4: LEA RAX, [0x2677d0]
0x6f8dab: MOV dword ptr [0x0391c2c0], 0x1
0x6f8db5: LEA RDI, [0x391c280]
0x6f8dbc: LEA RSI, [RBP + -0x40]
0x6f8dc0: MOV qword ptr [RBP + -0x40], 0x0
0x6f8dc8: MOV qword ptr [0x0391c2b0], RAX
0x6f8dcf: MOV RAX, 0x68db8bac71094
0x6f8dd9: MOV qword ptr [RBP + -0x38], RAX
0x6f8ddd: CALL 0x00ac7470
0x6f8de2: MOV byte ptr [0x0391c230], 0x1
0x6f8de9: MOV byte ptr [0x0391c234], R15B
0x6f8df0: XOR R13D, R13D
0x6f8df3: XOR ESI, ESI
0x6f8df5: XOR EDX, EDX
0x6f8df7: XOR ECX, ECX
0x6f8df9: MOV RDI, qword ptr [R14]
0x6f8dfc: ADD RDI, 0x18
0x6f8e00: CALL 0x004c7520
0x6f8e05: XOR EBX, EBX
0x6f8e07: JMP 0x006f90b8
0x6f8e0c: MOV R15D, 0xffffffff
0x6f8e12: CMP EBX, 0x1
0x6f8e15: JNZ 0x006f91b1
0x6f8e1b: CALL 0x008c4180
0x6f8e20: JMP 0x006f91b1
0x6f8e25: MOV EAX, dword ptr GS:[0x34]
0x6f8e2d: TEST EAX, EAX
0x6f8e2f: JZ 0x006f91d1
0x6f8e35: XOR EDI, EDI
0x6f8e37: CALL 0x006b6c00
0x6f8e3c: JMP 0x006f91d9
0x6f8e41: LEA RDI, [0x391c280]
0x6f8e48: LEA RAX, [0x2677d0]
0x6f8e4f: MOV RCX, 0x13a92a305531bc0
0x6f8e59: MOV dword ptr [0x0391c2c0], 0x1
0x6f8e63: MOV qword ptr [RBP + -0x40], 0x0
0x6f8e6b: MOV qword ptr [0x0391c2b0], RAX
0x6f8e72: MOV qword ptr [RBP + -0x38], RCX
0x6f8e76: LEA RSI, [RBP + -0x40]
0x6f8e7a: CALL 0x00ac7470
0x6f8e7f: CALL 0x00b078d0
0x6f8e84: TEST EAX, EAX
0x6f8e86: SETZ CL
0x6f8e89: CMP dword ptr [0x02cb0000], 0x0
0x6f8e90: SETZ AL
0x6f8e93: OR AL, CL
0x6f8e95: CMP EBX, 0x2
0x6f8e98: JNZ 0x006f8ec4
0x6f8e9a: TEST AL, AL
0x6f8e9c: JNZ 0x006f8eec
0x6f8e9e: MOV R13, qword ptr [0x03bf68e8]
0x6f8ea5: LEA RAX, [0x26b750]
0x6f8eac: SUB RAX, R13
0x6f8eaf: ROR RAX, 0x3
0x6f8eb3: CMP RAX, 0x8
0x6f8eb7: JA 0x006f928b
0x6f8ebd: MOV EDI, 0x3
0x6f8ec2: JMP 0x006f8ee9
0x6f8ec4: TEST AL, AL
0x6f8ec6: JNZ 0x006f8eec
0x6f8ec8: MOV R13, qword ptr [0x03bf68e8]
0x6f8ecf: LEA RAX, [0x26b750]
0x6f8ed6: SUB RAX, R13
0x6f8ed9: ROR RAX, 0x3
0x6f8edd: CMP RAX, 0x8
0x6f8ee1: JA 0x006f929f
0x6f8ee7: XOR EDI, EDI
0x6f8ee9: CALL R13
0x6f8eec: MOV byte ptr [0x0391c230], 0x0
0x6f8ef3: MOV dword ptr [RBP + -0x44], 0x1
0x6f8efa: TEST R15B, R15B
0x6f8efd: JZ 0x006f905a
0x6f8f03: MOV byte ptr [0x0391c234], 0x1
0x6f8f0a: JMP 0x006f905a
0x6f8f0f: LEA RDI, [0x391c280]
0x6f8f16: MOV dword ptr [RBP + -0x44], ECX
0x6f8f19: MOV dword ptr [0x021fb3c8], 0x1
0x6f8f23: CALL 0x00ac7630
0x6f8f28: MOV EAX, dword ptr [0x021fb3c4]
0x6f8f2e: CMP EAX, 0x1
0x6f8f31: JNZ 0x006f8fe3
0x6f8f37: MOVSXD RAX, dword ptr [0x021fb3e8]
0x6f8f3e: LEA RCX, [0x2677d0]
0x6f8f45: MOV dword ptr [0x0391c2c0], 0x1
0x6f8f4f: LEA RDI, [0x391c280]
0x6f8f56: MOV qword ptr [RBP + -0x40], 0x0
0x6f8f5e: MOV qword ptr [0x0391c2b0], RCX
0x6f8f65: MOV RCX, 0x10c6f7a0b5ed
0x6f8f6f: IMUL RCX, RAX
0x6f8f73: JMP 0x006f9014
0x6f8f78: LEA RDI, [0x391c280]
0x6f8f7f: LEA RAX, [0x2677d0]
0x6f8f86: MOV RCX, 0x13a92a305531bc0
0x6f8f90: MOV dword ptr [0x0391c2c0], 0x1
0x6f8f9a: MOV qword ptr [RBP + -0x40], 0x0
0x6f8fa2: MOV qword ptr [0x0391c2b0], RAX
0x6f8fa9: MOV qword ptr [RBP + -0x38], RCX
0x6f8fad: LEA RSI, [RBP + -0x40]
0x6f8fb1: CALL 0x00ac7470
0x6f8fb6: MOV byte ptr [0x0391c234], 0x1
0x6f8fbd: MOV dword ptr [RBP + -0x44], 0x1
0x6f8fc4: JMP 0x006f905a
0x6f8fc9: MOV EAX, dword ptr GS:[0x34]
0x6f8fd1: XOR R15D, R15D
0x6f8fd4: CMP EAX, 0x3
0x6f8fd7: SETNZ R15B
0x6f8fdb: NEG R15D
0x6f8fde: JMP 0x006f91b1
0x6f8fe3: LEA RDI, [0x391c280]
0x6f8fea: LEA RAX, [0x2677d0]
0x6f8ff1: MOV RCX, 0x22ee41919ac671
0x6f8ffb: MOV dword ptr [0x0391c2c0], 0x1
0x6f9005: MOV qword ptr [RBP + -0x40], 0x0
0x6f900d: MOV qword ptr [0x0391c2b0], RAX
0x6f9014: MOV qword ptr [RBP + -0x38], RCX
0x6f9018: LEA RSI, [RBP + -0x40]
0x6f901c: CALL 0x00ac7470
0x6f9021: CALL 0x00b078d0
0x6f9026: TEST EAX, EAX
0x6f9028: JZ 0x006f905a
0x6f902a: CMP dword ptr [0x02cb0000], 0x0
0x6f9031: JZ 0x006f905a
0x6f9033: MOV R15, qword ptr [0x03bf68e8]
0x6f903a: LEA RAX, [0x26b750]
0x6f9041: SUB RAX, R15
0x6f9044: ROR RAX, 0x3
0x6f9048: CMP RAX, 0x8
0x6f904c: JA 0x006f92b3
0x6f9052: MOV EDI, 0x1
0x6f9057: CALL R15
0x6f905a: MOV RDI, qword ptr [R14]
0x6f905d: XOR ESI, ESI
0x6f905f: XOR EDX, EDX
0x6f9061: XOR ECX, ECX
0x6f9063: ADD RDI, 0x18
0x6f9067: CALL 0x004c7520
0x6f906c: MOV EAX, dword ptr [0x021fb3c0]
0x6f9072: XOR EBX, EBX
0x6f9074: MOV R13B, 0x1
0x6f9077: CMP EAX, 0x1
0x6f907a: SETZ BL
0x6f907d: SHL EBX, 0x3
0x6f9080: CMP dword ptr [0x021fb3c4], 0x0
0x6f9087: JNZ 0x006f90b8
0x6f9089: MOVSXD RAX, dword ptr [0x021fb3cc]
0x6f9090: LEA RCX, [0x13b9e10]
0x6f9097: MOV EDX, 0x1
0x6f909c: MOVZX EAX, byte ptr [RCX + RAX*0x8]
0x6f90a0: SHLX RAX, RDX, RAX
0x6f90a5: MOVSXD RDX, dword ptr [0x021fb3cc]
0x6f90ac: MOVZX ECX, byte ptr [RCX + RDX*0x8 + 0x4]
0x6f90b1: BTS RAX, RCX
0x6f90b5: OR RBX, RAX
0x6f90b8: OR RBX, R12
0x6f90bb: LEA R15, [0x1279d12]
0x6f90c2: XOR R14D, R14D
0x6f90c5: JMP 0x006f90e4
0x6f90d0: MOV EDI, R14D
0x6f90d3: CALL 0x006b6c00
0x6f90d8: INC R14D
0x6f90db: CMP R14D, dword ptr [0x03d0e8b8]
0x6f90e2: JA 0x006f912f
0x6f90e4: BT RBX, R14
0x6f90e8: JNC 0x006f90d8
0x6f90ea: MOV EAX, dword ptr GS:[0x34]
0x6f90f2: CMP R14D, EAX
0x6f90f5: JNZ 0x006f90d0
0x6f90f7: MOV R12, qword ptr GS:[0x0]
0x6f9100: MOV RDI, R12
0x6f9103: MOV RDX, R15
0x6f9106: MOV ECX, 0x2b4
0x6f910b: XOR ESI, ESI
0x6f910d: CALL 0x004c78b0
0x6f9112: MOV RDI, R12
0x6f9115: CALL 0x006b6cf0
0x6f911a: MOV RDI, qword ptr [R12]
0x6f911e: XOR ESI, ESI
0x6f9120: XOR EDX, EDX
0x6f9122: XOR ECX, ECX
0x6f9124: ADD RDI, 0x18
0x6f9128: CALL 0x004c7520
0x6f912d: JMP 0x006f90d8
0x6f912f: LEA RDI, [0x391c198]
0x6f9136: XOR R15D, R15D
0x6f9139: XOR ESI, ESI
0x6f913b: XOR EDX, EDX
0x6f913d: XOR ECX, ECX
0x6f913f: CALL 0x004c7520
0x6f9144: TEST R13B, R13B
0x6f9147: JNZ 0x006f9170
0x6f9149: MOV EAX, dword ptr [0x021fb3c0]
0x6f914f: CMP EAX, 0x1
0x6f9152: JNZ 0x006f9170
0x6f9154: CMP dword ptr [0x0391c240], 0x0
0x6f915b: JZ 0x006f9170
0x6f915d: MOV RDI, qword ptr [0x0391c238]
0x6f9164: LEA RSI, [0x21fb4b0]
0x6f916b: CALL 0x004ea9b0
0x6f9170: CMP dword ptr [RBP + -0x44], 0x0
0x6f9174: LEA R13, [0x391c310]
0x6f917b: MOV EAX, dword ptr [RBP + -0x48]
0x6f917e: JZ 0x006f91b1
0x6f9180: TEST byte ptr [0x0391c234], 0x1
0x6f9187: JZ 0x006f91b1
0x6f9189: DEC EAX
0x6f918b: CMP EAX, 0x1
0x6f918e: JA 0x006f9197
0x6f9190: CALL 0x008c4180
0x6f9195: JMP 0x006f91aa
0x6f9197: MOV RDI, qword ptr [0x0391c238]
0x6f919e: LEA RSI, [0x21fb490]
0x6f91a5: CALL 0x004ea9b0
0x6f91aa: MOV byte ptr [0x0391c234], 0x0
0x6f91b1: MOV RAX, qword ptr [R13]
0x6f91b5: CMP RAX, qword ptr [RBP + -0x30]
0x6f91b9: JNZ 0x006f9270
0x6f91bf: MOV EAX, R15D
0x6f91c2: ADD RSP, 0x28
0x6f91c6: POP RBX
0x6f91c7: POP R12
0x6f91c9: POP R13
0x6f91cb: POP R14
0x6f91cd: POP R15
0x6f91cf: POP RBP
0x6f91d0: RET
0x6f91d1: MOV RDI, R14
0x6f91d4: CALL 0x006b6cf0
0x6f91d9: MOV RDI, qword ptr [R14]
0x6f91dc: XOR ESI, ESI
0x6f91de: XOR EDX, EDX
0x6f91e0: XOR ECX, ECX
0x6f91e2: ADD RDI, 0x18
0x6f91e6: CALL 0x004c7520
0x6f91eb: LEA RDI, [0x391c198]
0x6f91f2: XOR ESI, ESI
0x6f91f4: XOR EDX, EDX
0x6f91f6: XOR ECX, ECX
0x6f91f8: CALL 0x004c7520
0x6f91fd: CALL 0x008c4180
0x6f9202: MOV R15D, 0xffffffff
0x6f9208: JMP 0x006f91b1
0x6f920a: CMP EBX, 0x1
0x6f920d: JNZ 0x006f8948
0x6f9213: LEA R15, [0x13b25df]
0x6f921a: XOR ESI, ESI
0x6f921c: MOV RDI, R15
0x6f921f: CALL 0x00a90d70
0x6f9224: MOV RDI, R15
0x6f9227: MOV ESI, 0xf
0x6f922c: CALL 0x00a90d70
0x6f9231: MOV RDI, R15
0x6f9234: XOR ESI, ESI
0x6f9236: CALL 0x00a90d70
0x6f923b: JMP 0x006f8948
0x6f9240: MOV EDI, 0x1
0x6f9245: XOR ESI, ESI
0x6f9247: CALL 0x006f9960
0x6f924c: JMP 0x006f8aa7
0x6f9251: MOV EDI, dword ptr [0x021fb3d4]
0x6f9257: MOV ESI, 0x1
0x6f925c: CALL 0x006f9960
0x6f9261: JMP 0x006f8a6d
0x6f9266: CALL 0x006f8830
0x6f926b: JMP 0x006f8b64
0x6f9270: CALL 0x006fd6b0
0x6f9275: UD2
0x6f9277: LEA RDI, [0x21fb430]
0x6f927e: MOV RSI, R13
0x6f9281: CALL 0x0044f8c0
0x6f9286: JMP 0x006f8d9c
0x6f928b: LEA RDI, [0x21fb450]
0x6f9292: MOV RSI, R13
0x6f9295: CALL 0x0044f8c0
0x6f929a: JMP 0x006f8ebd
0x6f929f: LEA RDI, [0x21fb470]
0x6f92a6: MOV RSI, R13
0x6f92a9: CALL 0x0044f8c0
0x6f92ae: JMP 0x006f8ee7
0x6f92b3: LEA RDI, [0x21fb410]
0x6f92ba: MOV RSI, R15
0x6f92bd: CALL 0x0044f8c0
0x6f92c2: JMP 0x006f9052


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_006f92d0 RVA 0x6f92d0 | Evidence ev_8f143a0594eab42e88c821757be8fe1f7c4e1be535b33f6c8ef50ee6903e0f6a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
FUN_006f92d0:
0x6f92d0: PUSH RBP
0x6f92d1: MOV RBP, RSP
0x6f92d4: MOV EDI, 0x1
0x6f92d9: POP RBP
0x6f92da: JMP 0x006f8910


; ===== TARGET: handler_676_body RVA 0x6f92e0 | Evidence ev_d1b588fe78e706c3825cc0049d254e141a90f2fd6f058f6aaa4872bb9c9a3b0f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
handler_676_body:
0x6f92e0: MOV RAX, qword ptr GS:[0x0]
0x6f92e9: MOV RCX, qword ptr [RAX + 0x8]
0x6f92ed: MOV EAX, 0x4e
0x6f92f2: CMP byte ptr [RCX + 0xc81], 0x0
0x6f92f9: JZ 0x006f92fc
0x6f92fb: RET
0x6f92fc: CMP byte ptr [0x0391c1c0], 0x0
0x6f9303: JNZ 0x006f930c
0x6f9305: MOV byte ptr [0x0391c1c0], 0x1


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_676_continuation RVA 0x6f930c | Evidence ev_4a6161f1939b938ebfffa78d3fd9344a0c694ecd60ef7f99bd6b0e639bcca554 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
handler_676_continuation:
0x6f930c: PUSH RBP
0x6f930d: MOV RBP, RSP
0x6f9310: MOV EDI, 0x2
0x6f9315: CALL 0x006f8910
0x6f931a: MOV ECX, EAX
0x6f931c: TEST EAX, EAX
0x6f931e: MOV EAX, 0x16
0x6f9323: CMOVZ EAX, ECX
0x6f9326: POP RBP
0x6f9327: RET


; ===== SUPPLEMENTAL GNU objdump full linear disassembly of every original4096 input byte =====
; Source raw file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_676.bin
; This is independent linear decoding, not REA function discovery; padding/data may decode as instructions.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_676.bin:     file format binary


Disassembly of section .data:

0000000000265fa8 <.data>:
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
  266fa0:	e9 eb 9f 9f 00       	jmp    0xc60f90
  266fa5:	cc                   	int3
  266fa6:	cc                   	int3
  266fa7:	cc                   	int3


; ===== SUPPLEMENTAL GNU objdump FULL original target-window bytes =====
; Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.body.bin SHA256 36647ddebab4b8b43e2458ac0a5592eae2db02b961a6a293a00249c857609e9c
; RVA 0x6f92e0; size16384 bytes. This linear decode may include adjacent code/data and is not a REA boundary claim.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.body.bin:     file format binary


Disassembly of section .data:

00000000006f92e0 <.data>:
  6f92e0:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6f92e7:	00 00 
  6f92e9:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
  6f92ed:	b8 4e 00 00 00       	mov    eax,0x4e
  6f92f2:	80 b9 81 0c 00 00 00 	cmp    BYTE PTR [rcx+0xc81],0x0
  6f92f9:	74 01                	je     0x6f92fc
  6f92fb:	c3                   	ret
  6f92fc:	80 3d bd 2e 22 03 00 	cmp    BYTE PTR [rip+0x3222ebd],0x0        # 0x391c1c0
  6f9303:	75 07                	jne    0x6f930c
  6f9305:	c6 05 b4 2e 22 03 01 	mov    BYTE PTR [rip+0x3222eb4],0x1        # 0x391c1c0
  6f930c:	55                   	push   rbp
  6f930d:	48 89 e5             	mov    rbp,rsp
  6f9310:	bf 02 00 00 00       	mov    edi,0x2
  6f9315:	e8 f6 f5 ff ff       	call   0x6f8910
  6f931a:	89 c1                	mov    ecx,eax
  6f931c:	85 c0                	test   eax,eax
  6f931e:	b8 16 00 00 00       	mov    eax,0x16
  6f9323:	0f 44 c1             	cmove  eax,ecx
  6f9326:	5d                   	pop    rbp
  6f9327:	c3                   	ret
  6f9328:	90                   	nop
  6f9329:	90                   	nop
  6f932a:	90                   	nop
  6f932b:	90                   	nop
  6f932c:	90                   	nop
  6f932d:	90                   	nop
  6f932e:	90                   	nop
  6f932f:	90                   	nop
  6f9330:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6f9337:	00 00 
  6f9339:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  6f933d:	83 b8 d0 05 00 00 00 	cmp    DWORD PTR [rax+0x5d0],0x0
  6f9344:	74 01                	je     0x6f9347
  6f9346:	c3                   	ret
  6f9347:	55                   	push   rbp
  6f9348:	48 89 e5             	mov    rbp,rsp
  6f934b:	41 56                	push   r14
  6f934d:	53                   	push   rbx
  6f934e:	4c 8d 35 43 2e 22 03 	lea    r14,[rip+0x3222e43]        # 0x391c198
  6f9355:	89 fb                	mov    ebx,edi
  6f9357:	31 f6                	xor    esi,esi
  6f9359:	31 d2                	xor    edx,edx
  6f935b:	31 c9                	xor    ecx,ecx
  6f935d:	4c 89 f7             	mov    rdi,r14
  6f9360:	e8 2b de dc ff       	call   0x4c7190
  6f9365:	85 db                	test   ebx,ebx
  6f9367:	b8 6a 0a 00 00       	mov    eax,0xa6a
  6f936c:	b9 55 08 00 00       	mov    ecx,0x855
  6f9371:	ba 7f 0c 00 00       	mov    edx,0xc7f
  6f9376:	4c 89 f7             	mov    rdi,r14
  6f9379:	0f 44 c8             	cmove  ecx,eax
  6f937c:	0f 44 d0             	cmove  edx,eax
  6f937f:	31 f6                	xor    esi,esi
  6f9381:	89 0d 61 20 b0 01    	mov    DWORD PTR [rip+0x1b02061],ecx        # 0x21fb3e8
  6f9387:	89 15 5f 20 b0 01    	mov    DWORD PTR [rip+0x1b0205f],edx        # 0x21fb3ec
  6f938d:	31 d2                	xor    edx,edx
  6f938f:	31 c9                	xor    ecx,ecx
  6f9391:	5b                   	pop    rbx
  6f9392:	41 5e                	pop    r14
  6f9394:	5d                   	pop    rbp
  6f9395:	e9 86 e1 dc ff       	jmp    0x4c7520
  6f939a:	90                   	nop
  6f939b:	90                   	nop
  6f939c:	90                   	nop
  6f939d:	90                   	nop
  6f939e:	90                   	nop
  6f939f:	90                   	nop
  6f93a0:	55                   	push   rbp
  6f93a1:	48 89 e5             	mov    rbp,rsp
  6f93a4:	41 56                	push   r14
  6f93a6:	53                   	push   rbx
  6f93a7:	48 83 ec 10          	sub    rsp,0x10
  6f93ab:	4c 8d 35 5e 2f 22 03 	lea    r14,[rip+0x3222f5e]        # 0x391c310
  6f93b2:	49 8b 06             	mov    rax,QWORD PTR [r14]
  6f93b5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
  6f93b9:	8b 87 84 03 00 00    	mov    eax,DWORD PTR [rdi+0x384]
  6f93bf:	83 f8 40             	cmp    eax,0x40
  6f93c2:	74 18                	je     0x6f93dc
  6f93c4:	83 f8 02             	cmp    eax,0x2
  6f93c7:	75 3a                	jne    0x6f9403
  6f93c9:	48 8d 75 e0          	lea    rsi,[rbp-0x20]
  6f93cd:	48 c7 45 e0 f8 ff 00 	mov    QWORD PTR [rbp-0x20],0xfff8
  6f93d4:	00 
  6f93d5:	e8 06 38 14 00       	call   0x83cbe0
  6f93da:	eb 27                	jmp    0x6f9403
  6f93dc:	48 8d 75 e0          	lea    rsi,[rbp-0x20]
  6f93e0:	c7 87 84 03 00 00 00 	mov    DWORD PTR [rdi+0x384],0x0
  6f93e7:	00 00 00 
  6f93ea:	48 c7 45 e0 07 00 00 	mov    QWORD PTR [rbp-0x20],0x7
  6f93f1:	00 
  6f93f2:	48 89 fb             	mov    rbx,rdi
  6f93f5:	e8 e6 37 14 00       	call   0x83cbe0
  6f93fa:	83 3d 07 20 b0 01 00 	cmp    DWORD PTR [rip+0x1b02007],0x0        # 0x21fb408
  6f9401:	75 12                	jne    0x6f9415
  6f9403:	49 8b 06             	mov    rax,QWORD PTR [r14]
  6f9406:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
  6f940a:	75 13                	jne    0x6f941f
  6f940c:	48 83 c4 10          	add    rsp,0x10
  6f9410:	5b                   	pop    rbx
  6f9411:	41 5e                	pop    r14
  6f9413:	5d                   	pop    rbp
  6f9414:	c3                   	ret
  6f9415:	48 89 df             	mov    rdi,rbx
  6f9418:	e8 13 00 00 00       	call   0x6f9430
  6f941d:	eb e4                	jmp    0x6f9403
  6f941f:	e8 8c 42 00 00       	call   0x6fd6b0
  6f9424:	0f 0b                	ud2
  6f9426:	90                   	nop
  6f9427:	90                   	nop
  6f9428:	90                   	nop
  6f9429:	90                   	nop
  6f942a:	90                   	nop
  6f942b:	90                   	nop
  6f942c:	90                   	nop
  6f942d:	90                   	nop
  6f942e:	90                   	nop
  6f942f:	90                   	nop
  6f9430:	55                   	push   rbp
  6f9431:	48 89 e5             	mov    rbp,rsp
  6f9434:	53                   	push   rbx
  6f9435:	50                   	push   rax
  6f9436:	48 89 fb             	mov    rbx,rdi
  6f9439:	48 8d 3d a0 2d 22 03 	lea    rdi,[rip+0x3222da0]        # 0x391c1e0
  6f9440:	31 f6                	xor    esi,esi
  6f9442:	31 d2                	xor    edx,edx
  6f9444:	31 c9                	xor    ecx,ecx
  6f9446:	e8 45 dd dc ff       	call   0x4c7190
  6f944b:	48 3b 1d f6 1e b0 01 	cmp    rbx,QWORD PTR [rip+0x1b01ef6]        # 0x21fb348
  6f9452:	75 2a                	jne    0x6f947e
  6f9454:	48 c7 05 e9 1e b0 01 	mov    QWORD PTR [rip+0x1b01ee9],0x0        # 0x21fb348
  6f945b:	00 00 00 00 
  6f945f:	83 3d 6e 1f b0 01 00 	cmp    DWORD PTR [rip+0x1b01f6e],0x0        # 0x21fb3d4
  6f9466:	75 16                	jne    0x6f947e
  6f9468:	48 83 3d 98 1e b0 01 	cmp    QWORD PTR [rip+0x1b01e98],0x0        # 0x21fb308
  6f946f:	00 
  6f9470:	74 0c                	je     0x6f947e
  6f9472:	48 8d 3d 8f 1e b0 01 	lea    rdi,[rip+0x1b01e8f]        # 0x21fb308
  6f9479:	e8 c2 01 00 00       	call   0x6f9640
  6f947e:	48 8d 3d 5b 2d 22 03 	lea    rdi,[rip+0x3222d5b]        # 0x391c1e0
  6f9485:	31 f6                	xor    esi,esi
  6f9487:	31 d2                	xor    edx,edx
  6f9489:	31 c9                	xor    ecx,ecx
  6f948b:	48 83 c4 08          	add    rsp,0x8
  6f948f:	5b                   	pop    rbx
  6f9490:	5d                   	pop    rbp
  6f9491:	e9 8a e0 dc ff       	jmp    0x4c7520
  6f9496:	90                   	nop
  6f9497:	90                   	nop
  6f9498:	90                   	nop
  6f9499:	90                   	nop
  6f949a:	90                   	nop
  6f949b:	90                   	nop
  6f949c:	90                   	nop
  6f949d:	90                   	nop
  6f949e:	90                   	nop
  6f949f:	90                   	nop
  6f94a0:	55                   	push   rbp
  6f94a1:	48 89 e5             	mov    rbp,rsp
  6f94a4:	41 56                	push   r14
  6f94a6:	53                   	push   rbx
  6f94a7:	85 d2                	test   edx,edx
  6f94a9:	75 09                	jne    0x6f94b4
  6f94ab:	83 3d 56 1f b0 01 00 	cmp    DWORD PTR [rip+0x1b01f56],0x0        # 0x21fb408
  6f94b2:	75 05                	jne    0x6f94b9
  6f94b4:	5b                   	pop    rbx
  6f94b5:	41 5e                	pop    r14
  6f94b7:	5d                   	pop    rbp
  6f94b8:	c3                   	ret
  6f94b9:	49 89 fe             	mov    r14,rdi
  6f94bc:	48 8d 3d 1d 2d 22 03 	lea    rdi,[rip+0x3222d1d]        # 0x391c1e0
  6f94c3:	48 89 f3             	mov    rbx,rsi
  6f94c6:	31 f6                	xor    esi,esi
  6f94c8:	31 d2                	xor    edx,edx
  6f94ca:	31 c9                	xor    ecx,ecx
  6f94cc:	e8 bf dc dc ff       	call   0x4c7190
  6f94d1:	83 3d 80 1e b0 01 00 	cmp    DWORD PTR [rip+0x1b01e80],0x0        # 0x21fb358
  6f94d8:	0f 84 fb 00 00 00    	je     0x6f95d9
  6f94de:	83 bb 84 03 00 00 40 	cmp    DWORD PTR [rbx+0x384],0x40
  6f94e5:	48 89 d9             	mov    rcx,rbx
  6f94e8:	74 0a                	je     0x6f94f4
  6f94ea:	41 83 be 84 03 00 00 	cmp    DWORD PTR [r14+0x384],0x40
  6f94f1:	40 
  6f94f2:	75 7c                	jne    0x6f9570
  6f94f4:	48 83 3d 9c 1d b0 01 	cmp    QWORD PTR [rip+0x1b01d9c],0x0        # 0x21fb298
  6f94fb:	00 
  6f94fc:	75 72                	jne    0x6f9570
  6f94fe:	0f 31                	rdtsc
  6f9500:	89 c7                	mov    edi,eax
  6f9502:	48 2b 3d 5f 1e b0 01 	sub    rdi,QWORD PTR [rip+0x1b01e5f]        # 0x21fb368
  6f9509:	48 c1 e2 20          	shl    rdx,0x20
  6f950d:	48 01 d7             	add    rdi,rdx
  6f9510:	e8 ab 74 3d 00       	call   0xad09c0
  6f9515:	48 89 d9             	mov    rcx,rbx
  6f9518:	48 83 f8 65          	cmp    rax,0x65
  6f951c:	72 52                	jb     0x6f9570
  6f951e:	48 8d 3d b0 96 ba 00 	lea    rdi,[rip+0xba96b0]        # 0x12a2bd5
  6f9525:	31 f6                	xor    esi,esi
  6f9527:	e8 74 78 39 00       	call   0xa90da0
  6f952c:	0f 31                	rdtsc
  6f952e:	89 c7                	mov    edi,eax
  6f9530:	48 2b 3d 31 1e b0 01 	sub    rdi,QWORD PTR [rip+0x1b01e31]        # 0x21fb368
  6f9537:	48 c1 e2 20          	shl    rdx,0x20
  6f953b:	48 01 d7             	add    rdi,rdx
  6f953e:	e8 7d 74 3d 00       	call   0xad09c0
  6f9543:	48 89 d9             	mov    rcx,rbx
  6f9546:	48 83 f8 65          	cmp    rax,0x65
  6f954a:	72 24                	jb     0x6f9570
  6f954c:	83 b9 84 03 00 00 40 	cmp    DWORD PTR [rcx+0x384],0x40
  6f9553:	75 1b                	jne    0x6f9570
  6f9555:	0f bf 81 0a 01 00 00 	movsx  eax,WORD PTR [rcx+0x10a]
  6f955c:	0f bf 91 0c 01 00 00 	movsx  edx,WORD PTR [rcx+0x10c]
  6f9563:	0f bf b1 0e 01 00 00 	movsx  esi,WORD PTR [rcx+0x10e]
  6f956a:	01 c2                	add    edx,eax
  6f956c:	01 d6                	add    esi,edx
  6f956e:	7e 7f                	jle    0x6f95ef
  6f9570:	4c 3b 35 d1 1d b0 01 	cmp    r14,QWORD PTR [rip+0x1b01dd1]        # 0x21fb348
  6f9577:	75 2d                	jne    0x6f95a6
  6f9579:	48 c7 05 c4 1d b0 01 	mov    QWORD PTR [rip+0x1b01dc4],0x0        # 0x21fb348
  6f9580:	00 00 00 00 
  6f9584:	83 3d 49 1e b0 01 00 	cmp    DWORD PTR [rip+0x1b01e49],0x0        # 0x21fb3d4
  6f958b:	75 19                	jne    0x6f95a6
  6f958d:	48 83 3d 73 1d b0 01 	cmp    QWORD PTR [rip+0x1b01d73],0x0        # 0x21fb308
  6f9594:	00 
  6f9595:	74 0f                	je     0x6f95a6
  6f9597:	48 8d 3d 6a 1d b0 01 	lea    rdi,[rip+0x1b01d6a]        # 0x21fb308
  6f959e:	e8 9d 00 00 00       	call   0x6f9640
  6f95a3:	48 89 d9             	mov    rcx,rbx
  6f95a6:	83 3d 43 1e b0 01 00 	cmp    DWORD PTR [rip+0x1b01e43],0x0        # 0x21fb3f0
  6f95ad:	74 21                	je     0x6f95d0
  6f95af:	83 b9 84 03 00 00 40 	cmp    DWORD PTR [rcx+0x384],0x40
  6f95b6:	75 18                	jne    0x6f95d0
  6f95b8:	48 83 3d 48 1d b0 01 	cmp    QWORD PTR [rip+0x1b01d48],0x0        # 0x21fb308
  6f95bf:	00 
  6f95c0:	75 10                	jne    0x6f95d2
  6f95c2:	48 8d 3d 3f 1d b0 01 	lea    rdi,[rip+0x1b01d3f]        # 0x21fb308
  6f95c9:	e8 f2 00 00 00       	call   0x6f96c0
  6f95ce:	eb 02                	jmp    0x6f95d2
  6f95d0:	31 db                	xor    ebx,ebx
  6f95d2:	48 89 1d 6f 1d b0 01 	mov    QWORD PTR [rip+0x1b01d6f],rbx        # 0x21fb348
  6f95d9:	48 8d 3d 00 2c 22 03 	lea    rdi,[rip+0x3222c00]        # 0x391c1e0
  6f95e0:	31 f6                	xor    esi,esi
  6f95e2:	31 d2                	xor    edx,edx
  6f95e4:	31 c9                	xor    ecx,ecx
  6f95e6:	5b                   	pop    rbx
  6f95e7:	41 5e                	pop    r14
  6f95e9:	5d                   	pop    rbp
  6f95ea:	e9 31 df dc ff       	jmp    0x4c7520
  6f95ef:	49 89 ce             	mov    r14,rcx
  6f95f2:	e8 59 83 0f 00       	call   0x7f1950
  6f95f7:	49 63 b6 9c 00 00 00 	movsxd rsi,DWORD PTR [r14+0x9c]
  6f95fe:	49 8d 9e 94 02 00 00 	lea    rbx,[r14+0x294]
  6f9605:	48 8d 3d e3 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe3]        # 0x6f95ef
  6f960c:	48 89 da             	mov    rdx,rbx
  6f960f:	e8 fc 89 0f 00       	call   0x7f2010
  6f9614:	41 8b 96 9c 00 00 00 	mov    edx,DWORD PTR [r14+0x9c]
  6f961b:	48 8d 35 6f 78 bc 00 	lea    rsi,[rip+0xbc786f]        # 0x12c0e91
  6f9622:	bf 6b 00 00 00       	mov    edi,0x6b
  6f9627:	48 89 d9             	mov    rcx,rbx
  6f962a:	31 c0                	xor    eax,eax
  6f962c:	e8 df 13 5a 00       	call   0xc9aa10
  6f9631:	0f 0b                	ud2
  6f9633:	90                   	nop
  6f9634:	90                   	nop
  6f9635:	90                   	nop
  6f9636:	90                   	nop
  6f9637:	90                   	nop
  6f9638:	90                   	nop
  6f9639:	90                   	nop
  6f963a:	90                   	nop
  6f963b:	90                   	nop
  6f963c:	90                   	nop
  6f963d:	90                   	nop
  6f963e:	90                   	nop
  6f963f:	90                   	nop
  6f9640:	55                   	push   rbp
  6f9641:	48 89 e5             	mov    rbp,rsp
  6f9644:	53                   	push   rbx
  6f9645:	50                   	push   rax
  6f9646:	0f 31                	rdtsc
  6f9648:	48 8b 0f             	mov    rcx,QWORD PTR [rdi]
  6f964b:	48 85 c9             	test   rcx,rcx
  6f964e:	74 46                	je     0x6f9696
  6f9650:	48 89 fb             	mov    rbx,rdi
  6f9653:	89 c7                	mov    edi,eax
  6f9655:	48 c1 e2 20          	shl    rdx,0x20
  6f9659:	48 29 cf             	sub    rdi,rcx
  6f965c:	48 01 d7             	add    rdi,rdx
  6f965f:	48 3b 7b 08          	cmp    rdi,QWORD PTR [rbx+0x8]
  6f9663:	73 04                	jae    0x6f9669
  6f9665:	48 89 7b 08          	mov    QWORD PTR [rbx+0x8],rdi
  6f9669:	48 3b 7b 10          	cmp    rdi,QWORD PTR [rbx+0x10]
  6f966d:	76 04                	jbe    0x6f9673
  6f966f:	48 89 7b 10          	mov    QWORD PTR [rbx+0x10],rdi
  6f9673:	48 c7 03 00 00 00 00 	mov    QWORD PTR [rbx],0x0
  6f967a:	48 01 7b 18          	add    QWORD PTR [rbx+0x18],rdi
  6f967e:	ff 43 20             	inc    DWORD PTR [rbx+0x20]
  6f9681:	e8 3a 73 3d 00       	call   0xad09c0
  6f9686:	48 3b 43 28          	cmp    rax,QWORD PTR [rbx+0x28]
  6f968a:	76 03                	jbe    0x6f968f
  6f968c:	ff 43 30             	inc    DWORD PTR [rbx+0x30]
  6f968f:	48 83 c4 08          	add    rsp,0x8
  6f9693:	5b                   	pop    rbx
  6f9694:	5d                   	pop    rbp
  6f9695:	c3                   	ret
  6f9696:	e8 b5 82 0f 00       	call   0x7f1950
  6f969b:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6f9696
  6f96a2:	e8 69 81 0f 00       	call   0x7f1810
  6f96a7:	48 8d 35 74 06 c3 00 	lea    rsi,[rip+0xc30674]        # 0x1329d22
  6f96ae:	bf 67 00 00 00       	mov    edi,0x67
  6f96b3:	31 c0                	xor    eax,eax
  6f96b5:	e8 56 13 5a 00       	call   0xc9aa10
  6f96ba:	0f 0b                	ud2
  6f96bc:	90                   	nop
  6f96bd:	90                   	nop
  6f96be:	90                   	nop
  6f96bf:	90                   	nop
  6f96c0:	48 83 3f 00          	cmp    QWORD PTR [rdi],0x0
  6f96c4:	75 0f                	jne    0x6f96d5
  6f96c6:	0f 31                	rdtsc
  6f96c8:	89 c0                	mov    eax,eax
  6f96ca:	48 c1 e2 20          	shl    rdx,0x20
  6f96ce:	48 09 c2             	or     rdx,rax
  6f96d1:	48 89 17             	mov    QWORD PTR [rdi],rdx
  6f96d4:	c3                   	ret
  6f96d5:	55                   	push   rbp
  6f96d6:	48 89 e5             	mov    rbp,rsp
  6f96d9:	e8 72 82 0f 00       	call   0x7f1950
  6f96de:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0x6f96d5
  6f96e5:	e8 26 81 0f 00       	call   0x7f1810
  6f96ea:	48 8d 35 73 e3 c8 00 	lea    rsi,[rip+0xc8e373]        # 0x1387a64
  6f96f1:	bf 63 00 00 00       	mov    edi,0x63
  6f96f6:	31 c0                	xor    eax,eax
  6f96f8:	e8 13 13 5a 00       	call   0xc9aa10
  6f96fd:	0f 0b                	ud2
  6f96ff:	90                   	nop
  6f9700:	55                   	push   rbp
  6f9701:	48 89 e5             	mov    rbp,rsp
  6f9704:	41 57                	push   r15
  6f9706:	41 56                	push   r14
  6f9708:	53                   	push   rbx
  6f9709:	48 83 ec 28          	sub    rsp,0x28
  6f970d:	4c 8d 3d fc 2b 22 03 	lea    r15,[rip+0x3222bfc]        # 0x391c310
  6f9714:	48 8d 3d 7d 2a 22 03 	lea    rdi,[rip+0x3222a7d]        # 0x391c198
  6f971b:	31 f6                	xor    esi,esi
  6f971d:	31 d2                	xor    edx,edx
  6f971f:	31 c9                	xor    ecx,ecx
  6f9721:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6f9724:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  6f9728:	65 48 8b 1c 25 00 00 	mov    rbx,QWORD PTR gs:0x0
  6f972f:	00 00 
  6f9731:	e8 5a da dc ff       	call   0x4c7190
  6f9736:	48 8d 3d 7b 2a 22 03 	lea    rdi,[rip+0x3222a7b]        # 0x391c1b8
  6f973d:	31 f6                	xor    esi,esi
  6f973f:	31 d2                	xor    edx,edx
  6f9741:	31 c9                	xor    ecx,ecx
  6f9743:	e8 48 da dc ff       	call   0x4c7190
  6f9748:	83 3d a1 1c b0 01 00 	cmp    DWORD PTR [rip+0x1b01ca1],0x0        # 0x21fb3f0
  6f974f:	74 3c                	je     0x6f978d
  6f9751:	48 8b 05 a8 1c b0 01 	mov    rax,QWORD PTR [rip+0x1b01ca8]        # 0x21fb400
  6f9758:	48 0b 05 99 1c b0 01 	or     rax,QWORD PTR [rip+0x1b01c99]        # 0x21fb3f8
  6f975f:	0f 84 f9 00 00 00    	je     0x6f985e
  6f9765:	48 8d 7d d0          	lea    rdi,[rbp-0x30]
  6f9769:	e8 92 5a 3d 00       	call   0xacf200
  6f976e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  6f9772:	48 3b 05 7f 1c b0 01 	cmp    rax,QWORD PTR [rip+0x1b01c7f]        # 0x21fb3f8
  6f9779:	75 4d                	jne    0x6f97c8
  6f977b:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
  6f977f:	48 3b 0d 7a 1c b0 01 	cmp    rcx,QWORD PTR [rip+0x1b01c7a]        # 0x21fb400
  6f9786:	72 46                	jb     0x6f97ce
  6f9788:	e9 aa 00 00 00       	jmp    0x6f9837
  6f978d:	48 8d 3d 24 2a 22 03 	lea    rdi,[rip+0x3222a24]        # 0x391c1b8
  6f9794:	31 f6                	xor    esi,esi
  6f9796:	31 d2                	xor    edx,edx
  6f9798:	31 c9                	xor    ecx,ecx
  6f979a:	e8 81 dd dc ff       	call   0x4c7520
  6f979f:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6f97a2:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  6f97a6:	0f 85 ab 01 00 00    	jne    0x6f9957
  6f97ac:	48 8d 3d e5 29 22 03 	lea    rdi,[rip+0x32229e5]        # 0x391c198
  6f97b3:	31 f6                	xor    esi,esi
  6f97b5:	31 d2                	xor    edx,edx
  6f97b7:	31 c9                	xor    ecx,ecx
  6f97b9:	48 83 c4 28          	add    rsp,0x28
  6f97bd:	5b                   	pop    rbx
  6f97be:	41 5e                	pop    r14
  6f97c0:	41 5f                	pop    r15
  6f97c2:	5d                   	pop    rbp
  6f97c3:	e9 58 dd dc ff       	jmp    0x4c7520
  6f97c8:	7d 6d                	jge    0x6f9837
  6f97ca:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
  6f97ce:	48 8b 15 2b 1c b0 01 	mov    rdx,QWORD PTR [rip+0x1b01c2b]        # 0x21fb400
  6f97d5:	4c 8d 35 0c 2a 22 03 	lea    r14,[rip+0x3222a0c]        # 0x391c1e8
  6f97dc:	4c 89 f7             	mov    rdi,r14
  6f97df:	48 29 ca             	sub    rdx,rcx
  6f97e2:	48 19 c9             	sbb    rcx,rcx
  6f97e5:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  6f97e9:	48 29 c1             	sub    rcx,rax
  6f97ec:	48 03 0d 05 1c b0 01 	add    rcx,QWORD PTR [rip+0x1b01c05]        # 0x21fb3f8
  6f97f3:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
  6f97f7:	e8 34 de 3c 00       	call   0xac7630
  6f97fc:	48 8d 05 d5 df b6 ff 	lea    rax,[rip+0xffffffffffb6dfd5]        # 0x2677d8
  6f9803:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  6f9807:	4c 89 f7             	mov    rdi,r14
  6f980a:	c7 05 14 2a 22 03 01 	mov    DWORD PTR [rip+0x3222a14],0x1        # 0x391c228
  6f9811:	00 00 00 
  6f9814:	48 89 05 fd 29 22 03 	mov    QWORD PTR [rip+0x32229fd],rax        # 0x391c218
  6f981b:	e8 50 dc 3c 00       	call   0xac7470
  6f9820:	48 8d 3d 91 29 22 03 	lea    rdi,[rip+0x3222991]        # 0x391c1b8
  6f9827:	31 f6                	xor    esi,esi
  6f9829:	31 d2                	xor    edx,edx
  6f982b:	31 c9                	xor    ecx,ecx
  6f982d:	e8 ee dc dc ff       	call   0x4c7520
  6f9832:	e9 a6 00 00 00       	jmp    0x6f98dd
  6f9837:	48 8d 3d aa 29 22 03 	lea    rdi,[rip+0x32229aa]        # 0x391c1e8
  6f983e:	e8 ed dd 3c 00       	call   0xac7630
  6f9843:	48 8d 3d ae 1b b0 01 	lea    rdi,[rip+0x1b01bae]        # 0x21fb3f8
  6f984a:	be 10 00 00 00       	mov    esi,0x10
  6f984f:	c7 05 97 1b b0 01 00 	mov    DWORD PTR [rip+0x1b01b97],0x0        # 0x21fb3f0
  6f9856:	00 00 00 
  6f9859:	e8 92 f7 b5 ff       	call   0x258ff0
  6f985e:	48 8d 3d 53 29 22 03 	lea    rdi,[rip+0x3222953]        # 0x391c1b8
  6f9865:	31 f6                	xor    esi,esi
  6f9867:	31 d2                	xor    edx,edx
  6f9869:	31 c9                	xor    ecx,ecx
  6f986b:	e8 b0 dc dc ff       	call   0x4c7520
  6f9870:	83 3d 5d 1b b0 01 00 	cmp    DWORD PTR [rip+0x1b01b5d],0x0        # 0x21fb3d4
  6f9877:	74 64                	je     0x6f98dd
  6f9879:	31 ff                	xor    edi,edi
  6f987b:	e8 00 e6 fb ff       	call   0x6b7e80
  6f9880:	4c 8d 35 31 29 22 03 	lea    r14,[rip+0x3222931]        # 0x391c1b8
  6f9887:	31 f6                	xor    esi,esi
  6f9889:	31 d2                	xor    edx,edx
  6f988b:	31 c9                	xor    ecx,ecx
  6f988d:	4c 89 f7             	mov    rdi,r14
  6f9890:	e8 fb d8 dc ff       	call   0x4c7190
  6f9895:	48 8d 3d 4c 29 22 03 	lea    rdi,[rip+0x322294c]        # 0x391c1e8
  6f989c:	e8 8f dd 3c 00       	call   0xac7630
  6f98a1:	48 8d 3d 50 1b b0 01 	lea    rdi,[rip+0x1b01b50]        # 0x21fb3f8
  6f98a8:	be 10 00 00 00       	mov    esi,0x10
  6f98ad:	c7 05 39 1b b0 01 00 	mov    DWORD PTR [rip+0x1b01b39],0x0        # 0x21fb3f0
  6f98b4:	00 00 00 
  6f98b7:	e8 34 f7 b5 ff       	call   0x258ff0
  6f98bc:	4c 89 f7             	mov    rdi,r14
  6f98bf:	31 f6                	xor    esi,esi
  6f98c1:	31 d2                	xor    edx,edx
  6f98c3:	31 c9                	xor    ecx,ecx
  6f98c5:	e8 56 dc dc ff       	call   0x4c7520
  6f98ca:	c7 05 00 1b b0 01 00 	mov    DWORD PTR [rip+0x1b01b00],0x0        # 0x21fb3d4
  6f98d1:	00 00 00 
  6f98d4:	83 3d 2d 1b b0 01 00 	cmp    DWORD PTR [rip+0x1b01b2d],0x0        # 0x21fb408
  6f98db:	75 6b                	jne    0x6f9948
  6f98dd:	48 8d 15 2e 04 b8 00 	lea    rdx,[rip+0xb8042e]        # 0x1279d12
  6f98e4:	48 89 df             	mov    rdi,rbx
  6f98e7:	b9 36 04 00 00       	mov    ecx,0x436
  6f98ec:	31 f6                	xor    esi,esi
  6f98ee:	e8 bd df dc ff       	call   0x4c78b0
  6f98f3:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6f98fa:	00 
  6f98fb:	85 c0                	test   eax,eax
  6f98fd:	74 09                	je     0x6f9908
  6f98ff:	31 ff                	xor    edi,edi
  6f9901:	e8 fa d2 fb ff       	call   0x6b6c00
  6f9906:	eb 08                	jmp    0x6f9910
  6f9908:	48 89 df             	mov    rdi,rbx
  6f990b:	e8 e0 d3 fb ff       	call   0x6b6cf0
  6f9910:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
  6f9913:	31 f6                	xor    esi,esi
  6f9915:	31 d2                	xor    edx,edx
  6f9917:	31 c9                	xor    ecx,ecx
  6f9919:	48 83 c7 18          	add    rdi,0x18
  6f991d:	e8 fe db dc ff       	call   0x4c7520
  6f9922:	48 8d 3d 6f 28 22 03 	lea    rdi,[rip+0x322286f]        # 0x391c198
  6f9929:	31 f6                	xor    esi,esi
  6f992b:	31 d2                	xor    edx,edx
  6f992d:	31 c9                	xor    ecx,ecx
  6f992f:	e8 ec db dc ff       	call   0x4c7520
  6f9934:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6f9937:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  6f993b:	75 1a                	jne    0x6f9957
  6f993d:	48 83 c4 28          	add    rsp,0x28
  6f9941:	5b                   	pop    rbx
  6f9942:	41 5e                	pop    r14
  6f9944:	41 5f                	pop    r15
  6f9946:	5d                   	pop    rbp
  6f9947:	c3                   	ret
  6f9948:	8b 3d 86 1a b0 01    	mov    edi,DWORD PTR [rip+0x1b01a86]        # 0x21fb3d4
  6f994e:	31 f6                	xor    esi,esi
  6f9950:	e8 0b 00 00 00       	call   0x6f9960
  6f9955:	eb 86                	jmp    0x6f98dd
  6f9957:	e8 54 3d 00 00       	call   0x6fd6b0
  6f995c:	0f 0b                	ud2
  6f995e:	90                   	nop
  6f995f:	90                   	nop
  6f9960:	55                   	push   rbp
  6f9961:	48 89 e5             	mov    rbp,rsp
  6f9964:	41 57                	push   r15
  6f9966:	41 56                	push   r14
  6f9968:	41 55                	push   r13
  6f996a:	41 54                	push   r12
  6f996c:	53                   	push   rbx
  6f996d:	50                   	push   rax
  6f996e:	41 89 fd             	mov    r13d,edi
  6f9971:	89 f3                	mov    ebx,esi
  6f9973:	31 c0                	xor    eax,eax
  6f9975:	be 0f 00 00 00       	mov    esi,0xf
  6f997a:	4c 8d 25 73 45 b9 00 	lea    r12,[rip+0xb94573]        # 0x128def4
  6f9981:	41 89 fe             	mov    r14d,edi
  6f9984:	41 bf 0f 00 00 00    	mov    r15d,0xf
  6f998a:	41 83 f5 01          	xor    r13d,0x1
  6f998e:	4c 89 e7             	mov    rdi,r12
  6f9991:	0f 44 f0             	cmove  esi,eax
  6f9994:	44 0f 45 f8          	cmovne r15d,eax
  6f9998:	e8 d3 73 39 00       	call   0xa90d70
  6f999d:	4c 89 e7             	mov    rdi,r12
  6f99a0:	44 89 fe             	mov    esi,r15d
  6f99a3:	e8 c8 73 39 00       	call   0xa90d70
  6f99a8:	48 8d 3d 31 28 22 03 	lea    rdi,[rip+0x3222831]        # 0x391c1e0
  6f99af:	31 f6                	xor    esi,esi
  6f99b1:	31 d2                	xor    edx,edx
  6f99b3:	31 c9                	xor    ecx,ecx
  6f99b5:	e8 d6 d7 dc ff       	call   0x4c7190
  6f99ba:	8b 05 98 19 b0 01    	mov    eax,DWORD PTR [rip+0x1b01998]        # 0x21fb358
  6f99c0:	41 09 c5             	or     r13d,eax
  6f99c3:	75 31                	jne    0x6f99f6
  6f99c5:	0f 31                	rdtsc
  6f99c7:	89 c7                	mov    edi,eax
  6f99c9:	48 2b 3d 80 19 b0 01 	sub    rdi,QWORD PTR [rip+0x1b01980]        # 0x21fb350
  6f99d0:	48 c1 e2 20          	shl    rdx,0x20
  6f99d4:	48 01 d7             	add    rdi,rdx
  6f99d7:	e8 e4 6f 3d 00       	call   0xad09c0
  6f99dc:	48 3d 81 84 1e 00    	cmp    rax,0x1e8481
  6f99e2:	72 0c                	jb     0x6f99f0
  6f99e4:	c7 05 6a 19 b0 01 01 	mov    DWORD PTR [rip+0x1b0196a],0x1        # 0x21fb358
  6f99eb:	00 00 00 
  6f99ee:	eb 14                	jmp    0x6f9a04
  6f99f0:	8b 05 62 19 b0 01    	mov    eax,DWORD PTR [rip+0x1b01962]        # 0x21fb358
  6f99f6:	85 c0                	test   eax,eax
  6f99f8:	0f 84 c2 00 00 00    	je     0x6f9ac0
  6f99fe:	41 83 fe 01          	cmp    r14d,0x1
  6f9a02:	75 4b                	jne    0x6f9a4f
  6f9a04:	48 83 3d fc 18 b0 01 	cmp    QWORD PTR [rip+0x1b018fc],0x0        # 0x21fb308
  6f9a0b:	00 
  6f9a0c:	0f 85 7a 01 00 00    	jne    0x6f9b8c
  6f9a12:	48 8d 3d 7f 18 b0 01 	lea    rdi,[rip+0x1b0187f]        # 0x21fb298
  6f9a19:	e8 a2 fc ff ff       	call   0x6f96c0
  6f9a1e:	48 83 3d aa 18 b0 01 	cmp    QWORD PTR [rip+0x1b018aa],0x0        # 0x21fb2d0
  6f9a25:	00 
  6f9a26:	74 0c                	je     0x6f9a34
  6f9a28:	48 8d 3d a1 18 b0 01 	lea    rdi,[rip+0x1b018a1]        # 0x21fb2d0
  6f9a2f:	e8 0c fc ff ff       	call   0x6f9640
  6f9a34:	48 8d 3d 95 18 b0 01 	lea    rdi,[rip+0x1b01895]        # 0x21fb2d0
  6f9a3b:	e8 80 fc ff ff       	call   0x6f96c0
  6f9a40:	48 c7 05 15 19 b0 01 	mov    QWORD PTR [rip+0x1b01915],0x0        # 0x21fb360
  6f9a47:	00 00 00 00 
  6f9a4b:	31 d2                	xor    edx,edx
  6f9a4d:	eb 6a                	jmp    0x6f9ab9
  6f9a4f:	85 db                	test   ebx,ebx
  6f9a51:	0f 84 89 00 00 00    	je     0x6f9ae0
  6f9a57:	48 c7 05 36 18 b0 01 	mov    QWORD PTR [rip+0x1b01836],0x0        # 0x21fb298
  6f9a5e:	00 00 00 00 
  6f9a62:	48 c7 05 9b 18 b0 01 	mov    QWORD PTR [rip+0x1b0189b],0x0        # 0x21fb308
  6f9a69:	00 00 00 00 
  6f9a6d:	48 c7 05 58 18 b0 01 	mov    QWORD PTR [rip+0x1b01858],0x0        # 0x21fb2d0
  6f9a74:	00 00 00 00 
  6f9a78:	48 c7 05 c5 18 b0 01 	mov    QWORD PTR [rip+0x1b018c5],0x0        # 0x21fb348
  6f9a7f:	00 00 00 00 
  6f9a83:	48 c7 05 d2 18 b0 01 	mov    QWORD PTR [rip+0x1b018d2],0x0        # 0x21fb360
  6f9a8a:	00 00 00 00 
  6f9a8e:	48 83 3d b2 18 b0 01 	cmp    QWORD PTR [rip+0x1b018b2],0x0        # 0x21fb348
  6f9a95:	00 
  6f9a96:	75 16                	jne    0x6f9aae
  6f9a98:	48 83 3d 68 18 b0 01 	cmp    QWORD PTR [rip+0x1b01868],0x0        # 0x21fb308
  6f9a9f:	00 
  6f9aa0:	74 0c                	je     0x6f9aae
  6f9aa2:	48 8d 3d 5f 18 b0 01 	lea    rdi,[rip+0x1b0185f]        # 0x21fb308
  6f9aa9:	e8 92 fb ff ff       	call   0x6f9640
  6f9aae:	0f 31                	rdtsc
  6f9ab0:	89 c0                	mov    eax,eax
  6f9ab2:	48 c1 e2 20          	shl    rdx,0x20
  6f9ab6:	48 09 c2             	or     rdx,rax
  6f9ab9:	48 89 15 a8 18 b0 01 	mov    QWORD PTR [rip+0x1b018a8],rdx        # 0x21fb368
  6f9ac0:	48 8d 3d 19 27 22 03 	lea    rdi,[rip+0x3222719]        # 0x391c1e0
  6f9ac7:	31 f6                	xor    esi,esi
  6f9ac9:	31 d2                	xor    edx,edx
  6f9acb:	31 c9                	xor    ecx,ecx
  6f9acd:	48 83 c4 08          	add    rsp,0x8
  6f9ad1:	5b                   	pop    rbx
  6f9ad2:	41 5c                	pop    r12
  6f9ad4:	41 5d                	pop    r13
  6f9ad6:	41 5e                	pop    r14
  6f9ad8:	41 5f                	pop    r15
  6f9ada:	5d                   	pop    rbp
  6f9adb:	e9 40 da dc ff       	jmp    0x4c7520
  6f9ae0:	48 8d 3d b1 17 b0 01 	lea    rdi,[rip+0x1b017b1]        # 0x21fb298
  6f9ae7:	e8 54 fb ff ff       	call   0x6f9640
  6f9aec:	48 8b 0d 6d 18 b0 01 	mov    rcx,QWORD PTR [rip+0x1b0186d]        # 0x21fb360
  6f9af3:	0f 31                	rdtsc
  6f9af5:	89 d7                	mov    edi,edx
  6f9af7:	89 c0                	mov    eax,eax
  6f9af9:	48 c1 e7 20          	shl    rdi,0x20
  6f9afd:	48 09 c7             	or     rdi,rax
  6f9b00:	48 85 c9             	test   rcx,rcx
  6f9b03:	74 4b                	je     0x6f9b50
  6f9b05:	48 2b 3d 54 18 b0 01 	sub    rdi,QWORD PTR [rip+0x1b01854]        # 0x21fb360
  6f9b0c:	e8 af 6e 3d 00       	call   0xad09c0
  6f9b11:	48 3d 29 01 00 00    	cmp    rax,0x129
  6f9b17:	0f 82 66 ff ff ff    	jb     0x6f9a83
  6f9b1d:	48 8d 3d 9d 01 c3 00 	lea    rdi,[rip+0xc3019d]        # 0x1329cc1
  6f9b24:	31 f6                	xor    esi,esi
  6f9b26:	48 89 c3             	mov    rbx,rax
  6f9b29:	e8 72 72 39 00       	call   0xa90da0
  6f9b2e:	48 8d 3d d2 dd ca 00 	lea    rdi,[rip+0xcaddd2]        # 0x13a7907
  6f9b35:	48 8d 35 ef de c8 00 	lea    rsi,[rip+0xc8deef]        # 0x1387a2b
  6f9b3c:	ba ec 08 00 00       	mov    edx,0x8ec
  6f9b41:	48 89 d9             	mov    rcx,rbx
  6f9b44:	31 c0                	xor    eax,eax
  6f9b46:	e8 c5 38 b6 ff       	call   0x25d410
  6f9b4b:	e9 33 ff ff ff       	jmp    0x6f9a83
  6f9b50:	48 2b 3d f9 17 b0 01 	sub    rdi,QWORD PTR [rip+0x1b017f9]        # 0x21fb350
  6f9b57:	e8 64 6e 3d 00       	call   0xad09c0
  6f9b5c:	48 89 c1             	mov    rcx,rax
  6f9b5f:	48 8d 3d 00 33 ca 00 	lea    rdi,[rip+0xca3300]        # 0x139ce66
  6f9b66:	48 8d 35 be de c8 00 	lea    rsi,[rip+0xc8debe]        # 0x1387a2b
  6f9b6d:	ba de 08 00 00       	mov    edx,0x8de
  6f9b72:	31 c0                	xor    eax,eax
  6f9b74:	e8 97 38 b6 ff       	call   0x25d410
  6f9b79:	48 8d 3d 2f aa c1 00 	lea    rdi,[rip+0xc1aa2f]        # 0x13145af
  6f9b80:	31 f6                	xor    esi,esi
  6f9b82:	e8 19 72 39 00       	call   0xa90da0
  6f9b87:	e9 f7 fe ff ff       	jmp    0x6f9a83
  6f9b8c:	e8 bf 7d 0f 00       	call   0x7f1950
  6f9b91:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6f9b8c
  6f9b98:	be c8 08 00 00       	mov    esi,0x8c8
  6f9b9d:	e8 fe 7c 0f 00       	call   0x7f18a0
  6f9ba2:	48 8d 35 a2 b2 bf 00 	lea    rsi,[rip+0xbfb2a2]        # 0x12f4e4b
  6f9ba9:	bf 6f 00 00 00       	mov    edi,0x6f
  6f9bae:	ba c8 08 00 00       	mov    edx,0x8c8
  6f9bb3:	31 c0                	xor    eax,eax
  6f9bb5:	e8 56 0e 5a 00       	call   0xc9aa10
  6f9bba:	0f 0b                	ud2
  6f9bbc:	90                   	nop
  6f9bbd:	90                   	nop
  6f9bbe:	90                   	nop
  6f9bbf:	90                   	nop
  6f9bc0:	55                   	push   rbp
  6f9bc1:	48 89 e5             	mov    rbp,rsp
  6f9bc4:	5d                   	pop    rbp
  6f9bc5:	e9 b6 a5 1c 00       	jmp    0x8c4180
  6f9bca:	90                   	nop
  6f9bcb:	90                   	nop
  6f9bcc:	90                   	nop
  6f9bcd:	90                   	nop
  6f9bce:	90                   	nop
  6f9bcf:	90                   	nop
  6f9bd0:	55                   	push   rbp
  6f9bd1:	48 89 e5             	mov    rbp,rsp
  6f9bd4:	48 8d 3d 6d 26 22 03 	lea    rdi,[rip+0x322266d]        # 0x391c248
  6f9bdb:	c6 05 62 26 22 03 01 	mov    BYTE PTR [rip+0x3222662],0x1        # 0x391c244
  6f9be2:	31 f6                	xor    esi,esi
  6f9be4:	31 d2                	xor    edx,edx
  6f9be6:	e8 65 a1 c1 ff       	call   0x313d50
  6f9beb:	c6 05 52 26 22 03 00 	mov    BYTE PTR [rip+0x3222652],0x0        # 0x391c244
  6f9bf2:	5d                   	pop    rbp
  6f9bf3:	c3                   	ret
  6f9bf4:	90                   	nop
  6f9bf5:	90                   	nop
  6f9bf6:	90                   	nop
  6f9bf7:	90                   	nop
  6f9bf8:	90                   	nop
  6f9bf9:	90                   	nop
  6f9bfa:	90                   	nop
  6f9bfb:	90                   	nop
  6f9bfc:	90                   	nop
  6f9bfd:	90                   	nop
  6f9bfe:	90                   	nop
  6f9bff:	90                   	nop
  6f9c00:	55                   	push   rbp
  6f9c01:	48 89 e5             	mov    rbp,rsp
  6f9c04:	bf af 00 00 00       	mov    edi,0xaf
  6f9c09:	e8 92 2d 3d 00       	call   0xacc9a0
  6f9c0e:	85 c0                	test   eax,eax
  6f9c10:	74 07                	je     0x6f9c19
  6f9c12:	c6 05 5f 25 22 03 01 	mov    BYTE PTR [rip+0x322255f],0x1        # 0x391c178
  6f9c19:	48 8d 3d 78 25 22 03 	lea    rdi,[rip+0x3222578]        # 0x391c198
  6f9c20:	48 8d 35 bb d0 bd 00 	lea    rsi,[rip+0xbdd0bb]        # 0x12d6ce2
  6f9c27:	b9 01 00 00 00       	mov    ecx,0x1
  6f9c2c:	31 d2                	xor    edx,edx
  6f9c2e:	e8 9d e1 dc ff       	call   0x4c7dd0
  6f9c33:	48 8d 3d 7e 25 22 03 	lea    rdi,[rip+0x322257e]        # 0x391c1b8
  6f9c3a:	48 8d 35 b2 8f ba 00 	lea    rsi,[rip+0xba8fb2]        # 0x12a2bf3
  6f9c41:	b9 01 00 00 00       	mov    ecx,0x1
  6f9c46:	31 d2                	xor    edx,edx
  6f9c48:	e8 83 e1 dc ff       	call   0x4c7dd0
  6f9c4d:	48 8d 35 37 0f c4 00 	lea    rsi,[rip+0xc40f37]        # 0x133ab8b
  6f9c54:	48 8d 15 85 db b6 ff 	lea    rdx,[rip+0xffffffffffb6db85]        # 0x2677e0
  6f9c5b:	48 8d 0d 98 2c bb 00 	lea    rcx,[rip+0xbb2c98]        # 0x12ac8fa
  6f9c62:	41 b9 10 27 00 00    	mov    r9d,0x2710
  6f9c68:	31 ff                	xor    edi,edi
  6f9c6a:	45 31 c0             	xor    r8d,r8d
  6f9c6d:	e8 ce 40 04 00       	call   0x73dd40
  6f9c72:	48 8d 35 79 d8 b7 00 	lea    rsi,[rip+0xb7d879]        # 0x12774f2
  6f9c79:	48 8d 15 68 db b6 ff 	lea    rdx,[rip+0xffffffffffb6db68]        # 0x2677e8
  6f9c80:	48 8d 0d 7d 8f ba 00 	lea    rcx,[rip+0xba8f7d]        # 0x12a2c04
  6f9c87:	41 b9 10 27 00 00    	mov    r9d,0x2710
  6f9c8d:	31 ff                	xor    edi,edi
  6f9c8f:	45 31 c0             	xor    r8d,r8d
  6f9c92:	e8 a9 40 04 00       	call   0x73dd40
  6f9c97:	48 8d 35 f9 29 c2 00 	lea    rsi,[rip+0xc229f9]        # 0x131c697
  6f9c9e:	48 8d 15 4b db b6 ff 	lea    rdx,[rip+0xffffffffffb6db4b]        # 0x2677f0
  6f9ca5:	48 8d 0d 32 00 c3 00 	lea    rcx,[rip+0xc30032]        # 0x1329cde
  6f9cac:	41 b9 10 27 00 00    	mov    r9d,0x2710
  6f9cb2:	31 ff                	xor    edi,edi
  6f9cb4:	45 31 c0             	xor    r8d,r8d
  6f9cb7:	e8 84 40 04 00       	call   0x73dd40
  6f9cbc:	48 8d 35 5a de bc 00 	lea    rsi,[rip+0xbcde5a]        # 0x12c7b1d
  6f9cc3:	48 8d 15 2e db b6 ff 	lea    rdx,[rip+0xffffffffffb6db2e]        # 0x2677f8
  6f9cca:	48 8d 0d c9 0e bf 00 	lea    rcx,[rip+0xbf0ec9]        # 0x12eab9a
  6f9cd1:	41 b9 10 27 00 00    	mov    r9d,0x2710
  6f9cd7:	31 ff                	xor    edi,edi
  6f9cd9:	45 31 c0             	xor    r8d,r8d
  6f9cdc:	e8 5f 40 04 00       	call   0x73dd40
  6f9ce1:	48 8d 35 ca 8b c1 00 	lea    rsi,[rip+0xc18bca]        # 0x13128b2
  6f9ce8:	48 8d 15 11 db b6 ff 	lea    rdx,[rip+0xffffffffffb6db11]        # 0x267800
  6f9cef:	48 8d 0d 01 ed b9 00 	lea    rcx,[rip+0xb9ed01]        # 0x12989f7
  6f9cf6:	41 b9 10 27 00 00    	mov    r9d,0x2710
  6f9cfc:	31 ff                	xor    edi,edi
  6f9cfe:	45 31 c0             	xor    r8d,r8d
  6f9d01:	e8 3a 40 04 00       	call   0x73dd40
  6f9d06:	48 8d 35 a6 0e bf 00 	lea    rsi,[rip+0xbf0ea6]        # 0x12eabb3
  6f9d0d:	48 8d 15 b4 da b6 ff 	lea    rdx,[rip+0xffffffffffb6dab4]        # 0x2677c8
  6f9d14:	48 8d 0d d1 88 cb 00 	lea    rcx,[rip+0xcb88d1]        # 0x13b25ec
  6f9d1b:	41 b9 10 27 00 00    	mov    r9d,0x2710
  6f9d21:	31 ff                	xor    edi,edi
  6f9d23:	45 31 c0             	xor    r8d,r8d
  6f9d26:	e8 15 40 04 00       	call   0x73dd40
  6f9d2b:	48 8d 3d 16 25 22 03 	lea    rdi,[rip+0x3222516]        # 0x391c248
  6f9d32:	31 f6                	xor    esi,esi
  6f9d34:	31 d2                	xor    edx,edx
  6f9d36:	31 c9                	xor    ecx,ecx
  6f9d38:	45 31 c0             	xor    r8d,r8d
  6f9d3b:	45 31 c9             	xor    r9d,r9d
  6f9d3e:	e8 ad a4 c1 ff       	call   0x3141f0
  6f9d43:	48 8d 35 86 17 b0 01 	lea    rsi,[rip+0x1b01786]        # 0x21fb4d0
  6f9d4a:	bf e9 ff ff ff       	mov    edi,0xffffffe9
  6f9d4f:	5d                   	pop    rbp
  6f9d50:	e9 bb 9e c1 ff       	jmp    0x313c10
  6f9d55:	90                   	nop
  6f9d56:	90                   	nop
  6f9d57:	90                   	nop
  6f9d58:	90                   	nop
  6f9d59:	90                   	nop
  6f9d5a:	90                   	nop
  6f9d5b:	90                   	nop
  6f9d5c:	90                   	nop
  6f9d5d:	90                   	nop
  6f9d5e:	90                   	nop
  6f9d5f:	90                   	nop
  6f9d60:	55                   	push   rbp
  6f9d61:	48 89 e5             	mov    rbp,rsp
  6f9d64:	41 57                	push   r15
  6f9d66:	41 56                	push   r14
  6f9d68:	53                   	push   rbx
  6f9d69:	48 83 ec 18          	sub    rsp,0x18
  6f9d6d:	4c 8d 3d 9c 25 22 03 	lea    r15,[rip+0x322259c]        # 0x391c310
  6f9d74:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6f9d77:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  6f9d7b:	65 48 8b 1c 25 00 00 	mov    rbx,QWORD PTR gs:0x0
  6f9d82:	00 00 
  6f9d84:	48 8b be 80 05 00 00 	mov    rdi,QWORD PTR [rsi+0x580]
  6f9d8b:	48 85 ff             	test   rdi,rdi
  6f9d8e:	0f 84 31 02 00 00    	je     0x6f9fc5
  6f9d94:	49 89 f6             	mov    r14,rsi
  6f9d97:	e8 04 2f 30 00       	call   0x9fcca0
  6f9d9c:	3d 00 01 00 02       	cmp    eax,0x2000100
  6f9da1:	0f 85 b1 00 00 00    	jne    0x6f9e58
  6f9da7:	41 81 be d8 05 00 00 	cmp    DWORD PTR [r14+0x5d8],0x1500000
  6f9dae:	00 00 50 01 
  6f9db2:	0f 82 0d 02 00 00    	jb     0x6f9fc5
  6f9db8:	48 8d 3d d9 23 22 03 	lea    rdi,[rip+0x32223d9]        # 0x391c198
  6f9dbf:	31 f6                	xor    esi,esi
  6f9dc1:	31 d2                	xor    edx,edx
  6f9dc3:	31 c9                	xor    ecx,ecx
  6f9dc5:	e8 c6 d3 dc ff       	call   0x4c7190
  6f9dca:	83 3d ff 15 b0 01 00 	cmp    DWORD PTR [rip+0x1b015ff],0x0        # 0x21fb3d0
  6f9dd1:	0f 85 13 02 00 00    	jne    0x6f9fea
  6f9dd7:	8b 05 f7 15 b0 01    	mov    eax,DWORD PTR [rip+0x1b015f7]        # 0x21fb3d4
  6f9ddd:	83 f8 01             	cmp    eax,0x1
  6f9de0:	0f 84 23 02 00 00    	je     0x6fa009
  6f9de6:	c7 05 e0 15 b0 01 01 	mov    DWORD PTR [rip+0x1b015e0],0x1        # 0x21fb3d0
  6f9ded:	00 00 00 
  6f9df0:	83 3d 11 16 b0 01 00 	cmp    DWORD PTR [rip+0x1b01611],0x0        # 0x21fb408
  6f9df7:	0f 85 dc 01 00 00    	jne    0x6f9fd9
  6f9dfd:	48 8d 3d 94 23 22 03 	lea    rdi,[rip+0x3222394]        # 0x391c198
  6f9e04:	31 f6                	xor    esi,esi
  6f9e06:	31 d2                	xor    edx,edx
  6f9e08:	31 c9                	xor    ecx,ecx
  6f9e0a:	e8 11 d7 dc ff       	call   0x4c7520
  6f9e0f:	48 8d 15 fc fe b7 00 	lea    rdx,[rip+0xb7fefc]        # 0x1279d12
  6f9e16:	48 89 df             	mov    rdi,rbx
  6f9e19:	b9 60 05 00 00       	mov    ecx,0x560
  6f9e1e:	31 f6                	xor    esi,esi
  6f9e20:	e8 8b da dc ff       	call   0x4c78b0
  6f9e25:	c7 83 84 03 00 00 40 	mov    DWORD PTR [rbx+0x384],0x40
  6f9e2c:	00 00 00 
  6f9e2f:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
  6f9e32:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6f9e35:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  6f9e39:	0f 85 a4 01 00 00    	jne    0x6f9fe3
  6f9e3f:	48 83 c7 18          	add    rdi,0x18
  6f9e43:	31 f6                	xor    esi,esi
  6f9e45:	31 d2                	xor    edx,edx
  6f9e47:	31 c9                	xor    ecx,ecx
  6f9e49:	48 83 c4 18          	add    rsp,0x18
  6f9e4d:	5b                   	pop    rbx
  6f9e4e:	41 5e                	pop    r14
  6f9e50:	41 5f                	pop    r15
  6f9e52:	5d                   	pop    rbp
  6f9e53:	e9 c8 d6 dc ff       	jmp    0x4c7520
  6f9e58:	3d ff ff ff 00       	cmp    eax,0xffffff
  6f9e5d:	0f 87 62 01 00 00    	ja     0x6f9fc5
  6f9e63:	3d ff ef 01 00       	cmp    eax,0x1efff
  6f9e68:	7e 17                	jle    0x6f9e81
  6f9e6a:	3d 00 f0 01 00       	cmp    eax,0x1f000
  6f9e6f:	74 1e                	je     0x6f9e8f
  6f9e71:	3d 00 f0 02 00       	cmp    eax,0x2f000
  6f9e76:	74 17                	je     0x6f9e8f
  6f9e78:	3d 00 f3 01 00       	cmp    eax,0x1f300
  6f9e7d:	74 10                	je     0x6f9e8f
  6f9e7f:	eb 5c                	jmp    0x6f9edd
  6f9e81:	3d 00 f0 00 00       	cmp    eax,0xf000
  6f9e86:	74 07                	je     0x6f9e8f
  6f9e88:	3d 00 f1 00 00       	cmp    eax,0xf100
  6f9e8d:	75 4e                	jne    0x6f9edd
  6f9e8f:	4c 89 f7             	mov    rdi,r14
  6f9e92:	e8 d9 2d 30 00       	call   0x9fcc70
  6f9e97:	48 89 c7             	mov    rdi,rax
  6f9e9a:	e8 41 2e 30 00       	call   0x9fcce0
  6f9e9f:	0f b7 40 29          	movzx  eax,WORD PTR [rax+0x29]
  6f9ea3:	a9 80 03 00 00       	test   eax,0x380
  6f9ea8:	75 33                	jne    0x6f9edd
  6f9eaa:	41 81 be d4 05 00 00 	cmp    DWORD PTR [r14+0x5d4],0x2ffffff
  6f9eb1:	ff ff ff 02 
  6f9eb5:	77 26                	ja     0x6f9edd
  6f9eb7:	48 c7 05 1e 15 b0 01 	mov    QWORD PTR [rip+0x1b0151e],0xfff8        # 0x21fb3e0
  6f9ebe:	f8 ff 00 00 
  6f9ec2:	be 02 00 00 00       	mov    esi,0x2
  6f9ec7:	49 8b be 80 05 00 00 	mov    rdi,QWORD PTR [r14+0x580]
  6f9ece:	e8 dd 2e 30 00       	call   0x9fcdb0
  6f9ed3:	bf 02 00 00 00       	mov    edi,0x2
  6f9ed8:	e8 73 07 00 00       	call   0x6fa650
  6f9edd:	48 8d 15 2e fe b7 00 	lea    rdx,[rip+0xb7fe2e]        # 0x1279d12
  6f9ee4:	48 89 df             	mov    rdi,rbx
  6f9ee7:	b9 72 05 00 00       	mov    ecx,0x572
  6f9eec:	31 f6                	xor    esi,esi
  6f9eee:	e8 bd d9 dc ff       	call   0x4c78b0
  6f9ef3:	c7 83 84 03 00 00 02 	mov    DWORD PTR [rbx+0x384],0x2
  6f9efa:	00 00 00 
  6f9efd:	31 f6                	xor    esi,esi
  6f9eff:	31 d2                	xor    edx,edx
  6f9f01:	31 c9                	xor    ecx,ecx
  6f9f03:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
  6f9f06:	48 83 c7 18          	add    rdi,0x18
  6f9f0a:	e8 11 d6 dc ff       	call   0x4c7520
  6f9f0f:	8b 05 ab 14 b0 01    	mov    eax,DWORD PTR [rip+0x1b014ab]        # 0x21fb3c0
  6f9f15:	83 f8 01             	cmp    eax,0x1
  6f9f18:	75 4a                	jne    0x6f9f64
  6f9f1a:	48 8d 15 f1 fd b7 00 	lea    rdx,[rip+0xb7fdf1]        # 0x1279d12
  6f9f21:	48 89 df             	mov    rdi,rbx
  6f9f24:	b9 7b 05 00 00       	mov    ecx,0x57b
  6f9f29:	31 f6                	xor    esi,esi
  6f9f2b:	48 c7 45 d8 a8 aa 00 	mov    QWORD PTR [rbp-0x28],0xaaa8
  6f9f32:	00 
  6f9f33:	e8 78 d9 dc ff       	call   0x4c78b0
  6f9f38:	48 8d 75 d8          	lea    rsi,[rbp-0x28]
  6f9f3c:	48 89 df             	mov    rdi,rbx
  6f9f3f:	e8 8c 2c 14 00       	call   0x83cbd0
  6f9f44:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
  6f9f47:	31 f6                	xor    esi,esi
  6f9f49:	31 d2                	xor    edx,edx
  6f9f4b:	31 c9                	xor    ecx,ecx
  6f9f4d:	48 83 c7 18          	add    rdi,0x18
  6f9f51:	e8 ca d5 dc ff       	call   0x4c7520
  6f9f56:	41 8b be cc 05 00 00 	mov    edi,DWORD PTR [r14+0x5cc]
  6f9f5d:	be 55 15 00 00       	mov    esi,0x1555
  6f9f62:	eb 5c                	jmp    0x6f9fc0
  6f9f64:	83 3d 55 14 b0 01 00 	cmp    DWORD PTR [rip+0x1b01455],0x0        # 0x21fb3c0
  6f9f6b:	74 0b                	je     0x6f9f78
  6f9f6d:	8b 05 4d 14 b0 01    	mov    eax,DWORD PTR [rip+0x1b0144d]        # 0x21fb3c0
  6f9f73:	83 f8 02             	cmp    eax,0x2
  6f9f76:	75 4d                	jne    0x6f9fc5
  6f9f78:	48 8d 15 93 fd b7 00 	lea    rdx,[rip+0xb7fd93]        # 0x1279d12
  6f9f7f:	48 89 df             	mov    rdi,rbx
  6f9f82:	b9 85 05 00 00       	mov    ecx,0x585
  6f9f87:	31 f6                	xor    esi,esi
  6f9f89:	48 c7 45 d8 a0 aa 00 	mov    QWORD PTR [rbp-0x28],0xaaa0
  6f9f90:	00 
  6f9f91:	e8 1a d9 dc ff       	call   0x4c78b0
  6f9f96:	48 8d 75 d8          	lea    rsi,[rbp-0x28]
  6f9f9a:	48 89 df             	mov    rdi,rbx
  6f9f9d:	e8 2e 2c 14 00       	call   0x83cbd0
  6f9fa2:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
  6f9fa5:	31 f6                	xor    esi,esi
  6f9fa7:	31 d2                	xor    edx,edx
  6f9fa9:	31 c9                	xor    ecx,ecx
  6f9fab:	48 83 c7 18          	add    rdi,0x18
  6f9faf:	e8 6c d5 dc ff       	call   0x4c7520
  6f9fb4:	41 8b be cc 05 00 00 	mov    edi,DWORD PTR [r14+0x5cc]
  6f9fbb:	be 55 05 00 00       	mov    esi,0x555
  6f9fc0:	e8 6b ca ea ff       	call   0x5a6a30
  6f9fc5:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6f9fc8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  6f9fcc:	75 15                	jne    0x6f9fe3
  6f9fce:	48 83 c4 18          	add    rsp,0x18
  6f9fd2:	5b                   	pop    rbx
  6f9fd3:	41 5e                	pop    r14
  6f9fd5:	41 5f                	pop    r15
  6f9fd7:	5d                   	pop    rbp
  6f9fd8:	c3                   	ret
  6f9fd9:	e8 22 06 00 00       	call   0x6fa600
  6f9fde:	e9 1a fe ff ff       	jmp    0x6f9dfd
  6f9fe3:	e8 c8 36 00 00       	call   0x6fd6b0
  6f9fe8:	0f 0b                	ud2
  6f9fea:	e8 61 79 0f 00       	call   0x7f1950
  6f9fef:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6f9fea
  6f9ff6:	e8 15 78 0f 00       	call   0x7f1810
  6f9ffb:	48 8d 35 44 da c8 00 	lea    rsi,[rip+0xc8da44]        # 0x1387a46
  6fa002:	bf 2b 00 00 00       	mov    edi,0x2b
  6fa007:	eb 1d                	jmp    0x6fa026
  6fa009:	e8 42 79 0f 00       	call   0x7f1950
  6fa00e:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6fa009
  6fa015:	e8 f6 77 0f 00       	call   0x7f1810
  6fa01a:	48 8d 35 d4 fc c2 00 	lea    rsi,[rip+0xc2fcd4]        # 0x1329cf5
  6fa021:	bf 2f 00 00 00       	mov    edi,0x2f
  6fa026:	31 c0                	xor    eax,eax
  6fa028:	e8 e3 09 5a 00       	call   0xc9aa10
  6fa02d:	0f 0b                	ud2
  6fa02f:	90                   	nop
  6fa030:	55                   	push   rbp
  6fa031:	48 89 e5             	mov    rbp,rsp
  6fa034:	41 57                	push   r15
  6fa036:	41 56                	push   r14
  6fa038:	53                   	push   rbx
  6fa039:	50                   	push   rax
  6fa03a:	48 89 f7             	mov    rdi,rsi
  6fa03d:	48 89 f3             	mov    rbx,rsi
  6fa040:	e8 5b 2c 30 00       	call   0x9fcca0
  6fa045:	3d ff ff ff 00       	cmp    eax,0xffffff
  6fa04a:	76 0b                	jbe    0x6fa057
  6fa04c:	48 83 c4 08          	add    rsp,0x8
  6fa050:	5b                   	pop    rbx
  6fa051:	41 5e                	pop    r14
  6fa053:	41 5f                	pop    r15
  6fa055:	5d                   	pop    rbp
  6fa056:	c3                   	ret
  6fa057:	48 89 df             	mov    rdi,rbx
  6fa05a:	41 89 c6             	mov    r14d,eax
  6fa05d:	e8 7e 2c 30 00       	call   0x9fcce0
  6fa062:	41 f7 c6 00 f0 00 00 	test   r14d,0xf000
  6fa069:	74 50                	je     0x6fa0bb
  6fa06b:	44 8b 78 28          	mov    r15d,DWORD PTR [rax+0x28]
  6fa06f:	41 81 e7 00 80 03 00 	and    r15d,0x38000
  6fa076:	44 89 f8             	mov    eax,r15d
  6fa079:	c1 e8 0f             	shr    eax,0xf
  6fa07c:	83 f8 03             	cmp    eax,0x3
  6fa07f:	0f 87 df 00 00 00    	ja     0x6fa164
  6fa085:	48 8d 0d f0 1e 03 01 	lea    rcx,[rip+0x1031ef0]        # 0x172bf7c
  6fa08c:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
  6fa090:	48 01 c8             	add    rax,rcx
  6fa093:	ff e0                	jmp    rax
  6fa095:	41 81 fe ff ef 01 00 	cmp    r14d,0x1efff
  6fa09c:	7e 50                	jle    0x6fa0ee
  6fa09e:	41 81 fe 00 f0 01 00 	cmp    r14d,0x1f000
  6fa0a5:	74 59                	je     0x6fa100
  6fa0a7:	41 81 fe 00 f3 01 00 	cmp    r14d,0x1f300
  6fa0ae:	74 50                	je     0x6fa100
  6fa0b0:	41 81 fe 00 f0 02 00 	cmp    r14d,0x2f000
  6fa0b7:	74 47                	je     0x6fa100
  6fa0b9:	eb 75                	jmp    0x6fa130
  6fa0bb:	0f b6 48 4b          	movzx  ecx,BYTE PTR [rax+0x4b]
  6fa0bf:	41 be 03 00 00 00    	mov    r14d,0x3
  6fa0c5:	85 c9                	test   ecx,ecx
  6fa0c7:	74 18                	je     0x6fa0e1
  6fa0c9:	83 f9 01             	cmp    ecx,0x1
  6fa0cc:	75 6c                	jne    0x6fa13a
  6fa0ce:	41 be 05 00 00 00    	mov    r14d,0x5
  6fa0d4:	eb 0b                	jmp    0x6fa0e1
  6fa0d6:	45 31 f6             	xor    r14d,r14d
  6fa0d9:	eb 06                	jmp    0x6fa0e1
  6fa0db:	41 be 02 00 00 00    	mov    r14d,0x2
  6fa0e1:	48 89 df             	mov    rdi,rbx
  6fa0e4:	44 89 f6             	mov    esi,r14d
  6fa0e7:	e8 c4 2c 30 00       	call   0x9fcdb0
  6fa0ec:	eb 30                	jmp    0x6fa11e
  6fa0ee:	41 81 fe 00 f0 00 00 	cmp    r14d,0xf000
  6fa0f5:	74 09                	je     0x6fa100
  6fa0f7:	41 81 fe 00 f1 00 00 	cmp    r14d,0xf100
  6fa0fe:	75 30                	jne    0x6fa130
  6fa100:	48 89 df             	mov    rdi,rbx
  6fa103:	be 01 00 00 00       	mov    esi,0x1
  6fa108:	41 be 01 00 00 00    	mov    r14d,0x1
  6fa10e:	e8 9d 2c 30 00       	call   0x9fcdb0
  6fa113:	48 c7 05 c2 12 b0 01 	mov    QWORD PTR [rip+0x1b012c2],0xaaa8        # 0x21fb3e0
  6fa11a:	a8 aa 00 00 
  6fa11e:	44 89 f7             	mov    edi,r14d
  6fa121:	48 83 c4 08          	add    rsp,0x8
  6fa125:	5b                   	pop    rbx
  6fa126:	41 5e                	pop    r14
  6fa128:	41 5f                	pop    r15
  6fa12a:	5d                   	pop    rbp
  6fa12b:	e9 20 05 00 00       	jmp    0x6fa650
  6fa130:	45 31 f6             	xor    r14d,r14d
  6fa133:	48 89 df             	mov    rdi,rbx
  6fa136:	31 f6                	xor    esi,esi
  6fa138:	eb ad                	jmp    0x6fa0e7
  6fa13a:	48 89 c3             	mov    rbx,rax
  6fa13d:	e8 0e 78 0f 00       	call   0x7f1950
  6fa142:	0f b6 73 4b          	movzx  esi,BYTE PTR [rbx+0x4b]
  6fa146:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fa13a
  6fa14d:	e8 4e 77 0f 00       	call   0x7f18a0
  6fa152:	0f b6 53 4b          	movzx  edx,BYTE PTR [rbx+0x4b]
  6fa156:	48 8d 35 92 cb bd 00 	lea    rsi,[rip+0xbdcb92]        # 0x12d6cef
  6fa15d:	bf 33 00 00 00       	mov    edi,0x33
  6fa162:	eb 23                	jmp    0x6fa187
  6fa164:	e8 e7 77 0f 00       	call   0x7f1950
  6fa169:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6fa164
  6fa170:	4c 89 fe             	mov    rsi,r15
  6fa173:	e8 28 77 0f 00       	call   0x7f18a0
  6fa178:	48 8d 35 40 0a bf 00 	lea    rsi,[rip+0xbf0a40]        # 0x12eabbf
  6fa17f:	bf 37 00 00 00       	mov    edi,0x37
  6fa184:	44 89 fa             	mov    edx,r15d
  6fa187:	31 c0                	xor    eax,eax
  6fa189:	e8 82 08 5a 00       	call   0xc9aa10
  6fa18e:	0f 0b                	ud2
  6fa190:	55                   	push   rbp
  6fa191:	48 89 e5             	mov    rbp,rsp
  6fa194:	41 57                	push   r15
  6fa196:	41 56                	push   r14
  6fa198:	53                   	push   rbx
  6fa199:	50                   	push   rax
  6fa19a:	48 89 f7             	mov    rdi,rsi
  6fa19d:	e8 fe 2a 30 00       	call   0x9fcca0
  6fa1a2:	83 3d 27 12 b0 01 00 	cmp    DWORD PTR [rip+0x1b01227],0x0        # 0x21fb3d0
  6fa1a9:	0f 95 c1             	setne  cl
  6fa1ac:	3d 00 01 00 02       	cmp    eax,0x2000100
  6fa1b1:	0f 94 c2             	sete   dl
  6fa1b4:	20 ca                	and    dl,cl
  6fa1b6:	80 fa 01             	cmp    dl,0x1
  6fa1b9:	0f 85 0c 01 00 00    	jne    0x6fa2cb
  6fa1bf:	48 8d 3d d2 1f 22 03 	lea    rdi,[rip+0x3221fd2]        # 0x391c198
  6fa1c6:	31 f6                	xor    esi,esi
  6fa1c8:	31 d2                	xor    edx,edx
  6fa1ca:	31 c9                	xor    ecx,ecx
  6fa1cc:	e8 bf cf dc ff       	call   0x4c7190
  6fa1d1:	c7 05 f5 11 b0 01 00 	mov    DWORD PTR [rip+0x1b011f5],0x0        # 0x21fb3d0
  6fa1d8:	00 00 00 
  6fa1db:	8b 05 f3 11 b0 01    	mov    eax,DWORD PTR [rip+0x1b011f3]        # 0x21fb3d4
  6fa1e1:	83 f8 01             	cmp    eax,0x1
  6fa1e4:	0f 85 f3 00 00 00    	jne    0x6fa2dd
  6fa1ea:	83 3d e3 11 b0 01 00 	cmp    DWORD PTR [rip+0x1b011e3],0x0        # 0x21fb3d4
  6fa1f1:	74 68                	je     0x6fa25b
  6fa1f3:	31 ff                	xor    edi,edi
  6fa1f5:	e8 86 dc fb ff       	call   0x6b7e80
  6fa1fa:	48 8d 1d b7 1f 22 03 	lea    rbx,[rip+0x3221fb7]        # 0x391c1b8
  6fa201:	31 f6                	xor    esi,esi
  6fa203:	31 d2                	xor    edx,edx
  6fa205:	31 c9                	xor    ecx,ecx
  6fa207:	48 89 df             	mov    rdi,rbx
  6fa20a:	e8 81 cf dc ff       	call   0x4c7190
  6fa20f:	48 8d 3d d2 1f 22 03 	lea    rdi,[rip+0x3221fd2]        # 0x391c1e8
  6fa216:	e8 15 d4 3c 00       	call   0xac7630
  6fa21b:	48 8d 3d d6 11 b0 01 	lea    rdi,[rip+0x1b011d6]        # 0x21fb3f8
  6fa222:	be 10 00 00 00       	mov    esi,0x10
  6fa227:	c7 05 bf 11 b0 01 00 	mov    DWORD PTR [rip+0x1b011bf],0x0        # 0x21fb3f0
  6fa22e:	00 00 00 
  6fa231:	e8 ba ed b5 ff       	call   0x258ff0
  6fa236:	48 89 df             	mov    rdi,rbx
  6fa239:	31 f6                	xor    esi,esi
  6fa23b:	31 d2                	xor    edx,edx
  6fa23d:	31 c9                	xor    ecx,ecx
  6fa23f:	e8 dc d2 dc ff       	call   0x4c7520
  6fa244:	c7 05 86 11 b0 01 00 	mov    DWORD PTR [rip+0x1b01186],0x0        # 0x21fb3d4
  6fa24b:	00 00 00 
  6fa24e:	83 3d b3 11 b0 01 00 	cmp    DWORD PTR [rip+0x1b011b3],0x0        # 0x21fb408
  6fa255:	0f 85 f0 00 00 00    	jne    0x6fa34b
  6fa25b:	48 8d 1d b0 fa b7 00 	lea    rbx,[rip+0xb7fab0]        # 0x1279d12
  6fa262:	45 31 ff             	xor    r15d,r15d
  6fa265:	eb 1c                	jmp    0x6fa283
  6fa267:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  6fa26e:	00 00 
  6fa270:	31 ff                	xor    edi,edi
  6fa272:	e8 89 c9 fb ff       	call   0x6b6c00
  6fa277:	41 ff c7             	inc    r15d
  6fa27a:	44 3b 3d 37 46 61 03 	cmp    r15d,DWORD PTR [rip+0x3614637]        # 0x3d0e8b8
  6fa281:	77 5a                	ja     0x6fa2dd
  6fa283:	45 85 ff             	test   r15d,r15d
  6fa286:	75 ef                	jne    0x6fa277
  6fa288:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6fa28f:	00 
  6fa290:	85 c0                	test   eax,eax
  6fa292:	75 dc                	jne    0x6fa270
  6fa294:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  6fa29b:	00 00 
  6fa29d:	4c 89 f7             	mov    rdi,r14
  6fa2a0:	48 89 da             	mov    rdx,rbx
  6fa2a3:	b9 b4 02 00 00       	mov    ecx,0x2b4
  6fa2a8:	31 f6                	xor    esi,esi
  6fa2aa:	e8 01 d6 dc ff       	call   0x4c78b0
  6fa2af:	4c 89 f7             	mov    rdi,r14
  6fa2b2:	e8 39 ca fb ff       	call   0x6b6cf0
  6fa2b7:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  6fa2ba:	31 f6                	xor    esi,esi
  6fa2bc:	31 d2                	xor    edx,edx
  6fa2be:	31 c9                	xor    ecx,ecx
  6fa2c0:	48 83 c7 18          	add    rdi,0x18
  6fa2c4:	e8 57 d2 dc ff       	call   0x4c7520
  6fa2c9:	eb ac                	jmp    0x6fa277
  6fa2cb:	3d ff ff ff 00       	cmp    eax,0xffffff
  6fa2d0:	76 1b                	jbe    0x6fa2ed
  6fa2d2:	48 83 c4 08          	add    rsp,0x8
  6fa2d6:	5b                   	pop    rbx
  6fa2d7:	41 5e                	pop    r14
  6fa2d9:	41 5f                	pop    r15
  6fa2db:	5d                   	pop    rbp
  6fa2dc:	c3                   	ret
  6fa2dd:	83 3d 24 11 b0 01 00 	cmp    DWORD PTR [rip+0x1b01124],0x0        # 0x21fb408
  6fa2e4:	74 49                	je     0x6fa32f
  6fa2e6:	e8 55 0b 00 00       	call   0x6fae40
  6fa2eb:	eb 42                	jmp    0x6fa32f
  6fa2ed:	bf 04 00 00 00       	mov    edi,0x4
  6fa2f2:	e8 59 03 00 00       	call   0x6fa650
  6fa2f7:	48 8d 3d 9a 1e 22 03 	lea    rdi,[rip+0x3221e9a]        # 0x391c198
  6fa2fe:	31 f6                	xor    esi,esi
  6fa300:	31 d2                	xor    edx,edx
  6fa302:	31 c9                	xor    ecx,ecx
  6fa304:	e8 87 ce dc ff       	call   0x4c7190
  6fa309:	48 b8 6a 0a 00 00 6a 	movabs rax,0xa6a00000a6a
  6fa310:	0a 00 00 
  6fa313:	c7 05 bb 10 b0 01 ff 	mov    DWORD PTR [rip+0x1b010bb],0xff        # 0x21fb3d8
  6fa31a:	00 00 00 
  6fa31d:	48 c7 05 b8 10 b0 01 	mov    QWORD PTR [rip+0x1b010b8],0xfff8        # 0x21fb3e0
  6fa324:	f8 ff 00 00 
  6fa328:	48 89 05 b9 10 b0 01 	mov    QWORD PTR [rip+0x1b010b9],rax        # 0x21fb3e8
  6fa32f:	48 8d 3d 62 1e 22 03 	lea    rdi,[rip+0x3221e62]        # 0x391c198
  6fa336:	31 f6                	xor    esi,esi
  6fa338:	31 d2                	xor    edx,edx
  6fa33a:	31 c9                	xor    ecx,ecx
  6fa33c:	48 83 c4 08          	add    rsp,0x8
  6fa340:	5b                   	pop    rbx
  6fa341:	41 5e                	pop    r14
  6fa343:	41 5f                	pop    r15
  6fa345:	5d                   	pop    rbp
  6fa346:	e9 d5 d1 dc ff       	jmp    0x4c7520
  6fa34b:	8b 3d 83 10 b0 01    	mov    edi,DWORD PTR [rip+0x1b01083]        # 0x21fb3d4
  6fa351:	be 01 00 00 00       	mov    esi,0x1
  6fa356:	e8 05 f6 ff ff       	call   0x6f9960
  6fa35b:	e9 fb fe ff ff       	jmp    0x6fa25b
  6fa360:	55                   	push   rbp
  6fa361:	48 89 e5             	mov    rbp,rsp
  6fa364:	41 57                	push   r15
  6fa366:	41 56                	push   r14
  6fa368:	41 54                	push   r12
  6fa36a:	53                   	push   rbx
  6fa36b:	48 89 f7             	mov    rdi,rsi
  6fa36e:	e8 2d 29 30 00       	call   0x9fcca0
  6fa373:	89 c3                	mov    ebx,eax
  6fa375:	3d 00 01 00 02       	cmp    eax,0x2000100
  6fa37a:	0f 85 36 01 00 00    	jne    0x6fa4b6
  6fa380:	48 8d 3d 11 1e 22 03 	lea    rdi,[rip+0x3221e11]        # 0x391c198
  6fa387:	31 f6                	xor    esi,esi
  6fa389:	31 d2                	xor    edx,edx
  6fa38b:	31 c9                	xor    ecx,ecx
  6fa38d:	e8 fe cd dc ff       	call   0x4c7190
  6fa392:	83 3d 37 10 b0 01 00 	cmp    DWORD PTR [rip+0x1b01037],0x0        # 0x21fb3d0
  6fa399:	0f 84 56 01 00 00    	je     0x6fa4f5
  6fa39f:	c7 05 27 10 b0 01 00 	mov    DWORD PTR [rip+0x1b01027],0x0        # 0x21fb3d0
  6fa3a6:	00 00 00 
  6fa3a9:	8b 05 25 10 b0 01    	mov    eax,DWORD PTR [rip+0x1b01025]        # 0x21fb3d4
  6fa3af:	83 f8 01             	cmp    eax,0x1
  6fa3b2:	0f 85 e3 00 00 00    	jne    0x6fa49b
  6fa3b8:	83 3d 15 10 b0 01 00 	cmp    DWORD PTR [rip+0x1b01015],0x0        # 0x21fb3d4
  6fa3bf:	74 68                	je     0x6fa429
  6fa3c1:	31 ff                	xor    edi,edi
  6fa3c3:	e8 b8 da fb ff       	call   0x6b7e80
  6fa3c8:	4c 8d 35 e9 1d 22 03 	lea    r14,[rip+0x3221de9]        # 0x391c1b8
  6fa3cf:	31 f6                	xor    esi,esi
  6fa3d1:	31 d2                	xor    edx,edx
  6fa3d3:	31 c9                	xor    ecx,ecx
  6fa3d5:	4c 89 f7             	mov    rdi,r14
  6fa3d8:	e8 b3 cd dc ff       	call   0x4c7190
  6fa3dd:	48 8d 3d 04 1e 22 03 	lea    rdi,[rip+0x3221e04]        # 0x391c1e8
  6fa3e4:	e8 47 d2 3c 00       	call   0xac7630
  6fa3e9:	48 8d 3d 08 10 b0 01 	lea    rdi,[rip+0x1b01008]        # 0x21fb3f8
  6fa3f0:	be 10 00 00 00       	mov    esi,0x10
  6fa3f5:	c7 05 f1 0f b0 01 00 	mov    DWORD PTR [rip+0x1b00ff1],0x0        # 0x21fb3f0
  6fa3fc:	00 00 00 
  6fa3ff:	e8 ec eb b5 ff       	call   0x258ff0
  6fa404:	4c 89 f7             	mov    rdi,r14
  6fa407:	31 f6                	xor    esi,esi
  6fa409:	31 d2                	xor    edx,edx
  6fa40b:	31 c9                	xor    ecx,ecx
  6fa40d:	e8 0e d1 dc ff       	call   0x4c7520
  6fa412:	c7 05 b8 0f b0 01 00 	mov    DWORD PTR [rip+0x1b00fb8],0x0        # 0x21fb3d4
  6fa419:	00 00 00 
  6fa41c:	83 3d e5 0f b0 01 00 	cmp    DWORD PTR [rip+0x1b00fe5],0x0        # 0x21fb408
  6fa423:	0f 85 b7 00 00 00    	jne    0x6fa4e0
  6fa429:	4c 8d 35 e2 f8 b7 00 	lea    r14,[rip+0xb7f8e2]        # 0x1279d12
  6fa430:	45 31 e4             	xor    r12d,r12d
  6fa433:	eb 1e                	jmp    0x6fa453
  6fa435:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fa43c:	00 00 00 00 
  6fa440:	31 ff                	xor    edi,edi
  6fa442:	e8 b9 c7 fb ff       	call   0x6b6c00
  6fa447:	41 ff c4             	inc    r12d
  6fa44a:	44 3b 25 67 44 61 03 	cmp    r12d,DWORD PTR [rip+0x3614467]        # 0x3d0e8b8
  6fa451:	77 48                	ja     0x6fa49b
  6fa453:	45 85 e4             	test   r12d,r12d
  6fa456:	75 ef                	jne    0x6fa447
  6fa458:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6fa45f:	00 
  6fa460:	85 c0                	test   eax,eax
  6fa462:	75 dc                	jne    0x6fa440
  6fa464:	65 4c 8b 3c 25 00 00 	mov    r15,QWORD PTR gs:0x0
  6fa46b:	00 00 
  6fa46d:	4c 89 ff             	mov    rdi,r15
  6fa470:	4c 89 f2             	mov    rdx,r14
  6fa473:	b9 b4 02 00 00       	mov    ecx,0x2b4
  6fa478:	31 f6                	xor    esi,esi
  6fa47a:	e8 31 d4 dc ff       	call   0x4c78b0
  6fa47f:	4c 89 ff             	mov    rdi,r15
  6fa482:	e8 69 c8 fb ff       	call   0x6b6cf0
  6fa487:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  6fa48a:	31 f6                	xor    esi,esi
  6fa48c:	31 d2                	xor    edx,edx
  6fa48e:	31 c9                	xor    ecx,ecx
  6fa490:	48 83 c7 18          	add    rdi,0x18
  6fa494:	e8 87 d0 dc ff       	call   0x4c7520
  6fa499:	eb ac                	jmp    0x6fa447
  6fa49b:	83 3d 66 0f b0 01 00 	cmp    DWORD PTR [rip+0x1b00f66],0x0        # 0x21fb408
  6fa4a2:	75 35                	jne    0x6fa4d9
  6fa4a4:	48 8d 3d ed 1c 22 03 	lea    rdi,[rip+0x3221ced]        # 0x391c198
  6fa4ab:	31 f6                	xor    esi,esi
  6fa4ad:	31 d2                	xor    edx,edx
  6fa4af:	31 c9                	xor    ecx,ecx
  6fa4b1:	e8 6a d0 dc ff       	call   0x4c7520
  6fa4b6:	81 fb ff ff ff 00    	cmp    ebx,0xffffff
  6fa4bc:	76 09                	jbe    0x6fa4c7
  6fa4be:	5b                   	pop    rbx
  6fa4bf:	41 5c                	pop    r12
  6fa4c1:	41 5e                	pop    r14
  6fa4c3:	41 5f                	pop    r15
  6fa4c5:	5d                   	pop    rbp
  6fa4c6:	c3                   	ret
  6fa4c7:	bf 04 00 00 00       	mov    edi,0x4
  6fa4cc:	5b                   	pop    rbx
  6fa4cd:	41 5c                	pop    r12
  6fa4cf:	41 5e                	pop    r14
  6fa4d1:	41 5f                	pop    r15
  6fa4d3:	5d                   	pop    rbp
  6fa4d4:	e9 77 01 00 00       	jmp    0x6fa650
  6fa4d9:	e8 62 09 00 00       	call   0x6fae40
  6fa4de:	eb c4                	jmp    0x6fa4a4
  6fa4e0:	8b 3d ee 0e b0 01    	mov    edi,DWORD PTR [rip+0x1b00eee]        # 0x21fb3d4
  6fa4e6:	be 01 00 00 00       	mov    esi,0x1
  6fa4eb:	e8 70 f4 ff ff       	call   0x6f9960
  6fa4f0:	e9 34 ff ff ff       	jmp    0x6fa429
  6fa4f5:	e8 56 74 0f 00       	call   0x7f1950
  6fa4fa:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6fa4f5
  6fa501:	e8 0a 73 0f 00       	call   0x7f1810
  6fa506:	48 8d 35 f3 80 cb 00 	lea    rsi,[rip+0xcb80f3]        # 0x13b2600
  6fa50d:	bf 3b 00 00 00       	mov    edi,0x3b
  6fa512:	31 c0                	xor    eax,eax
  6fa514:	e8 f7 04 5a 00       	call   0xc9aa10
  6fa519:	0f 0b                	ud2
  6fa51b:	90                   	nop
  6fa51c:	90                   	nop
  6fa51d:	90                   	nop
  6fa51e:	90                   	nop
  6fa51f:	90                   	nop
  6fa520:	55                   	push   rbp
  6fa521:	48 89 e5             	mov    rbp,rsp
  6fa524:	53                   	push   rbx
  6fa525:	50                   	push   rax
  6fa526:	48 89 f7             	mov    rdi,rsi
  6fa529:	48 89 f3             	mov    rbx,rsi
  6fa52c:	e8 6f 27 30 00       	call   0x9fcca0
  6fa531:	3d 00 01 00 02       	cmp    eax,0x2000100
  6fa536:	75 51                	jne    0x6fa589
  6fa538:	48 8d 3d 59 1c 22 03 	lea    rdi,[rip+0x3221c59]        # 0x391c198
  6fa53f:	31 f6                	xor    esi,esi
  6fa541:	31 d2                	xor    edx,edx
  6fa543:	31 c9                	xor    ecx,ecx
  6fa545:	e8 46 cc dc ff       	call   0x4c7190
  6fa54a:	83 3d 7f 0e b0 01 00 	cmp    DWORD PTR [rip+0x1b00e7f],0x0        # 0x21fb3d0
  6fa551:	75 60                	jne    0x6fa5b3
  6fa553:	8b 05 7b 0e b0 01    	mov    eax,DWORD PTR [rip+0x1b00e7b]        # 0x21fb3d4
  6fa559:	83 f8 01             	cmp    eax,0x1
  6fa55c:	74 74                	je     0x6fa5d2
  6fa55e:	c7 05 68 0e b0 01 01 	mov    DWORD PTR [rip+0x1b00e68],0x1        # 0x21fb3d0
  6fa565:	00 00 00 
  6fa568:	83 3d 99 0e b0 01 00 	cmp    DWORD PTR [rip+0x1b00e99],0x0        # 0x21fb408
  6fa56f:	75 3b                	jne    0x6fa5ac
  6fa571:	48 8d 3d 20 1c 22 03 	lea    rdi,[rip+0x3221c20]        # 0x391c198
  6fa578:	31 f6                	xor    esi,esi
  6fa57a:	31 d2                	xor    edx,edx
  6fa57c:	31 c9                	xor    ecx,ecx
  6fa57e:	48 83 c4 08          	add    rsp,0x8
  6fa582:	5b                   	pop    rbx
  6fa583:	5d                   	pop    rbp
  6fa584:	e9 97 cf dc ff       	jmp    0x4c7520
  6fa589:	3d ff ff ff 00       	cmp    eax,0xffffff
  6fa58e:	76 07                	jbe    0x6fa597
  6fa590:	48 83 c4 08          	add    rsp,0x8
  6fa594:	5b                   	pop    rbx
  6fa595:	5d                   	pop    rbp
  6fa596:	c3                   	ret
  6fa597:	48 89 df             	mov    rdi,rbx
  6fa59a:	e8 21 28 30 00       	call   0x9fcdc0
  6fa59f:	89 c7                	mov    edi,eax
  6fa5a1:	48 83 c4 08          	add    rsp,0x8
  6fa5a5:	5b                   	pop    rbx
  6fa5a6:	5d                   	pop    rbp
  6fa5a7:	e9 a4 00 00 00       	jmp    0x6fa650
  6fa5ac:	e8 4f 00 00 00       	call   0x6fa600
  6fa5b1:	eb be                	jmp    0x6fa571
  6fa5b3:	e8 98 73 0f 00       	call   0x7f1950
  6fa5b8:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6fa5b3
  6fa5bf:	e8 4c 72 0f 00       	call   0x7f1810
  6fa5c4:	48 8d 35 2b 96 c5 00 	lea    rsi,[rip+0xc5962b]        # 0x1353bf6
  6fa5cb:	bf 3f 00 00 00       	mov    edi,0x3f
  6fa5d0:	eb 1d                	jmp    0x6fa5ef
  6fa5d2:	e8 79 73 0f 00       	call   0x7f1950
  6fa5d7:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x6fa5d2
  6fa5de:	e8 2d 72 0f 00       	call   0x7f1810
  6fa5e3:	48 8d 35 26 c7 bd 00 	lea    rsi,[rip+0xbdc726]        # 0x12d6d10
  6fa5ea:	bf 43 00 00 00       	mov    edi,0x43
  6fa5ef:	31 c0                	xor    eax,eax
  6fa5f1:	e8 1a 04 5a 00       	call   0xc9aa10
  6fa5f6:	0f 0b                	ud2
  6fa5f8:	90                   	nop
  6fa5f9:	90                   	nop
  6fa5fa:	90                   	nop
  6fa5fb:	90                   	nop
  6fa5fc:	90                   	nop
  6fa5fd:	90                   	nop
  6fa5fe:	90                   	nop
  6fa5ff:	90                   	nop
  6fa600:	55                   	push   rbp
  6fa601:	48 89 e5             	mov    rbp,rsp
  6fa604:	53                   	push   rbx
  6fa605:	50                   	push   rax
  6fa606:	48 8d 1d d3 1b 22 03 	lea    rbx,[rip+0x3221bd3]        # 0x391c1e0
  6fa60d:	31 f6                	xor    esi,esi
  6fa60f:	31 d2                	xor    edx,edx
  6fa611:	31 c9                	xor    ecx,ecx
  6fa613:	48 89 df             	mov    rdi,rbx
  6fa616:	e8 75 cb dc ff       	call   0x4c7190
  6fa61b:	0f 31                	rdtsc
  6fa61d:	89 c0                	mov    eax,eax
  6fa61f:	48 c1 e2 20          	shl    rdx,0x20
  6fa623:	48 89 df             	mov    rdi,rbx
  6fa626:	31 f6                	xor    esi,esi
  6fa628:	31 c9                	xor    ecx,ecx
  6fa62a:	48 09 c2             	or     rdx,rax
  6fa62d:	48 89 15 1c 0d b0 01 	mov    QWORD PTR [rip+0x1b00d1c],rdx        # 0x21fb350
  6fa634:	c7 05 1a 0d b0 01 00 	mov    DWORD PTR [rip+0x1b00d1a],0x0        # 0x21fb358
  6fa63b:	00 00 00 
  6fa63e:	31 d2                	xor    edx,edx
  6fa640:	48 83 c4 08          	add    rsp,0x8
  6fa644:	5b                   	pop    rbx
  6fa645:	5d                   	pop    rbp
  6fa646:	e9 d5 ce dc ff       	jmp    0x4c7520
  6fa64b:	90                   	nop
  6fa64c:	90                   	nop
  6fa64d:	90                   	nop
  6fa64e:	90                   	nop
  6fa64f:	90                   	nop
  6fa650:	55                   	push   rbp
  6fa651:	48 89 e5             	mov    rbp,rsp
  6fa654:	41 57                	push   r15
  6fa656:	41 56                	push   r14
  6fa658:	41 55                	push   r13
  6fa65a:	41 54                	push   r12
  6fa65c:	53                   	push   rbx
  6fa65d:	48 83 ec 28          	sub    rsp,0x28
  6fa661:	48 8d 1d a8 1c 22 03 	lea    rbx,[rip+0x3221ca8]        # 0x391c310
  6fa668:	41 89 fe             	mov    r14d,edi
  6fa66b:	48 8d 3d 26 1b 22 03 	lea    rdi,[rip+0x3221b26]        # 0x391c198
  6fa672:	31 f6                	xor    esi,esi
  6fa674:	31 d2                	xor    edx,edx
  6fa676:	31 c9                	xor    ecx,ecx
  6fa678:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  6fa67b:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6fa67f:	e8 0c cb dc ff       	call   0x4c7190
  6fa684:	8b 05 36 0d b0 01    	mov    eax,DWORD PTR [rip+0x1b00d36]        # 0x21fb3c0
  6fa68a:	44 39 f0             	cmp    eax,r14d
  6fa68d:	75 2d                	jne    0x6fa6bc
  6fa68f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  6fa692:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6fa696:	0f 85 cf 04 00 00    	jne    0x6fab6b
  6fa69c:	48 8d 3d f5 1a 22 03 	lea    rdi,[rip+0x3221af5]        # 0x391c198
  6fa6a3:	31 f6                	xor    esi,esi
  6fa6a5:	31 d2                	xor    edx,edx
  6fa6a7:	31 c9                	xor    ecx,ecx
  6fa6a9:	48 83 c4 28          	add    rsp,0x28
  6fa6ad:	5b                   	pop    rbx
  6fa6ae:	41 5c                	pop    r12
  6fa6b0:	41 5d                	pop    r13
  6fa6b2:	41 5e                	pop    r14
  6fa6b4:	41 5f                	pop    r15
  6fa6b6:	5d                   	pop    rbp
  6fa6b7:	e9 64 ce dc ff       	jmp    0x4c7520
  6fa6bc:	8b 15 fe 0c b0 01    	mov    edx,DWORD PTR [rip+0x1b00cfe]        # 0x21fb3c0
  6fa6c2:	44 89 f3             	mov    ebx,r14d
  6fa6c5:	44 89 35 f4 0c b0 01 	mov    DWORD PTR [rip+0x1b00cf4],r14d        # 0x21fb3c0
  6fa6cc:	48 83 fa 05          	cmp    rdx,0x5
  6fa6d0:	0f 87 9c 04 00 00    	ja     0x6fab72
  6fa6d6:	48 8d 05 af 18 03 01 	lea    rax,[rip+0x10318af]        # 0x172bf8c
  6fa6dd:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  6fa6e1:	89 5d b4             	mov    DWORD PTR [rbp-0x4c],ebx
  6fa6e4:	48 63 0c 90          	movsxd rcx,DWORD PTR [rax+rdx*4]
  6fa6e8:	48 01 c1             	add    rcx,rax
  6fa6eb:	ff e1                	jmp    rcx
  6fa6ed:	83 fb 04             	cmp    ebx,0x4
  6fa6f0:	0f 84 de 00 00 00    	je     0x6fa7d4
  6fa6f6:	e8 55 72 0f 00       	call   0x7f1950
  6fa6fb:	4c 8b 75 b8          	mov    r14,QWORD PTR [rbp-0x48]
  6fa6ff:	48 63 d3             	movsxd rdx,ebx
  6fa702:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fa6f6
  6fa709:	4c 89 f6             	mov    rsi,r14
  6fa70c:	e8 ff 78 0f 00       	call   0x7f2010
  6fa711:	48 8d 35 ed 37 b9 00 	lea    rsi,[rip+0xb937ed]        # 0x128df05
  6fa718:	bf 17 00 00 00       	mov    edi,0x17
  6fa71d:	e9 76 04 00 00       	jmp    0x6fab98
  6fa722:	83 fb 04             	cmp    ebx,0x4
  6fa725:	0f 84 a9 00 00 00    	je     0x6fa7d4
  6fa72b:	e8 20 72 0f 00       	call   0x7f1950
  6fa730:	48 63 d3             	movsxd rdx,ebx
  6fa733:	48 8d 3d f1 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff1]        # 0x6fa72b
  6fa73a:	be 02 00 00 00       	mov    esi,0x2
  6fa73f:	e8 cc 78 0f 00       	call   0x7f2010
  6fa744:	48 8d 35 ba 37 b9 00 	lea    rsi,[rip+0xb937ba]        # 0x128df05
  6fa74b:	bf 23 00 00 00       	mov    edi,0x23
  6fa750:	ba 02 00 00 00       	mov    edx,0x2
  6fa755:	e9 41 04 00 00       	jmp    0x6fab9b
  6fa75a:	83 fb 04             	cmp    ebx,0x4
  6fa75d:	74 75                	je     0x6fa7d4
  6fa75f:	e8 ec 71 0f 00       	call   0x7f1950
  6fa764:	48 63 d3             	movsxd rdx,ebx
  6fa767:	48 8d 3d f1 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff1]        # 0x6fa75f
  6fa76e:	31 f6                	xor    esi,esi
  6fa770:	e8 9b 78 0f 00       	call   0x7f2010
  6fa775:	48 8d 35 89 37 b9 00 	lea    rsi,[rip+0xb93789]        # 0x128df05
  6fa77c:	bf 1b 00 00 00       	mov    edi,0x1b
  6fa781:	31 d2                	xor    edx,edx
  6fa783:	e9 13 04 00 00       	jmp    0x6fab9b
  6fa788:	83 fb 04             	cmp    ebx,0x4
  6fa78b:	74 5f                	je     0x6fa7ec
  6fa78d:	83 fb 02             	cmp    ebx,0x2
  6fa790:	74 5a                	je     0x6fa7ec
  6fa792:	e8 b9 71 0f 00       	call   0x7f1950
  6fa797:	48 63 d3             	movsxd rdx,ebx
  6fa79a:	48 8d 3d f1 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff1]        # 0x6fa792
  6fa7a1:	be 01 00 00 00       	mov    esi,0x1
  6fa7a6:	e8 65 78 0f 00       	call   0x7f2010
  6fa7ab:	48 8d 35 53 37 b9 00 	lea    rsi,[rip+0xb93753]        # 0x128df05
  6fa7b2:	bf 1f 00 00 00       	mov    edi,0x1f
  6fa7b7:	ba 01 00 00 00       	mov    edx,0x1
  6fa7bc:	e9 da 03 00 00       	jmp    0x6fab9b
  6fa7c1:	83 fb 05             	cmp    ebx,0x5
  6fa7c4:	0f 87 dc 03 00 00    	ja     0x6faba6
  6fa7ca:	b8 2d 00 00 00       	mov    eax,0x2d
  6fa7cf:	0f a3 d8             	bt     eax,ebx
  6fa7d2:	73 0f                	jae    0x6fa7e3
  6fa7d4:	e8 07 04 00 00       	call   0x6fabe0
  6fa7d9:	e8 32 05 00 00       	call   0x6fad10
  6fa7de:	45 31 f6             	xor    r14d,r14d
  6fa7e1:	eb 23                	jmp    0x6fa806
  6fa7e3:	83 fb 01             	cmp    ebx,0x1
  6fa7e6:	0f 85 ba 03 00 00    	jne    0x6faba6
  6fa7ec:	e8 ef 03 00 00       	call   0x6fabe0
  6fa7f1:	e8 1a 05 00 00       	call   0x6fad10
  6fa7f6:	44 0f b6 35 7a 19 22 	movzx  r14d,BYTE PTR [rip+0x322197a]        # 0x391c178
  6fa7fd:	03 
  6fa7fe:	41 83 f6 01          	xor    r14d,0x1
  6fa802:	41 c1 e6 03          	shl    r14d,0x3
  6fa806:	bb 01 00 00 00       	mov    ebx,0x1
  6fa80b:	4c 8d 25 00 f5 b7 00 	lea    r12,[rip+0xb7f500]        # 0x1279d12
  6fa812:	45 31 ff             	xor    r15d,r15d
  6fa815:	eb 1d                	jmp    0x6fa834
  6fa817:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  6fa81e:	00 00 
  6fa820:	44 89 ff             	mov    edi,r15d
  6fa823:	e8 d8 c3 fb ff       	call   0x6b6c00
  6fa828:	41 ff c7             	inc    r15d
  6fa82b:	44 3b 3d 86 40 61 03 	cmp    r15d,DWORD PTR [rip+0x3614086]        # 0x3d0e8b8
  6fa832:	77 4f                	ja     0x6fa883
  6fa834:	c4 e2 81 f7 c3       	shlx   rax,rbx,r15
  6fa839:	44 85 f0             	test   eax,r14d
  6fa83c:	74 ea                	je     0x6fa828
  6fa83e:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6fa845:	00 
  6fa846:	41 39 c7             	cmp    r15d,eax
  6fa849:	75 d5                	jne    0x6fa820
  6fa84b:	65 4c 8b 2c 25 00 00 	mov    r13,QWORD PTR gs:0x0
  6fa852:	00 00 
  6fa854:	4c 89 ef             	mov    rdi,r13
  6fa857:	4c 89 e2             	mov    rdx,r12
  6fa85a:	b9 b4 02 00 00       	mov    ecx,0x2b4
  6fa85f:	31 f6                	xor    esi,esi
  6fa861:	e8 4a d0 dc ff       	call   0x4c78b0
  6fa866:	4c 89 ef             	mov    rdi,r13
  6fa869:	e8 82 c4 fb ff       	call   0x6b6cf0
  6fa86e:	49 8b 7d 00          	mov    rdi,QWORD PTR [r13+0x0]
  6fa872:	31 f6                	xor    esi,esi
  6fa874:	31 d2                	xor    edx,edx
  6fa876:	31 c9                	xor    ecx,ecx
  6fa878:	48 83 c7 18          	add    rdi,0x18
  6fa87c:	e8 9f cc dc ff       	call   0x4c7520
  6fa881:	eb a5                	jmp    0x6fa828
  6fa883:	48 8d 3d 0e 19 22 03 	lea    rdi,[rip+0x322190e]        # 0x391c198
  6fa88a:	31 f6                	xor    esi,esi
  6fa88c:	31 d2                	xor    edx,edx
  6fa88e:	31 c9                	xor    ecx,ecx
  6fa890:	e8 8b cc dc ff       	call   0x4c7520
  6fa895:	8b 5d b4             	mov    ebx,DWORD PTR [rbp-0x4c]
  6fa898:	83 fb 05             	cmp    ebx,0x5
  6fa89b:	0f 95 c0             	setne  al
  6fa89e:	48 83 7d b8 05       	cmp    QWORD PTR [rbp-0x48],0x5
  6fa8a3:	0f 95 c1             	setne  cl
  6fa8a6:	84 c8                	test   al,cl
  6fa8a8:	0f 85 9e 02 00 00    	jne    0x6fab4c
  6fa8ae:	e8 fd d8 ea ff       	call   0x5a81b0
  6fa8b3:	48 8d 3d a6 f5 e8 02 	lea    rdi,[rip+0x2e8f5a6]        # 0x3589e60
  6fa8ba:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
  6fa8bd:	31 f6                	xor    esi,esi
  6fa8bf:	31 d2                	xor    edx,edx
  6fa8c1:	31 c9                	xor    ecx,ecx
  6fa8c3:	e8 88 0a 55 00       	call   0xc4b350
  6fa8c8:	4c 8b 35 b1 f5 e8 02 	mov    r14,QWORD PTR [rip+0x2e8f5b1]        # 0x3589e80
  6fa8cf:	4d 85 f6             	test   r14,r14
  6fa8d2:	0f 84 5e 01 00 00    	je     0x6faa36
  6fa8d8:	4c 8d 25 33 f4 b7 00 	lea    r12,[rip+0xb7f433]        # 0x1279d12
  6fa8df:	eb 29                	jmp    0x6fa90a
  6fa8e1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fa8e8:	0f 1f 84 00 00 00 00 
  6fa8ef:	00 
  6fa8f0:	4c 89 ff             	mov    rdi,r15
  6fa8f3:	31 f6                	xor    esi,esi
  6fa8f5:	31 d2                	xor    edx,edx
  6fa8f7:	31 c9                	xor    ecx,ecx
  6fa8f9:	e8 a2 c6 dc ff       	call   0x4c6fa0
  6fa8fe:	4d 8b 36             	mov    r14,QWORD PTR [r14]
  6fa901:	4d 85 f6             	test   r14,r14
  6fa904:	0f 84 2c 01 00 00    	je     0x6faa36
  6fa90a:	4d 8d be 48 01 00 00 	lea    r15,[r14+0x148]
  6fa911:	31 f6                	xor    esi,esi
  6fa913:	31 d2                	xor    edx,edx
  6fa915:	31 c9                	xor    ecx,ecx
  6fa917:	4c 89 ff             	mov    rdi,r15
  6fa91a:	e8 e1 c0 dc ff       	call   0x4c6a00
  6fa91f:	41 83 be d0 05 00 00 	cmp    DWORD PTR [r14+0x5d0],0x2
  6fa926:	02 
  6fa927:	75 c7                	jne    0x6fa8f0
  6fa929:	41 f6 86 b0 00 00 00 	test   BYTE PTR [r14+0xb0],0x4
  6fa930:	04 
  6fa931:	75 bd                	jne    0x6fa8f0
  6fa933:	4d 8b 6e 10          	mov    r13,QWORD PTR [r14+0x10]
  6fa937:	eb 2e                	jmp    0x6fa967
  6fa939:	4c 89 ef             	mov    rdi,r13
  6fa93c:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  6fa940:	e8 9b 22 14 00       	call   0x83cbe0
  6fa945:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fa94c:	00 00 00 00 
  6fa950:	49 8b 7d 00          	mov    rdi,QWORD PTR [r13+0x0]
  6fa954:	31 f6                	xor    esi,esi
  6fa956:	31 d2                	xor    edx,edx
  6fa958:	31 c9                	xor    ecx,ecx
  6fa95a:	48 83 c7 18          	add    rdi,0x18
  6fa95e:	e8 bd cb dc ff       	call   0x4c7520
  6fa963:	4d 8b 6d 10          	mov    r13,QWORD PTR [r13+0x10]
  6fa967:	4d 85 ed             	test   r13,r13
  6fa96a:	74 84                	je     0x6fa8f0
  6fa96c:	4c 89 ef             	mov    rdi,r13
  6fa96f:	4c 89 e2             	mov    rdx,r12
  6fa972:	b9 f0 02 00 00       	mov    ecx,0x2f0
  6fa977:	31 f6                	xor    esi,esi
  6fa979:	e8 32 cf dc ff       	call   0x4c78b0
  6fa97e:	41 83 bd 84 03 00 00 	cmp    DWORD PTR [r13+0x384],0x0
  6fa985:	00 
  6fa986:	75 c8                	jne    0x6fa950
  6fa988:	49 8b 45 60          	mov    rax,QWORD PTR [r13+0x60]
  6fa98c:	48 8b 00             	mov    rax,QWORD PTR [rax]
  6fa98f:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  6fa993:	83 fb 05             	cmp    ebx,0x5
  6fa996:	75 0d                	jne    0x6fa9a5
  6fa998:	49 8b 4d 60          	mov    rcx,QWORD PTR [r13+0x60]
  6fa99c:	48 f7 01 a8 ff ff ff 	test   QWORD PTR [rcx],0xffffffffffffffa8
  6fa9a3:	74 47                	je     0x6fa9ec
  6fa9a5:	83 7d b8 05          	cmp    DWORD PTR [rbp-0x48],0x5
  6fa9a9:	75 a5                	jne    0x6fa950
  6fa9ab:	49 8b 4d 60          	mov    rcx,QWORD PTR [r13+0x60]
  6fa9af:	48 f7 01 f8 fa ff ff 	test   QWORD PTR [rcx],0xfffffffffffffaf8
  6fa9b6:	75 98                	jne    0x6fa950
  6fa9b8:	89 c1                	mov    ecx,eax
  6fa9ba:	48 89 c2             	mov    rdx,rax
  6fa9bd:	48 81 e2 ef fe ff ff 	and    rdx,0xfffffffffffffeef
  6fa9c4:	81 e1 00 01 00 00    	and    ecx,0x100
  6fa9ca:	48 83 ca 10          	or     rdx,0x10
  6fa9ce:	48 85 c9             	test   rcx,rcx
  6fa9d1:	48 0f 44 d0          	cmove  rdx,rax
  6fa9d5:	48 89 d0             	mov    rax,rdx
  6fa9d8:	89 d6                	mov    esi,edx
  6fa9da:	48 25 bf fb ff ff    	and    rax,0xfffffffffffffbbf
  6fa9e0:	81 e6 00 04 00 00    	and    esi,0x400
  6fa9e6:	48 83 c8 40          	or     rax,0x40
  6fa9ea:	eb 31                	jmp    0x6faa1d
  6fa9ec:	89 c1                	mov    ecx,eax
  6fa9ee:	48 89 c2             	mov    rdx,rax
  6fa9f1:	48 81 e2 ef fe ff ff 	and    rdx,0xfffffffffffffeef
  6fa9f8:	83 e1 10             	and    ecx,0x10
  6fa9fb:	48 81 ca 00 01 00 00 	or     rdx,0x100
  6faa02:	48 85 c9             	test   rcx,rcx
  6faa05:	48 0f 44 d0          	cmove  rdx,rax
  6faa09:	48 89 d0             	mov    rax,rdx
  6faa0c:	89 d6                	mov    esi,edx
  6faa0e:	48 25 bf fb ff ff    	and    rax,0xfffffffffffffbbf
  6faa14:	83 e6 40             	and    esi,0x40
  6faa17:	48 0d 00 04 00 00    	or     rax,0x400
  6faa1d:	48 85 f6             	test   rsi,rsi
  6faa20:	48 0f 44 c2          	cmove  rax,rdx
  6faa24:	48 09 ce             	or     rsi,rcx
  6faa27:	0f 84 0c ff ff ff    	je     0x6fa939
  6faa2d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  6faa31:	e9 03 ff ff ff       	jmp    0x6fa939
  6faa36:	48 8d 3d 23 f4 e8 02 	lea    rdi,[rip+0x2e8f423]        # 0x3589e60
  6faa3d:	31 f6                	xor    esi,esi
  6faa3f:	31 d2                	xor    edx,edx
  6faa41:	e8 ba 18 55 00       	call   0xc4c300
  6faa46:	83 fb 05             	cmp    ebx,0x5
  6faa49:	75 33                	jne    0x6faa7e
  6faa4b:	bf 07 05 00 00       	mov    edi,0x507
  6faa50:	e8 4b 2f 14 00       	call   0x83d9a0
  6faa55:	8b 7d c4             	mov    edi,DWORD PTR [rbp-0x3c]
  6faa58:	0f b7 f0             	movzx  esi,ax
  6faa5b:	e8 d0 bf ea ff       	call   0x5a6a30
  6faa60:	48 8d 3d 31 17 22 03 	lea    rdi,[rip+0x3221731]        # 0x391c198
  6faa67:	31 f6                	xor    esi,esi
  6faa69:	31 d2                	xor    edx,edx
  6faa6b:	31 c9                	xor    ecx,ecx
  6faa6d:	e8 1e c7 dc ff       	call   0x4c7190
  6faa72:	c7 05 50 09 b0 01 01 	mov    DWORD PTR [rip+0x1b00950],0x1        # 0x21fb3cc
  6faa79:	00 00 00 
  6faa7c:	eb 4b                	jmp    0x6faac9
  6faa7e:	83 7d b8 05          	cmp    DWORD PTR [rbp-0x48],0x5
  6faa82:	75 33                	jne    0x6faab7
  6faa84:	bf 57 00 00 00       	mov    edi,0x57
  6faa89:	e8 12 2f 14 00       	call   0x83d9a0
  6faa8e:	8b 7d c4             	mov    edi,DWORD PTR [rbp-0x3c]
  6faa91:	0f b7 f0             	movzx  esi,ax
  6faa94:	e8 97 bf ea ff       	call   0x5a6a30
  6faa99:	48 8d 3d f8 16 22 03 	lea    rdi,[rip+0x32216f8]        # 0x391c198
  6faaa0:	31 f6                	xor    esi,esi
  6faaa2:	31 d2                	xor    edx,edx
  6faaa4:	31 c9                	xor    ecx,ecx
  6faaa6:	e8 e5 c6 dc ff       	call   0x4c7190
  6faaab:	c7 05 17 09 b0 01 00 	mov    DWORD PTR [rip+0x1b00917],0x0        # 0x21fb3cc
  6faab2:	00 00 00 
  6faab5:	eb 12                	jmp    0x6faac9
  6faab7:	48 8d 3d da 16 22 03 	lea    rdi,[rip+0x32216da]        # 0x391c198
  6faabe:	31 f6                	xor    esi,esi
  6faac0:	31 d2                	xor    edx,edx
  6faac2:	31 c9                	xor    ecx,ecx
  6faac4:	e8 c7 c6 dc ff       	call   0x4c7190
  6faac9:	41 bc 50 05 00 00    	mov    r12d,0x550
  6faacf:	4c 8d 35 3c f2 b7 00 	lea    r14,[rip+0xb7f23c]        # 0x1279d12
  6faad6:	31 db                	xor    ebx,ebx
  6faad8:	eb 17                	jmp    0x6faaf1
  6faada:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  6faae0:	89 df                	mov    edi,ebx
  6faae2:	e8 19 c1 fb ff       	call   0x6b6c00
  6faae7:	ff c3                	inc    ebx
  6faae9:	3b 1d c9 3d 61 03    	cmp    ebx,DWORD PTR [rip+0x3613dc9]        # 0x3d0e8b8
  6faaef:	77 49                	ja     0x6fab3a
  6faaf1:	49 0f a3 dc          	bt     r12,rbx
  6faaf5:	73 f0                	jae    0x6faae7
  6faaf7:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6faafe:	00 
  6faaff:	39 c3                	cmp    ebx,eax
  6fab01:	75 dd                	jne    0x6faae0
  6fab03:	65 4c 8b 3c 25 00 00 	mov    r15,QWORD PTR gs:0x0
  6fab0a:	00 00 
  6fab0c:	4c 89 ff             	mov    rdi,r15
  6fab0f:	4c 89 f2             	mov    rdx,r14
  6fab12:	b9 b4 02 00 00       	mov    ecx,0x2b4
  6fab17:	31 f6                	xor    esi,esi
  6fab19:	e8 92 cd dc ff       	call   0x4c78b0
  6fab1e:	4c 89 ff             	mov    rdi,r15
  6fab21:	e8 ca c1 fb ff       	call   0x6b6cf0
  6fab26:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  6fab29:	31 f6                	xor    esi,esi
  6fab2b:	31 d2                	xor    edx,edx
  6fab2d:	31 c9                	xor    ecx,ecx
  6fab2f:	48 83 c7 18          	add    rdi,0x18
  6fab33:	e8 e8 c9 dc ff       	call   0x4c7520
  6fab38:	eb ad                	jmp    0x6faae7
  6fab3a:	48 8d 3d 57 16 22 03 	lea    rdi,[rip+0x3221657]        # 0x391c198
  6fab41:	31 f6                	xor    esi,esi
  6fab43:	31 d2                	xor    edx,edx
  6fab45:	31 c9                	xor    ecx,ecx
  6fab47:	e8 d4 c9 dc ff       	call   0x4c7520
  6fab4c:	48 8d 05 bd 17 22 03 	lea    rax,[rip+0x32217bd]        # 0x391c310
  6fab53:	48 8b 00             	mov    rax,QWORD PTR [rax]
  6fab56:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6fab5a:	75 0f                	jne    0x6fab6b
  6fab5c:	48 83 c4 28          	add    rsp,0x28
  6fab60:	5b                   	pop    rbx
  6fab61:	41 5c                	pop    r12
  6fab63:	41 5d                	pop    r13
  6fab65:	41 5e                	pop    r14
  6fab67:	41 5f                	pop    r15
  6fab69:	5d                   	pop    rbp
  6fab6a:	c3                   	ret
  6fab6b:	e8 40 2b 00 00       	call   0x6fd6b0
  6fab70:	0f 0b                	ud2
  6fab72:	4c 63 f2             	movsxd r14,edx
  6fab75:	e8 d6 6d 0f 00       	call   0x7f1950
  6fab7a:	48 63 d3             	movsxd rdx,ebx
  6fab7d:	48 8d 3d ee ff ff ff 	lea    rdi,[rip+0xffffffffffffffee]        # 0x6fab72
  6fab84:	4c 89 f6             	mov    rsi,r14
  6fab87:	e8 84 74 0f 00       	call   0x7f2010
  6fab8c:	48 8d 35 72 33 b9 00 	lea    rsi,[rip+0xb93372]        # 0x128df05
  6fab93:	bf 27 00 00 00       	mov    edi,0x27
  6fab98:	44 89 f2             	mov    edx,r14d
  6fab9b:	89 d9                	mov    ecx,ebx
  6fab9d:	31 c0                	xor    eax,eax
  6fab9f:	e8 6c fe 59 00       	call   0xc9aa10
  6faba4:	0f 0b                	ud2
  6faba6:	e8 a5 6d 0f 00       	call   0x7f1950
  6fabab:	48 63 d3             	movsxd rdx,ebx
  6fabae:	48 8d 3d f1 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff1]        # 0x6faba6
  6fabb5:	be 04 00 00 00       	mov    esi,0x4
  6fabba:	e8 51 74 0f 00       	call   0x7f2010
  6fabbf:	48 8d 35 3f 33 b9 00 	lea    rsi,[rip+0xb9333f]        # 0x128df05
  6fabc6:	bf 13 00 00 00       	mov    edi,0x13
  6fabcb:	ba 04 00 00 00       	mov    edx,0x4
  6fabd0:	eb c9                	jmp    0x6fab9b
  6fabd2:	90                   	nop
  6fabd3:	90                   	nop
  6fabd4:	90                   	nop
  6fabd5:	90                   	nop
  6fabd6:	90                   	nop
  6fabd7:	90                   	nop
  6fabd8:	90                   	nop
  6fabd9:	90                   	nop
  6fabda:	90                   	nop
  6fabdb:	90                   	nop
  6fabdc:	90                   	nop
  6fabdd:	90                   	nop
  6fabde:	90                   	nop
  6fabdf:	90                   	nop
  6fabe0:	55                   	push   rbp
  6fabe1:	48 89 e5             	mov    rbp,rsp
  6fabe4:	41 57                	push   r15
  6fabe6:	41 56                	push   r14
  6fabe8:	41 55                	push   r13
  6fabea:	41 54                	push   r12
  6fabec:	53                   	push   rbx
  6fabed:	48 83 ec 18          	sub    rsp,0x18
  6fabf1:	48 8d 05 18 17 22 03 	lea    rax,[rip+0x3221718]        # 0x391c310
  6fabf8:	48 8b 00             	mov    rax,QWORD PTR [rax]
  6fabfb:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6fabff:	8b 05 bb 07 b0 01    	mov    eax,DWORD PTR [rip+0x1b007bb]        # 0x21fb3c0
  6fac05:	83 f8 04             	cmp    eax,0x4
  6fac08:	74 26                	je     0x6fac30
  6fac0a:	8b 05 b0 07 b0 01    	mov    eax,DWORD PTR [rip+0x1b007b0]        # 0x21fb3c0
  6fac10:	83 f8 03             	cmp    eax,0x3
  6fac13:	74 1b                	je     0x6fac30
  6fac15:	8b 05 a5 07 b0 01    	mov    eax,DWORD PTR [rip+0x1b007a5]        # 0x21fb3c0
  6fac1b:	83 f8 05             	cmp    eax,0x5
  6fac1e:	74 10                	je     0x6fac30
  6fac20:	8b 0d 9a 07 b0 01    	mov    ecx,DWORD PTR [rip+0x1b0079a]        # 0x21fb3c0
  6fac26:	b8 aa 00 00 00       	mov    eax,0xaa
  6fac2b:	83 f9 01             	cmp    ecx,0x1
  6fac2e:	75 07                	jne    0x6fac37
  6fac30:	48 8b 05 a9 07 b0 01 	mov    rax,QWORD PTR [rip+0x1b007a9]        # 0x21fb3e0
  6fac37:	4c 8b 2d e2 03 b0 01 	mov    r13,QWORD PTR [rip+0x1b003e2]        # 0x21fb020
  6fac3e:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  6fac42:	4d 85 ed             	test   r13,r13
  6fac45:	0f 84 9d 00 00 00    	je     0x6face8
  6fac4b:	48 8d 1d c0 f0 b7 00 	lea    rbx,[rip+0xb7f0c0]        # 0x1279d12
  6fac52:	4c 8d 25 7f 07 b0 01 	lea    r12,[rip+0x1b0077f]        # 0x21fb3d8
  6fac59:	4c 8d 75 c8          	lea    r14,[rbp-0x38]
  6fac5d:	eb 32                	jmp    0x6fac91
  6fac5f:	90                   	nop
  6fac60:	0f b7 30             	movzx  esi,WORD PTR [rax]
  6fac63:	4c 89 ff             	mov    rdi,r15
  6fac66:	e8 a5 ac fb ff       	call   0x6b5910
  6fac6b:	4c 89 ff             	mov    rdi,r15
  6fac6e:	4c 89 f6             	mov    rsi,r14
  6fac71:	e8 5a 1f 14 00       	call   0x83cbd0
  6fac76:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  6fac79:	31 f6                	xor    esi,esi
  6fac7b:	31 d2                	xor    edx,edx
  6fac7d:	31 c9                	xor    ecx,ecx
  6fac7f:	48 83 c7 18          	add    rdi,0x18
  6fac83:	e8 98 c8 dc ff       	call   0x4c7520
  6fac88:	4d 8b 6d 00          	mov    r13,QWORD PTR [r13+0x0]
  6fac8c:	4d 85 ed             	test   r13,r13
  6fac8f:	74 57                	je     0x6face8
  6fac91:	4d 8b 7d 10          	mov    r15,QWORD PTR [r13+0x10]
  6fac95:	48 89 da             	mov    rdx,rbx
  6fac98:	b9 c6 01 00 00       	mov    ecx,0x1c6
  6fac9d:	31 f6                	xor    esi,esi
  6fac9f:	4c 89 ff             	mov    rdi,r15
  6faca2:	e8 09 cc dc ff       	call   0x4c78b0
  6faca7:	8b 0d 13 07 b0 01    	mov    ecx,DWORD PTR [rip+0x1b00713]        # 0x21fb3c0
  6facad:	4c 89 e0             	mov    rax,r12
  6facb0:	83 f9 04             	cmp    ecx,0x4
  6facb3:	74 ab                	je     0x6fac60
  6facb5:	8b 0d 05 07 b0 01    	mov    ecx,DWORD PTR [rip+0x1b00705]        # 0x21fb3c0
  6facbb:	4c 89 e0             	mov    rax,r12
  6facbe:	83 f9 03             	cmp    ecx,0x3
  6facc1:	74 9d                	je     0x6fac60
  6facc3:	8b 0d f7 06 b0 01    	mov    ecx,DWORD PTR [rip+0x1b006f7]        # 0x21fb3c0
  6facc9:	4c 89 e0             	mov    rax,r12
  6faccc:	83 f9 05             	cmp    ecx,0x5
  6faccf:	74 8f                	je     0x6fac60
  6facd1:	8b 0d e9 06 b0 01    	mov    ecx,DWORD PTR [rip+0x1b006e9]        # 0x21fb3c0
  6facd7:	4c 89 e0             	mov    rax,r12
  6facda:	83 f9 01             	cmp    ecx,0x1
  6facdd:	74 81                	je     0x6fac60
  6facdf:	49 8d 45 18          	lea    rax,[r13+0x18]
  6face3:	e9 78 ff ff ff       	jmp    0x6fac60
  6face8:	48 8d 05 21 16 22 03 	lea    rax,[rip+0x3221621]        # 0x391c310
  6facef:	48 8b 00             	mov    rax,QWORD PTR [rax]
  6facf2:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6facf6:	75 0f                	jne    0x6fad07
  6facf8:	48 83 c4 18          	add    rsp,0x18
  6facfc:	5b                   	pop    rbx
  6facfd:	41 5c                	pop    r12
  6facff:	41 5d                	pop    r13
  6fad01:	41 5e                	pop    r14
  6fad03:	41 5f                	pop    r15
  6fad05:	5d                   	pop    rbp
  6fad06:	c3                   	ret
  6fad07:	e8 a4 29 00 00       	call   0x6fd6b0
  6fad0c:	0f 0b                	ud2
  6fad0e:	90                   	nop
  6fad0f:	90                   	nop
  6fad10:	55                   	push   rbp
  6fad11:	48 89 e5             	mov    rbp,rsp
  6fad14:	41 57                	push   r15
  6fad16:	41 56                	push   r14
  6fad18:	41 55                	push   r13
  6fad1a:	41 54                	push   r12
  6fad1c:	53                   	push   rbx
  6fad1d:	48 83 ec 18          	sub    rsp,0x18
  6fad21:	48 8d 05 e8 15 22 03 	lea    rax,[rip+0x32215e8]        # 0x391c310
  6fad28:	48 8b 00             	mov    rax,QWORD PTR [rax]
  6fad2b:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6fad2f:	4c 8b 2d fa 02 b0 01 	mov    r13,QWORD PTR [rip+0x1b002fa]        # 0x21fb030
  6fad36:	4d 85 ed             	test   r13,r13
  6fad39:	0f 84 d7 00 00 00    	je     0x6fae16
  6fad3f:	48 8d 1d cc ef b7 00 	lea    rbx,[rip+0xb7efcc]        # 0x1279d12
  6fad46:	4c 8d 75 c8          	lea    r14,[rbp-0x38]
  6fad4a:	4c 8d 25 53 12 03 01 	lea    r12,[rip+0x1031253]        # 0x172bfa4
  6fad51:	eb 3d                	jmp    0x6fad90
  6fad53:	0f b6 40 19          	movzx  eax,BYTE PTR [rax+0x19]
  6fad57:	48 8d 0d a2 12 03 01 	lea    rcx,[rip+0x10312a2]        # 0x172c000
  6fad5e:	48 8b 04 c1          	mov    rax,QWORD PTR [rcx+rax*8]
  6fad62:	4c 89 ff             	mov    rdi,r15
  6fad65:	4c 89 f6             	mov    rsi,r14
  6fad68:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  6fad6c:	e8 5f 1e 14 00       	call   0x83cbd0
  6fad71:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  6fad74:	31 f6                	xor    esi,esi
  6fad76:	31 d2                	xor    edx,edx
  6fad78:	31 c9                	xor    ecx,ecx
  6fad7a:	48 83 c7 18          	add    rdi,0x18
  6fad7e:	e8 9d c7 dc ff       	call   0x4c7520
  6fad83:	4d 8b 6d 00          	mov    r13,QWORD PTR [r13+0x0]
  6fad87:	4d 85 ed             	test   r13,r13
  6fad8a:	0f 84 86 00 00 00    	je     0x6fae16
  6fad90:	4d 8b 7d 10          	mov    r15,QWORD PTR [r13+0x10]
  6fad94:	48 89 da             	mov    rdx,rbx
  6fad97:	b9 83 02 00 00       	mov    ecx,0x283
  6fad9c:	31 f6                	xor    esi,esi
  6fad9e:	4c 89 ff             	mov    rdi,r15
  6fada1:	e8 0a cb dc ff       	call   0x4c78b0
  6fada6:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  6fadad:	00 
  6fadae:	8b 0d 0c 06 b0 01    	mov    ecx,DWORD PTR [rip+0x1b0060c]        # 0x21fb3c0
  6fadb4:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6fadb7:	48 83 f9 05          	cmp    rcx,0x5
  6fadbb:	77 3e                	ja     0x6fadfb
  6fadbd:	49 63 0c 8c          	movsxd rcx,DWORD PTR [r12+rcx*4]
  6fadc1:	49 8b 87 88 03 00 00 	mov    rax,QWORD PTR [r15+0x388]
  6fadc8:	4c 01 e1             	add    rcx,r12
  6fadcb:	ff e1                	jmp    rcx
  6fadcd:	0f b6 40 18          	movzx  eax,BYTE PTR [rax+0x18]
  6fadd1:	48 8d 0d e8 11 03 01 	lea    rcx,[rip+0x10311e8]        # 0x172bfc0
  6fadd8:	eb 84                	jmp    0x6fad5e
  6fadda:	0f b6 40 18          	movzx  eax,BYTE PTR [rax+0x18]
  6fadde:	48 8d 0d fb 11 03 01 	lea    rcx,[rip+0x10311fb]        # 0x172bfe0
  6fade5:	e9 74 ff ff ff       	jmp    0x6fad5e
  6fadea:	0f b6 48 1a          	movzx  ecx,BYTE PTR [rax+0x1a]
  6fadee:	83 f9 01             	cmp    ecx,0x1
  6fadf1:	74 19                	je     0x6fae0c
  6fadf3:	85 c9                	test   ecx,ecx
  6fadf5:	0f 84 58 ff ff ff    	je     0x6fad53
  6fadfb:	31 c0                	xor    eax,eax
  6fadfd:	e9 60 ff ff ff       	jmp    0x6fad62
  6fae02:	b8 ff ff 00 00       	mov    eax,0xffff
  6fae07:	e9 56 ff ff ff       	jmp    0x6fad62
  6fae0c:	b8 f8 00 00 00       	mov    eax,0xf8
  6fae11:	e9 4c ff ff ff       	jmp    0x6fad62
  6fae16:	48 8d 05 f3 14 22 03 	lea    rax,[rip+0x32214f3]        # 0x391c310
  6fae1d:	48 8b 00             	mov    rax,QWORD PTR [rax]
  6fae20:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6fae24:	75 0f                	jne    0x6fae35
  6fae26:	48 83 c4 18          	add    rsp,0x18
  6fae2a:	5b                   	pop    rbx
  6fae2b:	41 5c                	pop    r12
  6fae2d:	41 5d                	pop    r13
  6fae2f:	41 5e                	pop    r14
  6fae31:	41 5f                	pop    r15
  6fae33:	5d                   	pop    rbp
  6fae34:	c3                   	ret
  6fae35:	e8 76 28 00 00       	call   0x6fd6b0
  6fae3a:	0f 0b                	ud2
  6fae3c:	90                   	nop
  6fae3d:	90                   	nop
  6fae3e:	90                   	nop
  6fae3f:	90                   	nop
  6fae40:	55                   	push   rbp
  6fae41:	48 89 e5             	mov    rbp,rsp
  6fae44:	53                   	push   rbx
  6fae45:	50                   	push   rax
  6fae46:	48 8d 1d 93 13 22 03 	lea    rbx,[rip+0x3221393]        # 0x391c1e0
  6fae4d:	31 f6                	xor    esi,esi
  6fae4f:	31 d2                	xor    edx,edx
  6fae51:	31 c9                	xor    ecx,ecx
  6fae53:	48 89 df             	mov    rdi,rbx
  6fae56:	e8 35 c3 dc ff       	call   0x4c7190
  6fae5b:	48 c7 05 ea 04 b0 01 	mov    QWORD PTR [rip+0x1b004ea],0x0        # 0x21fb350
  6fae62:	00 00 00 00 
  6fae66:	48 89 df             	mov    rdi,rbx
  6fae69:	31 f6                	xor    esi,esi
  6fae6b:	31 d2                	xor    edx,edx
  6fae6d:	31 c9                	xor    ecx,ecx
  6fae6f:	48 83 c4 08          	add    rsp,0x8
  6fae73:	5b                   	pop    rbx
  6fae74:	5d                   	pop    rbp
  6fae75:	e9 a6 c6 dc ff       	jmp    0x4c7520
  6fae7a:	90                   	nop
  6fae7b:	90                   	nop
  6fae7c:	90                   	nop
  6fae7d:	90                   	nop
  6fae7e:	90                   	nop
  6fae7f:	90                   	nop
  6fae80:	55                   	push   rbp
  6fae81:	48 89 e5             	mov    rbp,rsp
  6fae84:	53                   	push   rbx
  6fae85:	50                   	push   rax
  6fae86:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6fae8d:	00 00 
  6fae8f:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  6fae93:	bb 16 00 00 00       	mov    ebx,0x16
  6fae98:	80 b8 81 0c 00 00 00 	cmp    BYTE PTR [rax+0xc81],0x0
  6fae9f:	75 2e                	jne    0x6faecf
  6faea1:	48 c7 47 70 00 00 00 	mov    QWORD PTR [rdi+0x70],0x0
  6faea8:	00 
  6faea9:	80 4f 3a 20          	or     BYTE PTR [rdi+0x3a],0x20
  6faead:	c7 47 3c 64 00 00 00 	mov    DWORD PTR [rdi+0x3c],0x64
  6faeb4:	48 89 fe             	mov    rsi,rdi
  6faeb7:	48 8d 3d 8a 13 22 03 	lea    rdi,[rip+0x322138a]        # 0x391c248
  6faebe:	31 db                	xor    ebx,ebx
  6faec0:	31 d2                	xor    edx,edx
  6faec2:	f0 83 05 76 13 22 03 	lock add DWORD PTR [rip+0x3221376],0x1        # 0x391c240
  6faec9:	01 
  6faeca:	e8 f1 90 c1 ff       	call   0x313fc0
  6faecf:	89 d8                	mov    eax,ebx
  6faed1:	48 83 c4 08          	add    rsp,0x8
  6faed5:	5b                   	pop    rbx
  6faed6:	5d                   	pop    rbp
  6faed7:	c3                   	ret
  6faed8:	90                   	nop
  6faed9:	90                   	nop
  6faeda:	90                   	nop
  6faedb:	90                   	nop
  6faedc:	90                   	nop
  6faedd:	90                   	nop
  6faede:	90                   	nop
  6faedf:	90                   	nop
  6faee0:	55                   	push   rbp
  6faee1:	48 89 e5             	mov    rbp,rsp
  6faee4:	48 89 fe             	mov    rsi,rdi
  6faee7:	48 8d 3d 5a 13 22 03 	lea    rdi,[rip+0x322135a]        # 0x391c248
  6faeee:	31 d2                	xor    edx,edx
  6faef0:	e8 9b 91 c1 ff       	call   0x314090
  6faef5:	f0 83 05 43 13 22 03 	lock add DWORD PTR [rip+0x3221343],0xffffffff        # 0x391c240
  6faefc:	ff 
  6faefd:	5d                   	pop    rbp
  6faefe:	c3                   	ret
  6faeff:	90                   	nop
  6faf00:	55                   	push   rbp
  6faf01:	48 89 e5             	mov    rbp,rsp
  6faf04:	0f b6 05 39 13 22 03 	movzx  eax,BYTE PTR [rip+0x3221339]        # 0x391c244
  6faf0b:	83 f8 01             	cmp    eax,0x1
  6faf0e:	75 04                	jne    0x6faf14
  6faf10:	48 ff 47 40          	inc    QWORD PTR [rdi+0x40]
  6faf14:	5d                   	pop    rbp
  6faf15:	c3                   	ret
  6faf16:	90                   	nop
  6faf17:	90                   	nop
  6faf18:	90                   	nop
  6faf19:	90                   	nop
  6faf1a:	90                   	nop
  6faf1b:	90                   	nop
  6faf1c:	90                   	nop
  6faf1d:	90                   	nop
  6faf1e:	90                   	nop
  6faf1f:	90                   	nop
  6faf20:	55                   	push   rbp
  6faf21:	48 89 e5             	mov    rbp,rsp
  6faf24:	41 57                	push   r15
  6faf26:	41 56                	push   r14
  6faf28:	41 54                	push   r12
  6faf2a:	53                   	push   rbx
  6faf2b:	48 83 ec 20          	sub    rsp,0x20
  6faf2f:	4c 8d 3d da 13 22 03 	lea    r15,[rip+0x32213da]        # 0x391c310
  6faf36:	48 8d 15 d5 ed b7 00 	lea    rdx,[rip+0xb7edd5]        # 0x1279d12
  6faf3d:	b9 0b 05 00 00       	mov    ecx,0x50b
  6faf42:	31 f6                	xor    esi,esi
  6faf44:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6faf47:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  6faf4b:	65 48 8b 1c 25 00 00 	mov    rbx,QWORD PTR gs:0x0
  6faf52:	00 00 
  6faf54:	48 89 df             	mov    rdi,rbx
  6faf57:	e8 54 c9 dc ff       	call   0x4c78b0
  6faf5c:	4c 8d 75 c8          	lea    r14,[rbp-0x38]
  6faf60:	48 8d 3d 19 13 22 03 	lea    rdi,[rip+0x3221319]        # 0x391c280
  6faf67:	48 8d 05 62 c8 b6 ff 	lea    rax,[rip+0xffffffffffb6c862]        # 0x2677d0
  6faf6e:	49 bc 22 96 a6 cf 0e 	movabs r12,0xaeb80ecfa69622
  6faf75:	b8 ae 00 
  6faf78:	c7 05 3e 13 22 03 01 	mov    DWORD PTR [rip+0x322133e],0x1        # 0x391c2c0
  6faf7f:	00 00 00 
  6faf82:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  6faf89:	00 
  6faf8a:	4c 89 f6             	mov    rsi,r14
  6faf8d:	48 89 05 1c 13 22 03 	mov    QWORD PTR [rip+0x322131c],rax        # 0x391c2b0
  6faf94:	4c 89 65 d0          	mov    QWORD PTR [rbp-0x30],r12
  6faf98:	e8 d3 c4 3c 00       	call   0xac7470
  6faf9d:	48 8d 3d 44 12 22 03 	lea    rdi,[rip+0x3221244]        # 0x391c1e8
  6fafa4:	4c 89 f6             	mov    rsi,r14
  6fafa7:	48 8d 05 2a c8 b6 ff 	lea    rax,[rip+0xffffffffffb6c82a]        # 0x2677d8
  6fafae:	c7 05 70 12 22 03 01 	mov    DWORD PTR [rip+0x3221270],0x1        # 0x391c228
  6fafb5:	00 00 00 
  6fafb8:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  6fafbf:	00 
  6fafc0:	4c 89 65 d0          	mov    QWORD PTR [rbp-0x30],r12
  6fafc4:	48 89 05 4d 12 22 03 	mov    QWORD PTR [rip+0x322124d],rax        # 0x391c218
  6fafcb:	e8 a0 c4 3c 00       	call   0xac7470
  6fafd0:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
  6fafd3:	31 f6                	xor    esi,esi
  6fafd5:	31 d2                	xor    edx,edx
  6fafd7:	31 c9                	xor    ecx,ecx
  6fafd9:	48 83 c7 18          	add    rdi,0x18
  6fafdd:	e8 3e c5 dc ff       	call   0x4c7520
  6fafe2:	48 8d 15 2f 64 b6 ff 	lea    rdx,[rip+0xffffffffffb6642f]        # 0x261418
  6fafe9:	48 8d 1d 48 12 22 03 	lea    rbx,[rip+0x3221248]        # 0x391c238
  6faff0:	48 8d 3d d1 95 c1 00 	lea    rdi,[rip+0xc195d1]        # 0x13145c8
  6faff7:	be 02 00 00 00       	mov    esi,0x2
  6faffc:	48 89 d9             	mov    rcx,rbx
  6fafff:	e8 8c 0c df ff       	call   0x4ebc90
  6fb004:	48 8d 0d 58 7d c7 00 	lea    rcx,[rip+0xc77d58]        # 0x1372d63
  6fb00b:	48 89 df             	mov    rdi,rbx
  6fb00e:	be 01 00 00 00       	mov    esi,0x1
  6fb013:	ba 2c 00 00 00       	mov    edx,0x2c
  6fb018:	48 89 05 19 12 22 03 	mov    QWORD PTR [rip+0x3221219],rax        # 0x391c238
  6fb01f:	31 c0                	xor    eax,eax
  6fb021:	e8 fa 07 df ff       	call   0x4eb820
  6fb026:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6fb029:	48 3b 45 d8          	cmp    rax,QWORD PTR [rbp-0x28]
  6fb02d:	75 0d                	jne    0x6fb03c
  6fb02f:	48 83 c4 20          	add    rsp,0x20
  6fb033:	5b                   	pop    rbx
  6fb034:	41 5c                	pop    r12
  6fb036:	41 5e                	pop    r14
  6fb038:	41 5f                	pop    r15
  6fb03a:	5d                   	pop    rbp
  6fb03b:	c3                   	ret
  6fb03c:	e8 6f 26 00 00       	call   0x6fd6b0
  6fb041:	0f 0b                	ud2
  6fb043:	90                   	nop
  6fb044:	90                   	nop
  6fb045:	90                   	nop
  6fb046:	90                   	nop
  6fb047:	90                   	nop
  6fb048:	90                   	nop
  6fb049:	90                   	nop
  6fb04a:	90                   	nop
  6fb04b:	90                   	nop
  6fb04c:	90                   	nop
  6fb04d:	90                   	nop
  6fb04e:	90                   	nop
  6fb04f:	90                   	nop
  6fb050:	55                   	push   rbp
  6fb051:	48 89 e5             	mov    rbp,rsp
  6fb054:	41 57                	push   r15
  6fb056:	41 56                	push   r14
  6fb058:	53                   	push   rbx
  6fb059:	48 83 ec 18          	sub    rsp,0x18
  6fb05d:	4c 8d 3d ac 12 22 03 	lea    r15,[rip+0x32212ac]        # 0x391c310
  6fb064:	48 8d 3d 2d 11 22 03 	lea    rdi,[rip+0x322112d]        # 0x391c198
  6fb06b:	48 89 cb             	mov    rbx,rcx
  6fb06e:	31 f6                	xor    esi,esi
  6fb070:	31 d2                	xor    edx,edx
  6fb072:	31 c9                	xor    ecx,ecx
  6fb074:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6fb077:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  6fb07b:	e8 10 c1 dc ff       	call   0x4c7190
  6fb080:	8b 05 3a 03 b0 01    	mov    eax,DWORD PTR [rip+0x1b0033a]        # 0x21fb3c0
  6fb086:	83 f8 04             	cmp    eax,0x4
  6fb089:	74 21                	je     0x6fb0ac
  6fb08b:	8b 05 2f 03 b0 01    	mov    eax,DWORD PTR [rip+0x1b0032f]        # 0x21fb3c0
  6fb091:	83 f8 03             	cmp    eax,0x3
  6fb094:	74 16                	je     0x6fb0ac
  6fb096:	8b 05 24 03 b0 01    	mov    eax,DWORD PTR [rip+0x1b00324]        # 0x21fb3c0
  6fb09c:	83 f8 05             	cmp    eax,0x5
  6fb09f:	74 0b                	je     0x6fb0ac
  6fb0a1:	8b 05 19 03 b0 01    	mov    eax,DWORD PTR [rip+0x1b00319]        # 0x21fb3c0
  6fb0a7:	83 f8 01             	cmp    eax,0x1
  6fb0aa:	75 5d                	jne    0x6fb109
  6fb0ac:	8b 05 12 03 b0 01    	mov    eax,DWORD PTR [rip+0x1b00312]        # 0x21fb3c4
  6fb0b2:	8d 04 85 01 00 00 00 	lea    eax,[rax*4+0x1]
  6fb0b9:	48 8d 3d d8 10 22 03 	lea    rdi,[rip+0x32210d8]        # 0x391c198
  6fb0c0:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
  6fb0c3:	31 f6                	xor    esi,esi
  6fb0c5:	31 d2                	xor    edx,edx
  6fb0c7:	31 c9                	xor    ecx,ecx
  6fb0c9:	e8 52 c4 dc ff       	call   0x4c7520
  6fb0ce:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  6fb0d2:	48 8d 05 5f e2 b6 ff 	lea    rax,[rip+0xffffffffffb6e25f]        # 0x269338
  6fb0d9:	4c 29 f0             	sub    rax,r14
  6fb0dc:	48 c1 c8 03          	ror    rax,0x3
  6fb0e0:	48 83 f8 03          	cmp    rax,0x3
  6fb0e4:	77 2b                	ja     0x6fb111
  6fb0e6:	48 8d 75 dc          	lea    rsi,[rbp-0x24]
  6fb0ea:	ba 04 00 00 00       	mov    edx,0x4
  6fb0ef:	48 89 df             	mov    rdi,rbx
  6fb0f2:	41 ff d6             	call   r14
  6fb0f5:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  6fb0f8:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  6fb0fc:	75 24                	jne    0x6fb122
  6fb0fe:	48 83 c4 18          	add    rsp,0x18
  6fb102:	5b                   	pop    rbx
  6fb103:	41 5e                	pop    r14
  6fb105:	41 5f                	pop    r15
  6fb107:	5d                   	pop    rbp
  6fb108:	c3                   	ret
  6fb109:	8b 05 b1 02 b0 01    	mov    eax,DWORD PTR [rip+0x1b002b1]        # 0x21fb3c0
  6fb10f:	eb a8                	jmp    0x6fb0b9
  6fb111:	48 8d 3d e8 03 b0 01 	lea    rdi,[rip+0x1b003e8]        # 0x21fb500
  6fb118:	4c 89 f6             	mov    rsi,r14
  6fb11b:	e8 a0 47 d5 ff       	call   0x44f8c0
  6fb120:	eb c4                	jmp    0x6fb0e6
  6fb122:	e8 89 25 00 00       	call   0x6fd6b0
  6fb127:	0f 0b                	ud2
  6fb129:	90                   	nop
  6fb12a:	90                   	nop
  6fb12b:	90                   	nop
  6fb12c:	90                   	nop
  6fb12d:	90                   	nop
  6fb12e:	90                   	nop
  6fb12f:	90                   	nop
  6fb130:	55                   	push   rbp
  6fb131:	48 89 e5             	mov    rbp,rsp
  6fb134:	41 57                	push   r15
  6fb136:	41 56                	push   r14
  6fb138:	41 55                	push   r13
  6fb13a:	41 54                	push   r12
  6fb13c:	53                   	push   rbx
  6fb13d:	48 83 ec 18          	sub    rsp,0x18
  6fb141:	4c 8d 2d c8 11 22 03 	lea    r13,[rip+0x32211c8]        # 0x391c310
  6fb148:	48 8d 75 cc          	lea    rsi,[rbp-0x34]
  6fb14c:	31 d2                	xor    edx,edx
  6fb14e:	49 89 ce             	mov    r14,rcx
  6fb151:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  6fb155:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6fb159:	8b 05 65 02 b0 01    	mov    eax,DWORD PTR [rip+0x1b00265]        # 0x21fb3c4
  6fb15f:	89 45 cc             	mov    DWORD PTR [rbp-0x34],eax
  6fb162:	e8 81 58 b7 ff       	call   0x2709e8
  6fb167:	89 c3                	mov    ebx,eax
  6fb169:	85 c0                	test   eax,eax
  6fb16b:	74 1f                	je     0x6fb18c
  6fb16d:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  6fb171:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6fb175:	0f 85 62 02 00 00    	jne    0x6fb3dd
  6fb17b:	89 d8                	mov    eax,ebx
  6fb17d:	48 83 c4 18          	add    rsp,0x18
  6fb181:	5b                   	pop    rbx
  6fb182:	41 5c                	pop    r12
  6fb184:	41 5d                	pop    r13
  6fb186:	41 5e                	pop    r14
  6fb188:	41 5f                	pop    r15
  6fb18a:	5d                   	pop    rbp
  6fb18b:	c3                   	ret
  6fb18c:	49 83 7e 30 00       	cmp    QWORD PTR [r14+0x30],0x0
  6fb191:	bb 00 00 00 00       	mov    ebx,0x0
  6fb196:	74 d5                	je     0x6fb16d
  6fb198:	83 7d cc 01          	cmp    DWORD PTR [rbp-0x34],0x1
  6fb19c:	bb 16 00 00 00       	mov    ebx,0x16
  6fb1a1:	77 ca                	ja     0x6fb16d
  6fb1a3:	48 8d 3d ee 0f 22 03 	lea    rdi,[rip+0x3220fee]        # 0x391c198
  6fb1aa:	31 db                	xor    ebx,ebx
  6fb1ac:	31 f6                	xor    esi,esi
  6fb1ae:	31 d2                	xor    edx,edx
  6fb1b0:	31 c9                	xor    ecx,ecx
  6fb1b2:	e8 d9 bf dc ff       	call   0x4c7190
  6fb1b7:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
  6fb1ba:	8b 0d 04 02 b0 01    	mov    ecx,DWORD PTR [rip+0x1b00204]        # 0x21fb3c4
  6fb1c0:	39 c1                	cmp    ecx,eax
  6fb1c2:	0f 85 b8 00 00 00    	jne    0x6fb280
  6fb1c8:	48 8d 3d c9 0f 22 03 	lea    rdi,[rip+0x3220fc9]        # 0x391c198
  6fb1cf:	31 f6                	xor    esi,esi
  6fb1d1:	31 d2                	xor    edx,edx
  6fb1d3:	31 c9                	xor    ecx,ecx
  6fb1d5:	e8 46 c3 dc ff       	call   0x4c7520
  6fb1da:	48 8d 3d a8 8f ca 00 	lea    rdi,[rip+0xca8fa8]        # 0x13a4189
  6fb1e1:	e8 fa 30 04 00       	call   0x73e2e0
  6fb1e6:	48 85 c0             	test   rax,rax
  6fb1e9:	74 82                	je     0x6fb16d
  6fb1eb:	49 89 c6             	mov    r14,rax
  6fb1ee:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
  6fb1f1:	8d 48 01             	lea    ecx,[rax+0x1]
  6fb1f4:	41 89 4e 0c          	mov    DWORD PTR [r14+0xc],ecx
  6fb1f8:	4d 8b 7e 40          	mov    r15,QWORD PTR [r14+0x40]
  6fb1fc:	4d 85 ff             	test   r15,r15
  6fb1ff:	0f 84 af 01 00 00    	je     0x6fb3b4
  6fb205:	49 8d 5e 28          	lea    rbx,[r14+0x28]
  6fb209:	4c 8d 2d 58 fd b6 ff 	lea    r13,[rip+0xffffffffffb6fd58]        # 0x26af68
  6fb210:	eb 32                	jmp    0x6fb244
  6fb212:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fb219:	1f 84 00 00 00 00 00 
  6fb220:	49 8b 7f 18          	mov    rdi,QWORD PTR [r15+0x18]
  6fb224:	8b 75 cc             	mov    esi,DWORD PTR [rbp-0x34]
  6fb227:	41 ff d4             	call   r12
  6fb22a:	48 89 df             	mov    rdi,rbx
  6fb22d:	31 f6                	xor    esi,esi
  6fb22f:	31 d2                	xor    edx,edx
  6fb231:	31 c9                	xor    ecx,ecx
  6fb233:	e8 c8 b7 dc ff       	call   0x4c6a00
  6fb238:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  6fb23b:	4d 85 ff             	test   r15,r15
  6fb23e:	0f 84 63 01 00 00    	je     0x6fb3a7
  6fb244:	41 83 7f 10 ff       	cmp    DWORD PTR [r15+0x10],0xffffffff
  6fb249:	74 ed                	je     0x6fb238
  6fb24b:	48 89 df             	mov    rdi,rbx
  6fb24e:	31 f6                	xor    esi,esi
  6fb250:	31 d2                	xor    edx,edx
  6fb252:	31 c9                	xor    ecx,ecx
  6fb254:	e8 47 bd dc ff       	call   0x4c6fa0
  6fb259:	4d 8b 67 28          	mov    r12,QWORD PTR [r15+0x28]
  6fb25d:	4c 89 e8             	mov    rax,r13
  6fb260:	4c 29 e0             	sub    rax,r12
  6fb263:	48 c1 c8 03          	ror    rax,0x3
  6fb267:	48 3d 0b 01 00 00    	cmp    rax,0x10b
  6fb26d:	76 b1                	jbe    0x6fb220
  6fb26f:	48 8d 3d aa 02 b0 01 	lea    rdi,[rip+0x1b002aa]        # 0x21fb520
  6fb276:	4c 89 e6             	mov    rsi,r12
  6fb279:	e8 42 46 d5 ff       	call   0x44f8c0
  6fb27e:	eb a0                	jmp    0x6fb220
  6fb280:	89 05 3e 01 b0 01    	mov    DWORD PTR [rip+0x1b0013e],eax        # 0x21fb3c4
  6fb286:	8b 05 34 01 b0 01    	mov    eax,DWORD PTR [rip+0x1b00134]        # 0x21fb3c0
  6fb28c:	83 f8 04             	cmp    eax,0x4
  6fb28f:	74 21                	je     0x6fb2b2
  6fb291:	8b 05 29 01 b0 01    	mov    eax,DWORD PTR [rip+0x1b00129]        # 0x21fb3c0
  6fb297:	83 f8 03             	cmp    eax,0x3
  6fb29a:	74 16                	je     0x6fb2b2
  6fb29c:	8b 05 1e 01 b0 01    	mov    eax,DWORD PTR [rip+0x1b0011e]        # 0x21fb3c0
  6fb2a2:	83 f8 05             	cmp    eax,0x5
  6fb2a5:	74 0b                	je     0x6fb2b2
  6fb2a7:	8b 05 17 01 b0 01    	mov    eax,DWORD PTR [rip+0x1b00117]        # 0x21fb3c4
  6fb2ad:	83 f8 01             	cmp    eax,0x1
  6fb2b0:	75 4c                	jne    0x6fb2fe
  6fb2b2:	83 3d 0f 01 b0 01 00 	cmp    DWORD PTR [rip+0x1b0010f],0x0        # 0x21fb3c8
  6fb2b9:	75 43                	jne    0x6fb2fe
  6fb2bb:	c7 05 03 01 b0 01 01 	mov    DWORD PTR [rip+0x1b00103],0x1        # 0x21fb3c8
  6fb2c2:	00 00 00 
  6fb2c5:	e8 06 c6 40 00       	call   0xb078d0
  6fb2ca:	85 c0                	test   eax,eax
  6fb2cc:	74 30                	je     0x6fb2fe
  6fb2ce:	83 3d 2b 4d 5b 02 00 	cmp    DWORD PTR [rip+0x25b4d2b],0x0        # 0x2cb0000
  6fb2d5:	74 27                	je     0x6fb2fe
  6fb2d7:	4c 8b 35 0a b6 4f 03 	mov    r14,QWORD PTR [rip+0x34fb60a]        # 0x3bf68e8
  6fb2de:	48 8d 05 6b 04 b7 ff 	lea    rax,[rip+0xffffffffffb7046b]        # 0x26b750
  6fb2e5:	4c 29 f0             	sub    rax,r14
  6fb2e8:	48 c1 c8 03          	ror    rax,0x3
  6fb2ec:	48 83 f8 08          	cmp    rax,0x8
  6fb2f0:	0f 87 ee 00 00 00    	ja     0x6fb3e4
  6fb2f6:	bf 01 00 00 00       	mov    edi,0x1
  6fb2fb:	41 ff d6             	call   r14
  6fb2fe:	48 63 05 c7 00 b0 01 	movsxd rax,DWORD PTR [rip+0x1b000c7]        # 0x21fb3cc
  6fb305:	48 8d 0d 04 eb cb 00 	lea    rcx,[rip+0xcbeb04]        # 0x13b9e10
  6fb30c:	ba 01 00 00 00       	mov    edx,0x1
  6fb311:	45 31 f6             	xor    r14d,r14d
  6fb314:	0f b6 04 c1          	movzx  eax,BYTE PTR [rcx+rax*8]
  6fb318:	c4 62 f9 f7 fa       	shlx   r15,rdx,rax
  6fb31d:	48 63 05 a8 00 b0 01 	movsxd rax,DWORD PTR [rip+0x1b000a8]        # 0x21fb3cc
  6fb324:	0f b6 44 c1 04       	movzx  eax,BYTE PTR [rcx+rax*8+0x4]
  6fb329:	49 0f ab c7          	bts    r15,rax
  6fb32d:	49 83 cf 08          	or     r15,0x8
  6fb331:	eb 25                	jmp    0x6fb358
  6fb333:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fb33a:	84 00 00 00 00 00 
  6fb340:	44 89 f7             	mov    edi,r14d
  6fb343:	e8 b8 b8 fb ff       	call   0x6b6c00
  6fb348:	41 ff c6             	inc    r14d
  6fb34b:	44 3b 35 66 35 61 03 	cmp    r14d,DWORD PTR [rip+0x3613566]        # 0x3d0e8b8
  6fb352:	0f 87 70 fe ff ff    	ja     0x6fb1c8
  6fb358:	4d 0f a3 f7          	bt     r15,r14
  6fb35c:	73 ea                	jae    0x6fb348
  6fb35e:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6fb365:	00 
  6fb366:	41 39 c6             	cmp    r14d,eax
  6fb369:	75 d5                	jne    0x6fb340
  6fb36b:	65 4c 8b 24 25 00 00 	mov    r12,QWORD PTR gs:0x0
  6fb372:	00 00 
  6fb374:	4c 89 e7             	mov    rdi,r12
  6fb377:	48 8d 15 94 e9 b7 00 	lea    rdx,[rip+0xb7e994]        # 0x1279d12
  6fb37e:	b9 b4 02 00 00       	mov    ecx,0x2b4
  6fb383:	31 f6                	xor    esi,esi
  6fb385:	e8 26 c5 dc ff       	call   0x4c78b0
  6fb38a:	4c 89 e7             	mov    rdi,r12
  6fb38d:	e8 5e b9 fb ff       	call   0x6b6cf0
  6fb392:	49 8b 3c 24          	mov    rdi,QWORD PTR [r12]
  6fb396:	31 f6                	xor    esi,esi
  6fb398:	31 d2                	xor    edx,edx
  6fb39a:	31 c9                	xor    ecx,ecx
  6fb39c:	48 83 c7 18          	add    rdi,0x18
  6fb3a0:	e8 7b c1 dc ff       	call   0x4c7520
  6fb3a5:	eb a1                	jmp    0x6fb348
  6fb3a7:	41 8b 46 0c          	mov    eax,DWORD PTR [r14+0xc]
  6fb3ab:	4c 8d 2d 5e 0f 22 03 	lea    r13,[rip+0x3220f5e]        # 0x391c310
  6fb3b2:	ff c8                	dec    eax
  6fb3b4:	41 89 46 0c          	mov    DWORD PTR [r14+0xc],eax
  6fb3b8:	85 c0                	test   eax,eax
  6fb3ba:	75 08                	jne    0x6fb3c4
  6fb3bc:	4c 89 f7             	mov    rdi,r14
  6fb3bf:	e8 ac 2f 04 00       	call   0x73e370
  6fb3c4:	49 83 c6 28          	add    r14,0x28
  6fb3c8:	31 db                	xor    ebx,ebx
  6fb3ca:	31 f6                	xor    esi,esi
  6fb3cc:	31 d2                	xor    edx,edx
  6fb3ce:	31 c9                	xor    ecx,ecx
  6fb3d0:	4c 89 f7             	mov    rdi,r14
  6fb3d3:	e8 c8 bb dc ff       	call   0x4c6fa0
  6fb3d8:	e9 90 fd ff ff       	jmp    0x6fb16d
  6fb3dd:	e8 ce 22 00 00       	call   0x6fd6b0
  6fb3e2:	0f 0b                	ud2
  6fb3e4:	48 8d 3d 55 01 b0 01 	lea    rdi,[rip+0x1b00155]        # 0x21fb540
  6fb3eb:	4c 89 f6             	mov    rsi,r14
  6fb3ee:	e8 cd 44 d5 ff       	call   0x44f8c0
  6fb3f3:	e9 fe fe ff ff       	jmp    0x6fb2f6
  6fb3f8:	90                   	nop
  6fb3f9:	90                   	nop
  6fb3fa:	90                   	nop
  6fb3fb:	90                   	nop
  6fb3fc:	90                   	nop
  6fb3fd:	90                   	nop
  6fb3fe:	90                   	nop
  6fb3ff:	90                   	nop
  6fb400:	55                   	push   rbp
  6fb401:	48 89 e5             	mov    rbp,rsp
  6fb404:	41 57                	push   r15
  6fb406:	41 56                	push   r14
  6fb408:	41 55                	push   r13
  6fb40a:	41 54                	push   r12
  6fb40c:	53                   	push   rbx
  6fb40d:	48 83 ec 28          	sub    rsp,0x28
  6fb411:	4c 8d 2d f8 0e 22 03 	lea    r13,[rip+0x3220ef8]        # 0x391c310
  6fb418:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  6fb41c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6fb420:	48 8d 05 d9 ea b6 ff 	lea    rax,[rip+0xffffffffffb6ead9]        # 0x269f00
  6fb427:	48 8b 59 48          	mov    rbx,QWORD PTR [rcx+0x48]
  6fb42b:	48 29 d8             	sub    rax,rbx
  6fb42e:	48 c1 c8 03          	ror    rax,0x3
  6fb432:	48 83 f8 16          	cmp    rax,0x16
  6fb436:	0f 87 e1 01 00 00    	ja     0x6fb61d
  6fb43c:	48 8d 75 b8          	lea    rsi,[rbp-0x48]
  6fb440:	ba 10 00 00 00       	mov    edx,0x10
  6fb445:	48 89 cf             	mov    rdi,rcx
  6fb448:	ff d3                	call   rbx
  6fb44a:	89 c3                	mov    ebx,eax
  6fb44c:	85 c0                	test   eax,eax
  6fb44e:	0f 85 ae 01 00 00    	jne    0x6fb602
  6fb454:	8b 05 66 ff af 01    	mov    eax,DWORD PTR [rip+0x1afff66]        # 0x21fb3c0
  6fb45a:	83 f8 04             	cmp    eax,0x4
  6fb45d:	74 2a                	je     0x6fb489
  6fb45f:	8b 05 5b ff af 01    	mov    eax,DWORD PTR [rip+0x1afff5b]        # 0x21fb3c0
  6fb465:	83 f8 03             	cmp    eax,0x3
  6fb468:	74 1f                	je     0x6fb489
  6fb46a:	8b 05 50 ff af 01    	mov    eax,DWORD PTR [rip+0x1afff50]        # 0x21fb3c0
  6fb470:	83 f8 05             	cmp    eax,0x5
  6fb473:	74 14                	je     0x6fb489
  6fb475:	8b 05 45 ff af 01    	mov    eax,DWORD PTR [rip+0x1afff45]        # 0x21fb3c0
  6fb47b:	bb 01 00 00 00       	mov    ebx,0x1
  6fb480:	83 f8 01             	cmp    eax,0x1
  6fb483:	0f 85 79 01 00 00    	jne    0x6fb602
  6fb489:	b8 00 fd ff ff       	mov    eax,0xfffffd00
  6fb48e:	03 45 c0             	add    eax,DWORD PTR [rbp-0x40]
  6fb491:	bb 16 00 00 00       	mov    ebx,0x16
  6fb496:	3d ff fd ff ff       	cmp    eax,0xfffffdff
  6fb49b:	0f 82 61 01 00 00    	jb     0x6fb602
  6fb4a1:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  6fb4a5:	48 85 ff             	test   rdi,rdi
  6fb4a8:	74 29                	je     0x6fb4d3
  6fb4aa:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6fb4b1:	00 00 
  6fb4b3:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  6fb4b7:	80 b8 81 0c 00 00 01 	cmp    BYTE PTR [rax+0xc81],0x1
  6fb4be:	75 1d                	jne    0x6fb4dd
  6fb4c0:	bb 01 00 00 00       	mov    ebx,0x1
  6fb4c5:	48 81 ff 00 20 00 00 	cmp    rdi,0x2000
  6fb4cc:	72 2a                	jb     0x6fb4f8
  6fb4ce:	e9 2f 01 00 00       	jmp    0x6fb602
  6fb4d3:	bb 0b 00 00 00       	mov    ebx,0xb
  6fb4d8:	e9 25 01 00 00       	jmp    0x6fb602
  6fb4dd:	bb 01 00 00 00       	mov    ebx,0x1
  6fb4e2:	48 83 ff 7f          	cmp    rdi,0x7f
  6fb4e6:	0f 87 16 01 00 00    	ja     0x6fb602
  6fb4ec:	e8 4f 25 14 00       	call   0x83da40
  6fb4f1:	0f b7 c0             	movzx  eax,ax
  6fb4f4:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  6fb4f8:	48 8d 3d 99 0c 22 03 	lea    rdi,[rip+0x3220c99]        # 0x391c198
  6fb4ff:	31 f6                	xor    esi,esi
  6fb501:	31 d2                	xor    edx,edx
  6fb503:	31 c9                	xor    ecx,ecx
  6fb505:	e8 86 bc dc ff       	call   0x4c7190
  6fb50a:	0f b7 7d b8          	movzx  edi,WORD PTR [rbp-0x48]
  6fb50e:	44 8b 75 c0          	mov    r14d,DWORD PTR [rbp-0x40]
  6fb512:	e8 d9 24 14 00       	call   0x83d9f0
  6fb517:	0f b7 d8             	movzx  ebx,ax
  6fb51a:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  6fb51e:	44 39 35 b3 fe af 01 	cmp    DWORD PTR [rip+0x1affeb3],r14d        # 0x21fb3d8
  6fb525:	75 0d                	jne    0x6fb534
  6fb527:	48 39 1d b2 fe af 01 	cmp    QWORD PTR [rip+0x1affeb2],rbx        # 0x21fb3e0
  6fb52e:	0f 84 ba 00 00 00    	je     0x6fb5ee
  6fb534:	8b 05 86 fe af 01    	mov    eax,DWORD PTR [rip+0x1affe86]        # 0x21fb3c0
  6fb53a:	83 f8 04             	cmp    eax,0x4
  6fb53d:	74 25                	je     0x6fb564
  6fb53f:	8b 05 7b fe af 01    	mov    eax,DWORD PTR [rip+0x1affe7b]        # 0x21fb3c0
  6fb545:	83 f8 03             	cmp    eax,0x3
  6fb548:	74 1a                	je     0x6fb564
  6fb54a:	8b 05 70 fe af 01    	mov    eax,DWORD PTR [rip+0x1affe70]        # 0x21fb3c0
  6fb550:	83 f8 05             	cmp    eax,0x5
  6fb553:	74 0f                	je     0x6fb564
  6fb555:	8b 05 65 fe af 01    	mov    eax,DWORD PTR [rip+0x1affe65]        # 0x21fb3c0
  6fb55b:	83 f8 01             	cmp    eax,0x1
  6fb55e:	0f 85 7c 00 00 00    	jne    0x6fb5e0
  6fb564:	4c 8b 3d b5 fa af 01 	mov    r15,QWORD PTR [rip+0x1affab5]        # 0x21fb020
  6fb56b:	4d 85 ff             	test   r15,r15
  6fb56e:	74 70                	je     0x6fb5e0
  6fb570:	41 0f b7 c6          	movzx  eax,r14w
  6fb574:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
  6fb577:	eb 22                	jmp    0x6fb59b
  6fb579:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  6fb580:	49 8b 3c 24          	mov    rdi,QWORD PTR [r12]
  6fb584:	31 f6                	xor    esi,esi
  6fb586:	31 d2                	xor    edx,edx
  6fb588:	31 c9                	xor    ecx,ecx
  6fb58a:	48 83 c7 18          	add    rdi,0x18
  6fb58e:	e8 8d bf dc ff       	call   0x4c7520
  6fb593:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  6fb596:	4d 85 ff             	test   r15,r15
  6fb599:	74 45                	je     0x6fb5e0
  6fb59b:	4d 8b 67 10          	mov    r12,QWORD PTR [r15+0x10]
  6fb59f:	48 8d 15 6c e7 b7 00 	lea    rdx,[rip+0xb7e76c]        # 0x1279d12
  6fb5a6:	b9 ed 01 00 00       	mov    ecx,0x1ed
  6fb5ab:	31 f6                	xor    esi,esi
  6fb5ad:	4c 89 e7             	mov    rdi,r12
  6fb5b0:	e8 fb c2 dc ff       	call   0x4c78b0
  6fb5b5:	44 39 35 1c fe af 01 	cmp    DWORD PTR [rip+0x1affe1c],r14d        # 0x21fb3d8
  6fb5bc:	74 0b                	je     0x6fb5c9
  6fb5be:	8b 75 b4             	mov    esi,DWORD PTR [rbp-0x4c]
  6fb5c1:	4c 89 e7             	mov    rdi,r12
  6fb5c4:	e8 47 a3 fb ff       	call   0x6b5910
  6fb5c9:	48 39 1d 10 fe af 01 	cmp    QWORD PTR [rip+0x1affe10],rbx        # 0x21fb3e0
  6fb5d0:	74 ae                	je     0x6fb580
  6fb5d2:	4c 89 e7             	mov    rdi,r12
  6fb5d5:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  6fb5d9:	e8 f2 15 14 00       	call   0x83cbd0
  6fb5de:	eb a0                	jmp    0x6fb580
  6fb5e0:	44 89 35 f1 fd af 01 	mov    DWORD PTR [rip+0x1affdf1],r14d        # 0x21fb3d8
  6fb5e7:	48 89 1d f2 fd af 01 	mov    QWORD PTR [rip+0x1affdf2],rbx        # 0x21fb3e0
  6fb5ee:	48 8d 3d a3 0b 22 03 	lea    rdi,[rip+0x3220ba3]        # 0x391c198
  6fb5f5:	31 db                	xor    ebx,ebx
  6fb5f7:	31 f6                	xor    esi,esi
  6fb5f9:	31 d2                	xor    edx,edx
  6fb5fb:	31 c9                	xor    ecx,ecx
  6fb5fd:	e8 1e bf dc ff       	call   0x4c7520
  6fb602:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  6fb606:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6fb60a:	75 2b                	jne    0x6fb637
  6fb60c:	89 d8                	mov    eax,ebx
  6fb60e:	48 83 c4 28          	add    rsp,0x28
  6fb612:	5b                   	pop    rbx
  6fb613:	41 5c                	pop    r12
  6fb615:	41 5d                	pop    r13
  6fb617:	41 5e                	pop    r14
  6fb619:	41 5f                	pop    r15
  6fb61b:	5d                   	pop    rbp
  6fb61c:	c3                   	ret
  6fb61d:	48 8d 3d 3c ff af 01 	lea    rdi,[rip+0x1afff3c]        # 0x21fb560
  6fb624:	48 89 de             	mov    rsi,rbx
  6fb627:	49 89 ce             	mov    r14,rcx
  6fb62a:	e8 91 42 d5 ff       	call   0x44f8c0
  6fb62f:	4c 89 f1             	mov    rcx,r14
  6fb632:	e9 05 fe ff ff       	jmp    0x6fb43c
  6fb637:	e8 74 20 00 00       	call   0x6fd6b0
  6fb63c:	0f 0b                	ud2
  6fb63e:	90                   	nop
  6fb63f:	90                   	nop
  6fb640:	55                   	push   rbp
  6fb641:	48 89 e5             	mov    rbp,rsp
  6fb644:	41 56                	push   r14
  6fb646:	53                   	push   rbx
  6fb647:	49 89 fe             	mov    r14,rdi
  6fb64a:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6fb651:	00 00 
  6fb653:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  6fb65a:	48 89 cb             	mov    rbx,rcx
  6fb65d:	e8 ae da f0 ff       	call   0x609110
  6fb662:	85 c0                	test   eax,eax
  6fb664:	74 18                	je     0x6fb67e
  6fb666:	48 8d 35 13 ff af 01 	lea    rsi,[rip+0x1afff13]        # 0x21fb580
  6fb66d:	4c 89 f7             	mov    rdi,r14
  6fb670:	31 d2                	xor    edx,edx
  6fb672:	48 89 d9             	mov    rcx,rbx
  6fb675:	5b                   	pop    rbx
  6fb676:	41 5e                	pop    r14
  6fb678:	5d                   	pop    rbp
  6fb679:	e9 6a 53 b7 ff       	jmp    0x2709e8
  6fb67e:	b8 4e 00 00 00       	mov    eax,0x4e
  6fb683:	5b                   	pop    rbx
  6fb684:	41 5e                	pop    r14
  6fb686:	5d                   	pop    rbp
  6fb687:	c3                   	ret
  6fb688:	90                   	nop
  6fb689:	90                   	nop
  6fb68a:	90                   	nop
  6fb68b:	90                   	nop
  6fb68c:	90                   	nop
  6fb68d:	90                   	nop
  6fb68e:	90                   	nop
  6fb68f:	90                   	nop
  6fb690:	55                   	push   rbp
  6fb691:	48 89 e5             	mov    rbp,rsp
  6fb694:	53                   	push   rbx
  6fb695:	50                   	push   rax
  6fb696:	48 8d 3d 4b 0c 22 03 	lea    rdi,[rip+0x3220c4b]        # 0x391c2e8
  6fb69d:	48 8d 35 80 38 c2 00 	lea    rsi,[rip+0xc23880]        # 0x131ef24
  6fb6a4:	48 c7 05 19 0c 22 03 	mov    QWORD PTR [rip+0x3220c19],0x0        # 0x391c2c8
  6fb6ab:	00 00 00 00 
  6fb6af:	31 d2                	xor    edx,edx
  6fb6b1:	31 c9                	xor    ecx,ecx
  6fb6b3:	e8 18 c7 dc ff       	call   0x4c7dd0
  6fb6b8:	bf e9 00 00 00       	mov    edi,0xe9
  6fb6bd:	c7 05 29 0c 22 03 00 	mov    DWORD PTR [rip+0x3220c29],0x0        # 0x391c2f0
  6fb6c4:	00 00 00 
  6fb6c7:	e8 d4 12 3d 00       	call   0xacc9a0
  6fb6cc:	85 c0                	test   eax,eax
  6fb6ce:	74 2e                	je     0x6fb6fe
  6fb6d0:	48 8d 1d 11 0c 22 03 	lea    rbx,[rip+0x3220c11]        # 0x391c2e8
  6fb6d7:	31 f6                	xor    esi,esi
  6fb6d9:	31 d2                	xor    edx,edx
  6fb6db:	31 c9                	xor    ecx,ecx
  6fb6dd:	48 89 df             	mov    rdi,rbx
  6fb6e0:	e8 1b b3 dc ff       	call   0x4c6a00
  6fb6e5:	e8 26 00 00 00       	call   0x6fb710
  6fb6ea:	48 89 df             	mov    rdi,rbx
  6fb6ed:	31 f6                	xor    esi,esi
  6fb6ef:	31 d2                	xor    edx,edx
  6fb6f1:	31 c9                	xor    ecx,ecx
  6fb6f3:	48 83 c4 08          	add    rsp,0x8
  6fb6f7:	5b                   	pop    rbx
  6fb6f8:	5d                   	pop    rbp
  6fb6f9:	e9 a2 b8 dc ff       	jmp    0x4c6fa0
  6fb6fe:	48 83 c4 08          	add    rsp,0x8
  6fb702:	5b                   	pop    rbx
  6fb703:	5d                   	pop    rbp
  6fb704:	c3                   	ret
  6fb705:	90                   	nop
  6fb706:	90                   	nop
  6fb707:	90                   	nop
  6fb708:	90                   	nop
  6fb709:	90                   	nop
  6fb70a:	90                   	nop
  6fb70b:	90                   	nop
  6fb70c:	90                   	nop
  6fb70d:	90                   	nop
  6fb70e:	90                   	nop
  6fb70f:	90                   	nop
  6fb710:	55                   	push   rbp
  6fb711:	48 89 e5             	mov    rbp,rsp
  6fb714:	41 57                	push   r15
  6fb716:	41 56                	push   r14
  6fb718:	41 55                	push   r13
  6fb71a:	41 54                	push   r12
  6fb71c:	53                   	push   rbx
  6fb71d:	48 83 ec 18          	sub    rsp,0x18
  6fb721:	4c 8d 35 e8 0b 22 03 	lea    r14,[rip+0x3220be8]        # 0x391c310
  6fb728:	48 8d 3d cc 31 c6 00 	lea    rdi,[rip+0xc631cc]        # 0x135e8fb
  6fb72f:	49 8b 06             	mov    rax,QWORD PTR [r14]
  6fb732:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6fb736:	31 c0                	xor    eax,eax
  6fb738:	e8 d3 1c b6 ff       	call   0x25d410
  6fb73d:	83 3d c4 fc af 01 00 	cmp    DWORD PTR [rip+0x1affcc4],0x0        # 0x21fb408
  6fb744:	0f 85 4d 01 00 00    	jne    0x6fb897
  6fb74a:	48 8d 3d 97 0b 22 03 	lea    rdi,[rip+0x3220b97]        # 0x391c2e8
  6fb751:	c7 05 ad fc af 01 01 	mov    DWORD PTR [rip+0x1affcad],0x1        # 0x21fb408
  6fb758:	00 00 00 
  6fb75b:	31 f6                	xor    esi,esi
  6fb75d:	31 d2                	xor    edx,edx
  6fb75f:	31 c9                	xor    ecx,ecx
  6fb761:	e8 3a b8 dc ff       	call   0x4c6fa0
  6fb766:	48 83 ec 08          	sub    rsp,0x8
  6fb76a:	4c 8d 15 6d 2b c4 00 	lea    r10,[rip+0xc42b6d]        # 0x133e2de
  6fb771:	48 8d 3d c8 7a b6 ff 	lea    rdi,[rip+0xffffffffffb67ac8]        # 0x263240
  6fb778:	48 8d 4d c8          	lea    rcx,[rbp-0x38]
  6fb77c:	31 f6                	xor    esi,esi
  6fb77e:	31 d2                	xor    edx,edx
  6fb780:	45 31 c0             	xor    r8d,r8d
  6fb783:	45 31 c9             	xor    r9d,r9d
  6fb786:	31 c0                	xor    eax,eax
  6fb788:	41 52                	push   r10
  6fb78a:	e8 41 a3 22 00       	call   0x925ad0
  6fb78f:	48 83 c4 10          	add    rsp,0x10
  6fb793:	bf 01 00 00 00       	mov    edi,0x1
  6fb798:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
  6fb79b:	e8 80 c8 fb ff       	call   0x6b8020
  6fb7a0:	4c 8d 2d 51 0b 22 03 	lea    r13,[rip+0x3220b51]        # 0x391c2f8
  6fb7a7:	4c 89 ef             	mov    rdi,r13
  6fb7aa:	e8 e1 b5 e5 ff       	call   0x556d90
  6fb7af:	48 83 ec 08          	sub    rsp,0x8
  6fb7b3:	48 8d 35 f6 0c e7 01 	lea    rsi,[rip+0x1e70cf6]        # 0x256c4b0
  6fb7ba:	48 8d 0d 5a 02 bd 00 	lea    rcx,[rip+0xbd025a]        # 0x12cba1b
  6fb7c1:	48 8d 05 24 7a c8 00 	lea    rax,[rip+0xc87a24]        # 0x13831ec
  6fb7c8:	4c 89 ef             	mov    rdi,r13
  6fb7cb:	ba ff ff ff ff       	mov    edx,0xffffffff
  6fb7d0:	41 b8 01 00 00 c0    	mov    r8d,0xc0000001
  6fb7d6:	45 31 c9             	xor    r9d,r9d
  6fb7d9:	6a 01                	push   0x1
  6fb7db:	51                   	push   rcx
  6fb7dc:	50                   	push   rax
  6fb7dd:	6a 00                	push   0x0
  6fb7df:	6a 00                	push   0x0
  6fb7e1:	e8 3a b9 e5 ff       	call   0x557120
  6fb7e6:	48 83 c4 30          	add    rsp,0x30
  6fb7ea:	49 89 c7             	mov    r15,rax
  6fb7ed:	48 83 ec 08          	sub    rsp,0x8
  6fb7f1:	48 8d 1d f0 51 b7 ff 	lea    rbx,[rip+0xffffffffffb751f0]        # 0x2709e8
  6fb7f8:	48 8d 0d 4b e5 b7 00 	lea    rcx,[rip+0xb7e54b]        # 0x1279d4a
  6fb7ff:	4c 8d 25 41 24 c9 00 	lea    r12,[rip+0xc92441]        # 0x138dc47
  6fb806:	4c 89 ef             	mov    rdi,r13
  6fb809:	48 89 c6             	mov    rsi,rax
  6fb80c:	ba ff ff ff ff       	mov    edx,0xffffffff
  6fb811:	41 b8 02 00 04 80    	mov    r8d,0x80040002
  6fb817:	4c 8d 0d a2 fb af 01 	lea    r9,[rip+0x1affba2]        # 0x21fb3c0
  6fb81e:	6a 01                	push   0x1
  6fb820:	51                   	push   rcx
  6fb821:	41 54                	push   r12
  6fb823:	53                   	push   rbx
  6fb824:	6a 00                	push   0x0
  6fb826:	e8 f5 b8 e5 ff       	call   0x557120
  6fb82b:	48 83 c4 28          	add    rsp,0x28
  6fb82f:	48 8d 0d cc 29 c6 00 	lea    rcx,[rip+0xc629cc]        # 0x135e202
  6fb836:	4c 89 ef             	mov    rdi,r13
  6fb839:	4c 89 fe             	mov    rsi,r15
  6fb83c:	ba ff ff ff ff       	mov    edx,0xffffffff
  6fb841:	41 b8 02 00 04 80    	mov    r8d,0x80040002
  6fb847:	4c 8d 0d ba fb af 01 	lea    r9,[rip+0x1affbba]        # 0x21fb408
  6fb84e:	6a 01                	push   0x1
  6fb850:	51                   	push   rcx
  6fb851:	41 54                	push   r12
  6fb853:	53                   	push   rbx
  6fb854:	6a 00                	push   0x0
  6fb856:	e8 c5 b8 e5 ff       	call   0x557120
  6fb85b:	48 83 c4 30          	add    rsp,0x30
  6fb85f:	48 8d 3d 82 0a 22 03 	lea    rdi,[rip+0x3220a82]        # 0x391c2e8
  6fb866:	31 f6                	xor    esi,esi
  6fb868:	31 d2                	xor    edx,edx
  6fb86a:	31 c9                	xor    ecx,ecx
  6fb86c:	e8 8f b1 dc ff       	call   0x4c6a00
  6fb871:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  6fb875:	48 89 05 4c 0a 22 03 	mov    QWORD PTR [rip+0x3220a4c],rax        # 0x391c2c8
  6fb87c:	49 8b 06             	mov    rax,QWORD PTR [r14]
  6fb87f:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6fb883:	75 1b                	jne    0x6fb8a0
  6fb885:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
  6fb888:	48 83 c4 18          	add    rsp,0x18
  6fb88c:	5b                   	pop    rbx
  6fb88d:	41 5c                	pop    r12
  6fb88f:	41 5d                	pop    r13
  6fb891:	41 5e                	pop    r14
  6fb893:	41 5f                	pop    r15
  6fb895:	5d                   	pop    rbp
  6fb896:	c3                   	ret
  6fb897:	c7 45 c4 10 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x10
  6fb89e:	eb dc                	jmp    0x6fb87c
  6fb8a0:	e8 0b 1e 00 00       	call   0x6fd6b0
  6fb8a5:	0f 0b                	ud2
  6fb8a7:	90                   	nop
  6fb8a8:	90                   	nop
  6fb8a9:	90                   	nop
  6fb8aa:	90                   	nop
  6fb8ab:	90                   	nop
  6fb8ac:	90                   	nop
  6fb8ad:	90                   	nop
  6fb8ae:	90                   	nop
  6fb8af:	90                   	nop
  6fb8b0:	55                   	push   rbp
  6fb8b1:	48 89 e5             	mov    rbp,rsp
  6fb8b4:	41 56                	push   r14
  6fb8b6:	53                   	push   rbx
  6fb8b7:	48 8d 3d 20 2a c4 00 	lea    rdi,[rip+0xc42a20]        # 0x133e2de
  6fb8be:	be 00 01 00 00       	mov    esi,0x100
  6fb8c3:	ba ff ff 00 00       	mov    edx,0xffff
  6fb8c8:	31 c9                	xor    ecx,ecx
  6fb8ca:	e8 91 ab 22 00       	call   0x926460
  6fb8cf:	83 3d 1a 0a 22 03 00 	cmp    DWORD PTR [rip+0x3220a1a],0x0        # 0x391c2f0
  6fb8d6:	75 72                	jne    0x6fb94a
  6fb8d8:	48 8d 1d b9 08 22 03 	lea    rbx,[rip+0x32208b9]        # 0x391c198
  6fb8df:	4c 8d 35 73 4c b7 00 	lea    r14,[rip+0xb74c73]        # 0x1270559
  6fb8e6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  6fb8ed:	00 00 00 
  6fb8f0:	48 89 df             	mov    rdi,rbx
  6fb8f3:	31 f6                	xor    esi,esi
  6fb8f5:	31 d2                	xor    edx,edx
  6fb8f7:	31 c9                	xor    ecx,ecx
  6fb8f9:	e8 92 b8 dc ff       	call   0x4c7190
  6fb8fe:	e8 8d 00 00 00       	call   0x6fb990
  6fb903:	48 89 df             	mov    rdi,rbx
  6fb906:	31 f6                	xor    esi,esi
  6fb908:	31 d2                	xor    edx,edx
  6fb90a:	31 c9                	xor    ecx,ecx
  6fb90c:	e8 0f bc dc ff       	call   0x4c7520
  6fb911:	e8 7a c7 fb ff       	call   0x6b8090
  6fb916:	8b 05 24 4b 22 03    	mov    eax,DWORD PTR [rip+0x3224b24]        # 0x3920440
  6fb91c:	4c 89 f7             	mov    rdi,r14
  6fb91f:	8d 48 03             	lea    ecx,[rax+0x3]
  6fb922:	85 c0                	test   eax,eax
  6fb924:	0f 49 c8             	cmovns ecx,eax
  6fb927:	31 d2                	xor    edx,edx
  6fb929:	c1 f9 02             	sar    ecx,0x2
  6fb92c:	48 63 f1             	movsxd rsi,ecx
  6fb92f:	48 0f af 35 99 4a 22 	imul   rsi,QWORD PTR [rip+0x3224a99]        # 0x39203d0
  6fb936:	03 
  6fb937:	b9 00 01 00 00       	mov    ecx,0x100
  6fb93c:	e8 ef ae 50 00       	call   0xc06830
  6fb941:	83 3d a8 09 22 03 00 	cmp    DWORD PTR [rip+0x32209a8],0x0        # 0x391c2f0
  6fb948:	74 a6                	je     0x6fb8f0
  6fb94a:	48 8d 1d 97 09 22 03 	lea    rbx,[rip+0x3220997]        # 0x391c2e8
  6fb951:	31 f6                	xor    esi,esi
  6fb953:	31 d2                	xor    edx,edx
  6fb955:	31 c9                	xor    ecx,ecx
  6fb957:	48 89 df             	mov    rdi,rbx
  6fb95a:	e8 a1 b0 dc ff       	call   0x4c6a00
  6fb95f:	48 8d 3d 8a 09 22 03 	lea    rdi,[rip+0x322098a]        # 0x391c2f0
  6fb966:	c7 05 80 09 22 03 00 	mov    DWORD PTR [rip+0x3220980],0x0        # 0x391c2f0
  6fb96d:	00 00 00 
  6fb970:	e8 9b af 50 00       	call   0xc06910
  6fb975:	48 89 df             	mov    rdi,rbx
  6fb978:	31 f6                	xor    esi,esi
  6fb97a:	31 d2                	xor    edx,edx
  6fb97c:	31 c9                	xor    ecx,ecx
  6fb97e:	e8 1d b6 dc ff       	call   0x4c6fa0
  6fb983:	e8 f8 a3 22 00       	call   0x925d80
  6fb988:	0f 0b                	ud2
  6fb98a:	90                   	nop
  6fb98b:	90                   	nop
  6fb98c:	90                   	nop
  6fb98d:	90                   	nop
  6fb98e:	90                   	nop
  6fb98f:	90                   	nop
  6fb990:	55                   	push   rbp
  6fb991:	48 89 e5             	mov    rbp,rsp
  6fb994:	83 3d 25 fa af 01 00 	cmp    DWORD PTR [rip+0x1affa25],0x0        # 0x21fb3c0
  6fb99b:	74 3b                	je     0x6fb9d8
  6fb99d:	8b 05 1d fa af 01    	mov    eax,DWORD PTR [rip+0x1affa1d]        # 0x21fb3c0
  6fb9a3:	83 f8 01             	cmp    eax,0x1
  6fb9a6:	74 30                	je     0x6fb9d8
  6fb9a8:	8b 05 12 fa af 01    	mov    eax,DWORD PTR [rip+0x1affa12]        # 0x21fb3c0
  6fb9ae:	83 f8 02             	cmp    eax,0x2
  6fb9b1:	74 25                	je     0x6fb9d8
  6fb9b3:	8b 05 07 fa af 01    	mov    eax,DWORD PTR [rip+0x1affa07]        # 0x21fb3c0
  6fb9b9:	83 f8 03             	cmp    eax,0x3
  6fb9bc:	74 1a                	je     0x6fb9d8
  6fb9be:	8b 05 fc f9 af 01    	mov    eax,DWORD PTR [rip+0x1aff9fc]        # 0x21fb3c0
  6fb9c4:	83 f8 05             	cmp    eax,0x5
  6fb9c7:	74 0f                	je     0x6fb9d8
  6fb9c9:	8b 05 f1 f9 af 01    	mov    eax,DWORD PTR [rip+0x1aff9f1]        # 0x21fb3c0
  6fb9cf:	83 f8 04             	cmp    eax,0x4
  6fb9d2:	0f 85 a1 01 00 00    	jne    0x6fbb79
  6fb9d8:	83 3d e5 f9 af 01 00 	cmp    DWORD PTR [rip+0x1aff9e5],0x0        # 0x21fb3c4
  6fb9df:	74 0b                	je     0x6fb9ec
  6fb9e1:	8b 05 dd f9 af 01    	mov    eax,DWORD PTR [rip+0x1aff9dd]        # 0x21fb3c4
  6fb9e7:	83 f8 01             	cmp    eax,0x1
  6fb9ea:	75 60                	jne    0x6fba4c
  6fb9ec:	83 3d d5 f9 af 01 00 	cmp    DWORD PTR [rip+0x1aff9d5],0x0        # 0x21fb3c8
  6fb9f3:	74 0f                	je     0x6fba04
  6fb9f5:	8b 05 cd f9 af 01    	mov    eax,DWORD PTR [rip+0x1aff9cd]        # 0x21fb3c8
  6fb9fb:	83 f8 01             	cmp    eax,0x1
  6fb9fe:	0f 85 81 00 00 00    	jne    0x6fba85
  6fba04:	83 3d c5 f9 af 01 00 	cmp    DWORD PTR [rip+0x1aff9c5],0x0        # 0x21fb3d0
  6fba0b:	74 0f                	je     0x6fba1c
  6fba0d:	8b 05 bd f9 af 01    	mov    eax,DWORD PTR [rip+0x1aff9bd]        # 0x21fb3d0
  6fba13:	83 f8 01             	cmp    eax,0x1
  6fba16:	0f 85 9f 00 00 00    	jne    0x6fbabb
  6fba1c:	83 3d b1 f9 af 01 00 	cmp    DWORD PTR [rip+0x1aff9b1],0x0        # 0x21fb3d4
  6fba23:	74 0f                	je     0x6fba34
  6fba25:	8b 05 a9 f9 af 01    	mov    eax,DWORD PTR [rip+0x1aff9a9]        # 0x21fb3d4
  6fba2b:	83 f8 01             	cmp    eax,0x1
  6fba2e:	0f 85 bd 00 00 00    	jne    0x6fbaf1
  6fba34:	83 3d 95 f9 af 01 00 	cmp    DWORD PTR [rip+0x1aff995],0x0        # 0x21fb3d0
  6fba3b:	75 0d                	jne    0x6fba4a
  6fba3d:	83 3d 90 f9 af 01 00 	cmp    DWORD PTR [rip+0x1aff990],0x0        # 0x21fb3d4
  6fba44:	0f 85 e4 00 00 00    	jne    0x6fbb2e
  6fba4a:	5d                   	pop    rbp
  6fba4b:	c3                   	ret
  6fba4c:	e8 ff 5e 0f 00       	call   0x7f1950
  6fba51:	48 63 15 6c f9 af 01 	movsxd rdx,DWORD PTR [rip+0x1aff96c]        # 0x21fb3c4
  6fba58:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fba4c
  6fba5f:	be 6f 07 00 00       	mov    esi,0x76f
  6fba64:	e8 a7 65 0f 00       	call   0x7f2010
  6fba69:	8b 0d 55 f9 af 01    	mov    ecx,DWORD PTR [rip+0x1aff955]        # 0x21fb3c4
  6fba6f:	48 8d 35 9f b1 bb 00 	lea    rsi,[rip+0xbbb19f]        # 0x12b6c15
  6fba76:	bf 4f 00 00 00       	mov    edi,0x4f
  6fba7b:	ba 6f 07 00 00       	mov    edx,0x76f
  6fba80:	e9 a0 00 00 00       	jmp    0x6fbb25
  6fba85:	e8 c6 5e 0f 00       	call   0x7f1950
  6fba8a:	48 63 15 37 f9 af 01 	movsxd rdx,DWORD PTR [rip+0x1aff937]        # 0x21fb3c8
  6fba91:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fba85
  6fba98:	be 73 07 00 00       	mov    esi,0x773
  6fba9d:	e8 6e 65 0f 00       	call   0x7f2010
  6fbaa2:	8b 0d 20 f9 af 01    	mov    ecx,DWORD PTR [rip+0x1aff920]        # 0x21fb3c8
  6fbaa8:	48 8d 35 a7 e2 b7 00 	lea    rsi,[rip+0xb7e2a7]        # 0x1279d56
  6fbaaf:	bf 53 00 00 00       	mov    edi,0x53
  6fbab4:	ba 73 07 00 00       	mov    edx,0x773
  6fbab9:	eb 6a                	jmp    0x6fbb25
  6fbabb:	e8 90 5e 0f 00       	call   0x7f1950
  6fbac0:	48 63 15 09 f9 af 01 	movsxd rdx,DWORD PTR [rip+0x1aff909]        # 0x21fb3d0
  6fbac7:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fbabb
  6fbace:	be 77 07 00 00       	mov    esi,0x777
  6fbad3:	e8 38 65 0f 00       	call   0x7f2010
  6fbad8:	8b 0d f2 f8 af 01    	mov    ecx,DWORD PTR [rip+0x1aff8f2]        # 0x21fb3d0
  6fbade:	48 8d 35 ac 13 ca 00 	lea    rsi,[rip+0xca13ac]        # 0x139ce91
  6fbae5:	bf 57 00 00 00       	mov    edi,0x57
  6fbaea:	ba 77 07 00 00       	mov    edx,0x777
  6fbaef:	eb 34                	jmp    0x6fbb25
  6fbaf1:	e8 5a 5e 0f 00       	call   0x7f1950
  6fbaf6:	48 63 15 d7 f8 af 01 	movsxd rdx,DWORD PTR [rip+0x1aff8d7]        # 0x21fb3d4
  6fbafd:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fbaf1
  6fbb04:	be 7b 07 00 00       	mov    esi,0x77b
  6fbb09:	e8 02 65 0f 00       	call   0x7f2010
  6fbb0e:	8b 0d c0 f8 af 01    	mov    ecx,DWORD PTR [rip+0x1aff8c0]        # 0x21fb3d4
  6fbb14:	48 8d 35 bd 83 c3 00 	lea    rsi,[rip+0xc383bd]        # 0x1333ed8
  6fbb1b:	bf 5b 00 00 00       	mov    edi,0x5b
  6fbb20:	ba 7b 07 00 00       	mov    edx,0x77b
  6fbb25:	31 c0                	xor    eax,eax
  6fbb27:	e8 e4 ee 59 00       	call   0xc9aa10
  6fbb2c:	0f 0b                	ud2
  6fbb2e:	e8 1d 5e 0f 00       	call   0x7f1950
  6fbb33:	48 63 15 96 f8 af 01 	movsxd rdx,DWORD PTR [rip+0x1aff896]        # 0x21fb3d0
  6fbb3a:	48 63 0d 93 f8 af 01 	movsxd rcx,DWORD PTR [rip+0x1aff893]        # 0x21fb3d4
  6fbb41:	48 8d 3d e6 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe6]        # 0x6fbb2e
  6fbb48:	be 7e 07 00 00       	mov    esi,0x77e
  6fbb4d:	e8 6e 65 0f 00       	call   0x7f20c0
  6fbb52:	8b 0d 78 f8 af 01    	mov    ecx,DWORD PTR [rip+0x1aff878]        # 0x21fb3d0
  6fbb58:	44 8b 05 75 f8 af 01 	mov    r8d,DWORD PTR [rip+0x1aff875]        # 0x21fb3d4
  6fbb5f:	48 8d 35 84 f0 be 00 	lea    rsi,[rip+0xbef084]        # 0x12eabea
  6fbb66:	bf 5f 00 00 00       	mov    edi,0x5f
  6fbb6b:	ba 7e 07 00 00       	mov    edx,0x77e
  6fbb70:	31 c0                	xor    eax,eax
  6fbb72:	e8 99 ee 59 00       	call   0xc9aa10
  6fbb77:	0f 0b                	ud2
  6fbb79:	e8 d2 5d 0f 00       	call   0x7f1950
  6fbb7e:	48 63 15 3b f8 af 01 	movsxd rdx,DWORD PTR [rip+0x1aff83b]        # 0x21fb3c0
  6fbb85:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x6fbb79
  6fbb8c:	be 6b 07 00 00       	mov    esi,0x76b
  6fbb91:	e8 7a 64 0f 00       	call   0x7f2010
  6fbb96:	8b 0d 24 f8 af 01    	mov    ecx,DWORD PTR [rip+0x1aff824]        # 0x21fb3c0
  6fbb9c:	48 8d 35 78 2d c6 00 	lea    rsi,[rip+0xc62d78]        # 0x135e91b
  6fbba3:	bf 4b 00 00 00       	mov    edi,0x4b
  6fbba8:	ba 6b 07 00 00       	mov    edx,0x76b
  6fbbad:	e9 73 ff ff ff       	jmp    0x6fbb25
  6fbbb2:	90                   	nop
  6fbbb3:	90                   	nop
  6fbbb4:	90                   	nop
  6fbbb5:	90                   	nop
  6fbbb6:	90                   	nop
  6fbbb7:	90                   	nop
  6fbbb8:	90                   	nop
  6fbbb9:	90                   	nop
  6fbbba:	90                   	nop
  6fbbbb:	90                   	nop
  6fbbbc:	90                   	nop
  6fbbbd:	90                   	nop
  6fbbbe:	90                   	nop
  6fbbbf:	90                   	nop
  6fbbc0:	55                   	push   rbp
  6fbbc1:	48 89 e5             	mov    rbp,rsp
  6fbbc4:	41 57                	push   r15
  6fbbc6:	41 56                	push   r14
  6fbbc8:	53                   	push   rbx
  6fbbc9:	48 83 ec 18          	sub    rsp,0x18
  6fbbcd:	4c 8d 3d 3c 07 22 03 	lea    r15,[rip+0x322073c]        # 0x391c310
  6fbbd4:	48 89 cb             	mov    rbx,rcx
  6fbbd7:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6fbbda:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  6fbbde:	e8 3d bd 40 00       	call   0xb07920
  6fbbe3:	41 be 01 00 00 00    	mov    r14d,0x1
  6fbbe9:	85 c0                	test   eax,eax
  6fbbeb:	74 3e                	je     0x6fbc2b
  6fbbed:	e8 1e 12 3d 00       	call   0xacce10
  6fbbf2:	85 c0                	test   eax,eax
  6fbbf4:	74 35                	je     0x6fbc2b
  6fbbf6:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  6fbbfa:	48 8d 05 37 d7 b6 ff 	lea    rax,[rip+0xffffffffffb6d737]        # 0x269338
  6fbc01:	4c 29 f0             	sub    rax,r14
  6fbc04:	48 c1 c8 03          	ror    rax,0x3
  6fbc08:	48 83 f8 03          	cmp    rax,0x3
  6fbc0c:	0f 87 0c 01 00 00    	ja     0x6fbd1e
  6fbc12:	48 8d 35 ef f7 af 01 	lea    rsi,[rip+0x1aff7ef]        # 0x21fb408
  6fbc19:	ba 04 00 00 00       	mov    edx,0x4
  6fbc1e:	48 89 df             	mov    rdi,rbx
  6fbc21:	41 ff d6             	call   r14
  6fbc24:	85 c0                	test   eax,eax
  6fbc26:	74 1e                	je     0x6fbc46
  6fbc28:	41 89 c6             	mov    r14d,eax
  6fbc2b:	49 8b 07             	mov    rax,QWORD PTR [r15]
  6fbc2e:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  6fbc32:	0f 85 df 00 00 00    	jne    0x6fbd17
  6fbc38:	44 89 f0             	mov    eax,r14d
  6fbc3b:	48 83 c4 18          	add    rsp,0x18
  6fbc3f:	5b                   	pop    rbx
  6fbc40:	41 5e                	pop    r14
  6fbc42:	41 5f                	pop    r15
  6fbc44:	5d                   	pop    rbp
  6fbc45:	c3                   	ret
  6fbc46:	45 31 f6             	xor    r14d,r14d
  6fbc49:	48 83 7b 30 00       	cmp    QWORD PTR [rbx+0x30],0x0
  6fbc4e:	74 db                	je     0x6fbc2b
  6fbc50:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6fbc57:	00 00 
  6fbc59:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  6fbc60:	e8 2b d3 f0 ff       	call   0x608f90
  6fbc65:	85 c0                	test   eax,eax
  6fbc67:	0f 84 80 00 00 00    	je     0x6fbced
  6fbc6d:	bf e9 00 00 00       	mov    edi,0xe9
  6fbc72:	e8 29 0d 3d 00       	call   0xacc9a0
  6fbc77:	85 c0                	test   eax,eax
  6fbc79:	75 b0                	jne    0x6fbc2b
  6fbc7b:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
  6fbc82:	48 8d 05 77 e2 b6 ff 	lea    rax,[rip+0xffffffffffb6e277]        # 0x269f00
  6fbc89:	4c 8b 73 48          	mov    r14,QWORD PTR [rbx+0x48]
  6fbc8d:	4c 29 f0             	sub    rax,r14
  6fbc90:	48 c1 c8 03          	ror    rax,0x3
  6fbc94:	48 83 f8 16          	cmp    rax,0x16
  6fbc98:	0f 87 94 00 00 00    	ja     0x6fbd32
  6fbc9e:	48 8d 75 dc          	lea    rsi,[rbp-0x24]
  6fbca2:	ba 04 00 00 00       	mov    edx,0x4
  6fbca7:	48 89 df             	mov    rdi,rbx
  6fbcaa:	41 ff d6             	call   r14
  6fbcad:	85 c0                	test   eax,eax
  6fbcaf:	0f 85 73 ff ff ff    	jne    0x6fbc28
  6fbcb5:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
  6fbcb9:	74 07                	je     0x6fbcc2
  6fbcbb:	c7 45 dc 01 00 00 00 	mov    DWORD PTR [rbp-0x24],0x1
  6fbcc2:	48 8d 3d 1f 06 22 03 	lea    rdi,[rip+0x322061f]        # 0x391c2e8
  6fbcc9:	45 31 f6             	xor    r14d,r14d
  6fbccc:	31 f6                	xor    esi,esi
  6fbcce:	31 d2                	xor    edx,edx
  6fbcd0:	31 c9                	xor    ecx,ecx
  6fbcd2:	e8 29 ad dc ff       	call   0x4c6a00
  6fbcd7:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
  6fbcda:	3b 05 28 f7 af 01    	cmp    eax,DWORD PTR [rip+0x1aff728]        # 0x21fb408
  6fbce0:	74 1e                	je     0x6fbd00
  6fbce2:	85 c0                	test   eax,eax
  6fbce4:	74 12                	je     0x6fbcf8
  6fbce6:	e8 25 fa ff ff       	call   0x6fb710
  6fbceb:	eb 10                	jmp    0x6fbcfd
  6fbced:	41 be 4e 00 00 00    	mov    r14d,0x4e
  6fbcf3:	e9 33 ff ff ff       	jmp    0x6fbc2b
  6fbcf8:	e8 53 00 00 00       	call   0x6fbd50
  6fbcfd:	41 89 c6             	mov    r14d,eax
  6fbd00:	48 8d 3d e1 05 22 03 	lea    rdi,[rip+0x32205e1]        # 0x391c2e8
  6fbd07:	31 f6                	xor    esi,esi
  6fbd09:	31 d2                	xor    edx,edx
  6fbd0b:	31 c9                	xor    ecx,ecx
  6fbd0d:	e8 8e b2 dc ff       	call   0x4c6fa0
  6fbd12:	e9 14 ff ff ff       	jmp    0x6fbc2b
  6fbd17:	e8 94 19 00 00       	call   0x6fd6b0
  6fbd1c:	0f 0b                	ud2
  6fbd1e:	48 8d 3d 6b f8 af 01 	lea    rdi,[rip+0x1aff86b]        # 0x21fb590
  6fbd25:	4c 89 f6             	mov    rsi,r14
  6fbd28:	e8 93 3b d5 ff       	call   0x44f8c0
  6fbd2d:	e9 e0 fe ff ff       	jmp    0x6fbc12
  6fbd32:	48 8d 3d 77 f8 af 01 	lea    rdi,[rip+0x1aff877]        # 0x21fb5b0
  6fbd39:	4c 89 f6             	mov    rsi,r14
  6fbd3c:	e8 7f 3b d5 ff       	call   0x44f8c0
  6fbd41:	e9 58 ff ff ff       	jmp    0x6fbc9e
  6fbd46:	90                   	nop
  6fbd47:	90                   	nop
  6fbd48:	90                   	nop
  6fbd49:	90                   	nop
  6fbd4a:	90                   	nop
  6fbd4b:	90                   	nop
  6fbd4c:	90                   	nop
  6fbd4d:	90                   	nop
  6fbd4e:	90                   	nop
  6fbd4f:	90                   	nop
  6fbd50:	55                   	push   rbp
  6fbd51:	48 89 e5             	mov    rbp,rsp
  6fbd54:	41 56                	push   r14
  6fbd56:	53                   	push   rbx
  6fbd57:	48 83 ec 10          	sub    rsp,0x10
  6fbd5b:	83 3d a6 f6 af 01 00 	cmp    DWORD PTR [rip+0x1aff6a6],0x0        # 0x21fb408
  6fbd62:	bb 10 00 00 00       	mov    ebx,0x10
  6fbd67:	0f 84 9c 00 00 00    	je     0x6fbe09
  6fbd6d:	48 83 3d 53 05 22 03 	cmp    QWORD PTR [rip+0x3220553],0x0        # 0x391c2c8
  6fbd74:	00 
  6fbd75:	0f 84 8e 00 00 00    	je     0x6fbe09
  6fbd7b:	48 8d 3d 6e 05 22 03 	lea    rdi,[rip+0x322056e]        # 0x391c2f0
  6fbd82:	48 8d 35 47 05 22 03 	lea    rsi,[rip+0x3220547]        # 0x391c2d0
  6fbd89:	48 8d 0d 8a 7e c5 00 	lea    rcx,[rip+0xc57e8a]        # 0x1353c1a
  6fbd90:	c7 05 56 05 22 03 01 	mov    DWORD PTR [rip+0x3220556],0x1        # 0x391c2f0
  6fbd97:	00 00 00 
  6fbd9a:	c7 04 24 00 01 00 00 	mov    DWORD PTR [rsp],0x100
  6fbda1:	31 db                	xor    ebx,ebx
  6fbda3:	31 d2                	xor    edx,edx
  6fbda5:	45 31 c0             	xor    r8d,r8d
  6fbda8:	45 31 c9             	xor    r9d,r9d
  6fbdab:	e8 b0 a4 50 00       	call   0xc06260
  6fbdb0:	48 8d 3d 67 0b bb 00 	lea    rdi,[rip+0xbb0b67]        # 0x12ac91e
  6fbdb7:	31 c0                	xor    eax,eax
  6fbdb9:	c7 05 45 f6 af 01 00 	mov    DWORD PTR [rip+0x1aff645],0x0        # 0x21fb408
  6fbdc0:	00 00 00 
  6fbdc3:	e8 48 16 b6 ff       	call   0x25d410
  6fbdc8:	31 ff                	xor    edi,edi
  6fbdca:	48 c7 05 f3 04 22 03 	mov    QWORD PTR [rip+0x32204f3],0x0        # 0x391c2c8
  6fbdd1:	00 00 00 00 
  6fbdd5:	e8 46 c2 fb ff       	call   0x6b8020
  6fbdda:	4c 8d 35 07 05 22 03 	lea    r14,[rip+0x3220507]        # 0x391c2e8
  6fbde1:	31 f6                	xor    esi,esi
  6fbde3:	31 d2                	xor    edx,edx
  6fbde5:	31 c9                	xor    ecx,ecx
  6fbde7:	4c 89 f7             	mov    rdi,r14
  6fbdea:	e8 b1 b1 dc ff       	call   0x4c6fa0
  6fbdef:	48 8d 3d 02 05 22 03 	lea    rdi,[rip+0x3220502]        # 0x391c2f8
  6fbdf6:	e8 b5 af e5 ff       	call   0x556db0
  6fbdfb:	4c 89 f7             	mov    rdi,r14
  6fbdfe:	31 f6                	xor    esi,esi
  6fbe00:	31 d2                	xor    edx,edx
  6fbe02:	31 c9                	xor    ecx,ecx
  6fbe04:	e8 f7 ab dc ff       	call   0x4c6a00
  6fbe09:	89 d8                	mov    eax,ebx
  6fbe0b:	48 83 c4 10          	add    rsp,0x10
  6fbe0f:	5b                   	pop    rbx
  6fbe10:	41 5e                	pop    r14
  6fbe12:	5d                   	pop    rbp
  6fbe13:	c3                   	ret
  6fbe14:	90                   	nop
  6fbe15:	90                   	nop
  6fbe16:	90                   	nop
  6fbe17:	90                   	nop
  6fbe18:	90                   	nop
  6fbe19:	90                   	nop
  6fbe1a:	90                   	nop
  6fbe1b:	90                   	nop
  6fbe1c:	90                   	nop
  6fbe1d:	90                   	nop
  6fbe1e:	90                   	nop
  6fbe1f:	90                   	nop
  6fbe20:	55                   	push   rbp
  6fbe21:	48 89 e5             	mov    rbp,rsp
  6fbe24:	41 57                	push   r15
  6fbe26:	41 56                	push   r14
  6fbe28:	53                   	push   rbx
  6fbe29:	50                   	push   rax
  6fbe2a:	48 8b 4f 10          	mov    rcx,QWORD PTR [rdi+0x10]
  6fbe2e:	b8 16 00 00 00       	mov    eax,0x16
  6fbe33:	8b 51 04             	mov    edx,DWORD PTR [rcx+0x4]
  6fbe36:	3b 51 08             	cmp    edx,DWORD PTR [rcx+0x8]
  6fbe39:	0f 85 af 00 00 00    	jne    0x6fbeee
  6fbe3f:	48 8d 35 ca f9 4f 02 	lea    rsi,[rip+0x24ff9ca]        # 0x2bfb810
  6fbe46:	48 89 fb             	mov    rbx,rdi
  6fbe49:	bf 80 00 00 00       	mov    edi,0x80
  6fbe4e:	ba 01 01 00 00       	mov    edx,0x101
  6fbe53:	e8 f8 cc 50 00       	call   0xc08b50
  6fbe58:	48 85 c0             	test   rax,rax
  6fbe5b:	0f 84 84 00 00 00    	je     0x6fbee5
  6fbe61:	49 89 c6             	mov    r14,rax
  6fbe64:	48 ba 80 bb 00 00 80 	movabs rdx,0xbb800000bb80
  6fbe6b:	bb 00 00 
  6fbe6e:	b9 14 05 00 00       	mov    ecx,0x514
  6fbe73:	48 89 df             	mov    rdi,rbx
  6fbe76:	49 89 16             	mov    QWORD PTR [r14],rdx
  6fbe79:	41 c7 46 18 01 00 00 	mov    DWORD PTR [r14+0x18],0x1
  6fbe80:	00 
  6fbe81:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  6fbe85:	c4 e2 70 f7 40 04    	bextr  eax,DWORD PTR [rax+0x4],ecx
  6fbe8b:	41 89 46 10          	mov    DWORD PTR [r14+0x10],eax
  6fbe8f:	4c 89 73 30          	mov    QWORD PTR [rbx+0x30],r14
  6fbe93:	e8 28 06 00 00       	call   0x6fc4c0
  6fbe98:	85 c0                	test   eax,eax
  6fbe9a:	74 50                	je     0x6fbeec
  6fbe9c:	49 8b 7e 40          	mov    rdi,QWORD PTR [r14+0x40]
  6fbea0:	41 89 c7             	mov    r15d,eax
  6fbea3:	48 85 ff             	test   rdi,rdi
  6fbea6:	74 0c                	je     0x6fbeb4
  6fbea8:	48 8d 35 61 f9 4f 02 	lea    rsi,[rip+0x24ff961]        # 0x2bfb810
  6fbeaf:	e8 3c cf 50 00       	call   0xc08df0
  6fbeb4:	49 8b 7e 28          	mov    rdi,QWORD PTR [r14+0x28]
  6fbeb8:	48 85 ff             	test   rdi,rdi
  6fbebb:	74 0c                	je     0x6fbec9
  6fbebd:	48 8d 35 4c f9 4f 02 	lea    rsi,[rip+0x24ff94c]        # 0x2bfb810
  6fbec4:	e8 27 cf 50 00       	call   0xc08df0
  6fbec9:	48 8d 35 40 f9 4f 02 	lea    rsi,[rip+0x24ff940]        # 0x2bfb810
  6fbed0:	4c 89 f7             	mov    rdi,r14
  6fbed3:	e8 18 cf 50 00       	call   0xc08df0
  6fbed8:	44 89 f8             	mov    eax,r15d
  6fbedb:	48 c7 43 30 00 00 00 	mov    QWORD PTR [rbx+0x30],0x0
  6fbee2:	00 
  6fbee3:	eb 09                	jmp    0x6fbeee
  6fbee5:	b8 0c 00 00 00       	mov    eax,0xc
  6fbeea:	eb 02                	jmp    0x6fbeee
  6fbeec:	31 c0                	xor    eax,eax
  6fbeee:	48 83 c4 08          	add    rsp,0x8
  6fbef2:	5b                   	pop    rbx
  6fbef3:	41 5e                	pop    r14
  6fbef5:	41 5f                	pop    r15
  6fbef7:	5d                   	pop    rbp
  6fbef8:	c3                   	ret
  6fbef9:	90                   	nop
  6fbefa:	90                   	nop
  6fbefb:	90                   	nop
  6fbefc:	90                   	nop
  6fbefd:	90                   	nop
  6fbefe:	90                   	nop
  6fbeff:	90                   	nop
  6fbf00:	55                   	push   rbp
  6fbf01:	48 89 e5             	mov    rbp,rsp
  6fbf04:	41 56                	push   r14
  6fbf06:	53                   	push   rbx
  6fbf07:	4c 8b 77 30          	mov    r14,QWORD PTR [rdi+0x30]
  6fbf0b:	48 89 fb             	mov    rbx,rdi
  6fbf0e:	4d 85 f6             	test   r14,r14
  6fbf11:	74 39                	je     0x6fbf4c
  6fbf13:	49 8b 7e 40          	mov    rdi,QWORD PTR [r14+0x40]
  6fbf17:	48 85 ff             	test   rdi,rdi
  6fbf1a:	74 0c                	je     0x6fbf28
  6fbf1c:	48 8d 35 ed f8 4f 02 	lea    rsi,[rip+0x24ff8ed]        # 0x2bfb810
  6fbf23:	e8 c8 ce 50 00       	call   0xc08df0
  6fbf28:	49 8b 7e 28          	mov    rdi,QWORD PTR [r14+0x28]
  6fbf2c:	48 85 ff             	test   rdi,rdi
  6fbf2f:	74 0c                	je     0x6fbf3d
  6fbf31:	48 8d 35 d8 f8 4f 02 	lea    rsi,[rip+0x24ff8d8]        # 0x2bfb810
  6fbf38:	e8 b3 ce 50 00       	call   0xc08df0
  6fbf3d:	48 8d 35 cc f8 4f 02 	lea    rsi,[rip+0x24ff8cc]        # 0x2bfb810
  6fbf44:	4c 89 f7             	mov    rdi,r14
  6fbf47:	e8 a4 ce 50 00       	call   0xc08df0
  6fbf4c:	48 c7 43 30 00 00 00 	mov    QWORD PTR [rbx+0x30],0x0
  6fbf53:	00 
  6fbf54:	31 c0                	xor    eax,eax
  6fbf56:	5b                   	pop    rbx
  6fbf57:	41 5e                	pop    r14
  6fbf59:	5d                   	pop    rbp
  6fbf5a:	c3                   	ret
  6fbf5b:	90                   	nop
  6fbf5c:	90                   	nop
  6fbf5d:	90                   	nop
  6fbf5e:	90                   	nop
  6fbf5f:	90                   	nop
  6fbf60:	55                   	push   rbp
  6fbf61:	48 89 e5             	mov    rbp,rsp
  6fbf64:	41 57                	push   r15
  6fbf66:	41 56                	push   r14
  6fbf68:	53                   	push   rbx
  6fbf69:	50                   	push   rax
  6fbf6a:	b8 16 00 00 00       	mov    eax,0x16
  6fbf6f:	83 fe 03             	cmp    esi,0x3
  6fbf72:	0f 87 93 00 00 00    	ja     0x6fc00b
  6fbf78:	89 f1                	mov    ecx,esi
  6fbf7a:	4c 8d 05 b3 01 03 01 	lea    r8,[rip+0x10301b3]        # 0x172c134
  6fbf81:	4c 8b 77 30          	mov    r14,QWORD PTR [rdi+0x30]
  6fbf85:	49 63 0c 88          	movsxd rcx,DWORD PTR [r8+rcx*4]
  6fbf89:	4c 01 c1             	add    rcx,r8
  6fbf8c:	ff e1                	jmp    rcx
  6fbf8e:	b8 07 00 00 00       	mov    eax,0x7
  6fbf93:	3b 15 4f f6 af 01    	cmp    edx,DWORD PTR [rip+0x1aff64f]        # 0x21fb5e8
  6fbf99:	7c 70                	jl     0x6fc00b
  6fbf9b:	3b 15 4b f6 af 01    	cmp    edx,DWORD PTR [rip+0x1aff64b]        # 0x21fb5ec
  6fbfa1:	7f 68                	jg     0x6fc00b
  6fbfa3:	41 3b 16             	cmp    edx,DWORD PTR [r14]
  6fbfa6:	74 61                	je     0x6fc009
  6fbfa8:	41 89 16             	mov    DWORD PTR [r14],edx
  6fbfab:	eb 6d                	jmp    0x6fc01a
  6fbfad:	83 fa 04             	cmp    edx,0x4
  6fbfb0:	77 59                	ja     0x6fc00b
  6fbfb2:	45 8b 7e 18          	mov    r15d,DWORD PTR [r14+0x18]
  6fbfb6:	31 c0                	xor    eax,eax
  6fbfb8:	44 39 fa             	cmp    edx,r15d
  6fbfbb:	74 4e                	je     0x6fc00b
  6fbfbd:	41 89 56 18          	mov    DWORD PTR [r14+0x18],edx
  6fbfc1:	48 89 fb             	mov    rbx,rdi
  6fbfc4:	e8 f7 04 00 00       	call   0x6fc4c0
  6fbfc9:	89 c1                	mov    ecx,eax
  6fbfcb:	31 c0                	xor    eax,eax
  6fbfcd:	85 c9                	test   ecx,ecx
  6fbfcf:	74 3a                	je     0x6fc00b
  6fbfd1:	48 89 df             	mov    rdi,rbx
  6fbfd4:	45 89 7e 18          	mov    DWORD PTR [r14+0x18],r15d
  6fbfd8:	eb 40                	jmp    0x6fc01a
  6fbfda:	8d 4a f7             	lea    ecx,[rdx-0x9]
  6fbfdd:	83 f9 f8             	cmp    ecx,0xfffffff8
  6fbfe0:	72 29                	jb     0x6fc00b
  6fbfe2:	41 3b 56 10          	cmp    edx,DWORD PTR [r14+0x10]
  6fbfe6:	74 21                	je     0x6fc009
  6fbfe8:	41 89 56 10          	mov    DWORD PTR [r14+0x10],edx
  6fbfec:	eb 2c                	jmp    0x6fc01a
  6fbfee:	b8 07 00 00 00       	mov    eax,0x7
  6fbff3:	3b 15 ef f5 af 01    	cmp    edx,DWORD PTR [rip+0x1aff5ef]        # 0x21fb5e8
  6fbff9:	7c 10                	jl     0x6fc00b
  6fbffb:	3b 15 eb f5 af 01    	cmp    edx,DWORD PTR [rip+0x1aff5eb]        # 0x21fb5ec
  6fc001:	7f 08                	jg     0x6fc00b
  6fc003:	41 3b 56 04          	cmp    edx,DWORD PTR [r14+0x4]
  6fc007:	75 0d                	jne    0x6fc016
  6fc009:	31 c0                	xor    eax,eax
  6fc00b:	48 83 c4 08          	add    rsp,0x8
  6fc00f:	5b                   	pop    rbx
  6fc010:	41 5e                	pop    r14
  6fc012:	41 5f                	pop    r15
  6fc014:	5d                   	pop    rbp
  6fc015:	c3                   	ret
  6fc016:	41 89 56 04          	mov    DWORD PTR [r14+0x4],edx
  6fc01a:	48 83 c4 08          	add    rsp,0x8
  6fc01e:	5b                   	pop    rbx
  6fc01f:	41 5e                	pop    r14
  6fc021:	41 5f                	pop    r15
  6fc023:	5d                   	pop    rbp
  6fc024:	e9 97 04 00 00       	jmp    0x6fc4c0
  6fc029:	90                   	nop
  6fc02a:	90                   	nop
  6fc02b:	90                   	nop
  6fc02c:	90                   	nop
  6fc02d:	90                   	nop
  6fc02e:	90                   	nop
  6fc02f:	90                   	nop
  6fc030:	83 fe 03             	cmp    esi,0x3
  6fc033:	77 2d                	ja     0x6fc062
  6fc035:	55                   	push   rbp
  6fc036:	48 89 e5             	mov    rbp,rsp
  6fc039:	89 f1                	mov    ecx,esi
  6fc03b:	48 8d 15 02 01 03 01 	lea    rdx,[rip+0x1030102]        # 0x172c144
  6fc042:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
  6fc046:	48 63 0c 8a          	movsxd rcx,DWORD PTR [rdx+rcx*4]
  6fc04a:	48 01 d1             	add    rcx,rdx
  6fc04d:	ff e1                	jmp    rcx
  6fc04f:	8b 00                	mov    eax,DWORD PTR [rax]
  6fc051:	5d                   	pop    rbp
  6fc052:	c3                   	ret
  6fc053:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
  6fc056:	5d                   	pop    rbp
  6fc057:	c3                   	ret
  6fc058:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  6fc05b:	5d                   	pop    rbp
  6fc05c:	c3                   	ret
  6fc05d:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
  6fc060:	5d                   	pop    rbp
  6fc061:	c3                   	ret
  6fc062:	b8 ff ff ff ff       	mov    eax,0xffffffff
  6fc067:	c3                   	ret
  6fc068:	90                   	nop
  6fc069:	90                   	nop
  6fc06a:	90                   	nop
  6fc06b:	90                   	nop
  6fc06c:	90                   	nop
  6fc06d:	90                   	nop
  6fc06e:	90                   	nop
  6fc06f:	90                   	nop
  6fc070:	55                   	push   rbp
  6fc071:	48 89 e5             	mov    rbp,rsp
  6fc074:	41 57                	push   r15
  6fc076:	41 56                	push   r14
  6fc078:	41 55                	push   r13
  6fc07a:	41 54                	push   r12
  6fc07c:	53                   	push   rbx
  6fc07d:	48 83 ec 78          	sub    rsp,0x78
  6fc081:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
  6fc085:	4c 8d 35 34 69 e2 01 	lea    r14,[rip+0x1e26934]        # 0x25229c0
  6fc08c:	4c 89 45 88          	mov    QWORD PTR [rbp-0x78],r8
  6fc090:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  6fc094:	48 89 75 90          	mov    QWORD PTR [rbp-0x70],rsi
  6fc098:	89 4d b4             	mov    DWORD PTR [rbp-0x4c],ecx
  6fc09b:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  6fc09f:	8b 40 74             	mov    eax,DWORD PTR [rax+0x74]
  6fc0a2:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
  6fc0a5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fc0ac:	00 00 00 00 
  6fc0b0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
  6fc0b3:	4c 8b 7f 30          	mov    r15,QWORD PTR [rdi+0x30]
  6fc0b7:	41 89 cc             	mov    r12d,ecx
  6fc0ba:	89 4d ac             	mov    DWORD PTR [rbp-0x54],ecx
  6fc0bd:	39 c8                	cmp    eax,ecx
  6fc0bf:	44 0f 42 e0          	cmovb  r12d,eax
  6fc0c3:	49 83 7f 78 00       	cmp    QWORD PTR [r15+0x78],0x0
  6fc0c8:	74 76                	je     0x6fc140
  6fc0ca:	41 8b 47 14          	mov    eax,DWORD PTR [r15+0x14]
  6fc0ce:	41 0f af 47 10       	imul   eax,DWORD PTR [r15+0x10]
  6fc0d3:	48 63 d0             	movsxd rdx,eax
  6fc0d6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
  6fc0d9:	48 8d 05 80 00 03 01 	lea    rax,[rip+0x1030080]        # 0x172c160
  6fc0e0:	8b 34 d0             	mov    esi,DWORD PTR [rax+rdx*8]
  6fc0e3:	8b 44 d0 04          	mov    eax,DWORD PTR [rax+rdx*8+0x4]
  6fc0e7:	48 89 95 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rdx
  6fc0ee:	44 0f af e6          	imul   r12d,esi
  6fc0f2:	89 75 a4             	mov    DWORD PTR [rbp-0x5c],esi
  6fc0f5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
  6fc0f8:	c4 c2 7b f7 f4       	shrx   esi,r12d,eax
  6fc0fd:	85 f6                	test   esi,esi
  6fc0ff:	0f 84 a3 03 00 00    	je     0x6fc4a8
  6fc105:	49 63 47 1c          	movsxd rax,DWORD PTR [r15+0x1c]
  6fc109:	48 63 d6             	movsxd rdx,esi
  6fc10c:	49 63 4f 20          	movsxd rcx,DWORD PTR [r15+0x20]
  6fc110:	48 0f af d0          	imul   rdx,rax
  6fc114:	41 8b 47 24          	mov    eax,DWORD PTR [r15+0x24]
  6fc118:	f7 d0                	not    eax
  6fc11a:	01 c8                	add    eax,ecx
  6fc11c:	48 98                	cdqe
  6fc11e:	48 01 d0             	add    rax,rdx
  6fc121:	48 89 c2             	mov    rdx,rax
  6fc124:	48 09 ca             	or     rdx,rcx
  6fc127:	48 c1 ea 20          	shr    rdx,0x20
  6fc12b:	74 73                	je     0x6fc1a0
  6fc12d:	31 d2                	xor    edx,edx
  6fc12f:	48 f7 f1             	div    rcx
  6fc132:	eb 70                	jmp    0x6fc1a4
  6fc134:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fc13b:	00 00 00 00 00 
  6fc140:	48 8b 5f 40          	mov    rbx,QWORD PTR [rdi+0x40]
  6fc144:	41 0f b6 16          	movzx  edx,BYTE PTR [r14]
  6fc148:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
  6fc14b:	48 8b 04 d1          	mov    rax,QWORD PTR [rcx+rdx*8]
  6fc14f:	4c 39 30             	cmp    QWORD PTR [rax],r14
  6fc152:	74 13                	je     0x6fc167
  6fc154:	48 8b b9 00 08 00 00 	mov    rdi,QWORD PTR [rcx+0x800]
  6fc15b:	48 8d 34 d1          	lea    rsi,[rcx+rdx*8]
  6fc15f:	4c 89 f2             	mov    rdx,r14
  6fc162:	e8 89 9e c2 ff       	call   0x325ff0
  6fc167:	4c 8b 78 08          	mov    r15,QWORD PTR [rax+0x8]
  6fc16b:	48 8d 05 56 f7 b6 ff 	lea    rax,[rip+0xffffffffffb6f756]        # 0x26b8c8
  6fc172:	4c 29 f8             	sub    rax,r15
  6fc175:	48 c1 c8 03          	ror    rax,0x3
  6fc179:	48 83 f8 07          	cmp    rax,0x7
  6fc17d:	0f 87 11 03 00 00    	ja     0x6fc494
  6fc183:	48 8b 75 90          	mov    rsi,QWORD PTR [rbp-0x70]
  6fc187:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
  6fc18b:	4c 8b 45 88          	mov    r8,QWORD PTR [rbp-0x78]
  6fc18f:	48 89 df             	mov    rdi,rbx
  6fc192:	44 89 e1             	mov    ecx,r12d
  6fc195:	41 ff d7             	call   r15
  6fc198:	41 89 c4             	mov    r12d,eax
  6fc19b:	e9 d4 02 00 00       	jmp    0x6fc474
  6fc1a0:	31 d2                	xor    edx,edx
  6fc1a2:	f7 f1                	div    ecx
  6fc1a4:	41 8b 57 70          	mov    edx,DWORD PTR [r15+0x70]
  6fc1a8:	41 8b 4f 6c          	mov    ecx,DWORD PTR [r15+0x6c]
  6fc1ac:	41 8b 7f 54          	mov    edi,DWORD PTR [r15+0x54]
  6fc1b0:	4c 8b 65 c8          	mov    r12,QWORD PTR [rbp-0x38]
  6fc1b4:	29 ca                	sub    edx,ecx
  6fc1b6:	41 23 57 5c          	and    edx,DWORD PTR [r15+0x5c]
  6fc1ba:	89 7d 9c             	mov    DWORD PTR [rbp-0x64],edi
  6fc1bd:	29 d0                	sub    eax,edx
  6fc1bf:	41 8b 57 58          	mov    edx,DWORD PTR [r15+0x58]
  6fc1c3:	ff c0                	inc    eax
  6fc1c5:	48 89 95 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rdx
  6fc1cc:	ff ca                	dec    edx
  6fc1ce:	89 55 a0             	mov    DWORD PTR [rbp-0x60],edx
  6fc1d1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fc1d8:	0f 1f 84 00 00 00 00 
  6fc1df:	00 
  6fc1e0:	41 8b 5f 70          	mov    ebx,DWORD PTR [r15+0x70]
  6fc1e4:	89 75 d0             	mov    DWORD PTR [rbp-0x30],esi
  6fc1e7:	85 c0                	test   eax,eax
  6fc1e9:	0f 84 51 01 00 00    	je     0x6fc340
  6fc1ef:	41 8b 57 64          	mov    edx,DWORD PTR [r15+0x64]
  6fc1f3:	49 89 c6             	mov    r14,rax
  6fc1f6:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  6fc1fa:	41 89 d5             	mov    r13d,edx
  6fc1fd:	41 29 dd             	sub    r13d,ebx
  6fc200:	45 39 f5             	cmp    r13d,r14d
  6fc203:	45 0f 43 ee          	cmovae r13d,r14d
  6fc207:	39 da                	cmp    edx,ebx
  6fc209:	0f 85 81 00 00 00    	jne    0x6fc290
  6fc20f:	41 8b 57 60          	mov    edx,DWORD PTR [r15+0x60]
  6fc213:	41 8b 47 5c          	mov    eax,DWORD PTR [r15+0x5c]
  6fc217:	44 8b 45 d4          	mov    r8d,DWORD PTR [rbp-0x2c]
  6fc21b:	29 cb                	sub    ebx,ecx
  6fc21d:	49 8b 7f 28          	mov    rdi,QWORD PTR [r15+0x28]
  6fc221:	8d 34 12             	lea    esi,[rdx+rdx*1]
  6fc224:	21 c3                	and    ebx,eax
  6fc226:	f7 de                	neg    esi
  6fc228:	44 8d 4c 53 ff       	lea    r9d,[rbx+rdx*2-0x1]
  6fc22d:	8d 4c 31 01          	lea    ecx,[rcx+rsi*1+0x1]
  6fc231:	45 0f af c8          	imul   r9d,r8d
  6fc235:	21 c1                	and    ecx,eax
  6fc237:	41 0f af c8          	imul   ecx,r8d
  6fc23b:	49 63 d1             	movsxd rdx,r9d
  6fc23e:	48 63 f1             	movsxd rsi,ecx
  6fc241:	48 01 fe             	add    rsi,rdi
  6fc244:	e8 67 ce b5 ff       	call   0x2590b0
  6fc249:	41 8b 4f 60          	mov    ecx,DWORD PTR [r15+0x60]
  6fc24d:	41 8b 47 5c          	mov    eax,DWORD PTR [r15+0x5c]
  6fc251:	41 8b 57 64          	mov    edx,DWORD PTR [r15+0x64]
  6fc255:	8d 4c 09 ff          	lea    ecx,[rcx+rcx*1-0x1]
  6fc259:	41 89 d5             	mov    r13d,edx
  6fc25c:	21 c1                	and    ecx,eax
  6fc25e:	01 cb                	add    ebx,ecx
  6fc260:	41 89 4f 6c          	mov    DWORD PTR [r15+0x6c],ecx
  6fc264:	21 c3                	and    ebx,eax
  6fc266:	41 29 dd             	sub    r13d,ebx
  6fc269:	41 89 5f 70          	mov    DWORD PTR [r15+0x70],ebx
  6fc26d:	45 39 f5             	cmp    r13d,r14d
  6fc270:	45 0f 43 ee          	cmovae r13d,r14d
  6fc274:	39 da                	cmp    edx,ebx
  6fc276:	75 18                	jne    0x6fc290
  6fc278:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
  6fc27c:	4c 8d 35 3d 67 e2 01 	lea    r14,[rip+0x1e2673d]        # 0x25229c0
  6fc283:	e9 ba 00 00 00       	jmp    0x6fc342
  6fc288:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  6fc28f:	00 
  6fc290:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  6fc294:	0f af 5d d4          	imul   ebx,DWORD PTR [rbp-0x2c]
  6fc298:	4c 8d 35 21 67 e2 01 	lea    r14,[rip+0x1e26721]        # 0x25229c0
  6fc29f:	48 8b 78 40          	mov    rdi,QWORD PTR [rax+0x40]
  6fc2a3:	41 0f b6 16          	movzx  edx,BYTE PTR [r14]
  6fc2a7:	4c 63 c3             	movsxd r8,ebx
  6fc2aa:	4d 03 47 28          	add    r8,QWORD PTR [r15+0x28]
  6fc2ae:	48 8b 0f             	mov    rcx,QWORD PTR [rdi]
  6fc2b1:	48 8b 04 d1          	mov    rax,QWORD PTR [rcx+rdx*8]
  6fc2b5:	4c 39 30             	cmp    QWORD PTR [rax],r14
  6fc2b8:	74 26                	je     0x6fc2e0
  6fc2ba:	48 89 fb             	mov    rbx,rdi
  6fc2bd:	48 8b b9 00 08 00 00 	mov    rdi,QWORD PTR [rcx+0x800]
  6fc2c4:	48 8d 34 d1          	lea    rsi,[rcx+rdx*8]
  6fc2c8:	4c 89 f2             	mov    rdx,r14
  6fc2cb:	4d 89 c6             	mov    r14,r8
  6fc2ce:	e8 1d 9d c2 ff       	call   0x325ff0
  6fc2d3:	4d 89 f0             	mov    r8,r14
  6fc2d6:	4c 8d 35 e3 66 e2 01 	lea    r14,[rip+0x1e266e3]        # 0x25229c0
  6fc2dd:	48 89 df             	mov    rdi,rbx
  6fc2e0:	44 89 eb             	mov    ebx,r13d
  6fc2e3:	0f af 5d d4          	imul   ebx,DWORD PTR [rbp-0x2c]
  6fc2e7:	4c 8b 48 08          	mov    r9,QWORD PTR [rax+0x8]
  6fc2eb:	48 8d 05 d6 f5 b6 ff 	lea    rax,[rip+0xffffffffffb6f5d6]        # 0x26b8c8
  6fc2f2:	4c 29 c8             	sub    rax,r9
  6fc2f5:	48 c1 c8 03          	ror    rax,0x3
  6fc2f9:	48 83 f8 07          	cmp    rax,0x7
  6fc2fd:	0f 87 32 01 00 00    	ja     0x6fc435
  6fc303:	4c 89 c2             	mov    rdx,r8
  6fc306:	48 8b 75 90          	mov    rsi,QWORD PTR [rbp-0x70]
  6fc30a:	4c 8b 45 88          	mov    r8,QWORD PTR [rbp-0x78]
  6fc30e:	89 d9                	mov    ecx,ebx
  6fc310:	41 ff d1             	call   r9
  6fc313:	0f af 45 a4          	imul   eax,DWORD PTR [rbp-0x5c]
  6fc317:	8b 4d a8             	mov    ecx,DWORD PTR [rbp-0x58]
  6fc31a:	41 8b 5f 70          	mov    ebx,DWORD PTR [r15+0x70]
  6fc31e:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
  6fc322:	c4 e2 73 f7 c0       	shrx   eax,eax,ecx
  6fc327:	01 c3                	add    ebx,eax
  6fc329:	29 c2                	sub    edx,eax
  6fc32b:	44 39 e8             	cmp    eax,r13d
  6fc32e:	b8 00 00 00 00       	mov    eax,0x0
  6fc333:	41 89 5f 70          	mov    DWORD PTR [r15+0x70],ebx
  6fc337:	0f 45 d0             	cmovne edx,eax
  6fc33a:	41 8b 4f 6c          	mov    ecx,DWORD PTR [r15+0x6c]
  6fc33e:	eb 02                	jmp    0x6fc342
  6fc340:	31 d2                	xor    edx,edx
  6fc342:	29 cb                	sub    ebx,ecx
  6fc344:	41 23 5f 5c          	and    ebx,DWORD PTR [r15+0x5c]
  6fc348:	49 63 47 20          	movsxd rax,DWORD PTR [r15+0x20]
  6fc34c:	48 89 55 c0          	mov    QWORD PTR [rbp-0x40],rdx
  6fc350:	49 63 77 1c          	movsxd rsi,DWORD PTR [r15+0x1c]
  6fc354:	ff cb                	dec    ebx
  6fc356:	48 63 d3             	movsxd rdx,ebx
  6fc359:	48 0f af d0          	imul   rdx,rax
  6fc35d:	49 63 47 24          	movsxd rax,DWORD PTR [r15+0x24]
  6fc361:	48 01 d0             	add    rax,rdx
  6fc364:	48 89 c2             	mov    rdx,rax
  6fc367:	48 09 f2             	or     rdx,rsi
  6fc36a:	48 c1 ea 20          	shr    rdx,0x20
  6fc36e:	74 10                	je     0x6fc380
  6fc370:	31 d2                	xor    edx,edx
  6fc372:	48 f7 f6             	div    rsi
  6fc375:	49 89 c5             	mov    r13,rax
  6fc378:	eb 0d                	jmp    0x6fc387
  6fc37a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  6fc380:	31 d2                	xor    edx,edx
  6fc382:	f7 f6                	div    esi
  6fc384:	41 89 c5             	mov    r13d,eax
  6fc387:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
  6fc38a:	41 39 c5             	cmp    r13d,eax
  6fc38d:	44 0f 43 e8          	cmovae r13d,eax
  6fc391:	45 85 ed             	test   r13d,r13d
  6fc394:	0f 84 86 00 00 00    	je     0x6fc420
  6fc39a:	45 89 ee             	mov    r14d,r13d
  6fc39d:	eb 18                	jmp    0x6fc3b7
  6fc39f:	90                   	nop
  6fc3a0:	03 4d a0             	add    ecx,DWORD PTR [rbp-0x60]
  6fc3a3:	41 89 47 24          	mov    DWORD PTR [r15+0x24],eax
  6fc3a7:	4c 03 a5 68 ff ff ff 	add    r12,QWORD PTR [rbp-0x98]
  6fc3ae:	41 ff ce             	dec    r14d
  6fc3b1:	41 89 4f 6c          	mov    DWORD PTR [r15+0x6c],ecx
  6fc3b5:	74 59                	je     0x6fc410
  6fc3b7:	49 8b 5f 78          	mov    rbx,QWORD PTR [r15+0x78]
  6fc3bb:	48 8d 05 c6 ba b6 ff 	lea    rax,[rip+0xffffffffffb6bac6]        # 0x267e88
  6fc3c2:	48 29 d8             	sub    rax,rbx
  6fc3c5:	48 c1 c8 03          	ror    rax,0x3
  6fc3c9:	48 3d 97 01 00 00    	cmp    rax,0x197
  6fc3cf:	77 25                	ja     0x6fc3f6
  6fc3d1:	4c 89 ff             	mov    rdi,r15
  6fc3d4:	4c 89 e6             	mov    rsi,r12
  6fc3d7:	ff d3                	call   rbx
  6fc3d9:	41 8b 47 24          	mov    eax,DWORD PTR [r15+0x24]
  6fc3dd:	03 45 9c             	add    eax,DWORD PTR [rbp-0x64]
  6fc3e0:	41 89 47 24          	mov    DWORD PTR [r15+0x24],eax
  6fc3e4:	41 2b 47 20          	sub    eax,DWORD PTR [r15+0x20]
  6fc3e8:	41 8b 4f 6c          	mov    ecx,DWORD PTR [r15+0x6c]
  6fc3ec:	7d b2                	jge    0x6fc3a0
  6fc3ee:	03 8d 70 ff ff ff    	add    ecx,DWORD PTR [rbp-0x90]
  6fc3f4:	eb b1                	jmp    0x6fc3a7
  6fc3f6:	48 8d 3d 53 5b b0 01 	lea    rdi,[rip+0x1b05b53]        # 0x2201f50
  6fc3fd:	48 89 de             	mov    rsi,rbx
  6fc400:	e8 bb 34 d5 ff       	call   0x44f8c0
  6fc405:	eb ca                	jmp    0x6fc3d1
  6fc407:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  6fc40e:	00 00 
  6fc410:	8b 75 d0             	mov    esi,DWORD PTR [rbp-0x30]
  6fc413:	4c 8d 35 a6 65 e2 01 	lea    r14,[rip+0x1e265a6]        # 0x25229c0
  6fc41a:	44 29 ee             	sub    esi,r13d
  6fc41d:	eb 04                	jmp    0x6fc423
  6fc41f:	90                   	nop
  6fc420:	8b 75 d0             	mov    esi,DWORD PTR [rbp-0x30]
  6fc423:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  6fc427:	85 c0                	test   eax,eax
  6fc429:	74 45                	je     0x6fc470
  6fc42b:	85 f6                	test   esi,esi
  6fc42d:	0f 85 ad fd ff ff    	jne    0x6fc1e0
  6fc433:	eb 3b                	jmp    0x6fc470
  6fc435:	48 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdi
  6fc43c:	48 8d 3d 2d 5b b0 01 	lea    rdi,[rip+0x1b05b2d]        # 0x2201f70
  6fc443:	4c 89 ce             	mov    rsi,r9
  6fc446:	4d 89 c6             	mov    r14,r8
  6fc449:	4c 89 4d 80          	mov    QWORD PTR [rbp-0x80],r9
  6fc44d:	e8 6e 34 d5 ff       	call   0x44f8c0
  6fc452:	4d 89 f0             	mov    r8,r14
  6fc455:	4c 8b 4d 80          	mov    r9,QWORD PTR [rbp-0x80]
  6fc459:	4c 8d 35 60 65 e2 01 	lea    r14,[rip+0x1e26560]        # 0x25229c0
  6fc460:	48 8b bd 78 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x88]
  6fc467:	e9 97 fe ff ff       	jmp    0x6fc303
  6fc46c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  6fc470:	44 2b 65 c8          	sub    r12d,DWORD PTR [rbp-0x38]
  6fc474:	8b 4d ac             	mov    ecx,DWORD PTR [rbp-0x54]
  6fc477:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  6fc47b:	44 29 e1             	sub    ecx,r12d
  6fc47e:	45 85 e4             	test   r12d,r12d
  6fc481:	74 25                	je     0x6fc4a8
  6fc483:	44 89 e0             	mov    eax,r12d
  6fc486:	48 01 45 c8          	add    QWORD PTR [rbp-0x38],rax
  6fc48a:	85 c9                	test   ecx,ecx
  6fc48c:	0f 85 1e fc ff ff    	jne    0x6fc0b0
  6fc492:	eb 14                	jmp    0x6fc4a8
  6fc494:	48 8d 3d d5 5a b0 01 	lea    rdi,[rip+0x1b05ad5]        # 0x2201f70
  6fc49b:	4c 89 fe             	mov    rsi,r15
  6fc49e:	e8 1d 34 d5 ff       	call   0x44f8c0
  6fc4a3:	e9 db fc ff ff       	jmp    0x6fc183
  6fc4a8:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
  6fc4ab:	29 c8                	sub    eax,ecx
  6fc4ad:	48 83 c4 78          	add    rsp,0x78
  6fc4b1:	5b                   	pop    rbx
  6fc4b2:	41 5c                	pop    r12
  6fc4b4:	41 5d                	pop    r13
  6fc4b6:	41 5e                	pop    r14
  6fc4b8:	41 5f                	pop    r15
  6fc4ba:	5d                   	pop    rbp
  6fc4bb:	c3                   	ret
  6fc4bc:	90                   	nop
  6fc4bd:	90                   	nop
  6fc4be:	90                   	nop
  6fc4bf:	90                   	nop
  6fc4c0:	55                   	push   rbp
  6fc4c1:	48 89 e5             	mov    rbp,rsp
  6fc4c4:	41 57                	push   r15
  6fc4c6:	41 56                	push   r14
  6fc4c8:	41 55                	push   r13
  6fc4ca:	41 54                	push   r12
  6fc4cc:	53                   	push   rbx
  6fc4cd:	48 83 ec 38          	sub    rsp,0x38
  6fc4d1:	4c 8b 67 30          	mov    r12,QWORD PTR [rdi+0x30]
  6fc4d5:	8b 05 15 f1 af 01    	mov    eax,DWORD PTR [rip+0x1aff115]        # 0x21fb5f0
  6fc4db:	41 b8 01 00 00 00    	mov    r8d,0x1
  6fc4e1:	48 89 fb             	mov    rbx,rdi
  6fc4e4:	bf 01 00 00 00       	mov    edi,0x1
  6fc4e9:	41 8b 34 24          	mov    esi,DWORD PTR [r12]
  6fc4ed:	41 8b 4c 24 04       	mov    ecx,DWORD PTR [r12+0x4]
  6fc4f2:	39 c6                	cmp    esi,eax
  6fc4f4:	44 0f 4f c0          	cmovg  r8d,eax
  6fc4f8:	85 c0                	test   eax,eax
  6fc4fa:	89 f0                	mov    eax,esi
  6fc4fc:	44 0f 4e c7          	cmovle r8d,edi
  6fc500:	99                   	cdq
  6fc501:	41 f7 f8             	idiv   r8d
  6fc504:	29 d6                	sub    esi,edx
  6fc506:	41 89 74 24 08       	mov    DWORD PTR [r12+0x8],esi
  6fc50b:	be 01 00 00 00       	mov    esi,0x1
  6fc510:	8b 05 da f0 af 01    	mov    eax,DWORD PTR [rip+0x1aff0da]        # 0x21fb5f0
  6fc516:	39 c1                	cmp    ecx,eax
  6fc518:	0f 4f f0             	cmovg  esi,eax
  6fc51b:	85 c0                	test   eax,eax
  6fc51d:	89 c8                	mov    eax,ecx
  6fc51f:	0f 4e f7             	cmovle esi,edi
  6fc522:	99                   	cdq
  6fc523:	f7 fe                	idiv   esi
  6fc525:	48 b8 01 00 00 00 01 	movabs rax,0x100000001
  6fc52c:	00 00 00 
  6fc52f:	29 d1                	sub    ecx,edx
  6fc531:	41 89 4c 24 0c       	mov    DWORD PTR [r12+0xc],ecx
  6fc536:	49 89 44 24 1c       	mov    QWORD PTR [r12+0x1c],rax
  6fc53b:	41 c7 44 24 24 00 00 	mov    DWORD PTR [r12+0x24],0x0
  6fc542:	00 00 
  6fc544:	49 c7 44 24 78 00 00 	mov    QWORD PTR [r12+0x78],0x0
  6fc54b:	00 00 
  6fc54d:	41 c7 44 24 60 01 00 	mov    DWORD PTR [r12+0x60],0x1
  6fc554:	00 00 
  6fc556:	49 c7 44 24 30 00 00 	mov    QWORD PTR [r12+0x30],0x0
  6fc55d:	00 00 
  6fc55f:	49 c7 44 24 38 00 00 	mov    QWORD PTR [r12+0x38],0x0
  6fc566:	00 00 
  6fc568:	49 8b 7c 24 40       	mov    rdi,QWORD PTR [r12+0x40]
  6fc56d:	48 85 ff             	test   rdi,rdi
  6fc570:	74 15                	je     0x6fc587
  6fc572:	48 8d 35 97 f2 4f 02 	lea    rsi,[rip+0x24ff297]        # 0x2bfb810
  6fc579:	e8 72 c8 50 00       	call   0xc08df0
  6fc57e:	49 c7 44 24 40 00 00 	mov    QWORD PTR [r12+0x40],0x0
  6fc585:	00 00 
  6fc587:	48 b8 00 00 00 02 00 	movabs rax,0x4000000002000000
  6fc58e:	00 00 40 
  6fc591:	49 89 44 24 48       	mov    QWORD PTR [r12+0x48],rax
  6fc596:	41 c7 44 24 50 00 00 	mov    DWORD PTR [r12+0x50],0x40000000
  6fc59d:	00 40 
  6fc59f:	45 8b 44 24 18       	mov    r8d,DWORD PTR [r12+0x18]
  6fc5a4:	45 85 c0             	test   r8d,r8d
  6fc5a7:	78 0d                	js     0x6fc5b6
  6fc5a9:	b8 04 00 00 00       	mov    eax,0x4
  6fc5ae:	41 83 f8 05          	cmp    r8d,0x5
  6fc5b2:	73 04                	jae    0x6fc5b8
  6fc5b4:	eb 0a                	jmp    0x6fc5c0
  6fc5b6:	31 c0                	xor    eax,eax
  6fc5b8:	41 89 c0             	mov    r8d,eax
  6fc5bb:	41 89 44 24 18       	mov    DWORD PTR [r12+0x18],eax
  6fc5c0:	41 8b 74 24 08       	mov    esi,DWORD PTR [r12+0x8]
  6fc5c5:	41 8b 7c 24 0c       	mov    edi,DWORD PTR [r12+0xc]
  6fc5ca:	31 c9                	xor    ecx,ecx
  6fc5cc:	39 fe                	cmp    esi,edi
  6fc5ce:	0f 84 dd 05 00 00    	je     0x6fcbb1
  6fc5d4:	89 f1                	mov    ecx,esi
  6fc5d6:	85 ff                	test   edi,edi
  6fc5d8:	74 11                	je     0x6fc5eb
  6fc5da:	89 f0                	mov    eax,esi
  6fc5dc:	89 fa                	mov    edx,edi
  6fc5de:	66 90                	xchg   ax,ax
  6fc5e0:	89 d1                	mov    ecx,edx
  6fc5e2:	99                   	cdq
  6fc5e3:	f7 f9                	idiv   ecx
  6fc5e5:	89 c8                	mov    eax,ecx
  6fc5e7:	85 d2                	test   edx,edx
  6fc5e9:	75 f5                	jne    0x6fc5e0
  6fc5eb:	89 f0                	mov    eax,esi
  6fc5ed:	99                   	cdq
  6fc5ee:	f7 f9                	idiv   ecx
  6fc5f0:	89 c6                	mov    esi,eax
  6fc5f2:	41 89 44 24 1c       	mov    DWORD PTR [r12+0x1c],eax
  6fc5f7:	89 f8                	mov    eax,edi
  6fc5f9:	99                   	cdq
  6fc5fa:	f7 f9                	idiv   ecx
  6fc5fc:	8d 96 00 00 00 fe    	lea    edx,[rsi-0x2000000]
  6fc602:	89 c1                	mov    ecx,eax
  6fc604:	41 89 44 24 20       	mov    DWORD PTR [r12+0x20],eax
  6fc609:	81 fa 01 00 00 fe    	cmp    edx,0xfe000001
  6fc60f:	0f 82 97 05 00 00    	jb     0x6fcbac
  6fc615:	8d 81 00 00 00 fe    	lea    eax,[rcx-0x2000000]
  6fc61b:	3d 01 00 00 fe       	cmp    eax,0xfe000001
  6fc620:	0f 82 86 05 00 00    	jb     0x6fcbac
  6fc626:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  6fc62a:	48 89 5d a8          	mov    QWORD PTR [rbp-0x58],rbx
  6fc62e:	44 8b 78 04          	mov    r15d,DWORD PTR [rax+0x4]
  6fc632:	44 89 7d cc          	mov    DWORD PTR [rbp-0x34],r15d
  6fc636:	41 83 f8 02          	cmp    r8d,0x2
  6fc63a:	72 3a                	jb     0x6fc676
  6fc63c:	bb 00 00 00 02       	mov    ebx,0x2000000
  6fc641:	39 ce                	cmp    esi,ecx
  6fc643:	76 61                	jbe    0x6fc6a6
  6fc645:	89 f0                	mov    eax,esi
  6fc647:	31 d2                	xor    edx,edx
  6fc649:	bb aa aa 0a 00       	mov    ebx,0xaaaaa
  6fc64e:	f7 f1                	div    ecx
  6fc650:	83 f8 30             	cmp    eax,0x30
  6fc653:	77 51                	ja     0x6fc6a6
  6fc655:	89 c8                	mov    eax,ecx
  6fc657:	89 f1                	mov    ecx,esi
  6fc659:	48 ba 00 00 00 00 ff 	movabs rdx,0x1ffffff00000000
  6fc660:	ff ff 01 
  6fc663:	48 c1 e0 19          	shl    rax,0x19
  6fc667:	48 85 d0             	test   rax,rdx
  6fc66a:	74 34                	je     0x6fc6a0
  6fc66c:	31 d2                	xor    edx,edx
  6fc66e:	48 f7 f1             	div    rcx
  6fc671:	48 89 c3             	mov    rbx,rax
  6fc674:	eb 30                	jmp    0x6fc6a6
  6fc676:	41 bd 00 00 00 00    	mov    r13d,0x0
  6fc67c:	31 db                	xor    ebx,ebx
  6fc67e:	41 83 f8 01          	cmp    r8d,0x1
  6fc682:	0f 85 ef 01 00 00    	jne    0x6fc877
  6fc688:	b8 00 00 00 40       	mov    eax,0x40000000
  6fc68d:	31 d2                	xor    edx,edx
  6fc68f:	31 db                	xor    ebx,ebx
  6fc691:	45 31 ed             	xor    r13d,r13d
  6fc694:	f7 f1                	div    ecx
  6fc696:	41 89 44 24 4c       	mov    DWORD PTR [r12+0x4c],eax
  6fc69b:	e9 d7 01 00 00       	jmp    0x6fc877
  6fc6a0:	31 d2                	xor    edx,edx
  6fc6a2:	f7 f1                	div    ecx
  6fc6a4:	89 c3                	mov    ebx,eax
  6fc6a6:	85 db                	test   ebx,ebx
  6fc6a8:	0f 8e 81 01 00 00    	jle    0x6fc82f
  6fc6ae:	40 b6 01             	mov    sil,0x1
  6fc6b1:	31 d2                	xor    edx,edx
  6fc6b3:	41 89 df             	mov    r15d,ebx
  6fc6b6:	48 89 5d b8          	mov    QWORD PTR [rbp-0x48],rbx
  6fc6ba:	41 c1 e7 05          	shl    r15d,0x5
  6fc6be:	66 90                	xchg   ax,ax
  6fc6c0:	49 8b 7c 24 40       	mov    rdi,QWORD PTR [r12+0x40]
  6fc6c5:	41 89 d5             	mov    r13d,edx
  6fc6c8:	89 f3                	mov    ebx,esi
  6fc6ca:	48 85 ff             	test   rdi,rdi
  6fc6cd:	74 15                	je     0x6fc6e4
  6fc6cf:	48 8d 35 3a f1 4f 02 	lea    rsi,[rip+0x24ff13a]        # 0x2bfb810
  6fc6d6:	e8 15 c7 50 00       	call   0xc08df0
  6fc6db:	49 c7 44 24 40 00 00 	mov    QWORD PTR [r12+0x40],0x0
  6fc6e2:	00 00 
  6fc6e4:	f6 c3 01             	test   bl,0x1
  6fc6e7:	74 37                	je     0x6fc720
  6fc6e9:	45 89 7c 24 50       	mov    DWORD PTR [r12+0x50],r15d
  6fc6ee:	45 85 ff             	test   r15d,r15d
  6fc6f1:	0f 8e 38 01 00 00    	jle    0x6fc82f
  6fc6f7:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  6fc6fb:	31 f6                	xor    esi,esi
  6fc6fd:	41 89 44 24 48       	mov    DWORD PTR [r12+0x48],eax
  6fc702:	44 89 f8             	mov    eax,r15d
  6fc705:	41 8b 4c 24 20       	mov    ecx,DWORD PTR [r12+0x20]
  6fc70a:	99                   	cdq
  6fc70b:	f7 f9                	idiv   ecx
  6fc70d:	ba 01 00 00 00       	mov    edx,0x1
  6fc712:	41 89 44 24 4c       	mov    DWORD PTR [r12+0x4c],eax
  6fc717:	85 c0                	test   eax,eax
  6fc719:	7f 32                	jg     0x6fc74d
  6fc71b:	eb a3                	jmp    0x6fc6c0
  6fc71d:	0f 1f 00             	nop    DWORD PTR [rax]
  6fc720:	41 c7 44 24 50 00 00 	mov    DWORD PTR [r12+0x50],0x40000000
  6fc727:	00 40 
  6fc729:	41 c7 44 24 48 00 00 	mov    DWORD PTR [r12+0x48],0x2000000
  6fc730:	00 02 
  6fc732:	b8 00 00 00 40       	mov    eax,0x40000000
  6fc737:	31 d2                	xor    edx,edx
  6fc739:	41 8b 4c 24 20       	mov    ecx,DWORD PTR [r12+0x20]
  6fc73e:	f7 f9                	idiv   ecx
  6fc740:	41 89 44 24 4c       	mov    DWORD PTR [r12+0x4c],eax
  6fc745:	85 c0                	test   eax,eax
  6fc747:	0f 8e e2 00 00 00    	jle    0x6fc82f
  6fc74d:	0f af c1             	imul   eax,ecx
  6fc750:	41 89 44 24 50       	mov    DWORD PTR [r12+0x50],eax
  6fc755:	41 8b 4c 24 18       	mov    ecx,DWORD PTR [r12+0x18]
  6fc75a:	83 c1 fe             	add    ecx,0xfffffffe
  6fc75d:	83 f9 03             	cmp    ecx,0x3
  6fc760:	0f 83 d3 00 00 00    	jae    0x6fc839
  6fc766:	89 c9                	mov    ecx,ecx
  6fc768:	48 8d 15 91 6c 78 00 	lea    rdx,[rip+0x786c91]        # 0xe83400
  6fc76f:	44 89 6d d0          	mov    DWORD PTR [rbp-0x30],r13d
  6fc773:	89 c6                	mov    esi,eax
  6fc775:	45 31 f6             	xor    r14d,r14d
  6fc778:	48 8d 0c 49          	lea    rcx,[rcx+rcx*2]
  6fc77c:	4c 8d 2c ca          	lea    r13,[rdx+rcx*8]
  6fc780:	48 63 0c ca          	movsxd rcx,DWORD PTR [rdx+rcx*8]
  6fc784:	31 d2                	xor    edx,edx
  6fc786:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  6fc78d:	00 00 00 
  6fc790:	89 d7                	mov    edi,edx
  6fc792:	89 f2                	mov    edx,esi
  6fc794:	c1 fa 19             	sar    edx,0x19
  6fc797:	01 fa                	add    edx,edi
  6fc799:	39 ca                	cmp    edx,ecx
  6fc79b:	7d 18                	jge    0x6fc7b5
  6fc79d:	41 ff c6             	inc    r14d
  6fc7a0:	81 e6 ff ff ff 01    	and    esi,0x1ffffff
  6fc7a6:	44 89 f7             	mov    edi,r14d
  6fc7a9:	01 c6                	add    esi,eax
  6fc7ab:	f7 df                	neg    edi
  6fc7ad:	71 e1                	jno    0x6fc790
  6fc7af:	41 be 00 00 00 80    	mov    r14d,0x80000000
  6fc7b5:	48 c1 e1 19          	shl    rcx,0x19
  6fc7b9:	48 63 f0             	movsxd rsi,eax
  6fc7bc:	48 89 ca             	mov    rdx,rcx
  6fc7bf:	48 09 f2             	or     rdx,rsi
  6fc7c2:	48 c1 ea 20          	shr    rdx,0x20
  6fc7c6:	74 58                	je     0x6fc820
  6fc7c8:	48 89 c8             	mov    rax,rcx
  6fc7cb:	31 d2                	xor    edx,edx
  6fc7cd:	48 f7 f6             	div    rsi
  6fc7d0:	41 39 c6             	cmp    r14d,eax
  6fc7d3:	74 1a                	je     0x6fc7ef
  6fc7d5:	89 c1                	mov    ecx,eax
  6fc7d7:	48 8d 3d d4 d5 b7 00 	lea    rdi,[rip+0xb7d5d4]        # 0x1279db2
  6fc7de:	48 8d 35 70 17 b9 00 	lea    rsi,[rip+0xb91770]        # 0x128df55
  6fc7e5:	44 89 f2             	mov    edx,r14d
  6fc7e8:	31 c0                	xor    eax,eax
  6fc7ea:	e8 21 0c b6 ff       	call   0x25d410
  6fc7ef:	44 89 f0             	mov    eax,r14d
  6fc7f2:	83 e0 fe             	and    eax,0xfffffffe
  6fc7f5:	41 83 fe 02          	cmp    r14d,0x2
  6fc7f9:	0f 9d c1             	setge  cl
  6fc7fc:	3d 00 00 40 00       	cmp    eax,0x400000
  6fc801:	41 89 44 24 60       	mov    DWORD PTR [r12+0x60],eax
  6fc806:	0f 9c c0             	setl   al
  6fc809:	84 c1                	test   cl,al
  6fc80b:	75 33                	jne    0x6fc840
  6fc80d:	ba 01 00 00 00       	mov    edx,0x1
  6fc812:	31 f6                	xor    esi,esi
  6fc814:	f6 c3 01             	test   bl,0x1
  6fc817:	0f 85 a3 fe ff ff    	jne    0x6fc6c0
  6fc81d:	eb 10                	jmp    0x6fc82f
  6fc81f:	90                   	nop
  6fc820:	89 c6                	mov    esi,eax
  6fc822:	89 c8                	mov    eax,ecx
  6fc824:	31 d2                	xor    edx,edx
  6fc826:	f7 f6                	div    esi
  6fc828:	41 39 c6             	cmp    r14d,eax
  6fc82b:	75 a8                	jne    0x6fc7d5
  6fc82d:	eb c0                	jmp    0x6fc7ef
  6fc82f:	b9 07 00 00 00       	mov    ecx,0x7
  6fc834:	e9 78 03 00 00       	jmp    0x6fcbb1
  6fc839:	49 8b 44 24 30       	mov    rax,QWORD PTR [r12+0x30]
  6fc83e:	eb 1a                	jmp    0x6fc85a
  6fc840:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  6fc844:	49 8b 4d 10          	mov    rcx,QWORD PTR [r13+0x10]
  6fc848:	44 8b 6d d0          	mov    r13d,DWORD PTR [rbp-0x30]
  6fc84c:	48 83 c0 14          	add    rax,0x14
  6fc850:	49 89 44 24 30       	mov    QWORD PTR [r12+0x30],rax
  6fc855:	49 89 4c 24 38       	mov    QWORD PTR [r12+0x38],rcx
  6fc85a:	44 8b 7d cc          	mov    r15d,DWORD PTR [rbp-0x34]
  6fc85e:	48 8b 5d b8          	mov    rbx,QWORD PTR [rbp-0x48]
  6fc862:	48 85 c0             	test   rax,rax
  6fc865:	0f 84 41 03 00 00    	je     0x6fcbac
  6fc86b:	49 83 7c 24 38 00    	cmp    QWORD PTR [r12+0x38],0x0
  6fc871:	0f 84 35 03 00 00    	je     0x6fcbac
  6fc877:	44 89 f8             	mov    eax,r15d
  6fc87a:	4c 8d 35 cf 6b 78 00 	lea    r14,[rip+0x786bcf]        # 0xe83450
  6fc881:	25 ff ff 0f f0       	and    eax,0xf00fffff
  6fc886:	83 f8 10             	cmp    eax,0x10
  6fc889:	74 12                	je     0x6fc89d
  6fc88b:	3d 00 10 00 00       	cmp    eax,0x1000
  6fc890:	0f 85 08 03 00 00    	jne    0x6fcb9e
  6fc896:	4c 8d 35 db 6b 78 00 	lea    r14,[rip+0x786bdb]        # 0xe83478
  6fc89d:	45 85 ed             	test   r13d,r13d
  6fc8a0:	0f 85 95 01 00 00    	jne    0x6fca3b
  6fc8a6:	41 83 7c 24 18 02    	cmp    DWORD PTR [r12+0x18],0x2
  6fc8ac:	0f 8c 89 01 00 00    	jl     0x6fca3b
  6fc8b2:	49 8b 7c 24 40       	mov    rdi,QWORD PTR [r12+0x40]
  6fc8b7:	48 85 ff             	test   rdi,rdi
  6fc8ba:	74 15                	je     0x6fc8d1
  6fc8bc:	48 8d 35 4d ef 4f 02 	lea    rsi,[rip+0x24fef4d]        # 0x2bfb810
  6fc8c3:	e8 28 c5 50 00       	call   0xc08df0
  6fc8c8:	49 c7 44 24 40 00 00 	mov    QWORD PTR [r12+0x40],0x0
  6fc8cf:	00 00 
  6fc8d1:	49 63 44 24 60       	movsxd rax,DWORD PTR [r12+0x60]
  6fc8d6:	49 63 7c 24 20       	movsxd rdi,DWORD PTR [r12+0x20]
  6fc8db:	48 0f af f8          	imul   rdi,rax
  6fc8df:	48 8d 04 3f          	lea    rax,[rdi+rdi*1]
  6fc8e3:	48 3d 00 cb 02 00    	cmp    rax,0x2cb00
  6fc8e9:	0f 8f 4c 01 00 00    	jg     0x6fca3b
  6fc8ef:	48 8d 35 1a ef 4f 02 	lea    rsi,[rip+0x24fef1a]        # 0x2bfb810
  6fc8f6:	48 c1 e7 03          	shl    rdi,0x3
  6fc8fa:	ba 01 01 00 00       	mov    edx,0x101
  6fc8ff:	e8 4c c2 50 00       	call   0xc08b50
  6fc904:	49 89 44 24 40       	mov    QWORD PTR [r12+0x40],rax
  6fc909:	48 85 c0             	test   rax,rax
  6fc90c:	0f 84 29 01 00 00    	je     0x6fca3b
  6fc912:	41 83 7c 24 20 00    	cmp    DWORD PTR [r12+0x20],0x0
  6fc918:	b8 03 00 00 00       	mov    eax,0x3
  6fc91d:	0f 8e 2b 01 00 00    	jle    0x6fca4e
  6fc923:	b8 02 00 00 00       	mov    eax,0x2
  6fc928:	31 c9                	xor    ecx,ecx
  6fc92a:	4c 89 75 b0          	mov    QWORD PTR [rbp-0x50],r14
  6fc92e:	44 89 6d d0          	mov    DWORD PTR [rbp-0x30],r13d
  6fc932:	48 89 5d b8          	mov    QWORD PTR [rbp-0x48],rbx
  6fc936:	c7 45 d4 00 00 00 00 	mov    DWORD PTR [rbp-0x2c],0x0
  6fc93d:	eb 1d                	jmp    0x6fc95c
  6fc93f:	90                   	nop
  6fc940:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
  6fc943:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
  6fc946:	83 c1 02             	add    ecx,0x2
  6fc949:	ff c2                	inc    edx
  6fc94b:	83 c0 02             	add    eax,0x2
  6fc94e:	89 55 d4             	mov    DWORD PTR [rbp-0x2c],edx
  6fc951:	41 3b 54 24 20       	cmp    edx,DWORD PTR [r12+0x20]
  6fc956:	0f 8d cc 02 00 00    	jge    0x6fcc28
  6fc95c:	45 8b 6c 24 60       	mov    r13d,DWORD PTR [r12+0x60]
  6fc961:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
  6fc964:	45 85 ed             	test   r13d,r13d
  6fc967:	74 d7                	je     0x6fc940
  6fc969:	45 8b 74 24 4c       	mov    r14d,DWORD PTR [r12+0x4c]
  6fc96e:	44 0f af 75 d4       	imul   r14d,DWORD PTR [rbp-0x2c]
  6fc973:	41 f7 dd             	neg    r13d
  6fc976:	45 31 ff             	xor    r15d,r15d
  6fc979:	89 4d c8             	mov    DWORD PTR [rbp-0x38],ecx
  6fc97c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  6fc980:	44 89 f0             	mov    eax,r14d
  6fc983:	41 8b 5c 24 60       	mov    ebx,DWORD PTR [r12+0x60]
  6fc988:	0f af 5d c4          	imul   ebx,DWORD PTR [rbp-0x3c]
  6fc98c:	41 81 e6 ff ff ff 01 	and    r14d,0x1ffffff
  6fc993:	c1 f8 19             	sar    eax,0x19
  6fc996:	44 89 f7             	mov    edi,r14d
  6fc999:	41 01 c7             	add    r15d,eax
  6fc99c:	49 63 f7             	movsxd rsi,r15d
  6fc99f:	48 c1 e6 02          	shl    rsi,0x2
  6fc9a3:	49 03 74 24 30       	add    rsi,QWORD PTR [r12+0x30]
  6fc9a8:	44 01 eb             	add    ebx,r13d
  6fc9ab:	e8 60 0b 00 00       	call   0x6fd510
  6fc9b0:	49 8b 4c 24 40       	mov    rcx,QWORD PTR [r12+0x40]
  6fc9b5:	48 63 d3             	movsxd rdx,ebx
  6fc9b8:	89 04 91             	mov    DWORD PTR [rcx+rdx*4],eax
  6fc9bb:	41 8b 5c 24 50       	mov    ebx,DWORD PTR [r12+0x50]
  6fc9c0:	41 01 de             	add    r14d,ebx
  6fc9c3:	41 ff c5             	inc    r13d
  6fc9c6:	75 b8                	jne    0x6fc980
  6fc9c8:	45 8b 74 24 60       	mov    r14d,DWORD PTR [r12+0x60]
  6fc9cd:	8b 4d c8             	mov    ecx,DWORD PTR [rbp-0x38]
  6fc9d0:	45 85 f6             	test   r14d,r14d
  6fc9d3:	0f 84 67 ff ff ff    	je     0x6fc940
  6fc9d9:	41 8b 44 24 4c       	mov    eax,DWORD PTR [r12+0x4c]
  6fc9de:	0f af 45 d4          	imul   eax,DWORD PTR [rbp-0x2c]
  6fc9e2:	41 ff ce             	dec    r14d
  6fc9e5:	45 31 ff             	xor    r15d,r15d
  6fc9e8:	29 c3                	sub    ebx,eax
  6fc9ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  6fc9f0:	89 d8                	mov    eax,ebx
  6fc9f2:	45 8b 6c 24 60       	mov    r13d,DWORD PTR [r12+0x60]
  6fc9f7:	81 e3 ff ff ff 01    	and    ebx,0x1ffffff
  6fc9fd:	c1 f8 19             	sar    eax,0x19
  6fca00:	89 df                	mov    edi,ebx
  6fca02:	41 01 c7             	add    r15d,eax
  6fca05:	49 63 f7             	movsxd rsi,r15d
  6fca08:	48 c1 e6 02          	shl    rsi,0x2
  6fca0c:	49 03 74 24 30       	add    rsi,QWORD PTR [r12+0x30]
  6fca11:	44 0f af e9          	imul   r13d,ecx
  6fca15:	45 01 f5             	add    r13d,r14d
  6fca18:	e8 f3 0a 00 00       	call   0x6fd510
  6fca1d:	49 8b 4c 24 40       	mov    rcx,QWORD PTR [r12+0x40]
  6fca22:	49 63 d5             	movsxd rdx,r13d
  6fca25:	89 04 91             	mov    DWORD PTR [rcx+rdx*4],eax
  6fca28:	8b 4d c8             	mov    ecx,DWORD PTR [rbp-0x38]
  6fca2b:	41 03 5c 24 50       	add    ebx,DWORD PTR [r12+0x50]
  6fca30:	41 83 c6 ff          	add    r14d,0xffffffff
  6fca34:	72 ba                	jb     0x6fc9f0
  6fca36:	e9 05 ff ff ff       	jmp    0x6fc940
  6fca3b:	41 8b 44 24 18       	mov    eax,DWORD PTR [r12+0x18]
  6fca40:	b9 02 00 00 00       	mov    ecx,0x2
  6fca45:	83 f8 02             	cmp    eax,0x2
  6fca48:	0f 4c c8             	cmovl  ecx,eax
  6fca4b:	48 63 c1             	movsxd rax,ecx
  6fca4e:	49 8b 44 c6 08       	mov    rax,QWORD PTR [r14+rax*8+0x8]
  6fca53:	49 89 44 24 78       	mov    QWORD PTR [r12+0x78],rax
  6fca58:	48 85 c0             	test   rax,rax
  6fca5b:	0f 84 4b 01 00 00    	je     0x6fcbac
  6fca61:	41 be 04 00 00 00    	mov    r14d,0x4
  6fca67:	41 f7 c7 00 f0 00 00 	test   r15d,0xf000
  6fca6e:	75 24                	jne    0x6fca94
  6fca70:	41 be 03 00 00 00    	mov    r14d,0x3
  6fca76:	41 f7 c7 00 00 0f 00 	test   r15d,0xf0000
  6fca7d:	75 15                	jne    0x6fca94
  6fca7f:	44 89 f8             	mov    eax,r15d
  6fca82:	41 be 02 00 00 00    	mov    r14d,0x2
  6fca88:	25 b0 05 00 00       	and    eax,0x5b0
  6fca8d:	83 f8 01             	cmp    eax,0x1
  6fca90:	41 83 de 00          	sbb    r14d,0x0
  6fca94:	45 89 74 24 14       	mov    DWORD PTR [r12+0x14],r14d
  6fca99:	4d 63 44 24 20       	movsxd r8,DWORD PTR [r12+0x20]
  6fca9e:	45 0f af 74 24 10    	imul   r14d,DWORD PTR [r12+0x10]
  6fcaa4:	4d 63 4c 24 1c       	movsxd r9,DWORD PTR [r12+0x1c]
  6fcaa9:	4c 89 c1             	mov    rcx,r8
  6fcaac:	48 c1 e1 1f          	shl    rcx,0x1f
  6fcab0:	4c 29 c1             	sub    rcx,r8
  6fcab3:	4c 29 c1             	sub    rcx,r8
  6fcab6:	48 89 c8             	mov    rax,rcx
  6fcab9:	4c 09 c9             	or     rcx,r9
  6fcabc:	48 83 c8 01          	or     rax,0x1
  6fcac0:	48 c1 e9 20          	shr    rcx,0x20
  6fcac4:	74 0a                	je     0x6fcad0
  6fcac6:	31 d2                	xor    edx,edx
  6fcac8:	49 f7 f1             	div    r9
  6fcacb:	48 89 c6             	mov    rsi,rax
  6fcace:	eb 07                	jmp    0x6fcad7
  6fcad0:	31 d2                	xor    edx,edx
  6fcad2:	41 f7 f1             	div    r9d
  6fcad5:	89 c6                	mov    esi,eax
  6fcad7:	49 63 c6             	movsxd rax,r14d
  6fcada:	48 0f af c6          	imul   rax,rsi
  6fcade:	48 3d 01 00 01 00    	cmp    rax,0x10001
  6fcae4:	7c 0d                	jl     0x6fcaf3
  6fcae6:	b8 00 00 01 00       	mov    eax,0x10000
  6fcaeb:	31 d2                	xor    edx,edx
  6fcaed:	41 f7 fe             	idiv   r14d
  6fcaf0:	48 63 f0             	movsxd rsi,eax
  6fcaf3:	b9 07 00 00 00       	mov    ecx,0x7
  6fcaf8:	48 85 f6             	test   rsi,rsi
  6fcafb:	0f 8e b0 00 00 00    	jle    0x6fcbb1
  6fcb01:	4c 89 c8             	mov    rax,r9
  6fcb04:	48 c1 e0 1f          	shl    rax,0x1f
  6fcb08:	4c 29 c8             	sub    rax,r9
  6fcb0b:	4c 29 c0             	sub    rax,r8
  6fcb0e:	48 89 c2             	mov    rdx,rax
  6fcb11:	4c 09 c2             	or     rdx,r8
  6fcb14:	48 c1 ea 20          	shr    rdx,0x20
  6fcb18:	74 0f                	je     0x6fcb29
  6fcb1a:	31 d2                	xor    edx,edx
  6fcb1c:	49 f7 f0             	div    r8
  6fcb1f:	48 85 c0             	test   rax,rax
  6fcb22:	7f 0f                	jg     0x6fcb33
  6fcb24:	e9 88 00 00 00       	jmp    0x6fcbb1
  6fcb29:	31 d2                	xor    edx,edx
  6fcb2b:	41 f7 f0             	div    r8d
  6fcb2e:	48 85 c0             	test   rax,rax
  6fcb31:	7e 7e                	jle    0x6fcbb1
  6fcb33:	41 8b 54 24 24       	mov    edx,DWORD PTR [r12+0x24]
  6fcb38:	48 3d ff ff ff 7f    	cmp    rax,0x7fffffff
  6fcb3e:	41 ba ff ff ff 7f    	mov    r10d,0x7fffffff
  6fcb44:	4c 0f 42 d0          	cmovb  r10,rax
  6fcb48:	48 89 f0             	mov    rax,rsi
  6fcb4b:	49 0f af c1          	imul   rax,r9
  6fcb4f:	f7 d2                	not    edx
  6fcb51:	44 01 c2             	add    edx,r8d
  6fcb54:	48 63 fa             	movsxd rdi,edx
  6fcb57:	48 01 f8             	add    rax,rdi
  6fcb5a:	48 89 c2             	mov    rdx,rax
  6fcb5d:	4c 09 c2             	or     rdx,r8
  6fcb60:	48 c1 ea 20          	shr    rdx,0x20
  6fcb64:	74 0c                	je     0x6fcb72
  6fcb66:	31 d2                	xor    edx,edx
  6fcb68:	49 f7 f0             	div    r8
  6fcb6b:	4c 39 d0             	cmp    rax,r10
  6fcb6e:	76 0c                	jbe    0x6fcb7c
  6fcb70:	eb 3f                	jmp    0x6fcbb1
  6fcb72:	31 d2                	xor    edx,edx
  6fcb74:	41 f7 f0             	div    r8d
  6fcb77:	4c 39 d0             	cmp    rax,r10
  6fcb7a:	77 35                	ja     0x6fcbb1
  6fcb7c:	4c 01 cf             	add    rdi,r9
  6fcb7f:	41 0f af f6          	imul   esi,r14d
  6fcb83:	48 89 f8             	mov    rax,rdi
  6fcb86:	4c 09 c0             	or     rax,r8
  6fcb89:	48 c1 e8 20          	shr    rax,0x20
  6fcb8d:	41 89 74 24 74       	mov    DWORD PTR [r12+0x74],esi
  6fcb92:	74 2e                	je     0x6fcbc2
  6fcb94:	48 89 f8             	mov    rax,rdi
  6fcb97:	31 d2                	xor    edx,edx
  6fcb99:	49 f7 f0             	div    r8
  6fcb9c:	eb 2b                	jmp    0x6fcbc9
  6fcb9e:	49 8b 44 24 78       	mov    rax,QWORD PTR [r12+0x78]
  6fcba3:	48 85 c0             	test   rax,rax
  6fcba6:	0f 85 b5 fe ff ff    	jne    0x6fca61
  6fcbac:	b9 16 00 00 00       	mov    ecx,0x16
  6fcbb1:	89 c8                	mov    eax,ecx
  6fcbb3:	48 83 c4 38          	add    rsp,0x38
  6fcbb7:	5b                   	pop    rbx
  6fcbb8:	41 5c                	pop    r12
  6fcbba:	41 5d                	pop    r13
  6fcbbc:	41 5e                	pop    r14
  6fcbbe:	41 5f                	pop    r15
  6fcbc0:	5d                   	pop    rbp
  6fcbc1:	c3                   	ret
  6fcbc2:	89 f8                	mov    eax,edi
  6fcbc4:	31 d2                	xor    edx,edx
  6fcbc6:	41 f7 f0             	div    r8d
  6fcbc9:	44 0f af c0          	imul   r8d,eax
  6fcbcd:	41 89 44 24 58       	mov    DWORD PTR [r12+0x58],eax
  6fcbd2:	bf 01 00 00 00       	mov    edi,0x1
  6fcbd7:	45 29 c8             	sub    r8d,r9d
  6fcbda:	45 89 44 24 54       	mov    DWORD PTR [r12+0x54],r8d
  6fcbdf:	41 8b 54 24 60       	mov    edx,DWORD PTR [r12+0x60]
  6fcbe4:	8d 34 50             	lea    esi,[rax+rdx*2]
  6fcbe7:	89 d0                	mov    eax,edx
  6fcbe9:	01 d0                	add    eax,edx
  6fcbeb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  6fcbf0:	89 fa                	mov    edx,edi
  6fcbf2:	85 ff                	test   edi,edi
  6fcbf4:	7e 07                	jle    0x6fcbfd
  6fcbf6:	8d 3c 12             	lea    edi,[rdx+rdx*1]
  6fcbf9:	39 f2                	cmp    edx,esi
  6fcbfb:	7c f3                	jl     0x6fcbf0
  6fcbfd:	41 89 d7             	mov    r15d,edx
  6fcc00:	41 89 54 24 64       	mov    DWORD PTR [r12+0x64],edx
  6fcc05:	45 0f af fe          	imul   r15d,r14d
  6fcc09:	45 85 ff             	test   r15d,r15d
  6fcc0c:	7f 34                	jg     0x6fcc42
  6fcc0e:	45 85 ed             	test   r13d,r13d
  6fcc11:	75 9e                	jne    0x6fcbb1
  6fcc13:	31 f6                	xor    esi,esi
  6fcc15:	41 83 7c 24 18 01    	cmp    DWORD PTR [r12+0x18],0x1
  6fcc1b:	ba 01 00 00 00       	mov    edx,0x1
  6fcc20:	0f 8f 8d fa ff ff    	jg     0x6fc6b3
  6fcc26:	eb 89                	jmp    0x6fcbb1
  6fcc28:	44 8b 7d cc          	mov    r15d,DWORD PTR [rbp-0x34]
  6fcc2c:	48 8b 5d b8          	mov    rbx,QWORD PTR [rbp-0x48]
  6fcc30:	44 8b 6d d0          	mov    r13d,DWORD PTR [rbp-0x30]
  6fcc34:	4c 8b 75 b0          	mov    r14,QWORD PTR [rbp-0x50]
  6fcc38:	b8 03 00 00 00       	mov    eax,0x3
  6fcc3d:	e9 0c fe ff ff       	jmp    0x6fca4e
  6fcc42:	81 fa ff ff 01 00    	cmp    edx,0x1ffff
  6fcc48:	7f 2e                	jg     0x6fcc78
  6fcc4a:	89 d6                	mov    esi,edx
  6fcc4c:	29 c6                	sub    esi,eax
  6fcc4e:	81 fe ff 07 00 00    	cmp    esi,0x7ff
  6fcc54:	7f 22                	jg     0x6fcc78
  6fcc56:	01 d2                	add    edx,edx
  6fcc58:	81 fa ff ff 01 00    	cmp    edx,0x1ffff
  6fcc5e:	7f 0c                	jg     0x6fcc6c
  6fcc60:	89 d6                	mov    esi,edx
  6fcc62:	29 c6                	sub    esi,eax
  6fcc64:	81 fe 00 08 00 00    	cmp    esi,0x800
  6fcc6a:	7c ea                	jl     0x6fcc56
  6fcc6c:	41 89 d7             	mov    r15d,edx
  6fcc6f:	41 89 54 24 64       	mov    DWORD PTR [r12+0x64],edx
  6fcc74:	45 0f af fe          	imul   r15d,r14d
  6fcc78:	ff ca                	dec    edx
  6fcc7a:	ff c8                	dec    eax
  6fcc7c:	21 d0                	and    eax,edx
  6fcc7e:	41 89 54 24 5c       	mov    DWORD PTR [r12+0x5c],edx
  6fcc83:	41 89 44 24 6c       	mov    DWORD PTR [r12+0x6c],eax
  6fcc88:	ff c0                	inc    eax
  6fcc8a:	21 d0                	and    eax,edx
  6fcc8c:	41 89 44 24 70       	mov    DWORD PTR [r12+0x70],eax
  6fcc91:	45 85 ff             	test   r15d,r15d
  6fcc94:	0f 8e 17 ff ff ff    	jle    0x6fcbb1
  6fcc9a:	49 8b 5c 24 28       	mov    rbx,QWORD PTR [r12+0x28]
  6fcc9f:	48 85 db             	test   rbx,rbx
  6fcca2:	74 26                	je     0x6fccca
  6fcca4:	41 8b 44 24 68       	mov    eax,DWORD PTR [r12+0x68]
  6fcca9:	44 39 f8             	cmp    eax,r15d
  6fccac:	0f 9d c1             	setge  cl
  6fccaf:	d1 e8                	shr    eax,1
  6fccb1:	41 39 c7             	cmp    r15d,eax
  6fccb4:	0f 97 c0             	seta   al
  6fccb7:	84 c1                	test   cl,al
  6fccb9:	75 35                	jne    0x6fccf0
  6fccbb:	48 8d 35 4e eb 4f 02 	lea    rsi,[rip+0x24feb4e]        # 0x2bfb810
  6fccc2:	48 89 df             	mov    rdi,rbx
  6fccc5:	e8 26 c1 50 00       	call   0xc08df0
  6fccca:	48 8d 35 3f eb 4f 02 	lea    rsi,[rip+0x24feb3f]        # 0x2bfb810
  6fccd1:	44 89 ff             	mov    edi,r15d
  6fccd4:	ba 01 01 00 00       	mov    edx,0x101
  6fccd9:	e8 72 be 50 00       	call   0xc08b50
  6fccde:	49 89 44 24 28       	mov    QWORD PTR [r12+0x28],rax
  6fcce3:	48 85 c0             	test   rax,rax
  6fcce6:	74 56                	je     0x6fcd3e
  6fcce8:	48 89 c3             	mov    rbx,rax
  6fcceb:	45 89 7c 24 68       	mov    DWORD PTR [r12+0x68],r15d
  6fccf0:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
  6fccf4:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  6fccf8:	8b 78 08             	mov    edi,DWORD PTR [rax+0x8]
  6fccfb:	e8 70 e8 3c 00       	call   0xacb570
  6fcd00:	45 0f af 74 24 70    	imul   r14d,DWORD PTR [r12+0x70]
  6fcd06:	49 63 f6             	movsxd rsi,r14d
  6fcd09:	84 c0                	test   al,al
  6fcd0b:	74 22                	je     0x6fcd2f
  6fcd0d:	b9 00 00 00 00       	mov    ecx,0x0
  6fcd12:	45 85 f6             	test   r14d,r14d
  6fcd15:	0f 84 96 fe ff ff    	je     0x6fcbb1
  6fcd1b:	31 c9                	xor    ecx,ecx
  6fcd1d:	31 d2                	xor    edx,edx
  6fcd1f:	88 04 13             	mov    BYTE PTR [rbx+rdx*1],al
  6fcd22:	48 ff c2             	inc    rdx
  6fcd25:	48 39 d6             	cmp    rsi,rdx
  6fcd28:	75 f5                	jne    0x6fcd1f
  6fcd2a:	e9 82 fe ff ff       	jmp    0x6fcbb1
  6fcd2f:	48 89 df             	mov    rdi,rbx
  6fcd32:	e8 b9 c2 b5 ff       	call   0x258ff0
  6fcd37:	31 c9                	xor    ecx,ecx
  6fcd39:	e9 73 fe ff ff       	jmp    0x6fcbb1
  6fcd3e:	b9 0c 00 00 00       	mov    ecx,0xc
  6fcd43:	e9 69 fe ff ff       	jmp    0x6fcbb1
  6fcd48:	90                   	nop
  6fcd49:	90                   	nop
  6fcd4a:	90                   	nop
  6fcd4b:	90                   	nop
  6fcd4c:	90                   	nop
  6fcd4d:	90                   	nop
  6fcd4e:	90                   	nop
  6fcd4f:	90                   	nop
  6fcd50:	55                   	push   rbp
  6fcd51:	48 89 e5             	mov    rbp,rsp
  6fcd54:	8b 47 14             	mov    eax,DWORD PTR [rdi+0x14]
  6fcd57:	0f af 47 10          	imul   eax,DWORD PTR [rdi+0x10]
  6fcd5b:	8b 4f 6c             	mov    ecx,DWORD PTR [rdi+0x6c]
  6fcd5e:	31 d2                	xor    edx,edx
  6fcd60:	0f af c8             	imul   ecx,eax
  6fcd63:	48 03 4f 28          	add    rcx,QWORD PTR [rdi+0x28]
  6fcd67:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  6fcd6e:	00 00 
  6fcd70:	0f b6 3c 11          	movzx  edi,BYTE PTR [rcx+rdx*1]
  6fcd74:	40 88 3c 16          	mov    BYTE PTR [rsi+rdx*1],dil
  6fcd78:	48 ff c2             	inc    rdx
  6fcd7b:	39 d0                	cmp    eax,edx
  6fcd7d:	75 f1                	jne    0x6fcd70
  6fcd7f:	5d                   	pop    rbp
  6fcd80:	c3                   	ret
  6fcd81:	90                   	nop
  6fcd82:	90                   	nop
  6fcd83:	90                   	nop
  6fcd84:	90                   	nop
  6fcd85:	90                   	nop
  6fcd86:	90                   	nop
  6fcd87:	90                   	nop
  6fcd88:	90                   	nop
  6fcd89:	90                   	nop
  6fcd8a:	90                   	nop
  6fcd8b:	90                   	nop
  6fcd8c:	90                   	nop
  6fcd8d:	90                   	nop
  6fcd8e:	90                   	nop
  6fcd8f:	90                   	nop
  6fcd90:	55                   	push   rbp
  6fcd91:	48 89 e5             	mov    rbp,rsp
  6fcd94:	8b 47 10             	mov    eax,DWORD PTR [rdi+0x10]
  6fcd97:	8b 57 6c             	mov    edx,DWORD PTR [rdi+0x6c]
  6fcd9a:	8b 4f 4c             	mov    ecx,DWORD PTR [rdi+0x4c]
  6fcd9d:	0f af 4f 24          	imul   ecx,DWORD PTR [rdi+0x24]
  6fcda1:	0f af d0             	imul   edx,eax
  6fcda4:	01 d2                	add    edx,edx
  6fcda6:	c1 e9 16             	shr    ecx,0x16
  6fcda9:	48 63 d2             	movsxd rdx,edx
  6fcdac:	48 03 57 28          	add    rdx,QWORD PTR [rdi+0x28]
  6fcdb0:	8d 3c 00             	lea    edi,[rax+rax*1]
  6fcdb3:	4c 63 c7             	movsxd r8,edi
  6fcdb6:	48 89 d7             	mov    rdi,rdx
  6fcdb9:	4c 29 c7             	sub    rdi,r8
  6fcdbc:	45 31 c0             	xor    r8d,r8d
  6fcdbf:	90                   	nop
  6fcdc0:	46 0f bf 0c 42       	movsx  r9d,WORD PTR [rdx+r8*2]
  6fcdc5:	46 0f bf 14 47       	movsx  r10d,WORD PTR [rdi+r8*2]
  6fcdca:	45 29 ca             	sub    r10d,r9d
  6fcdcd:	44 0f af d1          	imul   r10d,ecx
  6fcdd1:	41 c1 ea 08          	shr    r10d,0x8
  6fcdd5:	45 01 ca             	add    r10d,r9d
  6fcdd8:	66 46 89 14 46       	mov    WORD PTR [rsi+r8*2],r10w
  6fcddd:	49 ff c0             	inc    r8
  6fcde0:	44 39 c0             	cmp    eax,r8d
  6fcde3:	75 db                	jne    0x6fcdc0
  6fcde5:	5d                   	pop    rbp
  6fcde6:	c3                   	ret
  6fcde7:	90                   	nop
  6fcde8:	90                   	nop
  6fcde9:	90                   	nop
  6fcdea:	90                   	nop
  6fcdeb:	90                   	nop
  6fcdec:	90                   	nop
  6fcded:	90                   	nop
  6fcdee:	90                   	nop
  6fcdef:	90                   	nop
  6fcdf0:	55                   	push   rbp
  6fcdf1:	48 89 e5             	mov    rbp,rsp
  6fcdf4:	41 57                	push   r15
  6fcdf6:	41 56                	push   r14
  6fcdf8:	41 55                	push   r13
  6fcdfa:	41 54                	push   r12
  6fcdfc:	53                   	push   rbx
  6fcdfd:	48 83 ec 30          	sub    rsp,0x30
  6fce01:	8b 57 6c             	mov    edx,DWORD PTR [rdi+0x6c]
  6fce04:	2b 57 60             	sub    edx,DWORD PTR [rdi+0x60]
  6fce07:	8b 5f 10             	mov    ebx,DWORD PTR [rdi+0x10]
  6fce0a:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
  6fce0e:	48 8b 4f 38          	mov    rcx,QWORD PTR [rdi+0x38]
  6fce12:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  6fce16:	23 57 5c             	and    edx,DWORD PTR [rdi+0x5c]
  6fce19:	01 db                	add    ebx,ebx
  6fce1b:	48 01 de             	add    rsi,rbx
  6fce1e:	44 8d 42 01          	lea    r8d,[rdx+0x1]
  6fce22:	01 d2                	add    edx,edx
  6fce24:	44 89 45 d4          	mov    DWORD PTR [rbp-0x2c],r8d
  6fce28:	48 89 55 c0          	mov    QWORD PTR [rbp-0x40],rdx
  6fce2c:	eb 3d                	jmp    0x6fce6b
  6fce2e:	66 90                	xchg   ax,ax
  6fce30:	49 c1 fd 1e          	sar    r13,0x1e
  6fce34:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  6fce38:	48 c7 c2 00 80 ff ff 	mov    rdx,0xffffffffffff8000
  6fce3f:	48 83 c6 fe          	add    rsi,0xfffffffffffffffe
  6fce43:	49 81 fd 01 80 ff ff 	cmp    r13,0xffffffffffff8001
  6fce4a:	4c 0f 4c ea          	cmovl  r13,rdx
  6fce4e:	ba ff 7f 00 00       	mov    edx,0x7fff
  6fce53:	49 81 fd ff 7f 00 00 	cmp    r13,0x7fff
  6fce5a:	4c 0f 4d ea          	cmovge r13,rdx
  6fce5e:	66 44 89 2e          	mov    WORD PTR [rsi],r13w
  6fce62:	48 85 db             	test   rbx,rbx
  6fce65:	0f 84 99 01 00 00    	je     0x6fd004
  6fce6b:	8b 57 60             	mov    edx,DWORD PTR [rdi+0x60]
  6fce6e:	83 c3 fe             	add    ebx,0xfffffffe
  6fce71:	48 89 75 c8          	mov    QWORD PTR [rbp-0x38],rsi
  6fce75:	85 d2                	test   edx,edx
  6fce77:	0f 84 63 01 00 00    	je     0x6fcfe0
  6fce7d:	44 8b 4f 5c          	mov    r9d,DWORD PTR [rdi+0x5c]
  6fce81:	8b 77 10             	mov    esi,DWORD PTR [rdi+0x10]
  6fce84:	44 23 4d d4          	and    r9d,DWORD PTR [rbp-0x2c]
  6fce88:	44 8b 57 4c          	mov    r10d,DWORD PTR [rdi+0x4c]
  6fce8c:	44 0f af 57 24       	imul   r10d,DWORD PTR [rdi+0x24]
  6fce91:	4c 8b 77 28          	mov    r14,QWORD PTR [rdi+0x28]
  6fce95:	44 8b 7f 50          	mov    r15d,DWORD PTR [rdi+0x50]
  6fce99:	48 89 5d a8          	mov    QWORD PTR [rbp-0x58],rbx
  6fce9d:	45 31 ed             	xor    r13d,r13d
  6fcea0:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
  6fcea4:	01 f6                	add    esi,esi
  6fcea6:	4d 8d 04 1e          	lea    r8,[r14+rbx*1]
  6fceaa:	89 d3                	mov    ebx,edx
  6fceac:	44 0f af ce          	imul   r9d,esi
  6fceb0:	4c 63 e6             	movsxd r12,esi
  6fceb3:	44 89 55 d0          	mov    DWORD PTR [rbp-0x30],r10d
  6fceb7:	4d 01 c1             	add    r9,r8
  6fceba:	45 31 c0             	xor    r8d,r8d
  6fcebd:	0f 1f 00             	nop    DWORD PTR [rax]
  6fcec0:	45 89 d3             	mov    r11d,r10d
  6fcec3:	41 81 e2 ff ff ff 01 	and    r10d,0x1ffffff
  6fceca:	4b 0f bf 34 21       	movsx  rsi,WORD PTR [r9+r12*1]
  6fcecf:	41 c1 fb 19          	sar    r11d,0x19
  6fced3:	44 89 d7             	mov    edi,r10d
  6fced6:	45 01 fa             	add    r10d,r15d
  6fced9:	45 01 c3             	add    r11d,r8d
  6fcedc:	c1 ef 0e             	shr    edi,0xe
  6fcedf:	4d 0f bf 01          	movsx  r8,WORD PTR [r9]
  6fcee3:	4d 01 e1             	add    r9,r12
  6fcee6:	42 0f af 3c 99       	imul   edi,DWORD PTR [rcx+r11*4]
  6fceeb:	4d 01 e1             	add    r9,r12
  6fceee:	c1 ff 05             	sar    edi,0x5
  6fcef1:	42 03 3c 98          	add    edi,DWORD PTR [rax+r11*4]
  6fcef5:	48 63 ff             	movsxd rdi,edi
  6fcef8:	49 0f af f8          	imul   rdi,r8
  6fcefc:	45 89 d0             	mov    r8d,r10d
  6fceff:	41 81 e2 ff ff ff 01 	and    r10d,0x1ffffff
  6fcf06:	41 c1 f8 19          	sar    r8d,0x19
  6fcf0a:	45 01 d8             	add    r8d,r11d
  6fcf0d:	4c 01 ef             	add    rdi,r13
  6fcf10:	45 89 d5             	mov    r13d,r10d
  6fcf13:	45 01 fa             	add    r10d,r15d
  6fcf16:	41 c1 ed 0e          	shr    r13d,0xe
  6fcf1a:	46 0f af 2c 81       	imul   r13d,DWORD PTR [rcx+r8*4]
  6fcf1f:	41 c1 fd 05          	sar    r13d,0x5
  6fcf23:	46 03 2c 80          	add    r13d,DWORD PTR [rax+r8*4]
  6fcf27:	4d 63 ed             	movsxd r13,r13d
  6fcf2a:	4c 0f af ee          	imul   r13,rsi
  6fcf2e:	49 01 fd             	add    r13,rdi
  6fcf31:	83 c3 fe             	add    ebx,0xfffffffe
  6fcf34:	75 8a                	jne    0x6fcec0
  6fcf36:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  6fcf3a:	0f af 75 c0          	imul   esi,DWORD PTR [rbp-0x40]
  6fcf3e:	45 89 f9             	mov    r9d,r15d
  6fcf41:	48 8b 5d a8          	mov    rbx,QWORD PTR [rbp-0x58]
  6fcf45:	44 2b 4d d0          	sub    r9d,DWORD PTR [rbp-0x30]
  6fcf49:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  6fcf4d:	49 f7 dc             	neg    r12
  6fcf50:	45 31 db             	xor    r11d,r11d
  6fcf53:	49 01 f6             	add    r14,rsi
  6fcf56:	49 01 de             	add    r14,rbx
  6fcf59:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  6fcf60:	44 89 ce             	mov    esi,r9d
  6fcf63:	41 81 e1 ff ff ff 01 	and    r9d,0x1ffffff
  6fcf6a:	4d 0f bf 16          	movsx  r10,WORD PTR [r14]
  6fcf6e:	c1 fe 19             	sar    esi,0x19
  6fcf71:	45 89 c8             	mov    r8d,r9d
  6fcf74:	45 01 f9             	add    r9d,r15d
  6fcf77:	44 01 de             	add    esi,r11d
  6fcf7a:	41 c1 e8 0e          	shr    r8d,0xe
  6fcf7e:	45 89 cb             	mov    r11d,r9d
  6fcf81:	41 81 e1 ff ff ff 01 	and    r9d,0x1ffffff
  6fcf88:	44 0f af 04 b1       	imul   r8d,DWORD PTR [rcx+rsi*4]
  6fcf8d:	41 c1 fb 19          	sar    r11d,0x19
  6fcf91:	41 01 f3             	add    r11d,esi
  6fcf94:	41 c1 f8 05          	sar    r8d,0x5
  6fcf98:	44 03 04 b0          	add    r8d,DWORD PTR [rax+rsi*4]
  6fcf9c:	4d 63 c0             	movsxd r8,r8d
  6fcf9f:	4d 0f af c2          	imul   r8,r10
  6fcfa3:	4f 0f bf 14 26       	movsx  r10,WORD PTR [r14+r12*1]
  6fcfa8:	4d 01 e6             	add    r14,r12
  6fcfab:	4d 01 e6             	add    r14,r12
  6fcfae:	4d 01 e8             	add    r8,r13
  6fcfb1:	45 89 cd             	mov    r13d,r9d
  6fcfb4:	45 01 f9             	add    r9d,r15d
  6fcfb7:	41 c1 ed 0e          	shr    r13d,0xe
  6fcfbb:	46 0f af 2c 99       	imul   r13d,DWORD PTR [rcx+r11*4]
  6fcfc0:	41 c1 fd 05          	sar    r13d,0x5
  6fcfc4:	46 03 2c 98          	add    r13d,DWORD PTR [rax+r11*4]
  6fcfc8:	4d 63 ed             	movsxd r13,r13d
  6fcfcb:	4d 0f af ea          	imul   r13,r10
  6fcfcf:	4d 01 c5             	add    r13,r8
  6fcfd2:	83 c2 fe             	add    edx,0xfffffffe
  6fcfd5:	75 89                	jne    0x6fcf60
  6fcfd7:	eb 0a                	jmp    0x6fcfe3
  6fcfd9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  6fcfe0:	45 31 ed             	xor    r13d,r13d
  6fcfe3:	8b 57 48             	mov    edx,DWORD PTR [rdi+0x48]
  6fcfe6:	48 81 fa 00 00 00 02 	cmp    rdx,0x2000000
  6fcfed:	0f 84 3d fe ff ff    	je     0x6fce30
  6fcff3:	49 c1 fd 0e          	sar    r13,0xe
  6fcff7:	4c 0f af ea          	imul   r13,rdx
  6fcffb:	49 c1 fd 29          	sar    r13,0x29
  6fcfff:	e9 30 fe ff ff       	jmp    0x6fce34
  6fd004:	48 83 c4 30          	add    rsp,0x30
  6fd008:	5b                   	pop    rbx
  6fd009:	41 5c                	pop    r12
  6fd00b:	41 5d                	pop    r13
  6fd00d:	41 5e                	pop    r14
  6fd00f:	41 5f                	pop    r15
  6fd011:	5d                   	pop    rbp
  6fd012:	c3                   	ret
  6fd013:	90                   	nop
  6fd014:	90                   	nop
  6fd015:	90                   	nop
  6fd016:	90                   	nop
  6fd017:	90                   	nop
  6fd018:	90                   	nop
  6fd019:	90                   	nop
  6fd01a:	90                   	nop
  6fd01b:	90                   	nop
  6fd01c:	90                   	nop
  6fd01d:	90                   	nop
  6fd01e:	90                   	nop
  6fd01f:	90                   	nop
  6fd020:	55                   	push   rbp
  6fd021:	48 89 e5             	mov    rbp,rsp
  6fd024:	41 57                	push   r15
  6fd026:	41 56                	push   r14
  6fd028:	41 55                	push   r13
  6fd02a:	41 54                	push   r12
  6fd02c:	53                   	push   rbx
  6fd02d:	8b 4f 60             	mov    ecx,DWORD PTR [rdi+0x60]
  6fd030:	44 8b 47 6c          	mov    r8d,DWORD PTR [rdi+0x6c]
  6fd034:	8b 47 10             	mov    eax,DWORD PTR [rdi+0x10]
  6fd037:	01 c9                	add    ecx,ecx
  6fd039:	01 c0                	add    eax,eax
  6fd03b:	41 29 c8             	sub    r8d,ecx
  6fd03e:	48 63 d0             	movsxd rdx,eax
  6fd041:	41 ff c0             	inc    r8d
  6fd044:	44 23 47 5c          	and    r8d,DWORD PTR [rdi+0x5c]
  6fd048:	48 01 d6             	add    rsi,rdx
  6fd04b:	41 0f af d0          	imul   edx,r8d
  6fd04f:	41 b8 ff 7f 00 00    	mov    r8d,0x7fff
  6fd055:	48 63 ca             	movsxd rcx,edx
  6fd058:	48 c7 c2 00 80 ff ff 	mov    rdx,0xffffffffffff8000
  6fd05f:	eb 39                	jmp    0x6fd09a
  6fd061:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fd068:	0f 1f 84 00 00 00 00 
  6fd06f:	00 
  6fd070:	49 c1 fa 1e          	sar    r10,0x1e
  6fd074:	48 83 c6 fe          	add    rsi,0xfffffffffffffffe
  6fd078:	49 81 fa 01 80 ff ff 	cmp    r10,0xffffffffffff8001
  6fd07f:	4c 0f 4c d2          	cmovl  r10,rdx
  6fd083:	49 81 fa ff 7f 00 00 	cmp    r10,0x7fff
  6fd08a:	4d 0f 4d d0          	cmovge r10,r8
  6fd08e:	66 44 89 16          	mov    WORD PTR [rsi],r10w
  6fd092:	85 c0                	test   eax,eax
  6fd094:	0f 84 9b 00 00 00    	je     0x6fd135
  6fd09a:	44 8b 4f 60          	mov    r9d,DWORD PTR [rdi+0x60]
  6fd09e:	83 c0 fe             	add    eax,0xfffffffe
  6fd0a1:	4d 85 c9             	test   r9,r9
  6fd0a4:	74 6a                	je     0x6fd110
  6fd0a6:	44 8b 57 24          	mov    r10d,DWORD PTR [rdi+0x24]
  6fd0aa:	48 63 d8             	movsxd rbx,eax
  6fd0ad:	45 31 ff             	xor    r15d,r15d
  6fd0b0:	45 0f af d1          	imul   r10d,r9d
  6fd0b4:	45 01 d2             	add    r10d,r10d
  6fd0b7:	4d 63 da             	movsxd r11,r10d
  6fd0ba:	4c 8b 57 28          	mov    r10,QWORD PTR [rdi+0x28]
  6fd0be:	49 c1 e3 02          	shl    r11,0x2
  6fd0c2:	4c 03 5f 40          	add    r11,QWORD PTR [rdi+0x40]
  6fd0c6:	49 01 ca             	add    r10,rcx
  6fd0c9:	4c 01 d3             	add    rbx,r10
  6fd0cc:	44 8b 57 10          	mov    r10d,DWORD PTR [rdi+0x10]
  6fd0d0:	45 01 d2             	add    r10d,r10d
  6fd0d3:	4d 63 f2             	movsxd r14,r10d
  6fd0d6:	45 31 d2             	xor    r10d,r10d
  6fd0d9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  6fd0e0:	4c 0f bf 23          	movsx  r12,WORD PTR [rbx]
  6fd0e4:	4f 63 2c fb          	movsxd r13,DWORD PTR [r11+r15*8]
  6fd0e8:	4d 0f af ec          	imul   r13,r12
  6fd0ec:	4e 0f bf 24 33       	movsx  r12,WORD PTR [rbx+r14*1]
  6fd0f1:	4c 01 f3             	add    rbx,r14
  6fd0f4:	4c 01 f3             	add    rbx,r14
  6fd0f7:	4d 01 d5             	add    r13,r10
  6fd0fa:	4f 63 54 fb 04       	movsxd r10,DWORD PTR [r11+r15*8+0x4]
  6fd0ff:	49 ff c7             	inc    r15
  6fd102:	4d 0f af d4          	imul   r10,r12
  6fd106:	4d 01 ea             	add    r10,r13
  6fd109:	45 39 f9             	cmp    r9d,r15d
  6fd10c:	75 d2                	jne    0x6fd0e0
  6fd10e:	eb 03                	jmp    0x6fd113
  6fd110:	45 31 d2             	xor    r10d,r10d
  6fd113:	44 8b 4f 48          	mov    r9d,DWORD PTR [rdi+0x48]
  6fd117:	49 81 f9 00 00 00 02 	cmp    r9,0x2000000
  6fd11e:	0f 84 4c ff ff ff    	je     0x6fd070
  6fd124:	49 c1 fa 0e          	sar    r10,0xe
  6fd128:	4d 0f af d1          	imul   r10,r9
  6fd12c:	49 c1 fa 29          	sar    r10,0x29
  6fd130:	e9 3f ff ff ff       	jmp    0x6fd074
  6fd135:	5b                   	pop    rbx
  6fd136:	41 5c                	pop    r12
  6fd138:	41 5d                	pop    r13
  6fd13a:	41 5e                	pop    r14
  6fd13c:	41 5f                	pop    r15
  6fd13e:	5d                   	pop    rbp
  6fd13f:	c3                   	ret
  6fd140:	55                   	push   rbp
  6fd141:	48 89 e5             	mov    rbp,rsp
  6fd144:	8b 47 10             	mov    eax,DWORD PTR [rdi+0x10]
  6fd147:	8b 57 6c             	mov    edx,DWORD PTR [rdi+0x6c]
  6fd14a:	8b 4f 4c             	mov    ecx,DWORD PTR [rdi+0x4c]
  6fd14d:	0f af 4f 24          	imul   ecx,DWORD PTR [rdi+0x24]
  6fd151:	0f af d0             	imul   edx,eax
  6fd154:	c1 e2 02             	shl    edx,0x2
  6fd157:	c1 e9 16             	shr    ecx,0x16
  6fd15a:	48 63 d2             	movsxd rdx,edx
  6fd15d:	48 03 57 28          	add    rdx,QWORD PTR [rdi+0x28]
  6fd161:	8d 3c 85 00 00 00 00 	lea    edi,[rax*4+0x0]
  6fd168:	4c 63 c7             	movsxd r8,edi
  6fd16b:	48 89 d7             	mov    rdi,rdx
  6fd16e:	4c 29 c7             	sub    rdi,r8
  6fd171:	45 31 c0             	xor    r8d,r8d
  6fd174:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fd17b:	00 00 00 00 00 
  6fd180:	4e 63 0c 82          	movsxd r9,DWORD PTR [rdx+r8*4]
  6fd184:	4e 63 14 87          	movsxd r10,DWORD PTR [rdi+r8*4]
  6fd188:	4d 29 ca             	sub    r10,r9
  6fd18b:	4c 0f af d1          	imul   r10,rcx
  6fd18f:	49 c1 ea 08          	shr    r10,0x8
  6fd193:	45 01 ca             	add    r10d,r9d
  6fd196:	46 89 14 86          	mov    DWORD PTR [rsi+r8*4],r10d
  6fd19a:	49 ff c0             	inc    r8
  6fd19d:	44 39 c0             	cmp    eax,r8d
  6fd1a0:	75 de                	jne    0x6fd180
  6fd1a2:	5d                   	pop    rbp
  6fd1a3:	c3                   	ret
  6fd1a4:	90                   	nop
  6fd1a5:	90                   	nop
  6fd1a6:	90                   	nop
  6fd1a7:	90                   	nop
  6fd1a8:	90                   	nop
  6fd1a9:	90                   	nop
  6fd1aa:	90                   	nop
  6fd1ab:	90                   	nop
  6fd1ac:	90                   	nop
  6fd1ad:	90                   	nop
  6fd1ae:	90                   	nop
  6fd1af:	90                   	nop
  6fd1b0:	55                   	push   rbp
  6fd1b1:	48 89 e5             	mov    rbp,rsp
  6fd1b4:	41 57                	push   r15
  6fd1b6:	41 56                	push   r14
  6fd1b8:	41 55                	push   r13
  6fd1ba:	41 54                	push   r12
  6fd1bc:	53                   	push   rbx
  6fd1bd:	48 83 ec 30          	sub    rsp,0x30
  6fd1c1:	8b 57 6c             	mov    edx,DWORD PTR [rdi+0x6c]
  6fd1c4:	2b 57 60             	sub    edx,DWORD PTR [rdi+0x60]
  6fd1c7:	44 8b 5f 10          	mov    r11d,DWORD PTR [rdi+0x10]
  6fd1cb:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
  6fd1cf:	48 8b 4f 38          	mov    rcx,QWORD PTR [rdi+0x38]
  6fd1d3:	48 89 7d c0          	mov    QWORD PTR [rbp-0x40],rdi
  6fd1d7:	23 57 5c             	and    edx,DWORD PTR [rdi+0x5c]
  6fd1da:	41 c1 e3 02          	shl    r11d,0x2
  6fd1de:	4d 8d 04 33          	lea    r8,[r11+rsi*1]
  6fd1e2:	8d 72 01             	lea    esi,[rdx+0x1]
  6fd1e5:	c1 e2 02             	shl    edx,0x2
  6fd1e8:	89 75 d4             	mov    DWORD PTR [rbp-0x2c],esi
  6fd1eb:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  6fd1ef:	eb 5d                	jmp    0x6fd24e
  6fd1f1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fd1f8:	0f 1f 84 00 00 00 00 
  6fd1ff:	00 
  6fd200:	45 31 ed             	xor    r13d,r13d
  6fd203:	8b 57 48             	mov    edx,DWORD PTR [rdi+0x48]
  6fd206:	4c 89 ee             	mov    rsi,r13
  6fd209:	49 83 c0 fc          	add    r8,0xfffffffffffffffc
  6fd20d:	48 0f af f2          	imul   rsi,rdx
  6fd211:	48 c1 fe 19          	sar    rsi,0x19
  6fd215:	48 81 fa 00 00 00 02 	cmp    rdx,0x2000000
  6fd21c:	48 c7 c2 00 00 00 80 	mov    rdx,0xffffffff80000000
  6fd223:	49 0f 44 f5          	cmove  rsi,r13
  6fd227:	48 81 fe 01 00 00 80 	cmp    rsi,0xffffffff80000001
  6fd22e:	48 0f 4c f2          	cmovl  rsi,rdx
  6fd232:	ba ff ff ff 7f       	mov    edx,0x7fffffff
  6fd237:	48 81 fe ff ff ff 7f 	cmp    rsi,0x7fffffff
  6fd23e:	48 0f 4d f2          	cmovge rsi,rdx
  6fd242:	41 89 30             	mov    DWORD PTR [r8],esi
  6fd245:	4d 85 db             	test   r11,r11
  6fd248:	0f 84 85 01 00 00    	je     0x6fd3d3
  6fd24e:	8b 57 60             	mov    edx,DWORD PTR [rdi+0x60]
  6fd251:	41 83 c3 fc          	add    r11d,0xfffffffc
  6fd255:	85 d2                	test   edx,edx
  6fd257:	74 a7                	je     0x6fd200
  6fd259:	8b 77 10             	mov    esi,DWORD PTR [rdi+0x10]
  6fd25c:	44 8b 4f 5c          	mov    r9d,DWORD PTR [rdi+0x5c]
  6fd260:	44 23 4d d4          	and    r9d,DWORD PTR [rbp-0x2c]
  6fd264:	44 8b 57 4c          	mov    r10d,DWORD PTR [rdi+0x4c]
  6fd268:	44 0f af 57 24       	imul   r10d,DWORD PTR [rdi+0x24]
  6fd26d:	4c 8b 77 28          	mov    r14,QWORD PTR [rdi+0x28]
  6fd271:	44 8b 7f 50          	mov    r15d,DWORD PTR [rdi+0x50]
  6fd275:	4c 89 45 b0          	mov    QWORD PTR [rbp-0x50],r8
  6fd279:	89 d3                	mov    ebx,edx
  6fd27b:	4c 89 5d a8          	mov    QWORD PTR [rbp-0x58],r11
  6fd27f:	45 31 ed             	xor    r13d,r13d
  6fd282:	48 89 75 b8          	mov    QWORD PTR [rbp-0x48],rsi
  6fd286:	8d 34 b5 00 00 00 00 	lea    esi,[rsi*4+0x0]
  6fd28d:	44 0f af ce          	imul   r9d,esi
  6fd291:	4c 63 e6             	movsxd r12,esi
  6fd294:	44 89 55 d0          	mov    DWORD PTR [rbp-0x30],r10d
  6fd298:	4d 01 f1             	add    r9,r14
  6fd29b:	4d 01 d9             	add    r9,r11
  6fd29e:	45 31 c0             	xor    r8d,r8d
  6fd2a1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  6fd2a8:	0f 1f 84 00 00 00 00 
  6fd2af:	00 
  6fd2b0:	45 89 d3             	mov    r11d,r10d
  6fd2b3:	41 81 e2 ff ff ff 01 	and    r10d,0x1ffffff
  6fd2ba:	4b 63 34 21          	movsxd rsi,DWORD PTR [r9+r12*1]
  6fd2be:	41 c1 fb 19          	sar    r11d,0x19
  6fd2c2:	44 89 d7             	mov    edi,r10d
  6fd2c5:	45 01 fa             	add    r10d,r15d
  6fd2c8:	45 01 c3             	add    r11d,r8d
  6fd2cb:	c1 ef 0e             	shr    edi,0xe
  6fd2ce:	4d 63 01             	movsxd r8,DWORD PTR [r9]
  6fd2d1:	4d 01 e1             	add    r9,r12
  6fd2d4:	42 0f af 3c 99       	imul   edi,DWORD PTR [rcx+r11*4]
  6fd2d9:	4d 01 e1             	add    r9,r12
  6fd2dc:	c1 ff 05             	sar    edi,0x5
  6fd2df:	42                   	rex.X


; ===== SUPPLEMENTAL GNU objdump FULL backward CPU-mode helper bytes =====
; {"path": "/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin", "rva": "0x6f8910", "sha256": "52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f", "size": 2584, "kernel_offset": "0x6f8910"}

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin:     file format binary


Disassembly of section .data:

00000000006f8910 <.data>:
  6f8910:	55                   	push   rbp
  6f8911:	48 89 e5             	mov    rbp,rsp
  6f8914:	41 57                	push   r15
  6f8916:	41 56                	push   r14
  6f8918:	41 55                	push   r13
  6f891a:	41 54                	push   r12
  6f891c:	53                   	push   rbx
  6f891d:	48 83 ec 28          	sub    rsp,0x28
  6f8921:	4c 8d 2d e8 39 22 03 	lea    r13,[rip+0x32239e8]        # 0x391c310
  6f8928:	89 fb                	mov    ebx,edi
  6f892a:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  6f892e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  6f8932:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  6f8939:	00 00 
  6f893b:	83 3d c6 2a b0 01 00 	cmp    DWORD PTR [rip+0x1b02ac6],0x0        # 0x21fb408
  6f8942:	0f 85 c2 08 00 00    	jne    0x6f920a
  6f8948:	8b 05 76 2a b0 01    	mov    eax,DWORD PTR [rip+0x1b02a76]        # 0x21fb3c4
  6f894e:	83 f8 01             	cmp    eax,0x1
  6f8951:	75 0d                	jne    0x6f8960
  6f8953:	83 3d 76 2a b0 01 00 	cmp    DWORD PTR [rip+0x1b02a76],0x0        # 0x21fb3d0
  6f895a:	0f 84 7c 02 00 00    	je     0x6f8bdc
  6f8960:	48 8d 3d 31 38 22 03 	lea    rdi,[rip+0x3223831]        # 0x391c198
  6f8967:	45 31 e4             	xor    r12d,r12d
  6f896a:	31 f6                	xor    esi,esi
  6f896c:	31 d2                	xor    edx,edx
  6f896e:	31 c9                	xor    ecx,ecx
  6f8970:	e8 1b e8 dc ff       	call   0x4c7190
  6f8975:	48 8d 15 96 13 b8 00 	lea    rdx,[rip+0xb81396]        # 0x1279d12
  6f897c:	4c 89 f7             	mov    rdi,r14
  6f897f:	b9 84 04 00 00       	mov    ecx,0x484
  6f8984:	31 f6                	xor    esi,esi
  6f8986:	e8 25 ef dc ff       	call   0x4c78b0
  6f898b:	83 fb 02             	cmp    ebx,0x2
  6f898e:	75 3c                	jne    0x6f89cc
  6f8990:	80 3d 99 38 22 03 01 	cmp    BYTE PTR [rip+0x3223899],0x1        # 0x391c230
  6f8997:	0f 85 10 02 00 00    	jne    0x6f8bad
  6f899d:	83 3d 24 2a b0 01 00 	cmp    DWORD PTR [rip+0x1b02a24],0x0        # 0x21fb3c8
  6f89a4:	0f 84 03 02 00 00    	je     0x6f8bad
  6f89aa:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6f89b1:	00 
  6f89b2:	83 f8 03             	cmp    eax,0x3
  6f89b5:	0f 85 f2 01 00 00    	jne    0x6f8bad
  6f89bb:	8b 05 0f 2a b0 01    	mov    eax,DWORD PTR [rip+0x1b02a0f]        # 0x21fb3d0
  6f89c1:	45 31 e4             	xor    r12d,r12d
  6f89c4:	45 31 ff             	xor    r15d,r15d
  6f89c7:	e9 86 02 00 00       	jmp    0x6f8c52
  6f89cc:	8b 05 fe 29 b0 01    	mov    eax,DWORD PTR [rip+0x1b029fe]        # 0x21fb3d0
  6f89d2:	83 fb 01             	cmp    ebx,0x1
  6f89d5:	41 0f 94 c7          	sete   r15b
  6f89d9:	0f 85 73 02 00 00    	jne    0x6f8c52
  6f89df:	b9 00 00 00 00       	mov    ecx,0x0
  6f89e4:	85 c0                	test   eax,eax
  6f89e6:	0f 84 68 02 00 00    	je     0x6f8c54
  6f89ec:	8b 05 e2 29 b0 01    	mov    eax,DWORD PTR [rip+0x1b029e2]        # 0x21fb3d4
  6f89f2:	83 f8 01             	cmp    eax,0x1
  6f89f5:	75 76                	jne    0x6f8a6d
  6f89f7:	48 8d 3d ae 84 bc 00 	lea    rdi,[rip+0xbc84ae]        # 0x12c0eac
  6f89fe:	31 c0                	xor    eax,eax
  6f8a00:	e8 0b 4a b6 ff       	call   0x25d410
  6f8a05:	31 ff                	xor    edi,edi
  6f8a07:	c7 05 c3 29 b0 01 00 	mov    DWORD PTR [rip+0x1b029c3],0x0        # 0x21fb3d4
  6f8a0e:	00 00 00 
  6f8a11:	e8 6a f4 fb ff       	call   0x6b7e80
  6f8a16:	4c 8d 3d 9b 37 22 03 	lea    r15,[rip+0x322379b]        # 0x391c1b8
  6f8a1d:	31 f6                	xor    esi,esi
  6f8a1f:	31 d2                	xor    edx,edx
  6f8a21:	31 c9                	xor    ecx,ecx
  6f8a23:	4c 89 ff             	mov    rdi,r15
  6f8a26:	e8 65 e7 dc ff       	call   0x4c7190
  6f8a2b:	48 8d 3d b6 37 22 03 	lea    rdi,[rip+0x32237b6]        # 0x391c1e8
  6f8a32:	e8 f9 eb 3c 00       	call   0xac7630
  6f8a37:	48 8d 3d ba 29 b0 01 	lea    rdi,[rip+0x1b029ba]        # 0x21fb3f8
  6f8a3e:	be 10 00 00 00       	mov    esi,0x10
  6f8a43:	c7 05 a3 29 b0 01 00 	mov    DWORD PTR [rip+0x1b029a3],0x0        # 0x21fb3f0
  6f8a4a:	00 00 00 
  6f8a4d:	e8 9e 05 b6 ff       	call   0x258ff0
  6f8a52:	4c 89 ff             	mov    rdi,r15
  6f8a55:	31 f6                	xor    esi,esi
  6f8a57:	31 d2                	xor    edx,edx
  6f8a59:	31 c9                	xor    ecx,ecx
  6f8a5b:	e8 c0 ea dc ff       	call   0x4c7520
  6f8a60:	83 3d a1 29 b0 01 00 	cmp    DWORD PTR [rip+0x1b029a1],0x0        # 0x21fb408
  6f8a67:	0f 85 e4 07 00 00    	jne    0x6f9251
  6f8a6d:	4c 8d 3d 44 37 22 03 	lea    r15,[rip+0x3223744]        # 0x391c1b8
  6f8a74:	31 f6                	xor    esi,esi
  6f8a76:	31 d2                	xor    edx,edx
  6f8a78:	31 c9                	xor    ecx,ecx
  6f8a7a:	4c 89 ff             	mov    rdi,r15
  6f8a7d:	e8 0e e7 dc ff       	call   0x4c7190
  6f8a82:	4c 89 ff             	mov    rdi,r15
  6f8a85:	c7 05 61 29 b0 01 01 	mov    DWORD PTR [rip+0x1b02961],0x1        # 0x21fb3f0
  6f8a8c:	00 00 00 
  6f8a8f:	31 f6                	xor    esi,esi
  6f8a91:	31 d2                	xor    edx,edx
  6f8a93:	31 c9                	xor    ecx,ecx
  6f8a95:	e8 86 ea dc ff       	call   0x4c7520
  6f8a9a:	83 3d 67 29 b0 01 00 	cmp    DWORD PTR [rip+0x1b02967],0x0        # 0x21fb408
  6f8aa1:	0f 85 99 07 00 00    	jne    0x6f9240
  6f8aa7:	bf 01 00 00 00       	mov    edi,0x1
  6f8aac:	e8 cf f3 fb ff       	call   0x6b7e80
  6f8ab1:	c7 05 19 29 b0 01 01 	mov    DWORD PTR [rip+0x1b02919],0x1        # 0x21fb3d4
  6f8ab8:	00 00 00 
  6f8abb:	85 c0                	test   eax,eax
  6f8abd:	0f 85 b6 00 00 00    	jne    0x6f8b79
  6f8ac3:	41 89 dc             	mov    r12d,ebx
  6f8ac6:	48 bb 42 08 fd 4c bd 	movabs rbx,0x116ebd4cfd0842
  6f8acd:	6e 11 00 
  6f8ad0:	48 8d 3d e1 36 22 03 	lea    rdi,[rip+0x32236e1]        # 0x391c1b8
  6f8ad7:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8ade:	00 
  6f8adf:	31 f6                	xor    esi,esi
  6f8ae1:	31 d2                	xor    edx,edx
  6f8ae3:	31 c9                	xor    ecx,ecx
  6f8ae5:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  6f8ae9:	e8 a2 e6 dc ff       	call   0x4c7190
  6f8aee:	48 8d 3d 03 29 b0 01 	lea    rdi,[rip+0x1b02903]        # 0x21fb3f8
  6f8af5:	e8 06 67 3d 00       	call   0xacf200
  6f8afa:	48 8b 05 ff 28 b0 01 	mov    rax,QWORD PTR [rip+0x1b028ff]        # 0x21fb400
  6f8b01:	48 b9 bd f7 02 b3 42 	movabs rcx,0xffee9142b302f7bd
  6f8b08:	91 ee ff 
  6f8b0b:	31 d2                	xor    edx,edx
  6f8b0d:	4c 8d 3d d4 36 22 03 	lea    r15,[rip+0x32236d4]        # 0x391c1e8
  6f8b14:	4c 89 ff             	mov    rdi,r15
  6f8b17:	48 01 c3             	add    rbx,rax
  6f8b1a:	48 39 c8             	cmp    rax,rcx
  6f8b1d:	0f 97 c2             	seta   dl
  6f8b20:	48 89 1d d9 28 b0 01 	mov    QWORD PTR [rip+0x1b028d9],rbx        # 0x21fb400
  6f8b27:	48 01 15 ca 28 b0 01 	add    QWORD PTR [rip+0x1b028ca],rdx        # 0x21fb3f8
  6f8b2e:	e8 fd ea 3c 00       	call   0xac7630
  6f8b33:	48 8d 05 9e ec b6 ff 	lea    rax,[rip+0xffffffffffb6ec9e]        # 0x2677d8
  6f8b3a:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  6f8b3e:	4c 89 ff             	mov    rdi,r15
  6f8b41:	c7 05 dd 36 22 03 01 	mov    DWORD PTR [rip+0x32236dd],0x1        # 0x391c228
  6f8b48:	00 00 00 
  6f8b4b:	48 89 05 c6 36 22 03 	mov    QWORD PTR [rip+0x32236c6],rax        # 0x391c218
  6f8b52:	e8 19 e9 3c 00       	call   0xac7470
  6f8b57:	83 3d aa 28 b0 01 00 	cmp    DWORD PTR [rip+0x1b028aa],0x0        # 0x21fb408
  6f8b5e:	0f 85 02 07 00 00    	jne    0x6f9266
  6f8b64:	48 8d 3d 4d 36 22 03 	lea    rdi,[rip+0x322364d]        # 0x391c1b8
  6f8b6b:	31 f6                	xor    esi,esi
  6f8b6d:	31 d2                	xor    edx,edx
  6f8b6f:	31 c9                	xor    ecx,ecx
  6f8b71:	e8 aa e9 dc ff       	call   0x4c7520
  6f8b76:	44 89 e3             	mov    ebx,r12d
  6f8b79:	8b 05 45 28 b0 01    	mov    eax,DWORD PTR [rip+0x1b02845]        # 0x21fb3c4
  6f8b7f:	83 f8 01             	cmp    eax,0x1
  6f8b82:	75 0f                	jne    0x6f8b93
  6f8b84:	8b 05 36 28 b0 01    	mov    eax,DWORD PTR [rip+0x1b02836]        # 0x21fb3c0
  6f8b8a:	83 f8 01             	cmp    eax,0x1
  6f8b8d:	0f 85 92 02 00 00    	jne    0x6f8e25
  6f8b93:	b9 01 00 00 00       	mov    ecx,0x1
  6f8b98:	41 b7 01             	mov    r15b,0x1
  6f8b9b:	41 bc 01 00 00 00    	mov    r12d,0x1
  6f8ba1:	c6 05 8c 36 22 03 01 	mov    BYTE PTR [rip+0x322368c],0x1        # 0x391c234
  6f8ba8:	e9 a7 00 00 00       	jmp    0x6f8c54
  6f8bad:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  6f8bb0:	31 f6                	xor    esi,esi
  6f8bb2:	31 d2                	xor    edx,edx
  6f8bb4:	31 c9                	xor    ecx,ecx
  6f8bb6:	48 83 c7 18          	add    rdi,0x18
  6f8bba:	e8 61 e9 dc ff       	call   0x4c7520
  6f8bbf:	48 8d 3d d2 35 22 03 	lea    rdi,[rip+0x32235d2]        # 0x391c198
  6f8bc6:	31 f6                	xor    esi,esi
  6f8bc8:	31 d2                	xor    edx,edx
  6f8bca:	31 c9                	xor    ecx,ecx
  6f8bcc:	e8 4f e9 dc ff       	call   0x4c7520
  6f8bd1:	41 bf ff ff ff ff    	mov    r15d,0xffffffff
  6f8bd7:	e9 d5 05 00 00       	jmp    0x6f91b1
  6f8bdc:	8b 05 de 27 b0 01    	mov    eax,DWORD PTR [rip+0x1b027de]        # 0x21fb3c0
  6f8be2:	83 f8 01             	cmp    eax,0x1
  6f8be5:	0f 85 21 02 00 00    	jne    0x6f8e0c
  6f8beb:	80 3d 86 35 22 03 01 	cmp    BYTE PTR [rip+0x3223586],0x1        # 0x391c178
  6f8bf2:	0f 85 68 fd ff ff    	jne    0x6f8960
  6f8bf8:	83 fb 01             	cmp    ebx,0x1
  6f8bfb:	0f 85 c8 03 00 00    	jne    0x6f8fc9
  6f8c01:	48 8d 15 0a 11 b8 00 	lea    rdx,[rip+0xb8110a]        # 0x1279d12
  6f8c08:	4c 89 f7             	mov    rdi,r14
  6f8c0b:	b9 71 04 00 00       	mov    ecx,0x471
  6f8c10:	31 f6                	xor    esi,esi
  6f8c12:	45 31 ff             	xor    r15d,r15d
  6f8c15:	e8 96 ec dc ff       	call   0x4c78b0
  6f8c1a:	83 3d 1f 36 22 03 00 	cmp    DWORD PTR [rip+0x322361f],0x0        # 0x391c240
  6f8c21:	74 13                	je     0x6f8c36
  6f8c23:	48 8b 3d 0e 36 22 03 	mov    rdi,QWORD PTR [rip+0x322360e]        # 0x391c238
  6f8c2a:	48 8d 35 7f 28 b0 01 	lea    rsi,[rip+0x1b0287f]        # 0x21fb4b0
  6f8c31:	e8 7a 1d df ff       	call   0x4ea9b0
  6f8c36:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  6f8c39:	31 f6                	xor    esi,esi
  6f8c3b:	31 d2                	xor    edx,edx
  6f8c3d:	31 c9                	xor    ecx,ecx
  6f8c3f:	48 83 c7 18          	add    rdi,0x18
  6f8c43:	e8 d8 e8 dc ff       	call   0x4c7520
  6f8c48:	e8 33 b5 1c 00       	call   0x8c4180
  6f8c4d:	e9 5f 05 00 00       	jmp    0x6f91b1
  6f8c52:	31 c9                	xor    ecx,ecx
  6f8c54:	83 3d 69 27 b0 01 00 	cmp    DWORD PTR [rip+0x1b02769],0x0        # 0x21fb3c4
  6f8c5b:	89 5d b8             	mov    DWORD PTR [rbp-0x48],ebx
  6f8c5e:	74 0b                	je     0x6f8c6b
  6f8c60:	8b 05 5a 27 b0 01    	mov    eax,DWORD PTR [rip+0x1b0275a]        # 0x21fb3c0
  6f8c66:	83 f8 01             	cmp    eax,0x1
  6f8c69:	75 7c                	jne    0x6f8ce7
  6f8c6b:	83 3d 56 27 b0 01 00 	cmp    DWORD PTR [rip+0x1b02756],0x0        # 0x21fb3c8
  6f8c72:	74 7b                	je     0x6f8cef
  6f8c74:	80 3d b5 35 22 03 00 	cmp    BYTE PTR [rip+0x32235b5],0x0        # 0x391c230
  6f8c7b:	0f 84 d2 00 00 00    	je     0x6f8d53
  6f8c81:	48 8d 3d f8 35 22 03 	lea    rdi,[rip+0x32235f8]        # 0x391c280
  6f8c88:	c7 05 36 27 b0 01 00 	mov    DWORD PTR [rip+0x1b02736],0x0        # 0x21fb3c8
  6f8c8f:	00 00 00 
  6f8c92:	e8 99 e9 3c 00       	call   0xac7630
  6f8c97:	8b 05 27 27 b0 01    	mov    eax,DWORD PTR [rip+0x1b02727]        # 0x21fb3c4
  6f8c9d:	83 f8 01             	cmp    eax,0x1
  6f8ca0:	0f 85 9b 01 00 00    	jne    0x6f8e41
  6f8ca6:	48 63 05 3f 27 b0 01 	movsxd rax,DWORD PTR [rip+0x1b0273f]        # 0x21fb3ec
  6f8cad:	48 8d 0d 1c eb b6 ff 	lea    rcx,[rip+0xffffffffffb6eb1c]        # 0x2677d0
  6f8cb4:	c7 05 02 36 22 03 01 	mov    DWORD PTR [rip+0x3223602],0x1        # 0x391c2c0
  6f8cbb:	00 00 00 
  6f8cbe:	48 8d 3d bb 35 22 03 	lea    rdi,[rip+0x32235bb]        # 0x391c280
  6f8cc5:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8ccc:	00 
  6f8ccd:	48 89 0d dc 35 22 03 	mov    QWORD PTR [rip+0x32235dc],rcx        # 0x391c2b0
  6f8cd4:	48 b9 ed b5 a0 f7 c6 	movabs rcx,0x10c6f7a0b5ed
  6f8cdb:	10 00 00 
  6f8cde:	48 0f af c8          	imul   rcx,rax
  6f8ce2:	e9 8b 01 00 00       	jmp    0x6f8e72
  6f8ce7:	89 4d bc             	mov    DWORD PTR [rbp-0x44],ecx
  6f8cea:	e9 6b 03 00 00       	jmp    0x6f905a
  6f8cef:	85 db                	test   ebx,ebx
  6f8cf1:	0f 84 18 02 00 00    	je     0x6f8f0f
  6f8cf7:	48 8d 3d 82 35 22 03 	lea    rdi,[rip+0x3223582]        # 0x391c280
  6f8cfe:	e8 2d e9 3c 00       	call   0xac7630
  6f8d03:	8b 05 bb 26 b0 01    	mov    eax,DWORD PTR [rip+0x1b026bb]        # 0x21fb3c4
  6f8d09:	83 f8 01             	cmp    eax,0x1
  6f8d0c:	0f 85 66 02 00 00    	jne    0x6f8f78
  6f8d12:	48 63 05 d3 26 b0 01 	movsxd rax,DWORD PTR [rip+0x1b026d3]        # 0x21fb3ec
  6f8d19:	48 8d 0d b0 ea b6 ff 	lea    rcx,[rip+0xffffffffffb6eab0]        # 0x2677d0
  6f8d20:	c7 05 96 35 22 03 01 	mov    DWORD PTR [rip+0x3223596],0x1        # 0x391c2c0
  6f8d27:	00 00 00 
  6f8d2a:	48 8d 3d 4f 35 22 03 	lea    rdi,[rip+0x322354f]        # 0x391c280
  6f8d31:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8d38:	00 
  6f8d39:	48 89 0d 70 35 22 03 	mov    QWORD PTR [rip+0x3223570],rcx        # 0x391c2b0
  6f8d40:	48 b9 ed b5 a0 f7 c6 	movabs rcx,0x10c6f7a0b5ed
  6f8d47:	10 00 00 
  6f8d4a:	48 0f af c8          	imul   rcx,rax
  6f8d4e:	e9 56 02 00 00       	jmp    0x6f8fa9
  6f8d53:	48 8d 3d 26 35 22 03 	lea    rdi,[rip+0x3223526]        # 0x391c280
  6f8d5a:	89 4d bc             	mov    DWORD PTR [rbp-0x44],ecx
  6f8d5d:	e8 ce e8 3c 00       	call   0xac7630
  6f8d62:	e8 69 eb 40 00       	call   0xb078d0
  6f8d67:	85 c0                	test   eax,eax
  6f8d69:	74 39                	je     0x6f8da4
  6f8d6b:	83 3d 8e 72 5b 02 00 	cmp    DWORD PTR [rip+0x25b728e],0x0        # 0x2cb0000
  6f8d72:	74 30                	je     0x6f8da4
  6f8d74:	f6 05 45 34 22 03 01 	test   BYTE PTR [rip+0x3223445],0x1        # 0x391c1c0
  6f8d7b:	74 27                	je     0x6f8da4
  6f8d7d:	4c 8b 2d 64 db 4f 03 	mov    r13,QWORD PTR [rip+0x34fdb64]        # 0x3bf68e8
  6f8d84:	48 8d 05 c5 29 b7 ff 	lea    rax,[rip+0xffffffffffb729c5]        # 0x26b750
  6f8d8b:	4c 29 e8             	sub    rax,r13
  6f8d8e:	48 c1 c8 03          	ror    rax,0x3
  6f8d92:	48 83 f8 08          	cmp    rax,0x8
  6f8d96:	0f 87 db 04 00 00    	ja     0x6f9277
  6f8d9c:	bf 02 00 00 00       	mov    edi,0x2
  6f8da1:	41 ff d5             	call   r13
  6f8da4:	48 8d 05 25 ea b6 ff 	lea    rax,[rip+0xffffffffffb6ea25]        # 0x2677d0
  6f8dab:	c7 05 0b 35 22 03 01 	mov    DWORD PTR [rip+0x322350b],0x1        # 0x391c2c0
  6f8db2:	00 00 00 
  6f8db5:	48 8d 3d c4 34 22 03 	lea    rdi,[rip+0x32234c4]        # 0x391c280
  6f8dbc:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  6f8dc0:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8dc7:	00 
  6f8dc8:	48 89 05 e1 34 22 03 	mov    QWORD PTR [rip+0x32234e1],rax        # 0x391c2b0
  6f8dcf:	48 b8 94 10 c7 ba b8 	movabs rax,0x68db8bac71094
  6f8dd6:	8d 06 00 
  6f8dd9:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  6f8ddd:	e8 8e e6 3c 00       	call   0xac7470
  6f8de2:	c6 05 47 34 22 03 01 	mov    BYTE PTR [rip+0x3223447],0x1        # 0x391c230
  6f8de9:	44 88 3d 44 34 22 03 	mov    BYTE PTR [rip+0x3223444],r15b        # 0x391c234
  6f8df0:	45 31 ed             	xor    r13d,r13d
  6f8df3:	31 f6                	xor    esi,esi
  6f8df5:	31 d2                	xor    edx,edx
  6f8df7:	31 c9                	xor    ecx,ecx
  6f8df9:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  6f8dfc:	48 83 c7 18          	add    rdi,0x18
  6f8e00:	e8 1b e7 dc ff       	call   0x4c7520
  6f8e05:	31 db                	xor    ebx,ebx
  6f8e07:	e9 ac 02 00 00       	jmp    0x6f90b8
  6f8e0c:	41 bf ff ff ff ff    	mov    r15d,0xffffffff
  6f8e12:	83 fb 01             	cmp    ebx,0x1
  6f8e15:	0f 85 96 03 00 00    	jne    0x6f91b1
  6f8e1b:	e8 60 b3 1c 00       	call   0x8c4180
  6f8e20:	e9 8c 03 00 00       	jmp    0x6f91b1
  6f8e25:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6f8e2c:	00 
  6f8e2d:	85 c0                	test   eax,eax
  6f8e2f:	0f 84 9c 03 00 00    	je     0x6f91d1
  6f8e35:	31 ff                	xor    edi,edi
  6f8e37:	e8 c4 dd fb ff       	call   0x6b6c00
  6f8e3c:	e9 98 03 00 00       	jmp    0x6f91d9
  6f8e41:	48 8d 3d 38 34 22 03 	lea    rdi,[rip+0x3223438]        # 0x391c280
  6f8e48:	48 8d 05 81 e9 b6 ff 	lea    rax,[rip+0xffffffffffb6e981]        # 0x2677d0
  6f8e4f:	48 b9 c0 1b 53 05 a3 	movabs rcx,0x13a92a305531bc0
  6f8e56:	92 3a 01 
  6f8e59:	c7 05 5d 34 22 03 01 	mov    DWORD PTR [rip+0x322345d],0x1        # 0x391c2c0
  6f8e60:	00 00 00 
  6f8e63:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8e6a:	00 
  6f8e6b:	48 89 05 3e 34 22 03 	mov    QWORD PTR [rip+0x322343e],rax        # 0x391c2b0
  6f8e72:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
  6f8e76:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  6f8e7a:	e8 f1 e5 3c 00       	call   0xac7470
  6f8e7f:	e8 4c ea 40 00       	call   0xb078d0
  6f8e84:	85 c0                	test   eax,eax
  6f8e86:	0f 94 c1             	sete   cl
  6f8e89:	83 3d 70 71 5b 02 00 	cmp    DWORD PTR [rip+0x25b7170],0x0        # 0x2cb0000
  6f8e90:	0f 94 c0             	sete   al
  6f8e93:	08 c8                	or     al,cl
  6f8e95:	83 fb 02             	cmp    ebx,0x2
  6f8e98:	75 2a                	jne    0x6f8ec4
  6f8e9a:	84 c0                	test   al,al
  6f8e9c:	75 4e                	jne    0x6f8eec
  6f8e9e:	4c 8b 2d 43 da 4f 03 	mov    r13,QWORD PTR [rip+0x34fda43]        # 0x3bf68e8
  6f8ea5:	48 8d 05 a4 28 b7 ff 	lea    rax,[rip+0xffffffffffb728a4]        # 0x26b750
  6f8eac:	4c 29 e8             	sub    rax,r13
  6f8eaf:	48 c1 c8 03          	ror    rax,0x3
  6f8eb3:	48 83 f8 08          	cmp    rax,0x8
  6f8eb7:	0f 87 ce 03 00 00    	ja     0x6f928b
  6f8ebd:	bf 03 00 00 00       	mov    edi,0x3
  6f8ec2:	eb 25                	jmp    0x6f8ee9
  6f8ec4:	84 c0                	test   al,al
  6f8ec6:	75 24                	jne    0x6f8eec
  6f8ec8:	4c 8b 2d 19 da 4f 03 	mov    r13,QWORD PTR [rip+0x34fda19]        # 0x3bf68e8
  6f8ecf:	48 8d 05 7a 28 b7 ff 	lea    rax,[rip+0xffffffffffb7287a]        # 0x26b750
  6f8ed6:	4c 29 e8             	sub    rax,r13
  6f8ed9:	48 c1 c8 03          	ror    rax,0x3
  6f8edd:	48 83 f8 08          	cmp    rax,0x8
  6f8ee1:	0f 87 b8 03 00 00    	ja     0x6f929f
  6f8ee7:	31 ff                	xor    edi,edi
  6f8ee9:	41 ff d5             	call   r13
  6f8eec:	c6 05 3d 33 22 03 00 	mov    BYTE PTR [rip+0x322333d],0x0        # 0x391c230
  6f8ef3:	c7 45 bc 01 00 00 00 	mov    DWORD PTR [rbp-0x44],0x1
  6f8efa:	45 84 ff             	test   r15b,r15b
  6f8efd:	0f 84 57 01 00 00    	je     0x6f905a
  6f8f03:	c6 05 2a 33 22 03 01 	mov    BYTE PTR [rip+0x322332a],0x1        # 0x391c234
  6f8f0a:	e9 4b 01 00 00       	jmp    0x6f905a
  6f8f0f:	48 8d 3d 6a 33 22 03 	lea    rdi,[rip+0x322336a]        # 0x391c280
  6f8f16:	89 4d bc             	mov    DWORD PTR [rbp-0x44],ecx
  6f8f19:	c7 05 a5 24 b0 01 01 	mov    DWORD PTR [rip+0x1b024a5],0x1        # 0x21fb3c8
  6f8f20:	00 00 00 
  6f8f23:	e8 08 e7 3c 00       	call   0xac7630
  6f8f28:	8b 05 96 24 b0 01    	mov    eax,DWORD PTR [rip+0x1b02496]        # 0x21fb3c4
  6f8f2e:	83 f8 01             	cmp    eax,0x1
  6f8f31:	0f 85 ac 00 00 00    	jne    0x6f8fe3
  6f8f37:	48 63 05 aa 24 b0 01 	movsxd rax,DWORD PTR [rip+0x1b024aa]        # 0x21fb3e8
  6f8f3e:	48 8d 0d 8b e8 b6 ff 	lea    rcx,[rip+0xffffffffffb6e88b]        # 0x2677d0
  6f8f45:	c7 05 71 33 22 03 01 	mov    DWORD PTR [rip+0x3223371],0x1        # 0x391c2c0
  6f8f4c:	00 00 00 
  6f8f4f:	48 8d 3d 2a 33 22 03 	lea    rdi,[rip+0x322332a]        # 0x391c280
  6f8f56:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8f5d:	00 
  6f8f5e:	48 89 0d 4b 33 22 03 	mov    QWORD PTR [rip+0x322334b],rcx        # 0x391c2b0
  6f8f65:	48 b9 ed b5 a0 f7 c6 	movabs rcx,0x10c6f7a0b5ed
  6f8f6c:	10 00 00 
  6f8f6f:	48 0f af c8          	imul   rcx,rax
  6f8f73:	e9 9c 00 00 00       	jmp    0x6f9014
  6f8f78:	48 8d 3d 01 33 22 03 	lea    rdi,[rip+0x3223301]        # 0x391c280
  6f8f7f:	48 8d 05 4a e8 b6 ff 	lea    rax,[rip+0xffffffffffb6e84a]        # 0x2677d0
  6f8f86:	48 b9 c0 1b 53 05 a3 	movabs rcx,0x13a92a305531bc0
  6f8f8d:	92 3a 01 
  6f8f90:	c7 05 26 33 22 03 01 	mov    DWORD PTR [rip+0x3223326],0x1        # 0x391c2c0
  6f8f97:	00 00 00 
  6f8f9a:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f8fa1:	00 
  6f8fa2:	48 89 05 07 33 22 03 	mov    QWORD PTR [rip+0x3223307],rax        # 0x391c2b0
  6f8fa9:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
  6f8fad:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  6f8fb1:	e8 ba e4 3c 00       	call   0xac7470
  6f8fb6:	c6 05 77 32 22 03 01 	mov    BYTE PTR [rip+0x3223277],0x1        # 0x391c234
  6f8fbd:	c7 45 bc 01 00 00 00 	mov    DWORD PTR [rbp-0x44],0x1
  6f8fc4:	e9 91 00 00 00       	jmp    0x6f905a
  6f8fc9:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6f8fd0:	00 
  6f8fd1:	45 31 ff             	xor    r15d,r15d
  6f8fd4:	83 f8 03             	cmp    eax,0x3
  6f8fd7:	41 0f 95 c7          	setne  r15b
  6f8fdb:	41 f7 df             	neg    r15d
  6f8fde:	e9 ce 01 00 00       	jmp    0x6f91b1
  6f8fe3:	48 8d 3d 96 32 22 03 	lea    rdi,[rip+0x3223296]        # 0x391c280
  6f8fea:	48 8d 05 df e7 b6 ff 	lea    rax,[rip+0xffffffffffb6e7df]        # 0x2677d0
  6f8ff1:	48 b9 71 c6 9a 91 41 	movabs rcx,0x22ee41919ac671
  6f8ff8:	ee 22 00 
  6f8ffb:	c7 05 bb 32 22 03 01 	mov    DWORD PTR [rip+0x32232bb],0x1        # 0x391c2c0
  6f9002:	00 00 00 
  6f9005:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  6f900c:	00 
  6f900d:	48 89 05 9c 32 22 03 	mov    QWORD PTR [rip+0x322329c],rax        # 0x391c2b0
  6f9014:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
  6f9018:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  6f901c:	e8 4f e4 3c 00       	call   0xac7470
  6f9021:	e8 aa e8 40 00       	call   0xb078d0
  6f9026:	85 c0                	test   eax,eax
  6f9028:	74 30                	je     0x6f905a
  6f902a:	83 3d cf 6f 5b 02 00 	cmp    DWORD PTR [rip+0x25b6fcf],0x0        # 0x2cb0000
  6f9031:	74 27                	je     0x6f905a
  6f9033:	4c 8b 3d ae d8 4f 03 	mov    r15,QWORD PTR [rip+0x34fd8ae]        # 0x3bf68e8
  6f903a:	48 8d 05 0f 27 b7 ff 	lea    rax,[rip+0xffffffffffb7270f]        # 0x26b750
  6f9041:	4c 29 f8             	sub    rax,r15
  6f9044:	48 c1 c8 03          	ror    rax,0x3
  6f9048:	48 83 f8 08          	cmp    rax,0x8
  6f904c:	0f 87 61 02 00 00    	ja     0x6f92b3
  6f9052:	bf 01 00 00 00       	mov    edi,0x1
  6f9057:	41 ff d7             	call   r15
  6f905a:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  6f905d:	31 f6                	xor    esi,esi
  6f905f:	31 d2                	xor    edx,edx
  6f9061:	31 c9                	xor    ecx,ecx
  6f9063:	48 83 c7 18          	add    rdi,0x18
  6f9067:	e8 b4 e4 dc ff       	call   0x4c7520
  6f906c:	8b 05 4e 23 b0 01    	mov    eax,DWORD PTR [rip+0x1b0234e]        # 0x21fb3c0
  6f9072:	31 db                	xor    ebx,ebx
  6f9074:	41 b5 01             	mov    r13b,0x1
  6f9077:	83 f8 01             	cmp    eax,0x1
  6f907a:	0f 94 c3             	sete   bl
  6f907d:	c1 e3 03             	shl    ebx,0x3
  6f9080:	83 3d 3d 23 b0 01 00 	cmp    DWORD PTR [rip+0x1b0233d],0x0        # 0x21fb3c4
  6f9087:	75 2f                	jne    0x6f90b8
  6f9089:	48 63 05 3c 23 b0 01 	movsxd rax,DWORD PTR [rip+0x1b0233c]        # 0x21fb3cc
  6f9090:	48 8d 0d 79 0d cc 00 	lea    rcx,[rip+0xcc0d79]        # 0x13b9e10
  6f9097:	ba 01 00 00 00       	mov    edx,0x1
  6f909c:	0f b6 04 c1          	movzx  eax,BYTE PTR [rcx+rax*8]
  6f90a0:	c4 e2 f9 f7 c2       	shlx   rax,rdx,rax
  6f90a5:	48 63 15 20 23 b0 01 	movsxd rdx,DWORD PTR [rip+0x1b02320]        # 0x21fb3cc
  6f90ac:	0f b6 4c d1 04       	movzx  ecx,BYTE PTR [rcx+rdx*8+0x4]
  6f90b1:	48 0f ab c8          	bts    rax,rcx
  6f90b5:	48 09 c3             	or     rbx,rax
  6f90b8:	4c 09 e3             	or     rbx,r12
  6f90bb:	4c 8d 3d 50 0c b8 00 	lea    r15,[rip+0xb80c50]        # 0x1279d12
  6f90c2:	45 31 f6             	xor    r14d,r14d
  6f90c5:	eb 1d                	jmp    0x6f90e4
  6f90c7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  6f90ce:	00 00 
  6f90d0:	44 89 f7             	mov    edi,r14d
  6f90d3:	e8 28 db fb ff       	call   0x6b6c00
  6f90d8:	41 ff c6             	inc    r14d
  6f90db:	44 3b 35 d6 57 61 03 	cmp    r14d,DWORD PTR [rip+0x36157d6]        # 0x3d0e8b8
  6f90e2:	77 4b                	ja     0x6f912f
  6f90e4:	4c 0f a3 f3          	bt     rbx,r14
  6f90e8:	73 ee                	jae    0x6f90d8
  6f90ea:	65 8b 04 25 34 00 00 	mov    eax,DWORD PTR gs:0x34
  6f90f1:	00 
  6f90f2:	41 39 c6             	cmp    r14d,eax
  6f90f5:	75 d9                	jne    0x6f90d0
  6f90f7:	65 4c 8b 24 25 00 00 	mov    r12,QWORD PTR gs:0x0
  6f90fe:	00 00 
  6f9100:	4c 89 e7             	mov    rdi,r12
  6f9103:	4c 89 fa             	mov    rdx,r15
  6f9106:	b9 b4 02 00 00       	mov    ecx,0x2b4
  6f910b:	31 f6                	xor    esi,esi
  6f910d:	e8 9e e7 dc ff       	call   0x4c78b0
  6f9112:	4c 89 e7             	mov    rdi,r12
  6f9115:	e8 d6 db fb ff       	call   0x6b6cf0
  6f911a:	49 8b 3c 24          	mov    rdi,QWORD PTR [r12]
  6f911e:	31 f6                	xor    esi,esi
  6f9120:	31 d2                	xor    edx,edx
  6f9122:	31 c9                	xor    ecx,ecx
  6f9124:	48 83 c7 18          	add    rdi,0x18
  6f9128:	e8 f3 e3 dc ff       	call   0x4c7520
  6f912d:	eb a9                	jmp    0x6f90d8
  6f912f:	48 8d 3d 62 30 22 03 	lea    rdi,[rip+0x3223062]        # 0x391c198
  6f9136:	45 31 ff             	xor    r15d,r15d
  6f9139:	31 f6                	xor    esi,esi
  6f913b:	31 d2                	xor    edx,edx
  6f913d:	31 c9                	xor    ecx,ecx
  6f913f:	e8 dc e3 dc ff       	call   0x4c7520
  6f9144:	45 84 ed             	test   r13b,r13b
  6f9147:	75 27                	jne    0x6f9170
  6f9149:	8b 05 71 22 b0 01    	mov    eax,DWORD PTR [rip+0x1b02271]        # 0x21fb3c0
  6f914f:	83 f8 01             	cmp    eax,0x1
  6f9152:	75 1c                	jne    0x6f9170
  6f9154:	83 3d e5 30 22 03 00 	cmp    DWORD PTR [rip+0x32230e5],0x0        # 0x391c240
  6f915b:	74 13                	je     0x6f9170
  6f915d:	48 8b 3d d4 30 22 03 	mov    rdi,QWORD PTR [rip+0x32230d4]        # 0x391c238
  6f9164:	48 8d 35 45 23 b0 01 	lea    rsi,[rip+0x1b02345]        # 0x21fb4b0
  6f916b:	e8 40 18 df ff       	call   0x4ea9b0
  6f9170:	83 7d bc 00          	cmp    DWORD PTR [rbp-0x44],0x0
  6f9174:	4c 8d 2d 95 31 22 03 	lea    r13,[rip+0x3223195]        # 0x391c310
  6f917b:	8b 45 b8             	mov    eax,DWORD PTR [rbp-0x48]
  6f917e:	74 31                	je     0x6f91b1
  6f9180:	f6 05 ad 30 22 03 01 	test   BYTE PTR [rip+0x32230ad],0x1        # 0x391c234
  6f9187:	74 28                	je     0x6f91b1
  6f9189:	ff c8                	dec    eax
  6f918b:	83 f8 01             	cmp    eax,0x1
  6f918e:	77 07                	ja     0x6f9197
  6f9190:	e8 eb af 1c 00       	call   0x8c4180
  6f9195:	eb 13                	jmp    0x6f91aa
  6f9197:	48 8b 3d 9a 30 22 03 	mov    rdi,QWORD PTR [rip+0x322309a]        # 0x391c238
  6f919e:	48 8d 35 eb 22 b0 01 	lea    rsi,[rip+0x1b022eb]        # 0x21fb490
  6f91a5:	e8 06 18 df ff       	call   0x4ea9b0
  6f91aa:	c6 05 83 30 22 03 00 	mov    BYTE PTR [rip+0x3223083],0x0        # 0x391c234
  6f91b1:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  6f91b5:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  6f91b9:	0f 85 b1 00 00 00    	jne    0x6f9270
  6f91bf:	44 89 f8             	mov    eax,r15d
  6f91c2:	48 83 c4 28          	add    rsp,0x28
  6f91c6:	5b                   	pop    rbx
  6f91c7:	41 5c                	pop    r12
  6f91c9:	41 5d                	pop    r13
  6f91cb:	41 5e                	pop    r14
  6f91cd:	41 5f                	pop    r15
  6f91cf:	5d                   	pop    rbp
  6f91d0:	c3                   	ret
  6f91d1:	4c 89 f7             	mov    rdi,r14
  6f91d4:	e8 17 db fb ff       	call   0x6b6cf0
  6f91d9:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  6f91dc:	31 f6                	xor    esi,esi
  6f91de:	31 d2                	xor    edx,edx
  6f91e0:	31 c9                	xor    ecx,ecx
  6f91e2:	48 83 c7 18          	add    rdi,0x18
  6f91e6:	e8 35 e3 dc ff       	call   0x4c7520
  6f91eb:	48 8d 3d a6 2f 22 03 	lea    rdi,[rip+0x3222fa6]        # 0x391c198
  6f91f2:	31 f6                	xor    esi,esi
  6f91f4:	31 d2                	xor    edx,edx
  6f91f6:	31 c9                	xor    ecx,ecx
  6f91f8:	e8 23 e3 dc ff       	call   0x4c7520
  6f91fd:	e8 7e af 1c 00       	call   0x8c4180
  6f9202:	41 bf ff ff ff ff    	mov    r15d,0xffffffff
  6f9208:	eb a7                	jmp    0x6f91b1
  6f920a:	83 fb 01             	cmp    ebx,0x1
  6f920d:	0f 85 35 f7 ff ff    	jne    0x6f8948
  6f9213:	4c 8d 3d c5 93 cb 00 	lea    r15,[rip+0xcb93c5]        # 0x13b25df
  6f921a:	31 f6                	xor    esi,esi
  6f921c:	4c 89 ff             	mov    rdi,r15
  6f921f:	e8 4c 7b 39 00       	call   0xa90d70
  6f9224:	4c 89 ff             	mov    rdi,r15
  6f9227:	be 0f 00 00 00       	mov    esi,0xf
  6f922c:	e8 3f 7b 39 00       	call   0xa90d70
  6f9231:	4c 89 ff             	mov    rdi,r15
  6f9234:	31 f6                	xor    esi,esi
  6f9236:	e8 35 7b 39 00       	call   0xa90d70
  6f923b:	e9 08 f7 ff ff       	jmp    0x6f8948
  6f9240:	bf 01 00 00 00       	mov    edi,0x1
  6f9245:	31 f6                	xor    esi,esi
  6f9247:	e8 14 07 00 00       	call   0x6f9960
  6f924c:	e9 56 f8 ff ff       	jmp    0x6f8aa7
  6f9251:	8b 3d 7d 21 b0 01    	mov    edi,DWORD PTR [rip+0x1b0217d]        # 0x21fb3d4
  6f9257:	be 01 00 00 00       	mov    esi,0x1
  6f925c:	e8 ff 06 00 00       	call   0x6f9960
  6f9261:	e9 07 f8 ff ff       	jmp    0x6f8a6d
  6f9266:	e8 c5 f5 ff ff       	call   0x6f8830
  6f926b:	e9 f4 f8 ff ff       	jmp    0x6f8b64
  6f9270:	e8 3b 44 00 00       	call   0x6fd6b0
  6f9275:	0f 0b                	ud2
  6f9277:	48 8d 3d b2 21 b0 01 	lea    rdi,[rip+0x1b021b2]        # 0x21fb430
  6f927e:	4c 89 ee             	mov    rsi,r13
  6f9281:	e8 3a 66 d5 ff       	call   0x44f8c0
  6f9286:	e9 11 fb ff ff       	jmp    0x6f8d9c
  6f928b:	48 8d 3d be 21 b0 01 	lea    rdi,[rip+0x1b021be]        # 0x21fb450
  6f9292:	4c 89 ee             	mov    rsi,r13
  6f9295:	e8 26 66 d5 ff       	call   0x44f8c0
  6f929a:	e9 1e fc ff ff       	jmp    0x6f8ebd
  6f929f:	48 8d 3d ca 21 b0 01 	lea    rdi,[rip+0x1b021ca]        # 0x21fb470
  6f92a6:	4c 89 ee             	mov    rsi,r13
  6f92a9:	e8 12 66 d5 ff       	call   0x44f8c0
  6f92ae:	e9 34 fc ff ff       	jmp    0x6f8ee7
  6f92b3:	48 8d 3d 56 21 b0 01 	lea    rdi,[rip+0x1b02156]        # 0x21fb410
  6f92ba:	4c 89 fe             	mov    rsi,r15
  6f92bd:	e8 fe 65 d5 ff       	call   0x44f8c0
  6f92c2:	e9 8b fd ff ff       	jmp    0x6f9052
  6f92c7:	90                   	nop
  6f92c8:	90                   	nop
  6f92c9:	90                   	nop
  6f92ca:	90                   	nop
  6f92cb:	90                   	nop
  6f92cc:	90                   	nop
  6f92cd:	90                   	nop
  6f92ce:	90                   	nop
  6f92cf:	90                   	nop
  6f92d0:	55                   	push   rbp
  6f92d1:	48 89 e5             	mov    rbp,rsp
  6f92d4:	bf 01 00 00 00       	mov    edi,0x1
  6f92d9:	5d                   	pop    rbp
  6f92da:	e9 31 f6 ff ff       	jmp    0x6f8910
  6f92df:	90                   	nop
  6f92e0:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  6f92e7:	00 00 
  6f92e9:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
  6f92ed:	b8 4e 00 00 00       	mov    eax,0x4e
  6f92f2:	80 b9 81 0c 00 00 00 	cmp    BYTE PTR [rcx+0xc81],0x0
  6f92f9:	74 01                	je     0x6f92fc
  6f92fb:	c3                   	ret
  6f92fc:	80 3d bd 2e 22 03 00 	cmp    BYTE PTR [rip+0x3222ebd],0x0        # 0x391c1c0
  6f9303:	75 07                	jne    0x6f930c
  6f9305:	c6 05 b4 2e 22 03 01 	mov    BYTE PTR [rip+0x3222eb4],0x1        # 0x391c1c0
  6f930c:	55                   	push   rbp
  6f930d:	48 89 e5             	mov    rbp,rsp
  6f9310:	bf 02 00 00 00       	mov    edi,0x2
  6f9315:	e8 f6 f5 ff ff       	call   0x6f8910
  6f931a:	89 c1                	mov    ecx,eax
  6f931c:	85 c0                	test   eax,eax
  6f931e:	b8 16 00 00 00       	mov    eax,0x16
  6f9323:	0f 44 c1             	cmove  eax,ecx
  6f9326:	5d                   	pop    rbp
  6f9327:	c3                   	ret
